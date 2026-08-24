//! Allocation-bounded, cryptographically verified trade-mutation admission.

use core::fmt;
use std::{borrow::Cow, collections::BTreeSet, error::Error};

use radroots_event::{
    envelope::{EventEnvelope, kind::is_trade_mutation_event_kind},
    id::{EventId, MutationId},
    trade::TradeMutationEnvelopeV1,
    wire::{
        DEFAULT_EXTRA_MAX_FIELDS, DEFAULT_EXTRA_TOTAL_JSON_MAX_BYTES, EventWireLimits,
        Nip01EventWire,
    },
};
use radroots_event_codec::decode::trade::{RadrootsTradeMutationError, trade_mutation_from_event};
use radroots_nostr::event::{Verification, verify, verify_id};
use serde::Deserialize;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;

use crate::RhiConfigDocumentV1;

/// Maximum encoded Nostr event-identifier length admitted before allocation.
pub const RHI_TRADE_EVENT_ID_MAX_BYTES: usize = 64;

/// Exact version of the RHI trade-ingest contract.
pub const RHI_TRADE_INGEST_CONTRACT_VERSION: u32 = 1;

/// Maximum encoded Nostr public-key length admitted before allocation.
pub const RHI_TRADE_EVENT_PUBLIC_KEY_MAX_BYTES: usize = 64;

/// Maximum encoded Nostr signature length admitted before allocation.
pub const RHI_TRADE_EVENT_SIGNATURE_MAX_BYTES: usize = 128;

/// Maximum number of bounded, non-authoritative outer event extensions.
pub const RHI_TRADE_EVENT_EXTRA_FIELD_MAX_COUNT: usize = DEFAULT_EXTRA_MAX_FIELDS;

/// Maximum aggregate JSON bytes for non-authoritative outer event extensions.
pub const RHI_TRADE_EVENT_EXTRA_JSON_MAX_BYTES: usize = DEFAULT_EXTRA_TOTAL_JSON_MAX_BYTES;

const DUPLICATE_FIELD_SENTINEL: &str = "rhi-duplicate-event-field";
const EXTRA_COUNT_SENTINEL: &str = "rhi-extra-field-count-limit";
const EXTRA_BYTES_SENTINEL: &str = "rhi-extra-field-bytes-limit";
const TAG_COUNT_SENTINEL: &str = "rhi-tag-count-limit";
const TAG_ELEMENT_COUNT_SENTINEL: &str = "rhi-tag-element-count-limit";
const TAG_ELEMENT_BYTES_SENTINEL: &str = "rhi-tag-element-bytes-limit";
const TAG_TOTAL_BYTES_SENTINEL: &str = "rhi-tag-total-bytes-limit";

/// Immutable trade-event limits projected from one admitted RHI configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiTradeMutationAdmissionLimits {
    wire_bytes: usize,
    content_bytes: usize,
    tag_count: usize,
    tag_total_elements: usize,
    tag_element_bytes: usize,
    tag_total_bytes: usize,
}

impl RhiTradeMutationAdmissionLimits {
    /// Projects the exact event limits from a validated immutable configuration.
    pub fn from_config(
        configuration: &RhiConfigDocumentV1,
    ) -> Result<Self, RhiTradeMutationAdmissionError> {
        Ok(Self {
            wire_bytes: config_limit(configuration, "/resource_limits/events/wire_bytes")?,
            content_bytes: config_limit(configuration, "/resource_limits/events/content_bytes")?,
            tag_count: config_limit(configuration, "/resource_limits/events/tag_count")?,
            tag_total_elements: config_limit(
                configuration,
                "/resource_limits/events/tag_total_elements",
            )?,
            tag_element_bytes: config_limit(
                configuration,
                "/resource_limits/events/tag_element_bytes",
            )?,
            tag_total_bytes: config_limit(
                configuration,
                "/resource_limits/events/tag_total_bytes",
            )?,
        })
    }

    /// Returns the original event-wire byte cap.
    #[must_use]
    pub const fn wire_bytes(self) -> usize {
        self.wire_bytes
    }

    /// Returns the decoded canonical-content byte cap.
    #[must_use]
    pub const fn content_bytes(self) -> usize {
        self.content_bytes
    }

    /// Returns the event-tag count cap.
    #[must_use]
    pub const fn tag_count(self) -> usize {
        self.tag_count
    }

    /// Returns the aggregate event-tag-element count cap.
    #[must_use]
    pub const fn tag_total_elements(self) -> usize {
        self.tag_total_elements
    }

    /// Returns the decoded byte cap for one tag element.
    #[must_use]
    pub const fn tag_element_bytes(self) -> usize {
        self.tag_element_bytes
    }

    /// Returns the aggregate decoded byte cap for all tag elements.
    #[must_use]
    pub const fn tag_total_bytes(self) -> usize {
        self.tag_total_bytes
    }

    const fn wire_limits(self) -> EventWireLimits {
        EventWireLimits {
            max_raw_json_bytes: self.wire_bytes,
            max_content_bytes: self.content_bytes,
            max_tag_count: self.tag_count,
            max_total_tag_elements: self.tag_total_elements,
            max_tag_element_bytes: self.tag_element_bytes,
            max_total_tag_bytes: self.tag_total_bytes,
            max_extra_fields: RHI_TRADE_EVENT_EXTRA_FIELD_MAX_COUNT,
            max_total_extra_json_bytes: RHI_TRADE_EVENT_EXTRA_JSON_MAX_BYTES,
        }
    }
}

impl fmt::Debug for RhiTradeMutationAdmissionLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiTradeMutationAdmissionLimits")
            .field("wire_bytes", &self.wire_bytes)
            .field("content_bytes", &self.content_bytes)
            .field("tag_count", &self.tag_count)
            .field("tag_total_elements", &self.tag_total_elements)
            .field("tag_element_bytes", &self.tag_element_bytes)
            .field("tag_total_bytes", &self.tag_total_bytes)
            .finish()
    }
}

/// Injected UTC second at which one trade event is observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RhiTradeMutationObservedAtUnixSeconds(u64);

impl RhiTradeMutationObservedAtUnixSeconds {
    /// Validates a positive instant representable by SQLite's signed integer.
    pub fn new(value: u64) -> Result<Self, RhiTradeMutationAdmissionError> {
        if value == 0 || i64::try_from(value).is_err() {
            return Err(failure(
                RhiTradeMutationAdmissionErrorKind::InvalidObservationTime,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the injected observation time.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Explicit caller-selected future authored-time tolerance with no default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RhiTradeMutationAuthoredTimePolicy {
    maximum_future_seconds: u64,
}

impl RhiTradeMutationAuthoredTimePolicy {
    /// Validates the inclusive maximum future skew.
    pub fn new(maximum_future_seconds: u64) -> Result<Self, RhiTradeMutationAdmissionError> {
        if i64::try_from(maximum_future_seconds).is_err() {
            return Err(failure(
                RhiTradeMutationAdmissionErrorKind::InvalidTimePolicy,
            ));
        }
        Ok(Self {
            maximum_future_seconds,
        })
    }

    /// Returns the inclusive maximum future skew.
    #[must_use]
    pub const fn maximum_future_seconds(self) -> u64 {
        self.maximum_future_seconds
    }
}

/// Stable source-free classification for trade-mutation admission failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiTradeMutationAdmissionErrorKind {
    InvalidLimits,
    EmptyEvent,
    EventTooLarge,
    InvalidEventUtf8,
    MalformedEvent,
    DuplicateEventField,
    EventIdentifierTooLarge,
    EventContentTooLarge,
    TooManyTags,
    TooManyTagElements,
    TagElementTooLarge,
    TagsTooLarge,
    TooManyExtraFields,
    ExtraFieldsTooLarge,
    InvalidObservationTime,
    InvalidTimePolicy,
    InvalidAuthoredTime,
    InvalidEventId,
    InvalidSignature,
    UnsupportedKind,
    InvalidAuthor,
    InvalidMutation,
    AuthoredTimeRejected,
}

impl RhiTradeMutationAdmissionErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidLimits => "trade-event admission limits are invalid",
            Self::EmptyEvent => "trade event bytes are empty",
            Self::EventTooLarge => "trade event exceeds its wire limit",
            Self::InvalidEventUtf8 => "trade event is not valid UTF-8",
            Self::MalformedEvent => "trade event structure is invalid",
            Self::DuplicateEventField => "trade event contains a duplicate field",
            Self::EventIdentifierTooLarge => "trade event identifier exceeds its limit",
            Self::EventContentTooLarge => "trade event content exceeds its limit",
            Self::TooManyTags => "trade event tag count exceeds its limit",
            Self::TooManyTagElements => "trade event tag elements exceed their count limit",
            Self::TagElementTooLarge => "trade event tag element exceeds its byte limit",
            Self::TagsTooLarge => "trade event tags exceed their aggregate byte limit",
            Self::TooManyExtraFields => "trade event extras exceed their field limit",
            Self::ExtraFieldsTooLarge => "trade event extras exceed their byte limit",
            Self::InvalidObservationTime => "trade-event observation time is invalid",
            Self::InvalidTimePolicy => "trade-event authored-time policy is invalid",
            Self::InvalidAuthoredTime => "trade-event authored time is invalid",
            Self::InvalidEventId => "trade event identifier verification failed",
            Self::InvalidSignature => "trade event signature verification failed",
            Self::UnsupportedKind => "trade event kind is unsupported",
            Self::InvalidAuthor => "trade event author binding is invalid",
            Self::InvalidMutation => "trade mutation contract is invalid",
            Self::AuthoredTimeRejected => "trade-event authored time is outside policy",
        }
    }
}

/// One redacted trade-mutation admission failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiTradeMutationAdmissionError {
    kind: RhiTradeMutationAdmissionErrorKind,
}

impl RhiTradeMutationAdmissionError {
    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> RhiTradeMutationAdmissionErrorKind {
        self.kind
    }
}

impl fmt::Debug for RhiTradeMutationAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiTradeMutationAdmissionError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiTradeMutationAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for RhiTradeMutationAdmissionError {}

/// One bounded, signature-verified, canonical trade-mutation event.
///
/// Construction is sealed to the admission boundary:
///
/// ```compile_fail
/// use rhi::RhiAdmittedTradeMutationEvent;
///
/// let _forged = RhiAdmittedTradeMutationEvent {};
/// ```
pub struct RhiAdmittedTradeMutationEvent {
    original: Box<[u8]>,
    event: EventEnvelope,
    mutation: TradeMutationEnvelopeV1,
    mutation_id: MutationId,
    observed_at: RhiTradeMutationObservedAtUnixSeconds,
}

impl RhiAdmittedTradeMutationEvent {
    /// Returns the exact bounded wire bytes supplied to the admission boundary.
    #[must_use]
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    /// Returns the independently verified Nostr event identifier.
    #[must_use]
    pub fn event_id(&self) -> &EventId {
        self.event.id()
    }

    /// Returns the canonical content-derived mutation identifier.
    #[must_use]
    pub const fn mutation_id(&self) -> &MutationId {
        &self.mutation_id
    }

    /// Returns the exact registered Nostr event kind.
    #[must_use]
    pub fn event_kind(&self) -> u32 {
        self.event.kind_u32()
    }

    /// Returns the untrusted-but-policy-admitted event-authored UTC second.
    #[must_use]
    pub fn authored_at_unix_seconds(&self) -> u64 {
        self.event.created_at_u64()
    }

    /// Returns the injected UTC second used to admit this source observation.
    #[must_use]
    pub const fn observed_at_unix_seconds(&self) -> RhiTradeMutationObservedAtUnixSeconds {
        self.observed_at
    }

    /// Returns the canonical typed mutation bound to the signed event.
    #[must_use]
    pub const fn mutation(&self) -> &TradeMutationEnvelopeV1 {
        &self.mutation
    }

    pub(crate) fn event_signature_bytes(&self) -> [u8; 64] {
        *self.event.sig().as_bytes()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Box<[u8]>,
        EventEnvelope,
        TradeMutationEnvelopeV1,
        MutationId,
        RhiTradeMutationObservedAtUnixSeconds,
    ) {
        (
            self.original,
            self.event,
            self.mutation,
            self.mutation_id,
            self.observed_at,
        )
    }
}

impl fmt::Debug for RhiAdmittedTradeMutationEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiAdmittedTradeMutationEvent")
            .field("wire_bytes", &self.original.len())
            .field("content_bytes", &self.event.content().len())
            .field("tag_count", &self.event.tags().len())
            .field("event_kind", &self.event.kind_u32())
            .field("authored_at_unix_seconds", &self.event.created_at_u64())
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Bounds, verifies, and admits one canonical signed trade-mutation event.
pub fn admit_rhi_trade_mutation_event(
    limits: RhiTradeMutationAdmissionLimits,
    original: &[u8],
    observed_at: RhiTradeMutationObservedAtUnixSeconds,
    authored_time_policy: RhiTradeMutationAuthoredTimePolicy,
) -> Result<RhiAdmittedTradeMutationEvent, RhiTradeMutationAdmissionError> {
    if original.is_empty() {
        return Err(failure(RhiTradeMutationAdmissionErrorKind::EmptyEvent));
    }
    if original.len() > limits.wire_bytes {
        return Err(failure(RhiTradeMutationAdmissionErrorKind::EventTooLarge));
    }
    let source = std::str::from_utf8(original)
        .map_err(|_| failure(RhiTradeMutationAdmissionErrorKind::InvalidEventUtf8))?;
    preflight_wire(source, limits)?;

    let wire = Nip01EventWire::parse_json_unverified_with_limits(source, limits.wire_limits())
        .map_err(|_| failure(RhiTradeMutationAdmissionErrorKind::MalformedEvent))?;
    let event = wire
        .into_unverified_envelope()
        .map_err(|_| failure(RhiTradeMutationAdmissionErrorKind::MalformedEvent))?;

    match verify_id(&event) {
        Verification::IdVerified => {}
        Verification::IdMismatch => {
            return Err(failure(RhiTradeMutationAdmissionErrorKind::InvalidEventId));
        }
        _ => return Err(failure(RhiTradeMutationAdmissionErrorKind::MalformedEvent)),
    }
    match verify(&event) {
        Verification::Verified => {}
        Verification::IdMismatch => {
            return Err(failure(RhiTradeMutationAdmissionErrorKind::InvalidEventId));
        }
        Verification::SignatureInvalid => {
            return Err(failure(
                RhiTradeMutationAdmissionErrorKind::InvalidSignature,
            ));
        }
        Verification::IdVerified | Verification::MalformedEnvelope => {
            return Err(failure(RhiTradeMutationAdmissionErrorKind::MalformedEvent));
        }
    }

    validate_authored_time_representation(event.created_at_u64())?;
    if !is_trade_mutation_event_kind(event.kind_u32()) {
        return Err(failure(RhiTradeMutationAdmissionErrorKind::UnsupportedKind));
    }
    let mutation = trade_mutation_from_event(&event).map_err(classify_mutation_error)?;
    let mutation_id = mutation
        .mutation_id
        .ok_or_else(|| failure(RhiTradeMutationAdmissionErrorKind::InvalidMutation))?;
    enforce_authored_time_policy(event.created_at_u64(), observed_at, authored_time_policy)?;

    Ok(RhiAdmittedTradeMutationEvent {
        original: original.into(),
        event,
        mutation,
        mutation_id,
        observed_at,
    })
}

fn validate_authored_time_representation(
    authored_at: u64,
) -> Result<(), RhiTradeMutationAdmissionError> {
    if i64::try_from(authored_at).is_err() {
        return Err(failure(
            RhiTradeMutationAdmissionErrorKind::InvalidAuthoredTime,
        ));
    }
    Ok(())
}

fn enforce_authored_time_policy(
    authored_at: u64,
    observed_at: RhiTradeMutationObservedAtUnixSeconds,
    policy: RhiTradeMutationAuthoredTimePolicy,
) -> Result<(), RhiTradeMutationAdmissionError> {
    let latest = observed_at
        .get()
        .saturating_add(policy.maximum_future_seconds());
    if authored_at > latest {
        return Err(failure(
            RhiTradeMutationAdmissionErrorKind::AuthoredTimeRejected,
        ));
    }
    Ok(())
}

fn classify_mutation_error(error: RadrootsTradeMutationError) -> RhiTradeMutationAdmissionError {
    let kind = match error {
        RadrootsTradeMutationError::InvalidKind => {
            RhiTradeMutationAdmissionErrorKind::UnsupportedKind
        }
        RadrootsTradeMutationError::AuthorMismatch => {
            RhiTradeMutationAdmissionErrorKind::InvalidAuthor
        }
        _ => RhiTradeMutationAdmissionErrorKind::InvalidMutation,
    };
    failure(kind)
}

fn config_limit(
    configuration: &RhiConfigDocumentV1,
    pointer: &str,
) -> Result<usize, RhiTradeMutationAdmissionError> {
    configuration
        .normalized()
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| failure(RhiTradeMutationAdmissionErrorKind::InvalidLimits))
}

struct RawEvent<'a> {
    id: &'a RawValue,
    pubkey: &'a RawValue,
    created_at: &'a RawValue,
    kind: &'a RawValue,
    tags: &'a RawValue,
    content: &'a RawValue,
    sig: &'a RawValue,
}

fn preflight_wire(
    source: &str,
    limits: RhiTradeMutationAdmissionLimits,
) -> Result<(), RhiTradeMutationAdmissionError> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let raw = RawEventSeed
        .deserialize(&mut deserializer)
        .map_err(classify_wire_preflight_error)?;
    deserializer
        .end()
        .map_err(|_| failure(RhiTradeMutationAdmissionErrorKind::MalformedEvent))?;

    validate_bounded_string(
        raw.id,
        RHI_TRADE_EVENT_ID_MAX_BYTES,
        RhiTradeMutationAdmissionErrorKind::EventIdentifierTooLarge,
    )?;
    validate_bounded_string(
        raw.pubkey,
        RHI_TRADE_EVENT_PUBLIC_KEY_MAX_BYTES,
        RhiTradeMutationAdmissionErrorKind::EventIdentifierTooLarge,
    )?;
    validate_bounded_string(
        raw.sig,
        RHI_TRADE_EVENT_SIGNATURE_MAX_BYTES,
        RhiTradeMutationAdmissionErrorKind::EventIdentifierTooLarge,
    )?;
    validate_bounded_string(
        raw.content,
        limits.content_bytes,
        RhiTradeMutationAdmissionErrorKind::EventContentTooLarge,
    )?;
    parse_scalar::<u64>(raw.created_at)?;
    parse_scalar::<u32>(raw.kind)?;
    measure_tags(raw.tags, limits)?;
    Ok(())
}

struct RawEventSeed;

impl<'de> DeserializeSeed<'de> for RawEventSeed {
    type Value = RawEvent<'de>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(RawEventVisitor)
    }
}

struct RawEventVisitor;

impl<'de> Visitor<'de> for RawEventVisitor {
    type Value = RawEvent<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded NIP-01 event object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut id = None;
        let mut pubkey = None;
        let mut created_at = None;
        let mut kind = None;
        let mut tags = None;
        let mut content = None;
        let mut sig = None;
        let mut extras = BTreeSet::new();
        let mut extra_bytes = 0usize;

        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            let slot = match key.as_ref() {
                "id" => Some(&mut id),
                "pubkey" => Some(&mut pubkey),
                "created_at" => Some(&mut created_at),
                "kind" => Some(&mut kind),
                "tags" => Some(&mut tags),
                "content" => Some(&mut content),
                "sig" => Some(&mut sig),
                _ => None,
            };
            if let Some(slot) = slot {
                if slot.is_some() {
                    return Err(de::Error::custom(DUPLICATE_FIELD_SENTINEL));
                }
                *slot = Some(map.next_value::<&'de RawValue>()?);
                continue;
            }

            if !extras.insert(key.clone()) {
                return Err(de::Error::custom(DUPLICATE_FIELD_SENTINEL));
            }
            if extras.len() > RHI_TRADE_EVENT_EXTRA_FIELD_MAX_COUNT {
                return Err(de::Error::custom(EXTRA_COUNT_SENTINEL));
            }
            let value = map.next_value::<&'de RawValue>()?;
            extra_bytes = extra_bytes
                .checked_add(canonical_json_string_len(key.as_ref()))
                .and_then(|total| total.checked_add(1))
                .and_then(|total| total.checked_add(value.get().len()))
                .ok_or_else(|| de::Error::custom(EXTRA_BYTES_SENTINEL))?;
            if extra_bytes > RHI_TRADE_EVENT_EXTRA_JSON_MAX_BYTES {
                return Err(de::Error::custom(EXTRA_BYTES_SENTINEL));
            }
        }

        Ok(RawEvent {
            id: required(id)?,
            pubkey: required(pubkey)?,
            created_at: required(created_at)?,
            kind: required(kind)?,
            tags: required(tags)?,
            content: required(content)?,
            sig: required(sig)?,
        })
    }
}

fn required<E>(value: Option<&RawValue>) -> Result<&RawValue, E>
where
    E: de::Error,
{
    value.ok_or_else(|| de::Error::custom("missing required event field"))
}

fn canonical_json_string_len(value: &str) -> usize {
    value.chars().fold(2usize, |length, character| {
        length.saturating_add(match character {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{08}' | '\u{0c}' => 2,
            '\u{00}'..='\u{1f}' => 6,
            _ => character.len_utf8(),
        })
    })
}

fn parse_scalar<T>(raw: &RawValue) -> Result<T, RhiTradeMutationAdmissionError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(raw.get())
        .map_err(|_| failure(RhiTradeMutationAdmissionErrorKind::MalformedEvent))
}

fn validate_bounded_string(
    raw: &RawValue,
    maximum: usize,
    too_large: RhiTradeMutationAdmissionErrorKind,
) -> Result<usize, RhiTradeMutationAdmissionError> {
    let length = decoded_json_string_utf8_bytes(raw.get())
        .ok_or_else(|| failure(RhiTradeMutationAdmissionErrorKind::MalformedEvent))?;
    if length > maximum {
        return Err(failure(too_large));
    }
    Ok(length)
}

fn decoded_json_string_utf8_bytes(raw: &str) -> Option<usize> {
    let bytes = raw.as_bytes();
    if bytes.len() < 2 || bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return None;
    }
    let end = bytes.len() - 1;
    let mut index = 1;
    let mut length = 0usize;
    while index < end {
        let byte = bytes[index];
        if byte == b'\\' {
            index = index.checked_add(1)?;
            let escaped = *bytes.get(index)?;
            match escaped {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                    length = length.checked_add(1)?;
                    index = index.checked_add(1)?;
                }
                b'u' => {
                    let first = parse_hex_u16(bytes.get(index + 1..index + 5)?)?;
                    index = index.checked_add(5)?;
                    let scalar = if (0xd800..=0xdbff).contains(&first) {
                        if bytes.get(index..index + 2)? != b"\\u" {
                            return None;
                        }
                        let second = parse_hex_u16(bytes.get(index + 2..index + 6)?)?;
                        if !(0xdc00..=0xdfff).contains(&second) {
                            return None;
                        }
                        index = index.checked_add(6)?;
                        0x1_0000
                            + ((u32::from(first) - 0xd800) << 10)
                            + (u32::from(second) - 0xdc00)
                    } else if (0xdc00..=0xdfff).contains(&first) {
                        return None;
                    } else {
                        u32::from(first)
                    };
                    length = length.checked_add(char::from_u32(scalar)?.len_utf8())?;
                }
                _ => return None,
            }
        } else if byte < 0x80 {
            if byte < 0x20 || byte == b'"' {
                return None;
            }
            length = length.checked_add(1)?;
            index = index.checked_add(1)?;
        } else {
            let character = raw.get(index..end)?.chars().next()?;
            let width = character.len_utf8();
            length = length.checked_add(width)?;
            index = index.checked_add(width)?;
        }
    }
    (index == end).then_some(length)
}

fn parse_hex_u16(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    bytes.iter().try_fold(0u16, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte - b'0'),
            b'a'..=b'f' => u16::from(byte - b'a') + 10,
            b'A'..=b'F' => u16::from(byte - b'A') + 10,
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit)
    })
}

#[derive(Clone, Copy)]
struct Measurement {
    count: usize,
    elements: usize,
    bytes: usize,
}

fn measure_tags(
    raw: &RawValue,
    limits: RhiTradeMutationAdmissionLimits,
) -> Result<Measurement, RhiTradeMutationAdmissionError> {
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    let measurement = TagsSeed { limits }
        .deserialize(&mut deserializer)
        .map_err(classify_tag_error)?;
    deserializer
        .end()
        .map_err(|_| failure(RhiTradeMutationAdmissionErrorKind::MalformedEvent))?;
    Ok(measurement)
}

struct TagsSeed {
    limits: RhiTradeMutationAdmissionLimits,
}

impl<'de> DeserializeSeed<'de> for TagsSeed {
    type Value = Measurement;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(TagsVisitor {
            limits: self.limits,
        })
    }
}

struct TagsVisitor {
    limits: RhiTradeMutationAdmissionLimits,
}

impl<'de> Visitor<'de> for TagsVisitor {
    type Value = Measurement;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded array of Nostr tags")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result = Measurement {
            count: 0,
            elements: 0,
            bytes: 0,
        };
        while result.count < self.limits.tag_count {
            let remaining_elements = self
                .limits
                .tag_total_elements
                .checked_sub(result.elements)
                .ok_or_else(|| de::Error::custom(TAG_ELEMENT_COUNT_SENTINEL))?;
            let Some(tag) = sequence.next_element_seed(TagSeed {
                maximum_elements: remaining_elements,
                maximum_element_bytes: self.limits.tag_element_bytes,
            })?
            else {
                return Ok(result);
            };
            result.count += 1;
            result.elements = result
                .elements
                .checked_add(tag.elements)
                .ok_or_else(|| de::Error::custom(TAG_ELEMENT_COUNT_SENTINEL))?;
            result.bytes = result
                .bytes
                .checked_add(tag.bytes)
                .ok_or_else(|| de::Error::custom(TAG_TOTAL_BYTES_SENTINEL))?;
            if result.bytes > self.limits.tag_total_bytes {
                return Err(de::Error::custom(TAG_TOTAL_BYTES_SENTINEL));
            }
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(TAG_COUNT_SENTINEL));
        }
        Ok(result)
    }
}

struct TagSeed {
    maximum_elements: usize,
    maximum_element_bytes: usize,
}

impl<'de> DeserializeSeed<'de> for TagSeed {
    type Value = Measurement;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(TagVisitor {
            maximum_elements: self.maximum_elements,
            maximum_element_bytes: self.maximum_element_bytes,
        })
    }
}

struct TagVisitor {
    maximum_elements: usize,
    maximum_element_bytes: usize,
}

impl<'de> Visitor<'de> for TagVisitor {
    type Value = Measurement;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Nostr tag")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result = Measurement {
            count: 1,
            elements: 0,
            bytes: 0,
        };
        while result.elements < self.maximum_elements {
            let Some(length) = sequence.next_element_seed(StringLengthSeed {
                maximum: self.maximum_element_bytes,
            })?
            else {
                return Ok(result);
            };
            result.elements += 1;
            result.bytes = result
                .bytes
                .checked_add(length)
                .ok_or_else(|| de::Error::custom(TAG_TOTAL_BYTES_SENTINEL))?;
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(TAG_ELEMENT_COUNT_SENTINEL));
        }
        Ok(result)
    }
}

struct StringLengthSeed {
    maximum: usize,
}

impl<'de> DeserializeSeed<'de> for StringLengthSeed {
    type Value = usize;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <&RawValue>::deserialize(deserializer)?;
        let length = decoded_json_string_utf8_bytes(raw.get())
            .ok_or_else(|| de::Error::invalid_type(de::Unexpected::Other("non-string"), &self))?;
        if length > self.maximum {
            return Err(de::Error::custom(TAG_ELEMENT_BYTES_SENTINEL));
        }
        Ok(length)
    }
}

impl de::Expected for StringLengthSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON string")
    }
}

fn classify_wire_preflight_error(error: serde_json::Error) -> RhiTradeMutationAdmissionError {
    let rendered = error.to_string();
    let kind = if rendered.contains(DUPLICATE_FIELD_SENTINEL) {
        RhiTradeMutationAdmissionErrorKind::DuplicateEventField
    } else if rendered.contains(EXTRA_COUNT_SENTINEL) {
        RhiTradeMutationAdmissionErrorKind::TooManyExtraFields
    } else if rendered.contains(EXTRA_BYTES_SENTINEL) {
        RhiTradeMutationAdmissionErrorKind::ExtraFieldsTooLarge
    } else {
        RhiTradeMutationAdmissionErrorKind::MalformedEvent
    };
    failure(kind)
}

fn classify_tag_error(error: serde_json::Error) -> RhiTradeMutationAdmissionError {
    let rendered = error.to_string();
    let kind = if rendered.contains(TAG_COUNT_SENTINEL) {
        RhiTradeMutationAdmissionErrorKind::TooManyTags
    } else if rendered.contains(TAG_ELEMENT_COUNT_SENTINEL) {
        RhiTradeMutationAdmissionErrorKind::TooManyTagElements
    } else if rendered.contains(TAG_ELEMENT_BYTES_SENTINEL) {
        RhiTradeMutationAdmissionErrorKind::TagElementTooLarge
    } else if rendered.contains(TAG_TOTAL_BYTES_SENTINEL) {
        RhiTradeMutationAdmissionErrorKind::TagsTooLarge
    } else {
        RhiTradeMutationAdmissionErrorKind::MalformedEvent
    };
    failure(kind)
}

const fn failure(kind: RhiTradeMutationAdmissionErrorKind) -> RhiTradeMutationAdmissionError {
    RhiTradeMutationAdmissionError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_string_length_is_allocation_free_and_exact() {
        assert_eq!(canonical_json_string_len("plain"), 7);
        assert_eq!(canonical_json_string_len("a\nb"), 6);
        assert_eq!(canonical_json_string_len("é"), 4);
        assert_eq!(canonical_json_string_len("\u{0001}"), 8);
    }

    #[test]
    fn decoded_json_string_length_handles_escapes_and_surrogates() {
        assert_eq!(decoded_json_string_utf8_bytes(r#""plain""#), Some(5));
        assert_eq!(decoded_json_string_utf8_bytes(r#""a\nb""#), Some(3));
        assert_eq!(decoded_json_string_utf8_bytes(r#""\u00e9""#), Some(2));
        assert_eq!(decoded_json_string_utf8_bytes(r#""\ud83c\udf31""#), Some(4));
        assert_eq!(decoded_json_string_utf8_bytes(r#""\ud83c""#), None);
    }
}
