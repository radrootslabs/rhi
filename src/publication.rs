//! Explicit publication authority and immutable target-set identity.

use core::fmt;
use std::error::Error;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::RhiConfigDocumentV1;

/// Exact version of the RHI publication-authority contract.
pub const RHI_PUBLICATION_CONTRACT_VERSION: u32 = 1;

/// Absolute number of publication targets admitted by the v1 contract.
pub const RHI_PUBLICATION_MAX_TARGETS: usize = 32;

/// Absolute number of durable publication attempts admitted per target.
pub const RHI_PUBLICATION_MAX_ATTEMPTS: u16 = 100;

const AUTHORITY_DOMAIN: &[u8] = b"radroots.rhi.publication_authority.v1\0";
const TARGET_SET_DOMAIN: &[u8] = b"radroots.rhi.publication_target_set.v1\0";

/// Closed publication authority selected by the complete validated configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiPublicationMode {
    Required,
    Disabled,
}

impl RhiPublicationMode {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Disabled => "disabled",
        }
    }
}

/// Immutable retry authority copied from one validated required-publication config.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RhiPublicationRetryPolicy {
    maximum_attempts: u16,
    initial_backoff_milliseconds: u64,
    maximum_backoff_milliseconds: u64,
    attempt_deadline_milliseconds: u64,
}

impl RhiPublicationRetryPolicy {
    /// Returns the total allowed attempts for each target.
    #[must_use]
    pub const fn maximum_attempts(self) -> u16 {
        self.maximum_attempts
    }

    /// Returns the configured initial retry bound in whole milliseconds.
    #[must_use]
    pub const fn initial_backoff_milliseconds(self) -> u64 {
        self.initial_backoff_milliseconds
    }

    /// Returns the configured maximum retry bound in whole milliseconds.
    #[must_use]
    pub const fn maximum_backoff_milliseconds(self) -> u64 {
        self.maximum_backoff_milliseconds
    }

    /// Returns the absolute per-attempt duration bound in whole milliseconds.
    #[must_use]
    pub const fn attempt_deadline_milliseconds(self) -> u64 {
        self.attempt_deadline_milliseconds
    }
}

/// One immutable publication target derived from the configured relay inventory.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RhiPublicationTarget {
    ordinal: u8,
    relay_id: Box<str>,
    required: bool,
}

impl RhiPublicationTarget {
    /// Returns the stable zero-based position from the configured target inventory.
    #[must_use]
    pub const fn ordinal(&self) -> u8 {
        self.ordinal
    }

    /// Returns the validated stable relay identifier.
    #[must_use]
    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    /// Returns whether this relay is required by the governed relay authority.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

impl fmt::Debug for RhiPublicationTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPublicationTarget")
            .field("ordinal", &self.ordinal)
            .field("relay_id", &"[redacted]")
            .field("required", &self.required)
            .finish()
    }
}

/// Sealed immutable publication authority derived from one validated config.
///
/// Disabled authority contains no target or retry state. Required authority
/// preserves the complete configured target order and binds every target's
/// requiredness, the retry policy, and queue bound into one domain-separated
/// digest. Construction performs no I/O.
///
/// ```compile_fail
/// use rhi::RhiPublicationAuthority;
///
/// let _forged = RhiPublicationAuthority { mode: todo!() };
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct RhiPublicationAuthority {
    mode: RhiPublicationMode,
    targets: Box<[RhiPublicationTarget]>,
    retry: Option<RhiPublicationRetryPolicy>,
    queue_capacity: u32,
    target_set_sha256: [u8; 32],
    authority_sha256: [u8; 32],
}

impl RhiPublicationAuthority {
    /// Derives the only publication authority from one complete admitted config.
    pub fn from_config(config: &RhiConfigDocumentV1) -> Result<Self, RhiPublicationError> {
        derive_authority(config.normalized())
    }

    /// Returns the explicit configured publication mode.
    #[must_use]
    pub const fn mode(&self) -> RhiPublicationMode {
        self.mode
    }

    /// Returns the immutable configured target inventory.
    #[must_use]
    pub fn targets(&self) -> &[RhiPublicationTarget] {
        &self.targets
    }

    /// Returns retry authority only when publication is required.
    #[must_use]
    pub const fn retry_policy(&self) -> Option<RhiPublicationRetryPolicy> {
        self.retry
    }

    /// Returns the configured durable publication queue bound.
    #[must_use]
    pub const fn queue_capacity(&self) -> u32 {
        self.queue_capacity
    }

    /// Returns the domain-separated immutable target-set identity.
    #[must_use]
    pub const fn target_set_sha256(&self) -> &[u8; 32] {
        &self.target_set_sha256
    }

    /// Returns the domain-separated identity of the complete publication authority.
    #[must_use]
    pub const fn authority_sha256(&self) -> &[u8; 32] {
        &self.authority_sha256
    }
}

impl fmt::Debug for RhiPublicationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPublicationAuthority")
            .field("mode", &self.mode)
            .field("target_count", &self.targets.len())
            .field("queue_capacity", &self.queue_capacity)
            .finish_non_exhaustive()
    }
}

/// Stable source-free publication-authority construction failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiPublicationErrorKind {
    InvalidConfiguration,
    TargetInventory,
}

impl RhiPublicationErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "publication_configuration_invalid",
            Self::TargetInventory => "publication_target_inventory_invalid",
        }
    }
}

/// Redacted source-free publication-authority failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiPublicationError {
    kind: RhiPublicationErrorKind,
}

impl RhiPublicationError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiPublicationErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiPublicationErrorKind::InvalidConfiguration => {
                "RHI publication configuration is invalid"
            }
            RhiPublicationErrorKind::TargetInventory => {
                "RHI publication target inventory is invalid"
            }
        })
    }
}

impl fmt::Debug for RhiPublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPublicationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiPublicationError {}

fn derive_authority(document: &Value) -> Result<RhiPublicationAuthority, RhiPublicationError> {
    let mode = match string(document, "/publication/mode")? {
        "required" => RhiPublicationMode::Required,
        "disabled" => RhiPublicationMode::Disabled,
        _ => return Err(failure(RhiPublicationErrorKind::InvalidConfiguration)),
    };
    let queue_capacity =
        integer(document, "/resource_limits/queues/publication").and_then(|value| {
            u32::try_from(value).map_err(|_| failure(RhiPublicationErrorKind::InvalidConfiguration))
        })?;
    if queue_capacity == 0 || queue_capacity > 65_536 {
        return Err(failure(RhiPublicationErrorKind::InvalidConfiguration));
    }

    let (targets, retry) = match mode {
        RhiPublicationMode::Disabled => {
            if document.pointer("/publication/target_relay_ids").is_some()
                || document.pointer("/publication/retry").is_some()
            {
                return Err(failure(RhiPublicationErrorKind::InvalidConfiguration));
            }
            (Vec::new(), None)
        }
        RhiPublicationMode::Required => {
            let target_ids = document
                .pointer("/publication/target_relay_ids")
                .and_then(Value::as_array)
                .ok_or_else(|| failure(RhiPublicationErrorKind::TargetInventory))?;
            if target_ids.is_empty() || target_ids.len() > RHI_PUBLICATION_MAX_TARGETS {
                return Err(failure(RhiPublicationErrorKind::TargetInventory));
            }
            let relays = document
                .pointer("/relays")
                .and_then(Value::as_array)
                .ok_or_else(|| failure(RhiPublicationErrorKind::TargetInventory))?;
            let mut targets = Vec::with_capacity(target_ids.len());
            for (ordinal, target_id) in target_ids.iter().enumerate() {
                let relay_id = target_id
                    .as_str()
                    .filter(|value| valid_relay_id(value))
                    .ok_or_else(|| failure(RhiPublicationErrorKind::TargetInventory))?;
                if targets
                    .iter()
                    .any(|target: &RhiPublicationTarget| target.relay_id() == relay_id)
                {
                    return Err(failure(RhiPublicationErrorKind::TargetInventory));
                }
                let relay = relays
                    .iter()
                    .find(|relay| relay.pointer("/id").and_then(Value::as_str) == Some(relay_id))
                    .ok_or_else(|| failure(RhiPublicationErrorKind::TargetInventory))?;
                if relay.pointer("/write").and_then(Value::as_bool) != Some(true) {
                    return Err(failure(RhiPublicationErrorKind::TargetInventory));
                }
                targets.push(RhiPublicationTarget {
                    ordinal: u8::try_from(ordinal)
                        .map_err(|_| failure(RhiPublicationErrorKind::TargetInventory))?,
                    relay_id: relay_id.into(),
                    required: relay
                        .pointer("/required")
                        .and_then(Value::as_bool)
                        .ok_or_else(|| failure(RhiPublicationErrorKind::TargetInventory))?,
                });
            }
            let maximum_attempts =
                integer(document, "/publication/retry/max_attempts").and_then(|value| {
                    u16::try_from(value)
                        .map_err(|_| failure(RhiPublicationErrorKind::InvalidConfiguration))
                })?;
            let retry = RhiPublicationRetryPolicy {
                maximum_attempts,
                initial_backoff_milliseconds: integer(
                    document,
                    "/publication/retry/initial_backoff_ms",
                )?,
                maximum_backoff_milliseconds: integer(
                    document,
                    "/publication/retry/maximum_backoff_ms",
                )?,
                attempt_deadline_milliseconds: integer(
                    document,
                    "/publication/retry/attempt_deadline_ms",
                )?,
            };
            if retry.maximum_attempts == 0
                || retry.maximum_attempts > RHI_PUBLICATION_MAX_ATTEMPTS
                || retry.initial_backoff_milliseconds == 0
                || retry.initial_backoff_milliseconds > retry.maximum_backoff_milliseconds
                || retry.maximum_backoff_milliseconds > 3_600_000
                || !(100..=30_000).contains(&retry.attempt_deadline_milliseconds)
            {
                return Err(failure(RhiPublicationErrorKind::InvalidConfiguration));
            }
            (targets, Some(retry))
        }
    };

    let target_set_sha256 = target_set_digest(&targets)?;
    let authority_sha256 = authority_digest(
        mode,
        &target_set_sha256,
        targets.len(),
        retry,
        queue_capacity,
    )?;
    Ok(RhiPublicationAuthority {
        mode,
        targets: targets.into_boxed_slice(),
        retry,
        queue_capacity,
        target_set_sha256,
        authority_sha256,
    })
}

fn target_set_digest(targets: &[RhiPublicationTarget]) -> Result<[u8; 32], RhiPublicationError> {
    let mut digest = Sha256::new();
    digest.update(TARGET_SET_DOMAIN);
    digest.update(
        u32::try_from(targets.len())
            .map_err(|_| failure(RhiPublicationErrorKind::TargetInventory))?
            .to_be_bytes(),
    );
    for target in targets {
        digest.update(u32::from(target.ordinal).to_be_bytes());
        digest.update(
            u64::try_from(target.relay_id.len())
                .map_err(|_| failure(RhiPublicationErrorKind::TargetInventory))?
                .to_be_bytes(),
        );
        digest.update(target.relay_id.as_bytes());
        digest.update([u8::from(target.required)]);
    }
    Ok(digest.finalize().into())
}

fn authority_digest(
    mode: RhiPublicationMode,
    target_set_sha256: &[u8; 32],
    target_count: usize,
    retry: Option<RhiPublicationRetryPolicy>,
    queue_capacity: u32,
) -> Result<[u8; 32], RhiPublicationError> {
    let mut digest = Sha256::new();
    digest.update(AUTHORITY_DOMAIN);
    digest.update([match mode {
        RhiPublicationMode::Disabled => 0,
        RhiPublicationMode::Required => 1,
    }]);
    digest.update(
        u32::try_from(target_count)
            .map_err(|_| failure(RhiPublicationErrorKind::TargetInventory))?
            .to_be_bytes(),
    );
    digest.update(target_set_sha256);
    match retry {
        Some(retry) => {
            digest.update([1]);
            digest.update(retry.maximum_attempts.to_be_bytes());
            digest.update(retry.initial_backoff_milliseconds.to_be_bytes());
            digest.update(retry.maximum_backoff_milliseconds.to_be_bytes());
            digest.update(retry.attempt_deadline_milliseconds.to_be_bytes());
        }
        None => digest.update([0]),
    }
    digest.update(queue_capacity.to_be_bytes());
    Ok(digest.finalize().into())
}

fn string<'a>(document: &'a Value, pointer: &str) -> Result<&'a str, RhiPublicationError> {
    document
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| failure(RhiPublicationErrorKind::InvalidConfiguration))
}

fn integer(document: &Value, pointer: &str) -> Result<u64, RhiPublicationError> {
    document
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| failure(RhiPublicationErrorKind::InvalidConfiguration))
}

fn valid_relay_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

const fn failure(kind: RhiPublicationErrorKind) -> RhiPublicationError {
    RhiPublicationError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RhiConfigProfile, parse_rhi_config_v1};

    const EXAMPLE: &[u8] = include_bytes!("../contracts/services_hardening/config.v1.example.toml");

    #[test]
    fn required_and_disabled_authority_are_exact_and_deterministic() {
        let config = parse_rhi_config_v1(EXAMPLE, RhiConfigProfile::Production).expect("config");
        let first = RhiPublicationAuthority::from_config(&config).expect("authority");
        let second = RhiPublicationAuthority::from_config(&config).expect("authority");
        assert_eq!(first, second);
        assert_eq!(first.mode(), RhiPublicationMode::Required);
        assert_eq!(first.queue_capacity(), 4_096);
        assert_eq!(first.targets().len(), 2);
        assert_eq!(first.targets()[0].ordinal(), 0);
        assert_eq!(first.targets()[0].relay_id(), "relay-primary");
        assert!(first.targets()[0].required());
        assert_eq!(first.targets()[1].ordinal(), 1);
        assert_eq!(first.targets()[1].relay_id(), "relay-secondary");
        assert!(!first.targets()[1].required());
        let retry = first.retry_policy().expect("required retry");
        assert_eq!(retry.maximum_attempts(), 10);
        assert_eq!(retry.initial_backoff_milliseconds(), 250);
        assert_eq!(retry.maximum_backoff_milliseconds(), 30_000);
        assert_eq!(retry.attempt_deadline_milliseconds(), 15_000);
        assert_ne!(first.target_set_sha256(), &[0; 32]);
        assert_ne!(first.authority_sha256(), &[0; 32]);

        let source = core::str::from_utf8(EXAMPLE).expect("utf8");
        let publication = source.find("[publication]").expect("publication section");
        let presence = source.find("[presence]").expect("presence section");
        let disabled = format!(
            "{}[publication]\nmode = \"disabled\"\n\n{}",
            &source[..publication],
            &source[presence..]
        );
        let config = parse_rhi_config_v1(disabled.as_bytes(), RhiConfigProfile::Production)
            .expect("disabled config");
        let disabled = RhiPublicationAuthority::from_config(&config).expect("disabled authority");
        assert_eq!(disabled.mode(), RhiPublicationMode::Disabled);
        assert!(disabled.targets().is_empty());
        assert_eq!(disabled.retry_policy(), None);
        assert_eq!(disabled.queue_capacity(), 4_096);
        assert_ne!(disabled.authority_sha256(), first.authority_sha256());
    }

    #[test]
    fn target_order_requiredness_and_retry_change_the_authority_digest() {
        let source = core::str::from_utf8(EXAMPLE).expect("utf8");
        let baseline = parse_rhi_config_v1(EXAMPLE, RhiConfigProfile::Production).expect("config");
        let baseline = RhiPublicationAuthority::from_config(&baseline).expect("authority");
        for changed in [
            source.replace(
                "target_relay_ids = [\"relay-primary\", \"relay-secondary\"]",
                "target_relay_ids = [\"relay-secondary\", \"relay-primary\"]",
            ),
            source.replacen("required = true", "required = false", 1),
            source.replace("max_attempts = 10", "max_attempts = 9"),
            source.replace("publication = 4096", "publication = 4095"),
        ] {
            let config = parse_rhi_config_v1(changed.as_bytes(), RhiConfigProfile::Production)
                .expect("changed config");
            let changed = RhiPublicationAuthority::from_config(&config).expect("authority");
            assert_ne!(changed.authority_sha256(), baseline.authority_sha256());
        }
    }

    #[test]
    fn public_diagnostics_are_source_free_and_redacted() {
        for kind in [
            RhiPublicationErrorKind::InvalidConfiguration,
            RhiPublicationErrorKind::TargetInventory,
        ] {
            let error = failure(kind);
            assert_eq!(error.kind(), kind);
            assert!(error.code().starts_with("publication_"));
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("relay-secret"));
            assert!(!rendered.contains("wss://"));
        }
    }
}
