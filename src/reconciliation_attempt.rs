//! Pure bounded per-source reconciliation-attempt planning and result inventory.

use core::fmt;
use std::error::Error;

use sha2::{Digest, Sha256};

use crate::{
    RHI_TRADE_SOURCE_RESULT_MAX_BYTES, RHI_TRADE_SOURCE_RESULT_MAX_EVENTS, RhiConfigDocumentV1,
    RhiEvidencePolicyDigest, RhiReconciliationJobId, RhiReconciliationJobPolicy,
    RhiReconciliationJobState, RhiReconciliationLease, RhiReconciliationUnixMilliseconds,
    RhiTradeSourceCompletion, state_metadata,
};

/// Exact version of the per-source reconciliation-attempt contract.
pub const RHI_RECONCILIATION_ATTEMPT_CONTRACT_VERSION: u32 = 1;

/// Maximum configured sources represented by one attempt.
pub const RHI_RECONCILIATION_ATTEMPT_MAX_SOURCES: usize = 16;

const ATTEMPT_ID_DOMAIN: &[u8] = b"radroots.rhi.reconciliation_attempt.v1\0";
const SELECTOR_DIGEST_DOMAIN: &[u8] = b"radroots.rhi.reconciliation_selector.v1\0";
const REQUEST_ID_DOMAIN: &[u8] = b"radroots.rhi.reconciliation_source_request.v1\0";
const SOURCE_SELECTOR: &str = "trade_mutation_lineage_v1";
const SOURCE_KIND: &str = "nostr_relay";
const EVENT_KIND_COUNT: u32 = 5;
const EVENT_KINDS: [u32; 5] = [3470, 3471, 3472, 3473, 3474];
const _: [(); EVENT_KIND_COUNT as usize] = [(); EVENT_KINDS.len()];
const MAX_UNIX_MILLISECONDS: u64 = i64::MAX as u64;

/// Stable source-free attempt-model failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationAttemptErrorKind {
    InvalidInput,
    InvalidConfiguration,
    PolicyMismatch,
    LeaseExpired,
    ResultInventory,
}

impl RhiReconciliationAttemptErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "reconciliation_attempt_input_invalid",
            Self::InvalidConfiguration => "reconciliation_attempt_configuration_invalid",
            Self::PolicyMismatch => "reconciliation_attempt_policy_mismatch",
            Self::LeaseExpired => "reconciliation_attempt_lease_expired",
            Self::ResultInventory => "reconciliation_attempt_result_inventory_invalid",
        }
    }
}

/// Redacted source-free attempt-model failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationAttemptError {
    kind: RhiReconciliationAttemptErrorKind,
}

impl RhiReconciliationAttemptError {
    const fn new(kind: RhiReconciliationAttemptErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiReconciliationAttemptErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiReconciliationAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiReconciliationAttemptErrorKind::InvalidInput => {
                "RHI reconciliation attempt input is invalid"
            }
            RhiReconciliationAttemptErrorKind::InvalidConfiguration => {
                "RHI reconciliation attempt configuration is invalid"
            }
            RhiReconciliationAttemptErrorKind::PolicyMismatch => {
                "RHI reconciliation attempt policy does not match the claimed job"
            }
            RhiReconciliationAttemptErrorKind::LeaseExpired => {
                "RHI reconciliation attempt lease has expired"
            }
            RhiReconciliationAttemptErrorKind::ResultInventory => {
                "RHI reconciliation attempt result inventory is invalid"
            }
        })
    }
}

impl fmt::Debug for RhiReconciliationAttemptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationAttemptError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiReconciliationAttemptError {}

macro_rules! redacted_digest {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Returns the exact identity bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

redacted_digest!(
    RhiReconciliationAttemptId,
    "Domain-separated identity of one claimed reconciliation attempt."
);
redacted_digest!(
    RhiReconciliationSourceRequestId,
    "Domain-separated identity of one exact source request."
);
redacted_digest!(
    RhiReconciliationSourceSelectorDigest,
    "Domain-separated digest of the exact trade-mutation selector."
);

/// One exact configured source request within a claimed job attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct RhiReconciliationSourceRequest {
    id: RhiReconciliationSourceRequestId,
    source_id: Box<str>,
    trade_id: radroots_event::id::TradeId,
    required: bool,
    selector_digest: RhiReconciliationSourceSelectorDigest,
    attempt_started_at: RhiReconciliationUnixMilliseconds,
    deadline: RhiReconciliationUnixMilliseconds,
    lookback_seconds: u64,
    maximum_events: u32,
    maximum_bytes: u64,
}

impl RhiReconciliationSourceRequest {
    /// Returns the exact derived request identity.
    #[must_use]
    pub const fn id(&self) -> RhiReconciliationSourceRequestId {
        self.id
    }

    /// Returns the validated configured source ID.
    #[must_use]
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    /// Returns the exact trade selected by this request.
    #[must_use]
    pub const fn trade_id(&self) -> radroots_event::id::TradeId {
        self.trade_id
    }

    /// Reports whether this source is required by the evidence policy.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    /// Returns the exact base-selector digest.
    #[must_use]
    pub const fn selector_digest(&self) -> RhiReconciliationSourceSelectorDigest {
        self.selector_digest
    }

    /// Returns the injected attempt start in integer UTC milliseconds.
    #[must_use]
    pub const fn attempt_started_at(&self) -> RhiReconciliationUnixMilliseconds {
        self.attempt_started_at
    }

    /// Returns the absolute source deadline capped by attempt and lease expiry.
    #[must_use]
    pub const fn deadline(&self) -> RhiReconciliationUnixMilliseconds {
        self.deadline
    }

    /// Returns the configured initial lookback in whole seconds.
    #[must_use]
    pub const fn lookback_seconds(&self) -> u64 {
        self.lookback_seconds
    }

    /// Returns the configured maximum accepted event count.
    #[must_use]
    pub const fn maximum_events(&self) -> u32 {
        self.maximum_events
    }

    /// Returns the configured maximum accepted original-event bytes.
    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }
}

impl fmt::Debug for RhiReconciliationSourceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationSourceRequest")
            .field("identity", &"[redacted]")
            .field("required", &self.required)
            .field("attempt_started_at", &self.attempt_started_at)
            .field("deadline", &self.deadline)
            .field("lookback_seconds", &self.lookback_seconds)
            .field("maximum_events", &self.maximum_events)
            .field("maximum_bytes", &self.maximum_bytes)
            .finish()
    }
}

/// Canonically ordered per-source plan for one claimed durable job attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct RhiReconciliationAttemptPlan {
    id: RhiReconciliationAttemptId,
    job_id: RhiReconciliationJobId,
    input_generation: u64,
    policy_digest: RhiEvidencePolicyDigest,
    attempt_started_at: RhiReconciliationUnixMilliseconds,
    deadline: RhiReconciliationUnixMilliseconds,
    requests: Box<[RhiReconciliationSourceRequest]>,
}

impl RhiReconciliationAttemptPlan {
    /// Derives the complete bounded source plan from one unexpired claimed lease.
    pub fn from_claim(
        lease: RhiReconciliationLease,
        configuration: &RhiConfigDocumentV1,
        attempt_started_at: RhiReconciliationUnixMilliseconds,
    ) -> Result<Self, RhiReconciliationAttemptError> {
        let job = lease.job();
        if job.state() != RhiReconciliationJobState::Leased || job.attempt_count() == 0 {
            return Err(error(RhiReconciliationAttemptErrorKind::InvalidInput));
        }
        if attempt_started_at >= lease.lease_expires() {
            return Err(error(RhiReconciliationAttemptErrorKind::LeaseExpired));
        }
        let normalized = configuration.normalized();
        let policy_digest = state_metadata::evidence_policy_digest(normalized)
            .map_err(|_| error(RhiReconciliationAttemptErrorKind::InvalidConfiguration))?;
        if policy_digest != job.evidence_policy_digest() {
            return Err(error(RhiReconciliationAttemptErrorKind::PolicyMismatch));
        }
        let configured_job_policy =
            RhiReconciliationJobPolicy::from_configuration(configuration)
                .map_err(|_| error(RhiReconciliationAttemptErrorKind::InvalidConfiguration))?;
        if !job.attempt_policy_matches(configured_job_policy) {
            return Err(error(RhiReconciliationAttemptErrorKind::PolicyMismatch));
        }
        let attempt_deadline_ms = bounded_integer(
            normalized,
            "/reconciliation/attempt_deadline_ms",
            100,
            30_000,
        )?;
        let deadline = absolute_deadline(
            attempt_started_at,
            attempt_deadline_ms,
            lease.lease_expires(),
        )?;
        let maximum_events = bounded_integer(
            normalized,
            "/resource_limits/source_results/events",
            1,
            RHI_TRADE_SOURCE_RESULT_MAX_EVENTS as u64,
        )
        .and_then(|value| {
            u32::try_from(value)
                .map_err(|_| error(RhiReconciliationAttemptErrorKind::InvalidConfiguration))
        })?;
        let maximum_bytes = bounded_integer(
            normalized,
            "/resource_limits/source_results/bytes",
            1,
            RHI_TRADE_SOURCE_RESULT_MAX_BYTES as u64,
        )?;
        let sources = normalized
            .pointer("/evidence/sources")
            .and_then(serde_json::Value::as_array)
            .filter(|sources| {
                !sources.is_empty() && sources.len() <= RHI_RECONCILIATION_ATTEMPT_MAX_SOURCES
            })
            .ok_or_else(|| error(RhiReconciliationAttemptErrorKind::InvalidConfiguration))?;
        let id = attempt_id(job.id(), job.attempt_count());
        let selector_digest = selector_digest(job.trade_id());
        let mut requests = Vec::with_capacity(sources.len());
        let mut prior_source_id: Option<&str> = None;
        for source in sources {
            let source_id = bounded_source_id(source)?;
            if prior_source_id.is_some_and(|prior| prior >= source_id)
                || source.pointer("/kind").and_then(serde_json::Value::as_str) != Some(SOURCE_KIND)
                || source
                    .pointer("/selector")
                    .and_then(serde_json::Value::as_str)
                    != Some(SOURCE_SELECTOR)
            {
                return Err(error(
                    RhiReconciliationAttemptErrorKind::InvalidConfiguration,
                ));
            }
            prior_source_id = Some(source_id);
            let required = source
                .pointer("/required")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| error(RhiReconciliationAttemptErrorKind::InvalidConfiguration))?;
            let source_deadline_ms = bounded_integer(source, "/deadline_ms", 100, 30_000)?;
            if source_deadline_ms > attempt_deadline_ms {
                return Err(error(
                    RhiReconciliationAttemptErrorKind::InvalidConfiguration,
                ));
            }
            let source_deadline =
                absolute_deadline(attempt_started_at, source_deadline_ms, deadline)?;
            let lookback_seconds = bounded_integer(source, "/lookback_seconds", 60, 2_678_400)?;
            requests.push(RhiReconciliationSourceRequest {
                id: request_id(RequestIdentityMaterial {
                    attempt_id: id,
                    source_id,
                    required,
                    selector_digest,
                    attempt_started_at,
                    deadline: source_deadline,
                    lookback_seconds,
                    maximum_events,
                    maximum_bytes,
                }),
                source_id: source_id.into(),
                trade_id: job.trade_id(),
                required,
                selector_digest,
                attempt_started_at,
                deadline: source_deadline,
                lookback_seconds,
                maximum_events,
                maximum_bytes,
            });
        }
        Ok(Self {
            id,
            job_id: job.id(),
            input_generation: job.input_generation(),
            policy_digest,
            attempt_started_at,
            deadline,
            requests: requests.into_boxed_slice(),
        })
    }

    /// Returns the exact derived attempt identity.
    #[must_use]
    pub const fn id(&self) -> RhiReconciliationAttemptId {
        self.id
    }

    /// Returns the claimed durable job identity.
    #[must_use]
    pub const fn job_id(&self) -> RhiReconciliationJobId {
        self.job_id
    }

    /// Returns the exact dirty generation fenced by the claimed job.
    #[must_use]
    pub const fn input_generation(&self) -> u64 {
        self.input_generation
    }

    /// Returns the exact normalized evidence-policy digest.
    #[must_use]
    pub const fn evidence_policy_digest(&self) -> RhiEvidencePolicyDigest {
        self.policy_digest
    }

    /// Returns the injected attempt start in integer UTC milliseconds.
    #[must_use]
    pub const fn attempt_started_at(&self) -> RhiReconciliationUnixMilliseconds {
        self.attempt_started_at
    }

    /// Returns the absolute attempt deadline capped by lease expiry.
    #[must_use]
    pub const fn deadline(&self) -> RhiReconciliationUnixMilliseconds {
        self.deadline
    }

    /// Returns the canonical configured-source request inventory.
    #[must_use]
    pub fn requests(&self) -> &[RhiReconciliationSourceRequest] {
        &self.requests
    }
}

impl fmt::Debug for RhiReconciliationAttemptPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationAttemptPlan")
            .field("identity", &"[redacted]")
            .field("input_generation", &self.input_generation)
            .field("attempt_started_at", &self.attempt_started_at)
            .field("deadline", &self.deadline)
            .field("source_count", &self.requests.len())
            .finish()
    }
}

/// Bounded source result bound to one exact request identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationSourceResult {
    request_id: RhiReconciliationSourceRequestId,
    outcome: RhiTradeSourceCompletion,
    started_at: RhiReconciliationUnixMilliseconds,
    finished_at: RhiReconciliationUnixMilliseconds,
    accepted_event_count: u32,
    accepted_event_bytes: u64,
}

impl RhiReconciliationSourceResult {
    /// Validates exact timing and result bounds for one source request.
    pub fn new(
        request: &RhiReconciliationSourceRequest,
        outcome: RhiTradeSourceCompletion,
        started_at: RhiReconciliationUnixMilliseconds,
        finished_at: RhiReconciliationUnixMilliseconds,
        accepted_event_count: u32,
        accepted_event_bytes: u64,
    ) -> Result<Self, RhiReconciliationAttemptError> {
        let before_deadline = finished_at < request.deadline();
        if started_at < request.attempt_started_at()
            || started_at > finished_at
            || started_at >= request.deadline()
            || (outcome == RhiTradeSourceCompletion::IncompleteTimeout && before_deadline)
            || (outcome != RhiTradeSourceCompletion::IncompleteTimeout && !before_deadline)
            || accepted_event_count > request.maximum_events()
            || accepted_event_bytes > request.maximum_bytes()
            || (accepted_event_count == 0) != (accepted_event_bytes == 0)
            || (outcome == RhiTradeSourceCompletion::Unsupported
                && (accepted_event_count != 0 || accepted_event_bytes != 0))
        {
            return Err(error(RhiReconciliationAttemptErrorKind::InvalidInput));
        }
        Ok(Self {
            request_id: request.id(),
            outcome,
            started_at,
            finished_at,
            accepted_event_count,
            accepted_event_bytes,
        })
    }

    /// Returns the exact request identity this result satisfies.
    #[must_use]
    pub const fn request_id(self) -> RhiReconciliationSourceRequestId {
        self.request_id
    }

    /// Returns the stable terminal source-completion classification.
    #[must_use]
    pub const fn outcome(self) -> RhiTradeSourceCompletion {
        self.outcome
    }

    /// Returns the injected source-operation start in UTC milliseconds.
    #[must_use]
    pub const fn started_at(self) -> RhiReconciliationUnixMilliseconds {
        self.started_at
    }

    /// Returns the injected source-operation finish in UTC milliseconds.
    #[must_use]
    pub const fn finished_at(self) -> RhiReconciliationUnixMilliseconds {
        self.finished_at
    }

    /// Returns the bounded accepted event count.
    #[must_use]
    pub const fn accepted_event_count(self) -> u32 {
        self.accepted_event_count
    }

    /// Returns the bounded accepted original-event bytes.
    #[must_use]
    pub const fn accepted_event_bytes(self) -> u64 {
        self.accepted_event_bytes
    }
}

impl fmt::Debug for RhiReconciliationSourceResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationSourceResult")
            .field("request_id", &"[redacted]")
            .field("outcome", &self.outcome)
            .field("started_at", &self.started_at)
            .field("finished_at", &self.finished_at)
            .field("accepted_event_count", &self.accepted_event_count)
            .field("accepted_event_bytes", &self.accepted_event_bytes)
            .finish()
    }
}

/// Exact canonically ordered result inventory for one attempt plan.
#[derive(Clone, PartialEq, Eq)]
pub struct RhiReconciliationAttemptResults {
    attempt_id: RhiReconciliationAttemptId,
    results: Box<[RhiReconciliationSourceResult]>,
}

impl RhiReconciliationAttemptResults {
    /// Boundedly ingests exactly one result for each request in canonical order.
    pub fn new<I>(
        plan: &RhiReconciliationAttemptPlan,
        results: I,
    ) -> Result<Self, RhiReconciliationAttemptError>
    where
        I: IntoIterator<Item = RhiReconciliationSourceResult>,
    {
        let results = results
            .into_iter()
            .take(plan.requests.len().saturating_add(1))
            .collect::<Vec<_>>();
        if results.len() != plan.requests.len()
            || results
                .iter()
                .zip(plan.requests.iter())
                .any(|(result, request)| result.request_id != request.id)
        {
            return Err(error(RhiReconciliationAttemptErrorKind::ResultInventory));
        }
        Ok(Self {
            attempt_id: plan.id,
            results: results.into_boxed_slice(),
        })
    }

    /// Returns the exact attempt identity satisfied by this inventory.
    #[must_use]
    pub const fn attempt_id(&self) -> RhiReconciliationAttemptId {
        self.attempt_id
    }

    /// Returns the canonical exact result inventory.
    #[must_use]
    pub fn results(&self) -> &[RhiReconciliationSourceResult] {
        &self.results
    }
}

impl fmt::Debug for RhiReconciliationAttemptResults {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationAttemptResults")
            .field("attempt_id", &"[redacted]")
            .field("result_count", &self.results.len())
            .finish()
    }
}

fn bounded_source_id(source: &serde_json::Value) -> Result<&str, RhiReconciliationAttemptError> {
    source
        .pointer("/source_id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 64
                && value.bytes().enumerate().all(|(index, byte)| {
                    if index == 0 {
                        byte.is_ascii_lowercase()
                    } else {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-')
                    }
                })
        })
        .ok_or_else(|| error(RhiReconciliationAttemptErrorKind::InvalidConfiguration))
}

fn bounded_integer(
    value: &serde_json::Value,
    pointer: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, RhiReconciliationAttemptError> {
    value
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or_else(|| error(RhiReconciliationAttemptErrorKind::InvalidConfiguration))
}

fn absolute_deadline(
    started_at: RhiReconciliationUnixMilliseconds,
    duration_ms: u64,
    ceiling: RhiReconciliationUnixMilliseconds,
) -> Result<RhiReconciliationUnixMilliseconds, RhiReconciliationAttemptError> {
    let deadline = started_at
        .get()
        .checked_add(duration_ms)
        .filter(|value| *value <= MAX_UNIX_MILLISECONDS)
        .map(|value| value.min(ceiling.get()))
        .filter(|value| *value > started_at.get())
        .ok_or_else(|| error(RhiReconciliationAttemptErrorKind::InvalidInput))?;
    RhiReconciliationUnixMilliseconds::new(deadline)
        .map_err(|_| error(RhiReconciliationAttemptErrorKind::InvalidInput))
}

fn attempt_id(job_id: RhiReconciliationJobId, attempt_count: u16) -> RhiReconciliationAttemptId {
    let mut hasher = Sha256::new();
    hasher.update(ATTEMPT_ID_DOMAIN);
    hasher.update(job_id.as_bytes());
    hasher.update(attempt_count.to_be_bytes());
    RhiReconciliationAttemptId(hasher.finalize().into())
}

fn selector_digest(trade_id: radroots_event::id::TradeId) -> RhiReconciliationSourceSelectorDigest {
    let mut hasher = Sha256::new();
    hasher.update(SELECTOR_DIGEST_DOMAIN);
    hash_framed(&mut hasher, SOURCE_SELECTOR.as_bytes());
    hasher.update(EVENT_KIND_COUNT.to_be_bytes());
    for kind in EVENT_KINDS {
        hasher.update(kind.to_be_bytes());
    }
    hasher.update(b"d");
    hasher.update(trade_id.as_bytes());
    RhiReconciliationSourceSelectorDigest(hasher.finalize().into())
}

struct RequestIdentityMaterial<'source> {
    attempt_id: RhiReconciliationAttemptId,
    source_id: &'source str,
    required: bool,
    selector_digest: RhiReconciliationSourceSelectorDigest,
    attempt_started_at: RhiReconciliationUnixMilliseconds,
    deadline: RhiReconciliationUnixMilliseconds,
    lookback_seconds: u64,
    maximum_events: u32,
    maximum_bytes: u64,
}

fn request_id(material: RequestIdentityMaterial<'_>) -> RhiReconciliationSourceRequestId {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_ID_DOMAIN);
    hasher.update(material.attempt_id.as_bytes());
    hash_framed(&mut hasher, material.source_id.as_bytes());
    hasher.update([u8::from(material.required)]);
    hasher.update(material.selector_digest.as_bytes());
    hasher.update(material.attempt_started_at.get().to_be_bytes());
    hasher.update(material.deadline.get().to_be_bytes());
    hasher.update(material.lookback_seconds.to_be_bytes());
    hasher.update(material.maximum_events.to_be_bytes());
    hasher.update(material.maximum_bytes.to_be_bytes());
    RhiReconciliationSourceRequestId(hasher.finalize().into())
}

fn hash_framed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

const fn error(kind: RhiReconciliationAttemptErrorKind) -> RhiReconciliationAttemptError {
    RhiReconciliationAttemptError::new(kind)
}
