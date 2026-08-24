//! Bounded relay-source ingestion with generation-fenced checkpoint commit.

use core::{cmp::Ordering, fmt};
use std::{collections::BTreeSet, error::Error};

use radroots_event::{SignedEvent, id::TradeId};
use radroots_service_host::UnixTimeSeconds;
use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use radroots_transport::{
    FetchRequest, Target, TargetSet,
    outcome::FetchTargetState,
    source::{FetchBounds, FetchCursor, FetchSelector, NextPage},
};
use serde_json::Value;
use sqlx::Row;

use crate::{
    RhiAdmittedTradeMutationEvent, RhiConfigDocumentV1, RhiEvidencePolicyDigest, RhiStateHostMode,
    RhiStateRepositories, RhiTradeMutationAdmissionLimits, RhiTradeMutationAuthoredTimePolicy,
    RhiTradeMutationObservedAtUnixSeconds, RhiTradeSourceObservation, RhiTransportAdapters,
    admit_rhi_trade_mutation_event, state_metadata,
    state_trade::{PersistenceOperationError, PersistenceRecord, persist},
};

/// Exact version of the RHI relay-source ingestion contract.
pub const RHI_TRADE_SOURCE_INGEST_CONTRACT_VERSION: u32 = 1;

/// Maximum distinct event identities admitted from one source attempt.
pub const RHI_TRADE_SOURCE_RESULT_MAX_EVENTS: usize = 4_096;

/// Maximum aggregate original event bytes admitted from one source attempt.
pub const RHI_TRADE_SOURCE_RESULT_MAX_BYTES: usize = 8 * 1024 * 1024;

const SOURCE_SELECTOR: &str = "trade_mutation_lineage_v1";
const FETCH_REQUEST_ID_MAX_BYTES: usize = 256;
const FETCH_PAGE_MAX_EVENTS: u16 = 1_000;
const EVENT_KINDS: [u32; 5] = [3470, 3471, 3472, 3473, 3474];

const READ_CHECKPOINT_SQL: &str = r#"SELECT
    cursor_created_at_unix_s,
    length(cursor_event_id) AS cursor_event_id_bytes,
    substr(cursor_event_id, 1, 33) AS cursor_event_id,
    revision,
    completed_at_unix_s
FROM relay_checkpoints
WHERE source_id = ? AND selector_id = ? AND evidence_policy_sha256 = ? AND trade_id = ?
LIMIT 1"#;
const INSERT_CHECKPOINT_SQL: &str = r#"INSERT INTO relay_checkpoints (
    source_id, selector_id, evidence_policy_sha256, trade_id,
    cursor_created_at_unix_s, cursor_event_id, revision, completed_at_unix_s
) VALUES (?, ?, ?, ?, ?, ?, 1, ?)"#;
const UPDATE_CHECKPOINT_SQL: &str = r#"UPDATE relay_checkpoints
SET cursor_created_at_unix_s = ?, cursor_event_id = ?,
    revision = revision + 1, completed_at_unix_s = ?
WHERE source_id = ? AND selector_id = ? AND evidence_policy_sha256 = ? AND trade_id = ?
    AND revision = ?"#;
const READ_DIRTY_SQL: &str = r#"SELECT generation,
    length(evidence_policy_sha256) AS evidence_policy_bytes,
    substr(evidence_policy_sha256, 1, 33) AS evidence_policy_sha256,
    updated_at_unix_s
FROM trade_dirty_generations
WHERE trade_id = ?
LIMIT 1"#;
const INSERT_DIRTY_SQL: &str = r#"INSERT INTO trade_dirty_generations (
    trade_id, generation, evidence_policy_sha256, updated_at_unix_s
) VALUES (?, 1, ?, ?)"#;
const UPDATE_DIRTY_SQL: &str = r#"UPDATE trade_dirty_generations
SET generation = generation + 1, evidence_policy_sha256 = ?, updated_at_unix_s = ?
WHERE trade_id = ? AND generation = ?"#;

/// Stable terminal classification for one exact relay-source attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiTradeSourceCompletion {
    Complete,
    IncompleteTimeout,
    IncompleteUnavailable,
    IncompleteResourceLimit,
    IncompleteUnknown,
    Unsupported,
}

impl RhiTradeSourceCompletion {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::IncompleteTimeout => "incomplete_timeout",
            Self::IncompleteUnavailable => "incomplete_unavailable",
            Self::IncompleteResourceLimit => "incomplete_resource_limit",
            Self::IncompleteUnknown => "incomplete_unknown",
            Self::Unsupported => "unsupported",
        }
    }

    #[must_use]
    pub(crate) const fn allows_checkpoint(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Monotonic per-trade invalidation generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RhiTradeDirtyGeneration(u64);

impl RhiTradeDirtyGeneration {
    /// Returns the positive durable generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Exact canonically admitted cursor tuple for one source scope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiTradeSourceCursor {
    created_at_unix_seconds: u64,
    event_id: [u8; 32],
}

impl RhiTradeSourceCursor {
    pub(crate) const fn from_verified_parts(
        created_at_unix_seconds: u64,
        event_id: [u8; 32],
    ) -> Self {
        Self {
            created_at_unix_seconds,
            event_id,
        }
    }

    /// Returns the inclusive event-authored UTC second.
    #[must_use]
    pub const fn created_at_unix_seconds(self) -> u64 {
        self.created_at_unix_seconds
    }

    /// Returns the exact verified Nostr event identifier bytes.
    #[must_use]
    pub const fn event_id(self) -> [u8; 32] {
        self.event_id
    }
}

impl fmt::Debug for RhiTradeSourceCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiTradeSourceCursor")
            .field("created_at_unix_seconds", &self.created_at_unix_seconds)
            .field("event_id", &"[redacted]")
            .finish()
    }
}

/// Caller-owned, injected timing and request evidence for one fetch attempt.
pub struct RhiTradeSourceAttempt {
    request_id: Box<str>,
    attempt_started_at: UnixTimeSeconds,
    observed_at: RhiTradeMutationObservedAtUnixSeconds,
    authored_time_policy: RhiTradeMutationAuthoredTimePolicy,
}

impl RhiTradeSourceAttempt {
    /// Validates a bounded request identity and explicit, ordered timestamps.
    pub fn new(
        request_id: impl AsRef<str>,
        attempt_started_at: UnixTimeSeconds,
        observed_at: RhiTradeMutationObservedAtUnixSeconds,
        authored_time_policy: RhiTradeMutationAuthoredTimePolicy,
    ) -> Result<Self, RhiTradeSourceIngestError> {
        let request_id = request_id.as_ref();
        if request_id.is_empty()
            || request_id.len() > FETCH_REQUEST_ID_MAX_BYTES
            || request_id != request_id.trim()
            || request_id.chars().any(char::is_control)
            || attempt_started_at.get() == 0
            || i64::try_from(attempt_started_at.get()).is_err()
            || observed_at.get() < attempt_started_at.get()
        {
            return Err(failure(RhiTradeSourceIngestErrorKind::InvalidInput));
        }
        Ok(Self {
            request_id: request_id.into(),
            attempt_started_at,
            observed_at,
            authored_time_policy,
        })
    }
}

impl fmt::Debug for RhiTradeSourceAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiTradeSourceAttempt")
            .field("request_id", &"[redacted]")
            .field("attempt_started_at", &self.attempt_started_at.get())
            .field("observed_at", &self.observed_at.get())
            .field("authored_time_policy", &self.authored_time_policy)
            .finish()
    }
}

/// Stable source-free relay-ingest failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiTradeSourceIngestErrorKind {
    InvalidMode,
    InvalidInput,
    InvalidConfiguration,
    GenerationConflict,
    Storage,
    CommitOutcomeUnknown,
}

impl RhiTradeSourceIngestErrorKind {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "trade_source_mode_invalid",
            Self::InvalidInput => "trade_source_input_invalid",
            Self::InvalidConfiguration => "trade_source_configuration_invalid",
            Self::GenerationConflict => "trade_source_generation_conflict",
            Self::Storage => "trade_source_storage_failed",
            Self::CommitOutcomeUnknown => "trade_source_commit_outcome_unknown",
        }
    }
}

/// Redacted source-free relay-ingest failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiTradeSourceIngestError {
    kind: RhiTradeSourceIngestErrorKind,
}

impl RhiTradeSourceIngestError {
    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> RhiTradeSourceIngestErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for RhiTradeSourceIngestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiTradeSourceIngestError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiTradeSourceIngestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiTradeSourceIngestErrorKind::InvalidMode => {
                "RHI trade-source ingestion requires writable state"
            }
            RhiTradeSourceIngestErrorKind::InvalidInput => {
                "RHI trade-source attempt input is invalid"
            }
            RhiTradeSourceIngestErrorKind::InvalidConfiguration => {
                "RHI trade-source configuration is invalid"
            }
            RhiTradeSourceIngestErrorKind::GenerationConflict => {
                "RHI trade-source generation changed during the attempt"
            }
            RhiTradeSourceIngestErrorKind::Storage => "RHI trade-source state transaction failed",
            RhiTradeSourceIngestErrorKind::CommitOutcomeUnknown => {
                "RHI trade-source commit outcome is unknown"
            }
        })
    }
}

impl Error for RhiTradeSourceIngestError {}

/// Durable outcome of one bounded source fetch and atomic evidence commit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiTradeSourceIngestOutcome {
    completion: RhiTradeSourceCompletion,
    received_events: u32,
    admitted_events: u32,
    rejected_events: u32,
    duplicate_events: u32,
    inserted_mutations: u32,
    inserted_signed_events: u32,
    inserted_observations: u32,
    checkpoint: Option<RhiTradeSourceCursor>,
    checkpoint_advanced: bool,
    dirty_generation: Option<RhiTradeDirtyGeneration>,
    dirty_generation_advanced: bool,
}

impl RhiTradeSourceIngestOutcome {
    #[must_use]
    pub const fn completion(self) -> RhiTradeSourceCompletion {
        self.completion
    }

    #[must_use]
    pub const fn received_events(self) -> u32 {
        self.received_events
    }

    #[must_use]
    pub const fn admitted_events(self) -> u32 {
        self.admitted_events
    }

    #[must_use]
    pub const fn rejected_events(self) -> u32 {
        self.rejected_events
    }

    #[must_use]
    pub const fn duplicate_events(self) -> u32 {
        self.duplicate_events
    }

    #[must_use]
    pub const fn inserted_mutations(self) -> u32 {
        self.inserted_mutations
    }

    #[must_use]
    pub const fn inserted_signed_events(self) -> u32 {
        self.inserted_signed_events
    }

    #[must_use]
    pub const fn inserted_observations(self) -> u32 {
        self.inserted_observations
    }

    #[must_use]
    pub const fn checkpoint(self) -> Option<RhiTradeSourceCursor> {
        self.checkpoint
    }

    #[must_use]
    pub const fn checkpoint_advanced(self) -> bool {
        self.checkpoint_advanced
    }

    #[must_use]
    pub const fn dirty_generation(self) -> Option<RhiTradeDirtyGeneration> {
        self.dirty_generation
    }

    #[must_use]
    pub const fn dirty_generation_advanced(self) -> bool {
        self.dirty_generation_advanced
    }
}

impl fmt::Debug for RhiTradeSourceIngestOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiTradeSourceIngestOutcome")
            .field("completion", &self.completion)
            .field("received_events", &self.received_events)
            .field("admitted_events", &self.admitted_events)
            .field("rejected_events", &self.rejected_events)
            .field("duplicate_events", &self.duplicate_events)
            .field("inserted_mutations", &self.inserted_mutations)
            .field("inserted_signed_events", &self.inserted_signed_events)
            .field("inserted_observations", &self.inserted_observations)
            .field("checkpoint", &self.checkpoint)
            .field("checkpoint_advanced", &self.checkpoint_advanced)
            .field("dirty_generation", &self.dirty_generation)
            .field("dirty_generation_advanced", &self.dirty_generation_advanced)
            .finish()
    }
}

/// Fetches one exact configured relay source and atomically commits admitted evidence.
pub async fn ingest_rhi_trade_source(
    repositories: &RhiStateRepositories<'_>,
    transports: &RhiTransportAdapters,
    configuration: &RhiConfigDocumentV1,
    source_id: &str,
    trade_id: TradeId,
    attempt: RhiTradeSourceAttempt,
) -> Result<RhiTradeSourceIngestOutcome, RhiTradeSourceIngestError> {
    let host = repositories.host();
    if host.mode() != RhiStateHostMode::ReadWriteExisting {
        return Err(failure(RhiTradeSourceIngestErrorKind::InvalidMode));
    }
    let source = ConfiguredSource::new(host, configuration, source_id)?;
    let initial = read_initial_state(repositories, &source, trade_id).await?;
    let fetched = fetch_source(transports, &source, trade_id, &attempt, initial.checkpoint).await?;
    commit_source_result(repositories, source, trade_id, attempt, initial, fetched).await
}

struct ConfiguredSource {
    source_id: Box<str>,
    relay_url: Box<str>,
    policy: RhiEvidencePolicyDigest,
    deadline_ms: u64,
    lookback_seconds: u64,
    overlap_seconds: u64,
    maximum_events: usize,
    maximum_bytes: usize,
    admission_limits: RhiTradeMutationAdmissionLimits,
}

impl ConfiguredSource {
    fn new(
        host: &crate::RhiStateHost,
        configuration: &RhiConfigDocumentV1,
        source_id: &str,
    ) -> Result<Self, RhiTradeSourceIngestError> {
        let normalized = configuration.normalized();
        let source = configured_source(normalized, source_id)
            .ok_or_else(|| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
        if source.pointer("/kind").and_then(Value::as_str) != Some("nostr_relay")
            || source.pointer("/selector").and_then(Value::as_str) != Some(SOURCE_SELECTOR)
        {
            return Err(failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration));
        }
        let relay_id = source
            .pointer("/relay_id")
            .and_then(Value::as_str)
            .ok_or_else(|| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
        let relay = normalized
            .pointer("/relays")
            .and_then(Value::as_array)
            .and_then(|relays| {
                relays
                    .iter()
                    .find(|relay| relay.pointer("/id").and_then(Value::as_str) == Some(relay_id))
            })
            .filter(|relay| relay.pointer("/read").and_then(Value::as_bool) == Some(true))
            .ok_or_else(|| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
        let relay_url = relay
            .pointer("/url")
            .and_then(Value::as_str)
            .ok_or_else(|| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
        let policy = state_metadata::evidence_policy_digest(normalized)
            .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
        if policy != host.metadata().evidence_policy_digest() {
            return Err(failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration));
        }
        let deadline_ms = exact_u64(source, "/deadline_ms", 100, 30_000)?;
        let lookback_seconds = exact_u64(source, "/lookback_seconds", 60, 2_678_400)?;
        let overlap_seconds = exact_u64(source, "/overlap_seconds", 1, 86_400)?;
        if overlap_seconds > lookback_seconds {
            return Err(failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration));
        }
        let maximum_events = exact_usize(
            normalized,
            "/resource_limits/source_results/events",
            1,
            RHI_TRADE_SOURCE_RESULT_MAX_EVENTS,
        )?;
        let maximum_bytes = exact_usize(
            normalized,
            "/resource_limits/source_results/bytes",
            1,
            RHI_TRADE_SOURCE_RESULT_MAX_BYTES,
        )?;
        Target::nostr_relay(relay_url)
            .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
        let admission_limits = RhiTradeMutationAdmissionLimits::from_config(configuration)
            .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
        Ok(Self {
            source_id: source_id.into(),
            relay_url: relay_url.into(),
            policy,
            deadline_ms,
            lookback_seconds,
            overlap_seconds,
            maximum_events,
            maximum_bytes,
            admission_limits,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Checkpoint {
    pub(crate) cursor: RhiTradeSourceCursor,
    pub(crate) revision: u64,
    pub(crate) completed_at_unix_s: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirtyState {
    pub(crate) generation: RhiTradeDirtyGeneration,
    pub(crate) policy: RhiEvidencePolicyDigest,
    pub(crate) updated_at_unix_s: u64,
}

#[derive(Clone, Copy)]
struct InitialState {
    checkpoint: Option<Checkpoint>,
    dirty: Option<DirtyState>,
}

struct Candidate {
    event: SignedEvent,
}

struct FetchedSource {
    completion: RhiTradeSourceCompletion,
    received_events: usize,
    duplicate_events: usize,
    admitted: Vec<RhiAdmittedTradeMutationEvent>,
    rejected_events: usize,
    cursor_candidate: Option<RhiTradeSourceCursor>,
}

async fn fetch_source(
    transports: &RhiTransportAdapters,
    source: &ConfiguredSource,
    trade_id: TradeId,
    attempt: &RhiTradeSourceAttempt,
    checkpoint: Option<Checkpoint>,
) -> Result<FetchedSource, RhiTradeSourceIngestError> {
    let deadline_unix_ms = attempt
        .attempt_started_at
        .get()
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(source.deadline_ms))
        .ok_or_else(|| failure(RhiTradeSourceIngestErrorKind::InvalidInput))?;
    let since = checkpoint.map_or_else(
        || {
            attempt
                .attempt_started_at
                .get()
                .saturating_sub(source.lookback_seconds)
        },
        |value| {
            value
                .cursor
                .created_at_unix_seconds
                .saturating_sub(source.overlap_seconds)
        },
    );
    let selector = FetchSelector::all()
        .with_kinds(EVENT_KINDS.to_vec())
        .and_then(|selector| selector.with_exact_tag_value('d', trade_id.to_hex()))
        .and_then(|selector| selector.with_since_unix_seconds(since))
        .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
    let target = Target::nostr_relay(source.relay_url.as_ref())
        .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
    let fingerprint = target.fingerprint().clone();
    let targets = TargetSet::new(vec![target])
        .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?;
    let mut adapter_cursor = None::<FetchCursor>;
    let mut seen_adapter_cursors = BTreeSet::new();
    let mut candidates = Vec::new();
    let mut received_events = 0_usize;
    let mut received_bytes = 0_usize;
    let completion = loop {
        let remaining = source.maximum_events.saturating_sub(received_events);
        let request_limit = usize::min(usize::from(FETCH_PAGE_MAX_EVENTS), remaining + 1);
        let bounds = FetchBounds::new(
            u16::try_from(request_limit)
                .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))?,
            deadline_unix_ms,
        )
        .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidInput))?;
        let mut request = FetchRequest::new(attempt.request_id.as_ref(), targets.clone(), bounds)
            .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidInput))?
            .with_selector(selector.clone());
        if let Some(cursor) = adapter_cursor.take() {
            request = request.with_cursor(cursor);
        }
        let page = match transports.evidence_source().fetch(request.clone()).await {
            Ok(page) => page,
            Err(radroots_transport::Error::UnsupportedOperation) => {
                break RhiTradeSourceCompletion::Unsupported;
            }
            Err(_) => break RhiTradeSourceCompletion::IncompleteUnknown,
        };
        if page.validate_for_request(&request).is_err() {
            break RhiTradeSourceCompletion::IncompleteUnknown;
        }
        let outcome = page
            .target_outcomes()
            .iter()
            .find(|outcome| outcome.target() == &fingerprint);
        let Some(outcome) = outcome.filter(|_| page.target_outcomes().len() == 1) else {
            break RhiTradeSourceCompletion::IncompleteUnknown;
        };
        let target_state = outcome.state();
        match target_state {
            FetchTargetState::Complete | FetchTargetState::Partial => {}
            FetchTargetState::Unavailable | FetchTargetState::FailedRetryable => {
                break RhiTradeSourceCompletion::IncompleteUnavailable;
            }
            FetchTargetState::FailedTerminal => {
                break RhiTradeSourceCompletion::IncompleteUnknown;
            }
            FetchTargetState::Cancelled => break RhiTradeSourceCompletion::IncompleteTimeout,
        }
        for observed in page.events() {
            received_events = received_events.saturating_add(1);
            if received_events > source.maximum_events {
                break;
            }
            received_bytes = match received_bytes.checked_add(observed.event().raw_json().len()) {
                Some(value) if value <= source.maximum_bytes => value,
                _ => {
                    received_events = source.maximum_events.saturating_add(1);
                    break;
                }
            };
            candidates.push(Candidate {
                event: observed.event().clone(),
            });
        }
        if received_events > source.maximum_events {
            break RhiTradeSourceCompletion::IncompleteResourceLimit;
        }
        if target_state == FetchTargetState::Partial {
            break RhiTradeSourceCompletion::IncompleteUnknown;
        }
        match page.next_page() {
            NextPage::Complete => break RhiTradeSourceCompletion::Complete,
            NextPage::Cancelled { .. } => break RhiTradeSourceCompletion::IncompleteTimeout,
            NextPage::Cursor(cursor) => {
                if page.events().is_empty()
                    || !seen_adapter_cursors.insert(cursor.as_str().to_owned())
                {
                    break RhiTradeSourceCompletion::IncompleteUnknown;
                }
                adapter_cursor = Some(cursor.clone());
            }
        }
    };

    candidates.sort_by(compare_candidate);
    let mut duplicate_events = 0_usize;
    let mut admitted_signed_event_ids = BTreeSet::new();
    let mut admitted = Vec::with_capacity(candidates.len());
    let mut rejected_events = 0_usize;
    let mut cursor_candidate = None;
    for candidate in candidates {
        match admit_rhi_trade_mutation_event(
            source.admission_limits,
            candidate.event.raw_json().as_bytes(),
            attempt.observed_at,
            attempt.authored_time_policy,
        ) {
            Ok(event) if event.mutation().trade_id == trade_id => {
                if !admitted_signed_event_ids
                    .insert((*event.event_id().as_bytes(), event.event_signature_bytes()))
                {
                    duplicate_events = duplicate_events.saturating_add(1);
                    continue;
                }
                let cursor = RhiTradeSourceCursor {
                    created_at_unix_seconds: event.authored_at_unix_seconds(),
                    event_id: *event.event_id().as_bytes(),
                };
                cursor_candidate = Some(cursor_candidate.map_or(cursor, |current| {
                    if compare_cursor(current, cursor).is_lt() {
                        cursor
                    } else {
                        current
                    }
                }));
                admitted.push(event);
            }
            Ok(_) | Err(_) => rejected_events = rejected_events.saturating_add(1),
        }
    }
    Ok(FetchedSource {
        completion,
        received_events: received_events.min(source.maximum_events),
        duplicate_events,
        admitted,
        rejected_events,
        cursor_candidate,
    })
}

async fn read_initial_state(
    repositories: &RhiStateRepositories<'_>,
    source: &ConfiguredSource,
    trade_id: TradeId,
) -> Result<InitialState, RhiTradeSourceIngestError> {
    let source_id = source.source_id.clone();
    let policy = source.policy;
    repositories
        .host()
        .sqlite_host()
        .transaction(move |transaction| {
            Box::pin(async move {
                Ok(InitialState {
                    checkpoint: read_checkpoint(transaction, source_id.as_ref(), policy, trade_id)
                        .await?,
                    dirty: read_dirty(transaction, trade_id).await?,
                })
            })
        })
        .await
        .map_err(map_transaction_error)
}

async fn commit_source_result(
    repositories: &RhiStateRepositories<'_>,
    source: ConfiguredSource,
    trade_id: TradeId,
    attempt: RhiTradeSourceAttempt,
    initial: InitialState,
    fetched: FetchedSource,
) -> Result<RhiTradeSourceIngestOutcome, RhiTradeSourceIngestError> {
    let source_id = source.source_id;
    let policy = source.policy;
    repositories
        .host()
        .sqlite_host()
        .transaction(move |transaction| {
            Box::pin(async move {
                if read_checkpoint(transaction, source_id.as_ref(), policy, trade_id).await?
                    != initial.checkpoint
                    || read_dirty(transaction, trade_id).await? != initial.dirty
                {
                    return Err(SourceOperationError::GenerationConflict);
                }
                let mut inserted_mutations = 0_u32;
                let mut inserted_signed_events = 0_u32;
                let mut inserted_observations = 0_u32;
                let admitted_events = u32::try_from(fetched.admitted.len())
                    .map_err(|_| SourceOperationError::Storage)?;
                for admitted in fetched.admitted {
                    let observation =
                        RhiTradeSourceObservation::from_parts(source_id.clone(), policy, &admitted);
                    let record = PersistenceRecord::from_admitted(admitted)
                        .map_err(|_| SourceOperationError::Storage)?;
                    let persisted = persist(transaction, &record, &observation)
                        .await
                        .map_err(SourceOperationError::Persistence)?;
                    inserted_mutations = inserted_mutations
                        .checked_add(u32::from(persisted.mutation_inserted()))
                        .ok_or(SourceOperationError::Storage)?;
                    inserted_signed_events = inserted_signed_events
                        .checked_add(u32::from(persisted.signed_event_inserted()))
                        .ok_or(SourceOperationError::Storage)?;
                    inserted_observations = inserted_observations
                        .checked_add(u32::from(persisted.observation_inserted()))
                        .ok_or(SourceOperationError::Storage)?;
                }
                let new_relevant_evidence = inserted_mutations != 0 || inserted_signed_events != 0;
                let (dirty_generation, dirty_generation_advanced) = if new_relevant_evidence {
                    let generation = advance_dirty_generation(
                        transaction,
                        trade_id,
                        policy,
                        attempt.observed_at.get(),
                        initial.dirty,
                    )
                    .await?;
                    (Some(generation), true)
                } else {
                    (initial.dirty.map(|dirty| dirty.generation), false)
                };
                let mut checkpoint = initial.checkpoint.map(|value| value.cursor);
                let mut checkpoint_advanced = false;
                if fetched.completion.allows_checkpoint()
                    && fetched.cursor_candidate.is_some_and(|candidate| {
                        initial
                            .checkpoint
                            .is_none_or(|current| compare_cursor(current.cursor, candidate).is_lt())
                    })
                {
                    let Some(candidate) = fetched.cursor_candidate else {
                        return Err(SourceOperationError::Storage);
                    };
                    write_checkpoint(
                        transaction,
                        source_id.as_ref(),
                        policy,
                        trade_id,
                        initial.checkpoint,
                        candidate,
                        attempt.observed_at.get(),
                    )
                    .await?;
                    checkpoint = Some(candidate);
                    checkpoint_advanced = true;
                }
                Ok(RhiTradeSourceIngestOutcome {
                    completion: fetched.completion,
                    received_events: u32::try_from(fetched.received_events)
                        .map_err(|_| SourceOperationError::Storage)?,
                    admitted_events,
                    rejected_events: u32::try_from(fetched.rejected_events)
                        .map_err(|_| SourceOperationError::Storage)?,
                    duplicate_events: u32::try_from(fetched.duplicate_events)
                        .map_err(|_| SourceOperationError::Storage)?,
                    inserted_mutations,
                    inserted_signed_events,
                    inserted_observations,
                    checkpoint,
                    checkpoint_advanced,
                    dirty_generation,
                    dirty_generation_advanced,
                })
            })
        })
        .await
        .map_err(map_transaction_error)
}

pub(crate) async fn advance_dirty_generation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    trade_id: TradeId,
    policy: RhiEvidencePolicyDigest,
    updated_at_unix_s: u64,
    expected: Option<DirtyState>,
) -> Result<RhiTradeDirtyGeneration, SourceOperationError> {
    let updated_at = i64::try_from(updated_at_unix_s).map_err(|_| SourceOperationError::Storage)?;
    match expected {
        None => {
            let result = sqlx::query(INSERT_DIRTY_SQL)
                .bind(trade_id.as_bytes().as_slice())
                .bind(policy.as_bytes().as_slice())
                .bind(updated_at)
                .execute(&mut *transaction)
                .await
                .map_err(|_| SourceOperationError::Storage)?;
            if result.rows_affected() != 1 {
                return Err(SourceOperationError::GenerationConflict);
            }
            Ok(RhiTradeDirtyGeneration(1))
        }
        Some(current)
            if current.policy == policy && updated_at_unix_s >= current.updated_at_unix_s =>
        {
            let next = current
                .generation
                .get()
                .checked_add(1)
                .filter(|value| i64::try_from(*value).is_ok())
                .ok_or(SourceOperationError::Storage)?;
            let result = sqlx::query(UPDATE_DIRTY_SQL)
                .bind(policy.as_bytes().as_slice())
                .bind(updated_at)
                .bind(trade_id.as_bytes().as_slice())
                .bind(
                    i64::try_from(current.generation.get())
                        .map_err(|_| SourceOperationError::Storage)?,
                )
                .execute(&mut *transaction)
                .await
                .map_err(|_| SourceOperationError::Storage)?;
            if result.rows_affected() != 1 {
                return Err(SourceOperationError::GenerationConflict);
            }
            Ok(RhiTradeDirtyGeneration(next))
        }
        Some(_) => Err(SourceOperationError::GenerationConflict),
    }
}

pub(crate) async fn read_dirty(
    transaction: &mut ServiceSqliteTransaction<'_>,
    trade_id: TradeId,
) -> Result<Option<DirtyState>, SourceOperationError> {
    let Some(row) = sqlx::query(READ_DIRTY_SQL)
        .bind(trade_id.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| SourceOperationError::Storage)?
    else {
        return Ok(None);
    };
    let generation = positive_i64_u64(&row, "generation")?;
    let policy = exact_digest(&row, "evidence_policy_sha256", "evidence_policy_bytes")?;
    let updated_at_unix_s = nonnegative_i64_u64(&row, "updated_at_unix_s")?;
    Ok(Some(DirtyState {
        generation: RhiTradeDirtyGeneration(generation),
        policy: RhiEvidencePolicyDigest::from_bytes(policy),
        updated_at_unix_s,
    }))
}

pub(crate) async fn read_checkpoint(
    transaction: &mut ServiceSqliteTransaction<'_>,
    source_id: &str,
    policy: RhiEvidencePolicyDigest,
    trade_id: TradeId,
) -> Result<Option<Checkpoint>, SourceOperationError> {
    let Some(row) = sqlx::query(READ_CHECKPOINT_SQL)
        .bind(source_id)
        .bind(SOURCE_SELECTOR)
        .bind(policy.as_bytes().as_slice())
        .bind(trade_id.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| SourceOperationError::Storage)?
    else {
        return Ok(None);
    };
    Ok(Some(Checkpoint {
        cursor: RhiTradeSourceCursor {
            created_at_unix_seconds: nonnegative_i64_u64(&row, "cursor_created_at_unix_s")?,
            event_id: exact_digest(&row, "cursor_event_id", "cursor_event_id_bytes")?,
        },
        revision: positive_i64_u64(&row, "revision")?,
        completed_at_unix_s: positive_i64_u64(&row, "completed_at_unix_s")?,
    }))
}

pub(crate) async fn write_checkpoint(
    transaction: &mut ServiceSqliteTransaction<'_>,
    source_id: &str,
    policy: RhiEvidencePolicyDigest,
    trade_id: TradeId,
    current: Option<Checkpoint>,
    next: RhiTradeSourceCursor,
    completed_at_unix_s: u64,
) -> Result<(), SourceOperationError> {
    let created_at =
        i64::try_from(next.created_at_unix_seconds).map_err(|_| SourceOperationError::Storage)?;
    let completed_at =
        i64::try_from(completed_at_unix_s).map_err(|_| SourceOperationError::Storage)?;
    let result = match current {
        None => {
            sqlx::query(INSERT_CHECKPOINT_SQL)
                .bind(source_id)
                .bind(SOURCE_SELECTOR)
                .bind(policy.as_bytes().as_slice())
                .bind(trade_id.as_bytes().as_slice())
                .bind(created_at)
                .bind(next.event_id.as_slice())
                .bind(completed_at)
                .execute(&mut *transaction)
                .await
        }
        Some(current) => {
            sqlx::query(UPDATE_CHECKPOINT_SQL)
                .bind(created_at)
                .bind(next.event_id.as_slice())
                .bind(completed_at)
                .bind(source_id)
                .bind(SOURCE_SELECTOR)
                .bind(policy.as_bytes().as_slice())
                .bind(trade_id.as_bytes().as_slice())
                .bind(i64::try_from(current.revision).map_err(|_| SourceOperationError::Storage)?)
                .execute(&mut *transaction)
                .await
        }
    }
    .map_err(|_| SourceOperationError::Storage)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(SourceOperationError::GenerationConflict)
    }
}

fn compare_candidate(left: &Candidate, right: &Candidate) -> Ordering {
    left.event
        .created_at()
        .cmp(&right.event.created_at())
        .then_with(|| left.event.id().as_bytes().cmp(right.event.id().as_bytes()))
        .then_with(|| {
            left.event
                .sig()
                .as_bytes()
                .cmp(right.event.sig().as_bytes())
        })
}

pub(crate) fn compare_cursor(left: RhiTradeSourceCursor, right: RhiTradeSourceCursor) -> Ordering {
    (left.created_at_unix_seconds, left.event_id)
        .cmp(&(right.created_at_unix_seconds, right.event_id))
}

fn configured_source<'a>(configuration: &'a Value, source_id: &str) -> Option<&'a Value> {
    if source_id.is_empty()
        || source_id.len() > 64
        || !source_id.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_lowercase()
            } else {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            }
        })
    {
        return None;
    }
    configuration
        .pointer("/evidence/sources")?
        .as_array()?
        .iter()
        .find(|source| source.pointer("/source_id").and_then(Value::as_str) == Some(source_id))
}

fn exact_u64(
    value: &Value,
    pointer: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, RhiTradeSourceIngestError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or_else(|| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))
}

fn exact_usize(
    value: &Value,
    pointer: &str,
    minimum: usize,
    maximum: usize,
) -> Result<usize, RhiTradeSourceIngestError> {
    exact_u64(
        value,
        pointer,
        u64::try_from(minimum).unwrap_or(u64::MAX),
        u64::try_from(maximum).unwrap_or(u64::MAX),
    )
    .and_then(|value| {
        usize::try_from(value)
            .map_err(|_| failure(RhiTradeSourceIngestErrorKind::InvalidConfiguration))
    })
}

fn exact_digest(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    length_field: &str,
) -> Result<[u8; 32], SourceOperationError> {
    if row.try_get::<i64, _>(length_field).ok() != Some(32) {
        return Err(SourceOperationError::Storage);
    }
    row.try_get::<Vec<u8>, _>(field)
        .map_err(|_| SourceOperationError::Storage)?
        .try_into()
        .map_err(|_| SourceOperationError::Storage)
}

fn positive_i64_u64(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
) -> Result<u64, SourceOperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .filter(|value| *value > 0)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(SourceOperationError::Storage)
}

fn nonnegative_i64_u64(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
) -> Result<u64, SourceOperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .filter(|value| *value >= 0)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(SourceOperationError::Storage)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceOperationError {
    GenerationConflict,
    Persistence(PersistenceOperationError),
    Storage,
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<SourceOperationError>,
) -> RhiTradeSourceIngestError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return failure(RhiTradeSourceIngestErrorKind::CommitOutcomeUnknown);
    }
    failure(match error.operation_error().copied() {
        Some(SourceOperationError::GenerationConflict) => {
            RhiTradeSourceIngestErrorKind::GenerationConflict
        }
        Some(SourceOperationError::Persistence(_)) | Some(SourceOperationError::Storage) | None => {
            RhiTradeSourceIngestErrorKind::Storage
        }
    })
}

const fn failure(kind: RhiTradeSourceIngestErrorKind) -> RhiTradeSourceIngestError {
    RhiTradeSourceIngestError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_timestamp_cursor_order_uses_verified_event_id() {
        let lower = RhiTradeSourceCursor {
            created_at_unix_seconds: 100,
            event_id: [0x11; 32],
        };
        let higher = RhiTradeSourceCursor {
            created_at_unix_seconds: 100,
            event_id: [0x22; 32],
        };
        assert_eq!(compare_cursor(lower, higher), Ordering::Less);
        assert_eq!(compare_cursor(higher, lower), Ordering::Greater);
        assert_eq!(compare_cursor(lower, lower), Ordering::Equal);
    }

    #[test]
    fn completion_codes_and_checkpoint_policy_are_closed() {
        let vectors = [
            (RhiTradeSourceCompletion::Complete, "complete", true),
            (
                RhiTradeSourceCompletion::IncompleteTimeout,
                "incomplete_timeout",
                false,
            ),
            (
                RhiTradeSourceCompletion::IncompleteUnavailable,
                "incomplete_unavailable",
                false,
            ),
            (
                RhiTradeSourceCompletion::IncompleteResourceLimit,
                "incomplete_resource_limit",
                false,
            ),
            (
                RhiTradeSourceCompletion::IncompleteUnknown,
                "incomplete_unknown",
                false,
            ),
            (RhiTradeSourceCompletion::Unsupported, "unsupported", false),
        ];
        for (completion, code, checkpoint) in vectors {
            assert_eq!(completion.code(), code);
            assert_eq!(completion.allows_checkpoint(), checkpoint);
        }
    }
}
