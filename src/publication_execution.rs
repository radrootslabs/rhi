//! Durable exact-byte publication claims, outcomes, retry, and recovery.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use radroots_transport::BoxFuture;
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;

use crate::{
    RHI_PUBLICATION_ATTEMPT_NUMBER_MAXIMUM, RHI_PUBLICATION_TARGET_ORDINAL_MAXIMUM,
    RhiCommittedPublication, RhiJitterBoundMilliseconds, RhiPublicationAttemptEvidence,
    RhiPublicationAttemptId, RhiPublicationAttemptOutcome, RhiPublicationAuthority,
    RhiPublicationMode, RhiPublicationOutboxId, RhiPublicationOutboxRepository,
    RhiPublicationTargetState, RhiPublicationUnixMilliseconds, RhiRuntimeAdapterErrorKind,
    RhiStateHostMode, RhiTimeEntropyAdapters,
    publication_attempt::derive_attempt_id,
    publication_submission::{ReadError, read_committed},
};

/// Exact version of the durable publication-execution contract.
pub const RHI_PUBLICATION_EXECUTION_CONTRACT_VERSION: u32 = 1;

const LEASE_OWNER_BYTES: usize = 16;
const MAX_UNIX_MILLISECONDS: u64 = i64::MAX as u64;
const TARGET_SET_DOMAIN: &[u8] = b"radroots.rhi.publication_target_set.v1\0";
const READ_OUTBOX_SQL: &str = r#"SELECT
    CASE WHEN typeof(outbox_id) = 'blob' AND length(outbox_id) = 32
        THEN outbox_id ELSE NULL END AS outbox_id,
    CASE WHEN typeof(event_sha256) = 'blob' AND length(event_sha256) = 32
        THEN event_sha256 ELSE NULL END AS event_sha256,
    CASE WHEN typeof(publication_authority_sha256) = 'blob'
            AND length(publication_authority_sha256) = 32
        THEN publication_authority_sha256 ELSE NULL END AS publication_authority_sha256,
    CASE WHEN typeof(target_set_sha256) = 'blob' AND length(target_set_sha256) = 32
        THEN target_set_sha256 ELSE NULL END AS target_set_sha256,
    target_count, required_target_count, max_attempts,
    initial_backoff_ms, maximum_backoff_ms, attempt_deadline_ms,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 9) AS state,
    revision, next_attempt_unix_ms,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE length(lease_owner) END AS lease_owner_bytes,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE substr(lease_owner, 1, 17) END AS lease_owner,
    lease_expires_unix_ms, created_at_unix_ms, updated_at_unix_ms
FROM publication_outbox
WHERE outbox_id = ?
LIMIT 2"#;

const READ_CLAIMABLE_OUTBOX_SQL: &str = r#"SELECT
    CASE WHEN typeof(outbox_id) = 'blob' AND length(outbox_id) = 32
        THEN outbox_id ELSE NULL END AS outbox_id,
    CASE WHEN typeof(event_sha256) = 'blob' AND length(event_sha256) = 32
        THEN event_sha256 ELSE NULL END AS event_sha256,
    CASE WHEN typeof(publication_authority_sha256) = 'blob'
            AND length(publication_authority_sha256) = 32
        THEN publication_authority_sha256 ELSE NULL END AS publication_authority_sha256,
    CASE WHEN typeof(target_set_sha256) = 'blob' AND length(target_set_sha256) = 32
        THEN target_set_sha256 ELSE NULL END AS target_set_sha256,
    target_count, required_target_count, max_attempts,
    initial_backoff_ms, maximum_backoff_ms, attempt_deadline_ms,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 9) AS state,
    revision, next_attempt_unix_ms,
    NULL AS lease_owner_bytes, NULL AS lease_owner,
    lease_expires_unix_ms, created_at_unix_ms, updated_at_unix_ms
FROM publication_outbox
WHERE state = 'pending' AND next_attempt_unix_ms <= ?
ORDER BY next_attempt_unix_ms, created_at_unix_ms, outbox_id
LIMIT 1"#;

const READ_EXPIRED_OUTBOX_SQL: &str = r#"SELECT
    CASE WHEN typeof(outbox_id) = 'blob' AND length(outbox_id) = 32
        THEN outbox_id ELSE NULL END AS outbox_id,
    CASE WHEN typeof(event_sha256) = 'blob' AND length(event_sha256) = 32
        THEN event_sha256 ELSE NULL END AS event_sha256,
    CASE WHEN typeof(publication_authority_sha256) = 'blob'
            AND length(publication_authority_sha256) = 32
        THEN publication_authority_sha256 ELSE NULL END AS publication_authority_sha256,
    CASE WHEN typeof(target_set_sha256) = 'blob' AND length(target_set_sha256) = 32
        THEN target_set_sha256 ELSE NULL END AS target_set_sha256,
    target_count, required_target_count, max_attempts,
    initial_backoff_ms, maximum_backoff_ms, attempt_deadline_ms,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 9) AS state,
    revision, next_attempt_unix_ms,
    length(lease_owner) AS lease_owner_bytes, substr(lease_owner, 1, 17) AS lease_owner,
    lease_expires_unix_ms, created_at_unix_ms, updated_at_unix_ms
FROM publication_outbox
WHERE state = 'leased' AND lease_expires_unix_ms <= ?
ORDER BY lease_expires_unix_ms, created_at_unix_ms, outbox_id
LIMIT 1"#;

const READ_TARGETS_SQL: &str = r#"SELECT target_ordinal,
    length(CAST(relay_id AS BLOB)) AS relay_id_bytes, substr(relay_id, 1, 65) AS relay_id,
    required,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 14) AS state,
    revision, attempt_count, next_attempt_unix_ms,
    CASE WHEN last_attempt_id IS NULL THEN NULL ELSE length(last_attempt_id) END
        AS last_attempt_id_bytes,
    CASE WHEN last_attempt_id IS NULL THEN NULL ELSE substr(last_attempt_id, 1, 33) END
        AS last_attempt_id,
    updated_at_unix_ms
FROM publication_targets
WHERE outbox_id = ?
ORDER BY target_ordinal
LIMIT 33"#;

const CLAIM_OUTBOX_SQL: &str = r#"UPDATE publication_outbox
SET state = 'leased', revision = revision + 1,
    next_attempt_unix_ms = NULL, lease_owner = ?, lease_expires_unix_ms = ?,
    updated_at_unix_ms = ?
WHERE outbox_id = ? AND revision = ? AND state = 'pending'
    AND next_attempt_unix_ms <= ? AND updated_at_unix_ms <= ?"#;

const PREPARE_TARGET_SQL: &str = r#"UPDATE publication_targets
SET state = 'submitted', revision = revision + 1,
    attempt_count = attempt_count + 1, next_attempt_unix_ms = NULL,
    last_attempt_id = ?, updated_at_unix_ms = ?
WHERE outbox_id = ? AND target_ordinal = ? AND revision = ?
    AND state IN ('pending', 'failed', 'rate_limited', 'unknown')
    AND attempt_count < ? AND next_attempt_unix_ms <= ?
    AND updated_at_unix_ms <= ?"#;

const INSERT_ATTEMPT_SQL: &str = r#"INSERT INTO publication_attempts (
    attempt_id, outbox_id, target_ordinal, attempt_number, event_sha256,
    lease_owner, started_at_unix_ms, finished_at_unix_ms, outcome, result_code
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#;

const READ_ATTEMPT_SQL: &str = r#"SELECT
    CASE WHEN typeof(attempt_id) = 'blob' AND length(attempt_id) = 32
        THEN attempt_id ELSE NULL END AS attempt_id,
    CASE WHEN typeof(outbox_id) = 'blob' AND length(outbox_id) = 32
        THEN outbox_id ELSE NULL END AS outbox_id,
    target_ordinal, attempt_number,
    CASE WHEN typeof(event_sha256) = 'blob' AND length(event_sha256) = 32
        THEN event_sha256 ELSE NULL END AS event_sha256,
    CASE WHEN typeof(lease_owner) = 'blob' AND length(lease_owner) = 16
        THEN lease_owner ELSE NULL END AS lease_owner,
    started_at_unix_ms, finished_at_unix_ms,
    length(CAST(outcome AS BLOB)) AS outcome_bytes, substr(outcome, 1, 14) AS outcome,
    length(CAST(result_code AS BLOB)) AS result_code_bytes,
    substr(result_code, 1, 65) AS result_code
FROM publication_attempts
WHERE attempt_id = ?
LIMIT 2"#;

const UPDATE_TARGET_OUTCOME_SQL: &str = r#"UPDATE publication_targets
SET state = ?, revision = revision + 1, next_attempt_unix_ms = ?,
    updated_at_unix_ms = ?
WHERE outbox_id = ? AND target_ordinal = ? AND revision = ?
    AND state = 'submitted' AND attempt_count = ? AND last_attempt_id = ?"#;

const UPDATE_OUTBOX_AFTER_ATTEMPT_SQL: &str = r#"UPDATE publication_outbox
SET state = ?, revision = revision + 1, next_attempt_unix_ms = ?,
    lease_owner = NULL, lease_expires_unix_ms = NULL, updated_at_unix_ms = ?
WHERE outbox_id = ? AND revision = ? AND state = 'leased'
    AND lease_owner = ? AND lease_expires_unix_ms = ?
    AND lease_expires_unix_ms > ? AND updated_at_unix_ms <= ?"#;

const UPDATE_OUTBOX_RECOVERY_SQL: &str = r#"UPDATE publication_outbox
SET state = ?, revision = revision + 1, next_attempt_unix_ms = ?,
    lease_owner = NULL, lease_expires_unix_ms = NULL, updated_at_unix_ms = ?
WHERE outbox_id = ? AND revision = ? AND state = 'leased'
    AND lease_owner = ? AND lease_expires_unix_ms = ?
    AND lease_expires_unix_ms <= ? AND updated_at_unix_ms <= ?"#;

/// Stable durable outbox lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiPublicationOutboxState {
    Pending,
    Leased,
    Complete,
    Blocked,
}

impl RhiPublicationOutboxState {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Complete => "complete",
            Self::Blocked => "blocked",
        }
    }
}

/// Stable source-free durable publication-execution failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiPublicationExecutionErrorKind {
    InvalidMode,
    InvalidInput,
    NotReady,
    LeaseLost,
    Invariant,
    ClockUnavailable,
    EntropyUnavailable,
    Storage,
    CommitOutcomeUnknown,
}

impl RhiPublicationExecutionErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "publication_execution_mode_invalid",
            Self::InvalidInput => "publication_execution_input_invalid",
            Self::NotReady => "publication_execution_not_ready",
            Self::LeaseLost => "publication_execution_lease_lost",
            Self::Invariant => "publication_execution_invariant_failed",
            Self::ClockUnavailable => "publication_execution_clock_unavailable",
            Self::EntropyUnavailable => "publication_execution_entropy_unavailable",
            Self::Storage => "publication_execution_storage_failed",
            Self::CommitOutcomeUnknown => "publication_execution_commit_outcome_unknown",
        }
    }
}

/// Redacted source-free durable publication-execution failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiPublicationExecutionError {
    kind: RhiPublicationExecutionErrorKind,
}

impl RhiPublicationExecutionError {
    const fn new(kind: RhiPublicationExecutionErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiPublicationExecutionErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiPublicationExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiPublicationExecutionErrorKind::InvalidMode => {
                "RHI publication execution requires writable state"
            }
            RhiPublicationExecutionErrorKind::InvalidInput => {
                "RHI publication execution input is invalid"
            }
            RhiPublicationExecutionErrorKind::NotReady => "RHI publication work is not ready",
            RhiPublicationExecutionErrorKind::LeaseLost => {
                "RHI publication lease is no longer authoritative"
            }
            RhiPublicationExecutionErrorKind::Invariant => "RHI publication state invariant failed",
            RhiPublicationExecutionErrorKind::ClockUnavailable => {
                "RHI publication clock is unavailable"
            }
            RhiPublicationExecutionErrorKind::EntropyUnavailable => {
                "RHI publication retry entropy is unavailable"
            }
            RhiPublicationExecutionErrorKind::Storage => "RHI publication transaction failed",
            RhiPublicationExecutionErrorKind::CommitOutcomeUnknown => {
                "RHI publication commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for RhiPublicationExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPublicationExecutionError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiPublicationExecutionError {}

/// Stable process-local owner token for one compare-and-swap publication lease.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiPublicationLeaseOwner([u8; LEASE_OWNER_BYTES]);

impl RhiPublicationLeaseOwner {
    /// Validates one injected nonzero lease-owner identity.
    pub fn from_bytes(
        bytes: [u8; LEASE_OWNER_BYTES],
    ) -> Result<Self, RhiPublicationExecutionError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RhiPublicationExecutionError::new(
                RhiPublicationExecutionErrorKind::InvalidInput,
            ));
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for RhiPublicationLeaseOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiPublicationLeaseOwner([redacted])")
    }
}

/// Bounded caller-injected retry delay in whole milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RhiPublicationRetryDelayMilliseconds(u64);

impl RhiPublicationRetryDelayMilliseconds {
    /// Validates a delay against the absolute publication backoff ceiling.
    pub fn new(value: u64) -> Result<Self, RhiPublicationExecutionError> {
        if value > 3_600_000 {
            return Err(RhiPublicationExecutionError::new(
                RhiPublicationExecutionErrorKind::InvalidInput,
            ));
        }
        Ok(Self(value))
    }

    /// Returns the exact delay.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Non-forgeable compare-and-swap authority for one claimed outbox.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiPublicationLease {
    outbox: OutboxRecord,
    owner: RhiPublicationLeaseOwner,
    expires_at: RhiPublicationUnixMilliseconds,
}

impl RhiPublicationLease {
    /// Returns the exact claimed outbox identity.
    #[must_use]
    pub const fn outbox_id(self) -> RhiPublicationOutboxId {
        self.outbox.id
    }

    /// Returns the exact lease expiry.
    #[must_use]
    pub const fn expires_at(self) -> RhiPublicationUnixMilliseconds {
        self.expires_at
    }
}

impl fmt::Debug for RhiPublicationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPublicationLease")
            .field("outbox", &"[redacted]")
            .field("revision", &self.outbox.revision)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Sealed exact-byte remote submission prepared only after durable Submitted.
#[must_use = "prepared publication must be executed exactly or left for unknown recovery"]
pub struct RhiPreparedPublicationAttempt {
    lease: RhiPublicationLease,
    target: TargetRecord,
    attempt_id: RhiPublicationAttemptId,
    started_at: RhiPublicationUnixMilliseconds,
    deadline_at: RhiPublicationUnixMilliseconds,
    publication: RhiCommittedPublication,
}

impl RhiPreparedPublicationAttempt {
    /// Returns the exact attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> RhiPublicationAttemptId {
        self.attempt_id
    }

    /// Returns the stable configured relay identity without an endpoint or secret.
    #[must_use]
    pub fn relay_id(&self) -> &str {
        &self.target.relay_id
    }

    /// Returns the exact committed signed-event bytes with no transformation.
    #[must_use]
    pub const fn exact_signed_event_bytes(&self) -> &[u8] {
        self.publication.exact_signed_event_bytes()
    }

    /// Returns the absolute attempt deadline.
    #[must_use]
    pub const fn deadline_at(&self) -> RhiPublicationUnixMilliseconds {
        self.deadline_at
    }

    /// Returns the one-based durable attempt number.
    #[must_use]
    pub const fn attempt_number(&self) -> u16 {
        self.target.attempt_count
    }

    fn retry_upper_bound(&self) -> u64 {
        retry_upper_bound(self.lease.outbox, self.target.attempt_count)
    }
}

impl fmt::Debug for RhiPreparedPublicationAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPreparedPublicationAttempt")
            .field("identity", &"[redacted]")
            .field("target_ordinal", &self.target.ordinal)
            .field("attempt_number", &self.target.attempt_count)
            .field("deadline_at", &self.deadline_at)
            .finish()
    }
}

/// Closed exact-byte transport boundary used by the durable executor.
///
/// The adapter receives the original committed payload and must submit that
/// byte slice unchanged. Dropping the future after durable preparation leaves
/// Submitted evidence; expired-lease recovery records Unknown before retry.
pub trait RhiExactPublicationSink: Send + Sync {
    /// Submits one exact prepared payload and returns only a closed observation.
    fn submit_exact<'a>(
        &'a self,
        attempt: &'a RhiPreparedPublicationAttempt,
    ) -> BoxFuture<'a, RhiPublicationAttemptOutcome>;
}

/// Confirmed durable result for one exact publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiPublicationAttemptCommit {
    outbox_id: RhiPublicationOutboxId,
    attempt_id: RhiPublicationAttemptId,
    target_ordinal: u8,
    attempt_number: u16,
    outcome: RhiPublicationAttemptOutcome,
    target_state: RhiPublicationTargetState,
    outbox_state: RhiPublicationOutboxState,
}

impl RhiPublicationAttemptCommit {
    #[must_use]
    pub const fn outbox_id(self) -> RhiPublicationOutboxId {
        self.outbox_id
    }

    #[must_use]
    pub const fn attempt_id(self) -> RhiPublicationAttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn target_ordinal(self) -> u8 {
        self.target_ordinal
    }

    #[must_use]
    pub const fn attempt_number(self) -> u16 {
        self.attempt_number
    }

    #[must_use]
    pub const fn outcome(self) -> RhiPublicationAttemptOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn target_state(self) -> RhiPublicationTargetState {
        self.target_state
    }

    #[must_use]
    pub const fn outbox_state(self) -> RhiPublicationOutboxState {
        self.outbox_state
    }
}

impl RhiPublicationOutboxRepository<'_> {
    /// Claims the oldest due outbox using one injected owner and wall time.
    pub async fn claim_next_publication(
        &self,
        owner: RhiPublicationLeaseOwner,
        now: RhiPublicationUnixMilliseconds,
        authority: &RhiPublicationAuthority,
    ) -> Result<Option<RhiPublicationLease>, RhiPublicationExecutionError> {
        require_writable(self)?;
        let Some(authority) = AuthorityBinding::from_authority(authority) else {
            return Ok(None);
        };
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { claim_next(transaction, owner, now, authority).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Persists Submitted before exposing exact bytes to remote I/O.
    pub async fn prepare_next_publication_target(
        &self,
        lease: RhiPublicationLease,
        started_at: RhiPublicationUnixMilliseconds,
    ) -> Result<RhiPreparedPublicationAttempt, RhiPublicationExecutionError> {
        require_writable(self)?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { prepare_next(transaction, lease, started_at).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Commits one closed observed outcome by exact compare-and-swap.
    pub async fn record_publication_outcome(
        &self,
        prepared: &RhiPreparedPublicationAttempt,
        finished_at: RhiPublicationUnixMilliseconds,
        outcome: RhiPublicationAttemptOutcome,
        retry_delay: RhiPublicationRetryDelayMilliseconds,
    ) -> Result<RhiPublicationAttemptCommit, RhiPublicationExecutionError> {
        require_writable(self)?;
        let input = RecordInput::from_prepared(prepared, finished_at, outcome, retry_delay)?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { record_outcome(transaction, input).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Recovers at most one expired lease and persists Unknown for Submitted work.
    pub async fn recover_one_expired_publication(
        &self,
        adapters: &RhiTimeEntropyAdapters,
        now: RhiPublicationUnixMilliseconds,
        authority: &RhiPublicationAuthority,
    ) -> Result<bool, RhiPublicationExecutionError> {
        require_writable(self)?;
        let Some(authority) = AuthorityBinding::from_authority(authority) else {
            return Ok(false);
        };
        let candidate = self
            .host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { read_expired_candidate(transaction, now, authority).await })
            })
            .await
            .map_err(map_transaction_error)?;
        let Some(candidate) = candidate else {
            return Ok(false);
        };
        let cap = candidate.retry_upper_bound;
        let delay = sample_retry_delay(adapters, cap)?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { recover_expired(transaction, candidate, now, delay).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Executes at most one exact-byte attempt through the injected sink.
    ///
    /// Cancellation before a claim has no effect. Cancellation after durable
    /// preparation leaves Submitted state; lease-expiry recovery records
    /// Unknown and schedules the exact same committed bytes without rebuilding.
    pub async fn execute_next_publication(
        &self,
        owner: RhiPublicationLeaseOwner,
        adapters: &RhiTimeEntropyAdapters,
        sink: &dyn RhiExactPublicationSink,
        authority: &RhiPublicationAuthority,
    ) -> Result<Option<RhiPublicationAttemptCommit>, RhiPublicationExecutionError> {
        let now = publication_now(adapters)?;
        self.recover_one_expired_publication(adapters, now, authority)
            .await?;
        let Some(lease) = self.claim_next_publication(owner, now, authority).await? else {
            return Ok(None);
        };
        let prepared = self.prepare_next_publication_target(lease, now).await?;
        let outcome = match sink.submit_exact(&prepared).await {
            RhiPublicationAttemptOutcome::Submitted => RhiPublicationAttemptOutcome::Unknown,
            outcome => outcome,
        };
        let finished_at = publication_now(adapters)?;
        let retry_delay = if retryable_outcome(outcome) {
            sample_retry_delay(adapters, prepared.retry_upper_bound())?
        } else {
            RhiPublicationRetryDelayMilliseconds(0)
        };
        self.record_publication_outcome(&prepared, finished_at, outcome, retry_delay)
            .await
            .map(Some)
    }
}

fn require_writable(
    repository: &RhiPublicationOutboxRepository<'_>,
) -> Result<(), RhiPublicationExecutionError> {
    if repository.host().mode() == RhiStateHostMode::ReadWriteExisting {
        Ok(())
    } else {
        Err(RhiPublicationExecutionError::new(
            RhiPublicationExecutionErrorKind::InvalidMode,
        ))
    }
}

fn publication_now(
    adapters: &RhiTimeEntropyAdapters,
) -> Result<RhiPublicationUnixMilliseconds, RhiPublicationExecutionError> {
    let value = adapters.now_utc_milliseconds().map_err(|error| {
        RhiPublicationExecutionError::new(match error.kind() {
            RhiRuntimeAdapterErrorKind::WallClockUnavailable => {
                RhiPublicationExecutionErrorKind::ClockUnavailable
            }
            _ => RhiPublicationExecutionErrorKind::ClockUnavailable,
        })
    })?;
    RhiPublicationUnixMilliseconds::new(value).map_err(|_| {
        RhiPublicationExecutionError::new(RhiPublicationExecutionErrorKind::ClockUnavailable)
    })
}

fn sample_retry_delay(
    adapters: &RhiTimeEntropyAdapters,
    cap: u64,
) -> Result<RhiPublicationRetryDelayMilliseconds, RhiPublicationExecutionError> {
    if cap == 0 {
        return Ok(RhiPublicationRetryDelayMilliseconds(0));
    }
    let bound = RhiJitterBoundMilliseconds::new(cap).map_err(|_| {
        RhiPublicationExecutionError::new(RhiPublicationExecutionErrorKind::InvalidInput)
    })?;
    adapters
        .sample_full_jitter(bound)
        .map(|delay| RhiPublicationRetryDelayMilliseconds(delay.get()))
        .map_err(|_| {
            RhiPublicationExecutionError::new(RhiPublicationExecutionErrorKind::EntropyUnavailable)
        })
}

async fn claim_next(
    transaction: &mut ServiceSqliteTransaction<'_>,
    owner: RhiPublicationLeaseOwner,
    now: RhiPublicationUnixMilliseconds,
    authority: AuthorityBinding,
) -> Result<Option<RhiPublicationLease>, OperationError> {
    let rows = sqlx::query(READ_CLAIMABLE_OUTBOX_SQL)
        .bind(i64_value(now.get())?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    let Some(row) = exactly_zero_or_one(rows)? else {
        return Ok(None);
    };
    let outbox = decode_outbox(row)?;
    validate_authority(outbox, authority)?;
    validate_target_inventory(transaction, outbox).await?;
    let expires = now
        .get()
        .checked_add(outbox.attempt_deadline_ms)
        .filter(|value| *value <= MAX_UNIX_MILLISECONDS)
        .ok_or(OperationError::InvalidInput)?;
    let result = sqlx::query(CLAIM_OUTBOX_SQL)
        .bind(owner.0.as_slice())
        .bind(i64_value(expires)?)
        .bind(i64_value(now.get())?)
        .bind(outbox.id.as_bytes().as_slice())
        .bind(i64_value(outbox.revision)?)
        .bind(i64_value(now.get())?)
        .bind(i64_value(now.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::LeaseLost);
    }
    let leased = read_outbox(transaction, outbox.id)
        .await?
        .filter(|record| {
            record.state == RhiPublicationOutboxState::Leased
                && record.lease_owner == Some(owner)
                && record.lease_expires == Some(RhiPublicationUnixMilliseconds(expires))
        })
        .ok_or(OperationError::Invariant)?;
    Ok(Some(RhiPublicationLease {
        outbox: leased,
        owner,
        expires_at: RhiPublicationUnixMilliseconds(expires),
    }))
}

async fn prepare_next(
    transaction: &mut ServiceSqliteTransaction<'_>,
    lease: RhiPublicationLease,
    started_at: RhiPublicationUnixMilliseconds,
) -> Result<RhiPreparedPublicationAttempt, OperationError> {
    validate_lease(transaction, lease, started_at, true).await?;
    let targets = read_targets(transaction, lease.outbox.id).await?;
    validate_targets(lease.outbox, &targets)?;
    let candidate = targets
        .into_iter()
        .find(|target| target_is_due(target, lease.outbox.max_attempts, started_at))
        .ok_or(OperationError::NotReady)?;
    let attempt_number = candidate
        .attempt_count
        .checked_add(1)
        .filter(|value| *value <= lease.outbox.max_attempts)
        .ok_or(OperationError::Invariant)?;
    let attempt_id = derive_attempt_id(
        lease.outbox.id,
        lease.outbox.event_sha256,
        candidate.ordinal,
        attempt_number,
    );
    let result = sqlx::query(PREPARE_TARGET_SQL)
        .bind(attempt_id.as_bytes().as_slice())
        .bind(i64_value(started_at.get())?)
        .bind(lease.outbox.id.as_bytes().as_slice())
        .bind(i64::from(candidate.ordinal))
        .bind(i64_value(candidate.revision)?)
        .bind(i64::from(lease.outbox.max_attempts))
        .bind(i64_value(started_at.get())?)
        .bind(i64_value(started_at.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::LeaseLost);
    }
    let target = read_targets(transaction, lease.outbox.id)
        .await?
        .into_iter()
        .find(|target| target.ordinal == candidate.ordinal)
        .filter(|target| {
            target.state == RhiPublicationTargetState::Submitted
                && target.attempt_count == attempt_number
                && target.last_attempt_id == Some(attempt_id)
        })
        .ok_or(OperationError::Invariant)?;
    let publication = read_committed(transaction, lease.outbox.id)
        .await
        .map_err(|error| match error {
            ReadError::Storage => OperationError::Storage,
            ReadError::NotFound | ReadError::Binding => OperationError::Invariant,
        })?;
    if publication.event_sha256() != &lease.outbox.event_sha256 {
        return Err(OperationError::Invariant);
    }
    Ok(RhiPreparedPublicationAttempt {
        lease,
        target,
        attempt_id,
        started_at,
        deadline_at: lease.expires_at,
        publication,
    })
}

async fn record_outcome(
    transaction: &mut ServiceSqliteTransaction<'_>,
    input: RecordInput,
) -> Result<RhiPublicationAttemptCommit, OperationError> {
    if let Some(existing) = read_attempt(transaction, input.attempt_id).await? {
        return reconcile_recorded(transaction, input, existing).await;
    }
    validate_lease(transaction, input.lease, input.finished_at, true).await?;
    let target = read_targets(transaction, input.lease.outbox.id)
        .await?
        .into_iter()
        .find(|target| target.ordinal == input.target_ordinal)
        .ok_or(OperationError::Invariant)?;
    if target.state != RhiPublicationTargetState::Submitted
        || target.revision != input.target_revision
        || target.attempt_count != input.attempt_number
        || target.last_attempt_id != Some(input.attempt_id)
        || target.updated_at != input.started_at
    {
        return Err(OperationError::LeaseLost);
    }
    insert_attempt(transaction, input).await?;
    let (next_state, next_attempt) = target_outcome_schedule(input)?;
    let result = sqlx::query(UPDATE_TARGET_OUTCOME_SQL)
        .bind(next_state.code())
        .bind(optional_i64(next_attempt)?)
        .bind(i64_value(input.finished_at.get())?)
        .bind(input.lease.outbox.id.as_bytes().as_slice())
        .bind(i64::from(input.target_ordinal))
        .bind(i64_value(input.target_revision)?)
        .bind(i64::from(input.attempt_number))
        .bind(input.attempt_id.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::LeaseLost);
    }
    let targets = read_targets(transaction, input.lease.outbox.id).await?;
    let disposition = disposition(input.lease.outbox, &targets)?;
    update_outbox_after_attempt(transaction, input, disposition).await?;
    Ok(RhiPublicationAttemptCommit {
        outbox_id: input.lease.outbox.id,
        attempt_id: input.attempt_id,
        target_ordinal: input.target_ordinal,
        attempt_number: input.attempt_number,
        outcome: input.outcome,
        target_state: next_state,
        outbox_state: disposition.state,
    })
}

async fn read_expired_candidate(
    transaction: &mut ServiceSqliteTransaction<'_>,
    now: RhiPublicationUnixMilliseconds,
    authority: AuthorityBinding,
) -> Result<Option<RecoveryCandidate>, OperationError> {
    let rows = sqlx::query(READ_EXPIRED_OUTBOX_SQL)
        .bind(i64_value(now.get())?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    let Some(row) = exactly_zero_or_one(rows)? else {
        return Ok(None);
    };
    let outbox = decode_outbox(row)?;
    validate_authority(outbox, authority)?;
    let targets = read_targets(transaction, outbox.id).await?;
    validate_targets(outbox, &targets)?;
    let submitted_attempts: Vec<_> = targets
        .iter()
        .filter(|target| target.state == RhiPublicationTargetState::Submitted)
        .map(|target| target.attempt_count)
        .collect();
    if submitted_attempts.len() > 1 {
        return Err(OperationError::Invariant);
    }
    let retry_upper_bound = submitted_attempts
        .first()
        .copied()
        .filter(|attempt| *attempt < outbox.max_attempts)
        .map_or(0, |attempt| retry_upper_bound(outbox, attempt));
    Ok(Some(RecoveryCandidate {
        outbox,
        retry_upper_bound,
    }))
}

async fn recover_expired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    candidate: RecoveryCandidate,
    now: RhiPublicationUnixMilliseconds,
    delay: RhiPublicationRetryDelayMilliseconds,
) -> Result<bool, OperationError> {
    let current = read_outbox(transaction, candidate.outbox.id)
        .await?
        .filter(|current| *current == candidate.outbox)
        .ok_or(OperationError::LeaseLost)?;
    if current.state != RhiPublicationOutboxState::Leased
        || current.lease_expires.is_none_or(|expires| expires > now)
    {
        return Err(OperationError::LeaseLost);
    }
    let owner = current.lease_owner.ok_or(OperationError::Invariant)?;
    let mut targets = read_targets(transaction, current.id).await?;
    validate_targets(current, &targets)?;
    for target in targets
        .iter_mut()
        .filter(|target| target.state == RhiPublicationTargetState::Submitted)
    {
        let attempt_id = target.last_attempt_id.ok_or(OperationError::Invariant)?;
        let publication =
            read_committed(transaction, current.id)
                .await
                .map_err(|error| match error {
                    ReadError::Storage => OperationError::Storage,
                    ReadError::NotFound | ReadError::Binding => OperationError::Invariant,
                })?;
        let evidence = RhiPublicationAttemptEvidence::new(
            &publication,
            u32::from(target.ordinal),
            target.attempt_count,
            target.updated_at,
            now,
            RhiPublicationAttemptOutcome::Unknown,
        )
        .map_err(|_| OperationError::Invariant)?;
        if attempt_id != evidence.id() || read_attempt(transaction, attempt_id).await?.is_some() {
            return Err(OperationError::Invariant);
        }
        let input = RecordInput {
            lease: RhiPublicationLease {
                outbox: current,
                owner,
                expires_at: current.lease_expires.ok_or(OperationError::Invariant)?,
            },
            target_ordinal: target.ordinal,
            target_revision: target.revision,
            attempt_number: target.attempt_count,
            attempt_id,
            started_at: target.updated_at,
            finished_at: now,
            outcome: RhiPublicationAttemptOutcome::Unknown,
            retry_delay: delay,
        };
        insert_attempt(transaction, input).await?;
        let (state, next) = target_outcome_schedule(input)?;
        let result = sqlx::query(UPDATE_TARGET_OUTCOME_SQL)
            .bind(state.code())
            .bind(optional_i64(next)?)
            .bind(i64_value(now.get())?)
            .bind(current.id.as_bytes().as_slice())
            .bind(i64::from(target.ordinal))
            .bind(i64_value(target.revision)?)
            .bind(i64::from(target.attempt_count))
            .bind(attempt_id.as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| OperationError::Storage)?;
        if result.rows_affected() != 1 {
            return Err(OperationError::LeaseLost);
        }
    }
    targets = read_targets(transaction, current.id).await?;
    let disposition = disposition(current, &targets)?;
    let result = sqlx::query(UPDATE_OUTBOX_RECOVERY_SQL)
        .bind(disposition.state.code())
        .bind(optional_i64(disposition.next_attempt)?)
        .bind(i64_value(now.get())?)
        .bind(current.id.as_bytes().as_slice())
        .bind(i64_value(current.revision)?)
        .bind(owner.0.as_slice())
        .bind(i64_value(
            current
                .lease_expires
                .ok_or(OperationError::Invariant)?
                .get(),
        )?)
        .bind(i64_value(now.get())?)
        .bind(i64_value(now.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::LeaseLost);
    }
    Ok(true)
}

async fn validate_lease(
    transaction: &mut ServiceSqliteTransaction<'_>,
    lease: RhiPublicationLease,
    now: RhiPublicationUnixMilliseconds,
    require_unexpired: bool,
) -> Result<(), OperationError> {
    let current = read_outbox(transaction, lease.outbox.id)
        .await?
        .filter(|current| *current == lease.outbox)
        .ok_or(OperationError::LeaseLost)?;
    if current.state != RhiPublicationOutboxState::Leased
        || current.lease_owner != Some(lease.owner)
        || current.lease_expires != Some(lease.expires_at)
        || (require_unexpired && lease.expires_at <= now)
    {
        return Err(OperationError::LeaseLost);
    }
    Ok(())
}

async fn insert_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    input: RecordInput,
) -> Result<(), OperationError> {
    let result = sqlx::query(INSERT_ATTEMPT_SQL)
        .bind(input.attempt_id.as_bytes().as_slice())
        .bind(input.lease.outbox.id.as_bytes().as_slice())
        .bind(i64::from(input.target_ordinal))
        .bind(i64::from(input.attempt_number))
        .bind(input.lease.outbox.event_sha256.as_slice())
        .bind(input.lease.owner.0.as_slice())
        .bind(i64_value(input.started_at.get())?)
        .bind(i64_value(input.finished_at.get())?)
        .bind(input.outcome.code())
        .bind(input.outcome.code())
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::Storage);
    }
    Ok(())
}

async fn reconcile_recorded(
    transaction: &mut ServiceSqliteTransaction<'_>,
    input: RecordInput,
    existing: AttemptRecord,
) -> Result<RhiPublicationAttemptCommit, OperationError> {
    if existing != AttemptRecord::from_input(input) {
        return Err(OperationError::Invariant);
    }
    let outbox = read_outbox(transaction, input.lease.outbox.id)
        .await?
        .ok_or(OperationError::Invariant)?;
    if !same_outbox_identity(outbox, input.lease.outbox)
        || outbox.revision
            != input
                .lease
                .outbox
                .revision
                .checked_add(1)
                .ok_or(OperationError::Invariant)?
        || outbox.updated_at != input.finished_at
        || outbox.lease_owner.is_some()
        || outbox.lease_expires.is_some()
    {
        return Err(OperationError::Invariant);
    }
    let targets = read_targets(transaction, outbox.id).await?;
    validate_targets(outbox, &targets)?;
    let (expected_target_state, expected_target_schedule) = target_outcome_schedule(input)?;
    let expected_target_revision = input
        .target_revision
        .checked_add(1)
        .ok_or(OperationError::Invariant)?;
    let target = targets
        .iter()
        .find(|target| target.ordinal == input.target_ordinal)
        .filter(|target| {
            target.revision == expected_target_revision
                && target.attempt_count == input.attempt_number
                && target.last_attempt_id == Some(input.attempt_id)
                && target.state == expected_target_state
                && target.next_attempt == expected_target_schedule
                && target.updated_at == input.finished_at
        })
        .ok_or(OperationError::Invariant)?;
    let expected_disposition = disposition(outbox, &targets)?;
    if outbox.state != expected_disposition.state
        || outbox.next_attempt != expected_disposition.next_attempt
    {
        return Err(OperationError::Invariant);
    }
    Ok(RhiPublicationAttemptCommit {
        outbox_id: outbox.id,
        attempt_id: input.attempt_id,
        target_ordinal: input.target_ordinal,
        attempt_number: input.attempt_number,
        outcome: input.outcome,
        target_state: target.state,
        outbox_state: outbox.state,
    })
}

fn same_outbox_identity(current: OutboxRecord, prior: OutboxRecord) -> bool {
    current.id == prior.id
        && current.event_sha256 == prior.event_sha256
        && current.authority_sha256 == prior.authority_sha256
        && current.target_set_sha256 == prior.target_set_sha256
        && current.target_count == prior.target_count
        && current.required_target_count == prior.required_target_count
        && current.max_attempts == prior.max_attempts
        && current.initial_backoff_ms == prior.initial_backoff_ms
        && current.maximum_backoff_ms == prior.maximum_backoff_ms
        && current.attempt_deadline_ms == prior.attempt_deadline_ms
        && current.created_at == prior.created_at
}

async fn update_outbox_after_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    input: RecordInput,
    disposition: OutboxDisposition,
) -> Result<(), OperationError> {
    let result = sqlx::query(UPDATE_OUTBOX_AFTER_ATTEMPT_SQL)
        .bind(disposition.state.code())
        .bind(optional_i64(disposition.next_attempt)?)
        .bind(i64_value(input.finished_at.get())?)
        .bind(input.lease.outbox.id.as_bytes().as_slice())
        .bind(i64_value(input.lease.outbox.revision)?)
        .bind(input.lease.owner.0.as_slice())
        .bind(i64_value(input.lease.expires_at.get())?)
        .bind(i64_value(input.finished_at.get())?)
        .bind(i64_value(input.finished_at.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::LeaseLost);
    }
    Ok(())
}

async fn read_outbox(
    transaction: &mut ServiceSqliteTransaction<'_>,
    id: RhiPublicationOutboxId,
) -> Result<Option<OutboxRecord>, OperationError> {
    let rows = sqlx::query(READ_OUTBOX_SQL)
        .bind(id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    exactly_zero_or_one(rows)?.map(decode_outbox).transpose()
}

async fn read_targets(
    transaction: &mut ServiceSqliteTransaction<'_>,
    id: RhiPublicationOutboxId,
) -> Result<Vec<TargetRecord>, OperationError> {
    sqlx::query(READ_TARGETS_SQL)
        .bind(id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?
        .into_iter()
        .map(decode_target)
        .collect()
}

async fn validate_target_inventory(
    transaction: &mut ServiceSqliteTransaction<'_>,
    outbox: OutboxRecord,
) -> Result<(), OperationError> {
    let targets = read_targets(transaction, outbox.id).await?;
    validate_targets(outbox, &targets)
}

fn validate_targets(outbox: OutboxRecord, targets: &[TargetRecord]) -> Result<(), OperationError> {
    if targets.len() != usize::from(outbox.target_count)
        || targets.len()
            > usize::try_from(RHI_PUBLICATION_TARGET_ORDINAL_MAXIMUM + 1)
                .map_err(|_| OperationError::Invariant)?
        || targets
            .iter()
            .enumerate()
            .any(|(index, target)| usize::from(target.ordinal) != index)
        || targets.iter().filter(|target| target.required).count()
            != usize::from(outbox.required_target_count)
    {
        return Err(OperationError::Invariant);
    }
    for (index, target) in targets.iter().enumerate() {
        if targets[index + 1..]
            .iter()
            .any(|other| other.relay_id == target.relay_id)
        {
            return Err(OperationError::Invariant);
        }
    }
    let mut digest = Sha256::new();
    digest.update(TARGET_SET_DOMAIN);
    digest.update(u32::from(outbox.target_count).to_be_bytes());
    for target in targets {
        digest.update(u32::from(target.ordinal).to_be_bytes());
        digest.update(
            u64::try_from(target.relay_id.len())
                .map_err(|_| OperationError::Invariant)?
                .to_be_bytes(),
        );
        digest.update(target.relay_id.as_bytes());
        digest.update([u8::from(target.required)]);
    }
    let actual: [u8; 32] = digest.finalize().into();
    if actual != outbox.target_set_sha256 {
        return Err(OperationError::Invariant);
    }
    Ok(())
}

fn validate_authority(
    outbox: OutboxRecord,
    authority: AuthorityBinding,
) -> Result<(), OperationError> {
    if outbox.authority_sha256 != authority.authority_sha256
        || outbox.target_set_sha256 != authority.target_set_sha256
        || outbox.target_count != authority.target_count
        || outbox.required_target_count != authority.required_target_count
        || outbox.max_attempts != authority.max_attempts
        || outbox.initial_backoff_ms != authority.initial_backoff_ms
        || outbox.maximum_backoff_ms != authority.maximum_backoff_ms
        || outbox.attempt_deadline_ms != authority.attempt_deadline_ms
    {
        return Err(OperationError::Invariant);
    }
    Ok(())
}

fn disposition(
    outbox: OutboxRecord,
    targets: &[TargetRecord],
) -> Result<OutboxDisposition, OperationError> {
    validate_targets(outbox, targets)?;
    let required = targets.iter().filter(|target| target.required);
    if required
        .clone()
        .all(|target| target.state == RhiPublicationTargetState::Accepted)
    {
        return Ok(OutboxDisposition {
            state: RhiPublicationOutboxState::Complete,
            next_attempt: None,
        });
    }
    if required
        .clone()
        .any(|target| target_is_blocking(target, outbox.max_attempts))
    {
        return Ok(OutboxDisposition {
            state: RhiPublicationOutboxState::Blocked,
            next_attempt: None,
        });
    }
    let next_attempt = required
        .filter_map(|target| target.next_attempt)
        .min()
        .ok_or(OperationError::Invariant)?;
    Ok(OutboxDisposition {
        state: RhiPublicationOutboxState::Pending,
        next_attempt: Some(next_attempt),
    })
}

fn target_is_blocking(target: &TargetRecord, max_attempts: u16) -> bool {
    matches!(
        target.state,
        RhiPublicationTargetState::Rejected | RhiPublicationTargetState::AuthRequired
    ) || (retryable_state(target.state)
        && target.attempt_count >= max_attempts
        && target.next_attempt.is_none())
}

fn target_is_due(
    target: &TargetRecord,
    max_attempts: u16,
    now: RhiPublicationUnixMilliseconds,
) -> bool {
    retryable_state(target.state)
        && target.attempt_count < max_attempts
        && target.next_attempt.is_some_and(|next| next <= now)
}

const fn retryable_state(state: RhiPublicationTargetState) -> bool {
    matches!(
        state,
        RhiPublicationTargetState::Pending
            | RhiPublicationTargetState::Failed
            | RhiPublicationTargetState::RateLimited
            | RhiPublicationTargetState::Unknown
    )
}

const fn retryable_outcome(outcome: RhiPublicationAttemptOutcome) -> bool {
    matches!(
        outcome,
        RhiPublicationAttemptOutcome::RateLimited
            | RhiPublicationAttemptOutcome::Failed
            | RhiPublicationAttemptOutcome::Unknown
    )
}

fn target_outcome_schedule(
    input: RecordInput,
) -> Result<
    (
        RhiPublicationTargetState,
        Option<RhiPublicationUnixMilliseconds>,
    ),
    OperationError,
> {
    let state = input.outcome.target_state();
    if input.outcome == RhiPublicationAttemptOutcome::Submitted {
        return Err(OperationError::InvalidInput);
    }
    let next = if retryable_outcome(input.outcome)
        && input.attempt_number < input.lease.outbox.max_attempts
    {
        if input.retry_delay.get() > retry_upper_bound(input.lease.outbox, input.attempt_number) {
            return Err(OperationError::InvalidInput);
        }
        Some(RhiPublicationUnixMilliseconds(
            input
                .finished_at
                .get()
                .checked_add(input.retry_delay.get())
                .filter(|value| *value <= MAX_UNIX_MILLISECONDS)
                .ok_or(OperationError::InvalidInput)?,
        ))
    } else {
        if input.retry_delay.get() != 0 {
            return Err(OperationError::InvalidInput);
        }
        None
    };
    Ok((state, next))
}

fn retry_upper_bound(outbox: OutboxRecord, attempt_number: u16) -> u64 {
    let mut bound = outbox.initial_backoff_ms;
    for _ in 1..attempt_number {
        bound = bound.saturating_mul(2).min(outbox.maximum_backoff_ms);
    }
    bound.min(outbox.maximum_backoff_ms)
}

fn decode_outbox(row: sqlx::sqlite::SqliteRow) -> Result<OutboxRecord, OperationError> {
    let id = RhiPublicationOutboxId::from_committed_bytes(blob::<32>(&row, "outbox_id")?);
    let state = decode_outbox_state(bounded_text(&row, "state", "state_bytes", 8)?.as_str())?;
    let target_count = bounded_u16(&row, "target_count", 1, 32)? as u8;
    let required_target_count =
        bounded_u16(&row, "required_target_count", 0, target_count.into())? as u8;
    let max_attempts = bounded_u16(
        &row,
        "max_attempts",
        1,
        RHI_PUBLICATION_ATTEMPT_NUMBER_MAXIMUM,
    )?;
    let initial_backoff_ms = bounded_u64(&row, "initial_backoff_ms", 1, 60_000)?;
    let maximum_backoff_ms = bounded_u64(&row, "maximum_backoff_ms", 1, 3_600_000)?;
    if initial_backoff_ms > maximum_backoff_ms {
        return Err(OperationError::Invariant);
    }
    let attempt_deadline_ms = bounded_u64(&row, "attempt_deadline_ms", 100, 30_000)?;
    let lease_owner = optional_owner(&row)?;
    let lease_expires = optional_millis(&row, "lease_expires_unix_ms")?;
    let next_attempt = optional_millis(&row, "next_attempt_unix_ms")?;
    if !valid_outbox_shape(state, next_attempt, lease_owner, lease_expires) {
        return Err(OperationError::Invariant);
    }
    Ok(OutboxRecord {
        id,
        event_sha256: blob::<32>(&row, "event_sha256")?,
        authority_sha256: blob::<32>(&row, "publication_authority_sha256")?,
        target_set_sha256: blob::<32>(&row, "target_set_sha256")?,
        target_count,
        required_target_count,
        max_attempts,
        initial_backoff_ms,
        maximum_backoff_ms,
        attempt_deadline_ms,
        state,
        revision: positive_u64(&row, "revision")?,
        next_attempt,
        lease_owner,
        lease_expires,
        created_at: nonnegative_millis(&row, "created_at_unix_ms")?,
        updated_at: nonnegative_millis(&row, "updated_at_unix_ms")?,
    })
}

fn decode_target(row: sqlx::sqlite::SqliteRow) -> Result<TargetRecord, OperationError> {
    let ordinal = bounded_u16(
        &row,
        "target_ordinal",
        0,
        u16::try_from(RHI_PUBLICATION_TARGET_ORDINAL_MAXIMUM)
            .map_err(|_| OperationError::Invariant)?,
    )? as u8;
    let relay_id = bounded_text(&row, "relay_id", "relay_id_bytes", 64)?;
    if relay_id.is_empty()
        || !relay_id.bytes().enumerate().all(|(index, byte)| {
            (byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-'))
                && (index != 0 || byte.is_ascii_lowercase())
        })
    {
        return Err(OperationError::Invariant);
    }
    let required = match row.try_get::<i64, _>("required") {
        Ok(0) => false,
        Ok(1) => true,
        _ => return Err(OperationError::Invariant),
    };
    let state = decode_target_state(bounded_text(&row, "state", "state_bytes", 13)?.as_str())?;
    let attempt_count = bounded_u16(
        &row,
        "attempt_count",
        0,
        RHI_PUBLICATION_ATTEMPT_NUMBER_MAXIMUM,
    )?;
    let last_attempt_id = optional_attempt_id(&row)?;
    if (attempt_count == 0) != last_attempt_id.is_none() {
        return Err(OperationError::Invariant);
    }
    Ok(TargetRecord {
        ordinal,
        relay_id: relay_id.into_boxed_str(),
        required,
        state,
        revision: positive_u64(&row, "revision")?,
        attempt_count,
        next_attempt: optional_millis(&row, "next_attempt_unix_ms")?,
        last_attempt_id,
        updated_at: nonnegative_millis(&row, "updated_at_unix_ms")?,
    })
}

async fn read_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    id: RhiPublicationAttemptId,
) -> Result<Option<AttemptRecord>, OperationError> {
    let rows = sqlx::query(READ_ATTEMPT_SQL)
        .bind(id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    exactly_zero_or_one(rows)?.map(decode_attempt).transpose()
}

fn decode_attempt(row: sqlx::sqlite::SqliteRow) -> Result<AttemptRecord, OperationError> {
    let outcome =
        decode_attempt_outcome(bounded_text(&row, "outcome", "outcome_bytes", 13)?.as_str())?;
    let result_code = bounded_text(&row, "result_code", "result_code_bytes", 64)?;
    if result_code != outcome.code() {
        return Err(OperationError::Invariant);
    }
    Ok(AttemptRecord {
        attempt_id: attempt_id_from_durable_bytes(blob::<32>(&row, "attempt_id")?),
        outbox_id: RhiPublicationOutboxId::from_committed_bytes(blob::<32>(&row, "outbox_id")?),
        target_ordinal: bounded_u16(&row, "target_ordinal", 0, 31)? as u8,
        attempt_number: bounded_u16(&row, "attempt_number", 1, 100)?,
        event_sha256: blob::<32>(&row, "event_sha256")?,
        lease_owner: RhiPublicationLeaseOwner(blob::<16>(&row, "lease_owner")?),
        started_at: nonnegative_millis(&row, "started_at_unix_ms")?,
        finished_at: nonnegative_millis(&row, "finished_at_unix_ms")?,
        outcome,
    })
}

fn decode_outbox_state(value: &str) -> Result<RhiPublicationOutboxState, OperationError> {
    match value {
        "pending" => Ok(RhiPublicationOutboxState::Pending),
        "leased" => Ok(RhiPublicationOutboxState::Leased),
        "complete" => Ok(RhiPublicationOutboxState::Complete),
        "blocked" => Ok(RhiPublicationOutboxState::Blocked),
        _ => Err(OperationError::Invariant),
    }
}

fn decode_target_state(value: &str) -> Result<RhiPublicationTargetState, OperationError> {
    match value {
        "pending" => Ok(RhiPublicationTargetState::Pending),
        "submitted" => Ok(RhiPublicationTargetState::Submitted),
        "accepted" => Ok(RhiPublicationTargetState::Accepted),
        "rejected" => Ok(RhiPublicationTargetState::Rejected),
        "rate_limited" => Ok(RhiPublicationTargetState::RateLimited),
        "auth_required" => Ok(RhiPublicationTargetState::AuthRequired),
        "failed" => Ok(RhiPublicationTargetState::Failed),
        "unknown" => Ok(RhiPublicationTargetState::Unknown),
        _ => Err(OperationError::Invariant),
    }
}

fn decode_attempt_outcome(value: &str) -> Result<RhiPublicationAttemptOutcome, OperationError> {
    match value {
        "submitted" => Ok(RhiPublicationAttemptOutcome::Submitted),
        "accepted" => Ok(RhiPublicationAttemptOutcome::Accepted),
        "rejected" => Ok(RhiPublicationAttemptOutcome::Rejected),
        "rate_limited" => Ok(RhiPublicationAttemptOutcome::RateLimited),
        "auth_required" => Ok(RhiPublicationAttemptOutcome::AuthRequired),
        "failed" => Ok(RhiPublicationAttemptOutcome::Failed),
        "unknown" => Ok(RhiPublicationAttemptOutcome::Unknown),
        _ => Err(OperationError::Invariant),
    }
}

fn valid_outbox_shape(
    state: RhiPublicationOutboxState,
    next: Option<RhiPublicationUnixMilliseconds>,
    owner: Option<RhiPublicationLeaseOwner>,
    expires: Option<RhiPublicationUnixMilliseconds>,
) -> bool {
    match state {
        RhiPublicationOutboxState::Pending => {
            next.is_some() && owner.is_none() && expires.is_none()
        }
        RhiPublicationOutboxState::Leased => {
            next.is_none() && owner.is_some() && expires.is_some_and(|value| value.get() > 0)
        }
        RhiPublicationOutboxState::Complete | RhiPublicationOutboxState::Blocked => {
            next.is_none() && owner.is_none() && expires.is_none()
        }
    }
}

fn exactly_zero_or_one(
    mut rows: Vec<sqlx::sqlite::SqliteRow>,
) -> Result<Option<sqlx::sqlite::SqliteRow>, OperationError> {
    match rows.len() {
        0 => Ok(None),
        1 => Ok(rows.pop()),
        _ => Err(OperationError::Invariant),
    }
}

fn blob<const N: usize>(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; N], OperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| OperationError::Invariant)?
        .ok_or(OperationError::Invariant)?
        .try_into()
        .map_err(|_| OperationError::Invariant)
}

fn bounded_text(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    length_column: &str,
    maximum: usize,
) -> Result<String, OperationError> {
    let length = row
        .try_get::<i64, _>(length_column)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value <= maximum)
        .ok_or(OperationError::Invariant)?;
    let value = row
        .try_get::<String, _>(column)
        .map_err(|_| OperationError::Invariant)?;
    if value.len() != length {
        return Err(OperationError::Invariant);
    }
    Ok(value)
}

fn bounded_u16(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    minimum: u16,
    maximum: u16,
) -> Result<u16, OperationError> {
    row.try_get::<i64, _>(column)
        .ok()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value >= minimum && *value <= maximum)
        .ok_or(OperationError::Invariant)
}

fn bounded_u64(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, OperationError> {
    row.try_get::<i64, _>(column)
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value >= minimum && *value <= maximum)
        .ok_or(OperationError::Invariant)
}

fn positive_u64(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<u64, OperationError> {
    bounded_u64(row, column, 1, MAX_UNIX_MILLISECONDS)
}

fn nonnegative_millis(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<RhiPublicationUnixMilliseconds, OperationError> {
    bounded_u64(row, column, 0, MAX_UNIX_MILLISECONDS).map(RhiPublicationUnixMilliseconds)
}

fn optional_millis(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Option<RhiPublicationUnixMilliseconds>, OperationError> {
    row.try_get::<Option<i64>, _>(column)
        .map_err(|_| OperationError::Invariant)?
        .map(|value| {
            u64::try_from(value)
                .ok()
                .filter(|value| *value <= MAX_UNIX_MILLISECONDS)
                .map(RhiPublicationUnixMilliseconds)
                .ok_or(OperationError::Invariant)
        })
        .transpose()
}

fn optional_owner(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Option<RhiPublicationLeaseOwner>, OperationError> {
    let length = row
        .try_get::<Option<i64>, _>("lease_owner_bytes")
        .map_err(|_| OperationError::Invariant)?;
    let bytes = row
        .try_get::<Option<Vec<u8>>, _>("lease_owner")
        .map_err(|_| OperationError::Invariant)?;
    match (length, bytes) {
        (None, None) => Ok(None),
        (Some(length), Some(bytes))
            if length == LEASE_OWNER_BYTES as i64 && bytes.len() == LEASE_OWNER_BYTES =>
        {
            let bytes: [u8; LEASE_OWNER_BYTES] =
                bytes.try_into().map_err(|_| OperationError::Invariant)?;
            RhiPublicationLeaseOwner::from_bytes(bytes)
                .map(Some)
                .map_err(|_| OperationError::Invariant)
        }
        _ => Err(OperationError::Invariant),
    }
}

fn optional_attempt_id(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Option<RhiPublicationAttemptId>, OperationError> {
    let length = row
        .try_get::<Option<i64>, _>("last_attempt_id_bytes")
        .map_err(|_| OperationError::Invariant)?;
    let bytes = row
        .try_get::<Option<Vec<u8>>, _>("last_attempt_id")
        .map_err(|_| OperationError::Invariant)?;
    match (length, bytes) {
        (None, None) => Ok(None),
        (Some(32), Some(bytes)) if bytes.len() == 32 => Ok(Some(attempt_id_from_durable_bytes(
            bytes.try_into().map_err(|_| OperationError::Invariant)?,
        ))),
        _ => Err(OperationError::Invariant),
    }
}

fn attempt_id_from_durable_bytes(bytes: [u8; 32]) -> RhiPublicationAttemptId {
    // Restricted to bounded database decoding; every caller subsequently
    // compares the value with a freshly domain-derived identity.
    crate::publication_attempt::attempt_id_from_durable_bytes(bytes)
}

fn i64_value(value: u64) -> Result<i64, OperationError> {
    i64::try_from(value).map_err(|_| OperationError::InvalidInput)
}

fn optional_i64(
    value: Option<RhiPublicationUnixMilliseconds>,
) -> Result<Option<i64>, OperationError> {
    value.map(|value| i64_value(value.get())).transpose()
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct OutboxRecord {
    id: RhiPublicationOutboxId,
    event_sha256: [u8; 32],
    authority_sha256: [u8; 32],
    target_set_sha256: [u8; 32],
    target_count: u8,
    required_target_count: u8,
    max_attempts: u16,
    initial_backoff_ms: u64,
    maximum_backoff_ms: u64,
    attempt_deadline_ms: u64,
    state: RhiPublicationOutboxState,
    revision: u64,
    next_attempt: Option<RhiPublicationUnixMilliseconds>,
    lease_owner: Option<RhiPublicationLeaseOwner>,
    lease_expires: Option<RhiPublicationUnixMilliseconds>,
    created_at: RhiPublicationUnixMilliseconds,
    updated_at: RhiPublicationUnixMilliseconds,
}

#[derive(Clone, Copy)]
struct AuthorityBinding {
    authority_sha256: [u8; 32],
    target_set_sha256: [u8; 32],
    target_count: u8,
    required_target_count: u8,
    max_attempts: u16,
    initial_backoff_ms: u64,
    maximum_backoff_ms: u64,
    attempt_deadline_ms: u64,
}

impl AuthorityBinding {
    fn from_authority(authority: &RhiPublicationAuthority) -> Option<Self> {
        if authority.mode() == RhiPublicationMode::Disabled {
            return None;
        }
        let retry = authority.retry_policy()?;
        Some(Self {
            authority_sha256: *authority.authority_sha256(),
            target_set_sha256: *authority.target_set_sha256(),
            target_count: u8::try_from(authority.targets().len()).ok()?,
            required_target_count: u8::try_from(
                authority
                    .targets()
                    .iter()
                    .filter(|target| target.required())
                    .count(),
            )
            .ok()?,
            max_attempts: retry.maximum_attempts(),
            initial_backoff_ms: retry.initial_backoff_milliseconds(),
            maximum_backoff_ms: retry.maximum_backoff_milliseconds(),
            attempt_deadline_ms: retry.attempt_deadline_milliseconds(),
        })
    }
}

#[derive(PartialEq, Eq)]
struct TargetRecord {
    ordinal: u8,
    relay_id: Box<str>,
    required: bool,
    state: RhiPublicationTargetState,
    revision: u64,
    attempt_count: u16,
    next_attempt: Option<RhiPublicationUnixMilliseconds>,
    last_attempt_id: Option<RhiPublicationAttemptId>,
    updated_at: RhiPublicationUnixMilliseconds,
}

impl Clone for TargetRecord {
    fn clone(&self) -> Self {
        Self {
            ordinal: self.ordinal,
            relay_id: self.relay_id.clone(),
            required: self.required,
            state: self.state,
            revision: self.revision,
            attempt_count: self.attempt_count,
            next_attempt: self.next_attempt,
            last_attempt_id: self.last_attempt_id,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Clone, Copy)]
struct RecoveryCandidate {
    outbox: OutboxRecord,
    retry_upper_bound: u64,
}

#[derive(Clone, Copy)]
struct RecordInput {
    lease: RhiPublicationLease,
    target_ordinal: u8,
    target_revision: u64,
    attempt_number: u16,
    attempt_id: RhiPublicationAttemptId,
    started_at: RhiPublicationUnixMilliseconds,
    finished_at: RhiPublicationUnixMilliseconds,
    outcome: RhiPublicationAttemptOutcome,
    retry_delay: RhiPublicationRetryDelayMilliseconds,
}

impl RecordInput {
    fn from_prepared(
        prepared: &RhiPreparedPublicationAttempt,
        finished_at: RhiPublicationUnixMilliseconds,
        outcome: RhiPublicationAttemptOutcome,
        retry_delay: RhiPublicationRetryDelayMilliseconds,
    ) -> Result<Self, RhiPublicationExecutionError> {
        if finished_at < prepared.started_at || outcome == RhiPublicationAttemptOutcome::Submitted {
            return Err(RhiPublicationExecutionError::new(
                RhiPublicationExecutionErrorKind::InvalidInput,
            ));
        }
        let evidence = RhiPublicationAttemptEvidence::new(
            &prepared.publication,
            u32::from(prepared.target.ordinal),
            prepared.target.attempt_count,
            prepared.started_at,
            finished_at,
            outcome,
        )
        .map_err(|_| {
            RhiPublicationExecutionError::new(RhiPublicationExecutionErrorKind::InvalidInput)
        })?;
        if evidence.id() != prepared.attempt_id {
            return Err(RhiPublicationExecutionError::new(
                RhiPublicationExecutionErrorKind::Invariant,
            ));
        }
        Ok(Self {
            lease: prepared.lease,
            target_ordinal: prepared.target.ordinal,
            target_revision: prepared.target.revision,
            attempt_number: prepared.target.attempt_count,
            attempt_id: prepared.attempt_id,
            started_at: prepared.started_at,
            finished_at,
            outcome,
            retry_delay,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct AttemptRecord {
    attempt_id: RhiPublicationAttemptId,
    outbox_id: RhiPublicationOutboxId,
    target_ordinal: u8,
    attempt_number: u16,
    event_sha256: [u8; 32],
    lease_owner: RhiPublicationLeaseOwner,
    started_at: RhiPublicationUnixMilliseconds,
    finished_at: RhiPublicationUnixMilliseconds,
    outcome: RhiPublicationAttemptOutcome,
}

impl AttemptRecord {
    const fn from_input(input: RecordInput) -> Self {
        Self {
            attempt_id: input.attempt_id,
            outbox_id: input.lease.outbox.id,
            target_ordinal: input.target_ordinal,
            attempt_number: input.attempt_number,
            event_sha256: input.lease.outbox.event_sha256,
            lease_owner: input.lease.owner,
            started_at: input.started_at,
            finished_at: input.finished_at,
            outcome: input.outcome,
        }
    }
}

#[derive(Clone, Copy)]
struct OutboxDisposition {
    state: RhiPublicationOutboxState,
    next_attempt: Option<RhiPublicationUnixMilliseconds>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationError {
    InvalidInput,
    NotReady,
    LeaseLost,
    Invariant,
    Storage,
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<OperationError>,
) -> RhiPublicationExecutionError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return RhiPublicationExecutionError::new(
            RhiPublicationExecutionErrorKind::CommitOutcomeUnknown,
        );
    }
    RhiPublicationExecutionError::new(match error.operation_error().copied() {
        Some(OperationError::InvalidInput) => RhiPublicationExecutionErrorKind::InvalidInput,
        Some(OperationError::NotReady) => RhiPublicationExecutionErrorKind::NotReady,
        Some(OperationError::LeaseLost) => RhiPublicationExecutionErrorKind::LeaseLost,
        Some(OperationError::Invariant) => RhiPublicationExecutionErrorKind::Invariant,
        Some(OperationError::Storage) | None => RhiPublicationExecutionErrorKind::Storage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_bounds_are_saturating_closed_and_errors_are_safe() {
        let outbox = OutboxRecord {
            id: RhiPublicationOutboxId::from_committed_bytes([1; 32]),
            event_sha256: [2; 32],
            authority_sha256: [3; 32],
            target_set_sha256: [4; 32],
            target_count: 1,
            required_target_count: 1,
            max_attempts: 100,
            initial_backoff_ms: 250,
            maximum_backoff_ms: 30_000,
            attempt_deadline_ms: 5_000,
            state: RhiPublicationOutboxState::Pending,
            revision: 1,
            next_attempt: Some(RhiPublicationUnixMilliseconds(0)),
            lease_owner: None,
            lease_expires: None,
            created_at: RhiPublicationUnixMilliseconds(0),
            updated_at: RhiPublicationUnixMilliseconds(0),
        };
        assert_eq!(retry_upper_bound(outbox, 1), 250);
        assert_eq!(retry_upper_bound(outbox, 2), 500);
        assert_eq!(retry_upper_bound(outbox, 100), 30_000);
        assert!(RhiPublicationLeaseOwner::from_bytes([0; 16]).is_err());
        assert!(RhiPublicationRetryDelayMilliseconds::new(3_600_001).is_err());
        for kind in [
            RhiPublicationExecutionErrorKind::InvalidMode,
            RhiPublicationExecutionErrorKind::InvalidInput,
            RhiPublicationExecutionErrorKind::NotReady,
            RhiPublicationExecutionErrorKind::LeaseLost,
            RhiPublicationExecutionErrorKind::Invariant,
            RhiPublicationExecutionErrorKind::ClockUnavailable,
            RhiPublicationExecutionErrorKind::EntropyUnavailable,
            RhiPublicationExecutionErrorKind::Storage,
            RhiPublicationExecutionErrorKind::CommitOutcomeUnknown,
        ] {
            let error = RhiPublicationExecutionError::new(kind);
            assert!(error.code().starts_with("publication_execution_"));
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("relay-primary"));
            assert!(!rendered.contains("SELECT"));
        }
    }
}
