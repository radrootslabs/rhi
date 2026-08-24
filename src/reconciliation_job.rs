//! Bounded durable reconciliation-job scheduling and lease state machine.

use core::fmt;
use std::error::Error;

use radroots_event::id::TradeId;
use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    RhiConfigDocumentV1, RhiEvidencePolicyDigest, RhiReconciliationJobRepository, RhiStateHostMode,
};

/// Exact version of the durable reconciliation-job contract.
pub const RHI_RECONCILIATION_JOB_CONTRACT_VERSION: u32 = 1;

/// Absolute hard ceiling for active durable reconciliation jobs.
pub const RHI_RECONCILIATION_JOB_MAX_ACTIVE: u32 = 65_536;

const JOB_ID_DOMAIN: &[u8] = b"radroots.rhi.reconciliation_job.v1\0";
const LEASE_OWNER_BYTES: usize = 16;
const MAX_UNIX_MILLISECONDS: u64 = i64::MAX as u64;
const MAX_ATTEMPTS: u16 = 100;
const MAX_LEASE_MILLISECONDS: u64 = 300_000;
const MAX_RENEWAL_MILLISECONDS: u64 = 150_000;
const MAX_INITIAL_BACKOFF_MILLISECONDS: u64 = 60_000;
const MAX_BACKOFF_MILLISECONDS: u64 = 3_600_000;

const READ_DIRTY_SQL: &str = r#"SELECT generation,
    length(evidence_policy_sha256) AS evidence_policy_bytes,
    substr(evidence_policy_sha256, 1, 33) AS evidence_policy_sha256
FROM trade_dirty_generations
WHERE trade_id = ?
LIMIT 1"#;
const READ_JOB_SQL: &str = r#"SELECT
    length(job_id) AS job_id_bytes, substr(job_id, 1, 33) AS job_id,
    length(trade_id) AS trade_id_bytes, substr(trade_id, 1, 17) AS trade_id,
    input_generation,
    length(evidence_policy_sha256) AS evidence_policy_bytes,
    substr(evidence_policy_sha256, 1, 33) AS evidence_policy_sha256,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 12) AS state,
    revision, attempt_count, failure_count, max_attempts,
    lease_duration_ms, lease_renewal_ms, initial_backoff_ms, maximum_backoff_ms,
    next_attempt_unix_ms,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE length(lease_owner) END AS lease_owner_bytes,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE substr(lease_owner, 1, 17) END AS lease_owner,
    lease_expires_unix_ms, created_at_unix_ms, updated_at_unix_ms
FROM reconciliation_jobs
WHERE job_id = ?
LIMIT 1"#;
const READ_ACTIVE_JOB_SQL: &str = r#"SELECT
    length(job_id) AS job_id_bytes, substr(job_id, 1, 33) AS job_id,
    length(trade_id) AS trade_id_bytes, substr(trade_id, 1, 17) AS trade_id,
    input_generation,
    length(evidence_policy_sha256) AS evidence_policy_bytes,
    substr(evidence_policy_sha256, 1, 33) AS evidence_policy_sha256,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 12) AS state,
    revision, attempt_count, failure_count, max_attempts,
    lease_duration_ms, lease_renewal_ms, initial_backoff_ms, maximum_backoff_ms,
    next_attempt_unix_ms,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE length(lease_owner) END AS lease_owner_bytes,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE substr(lease_owner, 1, 17) END AS lease_owner,
    lease_expires_unix_ms, created_at_unix_ms, updated_at_unix_ms
FROM reconciliation_jobs
WHERE trade_id = ? AND state IN ('ready', 'leased')
LIMIT 2"#;
const ACTIVE_JOB_COUNT_SQL: &str = r#"SELECT COUNT(*) AS active_count
FROM reconciliation_jobs
WHERE state IN ('ready', 'leased')"#;
const SUPERSEDE_JOB_SQL: &str = r#"UPDATE reconciliation_jobs
SET state = 'superseded', revision = revision + 1,
    next_attempt_unix_ms = NULL, lease_owner = NULL, lease_expires_unix_ms = NULL,
    updated_at_unix_ms = ?
WHERE job_id = ? AND revision = ? AND state IN ('ready', 'leased')"#;
const INSERT_JOB_SQL: &str = r#"INSERT INTO reconciliation_jobs (
    job_id, trade_id, input_generation, evidence_policy_sha256, state, revision,
    attempt_count, failure_count, max_attempts, lease_duration_ms,
    lease_renewal_ms, initial_backoff_ms, maximum_backoff_ms,
    next_attempt_unix_ms, lease_owner, lease_expires_unix_ms,
    created_at_unix_ms, updated_at_unix_ms
) VALUES (?, ?, ?, ?, 'ready', 1, 0, 0, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)"#;
const EXHAUST_EXPIRED_SQL: &str = r#"UPDATE reconciliation_jobs
SET state = 'exhausted', revision = revision + 1,
    failure_count = attempt_count, lease_owner = NULL, lease_expires_unix_ms = NULL,
    updated_at_unix_ms = ?
WHERE job_id IN (
    SELECT job_id FROM reconciliation_jobs
    WHERE state = 'leased' AND lease_expires_unix_ms <= ?
        AND attempt_count >= max_attempts AND updated_at_unix_ms <= ?
    ORDER BY lease_expires_unix_ms, created_at_unix_ms, job_id
    LIMIT 65536
)"#;
const READ_CLAIMABLE_SQL: &str = r#"SELECT
    length(job_id) AS job_id_bytes, substr(job_id, 1, 33) AS job_id,
    length(trade_id) AS trade_id_bytes, substr(trade_id, 1, 17) AS trade_id,
    input_generation,
    length(evidence_policy_sha256) AS evidence_policy_bytes,
    substr(evidence_policy_sha256, 1, 33) AS evidence_policy_sha256,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 12) AS state,
    revision, attempt_count, failure_count, max_attempts,
    lease_duration_ms, lease_renewal_ms, initial_backoff_ms, maximum_backoff_ms,
    next_attempt_unix_ms,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE length(lease_owner) END AS lease_owner_bytes,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE substr(lease_owner, 1, 17) END AS lease_owner,
    lease_expires_unix_ms, created_at_unix_ms, updated_at_unix_ms
FROM reconciliation_jobs
WHERE attempt_count < max_attempts AND updated_at_unix_ms <= ? AND (
    (state = 'ready' AND next_attempt_unix_ms <= ?)
    OR (state = 'leased' AND lease_expires_unix_ms <= ?)
)
ORDER BY
    CASE state WHEN 'ready' THEN next_attempt_unix_ms ELSE lease_expires_unix_ms END,
    created_at_unix_ms, job_id
LIMIT 1"#;
const CLAIM_JOB_SQL: &str = r#"UPDATE reconciliation_jobs
SET state = 'leased', revision = revision + 1, attempt_count = attempt_count + 1,
    next_attempt_unix_ms = NULL, lease_owner = ?, lease_expires_unix_ms = ?,
    updated_at_unix_ms = ?
WHERE job_id = ? AND revision = ? AND attempt_count < max_attempts
    AND updated_at_unix_ms <= ? AND (
        (state = 'ready' AND next_attempt_unix_ms <= ?)
        OR (state = 'leased' AND lease_expires_unix_ms <= ?)
    )"#;
const RENEW_JOB_SQL: &str = r#"UPDATE reconciliation_jobs
SET revision = revision + 1, lease_expires_unix_ms = ?, updated_at_unix_ms = ?
WHERE job_id = ? AND revision = ? AND state = 'leased'
    AND lease_owner = ? AND lease_expires_unix_ms = ?
    AND lease_expires_unix_ms > ? AND updated_at_unix_ms <= ?"#;
const RETRY_JOB_SQL: &str = r#"UPDATE reconciliation_jobs
SET state = 'ready', revision = revision + 1, failure_count = failure_count + 1,
    next_attempt_unix_ms = ?, lease_owner = NULL, lease_expires_unix_ms = NULL,
    updated_at_unix_ms = ?
WHERE job_id = ? AND revision = ? AND state = 'leased'
    AND lease_owner = ? AND lease_expires_unix_ms = ?
    AND lease_expires_unix_ms > ? AND attempt_count < max_attempts"#;
const EXHAUST_JOB_SQL: &str = r#"UPDATE reconciliation_jobs
SET state = 'exhausted', revision = revision + 1, failure_count = failure_count + 1,
    next_attempt_unix_ms = NULL, lease_owner = NULL, lease_expires_unix_ms = NULL,
    updated_at_unix_ms = ?
WHERE job_id = ? AND revision = ? AND state = 'leased'
    AND lease_owner = ? AND lease_expires_unix_ms = ?
    AND lease_expires_unix_ms > ? AND attempt_count >= max_attempts"#;

/// Stable durable reconciliation-job lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiReconciliationJobState {
    Ready,
    Leased,
    Exhausted,
    Superseded,
    Completed,
}

impl RhiReconciliationJobState {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Leased => "leased",
            Self::Exhausted => "exhausted",
            Self::Superseded => "superseded",
            Self::Completed => "completed",
        }
    }
}

/// Stable source-free durable job failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationJobErrorKind {
    InvalidMode,
    InvalidInput,
    QueueFull,
    DirtyGenerationConflict,
    LeaseLost,
    NotReady,
    Storage,
    CommitOutcomeUnknown,
}

impl RhiReconciliationJobErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "reconciliation_job_mode_invalid",
            Self::InvalidInput => "reconciliation_job_input_invalid",
            Self::QueueFull => "reconciliation_queue_full",
            Self::DirtyGenerationConflict => "reconciliation_dirty_generation_conflict",
            Self::LeaseLost => "reconciliation_lease_lost",
            Self::NotReady => "reconciliation_job_not_ready",
            Self::Storage => "reconciliation_job_storage_failed",
            Self::CommitOutcomeUnknown => "reconciliation_job_commit_outcome_unknown",
        }
    }
}

/// Redacted source-free durable job failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationJobError {
    kind: RhiReconciliationJobErrorKind,
}

impl RhiReconciliationJobError {
    const fn new(kind: RhiReconciliationJobErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiReconciliationJobErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiReconciliationJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiReconciliationJobErrorKind::InvalidMode => {
                "RHI reconciliation jobs require writable state"
            }
            RhiReconciliationJobErrorKind::InvalidInput => {
                "RHI reconciliation job input is invalid"
            }
            RhiReconciliationJobErrorKind::QueueFull => {
                "RHI reconciliation job capacity is exhausted"
            }
            RhiReconciliationJobErrorKind::DirtyGenerationConflict => {
                "RHI reconciliation dirty generation changed"
            }
            RhiReconciliationJobErrorKind::LeaseLost => {
                "RHI reconciliation lease is no longer authoritative"
            }
            RhiReconciliationJobErrorKind::NotReady => "RHI reconciliation job is not ready",
            RhiReconciliationJobErrorKind::Storage => "RHI reconciliation job transaction failed",
            RhiReconciliationJobErrorKind::CommitOutcomeUnknown => {
                "RHI reconciliation job commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for RhiReconciliationJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationJobError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiReconciliationJobError {}

/// Validated numeric scheduling authority copied into each durable job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiReconciliationJobPolicy {
    queue_capacity: u32,
    lease_duration_ms: u64,
    lease_renewal_ms: u64,
    max_attempts: u16,
    initial_backoff_ms: u64,
    maximum_backoff_ms: u64,
}

impl RhiReconciliationJobPolicy {
    /// Constructs an explicit bounded policy with no ambient defaults.
    pub fn new(
        queue_capacity: u32,
        lease_duration_ms: u64,
        lease_renewal_ms: u64,
        max_attempts: u16,
        initial_backoff_ms: u64,
        maximum_backoff_ms: u64,
    ) -> Result<Self, RhiReconciliationJobError> {
        if queue_capacity == 0
            || queue_capacity > RHI_RECONCILIATION_JOB_MAX_ACTIVE
            || !(1_000..=MAX_LEASE_MILLISECONDS).contains(&lease_duration_ms)
            || !(100..=MAX_RENEWAL_MILLISECONDS).contains(&lease_renewal_ms)
            || lease_renewal_ms >= lease_duration_ms
            || max_attempts == 0
            || max_attempts > MAX_ATTEMPTS
            || !(1..=MAX_INITIAL_BACKOFF_MILLISECONDS).contains(&initial_backoff_ms)
            || !(1..=MAX_BACKOFF_MILLISECONDS).contains(&maximum_backoff_ms)
            || initial_backoff_ms > maximum_backoff_ms
        {
            return Err(RhiReconciliationJobError::new(
                RhiReconciliationJobErrorKind::InvalidInput,
            ));
        }
        Ok(Self {
            queue_capacity,
            lease_duration_ms,
            lease_renewal_ms,
            max_attempts,
            initial_backoff_ms,
            maximum_backoff_ms,
        })
    }

    /// Extracts the exact admitted reconciliation policy from one immutable configuration.
    pub fn from_configuration(
        configuration: &RhiConfigDocumentV1,
    ) -> Result<Self, RhiReconciliationJobError> {
        let value = |pointer: &str| {
            configuration
                .normalized()
                .pointer(pointer)
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    RhiReconciliationJobError::new(RhiReconciliationJobErrorKind::InvalidInput)
                })
        };
        Self::new(
            u32::try_from(value("/reconciliation/queue_capacity")?).map_err(|_| {
                RhiReconciliationJobError::new(RhiReconciliationJobErrorKind::InvalidInput)
            })?,
            value("/reconciliation/lease_ms")?,
            value("/reconciliation/lease_renewal_ms")?,
            u16::try_from(value("/reconciliation/max_attempts")?).map_err(|_| {
                RhiReconciliationJobError::new(RhiReconciliationJobErrorKind::InvalidInput)
            })?,
            value("/reconciliation/initial_backoff_ms")?,
            value("/reconciliation/maximum_backoff_ms")?,
        )
    }

    #[must_use]
    pub const fn queue_capacity(self) -> u32 {
        self.queue_capacity
    }

    #[must_use]
    pub const fn lease_duration_milliseconds(self) -> u64 {
        self.lease_duration_ms
    }

    #[must_use]
    pub const fn lease_renewal_milliseconds(self) -> u64 {
        self.lease_renewal_ms
    }

    #[must_use]
    pub const fn max_attempts(self) -> u16 {
        self.max_attempts
    }

    #[must_use]
    pub const fn initial_backoff_milliseconds(self) -> u64 {
        self.initial_backoff_ms
    }

    #[must_use]
    pub const fn maximum_backoff_milliseconds(self) -> u64 {
        self.maximum_backoff_ms
    }
}

/// Injected wall-clock millisecond used only for durable scheduling evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RhiReconciliationUnixMilliseconds(u64);

impl RhiReconciliationUnixMilliseconds {
    pub fn new(value: u64) -> Result<Self, RhiReconciliationJobError> {
        if value > MAX_UNIX_MILLISECONDS {
            return Err(RhiReconciliationJobError::new(
                RhiReconciliationJobErrorKind::InvalidInput,
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Injected full-jitter delay for one failed reconciliation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RhiReconciliationRetryDelayMilliseconds(u64);

impl RhiReconciliationRetryDelayMilliseconds {
    pub fn new(value: u64) -> Result<Self, RhiReconciliationJobError> {
        if value > MAX_BACKOFF_MILLISECONDS {
            return Err(RhiReconciliationJobError::new(
                RhiReconciliationJobErrorKind::InvalidInput,
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable process-local owner token for compare-and-swap leases.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiReconciliationLeaseOwner([u8; LEASE_OWNER_BYTES]);

impl RhiReconciliationLeaseOwner {
    pub fn from_bytes(bytes: [u8; LEASE_OWNER_BYTES]) -> Result<Self, RhiReconciliationJobError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RhiReconciliationJobError::new(
                RhiReconciliationJobErrorKind::InvalidInput,
            ));
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for RhiReconciliationLeaseOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiReconciliationLeaseOwner([redacted])")
    }
}

/// Deterministic identity of one trade generation and evidence policy.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiReconciliationJobId([u8; 32]);

impl RhiReconciliationJobId {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RhiReconciliationJobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiReconciliationJobId([redacted])")
    }
}

/// Immutable decoded view of one retained durable job row.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationJob {
    id: RhiReconciliationJobId,
    trade_id: TradeId,
    input_generation: u64,
    policy_digest: RhiEvidencePolicyDigest,
    state: RhiReconciliationJobState,
    revision: u64,
    attempt_count: u16,
    failure_count: u16,
    policy: RhiReconciliationJobPolicy,
    next_attempt: Option<RhiReconciliationUnixMilliseconds>,
    lease_owner: Option<RhiReconciliationLeaseOwner>,
    lease_expires: Option<RhiReconciliationUnixMilliseconds>,
    created_at: RhiReconciliationUnixMilliseconds,
    updated_at: RhiReconciliationUnixMilliseconds,
}

impl RhiReconciliationJob {
    pub(crate) const fn attempt_policy_matches(self, expected: RhiReconciliationJobPolicy) -> bool {
        self.policy.lease_duration_ms == expected.lease_duration_ms
            && self.policy.lease_renewal_ms == expected.lease_renewal_ms
            && self.policy.max_attempts == expected.max_attempts
            && self.policy.initial_backoff_ms == expected.initial_backoff_ms
            && self.policy.maximum_backoff_ms == expected.maximum_backoff_ms
    }

    #[must_use]
    pub const fn id(self) -> RhiReconciliationJobId {
        self.id
    }

    #[must_use]
    pub const fn trade_id(self) -> TradeId {
        self.trade_id
    }

    #[must_use]
    pub const fn input_generation(self) -> u64 {
        self.input_generation
    }

    #[must_use]
    pub const fn evidence_policy_digest(self) -> RhiEvidencePolicyDigest {
        self.policy_digest
    }

    #[must_use]
    pub const fn state(self) -> RhiReconciliationJobState {
        self.state
    }

    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn attempt_count(self) -> u16 {
        self.attempt_count
    }

    #[must_use]
    pub const fn failure_count(self) -> u16 {
        self.failure_count
    }

    #[must_use]
    pub const fn next_attempt(self) -> Option<RhiReconciliationUnixMilliseconds> {
        self.next_attempt
    }

    #[must_use]
    pub const fn created_at(self) -> RhiReconciliationUnixMilliseconds {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(self) -> RhiReconciliationUnixMilliseconds {
        self.updated_at
    }
}

impl fmt::Debug for RhiReconciliationJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationJob")
            .field("identity", &"[redacted]")
            .field("state", &self.state)
            .field("revision", &self.revision)
            .field("attempt_count", &self.attempt_count)
            .field("failure_count", &self.failure_count)
            .field("next_attempt", &self.next_attempt)
            .field("lease", &self.lease_owner.map(|_| "[redacted]"))
            .field("lease_expires", &self.lease_expires)
            .finish()
    }
}

/// Idempotent schedule result for one exact dirty generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiReconciliationScheduleOutcome {
    job: RhiReconciliationJob,
    created: bool,
}

impl RhiReconciliationScheduleOutcome {
    #[must_use]
    pub const fn job(self) -> RhiReconciliationJob {
        self.job
    }

    #[must_use]
    pub const fn created(self) -> bool {
        self.created
    }
}

/// Non-forgeable compare-and-swap lease returned by a successful claim.
///
/// ```compile_fail
/// use rhi::RhiReconciliationLease;
///
/// let _ = RhiReconciliationLease { job: todo!(), owner: todo!(), lease_expires: todo!() };
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationLease {
    job: RhiReconciliationJob,
    owner: RhiReconciliationLeaseOwner,
    lease_expires: RhiReconciliationUnixMilliseconds,
}

impl RhiReconciliationLease {
    #[must_use]
    pub const fn job(self) -> RhiReconciliationJob {
        self.job
    }

    #[must_use]
    pub const fn lease_expires(self) -> RhiReconciliationUnixMilliseconds {
        self.lease_expires
    }

    #[must_use]
    pub fn renewal_due(self) -> RhiReconciliationUnixMilliseconds {
        RhiReconciliationUnixMilliseconds(
            self.lease_expires()
                .get()
                .saturating_sub(self.job.policy.lease_renewal_ms),
        )
    }

    #[must_use]
    pub fn retry_delay_upper_bound(self) -> u64 {
        retry_delay_upper_bound(self.job.policy, self.job.failure_count)
    }
}

impl fmt::Debug for RhiReconciliationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationLease")
            .field("job", &self.job)
            .field("owner", &"[redacted]")
            .finish()
    }
}

impl RhiReconciliationJobRepository<'_> {
    /// Idempotently schedules the current durable dirty generation for one trade.
    pub async fn schedule_trade(
        &self,
        trade_id: TradeId,
        policy: RhiReconciliationJobPolicy,
        now: RhiReconciliationUnixMilliseconds,
    ) -> Result<RhiReconciliationScheduleOutcome, RhiReconciliationJobError> {
        require_writable(self)?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { schedule(transaction, trade_id, policy, now).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Claims the oldest eligible job or reclaims one expired lease.
    pub async fn claim_next(
        &self,
        owner: RhiReconciliationLeaseOwner,
        now: RhiReconciliationUnixMilliseconds,
    ) -> Result<Option<RhiReconciliationLease>, RhiReconciliationJobError> {
        require_writable(self)?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { claim_next(transaction, owner, now).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Renews an unexpired lease only after its configured renewal point.
    pub async fn renew(
        &self,
        lease: RhiReconciliationLease,
        now: RhiReconciliationUnixMilliseconds,
    ) -> Result<RhiReconciliationLease, RhiReconciliationJobError> {
        require_writable(self)?;
        if now >= lease.lease_expires() {
            return Err(RhiReconciliationJobError::new(
                RhiReconciliationJobErrorKind::LeaseLost,
            ));
        }
        if now < lease.renewal_due() {
            return Err(RhiReconciliationJobError::new(
                RhiReconciliationJobErrorKind::NotReady,
            ));
        }
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { renew(transaction, lease, now).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Records one failed leased attempt and schedules bounded full-jitter retry.
    pub async fn record_failure(
        &self,
        lease: RhiReconciliationLease,
        now: RhiReconciliationUnixMilliseconds,
        delay: RhiReconciliationRetryDelayMilliseconds,
    ) -> Result<RhiReconciliationJob, RhiReconciliationJobError> {
        require_writable(self)?;
        if now >= lease.lease_expires() {
            return Err(RhiReconciliationJobError::new(
                RhiReconciliationJobErrorKind::LeaseLost,
            ));
        }
        if delay.get() > lease.retry_delay_upper_bound() {
            return Err(RhiReconciliationJobError::new(
                RhiReconciliationJobErrorKind::InvalidInput,
            ));
        }
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { record_failure(transaction, lease, now, delay).await })
            })
            .await
            .map_err(map_transaction_error)
    }
}

fn require_writable(
    repository: &RhiReconciliationJobRepository<'_>,
) -> Result<(), RhiReconciliationJobError> {
    if repository.host().mode() == RhiStateHostMode::ReadWriteExisting {
        Ok(())
    } else {
        Err(RhiReconciliationJobError::new(
            RhiReconciliationJobErrorKind::InvalidMode,
        ))
    }
}

async fn schedule(
    transaction: &mut ServiceSqliteTransaction<'_>,
    trade_id: TradeId,
    policy: RhiReconciliationJobPolicy,
    now: RhiReconciliationUnixMilliseconds,
) -> Result<RhiReconciliationScheduleOutcome, OperationError> {
    let dirty = read_dirty(transaction, trade_id).await?;
    let id = job_id(trade_id, dirty.generation, dirty.policy);
    if let Some(job) = read_job(transaction, id).await? {
        if job.trade_id != trade_id
            || job.input_generation != dirty.generation
            || job.policy_digest != dirty.policy
        {
            return Err(OperationError::Storage);
        }
        return Ok(RhiReconciliationScheduleOutcome {
            job,
            created: false,
        });
    }

    if let Some(active) = read_active_job(transaction, trade_id).await? {
        if active.input_generation >= dirty.generation {
            return Err(OperationError::DirtyGenerationConflict);
        }
        let result = sqlx::query(SUPERSEDE_JOB_SQL)
            .bind(i64_value(now.get())?)
            .bind(active.id.as_bytes().as_slice())
            .bind(i64_value(active.revision)?)
            .execute(&mut *transaction)
            .await
            .map_err(|_| OperationError::Storage)?;
        if result.rows_affected() != 1 {
            return Err(OperationError::DirtyGenerationConflict);
        }
    }

    let active = sqlx::query(ACTIVE_JOB_COUNT_SQL)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?
        .try_get::<i64, _>("active_count")
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(OperationError::Storage)?;
    if active >= policy.queue_capacity {
        return Err(OperationError::QueueFull);
    }

    let now = i64_value(now.get())?;
    let result = sqlx::query(INSERT_JOB_SQL)
        .bind(id.as_bytes().as_slice())
        .bind(trade_id.as_bytes().as_slice())
        .bind(i64_value(dirty.generation)?)
        .bind(dirty.policy.as_bytes().as_slice())
        .bind(i64::from(policy.max_attempts))
        .bind(i64_value(policy.lease_duration_ms)?)
        .bind(i64_value(policy.lease_renewal_ms)?)
        .bind(i64_value(policy.initial_backoff_ms)?)
        .bind(i64_value(policy.maximum_backoff_ms)?)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::Storage);
    }
    let job = read_job(transaction, id)
        .await?
        .ok_or(OperationError::Storage)?;
    Ok(RhiReconciliationScheduleOutcome { job, created: true })
}

async fn claim_next(
    transaction: &mut ServiceSqliteTransaction<'_>,
    owner: RhiReconciliationLeaseOwner,
    now: RhiReconciliationUnixMilliseconds,
) -> Result<Option<RhiReconciliationLease>, OperationError> {
    let now_value = i64_value(now.get())?;
    sqlx::query(EXHAUST_EXPIRED_SQL)
        .bind(now_value)
        .bind(now_value)
        .bind(now_value)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    let Some(row) = sqlx::query(READ_CLAIMABLE_SQL)
        .bind(now_value)
        .bind(now_value)
        .bind(now_value)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?
    else {
        return Ok(None);
    };
    let candidate = decode_job(row)?;
    let expires = now
        .get()
        .checked_add(candidate.policy.lease_duration_ms)
        .filter(|value| *value <= MAX_UNIX_MILLISECONDS)
        .ok_or(OperationError::InvalidInput)?;
    let result = sqlx::query(CLAIM_JOB_SQL)
        .bind(owner.0.as_slice())
        .bind(i64_value(expires)?)
        .bind(now_value)
        .bind(candidate.id.as_bytes().as_slice())
        .bind(i64_value(candidate.revision)?)
        .bind(now_value)
        .bind(now_value)
        .bind(now_value)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::LeaseLost);
    }
    let job = read_job(transaction, candidate.id)
        .await?
        .filter(|job| job.state == RhiReconciliationJobState::Leased)
        .ok_or(OperationError::Storage)?;
    let lease_expires = job.lease_expires.ok_or(OperationError::Storage)?;
    Ok(Some(RhiReconciliationLease {
        job,
        owner,
        lease_expires,
    }))
}

async fn renew(
    transaction: &mut ServiceSqliteTransaction<'_>,
    lease: RhiReconciliationLease,
    now: RhiReconciliationUnixMilliseconds,
) -> Result<RhiReconciliationLease, OperationError> {
    let previous_expiry = lease.lease_expires().get();
    let expires = now
        .get()
        .checked_add(lease.job.policy.lease_duration_ms)
        .filter(|value| *value > previous_expiry && *value <= MAX_UNIX_MILLISECONDS)
        .ok_or(OperationError::NotReady)?;
    let result = sqlx::query(RENEW_JOB_SQL)
        .bind(i64_value(expires)?)
        .bind(i64_value(now.get())?)
        .bind(lease.job.id.as_bytes().as_slice())
        .bind(i64_value(lease.job.revision)?)
        .bind(lease.owner.0.as_slice())
        .bind(i64_value(previous_expiry)?)
        .bind(i64_value(now.get())?)
        .bind(i64_value(now.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::LeaseLost);
    }
    let job = read_job(transaction, lease.job.id)
        .await?
        .filter(|job| job.state == RhiReconciliationJobState::Leased)
        .ok_or(OperationError::Storage)?;
    Ok(RhiReconciliationLease {
        job,
        owner: lease.owner,
        lease_expires: job.lease_expires.ok_or(OperationError::Storage)?,
    })
}

async fn record_failure(
    transaction: &mut ServiceSqliteTransaction<'_>,
    lease: RhiReconciliationLease,
    now: RhiReconciliationUnixMilliseconds,
    delay: RhiReconciliationRetryDelayMilliseconds,
) -> Result<RhiReconciliationJob, OperationError> {
    let now_value = i64_value(now.get())?;
    let query = if lease.job.attempt_count >= lease.job.policy.max_attempts {
        sqlx::query(EXHAUST_JOB_SQL)
            .bind(now_value)
            .bind(lease.job.id.as_bytes().as_slice())
            .bind(i64_value(lease.job.revision)?)
            .bind(lease.owner.0.as_slice())
            .bind(i64_value(lease.lease_expires().get())?)
            .bind(now_value)
    } else {
        let next = now
            .get()
            .checked_add(delay.get())
            .filter(|value| *value <= MAX_UNIX_MILLISECONDS)
            .ok_or(OperationError::InvalidInput)?;
        sqlx::query(RETRY_JOB_SQL)
            .bind(i64_value(next)?)
            .bind(now_value)
            .bind(lease.job.id.as_bytes().as_slice())
            .bind(i64_value(lease.job.revision)?)
            .bind(lease.owner.0.as_slice())
            .bind(i64_value(lease.lease_expires().get())?)
            .bind(now_value)
    };
    let result = query
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::LeaseLost);
    }
    read_job(transaction, lease.job.id)
        .await?
        .ok_or(OperationError::Storage)
}

async fn read_dirty(
    transaction: &mut ServiceSqliteTransaction<'_>,
    trade_id: TradeId,
) -> Result<DirtyGeneration, OperationError> {
    let row = sqlx::query(READ_DIRTY_SQL)
        .bind(trade_id.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?
        .ok_or(OperationError::DirtyGenerationConflict)?;
    Ok(DirtyGeneration {
        generation: positive_u64(&row, "generation")?,
        policy: RhiEvidencePolicyDigest::from_bytes(exact_bytes::<32>(
            &row,
            "evidence_policy_sha256",
            "evidence_policy_bytes",
        )?),
    })
}

async fn read_job(
    transaction: &mut ServiceSqliteTransaction<'_>,
    id: RhiReconciliationJobId,
) -> Result<Option<RhiReconciliationJob>, OperationError> {
    sqlx::query(READ_JOB_SQL)
        .bind(id.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?
        .map(decode_job)
        .transpose()
}

async fn read_active_job(
    transaction: &mut ServiceSqliteTransaction<'_>,
    trade_id: TradeId,
) -> Result<Option<RhiReconciliationJob>, OperationError> {
    let rows = sqlx::query(READ_ACTIVE_JOB_SQL)
        .bind(trade_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    match rows.len() {
        0 => Ok(None),
        1 => Ok(Some(decode_job(
            rows.into_iter().next().ok_or(OperationError::Storage)?,
        )?)),
        _ => Err(OperationError::Storage),
    }
}

fn decode_job(row: sqlx::sqlite::SqliteRow) -> Result<RhiReconciliationJob, OperationError> {
    let id = RhiReconciliationJobId(exact_bytes::<32>(&row, "job_id", "job_id_bytes")?);
    let trade_id = TradeId::from_bytes(exact_bytes::<16>(&row, "trade_id", "trade_id_bytes")?);
    let input_generation = positive_u64(&row, "input_generation")?;
    let policy_digest = RhiEvidencePolicyDigest::from_bytes(exact_bytes::<32>(
        &row,
        "evidence_policy_sha256",
        "evidence_policy_bytes",
    )?);
    let state = match bounded_text(&row, "state", "state_bytes", 10)?.as_str() {
        "ready" => RhiReconciliationJobState::Ready,
        "leased" => RhiReconciliationJobState::Leased,
        "exhausted" => RhiReconciliationJobState::Exhausted,
        "superseded" => RhiReconciliationJobState::Superseded,
        "completed" => RhiReconciliationJobState::Completed,
        _ => return Err(OperationError::Storage),
    };
    let revision = positive_u64(&row, "revision")?;
    let attempt_count = bounded_u16(&row, "attempt_count", 0, MAX_ATTEMPTS)?;
    let failure_count = bounded_u16(&row, "failure_count", 0, attempt_count)?;
    let max_attempts = bounded_u16(&row, "max_attempts", 1, MAX_ATTEMPTS)?;
    let lease_duration_ms = bounded_u64(&row, "lease_duration_ms", 1_000, MAX_LEASE_MILLISECONDS)?;
    let lease_renewal_ms = bounded_u64(&row, "lease_renewal_ms", 100, MAX_RENEWAL_MILLISECONDS)?;
    let initial_backoff_ms = bounded_u64(
        &row,
        "initial_backoff_ms",
        1,
        MAX_INITIAL_BACKOFF_MILLISECONDS,
    )?;
    let maximum_backoff_ms = bounded_u64(&row, "maximum_backoff_ms", 1, MAX_BACKOFF_MILLISECONDS)?;
    let policy = RhiReconciliationJobPolicy::new(
        RHI_RECONCILIATION_JOB_MAX_ACTIVE,
        lease_duration_ms,
        lease_renewal_ms,
        max_attempts,
        initial_backoff_ms,
        maximum_backoff_ms,
    )
    .map_err(|_| OperationError::Storage)?;
    let next_attempt = optional_millis(&row, "next_attempt_unix_ms")?;
    let lease_expires = optional_millis(&row, "lease_expires_unix_ms")?;
    let lease_owner = optional_owner(&row)?;
    let created_at =
        RhiReconciliationUnixMilliseconds(nonnegative_u64(&row, "created_at_unix_ms")?);
    let updated_at =
        RhiReconciliationUnixMilliseconds(nonnegative_u64(&row, "updated_at_unix_ms")?);
    if updated_at < created_at
        || failure_count > attempt_count
        || job_id(trade_id, input_generation, policy_digest) != id
        || !valid_state_fields(
            state,
            attempt_count,
            max_attempts,
            next_attempt,
            lease_owner,
            lease_expires,
        )
    {
        return Err(OperationError::Storage);
    }
    Ok(RhiReconciliationJob {
        id,
        trade_id,
        input_generation,
        policy_digest,
        state,
        revision,
        attempt_count,
        failure_count,
        policy,
        next_attempt,
        lease_owner,
        lease_expires,
        created_at,
        updated_at,
    })
}

fn valid_state_fields(
    state: RhiReconciliationJobState,
    attempt_count: u16,
    max_attempts: u16,
    next_attempt: Option<RhiReconciliationUnixMilliseconds>,
    owner: Option<RhiReconciliationLeaseOwner>,
    expires: Option<RhiReconciliationUnixMilliseconds>,
) -> bool {
    match state {
        RhiReconciliationJobState::Ready => {
            attempt_count < max_attempts
                && next_attempt.is_some()
                && owner.is_none()
                && expires.is_none()
        }
        RhiReconciliationJobState::Leased => {
            attempt_count > 0
                && attempt_count <= max_attempts
                && next_attempt.is_none()
                && owner.is_some()
                && expires.is_some()
        }
        RhiReconciliationJobState::Exhausted
        | RhiReconciliationJobState::Superseded
        | RhiReconciliationJobState::Completed => {
            next_attempt.is_none() && owner.is_none() && expires.is_none()
        }
    }
}

fn job_id(
    trade_id: TradeId,
    generation: u64,
    policy: RhiEvidencePolicyDigest,
) -> RhiReconciliationJobId {
    let mut hasher = Sha256::new();
    hasher.update(JOB_ID_DOMAIN);
    hasher.update(trade_id.as_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update(policy.as_bytes());
    RhiReconciliationJobId(hasher.finalize().into())
}

fn retry_delay_upper_bound(policy: RhiReconciliationJobPolicy, failure_count: u16) -> u64 {
    let exponent = u32::from(failure_count.min(63));
    policy
        .initial_backoff_ms
        .saturating_mul(1_u64.checked_shl(exponent).unwrap_or(u64::MAX))
        .min(policy.maximum_backoff_ms)
}

fn exact_bytes<const N: usize>(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    length_field: &str,
) -> Result<[u8; N], OperationError> {
    if row.try_get::<i64, _>(length_field).ok() != i64::try_from(N).ok() {
        return Err(OperationError::Storage);
    }
    row.try_get::<Vec<u8>, _>(field)
        .map_err(|_| OperationError::Storage)?
        .try_into()
        .map_err(|_| OperationError::Storage)
}

fn optional_owner(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Option<RhiReconciliationLeaseOwner>, OperationError> {
    let length = row
        .try_get::<Option<i64>, _>("lease_owner_bytes")
        .map_err(|_| OperationError::Storage)?;
    match length {
        None => Ok(None),
        Some(value) if value == LEASE_OWNER_BYTES as i64 => {
            let bytes: [u8; LEASE_OWNER_BYTES] = row
                .try_get::<Vec<u8>, _>("lease_owner")
                .map_err(|_| OperationError::Storage)?
                .try_into()
                .map_err(|_| OperationError::Storage)?;
            RhiReconciliationLeaseOwner::from_bytes(bytes)
                .map(Some)
                .map_err(|_| OperationError::Storage)
        }
        Some(_) => Err(OperationError::Storage),
    }
}

fn bounded_text(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    length_field: &str,
    maximum: usize,
) -> Result<String, OperationError> {
    let length = row
        .try_get::<i64, _>(length_field)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0 && *value <= maximum)
        .ok_or(OperationError::Storage)?;
    let value = row
        .try_get::<String, _>(field)
        .map_err(|_| OperationError::Storage)?;
    if value.len() == length {
        Ok(value)
    } else {
        Err(OperationError::Storage)
    }
}

fn bounded_u16(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    minimum: u16,
    maximum: u16,
) -> Result<u16, OperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .ok_or(OperationError::Storage)
}

fn bounded_u64(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    minimum: u64,
    maximum: u64,
) -> Result<u64, OperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| (*value >= minimum) && (*value <= maximum))
        .ok_or(OperationError::Storage)
}

fn positive_u64(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<u64, OperationError> {
    bounded_u64(row, field, 1, MAX_UNIX_MILLISECONDS)
}

fn nonnegative_u64(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<u64, OperationError> {
    bounded_u64(row, field, 0, MAX_UNIX_MILLISECONDS)
}

fn optional_millis(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
) -> Result<Option<RhiReconciliationUnixMilliseconds>, OperationError> {
    row.try_get::<Option<i64>, _>(field)
        .map_err(|_| OperationError::Storage)?
        .map(|value| {
            u64::try_from(value)
                .map(RhiReconciliationUnixMilliseconds)
                .map_err(|_| OperationError::Storage)
        })
        .transpose()
}

fn i64_value(value: u64) -> Result<i64, OperationError> {
    i64::try_from(value).map_err(|_| OperationError::InvalidInput)
}

#[derive(Clone, Copy)]
struct DirtyGeneration {
    generation: u64,
    policy: RhiEvidencePolicyDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationError {
    InvalidInput,
    QueueFull,
    DirtyGenerationConflict,
    LeaseLost,
    NotReady,
    Storage,
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<OperationError>,
) -> RhiReconciliationJobError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return RhiReconciliationJobError::new(RhiReconciliationJobErrorKind::CommitOutcomeUnknown);
    }
    RhiReconciliationJobError::new(match error.operation_error().copied() {
        Some(OperationError::InvalidInput) => RhiReconciliationJobErrorKind::InvalidInput,
        Some(OperationError::QueueFull) => RhiReconciliationJobErrorKind::QueueFull,
        Some(OperationError::DirtyGenerationConflict) => {
            RhiReconciliationJobErrorKind::DirtyGenerationConflict
        }
        Some(OperationError::LeaseLost) => RhiReconciliationJobErrorKind::LeaseLost,
        Some(OperationError::NotReady) => RhiReconciliationJobErrorKind::NotReady,
        Some(OperationError::Storage) | None => RhiReconciliationJobErrorKind::Storage,
    })
}
