//! Atomic durable finalization of one independently verified attestation.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use radroots_trade::evidence::{
    RadrootsTradeEvidenceOutcomeV1, RadrootsTradeEvidenceSourceCompletionV1,
    RadrootsTradeEvidenceSourceRequirementV1,
};
use sha2::{Digest, Sha256};

use crate::{
    RhiPublicationAuthority, RhiPublicationMode, RhiPublicationOutboxId,
    RhiReconciliationAttemptRepository, RhiReconciliationLease, RhiReconciliationOutcome,
    RhiReconciliationUnixMilliseconds, RhiSignedEvidenceAttestation, RhiStateHostMode,
    reconciliation_finalization::{FinalizationIdentity, validate_finalization_identity},
};

/// Exact version of the atomic reconciliation-finalization commit contract.
pub const RHI_RECONCILIATION_FINALIZATION_COMMIT_CONTRACT_VERSION: u32 = 1;

const OUTBOX_ID_DOMAIN: &[u8] = b"radroots.rhi.publication_outbox.v1\0";

const INSERT_MANIFEST_SQL: &str = r#"INSERT INTO evidence_manifests (
    manifest_sha256, attempt_id, trade_id, trade_generation,
    evidence_policy_sha256, canonical_manifest, observed_at_unix_s,
    source_count, observation_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#;
const INSERT_PROJECTION_SQL: &str = r#"INSERT INTO trade_projections (
    projection_sha256, manifest_sha256, shared_projection_sha256,
    reducer_contract, reducer_contract_version, issue_count
) VALUES (?, ?, ?, 'radroots.trade.reducer.v1', 1, ?)"#;
const INSERT_REPORT_SQL: &str = r#"INSERT INTO attestation_reports (
    statement_sha256, manifest_sha256, projection_sha256, trade_id,
    claim_mutation_id, issuer_public_key, outcome, canonical_report,
    observed_at_unix_s, supersedes_statement_sha256, supersedes_event_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#;
const INSERT_SIGNED_EVENT_SQL: &str = r#"INSERT INTO signed_attestation_events (
    event_id, statement_sha256, event_sha256, issuer_public_key,
    authored_at_unix_s, canonical_event_json
) VALUES (?, ?, ?, ?, ?, ?)"#;
const INSERT_OUTBOX_SQL: &str = r#"INSERT INTO publication_outbox (
    outbox_id, event_id, event_sha256, publication_authority_sha256,
    target_set_sha256, target_count, required_target_count, max_attempts,
    initial_backoff_ms, maximum_backoff_ms, attempt_deadline_ms,
    state, revision, next_attempt_unix_ms, lease_owner,
    lease_expires_unix_ms, created_at_unix_ms, updated_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
    'pending', 1, ?, NULL, NULL, ?, ?)"#;
const INSERT_TARGET_SQL: &str = r#"INSERT INTO publication_targets (
    outbox_id, target_ordinal, relay_id, required, state, revision,
    attempt_count, next_attempt_unix_ms, last_attempt_id, updated_at_unix_ms
) VALUES (?, ?, ?, ?, 'pending', 1, 0, ?, NULL, ?)"#;
const COMPLETE_JOB_SQL: &str = r#"UPDATE reconciliation_jobs
SET state = 'completed', revision = revision + 1, next_attempt_unix_ms = NULL,
    lease_owner = NULL, lease_expires_unix_ms = NULL, updated_at_unix_ms = ?
WHERE job_id = ? AND state = 'leased' AND revision = ?
    AND lease_owner = ? AND lease_expires_unix_ms = ?
    AND updated_at_unix_ms <= ?"#;

/// Stable source-free atomic-finalization failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationFinalizationCommitErrorKind {
    InvalidMode,
    InvalidInput,
    LeaseLost,
    GenerationConflict,
    AttemptUnavailable,
    PublicationQueueFull,
    Conflict,
    Storage,
    CommitOutcomeUnknown,
}

impl RhiReconciliationFinalizationCommitErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "reconciliation_finalization_commit_mode_invalid",
            Self::InvalidInput => "reconciliation_finalization_commit_input_invalid",
            Self::LeaseLost => "reconciliation_finalization_commit_lease_lost",
            Self::GenerationConflict => "reconciliation_finalization_commit_generation_conflict",
            Self::AttemptUnavailable => "reconciliation_finalization_commit_attempt_unavailable",
            Self::PublicationQueueFull => "reconciliation_publication_queue_full",
            Self::Conflict => "reconciliation_finalization_commit_conflict",
            Self::Storage => "reconciliation_finalization_commit_storage_failed",
            Self::CommitOutcomeUnknown => "reconciliation_finalization_commit_outcome_unknown",
        }
    }
}

/// Redacted source-free atomic-finalization failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationFinalizationCommitError {
    kind: RhiReconciliationFinalizationCommitErrorKind,
}

impl RhiReconciliationFinalizationCommitError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiReconciliationFinalizationCommitErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiReconciliationFinalizationCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiReconciliationFinalizationCommitErrorKind::InvalidMode => {
                "RHI reconciliation finalization requires writable state"
            }
            RhiReconciliationFinalizationCommitErrorKind::InvalidInput => {
                "RHI reconciliation finalization commit input is invalid"
            }
            RhiReconciliationFinalizationCommitErrorKind::LeaseLost => {
                "RHI reconciliation finalization lease is no longer authoritative"
            }
            RhiReconciliationFinalizationCommitErrorKind::GenerationConflict => {
                "RHI reconciliation finalization generation changed"
            }
            RhiReconciliationFinalizationCommitErrorKind::AttemptUnavailable => {
                "RHI reconciliation finalization attempt is unavailable"
            }
            RhiReconciliationFinalizationCommitErrorKind::PublicationQueueFull => {
                "RHI publication queue capacity is exhausted"
            }
            RhiReconciliationFinalizationCommitErrorKind::Conflict => {
                "RHI reconciliation finalization conflicts with durable state"
            }
            RhiReconciliationFinalizationCommitErrorKind::Storage => {
                "RHI reconciliation finalization transaction failed"
            }
            RhiReconciliationFinalizationCommitErrorKind::CommitOutcomeUnknown => {
                "RHI reconciliation finalization outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for RhiReconciliationFinalizationCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationFinalizationCommitError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiReconciliationFinalizationCommitError {}

/// Durable result of one exact atomic finalization commit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationFinalizationCommitOutcome {
    created: bool,
    publication_mode: RhiPublicationMode,
    target_count: u8,
    outbox_id: Option<RhiPublicationOutboxId>,
}

impl RhiReconciliationFinalizationCommitOutcome {
    /// Reports whether this call created the immutable finalization inventory.
    #[must_use]
    pub const fn created(self) -> bool {
        self.created
    }

    /// Returns the explicit configured publication mode committed with the result.
    #[must_use]
    pub const fn publication_mode(self) -> RhiPublicationMode {
        self.publication_mode
    }

    /// Returns the exact immutable target count, or zero when publication is disabled.
    #[must_use]
    pub const fn target_count(self) -> u8 {
        self.target_count
    }

    /// Returns the immutable outbox identity when publication is required.
    #[must_use]
    pub const fn outbox_id(self) -> Option<RhiPublicationOutboxId> {
        self.outbox_id
    }
}

impl fmt::Debug for RhiReconciliationFinalizationCommitOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationFinalizationCommitOutcome")
            .field("created", &self.created)
            .field("publication_mode", &self.publication_mode)
            .field("target_count", &self.target_count)
            .field("outbox_id", &self.outbox_id.map(|_| "[redacted]"))
            .finish()
    }
}

impl RhiReconciliationAttemptRepository<'_> {
    /// Atomically persists one sealed signed result and finalizes its exact job.
    ///
    /// The attestation is borrowed so a caller can reconcile a lost commit
    /// acknowledgement by retrying the same sealed value. Exact prior success
    /// is recognized before the consumed lease is checked. No relay, source,
    /// clock, entropy, filesystem, or task operation occurs in this boundary.
    pub async fn commit_finalization(
        &self,
        attestation: &RhiSignedEvidenceAttestation,
        publication: &RhiPublicationAuthority,
        now: RhiReconciliationUnixMilliseconds,
    ) -> Result<RhiReconciliationFinalizationCommitOutcome, RhiReconciliationFinalizationCommitError>
    {
        if self.host().mode() != RhiStateHostMode::ReadWriteExisting {
            return Err(failure(
                RhiReconciliationFinalizationCommitErrorKind::InvalidMode,
            ));
        }
        if publication.configuration_sha256()
            != self.host().metadata().configuration_digest().as_bytes()
        {
            return Err(failure(
                RhiReconciliationFinalizationCommitErrorKind::InvalidInput,
            ));
        }
        let record = FinalizationRecord::from_inputs(attestation, publication, now)
            .ok_or_else(|| failure(RhiReconciliationFinalizationCommitErrorKind::InvalidInput))?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { commit(transaction, &record).await })
            })
            .await
            .map_err(map_transaction_error)
    }
}

struct FinalizationTarget {
    ordinal: u8,
    relay_id: Box<str>,
    required: bool,
}

struct FinalizationSource {
    source_id: Box<str>,
    required: bool,
    completion: RadrootsTradeEvidenceSourceCompletionV1,
    admitted_event_count: u32,
}

struct RequiredPublication {
    outbox_id: [u8; 32],
    authority_sha256: [u8; 32],
    target_set_sha256: [u8; 32],
    queue_capacity: u32,
    maximum_attempts: u16,
    initial_backoff_ms: u64,
    maximum_backoff_ms: u64,
    attempt_deadline_ms: u64,
    target_count: u8,
    targets: Box<[FinalizationTarget]>,
}

enum FinalizationPublication {
    Disabled,
    Required(RequiredPublication),
}

struct FinalizationRecord {
    lease: RhiReconciliationLease,
    identity: FinalizationIdentity,
    now: RhiReconciliationUnixMilliseconds,
    manifest_sha256: [u8; 32],
    canonical_manifest: Box<[u8]>,
    observed_at_unix_s: u64,
    source_count: u8,
    sources: Box<[FinalizationSource]>,
    observation_count: u32,
    projection_sha256: [u8; 32],
    shared_projection_sha256: [u8; 32],
    issue_count: u32,
    statement_sha256: [u8; 32],
    claim_mutation_id: [u8; 32],
    issuer_public_key: [u8; 32],
    outcome: &'static str,
    canonical_report: Box<[u8]>,
    supersession: Option<([u8; 32], [u8; 32])>,
    event_id: [u8; 32],
    event_sha256: [u8; 32],
    authored_at_unix_s: u64,
    canonical_event_json: Box<[u8]>,
    publication: FinalizationPublication,
}

impl FinalizationRecord {
    fn from_inputs(
        attestation: &RhiSignedEvidenceAttestation,
        publication: &RhiPublicationAuthority,
        now: RhiReconciliationUnixMilliseconds,
    ) -> Option<Self> {
        let fence = attestation.fence();
        let (lease, identity) = fence.validation_parts();
        let evaluation = fence.evaluation();
        let projection = evaluation.projection();
        let manifest = projection.manifest();
        let projection_sha256 = projection.digest()?;
        let shared_projection_sha256 = projection.shared_projection_digest()?;
        let source_count = u8::try_from(manifest.source_count()).ok()?;
        let sources = manifest
            .inner()
            .sources()
            .iter()
            .map(|source| {
                let result = source.result();
                FinalizationSource {
                    source_id: source.source_id().as_str().into(),
                    required: matches!(
                        result.requirement(),
                        RadrootsTradeEvidenceSourceRequirementV1::Required
                    ),
                    completion: result.completion(),
                    admitted_event_count: result.admitted_event_count(),
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let observation_count = u32::try_from(manifest.observation_count()).ok()?;
        let issue_count = u32::try_from(projection.issue_count()).ok()?;
        let observed_at_unix_s = manifest.observed_at_unix_seconds();
        if attestation.report_observed_at_unix_seconds() != observed_at_unix_s
            || [
                now.get(),
                observed_at_unix_s,
                attestation.created_at_unix_seconds(),
                manifest.trade_generation(),
            ]
            .iter()
            .any(|value| i64::try_from(*value).is_err())
        {
            return None;
        }
        let publication = match publication.mode() {
            RhiPublicationMode::Disabled => {
                if !publication.targets().is_empty() || publication.retry_policy().is_some() {
                    return None;
                }
                FinalizationPublication::Disabled
            }
            RhiPublicationMode::Required => {
                let retry = publication.retry_policy()?;
                let targets = publication
                    .targets()
                    .iter()
                    .map(|target| FinalizationTarget {
                        ordinal: target.ordinal(),
                        relay_id: target.relay_id().into(),
                        required: target.required(),
                    })
                    .collect::<Vec<_>>();
                if targets.is_empty()
                    || targets.len() > crate::RHI_PUBLICATION_MAX_TARGETS
                    || targets
                        .iter()
                        .enumerate()
                        .any(|(ordinal, target)| usize::from(target.ordinal) != ordinal)
                {
                    return None;
                }
                let target_count = u8::try_from(targets.len()).ok()?;
                FinalizationPublication::Required(RequiredPublication {
                    outbox_id: outbox_id(
                        attestation.event_id(),
                        publication.authority_sha256(),
                        publication.target_set_sha256(),
                    ),
                    authority_sha256: *publication.authority_sha256(),
                    target_set_sha256: *publication.target_set_sha256(),
                    queue_capacity: publication.queue_capacity(),
                    maximum_attempts: retry.maximum_attempts(),
                    initial_backoff_ms: retry.initial_backoff_milliseconds(),
                    maximum_backoff_ms: retry.maximum_backoff_milliseconds(),
                    attempt_deadline_ms: retry.attempt_deadline_milliseconds(),
                    target_count,
                    targets: targets.into_boxed_slice(),
                })
            }
        };
        Some(Self {
            lease,
            identity,
            now,
            manifest_sha256: manifest.digest(),
            canonical_manifest: manifest.canonical_bytes().into(),
            observed_at_unix_s,
            source_count,
            sources,
            observation_count,
            projection_sha256,
            shared_projection_sha256,
            issue_count,
            statement_sha256: attestation.statement_digest(),
            claim_mutation_id: attestation.claim_mutation_id_bytes(),
            issuer_public_key: attestation.issuer_public_key_bytes(),
            outcome: outcome_code(attestation.outcome()),
            canonical_report: attestation.canonical_report_bytes().into(),
            supersession: attestation.supersession_bytes(),
            event_id: *attestation.event_id(),
            event_sha256: *attestation.signed_event_sha256(),
            authored_at_unix_s: attestation.created_at_unix_seconds(),
            canonical_event_json: attestation.signed_event_bytes().into(),
            publication,
        })
    }

    fn outcome(&self, created: bool) -> RhiReconciliationFinalizationCommitOutcome {
        let (publication_mode, target_count, outbox_id) = match &self.publication {
            FinalizationPublication::Disabled => (RhiPublicationMode::Disabled, 0, None),
            FinalizationPublication::Required(required) => (
                RhiPublicationMode::Required,
                required.target_count,
                Some(RhiPublicationOutboxId::from_committed_bytes(
                    required.outbox_id,
                )),
            ),
        };
        RhiReconciliationFinalizationCommitOutcome {
            created,
            publication_mode,
            target_count,
            outbox_id,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationError {
    LeaseLost,
    GenerationConflict,
    AttemptUnavailable,
    QueueFull,
    Conflict,
    Storage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExistingState {
    Absent,
    Exact,
}

async fn commit(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<RhiReconciliationFinalizationCommitOutcome, OperationError> {
    match reconcile_existing(transaction, record).await? {
        ExistingState::Exact => return Ok(record.outcome(false)),
        ExistingState::Absent => {}
    }
    validate_finalization_identity(transaction, record.lease, record.identity, record.now)
        .await
        .map_err(|error| match error {
            crate::reconciliation_finalization::FinalizationOperationError::LeaseLost => {
                OperationError::LeaseLost
            }
            crate::reconciliation_finalization::FinalizationOperationError::GenerationConflict => {
                OperationError::GenerationConflict
            }
            crate::reconciliation_finalization::FinalizationOperationError::AttemptUnavailable => {
                OperationError::AttemptUnavailable
            }
            crate::reconciliation_finalization::FinalizationOperationError::Storage => {
                OperationError::Storage
            }
        })?;
    validate_source_inventory(transaction, record).await?;
    validate_advanced_checkpoints(transaction, record).await?;
    validate_supersession(transaction, record).await?;
    if let FinalizationPublication::Required(required) = &record.publication {
        let active: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM publication_outbox WHERE state != 'complete'")
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| OperationError::Storage)?;
        let active = u64::try_from(active).map_err(|_| OperationError::Storage)?;
        if active >= u64::from(required.queue_capacity) {
            return Err(OperationError::QueueFull);
        }
    }

    insert_finalization(transaction, record).await?;
    let lease_job = record.lease.job();
    let result = sqlx::query(COMPLETE_JOB_SQL)
        .bind(i64_value(record.now.get())?)
        .bind(record.identity.job_id.as_bytes().as_slice())
        .bind(i64_value(lease_job.revision())?)
        .bind(record.lease.owner_bytes().as_slice())
        .bind(i64_value(record.lease.lease_expires().get())?)
        .bind(i64_value(record.now.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(OperationError::LeaseLost);
    }
    Ok(record.outcome(true))
}

async fn validate_source_inventory(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<(), OperationError> {
    let attempt_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence_reconciliations WHERE attempt_id = ? AND source_count = ?",
    )
    .bind(record.identity.attempt_id.as_bytes().as_slice())
    .bind(i64::from(record.source_count))
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| OperationError::Storage)?;
    if attempt_count != 1 {
        return Err(OperationError::AttemptUnavailable);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM evidence_reconciliation_sources WHERE attempt_id = ?",
    )
    .bind(record.identity.attempt_id.as_bytes().as_slice())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| OperationError::Storage)?;
    if count != i64::from(record.source_count) {
        return Err(OperationError::AttemptUnavailable);
    }
    for (ordinal, source) in record.sources.iter().enumerate() {
        let completion = match source.completion {
            RadrootsTradeEvidenceSourceCompletionV1::Complete => "complete",
            RadrootsTradeEvidenceSourceCompletionV1::Unsupported => "unsupported",
            RadrootsTradeEvidenceSourceCompletionV1::Incomplete => "incomplete",
        };
        let source_match: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM evidence_reconciliation_sources
WHERE attempt_id = ? AND source_ordinal = ? AND source_id = ?
    AND required = ? AND accepted_event_count = ?
    AND CASE ?
        WHEN 'complete' THEN completion = 'complete'
        WHEN 'unsupported' THEN completion = 'unsupported'
        ELSE completion IN (
            'incomplete_timeout', 'incomplete_unavailable',
            'incomplete_resource_limit', 'incomplete_unknown'
        )
    END"#,
        )
        .bind(record.identity.attempt_id.as_bytes().as_slice())
        .bind(i64::try_from(ordinal).map_err(|_| OperationError::Storage)?)
        .bind(source.source_id.as_ref())
        .bind(i64::from(source.required))
        .bind(i64::from(source.admitted_event_count))
        .bind(completion)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
        if source_match != 1 {
            return Err(OperationError::AttemptUnavailable);
        }
    }
    Ok(())
}

async fn validate_advanced_checkpoints(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<(), OperationError> {
    let bad_checkpoint: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
FROM evidence_reconciliation_sources AS source
LEFT JOIN relay_checkpoints AS checkpoint
    ON checkpoint.source_id = source.source_id
    AND checkpoint.evidence_policy_sha256 = ?
    AND checkpoint.trade_id = source.trade_id
WHERE source.attempt_id = ? AND source.checkpoint_advanced = 1
    AND (checkpoint.cursor_created_at_unix_s IS NULL
        OR checkpoint.cursor_event_id IS NULL
        OR checkpoint.cursor_created_at_unix_s != source.candidate_created_at_unix_s
        OR checkpoint.cursor_event_id != source.candidate_event_id)"#,
    )
    .bind(record.identity.policy_digest.as_bytes().as_slice())
    .bind(record.identity.attempt_id.as_bytes().as_slice())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| OperationError::Storage)?;
    if bad_checkpoint == 0 {
        Ok(())
    } else {
        Err(OperationError::GenerationConflict)
    }
}

async fn insert_finalization(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<(), OperationError> {
    execute_one(
        sqlx::query(INSERT_MANIFEST_SQL)
            .bind(record.manifest_sha256.as_slice())
            .bind(record.identity.attempt_id.as_bytes().as_slice())
            .bind(record.identity.trade_id.as_bytes().as_slice())
            .bind(i64_value(record.identity.generation)?)
            .bind(record.identity.policy_digest.as_bytes().as_slice())
            .bind(record.canonical_manifest.as_ref())
            .bind(i64_value(record.observed_at_unix_s)?)
            .bind(i64::from(record.source_count))
            .bind(i64::from(record.observation_count)),
        transaction,
    )
    .await?;
    execute_one(
        sqlx::query(INSERT_PROJECTION_SQL)
            .bind(record.projection_sha256.as_slice())
            .bind(record.manifest_sha256.as_slice())
            .bind(record.shared_projection_sha256.as_slice())
            .bind(i64::from(record.issue_count)),
        transaction,
    )
    .await?;
    let supersedes_statement = record.supersession.as_ref().map(|value| value.0.as_slice());
    let supersedes_event = record.supersession.as_ref().map(|value| value.1.as_slice());
    execute_one(
        sqlx::query(INSERT_REPORT_SQL)
            .bind(record.statement_sha256.as_slice())
            .bind(record.manifest_sha256.as_slice())
            .bind(record.projection_sha256.as_slice())
            .bind(record.identity.trade_id.as_bytes().as_slice())
            .bind(record.claim_mutation_id.as_slice())
            .bind(record.issuer_public_key.as_slice())
            .bind(record.outcome)
            .bind(record.canonical_report.as_ref())
            .bind(i64_value(record.observed_at_unix_s)?)
            .bind(supersedes_statement)
            .bind(supersedes_event),
        transaction,
    )
    .await?;
    execute_one(
        sqlx::query(INSERT_SIGNED_EVENT_SQL)
            .bind(record.event_id.as_slice())
            .bind(record.statement_sha256.as_slice())
            .bind(record.event_sha256.as_slice())
            .bind(record.issuer_public_key.as_slice())
            .bind(i64_value(record.authored_at_unix_s)?)
            .bind(record.canonical_event_json.as_ref()),
        transaction,
    )
    .await?;
    if let FinalizationPublication::Required(required) = &record.publication {
        let required_count = required
            .targets
            .iter()
            .filter(|target| target.required)
            .count();
        execute_one(
            sqlx::query(INSERT_OUTBOX_SQL)
                .bind(required.outbox_id.as_slice())
                .bind(record.event_id.as_slice())
                .bind(record.event_sha256.as_slice())
                .bind(required.authority_sha256.as_slice())
                .bind(required.target_set_sha256.as_slice())
                .bind(i64::try_from(required.targets.len()).map_err(|_| OperationError::Storage)?)
                .bind(i64::try_from(required_count).map_err(|_| OperationError::Storage)?)
                .bind(i64::from(required.maximum_attempts))
                .bind(i64_value(required.initial_backoff_ms)?)
                .bind(i64_value(required.maximum_backoff_ms)?)
                .bind(i64_value(required.attempt_deadline_ms)?)
                .bind(i64_value(record.now.get())?)
                .bind(i64_value(record.now.get())?)
                .bind(i64_value(record.now.get())?),
            transaction,
        )
        .await?;
        for target in &required.targets {
            execute_one(
                sqlx::query(INSERT_TARGET_SQL)
                    .bind(required.outbox_id.as_slice())
                    .bind(i64::from(target.ordinal))
                    .bind(target.relay_id.as_ref())
                    .bind(i64::from(target.required))
                    .bind(i64_value(record.now.get())?)
                    .bind(i64_value(record.now.get())?),
                transaction,
            )
            .await?;
        }
    }
    Ok(())
}

async fn reconcile_existing(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<ExistingState, OperationError> {
    let footprint: i64 = sqlx::query_scalar(
        r#"SELECT
    (SELECT COUNT(*) FROM evidence_manifests
        WHERE manifest_sha256 = ? OR attempt_id = ?)
    + (SELECT COUNT(*) FROM trade_projections
        WHERE projection_sha256 = ? OR manifest_sha256 = ?)
    + (SELECT COUNT(*) FROM attestation_reports WHERE statement_sha256 = ?)
    + (SELECT COUNT(*) FROM signed_attestation_events
        WHERE event_id = ? OR statement_sha256 = ? OR event_sha256 = ?)
    + (SELECT COUNT(*) FROM publication_outbox WHERE event_id = ?)
    + (SELECT COUNT(*) FROM reconciliation_jobs
        WHERE job_id = ? AND state = 'completed')"#,
    )
    .bind(record.manifest_sha256.as_slice())
    .bind(record.identity.attempt_id.as_bytes().as_slice())
    .bind(record.projection_sha256.as_slice())
    .bind(record.manifest_sha256.as_slice())
    .bind(record.statement_sha256.as_slice())
    .bind(record.event_id.as_slice())
    .bind(record.statement_sha256.as_slice())
    .bind(record.event_sha256.as_slice())
    .bind(record.event_id.as_slice())
    .bind(record.identity.job_id.as_bytes().as_slice())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| OperationError::Storage)?;
    if footprint == 0 {
        return Ok(ExistingState::Absent);
    }
    if manifest_matches(transaction, record).await?
        && projection_matches(transaction, record).await?
        && report_matches(transaction, record).await?
        && event_matches(transaction, record).await?
        && publication_matches(transaction, record).await?
        && completed_job_matches(transaction, record).await?
    {
        validate_source_inventory(transaction, record).await?;
        validate_supersession(transaction, record).await?;
        Ok(ExistingState::Exact)
    } else {
        Err(OperationError::Conflict)
    }
}

async fn validate_supersession(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<(), OperationError> {
    let Some((statement_sha256, event_id)) = record.supersession else {
        return Ok(());
    };
    let count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
FROM attestation_reports AS report
JOIN signed_attestation_events AS event
    ON event.statement_sha256 = report.statement_sha256
WHERE report.statement_sha256 = ? AND event.event_id = ?"#,
    )
    .bind(statement_sha256.as_slice())
    .bind(event_id.as_slice())
    .fetch_one(&mut *transaction)
    .await
    .map_err(|_| OperationError::Storage)?;
    if count == 1 {
        Ok(())
    } else {
        Err(OperationError::Conflict)
    }
}

async fn manifest_matches(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<bool, OperationError> {
    match_count(
        sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM evidence_manifests
WHERE manifest_sha256 = ? AND attempt_id = ? AND trade_id = ?
    AND trade_generation = ? AND evidence_policy_sha256 = ?
    AND canonical_manifest = ? AND observed_at_unix_s = ?
    AND source_count = ? AND observation_count = ?"#,
        )
        .bind(record.manifest_sha256.as_slice())
        .bind(record.identity.attempt_id.as_bytes().as_slice())
        .bind(record.identity.trade_id.as_bytes().as_slice())
        .bind(i64_value(record.identity.generation)?)
        .bind(record.identity.policy_digest.as_bytes().as_slice())
        .bind(record.canonical_manifest.as_ref())
        .bind(i64_value(record.observed_at_unix_s)?)
        .bind(i64::from(record.source_count))
        .bind(i64::from(record.observation_count)),
        transaction,
    )
    .await
}

async fn projection_matches(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<bool, OperationError> {
    match_count(
        sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM trade_projections
WHERE projection_sha256 = ? AND manifest_sha256 = ?
    AND shared_projection_sha256 = ?
    AND reducer_contract = 'radroots.trade.reducer.v1'
    AND reducer_contract_version = 1 AND issue_count = ?"#,
        )
        .bind(record.projection_sha256.as_slice())
        .bind(record.manifest_sha256.as_slice())
        .bind(record.shared_projection_sha256.as_slice())
        .bind(i64::from(record.issue_count)),
        transaction,
    )
    .await
}

async fn report_matches(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<bool, OperationError> {
    let supersedes_statement = record.supersession.as_ref().map(|value| value.0.as_slice());
    let supersedes_event = record.supersession.as_ref().map(|value| value.1.as_slice());
    match_count(
        sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM attestation_reports
WHERE statement_sha256 = ? AND manifest_sha256 = ? AND projection_sha256 = ?
    AND trade_id = ? AND claim_mutation_id = ? AND issuer_public_key = ?
    AND outcome = ? AND canonical_report = ? AND observed_at_unix_s = ?
    AND supersedes_statement_sha256 IS ? AND supersedes_event_id IS ?"#,
        )
        .bind(record.statement_sha256.as_slice())
        .bind(record.manifest_sha256.as_slice())
        .bind(record.projection_sha256.as_slice())
        .bind(record.identity.trade_id.as_bytes().as_slice())
        .bind(record.claim_mutation_id.as_slice())
        .bind(record.issuer_public_key.as_slice())
        .bind(record.outcome)
        .bind(record.canonical_report.as_ref())
        .bind(i64_value(record.observed_at_unix_s)?)
        .bind(supersedes_statement)
        .bind(supersedes_event),
        transaction,
    )
    .await
}

async fn event_matches(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<bool, OperationError> {
    match_count(
        sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM signed_attestation_events
WHERE event_id = ? AND statement_sha256 = ? AND event_sha256 = ?
    AND issuer_public_key = ? AND authored_at_unix_s = ?
    AND canonical_event_json = ?"#,
        )
        .bind(record.event_id.as_slice())
        .bind(record.statement_sha256.as_slice())
        .bind(record.event_sha256.as_slice())
        .bind(record.issuer_public_key.as_slice())
        .bind(i64_value(record.authored_at_unix_s)?)
        .bind(record.canonical_event_json.as_ref()),
        transaction,
    )
    .await
}

async fn publication_matches(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<bool, OperationError> {
    match &record.publication {
        FinalizationPublication::Disabled => {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM publication_outbox WHERE event_id = ?")
                    .bind(record.event_id.as_slice())
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|_| OperationError::Storage)?;
            Ok(count == 0)
        }
        FinalizationPublication::Required(required) => {
            let required_count = required
                .targets
                .iter()
                .filter(|target| target.required)
                .count();
            let outbox = match_count(
                sqlx::query_scalar(
                    r#"SELECT COUNT(*) FROM publication_outbox
WHERE outbox_id = ? AND event_id = ? AND event_sha256 = ?
    AND publication_authority_sha256 = ? AND target_set_sha256 = ?
    AND target_count = ? AND required_target_count = ? AND max_attempts = ?
    AND initial_backoff_ms = ? AND maximum_backoff_ms = ?
    AND attempt_deadline_ms = ?"#,
                )
                .bind(required.outbox_id.as_slice())
                .bind(record.event_id.as_slice())
                .bind(record.event_sha256.as_slice())
                .bind(required.authority_sha256.as_slice())
                .bind(required.target_set_sha256.as_slice())
                .bind(i64::try_from(required.targets.len()).map_err(|_| OperationError::Storage)?)
                .bind(i64::try_from(required_count).map_err(|_| OperationError::Storage)?)
                .bind(i64::from(required.maximum_attempts))
                .bind(i64_value(required.initial_backoff_ms)?)
                .bind(i64_value(required.maximum_backoff_ms)?)
                .bind(i64_value(required.attempt_deadline_ms)?),
                transaction,
            )
            .await?;
            if !outbox {
                return Ok(false);
            }
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM publication_targets WHERE outbox_id = ?")
                    .bind(required.outbox_id.as_slice())
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|_| OperationError::Storage)?;
            if count
                != i64::try_from(required.targets.len()).map_err(|_| OperationError::Storage)?
            {
                return Ok(false);
            }
            for target in &required.targets {
                if !match_count(
                    sqlx::query_scalar(
                        r#"SELECT COUNT(*) FROM publication_targets
WHERE outbox_id = ? AND target_ordinal = ? AND relay_id = ? AND required = ?"#,
                    )
                    .bind(required.outbox_id.as_slice())
                    .bind(i64::from(target.ordinal))
                    .bind(target.relay_id.as_ref())
                    .bind(i64::from(target.required)),
                    transaction,
                )
                .await?
                {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

async fn completed_job_matches(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &FinalizationRecord,
) -> Result<bool, OperationError> {
    let job = record.lease.job();
    match_count(
        sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM reconciliation_jobs
WHERE job_id = ? AND trade_id = ? AND input_generation = ?
    AND evidence_policy_sha256 = ? AND state = 'completed'
    AND revision = ? AND attempt_count = ? AND failure_count = ?
    AND max_attempts = ? AND next_attempt_unix_ms IS NULL
    AND lease_owner IS NULL AND lease_expires_unix_ms IS NULL"#,
        )
        .bind(record.identity.job_id.as_bytes().as_slice())
        .bind(record.identity.trade_id.as_bytes().as_slice())
        .bind(i64_value(record.identity.generation)?)
        .bind(record.identity.policy_digest.as_bytes().as_slice())
        .bind(i64_value(
            job.revision()
                .checked_add(1)
                .ok_or(OperationError::Storage)?,
        )?)
        .bind(i64::from(job.attempt_count()))
        .bind(i64::from(job.failure_count()))
        .bind(i64::from(job.policy().max_attempts())),
        transaction,
    )
    .await
}

async fn execute_one<'query>(
    query: sqlx::query::Query<'query, sqlx::Sqlite, sqlx::sqlite::SqliteArguments>,
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<(), OperationError> {
    let result = query
        .execute(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(OperationError::Storage)
    }
}

async fn match_count<'query>(
    query: sqlx::query::QueryScalar<'query, sqlx::Sqlite, i64, sqlx::sqlite::SqliteArguments>,
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<bool, OperationError> {
    query
        .fetch_one(&mut *transaction)
        .await
        .map(|count| count == 1)
        .map_err(|_| OperationError::Storage)
}

const fn outcome_code(outcome: RhiReconciliationOutcome) -> &'static str {
    match outcome {
        RadrootsTradeEvidenceOutcomeV1::Valid => "valid",
        RadrootsTradeEvidenceOutcomeV1::Invalid => "invalid",
        RadrootsTradeEvidenceOutcomeV1::Indeterminate => "indeterminate",
    }
}

fn outbox_id(
    event_id: &[u8; 32],
    authority_sha256: &[u8; 32],
    target_set_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(OUTBOX_ID_DOMAIN);
    digest.update(event_id);
    digest.update(authority_sha256);
    digest.update(target_set_sha256);
    digest.finalize().into()
}

fn i64_value(value: u64) -> Result<i64, OperationError> {
    i64::try_from(value).map_err(|_| OperationError::Storage)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<OperationError>,
) -> RhiReconciliationFinalizationCommitError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return failure(RhiReconciliationFinalizationCommitErrorKind::CommitOutcomeUnknown);
    }
    failure(match error.operation_error().copied() {
        Some(OperationError::LeaseLost) => RhiReconciliationFinalizationCommitErrorKind::LeaseLost,
        Some(OperationError::GenerationConflict) => {
            RhiReconciliationFinalizationCommitErrorKind::GenerationConflict
        }
        Some(OperationError::AttemptUnavailable) => {
            RhiReconciliationFinalizationCommitErrorKind::AttemptUnavailable
        }
        Some(OperationError::QueueFull) => {
            RhiReconciliationFinalizationCommitErrorKind::PublicationQueueFull
        }
        Some(OperationError::Conflict) => RhiReconciliationFinalizationCommitErrorKind::Conflict,
        Some(OperationError::Storage) | None => {
            RhiReconciliationFinalizationCommitErrorKind::Storage
        }
    })
}

const fn failure(
    kind: RhiReconciliationFinalizationCommitErrorKind,
) -> RhiReconciliationFinalizationCommitError {
    RhiReconciliationFinalizationCommitError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbox_identity_is_exact_and_domain_separated() {
        assert_eq!(
            outbox_id(&[0x11; 32], &[0x22; 32], &[0x33; 32]),
            [
                0xf7, 0x80, 0x86, 0x80, 0xd5, 0xa6, 0x84, 0x1f, 0x2e, 0xcd, 0xaf, 0xb0, 0xc3, 0x1c,
                0x71, 0xb7, 0x4f, 0x0f, 0xf4, 0x02, 0x7f, 0x85, 0xb2, 0x49, 0x1f, 0x00, 0xc8, 0xb9,
                0xa4, 0xf5, 0x9e, 0x37,
            ]
        );
        assert_ne!(
            outbox_id(&[0x11; 32], &[0x22; 32], &[0x33; 32]),
            outbox_id(&[0x11; 32], &[0x22; 32], &[0x34; 32])
        );
    }

    #[test]
    fn errors_are_closed_source_free_and_redacted() {
        for kind in [
            RhiReconciliationFinalizationCommitErrorKind::InvalidMode,
            RhiReconciliationFinalizationCommitErrorKind::InvalidInput,
            RhiReconciliationFinalizationCommitErrorKind::LeaseLost,
            RhiReconciliationFinalizationCommitErrorKind::GenerationConflict,
            RhiReconciliationFinalizationCommitErrorKind::AttemptUnavailable,
            RhiReconciliationFinalizationCommitErrorKind::PublicationQueueFull,
            RhiReconciliationFinalizationCommitErrorKind::Conflict,
            RhiReconciliationFinalizationCommitErrorKind::Storage,
            RhiReconciliationFinalizationCommitErrorKind::CommitOutcomeUnknown,
        ] {
            let error = failure(kind);
            assert_eq!(error.kind(), kind);
            assert!(error.code().starts_with("reconciliation_"));
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("relay-primary"));
            assert!(!rendered.contains("11111111"));
            assert!(!rendered.contains("SELECT"));
        }
    }
}
