//! Generation-fenced reconciliation-finalization preflight.

use core::fmt;
use std::error::Error;

use radroots_event::id::TradeId;
use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};

use crate::{
    RhiEvidencePolicyDigest, RhiReconciliationAttemptId, RhiReconciliationAttemptRepository,
    RhiReconciliationEvaluation, RhiReconciliationJobId, RhiReconciliationJobState,
    RhiReconciliationLease, RhiReconciliationUnixMilliseconds, RhiStateHostMode,
    reconciliation_attempt::attempt_id,
    reconciliation_job::{LeaseValidationError, validate_exact_lease},
    source_ingest::{SourceOperationError, read_dirty},
};

/// Exact version of the reconciliation-finalization fence contract.
pub const RHI_RECONCILIATION_FINALIZATION_CONTRACT_VERSION: u32 = 1;

const MATCH_COMMITTED_ATTEMPT_SQL: &str = r#"SELECT COUNT(*)
FROM evidence_reconciliations
WHERE attempt_id = ? AND job_id = ? AND trade_id = ? AND input_generation = ?
    AND evidence_policy_sha256 = ?"#;

/// Stable source-free failure class for finalization preflight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationFinalizationErrorKind {
    InvalidMode,
    InvalidInput,
    LeaseLost,
    GenerationConflict,
    AttemptUnavailable,
    ProjectionUnavailable,
    Storage,
    CommitOutcomeUnknown,
}

impl RhiReconciliationFinalizationErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "reconciliation_finalization_mode_invalid",
            Self::InvalidInput => "reconciliation_finalization_input_invalid",
            Self::LeaseLost => "reconciliation_finalization_lease_lost",
            Self::GenerationConflict => "reconciliation_finalization_generation_conflict",
            Self::AttemptUnavailable => "reconciliation_finalization_attempt_unavailable",
            Self::ProjectionUnavailable => "reconciliation_finalization_projection_unavailable",
            Self::Storage => "reconciliation_finalization_storage_failed",
            Self::CommitOutcomeUnknown => "reconciliation_finalization_outcome_unknown",
        }
    }
}

/// Redacted source-free finalization-preflight failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationFinalizationError {
    kind: RhiReconciliationFinalizationErrorKind,
}

impl RhiReconciliationFinalizationError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiReconciliationFinalizationErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiReconciliationFinalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiReconciliationFinalizationErrorKind::InvalidMode => {
                "RHI reconciliation finalization requires writable state"
            }
            RhiReconciliationFinalizationErrorKind::InvalidInput => {
                "RHI reconciliation finalization input is invalid"
            }
            RhiReconciliationFinalizationErrorKind::LeaseLost => {
                "RHI reconciliation finalization lease is no longer authoritative"
            }
            RhiReconciliationFinalizationErrorKind::GenerationConflict => {
                "RHI reconciliation finalization generation changed"
            }
            RhiReconciliationFinalizationErrorKind::AttemptUnavailable => {
                "RHI reconciliation finalization attempt is unavailable"
            }
            RhiReconciliationFinalizationErrorKind::ProjectionUnavailable => {
                "RHI reconciliation finalization projection is unavailable"
            }
            RhiReconciliationFinalizationErrorKind::Storage => {
                "RHI reconciliation finalization preflight failed"
            }
            RhiReconciliationFinalizationErrorKind::CommitOutcomeUnknown => {
                "RHI reconciliation finalization preflight outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for RhiReconciliationFinalizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationFinalizationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiReconciliationFinalizationError {}

/// Sealed preflight capability for one exact evaluated reconciliation attempt.
///
/// This value proves only that its lease, generation, policy, and committed
/// attempt matched during one bounded read-only preflight transaction. The
/// eventual Step199 writer must rerun the same validator inside its atomic
/// transaction before any mutation.
///
/// ```compile_fail
/// use rhi::RhiReconciliationFinalizationFence;
///
/// let _forged = RhiReconciliationFinalizationFence { evaluation: todo!() };
/// ```
pub struct RhiReconciliationFinalizationFence {
    lease: RhiReconciliationLease,
    identity: FinalizationIdentity,
    evaluation: RhiReconciliationEvaluation,
}

impl RhiReconciliationFinalizationFence {
    /// Returns the exact finalization-fence contract version.
    #[must_use]
    pub const fn contract_version(&self) -> u32 {
        RHI_RECONCILIATION_FINALIZATION_CONTRACT_VERSION
    }

    /// Returns the sealed Step194 evaluation retained by this preflight.
    #[must_use]
    pub const fn evaluation(&self) -> &RhiReconciliationEvaluation {
        &self.evaluation
    }
}

impl fmt::Debug for RhiReconciliationFinalizationFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationFinalizationFence")
            .field("coverage", &self.evaluation.coverage())
            .field("outcome", &self.evaluation.outcome())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FinalizationIdentity {
    pub(crate) attempt_id: RhiReconciliationAttemptId,
    pub(crate) job_id: RhiReconciliationJobId,
    pub(crate) trade_id: TradeId,
    pub(crate) generation: u64,
    pub(crate) policy_digest: RhiEvidencePolicyDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalizationOperationError {
    LeaseLost,
    GenerationConflict,
    AttemptUnavailable,
    Storage,
}

impl RhiReconciliationAttemptRepository<'_> {
    /// Performs one bounded read-only preflight for later atomic finalization.
    ///
    /// The returned capability is not commit authority. Durable finalization
    /// must rerun the same exact checks inside its Step199 write transaction.
    pub async fn prepare_finalization(
        &self,
        lease: RhiReconciliationLease,
        evaluation: RhiReconciliationEvaluation,
        now: RhiReconciliationUnixMilliseconds,
    ) -> Result<RhiReconciliationFinalizationFence, RhiReconciliationFinalizationError> {
        if self.host().mode() != RhiStateHostMode::ReadWriteExisting {
            return Err(failure(RhiReconciliationFinalizationErrorKind::InvalidMode));
        }
        let identity = finalization_identity(lease, &evaluation, now)?;
        let fence = RhiReconciliationFinalizationFence {
            lease,
            identity,
            evaluation,
        };
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    validate_finalization_fence(transaction, &fence, now).await?;
                    Ok(fence)
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

impl RhiReconciliationFinalizationFence {
    pub(crate) const fn validation_parts(&self) -> (RhiReconciliationLease, FinalizationIdentity) {
        (self.lease, self.identity)
    }
}

pub(crate) async fn validate_finalization_fence(
    transaction: &mut ServiceSqliteTransaction<'_>,
    fence: &RhiReconciliationFinalizationFence,
    now: RhiReconciliationUnixMilliseconds,
) -> Result<(), FinalizationOperationError> {
    validate_finalization_identity(transaction, fence.lease, fence.identity, now).await
}

fn finalization_identity(
    lease: RhiReconciliationLease,
    evaluation: &RhiReconciliationEvaluation,
    now: RhiReconciliationUnixMilliseconds,
) -> Result<FinalizationIdentity, RhiReconciliationFinalizationError> {
    let job = lease.job();
    let manifest = evaluation.projection().manifest();
    if job.state() != RhiReconciliationJobState::Leased
        || job.attempt_count() == 0
        || manifest.job_id() != job.id()
        || manifest.attempt_id() != attempt_id(job.id(), job.attempt_count())
        || manifest.trade_id() != &job.trade_id()
        || manifest.trade_generation() != job.input_generation()
        || manifest.inner().evidence_policy_digest().as_bytes()
            != job.evidence_policy_digest().as_bytes()
    {
        return Err(failure(
            RhiReconciliationFinalizationErrorKind::InvalidInput,
        ));
    }
    if now >= lease.lease_expires() {
        return Err(failure(RhiReconciliationFinalizationErrorKind::LeaseLost));
    }
    if evaluation.projection().digest().is_none() {
        return Err(failure(
            RhiReconciliationFinalizationErrorKind::ProjectionUnavailable,
        ));
    }
    Ok(FinalizationIdentity {
        attempt_id: manifest.attempt_id(),
        job_id: manifest.job_id(),
        trade_id: job.trade_id(),
        generation: job.input_generation(),
        policy_digest: job.evidence_policy_digest(),
    })
}

pub(crate) async fn validate_finalization_identity(
    transaction: &mut ServiceSqliteTransaction<'_>,
    lease: RhiReconciliationLease,
    identity: FinalizationIdentity,
    now: RhiReconciliationUnixMilliseconds,
) -> Result<(), FinalizationOperationError> {
    if now >= lease.lease_expires() {
        return Err(FinalizationOperationError::LeaseLost);
    }
    validate_exact_lease(transaction, lease)
        .await
        .map_err(|error| match error {
            LeaseValidationError::LeaseLost => FinalizationOperationError::LeaseLost,
            LeaseValidationError::Storage => FinalizationOperationError::Storage,
        })?;
    read_dirty(transaction, identity.trade_id)
        .await
        .map_err(|error| match error {
            SourceOperationError::GenerationConflict => {
                FinalizationOperationError::GenerationConflict
            }
            SourceOperationError::Persistence(_) | SourceOperationError::Storage => {
                FinalizationOperationError::Storage
            }
        })?
        .filter(|dirty| {
            dirty.generation.get() == identity.generation && dirty.policy == identity.policy_digest
        })
        .ok_or(FinalizationOperationError::GenerationConflict)?;
    let generation =
        i64::try_from(identity.generation).map_err(|_| FinalizationOperationError::Storage)?;
    let count = sqlx::query_scalar::<_, i64>(MATCH_COMMITTED_ATTEMPT_SQL)
        .bind(identity.attempt_id.as_bytes().as_slice())
        .bind(identity.job_id.as_bytes().as_slice())
        .bind(identity.trade_id.as_bytes().as_slice())
        .bind(generation)
        .bind(identity.policy_digest.as_bytes().as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| FinalizationOperationError::Storage)?;
    if count == 1 {
        Ok(())
    } else {
        Err(FinalizationOperationError::AttemptUnavailable)
    }
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<FinalizationOperationError>,
) -> RhiReconciliationFinalizationError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return failure(RhiReconciliationFinalizationErrorKind::CommitOutcomeUnknown);
    }
    failure(match error.operation_error().copied() {
        Some(FinalizationOperationError::LeaseLost) => {
            RhiReconciliationFinalizationErrorKind::LeaseLost
        }
        Some(FinalizationOperationError::GenerationConflict) => {
            RhiReconciliationFinalizationErrorKind::GenerationConflict
        }
        Some(FinalizationOperationError::AttemptUnavailable) => {
            RhiReconciliationFinalizationErrorKind::AttemptUnavailable
        }
        Some(FinalizationOperationError::Storage) | None => {
            RhiReconciliationFinalizationErrorKind::Storage
        }
    })
}

const fn failure(
    kind: RhiReconciliationFinalizationErrorKind,
) -> RhiReconciliationFinalizationError {
    RhiReconciliationFinalizationError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_inventory_is_exact_source_free_and_redacted() {
        let cases = [
            (
                RhiReconciliationFinalizationErrorKind::InvalidMode,
                "reconciliation_finalization_mode_invalid",
            ),
            (
                RhiReconciliationFinalizationErrorKind::InvalidInput,
                "reconciliation_finalization_input_invalid",
            ),
            (
                RhiReconciliationFinalizationErrorKind::LeaseLost,
                "reconciliation_finalization_lease_lost",
            ),
            (
                RhiReconciliationFinalizationErrorKind::GenerationConflict,
                "reconciliation_finalization_generation_conflict",
            ),
            (
                RhiReconciliationFinalizationErrorKind::AttemptUnavailable,
                "reconciliation_finalization_attempt_unavailable",
            ),
            (
                RhiReconciliationFinalizationErrorKind::ProjectionUnavailable,
                "reconciliation_finalization_projection_unavailable",
            ),
            (
                RhiReconciliationFinalizationErrorKind::Storage,
                "reconciliation_finalization_storage_failed",
            ),
            (
                RhiReconciliationFinalizationErrorKind::CommitOutcomeUnknown,
                "reconciliation_finalization_outcome_unknown",
            ),
        ];
        for (kind, code) in cases {
            let error = failure(kind);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.code(), code);
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("11111111"));
            assert!(!rendered.contains("trade-primary"));
        }
    }
}
