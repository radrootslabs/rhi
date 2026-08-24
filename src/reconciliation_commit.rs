//! Atomic durable reconciliation-source result commit.

use core::{cmp::Ordering, fmt};
use std::error::Error;

use radroots_event::id::TradeId;
use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    RhiReconciliationAttemptPlan, RhiReconciliationAttemptRepository, RhiReconciliationLease,
    RhiReconciliationSourceCursorEvidence, RhiReconciliationSourceReplay, RhiStateHostMode,
    RhiTradeSourceCursor,
    reconciliation_job::{LeaseValidationError, validate_exact_lease},
    reconciliation_replay::{
        RhiReconciliationReplayCommitFact, RhiReconciliationReplayCommitParts,
        committed_cursor_evidence,
    },
    source_ingest::{
        SourceOperationError, advance_dirty_generation, compare_cursor, read_checkpoint,
        read_dirty, write_checkpoint,
    },
    state_trade::{PersistenceOperationError, RhiTradeSourceObservation, persist},
};

/// Exact version of the atomic reconciliation-source commit contract.
pub const RHI_RECONCILIATION_COMMIT_CONTRACT_VERSION: u32 = 1;

const SOURCE_INVENTORY_DIGEST_DOMAIN: &[u8] = b"radroots.rhi.reconciliation_source_inventory.v1\0";

const COUNT_ATTEMPT_SQL: &str =
    "SELECT COUNT(*) AS row_count FROM evidence_reconciliations WHERE attempt_id = ?";
const MATCH_ATTEMPT_SQL: &str = r#"SELECT COUNT(*) AS row_count
FROM evidence_reconciliations
WHERE attempt_id = ? AND job_id = ? AND trade_id = ? AND input_generation = ?
    AND evidence_policy_sha256 = ? AND attempt_started_unix_ms = ?
    AND deadline_unix_ms = ? AND source_count = ?"#;
const COUNT_SOURCE_RESULTS_SQL: &str = r#"SELECT COUNT(*) AS row_count
FROM evidence_reconciliation_sources WHERE attempt_id = ?"#;
const MATCH_SOURCE_RESULT_SQL: &str = r#"SELECT COUNT(*) AS row_count
FROM evidence_reconciliation_sources
WHERE attempt_id = ? AND request_id = ? AND source_ordinal = ?
    AND source_id = ? AND trade_id = ? AND required = ? AND selector_sha256 = ?
    AND replay_id = ? AND completion = ? AND started_unix_ms = ? AND finished_unix_ms = ?
    AND accepted_event_count = ? AND accepted_event_bytes = ?
    AND accepted_inventory_sha256 = ?
    AND duplicate_observation_count = ? AND first_observed_unix_s IS ?
    AND prior_cursor_created_at_unix_s IS ? AND prior_cursor_event_id IS ?
    AND overlap_seconds = ? AND inclusive_since_unix_s = ?
    AND candidate_created_at_unix_s IS ? AND candidate_event_id IS ?
    AND checkpoint_advanced = ?"#;
const INSERT_ATTEMPT_SQL: &str = r#"INSERT INTO evidence_reconciliations (
    attempt_id, job_id, trade_id, input_generation, evidence_policy_sha256,
    attempt_started_unix_ms, deadline_unix_ms, source_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"#;
const INSERT_SOURCE_RESULT_SQL: &str = r#"INSERT INTO evidence_reconciliation_sources (
    attempt_id, request_id, source_ordinal, source_id, trade_id, required,
    selector_sha256, replay_id, completion, started_unix_ms, finished_unix_ms,
    accepted_event_count, accepted_event_bytes, accepted_inventory_sha256,
    duplicate_observation_count,
    first_observed_unix_s, prior_cursor_created_at_unix_s, prior_cursor_event_id,
    overlap_seconds, inclusive_since_unix_s, candidate_created_at_unix_s,
    candidate_event_id, checkpoint_advanced
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#;

/// Stable source-free failure classification for one atomic result commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationCommitErrorKind {
    InvalidMode,
    InvalidInput,
    LeaseLost,
    GenerationConflict,
    Conflict,
    Storage,
    CommitOutcomeUnknown,
}

impl RhiReconciliationCommitErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "reconciliation_commit_mode_invalid",
            Self::InvalidInput => "reconciliation_commit_input_invalid",
            Self::LeaseLost => "reconciliation_commit_lease_lost",
            Self::GenerationConflict => "reconciliation_commit_generation_conflict",
            Self::Conflict => "reconciliation_commit_conflict",
            Self::Storage => "reconciliation_commit_storage_failed",
            Self::CommitOutcomeUnknown => "reconciliation_commit_outcome_unknown",
        }
    }
}

/// Redacted source-free atomic reconciliation commit failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationCommitError {
    kind: RhiReconciliationCommitErrorKind,
}

impl RhiReconciliationCommitError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiReconciliationCommitErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiReconciliationCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiReconciliationCommitErrorKind::InvalidMode => {
                "RHI reconciliation commit requires writable state"
            }
            RhiReconciliationCommitErrorKind::InvalidInput => {
                "RHI reconciliation commit input is invalid"
            }
            RhiReconciliationCommitErrorKind::LeaseLost => {
                "RHI reconciliation lease is no longer authoritative"
            }
            RhiReconciliationCommitErrorKind::GenerationConflict => {
                "RHI reconciliation generation or cursor changed"
            }
            RhiReconciliationCommitErrorKind::Conflict => {
                "RHI reconciliation evidence conflicts with durable state"
            }
            RhiReconciliationCommitErrorKind::Storage => {
                "RHI reconciliation commit transaction failed"
            }
            RhiReconciliationCommitErrorKind::CommitOutcomeUnknown => {
                "RHI reconciliation commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for RhiReconciliationCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationCommitError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiReconciliationCommitError {}

/// Durable result of one exact bounded reconciliation-attempt commit.
pub struct RhiReconciliationSourceCommitOutcome {
    created: bool,
    source_result_count: u32,
    checkpoint_advance_count: u32,
    dirty_generation_advanced: bool,
    committed_cursors: Box<[RhiReconciliationSourceCursorEvidence]>,
}

impl RhiReconciliationSourceCommitOutcome {
    /// Reports whether this call created the immutable attempt inventory.
    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }

    /// Returns the exact committed source-result count.
    #[must_use]
    pub const fn source_result_count(&self) -> u32 {
        self.source_result_count
    }

    /// Returns the exact cursor checkpoint-advance count.
    #[must_use]
    pub const fn checkpoint_advance_count(&self) -> u32 {
        self.checkpoint_advance_count
    }

    /// Reports whether newly durable mutation/event evidence advanced dirty state once.
    #[must_use]
    pub const fn dirty_generation_advanced(&self) -> bool {
        self.dirty_generation_advanced
    }

    /// Returns sealed cursor evidence minted only after durable commit confirmation.
    #[must_use]
    pub fn committed_cursors(&self) -> &[RhiReconciliationSourceCursorEvidence] {
        &self.committed_cursors
    }
}

impl fmt::Debug for RhiReconciliationSourceCommitOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationSourceCommitOutcome")
            .field("created", &self.created)
            .field("source_result_count", &self.source_result_count)
            .field("checkpoint_advance_count", &self.checkpoint_advance_count)
            .field("dirty_generation_advanced", &self.dirty_generation_advanced)
            .field("committed_cursors", &self.committed_cursors.len())
            .finish()
    }
}

impl RhiReconciliationAttemptRepository<'_> {
    /// Atomically commits one exact bounded source-result inventory.
    pub async fn commit_source_replays<I>(
        &self,
        lease: RhiReconciliationLease,
        plan: RhiReconciliationAttemptPlan,
        replays: I,
    ) -> Result<RhiReconciliationSourceCommitOutcome, RhiReconciliationCommitError>
    where
        I: IntoIterator<Item = RhiReconciliationSourceReplay>,
    {
        if self.host().mode() != RhiStateHostMode::ReadWriteExisting {
            return Err(failure(RhiReconciliationCommitErrorKind::InvalidMode));
        }
        let replays = replays
            .into_iter()
            .take(plan.requests().len().saturating_add(1))
            .collect::<Vec<_>>();
        if replays.len() != plan.requests().len()
            || plan.job_id() != lease.job().id()
            || plan.input_generation() != lease.job().input_generation()
            || plan.evidence_policy_digest() != lease.job().evidence_policy_digest()
            || plan.deadline() > lease.lease_expires()
        {
            return Err(failure(RhiReconciliationCommitErrorKind::InvalidInput));
        }
        let parts = replays
            .into_iter()
            .map(RhiReconciliationSourceReplay::into_commit_parts)
            .collect::<Vec<_>>();
        if parts.iter().zip(plan.requests()).any(|(replay, request)| {
            replay.request_id != request.id()
                || replay.result.request_id() != request.id()
                || replay.source_id.as_ref() != request.source_id()
                || replay.trade_id != request.trade_id()
                || replay.required != request.required()
                || replay.trade_id != lease.job().trade_id()
                || replay.policy_digest != *plan.evidence_policy_digest().as_bytes()
                || replay.selector_digest != *request.selector_digest().as_bytes()
                || replay.result.finished_at() >= lease.lease_expires()
                || replay.facts.len() != replay.result.accepted_event_count() as usize
                || replay
                    .eligible_cursor
                    .is_some_and(|_| replay.result.finished_at().get() / 1_000 == 0)
        }) {
            return Err(failure(RhiReconciliationCommitErrorKind::InvalidInput));
        }

        let raw = self
            .host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { commit(transaction, lease, plan, parts).await })
            })
            .await
            .map_err(map_transaction_error)?;
        let committed_cursors = raw
            .cursor_scopes
            .into_vec()
            .into_iter()
            .map(|scope| {
                committed_cursor_evidence(
                    scope.source_id,
                    scope.trade_id,
                    scope.policy_digest,
                    scope.selector_digest,
                    scope.cursor,
                )
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(RhiReconciliationSourceCommitOutcome {
            created: raw.created,
            source_result_count: raw.source_result_count,
            checkpoint_advance_count: raw.checkpoint_advance_count,
            dirty_generation_advanced: raw.dirty_generation_advanced,
            committed_cursors,
        })
    }
}

struct RawCommitOutcome {
    created: bool,
    source_result_count: u32,
    checkpoint_advance_count: u32,
    dirty_generation_advanced: bool,
    cursor_scopes: Box<[CommittedCursorScope]>,
}

struct CommittedCursorScope {
    source_id: Box<str>,
    trade_id: TradeId,
    policy_digest: [u8; 32],
    selector_digest: [u8; 32],
    cursor: RhiTradeSourceCursor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CommitOperationError {
    LeaseLost,
    GenerationConflict,
    Conflict,
    Storage,
}

async fn commit(
    transaction: &mut ServiceSqliteTransaction<'_>,
    lease: RhiReconciliationLease,
    plan: RhiReconciliationAttemptPlan,
    parts: Vec<RhiReconciliationReplayCommitParts>,
) -> Result<RawCommitOutcome, CommitOperationError> {
    if reconcile_existing(transaction, &plan, &parts).await? {
        return raw_outcome(false, false, &parts);
    }
    validate_exact_lease(transaction, lease)
        .await
        .map_err(|error| match error {
            LeaseValidationError::LeaseLost => CommitOperationError::LeaseLost,
            LeaseValidationError::Storage => CommitOperationError::Storage,
        })?;
    let policy = plan.evidence_policy_digest();
    let dirty = read_dirty(transaction, lease.job().trade_id())
        .await
        .map_err(map_source_error)?
        .filter(|state| state.generation.get() == plan.input_generation() && state.policy == policy)
        .ok_or(CommitOperationError::GenerationConflict)?;
    let mut checkpoints = Vec::with_capacity(parts.len());
    for part in &parts {
        let checkpoint =
            read_checkpoint(transaction, part.source_id.as_ref(), policy, part.trade_id)
                .await
                .map_err(map_source_error)?;
        if checkpoint.map(|value| value.cursor) != part.prior_cursor {
            return Err(CommitOperationError::GenerationConflict);
        }
        checkpoints.push(checkpoint);
    }

    insert_attempt(transaction, &plan).await?;
    let mut new_relevant_evidence = false;
    for part in &parts {
        for fact in &part.facts {
            let observation = RhiTradeSourceObservation::from_persistence_parts(
                part.source_id.clone(),
                policy,
                &fact.record,
                fact.observed_at,
            );
            let outcome = persist(transaction, &fact.record, &observation)
                .await
                .map_err(map_persistence_error)?;
            new_relevant_evidence |= outcome.mutation_inserted() || outcome.signed_event_inserted();
        }
    }

    if new_relevant_evidence {
        let updated_at = parts
            .iter()
            .map(|part| part.result.finished_at().get() / 1_000)
            .max()
            .ok_or(CommitOperationError::Storage)?;
        advance_dirty_generation(
            transaction,
            lease.job().trade_id(),
            policy,
            updated_at,
            Some(dirty),
        )
        .await
        .map_err(map_source_error)?;
    }

    for ((ordinal, part), checkpoint) in parts.iter().enumerate().zip(checkpoints) {
        if let Some(candidate) = part.eligible_cursor {
            write_checkpoint(
                transaction,
                part.source_id.as_ref(),
                policy,
                part.trade_id,
                checkpoint,
                candidate,
                part.result.finished_at().get() / 1_000,
            )
            .await
            .map_err(map_source_error)?;
        }
        insert_source_result(transaction, plan.id().as_bytes(), ordinal, part).await?;
    }
    raw_outcome(true, new_relevant_evidence, &parts)
}

fn raw_outcome(
    created: bool,
    dirty_generation_advanced: bool,
    parts: &[RhiReconciliationReplayCommitParts],
) -> Result<RawCommitOutcome, CommitOperationError> {
    let cursor_scopes = parts
        .iter()
        .filter_map(|part| {
            part.eligible_cursor.map(|cursor| CommittedCursorScope {
                source_id: part.source_id.clone(),
                trade_id: part.trade_id,
                policy_digest: part.policy_digest,
                selector_digest: part.selector_digest,
                cursor,
            })
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    Ok(RawCommitOutcome {
        created,
        source_result_count: u32::try_from(parts.len())
            .map_err(|_| CommitOperationError::Storage)?,
        checkpoint_advance_count: u32::try_from(cursor_scopes.len())
            .map_err(|_| CommitOperationError::Storage)?,
        dirty_generation_advanced,
        cursor_scopes,
    })
}

async fn reconcile_existing(
    transaction: &mut ServiceSqliteTransaction<'_>,
    plan: &RhiReconciliationAttemptPlan,
    parts: &[RhiReconciliationReplayCommitParts],
) -> Result<bool, CommitOperationError> {
    let count = count_query(transaction, COUNT_ATTEMPT_SQL, plan.id().as_bytes()).await?;
    if count == 0 {
        return Ok(false);
    }
    if count != 1 || match_attempt(transaction, plan).await? != 1 {
        return Err(CommitOperationError::Conflict);
    }
    let source_count =
        count_query(transaction, COUNT_SOURCE_RESULTS_SQL, plan.id().as_bytes()).await?;
    if source_count != parts.len() as u64 {
        return Err(CommitOperationError::Conflict);
    }
    for (ordinal, part) in parts.iter().enumerate() {
        if match_source_result(transaction, plan.id().as_bytes(), ordinal, part).await? != 1 {
            return Err(CommitOperationError::Conflict);
        }
        if let Some(candidate) = part.eligible_cursor {
            let checkpoint = read_checkpoint(
                transaction,
                part.source_id.as_ref(),
                plan.evidence_policy_digest(),
                part.trade_id,
            )
            .await
            .map_err(map_source_error)?
            .ok_or(CommitOperationError::Conflict)?;
            if compare_cursor(checkpoint.cursor, candidate) == Ordering::Less {
                return Err(CommitOperationError::Conflict);
            }
        }
    }
    Ok(true)
}

async fn count_query(
    transaction: &mut ServiceSqliteTransaction<'_>,
    sql: &'static str,
    id: &[u8; 32],
) -> Result<u64, CommitOperationError> {
    sqlx::query(sql)
        .bind(id.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| CommitOperationError::Storage)?
        .try_get::<i64, _>("row_count")
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(CommitOperationError::Storage)
}

async fn match_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    plan: &RhiReconciliationAttemptPlan,
) -> Result<u64, CommitOperationError> {
    let trade = plan
        .requests()
        .first()
        .ok_or(CommitOperationError::Storage)?
        .trade_id();
    count_row(
        sqlx::query(MATCH_ATTEMPT_SQL)
            .bind(plan.id().as_bytes().as_slice())
            .bind(plan.job_id().as_bytes().as_slice())
            .bind(trade.as_bytes().as_slice())
            .bind(i64_value(plan.input_generation())?)
            .bind(plan.evidence_policy_digest().as_bytes().as_slice())
            .bind(i64_value(plan.attempt_started_at().get())?)
            .bind(i64_value(plan.deadline().get())?)
            .bind(i64::try_from(plan.requests().len()).map_err(|_| CommitOperationError::Storage)?),
        transaction,
    )
    .await
}

async fn match_source_result(
    transaction: &mut ServiceSqliteTransaction<'_>,
    attempt_id: &[u8; 32],
    ordinal: usize,
    part: &RhiReconciliationReplayCommitParts,
) -> Result<u64, CommitOperationError> {
    let prior_created = part
        .prior_cursor
        .map(|cursor| i64_value(cursor.created_at_unix_seconds()))
        .transpose()?;
    let prior_event = part.prior_cursor.map(|cursor| cursor.event_id());
    let candidate_created = part
        .cursor_candidate
        .map(|cursor| i64_value(cursor.created_at_unix_seconds()))
        .transpose()?;
    let candidate_event = part.cursor_candidate.map(|cursor| cursor.event_id());
    let inventory_digest = accepted_inventory_digest(part)?;
    count_row(
        sqlx::query(MATCH_SOURCE_RESULT_SQL)
            .bind(attempt_id.as_slice())
            .bind(part.request_id.as_bytes().as_slice())
            .bind(i64::try_from(ordinal).map_err(|_| CommitOperationError::Storage)?)
            .bind(part.source_id.as_ref())
            .bind(part.trade_id.as_bytes().as_slice())
            .bind(i64::from(part.required))
            .bind(part.selector_digest.as_slice())
            .bind(part.replay_id.as_bytes().as_slice())
            .bind(part.result.outcome().code())
            .bind(i64_value(part.result.started_at().get())?)
            .bind(i64_value(part.result.finished_at().get())?)
            .bind(i64::from(part.result.accepted_event_count()))
            .bind(i64_value(part.result.accepted_event_bytes())?)
            .bind(inventory_digest.as_slice())
            .bind(i64::from(part.duplicate_observations))
            .bind(
                part.first_observed_at
                    .map(|value| i64_value(value.get()))
                    .transpose()?,
            )
            .bind(prior_created)
            .bind(prior_event.as_ref().map(<[u8; 32]>::as_slice))
            .bind(i64_value(part.overlap_seconds)?)
            .bind(i64_value(part.since_unix_seconds)?)
            .bind(candidate_created)
            .bind(candidate_event.as_ref().map(<[u8; 32]>::as_slice))
            .bind(i64::from(part.eligible_cursor.is_some())),
        transaction,
    )
    .await
}

async fn insert_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    plan: &RhiReconciliationAttemptPlan,
) -> Result<(), CommitOperationError> {
    let trade = plan
        .requests()
        .first()
        .ok_or(CommitOperationError::Storage)?
        .trade_id();
    let result = sqlx::query(INSERT_ATTEMPT_SQL)
        .bind(plan.id().as_bytes().as_slice())
        .bind(plan.job_id().as_bytes().as_slice())
        .bind(trade.as_bytes().as_slice())
        .bind(i64_value(plan.input_generation())?)
        .bind(plan.evidence_policy_digest().as_bytes().as_slice())
        .bind(i64_value(plan.attempt_started_at().get())?)
        .bind(i64_value(plan.deadline().get())?)
        .bind(i64::try_from(plan.requests().len()).map_err(|_| CommitOperationError::Storage)?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| CommitOperationError::Storage)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(CommitOperationError::Storage)
    }
}

async fn insert_source_result(
    transaction: &mut ServiceSqliteTransaction<'_>,
    attempt_id: &[u8; 32],
    ordinal: usize,
    part: &RhiReconciliationReplayCommitParts,
) -> Result<(), CommitOperationError> {
    let prior_created = part
        .prior_cursor
        .map(|cursor| i64_value(cursor.created_at_unix_seconds()))
        .transpose()?;
    let prior_event = part.prior_cursor.map(|cursor| cursor.event_id());
    let candidate_created = part
        .cursor_candidate
        .map(|cursor| i64_value(cursor.created_at_unix_seconds()))
        .transpose()?;
    let candidate_event = part.cursor_candidate.map(|cursor| cursor.event_id());
    let inventory_digest = accepted_inventory_digest(part)?;
    let result = sqlx::query(INSERT_SOURCE_RESULT_SQL)
        .bind(attempt_id.as_slice())
        .bind(part.request_id.as_bytes().as_slice())
        .bind(i64::try_from(ordinal).map_err(|_| CommitOperationError::Storage)?)
        .bind(part.source_id.as_ref())
        .bind(part.trade_id.as_bytes().as_slice())
        .bind(i64::from(part.required))
        .bind(part.selector_digest.as_slice())
        .bind(part.replay_id.as_bytes().as_slice())
        .bind(part.result.outcome().code())
        .bind(i64_value(part.result.started_at().get())?)
        .bind(i64_value(part.result.finished_at().get())?)
        .bind(i64::from(part.result.accepted_event_count()))
        .bind(i64_value(part.result.accepted_event_bytes())?)
        .bind(inventory_digest.as_slice())
        .bind(i64::from(part.duplicate_observations))
        .bind(
            part.first_observed_at
                .map(|value| i64_value(value.get()))
                .transpose()?,
        )
        .bind(prior_created)
        .bind(prior_event.as_ref().map(<[u8; 32]>::as_slice))
        .bind(i64_value(part.overlap_seconds)?)
        .bind(i64_value(part.since_unix_seconds)?)
        .bind(candidate_created)
        .bind(candidate_event.as_ref().map(<[u8; 32]>::as_slice))
        .bind(i64::from(part.eligible_cursor.is_some()))
        .execute(&mut *transaction)
        .await
        .map_err(|_| CommitOperationError::Storage)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(CommitOperationError::Storage)
    }
}

fn accepted_inventory_digest(
    part: &RhiReconciliationReplayCommitParts,
) -> Result<[u8; 32], CommitOperationError> {
    accepted_inventory_digest_for_facts(&part.facts)
}

fn accepted_inventory_digest_for_facts(
    facts: &[RhiReconciliationReplayCommitFact],
) -> Result<[u8; 32], CommitOperationError> {
    let mut digest = Sha256::new();
    digest.update(SOURCE_INVENTORY_DIGEST_DOMAIN);
    digest.update(
        u32::try_from(facts.len())
            .map_err(|_| CommitOperationError::Storage)?
            .to_be_bytes(),
    );
    for fact in facts {
        let record = &fact.record;
        digest.update(record.mutation_id);
        digest.update(record.trade_id);
        update_framed(&mut digest, record.contract_id.as_bytes())?;
        digest.update(record.schema_version.to_be_bytes());
        digest.update(record.event_id);
        digest.update(record.event_signature);
        digest.update(record.author_pubkey);
        digest.update(record.event_kind.to_be_bytes());
        digest.update(record.authored_at_unix_s.to_be_bytes());
        update_framed(&mut digest, &record.canonical_content)?;
        update_framed(&mut digest, &record.canonical_event_json)?;
        digest.update(fact.observed_at.get().to_be_bytes());
    }
    Ok(digest.finalize().into())
}

fn update_framed(digest: &mut Sha256, bytes: &[u8]) -> Result<(), CommitOperationError> {
    digest.update(
        u64::try_from(bytes.len())
            .map_err(|_| CommitOperationError::Storage)?
            .to_be_bytes(),
    );
    digest.update(bytes);
    Ok(())
}

async fn count_row<'query>(
    query: sqlx::query::Query<'query, sqlx::Sqlite, sqlx::sqlite::SqliteArguments>,
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<u64, CommitOperationError> {
    query
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| CommitOperationError::Storage)?
        .try_get::<i64, _>("row_count")
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(CommitOperationError::Storage)
}

fn i64_value(value: u64) -> Result<i64, CommitOperationError> {
    i64::try_from(value).map_err(|_| CommitOperationError::Storage)
}

fn map_persistence_error(error: PersistenceOperationError) -> CommitOperationError {
    match error {
        PersistenceOperationError::MutationConflict
        | PersistenceOperationError::SignedEventConflict => CommitOperationError::Conflict,
        PersistenceOperationError::Storage => CommitOperationError::Storage,
    }
}

fn map_source_error(error: SourceOperationError) -> CommitOperationError {
    match error {
        SourceOperationError::GenerationConflict => CommitOperationError::GenerationConflict,
        SourceOperationError::Persistence(error) => map_persistence_error(error),
        SourceOperationError::Storage => CommitOperationError::Storage,
    }
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<CommitOperationError>,
) -> RhiReconciliationCommitError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return failure(RhiReconciliationCommitErrorKind::CommitOutcomeUnknown);
    }
    failure(match error.operation_error().copied() {
        Some(CommitOperationError::LeaseLost) => RhiReconciliationCommitErrorKind::LeaseLost,
        Some(CommitOperationError::GenerationConflict) => {
            RhiReconciliationCommitErrorKind::GenerationConflict
        }
        Some(CommitOperationError::Conflict) => RhiReconciliationCommitErrorKind::Conflict,
        Some(CommitOperationError::Storage) | None => RhiReconciliationCommitErrorKind::Storage,
    })
}

const fn failure(kind: RhiReconciliationCommitErrorKind) -> RhiReconciliationCommitError {
    RhiReconciliationCommitError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(observed_at: u64, content: &[u8]) -> RhiReconciliationReplayCommitFact {
        RhiReconciliationReplayCommitFact {
            record: crate::state_trade::PersistenceRecord {
                mutation_id: [0x11; 32],
                trade_id: [0x22; 16],
                contract_id: "radroots.trade.proposal.v1",
                schema_version: 1,
                event_id: [0x33; 32],
                event_signature: [0x44; 64],
                author_pubkey: [0x55; 32],
                event_kind: 3_470,
                authored_at_unix_s: 1_784_347_200,
                canonical_content: content.into(),
                canonical_event_json: br#"{"id":"example"}"#.as_slice().into(),
            },
            observed_at: crate::RhiTradeMutationObservedAtUnixSeconds::new(observed_at)
                .expect("observation"),
        }
    }

    #[test]
    fn source_inventory_digest_is_exact_framed_and_provenance_sensitive() {
        assert_eq!(
            accepted_inventory_digest_for_facts(&[]).expect("empty digest"),
            [
                0xc6, 0x77, 0x8e, 0xb5, 0x38, 0xe6, 0x1a, 0x6d, 0xa4, 0xe5, 0xba, 0xe1, 0x9c, 0xb1,
                0xb3, 0xf9, 0xcd, 0x14, 0x39, 0x8b, 0x7d, 0xc2, 0xfb, 0x26, 0x3c, 0xa0, 0x86, 0xf2,
                0xf5, 0xf3, 0x0c, 0xdb,
            ]
        );
        let first = accepted_inventory_digest_for_facts(&[fact(1_784_347_201, b"alpha")])
            .expect("first digest");
        let changed_provenance =
            accepted_inventory_digest_for_facts(&[fact(1_784_347_202, b"alpha")])
                .expect("provenance digest");
        let changed_content = accepted_inventory_digest_for_facts(&[fact(1_784_347_201, b"bravo")])
            .expect("content digest");
        assert_ne!(first, changed_provenance);
        assert_ne!(first, changed_content);
    }

    #[test]
    fn errors_are_closed_redacted_and_source_free() {
        for kind in [
            RhiReconciliationCommitErrorKind::InvalidMode,
            RhiReconciliationCommitErrorKind::InvalidInput,
            RhiReconciliationCommitErrorKind::LeaseLost,
            RhiReconciliationCommitErrorKind::GenerationConflict,
            RhiReconciliationCommitErrorKind::Conflict,
            RhiReconciliationCommitErrorKind::Storage,
            RhiReconciliationCommitErrorKind::CommitOutcomeUnknown,
        ] {
            let error = failure(kind);
            assert_eq!(error.kind(), kind);
            assert!(Error::source(&error).is_none());
            assert!(!format!("{error} {error:?}").contains("trade-primary"));
        }
    }
}
