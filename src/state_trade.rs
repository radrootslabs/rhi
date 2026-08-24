//! Atomic immutable persistence for admitted trade-event evidence.

use core::fmt;
use std::{error::Error, sync::Arc};

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use serde_json::Value;
use sqlx::Row;

use crate::{
    RhiAdmittedTradeMutationEvent, RhiConfigDocumentV1, RhiEvidencePolicyDigest, RhiStateHostMode,
    RhiStateRepositories, RhiTradeMutationObservedAtUnixSeconds, state_metadata,
};

/// Exact version of the immutable trade-evidence persistence contract.
pub const RHI_TRADE_EVIDENCE_PERSISTENCE_CONTRACT_VERSION: u32 = 1;

const SOURCE_SELECTOR: &str = "trade_mutation_lineage_v1";
const MAX_SOURCE_ID_BYTES: usize = 64;
const MAX_CONTRACT_ID_BYTES: usize = 128;
const MAX_MUTATION_CONTENT_BYTES: usize = 131_072;
const MAX_CANONICAL_EVENT_BYTES: usize = 524_288;

const INSERT_MUTATION_SQL: &str = r#"INSERT INTO trade_mutations (
    mutation_id, trade_id, contract_id, schema_version, event_kind,
    author_pubkey, canonical_content
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (mutation_id) DO NOTHING"#;
const READ_MUTATION_SQL: &str = r#"SELECT
    length(trade_id) AS trade_id_bytes,
    substr(trade_id, 1, 17) AS trade_id,
    length(CAST(contract_id AS BLOB)) AS contract_id_bytes,
    substr(contract_id, 1, 129) AS contract_id,
    schema_version,
    event_kind,
    length(author_pubkey) AS author_pubkey_bytes,
    substr(author_pubkey, 1, 33) AS author_pubkey,
    length(canonical_content) AS canonical_content_bytes,
    substr(canonical_content, 1, 131073) AS canonical_content
FROM trade_mutations
WHERE mutation_id = ?
LIMIT 1"#;
const INSERT_EVENT_SQL: &str = r#"INSERT INTO nostr_events (
    event_id, event_signature, mutation_id, author_pubkey, event_kind,
    authored_at_unix_s, canonical_event_json
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (event_id, event_signature) DO NOTHING"#;
const READ_EVENT_SQL: &str = r#"SELECT
    length(mutation_id) AS mutation_id_bytes,
    substr(mutation_id, 1, 33) AS mutation_id,
    length(author_pubkey) AS author_pubkey_bytes,
    substr(author_pubkey, 1, 33) AS author_pubkey,
    event_kind,
    authored_at_unix_s,
    length(canonical_event_json) AS canonical_event_json_bytes,
    substr(canonical_event_json, 1, 524289) AS canonical_event_json
FROM nostr_events
WHERE event_id = ? AND event_signature = ?
LIMIT 1"#;
const INSERT_OBSERVATION_SQL: &str = r#"INSERT INTO relay_observations (
    source_id, selector_id, evidence_policy_sha256, event_id,
    event_signature, observed_at_unix_s
) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (
    source_id, selector_id, evidence_policy_sha256, event_id,
    event_signature, observed_at_unix_s
) DO NOTHING"#;

/// One accepted configured source observation bound to an admitted signed event.
///
/// Construction is sealed to a validated RHI configuration and an admitted
/// event, so arbitrary source labels, selectors, policy digests, identifiers,
/// signatures, and observation times cannot be supplied independently.
pub struct RhiTradeSourceObservation {
    source_id: Box<str>,
    policy: RhiEvidencePolicyDigest,
    event_id: [u8; 32],
    event_signature: [u8; 64],
    observed_at: RhiTradeMutationObservedAtUnixSeconds,
}

impl RhiTradeSourceObservation {
    /// Binds one admitted event to an exact configured `nostr_relay` source.
    pub fn from_config(
        configuration: &RhiConfigDocumentV1,
        source_id: &str,
        event: &RhiAdmittedTradeMutationEvent,
    ) -> Result<Self, RhiTradeEvidencePersistenceError> {
        let source = configured_source(configuration.normalized(), source_id)
            .ok_or_else(|| failure(RhiTradeEvidencePersistenceErrorKind::InvalidObservation))?;
        if source.pointer("/kind").and_then(Value::as_str) != Some("nostr_relay")
            || source.pointer("/selector").and_then(Value::as_str) != Some(SOURCE_SELECTOR)
        {
            return Err(failure(
                RhiTradeEvidencePersistenceErrorKind::InvalidObservation,
            ));
        }
        let policy = state_metadata::evidence_policy_digest(configuration.normalized())
            .map_err(|_| failure(RhiTradeEvidencePersistenceErrorKind::InvalidObservation))?;
        Ok(Self {
            source_id: source_id.into(),
            policy,
            event_id: *event.event_id().as_bytes(),
            event_signature: event.event_signature_bytes(),
            observed_at: event.observed_at_unix_seconds(),
        })
    }

    pub(crate) fn from_parts(
        source_id: Box<str>,
        policy: RhiEvidencePolicyDigest,
        event: &RhiAdmittedTradeMutationEvent,
    ) -> Self {
        Self {
            source_id,
            policy,
            event_id: *event.event_id().as_bytes(),
            event_signature: event.event_signature_bytes(),
            observed_at: event.observed_at_unix_seconds(),
        }
    }

    pub(crate) fn from_persistence_parts(
        source_id: Box<str>,
        policy: RhiEvidencePolicyDigest,
        record: &PersistenceRecord,
        observed_at: RhiTradeMutationObservedAtUnixSeconds,
    ) -> Self {
        Self {
            source_id,
            policy,
            event_id: record.event_id,
            event_signature: record.event_signature,
            observed_at,
        }
    }
}

impl fmt::Debug for RhiTradeSourceObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiTradeSourceObservation")
            .field("selector", &SOURCE_SELECTOR)
            .field("observed_at_unix_seconds", &self.observed_at.get())
            .field("source", &"[redacted]")
            .field("event", &"[redacted]")
            .finish()
    }
}

/// Stable source-free classification for immutable evidence persistence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiTradeEvidencePersistenceErrorKind {
    InvalidMode,
    InvalidObservation,
    Encoding,
    MutationConflict,
    SignedEventConflict,
    Storage,
    CommitOutcomeUnknown,
}

impl RhiTradeEvidencePersistenceErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "trade_evidence_mode_invalid",
            Self::InvalidObservation => "trade_evidence_observation_invalid",
            Self::Encoding => "trade_evidence_encoding_failed",
            Self::MutationConflict => "trade_mutation_conflict",
            Self::SignedEventConflict => "trade_signed_event_conflict",
            Self::Storage => "trade_evidence_storage_failed",
            Self::CommitOutcomeUnknown => "trade_evidence_commit_outcome_unknown",
        }
    }
}

/// Redacted source-free immutable evidence persistence failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiTradeEvidencePersistenceError {
    kind: RhiTradeEvidencePersistenceErrorKind,
}

impl RhiTradeEvidencePersistenceError {
    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> RhiTradeEvidencePersistenceErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiTradeEvidencePersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiTradeEvidencePersistenceErrorKind::InvalidMode => {
                "RHI trade evidence requires writable state"
            }
            RhiTradeEvidencePersistenceErrorKind::InvalidObservation => {
                "RHI trade source observation is invalid"
            }
            RhiTradeEvidencePersistenceErrorKind::Encoding => {
                "RHI signed trade event encoding failed"
            }
            RhiTradeEvidencePersistenceErrorKind::MutationConflict => {
                "RHI canonical trade mutation conflicts with durable evidence"
            }
            RhiTradeEvidencePersistenceErrorKind::SignedEventConflict => {
                "RHI signed trade event conflicts with durable evidence"
            }
            RhiTradeEvidencePersistenceErrorKind::Storage => {
                "RHI trade evidence transaction failed"
            }
            RhiTradeEvidencePersistenceErrorKind::CommitOutcomeUnknown => {
                "RHI trade evidence commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for RhiTradeEvidencePersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiTradeEvidencePersistenceError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiTradeEvidencePersistenceError {}

/// Exact immutable facts newly inserted by one committed persistence call.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiTradeEvidencePersistenceOutcome {
    mutation_inserted: bool,
    signed_event_inserted: bool,
    observation_inserted: bool,
}

impl RhiTradeEvidencePersistenceOutcome {
    /// Returns whether the canonical mutation fact was newly inserted.
    #[must_use]
    pub const fn mutation_inserted(self) -> bool {
        self.mutation_inserted
    }

    /// Returns whether the exact signed-event fact was newly inserted.
    #[must_use]
    pub const fn signed_event_inserted(self) -> bool {
        self.signed_event_inserted
    }

    /// Returns whether the configured-source observation was newly inserted.
    #[must_use]
    pub const fn observation_inserted(self) -> bool {
        self.observation_inserted
    }
}

impl fmt::Debug for RhiTradeEvidencePersistenceOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiTradeEvidencePersistenceOutcome")
            .field("mutation_inserted", &self.mutation_inserted)
            .field("signed_event_inserted", &self.signed_event_inserted)
            .field("observation_inserted", &self.observation_inserted)
            .finish()
    }
}

impl RhiStateRepositories<'_> {
    /// Atomically persists one admitted mutation, signed event, and observation.
    pub async fn persist_trade_evidence(
        &self,
        event: RhiAdmittedTradeMutationEvent,
        observation: RhiTradeSourceObservation,
    ) -> Result<RhiTradeEvidencePersistenceOutcome, RhiTradeEvidencePersistenceError> {
        let host = self.host();
        if host.mode() != RhiStateHostMode::ReadWriteExisting {
            return Err(failure(RhiTradeEvidencePersistenceErrorKind::InvalidMode));
        }
        let record = PersistenceRecord::from_admitted(event)?;
        if observation.policy != host.metadata().evidence_policy_digest()
            || observation.event_id != record.event_id
            || observation.event_signature != record.event_signature
        {
            return Err(failure(
                RhiTradeEvidencePersistenceErrorKind::InvalidObservation,
            ));
        }
        host.sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { persist(transaction, &record, &observation).await })
            })
            .await
            .map_err(map_transaction_error)
    }
}

#[derive(Clone)]
pub(crate) struct PersistenceRecord {
    pub(crate) mutation_id: [u8; 32],
    pub(crate) trade_id: [u8; 16],
    pub(crate) contract_id: &'static str,
    pub(crate) schema_version: u16,
    pub(crate) event_id: [u8; 32],
    pub(crate) event_signature: [u8; 64],
    pub(crate) author_pubkey: [u8; 32],
    pub(crate) event_kind: u32,
    pub(crate) authored_at_unix_s: u64,
    pub(crate) canonical_content: Arc<[u8]>,
    pub(crate) canonical_event_json: Box<[u8]>,
}

impl PersistenceRecord {
    pub(crate) fn from_admitted(
        admitted: RhiAdmittedTradeMutationEvent,
    ) -> Result<Self, RhiTradeEvidencePersistenceError> {
        let (_original, event, mutation, mutation_id, _) = admitted.into_parts();
        let canonical_event_json = serde_json::to_vec(&event.to_nip01_wire())
            .map_err(|_| failure(RhiTradeEvidencePersistenceErrorKind::Encoding))?;
        if canonical_event_json.is_empty() || canonical_event_json.len() > MAX_CANONICAL_EVENT_BYTES
        {
            return Err(failure(RhiTradeEvidencePersistenceErrorKind::Encoding));
        }
        let canonical_content = event.content().as_bytes().to_vec();
        if canonical_content.is_empty() || canonical_content.len() > MAX_MUTATION_CONTENT_BYTES {
            return Err(failure(RhiTradeEvidencePersistenceErrorKind::Encoding));
        }
        Ok(Self {
            mutation_id: *mutation_id.as_bytes(),
            trade_id: *mutation.trade_id.as_bytes(),
            contract_id: mutation.mutation_kind().contract_id(),
            schema_version: mutation.schema_version,
            event_id: *event.id().as_bytes(),
            event_signature: *event.sig().as_bytes(),
            author_pubkey: *event.author().as_bytes(),
            event_kind: event.kind_u32(),
            authored_at_unix_s: event.created_at_u64(),
            canonical_content: canonical_content.into(),
            canonical_event_json: canonical_event_json.into_boxed_slice(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PersistenceOperationError {
    MutationConflict,
    SignedEventConflict,
    Storage,
}

pub(crate) async fn persist(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &PersistenceRecord,
    observation: &RhiTradeSourceObservation,
) -> Result<RhiTradeEvidencePersistenceOutcome, PersistenceOperationError> {
    let mutation_inserted = insert_mutation(transaction, record).await?;
    let signed_event_inserted = insert_event(transaction, record).await?;
    let observation_inserted = insert_observation(transaction, observation).await?;
    Ok(RhiTradeEvidencePersistenceOutcome {
        mutation_inserted,
        signed_event_inserted,
        observation_inserted,
    })
}

async fn insert_mutation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &PersistenceRecord,
) -> Result<bool, PersistenceOperationError> {
    let result = sqlx::query(INSERT_MUTATION_SQL)
        .bind(record.mutation_id.as_slice())
        .bind(record.trade_id.as_slice())
        .bind(record.contract_id)
        .bind(i64::from(record.schema_version))
        .bind(i64::from(record.event_kind))
        .bind(record.author_pubkey.as_slice())
        .bind(record.canonical_content.as_ref())
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceOperationError::Storage)?;
    match result.rows_affected() {
        1 => Ok(true),
        0 if mutation_matches(transaction, record).await? => Ok(false),
        0 => Err(PersistenceOperationError::MutationConflict),
        _ => Err(PersistenceOperationError::Storage),
    }
}

async fn mutation_matches(
    transaction: &mut ServiceSqliteTransaction<'_>,
    expected: &PersistenceRecord,
) -> Result<bool, PersistenceOperationError> {
    let row = sqlx::query(READ_MUTATION_SQL)
        .bind(expected.mutation_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceOperationError::Storage)?
        .ok_or(PersistenceOperationError::Storage)?;
    Ok(
        exact_blob(&row, "trade_id", "trade_id_bytes")? == expected.trade_id
            && bounded_text(
                &row,
                "contract_id",
                "contract_id_bytes",
                MAX_CONTRACT_ID_BYTES,
            )? == expected.contract_id
            && row.try_get::<i64, _>("schema_version").ok()
                == Some(i64::from(expected.schema_version))
            && row.try_get::<i64, _>("event_kind").ok() == Some(i64::from(expected.event_kind))
            && exact_blob(&row, "author_pubkey", "author_pubkey_bytes")? == expected.author_pubkey
            && bounded_blob(
                &row,
                "canonical_content",
                "canonical_content_bytes",
                MAX_MUTATION_CONTENT_BYTES,
            )? == expected.canonical_content.as_ref(),
    )
}

async fn insert_event(
    transaction: &mut ServiceSqliteTransaction<'_>,
    record: &PersistenceRecord,
) -> Result<bool, PersistenceOperationError> {
    let result = sqlx::query(INSERT_EVENT_SQL)
        .bind(record.event_id.as_slice())
        .bind(record.event_signature.as_slice())
        .bind(record.mutation_id.as_slice())
        .bind(record.author_pubkey.as_slice())
        .bind(i64::from(record.event_kind))
        .bind(
            i64::try_from(record.authored_at_unix_s)
                .map_err(|_| PersistenceOperationError::Storage)?,
        )
        .bind(record.canonical_event_json.as_ref())
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceOperationError::Storage)?;
    match result.rows_affected() {
        1 => Ok(true),
        0 if event_matches(transaction, record).await? => Ok(false),
        0 => Err(PersistenceOperationError::SignedEventConflict),
        _ => Err(PersistenceOperationError::Storage),
    }
}

async fn event_matches(
    transaction: &mut ServiceSqliteTransaction<'_>,
    expected: &PersistenceRecord,
) -> Result<bool, PersistenceOperationError> {
    let row = sqlx::query(READ_EVENT_SQL)
        .bind(expected.event_id.as_slice())
        .bind(expected.event_signature.as_slice())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| PersistenceOperationError::Storage)?
        .ok_or(PersistenceOperationError::Storage)?;
    Ok(
        exact_blob(&row, "mutation_id", "mutation_id_bytes")? == expected.mutation_id
            && exact_blob(&row, "author_pubkey", "author_pubkey_bytes")? == expected.author_pubkey
            && row.try_get::<i64, _>("event_kind").ok() == Some(i64::from(expected.event_kind))
            && row.try_get::<i64, _>("authored_at_unix_s").ok()
                == i64::try_from(expected.authored_at_unix_s).ok()
            && bounded_blob(
                &row,
                "canonical_event_json",
                "canonical_event_json_bytes",
                MAX_CANONICAL_EVENT_BYTES,
            )? == expected.canonical_event_json.as_ref(),
    )
}

async fn insert_observation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    observation: &RhiTradeSourceObservation,
) -> Result<bool, PersistenceOperationError> {
    let result = sqlx::query(INSERT_OBSERVATION_SQL)
        .bind(observation.source_id.as_ref())
        .bind(SOURCE_SELECTOR)
        .bind(observation.policy.as_bytes().as_slice())
        .bind(observation.event_id.as_slice())
        .bind(observation.event_signature.as_slice())
        .bind(
            i64::try_from(observation.observed_at.get())
                .map_err(|_| PersistenceOperationError::Storage)?,
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| PersistenceOperationError::Storage)?;
    match result.rows_affected() {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(PersistenceOperationError::Storage),
    }
}

fn configured_source<'a>(configuration: &'a Value, source_id: &str) -> Option<&'a Value> {
    if source_id.is_empty()
        || source_id.len() > MAX_SOURCE_ID_BYTES
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

fn exact_blob<const N: usize>(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    length_field: &str,
) -> Result<[u8; N], PersistenceOperationError> {
    bounded_blob(row, field, length_field, N)?
        .try_into()
        .map_err(|_| PersistenceOperationError::Storage)
}

fn bounded_text(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    length_field: &str,
    maximum: usize,
) -> Result<String, PersistenceOperationError> {
    let length = bounded_length(row, length_field, maximum)?;
    let value = row
        .try_get::<String, _>(field)
        .map_err(|_| PersistenceOperationError::Storage)?;
    (value.len() == length)
        .then_some(value)
        .ok_or(PersistenceOperationError::Storage)
}

fn bounded_blob(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    length_field: &str,
    maximum: usize,
) -> Result<Vec<u8>, PersistenceOperationError> {
    let length = bounded_length(row, length_field, maximum)?;
    let value = row
        .try_get::<Vec<u8>, _>(field)
        .map_err(|_| PersistenceOperationError::Storage)?;
    (value.len() == length)
        .then_some(value)
        .ok_or(PersistenceOperationError::Storage)
}

fn bounded_length(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    maximum: usize,
) -> Result<usize, PersistenceOperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (1..=maximum).contains(value))
        .ok_or(PersistenceOperationError::Storage)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<PersistenceOperationError>,
) -> RhiTradeEvidencePersistenceError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return failure(RhiTradeEvidencePersistenceErrorKind::CommitOutcomeUnknown);
    }
    failure(match error.operation_error().copied() {
        Some(PersistenceOperationError::MutationConflict) => {
            RhiTradeEvidencePersistenceErrorKind::MutationConflict
        }
        Some(PersistenceOperationError::SignedEventConflict) => {
            RhiTradeEvidencePersistenceErrorKind::SignedEventConflict
        }
        Some(PersistenceOperationError::Storage) | None => {
            RhiTradeEvidencePersistenceErrorKind::Storage
        }
    })
}

const fn failure(kind: RhiTradeEvidencePersistenceErrorKind) -> RhiTradeEvidencePersistenceError {
    RhiTradeEvidencePersistenceError { kind }
}
