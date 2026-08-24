//! Bounded durable idempotency for permissioned Rhi admin mutations.

use core::{fmt, future::Future, pin::Pin};
use std::error::Error;

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    RhiAdminRequestDocument, RhiAdminResponseDocument, RhiAdminRoute, RhiStateHost,
    RhiStateHostMode,
};

/// Maximum encoded length of a durable admin operation identifier.
pub const RHI_ADMIN_OPERATION_ID_MAX_BYTES: usize = 128;
/// Maximum canonical response-model bytes retained for replay.
pub const RHI_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES: usize = 8_192;
/// Maximum retained completed operations after expiry pruning.
pub const RHI_ADMIN_OPERATION_COMPLETED_LIMIT: u16 = 4_096;
/// Maximum retained operations whose external outcome is unresolved.
pub const RHI_ADMIN_OPERATION_PREPARED_LIMIT: u8 = 128;
/// Frozen seven-day completed-response retention.
pub const RHI_ADMIN_OPERATION_DEFAULT_RETENTION_MS: u64 = 604_800_000;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"radroots.rhi.admin_operation_request.v1\0";
const PRUNE_LIMIT: i64 = 4_096;

const PRUNE_EXPIRED_SQL: &str = r#"DELETE FROM rhi_admin_operations
WHERE operation_id IN (
    SELECT operation_id FROM rhi_admin_operations
    WHERE state = 'completed' AND expires_at_unix_ms <= ?
    ORDER BY expires_at_unix_ms, operation_id
    LIMIT ?
)"#;

const READ_OPERATION_SQL: &str = r#"SELECT
    CASE WHEN typeof(route) = 'text' AND length(CAST(route AS BLOB)) BETWEEN 1 AND 128
        THEN route ELSE NULL END AS route,
    CASE WHEN typeof(request_sha256) = 'blob' AND length(request_sha256) = 32
        THEN request_sha256 ELSE NULL END AS request_sha256,
    CASE WHEN typeof(state) = 'text' AND length(CAST(state AS BLOB)) <= 16
        THEN state ELSE NULL END AS state,
    CASE WHEN typeof(response_model) = 'blob' AND length(response_model) BETWEEN 1 AND 8192
        THEN response_model ELSE NULL END AS response_model,
    typeof(response_model) AS response_model_type,
    CASE WHEN typeof(response_sha256) = 'blob' AND length(response_sha256) = 32
        THEN response_sha256 ELSE NULL END AS response_sha256,
    typeof(response_sha256) AS response_sha256_type,
    prepared_at_unix_ms,
    completed_at_unix_ms,
    typeof(completed_at_unix_ms) AS completed_at_type,
    expires_at_unix_ms,
    typeof(expires_at_unix_ms) AS expires_at_type
FROM rhi_admin_operations
WHERE operation_id = ?
LIMIT 2"#;

const READ_COUNTS_SQL: &str = r#"SELECT
    COUNT(CASE WHEN state = 'completed' THEN 1 END) AS completed_count,
    COUNT(CASE WHEN state = 'prepared' THEN 1 END) AS prepared_count
FROM rhi_admin_operations"#;

const INSERT_PREPARED_SQL: &str = r#"INSERT INTO rhi_admin_operations (
    operation_id, route, request_sha256, state, prepared_at_unix_ms
) VALUES (?, ?, ?, 'prepared', ?)"#;

const COMPLETE_OPERATION_SQL: &str = r#"UPDATE rhi_admin_operations
SET state = 'completed', response_model = ?, response_sha256 = ?,
    completed_at_unix_ms = ?, expires_at_unix_ms = ?
WHERE operation_id = ? AND state = 'prepared'"#;

/// Stable source-free admin-journal failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiAdminOperationErrorKind {
    InvalidMode,
    InvalidInput,
    OperationConflict,
    OperationOutcomeUnknown,
    ResourceExhausted,
    Binding,
    Transaction,
    CommitOutcomeUnknown,
}

/// Redacted admin-journal error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiAdminOperationError {
    kind: RhiAdminOperationErrorKind,
}

impl RhiAdminOperationError {
    const fn new(kind: RhiAdminOperationErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiAdminOperationErrorKind {
        self.kind
    }
}

impl fmt::Display for RhiAdminOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiAdminOperationErrorKind::InvalidMode => {
                "RHI admin operation requires writable state"
            }
            RhiAdminOperationErrorKind::InvalidInput => "RHI admin operation input is invalid",
            RhiAdminOperationErrorKind::OperationConflict => {
                "RHI admin operation identity conflicts with retained evidence"
            }
            RhiAdminOperationErrorKind::OperationOutcomeUnknown => {
                "RHI admin operation outcome is unknown"
            }
            RhiAdminOperationErrorKind::ResourceExhausted => {
                "RHI admin operation capacity is exhausted"
            }
            RhiAdminOperationErrorKind::Binding => "RHI admin operation journal binding is invalid",
            RhiAdminOperationErrorKind::Transaction => "RHI admin operation transaction failed",
            RhiAdminOperationErrorKind::CommitOutcomeUnknown => {
                "RHI admin operation commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for RhiAdminOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiAdminOperationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiAdminOperationError {}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct AdminOperationIdBinding(Box<str>);

impl AdminOperationIdBinding {
    fn new(value: &str) -> Result<Self, RhiAdminOperationError> {
        let bytes = value.as_bytes();
        let valid = !bytes.is_empty()
            && bytes.len() <= RHI_ADMIN_OPERATION_ID_MAX_BYTES
            && bytes[0].is_ascii_alphanumeric()
            && bytes.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            });
        valid
            .then(|| Self(value.into()))
            .ok_or_else(|| RhiAdminOperationError::new(RhiAdminOperationErrorKind::InvalidInput))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdminOperationIdBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdminOperationIdBinding([redacted])")
    }
}

/// Injected UTC millisecond evidence representable by SQLite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RhiAdminOperationTimeUnixMs(u64);

impl RhiAdminOperationTimeUnixMs {
    /// Validates one UTC millisecond instant without reading ambient time.
    pub fn new(value: u64) -> Result<Self, RhiAdminOperationError> {
        i64::try_from(value)
            .map(|_| Self(value))
            .map_err(|_| RhiAdminOperationError::new(RhiAdminOperationErrorKind::InvalidInput))
    }

    /// Returns the validated instant.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn sqlite_value(self) -> i64 {
        i64::try_from(self.0).expect("validated admin operation time fits SQLite")
    }
}

/// Explicit bounded completed-response retention policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiAdminOperationJournalPolicy {
    completed_retention_ms: u64,
}

impl RhiAdminOperationJournalPolicy {
    /// Returns the exact seven-day policy.
    #[must_use]
    pub const fn seven_days() -> Self {
        Self {
            completed_retention_ms: RHI_ADMIN_OPERATION_DEFAULT_RETENTION_MS,
        }
    }

    /// Returns the admitted retention duration.
    #[must_use]
    pub const fn completed_retention_ms(self) -> u64 {
        self.completed_retention_ms
    }
}

/// Sealed evidence that one external or cross-resource mutation is unresolved.
pub struct RhiPreparedAdminOperation {
    operation_id: AdminOperationIdBinding,
    route: RhiAdminRoute,
    request_sha256: [u8; 32],
    prepared_at: RhiAdminOperationTimeUnixMs,
}

impl fmt::Debug for RhiPreparedAdminOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPreparedAdminOperation")
            .field("route", &self.route)
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Result of mutation admission after bounded expiry pruning.
pub enum RhiAdminOperationAdmission {
    Prepared(RhiPreparedAdminOperation),
    ExactReplay(RhiAdminResponseDocument),
}

impl fmt::Debug for RhiAdminOperationAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Prepared(_) => "RhiAdminOperationAdmission::Prepared([redacted])",
            Self::ExactReplay(_) => "RhiAdminOperationAdmission::ExactReplay([redacted])",
        })
    }
}

/// Result of completing a previously prepared operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiAdminOperationCompletion {
    Completed,
    ExactReplay,
}

pub(crate) struct RhiAdminOperationRepository<'host> {
    host: &'host RhiStateHost,
}

impl<'host> RhiAdminOperationRepository<'host> {
    pub(crate) const fn new(host: &'host RhiStateHost) -> Self {
        Self { host }
    }

    /// Atomically commits one SQLite-only admin mutation and its replay receipt.
    pub(crate) async fn execute_database_admin_operation<F>(
        &self,
        request: &RhiAdminRequestDocument,
        completed_at: RhiAdminOperationTimeUnixMs,
        policy: RhiAdminOperationJournalPolicy,
        operation: F,
    ) -> Result<RhiAdminResponseDocument, RhiAdminOperationError>
    where
        F: for<'a, 'b> FnOnce(
                &'a mut ServiceSqliteTransaction<'b>,
            ) -> AdminDatabaseOperationFuture<'a>
            + Send
            + 'static,
    {
        if self.host.mode() != RhiStateHostMode::ReadWriteExisting {
            return Err(RhiAdminOperationError::new(
                RhiAdminOperationErrorKind::InvalidMode,
            ));
        }
        let binding = AdminRequestBinding::from_document(request)?;
        let expires_at = completed_at
            .get()
            .checked_add(policy.completed_retention_ms())
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or_else(|| RhiAdminOperationError::new(RhiAdminOperationErrorKind::InvalidInput))?;
        self.host
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    let prepared = match prepare_operation(transaction, &binding, completed_at)
                        .await?
                    {
                        RhiAdminOperationAdmission::ExactReplay(response) => return Ok(response),
                        RhiAdminOperationAdmission::Prepared(prepared) => prepared,
                    };
                    let response = operation(transaction).await?;
                    if response.route() != binding.route
                        || response.canonical_bytes().is_empty()
                        || response.canonical_bytes().len()
                            > RHI_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES
                    {
                        return Err(AdminJournalOperationError::InvalidInput);
                    }
                    complete_operation(
                        transaction,
                        &PreparedBinding::from_prepared(&prepared),
                        response.canonical_bytes(),
                        completed_at,
                        expires_at,
                    )
                    .await?;
                    Ok(response)
                })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Prunes a bounded expired prefix and admits or replays one mutation.
    pub async fn prepare_admin_operation(
        &self,
        request: &RhiAdminRequestDocument,
        observed_at: RhiAdminOperationTimeUnixMs,
    ) -> Result<RhiAdminOperationAdmission, RhiAdminOperationError> {
        if self.host.mode() != RhiStateHostMode::ReadWriteExisting {
            return Err(RhiAdminOperationError::new(
                RhiAdminOperationErrorKind::InvalidMode,
            ));
        }
        let binding = AdminRequestBinding::from_document(request)?;
        self.host
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { prepare_operation(transaction, &binding, observed_at).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Completes one external mutation only after its durable effect exists.
    pub async fn complete_admin_operation(
        &self,
        prepared: &RhiPreparedAdminOperation,
        response: &RhiAdminResponseDocument,
        completed_at: RhiAdminOperationTimeUnixMs,
        policy: RhiAdminOperationJournalPolicy,
    ) -> Result<RhiAdminOperationCompletion, RhiAdminOperationError> {
        if self.host.mode() != RhiStateHostMode::ReadWriteExisting {
            return Err(RhiAdminOperationError::new(
                RhiAdminOperationErrorKind::InvalidMode,
            ));
        }
        if response.route() != prepared.route
            || response.canonical_bytes().is_empty()
            || response.canonical_bytes().len() > RHI_ADMIN_OPERATION_RESPONSE_MODEL_MAX_BYTES
            || completed_at < prepared.prepared_at
        {
            return Err(RhiAdminOperationError::new(
                RhiAdminOperationErrorKind::InvalidInput,
            ));
        }
        let expires_at = completed_at
            .get()
            .checked_add(policy.completed_retention_ms())
            .filter(|value| i64::try_from(*value).is_ok())
            .ok_or_else(|| RhiAdminOperationError::new(RhiAdminOperationErrorKind::InvalidInput))?;
        let binding = PreparedBinding::from_prepared(prepared);
        let response = response.canonical_bytes().to_vec().into_boxed_slice();
        self.host
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move {
                    complete_operation(transaction, &binding, &response, completed_at, expires_at)
                        .await
                })
            })
            .await
            .map_err(map_transaction_error)
    }
}

struct AdminRequestBinding {
    operation_id: AdminOperationIdBinding,
    route: RhiAdminRoute,
    request_sha256: [u8; 32],
}

impl AdminRequestBinding {
    fn from_document(request: &RhiAdminRequestDocument) -> Result<Self, RhiAdminOperationError> {
        if !request.route().is_mutation() {
            return Err(RhiAdminOperationError::new(
                RhiAdminOperationErrorKind::InvalidInput,
            ));
        }
        let operation_id = request
            .operation_id()
            .ok_or_else(|| RhiAdminOperationError::new(RhiAdminOperationErrorKind::InvalidInput))?;
        Ok(Self {
            operation_id: AdminOperationIdBinding::new(operation_id)?,
            route: request.route(),
            request_sha256: request_digest(request),
        })
    }
}

struct PreparedBinding {
    operation_id: AdminOperationIdBinding,
    route: RhiAdminRoute,
    request_sha256: [u8; 32],
    prepared_at: RhiAdminOperationTimeUnixMs,
}

impl PreparedBinding {
    fn from_prepared(prepared: &RhiPreparedAdminOperation) -> Self {
        Self {
            operation_id: prepared.operation_id.clone(),
            route: prepared.route,
            request_sha256: prepared.request_sha256,
            prepared_at: prepared.prepared_at,
        }
    }
}

enum StoredOperation {
    Prepared {
        route: RhiAdminRoute,
        request_sha256: [u8; 32],
        prepared_at: RhiAdminOperationTimeUnixMs,
    },
    Completed {
        route: RhiAdminRoute,
        request_sha256: [u8; 32],
        response: Box<[u8]>,
        response_sha256: [u8; 32],
        prepared_at: RhiAdminOperationTimeUnixMs,
        completed_at: RhiAdminOperationTimeUnixMs,
        expires_at: RhiAdminOperationTimeUnixMs,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdminJournalOperationError {
    InvalidInput,
    Conflict,
    OutcomeUnknown,
    ResourceExhausted,
    Binding,
    Storage,
}

pub(crate) type AdminDatabaseOperationFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<RhiAdminResponseDocument, AdminJournalOperationError>>
            + Send
            + 'a,
    >,
>;

async fn prepare_operation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    binding: &AdminRequestBinding,
    observed_at: RhiAdminOperationTimeUnixMs,
) -> Result<RhiAdminOperationAdmission, AdminJournalOperationError> {
    prune_expired(transaction, observed_at).await?;
    if let Some(existing) = read_operation(transaction, &binding.operation_id).await? {
        return match existing {
            StoredOperation::Prepared {
                route,
                request_sha256,
                ..
            } if route == binding.route && request_sha256 == binding.request_sha256 => {
                Err(AdminJournalOperationError::OutcomeUnknown)
            }
            StoredOperation::Completed {
                route,
                request_sha256,
                response,
                response_sha256,
                ..
            } if route == binding.route && request_sha256 == binding.request_sha256 => {
                if sha256(&response) != response_sha256 {
                    return Err(AdminJournalOperationError::Binding);
                }
                RhiAdminResponseDocument::from_canonical_bytes(route, &response)
                    .map(RhiAdminOperationAdmission::ExactReplay)
                    .map_err(|_| AdminJournalOperationError::Binding)
            }
            StoredOperation::Prepared { .. } | StoredOperation::Completed { .. } => {
                Err(AdminJournalOperationError::Conflict)
            }
        };
    }
    let (completed, prepared) = read_counts(transaction).await?;
    let reserved = completed
        .checked_add(prepared)
        .ok_or(AdminJournalOperationError::Binding)?;
    if reserved >= u64::from(RHI_ADMIN_OPERATION_COMPLETED_LIMIT)
        || prepared >= u64::from(RHI_ADMIN_OPERATION_PREPARED_LIMIT)
    {
        return Err(AdminJournalOperationError::ResourceExhausted);
    }
    let result = sqlx::query(INSERT_PREPARED_SQL)
        .bind(binding.operation_id.as_str())
        .bind(binding.route.operation_id())
        .bind(binding.request_sha256.as_slice())
        .bind(observed_at.sqlite_value())
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminJournalOperationError::Storage)?;
    require_one(result.rows_affected())?;
    match read_operation(transaction, &binding.operation_id).await? {
        Some(StoredOperation::Prepared {
            route,
            request_sha256,
            prepared_at,
        }) if route == binding.route
            && request_sha256 == binding.request_sha256
            && prepared_at == observed_at =>
        {
            Ok(RhiAdminOperationAdmission::Prepared(
                RhiPreparedAdminOperation {
                    operation_id: binding.operation_id.clone(),
                    route,
                    request_sha256,
                    prepared_at,
                },
            ))
        }
        Some(_) | None => Err(AdminJournalOperationError::Binding),
    }
}

async fn complete_operation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    binding: &PreparedBinding,
    response: &[u8],
    completed_at: RhiAdminOperationTimeUnixMs,
    expires_at: u64,
) -> Result<RhiAdminOperationCompletion, AdminJournalOperationError> {
    let response_sha256 = sha256(response);
    match read_operation(transaction, &binding.operation_id).await? {
        Some(StoredOperation::Completed {
            route,
            request_sha256,
            response: existing_response,
            response_sha256: existing_sha256,
            ..
        }) if route == binding.route
            && request_sha256 == binding.request_sha256
            && existing_response.as_ref() == response
            && existing_sha256 == response_sha256 =>
        {
            return Ok(RhiAdminOperationCompletion::ExactReplay);
        }
        Some(StoredOperation::Completed { .. }) => {
            return Err(AdminJournalOperationError::Conflict);
        }
        Some(StoredOperation::Prepared {
            route,
            request_sha256,
            prepared_at,
        }) if route == binding.route
            && request_sha256 == binding.request_sha256
            && prepared_at == binding.prepared_at => {}
        Some(StoredOperation::Prepared { .. }) => {
            return Err(AdminJournalOperationError::Conflict);
        }
        None => return Err(AdminJournalOperationError::Binding),
    }
    let (completed, _) = read_counts(transaction).await?;
    if completed >= u64::from(RHI_ADMIN_OPERATION_COMPLETED_LIMIT) {
        return Err(AdminJournalOperationError::ResourceExhausted);
    }
    let result = sqlx::query(COMPLETE_OPERATION_SQL)
        .bind(response)
        .bind(response_sha256.as_slice())
        .bind(completed_at.sqlite_value())
        .bind(i64::try_from(expires_at).map_err(|_| AdminJournalOperationError::InvalidInput)?)
        .bind(binding.operation_id.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|_| AdminJournalOperationError::Storage)?;
    require_one(result.rows_affected())?;
    match read_operation(transaction, &binding.operation_id).await? {
        Some(StoredOperation::Completed {
            route,
            request_sha256,
            response: actual_response,
            response_sha256: actual_sha256,
            prepared_at,
            completed_at: actual_completed_at,
            expires_at: actual_expires_at,
        }) if route == binding.route
            && request_sha256 == binding.request_sha256
            && actual_response.as_ref() == response
            && actual_sha256 == response_sha256
            && prepared_at == binding.prepared_at
            && actual_completed_at == completed_at
            && actual_expires_at.get() == expires_at =>
        {
            Ok(RhiAdminOperationCompletion::Completed)
        }
        Some(_) | None => Err(AdminJournalOperationError::Binding),
    }
}

async fn prune_expired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    observed_at: RhiAdminOperationTimeUnixMs,
) -> Result<(), AdminJournalOperationError> {
    sqlx::query(PRUNE_EXPIRED_SQL)
        .bind(observed_at.sqlite_value())
        .bind(PRUNE_LIMIT)
        .execute(&mut *transaction)
        .await
        .map(|_| ())
        .map_err(|_| AdminJournalOperationError::Storage)
}

async fn read_counts(
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<(u64, u64), AdminJournalOperationError> {
    let rows = sqlx::query(READ_COUNTS_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AdminJournalOperationError::Storage)?;
    if rows.len() != 1 {
        return Err(AdminJournalOperationError::Binding);
    }
    let completed = rows[0]
        .try_get::<i64, _>("completed_count")
        .map_err(|_| AdminJournalOperationError::Binding)?;
    let prepared = rows[0]
        .try_get::<i64, _>("prepared_count")
        .map_err(|_| AdminJournalOperationError::Binding)?;
    Ok((
        u64::try_from(completed).map_err(|_| AdminJournalOperationError::Binding)?,
        u64::try_from(prepared).map_err(|_| AdminJournalOperationError::Binding)?,
    ))
}

async fn read_operation(
    transaction: &mut ServiceSqliteTransaction<'_>,
    operation_id: &AdminOperationIdBinding,
) -> Result<Option<StoredOperation>, AdminJournalOperationError> {
    let rows = sqlx::query(READ_OPERATION_SQL)
        .bind(operation_id.as_str())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| AdminJournalOperationError::Storage)?;
    if rows.len() > 1 {
        return Err(AdminJournalOperationError::Binding);
    }
    rows.first().map(decode_operation).transpose()
}

fn decode_operation(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<StoredOperation, AdminJournalOperationError> {
    let route = row
        .try_get::<Option<&str>, _>("route")
        .map_err(|_| AdminJournalOperationError::Binding)?
        .and_then(parse_route)
        .ok_or(AdminJournalOperationError::Binding)?;
    let request_sha256 = exact_digest(row, "request_sha256")?;
    let state = row
        .try_get::<Option<&str>, _>("state")
        .map_err(|_| AdminJournalOperationError::Binding)?
        .ok_or(AdminJournalOperationError::Binding)?;
    let prepared_at = time(row, "prepared_at_unix_ms")?;
    match state {
        "prepared" => {
            require_null(row, "response_model_type")?;
            require_null(row, "response_sha256_type")?;
            require_null(row, "completed_at_type")?;
            require_null(row, "expires_at_type")?;
            Ok(StoredOperation::Prepared {
                route,
                request_sha256,
                prepared_at,
            })
        }
        "completed" => {
            require_type(row, "response_model_type", "blob")?;
            require_type(row, "response_sha256_type", "blob")?;
            require_type(row, "completed_at_type", "integer")?;
            require_type(row, "expires_at_type", "integer")?;
            let response = row
                .try_get::<Option<Vec<u8>>, _>("response_model")
                .map_err(|_| AdminJournalOperationError::Binding)?
                .ok_or(AdminJournalOperationError::Binding)?
                .into_boxed_slice();
            Ok(StoredOperation::Completed {
                route,
                request_sha256,
                response,
                response_sha256: exact_digest(row, "response_sha256")?,
                prepared_at,
                completed_at: time(row, "completed_at_unix_ms")?,
                expires_at: time(row, "expires_at_unix_ms")?,
            })
        }
        _ => Err(AdminJournalOperationError::Binding),
    }
}

fn request_digest(request: &RhiAdminRequestDocument) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hash_field(&mut hasher, request.route().operation_id().as_bytes());
    hasher.update([0]);
    hash_field(&mut hasher, request.model_bytes());
    hasher.finalize().into()
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(
        u64::try_from(bytes.len())
            .expect("bounded field length")
            .to_be_bytes(),
    );
    hasher.update(bytes);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn parse_route(value: &str) -> Option<RhiAdminRoute> {
    RhiAdminRoute::ALL
        .into_iter()
        .find(|route| route.is_mutation() && route.operation_id() == value)
}

fn exact_digest(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; 32], AdminJournalOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| AdminJournalOperationError::Binding)?
        .ok_or(AdminJournalOperationError::Binding)?
        .try_into()
        .map_err(|_| AdminJournalOperationError::Binding)
}

fn time(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<RhiAdminOperationTimeUnixMs, AdminJournalOperationError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| AdminJournalOperationError::Binding)?;
    RhiAdminOperationTimeUnixMs::new(
        u64::try_from(value).map_err(|_| AdminJournalOperationError::Binding)?,
    )
    .map_err(|_| AdminJournalOperationError::Binding)
}

fn require_null(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<(), AdminJournalOperationError> {
    require_type(row, column, "null")
}

fn require_type(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    expected: &str,
) -> Result<(), AdminJournalOperationError> {
    (row.try_get::<&str, _>(column)
        .map_err(|_| AdminJournalOperationError::Binding)?
        == expected)
        .then_some(())
        .ok_or(AdminJournalOperationError::Binding)
}

fn require_one(rows: u64) -> Result<(), AdminJournalOperationError> {
    (rows == 1)
        .then_some(())
        .ok_or(AdminJournalOperationError::Storage)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<AdminJournalOperationError>,
) -> RhiAdminOperationError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return RhiAdminOperationError::new(RhiAdminOperationErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error() {
        Some(AdminJournalOperationError::InvalidInput) => RhiAdminOperationErrorKind::InvalidInput,
        Some(AdminJournalOperationError::Conflict) => RhiAdminOperationErrorKind::OperationConflict,
        Some(AdminJournalOperationError::OutcomeUnknown) => {
            RhiAdminOperationErrorKind::OperationOutcomeUnknown
        }
        Some(AdminJournalOperationError::ResourceExhausted) => {
            RhiAdminOperationErrorKind::ResourceExhausted
        }
        Some(AdminJournalOperationError::Binding) => RhiAdminOperationErrorKind::Binding,
        Some(AdminJournalOperationError::Storage) | None => RhiAdminOperationErrorKind::Transaction,
    };
    RhiAdminOperationError::new(kind)
}
