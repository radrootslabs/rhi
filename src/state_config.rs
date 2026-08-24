//! Durable append-only RHI configuration-binding lifecycle.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, ServiceSqliteTransaction,
    ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use sqlx::Row;

use crate::{RhiConfigDocumentV1, RhiStateHost, RhiStateMetadata};

/// Maximum immutable configuration generations retained by one RHI instance.
pub const RHI_CONFIG_BINDING_MAX_GENERATIONS: u16 = 1024;

const READ_HISTORY_SQL: &str = r#"SELECT generation,
    normalized_config_sha256, evidence_policy_sha256,
    length(CAST(service_public_key AS BLOB)) AS service_public_key_bytes,
    substr(service_public_key, 1, 65) AS service_public_key,
    config_contract_version, state_contract_version, admin_contract_version,
    status_contract_version, provider_contract_version, applied_at_unix_s,
    length(CAST(service_version AS BLOB)) AS service_version_bytes,
    substr(service_version, 1, 129) AS service_version,
    length(CAST(service_commit AS BLOB)) AS service_commit_bytes,
    substr(service_commit, 1, 41) AS service_commit,
    length(CAST(lib_revision AS BLOB)) AS lib_revision_bytes,
    substr(lib_revision, 1, 41) AS lib_revision,
    length(CAST(rust_version AS BLOB)) AS rust_version_bytes,
    substr(rust_version, 1, 129) AS rust_version,
    length(CAST(target AS BLOB)) AS target_bytes,
    substr(target, 1, 129) AS target,
    length(CAST(feature_profile AS BLOB)) AS feature_profile_bytes,
    substr(feature_profile, 1, 129) AS feature_profile
FROM rhi_config_bindings
ORDER BY generation
LIMIT 1025"#;

const INSERT_BINDING_SQL: &str = r#"INSERT INTO rhi_config_bindings (
    generation, normalized_config_sha256, evidence_policy_sha256,
    service_public_key, config_contract_version, state_contract_version,
    admin_contract_version, status_contract_version, provider_contract_version,
    applied_at_unix_s, service_version, service_commit, lib_revision,
    rust_version, target, feature_profile
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#;
const READ_DIRTY_POLICY_BOUNDS_SQL: &str = r#"SELECT
    COUNT(*) FILTER (WHERE generation >= 9223372036854775807) AS exhausted,
    COALESCE(MAX(updated_at_unix_s), 0) AS latest_updated_at
FROM trade_dirty_generations
WHERE evidence_policy_sha256 != ?"#;
const ADVANCE_DIRTY_POLICY_SQL: &str = r#"UPDATE trade_dirty_generations
SET generation = generation + 1, evidence_policy_sha256 = ?, updated_at_unix_s = ?
WHERE evidence_policy_sha256 != ?"#;

/// Stable source-free offline configuration-application failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiConfigApplyErrorKind {
    InvalidInput,
    Binding,
    ResourceExhausted,
    Transaction,
    CommitOutcomeUnknown,
    Close,
}

impl RhiConfigApplyErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "config_apply_input_invalid",
            Self::Binding => "config_apply_binding_invalid",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Transaction => "config_apply_transaction_failed",
            Self::CommitOutcomeUnknown => "config_apply_commit_outcome_unknown",
            Self::Close => "config_apply_close_failed",
        }
    }
}

/// One redacted source-free RHI configuration-application failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiConfigApplyError {
    kind: RhiConfigApplyErrorKind,
}

impl RhiConfigApplyError {
    pub(crate) const fn new(kind: RhiConfigApplyErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiConfigApplyErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiConfigApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiConfigApplyErrorKind::InvalidInput => "RHI configuration apply evidence is invalid",
            RhiConfigApplyErrorKind::Binding => "RHI configuration history binding is invalid",
            RhiConfigApplyErrorKind::ResourceExhausted => {
                "RHI configuration history capacity is exhausted"
            }
            RhiConfigApplyErrorKind::Transaction => "RHI configuration apply transaction failed",
            RhiConfigApplyErrorKind::CommitOutcomeUnknown => {
                "RHI configuration apply commit outcome is unknown"
            }
            RhiConfigApplyErrorKind::Close => "RHI configuration apply state could not close",
        })
    }
}

impl fmt::Debug for RhiConfigApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiConfigApplyError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiConfigApplyError {}

/// Committed immutable configuration-generation evidence.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiConfigApplyOutcome {
    generation: u16,
    changed: bool,
}

impl RhiConfigApplyOutcome {
    /// Returns the committed consecutive configuration generation.
    #[must_use]
    pub const fn generation(self) -> u16 {
        self.generation
    }

    /// Returns whether this call appended a new durable generation.
    #[must_use]
    pub const fn changed(self) -> bool {
        self.changed
    }
}

impl fmt::Debug for RhiConfigApplyOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiConfigApplyOutcome")
            .field("generation", &self.generation)
            .field("changed", &self.changed)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ConfigBinding {
    normalized_config_sha256: [u8; 32],
    evidence_policy_sha256: [u8; 32],
    service_public_key: Box<str>,
    config_contract_version: u32,
    state_contract_version: u32,
    admin_contract_version: u32,
    status_contract_version: u32,
    provider_contract_version: u32,
}

impl ConfigBinding {
    fn is_governed(&self) -> bool {
        self.config_contract_version == crate::RHI_CONFIG_SCHEMA_VERSION
            && (crate::RHI_STATE_BASE_SCHEMA_VERSION..=crate::RHI_STATE_SCHEMA_VERSION)
                .contains(&self.state_contract_version)
            && self.admin_contract_version == crate::RHI_ADMIN_CONTRACT_VERSION
            && self.status_contract_version == crate::RHI_STATUS_CONTRACT_VERSION
            && self.provider_contract_version == crate::RHI_PROVIDER_CONTRACT_VERSION
    }

    fn is_same_identity_and_policy_except_state_version(&self, other: &Self) -> bool {
        self.normalized_config_sha256 == other.normalized_config_sha256
            && self.evidence_policy_sha256 == other.evidence_policy_sha256
            && self.service_public_key == other.service_public_key
            && self.config_contract_version == other.config_contract_version
            && self.admin_contract_version == other.admin_contract_version
            && self.status_contract_version == other.status_contract_version
            && self.provider_contract_version == other.provider_contract_version
            && self.state_contract_version < other.state_contract_version
    }
}

impl From<&RhiStateMetadata> for ConfigBinding {
    fn from(metadata: &RhiStateMetadata) -> Self {
        let versions = metadata.policy_versions();
        Self {
            normalized_config_sha256: *metadata.configuration_digest().as_bytes(),
            evidence_policy_sha256: *metadata.evidence_policy_digest().as_bytes(),
            service_public_key: metadata.expected_identity().as_hex().into(),
            config_contract_version: versions.configuration(),
            state_contract_version: versions.state(),
            admin_contract_version: versions.admin(),
            status_contract_version: versions.status(),
            provider_contract_version: versions.provider(),
        }
    }
}

#[derive(Clone)]
struct HistoryEntry {
    generation: u16,
    binding: ConfigBinding,
    applied_at_unix_s: u64,
    build: MigrationBuildIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigOperationError {
    InvalidInput,
    Binding,
    ResourceExhausted,
    Storage,
}

pub(crate) async fn bind_or_verify(
    host: &RhiStateHost,
    expected: &RhiStateMetadata,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<(), RhiConfigApplyError> {
    let expected = ConfigBinding::from(expected);
    let build = build.clone();
    host.sqlite_host()
        .transaction(move |transaction| {
            Box::pin(async move {
                let mut history = read_history(transaction).await?;
                // Schema migration and the service-owned first binding cannot
                // share one transaction. Treat an empty append-only table as
                // an interrupted one-time initialization so a retry can
                // finish binding the admitted configuration. Once any row
                // exists, the table triggers make this path unreachable
                // without external database tampering.
                if history.is_empty() {
                    insert_binding(transaction, 1, &expected, applied_at.get(), &build).await?;
                    history = read_history(transaction).await?;
                }
                validate_history(&history)?;
                match history.last() {
                    Some(actual) if actual.binding == expected => Ok(()),
                    Some(actual)
                        if actual
                            .binding
                            .is_same_identity_and_policy_except_state_version(&expected) =>
                    {
                        if actual.generation >= RHI_CONFIG_BINDING_MAX_GENERATIONS {
                            return Err(ConfigOperationError::ResourceExhausted);
                        }
                        if applied_at.get() < actual.applied_at_unix_s {
                            return Err(ConfigOperationError::InvalidInput);
                        }
                        insert_binding(
                            transaction,
                            actual.generation + 1,
                            &expected,
                            applied_at.get(),
                            &build,
                        )
                        .await
                    }
                    Some(_) | None => Err(ConfigOperationError::Binding),
                }
            })
        })
        .await
        .map_err(map_transaction_error)
}

pub(crate) async fn verify_binding(
    host: &RhiStateHost,
    expected: &RhiStateMetadata,
) -> Result<(), RhiConfigApplyError> {
    let expected = ConfigBinding::from(expected);
    host.sqlite_host()
        .transaction(move |transaction| {
            Box::pin(async move {
                let history = read_history(transaction).await?;
                validate_history(&history)?;
                match history.last() {
                    Some(actual) if actual.binding == expected => Ok(()),
                    Some(_) | None => Err(ConfigOperationError::Binding),
                }
            })
        })
        .await
        .map_err(map_transaction_error)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn current_generation(host: &RhiStateHost) -> Result<u16, RhiConfigApplyError> {
    host.sqlite_host()
        .transaction(move |transaction| {
            Box::pin(async move {
                let history = read_history(transaction).await?;
                validate_history(&history)?;
                history
                    .last()
                    .map(|entry| entry.generation)
                    .ok_or(ConfigOperationError::Binding)
            })
        })
        .await
        .map_err(map_transaction_error)
}

pub(crate) async fn append_configuration(
    host: &RhiStateHost,
    current: &RhiStateMetadata,
    candidate: &RhiStateMetadata,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<RhiConfigApplyOutcome, RhiConfigApplyError> {
    let current = ConfigBinding::from(current);
    let candidate = ConfigBinding::from(candidate);
    let build = build.clone();
    host.sqlite_host()
        .transaction(move |transaction| {
            Box::pin(async move {
                let history = read_history(transaction).await?;
                validate_history(&history)?;
                let latest = history.last().ok_or(ConfigOperationError::Binding)?;
                if latest.binding != current {
                    return Err(ConfigOperationError::Binding);
                }
                if latest.binding == candidate {
                    return Ok(RhiConfigApplyOutcome {
                        generation: latest.generation,
                        changed: false,
                    });
                }
                if latest.generation >= RHI_CONFIG_BINDING_MAX_GENERATIONS {
                    return Err(ConfigOperationError::ResourceExhausted);
                }
                if applied_at.get() < latest.applied_at_unix_s {
                    return Err(ConfigOperationError::InvalidInput);
                }
                let generation = latest.generation + 1;
                if latest.binding.evidence_policy_sha256 != candidate.evidence_policy_sha256 {
                    advance_dirty_policy(
                        transaction,
                        candidate.evidence_policy_sha256,
                        applied_at.get(),
                    )
                    .await?;
                }
                insert_binding(
                    transaction,
                    generation,
                    &candidate,
                    applied_at.get(),
                    &build,
                )
                .await?;
                let updated = read_history(transaction).await?;
                validate_history(&updated)?;
                let actual = updated.last().ok_or(ConfigOperationError::Binding)?;
                if actual.generation != generation || actual.binding != candidate {
                    return Err(ConfigOperationError::Binding);
                }
                Ok(RhiConfigApplyOutcome {
                    generation,
                    changed: true,
                })
            })
        })
        .await
        .map_err(map_transaction_error)
}

async fn advance_dirty_policy(
    transaction: &mut ServiceSqliteTransaction<'_>,
    policy: [u8; 32],
    updated_at_unix_s: u64,
) -> Result<(), ConfigOperationError> {
    let row = sqlx::query(READ_DIRTY_POLICY_BOUNDS_SQL)
        .bind(policy.as_slice())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?;
    let exhausted = row
        .try_get::<i64, _>("exhausted")
        .map_err(|_| ConfigOperationError::Storage)?;
    let latest_updated_at = row
        .try_get::<i64, _>("latest_updated_at")
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ConfigOperationError::Storage)?;
    if exhausted != 0 {
        return Err(ConfigOperationError::ResourceExhausted);
    }
    if updated_at_unix_s < latest_updated_at {
        return Err(ConfigOperationError::InvalidInput);
    }
    sqlx::query(ADVANCE_DIRTY_POLICY_SQL)
        .bind(policy.as_slice())
        .bind(i64::try_from(updated_at_unix_s).map_err(|_| ConfigOperationError::InvalidInput)?)
        .bind(policy.as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?;
    Ok(())
}

async fn read_history(
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<Vec<HistoryEntry>, ConfigOperationError> {
    let rows = sqlx::query(READ_HISTORY_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?;
    if rows.len() > usize::from(RHI_CONFIG_BINDING_MAX_GENERATIONS) {
        return Err(ConfigOperationError::ResourceExhausted);
    }
    rows.into_iter().map(decode_entry).collect()
}

fn decode_entry(row: sqlx::sqlite::SqliteRow) -> Result<HistoryEntry, ConfigOperationError> {
    let generation = bounded_u16(&row, "generation", 1, RHI_CONFIG_BINDING_MAX_GENERATIONS)?;
    let normalized_config_sha256 = exact_digest(&row, "normalized_config_sha256")?;
    let evidence_policy_sha256 = exact_digest(&row, "evidence_policy_sha256")?;
    let service_public_key = bounded_text(&row, "service_public_key", 64, 64)?;
    if !service_public_key
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || nostr::PublicKey::from_hex(&service_public_key).is_err()
    {
        return Err(ConfigOperationError::Binding);
    }
    let config_contract_version = positive_u32(&row, "config_contract_version")?;
    let state_contract_version = positive_u32(&row, "state_contract_version")?;
    let admin_contract_version = positive_u32(&row, "admin_contract_version")?;
    let status_contract_version = positive_u32(&row, "status_contract_version")?;
    let provider_contract_version = positive_u32(&row, "provider_contract_version")?;
    let applied_at_unix_s = nonnegative_u64(&row, "applied_at_unix_s")?;
    let service_version = bounded_text(&row, "service_version", 1, 128)?;
    let service_commit = bounded_text(&row, "service_commit", 40, 40)?;
    let lib_revision = bounded_text(&row, "lib_revision", 40, 40)?;
    let rust_version = bounded_text(&row, "rust_version", 1, 128)?;
    let target = bounded_text(&row, "target", 1, 128)?;
    let feature_profile = bounded_text(&row, "feature_profile", 1, 128)?;
    let build = MigrationBuildIdentity::new(
        &*service_version,
        &*service_commit,
        &*lib_revision,
        &*rust_version,
        &*target,
        &*feature_profile,
        config_contract_version,
        state_contract_version,
        admin_contract_version,
        status_contract_version,
        provider_contract_version,
    )
    .map_err(|_| ConfigOperationError::Binding)?;
    Ok(HistoryEntry {
        generation,
        binding: ConfigBinding {
            normalized_config_sha256,
            evidence_policy_sha256,
            service_public_key,
            config_contract_version,
            state_contract_version,
            admin_contract_version,
            status_contract_version,
            provider_contract_version,
        },
        applied_at_unix_s,
        build,
    })
}

fn validate_history(history: &[HistoryEntry]) -> Result<(), ConfigOperationError> {
    let mut previous_time = 0;
    for (index, entry) in history.iter().enumerate() {
        if usize::from(entry.generation) != index + 1
            || entry.applied_at_unix_s < previous_time
            || !entry.binding.is_governed()
            || entry.build.config_contract_version() != entry.binding.config_contract_version
            || entry.build.state_contract_version() != entry.binding.state_contract_version
            || entry.build.admin_contract_version() != entry.binding.admin_contract_version
            || entry.build.status_contract_version() != entry.binding.status_contract_version
            || entry.build.provider_contract_version() != entry.binding.provider_contract_version
        {
            return Err(ConfigOperationError::Binding);
        }
        previous_time = entry.applied_at_unix_s;
    }
    Ok(())
}

async fn insert_binding(
    transaction: &mut ServiceSqliteTransaction<'_>,
    generation: u16,
    binding: &ConfigBinding,
    applied_at_unix_s: u64,
    build: &MigrationBuildIdentity,
) -> Result<(), ConfigOperationError> {
    sqlx::query(INSERT_BINDING_SQL)
        .bind(i64::from(generation))
        .bind(binding.normalized_config_sha256.as_slice())
        .bind(binding.evidence_policy_sha256.as_slice())
        .bind(binding.service_public_key.as_ref())
        .bind(i64::from(binding.config_contract_version))
        .bind(i64::from(binding.state_contract_version))
        .bind(i64::from(binding.admin_contract_version))
        .bind(i64::from(binding.status_contract_version))
        .bind(i64::from(binding.provider_contract_version))
        .bind(i64::try_from(applied_at_unix_s).map_err(|_| ConfigOperationError::InvalidInput)?)
        .bind(build.service_version())
        .bind(build.service_commit())
        .bind(build.lib_revision())
        .bind(build.rust_version())
        .bind(build.target())
        .bind(build.feature_profile())
        .execute(&mut *transaction)
        .await
        .map_err(|_| ConfigOperationError::Storage)?;
    Ok(())
}

fn exact_digest(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
) -> Result<[u8; 32], ConfigOperationError> {
    let value = row
        .try_get::<Vec<u8>, _>(field)
        .map_err(|_| ConfigOperationError::Binding)?;
    value.try_into().map_err(|_| ConfigOperationError::Binding)
}

fn bounded_text(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Box<str>, ConfigOperationError> {
    let length_field = format!("{field}_bytes");
    let length = row
        .try_get::<i64, _>(length_field.as_str())
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or(ConfigOperationError::Binding)?;
    let value = row
        .try_get::<String, _>(field)
        .map_err(|_| ConfigOperationError::Binding)?;
    if value.len() != length {
        return Err(ConfigOperationError::Binding);
    }
    Ok(value.into_boxed_str())
}

fn bounded_u16(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    minimum: u16,
    maximum: u16,
) -> Result<u16, ConfigOperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or(ConfigOperationError::Binding)
}

fn positive_u32(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<u32, ConfigOperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or(ConfigOperationError::Binding)
}

fn nonnegative_u64(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
) -> Result<u64, ConfigOperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ConfigOperationError::Binding)
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<ConfigOperationError>,
) -> RhiConfigApplyError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return RhiConfigApplyError::new(RhiConfigApplyErrorKind::CommitOutcomeUnknown);
    }
    let kind = match error.operation_error().copied() {
        Some(ConfigOperationError::InvalidInput) => RhiConfigApplyErrorKind::InvalidInput,
        Some(ConfigOperationError::Binding) => RhiConfigApplyErrorKind::Binding,
        Some(ConfigOperationError::ResourceExhausted) => RhiConfigApplyErrorKind::ResourceExhausted,
        Some(ConfigOperationError::Storage) | None => RhiConfigApplyErrorKind::Transaction,
    };
    RhiConfigApplyError::new(kind)
}

pub(crate) fn metadata_for_configuration(
    runtime: &crate::RhiRuntimeContext,
    configuration: &RhiConfigDocumentV1,
    actual: &radroots_service_sqlite::ServiceDatabaseMetadata,
) -> Result<RhiStateMetadata, RhiConfigApplyError> {
    RhiStateMetadata::from_existing_database(runtime, configuration, actual)
        .map_err(|_| RhiConfigApplyError::new(RhiConfigApplyErrorKind::InvalidInput))
}
