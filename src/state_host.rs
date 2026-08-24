//! Sealed lifecycle boundary for the canonical RHI SQLite state catalog.

use core::fmt;
use std::{
    error::Error,
    path::{Path, PathBuf},
};

use radroots_service_sqlite::{
    BackupCreatedAtUnixMs, ExistingServiceDatabaseIntent, IntegrityCheckedAtUnixMs,
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, OpenMode, ServiceBackupManifest,
    ServiceSqliteApplicationId, ServiceSqliteConnectionOptions, ServiceSqliteHost,
    ServiceSqliteIntegrityReport, ServiceSqlitePaths, initialize_database,
};
use sqlx::{ConnectOptions, Connection, SqliteConnection, sqlite::SqliteConnectOptions};

use crate::{
    RHI_STATE_APPLICATION_ID, RHI_STATE_BASE_SCHEMA_VERSION, RHI_STATE_SCHEMA_VERSION,
    RhiConfigApplyError, RhiConfigApplyErrorKind, RhiConfigApplyOutcome, RhiConfigDocumentV1,
    RhiRuntimeContext, RhiStateMaintenanceError, RhiStateMaintenanceErrorKind, RhiStateMetadata,
    RhiStateRepositories, rhi_migration_catalog, rhi_schema_catalog, state_config,
    validate_rhi_state_catalogs,
};

/// Stable lifecycle mode of one opened RHI state host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiStateHostMode {
    ReadWriteExisting,
    ReadOnlyInspection,
}

/// Stable source-free class for an RHI state-host lifecycle failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiStateHostErrorKind {
    InvalidPaths,
    InvalidEvidence,
    Catalog,
    Initialize,
    ReadWriteOpen,
    InspectionOpen,
    Close,
}

impl RhiStateHostErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidPaths => "state_paths_invalid",
            Self::InvalidEvidence => "state_evidence_invalid",
            Self::Catalog => "state_catalog_invalid",
            Self::Initialize => "state_initialize_failed",
            Self::ReadWriteOpen => "state_read_write_open_failed",
            Self::InspectionOpen => "state_inspection_open_failed",
            Self::Close => "state_close_failed",
        }
    }
}

/// Redacted RHI state-host lifecycle failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiStateHostError {
    kind: RhiStateHostErrorKind,
}

impl RhiStateHostError {
    const fn new(kind: RhiStateHostErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiStateHostErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiStateHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiStateHostErrorKind::InvalidPaths => "RHI state paths are invalid",
            RhiStateHostErrorKind::InvalidEvidence => "RHI state identity evidence is invalid",
            RhiStateHostErrorKind::Catalog => "RHI state catalogs are invalid",
            RhiStateHostErrorKind::Initialize => "RHI state initialization failed",
            RhiStateHostErrorKind::ReadWriteOpen => "RHI writable state could not be opened",
            RhiStateHostErrorKind::InspectionOpen => "RHI inspection state could not be opened",
            RhiStateHostErrorKind::Close => "RHI state host could not be closed",
        })
    }
}

impl fmt::Debug for RhiStateHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStateHostError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiStateHostError {}

/// One opened RHI state catalog whose raw SQLite authority remains sealed.
///
/// Callers cannot construct the wrapper or extract the shared host:
///
/// ```compile_fail
/// use rhi::{RhiStateHost, RhiStateHostMode};
///
/// let _ = RhiStateHost {
///     host: todo!(),
///     mode: RhiStateHostMode::ReadWriteExisting,
/// };
/// ```
///
/// The wrapper intentionally exposes no transaction or connection escape:
///
/// ```compile_fail
/// use rhi::RhiStateHost;
///
/// fn bypass(host: &RhiStateHost) {
///     let _ = host.transaction(|_| async { Ok::<_, ()>(()) });
/// }
/// ```
pub struct RhiStateHost {
    host: ServiceSqliteHost,
    mode: RhiStateHostMode,
    metadata: RhiStateMetadata,
}

impl RhiStateHost {
    pub(crate) const fn sqlite_host(&self) -> &ServiceSqliteHost {
        &self.host
    }
    /// Returns the lifecycle mode selected when this host was opened.
    #[must_use]
    pub const fn mode(&self) -> RhiStateHostMode {
        self.mode
    }

    /// Returns the immutable RHI metadata bound to this host session.
    #[must_use]
    pub const fn metadata(&self) -> &RhiStateMetadata {
        &self.metadata
    }

    /// Returns the sealed family of typed repository capabilities.
    #[must_use]
    pub const fn repositories(&self) -> RhiStateRepositories<'_> {
        RhiStateRepositories::new(self)
    }

    /// Captures one governed point-in-time backup from a writable RHI host.
    ///
    /// The staging directory must be a new absolute path. The returned
    /// manifest remains in memory and contains no protected identity material.
    pub async fn capture_online_backup(
        &self,
        staging_directory: &Path,
        created_at: BackupCreatedAtUnixMs,
    ) -> Result<ServiceBackupManifest, RhiStateMaintenanceError> {
        if self.mode != RhiStateHostMode::ReadWriteExisting {
            return Err(RhiStateMaintenanceError::new(
                RhiStateMaintenanceErrorKind::InvalidMode,
            ));
        }
        self.host
            .capture_online_backup(staging_directory, created_at)
            .await
            .map_err(RhiStateMaintenanceError::from_sqlite)
    }

    /// Runs one explicit bounded integrity inspection over this host.
    pub async fn inspect_integrity(
        &self,
        checked_at: IntegrityCheckedAtUnixMs,
    ) -> Result<ServiceSqliteIntegrityReport, RhiStateMaintenanceError> {
        self.host
            .inspect_integrity(checked_at)
            .await
            .map_err(RhiStateMaintenanceError::from_sqlite)
    }

    /// Drains the shared host and explicitly releases retained authority.
    pub async fn close(&self) -> Result<(), RhiStateHostError> {
        self.host
            .close()
            .await
            .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Close))
    }
}

impl fmt::Debug for RhiStateHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStateHost")
            .field("mode", &self.mode)
            .field("state", &"[sealed]")
            .finish()
    }
}

/// Creates a missing RHI catalog exactly once and releases initialization authority.
///
/// This function never opens an existing database as initialization. The caller
/// injects the shared metadata and migration evidence. Contract versions are
/// cross-bound before database I/O, and all governed migrations are applied by
/// the shared host before initialization authority is explicitly released.
pub async fn initialize_rhi_state(
    runtime: &RhiRuntimeContext,
    metadata: &RhiStateMetadata,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<(), RhiStateHostError> {
    let paths = state_paths(runtime)?;
    require_metadata(runtime, metadata)?;
    require_migration_build(metadata, build)?;
    let (migrations, schema) = catalogs()?;
    let authority = initialize_database(
        &paths,
        OpenMode::Initialize,
        metadata.initial_database_metadata(),
        &schema,
        initialize_empty_catalog,
    )
    .await
    .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Initialize))?;
    let identity = metadata.database_identity();
    let (host, outcome) = ServiceSqliteHost::open_initialized(
        &paths,
        &identity,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
        authority,
        applied_at,
        build,
        &[],
    )
    .await
    .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Initialize))?;
    if !exact_migration_outcome(outcome) {
        return Err(close_error(&host, RhiStateHostErrorKind::Catalog).await);
    }
    let state = RhiStateHost {
        host,
        mode: RhiStateHostMode::ReadWriteExisting,
        metadata: metadata.clone(),
    };
    if state_config::bind_or_verify(&state, metadata, applied_at, build)
        .await
        .is_err()
    {
        return Err(close_error(&state.host, RhiStateHostErrorKind::Initialize).await);
    }
    state
        .close()
        .await
        .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Initialize))
}

/// Opens an already initialized RHI catalog with exclusive writer authority.
///
/// Missing state is never created. Migration time and build identity remain
/// explicit injected evidence for every governed migration or exact-current
/// reopen.
pub async fn open_rhi_state_read_write(
    runtime: &RhiRuntimeContext,
    metadata: &RhiStateMetadata,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<RhiStateHost, RhiStateHostError> {
    let paths = state_paths(runtime)?;
    require_metadata(runtime, metadata)?;
    require_migration_build(metadata, build)?;
    let identity = metadata.database_identity();
    let (migrations, schema) = catalogs()?;
    let (host, outcome) = ServiceSqliteHost::open_read_write_existing(
        &paths,
        &identity,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
        applied_at,
        build,
        &[],
    )
    .await
    .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::ReadWriteOpen))?;
    if !exact_migration_outcome(outcome) {
        return Err(close_error(&host, RhiStateHostErrorKind::Catalog).await);
    }
    let state = RhiStateHost {
        host,
        mode: RhiStateHostMode::ReadWriteExisting,
        metadata: metadata.clone(),
    };
    if state_config::bind_or_verify(&state, metadata, applied_at, build)
        .await
        .is_err()
    {
        return Err(close_error(&state.host, RhiStateHostErrorKind::InvalidEvidence).await);
    }
    Ok(state)
}

/// Opens existing RHI state from configuration intent and discovers source identity.
///
/// Missing state is never created. Source generation and database creation time
/// are read under the same retained writer authority returned in the host.
pub async fn open_rhi_state_read_write_from_config(
    runtime: &RhiRuntimeContext,
    configuration: &RhiConfigDocumentV1,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<RhiStateHost, RhiStateHostError> {
    let paths = state_paths(runtime)?;
    let intent = existing_intent(&paths)?;
    let (migrations, schema) = catalogs()?;
    let (opened, outcome) = ServiceSqliteHost::open_read_write_existing_with_intent(
        &paths,
        &intent,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
        applied_at,
        build,
        &[],
    )
    .await
    .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::ReadWriteOpen))?;
    if !exact_migration_outcome(outcome) {
        let (host, _) = opened.into_parts();
        return Err(close_error(&host, RhiStateHostErrorKind::Catalog).await);
    }
    let (host, actual) = opened.into_parts();
    let metadata = match RhiStateMetadata::from_existing_database(runtime, configuration, &actual) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Err(close_error(&host, RhiStateHostErrorKind::InvalidEvidence).await);
        }
    };
    if require_migration_build(&metadata, build).is_err() {
        return Err(close_error(&host, RhiStateHostErrorKind::InvalidEvidence).await);
    }
    let state = RhiStateHost {
        host,
        mode: RhiStateHostMode::ReadWriteExisting,
        metadata,
    };
    if state_config::bind_or_verify(&state, state.metadata(), applied_at, build)
        .await
        .is_err()
    {
        return Err(close_error(&state.host, RhiStateHostErrorKind::InvalidEvidence).await);
    }
    Ok(state)
}

/// Applies one admitted RHI configuration while the service is offline.
///
/// The function obtains exclusive writer authority, verifies the current
/// durable binding, appends only bounded digest/public-identity/build evidence,
/// and explicitly closes state before returning. It never stores raw TOML,
/// paths, URLs, credential references, or protected identity material.
pub async fn apply_rhi_configuration(
    runtime: &RhiRuntimeContext,
    current: &RhiConfigDocumentV1,
    candidate: &RhiConfigDocumentV1,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<RhiConfigApplyOutcome, RhiConfigApplyError> {
    let state = open_rhi_state_read_write_from_config(runtime, current, applied_at, build)
        .await
        .map_err(|_| RhiConfigApplyError::new(RhiConfigApplyErrorKind::Binding))?;
    let candidate_metadata = match state_config::metadata_for_configuration(
        runtime,
        candidate,
        state.metadata().initial_database_metadata(),
    ) {
        Ok(metadata) => metadata,
        Err(error) => return Err(close_apply_error(&state, error.kind()).await),
    };
    if require_migration_build(&candidate_metadata, build).is_err() {
        return Err(close_apply_error(&state, RhiConfigApplyErrorKind::InvalidInput).await);
    }
    let outcome = state_config::append_configuration(
        &state,
        state.metadata(),
        &candidate_metadata,
        applied_at,
        build,
    )
    .await;
    let closed = state.close().await;
    if closed.is_err() {
        Err(RhiConfigApplyError::new(RhiConfigApplyErrorKind::Close))
    } else {
        outcome
    }
}

async fn close_apply_error(
    state: &RhiStateHost,
    fallback: RhiConfigApplyErrorKind,
) -> RhiConfigApplyError {
    if state.close().await.is_err() {
        RhiConfigApplyError::new(RhiConfigApplyErrorKind::Close)
    } else {
        RhiConfigApplyError::new(fallback)
    }
}

/// Opens an already initialized RHI catalog for immutable inspection.
pub async fn open_rhi_state_inspection(
    runtime: &RhiRuntimeContext,
    metadata: &RhiStateMetadata,
) -> Result<RhiStateHost, RhiStateHostError> {
    let paths = state_paths(runtime)?;
    require_metadata(runtime, metadata)?;
    let identity = metadata.database_identity();
    let (migrations, schema) = catalogs()?;
    let host = ServiceSqliteHost::open_read_only_inspection(
        &paths,
        &identity,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
    )
    .await
    .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::InspectionOpen))?;
    let state = RhiStateHost {
        host,
        mode: RhiStateHostMode::ReadOnlyInspection,
        metadata: metadata.clone(),
    };
    if state_config::verify_binding(&state, metadata)
        .await
        .is_err()
    {
        return Err(close_error(&state.host, RhiStateHostErrorKind::InvalidEvidence).await);
    }
    Ok(state)
}

/// Opens existing inspection state from a sealed intent and actual metadata.
pub async fn open_rhi_state_inspection_from_config(
    runtime: &RhiRuntimeContext,
    configuration: &RhiConfigDocumentV1,
) -> Result<RhiStateHost, RhiStateHostError> {
    let paths = state_paths(runtime)?;
    let (migrations, schema) = catalogs()?;
    let intent = existing_intent(&paths)?;
    let opened = ServiceSqliteHost::open_read_only_inspection_with_intent(
        &paths,
        &intent,
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
    )
    .await
    .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::InspectionOpen))?;
    let (host, actual) = opened.into_parts();
    let metadata = match RhiStateMetadata::from_existing_database(runtime, configuration, &actual) {
        Ok(metadata) => metadata,
        Err(_) => {
            return Err(close_error(&host, RhiStateHostErrorKind::InvalidEvidence).await);
        }
    };
    let state = RhiStateHost {
        host,
        mode: RhiStateHostMode::ReadOnlyInspection,
        metadata,
    };
    if state_config::verify_binding(&state, state.metadata())
        .await
        .is_err()
    {
        return Err(close_error(&state.host, RhiStateHostErrorKind::InvalidEvidence).await);
    }
    Ok(state)
}

pub(crate) fn state_paths(
    runtime: &RhiRuntimeContext,
) -> Result<ServiceSqlitePaths, RhiStateHostError> {
    ServiceSqlitePaths::from_runtime_context(runtime.context())
        .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::InvalidPaths))
}

pub(crate) fn require_metadata(
    runtime: &RhiRuntimeContext,
    metadata: &RhiStateMetadata,
) -> Result<(), RhiStateHostError> {
    let database = metadata.database();
    let matches = metadata.matches_runtime(runtime)
        && database.service() == runtime.context().service()
        && database.instance() == runtime.context().instance()
        && database.state_schema_version().get() == RHI_STATE_BASE_SCHEMA_VERSION
        && metadata
            .database_identity()
            .supported_state_schema_version()
            .get()
            == RHI_STATE_SCHEMA_VERSION;
    matches
        .then_some(())
        .ok_or_else(|| RhiStateHostError::new(RhiStateHostErrorKind::InvalidEvidence))
}

fn require_migration_build(
    metadata: &RhiStateMetadata,
    build: &MigrationBuildIdentity,
) -> Result<(), RhiStateHostError> {
    let versions = metadata.policy_versions();
    let matches = build.config_contract_version() == versions.configuration()
        && build.state_contract_version() == versions.state()
        && build.admin_contract_version() == versions.admin()
        && build.status_contract_version() == versions.status()
        && build.provider_contract_version() == versions.provider();
    matches
        .then_some(())
        .ok_or_else(|| RhiStateHostError::new(RhiStateHostErrorKind::InvalidEvidence))
}

fn exact_migration_outcome(outcome: radroots_service_sqlite::MigrationApplicationOutcome) -> bool {
    (RHI_STATE_BASE_SCHEMA_VERSION..=RHI_STATE_SCHEMA_VERSION).contains(&outcome.initial_version())
        && outcome.final_version() == RHI_STATE_SCHEMA_VERSION
        && outcome.applied_count() == RHI_STATE_SCHEMA_VERSION - outcome.initial_version()
}

fn existing_intent(
    paths: &ServiceSqlitePaths,
) -> Result<ExistingServiceDatabaseIntent, RhiStateHostError> {
    let version = core::num::NonZeroU32::new(RHI_STATE_SCHEMA_VERSION)
        .ok_or_else(|| RhiStateHostError::new(RhiStateHostErrorKind::Catalog))?;
    let application = ServiceSqliteApplicationId::new(RHI_STATE_APPLICATION_ID)
        .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Catalog))?;
    Ok(ExistingServiceDatabaseIntent::new(
        paths,
        version,
        application,
    ))
}

async fn close_error(
    host: &ServiceSqliteHost,
    fallback: RhiStateHostErrorKind,
) -> RhiStateHostError {
    if host.close().await.is_err() {
        RhiStateHostError::new(RhiStateHostErrorKind::Close)
    } else {
        RhiStateHostError::new(fallback)
    }
}

pub(crate) fn catalogs() -> Result<
    (
        radroots_service_sqlite::MigrationCatalog,
        radroots_service_sqlite::SchemaCatalog,
    ),
    RhiStateHostError,
> {
    let migrations = rhi_migration_catalog()
        .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Catalog))?;
    let schema =
        rhi_schema_catalog().map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Catalog))?;
    validate_rhi_state_catalogs(&migrations, &schema)
        .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Catalog))?;
    Ok((migrations, schema))
}

#[derive(Debug)]
struct EmptyCatalogInitializationError;

impl fmt::Display for EmptyCatalogInitializationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RHI baseline database reservation could not be opened")
    }
}

impl Error for EmptyCatalogInitializationError {}

async fn initialize_empty_catalog(path: PathBuf) -> Result<(), EmptyCatalogInitializationError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .disable_statement_logging();
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|_| EmptyCatalogInitializationError)?;
    connection
        .close()
        .await
        .map_err(|_| EmptyCatalogInitializationError)
}
