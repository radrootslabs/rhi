//! Sealed lifecycle boundary for the canonical RHI SQLite state catalog.

use core::fmt;
use std::{error::Error, path::PathBuf};

use radroots_service_sqlite::{
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, OpenMode,
    ServiceSqliteConnectionOptions, ServiceSqliteHost, ServiceSqlitePaths, initialize_database,
};
use sqlx::{ConnectOptions, Connection, SqliteConnection, sqlite::SqliteConnectOptions};

use crate::{
    RHI_STATE_SCHEMA_VERSION, RhiRuntimeContext, RhiStateMetadata, rhi_migration_catalog,
    rhi_schema_catalog, validate_rhi_state_catalogs,
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
/// injects the shared metadata evidence; Step 171 owns its exact RHI application,
/// configuration, evidence-policy, identity, and contract-version bindings.
pub async fn initialize_rhi_state(
    runtime: &RhiRuntimeContext,
    metadata: &RhiStateMetadata,
) -> Result<(), RhiStateHostError> {
    let paths = state_paths(runtime)?;
    require_metadata(runtime, metadata)?;
    let (migrations, schema) = catalogs()?;
    let mut authority = initialize_database(
        &paths,
        OpenMode::Initialize,
        metadata.database(),
        &schema,
        initialize_empty_catalog,
    )
    .await
    .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Initialize))?;
    authority
        .release()
        .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::Initialize))?;
    drop(migrations);
    Ok(())
}

/// Opens an already initialized RHI catalog with exclusive writer authority.
///
/// Missing state is never created. Migration time and build identity remain
/// explicit injected evidence even while the baseline migration catalog is
/// empty.
pub async fn open_rhi_state_read_write(
    runtime: &RhiRuntimeContext,
    metadata: &RhiStateMetadata,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<RhiStateHost, RhiStateHostError> {
    let paths = state_paths(runtime)?;
    require_metadata(runtime, metadata)?;
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
    if outcome.initial_version() != RHI_STATE_SCHEMA_VERSION
        || outcome.final_version() != RHI_STATE_SCHEMA_VERSION
        || outcome.applied_count() != 0
    {
        let _ = host.close().await;
        return Err(RhiStateHostError::new(RhiStateHostErrorKind::Catalog));
    }
    Ok(RhiStateHost {
        host,
        mode: RhiStateHostMode::ReadWriteExisting,
        metadata: metadata.clone(),
    })
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
    Ok(RhiStateHost {
        host,
        mode: RhiStateHostMode::ReadOnlyInspection,
        metadata: metadata.clone(),
    })
}

fn state_paths(runtime: &RhiRuntimeContext) -> Result<ServiceSqlitePaths, RhiStateHostError> {
    ServiceSqlitePaths::from_runtime_context(runtime.context())
        .map_err(|_| RhiStateHostError::new(RhiStateHostErrorKind::InvalidPaths))
}

fn require_metadata(
    runtime: &RhiRuntimeContext,
    metadata: &RhiStateMetadata,
) -> Result<(), RhiStateHostError> {
    let database = metadata.database();
    let matches = metadata.matches_runtime(runtime)
        && database.service() == runtime.context().service()
        && database.instance() == runtime.context().instance()
        && database.state_schema_version().get() == RHI_STATE_SCHEMA_VERSION;
    matches
        .then_some(())
        .ok_or_else(|| RhiStateHostError::new(RhiStateHostErrorKind::InvalidEvidence))
}

fn catalogs() -> Result<
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
