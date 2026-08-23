//! RHI-bound integrity, backup, and offline restore integration.

use core::{fmt, num::NonZeroU64};
use std::{error::Error, path::Path};

use radroots_service_sqlite::{
    BackupManifestSha256, ServiceBackupManifest, ServiceDatabaseMetadata, ServiceSqliteError,
    ServiceSqliteErrorKind, StagedServiceRestore, VerifiedServiceBackup, finalize_staged_restore,
    stage_verified_restore, verify_backup_bundle,
};

use crate::{RhiRuntimeContext, RhiStateMetadata, state_host};

/// Stable source-free class for an RHI state-maintenance failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiStateMaintenanceErrorKind {
    InvalidEvidence,
    InvalidMode,
    Catalog,
    Authority,
    Open,
    Metadata,
    Migration,
    Backup,
    Restore,
    Integrity,
    Recovery,
}

impl RhiStateMaintenanceErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEvidence => "state_maintenance_evidence_invalid",
            Self::InvalidMode => "state_maintenance_mode_invalid",
            Self::Catalog => "state_maintenance_catalog_invalid",
            Self::Authority => "state_maintenance_authority_failed",
            Self::Open => "state_maintenance_open_failed",
            Self::Metadata => "state_maintenance_metadata_invalid",
            Self::Migration => "state_maintenance_migration_invalid",
            Self::Backup => "state_backup_failed",
            Self::Restore => "state_restore_failed",
            Self::Integrity => "state_integrity_failed",
            Self::Recovery => "state_recovery_failed",
        }
    }
}

/// Redacted RHI state-maintenance failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiStateMaintenanceError {
    kind: RhiStateMaintenanceErrorKind,
}

impl RhiStateMaintenanceError {
    pub(crate) const fn new(kind: RhiStateMaintenanceErrorKind) -> Self {
        Self { kind }
    }

    pub(crate) fn from_sqlite(error: ServiceSqliteError) -> Self {
        let kind = match error.kind() {
            ServiceSqliteErrorKind::Authority => RhiStateMaintenanceErrorKind::Authority,
            ServiceSqliteErrorKind::Open
            | ServiceSqliteErrorKind::Create
            | ServiceSqliteErrorKind::Pragma => RhiStateMaintenanceErrorKind::Open,
            ServiceSqliteErrorKind::Metadata => RhiStateMaintenanceErrorKind::Metadata,
            ServiceSqliteErrorKind::Migration => RhiStateMaintenanceErrorKind::Migration,
            ServiceSqliteErrorKind::Backup => RhiStateMaintenanceErrorKind::Backup,
            ServiceSqliteErrorKind::Restore => RhiStateMaintenanceErrorKind::Restore,
            ServiceSqliteErrorKind::Integrity => RhiStateMaintenanceErrorKind::Integrity,
            ServiceSqliteErrorKind::Recovery => RhiStateMaintenanceErrorKind::Recovery,
        };
        Self::new(kind)
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiStateMaintenanceErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiStateMaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiStateMaintenanceErrorKind::InvalidEvidence => {
                "RHI state maintenance evidence is invalid"
            }
            RhiStateMaintenanceErrorKind::InvalidMode => {
                "RHI state maintenance is unavailable in this host mode"
            }
            RhiStateMaintenanceErrorKind::Catalog => "RHI state catalogs are invalid",
            RhiStateMaintenanceErrorKind::Authority => {
                "RHI state maintenance authority could not be established"
            }
            RhiStateMaintenanceErrorKind::Open => "RHI state maintenance could not open state",
            RhiStateMaintenanceErrorKind::Metadata => "RHI state metadata is invalid",
            RhiStateMaintenanceErrorKind::Migration => "RHI state migration history is invalid",
            RhiStateMaintenanceErrorKind::Backup => "RHI state backup failed",
            RhiStateMaintenanceErrorKind::Restore => "RHI state restore failed",
            RhiStateMaintenanceErrorKind::Integrity => "RHI state integrity check failed",
            RhiStateMaintenanceErrorKind::Recovery => "RHI state recovery failed",
        })
    }
}

impl fmt::Debug for RhiStateMaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStateMaintenanceError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiStateMaintenanceError {}

/// Retained exact-inode proof of one verified RHI backup.
///
/// Construction is sealed to [`verify_rhi_state_backup`]. No raw descriptor or
/// pathname is exposed.
///
/// ```compile_fail
/// use rhi::RhiVerifiedStateBackup;
/// let _ = RhiVerifiedStateBackup { inner: todo!() };
/// ```
pub struct RhiVerifiedStateBackup {
    inner: VerifiedServiceBackup,
}

impl RhiVerifiedStateBackup {
    /// Returns the admitted canonical manifest.
    #[must_use]
    pub const fn manifest(&self) -> &ServiceBackupManifest {
        self.inner.manifest()
    }

    /// Returns the actual immutable database metadata read from the retained member.
    #[must_use]
    pub const fn database_metadata(&self) -> &ServiceDatabaseMetadata {
        self.inner.database_metadata()
    }
}

impl fmt::Debug for RhiVerifiedStateBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiVerifiedStateBackup([redacted])")
    }
}

/// Offline staged RHI replacement that retains exclusive writer authority.
///
/// Construction is sealed to [`stage_rhi_state_restore`]. Dropping this value
/// preserves the shared exact-inode cleanup and fail-closed evidence contract.
///
/// ```compile_fail
/// use rhi::RhiStagedStateRestore;
/// let _ = RhiStagedStateRestore { inner: todo!() };
/// ```
pub struct RhiStagedStateRestore {
    inner: StagedServiceRestore,
}

impl fmt::Debug for RhiStagedStateRestore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiStagedStateRestore([redacted])")
    }
}

/// Verifies an untrusted backup bundle against one sealed RHI state identity.
pub fn verify_rhi_state_backup(
    manifest_bytes: &[u8],
    expected_manifest_digest: BackupManifestSha256,
    bundle_directory: &Path,
    expected: &RhiStateMetadata,
    maximum_state_bytes: NonZeroU64,
) -> Result<RhiVerifiedStateBackup, RhiStateMaintenanceError> {
    verify_backup_bundle(
        manifest_bytes,
        expected_manifest_digest,
        bundle_directory,
        &expected.database_identity(),
        maximum_state_bytes,
    )
    .map(|inner| RhiVerifiedStateBackup { inner })
    .map_err(RhiStateMaintenanceError::from_sqlite)
}

/// Copies and completely reverifies a verified backup beside closed RHI state.
///
/// This operation acquires exclusive writer authority. It never creates a
/// recovery marker or replaces the live database.
pub async fn stage_rhi_state_restore(
    runtime: &RhiRuntimeContext,
    expected: &RhiStateMetadata,
    verified: RhiVerifiedStateBackup,
) -> Result<RhiStagedStateRestore, RhiStateMaintenanceError> {
    state_host::require_metadata(runtime, expected).map_err(|_| {
        RhiStateMaintenanceError::new(RhiStateMaintenanceErrorKind::InvalidEvidence)
    })?;
    let paths = state_host::state_paths(runtime).map_err(|_| {
        RhiStateMaintenanceError::new(RhiStateMaintenanceErrorKind::InvalidEvidence)
    })?;
    let (migrations, schema) = state_host::catalogs()
        .map_err(|_| RhiStateMaintenanceError::new(RhiStateMaintenanceErrorKind::Catalog))?;
    stage_verified_restore(
        &paths,
        &expected.database_identity(),
        &migrations,
        &schema,
        verified.inner,
    )
    .await
    .map(|inner| RhiStagedStateRestore { inner })
    .map_err(RhiStateMaintenanceError::from_sqlite)
}

/// Atomically installs a completely verified staged RHI restore.
///
/// Success intentionally returns no open host. The next writable open owns
/// exact recovery-evidence reconciliation before SQLite is exposed again.
pub async fn finalize_rhi_state_restore(
    staged: RhiStagedStateRestore,
) -> Result<(), RhiStateMaintenanceError> {
    finalize_staged_restore(staged.inner)
        .await
        .map_err(RhiStateMaintenanceError::from_sqlite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_failures_map_to_the_closed_source_free_rhi_vocabulary() {
        for (source, expected) in [
            (
                ServiceSqliteErrorKind::Authority,
                RhiStateMaintenanceErrorKind::Authority,
            ),
            (
                ServiceSqliteErrorKind::Open,
                RhiStateMaintenanceErrorKind::Open,
            ),
            (
                ServiceSqliteErrorKind::Create,
                RhiStateMaintenanceErrorKind::Open,
            ),
            (
                ServiceSqliteErrorKind::Pragma,
                RhiStateMaintenanceErrorKind::Open,
            ),
            (
                ServiceSqliteErrorKind::Metadata,
                RhiStateMaintenanceErrorKind::Metadata,
            ),
            (
                ServiceSqliteErrorKind::Migration,
                RhiStateMaintenanceErrorKind::Migration,
            ),
            (
                ServiceSqliteErrorKind::Backup,
                RhiStateMaintenanceErrorKind::Backup,
            ),
            (
                ServiceSqliteErrorKind::Restore,
                RhiStateMaintenanceErrorKind::Restore,
            ),
            (
                ServiceSqliteErrorKind::Integrity,
                RhiStateMaintenanceErrorKind::Integrity,
            ),
            (
                ServiceSqliteErrorKind::Recovery,
                RhiStateMaintenanceErrorKind::Recovery,
            ),
        ] {
            let mapped = RhiStateMaintenanceError::from_sqlite(ServiceSqliteError::with_source(
                source,
                SensitiveSource,
            ));
            assert_eq!(mapped.kind(), expected);
            assert!(Error::source(&mapped).is_none());
            let rendered = format!("{mapped} {mapped:?}");
            assert!(!rendered.contains("sensitive"));
            assert!(!mapped.code().is_empty());
        }
    }

    #[derive(Debug)]
    struct SensitiveSource;

    impl fmt::Display for SensitiveSource {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("sensitive /tmp/state.sqlite")
        }
    }

    impl Error for SensitiveSource {}
}
