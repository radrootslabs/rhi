#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiConfigProfile,
    RhiStateHostErrorKind, RhiStateHostMode, RhiStateMetadata, RhiStateRepositoryKind,
    initialize_rhi_state, open_rhi_state_inspection, open_rhi_state_read_write,
    parse_rhi_cli_v1_from, parse_rhi_config_v1, resolve_rhi_runtime_context,
};

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

const HOST_SOURCE: &str = include_str!("../src/state_host.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");

fn runtime(root: &Path, instance: &str) -> rhi::RhiRuntimeContext {
    let root = root.to_str().expect("UTF-8 temporary root");
    let invocation = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        "repo-local",
        "--instance",
        instance,
        "--repo-local-root",
        root,
        "run",
    ])
    .expect("valid test invocation");
    resolve_rhi_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context")
}

fn prepare_state_directory(runtime: &rhi::RhiRuntimeContext) {
    let directory = runtime.context().paths().state();
    fs::create_dir_all(directory).expect("state directory");
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("state mode");
}

fn metadata(runtime: &rhi::RhiRuntimeContext) -> RhiStateMetadata {
    let configuration = parse_rhi_config_v1(EXAMPLE.as_bytes(), RhiConfigProfile::RepoLocal)
        .expect("configuration");
    RhiStateMetadata::new(
        runtime,
        &configuration,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata")
}

fn migration_evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    let applied_at = MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("migration time");
    let build = MigrationBuildIdentity::new(
        env!("CARGO_PKG_VERSION"),
        "1111111111111111111111111111111111111111",
        "21b11e7a5120ea949f7ad0838c746873fc73aac2",
        "rustc-test",
        "test-target",
        "service-host",
        1,
        rhi::RHI_STATE_SCHEMA_VERSION,
        1,
        1,
        1,
    )
    .expect("build identity");
    (applied_at, build)
}

#[tokio::test]
async fn initialize_is_create_new_and_both_existing_open_modes_close_explicitly() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "primary");
    prepare_state_directory(&runtime);
    let metadata = metadata(&runtime);
    let state = runtime.artifacts().state_database();
    let lock = runtime.artifacts().state_lock();

    assert!(!state.exists());
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("create-new initialization");
    assert!(state.is_file());
    assert!(lock.is_file());
    assert_eq!(
        fs::metadata(state).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(lock).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let duplicate = initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect_err("second initialization must fail");
    assert_eq!(duplicate.kind(), RhiStateHostErrorKind::Initialize);

    let writer = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("existing writable state");
    assert_eq!(writer.mode(), RhiStateHostMode::ReadWriteExisting);
    assert_eq!(
        format!("{writer:?}"),
        "RhiStateHost { mode: ReadWriteExisting, state: \"[sealed]\" }"
    );

    let contended = open_rhi_state_inspection(&runtime, &metadata)
        .await
        .expect_err("inspection must not bypass active writer authority");
    assert_eq!(contended.kind(), RhiStateHostErrorKind::InspectionOpen);
    writer.close().await.expect("writer close");
    writer.close().await.expect("idempotent writer close");

    let inspection = open_rhi_state_inspection(&runtime, &metadata)
        .await
        .expect("existing inspection state");
    assert_eq!(inspection.mode(), RhiStateHostMode::ReadOnlyInspection);
    let repositories = inspection.repositories();
    assert_eq!(
        format!("{repositories:?}"),
        "RhiStateRepositories { mode: ReadOnlyInspection, state: \"[sealed]\" }"
    );
    assert_eq!(
        repositories.sources().kind(),
        RhiStateRepositoryKind::Source
    );
    assert_eq!(
        repositories.source_cursors().kind(),
        RhiStateRepositoryKind::SourceCursor
    );
    assert_eq!(
        repositories.source_completions().kind(),
        RhiStateRepositoryKind::SourceCompletion
    );
    assert_eq!(
        repositories.signed_events().kind(),
        RhiStateRepositoryKind::SignedEvent
    );
    assert_eq!(
        repositories.mutations().kind(),
        RhiStateRepositoryKind::Mutation
    );
    assert_eq!(
        repositories.provenance().kind(),
        RhiStateRepositoryKind::Provenance
    );
    assert_eq!(
        repositories.dirty_trades().kind(),
        RhiStateRepositoryKind::DirtyTrade
    );
    assert_eq!(
        repositories.reconciliation_jobs().kind(),
        RhiStateRepositoryKind::ReconciliationJob
    );
    assert_eq!(
        repositories.reconciliation_attempts().kind(),
        RhiStateRepositoryKind::ReconciliationAttempt
    );
    assert_eq!(
        repositories.evidence_manifests().kind(),
        RhiStateRepositoryKind::EvidenceManifest
    );
    assert_eq!(
        repositories.projections().kind(),
        RhiStateRepositoryKind::Projection
    );
    assert_eq!(
        repositories.reports().kind(),
        RhiStateRepositoryKind::Report
    );
    assert_eq!(
        repositories.supersessions().kind(),
        RhiStateRepositoryKind::Supersession
    );
    assert_eq!(
        repositories.signed_attestation_events().kind(),
        RhiStateRepositoryKind::SignedAttestationEvent
    );
    assert_eq!(
        repositories.publication_outbox().kind(),
        RhiStateRepositoryKind::PublicationOutbox
    );
    assert_eq!(
        repositories.publication_targets().kind(),
        RhiStateRepositoryKind::PublicationTarget
    );
    assert_eq!(
        repositories.publication_attempts().kind(),
        RhiStateRepositoryKind::PublicationAttempt
    );
    assert_eq!(
        repositories.desired_presence().kind(),
        RhiStateRepositoryKind::DesiredPresence
    );
    inspection.close().await.expect("inspection close");

    let writer = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("authority reacquisition after explicit close");
    writer.close().await.expect("reopened writer close");
}

#[tokio::test]
async fn missing_state_and_mismatched_evidence_fail_before_database_creation() {
    let directory = tempfile::tempdir().expect("temporary root");
    let primary = runtime(directory.path(), "primary");
    let secondary = runtime(directory.path(), "secondary");
    prepare_state_directory(&primary);
    let primary_metadata = metadata(&primary);
    let (applied_at, build) = migration_evidence();

    let missing = open_rhi_state_read_write(&primary, &primary_metadata, applied_at, &build)
        .await
        .expect_err("missing state is never created by open");
    assert_eq!(missing.kind(), RhiStateHostErrorKind::ReadWriteOpen);
    assert!(!primary.artifacts().state_database().exists());

    let invalid_build = MigrationBuildIdentity::new(
        env!("CARGO_PKG_VERSION"),
        "1111111111111111111111111111111111111111",
        "21b11e7a5120ea949f7ad0838c746873fc73aac2",
        "rustc-test",
        "test-target",
        "service-host",
        2,
        1,
        1,
        1,
        1,
    )
    .expect("structurally valid mismatched build");
    let invalid = initialize_rhi_state(&primary, &primary_metadata, applied_at, &invalid_build)
        .await
        .expect_err("migration build must match RHI policy before I/O");
    assert_eq!(invalid.kind(), RhiStateHostErrorKind::InvalidEvidence);
    assert!(!primary.artifacts().state_database().exists());

    let mismatch = initialize_rhi_state(&secondary, &primary_metadata, applied_at, &build)
        .await
        .expect_err("cross-instance metadata");
    assert_eq!(mismatch.kind(), RhiStateHostErrorKind::InvalidEvidence);
    assert_eq!(mismatch.code(), "state_evidence_invalid");
    assert!(Error::source(&mismatch).is_none());
    let rendered = format!("{mismatch} {mismatch:?}");
    assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!rendered.contains("state.sqlite"));
    assert!(!secondary.artifacts().state_database().exists());
}

#[test]
fn public_lifecycle_source_is_sealed() {
    assert!(LIB_SOURCE.contains("mod state_host;"));
    assert!(!LIB_SOURCE.contains("pub mod state_host;"));
    assert!(HOST_SOURCE.contains("host: ServiceSqliteHost"));
    assert!(!HOST_SOURCE.contains("pub host:"));
    for forbidden in [
        "pub fn transaction",
        "pub async fn transaction",
        "pub fn pool",
        "pub fn connection",
        "pub fn into_inner",
        "pub fn executor",
        "MigrationDescriptor::",
        "raw_sql",
        "CREATE TABLE",
        "PRAGMA application_id",
    ] {
        assert!(
            !HOST_SOURCE.contains(forbidden),
            "found forbidden lifecycle authority `{forbidden}`"
        );
    }
}
