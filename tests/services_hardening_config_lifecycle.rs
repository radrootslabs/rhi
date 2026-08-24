#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use nostr::{Keys, SecretKey};
use radroots_service_sqlite::{
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity, OpenMode,
    ServiceSqliteConnectionOptions, ServiceSqliteHost, ServiceSqlitePaths, initialize_database,
};
use radroots_storage::event::SourceGeneration;
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiConfigApplyErrorKind,
    RhiConfigProfile, RhiStateMetadata, apply_rhi_configuration, initialize_rhi_state,
    open_rhi_state_read_write_from_config, parse_rhi_cli_v1_from, parse_rhi_config_v1,
    resolve_rhi_runtime_context, rhi_migration_catalog, rhi_schema_catalog,
};
use sqlx::{ConnectOptions, Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONFIG_SOURCE: &str = include_str!("../src/state_config.rs");
const HOST_SOURCE: &str = include_str!("../src/state_host.rs");

fn runtime(root: &Path) -> rhi::RhiRuntimeContext {
    let invocation = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        "repo-local",
        "--instance",
        "primary",
        "--repo-local-root",
        root.to_str().expect("UTF-8 root"),
        "run",
    ])
    .expect("invocation");
    resolve_rhi_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime")
}

fn configuration(source: &str) -> rhi::RhiConfigDocumentV1 {
    parse_rhi_config_v1(source.as_bytes(), RhiConfigProfile::RepoLocal).expect("configuration")
}

fn evidence(at: u64) -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    let applied_at = MigrationAppliedAtUnixSeconds::new(at).expect("time");
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
    .expect("build");
    (applied_at, build)
}

async fn offline_connection(runtime: &rhi::RhiRuntimeContext) -> SqliteConnection {
    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    SqliteConnection::connect_with(&options)
        .await
        .expect("offline connection")
}

async fn initialize_empty_catalog(path: PathBuf) -> Result<(), std::io::Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .disable_statement_logging();
    let connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(|_| std::io::Error::other("database open failed"))?;
    connection
        .close()
        .await
        .map_err(|_| std::io::Error::other("database close failed"))
}

#[tokio::test]
async fn existing_intent_and_offline_apply_bind_exact_append_only_evidence() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
    let current = configuration(EXAMPLE);
    let metadata = RhiStateMetadata::new(
        &runtime,
        &current,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata");
    let (applied_at, build) = evidence(1_725_000_000);
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");

    let state = open_rhi_state_read_write_from_config(&runtime, &current, applied_at, &build)
        .await
        .expect("intent open");
    assert_eq!(
        state.metadata().database().source_generation(),
        metadata.database().source_generation()
    );
    state.close().await.expect("close");

    let changed_source = EXAMPLE.replacen("level = \"info\"", "level = \"debug\"", 1);
    let changed = configuration(&changed_source);
    let (second_at, second_build) = evidence(1_725_000_001);
    let outcome = apply_rhi_configuration(&runtime, &current, &changed, second_at, &second_build)
        .await
        .expect("offline apply");
    assert_eq!(outcome.generation(), 2);
    assert!(outcome.changed());
    let replay = apply_rhi_configuration(&runtime, &changed, &changed, second_at, &second_build)
        .await
        .expect("idempotent replay");
    assert_eq!(replay.generation(), 2);
    assert!(!replay.changed());

    let old = open_rhi_state_read_write_from_config(&runtime, &current, second_at, &second_build)
        .await
        .expect_err("stale config must fail closed");
    assert_eq!(old.kind(), rhi::RhiStateHostErrorKind::InvalidEvidence);
    let accepted =
        open_rhi_state_read_write_from_config(&runtime, &changed, second_at, &second_build)
            .await
            .expect("new config accepted");
    accepted.close().await.expect("close");

    let mut connection = offline_connection(&runtime).await;
    let rows = sqlx::query(
        "SELECT generation, length(normalized_config_sha256) AS config_bytes,
         length(evidence_policy_sha256) AS policy_bytes, service_public_key,
         state_contract_version, applied_at_unix_s
         FROM rhi_config_bindings ORDER BY generation",
    )
    .fetch_all(&mut connection)
    .await
    .expect("history");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].try_get::<i64, _>("generation").unwrap(), 1);
    assert_eq!(rows[1].try_get::<i64, _>("generation").unwrap(), 2);
    for row in &rows {
        assert_eq!(row.try_get::<i64, _>("config_bytes").unwrap(), 32);
        assert_eq!(row.try_get::<i64, _>("policy_bytes").unwrap(), 32);
        assert_eq!(
            row.try_get::<i64, _>("state_contract_version").unwrap(),
            i64::from(rhi::RHI_STATE_SCHEMA_VERSION)
        );
        assert_eq!(
            row.try_get::<String, _>("service_public_key")
                .unwrap()
                .len(),
            64
        );
    }
    assert!(
        rows[1].try_get::<i64, _>("applied_at_unix_s").unwrap()
            >= rows[0].try_get::<i64, _>("applied_at_unix_s").unwrap()
    );
    assert!(
        sqlx::query("UPDATE rhi_config_bindings SET generation = generation")
            .execute(&mut connection)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM rhi_config_bindings")
            .execute(&mut connection)
            .await
            .is_err()
    );
    connection.close().await.expect("connection close");

    let bytes = fs::read(runtime.artifacts().state_database()).expect("database bytes");
    for forbidden in [
        directory.path().to_string_lossy().as_bytes(),
        b"wss://relay-primary.example".as_slice(),
        b"service_wrapping_key".as_slice(),
        b"level = \"debug\"".as_slice(),
    ] {
        assert!(
            !bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden)
        );
    }
}

#[tokio::test]
async fn apply_requires_current_binding_and_monotonic_time_without_lock_leak() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
    let current = configuration(EXAMPLE);
    let metadata = RhiStateMetadata::new(
        &runtime,
        &current,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata");
    let (applied_at, build) = evidence(100);
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");
    let changed = configuration(&EXAMPLE.replacen("level = \"info\"", "level = \"debug\"", 1));
    let (earlier, earlier_build) = evidence(99);
    let error = apply_rhi_configuration(&runtime, &current, &changed, earlier, &earlier_build)
        .await
        .expect_err("time rollback");
    assert_eq!(error.kind(), RhiConfigApplyErrorKind::InvalidInput);
    let reopened = open_rhi_state_read_write_from_config(&runtime, &current, applied_at, &build)
        .await
        .expect("authority released after failed apply");
    reopened.close().await.expect("close");
}

#[tokio::test]
async fn interrupted_first_binding_resumes_after_schema_migration() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
    let current = configuration(EXAMPLE);
    let metadata = RhiStateMetadata::new(
        &runtime,
        &current,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata");
    let (applied_at, build) = evidence(1_725_000_000);
    let paths = ServiceSqlitePaths::from_runtime_context(runtime.context()).expect("paths");
    let migrations = rhi_migration_catalog().expect("migrations");
    let schema = rhi_schema_catalog().expect("schema");
    let authority = initialize_database(
        &paths,
        OpenMode::Initialize,
        metadata.initial_database_metadata(),
        &schema,
        initialize_empty_catalog,
    )
    .await
    .expect("baseline initialize");
    let (host, outcome) = ServiceSqliteHost::open_initialized(
        &paths,
        &metadata.database_identity(),
        &migrations,
        &schema,
        ServiceSqliteConnectionOptions::reviewed(),
        authority,
        applied_at,
        &build,
        &[],
    )
    .await
    .expect("schema migration");
    assert_eq!(
        outcome.initial_version(),
        rhi::RHI_STATE_BASE_SCHEMA_VERSION
    );
    assert_eq!(outcome.final_version(), rhi::RHI_STATE_SCHEMA_VERSION);
    host.close().await.expect("close before binding");

    let mut connection = offline_connection(&runtime).await;
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM rhi_config_bindings")
        .fetch_one(&mut connection)
        .await
        .expect("empty binding count");
    assert_eq!(count, 0);
    connection.close().await.expect("connection close");

    let resumed = open_rhi_state_read_write_from_config(&runtime, &current, applied_at, &build)
        .await
        .expect("resume first binding");
    resumed.close().await.expect("resumed close");
    let mut connection = offline_connection(&runtime).await;
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM rhi_config_bindings")
        .fetch_one(&mut connection)
        .await
        .expect("seeded binding count");
    assert_eq!(count, 1);
    connection.close().await.expect("connection close");
}

#[tokio::test]
async fn semantically_conflicting_but_structurally_valid_history_fails_closed() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
    let current = configuration(EXAMPLE);
    let metadata = RhiStateMetadata::new(
        &runtime,
        &current,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata");
    let (applied_at, build) = evidence(1_725_000_000);
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");

    let conflicting_key =
        Keys::new(SecretKey::from_slice(&[0x33; 32]).expect("deterministic conflicting secret"))
            .public_key()
            .to_hex();
    assert_ne!(conflicting_key, metadata.expected_identity().as_hex());
    let mut connection = offline_connection(&runtime).await;
    sqlx::query(
        r#"INSERT INTO rhi_config_bindings (
            generation, normalized_config_sha256, evidence_policy_sha256,
            service_public_key, config_contract_version, state_contract_version,
            admin_contract_version, status_contract_version, provider_contract_version,
            applied_at_unix_s, service_version, service_commit, lib_revision,
            rust_version, target, feature_profile
        )
        SELECT generation + 1, normalized_config_sha256, evidence_policy_sha256,
            ?, config_contract_version, state_contract_version,
            admin_contract_version, status_contract_version, provider_contract_version,
            applied_at_unix_s + 1, service_version, service_commit, lib_revision,
            rust_version, target, feature_profile
        FROM rhi_config_bindings WHERE generation = 1"#,
    )
    .bind(conflicting_key)
    .execute(&mut connection)
    .await
    .expect("append structurally valid conflicting evidence");
    connection.close().await.expect("connection close");

    let rejected = open_rhi_state_read_write_from_config(&runtime, &current, applied_at, &build)
        .await
        .expect_err("conflicting history must fail closed");
    assert_eq!(rejected.kind(), rhi::RhiStateHostErrorKind::InvalidEvidence);
    let retried = open_rhi_state_read_write_from_config(&runtime, &current, applied_at, &build)
        .await
        .expect_err("rejected history must not leak writer authority");
    assert_eq!(retried.kind(), rhi::RhiStateHostErrorKind::InvalidEvidence);

    let mut connection = offline_connection(&runtime).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM rhi_config_bindings")
            .fetch_one(&mut connection)
            .await
            .expect("history count"),
        2
    );
    connection.close().await.expect("connection close");
}

#[test]
fn configuration_lifecycle_surface_is_sealed_and_redacted() {
    assert!(HOST_SOURCE.contains("open_read_write_existing_with_intent"));
    assert!(CONFIG_SOURCE.contains("LIMIT 1025"));
    assert!(CONFIG_SOURCE.contains("RHI_CONFIG_BINDING_MAX_GENERATIONS"));
    for forbidden in [
        "pub host:",
        "pub transaction:",
        "raw_sql",
        "rusqlite",
        "std::env",
    ] {
        assert!(!CONFIG_SOURCE.contains(forbidden), "found {forbidden}");
    }
    for kind in [
        RhiConfigApplyErrorKind::InvalidInput,
        RhiConfigApplyErrorKind::Binding,
        RhiConfigApplyErrorKind::ResourceExhausted,
        RhiConfigApplyErrorKind::Transaction,
        RhiConfigApplyErrorKind::CommitOutcomeUnknown,
        RhiConfigApplyErrorKind::Close,
    ] {
        let rendered = format!("{kind:?}");
        assert!(!rendered.is_empty());
    }
}
