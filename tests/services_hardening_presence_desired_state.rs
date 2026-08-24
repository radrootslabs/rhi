#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiConfigDocumentV1,
    RhiConfigProfile, RhiPresenceDesiredAuthority, RhiPresenceDesiredErrorKind,
    RhiPresenceDesiredMode, RhiStateMetadata, apply_rhi_configuration, initialize_rhi_state,
    open_rhi_state_inspection, open_rhi_state_read_write_from_config, parse_rhi_cli_v1_from,
    parse_rhi_config_v1, resolve_rhi_runtime_context, validate_rhi_presence_desired_authority,
};
use sqlx::{ConnectOptions, Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONTRACT: &str =
    include_str!("../contracts/services_hardening/presence_desired_state.v1.json");
const SOURCE: &str = include_str!("../src/presence_desired.rs");

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

fn config(source: &str) -> RhiConfigDocumentV1 {
    parse_rhi_config_v1(source.as_bytes(), RhiConfigProfile::RepoLocal).expect("configuration")
}

fn evidence(at: u64) -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    let applied_at = MigrationAppliedAtUnixSeconds::new(at).expect("migration time");
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

async fn offline_connection(runtime: &rhi::RhiRuntimeContext) -> SqliteConnection {
    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .foreign_keys(false)
        .disable_statement_logging();
    SqliteConnection::connect_with(&options)
        .await
        .expect("offline connection")
}

#[tokio::test]
async fn desired_state_is_durable_exact_replay_and_semantic_change_only() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
    let original = config(EXAMPLE);
    let metadata = RhiStateMetadata::new(
        &runtime,
        &original,
        SourceGeneration::new([0x5a; 32]).expect("source generation"),
        1_725_000_000_000,
    )
    .expect("metadata");
    let (first_at, first_build) = evidence(1_725_000_000);
    initialize_rhi_state(&runtime, &metadata, first_at, &first_build)
        .await
        .expect("initialize");

    let original_authority =
        RhiPresenceDesiredAuthority::from_config(&original).expect("authority");
    let host = open_rhi_state_read_write_from_config(&runtime, &original, first_at, &first_build)
        .await
        .expect("writer");
    let repository = host.repositories().desired_presence();
    assert_eq!(repository.current().await.expect("initial read"), None);
    let first = repository
        .commit(&original_authority)
        .await
        .expect("first commit");
    assert!(first.changed());
    assert_eq!(first.state().generation(), 1);
    assert_eq!(first.state().mode(), RhiPresenceDesiredMode::Enabled);
    assert!(first.state().profile());
    assert!(first.state().application_handler());
    assert_eq!(first.state().target_count(), 2);
    assert_eq!(first.state().required_target_count(), 1);
    assert_eq!(first.state().queue_capacity(), 64);
    let replay = repository
        .commit(&original_authority)
        .await
        .expect("exact replay");
    assert!(!replay.changed());
    assert_eq!(replay.state(), first.state());
    assert_eq!(
        repository.current().await.expect("current"),
        Some(first.state())
    );
    host.close().await.expect("writer close");

    let inspection = open_rhi_state_inspection(&runtime, &metadata)
        .await
        .expect("inspection");
    let inspected = inspection
        .repositories()
        .desired_presence()
        .current()
        .await
        .expect("inspection read");
    assert_eq!(inspected, Some(first.state()));
    let rejected = inspection
        .repositories()
        .desired_presence()
        .commit(&original_authority)
        .await
        .expect_err("inspection mutation");
    assert_eq!(rejected.kind(), RhiPresenceDesiredErrorKind::InvalidMode);
    inspection.close().await.expect("inspection close");

    let unrelated_source = EXAMPLE.replacen("level = \"info\"", "level = \"debug\"", 1);
    let unrelated = config(&unrelated_source);
    let unrelated_authority =
        RhiPresenceDesiredAuthority::from_config(&unrelated).expect("unrelated authority");
    assert_eq!(
        unrelated_authority.desired_sha256(),
        original_authority.desired_sha256()
    );
    assert_eq!(
        validate_rhi_presence_desired_authority(&unrelated, &original_authority)
            .expect_err("full configuration binding")
            .kind(),
        RhiPresenceDesiredErrorKind::Binding
    );
    let (second_at, second_build) = evidence(1_725_000_001);
    apply_rhi_configuration(&runtime, &original, &unrelated, second_at, &second_build)
        .await
        .expect("apply unrelated configuration");
    let host =
        open_rhi_state_read_write_from_config(&runtime, &unrelated, second_at, &second_build)
            .await
            .expect("writer after unrelated config");
    let replay = host
        .repositories()
        .desired_presence()
        .commit(&unrelated_authority)
        .await
        .expect("semantic replay");
    assert!(!replay.changed());
    assert_eq!(replay.state().generation(), 1);
    host.close().await.expect("writer close");

    let presence_source = unrelated_source.replace("profile = true", "profile = false");
    let presence_changed = config(&presence_source);
    let changed_authority =
        RhiPresenceDesiredAuthority::from_config(&presence_changed).expect("changed authority");
    assert_ne!(
        changed_authority.desired_sha256(),
        original_authority.desired_sha256()
    );
    let (third_at, third_build) = evidence(1_725_000_002);
    apply_rhi_configuration(
        &runtime,
        &unrelated,
        &presence_changed,
        third_at,
        &third_build,
    )
    .await
    .expect("apply presence configuration");
    let host =
        open_rhi_state_read_write_from_config(&runtime, &presence_changed, third_at, &third_build)
            .await
            .expect("writer after presence change");
    let stale = host
        .repositories()
        .desired_presence()
        .commit(&original_authority)
        .await
        .expect_err("stale config authority");
    assert_eq!(stale.kind(), RhiPresenceDesiredErrorKind::Binding);
    let changed = host
        .repositories()
        .desired_presence()
        .commit(&changed_authority)
        .await
        .expect("changed desired state");
    assert!(changed.changed());
    assert_eq!(changed.state().generation(), 2);
    assert!(!changed.state().profile());
    assert!(changed.state().application_handler());
    assert_eq!(changed.state().target_count(), 2);
    assert_eq!(
        changed.state().desired_sha256(),
        changed_authority.desired_sha256()
    );
    host.close().await.expect("final writer close");

    let mut connection = offline_connection(&runtime).await;
    let row = sqlx::query(
        "SELECT COUNT(*) AS row_count, generation, length(desired_sha256) AS digest_bytes \
         FROM presence_desired_state",
    )
    .fetch_one(&mut connection)
    .await
    .expect("durable desired state");
    assert_eq!(row.try_get::<i64, _>("row_count").unwrap(), 1);
    assert_eq!(row.try_get::<i64, _>("generation").unwrap(), 2);
    assert_eq!(row.try_get::<i64, _>("digest_bytes").unwrap(), 32);
    assert!(
        sqlx::query("UPDATE presence_desired_state SET generation = generation")
            .execute(&mut connection)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM presence_desired_state")
            .execute(&mut connection)
            .await
            .is_err()
    );
    connection.close().await.expect("offline close");

    let database = fs::read(runtime.artifacts().state_database()).expect("database bytes");
    for forbidden in [
        b"wss://relay-primary.example".as_slice(),
        b"relay-primary".as_slice(),
        directory.path().to_string_lossy().as_bytes(),
    ] {
        assert!(
            !database
                .windows(forbidden.len())
                .any(|window| window == forbidden)
        );
    }
}

#[test]
fn machine_contract_freezes_desired_state_without_publication_effects() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.presence-desired-state");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["authority"]["maximum_targets"], 32);
    assert_eq!(
        contract["reference_vector"]["target_set_sha256"],
        "959f04012841ae6e9bf3e109468b4f66cfa9d966aac1df36df09e45c1e1c48f9"
    );
    assert_eq!(
        contract["reference_vector"]["desired_state_sha256"],
        "7235f1e386e839427625dc364df7b51ee74d39d5f170e12b25cf2c42fd7731f0"
    );
    assert_eq!(contract["effects"]["clock"], false);
    assert_eq!(contract["effects"]["entropy"], false);
    assert_eq!(contract["effects"]["network"], false);
    assert_eq!(contract["effects"]["relay_io"], false);
    assert_eq!(
        contract["separate_publication_authority"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    for required in [
        "DESIRED_STATE_DOMAIN",
        "TARGET_SET_DOMAIN",
        "pub fn validate_rhi_presence_desired_authority(",
        "pub async fn commit(",
        "pub async fn current(",
        "require_current_config(transaction, authority).await?",
        "LIMIT 2",
        "ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown",
    ] {
        assert!(
            SOURCE.contains(required),
            "missing Step204 boundary {required}"
        );
    }
    for forbidden in [
        "SystemTime",
        "OsRng",
        "thread_rng",
        "tokio::spawn",
        "std::net",
        "NostrEventAdapter",
        "sign_nostr_event",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "unexpected desired-state effect {forbidden}"
        );
    }
    for kind in [
        RhiPresenceDesiredErrorKind::InvalidConfiguration,
        RhiPresenceDesiredErrorKind::TargetInventory,
        RhiPresenceDesiredErrorKind::InvalidMode,
        RhiPresenceDesiredErrorKind::Binding,
        RhiPresenceDesiredErrorKind::ResourceExhausted,
        RhiPresenceDesiredErrorKind::Storage,
        RhiPresenceDesiredErrorKind::CommitOutcomeUnknown,
    ] {
        let rendered = format!("{kind:?}");
        assert!(!rendered.contains("relay-primary"));
    }
}
