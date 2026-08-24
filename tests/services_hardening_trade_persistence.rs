#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use nostr::secp256k1::{Keypair, Message};
use nostr::{EventId, Keys, SECP256K1};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use rhi::{
    RHI_TRADE_EVIDENCE_PERSISTENCE_CONTRACT_VERSION, RadrootsHostEnvironment, RadrootsPathResolver,
    RadrootsPlatform, RhiConfigProfile, RhiStateMetadata, RhiTradeEvidencePersistenceErrorKind,
    RhiTradeMutationAdmissionLimits, RhiTradeMutationAuthoredTimePolicy,
    RhiTradeMutationObservedAtUnixSeconds, RhiTradeSourceObservation,
    admit_rhi_trade_mutation_event, initialize_rhi_state, open_rhi_state_inspection,
    open_rhi_state_read_write, parse_rhi_cli_v1_from, parse_rhi_config_v1,
    resolve_rhi_runtime_context,
};
use serde_json::Value;
use sqlx::{ConnectOptions, Connection, SqliteConnection, sqlite::SqliteConnectOptions};

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONTRACT: &str =
    include_str!("../contracts/services_hardening/trade_evidence_persistence.v1.json");
const VECTOR: &str = include_str!("../contracts/conformance/vectors/trade_ingest_proposal.v1.json");

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

fn configuration() -> rhi::RhiConfigDocumentV1 {
    parse_rhi_config_v1(CONFIG.as_bytes(), RhiConfigProfile::RepoLocal).expect("configuration")
}

fn metadata(
    runtime: &rhi::RhiRuntimeContext,
    configuration: &rhi::RhiConfigDocumentV1,
) -> RhiStateMetadata {
    RhiStateMetadata::new(
        runtime,
        configuration,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata")
}

fn migration_evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    (
        MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("migration time"),
        MigrationBuildIdentity::new(
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
        .expect("build identity"),
    )
}

fn prepare_state_directory(runtime: &rhi::RhiRuntimeContext) {
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
}

fn signed_wire(auxiliary: u8) -> Vec<u8> {
    let vector: Value = serde_json::from_str(VECTOR).expect("vector");
    let mut event: Value =
        serde_json::from_str(vector["raw_json"].as_str().expect("raw event")).expect("event JSON");
    let keys = Keys::parse("10c5304d6c9ae3a1a16f7860f1cc8f5e3a76225a2663b3a989a0d775919b7df5")
        .expect("approved fixture keys");
    let event_id = EventId::from_hex(event["id"].as_str().expect("event id")).expect("event id");
    let message = Message::from_digest(event_id.to_bytes());
    let keypair = Keypair::from_secret_key(SECP256K1, keys.secret_key());
    let signature = SECP256K1.sign_schnorr_with_aux_rand(&message, &keypair, &[auxiliary; 32]);
    event["sig"] = signature.to_string().into();
    serde_json::to_vec(&event).expect("event JSON")
}

fn admitted(
    configuration: &rhi::RhiConfigDocumentV1,
    wire: &[u8],
    observed_at: u64,
) -> rhi::RhiAdmittedTradeMutationEvent {
    admit_rhi_trade_mutation_event(
        RhiTradeMutationAdmissionLimits::from_config(configuration).expect("limits"),
        wire,
        RhiTradeMutationObservedAtUnixSeconds::new(observed_at).expect("observation time"),
        RhiTradeMutationAuthoredTimePolicy::new(0).expect("time policy"),
    )
    .expect("admitted event")
}

async fn offline_connection(runtime: &rhi::RhiRuntimeContext) -> SqliteConnection {
    SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(runtime.artifacts().state_database())
            .create_if_missing(false)
            .disable_statement_logging(),
    )
    .await
    .expect("offline connection")
}

async fn insert_mutation(
    connection: &mut SqliteConnection,
    event: &rhi::RhiAdmittedTradeMutationEvent,
    canonical_content: &[u8],
) {
    let mutation = event.mutation();
    sqlx::query(
        r#"INSERT INTO trade_mutations (
            mutation_id, trade_id, contract_id, schema_version, event_kind,
            author_pubkey, canonical_content
        ) VALUES (?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(event.mutation_id().as_bytes().as_slice())
    .bind(mutation.trade_id.as_bytes().as_slice())
    .bind(mutation.mutation_kind().contract_id())
    .bind(i64::from(mutation.schema_version))
    .bind(i64::from(event.event_kind()))
    .bind(mutation.author_pubkey.as_bytes().as_slice())
    .bind(canonical_content)
    .execute(connection)
    .await
    .expect("seed mutation");
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex byte");
    }
    bytes
}

#[test]
fn machine_contract_freezes_three_separate_immutable_facts() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.trade-evidence-persistence.v1"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(RHI_TRADE_EVIDENCE_PERSISTENCE_CONTRACT_VERSION, 1);
    assert_eq!(
        contract["facts"]["canonical_mutation"]["table"],
        "trade_mutations"
    );
    assert_eq!(
        contract["facts"]["canonical_mutation"]["event_authored_time_column"],
        "absent_event_fact_only"
    );
    assert_eq!(contract["facts"]["signed_event"]["table"], "nostr_events");
    assert_eq!(
        contract["facts"]["signed_event"]["identity"],
        serde_json::json!(["verified_event_id", "verified_event_signature"])
    );
    assert_eq!(
        contract["facts"]["source_observation"]["table"],
        "relay_observations"
    );
    assert_eq!(contract["effects"]["checkpoint"], false);
    assert_eq!(contract["effects"]["dirty_generation"], false);
}

#[tokio::test]
async fn signed_events_mutations_and_observations_are_atomic_distinct_and_idempotent() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path());
    prepare_state_directory(&runtime);
    let configuration = configuration();
    let metadata = metadata(&runtime, &configuration);
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");
    let host = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");

    let first_wire = signed_wire(1);
    let second_wire = signed_wire(2);
    let first_json: Value = serde_json::from_slice(&first_wire).expect("first JSON");
    let second_json: Value = serde_json::from_slice(&second_wire).expect("second JSON");
    assert_eq!(first_json["id"], second_json["id"]);
    assert_ne!(first_json["sig"], second_json["sig"]);

    let first = admitted(&configuration, &first_wire, 1_784_347_200);
    let first_observation =
        RhiTradeSourceObservation::from_config(&configuration, "trade-primary", &first)
            .expect("observation");
    let outcome = host
        .repositories()
        .persist_trade_evidence(first, first_observation)
        .await
        .expect("first persistence");
    assert!(outcome.mutation_inserted());
    assert!(outcome.signed_event_inserted());
    assert!(outcome.observation_inserted());

    let second = admitted(&configuration, &second_wire, 1_784_347_201);
    let second_observation =
        RhiTradeSourceObservation::from_config(&configuration, "trade-primary", &second)
            .expect("second observation");
    let outcome = host
        .repositories()
        .persist_trade_evidence(second, second_observation)
        .await
        .expect("second signature");
    assert!(!outcome.mutation_inserted());
    assert!(outcome.signed_event_inserted());
    assert!(outcome.observation_inserted());

    let replay = admitted(&configuration, &first_wire, 1_784_347_200);
    let replay_observation =
        RhiTradeSourceObservation::from_config(&configuration, "trade-primary", &replay)
            .expect("replay observation");
    let outcome = host
        .repositories()
        .persist_trade_evidence(replay, replay_observation)
        .await
        .expect("exact replay");
    assert!(!outcome.mutation_inserted());
    assert!(!outcome.signed_event_inserted());
    assert!(!outcome.observation_inserted());

    let later = admitted(&configuration, &first_wire, 1_784_347_202);
    let later_observation =
        RhiTradeSourceObservation::from_config(&configuration, "trade-primary", &later)
            .expect("later observation");
    let outcome = host
        .repositories()
        .persist_trade_evidence(later, later_observation)
        .await
        .expect("later observation");
    assert!(!outcome.mutation_inserted());
    assert!(!outcome.signed_event_inserted());
    assert!(outcome.observation_inserted());

    host.close().await.expect("close");
    let mut connection = offline_connection(&runtime).await;
    for (query, table, expected) in [
        (
            "SELECT COUNT(*) FROM trade_mutations",
            "trade_mutations",
            1_i64,
        ),
        ("SELECT COUNT(*) FROM nostr_events", "nostr_events", 2),
        (
            "SELECT COUNT(*) FROM relay_observations",
            "relay_observations",
            3,
        ),
    ] {
        let count = sqlx::query_scalar::<_, i64>(query)
            .fetch_one(&mut connection)
            .await
            .expect("count");
        assert_eq!(count, expected, "{table}");
    }
    assert!(
        sqlx::query("UPDATE trade_mutations SET mutation_id = mutation_id")
            .execute(&mut connection)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM nostr_events")
            .execute(&mut connection)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM relay_observations")
            .execute(&mut connection)
            .await
            .is_err()
    );
    connection.close().await.expect("offline close");

    let inspection = open_rhi_state_inspection(&runtime, &metadata)
        .await
        .expect("inspection");
    let rejected = admitted(&configuration, &first_wire, 1_784_347_203);
    let observation =
        RhiTradeSourceObservation::from_config(&configuration, "trade-primary", &rejected)
            .expect("observation");
    let error = inspection
        .repositories()
        .persist_trade_evidence(rejected, observation)
        .await
        .expect_err("inspection cannot persist");
    assert_eq!(
        error.kind(),
        RhiTradeEvidencePersistenceErrorKind::InvalidMode
    );
    inspection.close().await.expect("inspection close");
}

#[tokio::test]
async fn durable_mutation_conflict_rolls_back_the_event_and_observation() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path());
    prepare_state_directory(&runtime);
    let configuration = configuration();
    let metadata = metadata(&runtime, &configuration);
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");

    let wire = signed_wire(1);
    let event = admitted(&configuration, &wire, 1_784_347_200);
    let mut connection = offline_connection(&runtime).await;
    insert_mutation(&mut connection, &event, br#"{}"#).await;
    connection.close().await.expect("offline close");

    let host = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let observation =
        RhiTradeSourceObservation::from_config(&configuration, "trade-primary", &event)
            .expect("observation");
    let error = host
        .repositories()
        .persist_trade_evidence(event, observation)
        .await
        .expect_err("conflicting mutation");
    assert_eq!(
        error.kind(),
        RhiTradeEvidencePersistenceErrorKind::MutationConflict
    );
    assert!(Error::source(&error).is_none());
    host.close().await.expect("close");

    let mut connection = offline_connection(&runtime).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM nostr_events")
            .fetch_one(&mut connection)
            .await
            .expect("event count"),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relay_observations")
            .fetch_one(&mut connection)
            .await
            .expect("observation count"),
        0
    );
    connection.close().await.expect("offline close");
}

#[tokio::test]
async fn durable_signed_event_conflict_rolls_back_the_observation() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path());
    prepare_state_directory(&runtime);
    let configuration = configuration();
    let metadata = metadata(&runtime, &configuration);
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");

    let wire = signed_wire(1);
    let wire_json: Value = serde_json::from_slice(&wire).expect("wire JSON");
    let event = admitted(&configuration, &wire, 1_784_347_200);
    let mut connection = offline_connection(&runtime).await;
    insert_mutation(
        &mut connection,
        &event,
        wire_json["content"].as_str().expect("content").as_bytes(),
    )
    .await;
    sqlx::query(
        r#"INSERT INTO nostr_events (
            event_id, event_signature, mutation_id, author_pubkey, event_kind,
            authored_at_unix_s, canonical_event_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)"#,
    )
    .bind(event.event_id().as_bytes().as_slice())
    .bind(decode_hex::<64>(wire_json["sig"].as_str().expect("signature")).as_slice())
    .bind(event.mutation_id().as_bytes().as_slice())
    .bind(event.mutation().author_pubkey.as_bytes().as_slice())
    .bind(i64::from(event.event_kind()))
    .bind(i64::try_from(event.authored_at_unix_seconds()).expect("authored time"))
    .bind(br#"{}"#.as_slice())
    .execute(&mut connection)
    .await
    .expect("seed conflicting event");
    connection.close().await.expect("offline close");

    let host = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let observation =
        RhiTradeSourceObservation::from_config(&configuration, "trade-primary", &event)
            .expect("observation");
    let error = host
        .repositories()
        .persist_trade_evidence(event, observation)
        .await
        .expect_err("conflicting signed event");
    assert_eq!(
        error.kind(),
        RhiTradeEvidencePersistenceErrorKind::SignedEventConflict
    );
    assert!(Error::source(&error).is_none());
    host.close().await.expect("close");

    let mut connection = offline_connection(&runtime).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relay_observations")
            .fetch_one(&mut connection)
            .await
            .expect("observation count"),
        0
    );
    connection.close().await.expect("offline close");
}

#[test]
fn observation_construction_and_public_diagnostics_are_closed_and_redacted() {
    let configuration = configuration();
    let wire = signed_wire(1);
    let event = admitted(&configuration, &wire, 1_784_347_200);
    let missing = RhiTradeSourceObservation::from_config(&configuration, "missing", &event)
        .expect_err("unknown source");
    assert_eq!(
        missing.kind(),
        RhiTradeEvidencePersistenceErrorKind::InvalidObservation
    );
    assert!(Error::source(&missing).is_none());

    let observation =
        RhiTradeSourceObservation::from_config(&configuration, "trade-primary", &event)
            .expect("observation");
    let rendered = format!("{observation:?} {missing} {missing:?}");
    let wire: Value = serde_json::from_slice(&wire).expect("wire JSON");
    assert!(!rendered.contains("trade-primary"));
    assert!(!rendered.contains(wire["id"].as_str().expect("id")));
    assert!(!rendered.contains(wire["sig"].as_str().expect("signature")));
}
