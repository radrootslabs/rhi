#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use nostr::{Keys, SecretKey};
use radroots_service_host::{
    EntropyError, EntropySource, SystemMonotonicClock, UnixTimeSeconds, WallClock, WallClockError,
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use radroots_transport::BoxFuture;
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiConfigDocumentV1,
    RhiConfigProfile, RhiDecryptedIdentity, RhiEncryptedIdentityProvisioningMaterial,
    RhiExactPresenceSink, RhiIdentityEnvelopeBinding, RhiPreparedPresenceAttempt,
    RhiPresenceAttemptOutcome, RhiPresenceDesiredAuthority, RhiPresenceLeaseOwner,
    RhiPresenceOutboxState, RhiPresenceRetryDelayMilliseconds, RhiPresenceTargetState,
    RhiPresenceUnixMilliseconds, RhiStateMetadata, RhiTimeEntropyAdapters, apply_rhi_configuration,
    build_rhi_signed_presence_documents, initialize_rhi_state,
    open_rhi_state_read_write_from_config, parse_rhi_cli_v1_from, parse_rhi_config_v1,
    provision_rhi_encrypted_identity, resolve_rhi_runtime_context, resolve_rhi_wrapping_credential,
    validate_rhi_signed_presence_documents,
};
use sqlx::{ConnectOptions, Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONTRACT: &str = include_str!("../contracts/services_hardening/presence_publication.v1.json");

struct FixedEntropy(u8);

impl EntropySource for FixedEntropy {
    fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(self.0);
        Ok(())
    }
}

struct UnavailableEntropy;

impl EntropySource for UnavailableEntropy {
    fn fill_bytes(&self, _destination: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::Unavailable)
    }
}

#[derive(Clone, Copy)]
struct FixedWall(u64);

impl WallClock for FixedWall {
    fn now_utc(&self) -> Result<UnixTimeSeconds, WallClockError> {
        Ok(UnixTimeSeconds::new(self.0))
    }
}

struct InspectingSink {
    database: PathBuf,
    expected: Box<[u8]>,
}

impl RhiExactPresenceSink for InspectingSink {
    fn submit_exact<'a>(
        &'a self,
        attempt: &'a RhiPreparedPresenceAttempt,
    ) -> BoxFuture<'a, RhiPresenceAttemptOutcome> {
        Box::pin(async move {
            assert_eq!(attempt.exact_signed_event_bytes(), self.expected.as_ref());
            let mut connection = offline_connection(&self.database).await;
            let row = sqlx::query(
                "SELECT targets.state, outbox.exact_signed_event_bytes \
                 FROM presence_targets AS targets \
                 JOIN presence_outbox AS outbox ON outbox.outbox_id = targets.outbox_id \
                 WHERE targets.last_attempt_id = ? LIMIT 2",
            )
            .bind(attempt.attempt_id().as_bytes().as_slice())
            .fetch_one(&mut connection)
            .await
            .expect("durable pre-I/O target");
            assert_eq!(row.try_get::<String, _>("state").unwrap(), "submitted");
            assert_eq!(
                row.try_get::<Vec<u8>, _>("exact_signed_event_bytes")
                    .unwrap(),
                self.expected.as_ref()
            );
            connection.close().await.expect("sink inspection close");
            RhiPresenceAttemptOutcome::Accepted
        })
    }
}

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

fn evidence(at: u64) -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    (
        MigrationAppliedAtUnixSeconds::new(at).expect("migration time"),
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

async fn offline_connection(database: &Path) -> SqliteConnection {
    let options = SqliteConnectOptions::new()
        .filename(database)
        .create_if_missing(false)
        .foreign_keys(false)
        .disable_statement_logging();
    SqliteConnection::connect_with(&options)
        .await
        .expect("offline connection")
}

fn secret() -> [u8; 32] {
    [1; 32]
}

fn configuration(runtime: &rhi::RhiRuntimeContext, public_key: &str) -> RhiConfigDocumentV1 {
    configuration_from(runtime, public_key, EXAMPLE)
}

fn configuration_from(
    runtime: &rhi::RhiRuntimeContext,
    public_key: &str,
    source: &str,
) -> RhiConfigDocumentV1 {
    let source = source
        .replace(
            "/var/lib/radroots/services/rhi/default/secrets/service.identity.ncrypt",
            runtime
                .identity_path()
                .to_str()
                .expect("UTF-8 identity path"),
        )
        .replace(&"2".repeat(64), public_key);
    parse_rhi_config_v1(source.as_bytes(), RhiConfigProfile::RepoLocal).expect("configuration")
}

#[tokio::test]
async fn expired_stale_generation_is_unknown_and_superseded_before_new_bytes_commit() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
    let public_key = Keys::new(SecretKey::from_slice(&secret()).expect("secret"))
        .public_key()
        .to_hex();
    let original = configuration(&runtime, &public_key);
    let metadata = RhiStateMetadata::new(
        &runtime,
        &original,
        SourceGeneration::new([0x5b; 32]).expect("source generation"),
        1_725_000_000_000,
    )
    .expect("metadata");
    let (first_at, first_build) = evidence(1_725_000_000);
    initialize_rhi_state(&runtime, &metadata, first_at, &first_build)
        .await
        .expect("initialize");
    let identity = provision(&runtime, &original, &metadata);
    let original_authority =
        RhiPresenceDesiredAuthority::from_config(&original).expect("original authority");
    let host = open_rhi_state_read_write_from_config(&runtime, &original, first_at, &first_build)
        .await
        .expect("writer");
    let original_desired = host
        .repositories()
        .desired_presence()
        .commit(&original_authority)
        .await
        .expect("original desired");
    let original_documents = build_rhi_signed_presence_documents(
        original_desired,
        &original_authority,
        &identity,
        UnixTimeSeconds::new(1_725_000_100),
        &FixedEntropy(0x92),
    )
    .expect("original documents");
    host.repositories()
        .presence_outbox()
        .commit_signed_presence(&original_documents, millis(1_725_000_100_000))
        .await
        .expect("original outbox");
    let lease = host
        .repositories()
        .presence_outbox()
        .claim_next_presence(
            RhiPresenceLeaseOwner::from_bytes([0x41; 16]).expect("owner"),
            millis(1_725_000_101_000),
        )
        .await
        .expect("claim")
        .expect("work");
    let submitted = host
        .repositories()
        .presence_outbox()
        .prepare_next_presence_target(lease, millis(1_725_000_101_000))
        .await
        .expect("submitted");
    drop(submitted);
    host.close().await.expect("close original host");

    let changed_source = EXAMPLE.replace("profile = true", "profile = false");
    let changed = configuration_from(&runtime, &public_key, &changed_source);
    let (second_at, second_build) = evidence(1_725_000_001);
    apply_rhi_configuration(&runtime, &original, &changed, second_at, &second_build)
        .await
        .expect("apply changed configuration");
    let host = open_rhi_state_read_write_from_config(&runtime, &changed, second_at, &second_build)
        .await
        .expect("changed writer");
    let changed_authority =
        RhiPresenceDesiredAuthority::from_config(&changed).expect("changed authority");
    let changed_desired = host
        .repositories()
        .desired_presence()
        .commit(&changed_authority)
        .await
        .expect("changed desired");
    assert_eq!(changed_desired.state().generation(), 2);
    let changed_documents = build_rhi_signed_presence_documents(
        changed_desired,
        &changed_authority,
        &identity,
        UnixTimeSeconds::new(1_725_000_200),
        &FixedEntropy(0x93),
    )
    .expect("changed documents");
    let blocked = host
        .repositories()
        .presence_outbox()
        .commit_signed_presence(&changed_documents, millis(1_725_000_200_000))
        .await
        .expect_err("active stale lease blocks replacement");
    assert_eq!(
        blocked.kind(),
        rhi::RhiPresencePublicationErrorKind::NotReady
    );

    let recovery_adapters = RhiTimeEntropyAdapters::new(
        FixedWall(1_725_000_120),
        SystemMonotonicClock::new(),
        UnavailableEntropy,
    );
    assert!(
        host.repositories()
            .presence_outbox()
            .recover_one_expired_presence(&recovery_adapters, millis(1_725_000_120_000))
            .await
            .expect("stale recovery does not sample retry entropy")
    );
    assert!(
        host.repositories()
            .presence_outbox()
            .commit_signed_presence(&changed_documents, millis(1_725_000_200_000))
            .await
            .expect("new generation commit")
            .changed()
    );
    host.close().await.expect("close changed host");

    let mut disabled_table = changed_source
        .parse::<toml::Table>()
        .expect("changed configuration TOML");
    let disabled_presence = disabled_table
        .get_mut("presence")
        .and_then(toml::Value::as_table_mut)
        .expect("presence table");
    disabled_presence.insert("enabled".to_owned(), toml::Value::Boolean(false));
    disabled_presence.insert("profile".to_owned(), toml::Value::Boolean(false));
    disabled_presence.insert(
        "application_handler".to_owned(),
        toml::Value::Boolean(false),
    );
    disabled_presence.remove("target_relay_ids");
    let disabled_source = toml::to_string(&disabled_table).expect("disabled configuration TOML");
    let disabled = configuration_from(&runtime, &public_key, &disabled_source);
    let (third_at, third_build) = evidence(1_725_000_002);
    apply_rhi_configuration(&runtime, &changed, &disabled, third_at, &third_build)
        .await
        .expect("disable presence");
    let host = open_rhi_state_read_write_from_config(&runtime, &disabled, third_at, &third_build)
        .await
        .expect("disabled writer");
    let disabled_authority =
        RhiPresenceDesiredAuthority::from_config(&disabled).expect("disabled authority");
    let disabled_desired = host
        .repositories()
        .desired_presence()
        .commit(&disabled_authority)
        .await
        .expect("disabled desired");
    assert_eq!(disabled_desired.state().generation(), 3);
    let disabled_documents = build_rhi_signed_presence_documents(
        disabled_desired,
        &disabled_authority,
        &identity,
        UnixTimeSeconds::new(1_725_000_300),
        &UnavailableEntropy,
    )
    .expect("disabled document inventory consumes no entropy");
    assert!(disabled_documents.documents().is_empty());
    assert!(
        host.repositories()
            .presence_outbox()
            .commit_signed_presence(&disabled_documents, millis(1_725_000_300_000))
            .await
            .expect("disabled generation commit")
            .changed()
    );
    assert!(
        !host
            .repositories()
            .presence_outbox()
            .commit_signed_presence(&disabled_documents, millis(1_725_000_300_000))
            .await
            .expect("disabled exact replay")
            .changed()
    );
    host.close().await.expect("close disabled host");

    let mut connection = offline_connection(runtime.artifacts().state_database()).await;
    let stale: (String, String) = sqlx::query_as(
        "SELECT outbox.state, attempts.outcome FROM presence_outbox AS outbox \
         JOIN presence_attempts AS attempts ON attempts.outbox_id = outbox.outbox_id \
         WHERE outbox.desired_generation = 1 AND outbox.document_kind = 'service_profile'",
    )
    .fetch_one(&mut connection)
    .await
    .expect("stale durable result");
    assert_eq!(stale, ("superseded".to_owned(), "unknown".to_owned()));
    let disabled_prior_state: String = sqlx::query_scalar(
        "SELECT state FROM presence_outbox WHERE desired_generation = 2 LIMIT 2",
    )
    .fetch_one(&mut connection)
    .await
    .expect("disabled prior generation");
    assert_eq!(disabled_prior_state, "superseded");
    let disabled_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM presence_outbox WHERE desired_generation = 3")
            .fetch_one(&mut connection)
            .await
            .expect("disabled outbox count");
    assert_eq!(disabled_count, 0);
    connection.close().await.expect("offline close");
}

fn provision(
    runtime: &rhi::RhiRuntimeContext,
    configuration: &RhiConfigDocumentV1,
    metadata: &RhiStateMetadata,
) -> RhiDecryptedIdentity {
    fs::create_dir_all(runtime.context().paths().secrets()).expect("secrets directory");
    fs::set_permissions(
        runtime.context().paths().secrets(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("secrets mode");
    let credential_path = runtime
        .context()
        .paths()
        .secrets()
        .join("service_wrapping_key");
    fs::write(&credential_path, [0x81; 32]).expect("credential");
    fs::set_permissions(&credential_path, fs::Permissions::from_mode(0o600))
        .expect("credential mode");
    let binding = RhiIdentityEnvelopeBinding::from_configuration(configuration, metadata)
        .expect("identity binding");
    let credential =
        resolve_rhi_wrapping_credential(runtime, &binding).expect("wrapping credential");
    provision_rhi_encrypted_identity(
        &binding,
        &credential,
        RhiEncryptedIdentityProvisioningMaterial::new(secret(), [0x42; 32], [0x43; 24], [0x44; 24])
            .expect("provisioning material"),
    )
    .expect("provision identity")
}

fn millis(value: u64) -> RhiPresenceUnixMilliseconds {
    RhiPresenceUnixMilliseconds::new(value).expect("milliseconds")
}

#[tokio::test]
async fn exact_bytes_are_durable_before_io_and_unknown_recovery_retries_unchanged() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path());
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
    let public_key = Keys::new(SecretKey::from_slice(&secret()).expect("secret"))
        .public_key()
        .to_hex();
    let configuration = configuration(&runtime, &public_key);
    let metadata = RhiStateMetadata::new(
        &runtime,
        &configuration,
        SourceGeneration::new([0x5a; 32]).expect("source generation"),
        1_725_000_000_000,
    )
    .expect("metadata");
    let (applied_at, build) = evidence(1_725_000_000);
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");
    let identity = provision(&runtime, &configuration, &metadata);
    let authority = RhiPresenceDesiredAuthority::from_config(&configuration).expect("authority");
    let host = open_rhi_state_read_write_from_config(&runtime, &configuration, applied_at, &build)
        .await
        .expect("writer");
    let desired = host
        .repositories()
        .desired_presence()
        .commit(&authority)
        .await
        .expect("desired state");
    let authored = UnixTimeSeconds::new(1_725_000_100);
    let invalid_time = build_rhi_signed_presence_documents(
        desired,
        &authority,
        &identity,
        UnixTimeSeconds::new(i64::MAX as u64 + 1),
        &FixedEntropy(0x91),
    )
    .expect_err("unrepresentable authored time");
    assert_eq!(
        invalid_time.kind(),
        rhi::RhiPresencePublicationErrorKind::InvalidInput
    );
    let documents = build_rhi_signed_presence_documents(
        desired,
        &authority,
        &identity,
        authored,
        &FixedEntropy(0x91),
    )
    .expect("signed presence");
    validate_rhi_signed_presence_documents(&documents, &authority)
        .expect("independently verified signed presence");
    let exact: Vec<Box<[u8]>> = documents
        .documents()
        .iter()
        .map(|document| document.signed_event_bytes().into())
        .collect();
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("machine contract");
    assert_eq!(contract["schema"], "radroots.rhi.presence-publication");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 205);
    assert_eq!(
        contract["reference_vector"]["profile"]["exact_signed_event_json"],
        String::from_utf8_lossy(&exact[0]).as_ref()
    );
    assert_eq!(
        contract["reference_vector"]["application_handler"]["exact_signed_event_json"],
        String::from_utf8_lossy(&exact[1]).as_ref()
    );
    assert_eq!(
        contract["reference_vector"]["profile"]["event_id"],
        lower_hex(documents.documents()[0].event_id())
    );
    assert_eq!(
        contract["reference_vector"]["application_handler"]["event_id"],
        lower_hex(documents.documents()[1].event_id())
    );
    assert_eq!(
        contract["reference_vector"]["profile"]["exact_signed_event_sha256"],
        lower_hex(documents.documents()[0].signed_event_sha256())
    );
    assert_eq!(
        contract["reference_vector"]["application_handler"]["exact_signed_event_sha256"],
        lower_hex(documents.documents()[1].signed_event_sha256())
    );
    let committed_at = millis(1_725_000_100_000);
    let committed = host
        .repositories()
        .presence_outbox()
        .commit_signed_presence(&documents, committed_at)
        .await
        .expect("durable exact presence");
    assert!(committed.changed());
    assert_eq!(committed.document_count(), 2);

    assert!(
        !host
            .repositories()
            .presence_outbox()
            .commit_signed_presence(&documents, committed_at)
            .await
            .expect("exact replay")
            .changed()
    );

    let adapters = RhiTimeEntropyAdapters::new(
        FixedWall(1_725_000_100),
        SystemMonotonicClock::new(),
        FixedEntropy(0xff),
    );
    let sink = InspectingSink {
        database: runtime.artifacts().state_database().to_path_buf(),
        expected: exact[0].clone(),
    };
    let first = host
        .repositories()
        .presence_outbox()
        .execute_next_presence(
            RhiPresenceLeaseOwner::from_bytes([0x11; 16]).expect("owner"),
            &adapters,
            &sink,
        )
        .await
        .expect("execute first")
        .expect("first work");
    assert_eq!(first.outbox_state(), RhiPresenceOutboxState::Complete);
    assert_eq!(first.target_state(), RhiPresenceTargetState::Accepted);

    let repository = host.repositories().presence_outbox();
    let started = millis(1_725_000_101_000);
    let second_lease = repository
        .claim_next_presence(
            RhiPresenceLeaseOwner::from_bytes([0x22; 16]).expect("owner"),
            started,
        )
        .await
        .expect("claim second")
        .expect("second work");
    let abandoned = repository
        .prepare_next_presence_target(second_lease, started)
        .await
        .expect("prepare second");
    assert_eq!(abandoned.exact_signed_event_bytes(), exact[1].as_ref());
    drop(abandoned);
    host.close().await.expect("close after cancellation");

    let host = open_rhi_state_read_write_from_config(&runtime, &configuration, applied_at, &build)
        .await
        .expect("reopen writer");
    let recovery_now = millis(1_725_000_120_000);
    assert!(
        host.repositories()
            .presence_outbox()
            .recover_one_expired_presence(&adapters, recovery_now)
            .await
            .expect("unknown recovery")
    );
    let retry_at = millis(1_725_000_150_000);
    let lease = host
        .repositories()
        .presence_outbox()
        .claim_next_presence(
            RhiPresenceLeaseOwner::from_bytes([0x33; 16]).expect("owner"),
            retry_at,
        )
        .await
        .expect("retry claim")
        .expect("retry work");
    let retried = host
        .repositories()
        .presence_outbox()
        .prepare_next_presence_target(lease, retry_at)
        .await
        .expect("retry prepare");
    assert_eq!(retried.exact_signed_event_bytes(), exact[1].as_ref());
    let accepted = host
        .repositories()
        .presence_outbox()
        .record_presence_outcome(
            &retried,
            millis(1_725_000_150_001),
            RhiPresenceAttemptOutcome::Accepted,
            RhiPresenceRetryDelayMilliseconds::new(0).expect("zero delay"),
        )
        .await
        .expect("retry accepted");
    assert_eq!(accepted.attempt_number(), 2);
    assert_eq!(accepted.outbox_state(), RhiPresenceOutboxState::Complete);
    host.close().await.expect("final close");

    let mut connection = offline_connection(runtime.artifacts().state_database()).await;
    let counts = sqlx::query(
        "SELECT (SELECT COUNT(*) FROM presence_outbox) AS outboxes, \
                (SELECT COUNT(*) FROM presence_targets) AS targets, \
                (SELECT COUNT(*) FROM presence_attempts) AS attempts",
    )
    .fetch_one(&mut connection)
    .await
    .expect("workflow counts");
    assert_eq!(counts.try_get::<i64, _>("outboxes").unwrap(), 2);
    assert_eq!(counts.try_get::<i64, _>("targets").unwrap(), 4);
    assert_eq!(counts.try_get::<i64, _>("attempts").unwrap(), 3);
    let bytes: Vec<Vec<u8>> =
        sqlx::query("SELECT exact_signed_event_bytes FROM presence_outbox ORDER BY document_kind")
            .fetch_all(&mut connection)
            .await
            .expect("exact bytes")
            .into_iter()
            .map(|row| row.try_get("exact_signed_event_bytes").unwrap())
            .collect();
    assert_eq!(bytes, vec![exact[1].to_vec(), exact[0].to_vec()]);
    connection.close().await.expect("offline close");
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        rendered.push(char::from(DIGITS[usize::from(byte >> 4)]));
        rendered.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    rendered
}
