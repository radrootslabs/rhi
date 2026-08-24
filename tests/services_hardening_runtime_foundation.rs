#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use nostr::{Keys, SecretKey};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use radroots_transport::{
    BoxFuture, BoxSubscription, DeliveryReceipt, DeliveryRequest, Error as TransportError,
    EventSink, EventSource, EventSubscriber, FetchPage, FetchRequest, SinkFailure, SinkStatus,
    SourceStatus, SubscriptionRequest,
};
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiConfigDocumentV1,
    RhiConfigProfile, RhiEncryptedIdentityProvisioningMaterial, RhiIdentityCredentialAdapters,
    RhiIdentityEnvelopeBinding, RhiRuntimeAdapters, RhiRuntimeFoundationErrorKind,
    RhiRuntimePrerequisite, RhiStateMetadata, RhiTimeEntropyAdapters, RhiTransportAdapters,
    initialize_rhi_state, open_rhi_runtime_foundation, open_rhi_state_read_write,
    parse_rhi_cli_v1_from, parse_rhi_config_v1, provision_rhi_encrypted_identity,
    resolve_rhi_runtime_context, resolve_rhi_wrapping_credential,
};
use sha2::{Digest, Sha256};

const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const FOUNDATION_SOURCE: &str = include_str!("../src/runtime_foundation.rs");
const CONTRACT_SOURCE: &str =
    include_str!("../contracts/services_hardening/runtime_foundation.v1.json");

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn identity_secret() -> [u8; 32] {
    let mut candidate = digest("radroots.rhi.runtime-foundation.identity.v1");
    while SecretKey::from_slice(&candidate).is_err() {
        candidate = Sha256::digest(candidate).into();
    }
    candidate
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

fn configuration(runtime: &rhi::RhiRuntimeContext, expected_identity: &str) -> RhiConfigDocumentV1 {
    let source = CONFIG_EXAMPLE
        .replace(
            "/var/lib/radroots/services/rhi/default/secrets/service.identity.ncrypt",
            runtime.identity_path().to_str().expect("identity path"),
        )
        .replace(&"2".repeat(64), expected_identity);
    parse_rhi_config_v1(source.as_bytes(), RhiConfigProfile::RepoLocal).expect("configuration")
}

fn evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    let applied_at = MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("time");
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

fn prepare(
    runtime: &rhi::RhiRuntimeContext,
    configuration: &RhiConfigDocumentV1,
) -> RhiStateMetadata {
    for directory in [
        runtime.context().paths().state(),
        runtime.context().paths().secrets(),
    ] {
        fs::create_dir_all(directory).expect("directory");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    let metadata = RhiStateMetadata::new(
        runtime,
        configuration,
        SourceGeneration::new([0x6b; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata");
    let binding = RhiIdentityEnvelopeBinding::from_configuration(configuration, &metadata)
        .expect("identity binding");
    let credential_bytes = digest("radroots.rhi.runtime-foundation.credential.v1");
    let credential_path = runtime
        .context()
        .paths()
        .secrets()
        .join("service_wrapping_key");
    fs::write(&credential_path, credential_bytes).expect("credential");
    fs::set_permissions(&credential_path, fs::Permissions::from_mode(0o600))
        .expect("credential mode");
    let credential = resolve_rhi_wrapping_credential(runtime, &binding).expect("credential open");
    provision_rhi_encrypted_identity(
        &binding,
        &credential,
        RhiEncryptedIdentityProvisioningMaterial::new(
            identity_secret(),
            digest("radroots.rhi.runtime-foundation.data-key.v1"),
            [7; 24],
            [9; 24],
        )
        .expect("material"),
    )
    .expect("identity provision");
    metadata
}

#[derive(Clone)]
struct TransportSpy(Arc<AtomicUsize>);

impl TransportSpy {
    fn invoked(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    fn mark(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl EventSource for TransportSpy {
    fn status(&self) -> BoxFuture<'_, Result<SourceStatus, TransportError>> {
        self.mark();
        Box::pin(async { panic!("foundation must not observe source status") })
    }

    fn fetch(&self, _request: FetchRequest) -> BoxFuture<'_, Result<FetchPage, TransportError>> {
        self.mark();
        Box::pin(async { panic!("foundation must not fetch") })
    }
}

impl EventSubscriber for TransportSpy {
    fn subscribe(
        &self,
        _request: SubscriptionRequest,
    ) -> BoxFuture<'_, Result<BoxSubscription, TransportError>> {
        self.mark();
        Box::pin(async { panic!("foundation must not subscribe") })
    }
}

impl EventSink for TransportSpy {
    fn status(&self) -> BoxFuture<'_, Result<SinkStatus, TransportError>> {
        self.mark();
        Box::pin(async { panic!("foundation must not observe sink status") })
    }

    fn deliver(
        &self,
        _request: DeliveryRequest,
    ) -> BoxFuture<'_, Result<DeliveryReceipt, SinkFailure>> {
        self.mark();
        Box::pin(async { panic!("foundation must not publish") })
    }
}

fn adapters(spy: &TransportSpy) -> RhiRuntimeAdapters {
    RhiRuntimeAdapters::new(
        RhiTimeEntropyAdapters::system(),
        RhiTransportAdapters::new(
            Arc::new(spy.clone()),
            Arc::new(spy.clone()),
            Arc::new(spy.clone()),
        ),
        RhiIdentityCredentialAdapters::canonical(),
    )
}

#[tokio::test]
async fn foundation_proves_state_config_identity_and_contacts_no_transport() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    let secret = identity_secret();
    let identity = Keys::new(SecretKey::from_slice(&secret).expect("secret"))
        .public_key()
        .to_hex();
    let configuration = configuration(&runtime, &identity);
    let metadata = prepare(&runtime, &configuration);
    let (applied_at, build) = evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");
    let spy = TransportSpy(Arc::new(AtomicUsize::new(0)));
    let foundation = open_rhi_runtime_foundation(
        runtime.clone(),
        configuration,
        adapters(&spy),
        applied_at,
        &build,
    )
    .await
    .expect("foundation");

    assert_eq!(spy.invoked(), 0);
    assert_eq!(
        foundation.metadata().database().source_generation(),
        metadata.database().source_generation()
    );
    assert!(!foundation.readiness().is_ready());
    assert_eq!(
        foundation.readiness().satisfied(),
        [
            RhiRuntimePrerequisite::ExistingState,
            RhiRuntimePrerequisite::DurableConfiguration,
            RhiRuntimePrerequisite::VerifiedIdentity,
        ]
    );
    assert!(
        foundation
            .readiness()
            .required()
            .contains(&RhiRuntimePrerequisite::PresenceDesiredState)
    );
    assert!(!foundation.readiness().reasons().is_empty());
    let rendered = format!("{foundation:?}");
    assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!rendered.contains(&identity));

    let contended = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect_err("foundation retains writer authority");
    assert_eq!(contended.kind(), rhi::RhiStateHostErrorKind::ReadWriteOpen);
    foundation.shutdown().await.expect("shutdown");
    let reopened = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopen");
    reopened.close().await.expect("close");
}

#[tokio::test]
async fn missing_state_fails_before_identity_or_transport_access() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    let secret = identity_secret();
    let identity = Keys::new(SecretKey::from_slice(&secret).expect("secret"))
        .public_key()
        .to_hex();
    let configuration = configuration(&runtime, &identity);
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
    let spy = TransportSpy(Arc::new(AtomicUsize::new(0)));
    let (applied_at, build) = evidence();
    let error = open_rhi_runtime_foundation(
        runtime.clone(),
        configuration,
        adapters(&spy),
        applied_at,
        &build,
    )
    .await
    .expect_err("missing state");
    assert_eq!(error.kind(), RhiRuntimeFoundationErrorKind::StateOpen);
    assert_eq!(spy.invoked(), 0);
    assert!(!runtime.artifacts().state_database().exists());
}

#[tokio::test]
async fn mismatched_configuration_fails_before_identity_or_transport_access() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    let secret = identity_secret();
    let identity = Keys::new(SecretKey::from_slice(&secret).expect("secret"))
        .public_key()
        .to_hex();
    let current = configuration(&runtime, &identity);
    let metadata = prepare(&runtime, &current);
    let (applied_at, build) = evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");

    let changed_source = CONFIG_EXAMPLE
        .replace(
            "/var/lib/radroots/services/rhi/default/secrets/service.identity.ncrypt",
            runtime.identity_path().to_str().expect("identity path"),
        )
        .replace(&"2".repeat(64), &identity)
        .replacen("level = \"info\"", "level = \"debug\"", 1);
    let changed = parse_rhi_config_v1(changed_source.as_bytes(), RhiConfigProfile::RepoLocal)
        .expect("changed configuration");
    let spy = TransportSpy(Arc::new(AtomicUsize::new(0)));
    let error =
        open_rhi_runtime_foundation(runtime.clone(), changed, adapters(&spy), applied_at, &build)
            .await
            .expect_err("configuration mismatch");
    assert_eq!(error.kind(), RhiRuntimeFoundationErrorKind::StateOpen);
    assert_eq!(spy.invoked(), 0);

    let reopened = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("failed foundation releases state authority");
    reopened.close().await.expect("close");
}

#[tokio::test]
async fn identity_failure_after_state_open_releases_authority_without_transport_access() {
    let directory = tempfile::tempdir().expect("root");
    let runtime = runtime(directory.path());
    let secret = identity_secret();
    let identity = Keys::new(SecretKey::from_slice(&secret).expect("secret"))
        .public_key()
        .to_hex();
    let configuration = configuration(&runtime, &identity);
    let metadata = prepare(&runtime, &configuration);
    let (applied_at, build) = evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");
    fs::remove_file(
        runtime
            .context()
            .paths()
            .secrets()
            .join("service_wrapping_key"),
    )
    .expect("remove credential");

    let spy = TransportSpy(Arc::new(AtomicUsize::new(0)));
    let error = open_rhi_runtime_foundation(
        runtime.clone(),
        configuration,
        adapters(&spy),
        applied_at,
        &build,
    )
    .await
    .expect_err("missing credential");
    assert_eq!(error.kind(), RhiRuntimeFoundationErrorKind::IdentityAccess);
    assert_eq!(spy.invoked(), 0);

    let reopened = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("identity failure releases state authority");
    reopened.close().await.expect("close");
}

#[test]
fn source_and_contract_keep_final_runtime_authority_deferred() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT_SOURCE).expect("contract");
    assert_eq!(contract["transport"]["invoked_during_foundation"], false);
    assert_eq!(contract["state_open"]["initialize_if_missing"], false);
    assert!(FOUNDATION_SOURCE.contains("open_rhi_state_read_write_from_config"));
    for forbidden in [
        "tokio::runtime",
        "ctrl_c",
        "signal_hook",
        "std::process::exit",
        ".fetch(",
        ".subscribe(",
        ".deliver(",
        "println!",
        "tracing::",
    ] {
        assert!(!FOUNDATION_SOURCE.contains(forbidden), "found {forbidden}");
    }
}
