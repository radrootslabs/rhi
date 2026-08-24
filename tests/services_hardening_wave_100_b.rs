#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use nostr::{Keys, SecretKey};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiConfigProfile,
    RhiEncryptedIdentityProvisioningMaterial, RhiIdentityEnvelopeBinding, RhiStateMetadata,
    initialize_rhi_state, open_rhi_encrypted_identity, open_rhi_state_read_write,
    parse_rhi_cli_v1_from, parse_rhi_config_v1, provision_rhi_encrypted_identity,
    resolve_rhi_runtime_context, resolve_rhi_wrapping_credential,
};
use sha2::{Digest, Sha256};

const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const ENVELOPE_CONTRACT: &str =
    include_str!("../contracts/services_hardening/encrypted_identity_envelope.v1.json");
const CREDENTIAL_CONTRACT: &str =
    include_str!("../contracts/services_hardening/wrapping_credential_resolution.v1.json");
const CONFIG_SOURCE: &str = include_str!("../src/config_v1.rs");
const CREDENTIAL_SOURCE: &str = include_str!("../src/identity_credential.rs");
const ENVELOPE_SOURCE: &str = include_str!("../src/identity_envelope.rs");
const STATE_HOST_SOURCE: &str = include_str!("../src/state_host.rs");
const STATE_MAINTENANCE_SOURCE: &str = include_str!("../src/state_maintenance.rs");

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn identity_secret() -> [u8; 32] {
    let mut candidate = digest("radroots.rhi.wave-100-b.identity-secret.v1");
    while SecretKey::from_slice(&candidate).is_err() {
        candidate = Sha256::digest(candidate).into();
    }
    candidate
}

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
    .expect("valid repo-local invocation");
    resolve_rhi_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context")
}

fn configuration(
    runtime: &rhi::RhiRuntimeContext,
    expected_identity: &str,
) -> rhi::RhiConfigDocumentV1 {
    let source = CONFIG_EXAMPLE
        .replace(
            "/var/lib/radroots/services/rhi/default/secrets/service.identity.ncrypt",
            runtime
                .identity_path()
                .to_str()
                .expect("UTF-8 identity artifact path"),
        )
        .replace(&"2".repeat(64), expected_identity);
    parse_rhi_config_v1(source.as_bytes(), RhiConfigProfile::RepoLocal)
        .expect("wave-two configuration")
}

fn prepare_secure_directory(path: &Path) {
    fs::create_dir_all(path).expect("secure directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("secure mode");
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn migration_evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    let applied_at = MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("migration time");
    let build = MigrationBuildIdentity::new(
        env!("CARGO_PKG_VERSION"),
        "1111111111111111111111111111111111111111",
        "79d7818c8fe22a425f9524b884ddf59d25f0ef89",
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
async fn wave_two_composes_one_runtime_without_crossing_secret_or_state_authority() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "primary");
    let secret = identity_secret();
    let expected_identity = Keys::new(SecretKey::from_slice(&secret).expect("identity secret"))
        .public_key()
        .to_hex();
    let configuration = configuration(&runtime, &expected_identity);
    let metadata = RhiStateMetadata::new(
        &runtime,
        &configuration,
        SourceGeneration::new([0x6b; 32]).expect("source generation"),
        1_725_000_000_000,
    )
    .expect("state metadata");
    let binding = RhiIdentityEnvelopeBinding::from_configuration(&configuration, &metadata)
        .expect("identity binding");

    prepare_secure_directory(runtime.context().paths().secrets());
    let credential_bytes = digest("radroots.rhi.wave-100-b.wrapping-credential.v1");
    let credential_path = runtime
        .context()
        .paths()
        .secrets()
        .join("service_wrapping_key");
    fs::write(&credential_path, credential_bytes).expect("credential artifact");
    fs::set_permissions(&credential_path, fs::Permissions::from_mode(0o600))
        .expect("credential mode");
    let credential =
        resolve_rhi_wrapping_credential(&runtime, &binding).expect("credential resolution");

    let material = RhiEncryptedIdentityProvisioningMaterial::new(
        secret,
        digest("radroots.rhi.wave-100-b.data-key.v1"),
        [7; 24],
        [9; 24],
    )
    .expect("provisioning material");
    let provisioned = provision_rhi_encrypted_identity(&binding, &credential, material)
        .expect("create-new identity provisioning");
    assert_eq!(provisioned.public_identity().as_hex(), expected_identity);
    let opened =
        open_rhi_encrypted_identity(&binding, &credential).expect("existing identity envelope");
    assert_eq!(opened.public_identity().as_hex(), expected_identity);

    prepare_secure_directory(runtime.context().paths().state());
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("create-new state initialization");
    let state = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("existing state open");
    state.close().await.expect("explicit state close");

    let state_bytes = fs::read(runtime.artifacts().state_database()).expect("state database");
    for forbidden in [
        secret.as_slice(),
        credential_bytes.as_slice(),
        b"RRS1".as_slice(),
        b"RHWK".as_slice(),
        b"service_wrapping_key".as_slice(),
    ] {
        assert!(
            !contains_bytes(&state_bytes, forbidden),
            "state database contains protected identity material"
        );
    }
    assert_eq!(
        runtime.identity_path().parent(),
        Some(runtime.context().paths().secrets())
    );
    assert_ne!(
        runtime.context().paths().state(),
        runtime.context().paths().secrets()
    );
    assert_eq!(
        fs::metadata(runtime.identity_path())
            .expect("identity metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&credential_path)
            .expect("credential metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn wave_two_contracts_freeze_backup_exclusion_at_the_sealed_maintenance_boundary() {
    let envelope: serde_json::Value =
        serde_json::from_str(ENVELOPE_CONTRACT).expect("envelope contract");
    let credential: serde_json::Value =
        serde_json::from_str(CREDENTIAL_CONTRACT).expect("credential contract");
    assert_eq!(envelope["backup"]["state_backup_includes_envelope"], false);
    assert_eq!(
        envelope["backup"]["state_backup_includes_wrapping_credential"],
        false
    );
    assert_eq!(
        envelope["backup"]["state_backup_includes_plaintext_identity"],
        false
    );
    assert_eq!(credential["backup_included"], false);
    assert!(STATE_HOST_SOURCE.contains("capture_online_backup"));
    assert!(!STATE_HOST_SOURCE.contains("verify_backup_bundle"));
    assert!(STATE_MAINTENANCE_SOURCE.contains("verify_backup_bundle"));
    assert!(!STATE_HOST_SOURCE.contains("finalize_staged_restore"));
}

#[test]
fn wave_two_keeps_configuration_state_identity_and_credential_authorities_separate() {
    for forbidden in [
        "resolve_rhi_wrapping_credential",
        "RhiWrappingCredential",
        "provision_rhi_encrypted_identity",
        "open_rhi_encrypted_identity",
        "service_wrapping_key",
    ] {
        assert!(!STATE_HOST_SOURCE.contains(forbidden));
    }
    for forbidden in ["sqlx::", "std::fs::", "std::env::"] {
        assert!(
            !CONFIG_SOURCE.contains(forbidden),
            "configuration parser contains forbidden authority {forbidden}"
        );
    }
    for source in [CREDENTIAL_SOURCE, ENVELOPE_SOURCE] {
        for forbidden in ["sqlx::", "rusqlite::", "state.sqlite"] {
            assert!(!source.contains(forbidden));
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(!root.join("src/host_identity.rs").exists());
    assert!(!root.join("src/identity_storage.rs").exists());
}
