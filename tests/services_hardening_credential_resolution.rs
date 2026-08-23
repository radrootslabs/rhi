#![forbid(unsafe_code)]

use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/wrapping_credential_resolution.v1.json");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");
const CREDENTIAL_SOURCE: &str = include_str!("../src/identity_credential.rs");
const ENVELOPE_SOURCE: &str = include_str!("../src/identity_envelope.rs");
const CONFIG_SCHEMA: &str = include_str!("../contracts/services_hardening/config.v1.schema.json");
const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const HOST_SOURCE: &str = include_str!("../src/state_host.rs");

#[test]
fn machine_contract_freezes_the_canonical_read_only_credential_boundary() {
    let actual: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(
        actual,
        json!({
            "schema": "radroots.rhi.wrapping-credential-resolution",
            "schema_version": 1,
            "contract_version": 1,
            "artifact_name": {
                "shared_type": "ServiceCredentialArtifactName",
                "maximum_utf8_bytes": 128
            },
            "artifact_path": "<canonical_instance_secrets>/<validated_credential_name>",
            "artifact": {
                "wire": "raw_32_bytes",
                "exact_bytes": 32,
                "symlink_follow": false,
                "regular_file": true,
                "single_link": true,
                "owner_uid": "effective_uid",
                "read_modes_octal": ["0400", "0600"],
                "secrets_root_modes_octal": ["0500", "0700"]
            },
            "profiles": {
                "service_host": "existing_injected_or_mounted",
                "repo_local": "existing_offline_provisioned",
                "interactive": "unsupported"
            },
            "resolution": {
                "read_existing_only": true,
                "creates_credential": false,
                "creates_parent": false,
                "caller_supplies_path": false,
                "caller_supplies_bytes": false,
                "ordinary_run_generates": false
            },
            "forbidden_sources": [
                "toml_secret",
                "environment_secret",
                "process_argument_secret",
                "adjacent_envelope_sibling",
                "implicit_fallback"
            ],
            "backup_included": false
        })
    );
}

#[test]
fn implementation_derives_only_the_shared_canonical_artifact() {
    for required in [
        "binding.matches_runtime(runtime)",
        "ServiceCredentialArtifactName::new(reference.as_str())",
        "service_credential_artifact_path(runtime.context().paths(), &name)",
        "load_resolved_wrapping_credential(&path)",
        "RhiBootstrapProfileV1::ServiceHost | RhiBootstrapProfileV1::RepoLocal",
        "pub fn resolve_rhi_wrapping_credential(",
    ] {
        assert!(
            CREDENTIAL_SOURCE.contains(required),
            "missing canonical resolution boundary {required}"
        );
    }
    assert!(LIB_SOURCE.contains("mod identity_credential;"));
    assert!(!LIB_SOURCE.contains("pub mod identity_credential"));
    assert!(ENVELOPE_SOURCE.contains("pub(crate) struct RhiCredentialResolutionProof"));
    assert!(ENVELOPE_SOURCE.contains("pub(crate) fn from_resolution("));
}

#[test]
fn no_configuration_process_sibling_or_creation_fallback_exists() {
    let production = CREDENTIAL_SOURCE
        .split("#[cfg(test)]")
        .next()
        .expect("production source");
    for forbidden in [
        "std::env::",
        "process::Command",
        "clap::",
        "create_dir",
        "create_new",
        "OpenOptions",
        "keyring::",
        "with_extension(\"key\")",
        "set_var(",
        "var_os(",
    ] {
        assert!(
            !production.contains(forbidden),
            "forbidden credential authority {forbidden}"
        );
    }
    for source in [CONFIG_SCHEMA, CONFIG_EXAMPLE] {
        for forbidden in [
            "wrapping_credential =",
            "credential_bytes",
            "credential_hex",
        ] {
            assert!(!source.contains(forbidden));
        }
    }
}

#[test]
fn state_host_remains_credential_free_and_prototypes_are_removed() {
    for forbidden in [
        "resolve_rhi_wrapping_credential",
        "RhiWrappingCredential",
        "identity_credential",
        "service_wrapping_key",
    ] {
        assert!(!HOST_SOURCE.contains(forbidden));
    }
    for forbidden in [
        "pub mod host_identity",
        "pub mod identity_storage",
        "LEGACY_ENVELOPE_VERSION",
        "LegacyV1",
        "encrypt_secret_key_ncryptsec",
        "secret_key_hex",
        "rand::random",
    ] {
        assert!(!LIB_SOURCE.contains(forbidden));
    }
    let source_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(!source_root.join("host_identity.rs").exists());
    assert!(!source_root.join("identity_storage.rs").exists());
    for removed_dependency in [
        "radroots_identity =",
        "rand = { version = \"0.9\"",
        "features = [\"nip49\"]",
    ] {
        assert!(!MANIFEST.contains(removed_dependency));
    }
}

#[test]
fn public_errors_are_source_path_and_dependency_free() {
    for required in [
        "pub enum RhiCredentialResolutionErrorKind",
        "pub struct RhiCredentialResolutionError",
        "impl Error for RhiCredentialResolutionError {}",
    ] {
        assert!(CREDENTIAL_SOURCE.contains(required));
    }
    for forbidden in [
        "pub path:",
        "pub source:",
        "pub credential:",
        "pub fn credential_path",
        "pub fn from_resolved_bytes",
        "pub fn from_resolution",
        "radroots_runtime_paths::ServiceCredentialArtifactNameError",
        "rustix::",
    ] {
        assert!(!LIB_SOURCE.contains(forbidden));
    }
}
