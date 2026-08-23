#![forbid(unsafe_code)]

use std::{error::Error, path::Path};

use radroots_storage::event::SourceGeneration;
use rhi::{
    RHI_ADMIN_CONTRACT_VERSION, RHI_CONFIG_SCHEMA_VERSION, RHI_PROVIDER_CONTRACT_VERSION,
    RHI_STATE_APPLICATION_ID, RHI_STATE_SCHEMA_VERSION, RHI_STATUS_CONTRACT_VERSION,
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiConfigProfile,
    RhiStateMetadata, RhiStateMetadataErrorKind, parse_rhi_cli_v1_from, parse_rhi_config_v1,
    resolve_rhi_runtime_context,
};

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const METADATA_SOURCE: &str = include_str!("../src/state_metadata.rs");

fn runtime(root: &Path, profile: &str) -> rhi::RhiRuntimeContext {
    let root = root.to_str().expect("UTF-8 temporary root");
    let invocation = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        profile,
        "--instance",
        "primary",
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

fn state_metadata(
    runtime: &rhi::RhiRuntimeContext,
    source: &str,
) -> Result<RhiStateMetadata, rhi::RhiStateMetadataError> {
    let configuration =
        parse_rhi_config_v1(source.as_bytes(), RhiConfigProfile::RepoLocal).expect("configuration");
    RhiStateMetadata::new(
        runtime,
        &configuration,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
}

#[test]
fn exact_database_configuration_identity_and_policy_bindings_are_frozen() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "repo-local");
    let metadata = state_metadata(&runtime, EXAMPLE).expect("state metadata");
    let database = metadata.database();

    assert_eq!(RHI_STATE_APPLICATION_ID.to_be_bytes(), *b"RDRH");
    assert_eq!(database.application_id().get(), RHI_STATE_APPLICATION_ID);
    assert_eq!(database.service().as_str(), "rhi");
    assert_eq!(database.instance().as_str(), "primary");
    assert_eq!(database.source_generation().as_bytes(), &[0x5a; 32]);
    assert_eq!(
        database.state_schema_version().get(),
        RHI_STATE_SCHEMA_VERSION
    );
    assert_eq!(database.created_at_unix_ms(), 1_725_000_000_000);
    assert_eq!(metadata.expected_identity().as_hex(), "2".repeat(64));

    let versions = metadata.policy_versions();
    assert_eq!(versions.configuration(), RHI_CONFIG_SCHEMA_VERSION);
    assert_eq!(versions.state(), RHI_STATE_SCHEMA_VERSION);
    assert_eq!(versions.admin(), RHI_ADMIN_CONTRACT_VERSION);
    assert_eq!(versions.status(), RHI_STATUS_CONTRACT_VERSION);
    assert_eq!(versions.provider(), RHI_PROVIDER_CONTRACT_VERSION);
    assert_eq!(
        lower_hex(metadata.configuration_digest().as_bytes()),
        "7950e77614e1302f673d3434a58a69bfb4ce9c8006b61b29a12deb2b729136d4"
    );
    assert_eq!(
        lower_hex(metadata.evidence_policy_digest().as_bytes()),
        "43f083e29fcff4f90e66b546c49f74b0205ecb148beb352adb5a211d3e5f86b2"
    );
}

#[test]
fn digests_use_fully_defaulted_values_and_change_with_normalized_policy() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "repo-local");
    let explicit = state_metadata(&runtime, EXAMPLE).expect("explicit defaults");
    let implicit_source = EXAMPLE
        .replace("shutdown_grace_ms = 30000\n", "")
        .replace("level = \"info\"\n", "")
        .replace("format = \"json\"\n", "")
        .replace("busy_timeout_ms = 5000\n", "")
        .replace("max_connections = 8\n", "");
    let implicit = state_metadata(&runtime, &implicit_source).expect("implicit defaults");
    assert_eq!(
        explicit.configuration_digest(),
        implicit.configuration_digest()
    );
    assert_eq!(
        explicit.evidence_policy_digest(),
        implicit.evidence_policy_digest()
    );

    let changed = state_metadata(
        &runtime,
        &EXAMPLE.replace("deadline_ms = 10000", "deadline_ms = 10001"),
    )
    .expect("changed policy");
    assert_ne!(
        explicit.configuration_digest(),
        changed.configuration_digest()
    );
    assert_ne!(
        explicit.evidence_policy_digest(),
        changed.evidence_policy_digest()
    );
}

#[test]
fn profile_binding_fails_closed_without_state_or_source_disclosure() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "repo-local");
    let production = parse_rhi_config_v1(EXAMPLE.as_bytes(), RhiConfigProfile::Production)
        .expect("production configuration");
    let error = RhiStateMetadata::new(
        &runtime,
        &production,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1,
    )
    .expect_err("profile mismatch");
    assert_eq!(error.kind(), RhiStateMetadataErrorKind::Profile);
    assert!(Error::source(&error).is_none());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
    assert!(!rendered.contains(&"2".repeat(64)));
}

#[test]
fn metadata_debug_and_package_boundary_disclose_no_values() {
    let directory = tempfile::tempdir().expect("temporary root");
    let runtime = runtime(directory.path(), "repo-local");
    let metadata = state_metadata(&runtime, EXAMPLE).expect("state metadata");
    let rendered = format!("{metadata:?}");
    for forbidden in [
        directory.path().to_string_lossy().as_ref(),
        &"2".repeat(64),
        &lower_hex(metadata.configuration_digest().as_bytes()),
        &lower_hex(metadata.evidence_policy_digest().as_bytes()),
    ] {
        assert!(!rendered.contains(forbidden));
    }

    assert!(LIB_SOURCE.contains("mod state_metadata;"));
    assert!(!LIB_SOURCE.contains("pub mod state_metadata;"));
    for forbidden in [
        "sqlx::",
        "rusqlite",
        "CREATE TABLE",
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "std::fs",
        "std::env",
        "std::time",
        "Serialize",
        "Deserialize",
    ] {
        assert!(
            !METADATA_SOURCE.contains(forbidden),
            "found forbidden metadata authority `{forbidden}`"
        );
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
