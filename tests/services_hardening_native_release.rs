#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde_json::json;

const CONTRACT: &str = include_str!("../contracts/services_hardening/native_release.v1.json");
const MANIFEST: &str = include_str!("../Cargo.toml");
const LOCK: &str = include_str!("../Cargo.lock");
const SOURCE_LOCK: &str = include_str!("../radroots.service.source-lock.v2.toml");
const CARGO_CONFIG: &str = include_str!("../.cargo/config.toml");
const SYSTEMD_UNIT: &str = include_str!("../packaging/systemd/rhi@.service");
const RELEASE_ACCEPTANCE: &str = include_str!("../scripts/release-acceptance.sh");
const XTASK_MANIFEST: &str = include_str!("../tools/xtask/Cargo.toml");

const LIB_REVISION: &str = "21b11e7a5120ea949f7ad0838c746873fc73aac2";
const LIB_REPOSITORY: &str = "https://github.com/radrootslabs/lib";

#[test]
fn native_release_contract_and_manifest_metadata_are_exact() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("release contract");
    assert_eq!(
        contract,
        json!({
            "schema": "radroots.rhi.native-release",
            "schema_version": 1,
            "contract_version": 1,
            "service": "rhi",
            "package": {
                "name": "rhi",
                "binary": "rhi",
                "version": "0.1.0",
                "repository": "https://github.com/radrootslabs/rhi",
                "publish_to_crates_io": false
            },
            "generator": {
                "command": "cargo xtask native-release",
                "modes": ["check", "write"],
                "required_arguments": [
                    "mode", "target", "binary", "output", "source_date_epoch"
                ],
                "source_date_epoch_range": "1..=4294967295",
                "clean_exact_head": true,
                "target_binary_validation": "executable_elf64_little_endian_exact_machine",
                "canonical_json": "compact_utf8_json_with_one_final_lf",
                "deterministic_archives": true,
                "output_directory_mode": "0755",
                "output_file_mode": "0644",
                "durability": "sync_files_then_output_directory_then_parent"
            },
            "toolchain": {
                "rust_version": "1.97.1",
                "edition": "2024",
                "resolver": "3",
                "host_feature_profile": "service-host"
            },
            "release_profile": {
                "lto": "thin",
                "codegen_units": 1,
                "overflow_checks": true,
                "strip": "symbols",
                "panic": "unwind"
            },
            "source_lock": {
                "filename": "radroots.service.source-lock.v2.toml",
                "schema": "radroots.service.source-lock.v2",
                "lib_repository": LIB_REPOSITORY,
                "architecture": "radroots.crates.release.v2",
                "nix_material": "absent"
            },
            "contract_versions": {
                "config": 1,
                "state": 11,
                "admin": 1,
                "status": 1,
                "provider": 1
            },
            "native_targets": [
                { "target": "aarch64-unknown-linux-gnu", "posture": "target" },
                { "target": "x86_64-unknown-linux-gnu", "posture": "target" }
            ],
            "output_inventory": [
                "LICENSE",
                "SHA256SUMS",
                "THIRD-PARTY-NOTICES.txt",
                "artifact-manifest.v1.json",
                "binary.tar.gz",
                "config.example.toml",
                "config.schema.json",
                "provenance-input.v1.json",
                "radroots.service.source-lock.v2.toml",
                "sbom.cdx.json",
                "service-source.tar.gz",
                "systemd.service"
            ],
            "signing_inputs": [
                "SHA256SUMS",
                "artifact-manifest.v1.json",
                "provenance-input.v1.json"
            ],
            "provenance_posture": "deterministic_unsigned_slsa_v1_input_external_keys_only",
            "sbom_format": "cyclonedx_json_1_5_locked_cargo_graph",
            "sbom_component_identity": "domain_separated_sha256_of_framed_name_version_source_checksum",
            "protected_material_scan": "tracked_source_binary_copied_and_generated_material_fixed_patterns",
            "source_archive": "locked_offline_cargo_build_with_vendored_dependencies",
            "checksum_format": "sha256_lower_hex_two_spaces_path_lf_sorted_by_path",
            "protected_material_included": false,
            "maximums": {
                "text_input_bytes": 1048576,
                "generated_document_bytes": 16777216,
                "cargo_metadata_bytes": 33554432,
                "binary_bytes": 536870912,
                "source_archive_bytes": 1073741824,
                "packages": 8192,
                "tracked_files": 4096
            },
            "deferred_through_rcld_rshr_170": [
                "nix_evaluation",
                "nix_build",
                "nixos_module_qualification",
                "oci_artifact"
            ],
            "forbidden": [
                "nix_input",
                "nixos_module_output",
                "oci_input",
                "oci_output",
                "protected_material",
                "parent_owned_human_docs",
                "private_harness",
                "local_or_path_lib_dependency",
                "floating_or_branch_lib_dependency",
                "mixed_lib_revision",
                "crates_io_publication",
                "signing",
                "tagging",
                "release_publication",
                "deployment"
            ]
        })
    );

    let manifest: toml::Value = toml::from_str(MANIFEST).expect("Cargo manifest");
    let package = manifest["package"].as_table().expect("package");
    assert_eq!(
        package["repository"].as_str(),
        Some("https://github.com/radrootslabs/rhi")
    );
    assert_eq!(package["readme"].as_str(), Some("README"));
    assert_eq!(package["publish"].as_bool(), Some(false));
    assert_eq!(
        manifest["workspace"]["members"],
        toml::Value::Array(vec![
            toml::Value::String(".".to_owned()),
            toml::Value::String("tools/xtask".to_owned())
        ])
    );
    assert_eq!(
        manifest["workspace"]["metadata"]["radroots"]["service_release"],
        toml::Value::Table(toml::toml! {
            service = "rhi"
            service_package = "rhi"
            binary_name = "rhi"
            version = "0.1.0"
        })
    );
    let source_lock: toml::Value = toml::from_str(SOURCE_LOCK).expect("source lock");
    assert_eq!(
        contract["contract_versions"]["state"].as_u64(),
        source_lock["contract_versions"]["state"]
            .as_integer()
            .and_then(|value| u64::try_from(value).ok())
    );
    assert_eq!(
        contract["contract_versions"]["state"].as_u64(),
        manifest["workspace"]["metadata"]["radroots"]["service_source_lock"]
            ["state_contract_version"]
            .as_integer()
            .and_then(|value| u64::try_from(value).ok())
    );
    assert_eq!(
        manifest["profile"]["release"],
        toml::Value::Table(toml::toml! {
            lto = "thin"
            codegen-units = 1
            overflow-checks = true
            strip = "symbols"
            panic = "unwind"
        })
    );
    assert_eq!(
        CARGO_CONFIG,
        "[alias]\nxtask = \"run --locked -p rhi_xtask --\"\n"
    );
    for required in [
        "ExecStart=/usr/bin/rhi --profile service-host --instance %i run",
        "ConfigDirectory=radroots/services/rhi/%i",
        "StateDirectory=radroots/services/rhi/%i",
        "CacheDirectory=radroots/services/rhi/%i",
        "LogsDirectory=radroots/services/rhi/%i",
        "RuntimeDirectory=radroots/services/rhi/%i",
        "UMask=0077",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
    ] {
        assert!(SYSTEMD_UNIT.contains(required), "missing `{required}`");
    }
}

#[test]
fn every_radroots_dependency_is_exactly_source_locked() {
    let manifest: toml::Value = toml::from_str(MANIFEST).expect("Cargo manifest");
    let dependencies = manifest["dependencies"].as_table().expect("dependencies");
    let radroots = dependencies
        .iter()
        .filter(|(name, _)| name.starts_with("radroots_"))
        .collect::<Vec<_>>();
    assert_eq!(radroots.len(), 12);
    for (name, dependency) in radroots {
        let dependency = dependency.as_table().expect("detailed dependency");
        assert_eq!(
            dependency.get("git").and_then(toml::Value::as_str),
            Some(LIB_REPOSITORY),
            "{name}"
        );
        assert_eq!(
            dependency.get("rev").and_then(toml::Value::as_str),
            Some(LIB_REVISION),
            "{name}"
        );
        assert_eq!(
            dependency.get("version").and_then(toml::Value::as_str),
            Some("=0.1.0-alpha"),
            "{name}"
        );
        for forbidden in ["path", "branch", "tag"] {
            assert!(
                !dependency.contains_key(forbidden),
                "{name} contains `{forbidden}`"
            );
        }
    }
    assert!(!MANIFEST.contains("[patch."));

    let sources = LOCK
        .lines()
        .filter_map(|line| line.strip_prefix("source = \"git+"))
        .filter_map(|line| line.strip_suffix('"'))
        .filter(|source| source.contains("radrootslabs/lib"))
        .collect::<BTreeSet<_>>();
    assert_eq!(sources.len(), 1);
    let source = sources.into_iter().next().expect("Lib source");
    assert!(source.contains(&format!("?rev={LIB_REVISION}#{LIB_REVISION}")));

    assert!(SOURCE_LOCK.contains("\n[nix]\nmaterial = \"absent\"\n"));
    assert!(!SOURCE_LOCK.contains("lib_revision ="));
    assert!(!SOURCE_LOCK.contains("flake_lock_sha256 ="));
}

#[test]
fn native_release_surfaces_remain_external_and_preterminal() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for required in [
        ".cargo/config.toml",
        "packaging/systemd/rhi@.service",
        "radroots.service.source-lock.v2.toml",
        "scripts/release-acceptance.sh",
        "tools/xtask/Cargo.toml",
        "tools/xtask/src/main.rs",
        "contracts/services_hardening/native_release.v1.json",
    ] {
        assert!(root.join(required).is_file(), "missing `{required}`");
    }
    assert!(
        !root
            .join("contracts/services_hardening/native_release.v2.json")
            .exists()
    );
    for forbidden in [
        ".github",
        ".act",
        "flake.nix",
        "flake.lock",
        "target",
        "result",
        "artifacts",
        "dist",
        "sbom.cdx.json",
        "provenance-input.v1.json",
        "oci-image.tar.gz",
    ] {
        assert!(
            !root.join(forbidden).exists(),
            "forbidden generated or deferred surface `{forbidden}` exists"
        );
    }
    assert!(!CONTRACT.contains("qualified"));
    assert!(!CONTRACT.contains("production_ready"));
    assert!(!CONTRACT.contains("oci-image"));
    assert!(!CONTRACT.contains("nixos-module"));
}

#[test]
fn release_acceptance_is_standalone_and_has_no_deferred_toolchain() {
    for required in [
        "cargo fmt --all --check",
        "cargo metadata --locked --format-version 1 --no-deps",
        "cargo check --locked --all-targets --no-default-features",
        "cargo check --locked --all-targets --no-default-features --features service-host",
        "cargo clippy --locked --all-targets -- -D warnings",
        "cargo test --locked",
        "cargo test --locked -p rhi_xtask",
        "git diff --check",
    ] {
        assert!(
            RELEASE_ACCEPTANCE.contains(required),
            "release acceptance is missing `{required}`"
        );
    }
    for forbidden in [
        "nix ",
        "nix-",
        "docker ",
        "podman ",
        "cosign ",
        "gh release",
    ] {
        assert!(
            !RELEASE_ACCEPTANCE.contains(forbidden),
            "release acceptance contains deferred or unauthorized command `{forbidden}`"
        );
    }
}

#[test]
fn release_tool_dependency_and_file_mode_boundaries_are_exact() {
    let manifest: toml::Value = toml::from_str(XTASK_MANIFEST).expect("xtask manifest");
    assert_eq!(manifest["package"]["name"].as_str(), Some("rhi_xtask"));
    assert_eq!(manifest["package"]["publish"].as_bool(), Some(false));
    let dependencies = manifest["dependencies"]
        .as_table()
        .expect("xtask dependencies")
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        dependencies,
        BTreeSet::from([
            "flate2",
            "hex",
            "serde",
            "serde_json",
            "sha2",
            "tar",
            "tempfile",
            "toml",
        ])
    );
    assert_eq!(
        manifest["target"]["cfg(unix)"]["dependencies"]
            .as_table()
            .expect("Unix dependencies")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["rustix"])
    );
    for forbidden in [
        "sqlx", "rusqlite", "reqwest", "tokio", "\nnix =", "nix::", "oci", "cosign", "path =",
        "git =",
    ] {
        assert!(
            !XTASK_MANIFEST.contains(forbidden),
            "release tool contains unauthorized dependency or authority `{forbidden}`"
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            std::fs::metadata(root.join("scripts/release-acceptance.sh"))
                .expect("release script metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            std::fs::metadata(root.join("packaging/systemd/rhi@.service"))
                .expect("systemd unit metadata")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }
}
