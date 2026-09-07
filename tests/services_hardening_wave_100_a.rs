#![forbid(unsafe_code)]

use std::path::Path;

use rhi::{RHI_CONFIG_SCHEMA, RhiConfigProfile, parse_rhi_config_v1};
use serde_json::Value;

const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONFIG_SCHEMA: &str = include_str!("../contracts/services_hardening/config.v1.schema.json");
const SOURCE_LOCK: &str = include_str!("../radroots.service.source-lock.v3.toml");

#[test]
fn canonical_example_agrees_with_the_exact_schema_and_parser() {
    let schema: Value = serde_json::from_str(CONFIG_SCHEMA).expect("configuration schema");
    let example: toml::Value = toml::from_str(CONFIG_EXAMPLE).expect("canonical example TOML");
    let example = serde_json::to_value(example).expect("canonical example JSON projection");
    let errors = jsonschema::validator_for(&schema)
        .expect("configuration schema compiles")
        .iter_errors(&example)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(errors.is_empty(), "schema/parser example drift: {errors:?}");

    let document = parse_rhi_config_v1(CONFIG_EXAMPLE.as_bytes(), RhiConfigProfile::Production)
        .expect("the canonical example must pass the production parser");
    assert_eq!(document.schema(), RHI_CONFIG_SCHEMA);
    assert_eq!(document.profile(), RhiConfigProfile::Production);
    assert!(document.effective().field_count() > 0);
}

#[test]
fn wave_one_removed_files_remain_absent_after_nix_qualification() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for removed in [
        "config.toml",
        "radroots.lib.source-lock.v1.toml",
        "src/config.rs",
        "src/host_nostr.rs",
        "src/host_runtime.rs",
        "src/rhi.rs",
    ] {
        assert!(
            !root.join(removed).exists(),
            "removed path remains: {removed}"
        );
    }
    assert!(!root.join("radroots.service.source-lock.v2.toml").exists());
    assert!(root.join("radroots.service.source-lock.v3.toml").is_file());
    assert!(root.join("flake.nix").is_file());
    assert!(root.join("flake.lock").is_file());
    assert!(SOURCE_LOCK.starts_with(
        "schema = \"radroots.service.source-lock.v3\"\ncontract_version = 3\nservice = \"rhi\"\n"
    ));
    assert!(SOURCE_LOCK.contains("material = \"qualified\""));
    assert!(SOURCE_LOCK.contains("lib_revision = \"055096853fca95e15d0f813d33a14aca13be3881\""));
}

#[test]
fn executable_has_no_prototype_runtime_fallback() {
    let main = include_str!("../src/main.rs");
    for forbidden in [
        "load_settings_from_path",
        "run_rhi",
        "init_rhi_logging",
        "tokio::runtime",
        "tracing_subscriber",
        "RHI_",
    ] {
        assert!(
            !main.contains(forbidden),
            "executable retains prototype fallback: {forbidden}"
        );
    }
    assert!(main.contains("parse_rhi_cli_v1_from"));
    assert!(main.contains("execute_rhi_cli_v1_with_signal_source"));
    assert!(main.contains("RhiProcessResult::InputOrConfiguration"));
    let process = include_str!("../src/process_v1.rs");
    assert!(process.contains("resolve_rhi_runtime_context"));
}
