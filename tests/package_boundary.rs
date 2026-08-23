#![forbid(unsafe_code)]

const MANIFEST: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README");
const AGENTS: &str = include_str!("../AGENTS.md");
const ROOT: &str = include_str!("../src/lib.rs");
const ADAPTERS: &str = include_str!("../src/adapters/mod.rs");
const NOSTR_ADAPTERS: &str = include_str!("../src/adapters/nostr/mod.rs");
const FEATURES: &str = include_str!("../src/features/mod.rs");
const RUNTIME_ADAPTERS: &str = include_str!("../src/runtime_adapters.rs");
const RUNTIME_ADAPTER_CONTRACT: &str =
    include_str!("../contracts/services_hardening/runtime_adapters.v1.json");
const RUNTIME_FOUNDATION: &str = include_str!("../src/runtime_foundation.rs");
const RUNTIME_FOUNDATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/runtime_foundation.v1.json");
const PUBLIC_API: &str = include_str!("../contracts/api_baselines/rhi.txt");
const SOURCES: &[&str] = &[
    include_str!("../src/adapters/nostr/event.rs"),
    include_str!("../src/cli_v1.rs"),
    include_str!("../src/config_v1.rs"),
    include_str!("../src/features/trade_agreement_attestation.rs"),
    include_str!("../src/identity_credential.rs"),
    include_str!("../src/identity_envelope.rs"),
    include_str!("../src/runtime_context.rs"),
    include_str!("../src/runtime_adapters.rs"),
    include_str!("../src/runtime_foundation.rs"),
    include_str!("../src/state_catalog.rs"),
    include_str!("../src/state_config.rs"),
    include_str!("../src/state_host.rs"),
    include_str!("../src/state_maintenance.rs"),
    include_str!("../src/state_metadata.rs"),
    include_str!("../src/state_repository.rs"),
];

#[test]
fn package_identity_is_standalone_and_non_publishable() {
    assert!(MANIFEST.contains("name = \"rhi\""));
    assert!(MANIFEST.contains("repository = \"https://github.com/radrootslabs/rhi\""));
    assert!(MANIFEST.contains("readme = \"README\""));
    assert!(MANIFEST.contains("publish = false"));
    for forbidden in [
        "path = \"../",
        "path = \"../../",
        "enterprise/",
        "ops/",
        "foundation/",
    ] {
        assert!(
            !MANIFEST.contains(forbidden),
            "standalone package retains forbidden dependency surface {forbidden}"
        );
    }
}

#[test]
fn shared_runtime_contracts_are_curated_without_exposing_implementation_authority() {
    for forbidden in [
        "pub use radroots_service_sqlite",
        "pub mod service_host",
        "pub mod service_sqlite",
        "sqlx::Pool",
        "sqlx::SqliteConnection",
        "SystemEntropy",
        "SystemMonotonicClock",
        "SystemWallClock",
        "TaskSupervisor",
        "CancellationToken",
    ] {
        assert!(
            !ROOT.contains(forbidden),
            "RHI public root exposes private host implementation {forbidden}"
        );
    }
    assert!(!PUBLIC_API.contains("radroots_service_host::HostError"));
    assert!(!PUBLIC_API.contains("radroots_service_host::TaskSupervisor"));
}

#[test]
fn state_catalog_module_is_private_and_root_api_is_curated() {
    for module in [
        "adapters",
        "cli_v1",
        "config_v1",
        "features",
        "identity_credential",
        "identity_envelope",
        "runtime_context",
        "runtime_adapters",
        "runtime_foundation",
        "state_catalog",
        "state_config",
        "state_host",
        "state_maintenance",
        "state_metadata",
        "state_repository",
    ] {
        assert!(
            ROOT.contains(&format!("mod {module};")),
            "RHI root is missing private module {module}"
        );
        assert!(
            !ROOT.contains(&format!("pub mod {module};")),
            "RHI root exposes module {module}"
        );
    }
    assert!(ADAPTERS.contains("pub(crate) mod nostr;"));
    assert!(NOSTR_ADAPTERS.contains("pub(crate) mod event;"));
    assert!(FEATURES.contains("pub(crate) mod trade_agreement_attestation;"));
    assert!(ROOT.contains("#![doc = include_str!(\"../README\")]"));
    for required in [
        "NostrEventAdapter",
        "TradeAgreementAttestationPolicy",
        "TradeAgreementAttestationErrorKind",
        "rhi_migration_catalog",
        "rhi_schema_catalog",
        "validate_rhi_state_catalogs",
        "RhiStateCatalogError",
        "RhiRuntimeAdapters",
        "RhiTimeEntropyAdapters",
        "RhiTransportAdapters",
        "RhiCredentialAccess",
        "RhiIdentityAccess",
        "RhiRuntimeFoundation",
        "RhiRuntimeReadiness",
        "open_rhi_runtime_foundation",
        "apply_rhi_configuration",
        "RhiConfigApplyOutcome",
        "WallClock",
        "MonotonicClock",
        "EntropySource",
        "EntropyError",
        "WallClockError",
        "MonotonicClockError",
    ] {
        assert!(
            ROOT.contains(required),
            "RHI root API is missing {required}"
        );
    }

    let public_modules = PUBLIC_API
        .lines()
        .filter(|line| line.starts_with("pub mod "))
        .collect::<Vec<_>>();
    assert_eq!(public_modules, ["pub mod rhi"]);
    assert!(PUBLIC_API.contains("pub struct rhi::NostrEventAdapter<'a>"));
    assert!(PUBLIC_API.contains("pub struct rhi::TradeAgreementAttestationError"));
    assert!(!PUBLIC_API.contains("rhi::adapters::"));
    assert!(!PUBLIC_API.contains("rhi::features::"));
    assert!(!PUBLIC_API.contains("rhi::runtime_adapters::"));
}

#[test]
fn public_errors_are_crate_owned_redacted_and_source_free() {
    let production = SOURCES.join("\n");
    assert!(!production.contains("fn source("));
    for forbidden in [
        "source: std::io::Error",
        "source: sqlx::Error",
        "source: serde_json::Error",
        "source: toml::de::Error",
        "source: url::ParseError",
    ] {
        assert!(
            !production.contains(forbidden),
            "raw error source `{forbidden}` escaped"
        );
    }
    for forbidden in [
        "serde_json::Error",
        "radroots_event::trade::TradeProtocolError",
        "sqlx::Error",
        "std::io::Error",
        "thiserror::",
    ] {
        assert!(
            !PUBLIC_API.contains(forbidden),
            "reviewed API exposes dependency error `{forbidden}`"
        );
    }
    let public_error_count = PUBLIC_API
        .lines()
        .filter(|line| line.starts_with("pub struct rhi::") && line.ends_with("Error"))
        .count();
    assert_eq!(public_error_count, 13);
}

#[test]
fn runtime_foundation_is_existing_only_passive_and_process_neutral() {
    let contract: serde_json::Value =
        serde_json::from_str(RUNTIME_FOUNDATION_CONTRACT).expect("runtime foundation contract");
    assert_eq!(contract["schema"], "radroots.rhi.runtime-foundation");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["state_open"]["initialize_if_missing"], false);
    assert_eq!(
        contract["state_open"]["durable_configuration_binding_required"],
        true
    );
    assert_eq!(contract["transport"]["invoked_during_foundation"], false);
    assert_eq!(contract["task_ownership"]["task_handles_exposed"], false);
    for required in [
        "open_rhi_state_read_write_from_config",
        "RhiIdentityEnvelopeBinding::from_configuration",
        ".identity_credential()",
        "startup_readiness(&configuration)",
    ] {
        assert!(RUNTIME_FOUNDATION.contains(required));
    }
    for forbidden in [
        "tokio::runtime",
        "tokio::signal",
        "signal_hook",
        "tracing_subscriber",
        "std::process::exit",
        ".fetch(",
        ".subscribe(",
        ".deliver(",
    ] {
        assert!(!RUNTIME_FOUNDATION.contains(forbidden));
    }
}

#[test]
fn runtime_adapter_boundary_is_exact_bounded_and_process_neutral() {
    let contract: serde_json::Value =
        serde_json::from_str(RUNTIME_ADAPTER_CONTRACT).expect("runtime adapter contract");
    assert_eq!(contract["schema"], "radroots.rhi.runtime-adapters");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["jitter"]["inclusive_maximum"], 3_600_000);
    assert_eq!(contract["jitter"]["maximum_entropy_draws"], 16);
    assert_eq!(contract["jitter"]["wall_clock_derived"], false);
    assert_eq!(contract["transport"]["evidence_fetch"], "EventSource");
    assert_eq!(
        contract["transport"]["evidence_subscription"],
        "EventSubscriber"
    );
    assert_eq!(contract["transport"]["publication"], "EventSink");
    assert_eq!(
        contract["identity"]["order"],
        serde_json::json!(["credential", "encrypted_identity"])
    );
    assert_eq!(contract["identity"]["fallback"], false);
    assert_eq!(contract["identity"]["generation"], false);
    assert_eq!(contract["tasks"]["join_owned"], true);
    assert_eq!(contract["tasks"]["handles_exposed"], false);

    for required in [
        "Arc<dyn WallClock>",
        "Arc<dyn MonotonicClock>",
        "Arc<dyn EntropySource>",
        "Arc<dyn EventSource>",
        "Arc<dyn EventSubscriber>",
        "Arc<dyn EventSink>",
        "TaskSupervisor",
        "RHI_RUNTIME_JITTER_MAX_MILLISECONDS: u64 = 3_600_000",
        "RHI_RUNTIME_JITTER_MAX_ENTROPY_DRAWS: usize = 16",
        "u128::from(u64::from_be_bytes(bytes)) * u128::from(range)",
        "low >= rejection_threshold",
        "resolve_rhi_wrapping_credential(runtime, binding)",
        "open_rhi_encrypted_identity(binding, credential)",
    ] {
        assert!(
            RUNTIME_ADAPTERS.contains(required),
            "runtime adapter boundary is missing {required}"
        );
    }
    for forbidden in [
        "tokio::runtime::Runtime",
        "tokio::runtime::Builder",
        "tokio::signal",
        "signal_hook",
        "tracing_subscriber",
        "std::process::exit",
        "tokio::spawn",
        "std::thread::spawn",
        "SystemTime::now",
        "subsec_nanos",
        "rand::",
    ] {
        assert!(
            !RUNTIME_ADAPTERS.contains(forbidden),
            "runtime adapter boundary contains forbidden authority {forbidden}"
        );
    }
    assert!(MANIFEST.contains("radroots_transport ="));
    assert!(MANIFEST.contains("default-features = false, features = [\"std\"]"));
}

#[test]
fn readme_freezes_the_root_only_boundary_and_exact_baseline() {
    for required in [
        "## Public API boundary",
        "one curated crate-root API",
        "public errors use RHI-owned stable classifications",
        "shared clock and entropy traits and their source-free error values",
        "failures into stable RHI classifications",
        "```compile_fail",
        "[RHI API baseline](contracts/api_baselines/rhi.txt)",
        "## Injected runtime adapters",
        "whole-second wall UTC",
        "process-local monotonic time",
        "exact v1 maximum of 3,600,000",
        "fails closed after sixteen rejected entropy draws",
        "never derived from wall-clock",
        "Constructing the adapter set performs no clock read",
        "no signal handler, Tokio runtime, logger, or process-exit policy",
        "[`runtime_adapters.v1.json`](contracts/services_hardening/runtime_adapters.v1.json)",
        "## Existing-state runtime foundation",
        "opens only an already initialized database",
        "No evidence source, live subscription, or publication sink is",
        "[`runtime_foundation.v1.json`](contracts/services_hardening/runtime_foundation.v1.json)",
        "at most 1,024 consecutive generations",
        "never stores raw TOML, paths, relay URLs, credential",
    ] {
        assert!(README.contains(required), "README is missing {required}");
    }
    for required in [
        "Keep every implementation module private",
        "contracts/api_baselines/rhi.txt",
        "Public errors must use RHI-owned stable classifications",
        "no raw dependency-owned source chain",
        "Compose those dependencies only through the sealed runtime-adapter boundary",
        "exposes no task handle or concrete transport handle",
    ] {
        assert!(AGENTS.contains(required), "AGENTS is missing {required}");
    }
}

#[test]
fn human_verification_contract_is_extbuild_only_through_rcld_170() {
    for required in [
        "cargo extbuild doctor",
        "cargo extbuild run -- cargo fmt --all --check",
        "cargo extbuild run -- cargo check --workspace --all-targets --locked",
        "cargo extbuild run -- cargo test --workspace --all-targets --locked",
        "cargo extbuild run -- cargo clippy --workspace --all-targets --locked -- -D warnings",
        "Nix-produced OCI artifacts are deferred and unclaimed",
    ] {
        assert!(README.contains(required), "README is missing {required}");
    }
    for forbidden in ["nix run", "nix develop", "nix build", "nix flake"] {
        assert!(
            !README.contains(forbidden),
            "README retains forbidden active Nix command {forbidden}"
        );
    }
}
