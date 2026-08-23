#![forbid(unsafe_code)]

const MANIFEST: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README");
const AGENTS: &str = include_str!("../AGENTS.md");
const ROOT: &str = include_str!("../src/lib.rs");
const ADAPTERS: &str = include_str!("../src/adapters/mod.rs");
const NOSTR_ADAPTERS: &str = include_str!("../src/adapters/nostr/mod.rs");
const FEATURES: &str = include_str!("../src/features/mod.rs");
const PUBLIC_API: &str = include_str!("../contracts/api_baselines/rhi.txt");
const SOURCES: &[&str] = &[
    include_str!("../src/adapters/nostr/event.rs"),
    include_str!("../src/cli_v1.rs"),
    include_str!("../src/config_v1.rs"),
    include_str!("../src/features/trade_agreement_attestation.rs"),
    include_str!("../src/identity_credential.rs"),
    include_str!("../src/identity_envelope.rs"),
    include_str!("../src/runtime_context.rs"),
    include_str!("../src/state_catalog.rs"),
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
fn shared_host_implementations_do_not_escape_the_public_api() {
    for forbidden in [
        "pub use radroots_service_host",
        "pub use radroots_service_sqlite",
        "pub mod service_host",
        "pub mod service_sqlite",
        "sqlx::Pool",
        "sqlx::SqliteConnection",
    ] {
        assert!(
            !ROOT.contains(forbidden),
            "RHI public root exposes private host implementation {forbidden}"
        );
    }
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
        "state_catalog",
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
    assert_eq!(public_error_count, 10);
}

#[test]
fn readme_freezes_the_root_only_boundary_and_exact_baseline() {
    for required in [
        "## Public API boundary",
        "one curated crate-root API",
        "public errors use RHI-owned stable classifications",
        "```compile_fail",
        "[RHI API baseline](contracts/api_baselines/rhi.txt)",
    ] {
        assert!(README.contains(required), "README is missing {required}");
    }
    for required in [
        "Keep every implementation module private",
        "contracts/api_baselines/rhi.txt",
        "Public errors must use RHI-owned stable classifications",
        "no raw dependency-owned source chain",
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
