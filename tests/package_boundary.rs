#![forbid(unsafe_code)]

const MANIFEST: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README");
const ROOT: &str = include_str!("../src/lib.rs");

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
