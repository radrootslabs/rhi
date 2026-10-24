#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

const MANIFEST: &str = include_str!("../Cargo.toml");
const SOURCE_LOCK: &str = include_str!("../radroots.service.source_lock.v4.toml");
const FLAKE_LOCK: &[u8] = include_bytes!("../flake.lock");

#[test]
fn manifest_freezes_the_native_service_policy() {
    assert!(MANIFEST.contains(
        "repository = \"https://github.com/radrootslabs/rhi\"\nreadme = \"README\"\npublish = false"
    ));
    assert!(MANIFEST.contains("[workspace]\nresolver = \"3\""));
    assert!(MANIFEST.contains("[workspace.lints.rust]\nunsafe_code = \"deny\""));
    assert!(MANIFEST.contains("[workspace.lints.rustdoc]\nbroken_intra_doc_links = \"deny\""));
    assert!(MANIFEST.contains(
        "[workspace.lints.clippy]\ndbg_macro = \"deny\"\ntodo = \"deny\"\nunimplemented = \"deny\""
    ));
    assert!(MANIFEST.contains("[lints]\nworkspace = true"));
    assert!(MANIFEST.contains("[features]\ndefault = [\"service-host\"]\nservice-host = []"));
}

#[test]
fn source_lock_metadata_is_exact_and_nix_is_bound() {
    assert!(MANIFEST.contains(
        "[workspace.metadata.radroots.service_source_lock]\nservice = \"rhi\"\nhost_feature_profile = \"service-host\"\nnix_material = \"bound\""
    ));
    for field in [
        "config_contract_version = 1",
        "state_contract_version = 11",
        "admin_contract_version = 1",
        "status_contract_version = 1",
        "provider_contract_version = 1",
    ] {
        assert!(
            MANIFEST.contains(field),
            "missing source-lock field {field}"
        );
    }
}

#[test]
fn shared_host_packages_are_exactly_source_locked() {
    for dependency in ["radroots_service_host", "radroots_service_sqlite"] {
        assert!(MANIFEST.contains(&format!(
            "{dependency} = {{ git = \"https://github.com/radrootslabs/lib\", rev = \"e55c1749902811732167a2ce5c099e22e964624f\", version = \"=0.1.0-alpha\" }}"
        )));
    }
}

#[test]
fn shared_service_sqlite_is_the_only_catalog_authority() {
    assert!(MANIFEST.contains(
        "radroots_service_sqlite = { git = \"https://github.com/radrootslabs/lib\", rev = \"e55c1749902811732167a2ce5c099e22e964624f\", version = \"=0.1.0-alpha\" }"
    ));
    for forbidden in ["rusqlite", "libsqlite3-sys"] {
        assert!(
            !MANIFEST.contains(forbidden),
            "RHI must not introduce alternate SQLite authority `{forbidden}`"
        );
    }
}

#[test]
fn shared_storage_generation_type_is_exactly_source_locked() {
    assert!(MANIFEST.contains(
        "radroots_storage = { git = \"https://github.com/radrootslabs/lib\", rev = \"e55c1749902811732167a2ce5c099e22e964624f\", version = \"=0.1.0-alpha\", default-features = false }"
    ));
}

#[test]
fn shared_transport_spi_is_exactly_source_locked_without_serde() {
    assert!(MANIFEST.contains(
        "radroots_transport = { git = \"https://github.com/radrootslabs/lib\", rev = \"e55c1749902811732167a2ce5c099e22e964624f\", version = \"=0.1.0-alpha\", default-features = false, features = [\"std\"] }"
    ));
    assert!(MANIFEST.contains(
        "radroots_transport_nostr = { git = \"https://github.com/radrootslabs/lib\", rev = \"e55c1749902811732167a2ce5c099e22e964624f\", version = \"=0.1.0-alpha\" }"
    ));
    assert!(MANIFEST.contains(
        "radroots_transport_nostr_native = { git = \"https://github.com/radrootslabs/lib\", rev = \"e55c1749902811732167a2ce5c099e22e964624f\", version = \"=0.1.0-alpha\" }"
    ));
}

#[test]
fn source_lock_binds_the_current_cargo_lock() {
    let digest = lower_hex(&Sha256::digest(include_bytes!("../Cargo.lock")));
    let flake_digest = lower_hex(&Sha256::digest(FLAKE_LOCK));
    assert!(SOURCE_LOCK.starts_with(
        "schema = \"radroots.service.source_lock.v4\"\ncontract_version = 4\nservice = \"rhi\"\n"
    ));
    assert!(SOURCE_LOCK.contains(&format!("cargo_lock_sha256 = \"{digest}\"")));
    assert!(SOURCE_LOCK.contains(&format!("sha256 = \"{flake_digest}\"")));
    assert!(SOURCE_LOCK.contains("revision = \"e55c1749902811732167a2ce5c099e22e964624f\""));
    assert!(SOURCE_LOCK.contains(
        "workspace_catalog_sha256 = \"424909855b2af1ffc8fa6bbfd5aa0e6d17642662c18212fef4660e71700fbfc8\""
    ));
    assert!(SOURCE_LOCK.contains(
        "source_archive_sha256 = \"5e6005a01402ed60225ec5207cb0db465a0d1cd4c8107e0505d2af0762dc57c0\""
    ));
    assert!(SOURCE_LOCK.contains(
        "[nix]\nmaterial = \"bound\"\nlib_revision = \"e55c1749902811732167a2ce5c099e22e964624f\"\nsupported_systems = [\"aarch64-darwin\", \"x86_64-linux\"]\n"
    ));
    assert!(SOURCE_LOCK.ends_with(
        "[contract_versions]\nconfig = 1\nstate = 11\nadmin = 1\nstatus = 1\nprovider = 1\n"
    ));
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
