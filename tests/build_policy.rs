#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

const MANIFEST: &str = include_str!("../Cargo.toml");
const SOURCE_LOCK: &str = include_str!("../radroots.service.source-lock.v2.toml");

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
fn source_lock_metadata_is_exact_and_nix_is_absent() {
    assert!(MANIFEST.contains(
        "[workspace.metadata.radroots.service_source_lock]\nservice = \"rhi\"\nhost_feature_profile = \"service-host\"\nnix_material = \"absent\""
    ));
    for field in [
        "config_contract_version = 1",
        "state_contract_version = 6",
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
            "{dependency} = {{ git = \"https://github.com/radrootslabs/lib\", rev = \"21b11e7a5120ea949f7ad0838c746873fc73aac2\", version = \"=0.1.0-alpha\" }}"
        )));
    }
}

#[test]
fn shared_service_sqlite_is_the_only_catalog_authority() {
    assert!(MANIFEST.contains(
        "radroots_service_sqlite = { git = \"https://github.com/radrootslabs/lib\", rev = \"21b11e7a5120ea949f7ad0838c746873fc73aac2\", version = \"=0.1.0-alpha\" }"
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
        "radroots_storage = { git = \"https://github.com/radrootslabs/lib\", rev = \"21b11e7a5120ea949f7ad0838c746873fc73aac2\", version = \"=0.1.0-alpha\", default-features = false }"
    ));
}

#[test]
fn shared_transport_spi_is_exactly_source_locked_without_serde() {
    assert!(MANIFEST.contains(
        "radroots_transport = { git = \"https://github.com/radrootslabs/lib\", rev = \"21b11e7a5120ea949f7ad0838c746873fc73aac2\", version = \"=0.1.0-alpha\", default-features = false, features = [\"std\"] }"
    ));
}

#[test]
fn source_lock_binds_the_current_cargo_lock() {
    let digest = lower_hex(&Sha256::digest(include_bytes!("../Cargo.lock")));
    assert!(SOURCE_LOCK.starts_with(
        "schema = \"radroots.service.source-lock.v2\"\ncontract_version = 2\nservice = \"rhi\"\n"
    ));
    assert!(SOURCE_LOCK.contains(&format!("cargo_lock_sha256 = \"{digest}\"")));
    assert!(SOURCE_LOCK.contains("revision = \"21b11e7a5120ea949f7ad0838c746873fc73aac2\""));
    assert!(SOURCE_LOCK.contains(
        "workspace_catalog_sha256 = \"deca0c080deae187ff8186c0708903e42f41ea57f77c5f91581e23aa561164a4\""
    ));
    assert!(SOURCE_LOCK.contains(
        "source_archive_sha256 = \"7e584a4b679264620d7bb6cf0a7028cc7651b33977b263c213f4e7b29c0e5a19\""
    ));
    assert!(SOURCE_LOCK.contains("\n[nix]\nmaterial = \"absent\"\n"));
    assert!(!SOURCE_LOCK.contains("flake_lock_sha256"));
    assert!(!SOURCE_LOCK.contains("lib_revision ="));
    assert!(SOURCE_LOCK.ends_with(
        "[contract_versions]\nconfig = 1\nstate = 6\nadmin = 1\nstatus = 1\nprovider = 1\n"
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
