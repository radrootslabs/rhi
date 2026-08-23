#![forbid(unsafe_code)]

use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/encrypted_identity_envelope.v1.json");
const ENVELOPE_SOURCE: &str = include_str!("../src/identity_envelope.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");

#[test]
fn machine_contract_freezes_the_exact_envelope_and_backup_boundary() {
    let actual: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(
        actual,
        json!({
            "schema": "radroots.rhi.encrypted-identity-envelope",
            "schema_version": 1,
            "contract_version": 1,
            "radroots_secrets_envelope_version": 2,
            "encoded_max_bytes": 262144,
            "identity_secret_bytes": 32,
            "wrapping_credential_bytes": 32,
            "provisioning_entropy": {
                "data_key_bytes": 32,
                "envelope_nonce_bytes": 24,
                "wrapping_nonce_bytes": 24,
                "caller_supplied": true
            },
            "authenticated_context": {
                "purpose": "radroots.rhi.encrypted_identity",
                "subject_type": "provider_identity",
                "subject_value": "service:<expected_public_key>",
                "payload_schema": "radroots.rhi.identity_secret.v1",
                "credential_reference_bound": true
            },
            "artifact": {
                "create_new": true,
                "overwrite": false,
                "symlink_follow": false,
                "regular_file": true,
                "single_link": true,
                "owner_uid": "effective_uid",
                "create_mode_octal": "0600",
                "read_modes_octal": ["0400", "0600"]
            },
            "verification": {
                "expected_identity_required": true,
                "derived_public_key_must_match": true,
                "legacy_envelope_accepted": false,
                "ordinary_run_provisions": false
            },
            "backup": {
                "state_backup_includes_envelope": false,
                "state_backup_includes_wrapping_credential": false,
                "state_backup_includes_plaintext_identity": false
            }
        })
    );
}

#[test]
fn implementation_uses_shared_envelopes_and_seals_credential_resolution() {
    for required in [
        "EncryptedEnvelope::seal(",
        "EncryptedEnvelope::decode(",
        ".open(&opener, expected_context)",
        "binding.role().as_str()",
        "OFlags::CREATE",
        "OFlags::EXCL",
        "OFlags::NOFOLLOW",
        "Mode::RUSR | Mode::WUSR",
        "RhiEncryptedIdentityEnvelopeErrorKind::MalformedEnvelope",
    ] {
        assert!(
            ENVELOPE_SOURCE.contains(required),
            "missing envelope boundary `{required}`"
        );
    }
    for forbidden in [
        "pub fn from_bytes",
        "pub fn from_resolved_bytes",
        "std::env::",
        "process::Command",
        "keyring::",
        "LEGACY_ENVELOPE_VERSION",
        "open_legacy_v1",
        "reseal_legacy_v1",
        ".key\"",
        "create_dir_all",
    ] {
        assert!(
            !ENVELOPE_SOURCE.contains(forbidden),
            "forbidden envelope authority `{forbidden}`"
        );
    }
    assert!(LIB_SOURCE.contains("mod identity_envelope;"));
    assert!(!LIB_SOURCE.contains("pub mod identity_envelope;"));
}

#[test]
fn public_models_disclose_no_path_or_secret_escape() {
    for required in [
        "pub struct RhiIdentityEnvelopeBinding",
        "pub struct RhiWrappingCredential(",
        "pub struct RhiEncryptedIdentityProvisioningMaterial",
        "pub struct RhiDecryptedIdentity",
        "formatter.write_str(\"RhiWrappingCredential([redacted])\")",
        "Zeroizing<[u8; WRAPPING_CREDENTIAL_BYTES]>",
        "identity_secret: Zeroizing<[u8; IDENTITY_SECRET_BYTES]>",
        "impl Error for RhiEncryptedIdentityEnvelopeError {}",
    ] {
        assert!(
            ENVELOPE_SOURCE.contains(required),
            "missing sealed boundary `{required}`"
        );
    }
    for forbidden in [
        "pub path:",
        "pub source:",
        "pub credential:",
        "pub secret:",
        "pub data_key:",
        "pub envelope_nonce:",
        "pub wrapping_nonce:",
        "pub fn expose_secret",
        "pub fn encrypted_envelope_path",
    ] {
        assert!(!ENVELOPE_SOURCE.contains(forbidden));
    }
}

#[test]
fn state_backup_contract_excludes_every_identity_material_class() {
    let value: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(
        value["backup"],
        json!({
            "state_backup_includes_envelope": false,
            "state_backup_includes_wrapping_credential": false,
            "state_backup_includes_plaintext_identity": false
        })
    );
}
