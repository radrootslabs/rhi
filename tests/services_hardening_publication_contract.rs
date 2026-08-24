#![forbid(unsafe_code)]

use std::error::Error;

use rhi::{
    RHI_PUBLICATION_CONTRACT_VERSION, RHI_PUBLICATION_MAX_ATTEMPTS, RHI_PUBLICATION_MAX_TARGETS,
    RhiConfigProfile, RhiPublicationAuthority, RhiPublicationMode, parse_rhi_config_v1,
};
use serde_json::json;

const CONTRACT: &str = include_str!("../contracts/services_hardening/publication_outbox.v1.json");
const EXAMPLE: &[u8] = include_bytes!("../contracts/services_hardening/config.v1.example.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const PUBLICATION_SOURCE: &str = include_str!("../src/publication.rs");
const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const README: &str = include_str!("../README");

#[test]
fn machine_contract_freezes_step_198_authority_and_schema() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.publication-outbox");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_PUBLICATION_CONTRACT_VERSION
    );
    // This Step198 contract records the schema version that introduced the
    // outbox. Later forward-only migrations are governed by their own
    // contracts and must not silently rewrite this historical evidence.
    assert_eq!(contract["state_schema_version"], 7);
    assert_eq!(
        contract["publication_modes"],
        json!(["required", "disabled"])
    );
    assert_eq!(
        contract["authority"]["required"]["target_count"]["maximum"],
        RHI_PUBLICATION_MAX_TARGETS
    );
    assert_eq!(
        contract["schema_objects"]["immutable"],
        json!([
            "evidence_manifests",
            "trade_projections",
            "attestation_reports",
            "signed_attestation_events",
            "publication_attempts"
        ])
    );
    assert_eq!(
        contract["schema_objects"]["compare_and_swap"],
        json!(["publication_outbox", "publication_targets"])
    );
    assert_eq!(
        contract["schema_objects"]["target_states"],
        json!([
            "pending",
            "submitted",
            "accepted",
            "rejected",
            "rate_limited",
            "auth_required",
            "failed",
            "unknown"
        ])
    );
    assert_eq!(contract["payload"]["signed_bytes_maximum"], 32_768);
    assert_eq!(contract["effects"]["sqlite_query_or_mutation"], false);
    assert_eq!(contract["effects"]["relay_or_network"], false);
    for forbidden in [
        "implicit_publication_mode",
        "disabled_mode_target_or_retry_state",
        "caller_forged_target",
        "non_write_relay_target",
        "mutable_signed_payload",
        "mutable_target_identity",
        "raw_upstream_error_text",
        "raw_sqlite_handle",
        "relay_io",
        "event_rebuild",
        "event_reserialize",
        "event_resign",
        "unbounded_queue_or_target_inventory",
    ] {
        assert!(
            contract["forbidden"]
                .as_array()
                .expect("forbidden")
                .iter()
                .any(|value| value == forbidden),
            "missing forbidden boundary {forbidden}"
        );
    }
}

#[test]
fn canonical_example_has_literal_publication_identities() {
    let config = parse_rhi_config_v1(EXAMPLE, RhiConfigProfile::Production).expect("config");
    let authority = RhiPublicationAuthority::from_config(&config).expect("authority");
    assert_eq!(authority.mode(), RhiPublicationMode::Required);
    assert_eq!(authority.targets().len(), 2);
    let retry = authority.retry_policy().expect("retry");
    assert_eq!(retry.maximum_attempts(), 10);
    assert!(retry.maximum_attempts() <= RHI_PUBLICATION_MAX_ATTEMPTS);
    assert_eq!(
        lower_hex(authority.target_set_sha256()),
        "fc044570890935bc41f4763b92d0e079ea0288e0a77a03fc1e299a4c830bbd76"
    );
    assert_eq!(
        lower_hex(authority.authority_sha256()),
        "6df5c3bf1bbb5c7b57d81bd1ee600677501a05d6e3c3aaf7577d64ffcbd9566b"
    );
}

#[test]
fn module_and_side_effect_authority_remain_private_and_deferred() {
    assert!(LIB_SOURCE.contains("mod publication;"));
    assert!(!LIB_SOURCE.contains("pub mod publication;"));
    assert!(LIB_SOURCE.contains("RhiPublicationAuthority"));
    assert!(README.contains("## Explicit publication authority and durable schema"));
    assert!(README.contains(
        "[`publication_outbox.v1.json`](contracts/services_hardening/publication_outbox.v1.json)"
    ));
    for table in [
        "evidence_manifests",
        "trade_projections",
        "attestation_reports",
        "signed_attestation_events",
        "publication_outbox",
        "publication_targets",
        "publication_attempts",
    ] {
        assert!(CATALOG_SOURCE.contains(&format!("CREATE TABLE {table}")));
    }
    assert!(CATALOG_SOURCE.contains("OR OLD.state = 'accepted'"));
    assert!(CATALOG_SOURCE.contains("AND next_attempt_unix_ms IS NOT NULL"));
    assert!(CATALOG_SOURCE.contains("AND lease_owner IS NOT NULL"));
    assert!(CATALOG_SOURCE.contains("AND lease_expires_unix_ms IS NOT NULL"));
    for forbidden in [
        "sqlx::",
        "radroots_transport",
        "PublicationSink",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "std::fs",
        "std::net",
        "tokio::spawn",
        "spawn_blocking",
        "pub fn sqlite",
        "pub fn transaction",
        "pub fn connection",
        "pub fn into_inner",
    ] {
        assert!(
            !PUBLICATION_SOURCE.contains(forbidden),
            "premature publication authority {forbidden}"
        );
    }
}

#[test]
fn public_authority_debug_and_errors_reveal_no_targets_or_digests() {
    let config = parse_rhi_config_v1(EXAMPLE, RhiConfigProfile::Production).expect("config");
    let authority = RhiPublicationAuthority::from_config(&config).expect("authority");
    let rendered = format!("{authority:?}");
    assert!(!rendered.contains("relay-primary"));
    assert!(!rendered.contains(&lower_hex(authority.authority_sha256())));

    let invalid = core::str::from_utf8(EXAMPLE)
        .expect("utf8")
        .replace("mode = \"required\"", "mode = \"invalid-secret\"");
    let error = parse_rhi_config_v1(invalid.as_bytes(), RhiConfigProfile::Production)
        .expect_err("invalid config");
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("invalid-secret"));
    assert!(Error::source(&error).is_none());
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
