#![forbid(unsafe_code)]

use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/publication_submission.v1.json");

#[test]
fn exact_committed_submission_contract_is_closed() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(contract["schema"], "radroots.rhi.publication-submission");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["source"]["maximum_signed_event_bytes"], 32_768);
    assert_eq!(
        contract["source"]["required_bindings"],
        json!([
            "requested_outbox_id",
            "outbox_event_id_equals_event_id",
            "outbox_event_sha256_equals_event_sha256",
            "sha256_exact_stored_bytes_equals_event_sha256"
        ])
    );
    assert_eq!(contract["sealed_capability"]["forgeable"], false);
    assert_eq!(contract["sealed_capability"]["cloneable"], false);
    assert_eq!(contract["retry_and_recovery"]["parse_event"], false);
    assert_eq!(contract["retry_and_recovery"]["rebuild_event"], false);
    assert_eq!(contract["retry_and_recovery"]["reserialize_event"], false);
    assert_eq!(contract["retry_and_recovery"]["resign_event"], false);
    assert_eq!(contract["effects"]["sqlite_read"], true);
    assert_eq!(contract["effects"]["sqlite_mutation"], false);
    assert_eq!(contract["effects"]["relay_or_network"], false);
    for forbidden in [
        "caller_forged_committed_publication",
        "unbounded_blob_decode",
        "json_or_event_deserialization",
        "event_rebuild",
        "event_reserialization",
        "event_resigning",
        "raw_sqlite_handle",
        "relay_io",
        "hidden_retry_loop",
    ] {
        assert!(
            contract["forbidden"]
                .as_array()
                .expect("forbidden inventory")
                .iter()
                .any(|value| value == forbidden),
            "missing forbidden boundary {forbidden}"
        );
    }
}
