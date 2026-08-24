#![forbid(unsafe_code)]

use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/publication_attempt_evidence.v1.json");
const SOURCE: &str = include_str!("../src/publication_attempt.rs");
const ROOT: &str = include_str!("../src/lib.rs");

#[test]
fn exact_target_and_attempt_vocabularies_are_closed() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.publication-attempt-evidence"
    );
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(
        contract["target_states"],
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
    assert_eq!(
        contract["attempt_outcomes"],
        json!([
            "submitted",
            "accepted",
            "rejected",
            "rate_limited",
            "auth_required",
            "failed",
            "unknown"
        ])
    );
    assert_eq!(contract["bounds"]["target_ordinal"]["maximum"], 31);
    assert_eq!(contract["bounds"]["attempt_number"]["maximum"], 100);
    assert_eq!(
        contract["bounds"]["unix_milliseconds"]["maximum"],
        9_223_372_036_854_775_807_u64
    );
    assert_eq!(contract["evidence"]["raw_relay_result_or_error"], false);
    assert_eq!(
        contract["semantics"]["submission_alone_proves_delivery"],
        false
    );
    assert_eq!(contract["effects"]["sqlite_read_or_mutation"], false);
    assert_eq!(contract["effects"]["relay_or_network"], false);
}

#[test]
fn pure_model_has_no_premature_workflow_or_effect_authority() {
    for required in [
        "pub enum RhiPublicationTargetState",
        "pub enum RhiPublicationAttemptOutcome",
        "pub struct RhiPublicationAttemptEvidence",
        "pub struct RhiPublicationAttemptId",
        "pub struct RhiPublicationUnixMilliseconds",
        "radroots.rhi.publication_attempt.v1\\0",
        "publication.outbox_id()",
        "publication.event_sha256()",
        "digest.update(u32::from(target_ordinal).to_be_bytes())",
        "digest.update(u32::from(attempt_number).to_be_bytes())",
    ] {
        assert!(
            SOURCE.contains(required),
            "missing evidence guard {required}"
        );
    }
    for forbidden in [
        "sqlx::",
        "radroots_transport",
        "EventSink",
        "SystemTime",
        "std::fs",
        "std::net",
        "tokio::spawn",
        "spawn_blocking",
        "serde_json",
        "publish(",
        "send(",
        "from_committed_parts",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "attempt evidence gained forbidden authority {forbidden}"
        );
    }
    assert!(ROOT.contains("mod publication_attempt;"));
    assert!(!ROOT.contains("pub mod publication_attempt;"));
}
