#![forbid(unsafe_code)]

use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/publication_execution.v1.json");
const SOURCE: &str = include_str!("../src/publication_execution.rs");
const ROOT: &str = include_str!("../src/lib.rs");

#[test]
fn execution_sequence_and_recovery_contract_are_exact() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(contract["schema"], "radroots.rhi.publication-execution");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(
        contract["claim"]["authority"],
        "exact_current_required_authority_and_target_set"
    );
    assert_eq!(
        contract["attempt"]["prepare_sequence"],
        json!([
            "revalidate_exact_unexpired_lease",
            "validate_complete_immutable_target_inventory",
            "select_first_due_target_by_ordinal",
            "increment_attempt_and_persist_submitted",
            "read_and_verify_exact_committed_event_bytes",
            "return_sealed_exact_byte_capability"
        ])
    );
    assert_eq!(contract["attempt"]["remote_io_outside_transaction"], true);
    assert_eq!(
        contract["retry"]["algorithm"],
        "full_jitter_exponential_cap"
    );
    assert_eq!(
        contract["retry"]["retryable_outcomes"],
        json!(["rate_limited", "failed", "unknown"])
    );
    assert_eq!(
        contract["cancellation_and_recovery"]["lost_acknowledgement"],
        "unknown_until_independent_evidence"
    );
    assert_eq!(contract["exact_byte_sink"]["parse"], false);
    assert_eq!(contract["exact_byte_sink"]["rebuild"], false);
    assert_eq!(contract["exact_byte_sink"]["reserialize"], false);
    assert_eq!(contract["exact_byte_sink"]["resign"], false);
}

#[test]
fn source_uses_only_the_sealed_sqlx_and_exact_byte_boundaries() {
    for required in [
        "pub trait RhiExactPublicationSink: Send + Sync",
        "pub const fn exact_signed_event_bytes(&self) -> &[u8]",
        "PREPARE_TARGET_SQL",
        "INSERT_ATTEMPT_SQL",
        "UPDATE_TARGET_OUTCOME_SQL",
        "UPDATE_OUTBOX_AFTER_ATTEMPT_SQL",
        "UPDATE_OUTBOX_RECOVERY_SQL",
        "read_committed(transaction, lease.outbox.id)",
        "RhiPublicationAttemptOutcome::Unknown",
        "sample_full_jitter(bound)",
        "CommitOutcomeUnknown",
    ] {
        assert!(
            SOURCE.contains(required),
            "missing execution guard {required}"
        );
    }
    for forbidden in [
        "radroots_event_codec",
        "Nip01EventWire",
        "SignedEvent",
        "DeliveryPayload",
        "EventSink",
        "serde_json",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "tokio::spawn",
        "SqliteConnection",
        "SqlitePool",
        "std::fs",
        "std::net",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "execution gained forbidden authority {forbidden}"
        );
    }
    assert!(ROOT.contains("mod publication_execution;"));
    assert!(!ROOT.contains("pub mod publication_execution;"));
}
