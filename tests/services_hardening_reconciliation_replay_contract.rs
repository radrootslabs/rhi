#![forbid(unsafe_code)]

use rhi::RHI_RECONCILIATION_REPLAY_CONTRACT_VERSION;
use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_replay.v1.json");
const ROOT: &str = include_str!("../src/lib.rs");
const SOURCE: &str = include_str!("../src/reconciliation_replay.rs");
const README: &str = include_str!("../README");

#[test]
fn machine_contract_freezes_the_complete_step_189_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-replay");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_RECONCILIATION_REPLAY_CONTRACT_VERSION
    );
    assert_eq!(contract["state_schema_version"], 5);
    assert_eq!(
        contract["replay_identity"]["domain"],
        "radroots.rhi.reconciliation_source_replay.v1\\0"
    );
    assert_eq!(
        contract["replay_identity"]["exact_vector"]["replay_id_hex"],
        "2490a2e9a6e85051e92f6c2fc2ff7e98a1367afd6c26f8625eb421cd2ab30c68"
    );
    assert_eq!(
        contract["cursor"]["tuple"],
        json!(["event_authored_unix_seconds", "verified_event_id"])
    );
    assert_eq!(contract["cursor"]["equal_timestamp_safe"], true);
    assert_eq!(
        contract["cursor"]["input"],
        "sealed_step_190_committed_cursor_evidence"
    );
    assert_eq!(
        contract["cursor"]["scope"],
        json!([
            "source_id",
            "trade_id",
            "evidence_policy_digest",
            "selector_digest"
        ])
    );
    assert_eq!(
        contract["cursor"]["eligible_only_for"],
        "complete_and_strictly_after_prior_cursor"
    );
    assert_eq!(
        contract["inventory"]["signed_event_identity"],
        json!(["verified_event_id", "verified_signature"])
    );
    assert_eq!(
        contract["inventory"]["first_provenance"],
        "earliest_injected_observation_time_retained"
    );
    assert_eq!(contract["effects"]["sqlite"], false);
    assert_eq!(contract["effects"]["source_or_relay"], false);
    assert_eq!(contract["effects"]["ambient_clock"], false);
    assert_eq!(contract["effects"]["ambient_entropy"], false);
    assert_eq!(
        contract["deferred"],
        json!([
            "source_execution",
            "durable_source_result_commit",
            "durable_scope_revalidation",
            "checkpoint_advance",
            "manifest",
            "reducer",
            "attestation",
            "publication"
        ])
    );
}

#[test]
fn replay_model_is_private_bounded_pure_and_documented() {
    assert!(ROOT.contains("mod reconciliation_replay;"));
    assert!(!ROOT.contains("pub mod reconciliation_replay;"));
    for required in [
        "RhiReconciliationSourceReplayPlan",
        "RhiReconciliationSourceReplay",
        "RhiReconciliationSourceCursorEvidence",
        "RhiReconciliationReplayError",
    ] {
        assert!(ROOT.contains(required), "root API is missing {required}");
    }
    for required in [
        ".take(maximum_events.saturating_add(1))",
        "saturating_sub(overlap_seconds)",
        "cursor_scope_matches(",
        "fn eligible_cursor(",
        "RhiTradeSourceCompletion::Complete",
        "RhiReconciliationReplayErrorKind::MutationConflict",
        "RhiReconciliationReplayErrorKind::SignedEventConflict",
    ] {
        assert!(
            SOURCE.contains(required),
            "replay boundary is missing {required}"
        );
    }
    for forbidden in [
        "sqlx::",
        "std::fs",
        "std::net",
        "tokio::",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "pub fn cursor_evidence",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "replay model gained deferred authority {forbidden}"
        );
    }
    assert!(README.contains("## Overlap-safe reconciliation replay"));
    assert!(README.contains(
        "[`reconciliation_replay.v1.json`](contracts/services_hardening/reconciliation_replay.v1.json)"
    ));
}
