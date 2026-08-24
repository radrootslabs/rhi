#![forbid(unsafe_code)]

use rhi::{RHI_RECONCILIATION_ATTEMPT_CONTRACT_VERSION, RHI_RECONCILIATION_ATTEMPT_MAX_SOURCES};
use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_attempts.v1.json");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const ATTEMPT_SOURCE: &str = include_str!("../src/reconciliation_attempt.rs");
const README: &str = include_str!("../README");

#[test]
fn machine_contract_freezes_the_complete_step_188_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-attempts");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_RECONCILIATION_ATTEMPT_CONTRACT_VERSION
    );
    assert_eq!(contract["state_schema_version"], 5);
    assert_eq!(
        contract["configuration_authority"],
        "contracts/services_hardening/evidence_policy.v1.json"
    );
    assert_eq!(
        contract["attempt_identity"],
        json!({
            "algorithm": "sha256",
            "domain": "radroots.rhi.reconciliation_attempt.v1\\0",
            "preimage": ["job_id_32_bytes", "attempt_count_u16_be"]
        })
    );
    assert_eq!(
        contract["selector_identity"]["event_kinds"],
        json!([3470, 3471, 3472, 3473, 3474])
    );
    assert_eq!(contract["selector_identity"]["exact_tag"], "#d");
    assert_eq!(
        contract["selector_identity"]["cursor_binding"],
        "contracts/services_hardening/reconciliation_replay.v1.json"
    );
    assert_eq!(
        contract["plan"]["source_count_maximum"],
        RHI_RECONCILIATION_ATTEMPT_MAX_SOURCES
    );
    assert_eq!(contract["plan"]["result_event_maximum"], 4_096);
    assert_eq!(
        contract["plan"]["result_original_event_bytes_maximum"],
        8_388_608
    );
    assert!(
        contract["source_request"]
            .as_array()
            .expect("source-request fields")
            .iter()
            .any(|field| field == "trade_id")
    );
    assert_eq!(
        contract["completion_codes"],
        json!([
            "complete",
            "incomplete_timeout",
            "incomplete_unavailable",
            "incomplete_resource_limit",
            "incomplete_unknown",
            "unsupported"
        ])
    );
    assert_eq!(
        contract["result"]["inventory_ingestion_bound"],
        "configured_source_count_plus_one"
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
            "checkpoint_advance",
            "manifest",
            "reducer",
            "attestation",
            "publication"
        ])
    );
}

#[test]
fn model_is_private_bounded_pure_and_documented() {
    assert!(LIB_SOURCE.contains("mod reconciliation_attempt;"));
    assert!(!LIB_SOURCE.contains("pub mod reconciliation_attempt;"));
    for required in [
        "RhiReconciliationAttemptPlan",
        "RhiReconciliationSourceRequest",
        "RhiReconciliationSourceResult",
        "RhiReconciliationAttemptResults",
    ] {
        assert!(
            LIB_SOURCE.contains(required),
            "root API is missing {required}"
        );
    }
    assert!(README.contains("## Bounded reconciliation source attempts"));
    assert!(README.contains(
        "[`reconciliation_attempts.v1.json`](contracts/services_hardening/reconciliation_attempts.v1.json)"
    ));
    for required in [
        ".take(plan.requests.len().saturating_add(1))",
        "attempt_started_at >= lease.lease_expires()",
        "state_metadata::evidence_policy_digest(normalized)",
        "outcome == RhiTradeSourceCompletion::IncompleteTimeout",
    ] {
        assert!(
            ATTEMPT_SOURCE.contains(required),
            "attempt boundary is missing {required}"
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
        "RhiTradeSourceCursor",
    ] {
        assert!(
            !ATTEMPT_SOURCE.contains(forbidden),
            "attempt model gained deferred authority {forbidden}"
        );
    }
}
