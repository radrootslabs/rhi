#![forbid(unsafe_code)]

use rhi::RHI_RECONCILIATION_FINALIZATION_CONTRACT_VERSION;
use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_finalization.v1.json");
const ROOT: &str = include_str!("../src/lib.rs");
const SOURCE: &str = include_str!("../src/reconciliation_finalization.rs");
const MANIFEST: &str = include_str!("../src/reconciliation_manifest.rs");
const README: &str = include_str!("../README");

#[test]
fn machine_contract_freezes_the_complete_step_195_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.reconciliation-finalization"
    );
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_RECONCILIATION_FINALIZATION_CONTRACT_VERSION
    );
    assert_eq!(
        contract["private_identity_chain"]["manifest_retains"],
        json!(["step_190_attempt_id", "step_190_job_id"])
    );
    assert_eq!(
        contract["private_identity_chain"]["canonical_manifest_wire_changed"],
        false
    );
    assert_eq!(
        contract["preflight_order"],
        json!([
            "writable_host",
            "sealed_identity_chain",
            "unexpired_input_lease",
            "exact_current_lease",
            "exact_current_dirty_generation_and_policy_digest",
            "exact_committed_attempt_row"
        ])
    );
    assert_eq!(contract["durable_validation"]["mutation"], false);
    assert_eq!(
        contract["durable_validation"]["step_199_requirement"],
        "rerun_same_validator_inside_atomic_finalization_transaction_before_any_write"
    );
    assert_eq!(
        contract["durable_validation"]["preflight_is_commit_authority"],
        false
    );
    assert_eq!(contract["effects"]["sqlite_read"], true);
    assert_eq!(contract["effects"]["sqlite_write"], false);
    for effect in [
        "filesystem",
        "source_or_relay",
        "network",
        "task_spawn",
        "ambient_clock",
        "ambient_entropy",
        "report_or_attestation",
        "publication",
        "job_finalization",
    ] {
        assert_eq!(contract["effects"][effect], false, "effect {effect}");
    }
}

#[test]
fn finalization_boundary_is_sealed_identity_bound_and_nonmutating() {
    assert!(ROOT.contains("mod reconciliation_finalization;"));
    assert!(!ROOT.contains("pub mod reconciliation_finalization;"));
    for required in [
        "RhiReconciliationFinalizationFence",
        "RhiReconciliationFinalizationError",
        "RhiReconciliationFinalizationErrorKind",
        "RHI_RECONCILIATION_FINALIZATION_CONTRACT_VERSION",
    ] {
        assert!(ROOT.contains(required), "root API is missing {required}");
    }
    for required in [
        "pub async fn prepare_finalization(",
        "validate_finalization_fence(",
        "validate_exact_lease(transaction, lease)",
        "read_dirty(transaction, identity.trade_id)",
        "MATCH_COMMITTED_ATTEMPT_SQL",
        "manifest.attempt_id() != attempt_id(job.id(), job.attempt_count())",
        "now >= lease.lease_expires()",
        "evaluation.projection().digest().is_none()",
    ] {
        assert!(
            SOURCE.contains(required),
            "finalization boundary is missing {required}"
        );
    }
    for required in [
        "attempt_id: RhiReconciliationAttemptId",
        "job_id: RhiReconciliationJobId",
        "attempt_id: plan.id()",
        "job_id: plan.job_id()",
    ] {
        assert!(
            MANIFEST.contains(required),
            "manifest is missing {required}"
        );
    }
    for forbidden in [
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "std::fs",
        "std::net",
        "tokio::spawn",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "pub fn new(",
        "pub const fn new(",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "finalization boundary gained forbidden authority {forbidden}"
        );
    }
    assert!(README.contains("## Generation-fenced finalization preflight"));
    assert!(README.contains(
        "[`reconciliation_finalization.v1.json`](contracts/services_hardening/reconciliation_finalization.v1.json)"
    ));
}
