#![forbid(unsafe_code)]

use rhi::RHI_RECONCILIATION_OUTCOME_CONTRACT_VERSION;
use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_outcome.v1.json");
const ROOT: &str = include_str!("../src/lib.rs");
const SOURCE: &str = include_str!("../src/reconciliation_reducer.rs");
const README: &str = include_str!("../README");

#[test]
fn machine_contract_freezes_the_complete_step_194_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-outcome");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_RECONCILIATION_OUTCOME_CONTRACT_VERSION
    );
    assert_eq!(
        contract["coverage"],
        json!(["missing", "partial", "scope_satisfied", "unsupported"])
    );
    assert_eq!(
        contract["outcome"],
        json!(["valid", "invalid", "indeterminate"])
    );
    assert_eq!(
        contract["precedence"],
        json!([
            "manifest_coverage",
            "projection_digest_availability",
            "shared_evidence_state",
            "reducer_issue_or_claim_ambiguity",
            "claim_presence",
            "clean_active_claim",
            "clean_cancelled_claim",
            "unresolved_claim"
        ])
    );
    assert_eq!(
        contract["decision"]["clean_active_claim"],
        json!(["valid", "scope_satisfied"])
    );
    assert_eq!(
        contract["decision"]["clean_cancelled_claim"],
        json!(["invalid", "agreement_claim_cancelled"])
    );
    for branch in [
        "missing",
        "partial",
        "unsupported",
        "projection_digest_unavailable",
        "shared_evidence_missing",
        "shared_evidence_partial",
        "shared_schema_unsupported",
        "reducer_issue_or_claim_ambiguity",
        "claim_missing",
        "claim_unresolved",
    ] {
        assert_eq!(
            contract["decision"][branch][0], "indeterminate",
            "{branch} must remain fail closed"
        );
    }
    assert_eq!(contract["reason_inventory"]["cardinality"], 1);
    assert_eq!(contract["reason_inventory"]["closed"], true);
    assert_eq!(
        contract["reason_inventory"]["codes"],
        json!([
            "required_evidence_missing",
            "required_source_incomplete",
            "required_source_unsupported",
            "projection_digest_unavailable",
            "governing_schema_unsupported",
            "reducer_issue_unresolved",
            "agreement_claim_missing",
            "agreement_claim_unresolved",
            "scope_satisfied",
            "agreement_claim_cancelled"
        ])
    );
    assert_eq!(contract["result"]["caller_forgeable"], false);
    assert_eq!(contract["result"]["retains_projection"], true);
    for effect in [
        "sqlite",
        "filesystem",
        "source_or_relay",
        "network",
        "task_spawn",
        "ambient_clock",
        "ambient_entropy",
    ] {
        assert_eq!(contract["effects"][effect], false, "effect {effect}");
    }
}

#[test]
fn outcome_boundary_is_sealed_typed_redacted_and_total() {
    for required in [
        "RhiReconciliationEvaluation",
        "RhiReconciliationCoverage",
        "RhiReconciliationOutcome",
        "RhiReconciliationReasonCode",
        "RHI_RECONCILIATION_OUTCOME_CONTRACT_VERSION",
        "evaluate_rhi_reconciliation_claim",
    ] {
        assert!(ROOT.contains(required), "root API is missing {required}");
    }
    for required in [
        "projection: RhiReconciliationProjection",
        "claim_mutation_id: MutationId",
        "reason_codes: [RhiReconciliationReasonCode; 1]",
        "fn classify_evaluation(",
        "RadrootsTradeEvidenceStateV1::UnsupportedVersion",
        "RhiReconciliationCoverage::ScopeSatisfied",
        "(Invalid, AgreementClaimCancelled)",
        "(Indeterminate, AgreementClaimUnresolved)",
    ] {
        assert!(
            SOURCE.contains(required),
            "outcome boundary is missing {required}"
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
        "pub fn new(",
        "pub const fn new(",
        "Result<RhiReconciliationEvaluation",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "outcome boundary gained forbidden authority {forbidden}"
        );
    }
    assert!(README.contains("## Pure reconciliation reducer"));
    assert!(README.contains(
        "[`reconciliation_outcome.v1.json`](contracts/services_hardening/reconciliation_outcome.v1.json)"
    ));
}
