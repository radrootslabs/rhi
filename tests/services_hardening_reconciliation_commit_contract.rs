#![forbid(unsafe_code)]

use rhi::RHI_RECONCILIATION_COMMIT_CONTRACT_VERSION;
use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_commit.v1.json");
const ROOT: &str = include_str!("../src/lib.rs");
const SOURCE: &str = include_str!("../src/reconciliation_commit.rs");
const README: &str = include_str!("../README");

#[test]
fn machine_contract_freezes_the_complete_step_190_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-commit");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_RECONCILIATION_COMMIT_CONTRACT_VERSION
    );
    assert_eq!(contract["state_schema_version"], 6);
    assert_eq!(
        contract["transaction"]["fences_before_mutation"],
        json!([
            "exact_live_lease_row",
            "exact_trade_dirty_generation",
            "exact_evidence_policy_digest",
            "exact_per_source_prior_checkpoint"
        ])
    );
    assert_eq!(
        contract["checkpoint"]["advance_only_when"],
        "completion_is_complete_and_candidate_is_strictly_newer_than_prior"
    );
    assert_eq!(
        contract["checkpoint"]["public_evidence"],
        "sealed_and_minted_only_after_durable_commit_confirmation"
    );
    assert_eq!(
        contract["dirty_generation"]["advance_count_maximum_per_attempt"],
        1
    );
    assert_eq!(
        contract["idempotency"]["lost_success_retry"],
        "checked_before_live_lease_and_generation_fences"
    );
    assert_eq!(
        contract["idempotency"]["source_inventory_identity"],
        "domain_separated_sha256_over_exact_ordered_persisted_facts_and_provenance"
    );
    assert_eq!(contract["effects"]["source_or_relay"], false);
    assert_eq!(contract["effects"]["ambient_clock"], false);
}

#[test]
fn commit_boundary_is_private_bounded_transactional_and_documented() {
    assert!(ROOT.contains("mod reconciliation_commit;"));
    assert!(!ROOT.contains("pub mod reconciliation_commit;"));
    for required in [
        "RhiReconciliationCommitError",
        "RhiReconciliationCommitErrorKind",
        "RhiReconciliationSourceCommitOutcome",
        "RHI_RECONCILIATION_COMMIT_CONTRACT_VERSION",
    ] {
        assert!(ROOT.contains(required), "root API is missing {required}");
    }
    for required in [
        ".take(plan.requests().len().saturating_add(1))",
        "validate_exact_lease(transaction, lease)",
        "reconcile_existing(transaction, &plan, &parts)",
        "SOURCE_INVENTORY_DIGEST_DOMAIN",
        "accepted_inventory_sha256",
        "advance_dirty_generation(",
        "write_checkpoint(",
        "committed_cursor_evidence(",
        "ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown",
    ] {
        assert!(
            SOURCE.contains(required),
            "commit boundary is missing {required}"
        );
    }
    for forbidden in [
        "std::fs",
        "std::net",
        "tokio::spawn",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "pub fn transaction",
        "pub fn sqlite_host",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "commit boundary gained forbidden authority {forbidden}"
        );
    }
    assert!(README.contains("## Atomic reconciliation result commit"));
    assert!(README.contains(
        "[`reconciliation_commit.v1.json`](contracts/services_hardening/reconciliation_commit.v1.json)"
    ));
}
