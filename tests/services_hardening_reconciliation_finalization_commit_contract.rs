#![forbid(unsafe_code)]

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_finalization_commit.v1.json");
const SOURCE: &str = include_str!("../src/reconciliation_finalization_commit.rs");
const ROOT: &str = include_str!("../src/lib.rs");

#[test]
fn contract_freezes_one_atomic_effect_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract JSON");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.reconciliation-finalization-commit"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["transaction"]["count"], 1);
    assert_eq!(
        contract["transaction"]["reconcile_exact_prior_success_before_consumed_lease_validation"],
        true
    );
    assert_eq!(contract["effects"]["sqlite_write"], true);
    assert_eq!(contract["effects"]["network"], false);
    assert_eq!(contract["effects"]["task_spawn"], false);
    assert_eq!(
        contract["publication"]["disabled"],
        "no_outbox_and_no_target_rows"
    );
}

#[test]
fn implementation_retains_exact_bytes_and_has_no_external_effect_authority() {
    for required in [
        "pub async fn commit_finalization(",
        "reconcile_existing(transaction, record)",
        "validate_finalization_identity(transaction, record.lease, record.identity, record.now)",
        "validate_source_inventory(transaction, record)",
        "validate_advanced_checkpoints(transaction, record)",
        "validate_supersession(transaction, record)",
        "INSERT_MANIFEST_SQL",
        "INSERT_PROJECTION_SQL",
        "INSERT_REPORT_SQL",
        "INSERT_SIGNED_EVENT_SQL",
        "INSERT_OUTBOX_SQL",
        "INSERT_TARGET_SQL",
        "COMPLETE_JOB_SQL",
        "record.canonical_manifest.as_ref()",
        "record.canonical_report.as_ref()",
        "record.canonical_event_json.as_ref()",
    ] {
        assert!(
            SOURCE.contains(required),
            "missing finalization guard {required}"
        );
    }
    for forbidden in [
        "tokio::spawn",
        "spawn_blocking",
        "SystemTime",
        "std::fs",
        "reqwest",
        "EventSink",
        "publish(",
        "send(",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "finalization gained forbidden effect authority {forbidden}"
        );
    }
    assert!(ROOT.contains("mod reconciliation_finalization_commit;"));
    assert!(!ROOT.contains("pub mod reconciliation_finalization_commit;"));
}
