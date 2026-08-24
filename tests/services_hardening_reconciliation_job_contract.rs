#![forbid(unsafe_code)]

use rhi::{RHI_RECONCILIATION_JOB_CONTRACT_VERSION, RHI_RECONCILIATION_JOB_MAX_ACTIVE};
use serde_json::json;

const CONTRACT: &str = include_str!("../contracts/services_hardening/reconciliation_jobs.v1.json");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const JOB_SOURCE: &str = include_str!("../src/reconciliation_job.rs");
const README: &str = include_str!("../README");

#[test]
fn machine_contract_freezes_the_complete_step_187_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-jobs");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_RECONCILIATION_JOB_CONTRACT_VERSION
    );
    assert_eq!(contract["state_schema_version"], 5);
    assert_eq!(contract["backing_table"], "reconciliation_jobs");
    assert_eq!(
        contract["job_identity"],
        json!({
            "algorithm": "sha256",
            "domain": "radroots.rhi.reconciliation_job.v1\\0",
            "preimage": [
                "trade_id_16_bytes",
                "input_generation_u64_be",
                "evidence_policy_sha256_32_bytes"
            ]
        })
    );
    assert_eq!(
        contract["active_job_bound"]["absolute_maximum"],
        RHI_RECONCILIATION_JOB_MAX_ACTIVE
    );
    assert_eq!(
        contract["states"],
        json!(["ready", "leased", "exhausted", "superseded", "completed"])
    );
    assert_eq!(
        contract["injected_authority"],
        json!(["wall_time_unix_ms", "lease_owner", "retry_jitter_ms"])
    );
    for forbidden in [
        "ambient_clock",
        "ambient_entropy",
        "network_io",
        "source_query_inside_transaction",
        "unbounded_queue",
        "raw_sqlite_handle",
        "caller_selected_job_id",
        "caller_selected_next_attempt_timestamp",
        "delete_job",
    ] {
        assert!(
            contract["forbidden"]
                .as_array()
                .expect("forbidden")
                .iter()
                .any(|value| value == forbidden),
            "missing {forbidden}"
        );
    }
    assert_eq!(
        contract["deferred"],
        json!([
            "per_source_attempt_inventory",
            "source_execution",
            "source_completion_commit",
            "manifest",
            "reducer",
            "attestation",
            "publication"
        ])
    );
}

#[test]
fn module_and_sqlite_authority_remain_private() {
    assert!(LIB_SOURCE.contains("mod reconciliation_job;"));
    assert!(!LIB_SOURCE.contains("pub mod reconciliation_job;"));
    assert!(LIB_SOURCE.contains("RhiReconciliationJobPolicy"));
    assert!(README.contains("## Durable reconciliation jobs"));
    assert!(README.contains(
        "[`reconciliation_jobs.v1.json`](contracts/services_hardening/reconciliation_jobs.v1.json)"
    ));
    for forbidden in [
        "pub fn sqlite",
        "pub fn transaction",
        "pub fn connection",
        "pub fn into_inner",
        "pub fn owner",
        "pub fn from_job_id",
        "std::time::",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "radroots_transport",
    ] {
        assert!(
            !JOB_SOURCE.contains(forbidden),
            "forbidden job authority {forbidden}"
        );
    }
    assert!(JOB_SOURCE.contains("ServiceSqliteTransaction"));
}
