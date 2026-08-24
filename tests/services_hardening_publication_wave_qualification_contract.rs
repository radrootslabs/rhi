#![forbid(unsafe_code)]

use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/publication_wave_qualification.v1.json");
const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const EXECUTION_SOURCE: &str = include_str!("../src/publication_execution.rs");
const README: &str = include_str!("../README");

#[test]
fn step203_machine_contract_freezes_the_complete_qualification_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.publication-wave-qualification"
    );
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 203);
    assert_eq!(contract["service"], "rhi");
    assert_eq!(contract["state_schema_version"], 8);
    assert_eq!(
        contract["component_corpus"],
        json!([
            "exact_byte_publication_persists_submitted_before_io_and_commits_accepted",
            "cancelled_submitted_attempt_recovers_unknown_and_retries_exact_bytes_after_reopen",
            "publication_outcome_commit_is_idempotent_and_inspection_is_nonmutating",
            "publication_execution_binds_live_authority_without_mutating_on_mismatch_or_disable",
            "terminal_required_rejection_blocks_the_outbox_without_retry_schedule",
            "concurrent_publication_execution_has_one_remote_submitter",
            "publication_queue_capacity_is_checked_before_finalization_mutation",
            "schema_v8_scans_historical_nullable_job_state_and_installs_permanent_guards"
        ])
    );
    assert_eq!(
        contract["source_locked_shared_sqlite_corpus"],
        json!([
            "every_initialization_durability_edge_fails_once_and_rolls_back",
            "transaction_durability_edges_preserve_exact_commit_semantics",
            "backup_durability_edges_fail_once_clean_exact_stage_and_recover",
            "close_durability_edges_are_once_only_retryable_or_terminal",
            "every_marker_and_restore_durability_edge_is_wired_once",
            "sigkill_restore_boundaries_recover_exact_topologies_and_preserve_permissions"
        ])
    );
    assert_eq!(
        contract["historical_reconciliation_job_guard"],
        json!({
            "migration_target_version": 8,
            "scan": "forward_only_fail_closed_before_guard_installation",
            "repair_or_delete_invalid_rows": false,
            "permanent_guards": [
                "reconciliation_jobs_shape_guard_insert",
                "reconciliation_jobs_shape_guard_update"
            ],
            "required_ready_fields": ["next_attempt_unix_ms"],
            "required_leased_fields": ["lease_owner", "lease_expires_unix_ms"],
            "terminal_nullable_fields": [
                "next_attempt_unix_ms",
                "lease_owner",
                "lease_expires_unix_ms"
            ]
        })
    );
    assert_eq!(
        contract["resource_bounds"],
        json!({
            "maximum_publication_queue": 65_536,
            "maximum_targets_per_outbox": 32,
            "maximum_attempts_per_target": 100,
            "maximum_signed_event_bytes": 32_768
        })
    );
    for invariant in [
        "exact_committed_bytes_only",
        "remote_io_outside_sql_transaction",
        "submitted_before_remote_io",
        "single_cas_winner",
        "unknown_outcome_recovered_before_retry",
        "invalid_historical_state_fails_without_repair",
    ] {
        assert_eq!(contract["invariants"][invariant], true, "{invariant}");
    }
    assert_eq!(
        contract["invariants"]["production_failpoint_surface"],
        false
    );
    assert_eq!(contract["invariants"]["ambient_network"], false);
    assert_eq!(contract["invariants"]["unbounded_resource"], false);
}

#[test]
fn qualification_remains_private_sqlx_owned_and_documented() {
    for required in [
        "CREATE TABLE reconciliation_jobs_shape_scan_v1",
        "DROP TABLE reconciliation_jobs_shape_scan_v1",
        "CREATE TRIGGER reconciliation_jobs_shape_guard_insert",
        "CREATE TRIGGER reconciliation_jobs_shape_guard_update",
        "typeof(next_attempt_unix_ms) != 'integer'",
        "typeof(lease_owner) != 'blob'",
        "typeof(lease_expires_unix_ms) != 'integer'",
    ] {
        assert!(CATALOG_SOURCE.contains(required), "missing `{required}`");
    }
    for forbidden in [
        "RHI_FAILPOINT",
        "RHI_TEST_",
        "production_failpoint",
        "pub fn sqlite",
        "pub fn connection",
        "pub fn transaction",
    ] {
        assert!(!EXECUTION_SOURCE.contains(forbidden), "found `{forbidden}`");
    }
    assert!(README.contains(
        "[`publication_wave_qualification.v1.json`](contracts/services_hardening/publication_wave_qualification.v1.json)"
    ));
}
