#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde_json::Value;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/failure_qualification.v1.json");
const SOURCE_LOCK: &str = include_str!("../radroots.service.source-lock.v2.toml");
const MANIFEST: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README");
const AGENTS: &str = include_str!("../AGENTS.md");
const COMPONENT_TESTS: &[&str] = &[
    include_str!("services_hardening_config_contract.rs"),
    include_str!("services_hardening_config_lifecycle.rs"),
    include_str!("services_hardening_state_resilience.rs"),
    include_str!("services_hardening_state_host.rs"),
    include_str!("services_hardening_reconciliation_jobs.rs"),
    include_str!("services_hardening_presence_publication.rs"),
    include_str!("services_hardening_source_ingest.rs"),
    include_str!("services_hardening_runtime_foundation.rs"),
    include_str!("services_hardening_doctor.rs"),
    include_str!("package_boundary.rs"),
];

#[test]
fn contract_freezes_the_exact_failure_qualification_corpus() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("failure qualification contract");
    assert_eq!(
        contract
            .as_object()
            .expect("qualification object")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "component_corpus",
            "contract_version",
            "deferred",
            "invariants",
            "resource_bounds",
            "schema",
            "schema_version",
            "service",
            "source_lock",
            "source_locked_shared_sqlite_corpus",
            "step",
        ])
    );
    assert_eq!(contract["schema"], "radroots.rhi.failure-qualification.v1");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 214);
    assert_eq!(contract["service"], "rhi");
    assert_eq!(
        contract["source_lock"],
        serde_json::json!({
            "schema": "radroots.service.source-lock.v2",
            "lib_revision": "21b11e7a5120ea949f7ad0838c746873fc73aac2"
        })
    );
    assert_eq!(
        contract["resource_bounds"],
        serde_json::json!({
            "configuration_document_utf8_bytes": 1_048_576,
            "source_result_events": 4_096,
            "source_result_bytes": 8_388_608,
            "reconciliation_queue": 65_536,
            "publication_queue": 65_536,
            "doctor_checks": 15
        })
    );
    assert_eq!(
        contract["component_corpus"],
        serde_json::json!({
            "resource_and_backlog": [
                "exact_resource_boundaries_and_safe_defaults_are_frozen",
                "source_results_enforce_deadline_outcome_and_exact_resource_bounds",
                "commit_inventory_bounds_infinite_iterators_before_any_mutation",
                "publication_queue_capacity_is_checked_before_finalization_mutation",
                "configured_result_bound_retains_admitted_evidence_without_checkpoint",
                "public_inputs_have_exact_bounds_and_diagnostics_are_redacted"
            ],
            "disk_and_durable_state": [
                "backup_integrity_and_offline_restore_obey_one_exact_rhi_authority",
                "maintenance_boundary_is_sealed_source_free_and_sqlx_owned",
                "initialize_is_create_new_and_both_existing_open_modes_close_explicitly"
            ],
            "corruption_and_malformed_history": [
                "semantically_conflicting_but_structurally_valid_history_fails_closed",
                "exact_open_rejects_unexpected_migration_history_without_repair",
                "publication_schema_rejects_null_state_holes_and_accepted_target_mutation",
                "schema_v8_scans_historical_nullable_job_state_and_installs_permanent_guards"
            ],
            "cancellation_outage_and_recovery": [
                "cancelled_blocked_commit_has_no_effect_and_exact_retry_succeeds",
                "cancelled_submitted_attempt_recovers_unknown_and_retries_exact_bytes_after_reopen",
                "exact_bytes_are_durable_before_io_and_unknown_recovery_retries_unchanged",
                "incomplete_and_unsupported_results_never_advance_checkpoint_or_dirty_generation",
                "missing_state_fails_before_identity_or_transport_access",
                "identity_failure_after_state_open_releases_authority_without_transport_access",
                "failures_schedule_exact_jitter_and_the_final_attempt_exhausts",
                "signed_attestation_fails_closed_when_injected_entropy_is_unavailable",
                "required_timeout_drops_work_and_remaining_checks_continue_in_order"
            ],
            "safe_error_posture": [
                "configuration_lifecycle_surface_is_sealed_and_redacted",
                "attempt_and_public_diagnostics_are_bounded_and_redacted",
                "report_debug_and_public_errors_retain_no_sensitive_values",
                "public_errors_are_crate_owned_redacted_and_source_free"
            ]
        })
    );
    assert_eq!(
        contract["invariants"],
        serde_json::json!({
            "bounded_ingestion_before_mutation": true,
            "atomic_commit_or_no_effect": true,
            "cancellation_retry_safe": true,
            "durable_unknown_recovered_before_retry": true,
            "malformed_history_repaired": false,
            "corruption_fails_closed": true,
            "sqlx_is_only_high_level_sqlite_authority": true,
            "production_failpoint_surface": false,
            "test_environment_selector": false,
            "public_errors_source_free": true,
            "diagnostics_path_secret_free": true
        })
    );
    assert_eq!(
        contract["deferred"],
        serde_json::json!([
            "actual_process_and_bounded_soak_step_215",
            "native_release_artifacts_step_216",
            "rcld_promotion_step_217",
            "parent_pin_alignment_step_217",
            "nix",
            "oci",
            "signing",
            "publication",
            "deployment"
        ])
    );
}

#[test]
fn every_component_contract_entry_names_an_executable_test() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("failure qualification contract");
    let sources = COMPONENT_TESTS.join("\n");
    let corpus = contract["component_corpus"]
        .as_object()
        .expect("component corpus");
    assert_eq!(
        corpus.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "cancellation_outage_and_recovery",
            "corruption_and_malformed_history",
            "disk_and_durable_state",
            "resource_and_backlog",
            "safe_error_posture",
        ])
    );
    for (category, tests) in corpus {
        let tests = tests.as_array().expect("test-name array");
        assert!(!tests.is_empty(), "empty qualification category {category}");
        for test in tests {
            let test = test.as_str().expect("test name");
            assert!(
                sources.contains(&format!("fn {test}(")),
                "qualification entry {category}/{test} has no executable test"
            );
        }
    }
}

#[test]
fn source_lock_binds_the_shared_sqlite_failure_corpus_without_a_second_authority() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("failure qualification contract");
    let revision = contract["source_lock"]["lib_revision"]
        .as_str()
        .expect("Lib revision");
    assert!(SOURCE_LOCK.contains(&format!("revision = \"{revision}\"")));
    assert!(MANIFEST.contains(&format!("radroots_service_sqlite = {{ git = \"https://github.com/radrootslabs/lib\", rev = \"{revision}\"")));
    assert_eq!(
        contract["source_locked_shared_sqlite_corpus"],
        serde_json::json!([
            "minimum_policy_and_strict_numeric_serde_are_bounded",
            "injected_values_classify_exact_boundary_and_propagate_failure",
            "physical_corruption_and_query_failure_remain_redacted_and_typed",
            "missing_extra_reordered_newer_and_corrupt_history_fail_closed",
            "oversized_corrupt_history_is_bounded_before_decode",
            "every_initialization_durability_edge_fails_once_and_rolls_back",
            "transaction_durability_edges_preserve_exact_commit_semantics",
            "backup_durability_edges_fail_once_clean_exact_stage_and_recover",
            "close_durability_edges_are_once_only_retryable_or_terminal",
            "every_marker_and_restore_durability_edge_is_wired_once",
            "sigkill_restore_boundaries_recover_exact_topologies_and_preserve_permissions"
        ])
    );
    assert!(!MANIFEST.contains("rusqlite"));
}

#[test]
fn human_boundary_is_explicit_and_does_not_preclaim_later_steps() {
    for required in [
        "## Failure-resilience qualification",
        "[`failure_qualification.v1.json`](contracts/services_hardening/failure_qualification.v1.json)",
        "actual-process and\nbounded-soak qualification remains Step 215 ownership",
        "native release\nartifacts remain Step 216 ownership",
        "promotion and parent-pin alignment\nremain Step 217 ownership",
    ] {
        assert!(README.contains(required), "README is missing {required}");
    }
    for required in [
        "Step 214 freezes the failure-resilience qualification corpus",
        "Do not add a second SQLite authority",
        "Step 215\n  alone owns actual-process and bounded-soak qualification",
    ] {
        assert!(AGENTS.contains(required), "AGENTS is missing {required}");
    }
}
