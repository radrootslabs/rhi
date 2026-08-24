#![forbid(unsafe_code)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");
const CONSUMER_ROOT: &str = include_str!("../.radroots-consumer-root");

fn contract() -> Value {
    serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract must be valid JSON")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decision_sections_digest(value: &Value) -> String {
    let sections = serde_json::json!({
        "identity_contract": value["admin"]["identity_contract"],
        "model_wire_contract": value["admin"]["model_wire_contract"],
        "models": value["admin"]["models"],
        "mutation_contract": value["admin"]["mutation_contract"],
        "pagination": value["admin"]["pagination"],
        "path_parameters": value["admin"]["path_parameters"],
        "report_contract": value["admin"]["report_contract"],
        "types": value["admin"]["types"]
    });
    sha256_hex(&serde_json::to_vec(&sections).expect("serialize decision sections"))
}

#[test]
fn source_lock_identity_and_shared_host_reference_are_exact() {
    assert_eq!(CONSUMER_ROOT, "rhi\n");
    let value = contract();
    assert_eq!(value["schema"], "radroots.rhi.operator-contract.v1");
    assert_eq!(value["contract_version"], 1);
    assert_eq!(value["decision_state"], "reserved_preimplementation");
    assert_eq!(value["service"], "rhi");
    assert_eq!(
        value["shared_host_contract"],
        serde_json::json!({
            "repository": "https://github.com/radrootslabs/lib",
            "path": "contracts/architecture/decisions/services_hardening_host.v1.json",
            "schema": "radroots.services-hardening.host-decisions.v1",
            "contract_version": 1
        })
    );
}

#[test]
fn admin_inventory_is_closed_unique_and_model_complete() {
    let value = contract();
    assert_eq!(
        value["admin"]["transport"],
        "http_1_1_over_unix_domain_socket"
    );
    assert_eq!(value["admin"]["base_path"], "/v1");
    assert_eq!(value["admin"]["route_inventory_closed"], true);
    let routes = value["admin"]["routes"].as_array().expect("routes");
    let exact_routes = routes
        .iter()
        .map(|route| {
            format!(
                "{}|{}|{}|{}|{}|{}",
                route["method"].as_str().unwrap(),
                route["path"].as_str().unwrap(),
                route["operation_id"].as_str().unwrap(),
                route["request_model"].as_str().unwrap(),
                route["response_model"].as_str().unwrap(),
                route["mutation"].as_bool().unwrap()
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        exact_routes,
        [
            "GET|/v1/status|radroots.rhi.status.get.v1|empty|service_status_v1|false",
            "GET|/v1/config/effective|radroots.rhi.config.effective.get.v1|empty|effective_config_v1|false",
            "GET|/v1/identity/status|radroots.rhi.identity.status.get.v1|identity_status_query_v1|identity_status_v1|false",
            "GET|/v1/identity/public|radroots.rhi.identity.public.get.v1|identity_public_query_v1|identity_public_v1|false",
            "GET|/v1/state/status|radroots.rhi.state.status.get.v1|empty|state_status_v1|false",
            "POST|/v1/state/backup|radroots.rhi.state.backup.create.v1|state_backup_request_v1|state_backup_receipt_v1|true",
            "GET|/v1/metrics/snapshot|radroots.rhi.metrics.snapshot.get.v1|empty|metrics_snapshot_v1|false",
            "GET|/v1/reconciliation/status|radroots.rhi.reconciliation.status.get.v1|empty|reconciliation_status_v1|false",
            "GET|/v1/reconciliation/jobs|radroots.rhi.reconciliation.jobs.list.v1|reconciliation_jobs_query_v1|reconciliation_jobs_page_v1|false",
            "POST|/v1/reconciliation/refresh|radroots.rhi.reconciliation.refresh.v1|reconciliation_refresh_request_v1|reconciliation_refresh_receipt_v1|true",
            "GET|/v1/sources|radroots.rhi.sources.list.v1|sources_query_v1|sources_page_v1|false",
            "GET|/v1/trades/{trade_id}/projection|radroots.rhi.trade.projection.get.v1|empty|trade_projection_v1|false",
            "GET|/v1/trades/{trade_id}/reports/current|radroots.rhi.trade.report.current.get.v1|empty|report_detail_v1|false",
            "GET|/v1/trades/{trade_id}/reports|radroots.rhi.trade.reports.list.v1|reports_query_v1|reports_page_v1|false",
            "GET|/v1/publication/backlog|radroots.rhi.publication.backlog.list.v1|publication_backlog_query_v1|publication_backlog_page_v1|false",
            "GET|/v1/publication/targets|radroots.rhi.publication.targets.list.v1|publication_targets_query_v1|publication_targets_page_v1|false",
            "POST|/v1/publication/retry|radroots.rhi.publication.retry.v1|publication_retry_request_v1|publication_retry_receipt_v1|true",
            "GET|/v1/presence/desired|radroots.rhi.presence.desired.get.v1|empty|presence_desired_v1|false",
            "POST|/v1/presence/render|radroots.rhi.presence.render.v1|presence_render_request_v1|presence_render_receipt_v1|true",
            "POST|/v1/presence/refresh|radroots.rhi.presence.refresh.v1|presence_refresh_request_v1|presence_refresh_receipt_v1|true"
        ]
    );
    assert_eq!(routes.len(), 20);
    let route_keys = routes
        .iter()
        .map(|route| format!("{} {}", route["method"], route["path"]))
        .collect::<BTreeSet<_>>();
    let operation_ids = routes
        .iter()
        .map(|route| route["operation_id"].as_str().expect("operation ID"))
        .collect::<BTreeSet<_>>();
    assert_eq!(route_keys.len(), routes.len());
    assert_eq!(operation_ids.len(), routes.len());
    assert!(
        operation_ids
            .iter()
            .all(|id| id.starts_with("radroots.rhi.") && id.ends_with(".v1"))
    );

    let models = value["admin"]["models"].as_object().expect("models");
    let types = value["admin"]["types"].as_object().expect("types");
    assert_eq!(models.len(), 33);
    for route in routes {
        for key in ["request_model", "response_model"] {
            let model = route[key].as_str().expect("model reference");
            assert!(models.contains_key(model), "missing model {model}");
        }
        assert_eq!(route["mutation"], route["method"] == "POST");
    }
    for (model_name, model) in models {
        assert_eq!(
            model
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["fields"],
            "model {model_name} must be a closed field inventory"
        );
        for (field_name, field) in model["fields"].as_object().unwrap() {
            assert_eq!(
                field
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                ["presence", "type"],
                "field {model_name}.{field_name} must bind only type and presence"
            );
            assert!(matches!(
                field["presence"].as_str(),
                Some("required" | "optional")
            ));
            let type_name = field["type"].as_str().unwrap();
            assert!(types.contains_key(type_name), "unknown type {type_name}");
        }
    }
    for (type_name, descriptor) in types {
        let referenced = match descriptor["kind"].as_str().unwrap() {
            "array" => vec![descriptor["items"].as_str().unwrap()],
            "map" => vec![
                descriptor["key"].as_str().unwrap(),
                descriptor["value"].as_str().unwrap(),
            ],
            "closed_object" => descriptor["fields"]
                .as_object()
                .unwrap()
                .values()
                .map(|field| field.as_str().unwrap())
                .collect(),
            "tagged_union" => descriptor["variants"]
                .as_array()
                .unwrap()
                .iter()
                .map(|variant| variant.as_str().unwrap())
                .collect(),
            "alias" => vec![descriptor["target"].as_str().unwrap()],
            "optional" => vec![descriptor["value"].as_str().unwrap()],
            "boolean" | "canonical_json_object" | "enum" | "integer" | "literal" | "string" => {
                Vec::new()
            }
            kind => panic!("unknown descriptor kind {kind} for {type_name}"),
        };
        for reference in referenced {
            assert!(
                types.contains_key(reference),
                "type {type_name} references missing type {reference}"
            );
        }
    }
    assert_eq!(
        value["admin"]["identity_contract"],
        serde_json::json!({
            "roles": [{ "id": "service", "required": true, "disabled_allowed": false, "providers": ["encrypted_file"] }],
            "rotation_mode": "offline_create_new_configuration_apply_restart",
            "live_rekey_route": false,
            "live_replace_route": false
        })
    );
    for removed in [
        "identity_rekey_request_v1",
        "identity_replace_request_v1",
        "identity_mutation_receipt_v1",
    ] {
        assert!(!models.contains_key(removed));
    }
    for removed in [
        "credential_reference",
        "encrypted_file_provider",
        "identity_provider_replacement",
        "encrypted_file_replacement",
    ] {
        assert!(!types.contains_key(removed));
    }
    assert_eq!(
        value["admin"]["types"]["service_phase"],
        serde_json::json!({ "kind": "enum", "values": ["starting", "ready", "degraded", "unready", "stopping", "failed"] })
    );
    assert_eq!(
        value["admin"]["types"]["coverage"],
        serde_json::json!({ "kind": "enum", "values": ["Missing", "Partial", "ScopeSatisfied", "Unsupported"] })
    );
    assert_eq!(
        value["admin"]["types"]["outcome"],
        serde_json::json!({ "kind": "enum", "values": ["Valid", "Invalid", "Indeterminate"] })
    );
    assert_eq!(
        value["admin"]["types"]["provider_state"]["fields"],
        serde_json::json!({
            "health": "provider_health",
            "identity": "identity_health",
            "reason_codes": "reason_codes"
        })
    );
    assert_eq!(
        value["admin"]["types"]["transport_state"]["fields"],
        serde_json::json!({
            "health": "transport_health",
            "required_sources_ready": "bool",
            "subscriber_active": "bool",
            "configured_source_count": "u64",
            "reachable_source_count": "u64",
            "reason_codes": "reason_codes"
        })
    );
    assert_eq!(
        value["admin"]["types"]["rhi_status"]["fields"],
        serde_json::json!({
            "identity": "identity_health",
            "reconciliation": "reconciliation_status",
            "publication": "publication_status",
            "presence": "presence_status"
        })
    );
    assert_eq!(
        value["admin"]["models"]["service_status_v1"]["fields"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "build_info",
            "configuration",
            "contract_version",
            "instance",
            "persistence",
            "phase",
            "provider",
            "ready",
            "reason_codes",
            "rhi",
            "service",
            "transport",
            "uptime_millis"
        ]
    );
    assert_eq!(
        value["admin"]["path_parameters"],
        serde_json::json!({
            "trade_id": { "type": "trade_id", "source": "percent_decoded_single_path_segment", "slash_allowed": false }
        })
    );
    assert_eq!(
        value["admin"]["report_contract"],
        serde_json::json!({
            "content_contract": "radroots.rhi.evidence_attestation.v1",
            "report_id_equals_statement_digest": true,
            "supersession_reference_presence": "supersedes_report_id_and_supersedes_event_id_both_or_neither",
            "current_selection": ["trade_generation_descending", "observed_at_unix_s_descending", "statement_digest_descending"],
            "relay_arrival_order_authoritative": false
        })
    );
    assert_eq!(
        value["admin"]["pagination"],
        serde_json::json!({
            "cursor_type": "page_cursor",
            "limit_min": 1,
            "limit_max": 200,
            "terminal_page": "next_cursor_field_absent",
            "cursor_reuse": "same_route_same_filters_only",
            "filter_or_route_mismatch": "invalid_cursor",
            "jobs_order": ["scheduled_at_utc_ascending", "job_id_ascending"],
            "jobs_snapshot": "maximum_job_sequence_fixed_by_first_page_cursor",
            "sources_order": ["source_id_ascending"],
            "sources_snapshot": "configuration_generation_fixed_by_first_page_cursor",
            "reports_order": ["observed_at_utc_descending", "report_id_descending"],
            "reports_snapshot": "maximum_report_sequence_fixed_by_first_page_cursor",
            "publication_backlog_order": ["next_attempt_at_utc_ascending_nulls_first", "workflow_id_ascending"],
            "publication_backlog_snapshot": "maximum_publication_sequence_fixed_by_first_page_cursor",
            "publication_targets_order": ["workflow_id_ascending", "target_id_ascending"],
            "publication_targets_snapshot": "maximum_publication_target_sequence_fixed_by_first_page_cursor"
        })
    );
    let mutation_operations = routes
        .iter()
        .filter(|route| route["mutation"] == true)
        .map(|route| route["operation_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let committed_effects = value["admin"]["mutation_contract"]["committed_effects"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(mutation_operations, committed_effects);
    assert_eq!(
        decision_sections_digest(&value),
        "49376e3bdf0e44c35f877ecd382f26bc9c38fec8fea7a674aa7d4da52ee00c62"
    );
}

#[test]
fn doctor_exit_and_tcp_contracts_are_exact() {
    let value = contract();
    assert_eq!(
        value["doctor"]["shared_schema"],
        "radroots.service.doctor.v1"
    );
    assert_eq!(value["doctor"]["contract_version"], 1);
    assert_eq!(value["doctor"]["execution"], "ordered");
    assert_eq!(value["doctor"]["pass_requires_all_scope"], true);
    assert_eq!(
        value["doctor"]["checks"]
            .as_array()
            .expect("doctor checks")
            .len(),
        15
    );
    assert_eq!(
        value["exit_codes"],
        serde_json::json!([
            { "code": 0, "name": "success", "meaning": "successful command or completed graceful first-signal shutdown" },
            { "code": 1, "name": "unexpected_internal", "meaning": "unexpected invariant, critical task, or internal failure" },
            { "code": 2, "name": "input_or_configuration", "meaning": "CLI, config, validation, or unsupported contract input" },
            { "code": 3, "name": "service_or_dependency_unavailable", "meaning": "daemon, required provider, relay, source, or local dependency unavailable" },
            { "code": 4, "name": "state_or_identity_unavailable", "meaning": "state, schema, lock, credential, or identity unavailable" },
            { "code": 5, "name": "operation_rejected_or_conflict", "meaning": "authorization rejection, idempotency conflict, stale generation, or domain conflict" },
            { "code": 6, "name": "doctor_required_check_failed", "meaning": "one or more required doctor checks failed or timed out" }
        ])
    );
    assert_eq!(
        value["tcp_operations"],
        serde_json::json!({
            "routes": [
                { "method": "GET", "path": "/livez", "source": "cached_supervisor_state" },
                { "method": "GET", "path": "/readyz", "source": "cached_readiness_state" },
                { "method": "GET", "path": "/metrics", "source": "cached_bounded_metrics_snapshot" }
            ],
            "active_probe_per_request": false,
            "additional_routes": false
        })
    );
}
