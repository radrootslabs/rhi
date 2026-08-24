#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use rhi::RhiAdminRoute;
use serde_json::{Value, json};

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/admin_wave_qualification.v1.json");
const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");
const ADMIN_SOURCE: &str = include_str!("../src/admin_v1.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");
const ROOT_SOURCE: &str = include_str!("../src/lib.rs");

#[test]
fn step209_machine_contract_freezes_the_complete_admin_wave() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("qualification contract");
    let operator: Value = serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract");
    assert_eq!(contract["schema"], "radroots.rhi.admin-wave-qualification");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 209);
    assert_eq!(contract["wave"], "130-b");
    assert_eq!(contract["service"], "rhi");
    assert_eq!(contract["final_inventory"]["route_count"], 20);
    assert_eq!(contract["final_inventory"]["model_count"], 33);
    assert_eq!(contract["final_inventory"]["common_route_count"], 7);
    assert_eq!(contract["final_inventory"]["domain_route_count"], 13);

    let routes = operator["admin"]["routes"].as_array().expect("routes");
    let models = operator["admin"]["models"].as_object().expect("models");
    assert_eq!(routes.len(), 20);
    assert_eq!(models.len(), 33);
    assert_eq!(RhiAdminRoute::ALL, RhiAdminRoute::ACTIVE);
    assert_eq!(
        RhiAdminRoute::COMMON
            .into_iter()
            .chain(RhiAdminRoute::DOMAIN)
            .collect::<Vec<_>>(),
        RhiAdminRoute::ALL
    );
    let referenced = routes
        .iter()
        .flat_map(|route| {
            ["request_model", "response_model"]
                .map(|field| route[field].as_str().expect("model reference"))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        referenced,
        models.keys().map(String::as_str).collect::<BTreeSet<_>>()
    );

    assert_eq!(
        contract["live_negative_matrix"],
        json!({
            "original_wire": [
                "duplicate_request_field",
                "nested_null",
                "missing_contract_version"
            ],
            "version": [
                "unknown_major_path",
                "contract_version_zero_every_mutation",
                "contract_version_two_every_mutation"
            ],
            "pagination": [
                "noncanonical_limit",
                "just_over_maximum_limit",
                "duplicate_query_item",
                "unknown_query_item",
                "malformed_percent_encoding",
                "noncanonical_cursor",
                "handler_rejected_unbound_cursor"
            ],
            "idempotency": [
                "exact_operation_replay_returns_success_without_second_commit",
                "conflicting_operation_reuse_rejected"
            ],
            "peer": [
                "owner_only_socket_mode",
                "current_owner_round_trip",
                "source_locked_linux_uid_or_gid_allow_and_other_deny"
            ],
            "removed_sensitive_routes": [
                "identity_rekey_unavailable",
                "identity_replace_unavailable"
            ],
            "resource": [
                "request_body_just_over_limit",
                "response_body_just_over_limit",
                "page_limit_just_over_maximum",
                "source_locked_header_query_connection_deadline_and_drain_limits"
            ]
        })
    );
}

#[test]
fn qualification_is_executable_source_locked_and_authority_safe() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("qualification contract");
    for test in contract["component_corpus"]
        .as_array()
        .expect("component corpus")
    {
        let test = test.as_str().expect("test name");
        assert!(
            ADMIN_SOURCE.contains(test),
            "missing component test `{test}`"
        );
    }

    let revision = contract["source_locked_transport_evidence"]["revision"]
        .as_str()
        .expect("Lib revision");
    assert_eq!(revision.len(), 40);
    assert!(
        revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
    assert!(MANIFEST.contains(&format!("rev = \"{revision}\"")));
    assert!(
        MANIFEST
            .contains("radroots_service_host = { git = \"https://github.com/radrootslabs/lib\"")
    );
    assert_eq!(
        contract["source_locked_transport_evidence"]["corpus"],
        json!([
            "serves_valid_json_with_exact_caller_correlation_and_no_web_headers",
            "rejects_oversized_and_malformed_json_before_the_handler",
            "rejects_invalid_mutation_envelopes_duplicates_and_nested_null_before_dispatch",
            "parameterized_routes_percent_decode_bounded_values_without_service_authority",
            "caller_correlation_precedes_entropy_and_survives_timeout_handoff",
            "rejects_http_1_0_before_dispatch",
            "request_deadline_returns_a_safe_timeout_and_cancels_the_handler_future",
            "enforces_header_query_response_and_body_correlation_boundaries",
            "connection_admission_never_exceeds_the_configured_limit",
            "graceful_cancellation_stops_admission_and_drains_an_active_request",
            "linux_process_credentials_allow_uid_or_gid_and_deny_otherwise",
            "exact_positive_boundaries_are_accepted_for_every_field",
            "zero_and_just_over_maximum_fail_for_every_field"
        ])
    );

    for invariant in [
        "active_equals_final_inventory",
        "all_models_referenced_exactly",
        "authoritative_commit_owned_by_handler",
        "cursor_authentication_owned_by_handler",
        "peer_authorization_owned_by_shared_transport",
    ] {
        assert_eq!(contract["invariants"][invariant], true, "{invariant}");
    }
    for invariant in [
        "adapter_performs_sqlite",
        "adapter_performs_relay_io",
        "adapter_performs_identity_mutation",
        "raw_shared_transport_public",
        "unbounded_resource",
    ] {
        assert_eq!(contract["invariants"][invariant], false, "{invariant}");
    }
    for forbidden in [
        "IdentityRekey",
        "IdentityReplace",
        "pub fn into_inner",
        "pub fn router",
        "pub fn listener",
        "sqlx::",
    ] {
        assert!(
            !ADMIN_SOURCE.contains(forbidden),
            "forbidden admin surface `{forbidden}`"
        );
        assert!(
            !ROOT_SOURCE.contains(forbidden),
            "forbidden root surface `{forbidden}`"
        );
    }
}
