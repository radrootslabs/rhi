#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde_json::Value;

const COMMON_CONTRACT: &str = include_str!("../contracts/services_hardening/admin_common.v1.json");
const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");

#[test]
fn common_route_inventory_is_an_exact_ordered_subset() {
    let common: Value = serde_json::from_str(COMMON_CONTRACT).expect("common admin contract");
    let operator: Value = serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract");
    assert_eq!(common["schema"], "radroots.rhi.admin-common.v1");
    assert_eq!(common["contract_version"], 1);
    assert_eq!(common["final_inventory"]["route_count"], 20);
    assert_eq!(common["final_inventory"]["model_count"], 33);

    let registered = common["registered_routes"]
        .as_array()
        .expect("registered routes")
        .iter()
        .map(|value| value.as_str().expect("operation ID"))
        .collect::<Vec<_>>();
    assert_eq!(
        registered,
        [
            "radroots.rhi.status.get.v1",
            "radroots.rhi.config.effective.get.v1",
            "radroots.rhi.identity.status.get.v1",
            "radroots.rhi.identity.public.get.v1",
            "radroots.rhi.state.status.get.v1",
            "radroots.rhi.state.backup.create.v1",
            "radroots.rhi.metrics.snapshot.get.v1",
        ]
    );
    assert_eq!(registered.iter().copied().collect::<BTreeSet<_>>().len(), 7);
    let governed = operator["admin"]["routes"]
        .as_array()
        .expect("operator routes")
        .iter()
        .map(|route| route["operation_id"].as_str().expect("operation ID"))
        .collect::<BTreeSet<_>>();
    assert!(
        registered
            .iter()
            .all(|operation| governed.contains(operation))
    );
}

#[test]
fn common_checkpoint_contract_remains_sealed_bounded_and_partial() {
    let common: Value = serde_json::from_str(COMMON_CONTRACT).expect("common admin contract");
    assert_eq!(common["shared_transport"], "radroots_service_host");
    assert_eq!(common["authority"]["raw_shared_router_public"], false);
    assert_eq!(common["authority"]["raw_listener_public"], false);
    assert_eq!(common["authority"]["raw_json_handler_public"], false);
    assert_eq!(common["authority"]["runtime_context_required"], true);
    assert_eq!(common["wire"]["duplicate_fields"], "reject");
    assert_eq!(common["wire"]["null"], "forbidden");
    assert_eq!(common["wire"]["response_body_max_utf8_bytes"], 1_048_576);
    assert_eq!(common["effects"]["router_construction_performs_io"], false);
    assert_eq!(common["effects"]["bind_spawns_task"], false);
    assert_eq!(common["effects"]["tcp_admin"], false);
    assert_eq!(
        common["historical_deferred_route_groups"],
        serde_json::json!([
            "domain_queries_and_mutations_step_207",
            "reserved_identity_mutations_removed_step_208"
        ])
    );
}
