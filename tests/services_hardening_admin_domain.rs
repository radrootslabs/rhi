#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use rhi::RhiAdminRoute;
use serde_json::Value;

const COMMON_CONTRACT: &str = include_str!("../contracts/services_hardening/admin_common.v1.json");
const DOMAIN_CONTRACT: &str = include_str!("../contracts/services_hardening/admin_domain.v1.json");
const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");
const ADMIN_SOURCE: &str = include_str!("../src/admin_v1.rs");

#[test]
fn domain_inventory_is_exact_ordered_disjoint_and_cumulative() {
    let common: Value = serde_json::from_str(COMMON_CONTRACT).expect("common admin contract");
    let domain: Value = serde_json::from_str(DOMAIN_CONTRACT).expect("domain admin contract");
    let operator: Value = serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract");
    assert_eq!(domain["schema"], "radroots.rhi.admin-domain.v1");
    assert_eq!(domain["contract_version"], 1);
    assert_eq!(domain["active_route_count"], 20);

    let common = common["registered_routes"]
        .as_array()
        .expect("common routes")
        .iter()
        .map(|value| value.as_str().expect("operation ID"))
        .collect::<Vec<_>>();
    let newly_registered = domain["newly_registered_routes"]
        .as_array()
        .expect("domain routes")
        .iter()
        .map(|value| value.as_str().expect("operation ID"))
        .collect::<Vec<_>>();
    assert_eq!(common.len(), 7);
    assert_eq!(newly_registered.len(), 13);
    assert!(common.iter().all(|route| !newly_registered.contains(route)));

    let active = common
        .iter()
        .chain(&newly_registered)
        .copied()
        .collect::<Vec<_>>();
    let governed = operator["admin"]["routes"]
        .as_array()
        .expect("operator routes")
        .iter()
        .map(|route| route["operation_id"].as_str().expect("operation ID"))
        .collect::<Vec<_>>();
    let deferred = [
        "radroots.rhi.identity.rekey.v1",
        "radroots.rhi.identity.replace.v1",
    ];
    let expected_active = governed
        .iter()
        .copied()
        .filter(|route| !deferred.contains(route))
        .collect::<Vec<_>>();
    assert_eq!(active, expected_active);
    assert_eq!(
        RhiAdminRoute::COMMON
            .into_iter()
            .map(RhiAdminRoute::operation_id)
            .collect::<Vec<_>>(),
        common
    );
    assert_eq!(
        RhiAdminRoute::DOMAIN
            .into_iter()
            .map(RhiAdminRoute::operation_id)
            .collect::<Vec<_>>(),
        newly_registered
    );
    assert_eq!(
        RhiAdminRoute::ACTIVE
            .into_iter()
            .map(RhiAdminRoute::operation_id)
            .collect::<Vec<_>>(),
        expected_active
    );
    assert_eq!(active.iter().copied().collect::<BTreeSet<_>>().len(), 20);
    assert_eq!(
        domain["deferred_routes"],
        serde_json::json!([
            "radroots.rhi.identity.rekey.v1",
            "radroots.rhi.identity.replace.v1"
        ])
    );
    assert_eq!(
        governed
            .iter()
            .copied()
            .filter(|route| deferred.contains(route))
            .collect::<Vec<_>>(),
        deferred
    );
}

#[test]
fn domain_adapter_is_bounded_handler_owned_and_sensitive_route_free() {
    let domain: Value = serde_json::from_str(DOMAIN_CONTRACT).expect("domain admin contract");
    assert_eq!(domain["pagination"]["maximum_page_items"], 200);
    assert_eq!(
        domain["pagination"]["cursor_encoding"],
        "canonical_base64url_no_padding"
    );
    assert_eq!(
        domain["pagination"]["cursor_integrity"],
        "server_authenticated"
    );
    assert_eq!(
        domain["pagination"]["cursor_binding"],
        serde_json::json!(["route", "filters", "snapshot"])
    );
    assert_eq!(domain["pagination"]["duplicate_query_items"], "reject");
    assert_eq!(domain["path_parameters"]["trade_id"]["utf8_bytes"], 32);
    assert_eq!(
        domain["authority"]["operation_id_conflicting_reuse"],
        "reject"
    );
    assert_eq!(domain["authority"]["raw_shared_router_public"], false);
    assert_eq!(domain["effects"]["adapter_performs_sqlite"], false);
    assert_eq!(domain["effects"]["adapter_performs_relay_io"], false);
    assert_eq!(domain["effects"]["identity_mutation"], false);

    for required in [
        "pub const DOMAIN: [Self; 13]",
        "pub const ACTIVE: [Self; 20]",
        "for route in RhiAdminRoute::ACTIVE",
        "Some((\"trade_id\", \"trade_id\"))",
        "RhiAdminHandlerErrorKind::InvalidCursor",
        "twenty_active_routes_round_trip_over_the_hardened_unix_boundary",
    ] {
        assert!(
            ADMIN_SOURCE.contains(required),
            "missing boundary `{required}`"
        );
    }
    for forbidden in [
        "for route in RhiAdminRoute::ALL",
        "pub fn into_inner",
        "TcpListener",
        "Cors",
    ] {
        assert!(
            !ADMIN_SOURCE.contains(forbidden),
            "forbidden boundary `{forbidden}`"
        );
    }
}
