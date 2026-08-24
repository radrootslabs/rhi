#![forbid(unsafe_code)]

use rhi::RhiAdminRoute;
use serde_json::Value;

const OFFLINE_IDENTITY_CONTRACT: &str =
    include_str!("../contracts/services_hardening/admin_identity_offline.v1.json");
const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");
const ADMIN_SOURCE: &str = include_str!("../src/admin_v1.rs");
const ROOT_SOURCE: &str = include_str!("../src/lib.rs");

#[test]
fn final_identity_policy_is_offline_only_and_inventory_is_exact() {
    let policy: Value =
        serde_json::from_str(OFFLINE_IDENTITY_CONTRACT).expect("offline identity contract");
    let operator: Value = serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract");

    assert_eq!(policy["schema"], "radroots.rhi.admin-identity-offline.v1");
    assert_eq!(policy["contract_version"], 1);
    assert_eq!(policy["final_inventory"]["route_count"], 20);
    assert_eq!(policy["final_inventory"]["model_count"], 33);
    assert_eq!(
        policy["identity_rotation"]["mode"],
        "offline_create_new_configuration_apply_restart"
    );
    assert_eq!(policy["identity_rotation"]["unix_admin_mutation"], false);
    assert_eq!(
        policy["peer_authorization"]["grants_identity_provider_authority"],
        false
    );
    assert_eq!(
        policy["peer_authorization"]["grants_direct_sqlite_authority"],
        false
    );

    let routes = operator["admin"]["routes"].as_array().expect("routes");
    let models = operator["admin"]["models"].as_object().expect("models");
    let types = operator["admin"]["types"].as_object().expect("types");
    assert_eq!(routes.len(), 20);
    assert_eq!(models.len(), 33);
    assert_eq!(RhiAdminRoute::ALL.len(), 20);
    assert_eq!(RhiAdminRoute::ACTIVE, RhiAdminRoute::ALL);

    for removed in policy["removed_live_routes"]
        .as_array()
        .expect("removed routes")
    {
        let path = removed["path"].as_str().expect("removed path");
        let operation_id = removed["operation_id"]
            .as_str()
            .expect("removed operation ID");
        assert!(routes.iter().all(|route| route["path"] != path));
        assert!(
            routes
                .iter()
                .all(|route| route["operation_id"] != operation_id)
        );
    }
    for removed in policy["removed_models"].as_array().expect("removed models") {
        assert!(!models.contains_key(removed.as_str().expect("model name")));
    }
    for removed in policy["removed_operator_types"]
        .as_array()
        .expect("removed operator types")
    {
        assert!(!types.contains_key(removed.as_str().expect("type name")));
    }
}

#[test]
fn removed_live_identity_surface_cannot_reenter_the_adapter_or_root_api() {
    for forbidden in [
        "IdentityRekey",
        "IdentityReplace",
        "identity_rekey_request_v1",
        "identity_replace_request_v1",
        "identity_mutation_receipt_v1",
        "build_rhi_identity",
        "direct_sqlite",
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
    for required in [
        "pub const ALL: [Self; 20]",
        "pub const ACTIVE: [Self; 20] = Self::ALL",
        "Live identity rekey and replace are absent by final offline-only policy",
    ] {
        assert!(
            ADMIN_SOURCE.contains(required),
            "missing guard `{required}`"
        );
    }
}
