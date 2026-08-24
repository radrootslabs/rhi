#![forbid(unsafe_code)]

use rhi::RHI_RECONCILIATION_REDUCER_CONTRACT_VERSION;
use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_reducer.v1.json");
const ROOT: &str = include_str!("../src/lib.rs");
const SOURCE: &str = include_str!("../src/reconciliation_reducer.rs");
const MANIFEST: &str = include_str!("../src/reconciliation_manifest.rs");
const README: &str = include_str!("../README");

#[test]
fn machine_contract_freezes_the_complete_step_193_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-reducer");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_RECONCILIATION_REDUCER_CONTRACT_VERSION
    );
    assert_eq!(
        contract["input"]["authority"],
        "sealed_confirmed_reconciliation_manifest_only"
    );
    assert_eq!(contract["input"]["maximum_mutations"], 65_536);
    assert_eq!(
        contract["input"]["maximum_canonical_content_bytes"],
        134_217_728
    );
    assert_eq!(
        contract["input"]["evidence_state"],
        json!({
            "missing": "missing",
            "partial": "query_partial",
            "scope_satisfied": "complete",
            "unsupported": "unsupported_version"
        })
    );
    assert_eq!(
        contract["shared_reducer"]["contract_id"],
        "radroots.trade.reducer.v1"
    );
    assert_eq!(
        contract["projection_digest"]["ordered_fields"],
        json!([
            "rhi_reducer_contract_version_u32_be",
            "shared_reducer_contract_id_length_u64_be",
            "shared_reducer_contract_id_utf8",
            "shared_reducer_contract_version_u16_be",
            "evidence_manifest_digest",
            "evidence_policy_digest",
            "shared_projection_digest"
        ])
    );
    assert_eq!(contract["effects"]["sqlite"], false);
    assert_eq!(contract["effects"]["source_or_relay"], false);
    assert_eq!(contract["effects"]["ambient_clock"], false);
    assert_eq!(contract["effects"]["ambient_entropy"], false);
}

#[test]
fn reducer_boundary_is_sealed_redacted_and_effect_free() {
    assert!(ROOT.contains("mod reconciliation_reducer;"));
    assert!(!ROOT.contains("pub mod reconciliation_reducer;"));
    for required in [
        "RhiReconciliationProjection",
        "RhiReconciliationReducerError",
        "RhiReconciliationReducerErrorKind",
        "RHI_RECONCILIATION_REDUCER_CONTRACT_VERSION",
        "reduce_rhi_reconciliation_manifest",
    ] {
        assert!(ROOT.contains(required), "root API is missing {required}");
    }
    for required in [
        "trade_mutation_from_canonical_content",
        "reduce_trade_records(input)",
        "PROJECTION_DIGEST_DOMAIN",
        "manifest.digest()",
        "inner.evidence_policy_digest()",
        "decode_lower_hex_32(shared.projection_digest())",
        "RHI_REDUCER_MAXIMUM_MUTATION_MATERIAL_BYTES",
    ] {
        assert!(SOURCE.contains(required), "reducer is missing {required}");
    }
    assert!(!SOURCE.contains("fn shared_projection(&self)"));
    for required in [
        "reducer_mutations: Box<[RhiReducerMutationMaterial]>",
        "BTreeMap::<[u8; 32], RhiReducerMutationMaterial>::new()",
        "RHI_REDUCER_MAXIMUM_MUTATION_MATERIAL_BYTES: usize = 134_217_728",
        "canonical_content: Arc<[u8]>",
        "canonical_content: fact.record.canonical_content.clone()",
    ] {
        assert!(
            MANIFEST.contains(required),
            "manifest reducer material is missing {required}"
        );
    }
    for forbidden in [
        "sqlx::",
        "std::fs",
        "std::net",
        "tokio::",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "pub fn new(",
        "pub const fn new(",
        "pub fn persist",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "reducer gained forbidden authority {forbidden}"
        );
    }
    assert!(README.contains("## Pure reconciliation reducer"));
    assert!(README.contains(
        "[`reconciliation_reducer.v1.json`](contracts/services_hardening/reconciliation_reducer.v1.json)"
    ));
}
