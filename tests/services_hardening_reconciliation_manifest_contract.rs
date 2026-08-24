#![forbid(unsafe_code)]

use rhi::RHI_RECONCILIATION_MANIFEST_CONTRACT_VERSION;
use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_manifest.v1.json");
const ROOT: &str = include_str!("../src/lib.rs");
const SOURCE: &str = include_str!("../src/reconciliation_manifest.rs");
const COMMIT: &str = include_str!("../src/reconciliation_commit.rs");
const README: &str = include_str!("../README");

#[test]
fn machine_contract_freezes_the_complete_step_191_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-manifest");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_RECONCILIATION_MANIFEST_CONTRACT_VERSION
    );
    assert_eq!(
        contract["construction_authority"],
        "confirmed_step_190_commit_outcome_only"
    );
    assert_eq!(
        contract["shared_manifest"]["contract_id"],
        "radroots.trade.evidence-manifest.v1"
    );
    assert_eq!(contract["shared_manifest"]["source_count_maximum"], 16);
    assert_eq!(
        contract["shared_manifest"]["observation_count_maximum"],
        65_536
    );
    assert_eq!(
        contract["identity"]["source_selector_digest"],
        "bound_inside_each_source_result_digest"
    );
    assert_eq!(
        contract["source_result_digest"]["ordered_fields"],
        json!([
            "attempt_id",
            "canonical_source_ordinal_u32_be",
            "request_id",
            "framed_source_id_utf8",
            "trade_id",
            "required_flag",
            "evidence_policy_digest",
            "source_selector_digest",
            "replay_id",
            "framed_detailed_completion_code_utf8",
            "started_at_unix_ms_u64_be",
            "finished_at_unix_ms_u64_be",
            "accepted_event_count_u32_be",
            "accepted_event_bytes_u64_be",
            "step_190_accepted_inventory_digest",
            "duplicate_observation_count_u32_be",
            "optional_first_observed_at_unix_s",
            "optional_prior_cursor",
            "overlap_seconds_u64_be",
            "inclusive_since_unix_s_u64_be",
            "optional_cursor_candidate",
            "checkpoint_eligible_flag"
        ])
    );
    assert_eq!(contract["effects"]["sqlite"], false);
    assert_eq!(contract["effects"]["ambient_clock"], false);
    assert_eq!(contract["effects"]["ambient_entropy"], false);
}

#[test]
fn manifest_boundary_is_sealed_canonical_redacted_and_effect_free() {
    assert!(ROOT.contains("mod reconciliation_manifest;"));
    assert!(!ROOT.contains("pub mod reconciliation_manifest;"));
    for required in [
        "RhiReconciliationManifest",
        "RhiReconciliationManifestError",
        "RhiReconciliationManifestErrorKind",
        "RhiReconciliationScopePrerequisites",
        "RHI_RECONCILIATION_MANIFEST_CONTRACT_VERSION",
    ] {
        assert!(ROOT.contains(required), "root API is missing {required}");
    }
    for required in [
        "RadrootsTradeEvidenceManifestV1::new(",
        "SOURCE_RESULT_DIGEST_DOMAIN",
        "PROVENANCE_DIGEST_DOMAIN",
        "SOURCE_SELECTOR",
        "committed_inventory_digest(part)",
        "RadrootsTradeSignedEventDigestV1::sha256(&record.canonical_event_json)",
        "self.manifest_material",
        "i64::try_from(observed_at.get())",
        "pub const fn shared_manifest_contract_id(&self)",
        "pub const fn shared_manifest_contract_version(&self)",
    ] {
        assert!(
            SOURCE.contains(required),
            "manifest boundary is missing {required}"
        );
    }
    assert!(COMMIT.contains("let manifest_material = committed_manifest_material(&plan, &parts)"));
    assert!(COMMIT.contains("manifest_material,"));
    assert!(
        COMMIT
            .find("let manifest_material = committed_manifest_material(&plan, &parts)")
            .expect("pure manifest derivation")
            < COMMIT
                .find(".transaction(move |transaction|")
                .expect("transaction boundary")
    );
    for forbidden in [
        "sqlx::",
        "std::fs",
        "std::net",
        "tokio::",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "from_canonical_bytes",
        "pub fn new(",
        "pub const fn new(",
        "pub fn persist",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "manifest boundary gained forbidden authority {forbidden}"
        );
    }
    assert!(README.contains("## Immutable reconciliation manifest"));
    assert!(README.contains(
        "[`reconciliation_manifest.v1.json`](contracts/services_hardening/reconciliation_manifest.v1.json)"
    ));
}
