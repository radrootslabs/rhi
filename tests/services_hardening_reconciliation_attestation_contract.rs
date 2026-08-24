#![forbid(unsafe_code)]

use rhi::{
    RHI_RECONCILIATION_ATTESTATION_CONTRACT_VERSION,
    RHI_RECONCILIATION_SIGNED_ATTESTATION_MAX_BYTES,
};
use serde_json::json;

const CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_attestation.v1.json");
const ROOT: &str = include_str!("../src/lib.rs");
const SOURCE: &str = include_str!("../src/reconciliation_attestation.rs");
const IDENTITY: &str = include_str!("../src/identity_envelope.rs");
const README: &str = include_str!("../README");
const SIGNED_VECTOR: &str = include_str!(
    "../contracts/conformance/vectors/reconciliation_attestation_signed_event.v1.json"
);

#[test]
fn machine_contract_freezes_the_complete_step_196_boundary() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.reconciliation-attestation"
    );
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["contract_version"],
        RHI_RECONCILIATION_ATTESTATION_CONTRACT_VERSION
    );
    assert_eq!(contract["report"]["maximum_canonical_bytes"], 16_384);
    assert_eq!(contract["event"]["kind"], 3_441);
    assert_eq!(
        contract["event"]["maximum_signed_json_bytes"],
        RHI_RECONCILIATION_SIGNED_ATTESTATION_MAX_BYTES
    );
    assert_eq!(
        contract["conformance_vector"],
        "contracts/conformance/vectors/reconciliation_attestation_signed_event.v1.json"
    );
    let vector: serde_json::Value = serde_json::from_str(SIGNED_VECTOR).expect("signed vector");
    assert_eq!(
        vector["id"],
        "f1a2a41d73b42ba54be19c716d6b49a9e5d608ae2a9c96347155d1773b8b8a1b"
    );
    assert_eq!(vector["kind"], 3_441);
    assert_eq!(vector["tags"].as_array().expect("tags").len(), 5);
    assert_eq!(
        contract["independent_verification"],
        json!([
            "bounded_original_signed_JSON",
            "strict_NIP01_wire_admission_with_no_extra_fields",
            "event_id_recomputation",
            "Schnorr_signature",
            "exact_planned_event_id_author_created_at_kind_tags_and_content",
            "typed_RHI_attestation_decode_and_structural_tag_binding",
            "canonical_shared_report_reparse",
            "exact_manifest_binding",
            "complete_report_equality",
            "governed_supersession_ordering_when_present"
        ])
    );
    for effect in [
        "sqlite",
        "filesystem",
        "source_or_relay",
        "network",
        "task_spawn",
        "ambient_clock",
        "ambient_entropy",
        "publication",
        "job_finalization",
    ] {
        assert_eq!(contract["effects"][effect], false, "effect {effect}");
    }
}

#[test]
fn implementation_uses_only_typed_authoring_and_independent_verification() {
    assert!(ROOT.contains("mod reconciliation_attestation;"));
    assert!(!ROOT.contains("pub mod reconciliation_attestation;"));
    for required in [
        "RhiSignedEvidenceAttestation",
        "RhiEvidenceAttestationSupersession",
        "RhiReconciliationAttestationErrorKind",
        "build_rhi_signed_evidence_attestation",
        "RHI_RECONCILIATION_SIGNED_ATTESTATION_MAX_BYTES",
    ] {
        assert!(ROOT.contains(required), "root API is missing {required}");
    }
    for required in [
        "RadrootsRhiEvidenceReportV1::new(",
        "RadrootsRhiEvidenceAttestationV1::from_canonical_content(",
        "validate_rhi_evidence_attestation_supersession(",
        "AuthoredEventBody::from_rhi_evidence_attestation(",
        "AuthoredEventPlan::bind(",
        ".fill_bytes(&mut auxiliary[..])",
        "sign_nostr_event(unsigned, auxiliary)",
        "Nip01EventWire::parse_json_unverified_with_limits(",
        "verify_id(&event)",
        "verify(&event)",
        "rhi_evidence_attestation_from_event(&event)",
        "validate_against_manifest(manifest)",
    ] {
        assert!(
            SOURCE.contains(required),
            "implementation is missing {required}"
        );
    }
    for required in [
        "sign_schnorr_with_aux_rand",
        "non_secure_erase()",
        "actual.to_hex() != self.public_identity.as_hex()",
    ] {
        assert!(IDENTITY.contains(required), "signer is missing {required}");
    }
    for forbidden in [
        "std::fs",
        "std::net",
        "sqlx::",
        "tokio::",
        "SystemTime",
        "SystemEntropy",
        "OsRng",
        "thread_rng",
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "pub fn new(",
        "pub const fn new(",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "attestation boundary gained forbidden authority {forbidden}"
        );
    }
    assert!(README.contains("## Canonical signed reconciliation attestation"));
    assert!(README.contains(
        "[`reconciliation_attestation.v1.json`](contracts/services_hardening/reconciliation_attestation.v1.json)"
    ));
}
