#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use crate::cli::Command;
use radroots_sp1_guest_trade::{
    RADROOTS_SP1_TRADE_KIND_LISTING, RADROOTS_SP1_TRADE_KIND_ORDER_DECISION,
    RADROOTS_SP1_TRADE_KIND_ORDER_REQUEST, RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET,
    RADROOTS_SP1_TRADE_PROTOCOL_VERSION, RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH,
    RADROOTS_SP1_TRADE_WITNESS_VERSION, RadrootsSp1TradeCanonicalEventEvidence,
    RadrootsSp1TradeEventEvidenceRole, RadrootsSp1TradeEventWorkflowPosition,
    RadrootsSp1TradeInventoryBinWitness, RadrootsSp1TradeInventoryCommitmentWitness,
    RadrootsSp1TradeOrderAcceptanceWitness, RadrootsSp1TradeOrderDecisionEventWitness,
    RadrootsSp1TradeOrderDecisionWitness, RadrootsSp1TradeOrderItemWitness,
    RadrootsSp1TradeOrderRequestWitness,
};
use radroots_sp1_host_trade::{
    RadrootsSp1TradeProofMode, generate_order_acceptance_proof,
    verify_order_acceptance_proof_artifact_structure,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;
use thiserror::Error;

const PROTOCOL_VERSION: &str = "radroots.rhi.proof_smoke.v0";
const WORKER_NAME: &str = "rhi";
const SP1_VERSION: &str = "6.2.1";
const ORDER_ACCEPTANCE_TINY_FIXTURE: &str = "order_acceptance_tiny_v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RhiProofSmokeRequest {
    pub protocol_version: String,
    pub operation: RhiProofSmokeOperation,
    pub backend: RhiProofSmokeBackend,
    #[serde(default)]
    pub fixture: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RhiProofSmokeOperation {
    Health,
    ProofSmoke,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RhiProofSmokeBackend {
    DeterministicNone,
    LocalExecute,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RhiProofSmokeResponse {
    pub ok: bool,
    pub protocol_version: String,
    pub operation: RhiProofSmokeOperation,
    pub worker_name: String,
    pub worker_version: String,
    pub git_rev: String,
    pub sp1_version: String,
    pub backend: RhiProofSmokeBackend,
    pub capabilities: Vec<String>,
    pub proof_generated: bool,
    pub public_values_hash: Option<String>,
    pub sp1_program_hash: Option<String>,
    pub sp1_verifying_key_hash: Option<String>,
    pub event_set_root: Option<String>,
    pub reducer_output_root: Option<String>,
    pub elapsed_ms: u128,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RhiProofSmokeError {
    #[error("invalid protocol version")]
    InvalidProtocolVersion,
    #[error("proof_smoke requires fixture order_acceptance_tiny_v1")]
    InvalidFixture,
    #[error("local_execute backend is unavailable in this build")]
    LocalExecuteUnavailable,
    #[error("deterministic proof smoke failed: {0}")]
    Deterministic(String),
    #[error("SP1 execute proof smoke failed: {0}")]
    Sp1Execute(String),
}

pub async fn run_cli_command(command: Command) -> anyhow::Result<()> {
    let Command::ProofSmoke { input, output } = command else {
        return Err(anyhow::anyhow!("proof-smoke command expected"));
    };
    let request_bytes = read_input(input.as_deref())?;
    let response = handle_request_bytes(&request_bytes).await;
    let response_bytes = serde_json::to_vec_pretty(&response)?;
    write_output(output.as_deref(), &response_bytes)?;
    if response.ok {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{}",
            response
                .error
                .as_deref()
                .unwrap_or("proof smoke request failed")
        ))
    }
}

pub async fn handle_request_bytes(bytes: &[u8]) -> RhiProofSmokeResponse {
    let started = Instant::now();
    match serde_json::from_slice::<RhiProofSmokeRequest>(bytes) {
        Ok(request) => response_for_request(request, started).await,
        Err(error) => response_for_error(
            RhiProofSmokeOperation::Health,
            RhiProofSmokeBackend::DeterministicNone,
            started,
            error.to_string(),
        ),
    }
}

async fn response_for_request(
    request: RhiProofSmokeRequest,
    started: Instant,
) -> RhiProofSmokeResponse {
    if request.protocol_version != PROTOCOL_VERSION {
        return response_for_error(
            request.operation,
            request.backend,
            started,
            RhiProofSmokeError::InvalidProtocolVersion.to_string(),
        );
    }

    match request.operation {
        RhiProofSmokeOperation::Health => response_for_success(
            request.operation,
            request.backend,
            started,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        ),
        RhiProofSmokeOperation::ProofSmoke => {
            match run_proof_smoke(request.backend, request.fixture).await {
                Ok(output) => response_for_success(
                    request.operation,
                    request.backend,
                    started,
                    Some(output.public_values_hash),
                    output.sp1_program_hash,
                    output.sp1_verifying_key_hash,
                    Some(output.event_set_root),
                    Some(output.reducer_output_root),
                    output.warnings,
                ),
                Err(error) => response_for_error(
                    request.operation,
                    request.backend,
                    started,
                    error.to_string(),
                ),
            }
        }
    }
}

struct RhiProofSmokeOutput {
    public_values_hash: String,
    sp1_program_hash: Option<String>,
    sp1_verifying_key_hash: Option<String>,
    event_set_root: String,
    reducer_output_root: String,
    warnings: Vec<String>,
}

async fn run_proof_smoke(
    backend: RhiProofSmokeBackend,
    fixture: Option<String>,
) -> Result<RhiProofSmokeOutput, RhiProofSmokeError> {
    if fixture.as_deref() != Some(ORDER_ACCEPTANCE_TINY_FIXTURE) {
        return Err(RhiProofSmokeError::InvalidFixture);
    }

    let witness = order_acceptance_tiny_witness();
    match backend {
        RhiProofSmokeBackend::DeterministicNone => deterministic_smoke(&witness),
        RhiProofSmokeBackend::LocalExecute => local_execute_smoke(&witness).await,
    }
}

fn deterministic_smoke(
    witness: &RadrootsSp1TradeOrderAcceptanceWitness,
) -> Result<RhiProofSmokeOutput, RhiProofSmokeError> {
    let bundle = generate_order_acceptance_proof(witness, RadrootsSp1TradeProofMode::None)
        .map_err(|error| RhiProofSmokeError::Deterministic(error.to_string()))?;
    verify_order_acceptance_proof_artifact_structure(&bundle.execution, &bundle.proof)
        .map_err(|error| RhiProofSmokeError::Deterministic(error.to_string()))?;
    Ok(RhiProofSmokeOutput {
        public_values_hash: canonical_hex_64(&bundle.execution.public_values_hash)?,
        sp1_program_hash: None,
        sp1_verifying_key_hash: None,
        event_set_root: canonical_hex_64(&bundle.execution.public_values.event_set_root)?,
        reducer_output_root: canonical_hex_64(&bundle.execution.public_values.new_state_root)?,
        warnings: Vec::new(),
    })
}

#[cfg(feature = "sp1_proving")]
async fn local_execute_smoke(
    witness: &RadrootsSp1TradeOrderAcceptanceWitness,
) -> Result<RhiProofSmokeOutput, RhiProofSmokeError> {
    let execution = radroots_sp1_host_trade::execute_order_acceptance_sp1_public_values(witness)
        .await
        .map_err(|error| RhiProofSmokeError::Sp1Execute(error.to_string()))?
        .execution;
    Ok(RhiProofSmokeOutput {
        public_values_hash: canonical_hex_64(&execution.public_values_hash)?,
        sp1_program_hash: execution
            .public_values
            .sp1_program_hash
            .as_deref()
            .map(canonical_hex_64)
            .transpose()?,
        sp1_verifying_key_hash: execution
            .public_values
            .sp1_verifying_key_hash
            .as_deref()
            .map(canonical_hex_64)
            .transpose()?,
        event_set_root: canonical_hex_64(&execution.public_values.event_set_root)?,
        reducer_output_root: canonical_hex_64(&execution.public_values.new_state_root)?,
        warnings: Vec::new(),
    })
}

#[cfg(not(feature = "sp1_proving"))]
async fn local_execute_smoke(
    _witness: &RadrootsSp1TradeOrderAcceptanceWitness,
) -> Result<RhiProofSmokeOutput, RhiProofSmokeError> {
    Err(RhiProofSmokeError::LocalExecuteUnavailable)
}

fn response_for_success(
    operation: RhiProofSmokeOperation,
    backend: RhiProofSmokeBackend,
    started: Instant,
    public_values_hash: Option<String>,
    sp1_program_hash: Option<String>,
    sp1_verifying_key_hash: Option<String>,
    event_set_root: Option<String>,
    reducer_output_root: Option<String>,
    warnings: Vec<String>,
) -> RhiProofSmokeResponse {
    RhiProofSmokeResponse {
        ok: true,
        protocol_version: PROTOCOL_VERSION.to_string(),
        operation,
        worker_name: WORKER_NAME.to_string(),
        worker_version: env!("CARGO_PKG_VERSION").to_string(),
        git_rev: option_env!("RADROOTS_GIT_REV")
            .unwrap_or("unknown")
            .to_string(),
        sp1_version: SP1_VERSION.to_string(),
        backend,
        capabilities: capabilities(),
        proof_generated: false,
        public_values_hash,
        sp1_program_hash,
        sp1_verifying_key_hash,
        event_set_root,
        reducer_output_root,
        elapsed_ms: started.elapsed().as_millis(),
        warnings,
        error: None,
    }
}

fn canonical_hex_64(value: &str) -> Result<String, RhiProofSmokeError> {
    let candidate = value.strip_prefix("0x").unwrap_or(value);
    if candidate.len() == 64 && candidate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(candidate.to_ascii_lowercase());
    }
    Err(RhiProofSmokeError::Deterministic(
        "public value is not canonical 32-byte hex".to_string(),
    ))
}

fn response_for_error(
    operation: RhiProofSmokeOperation,
    backend: RhiProofSmokeBackend,
    started: Instant,
    error: String,
) -> RhiProofSmokeResponse {
    let mut response = response_for_success(
        operation,
        backend,
        started,
        None,
        None,
        None,
        None,
        None,
        Vec::new(),
    );
    response.ok = false;
    response.error = Some(error);
    response
}

fn capabilities() -> Vec<String> {
    let mut values = vec![
        "health".to_string(),
        "proof_smoke".to_string(),
        "deterministic_none".to_string(),
    ];
    if cfg!(feature = "sp1_proving") {
        values.push("local_execute".to_string());
    }
    values
}

pub(crate) fn order_acceptance_tiny_witness() -> RadrootsSp1TradeOrderAcceptanceWitness {
    RadrootsSp1TradeOrderAcceptanceWitness {
        witness_version: RADROOTS_SP1_TRADE_WITNESS_VERSION,
        proof_target: RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET.to_string(),
        listing_event_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        request_event_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_string(),
        decision_event_id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_string(),
        event_evidence: order_acceptance_tiny_event_evidence(),
        request: RadrootsSp1TradeOrderRequestWitness {
            order_id: "order-1".to_string(),
            listing_addr:
                "30402:1111111111111111111111111111111111111111111111111111111111111111:listing-1"
                    .to_string(),
            buyer_pubkey: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            seller_pubkey: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            items: vec![RadrootsSp1TradeOrderItemWitness {
                bin_id: "bin-1".to_string(),
                bin_count: 2,
            }],
        },
        decision: RadrootsSp1TradeOrderDecisionEventWitness {
            order_id: "order-1".to_string(),
            listing_addr:
                "30402:1111111111111111111111111111111111111111111111111111111111111111:listing-1"
                    .to_string(),
            buyer_pubkey: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            seller_pubkey: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            decision: RadrootsSp1TradeOrderDecisionWitness::Accepted {
                inventory_commitments: vec![RadrootsSp1TradeInventoryCommitmentWitness {
                    bin_id: "bin-1".to_string(),
                    bin_count: 2,
                }],
            },
        },
        inventory_bins: vec![RadrootsSp1TradeInventoryBinWitness {
            bin_id: "bin-1".to_string(),
            listing_capacity: 5,
            previous_reserved: 1,
        }],
        inventory_sequence: 7,
        previous_state_root: None,
        reducer_program_hash: RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH.to_string(),
        radroots_protocol_version: RADROOTS_SP1_TRADE_PROTOCOL_VERSION.to_string(),
        sp1_program_hash: None,
        sp1_verifying_key_hash: None,
    }
}

fn order_acceptance_tiny_event_evidence() -> Vec<RadrootsSp1TradeCanonicalEventEvidence> {
    vec![
        RadrootsSp1TradeCanonicalEventEvidence {
            event_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            signer_pubkey: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            kind: RADROOTS_SP1_TRADE_KIND_LISTING,
            canonical_event_hash:
                "0x1010101010101010101010101010101010101010101010101010101010101010".to_string(),
            signature_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            preverified_signature: true,
            role: RadrootsSp1TradeEventEvidenceRole::Seller,
            workflow_position: RadrootsSp1TradeEventWorkflowPosition::Listing,
            content_hash: "0x1212121212121212121212121212121212121212121212121212121212121212"
                .to_string(),
            tags_hash: "0x1313131313131313131313131313131313131313131313131313131313131313"
                .to_string(),
            ordering_key: "001:listing".to_string(),
        },
        RadrootsSp1TradeCanonicalEventEvidence {
            event_id: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            signer_pubkey: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            kind: RADROOTS_SP1_TRADE_KIND_ORDER_REQUEST,
            canonical_event_hash:
                "0x2020202020202020202020202020202020202020202020202020202020202020".to_string(),
            signature_hash: "0x2121212121212121212121212121212121212121212121212121212121212121"
                .to_string(),
            preverified_signature: true,
            role: RadrootsSp1TradeEventEvidenceRole::Buyer,
            workflow_position: RadrootsSp1TradeEventWorkflowPosition::OrderRequest,
            content_hash: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            tags_hash: "0x2323232323232323232323232323232323232323232323232323232323232323"
                .to_string(),
            ordering_key: "002:order_request".to_string(),
        },
        RadrootsSp1TradeCanonicalEventEvidence {
            event_id: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .to_string(),
            signer_pubkey: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            kind: RADROOTS_SP1_TRADE_KIND_ORDER_DECISION,
            canonical_event_hash:
                "0x3030303030303030303030303030303030303030303030303030303030303030".to_string(),
            signature_hash: "0x3131313131313131313131313131313131313131313131313131313131313131"
                .to_string(),
            preverified_signature: true,
            role: RadrootsSp1TradeEventEvidenceRole::Seller,
            workflow_position: RadrootsSp1TradeEventWorkflowPosition::OrderDecision,
            content_hash: "0x3232323232323232323232323232323232323232323232323232323232323232"
                .to_string(),
            tags_hash: "0x3333333333333333333333333333333333333333333333333333333333333333"
                .to_string(),
            ordering_key: "003:order_decision".to_string(),
        },
    ]
}

fn read_input(input: Option<&Path>) -> anyhow::Result<Vec<u8>> {
    match input {
        Some(path) => Ok(std::fs::read(path)?),
        None => {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::io::stdin().read_to_end(&mut bytes)?;
            Ok(bytes)
        }
    }
}

fn write_output(output: Option<&Path>, bytes: &[u8]) -> anyhow::Result<()> {
    match output {
        Some(path) => {
            std::fs::write(path, bytes)?;
            Ok(())
        }
        None => {
            println!("{}", String::from_utf8_lossy(bytes));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PROTOCOL_VERSION, RhiProofSmokeBackend, RhiProofSmokeOperation, RhiProofSmokeRequest,
        RhiProofSmokeResponse, handle_request_bytes,
    };

    fn request(operation: RhiProofSmokeOperation, backend: RhiProofSmokeBackend) -> Vec<u8> {
        serde_json::to_vec(&RhiProofSmokeRequest {
            protocol_version: PROTOCOL_VERSION.to_string(),
            operation,
            backend,
            fixture: Some("order_acceptance_tiny_v1".to_string()),
        })
        .expect("request json")
    }

    #[tokio::test]
    async fn health_returns_worker_capabilities() {
        let bytes = serde_json::to_vec(&RhiProofSmokeRequest {
            protocol_version: PROTOCOL_VERSION.to_string(),
            operation: RhiProofSmokeOperation::Health,
            backend: RhiProofSmokeBackend::DeterministicNone,
            fixture: None,
        })
        .expect("request json");
        let response: RhiProofSmokeResponse = handle_request_bytes(&bytes).await;
        assert!(response.ok);
        assert_eq!(response.worker_name, "rhi");
        assert!(response.capabilities.contains(&"health".to_string()));
        assert!(!response.proof_generated);
    }

    #[tokio::test]
    async fn deterministic_proof_smoke_returns_public_values() {
        let response = handle_request_bytes(&request(
            RhiProofSmokeOperation::ProofSmoke,
            RhiProofSmokeBackend::DeterministicNone,
        ))
        .await;
        assert!(response.ok);
        assert_eq!(response.operation, RhiProofSmokeOperation::ProofSmoke);
        assert!(response.public_values_hash.is_some());
        assert!(response.sp1_program_hash.is_none());
        assert!(response.sp1_verifying_key_hash.is_none());
        assert!(response.event_set_root.is_some());
        assert!(response.reducer_output_root.is_some());
        for value in [
            response.public_values_hash.as_deref(),
            response.event_set_root.as_deref(),
            response.reducer_output_root.as_deref(),
        ] {
            let value = value.expect("public value");
            assert_eq!(value.len(), 64);
            assert!(!value.starts_with("0x"));
            assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert!(!response.proof_generated);
    }

    #[tokio::test]
    async fn proof_smoke_rejects_unknown_fixture() {
        let response = handle_request_bytes(
            &serde_json::to_vec(&RhiProofSmokeRequest {
                protocol_version: PROTOCOL_VERSION.to_string(),
                operation: RhiProofSmokeOperation::ProofSmoke,
                backend: RhiProofSmokeBackend::DeterministicNone,
                fixture: Some("other".to_string()),
            })
            .expect("request json"),
        )
        .await;
        assert!(!response.ok);
        assert_eq!(
            response.error.as_deref(),
            Some("proof_smoke requires fixture order_acceptance_tiny_v1")
        );
    }

    #[tokio::test]
    async fn proof_smoke_rejects_full_proof_request_fields() {
        let response = handle_request_bytes(
            br#"{"protocol_version":"radroots.rhi.proof_smoke.v0","operation":"proof_smoke","backend":"deterministic_none","fixture":"order_acceptance_tiny_v1","proof_mode":"core"}"#,
        )
        .await;
        assert!(!response.ok);
        assert!(
            response
                .error
                .as_deref()
                .is_some_and(|error| error.contains("unknown field"))
        );
    }

    #[cfg(not(feature = "sp1_proving"))]
    #[tokio::test]
    async fn local_execute_reports_unavailable_without_feature() {
        let response = handle_request_bytes(&request(
            RhiProofSmokeOperation::ProofSmoke,
            RhiProofSmokeBackend::LocalExecute,
        ))
        .await;
        assert!(!response.ok);
        assert_eq!(
            response.error.as_deref(),
            Some("local_execute backend is unavailable in this build")
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn local_execute_returns_sp1_public_values_without_proof_generation() {
        let deterministic = handle_request_bytes(&request(
            RhiProofSmokeOperation::ProofSmoke,
            RhiProofSmokeBackend::DeterministicNone,
        ))
        .await;
        let response = handle_request_bytes(&request(
            RhiProofSmokeOperation::ProofSmoke,
            RhiProofSmokeBackend::LocalExecute,
        ))
        .await;
        assert!(response.ok);
        assert_eq!(response.operation, RhiProofSmokeOperation::ProofSmoke);
        assert_eq!(response.backend, RhiProofSmokeBackend::LocalExecute);
        assert!(response.capabilities.contains(&"local_execute".to_string()));
        assert!(!response.proof_generated);
        assert_ne!(
            response.public_values_hash,
            deterministic.public_values_hash
        );
        assert!(response.sp1_program_hash.is_some());
        assert!(response.sp1_verifying_key_hash.is_some());
        for value in [
            response.sp1_program_hash.as_deref(),
            response.sp1_verifying_key_hash.as_deref(),
        ] {
            let value = value.expect("SP1 identity");
            assert_eq!(value.len(), 64);
            assert!(!value.starts_with("0x"));
            assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert_eq!(response.event_set_root, deterministic.event_set_root);
        assert_eq!(
            response.reducer_output_root,
            deterministic.reducer_output_root
        );
        assert!(response.error.is_none());
    }
}
