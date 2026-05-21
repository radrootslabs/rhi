#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use crate::cli::Command;
use radroots_sp1_guest_trade::{
    RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET, RADROOTS_SP1_TRADE_PROTOCOL_VERSION,
    RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH, RADROOTS_SP1_TRADE_WITNESS_VERSION,
};
use radroots_sp1_host_trade::{
    RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION, RADROOTS_SP1_TRADE_SP1_VERSION_LINE,
    RadrootsSp1TradeProofEngine, RadrootsSp1TradeProofMode, RadrootsSp1TradeRemoteProverRequest,
    RadrootsSp1TradeRemoteProverResponse, RadrootsSp1TradeRemoteProverStatus,
};
use std::path::Path;

pub async fn run_cli_command(command: Command) -> anyhow::Result<()> {
    let Command::RemoteProve {
        input,
        output,
        proof_engine,
    } = command
    else {
        return Err(anyhow::anyhow!("remote-prove command expected"));
    };
    let engine = RadrootsSp1TradeProofEngine::from_label(proof_engine.as_str())
        .ok_or_else(|| anyhow::anyhow!("invalid proof engine"))?;
    let request_bytes = read_input(input.as_deref())?;
    let response = handle_request_bytes(&request_bytes, engine).await;
    let response_bytes = serde_json::to_vec_pretty(&response)?;
    write_output(output.as_deref(), &response_bytes)?;
    if response.status == RadrootsSp1TradeRemoteProverStatus::Completed {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{}",
            response
                .message
                .as_deref()
                .unwrap_or("remote proof request did not complete")
        ))
    }
}

pub async fn handle_request_bytes(
    bytes: &[u8],
    engine: RadrootsSp1TradeProofEngine,
) -> RadrootsSp1TradeRemoteProverResponse {
    let request_id = request_id_from_bytes(bytes);
    let request = match serde_json::from_slice::<RadrootsSp1TradeRemoteProverRequest>(bytes) {
        Ok(request) => request,
        Err(error) => {
            return rejected_response(request_id, "invalid_json", error.to_string());
        }
    };
    match validate_request(&request) {
        Ok(()) => prove_request(request, engine).await,
        Err(rejection) => {
            rejected_response(request.request_id, rejection.reason, rejection.message)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RemoteProveRejection {
    reason: &'static str,
    message: &'static str,
}

fn validate_request(
    request: &RadrootsSp1TradeRemoteProverRequest,
) -> Result<(), RemoteProveRejection> {
    if request.schema_version != RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION {
        return Err(rejection(
            "invalid_schema_version",
            "invalid schema_version",
        ));
    }
    if request.request_id.trim().is_empty() {
        return Err(rejection("invalid_request_id", "invalid request_id"));
    }
    if request.proof_target != RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET {
        return Err(rejection(
            "unsupported_proof_target",
            "unsupported proof_target",
        ));
    }
    if request.proof_mode != RadrootsSp1TradeProofMode::Core {
        return Err(rejection(
            "unsupported_proof_mode",
            "unsupported proof_mode",
        ));
    }
    if request.sp1_version_line != RADROOTS_SP1_TRADE_SP1_VERSION_LINE {
        return Err(rejection(
            "unsupported_sp1_version",
            "unsupported sp1 version",
        ));
    }
    if request.expected_reducer_program_hash != RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH {
        return Err(rejection(
            "reducer_program_hash_mismatch",
            "expected reducer program hash mismatch",
        ));
    }
    if request.expected_protocol_version != RADROOTS_SP1_TRADE_PROTOCOL_VERSION {
        return Err(rejection(
            "protocol_version_mismatch",
            "expected protocol version mismatch",
        ));
    }
    if request.expected_witness_version != RADROOTS_SP1_TRADE_WITNESS_VERSION {
        return Err(rejection(
            "witness_version_mismatch",
            "expected witness version mismatch",
        ));
    }
    if request.witness.witness_version != request.expected_witness_version {
        return Err(rejection(
            "witness_version_mismatch",
            "witness version mismatch",
        ));
    }
    if request.witness.proof_target != request.proof_target {
        return Err(rejection(
            "proof_target_mismatch",
            "witness proof target mismatch",
        ));
    }
    if request.witness.reducer_program_hash != request.expected_reducer_program_hash {
        return Err(rejection(
            "reducer_program_hash_mismatch",
            "witness reducer program hash mismatch",
        ));
    }
    if request.witness.radroots_protocol_version != request.expected_protocol_version {
        return Err(rejection(
            "protocol_version_mismatch",
            "witness protocol version mismatch",
        ));
    }
    if request.witness.sp1_program_hash.as_deref()
        != Some(request.expected_sp1_program_hash.as_str())
    {
        return Err(rejection(
            "sp1_program_hash_mismatch",
            "witness SP1 program hash mismatch",
        ));
    }
    if request.witness.sp1_verifying_key_hash.as_deref()
        != Some(request.expected_sp1_verifying_key_hash.as_str())
    {
        return Err(rejection(
            "sp1_verifying_key_hash_mismatch",
            "witness SP1 verifying key hash mismatch",
        ));
    }
    for value in [
        request.expected_sp1_program_hash.as_str(),
        request.expected_sp1_verifying_key_hash.as_str(),
        request.expected_public_values_hash.as_str(),
    ] {
        if !is_hash32(value) {
            return Err(rejection("invalid_hash", "expected hash field is invalid"));
        }
    }
    let execution = radroots_sp1_host_trade::execute_order_acceptance_public_values(
        &request.witness,
    )
    .map_err(|_| {
        rejection(
            "public_values_execution_failed",
            "public values execution failed",
        )
    })?;
    if execution.public_values_hash != request.expected_public_values_hash {
        return Err(rejection(
            "public_values_hash_mismatch",
            "expected public values hash mismatch",
        ));
    }
    Ok(())
}

fn rejection(reason: &'static str, message: &'static str) -> RemoteProveRejection {
    RemoteProveRejection { reason, message }
}

#[cfg(feature = "sp1_proving")]
async fn prove_request(
    request: RadrootsSp1TradeRemoteProverRequest,
    engine: RadrootsSp1TradeProofEngine,
) -> RadrootsSp1TradeRemoteProverResponse {
    match radroots_sp1_host_trade::generate_order_acceptance_sp1_proof_with_engine(
        &request.witness,
        request.proof_mode,
        engine,
    )
    .await
    {
        Ok(bundle) => completed_response(request, bundle),
        Err(error) => failed_response(
            request.request_id,
            "proof_generation_failed",
            error.to_string(),
        ),
    }
}

#[cfg(not(feature = "sp1_proving"))]
async fn prove_request(
    request: RadrootsSp1TradeRemoteProverRequest,
    _engine: RadrootsSp1TradeProofEngine,
) -> RadrootsSp1TradeRemoteProverResponse {
    failed_response(
        request.request_id,
        "proof_generation_unavailable",
        "remote-prove requires the sp1_proving feature".to_string(),
    )
}

#[cfg(feature = "sp1_proving")]
fn completed_response(
    request: RadrootsSp1TradeRemoteProverRequest,
    bundle: radroots_sp1_host_trade::RadrootsSp1TradeProofBundle,
) -> RadrootsSp1TradeRemoteProverResponse {
    if bundle.execution.public_values_hash != request.expected_public_values_hash {
        return failed_response(
            request.request_id,
            "public_values_hash_mismatch",
            "generated public values hash mismatch".to_string(),
        );
    }
    if bundle.proof.program_hash.as_deref() != Some(request.expected_sp1_program_hash.as_str()) {
        return failed_response(
            request.request_id,
            "sp1_program_hash_mismatch",
            "generated SP1 program hash mismatch".to_string(),
        );
    }
    if bundle.proof.verifying_key_hash.as_deref()
        != Some(request.expected_sp1_verifying_key_hash.as_str())
    {
        return failed_response(
            request.request_id,
            "sp1_verifying_key_hash_mismatch",
            "generated SP1 verifying key hash mismatch".to_string(),
        );
    }
    RadrootsSp1TradeRemoteProverResponse {
        schema_version: RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION,
        request_id: request.request_id,
        status: RadrootsSp1TradeRemoteProverStatus::Completed,
        status_url: None,
        status_path: None,
        proof_system: Some(request.proof_mode.proof_system()),
        proof_mode: Some(request.proof_mode),
        public_values_hash: Some(bundle.execution.public_values_hash),
        sp1_program_hash: bundle.proof.program_hash.clone(),
        sp1_verifying_key_hash: bundle.proof.verifying_key_hash.clone(),
        proof_artifact: Some(bundle.proof),
        resolved_proof_envelope_base64: None,
        reason_code: None,
        message: None,
        detail: None,
    }
}

fn rejected_response(
    request_id: String,
    reason: impl Into<String>,
    message: impl Into<String>,
) -> RadrootsSp1TradeRemoteProverResponse {
    terminal_response(
        request_id,
        RadrootsSp1TradeRemoteProverStatus::Rejected,
        reason,
        message,
    )
}

fn failed_response(
    request_id: String,
    reason: impl Into<String>,
    message: impl Into<String>,
) -> RadrootsSp1TradeRemoteProverResponse {
    terminal_response(
        request_id,
        RadrootsSp1TradeRemoteProverStatus::Failed,
        reason,
        message,
    )
}

fn terminal_response(
    request_id: String,
    status: RadrootsSp1TradeRemoteProverStatus,
    reason: impl Into<String>,
    message: impl Into<String>,
) -> RadrootsSp1TradeRemoteProverResponse {
    RadrootsSp1TradeRemoteProverResponse {
        schema_version: RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION,
        request_id,
        status,
        status_url: None,
        status_path: None,
        proof_system: None,
        proof_mode: None,
        public_values_hash: None,
        sp1_program_hash: None,
        sp1_verifying_key_hash: None,
        proof_artifact: None,
        resolved_proof_envelope_base64: None,
        reason_code: Some(reason.into()),
        message: Some(message.into()),
        detail: None,
    }
}

fn request_id_from_bytes(bytes: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| {
            let request_id = value
                .get("request_id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)?;
            if request_id.is_empty() {
                None
            } else {
                Some(request_id.to_owned())
            }
        })
        .unwrap_or_else(|| "invalid-request".to_string())
}

fn is_hash32(value: &str) -> bool {
    value.len() == 66
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
    use super::handle_request_bytes;
    use radroots_sp1_guest_trade::{
        RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET, RADROOTS_SP1_TRADE_PROTOCOL_VERSION,
        RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH, RADROOTS_SP1_TRADE_WITNESS_VERSION,
    };
    use radroots_sp1_host_trade::{
        RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION, RADROOTS_SP1_TRADE_SP1_VERSION_LINE,
        RadrootsSp1TradeProofEngine, RadrootsSp1TradeProofMode,
        RadrootsSp1TradeRemoteProverRequest, RadrootsSp1TradeRemoteProverStatus,
    };

    fn hash32(ch: char) -> String {
        format!("0x{}", ch.to_string().repeat(64))
    }

    fn request() -> RadrootsSp1TradeRemoteProverRequest {
        let mut witness = crate::proof_smoke::order_acceptance_tiny_witness();
        witness.sp1_program_hash = Some(hash32('a'));
        witness.sp1_verifying_key_hash = Some(hash32('b'));
        let execution = radroots_sp1_host_trade::execute_order_acceptance_public_values(&witness)
            .expect("public values");
        RadrootsSp1TradeRemoteProverRequest {
            schema_version: RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION,
            request_id: "request-1".to_string(),
            proof_target: RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET.to_string(),
            proof_mode: RadrootsSp1TradeProofMode::Core,
            sp1_version_line: RADROOTS_SP1_TRADE_SP1_VERSION_LINE.to_string(),
            witness,
            expected_sp1_program_hash: hash32('a'),
            expected_sp1_verifying_key_hash: hash32('b'),
            expected_public_values_hash: execution.public_values_hash,
            expected_reducer_program_hash: RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH.to_string(),
            expected_protocol_version: RADROOTS_SP1_TRADE_PROTOCOL_VERSION.to_string(),
            expected_witness_version: RADROOTS_SP1_TRADE_WITNESS_VERSION,
        }
    }

    #[tokio::test]
    async fn remote_prove_rejects_unknown_provider_fields() {
        let response = handle_request_bytes(
            br#"{"schema_version":1,"request_id":"request-1","proof_target":"order_acceptance_v1","proof_mode":"core","sp1_version_line":"sp1-sdk-6.2.1","expected_sp1_program_hash":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_sp1_verifying_key_hash":"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_public_values_hash":"0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","expected_reducer_program_hash":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","expected_protocol_version":"radroots.sp1.trade.v1","expected_witness_version":1,"provider":"runpod"}"#,
            RadrootsSp1TradeProofEngine::Cpu,
        )
        .await;
        assert_eq!(response.request_id, "request-1");
        assert_eq!(
            response.status,
            RadrootsSp1TradeRemoteProverStatus::Rejected
        );
        assert_eq!(response.reason_code.as_deref(), Some("invalid_json"));
    }

    #[tokio::test]
    async fn remote_prove_rejects_expected_public_values_hash_mismatch() {
        let mut request = request();
        request.expected_public_values_hash = hash32('c');
        let response = handle_request_bytes(
            &serde_json::to_vec(&request).expect("request json"),
            RadrootsSp1TradeProofEngine::Cpu,
        )
        .await;
        assert_eq!(
            response.status,
            RadrootsSp1TradeRemoteProverStatus::Rejected
        );
        assert_eq!(
            response.reason_code.as_deref(),
            Some("public_values_hash_mismatch")
        );
    }

    #[tokio::test]
    async fn remote_prove_rejects_unsupported_modes_before_generation() {
        let mut request = request();
        request.proof_mode = RadrootsSp1TradeProofMode::Compressed;
        let response = handle_request_bytes(
            &serde_json::to_vec(&request).expect("request json"),
            RadrootsSp1TradeProofEngine::Cpu,
        )
        .await;
        assert_eq!(
            response.status,
            RadrootsSp1TradeRemoteProverStatus::Rejected
        );
        assert_eq!(
            response.reason_code.as_deref(),
            Some("unsupported_proof_mode")
        );
    }

    #[cfg(not(feature = "sp1_proving"))]
    #[tokio::test]
    async fn remote_prove_reports_generation_unavailable_without_proving_feature() {
        let request = request();
        let response = handle_request_bytes(
            &serde_json::to_vec(&request).expect("request json"),
            RadrootsSp1TradeProofEngine::Cpu,
        )
        .await;
        assert_eq!(response.status, RadrootsSp1TradeRemoteProverStatus::Failed);
        assert_eq!(
            response.reason_code.as_deref(),
            Some("proof_generation_unavailable")
        );
    }
}
