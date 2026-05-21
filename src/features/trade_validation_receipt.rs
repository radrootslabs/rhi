#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use radroots_events::kinds::{
    KIND_TRADE_VALIDATION_RECEIPT, KIND_WORKER_TRADE_TRANSITION_PROOF_REQ,
    KIND_WORKER_TRADE_TRANSITION_PROOF_RES, is_listing_kind,
};
use radroots_events::trade::{
    RadrootsTradeOrderDecision, RadrootsTradeOrderDecisionEvent, RadrootsTradeOrderRequested,
};
use radroots_events_codec::trade::{
    active_trade_order_decision_from_event, active_trade_order_request_from_event,
    parse_trade_listing_event_tag, parse_trade_prev_tag, parse_trade_root_tag,
};
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrKeys,
    RadrootsNostrKind, radroots_event_from_nostr, radroots_nostr_build_event,
    radroots_nostr_fetch_event_by_id, radroots_nostr_send_event,
};
use radroots_sp1_guest_trade::{
    RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET, RADROOTS_SP1_TRADE_PROTOCOL_VERSION,
    RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH, RADROOTS_SP1_TRADE_WITNESS_VERSION,
    RadrootsSp1TradeCanonicalEventEvidence, RadrootsSp1TradeEventEvidenceRole,
    RadrootsSp1TradeEventWorkflowPosition, RadrootsSp1TradeInventoryBinWitness,
    RadrootsSp1TradeInventoryCommitmentWitness, RadrootsSp1TradeOrderAcceptanceWitness,
    RadrootsSp1TradeOrderDecisionEventWitness, RadrootsSp1TradeOrderDecisionWitness,
    RadrootsSp1TradeOrderItemWitness, RadrootsSp1TradeOrderRequestWitness,
};
use radroots_sp1_host_trade::{
    RadrootsSp1TradeHostError, RadrootsSp1TradeProofBundle, RadrootsSp1TradeProofMode,
    generate_order_acceptance_proof, validation_receipt_for_order_acceptance_proof,
    verify_order_acceptance_proof_artifact_structure,
};
use radroots_trade::validation_receipt::{
    RadrootsValidationReceiptError, RadrootsValidationReceiptExpectedBinding,
    validation_receipt_event_build, verify_validation_receipt_event,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "sp1_proving")]
use std::time::Duration;
use thiserror::Error;

#[cfg(feature = "sp1_proving")]
use radroots_sp1_host_trade::{
    RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION, RADROOTS_SP1_TRADE_SP1_VERSION_LINE,
    RadrootsSp1TradeRemoteProverRequest, RadrootsSp1TradeRemoteProverResponse,
    RadrootsSp1TradeRemoteProverStatus, RadrootsSp1TradeResolvedProofArtifact,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeValidationReceiptJobRequest {
    pub witness_version: u32,
    pub proof_target: String,
    pub listing_event_id: String,
    pub request_event_id: String,
    pub decision_event_id: String,
    pub inventory_bins: Vec<RadrootsSp1TradeInventoryBinWitness>,
    pub inventory_sequence: u128,
    pub previous_state_root: Option<String>,
    pub proof_mode: RadrootsSp1TradeProofMode,
    pub reducer_program_hash: String,
    pub radroots_protocol_version: String,
    pub sp1_program_hash: Option<String>,
    pub sp1_verifying_key_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeValidationReceiptProverBackend {
    Disabled,
    DeterministicNone,
    LocalExecute,
    LocalCpuProve,
    LocalCudaProve,
    RemoteHttpProve,
}

impl TradeValidationReceiptProverBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::DeterministicNone => "deterministic_none",
            Self::LocalExecute => "local_execute",
            Self::LocalCpuProve => "local_cpu_prove",
            Self::LocalCudaProve => "local_cuda_prove",
            Self::RemoteHttpProve => "remote_http_prove",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeValidationReceiptProverPolicy {
    pub backend: TradeValidationReceiptProverBackend,
    pub proof_mode: RadrootsSp1TradeProofMode,
    #[serde(default)]
    pub expected_sp1_program_hash: Option<String>,
    #[serde(default)]
    pub expected_sp1_verifying_key_hash: Option<String>,
    #[serde(default)]
    pub remote_http: Option<TradeValidationReceiptRemoteHttpProverConfig>,
}

impl Default for TradeValidationReceiptProverPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

impl TradeValidationReceiptProverPolicy {
    pub fn disabled() -> Self {
        Self {
            backend: TradeValidationReceiptProverBackend::Disabled,
            proof_mode: RadrootsSp1TradeProofMode::None,
            expected_sp1_program_hash: None,
            expected_sp1_verifying_key_hash: None,
            remote_http: None,
        }
    }

    pub fn deterministic_none() -> Self {
        Self {
            backend: TradeValidationReceiptProverBackend::DeterministicNone,
            proof_mode: RadrootsSp1TradeProofMode::None,
            expected_sp1_program_hash: None,
            expected_sp1_verifying_key_hash: None,
            remote_http: None,
        }
    }

    pub fn validate(&self) -> Result<(), TradeValidationReceiptJobError> {
        validate_optional_hash32(&self.expected_sp1_program_hash)?;
        validate_optional_hash32(&self.expected_sp1_verifying_key_hash)?;
        match self.backend {
            TradeValidationReceiptProverBackend::Disabled => {
                if self.proof_mode != RadrootsSp1TradeProofMode::None {
                    return Err(TradeValidationReceiptJobError::ProverBackendDisabled);
                }
                if self.expected_sp1_program_hash.is_some()
                    || self.expected_sp1_verifying_key_hash.is_some()
                {
                    return Err(
                        TradeValidationReceiptJobError::Sp1IdentityConstraintsRequireSp1Proof,
                    );
                }
                Ok(())
            }
            TradeValidationReceiptProverBackend::DeterministicNone
            | TradeValidationReceiptProverBackend::LocalExecute => {
                if self.proof_mode != RadrootsSp1TradeProofMode::None {
                    return Err(TradeValidationReceiptJobError::ProverBackendRequiresNone);
                }
                if self.expected_sp1_program_hash.is_some()
                    || self.expected_sp1_verifying_key_hash.is_some()
                {
                    return Err(
                        TradeValidationReceiptJobError::Sp1IdentityConstraintsRequireSp1Proof,
                    );
                }
                if self.backend == TradeValidationReceiptProverBackend::LocalExecute
                    && !cfg!(feature = "sp1_proving")
                {
                    return Err(TradeValidationReceiptJobError::ProverBackendUnavailable(
                        self.backend.as_str(),
                    ));
                }
                Ok(())
            }
            TradeValidationReceiptProverBackend::LocalCpuProve => {
                if self.proof_mode == RadrootsSp1TradeProofMode::None {
                    return Err(TradeValidationReceiptJobError::ProverBackendRequiresSp1Proof);
                }
                if self.proof_mode != RadrootsSp1TradeProofMode::Core {
                    return Err(TradeValidationReceiptJobError::UnsupportedProofMode);
                }
                if self.expected_sp1_program_hash.is_none()
                    || self.expected_sp1_verifying_key_hash.is_none()
                {
                    return Err(TradeValidationReceiptJobError::Sp1IdentityPolicyRequired);
                }
                if !cfg!(feature = "sp1_proving") {
                    return Err(TradeValidationReceiptJobError::ProverBackendUnavailable(
                        self.backend.as_str(),
                    ));
                }
                Ok(())
            }
            TradeValidationReceiptProverBackend::LocalCudaProve => Err(
                TradeValidationReceiptJobError::ProverBackendUnavailable(self.backend.as_str()),
            ),
            TradeValidationReceiptProverBackend::RemoteHttpProve => {
                if self.proof_mode == RadrootsSp1TradeProofMode::None {
                    return Err(TradeValidationReceiptJobError::ProverBackendRequiresSp1Proof);
                }
                if self.expected_sp1_program_hash.is_none()
                    || self.expected_sp1_verifying_key_hash.is_none()
                {
                    return Err(TradeValidationReceiptJobError::Sp1IdentityPolicyRequired);
                }
                let remote_http = self
                    .remote_http
                    .as_ref()
                    .ok_or(TradeValidationReceiptJobError::RemoteHttpConfigRequired)?;
                remote_http.validate()?;
                remote_http_auth_token(remote_http)?;
                if !cfg!(feature = "sp1_proving") {
                    return Err(TradeValidationReceiptJobError::ProverBackendUnavailable(
                        self.backend.as_str(),
                    ));
                }
                Ok(())
            }
        }
    }

    pub fn validate_request(
        &self,
        request: &TradeValidationReceiptJobRequest,
    ) -> Result<(), TradeValidationReceiptJobError> {
        if request.proof_mode != self.proof_mode {
            return Err(TradeValidationReceiptJobError::ProverBackendPolicyMismatch);
        }
        if self.proof_mode == RadrootsSp1TradeProofMode::None {
            if request.sp1_program_hash.is_some() || request.sp1_verifying_key_hash.is_some() {
                return Err(TradeValidationReceiptJobError::Sp1IdentityConstraintsRequireSp1Proof);
            }
            return Ok(());
        }
        if request.sp1_program_hash.as_deref() != self.expected_sp1_program_hash.as_deref() {
            return Err(TradeValidationReceiptJobError::ExpectedSp1ProgramHashMismatch);
        }
        if request.sp1_verifying_key_hash.as_deref()
            != self.expected_sp1_verifying_key_hash.as_deref()
        {
            return Err(TradeValidationReceiptJobError::ExpectedSp1VerifyingKeyHashMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeValidationReceiptRemoteHttpProverConfig {
    pub endpoint_url: String,
    pub auth: TradeValidationReceiptRemoteHttpAuth,
    pub request_timeout_ms: u64,
    pub poll_interval_ms: u64,
    pub max_poll_attempts: u32,
    pub max_response_bytes: usize,
}

impl TradeValidationReceiptRemoteHttpProverConfig {
    pub fn validate(&self) -> Result<(), TradeValidationReceiptJobError> {
        let url = remote_http_endpoint_url(self)?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(TradeValidationReceiptJobError::RemoteHttpInvalidConfig(
                "endpoint_url",
            ));
        }
        if matches!(
            self.auth,
            TradeValidationReceiptRemoteHttpAuth::BearerTokenEnv { .. }
        ) && url.scheme() != "https"
        {
            return Err(TradeValidationReceiptJobError::RemoteHttpInvalidConfig(
                "auth.endpoint_url_scheme",
            ));
        }
        if self.request_timeout_ms == 0 {
            return Err(TradeValidationReceiptJobError::RemoteHttpInvalidConfig(
                "request_timeout_ms",
            ));
        }
        if self.poll_interval_ms == 0 {
            return Err(TradeValidationReceiptJobError::RemoteHttpInvalidConfig(
                "poll_interval_ms",
            ));
        }
        if self.max_response_bytes == 0 {
            return Err(TradeValidationReceiptJobError::RemoteHttpInvalidConfig(
                "max_response_bytes",
            ));
        }
        self.auth.validate()
    }
}

fn remote_http_endpoint_url(
    config: &TradeValidationReceiptRemoteHttpProverConfig,
) -> Result<reqwest::Url, TradeValidationReceiptJobError> {
    if config.endpoint_url.trim().is_empty() {
        return Err(TradeValidationReceiptJobError::RemoteHttpInvalidConfig(
            "endpoint_url",
        ));
    }
    reqwest::Url::parse(config.endpoint_url.as_str())
        .map_err(|_| TradeValidationReceiptJobError::RemoteHttpInvalidConfig("endpoint_url"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TradeValidationReceiptRemoteHttpAuth {
    NoAuth,
    BearerTokenEnv { env_var: String },
}

impl TradeValidationReceiptRemoteHttpAuth {
    fn validate(&self) -> Result<(), TradeValidationReceiptJobError> {
        match self {
            Self::NoAuth => Ok(()),
            Self::BearerTokenEnv { env_var } => {
                if env_var.trim().is_empty() {
                    return Err(TradeValidationReceiptJobError::RemoteHttpInvalidConfig(
                        "auth.env_var",
                    ));
                }
                Ok(())
            }
        }
    }
}

fn remote_http_auth_token(
    config: &TradeValidationReceiptRemoteHttpProverConfig,
) -> Result<Option<String>, TradeValidationReceiptJobError> {
    match &config.auth {
        TradeValidationReceiptRemoteHttpAuth::NoAuth => Ok(None),
        TradeValidationReceiptRemoteHttpAuth::BearerTokenEnv { env_var } => {
            let value = std::env::var(env_var).map_err(|_| {
                TradeValidationReceiptJobError::RemoteHttpAuthTokenMissing(env_var.clone())
            })?;
            let token = value.trim();
            if token.is_empty() {
                return Err(TradeValidationReceiptJobError::RemoteHttpAuthTokenMissing(
                    env_var.clone(),
                ));
            }
            Ok(Some(token.to_owned()))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeValidationReceiptJobResult {
    pub cryptographic_proof_verified: bool,
    pub decision_event_id: String,
    pub event_set_root: String,
    pub listing_event_id: String,
    pub order_id: String,
    pub proof_generated: bool,
    pub proof_mode: RadrootsSp1TradeProofMode,
    pub proof_system: String,
    pub public_values_hash: String,
    pub prover_backend: TradeValidationReceiptProverBackend,
    pub receipt_event_id: String,
    pub receipt_kind: u32,
    pub reducer_output_root: String,
    pub request_event_id: String,
    pub sp1_execute_checked: bool,
    pub sp1_execute_public_values_hash: Option<String>,
    pub status: TradeValidationReceiptJobStatus,
    pub worker_role: TradeValidationReceiptWorkerRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeValidationReceiptJobStatus {
    Succeeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeValidationReceiptWorkerRole {
    NonAuthoritativeProver,
}

#[derive(Debug, Error)]
pub enum TradeValidationReceiptJobError {
    #[error("event kind not supported")]
    UnsupportedKind,
    #[error("missing recipient tag")]
    MissingRecipient,
    #[error("invalid job request")]
    InvalidJobRequest,
    #[error("unsupported proof target")]
    UnsupportedProofTarget,
    #[error("unsupported witness version")]
    UnsupportedWitnessVersion,
    #[error("expected reducer program hash does not match canonical reducer")]
    ExpectedReducerProgramHashMismatch,
    #[error("expected protocol version does not match canonical protocol")]
    ExpectedProtocolVersionMismatch,
    #[error("unsupported proof mode")]
    UnsupportedProofMode,
    #[error("SP1 identity constraints require an SP1 proof mode")]
    Sp1IdentityConstraintsRequireSp1Proof,
    #[error("invalid listing event")]
    InvalidListingEvent,
    #[error("invalid signed event evidence")]
    InvalidSignedEvent,
    #[error("job request does not match fetched event set")]
    EventSetMismatch,
    #[error("invalid active trade event: {0}")]
    InvalidActiveTradeEvent(String),
    #[error("rhi prover backend is disabled")]
    ProverBackendDisabled,
    #[error("rhi prover backend requires proof_mode none")]
    ProverBackendRequiresNone,
    #[error("rhi prover backend requires an SP1 proof mode")]
    ProverBackendRequiresSp1Proof,
    #[error("rhi prover backend does not match configured policy")]
    ProverBackendPolicyMismatch,
    #[error("rhi prover backend {0} is unavailable in this build")]
    ProverBackendUnavailable(&'static str),
    #[error("configured SP1 identity policy is required for this prover backend")]
    Sp1IdentityPolicyRequired,
    #[error("remote_http prover config is required")]
    RemoteHttpConfigRequired,
    #[error("remote_http prover config field {0} is invalid")]
    RemoteHttpInvalidConfig(&'static str),
    #[error("remote_http bearer token environment variable {0} is missing or empty")]
    RemoteHttpAuthTokenMissing(String),
    #[error("remote_http transport error: {0}")]
    RemoteHttpTransport(String),
    #[error("remote_http response exceeded configured byte limit")]
    RemoteHttpResponseTooLarge,
    #[error("remote_http response field {0} is invalid")]
    RemoteHttpInvalidResponse(&'static str),
    #[error("remote_http terminal {status}: {reason_code}: {message}")]
    RemoteHttpTerminal {
        status: &'static str,
        reason_code: String,
        message: String,
    },
    #[error("remote_http polling timed out")]
    RemoteHttpTimeout,
    #[error("remote_http response identity field {0} did not match")]
    RemoteHttpIdentityMismatch(&'static str),
    #[error("expected SP1 program hash does not match configured policy")]
    ExpectedSp1ProgramHashMismatch,
    #[error("expected SP1 verifying key hash does not match configured policy")]
    ExpectedSp1VerifyingKeyHashMismatch,
    #[error("nostr error: {0}")]
    Nostr(#[from] radroots_nostr::error::RadrootsNostrError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("proof error: {0}")]
    Proof(#[from] RadrootsSp1TradeHostError),
    #[error("validation receipt error: {0}")]
    ValidationReceipt(#[from] RadrootsValidationReceiptError),
}

pub async fn handle_trade_validation_receipt_job_request(
    event: &RadrootsNostrEvent,
    keys: &RadrootsNostrKeys,
    client: &RadrootsNostrClient,
    prover_policy: &TradeValidationReceiptProverPolicy,
) -> Result<(), TradeValidationReceiptJobError> {
    let kind = event_kind_u32(event)?;
    if kind != KIND_WORKER_TRADE_TRANSITION_PROOF_REQ {
        return Err(TradeValidationReceiptJobError::UnsupportedKind);
    }

    let tags = event_tags(event);
    if !tag_has_value(&tags, "p", &keys.public_key().to_string()) {
        return Err(TradeValidationReceiptJobError::MissingRecipient);
    }

    prover_policy.validate()?;
    if prover_policy.backend == TradeValidationReceiptProverBackend::Disabled {
        return Err(TradeValidationReceiptJobError::ProverBackendDisabled);
    }
    let request: TradeValidationReceiptJobRequest = serde_json::from_str(&event.content)?;
    validate_job_request_shape(&request)?;
    prover_policy.validate_request(&request)?;

    let listing_event = fetch_event_by_id_io(client, &request.listing_event_id).await?;
    let order_request_event = fetch_event_by_id_io(client, &request.request_event_id).await?;
    let order_decision_event = fetch_event_by_id_io(client, &request.decision_event_id).await?;
    validate_fetched_event(&listing_event, &request.listing_event_id)?;
    validate_fetched_event(&order_request_event, &request.request_event_id)?;
    validate_fetched_event(&order_decision_event, &request.decision_event_id)?;

    let listing_kind = event_kind_u32(&listing_event)
        .map_err(|_| TradeValidationReceiptJobError::InvalidListingEvent)?;
    if !is_listing_kind(listing_kind) {
        return Err(TradeValidationReceiptJobError::InvalidListingEvent);
    }

    let request_rr = radroots_event_from_nostr(&order_request_event);
    let decision_rr = radroots_event_from_nostr(&order_decision_event);

    let request_envelope = active_trade_order_request_from_event(&request_rr).map_err(|error| {
        TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
    })?;
    let decision_envelope =
        active_trade_order_decision_from_event(&decision_rr).map_err(|error| {
            TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
        })?;

    let listing_event_ptr = parse_trade_listing_event_tag(&request_rr.tags)
        .map_err(|error| {
            TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
        })?
        .ok_or(TradeValidationReceiptJobError::EventSetMismatch)?;
    if listing_event_ptr.id != request.listing_event_id {
        return Err(TradeValidationReceiptJobError::EventSetMismatch);
    }

    let root_event_id = parse_trade_root_tag(&decision_rr.tags).map_err(|error| {
        TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
    })?;
    let prev_event_id = parse_trade_prev_tag(&decision_rr.tags).map_err(|error| {
        TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
    })?;
    if root_event_id.as_deref() != Some(request.request_event_id.as_str())
        || prev_event_id.as_deref() != Some(request.request_event_id.as_str())
    {
        return Err(TradeValidationReceiptJobError::EventSetMismatch);
    }

    let witness = RadrootsSp1TradeOrderAcceptanceWitness {
        witness_version: RADROOTS_SP1_TRADE_WITNESS_VERSION,
        proof_target: RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET.to_string(),
        listing_event_id: request.listing_event_id.clone(),
        request_event_id: request.request_event_id.clone(),
        decision_event_id: request.decision_event_id.clone(),
        event_evidence: canonical_event_evidence_from_events(
            &listing_event,
            &order_request_event,
            &order_decision_event,
        )?,
        request: order_request_witness_from_payload(request_envelope.payload),
        decision: order_decision_witness_from_payload(decision_envelope.payload),
        inventory_bins: request.inventory_bins.clone(),
        inventory_sequence: request.inventory_sequence,
        previous_state_root: request.previous_state_root.clone(),
        reducer_program_hash: request.reducer_program_hash.clone(),
        radroots_protocol_version: request.radroots_protocol_version.clone(),
        sp1_program_hash: request.sp1_program_hash.clone(),
        sp1_verifying_key_hash: request.sp1_verifying_key_hash.clone(),
    };
    let proof_outcome = proof_bundle_for_policy(&witness, prover_policy).await?;
    verify_order_acceptance_proof_artifact_structure(
        &proof_outcome.bundle.execution,
        &proof_outcome.bundle.proof,
    )?;
    let receipt = validation_receipt_for_order_acceptance_proof(&proof_outcome.bundle)?;
    let receipt_parts = validation_receipt_event_build(&witness.request.order_id, &receipt)?;
    let verified_receipt = verify_validation_receipt_event(
        &radroots_events::RadrootsNostrEvent {
            id: zero_event_id(),
            author: keys.public_key().to_string(),
            created_at: 0,
            kind: receipt_parts.kind,
            tags: receipt_parts.tags.clone(),
            content: receipt_parts.content.clone(),
            sig: zero_signature(),
        },
        RadrootsValidationReceiptExpectedBinding {
            event_set_root: Some(&receipt.event_set_root),
            listing_event_id: Some(&request.listing_event_id),
            order_id: Some(&witness.request.order_id),
            program_hash: prover_policy.expected_sp1_program_hash.as_deref(),
            proof_system: Some(receipt.proof.system),
            public_values_hash: Some(&receipt.public_values_hash),
            reducer_output_root: Some(&receipt.new_state_root),
            verifying_key_hash: prover_policy.expected_sp1_verifying_key_hash.as_deref(),
        },
    )?;
    let receipt_event_id = publish_event_parts_io(
        client,
        receipt_parts.kind,
        receipt_parts.content,
        receipt_parts.tags,
    )
    .await?;

    let result = TradeValidationReceiptJobResult {
        cryptographic_proof_verified: proof_outcome.cryptographic_proof_verified,
        decision_event_id: request.decision_event_id,
        event_set_root: verified_receipt.receipt.event_set_root,
        listing_event_id: request.listing_event_id,
        order_id: witness.request.order_id,
        proof_generated: proof_outcome.proof_generated,
        proof_mode: prover_policy.proof_mode,
        proof_system: verified_receipt.receipt.proof.system.as_str().to_string(),
        public_values_hash: verified_receipt.receipt.public_values_hash,
        prover_backend: prover_policy.backend,
        receipt_event_id: receipt_event_id.clone(),
        receipt_kind: KIND_TRADE_VALIDATION_RECEIPT,
        reducer_output_root: verified_receipt.receipt.new_state_root,
        request_event_id: request.request_event_id,
        sp1_execute_checked: proof_outcome.sp1_execute_checked,
        sp1_execute_public_values_hash: proof_outcome.sp1_execute_public_values_hash,
        status: TradeValidationReceiptJobStatus::Succeeded,
        worker_role: TradeValidationReceiptWorkerRole::NonAuthoritativeProver,
    };
    let result_content = serde_json::to_string(&result)?;
    let result_tags = result_tags(event, &receipt_event_id, &result);
    publish_event_parts_io(
        client,
        KIND_WORKER_TRADE_TRANSITION_PROOF_RES,
        result_content,
        result_tags,
    )
    .await?;

    Ok(())
}

fn canonical_event_evidence_from_events(
    listing_event: &RadrootsNostrEvent,
    order_request_event: &RadrootsNostrEvent,
    order_decision_event: &RadrootsNostrEvent,
) -> Result<Vec<RadrootsSp1TradeCanonicalEventEvidence>, TradeValidationReceiptJobError> {
    Ok(vec![
        canonical_event_evidence(
            listing_event,
            RadrootsSp1TradeEventEvidenceRole::Seller,
            RadrootsSp1TradeEventWorkflowPosition::Listing,
            "001:listing",
        )?,
        canonical_event_evidence(
            order_request_event,
            RadrootsSp1TradeEventEvidenceRole::Buyer,
            RadrootsSp1TradeEventWorkflowPosition::OrderRequest,
            "002:order_request",
        )?,
        canonical_event_evidence(
            order_decision_event,
            RadrootsSp1TradeEventEvidenceRole::Seller,
            RadrootsSp1TradeEventWorkflowPosition::OrderDecision,
            "003:order_decision",
        )?,
    ])
}

fn canonical_event_evidence(
    event: &RadrootsNostrEvent,
    role: RadrootsSp1TradeEventEvidenceRole,
    workflow_position: RadrootsSp1TradeEventWorkflowPosition,
    ordering_key: &'static str,
) -> Result<RadrootsSp1TradeCanonicalEventEvidence, TradeValidationReceiptJobError> {
    event
        .verify()
        .map_err(|_| TradeValidationReceiptJobError::InvalidSignedEvent)?;
    let canonical_event_json = serde_json::to_string(event)?;
    let tags_json = serde_json::to_vec(&event.tags)?;
    Ok(RadrootsSp1TradeCanonicalEventEvidence {
        event_id: event.id.to_hex(),
        signer_pubkey: event.pubkey.to_hex(),
        kind: event_kind_u32(event)?,
        canonical_event_hash: hash_bytes(
            "radroots:canonical-event:v1",
            canonical_event_json.as_bytes(),
        ),
        signature_hash: hash_bytes(
            "radroots:event-signature:v1",
            event.sig.to_string().as_bytes(),
        ),
        preverified_signature: true,
        role,
        workflow_position,
        content_hash: hash_bytes("radroots:event-content:v1", event.content.as_bytes()),
        tags_hash: hash_bytes("radroots:event-tags:v1", &tags_json),
        ordering_key: ordering_key.to_string(),
    })
}

fn validate_fetched_event(
    event: &RadrootsNostrEvent,
    expected_event_id: &str,
) -> Result<(), TradeValidationReceiptJobError> {
    if event.id.to_hex() != expected_event_id {
        return Err(TradeValidationReceiptJobError::EventSetMismatch);
    }
    event
        .verify()
        .map_err(|_| TradeValidationReceiptJobError::InvalidSignedEvent)
}

fn hash_bytes(domain: &'static str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(bytes);
    format!("0x{}", hex_lower(hasher.finalize().as_slice()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn order_request_witness_from_payload(
    payload: RadrootsTradeOrderRequested,
) -> RadrootsSp1TradeOrderRequestWitness {
    RadrootsSp1TradeOrderRequestWitness {
        order_id: payload.order_id,
        listing_addr: payload.listing_addr,
        buyer_pubkey: payload.buyer_pubkey,
        seller_pubkey: payload.seller_pubkey,
        items: payload
            .items
            .into_iter()
            .map(|item| RadrootsSp1TradeOrderItemWitness {
                bin_id: item.bin_id,
                bin_count: item.bin_count,
            })
            .collect(),
    }
}

fn order_decision_witness_from_payload(
    payload: RadrootsTradeOrderDecisionEvent,
) -> RadrootsSp1TradeOrderDecisionEventWitness {
    RadrootsSp1TradeOrderDecisionEventWitness {
        order_id: payload.order_id,
        listing_addr: payload.listing_addr,
        buyer_pubkey: payload.buyer_pubkey,
        seller_pubkey: payload.seller_pubkey,
        decision: match payload.decision {
            RadrootsTradeOrderDecision::Accepted {
                inventory_commitments,
            } => RadrootsSp1TradeOrderDecisionWitness::Accepted {
                inventory_commitments: inventory_commitments
                    .into_iter()
                    .map(|commitment| RadrootsSp1TradeInventoryCommitmentWitness {
                        bin_id: commitment.bin_id,
                        bin_count: commitment.bin_count,
                    })
                    .collect(),
            },
            RadrootsTradeOrderDecision::Declined { reason } => {
                RadrootsSp1TradeOrderDecisionWitness::Declined { reason }
            }
        },
    }
}

struct TradeValidationReceiptProofOutcome {
    bundle: RadrootsSp1TradeProofBundle,
    proof_generated: bool,
    sp1_execute_checked: bool,
    sp1_execute_public_values_hash: Option<String>,
    cryptographic_proof_verified: bool,
}

async fn proof_bundle_for_policy(
    witness: &RadrootsSp1TradeOrderAcceptanceWitness,
    policy: &TradeValidationReceiptProverPolicy,
) -> Result<TradeValidationReceiptProofOutcome, TradeValidationReceiptJobError> {
    match policy.backend {
        TradeValidationReceiptProverBackend::Disabled => {
            Err(TradeValidationReceiptJobError::ProverBackendDisabled)
        }
        TradeValidationReceiptProverBackend::DeterministicNone => {
            let bundle = generate_order_acceptance_proof(witness, policy.proof_mode)?;
            Ok(TradeValidationReceiptProofOutcome {
                bundle,
                proof_generated: false,
                sp1_execute_checked: false,
                sp1_execute_public_values_hash: None,
                cryptographic_proof_verified: false,
            })
        }
        TradeValidationReceiptProverBackend::LocalExecute => {
            run_local_execute_backend(witness, policy.proof_mode).await
        }
        TradeValidationReceiptProverBackend::LocalCpuProve => {
            run_local_cpu_prove_backend(witness, policy.proof_mode).await
        }
        TradeValidationReceiptProverBackend::LocalCudaProve => Err(
            TradeValidationReceiptJobError::ProverBackendUnavailable(policy.backend.as_str()),
        ),
        TradeValidationReceiptProverBackend::RemoteHttpProve => {
            run_remote_http_prove_backend(witness, policy).await
        }
    }
}

#[cfg(feature = "sp1_proving")]
async fn run_local_execute_backend(
    witness: &RadrootsSp1TradeOrderAcceptanceWitness,
    proof_mode: RadrootsSp1TradeProofMode,
) -> Result<TradeValidationReceiptProofOutcome, TradeValidationReceiptJobError> {
    let sp1_execution =
        radroots_sp1_host_trade::execute_order_acceptance_sp1_public_values(witness).await?;
    let bundle = generate_order_acceptance_proof(witness, proof_mode)?;
    Ok(TradeValidationReceiptProofOutcome {
        bundle,
        proof_generated: false,
        sp1_execute_checked: true,
        sp1_execute_public_values_hash: Some(sp1_execution.execution.public_values_hash),
        cryptographic_proof_verified: false,
    })
}

#[cfg(not(feature = "sp1_proving"))]
async fn run_local_execute_backend(
    _witness: &RadrootsSp1TradeOrderAcceptanceWitness,
    _proof_mode: RadrootsSp1TradeProofMode,
) -> Result<TradeValidationReceiptProofOutcome, TradeValidationReceiptJobError> {
    Err(TradeValidationReceiptJobError::ProverBackendUnavailable(
        TradeValidationReceiptProverBackend::LocalExecute.as_str(),
    ))
}

#[cfg(feature = "sp1_proving")]
async fn run_local_cpu_prove_backend(
    witness: &RadrootsSp1TradeOrderAcceptanceWitness,
    proof_mode: RadrootsSp1TradeProofMode,
) -> Result<TradeValidationReceiptProofOutcome, TradeValidationReceiptJobError> {
    let bundle =
        radroots_sp1_host_trade::generate_order_acceptance_sp1_proof(witness, proof_mode).await?;
    radroots_sp1_host_trade::verify_order_acceptance_resolved_sp1_proof_artifact(
        &bundle.execution,
        &RadrootsSp1TradeResolvedProofArtifact::inline(bundle.proof.clone()),
    )
    .await?;
    Ok(TradeValidationReceiptProofOutcome {
        sp1_execute_public_values_hash: Some(bundle.execution.public_values_hash.clone()),
        bundle,
        proof_generated: true,
        sp1_execute_checked: true,
        cryptographic_proof_verified: true,
    })
}

#[cfg(feature = "sp1_proving")]
async fn run_remote_http_prove_backend(
    witness: &RadrootsSp1TradeOrderAcceptanceWitness,
    policy: &TradeValidationReceiptProverPolicy,
) -> Result<TradeValidationReceiptProofOutcome, TradeValidationReceiptJobError> {
    let remote_http = policy
        .remote_http
        .as_ref()
        .ok_or(TradeValidationReceiptJobError::RemoteHttpConfigRequired)?;
    let expected_sp1_program_hash = policy
        .expected_sp1_program_hash
        .as_deref()
        .ok_or(TradeValidationReceiptJobError::Sp1IdentityPolicyRequired)?;
    let expected_sp1_verifying_key_hash = policy
        .expected_sp1_verifying_key_hash
        .as_deref()
        .ok_or(TradeValidationReceiptJobError::Sp1IdentityPolicyRequired)?;
    let execution = radroots_sp1_host_trade::execute_order_acceptance_public_values(witness)?;
    let request = RadrootsSp1TradeRemoteProverRequest {
        schema_version: RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION,
        request_id: remote_http_request_id(witness)?,
        proof_target: RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET.to_string(),
        proof_mode: policy.proof_mode,
        sp1_version_line: RADROOTS_SP1_TRADE_SP1_VERSION_LINE.to_string(),
        witness: witness.clone(),
        expected_sp1_program_hash: expected_sp1_program_hash.to_owned(),
        expected_sp1_verifying_key_hash: expected_sp1_verifying_key_hash.to_owned(),
        expected_reducer_program_hash: RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH.to_string(),
        expected_protocol_version: RADROOTS_SP1_TRADE_PROTOCOL_VERSION.to_string(),
        expected_witness_version: RADROOTS_SP1_TRADE_WITNESS_VERSION,
    };
    let response = remote_http_completed_response(remote_http, &request).await?;
    let artifact = remote_http_verified_artifact(
        &execution,
        policy,
        expected_sp1_program_hash,
        expected_sp1_verifying_key_hash,
        &request,
        response,
    )
    .await?;
    Ok(TradeValidationReceiptProofOutcome {
        sp1_execute_public_values_hash: Some(execution.public_values_hash.clone()),
        bundle: RadrootsSp1TradeProofBundle {
            execution,
            proof: artifact,
        },
        proof_generated: true,
        sp1_execute_checked: true,
        cryptographic_proof_verified: true,
    })
}

#[cfg(not(feature = "sp1_proving"))]
async fn run_remote_http_prove_backend(
    _witness: &RadrootsSp1TradeOrderAcceptanceWitness,
    _policy: &TradeValidationReceiptProverPolicy,
) -> Result<TradeValidationReceiptProofOutcome, TradeValidationReceiptJobError> {
    Err(TradeValidationReceiptJobError::ProverBackendUnavailable(
        TradeValidationReceiptProverBackend::RemoteHttpProve.as_str(),
    ))
}

#[cfg(feature = "sp1_proving")]
fn remote_http_request_id(
    witness: &RadrootsSp1TradeOrderAcceptanceWitness,
) -> Result<String, TradeValidationReceiptJobError> {
    let bytes = serde_json::to_vec(witness)?;
    Ok(hash_bytes("radroots:rhi-remote-proof-request:v1", &bytes))
}

#[cfg(feature = "sp1_proving")]
async fn remote_http_completed_response(
    config: &TradeValidationReceiptRemoteHttpProverConfig,
    request: &RadrootsSp1TradeRemoteProverRequest,
) -> Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError> {
    let mut response =
        remote_http_post_json_io(config, config.endpoint_url.as_str(), request).await?;
    remote_http_validate_response_identity(&response, request)?;
    match response.status {
        RadrootsSp1TradeRemoteProverStatus::Completed => return Ok(response),
        RadrootsSp1TradeRemoteProverStatus::Failed => {
            return Err(remote_http_terminal_error("failed", response));
        }
        RadrootsSp1TradeRemoteProverStatus::Rejected => {
            return Err(remote_http_terminal_error("rejected", response));
        }
        RadrootsSp1TradeRemoteProverStatus::Accepted
        | RadrootsSp1TradeRemoteProverStatus::Running => {}
    }
    for _ in 0..config.max_poll_attempts {
        let status_url = remote_http_status_url(config, &response)?;
        tokio::time::sleep(Duration::from_millis(config.poll_interval_ms)).await;
        response = remote_http_get_json_io(config, status_url.as_str(), request).await?;
        remote_http_validate_response_identity(&response, request)?;
        match response.status {
            RadrootsSp1TradeRemoteProverStatus::Completed => return Ok(response),
            RadrootsSp1TradeRemoteProverStatus::Failed => {
                return Err(remote_http_terminal_error("failed", response));
            }
            RadrootsSp1TradeRemoteProverStatus::Rejected => {
                return Err(remote_http_terminal_error("rejected", response));
            }
            RadrootsSp1TradeRemoteProverStatus::Accepted
            | RadrootsSp1TradeRemoteProverStatus::Running => {}
        }
    }
    Err(TradeValidationReceiptJobError::RemoteHttpTimeout)
}

#[cfg(feature = "sp1_proving")]
fn remote_http_validate_response_identity(
    response: &RadrootsSp1TradeRemoteProverResponse,
    request: &RadrootsSp1TradeRemoteProverRequest,
) -> Result<(), TradeValidationReceiptJobError> {
    if response.schema_version != RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION {
        return Err(TradeValidationReceiptJobError::RemoteHttpInvalidResponse(
            "schema_version",
        ));
    }
    if response.request_id != request.request_id {
        return Err(TradeValidationReceiptJobError::RemoteHttpIdentityMismatch(
            "request_id",
        ));
    }
    Ok(())
}

#[cfg(feature = "sp1_proving")]
fn remote_http_terminal_error(
    status: &'static str,
    response: RadrootsSp1TradeRemoteProverResponse,
) -> TradeValidationReceiptJobError {
    TradeValidationReceiptJobError::RemoteHttpTerminal {
        status,
        reason_code: response
            .reason_code
            .unwrap_or_else(|| "remote_prover_terminal".to_string()),
        message: response
            .message
            .unwrap_or_else(|| "remote prover reached a terminal non-success state".to_string()),
    }
}

#[cfg(feature = "sp1_proving")]
async fn remote_http_verified_artifact(
    execution: &radroots_sp1_guest_trade::RadrootsSp1TradePublicValuesExecution,
    policy: &TradeValidationReceiptProverPolicy,
    expected_sp1_program_hash: &str,
    expected_sp1_verifying_key_hash: &str,
    request: &RadrootsSp1TradeRemoteProverRequest,
    response: RadrootsSp1TradeRemoteProverResponse,
) -> Result<radroots_sp1_host_trade::RadrootsSp1TradeProofArtifact, TradeValidationReceiptJobError>
{
    if response.schema_version != RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION {
        return Err(TradeValidationReceiptJobError::RemoteHttpInvalidResponse(
            "schema_version",
        ));
    }
    if response.request_id != request.request_id {
        return Err(TradeValidationReceiptJobError::RemoteHttpIdentityMismatch(
            "request_id",
        ));
    }
    if response.proof_mode != Some(policy.proof_mode) {
        return Err(TradeValidationReceiptJobError::RemoteHttpIdentityMismatch(
            "proof_mode",
        ));
    }
    if response.proof_system != Some(policy.proof_mode.proof_system()) {
        return Err(TradeValidationReceiptJobError::RemoteHttpIdentityMismatch(
            "proof_system",
        ));
    }
    if response.public_values_hash.as_deref() != Some(execution.public_values_hash.as_str()) {
        return Err(TradeValidationReceiptJobError::RemoteHttpIdentityMismatch(
            "public_values_hash",
        ));
    }
    if response.sp1_program_hash.as_deref() != Some(expected_sp1_program_hash) {
        return Err(TradeValidationReceiptJobError::RemoteHttpIdentityMismatch(
            "sp1_program_hash",
        ));
    }
    if response.sp1_verifying_key_hash.as_deref() != Some(expected_sp1_verifying_key_hash) {
        return Err(TradeValidationReceiptJobError::RemoteHttpIdentityMismatch(
            "sp1_verifying_key_hash",
        ));
    }
    let artifact = response.proof_artifact.ok_or(
        TradeValidationReceiptJobError::RemoteHttpInvalidResponse("proof_artifact"),
    )?;
    let resolved = RadrootsSp1TradeResolvedProofArtifact {
        artifact,
        resolved_proof_envelope_base64: response.resolved_proof_envelope_base64,
    };
    verify_remote_proof_artifact_io(execution, &resolved).await?;
    Ok(resolved.artifact)
}

#[cfg(feature = "sp1_proving")]
async fn verify_remote_proof_artifact_io(
    execution: &radroots_sp1_guest_trade::RadrootsSp1TradePublicValuesExecution,
    resolved: &RadrootsSp1TradeResolvedProofArtifact,
) -> Result<(), TradeValidationReceiptJobError> {
    #[cfg(test)]
    if let Some(result) = pop_remote_proof_verification_hook() {
        return result;
    }

    radroots_sp1_host_trade::verify_order_acceptance_resolved_sp1_proof_artifact(
        execution, resolved,
    )
    .await?;
    Ok(())
}

#[cfg(feature = "sp1_proving")]
async fn remote_http_post_json_io(
    config: &TradeValidationReceiptRemoteHttpProverConfig,
    url: &str,
    request: &RadrootsSp1TradeRemoteProverRequest,
) -> Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError> {
    #[cfg(test)]
    if let Some(result) = pop_remote_http_response_hook(request) {
        return result;
    }

    let client = remote_http_client(config)?;
    let mut builder = client.post(url).json(request);
    if let Some(token) = remote_http_auth_token(config)? {
        builder = builder.bearer_auth(token);
    }
    remote_http_response_json(config, builder.send().await).await
}

#[cfg(feature = "sp1_proving")]
async fn remote_http_get_json_io(
    config: &TradeValidationReceiptRemoteHttpProverConfig,
    url: &str,
    _request: &RadrootsSp1TradeRemoteProverRequest,
) -> Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError> {
    #[cfg(test)]
    if let Some(result) = pop_remote_http_response_hook(_request) {
        return result;
    }

    let client = remote_http_client(config)?;
    let mut builder = client.get(url);
    if let Some(token) = remote_http_auth_token(config)? {
        builder = builder.bearer_auth(token);
    }
    remote_http_response_json(config, builder.send().await).await
}

#[cfg(feature = "sp1_proving")]
fn remote_http_client(
    config: &TradeValidationReceiptRemoteHttpProverConfig,
) -> Result<reqwest::Client, TradeValidationReceiptJobError> {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(config.request_timeout_ms))
        .build()
        .map_err(|error| TradeValidationReceiptJobError::RemoteHttpTransport(error.to_string()))
}

#[cfg(feature = "sp1_proving")]
async fn remote_http_response_json(
    config: &TradeValidationReceiptRemoteHttpProverConfig,
    response: Result<reqwest::Response, reqwest::Error>,
) -> Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError> {
    let mut response = response
        .map_err(|error| TradeValidationReceiptJobError::RemoteHttpTransport(error.to_string()))?;
    if !response.status().is_success() {
        return Err(TradeValidationReceiptJobError::RemoteHttpTransport(
            format!("http status {}", response.status().as_u16()),
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > config.max_response_bytes as u64)
    {
        return Err(TradeValidationReceiptJobError::RemoteHttpResponseTooLarge);
    }
    let mut bytes = Vec::with_capacity(config.max_response_bytes.min(8192));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| TradeValidationReceiptJobError::RemoteHttpTransport(error.to_string()))?
    {
        if chunk.len() > config.max_response_bytes.saturating_sub(bytes.len()) {
            return Err(TradeValidationReceiptJobError::RemoteHttpResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice::<RadrootsSp1TradeRemoteProverResponse>(&bytes)
        .map_err(TradeValidationReceiptJobError::Serde)
}

#[cfg(feature = "sp1_proving")]
fn remote_http_status_url(
    config: &TradeValidationReceiptRemoteHttpProverConfig,
    response: &RadrootsSp1TradeRemoteProverResponse,
) -> Result<String, TradeValidationReceiptJobError> {
    let base = remote_http_endpoint_url(config)?;
    if let Some(url) = response.status_url.as_deref() {
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| TradeValidationReceiptJobError::RemoteHttpInvalidResponse("status_url"))?;
        if (parsed.scheme() != "http" && parsed.scheme() != "https")
            || !remote_http_same_origin(&base, &parsed)
        {
            return Err(TradeValidationReceiptJobError::RemoteHttpInvalidResponse(
                "status_url",
            ));
        }
        return Ok(parsed.to_string());
    }
    if let Some(path) = response.status_path.as_deref() {
        if path.trim() != path
            || !path.starts_with('/')
            || path.starts_with("//")
            || reqwest::Url::parse(path).is_ok()
        {
            return Err(TradeValidationReceiptJobError::RemoteHttpInvalidResponse(
                "status_path",
            ));
        }
        let parsed = base.join(path).map_err(|_| {
            TradeValidationReceiptJobError::RemoteHttpInvalidResponse("status_path")
        })?;
        if !remote_http_same_origin(&base, &parsed) {
            return Err(TradeValidationReceiptJobError::RemoteHttpInvalidResponse(
                "status_path",
            ));
        }
        return Ok(parsed.to_string());
    }
    Err(TradeValidationReceiptJobError::RemoteHttpInvalidResponse(
        "status_url",
    ))
}

#[cfg(feature = "sp1_proving")]
fn remote_http_same_origin(base: &reqwest::Url, candidate: &reqwest::Url) -> bool {
    base.scheme() == candidate.scheme()
        && base.host_str() == candidate.host_str()
        && base.port_or_known_default() == candidate.port_or_known_default()
}

#[cfg(not(feature = "sp1_proving"))]
async fn run_local_cpu_prove_backend(
    _witness: &RadrootsSp1TradeOrderAcceptanceWitness,
    _proof_mode: RadrootsSp1TradeProofMode,
) -> Result<TradeValidationReceiptProofOutcome, TradeValidationReceiptJobError> {
    Err(TradeValidationReceiptJobError::ProverBackendUnavailable(
        TradeValidationReceiptProverBackend::LocalCpuProve.as_str(),
    ))
}

fn validate_job_request_shape(
    request: &TradeValidationReceiptJobRequest,
) -> Result<(), TradeValidationReceiptJobError> {
    if request.listing_event_id.trim().is_empty()
        || request.request_event_id.trim().is_empty()
        || request.decision_event_id.trim().is_empty()
        || request.proof_target.trim().is_empty()
        || request.reducer_program_hash.trim().is_empty()
        || request.radroots_protocol_version.trim().is_empty()
        || request.inventory_bins.is_empty()
    {
        return Err(TradeValidationReceiptJobError::InvalidJobRequest);
    }
    if request.witness_version != RADROOTS_SP1_TRADE_WITNESS_VERSION {
        return Err(TradeValidationReceiptJobError::UnsupportedWitnessVersion);
    }
    if request.proof_target != RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET {
        return Err(TradeValidationReceiptJobError::UnsupportedProofTarget);
    }
    if request.reducer_program_hash != RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH {
        return Err(TradeValidationReceiptJobError::ExpectedReducerProgramHashMismatch);
    }
    if request.radroots_protocol_version != RADROOTS_SP1_TRADE_PROTOCOL_VERSION {
        return Err(TradeValidationReceiptJobError::ExpectedProtocolVersionMismatch);
    }
    validate_optional_hash32(&request.sp1_program_hash)?;
    validate_optional_hash32(&request.sp1_verifying_key_hash)?;
    Ok(())
}

fn validate_optional_hash32(value: &Option<String>) -> Result<(), TradeValidationReceiptJobError> {
    if let Some(value) = value {
        let hash = value.as_str();
        if hash.len() != 66 || !hash.starts_with("0x") || !is_lower_hex(&hash[2..]) {
            return Err(TradeValidationReceiptJobError::InvalidJobRequest);
        }
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn event_kind_u32(event: &RadrootsNostrEvent) -> Result<u32, TradeValidationReceiptJobError> {
    match event.kind {
        RadrootsNostrKind::Custom(value) => Ok(u32::from(value)),
        _ => Err(TradeValidationReceiptJobError::UnsupportedKind),
    }
}

fn event_tags(event: &RadrootsNostrEvent) -> Vec<Vec<String>> {
    event
        .tags
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect()
}

fn result_tags(
    request_event: &RadrootsNostrEvent,
    receipt_event_id: &str,
    result: &TradeValidationReceiptJobResult,
) -> Vec<Vec<String>> {
    vec![
        vec!["p".to_string(), request_event.pubkey.to_string()],
        vec![
            "e".to_string(),
            request_event.id.to_hex(),
            String::new(),
            String::new(),
            "request".to_string(),
        ],
        vec![
            "e".to_string(),
            receipt_event_id.to_string(),
            String::new(),
            String::new(),
            "receipt".to_string(),
        ],
        vec![
            "public_values_hash".to_string(),
            result.public_values_hash.clone(),
        ],
        vec!["proof_system".to_string(), result.proof_system.clone()],
        vec![
            "prover_backend".to_string(),
            result.prover_backend.as_str().to_string(),
        ],
        vec![
            "proof_mode".to_string(),
            result.proof_mode.mode_label().unwrap_or("none").to_string(),
        ],
        vec![
            "proof_generated".to_string(),
            result.proof_generated.to_string(),
        ],
        vec![
            "sp1_execute_checked".to_string(),
            result.sp1_execute_checked.to_string(),
        ],
        vec![
            "cryptographic_proof_verified".to_string(),
            result.cryptographic_proof_verified.to_string(),
        ],
    ]
}

fn tag_has_value(tags: &[Vec<String>], key: &str, value: &str) -> bool {
    tags.iter().any(|tag| {
        tag.first().map(|tag_key| tag_key.as_str()) == Some(key)
            && tag.get(1).map(|tag_value| tag_value.as_str()) == Some(value)
    })
}

async fn fetch_event_by_id_io(
    client: &RadrootsNostrClient,
    event_id: &str,
) -> Result<RadrootsNostrEvent, TradeValidationReceiptJobError> {
    #[cfg(test)]
    if let Some(result) = pop_fetch_event_by_id_hook() {
        return result;
    }

    Ok(radroots_nostr_fetch_event_by_id(client, event_id).await?)
}

async fn publish_event_parts_io(
    client: &RadrootsNostrClient,
    kind: u32,
    content: String,
    tags: Vec<Vec<String>>,
) -> Result<String, TradeValidationReceiptJobError> {
    #[cfg(test)]
    if let Some(result) = pop_publish_event_hook(kind, content.clone(), tags.clone()) {
        return result;
    }

    let builder: RadrootsNostrEventBuilder = radroots_nostr_build_event(kind, content, tags)?;
    let output = radroots_nostr_send_event(client, builder).await?;
    Ok(output.val.to_hex())
}

fn zero_event_id() -> String {
    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

fn zero_signature() -> String {
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string()
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PublishedEventParts {
    kind: u32,
    content: String,
    tags: Vec<Vec<String>>,
}

#[cfg(test)]
#[derive(Default)]
struct TradeValidationReceiptTestHooks {
    fetch_event_by_id_results:
        std::collections::VecDeque<Result<RadrootsNostrEvent, TradeValidationReceiptJobError>>,
    publish_event_results:
        std::collections::VecDeque<Result<String, TradeValidationReceiptJobError>>,
    #[cfg(feature = "sp1_proving")]
    remote_http_results: std::collections::VecDeque<
        Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError>,
    >,
    #[cfg(feature = "sp1_proving")]
    remote_proof_verification_results:
        std::collections::VecDeque<Result<(), TradeValidationReceiptJobError>>,
    published_events: Vec<PublishedEventParts>,
}

#[cfg(test)]
static TRADE_VALIDATION_RECEIPT_TEST_HOOKS: std::sync::OnceLock<
    std::sync::Mutex<TradeValidationReceiptTestHooks>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn trade_validation_receipt_test_hooks()
-> &'static std::sync::Mutex<TradeValidationReceiptTestHooks> {
    TRADE_VALIDATION_RECEIPT_TEST_HOOKS
        .get_or_init(|| std::sync::Mutex::new(TradeValidationReceiptTestHooks::default()))
}

#[cfg(test)]
fn pop_fetch_event_by_id_hook() -> Option<Result<RadrootsNostrEvent, TradeValidationReceiptJobError>>
{
    trade_validation_receipt_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .fetch_event_by_id_results
        .pop_front()
}

#[cfg(test)]
fn pop_publish_event_hook(
    kind: u32,
    content: String,
    tags: Vec<Vec<String>>,
) -> Option<Result<String, TradeValidationReceiptJobError>> {
    let mut hooks = trade_validation_receipt_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    hooks.published_events.push(PublishedEventParts {
        kind,
        content,
        tags,
    });
    hooks.publish_event_results.pop_front()
}

#[cfg(all(test, feature = "sp1_proving"))]
fn pop_remote_http_response_hook(
    request: &RadrootsSp1TradeRemoteProverRequest,
) -> Option<Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError>> {
    pop_remote_http_response_hook_without_request().map(|result| {
        result.and_then(|response| remote_http_test_response_for_request(request, response))
    })
}

#[cfg(all(test, feature = "sp1_proving"))]
fn pop_remote_http_response_hook_without_request()
-> Option<Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError>> {
    trade_validation_receipt_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remote_http_results
        .pop_front()
}

#[cfg(all(test, feature = "sp1_proving"))]
fn remote_http_test_response_for_request(
    request: &RadrootsSp1TradeRemoteProverRequest,
    mut response: RadrootsSp1TradeRemoteProverResponse,
) -> Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError> {
    if response.request_id == "__request_id__" {
        response.request_id = request.request_id.clone();
    }
    if response.status == RadrootsSp1TradeRemoteProverStatus::Completed
        && response.proof_artifact.is_none()
    {
        let execution =
            radroots_sp1_host_trade::execute_order_acceptance_public_values(&request.witness)?;
        let artifact =
            radroots_sp1_host_trade::referenced_order_acceptance_proof_artifact_for_execution(
                &execution,
                request.proof_mode,
                format!("radroots-proof://sha256/{}", "1".repeat(64)),
            )?;
        if response.proof_system.is_none() {
            response.proof_system = Some(request.proof_mode.proof_system());
        }
        if response.proof_mode.is_none() {
            response.proof_mode = Some(request.proof_mode);
        }
        if response.public_values_hash.is_none() {
            response.public_values_hash = Some(execution.public_values_hash);
        }
        if response.sp1_program_hash.is_none() {
            response.sp1_program_hash = Some(request.expected_sp1_program_hash.clone());
        }
        if response.sp1_verifying_key_hash.is_none() {
            response.sp1_verifying_key_hash = Some(request.expected_sp1_verifying_key_hash.clone());
        }
        if response.proof_artifact.is_none() {
            response.proof_artifact = Some(artifact);
        }
    }
    Ok(response)
}

#[cfg(all(test, feature = "sp1_proving"))]
fn pop_remote_proof_verification_hook() -> Option<Result<(), TradeValidationReceiptJobError>> {
    trade_validation_receipt_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remote_proof_verification_results
        .pop_front()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        TradeValidationReceiptJobError, TradeValidationReceiptJobRequest,
        TradeValidationReceiptJobResult, TradeValidationReceiptProverBackend,
        TradeValidationReceiptProverPolicy, TradeValidationReceiptRemoteHttpAuth,
        TradeValidationReceiptRemoteHttpProverConfig, TradeValidationReceiptTestHooks,
        handle_trade_validation_receipt_job_request, trade_validation_receipt_test_hooks,
    };
    use radroots_core::{
        RadrootsCoreCurrency, RadrootsCoreDecimal, RadrootsCoreMoney, RadrootsCoreUnit,
    };
    use radroots_events::RadrootsNostrEventPtr;
    use radroots_events::kinds::{
        KIND_LISTING, KIND_TRADE_VALIDATION_RECEIPT, KIND_WORKER_TRADE_TRANSITION_PROOF_REQ,
        KIND_WORKER_TRADE_TRANSITION_PROOF_RES,
    };
    use radroots_events::trade::{
        RadrootsTradeInventoryCommitment, RadrootsTradeOrderDecision,
        RadrootsTradeOrderDecisionEvent, RadrootsTradeOrderEconomicItem,
        RadrootsTradeOrderEconomicLine, RadrootsTradeOrderEconomics, RadrootsTradeOrderItem,
        RadrootsTradeOrderRequested, RadrootsTradePricingBasis,
    };
    use radroots_events_codec::trade::{
        active_trade_order_decision_event_build, active_trade_order_request_event_build,
    };
    use radroots_nostr::prelude::{
        RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrKeys,
        RadrootsNostrKind, RadrootsNostrTag, RadrootsNostrTagKind, radroots_event_from_nostr,
        radroots_nostr_build_event,
    };
    use radroots_sp1_guest_trade::{
        RADROOTS_SP1_TRADE_PROTOCOL_VERSION, RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH,
        RadrootsSp1TradeInventoryBinWitness,
    };
    #[cfg(feature = "sp1_proving")]
    use radroots_sp1_host_trade::RadrootsSp1TradeHostError;
    use radroots_sp1_host_trade::RadrootsSp1TradeProofMode;
    #[cfg(feature = "sp1_proving")]
    use radroots_sp1_host_trade::{
        RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION, RadrootsSp1TradeRemoteProverResponse,
        RadrootsSp1TradeRemoteProverStatus,
    };
    use radroots_trade::validation_receipt::{
        RadrootsValidationReceiptExpectedBinding, RadrootsValidationReceiptProofSystem,
        verify_validation_receipt_event,
    };
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *trade_validation_receipt_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            TradeValidationReceiptTestHooks::default();
        guard
    }

    fn publish_result_id(index: u8) -> String {
        format!("{index:064x}")
    }

    fn listing_addr_for_seller(seller: &RadrootsNostrKeys) -> String {
        format!(
            "30402:{}:AAAAAAAAAAAAAAAAAAAAAA",
            seller.public_key().to_hex()
        )
    }

    fn signed_event(
        keys: &RadrootsNostrKeys,
        kind: u32,
        content: impl Into<String>,
        tags: Vec<Vec<String>>,
    ) -> RadrootsNostrEvent {
        radroots_nostr_build_event(kind, content.into(), tags)
            .expect("event builder")
            .sign_with_keys(keys)
            .expect("signed event")
    }

    fn listing_event(seller: &RadrootsNostrKeys) -> RadrootsNostrEvent {
        signed_event(
            seller,
            KIND_LISTING,
            "{}",
            vec![vec!["d".to_string(), "listing-1".to_string()]],
        )
    }

    fn request_payload(
        order_id: &str,
        listing_addr: &str,
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
    ) -> RadrootsTradeOrderRequested {
        RadrootsTradeOrderRequested {
            order_id: order_id.to_string(),
            listing_addr: listing_addr.to_string(),
            buyer_pubkey: buyer.public_key().to_hex(),
            seller_pubkey: seller.public_key().to_hex(),
            items: vec![RadrootsTradeOrderItem {
                bin_id: "bin-1".to_string(),
                bin_count: 2,
            }],
            economics: economics(order_id, 2),
        }
    }

    fn decision_payload(
        order_id: &str,
        listing_addr: &str,
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
    ) -> RadrootsTradeOrderDecisionEvent {
        RadrootsTradeOrderDecisionEvent {
            order_id: order_id.to_string(),
            listing_addr: listing_addr.to_string(),
            buyer_pubkey: buyer.public_key().to_hex(),
            seller_pubkey: seller.public_key().to_hex(),
            decision: RadrootsTradeOrderDecision::Accepted {
                inventory_commitments: vec![RadrootsTradeInventoryCommitment {
                    bin_id: "bin-1".to_string(),
                    bin_count: 2,
                }],
            },
        }
    }

    fn economics(order_id: &str, bin_count: u32) -> RadrootsTradeOrderEconomics {
        let subtotal = RadrootsCoreDecimal::from(5u32) * RadrootsCoreDecimal::from(bin_count);
        let money = RadrootsCoreMoney::new(subtotal, RadrootsCoreCurrency::USD);
        RadrootsTradeOrderEconomics {
            quote_id: format!("{order_id}-quote"),
            quote_version: 1,
            pricing_basis: RadrootsTradePricingBasis::ListingEvent,
            currency: RadrootsCoreCurrency::USD,
            items: vec![RadrootsTradeOrderEconomicItem {
                bin_id: "bin-1".to_string(),
                bin_count,
                quantity_amount: RadrootsCoreDecimal::from(1u32),
                quantity_unit: RadrootsCoreUnit::Each,
                unit_price_amount: RadrootsCoreDecimal::from(5u32),
                unit_price_currency: RadrootsCoreCurrency::USD,
                line_subtotal: money.clone(),
            }],
            discounts: Vec::<RadrootsTradeOrderEconomicLine>::new(),
            adjustments: Vec::<RadrootsTradeOrderEconomicLine>::new(),
            subtotal: money.clone(),
            discount_total: RadrootsCoreMoney::zero(RadrootsCoreCurrency::USD),
            adjustment_total: RadrootsCoreMoney::zero(RadrootsCoreCurrency::USD),
            total: money,
        }
    }

    fn signed_order_events(
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
        listing_event: &RadrootsNostrEvent,
    ) -> (RadrootsNostrEvent, RadrootsNostrEvent) {
        let listing_addr = listing_addr_for_seller(seller);
        let order_id = "order-1";
        let listing_ptr = RadrootsNostrEventPtr {
            id: listing_event.id.to_hex(),
            relays: None,
        };
        let request_wire = active_trade_order_request_event_build(
            &listing_ptr,
            &request_payload(order_id, &listing_addr, buyer, seller),
        )
        .expect("request wire");
        let request_event = signed_event(
            buyer,
            request_wire.kind,
            request_wire.content,
            request_wire.tags,
        );
        let decision_wire = active_trade_order_decision_event_build(
            &request_event.id.to_hex(),
            &request_event.id.to_hex(),
            &decision_payload(order_id, &listing_addr, buyer, seller),
        )
        .expect("decision wire");
        let decision_event = signed_event(
            seller,
            decision_wire.kind,
            decision_wire.content,
            decision_wire.tags,
        );
        (request_event, decision_event)
    }

    fn job_request(
        requester: &RadrootsNostrKeys,
        worker: &RadrootsNostrKeys,
        listing_event: &RadrootsNostrEvent,
        request_event: &RadrootsNostrEvent,
        decision_event: &RadrootsNostrEvent,
        proof_mode: RadrootsSp1TradeProofMode,
        sp1_program_hash: Option<String>,
        sp1_verifying_key_hash: Option<String>,
    ) -> RadrootsNostrEvent {
        let request = TradeValidationReceiptJobRequest {
            witness_version: radroots_sp1_guest_trade::RADROOTS_SP1_TRADE_WITNESS_VERSION,
            proof_target:
                radroots_sp1_guest_trade::RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET
                    .to_string(),
            listing_event_id: listing_event.id.to_hex(),
            request_event_id: request_event.id.to_hex(),
            decision_event_id: decision_event.id.to_hex(),
            inventory_bins: vec![RadrootsSp1TradeInventoryBinWitness {
                bin_id: "bin-1".to_string(),
                listing_capacity: 5,
                previous_reserved: 1,
            }],
            inventory_sequence: 7,
            previous_state_root: None,
            proof_mode,
            reducer_program_hash: RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH.to_string(),
            radroots_protocol_version: RADROOTS_SP1_TRADE_PROTOCOL_VERSION.to_string(),
            sp1_program_hash,
            sp1_verifying_key_hash,
        };
        signed_event(
            requester,
            KIND_WORKER_TRADE_TRANSITION_PROOF_REQ,
            serde_json::to_string(&request).expect("job json"),
            vec![vec!["p".to_string(), worker.public_key().to_string()]],
        )
    }

    fn client_for(keys: &RadrootsNostrKeys) -> RadrootsNostrClient {
        RadrootsNostrClient::new(keys.clone())
    }

    fn deterministic_policy() -> TradeValidationReceiptProverPolicy {
        TradeValidationReceiptProverPolicy::deterministic_none()
    }

    fn hash32(ch: char) -> String {
        format!("0x{}", ch.to_string().repeat(64))
    }

    fn remote_http_config() -> TradeValidationReceiptRemoteHttpProverConfig {
        TradeValidationReceiptRemoteHttpProverConfig {
            endpoint_url: "http://127.0.0.1:65535/prove".to_string(),
            auth: TradeValidationReceiptRemoteHttpAuth::NoAuth,
            request_timeout_ms: 1000,
            poll_interval_ms: 1,
            max_poll_attempts: 1,
            max_response_bytes: 65_536,
        }
    }

    fn remote_http_policy() -> TradeValidationReceiptProverPolicy {
        TradeValidationReceiptProverPolicy {
            backend: TradeValidationReceiptProverBackend::RemoteHttpProve,
            proof_mode: RadrootsSp1TradeProofMode::Core,
            expected_sp1_program_hash: Some(hash32('a')),
            expected_sp1_verifying_key_hash: Some(hash32('b')),
            remote_http: Some(remote_http_config()),
        }
    }

    #[cfg(feature = "sp1_proving")]
    fn remote_response(
        status: RadrootsSp1TradeRemoteProverStatus,
    ) -> RadrootsSp1TradeRemoteProverResponse {
        RadrootsSp1TradeRemoteProverResponse {
            schema_version: RADROOTS_SP1_TRADE_REMOTE_PROVER_SCHEMA_VERSION,
            request_id: "__request_id__".to_string(),
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
            reason_code: None,
            message: None,
            detail: None,
        }
    }

    #[cfg(feature = "sp1_proving")]
    fn remote_http_local_response_url(response: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test listener");
        let addr = listener.local_addr().expect("test listener address");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("test connection");
            let mut buffer = [0; 4096];
            let _ = std::io::Read::read(&mut stream, &mut buffer);
            std::io::Write::write_all(&mut stream, response.as_bytes()).expect("test response");
        });
        format!("http://{addr}/prove")
    }

    #[cfg(feature = "sp1_proving")]
    async fn run_remote_http_job(
        remote_http_results: Vec<
            Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError>,
        >,
        remote_proof_verification_results: Vec<Result<(), TradeValidationReceiptJobError>>,
        publish_results: Vec<Result<String, TradeValidationReceiptJobError>>,
    ) -> Result<Vec<super::PublishedEventParts>, TradeValidationReceiptJobError> {
        run_remote_http_job_with_policy(
            remote_http_policy(),
            remote_http_results,
            remote_proof_verification_results,
            publish_results,
        )
        .await
    }

    #[cfg(feature = "sp1_proving")]
    async fn run_remote_http_job_with_policy(
        policy: TradeValidationReceiptProverPolicy,
        remote_http_results: Vec<
            Result<RadrootsSp1TradeRemoteProverResponse, TradeValidationReceiptJobError>,
        >,
        remote_proof_verification_results: Vec<Result<(), TradeValidationReceiptJobError>>,
        publish_results: Vec<Result<String, TradeValidationReceiptJobError>>,
    ) -> Result<Vec<super::PublishedEventParts>, TradeValidationReceiptJobError> {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::Core,
            Some(hash32('a')),
            Some(hash32('b')),
        );

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks.fetch_event_by_id_results.push_back(Ok(listing_event));
            hooks.fetch_event_by_id_results.push_back(Ok(request_event));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event));
            hooks.remote_http_results.extend(remote_http_results);
            hooks
                .remote_proof_verification_results
                .extend(remote_proof_verification_results);
            hooks.publish_event_results.extend(publish_results);
        }

        handle_trade_validation_receipt_job_request(&job, &worker, &client_for(&worker), &policy)
            .await?;

        Ok(trade_validation_receipt_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .published_events
            .clone())
    }

    #[test]
    fn prover_policy_requires_configured_sp1_identity_for_local_cpu() {
        let missing_identity = TradeValidationReceiptProverPolicy {
            backend: TradeValidationReceiptProverBackend::LocalCpuProve,
            proof_mode: RadrootsSp1TradeProofMode::Core,
            expected_sp1_program_hash: None,
            expected_sp1_verifying_key_hash: Some(hash32('b')),
            remote_http: None,
        };
        assert!(matches!(
            missing_identity.validate(),
            Err(TradeValidationReceiptJobError::Sp1IdentityPolicyRequired)
        ));

        let policy = TradeValidationReceiptProverPolicy {
            backend: TradeValidationReceiptProverBackend::LocalCpuProve,
            proof_mode: RadrootsSp1TradeProofMode::Core,
            expected_sp1_program_hash: Some(hash32('a')),
            expected_sp1_verifying_key_hash: Some(hash32('b')),
            remote_http: None,
        };
        let request = TradeValidationReceiptJobRequest {
            witness_version: radroots_sp1_guest_trade::RADROOTS_SP1_TRADE_WITNESS_VERSION,
            proof_target:
                radroots_sp1_guest_trade::RADROOTS_SP1_TRADE_ORDER_ACCEPTANCE_PROOF_TARGET
                    .to_string(),
            listing_event_id: "listing-event".to_string(),
            request_event_id: "request-event".to_string(),
            decision_event_id: "decision-event".to_string(),
            inventory_bins: vec![RadrootsSp1TradeInventoryBinWitness {
                bin_id: "bin-1".to_string(),
                listing_capacity: 5,
                previous_reserved: 1,
            }],
            inventory_sequence: 7,
            previous_state_root: None,
            proof_mode: RadrootsSp1TradeProofMode::Core,
            reducer_program_hash: RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH.to_string(),
            radroots_protocol_version: RADROOTS_SP1_TRADE_PROTOCOL_VERSION.to_string(),
            sp1_program_hash: Some(hash32('c')),
            sp1_verifying_key_hash: Some(hash32('b')),
        };
        assert!(matches!(
            policy.validate_request(&request),
            Err(TradeValidationReceiptJobError::ExpectedSp1ProgramHashMismatch)
        ));

        let mut request = request;
        request.sp1_program_hash = None;
        request.sp1_verifying_key_hash = None;
        assert!(matches!(
            policy.validate_request(&request),
            Err(TradeValidationReceiptJobError::ExpectedSp1ProgramHashMismatch)
        ));
    }

    #[test]
    fn remote_http_policy_requires_explicit_config_and_identity_before_relay_fetch() {
        let missing_config = TradeValidationReceiptProverPolicy {
            backend: TradeValidationReceiptProverBackend::RemoteHttpProve,
            proof_mode: RadrootsSp1TradeProofMode::Core,
            expected_sp1_program_hash: Some(hash32('a')),
            expected_sp1_verifying_key_hash: Some(hash32('b')),
            remote_http: None,
        };
        assert!(matches!(
            missing_config.validate(),
            Err(TradeValidationReceiptJobError::RemoteHttpConfigRequired)
        ));

        let missing_identity = TradeValidationReceiptProverPolicy {
            backend: TradeValidationReceiptProverBackend::RemoteHttpProve,
            proof_mode: RadrootsSp1TradeProofMode::Core,
            expected_sp1_program_hash: None,
            expected_sp1_verifying_key_hash: Some(hash32('b')),
            remote_http: Some(remote_http_config()),
        };
        assert!(matches!(
            missing_identity.validate(),
            Err(TradeValidationReceiptJobError::Sp1IdentityPolicyRequired)
        ));

        let mut invalid_config = remote_http_policy();
        invalid_config
            .remote_http
            .as_mut()
            .expect("remote config")
            .endpoint_url = "file:///tmp/prove".to_string();
        assert!(matches!(
            invalid_config.validate(),
            Err(TradeValidationReceiptJobError::RemoteHttpInvalidConfig(
                "endpoint_url"
            ))
        ));

        let mut bearer_over_http = remote_http_policy();
        bearer_over_http
            .remote_http
            .as_mut()
            .expect("remote config")
            .auth = TradeValidationReceiptRemoteHttpAuth::BearerTokenEnv {
            env_var: "RADROOTS_TEST_REMOTE_HTTP_TOKEN".to_string(),
        };
        assert!(matches!(
            bearer_over_http.validate(),
            Err(TradeValidationReceiptJobError::RemoteHttpInvalidConfig(
                "auth.endpoint_url_scheme"
            ))
        ));
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_publishes_only_after_remote_artifact_verification() {
        let published = run_remote_http_job(
            vec![Ok(remote_response(
                RadrootsSp1TradeRemoteProverStatus::Completed,
            ))],
            vec![Ok(())],
            vec![Ok(publish_result_id(1)), Ok(publish_result_id(2))],
        )
        .await
        .expect("remote proof job");

        assert_eq!(published.len(), 2);
        assert_eq!(published[0].kind, KIND_TRADE_VALIDATION_RECEIPT);
        assert_eq!(published[1].kind, KIND_WORKER_TRADE_TRANSITION_PROOF_RES);
        let result: TradeValidationReceiptJobResult =
            serde_json::from_str(&published[1].content).expect("result json");
        assert_eq!(
            result.prover_backend,
            TradeValidationReceiptProverBackend::RemoteHttpProve
        );
        assert!(result.proof_generated);
        assert_eq!(result.proof_mode, RadrootsSp1TradeProofMode::Core);
        assert_eq!(result.proof_system, "sp1_core");
        assert!(result.sp1_execute_checked);
        assert_eq!(
            result.sp1_execute_public_values_hash.as_deref(),
            Some(result.public_values_hash.as_str())
        );
        assert!(result.cryptographic_proof_verified);
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_polls_running_until_completed() {
        let mut policy = remote_http_policy();
        policy
            .remote_http
            .as_mut()
            .expect("remote config")
            .max_poll_attempts = 2;
        let mut accepted = remote_response(RadrootsSp1TradeRemoteProverStatus::Accepted);
        accepted.status_path = Some("/prove/status/request-1".to_string());
        let mut running = remote_response(RadrootsSp1TradeRemoteProverStatus::Running);
        running.status_path = Some("/prove/status/request-1".to_string());
        let published = run_remote_http_job_with_policy(
            policy,
            vec![
                Ok(accepted),
                Ok(running),
                Ok(remote_response(
                    RadrootsSp1TradeRemoteProverStatus::Completed,
                )),
            ],
            vec![Ok(())],
            vec![Ok(publish_result_id(1)), Ok(publish_result_id(2))],
        )
        .await
        .expect("polled remote proof job");

        assert_eq!(published.len(), 2);
        let result: TradeValidationReceiptJobResult =
            serde_json::from_str(&published[1].content).expect("result json");
        assert_eq!(
            result.prover_backend,
            TradeValidationReceiptProverBackend::RemoteHttpProve
        );
        assert!(result.cryptographic_proof_verified);
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_accepts_same_origin_status_url() {
        let mut policy = remote_http_policy();
        policy
            .remote_http
            .as_mut()
            .expect("remote config")
            .max_poll_attempts = 1;
        let mut accepted = remote_response(RadrootsSp1TradeRemoteProverStatus::Accepted);
        accepted.status_url = Some("http://127.0.0.1:65535/prove/status/request-1".to_string());
        let published = run_remote_http_job_with_policy(
            policy,
            vec![
                Ok(accepted),
                Ok(remote_response(
                    RadrootsSp1TradeRemoteProverStatus::Completed,
                )),
            ],
            vec![Ok(())],
            vec![Ok(publish_result_id(1)), Ok(publish_result_id(2))],
        )
        .await
        .expect("same-origin status url");

        assert_eq!(published.len(), 2);
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_rejects_cross_origin_status_url() {
        let mut accepted = remote_response(RadrootsSp1TradeRemoteProverStatus::Accepted);
        accepted.status_url = Some("http://127.0.0.2:65535/prove/status/request-1".to_string());
        let error = run_remote_http_job(
            vec![Ok(accepted)],
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("cross-origin status url");

        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpInvalidResponse("status_url")
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_rejects_absolute_or_scheme_relative_status_path() {
        let mut absolute = remote_response(RadrootsSp1TradeRemoteProverStatus::Accepted);
        absolute.status_path = Some("https://example.invalid/status".to_string());
        let error = run_remote_http_job(
            vec![Ok(absolute)],
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("absolute status path");

        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpInvalidResponse("status_path")
        ));

        let mut scheme_relative = remote_response(RadrootsSp1TradeRemoteProverStatus::Accepted);
        scheme_relative.status_path = Some("//example.invalid/status".to_string());
        let error = run_remote_http_job(
            vec![Ok(scheme_relative)],
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("scheme-relative status path");

        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpInvalidResponse("status_path")
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_rejects_polling_request_id_mismatch_before_next_poll() {
        let mut accepted = remote_response(RadrootsSp1TradeRemoteProverStatus::Accepted);
        accepted.request_id = "wrong-request".to_string();
        accepted.status_path = Some("/prove/status/request-1".to_string());
        let error = run_remote_http_job(
            vec![
                Ok(accepted),
                Ok(remote_response(
                    RadrootsSp1TradeRemoteProverStatus::Completed,
                )),
            ],
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("polling identity mismatch");

        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpIdentityMismatch("request_id")
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_does_not_publish_when_verification_fails() {
        let error = run_remote_http_job(
            vec![Ok(remote_response(
                RadrootsSp1TradeRemoteProverStatus::Completed,
            ))],
            vec![Err(TradeValidationReceiptJobError::Proof(
                RadrootsSp1TradeHostError::Sp1ProofVerificationFailed("test".to_string()),
            ))],
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("remote verification failure");

        assert!(matches!(
            error,
            TradeValidationReceiptJobError::Proof(
                RadrootsSp1TradeHostError::Sp1ProofVerificationFailed(_)
            )
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_does_not_publish_when_reference_digest_mismatches() {
        let mut response = remote_response(RadrootsSp1TradeRemoteProverStatus::Completed);
        response.resolved_proof_envelope_base64 = Some("cHJvb2Y=".to_string());
        let error = run_remote_http_job(
            vec![Ok(response)],
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("remote proof reference mismatch");

        assert!(matches!(
            error,
            TradeValidationReceiptJobError::Proof(
                RadrootsSp1TradeHostError::Sp1ProofReferenceDigestMismatch
            )
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_does_not_publish_when_sp1_identity_mismatches() {
        let mut response = remote_response(RadrootsSp1TradeRemoteProverStatus::Completed);
        response.sp1_program_hash = Some(hash32('c'));
        let error = run_remote_http_job(
            vec![Ok(response)],
            vec![Ok(())],
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("remote sp1 identity mismatch");

        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpIdentityMismatch("sp1_program_hash")
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_does_not_publish_when_public_values_mismatch() {
        let mut response = remote_response(RadrootsSp1TradeRemoteProverStatus::Completed);
        response.public_values_hash = Some(hash32('d'));
        let error = run_remote_http_job(
            vec![Ok(response)],
            vec![Ok(())],
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("remote public values mismatch");

        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpIdentityMismatch("public_values_hash")
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_does_not_publish_terminal_failed_or_rejected() {
        let mut failed = remote_response(RadrootsSp1TradeRemoteProverStatus::Failed);
        failed.reason_code = Some("remote_failed".to_string());
        failed.message = Some("remote prover failed".to_string());
        let error = run_remote_http_job(
            vec![Ok(failed)],
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("remote failed");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpTerminal {
                status: "failed",
                ..
            }
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );

        let mut rejected = remote_response(RadrootsSp1TradeRemoteProverStatus::Rejected);
        rejected.reason_code = Some("remote_rejected".to_string());
        rejected.message = Some("remote prover rejected request".to_string());
        let error = run_remote_http_job(
            vec![Ok(rejected)],
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("remote rejected");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpTerminal {
                status: "rejected",
                ..
            }
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_does_not_publish_timeout_or_oversized_response() {
        let mut accepted = remote_response(RadrootsSp1TradeRemoteProverStatus::Accepted);
        accepted.status_path = Some("/prove/status/request-1".to_string());
        let mut running = remote_response(RadrootsSp1TradeRemoteProverStatus::Running);
        running.status_path = Some("/prove/status/request-1".to_string());
        let error = run_remote_http_job(
            vec![Ok(accepted), Ok(running)],
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("remote timeout");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpTimeout
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );

        let error = run_remote_http_job(
            vec![Err(
                TradeValidationReceiptJobError::RemoteHttpResponseTooLarge,
            )],
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("remote oversized response");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpResponseTooLarge
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[cfg(feature = "sp1_proving")]
    #[tokio::test]
    async fn remote_http_prove_rejects_oversized_http_response_before_publish() {
        let endpoint = remote_http_local_response_url(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
        );
        let mut policy = remote_http_policy();
        {
            let remote_http = policy.remote_http.as_mut().expect("remote config");
            remote_http.endpoint_url = endpoint;
            remote_http.max_response_bytes = 1;
        }
        let error = run_remote_http_job_with_policy(
            policy,
            Vec::new(),
            Vec::new(),
            vec![Err(TradeValidationReceiptJobError::InvalidJobRequest)],
        )
        .await
        .expect_err("oversized streamed response");

        assert!(matches!(
            error,
            TradeValidationReceiptJobError::RemoteHttpResponseTooLarge
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[tokio::test]
    async fn proof_job_publishes_verified_receipt_and_result_after_proof_verification() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::None,
            None,
            None,
        );

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(listing_event.clone()));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(request_event.clone()));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event.clone()));
            hooks
                .publish_event_results
                .push_back(Ok(publish_result_id(1)));
            hooks
                .publish_event_results
                .push_back(Ok(publish_result_id(2)));
        }

        handle_trade_validation_receipt_job_request(
            &job,
            &worker,
            &client_for(&worker),
            &deterministic_policy(),
        )
        .await
        .expect("proof job");

        let published = trade_validation_receipt_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .published_events
            .clone();
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].kind, KIND_TRADE_VALIDATION_RECEIPT);
        assert_eq!(published[1].kind, KIND_WORKER_TRADE_TRANSITION_PROOF_RES);

        let receipt_event = radroots_events::RadrootsNostrEvent {
            id: publish_result_id(1),
            author: worker.public_key().to_string(),
            created_at: 1,
            kind: published[0].kind,
            tags: published[0].tags.clone(),
            content: published[0].content.clone(),
            sig: super::zero_signature(),
        };
        let verified = verify_validation_receipt_event(
            &receipt_event,
            RadrootsValidationReceiptExpectedBinding {
                order_id: Some("order-1"),
                proof_system: Some(RadrootsValidationReceiptProofSystem::None),
                ..RadrootsValidationReceiptExpectedBinding::default()
            },
        )
        .expect("receipt verifies");
        let result: TradeValidationReceiptJobResult =
            serde_json::from_str(&published[1].content).expect("result json");
        assert_eq!(result.receipt_event_id, publish_result_id(1));
        assert_eq!(
            result.prover_backend,
            TradeValidationReceiptProverBackend::DeterministicNone
        );
        assert!(!result.proof_generated);
        assert_eq!(result.proof_mode, RadrootsSp1TradeProofMode::None);
        assert!(!result.sp1_execute_checked);
        assert!(result.sp1_execute_public_values_hash.is_none());
        assert!(!result.cryptographic_proof_verified);
        assert_eq!(
            result.public_values_hash,
            verified.receipt.public_values_hash
        );
        assert_eq!(result.worker_role.to_string(), "non_authoritative_prover");
        assert!(published[1].tags.iter().any(|tag| {
            tag.get(0).map(String::as_str) == Some("e")
                && tag.get(1).map(String::as_str) == Some(publish_result_id(1).as_str())
                && tag.get(4).map(String::as_str) == Some("receipt")
        }));
        assert!(published[1].tags.iter().any(|tag| {
            tag.get(0).map(String::as_str) == Some("prover_backend")
                && tag.get(1).map(String::as_str) == Some("deterministic_none")
        }));
        assert!(published[1].tags.iter().any(|tag| {
            tag.get(0).map(String::as_str) == Some("proof_mode")
                && tag.get(1).map(String::as_str) == Some("none")
        }));
    }

    #[tokio::test]
    async fn proof_job_rejects_unverified_proof_before_publication() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::Compressed,
            None,
            None,
        );

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks.fetch_event_by_id_results.push_back(Ok(listing_event));
            hooks.fetch_event_by_id_results.push_back(Ok(request_event));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event));
        }

        let error = handle_trade_validation_receipt_job_request(
            &job,
            &worker,
            &client_for(&worker),
            &deterministic_policy(),
        )
        .await
        .expect_err("backend rejects sp1 proof claim");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::ProverBackendPolicyMismatch
        ));
        assert_eq!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .fetch_event_by_id_results
                .len(),
            3
        );
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[tokio::test]
    async fn proof_job_rejects_request_prover_backend_override_before_relay_fetch() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::None,
            None,
            None,
        );
        let mut request_json: serde_json::Value =
            serde_json::from_str(&job.content).expect("request json");
        request_json["prover_backend"] = serde_json::Value::String("local_cpu_prove".to_string());
        let job = signed_event(
            &requester,
            KIND_WORKER_TRADE_TRANSITION_PROOF_REQ,
            serde_json::to_string(&request_json).expect("request json"),
            vec![vec!["p".to_string(), worker.public_key().to_string()]],
        );

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks.fetch_event_by_id_results.push_back(Ok(listing_event));
            hooks.fetch_event_by_id_results.push_back(Ok(request_event));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event));
        }

        let error = handle_trade_validation_receipt_job_request(
            &job,
            &worker,
            &client_for(&worker),
            &deterministic_policy(),
        )
        .await
        .expect_err("request backend override rejected");
        assert!(matches!(error, TradeValidationReceiptJobError::Serde(_)));
        let hooks = trade_validation_receipt_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(hooks.fetch_event_by_id_results.len(), 3);
        assert!(hooks.published_events.is_empty());
    }

    #[tokio::test]
    async fn proof_job_rejects_disabled_policy_before_relay_fetch() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::None,
            None,
            None,
        );

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks.fetch_event_by_id_results.push_back(Ok(listing_event));
            hooks.fetch_event_by_id_results.push_back(Ok(request_event));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event));
        }

        let error = handle_trade_validation_receipt_job_request(
            &job,
            &worker,
            &client_for(&worker),
            &TradeValidationReceiptProverPolicy::default(),
        )
        .await
        .expect_err("disabled policy rejected");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::ProverBackendDisabled
        ));
        let hooks = trade_validation_receipt_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(hooks.fetch_event_by_id_results.len(), 3);
        assert!(hooks.published_events.is_empty());
    }

    #[tokio::test]
    async fn proof_job_rejects_unverified_signed_event_evidence_before_publication() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (mut request_event, decision_event) =
            signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::None,
            None,
            None,
        );
        request_event.content.push(' ');

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks.fetch_event_by_id_results.push_back(Ok(listing_event));
            hooks.fetch_event_by_id_results.push_back(Ok(request_event));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event));
        }

        let error = handle_trade_validation_receipt_job_request(
            &job,
            &worker,
            &client_for(&worker),
            &deterministic_policy(),
        )
        .await
        .expect_err("signed evidence rejected");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::InvalidSignedEvent
        ));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[tokio::test]
    async fn proof_job_rejects_identity_mismatch_before_relay_fetch() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::None,
            None,
            None,
        );
        let mut request: TradeValidationReceiptJobRequest =
            serde_json::from_str(&job.content).expect("job request json");
        request.reducer_program_hash =
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string();
        let job = signed_event(
            &requester,
            KIND_WORKER_TRADE_TRANSITION_PROOF_REQ,
            serde_json::to_string(&request).expect("job json"),
            vec![vec!["p".to_string(), worker.public_key().to_string()]],
        );

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks.fetch_event_by_id_results.push_back(Ok(listing_event));
            hooks.fetch_event_by_id_results.push_back(Ok(request_event));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event));
        }

        let error = handle_trade_validation_receipt_job_request(
            &job,
            &worker,
            &client_for(&worker),
            &deterministic_policy(),
        )
        .await
        .expect_err("identity mismatch rejected");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::ExpectedReducerProgramHashMismatch
        ));
        let hooks = trade_validation_receipt_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(hooks.fetch_event_by_id_results.len(), 3);
        assert!(hooks.published_events.is_empty());
    }

    #[cfg(not(feature = "sp1_proving"))]
    #[tokio::test]
    async fn proof_job_rejects_unavailable_prover_backend_before_publication() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::None,
            None,
            None,
        );

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks.fetch_event_by_id_results.push_back(Ok(listing_event));
            hooks.fetch_event_by_id_results.push_back(Ok(request_event));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event));
        }

        let local_execute_policy = TradeValidationReceiptProverPolicy {
            backend: TradeValidationReceiptProverBackend::LocalExecute,
            proof_mode: RadrootsSp1TradeProofMode::None,
            expected_sp1_program_hash: None,
            expected_sp1_verifying_key_hash: None,
            remote_http: None,
        };
        let error = handle_trade_validation_receipt_job_request(
            &job,
            &worker,
            &client_for(&worker),
            &local_execute_policy,
        )
        .await
        .expect_err("backend unavailable");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::ProverBackendUnavailable("local_execute")
        ));
        assert_eq!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .fetch_event_by_id_results
                .len(),
            3
        );
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[tokio::test]
    async fn proof_job_requires_worker_recipient_tag() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let job = RadrootsNostrEventBuilder::new(
            RadrootsNostrKind::Custom(KIND_WORKER_TRADE_TRANSITION_PROOF_REQ as u16),
            "{}",
        )
        .tags(vec![RadrootsNostrTag::custom(
            RadrootsNostrTagKind::custom("p"),
            vec![requester.public_key().to_string()],
        )])
        .sign_with_keys(&requester)
        .expect("job");

        let error = handle_trade_validation_receipt_job_request(
            &job,
            &worker,
            &client_for(&worker),
            &deterministic_policy(),
        )
        .await
        .expect_err("missing recipient");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::MissingRecipient
        ));
    }

    trait WorkerRoleLabel {
        fn to_string(self) -> String;
    }

    impl WorkerRoleLabel for super::TradeValidationReceiptWorkerRole {
        fn to_string(self) -> String {
            serde_json::to_value(self)
                .expect("role json")
                .as_str()
                .expect("role string")
                .to_string()
        }
    }

    #[test]
    fn signed_events_are_canonical_active_trade_events() {
        let _guard = test_guard();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let request_rr = radroots_event_from_nostr(&request_event);
        let decision_rr = radroots_event_from_nostr(&decision_event);
        assert!(
            active_trade_order_request_event_build(
                &RadrootsNostrEventPtr {
                    id: listing_event.id.to_hex(),
                    relays: None,
                },
                &request_payload(
                    "order-1",
                    &listing_addr_for_seller(&seller),
                    &buyer,
                    &seller
                ),
            )
            .is_ok()
        );
        assert_eq!(request_rr.kind, 3422);
        assert_eq!(decision_rr.kind, 3423);
    }
}
