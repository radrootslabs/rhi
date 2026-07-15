#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use radroots_event::ids::{RadrootsAddressableCoordinate, RadrootsEventId};
use radroots_event::kinds::KIND_ORDER_DECISION;
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrKeys, RadrootsNostrKind,
    RadrootsNostrTimestamp, radroots_event_from_nostr, radroots_nostr_build_event,
    radroots_nostr_fetch_event_by_id,
};
use radroots_trade::order::{RadrootsOrderEventRecord, order_event_record_from_event};
use radroots_trade::validation_receipt::{
    RadrootsTradeValidationReceipt, RadrootsValidationReceiptError,
    RadrootsValidationReceiptExpectedBinding, RadrootsValidationReceiptProof,
    RadrootsValidationReceiptProofSystem, RadrootsValidationReceiptResult,
    RadrootsValidationReceiptStatement, RadrootsValidationReceiptType, VALIDATION_RECEIPT_DOMAIN,
    VALIDATION_RECEIPT_VERSION, validation_receipt_event_build,
    validation_receipt_public_values_hash_hex, validator_set_address_from_str,
    verify_validation_receipt_event,
};
use radroots_trade::workflow::RadrootsTradeWorkflowState;
use radroots_trade_sp1_host::RadrootsSp1TradeProofMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::features::trade_listing::processed_jobs::{
    RhiProcessedJobClaim, RhiProcessedJobState, RhiProcessedJobStatus, RhiProcessedJobStoreError,
};
use crate::features::trade_listing::state::{
    TradeListingRuntime, TradeListingRuntimeError, TradeOrderState,
};

const RHI_PROCESSED_JOB_CLAIM_LEASE_MS: i64 = 10 * 60 * 1000;
const ZERO_ERROR_BITMAP: &str = "0x00000000000000000000000000000000";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeValidationReceiptProverBackend {
    #[default]
    LocalExecute,
    LocalCpuProve,
    LocalCudaProve,
    RemoteHttpProve,
}

impl TradeValidationReceiptProverBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
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
    #[serde(default)]
    pub backend: TradeValidationReceiptProverBackend,
    #[serde(default = "default_proof_mode")]
    pub proof_mode: RadrootsSp1TradeProofMode,
    #[serde(default)]
    pub validator_set_addr: Option<String>,
    #[serde(default)]
    pub validator_set_event_id: Option<String>,
    #[serde(default)]
    pub expected_sp1_program_hash: Option<String>,
    #[serde(default)]
    pub expected_sp1_verifying_key_hash: Option<String>,
    #[serde(default)]
    pub remote_http: Option<TradeValidationReceiptRemoteHttpProverConfig>,
}

fn default_proof_mode() -> RadrootsSp1TradeProofMode {
    RadrootsSp1TradeProofMode::None
}

impl Default for TradeValidationReceiptProverPolicy {
    fn default() -> Self {
        Self {
            backend: TradeValidationReceiptProverBackend::LocalExecute,
            proof_mode: RadrootsSp1TradeProofMode::None,
            validator_set_addr: None,
            validator_set_event_id: None,
            expected_sp1_program_hash: None,
            expected_sp1_verifying_key_hash: None,
            remote_http: None,
        }
    }
}

impl TradeValidationReceiptProverPolicy {
    pub fn validate(&self) -> Result<(), TradeValidationReceiptJobError> {
        validate_optional_hash32(&self.expected_sp1_program_hash)?;
        validate_optional_hash32(&self.expected_sp1_verifying_key_hash)?;
        match self.backend {
            TradeValidationReceiptProverBackend::LocalExecute => {
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
                Ok(())
            }
            TradeValidationReceiptProverBackend::LocalCpuProve
            | TradeValidationReceiptProverBackend::LocalCudaProve
            | TradeValidationReceiptProverBackend::RemoteHttpProve => {
                if self.proof_mode == RadrootsSp1TradeProofMode::None {
                    return Err(TradeValidationReceiptJobError::ProverBackendRequiresSp1Proof);
                }
                if self.expected_sp1_program_hash.is_none()
                    || self.expected_sp1_verifying_key_hash.is_none()
                {
                    return Err(TradeValidationReceiptJobError::Sp1IdentityPolicyRequired);
                }
                match self.backend {
                    TradeValidationReceiptProverBackend::LocalCpuProve
                    | TradeValidationReceiptProverBackend::RemoteHttpProve => {
                        if !cfg!(feature = "sp1_verify") {
                            return Err(TradeValidationReceiptJobError::ProverBackendUnavailable(
                                self.backend.as_str(),
                            ));
                        }
                    }
                    TradeValidationReceiptProverBackend::LocalCudaProve => {
                        return Err(TradeValidationReceiptJobError::ProverBackendUnavailable(
                            self.backend.as_str(),
                        ));
                    }
                    TradeValidationReceiptProverBackend::LocalExecute => {}
                }
                if self.backend == TradeValidationReceiptProverBackend::RemoteHttpProve
                    && self.remote_http.is_none()
                {
                    return Err(TradeValidationReceiptJobError::RemoteHttpConfigRequired);
                }
                Ok(())
            }
        }
    }

    pub fn validator_binding(
        &self,
    ) -> Result<(RadrootsAddressableCoordinate, String), TradeValidationReceiptJobError> {
        let validator_set_addr = self.validator_set_addr.as_deref().ok_or(
            TradeValidationReceiptJobError::MissingValidatorSetBinding("validator_set_addr"),
        )?;
        let validator_set_event_id = self.validator_set_event_id.as_deref().ok_or(
            TradeValidationReceiptJobError::MissingValidatorSetBinding("validator_set_event_id"),
        )?;
        let validator_set_addr =
            validator_set_address_from_str(validator_set_addr).map_err(|_| {
                TradeValidationReceiptJobError::InvalidValidatorSetBinding("validator_set_addr")
            })?;
        let validator_set_event_id = RadrootsEventId::parse(validator_set_event_id)
            .map_err(|_| {
                TradeValidationReceiptJobError::InvalidValidatorSetBinding("validator_set_event_id")
            })?
            .into_string();
        Ok((validator_set_addr, validator_set_event_id))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeValidationReceiptRemoteHttpProverConfig {
    pub endpoint_url: String,
    #[serde(default)]
    pub auth: Option<TradeValidationReceiptRemoteHttpAuth>,
    #[serde(default)]
    pub max_response_bytes: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TradeValidationReceiptRemoteHttpAuth {
    BearerEnv { env_var: String },
}

#[derive(Debug, Error)]
pub enum TradeValidationReceiptJobError {
    #[error("event kind not supported")]
    UnsupportedKind,
    #[error("missing recipient tag")]
    MissingRecipient,
    #[error("trade validation receipt policy is missing {0}")]
    MissingValidatorSetBinding(&'static str),
    #[error("trade validation receipt policy has invalid {0}")]
    InvalidValidatorSetBinding(&'static str),
    #[error("trade validation receipt policy backend requires proof_mode none")]
    ProverBackendRequiresNone,
    #[error("trade validation receipt policy backend requires SP1 proof mode")]
    ProverBackendRequiresSp1Proof,
    #[error("trade validation receipt policy backend is unavailable: {0}")]
    ProverBackendUnavailable(&'static str),
    #[error("trade validation receipt policy requires SP1 program and verifying-key hashes")]
    Sp1IdentityPolicyRequired,
    #[error("SP1 identity constraints require an SP1 proof mode")]
    Sp1IdentityConstraintsRequireSp1Proof,
    #[error("remote HTTP prover config is required")]
    RemoteHttpConfigRequired,
    #[error("invalid configured hash field")]
    InvalidHashField,
    #[error("invalid active trade event: {0}")]
    InvalidActiveTradeEvent(String),
    #[error("invalid signed event")]
    InvalidSignedEvent,
    #[error("duplicate conflicting processed job")]
    DuplicateConflictingJob,
    #[error("duplicate conflicting receipt")]
    DuplicateConflictingReceipt,
    #[error("duplicate conflicting result")]
    DuplicateConflictingResult,
    #[error("stored processed job failed: {0}")]
    StoredProcessedJobFailed(String),
    #[error("nostr error: {0}")]
    Nostr(#[from] radroots_nostr::error::RadrootsNostrError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("validation receipt error: {0}")]
    ValidationReceipt(#[from] RadrootsValidationReceiptError),
    #[error("order decode error: {0}")]
    OrderDecode(#[from] radroots_trade::order::RadrootsOrderEventDecodeError),
    #[error("runtime state error: {0}")]
    Runtime(#[from] TradeListingRuntimeError),
    #[error("processed-job store error: {0}")]
    ProcessedJobStore(#[from] RhiProcessedJobStoreError),
}

#[derive(Clone, Debug, Serialize)]
struct DeterministicReceiptPublicValues {
    changed_records_root: String,
    event_set_root: String,
    listing_event_id: String,
    new_state_root: String,
    order_id: String,
    previous_state_root: String,
    proof_system: String,
    result: String,
    schema_version: u32,
    target_event_id: String,
    validator_set_addr: String,
    validator_set_event_id: String,
}

pub async fn publish_validation_receipt(
    accepted_event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
    runtime: &TradeListingRuntime,
    keys: &RadrootsNostrKeys,
    policy: &TradeValidationReceiptProverPolicy,
) -> Result<(), TradeValidationReceiptJobError> {
    policy.validate()?;
    if policy.backend != TradeValidationReceiptProverBackend::LocalExecute
        || policy.proof_mode != RadrootsSp1TradeProofMode::None
    {
        return Err(TradeValidationReceiptJobError::ProverBackendUnavailable(
            policy.backend.as_str(),
        ));
    }
    let (validator_set_addr, validator_set_event_id) = policy.validator_binding()?;
    let kind = event_kind_u32(accepted_event)?;
    if kind != KIND_ORDER_DECISION {
        return Err(TradeValidationReceiptJobError::UnsupportedKind);
    }
    let rr_event = radroots_event_from_nostr(accepted_event);
    let record = order_event_record_from_event(&rr_event)?;
    let RadrootsOrderEventRecord::Decision(decision) = record else {
        return Err(TradeValidationReceiptJobError::UnsupportedKind);
    };
    if !matches!(
        decision.payload.decision,
        radroots_event::order::RadrootsOrderDecisionOutcome::Accepted { .. }
    ) {
        return Err(TradeValidationReceiptJobError::InvalidActiveTradeEvent(
            "order decision is not accepted".to_string(),
        ));
    }
    let order = {
        let state = runtime.state();
        let state = state.lock().await;
        state
            .get_order(decision.payload.order_id.as_str())
            .cloned()
            .ok_or_else(|| {
                TradeValidationReceiptJobError::InvalidActiveTradeEvent(
                    "order is missing from RHI state".to_string(),
                )
            })?
    };
    if order.status != RadrootsTradeWorkflowState::AgreedPendingValidation {
        return Err(TradeValidationReceiptJobError::InvalidActiveTradeEvent(
            "order is not awaiting validation".to_string(),
        ));
    }
    let root_event_id = order.root_event_id.as_deref().ok_or_else(|| {
        TradeValidationReceiptJobError::InvalidActiveTradeEvent(
            "order is missing root event id".to_string(),
        )
    })?;
    let listing_event_id = order.listing_snapshot_event_id.as_deref().ok_or_else(|| {
        TradeValidationReceiptJobError::InvalidActiveTradeEvent(
            "order is missing listing snapshot event id".to_string(),
        )
    })?;
    let target_event_id = accepted_event.id.to_hex();
    if order.last_event_id.as_deref() != Some(target_event_id.as_str()) {
        return Err(TradeValidationReceiptJobError::InvalidActiveTradeEvent(
            "accepted event is not the current order head".to_string(),
        ));
    }
    let root_event = fetch_event_by_id_io(client, root_event_id).await?;
    let listing_event = fetch_event_by_id_io(client, listing_event_id).await?;
    verify_root_event(&root_event, &order)?;
    let receipt = deterministic_receipt_for_acceptance(
        &order,
        listing_event_id,
        root_event_id,
        target_event_id.as_str(),
        validator_set_addr,
        validator_set_event_id.as_str(),
        [&listing_event, &root_event, accepted_event],
    )?;
    let receipt_parts = validation_receipt_event_build(&order.order_id, &receipt)?;
    let receipt_event = signed_event_from_parts(
        keys,
        receipt_parts.kind,
        receipt_parts.content,
        receipt_parts.tags,
        Some(accepted_event.created_at.as_secs()),
    )?;
    verify_validation_receipt_event(
        &radroots_event_from_nostr(&receipt_event),
        RadrootsValidationReceiptExpectedBinding {
            order_id: Some(order.order_id.as_str()),
            listing_event_id: Some(listing_event_id),
            root_event_id: Some(root_event_id),
            target_event_id: Some(target_event_id.as_str()),
            validator_set_addr: policy.validator_set_addr.as_deref(),
            validator_set_event_id: Some(validator_set_event_id.as_str()),
            proof_system: Some(RadrootsValidationReceiptProofSystem::None),
            public_values_hash: Some(receipt.public_values_hash.as_str()),
            ..RadrootsValidationReceiptExpectedBinding::default()
        },
    )?;
    publish_receipt_with_processed_job(runtime, client, accepted_event, &order, receipt_event).await
}

async fn publish_receipt_with_processed_job(
    runtime: &TradeListingRuntime,
    client: &RadrootsNostrClient,
    accepted_event: &RadrootsNostrEvent,
    order: &TradeOrderState,
    receipt_event: RadrootsNostrEvent,
) -> Result<(), TradeValidationReceiptJobError> {
    let receipt_event_id = receipt_event.id.to_hex();
    let receipt_event_json = serde_json::to_string(&receipt_event)?;
    let job = processed_job_for_receipt(accepted_event, order)?;
    match runtime
        .processed_jobs()
        .claim_job(&job, now_unix_ms(), RHI_PROCESSED_JOB_CLAIM_LEASE_MS)
        .await
        .map_err(processed_job_store_error)?
    {
        RhiProcessedJobClaim::Execute => {
            mark_receipt_publishing(
                runtime,
                &job,
                receipt_event_id.as_str(),
                receipt_event_json.as_str(),
            )
            .await?;
            let published_event_id = publish_signed_event_io(client, receipt_event).await?;
            if published_event_id != receipt_event_id {
                return Err(TradeValidationReceiptJobError::DuplicateConflictingReceipt);
            }
            mark_receipt_published(runtime, &job, receipt_event_id.as_str()).await?;
            mark_receipt_completed(
                runtime,
                &job,
                receipt_event_id.as_str(),
                receipt_event_json.as_str(),
                accepted_event_created_at(accepted_event),
            )
            .await
        }
        RhiProcessedJobClaim::InProgress | RhiProcessedJobClaim::Completed => Ok(()),
        RhiProcessedJobClaim::Failed { error_code } => Err(
            TradeValidationReceiptJobError::StoredProcessedJobFailed(error_code),
        ),
        RhiProcessedJobClaim::RecoverReceipt {
            receipt_event_id,
            receipt_event_json,
        }
        | RhiProcessedJobClaim::RecoverResult {
            receipt_event_id,
            receipt_event_json,
            ..
        } => {
            let receipt_event = signed_event_from_json(receipt_event_json.as_str())?;
            let published_event_id = publish_signed_event_io(client, receipt_event).await?;
            if published_event_id != receipt_event_id {
                return Err(TradeValidationReceiptJobError::DuplicateConflictingReceipt);
            }
            mark_receipt_published(runtime, &job, receipt_event_id.as_str()).await?;
            mark_receipt_completed(
                runtime,
                &job,
                receipt_event_id.as_str(),
                receipt_event_json.as_str(),
                accepted_event_created_at(accepted_event),
            )
            .await
        }
    }
}

fn deterministic_receipt_for_acceptance<'a>(
    order: &TradeOrderState,
    listing_event_id: &str,
    root_event_id: &str,
    target_event_id: &str,
    validator_set_addr: RadrootsAddressableCoordinate,
    validator_set_event_id: &str,
    events: impl IntoIterator<Item = &'a RadrootsNostrEvent>,
) -> Result<RadrootsTradeValidationReceipt, TradeValidationReceiptJobError> {
    let canonical_event_json = events
        .into_iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?;
    let event_set_root = hash32_for_parts(
        "radroots:rhi-validation-event-set:v1",
        canonical_event_json.iter().map(String::as_str),
    );
    let previous_state_root = hash32_for_parts(
        "radroots:rhi-validation-previous-state:v1",
        [
            order.order_id.as_str(),
            root_event_id,
            workflow_state_label(RadrootsTradeWorkflowState::Requested),
        ],
    );
    let new_state_root = hash32_for_parts(
        "radroots:rhi-validation-new-state:v1",
        [
            order.order_id.as_str(),
            target_event_id,
            workflow_state_label(RadrootsTradeWorkflowState::AgreedPendingValidation),
        ],
    );
    let changed_records_root = hash32_for_parts(
        "radroots:rhi-validation-changed-records:v1",
        [order.order_id.as_str(), target_event_id],
    );
    let public_values = DeterministicReceiptPublicValues {
        changed_records_root: changed_records_root.clone(),
        event_set_root: event_set_root.clone(),
        listing_event_id: listing_event_id.to_string(),
        new_state_root: new_state_root.clone(),
        order_id: order.order_id.clone(),
        previous_state_root: previous_state_root.clone(),
        proof_system: RadrootsValidationReceiptProofSystem::None
            .as_str()
            .to_string(),
        result: "valid".to_string(),
        schema_version: 1,
        target_event_id: target_event_id.to_string(),
        validator_set_addr: validator_set_addr.as_str().to_string(),
        validator_set_event_id: validator_set_event_id.to_string(),
    };
    let public_values_json = serde_json::to_string(&public_values)?;
    Ok(RadrootsTradeValidationReceipt {
        changed_records_root,
        domain: VALIDATION_RECEIPT_DOMAIN.to_string(),
        error_bitmap: ZERO_ERROR_BITMAP.to_string(),
        event_set_root,
        new_state_root,
        previous_state_root,
        proof: RadrootsValidationReceiptProof {
            inline_proof_base64: None,
            mode: None,
            program_hash: None,
            proof_reference: None,
            system: RadrootsValidationReceiptProofSystem::None,
            verifying_key_hash: None,
        },
        public_values_hash: validation_receipt_public_values_hash_hex(
            public_values_json.as_bytes(),
        ),
        receipt_type: RadrootsValidationReceiptType::TradeTransition,
        result: RadrootsValidationReceiptResult::Valid,
        statement: RadrootsValidationReceiptStatement {
            listing_event_id: listing_event_id.to_string(),
            root_event_id: root_event_id.to_string(),
            target_event_id: target_event_id.to_string(),
            validator_set_addr,
            validator_set_event_id: validator_set_event_id.to_string(),
            statement_type: RadrootsValidationReceiptType::TradeTransition,
        },
        version: VALIDATION_RECEIPT_VERSION,
    })
}

fn verify_root_event(
    root_event: &RadrootsNostrEvent,
    order: &TradeOrderState,
) -> Result<(), TradeValidationReceiptJobError> {
    let rr_event = radroots_event_from_nostr(root_event);
    let record = order_event_record_from_event(&rr_event)?;
    if record.order_id().as_str() != order.order_id {
        return Err(TradeValidationReceiptJobError::InvalidActiveTradeEvent(
            "root event order id mismatch".to_string(),
        ));
    }
    if !matches!(record, RadrootsOrderEventRecord::Request(_)) {
        return Err(TradeValidationReceiptJobError::InvalidActiveTradeEvent(
            "root event is not an order request".to_string(),
        ));
    }
    Ok(())
}

fn workflow_state_label(state: RadrootsTradeWorkflowState) -> &'static str {
    match state {
        RadrootsTradeWorkflowState::Missing => "missing",
        RadrootsTradeWorkflowState::Requested => "requested",
        RadrootsTradeWorkflowState::AgreedPendingValidation => "agreed_pending_validation",
        RadrootsTradeWorkflowState::Committed => "committed",
        RadrootsTradeWorkflowState::Declined => "declined",
        RadrootsTradeWorkflowState::Cancelled => "cancelled",
        RadrootsTradeWorkflowState::ValidationExpired => "validation_expired",
        RadrootsTradeWorkflowState::Invalid => "invalid",
    }
}

fn processed_job_for_receipt(
    accepted_event: &RadrootsNostrEvent,
    order: &TradeOrderState,
) -> Result<RhiProcessedJobState, TradeValidationReceiptJobError> {
    Ok(RhiProcessedJobState {
        request_id: accepted_event.id.to_hex(),
        request_kind: event_kind_u32(accepted_event)?,
        request_hash: event_hash_hex(accepted_event)?,
        customer_pubkey: order.buyer_pubkey.clone(),
        status: RhiProcessedJobStatus::Processing,
        receipt_event_id: None,
        receipt_event_json: None,
        result_event_id: None,
        result_event_json: None,
        proof_metadata_json: None,
        error_code: None,
        created_timestamp: accepted_event_created_at(accepted_event),
        completed_timestamp: None,
    })
}

async fn mark_receipt_publishing(
    runtime: &TradeListingRuntime,
    job: &RhiProcessedJobState,
    receipt_event_id: &str,
    receipt_event_json: &str,
) -> Result<(), TradeValidationReceiptJobError> {
    runtime
        .processed_jobs()
        .mark_receipt_publishing(
            job,
            receipt_event_id,
            receipt_event_json,
            None,
            now_unix_ms(),
        )
        .await
        .map_err(processed_job_store_error)?;
    Ok(())
}

async fn mark_receipt_published(
    runtime: &TradeListingRuntime,
    job: &RhiProcessedJobState,
    receipt_event_id: &str,
) -> Result<(), TradeValidationReceiptJobError> {
    runtime
        .processed_jobs()
        .mark_receipt_published(job, receipt_event_id, now_unix_ms())
        .await
        .map_err(processed_job_store_error)?;
    Ok(())
}

async fn mark_receipt_completed(
    runtime: &TradeListingRuntime,
    job: &RhiProcessedJobState,
    receipt_event_id: &str,
    receipt_event_json: &str,
    completed_timestamp: u32,
) -> Result<(), TradeValidationReceiptJobError> {
    runtime
        .processed_jobs()
        .mark_receipt_completed(
            job,
            receipt_event_id,
            receipt_event_json,
            completed_timestamp,
            now_unix_ms(),
        )
        .await
        .map_err(processed_job_store_error)?;
    Ok(())
}

async fn fetch_event_by_id_io(
    client: &RadrootsNostrClient,
    event_id: &str,
) -> Result<RadrootsNostrEvent, TradeValidationReceiptJobError> {
    #[cfg(test)]
    if let Some(event) = pop_fetch_event_by_id_hook() {
        return event;
    }
    Ok(radroots_nostr_fetch_event_by_id(client, event_id).await?)
}

async fn publish_signed_event_io(
    client: &RadrootsNostrClient,
    event: RadrootsNostrEvent,
) -> Result<String, TradeValidationReceiptJobError> {
    #[cfg(test)]
    if let Some(result) = pop_publish_signed_event_hook(&event) {
        result?;
        return Ok(event.id.to_hex());
    }
    let output = client.send_event(&event).await?;
    Ok(output.val.to_hex())
}

fn signed_event_from_parts(
    keys: &RadrootsNostrKeys,
    kind: u32,
    content: String,
    tags: Vec<Vec<String>>,
    created_at_secs: Option<u64>,
) -> Result<RadrootsNostrEvent, TradeValidationReceiptJobError> {
    let mut builder = radroots_nostr_build_event(kind, content, tags)?;
    if let Some(created_at_secs) = created_at_secs {
        builder = builder.custom_created_at(RadrootsNostrTimestamp::from_secs(created_at_secs));
    }
    builder
        .sign_with_keys(keys)
        .map_err(|_| TradeValidationReceiptJobError::InvalidSignedEvent)
}

fn signed_event_from_json(
    value: &str,
) -> Result<RadrootsNostrEvent, TradeValidationReceiptJobError> {
    let event: RadrootsNostrEvent = serde_json::from_str(value)?;
    event
        .verify()
        .map_err(|_| TradeValidationReceiptJobError::InvalidSignedEvent)?;
    Ok(event)
}

fn event_kind_u32(event: &RadrootsNostrEvent) -> Result<u32, TradeValidationReceiptJobError> {
    match event.kind {
        RadrootsNostrKind::Custom(value) => Ok(u32::from(value)),
        _ => Err(TradeValidationReceiptJobError::UnsupportedKind),
    }
}

fn accepted_event_created_at(event: &RadrootsNostrEvent) -> u32 {
    u32::try_from(event.created_at.as_secs()).unwrap_or(u32::MAX)
}

fn event_hash_hex(event: &RadrootsNostrEvent) -> Result<String, TradeValidationReceiptJobError> {
    let canonical_event_json = serde_json::to_string(event)?;
    Ok(hash_hex_for_bytes(canonical_event_json.as_bytes()))
}

fn hash32_for_parts<'a>(domain: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update([0]);
        hasher.update(part.as_bytes());
    }
    format!("0x{}", lower_hex(hasher.finalize().as_slice()))
}

fn hash_hex_for_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    lower_hex(hasher.finalize().as_slice())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

fn validate_optional_hash32(value: &Option<String>) -> Result<(), TradeValidationReceiptJobError> {
    if let Some(value) = value
        && (value.len() != 66 || !value.starts_with("0x") || !is_lower_hex(&value[2..]))
    {
        return Err(TradeValidationReceiptJobError::InvalidHashField);
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn now_unix_ms() -> i64 {
    let Ok(elapsed) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
}

fn processed_job_store_error(error: RhiProcessedJobStoreError) -> TradeValidationReceiptJobError {
    match error {
        RhiProcessedJobStoreError::DuplicateConflictingJob => {
            TradeValidationReceiptJobError::DuplicateConflictingJob
        }
        RhiProcessedJobStoreError::DuplicateConflictingReceipt => {
            TradeValidationReceiptJobError::DuplicateConflictingReceipt
        }
        RhiProcessedJobStoreError::DuplicateConflictingResult => {
            TradeValidationReceiptJobError::DuplicateConflictingResult
        }
        other => TradeValidationReceiptJobError::ProcessedJobStore(other),
    }
}

#[cfg(test)]
#[derive(Default)]
struct TradeValidationReceiptTestHooks {
    fetch_event_by_id_results:
        std::collections::VecDeque<Result<RadrootsNostrEvent, TradeValidationReceiptJobError>>,
    publish_event_results:
        std::collections::VecDeque<Result<String, TradeValidationReceiptJobError>>,
    published_events: Vec<RadrootsNostrEvent>,
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
        .expect("trade validation receipt hooks lock")
        .fetch_event_by_id_results
        .pop_front()
}

#[cfg(test)]
fn pop_publish_signed_event_hook(
    event: &RadrootsNostrEvent,
) -> Option<Result<String, TradeValidationReceiptJobError>> {
    let mut hooks = trade_validation_receipt_test_hooks()
        .lock()
        .expect("trade validation receipt hooks lock");
    hooks.published_events.push(event.clone());
    hooks.publish_event_results.pop_front()
}

#[cfg(test)]
mod tests {
    use super::{
        TradeValidationReceiptProverBackend, TradeValidationReceiptProverPolicy,
        trade_validation_receipt_test_hooks,
    };
    use radroots_trade_sp1_host::RadrootsSp1TradeProofMode;

    #[test]
    fn default_policy_is_enabled_deterministic_receipt_path() {
        let policy = TradeValidationReceiptProverPolicy::default();
        assert_eq!(
            policy.backend,
            TradeValidationReceiptProverBackend::LocalExecute
        );
        assert_eq!(policy.proof_mode, RadrootsSp1TradeProofMode::None);
    }

    #[test]
    fn validator_binding_requires_address_and_event_id() {
        let policy = TradeValidationReceiptProverPolicy::default();
        let error = policy.validator_binding().expect_err("binding must fail");
        assert!(error.to_string().contains("validator_set_addr"));
    }

    #[test]
    fn validator_binding_accepts_canonical_set_reference() {
        let policy = TradeValidationReceiptProverPolicy {
            validator_set_addr: Some(
                "30381:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd:018f3d99-7d35-7c0c-8a0f-7f3b645abcde"
                    .to_string(),
            ),
            validator_set_event_id: Some(
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
                    .to_string(),
            ),
            ..TradeValidationReceiptProverPolicy::default()
        };
        let binding = policy.validator_binding().expect("validator binding");
        assert_eq!(
            binding.0.as_str(),
            "30381:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd:018f3d99-7d35-7c0c-8a0f-7f3b645abcde"
        );
        assert_eq!(
            binding.1,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
    }

    #[test]
    fn test_hooks_reset() {
        *trade_validation_receipt_test_hooks()
            .lock()
            .expect("trade validation receipt hooks lock") =
            super::TradeValidationReceiptTestHooks::default();
    }
}
