#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use radroots_event::envelope::kind::TRADE_MUTATION_EVENT_KINDS;
use radroots_event::id::{AddressableCoordinate, EventId, MutationId};
use radroots_event::trade::canonical_jcs_value;
use radroots_trade::evidence::{RadrootsTradeAttestationResultV1, RadrootsTradeEvidenceStateV1};
use radroots_trade::model::{
    RadrootsTradeAgreementStateV1, RadrootsTradeAttestationStateV1, RadrootsTradeProjectionV1,
};
use radroots_trade::reducer::{RADROOTS_TRADE_REDUCER_CONTRACT_ID, RADROOTS_TRADE_REDUCER_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const RHI_AGREEMENT_ATTESTATION_PROTOCOL_ID: &str = "radroots.rhi.agreement_attestation.v1";
pub const RHI_AGREEMENT_ATTESTATION_REPORT_VERSION: u16 = 1;
pub const RHI_AGREEMENT_ATTESTATION_PROOF_SYSTEM_LOCAL_STATEMENT_HASH: &str =
    "local_statement_hash";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeAgreementAttestationBackend {
    #[default]
    LocalStatementHash,
}

impl TradeAgreementAttestationBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalStatementHash => "local_statement_hash",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeAgreementAttestationPolicy {
    #[serde(default)]
    pub backend: TradeAgreementAttestationBackend,
    #[serde(default)]
    pub validator_set_addr: Option<String>,
    #[serde(default)]
    pub validator_set_event_id: Option<String>,
    #[serde(default)]
    pub expected_statement_contract_hash: Option<String>,
}

impl TradeAgreementAttestationPolicy {
    pub fn validate(&self) -> Result<(), TradeAgreementAttestationError> {
        validate_optional_hash32(&self.expected_statement_contract_hash)?;
        match (
            self.validator_set_addr.as_deref(),
            self.validator_set_event_id.as_deref(),
        ) {
            (Some(addr), Some(event_id)) => {
                AddressableCoordinate::parse(addr).map_err(|_| {
                    TradeAgreementAttestationError::InvalidValidatorSetBinding("validator_set_addr")
                })?;
                EventId::parse(event_id).map_err(|_| {
                    TradeAgreementAttestationError::InvalidValidatorSetBinding(
                        "validator_set_event_id",
                    )
                })?;
                Ok(())
            }
            (None, None) => Ok(()),
            (Some(_), None) => Err(TradeAgreementAttestationError::MissingValidatorSetBinding(
                "validator_set_event_id",
            )),
            (None, Some(_)) => Err(TradeAgreementAttestationError::MissingValidatorSetBinding(
                "validator_set_addr",
            )),
        }
    }

    fn validator_set_binding(
        &self,
    ) -> Result<Option<TradeAgreementAttestationValidatorSetBinding>, TradeAgreementAttestationError>
    {
        self.validate()?;
        match (
            self.validator_set_addr.as_deref(),
            self.validator_set_event_id.as_deref(),
        ) {
            (Some(addr), Some(event_id)) => {
                Ok(Some(TradeAgreementAttestationValidatorSetBinding {
                    validator_set_addr: addr.to_owned(),
                    validator_set_event_id: event_id.to_owned(),
                }))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeAgreementAttestationValidatorSetBinding {
    pub validator_set_addr: String,
    pub validator_set_event_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeAgreementAttestationStatementV1 {
    pub protocol_id: String,
    pub schema_version: u16,
    pub reducer_contract_id: String,
    pub reducer_version: u16,
    pub trade_id: String,
    pub claim_mutation_id: String,
    pub projection_digest: String,
    pub agreement_state: RadrootsTradeAgreementStateV1,
    pub attestation_state_before_report: RadrootsTradeAttestationStateV1,
    pub active_agreement_claim_ids: Vec<String>,
    pub contested_claim_ids: Vec<String>,
    pub cancelled_claim_ids: Vec<String>,
    pub evidence_state: RadrootsTradeEvidenceStateV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_set: Option<TradeAgreementAttestationValidatorSetBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeAgreementAttestationReportV1 {
    pub report_version: u16,
    pub attestation_id: String,
    pub result: RadrootsTradeAttestationResultV1,
    pub statement: TradeAgreementAttestationStatementV1,
    pub statement_hash: String,
    pub proof_system: String,
    pub proof_identity_hash: String,
}

#[derive(Debug, Error)]
pub enum TradeAgreementAttestationError {
    #[error("agreement claim is missing")]
    MissingAgreementClaim,
    #[error("attestation policy is missing {0}")]
    MissingValidatorSetBinding(&'static str),
    #[error("attestation policy has invalid {0}")]
    InvalidValidatorSetBinding(&'static str),
    #[error("invalid configured hash field")]
    InvalidHashField,
    #[error("trade protocol error: {0}")]
    TradeProtocol(#[from] radroots_event::trade::TradeProtocolError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub fn attest_projection_claim(
    projection: &RadrootsTradeProjectionV1,
    claim_mutation_id: &MutationId,
    policy: &TradeAgreementAttestationPolicy,
) -> Result<TradeAgreementAttestationReportV1, TradeAgreementAttestationError> {
    policy.validate()?;
    if !projection
        .agreement_claims()
        .iter()
        .any(|claim| claim.claim_mutation_id() == claim_mutation_id)
    {
        return Err(TradeAgreementAttestationError::MissingAgreementClaim);
    }
    let statement = TradeAgreementAttestationStatementV1 {
        protocol_id: RHI_AGREEMENT_ATTESTATION_PROTOCOL_ID.to_owned(),
        schema_version: RHI_AGREEMENT_ATTESTATION_REPORT_VERSION,
        reducer_contract_id: RADROOTS_TRADE_REDUCER_CONTRACT_ID.to_owned(),
        reducer_version: RADROOTS_TRADE_REDUCER_VERSION,
        trade_id: projection.trade_id().to_hex(),
        claim_mutation_id: claim_mutation_id.to_hex(),
        projection_digest: projection.projection_digest().to_owned(),
        agreement_state: projection.agreement_state(),
        attestation_state_before_report: projection.attestation_state(),
        active_agreement_claim_ids: mutation_ids_to_strings(
            projection.active_agreement_claim_ids(),
        ),
        contested_claim_ids: mutation_ids_to_strings(projection.contested_claim_ids()),
        cancelled_claim_ids: mutation_ids_to_strings(projection.cancelled_claim_ids()),
        evidence_state: projection.evidence_state(),
        validator_set: policy.validator_set_binding()?,
    };
    let statement_hash = hash_canonical_value(
        b"radroots:rhi-agreement-attestation-statement:v1\0",
        &statement,
    )?;
    let result = if projection.agreement_state() == RadrootsTradeAgreementStateV1::Agreed
        && projection
            .active_agreement_claim_ids()
            .iter()
            .any(|claim| claim == claim_mutation_id)
        && !projection
            .contested_claim_ids()
            .iter()
            .any(|claim| claim == claim_mutation_id)
        && !projection
            .cancelled_claim_ids()
            .iter()
            .any(|claim| claim == claim_mutation_id)
    {
        RadrootsTradeAttestationResultV1::Valid
    } else {
        RadrootsTradeAttestationResultV1::Invalid
    };
    let proof_identity_hash = hash_canonical_value(
        b"radroots:rhi-agreement-attestation-proof-identity:v1\0",
        &serde_json::json!({
            "backend": policy.backend.as_str(),
            "proof_system": RHI_AGREEMENT_ATTESTATION_PROOF_SYSTEM_LOCAL_STATEMENT_HASH,
            "statement_hash": statement_hash,
            "validator_set": statement.validator_set.clone(),
        }),
    )?;
    let attestation_id = hash_canonical_value(
        b"radroots:rhi-agreement-attestation-report:v1\0",
        &serde_json::json!({
            "proof_identity_hash": proof_identity_hash,
            "result": result,
            "statement_hash": statement_hash,
        }),
    )?;
    Ok(TradeAgreementAttestationReportV1 {
        report_version: RHI_AGREEMENT_ATTESTATION_REPORT_VERSION,
        attestation_id,
        result,
        statement,
        statement_hash,
        proof_system: RHI_AGREEMENT_ATTESTATION_PROOF_SYSTEM_LOCAL_STATEMENT_HASH.to_owned(),
        proof_identity_hash,
    })
}

pub fn trade_mutation_subscription_kinds() -> Vec<u32> {
    TRADE_MUTATION_EVENT_KINDS.to_vec()
}

fn mutation_ids_to_strings(values: &[MutationId]) -> Vec<String> {
    values.iter().map(MutationId::to_hex).collect()
}

fn validate_optional_hash32(value: &Option<String>) -> Result<(), TradeAgreementAttestationError> {
    if let Some(value) = value {
        validate_hash32(value)?;
    }
    Ok(())
}

fn validate_hash32(value: &str) -> Result<(), TradeAgreementAttestationError> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    if stripped.len() != 64 || !stripped.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(TradeAgreementAttestationError::InvalidHashField);
    }
    Ok(())
}

fn hash_canonical_value(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<String, TradeAgreementAttestationError> {
    let value = serde_json::to_value(value)?;
    let canonical = canonical_jcs_value(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}
