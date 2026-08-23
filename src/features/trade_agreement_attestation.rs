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

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

impl core::fmt::Debug for TradeAgreementAttestationPolicy {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TradeAgreementAttestationPolicy([redacted])")
    }
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
                    TradeAgreementAttestationError::new(
                        TradeAgreementAttestationErrorKind::InvalidValidatorSetBinding,
                    )
                })?;
                EventId::parse(event_id).map_err(|_| {
                    TradeAgreementAttestationError::new(
                        TradeAgreementAttestationErrorKind::InvalidValidatorSetBinding,
                    )
                })?;
                Ok(())
            }
            (None, None) => Ok(()),
            (Some(_), None) | (None, Some(_)) => Err(TradeAgreementAttestationError::new(
                TradeAgreementAttestationErrorKind::MissingValidatorSetBinding,
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

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeAgreementAttestationValidatorSetBinding {
    pub validator_set_addr: String,
    pub validator_set_event_id: String,
}

impl core::fmt::Debug for TradeAgreementAttestationValidatorSetBinding {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TradeAgreementAttestationValidatorSetBinding([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl core::fmt::Debug for TradeAgreementAttestationStatementV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TradeAgreementAttestationStatementV1([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl core::fmt::Debug for TradeAgreementAttestationReportV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("TradeAgreementAttestationReportV1([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TradeAgreementAttestationErrorKind {
    MissingAgreementClaim,
    MissingValidatorSetBinding,
    InvalidValidatorSetBinding,
    InvalidHashField,
    TradeProtocol,
    Encoding,
}

impl TradeAgreementAttestationErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingAgreementClaim => "agreement_claim_missing",
            Self::MissingValidatorSetBinding => "validator_set_binding_missing",
            Self::InvalidValidatorSetBinding => "validator_set_binding_invalid",
            Self::InvalidHashField => "configured_hash_invalid",
            Self::TradeProtocol => "trade_protocol_invalid",
            Self::Encoding => "attestation_encoding_failed",
        }
    }
}

impl core::fmt::Display for TradeAgreementAttestationErrorKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::MissingAgreementClaim => "agreement claim is missing",
            Self::MissingValidatorSetBinding => "attestation policy is incomplete",
            Self::InvalidValidatorSetBinding => "attestation policy is invalid",
            Self::InvalidHashField => "configured hash field is invalid",
            Self::TradeProtocol => "trade protocol input is invalid",
            Self::Encoding => "attestation encoding failed",
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Error)]
#[error("{kind}")]
pub struct TradeAgreementAttestationError {
    kind: TradeAgreementAttestationErrorKind,
}

impl TradeAgreementAttestationError {
    const fn new(kind: TradeAgreementAttestationErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> TradeAgreementAttestationErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl core::fmt::Debug for TradeAgreementAttestationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TradeAgreementAttestationError")
            .field("kind", &self.kind)
            .finish()
    }
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
        return Err(TradeAgreementAttestationError::new(
            TradeAgreementAttestationErrorKind::MissingAgreementClaim,
        ));
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
        return Err(TradeAgreementAttestationError::new(
            TradeAgreementAttestationErrorKind::InvalidHashField,
        ));
    }
    Ok(())
}

fn hash_canonical_value(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<String, TradeAgreementAttestationError> {
    let value = serde_json::to_value(value).map_err(|_| {
        TradeAgreementAttestationError::new(TradeAgreementAttestationErrorKind::Encoding)
    })?;
    let canonical = canonical_jcs_value(&value).map_err(|_| {
        TradeAgreementAttestationError::new(TradeAgreementAttestationErrorKind::TradeProtocol)
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_failures_are_closed_source_free_and_redacted() {
        for kind in [
            TradeAgreementAttestationErrorKind::MissingAgreementClaim,
            TradeAgreementAttestationErrorKind::MissingValidatorSetBinding,
            TradeAgreementAttestationErrorKind::InvalidValidatorSetBinding,
            TradeAgreementAttestationErrorKind::InvalidHashField,
            TradeAgreementAttestationErrorKind::TradeProtocol,
            TradeAgreementAttestationErrorKind::Encoding,
        ] {
            let error = TradeAgreementAttestationError::new(kind);
            assert_eq!(error.kind(), kind);
            assert!(!error.code().is_empty());
            assert!(std::error::Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            for forbidden in [
                "validator_set_addr",
                "validator_set_event_id",
                "serde_json",
                "TradeProtocolError",
                "/tmp/",
            ] {
                assert!(!rendered.contains(forbidden));
            }
        }
    }

    #[test]
    fn policy_failures_discard_field_values_and_dependency_causes() {
        let missing_policy = TradeAgreementAttestationPolicy {
            validator_set_addr: Some("secret:coordinate".to_owned()),
            ..TradeAgreementAttestationPolicy::default()
        };
        assert_eq!(
            format!("{missing_policy:?}"),
            "TradeAgreementAttestationPolicy([redacted])"
        );
        let missing = missing_policy.validate().expect_err("partial binding");
        assert_eq!(
            missing.kind(),
            TradeAgreementAttestationErrorKind::MissingValidatorSetBinding
        );

        let invalid = TradeAgreementAttestationPolicy {
            validator_set_addr: Some("secret:coordinate".to_owned()),
            validator_set_event_id: Some("secret:event".to_owned()),
            ..TradeAgreementAttestationPolicy::default()
        }
        .validate()
        .expect_err("invalid binding");
        assert_eq!(
            invalid.kind(),
            TradeAgreementAttestationErrorKind::InvalidValidatorSetBinding
        );

        let hash = TradeAgreementAttestationPolicy {
            expected_statement_contract_hash: Some("secret:hash".to_owned()),
            ..TradeAgreementAttestationPolicy::default()
        }
        .validate()
        .expect_err("invalid hash");
        assert_eq!(
            hash.kind(),
            TradeAgreementAttestationErrorKind::InvalidHashField
        );

        let rendered = format!("{missing:?} {invalid:?} {hash:?}");
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("coordinate"));
        assert!(!rendered.contains("event"));
        assert!(!rendered.contains("hash"));
    }
}
