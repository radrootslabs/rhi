//! Pure deterministic reduction of one sealed reconciliation manifest.

use core::fmt;
use std::{collections::BTreeSet, error::Error};

use radroots_event::{
    id::{MutationId, TradeId},
    trade::trade_mutation_from_canonical_content,
};
use radroots_trade::{
    evidence::{
        RadrootsTradeEvidenceCoverageV1, RadrootsTradeEvidenceOutcomeV1,
        RadrootsTradeEvidenceStateV1, RadrootsTradeMutationRecordV1,
    },
    model::{RadrootsTradeAgreementStateV1, RadrootsTradeProjectionV1},
    reducer::{
        RADROOTS_TRADE_REDUCER_CONTRACT_ID, RADROOTS_TRADE_REDUCER_VERSION,
        RadrootsTradeReductionInputV1, reduce_trade_records,
    },
};
use sha2::{Digest, Sha256};

use crate::{
    RhiReconciliationManifest,
    reconciliation_manifest::{
        RHI_REDUCER_MAXIMUM_MUTATION_MATERIAL_BYTES, RHI_REDUCER_MAXIMUM_MUTATIONS,
        RhiReducerMutationMaterial,
    },
};

/// Exact version of the RHI reconciliation-reducer binding.
pub const RHI_RECONCILIATION_REDUCER_CONTRACT_VERSION: u32 = 1;
/// Exact version of the RHI reconciliation coverage/outcome binding.
pub const RHI_RECONCILIATION_OUTCOME_CONTRACT_VERSION: u32 = 1;

/// Exact shared four-state reconciliation coverage vocabulary.
pub type RhiReconciliationCoverage = RadrootsTradeEvidenceCoverageV1;
/// Exact shared three-state reconciliation outcome vocabulary.
pub type RhiReconciliationOutcome = RadrootsTradeEvidenceOutcomeV1;

const PROJECTION_DIGEST_DOMAIN: &[u8] = b"radroots.rhi.reconciliation_projection.v1\0";

/// Stable source-free reconciliation-reducer failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationReducerErrorKind {
    InvalidManifest,
    ProjectionUnavailable,
}

impl RhiReconciliationReducerErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidManifest => "reconciliation_reducer_manifest_invalid",
            Self::ProjectionUnavailable => "reconciliation_reducer_projection_unavailable",
        }
    }
}

/// Redacted source-free reconciliation-reducer failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationReducerError {
    kind: RhiReconciliationReducerErrorKind,
}

impl RhiReconciliationReducerError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiReconciliationReducerErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiReconciliationReducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiReconciliationReducerErrorKind::InvalidManifest => {
                "RHI reconciliation manifest cannot be reduced"
            }
            RhiReconciliationReducerErrorKind::ProjectionUnavailable => {
                "RHI reconciliation projection is unavailable"
            }
        })
    }
}

impl fmt::Debug for RhiReconciliationReducerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationReducerError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiReconciliationReducerError {}

/// Sealed deterministic projection retaining its exact manifest capability.
///
/// Callers cannot construct or relabel a projection.
///
/// ```compile_fail
/// use rhi::RhiReconciliationProjection;
///
/// let _forged = RhiReconciliationProjection {};
/// ```
pub struct RhiReconciliationProjection {
    manifest: RhiReconciliationManifest,
    shared: RadrootsTradeProjectionV1,
    shared_projection_digest: Option<[u8; 32]>,
    digest: Option<[u8; 32]>,
}

impl RhiReconciliationProjection {
    /// Returns the exact RHI reducer-binding contract version.
    #[must_use]
    pub const fn contract_version(&self) -> u32 {
        RHI_RECONCILIATION_REDUCER_CONTRACT_VERSION
    }

    /// Returns the exact shared reducer contract ID.
    #[must_use]
    pub const fn shared_reducer_contract_id(&self) -> &'static str {
        RADROOTS_TRADE_REDUCER_CONTRACT_ID
    }

    /// Returns the exact shared reducer contract version.
    #[must_use]
    pub const fn shared_reducer_contract_version(&self) -> u16 {
        RADROOTS_TRADE_REDUCER_VERSION
    }

    /// Returns the sealed manifest consumed by this projection.
    #[must_use]
    pub const fn manifest(&self) -> &RhiReconciliationManifest {
        &self.manifest
    }

    /// Returns the exact trade selected by the immutable manifest.
    #[must_use]
    pub const fn trade_id(&self) -> &TradeId {
        self.manifest.trade_id()
    }

    /// Returns the exact shared projection digest decoded from lowercase hex.
    #[must_use]
    pub const fn shared_projection_digest(&self) -> Option<[u8; 32]> {
        self.shared_projection_digest
    }

    /// Returns the domain-separated RHI projection digest.
    #[must_use]
    pub const fn digest(&self) -> Option<[u8; 32]> {
        self.digest
    }

    /// Returns the number of canonical shared reducer issues.
    #[must_use]
    pub fn issue_count(&self) -> usize {
        self.shared.issues().len()
    }

    /// Returns the selected root mutation when the manifest establishes one.
    #[must_use]
    pub const fn root_mutation_id(&self) -> Option<&MutationId> {
        self.shared.root_mutation_id()
    }
}

/// Stable closed reason for one claim-specific reconciliation outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RhiReconciliationReasonCode {
    RequiredEvidenceMissing,
    RequiredSourceIncomplete,
    RequiredSourceUnsupported,
    ProjectionDigestUnavailable,
    GoverningSchemaUnsupported,
    ReducerIssueUnresolved,
    AgreementClaimMissing,
    AgreementClaimUnresolved,
    ScopeSatisfied,
    AgreementClaimCancelled,
}

impl RhiReconciliationReasonCode {
    /// Returns the exact stable lowercase report reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RequiredEvidenceMissing => "required_evidence_missing",
            Self::RequiredSourceIncomplete => "required_source_incomplete",
            Self::RequiredSourceUnsupported => "required_source_unsupported",
            Self::ProjectionDigestUnavailable => "projection_digest_unavailable",
            Self::GoverningSchemaUnsupported => "governing_schema_unsupported",
            Self::ReducerIssueUnresolved => "reducer_issue_unresolved",
            Self::AgreementClaimMissing => "agreement_claim_missing",
            Self::AgreementClaimUnresolved => "agreement_claim_unresolved",
            Self::ScopeSatisfied => "scope_satisfied",
            Self::AgreementClaimCancelled => "agreement_claim_cancelled",
        }
    }
}

/// Sealed claim-specific coverage and outcome derived from one projection.
///
/// Callers cannot construct or relabel an evaluation.
///
/// ```compile_fail
/// use rhi::RhiReconciliationEvaluation;
///
/// let _forged = RhiReconciliationEvaluation {};
/// ```
pub struct RhiReconciliationEvaluation {
    projection: RhiReconciliationProjection,
    claim_mutation_id: MutationId,
    coverage: RhiReconciliationCoverage,
    outcome: RhiReconciliationOutcome,
    reason_codes: [RhiReconciliationReasonCode; 1],
}

impl RhiReconciliationEvaluation {
    /// Returns the exact coverage/outcome contract version.
    #[must_use]
    pub const fn contract_version(&self) -> u32 {
        RHI_RECONCILIATION_OUTCOME_CONTRACT_VERSION
    }

    /// Returns the sealed projection evaluated for this claim.
    #[must_use]
    pub const fn projection(&self) -> &RhiReconciliationProjection {
        &self.projection
    }

    /// Returns the exact typed claim selected by the evaluation.
    #[must_use]
    pub const fn claim_mutation_id(&self) -> &MutationId {
        &self.claim_mutation_id
    }

    /// Returns the exact four-state evidence coverage.
    #[must_use]
    pub const fn coverage(&self) -> RhiReconciliationCoverage {
        self.coverage
    }

    /// Returns the exact three-state claim outcome.
    #[must_use]
    pub const fn outcome(&self) -> RhiReconciliationOutcome {
        self.outcome
    }

    /// Returns the exact bounded stable reason-code inventory.
    #[must_use]
    pub const fn reason_codes(&self) -> &[RhiReconciliationReasonCode] {
        &self.reason_codes
    }
}

impl fmt::Debug for RhiReconciliationEvaluation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationEvaluation")
            .field("coverage", &self.coverage)
            .field("outcome", &self.outcome)
            .field("reason_codes", &self.reason_codes)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RhiReconciliationProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationProjection")
            .field("source_count", &self.manifest.source_count())
            .field("observation_count", &self.manifest.observation_count())
            .field("issue_count", &self.issue_count())
            .finish_non_exhaustive()
    }
}

/// Reduces one sealed immutable reconciliation manifest without external I/O.
pub fn reduce_rhi_reconciliation_manifest(
    manifest: RhiReconciliationManifest,
) -> Result<RhiReconciliationProjection, RhiReconciliationReducerError> {
    let inner = manifest.inner();
    if !mutation_material_within_bounds(manifest.reducer_mutations()) {
        return Err(failure(RhiReconciliationReducerErrorKind::InvalidManifest));
    }
    let observation_inventory = inner
        .observations()
        .iter()
        .map(|observation| (*observation.mutation_id(), *observation.event_id()))
        .collect::<BTreeSet<_>>();
    if inner.observations().iter().any(|observation| {
        manifest
            .reducer_mutations()
            .binary_search_by_key(observation.mutation_id(), |material| material.mutation_id)
            .is_err()
    }) {
        return Err(failure(RhiReconciliationReducerErrorKind::InvalidManifest));
    }

    let mut mutations = Vec::with_capacity(manifest.reducer_mutations().len());
    for material in manifest.reducer_mutations() {
        if !observation_inventory.contains(&(material.mutation_id, material.event_id)) {
            return Err(failure(RhiReconciliationReducerErrorKind::InvalidManifest));
        }
        let content = core::str::from_utf8(&material.canonical_content)
            .map_err(|_| failure(RhiReconciliationReducerErrorKind::InvalidManifest))?;
        let mutation = trade_mutation_from_canonical_content(content)
            .map_err(|_| failure(RhiReconciliationReducerErrorKind::InvalidManifest))?;
        if mutation.mutation_id != Some(material.mutation_id)
            || mutation.trade_id != *inner.trade_id()
        {
            return Err(failure(RhiReconciliationReducerErrorKind::InvalidManifest));
        }
        mutations.push(RadrootsTradeMutationRecordV1::new(
            Some(material.event_id),
            mutation,
        ));
    }

    let input = RadrootsTradeReductionInputV1::new(*inner.trade_id())
        .with_mutations(mutations)
        .with_evidence_state(evidence_state(inner.coverage()))
        .with_observed_at_unix_s(Some(inner.observed_at_unix_s()));
    let shared = reduce_trade_records(input);
    if shared.reducer_contract_id() != RADROOTS_TRADE_REDUCER_CONTRACT_ID
        || shared.reducer_version() != RADROOTS_TRADE_REDUCER_VERSION
        || shared.trade_id() != inner.trade_id()
    {
        return Err(failure(
            RhiReconciliationReducerErrorKind::ProjectionUnavailable,
        ));
    }
    let shared_projection_digest = decode_lower_hex_32(shared.projection_digest());
    let digest = shared_projection_digest.and_then(|shared_projection_digest| {
        projection_digest(&manifest, shared_projection_digest)
    });
    Ok(RhiReconciliationProjection {
        manifest,
        shared,
        shared_projection_digest,
        digest,
    })
}

/// Evaluates one exact typed agreement claim against a sealed projection.
pub fn evaluate_rhi_reconciliation_claim(
    projection: RhiReconciliationProjection,
    claim_mutation_id: MutationId,
) -> RhiReconciliationEvaluation {
    let shared = &projection.shared;
    let facts = EvaluationFacts {
        coverage: projection.manifest.inner().coverage(),
        shared_evidence: shared.evidence_state(),
        projection_digest_available: projection.digest.is_some(),
        reducer_issue_present: !shared.issues().is_empty(),
        claim_present: shared
            .agreement_claims()
            .iter()
            .any(|claim| claim.claim_mutation_id() == &claim_mutation_id),
        claim_active: shared
            .active_agreement_claim_ids()
            .contains(&claim_mutation_id),
        claim_contested: shared.contested_claim_ids().contains(&claim_mutation_id),
        claim_cancelled: shared.cancelled_claim_ids().contains(&claim_mutation_id),
        agreement_agreed: shared.agreement_state() == RadrootsTradeAgreementStateV1::Agreed,
    };
    let (outcome, reason) = classify_evaluation(facts);
    RhiReconciliationEvaluation {
        projection,
        claim_mutation_id,
        coverage: facts.coverage,
        outcome,
        reason_codes: [reason],
    }
}

#[derive(Clone, Copy)]
struct EvaluationFacts {
    coverage: RhiReconciliationCoverage,
    shared_evidence: RadrootsTradeEvidenceStateV1,
    projection_digest_available: bool,
    reducer_issue_present: bool,
    claim_present: bool,
    claim_active: bool,
    claim_contested: bool,
    claim_cancelled: bool,
    agreement_agreed: bool,
}

fn classify_evaluation(
    facts: EvaluationFacts,
) -> (RhiReconciliationOutcome, RhiReconciliationReasonCode) {
    use RadrootsTradeEvidenceOutcomeV1::{Indeterminate, Invalid, Valid};
    use RhiReconciliationReasonCode::{
        AgreementClaimCancelled, AgreementClaimMissing, AgreementClaimUnresolved,
        GoverningSchemaUnsupported, ProjectionDigestUnavailable, ReducerIssueUnresolved,
        RequiredEvidenceMissing, RequiredSourceIncomplete, RequiredSourceUnsupported,
        ScopeSatisfied,
    };

    match facts.coverage {
        RhiReconciliationCoverage::Missing => return (Indeterminate, RequiredEvidenceMissing),
        RhiReconciliationCoverage::Partial => return (Indeterminate, RequiredSourceIncomplete),
        RhiReconciliationCoverage::Unsupported => {
            return (Indeterminate, RequiredSourceUnsupported);
        }
        RhiReconciliationCoverage::ScopeSatisfied => {}
    }
    if !facts.projection_digest_available {
        return (Indeterminate, ProjectionDigestUnavailable);
    }
    match facts.shared_evidence {
        RadrootsTradeEvidenceStateV1::Missing => {
            return (Indeterminate, RequiredEvidenceMissing);
        }
        RadrootsTradeEvidenceStateV1::QueryPartial => {
            return (Indeterminate, RequiredSourceIncomplete);
        }
        RadrootsTradeEvidenceStateV1::UnsupportedVersion => {
            return (Indeterminate, GoverningSchemaUnsupported);
        }
        RadrootsTradeEvidenceStateV1::Complete => {}
    }
    if facts.reducer_issue_present
        || facts.claim_contested
        || (facts.claim_active && facts.claim_cancelled)
    {
        return (Indeterminate, ReducerIssueUnresolved);
    }
    if !facts.claim_present {
        return (Indeterminate, AgreementClaimMissing);
    }
    if facts.claim_active && facts.agreement_agreed {
        return (Valid, ScopeSatisfied);
    }
    if facts.claim_cancelled && !facts.claim_active {
        return (Invalid, AgreementClaimCancelled);
    }
    (Indeterminate, AgreementClaimUnresolved)
}

fn mutation_material_within_bounds(materials: &[RhiReducerMutationMaterial]) -> bool {
    material_lengths_within_bounds(
        materials.len(),
        materials
            .iter()
            .map(|material| material.canonical_content.len()),
    )
}

fn material_lengths_within_bounds<I>(count: usize, lengths: I) -> bool
where
    I: IntoIterator<Item = usize>,
{
    count <= RHI_REDUCER_MAXIMUM_MUTATIONS
        && lengths
            .into_iter()
            .try_fold(0_usize, usize::checked_add)
            .is_some_and(|total| total <= RHI_REDUCER_MAXIMUM_MUTATION_MATERIAL_BYTES)
}

fn evidence_state(coverage: RadrootsTradeEvidenceCoverageV1) -> RadrootsTradeEvidenceStateV1 {
    match coverage {
        RadrootsTradeEvidenceCoverageV1::Missing => RadrootsTradeEvidenceStateV1::Missing,
        RadrootsTradeEvidenceCoverageV1::Partial => RadrootsTradeEvidenceStateV1::QueryPartial,
        RadrootsTradeEvidenceCoverageV1::ScopeSatisfied => RadrootsTradeEvidenceStateV1::Complete,
        RadrootsTradeEvidenceCoverageV1::Unsupported => {
            RadrootsTradeEvidenceStateV1::UnsupportedVersion
        }
    }
}

fn projection_digest(manifest: &RhiReconciliationManifest, shared: [u8; 32]) -> Option<[u8; 32]> {
    let inner = manifest.inner();
    let mut digest = Sha256::new();
    digest.update(PROJECTION_DIGEST_DOMAIN);
    digest.update(RHI_RECONCILIATION_REDUCER_CONTRACT_VERSION.to_be_bytes());
    digest.update(
        u64::try_from(RADROOTS_TRADE_REDUCER_CONTRACT_ID.len())
            .ok()?
            .to_be_bytes(),
    );
    digest.update(RADROOTS_TRADE_REDUCER_CONTRACT_ID.as_bytes());
    digest.update(RADROOTS_TRADE_REDUCER_VERSION.to_be_bytes());
    digest.update(manifest.digest());
    digest.update(inner.evidence_policy_digest().as_bytes());
    digest.update(shared);
    Some(digest.finalize().into())
}

fn decode_lower_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = decode_lower_hex(pair[0])?
            .checked_mul(16)?
            .checked_add(decode_lower_hex(pair[1])?)?;
    }
    Some(output)
}

const fn decode_lower_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

const fn failure(kind: RhiReconciliationReducerErrorKind) -> RhiReconciliationReducerError {
    RhiReconciliationReducerError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_satisfied_facts() -> EvaluationFacts {
        EvaluationFacts {
            coverage: RhiReconciliationCoverage::ScopeSatisfied,
            shared_evidence: RadrootsTradeEvidenceStateV1::Complete,
            projection_digest_available: true,
            reducer_issue_present: false,
            claim_present: true,
            claim_active: true,
            claim_contested: false,
            claim_cancelled: false,
            agreement_agreed: true,
        }
    }

    #[test]
    fn diagnostics_and_digest_decoder_are_closed() {
        for kind in [
            RhiReconciliationReducerErrorKind::InvalidManifest,
            RhiReconciliationReducerErrorKind::ProjectionUnavailable,
        ] {
            let error = failure(kind);
            assert_eq!(error.kind(), kind);
            assert!(Error::source(&error).is_none());
            assert!(!format!("{error} {error:?}").contains("trade-primary"));
        }
        assert_eq!(decode_lower_hex_32(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(decode_lower_hex_32(&"AB".repeat(32)), None);
        assert_eq!(decode_lower_hex_32("00"), None);
    }

    #[test]
    fn mutation_material_length_and_count_bounds_are_exact() {
        assert!(material_lengths_within_bounds(
            RHI_REDUCER_MAXIMUM_MUTATIONS,
            [RHI_REDUCER_MAXIMUM_MUTATION_MATERIAL_BYTES]
        ));
        assert!(!material_lengths_within_bounds(
            RHI_REDUCER_MAXIMUM_MUTATIONS,
            [RHI_REDUCER_MAXIMUM_MUTATION_MATERIAL_BYTES, 1]
        ));
        assert!(!material_lengths_within_bounds(
            RHI_REDUCER_MAXIMUM_MUTATIONS + 1,
            core::iter::empty()
        ));
        assert!(!material_lengths_within_bounds(1, [usize::MAX, 1]));
    }

    #[test]
    fn coverage_and_claim_state_matrix_is_total_and_fail_closed() {
        use RadrootsTradeEvidenceCoverageV1::{Missing, Partial, ScopeSatisfied, Unsupported};
        use RadrootsTradeEvidenceOutcomeV1::{Indeterminate, Invalid, Valid};
        use RhiReconciliationReasonCode::{
            AgreementClaimCancelled, AgreementClaimMissing, RequiredEvidenceMissing,
            RequiredSourceIncomplete, RequiredSourceUnsupported, ScopeSatisfied as ScopeReason,
        };

        for (coverage, incomplete_reason) in [
            (Missing, RequiredEvidenceMissing),
            (Partial, RequiredSourceIncomplete),
            (Unsupported, RequiredSourceUnsupported),
        ] {
            for (present, active, cancelled) in [
                (false, false, false),
                (true, true, false),
                (true, false, true),
            ] {
                let actual = classify_evaluation(EvaluationFacts {
                    coverage,
                    claim_present: present,
                    claim_active: active,
                    claim_cancelled: cancelled,
                    ..scope_satisfied_facts()
                });
                assert_eq!(actual, (Indeterminate, incomplete_reason));
                assert!(coverage.permits(actual.0));
            }
        }

        for (present, active, cancelled, expected) in [
            (false, false, false, (Indeterminate, AgreementClaimMissing)),
            (true, true, false, (Valid, ScopeReason)),
            (true, false, true, (Invalid, AgreementClaimCancelled)),
        ] {
            let actual = classify_evaluation(EvaluationFacts {
                coverage: ScopeSatisfied,
                claim_present: present,
                claim_active: active,
                claim_cancelled: cancelled,
                ..scope_satisfied_facts()
            });
            assert_eq!(actual, expected);
            assert!(ScopeSatisfied.permits(actual.0));
        }
    }

    #[test]
    fn fail_closed_precedence_covers_every_unavailable_or_ambiguous_fact() {
        use RadrootsTradeEvidenceOutcomeV1::Indeterminate;
        use RhiReconciliationReasonCode::{
            AgreementClaimUnresolved, GoverningSchemaUnsupported, ProjectionDigestUnavailable,
            ReducerIssueUnresolved, RequiredEvidenceMissing, RequiredSourceIncomplete,
        };

        let cases = [
            (
                EvaluationFacts {
                    projection_digest_available: false,
                    ..scope_satisfied_facts()
                },
                ProjectionDigestUnavailable,
            ),
            (
                EvaluationFacts {
                    shared_evidence: RadrootsTradeEvidenceStateV1::Missing,
                    ..scope_satisfied_facts()
                },
                RequiredEvidenceMissing,
            ),
            (
                EvaluationFacts {
                    shared_evidence: RadrootsTradeEvidenceStateV1::QueryPartial,
                    ..scope_satisfied_facts()
                },
                RequiredSourceIncomplete,
            ),
            (
                EvaluationFacts {
                    shared_evidence: RadrootsTradeEvidenceStateV1::UnsupportedVersion,
                    ..scope_satisfied_facts()
                },
                GoverningSchemaUnsupported,
            ),
            (
                EvaluationFacts {
                    reducer_issue_present: true,
                    ..scope_satisfied_facts()
                },
                ReducerIssueUnresolved,
            ),
            (
                EvaluationFacts {
                    claim_contested: true,
                    ..scope_satisfied_facts()
                },
                ReducerIssueUnresolved,
            ),
            (
                EvaluationFacts {
                    claim_cancelled: true,
                    ..scope_satisfied_facts()
                },
                ReducerIssueUnresolved,
            ),
            (
                EvaluationFacts {
                    agreement_agreed: false,
                    ..scope_satisfied_facts()
                },
                AgreementClaimUnresolved,
            ),
            (
                EvaluationFacts {
                    claim_active: false,
                    claim_cancelled: false,
                    ..scope_satisfied_facts()
                },
                AgreementClaimUnresolved,
            ),
        ];
        for (facts, reason) in cases {
            assert_eq!(classify_evaluation(facts), (Indeterminate, reason));
        }

        let precedence = classify_evaluation(EvaluationFacts {
            coverage: RhiReconciliationCoverage::Missing,
            projection_digest_available: false,
            shared_evidence: RadrootsTradeEvidenceStateV1::UnsupportedVersion,
            reducer_issue_present: true,
            claim_present: false,
            ..scope_satisfied_facts()
        });
        assert_eq!(precedence, (Indeterminate, RequiredEvidenceMissing));
    }

    #[test]
    fn reason_codes_are_closed_stable_and_source_free() {
        let inventory = [
            (
                RhiReconciliationReasonCode::RequiredEvidenceMissing,
                "required_evidence_missing",
            ),
            (
                RhiReconciliationReasonCode::RequiredSourceIncomplete,
                "required_source_incomplete",
            ),
            (
                RhiReconciliationReasonCode::RequiredSourceUnsupported,
                "required_source_unsupported",
            ),
            (
                RhiReconciliationReasonCode::ProjectionDigestUnavailable,
                "projection_digest_unavailable",
            ),
            (
                RhiReconciliationReasonCode::GoverningSchemaUnsupported,
                "governing_schema_unsupported",
            ),
            (
                RhiReconciliationReasonCode::ReducerIssueUnresolved,
                "reducer_issue_unresolved",
            ),
            (
                RhiReconciliationReasonCode::AgreementClaimMissing,
                "agreement_claim_missing",
            ),
            (
                RhiReconciliationReasonCode::AgreementClaimUnresolved,
                "agreement_claim_unresolved",
            ),
            (
                RhiReconciliationReasonCode::ScopeSatisfied,
                "scope_satisfied",
            ),
            (
                RhiReconciliationReasonCode::AgreementClaimCancelled,
                "agreement_claim_cancelled",
            ),
        ];
        assert_eq!(inventory.len(), 10);
        for (reason, code) in inventory {
            assert_eq!(reason.code(), code);
            assert!(!code.contains("source://"));
        }
    }
}
