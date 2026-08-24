//! Immutable manifest materialization from one confirmed reconciliation commit.

use core::{fmt, num::NonZeroU64};
use std::error::Error;

use radroots_event::id::{EventId, MutationId, TradeId};
use radroots_service_host::UnixTimeSeconds;
use radroots_trade::evidence::{
    RadrootsTradeEvidenceManifestObservationV1, RadrootsTradeEvidenceManifestSourceResultV1,
    RadrootsTradeEvidenceManifestV1, RadrootsTradeEvidencePolicyDigestV1,
    RadrootsTradeEvidenceProvenanceDigestV1, RadrootsTradeEvidenceScopePrerequisitesV1,
    RadrootsTradeEvidenceSourceCompletionV1, RadrootsTradeEvidenceSourceIdV1,
    RadrootsTradeEvidenceSourceRequirementV1, RadrootsTradeEvidenceSourceResultDigestV1,
    RadrootsTradeEvidenceSourceResultV1, RadrootsTradeSignedEventDigestV1,
};
use sha2::{Digest, Sha256};

use crate::{
    RhiReconciliationAttemptPlan, RhiReconciliationSourceCommitOutcome, RhiTradeSourceCompletion,
    reconciliation_commit::committed_inventory_digest,
    reconciliation_replay::{
        RhiReconciliationReplayCommitFact, RhiReconciliationReplayCommitParts,
    },
};

/// Exact version of the RHI reconciliation-manifest materialization contract.
pub const RHI_RECONCILIATION_MANIFEST_CONTRACT_VERSION: u32 = 1;

const SOURCE_RESULT_DIGEST_DOMAIN: &[u8] =
    b"radroots.rhi.reconciliation_manifest_source_result.v1\0";
const PROVENANCE_DIGEST_DOMAIN: &[u8] = b"radroots.rhi.evidence_provenance.v1\0";
const SOURCE_SELECTOR: &[u8] = b"trade_mutation_lineage_v1";

/// Exact non-source prerequisite state bound into one manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationScopePrerequisites {
    Satisfied,
    Unsatisfied,
}

/// Stable source-free manifest materialization failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationManifestErrorKind {
    InvalidObservationTime,
    InvalidCommittedInventory,
}

impl RhiReconciliationManifestErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidObservationTime => "reconciliation_manifest_observation_time_invalid",
            Self::InvalidCommittedInventory => "reconciliation_manifest_inventory_invalid",
        }
    }
}

/// Redacted source-free reconciliation-manifest failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationManifestError {
    kind: RhiReconciliationManifestErrorKind,
}

impl RhiReconciliationManifestError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiReconciliationManifestErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiReconciliationManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiReconciliationManifestErrorKind::InvalidObservationTime => {
                "RHI reconciliation manifest observation time is invalid"
            }
            RhiReconciliationManifestErrorKind::InvalidCommittedInventory => {
                "RHI committed reconciliation inventory is invalid"
            }
        })
    }
}

impl fmt::Debug for RhiReconciliationManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationManifestError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiReconciliationManifestError {}

/// Sealed immutable evidence manifest derived from one confirmed Step190 commit.
///
/// Callers cannot forge a manifest by constructing its representation.
///
/// ```compile_fail
/// use rhi::RhiReconciliationManifest;
///
/// let _forged = RhiReconciliationManifest { inner: todo!() };
/// ```
pub struct RhiReconciliationManifest {
    inner: RadrootsTradeEvidenceManifestV1,
}

impl RhiReconciliationManifest {
    /// Returns the exact RHI manifest-materialization contract version.
    #[must_use]
    pub const fn contract_version(&self) -> u32 {
        RHI_RECONCILIATION_MANIFEST_CONTRACT_VERSION
    }

    /// Returns the exact shared manifest encoding contract ID.
    #[must_use]
    pub const fn shared_manifest_contract_id(&self) -> &'static str {
        self.inner.contract_id()
    }

    /// Returns the exact shared manifest encoding contract version.
    #[must_use]
    pub const fn shared_manifest_contract_version(&self) -> u16 {
        self.inner.contract_version()
    }

    /// Returns the exact trade selected by the committed attempt.
    #[must_use]
    pub const fn trade_id(&self) -> &TradeId {
        self.inner.trade_id()
    }

    /// Returns the exact nonzero dirty generation frozen by the manifest.
    #[must_use]
    pub const fn trade_generation(&self) -> u64 {
        self.inner.trade_generation().get()
    }

    /// Returns the explicit observation time in UTC seconds.
    #[must_use]
    pub const fn observed_at_unix_seconds(&self) -> u64 {
        self.inner.observed_at_unix_s()
    }

    /// Returns the exact canonical manifest bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.inner.canonical_bytes()
    }

    /// Returns the domain-separated shared manifest digest bytes.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *self.inner.digest().as_bytes()
    }

    /// Returns the exact configured source count.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.inner.sources().len()
    }

    /// Returns the exact accepted source-observation count.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.inner.observations().len()
    }
}

impl fmt::Debug for RhiReconciliationManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationManifest")
            .field("source_count", &self.source_count())
            .field("observation_count", &self.observation_count())
            .finish_non_exhaustive()
    }
}

impl RhiReconciliationSourceCommitOutcome {
    /// Freezes the exact committed inventory into the governed shared manifest.
    ///
    /// This consumes the sealed commit outcome so uncommitted replay material
    /// cannot be relabelled as durable evidence. The observation time must be
    /// at or after every committed source-result completion.
    pub fn into_evidence_manifest(
        self,
        observed_at: UnixTimeSeconds,
        prerequisites: RhiReconciliationScopePrerequisites,
    ) -> Result<RhiReconciliationManifest, RhiReconciliationManifestError> {
        freeze_manifest(self.manifest_material, observed_at, prerequisites)
    }
}

pub(crate) struct RhiCommittedManifestMaterial {
    trade_id: TradeId,
    generation: NonZeroU64,
    policy_digest: RadrootsTradeEvidencePolicyDigestV1,
    latest_finished_unix_ms: u64,
    sources: Box<[RadrootsTradeEvidenceManifestSourceResultV1]>,
    observations: Box<[RadrootsTradeEvidenceManifestObservationV1]>,
}

pub(crate) fn committed_manifest_material(
    plan: &RhiReconciliationAttemptPlan,
    parts: &[RhiReconciliationReplayCommitParts],
) -> Result<RhiCommittedManifestMaterial, ()> {
    let trade_id = parts.first().ok_or(())?.trade_id;
    let generation = NonZeroU64::new(plan.input_generation()).ok_or(())?;
    let policy_digest =
        RadrootsTradeEvidencePolicyDigestV1::from_bytes(*plan.evidence_policy_digest().as_bytes());
    let mut latest_finished_unix_ms = 0_u64;
    let mut sources = Vec::with_capacity(parts.len());
    let observation_capacity = parts.iter().try_fold(0_usize, |total, part| {
        total.checked_add(part.facts.len()).ok_or(())
    })?;
    let mut observations = Vec::with_capacity(observation_capacity);

    for (ordinal, part) in parts.iter().enumerate() {
        if part.trade_id != trade_id
            || part.policy_digest != *plan.evidence_policy_digest().as_bytes()
        {
            return Err(());
        }
        latest_finished_unix_ms = latest_finished_unix_ms.max(part.result.finished_at().get());
        let source_id =
            RadrootsTradeEvidenceSourceIdV1::parse(part.source_id.as_ref()).map_err(|_| ())?;
        let result = RadrootsTradeEvidenceSourceResultV1::new(
            if part.required {
                RadrootsTradeEvidenceSourceRequirementV1::Required
            } else {
                RadrootsTradeEvidenceSourceRequirementV1::Optional
            },
            map_completion(part.result.outcome()),
            part.result.accepted_event_count(),
        )
        .map_err(|_| ())?;
        let inventory_digest = committed_inventory_digest(part).ok_or(())?;
        let result_digest = source_result_digest(plan, ordinal, part, inventory_digest)?;
        sources.push(RadrootsTradeEvidenceManifestSourceResultV1::new(
            source_id.clone(),
            result,
            RadrootsTradeEvidenceSourceResultDigestV1::from_bytes(result_digest),
        ));
        for fact in &part.facts {
            observations.push(manifest_observation(source_id.clone(), part, fact)?);
        }
    }

    Ok(RhiCommittedManifestMaterial {
        trade_id,
        generation,
        policy_digest,
        latest_finished_unix_ms,
        sources: sources.into_boxed_slice(),
        observations: observations.into_boxed_slice(),
    })
}

fn freeze_manifest(
    material: RhiCommittedManifestMaterial,
    observed_at: UnixTimeSeconds,
    prerequisites: RhiReconciliationScopePrerequisites,
) -> Result<RhiReconciliationManifest, RhiReconciliationManifestError> {
    let earliest_observation = material.latest_finished_unix_ms.div_ceil(1_000);
    if observed_at.get() < earliest_observation || i64::try_from(observed_at.get()).is_err() {
        return Err(error(
            RhiReconciliationManifestErrorKind::InvalidObservationTime,
        ));
    }
    let inner = RadrootsTradeEvidenceManifestV1::new(
        material.trade_id,
        material.generation,
        material.policy_digest,
        observed_at.get(),
        match prerequisites {
            RhiReconciliationScopePrerequisites::Satisfied => {
                RadrootsTradeEvidenceScopePrerequisitesV1::Satisfied
            }
            RhiReconciliationScopePrerequisites::Unsatisfied => {
                RadrootsTradeEvidenceScopePrerequisitesV1::Unsatisfied
            }
        },
        material.sources.into_vec(),
        material.observations.into_vec(),
    )
    .map_err(|_| error(RhiReconciliationManifestErrorKind::InvalidCommittedInventory))?;
    Ok(RhiReconciliationManifest { inner })
}

fn map_completion(value: RhiTradeSourceCompletion) -> RadrootsTradeEvidenceSourceCompletionV1 {
    match value {
        RhiTradeSourceCompletion::Complete => RadrootsTradeEvidenceSourceCompletionV1::Complete,
        RhiTradeSourceCompletion::Unsupported => {
            RadrootsTradeEvidenceSourceCompletionV1::Unsupported
        }
        RhiTradeSourceCompletion::IncompleteTimeout
        | RhiTradeSourceCompletion::IncompleteUnavailable
        | RhiTradeSourceCompletion::IncompleteResourceLimit
        | RhiTradeSourceCompletion::IncompleteUnknown => {
            RadrootsTradeEvidenceSourceCompletionV1::Incomplete
        }
    }
}

fn source_result_digest(
    plan: &RhiReconciliationAttemptPlan,
    ordinal: usize,
    part: &RhiReconciliationReplayCommitParts,
    inventory_digest: [u8; 32],
) -> Result<[u8; 32], ()> {
    let mut digest = Sha256::new();
    digest.update(SOURCE_RESULT_DIGEST_DOMAIN);
    digest.update(plan.id().as_bytes());
    digest.update(u32::try_from(ordinal).map_err(|_| ())?.to_be_bytes());
    digest.update(part.request_id.as_bytes());
    update_framed(&mut digest, part.source_id.as_bytes())?;
    digest.update(part.trade_id.as_bytes());
    digest.update([u8::from(part.required)]);
    digest.update(part.policy_digest);
    digest.update(part.selector_digest);
    digest.update(part.replay_id.as_bytes());
    update_framed(&mut digest, part.result.outcome().code().as_bytes())?;
    digest.update(part.result.started_at().get().to_be_bytes());
    digest.update(part.result.finished_at().get().to_be_bytes());
    digest.update(part.result.accepted_event_count().to_be_bytes());
    digest.update(part.result.accepted_event_bytes().to_be_bytes());
    digest.update(inventory_digest);
    digest.update(part.duplicate_observations.to_be_bytes());
    update_optional_u64(&mut digest, part.first_observed_at.map(|value| value.get()));
    update_optional_cursor(&mut digest, part.prior_cursor);
    digest.update(part.overlap_seconds.to_be_bytes());
    digest.update(part.since_unix_seconds.to_be_bytes());
    update_optional_cursor(&mut digest, part.cursor_candidate);
    digest.update([u8::from(part.eligible_cursor.is_some())]);
    Ok(digest.finalize().into())
}

fn manifest_observation(
    source_id: RadrootsTradeEvidenceSourceIdV1,
    part: &RhiReconciliationReplayCommitParts,
    fact: &RhiReconciliationReplayCommitFact,
) -> Result<RadrootsTradeEvidenceManifestObservationV1, ()> {
    let record = &fact.record;
    let mut provenance = Sha256::new();
    provenance.update(PROVENANCE_DIGEST_DOMAIN);
    update_framed(&mut provenance, part.source_id.as_bytes())?;
    update_framed(&mut provenance, SOURCE_SELECTOR)?;
    provenance.update(part.policy_digest);
    provenance.update(record.event_id);
    provenance.update(record.event_signature);
    provenance.update(fact.observed_at.get().to_be_bytes());
    Ok(RadrootsTradeEvidenceManifestObservationV1::new(
        source_id,
        MutationId::from_bytes(record.mutation_id),
        EventId::from_bytes(record.event_id),
        RadrootsTradeSignedEventDigestV1::sha256(&record.canonical_event_json),
        RadrootsTradeEvidenceProvenanceDigestV1::from_bytes(provenance.finalize().into()),
    ))
}

fn update_framed(digest: &mut Sha256, bytes: &[u8]) -> Result<(), ()> {
    digest.update(u64::try_from(bytes.len()).map_err(|_| ())?.to_be_bytes());
    digest.update(bytes);
    Ok(())
}

fn update_optional_u64(digest: &mut Sha256, value: Option<u64>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn update_optional_cursor(digest: &mut Sha256, value: Option<crate::RhiTradeSourceCursor>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.created_at_unix_seconds().to_be_bytes());
            digest.update(value.event_id());
        }
        None => digest.update([0]),
    }
}

const fn error(kind: RhiReconciliationManifestErrorKind) -> RhiReconciliationManifestError {
    RhiReconciliationManifestError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_closed_redacted_and_source_free() {
        for kind in [
            RhiReconciliationManifestErrorKind::InvalidObservationTime,
            RhiReconciliationManifestErrorKind::InvalidCommittedInventory,
        ] {
            let error = super::error(kind);
            assert_eq!(error.kind(), kind);
            assert!(Error::source(&error).is_none());
            assert!(!format!("{error} {error:?}").contains("trade-primary"));
        }
    }
}
