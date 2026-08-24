//! Canonical signed attestation construction from one finalization fence.

use core::fmt;
use std::error::Error;

use nostr::{EventBuilder, Kind, PublicKey as NostrPublicKey, Tag, Timestamp};
use radroots_event::{
    envelope::EventEnvelope,
    id::EventId,
    wire::{EventWireLimits, Nip01EventWire},
};
use radroots_event_codec::{
    authoring::{AuthoredEventBody, AuthoredEventPlan},
    decode::rhi::{
        RadrootsRhiEvidenceAttestationV1, rhi_evidence_attestation_from_event,
        validate_rhi_evidence_attestation_supersession,
    },
};
use radroots_nostr::event::{Verification, verify, verify_id};
use radroots_service_host::{EntropySource, UnixTimeSeconds};
use radroots_trade::evidence::{
    RadrootsRhiEvidenceReasonCodeV1, RadrootsRhiEvidenceReportV1,
    RadrootsRhiEvidenceSupersessionV1, RadrootsTradeEvidenceProjectionDigestV1,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    RhiDecryptedIdentity, RhiReconciliationCoverage, RhiReconciliationFinalizationFence,
    RhiReconciliationOutcome, RhiReconciliationReasonCode,
};

/// Exact version of the signed reconciliation-attestation boundary.
pub const RHI_RECONCILIATION_ATTESTATION_CONTRACT_VERSION: u32 = 1;

/// Exact cap for one canonical signed attestation event.
pub const RHI_RECONCILIATION_SIGNED_ATTESTATION_MAX_BYTES: usize = 32 * 1024;

const MAXIMUM_TAGS: usize = 7;
const MAXIMUM_TAG_ELEMENTS: usize = 21;
const MAXIMUM_TAG_ELEMENT_BYTES: usize = 128;
const MAXIMUM_TAG_BYTES: usize = 1_024;

/// Stable source-free signed-attestation failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationAttestationErrorKind {
    InvalidInput,
    IdentityMismatch,
    EntropyUnavailable,
    ReportInvalid,
    EventPlanInvalid,
    SigningFailed,
    VerificationFailed,
    SupersessionInvalid,
}

impl RhiReconciliationAttestationErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "reconciliation_attestation_input_invalid",
            Self::IdentityMismatch => "reconciliation_attestation_identity_mismatch",
            Self::EntropyUnavailable => "reconciliation_attestation_entropy_unavailable",
            Self::ReportInvalid => "reconciliation_attestation_report_invalid",
            Self::EventPlanInvalid => "reconciliation_attestation_event_plan_invalid",
            Self::SigningFailed => "reconciliation_attestation_signing_failed",
            Self::VerificationFailed => "reconciliation_attestation_verification_failed",
            Self::SupersessionInvalid => "reconciliation_attestation_supersession_invalid",
        }
    }
}

/// Redacted source-free signed-attestation failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationAttestationError {
    kind: RhiReconciliationAttestationErrorKind,
}

impl RhiReconciliationAttestationError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiReconciliationAttestationErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiReconciliationAttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiReconciliationAttestationErrorKind::InvalidInput => {
                "RHI reconciliation attestation input is invalid"
            }
            RhiReconciliationAttestationErrorKind::IdentityMismatch => {
                "RHI reconciliation attestation identity does not match"
            }
            RhiReconciliationAttestationErrorKind::EntropyUnavailable => {
                "RHI reconciliation attestation entropy is unavailable"
            }
            RhiReconciliationAttestationErrorKind::ReportInvalid => {
                "RHI reconciliation attestation report is invalid"
            }
            RhiReconciliationAttestationErrorKind::EventPlanInvalid => {
                "RHI reconciliation attestation event plan is invalid"
            }
            RhiReconciliationAttestationErrorKind::SigningFailed => {
                "RHI reconciliation attestation signing failed"
            }
            RhiReconciliationAttestationErrorKind::VerificationFailed => {
                "RHI reconciliation attestation verification failed"
            }
            RhiReconciliationAttestationErrorKind::SupersessionInvalid => {
                "RHI reconciliation attestation supersession is invalid"
            }
        })
    }
}

impl fmt::Debug for RhiReconciliationAttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationAttestationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiReconciliationAttestationError {}

/// Sealed exact reference to one prior independently verified attestation.
///
/// Callers cannot supply independent report and event identifiers that were
/// never proven together.
///
/// ```compile_fail
/// use rhi::RhiEvidenceAttestationSupersession;
///
/// let _forged = RhiEvidenceAttestationSupersession {};
/// ```
pub struct RhiEvidenceAttestationSupersession {
    report: RadrootsRhiEvidenceReportV1,
    event_id: EventId,
}

impl RhiEvidenceAttestationSupersession {
    /// Derives the only public supersession input from one verified result.
    #[must_use]
    pub fn from_attestation(attestation: &RhiSignedEvidenceAttestation) -> Self {
        Self {
            report: attestation.report.clone(),
            event_id: EventId::from_bytes(attestation.event_id),
        }
    }
}

impl fmt::Debug for RhiEvidenceAttestationSupersession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiEvidenceAttestationSupersession([redacted])")
    }
}

/// Sealed exact report and independently verified signed event.
///
/// This value owns its Step195 fence. Step199 consumes it, reruns the fence
/// inside its final write transaction, and persists these exact bytes without
/// rebuilding or re-signing them.
///
/// ```compile_fail
/// use rhi::RhiSignedEvidenceAttestation;
///
/// let _forged = RhiSignedEvidenceAttestation { event_id: [0; 32] };
/// ```
///
/// ```compile_fail
/// use rhi::RhiSignedEvidenceAttestation;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<RhiSignedEvidenceAttestation>();
/// ```
pub struct RhiSignedEvidenceAttestation {
    fence: RhiReconciliationFinalizationFence,
    report: RadrootsRhiEvidenceReportV1,
    event_id: [u8; 32],
    signed_event_bytes: Box<[u8]>,
    signed_event_sha256: [u8; 32],
    created_at_unix_seconds: u64,
}

impl RhiSignedEvidenceAttestation {
    /// Returns the exact RHI signed-attestation contract version.
    #[must_use]
    pub const fn contract_version(&self) -> u32 {
        RHI_RECONCILIATION_ATTESTATION_CONTRACT_VERSION
    }

    /// Returns the exact canonical report bytes.
    #[must_use]
    pub fn canonical_report_bytes(&self) -> &[u8] {
        self.report.canonical_content().as_bytes()
    }

    /// Returns the domain-separated statement/report identifier.
    #[must_use]
    pub fn statement_digest(&self) -> [u8; 32] {
        *self.report.statement_digest().as_bytes()
    }

    /// Returns the independently verified NIP-01 event identifier.
    #[must_use]
    pub const fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }

    /// Returns the exact signed event bytes that later persistence must retain.
    #[must_use]
    pub fn signed_event_bytes(&self) -> &[u8] {
        &self.signed_event_bytes
    }

    /// Returns the SHA-256 digest of the exact signed event bytes.
    #[must_use]
    pub const fn signed_event_sha256(&self) -> &[u8; 32] {
        &self.signed_event_sha256
    }

    /// Returns the injected NIP-01 authored time, distinct from observation time.
    #[must_use]
    pub const fn created_at_unix_seconds(&self) -> u64 {
        self.created_at_unix_seconds
    }

    /// Returns the exact evidence coverage retained by the finalization chain.
    #[must_use]
    pub const fn coverage(&self) -> RhiReconciliationCoverage {
        self.fence.evaluation().coverage()
    }

    /// Returns the exact claim outcome retained by the finalization chain.
    #[must_use]
    pub const fn outcome(&self) -> RhiReconciliationOutcome {
        self.fence.evaluation().outcome()
    }

    /// Returns whether this report explicitly supersedes one verified predecessor.
    #[must_use]
    pub const fn has_supersession(&self) -> bool {
        self.report.supersession().is_some()
    }
}

impl fmt::Debug for RhiSignedEvidenceAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiSignedEvidenceAttestation")
            .field("coverage", &self.coverage())
            .field("outcome", &self.outcome())
            .field("has_supersession", &self.has_supersession())
            .field("signed_event_bytes", &self.signed_event_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Builds, signs, and independently verifies one exact evidence attestation.
///
/// Signing consumes exactly 32 bytes from the injected entropy source. No
/// clock, entropy, source, relay, persistence, task, or network authority is
/// acquired implicitly.
pub fn build_rhi_signed_evidence_attestation(
    fence: RhiReconciliationFinalizationFence,
    identity: &RhiDecryptedIdentity,
    created_at: UnixTimeSeconds,
    entropy: &dyn EntropySource,
    supersession: Option<RhiEvidenceAttestationSupersession>,
) -> Result<RhiSignedEvidenceAttestation, RhiReconciliationAttestationError> {
    let evaluation = fence.evaluation();
    let projection = evaluation.projection();
    let manifest = projection.manifest();
    let projection_digest = projection
        .digest()
        .ok_or_else(|| failure(RhiReconciliationAttestationErrorKind::InvalidInput))?;
    let issuer = identity
        .public_identity()
        .as_hex()
        .parse()
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::IdentityMismatch))?;
    let reason_codes = evaluation
        .reason_codes()
        .iter()
        .copied()
        .map(report_reason)
        .collect::<Result<Vec<_>, _>>()?;
    let shared_supersession = supersession.as_ref().map(|prior| {
        RadrootsRhiEvidenceSupersessionV1::new(prior.report.statement_digest(), prior.event_id)
    });
    let report = RadrootsRhiEvidenceReportV1::new(
        issuer,
        *evaluation.claim_mutation_id(),
        evaluation.outcome(),
        reason_codes,
        RadrootsTradeEvidenceProjectionDigestV1::from_bytes(projection_digest),
        manifest.inner(),
        shared_supersession,
    )
    .map_err(|_| failure(RhiReconciliationAttestationErrorKind::ReportInvalid))?;
    report
        .validate_against_manifest(manifest.inner())
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::ReportInvalid))?;
    let attestation =
        RadrootsRhiEvidenceAttestationV1::from_canonical_content(report.canonical_content())
            .map_err(|_| failure(RhiReconciliationAttestationErrorKind::ReportInvalid))?;
    if let Some(prior) = supersession.as_ref() {
        let current = RadrootsRhiEvidenceAttestationV1::from_canonical_content(
            prior.report.canonical_content(),
        )
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::SupersessionInvalid))?;
        validate_rhi_evidence_attestation_supersession(&current, &prior.event_id, &attestation)
            .map_err(|_| failure(RhiReconciliationAttestationErrorKind::SupersessionInvalid))?;
    }
    let body = AuthoredEventBody::from_rhi_evidence_attestation(&attestation)
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::EventPlanInvalid))?;
    let plan = AuthoredEventPlan::bind(body, created_at.get(), identity.public_identity().as_hex())
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::EventPlanInvalid))?;

    let mut auxiliary = Zeroizing::new([0_u8; 32]);
    entropy
        .fill_bytes(&mut auxiliary[..])
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::EntropyUnavailable))?;
    let signed_event = sign_plan(identity, &plan, &auxiliary)?;
    let signed_event_bytes = serde_json::to_vec(&signed_event)
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::SigningFailed))?;
    if signed_event_bytes.len() > RHI_RECONCILIATION_SIGNED_ATTESTATION_MAX_BYTES {
        return Err(failure(
            RhiReconciliationAttestationErrorKind::SigningFailed,
        ));
    }
    let verified = verify_signed_event(&plan, &report, manifest.inner(), &signed_event_bytes)?;
    let signed_event_sha256 = Sha256::digest(&signed_event_bytes).into();
    Ok(RhiSignedEvidenceAttestation {
        fence,
        report,
        event_id: *verified.id().as_bytes(),
        signed_event_bytes: signed_event_bytes.into_boxed_slice(),
        signed_event_sha256,
        created_at_unix_seconds: created_at.get(),
    })
}

fn report_reason(
    reason: RhiReconciliationReasonCode,
) -> Result<RadrootsRhiEvidenceReasonCodeV1, RhiReconciliationAttestationError> {
    RadrootsRhiEvidenceReasonCodeV1::parse(reason.code())
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::ReportInvalid))
}

fn sign_plan(
    identity: &RhiDecryptedIdentity,
    plan: &AuthoredEventPlan,
    auxiliary: &[u8; 32],
) -> Result<nostr::Event, RhiReconciliationAttestationError> {
    let kind = u16::try_from(plan.body().kind())
        .map(Kind::Custom)
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::EventPlanInvalid))?;
    let tags = plan
        .body()
        .tags()
        .iter()
        .cloned()
        .map(Tag::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::EventPlanInvalid))?;
    let author = NostrPublicKey::from_hex(identity.public_identity().as_hex())
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::IdentityMismatch))?;
    let unsigned = EventBuilder::new(kind, plan.body().content())
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(plan.created_at()))
        .build(author);
    if unsigned.id.as_ref().map(|event_id| event_id.to_bytes())
        != Some(*plan.expected_event_id().as_bytes())
    {
        return Err(failure(
            RhiReconciliationAttestationErrorKind::EventPlanInvalid,
        ));
    }
    identity
        .sign_nostr_event(unsigned, auxiliary)
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::SigningFailed))
}

fn verify_signed_event(
    plan: &AuthoredEventPlan,
    report: &RadrootsRhiEvidenceReportV1,
    manifest: &radroots_trade::evidence::RadrootsTradeEvidenceManifestV1,
    signed_event_bytes: &[u8],
) -> Result<EventEnvelope, RhiReconciliationAttestationError> {
    let event = verify_signed_event_plan(plan, signed_event_bytes)?;
    let typed = rhi_evidence_attestation_from_event(&event)
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::VerificationFailed))?;
    if typed.canonical_content() != report.canonical_content() {
        return Err(failure(
            RhiReconciliationAttestationErrorKind::VerificationFailed,
        ));
    }
    let reparsed = RadrootsRhiEvidenceReportV1::from_canonical_content(event.content().as_bytes())
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::VerificationFailed))?;
    reparsed
        .validate_against_manifest(manifest)
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::VerificationFailed))?;
    if &reparsed != report {
        return Err(failure(
            RhiReconciliationAttestationErrorKind::VerificationFailed,
        ));
    }
    Ok(event)
}

fn verify_signed_event_plan(
    plan: &AuthoredEventPlan,
    signed_event_bytes: &[u8],
) -> Result<EventEnvelope, RhiReconciliationAttestationError> {
    if signed_event_bytes.is_empty()
        || signed_event_bytes.len() > RHI_RECONCILIATION_SIGNED_ATTESTATION_MAX_BYTES
    {
        return Err(failure(
            RhiReconciliationAttestationErrorKind::VerificationFailed,
        ));
    }
    let source = core::str::from_utf8(signed_event_bytes)
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::VerificationFailed))?;
    let wire = Nip01EventWire::parse_json_unverified_with_limits(source, signed_event_limits())
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::VerificationFailed))?;
    let event = wire
        .into_unverified_envelope()
        .map_err(|_| failure(RhiReconciliationAttestationErrorKind::VerificationFailed))?;
    if verify_id(&event) != Verification::IdVerified || verify(&event) != Verification::Verified {
        return Err(failure(
            RhiReconciliationAttestationErrorKind::VerificationFailed,
        ));
    }
    if event.id().as_bytes() != plan.expected_event_id().as_bytes()
        || event.author().to_hex() != plan.author().to_hex()
        || event.created_at_u64() != plan.created_at()
        || event.kind_u32() != plan.body().kind()
        || event.tags_as_vec() != plan.body().tags()
        || event.content() != plan.body().content()
    {
        return Err(failure(
            RhiReconciliationAttestationErrorKind::VerificationFailed,
        ));
    }
    Ok(event)
}

const fn signed_event_limits() -> EventWireLimits {
    EventWireLimits {
        max_raw_json_bytes: RHI_RECONCILIATION_SIGNED_ATTESTATION_MAX_BYTES,
        max_content_bytes:
            radroots_trade::evidence::RADROOTS_RHI_EVIDENCE_REPORT_MAXIMUM_CANONICAL_BYTES,
        max_tag_count: MAXIMUM_TAGS,
        max_total_tag_elements: MAXIMUM_TAG_ELEMENTS,
        max_tag_element_bytes: MAXIMUM_TAG_ELEMENT_BYTES,
        max_total_tag_bytes: MAXIMUM_TAG_BYTES,
        max_extra_fields: 0,
        max_total_extra_json_bytes: 0,
    }
}

const fn failure(kind: RhiReconciliationAttestationErrorKind) -> RhiReconciliationAttestationError {
    RhiReconciliationAttestationError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED_VECTOR: &str = include_str!(
        "../contracts/conformance/vectors/reconciliation_attestation_signed_event.v1.json"
    );

    fn vector_plan() -> AuthoredEventPlan {
        let value: serde_json::Value = serde_json::from_str(SIGNED_VECTOR).expect("signed vector");
        let content = value["content"].as_str().expect("report content");
        let attestation =
            RadrootsRhiEvidenceAttestationV1::from_canonical_content(content.as_bytes())
                .expect("typed report");
        AuthoredEventPlan::bind(
            AuthoredEventBody::from_rhi_evidence_attestation(&attestation).expect("typed body"),
            value["created_at"].as_u64().expect("authored time"),
            value["pubkey"].as_str().expect("author"),
        )
        .expect("typed plan")
    }

    #[test]
    fn frozen_vector_and_malicious_signer_output_are_independently_verified() {
        let plan = vector_plan();
        verify_signed_event_plan(&plan, SIGNED_VECTOR.trim_end().as_bytes())
            .expect("frozen signed vector");

        let mut wrong_signature: serde_json::Value =
            serde_json::from_str(SIGNED_VECTOR).expect("signed vector");
        wrong_signature["sig"] = serde_json::Value::String("0".repeat(128));
        let bytes = serde_json::to_vec(&wrong_signature).expect("malicious signer wire");
        assert_eq!(
            verify_signed_event_plan(&plan, &bytes)
                .expect_err("malicious signature")
                .kind(),
            RhiReconciliationAttestationErrorKind::VerificationFailed
        );

        let mut wrong_author: serde_json::Value =
            serde_json::from_str(SIGNED_VECTOR).expect("signed vector");
        wrong_author["pubkey"] = serde_json::Value::String("2".repeat(64));
        let bytes = serde_json::to_vec(&wrong_author).expect("wrong-author wire");
        assert_eq!(
            verify_signed_event_plan(&plan, &bytes)
                .expect_err("wrong author")
                .kind(),
            RhiReconciliationAttestationErrorKind::VerificationFailed
        );
    }

    #[test]
    fn every_public_error_class_is_source_free_and_redacted() {
        for kind in [
            RhiReconciliationAttestationErrorKind::InvalidInput,
            RhiReconciliationAttestationErrorKind::IdentityMismatch,
            RhiReconciliationAttestationErrorKind::EntropyUnavailable,
            RhiReconciliationAttestationErrorKind::ReportInvalid,
            RhiReconciliationAttestationErrorKind::EventPlanInvalid,
            RhiReconciliationAttestationErrorKind::SigningFailed,
            RhiReconciliationAttestationErrorKind::VerificationFailed,
            RhiReconciliationAttestationErrorKind::SupersessionInvalid,
        ] {
            let error = failure(kind);
            assert_eq!(error.kind(), kind);
            assert!(error.code().starts_with("reconciliation_attestation_"));
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("11111111"));
            assert!(!rendered.contains("f1a2a41d"));
            assert!(!rendered.contains("1b84c556"));
        }
    }
}
