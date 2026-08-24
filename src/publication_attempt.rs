//! Closed publication target states and bounded attempt evidence.

use core::fmt;
use std::error::Error;

use sha2::{Digest as _, Sha256};

use crate::RhiCommittedPublication;

/// Exact version of the publication-attempt evidence contract.
pub const RHI_PUBLICATION_ATTEMPT_EVIDENCE_CONTRACT_VERSION: u32 = 1;

/// Absolute target ordinal ceiling inherited from the 32-target publication bound.
pub const RHI_PUBLICATION_TARGET_ORDINAL_MAXIMUM: u32 = 31;

/// Absolute durable attempt ceiling inherited from the publication contract.
pub const RHI_PUBLICATION_ATTEMPT_NUMBER_MAXIMUM: u16 = 100;

const ATTEMPT_ID_DOMAIN: &[u8] = b"radroots.rhi.publication_attempt.v1\0";
const MAX_UNIX_MILLISECONDS: u64 = i64::MAX as u64;

/// Stable closed target state retained by the publication workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiPublicationTargetState {
    Pending,
    Submitted,
    Accepted,
    Rejected,
    RateLimited,
    AuthRequired,
    Failed,
    Unknown,
}

impl RhiPublicationTargetState {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::RateLimited => "rate_limited",
            Self::AuthRequired => "auth_required",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }

    /// Reports whether the state is the sole terminal target state.
    #[must_use]
    pub const fn is_accepted_terminal(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

/// Stable closed outcome for one bounded publication attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiPublicationAttemptOutcome {
    Submitted,
    Accepted,
    Rejected,
    RateLimited,
    AuthRequired,
    Failed,
    Unknown,
}

impl RhiPublicationAttemptOutcome {
    /// Returns the exact machine-contract spelling and safe persisted result code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::RateLimited => "rate_limited",
            Self::AuthRequired => "auth_required",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }

    /// Returns the target state represented by this exact observation.
    #[must_use]
    pub const fn target_state(self) -> RhiPublicationTargetState {
        match self {
            Self::Submitted => RhiPublicationTargetState::Submitted,
            Self::Accepted => RhiPublicationTargetState::Accepted,
            Self::Rejected => RhiPublicationTargetState::Rejected,
            Self::RateLimited => RhiPublicationTargetState::RateLimited,
            Self::AuthRequired => RhiPublicationTargetState::AuthRequired,
            Self::Failed => RhiPublicationTargetState::Failed,
            Self::Unknown => RhiPublicationTargetState::Unknown,
        }
    }
}

/// Bounded injected wall-clock value in integer UTC milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RhiPublicationUnixMilliseconds(u64);

impl RhiPublicationUnixMilliseconds {
    /// Validates an injected timestamp against SQLite's signed representation.
    pub fn new(value: u64) -> Result<Self, RhiPublicationAttemptEvidenceError> {
        if value > MAX_UNIX_MILLISECONDS {
            return Err(failure(RhiPublicationAttemptEvidenceErrorKind::InvalidTime));
        }
        Ok(Self(value))
    }

    /// Returns the exact integer UTC millisecond value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Domain-separated identity of one exact outbox-target attempt.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiPublicationAttemptId([u8; 32]);

impl RhiPublicationAttemptId {
    /// Returns the exact identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RhiPublicationAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiPublicationAttemptId([redacted])")
    }
}

/// Sealed bounded evidence for one exact publication attempt.
///
/// Construction binds the immutable committed outbox and event digest to a
/// bounded target ordinal and attempt number. It does not claim the target,
/// persist a Submitted transition, perform relay I/O, or authorize a later
/// durable outcome transition; Step 202 must revalidate those live facts.
///
/// ```compile_fail
/// use rhi::RhiPublicationAttemptEvidence;
///
/// let _forged = RhiPublicationAttemptEvidence { attempt_number: 1 };
/// ```
#[must_use = "publication attempt evidence must be durably reconciled or deliberately discarded"]
pub struct RhiPublicationAttemptEvidence {
    id: RhiPublicationAttemptId,
    outbox_id: crate::RhiPublicationOutboxId,
    event_sha256: [u8; 32],
    target_ordinal: u8,
    attempt_number: u16,
    started_at: RhiPublicationUnixMilliseconds,
    finished_at: RhiPublicationUnixMilliseconds,
    outcome: RhiPublicationAttemptOutcome,
}

impl RhiPublicationAttemptEvidence {
    /// Constructs one bounded observation from the exact committed publication.
    pub fn new(
        publication: &RhiCommittedPublication,
        target_ordinal: u32,
        attempt_number: u16,
        started_at: RhiPublicationUnixMilliseconds,
        finished_at: RhiPublicationUnixMilliseconds,
        outcome: RhiPublicationAttemptOutcome,
    ) -> Result<Self, RhiPublicationAttemptEvidenceError> {
        let target_ordinal = u8::try_from(target_ordinal)
            .ok()
            .filter(|ordinal| u32::from(*ordinal) <= RHI_PUBLICATION_TARGET_ORDINAL_MAXIMUM)
            .ok_or_else(|| failure(RhiPublicationAttemptEvidenceErrorKind::InvalidTargetOrdinal))?;
        if !(1..=RHI_PUBLICATION_ATTEMPT_NUMBER_MAXIMUM).contains(&attempt_number) {
            return Err(failure(
                RhiPublicationAttemptEvidenceErrorKind::InvalidAttemptNumber,
            ));
        }
        if finished_at < started_at {
            return Err(failure(RhiPublicationAttemptEvidenceErrorKind::InvalidTime));
        }
        let outbox_id = publication.outbox_id();
        let event_sha256 = *publication.event_sha256();
        let mut digest = Sha256::new();
        digest.update(ATTEMPT_ID_DOMAIN);
        digest.update(outbox_id.as_bytes());
        digest.update(event_sha256);
        digest.update(u32::from(target_ordinal).to_be_bytes());
        digest.update(u32::from(attempt_number).to_be_bytes());
        Ok(Self {
            id: RhiPublicationAttemptId(digest.finalize().into()),
            outbox_id,
            event_sha256,
            target_ordinal,
            attempt_number,
            started_at,
            finished_at,
            outcome,
        })
    }

    /// Returns the exact domain-separated attempt identity.
    #[must_use]
    pub const fn id(&self) -> RhiPublicationAttemptId {
        self.id
    }

    /// Returns the immutable committed outbox identity.
    #[must_use]
    pub const fn outbox_id(&self) -> crate::RhiPublicationOutboxId {
        self.outbox_id
    }

    /// Returns the digest of the exact committed signed-event bytes.
    #[must_use]
    pub const fn event_sha256(&self) -> &[u8; 32] {
        &self.event_sha256
    }

    /// Returns the bounded zero-based target ordinal.
    #[must_use]
    pub const fn target_ordinal(&self) -> u8 {
        self.target_ordinal
    }

    /// Returns the bounded one-based attempt number.
    #[must_use]
    pub const fn attempt_number(&self) -> u16 {
        self.attempt_number
    }

    /// Returns the injected attempt start time.
    #[must_use]
    pub const fn started_at(&self) -> RhiPublicationUnixMilliseconds {
        self.started_at
    }

    /// Returns the injected attempt finish time.
    #[must_use]
    pub const fn finished_at(&self) -> RhiPublicationUnixMilliseconds {
        self.finished_at
    }

    /// Returns the closed observed outcome.
    #[must_use]
    pub const fn outcome(&self) -> RhiPublicationAttemptOutcome {
        self.outcome
    }

    /// Returns the sole safe persisted result code for this outcome.
    #[must_use]
    pub const fn result_code(&self) -> &'static str {
        self.outcome.code()
    }
}

impl fmt::Debug for RhiPublicationAttemptEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPublicationAttemptEvidence")
            .field("identity", &"[redacted]")
            .field("target_ordinal", &self.target_ordinal)
            .field("attempt_number", &self.attempt_number)
            .field("started_at", &self.started_at)
            .field("finished_at", &self.finished_at)
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Stable source-free attempt-evidence failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiPublicationAttemptEvidenceErrorKind {
    InvalidTargetOrdinal,
    InvalidAttemptNumber,
    InvalidTime,
}

impl RhiPublicationAttemptEvidenceErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidTargetOrdinal => "publication_attempt_target_ordinal_invalid",
            Self::InvalidAttemptNumber => "publication_attempt_number_invalid",
            Self::InvalidTime => "publication_attempt_time_invalid",
        }
    }
}

/// Redacted source-free attempt-evidence failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiPublicationAttemptEvidenceError {
    kind: RhiPublicationAttemptEvidenceErrorKind,
}

impl RhiPublicationAttemptEvidenceError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiPublicationAttemptEvidenceErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiPublicationAttemptEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiPublicationAttemptEvidenceErrorKind::InvalidTargetOrdinal => {
                "RHI publication attempt target ordinal is invalid"
            }
            RhiPublicationAttemptEvidenceErrorKind::InvalidAttemptNumber => {
                "RHI publication attempt number is invalid"
            }
            RhiPublicationAttemptEvidenceErrorKind::InvalidTime => {
                "RHI publication attempt time is invalid"
            }
        })
    }
}

impl fmt::Debug for RhiPublicationAttemptEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPublicationAttemptEvidenceError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiPublicationAttemptEvidenceError {}

const fn failure(
    kind: RhiPublicationAttemptEvidenceErrorKind,
) -> RhiPublicationAttemptEvidenceError {
    RhiPublicationAttemptEvidenceError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publication() -> RhiCommittedPublication {
        RhiCommittedPublication::test_fixture(
            crate::RhiPublicationOutboxId::from_committed_bytes([0x11; 32]),
            [0x44; 32],
            [0x22; 32],
            vec![0x33].into_boxed_slice(),
        )
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(DIGITS[usize::from(byte >> 4)]));
            output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        output
    }

    #[test]
    fn states_and_outcomes_are_exact() {
        let states = [
            RhiPublicationTargetState::Pending,
            RhiPublicationTargetState::Submitted,
            RhiPublicationTargetState::Accepted,
            RhiPublicationTargetState::Rejected,
            RhiPublicationTargetState::RateLimited,
            RhiPublicationTargetState::AuthRequired,
            RhiPublicationTargetState::Failed,
            RhiPublicationTargetState::Unknown,
        ];
        assert_eq!(
            states.map(RhiPublicationTargetState::code),
            [
                "pending",
                "submitted",
                "accepted",
                "rejected",
                "rate_limited",
                "auth_required",
                "failed",
                "unknown",
            ]
        );
        assert!(RhiPublicationTargetState::Accepted.is_accepted_terminal());
        for state in states {
            assert_eq!(state.is_accepted_terminal(), state.code() == "accepted");
        }
        let outcomes = [
            RhiPublicationAttemptOutcome::Submitted,
            RhiPublicationAttemptOutcome::Accepted,
            RhiPublicationAttemptOutcome::Rejected,
            RhiPublicationAttemptOutcome::RateLimited,
            RhiPublicationAttemptOutcome::AuthRequired,
            RhiPublicationAttemptOutcome::Failed,
            RhiPublicationAttemptOutcome::Unknown,
        ];
        assert_eq!(
            outcomes.map(RhiPublicationAttemptOutcome::code),
            [
                "submitted",
                "accepted",
                "rejected",
                "rate_limited",
                "auth_required",
                "failed",
                "unknown",
            ]
        );
        for outcome in outcomes {
            assert_eq!(outcome.code(), outcome.target_state().code());
        }
    }

    #[test]
    fn time_and_error_boundaries_are_safe() {
        assert_eq!(RhiPublicationUnixMilliseconds::new(0).unwrap().get(), 0);
        assert_eq!(
            RhiPublicationUnixMilliseconds::new(MAX_UNIX_MILLISECONDS)
                .unwrap()
                .get(),
            MAX_UNIX_MILLISECONDS
        );
        let error = RhiPublicationUnixMilliseconds::new(MAX_UNIX_MILLISECONDS + 1)
            .expect_err("oversized time");
        assert_eq!(
            error.kind(),
            RhiPublicationAttemptEvidenceErrorKind::InvalidTime
        );
        for kind in [
            RhiPublicationAttemptEvidenceErrorKind::InvalidTargetOrdinal,
            RhiPublicationAttemptEvidenceErrorKind::InvalidAttemptNumber,
            RhiPublicationAttemptEvidenceErrorKind::InvalidTime,
        ] {
            let error = failure(kind);
            assert!(error.code().starts_with("publication_attempt_"));
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("relay-primary"));
            assert!(!rendered.contains("secret"));
        }
    }

    #[test]
    fn attempt_evidence_binds_exact_maximum_fields_and_closed_result() {
        let started_at = RhiPublicationUnixMilliseconds::new(42).unwrap();
        let finished_at = RhiPublicationUnixMilliseconds::new(43).unwrap();
        let evidence = RhiPublicationAttemptEvidence::new(
            &publication(),
            RHI_PUBLICATION_TARGET_ORDINAL_MAXIMUM,
            RHI_PUBLICATION_ATTEMPT_NUMBER_MAXIMUM,
            started_at,
            finished_at,
            RhiPublicationAttemptOutcome::RateLimited,
        )
        .expect("maximum evidence");
        assert_eq!(
            lower_hex(evidence.id().as_bytes()),
            "e1acaadff3f4d52ca7e9a8d14026039827bf8386ebb66551402dfd1d7309899c"
        );
        assert_eq!(
            evidence.outbox_id().as_bytes(),
            crate::RhiPublicationOutboxId::from_committed_bytes([0x11; 32]).as_bytes()
        );
        assert_eq!(evidence.event_sha256(), &[0x22; 32]);
        assert_eq!(evidence.target_ordinal(), 31);
        assert_eq!(evidence.attempt_number(), 100);
        assert_eq!(evidence.started_at(), started_at);
        assert_eq!(evidence.finished_at(), finished_at);
        assert_eq!(
            evidence.outcome(),
            RhiPublicationAttemptOutcome::RateLimited
        );
        assert_eq!(evidence.result_code(), "rate_limited");
        let rendered = format!("{evidence:?} {:?}", evidence.id());
        assert!(!rendered.contains(&lower_hex(evidence.id().as_bytes())));
        assert!(!rendered.contains("relay-primary"));
        assert!(!rendered.contains("3333"));
    }

    #[test]
    fn attempt_evidence_rejects_each_invalid_boundary() {
        let started_at = RhiPublicationUnixMilliseconds::new(42).unwrap();
        let finished_at = RhiPublicationUnixMilliseconds::new(43).unwrap();
        let cases = [
            (
                32,
                1,
                started_at,
                finished_at,
                RhiPublicationAttemptEvidenceErrorKind::InvalidTargetOrdinal,
            ),
            (
                0,
                0,
                started_at,
                finished_at,
                RhiPublicationAttemptEvidenceErrorKind::InvalidAttemptNumber,
            ),
            (
                0,
                101,
                started_at,
                finished_at,
                RhiPublicationAttemptEvidenceErrorKind::InvalidAttemptNumber,
            ),
            (
                0,
                1,
                finished_at,
                started_at,
                RhiPublicationAttemptEvidenceErrorKind::InvalidTime,
            ),
        ];
        for (ordinal, attempt, start, finish, expected) in cases {
            assert_eq!(
                RhiPublicationAttemptEvidence::new(
                    &publication(),
                    ordinal,
                    attempt,
                    start,
                    finish,
                    RhiPublicationAttemptOutcome::Unknown,
                )
                .expect_err("invalid evidence")
                .kind(),
                expected
            );
        }
    }
}
