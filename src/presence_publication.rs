//! Exact signed presence documents and durable target delivery.

use core::fmt;
use std::error::Error;

use nostr::{EventBuilder, Kind, PublicKey as NostrPublicKey, Tag, Timestamp};
use radroots_event::{
    GenericEventDraft,
    envelope::{EventEnvelope, kind::KIND_APPLICATION_HANDLER},
    profile::AuthoredProfile,
    wire::{EventWireLimits, Nip01EventWire},
};
use radroots_event_codec::authoring::AuthoredEventPlan;
use radroots_nostr::event::{
    ApplicationHandlerSpec, Verification, build_application_handler, verify, verify_id,
};
use radroots_service_host::{EntropySource, UnixTimeSeconds};
use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use radroots_transport::BoxFuture;
use sha2::{Digest as _, Sha256};
use sqlx::Row as _;
use zeroize::Zeroizing;

use crate::{
    RHI_PRESENCE_DESIRED_MAX_TARGETS, RhiDecryptedIdentity, RhiJitterBoundMilliseconds,
    RhiPresenceDesiredAuthority, RhiPresenceDesiredCommitOutcome, RhiPresenceDesiredMode,
    RhiPresenceDesiredState, RhiPresenceDocumentKind, RhiPresenceOutboxRepository,
    RhiPresenceTarget, RhiRuntimeAdapterErrorKind, RhiStateHostMode, RhiTimeEntropyAdapters,
    presence_desired::presence_authority_matches_state,
};

/// Exact version of the signed presence and delivery contract.
pub const RHI_PRESENCE_PUBLICATION_CONTRACT_VERSION: u32 = 1;
/// Maximum canonical bytes retained for one signed presence event.
pub const RHI_PRESENCE_SIGNED_EVENT_MAX_BYTES: usize = 32 * 1024;
/// Maximum durable attempts for one presence target.
pub const RHI_PRESENCE_MAX_ATTEMPTS: u16 = 100;

const PROFILE_NAME: &str = "rhi";
const PROFILE_DISPLAY_NAME: &str = "Radroots RHI";
const PROFILE_ABOUT: &str = "Radroots evidence reconciliation and attestation service";
const APPLICATION_HANDLER_IDENTIFIER: &str = "rhi";
const APPLICATION_HANDLER_KINDS: [u32; 1] = [3441];
const INITIAL_BACKOFF_MILLISECONDS: u64 = 250;
const MAXIMUM_BACKOFF_MILLISECONDS: u64 = 30_000;
const ATTEMPT_DEADLINE_MILLISECONDS: u64 = 15_000;
const MAX_UNIX_MILLISECONDS: u64 = i64::MAX as u64;
const OUTBOX_ID_DOMAIN: &[u8] = b"radroots.rhi.presence_outbox.v1\0";
const ATTEMPT_ID_DOMAIN: &[u8] = b"radroots.rhi.presence_attempt.v1\0";

const READ_DESIRED_BINDING_SQL: &str = r#"SELECT singleton, generation, enabled,
    profile, application_handler,
    CASE WHEN typeof(target_set_sha256) = 'blob' AND length(target_set_sha256) = 32
        THEN target_set_sha256 ELSE NULL END AS target_set_sha256,
    target_count, required_target_count, queue_capacity,
    CASE WHEN typeof(desired_sha256) = 'blob' AND length(desired_sha256) = 32
        THEN desired_sha256 ELSE NULL END AS desired_sha256
FROM presence_desired_state
LIMIT 2"#;

const READ_GENERATION_OUTBOX_SQL: &str = r#"SELECT
    CASE WHEN typeof(outbox_id) = 'blob' AND length(outbox_id) = 32
        THEN outbox_id ELSE NULL END AS outbox_id,
    desired_generation,
    length(CAST(document_kind AS BLOB)) AS document_kind_bytes,
    substr(document_kind, 1, 20) AS document_kind,
    CASE WHEN typeof(desired_sha256) = 'blob' AND length(desired_sha256) = 32
        THEN desired_sha256 ELSE NULL END AS desired_sha256,
    CASE WHEN typeof(target_set_sha256) = 'blob' AND length(target_set_sha256) = 32
        THEN target_set_sha256 ELSE NULL END AS target_set_sha256,
    CASE WHEN typeof(event_id) = 'blob' AND length(event_id) = 32
        THEN event_id ELSE NULL END AS event_id,
    CASE WHEN typeof(event_sha256) = 'blob' AND length(event_sha256) = 32
        THEN event_sha256 ELSE NULL END AS event_sha256,
    length(exact_signed_event_bytes) AS exact_signed_event_bytes_length,
    substr(exact_signed_event_bytes, 1, 32769) AS exact_signed_event_bytes,
    authored_at_unix_s,
    length(CAST(service_public_key AS BLOB)) AS service_public_key_bytes,
    substr(service_public_key, 1, 65) AS service_public_key,
    target_count, required_target_count, max_attempts,
    initial_backoff_ms, maximum_backoff_ms, attempt_deadline_ms,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 11) AS state,
    revision, next_attempt_unix_ms,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE length(lease_owner) END AS lease_owner_bytes,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE substr(lease_owner, 1, 17) END AS lease_owner,
    lease_expires_unix_ms, created_at_unix_ms, updated_at_unix_ms
FROM presence_outbox
WHERE desired_generation = ?
ORDER BY CASE document_kind
    WHEN 'service_profile' THEN 0
    WHEN 'application_handler' THEN 1
    ELSE 2 END
LIMIT 3"#;

const READ_OUTBOX_SQL: &str = r#"SELECT
    CASE WHEN typeof(outbox_id) = 'blob' AND length(outbox_id) = 32
        THEN outbox_id ELSE NULL END AS outbox_id,
    desired_generation,
    length(CAST(document_kind AS BLOB)) AS document_kind_bytes,
    substr(document_kind, 1, 20) AS document_kind,
    CASE WHEN typeof(desired_sha256) = 'blob' AND length(desired_sha256) = 32
        THEN desired_sha256 ELSE NULL END AS desired_sha256,
    CASE WHEN typeof(target_set_sha256) = 'blob' AND length(target_set_sha256) = 32
        THEN target_set_sha256 ELSE NULL END AS target_set_sha256,
    CASE WHEN typeof(event_id) = 'blob' AND length(event_id) = 32
        THEN event_id ELSE NULL END AS event_id,
    CASE WHEN typeof(event_sha256) = 'blob' AND length(event_sha256) = 32
        THEN event_sha256 ELSE NULL END AS event_sha256,
    length(exact_signed_event_bytes) AS exact_signed_event_bytes_length,
    substr(exact_signed_event_bytes, 1, 32769) AS exact_signed_event_bytes,
    authored_at_unix_s,
    length(CAST(service_public_key AS BLOB)) AS service_public_key_bytes,
    substr(service_public_key, 1, 65) AS service_public_key,
    target_count, required_target_count, max_attempts,
    initial_backoff_ms, maximum_backoff_ms, attempt_deadline_ms,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 11) AS state,
    revision, next_attempt_unix_ms,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE length(lease_owner) END AS lease_owner_bytes,
    CASE WHEN lease_owner IS NULL THEN NULL ELSE substr(lease_owner, 1, 17) END AS lease_owner,
    lease_expires_unix_ms, created_at_unix_ms, updated_at_unix_ms
FROM presence_outbox
WHERE outbox_id = ?
LIMIT 2"#;

const READ_CLAIMABLE_OUTBOX_SQL: &str = r#"SELECT
    CASE WHEN typeof(outbox.outbox_id) = 'blob' AND length(outbox.outbox_id) = 32
        THEN outbox.outbox_id ELSE NULL END AS outbox_id
FROM presence_outbox AS outbox
JOIN presence_desired_state AS desired
  ON desired.singleton = 1
 AND desired.generation = outbox.desired_generation
 AND desired.desired_sha256 = outbox.desired_sha256
WHERE outbox.state = 'pending' AND outbox.next_attempt_unix_ms <= ?
ORDER BY outbox.next_attempt_unix_ms, outbox.created_at_unix_ms,
         CASE outbox.document_kind
             WHEN 'service_profile' THEN 0
             WHEN 'application_handler' THEN 1
             ELSE 2 END,
         outbox.outbox_id
LIMIT 1"#;

const READ_EXPIRED_OUTBOX_SQL: &str = r#"SELECT
    CASE WHEN typeof(outbox_id) = 'blob' AND length(outbox_id) = 32
        THEN outbox_id ELSE NULL END AS outbox_id
FROM presence_outbox
WHERE state = 'leased' AND lease_expires_unix_ms <= ?
ORDER BY lease_expires_unix_ms, created_at_unix_ms, document_kind, outbox_id
LIMIT 1"#;

const READ_TARGETS_SQL: &str = r#"SELECT target_ordinal,
    length(CAST(relay_id AS BLOB)) AS relay_id_bytes,
    substr(relay_id, 1, 65) AS relay_id, required,
    length(CAST(state AS BLOB)) AS state_bytes, substr(state, 1, 14) AS state,
    revision, attempt_count, next_attempt_unix_ms,
    CASE WHEN last_attempt_id IS NULL THEN NULL ELSE length(last_attempt_id) END
        AS last_attempt_id_bytes,
    CASE WHEN last_attempt_id IS NULL THEN NULL ELSE substr(last_attempt_id, 1, 33) END
        AS last_attempt_id,
    updated_at_unix_ms
FROM presence_targets
WHERE outbox_id = ?
ORDER BY target_ordinal
LIMIT 33"#;

const INSERT_OUTBOX_SQL: &str = r#"INSERT INTO presence_outbox (
    outbox_id, desired_generation, document_kind, desired_sha256,
    target_set_sha256, event_id, event_sha256, exact_signed_event_bytes,
    authored_at_unix_s, service_public_key, target_count, required_target_count,
    max_attempts, initial_backoff_ms, maximum_backoff_ms, attempt_deadline_ms,
    state, revision, next_attempt_unix_ms, lease_owner, lease_expires_unix_ms,
    created_at_unix_ms, updated_at_unix_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 100, 250, 30000, 15000,
          'pending', 1, ?, NULL, NULL, ?, ?)"#;

const INSERT_TARGET_SQL: &str = r#"INSERT INTO presence_targets (
    outbox_id, target_ordinal, relay_id, required, state, revision,
    attempt_count, next_attempt_unix_ms, last_attempt_id, updated_at_unix_ms
) VALUES (?, ?, ?, ?, 'pending', 1, 0, ?, NULL, ?)"#;

const SUPERSEDE_OUTBOX_SQL: &str = r#"UPDATE presence_outbox
SET state = 'superseded', revision = revision + 1,
    next_attempt_unix_ms = NULL, lease_owner = NULL,
    lease_expires_unix_ms = NULL, updated_at_unix_ms = ?
WHERE desired_generation != ? AND state IN ('pending', 'blocked')
  AND updated_at_unix_ms <= ?"#;

const COUNT_STALE_LEASES_SQL: &str = r#"SELECT COUNT(*) AS lease_count
FROM presence_outbox
WHERE desired_generation != ? AND state = 'leased'"#;

const READ_MAX_AUTHORED_SQL: &str = r#"SELECT MAX(authored_at_unix_s) AS authored_at_unix_s
FROM presence_outbox WHERE document_kind = ?"#;

const CLAIM_OUTBOX_SQL: &str = r#"UPDATE presence_outbox
SET state = 'leased', revision = revision + 1,
    next_attempt_unix_ms = NULL, lease_owner = ?, lease_expires_unix_ms = ?,
    updated_at_unix_ms = ?
WHERE outbox_id = ? AND revision = ? AND state = 'pending'
  AND next_attempt_unix_ms <= ? AND updated_at_unix_ms <= ?"#;

const PREPARE_TARGET_SQL: &str = r#"UPDATE presence_targets
SET state = 'submitted', revision = revision + 1,
    attempt_count = attempt_count + 1, next_attempt_unix_ms = NULL,
    last_attempt_id = ?, updated_at_unix_ms = ?
WHERE outbox_id = ? AND target_ordinal = ? AND revision = ?
  AND state IN ('pending', 'failed', 'rate_limited', 'unknown')
  AND attempt_count < ? AND next_attempt_unix_ms <= ?
  AND updated_at_unix_ms <= ?"#;

const INSERT_ATTEMPT_SQL: &str = r#"INSERT INTO presence_attempts (
    attempt_id, outbox_id, target_ordinal, attempt_number, event_sha256,
    lease_owner, started_at_unix_ms, finished_at_unix_ms, outcome, result_code
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#;

const READ_ATTEMPT_SQL: &str = r#"SELECT
    CASE WHEN typeof(attempt_id) = 'blob' AND length(attempt_id) = 32
        THEN attempt_id ELSE NULL END AS attempt_id,
    CASE WHEN typeof(outbox_id) = 'blob' AND length(outbox_id) = 32
        THEN outbox_id ELSE NULL END AS outbox_id,
    target_ordinal, attempt_number,
    CASE WHEN typeof(event_sha256) = 'blob' AND length(event_sha256) = 32
        THEN event_sha256 ELSE NULL END AS event_sha256,
    CASE WHEN typeof(lease_owner) = 'blob' AND length(lease_owner) = 16
        THEN lease_owner ELSE NULL END AS lease_owner,
    started_at_unix_ms, finished_at_unix_ms,
    length(CAST(outcome AS BLOB)) AS outcome_bytes, substr(outcome, 1, 14) AS outcome,
    length(CAST(result_code AS BLOB)) AS result_code_bytes,
    substr(result_code, 1, 65) AS result_code
FROM presence_attempts
WHERE attempt_id = ?
LIMIT 2"#;

const UPDATE_TARGET_OUTCOME_SQL: &str = r#"UPDATE presence_targets
SET state = ?, revision = revision + 1, next_attempt_unix_ms = ?,
    updated_at_unix_ms = ?
WHERE outbox_id = ? AND target_ordinal = ? AND revision = ?
  AND state = 'submitted' AND attempt_count = ? AND last_attempt_id = ?"#;

const UPDATE_OUTBOX_AFTER_ATTEMPT_SQL: &str = r#"UPDATE presence_outbox
SET state = ?, revision = revision + 1, next_attempt_unix_ms = ?,
    lease_owner = NULL, lease_expires_unix_ms = NULL, updated_at_unix_ms = ?
WHERE outbox_id = ? AND revision = ? AND state = 'leased'
  AND lease_owner = ? AND lease_expires_unix_ms = ?
  AND lease_expires_unix_ms > ? AND updated_at_unix_ms <= ?"#;

const UPDATE_OUTBOX_RECOVERY_SQL: &str = r#"UPDATE presence_outbox
SET state = ?, revision = revision + 1, next_attempt_unix_ms = ?,
    lease_owner = NULL, lease_expires_unix_ms = NULL, updated_at_unix_ms = ?
WHERE outbox_id = ? AND revision = ? AND state = 'leased'
  AND lease_owner = ? AND lease_expires_unix_ms = ?
  AND lease_expires_unix_ms <= ? AND updated_at_unix_ms <= ?"#;

/// Stable source-free signed-presence and delivery failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiPresencePublicationErrorKind {
    InvalidMode,
    InvalidInput,
    DesiredStateMismatch,
    IdentityMismatch,
    EntropyUnavailable,
    RenderingFailed,
    VerificationFailed,
    NotReady,
    LeaseLost,
    Invariant,
    ClockUnavailable,
    Storage,
    CommitOutcomeUnknown,
}

impl RhiPresencePublicationErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidMode => "presence_publication_mode_invalid",
            Self::InvalidInput => "presence_publication_input_invalid",
            Self::DesiredStateMismatch => "presence_publication_desired_state_mismatch",
            Self::IdentityMismatch => "presence_publication_identity_mismatch",
            Self::EntropyUnavailable => "presence_publication_entropy_unavailable",
            Self::RenderingFailed => "presence_publication_rendering_failed",
            Self::VerificationFailed => "presence_publication_verification_failed",
            Self::NotReady => "presence_publication_not_ready",
            Self::LeaseLost => "presence_publication_lease_lost",
            Self::Invariant => "presence_publication_invariant_failed",
            Self::ClockUnavailable => "presence_publication_clock_unavailable",
            Self::Storage => "presence_publication_storage_failed",
            Self::CommitOutcomeUnknown => "presence_publication_commit_outcome_unknown",
        }
    }
}

/// Redacted source-free signed-presence and delivery failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiPresencePublicationError {
    kind: RhiPresencePublicationErrorKind,
}

impl RhiPresencePublicationError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiPresencePublicationErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiPresencePublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiPresencePublicationErrorKind::InvalidMode => {
                "RHI presence publication requires writable state"
            }
            RhiPresencePublicationErrorKind::InvalidInput => {
                "RHI presence publication input is invalid"
            }
            RhiPresencePublicationErrorKind::DesiredStateMismatch => {
                "RHI presence publication desired state does not match"
            }
            RhiPresencePublicationErrorKind::IdentityMismatch => {
                "RHI presence publication identity does not match"
            }
            RhiPresencePublicationErrorKind::EntropyUnavailable => {
                "RHI presence publication entropy is unavailable"
            }
            RhiPresencePublicationErrorKind::RenderingFailed => {
                "RHI presence publication rendering failed"
            }
            RhiPresencePublicationErrorKind::VerificationFailed => {
                "RHI presence publication verification failed"
            }
            RhiPresencePublicationErrorKind::NotReady => "RHI presence work is not ready",
            RhiPresencePublicationErrorKind::LeaseLost => {
                "RHI presence publication lease is no longer authoritative"
            }
            RhiPresencePublicationErrorKind::Invariant => {
                "RHI presence publication state invariant failed"
            }
            RhiPresencePublicationErrorKind::ClockUnavailable => {
                "RHI presence publication clock is unavailable"
            }
            RhiPresencePublicationErrorKind::Storage => {
                "RHI presence publication transaction failed"
            }
            RhiPresencePublicationErrorKind::CommitOutcomeUnknown => {
                "RHI presence publication commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for RhiPresencePublicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPresencePublicationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiPresencePublicationError {}

/// One independently verified exact signed presence document.
pub struct RhiSignedPresenceDocument {
    kind: RhiPresenceDocumentKind,
    event_id: [u8; 32],
    signed_event_sha256: [u8; 32],
    signed_event_bytes: Box<[u8]>,
    created_at_unix_seconds: u64,
}

impl RhiSignedPresenceDocument {
    /// Returns the closed document kind.
    #[must_use]
    pub const fn kind(&self) -> RhiPresenceDocumentKind {
        self.kind
    }

    /// Returns the independently verified NIP-01 event identifier.
    #[must_use]
    pub const fn event_id(&self) -> &[u8; 32] {
        &self.event_id
    }

    /// Returns the digest of the exact retained bytes.
    #[must_use]
    pub const fn signed_event_sha256(&self) -> &[u8; 32] {
        &self.signed_event_sha256
    }

    /// Returns the exact canonical signed bytes.
    #[must_use]
    pub fn signed_event_bytes(&self) -> &[u8] {
        &self.signed_event_bytes
    }

    /// Returns the injected authored timestamp.
    #[must_use]
    pub const fn created_at_unix_seconds(&self) -> u64 {
        self.created_at_unix_seconds
    }
}

impl fmt::Debug for RhiSignedPresenceDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiSignedPresenceDocument")
            .field("kind", &self.kind)
            .field("signed_event_bytes", &self.signed_event_bytes.len())
            .finish_non_exhaustive()
    }
}

/// Sealed exact document set bound to one committed desired-state generation.
pub struct RhiSignedPresenceDocuments {
    desired_state: RhiPresenceDesiredState,
    service_public_key: Box<str>,
    targets: Box<[RhiPresenceTarget]>,
    documents: Box<[RhiSignedPresenceDocument]>,
}

impl RhiSignedPresenceDocuments {
    /// Returns the exact committed desired state.
    #[must_use]
    pub const fn desired_state(&self) -> RhiPresenceDesiredState {
        self.desired_state
    }

    /// Returns the exact ordered signed-document inventory.
    #[must_use]
    pub fn documents(&self) -> &[RhiSignedPresenceDocument] {
        &self.documents
    }

    /// Returns the stable target count without exposing endpoints.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    fn retained_copy(&self) -> Self {
        Self {
            desired_state: self.desired_state,
            service_public_key: self.service_public_key.clone(),
            targets: self.targets.clone(),
            documents: self
                .documents
                .iter()
                .map(|document| RhiSignedPresenceDocument {
                    kind: document.kind,
                    event_id: document.event_id,
                    signed_event_sha256: document.signed_event_sha256,
                    signed_event_bytes: document.signed_event_bytes.clone(),
                    created_at_unix_seconds: document.created_at_unix_seconds,
                })
                .collect(),
        }
    }
}

impl fmt::Debug for RhiSignedPresenceDocuments {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiSignedPresenceDocuments")
            .field("desired_generation", &self.desired_state.generation())
            .field("document_count", &self.documents.len())
            .field("target_count", &self.targets.len())
            .finish_non_exhaustive()
    }
}

/// Opaque identity of one exact durable presence outbox.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiPresenceOutboxId([u8; 32]);

impl RhiPresenceOutboxId {
    /// Returns the exact identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RhiPresenceOutboxId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiPresenceOutboxId([redacted])")
    }
}

/// Opaque identity of one durable presence attempt.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiPresenceAttemptId([u8; 32]);

impl RhiPresenceAttemptId {
    /// Returns the exact identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RhiPresenceAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiPresenceAttemptId([redacted])")
    }
}

/// Bounded wall-clock instant in whole Unix milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RhiPresenceUnixMilliseconds(u64);

impl RhiPresenceUnixMilliseconds {
    /// Validates one injected instant against SQLite's signed representation.
    pub fn new(value: u64) -> Result<Self, RhiPresencePublicationError> {
        if value > MAX_UNIX_MILLISECONDS {
            return Err(failure(RhiPresencePublicationErrorKind::InvalidInput));
        }
        Ok(Self(value))
    }

    /// Returns the exact instant.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Bounded caller-injected retry delay in whole milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RhiPresenceRetryDelayMilliseconds(u64);

impl RhiPresenceRetryDelayMilliseconds {
    /// Validates one delay against the absolute retry ceiling.
    pub fn new(value: u64) -> Result<Self, RhiPresencePublicationError> {
        if value > MAXIMUM_BACKOFF_MILLISECONDS {
            return Err(failure(RhiPresencePublicationErrorKind::InvalidInput));
        }
        Ok(Self(value))
    }

    /// Returns the exact delay.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable process-local owner token for one compare-and-swap lease.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiPresenceLeaseOwner([u8; 16]);

impl RhiPresenceLeaseOwner {
    /// Validates one injected nonzero owner token.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, RhiPresencePublicationError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(failure(RhiPresencePublicationErrorKind::InvalidInput));
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for RhiPresenceLeaseOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiPresenceLeaseOwner([redacted])")
    }
}

/// Stable durable presence-outbox lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiPresenceOutboxState {
    Pending,
    Leased,
    Complete,
    Blocked,
    Superseded,
}

impl RhiPresenceOutboxState {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Complete => "complete",
            Self::Blocked => "blocked",
            Self::Superseded => "superseded",
        }
    }
}

/// Stable durable per-target presence state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiPresenceTargetState {
    Pending,
    Submitted,
    Accepted,
    Rejected,
    RateLimited,
    AuthRequired,
    Failed,
    Unknown,
}

impl RhiPresenceTargetState {
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
}

/// Closed result observed from one exact-byte relay submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiPresenceAttemptOutcome {
    Submitted,
    Accepted,
    Rejected,
    RateLimited,
    AuthRequired,
    Failed,
    Unknown,
}

impl RhiPresenceAttemptOutcome {
    /// Returns the exact machine-contract spelling.
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
}

/// Confirmed result of committing one complete signed presence generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiPresenceCommitOutcome {
    desired_state: RhiPresenceDesiredState,
    document_count: u8,
    changed: bool,
}

impl RhiPresenceCommitOutcome {
    /// Returns the exact committed desired-state identity.
    #[must_use]
    pub const fn desired_state(self) -> RhiPresenceDesiredState {
        self.desired_state
    }

    /// Returns the exact committed document count.
    #[must_use]
    pub const fn document_count(self) -> u8 {
        self.document_count
    }

    /// Reports whether any durable presence workflow state changed.
    #[must_use]
    pub const fn changed(self) -> bool {
        self.changed
    }
}

/// Non-forgeable compare-and-swap authority for one claimed presence outbox.
#[derive(PartialEq, Eq)]
pub struct RhiPresenceLease {
    outbox: PresenceOutboxRecord,
    owner: RhiPresenceLeaseOwner,
    expires_at: RhiPresenceUnixMilliseconds,
}

impl RhiPresenceLease {
    /// Returns the exact claimed outbox identity.
    #[must_use]
    pub const fn outbox_id(&self) -> RhiPresenceOutboxId {
        self.outbox.id
    }

    /// Returns the exact lease expiry.
    #[must_use]
    pub const fn expires_at(&self) -> RhiPresenceUnixMilliseconds {
        self.expires_at
    }
}

impl fmt::Debug for RhiPresenceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPresenceLease")
            .field("identity", &"[redacted]")
            .field("revision", &self.outbox.revision)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Exact signed bytes exposed only after durable Submitted state exists.
#[must_use = "prepared presence must be executed exactly or left for unknown recovery"]
pub struct RhiPreparedPresenceAttempt {
    lease: RhiPresenceLease,
    target: PresenceTargetRecord,
    attempt_id: RhiPresenceAttemptId,
    started_at: RhiPresenceUnixMilliseconds,
    deadline_at: RhiPresenceUnixMilliseconds,
    exact_signed_event_bytes: Box<[u8]>,
}

impl RhiPreparedPresenceAttempt {
    /// Returns the exact attempt identity.
    #[must_use]
    pub const fn attempt_id(&self) -> RhiPresenceAttemptId {
        self.attempt_id
    }

    /// Returns the stable relay identity without an endpoint or secret.
    #[must_use]
    pub fn relay_id(&self) -> &str {
        &self.target.relay_id
    }

    /// Returns the original committed bytes with no transformation.
    #[must_use]
    pub const fn exact_signed_event_bytes(&self) -> &[u8] {
        &self.exact_signed_event_bytes
    }

    /// Returns the absolute attempt deadline.
    #[must_use]
    pub const fn deadline_at(&self) -> RhiPresenceUnixMilliseconds {
        self.deadline_at
    }

    /// Returns the one-based durable attempt number.
    #[must_use]
    pub const fn attempt_number(&self) -> u16 {
        self.target.attempt_count
    }

    fn retry_upper_bound(&self) -> u64 {
        retry_upper_bound(self.target.attempt_count)
    }
}

impl fmt::Debug for RhiPreparedPresenceAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPreparedPresenceAttempt")
            .field("identity", &"[redacted]")
            .field("target_ordinal", &self.target.ordinal)
            .field("attempt_number", &self.target.attempt_count)
            .field("deadline_at", &self.deadline_at)
            .finish()
    }
}

/// Closed exact-byte transport boundary for durable presence delivery.
pub trait RhiExactPresenceSink: Send + Sync {
    /// Submits the exact retained payload and returns one closed observation.
    fn submit_exact<'a>(
        &'a self,
        attempt: &'a RhiPreparedPresenceAttempt,
    ) -> BoxFuture<'a, RhiPresenceAttemptOutcome>;
}

/// Confirmed durable result for one exact presence attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiPresenceAttemptCommit {
    outbox_id: RhiPresenceOutboxId,
    attempt_id: RhiPresenceAttemptId,
    target_ordinal: u8,
    attempt_number: u16,
    outcome: RhiPresenceAttemptOutcome,
    target_state: RhiPresenceTargetState,
    outbox_state: RhiPresenceOutboxState,
}

impl RhiPresenceAttemptCommit {
    #[must_use]
    pub const fn outbox_id(self) -> RhiPresenceOutboxId {
        self.outbox_id
    }

    #[must_use]
    pub const fn attempt_id(self) -> RhiPresenceAttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn target_ordinal(self) -> u8 {
        self.target_ordinal
    }

    #[must_use]
    pub const fn attempt_number(self) -> u16 {
        self.attempt_number
    }

    #[must_use]
    pub const fn outcome(self) -> RhiPresenceAttemptOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn target_state(self) -> RhiPresenceTargetState {
        self.target_state
    }

    #[must_use]
    pub const fn outbox_state(self) -> RhiPresenceOutboxState {
        self.outbox_state
    }
}

/// Builds, signs, and independently revalidates one complete desired document set.
///
/// Exactly 32 entropy bytes are consumed per enabled document. No clock,
/// persistence, relay, task, or network authority is acquired implicitly.
pub fn build_rhi_signed_presence_documents(
    desired: RhiPresenceDesiredCommitOutcome,
    authority: &RhiPresenceDesiredAuthority,
    identity: &RhiDecryptedIdentity,
    created_at: UnixTimeSeconds,
    entropy: &dyn EntropySource,
) -> Result<RhiSignedPresenceDocuments, RhiPresencePublicationError> {
    let state = desired.state();
    if created_at.get() > i64::MAX as u64 {
        return Err(failure(RhiPresencePublicationErrorKind::InvalidInput));
    }
    if !presence_authority_matches_state(state, authority) {
        return Err(failure(
            RhiPresencePublicationErrorKind::DesiredStateMismatch,
        ));
    }
    if identity.public_identity().as_hex() != authority.service_public_key() {
        return Err(failure(RhiPresencePublicationErrorKind::IdentityMismatch));
    }
    let mut documents = Vec::with_capacity(authority.document_kinds().len());
    for kind in authority.document_kinds() {
        let plan = presence_plan(*kind, identity.public_identity().as_hex(), created_at.get())?;
        let mut auxiliary = Zeroizing::new([0_u8; 32]);
        entropy
            .fill_bytes(&mut auxiliary[..])
            .map_err(|_| failure(RhiPresencePublicationErrorKind::EntropyUnavailable))?;
        let event = sign_plan(identity, &plan, &auxiliary)?;
        let bytes = serde_json::to_vec(&event)
            .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))?;
        let verified = validate_signed_document(
            *kind,
            identity.public_identity().as_hex(),
            created_at.get(),
            &bytes,
        )?;
        documents.push(RhiSignedPresenceDocument {
            kind: *kind,
            event_id: *verified.id().as_bytes(),
            signed_event_sha256: Sha256::digest(&bytes).into(),
            signed_event_bytes: bytes.into_boxed_slice(),
            created_at_unix_seconds: created_at.get(),
        });
    }
    if (state.mode() == RhiPresenceDesiredMode::Disabled && !documents.is_empty())
        || (state.mode() == RhiPresenceDesiredMode::Enabled
            && documents.len() != authority.document_kinds().len())
    {
        return Err(failure(RhiPresencePublicationErrorKind::Invariant));
    }
    Ok(RhiSignedPresenceDocuments {
        desired_state: state,
        service_public_key: authority.service_public_key().into(),
        targets: authority.targets().to_vec().into_boxed_slice(),
        documents: documents.into_boxed_slice(),
    })
}

/// Independently verifies every exact signed document against its bound intent.
pub fn validate_rhi_signed_presence_documents(
    documents: &RhiSignedPresenceDocuments,
    authority: &RhiPresenceDesiredAuthority,
) -> Result<(), RhiPresencePublicationError> {
    if !presence_authority_matches_state(documents.desired_state, authority)
        || documents.service_public_key.as_ref() != authority.service_public_key()
        || documents.targets.as_ref() != authority.targets()
        || documents.documents.len() != authority.document_kinds().len()
    {
        return Err(failure(
            RhiPresencePublicationErrorKind::DesiredStateMismatch,
        ));
    }
    for (document, kind) in documents.documents.iter().zip(authority.document_kinds()) {
        if document.kind != *kind
            || Sha256::digest(document.signed_event_bytes.as_ref()).as_slice()
                != document.signed_event_sha256
        {
            return Err(failure(RhiPresencePublicationErrorKind::VerificationFailed));
        }
        let verified = validate_signed_document(
            document.kind,
            authority.service_public_key(),
            document.created_at_unix_seconds,
            &document.signed_event_bytes,
        )?;
        if verified.id().as_bytes() != &document.event_id {
            return Err(failure(RhiPresencePublicationErrorKind::VerificationFailed));
        }
    }
    Ok(())
}

impl RhiPresenceOutboxRepository<'_> {
    /// Atomically commits exact signed bytes and the complete immutable target set.
    ///
    /// A successful return means every exact payload and initial target state is
    /// durable before any relay adapter can observe those bytes. The caller
    /// retains the sealed exact-byte capability so an unknown commit result can
    /// be reconciled by replaying this same value. Exact replay is idempotent.
    pub async fn commit_signed_presence(
        &self,
        documents: &RhiSignedPresenceDocuments,
        committed_at: RhiPresenceUnixMilliseconds,
    ) -> Result<RhiPresenceCommitOutcome, RhiPresencePublicationError> {
        require_writable(self)?;
        let documents = documents.retained_copy();
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { commit_signed(transaction, documents, committed_at).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Claims the oldest currently desired, due presence outbox.
    pub async fn claim_next_presence(
        &self,
        owner: RhiPresenceLeaseOwner,
        now: RhiPresenceUnixMilliseconds,
    ) -> Result<Option<RhiPresenceLease>, RhiPresencePublicationError> {
        require_writable(self)?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { claim_next(transaction, owner, now).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Persists Submitted before exposing the committed exact bytes.
    pub async fn prepare_next_presence_target(
        &self,
        lease: RhiPresenceLease,
        started_at: RhiPresenceUnixMilliseconds,
    ) -> Result<RhiPreparedPresenceAttempt, RhiPresencePublicationError> {
        require_writable(self)?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { prepare_next(transaction, lease, started_at).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Commits one closed observed outcome by exact compare-and-swap.
    pub async fn record_presence_outcome(
        &self,
        prepared: &RhiPreparedPresenceAttempt,
        finished_at: RhiPresenceUnixMilliseconds,
        outcome: RhiPresenceAttemptOutcome,
        retry_delay: RhiPresenceRetryDelayMilliseconds,
    ) -> Result<RhiPresenceAttemptCommit, RhiPresencePublicationError> {
        require_writable(self)?;
        let input =
            PresenceRecordInput::from_prepared(prepared, finished_at, outcome, retry_delay)?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { record_outcome(transaction, input).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Recovers at most one expired lease and records Unknown for submitted work.
    pub async fn recover_one_expired_presence(
        &self,
        adapters: &RhiTimeEntropyAdapters,
        now: RhiPresenceUnixMilliseconds,
    ) -> Result<bool, RhiPresencePublicationError> {
        require_writable(self)?;
        let candidate = self
            .host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { read_expired_candidate(transaction, now).await })
            })
            .await
            .map_err(map_transaction_error)?;
        let Some(candidate) = candidate else {
            return Ok(false);
        };
        let delay = sample_retry_delay(adapters, candidate.retry_upper_bound)?;
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { recover_expired(transaction, candidate, now, delay).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Executes at most one exact-byte presence attempt through an injected sink.
    ///
    /// Cancellation after durable preparation leaves Submitted evidence. Lease
    /// expiry recovery records Unknown before retrying the same retained bytes.
    pub async fn execute_next_presence(
        &self,
        owner: RhiPresenceLeaseOwner,
        adapters: &RhiTimeEntropyAdapters,
        sink: &dyn RhiExactPresenceSink,
    ) -> Result<Option<RhiPresenceAttemptCommit>, RhiPresencePublicationError> {
        let now = presence_now(adapters)?;
        self.recover_one_expired_presence(adapters, now).await?;
        let Some(lease) = self.claim_next_presence(owner, now).await? else {
            return Ok(None);
        };
        let prepared = self.prepare_next_presence_target(lease, now).await?;
        let outcome = match sink.submit_exact(&prepared).await {
            RhiPresenceAttemptOutcome::Submitted => RhiPresenceAttemptOutcome::Unknown,
            outcome => outcome,
        };
        let finished_at = presence_now(adapters)?;
        let retry_delay = if retryable_outcome(outcome) {
            sample_retry_delay(adapters, prepared.retry_upper_bound())?
        } else {
            RhiPresenceRetryDelayMilliseconds(0)
        };
        self.record_presence_outcome(&prepared, finished_at, outcome, retry_delay)
            .await
            .map(Some)
    }
}

fn require_writable(
    repository: &RhiPresenceOutboxRepository<'_>,
) -> Result<(), RhiPresencePublicationError> {
    if repository.host().mode() == RhiStateHostMode::ReadWriteExisting {
        Ok(())
    } else {
        Err(failure(RhiPresencePublicationErrorKind::InvalidMode))
    }
}

fn presence_now(
    adapters: &RhiTimeEntropyAdapters,
) -> Result<RhiPresenceUnixMilliseconds, RhiPresencePublicationError> {
    let value = adapters.now_utc_milliseconds().map_err(|error| {
        failure(match error.kind() {
            RhiRuntimeAdapterErrorKind::WallClockUnavailable => {
                RhiPresencePublicationErrorKind::ClockUnavailable
            }
            _ => RhiPresencePublicationErrorKind::ClockUnavailable,
        })
    })?;
    RhiPresenceUnixMilliseconds::new(value)
        .map_err(|_| failure(RhiPresencePublicationErrorKind::ClockUnavailable))
}

fn sample_retry_delay(
    adapters: &RhiTimeEntropyAdapters,
    cap: u64,
) -> Result<RhiPresenceRetryDelayMilliseconds, RhiPresencePublicationError> {
    if cap == 0 {
        return Ok(RhiPresenceRetryDelayMilliseconds(0));
    }
    let bound = RhiJitterBoundMilliseconds::new(cap)
        .map_err(|_| failure(RhiPresencePublicationErrorKind::InvalidInput))?;
    adapters
        .sample_full_jitter(bound)
        .map(|delay| RhiPresenceRetryDelayMilliseconds(delay.get()))
        .map_err(|_| failure(RhiPresencePublicationErrorKind::EntropyUnavailable))
}

async fn commit_signed(
    transaction: &mut ServiceSqliteTransaction<'_>,
    documents: RhiSignedPresenceDocuments,
    committed_at: RhiPresenceUnixMilliseconds,
) -> Result<RhiPresenceCommitOutcome, PresenceOperationError> {
    let desired = read_desired_binding(transaction).await?;
    validate_document_set(&documents, desired)?;
    let current = read_generation_outboxes(transaction, desired.generation).await?;
    if !current.is_empty() && generation_matches(&documents, &current)? {
        return Ok(RhiPresenceCommitOutcome {
            desired_state: documents.desired_state,
            document_count: u8::try_from(documents.documents.len())
                .map_err(|_| PresenceOperationError::Invariant)?,
            changed: false,
        });
    }
    if !current.is_empty() {
        return Err(PresenceOperationError::Invariant);
    }
    if documents.desired_state.mode() == RhiPresenceDesiredMode::Enabled {
        for document in &documents.documents {
            let rows = sqlx::query(READ_MAX_AUTHORED_SQL)
                .bind(document.kind.code())
                .fetch_all(&mut *transaction)
                .await
                .map_err(|_| PresenceOperationError::Storage)?;
            let [row] = rows.as_slice() else {
                return Err(PresenceOperationError::Invariant);
            };
            if let Some(previous) = row
                .try_get::<Option<i64>, _>("authored_at_unix_s")
                .map_err(|_| PresenceOperationError::Invariant)?
            {
                let previous =
                    u64::try_from(previous).map_err(|_| PresenceOperationError::Invariant)?;
                if document.created_at_unix_seconds <= previous {
                    return Err(PresenceOperationError::InvalidInput);
                }
            }
        }
    }
    let lease_rows = sqlx::query(COUNT_STALE_LEASES_SQL)
        .bind(i64_value(desired.generation)?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    let [lease_row] = lease_rows.as_slice() else {
        return Err(PresenceOperationError::Invariant);
    };
    if lease_row
        .try_get::<i64, _>("lease_count")
        .ok()
        .filter(|value| *value >= 0)
        .ok_or(PresenceOperationError::Invariant)?
        != 0
    {
        return Err(PresenceOperationError::NotReady);
    }
    let superseded = sqlx::query(SUPERSEDE_OUTBOX_SQL)
        .bind(i64_value(committed_at.get())?)
        .bind(i64_value(desired.generation)?)
        .bind(i64_value(committed_at.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?
        .rows_affected();

    for document in &documents.documents {
        let outbox_id = derive_outbox_id(
            desired.generation,
            document.kind,
            desired.desired_sha256,
            document.signed_event_sha256,
        );
        let inserted = sqlx::query(INSERT_OUTBOX_SQL)
            .bind(outbox_id.as_bytes().as_slice())
            .bind(i64_value(desired.generation)?)
            .bind(document.kind.code())
            .bind(desired.desired_sha256.as_slice())
            .bind(desired.target_set_sha256.as_slice())
            .bind(document.event_id.as_slice())
            .bind(document.signed_event_sha256.as_slice())
            .bind(document.signed_event_bytes.as_ref())
            .bind(i64_value(document.created_at_unix_seconds)?)
            .bind(documents.service_public_key.as_ref())
            .bind(i64::from(desired.target_count))
            .bind(i64::from(desired.required_target_count))
            .bind(i64_value(committed_at.get())?)
            .bind(i64_value(committed_at.get())?)
            .bind(i64_value(committed_at.get())?)
            .execute(&mut *transaction)
            .await
            .map_err(|_| PresenceOperationError::Storage)?;
        if inserted.rows_affected() != 1 {
            return Err(PresenceOperationError::Invariant);
        }
        for target in &documents.targets {
            let inserted = sqlx::query(INSERT_TARGET_SQL)
                .bind(outbox_id.as_bytes().as_slice())
                .bind(i64::from(target.ordinal()))
                .bind(target.relay_id())
                .bind(i64::from(target.required()))
                .bind(i64_value(committed_at.get())?)
                .bind(i64_value(committed_at.get())?)
                .bind(i64_value(committed_at.get())?)
                .execute(&mut *transaction)
                .await
                .map_err(|_| PresenceOperationError::Storage)?;
            if inserted.rows_affected() != 1 {
                return Err(PresenceOperationError::Invariant);
            }
        }
    }
    let committed = read_generation_outboxes(transaction, desired.generation).await?;
    if !generation_matches(&documents, &committed)? {
        return Err(PresenceOperationError::Invariant);
    }
    Ok(RhiPresenceCommitOutcome {
        desired_state: documents.desired_state,
        document_count: u8::try_from(documents.documents.len())
            .map_err(|_| PresenceOperationError::Invariant)?,
        changed: !documents.documents.is_empty() || superseded != 0,
    })
}

fn validate_document_set(
    documents: &RhiSignedPresenceDocuments,
    desired: PresenceDesiredBinding,
) -> Result<(), PresenceOperationError> {
    let state = documents.desired_state;
    if state.generation() != desired.generation
        || state.mode() != desired.mode
        || state.profile() != desired.profile
        || state.application_handler() != desired.application_handler
        || state.target_set_sha256() != &desired.target_set_sha256
        || state.target_count() != desired.target_count
        || state.required_target_count() != desired.required_target_count
        || state.queue_capacity() != desired.queue_capacity
        || state.desired_sha256() != &desired.desired_sha256
        || documents.targets.len() != usize::from(desired.target_count)
        || documents.documents.len() != desired.document_count()
        || target_set_digest(&documents.targets)? != desired.target_set_sha256
        || !valid_public_key(&documents.service_public_key)
    {
        return Err(PresenceOperationError::DesiredStateMismatch);
    }
    let expected = desired.document_kinds();
    for (document, kind) in documents.documents.iter().zip(expected) {
        if document.kind != kind
            || document.signed_event_bytes.is_empty()
            || document.signed_event_bytes.len() > RHI_PRESENCE_SIGNED_EVENT_MAX_BYTES
            || <[u8; 32]>::from(Sha256::digest(&document.signed_event_bytes))
                != document.signed_event_sha256
        {
            return Err(PresenceOperationError::VerificationFailed);
        }
        let event = validate_signed_document(
            document.kind,
            &documents.service_public_key,
            document.created_at_unix_seconds,
            &document.signed_event_bytes,
        )
        .map_err(|_| PresenceOperationError::VerificationFailed)?;
        if event.id().as_bytes() != &document.event_id {
            return Err(PresenceOperationError::VerificationFailed);
        }
    }
    Ok(())
}

fn generation_matches(
    documents: &RhiSignedPresenceDocuments,
    current: &[PresenceOutboxRecord],
) -> Result<bool, PresenceOperationError> {
    if documents.documents.len() != current.len() {
        return Ok(false);
    }
    for (document, outbox) in documents.documents.iter().zip(current) {
        if outbox.desired_generation != documents.desired_state.generation()
            || outbox.desired_sha256 != *documents.desired_state.desired_sha256()
            || outbox.target_set_sha256 != *documents.desired_state.target_set_sha256()
            || outbox.target_count != documents.desired_state.target_count()
            || outbox.required_target_count != documents.desired_state.required_target_count()
            || outbox.id
                != derive_outbox_id(
                    outbox.desired_generation,
                    document.kind,
                    outbox.desired_sha256,
                    document.signed_event_sha256,
                )
            || document.kind != outbox.document_kind
            || document.event_id != outbox.event_id
            || document.signed_event_sha256 != outbox.event_sha256
            || document.signed_event_bytes.as_ref() != outbox.exact_signed_event_bytes.as_ref()
            || document.created_at_unix_seconds != outbox.authored_at_unix_s
            || documents.service_public_key.as_ref() != outbox.service_public_key.as_ref()
            || documents
                .targets
                .iter()
                .zip(outbox.targets.iter())
                .any(|(expected, actual)| {
                    expected.ordinal() != actual.ordinal
                        || expected.relay_id() != actual.relay_id.as_ref()
                        || expected.required() != actual.required
                })
        {
            return Ok(false);
        }
        validate_targets(outbox, &outbox.targets)?;
    }
    Ok(true)
}

fn derive_outbox_id(
    generation: u64,
    kind: RhiPresenceDocumentKind,
    desired_sha256: [u8; 32],
    event_sha256: [u8; 32],
) -> RhiPresenceOutboxId {
    let mut digest = Sha256::new();
    digest.update(OUTBOX_ID_DOMAIN);
    digest.update(generation.to_be_bytes());
    digest.update([document_kind_tag(kind)]);
    digest.update(desired_sha256);
    digest.update(event_sha256);
    RhiPresenceOutboxId(digest.finalize().into())
}

fn derive_attempt_id(
    outbox: RhiPresenceOutboxId,
    event_sha256: [u8; 32],
    ordinal: u8,
    attempt_number: u16,
) -> RhiPresenceAttemptId {
    let mut digest = Sha256::new();
    digest.update(ATTEMPT_ID_DOMAIN);
    digest.update(outbox.0);
    digest.update(event_sha256);
    digest.update([ordinal]);
    digest.update(attempt_number.to_be_bytes());
    RhiPresenceAttemptId(digest.finalize().into())
}

const fn document_kind_tag(kind: RhiPresenceDocumentKind) -> u8 {
    match kind {
        RhiPresenceDocumentKind::ServiceProfile => 0,
        RhiPresenceDocumentKind::ApplicationHandler => 1,
    }
}

fn target_set_digest(targets: &[RhiPresenceTarget]) -> Result<[u8; 32], PresenceOperationError> {
    const DOMAIN: &[u8] = b"radroots.rhi.presence_target_set.v1\0";
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(
        u32::try_from(targets.len())
            .map_err(|_| PresenceOperationError::InvalidInput)?
            .to_be_bytes(),
    );
    for target in targets {
        digest.update(u32::from(target.ordinal()).to_be_bytes());
        digest.update(
            u64::try_from(target.relay_id().len())
                .map_err(|_| PresenceOperationError::InvalidInput)?
                .to_be_bytes(),
        );
        digest.update(target.relay_id().as_bytes());
        digest.update([u8::from(target.required())]);
    }
    Ok(digest.finalize().into())
}

async fn read_desired_binding(
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<PresenceDesiredBinding, PresenceOperationError> {
    let rows = sqlx::query(READ_DESIRED_BINDING_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    let [row] = rows.as_slice() else {
        return Err(PresenceOperationError::DesiredStateMismatch);
    };
    if row.try_get::<i64, _>("singleton").ok() != Some(1) {
        return Err(PresenceOperationError::Invariant);
    }
    let generation = positive_u64(row, "generation")?;
    let enabled = boolean_i64(row, "enabled")?;
    let profile = boolean_i64(row, "profile")?;
    let application_handler = boolean_i64(row, "application_handler")?;
    let target_set_sha256 = blob::<32>(row, "target_set_sha256")?;
    let target_count = bounded_u8(row, "target_count", RHI_PRESENCE_DESIRED_MAX_TARGETS)?;
    let required_target_count =
        bounded_u8(row, "required_target_count", usize::from(target_count))?;
    let queue_capacity = row
        .try_get::<i64, _>("queue_capacity")
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value <= 4_096)
        .ok_or(PresenceOperationError::Invariant)?;
    let desired_sha256 = blob::<32>(row, "desired_sha256")?;
    let mode = if enabled {
        RhiPresenceDesiredMode::Enabled
    } else {
        RhiPresenceDesiredMode::Disabled
    };
    let valid = if enabled {
        (profile || application_handler) && target_count > 0 && queue_capacity > 0
    } else {
        !profile
            && !application_handler
            && target_count == 0
            && required_target_count == 0
            && queue_capacity == 0
    };
    if !valid {
        return Err(PresenceOperationError::Invariant);
    }
    Ok(PresenceDesiredBinding {
        generation,
        mode,
        profile,
        application_handler,
        target_set_sha256,
        target_count,
        required_target_count,
        queue_capacity,
        desired_sha256,
    })
}

async fn read_generation_outboxes(
    transaction: &mut ServiceSqliteTransaction<'_>,
    generation: u64,
) -> Result<Vec<PresenceOutboxRecord>, PresenceOperationError> {
    let rows = sqlx::query(READ_GENERATION_OUTBOX_SQL)
        .bind(i64_value(generation)?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    if rows.len() > 2 {
        return Err(PresenceOperationError::Invariant);
    }
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let mut outbox = decode_outbox(row)?;
        outbox.targets = read_targets(transaction, outbox.id)
            .await?
            .into_boxed_slice();
        records.push(outbox);
    }
    Ok(records)
}

async fn read_outbox(
    transaction: &mut ServiceSqliteTransaction<'_>,
    id: RhiPresenceOutboxId,
) -> Result<Option<PresenceOutboxRecord>, PresenceOperationError> {
    let rows = sqlx::query(READ_OUTBOX_SQL)
        .bind(id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    let Some(row) = exactly_zero_or_one(rows)? else {
        return Ok(None);
    };
    let mut outbox = decode_outbox(row)?;
    outbox.targets = read_targets(transaction, outbox.id)
        .await?
        .into_boxed_slice();
    Ok(Some(outbox))
}

async fn read_targets(
    transaction: &mut ServiceSqliteTransaction<'_>,
    outbox_id: RhiPresenceOutboxId,
) -> Result<Vec<PresenceTargetRecord>, PresenceOperationError> {
    let rows = sqlx::query(READ_TARGETS_SQL)
        .bind(outbox_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    if rows.len() > RHI_PRESENCE_DESIRED_MAX_TARGETS {
        return Err(PresenceOperationError::Invariant);
    }
    rows.into_iter().map(decode_target).collect()
}

fn decode_outbox(
    row: sqlx::sqlite::SqliteRow,
) -> Result<PresenceOutboxRecord, PresenceOperationError> {
    let id = RhiPresenceOutboxId(blob::<32>(&row, "outbox_id")?);
    let desired_generation = positive_u64(&row, "desired_generation")?;
    let document_kind = decode_document_kind(&bounded_text(
        &row,
        "document_kind",
        "document_kind_bytes",
        19,
    )?)?;
    let desired_sha256 = blob::<32>(&row, "desired_sha256")?;
    let target_set_sha256 = blob::<32>(&row, "target_set_sha256")?;
    let event_id = blob::<32>(&row, "event_id")?;
    let event_sha256 = blob::<32>(&row, "event_sha256")?;
    let exact_length = positive_usize(&row, "exact_signed_event_bytes_length")?;
    if exact_length > RHI_PRESENCE_SIGNED_EVENT_MAX_BYTES {
        return Err(PresenceOperationError::Invariant);
    }
    let exact_signed_event_bytes = row
        .try_get::<Vec<u8>, _>("exact_signed_event_bytes")
        .map_err(|_| PresenceOperationError::Invariant)?;
    let authored_at_unix_s = nonnegative_u64(&row, "authored_at_unix_s")?;
    let service_public_key =
        bounded_text(&row, "service_public_key", "service_public_key_bytes", 64)?;
    let target_count = bounded_u8(&row, "target_count", RHI_PRESENCE_DESIRED_MAX_TARGETS)?;
    let required_target_count =
        bounded_u8(&row, "required_target_count", usize::from(target_count))?;
    let max_attempts = bounded_u16(&row, "max_attempts", RHI_PRESENCE_MAX_ATTEMPTS)?;
    let initial_backoff_ms = bounded_u64(&row, "initial_backoff_ms", INITIAL_BACKOFF_MILLISECONDS)?;
    let maximum_backoff_ms = bounded_u64(&row, "maximum_backoff_ms", MAXIMUM_BACKOFF_MILLISECONDS)?;
    let attempt_deadline_ms =
        bounded_u64(&row, "attempt_deadline_ms", ATTEMPT_DEADLINE_MILLISECONDS)?;
    let state = decode_outbox_state(&bounded_text(&row, "state", "state_bytes", 10)?)?;
    let revision = positive_u64(&row, "revision")?;
    let next_attempt = optional_millis(&row, "next_attempt_unix_ms")?;
    let lease_owner = optional_owner(&row)?;
    let lease_expires = optional_millis(&row, "lease_expires_unix_ms")?;
    let created_at = RhiPresenceUnixMilliseconds(nonnegative_u64(&row, "created_at_unix_ms")?);
    let updated_at = RhiPresenceUnixMilliseconds(nonnegative_u64(&row, "updated_at_unix_ms")?);
    if exact_signed_event_bytes.len() != exact_length
        || exact_signed_event_bytes.is_empty()
        || <[u8; 32]>::from(Sha256::digest(&exact_signed_event_bytes)) != event_sha256
        || !valid_public_key(&service_public_key)
        || max_attempts != RHI_PRESENCE_MAX_ATTEMPTS
        || initial_backoff_ms != INITIAL_BACKOFF_MILLISECONDS
        || maximum_backoff_ms != MAXIMUM_BACKOFF_MILLISECONDS
        || attempt_deadline_ms != ATTEMPT_DEADLINE_MILLISECONDS
        || initial_backoff_ms > maximum_backoff_ms
        || updated_at < created_at
        || !valid_outbox_shape(state, next_attempt, lease_owner, lease_expires)
    {
        return Err(PresenceOperationError::Invariant);
    }
    Ok(PresenceOutboxRecord {
        id,
        desired_generation,
        document_kind,
        desired_sha256,
        target_set_sha256,
        event_id,
        event_sha256,
        exact_signed_event_bytes: exact_signed_event_bytes.into_boxed_slice(),
        authored_at_unix_s,
        service_public_key: service_public_key.into_boxed_str(),
        target_count,
        required_target_count,
        max_attempts,
        state,
        revision,
        next_attempt,
        lease_owner,
        lease_expires,
        created_at,
        updated_at,
        targets: Box::new([]),
    })
}

fn decode_target(
    row: sqlx::sqlite::SqliteRow,
) -> Result<PresenceTargetRecord, PresenceOperationError> {
    let ordinal = bounded_u8(&row, "target_ordinal", RHI_PRESENCE_DESIRED_MAX_TARGETS - 1)?;
    let relay_id = bounded_text(&row, "relay_id", "relay_id_bytes", 64)?;
    let required = boolean_i64(&row, "required")?;
    let state = decode_target_state(&bounded_text(&row, "state", "state_bytes", 13)?)?;
    let revision = positive_u64(&row, "revision")?;
    let attempt_count = bounded_u16(&row, "attempt_count", RHI_PRESENCE_MAX_ATTEMPTS)?;
    let next_attempt = optional_millis(&row, "next_attempt_unix_ms")?;
    let last_attempt_id = optional_attempt_id(&row)?;
    let updated_at = RhiPresenceUnixMilliseconds(nonnegative_u64(&row, "updated_at_unix_ms")?);
    if !valid_relay_id(&relay_id)
        || !valid_target_shape(state, attempt_count, next_attempt, last_attempt_id)
    {
        return Err(PresenceOperationError::Invariant);
    }
    Ok(PresenceTargetRecord {
        ordinal,
        relay_id: relay_id.into_boxed_str(),
        required,
        state,
        revision,
        attempt_count,
        next_attempt,
        last_attempt_id,
        updated_at,
    })
}

async fn claim_next(
    transaction: &mut ServiceSqliteTransaction<'_>,
    owner: RhiPresenceLeaseOwner,
    now: RhiPresenceUnixMilliseconds,
) -> Result<Option<RhiPresenceLease>, PresenceOperationError> {
    let rows = sqlx::query(READ_CLAIMABLE_OUTBOX_SQL)
        .bind(i64_value(now.get())?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    let Some(row) = exactly_zero_or_one(rows)? else {
        return Ok(None);
    };
    let id = RhiPresenceOutboxId(blob::<32>(&row, "outbox_id")?);
    let outbox = read_outbox(transaction, id)
        .await?
        .ok_or(PresenceOperationError::Invariant)?;
    validate_current_desired(transaction, &outbox).await?;
    validate_targets(&outbox, &outbox.targets)?;
    let expires = now
        .get()
        .checked_add(ATTEMPT_DEADLINE_MILLISECONDS)
        .filter(|value| *value <= MAX_UNIX_MILLISECONDS)
        .ok_or(PresenceOperationError::InvalidInput)?;
    let result = sqlx::query(CLAIM_OUTBOX_SQL)
        .bind(owner.0.as_slice())
        .bind(i64_value(expires)?)
        .bind(i64_value(now.get())?)
        .bind(outbox.id.as_bytes().as_slice())
        .bind(i64_value(outbox.revision)?)
        .bind(i64_value(now.get())?)
        .bind(i64_value(now.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(PresenceOperationError::LeaseLost);
    }
    let leased = read_outbox(transaction, id)
        .await?
        .filter(|record| {
            record.state == RhiPresenceOutboxState::Leased
                && record.lease_owner == Some(owner)
                && record.lease_expires == Some(RhiPresenceUnixMilliseconds(expires))
        })
        .ok_or(PresenceOperationError::Invariant)?;
    Ok(Some(RhiPresenceLease {
        outbox: leased,
        owner,
        expires_at: RhiPresenceUnixMilliseconds(expires),
    }))
}

async fn prepare_next(
    transaction: &mut ServiceSqliteTransaction<'_>,
    lease: RhiPresenceLease,
    started_at: RhiPresenceUnixMilliseconds,
) -> Result<RhiPreparedPresenceAttempt, PresenceOperationError> {
    validate_lease(transaction, &lease, started_at, true).await?;
    let candidate = lease
        .outbox
        .targets
        .iter()
        .find(|target| target_is_due(target, lease.outbox.max_attempts, started_at))
        .ok_or(PresenceOperationError::NotReady)?;
    let candidate_ordinal = candidate.ordinal;
    let candidate_revision = candidate.revision;
    let attempt_number = candidate
        .attempt_count
        .checked_add(1)
        .filter(|value| *value <= lease.outbox.max_attempts)
        .ok_or(PresenceOperationError::Invariant)?;
    let attempt_id = derive_attempt_id(
        lease.outbox.id,
        lease.outbox.event_sha256,
        candidate_ordinal,
        attempt_number,
    );
    let result = sqlx::query(PREPARE_TARGET_SQL)
        .bind(attempt_id.as_bytes().as_slice())
        .bind(i64_value(started_at.get())?)
        .bind(lease.outbox.id.as_bytes().as_slice())
        .bind(i64::from(candidate_ordinal))
        .bind(i64_value(candidate_revision)?)
        .bind(i64::from(lease.outbox.max_attempts))
        .bind(i64_value(started_at.get())?)
        .bind(i64_value(started_at.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(PresenceOperationError::LeaseLost);
    }
    let current = read_outbox(transaction, lease.outbox.id)
        .await?
        .ok_or(PresenceOperationError::Invariant)?;
    if !same_outbox_identity(&current, &lease.outbox) {
        return Err(PresenceOperationError::LeaseLost);
    }
    let target = current
        .targets
        .into_vec()
        .into_iter()
        .find(|target| target.ordinal == candidate_ordinal)
        .filter(|target| {
            target.state == RhiPresenceTargetState::Submitted
                && target.attempt_count == attempt_number
                && target.last_attempt_id == Some(attempt_id)
                && target.updated_at == started_at
        })
        .ok_or(PresenceOperationError::Invariant)?;
    validate_signed_document(
        lease.outbox.document_kind,
        &lease.outbox.service_public_key,
        lease.outbox.authored_at_unix_s,
        &lease.outbox.exact_signed_event_bytes,
    )
    .map_err(|_| PresenceOperationError::Invariant)?;
    let deadline_at = lease.expires_at;
    let exact_signed_event_bytes = lease.outbox.exact_signed_event_bytes.clone();
    Ok(RhiPreparedPresenceAttempt {
        lease,
        target,
        attempt_id,
        started_at,
        deadline_at,
        exact_signed_event_bytes,
    })
}

async fn record_outcome(
    transaction: &mut ServiceSqliteTransaction<'_>,
    input: PresenceRecordInput,
) -> Result<RhiPresenceAttemptCommit, PresenceOperationError> {
    if let Some(existing) = read_attempt(transaction, input.attempt_id).await? {
        return reconcile_recorded(transaction, input, existing).await;
    }
    validate_input_lease(transaction, input, true).await?;
    let outbox = read_outbox(transaction, input.outbox_id)
        .await?
        .ok_or(PresenceOperationError::Invariant)?;
    let target = outbox
        .targets
        .iter()
        .find(|target| target.ordinal == input.target_ordinal)
        .ok_or(PresenceOperationError::Invariant)?;
    if target.state != RhiPresenceTargetState::Submitted
        || target.revision != input.target_revision
        || target.attempt_count != input.attempt_number
        || target.last_attempt_id != Some(input.attempt_id)
        || target.updated_at != input.started_at
    {
        return Err(PresenceOperationError::LeaseLost);
    }
    insert_attempt(transaction, input).await?;
    let (next_state, next_attempt) = target_outcome_schedule(input)?;
    let result = sqlx::query(UPDATE_TARGET_OUTCOME_SQL)
        .bind(next_state.code())
        .bind(optional_i64(next_attempt)?)
        .bind(i64_value(input.finished_at.get())?)
        .bind(input.outbox_id.as_bytes().as_slice())
        .bind(i64::from(input.target_ordinal))
        .bind(i64_value(input.target_revision)?)
        .bind(i64::from(input.attempt_number))
        .bind(input.attempt_id.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(PresenceOperationError::LeaseLost);
    }
    let targets = read_targets(transaction, input.outbox_id).await?;
    let disposition = disposition(&outbox, &targets)?;
    update_outbox_after_attempt(transaction, input, disposition).await?;
    Ok(RhiPresenceAttemptCommit {
        outbox_id: input.outbox_id,
        attempt_id: input.attempt_id,
        target_ordinal: input.target_ordinal,
        attempt_number: input.attempt_number,
        outcome: input.outcome,
        target_state: next_state,
        outbox_state: disposition.state,
    })
}

async fn read_expired_candidate(
    transaction: &mut ServiceSqliteTransaction<'_>,
    now: RhiPresenceUnixMilliseconds,
) -> Result<Option<PresenceRecoveryCandidate>, PresenceOperationError> {
    let rows = sqlx::query(READ_EXPIRED_OUTBOX_SQL)
        .bind(i64_value(now.get())?)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    let Some(row) = exactly_zero_or_one(rows)? else {
        return Ok(None);
    };
    let id = RhiPresenceOutboxId(blob::<32>(&row, "outbox_id")?);
    let outbox = read_outbox(transaction, id)
        .await?
        .ok_or(PresenceOperationError::Invariant)?;
    let desired = read_desired_binding(transaction).await?;
    let current_desired = desired_matches_outbox(desired, &outbox);
    validate_targets(&outbox, &outbox.targets)?;
    let submitted: Vec<_> = outbox
        .targets
        .iter()
        .filter(|target| target.state == RhiPresenceTargetState::Submitted)
        .map(|target| target.attempt_count)
        .collect();
    if submitted.len() > 1 {
        return Err(PresenceOperationError::Invariant);
    }
    let retry_upper_bound = if current_desired {
        submitted
            .first()
            .copied()
            .filter(|attempt| *attempt < outbox.max_attempts)
            .map_or(0, retry_upper_bound)
    } else {
        0
    };
    Ok(Some(PresenceRecoveryCandidate {
        outbox,
        retry_upper_bound,
        current_desired,
    }))
}

async fn recover_expired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    candidate: PresenceRecoveryCandidate,
    now: RhiPresenceUnixMilliseconds,
    delay: RhiPresenceRetryDelayMilliseconds,
) -> Result<bool, PresenceOperationError> {
    let current = read_outbox(transaction, candidate.outbox.id)
        .await?
        .filter(|current| same_outbox(current, &candidate.outbox))
        .ok_or(PresenceOperationError::LeaseLost)?;
    if current.state != RhiPresenceOutboxState::Leased
        || current.lease_expires.is_none_or(|expires| expires > now)
    {
        return Err(PresenceOperationError::LeaseLost);
    }
    let owner = current
        .lease_owner
        .ok_or(PresenceOperationError::Invariant)?;
    let expires = current
        .lease_expires
        .ok_or(PresenceOperationError::Invariant)?;
    for target in current
        .targets
        .iter()
        .filter(|target| target.state == RhiPresenceTargetState::Submitted)
    {
        let attempt_id = target
            .last_attempt_id
            .ok_or(PresenceOperationError::Invariant)?;
        if read_attempt(transaction, attempt_id).await?.is_some() {
            return Err(PresenceOperationError::Invariant);
        }
        let input = PresenceRecordInput {
            outbox_id: current.id,
            outbox_revision: current.revision,
            event_sha256: current.event_sha256,
            owner,
            lease_expires: expires,
            target_ordinal: target.ordinal,
            target_revision: target.revision,
            attempt_number: target.attempt_count,
            attempt_id,
            started_at: target.updated_at,
            finished_at: now,
            outcome: RhiPresenceAttemptOutcome::Unknown,
            retry_delay: delay,
        };
        insert_attempt(transaction, input).await?;
        let (state, next) = target_outcome_schedule(input)?;
        let result = sqlx::query(UPDATE_TARGET_OUTCOME_SQL)
            .bind(state.code())
            .bind(optional_i64(next)?)
            .bind(i64_value(now.get())?)
            .bind(current.id.as_bytes().as_slice())
            .bind(i64::from(target.ordinal))
            .bind(i64_value(target.revision)?)
            .bind(i64::from(target.attempt_count))
            .bind(attempt_id.as_bytes().as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| PresenceOperationError::Storage)?;
        if result.rows_affected() != 1 {
            return Err(PresenceOperationError::LeaseLost);
        }
    }
    let targets = read_targets(transaction, current.id).await?;
    let disposition = if candidate.current_desired {
        disposition(&current, &targets)?
    } else {
        PresenceOutboxDisposition {
            state: RhiPresenceOutboxState::Superseded,
            next_attempt: None,
        }
    };
    let result = sqlx::query(UPDATE_OUTBOX_RECOVERY_SQL)
        .bind(disposition.state.code())
        .bind(optional_i64(disposition.next_attempt)?)
        .bind(i64_value(now.get())?)
        .bind(current.id.as_bytes().as_slice())
        .bind(i64_value(current.revision)?)
        .bind(owner.0.as_slice())
        .bind(i64_value(expires.get())?)
        .bind(i64_value(now.get())?)
        .bind(i64_value(now.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(PresenceOperationError::LeaseLost);
    }
    Ok(true)
}

async fn validate_current_desired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    outbox: &PresenceOutboxRecord,
) -> Result<(), PresenceOperationError> {
    let desired = read_desired_binding(transaction).await?;
    if !desired_matches_outbox(desired, outbox) {
        return Err(PresenceOperationError::DesiredStateMismatch);
    }
    Ok(())
}

fn desired_matches_outbox(desired: PresenceDesiredBinding, outbox: &PresenceOutboxRecord) -> bool {
    desired.mode == RhiPresenceDesiredMode::Enabled
        && desired.generation == outbox.desired_generation
        && desired.desired_sha256 == outbox.desired_sha256
        && desired.target_set_sha256 == outbox.target_set_sha256
        && desired.target_count == outbox.target_count
        && desired.required_target_count == outbox.required_target_count
        && desired
            .document_kinds()
            .any(|kind| kind == outbox.document_kind)
}

async fn validate_lease(
    transaction: &mut ServiceSqliteTransaction<'_>,
    lease: &RhiPresenceLease,
    now: RhiPresenceUnixMilliseconds,
    require_unexpired: bool,
) -> Result<(), PresenceOperationError> {
    let current = read_outbox(transaction, lease.outbox.id)
        .await?
        .filter(|current| same_outbox(current, &lease.outbox))
        .ok_or(PresenceOperationError::LeaseLost)?;
    validate_current_desired(transaction, &current).await?;
    if current.state != RhiPresenceOutboxState::Leased
        || current.lease_owner != Some(lease.owner)
        || current.lease_expires != Some(lease.expires_at)
        || (require_unexpired && lease.expires_at <= now)
    {
        return Err(PresenceOperationError::LeaseLost);
    }
    Ok(())
}

async fn validate_input_lease(
    transaction: &mut ServiceSqliteTransaction<'_>,
    input: PresenceRecordInput,
    require_unexpired: bool,
) -> Result<(), PresenceOperationError> {
    let current = read_outbox(transaction, input.outbox_id)
        .await?
        .ok_or(PresenceOperationError::LeaseLost)?;
    validate_current_desired(transaction, &current).await?;
    if current.revision != input.outbox_revision
        || current.event_sha256 != input.event_sha256
        || current.state != RhiPresenceOutboxState::Leased
        || current.lease_owner != Some(input.owner)
        || current.lease_expires != Some(input.lease_expires)
        || (require_unexpired && input.lease_expires <= input.finished_at)
    {
        return Err(PresenceOperationError::LeaseLost);
    }
    Ok(())
}

async fn insert_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    input: PresenceRecordInput,
) -> Result<(), PresenceOperationError> {
    let result = sqlx::query(INSERT_ATTEMPT_SQL)
        .bind(input.attempt_id.as_bytes().as_slice())
        .bind(input.outbox_id.as_bytes().as_slice())
        .bind(i64::from(input.target_ordinal))
        .bind(i64::from(input.attempt_number))
        .bind(input.event_sha256.as_slice())
        .bind(input.owner.0.as_slice())
        .bind(i64_value(input.started_at.get())?)
        .bind(i64_value(input.finished_at.get())?)
        .bind(input.outcome.code())
        .bind(input.outcome.code())
        .execute(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(PresenceOperationError::Storage);
    }
    Ok(())
}

async fn update_outbox_after_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    input: PresenceRecordInput,
    disposition: PresenceOutboxDisposition,
) -> Result<(), PresenceOperationError> {
    let result = sqlx::query(UPDATE_OUTBOX_AFTER_ATTEMPT_SQL)
        .bind(disposition.state.code())
        .bind(optional_i64(disposition.next_attempt)?)
        .bind(i64_value(input.finished_at.get())?)
        .bind(input.outbox_id.as_bytes().as_slice())
        .bind(i64_value(input.outbox_revision)?)
        .bind(input.owner.0.as_slice())
        .bind(i64_value(input.lease_expires.get())?)
        .bind(i64_value(input.finished_at.get())?)
        .bind(i64_value(input.finished_at.get())?)
        .execute(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    if result.rows_affected() != 1 {
        return Err(PresenceOperationError::LeaseLost);
    }
    Ok(())
}

async fn read_attempt(
    transaction: &mut ServiceSqliteTransaction<'_>,
    attempt_id: RhiPresenceAttemptId,
) -> Result<Option<PresenceAttemptRecord>, PresenceOperationError> {
    let rows = sqlx::query(READ_ATTEMPT_SQL)
        .bind(attempt_id.as_bytes().as_slice())
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| PresenceOperationError::Storage)?;
    exactly_zero_or_one(rows)?.map(decode_attempt).transpose()
}

fn decode_attempt(
    row: sqlx::sqlite::SqliteRow,
) -> Result<PresenceAttemptRecord, PresenceOperationError> {
    let attempt_id = RhiPresenceAttemptId(blob::<32>(&row, "attempt_id")?);
    let outbox_id = RhiPresenceOutboxId(blob::<32>(&row, "outbox_id")?);
    let target_ordinal = bounded_u8(&row, "target_ordinal", RHI_PRESENCE_DESIRED_MAX_TARGETS - 1)?;
    let attempt_number = bounded_u16(&row, "attempt_number", RHI_PRESENCE_MAX_ATTEMPTS)?;
    let event_sha256 = blob::<32>(&row, "event_sha256")?;
    let owner = RhiPresenceLeaseOwner(blob::<16>(&row, "lease_owner")?);
    let started_at = RhiPresenceUnixMilliseconds(nonnegative_u64(&row, "started_at_unix_ms")?);
    let finished_at = RhiPresenceUnixMilliseconds(nonnegative_u64(&row, "finished_at_unix_ms")?);
    let outcome = decode_attempt_outcome(&bounded_text(&row, "outcome", "outcome_bytes", 13)?)?;
    let result_code = bounded_text(&row, "result_code", "result_code_bytes", 64)?;
    if owner.0.iter().all(|byte| *byte == 0)
        || started_at > finished_at
        || result_code != outcome.code()
    {
        return Err(PresenceOperationError::Invariant);
    }
    Ok(PresenceAttemptRecord {
        attempt_id,
        outbox_id,
        target_ordinal,
        attempt_number,
        event_sha256,
        owner,
        started_at,
        finished_at,
        outcome,
    })
}

async fn reconcile_recorded(
    transaction: &mut ServiceSqliteTransaction<'_>,
    input: PresenceRecordInput,
    existing: PresenceAttemptRecord,
) -> Result<RhiPresenceAttemptCommit, PresenceOperationError> {
    if existing != PresenceAttemptRecord::from_input(input) {
        return Err(PresenceOperationError::Invariant);
    }
    let outbox = read_outbox(transaction, input.outbox_id)
        .await?
        .ok_or(PresenceOperationError::Invariant)?;
    if outbox.revision
        != input
            .outbox_revision
            .checked_add(1)
            .ok_or(PresenceOperationError::Invariant)?
        || outbox.updated_at != input.finished_at
        || outbox.lease_owner.is_some()
        || outbox.lease_expires.is_some()
        || outbox.event_sha256 != input.event_sha256
    {
        return Err(PresenceOperationError::Invariant);
    }
    validate_targets(&outbox, &outbox.targets)?;
    let (expected_state, expected_next) = target_outcome_schedule(input)?;
    let expected_target_revision = input
        .target_revision
        .checked_add(1)
        .ok_or(PresenceOperationError::Invariant)?;
    let target = outbox
        .targets
        .iter()
        .find(|target| target.ordinal == input.target_ordinal)
        .filter(|target| {
            target.revision == expected_target_revision
                && target.attempt_count == input.attempt_number
                && target.last_attempt_id == Some(input.attempt_id)
                && target.state == expected_state
                && target.next_attempt == expected_next
                && target.updated_at == input.finished_at
        })
        .ok_or(PresenceOperationError::Invariant)?;
    let expected_disposition = disposition(&outbox, &outbox.targets)?;
    if outbox.state != expected_disposition.state
        || outbox.next_attempt != expected_disposition.next_attempt
    {
        return Err(PresenceOperationError::Invariant);
    }
    Ok(RhiPresenceAttemptCommit {
        outbox_id: outbox.id,
        attempt_id: input.attempt_id,
        target_ordinal: input.target_ordinal,
        attempt_number: input.attempt_number,
        outcome: input.outcome,
        target_state: target.state,
        outbox_state: outbox.state,
    })
}

fn disposition(
    outbox: &PresenceOutboxRecord,
    targets: &[PresenceTargetRecord],
) -> Result<PresenceOutboxDisposition, PresenceOperationError> {
    validate_targets(outbox, targets)?;
    let required = targets.iter().filter(|target| target.required);
    if required
        .clone()
        .all(|target| target.state == RhiPresenceTargetState::Accepted)
    {
        return Ok(PresenceOutboxDisposition {
            state: RhiPresenceOutboxState::Complete,
            next_attempt: None,
        });
    }
    if required
        .clone()
        .any(|target| target_is_blocking(target, outbox.max_attempts))
    {
        return Ok(PresenceOutboxDisposition {
            state: RhiPresenceOutboxState::Blocked,
            next_attempt: None,
        });
    }
    let next_attempt = required
        .filter_map(|target| target.next_attempt)
        .min()
        .ok_or(PresenceOperationError::Invariant)?;
    Ok(PresenceOutboxDisposition {
        state: RhiPresenceOutboxState::Pending,
        next_attempt: Some(next_attempt),
    })
}

fn validate_targets(
    outbox: &PresenceOutboxRecord,
    targets: &[PresenceTargetRecord],
) -> Result<(), PresenceOperationError> {
    if targets.len() != usize::from(outbox.target_count)
        || targets.is_empty()
        || targets.len() > RHI_PRESENCE_DESIRED_MAX_TARGETS
        || targets.iter().filter(|target| target.required).count()
            != usize::from(outbox.required_target_count)
        || targets
            .iter()
            .enumerate()
            .any(|(ordinal, target)| usize::from(target.ordinal) != ordinal)
        || targets.iter().enumerate().any(|(index, target)| {
            targets[index + 1..]
                .iter()
                .any(|later| later.relay_id == target.relay_id)
        })
    {
        return Err(PresenceOperationError::Invariant);
    }
    let mut digest = Sha256::new();
    digest.update(b"radroots.rhi.presence_target_set.v1\0");
    digest.update(
        u32::try_from(targets.len())
            .map_err(|_| PresenceOperationError::Invariant)?
            .to_be_bytes(),
    );
    for target in targets {
        digest.update(u32::from(target.ordinal).to_be_bytes());
        digest.update(
            u64::try_from(target.relay_id.len())
                .map_err(|_| PresenceOperationError::Invariant)?
                .to_be_bytes(),
        );
        digest.update(target.relay_id.as_bytes());
        digest.update([u8::from(target.required)]);
    }
    if <[u8; 32]>::from(digest.finalize()) != outbox.target_set_sha256 {
        return Err(PresenceOperationError::Invariant);
    }
    Ok(())
}

fn target_outcome_schedule(
    input: PresenceRecordInput,
) -> Result<(RhiPresenceTargetState, Option<RhiPresenceUnixMilliseconds>), PresenceOperationError> {
    let state = target_state_for_outcome(input.outcome)?;
    let next =
        if retryable_outcome(input.outcome) && input.attempt_number < RHI_PRESENCE_MAX_ATTEMPTS {
            if input.retry_delay.get() > retry_upper_bound(input.attempt_number) {
                return Err(PresenceOperationError::InvalidInput);
            }
            Some(RhiPresenceUnixMilliseconds(
                input
                    .finished_at
                    .get()
                    .checked_add(input.retry_delay.get())
                    .filter(|value| *value <= MAX_UNIX_MILLISECONDS)
                    .ok_or(PresenceOperationError::InvalidInput)?,
            ))
        } else {
            if input.retry_delay.get() != 0 {
                return Err(PresenceOperationError::InvalidInput);
            }
            None
        };
    Ok((state, next))
}

fn target_is_blocking(target: &PresenceTargetRecord, max_attempts: u16) -> bool {
    matches!(
        target.state,
        RhiPresenceTargetState::Rejected | RhiPresenceTargetState::AuthRequired
    ) || (retryable_state(target.state)
        && target.attempt_count >= max_attempts
        && target.next_attempt.is_none())
}

fn target_is_due(
    target: &PresenceTargetRecord,
    max_attempts: u16,
    now: RhiPresenceUnixMilliseconds,
) -> bool {
    retryable_state(target.state)
        && target.attempt_count < max_attempts
        && target.next_attempt.is_some_and(|next| next <= now)
}

const fn retryable_state(state: RhiPresenceTargetState) -> bool {
    matches!(
        state,
        RhiPresenceTargetState::Pending
            | RhiPresenceTargetState::Failed
            | RhiPresenceTargetState::RateLimited
            | RhiPresenceTargetState::Unknown
    )
}

const fn retryable_outcome(outcome: RhiPresenceAttemptOutcome) -> bool {
    matches!(
        outcome,
        RhiPresenceAttemptOutcome::RateLimited
            | RhiPresenceAttemptOutcome::Failed
            | RhiPresenceAttemptOutcome::Unknown
    )
}

const fn target_state_for_outcome(
    outcome: RhiPresenceAttemptOutcome,
) -> Result<RhiPresenceTargetState, PresenceOperationError> {
    match outcome {
        RhiPresenceAttemptOutcome::Submitted => Err(PresenceOperationError::InvalidInput),
        RhiPresenceAttemptOutcome::Accepted => Ok(RhiPresenceTargetState::Accepted),
        RhiPresenceAttemptOutcome::Rejected => Ok(RhiPresenceTargetState::Rejected),
        RhiPresenceAttemptOutcome::RateLimited => Ok(RhiPresenceTargetState::RateLimited),
        RhiPresenceAttemptOutcome::AuthRequired => Ok(RhiPresenceTargetState::AuthRequired),
        RhiPresenceAttemptOutcome::Failed => Ok(RhiPresenceTargetState::Failed),
        RhiPresenceAttemptOutcome::Unknown => Ok(RhiPresenceTargetState::Unknown),
    }
}

fn retry_upper_bound(attempt_number: u16) -> u64 {
    let mut bound = INITIAL_BACKOFF_MILLISECONDS;
    for _ in 1..attempt_number {
        bound = bound.saturating_mul(2).min(MAXIMUM_BACKOFF_MILLISECONDS);
    }
    bound.min(MAXIMUM_BACKOFF_MILLISECONDS)
}

fn same_outbox(current: &PresenceOutboxRecord, prior: &PresenceOutboxRecord) -> bool {
    same_outbox_identity(current, prior)
        && current.state == prior.state
        && current.revision == prior.revision
        && current.next_attempt == prior.next_attempt
        && current.lease_owner == prior.lease_owner
        && current.lease_expires == prior.lease_expires
        && current.updated_at == prior.updated_at
        && current.targets == prior.targets
}

fn same_outbox_identity(current: &PresenceOutboxRecord, prior: &PresenceOutboxRecord) -> bool {
    current.id == prior.id
        && current.desired_generation == prior.desired_generation
        && current.document_kind == prior.document_kind
        && current.desired_sha256 == prior.desired_sha256
        && current.target_set_sha256 == prior.target_set_sha256
        && current.event_id == prior.event_id
        && current.event_sha256 == prior.event_sha256
        && current.exact_signed_event_bytes == prior.exact_signed_event_bytes
        && current.authored_at_unix_s == prior.authored_at_unix_s
        && current.service_public_key == prior.service_public_key
        && current.target_count == prior.target_count
        && current.required_target_count == prior.required_target_count
        && current.max_attempts == prior.max_attempts
        && current.created_at == prior.created_at
}

fn valid_outbox_shape(
    state: RhiPresenceOutboxState,
    next_attempt: Option<RhiPresenceUnixMilliseconds>,
    lease_owner: Option<RhiPresenceLeaseOwner>,
    lease_expires: Option<RhiPresenceUnixMilliseconds>,
) -> bool {
    match state {
        RhiPresenceOutboxState::Pending => {
            next_attempt.is_some() && lease_owner.is_none() && lease_expires.is_none()
        }
        RhiPresenceOutboxState::Leased => {
            next_attempt.is_none() && lease_owner.is_some() && lease_expires.is_some()
        }
        RhiPresenceOutboxState::Complete
        | RhiPresenceOutboxState::Blocked
        | RhiPresenceOutboxState::Superseded => {
            next_attempt.is_none() && lease_owner.is_none() && lease_expires.is_none()
        }
    }
}

fn valid_target_shape(
    state: RhiPresenceTargetState,
    attempt_count: u16,
    next_attempt: Option<RhiPresenceUnixMilliseconds>,
    last_attempt_id: Option<RhiPresenceAttemptId>,
) -> bool {
    match state {
        RhiPresenceTargetState::Pending => {
            attempt_count == 0 && next_attempt.is_some() && last_attempt_id.is_none()
        }
        RhiPresenceTargetState::Submitted => {
            attempt_count > 0 && next_attempt.is_none() && last_attempt_id.is_some()
        }
        RhiPresenceTargetState::Accepted
        | RhiPresenceTargetState::Rejected
        | RhiPresenceTargetState::AuthRequired => {
            attempt_count > 0 && next_attempt.is_none() && last_attempt_id.is_some()
        }
        RhiPresenceTargetState::RateLimited
        | RhiPresenceTargetState::Failed
        | RhiPresenceTargetState::Unknown => {
            attempt_count > 0
                && last_attempt_id.is_some()
                && if attempt_count < RHI_PRESENCE_MAX_ATTEMPTS {
                    next_attempt.is_some()
                } else {
                    next_attempt.is_none()
                }
        }
    }
}

fn decode_document_kind(value: &str) -> Result<RhiPresenceDocumentKind, PresenceOperationError> {
    match value {
        "service_profile" => Ok(RhiPresenceDocumentKind::ServiceProfile),
        "application_handler" => Ok(RhiPresenceDocumentKind::ApplicationHandler),
        _ => Err(PresenceOperationError::Invariant),
    }
}

fn decode_outbox_state(value: &str) -> Result<RhiPresenceOutboxState, PresenceOperationError> {
    match value {
        "pending" => Ok(RhiPresenceOutboxState::Pending),
        "leased" => Ok(RhiPresenceOutboxState::Leased),
        "complete" => Ok(RhiPresenceOutboxState::Complete),
        "blocked" => Ok(RhiPresenceOutboxState::Blocked),
        "superseded" => Ok(RhiPresenceOutboxState::Superseded),
        _ => Err(PresenceOperationError::Invariant),
    }
}

fn decode_target_state(value: &str) -> Result<RhiPresenceTargetState, PresenceOperationError> {
    match value {
        "pending" => Ok(RhiPresenceTargetState::Pending),
        "submitted" => Ok(RhiPresenceTargetState::Submitted),
        "accepted" => Ok(RhiPresenceTargetState::Accepted),
        "rejected" => Ok(RhiPresenceTargetState::Rejected),
        "rate_limited" => Ok(RhiPresenceTargetState::RateLimited),
        "auth_required" => Ok(RhiPresenceTargetState::AuthRequired),
        "failed" => Ok(RhiPresenceTargetState::Failed),
        "unknown" => Ok(RhiPresenceTargetState::Unknown),
        _ => Err(PresenceOperationError::Invariant),
    }
}

fn decode_attempt_outcome(
    value: &str,
) -> Result<RhiPresenceAttemptOutcome, PresenceOperationError> {
    match value {
        "submitted" => Ok(RhiPresenceAttemptOutcome::Submitted),
        "accepted" => Ok(RhiPresenceAttemptOutcome::Accepted),
        "rejected" => Ok(RhiPresenceAttemptOutcome::Rejected),
        "rate_limited" => Ok(RhiPresenceAttemptOutcome::RateLimited),
        "auth_required" => Ok(RhiPresenceAttemptOutcome::AuthRequired),
        "failed" => Ok(RhiPresenceAttemptOutcome::Failed),
        "unknown" => Ok(RhiPresenceAttemptOutcome::Unknown),
        _ => Err(PresenceOperationError::Invariant),
    }
}

fn exactly_zero_or_one(
    rows: Vec<sqlx::sqlite::SqliteRow>,
) -> Result<Option<sqlx::sqlite::SqliteRow>, PresenceOperationError> {
    match rows.as_slice() {
        [] => Ok(None),
        [_] => Ok(rows.into_iter().next()),
        _ => Err(PresenceOperationError::Invariant),
    }
}

fn blob<const N: usize>(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; N], PresenceOperationError> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| PresenceOperationError::Invariant)?
        .ok_or(PresenceOperationError::Invariant)?
        .try_into()
        .map_err(|_| PresenceOperationError::Invariant)
}

fn bounded_text(
    row: &sqlx::sqlite::SqliteRow,
    value_column: &str,
    length_column: &str,
    maximum: usize,
) -> Result<String, PresenceOperationError> {
    let length = row
        .try_get::<i64, _>(length_column)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0 && *value <= maximum)
        .ok_or(PresenceOperationError::Invariant)?;
    let value = row
        .try_get::<String, _>(value_column)
        .map_err(|_| PresenceOperationError::Invariant)?;
    if value.len() != length {
        return Err(PresenceOperationError::Invariant);
    }
    Ok(value)
}

fn bounded_u8(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    maximum: usize,
) -> Result<u8, PresenceOperationError> {
    row.try_get::<i64, _>(column)
        .ok()
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| usize::from(*value) <= maximum)
        .ok_or(PresenceOperationError::Invariant)
}

fn bounded_u16(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    maximum: u16,
) -> Result<u16, PresenceOperationError> {
    row.try_get::<i64, _>(column)
        .ok()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value <= maximum)
        .ok_or(PresenceOperationError::Invariant)
}

fn bounded_u64(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
    maximum: u64,
) -> Result<u64, PresenceOperationError> {
    row.try_get::<i64, _>(column)
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value <= maximum)
        .ok_or(PresenceOperationError::Invariant)
}

fn positive_u64(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<u64, PresenceOperationError> {
    nonnegative_u64(row, column).and_then(|value| {
        (value != 0)
            .then_some(value)
            .ok_or(PresenceOperationError::Invariant)
    })
}

fn nonnegative_u64(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<u64, PresenceOperationError> {
    row.try_get::<i64, _>(column)
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(PresenceOperationError::Invariant)
}

fn positive_usize(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<usize, PresenceOperationError> {
    row.try_get::<i64, _>(column)
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or(PresenceOperationError::Invariant)
}

fn boolean_i64(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<bool, PresenceOperationError> {
    match row.try_get::<i64, _>(column) {
        Ok(0) => Ok(false),
        Ok(1) => Ok(true),
        Ok(_) | Err(_) => Err(PresenceOperationError::Invariant),
    }
}

fn optional_millis(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Option<RhiPresenceUnixMilliseconds>, PresenceOperationError> {
    row.try_get::<Option<i64>, _>(column)
        .map_err(|_| PresenceOperationError::Invariant)?
        .map(|value| {
            u64::try_from(value)
                .map(RhiPresenceUnixMilliseconds)
                .map_err(|_| PresenceOperationError::Invariant)
        })
        .transpose()
}

fn optional_owner(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Option<RhiPresenceLeaseOwner>, PresenceOperationError> {
    let length = row
        .try_get::<Option<i64>, _>("lease_owner_bytes")
        .map_err(|_| PresenceOperationError::Invariant)?;
    let value = row
        .try_get::<Option<Vec<u8>>, _>("lease_owner")
        .map_err(|_| PresenceOperationError::Invariant)?;
    match (length, value) {
        (None, None) => Ok(None),
        (Some(16), Some(value)) => {
            let value: [u8; 16] = value
                .try_into()
                .map_err(|_| PresenceOperationError::Invariant)?;
            if value.iter().all(|byte| *byte == 0) {
                return Err(PresenceOperationError::Invariant);
            }
            Ok(Some(RhiPresenceLeaseOwner(value)))
        }
        _ => Err(PresenceOperationError::Invariant),
    }
}

fn optional_attempt_id(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<Option<RhiPresenceAttemptId>, PresenceOperationError> {
    let length = row
        .try_get::<Option<i64>, _>("last_attempt_id_bytes")
        .map_err(|_| PresenceOperationError::Invariant)?;
    let value = row
        .try_get::<Option<Vec<u8>>, _>("last_attempt_id")
        .map_err(|_| PresenceOperationError::Invariant)?;
    match (length, value) {
        (None, None) => Ok(None),
        (Some(32), Some(value)) => Ok(Some(RhiPresenceAttemptId(
            value
                .try_into()
                .map_err(|_| PresenceOperationError::Invariant)?,
        ))),
        _ => Err(PresenceOperationError::Invariant),
    }
}

fn valid_public_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && NostrPublicKey::from_hex(value).is_ok()
}

fn valid_relay_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn i64_value(value: u64) -> Result<i64, PresenceOperationError> {
    i64::try_from(value).map_err(|_| PresenceOperationError::InvalidInput)
}

fn optional_i64(
    value: Option<RhiPresenceUnixMilliseconds>,
) -> Result<Option<i64>, PresenceOperationError> {
    value.map(|value| i64_value(value.get())).transpose()
}

#[derive(Clone, Copy)]
struct PresenceDesiredBinding {
    generation: u64,
    mode: RhiPresenceDesiredMode,
    profile: bool,
    application_handler: bool,
    target_set_sha256: [u8; 32],
    target_count: u8,
    required_target_count: u8,
    queue_capacity: u32,
    desired_sha256: [u8; 32],
}

impl PresenceDesiredBinding {
    const fn document_count(self) -> usize {
        self.profile as usize + self.application_handler as usize
    }

    fn document_kinds(self) -> impl Iterator<Item = RhiPresenceDocumentKind> {
        [
            self.profile
                .then_some(RhiPresenceDocumentKind::ServiceProfile),
            self.application_handler
                .then_some(RhiPresenceDocumentKind::ApplicationHandler),
        ]
        .into_iter()
        .flatten()
    }
}

#[derive(PartialEq, Eq)]
struct PresenceOutboxRecord {
    id: RhiPresenceOutboxId,
    desired_generation: u64,
    document_kind: RhiPresenceDocumentKind,
    desired_sha256: [u8; 32],
    target_set_sha256: [u8; 32],
    event_id: [u8; 32],
    event_sha256: [u8; 32],
    exact_signed_event_bytes: Box<[u8]>,
    authored_at_unix_s: u64,
    service_public_key: Box<str>,
    target_count: u8,
    required_target_count: u8,
    max_attempts: u16,
    state: RhiPresenceOutboxState,
    revision: u64,
    next_attempt: Option<RhiPresenceUnixMilliseconds>,
    lease_owner: Option<RhiPresenceLeaseOwner>,
    lease_expires: Option<RhiPresenceUnixMilliseconds>,
    created_at: RhiPresenceUnixMilliseconds,
    updated_at: RhiPresenceUnixMilliseconds,
    targets: Box<[PresenceTargetRecord]>,
}

#[derive(Clone, PartialEq, Eq)]
struct PresenceTargetRecord {
    ordinal: u8,
    relay_id: Box<str>,
    required: bool,
    state: RhiPresenceTargetState,
    revision: u64,
    attempt_count: u16,
    next_attempt: Option<RhiPresenceUnixMilliseconds>,
    last_attempt_id: Option<RhiPresenceAttemptId>,
    updated_at: RhiPresenceUnixMilliseconds,
}

struct PresenceRecoveryCandidate {
    outbox: PresenceOutboxRecord,
    retry_upper_bound: u64,
    current_desired: bool,
}

#[derive(Clone, Copy)]
struct PresenceRecordInput {
    outbox_id: RhiPresenceOutboxId,
    outbox_revision: u64,
    event_sha256: [u8; 32],
    owner: RhiPresenceLeaseOwner,
    lease_expires: RhiPresenceUnixMilliseconds,
    target_ordinal: u8,
    target_revision: u64,
    attempt_number: u16,
    attempt_id: RhiPresenceAttemptId,
    started_at: RhiPresenceUnixMilliseconds,
    finished_at: RhiPresenceUnixMilliseconds,
    outcome: RhiPresenceAttemptOutcome,
    retry_delay: RhiPresenceRetryDelayMilliseconds,
}

impl PresenceRecordInput {
    fn from_prepared(
        prepared: &RhiPreparedPresenceAttempt,
        finished_at: RhiPresenceUnixMilliseconds,
        outcome: RhiPresenceAttemptOutcome,
        retry_delay: RhiPresenceRetryDelayMilliseconds,
    ) -> Result<Self, RhiPresencePublicationError> {
        if finished_at < prepared.started_at || outcome == RhiPresenceAttemptOutcome::Submitted {
            return Err(failure(RhiPresencePublicationErrorKind::InvalidInput));
        }
        let expected = derive_attempt_id(
            prepared.lease.outbox.id,
            prepared.lease.outbox.event_sha256,
            prepared.target.ordinal,
            prepared.target.attempt_count,
        );
        if expected != prepared.attempt_id {
            return Err(failure(RhiPresencePublicationErrorKind::Invariant));
        }
        Ok(Self {
            outbox_id: prepared.lease.outbox.id,
            outbox_revision: prepared.lease.outbox.revision,
            event_sha256: prepared.lease.outbox.event_sha256,
            owner: prepared.lease.owner,
            lease_expires: prepared.lease.expires_at,
            target_ordinal: prepared.target.ordinal,
            target_revision: prepared.target.revision,
            attempt_number: prepared.target.attempt_count,
            attempt_id: prepared.attempt_id,
            started_at: prepared.started_at,
            finished_at,
            outcome,
            retry_delay,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PresenceAttemptRecord {
    attempt_id: RhiPresenceAttemptId,
    outbox_id: RhiPresenceOutboxId,
    target_ordinal: u8,
    attempt_number: u16,
    event_sha256: [u8; 32],
    owner: RhiPresenceLeaseOwner,
    started_at: RhiPresenceUnixMilliseconds,
    finished_at: RhiPresenceUnixMilliseconds,
    outcome: RhiPresenceAttemptOutcome,
}

impl PresenceAttemptRecord {
    const fn from_input(input: PresenceRecordInput) -> Self {
        Self {
            attempt_id: input.attempt_id,
            outbox_id: input.outbox_id,
            target_ordinal: input.target_ordinal,
            attempt_number: input.attempt_number,
            event_sha256: input.event_sha256,
            owner: input.owner,
            started_at: input.started_at,
            finished_at: input.finished_at,
            outcome: input.outcome,
        }
    }
}

#[derive(Clone, Copy)]
struct PresenceOutboxDisposition {
    state: RhiPresenceOutboxState,
    next_attempt: Option<RhiPresenceUnixMilliseconds>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PresenceOperationError {
    InvalidInput,
    DesiredStateMismatch,
    VerificationFailed,
    NotReady,
    LeaseLost,
    Invariant,
    Storage,
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<PresenceOperationError>,
) -> RhiPresencePublicationError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return failure(RhiPresencePublicationErrorKind::CommitOutcomeUnknown);
    }
    failure(match error.operation_error().copied() {
        Some(PresenceOperationError::InvalidInput) => RhiPresencePublicationErrorKind::InvalidInput,
        Some(PresenceOperationError::DesiredStateMismatch) => {
            RhiPresencePublicationErrorKind::DesiredStateMismatch
        }
        Some(PresenceOperationError::VerificationFailed) => {
            RhiPresencePublicationErrorKind::VerificationFailed
        }
        Some(PresenceOperationError::NotReady) => RhiPresencePublicationErrorKind::NotReady,
        Some(PresenceOperationError::LeaseLost) => RhiPresencePublicationErrorKind::LeaseLost,
        Some(PresenceOperationError::Invariant) => RhiPresencePublicationErrorKind::Invariant,
        Some(PresenceOperationError::Storage) | None => RhiPresencePublicationErrorKind::Storage,
    })
}

fn presence_plan(
    kind: RhiPresenceDocumentKind,
    author: &str,
    created_at: u64,
) -> Result<AuthoredEventPlan, RhiPresencePublicationError> {
    match kind {
        RhiPresenceDocumentKind::ServiceProfile => {
            let profile = AuthoredProfile::new(PROFILE_NAME)
                .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))?
                .with_display_name(PROFILE_DISPLAY_NAME)
                .with_about(PROFILE_ABOUT)
                .with_bot(true);
            AuthoredEventPlan::from_profile(&profile, created_at, author)
                .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))
        }
        RhiPresenceDocumentKind::ApplicationHandler => {
            let metadata = nostr::Metadata::new()
                .name(PROFILE_DISPLAY_NAME)
                .about(PROFILE_ABOUT);
            let content = serde_json::to_string(&metadata)
                .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))?;
            let spec = ApplicationHandlerSpec::new(APPLICATION_HANDLER_KINDS.to_vec())
                .with_identifier(APPLICATION_HANDLER_IDENTIFIER)
                .with_metadata(metadata);
            let builder = build_application_handler(&spec)
                .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))?
                .custom_created_at(Timestamp::from_secs(created_at));
            let public_key = NostrPublicKey::from_hex(author)
                .map_err(|_| failure(RhiPresencePublicationErrorKind::IdentityMismatch))?;
            let request = builder
                .into_external_signing_request(public_key)
                .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))?;
            let draft = GenericEventDraft::new(
                "radroots.application.handler.v1",
                KIND_APPLICATION_HANDLER,
                created_at,
                vec![
                    vec!["d".to_owned(), APPLICATION_HANDLER_IDENTIFIER.to_owned()],
                    vec!["k".to_owned(), APPLICATION_HANDLER_KINDS[0].to_string()],
                ],
                content,
                author,
            )
            .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))?;
            let plan = AuthoredEventPlan::from_generic(draft)
                .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))?;
            if request.expected_event_id().to_bytes() != *plan.expected_event_id().as_bytes() {
                return Err(failure(RhiPresencePublicationErrorKind::RenderingFailed));
            }
            Ok(plan)
        }
    }
}

fn sign_plan(
    identity: &RhiDecryptedIdentity,
    plan: &AuthoredEventPlan,
    auxiliary: &[u8; 32],
) -> Result<nostr::Event, RhiPresencePublicationError> {
    let kind = u16::try_from(plan.body().kind())
        .map(Kind::Custom)
        .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))?;
    let tags = plan
        .body()
        .tags()
        .iter()
        .cloned()
        .map(Tag::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))?;
    let author = NostrPublicKey::from_hex(identity.public_identity().as_hex())
        .map_err(|_| failure(RhiPresencePublicationErrorKind::IdentityMismatch))?;
    let unsigned = EventBuilder::new(kind, plan.body().content())
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(plan.created_at()))
        .build(author);
    if unsigned.id.as_ref().map(|id| id.to_bytes()) != Some(*plan.expected_event_id().as_bytes()) {
        return Err(failure(RhiPresencePublicationErrorKind::RenderingFailed));
    }
    identity
        .sign_nostr_event(unsigned, auxiliary)
        .map_err(|_| failure(RhiPresencePublicationErrorKind::RenderingFailed))
}

fn validate_signed_document(
    kind: RhiPresenceDocumentKind,
    author: &str,
    created_at: u64,
    bytes: &[u8],
) -> Result<EventEnvelope, RhiPresencePublicationError> {
    if bytes.is_empty() || bytes.len() > RHI_PRESENCE_SIGNED_EVENT_MAX_BYTES {
        return Err(failure(RhiPresencePublicationErrorKind::VerificationFailed));
    }
    let source = core::str::from_utf8(bytes)
        .map_err(|_| failure(RhiPresencePublicationErrorKind::VerificationFailed))?;
    let wire = Nip01EventWire::parse_json_unverified_with_limits(source, presence_wire_limits())
        .map_err(|_| failure(RhiPresencePublicationErrorKind::VerificationFailed))?;
    let event = wire
        .into_unverified_envelope()
        .map_err(|_| failure(RhiPresencePublicationErrorKind::VerificationFailed))?;
    if verify_id(&event) != Verification::IdVerified
        || verify(&event) != Verification::Verified
        || event.author().to_hex() != author
        || event.created_at_u64() != created_at
    {
        return Err(failure(RhiPresencePublicationErrorKind::VerificationFailed));
    }
    let expected = presence_plan(kind, author, created_at)?;
    if event.id().as_bytes() != expected.expected_event_id().as_bytes()
        || event.kind_u32() != expected.body().kind()
        || event.tags_as_vec() != expected.body().tags()
        || event.content() != expected.body().content()
    {
        return Err(failure(RhiPresencePublicationErrorKind::VerificationFailed));
    }
    Ok(event)
}

const fn presence_wire_limits() -> EventWireLimits {
    EventWireLimits {
        max_raw_json_bytes: RHI_PRESENCE_SIGNED_EVENT_MAX_BYTES,
        max_content_bytes: 4 * 1024,
        max_tag_count: 4,
        max_total_tag_elements: 8,
        max_tag_element_bytes: 64,
        max_total_tag_bytes: 256,
        max_extra_fields: 0,
        max_total_extra_json_bytes: 0,
    }
}

const fn failure(kind: RhiPresencePublicationErrorKind) -> RhiPresencePublicationError {
    RhiPresencePublicationError { kind }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, error::Error as _};

    use super::*;

    #[test]
    fn public_vocabularies_bounds_and_diagnostics_are_closed() {
        let kinds = [
            RhiPresencePublicationErrorKind::InvalidMode,
            RhiPresencePublicationErrorKind::InvalidInput,
            RhiPresencePublicationErrorKind::DesiredStateMismatch,
            RhiPresencePublicationErrorKind::IdentityMismatch,
            RhiPresencePublicationErrorKind::EntropyUnavailable,
            RhiPresencePublicationErrorKind::RenderingFailed,
            RhiPresencePublicationErrorKind::VerificationFailed,
            RhiPresencePublicationErrorKind::NotReady,
            RhiPresencePublicationErrorKind::LeaseLost,
            RhiPresencePublicationErrorKind::Invariant,
            RhiPresencePublicationErrorKind::ClockUnavailable,
            RhiPresencePublicationErrorKind::Storage,
            RhiPresencePublicationErrorKind::CommitOutcomeUnknown,
        ];
        let codes: BTreeSet<_> = kinds.iter().map(|kind| kind.code()).collect();
        assert_eq!(codes.len(), kinds.len());
        for kind in kinds {
            let error = failure(kind);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.code(), kind.code());
            assert!(error.source().is_none());
            let rendered = format!("{error} {error:?}");
            for forbidden in ["relay", "wss://", "state.sqlite", "010101", "sqlx"] {
                assert!(!rendered.contains(forbidden));
            }
        }

        assert_eq!(
            RhiPresenceUnixMilliseconds::new(i64::MAX as u64)
                .expect("maximum time")
                .get(),
            i64::MAX as u64
        );
        assert!(RhiPresenceUnixMilliseconds::new(i64::MAX as u64 + 1).is_err());
        assert_eq!(
            RhiPresenceRetryDelayMilliseconds::new(MAXIMUM_BACKOFF_MILLISECONDS)
                .expect("maximum delay")
                .get(),
            MAXIMUM_BACKOFF_MILLISECONDS
        );
        assert!(RhiPresenceRetryDelayMilliseconds::new(MAXIMUM_BACKOFF_MILLISECONDS + 1).is_err());
        assert!(RhiPresenceLeaseOwner::from_bytes([0; 16]).is_err());
        assert_eq!(
            format!("{:?}", RhiPresenceLeaseOwner::from_bytes([1; 16]).unwrap()),
            "RhiPresenceLeaseOwner([redacted])"
        );
        assert_eq!(
            format!("{:?}", RhiPresenceOutboxId([0x5a; 32])),
            "RhiPresenceOutboxId([redacted])"
        );
        assert_eq!(
            format!("{:?}", RhiPresenceAttemptId([0x6a; 32])),
            "RhiPresenceAttemptId([redacted])"
        );
    }

    #[test]
    fn state_and_outcome_codes_are_exact() {
        assert_eq!(
            [
                RhiPresenceOutboxState::Pending,
                RhiPresenceOutboxState::Leased,
                RhiPresenceOutboxState::Complete,
                RhiPresenceOutboxState::Blocked,
                RhiPresenceOutboxState::Superseded,
            ]
            .map(RhiPresenceOutboxState::code),
            ["pending", "leased", "complete", "blocked", "superseded"]
        );
        assert_eq!(
            [
                RhiPresenceTargetState::Pending,
                RhiPresenceTargetState::Submitted,
                RhiPresenceTargetState::Accepted,
                RhiPresenceTargetState::Rejected,
                RhiPresenceTargetState::RateLimited,
                RhiPresenceTargetState::AuthRequired,
                RhiPresenceTargetState::Failed,
                RhiPresenceTargetState::Unknown,
            ]
            .map(RhiPresenceTargetState::code),
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
        assert_eq!(
            [
                RhiPresenceAttemptOutcome::Submitted,
                RhiPresenceAttemptOutcome::Accepted,
                RhiPresenceAttemptOutcome::Rejected,
                RhiPresenceAttemptOutcome::RateLimited,
                RhiPresenceAttemptOutcome::AuthRequired,
                RhiPresenceAttemptOutcome::Failed,
                RhiPresenceAttemptOutcome::Unknown,
            ]
            .map(RhiPresenceAttemptOutcome::code),
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
    }
}
