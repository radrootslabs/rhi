//! Pure overlap-safe reconciliation replay and provenance canonicalization.

use core::{cmp::Ordering, fmt};
use std::{collections::BTreeMap, error::Error};

use sha2::{Digest, Sha256};

use crate::{
    RhiAdmittedTradeMutationEvent, RhiConfigDocumentV1, RhiReconciliationAttemptPlan,
    RhiReconciliationSourceRequest, RhiReconciliationSourceRequestId,
    RhiReconciliationSourceResult, RhiReconciliationUnixMilliseconds,
    RhiTradeMutationObservedAtUnixSeconds, RhiTradeSourceCompletion, RhiTradeSourceCursor,
    state_metadata, state_trade::PersistenceRecord,
};

/// Exact version of the reconciliation replay contract.
pub const RHI_RECONCILIATION_REPLAY_CONTRACT_VERSION: u32 = 1;

const REPLAY_ID_DOMAIN: &[u8] = b"radroots.rhi.reconciliation_source_replay.v1\0";
const SOURCE_KIND: &str = "nostr_relay";
const SOURCE_SELECTOR: &str = "trade_mutation_lineage_v1";
const MAX_OVERLAP_SECONDS: u64 = 86_400;

/// Stable source-free replay validation class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationReplayErrorKind {
    InvalidInput,
    InvalidConfiguration,
    PolicyMismatch,
    ResourceLimit,
    MutationConflict,
    SignedEventConflict,
}

impl RhiReconciliationReplayErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "reconciliation_replay_input_invalid",
            Self::InvalidConfiguration => "reconciliation_replay_configuration_invalid",
            Self::PolicyMismatch => "reconciliation_replay_policy_mismatch",
            Self::ResourceLimit => "reconciliation_replay_resource_limit",
            Self::MutationConflict => "reconciliation_replay_mutation_conflict",
            Self::SignedEventConflict => "reconciliation_replay_signed_event_conflict",
        }
    }
}

/// Redacted source-free replay validation failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiReconciliationReplayError {
    kind: RhiReconciliationReplayErrorKind,
}

impl RhiReconciliationReplayError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiReconciliationReplayErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiReconciliationReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiReconciliationReplayErrorKind::InvalidInput => {
                "RHI reconciliation replay input is invalid"
            }
            RhiReconciliationReplayErrorKind::InvalidConfiguration => {
                "RHI reconciliation replay configuration is invalid"
            }
            RhiReconciliationReplayErrorKind::PolicyMismatch => {
                "RHI reconciliation replay policy does not match the attempt"
            }
            RhiReconciliationReplayErrorKind::ResourceLimit => {
                "RHI reconciliation replay exceeds its resource limit"
            }
            RhiReconciliationReplayErrorKind::MutationConflict => {
                "RHI reconciliation replay conflicts with canonical mutation evidence"
            }
            RhiReconciliationReplayErrorKind::SignedEventConflict => {
                "RHI reconciliation replay conflicts with signed event evidence"
            }
        })
    }
}

impl fmt::Debug for RhiReconciliationReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationReplayError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiReconciliationReplayError {}

/// Domain-separated identity of one request's exact cursor/overlap binding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiReconciliationSourceReplayId([u8; 32]);

impl RhiReconciliationSourceReplayId {
    /// Returns the exact identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RhiReconciliationSourceReplayId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiReconciliationSourceReplayId([redacted])")
    }
}

/// Sealed source/trade/policy/selector-scoped evidence for a committed cursor.
///
/// Step 189 defines and consumes this non-forgeable capability but provides no
/// minting path. Step 190 alone may construct it after the replay and cursor
/// are committed atomically under their exact durable scope.
#[derive(Clone, PartialEq, Eq)]
pub struct RhiReconciliationSourceCursorEvidence {
    source_id: Box<str>,
    trade_id: radroots_event::id::TradeId,
    policy_digest: [u8; 32],
    selector_digest: [u8; 32],
    cursor: RhiTradeSourceCursor,
}

impl RhiReconciliationSourceCursorEvidence {
    /// Returns the retained exact cursor tuple.
    #[must_use]
    pub const fn cursor(&self) -> RhiTradeSourceCursor {
        self.cursor
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn read_committed_reconciliation_cursor(
    repositories: &crate::RhiStateRepositories<'_>,
    request: &crate::RhiReconciliationSourceRequest,
    policy: crate::RhiEvidencePolicyDigest,
) -> Result<Option<RhiReconciliationSourceCursorEvidence>, ()> {
    let source_id: Box<str> = request.source_id().into();
    let trade_id = request.trade_id();
    let selector_digest = *request.selector_digest().as_bytes();
    repositories
        .host()
        .sqlite_host()
        .transaction(move |transaction| {
            Box::pin(async move {
                crate::source_ingest::read_checkpoint(
                    transaction,
                    source_id.as_ref(),
                    policy,
                    trade_id,
                )
                .await
                .map(|checkpoint| {
                    checkpoint.map(|checkpoint| {
                        committed_cursor_evidence(
                            source_id,
                            trade_id,
                            *policy.as_bytes(),
                            selector_digest,
                            checkpoint.cursor,
                        )
                    })
                })
            })
        })
        .await
        .map_err(|_| ())
}

impl fmt::Debug for RhiReconciliationSourceCursorEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationSourceCursorEvidence")
            .field("scope", &"[redacted]")
            .field("cursor", &self.cursor)
            .finish()
    }
}

/// Pure source-request binding to an optional prior cursor and overlap window.
#[derive(Clone, PartialEq, Eq)]
pub struct RhiReconciliationSourceReplayPlan {
    id: RhiReconciliationSourceReplayId,
    request_id: RhiReconciliationSourceRequestId,
    source_id: Box<str>,
    trade_id: radroots_event::id::TradeId,
    required: bool,
    policy_digest: [u8; 32],
    selector_digest: [u8; 32],
    prior_cursor: Option<RhiReconciliationSourceCursorEvidence>,
    overlap_seconds: u64,
    since_unix_seconds: u64,
}

impl RhiReconciliationSourceReplayPlan {
    /// Derives the exact overlap-safe cursor binding for one attempt request.
    pub fn from_request(
        attempt: &RhiReconciliationAttemptPlan,
        request: &RhiReconciliationSourceRequest,
        configuration: &RhiConfigDocumentV1,
        prior_cursor: Option<RhiReconciliationSourceCursorEvidence>,
    ) -> Result<Self, RhiReconciliationReplayError> {
        if !attempt
            .requests()
            .iter()
            .any(|candidate| candidate.id() == request.id())
        {
            return Err(failure(RhiReconciliationReplayErrorKind::InvalidInput));
        }
        let normalized = configuration.normalized();
        let policy = state_metadata::evidence_policy_digest(normalized)
            .map_err(|_| failure(RhiReconciliationReplayErrorKind::InvalidConfiguration))?;
        if policy != attempt.evidence_policy_digest() {
            return Err(failure(RhiReconciliationReplayErrorKind::PolicyMismatch));
        }
        if prior_cursor.as_ref().is_some_and(|evidence| {
            !cursor_scope_matches(
                evidence,
                request.source_id(),
                request.trade_id(),
                policy.as_bytes(),
                request.selector_digest().as_bytes(),
            )
        }) {
            return Err(failure(RhiReconciliationReplayErrorKind::PolicyMismatch));
        }
        let source = normalized
            .pointer("/evidence/sources")
            .and_then(serde_json::Value::as_array)
            .and_then(|sources| {
                sources.iter().find(|source| {
                    source
                        .pointer("/source_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(request.source_id())
                })
            })
            .filter(|source| {
                source.pointer("/kind").and_then(serde_json::Value::as_str) == Some(SOURCE_KIND)
                    && source
                        .pointer("/selector")
                        .and_then(serde_json::Value::as_str)
                        == Some(SOURCE_SELECTOR)
            })
            .ok_or_else(|| failure(RhiReconciliationReplayErrorKind::InvalidConfiguration))?;
        let overlap_seconds = source
            .pointer("/overlap_seconds")
            .and_then(serde_json::Value::as_u64)
            .filter(|value| (1..=MAX_OVERLAP_SECONDS).contains(value))
            .ok_or_else(|| failure(RhiReconciliationReplayErrorKind::InvalidConfiguration))?;
        let lookback_seconds = source
            .pointer("/lookback_seconds")
            .and_then(serde_json::Value::as_u64)
            .filter(|value| *value == request.lookback_seconds() && overlap_seconds <= *value)
            .ok_or_else(|| failure(RhiReconciliationReplayErrorKind::InvalidConfiguration))?;
        let raw_prior_cursor = prior_cursor.as_ref().map(|evidence| evidence.cursor);
        let since_unix_seconds = raw_prior_cursor.map_or_else(
            || {
                request
                    .attempt_started_at()
                    .get()
                    .checked_div(1_000)
                    .unwrap_or(0)
                    .saturating_sub(lookback_seconds)
            },
            |cursor| resume_since(cursor, overlap_seconds),
        );
        Ok(Self {
            id: replay_id(
                request.id(),
                raw_prior_cursor,
                overlap_seconds,
                since_unix_seconds,
            ),
            request_id: request.id(),
            source_id: request.source_id().into(),
            trade_id: request.trade_id(),
            required: request.required(),
            policy_digest: *policy.as_bytes(),
            selector_digest: *request.selector_digest().as_bytes(),
            prior_cursor,
            overlap_seconds,
            since_unix_seconds,
        })
    }

    /// Returns the exact cursor-binding identity.
    #[must_use]
    pub const fn id(&self) -> RhiReconciliationSourceReplayId {
        self.id
    }

    /// Returns the exact source request identity.
    #[must_use]
    pub const fn request_id(&self) -> RhiReconciliationSourceRequestId {
        self.request_id
    }

    /// Returns the retained prior cursor, when one exists.
    #[must_use]
    pub fn prior_cursor(&self) -> Option<RhiTradeSourceCursor> {
        self.prior_cursor.as_ref().map(|evidence| evidence.cursor)
    }

    /// Returns the configured overlap in whole seconds.
    #[must_use]
    pub const fn overlap_seconds(&self) -> u64 {
        self.overlap_seconds
    }

    /// Returns the inclusive overlap-safe query start in Unix seconds.
    #[must_use]
    pub const fn since_unix_seconds(&self) -> u64 {
        self.since_unix_seconds
    }

    /// Canonicalizes a bounded admitted-event result for a later atomic commit.
    pub fn finish<I>(
        self,
        request: &RhiReconciliationSourceRequest,
        outcome: RhiTradeSourceCompletion,
        started_at: RhiReconciliationUnixMilliseconds,
        finished_at: RhiReconciliationUnixMilliseconds,
        events: I,
    ) -> Result<RhiReconciliationSourceReplay, RhiReconciliationReplayError>
    where
        I: IntoIterator<Item = RhiAdmittedTradeMutationEvent>,
    {
        if request.id() != self.request_id {
            return Err(failure(RhiReconciliationReplayErrorKind::InvalidInput));
        }
        RhiReconciliationSourceResult::new(request, outcome, started_at, finished_at, 0, 0)
            .map_err(|_| failure(RhiReconciliationReplayErrorKind::InvalidInput))?;
        let maximum_events = usize::try_from(request.maximum_events())
            .map_err(|_| failure(RhiReconciliationReplayErrorKind::InvalidConfiguration))?;
        let candidates = ingest_bounded_facts(
            events.into_iter().map(|event| {
                if event.mutation().trade_id != request.trade_id() {
                    return Err(failure(RhiReconciliationReplayErrorKind::InvalidInput));
                }
                let event_bytes = u64::try_from(event.original_bytes().len())
                    .map_err(|_| failure(RhiReconciliationReplayErrorKind::ResourceLimit))?;
                let observed_at = event.observed_at_unix_seconds();
                let observed_at_milliseconds = observed_at
                    .get()
                    .checked_mul(1_000)
                    .ok_or_else(|| failure(RhiReconciliationReplayErrorKind::InvalidInput))?;
                let observed_interval_end = observed_at_milliseconds
                    .checked_add(999)
                    .ok_or_else(|| failure(RhiReconciliationReplayErrorKind::InvalidInput))?;
                if observed_interval_end < started_at.get()
                    || observed_at_milliseconds > finished_at.get()
                {
                    return Err(failure(RhiReconciliationReplayErrorKind::InvalidInput));
                }
                Ok(ReplayFact {
                    original_bytes: event_bytes,
                    observed_at,
                    record: PersistenceRecord::from_admitted(event)
                        .map_err(|_| failure(RhiReconciliationReplayErrorKind::InvalidInput))?,
                })
            }),
            maximum_events,
            request.maximum_bytes(),
        )?;
        let CanonicalReplay {
            facts,
            duplicate_observations,
            accepted_original_bytes,
            cursor_candidate,
            first_observed_at,
        } = canonicalize(candidates)?;
        let accepted_event_count = u32::try_from(facts.len())
            .map_err(|_| failure(RhiReconciliationReplayErrorKind::ResourceLimit))?;
        let result = RhiReconciliationSourceResult::new(
            request,
            outcome,
            started_at,
            finished_at,
            accepted_event_count,
            accepted_original_bytes,
        )
        .map_err(|_| failure(RhiReconciliationReplayErrorKind::InvalidInput))?;
        Ok(RhiReconciliationSourceReplay {
            plan: self,
            result,
            duplicate_observations,
            accepted_original_bytes,
            cursor_candidate,
            first_observed_at,
            facts: facts.into_boxed_slice(),
        })
    }
}

impl fmt::Debug for RhiReconciliationSourceReplayPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationSourceReplayPlan")
            .field("identity", &"[redacted]")
            .field("has_prior_cursor", &self.prior_cursor.is_some())
            .field("overlap_seconds", &self.overlap_seconds)
            .field("since_unix_seconds", &self.since_unix_seconds)
            .finish()
    }
}

/// Canonical bounded replay result prepared for the Step 190 commit boundary.
pub struct RhiReconciliationSourceReplay {
    plan: RhiReconciliationSourceReplayPlan,
    result: RhiReconciliationSourceResult,
    duplicate_observations: u32,
    accepted_original_bytes: u64,
    cursor_candidate: Option<RhiTradeSourceCursor>,
    first_observed_at: Option<RhiTradeMutationObservedAtUnixSeconds>,
    facts: Box<[ReplayFact]>,
}

impl RhiReconciliationSourceReplay {
    /// Returns the exact cursor-binding identity.
    #[must_use]
    pub const fn id(&self) -> RhiReconciliationSourceReplayId {
        self.plan.id()
    }

    /// Returns the validated source result derived from the canonical inventory.
    #[must_use]
    pub const fn result(&self) -> RhiReconciliationSourceResult {
        self.result
    }

    /// Returns the number of distinct accepted signed-event identities.
    #[must_use]
    pub fn accepted_event_count(&self) -> usize {
        self.facts.len()
    }

    /// Returns the retained first-provenance original-byte total.
    #[must_use]
    pub const fn accepted_original_event_bytes(&self) -> u64 {
        self.accepted_original_bytes
    }

    /// Returns the exact replay observations removed by canonical deduplication.
    #[must_use]
    pub const fn duplicate_observation_count(&self) -> u32 {
        self.duplicate_observations
    }

    /// Returns the earliest retained source observation, when evidence exists.
    #[must_use]
    pub const fn first_observed_at(&self) -> Option<RhiTradeMutationObservedAtUnixSeconds> {
        self.first_observed_at
    }

    /// Returns the greatest admitted cursor candidate regardless of completion.
    #[must_use]
    pub const fn cursor_candidate(&self) -> Option<RhiTradeSourceCursor> {
        self.cursor_candidate
    }

    /// Returns a cursor only when exact source completion makes it eligible.
    #[must_use]
    pub fn eligible_cursor(&self) -> Option<RhiTradeSourceCursor> {
        eligible_cursor(
            self.result.outcome(),
            self.cursor_candidate,
            self.plan
                .prior_cursor
                .as_ref()
                .map(|evidence| evidence.cursor),
        )
    }

    pub(crate) fn into_commit_parts(self) -> RhiReconciliationReplayCommitParts {
        let eligible_cursor = self.eligible_cursor();
        RhiReconciliationReplayCommitParts {
            replay_id: self.plan.id,
            request_id: self.plan.request_id,
            source_id: self.plan.source_id,
            trade_id: self.plan.trade_id,
            required: self.plan.required,
            policy_digest: self.plan.policy_digest,
            selector_digest: self.plan.selector_digest,
            prior_cursor: self.plan.prior_cursor.map(|evidence| evidence.cursor),
            overlap_seconds: self.plan.overlap_seconds,
            since_unix_seconds: self.plan.since_unix_seconds,
            result: self.result,
            duplicate_observations: self.duplicate_observations,
            cursor_candidate: self.cursor_candidate,
            eligible_cursor,
            first_observed_at: self.first_observed_at,
            facts: self
                .facts
                .into_vec()
                .into_iter()
                .map(|fact| RhiReconciliationReplayCommitFact {
                    record: fact.record,
                    observed_at: fact.observed_at,
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }
}

pub(crate) struct RhiReconciliationReplayCommitParts {
    pub(crate) replay_id: RhiReconciliationSourceReplayId,
    pub(crate) request_id: RhiReconciliationSourceRequestId,
    pub(crate) source_id: Box<str>,
    pub(crate) trade_id: radroots_event::id::TradeId,
    pub(crate) required: bool,
    pub(crate) policy_digest: [u8; 32],
    pub(crate) selector_digest: [u8; 32],
    pub(crate) prior_cursor: Option<RhiTradeSourceCursor>,
    pub(crate) overlap_seconds: u64,
    pub(crate) since_unix_seconds: u64,
    pub(crate) result: RhiReconciliationSourceResult,
    pub(crate) duplicate_observations: u32,
    pub(crate) cursor_candidate: Option<RhiTradeSourceCursor>,
    pub(crate) eligible_cursor: Option<RhiTradeSourceCursor>,
    pub(crate) first_observed_at: Option<RhiTradeMutationObservedAtUnixSeconds>,
    pub(crate) facts: Box<[RhiReconciliationReplayCommitFact]>,
}

pub(crate) struct RhiReconciliationReplayCommitFact {
    pub(crate) record: PersistenceRecord,
    pub(crate) observed_at: RhiTradeMutationObservedAtUnixSeconds,
}

pub(crate) fn committed_cursor_evidence(
    source_id: Box<str>,
    trade_id: radroots_event::id::TradeId,
    policy_digest: [u8; 32],
    selector_digest: [u8; 32],
    cursor: RhiTradeSourceCursor,
) -> RhiReconciliationSourceCursorEvidence {
    RhiReconciliationSourceCursorEvidence {
        source_id,
        trade_id,
        policy_digest,
        selector_digest,
        cursor,
    }
}

fn cursor_scope_matches(
    evidence: &RhiReconciliationSourceCursorEvidence,
    source_id: &str,
    trade_id: radroots_event::id::TradeId,
    policy_digest: &[u8; 32],
    selector_digest: &[u8; 32],
) -> bool {
    evidence.source_id.as_ref() == source_id
        && evidence.trade_id == trade_id
        && &evidence.policy_digest == policy_digest
        && &evidence.selector_digest == selector_digest
}

impl fmt::Debug for RhiReconciliationSourceReplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiReconciliationSourceReplay")
            .field("identity", &"[redacted]")
            .field("outcome", &self.result.outcome())
            .field("accepted_event_count", &self.facts.len())
            .field(
                "accepted_original_event_bytes",
                &self.accepted_original_bytes,
            )
            .field("duplicate_observations", &self.duplicate_observations)
            .field("has_cursor_candidate", &self.cursor_candidate.is_some())
            .finish()
    }
}

struct ReplayFact {
    record: PersistenceRecord,
    original_bytes: u64,
    observed_at: RhiTradeMutationObservedAtUnixSeconds,
}

struct CanonicalReplay {
    facts: Vec<ReplayFact>,
    duplicate_observations: u32,
    accepted_original_bytes: u64,
    cursor_candidate: Option<RhiTradeSourceCursor>,
    first_observed_at: Option<RhiTradeMutationObservedAtUnixSeconds>,
}

fn ingest_bounded_facts<I>(
    facts: I,
    maximum_events: usize,
    maximum_bytes: u64,
) -> Result<Vec<ReplayFact>, RhiReconciliationReplayError>
where
    I: IntoIterator<Item = Result<ReplayFact, RhiReconciliationReplayError>>,
{
    let mut accepted_bytes = 0_u64;
    let mut bounded = Vec::with_capacity(maximum_events);
    for fact in facts.into_iter().take(maximum_events.saturating_add(1)) {
        if bounded.len() == maximum_events {
            return Err(failure(RhiReconciliationReplayErrorKind::ResourceLimit));
        }
        let fact = fact?;
        accepted_bytes = accepted_bytes
            .checked_add(fact.original_bytes)
            .filter(|value| *value <= maximum_bytes)
            .ok_or_else(|| failure(RhiReconciliationReplayErrorKind::ResourceLimit))?;
        bounded.push(fact);
    }
    Ok(bounded)
}

fn canonicalize(
    mut candidates: Vec<ReplayFact>,
) -> Result<CanonicalReplay, RhiReconciliationReplayError> {
    candidates.sort_by(compare_fact);
    let mut event_indexes = BTreeMap::<([u8; 32], [u8; 64]), usize>::new();
    let mut mutation_indexes = BTreeMap::<[u8; 32], usize>::new();
    let mut facts = Vec::<ReplayFact>::with_capacity(candidates.len());
    let mut duplicate_observations = 0_u32;
    let mut accepted_original_bytes = 0_u64;
    let mut cursor_candidate = None;
    let mut first_observed_at: Option<RhiTradeMutationObservedAtUnixSeconds> = None;
    for candidate in candidates {
        let event_key = (candidate.record.event_id, candidate.record.event_signature);
        if let Some(index) = event_indexes.get(&event_key).copied() {
            if !same_event(&facts[index].record, &candidate.record) {
                return Err(failure(
                    RhiReconciliationReplayErrorKind::SignedEventConflict,
                ));
            }
            duplicate_observations = duplicate_observations
                .checked_add(1)
                .ok_or_else(|| failure(RhiReconciliationReplayErrorKind::ResourceLimit))?;
            continue;
        }
        if let Some(index) = mutation_indexes.get(&candidate.record.mutation_id).copied()
            && !same_mutation(&facts[index].record, &candidate.record)
        {
            return Err(failure(RhiReconciliationReplayErrorKind::MutationConflict));
        }
        accepted_original_bytes = accepted_original_bytes
            .checked_add(candidate.original_bytes)
            .ok_or_else(|| failure(RhiReconciliationReplayErrorKind::ResourceLimit))?;
        let cursor = RhiTradeSourceCursor::from_verified_parts(
            candidate.record.authored_at_unix_s,
            candidate.record.event_id,
        );
        cursor_candidate = Some(cursor_candidate.map_or(cursor, |current| {
            if compare_cursor(current, cursor).is_lt() {
                cursor
            } else {
                current
            }
        }));
        first_observed_at = Some(first_observed_at.map_or(candidate.observed_at, |current| {
            if candidate.observed_at.get() < current.get() {
                candidate.observed_at
            } else {
                current
            }
        }));
        let index = facts.len();
        event_indexes.insert(event_key, index);
        mutation_indexes
            .entry(candidate.record.mutation_id)
            .or_insert(index);
        facts.push(candidate);
    }
    Ok(CanonicalReplay {
        facts,
        duplicate_observations,
        accepted_original_bytes,
        cursor_candidate,
        first_observed_at,
    })
}

fn compare_fact(left: &ReplayFact, right: &ReplayFact) -> Ordering {
    left.record
        .authored_at_unix_s
        .cmp(&right.record.authored_at_unix_s)
        .then_with(|| left.record.event_id.cmp(&right.record.event_id))
        .then_with(|| {
            left.record
                .event_signature
                .cmp(&right.record.event_signature)
        })
        .then_with(|| left.observed_at.get().cmp(&right.observed_at.get()))
        .then_with(|| left.original_bytes.cmp(&right.original_bytes))
}

fn same_mutation(left: &PersistenceRecord, right: &PersistenceRecord) -> bool {
    left.mutation_id == right.mutation_id
        && left.trade_id == right.trade_id
        && left.contract_id == right.contract_id
        && left.schema_version == right.schema_version
        && left.event_kind == right.event_kind
        && left.author_pubkey == right.author_pubkey
        && left.canonical_content == right.canonical_content
}

fn same_event(left: &PersistenceRecord, right: &PersistenceRecord) -> bool {
    same_mutation(left, right)
        && left.event_id == right.event_id
        && left.event_signature == right.event_signature
        && left.event_kind == right.event_kind
        && left.authored_at_unix_s == right.authored_at_unix_s
        && left.canonical_event_json == right.canonical_event_json
}

fn compare_cursor(left: RhiTradeSourceCursor, right: RhiTradeSourceCursor) -> Ordering {
    (left.created_at_unix_seconds(), left.event_id())
        .cmp(&(right.created_at_unix_seconds(), right.event_id()))
}

fn resume_since(cursor: RhiTradeSourceCursor, overlap_seconds: u64) -> u64 {
    cursor
        .created_at_unix_seconds()
        .saturating_sub(overlap_seconds)
}

fn eligible_cursor(
    outcome: RhiTradeSourceCompletion,
    candidate: Option<RhiTradeSourceCursor>,
    prior: Option<RhiTradeSourceCursor>,
) -> Option<RhiTradeSourceCursor> {
    if !matches!(outcome, RhiTradeSourceCompletion::Complete) {
        return None;
    }
    candidate
        .filter(|candidate| prior.is_none_or(|prior| compare_cursor(prior, *candidate).is_lt()))
}

fn replay_id(
    request_id: RhiReconciliationSourceRequestId,
    prior_cursor: Option<RhiTradeSourceCursor>,
    overlap_seconds: u64,
    since_unix_seconds: u64,
) -> RhiReconciliationSourceReplayId {
    let mut digest = Sha256::new();
    digest.update(REPLAY_ID_DOMAIN);
    digest.update(request_id.as_bytes());
    match prior_cursor {
        Some(cursor) => {
            digest.update([1]);
            digest.update(cursor.created_at_unix_seconds().to_be_bytes());
            digest.update(cursor.event_id());
        }
        None => digest.update([0]),
    }
    digest.update(overlap_seconds.to_be_bytes());
    digest.update(since_unix_seconds.to_be_bytes());
    RhiReconciliationSourceReplayId(digest.finalize().into())
}

const fn failure(kind: RhiReconciliationReplayErrorKind) -> RhiReconciliationReplayError {
    RhiReconciliationReplayError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(value: u64) -> RhiTradeMutationObservedAtUnixSeconds {
        RhiTradeMutationObservedAtUnixSeconds::new(value).expect("observation")
    }

    fn record(event: u8, signature: u8, mutation: u8, content: &[u8]) -> PersistenceRecord {
        PersistenceRecord {
            mutation_id: [mutation; 32],
            trade_id: [0x11; 16],
            contract_id: "radroots.trade.proposal.v1",
            schema_version: 1,
            event_id: [event; 32],
            event_signature: [signature; 64],
            author_pubkey: [0x22; 32],
            event_kind: 3470,
            authored_at_unix_s: 1_784_347_200,
            canonical_content: content.into(),
            canonical_event_json: [b"event:".as_slice(), content].concat().into_boxed_slice(),
        }
    }

    fn fact(
        event: u8,
        signature: u8,
        mutation: u8,
        content: &[u8],
        observation: u64,
        bytes: u64,
    ) -> ReplayFact {
        ReplayFact {
            record: record(event, signature, mutation, content),
            original_bytes: bytes,
            observed_at: observed(observation),
        }
    }

    #[test]
    fn canonicalization_deduplicates_replay_and_retains_first_provenance() {
        let canonical = canonicalize(vec![
            fact(1, 2, 3, b"same", 1_784_347_202, 12),
            fact(1, 2, 3, b"same", 1_784_347_200, 10),
            fact(1, 4, 3, b"same", 1_784_347_201, 11),
        ])
        .expect("canonical replay");
        assert_eq!(canonical.facts.len(), 2);
        assert_eq!(canonical.duplicate_observations, 1);
        assert_eq!(canonical.accepted_original_bytes, 21);
        assert_eq!(
            canonical.first_observed_at.expect("first").get(),
            1_784_347_200
        );
    }

    #[test]
    fn conflicting_mutation_and_event_identity_reuse_fail_closed() {
        let mutation = canonicalize(vec![
            fact(1, 2, 3, b"first", 1_784_347_200, 10),
            fact(4, 5, 3, b"second", 1_784_347_201, 10),
        ])
        .err()
        .expect("mutation conflict");
        assert_eq!(
            mutation.kind(),
            RhiReconciliationReplayErrorKind::MutationConflict
        );

        let event = canonicalize(vec![
            fact(1, 2, 3, b"first", 1_784_347_200, 10),
            fact(1, 2, 4, b"second", 1_784_347_201, 10),
        ])
        .err()
        .expect("event conflict");
        assert_eq!(
            event.kind(),
            RhiReconciliationReplayErrorKind::SignedEventConflict
        );
    }

    #[test]
    fn pre_dedup_bound_is_exact_and_infinite_iterators_terminate() {
        let exact = ingest_bounded_facts([Ok(fact(1, 2, 3, b"one", 1_784_347_200, 10))], 1, 10)
            .expect("exact maximum");
        assert_eq!(exact.len(), 1);

        let over_bytes =
            ingest_bounded_facts([Ok(fact(1, 2, 3, b"one", 1_784_347_200, 11))], 1, 10)
                .err()
                .expect("byte maximum plus one");
        assert_eq!(
            over_bytes.kind(),
            RhiReconciliationReplayErrorKind::ResourceLimit
        );

        let mut event = 0_u8;
        let over_count = ingest_bounded_facts(
            std::iter::repeat_with(|| {
                event = event.wrapping_add(1);
                Ok(fact(event, 2, event, b"one", 1_784_347_200, 1))
            }),
            1,
            10,
        )
        .err()
        .expect("count maximum plus one");
        assert_eq!(
            over_count.kind(),
            RhiReconciliationReplayErrorKind::ResourceLimit
        );
    }

    #[test]
    fn errors_are_source_free_and_redacted() {
        let error = failure(RhiReconciliationReplayErrorKind::SignedEventConflict);
        assert!(Error::source(&error).is_none());
        assert_eq!(error.code(), "reconciliation_replay_signed_event_conflict");
        assert_eq!(
            format!("{error:?}"),
            "RhiReconciliationReplayError { kind: SignedEventConflict }"
        );
    }

    #[test]
    fn cursor_evidence_scope_requires_every_exact_dimension() {
        let exact = RhiReconciliationSourceCursorEvidence {
            source_id: "trade-primary".into(),
            trade_id: radroots_event::id::TradeId::from_bytes([0x11; 16]),
            policy_digest: [0x22; 32],
            selector_digest: [0x33; 32],
            cursor: RhiTradeSourceCursor::from_verified_parts(42, [0x44; 32]),
        };
        assert!(cursor_scope_matches(
            &exact,
            "trade-primary",
            radroots_event::id::TradeId::from_bytes([0x11; 16]),
            &[0x22; 32],
            &[0x33; 32],
        ));
        assert!(!cursor_scope_matches(
            &exact,
            "trade-secondary",
            radroots_event::id::TradeId::from_bytes([0x11; 16]),
            &[0x22; 32],
            &[0x33; 32],
        ));
        assert!(!cursor_scope_matches(
            &exact,
            "trade-primary",
            radroots_event::id::TradeId::from_bytes([0x12; 16]),
            &[0x22; 32],
            &[0x33; 32],
        ));
        assert!(!cursor_scope_matches(
            &exact,
            "trade-primary",
            radroots_event::id::TradeId::from_bytes([0x11; 16]),
            &[0x23; 32],
            &[0x33; 32],
        ));
        assert!(!cursor_scope_matches(
            &exact,
            "trade-primary",
            radroots_event::id::TradeId::from_bytes([0x11; 16]),
            &[0x22; 32],
            &[0x34; 32],
        ));
    }

    #[test]
    fn resume_overlap_and_cursor_eligibility_are_exact() {
        let prior = RhiTradeSourceCursor::from_verified_parts(500, [0x11; 32]);
        let equal = RhiTradeSourceCursor::from_verified_parts(500, [0x11; 32]);
        let older = RhiTradeSourceCursor::from_verified_parts(499, [0xff; 32]);
        let newer = RhiTradeSourceCursor::from_verified_parts(500, [0x12; 32]);
        assert_eq!(resume_since(prior, 300), 200);
        assert_eq!(resume_since(prior, 600), 0);
        assert_eq!(
            eligible_cursor(RhiTradeSourceCompletion::Complete, Some(newer), Some(prior)),
            Some(newer)
        );
        assert_eq!(
            eligible_cursor(RhiTradeSourceCompletion::Complete, Some(equal), Some(prior)),
            None
        );
        assert_eq!(
            eligible_cursor(RhiTradeSourceCompletion::Complete, Some(older), Some(prior)),
            None
        );
        assert_eq!(
            eligible_cursor(
                RhiTradeSourceCompletion::IncompleteUnavailable,
                Some(newer),
                Some(prior),
            ),
            None
        );
    }
}
