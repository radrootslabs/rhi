#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::host_nostr::{
    Client, Event, Filter, Keys, Kind, RelayPoolNotification, SubscriptionId, Timestamp,
};
use anyhow::{Result, anyhow};
use radroots_event::envelope::kind::{TRADE_MUTATION_EVENT_KINDS, is_trade_mutation_event_kind};
use radroots_event::id::{AddressableCoordinate, EventId, MutationId, TradeId};
use radroots_event::trade::{
    TradeMutationEnvelopeV1, canonical_jcs_value, trade_mutation_from_canonical_content,
};
use radroots_identity::PublicKey;
use radroots_trade::evidence::{
    RadrootsTradeAttestationResultV1, RadrootsTradeEvidenceStateV1, RadrootsTradeMutationRecordV1,
};
use radroots_trade::model::{
    RadrootsTradeAgreementStateV1, RadrootsTradeAttestationStateV1, RadrootsTradeProjectionV1,
};
use radroots_trade::reducer::{
    RADROOTS_TRADE_REDUCER_CONTRACT_ID, RADROOTS_TRADE_REDUCER_VERSION,
    RadrootsTradeReductionInputV1, reduce_trade_records,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Mutex, watch};
use tokio::time::sleep;
use tracing::{info, warn};

pub const RHI_AGREEMENT_ATTESTATION_PROTOCOL_ID: &str = "radroots.rhi.agreement_attestation.v1";
pub const RHI_AGREEMENT_ATTESTATION_STATE_VERSION: u32 = 1;
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeMutationObservationV1 {
    pub event_id: String,
    pub event_kind: u32,
    pub event_pubkey: String,
    pub trade_id: String,
    pub mutation_id: String,
    pub content: String,
    pub observed_at_unix_s: u64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeAgreementAttestationState {
    #[serde(default)]
    seen_event_ids: BTreeSet<String>,
    #[serde(default)]
    mutation_events: BTreeMap<String, TradeMutationObservationV1>,
    #[serde(default)]
    reports_by_claim: BTreeMap<String, TradeAgreementAttestationReportV1>,
    last_event_created_at: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct TradeAgreementAttestationRuntime {
    state: Arc<Mutex<TradeAgreementAttestationState>>,
    config: TradeAgreementAttestationRuntimeConfig,
    persistence: Option<Arc<TradeAgreementAttestationStatePersistence>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TradeAgreementAttestationRuntimeConfig {
    pub state_path: PathBuf,
    pub replay_window_secs: u64,
    pub replay_overlap_secs: u64,
}

#[derive(Clone, Debug)]
struct TradeAgreementAttestationStatePersistence {
    path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedTradeAgreementAttestationState {
    version: u32,
    state: TradeAgreementAttestationState,
}

#[derive(Debug, Error)]
pub enum TradeAgreementAttestationError {
    #[error("event kind not supported")]
    UnsupportedKind,
    #[error("invalid event author")]
    InvalidEventAuthor,
    #[error("trade mutation is missing mutation_id")]
    MissingMutationId,
    #[error("agreement claim is missing")]
    MissingAgreementClaim,
    #[error("attestation policy is missing {0}")]
    MissingValidatorSetBinding(&'static str),
    #[error("attestation policy has invalid {0}")]
    InvalidValidatorSetBinding(&'static str),
    #[error("invalid configured hash field")]
    InvalidHashField,
    #[error("invalid signed event")]
    InvalidSignedEvent,
    #[error("trade protocol error: {0}")]
    TradeProtocol(#[from] radroots_event::trade::TradeProtocolError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("state error: {0}")]
    State(#[from] TradeAgreementAttestationRuntimeError),
}

#[derive(Debug, Error)]
pub enum TradeAgreementAttestationRuntimeError {
    #[error("state path is invalid: {0}")]
    InvalidStatePath(PathBuf),
    #[error("state version {0} is unsupported")]
    UnsupportedStateVersion(u32),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl Default for TradeAgreementAttestationRuntimeConfig {
    fn default() -> Self {
        Self {
            state_path: crate::paths::default_subscriber_state_path_for_process()
                .expect("resolve canonical rhi agreement-attestation state path"),
            replay_window_secs: 24 * 60 * 60,
            replay_overlap_secs: 5 * 60,
        }
    }
}

impl Default for TradeAgreementAttestationRuntime {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(TradeAgreementAttestationState::default())),
            config: TradeAgreementAttestationRuntimeConfig::default(),
            persistence: None,
        }
    }
}

impl TradeAgreementAttestationRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn load(
        config: TradeAgreementAttestationRuntimeConfig,
    ) -> Result<Self, TradeAgreementAttestationRuntimeError> {
        let persistence = Arc::new(TradeAgreementAttestationStatePersistence::new(
            config.state_path.clone(),
        ));
        let state = persistence.load().await?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            config,
            persistence: Some(persistence),
        })
    }

    pub fn state(&self) -> Arc<Mutex<TradeAgreementAttestationState>> {
        Arc::clone(&self.state)
    }

    pub async fn persist(&self) -> Result<(), TradeAgreementAttestationRuntimeError> {
        let Some(persistence) = &self.persistence else {
            return Ok(());
        };
        let snapshot = self.state.lock().await.clone();
        persistence.persist(&snapshot).await
    }

    pub async fn mark_processed_event(
        &self,
        created_at: u32,
    ) -> Result<(), TradeAgreementAttestationRuntimeError> {
        {
            let mut state = self.state.lock().await;
            state.observe_event_created_at(created_at);
        }
        self.persist().await
    }

    pub async fn recovery_filter(&self, kinds: Vec<Kind>) -> Filter {
        let since = {
            let state = self.state.lock().await;
            state.replay_since(
                Timestamp::now().as_secs(),
                self.config.replay_window_secs,
                self.config.replay_overlap_secs,
            )
        };
        Filter::new().kinds(kinds).since(Timestamp::from(since))
    }

    pub async fn reports(&self) -> Vec<TradeAgreementAttestationReportV1> {
        self.state
            .lock()
            .await
            .reports_by_claim
            .values()
            .cloned()
            .collect()
    }

    async fn observe_mutation_event(
        &self,
        event: &Event,
        mutation: &TradeMutationEnvelopeV1,
        mutation_id: &MutationId,
        kind: u32,
    ) -> Result<bool, TradeAgreementAttestationRuntimeError> {
        let observation = TradeMutationObservationV1 {
            event_id: event.id.to_hex(),
            event_kind: kind,
            event_pubkey: event.pubkey.to_hex(),
            trade_id: mutation.trade_id.to_hex(),
            mutation_id: mutation_id.to_hex(),
            content: event.content.clone(),
            observed_at_unix_s: event.created_at.as_secs(),
        };
        let mut state = self.state.lock().await;
        if !state.seen_event_ids.insert(observation.event_id.clone()) {
            return Ok(false);
        }
        state
            .mutation_events
            .insert(observation.mutation_id.clone(), observation);
        Ok(true)
    }

    async fn reduce_trade(
        &self,
        trade_id: &TradeId,
    ) -> Result<RadrootsTradeProjectionV1, TradeAgreementAttestationError> {
        let observations = {
            let state = self.state.lock().await;
            state
                .mutation_events
                .values()
                .filter(|observation| observation.trade_id == trade_id.to_hex().as_str())
                .cloned()
                .collect::<Vec<_>>()
        };
        let mutations = observations
            .iter()
            .map(|observation| {
                let mutation = trade_mutation_from_canonical_content(observation.content.as_str())?;
                let transport_event_id = EventId::parse(observation.event_id.as_str())
                    .map(Some)
                    .map_err(|_| TradeAgreementAttestationError::InvalidSignedEvent)?;
                Ok(RadrootsTradeMutationRecordV1::new(
                    transport_event_id,
                    mutation,
                ))
            })
            .collect::<Result<Vec<_>, TradeAgreementAttestationError>>()?;
        let input = RadrootsTradeReductionInputV1::new(*trade_id)
            .with_evidence_state(RadrootsTradeEvidenceStateV1::Complete)
            .with_mutations(mutations);
        Ok(reduce_trade_records(input))
    }

    async fn store_report(
        &self,
        report: TradeAgreementAttestationReportV1,
    ) -> Result<(), TradeAgreementAttestationRuntimeError> {
        {
            let mut state = self.state.lock().await;
            state
                .reports_by_claim
                .insert(report.statement.claim_mutation_id.clone(), report);
        }
        self.persist().await
    }
}

impl TradeAgreementAttestationState {
    pub fn report_for_claim(
        &self,
        claim_mutation_id: &str,
    ) -> Option<&TradeAgreementAttestationReportV1> {
        self.reports_by_claim.get(claim_mutation_id)
    }

    pub fn observed_mutation_count(&self) -> usize {
        self.mutation_events.len()
    }

    fn observe_event_created_at(&mut self, created_at: u32) {
        self.last_event_created_at = Some(
            self.last_event_created_at
                .map_or(created_at, |current| current.max(created_at)),
        );
    }

    fn replay_since(&self, now: u64, replay_window_secs: u64, replay_overlap_secs: u64) -> u64 {
        let window_start = now.saturating_sub(replay_window_secs);
        match self.last_event_created_at {
            Some(last) => u64::from(last).saturating_sub(replay_overlap_secs),
            None => window_start,
        }
    }
}

impl TradeAgreementAttestationStatePersistence {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    async fn load(
        &self,
    ) -> Result<TradeAgreementAttestationState, TradeAgreementAttestationRuntimeError> {
        if !self.path.exists() {
            return Ok(TradeAgreementAttestationState::default());
        }
        let payload = tokio::fs::read_to_string(&self.path).await?;
        let snapshot: PersistedTradeAgreementAttestationState = serde_json::from_str(&payload)?;
        if snapshot.version != RHI_AGREEMENT_ATTESTATION_STATE_VERSION {
            return Err(
                TradeAgreementAttestationRuntimeError::UnsupportedStateVersion(snapshot.version),
            );
        }
        Ok(snapshot.state)
    }

    async fn persist(
        &self,
        state: &TradeAgreementAttestationState,
    ) -> Result<(), TradeAgreementAttestationRuntimeError> {
        let parent = self.path.parent().ok_or_else(|| {
            TradeAgreementAttestationRuntimeError::InvalidStatePath(self.path.clone())
        })?;
        tokio::fs::create_dir_all(parent).await?;
        let snapshot = PersistedTradeAgreementAttestationState {
            version: RHI_AGREEMENT_ATTESTATION_STATE_VERSION,
            state: state.clone(),
        };
        let payload = serde_json::to_vec_pretty(&snapshot)?;
        let temp = temp_state_path(&self.path)?;
        tokio::fs::write(&temp, payload).await?;
        tokio::fs::rename(temp, &self.path).await?;
        Ok(())
    }
}

fn temp_state_path(path: &Path) -> Result<PathBuf, TradeAgreementAttestationRuntimeError> {
    let parent = path.parent().ok_or_else(|| {
        TradeAgreementAttestationRuntimeError::InvalidStatePath(path.to_path_buf())
    })?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            TradeAgreementAttestationRuntimeError::InvalidStatePath(path.to_path_buf())
        })?;
    Ok(parent.join(format!(".{file_name}.tmp")))
}

pub async fn handle_trade_mutation_event(
    event: Event,
    runtime: TradeAgreementAttestationRuntime,
    policy: &TradeAgreementAttestationPolicy,
) -> Result<Option<TradeAgreementAttestationReportV1>, TradeAgreementAttestationError> {
    policy.validate()?;
    let kind = event_kind_u32(&event)?;
    if !is_trade_mutation_event_kind(kind) {
        return Err(TradeAgreementAttestationError::UnsupportedKind);
    }
    let mutation = trade_mutation_from_canonical_content(event.content.as_str())?;
    if mutation.mutation_kind().nostr_kind() != kind {
        return Err(TradeAgreementAttestationError::UnsupportedKind);
    }
    let event_author = PublicKey::from_hex(&event.pubkey.to_hex())
        .map_err(|_| TradeAgreementAttestationError::InvalidSignedEvent)?;
    if event_author != mutation.author_pubkey {
        return Err(TradeAgreementAttestationError::InvalidEventAuthor);
    }
    let mutation_id = mutation
        .mutation_id
        .ok_or(TradeAgreementAttestationError::MissingMutationId)?;
    if !runtime
        .observe_mutation_event(&event, &mutation, &mutation_id, kind)
        .await?
    {
        return Ok(None);
    }
    let projection = runtime.reduce_trade(&mutation.trade_id).await?;
    let Some(claim_id) = projection
        .active_agreement_claim_ids()
        .iter()
        .find(|claim_id| **claim_id == mutation_id)
        .or_else(|| projection.active_agreement_claim_ids().first())
        .cloned()
    else {
        return Ok(None);
    };
    let report = attest_projection_claim(&projection, &claim_id, policy)?;
    runtime.store_report(report.clone()).await?;
    Ok(Some(report))
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

fn event_kind_u32(event: &Event) -> Result<u32, TradeAgreementAttestationError> {
    match event.kind {
        Kind::Custom(value) => Ok(u32::from(value)),
        _ => Err(TradeAgreementAttestationError::UnsupportedKind),
    }
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

fn map_notification_recv_result(
    result: Result<RelayPoolNotification, tokio::sync::broadcast::error::RecvError>,
) -> Result<RelayPoolNotification, ()> {
    result.map_err(|_| ())
}

async fn subscribe_io(client: &Client, filter: Filter) -> Result<SubscriptionId> {
    client.subscribe(filter).await.map_err(Into::into)
}

async fn unsubscribe_io(client: &Client, subscription_id: &SubscriptionId) {
    client.unsubscribe(subscription_id).await;
}

fn should_delay_before_event_handle() -> bool {
    cfg!(all(debug_assertions, not(test)))
}

async fn process_event_notification(
    event: Event,
    runtime: TradeAgreementAttestationRuntime,
    policy: TradeAgreementAttestationPolicy,
) -> Result<()> {
    let created_at = u32::try_from(event.created_at.as_secs()).unwrap_or(u32::MAX);
    if should_delay_before_event_handle() {
        sleep(Duration::from_millis(200)).await;
    }
    match handle_trade_mutation_event(event, runtime.clone(), &policy).await {
        Ok(_) | Err(TradeAgreementAttestationError::UnsupportedKind) => {
            runtime.mark_processed_event(created_at).await?;
            Ok(())
        }
        Err(error) => {
            warn!("rhi agreement attestation rejected event: {error}");
            runtime.mark_processed_event(created_at).await?;
            Ok(())
        }
    }
}

pub async fn subscriber(
    client: Client,
    _keys: Keys,
    runtime: TradeAgreementAttestationRuntime,
    policy: TradeAgreementAttestationPolicy,
    mut stop_rx: watch::Receiver<bool>,
) -> Result<()> {
    let subscribed_kinds = trade_mutation_subscription_kinds();
    info!(
        "Starting subscriber for release-product trade mutation kinds: {:?}",
        subscribed_kinds
    );

    let kinds: Vec<Kind> = subscribed_kinds
        .iter()
        .map(|kind| u16::try_from(*kind).expect("trade mutation kinds fit in nostr custom range"))
        .map(Kind::Custom)
        .collect();
    let filter = runtime.recovery_filter(kinds).await;

    if *stop_rx.borrow() {
        return Ok(());
    }

    let subscription_id = subscribe_io(&client, filter).await?;
    let sdk_client = client.clone().into_inner();
    let mut notifications = sdk_client.notifications();
    let mut notifications_closed = false;

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                break;
            }
            msg = async {
                map_notification_recv_result(notifications.recv().await)
            } => {
                let n = match msg {
                    Ok(n) => n,
                    Err(_) => {
                        notifications_closed = true;
                        break;
                    }
                };

                if let RelayPoolNotification::Event { event, .. } = n {
                    let event = (*event).clone();
                    process_event_notification(event, runtime.clone(), policy.clone()).await?;
                }
            }
        }
    }

    unsubscribe_io(&client, &subscription_id).await;
    if notifications_closed {
        return Err(anyhow!(
            "rhi agreement attestation subscriber notifications closed"
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeAgreementAttestationSmokeRequest {
    pub protocol_id: String,
    pub operation: TradeAgreementAttestationSmokeOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeAgreementAttestationSmokeOperation {
    Health,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeAgreementAttestationSmokeResponse {
    pub ok: bool,
    pub protocol_id: String,
    pub operation: TradeAgreementAttestationSmokeOperation,
    pub worker_name: String,
    pub worker_version: String,
    pub capabilities: Vec<String>,
    pub error: Option<String>,
}

pub async fn run_smoke_cli_command(command: crate::cli::Command) -> anyhow::Result<()> {
    let crate::cli::Command::AttestationSmoke { input, output } = command;
    let request_bytes = read_input(input.as_deref())?;
    let response = handle_smoke_request_bytes(&request_bytes).await;
    let response_bytes = serde_json::to_vec_pretty(&response)?;
    write_output(output.as_deref(), &response_bytes)?;
    if response.ok {
        Ok(())
    } else {
        Err(anyhow!(
            "{}",
            response
                .error
                .as_deref()
                .unwrap_or("attestation smoke request failed")
        ))
    }
}

pub async fn handle_smoke_request_bytes(bytes: &[u8]) -> TradeAgreementAttestationSmokeResponse {
    match serde_json::from_slice::<TradeAgreementAttestationSmokeRequest>(bytes) {
        Ok(request) if request.protocol_id == RHI_AGREEMENT_ATTESTATION_PROTOCOL_ID => {
            TradeAgreementAttestationSmokeResponse {
                ok: true,
                protocol_id: request.protocol_id,
                operation: request.operation,
                worker_name: "rhi".to_owned(),
                worker_version: env!("CARGO_PKG_VERSION").to_owned(),
                capabilities: vec![
                    "release_product_trade_mutation_observation".to_owned(),
                    "agreement_claim_attestation_report".to_owned(),
                    "no_agreement_authority".to_owned(),
                ],
                error: None,
            }
        }
        Ok(request) => TradeAgreementAttestationSmokeResponse {
            ok: false,
            protocol_id: request.protocol_id,
            operation: request.operation,
            worker_name: "rhi".to_owned(),
            worker_version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: Vec::new(),
            error: Some("invalid protocol id".to_owned()),
        },
        Err(error) => TradeAgreementAttestationSmokeResponse {
            ok: false,
            protocol_id: RHI_AGREEMENT_ATTESTATION_PROTOCOL_ID.to_owned(),
            operation: TradeAgreementAttestationSmokeOperation::Health,
            worker_name: "rhi".to_owned(),
            worker_version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: Vec::new(),
            error: Some(error.to_string()),
        },
    }
}

fn read_input(path: Option<&Path>) -> anyhow::Result<Vec<u8>> {
    match path {
        Some(path) => std::fs::read(path).map_err(anyhow::Error::from),
        None => std::io::read_to_string(std::io::stdin())
            .map(|value| value.into_bytes())
            .map_err(anyhow::Error::from),
    }
}

fn write_output(path: Option<&Path>, bytes: &[u8]) -> anyhow::Result<()> {
    match path {
        Some(path) => std::fs::write(path, bytes).map_err(anyhow::Error::from),
        None => {
            println!("{}", String::from_utf8_lossy(bytes));
            Ok(())
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        RHI_AGREEMENT_ATTESTATION_PROTOCOL_ID, TradeAgreementAttestationRuntime,
        TradeAgreementAttestationRuntimeConfig, TradeAgreementAttestationSmokeOperation,
        TradeAgreementAttestationSmokeRequest, handle_smoke_request_bytes,
    };
    #[tokio::test]
    async fn runtime_persists_and_loads_attestation_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config = TradeAgreementAttestationRuntimeConfig {
            state_path: temp.path().join("state.json"),
            replay_window_secs: 100,
            replay_overlap_secs: 10,
        };
        let runtime = TradeAgreementAttestationRuntime::load(config.clone())
            .await
            .expect("load");
        {
            let state = runtime.state();
            state.lock().await.observe_event_created_at(42);
        }
        runtime.persist().await.expect("persist");
        let loaded = TradeAgreementAttestationRuntime::load(config)
            .await
            .expect("load persisted");
        assert_eq!(loaded.state().lock().await.replay_since(100, 100, 10), 32);
    }

    #[tokio::test]
    async fn smoke_request_reports_optional_capabilities() {
        let request = TradeAgreementAttestationSmokeRequest {
            protocol_id: RHI_AGREEMENT_ATTESTATION_PROTOCOL_ID.to_owned(),
            operation: TradeAgreementAttestationSmokeOperation::Health,
        };
        let response =
            handle_smoke_request_bytes(&serde_json::to_vec(&request).expect("json")).await;
        assert!(response.ok);
        assert!(
            response
                .capabilities
                .contains(&"no_agreement_authority".to_owned())
        );
    }
}
