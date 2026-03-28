#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use radroots_nostr::prelude::{RadrootsNostrFilter, RadrootsNostrKind, RadrootsNostrTimestamp};
use radroots_trade::listing::order::TradeOrderStatus;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

pub type SharedTradeListingState = Arc<Mutex<TradeListingState>>;

const TRADE_LISTING_STATE_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TradeOrderState {
    pub order_id: String,
    pub listing_addr: String,
    pub buyer_pubkey: String,
    pub seller_pubkey: String,
    pub status: TradeOrderStatus,
    pub seen_event_ids: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedListingState {
    pub event_id: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TradeListingState {
    #[serde(default)]
    validated_listings: HashSet<String>,
    #[serde(default)]
    validated_listing_events: HashMap<String, ValidatedListingState>,
    #[serde(default)]
    seen_non_order_event_ids: HashSet<String>,
    orders: HashMap<String, TradeOrderState>,
    last_event_created_at: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct TradeListingRuntime {
    state: SharedTradeListingState,
    config: TradeListingRuntimeConfig,
    persistence: Option<Arc<TradeListingStatePersistence>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TradeListingRuntimeConfig {
    pub state_path: PathBuf,
    pub replay_window_secs: u64,
    pub replay_overlap_secs: u64,
}

#[derive(Clone, Debug)]
struct TradeListingStatePersistence {
    path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedTradeListingState {
    version: u32,
    state: TradeListingState,
}

impl Default for TradeListingRuntimeConfig {
    fn default() -> Self {
        Self {
            state_path: PathBuf::from("state/trade-listing-state.json"),
            replay_window_secs: 24 * 60 * 60,
            replay_overlap_secs: 5 * 60,
        }
    }
}

impl Default for TradeListingRuntime {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(TradeListingState::default())),
            config: TradeListingRuntimeConfig::default(),
            persistence: None,
        }
    }
}

impl TradeListingRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn load(config: TradeListingRuntimeConfig) -> Result<Self, TradeListingRuntimeError> {
        let persistence = Arc::new(TradeListingStatePersistence::new(config.state_path.clone()));
        let state = persistence.load().await?;
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            config,
            persistence: Some(persistence),
        })
    }

    pub fn state(&self) -> SharedTradeListingState {
        Arc::clone(&self.state)
    }

    pub async fn persist(&self) -> Result<(), TradeListingRuntimeError> {
        let Some(persistence) = &self.persistence else {
            return Ok(());
        };
        let snapshot = self.state.lock().await.clone();
        persistence.persist(&snapshot).await
    }

    pub async fn mark_processed_event(
        &self,
        created_at: u32,
    ) -> Result<(), TradeListingRuntimeError> {
        {
            let mut state = self.state.lock().await;
            state.observe_event_created_at(created_at);
        }
        self.persist().await
    }

    pub async fn recovery_filter(&self, kinds: Vec<RadrootsNostrKind>) -> RadrootsNostrFilter {
        let since = {
            let state = self.state.lock().await;
            state.replay_since(
                RadrootsNostrTimestamp::now().as_secs(),
                self.config.replay_window_secs,
                self.config.replay_overlap_secs,
            )
        };
        RadrootsNostrFilter::new()
            .kinds(kinds)
            .since(RadrootsNostrTimestamp::from(since))
    }
}

impl TradeListingState {
    pub fn mark_listing_validated(&mut self, listing_addr: &str, event_id: &str) {
        self.validated_listings.insert(listing_addr.to_string());
        self.validated_listing_events.insert(
            listing_addr.to_string(),
            ValidatedListingState {
                event_id: event_id.to_string(),
            },
        );
    }

    pub fn clear_listing_validation(&mut self, listing_addr: &str) {
        self.validated_listings.remove(listing_addr);
        self.validated_listing_events.remove(listing_addr);
    }

    pub fn validated_listing_event_id(&self, listing_addr: &str) -> Option<&str> {
        self.validated_listing_events
            .get(listing_addr)
            .map(|validated| validated.event_id.as_str())
    }

    pub fn is_listing_validated(&self, listing_addr: &str) -> bool {
        self.validated_listing_event_id(listing_addr).is_some()
    }

    pub fn order_exists(&self, order_id: &str) -> bool {
        self.orders.contains_key(order_id)
    }

    pub fn get_order_mut(&mut self, order_id: &str) -> Option<&mut TradeOrderState> {
        self.orders.get_mut(order_id)
    }

    pub fn insert_order(&mut self, order: TradeOrderState) {
        self.orders.insert(order.order_id.clone(), order);
    }

    pub fn mark_event_seen(&mut self, order_id: &str, event_id: &str) -> bool {
        if let Some(state) = self.orders.get_mut(order_id) {
            state.seen_event_ids.insert(event_id.to_string())
        } else {
            false
        }
    }

    pub fn is_event_seen(&self, order_id: &str, event_id: &str) -> bool {
        self.orders
            .get(order_id)
            .map(|state| state.seen_event_ids.contains(event_id))
            .unwrap_or(false)
    }

    pub fn mark_non_order_event_seen(&mut self, event_id: &str) -> bool {
        self.seen_non_order_event_ids.insert(event_id.to_string())
    }

    pub fn is_non_order_event_seen(&self, event_id: &str) -> bool {
        self.seen_non_order_event_ids.contains(event_id)
    }

    pub fn observe_event_created_at(&mut self, created_at: u32) {
        self.last_event_created_at = Some(
            self.last_event_created_at
                .map_or(created_at, |current| current.max(created_at)),
        );
    }

    pub fn last_event_created_at(&self) -> Option<u32> {
        self.last_event_created_at
    }

    pub fn replay_since(
        &self,
        now_secs: u64,
        replay_window_secs: u64,
        replay_overlap_secs: u64,
    ) -> u64 {
        match self.last_event_created_at {
            Some(last) => u64::from(last).saturating_sub(replay_overlap_secs),
            None => now_secs.saturating_sub(replay_window_secs),
        }
    }
}

impl TradeListingStatePersistence {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    async fn load(&self) -> Result<TradeListingState, TradeListingRuntimeError> {
        if !tokio::fs::try_exists(&self.path).await? {
            return Ok(TradeListingState::default());
        }

        let payload = tokio::fs::read_to_string(&self.path).await?;
        let snapshot: PersistedTradeListingState = serde_json::from_str(&payload)?;
        if snapshot.version != TRADE_LISTING_STATE_VERSION {
            return Err(TradeListingRuntimeError::UnsupportedStateVersion(
                snapshot.version,
            ));
        }
        Ok(snapshot.state)
    }

    async fn persist(&self, state: &TradeListingState) -> Result<(), TradeListingRuntimeError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let snapshot = PersistedTradeListingState {
            version: TRADE_LISTING_STATE_VERSION,
            state: state.clone(),
        };
        let payload = serde_json::to_vec_pretty(&snapshot)?;
        let temp_path = temp_state_path(&self.path)?;
        tokio::fs::write(&temp_path, payload).await?;
        tokio::fs::rename(&temp_path, &self.path).await?;
        Ok(())
    }
}

fn temp_state_path(path: &Path) -> Result<PathBuf, TradeListingRuntimeError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| TradeListingRuntimeError::InvalidStatePath(path.to_path_buf()))?;
    Ok(path.with_file_name(format!("{}.tmp", file_name.to_string_lossy())))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TradeListingStateError {
    MissingOrder,
    InvalidTransition {
        from: TradeOrderStatus,
        to: TradeOrderStatus,
    },
}

impl core::fmt::Display for TradeListingStateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TradeListingStateError::MissingOrder => write!(f, "missing order state"),
            TradeListingStateError::InvalidTransition { from, to } => {
                write!(f, "invalid order transition: {from:?} -> {to:?}")
            }
        }
    }
}

impl std::error::Error for TradeListingStateError {}

#[derive(Debug, Error)]
pub enum TradeListingRuntimeError {
    #[error("invalid trade listing state path: {0}")]
    InvalidStatePath(PathBuf),
    #[error("unsupported trade listing state version: {0}")]
    UnsupportedStateVersion(u32),
    #[error("trade listing state io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("trade listing state json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        PersistedTradeListingState, TradeListingRuntime, TradeListingRuntimeConfig,
        TradeListingRuntimeError, TradeListingState, TradeListingStateError, TradeOrderState,
        ValidatedListingState,
    };
    use radroots_trade::listing::order::TradeOrderStatus;
    use std::collections::{HashMap, HashSet};

    fn unique_state_path(suffix: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("rhi-trade-state-{suffix}-{nanos}.json"))
    }

    #[test]
    fn state_tracks_listings_events_and_replay_anchor() {
        let mut state = TradeListingState::default();
        assert!(!state.is_listing_validated("addr"));
        state.mark_listing_validated("addr", "evt-listing-1");
        assert!(state.is_listing_validated("addr"));
        assert_eq!(
            state.validated_listing_event_id("addr"),
            Some("evt-listing-1")
        );

        let order = TradeOrderState {
            order_id: "order-1".into(),
            listing_addr: "addr".into(),
            buyer_pubkey: "buyer".into(),
            seller_pubkey: "seller".into(),
            status: TradeOrderStatus::Requested,
            seen_event_ids: Default::default(),
        };
        state.insert_order(order);
        assert!(!state.is_event_seen("order-1", "evt"));
        assert!(state.mark_event_seen("order-1", "evt"));
        assert!(state.is_event_seen("order-1", "evt"));
        assert!(!state.is_non_order_event_seen("evt-non-order"));
        assert!(state.mark_non_order_event_seen("evt-non-order"));
        assert!(state.is_non_order_event_seen("evt-non-order"));
        assert_eq!(state.replay_since(1_000, 300, 60), 700);

        state.observe_event_created_at(900);
        assert_eq!(state.last_event_created_at(), Some(900));
        assert_eq!(state.replay_since(1_000, 300, 60), 840);
    }

    #[test]
    fn state_covers_missing_order_paths_and_error_display() {
        let mut state = TradeListingState::default();
        assert!(!state.order_exists("missing"));
        assert!(state.get_order_mut("missing").is_none());
        assert!(!state.mark_event_seen("missing", "evt-1"));
        assert!(!state.is_event_seen("missing", "evt-1"));
        assert!(!state.is_non_order_event_seen("evt-2"));

        assert_eq!(
            TradeListingStateError::MissingOrder.to_string(),
            "missing order state"
        );

        let invalid = TradeListingStateError::InvalidTransition {
            from: TradeOrderStatus::Requested,
            to: TradeOrderStatus::Completed,
        };
        assert_eq!(
            invalid.to_string(),
            "invalid order transition: Requested -> Completed"
        );
    }

    #[tokio::test]
    async fn runtime_reuses_shared_trade_listing_state() {
        let runtime = TradeListingRuntime::new();
        let state = runtime.state();
        state
            .lock()
            .await
            .mark_listing_validated("addr", "evt-listing-1");

        assert!(runtime.state().lock().await.is_listing_validated("addr"));
    }

    #[tokio::test]
    async fn runtime_persists_and_loads_trade_listing_state() {
        let path = unique_state_path("roundtrip");
        let config = TradeListingRuntimeConfig {
            state_path: path.clone(),
            replay_window_secs: 600,
            replay_overlap_secs: 30,
        };
        let runtime = TradeListingRuntime::load(config.clone())
            .await
            .expect("runtime");

        {
            let state_handle = runtime.state();
            let mut state = state_handle.lock().await;
            state.mark_listing_validated("addr", "evt-listing-1");
            state.mark_non_order_event_seen("evt-validate-1");
            state.observe_event_created_at(456);
        }
        runtime.persist().await.expect("persist");

        let loaded = TradeListingRuntime::load(config).await.expect("load");
        let loaded_state_handle = loaded.state();
        let loaded_state = loaded_state_handle.lock().await;
        assert!(loaded_state.is_listing_validated("addr"));
        assert_eq!(
            loaded_state.validated_listing_event_id("addr"),
            Some("evt-listing-1")
        );
        assert!(loaded_state.is_non_order_event_seen("evt-validate-1"));
        assert_eq!(loaded_state.last_event_created_at(), Some(456));

        let _ = tokio::fs::remove_file(path).await;
    }

    #[tokio::test]
    async fn runtime_load_rejects_unsupported_snapshot_version() {
        let path = unique_state_path("version");
        let payload = PersistedTradeListingState {
            version: 99,
            state: TradeListingState::default(),
        };
        tokio::fs::write(&path, serde_json::to_vec(&payload).expect("payload"))
            .await
            .expect("write");

        let err = TradeListingRuntime::load(TradeListingRuntimeConfig {
            state_path: path.clone(),
            replay_window_secs: 600,
            replay_overlap_secs: 30,
        })
        .await
        .expect_err("unsupported snapshot should fail");
        assert!(matches!(
            err,
            TradeListingRuntimeError::UnsupportedStateVersion(99)
        ));

        let _ = tokio::fs::remove_file(path).await;
    }

    #[tokio::test]
    async fn runtime_loads_legacy_validation_state_without_trusting_it() {
        let path = unique_state_path("legacy-validation");
        let payload = PersistedTradeListingState {
            version: 1,
            state: TradeListingState {
                validated_listings: ["addr".to_string()].into_iter().collect(),
                validated_listing_events: HashMap::new(),
                seen_non_order_event_ids: HashSet::new(),
                orders: HashMap::new(),
                last_event_created_at: Some(321),
            },
        };
        tokio::fs::write(&path, serde_json::to_vec(&payload).expect("payload"))
            .await
            .expect("write");

        let loaded = TradeListingRuntime::load(TradeListingRuntimeConfig {
            state_path: path.clone(),
            replay_window_secs: 600,
            replay_overlap_secs: 30,
        })
        .await
        .expect("load");
        let loaded_state_handle = loaded.state();
        let loaded_state = loaded_state_handle.lock().await;
        assert!(!loaded_state.is_listing_validated("addr"));
        assert_eq!(loaded_state.validated_listing_event_id("addr"), None);
        assert_eq!(loaded_state.last_event_created_at(), Some(321));

        let _ = tokio::fs::remove_file(path).await;
    }

    #[test]
    fn state_can_clear_listing_validation() {
        let mut state = TradeListingState {
            validated_listings: ["addr".to_string()].into_iter().collect(),
            validated_listing_events: HashMap::from([(
                "addr".to_string(),
                ValidatedListingState {
                    event_id: "evt-listing-1".to_string(),
                },
            )]),
            seen_non_order_event_ids: HashSet::new(),
            orders: HashMap::new(),
            last_event_created_at: None,
        };
        assert!(state.is_listing_validated("addr"));
        state.clear_listing_validation("addr");
        assert!(!state.is_listing_validated("addr"));
        assert_eq!(state.validated_listing_event_id("addr"), None);
    }
}
