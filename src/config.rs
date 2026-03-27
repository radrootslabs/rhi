use radroots_nostr::prelude::RadrootsNostrMetadata;
use radroots_runtime::{BackoffConfig, RadrootsNostrServiceConfig};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configuration {
    #[serde(flatten)]
    pub service: RadrootsNostrServiceConfig,
    #[serde(default)]
    pub subscriber: SubscriberConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriberConfig {
    #[serde(default)]
    pub backoff: BackoffConfig,
    #[serde(default)]
    pub state: SubscriberStateConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberStateConfig {
    pub path: PathBuf,
    pub replay_window_secs: u64,
    pub replay_overlap_secs: u64,
}

impl Default for SubscriberStateConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("state/trade-listing-state.json"),
            replay_window_secs: 24 * 60 * 60,
            replay_overlap_secs: 5 * 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub metadata: RadrootsNostrMetadata,
    pub config: Configuration,
}
