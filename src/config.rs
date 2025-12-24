use radroots_nostr::prelude::RadrootsNostrMetadata;
use radroots_runtime::BackoffConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configuration {
    pub logs_dir: String,
    pub relays: Vec<String>,
    #[serde(default)]
    pub subscriber: SubscriberConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriberConfig {
    #[serde(default)]
    pub backoff: BackoffConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub metadata: RadrootsNostrMetadata,
    pub config: Configuration,
}
