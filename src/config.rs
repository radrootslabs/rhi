use radroots_nostr::prelude::RadrootsNostrMetadata;
use radroots_runtime::{BackoffConfig, RadrootsNostrServiceConfig};
use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub metadata: RadrootsNostrMetadata,
    pub config: Configuration,
}
