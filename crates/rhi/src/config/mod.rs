use config::{Config, ConfigError, File};
use nostr::Metadata;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use tracing::error;

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("Configuration loading failed: {0}")]
    Load(#[from] ConfigError),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Configuration {
    pub logs_dir: String,
    pub keys_path: String,
    pub generate_keys: bool,
    pub identifier: Option<String>,
    pub relays: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub metadata: Metadata,
    pub config: Configuration,
}

impl Settings {
    pub fn load(config_path: &Option<std::path::PathBuf>) -> Result<Self, SettingsError> {
        let path: &Path = config_path
            .as_deref()
            .unwrap_or_else(|| Path::new("config.toml"));

        let builder = Config::builder().add_source(File::from(path).required(true));

        match builder.build() {
            Ok(cfg) => match cfg.try_deserialize::<Settings>() {
                Ok(settings) => Ok(settings),
                Err(err) => {
                    error!("❌ Failed to deserialize configuration: {err}");
                    Err(SettingsError::Load(err))
                }
            },
            Err(err) => {
                error!(
                    "❌ Failed to load configuration from '{}': {err}",
                    path.display()
                );
                Err(SettingsError::Load(err))
            }
        }
    }
}
