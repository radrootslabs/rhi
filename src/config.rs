//! Transitional runtime settings materialization under the sealed path context.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::RhiRuntimeContext;
use crate::features::trade_agreement_attestation::TradeAgreementAttestationPolicy;
use crate::host_nostr::Metadata;
use crate::host_runtime::{BackoffConfig, NostrServiceConfig};

fn default_replay_window_secs() -> u64 {
    24 * 60 * 60
}

fn default_replay_overlap_secs() -> u64 {
    5 * 60
}

fn default_logging_filter() -> String {
    "info".to_owned()
}

const fn default_logging_stdout() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub output_dir: PathBuf,
    pub filter: String,
    pub stdout: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
struct RawLoggingConfig {
    filter: Option<String>,
    stdout: Option<bool>,
}

impl RawLoggingConfig {
    fn into_logging_config(self, context: &RhiRuntimeContext) -> Result<LoggingConfig> {
        let filter = self.filter.unwrap_or_else(default_logging_filter);
        let filter = filter.trim();
        if filter.is_empty() {
            bail!("logging.filter must not be empty");
        }
        Ok(LoggingConfig {
            output_dir: context.context().paths().logs().to_path_buf(),
            filter: filter.to_owned(),
            stdout: self.stdout.unwrap_or_else(default_logging_stdout),
        })
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
struct RawRelaysConfig {
    urls: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
struct RawNostrConfig {
    nip89: RawNip89Config,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
struct RawNip89Config {
    identifier: Option<String>,
    extra_tags: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
struct RawServiceConfig {
    logging: LoggingConfig,
    relays: RawRelaysConfig,
    nostr: RawNostrConfig,
}

impl RawServiceConfig {
    fn into_service_config(self) -> NostrServiceConfig {
        NostrServiceConfig {
            logs_dir: self.logging.output_dir.display().to_string(),
            relays: self.relays.urls,
            nip89_identifier: self.nostr.nip89.identifier,
            nip89_extra_tags: self.nostr.nip89.extra_tags,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    #[serde(flatten)]
    pub service: NostrServiceConfig,
    pub logging: LoggingConfig,
    pub subscriber: SubscriberConfig,
    #[serde(default)]
    pub trade_agreement_attestation: TradeAgreementAttestationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberConfig {
    pub backoff: BackoffConfig,
    pub state: SubscriberStateConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
struct RawSubscriberConfig {
    backoff: BackoffConfig,
    state: RawSubscriberStateConfig,
}

impl RawSubscriberConfig {
    fn into_subscriber_config(self, context: &RhiRuntimeContext) -> SubscriberConfig {
        SubscriberConfig {
            backoff: self.backoff,
            state: self.state.into_subscriber_state_config(context),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberStateConfig {
    pub path: PathBuf,
    pub replay_window_secs: u64,
    pub replay_overlap_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct RawSubscriberStateConfig {
    #[serde(default = "default_replay_window_secs")]
    replay_window_secs: u64,
    #[serde(default = "default_replay_overlap_secs")]
    replay_overlap_secs: u64,
}

impl Default for RawSubscriberStateConfig {
    fn default() -> Self {
        Self {
            replay_window_secs: default_replay_window_secs(),
            replay_overlap_secs: default_replay_overlap_secs(),
        }
    }
}

impl RawSubscriberStateConfig {
    fn into_subscriber_state_config(self, context: &RhiRuntimeContext) -> SubscriberStateConfig {
        SubscriberStateConfig {
            path: context
                .context()
                .paths()
                .state()
                .join("trade-agreement-attestation")
                .join("state.json"),
            replay_window_secs: self.replay_window_secs,
            replay_overlap_secs: self.replay_overlap_secs,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    metadata: Metadata,
    #[serde(default)]
    logging: RawLoggingConfig,
    #[serde(default)]
    relays: RawRelaysConfig,
    #[serde(default)]
    nostr: RawNostrConfig,
    #[serde(default)]
    subscriber: RawSubscriberConfig,
    #[serde(default)]
    trade_agreement_attestation: TradeAgreementAttestationPolicy,
}

impl RawSettings {
    fn into_settings(self, context: &RhiRuntimeContext) -> Result<Settings> {
        let logging = self.logging.into_logging_config(context)?;
        let service = RawServiceConfig {
            logging: logging.clone(),
            relays: self.relays,
            nostr: self.nostr,
        }
        .into_service_config();
        Ok(Settings {
            metadata: self.metadata,
            config: Configuration {
                service,
                logging,
                subscriber: self.subscriber.into_subscriber_config(context),
                trade_agreement_attestation: self.trade_agreement_attestation,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub metadata: Metadata,
    pub config: Configuration,
}

/// Loads transitional runtime settings with all paths supplied by one sealed context.
///
/// The final versioned configuration parser is [`crate::parse_rhi_config_v1`].
/// This adapter remains only until the legacy runtime is removed in Step 168;
/// it accepts no path overrides and performs no ambient environment selection.
pub fn load_settings_from_path(path: &Path, context: &RhiRuntimeContext) -> Result<Settings> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read configuration from {}", path.display()))?;
    let settings: RawSettings =
        toml::from_str(&raw).with_context(|| format!("parse configuration {}", path.display()))?;
    let settings = settings.into_settings(context)?;
    settings.config.trade_agreement_attestation.validate()?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::{
        RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, parse_rhi_cli_v1_from,
        resolve_rhi_runtime_context,
    };

    use super::load_settings_from_path;

    fn context() -> crate::RhiRuntimeContext {
        let invocation = parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "interactive",
            "--instance",
            "default",
            "run",
        ])
        .expect("invocation");
        resolve_rhi_runtime_context(
            &RadrootsPathResolver::new(
                RadrootsPlatform::Linux,
                RadrootsHostEnvironment {
                    home_dir: Some(PathBuf::from("/home/operator")),
                    xdg_config_home: Some(PathBuf::from("/xdg/config")),
                    xdg_data_home: Some(PathBuf::from("/xdg/data")),
                    xdg_state_home: Some(PathBuf::from("/xdg/state")),
                    xdg_cache_home: Some(PathBuf::from("/xdg/cache")),
                    xdg_runtime_dir: Some(PathBuf::from("/xdg/run")),
                    ..RadrootsHostEnvironment::default()
                },
            ),
            &invocation,
        )
        .expect("context")
    }

    #[test]
    fn materializes_only_context_derived_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
[metadata]
name = "rhi-test"

[relays]
urls = ["wss://relay.example.com"]

[subscriber.state]
replay_window_secs = 123
replay_overlap_secs = 45
"#,
        )
        .expect("config");
        let settings = load_settings_from_path(&config_path, &context()).expect("settings");
        assert_eq!(
            settings.config.logging.output_dir,
            Path::new("/xdg/state/radroots/logs/services/rhi/default")
        );
        assert_eq!(
            settings.config.subscriber.state.path,
            Path::new(
                "/xdg/data/radroots/services/rhi/default/trade-agreement-attestation/state.json"
            )
        );
        assert_eq!(settings.config.subscriber.state.replay_window_secs, 123);
        assert_eq!(settings.config.subscriber.state.replay_overlap_secs, 45);
    }

    #[test]
    fn path_leaf_overrides_are_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        for (name, extra) in [
            ("logging", "[logging]\noutput_dir = \"/tmp/logs\"\n"),
            ("state", "[subscriber.state]\npath = \"/tmp/state.json\"\n"),
        ] {
            let config_path = temp.path().join(format!("{name}.toml"));
            std::fs::write(
                &config_path,
                format!("[metadata]\nname = \"rhi-test\"\n\n{extra}"),
            )
            .expect("config");
            assert!(load_settings_from_path(&config_path, &context()).is_err());
        }
    }
}
