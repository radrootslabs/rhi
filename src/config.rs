use anyhow::{Context, Result, bail};
use radroots_nostr::prelude::RadrootsNostrMetadata;
use radroots_runtime::{BackoffConfig, RadrootsNostrServiceConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::features::trade_validation_receipt::TradeValidationReceiptProverPolicy;
use crate::paths::{
    RhiRuntimePaths, default_subscriber_state_path_for_process, resolve_runtime_paths_with_resolver,
};

fn default_replay_window_secs() -> u64 {
    24 * 60 * 60
}

fn default_replay_overlap_secs() -> u64 {
    5 * 60
}

fn default_logging_filter() -> String {
    "info".to_owned()
}

fn default_logging_stdout() -> bool {
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
    pub output_dir: Option<PathBuf>,
    pub filter: Option<String>,
    pub stdout: Option<bool>,
}

impl RawLoggingConfig {
    fn into_logging_config(self, paths: &RhiRuntimePaths) -> Result<LoggingConfig> {
        let filter = self.filter.unwrap_or_else(default_logging_filter);
        let filter = filter.trim();
        if filter.is_empty() {
            bail!("logging.filter must not be empty");
        }

        Ok(LoggingConfig {
            output_dir: self.output_dir.unwrap_or_else(|| paths.logs_dir.clone()),
            filter: filter.to_owned(),
            stdout: self.stdout.unwrap_or_else(default_logging_stdout),
        })
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
struct RawRelaysConfig {
    pub urls: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
struct RawNostrConfig {
    pub nip89: RawNip89Config,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
struct RawNip89Config {
    pub identifier: Option<String>,
    pub extra_tags: Vec<Vec<String>>,
}

#[derive(Debug, Clone)]
struct RawServiceConfig {
    pub logging: LoggingConfig,
    pub relays: RawRelaysConfig,
    pub nostr: RawNostrConfig,
}

impl RawServiceConfig {
    fn into_service_config(self) -> RadrootsNostrServiceConfig {
        RadrootsNostrServiceConfig {
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
    pub service: RadrootsNostrServiceConfig,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub subscriber: SubscriberConfig,
    #[serde(default)]
    pub trade_validation_receipt: TradeValidationReceiptProverPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriberConfig {
    #[serde(default)]
    pub backoff: BackoffConfig,
    #[serde(default)]
    pub state: SubscriberStateConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default, deny_unknown_fields)]
struct RawSubscriberConfig {
    #[serde(default)]
    pub backoff: BackoffConfig,
    #[serde(default)]
    pub state: RawSubscriberStateConfig,
}

impl RawSubscriberConfig {
    fn into_subscriber_config(self, paths: &RhiRuntimePaths) -> SubscriberConfig {
        SubscriberConfig {
            backoff: self.backoff,
            state: self.state.into_subscriber_state_config(paths),
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
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_replay_window_secs")]
    pub replay_window_secs: u64,
    #[serde(default = "default_replay_overlap_secs")]
    pub replay_overlap_secs: u64,
}

impl Default for RawSubscriberStateConfig {
    fn default() -> Self {
        Self {
            path: None,
            replay_window_secs: default_replay_window_secs(),
            replay_overlap_secs: default_replay_overlap_secs(),
        }
    }
}

impl RawSubscriberStateConfig {
    fn into_subscriber_state_config(self, paths: &RhiRuntimePaths) -> SubscriberStateConfig {
        SubscriberStateConfig {
            path: self
                .path
                .unwrap_or_else(|| paths.subscriber_state_path.clone()),
            replay_window_secs: self.replay_window_secs,
            replay_overlap_secs: self.replay_overlap_secs,
        }
    }
}

impl Default for SubscriberStateConfig {
    fn default() -> Self {
        Self {
            path: default_subscriber_state_path_for_process()
                .expect("resolve canonical rhi subscriber state path"),
            replay_window_secs: default_replay_window_secs(),
            replay_overlap_secs: default_replay_overlap_secs(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    pub metadata: RadrootsNostrMetadata,
    #[serde(default)]
    pub logging: RawLoggingConfig,
    #[serde(default)]
    pub relays: RawRelaysConfig,
    #[serde(default)]
    pub nostr: RawNostrConfig,
    #[serde(default)]
    pub subscriber: RawSubscriberConfig,
    #[serde(default)]
    pub trade_validation_receipt: TradeValidationReceiptProverPolicy,
}

impl RawSettings {
    fn into_settings(self, paths: &RhiRuntimePaths) -> Result<Settings> {
        let logging = self.logging.into_logging_config(paths)?;
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
                subscriber: self.subscriber.into_subscriber_config(paths),
                trade_validation_receipt: self.trade_validation_receipt,
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub metadata: RadrootsNostrMetadata,
    pub config: Configuration,
}

fn load_settings_from_path_with_resolver(
    path: &Path,
    resolver: &radroots_runtime_paths::RadrootsPathResolver,
    profile: radroots_runtime_paths::RadrootsPathProfile,
    repo_local_root: Option<&Path>,
) -> Result<Settings> {
    let paths = resolve_runtime_paths_with_resolver(resolver, profile, repo_local_root)?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read configuration from {}", path.display()))?;
    let settings: RawSettings =
        toml::from_str(&raw).with_context(|| format!("parse configuration {}", path.display()))?;
    settings.into_settings(&paths)
}

pub fn load_settings_from_path(path: &Path) -> Result<Settings> {
    let (profile, repo_local_root) = crate::paths::process_path_selection()?;
    load_settings_from_path_with_resolver(
        path,
        &radroots_runtime_paths::RadrootsPathResolver::current(),
        profile,
        repo_local_root.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::load_settings_from_path_with_resolver;
    use crate::features::trade_validation_receipt::TradeValidationReceiptProverBackend;
    use crate::paths::{
        default_subscriber_state_path_for_process, resolve_runtime_paths_with_resolver,
        runtime_contract_with_resolver,
    };
    use radroots_runtime_paths::{
        RadrootsHostEnvironment, RadrootsPathOverrides, RadrootsPathProfile, RadrootsPathResolver,
        RadrootsPlatform, RadrootsRuntimeNamespace,
    };
    use radroots_sp1_host_trade::RadrootsSp1TradeProofMode;
    use std::path::PathBuf;

    fn linux_resolver() -> RadrootsPathResolver {
        RadrootsPathResolver::new(
            RadrootsPlatform::Linux,
            RadrootsHostEnvironment {
                home_dir: Some(PathBuf::from("/home/treesap")),
                ..RadrootsHostEnvironment::default()
            },
        )
    }

    #[test]
    fn worker_namespace_uses_canonical_interactive_roots() {
        let namespace = RadrootsRuntimeNamespace::worker("rhi").expect("worker namespace");
        let namespaced = linux_resolver()
            .resolve(
                RadrootsPathProfile::InteractiveUser,
                &RadrootsPathOverrides::default(),
            )
            .expect("interactive_user roots")
            .namespaced(&namespace);

        assert_eq!(
            namespaced.config,
            PathBuf::from("/home/treesap/.radroots/config/workers/rhi")
        );
        assert_eq!(
            namespaced.data,
            PathBuf::from("/home/treesap/.radroots/data/workers/rhi")
        );
        assert_eq!(
            namespaced.logs,
            PathBuf::from("/home/treesap/.radroots/logs/workers/rhi")
        );
        assert_eq!(
            namespaced.secrets,
            PathBuf::from("/home/treesap/.radroots/secrets/workers/rhi")
        );
    }

    #[test]
    fn runtime_paths_follow_interactive_user_contract() {
        let paths = resolve_runtime_paths_with_resolver(
            &linux_resolver(),
            RadrootsPathProfile::InteractiveUser,
            None,
        )
        .expect("interactive_user paths should resolve");

        assert_eq!(
            paths.config_path,
            PathBuf::from("/home/treesap/.radroots/config/workers/rhi/config.toml")
        );
        assert_eq!(
            paths.logs_dir,
            PathBuf::from("/home/treesap/.radroots/logs/workers/rhi")
        );
        assert_eq!(
            paths.identity_path,
            PathBuf::from("/home/treesap/.radroots/secrets/workers/rhi/identity.secret.json")
        );
        assert_eq!(
            paths.subscriber_state_path,
            PathBuf::from("/home/treesap/.radroots/data/workers/rhi/trade-listing/state.json")
        );
    }

    #[test]
    fn runtime_paths_follow_service_host_contract() {
        let resolver =
            RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default());
        let paths =
            resolve_runtime_paths_with_resolver(&resolver, RadrootsPathProfile::ServiceHost, None)
                .expect("service_host paths should resolve");

        assert_eq!(
            paths.config_path,
            PathBuf::from("/etc/radroots/workers/rhi/config.toml")
        );
        assert_eq!(
            paths.logs_dir,
            PathBuf::from("/var/log/radroots/workers/rhi")
        );
        assert_eq!(
            paths.identity_path,
            PathBuf::from("/etc/radroots/secrets/workers/rhi/identity.secret.json")
        );
        assert_eq!(
            paths.subscriber_state_path,
            PathBuf::from("/var/lib/radroots/workers/rhi/trade-listing/state.json")
        );
    }

    #[test]
    fn runtime_paths_follow_repo_local_contract() {
        let repo_local_root = PathBuf::from("/repo/.local/radroots/dev/rhi");
        let paths = resolve_runtime_paths_with_resolver(
            &linux_resolver(),
            RadrootsPathProfile::RepoLocal,
            Some(repo_local_root.as_path()),
        )
        .expect("repo_local paths should resolve");

        assert_eq!(
            paths.config_path,
            repo_local_root.join("config/workers/rhi/config.toml")
        );
        assert_eq!(paths.logs_dir, repo_local_root.join("logs/workers/rhi"));
        assert_eq!(
            paths.identity_path,
            repo_local_root.join("secrets/workers/rhi/identity.secret.json")
        );
        assert_eq!(
            paths.subscriber_state_path,
            repo_local_root.join("data/workers/rhi/trade-listing/state.json")
        );
    }

    #[test]
    fn load_settings_materializes_profile_defaults_when_paths_are_omitted() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
[metadata]
name = "rhi-test"

[relays]
urls = ["wss://relay.example.com"]

[nostr.nip89]
identifier = "rhi"

[subscriber.state]
replay_window_secs = 123
replay_overlap_secs = 45
"#,
        )
        .expect("write config");

        let settings = load_settings_from_path_with_resolver(
            &config_path,
            &linux_resolver(),
            RadrootsPathProfile::InteractiveUser,
            None,
        )
        .expect("load settings");

        assert_eq!(
            settings.config.service.logs_dir,
            "/home/treesap/.radroots/logs/workers/rhi"
        );
        assert_eq!(
            settings.config.logging.output_dir,
            PathBuf::from("/home/treesap/.radroots/logs/workers/rhi")
        );
        assert_eq!(settings.config.logging.filter, "info");
        assert!(settings.config.logging.stdout);
        assert_eq!(
            settings.config.service.relays,
            vec!["wss://relay.example.com"]
        );
        assert_eq!(
            settings.config.service.nip89_identifier.as_deref(),
            Some("rhi")
        );
        assert_eq!(
            settings.config.subscriber.state.path,
            PathBuf::from("/home/treesap/.radroots/data/workers/rhi/trade-listing/state.json")
        );
        assert_eq!(settings.config.subscriber.state.replay_window_secs, 123);
        assert_eq!(settings.config.subscriber.state.replay_overlap_secs, 45);
        assert_eq!(
            settings.config.trade_validation_receipt.backend,
            TradeValidationReceiptProverBackend::Disabled
        );
        assert_eq!(
            settings.config.trade_validation_receipt.proof_mode,
            RadrootsSp1TradeProofMode::None
        );
    }

    #[test]
    fn load_settings_parses_trade_validation_receipt_policy() {
        let temp = tempfile::tempdir().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
[metadata]
name = "rhi-test"

[logging]
output_dir = "logs/rhi"
filter = "warn"
stdout = false

[relays]
urls = ["wss://relay.example.com"]

[nostr.nip89]
identifier = "rhi"
extra_tags = [["t", "radroots"]]

[subscriber.backoff]
base_ms = 10
max_ms = 100
factor = 3
jitter_ms = 5

[subscriber.state]
path = "state/trade-listing.json"

[trade_validation_receipt]
backend = "deterministic_none"
proof_mode = "none"
"#,
        )
        .expect("write config");

        let settings = load_settings_from_path_with_resolver(
            &config_path,
            &linux_resolver(),
            RadrootsPathProfile::InteractiveUser,
            None,
        )
        .expect("load settings");

        assert_eq!(settings.config.service.logs_dir, "logs/rhi");
        assert_eq!(
            settings.config.logging.output_dir,
            PathBuf::from("logs/rhi")
        );
        assert_eq!(settings.config.logging.filter, "warn");
        assert!(!settings.config.logging.stdout);
        assert_eq!(
            settings.config.service.relays,
            vec!["wss://relay.example.com"]
        );
        assert_eq!(
            settings.config.service.nip89_identifier.as_deref(),
            Some("rhi")
        );
        assert_eq!(
            settings.config.service.nip89_extra_tags,
            vec![vec!["t".to_owned(), "radroots".to_owned()]]
        );
        assert_eq!(settings.config.subscriber.backoff.base_ms, 10);
        assert_eq!(settings.config.subscriber.backoff.max_ms, 100);
        assert_eq!(settings.config.subscriber.backoff.factor, 3);
        assert_eq!(settings.config.subscriber.backoff.jitter_ms, 5);
        assert_eq!(
            settings.config.subscriber.state.path,
            PathBuf::from("state/trade-listing.json")
        );
        assert_eq!(
            settings.config.trade_validation_receipt.backend,
            TradeValidationReceiptProverBackend::DeterministicNone
        );
        assert_eq!(
            settings.config.trade_validation_receipt.proof_mode,
            RadrootsSp1TradeProofMode::None
        );
    }

    #[test]
    fn old_config_roots_are_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        for (name, body, needle) in [
            (
                "config-root",
                r#"
[metadata]
name = "rhi-test"

[config]
relays = ["wss://relay.example.com"]
"#,
                "unknown field `config`",
            ),
            (
                "config-subscriber-backoff",
                r#"
[metadata]
name = "rhi-test"

[config.subscriber.backoff]
base_ms = 10
"#,
                "unknown field `config`",
            ),
            (
                "config-subscriber-state",
                r#"
[metadata]
name = "rhi-test"

[config.subscriber.state]
replay_window_secs = 10
"#,
                "unknown field `config`",
            ),
            (
                "config-trade-validation-receipt",
                r#"
[metadata]
name = "rhi-test"

[config.trade_validation_receipt]
backend = "deterministic_none"
proof_mode = "none"
"#,
                "unknown field `config`",
            ),
        ] {
            let config_path = temp.path().join(format!("{name}.toml"));
            std::fs::write(&config_path, body).expect("write config");

            let error = load_settings_from_path_with_resolver(
                &config_path,
                &linux_resolver(),
                RadrootsPathProfile::InteractiveUser,
                None,
            )
            .expect_err("old config root must fail");
            let message = format!("{error:#}");
            assert!(message.contains(needle), "{message}");
        }
    }

    #[test]
    fn default_subscriber_state_path_is_canonical_for_current_process() {
        let path =
            default_subscriber_state_path_for_process().expect("resolve current process defaults");
        assert!(path.ends_with("trade-listing/state.json"));
    }

    #[test]
    fn runtime_contract_output_matches_interactive_user_contract() {
        let contract = runtime_contract_with_resolver(
            &linux_resolver(),
            RadrootsPathProfile::InteractiveUser,
            None,
        )
        .expect("interactive-user contract");

        assert_eq!(contract.active_profile, "interactive_user");
        assert_eq!(contract.path_overrides.profile_source, "caller");
        assert_eq!(contract.path_overrides.root_source, "host_defaults");
        assert_eq!(contract.path_overrides.repo_local_root, None);
        assert_eq!(contract.path_overrides.repo_local_root_source, None);
        assert_eq!(
            contract.path_overrides.subordinate_path_override_source,
            "config_artifact"
        );
        assert_eq!(
            contract.path_overrides.subordinate_path_override_keys,
            vec![
                "logging.output_dir".to_owned(),
                "subscriber.state.path".to_owned(),
            ]
        );
        assert_eq!(
            contract.allowed_profiles,
            vec![
                "interactive_user".to_owned(),
                "service_host".to_owned(),
                "repo_local".to_owned(),
            ]
        );
        assert_eq!(contract.default_shared_secret_backend, "encrypted_file");
        assert_eq!(
            contract.allowed_shared_secret_backends,
            vec!["encrypted_file".to_owned()]
        );
        assert_eq!(
            contract.migration.posture,
            "explicit_operator_import_required"
        );
        assert_eq!(contract.migration.state, "ready");
        assert_eq!(contract.migration.silent_startup_relocation, false);
        assert_eq!(
            contract.migration.compatibility_window,
            "detect_and_report_only"
        );
        assert!(contract.migration.detected_legacy_paths.is_empty());
        assert_eq!(
            contract.canonical_config_path,
            PathBuf::from("/home/treesap/.radroots/config/workers/rhi/config.toml")
        );
        assert_eq!(
            contract.canonical_logs_dir,
            PathBuf::from("/home/treesap/.radroots/logs/workers/rhi")
        );
        assert_eq!(
            contract.canonical_identity_path,
            PathBuf::from("/home/treesap/.radroots/secrets/workers/rhi/identity.secret.json")
        );
        assert_eq!(
            contract.canonical_subscriber_state_path,
            PathBuf::from("/home/treesap/.radroots/data/workers/rhi/trade-listing/state.json")
        );
    }

    #[test]
    fn runtime_contract_output_matches_service_host_contract() {
        let resolver =
            RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default());
        let contract =
            runtime_contract_with_resolver(&resolver, RadrootsPathProfile::ServiceHost, None)
                .expect("service-host contract");

        assert_eq!(contract.active_profile, "service_host");
        assert_eq!(
            contract.canonical_config_path,
            PathBuf::from("/etc/radroots/workers/rhi/config.toml")
        );
        assert_eq!(
            contract.canonical_logs_dir,
            PathBuf::from("/var/log/radroots/workers/rhi")
        );
        assert_eq!(
            contract.canonical_identity_path,
            PathBuf::from("/etc/radroots/secrets/workers/rhi/identity.secret.json")
        );
        assert_eq!(
            contract.canonical_subscriber_state_path,
            PathBuf::from("/var/lib/radroots/workers/rhi/trade-listing/state.json")
        );
    }
}
