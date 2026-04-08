use anyhow::{Context, Result, bail};
use radroots_nostr::prelude::RadrootsNostrMetadata;
use radroots_runtime::{BackoffConfig, RadrootsNostrServiceConfig};
use radroots_runtime_paths::{
    DEFAULT_CONFIG_FILE_NAME, DEFAULT_SERVICE_IDENTITY_FILE_NAME, RadrootsPathOverrides,
    RadrootsPathProfile, RadrootsPathResolver, RadrootsRuntimeNamespace,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const RHI_RUNTIME_ID: &str = "rhi";
const SUBSCRIBER_STATE_DIR_NAME: &str = "trade-listing";
const SUBSCRIBER_STATE_FILE_NAME: &str = "state.json";
const RHI_PATHS_PROFILE_ENV: &str = "RHI_PATHS_PROFILE";
const RHI_PATHS_REPO_LOCAL_ROOT_ENV: &str = "RHI_PATHS_REPO_LOCAL_ROOT";

fn default_replay_window_secs() -> u64 {
    24 * 60 * 60
}

fn default_replay_overlap_secs() -> u64 {
    5 * 60
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RhiRuntimePaths {
    config_path: PathBuf,
    logs_dir: PathBuf,
    identity_path: PathBuf,
    subscriber_state_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone, Default)]
struct RawServiceConfig {
    #[serde(default)]
    pub logs_dir: Option<String>,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub nip89_identifier: Option<String>,
    #[serde(default)]
    pub nip89_extra_tags: Vec<Vec<String>>,
}

impl RawServiceConfig {
    fn into_service_config(self, paths: &RhiRuntimePaths) -> RadrootsNostrServiceConfig {
        RadrootsNostrServiceConfig {
            logs_dir: self
                .logs_dir
                .unwrap_or_else(|| paths.logs_dir.display().to_string()),
            relays: self.relays,
            nip89_identifier: self.nip89_identifier,
            nip89_extra_tags: self.nip89_extra_tags,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Deserialize, Clone, Default)]
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
struct RawConfiguration {
    #[serde(flatten)]
    pub service: RawServiceConfig,
    #[serde(default)]
    pub subscriber: RawSubscriberConfig,
}

#[derive(Debug, Deserialize, Clone)]
struct RawSettings {
    pub metadata: RadrootsNostrMetadata,
    pub config: RawConfiguration,
}

impl RawSettings {
    fn into_settings(self, paths: &RhiRuntimePaths) -> Settings {
        Settings {
            metadata: self.metadata,
            config: Configuration {
                service: self.config.service.into_service_config(paths),
                subscriber: self.config.subscriber.into_subscriber_config(paths),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub metadata: RadrootsNostrMetadata,
    pub config: Configuration,
}

fn parse_path_profile(value: &str) -> Result<RadrootsPathProfile> {
    match value {
        "interactive_user" => Ok(RadrootsPathProfile::InteractiveUser),
        "service_host" => Ok(RadrootsPathProfile::ServiceHost),
        "repo_local" => Ok(RadrootsPathProfile::RepoLocal),
        _ => bail!(
            "{RHI_PATHS_PROFILE_ENV} must be `interactive_user`, `service_host`, or `repo_local`"
        ),
    }
}

fn process_path_selection() -> Result<(RadrootsPathProfile, Option<PathBuf>)> {
    let profile = match std::env::var(RHI_PATHS_PROFILE_ENV) {
        Ok(value) => parse_path_profile(&value)?,
        Err(std::env::VarError::NotPresent) => RadrootsPathProfile::InteractiveUser,
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{RHI_PATHS_PROFILE_ENV} must be valid utf-8 when set")
        }
    };
    let repo_local_root = std::env::var_os(RHI_PATHS_REPO_LOCAL_ROOT_ENV).map(PathBuf::from);
    Ok((profile, repo_local_root))
}

fn path_overrides_for(
    profile: RadrootsPathProfile,
    repo_local_root: Option<&Path>,
) -> Result<RadrootsPathOverrides> {
    match profile {
        RadrootsPathProfile::RepoLocal => {
            let repo_local_root = repo_local_root.context(format!(
                "{RHI_PATHS_REPO_LOCAL_ROOT_ENV} must be set when {RHI_PATHS_PROFILE_ENV}=repo_local"
            ))?;
            Ok(RadrootsPathOverrides::repo_local(repo_local_root))
        }
        _ => Ok(RadrootsPathOverrides::default()),
    }
}

fn resolve_runtime_paths_with_resolver(
    resolver: &RadrootsPathResolver,
    profile: RadrootsPathProfile,
    repo_local_root: Option<&Path>,
) -> Result<RhiRuntimePaths> {
    let namespace = RadrootsRuntimeNamespace::worker(RHI_RUNTIME_ID)
        .map_err(|error| anyhow::anyhow!("resolve rhi namespace: {error}"))?;
    let overrides = path_overrides_for(profile, repo_local_root)?;
    let namespaced = resolver
        .resolve(profile, &overrides)
        .map_err(|error| anyhow::anyhow!("resolve rhi runtime paths: {error}"))?
        .namespaced(&namespace);
    Ok(RhiRuntimePaths {
        config_path: namespaced.config.join(DEFAULT_CONFIG_FILE_NAME),
        logs_dir: namespaced.logs,
        identity_path: namespaced.secrets.join(DEFAULT_SERVICE_IDENTITY_FILE_NAME),
        subscriber_state_path: namespaced
            .data
            .join(SUBSCRIBER_STATE_DIR_NAME)
            .join(SUBSCRIBER_STATE_FILE_NAME),
    })
}

fn default_runtime_paths_for_process() -> Result<RhiRuntimePaths> {
    let (profile, repo_local_root) = process_path_selection()?;
    resolve_runtime_paths_with_resolver(
        &RadrootsPathResolver::current(),
        profile,
        repo_local_root.as_deref(),
    )
}

pub fn default_config_path_for_process() -> Result<PathBuf> {
    Ok(default_runtime_paths_for_process()?.config_path)
}

pub fn default_identity_path_for_process() -> Result<PathBuf> {
    Ok(default_runtime_paths_for_process()?.identity_path)
}

pub fn default_subscriber_state_path_for_process() -> Result<PathBuf> {
    Ok(default_runtime_paths_for_process()?.subscriber_state_path)
}

fn load_settings_from_path_with_resolver(
    path: &Path,
    resolver: &RadrootsPathResolver,
    profile: RadrootsPathProfile,
    repo_local_root: Option<&Path>,
) -> Result<Settings> {
    let paths = resolve_runtime_paths_with_resolver(resolver, profile, repo_local_root)?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read configuration from {}", path.display()))?;
    let settings: RawSettings =
        toml::from_str(&raw).with_context(|| format!("parse configuration {}", path.display()))?;
    Ok(settings.into_settings(&paths))
}

pub fn load_settings_from_path(path: &Path) -> Result<Settings> {
    let (profile, repo_local_root) = process_path_selection()?;
    load_settings_from_path_with_resolver(
        path,
        &RadrootsPathResolver::current(),
        profile,
        repo_local_root.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        default_subscriber_state_path_for_process, load_settings_from_path_with_resolver,
        resolve_runtime_paths_with_resolver,
    };
    use radroots_runtime_paths::{
        RadrootsHostEnvironment, RadrootsPathOverrides, RadrootsPathProfile, RadrootsPathResolver,
        RadrootsPlatform, RadrootsRuntimeNamespace,
    };
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

[config]
relays = ["wss://relay.example.com"]
nip89_identifier = "rhi"

[config.subscriber.state]
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
            settings.config.subscriber.state.path,
            PathBuf::from("/home/treesap/.radroots/data/workers/rhi/trade-listing/state.json")
        );
        assert_eq!(settings.config.subscriber.state.replay_window_secs, 123);
        assert_eq!(settings.config.subscriber.state.replay_overlap_secs, 45);
    }

    #[test]
    fn default_subscriber_state_path_is_canonical_for_current_process() {
        let path =
            default_subscriber_state_path_for_process().expect("resolve current process defaults");
        assert!(path.ends_with("trade-listing/state.json"));
    }
}
