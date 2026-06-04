use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use radroots_runtime_paths::{
    DEFAULT_CONFIG_FILE_NAME, DEFAULT_SERVICE_IDENTITY_FILE_NAME, RadrootsLegacyPathCandidate,
    RadrootsMigrationReport, RadrootsPathOverrides, RadrootsPathProfile, RadrootsPathResolver,
    RadrootsRuntimeNamespace, inspect_legacy_paths,
};
use serde::Serialize;

const RHI_RUNTIME_ID: &str = "rhi";
const SUBSCRIBER_STATE_DIR_NAME: &str = "trade-listing";
const SUBSCRIBER_STATE_FILE_NAME: &str = "state.json";
const RHI_PATHS_PROFILE_ENV: &str = "RHI_PATHS_PROFILE";
const RHI_PATHS_REPO_LOCAL_ROOT_ENV: &str = "RHI_PATHS_REPO_LOCAL_ROOT";
const RHI_DEFAULT_SHARED_SECRET_BACKEND: &str = "encrypted_file";
const RHI_ALLOWED_PROFILES: [&str; 3] = ["interactive_user", "service_host", "repo_local"];
const RHI_ALLOWED_SHARED_SECRET_BACKENDS: [&str; 1] = ["encrypted_file"];
const SUBORDINATE_PATH_OVERRIDE_SOURCE: &str = "config_artifact";
const SUBORDINATE_PATH_OVERRIDE_KEYS: [&str; 2] = ["logging.output_dir", "subscriber.state.path"];
const MIGRATION_IMPORT_HINT: &str = "stop the worker, inspect this legacy path, then perform an explicit import or manual copy into the canonical destination; rhi will not move it on startup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RhiRuntimePaths {
    pub(crate) config_path: PathBuf,
    pub(crate) logs_dir: PathBuf,
    pub(crate) identity_path: PathBuf,
    pub(crate) subscriber_state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RhiRuntimeContractOutput {
    pub active_profile: String,
    pub allowed_profiles: Vec<String>,
    pub path_overrides: RhiRuntimePathOverrideContractOutput,
    pub default_shared_secret_backend: String,
    pub allowed_shared_secret_backends: Vec<String>,
    pub migration: RhiRuntimeMigrationContractOutput,
    pub canonical_config_path: PathBuf,
    pub canonical_logs_dir: PathBuf,
    pub canonical_identity_path: PathBuf,
    pub canonical_subscriber_state_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RhiRuntimeMigrationContractOutput {
    pub posture: String,
    pub state: String,
    pub silent_startup_relocation: bool,
    pub compatibility_window: String,
    pub detected_legacy_paths: Vec<RhiRuntimeLegacyPathOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RhiRuntimeLegacyPathOutput {
    pub id: String,
    pub description: String,
    pub path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<PathBuf>,
    pub import_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RhiRuntimePathOverrideContractOutput {
    pub profile_source: String,
    pub root_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_local_root: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_local_root_source: Option<String>,
    pub subordinate_path_override_source: String,
    pub subordinate_path_override_keys: Vec<String>,
}

struct RhiRuntimePathSelection {
    profile: RadrootsPathProfile,
    profile_source: String,
    repo_local_root: Option<PathBuf>,
    repo_local_root_source: Option<String>,
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

pub(crate) fn process_path_selection() -> Result<(RadrootsPathProfile, Option<PathBuf>)> {
    let selection = process_path_selection_with_sources()?;
    Ok((selection.profile, selection.repo_local_root))
}

fn process_path_selection_with_sources() -> Result<RhiRuntimePathSelection> {
    let profile = match std::env::var(RHI_PATHS_PROFILE_ENV) {
        Ok(value) => (
            parse_path_profile(&value)?,
            format!("process_env:{RHI_PATHS_PROFILE_ENV}"),
        ),
        Err(std::env::VarError::NotPresent) => {
            (RadrootsPathProfile::InteractiveUser, "default".to_owned())
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("{RHI_PATHS_PROFILE_ENV} must be valid utf-8 when set")
        }
    };
    let repo_local_root_raw = std::env::var_os(RHI_PATHS_REPO_LOCAL_ROOT_ENV);
    let repo_local_root = repo_local_root_raw.as_ref().map(PathBuf::from);
    Ok(RhiRuntimePathSelection {
        profile: profile.0,
        profile_source: profile.1,
        repo_local_root,
        repo_local_root_source: repo_local_root_raw
            .as_ref()
            .map(|_| format!("process_env:{RHI_PATHS_REPO_LOCAL_ROOT_ENV}")),
    })
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

pub(crate) fn resolve_runtime_paths_with_resolver(
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

pub(crate) fn default_runtime_paths_for_process() -> Result<RhiRuntimePaths> {
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

pub fn runtime_contract_for_process() -> Result<RhiRuntimeContractOutput> {
    let selection = process_path_selection_with_sources()?;
    runtime_contract_with_selection(&RadrootsPathResolver::current(), &selection)
}

#[cfg(test)]
pub(crate) fn runtime_contract_with_resolver(
    resolver: &RadrootsPathResolver,
    profile: RadrootsPathProfile,
    repo_local_root: Option<&Path>,
) -> Result<RhiRuntimeContractOutput> {
    runtime_contract_with_selection(
        resolver,
        &RhiRuntimePathSelection {
            profile,
            profile_source: "caller".to_owned(),
            repo_local_root: repo_local_root.map(Path::to_path_buf),
            repo_local_root_source: repo_local_root.map(|_| "caller".to_owned()),
        },
    )
}

fn runtime_contract_with_selection(
    resolver: &RadrootsPathResolver,
    selection: &RhiRuntimePathSelection,
) -> Result<RhiRuntimeContractOutput> {
    let profile = selection.profile;
    let repo_local_root = selection.repo_local_root.as_deref();
    let paths = resolve_runtime_paths_with_resolver(resolver, profile, repo_local_root)?;
    Ok(RhiRuntimeContractOutput {
        active_profile: profile.to_string(),
        allowed_profiles: RHI_ALLOWED_PROFILES
            .into_iter()
            .map(str::to_owned)
            .collect(),
        path_overrides: RhiRuntimePathOverrideContractOutput {
            profile_source: selection.profile_source.clone(),
            root_source: root_source_for_profile(profile).to_owned(),
            repo_local_root: selection.repo_local_root.clone(),
            repo_local_root_source: selection.repo_local_root_source.clone(),
            subordinate_path_override_source: SUBORDINATE_PATH_OVERRIDE_SOURCE.to_owned(),
            subordinate_path_override_keys: SUBORDINATE_PATH_OVERRIDE_KEYS
                .into_iter()
                .map(str::to_owned)
                .collect(),
        },
        default_shared_secret_backend: RHI_DEFAULT_SHARED_SECRET_BACKEND.to_owned(),
        allowed_shared_secret_backends: RHI_ALLOWED_SHARED_SECRET_BACKENDS
            .into_iter()
            .map(str::to_owned)
            .collect(),
        migration: migration_contract_output(RadrootsMigrationReport::empty()),
        canonical_config_path: paths.config_path,
        canonical_logs_dir: paths.logs_dir,
        canonical_identity_path: paths.identity_path,
        canonical_subscriber_state_path: paths.subscriber_state_path,
    })
}

pub fn runtime_migration_for_process(
    contract: &RhiRuntimeContractOutput,
) -> Result<RhiRuntimeMigrationContractOutput> {
    let current_dir = std::env::current_dir().context("resolve current directory")?;
    Ok(runtime_migration_for_current_dir(
        contract,
        current_dir.as_path(),
    ))
}

pub(crate) fn runtime_migration_for_current_dir(
    contract: &RhiRuntimeContractOutput,
    current_dir: &Path,
) -> RhiRuntimeMigrationContractOutput {
    let report = inspect_legacy_paths(legacy_path_candidates(contract, current_dir));
    migration_contract_output(report)
}

fn legacy_path_candidates(
    contract: &RhiRuntimeContractOutput,
    current_dir: &Path,
) -> Vec<RadrootsLegacyPathCandidate> {
    vec![
        RadrootsLegacyPathCandidate::new(
            "rhi_repo_config_v0",
            "legacy rhi repo-relative config",
            current_dir.join(DEFAULT_CONFIG_FILE_NAME),
            Some(contract.canonical_config_path.clone()),
            MIGRATION_IMPORT_HINT,
        ),
        RadrootsLegacyPathCandidate::new(
            "rhi_repo_logs_v0",
            "legacy rhi repo-relative logs directory",
            current_dir.join("logs"),
            Some(contract.canonical_logs_dir.clone()),
            MIGRATION_IMPORT_HINT,
        ),
        RadrootsLegacyPathCandidate::new(
            "rhi_repo_subscriber_state_v0",
            "legacy rhi repo-relative subscriber state",
            current_dir.join("state/trade-listing-state.json"),
            Some(contract.canonical_subscriber_state_path.clone()),
            MIGRATION_IMPORT_HINT,
        ),
    ]
}

fn migration_contract_output(report: RadrootsMigrationReport) -> RhiRuntimeMigrationContractOutput {
    RhiRuntimeMigrationContractOutput {
        posture: report.posture.to_owned(),
        state: report.state.to_owned(),
        silent_startup_relocation: report.silent_startup_relocation,
        compatibility_window: report.compatibility_window.to_owned(),
        detected_legacy_paths: report
            .detected_legacy_paths
            .into_iter()
            .map(|path| RhiRuntimeLegacyPathOutput {
                id: path.id,
                description: path.description,
                path: path.path,
                destination: path.destination,
                import_hint: path.import_hint,
            })
            .collect(),
    }
}

fn root_source_for_profile(profile: RadrootsPathProfile) -> &'static str {
    match profile {
        RadrootsPathProfile::InteractiveUser => "host_defaults",
        RadrootsPathProfile::ServiceHost => "service_host_defaults",
        RadrootsPathProfile::RepoLocal => "repo_local_root",
        RadrootsPathProfile::MobileNative => "mobile_native_defaults",
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use radroots_runtime_paths::{
        RadrootsHostEnvironment, RadrootsPathProfile, RadrootsPathResolver, RadrootsPlatform,
    };

    use super::{runtime_contract_with_resolver, runtime_migration_for_current_dir};

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
    fn runtime_migration_detects_legacy_repo_relative_state_without_moving_it() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp.path().join("config.toml"),
            "[metadata]\nname = \"old\"\n",
        )
        .expect("write old config");
        std::fs::create_dir_all(temp.path().join("state")).expect("state dir");
        std::fs::write(temp.path().join("state/trade-listing-state.json"), "{}")
            .expect("write old subscriber state");
        let contract = runtime_contract_with_resolver(
            &linux_resolver(),
            RadrootsPathProfile::InteractiveUser,
            None,
        )
        .expect("contract");

        let report = runtime_migration_for_current_dir(&contract, temp.path());

        assert_eq!(report.posture, "explicit_operator_import_required");
        assert_eq!(report.state, "legacy_state_detected");
        assert!(!report.silent_startup_relocation);
        assert_eq!(report.detected_legacy_paths.len(), 2);
        assert_eq!(report.detected_legacy_paths[0].id, "rhi_repo_config_v0");
        assert_eq!(
            report.detected_legacy_paths[1].id,
            "rhi_repo_subscriber_state_v0"
        );
        assert_eq!(
            report.detected_legacy_paths[1].destination,
            Some(contract.canonical_subscriber_state_path)
        );
    }
}
