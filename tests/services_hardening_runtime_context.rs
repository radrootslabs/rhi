#![forbid(unsafe_code)]

use std::error::Error;
use std::path::{Path, PathBuf};

use rhi::{
    RadrootsHostEnvironment, RadrootsPathProfile, RadrootsPathResolver, RadrootsPlatform,
    RhiBootstrapProfileV1, RuntimeContextSource, parse_rhi_cli_v1_from,
    resolve_rhi_runtime_context,
};

fn resolve(
    resolver: &RadrootsPathResolver,
    profile: &str,
    instance: &str,
    repo_local_root: Option<&str>,
    config_path: Option<&str>,
) -> rhi::RhiRuntimeContext {
    let mut arguments = vec!["rhi", "--profile", profile, "--instance", instance];
    if let Some(root) = repo_local_root {
        arguments.extend(["--repo-local-root", root]);
    }
    if let Some(path) = config_path {
        arguments.extend(["--config", path]);
    }
    arguments.push("run");
    let invocation = parse_rhi_cli_v1_from(arguments).expect("validated invocation");
    resolve_rhi_runtime_context(resolver, &invocation).expect("runtime context")
}

fn assert_roots(context: &rhi::RhiRuntimeContext, expected: [&str; 6]) {
    let paths = context.context().paths();
    assert_eq!(paths.config(), Path::new(expected[0]));
    assert_eq!(paths.state(), Path::new(expected[1]));
    assert_eq!(paths.cache(), Path::new(expected[2]));
    assert_eq!(paths.logs(), Path::new(expected[3]));
    assert_eq!(paths.run(), Path::new(expected[4]));
    assert_eq!(paths.secrets(), Path::new(expected[5]));
}

#[test]
fn repo_local_context_binds_identity_provenance_and_exact_artifacts() {
    let resolver =
        RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default());
    let primary = resolve(
        &resolver,
        "repo-local",
        "primary",
        Some("/repo/.local/radroots"),
        None,
    );
    let secondary = resolve(
        &resolver,
        "repo-local",
        "secondary",
        Some("/repo/.local/radroots"),
        None,
    );

    assert_eq!(primary.context().service().as_str(), "rhi");
    assert_eq!(primary.context().instance().as_str(), "primary");
    assert_eq!(primary.profile(), RhiBootstrapProfileV1::RepoLocal);
    assert_eq!(primary.context().profile(), RadrootsPathProfile::RepoLocal);
    assert_eq!(
        primary.context().sources().service(),
        RuntimeContextSource::SafeDefault
    );
    assert_eq!(
        primary.context().sources().instance(),
        RuntimeContextSource::BootstrapCli
    );
    assert_eq!(
        primary.context().sources().profile(),
        RuntimeContextSource::BootstrapCli
    );
    assert_eq!(
        primary.context().sources().repo_local_root(),
        Some(RuntimeContextSource::BootstrapCli)
    );
    assert_eq!(
        primary.context().sources().paths(),
        RuntimeContextSource::DerivedPath
    );
    assert_roots(
        &primary,
        [
            "/repo/.local/radroots/config/services/rhi/primary",
            "/repo/.local/radroots/data/services/rhi/primary",
            "/repo/.local/radroots/cache/services/rhi/primary",
            "/repo/.local/radroots/logs/services/rhi/primary",
            "/repo/.local/radroots/run/services/rhi/primary",
            "/repo/.local/radroots/secrets/services/rhi/primary",
        ],
    );
    assert_eq!(
        primary.artifacts().config(),
        Path::new("/repo/.local/radroots/config/services/rhi/primary/config.toml")
    );
    assert_eq!(
        primary.artifacts().state_database(),
        Path::new("/repo/.local/radroots/data/services/rhi/primary/state.sqlite")
    );
    assert_eq!(
        primary.artifacts().state_lock(),
        Path::new("/repo/.local/radroots/data/services/rhi/primary/state.lock")
    );
    assert_eq!(
        primary.artifacts().admin_socket(),
        Path::new("/repo/.local/radroots/run/services/rhi/primary/admin.sock")
    );
    assert_eq!(
        primary.identity_path(),
        Path::new("/repo/.local/radroots/secrets/services/rhi/primary/service.identity.ncrypt")
    );
    assert_eq!(primary.selected_config_path(), primary.artifacts().config());
    assert_ne!(primary.context().paths(), secondary.context().paths());
}

#[test]
fn service_host_and_interactive_profiles_have_exact_roots() {
    let service_host = resolve(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        "service-host",
        "default",
        None,
        None,
    );
    assert_roots(
        &service_host,
        [
            "/etc/radroots/services/rhi/default",
            "/var/lib/radroots/services/rhi/default",
            "/var/cache/radroots/services/rhi/default",
            "/var/log/radroots/services/rhi/default",
            "/run/radroots/services/rhi/default",
            "/etc/radroots/secrets/services/rhi/default",
        ],
    );

    let interactive = resolve(
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
        "interactive",
        "default",
        None,
        Some("/operator/rhi.toml"),
    );
    assert_roots(
        &interactive,
        [
            "/xdg/config/radroots/services/rhi/default",
            "/xdg/data/radroots/services/rhi/default",
            "/xdg/cache/radroots/services/rhi/default",
            "/xdg/state/radroots/logs/services/rhi/default",
            "/xdg/run/radroots/services/rhi/default",
            "/xdg/config/radroots/secrets/services/rhi/default",
        ],
    );
    assert_eq!(
        interactive.selected_config_path(),
        Path::new("/operator/rhi.toml")
    );
}

#[test]
fn macos_and_windows_interactive_roots_remain_exact_and_injected() {
    let macos = resolve(
        &RadrootsPathResolver::new(
            RadrootsPlatform::Macos,
            RadrootsHostEnvironment {
                home_dir: Some(PathBuf::from("/Users/operator")),
                ..RadrootsHostEnvironment::default()
            },
        ),
        "interactive",
        "default",
        None,
        None,
    );
    assert_roots(
        &macos,
        [
            "/Users/operator/Library/Application Support/Radroots/config/services/rhi/default",
            "/Users/operator/Library/Application Support/Radroots/data/services/rhi/default",
            "/Users/operator/Library/Caches/Radroots/services/rhi/default",
            "/Users/operator/Library/Logs/Radroots/services/rhi/default",
            "/Users/operator/Library/Application Support/Radroots/run/services/rhi/default",
            "/Users/operator/Library/Application Support/Radroots/secrets/services/rhi/default",
        ],
    );

    let windows = resolve(
        &RadrootsPathResolver::new(
            RadrootsPlatform::Windows,
            RadrootsHostEnvironment {
                appdata_dir: Some(PathBuf::from(r"C:\Users\operator\AppData\Roaming")),
                localappdata_dir: Some(PathBuf::from(r"C:\Users\operator\AppData\Local")),
                ..RadrootsHostEnvironment::default()
            },
        ),
        "interactive",
        "default",
        None,
        None,
    );
    assert_roots(
        &windows,
        [
            r"C:\Users\operator\AppData\Roaming/Radroots/config/services/rhi/default",
            r"C:\Users\operator\AppData\Local/Radroots/data/services/rhi/default",
            r"C:\Users\operator\AppData\Local/Radroots/cache/services/rhi/default",
            r"C:\Users\operator\AppData\Local/Radroots/logs/services/rhi/default",
            r"C:\Users\operator\AppData\Local/Radroots/run/services/rhi/default",
            r"C:\Users\operator\AppData\Roaming/Radroots/secrets/services/rhi/default",
        ],
    );
}

#[test]
fn debug_and_errors_do_not_disclose_paths_or_instances() {
    let context = resolve(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        "repo-local",
        "secret-instance",
        Some("/secret/root"),
        Some("/secret/config.toml"),
    );
    let rendered = format!("{context:?}");
    for forbidden in ["secret-instance", "/secret/root", "/secret/config.toml"] {
        assert!(!rendered.contains(forbidden), "{rendered}");
    }

    let invocation = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        "interactive",
        "--instance",
        "default",
        "run",
    ])
    .expect("invocation");
    let error = resolve_rhi_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Macos, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect_err("missing HOME");
    assert!(error.source().is_none());
    assert!(!format!("{error:?} {error}").contains("HOME"));
}

#[test]
fn source_contains_no_legacy_path_authority() {
    let lib = include_str!("../src/lib.rs");
    let context = include_str!("../src/runtime_context.rs");
    let main = include_str!("../src/main.rs");
    let config = include_str!("../src/config.rs");
    for forbidden in [
        "pub mod host_paths",
        "pub mod paths",
        "RHI_PATHS_PROFILE",
        "RHI_PATHS_REPO_LOCAL_ROOT",
        "RadrootsRuntimeNamespace::worker",
        "RhiRuntimeStartupReport",
        "RhiRuntimeContractOutput",
        "default_config_path_for_process",
        "default_identity_path_for_process",
        "default_subscriber_state_path_for_process",
    ] {
        assert!(!lib.contains(forbidden));
        assert!(!context.contains(forbidden));
        assert!(!main.contains(forbidden));
        assert!(!config.contains(forbidden));
    }
    for removed in ["src/paths.rs", "src/host_paths/mod.rs", "src/cli.rs"] {
        assert!(
            !Path::new(env!("CARGO_MANIFEST_DIR")).join(removed).exists(),
            "legacy path authority remains at {removed}"
        );
    }
}
