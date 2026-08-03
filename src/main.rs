#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

#[cfg(not(test))]
use anyhow::Context;
use anyhow::Result;
#[cfg(not(test))]
use clap::Parser;
#[cfg(not(test))]
use rhi::cli::Command;
#[cfg(not(test))]
use rhi::features::trade_agreement_attestation::run_smoke_cli_command;
use rhi::{cli_args, config, paths, run_rhi};
use std::path::PathBuf;
use std::process::ExitCode;
use tracing::info;

#[cfg(not(test))]
#[tokio::main]
async fn main() -> ExitCode {
    exit_code_from_run(run().await)
}

#[cfg(test)]
fn main() -> ExitCode {
    exit_code_from_run(Ok(()))
}

fn exit_code_from_run(result: Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = ?err, "Fatal error");
            eprintln!("Fatal error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
type RunLoadHookValue = Option<Result<(cli_args, config::Settings)>>;
#[cfg(test)]
type RunLoadHook = std::sync::Mutex<RunLoadHookValue>;
#[cfg(test)]
static RUN_LOAD_HOOK: std::sync::OnceLock<RunLoadHook> = std::sync::OnceLock::new();

#[cfg(test)]
fn run_load_hook() -> &'static RunLoadHook {
    RUN_LOAD_HOOK.get_or_init(|| std::sync::Mutex::new(None))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RhiRuntimeStartupReport {
    active_profile: String,
    config_path: PathBuf,
    config_path_source: String,
    canonical_config_path: PathBuf,
    logs_dir: PathBuf,
    logs_dir_source: String,
    canonical_logs_dir: PathBuf,
    identity_path: PathBuf,
    identity_path_source: String,
    canonical_identity_path: PathBuf,
    subscriber_state_path: PathBuf,
    subscriber_state_path_source: String,
    canonical_subscriber_state_path: PathBuf,
    path_overrides: paths::RhiRuntimePathOverrideContractOutput,
    default_shared_secret_backend: String,
    allowed_shared_secret_backends: Vec<String>,
}

fn load_args_and_settings() -> Result<(cli_args, config::Settings)> {
    #[cfg(test)]
    {
        if let Some(result) = run_load_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            return result;
        }
        Err(anyhow::anyhow!("run loader hook not set"))
    }

    #[cfg(not(test))]
    {
        let args = cli_args::try_parse()?;
        let config_path = args
            .service
            .config
            .clone()
            .map(Ok)
            .unwrap_or_else(paths::default_config_path_for_process)?;
        let settings =
            config::load_settings_from_path(&config_path).context("load configuration")?;
        init_rhi_logging(&settings)?;
        Ok((args, settings))
    }
}

#[cfg(not(test))]
fn init_rhi_logging(settings: &config::Settings) -> Result<()> {
    use tracing_subscriber::fmt::writer::MakeWriterExt as _;

    std::fs::create_dir_all(&settings.config.logging.output_dir)
        .context("create RHI log directory")?;
    let appender = tracing_appender::rolling::daily(&settings.config.logging.output_dir, "rhi.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    static LOG_GUARD: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> =
        std::sync::OnceLock::new();
    let filter = tracing_subscriber::EnvFilter::new(&settings.config.logging.filter);
    if settings.config.logging.stdout {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer.and(std::io::stdout))
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize RHI logging: {error}"))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .try_init()
            .map_err(|error| anyhow::anyhow!("initialize RHI logging: {error}"))?;
    }
    LOG_GUARD
        .set(guard)
        .map_err(|_| anyhow::anyhow!("RHI logging is already initialized"))
}

fn runtime_startup_report(
    args: &cli_args,
    settings: &config::Settings,
    contract: &paths::RhiRuntimeContractOutput,
) -> RhiRuntimeStartupReport {
    RhiRuntimeStartupReport {
        active_profile: contract.active_profile.clone(),
        config_path: args
            .service
            .config
            .clone()
            .unwrap_or_else(|| contract.canonical_config_path.clone()),
        config_path_source: cli_or_profile_path_source(
            args.service.config.is_some(),
            &args
                .service
                .config
                .clone()
                .unwrap_or_else(|| contract.canonical_config_path.clone()),
            &contract.canonical_config_path,
        ),
        canonical_config_path: contract.canonical_config_path.clone(),
        logs_dir: settings.config.logging.output_dir.clone(),
        logs_dir_source: config_or_profile_path_source(
            &settings.config.logging.output_dir,
            &contract.canonical_logs_dir,
        ),
        canonical_logs_dir: contract.canonical_logs_dir.clone(),
        identity_path: args
            .service
            .identity
            .clone()
            .unwrap_or_else(|| contract.canonical_identity_path.clone()),
        identity_path_source: cli_or_profile_path_source(
            args.service.identity.is_some(),
            &args
                .service
                .identity
                .clone()
                .unwrap_or_else(|| contract.canonical_identity_path.clone()),
            &contract.canonical_identity_path,
        ),
        canonical_identity_path: contract.canonical_identity_path.clone(),
        subscriber_state_path: settings.config.subscriber.state.path.clone(),
        subscriber_state_path_source: config_or_profile_path_source(
            &settings.config.subscriber.state.path,
            &contract.canonical_subscriber_state_path,
        ),
        canonical_subscriber_state_path: contract.canonical_subscriber_state_path.clone(),
        path_overrides: contract.path_overrides.clone(),
        default_shared_secret_backend: contract.default_shared_secret_backend.clone(),
        allowed_shared_secret_backends: contract.allowed_shared_secret_backends.clone(),
    }
}

fn cli_or_profile_path_source(
    is_cli_arg: bool,
    actual_path: &PathBuf,
    canonical_path: &PathBuf,
) -> String {
    if is_cli_arg {
        "cli_arg".to_owned()
    } else {
        config_or_profile_path_source(actual_path, canonical_path)
    }
}

fn config_or_profile_path_source(actual_path: &PathBuf, canonical_path: &PathBuf) -> String {
    if actual_path == canonical_path {
        "profile_default".to_owned()
    } else {
        "config_artifact".to_owned()
    }
}

#[cfg(not(test))]
fn log_runtime_startup_report(report: &RhiRuntimeStartupReport) {
    info!(
        active_profile = report.active_profile.as_str(),
        profile_source = report.path_overrides.profile_source.as_str(),
        root_source = report.path_overrides.root_source.as_str(),
        repo_local_root = ?report.path_overrides.repo_local_root,
        repo_local_root_source = ?report.path_overrides.repo_local_root_source,
        subordinate_path_override_source = report.path_overrides.subordinate_path_override_source.as_str(),
        config_path = %report.config_path.display(),
        config_path_source = report.config_path_source.as_str(),
        canonical_config_path = %report.canonical_config_path.display(),
        logs_dir = %report.logs_dir.display(),
        logs_dir_source = report.logs_dir_source.as_str(),
        canonical_logs_dir = %report.canonical_logs_dir.display(),
        identity_path = %report.identity_path.display(),
        identity_path_source = report.identity_path_source.as_str(),
        canonical_identity_path = %report.canonical_identity_path.display(),
        subscriber_state_path = %report.subscriber_state_path.display(),
        subscriber_state_path_source = report.subscriber_state_path_source.as_str(),
        canonical_subscriber_state_path = %report.canonical_subscriber_state_path.display(),
        default_shared_secret_backend = report.default_shared_secret_backend.as_str(),
        allowed_shared_secret_backends = ?report.allowed_shared_secret_backends,
        "rhi runtime contract"
    );
}

async fn run() -> Result<()> {
    #[cfg(not(test))]
    {
        let args = cli_args::try_parse()?;
        if let Some(command) = args.command {
            return match command {
                Command::AttestationSmoke { .. } => run_smoke_cli_command(command).await,
            };
        }
    }

    let (args, settings): (cli_args, config::Settings) = load_args_and_settings()?;

    #[cfg(not(test))]
    {
        let contract = paths::runtime_contract_for_process().context("resolve runtime contract")?;
        let report = runtime_startup_report(&args, &settings, &contract);
        log_runtime_startup_report(&report);
    }

    info!("Starting");

    run_rhi(&settings, &args).await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        RhiRuntimeStartupReport, exit_code_from_run, main, run, run_load_hook, run_rhi,
        runtime_startup_report,
    };
    use rhi::features::trade_agreement_attestation::TradeAgreementAttestationRuntime;
    use rhi::host_nostr::{Client, Keys};
    use rhi::{cli_args, config, paths};
    use std::path::PathBuf;
    use std::process::ExitCode;

    static RUN_HOOK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn run_hook_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
        RUN_HOOK_TEST_LOCK.lock().await
    }

    fn minimal_settings() -> config::Settings {
        config::Settings {
            metadata: serde_json::from_str(r#"{"name":"rhi-test"}"#).expect("metadata"),
            config: config::Configuration {
                service: rhi::host_runtime::NostrServiceConfig {
                    logs_dir: std::env::temp_dir()
                        .join("rhi-test-logs")
                        .display()
                        .to_string(),
                    relays: Vec::new(),
                    nip89_identifier: Some("rhi".to_string()),
                    nip89_extra_tags: Vec::new(),
                },
                logging: config::LoggingConfig {
                    output_dir: std::env::temp_dir().join("rhi-test-logs"),
                    filter: "info".to_string(),
                    stdout: true,
                },
                subscriber: config::SubscriberConfig::default(),
                trade_agreement_attestation:
                    rhi::features::trade_agreement_attestation::TradeAgreementAttestationPolicy::default(),
            },
        }
    }

    fn sample_runtime_contract() -> paths::RhiRuntimeContractOutput {
        paths::RhiRuntimeContractOutput {
            active_profile: "interactive_user".to_string(),
            allowed_profiles: vec![
                "interactive_user".to_string(),
                "service_host".to_string(),
                "repo_local".to_string(),
            ],
            path_overrides: paths::RhiRuntimePathOverrideContractOutput {
                profile_source: "caller".to_string(),
                root_source: "host_defaults".to_string(),
                repo_local_root: None,
                repo_local_root_source: None,
                subordinate_path_override_source: "config_artifact".to_string(),
                subordinate_path_override_keys: vec![
                    "logging.output_dir".to_string(),
                    "subscriber.state.path".to_string(),
                ],
            },
            default_shared_secret_backend: "encrypted_file".to_string(),
            allowed_shared_secret_backends: vec!["encrypted_file".to_string()],
            canonical_config_path: PathBuf::from(
                "/home/treesap/.radroots/config/workers/rhi/config.toml",
            ),
            canonical_logs_dir: PathBuf::from("/home/treesap/.radroots/logs/workers/rhi"),
            canonical_identity_path: PathBuf::from(
                "/home/treesap/.radroots/secrets/workers/rhi/identity.secret.json",
            ),
            canonical_subscriber_state_path: PathBuf::from(
                "/home/treesap/.radroots/data/workers/rhi/trade-agreement-attestation/state.json",
            ),
        }
    }

    #[test]
    fn exit_code_from_run_maps_success_and_error() {
        assert_eq!(exit_code_from_run(Ok(())), ExitCode::SUCCESS);
        assert_eq!(
            exit_code_from_run(Err(anyhow::anyhow!("boom"))),
            ExitCode::FAILURE
        );
    }

    #[tokio::test]
    async fn run_rhi_returns_error_when_identity_is_missing() {
        let args = cli_args {
            command: None,
            service: rhi::host_runtime::ServiceCliArgs {
                config: Some(PathBuf::from("config.toml")),
                identity: Some(PathBuf::from("/tmp/rhi-missing-identity.secret.json")),
                allow_generate_identity: false,
            },
        };
        let settings = minimal_settings();
        let err = run_rhi(&settings, &args)
            .await
            .expect_err("identity should fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("identity"));
    }

    #[test]
    fn main_returns_success_in_test_build() {
        assert_eq!(main(), ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn run_uses_injected_config_loader_result() {
        let _guard = run_hook_test_guard().await;
        let args = cli_args {
            command: None,
            service: rhi::host_runtime::ServiceCliArgs {
                config: Some(PathBuf::from("config.toml")),
                identity: Some(PathBuf::from("/tmp/rhi-run-hook-missing.secret.json")),
                allow_generate_identity: false,
            },
        };
        *run_load_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Ok((args, minimal_settings())));
        let err = run().await.expect_err("missing identity should bubble");
        let msg = format!("{err:#}");
        assert!(msg.contains("identity"));
    }

    #[tokio::test]
    async fn run_returns_error_when_loader_hook_is_absent() {
        let _guard = run_hook_test_guard().await;
        *run_load_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let err = run()
            .await
            .expect_err("loader hook should be required in test build");
        let msg = format!("{err:#}");
        assert!(msg.contains("run loader hook not set"));
    }

    #[tokio::test]
    async fn non_test_start_subscriber_path_can_start_and_stop() {
        let keys = Keys::generate();
        let client = Client::new(keys.clone());
        let handle = rhi::rhi::start_subscriber(
            client,
            keys,
            TradeAgreementAttestationRuntime::new(),
            rhi::host_runtime::BackoffConfig {
                base_ms: 1,
                max_ms: 2,
                factor: 1,
                jitter_ms: 0,
            },
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        handle.stop();
        handle.stopped().await;
    }

    #[test]
    fn runtime_startup_report_prefers_explicit_cli_paths() {
        let args = cli_args {
            service: rhi::host_runtime::ServiceCliArgs {
                config: Some(PathBuf::from("/tmp/rhi/config.toml")),
                identity: Some(PathBuf::from("/tmp/rhi/identity.secret.json")),
                allow_generate_identity: false,
            },
            command: None,
        };
        let mut settings = minimal_settings();
        settings.config.service.logs_dir = "/tmp/rhi/logs".to_string();
        settings.config.logging.output_dir = PathBuf::from("/tmp/rhi/logs");
        settings.config.subscriber.state.path = PathBuf::from("/tmp/rhi/state.json");

        let contract = sample_runtime_contract();
        let report = runtime_startup_report(&args, &settings, &contract);

        assert_eq!(
            report,
            RhiRuntimeStartupReport {
                active_profile: "interactive_user".to_string(),
                config_path: PathBuf::from("/tmp/rhi/config.toml"),
                config_path_source: "cli_arg".to_string(),
                canonical_config_path: PathBuf::from(
                    "/home/treesap/.radroots/config/workers/rhi/config.toml"
                ),
                logs_dir: PathBuf::from("/tmp/rhi/logs"),
                logs_dir_source: "config_artifact".to_string(),
                canonical_logs_dir: PathBuf::from("/home/treesap/.radroots/logs/workers/rhi"),
                identity_path: PathBuf::from("/tmp/rhi/identity.secret.json"),
                identity_path_source: "cli_arg".to_string(),
                canonical_identity_path: PathBuf::from(
                    "/home/treesap/.radroots/secrets/workers/rhi/identity.secret.json"
                ),
                subscriber_state_path: PathBuf::from("/tmp/rhi/state.json"),
                subscriber_state_path_source: "config_artifact".to_string(),
                canonical_subscriber_state_path: PathBuf::from(
                    "/home/treesap/.radroots/data/workers/rhi/trade-agreement-attestation/state.json"
                ),
                path_overrides: sample_runtime_contract().path_overrides,
                default_shared_secret_backend: "encrypted_file".to_string(),
                allowed_shared_secret_backends: vec!["encrypted_file".to_string()],
            }
        );
    }

    #[test]
    fn runtime_startup_report_falls_back_to_canonical_contract_paths() {
        let args = cli_args {
            command: None,
            service: rhi::host_runtime::ServiceCliArgs {
                config: None,
                identity: None,
                allow_generate_identity: false,
            },
        };
        let contract = sample_runtime_contract();
        let mut settings = minimal_settings();
        settings.config.service.logs_dir = contract.canonical_logs_dir.display().to_string();
        settings.config.logging.output_dir = contract.canonical_logs_dir.clone();
        settings.config.subscriber.state.path = contract.canonical_subscriber_state_path.clone();

        let report = runtime_startup_report(&args, &settings, &contract);

        assert_eq!(report.config_path, contract.canonical_config_path);
        assert_eq!(report.config_path_source, "profile_default");
        assert_eq!(report.logs_dir, contract.canonical_logs_dir);
        assert_eq!(report.logs_dir_source, "profile_default");
        assert_eq!(report.identity_path, contract.canonical_identity_path);
        assert_eq!(report.identity_path_source, "profile_default");
        assert_eq!(
            report.subscriber_state_path,
            contract.canonical_subscriber_state_path
        );
        assert_eq!(report.subscriber_state_path_source, "profile_default");
        assert_eq!(report.path_overrides, contract.path_overrides);
        assert_eq!(report.default_shared_secret_backend, "encrypted_file");
        assert_eq!(
            report.allowed_shared_secret_backends,
            vec!["encrypted_file".to_string()]
        );
    }
}
