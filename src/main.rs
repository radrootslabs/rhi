#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use anyhow::Result;
#[cfg(not(test))]
use anyhow::Context;
use rhi::{cli_args, config, run_rhi};
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
static RUN_LOAD_HOOK: std::sync::OnceLock<
    std::sync::Mutex<Option<Result<(cli_args, config::Settings)>>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn run_load_hook() -> &'static std::sync::Mutex<Option<Result<(cli_args, config::Settings)>>> {
    RUN_LOAD_HOOK.get_or_init(|| std::sync::Mutex::new(None))
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
        return Err(anyhow::anyhow!("run loader hook not set"));
    }

    #[cfg(not(test))]
    radroots_runtime::parse_and_load_path_with_init(
        |a: &cli_args| Some(a.service.config.as_path()),
        |cfg: &config::Settings| cfg.config.service.logs_dir.as_str(),
        None,
    )
    .context("load configuration")
}

async fn run() -> Result<()> {
    let (args, settings): (cli_args, config::Settings) = load_args_and_settings()?;

    info!("Starting");

    run_rhi(&settings, &args).await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{exit_code_from_run, main, run, run_load_hook, run_rhi};
    use radroots_nostr::prelude::{RadrootsNostrClient, RadrootsNostrKeys};
    use rhi::{cli_args, config};
    use std::path::PathBuf;
    use std::process::ExitCode;

    fn minimal_settings() -> config::Settings {
        config::Settings {
            metadata: serde_json::from_str(r#"{"name":"rhi-test"}"#).expect("metadata"),
            config: config::Configuration {
                service: radroots_runtime::RadrootsNostrServiceConfig {
                    logs_dir: "logs".to_string(),
                    relays: Vec::new(),
                    nip89_identifier: Some("rhi".to_string()),
                    nip89_extra_tags: Vec::new(),
                },
                subscriber: config::SubscriberConfig::default(),
            },
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
            service: radroots_runtime::RadrootsServiceCliArgs {
                config: PathBuf::from("config.toml"),
                identity: Some(PathBuf::from("/tmp/rhi-missing-identity.json")),
                allow_generate_identity: false,
            },
        };
        let settings = minimal_settings();
        let err = run_rhi(&settings, &args).await.expect_err("identity should fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("identity"));
    }

    #[test]
    fn main_returns_success_in_test_build() {
        assert_eq!(main(), ExitCode::SUCCESS);
    }

    #[tokio::test]
    async fn run_uses_injected_config_loader_result() {
        let args = cli_args {
            service: radroots_runtime::RadrootsServiceCliArgs {
                config: PathBuf::from("config.toml"),
                identity: Some(PathBuf::from("/tmp/rhi-run-hook-missing.json")),
                allow_generate_identity: false,
            },
        };
        *run_load_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Ok((args, minimal_settings())));
        let err = run().await.expect_err("missing identity should bubble");
        let msg = format!("{err:#}");
        assert!(msg.contains("identity"));
    }

    #[tokio::test]
    async fn run_returns_error_when_loader_hook_is_absent() {
        *run_load_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        let err = run().await.expect_err("loader hook should be required in test build");
        let msg = format!("{err:#}");
        assert!(msg.contains("run loader hook not set"));
    }

    #[tokio::test]
    async fn non_test_start_subscriber_path_can_start_and_stop() {
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let handle = rhi::rhi::start_subscriber(
            client,
            keys,
            radroots_runtime::BackoffConfig {
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
}
