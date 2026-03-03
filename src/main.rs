use anyhow::{Context, Result};
use rhi::{cli_args, config, run_rhi};
use std::process::ExitCode;
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    exit_code_from_run(run().await)
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

async fn run() -> Result<()> {
    let (args, settings): (cli_args, config::Settings) =
        radroots_runtime::parse_and_load_path_with_init(
            |a: &cli_args| Some(a.service.config.as_path()),
            |cfg: &config::Settings| cfg.config.service.logs_dir.as_str(),
            None,
        )
        .context("load configuration")?;

    info!("Starting");

    run_rhi(&settings, &args).await
}

#[cfg(test)]
mod tests {
    use super::{exit_code_from_run, run_rhi};
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
        assert!(msg.contains("identity") || msg.contains("not found"));
    }
}
