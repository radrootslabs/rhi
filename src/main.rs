use anyhow::{Context, Result};
use rhi::{cli_args, config, run_rhi};
use std::process::ExitCode;
use tracing::info;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
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
            |a: &cli_args| Some(a.config.as_path()),
            |cfg: &config::Settings| cfg.config.logs_dir.as_str(),
            None,
        )
        .context("load configuration")?;

    info!("Starting");

    run_rhi(&settings, &args).await
}
