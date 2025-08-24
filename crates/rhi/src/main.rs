use anyhow::Result;
use rhi::{cli_args, config, run_rhi};
use tracing::info;

#[tokio::main]
async fn main() {
    if let Err(err) = setup().await {
        eprintln!("Fatal error: {err:#?}");
        std::process::exit(1);
    }
}

async fn setup() -> Result<()> {
    let (args, settings): (cli_args, config::Settings) =
        radroots_runtime::parse_and_load_path(|a: &cli_args| Some(a.config.as_path()))?;

    radroots_runtime::init_with(&settings.config.logs_dir, None)?;

    info!("Starting");

    run_rhi(&settings, &args).await
}
