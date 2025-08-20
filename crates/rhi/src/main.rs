use anyhow::Result;
use clap::Parser;
use tracing::{error, info};

use rhi::{Args, config::Settings, infra::telemetry, run};

#[tokio::main]
async fn main() {
    if let Err(err) = setup().await {
        error!("Fatal error: {err:#?}");
        std::process::exit(1);
    }
}

async fn setup() -> Result<()> {
    let args = Args::parse();

    let settings = Settings::load(&args.config)?;

    telemetry::init(&settings.config.logs_dir);
    info!("Starting");

    run(settings).await
}
