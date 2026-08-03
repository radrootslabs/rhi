use crate::host_runtime::ServiceCliArgs;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    about = env!("CARGO_PKG_DESCRIPTION"),
    author = env!("CARGO_PKG_AUTHORS"),
    version = env!("CARGO_PKG_VERSION")
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub service: ServiceCliArgs,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Command {
    #[command(
        name = "attestation-smoke",
        about = "Run a release-product agreement attestation smoke request"
    )]
    AttestationSmoke {
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}
