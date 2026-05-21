use clap::Parser;
use radroots_runtime::RadrootsServiceCliArgs;
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
    pub service: RadrootsServiceCliArgs,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum Command {
    #[command(
        name = "proof-smoke",
        about = "Run a provider-neutral proof smoke request"
    )]
    ProofSmoke {
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    #[command(
        name = "remote-prove",
        about = "Run a provider-neutral remote proof request"
    )]
    RemoteProve {
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "cpu", value_parser = ["cpu", "cuda"])]
        proof_engine: String,
    },
}
