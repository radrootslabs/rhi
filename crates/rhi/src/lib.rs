pub mod adapters;
pub mod config;
pub mod infra;

pub mod features {
    pub mod trade_listing;
}

pub mod identity {
    pub mod keys;
}

use anyhow::Result;
use nostr::event::Event;
use nostr_sdk::Client;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};

use crate::{config::Settings, features::trade_listing, identity::keys::KeyProfile};

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    about = env!("CARGO_PKG_DESCRIPTION"),
    author = env!("CARGO_PKG_AUTHORS"),
    version = env!("CARGO_PKG_VERSION")
)]
pub struct Args {
    #[arg(
        long,
        value_name = "PATH",
        value_parser = clap::value_parser!(PathBuf),
        help = "(Optional) Path to config file; default is 'config.toml'"
    )]
    pub config: Option<PathBuf>,
}

pub async fn run(settings: Settings) -> Result<()> {
    let mut key_profile = KeyProfile::init(
        &settings.config.keys_path,
        settings.config.generate_keys,
        settings.config.identifier.clone(),
    )?;

    let keys = key_profile.keys()?;
    let metadata = settings.metadata.clone();

    let mut events_to_send: Vec<Event> = vec![];

    if let Some(event) = key_profile.build_metadata(&metadata).await? {
        events_to_send.push(event);
    }

    if let Some(event) = key_profile.build_application_handler().await? {
        events_to_send.push(event);
    }

    if !events_to_send.is_empty() {
        let client = Client::new(keys.clone());
        for relay in &settings.config.relays {
            client.add_relay(relay).await?;
        }
        client.connect().await;
        for event in events_to_send {
            client.send_event(&event).await?;
            info!("Sent kind {} event for key profile", event.kind);
        }
        client.disconnect().await;
    }

    let keys_sub = keys.clone();
    let relays_sub = settings.config.relays.clone();

    tokio::spawn(async move {
        loop {
            if let Err(e) =
                trade_listing::subscriber::subscriber(keys_sub.clone(), relays_sub.clone()).await
            {
                error!("Error on job request subscription: {e}");
            }
        }
    });

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM. Shutting down...");
        },
        _ = sigint.recv() => {
            info!("Received SIGINT. Shutting down...");
        }
    }

    Ok(())
}
