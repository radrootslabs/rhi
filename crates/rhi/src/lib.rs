pub mod adapters;
pub mod cli;
pub mod config;
pub mod infra;
pub mod rhi;

pub mod features {
    pub mod trade_listing;
}

pub mod key_profile;

pub use cli::Args as cli_args;

use anyhow::Result;

use crate::{
    key_profile::KeyProfile,
    rhi::{Rhi, start_subscriber},
};

pub async fn run_rhi(settings: &config::Settings, args: &cli_args) -> Result<()> {
    let identity = radroots_identity::load_or_generate::<KeyProfile, _>(
        args.identity.as_ref(),
        args.allow_generate_identity,
    )?;
    let keys = radroots_identity::to_keys(&identity.value)?;

    let rhi = Rhi::new(keys.clone());

    for relay in settings.config.relays.iter() {
        rhi.client.add_relay(relay).await?;
    }

    if !settings.config.relays.is_empty() {
        let client = rhi.client.clone();
        let md = settings.metadata.clone();
        let has_metadata = serde_json::to_value(&md)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .map(|o| !o.is_empty())
            .unwrap_or(false);

        tokio::spawn(async move {
            client.connect().await;
            if has_metadata {
                if let Err(e) = client.set_metadata(&md).await {
                    tracing::warn!("Failed to publish metadata on startup: {e}");
                } else {
                    tracing::info!("Published metadata on startup");
                }
            }
        });
    }

    let keys_sub = keys.clone();
    let relays_sub = settings.config.relays.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = crate::features::trade_listing::subscriber::subscriber(
                keys_sub.clone(),
                relays_sub.clone(),
            )
            .await
            {
                tracing::error!("Error on job request subscription: {e}");
            }
        }
    });

    let handle = start_subscriber(keys.clone(), settings.config.relays.clone()).await;

    let stop_handle = handle.clone();

    tokio::select! {
        _ = radroots_runtime::shutdown_signal() => {
            tracing::info!("Shutting down…");
            stop_handle.stop();
        }
        _ = handle.stopped() => {}
    }

    /*
    let identity = radroots_identity::load_or_generate::<KeyProfile, _>(
        args.identity.as_ref(),
        args.allow_generate_identity,
    )?;
    let keys = radroots_identity::to_keys(&identity.value)?;

    let metadata = settings.metadata.clone();

    let mut events_to_send: Vec<Event> = vec![];

    if let Some(event) = identity.value.metadata.clone() {
        events_to_send.push(event);
    }

    if let Some(event) = identity.value.application_handler.clone() {
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
    */

    Ok(())
}
