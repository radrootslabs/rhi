pub mod adapters;
pub mod cli;
pub mod config;
pub mod infra;
pub mod rhi;

pub mod features {
    pub mod trade_listing;
}

pub use cli::Args as cli_args;

use anyhow::Result;
use std::time::Duration;

use crate::rhi::{Rhi, start_subscriber};
use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{
    RadrootsNostrApplicationHandlerSpec, radroots_nostr_bootstrap_service_presence,
};
use radroots_trade::listing::kinds::TRADE_LISTING_KINDS;
use tracing::{info, warn};

pub async fn run_rhi(settings: &config::Settings, args: &cli_args) -> Result<()> {
    let identity = RadrootsIdentity::load_or_generate(
        args.service.identity.as_ref(),
        args.service.allow_generate_identity,
    )?;
    let keys = identity.keys().clone();

    let rhi = Rhi::new(keys.clone());
    let client = rhi.client.clone();
    let service_cfg = settings.config.service.clone();
    let relays = service_cfg.relays.clone();

    for relay in &relays {
        client.add_relay(relay).await?;
    }

    let md = settings.metadata.clone();

    if !relays.is_empty() {
        let handler_kinds = TRADE_LISTING_KINDS
            .iter()
            .map(|kind| *kind as u32)
            .collect();
        let handler_spec = RadrootsNostrApplicationHandlerSpec {
            kinds: handler_kinds,
            identifier: service_cfg.nip89_identifier.clone(),
            metadata: Some(md.clone()),
            extra_tags: service_cfg.nip89_extra_tags.clone(),
            relays: relays.clone(),
            nostrconnect_url: None,
        };
        if let Err(e) = radroots_nostr_bootstrap_service_presence(
            &client,
            &identity,
            None,
            &md,
            &handler_spec,
            Duration::from_secs(5),
        )
        .await
        {
            warn!("Failed to publish service presence on startup: {e}");
        } else {
            info!("Published service presence on startup");
        }
    }

    let handle = start_subscriber(
        client.clone(),
        keys.clone(),
        settings.config.subscriber.backoff.clone(),
    )
    .await;

    let stop_handle = handle.clone();

    tokio::select! {
        _ = radroots_runtime::shutdown_signal() => {
            info!("Shutting down…");
            stop_handle.stop();
        }
        _ = handle.stopped() => {}
    }

    client.unsubscribe_all().await;
    client.disconnect().await;

    Ok(())
}
