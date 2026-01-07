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

use crate::{
    rhi::{Rhi, start_subscriber},
};
use radroots_identity::RadrootsIdentity;
use radroots_nostr::prelude::{
    radroots_nostr_publish_application_handler,
    radroots_nostr_publish_identity_profile,
    RadrootsNostrApplicationHandlerSpec,
    RadrootsNostrMetadata,
};
use radroots_trade::listing::dvm_kinds::TRADE_LISTING_DVM_KINDS;
use tracing::{info, warn};

fn metadata_has_fields(md: &RadrootsNostrMetadata) -> bool {
    md.name.is_some()
        || md.display_name.is_some()
        || md.about.is_some()
        || md.website.is_some()
        || md.picture.is_some()
        || md.banner.is_some()
        || md.nip05.is_some()
        || md.lud06.is_some()
        || md.lud16.is_some()
        || !md.custom.is_empty()
}

pub async fn run_rhi(settings: &config::Settings, args: &cli_args) -> Result<()> {
    let identity = RadrootsIdentity::load_or_generate(
        args.identity.as_ref(),
        args.allow_generate_identity,
    )?;
    let keys = identity.keys().clone();

    let rhi = Rhi::new(keys.clone());
    let client = rhi.client.clone();
    let relays = settings.config.relays.clone();

    for relay in &relays {
        client.add_relay(relay).await?;
    }

    let md = settings.metadata.clone();
    let has_metadata = metadata_has_fields(&md);

    if !relays.is_empty() {
        client.connect().await;
        client.wait_for_connection(Duration::from_secs(5)).await;
        let profile_published = match radroots_nostr_publish_identity_profile(&client, &identity).await
        {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                warn!("Failed to publish identity profile: {e}");
                false
            }
        };
        if has_metadata && !profile_published {
            if let Err(e) = client.set_metadata(&md).await {
                warn!("Failed to publish metadata on startup: {e}");
            } else {
                info!("Published metadata on startup");
            }
        }

        let handler_kinds = TRADE_LISTING_DVM_KINDS
            .iter()
            .map(|kind| *kind as u32)
            .collect();
        let handler_spec = RadrootsNostrApplicationHandlerSpec {
            kinds: handler_kinds,
            identifier: None,
            metadata: Some(md.clone()),
            extra_tags: Vec::new(),
            relays: relays.clone(),
            nostrconnect_url: None,
        };
        if let Err(e) = radroots_nostr_publish_application_handler(&client, &handler_spec).await {
            warn!("Failed to publish NIP-89 announcement: {e}");
        } else {
            info!("Published NIP-89 announcement");
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
