#![forbid(unsafe_code)]

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use radroots_nostr::prelude::{
    radroots_nostr_filter_new_events,
    radroots_nostr_tags_resolve,
    RadrootsNostrClient,
    RadrootsNostrFilter,
    RadrootsNostrKind,
    RadrootsNostrKeys,
    RadrootsNostrRelayPoolNotification,
};
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{info, warn};

use radroots_trade::listing::dvm_kinds::TRADE_LISTING_DVM_KINDS;

use crate::features::trade_listing::{
    handlers::dvm::{handle_error, handle_event, TradeListingDvmError},
    state::TradeListingState,
};

pub async fn subscriber(
    client: RadrootsNostrClient,
    keys: RadrootsNostrKeys,
    mut stop_rx: watch::Receiver<bool>,
) -> Result<()> {
    info!(
        "Starting subscriber for trade listing DVM kinds: {:?}",
        TRADE_LISTING_DVM_KINDS
    );

    let kinds: Vec<RadrootsNostrKind> = TRADE_LISTING_DVM_KINDS
        .iter()
        .map(|kind| RadrootsNostrKind::Custom(*kind))
        .collect();
    let filter = radroots_nostr_filter_new_events(RadrootsNostrFilter::new().kinds(kinds));

    if *stop_rx.borrow() {
        return Ok(());
    }

    let subscription = client.subscribe(filter, None).await?;

    let state = Arc::new(tokio::sync::Mutex::new(TradeListingState::default()));
    let mut notifications = client.notifications();

    let mut stop_requested = false;
    let mut notifications_closed = false;

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                stop_requested = true;
                break;
            }
            msg = notifications.recv() => {
                let n = match msg {
                    Ok(n) => n,
                    Err(_) => {
                        notifications_closed = true;
                        break;
                    }
                };

                if let RadrootsNostrRelayPoolNotification::Event { event, .. } = n {
                    let event = (*event).clone();
                    let keys = keys.clone();
                    let client = client.clone();
                    let state = Arc::clone(&state);

                    tokio::spawn(async move {
                        if cfg!(debug_assertions) {
                            sleep(Duration::from_millis(200)).await;
                        }

                        let resolved_tags = match radroots_nostr_tags_resolve(&event, &keys) {
                            Ok(tags) => tags,
                            Err(err) => {
                                warn!("trade_listing: failed to resolve tags: {err}");
                                return;
                            }
                        };

                        if let Err(err) =
                            handle_event(event.clone(), resolved_tags, keys, client.clone(), state).await
                        {
                            match err {
                                TradeListingDvmError::MissingRecipient
                                | TradeListingDvmError::UnsupportedKind => {}
                                other => {
                                    if let Err(err) = handle_error(other, &event, &client).await {
                                        warn!("trade_listing: failed to send error feedback: {err}");
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    client.unsubscribe(&subscription.val).await;
    if stop_requested {
        return Ok(());
    }
    if notifications_closed {
        return Err(anyhow!("trade_listing subscriber notifications closed"));
    }
    Ok(())
}
