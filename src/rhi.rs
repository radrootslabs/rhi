use std::time::{Duration, Instant};

use radroots_nostr::prelude::{RadrootsNostrClient, RadrootsNostrKeys};
use radroots_runtime::{Backoff, BackoffConfig};

pub struct Rhi {
    pub(crate) _started: Instant,
    pub client: RadrootsNostrClient,
}

impl Rhi {
    pub fn new(keys: RadrootsNostrKeys) -> Self {
        let client = RadrootsNostrClient::new(keys);
        Self {
            _started: Instant::now(),
            client,
        }
    }
}

use std::sync::Arc;
use tokio::sync::Mutex;

pub struct RhiHandle {
    stop_tx: Arc<Mutex<Option<tokio::sync::watch::Sender<bool>>>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl Clone for RhiHandle {
    fn clone(&self) -> Self {
        Self {
            stop_tx: Arc::clone(&self.stop_tx),
            join: None, // don’t clone the JoinHandle!
        }
    }
}

impl RhiHandle {
    pub fn stop(&self) {
        if let Some(tx) = self.stop_tx.try_lock().ok().and_then(|mut opt| opt.take()) {
            let _ = tx.send(true);
        }
    }

    pub async fn stopped(mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

pub async fn start_subscriber(
    client: RadrootsNostrClient,
    keys: RadrootsNostrKeys,
    backoff_cfg: BackoffConfig,
) -> RhiHandle {
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);

    let join = tokio::spawn(async move {
        let mut backoff = Backoff::new(backoff_cfg);
        loop {
            if *stop_rx.borrow() {
                break;
            }

            client.connect().await;
            tokio::select! {
                _ = client.wait_for_connection(Duration::from_secs(5)) => {}
                _ = stop_rx.changed() => break,
            }

            let res = crate::features::trade_listing::subscriber::subscriber(
                client.clone(),
                keys.clone(),
                stop_rx.clone(),
            )
            .await;

            let failed = res.is_err();

            if let Err(e) = res {
                tracing::error!("Error on job request subscription: {e}");
            } else {
                backoff.reset();
            }

            if *stop_rx.borrow() {
                break;
            }

            if failed {
                let delay = backoff.next_delay();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = stop_rx.changed() => break,
                }
            }
        }
    });

    RhiHandle {
        stop_tx: Arc::new(Mutex::new(Some(stop_tx))),
        join: Some(join),
    }
}
