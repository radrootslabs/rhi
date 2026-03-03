#![cfg_attr(coverage_nightly, coverage(off))]

use std::time::{Duration, Instant};

use radroots_nostr::prelude::{RadrootsNostrClient, RadrootsNostrKeys};
use radroots_runtime::{Backoff, BackoffConfig};

#[cfg(not(test))]
fn connection_wait_timeout() -> Duration {
    Duration::from_secs(5)
}

#[cfg(test)]
fn connection_wait_timeout() -> Duration {
    Duration::from_millis(10)
}

#[cfg(test)]
static SUBSCRIBER_RESULT_HOOK: std::sync::OnceLock<
    std::sync::Mutex<std::collections::VecDeque<Result<(), anyhow::Error>>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn subscriber_result_hook() -> &'static std::sync::Mutex<std::collections::VecDeque<Result<(), anyhow::Error>>> {
    SUBSCRIBER_RESULT_HOOK.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::new()))
}

async fn run_subscriber_once(
    client: RadrootsNostrClient,
    keys: RadrootsNostrKeys,
    stop_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), anyhow::Error> {
    #[cfg(test)]
    if let Some(result) = subscriber_result_hook()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .pop_front()
    {
        return result;
    }

    crate::features::trade_listing::subscriber::subscriber(client, keys, stop_rx).await
}

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
                _ = client.wait_for_connection(connection_wait_timeout()) => {}
                _ = stop_rx.changed() => break,
            }

            let res = run_subscriber_once(
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use anyhow::anyhow;
    use super::{Rhi, RhiHandle, start_subscriber, subscriber_result_hook};
    use radroots_nostr::prelude::{RadrootsNostrClient, RadrootsNostrKeys};
    use radroots_runtime::BackoffConfig;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[test]
    fn rhi_new_initializes_client() {
        let keys = RadrootsNostrKeys::generate();
        let rhi = Rhi::new(keys);
        let _ = rhi.client.clone();
    }

    #[tokio::test]
    async fn rhi_handle_stop_and_stopped_cover_paths() {
        let (tx, _rx) = tokio::sync::watch::channel(false);
        let join = tokio::spawn(async {});
        let handle = RhiHandle {
            stop_tx: Arc::new(Mutex::new(Some(tx))),
            join: Some(join),
        };
        handle.stop();
        handle.stop();
        handle.clone().stopped().await;
        handle.stopped().await;
    }

    #[tokio::test]
    async fn start_subscriber_runs_with_and_without_relay() {
        let keys = RadrootsNostrKeys::generate();
        let cfg = BackoffConfig {
            base_ms: 1,
            max_ms: 2,
            factor: 1,
            jitter_ms: 0,
        };

        let client_err = RadrootsNostrClient::new(keys.clone());
        let handle_err = start_subscriber(client_err, keys.clone(), cfg.clone()).await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        handle_err.stop();
        handle_err.stopped().await;

        let client_ok = RadrootsNostrClient::new(keys.clone());
        let _ = client_ok.add_relay("wss://relay.example.com").await;
        subscriber_result_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(Ok(()));
        let handle_ok = start_subscriber(client_ok, keys, cfg).await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        handle_ok.stop();
        handle_ok.stopped().await;
    }

    #[tokio::test]
    async fn start_subscriber_stops_during_connection_wait_branch() {
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let handle = start_subscriber(
            client,
            keys,
            BackoffConfig {
                base_ms: 25,
                max_ms: 50,
                factor: 1,
                jitter_ms: 0,
            },
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        handle.stop();
        handle.stopped().await;
    }

    #[tokio::test]
    async fn start_subscriber_stops_during_backoff_wait_branch() {
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let _ = client.add_relay("wss://relay.example.com").await;
        subscriber_result_hook()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(Err(anyhow!("forced subscriber failure")));
        let handle = start_subscriber(
            client,
            keys,
            BackoffConfig {
                base_ms: 200,
                max_ms: 200,
                factor: 1,
                jitter_ms: 0,
            },
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        handle.stop();
        handle.stopped().await;
    }
}
