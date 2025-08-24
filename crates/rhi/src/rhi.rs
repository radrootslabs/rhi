use nostr_sdk::Client;
use std::time::Instant;

pub struct Rhi {
    pub(crate) _started: Instant,
    pub client: Client,
}

impl Rhi {
    pub fn new(keys: nostr::Keys) -> Self {
        let client = Client::new(keys);
        Self {
            _started: Instant::now(),
            client,
        }
    }
}

use std::sync::Arc;
use tokio::sync::Mutex;

pub struct RhiHandle {
    stop_tx: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
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
            let _ = tx.send(());
        }
    }

    pub async fn stopped(mut self) {
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

pub async fn start_subscriber(keys: nostr::Keys, relays: Vec<String>) -> RhiHandle {
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();

    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                res = crate::features::trade_listing::subscriber::subscriber(keys.clone(), relays.clone()) => {
                    if let Err(e) = res {
                        tracing::error!("Error on job request subscription: {e}");
                    }
                }
            }
        }
    });

    RhiHandle {
        stop_tx: Arc::new(Mutex::new(Some(stop_tx))),
        join: Some(join),
    }
}
