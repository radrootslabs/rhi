//! RHI-owned relay client over the final portable Nostr contract.

use core::time::Duration;

pub use nostr::{Event, Filter, Keys, Kind, Metadata, SubscriptionId, Timestamp};
pub use nostr::{Tag, TagKind};
pub use nostr_sdk::RelayPoolNotification;
pub use radroots_nostr::event::{ApplicationHandlerSpec, GenericBuilder, ProfileBuilder};

#[derive(Clone)]
pub struct Client {
    inner: nostr_sdk::Client,
    keys: Keys,
}

impl Client {
    pub fn new(keys: Keys) -> Self {
        let inner = nostr_sdk::Client::new(keys.clone());
        inner.automatic_authentication(false);
        Self { inner, keys }
    }

    pub fn into_inner(self) -> nostr_sdk::Client {
        self.inner
    }
    pub fn keys(&self) -> &Keys {
        &self.keys
    }
    pub async fn connect(&self) {
        self.inner.connect().await;
    }
    pub async fn wait_for_connection(&self, timeout: Duration) {
        self.inner.wait_for_connection(timeout).await;
    }
    pub async fn add_relay(&self, url: &str) -> Result<bool, nostr_sdk::client::Error> {
        self.inner.add_relay(url).await
    }
    pub async fn subscribe(
        &self,
        filter: Filter,
    ) -> Result<SubscriptionId, nostr_sdk::client::Error> {
        Ok(self.inner.subscribe(filter, None).await?.val)
    }
    pub async fn unsubscribe(&self, id: &SubscriptionId) {
        self.inner.unsubscribe(id).await;
    }
    pub async fn send_event(
        &self,
        event: &Event,
    ) -> Result<nostr_sdk::prelude::Output<nostr::EventId>, nostr_sdk::client::Error> {
        self.inner.send_event(event).await
    }
}
