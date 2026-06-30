#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use std::convert::TryFrom;
use std::time::Duration;

use anyhow::{Result, anyhow};
use radroots_events::kinds::{
    KIND_LISTING, KIND_LISTING_DRAFT, ORDER_EVENT_KINDS, TRADE_VALIDATION_EVENT_KINDS,
    is_trade_validation_service_event_kind,
};
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrFilter, RadrootsNostrKeys,
    RadrootsNostrKind, RadrootsNostrRelayPoolNotification, RadrootsNostrSubscriptionId,
    RadrootsNostrTag, radroots_nostr_tags_resolve,
};
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::features::trade_listing::{
    handlers::dvm::{TradeListingDvmError, handle_error, handle_event_with_policy},
    state::TradeListingRuntime,
};
use crate::features::trade_validation_receipt::TradeValidationReceiptProverPolicy;

#[cfg(test)]
#[derive(Default)]
struct SubscriberTestHooks {
    subscribe_results: std::collections::VecDeque<Result<RadrootsNostrSubscriptionId, ()>>,
    unsubscribe_results: std::collections::VecDeque<()>,
    notifications: std::collections::VecDeque<Result<RadrootsNostrRelayPoolNotification, ()>>,
    delay_before_event_handle: std::collections::VecDeque<bool>,
    resolve_tags_results: std::collections::VecDeque<
        Result<Vec<RadrootsNostrTag>, radroots_nostr::error::RadrootsNostrTagsResolveError>,
    >,
    handle_event_results: std::collections::VecDeque<Result<(), TradeListingDvmError>>,
    handle_error_results: std::collections::VecDeque<Result<(), TradeListingDvmError>>,
}

#[cfg(test)]
static SUBSCRIBER_TEST_HOOKS: std::sync::OnceLock<std::sync::Mutex<SubscriberTestHooks>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn subscriber_test_hooks() -> &'static std::sync::Mutex<SubscriberTestHooks> {
    SUBSCRIBER_TEST_HOOKS.get_or_init(|| std::sync::Mutex::new(SubscriberTestHooks::default()))
}

#[cfg(test)]
fn pop_subscribe_hook() -> Option<Result<RadrootsNostrSubscriptionId, ()>> {
    subscriber_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .subscribe_results
        .pop_front()
}

#[cfg(test)]
fn pop_unsubscribe_hook() -> Option<()> {
    subscriber_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .unsubscribe_results
        .pop_front()
}

#[cfg(test)]
fn pop_notification_hook() -> Option<Result<RadrootsNostrRelayPoolNotification, ()>> {
    subscriber_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .notifications
        .pop_front()
}

#[cfg(test)]
fn pop_delay_hook() -> Option<bool> {
    subscriber_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .delay_before_event_handle
        .pop_front()
}

#[cfg(test)]
fn take_delay_hook() -> Option<bool> {
    pop_delay_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_delay_hook() -> Option<bool> {
    None
}

#[cfg(test)]
fn pop_resolve_tags_hook()
-> Option<Result<Vec<RadrootsNostrTag>, radroots_nostr::error::RadrootsNostrTagsResolveError>> {
    subscriber_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .resolve_tags_results
        .pop_front()
}

#[cfg(test)]
fn take_resolve_tags_hook()
-> Option<Result<Vec<RadrootsNostrTag>, radroots_nostr::error::RadrootsNostrTagsResolveError>> {
    pop_resolve_tags_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_resolve_tags_hook()
-> Option<Result<Vec<RadrootsNostrTag>, radroots_nostr::error::RadrootsNostrTagsResolveError>> {
    None
}

#[cfg(test)]
fn pop_handle_event_hook() -> Option<Result<(), TradeListingDvmError>> {
    subscriber_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .handle_event_results
        .pop_front()
}

#[cfg(test)]
fn take_handle_event_hook() -> Option<Result<(), TradeListingDvmError>> {
    pop_handle_event_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_handle_event_hook() -> Option<Result<(), TradeListingDvmError>> {
    None
}

#[cfg(test)]
fn pop_handle_error_hook() -> Option<Result<(), TradeListingDvmError>> {
    subscriber_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .handle_error_results
        .pop_front()
}

#[cfg(test)]
fn take_handle_error_hook() -> Option<Result<(), TradeListingDvmError>> {
    pop_handle_error_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_handle_error_hook() -> Option<Result<(), TradeListingDvmError>> {
    None
}

fn resolve_tags_io(
    event: &RadrootsNostrEvent,
    keys: &RadrootsNostrKeys,
) -> Result<Vec<RadrootsNostrTag>, radroots_nostr::error::RadrootsNostrTagsResolveError> {
    let resolved = match take_resolve_tags_hook() {
        Some(result) => result?,
        None => return radroots_nostr_tags_resolve(event, keys),
    };
    Ok(resolved)
}

fn map_notification_recv_result(
    result: Result<RadrootsNostrRelayPoolNotification, tokio::sync::broadcast::error::RecvError>,
) -> Result<RadrootsNostrRelayPoolNotification, ()> {
    result.map_err(|_| ())
}

async fn subscribe_io(
    client: &RadrootsNostrClient,
    filter: RadrootsNostrFilter,
) -> Result<RadrootsNostrSubscriptionId> {
    #[cfg(test)]
    if let Some(result) = pop_subscribe_hook() {
        return result.map_err(|_| anyhow!("trade_listing subscriber subscribe failed"));
    }
    let subscription = client.subscribe(filter, None).await?;
    Ok(subscription.val)
}

async fn unsubscribe_io(
    client: &RadrootsNostrClient,
    subscription_id: &RadrootsNostrSubscriptionId,
) {
    #[cfg(test)]
    if pop_unsubscribe_hook().is_some() {
        return;
    }
    client.unsubscribe(subscription_id).await;
}

async fn handle_event_io(
    event: RadrootsNostrEvent,
    resolved_tags: Vec<RadrootsNostrTag>,
    keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    runtime: TradeListingRuntime,
    proof_policy: TradeValidationReceiptProverPolicy,
) -> Result<(), TradeListingDvmError> {
    let result = match take_handle_event_hook() {
        Some(result) => result,
        None => {
            handle_event_with_policy(event, resolved_tags, keys, client, runtime, &proof_policy)
                .await
        }
    };
    result?;
    Ok(())
}

async fn handle_error_io(
    err: TradeListingDvmError,
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
) -> Result<(), TradeListingDvmError> {
    let result = match take_handle_error_hook() {
        Some(result) => result,
        None => handle_error(err, event, client).await,
    };
    result?;
    Ok(())
}

fn should_delay_before_event_handle() -> bool {
    if let Some(delay) = take_delay_hook() {
        return delay;
    }
    cfg!(all(debug_assertions, not(test)))
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn process_event_notification(
    event: RadrootsNostrEvent,
    keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    runtime: TradeListingRuntime,
    proof_policy: TradeValidationReceiptProverPolicy,
) -> Result<()> {
    let created_at = u32::try_from(event.created_at.as_secs()).unwrap_or(u32::MAX);
    if should_delay_before_event_handle() {
        sleep(Duration::from_millis(200)).await;
    }

    let resolved_tags = match resolve_tags_io(&event, &keys) {
        Ok(tags) => tags,
        Err(err) => {
            warn!("trade_listing: failed to resolve tags: {err}");
            return Ok(());
        }
    };

    let event_kind = match event.kind {
        RadrootsNostrKind::Custom(v) => Some(u32::from(v)),
        _ => None,
    };
    if let Err(err) = handle_event_io(
        event.clone(),
        resolved_tags,
        keys,
        client.clone(),
        runtime.clone(),
        proof_policy,
    )
    .await
    {
        match err {
            TradeListingDvmError::MissingRecipient | TradeListingDvmError::UnsupportedKind => {}
            other => {
                if event_kind.is_some_and(is_trade_validation_service_event_kind) {
                    if let Err(err) = handle_error_io(other, &event, &client).await {
                        warn!("trade_listing: failed to send error feedback: {err}");
                    }
                } else {
                    warn!("trade_listing: rejected public trade event: {other}");
                }
                runtime.mark_processed_event(created_at).await?;
            }
        }
        return Ok(());
    }

    runtime.mark_processed_event(created_at).await?;
    Ok(())
}

async fn dispatch_event_processing(
    event: RadrootsNostrEvent,
    keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    runtime: TradeListingRuntime,
    proof_policy: TradeValidationReceiptProverPolicy,
) -> Result<()> {
    process_event_notification(event, keys, client, runtime, proof_policy).await
}

pub async fn subscriber(
    client: RadrootsNostrClient,
    keys: RadrootsNostrKeys,
    runtime: TradeListingRuntime,
    proof_policy: TradeValidationReceiptProverPolicy,
    mut stop_rx: watch::Receiver<bool>,
) -> Result<()> {
    let subscribed_kinds = [KIND_LISTING, KIND_LISTING_DRAFT]
        .into_iter()
        .chain(ORDER_EVENT_KINDS)
        .chain(TRADE_VALIDATION_EVENT_KINDS)
        .collect::<Vec<_>>();
    info!(
        "Starting subscriber for trade listing, order, and trade validation kinds: {:?}",
        subscribed_kinds
    );

    let kinds: Vec<RadrootsNostrKind> = subscribed_kinds
        .iter()
        .map(|kind| u16::try_from(*kind).expect("trade listing kinds fit in nostr custom range"))
        .map(RadrootsNostrKind::Custom)
        .collect();
    let filter: RadrootsNostrFilter = runtime.recovery_filter(kinds).await;

    if *stop_rx.borrow() {
        return Ok(());
    }

    let subscription_id = subscribe_io(&client, filter).await?;
    let mut notifications = client.notifications();

    let mut notifications_closed = false;

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                break;
            }
            msg = async {
                #[cfg(test)]
                if let Some(result) = pop_notification_hook() {
                    return result;
                }
                map_notification_recv_result(notifications.recv().await)
            } => {
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
                    let runtime = runtime.clone();
                    let proof_policy = proof_policy.clone();
                    dispatch_event_processing(event, keys, client, runtime, proof_policy).await?;
                }
            }
        }
    }

    unsubscribe_io(&client, &subscription_id).await;
    if notifications_closed {
        return Err(anyhow!("trade_listing subscriber notifications closed"));
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        SubscriberTestHooks, handle_error_io, handle_event_io, map_notification_recv_result,
        process_event_notification, resolve_tags_io, subscriber, subscriber_test_hooks,
    };
    use crate::features::trade_listing::handlers::dvm::TradeListingDvmError;
    use crate::features::trade_listing::state::TradeListingRuntime;
    use crate::features::trade_validation_receipt::TradeValidationReceiptProverPolicy;
    use radroots_nostr::error::RadrootsNostrTagsResolveError;
    use radroots_nostr::prelude::{
        RadrootsNostrClient, RadrootsNostrEventBuilder, RadrootsNostrKeys, RadrootsNostrKind,
        RadrootsNostrRelayPoolNotification, RadrootsNostrRelayUrl, RadrootsNostrSubscriptionId,
        RadrootsNostrTag,
    };
    use tokio::sync::{Mutex, MutexGuard, watch};

    static TEST_LOCK: Mutex<()> = Mutex::const_new(());

    async fn test_guard() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().await;
        *subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = SubscriberTestHooks::default();
        guard
    }

    fn scripted_event_notification(keys: &RadrootsNostrKeys) -> RadrootsNostrRelayPoolNotification {
        let event = RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(6000), "test")
            .sign_with_keys(keys)
            .expect("event");
        RadrootsNostrRelayPoolNotification::Event {
            relay_url: RadrootsNostrRelayUrl::parse("wss://relay.example.com").expect("relay"),
            subscription_id: RadrootsNostrSubscriptionId::new("sub-1"),
            event: Box::new(event),
        }
    }

    fn scripted_shutdown_notification() -> RadrootsNostrRelayPoolNotification {
        RadrootsNostrRelayPoolNotification::Shutdown
    }

    fn prime_subscription_hooks() {
        let mut hooks = subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks
            .subscribe_results
            .push_back(Ok(RadrootsNostrSubscriptionId::new("sub-hook")));
        hooks.unsubscribe_results.push_back(());
    }

    fn shared_runtime() -> TradeListingRuntime {
        TradeListingRuntime::new()
    }

    fn proof_policy() -> TradeValidationReceiptProverPolicy {
        TradeValidationReceiptProverPolicy::default()
    }

    #[test]
    fn notification_recv_result_mapping_covers_ok_and_err() {
        let keys = RadrootsNostrKeys::generate();
        assert!(map_notification_recv_result(Ok(scripted_event_notification(&keys))).is_ok());
        assert!(
            map_notification_recv_result(Err(tokio::sync::broadcast::error::RecvError::Closed))
                .is_err()
        );
    }

    #[tokio::test]
    async fn subscriber_io_wrappers_cover_fallback_and_hook_paths() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let event = RadrootsNostrEventBuilder::new(RadrootsNostrKind::TextNote, "test")
            .sign_with_keys(&keys)
            .expect("event");

        let _ = resolve_tags_io(&event, &keys);
        subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolve_tags_results
            .push_back(Ok(Vec::<RadrootsNostrTag>::new()));
        assert!(resolve_tags_io(&event, &keys).is_ok());

        let runtime = shared_runtime();
        assert!(matches!(
            handle_event_io(
                event.clone(),
                Vec::new(),
                keys.clone(),
                client.clone(),
                runtime.clone(),
                proof_policy()
            )
            .await,
            Err(TradeListingDvmError::UnsupportedKind)
        ));
        subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .handle_event_results
            .push_back(Ok(()));
        assert!(
            handle_event_io(
                event.clone(),
                Vec::new(),
                keys.clone(),
                client.clone(),
                runtime,
                proof_policy()
            )
            .await
            .is_ok()
        );

        let _ = handle_error_io(TradeListingDvmError::InvalidOrder, &event, &client).await;
        subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .handle_error_results
            .push_back(Ok(()));
        assert!(
            handle_error_io(TradeListingDvmError::InvalidOrder, &event, &client)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn subscriber_returns_ok_when_stop_is_pre_requested() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let (_tx, rx) = watch::channel(true);
        assert!(
            subscriber(client, keys, shared_runtime(), proof_policy(), rx)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn subscriber_reuses_runtime_owned_state_across_runs() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let runtime = shared_runtime();
        let state = runtime.state();
        state
            .lock()
            .await
            .mark_listing_validated("addr", "evt-listing-1");

        let (_tx_first, rx_first) = watch::channel(true);
        assert!(
            subscriber(
                client.clone(),
                keys.clone(),
                runtime.clone(),
                proof_policy(),
                rx_first
            )
            .await
            .is_ok()
        );
        assert!(state.lock().await.is_listing_validated("addr"));

        let (_tx_second, rx_second) = watch::channel(true);
        assert!(
            subscriber(client, keys, runtime.clone(), proof_policy(), rx_second)
                .await
                .is_ok()
        );
        assert!(state.lock().await.is_listing_validated("addr"));
    }

    #[tokio::test]
    async fn subscriber_returns_err_when_no_relays_are_configured() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let (_tx, rx) = watch::channel(false);
        let err = subscriber(client, keys, shared_runtime(), proof_policy(), rx)
            .await
            .expect_err("expected relay error");
        let msg = format!("{err:#}");
        assert!(msg.contains("relay"));
    }

    #[tokio::test]
    async fn subscriber_can_stop_after_start_when_subscription_is_ready() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        prime_subscription_hooks();
        let (tx, rx) = watch::channel(false);
        let join = tokio::spawn(subscriber(
            client,
            keys,
            shared_runtime(),
            proof_policy(),
            rx,
        ));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let _ = tx.send(true);
        let _ = join.await;
    }

    #[tokio::test]
    async fn subscriber_covers_notification_closed_path() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        prime_subscription_hooks();
        subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .notifications
            .push_back(Err(()));
        let (_tx, rx) = watch::channel(false);
        let err = subscriber(client, keys, shared_runtime(), proof_policy(), rx)
            .await
            .expect_err("closed notifications");
        let msg = format!("{err:#}");
        assert!(msg.contains("notifications closed"));
    }

    #[tokio::test]
    async fn subscriber_covers_non_event_notification_and_stop_ok_path() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        prime_subscription_hooks();

        subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .notifications
            .push_back(Ok(scripted_shutdown_notification()));

        let (tx, rx) = watch::channel(false);
        let join = tokio::spawn(subscriber(
            client,
            keys,
            shared_runtime(),
            proof_policy(),
            rx,
        ));
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let _ = tx.send(true);
        let result = join.await.expect("subscriber join");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn subscriber_covers_event_processing_paths() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        prime_subscription_hooks();
        subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .notifications
            .push_back(Ok(scripted_event_notification(&keys)));
        subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .resolve_tags_results
            .push_back(Err(RadrootsNostrTagsResolveError::DecryptionError(
                "resolve-failed".to_string(),
            )));
        let (tx, rx) = watch::channel(false);
        let join = tokio::spawn(subscriber(
            client,
            keys,
            shared_runtime(),
            proof_policy(),
            rx,
        ));
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let _ = tx.send(true);
        let _ = join.await;
    }

    #[tokio::test]
    async fn subscriber_covers_handle_event_and_error_paths() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        prime_subscription_hooks();

        let mut hooks = subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks
            .notifications
            .push_back(Ok(scripted_event_notification(&keys)));
        hooks
            .notifications
            .push_back(Ok(scripted_event_notification(&keys)));
        hooks.resolve_tags_results.push_back(Ok(Vec::new()));
        hooks.resolve_tags_results.push_back(Ok(Vec::new()));
        hooks
            .handle_event_results
            .push_back(Err(TradeListingDvmError::MissingRecipient));
        hooks
            .handle_event_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        hooks
            .handle_error_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        drop(hooks);

        let (tx, rx) = watch::channel(false);
        let join = tokio::spawn(subscriber(
            client,
            keys,
            shared_runtime(),
            proof_policy(),
            rx,
        ));
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let _ = tx.send(true);
        let _ = join.await;
    }

    #[tokio::test]
    async fn subscriber_covers_delay_and_error_feedback_warn_path() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        prime_subscription_hooks();

        let mut hooks = subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks
            .notifications
            .push_back(Ok(scripted_event_notification(&keys)));
        hooks.notifications.push_back(Err(()));
        hooks.delay_before_event_handle.push_back(true);
        hooks.resolve_tags_results.push_back(Ok(Vec::new()));
        hooks
            .handle_event_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        hooks
            .handle_error_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        drop(hooks);

        let (_tx, rx) = watch::channel(false);
        let err = subscriber(client, keys, shared_runtime(), proof_policy(), rx)
            .await
            .expect_err("notifications closed");
        let msg = format!("{err:#}");
        assert!(msg.contains("notifications closed"));
    }

    #[tokio::test]
    async fn handled_domain_errors_advance_replay_anchor() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let runtime = shared_runtime();
        let event = RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(6000), "test")
            .custom_created_at(1_234_u64.into())
            .sign_with_keys(&keys)
            .expect("event");

        let mut hooks = subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks.resolve_tags_results.push_back(Ok(Vec::new()));
        hooks
            .handle_event_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        hooks.handle_error_results.push_back(Ok(()));
        drop(hooks);

        process_event_notification(event, keys, client, runtime.clone(), proof_policy())
            .await
            .expect("notification");

        assert_eq!(
            runtime.state().lock().await.last_event_created_at(),
            Some(1_234)
        );
    }

    #[tokio::test]
    async fn subscriber_process_event_feedback_error_branches_are_covered() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let event = RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(6000), "event")
            .sign_with_keys(&keys)
            .expect("event");
        let runtime = shared_runtime();

        let mut hooks = subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks.resolve_tags_results.push_back(Ok(Vec::new()));
        hooks
            .handle_event_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        hooks
            .handle_error_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        drop(hooks);

        process_event_notification(event, keys, client, runtime, proof_policy())
            .await
            .expect("processing");
    }

    #[tokio::test]
    async fn subscriber_process_event_feedback_non_error_branches_are_covered() {
        let _guard = test_guard().await;
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let event_ok = RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(6000), "ok")
            .sign_with_keys(&keys)
            .expect("event ok");
        let event_err = RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(6000), "err")
            .sign_with_keys(&keys)
            .expect("event err");
        let runtime = shared_runtime();

        let mut hooks = subscriber_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hooks.resolve_tags_results.push_back(Ok(Vec::new()));
        hooks.handle_event_results.push_back(Ok(()));
        hooks.resolve_tags_results.push_back(Ok(Vec::new()));
        hooks
            .handle_event_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        hooks.handle_error_results.push_back(Ok(()));
        drop(hooks);

        process_event_notification(
            event_ok,
            keys.clone(),
            client.clone(),
            runtime.clone(),
            proof_policy(),
        )
        .await
        .expect("ok path");
        process_event_notification(event_err, keys, client, runtime, proof_policy())
            .await
            .expect("error path");
    }
}
