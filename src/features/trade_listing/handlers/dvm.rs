#![forbid(unsafe_code)]

use std::{sync::Arc, time::Duration};

use radroots_events::kinds::KIND_FARM;
use radroots_events::listing::RadrootsListingFarmRef;
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrFilter,
    RadrootsNostrKind, RadrootsNostrKeys, RadrootsNostrTag, radroots_event_from_nostr,
    radroots_nostr_build_event, radroots_nostr_build_event_job_feedback,
    radroots_nostr_fetch_event_by_id, radroots_nostr_parse_pubkey, radroots_nostr_send_event,
};
use radroots_trade::listing::{
    dvm::{
        TradeListingAddress, TradeListingCancel, TradeListingEnvelope, TradeListingEnvelopeError,
        TradeListingMessageType, TradeListingValidateRequest, TradeListingValidateResult,
        TradeOrderResponse, TradeOrderRevisionResponse, trade_listing_envelope_event_build,
    },
    kinds::is_trade_listing_kind,
    order::{
        TradeAnswer, TradeDiscountDecision, TradeDiscountOffer, TradeDiscountRequest,
        TradeFulfillmentUpdate, TradeOrder, TradeOrderRevision, TradeOrderStatus, TradeQuestion,
        TradeReceipt,
    },
    validation::{TradeListingValidationError, validate_listing_event},
};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::features::trade_listing::state::{
    TradeListingState, TradeListingStateError, TradeOrderState,
};

#[derive(Debug, Error)]
pub enum TradeListingDvmError {
    #[error("event kind not supported")]
    UnsupportedKind,
    #[error("missing recipient tag")]
    MissingRecipient,
    #[error("missing required tag: {0}")]
    MissingTag(&'static str),
    #[error("tag mismatch: {0}")]
    TagMismatch(&'static str),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(#[from] TradeListingEnvelopeError),
    #[error("invalid envelope payload: {0}")]
    InvalidPayload(String),
    #[error("invalid listing address")]
    InvalidListingAddr,
    #[error("invalid order request payload")]
    InvalidOrder,
    #[error("state error: {0}")]
    State(#[from] TradeListingStateError),
    #[error("nostr error: {0}")]
    Nostr(#[from] radroots_nostr::error::RadrootsNostrError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("unauthorized sender")]
    Unauthorized,
    #[error("listing not validated")]
    ListingNotValidated,
}

#[cfg(test)]
#[derive(Default)]
struct DvmTestHooks {
    fetch_event_by_id_results:
        std::collections::VecDeque<Result<RadrootsNostrEvent, TradeListingDvmError>>,
    fetch_events_results:
        std::collections::VecDeque<Result<Vec<RadrootsNostrEvent>, TradeListingDvmError>>,
    send_event_results: std::collections::VecDeque<Result<(), TradeListingDvmError>>,
    validate_listing_results:
        std::collections::VecDeque<Result<RadrootsListingFarmRef, TradeListingValidationError>>,
    farm_validation_results:
        std::collections::VecDeque<Result<Vec<TradeListingValidationError>, TradeListingDvmError>>,
}

#[cfg(test)]
static DVM_TEST_HOOKS: std::sync::OnceLock<std::sync::Mutex<DvmTestHooks>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn dvm_test_hooks() -> &'static std::sync::Mutex<DvmTestHooks> {
    DVM_TEST_HOOKS.get_or_init(|| std::sync::Mutex::new(DvmTestHooks::default()))
}

#[cfg(test)]
fn pop_fetch_event_by_id_hook() -> Option<Result<RadrootsNostrEvent, TradeListingDvmError>> {
    dvm_test_hooks()
        .lock()
        .expect("dvm test hooks lock")
        .fetch_event_by_id_results
        .pop_front()
}

#[cfg(test)]
fn pop_fetch_events_hook() -> Option<Result<Vec<RadrootsNostrEvent>, TradeListingDvmError>> {
    dvm_test_hooks()
        .lock()
        .expect("dvm test hooks lock")
        .fetch_events_results
        .pop_front()
}

#[cfg(test)]
fn pop_send_event_hook() -> Option<Result<(), TradeListingDvmError>> {
    dvm_test_hooks()
        .lock()
        .expect("dvm test hooks lock")
        .send_event_results
        .pop_front()
}

#[cfg(test)]
fn pop_validate_listing_hook() -> Option<Result<RadrootsListingFarmRef, TradeListingValidationError>> {
    dvm_test_hooks()
        .lock()
        .expect("dvm test hooks lock")
        .validate_listing_results
        .pop_front()
}

#[cfg(test)]
fn pop_farm_validation_hook() -> Option<Result<Vec<TradeListingValidationError>, TradeListingDvmError>> {
    dvm_test_hooks()
        .lock()
        .expect("dvm test hooks lock")
        .farm_validation_results
        .pop_front()
}

async fn fetch_event_by_id_io(
    client: &RadrootsNostrClient,
    id: &str,
) -> Result<RadrootsNostrEvent, TradeListingDvmError> {
    #[cfg(test)]
    if let Some(result) = pop_fetch_event_by_id_hook() {
        return Ok(result?);
    }
    let event = radroots_nostr_fetch_event_by_id(client, id).await?;
    Ok(event)
}

async fn fetch_events_io(
    client: &RadrootsNostrClient,
    filter: RadrootsNostrFilter,
    timeout: Duration,
) -> Result<Vec<RadrootsNostrEvent>, TradeListingDvmError> {
    #[cfg(test)]
    if let Some(result) = pop_fetch_events_hook() {
        return Ok(result?);
    }
    let events = client.fetch_events(filter, timeout).await?;
    Ok(events)
}

async fn send_event_io(
    client: &RadrootsNostrClient,
    builder: RadrootsNostrEventBuilder,
) -> Result<(), TradeListingDvmError> {
    #[cfg(test)]
    if let Some(result) = pop_send_event_hook() {
        result?;
        return Ok(());
    }

    let _ = radroots_nostr_send_event(client, builder).await?;
    Ok(())
}

fn validate_listing_event_io(
    event: &RadrootsNostrEvent,
) -> Result<RadrootsListingFarmRef, TradeListingValidationError> {
    #[cfg(test)]
    if let Some(result) = pop_validate_listing_hook() {
        return Ok(result?);
    }
    let rr_event = radroots_event_from_nostr(event);
    let listing = validate_listing_event(&rr_event)?;
    let farm = listing.listing.farm;
    Ok(farm)
}

pub async fn handle_event(
    event: RadrootsNostrEvent,
    tags: Vec<RadrootsNostrTag>,
    keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    state: Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let kind = match event.kind {
        RadrootsNostrKind::Custom(v) => v,
        _ => return Err(TradeListingDvmError::UnsupportedKind),
    };
    if !is_trade_listing_kind(kind) {
        return Err(TradeListingDvmError::UnsupportedKind);
    }

    if event.pubkey == keys.public_key() {
        return Ok(());
    }

    let tag_slices: Vec<Vec<String>> = tags.iter().map(|t| t.as_slice().to_vec()).collect();
    let rhi_pubkey = keys.public_key().to_string();
    if !tag_has_value(&tag_slices, "p", &rhi_pubkey) {
        return Err(TradeListingDvmError::MissingRecipient);
    }

    let envelope: TradeListingEnvelope<serde_json::Value> = serde_json::from_str(&event.content)?;
    envelope.validate()?;
    if envelope.message_type.kind() != kind {
        return Err(TradeListingDvmError::TagMismatch("kind"));
    }

    let listing_addr = tag_value(&tag_slices, "a").ok_or(TradeListingDvmError::MissingTag("a"))?;
    if listing_addr != envelope.listing_addr {
        return Err(TradeListingDvmError::TagMismatch("a"));
    }

    let order_id = envelope.order_id.as_deref();
    if envelope.message_type.requires_order_id() {
        let tag_order_id =
            tag_value(&tag_slices, "d").ok_or(TradeListingDvmError::MissingTag("d"))?;
        if Some(tag_order_id.as_str()) != order_id {
            return Err(TradeListingDvmError::TagMismatch("d"));
        }
    }

    let listing_addr_parsed = TradeListingAddress::parse(&listing_addr)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    if listing_addr_parsed.kind != 30402 {
        return Err(TradeListingDvmError::InvalidListingAddr);
    }

    match envelope.message_type {
        TradeListingMessageType::ListingValidateRequest => {
            let payload: TradeListingValidateRequest = parse_payload(envelope.payload)?;
            handle_listing_validate_request(&event, payload, &listing_addr, &client, &state)
                .await?;
        }
        TradeListingMessageType::OrderRequest => {
            let payload: TradeOrder = parse_payload(envelope.payload)?;
            handle_order_request(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::OrderResponse => {
            let payload: TradeOrderResponse = parse_payload(envelope.payload)?;
            handle_order_response(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::OrderRevision => {
            let payload: TradeOrderRevision = parse_payload(envelope.payload)?;
            handle_order_revision(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::OrderRevisionAccept
        | TradeListingMessageType::OrderRevisionDecline => {
            let payload: TradeOrderRevisionResponse = parse_payload(envelope.payload)?;
            handle_order_revision_response(
                &event,
                envelope.message_type,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::Question => {
            let payload: TradeQuestion = parse_payload(envelope.payload)?;
            handle_question(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::Answer => {
            let payload: TradeAnswer = parse_payload(envelope.payload)?;
            handle_answer(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::DiscountRequest => {
            let payload: TradeDiscountRequest = parse_payload(envelope.payload)?;
            handle_discount_request(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::DiscountOffer => {
            let payload: TradeDiscountOffer = parse_payload(envelope.payload)?;
            handle_discount_offer(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::DiscountAccept | TradeListingMessageType::DiscountDecline => {
            let payload: TradeDiscountDecision = parse_payload(envelope.payload)?;
            handle_discount_decision(
                &event,
                envelope.message_type,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::Cancel => {
            let payload: TradeListingCancel = parse_payload(envelope.payload)?;
            handle_cancel(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::FulfillmentUpdate => {
            let payload: TradeFulfillmentUpdate = parse_payload(envelope.payload)?;
            handle_fulfillment_update(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::Receipt => {
            let payload: TradeReceipt = parse_payload(envelope.payload)?;
            handle_receipt(
                &event,
                payload,
                &listing_addr_parsed,
                order_id,
                &client,
                &state,
            )
            .await?;
        }
        TradeListingMessageType::ListingValidateResult => {}
    }

    Ok(())
}

async fn handle_listing_validate_request(
    event: &RadrootsNostrEvent,
    payload: TradeListingValidateRequest,
    listing_addr: &str,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let listing_event = if let Some(ptr) = payload.listing_event {
        match fetch_event_by_id_io(client, &ptr.id).await {
            Ok(evt) => Some(evt),
            Err(err) => {
                let error = match err {
                    TradeListingDvmError::Nostr(
                        radroots_nostr::error::RadrootsNostrError::EventNotFound(_),
                    ) => TradeListingValidationError::ListingEventNotFound {
                        listing_addr: listing_addr.to_string(),
                    },
                    _ => TradeListingValidationError::ListingEventFetchFailed {
                        listing_addr: listing_addr.to_string(),
                    },
                };
                send_validate_result(event, client, listing_addr, vec![error]).await?;
                return Ok(());
            }
        }
    } else {
        match fetch_listing_by_addr(client, listing_addr).await {
            Ok(event) => event,
            Err(_) => {
                let error = TradeListingValidationError::ListingEventFetchFailed {
                    listing_addr: listing_addr.to_string(),
                };
                send_validate_result(event, client, listing_addr, vec![error]).await?;
                return Ok(());
            }
        }
    };

    let errors = if let Some(event) = listing_event {
        match validate_listing_event_io(&event) {
            Ok(farm) => {
                let errors = validate_farm_dependencies(client, &farm).await?;
                if errors.is_empty() {
                    let mut state = state.lock().await;
                    state.mark_listing_validated(listing_addr);
                }
                errors
            }
            Err(err) => vec![err],
        }
    } else {
        vec![TradeListingValidationError::ListingEventNotFound {
            listing_addr: listing_addr.to_string(),
        }]
    };

    send_validate_result(event, client, listing_addr, errors).await
}

async fn send_validate_result(
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
    listing_addr: &str,
    errors: Vec<TradeListingValidationError>,
) -> Result<(), TradeListingDvmError> {
    let payload = TradeListingValidateResult {
        valid: errors.is_empty(),
        errors,
    };
    send_envelope(
        client,
        event.pubkey.to_string(),
        TradeListingMessageType::ListingValidateResult,
        listing_addr,
        None,
        &payload,
    )
    .await
}

async fn handle_order_request(
    event: &RadrootsNostrEvent,
    payload: TradeOrder,
    listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    if payload.order_id != order_id || payload.listing_addr != listing_addr.as_str() {
        return Err(TradeListingDvmError::InvalidOrder);
    }

    let mut state = state.lock().await;
    if !state.is_listing_validated(&payload.listing_addr) {
        return Err(TradeListingDvmError::ListingNotValidated);
    }
    if state.order_exists(order_id) {
        return Ok(());
    }

    if payload.buyer_pubkey != event.pubkey.to_string()
        || payload.seller_pubkey != listing_addr.seller_pubkey
    {
        return Err(TradeListingDvmError::Unauthorized);
    }

    let mut seen = std::collections::HashSet::new();
    seen.insert(event.id.to_string());

    state.insert_order(TradeOrderState {
        order_id: order_id.to_string(),
        listing_addr: payload.listing_addr.clone(),
        buyer_pubkey: payload.buyer_pubkey.clone(),
        seller_pubkey: payload.seller_pubkey.clone(),
        status: TradeOrderStatus::Requested,
        seen_event_ids: seen,
    });

    drop(state);

    send_envelope(
        client,
        payload.seller_pubkey.clone(),
        TradeListingMessageType::OrderRequest,
        &payload.listing_addr,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_order_response(
    event: &RadrootsNostrEvent,
    payload: TradeOrderResponse,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.seller_pubkey != event.pubkey.to_string() {
        return Err(TradeListingDvmError::Unauthorized);
    }

    let next_status = if payload.accepted {
        TradeOrderStatus::Accepted
    } else {
        TradeOrderStatus::Declined
    };
    ensure_transition(order.status.clone(), next_status.clone())?;
    order.status = next_status;
    order.seen_event_ids.insert(event_id);

    let buyer = order.buyer_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        buyer,
        TradeListingMessageType::OrderResponse,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_order_revision(
    event: &RadrootsNostrEvent,
    payload: TradeOrderRevision,
    listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    if payload.order_id != order_id {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.seller_pubkey != event.pubkey.to_string()
        || listing_addr.seller_pubkey != order.seller_pubkey
    {
        return Err(TradeListingDvmError::Unauthorized);
    }
    ensure_transition(order.status.clone(), TradeOrderStatus::Revised)?;
    order.status = TradeOrderStatus::Revised;
    order.seen_event_ids.insert(event_id);
    let buyer = order.buyer_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        buyer,
        TradeListingMessageType::OrderRevision,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_order_revision_response(
    event: &RadrootsNostrEvent,
    message_type: TradeListingMessageType,
    payload: TradeOrderRevisionResponse,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.buyer_pubkey != event.pubkey.to_string() {
        return Err(TradeListingDvmError::Unauthorized);
    }
    if message_type == TradeListingMessageType::OrderRevisionAccept && !payload.accepted {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    if message_type == TradeListingMessageType::OrderRevisionDecline && payload.accepted {
        return Err(TradeListingDvmError::InvalidOrder);
    }

    let next_status = if matches!(message_type, TradeListingMessageType::OrderRevisionAccept) {
        TradeOrderStatus::Accepted
    } else {
        TradeOrderStatus::Declined
    };
    ensure_transition(order.status.clone(), next_status.clone())?;
    order.status = next_status;
    order.seen_event_ids.insert(event_id);
    let seller = order.seller_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        seller,
        message_type,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_question(
    event: &RadrootsNostrEvent,
    payload: TradeQuestion,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    if let Some(ref payload_order_id) = payload.order_id {
        if payload_order_id != order_id {
            return Err(TradeListingDvmError::InvalidOrder);
        }
    }
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.buyer_pubkey != event.pubkey.to_string() {
        return Err(TradeListingDvmError::Unauthorized);
    }
    ensure_transition(order.status.clone(), TradeOrderStatus::Questioned)?;
    order.status = TradeOrderStatus::Questioned;
    order.seen_event_ids.insert(event_id);
    let seller = order.seller_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        seller,
        TradeListingMessageType::Question,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_answer(
    event: &RadrootsNostrEvent,
    payload: TradeAnswer,
    listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    if let Some(ref payload_order_id) = payload.order_id {
        if payload_order_id != order_id {
            return Err(TradeListingDvmError::InvalidOrder);
        }
    }
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.seller_pubkey != event.pubkey.to_string()
        || listing_addr.seller_pubkey != order.seller_pubkey
    {
        return Err(TradeListingDvmError::Unauthorized);
    }
    ensure_transition(order.status.clone(), TradeOrderStatus::Requested)?;
    order.status = TradeOrderStatus::Requested;
    order.seen_event_ids.insert(event_id);
    let buyer = order.buyer_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        buyer,
        TradeListingMessageType::Answer,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_discount_request(
    event: &RadrootsNostrEvent,
    payload: TradeDiscountRequest,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    if payload.order_id != order_id {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.buyer_pubkey != event.pubkey.to_string() {
        return Err(TradeListingDvmError::Unauthorized);
    }
    order.seen_event_ids.insert(event_id);
    let seller = order.seller_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        seller,
        TradeListingMessageType::DiscountRequest,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_discount_offer(
    event: &RadrootsNostrEvent,
    payload: TradeDiscountOffer,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    if payload.order_id != order_id {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.seller_pubkey != event.pubkey.to_string() {
        return Err(TradeListingDvmError::Unauthorized);
    }
    ensure_transition(order.status.clone(), TradeOrderStatus::Revised)?;
    order.status = TradeOrderStatus::Revised;
    order.seen_event_ids.insert(event_id);
    let buyer = order.buyer_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        buyer,
        TradeListingMessageType::DiscountOffer,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_discount_decision(
    event: &RadrootsNostrEvent,
    message_type: TradeListingMessageType,
    payload: TradeDiscountDecision,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.buyer_pubkey != event.pubkey.to_string() {
        return Err(TradeListingDvmError::Unauthorized);
    }
    let payload_is_accept = matches!(payload, TradeDiscountDecision::Accept { .. });
    let payload_is_decline = matches!(payload, TradeDiscountDecision::Decline { .. });
    if message_type == TradeListingMessageType::DiscountAccept && !payload_is_accept {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    if message_type == TradeListingMessageType::DiscountDecline && !payload_is_decline {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    let next_status = match message_type {
        TradeListingMessageType::DiscountAccept => TradeOrderStatus::Accepted,
        TradeListingMessageType::DiscountDecline => TradeOrderStatus::Requested,
        _ => order.status.clone(),
    };
    ensure_transition(order.status.clone(), next_status.clone())?;
    order.status = next_status;
    order.seen_event_ids.insert(event_id);
    let seller = order.seller_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        seller,
        message_type,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_cancel(
    event: &RadrootsNostrEvent,
    payload: TradeListingCancel,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    let sender = event.pubkey.to_string();
    if sender != order.buyer_pubkey && sender != order.seller_pubkey {
        return Err(TradeListingDvmError::Unauthorized);
    }
    ensure_transition(order.status.clone(), TradeOrderStatus::Cancelled)?;
    order.status = TradeOrderStatus::Cancelled;
    order.seen_event_ids.insert(event_id);
    let recipient = if sender == order.buyer_pubkey {
        order.seller_pubkey.clone()
    } else {
        order.buyer_pubkey.clone()
    };
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        recipient,
        TradeListingMessageType::Cancel,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_fulfillment_update(
    event: &RadrootsNostrEvent,
    payload: TradeFulfillmentUpdate,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.seller_pubkey != event.pubkey.to_string() {
        return Err(TradeListingDvmError::Unauthorized);
    }
    ensure_transition(order.status.clone(), TradeOrderStatus::Fulfilled)?;
    order.status = TradeOrderStatus::Fulfilled;
    order.seen_event_ids.insert(event_id);
    let buyer = order.buyer_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        buyer,
        TradeListingMessageType::FulfillmentUpdate,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn handle_receipt(
    event: &RadrootsNostrEvent,
    payload: TradeReceipt,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    let mut state = state.lock().await;
    let event_id = event.id.to_string();
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    if order.buyer_pubkey != event.pubkey.to_string() {
        return Err(TradeListingDvmError::Unauthorized);
    }
    ensure_transition(order.status.clone(), TradeOrderStatus::Completed)?;
    order.status = TradeOrderStatus::Completed;
    order.seen_event_ids.insert(event_id);
    let seller = order.seller_pubkey.clone();
    let listing_addr_str = order.listing_addr.clone();
    drop(state);

    send_envelope(
        client,
        seller,
        TradeListingMessageType::Receipt,
        &listing_addr_str,
        Some(order_id),
        &payload,
    )
    .await
}

async fn send_envelope<T: serde::Serialize + Clone>(
    client: &RadrootsNostrClient,
    recipient_pubkey: String,
    message_type: TradeListingMessageType,
    listing_addr: &str,
    order_id: Option<&str>,
    payload: &T,
) -> Result<(), TradeListingDvmError> {
    let envelope_event = trade_listing_envelope_event_build(
        recipient_pubkey,
        message_type,
        listing_addr,
        order_id.map(|value| value.to_string()),
        payload,
    )?;
    let builder = radroots_nostr_build_event(
        envelope_event.kind as u32,
        envelope_event.content,
        envelope_event.tags,
    )?;
    send_event_io(client, builder).await?;
    Ok(())
}

async fn fetch_listing_by_addr(
    client: &RadrootsNostrClient,
    listing_addr: &str,
) -> Result<Option<RadrootsNostrEvent>, TradeListingDvmError> {
    let addr = TradeListingAddress::parse(listing_addr)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let author = radroots_nostr_parse_pubkey(&addr.seller_pubkey)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let filter = RadrootsNostrFilter::new()
        .kind(RadrootsNostrKind::Custom(addr.kind))
        .author(author)
        .identifier(addr.listing_id);
    let events = fetch_events_io(client, filter, Duration::from_secs(10)).await?;
    let mut latest: Option<RadrootsNostrEvent> = None;
    for ev in events {
        if ev.kind != RadrootsNostrKind::Custom(addr.kind) {
            continue;
        }
        match &latest {
            Some(cur) if ev.created_at <= cur.created_at => {}
            _ => latest = Some(ev),
        }
    }
    Ok(latest)
}

async fn fetch_latest_event_by_kind(
    client: &RadrootsNostrClient,
    filter: RadrootsNostrFilter,
    kind: RadrootsNostrKind,
) -> Result<Option<RadrootsNostrEvent>, TradeListingDvmError> {
    let events = fetch_events_io(client, filter, Duration::from_secs(10)).await?;
    let mut latest: Option<RadrootsNostrEvent> = None;
    for ev in events {
        if ev.kind != kind {
            continue;
        }
        match &latest {
            Some(cur) if ev.created_at <= cur.created_at => {}
            _ => latest = Some(ev),
        }
    }
    Ok(latest)
}

async fn validate_farm_dependencies(
    client: &RadrootsNostrClient,
    farm: &RadrootsListingFarmRef,
) -> Result<Vec<TradeListingValidationError>, TradeListingDvmError> {
    #[cfg(test)]
    if let Some(result) = pop_farm_validation_hook() {
        return result;
    }

    let mut errors = Vec::new();
    let farm_pubkey = farm.pubkey.trim();
    let farm_d_tag = farm.d_tag.trim();
    let author = match radroots_nostr_parse_pubkey(farm_pubkey) {
        Ok(author) => author,
        Err(_) => {
            errors.push(TradeListingValidationError::MissingFarmProfile);
            errors.push(TradeListingValidationError::MissingFarmRecord);
            return Ok(errors);
        }
    };

    let profile_filter = RadrootsNostrFilter::new()
        .kind(RadrootsNostrKind::Metadata)
        .author(author.clone());
    let profile_event =
        match fetch_latest_event_by_kind(client, profile_filter, RadrootsNostrKind::Metadata).await
        {
            Ok(event) => event,
            Err(_) => None,
        };
    let has_profile = profile_event
        .map(|event| {
            let rr_event = radroots_event_from_nostr(&event);
            tag_has_value(&rr_event.tags, "t", "radroots:type:farm")
        })
        .unwrap_or(false);
    if !has_profile {
        errors.push(TradeListingValidationError::MissingFarmProfile);
    }

    if !farm_d_tag.is_empty() {
        let record_filter = RadrootsNostrFilter::new()
            .kind(RadrootsNostrKind::Custom(KIND_FARM as u16))
            .author(author)
            .identifier(farm_d_tag.to_string());
        let record_event = match fetch_latest_event_by_kind(
            client,
            record_filter,
            RadrootsNostrKind::Custom(KIND_FARM as u16),
        )
        .await
        {
            Ok(event) => event,
            Err(_) => None,
        };
        if record_event.is_none() {
            errors.push(TradeListingValidationError::MissingFarmRecord);
        }
    } else {
        errors.push(TradeListingValidationError::MissingFarmRecord);
    }

    Ok(errors)
}

fn parse_payload<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, TradeListingDvmError> {
    serde_json::from_value(value).map_err(|e| TradeListingDvmError::InvalidPayload(e.to_string()))
}

fn tag_value(tags: &[Vec<String>], key: &str) -> Option<String> {
    tags.iter().find_map(|t| {
        if t.get(0).map(|k| k.as_str()) == Some(key) {
            t.get(1).cloned()
        } else {
            None
        }
    })
}

fn tag_has_value(tags: &[Vec<String>], key: &str, value: &str) -> bool {
    tags.iter().any(|t| {
        t.get(0).map(|k| k.as_str()) == Some(key) && t.get(1).map(|v| v.as_str()) == Some(value)
    })
}

fn ensure_transition(
    from: TradeOrderStatus,
    to: TradeOrderStatus,
) -> Result<(), TradeListingStateError> {
    if from == to {
        return Ok(());
    }
    let allowed = match from {
        TradeOrderStatus::Draft => matches!(to, TradeOrderStatus::Requested),
        TradeOrderStatus::Validated => matches!(to, TradeOrderStatus::Requested),
        TradeOrderStatus::Requested => matches!(
            to,
            TradeOrderStatus::Accepted
                | TradeOrderStatus::Declined
                | TradeOrderStatus::Questioned
                | TradeOrderStatus::Revised
                | TradeOrderStatus::Cancelled
                | TradeOrderStatus::Requested
        ),
        TradeOrderStatus::Questioned => matches!(
            to,
            TradeOrderStatus::Requested | TradeOrderStatus::Revised | TradeOrderStatus::Cancelled
        ),
        TradeOrderStatus::Revised => matches!(
            to,
            TradeOrderStatus::Accepted
                | TradeOrderStatus::Declined
                | TradeOrderStatus::Cancelled
                | TradeOrderStatus::Requested
        ),
        TradeOrderStatus::Accepted => {
            matches!(
                to,
                TradeOrderStatus::Fulfilled | TradeOrderStatus::Cancelled
            )
        }
        TradeOrderStatus::Declined => false,
        TradeOrderStatus::Cancelled => false,
        TradeOrderStatus::Fulfilled => {
            matches!(
                to,
                TradeOrderStatus::Completed
                    | TradeOrderStatus::Fulfilled
                    | TradeOrderStatus::Cancelled
            )
        }
        TradeOrderStatus::Completed => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(TradeListingStateError::InvalidTransition { from, to })
    }
}

pub async fn handle_error(
    error: TradeListingDvmError,
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
) -> Result<(), TradeListingDvmError> {
    let builder =
        radroots_nostr_build_event_job_feedback(event, "error", Some(error.to_string()), None)?;
    send_event_io(client, builder).await
}

#[cfg(test)]
mod tests {
    use super::{
        DvmTestHooks, TradeListingDvmError, dvm_test_hooks, ensure_transition, fetch_events_io,
        fetch_event_by_id_io, fetch_latest_event_by_kind, fetch_listing_by_addr, handle_answer,
        handle_cancel, handle_discount_decision, handle_discount_offer, handle_discount_request,
        handle_error, handle_event,
        handle_fulfillment_update, handle_listing_validate_request, handle_order_request,
        handle_order_response, handle_order_revision, handle_order_revision_response,
        handle_question, handle_receipt, parse_payload, send_envelope, send_event_io, tag_has_value,
        tag_value, validate_farm_dependencies, validate_listing_event_io,
    };
    use crate::features::trade_listing::state::{TradeListingState, TradeOrderState};
    use radroots_core::{RadrootsCoreCurrency, RadrootsCoreDiscountValue, RadrootsCoreMoney};
    use radroots_events::RadrootsNostrEventPtr;
    use radroots_events::listing::RadrootsListingFarmRef;
    use radroots_nostr::error::RadrootsNostrError;
    use radroots_nostr::prelude::{
        RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrFilter,
        RadrootsNostrKind, RadrootsNostrKeys, RadrootsNostrTag, RadrootsNostrTagKind,
    };
    use radroots_trade::listing::dvm::{
        TradeListingAddress, TradeListingCancel, TradeListingEnvelope, TradeListingMessageType,
        TradeListingValidateRequest, TradeOrderResponse, TradeOrderRevisionResponse,
    };
    use radroots_trade::listing::kinds::{
        KIND_TRADE_LISTING_ANSWER_RES, KIND_TRADE_LISTING_CANCEL_REQ,
        KIND_TRADE_LISTING_DISCOUNT_ACCEPT_REQ, KIND_TRADE_LISTING_DISCOUNT_DECLINE_REQ,
        KIND_TRADE_LISTING_DISCOUNT_OFFER_RES, KIND_TRADE_LISTING_DISCOUNT_REQ,
        KIND_TRADE_LISTING_FULFILLMENT_UPDATE_REQ, KIND_TRADE_LISTING_ORDER_REQ,
        KIND_TRADE_LISTING_ORDER_RES, KIND_TRADE_LISTING_ORDER_REVISION_REQ,
        KIND_TRADE_LISTING_ORDER_REVISION_RES, KIND_TRADE_LISTING_QUESTION_REQ,
        KIND_TRADE_LISTING_RECEIPT_REQ, KIND_TRADE_LISTING_VALIDATE_REQ,
        KIND_TRADE_LISTING_VALIDATE_RES,
    };
    use radroots_trade::listing::order::{
        TradeAnswer, TradeDiscountDecision, TradeDiscountOffer, TradeDiscountRequest,
        TradeFulfillmentStatus, TradeFulfillmentUpdate, TradeOrder, TradeOrderStatus,
        TradeOrderRevision, TradeQuestion, TradeReceipt,
    };
    use radroots_trade::listing::validation::TradeListingValidationError;
    use serde_json::json;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex, MutexGuard};
    use tokio::sync::Mutex as AsyncMutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        *dvm_test_hooks()
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = DvmTestHooks::default();
        guard
    }

    fn push_send_ok() {
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .send_event_results
            .push_back(Ok(()));
    }

    fn push_fetch_events_ok(events: Vec<RadrootsNostrEvent>) {
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_events_results
            .push_back(Ok(events));
    }

    fn push_fetch_event_by_id_error_not_found() {
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Err(TradeListingDvmError::Nostr(
                RadrootsNostrError::EventNotFound("missing".to_string()),
            )));
    }

    fn push_validate_listing_ok(farm: RadrootsListingFarmRef) {
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .validate_listing_results
            .push_back(Ok(farm));
    }

    fn push_farm_validation_result(result: Result<Vec<TradeListingValidationError>, TradeListingDvmError>) {
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .farm_validation_results
            .push_back(result);
    }

    fn make_keys() -> (RadrootsNostrKeys, RadrootsNostrKeys, RadrootsNostrKeys) {
        (
            RadrootsNostrKeys::generate(),
            RadrootsNostrKeys::generate(),
            RadrootsNostrKeys::generate(),
        )
    }

    fn listing_addr_for_seller(seller: &RadrootsNostrKeys) -> String {
        format!("30402:{}:AAAAAAAAAAAAAAAAAAAAAA", seller.public_key().to_hex())
    }

    fn make_client(keys: &RadrootsNostrKeys) -> RadrootsNostrClient {
        RadrootsNostrClient::new(keys.clone())
    }

    fn make_order(
        order_id: &str,
        listing_addr: &str,
        buyer: &str,
        seller: &str,
        status: TradeOrderStatus,
    ) -> TradeOrder {
        TradeOrder {
            order_id: order_id.to_string(),
            listing_addr: listing_addr.to_string(),
            buyer_pubkey: buyer.to_string(),
            seller_pubkey: seller.to_string(),
            items: Vec::new(),
            discounts: None,
            notes: None,
            status,
        }
    }

    fn make_order_state(
        order_id: &str,
        listing_addr: &str,
        buyer: &str,
        seller: &str,
        status: TradeOrderStatus,
    ) -> TradeOrderState {
        TradeOrderState {
            order_id: order_id.to_string(),
            listing_addr: listing_addr.to_string(),
            buyer_pubkey: buyer.to_string(),
            seller_pubkey: seller.to_string(),
            status,
            seen_event_ids: HashSet::new(),
        }
    }

    async fn state_with_order(
        listing_addr: &str,
        order_id: &str,
        buyer: &str,
        seller: &str,
        status: TradeOrderStatus,
    ) -> Arc<AsyncMutex<TradeListingState>> {
        let state = Arc::new(AsyncMutex::new(TradeListingState::default()));
        let mut locked = state.lock().await;
        locked.mark_listing_validated(listing_addr);
        locked.insert_order(make_order_state(order_id, listing_addr, buyer, seller, status));
        drop(locked);
        state
    }

    async fn set_order_status(
        state: &Arc<AsyncMutex<TradeListingState>>,
        order_id: &str,
        status: TradeOrderStatus,
    ) {
        let mut locked = state.lock().await;
        let order = locked.get_order_mut(order_id).expect("order");
        order.status = status;
        order.seen_event_ids.clear();
    }

    async fn mark_event_seen(
        state: &Arc<AsyncMutex<TradeListingState>>,
        order_id: &str,
        event_id: String,
    ) {
        let mut locked = state.lock().await;
        let order = locked.get_order_mut(order_id).expect("order");
        order.seen_event_ids.insert(event_id);
    }

    fn make_custom_tags(recipient: &str, listing_addr: &str, order_id: Option<&str>) -> Vec<RadrootsNostrTag> {
        let mut tags = vec![
            RadrootsNostrTag::custom(RadrootsNostrTagKind::custom("p"), vec![recipient.to_string()]),
            RadrootsNostrTag::custom(RadrootsNostrTagKind::custom("a"), vec![listing_addr.to_string()]),
        ];
        if let Some(order_id) = order_id {
            tags.push(RadrootsNostrTag::custom(
                RadrootsNostrTagKind::custom("d"),
                vec![order_id.to_string()],
            ));
        }
        tags
    }

    fn make_event(
        sender: &RadrootsNostrKeys,
        kind: RadrootsNostrKind,
        content: String,
        tags: Vec<RadrootsNostrTag>,
    ) -> RadrootsNostrEvent {
        RadrootsNostrEventBuilder::new(kind, content)
            .tags(tags)
            .sign_with_keys(sender)
            .expect("event")
    }

    fn make_envelope_content(
        message_type: TradeListingMessageType,
        listing_addr: &str,
        order_id: Option<&str>,
        payload: serde_json::Value,
    ) -> String {
        serde_json::to_string(&TradeListingEnvelope::new(
            message_type,
            listing_addr.to_string(),
            order_id.map(|v| v.to_string()),
            payload,
        ))
        .expect("envelope")
    }

    fn sample_discount_value() -> RadrootsCoreDiscountValue {
        RadrootsCoreDiscountValue::MoneyPerBin(RadrootsCoreMoney::from_minor_units_u32(
            100,
            RadrootsCoreCurrency::USD,
        ))
    }

    #[test]
    fn transition_matrix_and_tag_helpers_are_covered() {
        let _guard = test_guard();

        assert!(ensure_transition(TradeOrderStatus::Requested, TradeOrderStatus::Revised).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Declined, TradeOrderStatus::Accepted).is_err());
        assert!(ensure_transition(TradeOrderStatus::Fulfilled, TradeOrderStatus::Completed).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Completed, TradeOrderStatus::Requested).is_err());
        assert!(ensure_transition(TradeOrderStatus::Draft, TradeOrderStatus::Draft).is_ok());

        let tags = vec![
            vec!["p".to_string(), "pk".to_string()],
            vec!["a".to_string(), "addr".to_string()],
        ];
        assert_eq!(tag_value(&tags, "a"), Some("addr".to_string()));
        assert_eq!(tag_value(&tags, "x"), None);
        assert!(tag_has_value(&tags, "p", "pk"));
        assert!(!tag_has_value(&tags, "p", "miss"));

        let parsed: Result<TradeOrderResponse, _> = parse_payload(json!({"accepted":true,"reason":null}));
        assert!(parsed.is_ok());
        let invalid: Result<TradeOrderResponse, _> = parse_payload(json!({"accepted":"true"}));
        assert!(invalid.is_err());
    }

    #[test]
    fn transition_matrix_covers_all_from_arms() {
        let _guard = test_guard();

        assert!(ensure_transition(TradeOrderStatus::Draft, TradeOrderStatus::Requested).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Draft, TradeOrderStatus::Accepted).is_err());

        assert!(ensure_transition(TradeOrderStatus::Validated, TradeOrderStatus::Requested).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Validated, TradeOrderStatus::Accepted).is_err());

        assert!(ensure_transition(TradeOrderStatus::Requested, TradeOrderStatus::Accepted).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Requested, TradeOrderStatus::Fulfilled).is_err());

        assert!(ensure_transition(TradeOrderStatus::Questioned, TradeOrderStatus::Requested).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Questioned, TradeOrderStatus::Accepted).is_err());

        assert!(ensure_transition(TradeOrderStatus::Revised, TradeOrderStatus::Declined).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Revised, TradeOrderStatus::Fulfilled).is_err());

        assert!(ensure_transition(TradeOrderStatus::Accepted, TradeOrderStatus::Fulfilled).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Accepted, TradeOrderStatus::Requested).is_err());

        assert!(ensure_transition(TradeOrderStatus::Declined, TradeOrderStatus::Accepted).is_err());
        assert!(ensure_transition(TradeOrderStatus::Cancelled, TradeOrderStatus::Requested).is_err());

        assert!(ensure_transition(TradeOrderStatus::Fulfilled, TradeOrderStatus::Completed).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Fulfilled, TradeOrderStatus::Accepted).is_err());

        assert!(ensure_transition(TradeOrderStatus::Completed, TradeOrderStatus::Cancelled).is_err());
    }

    #[tokio::test]
    async fn io_hooks_cover_fetch_send_and_validate_wrappers() {
        let _guard = test_guard();
        let (rhi_keys, _, _) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&rhi_keys);
        let event = make_event(
            &rhi_keys,
            RadrootsNostrKind::Metadata,
            "meta".to_string(),
            vec![RadrootsNostrTag::custom(
                RadrootsNostrTagKind::custom("t"),
                vec!["radroots:type:farm".to_string()],
            )],
        );
        push_fetch_events_ok(vec![event.clone()]);
        let fetched = fetch_events_io(&client, RadrootsNostrFilter::new(), std::time::Duration::from_secs(1))
            .await
            .expect("fetch hook");
        assert_eq!(fetched.len(), 1);

        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(event.clone()));
        let by_id = super::fetch_event_by_id_io(&client, "id").await.expect("by id");
        assert_eq!(by_id.id, event.id);

        push_send_ok();
        let builder = radroots_nostr::prelude::radroots_nostr_build_event(
            KIND_TRADE_LISTING_VALIDATE_RES as u32,
            "x",
            vec![vec!["p".to_string(), rhi_keys.public_key().to_hex()]],
        )
        .expect("builder");
        assert!(send_event_io(&client, builder).await.is_ok());

        let farm = RadrootsListingFarmRef {
            pubkey: rhi_keys.public_key().to_hex(),
            d_tag: "farmtag".to_string(),
        };
        push_validate_listing_ok(farm.clone());
        let validated = validate_listing_event_io(&event).expect("validate hook");
        assert_eq!(validated.pubkey, farm.pubkey);
        assert_eq!(listing_addr.contains(':',), true);
    }

    #[tokio::test]
    async fn farm_dependency_validation_paths_are_covered() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, _) = make_keys();
        let client = make_client(&rhi_keys);

        let invalid_farm = RadrootsListingFarmRef {
            pubkey: "bad".to_string(),
            d_tag: "farmtag".to_string(),
        };
        let errors = validate_farm_dependencies(&client, &invalid_farm)
            .await
            .expect("invalid farm result");
        assert!(errors.contains(&TradeListingValidationError::MissingFarmProfile));
        assert!(errors.contains(&TradeListingValidationError::MissingFarmRecord));

        let farm = RadrootsListingFarmRef {
            pubkey: seller_keys.public_key().to_hex(),
            d_tag: "farmtag".to_string(),
        };
        push_fetch_events_ok(Vec::new());
        push_fetch_events_ok(Vec::new());
        let missing = validate_farm_dependencies(&client, &farm)
            .await
            .expect("missing deps");
        assert!(missing.contains(&TradeListingValidationError::MissingFarmProfile));
        assert!(missing.contains(&TradeListingValidationError::MissingFarmRecord));

        let profile_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Metadata,
            "profile".to_string(),
            vec![RadrootsNostrTag::custom(
                RadrootsNostrTagKind::custom("t"),
                vec!["radroots:type:farm".to_string()],
            )],
        );
        let record_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(radroots_events::kinds::KIND_FARM as u16),
            "record".to_string(),
            Vec::new(),
        );
        push_fetch_events_ok(vec![profile_event]);
        push_fetch_events_ok(vec![record_event]);
        let ok = validate_farm_dependencies(&client, &farm).await.expect("ok deps");
        assert!(ok.is_empty());
    }

    #[tokio::test]
    async fn handle_listing_validate_request_paths_are_covered() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, _) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let state = Arc::new(AsyncMutex::new(TradeListingState::default()));
        let event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_VALIDATE_REQ),
            "content".to_string(),
            Vec::new(),
        );

        push_fetch_event_by_id_error_not_found();
        push_send_ok();
        let payload = TradeListingValidateRequest {
            listing_event: Some(RadrootsNostrEventPtr {
                id: "missing".to_string(),
                relays: None,
            }),
        };
        assert!(handle_listing_validate_request(&event, payload, &listing_addr, &client, &state)
            .await
            .is_ok());

        push_fetch_events_ok(Vec::new());
        push_send_ok();
        let payload = TradeListingValidateRequest { listing_event: None };
        assert!(handle_listing_validate_request(&event, payload, &listing_addr, &client, &state)
            .await
            .is_ok());

        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(event.clone()));
        push_validate_listing_ok(RadrootsListingFarmRef {
            pubkey: seller_keys.public_key().to_hex(),
            d_tag: "farmtag".to_string(),
        });
        push_farm_validation_result(Ok(Vec::new()));
        push_send_ok();
        let payload = TradeListingValidateRequest {
            listing_event: Some(RadrootsNostrEventPtr {
                id: event.id.to_hex(),
                relays: None,
            }),
        };
        assert!(handle_listing_validate_request(&event, payload, &listing_addr, &client, &state)
            .await
            .is_ok());
        assert!(state.lock().await.is_listing_validated(&listing_addr));
    }

    #[tokio::test]
    async fn handler_paths_cover_state_transitions() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, buyer_keys) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let listing_addr_parsed = TradeListingAddress::parse(&listing_addr).expect("addr");
        let order_id = "order-1";
        let seller_pub = seller_keys.public_key().to_hex();
        let buyer_pub = buyer_keys.public_key().to_hex();
        let state = Arc::new(AsyncMutex::new(TradeListingState::default()));
        state.lock().await.mark_listing_validated(&listing_addr);

        let order_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            "order".to_string(),
            Vec::new(),
        );
        push_send_ok();
        let order_payload = make_order(
            order_id,
            &listing_addr,
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        assert!(handle_order_request(
            &order_event,
            order_payload,
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        let response_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_RES),
            "resp".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_order_response(
            &response_event,
            TradeOrderResponse {
                accepted: true,
                reason: None,
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        state.lock().await.get_order_mut(order_id).expect("order").status = TradeOrderStatus::Requested;
        let revision_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REVISION_REQ),
            "rev".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_order_revision(
            &revision_event,
            TradeOrderRevision {
                revision_id: "r1".to_string(),
                order_id: order_id.to_string(),
                changes: Vec::new(),
                reason: None,
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        let revision_response_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REVISION_RES),
            "revresp".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_order_revision_response(
            &revision_response_event,
            TradeListingMessageType::OrderRevisionAccept,
            TradeOrderRevisionResponse {
                accepted: true,
                reason: None,
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        state.lock().await.get_order_mut(order_id).expect("order").status = TradeOrderStatus::Requested;
        let question_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_QUESTION_REQ),
            "q".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_question(
            &question_event,
            TradeQuestion {
                question_id: "q1".to_string(),
                order_id: Some(order_id.to_string()),
                listing_addr: Some(listing_addr.clone()),
                question_text: "what".to_string(),
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        let answer_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ANSWER_RES),
            "a".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_answer(
            &answer_event,
            TradeAnswer {
                question_id: "q1".to_string(),
                order_id: Some(order_id.to_string()),
                listing_addr: Some(listing_addr.clone()),
                answer_text: "ans".to_string(),
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        let discount_request_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_REQ),
            "dr".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_discount_request(
            &discount_request_event,
            TradeDiscountRequest {
                discount_id: "d1".to_string(),
                order_id: order_id.to_string(),
                value: sample_discount_value(),
                conditions: None,
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        let discount_offer_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_OFFER_RES),
            "do".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_discount_offer(
            &discount_offer_event,
            TradeDiscountOffer {
                discount_id: "d1".to_string(),
                order_id: order_id.to_string(),
                value: sample_discount_value(),
                conditions: None,
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        let discount_accept_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_ACCEPT_REQ),
            "da".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_discount_decision(
            &discount_accept_event,
            TradeListingMessageType::DiscountAccept,
            TradeDiscountDecision::Accept {
                value: sample_discount_value(),
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        state.lock().await.get_order_mut(order_id).expect("order").status = TradeOrderStatus::Requested;
        let cancel_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_CANCEL_REQ),
            "cancel".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_cancel(
            &cancel_event,
            TradeListingCancel { reason: None },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        state.lock().await.get_order_mut(order_id).expect("order").status = TradeOrderStatus::Accepted;
        let fulfill_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_FULFILLMENT_UPDATE_REQ),
            "fulfill".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_fulfillment_update(
            &fulfill_event,
            TradeFulfillmentUpdate {
                status: TradeFulfillmentStatus::Shipped,
                tracking: None,
                eta: None,
                notes: None,
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());

        let receipt_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_RECEIPT_REQ),
            "receipt".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_receipt(
            &receipt_event,
            TradeReceipt {
                acknowledged: true,
                at: 1,
                note: None,
            },
            &listing_addr_parsed,
            Some(order_id),
            &client,
            &state
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn handle_event_covers_guard_and_dispatch_paths() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, buyer_keys) = make_keys();
        let client = make_client(&rhi_keys);
        let rhi_pub = rhi_keys.public_key().to_hex();
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let order_id = "order-1";
        let tags = make_custom_tags(&rhi_pub, &listing_addr, Some(order_id));
        let state = state_with_order(
            &listing_addr,
            order_id,
            &buyer_keys.public_key().to_hex(),
            &seller_keys.public_key().to_hex(),
            TradeOrderStatus::Requested,
        )
        .await;

        let unsupported = make_event(
            &buyer_keys,
            RadrootsNostrKind::TextNote,
            "x".to_string(),
            tags.clone(),
        );
        assert!(matches!(
            handle_event(
                unsupported,
                tags.clone(),
                rhi_keys.clone(),
                client.clone(),
                state.clone()
            )
            .await,
            Err(TradeListingDvmError::UnsupportedKind)
        ));

        let missing_recipient = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            make_envelope_content(
                TradeListingMessageType::OrderRequest,
                &listing_addr,
                Some(order_id),
                json!({}),
            ),
            Vec::new(),
        );
        assert!(matches!(
            handle_event(
                missing_recipient,
                Vec::new(),
                rhi_keys.clone(),
                client.clone(),
                state.clone()
            )
            .await,
            Err(TradeListingDvmError::MissingRecipient)
        ));

        let unsupported_custom = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(1),
            make_envelope_content(
                TradeListingMessageType::OrderRequest,
                &listing_addr,
                Some(order_id),
                json!({}),
            ),
            tags.clone(),
        );
        assert!(matches!(
            handle_event(
                unsupported_custom,
                tags.clone(),
                rhi_keys.clone(),
                client.clone(),
                state.clone()
            )
            .await,
            Err(TradeListingDvmError::UnsupportedKind)
        ));

        let self_event = make_event(
            &rhi_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            make_envelope_content(
                TradeListingMessageType::OrderRequest,
                &listing_addr,
                Some(order_id),
                json!({}),
            ),
            tags.clone(),
        );
        assert!(handle_event(
            self_event,
            tags.clone(),
            rhi_keys.clone(),
            client.clone(),
            state.clone(),
        )
        .await
        .is_ok());

        let kind_mismatch = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            make_envelope_content(
                TradeListingMessageType::Question,
                &listing_addr,
                Some(order_id),
                json!({}),
            ),
            tags.clone(),
        );
        assert!(matches!(
            handle_event(
                kind_mismatch,
                tags.clone(),
                rhi_keys.clone(),
                client.clone(),
                state.clone(),
            )
            .await,
            Err(TradeListingDvmError::TagMismatch("kind"))
        ));

        let a_mismatch_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            make_envelope_content(
                TradeListingMessageType::OrderRequest,
                "30402:deadbeef:AAAAAAAAAAAAAAAAAAAAAA",
                Some(order_id),
                json!({}),
            ),
            tags.clone(),
        );
        assert!(matches!(
            handle_event(
                a_mismatch_event,
                tags.clone(),
                rhi_keys.clone(),
                client.clone(),
                state.clone(),
            )
            .await,
            Err(TradeListingDvmError::TagMismatch("a"))
        ));

        let d_mismatch_tags = make_custom_tags(&rhi_pub, &listing_addr, Some("other-order"));
        let d_mismatch_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            make_envelope_content(
                TradeListingMessageType::OrderRequest,
                &listing_addr,
                Some(order_id),
                json!({}),
            ),
            d_mismatch_tags.clone(),
        );
        assert!(matches!(
            handle_event(
                d_mismatch_event,
                d_mismatch_tags,
                rhi_keys.clone(),
                client.clone(),
                state.clone(),
            )
            .await,
            Err(TradeListingDvmError::TagMismatch("d"))
        ));

        let bad_addr = format!("30403:{}:AAAAAAAAAAAAAAAAAAAAAA", seller_keys.public_key().to_hex());
        let bad_addr_tags = make_custom_tags(&rhi_pub, &bad_addr, Some(order_id));
        let bad_addr_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            make_envelope_content(
                TradeListingMessageType::OrderRequest,
                &bad_addr,
                Some(order_id),
                json!({}),
            ),
            bad_addr_tags.clone(),
        );
        assert!(matches!(
            handle_event(
                bad_addr_event,
                bad_addr_tags,
                rhi_keys.clone(),
                client.clone(),
                state.clone(),
            )
            .await,
            Err(TradeListingDvmError::InvalidListingAddr)
        ));

        let cases = vec![
            (TradeListingMessageType::ListingValidateRequest, KIND_TRADE_LISTING_VALIDATE_REQ),
            (TradeListingMessageType::OrderRequest, KIND_TRADE_LISTING_ORDER_REQ),
            (TradeListingMessageType::OrderResponse, KIND_TRADE_LISTING_ORDER_RES),
            (TradeListingMessageType::OrderRevision, KIND_TRADE_LISTING_ORDER_REVISION_REQ),
            (
                TradeListingMessageType::OrderRevisionAccept,
                KIND_TRADE_LISTING_ORDER_REVISION_RES,
            ),
            (
                TradeListingMessageType::OrderRevisionDecline,
                KIND_TRADE_LISTING_ORDER_REVISION_RES,
            ),
            (TradeListingMessageType::Question, KIND_TRADE_LISTING_QUESTION_REQ),
            (TradeListingMessageType::Answer, KIND_TRADE_LISTING_ANSWER_RES),
            (
                TradeListingMessageType::DiscountRequest,
                KIND_TRADE_LISTING_DISCOUNT_REQ,
            ),
            (
                TradeListingMessageType::DiscountOffer,
                KIND_TRADE_LISTING_DISCOUNT_OFFER_RES,
            ),
            (
                TradeListingMessageType::DiscountAccept,
                KIND_TRADE_LISTING_DISCOUNT_ACCEPT_REQ,
            ),
            (
                TradeListingMessageType::DiscountDecline,
                KIND_TRADE_LISTING_DISCOUNT_DECLINE_REQ,
            ),
            (TradeListingMessageType::Cancel, KIND_TRADE_LISTING_CANCEL_REQ),
            (
                TradeListingMessageType::FulfillmentUpdate,
                KIND_TRADE_LISTING_FULFILLMENT_UPDATE_REQ,
            ),
            (TradeListingMessageType::Receipt, KIND_TRADE_LISTING_RECEIPT_REQ),
            (
                TradeListingMessageType::ListingValidateResult,
                KIND_TRADE_LISTING_VALIDATE_RES,
            ),
        ];

        for (message_type, kind) in cases {
            if message_type == TradeListingMessageType::ListingValidateRequest {
                push_fetch_events_ok(Vec::new());
                push_send_ok();
            }
            if message_type == TradeListingMessageType::Cancel {
                state.lock().await.get_order_mut(order_id).expect("order").status = TradeOrderStatus::Requested;
            }
            let payload = if message_type == TradeListingMessageType::ListingValidateResult {
                json!({"valid": true, "errors": []})
            } else if message_type == TradeListingMessageType::ListingValidateRequest {
                json!({"listing_event": null})
            } else {
                json!({})
            };
            let content = make_envelope_content(
                message_type,
                &listing_addr,
                if message_type.requires_order_id() {
                    Some(order_id)
                } else {
                    None
                },
                payload,
            );
            let event = make_event(
                &buyer_keys,
                RadrootsNostrKind::Custom(kind),
                content,
                tags.clone(),
            );
            let _ = handle_event(
                event,
                tags.clone(),
                rhi_keys.clone(),
                client.clone(),
                state.clone(),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn fetch_latest_send_envelope_and_handle_error_paths() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, _) = make_keys();
        let client = make_client(&rhi_keys);
        let older = make_event(
            &seller_keys,
            RadrootsNostrKind::Metadata,
            "old".to_string(),
            Vec::new(),
        );
        let newer = make_event(
            &seller_keys,
            RadrootsNostrKind::Metadata,
            "new".to_string(),
            Vec::new(),
        );
        push_fetch_events_ok(vec![older, newer.clone()]);
        let latest = fetch_latest_event_by_kind(
            &client,
            RadrootsNostrFilter::new(),
            RadrootsNostrKind::Metadata,
        )
        .await
        .expect("latest");
        assert!(latest.is_some());

        push_send_ok();
        assert!(send_envelope(
            &client,
            seller_keys.public_key().to_hex(),
            TradeListingMessageType::ListingValidateResult,
            &listing_addr_for_seller(&seller_keys),
            None,
            &json!({"valid":true,"errors":[]}),
        )
        .await
        .is_ok());

        let event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            "x".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_error(TradeListingDvmError::UnsupportedKind, &event, &client)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn fetch_and_validation_guard_branches_are_covered() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, _) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let listing_kind = TradeListingAddress::parse(&listing_addr)
            .expect("listing address")
            .kind;

        let wrong_kind = make_event(
            &seller_keys,
            RadrootsNostrKind::Metadata,
            "metadata".to_string(),
            Vec::new(),
        );
        let listing_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(listing_kind),
            "listing".to_string(),
            Vec::new(),
        );
        push_fetch_events_ok(vec![wrong_kind.clone(), listing_event.clone(), listing_event.clone()]);
        let fetched_listing = fetch_listing_by_addr(&client, &listing_addr).await.expect("listing fetch");
        assert!(fetched_listing.is_some());

        let wrong_custom = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(9999),
            "other".to_string(),
            Vec::new(),
        );
        let metadata_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Metadata,
            "profile".to_string(),
            Vec::new(),
        );
        push_fetch_events_ok(vec![
            wrong_custom,
            metadata_event.clone(),
            metadata_event.clone(),
        ]);
        let fetched_latest = fetch_latest_event_by_kind(
            &client,
            RadrootsNostrFilter::new(),
            RadrootsNostrKind::Metadata,
        )
        .await
        .expect("latest metadata");
        assert!(fetched_latest.is_some());

        let farm = RadrootsListingFarmRef {
            pubkey: seller_keys.public_key().to_hex(),
            d_tag: "farm".to_string(),
        };
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_events_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_events_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        let errors = validate_farm_dependencies(&client, &farm)
            .await
            .expect("farm validation");
        assert!(errors.contains(&TradeListingValidationError::MissingFarmProfile));
        assert!(errors.contains(&TradeListingValidationError::MissingFarmRecord));

        let empty_farm_tag = RadrootsListingFarmRef {
            pubkey: seller_keys.public_key().to_hex(),
            d_tag: String::new(),
        };
        push_fetch_events_ok(Vec::new());
        let empty_tag_errors = validate_farm_dependencies(&client, &empty_farm_tag)
            .await
            .expect("empty farm tag");
        assert!(empty_tag_errors.contains(&TradeListingValidationError::MissingFarmRecord));
    }

    #[tokio::test]
    async fn io_wrapper_default_paths_cover_fallback_branches() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, _) = make_keys();
        let client = make_client(&rhi_keys);
        assert!(fetch_event_by_id_io(&client, "invalid-id").await.is_err());
        assert!(fetch_events_io(&client, RadrootsNostrFilter::new(), std::time::Duration::from_millis(1))
            .await
            .is_err());
        let builder = radroots_nostr::prelude::radroots_nostr_build_event(
            KIND_TRADE_LISTING_ORDER_REQ as u32,
            "x",
            vec![vec!["a".to_string(), listing_addr_for_seller(&seller_keys)]],
        )
        .expect("builder");
        assert!(send_event_io(&client, builder).await.is_err());
        let event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            "{}".to_string(),
            Vec::new(),
        );
        assert!(validate_listing_event_io(&event).is_err());
    }

    #[tokio::test]
    async fn handle_event_valid_dispatch_matrix_covers_arm_calls() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, buyer_keys) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let rhi_pub = rhi_keys.public_key().to_hex();
        let order_id = "order-1";
        let buyer_pub = buyer_keys.public_key().to_hex();
        let seller_pub = seller_keys.public_key().to_hex();
        let state = state_with_order(
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        )
        .await;

        push_fetch_events_ok(Vec::new());
        push_send_ok();
        let validate_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_VALIDATE_REQ),
            make_envelope_content(
                TradeListingMessageType::ListingValidateRequest,
                &listing_addr,
                None,
                json!({"listing_event": null}),
            ),
            make_custom_tags(&rhi_pub, &listing_addr, None),
        );
        let _ = handle_event(
            validate_event,
            make_custom_tags(&rhi_pub, &listing_addr, None),
            rhi_keys.clone(),
            client.clone(),
            state.clone(),
        )
        .await;

        let cases: Vec<(TradeListingMessageType, u16, serde_json::Value, TradeOrderStatus)> = vec![
            (
                TradeListingMessageType::OrderRequest,
                KIND_TRADE_LISTING_ORDER_REQ,
                serde_json::to_value(make_order(
                    order_id,
                    &listing_addr,
                    &buyer_pub,
                    &seller_pub,
                    TradeOrderStatus::Requested,
                ))
                .expect("order request"),
                TradeOrderStatus::Requested,
            ),
            (
                TradeListingMessageType::OrderResponse,
                KIND_TRADE_LISTING_ORDER_RES,
                serde_json::to_value(TradeOrderResponse {
                    accepted: true,
                    reason: None,
                })
                .expect("order response"),
                TradeOrderStatus::Requested,
            ),
            (
                TradeListingMessageType::OrderRevision,
                KIND_TRADE_LISTING_ORDER_REVISION_REQ,
                serde_json::to_value(TradeOrderRevision {
                    revision_id: "r2".to_string(),
                    order_id: order_id.to_string(),
                    changes: Vec::new(),
                    reason: None,
                })
                .expect("order revision"),
                TradeOrderStatus::Requested,
            ),
            (
                TradeListingMessageType::OrderRevisionAccept,
                KIND_TRADE_LISTING_ORDER_REVISION_RES,
                serde_json::to_value(TradeOrderRevisionResponse {
                    accepted: true,
                    reason: None,
                })
                .expect("order revision accept"),
                TradeOrderStatus::Revised,
            ),
            (
                TradeListingMessageType::OrderRevisionDecline,
                KIND_TRADE_LISTING_ORDER_REVISION_RES,
                serde_json::to_value(TradeOrderRevisionResponse {
                    accepted: false,
                    reason: None,
                })
                .expect("order revision decline"),
                TradeOrderStatus::Revised,
            ),
            (
                TradeListingMessageType::Question,
                KIND_TRADE_LISTING_QUESTION_REQ,
                serde_json::to_value(TradeQuestion {
                    question_id: "qx".to_string(),
                    order_id: Some(order_id.to_string()),
                    listing_addr: Some(listing_addr.clone()),
                    question_text: "question".to_string(),
                })
                .expect("question"),
                TradeOrderStatus::Requested,
            ),
            (
                TradeListingMessageType::Answer,
                KIND_TRADE_LISTING_ANSWER_RES,
                serde_json::to_value(TradeAnswer {
                    question_id: "qx".to_string(),
                    order_id: Some(order_id.to_string()),
                    listing_addr: Some(listing_addr.clone()),
                    answer_text: "answer".to_string(),
                })
                .expect("answer"),
                TradeOrderStatus::Questioned,
            ),
            (
                TradeListingMessageType::DiscountRequest,
                KIND_TRADE_LISTING_DISCOUNT_REQ,
                serde_json::to_value(TradeDiscountRequest {
                    discount_id: "d2".to_string(),
                    order_id: order_id.to_string(),
                    value: sample_discount_value(),
                    conditions: None,
                })
                .expect("discount request"),
                TradeOrderStatus::Requested,
            ),
            (
                TradeListingMessageType::DiscountOffer,
                KIND_TRADE_LISTING_DISCOUNT_OFFER_RES,
                serde_json::to_value(TradeDiscountOffer {
                    discount_id: "d2".to_string(),
                    order_id: order_id.to_string(),
                    value: sample_discount_value(),
                    conditions: None,
                })
                .expect("discount offer"),
                TradeOrderStatus::Requested,
            ),
            (
                TradeListingMessageType::DiscountAccept,
                KIND_TRADE_LISTING_DISCOUNT_ACCEPT_REQ,
                serde_json::to_value(TradeDiscountDecision::Accept {
                    value: sample_discount_value(),
                })
                .expect("discount accept"),
                TradeOrderStatus::Revised,
            ),
            (
                TradeListingMessageType::DiscountDecline,
                KIND_TRADE_LISTING_DISCOUNT_DECLINE_REQ,
                serde_json::to_value(TradeDiscountDecision::Decline { reason: None })
                    .expect("discount decline"),
                TradeOrderStatus::Revised,
            ),
            (
                TradeListingMessageType::Cancel,
                KIND_TRADE_LISTING_CANCEL_REQ,
                serde_json::to_value(TradeListingCancel { reason: None }).expect("cancel"),
                TradeOrderStatus::Requested,
            ),
            (
                TradeListingMessageType::FulfillmentUpdate,
                KIND_TRADE_LISTING_FULFILLMENT_UPDATE_REQ,
                serde_json::to_value(TradeFulfillmentUpdate {
                    status: TradeFulfillmentStatus::Shipped,
                    tracking: None,
                    eta: None,
                    notes: None,
                })
                .expect("fulfillment"),
                TradeOrderStatus::Accepted,
            ),
            (
                TradeListingMessageType::Receipt,
                KIND_TRADE_LISTING_RECEIPT_REQ,
                serde_json::to_value(TradeReceipt {
                    acknowledged: true,
                    at: 1,
                    note: None,
                })
                .expect("receipt"),
                TradeOrderStatus::Fulfilled,
            ),
            (
                TradeListingMessageType::ListingValidateResult,
                KIND_TRADE_LISTING_VALIDATE_RES,
                json!({"valid": true, "errors": []}),
                TradeOrderStatus::Requested,
            ),
        ];

        for (message_type, kind, payload, status_before) in cases {
            set_order_status(&state, order_id, status_before).await;
            if message_type != TradeListingMessageType::ListingValidateResult {
                push_send_ok();
            }
            let sender = match message_type {
                TradeListingMessageType::OrderResponse
                | TradeListingMessageType::OrderRevision
                | TradeListingMessageType::Answer
                | TradeListingMessageType::DiscountOffer
                | TradeListingMessageType::FulfillmentUpdate => &seller_keys,
                _ => &buyer_keys,
            };
            let content = make_envelope_content(message_type, &listing_addr, Some(order_id), payload);
            let tags = make_custom_tags(&rhi_pub, &listing_addr, Some(order_id));
            let event = make_event(sender, RadrootsNostrKind::Custom(kind), content, tags.clone());
            let _ = handle_event(
                event,
                tags,
                rhi_keys.clone(),
                client.clone(),
                state.clone(),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn handler_error_branches_are_covered() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, buyer_keys) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let parsed = TradeListingAddress::parse(&listing_addr).expect("listing");
        let buyer_pub = buyer_keys.public_key().to_hex();
        let seller_pub = seller_keys.public_key().to_hex();
        let state = state_with_order(
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        )
        .await;

        let bad_order = make_order("bad", &listing_addr, &buyer_pub, &seller_pub, TradeOrderStatus::Requested);
        let event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
            "x".to_string(),
            Vec::new(),
        );
        assert!(matches!(
            handle_order_request(&event, bad_order, &parsed, Some("order-1"), &client, &state).await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        let missing_state = Arc::new(AsyncMutex::new(TradeListingState::default()));
        let order = make_order("order-2", &listing_addr, &buyer_pub, &seller_pub, TradeOrderStatus::Requested);
        assert!(matches!(
            handle_order_request(&event, order, &parsed, Some("order-2"), &client, &missing_state).await,
            Err(TradeListingDvmError::ListingNotValidated)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let seller_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_RES),
            "x".to_string(),
            Vec::new(),
        );
        state
            .lock()
            .await
            .get_order_mut("order-1")
            .expect("order")
            .seen_event_ids
            .insert(seller_event.id.to_string());
        assert!(handle_order_response(
            &seller_event,
            TradeOrderResponse {
                accepted: true,
                reason: None,
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        let wrong_buyer = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REVISION_RES),
            "x".to_string(),
            Vec::new(),
        );
        assert!(matches!(
            handle_order_revision_response(
                &wrong_buyer,
                TradeListingMessageType::OrderRevisionAccept,
                TradeOrderRevisionResponse {
                    accepted: false,
                    reason: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized | TradeListingDvmError::InvalidOrder)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let wrong_sender = make_event(
            &rhi_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_CANCEL_REQ),
            "x".to_string(),
            Vec::new(),
        );
        assert!(matches!(
            handle_cancel(
                &wrong_sender,
                TradeListingCancel { reason: None },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        let validate_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_VALIDATE_REQ),
            "x".to_string(),
            Vec::new(),
        );
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        push_send_ok();
        assert!(handle_listing_validate_request(
            &validate_event,
            TradeListingValidateRequest {
                listing_event: Some(RadrootsNostrEventPtr {
                    id: "x".to_string(),
                    relays: None,
                }),
            },
            &listing_addr,
            &client,
            &state,
        )
        .await
        .is_ok());

        push_send_ok();
        assert!(handle_listing_validate_request(
            &validate_event,
            TradeListingValidateRequest { listing_event: None },
            "not-a-listing-addr",
            &client,
            &state,
        )
        .await
        .is_ok());

        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(validate_event.clone()));
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .validate_listing_results
            .push_back(Err(TradeListingValidationError::MissingInventory));
        push_send_ok();
        assert!(handle_listing_validate_request(
            &validate_event,
            TradeListingValidateRequest {
                listing_event: Some(RadrootsNostrEventPtr {
                    id: "x".to_string(),
                    relays: None,
                }),
            },
            &listing_addr,
            &client,
            &state,
        )
        .await
        .is_ok());

        let unauthorized_order = make_order(
            "order-3",
            &listing_addr,
            "different-buyer",
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        assert!(matches!(
            handle_order_request(
                &event,
                unauthorized_order,
                &parsed,
                Some("order-3"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        let duplicate_order = make_order(
            "order-1",
            &listing_addr,
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        assert!(handle_order_request(
            &event,
            duplicate_order,
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let buyer_event = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_RES),
            "x".to_string(),
            Vec::new(),
        );
        assert!(matches!(
            handle_order_response(
                &buyer_event,
                TradeOrderResponse {
                    accepted: false,
                    reason: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        push_send_ok();
        assert!(handle_order_response(
            &make_event(
                &seller_keys,
                RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_RES),
                "x".to_string(),
                Vec::new(),
            ),
            TradeOrderResponse {
                accepted: false,
                reason: None,
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        assert!(matches!(
            handle_order_revision(
                &make_event(
                    &seller_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REVISION_REQ),
                    "x".to_string(),
                    Vec::new(),
                ),
                TradeOrderRevision {
                    revision_id: "r3".to_string(),
                    order_id: "other".to_string(),
                    changes: Vec::new(),
                    reason: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        let seen_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REVISION_REQ),
            "x".to_string(),
            Vec::new(),
        );
        state
            .lock()
            .await
            .get_order_mut("order-1")
            .expect("order")
            .seen_event_ids
            .insert(seen_event.id.to_string());
        assert!(handle_order_revision(
            &seen_event,
            TradeOrderRevision {
                revision_id: "r4".to_string(),
                order_id: "order-1".to_string(),
                changes: Vec::new(),
                reason: None,
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        assert!(matches!(
            handle_question(
                &make_event(
                    &buyer_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_QUESTION_REQ),
                    "x".to_string(),
                    Vec::new(),
                ),
                TradeQuestion {
                    question_id: "q".to_string(),
                    order_id: Some("other".to_string()),
                    listing_addr: None,
                    question_text: "q".to_string(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Questioned).await;
        assert!(matches!(
            handle_answer(
                &make_event(
                    &seller_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ANSWER_RES),
                    "x".to_string(),
                    Vec::new(),
                ),
                TradeAnswer {
                    question_id: "q".to_string(),
                    order_id: Some("other".to_string()),
                    listing_addr: None,
                    answer_text: "a".to_string(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        assert!(matches!(
            handle_discount_request(
                &make_event(
                    &buyer_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_REQ),
                    "x".to_string(),
                    Vec::new(),
                ),
                TradeDiscountRequest {
                    discount_id: "d".to_string(),
                    order_id: "other".to_string(),
                    value: sample_discount_value(),
                    conditions: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        assert!(matches!(
            handle_discount_offer(
                &make_event(
                    &seller_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_OFFER_RES),
                    "x".to_string(),
                    Vec::new(),
                ),
                TradeDiscountOffer {
                    discount_id: "d".to_string(),
                    order_id: "other".to_string(),
                    value: sample_discount_value(),
                    conditions: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Revised).await;
        assert!(matches!(
            handle_discount_decision(
                &make_event(
                    &buyer_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_ACCEPT_REQ),
                    "x".to_string(),
                    Vec::new(),
                ),
                TradeListingMessageType::DiscountAccept,
                TradeDiscountDecision::Decline { reason: None },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));
        assert!(matches!(
            handle_discount_decision(
                &make_event(
                    &buyer_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_DECLINE_REQ),
                    "x".to_string(),
                    Vec::new(),
                ),
                TradeListingMessageType::DiscountDecline,
                TradeDiscountDecision::Accept {
                    value: sample_discount_value(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        push_send_ok();
        assert!(handle_discount_decision(
            &make_event(
                &buyer_keys,
                RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_DECLINE_REQ),
                "x".to_string(),
                Vec::new(),
            ),
            TradeListingMessageType::Cancel,
            TradeDiscountDecision::Decline { reason: None },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let cancel_by_seller = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_CANCEL_REQ),
            "x".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(handle_cancel(
            &cancel_by_seller,
            TradeListingCancel { reason: None },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        set_order_status(&state, "order-1", TradeOrderStatus::Accepted).await;
        assert!(matches!(
            handle_fulfillment_update(
                &make_event(
                    &buyer_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_FULFILLMENT_UPDATE_REQ),
                    "x".to_string(),
                    Vec::new(),
                ),
                TradeFulfillmentUpdate {
                    status: TradeFulfillmentStatus::Shipped,
                    tracking: None,
                    eta: None,
                    notes: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Fulfilled).await;
        assert!(matches!(
            handle_receipt(
                &make_event(
                    &seller_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_RECEIPT_REQ),
                    "x".to_string(),
                    Vec::new(),
                ),
                TradeReceipt {
                    acknowledged: true,
                    at: 1,
                    note: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn handler_duplicate_optional_and_guard_branches_are_covered() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, buyer_keys) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let parsed = TradeListingAddress::parse(&listing_addr).expect("listing");
        let buyer_pub = buyer_keys.public_key().to_hex();
        let seller_pub = seller_keys.public_key().to_hex();
        let state = state_with_order(
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        )
        .await;

        let mismatched_addr = listing_addr_for_seller(&buyer_keys);
        let mismatched_parsed = TradeListingAddress::parse(&mismatched_addr).expect("mismatched listing");
        let revision_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REVISION_REQ),
            "revision".to_string(),
            Vec::new(),
        );
        assert!(matches!(
            handle_order_revision(
                &revision_event,
                TradeOrderRevision {
                    revision_id: "r1".to_string(),
                    order_id: "order-1".to_string(),
                    changes: Vec::new(),
                    reason: None,
                },
                &mismatched_parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        let seen_revision_response = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REVISION_RES),
            "seen".to_string(),
            Vec::new(),
        );
        mark_event_seen(&state, "order-1", seen_revision_response.id.to_string()).await;
        assert!(handle_order_revision_response(
            &seen_revision_response,
            TradeListingMessageType::OrderRevisionAccept,
            TradeOrderRevisionResponse {
                accepted: true,
                reason: None,
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        assert!(matches!(
            handle_order_revision_response(
                &make_event(
                    &buyer_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REVISION_RES),
                    "accept-invalid".to_string(),
                    Vec::new(),
                ),
                TradeListingMessageType::OrderRevisionAccept,
                TradeOrderRevisionResponse {
                    accepted: false,
                    reason: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));
        assert!(matches!(
            handle_order_revision_response(
                &make_event(
                    &buyer_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ORDER_REVISION_RES),
                    "decline-invalid".to_string(),
                    Vec::new(),
                ),
                TradeListingMessageType::OrderRevisionDecline,
                TradeOrderRevisionResponse {
                    accepted: true,
                    reason: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        push_send_ok();
        assert!(handle_question(
            &make_event(
                &buyer_keys,
                RadrootsNostrKind::Custom(KIND_TRADE_LISTING_QUESTION_REQ),
                "question-ok".to_string(),
                Vec::new(),
            ),
            TradeQuestion {
                question_id: "q1".to_string(),
                order_id: None,
                listing_addr: Some(listing_addr.clone()),
                question_text: "question".to_string(),
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        let seen_question = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_QUESTION_REQ),
            "question-seen".to_string(),
            Vec::new(),
        );
        mark_event_seen(&state, "order-1", seen_question.id.to_string()).await;
        assert!(handle_question(
            &seen_question,
            TradeQuestion {
                question_id: "q2".to_string(),
                order_id: Some("order-1".to_string()),
                listing_addr: None,
                question_text: "question".to_string(),
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());
        assert!(matches!(
            handle_question(
                &make_event(
                    &seller_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_QUESTION_REQ),
                    "question-unauthorized".to_string(),
                    Vec::new(),
                ),
                TradeQuestion {
                    question_id: "q3".to_string(),
                    order_id: Some("order-1".to_string()),
                    listing_addr: None,
                    question_text: "question".to_string(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Questioned).await;
        push_send_ok();
        assert!(handle_answer(
            &make_event(
                &seller_keys,
                RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ANSWER_RES),
                "answer-ok".to_string(),
                Vec::new(),
            ),
            TradeAnswer {
                question_id: "q1".to_string(),
                order_id: None,
                listing_addr: Some(listing_addr.clone()),
                answer_text: "answer".to_string(),
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        let seen_answer = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ANSWER_RES),
            "answer-seen".to_string(),
            Vec::new(),
        );
        mark_event_seen(&state, "order-1", seen_answer.id.to_string()).await;
        assert!(handle_answer(
            &seen_answer,
            TradeAnswer {
                question_id: "q1".to_string(),
                order_id: Some("order-1".to_string()),
                listing_addr: None,
                answer_text: "answer".to_string(),
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());
        assert!(matches!(
            handle_answer(
                &make_event(
                    &buyer_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ANSWER_RES),
                    "answer-unauthorized".to_string(),
                    Vec::new(),
                ),
                TradeAnswer {
                    question_id: "q1".to_string(),
                    order_id: Some("order-1".to_string()),
                    listing_addr: None,
                    answer_text: "answer".to_string(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let seen_discount_request = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_REQ),
            "discount-request-seen".to_string(),
            Vec::new(),
        );
        mark_event_seen(&state, "order-1", seen_discount_request.id.to_string()).await;
        assert!(handle_discount_request(
            &seen_discount_request,
            TradeDiscountRequest {
                discount_id: "d1".to_string(),
                order_id: "order-1".to_string(),
                value: sample_discount_value(),
                conditions: None,
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());
        assert!(matches!(
            handle_discount_request(
                &make_event(
                    &seller_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_REQ),
                    "discount-request-unauthorized".to_string(),
                    Vec::new(),
                ),
                TradeDiscountRequest {
                    discount_id: "d2".to_string(),
                    order_id: "order-1".to_string(),
                    value: sample_discount_value(),
                    conditions: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let seen_discount_offer = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_OFFER_RES),
            "discount-offer-seen".to_string(),
            Vec::new(),
        );
        mark_event_seen(&state, "order-1", seen_discount_offer.id.to_string()).await;
        assert!(handle_discount_offer(
            &seen_discount_offer,
            TradeDiscountOffer {
                discount_id: "d1".to_string(),
                order_id: "order-1".to_string(),
                value: sample_discount_value(),
                conditions: None,
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());
        assert!(matches!(
            handle_discount_offer(
                &make_event(
                    &buyer_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_OFFER_RES),
                    "discount-offer-unauthorized".to_string(),
                    Vec::new(),
                ),
                TradeDiscountOffer {
                    discount_id: "d2".to_string(),
                    order_id: "order-1".to_string(),
                    value: sample_discount_value(),
                    conditions: None,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Revised).await;
        let seen_discount_decision = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_DECLINE_REQ),
            "discount-decision-seen".to_string(),
            Vec::new(),
        );
        mark_event_seen(&state, "order-1", seen_discount_decision.id.to_string()).await;
        assert!(handle_discount_decision(
            &seen_discount_decision,
            TradeListingMessageType::DiscountDecline,
            TradeDiscountDecision::Decline { reason: None },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());
        assert!(matches!(
            handle_discount_decision(
                &make_event(
                    &seller_keys,
                    RadrootsNostrKind::Custom(KIND_TRADE_LISTING_DISCOUNT_DECLINE_REQ),
                    "discount-decision-unauthorized".to_string(),
                    Vec::new(),
                ),
                TradeListingMessageType::DiscountDecline,
                TradeDiscountDecision::Decline { reason: None },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let seen_cancel = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_CANCEL_REQ),
            "cancel-seen".to_string(),
            Vec::new(),
        );
        mark_event_seen(&state, "order-1", seen_cancel.id.to_string()).await;
        assert!(handle_cancel(
            &seen_cancel,
            TradeListingCancel { reason: None },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        set_order_status(&state, "order-1", TradeOrderStatus::Accepted).await;
        let seen_fulfillment = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_FULFILLMENT_UPDATE_REQ),
            "fulfillment-seen".to_string(),
            Vec::new(),
        );
        mark_event_seen(&state, "order-1", seen_fulfillment.id.to_string()).await;
        assert!(handle_fulfillment_update(
            &seen_fulfillment,
            TradeFulfillmentUpdate {
                status: TradeFulfillmentStatus::Shipped,
                tracking: None,
                eta: None,
                notes: None,
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());

        set_order_status(&state, "order-1", TradeOrderStatus::Fulfilled).await;
        let seen_receipt = make_event(
            &buyer_keys,
            RadrootsNostrKind::Custom(KIND_TRADE_LISTING_RECEIPT_REQ),
            "receipt-seen".to_string(),
            Vec::new(),
        );
        mark_event_seen(&state, "order-1", seen_receipt.id.to_string()).await;
        assert!(handle_receipt(
            &seen_receipt,
            TradeReceipt {
                acknowledged: true,
                at: 1,
                note: None,
            },
            &parsed,
            Some("order-1"),
            &client,
            &state,
        )
        .await
        .is_ok());
    }
}
