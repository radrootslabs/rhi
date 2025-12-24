#![forbid(unsafe_code)]

use std::{sync::Arc, time::Duration};

use radroots_nostr::prelude::{
    radroots_event_from_nostr,
    radroots_nostr_build_event,
    radroots_nostr_build_event_job_feedback,
    radroots_nostr_fetch_event_by_id,
    radroots_nostr_parse_pubkey,
    radroots_nostr_send_event,
    RadrootsNostrClient,
    RadrootsNostrEvent,
    RadrootsNostrFilter,
    RadrootsNostrKind,
    RadrootsNostrKeys,
    RadrootsNostrTag,
};
use radroots_trade::listing::{
    dvm::{
        TradeListingEnvelope, TradeListingEnvelopeError, TradeListingMessageType,
        TradeListingValidateRequest, TradeListingValidateResult, TradeOrderResponse,
        TradeOrderRevisionResponse, TradeListingCancel, TradeListingAddress,
    },
    dvm_kinds::is_trade_listing_dvm_kind,
    order::{
        TradeAnswer, TradeDiscountDecision, TradeDiscountOffer, TradeDiscountRequest,
        TradeFulfillmentUpdate, TradeOrder, TradeOrderRevision, TradeOrderStatus, TradeQuestion,
        TradeReceipt,
    },
    validation::{validate_listing_event, TradeListingValidationError},
};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::features::trade_listing::state::{TradeListingState, TradeListingStateError, TradeOrderState};

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
    if !is_trade_listing_dvm_kind(kind) {
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

    let envelope: TradeListingEnvelope<serde_json::Value> =
        serde_json::from_str(&event.content)?;
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

    let listing_addr_parsed =
        TradeListingAddress::parse(&listing_addr).map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    if listing_addr_parsed.kind != 30402 {
        return Err(TradeListingDvmError::InvalidListingAddr);
    }

    match envelope.message_type {
        TradeListingMessageType::ListingValidateRequest => {
            let payload: TradeListingValidateRequest = parse_payload(envelope.payload)?;
            handle_listing_validate_request(
                &event,
                payload,
                &listing_addr,
                &client,
                &state,
            )
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
        TradeListingMessageType::OrderRevisionAccept | TradeListingMessageType::OrderRevisionDecline => {
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
        match radroots_nostr_fetch_event_by_id(client, &ptr.id).await {
            Ok(evt) => Some(evt),
            Err(err) => {
                let error = match err {
                    radroots_nostr::error::RadrootsNostrError::EventNotFound(_) => {
                        TradeListingValidationError::ListingEventNotFound {
                            listing_addr: listing_addr.to_string(),
                        }
                    }
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
        let rr_event = radroots_event_from_nostr(&event);
        match validate_listing_event(&rr_event) {
            Ok(_) => {
                let mut state = state.lock().await;
                state.mark_listing_validated(listing_addr);
                Vec::new()
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
    let envelope = TradeListingEnvelope::new(
        message_type,
        listing_addr.to_string(),
        order_id.map(|v| v.to_string()),
        payload.clone(),
    );
    let content = serde_json::to_string(&envelope)?;
    let mut tags = Vec::with_capacity(3);
    tags.push(vec!["p".into(), recipient_pubkey]);
    tags.push(vec!["a".into(), listing_addr.to_string()]);
    if let Some(order_id) = order_id {
        tags.push(vec!["d".into(), order_id.to_string()]);
    }
    let builder = radroots_nostr_build_event(message_type.kind() as u32, content, tags)?;
    radroots_nostr_send_event(client, builder).await?;
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
    let events = client.fetch_events(filter, Duration::from_secs(10)).await?;
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
            matches!(to, TradeOrderStatus::Fulfilled | TradeOrderStatus::Cancelled)
        }
        TradeOrderStatus::Declined => false,
        TradeOrderStatus::Cancelled => false,
        TradeOrderStatus::Fulfilled => {
            matches!(
                to,
                TradeOrderStatus::Completed | TradeOrderStatus::Fulfilled | TradeOrderStatus::Cancelled
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
    let _ = radroots_nostr_send_event(client, builder).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ensure_transition;
    use radroots_trade::listing::order::TradeOrderStatus;

    #[test]
    fn transition_rejects_accept_after_decline() {
        let err = ensure_transition(TradeOrderStatus::Declined, TradeOrderStatus::Accepted);
        assert!(err.is_err());
    }

    #[test]
    fn transition_allows_revision_after_request() {
        let ok = ensure_transition(TradeOrderStatus::Requested, TradeOrderStatus::Revised);
        assert!(ok.is_ok());
    }
}
