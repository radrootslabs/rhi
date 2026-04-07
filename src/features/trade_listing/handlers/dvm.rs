#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use std::{sync::Arc, time::Duration};

use radroots_events::kinds::{KIND_FARM, is_listing_kind, is_trade_kind};
use radroots_events::listing::RadrootsListingFarmRef;
use radroots_events::trade::{
    RadrootsTradeAnswer as TradeAnswer, RadrootsTradeDiscountDecision as TradeDiscountDecision,
    RadrootsTradeDiscountOffer as TradeDiscountOffer,
    RadrootsTradeDiscountRequest as TradeDiscountRequest,
    RadrootsTradeEnvelope as TradeListingEnvelope,
    RadrootsTradeEnvelopeError as TradeListingEnvelopeError,
    RadrootsTradeFulfillmentStatus as TradeFulfillmentStatus,
    RadrootsTradeFulfillmentUpdate as TradeFulfillmentUpdate,
    RadrootsTradeListingCancel as TradeListingCancel,
    RadrootsTradeListingValidateRequest as TradeListingValidateRequest,
    RadrootsTradeListingValidateResult as TradeListingValidateResult,
    RadrootsTradeListingValidationError as TradeListingValidationError,
    RadrootsTradeMessagePayload as TradeListingMessagePayload,
    RadrootsTradeMessageType as TradeListingMessageType, RadrootsTradeOrder as TradeOrder,
    RadrootsTradeOrderResponse as TradeOrderResponse,
    RadrootsTradeOrderRevision as TradeOrderRevision,
    RadrootsTradeOrderRevisionResponse as TradeOrderRevisionResponse,
    RadrootsTradeOrderStatus as TradeOrderStatus, RadrootsTradeQuestion as TradeQuestion,
    RadrootsTradeReceipt as TradeReceipt,
};
use radroots_events_codec::trade::{
    RadrootsTradeEnvelopeParseError as TradeListingEnvelopeParseError,
    RadrootsTradeListingAddress as TradeListingAddress,
    trade_envelope_event_build as trade_listing_envelope_event_build, trade_envelope_from_event,
};
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrFilter,
    RadrootsNostrKeys, RadrootsNostrKind, RadrootsNostrTag, radroots_event_from_nostr,
    radroots_nostr_build_event, radroots_nostr_build_event_job_feedback,
    radroots_nostr_fetch_event_by_id, radroots_nostr_parse_pubkey, radroots_nostr_send_event,
};
use radroots_trade::listing::projection::RadrootsTradeOrderWorkflowMessage;
use radroots_trade::listing::validation::validate_listing_event;
#[cfg(test)]
use serde::de::DeserializeOwned;
use std::convert::TryFrom;
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
    validate_listing_results: std::collections::VecDeque<
        Result<(String, RadrootsListingFarmRef), TradeListingValidationError>,
    >,
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
fn pop_validate_listing_hook()
-> Option<Result<(String, RadrootsListingFarmRef), TradeListingValidationError>> {
    dvm_test_hooks()
        .lock()
        .expect("dvm test hooks lock")
        .validate_listing_results
        .pop_front()
}

#[cfg(test)]
fn pop_farm_validation_hook()
-> Option<Result<Vec<TradeListingValidationError>, TradeListingDvmError>> {
    dvm_test_hooks()
        .lock()
        .expect("dvm test hooks lock")
        .farm_validation_results
        .pop_front()
}

#[cfg(test)]
fn take_fetch_event_by_id_hook() -> Option<Result<RadrootsNostrEvent, TradeListingDvmError>> {
    pop_fetch_event_by_id_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_fetch_event_by_id_hook() -> Option<Result<RadrootsNostrEvent, TradeListingDvmError>> {
    None
}

#[cfg(test)]
fn take_fetch_events_hook() -> Option<Result<Vec<RadrootsNostrEvent>, TradeListingDvmError>> {
    pop_fetch_events_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_fetch_events_hook() -> Option<Result<Vec<RadrootsNostrEvent>, TradeListingDvmError>> {
    None
}

#[cfg(test)]
fn take_send_event_hook() -> Option<Result<(), TradeListingDvmError>> {
    pop_send_event_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_send_event_hook() -> Option<Result<(), TradeListingDvmError>> {
    None
}

#[cfg(test)]
fn take_validate_listing_hook()
-> Option<Result<(String, RadrootsListingFarmRef), TradeListingValidationError>> {
    pop_validate_listing_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_validate_listing_hook()
-> Option<Result<(String, RadrootsListingFarmRef), TradeListingValidationError>> {
    None
}

async fn fetch_event_by_id_io(
    client: &RadrootsNostrClient,
    id: &str,
) -> Result<RadrootsNostrEvent, TradeListingDvmError> {
    let hook_result = take_fetch_event_by_id_hook();
    let event = match hook_result {
        Some(result) => result?,
        None => radroots_nostr_fetch_event_by_id(client, id).await?,
    };
    Ok(event)
}

async fn fetch_events_io(
    client: &RadrootsNostrClient,
    filter: RadrootsNostrFilter,
    timeout: Duration,
) -> Result<Vec<RadrootsNostrEvent>, TradeListingDvmError> {
    let hook_result = take_fetch_events_hook();
    let events = match hook_result {
        Some(result) => result?,
        None => client.fetch_events(filter, timeout).await?,
    };
    Ok(events)
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn send_event_io(
    client: &RadrootsNostrClient,
    builder: RadrootsNostrEventBuilder,
) -> Result<(), TradeListingDvmError> {
    let hook_result = take_send_event_hook();
    let send_result: Result<(), TradeListingDvmError> = match hook_result {
        Some(result) => result,
        None => radroots_nostr_send_event(client, builder)
            .await
            .map(|_| ())
            .map_err(TradeListingDvmError::from),
    };
    send_result?;
    Ok(())
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
fn validate_listing_event_io(
    event: &RadrootsNostrEvent,
) -> Result<(String, RadrootsListingFarmRef), TradeListingValidationError> {
    let hook_result = take_validate_listing_hook();
    let validated = match hook_result {
        Some(result) => result?,
        None => validate_listing_event(&radroots_event_from_nostr(event))
            .map(|listing| (listing.listing_addr, listing.listing.farm))?,
    };
    Ok(validated)
}

pub async fn handle_event(
    event: RadrootsNostrEvent,
    _tags: Vec<RadrootsNostrTag>,
    keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    state: Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let kind = match event.kind {
        RadrootsNostrKind::Custom(v) => u32::from(v),
        _ => return Err(TradeListingDvmError::UnsupportedKind),
    };
    if is_listing_kind(kind) {
        handle_listing_event(&event, &state).await?;
        return Ok(());
    }
    if !is_trade_kind(kind) {
        return Err(TradeListingDvmError::UnsupportedKind);
    }

    if event.pubkey == keys.public_key() {
        return Ok(());
    }

    let envelope_hint: TradeListingEnvelope<serde_json::Value> =
        serde_json::from_str(&event.content)
            .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))?;
    if envelope_hint.message_type.kind() != kind {
        return Err(TradeListingDvmError::TagMismatch("kind"));
    }

    let tag_slices: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
    if envelope_hint.message_type.is_service() {
        let rhi_pubkey = keys.public_key().to_string();
        if !tag_has_value(&tag_slices, "p", &rhi_pubkey) {
            return Err(TradeListingDvmError::MissingRecipient);
        }
    }

    let envelope: TradeListingEnvelope<TradeListingMessagePayload> =
        trade_envelope_from_event(&radroots_event_from_nostr(&event))
            .map_err(map_trade_envelope_parse_error)?;
    if envelope.payload.message_type() != envelope.message_type {
        return Err(TradeListingDvmError::InvalidPayload(
            "trade envelope payload does not match message type".to_string(),
        ));
    }

    let order_id = envelope.order_id.as_deref();
    let listing_addr = envelope.listing_addr.clone();
    let listing_addr_parsed = TradeListingAddress::parse(&listing_addr)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    if !is_listing_kind(listing_addr_parsed.kind) {
        return Err(TradeListingDvmError::InvalidListingAddr);
    }

    match envelope.payload {
        TradeListingMessagePayload::ListingValidateRequest(payload) => {
            handle_listing_validate_request(&event, payload, &listing_addr, &client, &state)
                .await?;
        }
        TradeListingMessagePayload::OrderRequest(payload) => {
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
        TradeListingMessagePayload::OrderResponse(payload) => {
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
        TradeListingMessagePayload::OrderRevision(payload) => {
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
        TradeListingMessagePayload::OrderRevisionAccept(payload)
        | TradeListingMessagePayload::OrderRevisionDecline(payload) => {
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
        TradeListingMessagePayload::Question(payload) => {
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
        TradeListingMessagePayload::Answer(payload) => {
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
        TradeListingMessagePayload::DiscountRequest(payload) => {
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
        TradeListingMessagePayload::DiscountOffer(payload) => {
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
        TradeListingMessagePayload::DiscountAccept(payload)
        | TradeListingMessagePayload::DiscountDecline(payload) => {
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
        TradeListingMessagePayload::Cancel(payload) => {
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
        TradeListingMessagePayload::FulfillmentUpdate(payload) => {
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
        TradeListingMessagePayload::Receipt(payload) => {
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
        TradeListingMessagePayload::ListingValidateResult(_) => {}
    }

    Ok(())
}

fn map_trade_envelope_parse_error(error: TradeListingEnvelopeParseError) -> TradeListingDvmError {
    match error {
        TradeListingEnvelopeParseError::InvalidKind(_) => TradeListingDvmError::UnsupportedKind,
        TradeListingEnvelopeParseError::InvalidJson
        | TradeListingEnvelopeParseError::InvalidTag(_) => {
            TradeListingDvmError::InvalidPayload(error.to_string())
        }
        TradeListingEnvelopeParseError::InvalidEnvelope(inner) => {
            TradeListingDvmError::InvalidEnvelope(inner)
        }
        TradeListingEnvelopeParseError::MessageTypeKindMismatch { .. } => {
            TradeListingDvmError::TagMismatch("kind")
        }
        TradeListingEnvelopeParseError::MissingTag(tag) => TradeListingDvmError::MissingTag(tag),
        TradeListingEnvelopeParseError::ListingAddrTagMismatch => {
            TradeListingDvmError::TagMismatch("a")
        }
        TradeListingEnvelopeParseError::OrderIdTagMismatch => {
            TradeListingDvmError::TagMismatch("d")
        }
        TradeListingEnvelopeParseError::InvalidListingAddr(_) => {
            TradeListingDvmError::InvalidListingAddr
        }
    }
}

async fn handle_listing_event(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let event_id = event.id.to_string();
    {
        let state = state.lock().await;
        if state.is_non_order_event_seen(&event_id) {
            return Ok(());
        }
    }

    let validated = validate_listing_event(&radroots_event_from_nostr(event))
        .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))?;
    let kind = match event.kind {
        RadrootsNostrKind::Custom(value) => u32::from(value),
        _ => return Err(TradeListingDvmError::UnsupportedKind),
    };

    let mut state = state.lock().await;
    state.upsert_listing_event(&validated.listing_addr, &event_id, kind);
    state.mark_non_order_event_seen(&event_id);
    Ok(())
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn handle_listing_validate_request(
    event: &RadrootsNostrEvent,
    payload: TradeListingValidateRequest,
    listing_addr: &str,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    {
        let state = state.lock().await;
        if state.is_non_order_event_seen(&event.id.to_string()) {
            return Ok(());
        }
    }

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
                state.lock().await.clear_listing_validation(listing_addr);
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
                state.lock().await.clear_listing_validation(listing_addr);
                send_validate_result(event, client, listing_addr, vec![error]).await?;
                return Ok(());
            }
        }
    };

    let (validated_event_id, errors): (Option<String>, Vec<TradeListingValidationError>) =
        if let Some(listing_event) = listing_event {
            match validate_listing_event_io(&listing_event) {
                Ok((validated_listing_addr, farm)) => {
                    if validated_listing_addr != listing_addr {
                        (
                            None,
                            vec![TradeListingValidationError::ListingEventNotFound {
                                listing_addr: listing_addr.to_string(),
                            }],
                        )
                    } else {
                        let errors: Vec<TradeListingValidationError> =
                            validate_farm_dependencies(client, &farm).await?;
                        if errors.is_empty() {
                            (Some(listing_event.id.to_string()), errors)
                        } else {
                            (None, errors)
                        }
                    }
                }
                Err(err) => (None, vec![err]),
            }
        } else {
            (
                None,
                vec![TradeListingValidationError::ListingEventNotFound {
                    listing_addr: listing_addr.to_string(),
                }],
            )
        };

    {
        let mut state = state.lock().await;
        match validated_event_id {
            Some(validated_event_id) => {
                state.mark_listing_validated(listing_addr, &validated_event_id);
            }
            None => state.clear_listing_validation(listing_addr),
        }
    }

    send_validate_result(event, client, listing_addr, errors).await?;
    state
        .lock()
        .await
        .mark_non_order_event_seen(&event.id.to_string());
    Ok(())
}

async fn send_validate_result(
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
    listing_addr: &str,
    errors: Vec<TradeListingValidationError>,
) -> Result<(), TradeListingDvmError> {
    let payload = TradeListingMessagePayload::ListingValidateResult(TradeListingValidateResult {
        valid: errors.is_empty(),
        errors,
    });
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

fn workflow_message_from_event(
    event: &RadrootsNostrEvent,
) -> Result<RadrootsTradeOrderWorkflowMessage, TradeListingDvmError> {
    RadrootsTradeOrderWorkflowMessage::from_event(&radroots_event_from_nostr(event))
        .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))
}

fn ensure_order_counterparty(actual: &str, expected: &str) -> Result<(), TradeListingDvmError> {
    if actual == expected {
        Ok(())
    } else {
        Err(TradeListingDvmError::Unauthorized)
    }
}

fn ensure_trade_chain(
    order: &TradeOrderState,
    message: &RadrootsTradeOrderWorkflowMessage,
) -> Result<(), TradeListingDvmError> {
    let root_event_id = message
        .root_event_id
        .as_deref()
        .ok_or(TradeListingDvmError::MissingTag("e:root"))?;
    if order.root_event_id.as_deref() != Some(root_event_id) {
        return Err(TradeListingDvmError::InvalidOrder);
    }

    let prev_event_id = message
        .prev_event_id
        .as_deref()
        .ok_or(TradeListingDvmError::MissingTag("e:prev"))?;
    if order.last_event_id.as_deref() != Some(prev_event_id) {
        return Err(TradeListingDvmError::InvalidOrder);
    }

    Ok(())
}

async fn ensure_listing_snapshot(
    message: &RadrootsTradeOrderWorkflowMessage,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<String, TradeListingDvmError> {
    let listing_event = message
        .listing_event
        .as_ref()
        .ok_or(TradeListingDvmError::MissingTag("listing_event"))?;
    let snapshot_id = listing_event.id.clone();

    {
        let state = state.lock().await;
        if state.listing_event_id(&message.listing_addr) == Some(snapshot_id.as_str()) {
            return Ok(snapshot_id);
        }
    }

    let snapshot_event = fetch_event_by_id_io(client, &snapshot_id).await?;
    let validated = validate_listing_event_io(&snapshot_event)
        .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))?;
    if validated.0 != message.listing_addr {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    let snapshot_kind = match snapshot_event.kind {
        RadrootsNostrKind::Custom(value) => u32::from(value),
        _ => return Err(TradeListingDvmError::InvalidListingAddr),
    };

    let mut state = state.lock().await;
    state.upsert_listing_event(&message.listing_addr, &snapshot_id, snapshot_kind);
    Ok(snapshot_id)
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn handle_order_request(
    event: &RadrootsNostrEvent,
    payload: TradeOrder,
    listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
    if payload.order_id != order_id || payload.listing_addr != listing_addr.as_str() {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    if payload.buyer_pubkey != event.pubkey.to_string() {
        return Err(TradeListingDvmError::Unauthorized);
    }
    ensure_order_counterparty(&message.counterparty_pubkey, &payload.seller_pubkey)?;
    let listing_snapshot_event_id = ensure_listing_snapshot(&message, client, state).await?;
    let event_id = event.id.to_string();

    {
        let state = state.lock().await;
        if state.order_exists(order_id) {
            return Ok(());
        }
    }

    let mut state = state.lock().await;
    if state.order_exists(order_id) {
        return Ok(());
    }

    if payload.buyer_pubkey != event.pubkey.to_string()
        || payload.seller_pubkey != listing_addr.seller_pubkey
    {
        return Err(TradeListingDvmError::Unauthorized);
    }

    let mut seen = std::collections::HashSet::new();
    seen.insert(event_id.clone());

    state.insert_order(TradeOrderState {
        order_id: order_id.to_string(),
        listing_addr: payload.listing_addr.clone(),
        buyer_pubkey: payload.buyer_pubkey.clone(),
        seller_pubkey: payload.seller_pubkey.clone(),
        status: TradeOrderStatus::Requested,
        listing_snapshot_event_id: Some(listing_snapshot_event_id),
        root_event_id: Some(event_id.clone()),
        last_event_id: Some(event_id.clone()),
        seen_event_ids: seen,
    });

    drop(state);

    Ok(())
}

async fn handle_order_response(
    event: &RadrootsNostrEvent,
    payload: TradeOrderResponse,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    _client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.buyer_pubkey)?;
    ensure_trade_chain(order, &message)?;

    let next_status = if payload.accepted {
        TradeOrderStatus::Accepted
    } else {
        TradeOrderStatus::Declined
    };
    ensure_transition(order.status.clone(), next_status.clone())?;
    order.status = next_status;
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);

    drop(state);

    Ok(())
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn handle_order_revision(
    event: &RadrootsNostrEvent,
    _payload: TradeOrderRevision,
    listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
    let listing_snapshot_event_id = ensure_listing_snapshot(&message, client, state).await?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.buyer_pubkey)?;
    ensure_trade_chain(order, &message)?;
    if listing_addr.seller_pubkey != order.seller_pubkey {
        return Err(TradeListingDvmError::Unauthorized);
    }
    ensure_transition(order.status.clone(), TradeOrderStatus::Revised)?;
    order.status = TradeOrderStatus::Revised;
    order.listing_snapshot_event_id = Some(listing_snapshot_event_id);
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

async fn handle_order_revision_response(
    event: &RadrootsNostrEvent,
    message_type: TradeListingMessageType,
    payload: TradeOrderRevisionResponse,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    _client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.seller_pubkey)?;
    ensure_trade_chain(order, &message)?;
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
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

async fn handle_question(
    event: &RadrootsNostrEvent,
    _payload: TradeQuestion,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    _client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.seller_pubkey)?;
    ensure_trade_chain(order, &message)?;
    ensure_transition(order.status.clone(), TradeOrderStatus::Questioned)?;
    order.status = TradeOrderStatus::Questioned;
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn handle_answer(
    event: &RadrootsNostrEvent,
    _payload: TradeAnswer,
    listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    _client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
    let order_id = order_id.ok_or(TradeListingDvmError::MissingTag("d"))?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.buyer_pubkey)?;
    ensure_trade_chain(order, &message)?;
    ensure_transition(order.status.clone(), TradeOrderStatus::Requested)?;
    order.status = TradeOrderStatus::Requested;
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

async fn handle_discount_request(
    event: &RadrootsNostrEvent,
    _payload: TradeDiscountRequest,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
    let listing_snapshot_event_id = ensure_listing_snapshot(&message, client, state).await?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.seller_pubkey)?;
    ensure_trade_chain(order, &message)?;
    order.listing_snapshot_event_id = Some(listing_snapshot_event_id);
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

async fn handle_discount_offer(
    event: &RadrootsNostrEvent,
    _payload: TradeDiscountOffer,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
    let listing_snapshot_event_id = ensure_listing_snapshot(&message, client, state).await?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.buyer_pubkey)?;
    ensure_trade_chain(order, &message)?;
    ensure_transition(order.status.clone(), TradeOrderStatus::Revised)?;
    order.status = TradeOrderStatus::Revised;
    order.listing_snapshot_event_id = Some(listing_snapshot_event_id);
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

async fn handle_discount_decision(
    event: &RadrootsNostrEvent,
    message_type: TradeListingMessageType,
    payload: TradeDiscountDecision,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    _client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.seller_pubkey)?;
    ensure_trade_chain(order, &message)?;
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
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

async fn handle_cancel(
    event: &RadrootsNostrEvent,
    _payload: TradeListingCancel,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    _client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
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
    let expected_counterparty = if sender == order.buyer_pubkey {
        order.seller_pubkey.as_str()
    } else {
        order.buyer_pubkey.as_str()
    };
    ensure_order_counterparty(&message.counterparty_pubkey, expected_counterparty)?;
    ensure_trade_chain(order, &message)?;
    ensure_transition(order.status.clone(), TradeOrderStatus::Cancelled)?;
    order.status = TradeOrderStatus::Cancelled;
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

async fn handle_fulfillment_update(
    event: &RadrootsNostrEvent,
    payload: TradeFulfillmentUpdate,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    _client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.buyer_pubkey)?;
    ensure_trade_chain(order, &message)?;
    if let Some(next_status) = next_status_for_fulfillment_update(&order.status, &payload.status)? {
        order.status = next_status;
    }
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

async fn handle_receipt(
    event: &RadrootsNostrEvent,
    payload: TradeReceipt,
    _listing_addr: &TradeListingAddress,
    order_id: Option<&str>,
    _client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let message = workflow_message_from_event(event)?;
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
    ensure_order_counterparty(&message.counterparty_pubkey, &order.seller_pubkey)?;
    ensure_trade_chain(order, &message)?;
    if let Some(next_status) = next_status_for_receipt(&order.status, payload.acknowledged)? {
        order.status = next_status;
    }
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    drop(state);

    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
async fn send_envelope(
    client: &RadrootsNostrClient,
    recipient_pubkey: String,
    message_type: TradeListingMessageType,
    listing_addr: &str,
    order_id: Option<&str>,
    payload: &TradeListingMessagePayload,
) -> Result<(), TradeListingDvmError> {
    let envelope_event = trade_listing_envelope_event_build(
        recipient_pubkey,
        message_type,
        listing_addr,
        order_id.map(|value| value.to_string()),
        None,
        None,
        None,
        payload,
    )
    .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))?;
    let builder = radroots_nostr_build_event(
        envelope_event.kind as u32,
        envelope_event.content,
        envelope_event.tags,
    )?;
    send_event_io(client, builder).await?;
    Ok(())
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn fetch_listing_by_addr(
    client: &RadrootsNostrClient,
    listing_addr: &str,
) -> Result<Option<RadrootsNostrEvent>, TradeListingDvmError> {
    let addr = TradeListingAddress::parse(listing_addr)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let author = radroots_nostr_parse_pubkey(&addr.seller_pubkey)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let kind = u16::try_from(addr.kind).map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let filter = RadrootsNostrFilter::new()
        .kind(RadrootsNostrKind::Custom(kind))
        .author(author)
        .identifier(addr.listing_id);
    let events = fetch_events_io(client, filter, Duration::from_secs(10)).await?;
    let latest = events
        .into_iter()
        .filter(|ev| ev.kind == RadrootsNostrKind::Custom(kind))
        .max_by_key(|ev| ev.created_at);
    Ok(latest)
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn fetch_latest_event_by_kind(
    client: &RadrootsNostrClient,
    filter: RadrootsNostrFilter,
    kind: RadrootsNostrKind,
) -> Result<Option<RadrootsNostrEvent>, TradeListingDvmError> {
    let events = fetch_events_io(client, filter, Duration::from_secs(10)).await?;
    let latest = events
        .into_iter()
        .filter(|ev| ev.kind == kind)
        .max_by_key(|ev| ev.created_at);
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn parse_payload<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, TradeListingDvmError> {
    serde_json::from_value(value).map_err(|e| TradeListingDvmError::InvalidPayload(e.to_string()))
}

#[cfg(test)]
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

fn next_status_for_fulfillment_update(
    current: &TradeOrderStatus,
    fulfillment_status: &TradeFulfillmentStatus,
) -> Result<Option<TradeOrderStatus>, TradeListingStateError> {
    match fulfillment_status {
        TradeFulfillmentStatus::Preparing
        | TradeFulfillmentStatus::Shipped
        | TradeFulfillmentStatus::ReadyForPickup => {
            if matches!(current, TradeOrderStatus::Accepted) {
                Ok(None)
            } else {
                Err(TradeListingStateError::InvalidTransition {
                    from: current.clone(),
                    to: TradeOrderStatus::Accepted,
                })
            }
        }
        TradeFulfillmentStatus::Delivered => {
            ensure_transition(current.clone(), TradeOrderStatus::Fulfilled)?;
            Ok(Some(TradeOrderStatus::Fulfilled))
        }
        TradeFulfillmentStatus::Cancelled => {
            ensure_transition(current.clone(), TradeOrderStatus::Cancelled)?;
            Ok(Some(TradeOrderStatus::Cancelled))
        }
    }
}

fn next_status_for_receipt(
    current: &TradeOrderStatus,
    acknowledged: bool,
) -> Result<Option<TradeOrderStatus>, TradeListingStateError> {
    if acknowledged {
        ensure_transition(current.clone(), TradeOrderStatus::Completed)?;
        Ok(Some(TradeOrderStatus::Completed))
    } else if matches!(current, TradeOrderStatus::Fulfilled) {
        Ok(None)
    } else {
        Err(TradeListingStateError::InvalidTransition {
            from: current.clone(),
            to: TradeOrderStatus::Fulfilled,
        })
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        DvmTestHooks, TradeListingDvmError, dvm_test_hooks, ensure_transition,
        fetch_event_by_id_io, fetch_events_io, fetch_latest_event_by_kind, fetch_listing_by_addr,
        handle_answer, handle_cancel, handle_discount_decision, handle_discount_offer,
        handle_discount_request, handle_error, handle_event, handle_fulfillment_update,
        handle_listing_validate_request, handle_order_request, handle_order_response,
        handle_order_revision, handle_order_revision_response, handle_question, handle_receipt,
        next_status_for_fulfillment_update, next_status_for_receipt, parse_payload, send_envelope,
        send_event_io, tag_has_value, tag_value, validate_farm_dependencies,
        validate_listing_event_io,
    };
    use crate::features::trade_listing::state::{
        TradeListingState, TradeListingStateError, TradeOrderState,
    };
    use radroots_core::{RadrootsCoreCurrency, RadrootsCoreDiscountValue, RadrootsCoreMoney};
    use radroots_events::RadrootsNostrEventPtr;
    use radroots_events::kinds::{
        KIND_TRADE_LISTING_ANSWER_RES, KIND_TRADE_LISTING_CANCEL_REQ,
        KIND_TRADE_LISTING_DISCOUNT_ACCEPT_REQ, KIND_TRADE_LISTING_DISCOUNT_DECLINE_REQ,
        KIND_TRADE_LISTING_DISCOUNT_OFFER_RES, KIND_TRADE_LISTING_DISCOUNT_REQ,
        KIND_TRADE_LISTING_FULFILLMENT_UPDATE_REQ, KIND_TRADE_LISTING_ORDER_REQ,
        KIND_TRADE_LISTING_ORDER_RES, KIND_TRADE_LISTING_ORDER_REVISION_REQ,
        KIND_TRADE_LISTING_ORDER_REVISION_RES, KIND_TRADE_LISTING_QUESTION_REQ,
        KIND_TRADE_LISTING_RECEIPT_REQ, KIND_TRADE_LISTING_VALIDATE_REQ,
        KIND_TRADE_LISTING_VALIDATE_RES,
    };
    use radroots_events::listing::RadrootsListingFarmRef;
    use radroots_events::trade::RadrootsTradeListingValidationError as TradeListingValidationError;
    use radroots_events::trade::{
        RadrootsTradeAnswer as TradeAnswer, RadrootsTradeDiscountDecision as TradeDiscountDecision,
        RadrootsTradeDiscountOffer as TradeDiscountOffer,
        RadrootsTradeDiscountRequest as TradeDiscountRequest,
        RadrootsTradeEnvelope as TradeListingEnvelope,
        RadrootsTradeFulfillmentStatus as TradeFulfillmentStatus,
        RadrootsTradeFulfillmentUpdate as TradeFulfillmentUpdate,
        RadrootsTradeListingCancel as TradeListingCancel,
        RadrootsTradeListingValidateRequest as TradeListingValidateRequest,
        RadrootsTradeListingValidateResult as TradeListingValidateResult,
        RadrootsTradeMessagePayload as TradeListingMessagePayload,
        RadrootsTradeMessageType as TradeListingMessageType, RadrootsTradeOrder as TradeOrder,
        RadrootsTradeOrderResponse as TradeOrderResponse,
        RadrootsTradeOrderRevision as TradeOrderRevision,
        RadrootsTradeOrderRevisionResponse as TradeOrderRevisionResponse,
        RadrootsTradeOrderStatus as TradeOrderStatus, RadrootsTradeQuestion as TradeQuestion,
        RadrootsTradeReceipt as TradeReceipt,
    };
    use radroots_events_codec::trade::RadrootsTradeListingAddress as TradeListingAddress;
    use radroots_nostr::error::RadrootsNostrError;
    use radroots_nostr::prelude::{
        RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrFilter,
        RadrootsNostrKeys, RadrootsNostrKind, RadrootsNostrTag, RadrootsNostrTagKind,
        RadrootsNostrTimestamp,
    };
    use serde_json::json;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex, MutexGuard};
    use tokio::sync::Mutex as AsyncMutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    const TEST_LISTING_EVENT_ID: &str = "listing-event";

    fn test_guard() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        *dvm_test_hooks()
            .lock()
            .unwrap_or_else(|err| err.into_inner()) = DvmTestHooks::default();
        guard
    }

    fn custom_trade_kind(kind: u32) -> RadrootsNostrKind {
        RadrootsNostrKind::Custom(
            kind.try_into()
                .expect("trade listing kinds fit in nostr custom range"),
        )
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

    fn push_validate_listing_ok(listing_addr: impl Into<String>, farm: RadrootsListingFarmRef) {
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .validate_listing_results
            .push_back(Ok((listing_addr.into(), farm)));
    }

    fn push_farm_validation_result(
        result: Result<Vec<TradeListingValidationError>, TradeListingDvmError>,
    ) {
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
        format!(
            "30402:{}:AAAAAAAAAAAAAAAAAAAAAA",
            seller.public_key().to_hex()
        )
    }

    fn make_client(keys: &RadrootsNostrKeys) -> RadrootsNostrClient {
        RadrootsNostrClient::new(keys.clone())
    }

    fn make_order(
        order_id: &str,
        listing_addr: &str,
        buyer: &str,
        seller: &str,
        _status: TradeOrderStatus,
    ) -> TradeOrder {
        TradeOrder {
            order_id: order_id.to_string(),
            listing_addr: listing_addr.to_string(),
            buyer_pubkey: buyer.to_string(),
            seller_pubkey: seller.to_string(),
            items: Vec::new(),
            discounts: None,
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
            listing_snapshot_event_id: Some("listing-event".to_string()),
            root_event_id: Some(format!("{order_id}:root")),
            last_event_id: Some(format!("{order_id}:root")),
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
        locked.mark_listing_validated(listing_addr, "validated-listing-event");
        locked.upsert_listing_event(listing_addr, TEST_LISTING_EVENT_ID, 30402);
        locked.insert_order(make_order_state(
            order_id,
            listing_addr,
            buyer,
            seller,
            status,
        ));
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

    fn make_custom_tags(
        recipient: &str,
        listing_addr: &str,
        order_id: Option<&str>,
    ) -> Vec<RadrootsNostrTag> {
        make_workflow_tags(recipient, listing_addr, order_id, None, None, None)
    }

    fn make_workflow_tags(
        recipient: &str,
        listing_addr: &str,
        order_id: Option<&str>,
        listing_event_id: Option<&str>,
        root_event_id: Option<&str>,
        prev_event_id: Option<&str>,
    ) -> Vec<RadrootsNostrTag> {
        let mut tags = vec![
            RadrootsNostrTag::custom(
                RadrootsNostrTagKind::custom("p"),
                vec![recipient.to_string()],
            ),
            RadrootsNostrTag::custom(
                RadrootsNostrTagKind::custom("a"),
                vec![listing_addr.to_string()],
            ),
        ];
        if let Some(order_id) = order_id {
            tags.push(RadrootsNostrTag::custom(
                RadrootsNostrTagKind::custom("d"),
                vec![order_id.to_string()],
            ));
        }
        if let Some(listing_event_id) = listing_event_id {
            tags.push(RadrootsNostrTag::custom(
                RadrootsNostrTagKind::custom("listing_event"),
                vec![listing_event_id.to_string()],
            ));
        }
        if let Some(root_event_id) = root_event_id {
            tags.push(RadrootsNostrTag::custom(
                RadrootsNostrTagKind::custom("e_root"),
                vec![root_event_id.to_string()],
            ));
        }
        if let Some(prev_event_id) = prev_event_id {
            tags.push(RadrootsNostrTag::custom(
                RadrootsNostrTagKind::custom("e_prev"),
                vec![prev_event_id.to_string()],
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

    fn make_canonical_envelope_content(
        message_type: TradeListingMessageType,
        listing_addr: &str,
        order_id: Option<&str>,
        payload: TradeListingMessagePayload,
    ) -> String {
        serde_json::to_string(&TradeListingEnvelope::new(
            message_type,
            listing_addr.to_string(),
            order_id.map(|value| value.to_string()),
            payload,
        ))
        .expect("canonical envelope")
    }

    fn payload_enum_for_message(
        message_type: TradeListingMessageType,
        order_id: &str,
        listing_addr: &str,
        buyer_pub: &str,
        seller_pub: &str,
    ) -> TradeListingMessagePayload {
        match message_type {
            TradeListingMessageType::ListingValidateRequest => {
                TradeListingMessagePayload::ListingValidateRequest(TradeListingValidateRequest {
                    listing_event: Some(RadrootsNostrEventPtr {
                        id: TEST_LISTING_EVENT_ID.to_string(),
                        relays: None,
                    }),
                })
            }
            TradeListingMessageType::ListingValidateResult => {
                TradeListingMessagePayload::ListingValidateResult(TradeListingValidateResult {
                    valid: true,
                    errors: Vec::new(),
                })
            }
            TradeListingMessageType::OrderRequest => {
                TradeListingMessagePayload::OrderRequest(make_order(
                    order_id,
                    listing_addr,
                    buyer_pub,
                    seller_pub,
                    TradeOrderStatus::Requested,
                ))
            }
            TradeListingMessageType::OrderResponse => {
                TradeListingMessagePayload::OrderResponse(TradeOrderResponse {
                    accepted: true,
                    reason: None,
                })
            }
            TradeListingMessageType::OrderRevision => {
                TradeListingMessagePayload::OrderRevision(TradeOrderRevision {
                    revision_id: "r-matrix".to_string(),
                    changes: Vec::new(),
                })
            }
            TradeListingMessageType::OrderRevisionAccept => {
                TradeListingMessagePayload::OrderRevisionAccept(TradeOrderRevisionResponse {
                    accepted: true,
                    reason: None,
                })
            }
            TradeListingMessageType::OrderRevisionDecline => {
                TradeListingMessagePayload::OrderRevisionDecline(TradeOrderRevisionResponse {
                    accepted: false,
                    reason: None,
                })
            }
            TradeListingMessageType::Question => {
                TradeListingMessagePayload::Question(TradeQuestion {
                    question_id: "q-matrix".to_string(),
                })
            }
            TradeListingMessageType::Answer => TradeListingMessagePayload::Answer(TradeAnswer {
                question_id: "q-matrix".to_string(),
            }),
            TradeListingMessageType::DiscountRequest => {
                TradeListingMessagePayload::DiscountRequest(TradeDiscountRequest {
                    discount_id: "d-matrix".to_string(),
                    value: sample_discount_value(),
                })
            }
            TradeListingMessageType::DiscountOffer => {
                TradeListingMessagePayload::DiscountOffer(TradeDiscountOffer {
                    discount_id: "d-matrix".to_string(),
                    value: sample_discount_value(),
                })
            }
            TradeListingMessageType::DiscountAccept => {
                TradeListingMessagePayload::DiscountAccept(TradeDiscountDecision::Accept {
                    value: sample_discount_value(),
                })
            }
            TradeListingMessageType::DiscountDecline => {
                TradeListingMessagePayload::DiscountDecline(TradeDiscountDecision::Decline {
                    reason: None,
                })
            }
            TradeListingMessageType::Cancel => {
                TradeListingMessagePayload::Cancel(TradeListingCancel { reason: None })
            }
            TradeListingMessageType::FulfillmentUpdate => {
                TradeListingMessagePayload::FulfillmentUpdate(TradeFulfillmentUpdate {
                    status: TradeFulfillmentStatus::Shipped,
                })
            }
            TradeListingMessageType::Receipt => TradeListingMessagePayload::Receipt(TradeReceipt {
                acknowledged: true,
                at: 1,
            }),
        }
    }

    fn recipient_for_message<'a>(
        message_type: TradeListingMessageType,
        buyer_pub: &'a str,
        seller_pub: &'a str,
    ) -> &'a str {
        match message_type {
            TradeListingMessageType::OrderResponse
            | TradeListingMessageType::OrderRevision
            | TradeListingMessageType::Answer
            | TradeListingMessageType::DiscountOffer
            | TradeListingMessageType::FulfillmentUpdate => buyer_pub,
            _ => seller_pub,
        }
    }

    async fn workflow_state_refs(
        message_type: TradeListingMessageType,
        listing_addr: &str,
        order_id: &str,
        state: &Arc<AsyncMutex<TradeListingState>>,
    ) -> (Option<String>, Option<String>, Option<String>) {
        let mut locked = state.lock().await;
        let listing_event_id = if message_type.requires_listing_snapshot() {
            Some(
                locked
                    .listing_event_id(listing_addr)
                    .unwrap_or(TEST_LISTING_EVENT_ID)
                    .to_string(),
            )
        } else {
            None
        };
        let (root_event_id, prev_event_id) = if message_type.requires_trade_chain() {
            if let Some(order) = locked.get_order_mut(order_id) {
                (order.root_event_id.clone(), order.last_event_id.clone())
            } else {
                (
                    Some(format!("{order_id}:root")),
                    Some(format!("{order_id}:prev")),
                )
            }
        } else {
            (None, None)
        };
        (listing_event_id, root_event_id, prev_event_id)
    }

    async fn make_public_trade_event(
        sender: &RadrootsNostrKeys,
        message_type: TradeListingMessageType,
        listing_addr: &str,
        order_id: &str,
        buyer_pub: &str,
        seller_pub: &str,
        state: Option<&Arc<AsyncMutex<TradeListingState>>>,
    ) -> RadrootsNostrEvent {
        let (listing_event_id, root_event_id, prev_event_id) = if let Some(state) = state {
            workflow_state_refs(message_type, listing_addr, order_id, state).await
        } else {
            let listing_event_id = message_type
                .requires_listing_snapshot()
                .then(|| TEST_LISTING_EVENT_ID.to_string());
            (listing_event_id, None, None)
        };

        let payload =
            payload_enum_for_message(message_type, order_id, listing_addr, buyer_pub, seller_pub);
        make_public_trade_event_with_payload(
            sender,
            message_type,
            listing_addr,
            order_id,
            buyer_pub,
            seller_pub,
            payload,
            listing_event_id,
            root_event_id,
            prev_event_id,
        )
    }

    fn make_public_trade_event_with_payload(
        sender: &RadrootsNostrKeys,
        message_type: TradeListingMessageType,
        listing_addr: &str,
        order_id: &str,
        buyer_pub: &str,
        seller_pub: &str,
        payload: TradeListingMessagePayload,
        listing_event_id: Option<String>,
        root_event_id: Option<String>,
        prev_event_id: Option<String>,
    ) -> RadrootsNostrEvent {
        let recipient = recipient_for_message(message_type, buyer_pub, seller_pub);
        make_trade_event_with_payload_and_recipient(
            sender,
            recipient,
            message_type,
            listing_addr,
            order_id,
            payload,
            listing_event_id,
            root_event_id,
            prev_event_id,
        )
    }

    fn make_trade_event_with_payload_and_recipient(
        sender: &RadrootsNostrKeys,
        recipient: &str,
        message_type: TradeListingMessageType,
        listing_addr: &str,
        order_id: &str,
        payload: TradeListingMessagePayload,
        listing_event_id: Option<String>,
        root_event_id: Option<String>,
        prev_event_id: Option<String>,
    ) -> RadrootsNostrEvent {
        let listing_event = listing_event_id.map(|id| RadrootsNostrEventPtr { id, relays: None });
        let envelope_event = super::trade_listing_envelope_event_build(
            recipient.to_string(),
            message_type,
            listing_addr.to_string(),
            Some(order_id.to_string()),
            listing_event.as_ref(),
            root_event_id.as_deref(),
            prev_event_id.as_deref(),
            &payload,
        )
        .expect("build trade event");
        let builder = radroots_nostr::prelude::radroots_nostr_build_event(
            envelope_event.kind,
            envelope_event.content,
            envelope_event.tags,
        )
        .expect("event builder");
        builder.sign_with_keys(sender).expect("event")
    }

    async fn make_handle_event_trade_event(
        sender: &RadrootsNostrKeys,
        message_type: TradeListingMessageType,
        listing_addr: &str,
        order_id: &str,
        buyer_pub: &str,
        seller_pub: &str,
        state: Option<&Arc<AsyncMutex<TradeListingState>>>,
    ) -> (RadrootsNostrEvent, Vec<RadrootsNostrTag>) {
        let (listing_event_id, root_event_id, prev_event_id) = if let Some(state) = state {
            workflow_state_refs(message_type, listing_addr, order_id, state).await
        } else {
            let listing_event_id = message_type
                .requires_listing_snapshot()
                .then(|| TEST_LISTING_EVENT_ID.to_string());
            (listing_event_id, None, None)
        };
        let event = make_public_trade_event_with_payload(
            sender,
            message_type,
            listing_addr,
            order_id,
            buyer_pub,
            seller_pub,
            payload_enum_for_message(message_type, order_id, listing_addr, buyer_pub, seller_pub),
            listing_event_id,
            root_event_id,
            prev_event_id,
        );
        let tags = event.tags.iter().cloned().collect();
        (event, tags)
    }

    fn sample_discount_value() -> RadrootsCoreDiscountValue {
        RadrootsCoreDiscountValue::MoneyPerBin(RadrootsCoreMoney::from_minor_units_u32(
            100,
            RadrootsCoreCurrency::USD,
        ))
    }

    fn sender_for_message<'a>(
        message_type: TradeListingMessageType,
        seller_keys: &'a RadrootsNostrKeys,
        buyer_keys: &'a RadrootsNostrKeys,
    ) -> &'a RadrootsNostrKeys {
        match message_type {
            TradeListingMessageType::OrderResponse
            | TradeListingMessageType::OrderRevision
            | TradeListingMessageType::Answer
            | TradeListingMessageType::DiscountOffer
            | TradeListingMessageType::FulfillmentUpdate => seller_keys,
            _ => buyer_keys,
        }
    }

    #[test]
    fn transition_matrix_and_tag_helpers_are_covered() {
        let _guard = test_guard();

        assert!(ensure_transition(TradeOrderStatus::Requested, TradeOrderStatus::Revised).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Declined, TradeOrderStatus::Accepted).is_err());
        assert!(
            ensure_transition(TradeOrderStatus::Fulfilled, TradeOrderStatus::Completed).is_ok()
        );
        assert!(
            ensure_transition(TradeOrderStatus::Completed, TradeOrderStatus::Requested).is_err()
        );
        assert!(ensure_transition(TradeOrderStatus::Draft, TradeOrderStatus::Draft).is_ok());
        assert_eq!(
            next_status_for_fulfillment_update(
                &TradeOrderStatus::Accepted,
                &TradeFulfillmentStatus::Shipped
            )
            .expect("shipped keeps accepted"),
            None
        );
        assert_eq!(
            next_status_for_fulfillment_update(
                &TradeOrderStatus::Accepted,
                &TradeFulfillmentStatus::Delivered
            )
            .expect("delivered fulfills"),
            Some(TradeOrderStatus::Fulfilled)
        );
        assert_eq!(
            next_status_for_fulfillment_update(
                &TradeOrderStatus::Accepted,
                &TradeFulfillmentStatus::Cancelled
            )
            .expect("cancelled cancels"),
            Some(TradeOrderStatus::Cancelled)
        );
        assert!(
            next_status_for_fulfillment_update(
                &TradeOrderStatus::Requested,
                &TradeFulfillmentStatus::Shipped
            )
            .is_err()
        );
        assert_eq!(
            next_status_for_receipt(&TradeOrderStatus::Fulfilled, false)
                .expect("unacknowledged receipt keeps fulfilled"),
            None
        );
        assert_eq!(
            next_status_for_receipt(&TradeOrderStatus::Fulfilled, true)
                .expect("acknowledged receipt completes"),
            Some(TradeOrderStatus::Completed)
        );
        assert!(next_status_for_receipt(&TradeOrderStatus::Requested, false).is_err());

        let tags = vec![
            vec!["p".to_string(), "pk".to_string()],
            vec!["a".to_string(), "addr".to_string()],
        ];
        assert_eq!(tag_value(&tags, "a"), Some("addr".to_string()));
        assert_eq!(tag_value(&tags, "x"), None);
        assert!(tag_has_value(&tags, "p", "pk"));
        assert!(!tag_has_value(&tags, "p", "miss"));

        let parsed: Result<TradeOrderResponse, _> =
            parse_payload(json!({"accepted":true,"reason":null}));
        assert!(parsed.is_ok());
        let invalid: Result<TradeOrderResponse, _> = parse_payload(json!({"accepted":"true"}));
        assert!(invalid.is_err());
    }

    #[test]
    fn transition_matrix_covers_all_from_arms() {
        let _guard = test_guard();

        assert!(ensure_transition(TradeOrderStatus::Draft, TradeOrderStatus::Requested).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Draft, TradeOrderStatus::Accepted).is_err());

        assert!(
            ensure_transition(TradeOrderStatus::Validated, TradeOrderStatus::Requested).is_ok()
        );
        assert!(
            ensure_transition(TradeOrderStatus::Validated, TradeOrderStatus::Accepted).is_err()
        );

        assert!(ensure_transition(TradeOrderStatus::Requested, TradeOrderStatus::Accepted).is_ok());
        assert!(
            ensure_transition(TradeOrderStatus::Requested, TradeOrderStatus::Fulfilled).is_err()
        );

        assert!(
            ensure_transition(TradeOrderStatus::Questioned, TradeOrderStatus::Requested).is_ok()
        );
        assert!(
            ensure_transition(TradeOrderStatus::Questioned, TradeOrderStatus::Accepted).is_err()
        );

        assert!(ensure_transition(TradeOrderStatus::Revised, TradeOrderStatus::Declined).is_ok());
        assert!(ensure_transition(TradeOrderStatus::Revised, TradeOrderStatus::Fulfilled).is_err());

        assert!(ensure_transition(TradeOrderStatus::Accepted, TradeOrderStatus::Fulfilled).is_ok());
        assert!(
            ensure_transition(TradeOrderStatus::Accepted, TradeOrderStatus::Requested).is_err()
        );

        assert!(ensure_transition(TradeOrderStatus::Declined, TradeOrderStatus::Accepted).is_err());
        assert!(
            ensure_transition(TradeOrderStatus::Cancelled, TradeOrderStatus::Requested).is_err()
        );

        assert!(
            ensure_transition(TradeOrderStatus::Fulfilled, TradeOrderStatus::Completed).is_ok()
        );
        assert!(
            ensure_transition(TradeOrderStatus::Fulfilled, TradeOrderStatus::Accepted).is_err()
        );

        assert!(
            ensure_transition(TradeOrderStatus::Completed, TradeOrderStatus::Cancelled).is_err()
        );
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
        let fetched = fetch_events_io(
            &client,
            RadrootsNostrFilter::new(),
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("fetch hook");
        assert_eq!(fetched.len(), 1);

        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(event.clone()));
        let by_id = super::fetch_event_by_id_io(&client, "id")
            .await
            .expect("by id");
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
        push_validate_listing_ok(listing_addr.clone(), farm.clone());
        let validated = validate_listing_event_io(&event).expect("validate hook");
        assert_eq!(validated.0, listing_addr);
        assert_eq!(validated.1.pubkey, farm.pubkey);
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
        let ok = validate_farm_dependencies(&client, &farm)
            .await
            .expect("ok deps");
        assert!(ok.is_empty());
    }

    #[tokio::test]
    async fn handle_listing_validate_request_paths_are_covered() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, buyer_keys) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let state = Arc::new(AsyncMutex::new(TradeListingState::default()));
        let missing_event = make_event(
            &seller_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            "missing".to_string(),
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
        assert!(
            handle_listing_validate_request(
                &missing_event,
                payload,
                &listing_addr,
                &client,
                &state
            )
            .await
            .is_ok()
        );

        let fetch_error_event = make_event(
            &seller_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            "fetch-error".to_string(),
            Vec::new(),
        );
        push_fetch_events_ok(Vec::new());
        push_send_ok();
        let payload = TradeListingValidateRequest {
            listing_event: None,
        };
        assert!(
            handle_listing_validate_request(
                &fetch_error_event,
                payload,
                &listing_addr,
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        let success_event = make_event(
            &seller_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            "success".to_string(),
            Vec::new(),
        );
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(success_event.clone()));
        push_validate_listing_ok(
            listing_addr.clone(),
            RadrootsListingFarmRef {
                pubkey: seller_keys.public_key().to_hex(),
                d_tag: "farmtag".to_string(),
            },
        );
        push_farm_validation_result(Ok(Vec::new()));
        push_send_ok();
        let payload = TradeListingValidateRequest {
            listing_event: Some(RadrootsNostrEventPtr {
                id: success_event.id.to_hex(),
                relays: None,
            }),
        };
        assert!(
            handle_listing_validate_request(
                &success_event,
                payload,
                &listing_addr,
                &client,
                &state
            )
            .await
            .is_ok()
        );
        assert!(state.lock().await.is_listing_validated(&listing_addr));
        assert_eq!(
            state.lock().await.validated_listing_event_id(&listing_addr),
            Some(success_event.id.to_string().as_str())
        );

        let other_listing_addr = listing_addr_for_seller(&rhi_keys);
        let mismatch_event = make_event(
            &seller_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            "mismatch".to_string(),
            Vec::new(),
        );
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(mismatch_event.clone()));
        push_validate_listing_ok(
            other_listing_addr,
            RadrootsListingFarmRef {
                pubkey: seller_keys.public_key().to_hex(),
                d_tag: "farmtag".to_string(),
            },
        );
        push_send_ok();
        let payload = TradeListingValidateRequest {
            listing_event: Some(RadrootsNostrEventPtr {
                id: mismatch_event.id.to_hex(),
                relays: None,
            }),
        };
        let mismatch_listing_addr = listing_addr_for_seller(&buyer_keys);
        assert!(
            handle_listing_validate_request(
                &mismatch_event,
                payload,
                &mismatch_listing_addr,
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert!(
            !state
                .lock()
                .await
                .is_listing_validated(&mismatch_listing_addr)
        );

        state
            .lock()
            .await
            .mark_listing_validated(&listing_addr, "stale-listing-event");
        let stale_event = make_event(
            &seller_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            "stale".to_string(),
            Vec::new(),
        );
        push_fetch_events_ok(Vec::new());
        push_send_ok();
        let payload = TradeListingValidateRequest {
            listing_event: None,
        };
        assert!(
            handle_listing_validate_request(&stale_event, payload, &listing_addr, &client, &state)
                .await
                .is_ok()
        );
        assert!(!state.lock().await.is_listing_validated(&listing_addr));
    }

    #[tokio::test]
    async fn handle_listing_validate_request_dedupes_replayed_request_event() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, _) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let state = Arc::new(AsyncMutex::new(TradeListingState::default()));
        let event = make_event(
            &seller_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            "content".to_string(),
            Vec::new(),
        );
        let payload = TradeListingValidateRequest {
            listing_event: Some(RadrootsNostrEventPtr {
                id: event.id.to_hex(),
                relays: None,
            }),
        };

        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(event.clone()));
        push_validate_listing_ok(
            listing_addr.clone(),
            RadrootsListingFarmRef {
                pubkey: seller_keys.public_key().to_hex(),
                d_tag: "farmtag".to_string(),
            },
        );
        push_farm_validation_result(Ok(Vec::new()));
        push_send_ok();
        assert!(
            handle_listing_validate_request(
                &event,
                payload.clone(),
                &listing_addr,
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert!(
            state
                .lock()
                .await
                .is_non_order_event_seen(&event.id.to_string())
        );

        assert!(
            handle_listing_validate_request(&event, payload, &listing_addr, &client, &state)
                .await
                .is_ok()
        );
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
        state
            .lock()
            .await
            .upsert_listing_event(&listing_addr, TEST_LISTING_EVENT_ID, 30402);

        let order_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::OrderRequest,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        let order_payload = make_order(
            order_id,
            &listing_addr,
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        assert!(
            handle_order_request(
                &order_event,
                order_payload,
                &listing_addr_parsed,
                Some(order_id),
                &client,
                &state
            )
            .await
            .is_ok()
        );

        let response_event = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::OrderResponse,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_order_response(
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
            .is_ok()
        );

        state
            .lock()
            .await
            .get_order_mut(order_id)
            .expect("order")
            .status = TradeOrderStatus::Requested;
        let revision_event = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::OrderRevision,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_order_revision(
                &revision_event,
                TradeOrderRevision {
                    revision_id: "r1".to_string(),
                    changes: Vec::new(),
                },
                &listing_addr_parsed,
                Some(order_id),
                &client,
                &state
            )
            .await
            .is_ok()
        );

        let revision_response_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::OrderRevisionAccept,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_order_revision_response(
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
            .is_ok()
        );

        state
            .lock()
            .await
            .get_order_mut(order_id)
            .expect("order")
            .status = TradeOrderStatus::Requested;
        let question_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::Question,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_question(
                &question_event,
                TradeQuestion {
                    question_id: "q1".to_string(),
                },
                &listing_addr_parsed,
                Some(order_id),
                &client,
                &state
            )
            .await
            .is_ok()
        );

        let answer_event = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::Answer,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_answer(
                &answer_event,
                TradeAnswer {
                    question_id: "q1".to_string(),
                },
                &listing_addr_parsed,
                Some(order_id),
                &client,
                &state
            )
            .await
            .is_ok()
        );

        let discount_request_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::DiscountRequest,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_discount_request(
                &discount_request_event,
                TradeDiscountRequest {
                    discount_id: "d1".to_string(),
                    value: sample_discount_value(),
                },
                &listing_addr_parsed,
                Some(order_id),
                &client,
                &state
            )
            .await
            .is_ok()
        );

        let discount_offer_event = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::DiscountOffer,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_discount_offer(
                &discount_offer_event,
                TradeDiscountOffer {
                    discount_id: "d1".to_string(),
                    value: sample_discount_value(),
                },
                &listing_addr_parsed,
                Some(order_id),
                &client,
                &state
            )
            .await
            .is_ok()
        );

        let discount_accept_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::DiscountAccept,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_discount_decision(
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
            .is_ok()
        );

        state
            .lock()
            .await
            .get_order_mut(order_id)
            .expect("order")
            .status = TradeOrderStatus::Requested;
        let cancel_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::Cancel,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_cancel(
                &cancel_event,
                TradeListingCancel { reason: None },
                &listing_addr_parsed,
                Some(order_id),
                &client,
                &state
            )
            .await
            .is_ok()
        );

        state
            .lock()
            .await
            .get_order_mut(order_id)
            .expect("order")
            .status = TradeOrderStatus::Accepted;
        let fulfill_event = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::FulfillmentUpdate,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_fulfillment_update(
                &fulfill_event,
                TradeFulfillmentUpdate {
                    status: TradeFulfillmentStatus::Delivered,
                },
                &listing_addr_parsed,
                Some(order_id),
                &client,
                &state
            )
            .await
            .is_ok()
        );

        let receipt_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::Receipt,
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_receipt(
                &receipt_event,
                TradeReceipt {
                    acknowledged: true,
                    at: 1,
                },
                &listing_addr_parsed,
                Some(order_id),
                &client,
                &state
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn handle_event_covers_guard_and_dispatch_paths() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, buyer_keys) = make_keys();
        let client = make_client(&rhi_keys);
        let rhi_pub = rhi_keys.public_key().to_hex();
        let buyer_pub = buyer_keys.public_key().to_hex();
        let seller_pub = seller_keys.public_key().to_hex();
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let order_id = "order-1";
        let tags = make_custom_tags(&rhi_pub, &listing_addr, Some(order_id));
        let state = state_with_order(
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
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
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            make_canonical_envelope_content(
                TradeListingMessageType::ListingValidateRequest,
                &listing_addr,
                None,
                TradeListingMessagePayload::ListingValidateRequest(TradeListingValidateRequest {
                    listing_event: None,
                }),
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
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
            make_envelope_content(
                TradeListingMessageType::OrderRequest,
                &listing_addr,
                Some(order_id),
                json!({}),
            ),
            tags.clone(),
        );
        assert!(
            handle_event(
                self_event,
                tags.clone(),
                rhi_keys.clone(),
                client.clone(),
                state.clone(),
            )
            .await
            .is_ok()
        );

        let kind_mismatch = make_event(
            &buyer_keys,
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
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
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
            make_canonical_envelope_content(
                TradeListingMessageType::OrderRequest,
                "30402:deadbeef:AAAAAAAAAAAAAAAAAAAAAA",
                Some(order_id),
                payload_enum_for_message(
                    TradeListingMessageType::OrderRequest,
                    order_id,
                    "30402:deadbeef:AAAAAAAAAAAAAAAAAAAAAA",
                    &buyer_pub,
                    &seller_pub,
                ),
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
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
            make_canonical_envelope_content(
                TradeListingMessageType::OrderRequest,
                &listing_addr,
                Some(order_id),
                payload_enum_for_message(
                    TradeListingMessageType::OrderRequest,
                    order_id,
                    &listing_addr,
                    &buyer_pub,
                    &seller_pub,
                ),
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

        let bad_addr = format!(
            "30404:{}:AAAAAAAAAAAAAAAAAAAAAA",
            seller_keys.public_key().to_hex()
        );
        let bad_addr_tags = make_workflow_tags(
            &rhi_pub,
            &bad_addr,
            Some(order_id),
            Some(TEST_LISTING_EVENT_ID),
            None,
            None,
        );
        let bad_addr_event = make_event(
            &buyer_keys,
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
            make_canonical_envelope_content(
                TradeListingMessageType::OrderRequest,
                &bad_addr,
                Some(order_id),
                payload_enum_for_message(
                    TradeListingMessageType::OrderRequest,
                    order_id,
                    &bad_addr,
                    &buyer_pub,
                    &seller_pub,
                ),
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
            (
                TradeListingMessageType::ListingValidateRequest,
                KIND_TRADE_LISTING_VALIDATE_REQ,
            ),
            (
                TradeListingMessageType::OrderRequest,
                KIND_TRADE_LISTING_ORDER_REQ,
            ),
            (
                TradeListingMessageType::OrderResponse,
                KIND_TRADE_LISTING_ORDER_RES,
            ),
            (
                TradeListingMessageType::OrderRevision,
                KIND_TRADE_LISTING_ORDER_REVISION_REQ,
            ),
            (
                TradeListingMessageType::OrderRevisionAccept,
                KIND_TRADE_LISTING_ORDER_REVISION_RES,
            ),
            (
                TradeListingMessageType::OrderRevisionDecline,
                KIND_TRADE_LISTING_ORDER_REVISION_RES,
            ),
            (
                TradeListingMessageType::Question,
                KIND_TRADE_LISTING_QUESTION_REQ,
            ),
            (
                TradeListingMessageType::Answer,
                KIND_TRADE_LISTING_ANSWER_RES,
            ),
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
            (
                TradeListingMessageType::Cancel,
                KIND_TRADE_LISTING_CANCEL_REQ,
            ),
            (
                TradeListingMessageType::FulfillmentUpdate,
                KIND_TRADE_LISTING_FULFILLMENT_UPDATE_REQ,
            ),
            (
                TradeListingMessageType::Receipt,
                KIND_TRADE_LISTING_RECEIPT_REQ,
            ),
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
                state
                    .lock()
                    .await
                    .get_order_mut(order_id)
                    .expect("order")
                    .status = TradeOrderStatus::Requested;
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
            let event = make_event(&buyer_keys, custom_trade_kind(kind), content, tags.clone());
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
        assert!(
            send_envelope(
                &client,
                seller_keys.public_key().to_hex(),
                TradeListingMessageType::ListingValidateResult,
                &listing_addr_for_seller(&seller_keys),
                None,
                &TradeListingMessagePayload::ListingValidateResult(TradeListingValidateResult {
                    valid: true,
                    errors: Vec::new(),
                }),
            )
            .await
            .is_ok()
        );

        let event = make_event(
            &seller_keys,
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
            "x".to_string(),
            Vec::new(),
        );
        push_send_ok();
        assert!(
            handle_error(TradeListingDvmError::UnsupportedKind, &event, &client)
                .await
                .is_ok()
        );
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
            custom_trade_kind(listing_kind),
            "listing".to_string(),
            Vec::new(),
        );
        push_fetch_events_ok(vec![
            wrong_kind.clone(),
            listing_event.clone(),
            listing_event.clone(),
        ]);
        let fetched_listing = fetch_listing_by_addr(&client, &listing_addr)
            .await
            .expect("listing fetch");
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
        assert!(
            fetch_events_io(
                &client,
                RadrootsNostrFilter::new(),
                std::time::Duration::from_millis(1)
            )
            .await
            .is_err()
        );
        let builder = radroots_nostr::prelude::radroots_nostr_build_event(
            KIND_TRADE_LISTING_ORDER_REQ as u32,
            "x",
            vec![vec!["a".to_string(), listing_addr_for_seller(&seller_keys)]],
        )
        .expect("builder");
        assert!(send_event_io(&client, builder).await.is_err());
        let event = make_event(
            &seller_keys,
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
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
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
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

        let cases: Vec<(
            TradeListingMessageType,
            u32,
            serde_json::Value,
            TradeOrderStatus,
        )> = vec![
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
                    changes: Vec::new(),
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
                })
                .expect("question"),
                TradeOrderStatus::Requested,
            ),
            (
                TradeListingMessageType::Answer,
                KIND_TRADE_LISTING_ANSWER_RES,
                serde_json::to_value(TradeAnswer {
                    question_id: "qx".to_string(),
                })
                .expect("answer"),
                TradeOrderStatus::Questioned,
            ),
            (
                TradeListingMessageType::DiscountRequest,
                KIND_TRADE_LISTING_DISCOUNT_REQ,
                serde_json::to_value(TradeDiscountRequest {
                    discount_id: "d2".to_string(),
                    value: sample_discount_value(),
                })
                .expect("discount request"),
                TradeOrderStatus::Requested,
            ),
            (
                TradeListingMessageType::DiscountOffer,
                KIND_TRADE_LISTING_DISCOUNT_OFFER_RES,
                serde_json::to_value(TradeDiscountOffer {
                    discount_id: "d2".to_string(),
                    value: sample_discount_value(),
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
            let content =
                make_envelope_content(message_type, &listing_addr, Some(order_id), payload);
            let tags = make_custom_tags(&rhi_pub, &listing_addr, Some(order_id));
            let event = make_event(sender, custom_trade_kind(kind), content, tags.clone());
            let _ =
                handle_event(event, tags, rhi_keys.clone(), client.clone(), state.clone()).await;
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

        let bad_order = make_order(
            "bad",
            &listing_addr,
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        let event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::OrderRequest,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(matches!(
            handle_order_request(&event, bad_order, &parsed, Some("order-1"), &client, &state)
                .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        let missing_state = Arc::new(AsyncMutex::new(TradeListingState::default()));
        let order = make_order(
            "order-2",
            &listing_addr,
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        let fetched_snapshot_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(30402),
            "listing-fetch".to_string(),
            Vec::new(),
        );
        let fetched_snapshot_id = fetched_snapshot_event.id.to_string();
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(fetched_snapshot_event));
        push_validate_listing_ok(
            listing_addr.clone(),
            RadrootsListingFarmRef {
                pubkey: seller_pub.clone(),
                d_tag: "farmtag".to_string(),
            },
        );
        let fetched_order_event = make_public_trade_event_with_payload(
            &buyer_keys,
            TradeListingMessageType::OrderRequest,
            &listing_addr,
            "order-2",
            &buyer_pub,
            &seller_pub,
            TradeListingMessagePayload::OrderRequest(make_order(
                "order-2",
                &listing_addr,
                &buyer_pub,
                &seller_pub,
                TradeOrderStatus::Requested,
            )),
            Some(fetched_snapshot_id),
            None,
            None,
        );
        assert!(
            handle_order_request(
                &fetched_order_event,
                order,
                &parsed,
                Some("order-2"),
                &client,
                &missing_state
            )
            .await
            .is_ok()
        );
        assert!(missing_state.lock().await.order_exists("order-2"));

        let mismatched_snapshot_state = Arc::new(AsyncMutex::new(TradeListingState::default()));
        let mismatched_snapshot_event = make_event(
            &seller_keys,
            RadrootsNostrKind::Custom(30402),
            "listing-mismatch".to_string(),
            Vec::new(),
        );
        let mismatched_snapshot_id = mismatched_snapshot_event.id.to_string();
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(mismatched_snapshot_event));
        push_validate_listing_ok(
            listing_addr_for_seller(&buyer_keys),
            RadrootsListingFarmRef {
                pubkey: buyer_pub.clone(),
                d_tag: "farmtag".to_string(),
            },
        );
        let mismatched_snapshot_order = make_order(
            "order-3",
            &listing_addr,
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        let mismatched_snapshot_event = make_public_trade_event_with_payload(
            &buyer_keys,
            TradeListingMessageType::OrderRequest,
            &listing_addr,
            "order-3",
            &buyer_pub,
            &seller_pub,
            TradeListingMessagePayload::OrderRequest(make_order(
                "order-3",
                &listing_addr,
                &buyer_pub,
                &seller_pub,
                TradeOrderStatus::Requested,
            )),
            Some(mismatched_snapshot_id),
            None,
            None,
        );
        assert!(matches!(
            handle_order_request(
                &mismatched_snapshot_event,
                mismatched_snapshot_order,
                &parsed,
                Some("order-3"),
                &client,
                &mismatched_snapshot_state
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let seller_event = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::OrderResponse,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        state
            .lock()
            .await
            .get_order_mut("order-1")
            .expect("order")
            .seen_event_ids
            .insert(seller_event.id.to_string());
        assert!(
            handle_order_response(
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
            .is_ok()
        );

        let wrong_buyer = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::OrderRevisionAccept,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
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
        let wrong_sender = make_public_trade_event(
            &rhi_keys,
            TradeListingMessageType::Cancel,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
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
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            "x".to_string(),
            Vec::new(),
        );
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        push_send_ok();
        assert!(
            handle_listing_validate_request(
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
            .is_ok()
        );

        push_send_ok();
        assert!(
            handle_listing_validate_request(
                &validate_event,
                TradeListingValidateRequest {
                    listing_event: None
                },
                "not-a-listing-addr",
                &client,
                &state,
            )
            .await
            .is_ok()
        );

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
        assert!(
            handle_listing_validate_request(
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
            .is_ok()
        );

        let duplicate_order = make_order(
            "order-1",
            &listing_addr,
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        let duplicate_order_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::OrderRequest,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(
            handle_order_request(
                &duplicate_order_event,
                duplicate_order,
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        let unauthorized_order = make_order(
            "order-3",
            &listing_addr,
            "different-buyer",
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        let unauthorized_order_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::OrderRequest,
            &listing_addr,
            "order-3",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(matches!(
            handle_order_request(
                &unauthorized_order_event,
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
        assert!(
            handle_order_request(
                &event,
                duplicate_order,
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let buyer_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::OrderResponse,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
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
        assert!(
            handle_order_response(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::OrderResponse,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
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
            .is_ok()
        );

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        assert!(matches!(
            handle_order_revision(
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::OrderRevision,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeOrderRevision {
                    revision_id: "r-wrong-sender".to_string(),
                    changes: Vec::new(),
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
        assert!(matches!(
            handle_order_revision(
                &make_public_trade_event_with_payload(
                    &seller_keys,
                    TradeListingMessageType::OrderRevision,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    payload_enum_for_message(
                        TradeListingMessageType::OrderRevision,
                        "order-1",
                        &listing_addr,
                        &buyer_pub,
                        &seller_pub,
                    ),
                    Some(TEST_LISTING_EVENT_ID.to_string()),
                    Some("wrong-root".to_string()),
                    Some("wrong-prev".to_string()),
                ),
                TradeOrderRevision {
                    revision_id: "r3".to_string(),
                    changes: Vec::new(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        let seen_event = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::OrderRevision,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        state
            .lock()
            .await
            .get_order_mut("order-1")
            .expect("order")
            .seen_event_ids
            .insert(seen_event.id.to_string());
        assert!(
            handle_order_revision(
                &seen_event,
                TradeOrderRevision {
                    revision_id: "r4".to_string(),
                    changes: Vec::new(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        assert!(matches!(
            handle_question(
                &make_public_trade_event_with_payload(
                    &buyer_keys,
                    TradeListingMessageType::Question,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    payload_enum_for_message(
                        TradeListingMessageType::Question,
                        "order-1",
                        &listing_addr,
                        &buyer_pub,
                        &seller_pub,
                    ),
                    None,
                    Some("wrong-root".to_string()),
                    Some("wrong-prev".to_string()),
                ),
                TradeQuestion {
                    question_id: "q".to_string(),
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
                &make_public_trade_event_with_payload(
                    &seller_keys,
                    TradeListingMessageType::Answer,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    payload_enum_for_message(
                        TradeListingMessageType::Answer,
                        "order-1",
                        &listing_addr,
                        &buyer_pub,
                        &seller_pub,
                    ),
                    None,
                    Some("wrong-root".to_string()),
                    Some("wrong-prev".to_string()),
                ),
                TradeAnswer {
                    question_id: "q".to_string(),
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
                &make_public_trade_event_with_payload(
                    &buyer_keys,
                    TradeListingMessageType::DiscountRequest,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    payload_enum_for_message(
                        TradeListingMessageType::DiscountRequest,
                        "order-1",
                        &listing_addr,
                        &buyer_pub,
                        &seller_pub,
                    ),
                    Some(TEST_LISTING_EVENT_ID.to_string()),
                    Some("wrong-root".to_string()),
                    Some("wrong-prev".to_string()),
                ),
                TradeDiscountRequest {
                    discount_id: "d".to_string(),
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

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        assert!(matches!(
            handle_discount_offer(
                &make_public_trade_event_with_payload(
                    &seller_keys,
                    TradeListingMessageType::DiscountOffer,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    payload_enum_for_message(
                        TradeListingMessageType::DiscountOffer,
                        "order-1",
                        &listing_addr,
                        &buyer_pub,
                        &seller_pub,
                    ),
                    Some(TEST_LISTING_EVENT_ID.to_string()),
                    Some("wrong-root".to_string()),
                    Some("wrong-prev".to_string()),
                ),
                TradeDiscountOffer {
                    discount_id: "d".to_string(),
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

        set_order_status(&state, "order-1", TradeOrderStatus::Revised).await;
        assert!(matches!(
            handle_discount_decision(
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::DiscountAccept,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
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
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::DiscountDecline,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
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
        assert!(
            handle_discount_decision(
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::DiscountDecline,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeListingMessageType::Cancel,
                TradeDiscountDecision::Decline { reason: None },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        let (cancel_root_event_id, cancel_prev_event_id) = {
            let mut locked = state.lock().await;
            let order = locked.get_order_mut("order-1").expect("order");
            (
                order.root_event_id.clone().expect("root event"),
                order.last_event_id.clone().expect("prev event"),
            )
        };
        let cancel_by_seller = make_trade_event_with_payload_and_recipient(
            &seller_keys,
            &buyer_pub,
            TradeListingMessageType::Cancel,
            &listing_addr,
            "order-1",
            payload_enum_for_message(
                TradeListingMessageType::Cancel,
                "order-1",
                &listing_addr,
                &buyer_pub,
                &seller_pub,
            ),
            None,
            Some(cancel_root_event_id),
            Some(cancel_prev_event_id),
        );
        push_send_ok();
        assert!(
            handle_cancel(
                &cancel_by_seller,
                TradeListingCancel { reason: None },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        set_order_status(&state, "order-1", TradeOrderStatus::Accepted).await;
        assert!(matches!(
            handle_fulfillment_update(
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::FulfillmentUpdate,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeFulfillmentUpdate {
                    status: TradeFulfillmentStatus::Shipped,
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
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::Receipt,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeReceipt {
                    acknowledged: true,
                    at: 1,
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
        let mismatched_parsed =
            TradeListingAddress::parse(&mismatched_addr).expect("mismatched listing");
        let revision_event = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::OrderRevision,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(matches!(
            handle_order_revision(
                &revision_event,
                TradeOrderRevision {
                    revision_id: "r1".to_string(),
                    changes: Vec::new(),
                },
                &mismatched_parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        let seen_revision_response = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::OrderRevisionAccept,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        mark_event_seen(&state, "order-1", seen_revision_response.id.to_string()).await;
        assert!(
            handle_order_revision_response(
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
            .is_ok()
        );

        let (listing_event_id, root_event_id, prev_event_id) = workflow_state_refs(
            TradeListingMessageType::OrderRevisionAccept,
            &listing_addr,
            "order-1",
            &state,
        )
        .await;
        assert!(matches!(
            handle_order_revision_response(
                &make_public_trade_event_with_payload(
                    &buyer_keys,
                    TradeListingMessageType::OrderRevisionAccept,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    TradeListingMessagePayload::OrderRevisionAccept(TradeOrderRevisionResponse {
                        accepted: false,
                        reason: None,
                    },),
                    listing_event_id,
                    root_event_id,
                    prev_event_id,
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
        let (listing_event_id, root_event_id, prev_event_id) = workflow_state_refs(
            TradeListingMessageType::OrderRevisionDecline,
            &listing_addr,
            "order-1",
            &state,
        )
        .await;
        assert!(matches!(
            handle_order_revision_response(
                &make_public_trade_event_with_payload(
                    &buyer_keys,
                    TradeListingMessageType::OrderRevisionDecline,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    TradeListingMessagePayload::OrderRevisionDecline(TradeOrderRevisionResponse {
                        accepted: true,
                        reason: None,
                    },),
                    listing_event_id,
                    root_event_id,
                    prev_event_id,
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
        assert!(
            handle_question(
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::Question,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeQuestion {
                    question_id: "q1".to_string(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        let seen_question = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::Question,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        mark_event_seen(&state, "order-1", seen_question.id.to_string()).await;
        assert!(
            handle_question(
                &seen_question,
                TradeQuestion {
                    question_id: "q2".to_string(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            handle_question(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::Question,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeQuestion {
                    question_id: "q3".to_string(),
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
        assert!(
            handle_answer(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::Answer,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeAnswer {
                    question_id: "q1".to_string(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        let seen_answer = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::Answer,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        mark_event_seen(&state, "order-1", seen_answer.id.to_string()).await;
        assert!(
            handle_answer(
                &seen_answer,
                TradeAnswer {
                    question_id: "q1".to_string(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            handle_answer(
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::Answer,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeAnswer {
                    question_id: "q1".to_string(),
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
        let seen_discount_request = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::DiscountRequest,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        mark_event_seen(&state, "order-1", seen_discount_request.id.to_string()).await;
        assert!(
            handle_discount_request(
                &seen_discount_request,
                TradeDiscountRequest {
                    discount_id: "d1".to_string(),
                    value: sample_discount_value(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            handle_discount_request(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::DiscountRequest,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeDiscountRequest {
                    discount_id: "d2".to_string(),
                    value: sample_discount_value(),
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
        let seen_discount_offer = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::DiscountOffer,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        mark_event_seen(&state, "order-1", seen_discount_offer.id.to_string()).await;
        assert!(
            handle_discount_offer(
                &seen_discount_offer,
                TradeDiscountOffer {
                    discount_id: "d1".to_string(),
                    value: sample_discount_value(),
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            handle_discount_offer(
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::DiscountOffer,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeDiscountOffer {
                    discount_id: "d2".to_string(),
                    value: sample_discount_value(),
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
        let seen_discount_decision = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::DiscountDecline,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        mark_event_seen(&state, "order-1", seen_discount_decision.id.to_string()).await;
        assert!(
            handle_discount_decision(
                &seen_discount_decision,
                TradeListingMessageType::DiscountDecline,
                TradeDiscountDecision::Decline { reason: None },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            handle_discount_decision(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::DiscountDecline,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
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
        let seen_cancel = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::Cancel,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        mark_event_seen(&state, "order-1", seen_cancel.id.to_string()).await;
        assert!(
            handle_cancel(
                &seen_cancel,
                TradeListingCancel { reason: None },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        set_order_status(&state, "order-1", TradeOrderStatus::Accepted).await;
        let seen_fulfillment = make_public_trade_event(
            &seller_keys,
            TradeListingMessageType::FulfillmentUpdate,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        mark_event_seen(&state, "order-1", seen_fulfillment.id.to_string()).await;
        assert!(
            handle_fulfillment_update(
                &seen_fulfillment,
                TradeFulfillmentUpdate {
                    status: TradeFulfillmentStatus::Shipped,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );

        set_order_status(&state, "order-1", TradeOrderStatus::Fulfilled).await;
        let seen_receipt = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::Receipt,
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        mark_event_seen(&state, "order-1", seen_receipt.id.to_string()).await;
        assert!(
            handle_receipt(
                &seen_receipt,
                TradeReceipt {
                    acknowledged: true,
                    at: 1,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn fulfillment_and_receipt_handlers_follow_projection_semantics() {
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
            TradeOrderStatus::Accepted,
        )
        .await;

        assert!(
            handle_fulfillment_update(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::FulfillmentUpdate,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeFulfillmentUpdate {
                    status: TradeFulfillmentStatus::Shipped,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert_eq!(
            state
                .lock()
                .await
                .get_order_mut("order-1")
                .expect("order")
                .status,
            TradeOrderStatus::Accepted
        );

        assert!(
            handle_fulfillment_update(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::FulfillmentUpdate,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeFulfillmentUpdate {
                    status: TradeFulfillmentStatus::Delivered,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert_eq!(
            state
                .lock()
                .await
                .get_order_mut("order-1")
                .expect("order")
                .status,
            TradeOrderStatus::Fulfilled
        );

        assert!(
            handle_receipt(
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::Receipt,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeReceipt {
                    acknowledged: false,
                    at: 1,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert_eq!(
            state
                .lock()
                .await
                .get_order_mut("order-1")
                .expect("order")
                .status,
            TradeOrderStatus::Fulfilled
        );

        assert!(
            handle_receipt(
                &make_public_trade_event(
                    &buyer_keys,
                    TradeListingMessageType::Receipt,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeReceipt {
                    acknowledged: true,
                    at: 2,
                },
                &parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await
            .is_ok()
        );
        assert_eq!(
            state
                .lock()
                .await
                .get_order_mut("order-1")
                .expect("order")
                .status,
            TradeOrderStatus::Completed
        );

        let cancelled_state = state_with_order(
            &listing_addr,
            "order-2",
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Accepted,
        )
        .await;
        assert!(
            handle_fulfillment_update(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::FulfillmentUpdate,
                    &listing_addr,
                    "order-2",
                    &buyer_pub,
                    &seller_pub,
                    Some(&cancelled_state),
                )
                .await,
                TradeFulfillmentUpdate {
                    status: TradeFulfillmentStatus::Cancelled,
                },
                &parsed,
                Some("order-2"),
                &client,
                &cancelled_state,
            )
            .await
            .is_ok()
        );
        assert_eq!(
            cancelled_state
                .lock()
                .await
                .get_order_mut("order-2")
                .expect("order")
                .status,
            TradeOrderStatus::Cancelled
        );
    }

    #[tokio::test]
    async fn dvm_remaining_edges_are_covered() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, buyer_keys) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let parsed = TradeListingAddress::parse(&listing_addr).expect("listing");
        let buyer_pub = buyer_keys.public_key().to_hex();
        let seller_pub = seller_keys.public_key().to_hex();

        let state_validate = Arc::new(AsyncMutex::new(TradeListingState::default()));
        let validate_event = make_event(
            &seller_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            "content".to_string(),
            Vec::new(),
        );
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(validate_event.clone()));
        push_validate_listing_ok(
            listing_addr.clone(),
            RadrootsListingFarmRef {
                pubkey: seller_keys.public_key().to_hex(),
                d_tag: "farmtag".to_string(),
            },
        );
        push_farm_validation_result(Ok(vec![TradeListingValidationError::MissingFarmRecord]));
        push_send_ok();
        assert!(
            handle_listing_validate_request(
                &validate_event,
                TradeListingValidateRequest {
                    listing_event: Some(RadrootsNostrEventPtr {
                        id: "x".to_string(),
                        relays: None,
                    }),
                },
                &listing_addr,
                &client,
                &state_validate,
            )
            .await
            .is_ok()
        );

        let state = state_with_order(
            &listing_addr,
            "order-1",
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        )
        .await;
        let order_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::OrderRequest,
            &listing_addr,
            "order-2",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;

        let mismatch_payload = make_order(
            "order-2",
            "30402:deadbeef:AAAAAAAAAAAAAAAAAAAAAA",
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        );
        assert!(matches!(
            handle_order_request(
                &order_event,
                mismatch_payload,
                &parsed,
                Some("order-2"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::InvalidOrder)
        ));

        let unauthorized_payload = make_order(
            "order-3",
            &listing_addr,
            &buyer_pub,
            "not-seller",
            TradeOrderStatus::Requested,
        );
        let unauthorized_order_event = make_public_trade_event(
            &buyer_keys,
            TradeListingMessageType::OrderRequest,
            &listing_addr,
            "order-3",
            &buyer_pub,
            &seller_pub,
            Some(&state),
        )
        .await;
        assert!(matches!(
            handle_order_request(
                &unauthorized_order_event,
                unauthorized_payload,
                &parsed,
                Some("order-3"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        let mismatched_listing_addr = listing_addr_for_seller(&buyer_keys);
        let mismatched_parsed =
            TradeListingAddress::parse(&mismatched_listing_addr).expect("mismatched listing");

        set_order_status(&state, "order-1", TradeOrderStatus::Requested).await;
        assert!(matches!(
            handle_order_revision(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::OrderRevision,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeOrderRevision {
                    revision_id: "r-edge".to_string(),
                    changes: Vec::new(),
                },
                &mismatched_parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        set_order_status(&state, "order-1", TradeOrderStatus::Questioned).await;
        assert!(matches!(
            handle_answer(
                &make_public_trade_event(
                    &seller_keys,
                    TradeListingMessageType::Answer,
                    &listing_addr,
                    "order-1",
                    &buyer_pub,
                    &seller_pub,
                    Some(&state),
                )
                .await,
                TradeAnswer {
                    question_id: "q-edge".to_string(),
                },
                &mismatched_parsed,
                Some("order-1"),
                &client,
                &state,
            )
            .await,
            Err(TradeListingDvmError::Unauthorized)
        ));

        let listing_event_new =
            RadrootsNostrEventBuilder::new(custom_trade_kind(parsed.kind), "listing-new")
                .custom_created_at(RadrootsNostrTimestamp::from(10_u64))
                .sign_with_keys(&seller_keys)
                .expect("listing new");
        let listing_event_old =
            RadrootsNostrEventBuilder::new(custom_trade_kind(parsed.kind), "listing-old")
                .custom_created_at(RadrootsNostrTimestamp::from(9_u64))
                .sign_with_keys(&seller_keys)
                .expect("listing old");
        push_fetch_events_ok(vec![listing_event_new, listing_event_old]);
        let fetched_listing = fetch_listing_by_addr(&client, &listing_addr)
            .await
            .expect("listing fetch");
        assert!(fetched_listing.is_some());

        let metadata_event_new =
            RadrootsNostrEventBuilder::new(RadrootsNostrKind::Metadata, "metadata-new")
                .custom_created_at(RadrootsNostrTimestamp::from(20_u64))
                .sign_with_keys(&seller_keys)
                .expect("metadata new");
        let metadata_event_old =
            RadrootsNostrEventBuilder::new(RadrootsNostrKind::Metadata, "metadata-old")
                .custom_created_at(RadrootsNostrTimestamp::from(19_u64))
                .sign_with_keys(&seller_keys)
                .expect("metadata old");
        push_fetch_events_ok(vec![metadata_event_new, metadata_event_old]);
        let latest_metadata = fetch_latest_event_by_kind(
            &client,
            RadrootsNostrFilter::new(),
            RadrootsNostrKind::Metadata,
        )
        .await
        .expect("latest metadata");
        assert!(latest_metadata.is_some());
    }

    #[tokio::test]
    async fn handle_event_guard_and_dispatch_error_paths_are_covered() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, buyer_keys) = make_keys();
        let client = make_client(&rhi_keys);
        let listing_addr = listing_addr_for_seller(&seller_keys);
        let rhi_pub = rhi_keys.public_key().to_hex();
        let buyer_pub = buyer_keys.public_key().to_hex();
        let seller_pub = seller_keys.public_key().to_hex();
        let order_id = "order-1";
        let missing_order_id = "order-missing";
        let state = state_with_order(
            &listing_addr,
            order_id,
            &buyer_pub,
            &seller_pub,
            TradeOrderStatus::Requested,
        )
        .await;

        let invalid_json_event = make_event(
            &buyer_keys,
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
            "{".to_string(),
            make_custom_tags(&rhi_pub, &listing_addr, Some(order_id)),
        );
        let invalid_json_result = handle_event(
            invalid_json_event,
            make_custom_tags(&rhi_pub, &listing_addr, Some(order_id)),
            rhi_keys.clone(),
            client.clone(),
            state.clone(),
        )
        .await;
        assert!(matches!(
            invalid_json_result,
            Err(TradeListingDvmError::InvalidPayload(_))
        ));

        let invalid_envelope_event = make_event(
            &buyer_keys,
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
            make_envelope_content(
                TradeListingMessageType::OrderRequest,
                &listing_addr,
                None,
                json!({}),
            ),
            make_custom_tags(&rhi_pub, &listing_addr, Some(order_id)),
        );
        let invalid_envelope_result = handle_event(
            invalid_envelope_event,
            make_custom_tags(&rhi_pub, &listing_addr, Some(order_id)),
            rhi_keys.clone(),
            client.clone(),
            state.clone(),
        )
        .await;
        assert!(matches!(
            invalid_envelope_result,
            Err(TradeListingDvmError::InvalidEnvelope(_))
                | Err(TradeListingDvmError::InvalidPayload(_))
        ));

        let missing_a_tags = vec![RadrootsNostrTag::custom(
            RadrootsNostrTagKind::custom("p"),
            vec![rhi_pub.clone()],
        )];
        let missing_a_event = make_event(
            &buyer_keys,
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
            make_canonical_envelope_content(
                TradeListingMessageType::OrderRequest,
                &listing_addr,
                Some(order_id),
                payload_enum_for_message(
                    TradeListingMessageType::OrderRequest,
                    order_id,
                    &listing_addr,
                    &buyer_pub,
                    &seller_pub,
                ),
            ),
            missing_a_tags.clone(),
        );
        let missing_a_result = handle_event(
            missing_a_event,
            missing_a_tags,
            rhi_keys.clone(),
            client.clone(),
            state.clone(),
        )
        .await;
        assert!(matches!(
            missing_a_result,
            Err(TradeListingDvmError::MissingTag("a"))
        ));

        let invalid_addr = "30402:badpubkey:id";
        let invalid_addr_tags = make_custom_tags(&rhi_pub, invalid_addr, Some(order_id));
        let invalid_addr_event = make_event(
            &buyer_keys,
            custom_trade_kind(KIND_TRADE_LISTING_ORDER_REQ),
            make_canonical_envelope_content(
                TradeListingMessageType::OrderRequest,
                invalid_addr,
                Some(order_id),
                payload_enum_for_message(
                    TradeListingMessageType::OrderRequest,
                    order_id,
                    invalid_addr,
                    &buyer_pub,
                    &seller_pub,
                ),
            ),
            invalid_addr_tags.clone(),
        );
        let invalid_addr_result = handle_event(
            invalid_addr_event,
            invalid_addr_tags,
            rhi_keys.clone(),
            client.clone(),
            state.clone(),
        )
        .await;
        assert!(matches!(
            invalid_addr_result,
            Err(TradeListingDvmError::InvalidListingAddr)
        ));

        let listing_validate_parse_error_event = make_event(
            &buyer_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            make_envelope_content(
                TradeListingMessageType::ListingValidateRequest,
                &listing_addr,
                None,
                json!({"listing_event": 1}),
            ),
            make_custom_tags(&rhi_pub, &listing_addr, None),
        );
        let listing_validate_parse_error = handle_event(
            listing_validate_parse_error_event,
            make_custom_tags(&rhi_pub, &listing_addr, None),
            rhi_keys.clone(),
            client.clone(),
            state.clone(),
        )
        .await;
        assert!(matches!(
            listing_validate_parse_error,
            Err(TradeListingDvmError::InvalidPayload(_))
        ));

        push_fetch_event_by_id_error_not_found();
        let listing_validate_send_err_event = make_event(
            &buyer_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            make_canonical_envelope_content(
                TradeListingMessageType::ListingValidateRequest,
                &listing_addr,
                None,
                TradeListingMessagePayload::ListingValidateRequest(TradeListingValidateRequest {
                    listing_event: Some(RadrootsNostrEventPtr {
                        id: "missing".to_string(),
                        relays: None,
                    }),
                }),
            ),
            make_custom_tags(&rhi_pub, &listing_addr, None),
        );
        assert!(matches!(
            handle_event(
                listing_validate_send_err_event,
                make_custom_tags(&rhi_pub, &listing_addr, None),
                rhi_keys.clone(),
                client.clone(),
                state.clone()
            )
            .await,
            Err(TradeListingDvmError::Nostr(_))
        ));

        let listing_validate_fetch_err_event = make_event(
            &buyer_keys,
            custom_trade_kind(KIND_TRADE_LISTING_VALIDATE_REQ),
            make_canonical_envelope_content(
                TradeListingMessageType::ListingValidateRequest,
                &listing_addr,
                None,
                TradeListingMessagePayload::ListingValidateRequest(TradeListingValidateRequest {
                    listing_event: None,
                }),
            ),
            make_custom_tags(&rhi_pub, &listing_addr, None),
        );
        assert!(matches!(
            handle_event(
                listing_validate_fetch_err_event,
                make_custom_tags(&rhi_pub, &listing_addr, None),
                rhi_keys.clone(),
                client.clone(),
                state.clone()
            )
            .await,
            Err(TradeListingDvmError::Nostr(_))
        ));

        let missing_d_cases: Vec<(TradeListingMessageType, u32)> = vec![
            (
                TradeListingMessageType::OrderRequest,
                KIND_TRADE_LISTING_ORDER_REQ,
            ),
            (
                TradeListingMessageType::OrderResponse,
                KIND_TRADE_LISTING_ORDER_RES,
            ),
            (
                TradeListingMessageType::OrderRevision,
                KIND_TRADE_LISTING_ORDER_REVISION_REQ,
            ),
            (
                TradeListingMessageType::OrderRevisionAccept,
                KIND_TRADE_LISTING_ORDER_REVISION_RES,
            ),
            (
                TradeListingMessageType::OrderRevisionDecline,
                KIND_TRADE_LISTING_ORDER_REVISION_RES,
            ),
            (
                TradeListingMessageType::Question,
                KIND_TRADE_LISTING_QUESTION_REQ,
            ),
            (
                TradeListingMessageType::Answer,
                KIND_TRADE_LISTING_ANSWER_RES,
            ),
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
            (
                TradeListingMessageType::Cancel,
                KIND_TRADE_LISTING_CANCEL_REQ,
            ),
            (
                TradeListingMessageType::FulfillmentUpdate,
                KIND_TRADE_LISTING_FULFILLMENT_UPDATE_REQ,
            ),
            (
                TradeListingMessageType::Receipt,
                KIND_TRADE_LISTING_RECEIPT_REQ,
            ),
        ];
        for (message_type, kind) in missing_d_cases {
            let sender = sender_for_message(message_type, &seller_keys, &buyer_keys);
            let event = make_event(
                sender,
                custom_trade_kind(kind),
                make_canonical_envelope_content(
                    message_type,
                    &listing_addr,
                    Some(order_id),
                    payload_enum_for_message(
                        message_type,
                        order_id,
                        &listing_addr,
                        &buyer_pub,
                        &seller_pub,
                    ),
                ),
                make_custom_tags(&rhi_pub, &listing_addr, None),
            );
            let result = handle_event(
                event,
                make_custom_tags(&rhi_pub, &listing_addr, None),
                rhi_keys.clone(),
                client.clone(),
                state.clone(),
            )
            .await;
            assert!(matches!(result, Err(TradeListingDvmError::MissingTag("d"))));
        }

        let missing_order_cases: Vec<TradeListingMessageType> = vec![
            TradeListingMessageType::OrderResponse,
            TradeListingMessageType::OrderRevision,
            TradeListingMessageType::OrderRevisionAccept,
            TradeListingMessageType::OrderRevisionDecline,
            TradeListingMessageType::Question,
            TradeListingMessageType::Answer,
            TradeListingMessageType::DiscountRequest,
            TradeListingMessageType::DiscountOffer,
            TradeListingMessageType::DiscountAccept,
            TradeListingMessageType::DiscountDecline,
            TradeListingMessageType::Cancel,
            TradeListingMessageType::FulfillmentUpdate,
            TradeListingMessageType::Receipt,
        ];
        for message_type in missing_order_cases {
            let sender = sender_for_message(message_type, &seller_keys, &buyer_keys);
            let (event, tags) = make_handle_event_trade_event(
                sender,
                message_type,
                &listing_addr,
                missing_order_id,
                &buyer_pub,
                &seller_pub,
                Some(&state),
            )
            .await;
            let result =
                handle_event(event, tags, rhi_keys.clone(), client.clone(), state.clone()).await;
            assert!(
                matches!(
                    result,
                    Err(TradeListingDvmError::State(
                        TradeListingStateError::MissingOrder
                    ))
                ),
                "{message_type:?}: {result:?}"
            );
        }

        let transition_cases: Vec<(TradeListingMessageType, TradeOrderStatus)> = vec![
            (
                TradeListingMessageType::OrderResponse,
                TradeOrderStatus::Completed,
            ),
            (
                TradeListingMessageType::OrderRevision,
                TradeOrderStatus::Completed,
            ),
            (
                TradeListingMessageType::OrderRevisionAccept,
                TradeOrderStatus::Completed,
            ),
            (
                TradeListingMessageType::OrderRevisionDecline,
                TradeOrderStatus::Completed,
            ),
            (
                TradeListingMessageType::Question,
                TradeOrderStatus::Completed,
            ),
            (TradeListingMessageType::Answer, TradeOrderStatus::Completed),
            (
                TradeListingMessageType::DiscountOffer,
                TradeOrderStatus::Completed,
            ),
            (
                TradeListingMessageType::DiscountAccept,
                TradeOrderStatus::Completed,
            ),
            (
                TradeListingMessageType::DiscountDecline,
                TradeOrderStatus::Completed,
            ),
            (TradeListingMessageType::Cancel, TradeOrderStatus::Completed),
            (
                TradeListingMessageType::FulfillmentUpdate,
                TradeOrderStatus::Completed,
            ),
            (
                TradeListingMessageType::Receipt,
                TradeOrderStatus::Requested,
            ),
        ];
        for (message_type, status_before) in transition_cases {
            set_order_status(&state, order_id, status_before).await;
            let sender = sender_for_message(message_type, &seller_keys, &buyer_keys);
            let (event, tags) = make_handle_event_trade_event(
                sender,
                message_type,
                &listing_addr,
                order_id,
                &buyer_pub,
                &seller_pub,
                Some(&state),
            )
            .await;
            let result =
                handle_event(event, tags, rhi_keys.clone(), client.clone(), state.clone()).await;
            assert!(matches!(
                result,
                Err(TradeListingDvmError::State(
                    TradeListingStateError::InvalidTransition { .. }
                ))
            ));
        }
    }

    #[tokio::test]
    async fn fetch_listing_by_addr_error_regions_are_covered() {
        let _guard = test_guard();
        let (rhi_keys, seller_keys, _) = make_keys();
        let client = make_client(&rhi_keys);

        let invalid_author_result = fetch_listing_by_addr(&client, "30402:not_a_pubkey:list");
        assert!(matches!(
            invalid_author_result.await,
            Err(TradeListingDvmError::InvalidListingAddr)
        ));

        let listing_addr = listing_addr_for_seller(&seller_keys);
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_events_results
            .push_back(Err(TradeListingDvmError::InvalidOrder));
        let fetch_error_result = fetch_listing_by_addr(&client, &listing_addr).await;
        assert!(matches!(
            fetch_error_result,
            Err(TradeListingDvmError::InvalidOrder)
        ));
    }
}
