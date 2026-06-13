#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use std::{sync::Arc, time::Duration};

use radroots_events::farm::RadrootsFarmRef;
use radroots_events::kinds::{
    KIND_FARM, KIND_ORDER_CANCELLATION, KIND_ORDER_DECISION, KIND_ORDER_FULFILLMENT_UPDATE,
    KIND_ORDER_PAYMENT_RECORD, KIND_ORDER_RECEIPT, KIND_ORDER_REQUEST,
    KIND_ORDER_REVISION_DECISION, KIND_ORDER_REVISION_PROPOSAL, KIND_ORDER_SETTLEMENT_DECISION,
    KIND_TRADE_LISTING_VALIDATION_REQUEST, KIND_TRADE_LISTING_VALIDATION_RESULT,
    KIND_TRADE_TRANSITION_PROOF_REQUEST, KIND_TRADE_TRANSITION_PROOF_RESULT, is_listing_kind,
    is_order_event_kind, is_trade_validation_service_event_kind,
};
use radroots_events::order::{
    RadrootsOrderDecisionOutcome, RadrootsOrderFulfillmentState, RadrootsOrderReceipt,
    RadrootsOrderRevisionOutcome,
};
use radroots_events::trade_validation::{
    RadrootsTradeValidationListingError as TradeListingValidationError,
    RadrootsTradeValidationListingRequest as TradeListingValidateRequest,
    RadrootsTradeValidationListingResult as TradeListingValidateResult,
};
use radroots_events_codec::order::{
    RadrootsOrderEnvelopeParseError, RadrootsOrderListingAddress as OrderListingAddress,
    order_cancellation_from_event, order_decision_from_event, order_fulfillment_update_from_event,
    order_payment_record_from_event, order_receipt_from_event, order_request_from_event,
    order_revision_decision_from_event, order_revision_proposal_from_event,
    order_settlement_decision_from_event, parse_order_listing_event_tag, parse_order_prev_tag,
    parse_order_root_tag,
};
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrFilter,
    RadrootsNostrKeys, RadrootsNostrKind, RadrootsNostrTag, radroots_event_from_nostr,
    radroots_nostr_build_event, radroots_nostr_build_event_job_feedback,
    radroots_nostr_fetch_event_by_id, radroots_nostr_parse_pubkey, radroots_nostr_send_event,
};
use radroots_trade::listing::validation::validate_listing_event;
use thiserror::Error;

use crate::features::trade_listing::state::{
    TradeListingState, TradeListingStateError, TradeOrderState, TradeOrderStatus,
};
use crate::features::trade_validation_receipt::{
    TradeValidationReceiptJobError, TradeValidationReceiptProverPolicy,
    handle_trade_validation_receipt_job_request,
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
    InvalidEnvelope(String),
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
        std::collections::VecDeque<Result<(String, RadrootsFarmRef), TradeListingValidationError>>,
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
-> Option<Result<(String, RadrootsFarmRef), TradeListingValidationError>> {
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
-> Option<Result<(String, RadrootsFarmRef), TradeListingValidationError>> {
    pop_validate_listing_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_validate_listing_hook()
-> Option<Result<(String, RadrootsFarmRef), TradeListingValidationError>> {
    None
}

async fn fetch_event_by_id_io(
    client: &RadrootsNostrClient,
    id: &str,
) -> Result<RadrootsNostrEvent, TradeListingDvmError> {
    match take_fetch_event_by_id_hook() {
        Some(result) => result,
        None => radroots_nostr_fetch_event_by_id(client, id)
            .await
            .map_err(TradeListingDvmError::from),
    }
}

async fn fetch_events_io(
    client: &RadrootsNostrClient,
    filter: RadrootsNostrFilter,
    timeout: Duration,
) -> Result<Vec<RadrootsNostrEvent>, TradeListingDvmError> {
    match take_fetch_events_hook() {
        Some(result) => result,
        None => client
            .fetch_events(filter, timeout)
            .await
            .map_err(TradeListingDvmError::from),
    }
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn send_event_io(
    client: &RadrootsNostrClient,
    builder: RadrootsNostrEventBuilder,
) -> Result<(), TradeListingDvmError> {
    match take_send_event_hook() {
        Some(result) => result,
        None => radroots_nostr_send_event(client, builder)
            .await
            .map(|_| ())
            .map_err(TradeListingDvmError::from),
    }
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
fn validate_listing_event_io(
    event: &RadrootsNostrEvent,
) -> Result<(String, RadrootsFarmRef), TradeListingValidationError> {
    match take_validate_listing_hook() {
        Some(result) => result,
        None => validate_listing_event(&radroots_event_from_nostr(event))
            .map(|listing| (listing.listing_addr, listing.listing.farm)),
    }
}

pub async fn handle_event_with_policy(
    event: RadrootsNostrEvent,
    _tags: Vec<RadrootsNostrTag>,
    keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    state: Arc<tokio::sync::Mutex<TradeListingState>>,
    proof_policy: &TradeValidationReceiptProverPolicy,
) -> Result<(), TradeListingDvmError> {
    let kind = event_kind_u32(&event)?;
    if is_listing_kind(kind) {
        return handle_listing_event(&event, &state).await;
    }
    if event.pubkey == keys.public_key() {
        return Ok(());
    }
    if kind == KIND_TRADE_TRANSITION_PROOF_REQUEST {
        return handle_trade_validation_receipt_job_request(&event, &keys, &client, proof_policy)
            .await
            .map_err(map_trade_validation_receipt_job_error);
    }
    if kind == KIND_TRADE_LISTING_VALIDATION_REQUEST {
        ensure_service_recipient(&event, &keys)?;
        return handle_listing_validate_request(&event, &client, &state).await;
    }
    if kind == KIND_TRADE_LISTING_VALIDATION_RESULT || kind == KIND_TRADE_TRANSITION_PROOF_RESULT {
        state
            .lock()
            .await
            .mark_non_order_event_seen(&event.id.to_string());
        return Ok(());
    }
    if is_order_event_kind(kind) {
        return handle_order_event(&event, kind, &client, &state).await;
    }
    if is_trade_validation_service_event_kind(kind) {
        return Err(TradeListingDvmError::UnsupportedKind);
    }
    Err(TradeListingDvmError::UnsupportedKind)
}

#[cfg(test)]
pub async fn handle_event(
    event: RadrootsNostrEvent,
    tags: Vec<RadrootsNostrTag>,
    keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    state: Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    handle_event_with_policy(
        event,
        tags,
        keys,
        client,
        state,
        &TradeValidationReceiptProverPolicy::default(),
    )
    .await
}

fn event_kind_u32(event: &RadrootsNostrEvent) -> Result<u32, TradeListingDvmError> {
    match event.kind {
        RadrootsNostrKind::Custom(value) => Ok(u32::from(value)),
        _ => Err(TradeListingDvmError::UnsupportedKind),
    }
}

fn map_trade_validation_receipt_job_error(
    error: TradeValidationReceiptJobError,
) -> TradeListingDvmError {
    match error {
        TradeValidationReceiptJobError::UnsupportedKind => TradeListingDvmError::UnsupportedKind,
        TradeValidationReceiptJobError::MissingRecipient => TradeListingDvmError::MissingRecipient,
        TradeValidationReceiptJobError::Nostr(error) => TradeListingDvmError::Nostr(error),
        other => TradeListingDvmError::InvalidPayload(other.to_string()),
    }
}

fn map_order_parse_error(error: RadrootsOrderEnvelopeParseError) -> TradeListingDvmError {
    match error {
        RadrootsOrderEnvelopeParseError::InvalidKind(_) => TradeListingDvmError::UnsupportedKind,
        RadrootsOrderEnvelopeParseError::MissingTag(tag) => TradeListingDvmError::MissingTag(tag),
        RadrootsOrderEnvelopeParseError::ListingAddrTagMismatch => {
            TradeListingDvmError::TagMismatch("a")
        }
        RadrootsOrderEnvelopeParseError::OrderIdTagMismatch => {
            TradeListingDvmError::TagMismatch("d")
        }
        RadrootsOrderEnvelopeParseError::InvalidListingAddr(_) => {
            TradeListingDvmError::InvalidListingAddr
        }
        RadrootsOrderEnvelopeParseError::InvalidEnvelope(error) => {
            TradeListingDvmError::InvalidEnvelope(error.to_string())
        }
        other => TradeListingDvmError::InvalidPayload(other.to_string()),
    }
}

fn ensure_service_recipient(
    event: &RadrootsNostrEvent,
    keys: &RadrootsNostrKeys,
) -> Result<(), TradeListingDvmError> {
    let tags = radroots_event_from_nostr(event).tags;
    if tag_has_value(&tags, "p", &keys.public_key().to_string()) {
        Ok(())
    } else {
        Err(TradeListingDvmError::MissingRecipient)
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
    let kind = event_kind_u32(event)?;
    let mut state = state.lock().await;
    state.upsert_listing_event(&validated.listing_addr, &event_id, kind);
    state.mark_non_order_event_seen(&event_id);
    Ok(())
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn handle_listing_validate_request(
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let event_id = event.id.to_string();
    {
        let state = state.lock().await;
        if state.is_non_order_event_seen(&event_id) {
            return Ok(());
        }
    }
    let rr_event = radroots_event_from_nostr(event);
    let listing_addr = required_tag_value(&rr_event.tags, "a")?;
    let parsed_listing_addr = OrderListingAddress::parse(&listing_addr)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    if !is_listing_kind(parsed_listing_addr.kind) {
        return Err(TradeListingDvmError::InvalidListingAddr);
    }
    let payload: TradeListingValidateRequest = serde_json::from_str(&event.content)?;
    let listing_event = resolve_listing_event(client, &listing_addr, payload.listing_event).await;
    let (validated_event_id, errors) = match listing_event {
        Ok(Some(listing_event)) => match validate_listing_event_io(&listing_event) {
            Ok((validated_listing_addr, farm)) if validated_listing_addr == listing_addr => {
                let errors = validate_farm_dependencies(client, &farm).await?;
                if errors.is_empty() {
                    (Some(listing_event.id.to_string()), errors)
                } else {
                    (None, errors)
                }
            }
            Ok(_) => (
                None,
                vec![TradeListingValidationError::ListingEventNotFound {
                    listing_addr: listing_addr.clone(),
                }],
            ),
            Err(error) => (None, vec![error]),
        },
        Ok(None) => (
            None,
            vec![TradeListingValidationError::ListingEventNotFound {
                listing_addr: listing_addr.clone(),
            }],
        ),
        Err(_) => (
            None,
            vec![TradeListingValidationError::ListingEventFetchFailed {
                listing_addr: listing_addr.clone(),
            }],
        ),
    };
    {
        let mut state = state.lock().await;
        match validated_event_id {
            Some(validated_event_id) => {
                state.mark_listing_validated(&listing_addr, &validated_event_id);
            }
            None => state.clear_listing_validation(&listing_addr),
        }
        state.mark_non_order_event_seen(&event_id);
    }
    send_validate_result(event, client, &listing_addr, errors).await
}

async fn resolve_listing_event(
    client: &RadrootsNostrClient,
    listing_addr: &str,
    listing_event: Option<radroots_events::RadrootsNostrEventPtr>,
) -> Result<Option<RadrootsNostrEvent>, TradeListingDvmError> {
    match listing_event {
        Some(ptr) => fetch_event_by_id_io(client, &ptr.id).await.map(Some),
        None => fetch_listing_by_addr(client, listing_addr).await,
    }
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
    let content = serde_json::to_string(&payload)?;
    let tags = vec![
        vec!["p".to_string(), event.pubkey.to_string()],
        vec!["a".to_string(), listing_addr.to_string()],
        vec!["e".to_string(), event.id.to_string()],
    ];
    let builder = radroots_nostr_build_event(KIND_TRADE_LISTING_VALIDATION_RESULT, content, tags)?;
    send_event_io(client, builder).await
}

async fn handle_order_event(
    event: &RadrootsNostrEvent,
    kind: u32,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    match kind {
        KIND_ORDER_REQUEST => handle_order_request(event, client, state).await,
        KIND_ORDER_DECISION => handle_order_decision(event, state).await,
        KIND_ORDER_REVISION_PROPOSAL => handle_order_revision_proposal(event, state).await,
        KIND_ORDER_REVISION_DECISION => handle_order_revision_decision(event, state).await,
        KIND_ORDER_CANCELLATION => handle_order_cancellation(event, state).await,
        KIND_ORDER_FULFILLMENT_UPDATE => handle_order_fulfillment_update(event, state).await,
        KIND_ORDER_RECEIPT => handle_order_receipt(event, state).await,
        KIND_ORDER_PAYMENT_RECORD => handle_order_payment_record(event, state).await,
        KIND_ORDER_SETTLEMENT_DECISION => handle_order_settlement_decision(event, state).await,
        _ => Err(TradeListingDvmError::UnsupportedKind),
    }
}

async fn handle_order_request(
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let envelope = order_request_from_event(&rr_event).map_err(map_order_parse_error)?;
    let listing_addr = OrderListingAddress::parse(&envelope.listing_addr)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    if !is_listing_kind(listing_addr.kind)
        || envelope.payload.seller_pubkey != listing_addr.seller_pubkey
    {
        return Err(TradeListingDvmError::InvalidListingAddr);
    }
    let listing_event = parse_order_listing_event_tag(&rr_event.tags)
        .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))?
        .ok_or(TradeListingDvmError::MissingTag("listing_event"))?;
    let listing_snapshot_event_id =
        ensure_listing_snapshot(&envelope.listing_addr, &listing_event, client, state).await?;
    let event_id = event.id.to_string();
    let mut state = state.lock().await;
    if state.order_exists(&envelope.order_id) {
        return Ok(());
    }
    let mut seen = std::collections::HashSet::new();
    seen.insert(event_id.clone());
    state.insert_order(TradeOrderState {
        order_id: envelope.order_id,
        listing_addr: envelope.payload.listing_addr.to_string(),
        buyer_pubkey: envelope.payload.buyer_pubkey,
        seller_pubkey: envelope.payload.seller_pubkey,
        status: TradeOrderStatus::Requested,
        listing_snapshot_event_id: Some(listing_snapshot_event_id),
        root_event_id: Some(event_id.clone()),
        last_event_id: Some(event_id),
        seen_event_ids: seen,
    });
    Ok(())
}

async fn ensure_listing_snapshot(
    listing_addr: &str,
    listing_event: &radroots_events::RadrootsNostrEventPtr,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<String, TradeListingDvmError> {
    {
        let state = state.lock().await;
        if state.listing_event_id(listing_addr) == Some(listing_event.id.as_str()) {
            return Ok(listing_event.id.clone());
        }
    }
    let event = fetch_event_by_id_io(client, &listing_event.id).await?;
    let (validated_listing_addr, _) = validate_listing_event_io(&event)
        .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))?;
    if validated_listing_addr != listing_addr {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    let kind = event_kind_u32(&event)?;
    let mut state = state.lock().await;
    state.upsert_listing_event(listing_addr, &listing_event.id, kind);
    Ok(listing_event.id.clone())
}

async fn handle_order_decision(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let envelope = order_decision_from_event(&rr_event).map_err(map_order_parse_error)?;
    let next_status = match envelope.payload.decision {
        RadrootsOrderDecisionOutcome::Accepted { .. } => TradeOrderStatus::Accepted,
        RadrootsOrderDecisionOutcome::Declined { .. } => TradeOrderStatus::Declined,
    };
    update_existing_order(event, &rr_event.tags, state, &envelope.order_id, |order| {
        ensure_order_binding(
            order,
            &envelope.payload.listing_addr,
            &envelope.payload.buyer_pubkey,
            &envelope.payload.seller_pubkey,
        )?;
        ensure_transition(&order.status, &next_status)?;
        order.status = next_status;
        Ok(())
    })
    .await
}

async fn handle_order_revision_proposal(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let envelope = order_revision_proposal_from_event(&rr_event).map_err(map_order_parse_error)?;
    update_existing_order(event, &rr_event.tags, state, &envelope.order_id, |order| {
        ensure_order_binding(
            order,
            &envelope.payload.listing_addr,
            &envelope.payload.buyer_pubkey,
            &envelope.payload.seller_pubkey,
        )?;
        ensure_transition(&order.status, &TradeOrderStatus::Accepted)?;
        Ok(())
    })
    .await
}

async fn handle_order_revision_decision(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let envelope = order_revision_decision_from_event(&rr_event).map_err(map_order_parse_error)?;
    update_existing_order(event, &rr_event.tags, state, &envelope.order_id, |order| {
        ensure_order_binding(
            order,
            &envelope.payload.listing_addr,
            &envelope.payload.buyer_pubkey,
            &envelope.payload.seller_pubkey,
        )?;
        match envelope.payload.decision {
            RadrootsOrderRevisionOutcome::Accepted
            | RadrootsOrderRevisionOutcome::Declined { .. } => {
                ensure_transition(&order.status, &TradeOrderStatus::Accepted)?;
                Ok(())
            }
        }
    })
    .await
}

async fn handle_order_cancellation(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let envelope = order_cancellation_from_event(&rr_event).map_err(map_order_parse_error)?;
    update_existing_order(event, &rr_event.tags, state, &envelope.order_id, |order| {
        ensure_order_binding(
            order,
            &envelope.payload.listing_addr,
            &envelope.payload.buyer_pubkey,
            &envelope.payload.seller_pubkey,
        )?;
        ensure_transition(&order.status, &TradeOrderStatus::Cancelled)?;
        order.status = TradeOrderStatus::Cancelled;
        Ok(())
    })
    .await
}

async fn handle_order_fulfillment_update(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let envelope = order_fulfillment_update_from_event(&rr_event).map_err(map_order_parse_error)?;
    update_existing_order(event, &rr_event.tags, state, &envelope.order_id, |order| {
        ensure_order_binding(
            order,
            &envelope.payload.listing_addr,
            &envelope.payload.buyer_pubkey,
            &envelope.payload.seller_pubkey,
        )?;
        ensure_transition(&order.status, &TradeOrderStatus::Accepted)?;
        if envelope.payload.status == RadrootsOrderFulfillmentState::SellerCancelled {
            order.status = TradeOrderStatus::Cancelled;
        }
        Ok(())
    })
    .await
}

async fn handle_order_receipt(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let envelope = order_receipt_from_event(&rr_event).map_err(map_order_parse_error)?;
    let next_status = receipt_status(&envelope.payload);
    update_existing_order(event, &rr_event.tags, state, &envelope.order_id, |order| {
        ensure_order_binding(
            order,
            &envelope.payload.listing_addr,
            &envelope.payload.buyer_pubkey,
            &envelope.payload.seller_pubkey,
        )?;
        ensure_transition(&order.status, &next_status)?;
        order.status = next_status;
        Ok(())
    })
    .await
}

async fn handle_order_payment_record(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let envelope = order_payment_record_from_event(&rr_event).map_err(map_order_parse_error)?;
    update_existing_order(event, &rr_event.tags, state, &envelope.order_id, |order| {
        ensure_order_binding(
            order,
            &envelope.payload.listing_addr,
            &envelope.payload.buyer_pubkey,
            &envelope.payload.seller_pubkey,
        )
    })
    .await
}

async fn handle_order_settlement_decision(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let envelope =
        order_settlement_decision_from_event(&rr_event).map_err(map_order_parse_error)?;
    update_existing_order(event, &rr_event.tags, state, &envelope.order_id, |order| {
        ensure_order_binding(
            order,
            &envelope.payload.listing_addr,
            &envelope.payload.buyer_pubkey,
            &envelope.payload.seller_pubkey,
        )
    })
    .await
}

async fn update_existing_order<F>(
    event: &RadrootsNostrEvent,
    tags: &[Vec<String>],
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
    order_id: &str,
    update: F,
) -> Result<(), TradeListingDvmError>
where
    F: FnOnce(&mut TradeOrderState) -> Result<(), TradeListingDvmError>,
{
    let event_id = event.id.to_string();
    let mut state = state.lock().await;
    if state.is_event_seen(order_id, &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id)
        .ok_or(TradeListingStateError::MissingOrder)?;
    ensure_order_chain(order, tags)?;
    update(order)?;
    order.last_event_id = Some(event_id.clone());
    order.seen_event_ids.insert(event_id);
    Ok(())
}

fn ensure_order_binding(
    order: &TradeOrderState,
    listing_addr: &str,
    buyer_pubkey: &str,
    seller_pubkey: &str,
) -> Result<(), TradeListingDvmError> {
    if order.listing_addr == listing_addr
        && order.buyer_pubkey == buyer_pubkey
        && order.seller_pubkey == seller_pubkey
    {
        Ok(())
    } else {
        Err(TradeListingDvmError::InvalidOrder)
    }
}

fn ensure_order_chain(
    order: &TradeOrderState,
    tags: &[Vec<String>],
) -> Result<(), TradeListingDvmError> {
    let root_event_id = parse_order_root_tag(tags)
        .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))?
        .ok_or(TradeListingDvmError::MissingTag("e:root"))?;
    let prev_event_id = parse_order_prev_tag(tags)
        .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))?
        .ok_or(TradeListingDvmError::MissingTag("e:prev"))?;
    if order.root_event_id.as_deref() == Some(root_event_id.as_str())
        && order.last_event_id.as_deref() == Some(prev_event_id.as_str())
    {
        Ok(())
    } else {
        Err(TradeListingDvmError::InvalidOrder)
    }
}

fn receipt_status(payload: &RadrootsOrderReceipt) -> TradeOrderStatus {
    if payload.received {
        TradeOrderStatus::Completed
    } else {
        TradeOrderStatus::Disputed
    }
}

fn ensure_transition(
    from: &TradeOrderStatus,
    to: &TradeOrderStatus,
) -> Result<(), TradeListingStateError> {
    if from == to {
        return Ok(());
    }
    let allowed = match from {
        TradeOrderStatus::Requested => matches!(
            to,
            TradeOrderStatus::Accepted | TradeOrderStatus::Declined | TradeOrderStatus::Cancelled
        ),
        TradeOrderStatus::Accepted => matches!(
            to,
            TradeOrderStatus::Cancelled | TradeOrderStatus::Completed | TradeOrderStatus::Disputed
        ),
        TradeOrderStatus::Declined
        | TradeOrderStatus::Cancelled
        | TradeOrderStatus::Completed
        | TradeOrderStatus::Disputed
        | TradeOrderStatus::Invalid => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(TradeListingStateError::InvalidTransition {
            from: from.clone(),
            to: to.clone(),
        })
    }
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn fetch_listing_by_addr(
    client: &RadrootsNostrClient,
    listing_addr: &str,
) -> Result<Option<RadrootsNostrEvent>, TradeListingDvmError> {
    let addr = OrderListingAddress::parse(listing_addr)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let author = radroots_nostr_parse_pubkey(&addr.seller_pubkey)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let kind = u16::try_from(addr.kind).map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let filter = RadrootsNostrFilter::new()
        .kind(RadrootsNostrKind::Custom(kind))
        .author(author)
        .identifier(addr.listing_id);
    let events = fetch_events_io(client, filter, Duration::from_secs(10)).await?;
    Ok(events
        .into_iter()
        .filter(|event| event.kind == RadrootsNostrKind::Custom(kind))
        .max_by_key(|event| event.created_at))
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn fetch_latest_event_by_kind(
    client: &RadrootsNostrClient,
    filter: RadrootsNostrFilter,
    kind: RadrootsNostrKind,
) -> Result<Option<RadrootsNostrEvent>, TradeListingDvmError> {
    let events = fetch_events_io(client, filter, Duration::from_secs(10)).await?;
    Ok(events
        .into_iter()
        .filter(|event| event.kind == kind)
        .max_by_key(|event| event.created_at))
}

async fn validate_farm_dependencies(
    client: &RadrootsNostrClient,
    farm: &RadrootsFarmRef,
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
        .author(author);
    let profile_event =
        fetch_latest_event_by_kind(client, profile_filter, RadrootsNostrKind::Metadata).await?;
    let has_profile = profile_event
        .map(|event| {
            let rr_event = radroots_event_from_nostr(&event);
            tag_has_value(&rr_event.tags, "t", "radroots:type:farm")
        })
        .unwrap_or(false);
    if !has_profile {
        errors.push(TradeListingValidationError::MissingFarmProfile);
    }
    if farm_d_tag.is_empty() {
        errors.push(TradeListingValidationError::MissingFarmRecord);
        return Ok(errors);
    }
    let author = radroots_nostr_parse_pubkey(farm_pubkey)
        .map_err(|_| TradeListingDvmError::InvalidPayload("invalid farm pubkey".to_string()))?;
    let record_filter = RadrootsNostrFilter::new()
        .kind(RadrootsNostrKind::Custom(KIND_FARM as u16))
        .author(author)
        .identifier(farm_d_tag.to_string());
    let record_event = fetch_latest_event_by_kind(
        client,
        record_filter,
        RadrootsNostrKind::Custom(KIND_FARM as u16),
    )
    .await?;
    if record_event.is_none() {
        errors.push(TradeListingValidationError::MissingFarmRecord);
    }
    Ok(errors)
}

fn required_tag_value(
    tags: &[Vec<String>],
    key: &'static str,
) -> Result<String, TradeListingDvmError> {
    tags.iter()
        .find_map(|tag| {
            if tag.first().map(String::as_str) == Some(key) {
                tag.get(1).cloned()
            } else {
                None
            }
        })
        .filter(|value| !value.trim().is_empty())
        .ok_or(TradeListingDvmError::MissingTag(key))
}

fn tag_has_value(tags: &[Vec<String>], key: &str, value: &str) -> bool {
    tags.iter().any(|tag| {
        tag.first().map(String::as_str) == Some(key)
            && tag.get(1).map(String::as_str) == Some(value)
    })
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
        DvmTestHooks, TradeListingDvmError, dvm_test_hooks, ensure_transition, handle_error,
        handle_event, tag_has_value,
    };
    use crate::features::trade_listing::state::{TradeListingState, TradeOrderStatus};
    use radroots_core::{
        RadrootsCoreCurrency, RadrootsCoreDecimal, RadrootsCoreMoney, RadrootsCoreUnit,
    };
    use radroots_events::RadrootsNostrEventPtr;
    use radroots_events::farm::RadrootsFarmRef;
    use radroots_events::kinds::{
        KIND_LISTING, KIND_ORDER_REQUEST, KIND_TRADE_LISTING_VALIDATION_REQUEST,
    };
    use radroots_events::order::{
        RadrootsOrderEconomicItem, RadrootsOrderEconomicLine, RadrootsOrderEconomics,
        RadrootsOrderItem, RadrootsOrderPricingBasis, RadrootsOrderRequest,
    };
    use radroots_events::trade_validation::RadrootsTradeValidationListingRequest;
    use radroots_events_codec::order::order_request_event_build;
    use radroots_nostr::prelude::{
        RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrKeys,
        RadrootsNostrKind, radroots_nostr_build_event,
    };
    use std::sync::Arc;
    use tokio::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::const_new(());

    async fn test_guard() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().await;
        *dvm_test_hooks().lock().expect("hooks") = DvmTestHooks::default();
        guard
    }

    fn listing_id() -> &'static str {
        "AAAAAAAAAAAAAAAAAAAAAg"
    }

    fn listing_addr(seller: &RadrootsNostrKeys) -> String {
        format!("{}:{}:{}", KIND_LISTING, seller.public_key(), listing_id())
    }

    fn listing_event_ptr() -> RadrootsNostrEventPtr {
        RadrootsNostrEventPtr {
            id: "listing-event-1".to_string(),
            relays: None,
        }
    }

    fn order_economics(order_id: &str) -> RadrootsOrderEconomics {
        RadrootsOrderEconomics {
            quote_id: format!("{order_id}-quote"),
            quote_version: 1,
            pricing_basis: RadrootsOrderPricingBasis::ListingEvent,
            currency: RadrootsCoreCurrency::USD,
            items: vec![RadrootsOrderEconomicItem {
                bin_id: "bin-1".to_string(),
                bin_count: 2,
                quantity_amount: RadrootsCoreDecimal::from(1u32),
                quantity_unit: RadrootsCoreUnit::Each,
                unit_price_amount: RadrootsCoreDecimal::from(5u32),
                unit_price_currency: RadrootsCoreCurrency::USD,
                line_subtotal: RadrootsCoreMoney::new(
                    RadrootsCoreDecimal::from(10u32),
                    RadrootsCoreCurrency::USD,
                ),
            }],
            discounts: Vec::<RadrootsOrderEconomicLine>::new(),
            adjustments: Vec::<RadrootsOrderEconomicLine>::new(),
            subtotal: RadrootsCoreMoney::new(
                RadrootsCoreDecimal::from(10u32),
                RadrootsCoreCurrency::USD,
            ),
            discount_total: RadrootsCoreMoney::new(
                RadrootsCoreDecimal::from(0u32),
                RadrootsCoreCurrency::USD,
            ),
            adjustment_total: RadrootsCoreMoney::new(
                RadrootsCoreDecimal::from(0u32),
                RadrootsCoreCurrency::USD,
            ),
            total: RadrootsCoreMoney::new(
                RadrootsCoreDecimal::from(10u32),
                RadrootsCoreCurrency::USD,
            ),
        }
    }

    fn order_request(
        order_id: &str,
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
    ) -> RadrootsOrderRequest {
        RadrootsOrderRequest {
            order_id: order_id.to_string(),
            listing_addr: listing_addr(seller),
            buyer_pubkey: buyer.public_key().to_string(),
            seller_pubkey: seller.public_key().to_string(),
            items: vec![RadrootsOrderItem {
                bin_id: "bin-1".to_string(),
                bin_count: 2,
            }],
            economics: order_economics(order_id),
        }
    }

    fn signed_order_request_event(
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
    ) -> RadrootsNostrEvent {
        let payload = order_request("order-1", buyer, seller);
        let wire = order_request_event_build(&listing_event_ptr(), &payload).expect("wire");
        radroots_nostr_build_event(wire.kind, wire.content, wire.tags)
            .expect("builder")
            .sign_with_keys(buyer)
            .expect("event")
    }

    fn listing_event(seller: &RadrootsNostrKeys) -> RadrootsNostrEvent {
        RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(KIND_LISTING as u16), "{}")
            .tags(vec![radroots_nostr::prelude::RadrootsNostrTag::identifier(
                listing_id(),
            )])
            .sign_with_keys(seller)
            .expect("listing event")
    }

    #[tokio::test]
    async fn order_request_inserts_canonical_order_state() {
        let _guard = test_guard().await;
        let worker = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(worker.clone());
        let state = Arc::new(Mutex::new(TradeListingState::default()));
        state.lock().await.upsert_listing_event(
            &listing_addr(&seller),
            "listing-event-1",
            KIND_LISTING,
        );

        handle_event(
            signed_order_request_event(&buyer, &seller),
            Vec::new(),
            worker,
            client,
            state.clone(),
        )
        .await
        .expect("order request");

        let mut state = state.lock().await;
        let order = state.get_order_mut("order-1").expect("order");
        assert_eq!(order.status, TradeOrderStatus::Requested);
        assert_eq!(order.buyer_pubkey, buyer.public_key().to_string());
        assert_eq!(order.seller_pubkey, seller.public_key().to_string());
    }

    #[tokio::test]
    async fn listing_validation_request_sends_result_and_marks_listing_validated() {
        let _guard = test_guard().await;
        let worker = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(worker.clone());
        let state = Arc::new(Mutex::new(TradeListingState::default()));
        let listing_addr = listing_addr(&seller);
        {
            let mut hooks = dvm_test_hooks().lock().expect("hooks");
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(listing_event(&seller)));
            hooks.validate_listing_results.push_back(Ok((
                listing_addr.clone(),
                RadrootsFarmRef {
                    pubkey: seller.public_key().to_string(),
                    d_tag: "farm-1".to_string(),
                },
            )));
            hooks.farm_validation_results.push_back(Ok(Vec::new()));
            hooks.send_event_results.push_back(Ok(()));
        }
        let payload = RadrootsTradeValidationListingRequest {
            listing_event: Some(listing_event_ptr()),
        };
        let event = radroots_nostr_build_event(
            KIND_TRADE_LISTING_VALIDATION_REQUEST,
            serde_json::to_string(&payload).expect("payload"),
            vec![
                vec!["p".to_string(), worker.public_key().to_string()],
                vec!["a".to_string(), listing_addr.clone()],
            ],
        )
        .expect("builder")
        .sign_with_keys(&requester)
        .expect("event");

        handle_event(event, Vec::new(), worker, client, state.clone())
            .await
            .expect("validation request");

        assert!(state.lock().await.is_listing_validated(&listing_addr));
    }

    #[tokio::test]
    async fn unsupported_kind_is_rejected() {
        let _guard = test_guard().await;
        let worker = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(worker.clone());
        let state = Arc::new(Mutex::new(TradeListingState::default()));
        let event = RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(4999), "test")
            .sign_with_keys(&RadrootsNostrKeys::generate())
            .expect("event");
        assert!(matches!(
            handle_event(event, Vec::new(), worker, client, state).await,
            Err(TradeListingDvmError::UnsupportedKind)
        ));
    }

    #[test]
    fn transition_and_tag_helpers_cover_core_paths() {
        assert!(
            ensure_transition(&TradeOrderStatus::Requested, &TradeOrderStatus::Accepted).is_ok()
        );
        assert!(
            ensure_transition(&TradeOrderStatus::Declined, &TradeOrderStatus::Accepted).is_err()
        );
        assert!(tag_has_value(
            &[vec!["p".to_string(), "pubkey".to_string()]],
            "p",
            "pubkey"
        ));
    }

    #[tokio::test]
    async fn handle_error_uses_send_hook() {
        let _guard = test_guard().await;
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .send_event_results
            .push_back(Ok(()));
        let keys = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(keys.clone());
        let event = RadrootsNostrEventBuilder::new(
            RadrootsNostrKind::Custom(KIND_ORDER_REQUEST as u16),
            "bad",
        )
        .sign_with_keys(&keys)
        .expect("event");
        assert!(
            handle_error(TradeListingDvmError::InvalidOrder, &event, &client)
                .await
                .is_ok()
        );
    }
}
