#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use std::{sync::Arc, time::Duration};

use radroots_events::farm::RadrootsFarmRef;
use radroots_events::kinds::{
    KIND_FARM, KIND_ORDER_CANCELLATION, KIND_ORDER_DECISION, KIND_ORDER_REQUEST,
    KIND_ORDER_REVISION_DECISION, KIND_ORDER_REVISION_PROPOSAL,
    KIND_TRADE_LISTING_VALIDATION_REQUEST, KIND_TRADE_LISTING_VALIDATION_RESULT,
    KIND_TRADE_TRANSITION_PROOF_REQUEST, KIND_TRADE_TRANSITION_PROOF_RESULT,
    KIND_TRADE_VALIDATION_RECEIPT, is_listing_kind, is_order_event_kind,
    is_trade_validation_service_event_kind,
};
use radroots_events::trade_validation::{
    RadrootsTradeValidationListingError as TradeListingValidationError,
    RadrootsTradeValidationListingRequest as TradeListingValidateRequest,
    RadrootsTradeValidationListingResult as TradeListingValidateResult,
};
use radroots_events_codec::order::{
    RadrootsOrderEnvelopeParseError, parse_order_listing_event_tag,
};
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrFilter,
    RadrootsNostrKeys, RadrootsNostrKind, RadrootsNostrTag, radroots_event_from_nostr,
    radroots_nostr_build_event, radroots_nostr_build_event_job_feedback,
    radroots_nostr_fetch_event_by_id, radroots_nostr_parse_pubkey, radroots_nostr_send_event,
};
use radroots_trade::listing::{
    parse_listing_address, parse_public_listing_address, validation::validate_listing_event,
};
use radroots_trade::order::{
    RadrootsOrderEventRecord, RadrootsOrderProjection, order_event_record_from_event,
    reduce_order_event_records,
};
use radroots_trade::workflow::RadrootsTradeWorkflowState;
use thiserror::Error;

use crate::features::trade_listing::state::{
    TradeListingState, TradeListingStateError, TradeOrderState,
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
    #[error("shared workflow rejected trade transition: {0}")]
    Workflow(String),
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
    if kind == KIND_TRADE_LISTING_VALIDATION_RESULT
        || kind == KIND_TRADE_TRANSITION_PROOF_RESULT
        || kind == KIND_TRADE_VALIDATION_RECEIPT
    {
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
    parse_listing_address(&listing_addr).map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
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
        KIND_ORDER_DECISION
        | KIND_ORDER_REVISION_PROPOSAL
        | KIND_ORDER_REVISION_DECISION
        | KIND_ORDER_CANCELLATION => handle_order_workflow_event(event, client, state).await,
        _ => Err(TradeListingDvmError::UnsupportedKind),
    }
}

async fn handle_order_request(
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let record = order_event_record_from_event(&rr_event).map_err(map_order_decode_error)?;
    let order_id = record.order_id().clone();
    let projection = reduce_order_event_records(&order_id, [record.clone()]);
    if projection.status != RadrootsTradeWorkflowState::Requested || !projection.issues.is_empty() {
        return Err(TradeListingDvmError::Workflow(workflow_rejection_message(
            &projection,
        )));
    }
    let RadrootsOrderEventRecord::Request(request) = record else {
        return Err(TradeListingDvmError::UnsupportedKind);
    };
    let listing_addr = parse_public_listing_address(&request.payload.listing_addr)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    if request.payload.seller_pubkey != listing_addr.seller_pubkey {
        return Err(TradeListingDvmError::InvalidListingAddr);
    }
    let listing_event = parse_order_listing_event_tag(&rr_event.tags)
        .map_err(|error| TradeListingDvmError::InvalidPayload(error.to_string()))?
        .ok_or(TradeListingDvmError::MissingTag("listing_event"))?;
    let listing_snapshot_event_id =
        ensure_listing_snapshot(&request.payload.listing_addr, &listing_event, client, state)
            .await?;
    let event_id = event.id.to_string();
    let mut state = state.lock().await;
    if state.order_exists(order_id.as_str()) {
        return Ok(());
    }
    let mut seen = std::collections::HashSet::new();
    seen.insert(event_id.clone());
    state.insert_order(TradeOrderState {
        order_id: order_id.to_string(),
        listing_addr: request.payload.listing_addr.to_string(),
        buyer_pubkey: request.payload.buyer_pubkey.to_string(),
        seller_pubkey: request.payload.seller_pubkey.to_string(),
        status: projection.status,
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

async fn handle_order_workflow_event(
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingDvmError> {
    let rr_event = radroots_event_from_nostr(event);
    let current_record =
        order_event_record_from_event(&rr_event).map_err(map_order_decode_error)?;
    let order_id = current_record.order_id().clone();
    let event_id = event.id.to_string();
    let order_snapshot = {
        let state = state.lock().await;
        if state.is_event_seen(order_id.as_str(), &event_id) {
            return Ok(());
        }
        state
            .get_order(order_id.as_str())
            .cloned()
            .ok_or(TradeListingStateError::MissingOrder)?
    };
    let mut records =
        fetch_seen_order_records(client, &order_snapshot, event, current_record).await?;
    let projection = reduce_order_event_records(&order_id, records.drain(..));
    if projection.status != RadrootsTradeWorkflowState::Invalid && !projection.issues.is_empty() {
        return Err(TradeListingDvmError::Workflow(workflow_rejection_message(
            &projection,
        )));
    }
    let mut state = state.lock().await;
    if state.is_event_seen(order_id.as_str(), &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id.as_str())
        .ok_or(TradeListingStateError::MissingOrder)?;
    ensure_projection_binding(order, &projection)?;
    order.status = projection.status;
    order.last_event_id = projection
        .last_event_id
        .map(|last_event_id| last_event_id.to_string())
        .or_else(|| Some(event_id.clone()));
    order.seen_event_ids.insert(event_id);
    Ok(())
}

async fn fetch_seen_order_records(
    client: &RadrootsNostrClient,
    order: &TradeOrderState,
    current_event: &RadrootsNostrEvent,
    current_record: RadrootsOrderEventRecord,
) -> Result<Vec<RadrootsOrderEventRecord>, TradeListingDvmError> {
    let current_event_id = current_event.id.to_string();
    let mut event_ids = order
        .seen_event_ids
        .iter()
        .filter(|event_id| event_id.as_str() != current_event_id)
        .cloned()
        .collect::<Vec<_>>();
    event_ids.sort();
    let mut records = Vec::with_capacity(event_ids.len() + 1);
    for event_id in event_ids {
        let event = fetch_event_by_id_io(client, &event_id).await?;
        let rr_event = radroots_event_from_nostr(&event);
        let record = order_event_record_from_event(&rr_event).map_err(map_order_decode_error)?;
        if record.order_id().as_str() != order.order_id {
            return Err(TradeListingDvmError::InvalidOrder);
        }
        records.push(record);
    }
    records.push(current_record);
    Ok(records)
}

fn ensure_projection_binding(
    order: &TradeOrderState,
    projection: &RadrootsOrderProjection,
) -> Result<(), TradeListingDvmError> {
    if projection
        .listing_addr
        .as_ref()
        .is_some_and(|listing_addr| listing_addr.to_string() != order.listing_addr)
        || projection
            .buyer_pubkey
            .as_ref()
            .is_some_and(|buyer_pubkey| buyer_pubkey.to_string() != order.buyer_pubkey)
        || projection
            .seller_pubkey
            .as_ref()
            .is_some_and(|seller_pubkey| seller_pubkey.to_string() != order.seller_pubkey)
    {
        return Err(TradeListingDvmError::InvalidOrder);
    }
    Ok(())
}

fn workflow_rejection_message(projection: &RadrootsOrderProjection) -> String {
    format!("{:?}:{:?}", projection.status, projection.issues)
}

fn map_order_decode_error(
    error: radroots_trade::order::RadrootsOrderEventDecodeError,
) -> TradeListingDvmError {
    match error {
        radroots_trade::order::RadrootsOrderEventDecodeError::Envelope(error) => {
            map_order_parse_error(error)
        }
        radroots_trade::order::RadrootsOrderEventDecodeError::UnsupportedKind { .. } => {
            TradeListingDvmError::UnsupportedKind
        }
        other => TradeListingDvmError::InvalidPayload(other.to_string()),
    }
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn fetch_listing_by_addr(
    client: &RadrootsNostrClient,
    listing_addr: &str,
) -> Result<Option<RadrootsNostrEvent>, TradeListingDvmError> {
    let addr = parse_listing_address(listing_addr)
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let author = radroots_nostr_parse_pubkey(addr.seller_pubkey.as_str())
        .map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let kind = u16::try_from(addr.kind).map_err(|_| TradeListingDvmError::InvalidListingAddr)?;
    let filter = RadrootsNostrFilter::new()
        .kind(RadrootsNostrKind::Custom(kind))
        .author(author)
        .identifier(addr.listing_id.into_string());
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
        DvmTestHooks, TradeListingDvmError, dvm_test_hooks, handle_error, handle_event,
        tag_has_value,
    };
    use crate::features::trade_listing::state::TradeListingState;
    use radroots_core::{
        RadrootsCoreCurrency, RadrootsCoreDecimal, RadrootsCoreMoney, RadrootsCoreUnit,
    };
    use radroots_events::RadrootsNostrEventPtr;
    use radroots_events::farm::RadrootsFarmRef;
    use radroots_events::ids::{
        RadrootsEventId, RadrootsInventoryBinId, RadrootsListingAddress, RadrootsOrderId,
        RadrootsOrderQuoteId, RadrootsPublicKey,
    };
    use radroots_events::kinds::{
        KIND_LISTING, KIND_ORDER_REQUEST, KIND_TRADE_LISTING_VALIDATION_REQUEST,
    };
    use radroots_events::order::{
        RadrootsOrderCancellation, RadrootsOrderDecision, RadrootsOrderDecisionOutcome,
        RadrootsOrderEconomicItem, RadrootsOrderEconomicLine, RadrootsOrderEconomics,
        RadrootsOrderInventoryCommitment, RadrootsOrderItem, RadrootsOrderPricingBasis,
        RadrootsOrderRequest,
    };
    use radroots_events::trade_validation::RadrootsTradeValidationListingRequest;
    use radroots_events_codec::order::{
        order_cancellation_event_build, order_decision_event_build, order_request_event_build,
    };
    use radroots_nostr::prelude::{
        RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrKeys,
        RadrootsNostrKind, radroots_nostr_build_event,
    };
    use radroots_trade::workflow::RadrootsTradeWorkflowState;
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

    fn listing_event_id() -> &'static str {
        "0000000000000000000000000000000000000000000000000000000000000001"
    }

    fn typed_listing_addr(seller: &RadrootsNostrKeys) -> RadrootsListingAddress {
        RadrootsListingAddress::parse(listing_addr(seller)).expect("listing address")
    }

    fn typed_order_id(order_id: &str) -> RadrootsOrderId {
        RadrootsOrderId::parse(order_id).expect("order id")
    }

    fn typed_quote_id(order_id: &str) -> RadrootsOrderQuoteId {
        RadrootsOrderQuoteId::parse(format!("{order_id}-quote")).expect("quote id")
    }

    fn typed_bin_id() -> RadrootsInventoryBinId {
        RadrootsInventoryBinId::parse("bin-1").expect("bin id")
    }

    fn typed_pubkey(keys: &RadrootsNostrKeys) -> RadrootsPublicKey {
        RadrootsPublicKey::parse(keys.public_key().to_string()).expect("public key")
    }

    fn typed_event_id(event: &RadrootsNostrEvent) -> RadrootsEventId {
        RadrootsEventId::parse(event.id.to_string()).expect("event id")
    }

    fn listing_event_ptr() -> RadrootsNostrEventPtr {
        RadrootsNostrEventPtr {
            id: listing_event_id().to_string(),
            relays: None,
        }
    }

    fn order_economics(order_id: &str) -> RadrootsOrderEconomics {
        RadrootsOrderEconomics {
            quote_id: typed_quote_id(order_id),
            quote_version: 1,
            pricing_basis: RadrootsOrderPricingBasis::ListingEvent,
            currency: RadrootsCoreCurrency::USD,
            items: vec![RadrootsOrderEconomicItem {
                bin_id: typed_bin_id(),
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
            order_id: typed_order_id(order_id),
            listing_addr: typed_listing_addr(seller),
            buyer_pubkey: typed_pubkey(buyer),
            seller_pubkey: typed_pubkey(seller),
            items: vec![RadrootsOrderItem {
                bin_id: typed_bin_id(),
                bin_count: 2,
            }],
            economics: order_economics(order_id),
        }
    }

    fn order_decision(
        order_id: &str,
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
    ) -> RadrootsOrderDecision {
        RadrootsOrderDecision {
            order_id: typed_order_id(order_id),
            listing_addr: typed_listing_addr(seller),
            buyer_pubkey: typed_pubkey(buyer),
            seller_pubkey: typed_pubkey(seller),
            decision: RadrootsOrderDecisionOutcome::Accepted {
                inventory_commitments: vec![RadrootsOrderInventoryCommitment {
                    bin_id: typed_bin_id(),
                    bin_count: 2,
                }],
            },
        }
    }

    fn order_cancellation(
        order_id: &str,
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
    ) -> RadrootsOrderCancellation {
        RadrootsOrderCancellation {
            order_id: typed_order_id(order_id),
            listing_addr: typed_listing_addr(seller),
            buyer_pubkey: typed_pubkey(buyer),
            seller_pubkey: typed_pubkey(seller),
            reason: "cancel after agreement".to_string(),
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

    fn signed_order_decision_event(
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
        request_event: &RadrootsNostrEvent,
    ) -> RadrootsNostrEvent {
        let payload = order_decision("order-1", buyer, seller);
        let root_event_id = typed_event_id(request_event);
        let wire =
            order_decision_event_build(&root_event_id, &root_event_id, &payload).expect("wire");
        radroots_nostr_build_event(wire.kind, wire.content, wire.tags)
            .expect("builder")
            .sign_with_keys(seller)
            .expect("event")
    }

    fn signed_order_cancellation_event(
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
        request_event: &RadrootsNostrEvent,
        decision_event: &RadrootsNostrEvent,
    ) -> RadrootsNostrEvent {
        let payload = order_cancellation("order-1", buyer, seller);
        let root_event_id = typed_event_id(request_event);
        let prev_event_id = typed_event_id(decision_event);
        let wire =
            order_cancellation_event_build(&root_event_id, &prev_event_id, &payload).expect("wire");
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
            listing_event_id(),
            KIND_LISTING,
        );

        let request_event = signed_order_request_event(&buyer, &seller);
        handle_event(request_event, Vec::new(), worker, client, state.clone())
            .await
            .expect("order request");

        let mut state = state.lock().await;
        let order = state.get_order_mut("order-1").expect("order");
        assert_eq!(order.status, RadrootsTradeWorkflowState::Requested);
        assert_eq!(order.buyer_pubkey, buyer.public_key().to_string());
        assert_eq!(order.seller_pubkey, seller.public_key().to_string());
    }

    #[tokio::test]
    async fn order_decision_uses_shared_workflow_pending_rhi_state() {
        let _guard = test_guard().await;
        let worker = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(worker.clone());
        let state = Arc::new(Mutex::new(TradeListingState::default()));
        state.lock().await.upsert_listing_event(
            &listing_addr(&seller),
            listing_event_id(),
            KIND_LISTING,
        );
        let request_event = signed_order_request_event(&buyer, &seller);
        handle_event(
            request_event.clone(),
            Vec::new(),
            worker.clone(),
            client.clone(),
            state.clone(),
        )
        .await
        .expect("order request");
        let decision_event = signed_order_decision_event(&buyer, &seller, &request_event);
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(request_event));

        handle_event(decision_event, Vec::new(), worker, client, state.clone())
            .await
            .expect("order decision");

        let mut state = state.lock().await;
        let order = state.get_order_mut("order-1").expect("order");
        assert_eq!(order.status, RadrootsTradeWorkflowState::AgreedPendingRhi);
    }

    #[tokio::test]
    async fn cancellation_after_pending_agreement_uses_shared_workflow_invalid_state() {
        let _guard = test_guard().await;
        let worker = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(worker.clone());
        let state = Arc::new(Mutex::new(TradeListingState::default()));
        state.lock().await.upsert_listing_event(
            &listing_addr(&seller),
            listing_event_id(),
            KIND_LISTING,
        );
        let request_event = signed_order_request_event(&buyer, &seller);
        handle_event(
            request_event.clone(),
            Vec::new(),
            worker.clone(),
            client.clone(),
            state.clone(),
        )
        .await
        .expect("order request");
        let decision_event = signed_order_decision_event(&buyer, &seller, &request_event);
        dvm_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(request_event.clone()));
        handle_event(
            decision_event.clone(),
            Vec::new(),
            worker.clone(),
            client.clone(),
            state.clone(),
        )
        .await
        .expect("order decision");
        let cancellation_event =
            signed_order_cancellation_event(&buyer, &seller, &request_event, &decision_event);
        {
            let mut hooks = dvm_test_hooks().lock().expect("hooks");
            hooks.fetch_event_by_id_results.push_back(Ok(request_event));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event));
        }

        handle_event(
            cancellation_event,
            Vec::new(),
            worker,
            client,
            state.clone(),
        )
        .await
        .expect("order cancellation");

        let mut state = state.lock().await;
        let order = state.get_order_mut("order-1").expect("order");
        assert_eq!(order.status, RadrootsTradeWorkflowState::Invalid);
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
    fn tag_helpers_cover_core_paths() {
        assert!(tag_has_value(
            &[vec!["p".to_string(), "pubkey".to_string()]],
            "p",
            "pubkey"
        ));
        assert!(!tag_has_value(
            &[vec!["p".to_string(), "pubkey".to_string()]],
            "p",
            "other"
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
