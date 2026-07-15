#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use std::sync::Arc;

use radroots_event::farm::RadrootsFarmRef;
use radroots_event::ids::{RadrootsEventId, RadrootsPublicKey};
use radroots_event::kinds::{
    KIND_JOB_FEEDBACK, KIND_ORDER_CANCELLATION, KIND_ORDER_DECISION, KIND_ORDER_REQUEST,
    KIND_TRADE_VALIDATION_RECEIPT, is_listing_kind, is_order_event_kind,
    is_trade_validation_service_event_kind,
};
use radroots_event::trade_validation::RadrootsTradeValidationListingError as TradeListingValidationError;
use radroots_event_codec::order::{RadrootsOrderEnvelopeParseError, parse_order_listing_event_tag};
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrKeys,
    RadrootsNostrKind, RadrootsNostrTag, radroots_event_from_nostr, radroots_nostr_build_event,
    radroots_nostr_fetch_event_by_id, radroots_nostr_send_event,
};
use radroots_trade::listing::{parse_public_listing_address, validation::validate_listing_event};
use radroots_trade::order::{
    RadrootsOrderEventRecord, RadrootsOrderProjection, order_event_record_from_event,
    reduce_order_event_records,
};
use radroots_trade::workflow::RadrootsTradeWorkflowState;
use thiserror::Error;

use crate::features::trade_listing::state::{
    TradeListingRuntime, TradeListingState, TradeListingStateError, TradeOrderState,
};
use crate::features::trade_validation_receipt::{
    TradeValidationReceiptJobError, TradeValidationReceiptProverPolicy, publish_validation_receipt,
};

#[derive(Debug, Error)]
pub enum TradeListingEventError {
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
struct TradeListingEventTestHooks {
    fetch_event_by_id_results:
        std::collections::VecDeque<Result<RadrootsNostrEvent, TradeListingEventError>>,
    send_event_results: std::collections::VecDeque<Result<(), TradeListingEventError>>,
    validate_listing_results:
        std::collections::VecDeque<Result<(String, RadrootsFarmRef), TradeListingValidationError>>,
}

#[cfg(test)]
static TRADE_LISTING_EVENT_TEST_HOOKS: std::sync::OnceLock<
    std::sync::Mutex<TradeListingEventTestHooks>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn trade_listing_event_test_hooks() -> &'static std::sync::Mutex<TradeListingEventTestHooks> {
    TRADE_LISTING_EVENT_TEST_HOOKS
        .get_or_init(|| std::sync::Mutex::new(TradeListingEventTestHooks::default()))
}

#[cfg(test)]
fn pop_fetch_event_by_id_hook() -> Option<Result<RadrootsNostrEvent, TradeListingEventError>> {
    trade_listing_event_test_hooks()
        .lock()
        .expect("trade listing event test hooks lock")
        .fetch_event_by_id_results
        .pop_front()
}

#[cfg(test)]
fn pop_send_event_hook() -> Option<Result<(), TradeListingEventError>> {
    trade_listing_event_test_hooks()
        .lock()
        .expect("trade listing event test hooks lock")
        .send_event_results
        .pop_front()
}

#[cfg(test)]
fn pop_validate_listing_hook()
-> Option<Result<(String, RadrootsFarmRef), TradeListingValidationError>> {
    trade_listing_event_test_hooks()
        .lock()
        .expect("trade listing event test hooks lock")
        .validate_listing_results
        .pop_front()
}

#[cfg(test)]
fn take_fetch_event_by_id_hook() -> Option<Result<RadrootsNostrEvent, TradeListingEventError>> {
    pop_fetch_event_by_id_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_fetch_event_by_id_hook() -> Option<Result<RadrootsNostrEvent, TradeListingEventError>> {
    None
}

#[cfg(test)]
fn take_send_event_hook() -> Option<Result<(), TradeListingEventError>> {
    pop_send_event_hook()
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
fn take_send_event_hook() -> Option<Result<(), TradeListingEventError>> {
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
) -> Result<RadrootsNostrEvent, TradeListingEventError> {
    match take_fetch_event_by_id_hook() {
        Some(result) => result,
        None => radroots_nostr_fetch_event_by_id(client, id)
            .await
            .map_err(TradeListingEventError::from),
    }
}

#[cfg_attr(all(not(test), coverage_nightly), coverage(off))]
async fn send_event_io(
    client: &RadrootsNostrClient,
    builder: RadrootsNostrEventBuilder,
) -> Result<(), TradeListingEventError> {
    match take_send_event_hook() {
        Some(result) => result,
        None => radroots_nostr_send_event(client, builder)
            .await
            .map(|_| ())
            .map_err(TradeListingEventError::from),
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
    runtime: TradeListingRuntime,
    proof_policy: &TradeValidationReceiptProverPolicy,
) -> Result<(), TradeListingEventError> {
    let kind = event_kind_u32(&event)?;
    let state = runtime.state();
    if is_listing_kind(kind) {
        return handle_listing_event(&event, &state).await;
    }
    if event.pubkey == keys.public_key() {
        return Ok(());
    }
    if kind == KIND_TRADE_VALIDATION_RECEIPT {
        state
            .lock()
            .await
            .mark_non_order_event_seen(&event.id.to_string());
        return Ok(());
    }
    if is_order_event_kind(kind) {
        return handle_order_event(&event, kind, &keys, &client, &runtime, proof_policy).await;
    }
    if is_trade_validation_service_event_kind(kind) {
        return Err(TradeListingEventError::UnsupportedKind);
    }
    Err(TradeListingEventError::UnsupportedKind)
}

#[cfg(test)]
pub async fn handle_event(
    event: RadrootsNostrEvent,
    tags: Vec<RadrootsNostrTag>,
    keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    runtime: TradeListingRuntime,
) -> Result<(), TradeListingEventError> {
    handle_event_with_policy(
        event,
        tags,
        keys,
        client,
        runtime,
        &TradeValidationReceiptProverPolicy::default(),
    )
    .await
}

fn event_kind_u32(event: &RadrootsNostrEvent) -> Result<u32, TradeListingEventError> {
    match event.kind {
        RadrootsNostrKind::Custom(value) => Ok(u32::from(value)),
        _ => Err(TradeListingEventError::UnsupportedKind),
    }
}

fn map_trade_validation_receipt_job_error(
    error: TradeValidationReceiptJobError,
) -> TradeListingEventError {
    match error {
        TradeValidationReceiptJobError::UnsupportedKind => TradeListingEventError::UnsupportedKind,
        TradeValidationReceiptJobError::MissingRecipient => {
            TradeListingEventError::MissingRecipient
        }
        TradeValidationReceiptJobError::Nostr(error) => TradeListingEventError::Nostr(error),
        other => TradeListingEventError::InvalidPayload(other.to_string()),
    }
}

fn map_order_parse_error(error: RadrootsOrderEnvelopeParseError) -> TradeListingEventError {
    match error {
        RadrootsOrderEnvelopeParseError::InvalidKind(_) => TradeListingEventError::UnsupportedKind,
        RadrootsOrderEnvelopeParseError::MissingTag(tag) => TradeListingEventError::MissingTag(tag),
        RadrootsOrderEnvelopeParseError::ListingAddrTagMismatch => {
            TradeListingEventError::TagMismatch("a")
        }
        RadrootsOrderEnvelopeParseError::OrderIdTagMismatch => {
            TradeListingEventError::TagMismatch("d")
        }
        RadrootsOrderEnvelopeParseError::InvalidListingAddr(_) => {
            TradeListingEventError::InvalidListingAddr
        }
        RadrootsOrderEnvelopeParseError::InvalidEnvelope(error) => {
            TradeListingEventError::InvalidEnvelope(error.to_string())
        }
        other => TradeListingEventError::InvalidPayload(other.to_string()),
    }
}

async fn handle_listing_event(
    event: &RadrootsNostrEvent,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingEventError> {
    let event_id = event.id.to_string();
    {
        let state = state.lock().await;
        if state.is_non_order_event_seen(&event_id) {
            return Ok(());
        }
    }
    let validated = validate_listing_event(&radroots_event_from_nostr(event))
        .map_err(|error| TradeListingEventError::InvalidPayload(error.to_string()))?;
    let kind = event_kind_u32(event)?;
    let mut state = state.lock().await;
    state.upsert_listing_event(&validated.listing_addr, &event_id, kind);
    state.mark_non_order_event_seen(&event_id);
    Ok(())
}

async fn handle_order_event(
    event: &RadrootsNostrEvent,
    kind: u32,
    keys: &RadrootsNostrKeys,
    client: &RadrootsNostrClient,
    runtime: &TradeListingRuntime,
    proof_policy: &TradeValidationReceiptProverPolicy,
) -> Result<(), TradeListingEventError> {
    let state = runtime.state();
    match kind {
        KIND_ORDER_REQUEST => handle_order_request(event, client, &state).await,
        KIND_ORDER_DECISION | KIND_ORDER_CANCELLATION => {
            handle_order_workflow_event(event, client, runtime, keys, proof_policy).await
        }
        _ => Err(TradeListingEventError::UnsupportedKind),
    }
}

async fn handle_order_request(
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<(), TradeListingEventError> {
    let rr_event = radroots_event_from_nostr(event);
    let record = order_event_record_from_event(&rr_event).map_err(map_order_decode_error)?;
    let order_id = record.order_id().clone();
    let projection = reduce_order_event_records(&order_id, [record.clone()]);
    if projection.status != RadrootsTradeWorkflowState::Requested || !projection.issues.is_empty() {
        return Err(TradeListingEventError::Workflow(
            workflow_rejection_message(&projection),
        ));
    }
    let RadrootsOrderEventRecord::Request(request) = record else {
        return Err(TradeListingEventError::UnsupportedKind);
    };
    let listing_addr = parse_public_listing_address(&request.payload.listing_addr)
        .map_err(|_| TradeListingEventError::InvalidListingAddr)?;
    if request.payload.seller_pubkey != listing_addr.seller_pubkey {
        return Err(TradeListingEventError::InvalidListingAddr);
    }
    let rr_tags = rr_event.tags_as_vec();
    let listing_event = parse_order_listing_event_tag(&rr_tags)
        .map_err(|error| TradeListingEventError::InvalidPayload(error.to_string()))?
        .ok_or(TradeListingEventError::MissingTag("listing_event"))?;
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
    listing_event: &radroots_event::RadrootsEventPtr,
    client: &RadrootsNostrClient,
    state: &Arc<tokio::sync::Mutex<TradeListingState>>,
) -> Result<String, TradeListingEventError> {
    {
        let state = state.lock().await;
        if state.listing_event_id(listing_addr) == Some(listing_event.id.as_str()) {
            return Ok(listing_event.id.clone());
        }
    }
    let event = fetch_event_by_id_io(client, &listing_event.id).await?;
    let (validated_listing_addr, _) = validate_listing_event_io(&event)
        .map_err(|error| TradeListingEventError::InvalidPayload(error.to_string()))?;
    if validated_listing_addr != listing_addr {
        return Err(TradeListingEventError::InvalidOrder);
    }
    let kind = event_kind_u32(&event)?;
    let mut state = state.lock().await;
    state.upsert_listing_event(listing_addr, &listing_event.id, kind);
    Ok(listing_event.id.clone())
}

async fn handle_order_workflow_event(
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
    runtime: &TradeListingRuntime,
    keys: &RadrootsNostrKeys,
    proof_policy: &TradeValidationReceiptProverPolicy,
) -> Result<(), TradeListingEventError> {
    let state = runtime.state();
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
        return Err(TradeListingEventError::Workflow(
            workflow_rejection_message(&projection),
        ));
    }
    let mut state = state.lock().await;
    if state.is_event_seen(order_id.as_str(), &event_id) {
        return Ok(());
    }
    let order = state
        .get_order_mut(order_id.as_str())
        .ok_or(TradeListingStateError::MissingOrder)?;
    ensure_projection_binding(order, &projection)?;
    let projected_status = projection.status.clone();
    order.status = projected_status.clone();
    order.last_event_id = projection
        .last_event_id
        .map(|last_event_id| last_event_id.to_string())
        .or_else(|| Some(event_id.clone()));
    order.seen_event_ids.insert(event_id);
    drop(state);
    if projected_status == RadrootsTradeWorkflowState::AgreedPendingValidation {
        publish_validation_receipt(event, client, runtime, keys, proof_policy)
            .await
            .map_err(map_trade_validation_receipt_job_error)?;
    }
    Ok(())
}

async fn fetch_seen_order_records(
    client: &RadrootsNostrClient,
    order: &TradeOrderState,
    current_event: &RadrootsNostrEvent,
    current_record: RadrootsOrderEventRecord,
) -> Result<Vec<RadrootsOrderEventRecord>, TradeListingEventError> {
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
            return Err(TradeListingEventError::InvalidOrder);
        }
        records.push(record);
    }
    records.push(current_record);
    Ok(records)
}

fn ensure_projection_binding(
    order: &TradeOrderState,
    projection: &RadrootsOrderProjection,
) -> Result<(), TradeListingEventError> {
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
        return Err(TradeListingEventError::InvalidOrder);
    }
    Ok(())
}

fn workflow_rejection_message(projection: &RadrootsOrderProjection) -> String {
    format!("{:?}:{:?}", projection.status, projection.issues)
}

fn map_order_decode_error(
    error: radroots_trade::order::RadrootsOrderEventDecodeError,
) -> TradeListingEventError {
    match error {
        radroots_trade::order::RadrootsOrderEventDecodeError::Envelope(error) => {
            map_order_parse_error(error)
        }
        radroots_trade::order::RadrootsOrderEventDecodeError::UnsupportedKind { .. } => {
            TradeListingEventError::UnsupportedKind
        }
        other => TradeListingEventError::InvalidPayload(other.to_string()),
    }
}

#[cfg(test)]
fn tag_has_value(tags: &[Vec<String>], key: &str, value: &str) -> bool {
    tags.iter().any(|tag| {
        tag.first().map(String::as_str) == Some(key)
            && tag.get(1).map(String::as_str) == Some(value)
    })
}

pub async fn handle_error(
    error: TradeListingEventError,
    event: &RadrootsNostrEvent,
    client: &RadrootsNostrClient,
) -> Result<(), TradeListingEventError> {
    let request_event_id = RadrootsEventId::parse(event.id.to_hex())
        .map_err(|err| TradeListingEventError::InvalidPayload(err.to_string()))?;
    let customer_pubkey = RadrootsPublicKey::parse(event.pubkey.to_hex())
        .map_err(|err| TradeListingEventError::InvalidPayload(err.to_string()))?;
    let tags = vec![
        vec!["e".to_string(), request_event_id.into_string()],
        vec!["p".to_string(), customer_pubkey.into_string()],
        vec!["status".to_string(), "error".to_string()],
    ];
    let builder = radroots_nostr_build_event(KIND_JOB_FEEDBACK, error.to_string(), tags)?;
    send_event_io(client, builder).await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        TradeListingEventError, TradeListingEventTestHooks, handle_error, handle_event,
        tag_has_value, trade_listing_event_test_hooks,
    };
    use crate::features::trade_listing::state::TradeListingRuntime;
    use radroots_core::{
        RadrootsCoreCurrency, RadrootsCoreDecimal, RadrootsCoreMoney, RadrootsCoreUnit,
    };
    use radroots_event::RadrootsEventPtr;
    use radroots_event::ids::{
        RadrootsEventId, RadrootsInventoryBinId, RadrootsListingAddress, RadrootsOrderId,
        RadrootsOrderQuoteId, RadrootsPublicKey,
    };
    use radroots_event::kinds::{KIND_LISTING, KIND_ORDER_REQUEST};
    use radroots_event::order::{
        RadrootsOrderCancellation, RadrootsOrderDecision, RadrootsOrderDecisionOutcome,
        RadrootsOrderEconomicItem, RadrootsOrderEconomicLine, RadrootsOrderEconomics,
        RadrootsOrderInventoryCommitment, RadrootsOrderItem, RadrootsOrderPricingBasis,
        RadrootsOrderRequest,
    };
    use radroots_event_codec::order::{
        order_cancellation_event_build, order_decision_event_build, order_request_event_build,
    };
    use radroots_nostr::prelude::{
        RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrKeys,
        RadrootsNostrKind, radroots_nostr_build_event,
    };
    use radroots_trade::workflow::RadrootsTradeWorkflowState;
    use tokio::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::const_new(());

    async fn test_guard() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().await;
        *trade_listing_event_test_hooks().lock().expect("hooks") =
            TradeListingEventTestHooks::default();
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

    fn listing_event_ptr() -> RadrootsEventPtr {
        RadrootsEventPtr {
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

    #[tokio::test]
    async fn order_request_inserts_canonical_order_state() {
        let _guard = test_guard().await;
        let worker = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(worker.clone());
        let runtime = TradeListingRuntime::new();
        let state = runtime.state();
        state.lock().await.upsert_listing_event(
            &listing_addr(&seller),
            listing_event_id(),
            KIND_LISTING,
        );

        let request_event = signed_order_request_event(&buyer, &seller);
        handle_event(request_event, Vec::new(), worker, client, runtime.clone())
            .await
            .expect("order request");

        let mut state = state.lock().await;
        let order = state.get_order_mut("order-1").expect("order");
        assert_eq!(order.status, RadrootsTradeWorkflowState::Requested);
        assert_eq!(order.buyer_pubkey, buyer.public_key().to_string());
        assert_eq!(order.seller_pubkey, seller.public_key().to_string());
    }

    #[tokio::test]
    async fn order_decision_uses_shared_workflow_pending_validation_state() {
        let _guard = test_guard().await;
        let worker = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(worker.clone());
        let runtime = TradeListingRuntime::new();
        let state = runtime.state();
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
            runtime.clone(),
        )
        .await
        .expect("order request");
        let decision_event = signed_order_decision_event(&buyer, &seller, &request_event);
        trade_listing_event_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(request_event));

        let error = handle_event(decision_event, Vec::new(), worker, client, runtime.clone())
            .await
            .expect_err("missing validator-set policy must fail closed");
        assert!(matches!(error, TradeListingEventError::InvalidPayload(_)));

        let mut state = state.lock().await;
        let order = state.get_order_mut("order-1").expect("order");
        assert_eq!(
            order.status,
            RadrootsTradeWorkflowState::AgreedPendingValidation
        );
    }

    #[tokio::test]
    async fn cancellation_after_pending_agreement_uses_shared_workflow_invalid_state() {
        let _guard = test_guard().await;
        let worker = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(worker.clone());
        let runtime = TradeListingRuntime::new();
        let state = runtime.state();
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
            runtime.clone(),
        )
        .await
        .expect("order request");
        let decision_event = signed_order_decision_event(&buyer, &seller, &request_event);
        trade_listing_event_test_hooks()
            .lock()
            .expect("hooks")
            .fetch_event_by_id_results
            .push_back(Ok(request_event.clone()));
        let decision_error = handle_event(
            decision_event.clone(),
            Vec::new(),
            worker.clone(),
            client.clone(),
            runtime.clone(),
        )
        .await
        .expect_err("missing validator-set policy must fail closed");
        assert!(matches!(
            decision_error,
            TradeListingEventError::InvalidPayload(_)
        ));
        let cancellation_event =
            signed_order_cancellation_event(&buyer, &seller, &request_event, &decision_event);
        {
            let mut hooks = trade_listing_event_test_hooks().lock().expect("hooks");
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
            runtime.clone(),
        )
        .await
        .expect("order cancellation");

        let mut state = state.lock().await;
        let order = state.get_order_mut("order-1").expect("order");
        assert_eq!(order.status, RadrootsTradeWorkflowState::Invalid);
    }

    #[tokio::test]
    async fn unsupported_kind_is_rejected() {
        let _guard = test_guard().await;
        let worker = RadrootsNostrKeys::generate();
        let client = RadrootsNostrClient::new(worker.clone());
        let runtime = TradeListingRuntime::new();
        let event = RadrootsNostrEventBuilder::new(RadrootsNostrKind::Custom(4999), "test")
            .sign_with_keys(&RadrootsNostrKeys::generate())
            .expect("event");
        assert!(matches!(
            handle_event(event, Vec::new(), worker, client, runtime).await,
            Err(TradeListingEventError::UnsupportedKind)
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
        trade_listing_event_test_hooks()
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
            handle_error(TradeListingEventError::InvalidOrder, &event, &client)
                .await
                .is_ok()
        );
    }
}
