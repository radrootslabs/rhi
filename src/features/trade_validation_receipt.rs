#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, coverage(off))]

use radroots_events::kinds::{
    KIND_TRADE_VALIDATION_RECEIPT, KIND_WORKER_TRADE_TRANSITION_PROOF_REQ,
    KIND_WORKER_TRADE_TRANSITION_PROOF_RES, is_listing_kind,
};
use radroots_events_codec::trade::{
    active_trade_order_decision_from_event, active_trade_order_request_from_event,
    parse_trade_listing_event_tag, parse_trade_prev_tag, parse_trade_root_tag,
};
use radroots_nostr::prelude::{
    RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrKeys,
    RadrootsNostrKind, radroots_event_from_nostr, radroots_nostr_build_event,
    radroots_nostr_fetch_event_by_id, radroots_nostr_send_event,
};
use radroots_sp1_guest_trade::{
    RadrootsSp1TradeInventoryBinWitness, RadrootsSp1TradeOrderAcceptanceWitness,
};
use radroots_sp1_host_trade::{
    RadrootsSp1TradeHostError, RadrootsSp1TradeProofMode, generate_order_acceptance_proof,
    validation_receipt_for_order_acceptance_proof, verify_order_acceptance_proof_artifact,
};
use radroots_trade::validation_receipt::{
    RadrootsValidationReceiptError, RadrootsValidationReceiptExpectedBinding,
    validation_receipt_event_build, verify_validation_receipt_event,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeValidationReceiptJobRequest {
    pub listing_event_id: String,
    pub request_event_id: String,
    pub decision_event_id: String,
    pub inventory_bins: Vec<RadrootsSp1TradeInventoryBinWitness>,
    pub inventory_sequence: u128,
    pub previous_state_root: Option<String>,
    pub proof_mode: RadrootsSp1TradeProofMode,
    pub reducer_program_hash: String,
    pub radroots_protocol_version: String,
    pub sp1_verifying_key_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TradeValidationReceiptJobResult {
    pub decision_event_id: String,
    pub event_set_root: String,
    pub listing_event_id: String,
    pub order_id: String,
    pub proof_system: String,
    pub public_values_hash: String,
    pub receipt_event_id: String,
    pub receipt_kind: u32,
    pub reducer_output_root: String,
    pub request_event_id: String,
    pub status: TradeValidationReceiptJobStatus,
    pub worker_role: TradeValidationReceiptWorkerRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeValidationReceiptJobStatus {
    Succeeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TradeValidationReceiptWorkerRole {
    NonAuthoritativeProver,
}

#[derive(Debug, Error)]
pub enum TradeValidationReceiptJobError {
    #[error("event kind not supported")]
    UnsupportedKind,
    #[error("missing recipient tag")]
    MissingRecipient,
    #[error("invalid job request")]
    InvalidJobRequest,
    #[error("invalid listing event")]
    InvalidListingEvent,
    #[error("job request does not match fetched event set")]
    EventSetMismatch,
    #[error("invalid active trade event: {0}")]
    InvalidActiveTradeEvent(String),
    #[error("nostr error: {0}")]
    Nostr(#[from] radroots_nostr::error::RadrootsNostrError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("proof error: {0}")]
    Proof(#[from] RadrootsSp1TradeHostError),
    #[error("validation receipt error: {0}")]
    ValidationReceipt(#[from] RadrootsValidationReceiptError),
}

pub async fn handle_trade_validation_receipt_job_request(
    event: &RadrootsNostrEvent,
    keys: &RadrootsNostrKeys,
    client: &RadrootsNostrClient,
) -> Result<(), TradeValidationReceiptJobError> {
    let kind = event_kind_u32(event)?;
    if kind != KIND_WORKER_TRADE_TRANSITION_PROOF_REQ {
        return Err(TradeValidationReceiptJobError::UnsupportedKind);
    }

    let tags = event_tags(event);
    if !tag_has_value(&tags, "p", &keys.public_key().to_string()) {
        return Err(TradeValidationReceiptJobError::MissingRecipient);
    }

    let request: TradeValidationReceiptJobRequest = serde_json::from_str(&event.content)?;
    validate_job_request_shape(&request)?;

    let listing_event = fetch_event_by_id_io(client, &request.listing_event_id).await?;
    let order_request_event = fetch_event_by_id_io(client, &request.request_event_id).await?;
    let order_decision_event = fetch_event_by_id_io(client, &request.decision_event_id).await?;

    let listing_kind = event_kind_u32(&listing_event)
        .map_err(|_| TradeValidationReceiptJobError::InvalidListingEvent)?;
    if !is_listing_kind(listing_kind) {
        return Err(TradeValidationReceiptJobError::InvalidListingEvent);
    }

    let request_rr = radroots_event_from_nostr(&order_request_event);
    let decision_rr = radroots_event_from_nostr(&order_decision_event);

    let request_envelope = active_trade_order_request_from_event(&request_rr).map_err(|error| {
        TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
    })?;
    let decision_envelope =
        active_trade_order_decision_from_event(&decision_rr).map_err(|error| {
            TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
        })?;

    let listing_event_ptr = parse_trade_listing_event_tag(&request_rr.tags)
        .map_err(|error| {
            TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
        })?
        .ok_or(TradeValidationReceiptJobError::EventSetMismatch)?;
    if listing_event_ptr.id != request.listing_event_id {
        return Err(TradeValidationReceiptJobError::EventSetMismatch);
    }

    let root_event_id = parse_trade_root_tag(&decision_rr.tags).map_err(|error| {
        TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
    })?;
    let prev_event_id = parse_trade_prev_tag(&decision_rr.tags).map_err(|error| {
        TradeValidationReceiptJobError::InvalidActiveTradeEvent(error.to_string())
    })?;
    if root_event_id.as_deref() != Some(request.request_event_id.as_str())
        || prev_event_id.as_deref() != Some(request.request_event_id.as_str())
    {
        return Err(TradeValidationReceiptJobError::EventSetMismatch);
    }

    let witness = RadrootsSp1TradeOrderAcceptanceWitness {
        listing_event_id: request.listing_event_id.clone(),
        request_event_id: request.request_event_id.clone(),
        decision_event_id: request.decision_event_id.clone(),
        request: request_envelope.payload,
        decision: decision_envelope.payload,
        inventory_bins: request.inventory_bins.clone(),
        inventory_sequence: request.inventory_sequence,
        previous_state_root: request.previous_state_root.clone(),
        reducer_program_hash: request.reducer_program_hash.clone(),
        radroots_protocol_version: request.radroots_protocol_version.clone(),
        sp1_verifying_key_hash: request.sp1_verifying_key_hash.clone(),
    };
    let bundle = generate_order_acceptance_proof(&witness, request.proof_mode)?;
    verify_order_acceptance_proof_artifact(&bundle.execution, &bundle.proof)?;
    let receipt = validation_receipt_for_order_acceptance_proof(&bundle)?;
    let receipt_parts = validation_receipt_event_build(&witness.request.order_id, &receipt)?;
    let verified_receipt = verify_validation_receipt_event(
        &radroots_events::RadrootsNostrEvent {
            id: zero_event_id(),
            author: keys.public_key().to_string(),
            created_at: 0,
            kind: receipt_parts.kind,
            tags: receipt_parts.tags.clone(),
            content: receipt_parts.content.clone(),
            sig: zero_signature(),
        },
        RadrootsValidationReceiptExpectedBinding {
            event_set_root: Some(&receipt.event_set_root),
            order_id: Some(&witness.request.order_id),
            proof_system: Some(receipt.proof.system),
            public_values_hash: Some(&receipt.public_values_hash),
            reducer_output_root: Some(&receipt.new_state_root),
        },
    )?;
    let receipt_event_id = publish_event_parts_io(
        client,
        receipt_parts.kind,
        receipt_parts.content,
        receipt_parts.tags,
    )
    .await?;

    let result = TradeValidationReceiptJobResult {
        decision_event_id: request.decision_event_id,
        event_set_root: verified_receipt.receipt.event_set_root,
        listing_event_id: request.listing_event_id,
        order_id: witness.request.order_id,
        proof_system: verified_receipt.receipt.proof.system.as_str().to_string(),
        public_values_hash: verified_receipt.receipt.public_values_hash,
        receipt_event_id: receipt_event_id.clone(),
        receipt_kind: KIND_TRADE_VALIDATION_RECEIPT,
        reducer_output_root: verified_receipt.receipt.new_state_root,
        request_event_id: request.request_event_id,
        status: TradeValidationReceiptJobStatus::Succeeded,
        worker_role: TradeValidationReceiptWorkerRole::NonAuthoritativeProver,
    };
    let result_content = serde_json::to_string(&result)?;
    let result_tags = result_tags(event, &receipt_event_id, &result);
    publish_event_parts_io(
        client,
        KIND_WORKER_TRADE_TRANSITION_PROOF_RES,
        result_content,
        result_tags,
    )
    .await?;

    Ok(())
}

fn validate_job_request_shape(
    request: &TradeValidationReceiptJobRequest,
) -> Result<(), TradeValidationReceiptJobError> {
    if request.listing_event_id.trim().is_empty()
        || request.request_event_id.trim().is_empty()
        || request.decision_event_id.trim().is_empty()
        || request.reducer_program_hash.trim().is_empty()
        || request.radroots_protocol_version.trim().is_empty()
        || request.inventory_bins.is_empty()
    {
        return Err(TradeValidationReceiptJobError::InvalidJobRequest);
    }
    Ok(())
}

fn event_kind_u32(event: &RadrootsNostrEvent) -> Result<u32, TradeValidationReceiptJobError> {
    match event.kind {
        RadrootsNostrKind::Custom(value) => Ok(u32::from(value)),
        _ => Err(TradeValidationReceiptJobError::UnsupportedKind),
    }
}

fn event_tags(event: &RadrootsNostrEvent) -> Vec<Vec<String>> {
    event
        .tags
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect()
}

fn result_tags(
    request_event: &RadrootsNostrEvent,
    receipt_event_id: &str,
    result: &TradeValidationReceiptJobResult,
) -> Vec<Vec<String>> {
    vec![
        vec!["p".to_string(), request_event.pubkey.to_string()],
        vec![
            "e".to_string(),
            request_event.id.to_hex(),
            String::new(),
            String::new(),
            "request".to_string(),
        ],
        vec![
            "e".to_string(),
            receipt_event_id.to_string(),
            String::new(),
            String::new(),
            "receipt".to_string(),
        ],
        vec![
            "public_values_hash".to_string(),
            result.public_values_hash.clone(),
        ],
        vec!["proof_system".to_string(), result.proof_system.clone()],
    ]
}

fn tag_has_value(tags: &[Vec<String>], key: &str, value: &str) -> bool {
    tags.iter().any(|tag| {
        tag.first().map(|tag_key| tag_key.as_str()) == Some(key)
            && tag.get(1).map(|tag_value| tag_value.as_str()) == Some(value)
    })
}

async fn fetch_event_by_id_io(
    client: &RadrootsNostrClient,
    event_id: &str,
) -> Result<RadrootsNostrEvent, TradeValidationReceiptJobError> {
    #[cfg(test)]
    if let Some(result) = pop_fetch_event_by_id_hook() {
        return result;
    }

    Ok(radroots_nostr_fetch_event_by_id(client, event_id).await?)
}

async fn publish_event_parts_io(
    client: &RadrootsNostrClient,
    kind: u32,
    content: String,
    tags: Vec<Vec<String>>,
) -> Result<String, TradeValidationReceiptJobError> {
    #[cfg(test)]
    if let Some(result) = pop_publish_event_hook(kind, content.clone(), tags.clone()) {
        return result;
    }

    let builder: RadrootsNostrEventBuilder = radroots_nostr_build_event(kind, content, tags)?;
    let output = radroots_nostr_send_event(client, builder).await?;
    Ok(output.val.to_hex())
}

fn zero_event_id() -> String {
    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

fn zero_signature() -> String {
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string()
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct PublishedEventParts {
    kind: u32,
    content: String,
    tags: Vec<Vec<String>>,
}

#[cfg(test)]
#[derive(Default)]
struct TradeValidationReceiptTestHooks {
    fetch_event_by_id_results:
        std::collections::VecDeque<Result<RadrootsNostrEvent, TradeValidationReceiptJobError>>,
    publish_event_results:
        std::collections::VecDeque<Result<String, TradeValidationReceiptJobError>>,
    published_events: Vec<PublishedEventParts>,
}

#[cfg(test)]
static TRADE_VALIDATION_RECEIPT_TEST_HOOKS: std::sync::OnceLock<
    std::sync::Mutex<TradeValidationReceiptTestHooks>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn trade_validation_receipt_test_hooks()
-> &'static std::sync::Mutex<TradeValidationReceiptTestHooks> {
    TRADE_VALIDATION_RECEIPT_TEST_HOOKS
        .get_or_init(|| std::sync::Mutex::new(TradeValidationReceiptTestHooks::default()))
}

#[cfg(test)]
fn pop_fetch_event_by_id_hook() -> Option<Result<RadrootsNostrEvent, TradeValidationReceiptJobError>>
{
    trade_validation_receipt_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .fetch_event_by_id_results
        .pop_front()
}

#[cfg(test)]
fn pop_publish_event_hook(
    kind: u32,
    content: String,
    tags: Vec<Vec<String>>,
) -> Option<Result<String, TradeValidationReceiptJobError>> {
    let mut hooks = trade_validation_receipt_test_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    hooks.published_events.push(PublishedEventParts {
        kind,
        content,
        tags,
    });
    hooks.publish_event_results.pop_front()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        TradeValidationReceiptJobError, TradeValidationReceiptJobRequest,
        TradeValidationReceiptJobResult, TradeValidationReceiptTestHooks,
        handle_trade_validation_receipt_job_request, trade_validation_receipt_test_hooks,
    };
    use radroots_core::{
        RadrootsCoreCurrency, RadrootsCoreDecimal, RadrootsCoreMoney, RadrootsCoreUnit,
    };
    use radroots_events::RadrootsNostrEventPtr;
    use radroots_events::kinds::{
        KIND_LISTING, KIND_TRADE_VALIDATION_RECEIPT, KIND_WORKER_TRADE_TRANSITION_PROOF_REQ,
        KIND_WORKER_TRADE_TRANSITION_PROOF_RES,
    };
    use radroots_events::trade::{
        RadrootsTradeInventoryCommitment, RadrootsTradeOrderDecision,
        RadrootsTradeOrderDecisionEvent, RadrootsTradeOrderEconomicItem,
        RadrootsTradeOrderEconomicLine, RadrootsTradeOrderEconomics, RadrootsTradeOrderItem,
        RadrootsTradeOrderRequested, RadrootsTradePricingBasis,
    };
    use radroots_events_codec::trade::{
        active_trade_order_decision_event_build, active_trade_order_request_event_build,
    };
    use radroots_nostr::prelude::{
        RadrootsNostrClient, RadrootsNostrEvent, RadrootsNostrEventBuilder, RadrootsNostrKeys,
        RadrootsNostrKind, RadrootsNostrTag, RadrootsNostrTagKind, radroots_event_from_nostr,
        radroots_nostr_build_event,
    };
    use radroots_sp1_guest_trade::{
        RADROOTS_SP1_TRADE_PROTOCOL_VERSION, RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH,
        RadrootsSp1TradeInventoryBinWitness,
    };
    use radroots_sp1_host_trade::RadrootsSp1TradeProofMode;
    use radroots_trade::validation_receipt::{
        RadrootsValidationReceiptExpectedBinding, RadrootsValidationReceiptProofSystem,
        verify_validation_receipt_event,
    };
    use std::sync::{Mutex, MutexGuard};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_guard() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *trade_validation_receipt_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            TradeValidationReceiptTestHooks::default();
        guard
    }

    fn publish_result_id(index: u8) -> String {
        format!("{index:064x}")
    }

    fn listing_addr_for_seller(seller: &RadrootsNostrKeys) -> String {
        format!(
            "30402:{}:AAAAAAAAAAAAAAAAAAAAAA",
            seller.public_key().to_hex()
        )
    }

    fn signed_event(
        keys: &RadrootsNostrKeys,
        kind: u32,
        content: impl Into<String>,
        tags: Vec<Vec<String>>,
    ) -> RadrootsNostrEvent {
        radroots_nostr_build_event(kind, content.into(), tags)
            .expect("event builder")
            .sign_with_keys(keys)
            .expect("signed event")
    }

    fn listing_event(seller: &RadrootsNostrKeys) -> RadrootsNostrEvent {
        signed_event(
            seller,
            KIND_LISTING,
            "{}",
            vec![vec!["d".to_string(), "listing-1".to_string()]],
        )
    }

    fn request_payload(
        order_id: &str,
        listing_addr: &str,
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
    ) -> RadrootsTradeOrderRequested {
        RadrootsTradeOrderRequested {
            order_id: order_id.to_string(),
            listing_addr: listing_addr.to_string(),
            buyer_pubkey: buyer.public_key().to_hex(),
            seller_pubkey: seller.public_key().to_hex(),
            items: vec![RadrootsTradeOrderItem {
                bin_id: "bin-1".to_string(),
                bin_count: 2,
            }],
            economics: economics(order_id, 2),
        }
    }

    fn decision_payload(
        order_id: &str,
        listing_addr: &str,
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
    ) -> RadrootsTradeOrderDecisionEvent {
        RadrootsTradeOrderDecisionEvent {
            order_id: order_id.to_string(),
            listing_addr: listing_addr.to_string(),
            buyer_pubkey: buyer.public_key().to_hex(),
            seller_pubkey: seller.public_key().to_hex(),
            decision: RadrootsTradeOrderDecision::Accepted {
                inventory_commitments: vec![RadrootsTradeInventoryCommitment {
                    bin_id: "bin-1".to_string(),
                    bin_count: 2,
                }],
            },
        }
    }

    fn economics(order_id: &str, bin_count: u32) -> RadrootsTradeOrderEconomics {
        let subtotal = RadrootsCoreDecimal::from(5u32) * RadrootsCoreDecimal::from(bin_count);
        let money = RadrootsCoreMoney::new(subtotal, RadrootsCoreCurrency::USD);
        RadrootsTradeOrderEconomics {
            quote_id: format!("{order_id}-quote"),
            quote_version: 1,
            pricing_basis: RadrootsTradePricingBasis::ListingEvent,
            currency: RadrootsCoreCurrency::USD,
            items: vec![RadrootsTradeOrderEconomicItem {
                bin_id: "bin-1".to_string(),
                bin_count,
                quantity_amount: RadrootsCoreDecimal::from(1u32),
                quantity_unit: RadrootsCoreUnit::Each,
                unit_price_amount: RadrootsCoreDecimal::from(5u32),
                unit_price_currency: RadrootsCoreCurrency::USD,
                line_subtotal: money.clone(),
            }],
            discounts: Vec::<RadrootsTradeOrderEconomicLine>::new(),
            adjustments: Vec::<RadrootsTradeOrderEconomicLine>::new(),
            subtotal: money.clone(),
            discount_total: RadrootsCoreMoney::zero(RadrootsCoreCurrency::USD),
            adjustment_total: RadrootsCoreMoney::zero(RadrootsCoreCurrency::USD),
            total: money,
        }
    }

    fn signed_order_events(
        buyer: &RadrootsNostrKeys,
        seller: &RadrootsNostrKeys,
        listing_event: &RadrootsNostrEvent,
    ) -> (RadrootsNostrEvent, RadrootsNostrEvent) {
        let listing_addr = listing_addr_for_seller(seller);
        let order_id = "order-1";
        let listing_ptr = RadrootsNostrEventPtr {
            id: listing_event.id.to_hex(),
            relays: None,
        };
        let request_wire = active_trade_order_request_event_build(
            &listing_ptr,
            &request_payload(order_id, &listing_addr, buyer, seller),
        )
        .expect("request wire");
        let request_event = signed_event(
            buyer,
            request_wire.kind,
            request_wire.content,
            request_wire.tags,
        );
        let decision_wire = active_trade_order_decision_event_build(
            &request_event.id.to_hex(),
            &request_event.id.to_hex(),
            &decision_payload(order_id, &listing_addr, buyer, seller),
        )
        .expect("decision wire");
        let decision_event = signed_event(
            seller,
            decision_wire.kind,
            decision_wire.content,
            decision_wire.tags,
        );
        (request_event, decision_event)
    }

    fn job_request(
        requester: &RadrootsNostrKeys,
        worker: &RadrootsNostrKeys,
        listing_event: &RadrootsNostrEvent,
        request_event: &RadrootsNostrEvent,
        decision_event: &RadrootsNostrEvent,
        proof_mode: RadrootsSp1TradeProofMode,
        sp1_verifying_key_hash: Option<String>,
    ) -> RadrootsNostrEvent {
        let request = TradeValidationReceiptJobRequest {
            listing_event_id: listing_event.id.to_hex(),
            request_event_id: request_event.id.to_hex(),
            decision_event_id: decision_event.id.to_hex(),
            inventory_bins: vec![RadrootsSp1TradeInventoryBinWitness {
                bin_id: "bin-1".to_string(),
                listing_capacity: 5,
                previous_reserved: 1,
            }],
            inventory_sequence: 7,
            previous_state_root: None,
            proof_mode,
            reducer_program_hash: RADROOTS_SP1_TRADE_REDUCER_PROGRAM_HASH.to_string(),
            radroots_protocol_version: RADROOTS_SP1_TRADE_PROTOCOL_VERSION.to_string(),
            sp1_verifying_key_hash,
        };
        signed_event(
            requester,
            KIND_WORKER_TRADE_TRANSITION_PROOF_REQ,
            serde_json::to_string(&request).expect("job json"),
            vec![vec!["p".to_string(), worker.public_key().to_string()]],
        )
    }

    fn client_for(keys: &RadrootsNostrKeys) -> RadrootsNostrClient {
        RadrootsNostrClient::new(keys.clone())
    }

    #[tokio::test]
    async fn proof_job_publishes_verified_receipt_and_result_after_proof_verification() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::None,
            None,
        );

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(listing_event.clone()));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(request_event.clone()));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event.clone()));
            hooks
                .publish_event_results
                .push_back(Ok(publish_result_id(1)));
            hooks
                .publish_event_results
                .push_back(Ok(publish_result_id(2)));
        }

        handle_trade_validation_receipt_job_request(&job, &worker, &client_for(&worker))
            .await
            .expect("proof job");

        let published = trade_validation_receipt_test_hooks()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .published_events
            .clone();
        assert_eq!(published.len(), 2);
        assert_eq!(published[0].kind, KIND_TRADE_VALIDATION_RECEIPT);
        assert_eq!(published[1].kind, KIND_WORKER_TRADE_TRANSITION_PROOF_RES);

        let receipt_event = radroots_events::RadrootsNostrEvent {
            id: publish_result_id(1),
            author: worker.public_key().to_string(),
            created_at: 1,
            kind: published[0].kind,
            tags: published[0].tags.clone(),
            content: published[0].content.clone(),
            sig: super::zero_signature(),
        };
        let verified = verify_validation_receipt_event(
            &receipt_event,
            RadrootsValidationReceiptExpectedBinding {
                order_id: Some("order-1"),
                proof_system: Some(RadrootsValidationReceiptProofSystem::None),
                ..RadrootsValidationReceiptExpectedBinding::default()
            },
        )
        .expect("receipt verifies");
        let result: TradeValidationReceiptJobResult =
            serde_json::from_str(&published[1].content).expect("result json");
        assert_eq!(result.receipt_event_id, publish_result_id(1));
        assert_eq!(
            result.public_values_hash,
            verified.receipt.public_values_hash
        );
        assert_eq!(result.worker_role.to_string(), "non_authoritative_prover");
        assert!(published[1].tags.iter().any(|tag| {
            tag.get(0).map(String::as_str) == Some("e")
                && tag.get(1).map(String::as_str) == Some(publish_result_id(1).as_str())
                && tag.get(4).map(String::as_str) == Some("receipt")
        }));
    }

    #[tokio::test]
    async fn proof_job_rejects_unverified_proof_before_publication() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let job = job_request(
            &requester,
            &worker,
            &listing_event,
            &request_event,
            &decision_event,
            RadrootsSp1TradeProofMode::Compressed,
            None,
        );

        {
            let mut hooks = trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hooks.fetch_event_by_id_results.push_back(Ok(listing_event));
            hooks.fetch_event_by_id_results.push_back(Ok(request_event));
            hooks
                .fetch_event_by_id_results
                .push_back(Ok(decision_event));
        }

        let error =
            handle_trade_validation_receipt_job_request(&job, &worker, &client_for(&worker))
                .await
                .expect_err("missing proof material");
        assert!(matches!(error, TradeValidationReceiptJobError::Proof(_)));
        assert!(
            trade_validation_receipt_test_hooks()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .published_events
                .is_empty()
        );
    }

    #[tokio::test]
    async fn proof_job_requires_worker_recipient_tag() {
        let _guard = test_guard();
        let worker = RadrootsNostrKeys::generate();
        let requester = RadrootsNostrKeys::generate();
        let job = RadrootsNostrEventBuilder::new(
            RadrootsNostrKind::Custom(KIND_WORKER_TRADE_TRANSITION_PROOF_REQ as u16),
            "{}",
        )
        .tags(vec![RadrootsNostrTag::custom(
            RadrootsNostrTagKind::custom("p"),
            vec![requester.public_key().to_string()],
        )])
        .sign_with_keys(&requester)
        .expect("job");

        let error =
            handle_trade_validation_receipt_job_request(&job, &worker, &client_for(&worker))
                .await
                .expect_err("missing recipient");
        assert!(matches!(
            error,
            TradeValidationReceiptJobError::MissingRecipient
        ));
    }

    trait WorkerRoleLabel {
        fn to_string(self) -> String;
    }

    impl WorkerRoleLabel for super::TradeValidationReceiptWorkerRole {
        fn to_string(self) -> String {
            serde_json::to_value(self)
                .expect("role json")
                .as_str()
                .expect("role string")
                .to_string()
        }
    }

    #[test]
    fn signed_events_are_canonical_active_trade_events() {
        let _guard = test_guard();
        let buyer = RadrootsNostrKeys::generate();
        let seller = RadrootsNostrKeys::generate();
        let listing_event = listing_event(&seller);
        let (request_event, decision_event) = signed_order_events(&buyer, &seller, &listing_event);
        let request_rr = radroots_event_from_nostr(&request_event);
        let decision_rr = radroots_event_from_nostr(&decision_event);
        assert!(
            active_trade_order_request_event_build(
                &RadrootsNostrEventPtr {
                    id: listing_event.id.to_hex(),
                    relays: None,
                },
                &request_payload(
                    "order-1",
                    &listing_addr_for_seller(&seller),
                    &buyer,
                    &seller
                ),
            )
            .is_ok()
        );
        assert_eq!(request_rr.kind, 3422);
        assert_eq!(decision_rr.kind, 3423);
    }
}
