use nostr::{event::Event, key::Keys};
use nostr_sdk::{Client, client::Error as NostrClientError};
use radroots_events_codec::job::{result::encode::job_result_build_tags, traits::JobEventBorrow};
use thiserror::Error;
use tracing::info;

use radroots_events::{
    RadrootsNostrEventPtr,
    job::{
        JobPaymentRequest, request::models::RadrootsJobInput, result::models::RadrootsJobResult,
    },
    kinds::result_kind_for_request_kind,
    listing::models::RadrootsListing,
};
use radroots_trade::prelude::{
    kinds::KIND_TRADE_LISTING_ORDER_RES, stage::order::TradeListingOrderRequest, tags,
};

use crate::{
    adapters::nostr::event::NostrEventAdapter,
    features::trade_listing::{
        domain::pricing::ListingOrderCalculator,
        subscriber::{JobRequestCtx, JobRequestError},
    },
    infra::nostr::{build_event_with_tags, nostr_fetch_event_by_id, nostr_send_event},
};

#[derive(Debug, Error)]
pub enum JobRequestOrderError {
    #[error("Failed to parse reference event: {0}")]
    ParseReference(String),
    #[error("Failed to fetch reference event: {0}")]
    FetchReference(String),
    #[error("Reference event not found: {0}")]
    MissingReference(String),
    #[error("Reference event does not meet request requirements: {0}")]
    MissingRequested(String),
    #[error("Failed to send job response")]
    ResponseSend(#[from] NostrClientError),
    #[error("Request cannot be satisfied: {0}")]
    Unsatisfiable(String),
}

pub async fn handle_job_request_trade_order(
    event_job_request: Event,
    _keys: Keys,
    client: Client,
    job_req: JobRequestCtx,
    job_req_input: RadrootsJobInput,
) -> Result<(), JobRequestError> {
    let ev = NostrEventAdapter::new(&event_job_request);

    let order_data: TradeListingOrderRequest = serde_json::from_str(&job_req_input.data)
        .map_err(|e| JobRequestOrderError::ParseReference(e.to_string()))?;

    let ref_id = &order_data.event.id;
    let ref_event = nostr_fetch_event_by_id(client.clone(), ref_id)
        .await
        .map_err(|_| JobRequestOrderError::FetchReference(ref_id.clone()))?;

    let listing: RadrootsListing = serde_json::from_str(&ref_event.content).map_err(|_| {
        JobRequestOrderError::ParseReference(format!("invalid listing content for {}", ref_id))
    })?;

    let order_result = listing.calculate_order(&order_data.payload)?;

    let result_kind = result_kind_for_request_kind(job_req.model.kind as u32)
        .unwrap_or(job_req.model.kind as u32 + 1000);
    debug_assert_eq!(result_kind as u16, KIND_TRADE_LISTING_ORDER_RES as u16);

    let payload_json = serde_json::to_string(&order_result)?;

    let result_model = RadrootsJobResult {
        kind: result_kind as u16,
        request_event: RadrootsNostrEventPtr {
            id: ev.raw_id().to_string(),
            relays: None,
        },
        request_json: Some(serde_json::to_string(&job_req.model)?),
        inputs: job_req.model.inputs.clone(),
        customer_pubkey: Some(ev.raw_author().to_string()),
        payment: None::<JobPaymentRequest>,
        content: Some(payload_json.clone()),
        encrypted: false,
    };

    let mut tag_slices = job_result_build_tags(&result_model);

    let e_root = ref_event.id.to_hex();
    let trade_id = format!("trade:{}:{}", e_root, event_job_request.id.to_hex());
    tags::push_trade_listing_chain_tags(
        &mut tag_slices,
        e_root.clone(),
        None::<String>,
        Some(trade_id.clone()),
    );

    let builder = build_event_with_tags(result_kind as u32, payload_json, tag_slices)?;
    let job_result_event_id = nostr_send_event(client, builder).await?;

    info!(
        "job request trade/order (e_root={}) result sent: {:?}",
        e_root, job_result_event_id
    );
    Ok(())
}
