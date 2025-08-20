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
    tag::{TAG_D, TAG_E_ROOT},
};
use radroots_trade::{
    listing::{
        kinds::{KIND_TRADE_LISTING_ACCEPT_RES, KIND_TRADE_LISTING_ORDER_RES},
        tags::push_trade_listing_chain_tags,
    },
    prelude::stage::accept::{TradeListingAcceptRequest, TradeListingAcceptResult},
};

use crate::{
    adapters::nostr::event::NostrEventAdapter,
    features::trade_listing::subscriber::{JobRequestCtx, JobRequestError},
    infra::nostr::{build_event_with_tags, nostr_fetch_event_by_id, nostr_send_event},
};

#[derive(Debug, Error)]
pub enum JobRequestAcceptError {
    #[error("Failed to parse accept request: {0}")]
    ParseRequest(String),
    #[error("Failed to fetch reference event: {0}")]
    FetchReference(String),
    #[error("Reference event not found: {0}")]
    MissingReference(String),
    #[error("Unauthorized: accepting profile must own the listing")]
    Unauthorized,
    #[error("Order result not kind 6301 or listing mismatch")]
    InvalidOrderResult,
    #[error("Failed to send job response")]
    ResponseSend(#[from] NostrClientError),
}

pub async fn handle_job_request_trade_accept(
    event_job_request: Event,
    keys: Keys,
    client: Client,
    job_req: JobRequestCtx,
    job_req_input: RadrootsJobInput,
) -> Result<(), JobRequestError> {
    let ev = NostrEventAdapter::new(&event_job_request);

    let req: TradeListingAcceptRequest = serde_json::from_str(&job_req_input.data)
        .map_err(|e| JobRequestAcceptError::ParseRequest(e.to_string()))?;

    let order_res_evt = nostr_fetch_event_by_id(client.clone(), &req.order_result_event_id)
        .await
        .map_err(|_| JobRequestAcceptError::FetchReference(req.order_result_event_id.clone()))?;

    let listing_evt = nostr_fetch_event_by_id(client.clone(), &req.listing_event_id)
        .await
        .map_err(|_| JobRequestAcceptError::FetchReference(req.listing_event_id.clone()))?;

    if listing_evt.pubkey != keys.public_key() {
        return Err(JobRequestAcceptError::Unauthorized.into());
    }

    if order_res_evt.kind != nostr::event::Kind::Custom(KIND_TRADE_LISTING_ORDER_RES) {
        return Err(JobRequestAcceptError::InvalidOrderResult.into());
    }
    let order_refs_listing = order_res_evt.tags.iter().any(|t| {
        let s = t.as_slice();
        s.get(0).map(|k| k.as_str()) == Some(TAG_E_ROOT)
            && s.get(1).map(String::as_str) == Some(req.listing_event_id.as_str())
    });
    if !order_refs_listing {
        return Err(JobRequestAcceptError::InvalidOrderResult.into());
    }

    let accept_result = TradeListingAcceptResult {
        listing_event_id: req.listing_event_id.clone(),
        order_result_event_id: req.order_result_event_id.clone(),
        accepted_by: keys.public_key().to_string(),
    };
    let payload_json = serde_json::to_string(&accept_result)?;

    let result_kind = result_kind_for_request_kind(job_req.model.kind as u32)
        .unwrap_or(job_req.model.kind as u32 + 1000);
    debug_assert_eq!(result_kind as u16, KIND_TRADE_LISTING_ACCEPT_RES);

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

    let e_root = order_res_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_E_ROOT)).then(|| s.get(1).cloned())
        })
        .flatten()
        .unwrap_or_else(|| req.listing_event_id.clone());

    let trade_id = order_res_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_D)).then(|| s.get(1).cloned())
        })
        .flatten();

    push_trade_listing_chain_tags(
        &mut tag_slices,
        e_root.clone(),
        Some(req.order_result_event_id.clone()),
        trade_id,
    );

    let builder = build_event_with_tags(result_kind as u32, payload_json, tag_slices)?;
    let job_result_event_id = nostr_send_event(client, builder).await?;

    info!(
        "job request trade/accept ({}={}) result sent: {:?}",
        TAG_E_ROOT, e_root, job_result_event_id
    );
    Ok(())
}
