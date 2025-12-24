use radroots_nostr::prelude::{
    radroots_nostr_build_event,
    radroots_nostr_fetch_event_by_id,
    radroots_nostr_send_event,
    RadrootsNostrClient,
    RadrootsNostrEvent,
    RadrootsNostrKind,
    RadrootsNostrKeys,
};
use radroots_events_codec::job::{result::encode::job_result_build_tags, traits::JobEventBorrow};
use thiserror::Error;
use tracing::info;

use radroots_events::{
    RadrootsNostrEventPtr,
    job_request::RadrootsJobInput,
    job_result::RadrootsJobResult,
    kinds::result_kind_for_request_kind,
    tags::{TAG_D, TAG_E_ROOT},
};
use radroots_trade::{
    listing::tags::push_trade_listing_chain_tags,
    prelude::{
        kinds::KIND_TRADE_LISTING_PAYMENT_RES,
        stage::fulfillment::{
            TradeListingFulfillmentRequest, TradeListingFulfillmentResult,
            TradeListingFulfillmentState,
        },
    },
};

use crate::{
    adapters::nostr::event::NostrEventAdapter,
    features::trade_listing::subscriber::{JobRequestCtx, JobRequestError},
};

#[derive(Debug, Error)]
pub enum JobRequestFulfillmentError {
    #[error("Failed to parse fulfillment request: {0}")]
    ParseRequest(String),
    #[error("Failed to fetch reference event: {0}")]
    FetchReference(String),
    #[error("Reference event not found: {0}")]
    MissingReference(String),
    #[error("Payment result not kind 6305 or missing chain")]
    InvalidPayment,
    #[error("Failed to send job response")]
    ResponseSend(#[from] radroots_nostr::error::RadrootsNostrError),
}

pub async fn handle_job_request_trade_fulfillment(
    event_job_request: RadrootsNostrEvent,
    _keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    job_req: JobRequestCtx,
    job_req_input: RadrootsJobInput,
) -> Result<(), JobRequestError> {
    let ev = NostrEventAdapter::new(&event_job_request);

    let req: TradeListingFulfillmentRequest = serde_json::from_str(&job_req_input.data)
        .map_err(|e| JobRequestFulfillmentError::ParseRequest(e.to_string()))?;

    let payment_evt = radroots_nostr_fetch_event_by_id(client.clone(), &req.payment_result_event_id)
        .await
        .map_err(|_| {
            JobRequestFulfillmentError::FetchReference(req.payment_result_event_id.clone())
        })?;
    if payment_evt.kind != RadrootsNostrKind::Custom(KIND_TRADE_LISTING_PAYMENT_RES) {
        return Err(JobRequestFulfillmentError::InvalidPayment.into());
    }

    let e_root = payment_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_E_ROOT)).then(|| s.get(1).cloned())
        })
        .flatten()
        .ok_or(JobRequestFulfillmentError::InvalidPayment)?;

    let d_tag = payment_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_D)).then(|| s.get(1).cloned())
        })
        .flatten();

    let status = TradeListingFulfillmentResult {
        state: TradeListingFulfillmentState::Preparing,
        tracking: None,
        eta: None,
        notes: Some("order accepted and paid; preparing shipment".into()),
    };
    let payload_json = serde_json::to_string(&status)?;

    let result_kind = result_kind_for_request_kind(job_req.model.kind as u32)
        .unwrap_or(job_req.model.kind as u32 + 1000);

    let result_model = RadrootsJobResult {
        kind: result_kind as u16,
        request_event: RadrootsNostrEventPtr {
            id: ev.raw_id().to_string(),
            relays: None,
        },
        request_json: Some(serde_json::to_string(&job_req.model)?),
        inputs: job_req.model.inputs.clone(),
        customer_pubkey: Some(ev.raw_author().to_string()),
        payment: None,
        content: Some(payload_json.clone()),
        encrypted: false,
    };

    let mut tag_slices = job_result_build_tags(&result_model);
    push_trade_listing_chain_tags(
        &mut tag_slices,
        e_root.clone(),
        Some(req.payment_result_event_id.clone()),
        d_tag,
    );

    let builder = radroots_nostr_build_event(result_kind as u32, payload_json, tag_slices)?;
    let job_result_event_id = radroots_nostr_send_event(client, builder).await?;

    info!(
        "job request trade/fulfillment ({}={}) result sent: {:?}",
        TAG_E_ROOT, e_root, job_result_event_id
    );
    Ok(())
}
