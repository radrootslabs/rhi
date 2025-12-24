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
use radroots_trade::prelude::{
    kinds::KIND_TRADE_LISTING_INVOICE_RES,
    stage::payment::{TradeListingPaymentProofRequest, TradeListingPaymentResult},
    tags::push_trade_listing_chain_tags,
};

use crate::{
    adapters::nostr::event::NostrEventAdapter,
    features::trade_listing::subscriber::{JobRequestCtx, JobRequestError},
};

#[derive(Debug, Error)]
pub enum JobRequestPaymentError {
    #[error("Failed to parse payment request: {0}")]
    ParseRequest(String),
    #[error("Failed to fetch reference event: {0}")]
    FetchReference(String),
    #[error("Reference event not found: {0}")]
    MissingReference(String),
    #[error("Invoice result not kind 6304 or missing chain")]
    InvalidInvoice,
    #[error("Failed to send job response")]
    ResponseSend(#[from] radroots_nostr::error::RadrootsNostrError),
}

pub async fn handle_job_request_trade_payment(
    event_job_request: RadrootsNostrEvent,
    _keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    job_req: JobRequestCtx,
    job_req_input: RadrootsJobInput,
) -> Result<(), JobRequestError> {
    let ev = NostrEventAdapter::new(&event_job_request);

    let req: TradeListingPaymentProofRequest = serde_json::from_str(&job_req_input.data)
        .map_err(|e| JobRequestPaymentError::ParseRequest(e.to_string()))?;

    let invoice_evt = radroots_nostr_fetch_event_by_id(client.clone(), &req.invoice_result_event_id)
        .await
        .map_err(|_| JobRequestPaymentError::FetchReference(req.invoice_result_event_id.clone()))?;
    if invoice_evt.kind != RadrootsNostrKind::Custom(KIND_TRADE_LISTING_INVOICE_RES) {
        return Err(JobRequestPaymentError::InvalidInvoice.into());
    }

    let e_root = invoice_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_E_ROOT)).then(|| s.get(1).cloned())
        })
        .flatten()
        .ok_or(JobRequestPaymentError::InvalidInvoice)?;

    let d_tag = invoice_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_D)).then(|| s.get(1).cloned())
        })
        .flatten();

    let ack = TradeListingPaymentResult {
        verified: true,
        message: Some("payment proof accepted".into()),
    };
    let payload_json = serde_json::to_string(&ack)?;

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
        Some(req.invoice_result_event_id.clone()),
        d_tag,
    );

    let builder = radroots_nostr_build_event(result_kind as u32, payload_json, tag_slices)?;
    let job_result_event_id = radroots_nostr_send_event(client, builder).await?;

    info!(
        "job request trade/payment ({}={}) result sent: {:?}",
        TAG_E_ROOT, e_root, job_result_event_id
    );
    Ok(())
}
