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
    job::JobPaymentRequest,
    job_request::RadrootsJobInput,
    job_result::RadrootsJobResult,
    kinds::result_kind_for_request_kind,
    tags::{TAG_D, TAG_E_ROOT},
};
use radroots_trade::{
    listing::{kinds::KIND_TRADE_LISTING_ACCEPT_RES, tags::push_trade_listing_chain_tags},
    prelude::stage::conveyance::{TradeListingConveyanceRequest, TradeListingConveyanceResult},
};

use crate::{
    adapters::nostr::event::NostrEventAdapter,
    features::trade_listing::subscriber::{JobRequestCtx, JobRequestError},
};

#[derive(Debug, Error)]
pub enum JobRequestConveyanceError {
    #[error("Failed to parse conveyance request: {0}")]
    ParseRequest(String),
    #[error("Failed to fetch reference event: {0}")]
    FetchReference(String),
    #[error("Reference event not found: {0}")]
    MissingReference(String),
    #[error("Invalid accept result kind")]
    InvalidAcceptKind,
    #[error("Failed to send job response")]
    ResponseSend(#[from] radroots_nostr::error::RadrootsNostrError),
}

pub async fn handle_job_request_trade_conveyance(
    event_job_request: RadrootsNostrEvent,
    _keys: RadrootsNostrKeys,
    client: RadrootsNostrClient,
    job_req: JobRequestCtx,
    job_req_input: RadrootsJobInput,
) -> Result<(), JobRequestError> {
    let ev = NostrEventAdapter::new(&event_job_request);

    let req: TradeListingConveyanceRequest = serde_json::from_str(&job_req_input.data)
        .map_err(|e| JobRequestConveyanceError::ParseRequest(e.to_string()))?;

    let accept_evt = radroots_nostr_fetch_event_by_id(client.clone(), &req.accept_result_event_id)
        .await
        .map_err(|_| {
            JobRequestConveyanceError::FetchReference(req.accept_result_event_id.clone())
        })?;
    if accept_evt.kind != RadrootsNostrKind::Custom(KIND_TRADE_LISTING_ACCEPT_RES) {
        return Err(JobRequestConveyanceError::InvalidAcceptKind.into());
    }

    let conv_res = TradeListingConveyanceResult {
        verified: true,
        method: req.method,
        message: Some("conveyance method verified".into()),
    };
    let payload_json = serde_json::to_string(&conv_res)?;

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
        payment: None::<JobPaymentRequest>,
        content: Some(payload_json.clone()),
        encrypted: false,
    };

    let mut tag_slices = job_result_build_tags(&result_model);

    let e_root = accept_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_E_ROOT)).then(|| s.get(1).cloned())
        })
        .flatten();

    let d_tag = accept_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_D)).then(|| s.get(1).cloned())
        })
        .flatten();

    push_trade_listing_chain_tags(
        &mut tag_slices,
        e_root.clone().unwrap_or_default(),
        Some(req.accept_result_event_id.clone()),
        d_tag,
    );

    let builder = radroots_nostr_build_event(result_kind as u32, payload_json, tag_slices)?;
    let job_result_event_id = radroots_nostr_send_event(client, builder).await?;

    info!(
        "job request trade/conveyance ({}={:?}) result sent: {:?}",
        TAG_E_ROOT, e_root, job_result_event_id
    );
    Ok(())
}
