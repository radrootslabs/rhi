use nostr::{event::Event, key::Keys};
use nostr_sdk::{Client, client::Error as NostrClientError};
use radroots_events_codec::job::{result::encode::job_result_build_tags, traits::JobEventBorrow};
use thiserror::Error;
use tracing::info;

use radroots_events::{
    RadrootsNostrEventPtr,
    job::{
        JobPaymentRequest,
        request::models::{RadrootsJobInput, RadrootsJobParam},
        result::models::RadrootsJobResult,
    },
    kinds::result_kind_for_request_kind,
    tag::{TAG_D, TAG_E_PREV, TAG_E_ROOT},
};
use radroots_trade::{
    listing::tags::push_trade_listing_chain_tags,
    prelude::{
        kinds::{
            KIND_TRADE_LISTING_ACCEPT_RES, KIND_TRADE_LISTING_INVOICE_RES,
            KIND_TRADE_LISTING_ORDER_RES,
        },
        stage::invoice::{TradeListingInvoiceRequest, TradeListingInvoiceResult},
    },
};

use crate::{
    adapters::nostr::event::NostrEventAdapter,
    features::trade_listing::subscriber::{JobRequestCtx, JobRequestError},
    infra::nostr::{build_event_with_tags, nostr_fetch_event_by_id, nostr_send_event},
};

#[derive(Debug, Error)]
pub enum JobRequestInvoiceError {
    #[error("Failed to parse invoice request: {0}")]
    ParseRequest(String),
    #[error("Failed to fetch reference event: {0}")]
    FetchReference(String),
    #[error("Reference event not found: {0}")]
    MissingReference(String),
    #[error("Accept result not kind 6302 or missing chain")]
    InvalidAccept,
    #[error("Failed to send job response")]
    ResponseSend(#[from] NostrClientError),
}

fn param_lookup<'a>(params: &'a [RadrootsJobParam], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|p| p.key == key)
        .map(|p| p.value.as_str())
}

pub async fn handle_job_request_trade_invoice(
    event_job_request: Event,
    _keys: Keys,
    client: Client,
    job_req: JobRequestCtx,
    job_req_input: RadrootsJobInput,
) -> Result<(), JobRequestError> {
    let ev = NostrEventAdapter::new(&event_job_request);

    let req: TradeListingInvoiceRequest = serde_json::from_str(&job_req_input.data)
        .map_err(|e| JobRequestInvoiceError::ParseRequest(e.to_string()))?;

    let accept_evt = nostr_fetch_event_by_id(client.clone(), &req.accept_result_event_id)
        .await
        .map_err(|_| JobRequestInvoiceError::FetchReference(req.accept_result_event_id.clone()))?;
    if accept_evt.kind != nostr::event::Kind::Custom(KIND_TRADE_LISTING_ACCEPT_RES) {
        return Err(JobRequestInvoiceError::InvalidAccept.into());
    }

    let e_root = accept_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_E_ROOT)).then(|| s.get(1).cloned())
        })
        .flatten()
        .ok_or(JobRequestInvoiceError::InvalidAccept)?;

    let d_tag = accept_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_D)).then(|| s.get(1).cloned())
        })
        .flatten();

    let order_res_id = accept_evt
        .tags
        .iter()
        .find_map(|t| {
            let s = t.as_slice();
            (s.get(0).map(|k| k.as_str()) == Some(TAG_E_PREV)).then(|| s.get(1).cloned())
        })
        .flatten();

    if let Some(prev_id) = &order_res_id {
        if let Ok(prev_evt) = nostr_fetch_event_by_id(client.clone(), prev_id).await {
            if prev_evt.kind != nostr::event::Kind::Custom(KIND_TRADE_LISTING_ORDER_RES) {}
        }
    }

    let amount_sat = param_lookup(&job_req.model.params, "amount_sat")
        .and_then(|v| v.parse::<u32>().ok())
        .or_else(|| {
            param_lookup(&job_req.model.params, "amount_msat")
                .and_then(|v| v.parse::<u64>().ok())
                .map(|msat| (msat / 1000) as u32)
        })
        .unwrap_or(0);

    let bolt11 = param_lookup(&job_req.model.params, "bolt11").map(|s| s.to_string());
    let note = param_lookup(&job_req.model.params, "note").map(|s| s.to_string());
    let expires_at =
        param_lookup(&job_req.model.params, "expires_at").and_then(|v| v.parse::<u32>().ok());

    let invoice = TradeListingInvoiceResult {
        total_sat: amount_sat,
        bolt11: bolt11.clone(),
        note,
        expires_at,
    };
    let payload_json = serde_json::to_string(&invoice)?;

    let result_kind = result_kind_for_request_kind(job_req.model.kind as u32)
        .unwrap_or(job_req.model.kind as u32 + 1000);
    debug_assert_eq!(result_kind as u16, KIND_TRADE_LISTING_INVOICE_RES);

    let result_model = RadrootsJobResult {
        kind: result_kind as u16,
        request_event: RadrootsNostrEventPtr {
            id: ev.raw_id().to_string(),
            relays: None,
        },
        request_json: Some(serde_json::to_string(&job_req.model)?),
        inputs: job_req.model.inputs.clone(),
        customer_pubkey: Some(ev.raw_author().to_string()),
        payment: Some(JobPaymentRequest { amount_sat, bolt11 }),
        content: Some(payload_json.clone()),
        encrypted: false,
    };

    let mut tag_slices = job_result_build_tags(&result_model);

    push_trade_listing_chain_tags(
        &mut tag_slices,
        e_root.clone(),
        Some(req.accept_result_event_id.clone()),
        d_tag,
    );

    let builder = build_event_with_tags(result_kind as u32, payload_json, tag_slices)?;
    let job_result_event_id = nostr_send_event(client, builder).await?;

    info!(
        "job request trade/invoice ({}={}) result sent: {:?}",
        TAG_E_ROOT, e_root, job_result_event_id
    );
    Ok(())
}
