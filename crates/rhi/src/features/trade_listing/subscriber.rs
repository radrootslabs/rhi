use std::{str::FromStr, time::Duration};

use anyhow::Result;
use nostr::event::{Event, EventId};
use nostr::filter::Filter;
use nostr::{event::Kind, key::Keys};
use nostr_sdk::{Client, RelayPoolNotification};
use radroots_events::job::request::models::RadrootsJobInput;
use radroots_events_codec::job::error::JobParseError;
use radroots_events_codec::job::request::decode::job_request_from_tags;
use radroots_events_codec::job::traits::BorrowedEventAdapter;
use radroots_trade::listing::kinds::{
    KIND_TRADE_LISTING_ACCEPT_REQ, KIND_TRADE_LISTING_CONVEYANCE_REQ,
    KIND_TRADE_LISTING_FULFILL_REQ, KIND_TRADE_LISTING_INVOICE_REQ, KIND_TRADE_LISTING_ORDER_REQ,
    KIND_TRADE_LISTING_PAYMENT_REQ, KIND_TRADE_LISTING_RECEIPT_REQ, is_trade_listing_request_kind,
};
use radroots_trade::listing::meta::MARKER_PAYLOAD;

use tokio::time::sleep;
use tracing::{info, warn};

use crate::adapters::nostr::event::NostrEventAdapter;
use crate::features::trade_listing::handlers::accept::{
    JobRequestAcceptError, handle_job_request_trade_accept,
};
use crate::features::trade_listing::handlers::conveyance::{
    JobRequestConveyanceError, handle_job_request_trade_conveyance,
};
use crate::features::trade_listing::handlers::fulfillment::{
    JobRequestFulfillmentError, handle_job_request_trade_fulfillment,
};
use crate::features::trade_listing::handlers::invoice::{
    JobRequestInvoiceError, handle_job_request_trade_invoice,
};
use crate::features::trade_listing::handlers::order::{
    JobRequestOrderError, handle_job_request_trade_order,
};
use crate::features::trade_listing::handlers::payment::{
    JobRequestPaymentError, handle_job_request_trade_payment,
};
use crate::features::trade_listing::handlers::receipt::{
    JobRequestReceiptError, handle_job_request_trade_receipt,
};
use crate::infra::nostr::{
    NostrTagsResolveError, NostrUtilsError, nostr_filter_new_events, nostr_tags_resolve,
};

#[derive(thiserror::Error, Debug)]
pub enum JobRequestError {
    #[error("{0}")]
    NostrUtilsError(#[from] NostrUtilsError),

    #[error("{0}")]
    NostrTagsResolve(#[from] NostrTagsResolveError),

    #[error("{0}")]
    JobParse(#[from] JobParseError),

    #[error("Order: {0}")]
    JobRequestOrder(#[from] JobRequestOrderError),

    #[error("Accept: {0}")]
    JobRequestAccept(#[from] JobRequestAcceptError),

    #[error("Conveyance: {0}")]
    JobRequestConveyance(#[from] JobRequestConveyanceError),

    #[error("Invoice: {0}")]
    JobRequestInvoice(#[from] JobRequestInvoiceError),

    #[error("Payment: {0}")]
    JobRequestPayment(#[from] JobRequestPaymentError),

    #[error("Fulfillment: {0}")]
    JobRequestFulfillment(#[from] JobRequestFulfillmentError),

    #[error("Receipt: {0}")]
    JobRequestReceipt(#[from] JobRequestReceiptError),

    #[error("Invalid job request input marker: {0}")]
    InvalidInputMarker(String),

    #[error("Deserialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Failure to process request")]
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobRequestInputMarker {
    TradeOrder,
    TradeAccept,
    TradeConveyance,
    TradeInvoice,
    TradePayment,
    TradeFulfillment,
    TradeReceipt,
}

impl std::fmt::Display for JobRequestInputMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            JobRequestInputMarker::TradeOrder => "order",
            JobRequestInputMarker::TradeAccept => "accept",
            JobRequestInputMarker::TradeConveyance => "conveyance",
            JobRequestInputMarker::TradeInvoice => "invoice",
            JobRequestInputMarker::TradePayment => "payment",
            JobRequestInputMarker::TradeFulfillment => "fulfillment",
            JobRequestInputMarker::TradeReceipt => "receipt",
        })
    }
}

impl TryFrom<&str> for JobRequestInputMarker {
    type Error = JobRequestError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "order" => Ok(Self::TradeOrder),
            "accept" => Ok(Self::TradeAccept),
            "conveyance" => Ok(Self::TradeConveyance),
            "invoice" => Ok(Self::TradeInvoice),
            "payment" => Ok(Self::TradePayment),
            "fulfillment" => Ok(Self::TradeFulfillment),
            "receipt" => Ok(Self::TradeReceipt),
            other => Err(JobRequestError::InvalidInputMarker(other.to_string())),
        }
    }
}

impl FromStr for JobRequestInputMarker {
    type Err = JobRequestError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

#[derive(Debug, Clone)]
pub struct JobRequestCtx {
    pub id: EventId,
    pub model: radroots_events::job::request::models::RadrootsJobRequest,
    pub tags: Vec<nostr::event::Tag>,
}

pub async fn subscriber(keys: Keys, relays: Vec<String>) -> Result<()> {
    info!(
        "Starting subscriber for trade listing request kinds: {}, {}, {}, {}, {}, {}, {}",
        KIND_TRADE_LISTING_ORDER_REQ,
        KIND_TRADE_LISTING_ACCEPT_REQ,
        KIND_TRADE_LISTING_CONVEYANCE_REQ,
        KIND_TRADE_LISTING_INVOICE_REQ,
        KIND_TRADE_LISTING_PAYMENT_REQ,
        KIND_TRADE_LISTING_FULFILL_REQ,
        KIND_TRADE_LISTING_RECEIPT_REQ
    );

    let client = Client::new(keys.clone());
    for relay in &relays {
        client.add_relay(relay).await?;
    }

    let kinds: Vec<Kind> = vec![
        Kind::Custom(KIND_TRADE_LISTING_ORDER_REQ),
        Kind::Custom(KIND_TRADE_LISTING_ACCEPT_REQ),
        Kind::Custom(KIND_TRADE_LISTING_CONVEYANCE_REQ),
        Kind::Custom(KIND_TRADE_LISTING_INVOICE_REQ),
        Kind::Custom(KIND_TRADE_LISTING_PAYMENT_REQ),
        Kind::Custom(KIND_TRADE_LISTING_FULFILL_REQ),
        Kind::Custom(KIND_TRADE_LISTING_RECEIPT_REQ),
    ];
    let filter = nostr_filter_new_events(Filter::new().kinds(kinds));

    client.connect().await;
    client.subscribe(filter, None).await?;

    let mut notifications = client.notifications();

    while let Ok(n) = notifications.recv().await {
        if let RelayPoolNotification::Event { event, .. } = n {
            let event = (*event).clone();

            let kind: u16 = match event.kind {
                Kind::Custom(v) => v,
                _ => 0,
            };
            if !is_trade_listing_request_kind(kind) {
                continue;
            }

            let keys = keys.clone();
            let client = client.clone();

            tokio::spawn(async move {
                if let Err(err) = handle_event(event.clone(), keys.clone(), client.clone()).await {
                    let _ = handle_error(err, event, keys, client, None).await;
                }
            });
        }
    }

    client.disconnect().await;
    Ok(())
}

async fn handle_error(
    error: JobRequestError,
    event: Event,
    _keys: Keys,
    client: Client,
    _job_req: Option<JobRequestCtx>,
) -> Result<()> {
    use crate::infra::nostr::nostr_event_job_feedback;

    warn!("job_request handle_error: {}", error);
    warn!("job_request handle_error event: {:?}", event);

    let builder = nostr_event_job_feedback(&event, error, "error", None)?;
    let event_id = client.send_event_builder(builder).await?;
    warn!("job_request handle_error sent feedback {:?}", event_id);
    Ok(())
}

async fn handle_event(event: Event, keys: Keys, client: Client) -> Result<(), JobRequestError> {
    let job_req = parse_event(&event, &keys)?;

    let kind: u16 = match event.kind {
        Kind::Custom(v) => v,
        _ => 0,
    };

    #[inline]
    fn select_payload_input<'a>(inputs: &'a [RadrootsJobInput]) -> Option<&'a RadrootsJobInput> {
        inputs
            .iter()
            .find(|i| i.marker.as_deref() == Some(MARKER_PAYLOAD))
            .or_else(|| inputs.get(0))
    }

    match kind {
        KIND_TRADE_LISTING_ORDER_REQ => {
            let input = select_payload_input(&job_req.model.inputs)
                .ok_or_else(|| JobRequestError::InvalidInputMarker(MARKER_PAYLOAD.into()))?;
            process_job_request(
                handle_job_request_trade_order,
                event.clone(),
                keys.clone(),
                client.clone(),
                job_req.clone(),
                input.clone(),
            )
            .await;
        }
        KIND_TRADE_LISTING_ACCEPT_REQ => {
            let input = select_payload_input(&job_req.model.inputs)
                .ok_or_else(|| JobRequestError::InvalidInputMarker(MARKER_PAYLOAD.into()))?;
            process_job_request(
                handle_job_request_trade_accept,
                event.clone(),
                keys.clone(),
                client.clone(),
                job_req.clone(),
                input.clone(),
            )
            .await;
        }
        KIND_TRADE_LISTING_CONVEYANCE_REQ => {
            let input = select_payload_input(&job_req.model.inputs)
                .ok_or_else(|| JobRequestError::InvalidInputMarker(MARKER_PAYLOAD.into()))?;
            process_job_request(
                handle_job_request_trade_conveyance,
                event.clone(),
                keys.clone(),
                client.clone(),
                job_req.clone(),
                input.clone(),
            )
            .await;
        }
        KIND_TRADE_LISTING_INVOICE_REQ => {
            let input = select_payload_input(&job_req.model.inputs)
                .ok_or_else(|| JobRequestError::InvalidInputMarker(MARKER_PAYLOAD.into()))?;
            process_job_request(
                handle_job_request_trade_invoice,
                event.clone(),
                keys.clone(),
                client.clone(),
                job_req.clone(),
                input.clone(),
            )
            .await;
        }
        KIND_TRADE_LISTING_PAYMENT_REQ => {
            let input = select_payload_input(&job_req.model.inputs)
                .ok_or_else(|| JobRequestError::InvalidInputMarker(MARKER_PAYLOAD.into()))?;
            process_job_request(
                handle_job_request_trade_payment,
                event.clone(),
                keys.clone(),
                client.clone(),
                job_req.clone(),
                input.clone(),
            )
            .await;
        }
        KIND_TRADE_LISTING_FULFILL_REQ => {
            let input = select_payload_input(&job_req.model.inputs)
                .ok_or_else(|| JobRequestError::InvalidInputMarker(MARKER_PAYLOAD.into()))?;
            process_job_request(
                handle_job_request_trade_fulfillment,
                event.clone(),
                keys.clone(),
                client.clone(),
                job_req.clone(),
                input.clone(),
            )
            .await;
        }
        KIND_TRADE_LISTING_RECEIPT_REQ => {
            let input = select_payload_input(&job_req.model.inputs)
                .ok_or_else(|| JobRequestError::InvalidInputMarker(MARKER_PAYLOAD.into()))?;
            process_job_request(
                handle_job_request_trade_receipt,
                event.clone(),
                keys.clone(),
                client.clone(),
                job_req.clone(),
                input.clone(),
            )
            .await;
        }
        _ => {}
    }

    Ok(())
}

fn parse_event(event: &Event, keys: &Keys) -> Result<JobRequestCtx, JobRequestError> {
    let originally_encrypted = event
        .tags
        .iter()
        .any(|t| t.kind() == nostr::event::TagKind::Encrypted);

    let resolved_tags = nostr_tags_resolve(event, keys)?;
    let tag_slices: Vec<Vec<String>> = resolved_tags
        .iter()
        .map(|t| t.as_slice().to_vec())
        .collect();

    let kind: u16 = match event.kind {
        Kind::Custom(v) => v,
        _ => 0,
    };

    let mut model = job_request_from_tags(kind as u32, &tag_slices)?;
    if originally_encrypted {
        model.encrypted = true;
    }

    let ev = NostrEventAdapter::new(event);
    let sig_hex = event.sig.to_string();
    let _evt_view =
        BorrowedEventAdapter::new(&ev, event.created_at.as_u64() as u32, &tag_slices, &sig_hex);

    Ok(JobRequestCtx {
        id: event.id,
        model,
        tags: resolved_tags,
    })
}

async fn process_job_request<F, Fut>(
    handler: F,
    event: Event,
    keys: Keys,
    client: Client,
    job_req: JobRequestCtx,
    job_req_input: RadrootsJobInput,
) where
    F: FnOnce(Event, Keys, Client, JobRequestCtx, RadrootsJobInput) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), JobRequestError>> + Send + 'static,
{
    if cfg!(debug_assertions) {
        sleep(Duration::from_millis(500)).await;
    }

    let error_event = event.clone();
    let error_job_req = job_req.clone();
    let error_keys = keys.clone();
    let error_client = client.clone();

    if let Err(err) = handler(event, keys, client, job_req, job_req_input).await {
        let _ = handle_error(
            err,
            error_event,
            error_keys,
            error_client,
            Some(error_job_req),
        )
        .await;
    }
}
