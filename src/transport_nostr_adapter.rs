//! Private source-locked Nostr transport composition for the RHI runtime.

use core::fmt;
use std::{collections::BTreeMap, error::Error, sync::Arc};

use radroots_event_codec::Codec;
use radroots_transport::{
    BoxFuture, DeliveryReceipt, DeliveryRequest, EventSink, EventSource, EventSubscriber,
    FetchPage, FetchRequest, SinkFailure, SinkStatus, SourceStatus, Target, TargetSet,
    outcome::{DeliveryOutcomeKind, FetchTargetState},
    policy::{SatisfactionClass, SatisfactionPolicy, TargetPolicy},
    sink::{DeliveryPayload, DeliveryTargetReceipt},
    source::{BoxSubscription, FetchBounds, FetchSelector, SubscriptionRequest},
    target::TargetFingerprint,
};
use radroots_transport_nostr::{
    Config, NostrTransport, PreparedDelivery, RelayAccess, RelayEndpoint, RelayProfile,
    RelayProfileKind, RelayUrlPolicy,
};

use crate::{
    RhiConfigDocumentV1, RhiConfigProfile, RhiExactPresenceSink, RhiExactPublicationSink,
    RhiPreparedPresenceAttempt, RhiPreparedPublicationAttempt, RhiPresenceAttemptOutcome,
    RhiPublicationAttemptOutcome, RhiTransportAdapters,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RhiNostrAdapterErrorKind {
    Configuration,
    Target,
    Payload,
    Preparation,
}

pub(crate) struct RhiNostrAdapterError {
    kind: RhiNostrAdapterErrorKind,
}

impl RhiNostrAdapterError {
    #[cfg(test)]
    pub(crate) const fn kind(&self) -> RhiNostrAdapterErrorKind {
        self.kind
    }
}

impl fmt::Debug for RhiNostrAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiNostrAdapterError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiNostrAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RHI Nostr adapter failed")
    }
}

impl Error for RhiNostrAdapterError {}

const fn adapter_error(kind: RhiNostrAdapterErrorKind) -> RhiNostrAdapterError {
    RhiNostrAdapterError { kind }
}

struct RelayDefinition {
    id: Box<str>,
    target: Target,
    kind: RelayProfileKind,
}

struct RelayBinding {
    transport: NostrTransport,
    target: Target,
}

/// One private adapter that routes a bounded request to exactly one configured
/// public or simulator transport group.
struct RhiNostrTransport {
    by_target: BTreeMap<TargetFingerprint, NostrTransport>,
}

impl RhiNostrTransport {
    fn for_targets(
        &self,
        targets: &TargetSet,
    ) -> Result<NostrTransport, radroots_transport::Error> {
        let mut selected: Option<NostrTransport> = None;
        for target in targets.targets() {
            let transport = self
                .by_target
                .get(target.fingerprint())
                .ok_or(radroots_transport::Error::UnsupportedOperation)?;
            if let Some(existing) = &selected {
                if existing.config() != transport.config() {
                    return Err(radroots_transport::Error::UnsupportedOperation);
                }
            } else {
                selected = Some(transport.clone());
            }
        }
        selected.ok_or(radroots_transport::Error::UnsupportedOperation)
    }
}

impl EventSource for RhiNostrTransport {
    fn status(&self) -> BoxFuture<'_, Result<SourceStatus, radroots_transport::Error>> {
        Box::pin(async { Err(radroots_transport::Error::UnsupportedOperation) })
    }

    fn fetch(
        &self,
        request: FetchRequest,
    ) -> BoxFuture<'_, Result<FetchPage, radroots_transport::Error>> {
        Box::pin(async move {
            let transport = self.for_targets(request.target_set())?;
            transport.fetch(request).await
        })
    }
}

impl EventSubscriber for RhiNostrTransport {
    fn subscribe(
        &self,
        request: SubscriptionRequest,
    ) -> BoxFuture<'_, Result<BoxSubscription, radroots_transport::Error>> {
        Box::pin(async move {
            let transport = self.for_targets(request.target_set())?;
            transport.subscribe(request).await
        })
    }
}

impl EventSink for RhiNostrTransport {
    fn status(&self) -> BoxFuture<'_, Result<SinkStatus, radroots_transport::Error>> {
        Box::pin(async { Err(radroots_transport::Error::UnsupportedOperation) })
    }

    fn deliver(
        &self,
        request: DeliveryRequest,
    ) -> BoxFuture<'_, Result<DeliveryReceipt, SinkFailure>> {
        Box::pin(async move {
            let transport = self
                .for_targets(request.target_set())
                .map_err(|_| SinkFailure::invalid_contract(&request))?;
            transport.deliver(request).await
        })
    }
}

pub(crate) struct RhiNostrExactSink {
    relays: BTreeMap<Box<str>, RelayBinding>,
}

struct RhiPreparedNostrDelivery {
    transport: NostrTransport,
    prepared: PreparedDelivery,
}

impl fmt::Debug for RhiPreparedNostrDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiPreparedNostrDelivery([redacted])")
    }
}

impl RhiNostrExactSink {
    fn prepare(
        &self,
        relay_id: &str,
        request_id: String,
        exact_event_bytes: &[u8],
        deadline_unix_ms: u64,
    ) -> Result<RhiPreparedNostrDelivery, RhiNostrAdapterError> {
        let binding = self
            .relays
            .get(relay_id)
            .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Target))?;
        let raw = core::str::from_utf8(exact_event_bytes)
            .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Payload))?;
        let signed = Codec::decode_signed_event(raw)
            .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Payload))?;
        if signed.raw_json().as_bytes() != exact_event_bytes {
            return Err(adapter_error(RhiNostrAdapterErrorKind::Payload));
        }
        let targets = TargetSet::new(vec![binding.target.clone()])
            .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Target))?;
        let request = DeliveryRequest::new(
            request_id,
            DeliveryPayload::new(signed),
            targets,
            SatisfactionPolicy::new(SatisfactionClass::Accepted, TargetPolicy::all()),
            deadline_unix_ms,
        )
        .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Preparation))?;
        let prepared = binding
            .transport
            .prepare_delivery(request)
            .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Preparation))?;
        Ok(RhiPreparedNostrDelivery {
            transport: binding.transport.clone(),
            prepared,
        })
    }

    async fn execute(
        &self,
        prepared: RhiPreparedNostrDelivery,
    ) -> Result<DeliveryOutcomeKind, RhiNostrAdapterError> {
        let RhiPreparedNostrDelivery {
            transport,
            prepared,
        } = prepared;
        let receipt = transport
            .execute_prepared_delivery(prepared)
            .await
            .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Preparation))?;
        classify_receipt(receipt.target_receipts())
    }
}

impl RhiExactPublicationSink for RhiNostrExactSink {
    fn submit_exact<'a>(
        &'a self,
        attempt: &'a RhiPreparedPublicationAttempt,
    ) -> BoxFuture<'a, RhiPublicationAttemptOutcome> {
        Box::pin(async move {
            let request_id = request_id("publication", attempt.attempt_id().as_bytes());
            let prepared = match self.prepare(
                attempt.relay_id(),
                request_id,
                attempt.exact_signed_event_bytes(),
                attempt.deadline_at().get(),
            ) {
                Ok(prepared) => prepared,
                Err(_) => return RhiPublicationAttemptOutcome::Failed,
            };
            match self.execute(prepared).await {
                Ok(DeliveryOutcomeKind::Accepted | DeliveryOutcomeKind::Delivered) => {
                    RhiPublicationAttemptOutcome::Accepted
                }
                Ok(DeliveryOutcomeKind::Rejected) => RhiPublicationAttemptOutcome::Rejected,
                Ok(DeliveryOutcomeKind::Unavailable | DeliveryOutcomeKind::Failed) => {
                    RhiPublicationAttemptOutcome::Failed
                }
                Err(_) => RhiPublicationAttemptOutcome::Unknown,
            }
        })
    }
}

impl RhiExactPresenceSink for RhiNostrExactSink {
    fn submit_exact<'a>(
        &'a self,
        attempt: &'a RhiPreparedPresenceAttempt,
    ) -> BoxFuture<'a, RhiPresenceAttemptOutcome> {
        Box::pin(async move {
            let request_id = request_id("presence", attempt.attempt_id().as_bytes());
            let prepared = match self.prepare(
                attempt.relay_id(),
                request_id,
                attempt.exact_signed_event_bytes(),
                attempt.deadline_at().get(),
            ) {
                Ok(prepared) => prepared,
                Err(_) => return RhiPresenceAttemptOutcome::Failed,
            };
            match self.execute(prepared).await {
                Ok(DeliveryOutcomeKind::Accepted | DeliveryOutcomeKind::Delivered) => {
                    RhiPresenceAttemptOutcome::Accepted
                }
                Ok(DeliveryOutcomeKind::Rejected) => RhiPresenceAttemptOutcome::Rejected,
                Ok(DeliveryOutcomeKind::Unavailable | DeliveryOutcomeKind::Failed) => {
                    RhiPresenceAttemptOutcome::Failed
                }
                Err(_) => RhiPresenceAttemptOutcome::Unknown,
            }
        })
    }
}

fn classify_receipt(
    receipts: &[DeliveryTargetReceipt],
) -> Result<DeliveryOutcomeKind, RhiNostrAdapterError> {
    let [receipt] = receipts else {
        return Err(adapter_error(RhiNostrAdapterErrorKind::Preparation));
    };
    Ok(receipt.outcome().kind())
}

fn request_id(prefix: &str, bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(prefix.len() + 1 + bytes.len() * 2);
    result.push_str(prefix);
    result.push('-');
    for byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

pub(crate) fn build_rhi_nostr_adapters(
    configuration: &RhiConfigDocumentV1,
) -> Result<(RhiTransportAdapters, Arc<RhiNostrExactSink>), RhiNostrAdapterError> {
    let relays = configuration
        .normalized()
        .pointer("/relays")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
    let connect_timeout = configuration_integer(configuration, "/network/connect_deadline_ms")?;
    let source_timeout = configuration
        .normalized()
        .pointer("/evidence/sources")
        .and_then(serde_json::Value::as_array)
        .and_then(|sources| {
            sources
                .iter()
                .filter_map(|source| {
                    source
                        .pointer("/deadline_ms")
                        .and_then(serde_json::Value::as_u64)
                })
                .max()
        })
        .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
    let publication_timeout = configuration
        .normalized()
        .pointer("/publication/retry/attempt_deadline_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(source_timeout);
    let request_timeout = source_timeout.max(publication_timeout);

    let mut public = Vec::new();
    let mut simulator = Vec::new();
    let mut definitions = Vec::with_capacity(relays.len());
    for relay in relays {
        let id = relay
            .pointer("/id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        let url = relay
            .pointer("/url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        let read = relay
            .pointer("/read")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        let write = relay
            .pointer("/write")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        let access = if write {
            RelayAccess::ReadWrite
        } else if read {
            RelayAccess::ReadOnly
        } else {
            return Err(adapter_error(RhiNostrAdapterErrorKind::Configuration));
        };
        let (kind, policy) = if url.starts_with("wss://") {
            (RelayProfileKind::Public, RelayUrlPolicy::Public)
        } else if configuration.profile() == RhiConfigProfile::RepoLocal && url.starts_with("ws://")
        {
            (RelayProfileKind::Simulator, RelayUrlPolicy::Local)
        } else {
            return Err(adapter_error(RhiNostrAdapterErrorKind::Configuration));
        };
        let endpoint = RelayEndpoint::new(url, policy, access)
            .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        match kind {
            RelayProfileKind::Public => public.push(endpoint),
            RelayProfileKind::Simulator => simulator.push(endpoint),
            _ => return Err(adapter_error(RhiNostrAdapterErrorKind::Configuration)),
        }
        definitions.push(RelayDefinition {
            id: Box::from(id),
            target: Target::nostr_relay(url)
                .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Target))?,
            kind,
        });
    }

    let public_transport = build_transport(
        RelayProfileKind::Public,
        public,
        connect_timeout,
        request_timeout,
    )?;
    let simulator_transport = build_transport(
        RelayProfileKind::Simulator,
        simulator,
        connect_timeout,
        request_timeout,
    )?;
    let mut by_target = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    for definition in definitions {
        let transport = match definition.kind {
            RelayProfileKind::Public => public_transport.clone(),
            RelayProfileKind::Simulator => simulator_transport.clone(),
            _ => None,
        }
        .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        if by_target
            .insert(definition.target.fingerprint().clone(), transport.clone())
            .is_some()
            || bindings
                .insert(
                    definition.id,
                    RelayBinding {
                        transport,
                        target: definition.target,
                    },
                )
                .is_some()
        {
            return Err(adapter_error(RhiNostrAdapterErrorKind::Configuration));
        }
    }
    if by_target.is_empty() {
        return Err(adapter_error(RhiNostrAdapterErrorKind::Configuration));
    }
    let transport = Arc::new(RhiNostrTransport { by_target });
    let adapters = RhiTransportAdapters::new(
        transport.clone(),
        transport.clone(),
        transport as Arc<dyn EventSink>,
    );
    Ok((adapters, Arc::new(RhiNostrExactSink { relays: bindings })))
}

pub(crate) async fn probe_required_sources(
    configuration: &RhiConfigDocumentV1,
    deadline_unix_ms: u64,
) -> Result<(), RhiNostrAdapterError> {
    let relays = configuration
        .normalized()
        .pointer("/relays")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
    let sources = configuration
        .normalized()
        .pointer("/evidence/sources")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
    let connect_timeout = configuration_integer(configuration, "/network/connect_deadline_ms")?;
    let request_timeout = sources
        .iter()
        .filter_map(|source| {
            source
                .pointer("/deadline_ms")
                .and_then(serde_json::Value::as_u64)
        })
        .max()
        .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;

    let mut public = Vec::new();
    let mut public_targets = Vec::new();
    let mut simulator = Vec::new();
    let mut simulator_targets = Vec::new();
    for source in sources.iter().filter(|source| {
        source
            .pointer("/required")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
    }) {
        let relay_id = source
            .pointer("/relay_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        let relay = relays
            .iter()
            .find(|relay| {
                relay.pointer("/id").and_then(serde_json::Value::as_str) == Some(relay_id)
            })
            .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        let url = relay
            .pointer("/url")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        let target = Target::nostr_relay(url)
            .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Target))?;
        let (kind, policy) = if url.starts_with("wss://") {
            (RelayProfileKind::Public, RelayUrlPolicy::Public)
        } else if configuration.profile() == RhiConfigProfile::RepoLocal && url.starts_with("ws://")
        {
            (RelayProfileKind::Simulator, RelayUrlPolicy::Local)
        } else {
            return Err(adapter_error(RhiNostrAdapterErrorKind::Configuration));
        };
        let endpoint = RelayEndpoint::new(url, policy, RelayAccess::ReadOnly)
            .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
        match kind {
            RelayProfileKind::Public => {
                public.push(endpoint);
                public_targets.push(target);
            }
            RelayProfileKind::Simulator => {
                simulator.push(endpoint);
                simulator_targets.push(target);
            }
            _ => return Err(adapter_error(RhiNostrAdapterErrorKind::Configuration)),
        }
    }
    if public_targets.is_empty() && simulator_targets.is_empty() {
        return Err(adapter_error(RhiNostrAdapterErrorKind::Configuration));
    }
    probe_group(
        RelayProfileKind::Public,
        public,
        public_targets,
        connect_timeout,
        request_timeout,
        deadline_unix_ms,
        "rhi-doctor-public",
    )
    .await?;
    probe_group(
        RelayProfileKind::Simulator,
        simulator,
        simulator_targets,
        connect_timeout,
        request_timeout,
        deadline_unix_ms,
        "rhi-doctor-simulator",
    )
    .await
}

async fn probe_group(
    kind: RelayProfileKind,
    endpoints: Vec<RelayEndpoint>,
    targets: Vec<Target>,
    connect_timeout: u64,
    request_timeout: u64,
    deadline_unix_ms: u64,
    request_id: &'static str,
) -> Result<(), RhiNostrAdapterError> {
    if targets.is_empty() {
        return Ok(());
    }
    let transport = build_transport(kind, endpoints, connect_timeout, request_timeout)?
        .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
    let target_set =
        TargetSet::new(targets).map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Target))?;
    let selector = FetchSelector::all()
        .with_since_unix_seconds(u64::MAX)
        .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
    let request = FetchRequest::new(
        request_id,
        target_set,
        FetchBounds::new(1, deadline_unix_ms)
            .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Configuration))?,
    )
    .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Configuration))?
    .with_selector(selector);
    let page = transport
        .fetch(request)
        .await
        .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Preparation))?;
    if page.target_outcomes().is_empty()
        || page.target_outcomes().iter().any(|outcome| {
            !matches!(
                outcome.state(),
                FetchTargetState::Complete | FetchTargetState::Partial
            )
        })
    {
        return Err(adapter_error(RhiNostrAdapterErrorKind::Preparation));
    }
    Ok(())
}

fn build_transport(
    kind: RelayProfileKind,
    endpoints: Vec<RelayEndpoint>,
    connect_timeout: u64,
    request_timeout: u64,
) -> Result<Option<NostrTransport>, RhiNostrAdapterError> {
    if endpoints.is_empty() {
        return Ok(None);
    }
    let maximum_connections = endpoints.len().min(8);
    let profile = RelayProfile::explicit(kind, endpoints)
        .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
    let config = Config::from_profile(profile)
        .with_timeouts(connect_timeout, request_timeout, connect_timeout)
        .and_then(|config| config.with_max_connections(maximum_connections))
        .map_err(|_| adapter_error(RhiNostrAdapterErrorKind::Configuration))?;
    Ok(Some(NostrTransport::new(config)))
}

fn configuration_integer(
    configuration: &RhiConfigDocumentV1,
    pointer: &str,
) -> Result<u64, RhiNostrAdapterError> {
    configuration
        .normalized()
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| adapter_error(RhiNostrAdapterErrorKind::Configuration))
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;
    use crate::{RhiConfigProfile, parse_rhi_config_v1};

    const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    #[test]
    fn exact_configuration_builds_without_network_io_and_errors_are_redacted() {
        let configuration = parse_rhi_config_v1(CONFIG.as_bytes(), RhiConfigProfile::Production)
            .expect("configuration");
        let (_adapters, sink) =
            build_rhi_nostr_adapters(&configuration).expect("offline composition");
        assert_eq!(sink.relays.len(), 2);
        assert_eq!(request_id("publication", &[0xab; 32]).len(), 76);
        for kind in [
            RhiNostrAdapterErrorKind::Configuration,
            RhiNostrAdapterErrorKind::Target,
            RhiNostrAdapterErrorKind::Payload,
            RhiNostrAdapterErrorKind::Preparation,
        ] {
            let error = adapter_error(kind);
            assert_eq!(error.kind(), kind);
            assert!(error.source().is_none());
            assert!(!format!("{error} {error:?}").contains("relay.example"));
        }
    }
}
