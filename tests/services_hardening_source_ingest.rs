#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    collections::VecDeque,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
};

use nostr::secp256k1::{Keypair, Message};
use nostr::{EventId, Keys, SECP256K1};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use radroots_transport::{
    BoxFuture, DeliveryReceipt, DeliveryRequest, EventSink, EventSource, EventSubscriber,
    EventSubscription, FetchPage, FetchRequest, SinkFailure, SinkStatus, SourceStatus,
    SubscriptionRequest,
    outcome::{FetchTargetOutcome, FetchTargetState},
    source::{EventProvenance, FetchCursor, NextPage, ObservedEvent},
};
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiConfigProfile,
    RhiStateMetadata, RhiTradeMutationAuthoredTimePolicy, RhiTradeMutationObservedAtUnixSeconds,
    RhiTradeSourceAttempt, RhiTradeSourceCompletion, RhiTransportAdapters, TradeId,
    UnixTimeSeconds, ingest_rhi_trade_source, initialize_rhi_state, open_rhi_state_read_write,
    parse_rhi_cli_v1_from, parse_rhi_config_v1, resolve_rhi_runtime_context,
};
use serde_json::Value;

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const VECTOR: &str = include_str!("../contracts/conformance/vectors/trade_ingest_proposal.v1.json");

#[derive(Clone)]
struct PageSpec {
    events: Vec<String>,
    state: FetchTargetState,
    next: Option<&'static str>,
}

#[derive(Clone)]
struct ScriptedTransport {
    pages: Arc<Mutex<VecDeque<PageSpec>>>,
    requests: Arc<Mutex<Vec<FetchRequest>>>,
}

impl ScriptedTransport {
    fn new(pages: impl IntoIterator<Item = PageSpec>) -> Self {
        Self {
            pages: Arc::new(Mutex::new(pages.into_iter().collect())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn requests(&self) -> Vec<FetchRequest> {
        self.requests.lock().expect("requests").clone()
    }
}

impl EventSource for ScriptedTransport {
    fn status(&self) -> BoxFuture<'_, Result<SourceStatus, radroots_transport::Error>> {
        Box::pin(async { Err(radroots_transport::Error::UnsupportedOperation) })
    }

    fn fetch(
        &self,
        request: FetchRequest,
    ) -> BoxFuture<'_, Result<FetchPage, radroots_transport::Error>> {
        self.requests
            .lock()
            .expect("requests")
            .push(request.clone());
        let page = self.pages.lock().expect("pages").pop_front();
        Box::pin(async move {
            let spec = page.ok_or(radroots_transport::Error::UnsupportedOperation)?;
            let target = request.target_set().targets().first().expect("one target");
            let events = spec
                .events
                .into_iter()
                .map(|raw| {
                    let event = radroots_event_codec::decode::signed_event(raw.as_str())
                        .expect("signed event");
                    let mut provenance = EventProvenance::new(
                        radroots_transport::TransportId::NOSTR,
                        target.fingerprint().clone(),
                        1,
                    )
                    .expect("provenance");
                    if let Some(cursor) = request.cursor().cloned() {
                        provenance = provenance.with_cursor(cursor);
                    }
                    ObservedEvent::new(event, provenance)
                })
                .collect();
            let outcome = FetchTargetOutcome::new(target.fingerprint().clone(), spec.state);
            let next = match spec.next {
                Some(cursor) => NextPage::Cursor(FetchCursor::parse(cursor).expect("cursor")),
                None => NextPage::Complete,
            };
            FetchPage::for_request(&request, events, vec![outcome], next)
        })
    }
}

impl EventSubscriber for ScriptedTransport {
    fn subscribe(
        &self,
        _request: SubscriptionRequest,
    ) -> BoxFuture<'_, Result<Box<dyn EventSubscription>, radroots_transport::Error>> {
        Box::pin(async { Err(radroots_transport::Error::UnsupportedOperation) })
    }
}

impl EventSink for ScriptedTransport {
    fn status(&self) -> BoxFuture<'_, Result<SinkStatus, radroots_transport::Error>> {
        Box::pin(async { Err(radroots_transport::Error::UnsupportedOperation) })
    }

    fn deliver(
        &self,
        request: DeliveryRequest,
    ) -> BoxFuture<'_, Result<DeliveryReceipt, SinkFailure>> {
        Box::pin(async move { Err(SinkFailure::invalid_contract(&request)) })
    }
}

fn adapters(source: &ScriptedTransport) -> RhiTransportAdapters {
    RhiTransportAdapters::new(
        Arc::new(source.clone()),
        Arc::new(source.clone()),
        Arc::new(source.clone()),
    )
}

fn runtime(root: &Path) -> rhi::RhiRuntimeContext {
    let invocation = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        "repo-local",
        "--instance",
        "primary",
        "--repo-local-root",
        root.to_str().expect("UTF-8 root"),
        "run",
    ])
    .expect("invocation");
    resolve_rhi_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime")
}

fn configuration() -> rhi::RhiConfigDocumentV1 {
    parse_rhi_config_v1(CONFIG.as_bytes(), RhiConfigProfile::RepoLocal).expect("configuration")
}

fn metadata(
    runtime: &rhi::RhiRuntimeContext,
    configuration: &rhi::RhiConfigDocumentV1,
) -> RhiStateMetadata {
    RhiStateMetadata::new(
        runtime,
        configuration,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata")
}

fn migration_evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    (
        MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("migration time"),
        MigrationBuildIdentity::new(
            env!("CARGO_PKG_VERSION"),
            "1111111111111111111111111111111111111111",
            "21b11e7a5120ea949f7ad0838c746873fc73aac2",
            "rustc-test",
            "test-target",
            "service-host",
            1,
            rhi::RHI_STATE_SCHEMA_VERSION,
            1,
            1,
            1,
        )
        .expect("build identity"),
    )
}

fn prepare_state_directory(runtime: &rhi::RhiRuntimeContext) {
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state mode");
}

fn vector_wire() -> String {
    let vector: Value = serde_json::from_str(VECTOR).expect("vector");
    vector["raw_json"].as_str().expect("raw event").to_owned()
}

fn resign_wire(raw: &str, auxiliary: u8) -> String {
    let mut event: Value = serde_json::from_str(raw).expect("event JSON");
    let keys = Keys::parse("10c5304d6c9ae3a1a16f7860f1cc8f5e3a76225a2663b3a989a0d775919b7df5")
        .expect("approved fixture keys");
    let event_id = EventId::from_hex(event["id"].as_str().expect("event id")).expect("event id");
    let message = Message::from_digest(event_id.to_bytes());
    let keypair = Keypair::from_secret_key(SECP256K1, keys.secret_key());
    event["sig"] = SECP256K1
        .sign_schnorr_with_aux_rand(&message, &keypair, &[auxiliary; 32])
        .to_string()
        .into();
    serde_json::to_string(&event).expect("event JSON")
}

fn attempt(request_id: &str, started_at: u64, observed_at: u64) -> RhiTradeSourceAttempt {
    RhiTradeSourceAttempt::new(
        request_id,
        UnixTimeSeconds::new(started_at),
        RhiTradeMutationObservedAtUnixSeconds::new(observed_at).expect("observed"),
        RhiTradeMutationAuthoredTimePolicy::new(0).expect("authored policy"),
    )
    .expect("attempt")
}

#[tokio::test]
async fn exact_selector_fetch_replay_and_rejection_preserve_cursor_and_generation() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path());
    prepare_state_directory(&runtime);
    let configuration = configuration();
    let metadata = metadata(&runtime, &configuration);
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");
    let host = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let trade_id = TradeId::parse("11111111111111111111111111111111").expect("trade id");
    let wire = vector_wire();

    let source = ScriptedTransport::new([PageSpec {
        events: vec![wire.clone()],
        state: FetchTargetState::Complete,
        next: None,
    }]);
    let outcome = ingest_rhi_trade_source(
        &host.repositories(),
        &adapters(&source),
        &configuration,
        "trade-primary",
        trade_id,
        attempt("attempt-1", 1_784_347_200, 1_784_347_200),
    )
    .await
    .expect("ingest");
    assert_eq!(outcome.completion(), RhiTradeSourceCompletion::Complete);
    assert_eq!(outcome.received_events(), 1);
    assert_eq!(outcome.admitted_events(), 1);
    assert_eq!(outcome.rejected_events(), 0);
    assert_eq!(outcome.inserted_mutations(), 1);
    assert_eq!(outcome.inserted_signed_events(), 1);
    assert_eq!(outcome.inserted_observations(), 1);
    assert!(outcome.checkpoint_advanced());
    assert_eq!(outcome.dirty_generation().expect("generation").get(), 1);
    assert!(outcome.dirty_generation_advanced());

    let requests = source.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].selector().kinds(),
        &[3470, 3471, 3472, 3473, 3474]
    );
    assert_eq!(
        requests[0]
            .selector()
            .exact_tag_filters()
            .collect::<Vec<_>>(),
        vec![('d', &["11111111111111111111111111111111".to_owned()][..])]
    );
    assert_eq!(
        requests[0].selector().since_unix_seconds(),
        Some(1_784_260_800)
    );
    assert_eq!(requests[0].bounds().deadline_unix_ms(), 1_784_347_210_000);

    let replay_source = ScriptedTransport::new([PageSpec {
        events: vec![wire.clone(), wire.clone()],
        state: FetchTargetState::Complete,
        next: None,
    }]);
    let replay = ingest_rhi_trade_source(
        &host.repositories(),
        &adapters(&replay_source),
        &configuration,
        "trade-primary",
        trade_id,
        attempt("attempt-2", 1_784_347_201, 1_784_347_201),
    )
    .await
    .expect("replay");
    assert_eq!(replay.admitted_events(), 1);
    assert_eq!(replay.duplicate_events(), 1);
    assert_eq!(replay.inserted_mutations(), 0);
    assert_eq!(replay.inserted_signed_events(), 0);
    assert_eq!(replay.inserted_observations(), 1);
    assert!(!replay.checkpoint_advanced());
    assert_eq!(replay.dirty_generation().expect("generation").get(), 1);
    assert!(!replay.dirty_generation_advanced());

    let rejected_source = ScriptedTransport::new([PageSpec {
        events: vec![resign_wire(&wire, 9)],
        state: FetchTargetState::Complete,
        next: None,
    }]);
    let rejected = ingest_rhi_trade_source(
        &host.repositories(),
        &adapters(&rejected_source),
        &configuration,
        "trade-primary",
        trade_id,
        attempt("attempt-3", 1_784_347_000, 1_784_347_199),
    )
    .await
    .expect("rejected attempt");
    assert_eq!(rejected.completion(), RhiTradeSourceCompletion::Complete);
    assert_eq!(rejected.rejected_events(), 1);
    assert_eq!(rejected.inserted_signed_events(), 0);
    assert!(!rejected.checkpoint_advanced());
    assert_eq!(rejected.dirty_generation().expect("generation").get(), 1);
    assert!(!rejected.dirty_generation_advanced());

    host.close().await.expect("close");
}

#[tokio::test]
async fn incomplete_and_unsupported_results_never_advance_checkpoint_or_dirty_generation() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path());
    prepare_state_directory(&runtime);
    let configuration = configuration();
    let metadata = metadata(&runtime, &configuration);
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");
    let host = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let trade_id = TradeId::parse("11111111111111111111111111111111").expect("trade id");
    let vectors = [
        (
            FetchTargetState::Cancelled,
            RhiTradeSourceCompletion::IncompleteTimeout,
        ),
        (
            FetchTargetState::Unavailable,
            RhiTradeSourceCompletion::IncompleteUnavailable,
        ),
        (
            FetchTargetState::FailedRetryable,
            RhiTradeSourceCompletion::IncompleteUnavailable,
        ),
        (
            FetchTargetState::FailedTerminal,
            RhiTradeSourceCompletion::IncompleteUnknown,
        ),
        (
            FetchTargetState::Partial,
            RhiTradeSourceCompletion::IncompleteUnknown,
        ),
    ];
    for (index, (state, expected)) in vectors.into_iter().enumerate() {
        let source = ScriptedTransport::new([PageSpec {
            events: Vec::new(),
            state,
            next: None,
        }]);
        let outcome = ingest_rhi_trade_source(
            &host.repositories(),
            &adapters(&source),
            &configuration,
            "trade-primary",
            trade_id,
            attempt(
                &format!("incomplete-{index}"),
                1_784_347_300 + index as u64,
                1_784_347_300 + index as u64,
            ),
        )
        .await
        .expect("classified incomplete result");
        assert_eq!(outcome.completion(), expected);
        assert_eq!(outcome.checkpoint(), None);
        assert_eq!(outcome.dirty_generation(), None);
        assert!(!outcome.checkpoint_advanced());
        assert!(!outcome.dirty_generation_advanced());
    }

    let unsupported = ScriptedTransport::new([]);
    let outcome = ingest_rhi_trade_source(
        &host.repositories(),
        &adapters(&unsupported),
        &configuration,
        "trade-primary",
        trade_id,
        attempt("unsupported", 1_784_347_400, 1_784_347_400),
    )
    .await
    .expect("unsupported result");
    assert_eq!(outcome.completion(), RhiTradeSourceCompletion::Unsupported);
    assert_eq!(outcome.checkpoint(), None);
    assert_eq!(outcome.dirty_generation(), None);

    host.close().await.expect("close");
}

#[tokio::test]
async fn configured_result_bound_retains_admitted_evidence_without_checkpoint() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path());
    prepare_state_directory(&runtime);
    let configuration = configuration();
    let metadata = metadata(&runtime, &configuration);
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");
    let host = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let trade_id = TradeId::parse("11111111111111111111111111111111").expect("trade id");
    let wire = vector_wire();
    let source = ScriptedTransport::new([
        PageSpec {
            events: vec![wire.clone(); 1_000],
            state: FetchTargetState::Complete,
            next: Some("page-1"),
        },
        PageSpec {
            events: vec![wire.clone(); 1_000],
            state: FetchTargetState::Complete,
            next: Some("page-2"),
        },
        PageSpec {
            events: vec![wire.clone(); 1_000],
            state: FetchTargetState::Complete,
            next: Some("page-3"),
        },
        PageSpec {
            events: vec![wire.clone(); 1_000],
            state: FetchTargetState::Complete,
            next: Some("page-4"),
        },
        PageSpec {
            events: vec![wire; 97],
            state: FetchTargetState::Complete,
            next: None,
        },
    ]);
    let outcome = ingest_rhi_trade_source(
        &host.repositories(),
        &adapters(&source),
        &configuration,
        "trade-primary",
        trade_id,
        attempt("resource-limit", 1_784_347_500, 1_784_347_500),
    )
    .await
    .expect("resource-limited result");
    assert_eq!(
        outcome.completion(),
        RhiTradeSourceCompletion::IncompleteResourceLimit
    );
    assert_eq!(outcome.received_events(), 4_096);
    assert_eq!(outcome.admitted_events(), 1);
    assert_eq!(outcome.inserted_mutations(), 1);
    assert_eq!(outcome.inserted_signed_events(), 1);
    assert_eq!(outcome.inserted_observations(), 1);
    assert_eq!(outcome.checkpoint(), None);
    assert!(!outcome.checkpoint_advanced());
    assert_eq!(outcome.dirty_generation().expect("dirty").get(), 1);
    assert!(outcome.dirty_generation_advanced());

    host.close().await.expect("close");
}

#[test]
fn attempt_and_public_diagnostics_are_bounded_and_redacted() {
    let observed = RhiTradeMutationObservedAtUnixSeconds::new(100).expect("observed");
    let policy = RhiTradeMutationAuthoredTimePolicy::new(0).expect("policy");
    assert!(RhiTradeSourceAttempt::new("", UnixTimeSeconds::new(1), observed, policy).is_err());
    assert!(
        RhiTradeSourceAttempt::new("x".repeat(257), UnixTimeSeconds::new(1), observed, policy,)
            .is_err()
    );
    let attempt = RhiTradeSourceAttempt::new(
        "secret-attempt-id",
        UnixTimeSeconds::new(99),
        observed,
        policy,
    )
    .expect("attempt");
    assert!(!format!("{attempt:?}").contains("secret-attempt-id"));

    let error = RhiTradeSourceAttempt::new(
        "\nsecret-request",
        UnixTimeSeconds::new(99),
        observed,
        policy,
    )
    .expect_err("control character");
    assert_eq!(error.code(), "trade_source_input_invalid");
    assert!(!format!("{error}").contains("secret-request"));
    assert!(!format!("{error:?}").contains("secret-request"));
    assert!(std::error::Error::source(&error).is_none());
}
