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
    RhiTradeSourceAttempt, RhiTradeSourceCompletion, RhiTradeSourceIngestErrorKind,
    RhiTransportAdapters, TradeId, UnixTimeSeconds, apply_rhi_configuration,
    ingest_rhi_trade_source, initialize_rhi_state, open_rhi_state_read_write,
    open_rhi_state_read_write_from_config, parse_rhi_cli_v1_from, parse_rhi_config_v1,
    resolve_rhi_runtime_context,
};
use serde_json::Value;
use sqlx::{ConnectOptions, Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};
use tokio::sync::Barrier;

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
    fetch_barrier: Option<Arc<Barrier>>,
}

impl ScriptedTransport {
    fn new(pages: impl IntoIterator<Item = PageSpec>) -> Self {
        Self {
            pages: Arc::new(Mutex::new(pages.into_iter().collect())),
            requests: Arc::new(Mutex::new(Vec::new())),
            fetch_barrier: None,
        }
    }

    fn with_fetch_barrier(mut self, parties: usize) -> Self {
        self.fetch_barrier = Some(Arc::new(Barrier::new(parties)));
        self
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
        let fetch_barrier = self.fetch_barrier.clone();
        Box::pin(async move {
            if let Some(barrier) = fetch_barrier {
                barrier.wait().await;
            }
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
            "053d0c750bf9cd683c6ea37cefe7e79617ba629f",
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

async fn offline_scalar(runtime: &rhi::RhiRuntimeContext, query: &'static str) -> i64 {
    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .expect("offline connection");
    let value = sqlx::query(query)
        .fetch_one(&mut connection)
        .await
        .expect("offline scalar")
        .try_get::<i64, _>(0)
        .expect("scalar value");
    connection.close().await.expect("offline close");
    value
}

async fn offline_signed_event_keys(runtime: &rhi::RhiRuntimeContext) -> Vec<(Vec<u8>, Vec<u8>)> {
    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .disable_statement_logging();
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .expect("offline connection");
    let rows = sqlx::query(
        "SELECT event_id, event_signature FROM nostr_events
         ORDER BY event_id, event_signature",
    )
    .fetch_all(&mut connection)
    .await
    .expect("signed-event inventory");
    let values = rows
        .into_iter()
        .map(|row| {
            (
                row.try_get::<Vec<u8>, _>("event_id").expect("event id"),
                row.try_get::<Vec<u8>, _>("event_signature")
                    .expect("event signature"),
            )
        })
        .collect();
    connection.close().await.expect("offline close");
    values
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

#[tokio::test]
async fn signed_event_identity_permutations_preserve_both_signatures_and_canonical_state() {
    let wire = vector_wire();
    let first = resign_wire(&wire, 1);
    let second = resign_wire(&wire, 2);
    let first_json: Value = serde_json::from_str(&first).expect("first event");
    let second_json: Value = serde_json::from_str(&second).expect("second event");
    assert_eq!(first_json["id"], second_json["id"]);
    assert_ne!(first_json["sig"], second_json["sig"]);

    let mut inventories = Vec::new();
    for (index, events) in [
        vec![first.clone(), second.clone()],
        vec![second.clone(), first.clone()],
    ]
    .into_iter()
    .enumerate()
    {
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
        let source = ScriptedTransport::new([PageSpec {
            events,
            state: FetchTargetState::Complete,
            next: None,
        }]);
        let outcome = ingest_rhi_trade_source(
            &host.repositories(),
            &adapters(&source),
            &configuration,
            "trade-primary",
            trade_id,
            attempt(
                &format!("signature-permutation-{index}"),
                1_784_347_600 + index as u64,
                1_784_347_600 + index as u64,
            ),
        )
        .await
        .expect("permutation ingest");
        assert_eq!(outcome.completion(), RhiTradeSourceCompletion::Complete);
        assert_eq!(outcome.admitted_events(), 2);
        assert_eq!(outcome.duplicate_events(), 0);
        assert_eq!(outcome.inserted_mutations(), 1);
        assert_eq!(outcome.inserted_signed_events(), 2);
        assert_eq!(outcome.inserted_observations(), 2);
        assert_eq!(outcome.dirty_generation().expect("dirty").get(), 1);
        assert!(outcome.dirty_generation_advanced());
        host.close().await.expect("close");

        assert_eq!(
            offline_scalar(&runtime, "SELECT COUNT(*) FROM trade_mutations").await,
            1
        );
        assert_eq!(
            offline_scalar(&runtime, "SELECT COUNT(*) FROM nostr_events").await,
            2
        );
        assert_eq!(
            offline_scalar(&runtime, "SELECT COUNT(*) FROM relay_observations").await,
            2
        );
        assert_eq!(
            offline_scalar(&runtime, "SELECT COUNT(*) FROM relay_checkpoints").await,
            1
        );
        inventories.push(offline_signed_event_keys(&runtime).await);
    }
    assert_eq!(inventories[0], inventories[1]);
}

#[tokio::test]
async fn checkpoint_and_dirty_generation_survive_close_reopen_and_exact_replay() {
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
    let first_source = ScriptedTransport::new([PageSpec {
        events: vec![wire.clone()],
        state: FetchTargetState::Complete,
        next: None,
    }]);
    let first = ingest_rhi_trade_source(
        &host.repositories(),
        &adapters(&first_source),
        &configuration,
        "trade-primary",
        trade_id,
        attempt("reopen-first", 1_784_347_700, 1_784_347_700),
    )
    .await
    .expect("first ingest");
    assert!(first.checkpoint_advanced());
    assert!(first.dirty_generation_advanced());
    host.close().await.expect("first close");

    let reopened = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("reopen");
    let replay_source = ScriptedTransport::new([PageSpec {
        events: vec![wire],
        state: FetchTargetState::Complete,
        next: None,
    }]);
    let replay = ingest_rhi_trade_source(
        &reopened.repositories(),
        &adapters(&replay_source),
        &configuration,
        "trade-primary",
        trade_id,
        attempt("reopen-replay", 1_784_347_701, 1_784_347_701),
    )
    .await
    .expect("replay after reopen");
    assert_eq!(replay.inserted_mutations(), 0);
    assert_eq!(replay.inserted_signed_events(), 0);
    assert_eq!(replay.inserted_observations(), 1);
    assert!(!replay.checkpoint_advanced());
    assert_eq!(replay.dirty_generation().expect("dirty").get(), 1);
    assert!(!replay.dirty_generation_advanced());
    reopened.close().await.expect("second close");

    assert_eq!(
        offline_scalar(&runtime, "SELECT COUNT(*) FROM trade_mutations").await,
        1
    );
    assert_eq!(
        offline_scalar(&runtime, "SELECT COUNT(*) FROM nostr_events").await,
        1
    );
    assert_eq!(
        offline_scalar(&runtime, "SELECT COUNT(*) FROM relay_observations").await,
        2
    );
    assert_eq!(
        offline_scalar(&runtime, "SELECT generation FROM trade_dirty_generations").await,
        1
    );
}

#[tokio::test]
async fn policy_change_dirties_existing_trade_once_and_starts_a_new_scoped_checkpoint() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path());
    prepare_state_directory(&runtime);
    let current = configuration();
    let changed = parse_rhi_config_v1(
        CONFIG
            .replacen(
                "policy_id = \"production-primary\"",
                "policy_id = \"production-secondary\"",
                1,
            )
            .as_bytes(),
        RhiConfigProfile::RepoLocal,
    )
    .expect("changed configuration");
    let metadata = metadata(&runtime, &current);
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(&runtime, &metadata, applied_at, &build)
        .await
        .expect("initialize");
    let host = open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
        .await
        .expect("writer");
    let trade_id = TradeId::parse("11111111111111111111111111111111").expect("trade id");
    let wire = vector_wire();
    let first_source = ScriptedTransport::new([PageSpec {
        events: vec![wire.clone()],
        state: FetchTargetState::Complete,
        next: None,
    }]);
    let first = ingest_rhi_trade_source(
        &host.repositories(),
        &adapters(&first_source),
        &current,
        "trade-primary",
        trade_id,
        attempt("policy-first", 1_784_347_800, 1_784_347_800),
    )
    .await
    .expect("initial policy ingest");
    assert_eq!(first.dirty_generation().expect("dirty").get(), 1);
    host.close().await.expect("close before apply");

    let changed_at = MigrationAppliedAtUnixSeconds::new(1_784_347_801).expect("policy time");
    let (_, changed_build) = migration_evidence();
    let applied = apply_rhi_configuration(&runtime, &current, &changed, changed_at, &changed_build)
        .await
        .expect("policy apply");
    assert_eq!(applied.generation(), 2);
    assert!(applied.changed());

    let changed_host =
        open_rhi_state_read_write_from_config(&runtime, &changed, changed_at, &changed_build)
            .await
            .expect("changed writer");
    let changed_source = ScriptedTransport::new([PageSpec {
        events: vec![wire],
        state: FetchTargetState::Complete,
        next: None,
    }]);
    let replay = ingest_rhi_trade_source(
        &changed_host.repositories(),
        &adapters(&changed_source),
        &changed,
        "trade-primary",
        trade_id,
        attempt("policy-replay", 1_784_347_802, 1_784_347_802),
    )
    .await
    .expect("new-policy replay");
    assert_eq!(replay.inserted_mutations(), 0);
    assert_eq!(replay.inserted_signed_events(), 0);
    assert_eq!(replay.inserted_observations(), 1);
    assert!(replay.checkpoint_advanced());
    assert_eq!(replay.dirty_generation().expect("dirty").get(), 2);
    assert!(!replay.dirty_generation_advanced());
    changed_host.close().await.expect("changed close");

    assert_eq!(
        offline_scalar(&runtime, "SELECT COUNT(*) FROM relay_checkpoints").await,
        2
    );
    assert_eq!(
        offline_scalar(&runtime, "SELECT generation FROM trade_dirty_generations").await,
        2
    );
}

#[tokio::test]
async fn concurrent_source_attempts_commit_once_and_generation_conflict_rolls_back_loser() {
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
            events: vec![wire.clone()],
            state: FetchTargetState::Complete,
            next: None,
        },
        PageSpec {
            events: vec![wire],
            state: FetchTargetState::Complete,
            next: None,
        },
    ])
    .with_fetch_barrier(2);
    let transports = adapters(&source);
    let repositories = host.repositories();
    let (first, second) = tokio::join!(
        ingest_rhi_trade_source(
            &repositories,
            &transports,
            &configuration,
            "trade-primary",
            trade_id,
            attempt("concurrent-first", 1_784_347_900, 1_784_347_900),
        ),
        ingest_rhi_trade_source(
            &repositories,
            &transports,
            &configuration,
            "trade-primary",
            trade_id,
            attempt("concurrent-second", 1_784_347_901, 1_784_347_901),
        ),
    );
    let results = [first, second];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let error = results
        .iter()
        .find_map(|result| result.as_ref().err())
        .expect("generation conflict");
    assert_eq!(
        error.kind(),
        RhiTradeSourceIngestErrorKind::GenerationConflict
    );
    host.close().await.expect("close");

    assert_eq!(
        offline_scalar(&runtime, "SELECT COUNT(*) FROM trade_mutations").await,
        1
    );
    assert_eq!(
        offline_scalar(&runtime, "SELECT COUNT(*) FROM nostr_events").await,
        1
    );
    assert_eq!(
        offline_scalar(&runtime, "SELECT COUNT(*) FROM relay_observations").await,
        1
    );
    assert_eq!(
        offline_scalar(&runtime, "SELECT COUNT(*) FROM relay_checkpoints").await,
        1
    );
    assert_eq!(
        offline_scalar(&runtime, "SELECT generation FROM trade_dirty_generations").await,
        1
    );
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
