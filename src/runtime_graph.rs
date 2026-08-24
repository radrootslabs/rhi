//! Binary-invoked RHI daemon graph with fixed task ownership and bounded shutdown.

use core::{fmt, future::pending, time::Duration};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use radroots_event::id::TradeId;
use radroots_service_host::{
    GracefulShutdown, HostError, HostErrorKind, ProcessSignal, ProcessSignalAdapter,
    ProcessSignalFuture, ProcessSignalSource, ShutdownDisposition, ShutdownPhase,
    ShutdownPhaseFuture, ShutdownPhaseHandler, SupervisedTaskExitStatus, TaskClassification,
    TaskMetadata, TaskName,
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_transport::{
    FetchRequest, SubscriptionNext, SubscriptionRequest, Target, TargetSet,
    outcome::FetchTargetState,
    source::{
        FETCH_PAGE_MAX_EVENTS, FetchBounds, FetchCursor, FetchSelector, NextPage,
        SubscriptionBounds,
    },
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::Row;

use crate::transport_nostr_adapter::{RhiNostrExactSink, build_rhi_nostr_adapters};
use crate::{
    RhiAdminCancellationToken, RhiAdminServer, RhiAdmittedTradeMutationEvent, RhiBoundAdminServer,
    RhiBoundOperationsServer, RhiConfigDocumentV1, RhiEvidenceAttestationSupersession,
    RhiEvidenceTransportStatusV1, RhiIdentityHealthV1, RhiIntegrityStateV1,
    RhiJitterBoundMilliseconds, RhiOperationsCancellationToken, RhiOperationsServer,
    RhiPersistenceHealthV1, RhiPersistenceStatusV1, RhiPresenceDesiredAuthority,
    RhiPresenceLeaseOwner, RhiPresenceStatusV1, RhiProcessResult, RhiProcessSignal,
    RhiProcessSignalSource, RhiProviderStatusV1, RhiPublicationAuthority, RhiPublicationLeaseOwner,
    RhiPublicationStatusV1, RhiReconciliationAttemptPlan, RhiReconciliationJobPolicy,
    RhiReconciliationLease, RhiReconciliationLeaseOwner, RhiReconciliationRetryDelayMilliseconds,
    RhiReconciliationScopePrerequisites, RhiReconciliationSourceReplay,
    RhiReconciliationSourceReplayPlan, RhiReconciliationSourceRequest, RhiReconciliationStatusV1,
    RhiReconciliationUnixMilliseconds, RhiRuntimeFoundation, RhiServicePhase, RhiStateHost,
    RhiStatusBuildInfoV1, RhiStatusBuildMode, RhiStatusCommonV1, RhiStatusConfigurationIdentityV1,
    RhiStatusConfigurationSource, RhiStatusObservationV1, RhiStatusPublisher, RhiStatusReasonCode,
    RhiStatusReasonCodes, RhiStatusUnixSeconds, RhiTimeEntropyAdapters,
    RhiTradeMutationAdmissionLimits, RhiTradeMutationAuthoredTimePolicy,
    RhiTradeMutationObservedAtUnixSeconds, RhiTradeSourceAttempt, RhiTradeSourceCompletion,
    RhiTransportHealthV1, admit_rhi_trade_mutation_event, build_rhi_signed_evidence_attestation,
    build_rhi_signed_presence_documents, evaluate_rhi_reconciliation_claim,
    open_rhi_runtime_foundation, reduce_rhi_reconciliation_manifest, rhi_status_cache,
};
use crate::{reconciliation_replay, source_ingest, state_config};

const TASK_ADMIN_SERVER: &str = "admin_server";
const TASK_OPERATIONS_SERVER: &str = "operations_server";
const TASK_SOURCE_SUBSCRIPTION: &str = "source_subscription";
const TASK_RECONCILIATION_WORKER: &str = "reconciliation_worker";
const TASK_PUBLICATION_WORKER: &str = "publication_worker";
const TASK_PRESENCE_WORKER: &str = "presence_worker";
const TRADE_EVENT_KINDS: [u32; 5] = [3470, 3471, 3472, 3473, 3474];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RhiDaemonErrorKind {
    State,
    Identity,
    Transport,
    Admin,
    Operations,
    Runtime,
}

struct RhiDaemonError {
    kind: RhiDaemonErrorKind,
}

impl RhiDaemonError {
    const fn new(kind: RhiDaemonErrorKind) -> Self {
        Self { kind }
    }

    const fn process_result(&self) -> RhiProcessResult {
        match self.kind {
            RhiDaemonErrorKind::State | RhiDaemonErrorKind::Identity => {
                RhiProcessResult::StateOrIdentityUnavailable
            }
            RhiDaemonErrorKind::Transport
            | RhiDaemonErrorKind::Admin
            | RhiDaemonErrorKind::Operations => RhiProcessResult::ServiceOrDependencyUnavailable,
            RhiDaemonErrorKind::Runtime => RhiProcessResult::UnexpectedInternal,
        }
    }
}

impl fmt::Debug for RhiDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiDaemonError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RHI daemon failed")
    }
}

impl Error for RhiDaemonError {}

struct HostSignalSource<S> {
    inner: S,
}

impl<S> HostSignalSource<S> {
    const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> ProcessSignalSource for HostSignalSource<S>
where
    S: RhiProcessSignalSource,
{
    fn next_signal(&mut self) -> ProcessSignalFuture<'_> {
        Box::pin(async move {
            self.inner.next_signal().await.map(|signal| match signal {
                RhiProcessSignal::Interrupt => ProcessSignal::Interrupt,
                #[cfg(unix)]
                RhiProcessSignal::Terminate => ProcessSignal::Terminate,
            })
        })
    }
}

struct RuntimeShutdownHandler {
    accepting_mutations: Arc<AtomicBool>,
    status: RhiStatusPublisher,
    status_context: RuntimeStatusContext,
    transport_ready: bool,
    operations_ready: bool,
}

impl RuntimeShutdownHandler {
    fn publish(&mut self, phase: RhiServicePhase) -> Result<(), HostError> {
        self.status
            .publish(self.status_context.observation(
                phase,
                self.transport_ready,
                self.operations_ready,
            )?)
            .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))
    }

    fn running_phase(&self) -> RhiServicePhase {
        if self.transport_ready && self.operations_ready {
            RhiServicePhase::Ready
        } else {
            RhiServicePhase::Degraded
        }
    }
}

impl ShutdownPhaseHandler for RuntimeShutdownHandler {
    fn enter(&mut self, phase: ShutdownPhase) -> ShutdownPhaseFuture<'_> {
        Box::pin(async move {
            if phase == ShutdownPhase::RejectNewMutations {
                self.accepting_mutations.store(false, Ordering::Release);
                self.publish(RhiServicePhase::Stopping)?;
            }
            Ok(())
        })
    }
}

struct RuntimeStatusContext {
    configuration_digest: String,
    configuration_source: RhiStatusConfigurationSource,
    schema_version: u32,
    generation: u64,
    source_count: u64,
    started_at: radroots_service_host::MonotonicTime,
    time_entropy: RhiTimeEntropyAdapters,
    reconciliation: RhiReconciliationStatusV1,
    publication: RhiPublicationStatusV1,
    presence: RhiPresenceStatusV1,
}

impl RuntimeStatusContext {
    async fn refresh_state(&mut self, state: &RhiStateHost) -> Result<(), HostError> {
        let summary = state
            .sqlite_host()
            .transaction(|transaction| {
                Box::pin(async move {
                    let row = sqlx::query(RUNTIME_STATUS_SQL)
                        .fetch_one(&mut *transaction)
                        .await
                        .map_err(|_| ())?;
                    Ok::<_, ()>((
                        row.try_get::<i64, _>("reconciliation_pending")
                            .map_err(|_| ())?,
                        row.try_get::<i64, _>("reconciliation_leased")
                            .map_err(|_| ())?,
                        row.try_get::<i64, _>("reconciliation_exhausted")
                            .map_err(|_| ())?,
                        row.try_get::<Option<i64>, _>("reconciliation_oldest")
                            .map_err(|_| ())?,
                        row.try_get::<i64, _>("publication_pending")
                            .map_err(|_| ())?,
                        row.try_get::<i64, _>("publication_unknown")
                            .map_err(|_| ())?,
                        row.try_get::<Option<i64>, _>("publication_oldest")
                            .map_err(|_| ())?,
                        row.try_get::<i64, _>("presence_pending").map_err(|_| ())?,
                        row.try_get::<i64, _>("presence_unknown").map_err(|_| ())?,
                    ))
                })
            })
            .await
            .map_err(|_| HostError::new(HostErrorKind::Lifecycle))?;
        self.reconciliation = RhiReconciliationStatusV1::new(
            status_count(summary.0)?,
            status_count(summary.1)?,
            status_count(summary.2)?,
            status_time(summary.3)?,
        );
        self.publication = RhiPublicationStatusV1::new(
            status_count(summary.4)?,
            status_count(summary.5)?,
            status_time(summary.6)?,
        );
        self.presence =
            RhiPresenceStatusV1::new(status_count(summary.7)?, status_count(summary.8)?);
        Ok(())
    }

    fn observation(
        &self,
        phase: RhiServicePhase,
        transport_ready: bool,
        operations_ready: bool,
    ) -> Result<RhiStatusObservationV1, HostError> {
        let ready =
            matches!(phase, RhiServicePhase::Ready | RhiServicePhase::Degraded) && transport_ready;
        let mut transport_reasons = Vec::new();
        if !transport_ready {
            transport_reasons.push(RhiStatusReasonCode::SourceUnavailable);
            transport_reasons.push(RhiStatusReasonCode::SubscriptionInactive);
        }
        let transport_reasons = RhiStatusReasonCodes::new(transport_reasons)
            .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
        let mut lifecycle_reasons = transport_reasons.as_slice().to_vec();
        if !operations_ready {
            lifecycle_reasons.push(RhiStatusReasonCode::OperationsListenerFailed);
        }
        if phase == RhiServicePhase::Stopping {
            lifecycle_reasons.push(RhiStatusReasonCode::ShutdownInProgress);
        }
        let lifecycle_reasons = RhiStatusReasonCodes::new(lifecycle_reasons)
            .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
        let transport_health = if transport_ready {
            RhiTransportHealthV1::Ready
        } else {
            RhiTransportHealthV1::Unavailable
        };
        let uptime = self
            .time_entropy
            .now_monotonic()
            .duration_since_origin()
            .saturating_sub(self.started_at.duration_since_origin())
            .as_millis();
        let uptime = u64::try_from(uptime).map_err(|_| HostError::new(HostErrorKind::Lifecycle))?;
        let build = runtime_build_info()?;
        let configuration = RhiStatusConfigurationIdentityV1::new(
            &self.configuration_digest,
            self.configuration_source,
        )
        .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
        let persistence = RhiPersistenceStatusV1::new(
            RhiPersistenceHealthV1::Ready,
            self.schema_version,
            self.generation,
            RhiIntegrityStateV1::Verified,
            RhiStatusReasonCodes::empty(),
        )
        .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
        let identity = RhiIdentityHealthV1::new(true, true, RhiStatusReasonCodes::empty())
            .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
        let provider = RhiProviderStatusV1::new(identity, RhiStatusReasonCodes::empty())
            .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
        let transport = RhiEvidenceTransportStatusV1::new(
            transport_health,
            transport_ready,
            transport_ready,
            self.source_count,
            if transport_ready {
                self.source_count
            } else {
                0
            },
            transport_reasons,
        )
        .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
        let common = RhiStatusCommonV1::new(
            phase,
            ready,
            lifecycle_reasons,
            uptime,
            build,
            configuration,
            persistence,
        )
        .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))?;
        Ok(RhiStatusObservationV1::new(
            common,
            provider,
            transport,
            self.reconciliation,
            self.publication,
            self.presence,
        ))
    }
}

const RUNTIME_STATUS_SQL: &str = r#"SELECT
    (SELECT COUNT(*) FROM reconciliation_jobs WHERE state = 'ready')
        AS reconciliation_pending,
    (SELECT COUNT(*) FROM reconciliation_jobs WHERE state = 'leased')
        AS reconciliation_leased,
    (SELECT COUNT(*) FROM reconciliation_jobs WHERE state = 'exhausted')
        AS reconciliation_exhausted,
    (SELECT MIN(created_at_unix_ms / 1000) FROM reconciliation_jobs WHERE state = 'ready')
        AS reconciliation_oldest,
    (SELECT COUNT(*) FROM publication_outbox WHERE state IN ('pending', 'leased'))
        AS publication_pending,
    (SELECT COUNT(*) FROM publication_outbox AS outbox
        WHERE outbox.state = 'blocked' OR EXISTS (
            SELECT 1 FROM publication_targets AS target
            WHERE target.outbox_id = outbox.outbox_id AND target.state = 'unknown'))
        AS publication_unknown,
    (SELECT MIN(created_at_unix_ms / 1000) FROM publication_outbox
        WHERE state IN ('pending', 'leased')) AS publication_oldest,
    (SELECT COUNT(*) FROM presence_outbox WHERE state IN ('pending', 'leased'))
        AS presence_pending,
    (SELECT COUNT(*) FROM presence_outbox AS outbox
        WHERE outbox.state = 'blocked' OR EXISTS (
            SELECT 1 FROM presence_targets AS target
            WHERE target.outbox_id = outbox.outbox_id AND target.state = 'unknown'))
        AS presence_unknown"#;

fn status_count(value: i64) -> Result<u64, HostError> {
    u64::try_from(value).map_err(|_| HostError::new(HostErrorKind::Lifecycle))
}

fn status_time(value: Option<i64>) -> Result<Option<RhiStatusUnixSeconds>, HostError> {
    value
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| HostError::new(HostErrorKind::Lifecycle))
                .and_then(|value| {
                    RhiStatusUnixSeconds::new(value)
                        .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))
                })
        })
        .transpose()
}

struct SourceBinding {
    source_id: Box<str>,
    target: Target,
}

struct InitialSubscription {
    request: SubscriptionRequest,
    subscription: radroots_transport::BoxSubscription,
    sources: Box<[SourceBinding]>,
}

/// Executes the real RHI daemon and converts every failure to the frozen process result.
pub(crate) async fn run_rhi_daemon<S>(
    runtime: crate::RhiRuntimeContext,
    configuration: RhiConfigDocumentV1,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
    signals: S,
) -> RhiProcessResult
where
    S: RhiProcessSignalSource + 'static,
{
    run_rhi_daemon_inner(runtime, configuration, applied_at, build, signals)
        .await
        .unwrap_or_else(|error| error.process_result())
}

async fn run_rhi_daemon_inner<S>(
    runtime: crate::RhiRuntimeContext,
    configuration: RhiConfigDocumentV1,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
    signals: S,
) -> Result<RhiProcessResult, RhiDaemonError>
where
    S: RhiProcessSignalSource + 'static,
{
    let (transport, exact_sink) = build_rhi_nostr_adapters(&configuration)
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Transport))?;
    let adapters = crate::RhiRuntimeAdapters::new(
        crate::RhiTimeEntropyAdapters::system(),
        transport,
        crate::RhiIdentityCredentialAdapters::canonical(),
    );
    let mut foundation =
        open_rhi_runtime_foundation(runtime, configuration, adapters, applied_at, build)
            .await
            .map_err(|error| match error.kind() {
                crate::RhiRuntimeFoundationErrorKind::IdentityAccess
                | crate::RhiRuntimeFoundationErrorKind::IdentityBinding => {
                    RhiDaemonError::new(RhiDaemonErrorKind::Identity)
                }
                _ => RhiDaemonError::new(RhiDaemonErrorKind::State),
            })?;

    let configuration = foundation.configuration_arc();
    let state = foundation.state();
    let publication = Arc::new(
        RhiPublicationAuthority::from_config(&configuration)
            .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?,
    );
    let presence = Arc::new(
        RhiPresenceDesiredAuthority::from_config(&configuration)
            .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?,
    );
    initialize_presence(&foundation, &presence)
        .await
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::State))?;

    let initial_subscription = open_initial_subscription(&foundation, &configuration)
        .await
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Transport))?;
    let generation = u64::from(
        state_config::current_generation(&state)
            .await
            .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::State))?,
    );
    let source_count = u64::try_from(initial_subscription.sources.len())
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;
    let time_entropy = foundation.adapters().time_entropy().clone();
    let started_at = time_entropy.now_monotonic();
    let mut status_context = RuntimeStatusContext {
        configuration_digest: lower_hex(state.metadata().configuration_digest().as_bytes()),
        configuration_source: if foundation.runtime_context().profile()
            == crate::RhiBootstrapProfileV1::RepoLocal
        {
            RhiStatusConfigurationSource::DerivedRepoLocal
        } else {
            RhiStatusConfigurationSource::ExplicitConfig
        },
        schema_version: crate::RHI_STATE_SCHEMA_VERSION,
        generation,
        source_count,
        started_at,
        time_entropy: time_entropy.clone(),
        reconciliation: RhiReconciliationStatusV1::default(),
        publication: RhiPublicationStatusV1::default(),
        presence: RhiPresenceStatusV1::default(),
    };
    status_context
        .refresh_state(&state)
        .await
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::State))?;
    let (status, status_reader) = rhi_status_cache(
        foundation.runtime_context().context().instance().clone(),
        status_context
            .observation(RhiServicePhase::Starting, true, true)
            .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?,
    )
    .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;
    let accepting_mutations = Arc::new(AtomicBool::new(true));
    let mut cursor_key = [0_u8; 32];
    time_entropy
        .entropy()
        .fill_bytes(&mut cursor_key)
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;
    let admin_handler = Arc::new(crate::runtime_admin::RuntimeAdminHandler {
        state: Arc::clone(&state),
        configuration: Arc::clone(&configuration),
        identity: foundation.identity_arc(),
        publication: Arc::clone(&publication),
        presence: Arc::clone(&presence),
        status: status_reader.clone(),
        accepting_mutations: Arc::clone(&accepting_mutations),
        cursor_key,
        time_entropy: time_entropy.clone(),
    });
    let admin = RhiAdminServer::new(&configuration, admin_handler)
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Admin))?
        .bind(foundation.runtime_context())
        .await
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Admin))?;
    let operations = if operations_enabled(&configuration)? {
        Some(
            RhiOperationsServer::new(&configuration, &status_reader)
                .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Operations))?
                .bind()
                .await
                .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Operations))?,
        )
    } else {
        None
    };

    spawn_admin(foundation.supervisor_mut(), admin)?;
    if let Some(operations) = operations {
        spawn_operations(foundation.supervisor_mut(), operations)?;
    }
    let source_transport = foundation.adapters().transport().clone();
    let (transport_health_sender, mut transport_health) = tokio::sync::watch::channel(true);
    spawn_source_subscription(
        foundation.supervisor_mut(),
        Arc::clone(&state),
        Arc::clone(&configuration),
        source_transport,
        time_entropy.clone(),
        initial_subscription,
        transport_health_sender,
    )?;
    let reconciliation_transport = foundation.adapters().transport().clone();
    let reconciliation_time = foundation.adapters().time_entropy().clone();
    let reconciliation_identity = foundation.identity_arc();
    spawn_reconciliation_worker(
        foundation.supervisor_mut(),
        Arc::clone(&state),
        Arc::clone(&configuration),
        reconciliation_transport,
        reconciliation_time,
        reconciliation_identity,
        Arc::clone(&publication),
    )?;
    spawn_publication_worker(
        foundation.supervisor_mut(),
        Arc::clone(&state),
        Arc::clone(&configuration),
        Arc::clone(&publication),
        Arc::clone(&exact_sink),
        time_entropy.clone(),
    )?;
    spawn_presence_worker(
        foundation.supervisor_mut(),
        Arc::clone(&state),
        Arc::clone(&configuration),
        Arc::clone(&exact_sink),
        time_entropy,
    )?;

    let mut shutdown_handler = RuntimeShutdownHandler {
        accepting_mutations,
        status,
        status_context,
        transport_ready: true,
        operations_ready: true,
    };
    shutdown_handler
        .publish(RhiServicePhase::Ready)
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;

    let mut signals = ProcessSignalAdapter::new(HostSignalSource::new(signals));
    let refresh_period = worker_idle(&configuration)
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;
    let mut status_refresh = tokio::time::interval(refresh_period);
    status_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    status_refresh.tick().await;
    let signal_initiated = loop {
        tokio::select! {
            action = signals.next_action() => {
                match action {
                    Ok(action) if !action.forces_termination() => break true,
                    Ok(_) | Err(_) => break false,
                }
            }
            changed = transport_health.changed() => {
                if changed.is_err() {
                    break false;
                }
                let ready = *transport_health.borrow_and_update();
                shutdown_handler.transport_ready = ready;
                shutdown_handler.publish(shutdown_handler.running_phase())
                    .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;
            }
            joined = foundation.supervisor_mut().join_next() => {
                match joined {
                    Some(Ok(exit))
                        if exit.status() == SupervisedTaskExitStatus::OptionalFailure
                            || exit.metadata().name().as_str() == TASK_OPERATIONS_SERVER => {
                        shutdown_handler.operations_ready = false;
                        shutdown_handler.publish(shutdown_handler.running_phase())
                            .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;
                    }
                    Some(Ok(_)) | Some(Err(_)) | None => break false,
                }
            }
            _ = status_refresh.tick() => {
                shutdown_handler.status_context.refresh_state(&state).await
                    .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::State))?;
                shutdown_handler.publish(shutdown_handler.running_phase())
                    .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;
            }
        }
    };
    let grace = Duration::from_millis(configuration_integer(
        &configuration,
        "/service/shutdown_grace_ms",
    )?);
    let mut shutdown = GracefulShutdown::new(grace)
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;
    let clock = radroots_service_host::SystemMonotonicClock::new();
    let summary = if signal_initiated {
        shutdown
            .run(
                &clock,
                foundation.supervisor_mut(),
                &mut shutdown_handler,
                async {
                    let _ = signals.next_action().await;
                },
            )
            .await
    } else {
        shutdown
            .run(
                &clock,
                foundation.supervisor_mut(),
                &mut shutdown_handler,
                pending::<()>(),
            )
            .await
    }
    .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?;
    drop(shutdown_handler);
    drop(state);
    foundation
        .shutdown()
        .await
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::State))?;
    if signal_initiated && summary.disposition() == ShutdownDisposition::Completed {
        Ok(RhiProcessResult::Success)
    } else {
        Err(RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
    }
}

async fn initialize_presence(
    foundation: &RhiRuntimeFoundation,
    authority: &RhiPresenceDesiredAuthority,
) -> Result<(), HostError> {
    let state = foundation.state();
    let desired = state
        .repositories()
        .desired_presence()
        .commit(authority)
        .await
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    if desired.changed() {
        let documents = build_rhi_signed_presence_documents(
            desired,
            authority,
            foundation.identity(),
            foundation
                .adapters()
                .time_entropy()
                .now_utc()
                .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?,
            foundation.adapters().time_entropy().entropy(),
        )
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
        let now = crate::RhiPresenceUnixMilliseconds::new(
            foundation
                .adapters()
                .time_entropy()
                .now_utc_milliseconds()
                .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?,
        )
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
        state
            .repositories()
            .presence_outbox()
            .commit_signed_presence(&documents, now)
            .await
            .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    }
    Ok(())
}

async fn open_initial_subscription(
    foundation: &RhiRuntimeFoundation,
    configuration: &RhiConfigDocumentV1,
) -> Result<InitialSubscription, HostError> {
    let sources = configured_sources(configuration)?;
    let (request, subscription) = subscribe_sources(
        configuration,
        foundation.adapters().transport(),
        foundation.adapters().time_entropy(),
        &sources,
    )
    .await?;
    Ok(InitialSubscription {
        request,
        subscription,
        sources: sources.into_boxed_slice(),
    })
}

async fn subscribe_sources(
    configuration: &RhiConfigDocumentV1,
    transport: &crate::RhiTransportAdapters,
    time_entropy: &RhiTimeEntropyAdapters,
    sources: &[SourceBinding],
) -> Result<(SubscriptionRequest, radroots_transport::BoxSubscription), HostError> {
    let targets = TargetSet::new(sources.iter().map(|source| source.target.clone()).collect())
        .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
    let deadline = time_entropy
        .now_utc_milliseconds()
        .ok()
        .and_then(|now| now.checked_add(maximum_source_deadline(configuration).ok()?))
        .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?;
    let selector = FetchSelector::all()
        .with_kinds(TRADE_EVENT_KINDS.to_vec())
        .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
    let request = SubscriptionRequest::new(
        "rhi-source-subscription",
        targets,
        SubscriptionBounds::new(1_000, deadline)
            .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?,
    )
    .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?
    .with_selector(selector);
    let subscription = transport
        .evidence_subscriber()
        .subscribe(request.clone())
        .await
        .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
    Ok((request, subscription))
}

fn configured_sources(
    configuration: &RhiConfigDocumentV1,
) -> Result<Vec<SourceBinding>, HostError> {
    let relays = configuration
        .normalized()
        .pointer("/relays")
        .and_then(Value::as_array)
        .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?;
    let relay_urls = relays
        .iter()
        .map(|relay| {
            let id = relay.pointer("/id").and_then(Value::as_str)?;
            let url = relay.pointer("/url").and_then(Value::as_str)?;
            Some((id, url))
        })
        .collect::<Option<BTreeMap<_, _>>>()
        .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?;
    configuration
        .normalized()
        .pointer("/evidence/sources")
        .and_then(Value::as_array)
        .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?
        .iter()
        .map(|source| {
            let source_id = source
                .pointer("/source_id")
                .and_then(Value::as_str)
                .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?;
            let relay_id = source
                .pointer("/relay_id")
                .and_then(Value::as_str)
                .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?;
            let url = relay_urls
                .get(relay_id)
                .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?;
            Ok(SourceBinding {
                source_id: source_id.into(),
                target: Target::nostr_relay(url)
                    .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?,
            })
        })
        .collect()
}

fn spawn_admin(
    supervisor: &mut radroots_service_host::TaskSupervisor,
    server: RhiBoundAdminServer,
) -> Result<(), RhiDaemonError> {
    supervisor
        .spawn(
            task_metadata(TASK_ADMIN_SERVER, TaskClassification::Critical, ShutdownPhase::CloseSockets)?,
            move |cancellation| async move {
                let token = RhiAdminCancellationToken::new();
                let serve_token = token.clone();
                let serve = server.serve(serve_token);
                tokio::pin!(serve);
                tokio::select! {
                    result = serve.as_mut() => result.map_err(|error| HostError::with_source(HostErrorKind::AdminTransport, error)),
                    () = cancellation.cancelled() => {
                        token.cancel();
                        serve.await.map_err(|error| HostError::with_source(HostErrorKind::AdminTransport, error))
                    }
                }
            },
        )
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
}

fn spawn_operations(
    supervisor: &mut radroots_service_host::TaskSupervisor,
    server: RhiBoundOperationsServer,
) -> Result<(), RhiDaemonError> {
    supervisor
        .spawn(
            task_metadata(TASK_OPERATIONS_SERVER, TaskClassification::Optional, ShutdownPhase::CloseSockets)?,
            move |cancellation| async move {
                let token = RhiOperationsCancellationToken::new();
                let serve_token = token.clone();
                let serve = server.serve(serve_token);
                tokio::pin!(serve);
                tokio::select! {
                    result = serve.as_mut() => result.map_err(|error| HostError::with_source(HostErrorKind::OperationsServe, error)),
                    () = cancellation.cancelled() => {
                        token.cancel();
                        serve.await.map_err(|error| HostError::with_source(HostErrorKind::OperationsServe, error))
                    }
                }
            },
        )
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
}

fn spawn_source_subscription(
    supervisor: &mut radroots_service_host::TaskSupervisor,
    state: Arc<RhiStateHost>,
    configuration: Arc<RhiConfigDocumentV1>,
    transport: crate::RhiTransportAdapters,
    time_entropy: RhiTimeEntropyAdapters,
    initial: InitialSubscription,
    health: tokio::sync::watch::Sender<bool>,
) -> Result<(), RhiDaemonError> {
    supervisor
        .spawn(
            task_metadata(
                TASK_SOURCE_SUBSCRIPTION,
                TaskClassification::Critical,
                ShutdownPhase::CancelIngress,
            )?,
            move |cancellation| async move {
                run_source_subscription(
                    cancellation,
                    state,
                    configuration,
                    transport,
                    time_entropy,
                    initial,
                    health,
                )
                .await
            },
        )
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
}

async fn run_source_subscription(
    cancellation: radroots_service_host::CancellationToken,
    state: Arc<RhiStateHost>,
    configuration: Arc<RhiConfigDocumentV1>,
    transport: crate::RhiTransportAdapters,
    time_entropy: RhiTimeEntropyAdapters,
    mut active: InitialSubscription,
    health: tokio::sync::watch::Sender<bool>,
) -> Result<(), HostError> {
    let policy = RhiReconciliationJobPolicy::from_configuration(&configuration)
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let retry_delay = worker_idle(&configuration)?;
    loop {
        let next = tokio::select! {
            () = cancellation.cancelled() => {
                active.subscription.cancel().await
                    .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
                return Ok(());
            }
            next = active.subscription.next() => next,
        };
        let reconnect = match next {
            Ok(SubscriptionNext::Event(event)) => {
                event
                    .validate_for_request(&active.request)
                    .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
                let Some(source) = active.sources.iter().find(|source| {
                    source.target.fingerprint() == event.observed().provenance().target()
                }) else {
                    return Err(HostError::new(HostErrorKind::TaskFailure));
                };
                let now = time_entropy
                    .now_utc()
                    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?
                    .get();
                let observed = RhiTradeMutationObservedAtUnixSeconds::new(now)
                    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
                let limits = RhiTradeMutationAdmissionLimits::from_config(&configuration)
                    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
                let admitted = match admit_rhi_trade_mutation_event(
                    limits,
                    event.observed().event().raw_json().as_bytes(),
                    observed,
                    RhiTradeMutationAuthoredTimePolicy::new(0).map_err(|error| {
                        HostError::with_source(HostErrorKind::TaskFailure, error)
                    })?,
                ) {
                    Ok(admitted) => admitted,
                    Err(_) => continue,
                };
                let trade_id = admitted.mutation().trade_id;
                let attempt = RhiTradeSourceAttempt::new(
                    subscription_attempt_id(event.checkpoint().cursor().as_str()),
                    radroots_service_host::UnixTimeSeconds::new(now),
                    observed,
                    RhiTradeMutationAuthoredTimePolicy::new(0).map_err(|error| {
                        HostError::with_source(HostErrorKind::TaskFailure, error)
                    })?,
                )
                .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
                let outcome = source_ingest::ingest_rhi_subscribed_trade_event(
                    &state.repositories(),
                    &configuration,
                    &source.source_id,
                    admitted,
                    attempt,
                )
                .await
                .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
                if outcome.dirty_generation_advanced() {
                    state
                        .repositories()
                        .reconciliation_jobs()
                        .schedule_trade(
                            trade_id,
                            policy,
                            RhiReconciliationUnixMilliseconds::new(
                                now.checked_mul(1_000)
                                    .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?,
                            )
                            .map_err(|error| {
                                HostError::with_source(HostErrorKind::TaskFailure, error)
                            })?,
                        )
                        .await
                        .map_err(|error| {
                            HostError::with_source(HostErrorKind::TaskFailure, error)
                        })?;
                }
                false
            }
            Ok(SubscriptionNext::End(end)) => {
                end.validate_for_request(&active.request)
                    .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
                true
            }
            Err(_) => true,
        };
        if !reconnect {
            continue;
        }
        health.send_replace(false);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                () = tokio::time::sleep(retry_delay) => {}
            }
            match subscribe_sources(&configuration, &transport, &time_entropy, &active.sources)
                .await
            {
                Ok((request, subscription)) => {
                    active.request = request;
                    active.subscription = subscription;
                    health.send_replace(true);
                    break;
                }
                Err(_) => continue,
            }
        }
    }
}

fn spawn_reconciliation_worker(
    supervisor: &mut radroots_service_host::TaskSupervisor,
    state: Arc<RhiStateHost>,
    configuration: Arc<RhiConfigDocumentV1>,
    transport: crate::RhiTransportAdapters,
    time_entropy: RhiTimeEntropyAdapters,
    identity: Arc<crate::RhiDecryptedIdentity>,
    publication: Arc<RhiPublicationAuthority>,
) -> Result<(), RhiDaemonError> {
    supervisor
        .spawn(
            task_metadata(
                TASK_RECONCILIATION_WORKER,
                TaskClassification::Critical,
                ShutdownPhase::DrainOperations,
            )?,
            move |cancellation| async move {
                run_reconciliation_worker(
                    cancellation,
                    state,
                    configuration,
                    transport,
                    time_entropy,
                    identity,
                    publication,
                )
                .await
            },
        )
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
}

async fn run_reconciliation_worker(
    cancellation: radroots_service_host::CancellationToken,
    state: Arc<RhiStateHost>,
    configuration: Arc<RhiConfigDocumentV1>,
    transport: crate::RhiTransportAdapters,
    time_entropy: RhiTimeEntropyAdapters,
    identity: Arc<crate::RhiDecryptedIdentity>,
    publication: Arc<RhiPublicationAuthority>,
) -> Result<(), HostError> {
    let owner = RhiReconciliationLeaseOwner::from_bytes(nonzero_entropy_16(&time_entropy)?)
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let idle = Duration::from_millis(
        configuration_integer(&configuration, "/reconciliation/initial_backoff_ms")
            .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?,
    );
    loop {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        let now = reconciliation_now_with(&time_entropy)?;
        let lease = state
            .repositories()
            .reconciliation_jobs()
            .claim_next(owner, now)
            .await
            .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
        let Some(lease) = lease else {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                () = tokio::time::sleep(idle) => continue,
            }
        };
        let completed = execute_reconciliation_attempt(
            &cancellation,
            &state,
            &configuration,
            &transport,
            &time_entropy,
            &identity,
            &publication,
            lease,
            now,
        )
        .await;
        if completed.is_err() && !cancellation.is_cancelled() {
            let maximum = RhiJitterBoundMilliseconds::new(lease.retry_delay_upper_bound())
                .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
            let delay = time_entropy
                .sample_full_jitter(maximum)
                .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
            state
                .repositories()
                .reconciliation_jobs()
                .record_failure(
                    lease,
                    reconciliation_now_with(&time_entropy)?,
                    RhiReconciliationRetryDelayMilliseconds::new(delay.get()).map_err(|error| {
                        HostError::with_source(HostErrorKind::TaskFailure, error)
                    })?,
                )
                .await
                .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
        } else if cancellation.is_cancelled() {
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_reconciliation_attempt(
    cancellation: &radroots_service_host::CancellationToken,
    state: &RhiStateHost,
    configuration: &RhiConfigDocumentV1,
    transport: &crate::RhiTransportAdapters,
    time_entropy: &RhiTimeEntropyAdapters,
    identity: &crate::RhiDecryptedIdentity,
    publication: &RhiPublicationAuthority,
    lease: RhiReconciliationLease,
    started_at: RhiReconciliationUnixMilliseconds,
) -> Result<(), HostError> {
    let plan = RhiReconciliationAttemptPlan::from_claim(lease, configuration, started_at)
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let mut replays = Vec::with_capacity(plan.requests().len());
    for request in plan.requests() {
        if cancellation.is_cancelled() {
            return Err(HostError::new(HostErrorKind::TaskFailure));
        }
        let prior = reconciliation_replay::read_committed_reconciliation_cursor(
            &state.repositories(),
            request,
            plan.evidence_policy_digest(),
        )
        .await
        .map_err(|()| HostError::new(HostErrorKind::TaskFailure))?;
        let replay =
            RhiReconciliationSourceReplayPlan::from_request(&plan, request, configuration, prior)
                .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
        replays.push(
            fetch_reconciliation_source(
                cancellation,
                transport,
                time_entropy,
                configuration,
                request,
                replay,
            )
            .await?,
        );
    }
    let committed = state
        .repositories()
        .reconciliation_attempts()
        .commit_source_replays(lease, plan, replays)
        .await
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let observed_at = time_entropy
        .now_utc()
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let manifest = committed
        .into_evidence_manifest(observed_at, RhiReconciliationScopePrerequisites::Satisfied)
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let projection = reduce_rhi_reconciliation_manifest(manifest)
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let claim = *projection
        .root_mutation_id()
        .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?;
    let evaluation = evaluate_rhi_reconciliation_claim(projection, claim);
    let now = reconciliation_now_with(time_entropy)?;
    let fence = state
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, now)
        .await
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    let supersession =
        current_verified_supersession(state, fence.evaluation().projection().trade_id()).await?;
    let attestation = build_rhi_signed_evidence_attestation(
        fence,
        identity,
        observed_at,
        time_entropy.entropy(),
        supersession,
    )
    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    state
        .repositories()
        .reconciliation_attempts()
        .commit_finalization(&attestation, publication, now)
        .await
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    Ok(())
}

async fn current_verified_supersession(
    state: &RhiStateHost,
    trade_id: &TradeId,
) -> Result<Option<RhiEvidenceAttestationSupersession>, HostError> {
    let trade_id = *trade_id;
    state
        .sqlite_host()
        .transaction(move |transaction| {
            Box::pin(async move {
                let rows = sqlx::query(
                    r#"SELECT
                        CASE WHEN typeof(report.statement_sha256) = 'blob'
                                  AND length(report.statement_sha256) = 32
                             THEN report.statement_sha256 ELSE NULL END AS statement_sha256,
                        CASE WHEN typeof(event.event_id) = 'blob' AND length(event.event_id) = 32
                             THEN event.event_id ELSE NULL END AS event_id,
                        CASE WHEN typeof(report.canonical_report) = 'blob'
                                  AND length(report.canonical_report) BETWEEN 1 AND 16384
                             THEN report.canonical_report ELSE NULL END AS canonical_report,
                        CASE WHEN typeof(event.canonical_event_json) = 'blob'
                                  AND length(event.canonical_event_json) BETWEEN 1 AND 32768
                             THEN event.canonical_event_json ELSE NULL END AS canonical_event_json
                    FROM attestation_reports AS report
                    JOIN signed_attestation_events AS event
                        ON event.statement_sha256 = report.statement_sha256
                    WHERE report.trade_id = ? AND NOT EXISTS (
                        SELECT 1 FROM attestation_reports AS successor
                        WHERE successor.supersedes_statement_sha256 = report.statement_sha256
                    )
                    ORDER BY report.observed_at_unix_s DESC, report.statement_sha256 DESC
                    LIMIT 2"#,
                )
                .bind(trade_id.as_bytes().as_slice())
                .fetch_all(&mut *transaction)
                .await
                .map_err(|_| ())?;
                if rows.is_empty() {
                    return Ok(None);
                }
                if rows.len() != 1 {
                    return Err(());
                }
                let row = &rows[0];
                let statement = bounded_blob::<32>(row, "statement_sha256")?;
                let event_id = bounded_blob::<32>(row, "event_id")?;
                let canonical_report = row
                    .try_get::<Option<Vec<u8>>, _>("canonical_report")
                    .map_err(|_| ())?
                    .ok_or(())?;
                let canonical_event = row
                    .try_get::<Option<Vec<u8>>, _>("canonical_event_json")
                    .map_err(|_| ())?
                    .ok_or(())?;
                RhiEvidenceAttestationSupersession::from_persisted(
                    &trade_id,
                    statement,
                    event_id,
                    &canonical_report,
                    &canonical_event,
                )
                .map(Some)
                .map_err(|_| ())
            })
        })
        .await
        .map_err(|_| HostError::new(HostErrorKind::TaskFailure))
}

fn bounded_blob<const N: usize>(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<[u8; N], ()> {
    row.try_get::<Option<Vec<u8>>, _>(column)
        .map_err(|_| ())?
        .ok_or(())?
        .try_into()
        .map_err(|_| ())
}

async fn fetch_reconciliation_source(
    cancellation: &radroots_service_host::CancellationToken,
    transport: &crate::RhiTransportAdapters,
    time_entropy: &RhiTimeEntropyAdapters,
    configuration: &RhiConfigDocumentV1,
    source_request: &RhiReconciliationSourceRequest,
    replay: RhiReconciliationSourceReplayPlan,
) -> Result<RhiReconciliationSourceReplay, HostError> {
    let source = configured_sources(configuration)?
        .into_iter()
        .find(|source| source.source_id.as_ref() == source_request.source_id())
        .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))?;
    let target_fingerprint = source.target.fingerprint().clone();
    let targets = TargetSet::new(vec![source.target])
        .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
    let selector = FetchSelector::all()
        .with_kinds(TRADE_EVENT_KINDS.to_vec())
        .and_then(|selector| selector.with_exact_tag_value('d', source_request.trade_id().to_hex()))
        .and_then(|selector| selector.with_since_unix_seconds(replay.since_unix_seconds()))
        .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
    let started_at = reconciliation_now_with(time_entropy)?;
    let request_id = format!(
        "rhi-reconcile-{}",
        lower_hex(source_request.id().as_bytes())
    );
    let maximum_events = usize::try_from(source_request.maximum_events())
        .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
    let mut adapter_cursor = None::<FetchCursor>;
    let mut seen_cursors = BTreeSet::new();
    let mut events = Vec::<RhiAdmittedTradeMutationEvent>::new();
    let mut original_bytes = 0_u64;
    let mut completion = 'pages: loop {
        if cancellation.is_cancelled() {
            break RhiTradeSourceCompletion::IncompleteTimeout;
        }
        let remaining = maximum_events.saturating_sub(events.len());
        let limit = usize::min(
            usize::from(FETCH_PAGE_MAX_EVENTS),
            remaining.saturating_add(1),
        );
        let bounds = FetchBounds::new(
            u16::try_from(limit).map_err(|_| HostError::new(HostErrorKind::TaskFailure))?,
            source_request.deadline().get(),
        )
        .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
        let mut request = FetchRequest::new(request_id.clone(), targets.clone(), bounds)
            .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?
            .with_selector(selector.clone());
        if let Some(cursor) = adapter_cursor.take() {
            request = request.with_cursor(cursor);
        }
        let fetched = tokio::select! {
            () = cancellation.cancelled() => {
                break 'pages RhiTradeSourceCompletion::IncompleteTimeout;
            }
            fetched = transport.evidence_source().fetch(request.clone()) => fetched,
        };
        let page = match fetched {
            Ok(page) => page,
            Err(radroots_transport::Error::UnsupportedOperation) => {
                events.clear();
                break RhiTradeSourceCompletion::Unsupported;
            }
            Err(_) => break RhiTradeSourceCompletion::IncompleteUnavailable,
        };
        if page.validate_for_request(&request).is_err() {
            break RhiTradeSourceCompletion::IncompleteUnknown;
        }
        let Some(outcome) = page
            .target_outcomes()
            .iter()
            .find(|outcome| outcome.target() == &target_fingerprint)
            .filter(|_| page.target_outcomes().len() == 1)
        else {
            break RhiTradeSourceCompletion::IncompleteUnknown;
        };
        match outcome.state() {
            FetchTargetState::Complete | FetchTargetState::Partial => {}
            FetchTargetState::Unavailable | FetchTargetState::FailedRetryable => {
                break RhiTradeSourceCompletion::IncompleteUnavailable;
            }
            FetchTargetState::Cancelled => {
                break RhiTradeSourceCompletion::IncompleteTimeout;
            }
            FetchTargetState::FailedTerminal => {
                break RhiTradeSourceCompletion::IncompleteUnknown;
            }
        }
        for observed in page.events() {
            let bytes = u64::try_from(observed.event().raw_json().len())
                .map_err(|_| HostError::new(HostErrorKind::TaskFailure))?;
            original_bytes = original_bytes.saturating_add(bytes);
            if events.len() >= maximum_events || original_bytes > source_request.maximum_bytes() {
                break 'pages RhiTradeSourceCompletion::IncompleteResourceLimit;
            }
            let observed_at = RhiTradeMutationObservedAtUnixSeconds::new(
                observed.provenance().observed_at_unix_ms() / 1_000,
            )
            .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
            if let Ok(admitted) = admit_rhi_trade_mutation_event(
                RhiTradeMutationAdmissionLimits::from_config(configuration)
                    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?,
                observed.event().raw_json().as_bytes(),
                observed_at,
                RhiTradeMutationAuthoredTimePolicy::new(0)
                    .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?,
            ) && admitted.mutation().trade_id == source_request.trade_id()
            {
                events.push(admitted);
            }
        }
        if outcome.state() == FetchTargetState::Partial {
            break RhiTradeSourceCompletion::IncompleteUnknown;
        }
        match page.next_page() {
            NextPage::Complete => break RhiTradeSourceCompletion::Complete,
            NextPage::Cancelled { .. } => break RhiTradeSourceCompletion::IncompleteTimeout,
            NextPage::Cursor(cursor) => {
                if page.events().is_empty() || !seen_cursors.insert(cursor.as_str().to_owned()) {
                    break RhiTradeSourceCompletion::IncompleteUnknown;
                }
                adapter_cursor = Some(cursor.clone());
            }
        }
    };
    let mut finished_at = reconciliation_now_with(time_entropy)?;
    if finished_at >= source_request.deadline() {
        completion = RhiTradeSourceCompletion::IncompleteTimeout;
        finished_at = source_request.deadline();
    }
    replay
        .finish(source_request, completion, started_at, finished_at, events)
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))
}

fn spawn_publication_worker(
    supervisor: &mut radroots_service_host::TaskSupervisor,
    state: Arc<RhiStateHost>,
    configuration: Arc<RhiConfigDocumentV1>,
    authority: Arc<RhiPublicationAuthority>,
    sink: Arc<RhiNostrExactSink>,
    time_entropy: RhiTimeEntropyAdapters,
) -> Result<(), RhiDaemonError> {
    supervisor
        .spawn(
            task_metadata(
                TASK_PUBLICATION_WORKER,
                TaskClassification::Critical,
                ShutdownPhase::PersistRecoverableWork,
            )?,
            move |cancellation| async move {
                let owner =
                    RhiPublicationLeaseOwner::from_bytes(nonzero_entropy_16(&time_entropy)?)
                        .map_err(|error| {
                            HostError::with_source(HostErrorKind::TaskFailure, error)
                        })?;
                let idle = worker_idle(&configuration)?;
                loop {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    let result = state
                        .repositories()
                        .publication_outbox()
                        .execute_next_publication(owner, &time_entropy, sink.as_ref(), &authority)
                        .await
                        .map_err(|error| {
                            HostError::with_source(HostErrorKind::TaskFailure, error)
                        })?;
                    if result.is_none() {
                        tokio::select! {
                            () = cancellation.cancelled() => return Ok(()),
                            () = tokio::time::sleep(idle) => {}
                        }
                    }
                }
            },
        )
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
}

fn spawn_presence_worker(
    supervisor: &mut radroots_service_host::TaskSupervisor,
    state: Arc<RhiStateHost>,
    configuration: Arc<RhiConfigDocumentV1>,
    sink: Arc<RhiNostrExactSink>,
    time_entropy: RhiTimeEntropyAdapters,
) -> Result<(), RhiDaemonError> {
    supervisor
        .spawn(
            task_metadata(
                TASK_PRESENCE_WORKER,
                TaskClassification::Critical,
                ShutdownPhase::PersistRecoverableWork,
            )?,
            move |cancellation| async move {
                let owner = RhiPresenceLeaseOwner::from_bytes(nonzero_entropy_16(&time_entropy)?)
                    .map_err(|error| {
                    HostError::with_source(HostErrorKind::TaskFailure, error)
                })?;
                let idle = worker_idle(&configuration)?;
                loop {
                    if cancellation.is_cancelled() {
                        return Ok(());
                    }
                    let result = state
                        .repositories()
                        .presence_outbox()
                        .execute_next_presence(owner, &time_entropy, sink.as_ref())
                        .await
                        .map_err(|error| {
                            HostError::with_source(HostErrorKind::TaskFailure, error)
                        })?;
                    if result.is_none() {
                        tokio::select! {
                            () = cancellation.cancelled() => return Ok(()),
                            () = tokio::time::sleep(idle) => {}
                        }
                    }
                }
            },
        )
        .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
}

fn task_metadata(
    name: &'static str,
    classification: TaskClassification,
    phase: ShutdownPhase,
) -> Result<TaskMetadata, RhiDaemonError> {
    TaskMetadata::new(
        TaskName::new(name).map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))?,
        classification,
        Some(phase),
    )
    .map_err(|_| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
}

fn runtime_build_info() -> Result<RhiStatusBuildInfoV1, HostError> {
    let service_revision = option_env!("RADROOTS_SERVICE_REVISION");
    let lib_revision = option_env!("RADROOTS_LIB_REVISION");
    let rust_version = option_env!("RADROOTS_RUST_VERSION");
    let target = option_env!("RADROOTS_BUILD_TARGET");
    let mode = if service_revision.is_some()
        && lib_revision.is_some()
        && rust_version.is_some()
        && target.is_some()
    {
        RhiStatusBuildMode::Release
    } else {
        RhiStatusBuildMode::Development
    };
    RhiStatusBuildInfoV1::new(
        mode,
        Some(env!("CARGO_PKG_VERSION")),
        service_revision,
        lib_revision,
        rust_version,
        target,
        Some("service-host"),
    )
    .map_err(|error| HostError::with_source(HostErrorKind::Lifecycle, error))
}

fn operations_enabled(configuration: &RhiConfigDocumentV1) -> Result<bool, RhiDaemonError> {
    configuration
        .normalized()
        .pointer("/operations/enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
}

fn maximum_source_deadline(configuration: &RhiConfigDocumentV1) -> Result<u64, HostError> {
    configuration
        .normalized()
        .pointer("/evidence/sources")
        .and_then(Value::as_array)
        .and_then(|sources| {
            sources
                .iter()
                .filter_map(|source| source.pointer("/deadline_ms").and_then(Value::as_u64))
                .max()
        })
        .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))
}

fn configuration_integer(
    configuration: &RhiConfigDocumentV1,
    pointer: &str,
) -> Result<u64, RhiDaemonError> {
    configuration
        .normalized()
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| RhiDaemonError::new(RhiDaemonErrorKind::Runtime))
}

fn worker_idle(configuration: &RhiConfigDocumentV1) -> Result<Duration, HostError> {
    configuration
        .normalized()
        .pointer("/reconciliation/initial_backoff_ms")
        .and_then(Value::as_u64)
        .map(Duration::from_millis)
        .ok_or_else(|| HostError::new(HostErrorKind::TaskFailure))
}

fn reconciliation_now_with(
    time_entropy: &RhiTimeEntropyAdapters,
) -> Result<RhiReconciliationUnixMilliseconds, HostError> {
    let milliseconds = time_entropy
        .now_utc_milliseconds()
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
    RhiReconciliationUnixMilliseconds::new(milliseconds)
        .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))
}

fn subscription_attempt_id(cursor: &str) -> String {
    let digest = Sha256::digest(cursor.as_bytes());
    format!("subscription-{}", lower_hex(&digest))
}

fn nonzero_entropy_16(time_entropy: &RhiTimeEntropyAdapters) -> Result<[u8; 16], HostError> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 16];
        time_entropy
            .entropy()
            .fill_bytes(&mut bytes)
            .map_err(|error| HostError::with_source(HostErrorKind::TaskFailure, error))?;
        if bytes.iter().any(|byte| *byte != 0) {
            return Ok(bytes);
        }
    }
    Err(HostError::new(HostErrorKind::TaskFailure))
}

fn lower_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_status_context() -> RuntimeStatusContext {
        let time_entropy = RhiTimeEntropyAdapters::system();
        RuntimeStatusContext {
            configuration_digest: "0".repeat(64),
            configuration_source: RhiStatusConfigurationSource::DerivedRepoLocal,
            schema_version: crate::RHI_STATE_SCHEMA_VERSION,
            generation: 1,
            source_count: 1,
            started_at: time_entropy.now_monotonic(),
            time_entropy,
            reconciliation: RhiReconciliationStatusV1::default(),
            publication: RhiPublicationStatusV1::default(),
            presence: RhiPresenceStatusV1::default(),
        }
    }

    #[test]
    fn runtime_status_keeps_optional_operations_degradation_ready_and_reasoned() {
        let context = empty_status_context();
        let observation = context
            .observation(RhiServicePhase::Degraded, true, false)
            .expect("degraded observation");
        let (_, reader) = crate::rhi_status_cache(
            radroots_runtime_paths::InstanceId::new("primary").expect("instance"),
            observation,
        )
        .expect("status cache");
        let snapshot = reader.snapshot();
        assert!(snapshot.is_ready());
        let json = std::str::from_utf8(snapshot.detailed_status_json()).expect("status UTF-8");
        assert!(json.contains("\"operations_listener_failed\""));
        assert!(!json.contains("\"source_unavailable\""));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn runtime_status_refresh_reads_the_exact_empty_durable_work_summary() {
        use std::{fs, os::unix::fs::PermissionsExt as _};

        use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
        use radroots_storage::event::SourceGeneration;

        let root = tempfile::tempdir().expect("test root");
        let root_text = root.path().to_str().expect("UTF-8 root");
        let invocation = crate::parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "repo-local",
            "--instance",
            "primary",
            "--repo-local-root",
            root_text,
            "run",
        ])
        .expect("invocation");
        let runtime = crate::resolve_rhi_runtime_context(
            &crate::RadrootsPathResolver::new(
                crate::RadrootsPlatform::Linux,
                crate::RadrootsHostEnvironment::default(),
            ),
            &invocation,
        )
        .expect("runtime");
        fs::create_dir_all(runtime.context().paths().state()).expect("state root");
        fs::set_permissions(
            runtime.context().paths().state(),
            fs::Permissions::from_mode(0o700),
        )
        .expect("state mode");
        let configuration = crate::parse_rhi_config_v1(
            include_bytes!("../contracts/services_hardening/config.v1.example.toml"),
            crate::RhiConfigProfile::RepoLocal,
        )
        .expect("configuration");
        let metadata = crate::RhiStateMetadata::new(
            &runtime,
            &configuration,
            SourceGeneration::new([0x41; 32]).expect("generation"),
            1_725_000_000_000,
        )
        .expect("metadata");
        let applied_at = MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("time");
        let build = MigrationBuildIdentity::new(
            env!("CARGO_PKG_VERSION"),
            "1111111111111111111111111111111111111111",
            "21b11e7a5120ea949f7ad0838c746873fc73aac2",
            "rustc-test",
            "test-target",
            "service-host",
            1,
            crate::RHI_STATE_SCHEMA_VERSION,
            1,
            1,
            1,
        )
        .expect("build");
        crate::initialize_rhi_state(&runtime, &metadata, applied_at, &build)
            .await
            .expect("initialize");
        let state = crate::open_rhi_state_read_write(&runtime, &metadata, applied_at, &build)
            .await
            .expect("open");
        let mut status = empty_status_context();
        status.refresh_state(&state).await.expect("refresh");
        assert_eq!(status.reconciliation, RhiReconciliationStatusV1::default());
        assert_eq!(status.publication, RhiPublicationStatusV1::default());
        assert_eq!(status.presence, RhiPresenceStatusV1::default());
        state.close().await.expect("close");
    }
}
