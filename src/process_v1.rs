//! Binary-owned execution for one already-admitted command invocation.

use std::env;
use std::io::{Read, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use radroots_service_host::{
    AdminClient, AdminClientErrorKind, AdminClientTarget, AdminOperationId,
};
use radroots_service_host::{
    ContractVersions, EntropySource, SystemEntropy, SystemWallClock, WallClock,
};
use radroots_service_sqlite::{
    BACKUP_MANIFEST_CANONICAL_MAX_BYTES, BackupManifestSha256, IntegrityCheckedAtUnixMs,
    MigrationAppliedAtUnixSeconds, MigrationBuildIdentity,
};
use radroots_storage::event::SourceGeneration;
use serde_json::{Value, json};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::admin_v1::{admin_transport_limits, admit_admin_response_value};
use crate::cli_bootstrap::read_identity_provisioning_document;
use crate::{
    RHI_ADMIN_CONTRACT_VERSION, RHI_CONFIG_DOCUMENT_MAX_UTF8_BYTES, RHI_CONFIG_SCHEMA_VERSION,
    RHI_PROVIDER_CONTRACT_VERSION, RHI_STATE_SCHEMA_VERSION, RHI_STATUS_CONTRACT_VERSION,
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiCliInvocationV1,
    RhiCliOutputModeV1, RhiCliPrimaryAuthorityV1, RhiCommandV1, RhiConfigCommandV1,
    RhiIdentityCommandV1, RhiProcessResult, RhiRuntimeContext, RhiStateCommandV1, RhiStateMetadata,
    apply_rhi_configuration, finalize_rhi_state_restore, initialize_rhi_config_document,
    initialize_rhi_state, load_rhi_config_candidate, load_rhi_config_document,
    open_rhi_state_read_write_from_config, plan_rhi_cli_v1, provision_rhi_encrypted_identity,
    resolve_rhi_runtime_context, resolve_rhi_wrapping_credential, stage_rhi_state_restore,
    verify_rhi_state_backup,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::{
    RhiMetricsCommandV1, RhiPresenceCommandV1, RhiPublicationCommandV1, RhiReconciliationCommandV1,
    RhiSourcesCommandV1, RhiTradeCommandV1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessFailure(RhiProcessResult);

type ProcessResult<T> = Result<T, ProcessFailure>;

/// Executes one admitted RHI invocation without reparsing process arguments.
#[must_use]
pub fn execute_rhi_cli_v1(invocation: RhiCliInvocationV1) -> RhiProcessResult {
    execute(invocation).unwrap_or_else(|failure| failure.0)
}

/// Executes one admitted invocation with a binary-owned process-signal source.
#[must_use]
pub fn execute_rhi_cli_v1_with_signal_source<F, S>(
    invocation: RhiCliInvocationV1,
    make_signal_source: F,
) -> RhiProcessResult
where
    F: FnOnce() -> Option<S>,
    S: crate::RhiProcessSignalSource + 'static,
{
    if !matches!(invocation.command(), RhiCommandV1::Run) {
        return execute_rhi_cli_v1(invocation);
    }
    execute_run(invocation, make_signal_source).unwrap_or_else(|failure| failure.0)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn execute_run<F, S>(
    invocation: RhiCliInvocationV1,
    make_signal_source: F,
) -> ProcessResult<RhiProcessResult>
where
    F: FnOnce() -> Option<S>,
    S: crate::RhiProcessSignalSource + 'static,
{
    let runtime = resolve_runtime(&invocation)?;
    let configuration = load_rhi_config_document(&runtime).map_err(|_| input_failure())?;
    let applied_at = migration_time()?;
    let build = migration_build_identity()?;
    let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
    tokio.block_on(async move {
        let signals = make_signal_source().ok_or(ProcessFailure(
            RhiProcessResult::ServiceOrDependencyUnavailable,
        ))?;
        Ok(crate::runtime_graph::run_rhi_daemon(
            runtime,
            configuration,
            applied_at,
            &build,
            signals,
        )
        .await)
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn execute_run<F, S>(
    _invocation: RhiCliInvocationV1,
    _make_signal_source: F,
) -> ProcessResult<RhiProcessResult>
where
    F: FnOnce() -> Option<S>,
    S: crate::RhiProcessSignalSource + 'static,
{
    Err(ProcessFailure(
        RhiProcessResult::ServiceOrDependencyUnavailable,
    ))
}

fn execute(invocation: RhiCliInvocationV1) -> ProcessResult<RhiProcessResult> {
    let plan = plan_rhi_cli_v1(&invocation);
    if plan.primary_authority() == RhiCliPrimaryAuthorityV1::Daemon {
        return Err(ProcessFailure(
            RhiProcessResult::ServiceOrDependencyUnavailable,
        ));
    }
    let runtime = resolve_runtime(&invocation)?;
    let output = invocation.output_mode();
    match (plan.primary_authority(), invocation.command()) {
        (RhiCliPrimaryAuthorityV1::Offline, RhiCommandV1::Config(command)) => {
            execute_config(output, &runtime, command)
        }
        (RhiCliPrimaryAuthorityV1::Offline, RhiCommandV1::State(command)) => {
            execute_state(output, &runtime, command)
        }
        (RhiCliPrimaryAuthorityV1::Offline, RhiCommandV1::Identity(command)) => {
            execute_identity(output, &runtime, *command)
        }
        (RhiCliPrimaryAuthorityV1::Offline, RhiCommandV1::Doctor) => {
            execute_doctor(output, &runtime)
        }
        (RhiCliPrimaryAuthorityV1::LiveUnixAdmin, command) => {
            execute_live(output, &runtime, command)
        }
        _ => Err(ProcessFailure(RhiProcessResult::UnexpectedInternal)),
    }
}

fn execute_config(
    output: RhiCliOutputModeV1,
    runtime: &RhiRuntimeContext,
    command: &RhiConfigCommandV1,
) -> ProcessResult<RhiProcessResult> {
    match command {
        RhiConfigCommandV1::Init => {
            let bytes = read_bounded_stdin(RHI_CONFIG_DOCUMENT_MAX_UTF8_BYTES)?;
            initialize_rhi_config_document(runtime, &bytes).map_err(|_| input_failure())?;
            emit_simple_success(output, "config_initialized")
        }
        RhiConfigCommandV1::Validate => {
            load_rhi_config_document(runtime).map_err(|_| input_failure())?;
            emit_simple_success(output, "config_valid")
        }
        RhiConfigCommandV1::Schema => emit_bytes(include_bytes!(
            "../contracts/services_hardening/config.v1.schema.json"
        )),
        RhiConfigCommandV1::Apply(arguments) => {
            let current = load_rhi_config_document(runtime).map_err(|_| input_failure())?;
            let candidate = load_rhi_config_candidate(runtime, arguments.candidate_config())
                .map_err(|_| input_failure())?;
            let tokio = build_tokio_runtime(current.runtime_thread_limits())?;
            let outcome = tokio
                .block_on(apply_rhi_configuration(
                    runtime,
                    &current,
                    &candidate,
                    migration_time()?,
                    &migration_build_identity()?,
                ))
                .map_err(|_| conflict_failure())?;
            emit_value(
                output,
                "config_applied",
                json!({"generation": outcome.generation()}),
            )
        }
        RhiConfigCommandV1::Show => Err(ProcessFailure(RhiProcessResult::UnexpectedInternal)),
    }
}

fn execute_state(
    output: RhiCliOutputModeV1,
    runtime: &RhiRuntimeContext,
    command: &RhiStateCommandV1,
) -> ProcessResult<RhiProcessResult> {
    let configuration = load_rhi_config_document(runtime).map_err(|_| input_failure())?;
    let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
    match command {
        RhiStateCommandV1::Init => {
            let metadata = RhiStateMetadata::new(
                runtime,
                &configuration,
                source_generation()?,
                wall_time_millis()?,
            )
            .map_err(|_| state_failure())?;
            tokio
                .block_on(initialize_rhi_state(
                    runtime,
                    &metadata,
                    migration_time()?,
                    &migration_build_identity()?,
                ))
                .map_err(|_| state_failure())?;
            emit_simple_success(output, "state_initialized")
        }
        RhiStateCommandV1::Restore(arguments) => {
            let state = tokio
                .block_on(open_rhi_state_read_write_from_config(
                    runtime,
                    &configuration,
                    migration_time()?,
                    &migration_build_identity()?,
                ))
                .map_err(|_| state_failure())?;
            let metadata = state.metadata().clone();
            tokio.block_on(state.close()).map_err(|_| state_failure())?;
            let manifest =
                read_bounded_file(arguments.manifest(), BACKUP_MANIFEST_CANONICAL_MAX_BYTES)?;
            let digest = decode_hex_32(arguments.manifest_sha256())?;
            let verified = verify_rhi_state_backup(
                &manifest,
                BackupManifestSha256::from_bytes(digest),
                arguments.bundle(),
                &metadata,
                NonZeroU64::new(arguments.maximum_state_bytes()).ok_or_else(input_failure)?,
            )
            .map_err(|_| state_failure())?;
            let staged = tokio
                .block_on(stage_rhi_state_restore(runtime, &metadata, verified))
                .map_err(|_| state_failure())?;
            tokio
                .block_on(finalize_rhi_state_restore(staged))
                .map_err(|_| state_failure())?;
            emit_simple_success(output, "state_restore_finalized")
        }
        RhiStateCommandV1::Verify | RhiStateCommandV1::Migrate => {
            let state = tokio
                .block_on(open_rhi_state_read_write_from_config(
                    runtime,
                    &configuration,
                    migration_time()?,
                    &migration_build_identity()?,
                ))
                .map_err(|_| state_failure())?;
            if matches!(command, RhiStateCommandV1::Verify) {
                let checked_at =
                    IntegrityCheckedAtUnixMs::new(wall_time_millis()?).ok_or_else(state_failure)?;
                tokio
                    .block_on(state.inspect_integrity(checked_at))
                    .map_err(|_| state_failure())?;
            }
            tokio.block_on(state.close()).map_err(|_| state_failure())?;
            emit_simple_success(
                output,
                if matches!(command, RhiStateCommandV1::Verify) {
                    "state_verified"
                } else {
                    "state_migrated"
                },
            )
        }
        RhiStateCommandV1::Status | RhiStateCommandV1::Backup(_) => {
            Err(ProcessFailure(RhiProcessResult::UnexpectedInternal))
        }
    }
}

fn execute_identity(
    output: RhiCliOutputModeV1,
    runtime: &RhiRuntimeContext,
    command: RhiIdentityCommandV1,
) -> ProcessResult<RhiProcessResult> {
    if command != RhiIdentityCommandV1::Init {
        return Err(ProcessFailure(RhiProcessResult::UnexpectedInternal));
    }
    let configuration = load_rhi_config_document(runtime).map_err(|_| input_failure())?;
    let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
    let state = tokio
        .block_on(open_rhi_state_read_write_from_config(
            runtime,
            &configuration,
            migration_time()?,
            &migration_build_identity()?,
        ))
        .map_err(|_| state_failure())?;
    let metadata = state.metadata().clone();
    tokio.block_on(state.close()).map_err(|_| state_failure())?;
    let binding = crate::RhiIdentityEnvelopeBinding::from_configuration(&configuration, &metadata)
        .map_err(|_| state_failure())?;
    let credential =
        resolve_rhi_wrapping_credential(runtime, &binding).map_err(|_| state_failure())?;
    let material = read_identity_provisioning_document(std::io::stdin().lock())
        .map_err(|_| input_failure())?;
    let identity = provision_rhi_encrypted_identity(&binding, &credential, material)
        .map_err(|_| state_failure())?;
    emit_value(
        output,
        "identity_initialized",
        json!({"generation": 0, "public_key": identity.public_identity().as_hex(), "role": "service"}),
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn execute_doctor(
    _output: RhiCliOutputModeV1,
    runtime: &RhiRuntimeContext,
) -> ProcessResult<RhiProcessResult> {
    let configuration = load_rhi_config_document(runtime).map_err(|_| input_failure())?;
    let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
    let report = tokio
        .block_on(crate::run_rhi_doctor(
            runtime,
            &crate::system_doctor::RhiSystemDoctorProbe::new(runtime, &configuration),
        ))
        .map_err(|_| ProcessFailure(RhiProcessResult::UnexpectedInternal))?;
    emit_bytes(report.canonical_json())?;
    if report.exit_code() == 0 {
        Ok(RhiProcessResult::Success)
    } else {
        Err(ProcessFailure(RhiProcessResult::DoctorRequiredCheckFailed))
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn execute_doctor(
    _output: RhiCliOutputModeV1,
    _runtime: &RhiRuntimeContext,
) -> ProcessResult<RhiProcessResult> {
    Err(ProcessFailure(
        RhiProcessResult::ServiceOrDependencyUnavailable,
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn execute_live(
    _output: RhiCliOutputModeV1,
    runtime: &RhiRuntimeContext,
    command: &RhiCommandV1,
) -> ProcessResult<RhiProcessResult> {
    let configuration = load_rhi_config_document(runtime).map_err(|_| input_failure())?;
    let tokio = build_tokio_runtime(configuration.runtime_thread_limits())?;
    let bytes = tokio.block_on(live_command(runtime, &configuration, command))?;
    emit_bytes(&bytes)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn execute_live(
    _output: RhiCliOutputModeV1,
    _runtime: &RhiRuntimeContext,
    _command: &RhiCommandV1,
) -> ProcessResult<RhiProcessResult> {
    Err(ProcessFailure(
        RhiProcessResult::ServiceOrDependencyUnavailable,
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn live_command(
    runtime: &RhiRuntimeContext,
    configuration: &crate::RhiConfigDocumentV1,
    command: &RhiCommandV1,
) -> ProcessResult<Box<[u8]>> {
    use crate::RhiAdminRoute as Route;
    let (route, target, mutation) = match command {
        RhiCommandV1::Config(RhiConfigCommandV1::Show) => (
            Route::EffectiveConfig,
            Route::EffectiveConfig.path().to_owned(),
            None,
        ),
        RhiCommandV1::State(RhiStateCommandV1::Status) => (
            Route::StateStatus,
            Route::StateStatus.path().to_owned(),
            None,
        ),
        RhiCommandV1::State(RhiStateCommandV1::Backup(arguments)) => (
            Route::StateBackup,
            Route::StateBackup.path().to_owned(),
            Some((
                arguments.operation_id(),
                json!({
                    "confirmation": "confirm",
                    "expected_generation": arguments.expected_generation(),
                    "target_path": arguments.target().to_str().ok_or_else(input_failure)?,
                }),
            )),
        ),
        RhiCommandV1::Identity(RhiIdentityCommandV1::Status) => (
            Route::IdentityStatus,
            format!("{}?role=service", Route::IdentityStatus.path()),
            None,
        ),
        RhiCommandV1::Identity(RhiIdentityCommandV1::ExportPublic) => (
            Route::IdentityPublic,
            format!("{}?role=service", Route::IdentityPublic.path()),
            None,
        ),
        RhiCommandV1::Status => (Route::Status, Route::Status.path().to_owned(), None),
        RhiCommandV1::Metrics(RhiMetricsCommandV1::Snapshot) => (
            Route::MetricsSnapshot,
            Route::MetricsSnapshot.path().to_owned(),
            None,
        ),
        RhiCommandV1::Reconciliation(RhiReconciliationCommandV1::Status) => (
            Route::ReconciliationStatus,
            Route::ReconciliationStatus.path().to_owned(),
            None,
        ),
        RhiCommandV1::Reconciliation(RhiReconciliationCommandV1::Jobs(page)) => (
            Route::ReconciliationJobs,
            paged_target(Route::ReconciliationJobs.path(), page),
            None,
        ),
        RhiCommandV1::Reconciliation(RhiReconciliationCommandV1::Refresh(arguments)) => (
            Route::ReconciliationRefresh,
            Route::ReconciliationRefresh.path().to_owned(),
            Some((
                arguments.operation_id(),
                json!({
                    "expected_dirty_generation": arguments.expected_dirty_generation(),
                    "trade_id": arguments.trade_id(),
                }),
            )),
        ),
        RhiCommandV1::Sources(RhiSourcesCommandV1::List(page)) => (
            Route::Sources,
            paged_target(Route::Sources.path(), page),
            None,
        ),
        RhiCommandV1::Trade(RhiTradeCommandV1::Projection(arguments)) => (
            Route::TradeProjection,
            Route::TradeProjection
                .path()
                .replace("{trade_id}", arguments.trade_id()),
            None,
        ),
        RhiCommandV1::Trade(RhiTradeCommandV1::ReportCurrent(arguments)) => (
            Route::TradeReportCurrent,
            Route::TradeReportCurrent
                .path()
                .replace("{trade_id}", arguments.trade_id()),
            None,
        ),
        RhiCommandV1::Trade(RhiTradeCommandV1::Reports(arguments)) => (
            Route::TradeReports,
            paged_target(
                &Route::TradeReports
                    .path()
                    .replace("{trade_id}", arguments.trade_id()),
                arguments.page(),
            ),
            None,
        ),
        RhiCommandV1::Publication(RhiPublicationCommandV1::Backlog(page)) => (
            Route::PublicationBacklog,
            paged_target(Route::PublicationBacklog.path(), page),
            None,
        ),
        RhiCommandV1::Publication(RhiPublicationCommandV1::Targets(page)) => (
            Route::PublicationTargets,
            paged_target(Route::PublicationTargets.path(), page),
            None,
        ),
        RhiCommandV1::Publication(RhiPublicationCommandV1::Retry(arguments)) => (
            Route::PublicationRetry,
            Route::PublicationRetry.path().to_owned(),
            Some((
                arguments.operation_id(),
                json!({
                    "expected_generation": arguments.expected_generation(),
                    "workflow_id": arguments.workflow_id(),
                }),
            )),
        ),
        RhiCommandV1::Presence(RhiPresenceCommandV1::Desired) => (
            Route::PresenceDesired,
            Route::PresenceDesired.path().to_owned(),
            None,
        ),
        RhiCommandV1::Presence(RhiPresenceCommandV1::Render(arguments)) => (
            Route::PresenceRender,
            Route::PresenceRender.path().to_owned(),
            Some((
                arguments.operation_id(),
                json!({"expected_generation": arguments.expected_generation()}),
            )),
        ),
        RhiCommandV1::Presence(RhiPresenceCommandV1::Refresh(arguments)) => (
            Route::PresenceRefresh,
            Route::PresenceRefresh.path().to_owned(),
            Some((
                arguments.operation_id(),
                json!({"expected_generation": arguments.expected_generation()}),
            )),
        ),
        _ => return Err(ProcessFailure(RhiProcessResult::UnexpectedInternal)),
    };
    let client = AdminClient::new(
        runtime.artifacts().admin_socket(),
        admin_transport_limits(configuration).map_err(|_| input_failure())?,
    )
    .map_err(|_| input_failure())?;
    let target = AdminClientTarget::new(target).map_err(|_| input_failure())?;
    let result = if let Some((operation_id, request)) = mutation {
        let operation_id = AdminOperationId::new(operation_id).map_err(|_| input_failure())?;
        client
            .mutate::<_, Value>(&target, operation_id, None, request)
            .await
            .map(|response| response.result().clone())
    } else {
        client
            .get::<Value>(&target)
            .await
            .map(|response| response.result().clone())
    };
    match result {
        Ok(value) => admit_admin_response_value(route, &value)
            .map_err(|_| ProcessFailure(RhiProcessResult::ServiceOrDependencyUnavailable)),
        Err(error) if error.kind() == AdminClientErrorKind::ServerFailure => {
            Err(conflict_failure())
        }
        Err(_) => Err(ProcessFailure(
            RhiProcessResult::ServiceOrDependencyUnavailable,
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn paged_target(path: &str, page: &crate::RhiPageQueryArgsV1) -> String {
    let mut target = format!("{path}?limit={}", page.limit());
    if let Some(cursor) = page.cursor() {
        target.push_str("&cursor=");
        target.push_str(cursor);
    }
    target
}

fn resolve_runtime(invocation: &RhiCliInvocationV1) -> ProcessResult<RhiRuntimeContext> {
    let resolver = RadrootsPathResolver::new(RadrootsPlatform::current(), host_environment());
    resolve_rhi_runtime_context(&resolver, invocation).map_err(|_| input_failure())
}

fn migration_build_identity() -> ProcessResult<MigrationBuildIdentity> {
    let versions = ContractVersions::new(
        RHI_CONFIG_SCHEMA_VERSION,
        RHI_STATE_SCHEMA_VERSION,
        RHI_ADMIN_CONTRACT_VERSION,
        RHI_STATUS_CONTRACT_VERSION,
        RHI_PROVIDER_CONTRACT_VERSION,
    )
    .map_err(|_| ProcessFailure(RhiProcessResult::UnexpectedInternal))?;
    let build = radroots_service_host::compile_time_build_info!(
        feature_profile: "service-host",
        contract_versions: versions,
    )
    .map_err(|_| ProcessFailure(RhiProcessResult::UnexpectedInternal))?;
    MigrationBuildIdentity::new(
        build.service_version(),
        build.service_commit(),
        build.lib_revision(),
        build.rust_version(),
        build.target(),
        build.feature_profile(),
        versions.config(),
        versions.state(),
        versions.admin(),
        versions.status(),
        versions.provider(),
    )
    .map_err(|_| ProcessFailure(RhiProcessResult::UnexpectedInternal))
}

fn source_generation() -> ProcessResult<SourceGeneration> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        SystemEntropy
            .fill_bytes(&mut bytes)
            .map_err(|_| state_failure())?;
        if let Ok(generation) = SourceGeneration::new(bytes) {
            return Ok(generation);
        }
    }
    Err(state_failure())
}

fn wall_time_seconds() -> ProcessResult<u64> {
    SystemWallClock
        .now_utc()
        .map(|time| time.get())
        .map_err(|_| ProcessFailure(RhiProcessResult::UnexpectedInternal))
}

fn wall_time_millis() -> ProcessResult<u64> {
    wall_time_seconds()?
        .checked_mul(1_000)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(ProcessFailure(RhiProcessResult::UnexpectedInternal))
}

fn migration_time() -> ProcessResult<MigrationAppliedAtUnixSeconds> {
    MigrationAppliedAtUnixSeconds::new(wall_time_seconds()?)
        .map_err(|_| ProcessFailure(RhiProcessResult::UnexpectedInternal))
}

fn build_tokio_runtime(
    limits: crate::RhiRuntimeThreadLimitsV1,
) -> ProcessResult<tokio::runtime::Runtime> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(ProcessFailure(RhiProcessResult::UnexpectedInternal));
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(limits.worker_threads())
        .max_blocking_threads(limits.blocking_threads())
        .enable_all()
        .build()
        .map_err(|_| ProcessFailure(RhiProcessResult::UnexpectedInternal))
}

fn host_environment() -> RadrootsHostEnvironment {
    let path = |name| {
        env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    RadrootsHostEnvironment {
        home_dir: path("HOME"),
        xdg_config_home: path("XDG_CONFIG_HOME"),
        xdg_data_home: path("XDG_DATA_HOME"),
        xdg_state_home: path("XDG_STATE_HOME"),
        xdg_cache_home: path("XDG_CACHE_HOME"),
        xdg_runtime_dir: path("XDG_RUNTIME_DIR"),
        appdata_dir: path("APPDATA"),
        localappdata_dir: path("LOCALAPPDATA"),
    }
}

fn read_bounded_stdin(maximum: usize) -> ProcessResult<Vec<u8>> {
    let mut reader = std::io::stdin().lock();
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1_024).saturating_add(1));
    Read::by_ref(&mut reader)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| input_failure())?;
    if bytes.len() > maximum {
        return Err(input_failure());
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_bounded_file(path: &Path, maximum: usize) -> ProcessResult<Vec<u8>> {
    crate::config_loader::read_secure_bounded_file(path, maximum).map_err(|_| state_failure())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_bounded_file(_path: &Path, _maximum: usize) -> ProcessResult<Vec<u8>> {
    Err(state_failure())
}

fn decode_hex_32(value: &str) -> ProcessResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(input_failure());
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

const fn hex_nibble(value: u8) -> ProcessResult<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(input_failure()),
    }
}

fn emit_simple_success(
    output: RhiCliOutputModeV1,
    code: &'static str,
) -> ProcessResult<RhiProcessResult> {
    emit_value(output, code, json!({"ok": true}))
}

fn emit_value(
    output: RhiCliOutputModeV1,
    code: &'static str,
    value: Value,
) -> ProcessResult<RhiProcessResult> {
    let bytes = match output {
        RhiCliOutputModeV1::Json => serde_json::to_vec(&value)
            .map_err(|_| ProcessFailure(RhiProcessResult::UnexpectedInternal))?,
        RhiCliOutputModeV1::Human => code.as_bytes().to_vec(),
    };
    emit_bytes(&bytes)
}

fn emit_bytes(bytes: &[u8]) -> ProcessResult<RhiProcessResult> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| {
            if bytes.ends_with(b"\n") {
                Ok(())
            } else {
                stdout.write_all(b"\n")
            }
        })
        .and_then(|()| stdout.flush())
        .map_err(|_| ProcessFailure(RhiProcessResult::UnexpectedInternal))?;
    Ok(RhiProcessResult::Success)
}

const fn input_failure() -> ProcessFailure {
    ProcessFailure(RhiProcessResult::InputOrConfiguration)
}

const fn state_failure() -> ProcessFailure {
    ProcessFailure(RhiProcessResult::StateOrIdentityUnavailable)
}

const fn conflict_failure() -> ProcessFailure {
    ProcessFailure(RhiProcessResult::OperationRejectedOrConflict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_limits_are_explicit_and_digest_decoding_is_strict() {
        let source = include_str!("process_v1.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(source.contains("worker_threads(limits.worker_threads())"));
        assert!(source.contains("max_blocking_threads(limits.blocking_threads())"));
        assert!(!source.contains("available_parallelism"));
        assert_eq!(
            decode_hex_32(&"ab".repeat(32)).expect("lowercase digest"),
            [0xab; 32]
        );
        assert!(decode_hex_32(&"AB".repeat(32)).is_err());
    }

    #[test]
    fn nested_tokio_runtime_creation_fails_closed_without_panicking() {
        let configuration = crate::parse_rhi_config_v1(
            include_bytes!("../contracts/services_hardening/config.v1.example.toml"),
            crate::RhiConfigProfile::Production,
        )
        .expect("configuration fixture");
        let outer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("outer runtime");
        let result =
            outer.block_on(async { build_tokio_runtime(configuration.runtime_thread_limits()) });
        assert_eq!(
            result.expect_err("nested runtime must be rejected"),
            ProcessFailure(RhiProcessResult::UnexpectedInternal)
        );
    }
}
