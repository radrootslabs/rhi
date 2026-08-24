#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    future::pending,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use rhi::{
    RHI_DOCTOR_CHECK_COUNT, RHI_DOCTOR_CONTRACT_VERSION, RHI_DOCTOR_REPORT_MAX_UTF8_BYTES,
    RHI_DOCTOR_SUMMARY_MAX_UTF8_BYTES, RadrootsHostEnvironment, RadrootsPathResolver,
    RadrootsPlatform, RhiDoctorAggregateStatus, RhiDoctorCheckDefinition, RhiDoctorCheckId,
    RhiDoctorCheckStatus, RhiDoctorFuture, RhiDoctorObservation, RhiDoctorProbe,
    RhiDoctorRemediationCode, RhiProcessResult, parse_rhi_cli_v1_from, resolve_rhi_runtime_context,
    rhi_doctor_check_definitions, run_rhi_doctor,
};
use sha2::{Digest, Sha256};

const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");

struct PendingGuard(Arc<AtomicBool>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct TestProbe {
    outcomes: BTreeMap<RhiDoctorCheckId, RhiDoctorObservation>,
    pending: Option<RhiDoctorCheckId>,
    calls: Arc<Mutex<Vec<RhiDoctorCheckId>>>,
    pending_dropped: Arc<AtomicBool>,
}

impl TestProbe {
    fn all(outcome: RhiDoctorObservation) -> Self {
        Self {
            outcomes: rhi_doctor_check_definitions()
                .iter()
                .map(|definition| (definition.id(), outcome))
                .collect(),
            pending: None,
            calls: Arc::new(Mutex::new(Vec::new())),
            pending_dropped: Arc::new(AtomicBool::new(false)),
        }
    }

    fn with(mut self, id: RhiDoctorCheckId, outcome: RhiDoctorObservation) -> Self {
        self.outcomes.insert(id, outcome);
        self
    }

    fn pending(mut self, id: RhiDoctorCheckId) -> Self {
        self.pending = Some(id);
        self
    }
}

impl RhiDoctorProbe for TestProbe {
    fn probe(&self, definition: RhiDoctorCheckDefinition) -> RhiDoctorFuture<'_> {
        let id = definition.id();
        self.calls.lock().expect("calls lock").push(id);
        if self.pending == Some(id) {
            let dropped = Arc::clone(&self.pending_dropped);
            return Box::pin(async move {
                let _guard = PendingGuard(dropped);
                pending().await
            });
        }
        let outcome = self.outcomes[&id];
        Box::pin(async move { outcome })
    }
}

fn runtime() -> (tempfile::TempDir, rhi::RhiRuntimeContext) {
    let directory = tempfile::tempdir().expect("temporary root");
    let invocation = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        "repo-local",
        "--instance",
        "primary",
        "--repo-local-root",
        directory.path().to_str().expect("UTF-8 path"),
        "doctor",
    ])
    .expect("doctor invocation");
    let context = resolve_rhi_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context");
    (directory, context)
}

#[test]
fn exact_inventory_and_exit_meanings_match_the_operator_contract() {
    let contract: serde_json::Value =
        serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract");
    let doctor = contract["doctor"].as_object().expect("doctor");
    assert_eq!(
        doctor.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "aggregate_statuses",
            "checks",
            "contract_version",
            "detached_probe_work",
            "execution",
            "pass_requires_all_scope",
            "probe_future_cancellation",
            "raw_error_or_path_allowed",
            "report_max_utf8_bytes",
            "required_fail_or_timeout_exit",
            "required_skipped",
            "shared_schema",
            "statuses",
            "summary_max_utf8_bytes",
        ])
    );
    assert_eq!(RHI_DOCTOR_CONTRACT_VERSION, 1);
    assert_eq!(RHI_DOCTOR_CHECK_COUNT, 15);
    assert_eq!(RHI_DOCTOR_SUMMARY_MAX_UTF8_BYTES, 256);
    assert_eq!(RHI_DOCTOR_REPORT_MAX_UTF8_BYTES, 8_192);
    assert_eq!(doctor["execution"], "ordered");
    assert_eq!(doctor["pass_requires_all_scope"], true);
    assert_eq!(
        doctor["probe_future_cancellation"],
        "drop_stops_or_owns_cleanup"
    );
    assert_eq!(doctor["detached_probe_work"], false);
    assert_eq!(doctor["required_skipped"], "forbidden");
    assert_eq!(doctor["raw_error_or_path_allowed"], false);
    assert_eq!(doctor["required_fail_or_timeout_exit"], 6);

    let rows = doctor["checks"].as_array().expect("checks");
    assert_eq!(rows.len(), RHI_DOCTOR_CHECK_COUNT);
    for (definition, row) in rhi_doctor_check_definitions().iter().zip(rows) {
        assert_eq!(row["id"], id_name(definition.id()));
        assert_eq!(row["required"], definition.required());
        assert_eq!(row["deadline_ms"], definition.deadline_ms());
        assert_eq!(
            row["remediation_code"],
            remediation_name(definition.remediation_code())
        );
        assert_eq!(
            row["scope"],
            serde_json::to_value(definition.scope()).expect("scope")
        );
    }

    let process_results = [
        RhiProcessResult::Success,
        RhiProcessResult::UnexpectedInternal,
        RhiProcessResult::InputOrConfiguration,
        RhiProcessResult::ServiceOrDependencyUnavailable,
        RhiProcessResult::StateOrIdentityUnavailable,
        RhiProcessResult::OperationRejectedOrConflict,
        RhiProcessResult::DoctorRequiredCheckFailed,
    ];
    for (result, row) in process_results
        .into_iter()
        .zip(contract["exit_codes"].as_array().expect("exit codes"))
    {
        assert_eq!(row["code"], result.exit_code_u8());
        assert_eq!(row["name"], result.code());
    }
}

#[tokio::test]
async fn all_pass_is_canonical_bounded_and_exit_zero() {
    let (_directory, context) = runtime();
    let probe = TestProbe::all(RhiDoctorObservation::Pass);
    let report = run_rhi_doctor(&context, &probe).await.expect("report");
    assert_eq!(report.service(), "rhi");
    assert_eq!(report.instance().as_str(), "primary");
    assert_eq!(report.status(), RhiDoctorAggregateStatus::Pass);
    assert_eq!(report.exit_code(), 0);
    assert_eq!(report.checks().len(), RHI_DOCTOR_CHECK_COUNT);
    assert!(
        report
            .checks()
            .iter()
            .all(|result| result.status() == RhiDoctorCheckStatus::Pass)
    );
    assert_eq!(
        probe.calls.lock().expect("calls").len(),
        RHI_DOCTOR_CHECK_COUNT
    );

    let bytes = report.canonical_json();
    assert!(bytes.len() <= RHI_DOCTOR_REPORT_MAX_UTF8_BYTES);
    assert!(!bytes.contains(&b'\n'));
    let wire: serde_json::Value = serde_json::from_slice(bytes).expect("JSON");
    assert_eq!(wire["contract_version"], 1);
    assert_eq!(wire["service"], "rhi");
    assert_eq!(wire["instance"], "primary");
    assert_eq!(wire["status"], "pass");
    assert_eq!(wire["checks"].as_array().expect("checks").len(), 15);
    assert!(String::from_utf8_lossy(bytes).starts_with(
        "{\"contract_version\":1,\"service\":\"rhi\",\"instance\":\"primary\",\"status\":\"pass\",\"checks\":["
    ));
    assert_eq!(
        sha256_hex(bytes),
        "5aabfc84927e36bb877c289f8d0ed2be8f4c3115deedad7def3f3e56daab399b"
    );
}

#[tokio::test]
async fn optional_nonpass_is_degraded_while_required_nonpass_fails() {
    let (_directory, context) = runtime();
    for outcome in [RhiDoctorObservation::Fail, RhiDoctorObservation::Skipped] {
        let optional =
            TestProbe::all(RhiDoctorObservation::Pass).with(RhiDoctorCheckId::ClockSkew, outcome);
        let report = run_rhi_doctor(&context, &optional)
            .await
            .expect("optional report");
        assert_eq!(report.status(), RhiDoctorAggregateStatus::Degraded);
        assert_eq!(report.exit_code(), 0);
        assert_ne!(report.checks()[14].status(), RhiDoctorCheckStatus::Pass);

        let required =
            TestProbe::all(RhiDoctorObservation::Pass).with(RhiDoctorCheckId::WriterLock, outcome);
        let report = run_rhi_doctor(&context, &required)
            .await
            .expect("required report");
        assert_eq!(report.status(), RhiDoctorAggregateStatus::Fail);
        assert_eq!(report.exit_code(), 6);
        assert_eq!(report.checks()[1].status(), RhiDoctorCheckStatus::Fail);
    }
}

#[tokio::test]
async fn required_timeout_drops_work_and_remaining_checks_continue_in_order() {
    let (_directory, context) = runtime();
    let probe =
        TestProbe::all(RhiDoctorObservation::Pass).pending(RhiDoctorCheckId::PathsPermissions);
    let report = run_rhi_doctor(&context, &probe).await.expect("report");
    assert_eq!(report.status(), RhiDoctorAggregateStatus::Fail);
    assert_eq!(report.exit_code(), 6);
    assert_eq!(report.checks()[0].status(), RhiDoctorCheckStatus::Timeout);
    assert!(probe.pending_dropped.load(Ordering::SeqCst));
    assert_eq!(
        *probe.calls.lock().expect("calls"),
        rhi_doctor_check_definitions()
            .iter()
            .map(|definition| definition.id())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn report_debug_and_public_errors_retain_no_sensitive_values() {
    let directory = tempfile::tempdir().expect("temporary root");
    let root = directory.path().join("secret-root");
    let invocation = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        "repo-local",
        "--instance",
        "secret-instance",
        "--repo-local-root",
        root.to_str().expect("UTF-8 path"),
        "doctor",
    ])
    .expect("doctor invocation");
    let context = resolve_rhi_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context");
    let report = run_rhi_doctor(&context, &TestProbe::all(RhiDoctorObservation::Pass))
        .await
        .expect("report");
    let debug = format!("{report:?}");
    assert!(!debug.contains("secret-instance"));
    assert!(!debug.contains("secret-root"));
    for result in report.checks() {
        assert!(result.summary().len() <= RHI_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
    }
    let rendered = format!("{:?}", rhi::RhiDoctorErrorKind::OutputTooLarge);
    assert!(!rendered.contains("secret"));
}

#[test]
fn binary_uses_stable_safe_nonzero_results() {
    let canary = "secret-canary-private-key-path-sql-relay-url";
    let invalid = Command::new(env!("CARGO_BIN_EXE_rhi"))
        .arg(format!("--credential={canary}"))
        .output()
        .expect("invalid invocation");
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    let stderr = String::from_utf8(invalid.stderr).expect("invalid stderr");
    assert_eq!(stderr, "RHI command failed: input_or_configuration\n");
    assert!(!stderr.contains(canary));

    let repo_local = tempfile::tempdir().expect("repo-local root");
    let admitted = Command::new(env!("CARGO_BIN_EXE_rhi"))
        .args(["--profile", "repo-local", "--instance", "primary"])
        .arg("--repo-local-root")
        .arg(repo_local.path())
        .arg("run")
        .output()
        .expect("admitted invocation");
    assert_eq!(admitted.status.code(), Some(2));
    assert!(admitted.stdout.is_empty());
    assert_eq!(
        String::from_utf8(admitted.stderr).expect("admitted stderr"),
        "RHI command failed: input_or_configuration\n"
    );
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn id_name(id: RhiDoctorCheckId) -> &'static str {
    match id {
        RhiDoctorCheckId::PathsPermissions => "paths_permissions",
        RhiDoctorCheckId::WriterLock => "writer_lock",
        RhiDoctorCheckId::SqliteSchema => "sqlite_schema",
        RhiDoctorCheckId::SqliteIntegrity => "sqlite_integrity",
        RhiDoctorCheckId::SqliteFreeSpace => "sqlite_free_space",
        RhiDoctorCheckId::IdentityBinding => "identity_binding",
        RhiDoctorCheckId::AdminBindPolicy => "admin_bind_policy",
        RhiDoctorCheckId::OperationsBindPolicy => "operations_bind_policy",
        RhiDoctorCheckId::NetworkPolicy => "network_policy",
        RhiDoctorCheckId::RequiredSources => "required_sources",
        RhiDoctorCheckId::CursorCheckpoint => "cursor_checkpoint",
        RhiDoctorCheckId::ReconciliationLeases => "reconciliation_leases",
        RhiDoctorCheckId::ReconciliationBacklog => "reconciliation_backlog",
        RhiDoctorCheckId::PublicationInvariants => "publication_invariants",
        RhiDoctorCheckId::ClockSkew => "clock_skew",
    }
}

fn remediation_name(code: RhiDoctorRemediationCode) -> &'static str {
    match code {
        RhiDoctorRemediationCode::CorrectPathPolicy => "correct_path_policy",
        RhiDoctorRemediationCode::ReleaseWriterLock => "release_writer_lock",
        RhiDoctorRemediationCode::RepairSchema => "repair_schema",
        RhiDoctorRemediationCode::RestoreVerifiedState => "restore_verified_state",
        RhiDoctorRemediationCode::FreeStateDiskSpace => "free_state_disk_space",
        RhiDoctorRemediationCode::RestoreIdentityBinding => "restore_identity_binding",
        RhiDoctorRemediationCode::CorrectAdminBindPolicy => "correct_admin_bind_policy",
        RhiDoctorRemediationCode::CorrectOperationsBindPolicy => "correct_operations_bind_policy",
        RhiDoctorRemediationCode::CorrectNetworkPolicy => "correct_network_policy",
        RhiDoctorRemediationCode::RestoreRequiredSources => "restore_required_sources",
        RhiDoctorRemediationCode::RepairCursorCheckpoint => "repair_cursor_checkpoint",
        RhiDoctorRemediationCode::RepairReconciliationLeases => "repair_reconciliation_leases",
        RhiDoctorRemediationCode::ReduceReconciliationBacklog => "reduce_reconciliation_backlog",
        RhiDoctorRemediationCode::RepairPublicationState => "repair_publication_state",
        RhiDoctorRemediationCode::CorrectClock => "correct_clock",
    }
}
