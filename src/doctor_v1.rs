//! Bounded active-doctor orchestration and safe structured evidence.

use core::{fmt, future::Future, pin::Pin, time::Duration};
use std::error::Error;

use radroots_runtime_paths::InstanceId;
use serde::Serialize;

use crate::RhiRuntimeContext;

/// RHI doctor wire-contract version.
pub const RHI_DOCTOR_CONTRACT_VERSION: u32 = 1;
/// Exact number of governed RHI doctor checks.
pub const RHI_DOCTOR_CHECK_COUNT: usize = 15;
/// Maximum encoded size of one safe summary.
pub const RHI_DOCTOR_SUMMARY_MAX_UTF8_BYTES: usize = 256;
/// Maximum encoded size of the complete canonical doctor report.
pub const RHI_DOCTOR_REPORT_MAX_UTF8_BYTES: usize = 8_192;

const RHI_SERVICE: &str = "rhi";
const DOCTOR_FAILURE_EXIT_CODE: u8 = 6;
const _: () = {
    assert!("check passed".len() <= RHI_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
    assert!("check failed".len() <= RHI_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
    assert!("check timed out".len() <= RHI_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
    assert!("optional check skipped".len() <= RHI_DOCTOR_SUMMARY_MAX_UTF8_BYTES);
};

/// The closed RHI doctor inventory.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum RhiDoctorCheckId {
    PathsPermissions,
    WriterLock,
    SqliteSchema,
    SqliteIntegrity,
    SqliteFreeSpace,
    IdentityBinding,
    AdminBindPolicy,
    OperationsBindPolicy,
    NetworkPolicy,
    RequiredSources,
    CursorCheckpoint,
    ReconciliationLeases,
    ReconciliationBacklog,
    PublicationInvariants,
    ClockSkew,
}

impl RhiDoctorCheckId {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PathsPermissions => "paths_permissions",
            Self::WriterLock => "writer_lock",
            Self::SqliteSchema => "sqlite_schema",
            Self::SqliteIntegrity => "sqlite_integrity",
            Self::SqliteFreeSpace => "sqlite_free_space",
            Self::IdentityBinding => "identity_binding",
            Self::AdminBindPolicy => "admin_bind_policy",
            Self::OperationsBindPolicy => "operations_bind_policy",
            Self::NetworkPolicy => "network_policy",
            Self::RequiredSources => "required_sources",
            Self::CursorCheckpoint => "cursor_checkpoint",
            Self::ReconciliationLeases => "reconciliation_leases",
            Self::ReconciliationBacklog => "reconciliation_backlog",
            Self::PublicationInvariants => "publication_invariants",
            Self::ClockSkew => "clock_skew",
        }
    }
}

/// Stable operator action associated with one doctor check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiDoctorRemediationCode {
    CorrectPathPolicy,
    ReleaseWriterLock,
    RepairSchema,
    RestoreVerifiedState,
    FreeStateDiskSpace,
    RestoreIdentityBinding,
    CorrectAdminBindPolicy,
    CorrectOperationsBindPolicy,
    CorrectNetworkPolicy,
    RestoreRequiredSources,
    RepairCursorCheckpoint,
    RepairReconciliationLeases,
    ReduceReconciliationBacklog,
    RepairPublicationState,
    CorrectClock,
}

impl RhiDoctorRemediationCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CorrectPathPolicy => "correct_path_policy",
            Self::ReleaseWriterLock => "release_writer_lock",
            Self::RepairSchema => "repair_schema",
            Self::RestoreVerifiedState => "restore_verified_state",
            Self::FreeStateDiskSpace => "free_state_disk_space",
            Self::RestoreIdentityBinding => "restore_identity_binding",
            Self::CorrectAdminBindPolicy => "correct_admin_bind_policy",
            Self::CorrectOperationsBindPolicy => "correct_operations_bind_policy",
            Self::CorrectNetworkPolicy => "correct_network_policy",
            Self::RestoreRequiredSources => "restore_required_sources",
            Self::RepairCursorCheckpoint => "repair_cursor_checkpoint",
            Self::RepairReconciliationLeases => "repair_reconciliation_leases",
            Self::ReduceReconciliationBacklog => "reduce_reconciliation_backlog",
            Self::RepairPublicationState => "repair_publication_state",
            Self::CorrectClock => "correct_clock",
        }
    }
}

/// Immutable authority for one check's requirement, deadline, and remediation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiDoctorCheckDefinition {
    id: RhiDoctorCheckId,
    required: bool,
    deadline_ms: u64,
    remediation_code: RhiDoctorRemediationCode,
    scope: &'static [&'static str],
}

impl RhiDoctorCheckDefinition {
    const fn new(
        id: RhiDoctorCheckId,
        required: bool,
        deadline_ms: u64,
        remediation_code: RhiDoctorRemediationCode,
        scope: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            required,
            deadline_ms,
            remediation_code,
            scope,
        }
    }

    /// Returns the governed check identifier.
    #[must_use]
    pub const fn id(self) -> RhiDoctorCheckId {
        self.id
    }

    /// Returns whether a non-pass result fails the doctor command.
    #[must_use]
    pub const fn required(self) -> bool {
        self.required
    }

    /// Returns the exact per-check deadline in milliseconds.
    #[must_use]
    pub const fn deadline_ms(self) -> u64 {
        self.deadline_ms
    }

    /// Returns the fixed, safe operator remediation classification.
    #[must_use]
    pub const fn remediation_code(self) -> RhiDoctorRemediationCode {
        self.remediation_code
    }

    /// Returns the exact safe evidence facets owned by this check.
    #[must_use]
    pub const fn scope(self) -> &'static [&'static str] {
        self.scope
    }
}

const CHECK_DEFINITIONS: [RhiDoctorCheckDefinition; RHI_DOCTOR_CHECK_COUNT] = [
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::PathsPermissions,
        true,
        2_000,
        RhiDoctorRemediationCode::CorrectPathPolicy,
        &["resolved_path_containment", "owner", "type", "mode"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::WriterLock,
        true,
        2_000,
        RhiDoctorRemediationCode::ReleaseWriterLock,
        &["state_directory_binding", "writer_lock_state"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::SqliteSchema,
        true,
        5_000,
        RhiDoctorRemediationCode::RepairSchema,
        &["metadata_identity", "migration_history", "schema_catalog"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::SqliteIntegrity,
        true,
        15_000,
        RhiDoctorRemediationCode::RestoreVerifiedState,
        &["integrity_check", "foreign_key_check"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::SqliteFreeSpace,
        true,
        2_000,
        RhiDoctorRemediationCode::FreeStateDiskSpace,
        &["state_filesystem_capacity", "minimum_free_bytes"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::IdentityBinding,
        true,
        2_000,
        RhiDoctorRemediationCode::RestoreIdentityBinding,
        &[
            "envelope_contract",
            "credential_reference",
            "public_identity",
        ],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::AdminBindPolicy,
        true,
        2_000,
        RhiDoctorRemediationCode::CorrectAdminBindPolicy,
        &["unix_socket_path", "socket_mode", "peer_authorization"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::OperationsBindPolicy,
        true,
        2_000,
        RhiDoctorRemediationCode::CorrectOperationsBindPolicy,
        &["enabled_posture", "listen_address", "bind_policy"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::NetworkPolicy,
        true,
        2_000,
        RhiDoctorRemediationCode::CorrectNetworkPolicy,
        &["dns_policy", "tls_policy", "relay_url_policy"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::RequiredSources,
        true,
        15_000,
        RhiDoctorRemediationCode::RestoreRequiredSources,
        &[
            "required_source_inventory",
            "reachability",
            "source_deadline",
        ],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::CursorCheckpoint,
        true,
        5_000,
        RhiDoctorRemediationCode::RepairCursorCheckpoint,
        &[
            "selector_binding",
            "cursor_plausibility",
            "completion_evidence",
        ],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::ReconciliationLeases,
        true,
        5_000,
        RhiDoctorRemediationCode::RepairReconciliationLeases,
        &["lease_ownership", "lease_expiry", "retry_state"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::ReconciliationBacklog,
        true,
        5_000,
        RhiDoctorRemediationCode::ReduceReconciliationBacklog,
        &["queue_bound", "attempt_bound", "schedule_plausibility"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::PublicationInvariants,
        true,
        5_000,
        RhiDoctorRemediationCode::RepairPublicationState,
        &["exact_signed_bytes", "target_inventory", "outbox_schedule"],
    ),
    RhiDoctorCheckDefinition::new(
        RhiDoctorCheckId::ClockSkew,
        false,
        5_000,
        RhiDoctorRemediationCode::CorrectClock,
        &["wall_clock_skew"],
    ),
];

/// Returns the exact ordered doctor inventory.
#[must_use]
pub const fn rhi_doctor_check_definitions()
-> &'static [RhiDoctorCheckDefinition; RHI_DOCTOR_CHECK_COUNT] {
    &CHECK_DEFINITIONS
}

/// A closed result supplied by one bounded check implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiDoctorObservation {
    Pass,
    Fail,
    Skipped,
}

/// Future returned by one doctor probe.
pub type RhiDoctorFuture<'a> = Pin<Box<dyn Future<Output = RhiDoctorObservation> + Send + 'a>>;

/// Executes each active check without receiving report-construction authority.
///
/// `Pass` is permitted only after every facet in
/// [`RhiDoctorCheckDefinition::scope`] is proven. Implementations must be
/// cancellation-safe: dropping the future at its deadline must stop work or
/// leave synchronous cleanup owned by that future, never detached mutation.
pub trait RhiDoctorProbe: Send + Sync {
    /// Runs one exact check. Raw errors, paths, and arbitrary summaries cannot
    /// cross this boundary.
    fn probe(&self, definition: RhiDoctorCheckDefinition) -> RhiDoctorFuture<'_>;
}

/// Stable status of one completed check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiDoctorCheckStatus {
    Pass,
    Fail,
    Timeout,
    Skipped,
}

impl RhiDoctorCheckStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Timeout => "timeout",
            Self::Skipped => "skipped",
        }
    }

    const fn summary(self) -> &'static str {
        match self {
            Self::Pass => "check passed",
            Self::Fail => "check failed",
            Self::Timeout => "check timed out",
            Self::Skipped => "optional check skipped",
        }
    }
}

/// Stable aggregate doctor status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiDoctorAggregateStatus {
    Pass,
    Degraded,
    Fail,
}

impl RhiDoctorAggregateStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Degraded => "degraded",
            Self::Fail => "fail",
        }
    }
}

/// One sealed structured doctor result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiDoctorCheckResult {
    definition: RhiDoctorCheckDefinition,
    status: RhiDoctorCheckStatus,
}

impl RhiDoctorCheckResult {
    /// Returns the exact check definition.
    #[must_use]
    pub const fn definition(self) -> RhiDoctorCheckDefinition {
        self.definition
    }

    /// Returns the admitted check status.
    #[must_use]
    pub const fn status(self) -> RhiDoctorCheckStatus {
        self.status
    }

    /// Returns the fixed content-free summary.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        self.status.summary()
    }
}

/// Stable source-free doctor construction failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiDoctorErrorKind {
    Encoding,
    OutputTooLarge,
}

impl RhiDoctorErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::Encoding => "RHI doctor output encoding failed",
            Self::OutputTooLarge => "RHI doctor output exceeds its byte limit",
        }
    }
}

/// One redacted doctor construction failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiDoctorError {
    kind: RhiDoctorErrorKind,
}

impl RhiDoctorError {
    const fn new(kind: RhiDoctorErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable error classification.
    #[must_use]
    pub const fn kind(self) -> RhiDoctorErrorKind {
        self.kind
    }
}

impl fmt::Debug for RhiDoctorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiDoctorError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiDoctorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for RhiDoctorError {}

/// One immutable, bounded, canonical RHI doctor report.
///
/// Construction remains inside [`run_rhi_doctor`]:
///
/// ```compile_fail
/// use rhi::{RhiDoctorAggregateStatus, RhiDoctorReport};
///
/// let _ = RhiDoctorReport {
///     instance: todo!(),
///     status: RhiDoctorAggregateStatus::Pass,
///     checks: Box::new([]),
///     canonical_json: Box::new([]),
/// };
/// ```
pub struct RhiDoctorReport {
    instance: InstanceId,
    status: RhiDoctorAggregateStatus,
    checks: Box<[RhiDoctorCheckResult]>,
    canonical_json: Box<[u8]>,
}

impl RhiDoctorReport {
    /// Returns the fixed service identifier.
    #[must_use]
    pub const fn service(&self) -> &'static str {
        RHI_SERVICE
    }

    /// Returns the validated instance identifier admitted into the report.
    #[must_use]
    pub const fn instance(&self) -> &InstanceId {
        &self.instance
    }

    /// Returns the aggregate result.
    #[must_use]
    pub const fn status(&self) -> RhiDoctorAggregateStatus {
        self.status
    }

    /// Returns the ordered complete check inventory.
    #[must_use]
    pub fn checks(&self) -> &[RhiDoctorCheckResult] {
        &self.checks
    }

    /// Returns exact compact UTF-8 JSON in the shared v1 field order.
    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    /// Returns exit 6 only when a required check failed or timed out.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self.status {
            RhiDoctorAggregateStatus::Fail => DOCTOR_FAILURE_EXIT_CODE,
            RhiDoctorAggregateStatus::Pass | RhiDoctorAggregateStatus::Degraded => 0,
        }
    }
}

impl fmt::Debug for RhiDoctorReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiDoctorReport")
            .field("service", &RHI_SERVICE)
            .field("instance", &"[redacted]")
            .field("status", &self.status)
            .field("check_count", &self.checks.len())
            .field("canonical_json", &"[redacted]")
            .finish()
    }
}

/// Runs every governed check in exact contract order under its fixed deadline.
///
/// Probe implementations retain operation-specific filesystem, SQLite,
/// identity, listener, network, source, reconciliation, publication, and clock
/// authority. This orchestrator accepts only a closed result and cannot
/// serialize their paths or raw errors.
pub async fn run_rhi_doctor(
    context: &RhiRuntimeContext,
    probe: &(impl RhiDoctorProbe + ?Sized),
) -> Result<RhiDoctorReport, RhiDoctorError> {
    let mut checks = Vec::with_capacity(RHI_DOCTOR_CHECK_COUNT);
    for definition in CHECK_DEFINITIONS {
        let status = match tokio::time::timeout(
            Duration::from_millis(definition.deadline_ms),
            probe.probe(definition),
        )
        .await
        {
            Ok(RhiDoctorObservation::Pass) => RhiDoctorCheckStatus::Pass,
            Ok(RhiDoctorObservation::Fail) => RhiDoctorCheckStatus::Fail,
            Ok(RhiDoctorObservation::Skipped) if !definition.required => {
                RhiDoctorCheckStatus::Skipped
            }
            Ok(RhiDoctorObservation::Skipped) => RhiDoctorCheckStatus::Fail,
            Err(_) => RhiDoctorCheckStatus::Timeout,
        };
        checks.push(RhiDoctorCheckResult { definition, status });
    }
    let checks = checks.into_boxed_slice();
    let status = aggregate_status(&checks);
    let instance = context.context().instance().clone();
    let canonical_json = encode_report(&instance, status, &checks)?;

    Ok(RhiDoctorReport {
        instance,
        status,
        checks,
        canonical_json,
    })
}

fn aggregate_status(checks: &[RhiDoctorCheckResult]) -> RhiDoctorAggregateStatus {
    if checks
        .iter()
        .any(|result| result.definition.required && result.status != RhiDoctorCheckStatus::Pass)
    {
        RhiDoctorAggregateStatus::Fail
    } else if checks
        .iter()
        .any(|result| result.status != RhiDoctorCheckStatus::Pass)
    {
        RhiDoctorAggregateStatus::Degraded
    } else {
        RhiDoctorAggregateStatus::Pass
    }
}

#[derive(Serialize)]
struct DoctorWireReport<'a> {
    contract_version: u32,
    service: &'static str,
    instance: &'a str,
    status: &'static str,
    checks: Vec<DoctorWireCheck>,
}

#[derive(Serialize)]
struct DoctorWireCheck {
    id: &'static str,
    status: &'static str,
    required: bool,
    deadline_ms: u64,
    summary: &'static str,
    remediation_code: &'static str,
}

fn encode_report(
    instance: &InstanceId,
    status: RhiDoctorAggregateStatus,
    checks: &[RhiDoctorCheckResult],
) -> Result<Box<[u8]>, RhiDoctorError> {
    let checks = checks
        .iter()
        .map(|result| DoctorWireCheck {
            id: result.definition.id.as_str(),
            status: result.status.as_str(),
            required: result.definition.required,
            deadline_ms: result.definition.deadline_ms,
            summary: result.status.summary(),
            remediation_code: result.definition.remediation_code.as_str(),
        })
        .collect();
    let encoded = serde_json::to_vec(&DoctorWireReport {
        contract_version: RHI_DOCTOR_CONTRACT_VERSION,
        service: RHI_SERVICE,
        instance: instance.as_str(),
        status: status.as_str(),
        checks,
    })
    .map_err(|_| RhiDoctorError::new(RhiDoctorErrorKind::Encoding))?;
    if encoded.len() > RHI_DOCTOR_REPORT_MAX_UTF8_BYTES {
        return Err(RhiDoctorError::new(RhiDoctorErrorKind::OutputTooLarge));
    }
    Ok(encoded.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{RhiDoctorError, RhiDoctorErrorKind};

    #[test]
    fn errors_are_source_free_and_content_free() {
        for kind in [
            RhiDoctorErrorKind::Encoding,
            RhiDoctorErrorKind::OutputTooLarge,
        ] {
            let error = RhiDoctorError::new(kind);
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            for forbidden in ["/private", "secret", "relay", "sqlite"] {
                assert!(!rendered.to_ascii_lowercase().contains(forbidden));
            }
        }
    }
}
