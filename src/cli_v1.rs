//! One-pass command-line admission for the hardened RHI command contract.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};
use radroots_runtime_paths::InstanceId;

/// The exact bootstrap profile selected by the operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiBootstrapProfileV1 {
    ServiceHost,
    Interactive,
    RepoLocal,
}

/// The only two governed command-result encodings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RhiCliOutputModeV1 {
    #[default]
    Human,
    Json,
}

/// The exact governed top-level RHI command inventory.
#[derive(PartialEq, Eq)]
pub enum RhiCommandV1 {
    Run,
    Config(RhiConfigCommandV1),
    State(RhiStateCommandV1),
    Identity(RhiIdentityCommandV1),
    Status,
    Metrics(RhiMetricsCommandV1),
    Reconciliation(RhiReconciliationCommandV1),
    Sources(RhiSourcesCommandV1),
    Trade(RhiTradeCommandV1),
    Publication(RhiPublicationCommandV1),
    Presence(RhiPresenceCommandV1),
    Doctor,
}

/// Governed configuration commands.
#[derive(PartialEq, Eq)]
pub enum RhiConfigCommandV1 {
    Init,
    Validate,
    Show,
    Schema,
    Apply(RhiConfigApplyArgsV1),
}

/// Governed state commands.
#[derive(PartialEq, Eq)]
pub enum RhiStateCommandV1 {
    Init,
    Status,
    Backup(RhiStateBackupArgsV1),
    Restore(RhiStateRestoreArgsV1),
    Verify,
    Migrate,
}

/// Governed service-identity commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiIdentityCommandV1 {
    Init,
    Status,
    ExportPublic,
}

/// Governed metrics commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiMetricsCommandV1 {
    Snapshot,
}

/// Governed reconciliation commands.
#[derive(PartialEq, Eq)]
pub enum RhiReconciliationCommandV1 {
    Status,
    Jobs(RhiPageQueryArgsV1),
    Refresh(RhiReconciliationRefreshArgsV1),
}

/// Governed evidence-source commands.
#[derive(PartialEq, Eq)]
pub enum RhiSourcesCommandV1 {
    List(RhiPageQueryArgsV1),
}

/// Governed trade-query commands.
#[derive(PartialEq, Eq)]
pub enum RhiTradeCommandV1 {
    Projection(RhiTradeArgsV1),
    ReportCurrent(RhiTradeArgsV1),
    Reports(RhiTradePageArgsV1),
}

/// Governed publication commands.
#[derive(PartialEq, Eq)]
pub enum RhiPublicationCommandV1 {
    Backlog(RhiPageQueryArgsV1),
    Targets(RhiPageQueryArgsV1),
    Retry(RhiPublicationRetryArgsV1),
}

/// Governed desired-presence commands.
#[derive(PartialEq, Eq)]
pub enum RhiPresenceCommandV1 {
    Desired,
    Render(RhiPresenceMutationArgsV1),
    Refresh(RhiPresenceMutationArgsV1),
}

/// Exact offline configuration-apply input.
#[derive(PartialEq, Eq)]
pub struct RhiConfigApplyArgsV1 {
    candidate_config: PathBuf,
}

impl RhiConfigApplyArgsV1 {
    #[must_use]
    pub fn candidate_config(&self) -> &Path {
        &self.candidate_config
    }
}

/// Exact live state-backup input.
#[derive(PartialEq, Eq)]
pub struct RhiStateBackupArgsV1 {
    operation_id: Box<str>,
    target: PathBuf,
    expected_generation: u64,
}

impl RhiStateBackupArgsV1 {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
}

/// Exact offline state-restore input.
#[derive(PartialEq, Eq)]
pub struct RhiStateRestoreArgsV1 {
    manifest: PathBuf,
    manifest_sha256: Box<str>,
    bundle: PathBuf,
    maximum_state_bytes: u64,
}

impl RhiStateRestoreArgsV1 {
    #[must_use]
    pub fn manifest(&self) -> &Path {
        &self.manifest
    }

    #[must_use]
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    #[must_use]
    pub fn bundle(&self) -> &Path {
        &self.bundle
    }

    #[must_use]
    pub const fn maximum_state_bytes(&self) -> u64 {
        self.maximum_state_bytes
    }
}

/// Bounded stable pagination input shared by list commands.
#[derive(PartialEq, Eq)]
pub struct RhiPageQueryArgsV1 {
    limit: u16,
    cursor: Option<Box<str>>,
}

impl RhiPageQueryArgsV1 {
    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}

/// Exact trade selection for one live query.
#[derive(PartialEq, Eq)]
pub struct RhiTradeArgsV1 {
    trade_id: Box<str>,
}

impl RhiTradeArgsV1 {
    #[must_use]
    pub fn trade_id(&self) -> &str {
        &self.trade_id
    }
}

/// Exact trade selection plus bounded report pagination.
#[derive(PartialEq, Eq)]
pub struct RhiTradePageArgsV1 {
    trade_id: Box<str>,
    page: RhiPageQueryArgsV1,
}

impl RhiTradePageArgsV1 {
    #[must_use]
    pub fn trade_id(&self) -> &str {
        &self.trade_id
    }

    #[must_use]
    pub const fn page(&self) -> &RhiPageQueryArgsV1 {
        &self.page
    }
}

/// Exact refresh request and idempotency identity.
#[derive(PartialEq, Eq)]
pub struct RhiReconciliationRefreshArgsV1 {
    operation_id: Box<str>,
    trade_id: Box<str>,
    expected_dirty_generation: u64,
}

impl RhiReconciliationRefreshArgsV1 {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn trade_id(&self) -> &str {
        &self.trade_id
    }

    #[must_use]
    pub const fn expected_dirty_generation(&self) -> u64 {
        self.expected_dirty_generation
    }
}

/// Exact publication retry request and idempotency identity.
#[derive(PartialEq, Eq)]
pub struct RhiPublicationRetryArgsV1 {
    operation_id: Box<str>,
    workflow_id: Box<str>,
    expected_generation: u64,
}

impl RhiPublicationRetryArgsV1 {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
}

/// Exact presence mutation request and idempotency identity.
#[derive(PartialEq, Eq)]
pub struct RhiPresenceMutationArgsV1 {
    operation_id: Box<str>,
    expected_generation: u64,
}

impl RhiPresenceMutationArgsV1 {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }
}

macro_rules! redacted_debug {
    ($($type:ty),+ $(,)?) => {
        $(
            impl fmt::Debug for $type {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(concat!(stringify!($type), "([redacted])"))
                }
            }
        )+
    };
}

redacted_debug!(
    RhiConfigApplyArgsV1,
    RhiStateBackupArgsV1,
    RhiStateRestoreArgsV1,
    RhiPageQueryArgsV1,
    RhiTradeArgsV1,
    RhiTradePageArgsV1,
    RhiReconciliationRefreshArgsV1,
    RhiPublicationRetryArgsV1,
    RhiPresenceMutationArgsV1,
);

impl fmt::Debug for RhiCommandV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Run => "RhiCommandV1::Run",
            Self::Config(_) => "RhiCommandV1::Config([redacted])",
            Self::State(_) => "RhiCommandV1::State([redacted])",
            Self::Identity(_) => "RhiCommandV1::Identity([redacted])",
            Self::Status => "RhiCommandV1::Status",
            Self::Metrics(_) => "RhiCommandV1::Metrics([redacted])",
            Self::Reconciliation(_) => "RhiCommandV1::Reconciliation([redacted])",
            Self::Sources(_) => "RhiCommandV1::Sources([redacted])",
            Self::Trade(_) => "RhiCommandV1::Trade([redacted])",
            Self::Publication(_) => "RhiCommandV1::Publication([redacted])",
            Self::Presence(_) => "RhiCommandV1::Presence([redacted])",
            Self::Doctor => "RhiCommandV1::Doctor",
        })
    }
}

/// The only three process authorities selected by the hardened CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiCliPrimaryAuthorityV1 {
    Daemon,
    Offline,
    LiveUnixAdmin,
}

/// The closed offline operation classes selected before any state access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiCliOfflineOperationV1 {
    Config,
    StateExclusive,
    IdentityExclusive,
    Doctor,
}

/// The closed Unix-admin operations reachable from the command inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiCliAdminOperationV1 {
    Status,
    EffectiveConfig,
    IdentityStatus,
    IdentityPublic,
    StateStatus,
    StateBackup,
    MetricsSnapshot,
    ReconciliationStatus,
    ReconciliationJobs,
    ReconciliationRefresh,
    Sources,
    TradeProjection,
    TradeReportCurrent,
    TradeReports,
    PublicationBacklog,
    PublicationTargets,
    PublicationRetry,
    PresenceDesired,
    PresenceRender,
    PresenceRefresh,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RhiCliAdminOperationV1 {
    /// Returns the exact native Unix-admin route selected by this operation.
    #[must_use]
    pub const fn route(self) -> crate::RhiAdminRoute {
        match self {
            Self::Status => crate::RhiAdminRoute::Status,
            Self::EffectiveConfig => crate::RhiAdminRoute::EffectiveConfig,
            Self::IdentityStatus => crate::RhiAdminRoute::IdentityStatus,
            Self::IdentityPublic => crate::RhiAdminRoute::IdentityPublic,
            Self::StateStatus => crate::RhiAdminRoute::StateStatus,
            Self::StateBackup => crate::RhiAdminRoute::StateBackup,
            Self::MetricsSnapshot => crate::RhiAdminRoute::MetricsSnapshot,
            Self::ReconciliationStatus => crate::RhiAdminRoute::ReconciliationStatus,
            Self::ReconciliationJobs => crate::RhiAdminRoute::ReconciliationJobs,
            Self::ReconciliationRefresh => crate::RhiAdminRoute::ReconciliationRefresh,
            Self::Sources => crate::RhiAdminRoute::Sources,
            Self::TradeProjection => crate::RhiAdminRoute::TradeProjection,
            Self::TradeReportCurrent => crate::RhiAdminRoute::TradeReportCurrent,
            Self::TradeReports => crate::RhiAdminRoute::TradeReports,
            Self::PublicationBacklog => crate::RhiAdminRoute::PublicationBacklog,
            Self::PublicationTargets => crate::RhiAdminRoute::PublicationTargets,
            Self::PublicationRetry => crate::RhiAdminRoute::PublicationRetry,
            Self::PresenceDesired => crate::RhiAdminRoute::PresenceDesired,
            Self::PresenceRender => crate::RhiAdminRoute::PresenceRender,
            Self::PresenceRefresh => crate::RhiAdminRoute::PresenceRefresh,
        }
    }
}

/// A sealed, side-effect-free execution plan for one admitted CLI invocation.
///
/// Construction is owned by [`plan_rhi_cli_v1`]. Live commands carry only a
/// governed Unix-admin operation and never receive an offline or direct-SQLite
/// fallback.
///
/// ```compile_fail
/// use rhi::{RhiCliExecutionPlanV1, RhiCliPrimaryAuthorityV1};
///
/// let _ = RhiCliExecutionPlanV1 {
///     primary_authority: RhiCliPrimaryAuthorityV1::Offline,
///     offline_operation: None,
///     admin_operation: None,
/// };
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiCliExecutionPlanV1 {
    primary_authority: RhiCliPrimaryAuthorityV1,
    offline_operation: Option<RhiCliOfflineOperationV1>,
    admin_operation: Option<RhiCliAdminOperationV1>,
}

impl RhiCliExecutionPlanV1 {
    /// Returns the sole selected process authority.
    #[must_use]
    pub const fn primary_authority(&self) -> RhiCliPrimaryAuthorityV1 {
        self.primary_authority
    }

    /// Returns the bounded offline operation, when the plan admits one.
    #[must_use]
    pub const fn offline_operation(&self) -> Option<RhiCliOfflineOperationV1> {
        self.offline_operation
    }

    /// Returns the bounded Unix-admin operation, when the plan admits one.
    #[must_use]
    pub const fn admin_operation(&self) -> Option<RhiCliAdminOperationV1> {
        self.admin_operation
    }
}

impl fmt::Debug for RhiCliExecutionPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiCliExecutionPlanV1")
            .field("primary_authority", &self.primary_authority)
            .field("offline_operation", &self.offline_operation)
            .field("admin_operation", &self.admin_operation)
            .finish()
    }
}

/// Stable source-free classification for command-line admission failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiCliV1ErrorKind {
    InvalidArguments,
    InvalidInstance,
    InvalidRepoLocalRoot,
    UnexpectedRepoLocalRoot,
    InvalidConfigPath,
    InvalidCommandInput,
}

impl RhiCliV1ErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidArguments => "command-line arguments are invalid",
            Self::InvalidInstance => "instance identifier is invalid",
            Self::InvalidRepoLocalRoot => "repo-local profile requires a valid absolute root",
            Self::UnexpectedRepoLocalRoot => {
                "repo-local root is forbidden outside the repo-local profile"
            }
            Self::InvalidConfigPath => "configuration path must be absolute without traversal",
            Self::InvalidCommandInput => "command input is invalid",
        }
    }
}

/// One safe command-line admission failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiCliV1Error {
    kind: RhiCliV1ErrorKind,
}

impl RhiCliV1Error {
    const fn new(kind: RhiCliV1ErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> RhiCliV1ErrorKind {
        self.kind
    }
}

impl fmt::Debug for RhiCliV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiCliV1Error")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiCliV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for RhiCliV1Error {}

/// A validated one-pass RHI bootstrap and command selection.
pub struct RhiCliInvocationV1 {
    profile: RhiBootstrapProfileV1,
    instance: InstanceId,
    repo_local_root: Option<PathBuf>,
    config_path: Option<PathBuf>,
    output_mode: RhiCliOutputModeV1,
    command: RhiCommandV1,
}

impl RhiCliInvocationV1 {
    /// Returns the explicitly selected bootstrap profile.
    #[must_use]
    pub const fn profile(&self) -> RhiBootstrapProfileV1 {
        self.profile
    }

    /// Returns the validated instance identifier.
    #[must_use]
    pub const fn instance(&self) -> &InstanceId {
        &self.instance
    }

    /// Returns the explicit repo-local root, when selected.
    #[must_use]
    pub fn repo_local_root(&self) -> Option<&Path> {
        self.repo_local_root.as_deref()
    }

    /// Returns the optional explicit configuration path.
    #[must_use]
    pub fn config_path(&self) -> Option<&Path> {
        self.config_path.as_deref()
    }

    /// Returns the selected human or governed machine-result encoding.
    #[must_use]
    pub const fn output_mode(&self) -> RhiCliOutputModeV1 {
        self.output_mode
    }

    /// Returns the exact governed command selection.
    #[must_use]
    pub const fn command(&self) -> &RhiCommandV1 {
        &self.command
    }
}

impl fmt::Debug for RhiCliInvocationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiCliInvocationV1")
            .field("profile", &self.profile)
            .field("instance", &"[redacted]")
            .field(
                "repo_local_root",
                &self.repo_local_root.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "config_path",
                &self.config_path.as_ref().map(|_| "[redacted]"),
            )
            .field("output_mode", &self.output_mode)
            .field("command", &self.command)
            .finish()
    }
}

/// Parses the exact hardened RHI bootstrap and command tree once.
///
/// The iterator must include the program name as its first element. Clap's
/// dependency-owned diagnostic is deliberately discarded so caller-controlled
/// argument text cannot escape through this crate's stable error boundary.
pub fn parse_rhi_cli_v1_from<I, T>(arguments: I) -> Result<RhiCliInvocationV1, RhiCliV1Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let parsed = RawRhiCliV1::try_parse_from(arguments)
        .map_err(|_| RhiCliV1Error::new(RhiCliV1ErrorKind::InvalidArguments))?;
    let profile = parsed
        .profile
        .ok_or_else(|| RhiCliV1Error::new(RhiCliV1ErrorKind::InvalidArguments))?
        .into();
    let instance = parsed
        .instance
        .ok_or_else(|| RhiCliV1Error::new(RhiCliV1ErrorKind::InvalidArguments))?;
    let instance = InstanceId::new(instance)
        .map_err(|_| RhiCliV1Error::new(RhiCliV1ErrorKind::InvalidInstance))?;
    validate_bootstrap_paths(
        profile,
        parsed.repo_local_root.as_deref(),
        parsed.config.as_deref(),
    )?;

    Ok(RhiCliInvocationV1 {
        profile,
        instance,
        repo_local_root: parsed.repo_local_root,
        config_path: parsed.config,
        output_mode: parsed.output.into(),
        command: admit_command(parsed.command)?,
    })
}

/// Selects the sole permitted execution authority for an admitted command.
///
/// This function performs no filesystem, database, socket, environment, task,
/// or process work. Later executors consume the plan without reparsing process
/// arguments. No live command receives direct SQLite or offline fallback
/// authority.
#[must_use]
pub const fn plan_rhi_cli_v1(invocation: &RhiCliInvocationV1) -> RhiCliExecutionPlanV1 {
    match &invocation.command {
        RhiCommandV1::Run => daemon_plan(),
        RhiCommandV1::Config(RhiConfigCommandV1::Init)
        | RhiCommandV1::Config(RhiConfigCommandV1::Validate)
        | RhiCommandV1::Config(RhiConfigCommandV1::Schema)
        | RhiCommandV1::Config(RhiConfigCommandV1::Apply(_)) => {
            offline_plan(RhiCliOfflineOperationV1::Config)
        }
        RhiCommandV1::Config(RhiConfigCommandV1::Show) => {
            admin_plan(RhiCliAdminOperationV1::EffectiveConfig)
        }
        RhiCommandV1::State(RhiStateCommandV1::Init)
        | RhiCommandV1::State(RhiStateCommandV1::Restore(_))
        | RhiCommandV1::State(RhiStateCommandV1::Verify)
        | RhiCommandV1::State(RhiStateCommandV1::Migrate) => {
            offline_plan(RhiCliOfflineOperationV1::StateExclusive)
        }
        RhiCommandV1::State(RhiStateCommandV1::Status) => {
            admin_plan(RhiCliAdminOperationV1::StateStatus)
        }
        RhiCommandV1::State(RhiStateCommandV1::Backup(_)) => {
            admin_plan(RhiCliAdminOperationV1::StateBackup)
        }
        RhiCommandV1::Identity(RhiIdentityCommandV1::Init) => {
            offline_plan(RhiCliOfflineOperationV1::IdentityExclusive)
        }
        RhiCommandV1::Identity(RhiIdentityCommandV1::Status) => {
            admin_plan(RhiCliAdminOperationV1::IdentityStatus)
        }
        RhiCommandV1::Identity(RhiIdentityCommandV1::ExportPublic) => {
            admin_plan(RhiCliAdminOperationV1::IdentityPublic)
        }
        RhiCommandV1::Status => admin_plan(RhiCliAdminOperationV1::Status),
        RhiCommandV1::Metrics(RhiMetricsCommandV1::Snapshot) => {
            admin_plan(RhiCliAdminOperationV1::MetricsSnapshot)
        }
        RhiCommandV1::Reconciliation(RhiReconciliationCommandV1::Status) => {
            admin_plan(RhiCliAdminOperationV1::ReconciliationStatus)
        }
        RhiCommandV1::Reconciliation(RhiReconciliationCommandV1::Jobs(_)) => {
            admin_plan(RhiCliAdminOperationV1::ReconciliationJobs)
        }
        RhiCommandV1::Reconciliation(RhiReconciliationCommandV1::Refresh(_)) => {
            admin_plan(RhiCliAdminOperationV1::ReconciliationRefresh)
        }
        RhiCommandV1::Sources(RhiSourcesCommandV1::List(_)) => {
            admin_plan(RhiCliAdminOperationV1::Sources)
        }
        RhiCommandV1::Trade(RhiTradeCommandV1::Projection(_)) => {
            admin_plan(RhiCliAdminOperationV1::TradeProjection)
        }
        RhiCommandV1::Trade(RhiTradeCommandV1::ReportCurrent(_)) => {
            admin_plan(RhiCliAdminOperationV1::TradeReportCurrent)
        }
        RhiCommandV1::Trade(RhiTradeCommandV1::Reports(_)) => {
            admin_plan(RhiCliAdminOperationV1::TradeReports)
        }
        RhiCommandV1::Publication(RhiPublicationCommandV1::Backlog(_)) => {
            admin_plan(RhiCliAdminOperationV1::PublicationBacklog)
        }
        RhiCommandV1::Publication(RhiPublicationCommandV1::Targets(_)) => {
            admin_plan(RhiCliAdminOperationV1::PublicationTargets)
        }
        RhiCommandV1::Publication(RhiPublicationCommandV1::Retry(_)) => {
            admin_plan(RhiCliAdminOperationV1::PublicationRetry)
        }
        RhiCommandV1::Presence(RhiPresenceCommandV1::Desired) => {
            admin_plan(RhiCliAdminOperationV1::PresenceDesired)
        }
        RhiCommandV1::Presence(RhiPresenceCommandV1::Render(_)) => {
            admin_plan(RhiCliAdminOperationV1::PresenceRender)
        }
        RhiCommandV1::Presence(RhiPresenceCommandV1::Refresh(_)) => {
            admin_plan(RhiCliAdminOperationV1::PresenceRefresh)
        }
        RhiCommandV1::Doctor => offline_plan(RhiCliOfflineOperationV1::Doctor),
    }
}

const fn daemon_plan() -> RhiCliExecutionPlanV1 {
    RhiCliExecutionPlanV1 {
        primary_authority: RhiCliPrimaryAuthorityV1::Daemon,
        offline_operation: None,
        admin_operation: None,
    }
}

const fn offline_plan(operation: RhiCliOfflineOperationV1) -> RhiCliExecutionPlanV1 {
    RhiCliExecutionPlanV1 {
        primary_authority: RhiCliPrimaryAuthorityV1::Offline,
        offline_operation: Some(operation),
        admin_operation: None,
    }
}

const fn admin_plan(operation: RhiCliAdminOperationV1) -> RhiCliExecutionPlanV1 {
    RhiCliExecutionPlanV1 {
        primary_authority: RhiCliPrimaryAuthorityV1::LiveUnixAdmin,
        offline_operation: None,
        admin_operation: Some(operation),
    }
}

fn validate_bootstrap_paths(
    profile: RhiBootstrapProfileV1,
    repo_local_root: Option<&Path>,
    config_path: Option<&Path>,
) -> Result<(), RhiCliV1Error> {
    match (profile, repo_local_root) {
        (RhiBootstrapProfileV1::RepoLocal, Some(root)) if valid_absolute_path(root, true) => {}
        (RhiBootstrapProfileV1::RepoLocal, _) => {
            return Err(RhiCliV1Error::new(RhiCliV1ErrorKind::InvalidRepoLocalRoot));
        }
        (_, Some(_)) => {
            return Err(RhiCliV1Error::new(
                RhiCliV1ErrorKind::UnexpectedRepoLocalRoot,
            ));
        }
        (_, None) => {}
    }

    if config_path.is_some_and(|path| !valid_absolute_path(path, true)) {
        return Err(RhiCliV1Error::new(RhiCliV1ErrorKind::InvalidConfigPath));
    }
    Ok(())
}

fn valid_absolute_path(path: &Path, require_non_root: bool) -> bool {
    path.is_absolute()
        && (!require_non_root || path.parent().is_some())
        && path
            .to_str()
            .is_some_and(|value| !value.is_empty() && value.len() <= 4_096)
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

#[derive(Parser)]
#[command(name = "rhi", disable_help_subcommand = true)]
struct RawRhiCliV1 {
    #[arg(long, global = true, value_enum)]
    profile: Option<RawProfile>,
    #[arg(long, global = true)]
    instance: Option<String>,
    #[arg(long = "repo-local-root", global = true)]
    repo_local_root: Option<PathBuf>,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true, value_enum, default_value_t = RawOutputMode::Human)]
    output: RawOutputMode,
    #[command(subcommand)]
    command: RawCommand,
}

#[derive(Clone, Copy, ValueEnum)]
enum RawProfile {
    ServiceHost,
    Interactive,
    RepoLocal,
}

impl From<RawProfile> for RhiBootstrapProfileV1 {
    fn from(value: RawProfile) -> Self {
        match value {
            RawProfile::ServiceHost => Self::ServiceHost,
            RawProfile::Interactive => Self::Interactive,
            RawProfile::RepoLocal => Self::RepoLocal,
        }
    }
}

#[derive(Clone, Copy, Default, ValueEnum)]
enum RawOutputMode {
    #[default]
    Human,
    Json,
}

impl From<RawOutputMode> for RhiCliOutputModeV1 {
    fn from(value: RawOutputMode) -> Self {
        match value {
            RawOutputMode::Human => Self::Human,
            RawOutputMode::Json => Self::Json,
        }
    }
}

#[derive(Subcommand)]
enum RawCommand {
    Run,
    Config {
        #[command(subcommand)]
        command: RawConfigCommand,
    },
    State {
        #[command(subcommand)]
        command: RawStateCommand,
    },
    Identity {
        #[command(subcommand)]
        command: RawIdentityCommand,
    },
    Status,
    Metrics {
        #[command(subcommand)]
        command: RawMetricsCommand,
    },
    Reconciliation {
        #[command(subcommand)]
        command: RawReconciliationCommand,
    },
    Sources {
        #[command(subcommand)]
        command: RawSourcesCommand,
    },
    Trade {
        #[command(subcommand)]
        command: RawTradeCommand,
    },
    Publication {
        #[command(subcommand)]
        command: RawPublicationCommand,
    },
    Presence {
        #[command(subcommand)]
        command: RawPresenceCommand,
    },
    Doctor,
}

macro_rules! command_enum {
    ($raw:ident, $public:ident, { $($variant:ident),+ $(,)? }) => {
        #[derive(Subcommand)]
        enum $raw {
            $($variant),+
        }

        impl From<$raw> for $public {
            fn from(value: $raw) -> Self {
                match value {
                    $($raw::$variant => Self::$variant),+
                }
            }
        }
    };
}

#[derive(Subcommand)]
enum RawConfigCommand {
    Init,
    Validate,
    Show,
    Schema,
    Apply {
        #[arg(long = "candidate-config")]
        candidate_config: PathBuf,
    },
}

#[derive(Subcommand)]
enum RawStateCommand {
    Init,
    Status,
    Backup {
        #[arg(long = "operation-id")]
        operation_id: String,
        #[arg(long)]
        target: PathBuf,
        #[arg(long = "expected-generation")]
        expected_generation: u64,
        #[arg(long, required = true)]
        confirm: bool,
    },
    Restore {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long = "manifest-sha256")]
        manifest_sha256: String,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long = "maximum-state-bytes")]
        maximum_state_bytes: u64,
        #[arg(long, required = true)]
        confirm: bool,
    },
    Verify,
    Migrate,
}

command_enum!(RawIdentityCommand, RhiIdentityCommandV1, {
    Init,
    Status,
    ExportPublic,
});
command_enum!(RawMetricsCommand, RhiMetricsCommandV1, { Snapshot });

#[derive(Subcommand)]
enum RawReconciliationCommand {
    Status,
    Jobs {
        #[command(flatten)]
        page: RawPageQuery,
    },
    Refresh {
        #[arg(long = "operation-id")]
        operation_id: String,
        #[arg(long = "trade-id")]
        trade_id: String,
        #[arg(long = "expected-dirty-generation")]
        expected_dirty_generation: u64,
    },
}

#[derive(Subcommand)]
enum RawSourcesCommand {
    List {
        #[command(flatten)]
        page: RawPageQuery,
    },
}

#[derive(Subcommand)]
enum RawTradeCommand {
    Projection {
        #[arg(long = "trade-id")]
        trade_id: String,
    },
    ReportCurrent {
        #[arg(long = "trade-id")]
        trade_id: String,
    },
    Reports {
        #[arg(long = "trade-id")]
        trade_id: String,
        #[command(flatten)]
        page: RawPageQuery,
    },
}

#[derive(Subcommand)]
enum RawPublicationCommand {
    Backlog {
        #[command(flatten)]
        page: RawPageQuery,
    },
    Targets {
        #[command(flatten)]
        page: RawPageQuery,
    },
    Retry {
        #[arg(long = "operation-id")]
        operation_id: String,
        #[arg(long = "workflow-id")]
        workflow_id: String,
        #[arg(long = "expected-generation")]
        expected_generation: u64,
    },
}

#[derive(Subcommand)]
enum RawPresenceCommand {
    Desired,
    Render {
        #[arg(long = "operation-id")]
        operation_id: String,
        #[arg(long = "expected-generation")]
        expected_generation: u64,
    },
    Refresh {
        #[arg(long = "operation-id")]
        operation_id: String,
        #[arg(long = "expected-generation")]
        expected_generation: u64,
    },
}

#[derive(clap::Args)]
struct RawPageQuery {
    #[arg(long, default_value_t = 100)]
    limit: u16,
    #[arg(long)]
    cursor: Option<String>,
}

fn admit_command(command: RawCommand) -> Result<RhiCommandV1, RhiCliV1Error> {
    let invalid = || RhiCliV1Error::new(RhiCliV1ErrorKind::InvalidCommandInput);
    let page = |value: RawPageQuery| {
        if !(1..=200).contains(&value.limit)
            || value.cursor.as_deref().is_some_and(|cursor| {
                cursor.is_empty()
                    || cursor.len() > 512
                    || cursor != cursor.trim()
                    || cursor.chars().any(char::is_control)
            })
        {
            return Err(invalid());
        }
        Ok(RhiPageQueryArgsV1 {
            limit: value.limit,
            cursor: value.cursor.map(String::into_boxed_str),
        })
    };
    let bounded_id = |value: String| {
        if value.is_empty()
            || value.len() > 128
            || value != value.trim()
            || value.chars().any(char::is_control)
        {
            Err(invalid())
        } else {
            Ok(value.into_boxed_str())
        }
    };
    let trade_id = |value: String| match radroots_event::id::TradeId::parse(&value) {
        Ok(parsed) if parsed.to_hex() == value => Ok(value.into_boxed_str()),
        Ok(_) | Err(_) => Err(invalid()),
    };
    Ok(match command {
        RawCommand::Run => RhiCommandV1::Run,
        RawCommand::Config { command } => RhiCommandV1::Config(match command {
            RawConfigCommand::Init => RhiConfigCommandV1::Init,
            RawConfigCommand::Validate => RhiConfigCommandV1::Validate,
            RawConfigCommand::Show => RhiConfigCommandV1::Show,
            RawConfigCommand::Schema => RhiConfigCommandV1::Schema,
            RawConfigCommand::Apply { candidate_config }
                if valid_absolute_path(&candidate_config, true) =>
            {
                RhiConfigCommandV1::Apply(RhiConfigApplyArgsV1 { candidate_config })
            }
            RawConfigCommand::Apply { .. } => return Err(invalid()),
        }),
        RawCommand::State { command } => RhiCommandV1::State(match command {
            RawStateCommand::Init => RhiStateCommandV1::Init,
            RawStateCommand::Status => RhiStateCommandV1::Status,
            RawStateCommand::Backup {
                operation_id,
                target,
                expected_generation,
                confirm: true,
            } if valid_absolute_path(&target, true) => {
                RhiStateCommandV1::Backup(RhiStateBackupArgsV1 {
                    operation_id: bounded_id(operation_id)?,
                    target,
                    expected_generation,
                })
            }
            RawStateCommand::Backup { .. } => return Err(invalid()),
            RawStateCommand::Restore {
                manifest,
                manifest_sha256,
                bundle,
                maximum_state_bytes,
                confirm: true,
            } if valid_absolute_path(&manifest, true)
                && valid_absolute_path(&bundle, true)
                && maximum_state_bytes != 0
                && is_lower_hex(&manifest_sha256, 64) =>
            {
                RhiStateCommandV1::Restore(RhiStateRestoreArgsV1 {
                    manifest,
                    manifest_sha256: manifest_sha256.into_boxed_str(),
                    bundle,
                    maximum_state_bytes,
                })
            }
            RawStateCommand::Restore { .. } => return Err(invalid()),
            RawStateCommand::Verify => RhiStateCommandV1::Verify,
            RawStateCommand::Migrate => RhiStateCommandV1::Migrate,
        }),
        RawCommand::Identity { command } => RhiCommandV1::Identity(command.into()),
        RawCommand::Status => RhiCommandV1::Status,
        RawCommand::Metrics { command } => RhiCommandV1::Metrics(command.into()),
        RawCommand::Reconciliation { command } => RhiCommandV1::Reconciliation(match command {
            RawReconciliationCommand::Status => RhiReconciliationCommandV1::Status,
            RawReconciliationCommand::Jobs { page: value } => {
                RhiReconciliationCommandV1::Jobs(page(value)?)
            }
            RawReconciliationCommand::Refresh {
                operation_id,
                trade_id: selected_trade,
                expected_dirty_generation,
            } => RhiReconciliationCommandV1::Refresh(RhiReconciliationRefreshArgsV1 {
                operation_id: bounded_id(operation_id)?,
                trade_id: trade_id(selected_trade)?,
                expected_dirty_generation,
            }),
        }),
        RawCommand::Sources { command } => RhiCommandV1::Sources(match command {
            RawSourcesCommand::List { page: value } => RhiSourcesCommandV1::List(page(value)?),
        }),
        RawCommand::Trade { command } => RhiCommandV1::Trade(match command {
            RawTradeCommand::Projection { trade_id: value } => {
                RhiTradeCommandV1::Projection(RhiTradeArgsV1 {
                    trade_id: trade_id(value)?,
                })
            }
            RawTradeCommand::ReportCurrent { trade_id: value } => {
                RhiTradeCommandV1::ReportCurrent(RhiTradeArgsV1 {
                    trade_id: trade_id(value)?,
                })
            }
            RawTradeCommand::Reports {
                trade_id: value,
                page: selected_page,
            } => RhiTradeCommandV1::Reports(RhiTradePageArgsV1 {
                trade_id: trade_id(value)?,
                page: page(selected_page)?,
            }),
        }),
        RawCommand::Publication { command } => RhiCommandV1::Publication(match command {
            RawPublicationCommand::Backlog { page: value } => {
                RhiPublicationCommandV1::Backlog(page(value)?)
            }
            RawPublicationCommand::Targets { page: value } => {
                RhiPublicationCommandV1::Targets(page(value)?)
            }
            RawPublicationCommand::Retry {
                operation_id,
                workflow_id,
                expected_generation,
            } => RhiPublicationCommandV1::Retry(RhiPublicationRetryArgsV1 {
                operation_id: bounded_id(operation_id)?,
                workflow_id: bounded_id(workflow_id)?,
                expected_generation,
            }),
        }),
        RawCommand::Presence { command } => RhiCommandV1::Presence(match command {
            RawPresenceCommand::Desired => RhiPresenceCommandV1::Desired,
            RawPresenceCommand::Render {
                operation_id,
                expected_generation,
            } => RhiPresenceCommandV1::Render(RhiPresenceMutationArgsV1 {
                operation_id: bounded_id(operation_id)?,
                expected_generation,
            }),
            RawPresenceCommand::Refresh {
                operation_id,
                expected_generation,
            } => RhiPresenceCommandV1::Refresh(RhiPresenceMutationArgsV1 {
                operation_id: bounded_id(operation_id)?,
                expected_generation,
            }),
        }),
        RawCommand::Doctor => RhiCommandV1::Doctor,
    })
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(command: &[&str]) -> Result<RhiCliInvocationV1, RhiCliV1Error> {
        let mut arguments = vec!["rhi", "--profile", "service-host", "--instance", "default"];
        arguments.extend_from_slice(command);
        parse_rhi_cli_v1_from(arguments)
    }

    #[test]
    fn exact_command_inventory_parses() {
        let trade = "00000000000000000000000000000000";
        let vectors = [
            vec!["run"],
            vec!["config", "init"],
            vec!["config", "validate"],
            vec!["config", "show"],
            vec!["config", "schema"],
            vec![
                "config",
                "apply",
                "--candidate-config",
                "/tmp/candidate.toml",
            ],
            vec!["state", "init"],
            vec!["state", "status"],
            vec![
                "state",
                "backup",
                "--operation-id",
                "backup-1",
                "--target",
                "/tmp/backup",
                "--expected-generation",
                "1",
                "--confirm",
            ],
            vec![
                "state",
                "restore",
                "--manifest",
                "/tmp/manifest.json",
                "--manifest-sha256",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--bundle",
                "/tmp/backup",
                "--maximum-state-bytes",
                "1048576",
                "--confirm",
            ],
            vec!["state", "verify"],
            vec!["state", "migrate"],
            vec!["identity", "init"],
            vec!["identity", "status"],
            vec!["identity", "export-public"],
            vec!["status"],
            vec!["metrics", "snapshot"],
            vec!["reconciliation", "status"],
            vec!["reconciliation", "jobs"],
            vec![
                "reconciliation",
                "refresh",
                "--operation-id",
                "refresh-1",
                "--trade-id",
                trade,
                "--expected-dirty-generation",
                "1",
            ],
            vec!["sources", "list"],
            vec!["trade", "projection", "--trade-id", trade],
            vec!["trade", "report-current", "--trade-id", trade],
            vec!["trade", "reports", "--trade-id", trade],
            vec!["publication", "backlog"],
            vec!["publication", "targets"],
            vec![
                "publication",
                "retry",
                "--operation-id",
                "retry-1",
                "--workflow-id",
                "workflow-1",
                "--expected-generation",
                "1",
            ],
            vec!["presence", "desired"],
            vec![
                "presence",
                "render",
                "--operation-id",
                "render-1",
                "--expected-generation",
                "1",
            ],
            vec![
                "presence",
                "refresh",
                "--operation-id",
                "presence-1",
                "--expected-generation",
                "1",
            ],
            vec!["doctor"],
        ];
        for arguments in vectors {
            parse(&arguments).expect("command");
        }
    }

    #[test]
    fn profiles_paths_and_output_are_cross_bound() {
        for profile in ["service-host", "interactive"] {
            let invocation = parse_rhi_cli_v1_from([
                "rhi",
                "--profile",
                profile,
                "--instance",
                "north-01",
                "--config",
                "/etc/radroots/rhi.toml",
                "--output",
                "json",
                "run",
            ])
            .expect("host profile");
            assert_eq!(invocation.instance().as_str(), "north-01");
            assert_eq!(
                invocation.config_path(),
                Some(Path::new("/etc/radroots/rhi.toml"))
            );
            assert_eq!(invocation.output_mode(), RhiCliOutputModeV1::Json);
            assert!(invocation.repo_local_root().is_none());
        }

        let repo_local = parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "repo-local",
            "--instance",
            "dev",
            "--repo-local-root",
            "/repo/radroots",
            "config",
            "validate",
        ])
        .expect("repo local");
        assert_eq!(repo_local.profile(), RhiBootstrapProfileV1::RepoLocal);
        assert_eq!(
            repo_local.repo_local_root(),
            Some(Path::new("/repo/radroots"))
        );
        assert_eq!(repo_local.output_mode(), RhiCliOutputModeV1::Human);
    }

    #[test]
    fn invalid_bootstrap_values_fail_with_stable_kinds() {
        for value in ["Upper", "north-", "north.west"] {
            let error = parse_rhi_cli_v1_from([
                "rhi",
                "--profile",
                "service-host",
                "--instance",
                value,
                "run",
            ])
            .expect_err("invalid instance");
            assert_eq!(error.kind(), RhiCliV1ErrorKind::InvalidInstance);
        }

        let exact = "a".repeat(radroots_runtime_paths::INSTANCE_ID_MAX_BYTES);
        assert!(
            parse_rhi_cli_v1_from([
                "rhi",
                "--profile",
                "service-host",
                "--instance",
                exact.as_str(),
                "run",
            ])
            .is_ok()
        );
        let overlong = "a".repeat(radroots_runtime_paths::INSTANCE_ID_MAX_BYTES + 1);
        assert_eq!(
            parse_rhi_cli_v1_from([
                "rhi",
                "--profile",
                "service-host",
                "--instance",
                overlong.as_str(),
                "run",
            ])
            .expect_err("overlong instance")
            .kind(),
            RhiCliV1ErrorKind::InvalidInstance
        );

        assert_eq!(
            parse_rhi_cli_v1_from(["rhi", "--profile", "repo-local", "--instance", "dev", "run"])
                .expect_err("missing root")
                .kind(),
            RhiCliV1ErrorKind::InvalidRepoLocalRoot
        );
        assert_eq!(
            parse_rhi_cli_v1_from([
                "rhi",
                "--profile",
                "interactive",
                "--instance",
                "dev",
                "--repo-local-root",
                "/repo/radroots",
                "run",
            ])
            .expect_err("unexpected root")
            .kind(),
            RhiCliV1ErrorKind::UnexpectedRepoLocalRoot
        );
        for invalid in ["relative", "/", "/repo/../escape"] {
            assert_eq!(
                parse_rhi_cli_v1_from([
                    "rhi",
                    "--profile",
                    "repo-local",
                    "--instance",
                    "dev",
                    "--repo-local-root",
                    invalid,
                    "run",
                ])
                .expect_err("invalid root")
                .kind(),
                RhiCliV1ErrorKind::InvalidRepoLocalRoot
            );
        }
        for invalid in ["relative.toml", "/", "/etc/../secret.toml"] {
            assert_eq!(
                parse_rhi_cli_v1_from([
                    "rhi",
                    "--profile",
                    "service-host",
                    "--instance",
                    "default",
                    "--config",
                    invalid,
                    "run",
                ])
                .expect_err("invalid config")
                .kind(),
                RhiCliV1ErrorKind::InvalidConfigPath
            );
        }
    }

    #[test]
    fn removed_and_unknown_inputs_fail_without_sources() {
        for arguments in [
            vec!["rhi", "run"],
            vec!["rhi", "--profile", "service-host", "run"],
            vec!["rhi", "--profile", "service-host", "--instance", "default"],
            vec![
                "rhi",
                "--profile",
                "production",
                "--instance",
                "default",
                "run",
            ],
            vec![
                "rhi",
                "--profile",
                "service-host",
                "--instance",
                "default",
                "--identity",
                "/secret",
                "run",
            ],
            vec![
                "rhi",
                "--profile",
                "service-host",
                "--instance",
                "default",
                "--allow-generate-identity",
                "run",
            ],
            vec![
                "rhi",
                "--profile",
                "service-host",
                "--instance",
                "default",
                "--logs-dir",
                "/tmp/logs",
                "run",
            ],
            vec![
                "rhi",
                "--profile",
                "service-host",
                "--instance",
                "default",
                "--worker",
                "legacy",
                "run",
            ],
            vec![
                "rhi",
                "--profile",
                "service-host",
                "--instance",
                "default",
                "identity",
                "rekey",
            ],
            vec![
                "rhi",
                "--profile",
                "service-host",
                "--instance",
                "default",
                "identity",
                "replace",
            ],
        ] {
            let failure = parse_rhi_cli_v1_from(arguments).expect_err("arguments must fail");
            assert_eq!(failure.kind(), RhiCliV1ErrorKind::InvalidArguments);
            assert!(Error::source(&failure).is_none());
        }
    }

    #[test]
    fn debug_and_errors_do_not_render_caller_values() {
        let instance = "sensitive-instance";
        let config = "/sensitive/config.toml";
        let invocation = parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "service-host",
            "--instance",
            instance,
            "--config",
            config,
            "doctor",
        ])
        .expect("invocation");
        let debug = format!("{invocation:?}");
        assert!(!debug.contains(instance));
        assert!(!debug.contains(config));

        let secret = "secret-cli-value";
        let failure =
            parse_rhi_cli_v1_from(["rhi", "--profile", secret, "--instance", "default", "run"])
                .expect_err("invalid profile");
        let rendered = format!("{failure} {failure:?}");
        assert!(!rendered.contains(secret));
        assert!(Error::source(&failure).is_none());
    }
}
