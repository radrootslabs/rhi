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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiConfigCommandV1 {
    Init,
    Validate,
    Show,
    Schema,
    Apply,
}

/// Governed state commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiStateCommandV1 {
    Init,
    Status,
    Backup,
    Restore,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiReconciliationCommandV1 {
    Status,
    Jobs,
    Refresh,
}

/// Governed evidence-source commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiSourcesCommandV1 {
    List,
}

/// Governed trade-query commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiTradeCommandV1 {
    Projection,
    ReportCurrent,
    Reports,
}

/// Governed publication commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiPublicationCommandV1 {
    Backlog,
    Targets,
    Retry,
}

/// Governed desired-presence commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiPresenceCommandV1 {
    Desired,
    Render,
    Refresh,
}

/// Stable source-free classification for command-line admission failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiCliV1ErrorKind {
    InvalidArguments,
    InvalidInstance,
    InvalidRepoLocalRoot,
    UnexpectedRepoLocalRoot,
    InvalidConfigPath,
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
    pub const fn command(&self) -> RhiCommandV1 {
        self.command
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
        command: parsed.command.into(),
    })
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

impl From<RawCommand> for RhiCommandV1 {
    fn from(value: RawCommand) -> Self {
        match value {
            RawCommand::Run => Self::Run,
            RawCommand::Config { command } => Self::Config(command.into()),
            RawCommand::State { command } => Self::State(command.into()),
            RawCommand::Identity { command } => Self::Identity(command.into()),
            RawCommand::Status => Self::Status,
            RawCommand::Metrics { command } => Self::Metrics(command.into()),
            RawCommand::Reconciliation { command } => Self::Reconciliation(command.into()),
            RawCommand::Sources { command } => Self::Sources(command.into()),
            RawCommand::Trade { command } => Self::Trade(command.into()),
            RawCommand::Publication { command } => Self::Publication(command.into()),
            RawCommand::Presence { command } => Self::Presence(command.into()),
            RawCommand::Doctor => Self::Doctor,
        }
    }
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

command_enum!(RawConfigCommand, RhiConfigCommandV1, {
    Init,
    Validate,
    Show,
    Schema,
    Apply,
});
command_enum!(RawStateCommand, RhiStateCommandV1, {
    Init,
    Status,
    Backup,
    Restore,
    Verify,
    Migrate,
});
command_enum!(RawIdentityCommand, RhiIdentityCommandV1, {
    Init,
    Status,
    ExportPublic,
});
command_enum!(RawMetricsCommand, RhiMetricsCommandV1, { Snapshot });
command_enum!(RawReconciliationCommand, RhiReconciliationCommandV1, {
    Status,
    Jobs,
    Refresh,
});
command_enum!(RawSourcesCommand, RhiSourcesCommandV1, { List });
command_enum!(RawTradeCommand, RhiTradeCommandV1, {
    Projection,
    ReportCurrent,
    Reports,
});
command_enum!(RawPublicationCommand, RhiPublicationCommandV1, {
    Backlog,
    Targets,
    Retry,
});
command_enum!(RawPresenceCommand, RhiPresenceCommandV1, {
    Desired,
    Render,
    Refresh,
});

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
        let vectors = [
            (&["run"][..], RhiCommandV1::Run),
            (
                &["config", "init"][..],
                RhiCommandV1::Config(RhiConfigCommandV1::Init),
            ),
            (
                &["config", "validate"][..],
                RhiCommandV1::Config(RhiConfigCommandV1::Validate),
            ),
            (
                &["config", "show"][..],
                RhiCommandV1::Config(RhiConfigCommandV1::Show),
            ),
            (
                &["config", "schema"][..],
                RhiCommandV1::Config(RhiConfigCommandV1::Schema),
            ),
            (
                &["config", "apply"][..],
                RhiCommandV1::Config(RhiConfigCommandV1::Apply),
            ),
            (
                &["state", "init"][..],
                RhiCommandV1::State(RhiStateCommandV1::Init),
            ),
            (
                &["state", "status"][..],
                RhiCommandV1::State(RhiStateCommandV1::Status),
            ),
            (
                &["state", "backup"][..],
                RhiCommandV1::State(RhiStateCommandV1::Backup),
            ),
            (
                &["state", "restore"][..],
                RhiCommandV1::State(RhiStateCommandV1::Restore),
            ),
            (
                &["state", "verify"][..],
                RhiCommandV1::State(RhiStateCommandV1::Verify),
            ),
            (
                &["state", "migrate"][..],
                RhiCommandV1::State(RhiStateCommandV1::Migrate),
            ),
            (
                &["identity", "init"][..],
                RhiCommandV1::Identity(RhiIdentityCommandV1::Init),
            ),
            (
                &["identity", "status"][..],
                RhiCommandV1::Identity(RhiIdentityCommandV1::Status),
            ),
            (
                &["identity", "export-public"][..],
                RhiCommandV1::Identity(RhiIdentityCommandV1::ExportPublic),
            ),
            (&["status"][..], RhiCommandV1::Status),
            (
                &["metrics", "snapshot"][..],
                RhiCommandV1::Metrics(RhiMetricsCommandV1::Snapshot),
            ),
            (
                &["reconciliation", "status"][..],
                RhiCommandV1::Reconciliation(RhiReconciliationCommandV1::Status),
            ),
            (
                &["reconciliation", "jobs"][..],
                RhiCommandV1::Reconciliation(RhiReconciliationCommandV1::Jobs),
            ),
            (
                &["reconciliation", "refresh"][..],
                RhiCommandV1::Reconciliation(RhiReconciliationCommandV1::Refresh),
            ),
            (
                &["sources", "list"][..],
                RhiCommandV1::Sources(RhiSourcesCommandV1::List),
            ),
            (
                &["trade", "projection"][..],
                RhiCommandV1::Trade(RhiTradeCommandV1::Projection),
            ),
            (
                &["trade", "report-current"][..],
                RhiCommandV1::Trade(RhiTradeCommandV1::ReportCurrent),
            ),
            (
                &["trade", "reports"][..],
                RhiCommandV1::Trade(RhiTradeCommandV1::Reports),
            ),
            (
                &["publication", "backlog"][..],
                RhiCommandV1::Publication(RhiPublicationCommandV1::Backlog),
            ),
            (
                &["publication", "targets"][..],
                RhiCommandV1::Publication(RhiPublicationCommandV1::Targets),
            ),
            (
                &["publication", "retry"][..],
                RhiCommandV1::Publication(RhiPublicationCommandV1::Retry),
            ),
            (
                &["presence", "desired"][..],
                RhiCommandV1::Presence(RhiPresenceCommandV1::Desired),
            ),
            (
                &["presence", "render"][..],
                RhiCommandV1::Presence(RhiPresenceCommandV1::Render),
            ),
            (
                &["presence", "refresh"][..],
                RhiCommandV1::Presence(RhiPresenceCommandV1::Refresh),
            ),
            (&["doctor"][..], RhiCommandV1::Doctor),
        ];
        for (arguments, expected) in vectors {
            assert_eq!(parse(arguments).expect("command").command(), expected);
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
