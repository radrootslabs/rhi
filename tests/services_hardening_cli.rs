#![forbid(unsafe_code)]

use std::error::Error;
use std::path::Path;

use rhi::{
    INSTANCE_ID_MAX_BYTES, RhiBootstrapProfileV1, RhiCliOutputModeV1, RhiCliV1ErrorKind,
    RhiCommandV1, RhiConfigCommandV1, RhiIdentityCommandV1, RhiMetricsCommandV1,
    RhiPresenceCommandV1, RhiPublicationCommandV1, RhiReconciliationCommandV1, RhiSourcesCommandV1,
    RhiStateCommandV1, RhiTradeCommandV1, parse_rhi_cli_v1_from,
};

fn parse(command: &[&str]) -> rhi::RhiCliInvocationV1 {
    let mut arguments = vec!["rhi", "--profile", "service-host", "--instance", "default"];
    arguments.extend_from_slice(command);
    parse_rhi_cli_v1_from(arguments).expect("governed command")
}

#[test]
fn root_api_exposes_the_complete_closed_command_inventory() {
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
        assert_eq!(parse(arguments).command(), expected);
    }
}

#[test]
fn bootstrap_values_are_explicit_bounded_and_cross_bound() {
    let repo = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        "repo-local",
        "--instance",
        "review_01",
        "--repo-local-root",
        "/repo/radroots",
        "--config",
        "/repo/config/rhi.toml",
        "--output",
        "json",
        "doctor",
    ])
    .expect("repo-local invocation");
    assert_eq!(repo.profile(), RhiBootstrapProfileV1::RepoLocal);
    assert_eq!(repo.instance().as_str(), "review_01");
    assert_eq!(repo.repo_local_root(), Some(Path::new("/repo/radroots")));
    assert_eq!(repo.config_path(), Some(Path::new("/repo/config/rhi.toml")));
    assert_eq!(repo.output_mode(), RhiCliOutputModeV1::Json);

    let exact = "a".repeat(INSTANCE_ID_MAX_BYTES);
    assert!(
        parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "interactive",
            "--instance",
            exact.as_str(),
            "run",
        ])
        .is_ok()
    );
    let over = "a".repeat(INSTANCE_ID_MAX_BYTES + 1);
    assert_eq!(
        parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "interactive",
            "--instance",
            over.as_str(),
            "run",
        ])
        .expect_err("overlong instance")
        .kind(),
        RhiCliV1ErrorKind::InvalidInstance
    );

    let exact_path = format!("/{}", "a".repeat(4_095));
    assert_eq!(exact_path.len(), 4_096);
    assert!(
        parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "interactive",
            "--instance",
            "default",
            "--config",
            exact_path.as_str(),
            "run",
        ])
        .is_ok()
    );
    let overlong_path = format!("{exact_path}a");
    assert_eq!(
        parse_rhi_cli_v1_from([
            "rhi",
            "--profile",
            "interactive",
            "--instance",
            "default",
            "--config",
            overlong_path.as_str(),
            "run",
        ])
        .expect_err("overlong path")
        .kind(),
        RhiCliV1ErrorKind::InvalidConfigPath
    );
}

#[test]
fn prototype_and_unsafe_commands_are_absent_and_errors_are_safe() {
    for arguments in [
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
            "--identity",
            "/secret/identity",
            "run",
        ],
        vec![
            "rhi",
            "--profile",
            "service-host",
            "--instance",
            "default",
            "--state-path",
            "/tmp/state",
            "run",
        ],
        vec![
            "rhi",
            "--profile",
            "service-host",
            "--instance",
            "default",
            "--worker",
            "rhi",
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
        vec![
            "rhi",
            "--profile",
            "service-host",
            "--instance",
            "default",
            "attestation-smoke",
        ],
    ] {
        let failure = parse_rhi_cli_v1_from(arguments).expect_err("removed surface");
        assert_eq!(failure.kind(), RhiCliV1ErrorKind::InvalidArguments);
        assert!(Error::source(&failure).is_none());
    }

    let secret = "never-render-cli-secret";
    let failure =
        parse_rhi_cli_v1_from(["rhi", "--profile", secret, "--instance", "default", "run"])
            .expect_err("secret profile");
    assert!(!format!("{failure} {failure:?}").contains(secret));
}
