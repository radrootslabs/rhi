#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::path::Path;

use rhi::{
    INSTANCE_ID_MAX_BYTES, RhiBootstrapProfileV1, RhiCliAdminOperationV1, RhiCliOfflineOperationV1,
    RhiCliOutputModeV1, RhiCliPrimaryAuthorityV1, RhiCliV1ErrorKind, RhiCommandV1,
    RhiConfigCommandV1, RhiIdentityCommandV1, RhiMetricsCommandV1, RhiPresenceCommandV1,
    RhiPublicationCommandV1, RhiReconciliationCommandV1, RhiSourcesCommandV1, RhiStateCommandV1,
    RhiTradeCommandV1, parse_rhi_cli_v1_from, plan_rhi_cli_v1,
};

const CLI_SOURCE: &str = include_str!("../src/cli_v1.rs");
const MAIN_SOURCE: &str = include_str!("../src/main.rs");
const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");

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
fn every_command_has_one_exact_nonforgeable_execution_plan() {
    let vectors = [
        ("run", vec!["run"], "daemon", None, None),
        (
            "config init",
            vec!["config", "init"],
            "offline",
            Some("config"),
            None,
        ),
        (
            "config validate",
            vec!["config", "validate"],
            "offline",
            Some("config"),
            None,
        ),
        (
            "config show",
            vec!["config", "show"],
            "live_unix_admin",
            None,
            Some("/v1/config/effective"),
        ),
        (
            "config schema",
            vec!["config", "schema"],
            "offline",
            Some("config"),
            None,
        ),
        (
            "config apply",
            vec!["config", "apply"],
            "offline",
            Some("config"),
            None,
        ),
        (
            "state init",
            vec!["state", "init"],
            "offline",
            Some("state_exclusive"),
            None,
        ),
        (
            "state status",
            vec!["state", "status"],
            "live_unix_admin",
            None,
            Some("/v1/state/status"),
        ),
        (
            "state backup",
            vec!["state", "backup"],
            "live_unix_admin",
            None,
            Some("/v1/state/backup"),
        ),
        (
            "state restore",
            vec!["state", "restore"],
            "offline",
            Some("state_exclusive"),
            None,
        ),
        (
            "state verify",
            vec!["state", "verify"],
            "offline",
            Some("state_exclusive"),
            None,
        ),
        (
            "state migrate",
            vec!["state", "migrate"],
            "offline",
            Some("state_exclusive"),
            None,
        ),
        (
            "identity init",
            vec!["identity", "init"],
            "offline",
            Some("identity_exclusive"),
            None,
        ),
        (
            "identity status",
            vec!["identity", "status"],
            "live_unix_admin",
            None,
            Some("/v1/identity/status"),
        ),
        (
            "identity export-public",
            vec!["identity", "export-public"],
            "live_unix_admin",
            None,
            Some("/v1/identity/public"),
        ),
        (
            "status",
            vec!["status"],
            "live_unix_admin",
            None,
            Some("/v1/status"),
        ),
        (
            "metrics snapshot",
            vec!["metrics", "snapshot"],
            "live_unix_admin",
            None,
            Some("/v1/metrics/snapshot"),
        ),
        (
            "reconciliation status",
            vec!["reconciliation", "status"],
            "live_unix_admin",
            None,
            Some("/v1/reconciliation/status"),
        ),
        (
            "reconciliation jobs",
            vec!["reconciliation", "jobs"],
            "live_unix_admin",
            None,
            Some("/v1/reconciliation/jobs"),
        ),
        (
            "reconciliation refresh",
            vec!["reconciliation", "refresh"],
            "live_unix_admin",
            None,
            Some("/v1/reconciliation/refresh"),
        ),
        (
            "sources list",
            vec!["sources", "list"],
            "live_unix_admin",
            None,
            Some("/v1/sources"),
        ),
        (
            "trade projection",
            vec!["trade", "projection"],
            "live_unix_admin",
            None,
            Some("/v1/trades/{trade_id}/projection"),
        ),
        (
            "trade report-current",
            vec!["trade", "report-current"],
            "live_unix_admin",
            None,
            Some("/v1/trades/{trade_id}/reports/current"),
        ),
        (
            "trade reports",
            vec!["trade", "reports"],
            "live_unix_admin",
            None,
            Some("/v1/trades/{trade_id}/reports"),
        ),
        (
            "publication backlog",
            vec!["publication", "backlog"],
            "live_unix_admin",
            None,
            Some("/v1/publication/backlog"),
        ),
        (
            "publication targets",
            vec!["publication", "targets"],
            "live_unix_admin",
            None,
            Some("/v1/publication/targets"),
        ),
        (
            "publication retry",
            vec!["publication", "retry"],
            "live_unix_admin",
            None,
            Some("/v1/publication/retry"),
        ),
        (
            "presence desired",
            vec!["presence", "desired"],
            "live_unix_admin",
            None,
            Some("/v1/presence/desired"),
        ),
        (
            "presence render",
            vec!["presence", "render"],
            "live_unix_admin",
            None,
            Some("/v1/presence/render"),
        ),
        (
            "presence refresh",
            vec!["presence", "refresh"],
            "live_unix_admin",
            None,
            Some("/v1/presence/refresh"),
        ),
        ("doctor", vec!["doctor"], "offline", Some("doctor"), None),
    ];
    let contract: serde_json::Value =
        serde_json::from_str(OPERATOR_CONTRACT).expect("operator contract");
    let dispatch = contract
        .get("cli_dispatch")
        .and_then(serde_json::Value::as_object)
        .expect("CLI dispatch contract");
    assert_eq!(
        dispatch.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "commands",
            "live_command_offline_fallback",
            "live_direct_sqlite_access",
            "parse_count",
            "primary_authorities",
        ])
    );
    assert_eq!(dispatch["parse_count"], 1);
    assert_eq!(
        dispatch["primary_authorities"],
        serde_json::json!(["daemon", "offline", "live_unix_admin"])
    );
    assert_eq!(dispatch["live_direct_sqlite_access"], false);
    assert_eq!(dispatch["live_command_offline_fallback"], false);
    let commands = dispatch["commands"].as_array().expect("command inventory");
    assert_eq!(commands.len(), vectors.len());

    for (index, (command, arguments, authority, offline, route)) in vectors.into_iter().enumerate()
    {
        let invocation = parse(&arguments);
        let plan = plan_rhi_cli_v1(&invocation);
        assert_eq!(authority_name(plan.primary_authority()), authority);
        assert_eq!(plan.offline_operation().map(offline_name), offline);
        assert_eq!(plan.admin_operation().map(admin_path), route);

        let row = commands[index].as_object().expect("command row");
        let mut expected_keys = BTreeSet::from(["command", "primary_authority"]);
        if offline.is_some() {
            expected_keys.insert("offline_operation");
        }
        if route.is_some() {
            expected_keys.insert("admin_route");
        }
        assert_eq!(
            row.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected_keys
        );
        assert_eq!(row["command"], command);
        assert_eq!(row["primary_authority"], authority);
        assert_eq!(
            row.get("offline_operation")
                .and_then(serde_json::Value::as_str),
            offline
        );
        assert_eq!(
            row.get("admin_route").and_then(serde_json::Value::as_str),
            route
        );
    }
}

fn authority_name(authority: RhiCliPrimaryAuthorityV1) -> &'static str {
    match authority {
        RhiCliPrimaryAuthorityV1::Daemon => "daemon",
        RhiCliPrimaryAuthorityV1::Offline => "offline",
        RhiCliPrimaryAuthorityV1::LiveUnixAdmin => "live_unix_admin",
    }
}

fn offline_name(operation: RhiCliOfflineOperationV1) -> &'static str {
    match operation {
        RhiCliOfflineOperationV1::Config => "config",
        RhiCliOfflineOperationV1::StateExclusive => "state_exclusive",
        RhiCliOfflineOperationV1::IdentityExclusive => "identity_exclusive",
        RhiCliOfflineOperationV1::Doctor => "doctor",
    }
}

fn admin_path(operation: RhiCliAdminOperationV1) -> &'static str {
    match operation {
        RhiCliAdminOperationV1::Status => "/v1/status",
        RhiCliAdminOperationV1::EffectiveConfig => "/v1/config/effective",
        RhiCliAdminOperationV1::IdentityStatus => "/v1/identity/status",
        RhiCliAdminOperationV1::IdentityPublic => "/v1/identity/public",
        RhiCliAdminOperationV1::StateStatus => "/v1/state/status",
        RhiCliAdminOperationV1::StateBackup => "/v1/state/backup",
        RhiCliAdminOperationV1::MetricsSnapshot => "/v1/metrics/snapshot",
        RhiCliAdminOperationV1::ReconciliationStatus => "/v1/reconciliation/status",
        RhiCliAdminOperationV1::ReconciliationJobs => "/v1/reconciliation/jobs",
        RhiCliAdminOperationV1::ReconciliationRefresh => "/v1/reconciliation/refresh",
        RhiCliAdminOperationV1::Sources => "/v1/sources",
        RhiCliAdminOperationV1::TradeProjection => "/v1/trades/{trade_id}/projection",
        RhiCliAdminOperationV1::TradeReportCurrent => "/v1/trades/{trade_id}/reports/current",
        RhiCliAdminOperationV1::TradeReports => "/v1/trades/{trade_id}/reports",
        RhiCliAdminOperationV1::PublicationBacklog => "/v1/publication/backlog",
        RhiCliAdminOperationV1::PublicationTargets => "/v1/publication/targets",
        RhiCliAdminOperationV1::PublicationRetry => "/v1/publication/retry",
        RhiCliAdminOperationV1::PresenceDesired => "/v1/presence/desired",
        RhiCliAdminOperationV1::PresenceRender => "/v1/presence/render",
        RhiCliAdminOperationV1::PresenceRefresh => "/v1/presence/refresh",
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cli_admin_operations_match_the_complete_governed_route_inventory() {
    assert_eq!(
        [
            RhiCliAdminOperationV1::Status,
            RhiCliAdminOperationV1::EffectiveConfig,
            RhiCliAdminOperationV1::IdentityStatus,
            RhiCliAdminOperationV1::IdentityPublic,
            RhiCliAdminOperationV1::StateStatus,
            RhiCliAdminOperationV1::StateBackup,
            RhiCliAdminOperationV1::MetricsSnapshot,
            RhiCliAdminOperationV1::ReconciliationStatus,
            RhiCliAdminOperationV1::ReconciliationJobs,
            RhiCliAdminOperationV1::ReconciliationRefresh,
            RhiCliAdminOperationV1::Sources,
            RhiCliAdminOperationV1::TradeProjection,
            RhiCliAdminOperationV1::TradeReportCurrent,
            RhiCliAdminOperationV1::TradeReports,
            RhiCliAdminOperationV1::PublicationBacklog,
            RhiCliAdminOperationV1::PublicationTargets,
            RhiCliAdminOperationV1::PublicationRetry,
            RhiCliAdminOperationV1::PresenceDesired,
            RhiCliAdminOperationV1::PresenceRender,
            RhiCliAdminOperationV1::PresenceRefresh,
        ]
        .map(RhiCliAdminOperationV1::route),
        rhi::RhiAdminRoute::ALL
    );
}

#[test]
fn execution_plan_is_safe_and_the_binary_parses_and_plans_once() {
    let invocation = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        "repo-local",
        "--instance",
        "secret-instance",
        "--repo-local-root",
        "/secret/repository",
        "--config",
        "/secret/config.toml",
        "publication",
        "retry",
    ])
    .expect("valid invocation");
    let rendered = format!("{invocation:?} {:?}", plan_rhi_cli_v1(&invocation));
    for forbidden in [
        "secret-instance",
        "/secret/repository",
        "/secret/config.toml",
    ] {
        assert!(!rendered.contains(forbidden));
    }

    assert_eq!(
        MAIN_SOURCE
            .matches("parse_rhi_cli_v1_from(std::env::args_os())")
            .count(),
        1
    );
    assert_eq!(
        MAIN_SOURCE.matches("plan_rhi_cli_v1(&invocation)").count(),
        1
    );
    for source in [CLI_SOURCE, MAIN_SOURCE] {
        for forbidden in ["sqlx::", "RhiStateHost", "open_rhi_state_"] {
            assert!(!source.contains(forbidden), "found `{forbidden}`");
        }
    }
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
