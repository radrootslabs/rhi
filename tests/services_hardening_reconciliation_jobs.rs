#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{error::Error, fs, os::unix::fs::PermissionsExt, path::Path};

use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiReconciliationJobErrorKind,
    RhiReconciliationJobPolicy, RhiReconciliationJobState, RhiReconciliationLeaseOwner,
    RhiReconciliationRetryDelayMilliseconds, RhiReconciliationUnixMilliseconds, RhiRuntimeContext,
    RhiStateMetadata, TradeId, initialize_rhi_state, open_rhi_state_inspection,
    open_rhi_state_read_write, parse_rhi_cli_v1_from, parse_rhi_config_v1,
    resolve_rhi_runtime_context,
};
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

fn runtime(root: &Path, instance: &str) -> RhiRuntimeContext {
    let invocation = parse_rhi_cli_v1_from([
        "rhi",
        "--profile",
        "repo-local",
        "--instance",
        instance,
        "--repo-local-root",
        root.to_str().expect("UTF-8 temporary root"),
        "run",
    ])
    .expect("runtime invocation");
    resolve_rhi_runtime_context(
        &RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default()),
        &invocation,
    )
    .expect("runtime context")
}

fn metadata(runtime: &RhiRuntimeContext) -> RhiStateMetadata {
    let config = parse_rhi_config_v1(EXAMPLE.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
        .expect("configuration");
    RhiStateMetadata::new(
        runtime,
        &config,
        SourceGeneration::new([0x5a; 32]).expect("generation"),
        1_725_000_000_000,
    )
    .expect("metadata")
}

fn migration_evidence() -> (MigrationAppliedAtUnixSeconds, MigrationBuildIdentity) {
    (
        MigrationAppliedAtUnixSeconds::new(1_725_000_000).expect("time"),
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
        .expect("build"),
    )
}

async fn initialize(runtime: &RhiRuntimeContext, metadata: &RhiStateMetadata) {
    fs::create_dir_all(runtime.context().paths().state()).expect("state directory");
    fs::set_permissions(
        runtime.context().paths().state(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("state permissions");
    let (applied_at, build) = migration_evidence();
    initialize_rhi_state(runtime, metadata, applied_at, &build)
        .await
        .expect("initialize");
}

async fn open_writer(
    runtime: &RhiRuntimeContext,
    metadata: &RhiStateMetadata,
) -> rhi::RhiStateHost {
    let (applied_at, build) = migration_evidence();
    open_rhi_state_read_write(runtime, metadata, applied_at, &build)
        .await
        .expect("writer")
}

async fn write_dirty(
    runtime: &RhiRuntimeContext,
    trade: TradeId,
    generation: u64,
    policy: [u8; 32],
    updated_at_unix_s: u64,
) {
    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .expect("offline fixture connection");
    sqlx::query(
        r#"INSERT INTO trade_dirty_generations (
            trade_id, generation, evidence_policy_sha256, updated_at_unix_s
        ) VALUES (?, ?, ?, ?)
        ON CONFLICT(trade_id) DO UPDATE SET
            generation = excluded.generation,
            evidence_policy_sha256 = excluded.evidence_policy_sha256,
            updated_at_unix_s = excluded.updated_at_unix_s"#,
    )
    .bind(trade.as_bytes().as_slice())
    .bind(i64::try_from(generation).expect("generation"))
    .bind(policy.as_slice())
    .bind(i64::try_from(updated_at_unix_s).expect("time"))
    .execute(&mut connection)
    .await
    .expect("dirty fixture");
    connection.close().await.expect("fixture close");
}

fn policy(
    queue_capacity: u32,
    lease_ms: u64,
    renewal_ms: u64,
    max_attempts: u16,
    initial_backoff_ms: u64,
    maximum_backoff_ms: u64,
) -> RhiReconciliationJobPolicy {
    RhiReconciliationJobPolicy::new(
        queue_capacity,
        lease_ms,
        renewal_ms,
        max_attempts,
        initial_backoff_ms,
        maximum_backoff_ms,
    )
    .expect("policy")
}

fn now(value: u64) -> RhiReconciliationUnixMilliseconds {
    RhiReconciliationUnixMilliseconds::new(value).expect("time")
}

fn owner(byte: u8) -> RhiReconciliationLeaseOwner {
    RhiReconciliationLeaseOwner::from_bytes([byte; 16]).expect("owner")
}

fn delay(value: u64) -> RhiReconciliationRetryDelayMilliseconds {
    RhiReconciliationRetryDelayMilliseconds::new(value).expect("delay")
}

#[tokio::test]
async fn schedule_is_bounded_idempotent_and_uses_the_frozen_job_identity() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "primary");
    let metadata = metadata(&runtime);
    initialize(&runtime, &metadata).await;
    let first_trade = TradeId::from_bytes([0x11; 16]);
    let second_trade = TradeId::from_bytes([0x33; 16]);
    write_dirty(&runtime, first_trade, 1, [0x22; 32], 1_000).await;
    write_dirty(&runtime, second_trade, 1, [0x44; 32], 1_000).await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    let bounded = policy(1, 1_000, 100, 3, 100, 1_000);

    let first = jobs
        .schedule_trade(first_trade, bounded, now(1_000))
        .await
        .expect("first schedule");
    assert!(first.created());
    assert_eq!(first.job().state(), RhiReconciliationJobState::Ready);
    assert_eq!(first.job().input_generation(), 1);
    assert_eq!(first.job().revision(), 1);
    assert_eq!(first.job().next_attempt(), Some(now(1_000)));
    assert_eq!(
        lower_hex(first.job().id().as_bytes()),
        "dc7b98b36fb8e839cba83dd7274f25fc27d021d2b46c2f5ab089ddde591fad02"
    );
    let replay = jobs
        .schedule_trade(first_trade, bounded, now(1_001))
        .await
        .expect("idempotent schedule");
    assert!(!replay.created());
    assert_eq!(replay.job(), first.job());

    let full = jobs
        .schedule_trade(second_trade, bounded, now(1_001))
        .await
        .expect_err("configured queue bound");
    assert_eq!(full.kind(), RhiReconciliationJobErrorKind::QueueFull);
    host.close().await.expect("close");
}

#[tokio::test]
async fn claims_renew_only_when_due_and_expired_leases_are_reclaimed() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "leases");
    let metadata = metadata(&runtime);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x12; 16]);
    write_dirty(&runtime, trade, 1, [0x23; 32], 1_000).await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    jobs.schedule_trade(trade, policy(8, 1_000, 100, 4, 100, 1_000), now(1_000))
        .await
        .expect("schedule");

    let first = jobs
        .claim_next(owner(1), now(1_000))
        .await
        .expect("claim")
        .expect("job");
    assert_eq!(first.job().attempt_count(), 1);
    assert_eq!(first.lease_expires(), now(2_000));
    assert_eq!(first.renewal_due(), now(1_900));
    assert_eq!(
        jobs.renew(first, now(1_899))
            .await
            .expect_err("early renewal")
            .kind(),
        RhiReconciliationJobErrorKind::NotReady
    );
    let renewed = jobs.renew(first, now(1_900)).await.expect("renew");
    assert_eq!(renewed.job().revision(), 3);
    assert_eq!(renewed.lease_expires(), now(2_900));
    assert!(
        jobs.claim_next(owner(2), now(2_899))
            .await
            .expect("no early reclaim")
            .is_none()
    );
    let reclaimed = jobs
        .claim_next(owner(2), now(2_900))
        .await
        .expect("reclaim")
        .expect("expired lease");
    assert_eq!(reclaimed.job().attempt_count(), 2);
    assert_eq!(reclaimed.job().revision(), 4);
    assert_eq!(
        jobs.record_failure(renewed, now(2_900), delay(0))
            .await
            .expect_err("expired lease")
            .kind(),
        RhiReconciliationJobErrorKind::LeaseLost
    );
    assert_eq!(
        jobs.renew(first, now(1_950))
            .await
            .expect_err("stale revision")
            .kind(),
        RhiReconciliationJobErrorKind::LeaseLost
    );
    host.close().await.expect("close");
}

#[tokio::test]
async fn failures_schedule_exact_jitter_and_the_final_attempt_exhausts() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "retry");
    let metadata = metadata(&runtime);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x13; 16]);
    write_dirty(&runtime, trade, 1, [0x24; 32], 1_000).await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    jobs.schedule_trade(trade, policy(8, 1_000, 100, 2, 100, 1_000), now(1_000))
        .await
        .expect("schedule");
    let first = jobs
        .claim_next(owner(3), now(1_000))
        .await
        .expect("claim")
        .expect("job");
    assert_eq!(first.retry_delay_upper_bound(), 100);
    assert_eq!(
        jobs.record_failure(first, now(1_100), delay(101))
            .await
            .expect_err("delay above governed cap")
            .kind(),
        RhiReconciliationJobErrorKind::InvalidInput
    );
    let retry = jobs
        .record_failure(first, now(1_100), delay(100))
        .await
        .expect("retry schedule");
    assert_eq!(retry.state(), RhiReconciliationJobState::Ready);
    assert_eq!(retry.failure_count(), 1);
    assert_eq!(retry.next_attempt(), Some(now(1_200)));
    assert!(
        jobs.claim_next(owner(4), now(1_199))
            .await
            .expect("not due")
            .is_none()
    );
    let second = jobs
        .claim_next(owner(4), now(1_200))
        .await
        .expect("second claim")
        .expect("job");
    assert_eq!(second.retry_delay_upper_bound(), 200);
    let exhausted = jobs
        .record_failure(second, now(1_300), delay(200))
        .await
        .expect("final failure");
    assert_eq!(exhausted.state(), RhiReconciliationJobState::Exhausted);
    assert_eq!(exhausted.attempt_count(), 2);
    assert_eq!(exhausted.failure_count(), 2);
    assert_eq!(exhausted.next_attempt(), None);
    assert!(
        jobs.claim_next(owner(5), now(9_000))
            .await
            .expect("terminal queue")
            .is_none()
    );
    host.close().await.expect("close");
}

#[tokio::test]
async fn an_expired_final_attempt_is_exhausted_instead_of_reclaimed() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "expired-final");
    let metadata = metadata(&runtime);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x18; 16]);
    write_dirty(&runtime, trade, 1, [0x29; 32], 1_000).await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    let job_policy = policy(8, 1_000, 100, 1, 100, 1_000);
    jobs.schedule_trade(trade, job_policy, now(1_000))
        .await
        .expect("schedule");
    jobs.claim_next(owner(10), now(1_000))
        .await
        .expect("claim")
        .expect("job");

    assert!(
        jobs.claim_next(owner(11), now(2_000))
            .await
            .expect("expired final attempt")
            .is_none()
    );
    let retained = jobs
        .schedule_trade(trade, job_policy, now(2_000))
        .await
        .expect("idempotent retained job");
    assert!(!retained.created());
    assert_eq!(retained.job().state(), RhiReconciliationJobState::Exhausted);
    assert_eq!(retained.job().attempt_count(), 1);
    assert_eq!(retained.job().failure_count(), 1);
    host.close().await.expect("close");
}

#[tokio::test]
async fn lease_and_schedule_state_survive_reopen_and_new_generation_supersedes() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "reopen");
    let metadata = metadata(&runtime);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x14; 16]);
    write_dirty(&runtime, trade, 1, [0x25; 32], 1_000).await;
    let job_policy = policy(8, 1_000, 100, 3, 100, 1_000);
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    let first_job = jobs
        .schedule_trade(trade, job_policy, now(1_000))
        .await
        .expect("schedule")
        .job();
    let stale = jobs
        .claim_next(owner(6), now(1_000))
        .await
        .expect("claim")
        .expect("job");
    host.close().await.expect("crash boundary close");

    write_dirty(&runtime, trade, 2, [0x26; 32], 1_001).await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    let newer = jobs
        .schedule_trade(trade, job_policy, now(1_900))
        .await
        .expect("new generation");
    assert!(newer.created());
    assert_eq!(newer.job().input_generation(), 2);
    assert_ne!(newer.job().id(), first_job.id());
    assert_eq!(
        jobs.renew(stale, now(1_900))
            .await
            .expect_err("superseded lease")
            .kind(),
        RhiReconciliationJobErrorKind::LeaseLost
    );
    let claimed = jobs
        .claim_next(owner(7), now(1_900))
        .await
        .expect("claim new")
        .expect("new job");
    assert_eq!(claimed.job().id(), newer.job().id());
    host.close().await.expect("close");
}

#[tokio::test]
async fn concurrent_claims_have_one_winner_and_read_only_state_cannot_mutate() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "concurrent");
    let metadata = metadata(&runtime);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x15; 16]);
    write_dirty(&runtime, trade, 1, [0x27; 32], 1_000).await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    jobs.schedule_trade(trade, policy(8, 1_000, 100, 3, 100, 1_000), now(1_000))
        .await
        .expect("schedule");
    let (left, right) = tokio::join!(
        jobs.claim_next(owner(8), now(1_000)),
        jobs.claim_next(owner(9), now(1_000))
    );
    let winners = [left, right]
        .into_iter()
        .filter_map(|result| result.expect("claim result"))
        .count();
    assert_eq!(winners, 1);
    host.close().await.expect("close");

    let inspection = open_rhi_state_inspection(&runtime, &metadata)
        .await
        .expect("inspection");
    let error = inspection
        .repositories()
        .reconciliation_jobs()
        .schedule_trade(trade, policy(8, 1_000, 100, 3, 100, 1_000), now(2_000))
        .await
        .expect_err("read-only mutation");
    assert_eq!(error.kind(), RhiReconciliationJobErrorKind::InvalidMode);
    inspection.close().await.expect("inspection close");
}

#[test]
fn public_inputs_have_exact_bounds_and_diagnostics_are_redacted() {
    let maximum = RhiReconciliationJobPolicy::new(65_536, 300_000, 150_000, 100, 60_000, 3_600_000)
        .expect("exact maximum policy");
    assert_eq!(maximum.queue_capacity(), 65_536);
    assert_eq!(maximum.lease_duration_milliseconds(), 300_000);
    assert_eq!(maximum.lease_renewal_milliseconds(), 150_000);
    assert_eq!(maximum.max_attempts(), 100);
    assert_eq!(maximum.initial_backoff_milliseconds(), 60_000);
    assert_eq!(maximum.maximum_backoff_milliseconds(), 3_600_000);
    let configuration = parse_rhi_config_v1(EXAMPLE.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
        .expect("configuration");
    let configured = RhiReconciliationJobPolicy::from_configuration(&configuration)
        .expect("configured reconciliation policy");
    assert_eq!(configured.queue_capacity(), 4_096);
    assert_eq!(configured.lease_duration_milliseconds(), 30_000);
    assert_eq!(configured.lease_renewal_milliseconds(), 10_000);
    assert_eq!(configured.max_attempts(), 10);
    assert_eq!(configured.initial_backoff_milliseconds(), 250);
    assert_eq!(configured.maximum_backoff_milliseconds(), 30_000);
    assert!(RhiReconciliationJobPolicy::new(0, 1_000, 100, 1, 1, 1).is_err());
    assert!(RhiReconciliationJobPolicy::new(65_537, 1_000, 100, 1, 1, 1).is_err());
    assert!(RhiReconciliationJobPolicy::new(1, 999, 100, 1, 1, 1).is_err());
    assert!(RhiReconciliationJobPolicy::new(1, 300_001, 100, 1, 1, 1).is_err());
    assert!(RhiReconciliationJobPolicy::new(1, 1_000, 1_000, 1, 1, 1).is_err());
    assert!(RhiReconciliationJobPolicy::new(1, 1_000, 100, 0, 1, 1).is_err());
    assert!(RhiReconciliationJobPolicy::new(1, 1_000, 100, 101, 1, 1).is_err());
    assert!(RhiReconciliationJobPolicy::new(1, 1_000, 100, 1, 0, 1).is_err());
    assert!(RhiReconciliationJobPolicy::new(1, 1_000, 100, 1, 2, 1).is_err());
    assert!(RhiReconciliationUnixMilliseconds::new(i64::MAX as u64).is_ok());
    assert!(RhiReconciliationUnixMilliseconds::new(i64::MAX as u64 + 1).is_err());
    assert!(RhiReconciliationRetryDelayMilliseconds::new(3_600_000).is_ok());
    assert!(RhiReconciliationRetryDelayMilliseconds::new(3_600_001).is_err());
    assert!(RhiReconciliationLeaseOwner::from_bytes([0; 16]).is_err());
    let secret = RhiReconciliationLeaseOwner::from_bytes([0xab; 16]).expect("owner");
    assert_eq!(
        format!("{secret:?}"),
        "RhiReconciliationLeaseOwner([redacted])"
    );
    let error =
        RhiReconciliationJobPolicy::new(0, 1_000, 100, 1, 1, 1).expect_err("invalid policy");
    assert!(Error::source(&error).is_none());
    assert_eq!(error.code(), "reconciliation_job_input_invalid");
    assert!(!format!("{error} {error:?}").contains("65536"));
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
