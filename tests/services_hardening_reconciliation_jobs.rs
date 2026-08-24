#![forbid(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use nostr::{Keys, SecretKey};
use radroots_service_host::{
    EntropyError, EntropySource, SystemMonotonicClock, UnixTimeSeconds, WallClock, WallClockError,
};
use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};
use radroots_storage::event::SourceGeneration;
use radroots_transport::BoxFuture;
use rhi::{
    RadrootsHostEnvironment, RadrootsPathResolver, RadrootsPlatform, RhiDecryptedIdentity,
    RhiEncryptedIdentityProvisioningMaterial, RhiEvidenceAttestationSupersession,
    RhiExactPublicationSink, RhiIdentityEnvelopeBinding, RhiPreparedPublicationAttempt,
    RhiPublicationAttemptOutcome, RhiPublicationAuthority, RhiPublicationLeaseOwner,
    RhiPublicationMode, RhiPublicationOutboxState, RhiPublicationRetryDelayMilliseconds,
    RhiPublicationTargetState, RhiPublicationUnixMilliseconds, RhiReconciliationAttemptErrorKind,
    RhiReconciliationAttemptPlan, RhiReconciliationAttemptResults,
    RhiReconciliationAttestationErrorKind, RhiReconciliationCommitErrorKind,
    RhiReconciliationFinalizationCommitErrorKind, RhiReconciliationFinalizationErrorKind,
    RhiReconciliationJobErrorKind, RhiReconciliationJobPolicy, RhiReconciliationJobState,
    RhiReconciliationLease, RhiReconciliationLeaseOwner, RhiReconciliationRetryDelayMilliseconds,
    RhiReconciliationScopePrerequisites, RhiReconciliationSourceReplayPlan,
    RhiReconciliationSourceResult, RhiReconciliationUnixMilliseconds, RhiRuntimeContext,
    RhiStateMetadata, RhiTimeEntropyAdapters, RhiTradeMutationAdmissionLimits,
    RhiTradeMutationAuthoredTimePolicy, RhiTradeMutationObservedAtUnixSeconds,
    RhiTradeSourceCompletion, TradeId, admit_rhi_trade_mutation_event,
    build_rhi_signed_evidence_attestation, initialize_rhi_state, open_rhi_state_inspection,
    open_rhi_state_read_write, parse_rhi_cli_v1_from, parse_rhi_config_v1,
    provision_rhi_encrypted_identity, reduce_rhi_reconciliation_manifest,
    resolve_rhi_runtime_context, resolve_rhi_wrapping_credential,
};
use sha2::{Digest, Sha256};
use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const TRADE_VECTOR: &str =
    include_str!("../contracts/conformance/vectors/trade_ingest_proposal.v1.json");
const SIGNED_ATTESTATION_VECTOR: &str = include_str!(
    "../contracts/conformance/vectors/reconciliation_attestation_signed_event.v1.json"
);

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
    metadata_from_config(runtime, &config)
}

fn metadata_from_config(
    runtime: &RhiRuntimeContext,
    config: &rhi::RhiConfigDocumentV1,
) -> RhiStateMetadata {
    RhiStateMetadata::new(
        runtime,
        config,
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

fn configured_policy(configuration: &rhi::RhiConfigDocumentV1) -> RhiReconciliationJobPolicy {
    RhiReconciliationJobPolicy::from_configuration(configuration).expect("configured job policy")
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

#[tokio::test]
async fn attempt_plan_binds_the_exact_claim_policy_sources_and_frozen_identities() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "attempt-plan");
    let configuration = parse_rhi_config_v1(EXAMPLE.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
        .expect("configuration");
    let metadata = metadata_from_config(&runtime, &configuration);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x11; 16]);
    write_dirty(
        &runtime,
        trade,
        1,
        *metadata.evidence_policy_digest().as_bytes(),
        1_000,
    )
    .await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    jobs.schedule_trade(trade, configured_policy(&configuration), now(1_000))
        .await
        .expect("schedule");
    let lease = jobs
        .claim_next(owner(0x71), now(1_000))
        .await
        .expect("claim")
        .expect("job");

    let plan = RhiReconciliationAttemptPlan::from_claim(lease, &configuration, now(1_000))
        .expect("attempt plan");
    assert_eq!(plan.job_id(), lease.job().id());
    assert_eq!(plan.input_generation(), 1);
    assert_eq!(
        plan.evidence_policy_digest(),
        metadata.evidence_policy_digest()
    );
    assert_eq!(plan.attempt_started_at(), now(1_000));
    assert_eq!(plan.deadline(), now(31_000));
    assert_eq!(
        lower_hex(plan.job_id().as_bytes()),
        "4e5ecfbee585698c6a67202b30487249291b446909b16a95fd8ae729c7d51e85"
    );
    assert_eq!(
        lower_hex(plan.id().as_bytes()),
        "89b61ce985d6f11ed963a0d96a05b80e8961a16749a122010d33e1aaee04fdeb"
    );
    let [request] = plan.requests() else {
        panic!("exact source inventory")
    };
    assert_eq!(request.source_id(), "trade-primary");
    assert_eq!(request.trade_id(), trade);
    assert!(request.required());
    assert_eq!(request.attempt_started_at(), now(1_000));
    assert_eq!(request.deadline(), now(11_000));
    assert_eq!(request.lookback_seconds(), 86_400);
    assert_eq!(request.maximum_events(), 4_096);
    assert_eq!(request.maximum_bytes(), 8_388_608);
    assert_eq!(
        lower_hex(request.selector_digest().as_bytes()),
        "2c489c22515b4db784f1be9ab2c224b578c8d28e95d3921ade420b6aa78345bd"
    );
    assert_eq!(
        lower_hex(request.id().as_bytes()),
        "ef58f9e8a61f7964734cf0c2aabe0bdb2cbdcec529b16f40ae18ec224d0c896d"
    );
    let replay =
        RhiReconciliationSourceReplayPlan::from_request(&plan, request, &configuration, None)
            .expect("replay plan");
    assert_eq!(replay.overlap_seconds(), 300);
    assert_eq!(replay.since_unix_seconds(), 0);
    assert_eq!(
        lower_hex(replay.id().as_bytes()),
        "2490a2e9a6e85051e92f6c2fc2ff7e98a1367afd6c26f8625eb421cd2ab30c68"
    );
    host.close().await.expect("close");
}

#[tokio::test]
async fn attempt_plan_rejects_policy_mismatch_and_expired_claim_time() {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "attempt-policy");
    let configuration = parse_rhi_config_v1(EXAMPLE.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
        .expect("configuration");
    let metadata = metadata_from_config(&runtime, &configuration);
    initialize(&runtime, &metadata).await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    let governed_policy = configured_policy(&configuration);

    let mismatch_trade = TradeId::from_bytes([0x61; 16]);
    write_dirty(&runtime, mismatch_trade, 1, [0x62; 32], 1_000).await;
    jobs.schedule_trade(mismatch_trade, governed_policy, now(1_000))
        .await
        .expect("schedule mismatch");
    let mismatch = jobs
        .claim_next(owner(0x63), now(1_000))
        .await
        .expect("claim mismatch")
        .expect("job");
    assert_eq!(
        RhiReconciliationAttemptPlan::from_claim(mismatch, &configuration, now(1_000))
            .expect_err("policy mismatch")
            .kind(),
        RhiReconciliationAttemptErrorKind::PolicyMismatch
    );

    let scheduling_mismatch_trade = TradeId::from_bytes([0x69; 16]);
    write_dirty(
        &runtime,
        scheduling_mismatch_trade,
        1,
        *metadata.evidence_policy_digest().as_bytes(),
        1_001,
    )
    .await;
    jobs.schedule_trade(
        scheduling_mismatch_trade,
        policy(8, 30_000, 10_000, 3, 250, 30_000),
        now(1_001),
    )
    .await
    .expect("schedule with mismatched job policy");
    let scheduling_mismatch = jobs
        .claim_next(owner(0x6a), now(1_001))
        .await
        .expect("claim scheduling mismatch")
        .expect("job");
    assert_eq!(
        RhiReconciliationAttemptPlan::from_claim(scheduling_mismatch, &configuration, now(1_001),)
            .expect_err("job policy mismatch")
            .kind(),
        RhiReconciliationAttemptErrorKind::PolicyMismatch
    );

    let expired_trade = TradeId::from_bytes([0x64; 16]);
    write_dirty(
        &runtime,
        expired_trade,
        1,
        *metadata.evidence_policy_digest().as_bytes(),
        1_002,
    )
    .await;
    jobs.schedule_trade(expired_trade, governed_policy, now(1_002))
        .await
        .expect("schedule expired");
    let expired = jobs
        .claim_next(owner(0x65), now(1_002))
        .await
        .expect("claim expired")
        .expect("job");
    assert_eq!(
        RhiReconciliationAttemptPlan::from_claim(expired, &configuration, expired.lease_expires(),)
            .expect_err("expired attempt start")
            .kind(),
        RhiReconciliationAttemptErrorKind::LeaseExpired
    );
    host.close().await.expect("close");
}

#[tokio::test]
async fn reclaimed_attempt_changes_identity_and_caps_deadlines_to_each_lease() {
    let short_lease = EXAMPLE
        .replace("lease_ms = 30000", "lease_ms = 1000")
        .replace("lease_renewal_ms = 10000", "lease_renewal_ms = 100");
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "attempt-reclaim");
    let configuration =
        parse_rhi_config_v1(short_lease.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
            .expect("short-lease configuration");
    let metadata = metadata_from_config(&runtime, &configuration);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x66; 16]);
    write_dirty(
        &runtime,
        trade,
        1,
        *metadata.evidence_policy_digest().as_bytes(),
        1_000,
    )
    .await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    jobs.schedule_trade(trade, configured_policy(&configuration), now(1_000))
        .await
        .expect("schedule");
    let first_lease = jobs
        .claim_next(owner(0x67), now(1_000))
        .await
        .expect("first claim")
        .expect("job");
    let first = RhiReconciliationAttemptPlan::from_claim(first_lease, &configuration, now(1_000))
        .expect("first plan");
    assert_eq!(first.deadline(), now(2_000));
    assert_eq!(first.requests()[0].deadline(), now(2_000));
    let later_start =
        RhiReconciliationAttemptPlan::from_claim(first_lease, &configuration, now(1_500))
            .expect("same claim with a later explicit start");
    assert_eq!(later_start.id(), first.id());
    assert_eq!(later_start.requests()[0].deadline(), now(2_000));
    assert_ne!(later_start.requests()[0].id(), first.requests()[0].id());

    let second_lease = jobs
        .claim_next(owner(0x68), now(2_000))
        .await
        .expect("reclaim")
        .expect("job");
    let second = RhiReconciliationAttemptPlan::from_claim(second_lease, &configuration, now(2_000))
        .expect("second plan");
    assert_eq!(second_lease.job().attempt_count(), 2);
    assert_eq!(second.deadline(), now(3_000));
    assert_eq!(second.requests()[0].deadline(), now(3_000));
    assert_ne!(first.id(), second.id());
    assert_ne!(first.requests()[0].id(), second.requests()[0].id());
    assert_eq!(
        first.requests()[0].selector_digest(),
        second.requests()[0].selector_digest()
    );
    host.close().await.expect("close");
}

#[tokio::test]
async fn source_results_enforce_deadline_outcome_and_exact_resource_bounds() {
    let (root, runtime, metadata, configuration, host, plan) =
        attempt_fixture("attempt-results").await;
    let request = &plan.requests()[0];
    let complete = RhiReconciliationSourceResult::new(
        request,
        RhiTradeSourceCompletion::Complete,
        now(1_000),
        now(10_999),
        4_096,
        8_388_608,
    )
    .expect("exact maximum result");
    assert_eq!(complete.request_id(), request.id());
    assert_eq!(complete.outcome().code(), "complete");
    assert_eq!(complete.accepted_event_count(), 4_096);
    assert_eq!(complete.accepted_event_bytes(), 8_388_608);
    assert_eq!(complete.started_at(), now(1_000));
    assert_eq!(complete.finished_at(), now(10_999));

    let timeout = RhiReconciliationSourceResult::new(
        request,
        RhiTradeSourceCompletion::IncompleteTimeout,
        now(1_000),
        now(11_000),
        0,
        0,
    )
    .expect("deadline timeout");
    assert_eq!(timeout.outcome().code(), "incomplete_timeout");
    for outcome in [
        RhiTradeSourceCompletion::IncompleteUnavailable,
        RhiTradeSourceCompletion::IncompleteResourceLimit,
        RhiTradeSourceCompletion::IncompleteUnknown,
        RhiTradeSourceCompletion::Unsupported,
    ] {
        let result =
            RhiReconciliationSourceResult::new(request, outcome, now(1_000), now(1_001), 0, 0)
                .expect("safe incomplete outcome");
        assert_eq!(result.outcome(), outcome);
    }
    for invalid in [
        RhiReconciliationSourceResult::new(
            request,
            RhiTradeSourceCompletion::Complete,
            now(1_000),
            now(11_000),
            0,
            0,
        ),
        RhiReconciliationSourceResult::new(
            request,
            RhiTradeSourceCompletion::IncompleteTimeout,
            now(1_000),
            now(10_999),
            0,
            0,
        ),
        RhiReconciliationSourceResult::new(
            request,
            RhiTradeSourceCompletion::IncompleteTimeout,
            now(11_000),
            now(11_000),
            0,
            0,
        ),
        RhiReconciliationSourceResult::new(
            request,
            RhiTradeSourceCompletion::Complete,
            now(1_000),
            now(1_001),
            4_097,
            8_388_608,
        ),
        RhiReconciliationSourceResult::new(
            request,
            RhiTradeSourceCompletion::Complete,
            now(1_000),
            now(1_001),
            4_096,
            8_388_609,
        ),
        RhiReconciliationSourceResult::new(
            request,
            RhiTradeSourceCompletion::Complete,
            now(1_000),
            now(1_001),
            1,
            0,
        ),
        RhiReconciliationSourceResult::new(
            request,
            RhiTradeSourceCompletion::Unsupported,
            now(1_000),
            now(1_001),
            1,
            1,
        ),
    ] {
        assert_eq!(
            invalid.expect_err("invalid result").kind(),
            RhiReconciliationAttemptErrorKind::InvalidInput
        );
    }

    let exact = RhiReconciliationAttemptResults::new(&plan, [complete]).expect("inventory");
    assert_eq!(exact.attempt_id(), plan.id());
    assert_eq!(exact.results(), [complete]);
    assert_eq!(
        RhiReconciliationAttemptResults::new(&plan, [])
            .expect_err("missing result")
            .kind(),
        RhiReconciliationAttemptErrorKind::ResultInventory
    );
    assert_eq!(
        RhiReconciliationAttemptResults::new(&plan, std::iter::repeat(complete))
            .expect_err("bounded infinite excess")
            .kind(),
        RhiReconciliationAttemptErrorKind::ResultInventory
    );
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));
}

#[tokio::test]
async fn result_inventory_rejects_reordered_configured_sources() {
    let multi_source = EXAMPLE
        .replace(
            "read = false\nwrite = true\nrequired = false",
            "read = true\nwrite = true\nrequired = false",
        )
        .replace(
            "[[evidence.sources]]\nsource_id = \"trade-primary\"",
            "[[evidence.sources]]\nsource_id = \"a-secondary\"\nkind = \"nostr_relay\"\nrelay_id = \"relay-secondary\"\nrequired = false\nselector = \"trade_mutation_lineage_v1\"\ndeadline_ms = 5000\nlookback_seconds = 3600\noverlap_seconds = 60\n\n[[evidence.sources]]\nsource_id = \"trade-primary\"",
        );
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), "attempt-order");
    let configuration =
        parse_rhi_config_v1(multi_source.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
            .expect("multi-source configuration");
    let metadata = metadata_from_config(&runtime, &configuration);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x51; 16]);
    write_dirty(
        &runtime,
        trade,
        1,
        *metadata.evidence_policy_digest().as_bytes(),
        1_000,
    )
    .await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    jobs.schedule_trade(trade, configured_policy(&configuration), now(1_000))
        .await
        .expect("schedule");
    let lease = jobs
        .claim_next(owner(0x52), now(1_000))
        .await
        .expect("claim")
        .expect("job");
    let plan =
        RhiReconciliationAttemptPlan::from_claim(lease, &configuration, now(1_000)).expect("plan");
    assert_eq!(
        plan.requests()
            .iter()
            .map(|request| request.source_id())
            .collect::<Vec<_>>(),
        ["a-secondary", "trade-primary"]
    );
    let mut results = plan
        .requests()
        .iter()
        .map(|request| {
            RhiReconciliationSourceResult::new(
                request,
                RhiTradeSourceCompletion::Complete,
                now(1_000),
                now(1_001),
                0,
                0,
            )
            .expect("result")
        })
        .collect::<Vec<_>>();
    assert!(RhiReconciliationAttemptResults::new(&plan, results.clone()).is_ok());
    results.reverse();
    assert_eq!(
        RhiReconciliationAttemptResults::new(&plan, results)
            .expect_err("reordered")
            .kind(),
        RhiReconciliationAttemptErrorKind::ResultInventory
    );
    host.close().await.expect("close");
}

#[tokio::test]
async fn attempt_diagnostics_are_redacted_and_source_free() {
    let (root, runtime, metadata, configuration, host, plan) =
        attempt_fixture("attempt-debug").await;
    let request = &plan.requests()[0];
    let result = RhiReconciliationSourceResult::new(
        request,
        RhiTradeSourceCompletion::Complete,
        now(1_000),
        now(1_001),
        1,
        16,
    )
    .expect("result");
    let inventory = RhiReconciliationAttemptResults::new(&plan, [result]).expect("inventory");
    let rendered = format!("{plan:?} {request:?} {result:?} {inventory:?}");
    for secret in [
        &lower_hex(plan.id().as_bytes()),
        &lower_hex(request.id().as_bytes()),
        &lower_hex(request.selector_digest().as_bytes()),
    ] {
        assert!(!rendered.contains(secret));
    }
    let error = RhiReconciliationAttemptResults::new(&plan, []).expect_err("error");
    assert!(Error::source(&error).is_none());
    assert_eq!(
        error.code(),
        "reconciliation_attempt_result_inventory_invalid"
    );
    assert!(!format!("{error} {error:?}").contains("trade-primary"));
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));
}

#[tokio::test]
async fn replay_plan_binds_overlap_deduplicates_and_retains_first_provenance() {
    let started_ms = 1_784_347_200_000;
    let (root, runtime, metadata, configuration, host, _lease, plan) =
        replay_fixture("replay-plan", EXAMPLE, started_ms).await;
    let request = &plan.requests()[0];
    let cursor_plan =
        RhiReconciliationSourceReplayPlan::from_request(&plan, request, &configuration, None)
            .expect("initial cursor plan");
    assert_eq!(cursor_plan.overlap_seconds(), 300);
    assert_eq!(cursor_plan.since_unix_seconds(), 1_784_260_800);
    assert!(cursor_plan.prior_cursor().is_none());

    let wire = replay_wire();
    let replay = cursor_plan
        .finish(
            request,
            RhiTradeSourceCompletion::Complete,
            now(started_ms),
            now(started_ms + 2_000),
            [
                admitted_replay(&configuration, &wire, 1_784_347_201),
                admitted_replay(&configuration, &wire, 1_784_347_200),
            ],
        )
        .expect("canonical replay");
    assert_eq!(replay.accepted_event_count(), 1);
    assert_eq!(
        replay.accepted_original_event_bytes(),
        u64::try_from(wire.len()).expect("wire bytes")
    );
    assert_eq!(replay.duplicate_observation_count(), 1);
    assert_eq!(
        replay.first_observed_at().expect("first provenance").get(),
        1_784_347_200
    );
    assert_eq!(replay.result().accepted_event_count(), 1);
    assert_eq!(
        replay.result().accepted_event_bytes(),
        u64::try_from(wire.len()).expect("wire bytes")
    );
    let cursor = replay.eligible_cursor().expect("eligible cursor");
    assert_eq!(cursor.created_at_unix_seconds(), 1_784_347_200);

    let incomplete =
        RhiReconciliationSourceReplayPlan::from_request(&plan, request, &configuration, None)
            .expect("incomplete plan")
            .finish(
                request,
                RhiTradeSourceCompletion::IncompleteUnavailable,
                now(started_ms),
                now(started_ms + 1_000),
                [admitted_replay(&configuration, &wire, 1_784_347_200)],
            )
            .expect("incomplete replay");
    assert!(incomplete.cursor_candidate().is_some());
    assert!(incomplete.eligible_cursor().is_none());
    assert!(!format!("{replay:?} {incomplete:?}").contains("trade-primary"));
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));
}

#[tokio::test]
async fn source_replay_commit_is_atomic_idempotent_and_mints_durable_cursor_evidence() {
    let started_ms = 1_784_347_200_000;
    let (root, runtime, metadata, configuration, host, lease, plan) =
        replay_fixture("replay-commit", EXAMPLE, started_ms).await;
    let request = &plan.requests()[0];
    let wire = replay_wire();
    let make_replay = || {
        RhiReconciliationSourceReplayPlan::from_request(&plan, request, &configuration, None)
            .expect("replay plan")
            .finish(
                request,
                RhiTradeSourceCompletion::Complete,
                now(started_ms),
                now(started_ms + 2_000),
                [admitted_replay(&configuration, &wire, 1_784_347_200)],
            )
            .expect("replay")
    };
    let first_replay = make_replay();
    let retry_replay = make_replay();
    let early_replay = make_replay();
    let resume_plan = plan.clone();
    let attempts = host.repositories().reconciliation_attempts();
    let committed = attempts
        .commit_source_replays(lease, plan.clone(), [first_replay])
        .await
        .expect("commit");
    assert!(committed.created());
    assert_eq!(committed.source_result_count(), 1);
    assert_eq!(committed.checkpoint_advance_count(), 1);
    assert!(committed.dirty_generation_advanced());
    assert_eq!(committed.committed_cursors().len(), 1);
    assert_eq!(
        committed.committed_cursors()[0]
            .cursor()
            .created_at_unix_seconds(),
        1_784_347_200
    );
    let committed_cursor = committed.committed_cursors()[0].clone();
    let resumed = RhiReconciliationSourceReplayPlan::from_request(
        &resume_plan,
        &resume_plan.requests()[0],
        &configuration,
        Some(committed_cursor),
    )
    .expect("committed cursor resumes exact scope");
    assert_eq!(resumed.since_unix_seconds(), 1_784_346_900);
    let manifest = committed
        .into_evidence_manifest(
            UnixTimeSeconds::new(1_784_347_203),
            RhiReconciliationScopePrerequisites::Satisfied,
        )
        .expect("manifest");
    assert_eq!(manifest.contract_version(), 1);
    assert_eq!(
        manifest.shared_manifest_contract_id(),
        "radroots.trade.evidence-manifest.v1"
    );
    assert_eq!(manifest.shared_manifest_contract_version(), 1);
    assert_eq!(manifest.trade_id(), &TradeId::from_bytes([0x11; 16]));
    assert_eq!(manifest.trade_generation(), 1);
    assert_eq!(manifest.observed_at_unix_seconds(), 1_784_347_203);
    assert_eq!(
        (manifest.source_count(), manifest.observation_count()),
        (1, 1)
    );
    assert_eq!(
        manifest.digest(),
        [
            0x0b, 0x19, 0x3e, 0xd2, 0x93, 0x56, 0xd6, 0x3d, 0x37, 0x31, 0x63, 0x4b, 0x37, 0xfe,
            0x1f, 0x5d, 0x53, 0x21, 0x48, 0x74, 0x79, 0x3d, 0xc2, 0x3f, 0xe4, 0xa3, 0xb9, 0x84,
            0xf8, 0xa4, 0x51, 0xc2,
        ]
    );
    let canonical_manifest = manifest.canonical_bytes().to_vec();
    let projection = reduce_rhi_reconciliation_manifest(manifest).expect("pure projection");
    assert_eq!(projection.contract_version(), 1);
    assert_eq!(
        projection.shared_reducer_contract_id(),
        "radroots.trade.reducer.v1"
    );
    assert_eq!(projection.shared_reducer_contract_version(), 1);
    assert_eq!(projection.trade_id(), &TradeId::from_bytes([0x11; 16]));
    assert_eq!(projection.manifest().canonical_bytes(), canonical_manifest);
    assert!(projection.root_mutation_id().is_some());
    assert_eq!(projection.issue_count(), 0);
    assert_eq!(
        projection.shared_projection_digest(),
        Some([
            0x21, 0xd5, 0xd5, 0xe6, 0x06, 0x7a, 0x13, 0x68, 0xd0, 0xd5, 0x25, 0xa3, 0xec, 0xd1,
            0xb5, 0xcc, 0x99, 0xcb, 0x03, 0xd7, 0xf8, 0x06, 0xe6, 0xba, 0x47, 0xd3, 0xb9, 0x29,
            0x99, 0xa7, 0xe9, 0x61,
        ])
    );
    assert_eq!(
        projection.digest(),
        Some([
            0xd1, 0x33, 0xa7, 0x72, 0xd2, 0x87, 0xa2, 0x56, 0x4a, 0xb3, 0xb3, 0xb2, 0xca, 0xb6,
            0xdc, 0xa6, 0xe5, 0xc5, 0xa0, 0x7f, 0x30, 0x8f, 0x67, 0xc5, 0xee, 0x77, 0x38, 0x06,
            0x40, 0x7a, 0x03, 0x71,
        ])
    );
    let claim = *projection.root_mutation_id().expect("root proposal");
    let evaluation = rhi::evaluate_rhi_reconciliation_claim(projection, claim);
    assert_eq!(evaluation.contract_version(), 1);
    assert_eq!(
        evaluation.coverage(),
        rhi::RhiReconciliationCoverage::ScopeSatisfied
    );
    assert_eq!(
        evaluation.outcome(),
        rhi::RhiReconciliationOutcome::Indeterminate
    );
    assert_eq!(
        evaluation.reason_codes(),
        [rhi::RhiReconciliationReasonCode::AgreementClaimMissing]
    );
    assert_eq!(evaluation.claim_mutation_id(), &claim);
    assert_eq!(
        evaluation.projection().trade_id(),
        &TradeId::from_bytes([0x11; 16])
    );
    let evaluation_debug = format!("{evaluation:?}");
    assert!(!evaluation_debug.contains(&format!("{claim:?}")));
    assert!(!evaluation_debug.contains("d133a772"));
    host.close()
        .await
        .expect("close before lost-success replay");

    let host = open_writer(&runtime, &metadata).await;
    let attempts = host.repositories().reconciliation_attempts();
    let reconciled = attempts
        .commit_source_replays(lease, plan.clone(), [retry_replay])
        .await
        .expect("idempotent reconcile");
    assert!(!reconciled.created());
    assert_eq!(reconciled.source_result_count(), 1);
    assert_eq!(reconciled.checkpoint_advance_count(), 1);
    assert!(!reconciled.dirty_generation_advanced());
    let reconciled_manifest = reconciled
        .into_evidence_manifest(
            UnixTimeSeconds::new(1_784_347_203),
            RhiReconciliationScopePrerequisites::Satisfied,
        )
        .expect("idempotent manifest");
    assert_eq!(reconciled_manifest.canonical_bytes(), canonical_manifest);
    let too_early = attempts
        .commit_source_replays(lease, plan, [early_replay])
        .await
        .expect("second idempotent reconcile")
        .into_evidence_manifest(
            UnixTimeSeconds::new(1_784_347_201),
            RhiReconciliationScopePrerequisites::Unsatisfied,
        )
        .expect_err("observation precedes source completion");
    assert_eq!(
        too_early.kind(),
        rhi::RhiReconciliationManifestErrorKind::InvalidObservationTime
    );
    host.close().await.expect("close");

    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .expect("offline fixture connection");
    let attempt_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM evidence_reconciliations")
        .fetch_one(&mut connection)
        .await
        .expect("attempt count");
    let source_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM evidence_reconciliation_sources")
            .fetch_one(&mut connection)
            .await
            .expect("source count");
    let checkpoint_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relay_checkpoints")
        .fetch_one(&mut connection)
        .await
        .expect("checkpoint count");
    let generation: i64 = sqlx::query_scalar("SELECT generation FROM trade_dirty_generations")
        .fetch_one(&mut connection)
        .await
        .expect("generation");
    assert_eq!(
        (attempt_count, source_count, checkpoint_count, generation),
        (1, 1, 1, 2)
    );
    connection.close().await.expect("fixture close");
    drop((configuration, metadata, runtime, root));
}

#[tokio::test]
async fn concurrent_exact_commits_converge_to_one_attempt_and_one_manifest() {
    let started_ms = 1_784_347_400_000;
    let (root, runtime, metadata, configuration, host, lease, plan) =
        replay_fixture("replay-concurrent-commit", EXAMPLE, started_ms).await;
    let request = &plan.requests()[0];
    let wire = replay_wire();
    let make_replay = || {
        RhiReconciliationSourceReplayPlan::from_request(&plan, request, &configuration, None)
            .expect("replay plan")
            .finish(
                request,
                RhiTradeSourceCompletion::Complete,
                now(started_ms),
                now(started_ms + 2_000),
                [admitted_replay(&configuration, &wire, 1_784_347_400)],
            )
            .expect("replay")
    };
    let left_replay = make_replay();
    let right_replay = make_replay();
    let attempts = host.repositories().reconciliation_attempts();
    let (left, right) = tokio::join!(
        attempts.commit_source_replays(lease, plan.clone(), [left_replay]),
        attempts.commit_source_replays(lease, plan.clone(), [right_replay]),
    );
    let left = left.expect("left exact commit");
    let right = right.expect("right exact commit");
    assert_eq!(u8::from(left.created()) + u8::from(right.created()), 1);
    assert_eq!(
        u8::from(left.dirty_generation_advanced()) + u8::from(right.dirty_generation_advanced()),
        1
    );
    let left = left
        .into_evidence_manifest(
            UnixTimeSeconds::new(1_784_347_403),
            RhiReconciliationScopePrerequisites::Satisfied,
        )
        .expect("left manifest");
    let right = right
        .into_evidence_manifest(
            UnixTimeSeconds::new(1_784_347_403),
            RhiReconciliationScopePrerequisites::Satisfied,
        )
        .expect("right manifest");
    assert_eq!(left.digest(), right.digest());
    assert_eq!(left.canonical_bytes(), right.canonical_bytes());
    host.close().await.expect("close");

    let mut connection = fixture_connection(&runtime).await;
    let counts: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT
            (SELECT COUNT(*) FROM evidence_reconciliations),
            (SELECT COUNT(*) FROM evidence_reconciliation_sources),
            (SELECT generation FROM trade_dirty_generations)"#,
    )
    .fetch_one(&mut connection)
    .await
    .expect("durable converged counts");
    assert_eq!(counts, (1, 1, 2));
    connection.close().await.expect("fixture close");
    drop((configuration, metadata, runtime, root));
}

#[tokio::test]
async fn cancelled_blocked_commit_has_no_effect_and_exact_retry_succeeds() {
    let started_ms = 1_784_347_500_000;
    let (root, runtime, metadata, configuration, host, lease, plan) =
        replay_fixture("replay-cancelled-commit", EXAMPLE, started_ms).await;
    let request = &plan.requests()[0];
    let wire = replay_wire();
    let make_replay = || {
        RhiReconciliationSourceReplayPlan::from_request(&plan, request, &configuration, None)
            .expect("replay plan")
            .finish(
                request,
                RhiTradeSourceCompletion::Complete,
                now(started_ms),
                now(started_ms + 2_000),
                [admitted_replay(&configuration, &wire, 1_784_347_500)],
            )
            .expect("replay")
    };
    let cancelled_replay = make_replay();
    let retry_replay = make_replay();
    let mut blocker = fixture_connection(&runtime).await;
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut blocker)
        .await
        .expect("exclusive SQLite write blocker");

    let attempts = host.repositories().reconciliation_attempts();
    let cancelled = tokio::time::timeout(
        Duration::from_millis(100),
        attempts.commit_source_replays(lease, plan.clone(), [cancelled_replay]),
    )
    .await;
    assert!(cancelled.is_err(), "blocked commit must remain cancellable");
    let attempt_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM evidence_reconciliations")
        .fetch_one(&mut blocker)
        .await
        .expect("no attempt before blocker release");
    assert_eq!(attempt_count, 0);
    sqlx::query("ROLLBACK")
        .execute(&mut blocker)
        .await
        .expect("release blocker");
    blocker.close().await.expect("blocker close");
    tokio::task::yield_now().await;

    let committed = attempts
        .commit_source_replays(lease, plan, [retry_replay])
        .await
        .expect("retry after cancellation");
    assert!(committed.created());
    assert_eq!(committed.source_result_count(), 1);
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));
}

#[tokio::test]
async fn commit_inventory_bounds_infinite_iterators_before_any_mutation() {
    let started_ms = 1_784_347_600_000;
    let (root, runtime, metadata, configuration, host, lease, plan) =
        replay_fixture("replay-bounded-commit", EXAMPLE, started_ms).await;
    let request = &plan.requests()[0];
    let wire = replay_wire();
    let make_replay = || {
        RhiReconciliationSourceReplayPlan::from_request(&plan, request, &configuration, None)
            .expect("replay plan")
            .finish(
                request,
                RhiTradeSourceCompletion::Complete,
                now(started_ms),
                now(started_ms + 2_000),
                [admitted_replay(&configuration, &wire, 1_784_347_600)],
            )
            .expect("replay")
    };
    let exact_replay = make_replay();
    let error = host
        .repositories()
        .reconciliation_attempts()
        .commit_source_replays(lease, plan.clone(), std::iter::repeat_with(make_replay))
        .await
        .expect_err("infinite inventory exceeds the exact source count");
    assert_eq!(error.kind(), RhiReconciliationCommitErrorKind::InvalidInput);

    let committed = host
        .repositories()
        .reconciliation_attempts()
        .commit_source_replays(lease, plan, [exact_replay])
        .await
        .expect("exact bounded retry");
    assert!(committed.created());
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));
}

#[tokio::test]
async fn incomplete_results_never_advance_and_stale_leases_fail_closed() {
    let started_ms = 1_784_347_200_000;
    let (root, runtime, metadata, configuration, host, lease, plan) =
        replay_fixture("replay-incomplete", EXAMPLE, started_ms).await;
    let request = &plan.requests()[0];
    let wire = replay_wire();
    let incomplete =
        RhiReconciliationSourceReplayPlan::from_request(&plan, request, &configuration, None)
            .expect("replay plan")
            .finish(
                request,
                RhiTradeSourceCompletion::IncompleteTimeout,
                now(started_ms),
                now(started_ms + 10_000),
                [admitted_replay(&configuration, &wire, 1_784_347_200)],
            )
            .expect("incomplete replay");
    let committed = host
        .repositories()
        .reconciliation_attempts()
        .commit_source_replays(lease, plan, [incomplete])
        .await
        .expect("incomplete commit");
    assert_eq!(committed.checkpoint_advance_count(), 0);
    assert!(committed.committed_cursors().is_empty());
    assert!(committed.dirty_generation_advanced());
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));

    let started_ms = 1_784_347_300_000;
    let (root, runtime, metadata, configuration, host, lease, plan) =
        replay_fixture("replay-stale-lease", EXAMPLE, started_ms).await;
    let request = &plan.requests()[0];
    let replay =
        RhiReconciliationSourceReplayPlan::from_request(&plan, request, &configuration, None)
            .expect("replay plan")
            .finish(
                request,
                RhiTradeSourceCompletion::Complete,
                now(started_ms),
                now(started_ms + 2_000),
                [],
            )
            .expect("empty replay");
    host.repositories()
        .reconciliation_jobs()
        .renew(lease, now(started_ms + 20_000))
        .await
        .expect("renewed lease");
    let error = host
        .repositories()
        .reconciliation_attempts()
        .commit_source_replays(lease, plan, [replay])
        .await
        .expect_err("stale lease");
    assert_eq!(error.kind(), RhiReconciliationCommitErrorKind::LeaseLost);
    assert!(Error::source(&error).is_none());
    host.close().await.expect("close");
    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .expect("offline fixture connection");
    let attempt_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM evidence_reconciliations")
        .fetch_one(&mut connection)
        .await
        .expect("attempt count");
    let checkpoint_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relay_checkpoints")
        .fetch_one(&mut connection)
        .await
        .expect("checkpoint count");
    let generation: i64 = sqlx::query_scalar("SELECT generation FROM trade_dirty_generations")
        .fetch_one(&mut connection)
        .await
        .expect("generation");
    assert_eq!((attempt_count, checkpoint_count, generation), (0, 0, 1));
    connection.close().await.expect("fixture close");
    drop((configuration, metadata, runtime, root));
}

#[tokio::test]
async fn finalization_preflight_is_exact_nonmutating_and_redacted() {
    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture("finalization-exact").await;
    let before = finalization_snapshot(&runtime).await;
    let fence = host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, now(1_784_347_206_000))
        .await
        .expect("finalization preflight");
    assert_eq!(fence.contract_version(), 1);
    assert_eq!(
        fence
            .evaluation()
            .projection()
            .manifest()
            .trade_generation(),
        2
    );
    assert!(fence.evaluation().projection().digest().is_some());
    let rendered = format!("{fence:?}");
    assert!(!rendered.contains("11111111"));
    assert!(!rendered.contains("reconciliation_attempt"));
    assert_eq!(finalization_snapshot(&runtime).await, before);
    host.close().await.expect("close");
    drop((fence, configuration, metadata, runtime, root));
}

#[tokio::test]
async fn finalization_rejects_stale_generation_policy_and_expired_or_lost_leases() {
    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture("finalization-generation").await;
    write_dirty(
        &runtime,
        lease.job().trade_id(),
        3,
        *lease.job().evidence_policy_digest().as_bytes(),
        1_784_347_207,
    )
    .await;
    let error = host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, now(1_784_347_207_000))
        .await
        .expect_err("stale generation");
    assert_eq!(
        error.kind(),
        RhiReconciliationFinalizationErrorKind::GenerationConflict
    );
    assert!(Error::source(&error).is_none());
    assert!(!format!("{error} {error:?}").contains("11111111"));
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));

    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture("finalization-policy").await;
    write_dirty(
        &runtime,
        lease.job().trade_id(),
        3,
        [0xa5; 32],
        1_784_347_207,
    )
    .await;
    let error = host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, now(1_784_347_207_000))
        .await
        .expect_err("stale policy");
    assert_eq!(
        error.kind(),
        RhiReconciliationFinalizationErrorKind::GenerationConflict
    );
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));

    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture("finalization-expired").await;
    let error = host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, lease.lease_expires())
        .await
        .expect_err("expired lease");
    assert_eq!(
        error.kind(),
        RhiReconciliationFinalizationErrorKind::LeaseLost
    );
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));

    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture("finalization-lost").await;
    host.repositories()
        .reconciliation_jobs()
        .record_failure(
            lease,
            now(1_784_347_206_000),
            RhiReconciliationRetryDelayMilliseconds::new(1).expect("delay"),
        )
        .await
        .expect("release lease");
    let error = host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, now(1_784_347_206_001))
        .await
        .expect_err("lost lease");
    assert_eq!(
        error.kind(),
        RhiReconciliationFinalizationErrorKind::LeaseLost
    );
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));
}

#[tokio::test]
async fn finalization_rejects_cross_attempt_relabelling_and_read_only_hosts() {
    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture("finalization-attempt").await;
    let jobs = host.repositories().reconciliation_jobs();
    jobs.record_failure(
        lease,
        now(1_784_347_206_000),
        RhiReconciliationRetryDelayMilliseconds::new(1).expect("delay"),
    )
    .await
    .expect("retry schedule");
    let next_lease = jobs
        .claim_next(owner(0x93), now(1_784_347_206_001))
        .await
        .expect("next claim")
        .expect("reclaimed job");
    assert_eq!(next_lease.job().attempt_count(), 2);
    let error = host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(next_lease, evaluation, now(1_784_347_206_002))
        .await
        .expect_err("old evaluation cannot be relabelled");
    assert_eq!(
        error.kind(),
        RhiReconciliationFinalizationErrorKind::InvalidInput
    );
    host.close().await.expect("close");
    drop((configuration, metadata, runtime, root));

    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture("finalization-inspection").await;
    host.close().await.expect("close writer");
    let inspection = open_rhi_state_inspection(&runtime, &metadata)
        .await
        .expect("inspection");
    let error = inspection
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, now(1_784_347_206_000))
        .await
        .expect_err("inspection cannot prepare finalization");
    assert_eq!(
        error.kind(),
        RhiReconciliationFinalizationErrorKind::InvalidMode
    );
    inspection.close().await.expect("inspection close");
    drop((configuration, metadata, runtime, root));
}

struct FixedAttestationEntropy(u8);

impl EntropySource for FixedAttestationEntropy {
    fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), EntropyError> {
        destination.fill(self.0);
        Ok(())
    }
}

struct FailingAttestationEntropy;

impl EntropySource for FailingAttestationEntropy {
    fn fill_bytes(&self, _destination: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::Unavailable)
    }
}

#[derive(Clone, Copy)]
struct FixedPublicationWall(u64);

impl WallClock for FixedPublicationWall {
    fn now_utc(&self) -> Result<UnixTimeSeconds, WallClockError> {
        Ok(UnixTimeSeconds::new(self.0))
    }
}

struct RecordingExactPublicationSink {
    expected: Arc<Vec<u8>>,
    calls: Arc<AtomicUsize>,
    outcome: RhiPublicationAttemptOutcome,
}

impl RhiExactPublicationSink for RecordingExactPublicationSink {
    fn submit_exact<'a>(
        &'a self,
        attempt: &'a RhiPreparedPublicationAttempt,
    ) -> BoxFuture<'a, RhiPublicationAttemptOutcome> {
        Box::pin(async move {
            assert_eq!(attempt.exact_signed_event_bytes(), self.expected.as_slice());
            assert_eq!(attempt.relay_id(), "relay-primary");
            assert!(attempt.deadline_at().get() > 0);
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcome
        })
    }
}

struct PendingExactPublicationSink;

impl RhiExactPublicationSink for PendingExactPublicationSink {
    fn submit_exact<'a>(
        &'a self,
        _attempt: &'a RhiPreparedPublicationAttempt,
    ) -> BoxFuture<'a, RhiPublicationAttemptOutcome> {
        Box::pin(std::future::pending())
    }
}

fn publication_now(value: u64) -> RhiPublicationUnixMilliseconds {
    RhiPublicationUnixMilliseconds::new(value).expect("publication time")
}

fn publication_owner(byte: u8) -> RhiPublicationLeaseOwner {
    RhiPublicationLeaseOwner::from_bytes([byte; 16]).expect("publication owner")
}

fn publication_adapters(seconds: u64) -> RhiTimeEntropyAdapters {
    RhiTimeEntropyAdapters::new(
        FixedPublicationWall(seconds),
        SystemMonotonicClock::new(),
        FixedAttestationEntropy(0xff),
    )
}

fn attestation_secret() -> [u8; 32] {
    [1; 32]
}

fn attestation_configuration(runtime: &RhiRuntimeContext, expected_public_key: &str) -> String {
    EXAMPLE
        .replace(
            "/var/lib/radroots/services/rhi/default/secrets/service.identity.ncrypt",
            runtime
                .identity_path()
                .to_str()
                .expect("UTF-8 identity path"),
        )
        .replace(&"2".repeat(64), expected_public_key)
}

fn provision_attestation_identity(
    runtime: &RhiRuntimeContext,
    configuration: &rhi::RhiConfigDocumentV1,
    metadata: &RhiStateMetadata,
) -> RhiDecryptedIdentity {
    fs::create_dir_all(runtime.context().paths().secrets()).expect("secrets directory");
    fs::set_permissions(
        runtime.context().paths().secrets(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("secrets directory mode");
    let credential_path = runtime
        .context()
        .paths()
        .secrets()
        .join("service_wrapping_key");
    fs::write(&credential_path, [0x81; 32]).expect("wrapping credential");
    fs::set_permissions(&credential_path, fs::Permissions::from_mode(0o600))
        .expect("wrapping credential mode");
    let binding = RhiIdentityEnvelopeBinding::from_configuration(configuration, metadata)
        .expect("identity binding");
    let credential =
        resolve_rhi_wrapping_credential(runtime, &binding).expect("wrapping credential open");
    provision_rhi_encrypted_identity(
        &binding,
        &credential,
        RhiEncryptedIdentityProvisioningMaterial::new(
            attestation_secret(),
            [0x42; 32],
            [0x43; 24],
            [0x44; 24],
        )
        .expect("provisioning material"),
    )
    .expect("identity provisioning")
}

#[tokio::test]
async fn signed_attestation_is_canonical_exact_verified_and_nonmutating() {
    let expected_public_key =
        Keys::new(SecretKey::from_slice(&attestation_secret()).expect("identity secret"))
            .public_key()
            .to_hex();
    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture_with_source("attestation-exact", |runtime| {
            attestation_configuration(runtime, &expected_public_key)
        })
        .await;
    let identity = provision_attestation_identity(&runtime, &configuration, &metadata);
    let before = finalization_snapshot(&runtime).await;
    let fence = host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, now(1_784_347_206_000))
        .await
        .expect("finalization fence");
    let signed = build_rhi_signed_evidence_attestation(
        fence,
        &identity,
        UnixTimeSeconds::new(1_784_347_207),
        &FixedAttestationEntropy(0xa5),
        None,
    )
    .expect("signed attestation");

    assert_eq!(signed.contract_version(), 1);
    assert_eq!(signed.created_at_unix_seconds(), 1_784_347_207);
    assert!(!signed.has_supersession());
    assert!(!signed.signed_event_bytes().is_empty());
    assert!(signed.signed_event_bytes().len() <= 32 * 1_024);
    assert_eq!(
        signed.signed_event_sha256(),
        &<[u8; 32]>::from(Sha256::digest(signed.signed_event_bytes()))
    );
    let event: serde_json::Value =
        serde_json::from_slice(signed.signed_event_bytes()).expect("signed event JSON");
    assert_eq!(
        signed.signed_event_bytes(),
        SIGNED_ATTESTATION_VECTOR.trim_end().as_bytes()
    );
    assert_eq!(event["id"], lower_hex(signed.event_id()));
    assert_eq!(event["pubkey"], expected_public_key);
    assert_eq!(event["created_at"], 1_784_347_207_u64);
    assert_eq!(event["kind"], 3_441);
    assert_eq!(event["tags"].as_array().expect("tags").len(), 5);
    assert_eq!(
        event["content"].as_str().expect("content").as_bytes(),
        signed.canonical_report_bytes()
    );
    let report: serde_json::Value =
        serde_json::from_slice(signed.canonical_report_bytes()).expect("canonical report");
    assert_eq!(report["issuer_pubkey"], expected_public_key);
    assert_eq!(report["trade_generation"], 2);
    assert_eq!(report["report_id"], lower_hex(&signed.statement_digest()));
    assert_eq!(report["statement_digest"], report["report_id"]);
    assert!(report["supersedes_report_id"].is_null());
    assert!(report["supersedes_event_id"].is_null());
    let rendered = format!("{signed:?}");
    assert!(!rendered.contains(&lower_hex(signed.event_id())));
    assert!(!rendered.contains(&lower_hex(&signed.statement_digest())));
    assert!(!rendered.contains(&expected_public_key));
    assert_eq!(finalization_snapshot(&runtime).await, before);

    let supersession = RhiEvidenceAttestationSupersession::from_attestation(&signed);
    assert_eq!(
        format!("{supersession:?}"),
        "RhiEvidenceAttestationSupersession([redacted])"
    );
    host.close().await.expect("close");
    drop((
        supersession,
        signed,
        identity,
        configuration,
        metadata,
        runtime,
        root,
    ));
}

#[tokio::test]
async fn signed_attestation_fails_closed_when_injected_entropy_is_unavailable() {
    let expected_public_key =
        Keys::new(SecretKey::from_slice(&attestation_secret()).expect("identity secret"))
            .public_key()
            .to_hex();
    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture_with_source("attestation-entropy", |runtime| {
            attestation_configuration(runtime, &expected_public_key)
        })
        .await;
    let identity = provision_attestation_identity(&runtime, &configuration, &metadata);
    let before = finalization_snapshot(&runtime).await;
    let fence = host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, now(1_784_347_206_000))
        .await
        .expect("finalization fence");
    let error = build_rhi_signed_evidence_attestation(
        fence,
        &identity,
        UnixTimeSeconds::new(1_784_347_207),
        &FailingAttestationEntropy,
        None,
    )
    .expect_err("entropy failure");
    assert_eq!(
        error.kind(),
        RhiReconciliationAttestationErrorKind::EntropyUnavailable
    );
    assert_eq!(
        error.code(),
        "reconciliation_attestation_entropy_unavailable"
    );
    assert!(Error::source(&error).is_none());
    assert!(!format!("{error} {error:?}").contains(&expected_public_key));
    assert_eq!(finalization_snapshot(&runtime).await, before);
    host.close().await.expect("close");
    drop((identity, configuration, metadata, runtime, root));
}

#[tokio::test]
async fn signed_attestation_supersession_is_verified_ordered_and_explicit() {
    let expected_public_key =
        Keys::new(SecretKey::from_slice(&attestation_secret()).expect("identity secret"))
            .public_key()
            .to_hex();
    let (
        prior_root,
        prior_runtime,
        prior_metadata,
        prior_config,
        prior_host,
        prior_lease,
        prior_eval,
    ) = finalization_fixture_with_source_and_generation("attestation-prior", 1, |runtime| {
        attestation_configuration(runtime, &expected_public_key)
    })
    .await;
    let prior_identity =
        provision_attestation_identity(&prior_runtime, &prior_config, &prior_metadata);
    let prior_fence = prior_host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(prior_lease, prior_eval, now(1_784_347_206_000))
        .await
        .expect("prior fence");
    let prior = build_rhi_signed_evidence_attestation(
        prior_fence,
        &prior_identity,
        UnixTimeSeconds::new(1_784_347_207),
        &FixedAttestationEntropy(0xa6),
        None,
    )
    .expect("prior attestation");

    let (next_root, next_runtime, next_metadata, next_config, next_host, next_lease, next_eval) =
        finalization_fixture_with_source_and_generation("attestation-next", 2, |runtime| {
            attestation_configuration(runtime, &expected_public_key)
        })
        .await;
    let next_identity = provision_attestation_identity(&next_runtime, &next_config, &next_metadata);
    let next_fence = next_host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(next_lease, next_eval, now(1_784_347_206_000))
        .await
        .expect("next fence");
    let next = build_rhi_signed_evidence_attestation(
        next_fence,
        &next_identity,
        UnixTimeSeconds::new(1_784_347_208),
        &FixedAttestationEntropy(0xa7),
        Some(RhiEvidenceAttestationSupersession::from_attestation(&prior)),
    )
    .expect("superseding attestation");
    assert!(next.has_supersession());
    let next_event: serde_json::Value =
        serde_json::from_slice(next.signed_event_bytes()).expect("next event");
    assert_eq!(next_event["tags"].as_array().expect("next tags").len(), 7);
    let next_report: serde_json::Value =
        serde_json::from_slice(next.canonical_report_bytes()).expect("next report");
    assert_eq!(
        next_report["supersedes_report_id"],
        lower_hex(&prior.statement_digest())
    );
    assert_eq!(
        next_report["supersedes_event_id"],
        lower_hex(prior.event_id())
    );
    assert_eq!(next_report["trade_generation"], 3);

    let (
        stale_root,
        stale_runtime,
        stale_metadata,
        stale_config,
        stale_host,
        stale_lease,
        stale_eval,
    ) = finalization_fixture_with_source_and_generation("attestation-stale", 1, |runtime| {
        attestation_configuration(runtime, &expected_public_key)
    })
    .await;
    let stale_identity =
        provision_attestation_identity(&stale_runtime, &stale_config, &stale_metadata);
    let stale_fence = stale_host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(stale_lease, stale_eval, now(1_784_347_206_000))
        .await
        .expect("stale fence");
    let error = build_rhi_signed_evidence_attestation(
        stale_fence,
        &stale_identity,
        UnixTimeSeconds::new(1_784_347_209),
        &FixedAttestationEntropy(0xa8),
        Some(RhiEvidenceAttestationSupersession::from_attestation(&next)),
    )
    .expect_err("older generation cannot supersede");
    assert_eq!(
        error.kind(),
        RhiReconciliationAttestationErrorKind::SupersessionInvalid
    );
    assert!(Error::source(&error).is_none());

    prior_host.close().await.expect("prior close");
    next_host.close().await.expect("next close");
    stale_host.close().await.expect("stale close");
    drop((
        prior,
        next,
        prior_identity,
        next_identity,
        stale_identity,
        prior_config,
        next_config,
        stale_config,
        prior_metadata,
        next_metadata,
        stale_metadata,
        prior_runtime,
        next_runtime,
        stale_runtime,
        prior_root,
        next_root,
        stale_root,
    ));
}

#[tokio::test]
async fn atomic_finalization_commits_exact_required_inventory_and_reconciles_retry() {
    let (
        root,
        runtime,
        metadata,
        configuration,
        host,
        lease,
        signed,
        publication,
        manifest,
        _trade,
    ) = signed_finalization_fixture("finalization-commit-required", false).await;
    let repositories = host.repositories();
    let first = repositories
        .reconciliation_attempts()
        .commit_finalization(&signed, &publication, now(1_784_347_208_000))
        .await
        .expect("atomic finalization");
    assert!(first.created());
    assert_eq!(first.publication_mode(), RhiPublicationMode::Required);
    assert_eq!(first.target_count(), 2);
    let outbox_id = first.outbox_id().expect("required outbox identity");
    let committed = repositories
        .publication_outbox()
        .read_committed_publication(outbox_id)
        .await
        .expect("committed exact publication");
    assert_eq!(committed.outbox_id(), outbox_id);
    assert_eq!(committed.event_id(), signed.event_id());
    assert_eq!(committed.event_sha256(), signed.signed_event_sha256());
    assert_eq!(
        committed.exact_signed_event_bytes(),
        signed.signed_event_bytes()
    );
    let committed_debug = format!("{committed:?} {outbox_id:?}");
    assert!(!committed_debug.contains("relay-primary"));
    assert!(!committed_debug.contains("{\"id\""));

    let mut progressed = fixture_connection(&runtime).await;
    let checkpoint = sqlx::query(
        r#"UPDATE relay_checkpoints
SET cursor_created_at_unix_s = cursor_created_at_unix_s + 1,
    cursor_event_id = ?, revision = revision + 1,
    completed_at_unix_s = completed_at_unix_s + 1"#,
    )
    .bind([0xfe; 32].as_slice())
    .execute(&mut progressed)
    .await
    .expect("later checkpoint progression");
    assert_eq!(checkpoint.rows_affected(), 1);
    progressed.close().await.expect("progression close");

    let retry = repositories
        .reconciliation_attempts()
        .commit_finalization(&signed, &publication, lease.lease_expires())
        .await
        .expect("exact retry after consumed lease");
    assert!(!retry.created());
    assert_eq!(retry.publication_mode(), RhiPublicationMode::Required);
    assert_eq!(retry.target_count(), 2);
    assert_eq!(retry.outbox_id(), Some(outbox_id));

    let mut connection = fixture_connection(&runtime).await;
    let counts: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"SELECT
            (SELECT COUNT(*) FROM evidence_manifests),
            (SELECT COUNT(*) FROM trade_projections),
            (SELECT COUNT(*) FROM attestation_reports),
            (SELECT COUNT(*) FROM signed_attestation_events),
            (SELECT COUNT(*) FROM publication_outbox),
            (SELECT COUNT(*) FROM publication_targets),
            (SELECT COUNT(*) FROM reconciliation_jobs WHERE state = 'completed')"#,
    )
    .fetch_one(&mut connection)
    .await
    .expect("final inventory counts");
    assert_eq!(counts, (1, 1, 1, 1, 1, 2, 1));
    let exact: (Vec<u8>, Vec<u8>, Vec<u8>, String, i64) = sqlx::query_as(
        r#"SELECT manifest.canonical_manifest, report.canonical_report,
            event.canonical_event_json, outbox.state, outbox.target_count
FROM evidence_manifests AS manifest
JOIN attestation_reports AS report
    ON report.manifest_sha256 = manifest.manifest_sha256
JOIN signed_attestation_events AS event
    ON event.statement_sha256 = report.statement_sha256
JOIN publication_outbox AS outbox ON outbox.event_id = event.event_id"#,
    )
    .fetch_one(&mut connection)
    .await
    .expect("exact final inventory");
    assert_eq!(exact.0.as_slice(), manifest.as_ref());
    assert_eq!(exact.1.as_slice(), signed.canonical_report_bytes());
    assert_eq!(exact.2.as_slice(), signed.signed_event_bytes());
    assert_eq!(exact.3, "pending");
    assert_eq!(exact.4, 2);
    connection.close().await.expect("fixture close");

    let exact_signed_event_bytes = signed.signed_event_bytes().to_vec();
    host.close().await.expect("host close");
    let inspection = open_rhi_state_inspection(&runtime, &metadata)
        .await
        .expect("reopened inspection");
    let recovered = inspection
        .repositories()
        .publication_outbox()
        .read_committed_publication(outbox_id)
        .await
        .expect("recovered exact publication");
    assert_eq!(
        recovered.exact_signed_event_bytes(),
        exact_signed_event_bytes
    );
    assert_eq!(recovered.event_sha256(), signed.signed_event_sha256());
    inspection.close().await.expect("inspection close");
    drop((
        signed,
        publication,
        manifest,
        configuration,
        metadata,
        runtime,
        root,
    ));
}

#[tokio::test]
async fn exact_byte_publication_persists_submitted_before_io_and_commits_accepted() {
    let (
        root,
        runtime,
        metadata,
        configuration,
        host,
        lease,
        signed,
        publication,
        manifest,
        _trade,
    ) = signed_finalization_fixture("publication-execution-accepted", false).await;
    let repositories = host.repositories();
    let finalized = repositories
        .reconciliation_attempts()
        .commit_finalization(&signed, &publication, now(1_784_347_208_000))
        .await
        .expect("finalization");
    let outbox_id = finalized.outbox_id().expect("outbox");
    let expected = Arc::new(signed.signed_event_bytes().to_vec());
    let calls = Arc::new(AtomicUsize::new(0));
    let sink = RecordingExactPublicationSink {
        expected: Arc::clone(&expected),
        calls: Arc::clone(&calls),
        outcome: RhiPublicationAttemptOutcome::Accepted,
    };
    let outcome = repositories
        .publication_outbox()
        .execute_next_publication(
            publication_owner(0x91),
            &publication_adapters(1_784_347_208),
            &sink,
            &publication,
        )
        .await
        .expect("exact publication")
        .expect("due publication");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(outcome.outbox_id(), outbox_id);
    assert_eq!(outcome.target_ordinal(), 0);
    assert_eq!(outcome.attempt_number(), 1);
    assert_eq!(outcome.outcome(), RhiPublicationAttemptOutcome::Accepted);
    assert_eq!(outcome.target_state(), RhiPublicationTargetState::Accepted);
    assert_eq!(outcome.outbox_state(), RhiPublicationOutboxState::Complete);

    let mut connection = fixture_connection(&runtime).await;
    let durable: (String, i64, String, i64, i64, String, String) = sqlx::query_as(
        r#"SELECT outbox.state, outbox.revision,
            target.state, target.revision, target.attempt_count,
            attempt.outcome, attempt.result_code
FROM publication_outbox AS outbox
JOIN publication_targets AS target ON target.outbox_id = outbox.outbox_id
JOIN publication_attempts AS attempt
    ON attempt.attempt_id = target.last_attempt_id
WHERE outbox.outbox_id = ? AND target.target_ordinal = 0"#,
    )
    .bind(outbox_id.as_bytes().as_slice())
    .fetch_one(&mut connection)
    .await
    .expect("durable publication outcome");
    assert_eq!(
        durable,
        (
            "complete".into(),
            3,
            "accepted".into(),
            3,
            1,
            "accepted".into(),
            "accepted".into()
        )
    );
    let stored: Vec<u8> = sqlx::query_scalar(
        r#"SELECT event.canonical_event_json
FROM publication_outbox AS outbox
JOIN signed_attestation_events AS event ON event.event_id = outbox.event_id
WHERE outbox.outbox_id = ?"#,
    )
    .bind(outbox_id.as_bytes().as_slice())
    .fetch_one(&mut connection)
    .await
    .expect("stored exact bytes");
    assert_eq!(stored, expected.as_ref().clone());
    connection.close().await.expect("fixture close");
    host.close().await.expect("host close");
    drop((
        manifest,
        publication,
        signed,
        lease,
        configuration,
        metadata,
        runtime,
        root,
    ));
}

#[tokio::test]
async fn cancelled_submitted_attempt_recovers_unknown_and_retries_exact_bytes_after_reopen() {
    let (
        root,
        runtime,
        metadata,
        configuration,
        host,
        lease,
        signed,
        publication,
        manifest,
        _trade,
    ) = signed_finalization_fixture("publication-execution-cancel", false).await;
    let repositories = host.repositories();
    let finalized = repositories
        .reconciliation_attempts()
        .commit_finalization(&signed, &publication, now(1_784_347_208_000))
        .await
        .expect("finalization");
    let outbox_id = finalized.outbox_id().expect("outbox");
    let claimed = repositories
        .publication_outbox()
        .claim_next_publication(
            publication_owner(0x92),
            publication_now(1_784_347_208_000),
            &publication,
        )
        .await
        .expect("claim")
        .expect("due outbox");
    let prepared = repositories
        .publication_outbox()
        .prepare_next_publication_target(claimed, publication_now(1_784_347_208_000))
        .await
        .expect("durable submitted");
    assert_eq!(
        prepared.exact_signed_event_bytes(),
        signed.signed_event_bytes()
    );
    let pending = PendingExactPublicationSink.submit_exact(&prepared);
    drop(pending);
    drop(prepared);

    let mut connection = fixture_connection(&runtime).await;
    let submitted: (String, String, i64, i64) = sqlx::query_as(
        r#"SELECT outbox.state, target.state, target.attempt_count,
            (SELECT COUNT(*) FROM publication_attempts)
FROM publication_outbox AS outbox
JOIN publication_targets AS target ON target.outbox_id = outbox.outbox_id
WHERE outbox.outbox_id = ? AND target.target_ordinal = 0"#,
    )
    .bind(outbox_id.as_bytes().as_slice())
    .fetch_one(&mut connection)
    .await
    .expect("submitted state");
    assert_eq!(submitted, ("leased".into(), "submitted".into(), 1, 0));
    connection.close().await.expect("fixture close");
    host.close().await.expect("host close");

    let reopened = open_writer(&runtime, &metadata).await;
    assert!(
        reopened
            .repositories()
            .publication_outbox()
            .recover_one_expired_publication(
                &publication_adapters(1_784_347_224),
                publication_now(1_784_347_224_000),
                &publication,
            )
            .await
            .expect("expired recovery")
    );
    let mut connection = fixture_connection(&runtime).await;
    let recovered: (String, String, i64, String, i64) = sqlx::query_as(
        r#"SELECT outbox.state, target.state, target.attempt_count,
            attempt.outcome, target.next_attempt_unix_ms
FROM publication_outbox AS outbox
JOIN publication_targets AS target ON target.outbox_id = outbox.outbox_id
JOIN publication_attempts AS attempt ON attempt.attempt_id = target.last_attempt_id
WHERE outbox.outbox_id = ? AND target.target_ordinal = 0"#,
    )
    .bind(outbox_id.as_bytes().as_slice())
    .fetch_one(&mut connection)
    .await
    .expect("recovered unknown");
    assert_eq!(recovered.0, "pending");
    assert_eq!(recovered.1, "unknown");
    assert_eq!(recovered.2, 1);
    assert_eq!(recovered.3, "unknown");
    assert!(recovered.4 >= 1_784_347_224_000);
    assert!(recovered.4 <= 1_784_347_224_250);
    connection.close().await.expect("fixture close");

    let expected = Arc::new(signed.signed_event_bytes().to_vec());
    let calls = Arc::new(AtomicUsize::new(0));
    let sink = RecordingExactPublicationSink {
        expected: Arc::clone(&expected),
        calls: Arc::clone(&calls),
        outcome: RhiPublicationAttemptOutcome::Accepted,
    };
    let retried = reopened
        .repositories()
        .publication_outbox()
        .execute_next_publication(
            publication_owner(0x93),
            &publication_adapters(1_784_347_300),
            &sink,
            &publication,
        )
        .await
        .expect("exact retry")
        .expect("retried target");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(retried.attempt_number(), 2);
    assert_eq!(retried.outbox_state(), RhiPublicationOutboxState::Complete);
    reopened.close().await.expect("reopened close");
    drop((
        manifest,
        publication,
        signed,
        lease,
        configuration,
        metadata,
        runtime,
        root,
    ));
}

#[tokio::test]
async fn publication_outcome_commit_is_idempotent_and_inspection_is_nonmutating() {
    let (
        root,
        runtime,
        metadata,
        configuration,
        host,
        lease,
        signed,
        publication,
        manifest,
        _trade,
    ) = signed_finalization_fixture("publication-execution-reconcile", false).await;
    let repositories = host.repositories();
    let finalized = repositories
        .reconciliation_attempts()
        .commit_finalization(&signed, &publication, now(1_784_347_208_000))
        .await
        .expect("finalization");
    let outbox_id = finalized.outbox_id().expect("outbox");
    let claimed = repositories
        .publication_outbox()
        .claim_next_publication(
            publication_owner(0x94),
            publication_now(1_784_347_208_000),
            &publication,
        )
        .await
        .expect("claim")
        .expect("due outbox");
    let prepared = repositories
        .publication_outbox()
        .prepare_next_publication_target(claimed, publication_now(1_784_347_208_000))
        .await
        .expect("prepare");
    let delay = RhiPublicationRetryDelayMilliseconds::new(0).expect("zero delay");
    let first = repositories
        .publication_outbox()
        .record_publication_outcome(
            &prepared,
            publication_now(1_784_347_208_001),
            RhiPublicationAttemptOutcome::Accepted,
            delay,
        )
        .await
        .expect("first commit");
    let retry = repositories
        .publication_outbox()
        .record_publication_outcome(
            &prepared,
            publication_now(1_784_347_208_001),
            RhiPublicationAttemptOutcome::Accepted,
            delay,
        )
        .await
        .expect("reconciled commit");
    assert_eq!(retry, first);
    assert_eq!(retry.outbox_id(), outbox_id);
    host.close().await.expect("host close");

    let inspection = open_rhi_state_inspection(&runtime, &metadata)
        .await
        .expect("inspection");
    let error = inspection
        .repositories()
        .publication_outbox()
        .claim_next_publication(
            publication_owner(0x95),
            publication_now(1_784_347_300_000),
            &publication,
        )
        .await
        .expect_err("inspection cannot claim");
    assert_eq!(
        error.kind(),
        rhi::RhiPublicationExecutionErrorKind::InvalidMode
    );
    inspection.close().await.expect("inspection close");
    drop((
        manifest,
        publication,
        signed,
        lease,
        configuration,
        metadata,
        runtime,
        root,
    ));
}

#[tokio::test]
async fn publication_execution_binds_live_authority_without_mutating_on_mismatch_or_disable() {
    let (
        root,
        runtime,
        metadata,
        configuration,
        host,
        lease,
        signed,
        publication,
        manifest,
        _trade,
    ) = signed_finalization_fixture("publication-execution-authority", false).await;
    let repositories = host.repositories();
    let finalized = repositories
        .reconciliation_attempts()
        .commit_finalization(&signed, &publication, now(1_784_347_208_000))
        .await
        .expect("finalization");
    let outbox_id = finalized.outbox_id().expect("outbox");
    let mut connection = fixture_connection(&runtime).await;
    let before: (String, i64, String, i64, i64) = sqlx::query_as(
        r#"SELECT outbox.state, outbox.revision, target.state,
            target.revision, target.attempt_count
FROM publication_outbox AS outbox
JOIN publication_targets AS target ON target.outbox_id = outbox.outbox_id
WHERE outbox.outbox_id = ? AND target.target_ordinal = 0"#,
    )
    .bind(outbox_id.as_bytes().as_slice())
    .fetch_one(&mut connection)
    .await
    .expect("before authority mismatch");
    connection.close().await.expect("fixture close");

    let changed = EXAMPLE.replacen(
        "attempt_deadline_ms = 15000",
        "attempt_deadline_ms = 14999",
        1,
    );
    let changed = parse_rhi_config_v1(changed.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
        .expect("changed configuration");
    let mismatched = RhiPublicationAuthority::from_config(&changed).expect("changed authority");
    let error = repositories
        .publication_outbox()
        .claim_next_publication(
            publication_owner(0xa1),
            publication_now(1_784_347_208_000),
            &mismatched,
        )
        .await
        .expect_err("mismatched authority");
    assert_eq!(
        error.kind(),
        rhi::RhiPublicationExecutionErrorKind::Invariant
    );

    let publication_offset = EXAMPLE.find("[publication]").expect("publication section");
    let presence_offset = EXAMPLE.find("[presence]").expect("presence section");
    let disabled_source = format!(
        "{}[publication]\nmode = \"disabled\"\n\n{}",
        &EXAMPLE[..publication_offset],
        &EXAMPLE[presence_offset..]
    );
    let disabled =
        parse_rhi_config_v1(disabled_source.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
            .expect("disabled configuration");
    let disabled = RhiPublicationAuthority::from_config(&disabled).expect("disabled authority");
    assert!(
        repositories
            .publication_outbox()
            .claim_next_publication(
                publication_owner(0xa2),
                publication_now(1_784_347_208_000),
                &disabled,
            )
            .await
            .expect("disabled authority")
            .is_none()
    );

    let mut connection = fixture_connection(&runtime).await;
    let after: (String, i64, String, i64, i64) = sqlx::query_as(
        r#"SELECT outbox.state, outbox.revision, target.state,
            target.revision, target.attempt_count
FROM publication_outbox AS outbox
JOIN publication_targets AS target ON target.outbox_id = outbox.outbox_id
WHERE outbox.outbox_id = ? AND target.target_ordinal = 0"#,
    )
    .bind(outbox_id.as_bytes().as_slice())
    .fetch_one(&mut connection)
    .await
    .expect("after authority mismatch");
    assert_eq!(after, before);
    connection.close().await.expect("fixture close");
    host.close().await.expect("host close");
    drop((
        manifest,
        publication,
        signed,
        lease,
        configuration,
        metadata,
        runtime,
        root,
    ));
}

#[tokio::test]
async fn terminal_required_rejection_blocks_the_outbox_without_retry_schedule() {
    let (
        root,
        runtime,
        metadata,
        configuration,
        host,
        lease,
        signed,
        publication,
        manifest,
        _trade,
    ) = signed_finalization_fixture("publication-execution-rejected", false).await;
    let repositories = host.repositories();
    let finalized = repositories
        .reconciliation_attempts()
        .commit_finalization(&signed, &publication, now(1_784_347_208_000))
        .await
        .expect("finalization");
    let expected = Arc::new(signed.signed_event_bytes().to_vec());
    let calls = Arc::new(AtomicUsize::new(0));
    let sink = RecordingExactPublicationSink {
        expected,
        calls: Arc::clone(&calls),
        outcome: RhiPublicationAttemptOutcome::Rejected,
    };
    let committed = repositories
        .publication_outbox()
        .execute_next_publication(
            publication_owner(0xa3),
            &publication_adapters(1_784_347_208),
            &sink,
            &publication,
        )
        .await
        .expect("terminal rejection")
        .expect("due outbox");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(committed.outcome(), RhiPublicationAttemptOutcome::Rejected);
    assert_eq!(
        committed.target_state(),
        RhiPublicationTargetState::Rejected
    );
    assert_eq!(committed.outbox_state(), RhiPublicationOutboxState::Blocked);

    let mut connection = fixture_connection(&runtime).await;
    let durable: (String, Option<i64>, String, Option<i64>) = sqlx::query_as(
        r#"SELECT outbox.state, outbox.next_attempt_unix_ms,
            target.state, target.next_attempt_unix_ms
FROM publication_outbox AS outbox
JOIN publication_targets AS target ON target.outbox_id = outbox.outbox_id
WHERE outbox.outbox_id = ? AND target.target_ordinal = 0"#,
    )
    .bind(finalized.outbox_id().expect("outbox").as_bytes().as_slice())
    .fetch_one(&mut connection)
    .await
    .expect("terminal durable state");
    assert_eq!(durable, ("blocked".into(), None, "rejected".into(), None));
    connection.close().await.expect("fixture close");
    host.close().await.expect("host close");
    drop((
        manifest,
        publication,
        signed,
        lease,
        configuration,
        metadata,
        runtime,
        root,
    ));
}

#[tokio::test]
async fn atomic_finalization_disabled_mode_creates_no_publication_rows() {
    let (
        root,
        runtime,
        metadata,
        configuration,
        host,
        _lease,
        signed,
        publication,
        manifest,
        _trade,
    ) = signed_finalization_fixture("finalization-commit-disabled", true).await;
    let outcome = host
        .repositories()
        .reconciliation_attempts()
        .commit_finalization(&signed, &publication, now(1_784_347_208_000))
        .await
        .expect("disabled finalization");
    assert!(outcome.created());
    assert_eq!(outcome.publication_mode(), RhiPublicationMode::Disabled);
    assert_eq!(outcome.target_count(), 0);
    assert_eq!(outcome.outbox_id(), None);
    let mut connection = fixture_connection(&runtime).await;
    let counts: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT
            (SELECT COUNT(*) FROM signed_attestation_events),
            (SELECT COUNT(*) FROM publication_outbox),
            (SELECT COUNT(*) FROM publication_targets)"#,
    )
    .fetch_one(&mut connection)
    .await
    .expect("disabled counts");
    assert_eq!(counts, (1, 0, 0));
    connection.close().await.expect("fixture close");
    host.close().await.expect("host close");
    drop((
        signed,
        publication,
        manifest,
        configuration,
        metadata,
        runtime,
        root,
    ));
}

#[tokio::test]
async fn atomic_finalization_rejects_configuration_and_generation_drift_without_partial_rows() {
    let (
        root,
        runtime,
        metadata,
        configuration,
        host,
        _lease,
        signed,
        publication,
        manifest,
        trade,
    ) = signed_finalization_fixture("finalization-commit-drift", false).await;
    let changed = attestation_configuration(
        &runtime,
        &Keys::new(SecretKey::from_slice(&attestation_secret()).expect("identity secret"))
            .public_key()
            .to_hex(),
    )
    .replace("samples = 512", "samples = 511");
    let changed = parse_rhi_config_v1(changed.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
        .expect("changed configuration");
    let mismatched = RhiPublicationAuthority::from_config(&changed).expect("changed authority");
    assert_eq!(mismatched, publication);
    let error = host
        .repositories()
        .reconciliation_attempts()
        .commit_finalization(&signed, &mismatched, now(1_784_347_208_000))
        .await
        .expect_err("configuration mismatch");
    assert_eq!(
        error.kind(),
        RhiReconciliationFinalizationCommitErrorKind::InvalidInput
    );

    write_dirty(
        &runtime,
        trade,
        3,
        *metadata.evidence_policy_digest().as_bytes(),
        1_784_347_208,
    )
    .await;
    let error = host
        .repositories()
        .reconciliation_attempts()
        .commit_finalization(&signed, &publication, now(1_784_347_208_001))
        .await
        .expect_err("generation drift");
    assert_eq!(
        error.kind(),
        RhiReconciliationFinalizationCommitErrorKind::GenerationConflict
    );
    let mut connection = fixture_connection(&runtime).await;
    let counts: (i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"SELECT
            (SELECT COUNT(*) FROM evidence_manifests),
            (SELECT COUNT(*) FROM trade_projections),
            (SELECT COUNT(*) FROM attestation_reports),
            (SELECT COUNT(*) FROM signed_attestation_events),
            (SELECT COUNT(*) FROM publication_outbox)"#,
    )
    .fetch_one(&mut connection)
    .await
    .expect("rolled-back inventory");
    assert_eq!(counts, (0, 0, 0, 0, 0));
    connection.close().await.expect("fixture close");
    host.close().await.expect("host close");
    drop((
        signed,
        publication,
        manifest,
        configuration,
        metadata,
        runtime,
        root,
    ));
}

async fn signed_finalization_fixture(
    instance: &str,
    publication_disabled: bool,
) -> (
    tempfile::TempDir,
    RhiRuntimeContext,
    RhiStateMetadata,
    rhi::RhiConfigDocumentV1,
    rhi::RhiStateHost,
    RhiReconciliationLease,
    rhi::RhiSignedEvidenceAttestation,
    RhiPublicationAuthority,
    Box<[u8]>,
    TradeId,
) {
    let expected_public_key =
        Keys::new(SecretKey::from_slice(&attestation_secret()).expect("identity secret"))
            .public_key()
            .to_hex();
    let (root, runtime, metadata, configuration, host, lease, evaluation) =
        finalization_fixture_with_source(instance, |runtime| {
            let source = attestation_configuration(runtime, &expected_public_key);
            if publication_disabled {
                let publication = source.find("[publication]").expect("publication section");
                let presence = source.find("[presence]").expect("presence section");
                format!(
                    "{}[publication]\nmode = \"disabled\"\n\n{}",
                    &source[..publication],
                    &source[presence..]
                )
            } else {
                source
            }
        })
        .await;
    let manifest = evaluation.projection().manifest().canonical_bytes().into();
    let trade = *evaluation.projection().manifest().trade_id();
    let identity = provision_attestation_identity(&runtime, &configuration, &metadata);
    let fence = host
        .repositories()
        .reconciliation_attempts()
        .prepare_finalization(lease, evaluation, now(1_784_347_206_000))
        .await
        .expect("finalization fence");
    let signed = build_rhi_signed_evidence_attestation(
        fence,
        &identity,
        UnixTimeSeconds::new(1_784_347_207),
        &FixedAttestationEntropy(0xb1),
        None,
    )
    .expect("signed attestation");
    let publication =
        RhiPublicationAuthority::from_config(&configuration).expect("publication authority");
    drop(identity);
    (
        root,
        runtime,
        metadata,
        configuration,
        host,
        lease,
        signed,
        publication,
        manifest,
        trade,
    )
}

async fn fixture_connection(runtime: &RhiRuntimeContext) -> SqliteConnection {
    let options = SqliteConnectOptions::new()
        .filename(runtime.artifacts().state_database())
        .create_if_missing(false)
        .foreign_keys(true);
    SqliteConnection::connect_with(&options)
        .await
        .expect("offline fixture connection")
}

async fn finalization_snapshot(
    runtime: &RhiRuntimeContext,
) -> (i64, i64, i64, i64, i64, i64, i64, i64) {
    let mut connection = fixture_connection(runtime).await;
    let row: (i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"SELECT
            (SELECT COUNT(*) FROM reconciliation_jobs),
            (SELECT COUNT(*) FROM reconciliation_jobs WHERE state = 'leased'),
            (SELECT SUM(revision) FROM reconciliation_jobs),
            (SELECT COUNT(*) FROM evidence_reconciliations),
            (SELECT COUNT(*) FROM evidence_reconciliation_sources),
            (SELECT COUNT(*) FROM relay_checkpoints),
            (SELECT generation FROM trade_dirty_generations LIMIT 1),
            (SELECT COUNT(*) FROM sqlite_schema WHERE name IN (
                'evidence_manifests', 'trade_projections', 'attestation_reports',
                'signed_attestation_events', 'publication_outbox'
            ))"#,
    )
    .fetch_one(&mut connection)
    .await
    .expect("finalization snapshot");
    connection.close().await.expect("snapshot close");
    row
}

async fn finalization_fixture(
    instance: &str,
) -> (
    tempfile::TempDir,
    RhiRuntimeContext,
    RhiStateMetadata,
    rhi::RhiConfigDocumentV1,
    rhi::RhiStateHost,
    RhiReconciliationLease,
    rhi::RhiReconciliationEvaluation,
) {
    finalization_fixture_with_source(instance, |_| EXAMPLE.to_owned()).await
}

async fn finalization_fixture_with_source<F>(
    instance: &str,
    source: F,
) -> (
    tempfile::TempDir,
    RhiRuntimeContext,
    RhiStateMetadata,
    rhi::RhiConfigDocumentV1,
    rhi::RhiStateHost,
    RhiReconciliationLease,
    rhi::RhiReconciliationEvaluation,
)
where
    F: FnOnce(&RhiRuntimeContext) -> String,
{
    finalization_fixture_with_source_and_generation(instance, 1, source).await
}

async fn finalization_fixture_with_source_and_generation<F>(
    instance: &str,
    initial_generation: u64,
    source: F,
) -> (
    tempfile::TempDir,
    RhiRuntimeContext,
    RhiStateMetadata,
    rhi::RhiConfigDocumentV1,
    rhi::RhiStateHost,
    RhiReconciliationLease,
    rhi::RhiReconciliationEvaluation,
)
where
    F: FnOnce(&RhiRuntimeContext) -> String,
{
    let started_ms = 1_784_347_200_000;
    let (root, runtime, metadata, configuration, host, first_lease, first_plan) =
        replay_fixture_with_source_and_generation(instance, started_ms, initial_generation, source)
            .await;
    let wire = replay_wire();
    let first_request = &first_plan.requests()[0];
    let first_replay = RhiReconciliationSourceReplayPlan::from_request(
        &first_plan,
        first_request,
        &configuration,
        None,
    )
    .expect("first replay plan")
    .finish(
        first_request,
        RhiTradeSourceCompletion::Complete,
        now(started_ms),
        now(started_ms + 2_000),
        [admitted_replay(&configuration, &wire, 1_784_347_200)],
    )
    .expect("first replay");
    let first = host
        .repositories()
        .reconciliation_attempts()
        .commit_source_replays(first_lease, first_plan, [first_replay])
        .await
        .expect("first commit");
    assert!(first.dirty_generation_advanced());
    let cursor = first.committed_cursors()[0].clone();
    drop(first);

    let jobs = host.repositories().reconciliation_jobs();
    let scheduled = jobs
        .schedule_trade(
            first_lease.job().trade_id(),
            configured_policy(&configuration),
            now(started_ms + 3_000),
        )
        .await
        .expect("schedule final generation");
    assert_eq!(scheduled.job().input_generation(), initial_generation + 1);
    let lease = jobs
        .claim_next(owner(0x92), now(started_ms + 3_000))
        .await
        .expect("claim final generation")
        .expect("final job");
    let plan =
        RhiReconciliationAttemptPlan::from_claim(lease, &configuration, now(started_ms + 3_000))
            .expect("final plan");
    let request = &plan.requests()[0];
    let replay = RhiReconciliationSourceReplayPlan::from_request(
        &plan,
        request,
        &configuration,
        Some(cursor),
    )
    .expect("final replay plan")
    .finish(
        request,
        RhiTradeSourceCompletion::Complete,
        now(started_ms + 3_000),
        now(started_ms + 5_000),
        [admitted_replay(&configuration, &wire, 1_784_347_203)],
    )
    .expect("final replay");
    let committed = host
        .repositories()
        .reconciliation_attempts()
        .commit_source_replays(lease, plan, [replay])
        .await
        .expect("final commit");
    assert!(!committed.dirty_generation_advanced());
    let manifest = committed
        .into_evidence_manifest(
            UnixTimeSeconds::new(1_784_347_206),
            RhiReconciliationScopePrerequisites::Satisfied,
        )
        .expect("final manifest");
    assert_eq!(manifest.trade_generation(), initial_generation + 1);
    let projection = reduce_rhi_reconciliation_manifest(manifest).expect("final projection");
    let claim = *projection.root_mutation_id().expect("root claim");
    let evaluation = rhi::evaluate_rhi_reconciliation_claim(projection, claim);
    (
        root,
        runtime,
        metadata,
        configuration,
        host,
        lease,
        evaluation,
    )
}

async fn attempt_fixture(
    instance: &str,
) -> (
    tempfile::TempDir,
    RhiRuntimeContext,
    RhiStateMetadata,
    rhi::RhiConfigDocumentV1,
    rhi::RhiStateHost,
    RhiReconciliationAttemptPlan,
) {
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), instance);
    let configuration = parse_rhi_config_v1(EXAMPLE.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
        .expect("configuration");
    let metadata = metadata_from_config(&runtime, &configuration);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x41; 16]);
    write_dirty(
        &runtime,
        trade,
        1,
        *metadata.evidence_policy_digest().as_bytes(),
        1_000,
    )
    .await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    jobs.schedule_trade(trade, configured_policy(&configuration), now(1_000))
        .await
        .expect("schedule");
    let lease = jobs
        .claim_next(owner(0x42), now(1_000))
        .await
        .expect("claim")
        .expect("job");
    let plan =
        RhiReconciliationAttemptPlan::from_claim(lease, &configuration, now(1_000)).expect("plan");
    (root, runtime, metadata, configuration, host, plan)
}

async fn replay_fixture(
    instance: &str,
    source: &str,
    started_ms: u64,
) -> (
    tempfile::TempDir,
    RhiRuntimeContext,
    RhiStateMetadata,
    rhi::RhiConfigDocumentV1,
    rhi::RhiStateHost,
    RhiReconciliationLease,
    RhiReconciliationAttemptPlan,
) {
    replay_fixture_with_source(instance, started_ms, |_| source.to_owned()).await
}

async fn replay_fixture_with_source<F>(
    instance: &str,
    started_ms: u64,
    source: F,
) -> (
    tempfile::TempDir,
    RhiRuntimeContext,
    RhiStateMetadata,
    rhi::RhiConfigDocumentV1,
    rhi::RhiStateHost,
    RhiReconciliationLease,
    RhiReconciliationAttemptPlan,
)
where
    F: FnOnce(&RhiRuntimeContext) -> String,
{
    replay_fixture_with_source_and_generation(instance, started_ms, 1, source).await
}

async fn replay_fixture_with_source_and_generation<F>(
    instance: &str,
    started_ms: u64,
    initial_generation: u64,
    source: F,
) -> (
    tempfile::TempDir,
    RhiRuntimeContext,
    RhiStateMetadata,
    rhi::RhiConfigDocumentV1,
    rhi::RhiStateHost,
    RhiReconciliationLease,
    RhiReconciliationAttemptPlan,
)
where
    F: FnOnce(&RhiRuntimeContext) -> String,
{
    let root = tempfile::tempdir().expect("root");
    let runtime = runtime(root.path(), instance);
    let source = source(&runtime);
    let configuration = parse_rhi_config_v1(source.as_bytes(), rhi::RhiConfigProfile::RepoLocal)
        .expect("configuration");
    let metadata = metadata_from_config(&runtime, &configuration);
    initialize(&runtime, &metadata).await;
    let trade = TradeId::from_bytes([0x11; 16]);
    write_dirty(
        &runtime,
        trade,
        initial_generation,
        *metadata.evidence_policy_digest().as_bytes(),
        started_ms / 1_000,
    )
    .await;
    let host = open_writer(&runtime, &metadata).await;
    let jobs = host.repositories().reconciliation_jobs();
    jobs.schedule_trade(trade, configured_policy(&configuration), now(started_ms))
        .await
        .expect("schedule");
    let lease = jobs
        .claim_next(owner(0x72), now(started_ms))
        .await
        .expect("claim")
        .expect("job");
    let plan = RhiReconciliationAttemptPlan::from_claim(lease, &configuration, now(started_ms))
        .expect("plan");
    (root, runtime, metadata, configuration, host, lease, plan)
}

fn replay_wire() -> Vec<u8> {
    serde_json::from_str::<serde_json::Value>(TRADE_VECTOR).expect("trade vector")["raw_json"]
        .as_str()
        .expect("raw event")
        .as_bytes()
        .to_vec()
}

fn admitted_replay(
    configuration: &rhi::RhiConfigDocumentV1,
    wire: &[u8],
    observed_at: u64,
) -> rhi::RhiAdmittedTradeMutationEvent {
    admit_rhi_trade_mutation_event(
        RhiTradeMutationAdmissionLimits::from_config(configuration).expect("admission limits"),
        wire,
        RhiTradeMutationObservedAtUnixSeconds::new(observed_at).expect("observed time"),
        RhiTradeMutationAuthoredTimePolicy::new(0).expect("authored-time policy"),
    )
    .expect("admitted event")
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
