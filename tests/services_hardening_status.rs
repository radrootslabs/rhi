#![forbid(unsafe_code)]

use std::error::Error;

use rhi::{
    InstanceId, RHI_DETAILED_STATUS_MAX_UTF8_BYTES, RHI_STATUS_CACHE_CONTRACT_VERSION,
    RhiEvidenceTransportStatusV1, RhiIdentityHealthV1, RhiIntegrityStateV1, RhiPersistenceHealthV1,
    RhiPersistenceStatusV1, RhiPresenceStatusV1, RhiProviderStatusV1, RhiPublicationStatusV1,
    RhiReconciliationStatusV1, RhiServicePhase, RhiStatusBuildInfoV1, RhiStatusBuildMode,
    RhiStatusCommonV1, RhiStatusConfigurationIdentityV1, RhiStatusConfigurationSource,
    RhiStatusErrorKind, RhiStatusObservationV1, RhiStatusReasonCode, RhiStatusReasonCodes,
    RhiStatusUnixSeconds, RhiTransportHealthV1, rhi_status_cache,
};

const CONTRACT: &str = include_str!("../contracts/services_hardening/status_cache.v1.json");
const SERVICE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const LIB_REVISION: &str = "89abcdef0123456789abcdef0123456789abcdef";

fn reasons(values: &[&str]) -> RhiStatusReasonCodes {
    RhiStatusReasonCodes::new(
        values
            .iter()
            .map(|value| RhiStatusReasonCode::new(value).expect("reason code")),
    )
    .expect("reason codes")
}

fn build_info() -> RhiStatusBuildInfoV1 {
    RhiStatusBuildInfoV1::new(
        RhiStatusBuildMode::Release,
        Some("0.1.0"),
        Some(SERVICE_REVISION),
        Some(LIB_REVISION),
        Some("1.97.1"),
        Some("x86_64-unknown-linux-gnu"),
        Some("service-host"),
    )
    .expect("build info")
}

fn identity(configured: bool, available: bool, reason: &[&str]) -> RhiIdentityHealthV1 {
    RhiIdentityHealthV1::new(configured, available, reasons(reason)).expect("identity health")
}

fn observation(
    phase: RhiServicePhase,
    ready: bool,
    uptime_ms: u64,
    pending_jobs: u64,
) -> RhiStatusObservationV1 {
    let lifecycle_reasons = if phase == RhiServicePhase::Degraded {
        reasons(&["source_unavailable"])
    } else {
        RhiStatusReasonCodes::empty()
    };
    let configuration = RhiStatusConfigurationIdentityV1::new(
        "a".repeat(64),
        RhiStatusConfigurationSource::ExplicitConfig,
    )
    .expect("configuration");
    let persistence = RhiPersistenceStatusV1::new(
        RhiPersistenceHealthV1::Ready,
        10,
        42,
        RhiIntegrityStateV1::Verified,
        RhiStatusReasonCodes::empty(),
    )
    .expect("persistence");
    let provider =
        RhiProviderStatusV1::new(identity(true, true, &[]), RhiStatusReasonCodes::empty())
            .expect("provider");
    let transport = RhiEvidenceTransportStatusV1::new(
        if phase == RhiServicePhase::Degraded {
            RhiTransportHealthV1::Degraded
        } else {
            RhiTransportHealthV1::Ready
        },
        true,
        true,
        2,
        if phase == RhiServicePhase::Degraded {
            1
        } else {
            2
        },
        if phase == RhiServicePhase::Degraded {
            reasons(&["source_unavailable"])
        } else {
            RhiStatusReasonCodes::empty()
        },
    )
    .expect("transport");
    RhiStatusObservationV1::new(
        RhiStatusCommonV1::new(
            phase,
            ready,
            lifecycle_reasons,
            uptime_ms,
            build_info(),
            configuration,
            persistence,
        )
        .expect("common status"),
        provider,
        transport,
        RhiReconciliationStatusV1::new(
            pending_jobs,
            3,
            1,
            Some(RhiStatusUnixSeconds::new(1_723_456_700).expect("job time")),
        ),
        RhiPublicationStatusV1::new(
            4,
            1,
            Some(RhiStatusUnixSeconds::new(1_723_456_789).expect("publication time")),
        ),
        RhiPresenceStatusV1::new(2, 1),
    )
}

#[test]
fn machine_contract_and_canonical_detailed_status_are_exact() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("status contract");
    assert_eq!(contract["schema"], "radroots.rhi.status-cache.v1");
    assert_eq!(
        contract["contract_version"],
        RHI_STATUS_CACHE_CONTRACT_VERSION
    );
    assert_eq!(contract["step"], 212);
    assert_eq!(
        contract["publication"]["capacity"],
        "one_latest_immutable_arc"
    );
    assert_eq!(contract["read"]["fresh_probe"], false);
    assert_eq!(
        contract["detailed_status"]["maximum_utf8_bytes"],
        RHI_DETAILED_STATUS_MAX_UTF8_BYTES
    );
    assert_eq!(
        contract["detailed_status"]["reason_codes"]
            .as_array()
            .expect("reason inventory")
            .iter()
            .map(|value| value.as_str().expect("reason"))
            .collect::<Vec<_>>(),
        [
            RhiStatusReasonCode::IdentityUnavailable,
            RhiStatusReasonCode::DatabaseSchemaMismatch,
            RhiStatusReasonCode::DatabaseReadOnly,
            RhiStatusReasonCode::DatabaseLowDisk,
            RhiStatusReasonCode::SourceUnavailable,
            RhiStatusReasonCode::SubscriptionInactive,
            RhiStatusReasonCode::RecoveryIncomplete,
            RhiStatusReasonCode::PublicationRecoveryIncomplete,
            RhiStatusReasonCode::PresenceStateUnavailable,
            RhiStatusReasonCode::ReconciliationBacklogExceeded,
            RhiStatusReasonCode::AdminListenerFailed,
            RhiStatusReasonCode::OperationsListenerFailed,
            RhiStatusReasonCode::ShutdownInProgress,
        ]
        .map(RhiStatusReasonCode::as_str)
    );

    let (_publisher, reader) = rhi_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(RhiServicePhase::Ready, true, 120_000, 5),
    )
    .expect("status cache");
    let snapshot = reader.snapshot();
    let wire = std::str::from_utf8(snapshot.detailed_status_json()).expect("status UTF-8");
    assert_eq!(
        wire,
        r#"{"contract_version":1,"service":"rhi","instance":"primary","phase":"ready","ready":true,"uptime_millis":120000,"reason_codes":[],"build_info":{"version":"0.1.0","revision":"0123456789abcdef0123456789abcdef01234567","toolchain":"1.97.1","contract_versions":{"config":1,"state":11,"admin":1,"status":1,"provider":1}},"configuration":{"schema":"radroots.rhi.config","schema_version":1,"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source":"explicit_config"},"persistence":{"health":"ready","schema_version":10,"generation":42,"integrity":"verified","reason_codes":[]},"provider":{"health":"ready","identity":{"configured":true,"available":true,"reason_codes":[]},"reason_codes":[]},"transport":{"health":"ready","required_sources_ready":true,"subscriber_active":true,"configured_source_count":2,"reachable_source_count":2,"reason_codes":[]},"rhi":{"identity":{"configured":true,"available":true,"reason_codes":[]},"reconciliation":{"pending":5,"leased":3,"exhausted":1,"oldest_pending_at_utc":1723456700},"publication":{"pending":4,"unknown":1,"oldest_pending_at_utc":1723456789},"presence":{"pending":2,"unknown":1}}}"#
    );
    assert!(wire.len() < RHI_DETAILED_STATUS_MAX_UTF8_BYTES);
    for forbidden in [
        "secret",
        "credential",
        "private_key",
        "password",
        "filesystem_path",
        "relay_url",
        "raw_error",
    ] {
        assert!(!wire.contains(forbidden), "wire leaked `{forbidden}`");
    }
}

#[tokio::test]
async fn latest_publication_is_atomic_passive_and_retains_old_snapshots() {
    let (mut publisher, reader) = rhi_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(RhiServicePhase::Starting, false, 0, 9),
    )
    .expect("status cache");
    let old = reader.snapshot();
    let old_pointer = old.detailed_status_json().as_ptr();
    for _ in 0..1_000 {
        let same = reader.snapshot();
        assert_eq!(same.detailed_status_json().as_ptr(), old_pointer);
        assert_eq!(same.phase(), RhiServicePhase::Starting);
    }

    let mut changed = publisher.subscribe();
    publisher
        .publish(observation(RhiServicePhase::Ready, true, 10, 2))
        .expect("ready publication");
    publisher
        .publish(observation(RhiServicePhase::Degraded, true, 20, 1))
        .expect("degraded publication");

    let latest = changed.changed().await.expect("latest publication");
    assert_eq!(latest.phase(), RhiServicePhase::Degraded);
    assert!(latest.is_ready());
    assert!(
        std::str::from_utf8(latest.detailed_status_json())
            .expect("status UTF-8")
            .contains("\"uptime_millis\":20")
    );
    assert_eq!(old.phase(), RhiServicePhase::Starting);
    assert!(
        std::str::from_utf8(old.detailed_status_json())
            .expect("old UTF-8")
            .contains("\"uptime_millis\":0")
    );
}

#[tokio::test]
async fn illegal_transition_and_publisher_drop_preserve_the_last_valid_value() {
    let (mut publisher, reader) = rhi_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(RhiServicePhase::Starting, false, 1, 0),
    )
    .expect("status cache");
    let before = reader.snapshot().detailed_status_json().to_vec();
    let error = publisher
        .publish(observation(RhiServicePhase::Unready, false, 2, 0))
        .expect_err("illegal starting to unready transition");
    assert_eq!(error.kind(), RhiStatusErrorKind::InvalidTransition);
    assert_eq!(reader.snapshot().detailed_status_json(), before);
    assert!(Error::source(&error).is_none());

    let mut dropped = publisher.subscribe();
    drop(publisher);
    let dropped_error = dropped.changed().await.expect_err("publisher dropped");
    assert_eq!(dropped_error.kind(), RhiStatusErrorKind::PublisherDropped);
    assert_eq!(reader.snapshot().detailed_status_json(), before);
}

#[test]
fn closed_work_counts_time_and_safe_debug_bound_the_status_surface() {
    let work = RhiReconciliationStatusV1::new(u64::MAX, 2, 3, None);
    assert_eq!(work.pending(), u64::MAX);
    assert_eq!(work.leased(), 2);
    assert_eq!(work.exhausted(), 3);
    assert_eq!(work.oldest_pending_at_utc(), None);
    assert_eq!(RhiStatusUnixSeconds::new(0).expect("zero").get(), 0);
    assert_eq!(
        RhiStatusUnixSeconds::new(i64::MAX as u64)
            .expect("maximum")
            .get(),
        i64::MAX as u64
    );
    assert_eq!(
        RhiStatusUnixSeconds::new(i64::MAX as u64 + 1)
            .expect_err("over maximum")
            .kind(),
        RhiStatusErrorKind::InvalidTime
    );

    let (publisher, reader) = rhi_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(RhiServicePhase::Ready, true, 5, 0),
    )
    .expect("status cache");
    let rendered = format!("{publisher:?} {reader:?} {:?}", reader.snapshot());
    for forbidden in [
        SERVICE_REVISION,
        LIB_REVISION,
        "radroots.rhi.config",
        "aaaaaaaaaaaaaaaa",
        "oldest_pending_at_utc",
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

#[test]
fn model_boundaries_fail_closed_before_publication() {
    assert_eq!(
        RhiStatusReasonCode::new("")
            .expect_err("empty reason")
            .kind(),
        RhiStatusErrorKind::InvalidReasonCode
    );
    assert_eq!(
        RhiStatusReasonCode::new("secret_canary_value")
            .expect_err("unknown reason")
            .kind(),
        RhiStatusErrorKind::InvalidReasonCode
    );
    let maximum = [
        RhiStatusReasonCode::IdentityUnavailable,
        RhiStatusReasonCode::DatabaseSchemaMismatch,
        RhiStatusReasonCode::DatabaseReadOnly,
        RhiStatusReasonCode::DatabaseLowDisk,
        RhiStatusReasonCode::SourceUnavailable,
        RhiStatusReasonCode::SubscriptionInactive,
        RhiStatusReasonCode::RecoveryIncomplete,
        RhiStatusReasonCode::PublicationRecoveryIncomplete,
        RhiStatusReasonCode::PresenceStateUnavailable,
        RhiStatusReasonCode::ReconciliationBacklogExceeded,
        RhiStatusReasonCode::AdminListenerFailed,
        RhiStatusReasonCode::OperationsListenerFailed,
        RhiStatusReasonCode::ShutdownInProgress,
    ];
    assert_eq!(
        RhiStatusReasonCodes::new(maximum)
            .expect("maximum reasons")
            .as_slice()
            .len(),
        13
    );
    let mut infinite = std::iter::repeat(RhiStatusReasonCode::IdentityUnavailable);
    assert_eq!(
        RhiStatusReasonCodes::new(&mut infinite)
            .expect_err("bounded infinite iterator")
            .kind(),
        RhiStatusErrorKind::TooManyReasonCodes
    );
    assert_eq!(
        infinite.next().expect("iterator retained"),
        RhiStatusReasonCode::IdentityUnavailable
    );

    assert_eq!(
        RhiStatusBuildInfoV1::new(
            RhiStatusBuildMode::Release,
            Some("0.1.0"),
            None,
            Some(LIB_REVISION),
            Some("1.97.1"),
            Some("x86_64-unknown-linux-gnu"),
            Some("service-host"),
        )
        .expect_err("release revision required")
        .kind(),
        RhiStatusErrorKind::InvalidBuildInfo
    );
    assert_eq!(
        RhiStatusConfigurationIdentityV1::new(
            "A".repeat(64),
            RhiStatusConfigurationSource::ExplicitConfig,
        )
        .expect_err("lowercase digest required")
        .kind(),
        RhiStatusErrorKind::InvalidConfiguration
    );
    assert_eq!(
        RhiPersistenceStatusV1::new(
            RhiPersistenceHealthV1::Ready,
            0,
            0,
            RhiIntegrityStateV1::Verified,
            RhiStatusReasonCodes::empty(),
        )
        .expect_err("positive schema required")
        .kind(),
        RhiStatusErrorKind::InvalidPersistence
    );

    let error = RhiStatusCommonV1::new(
        RhiServicePhase::Ready,
        false,
        RhiStatusReasonCodes::empty(),
        0,
        build_info(),
        RhiStatusConfigurationIdentityV1::new(
            "a".repeat(64),
            RhiStatusConfigurationSource::ExplicitConfig,
        )
        .expect("configuration"),
        RhiPersistenceStatusV1::new(
            RhiPersistenceHealthV1::Ready,
            10,
            0,
            RhiIntegrityStateV1::Verified,
            RhiStatusReasonCodes::empty(),
        )
        .expect("persistence"),
    )
    .expect_err("ready phase requires readiness");
    assert_eq!(error.kind(), RhiStatusErrorKind::InvalidLifecycle);

    let inconsistent = RhiStatusObservationV1::new(
        RhiStatusCommonV1::new(
            RhiServicePhase::Ready,
            true,
            RhiStatusReasonCodes::empty(),
            1,
            build_info(),
            RhiStatusConfigurationIdentityV1::new(
                "a".repeat(64),
                RhiStatusConfigurationSource::ExplicitConfig,
            )
            .expect("configuration"),
            RhiPersistenceStatusV1::new(
                RhiPersistenceHealthV1::Ready,
                10,
                1,
                RhiIntegrityStateV1::Verified,
                RhiStatusReasonCodes::empty(),
            )
            .expect("persistence"),
        )
        .expect("common"),
        RhiProviderStatusV1::new(
            identity(true, false, &["identity_unavailable"]),
            reasons(&["identity_unavailable"]),
        )
        .expect("provider"),
        RhiEvidenceTransportStatusV1::new(
            RhiTransportHealthV1::Ready,
            true,
            true,
            1,
            1,
            RhiStatusReasonCodes::empty(),
        )
        .expect("transport"),
        RhiReconciliationStatusV1::default(),
        RhiPublicationStatusV1::default(),
        RhiPresenceStatusV1::default(),
    );
    assert_eq!(
        rhi_status_cache(InstanceId::new("primary").expect("instance"), inconsistent,)
            .expect_err("ready status requires healthy critical dependencies")
            .kind(),
        RhiStatusErrorKind::InvalidLifecycle
    );
}

#[test]
fn provider_transport_and_optional_oldest_time_are_deterministic() {
    let ready = RhiProviderStatusV1::new(identity(true, true, &[]), RhiStatusReasonCodes::empty())
        .expect("ready provider");
    assert_eq!(ready.health(), rhi::RhiProviderHealthV1::Ready);

    let unavailable = RhiProviderStatusV1::new(
        identity(true, false, &["identity_unavailable"]),
        reasons(&["identity_unavailable"]),
    )
    .expect("unavailable provider");
    assert_eq!(unavailable.health(), rhi::RhiProviderHealthV1::Unavailable);

    let (_publisher, reader) = rhi_status_cache(
        InstanceId::new("primary").expect("instance"),
        RhiStatusObservationV1::new(
            RhiStatusCommonV1::new(
                RhiServicePhase::Ready,
                true,
                RhiStatusReasonCodes::empty(),
                1,
                build_info(),
                RhiStatusConfigurationIdentityV1::new(
                    "a".repeat(64),
                    RhiStatusConfigurationSource::ExplicitConfig,
                )
                .expect("configuration"),
                RhiPersistenceStatusV1::new(
                    RhiPersistenceHealthV1::Ready,
                    10,
                    0,
                    RhiIntegrityStateV1::Verified,
                    RhiStatusReasonCodes::empty(),
                )
                .expect("persistence"),
            )
            .expect("common status"),
            ready,
            RhiEvidenceTransportStatusV1::new(
                RhiTransportHealthV1::Ready,
                true,
                true,
                1,
                1,
                RhiStatusReasonCodes::empty(),
            )
            .expect("transport"),
            RhiReconciliationStatusV1::default(),
            RhiPublicationStatusV1::new(0, 0, None),
            RhiPresenceStatusV1::default(),
        ),
    )
    .expect("cache");
    let wire = std::str::from_utf8(reader.snapshot().detailed_status_json())
        .expect("status UTF-8")
        .to_owned();
    assert!(wire.contains("\"publication\":{\"pending\":0,\"unknown\":0}"));
    assert!(!wire.contains("oldest_pending_at_utc"));
}
