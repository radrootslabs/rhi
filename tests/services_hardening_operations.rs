#![forbid(unsafe_code)]

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use rhi::{
    InstanceId, RHI_LIVEZ_PATH, RHI_METRICS_PATH, RHI_OPERATIONS_CONTRACT_VERSION, RHI_READYZ_PATH,
    RhiConfigProfile, RhiEvidenceTransportStatusV1, RhiIdentityHealthV1, RhiIntegrityStateV1,
    RhiOperationsCancellationToken, RhiOperationsErrorKind, RhiOperationsServer,
    RhiPersistenceHealthV1, RhiPersistenceStatusV1, RhiPresenceStatusV1, RhiProviderStatusV1,
    RhiPublicationStatusV1, RhiReconciliationStatusV1, RhiServicePhase, RhiStatusBuildInfoV1,
    RhiStatusBuildMode, RhiStatusCommonV1, RhiStatusConfigurationIdentityV1,
    RhiStatusConfigurationSource, RhiStatusObservationV1, RhiStatusReasonCodes,
    RhiTransportHealthV1, parse_rhi_config_v1, rhi_status_cache,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONTRACT: &str = include_str!("../contracts/services_hardening/tcp_operations.v1.json");
const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const SERVICE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const LIB_REVISION: &str = "89abcdef0123456789abcdef0123456789abcdef";

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

fn identity(configured: bool, available: bool) -> RhiIdentityHealthV1 {
    RhiIdentityHealthV1::new(configured, available, RhiStatusReasonCodes::empty())
        .expect("identity health")
}

fn observation(phase: RhiServicePhase, ready: bool) -> RhiStatusObservationV1 {
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
    let provider = RhiProviderStatusV1::new(identity(true, true), RhiStatusReasonCodes::empty())
        .expect("provider");
    let transport = RhiEvidenceTransportStatusV1::new(
        RhiTransportHealthV1::Ready,
        true,
        true,
        2,
        2,
        RhiStatusReasonCodes::empty(),
    )
    .expect("transport");
    RhiStatusObservationV1::new(
        RhiStatusCommonV1::new(
            phase,
            ready,
            RhiStatusReasonCodes::empty(),
            1,
            build_info(),
            configuration,
            persistence,
        )
        .expect("common status"),
        provider,
        transport,
        RhiReconciliationStatusV1::default(),
        RhiPublicationStatusV1::new(0, 0, None),
        RhiPresenceStatusV1::default(),
    )
}

fn available_port() -> u16 {
    let listener =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("ephemeral listener");
    listener.local_addr().expect("local address").port()
}

fn enabled_config(port: u16) -> String {
    CONFIG.replacen(
        "[operations]\nenabled = false",
        &format!(
            "[operations]\nenabled = true\nlisten = \"127.0.0.1:{port}\"\nbind_policy = \"loopback_only\"\n\n[operations.limits]\nheader_count = 16\nheader_bytes = 8192\nresponse_body_utf8_bytes = 4096\nconcurrent_connections = 4\nrequest_deadline_ms = 500\nidle_timeout_ms = 500"
        ),
        1,
    )
}

async fn raw_request(address: std::net::SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.expect("connect");
    stream.write_all(request).await.expect("request write");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("response read");
    response
}

fn response_text(response: &[u8]) -> &str {
    std::str::from_utf8(response).expect("response UTF-8")
}

#[test]
fn machine_contract_freezes_exact_routes_metrics_and_non_authority() {
    let contract: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
    assert_eq!(contract["schema"], "radroots.rhi.tcp-operations.v1");
    assert_eq!(
        contract["contract_version"],
        RHI_OPERATIONS_CONTRACT_VERSION
    );
    assert_eq!(contract["step"], 212);
    assert_eq!(
        contract["routes"]
            .as_array()
            .expect("routes")
            .iter()
            .map(|route| route["path"].as_str().expect("route path"))
            .collect::<Vec<_>>(),
        [RHI_LIVEZ_PATH, RHI_READYZ_PATH, RHI_METRICS_PATH]
    );
    assert_eq!(contract["route_registration_extension"], false);
    assert_eq!(contract["metrics"]["high_cardinality_labels"], false);
    assert_eq!(contract["metrics"]["arbitrary_labels"], false);
}

#[tokio::test]
async fn exact_tcp_routes_use_only_latest_cached_lifecycle_and_metrics() {
    let config = parse_rhi_config_v1(
        enabled_config(available_port()).as_bytes(),
        RhiConfigProfile::Production,
    )
    .expect("enabled config");
    let (mut publisher, reader) = rhi_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(RhiServicePhase::Ready, true),
    )
    .expect("status cache");
    let detail_pointer = reader.snapshot().detailed_status_json().as_ptr();
    let bound = RhiOperationsServer::new(&config, &reader)
        .expect("operations server")
        .bind()
        .await
        .expect("bind");
    let address = bound.local_address();
    let cancellation = RhiOperationsCancellationToken::new();
    let task = tokio::spawn(bound.serve(cancellation.clone()));

    let live = raw_request(address, b"GET /livez HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let ready = raw_request(address, b"GET /readyz HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let metrics = raw_request(address, b"GET /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    assert!(response_text(&live).starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response_text(&live).ends_with("live\n"));
    assert!(response_text(&ready).ends_with("ready\n"));
    assert!(response_text(&metrics).contains("# TYPE radroots_rhi_service_phase gauge\n"));
    assert!(response_text(&metrics).contains("radroots_rhi_service_phase{phase=\"ready\"} 1\n"));
    assert!(response_text(&metrics).contains("radroots_rhi_service_ready 1\n"));

    for request in [
        &b"GET /status HTTP/1.1\r\nhost: localhost\r\n\r\n"[..],
        &b"GET /readyz?probe=1 HTTP/1.1\r\nhost: localhost\r\n\r\n"[..],
        &b"POST /metrics HTTP/1.1\r\nhost: localhost\r\ncontent-length: 0\r\n\r\n"[..],
        &b"GET /v1/status HTTP/1.1\r\nhost: localhost\r\n\r\n"[..],
    ] {
        let rejected = raw_request(address, request).await;
        assert!(response_text(&rejected).starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    publisher
        .publish(observation(RhiServicePhase::Unready, false))
        .expect("unready publication");
    let unready = raw_request(address, b"GET /readyz HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    let metrics = raw_request(address, b"GET /metrics HTTP/1.1\r\nhost: localhost\r\n\r\n").await;
    assert!(response_text(&unready).starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response_text(&unready).ends_with("unready\n"));
    assert!(response_text(&metrics).contains("radroots_rhi_service_phase{phase=\"unready\"} 1\n"));
    assert!(response_text(&metrics).contains("radroots_rhi_service_ready 0\n"));
    assert_ne!(
        reader.snapshot().detailed_status_json().as_ptr(),
        detail_pointer
    );

    cancellation.cancel();
    assert_eq!(task.await.expect("serve task"), Ok(()));
}

#[tokio::test]
async fn disabled_invalid_and_bind_failures_are_typed_source_free_and_redacted() {
    let disabled = parse_rhi_config_v1(CONFIG.as_bytes(), RhiConfigProfile::Production)
        .expect("disabled config");
    let (_, reader) = rhi_status_cache(
        InstanceId::new("primary").expect("instance"),
        observation(RhiServicePhase::Ready, true),
    )
    .expect("status cache");
    let disabled_error =
        RhiOperationsServer::new(&disabled, &reader).expect_err("disabled operations");
    assert_eq!(disabled_error.kind(), RhiOperationsErrorKind::Disabled);
    assert_eq!(disabled_error.code(), "operations_disabled");
    assert!(Error::source(&disabled_error).is_none());

    let below_floor =
        enabled_config(available_port()).replace("header_bytes = 8192", "header_bytes = 8191");
    assert!(parse_rhi_config_v1(below_floor.as_bytes(), RhiConfigProfile::Production).is_err());

    let occupied =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).expect("occupied listener");
    let port = occupied.local_addr().expect("occupied address").port();
    let config = parse_rhi_config_v1(
        enabled_config(port).as_bytes(),
        RhiConfigProfile::Production,
    )
    .expect("enabled config");
    let server = RhiOperationsServer::new(&config, &reader).expect("server");
    assert!(!format!("{server:?}").contains(&port.to_string()));
    let bind_error = server.bind().await.expect_err("occupied bind");
    assert_eq!(bind_error.kind(), RhiOperationsErrorKind::Bind);
    assert!(Error::source(&bind_error).is_none());
    assert!(!format!("{bind_error:?} {bind_error}").contains(&port.to_string()));
}
