#![forbid(unsafe_code)]

use std::error::Error;

use rhi::{
    RHI_CONFIG_SCHEMA, RHI_CONFIG_SCHEMA_VERSION, RhiConfigProfile, RhiConfigV1ErrorKind,
    parse_rhi_config_v1,
};

const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

#[test]
fn root_api_admits_the_canonical_document_and_exposes_only_redacted_effective_output() {
    let document = parse_rhi_config_v1(EXAMPLE.as_bytes(), RhiConfigProfile::Production)
        .expect("canonical configuration");
    assert_eq!(document.schema(), RHI_CONFIG_SCHEMA);
    assert_eq!(document.schema_version(), RHI_CONFIG_SCHEMA_VERSION);
    assert_eq!(document.relay_count(), 2);
    assert_eq!(document.evidence_source_count(), 1);

    let effective = document.effective().canonical_json();
    assert!(effective.contains("\"source\":\"toml\""));
    assert!(effective.contains("[redacted-public-key]"));
    for forbidden in [
        "/var/lib/radroots",
        "relay.example.com",
        "relay-primary",
        "trade-primary",
        "2222222222222222",
        "service_wrapping_key",
    ] {
        assert!(!effective.contains(forbidden));
        assert!(!format!("{document:?}").contains(forbidden));
    }
}

#[test]
fn root_api_failure_is_stable_and_source_free() {
    let secret = "never-render-this-value";
    let invalid = EXAMPLE.replacen(
        "shutdown_grace_ms = 30000",
        &format!("unknown = \"{secret}\""),
        1,
    );
    let failure = parse_rhi_config_v1(invalid.as_bytes(), RhiConfigProfile::Production)
        .expect_err("unknown field must fail");
    assert_eq!(failure.kind(), RhiConfigV1ErrorKind::InvalidDocument);
    assert!(Error::source(&failure).is_none());
    assert!(!format!("{failure} {failure:?}").contains(secret));
}
