//! Strict, bounded RHI configuration document v1 admission.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;

use nostr::PublicKey;
use serde::Serialize;
use serde_json::{Map, Value, json};
use url::Url;

const CONFIG_SCHEMA: &str = include_str!("../contracts/services_hardening/config.v1.schema.json");

/// Exact schema identity for the production RHI configuration document.
pub const RHI_CONFIG_SCHEMA: &str = "radroots.rhi.config";

/// Exact supported RHI configuration schema version.
pub const RHI_CONFIG_SCHEMA_VERSION: u32 = 1;

/// Hard cap applied to original bytes before UTF-8 or TOML parsing.
pub const RHI_CONFIG_DOCUMENT_MAX_UTF8_BYTES: usize = 1_048_576;

/// Hard cap applied to the deterministic redacted effective projection.
pub const RHI_CONFIG_EFFECTIVE_MAX_UTF8_BYTES: usize = 786_432;

/// Bootstrap-selected network posture used during relay admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiConfigProfile {
    /// Production and ordinary service-host configurations require WSS relays.
    Production,
    /// Explicit repository-local development may also use loopback WS relays.
    RepoLocal,
}

/// Stable origin classification for one effective configuration value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RhiConfigValueSource {
    BootstrapCli,
    Toml,
    SafeDefault,
    DerivedPath,
}

/// Exact governed authority behind a safely defaulted configuration leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RhiConfigDefaultAuthority {
    RadrootsServiceHost,
    RadrootsServiceSqlite,
    RadrootsEvent,
    RhiEvidencePolicy,
    AcceptedServiceAuthority,
    EngineeringSafety,
}

/// Stable source-free classification for configuration admission failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiConfigV1ErrorKind {
    TooLarge,
    InvalidUtf8,
    MalformedToml,
    MissingSchema,
    InvalidSchema,
    SchemaMismatch,
    MissingSchemaVersion,
    InvalidSchemaVersion,
    UnsupportedSchemaVersion,
    InvalidDocument,
    InvalidRelationship,
    Encoding,
}

impl RhiConfigV1ErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::TooLarge => "configuration document exceeds its size limit",
            Self::InvalidUtf8 => "configuration document is not valid UTF-8",
            Self::MalformedToml => "configuration document is not valid TOML",
            Self::MissingSchema => "configuration document schema is missing",
            Self::InvalidSchema => "configuration document schema is invalid",
            Self::SchemaMismatch => "configuration document schema is unsupported",
            Self::MissingSchemaVersion => "configuration document schema version is missing",
            Self::InvalidSchemaVersion => "configuration document schema version is invalid",
            Self::UnsupportedSchemaVersion => {
                "configuration document schema version is unsupported"
            }
            Self::InvalidDocument => "configuration document fields are invalid",
            Self::InvalidRelationship => "configuration document relationships are invalid",
            Self::Encoding => "effective configuration could not be encoded",
        }
    }
}

/// One source-free configuration admission failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiConfigV1Error {
    kind: RhiConfigV1ErrorKind,
}

impl RhiConfigV1Error {
    const fn new(kind: RhiConfigV1ErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> RhiConfigV1ErrorKind {
        self.kind
    }
}

impl fmt::Debug for RhiConfigV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiConfigV1Error")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiConfigV1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for RhiConfigV1Error {}

/// Deterministic redacted effective configuration with exact leaf provenance.
#[derive(Clone, PartialEq, Eq)]
pub struct RhiEffectiveConfigV1 {
    canonical_json: Box<str>,
    field_count: usize,
}

impl RhiEffectiveConfigV1 {
    /// Returns compact JSON in deterministic path order.
    #[must_use]
    pub fn canonical_json(&self) -> &str {
        &self.canonical_json
    }

    /// Returns the number of projected effective leaf values.
    #[must_use]
    pub const fn field_count(&self) -> usize {
        self.field_count
    }
}

impl fmt::Debug for RhiEffectiveConfigV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiEffectiveConfigV1")
            .field("canonical_json", &"[redacted]")
            .field("field_count", &self.field_count)
            .finish()
    }
}

/// Validated thread counts for the sole binary-owned Tokio runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiRuntimeThreadLimitsV1 {
    worker_threads: usize,
    blocking_threads: usize,
}

impl RhiRuntimeThreadLimitsV1 {
    /// Returns the configured asynchronous worker count.
    #[must_use]
    pub const fn worker_threads(self) -> usize {
        self.worker_threads
    }

    /// Returns the configured blocking worker ceiling.
    #[must_use]
    pub const fn blocking_threads(self) -> usize {
        self.blocking_threads
    }
}

/// A validated immutable RHI configuration document v1.
pub struct RhiConfigDocumentV1 {
    profile: RhiConfigProfile,
    normalized: Value,
    effective: RhiEffectiveConfigV1,
    runtime_thread_limits: RhiRuntimeThreadLimitsV1,
}

impl RhiConfigDocumentV1 {
    /// Returns the exact admitted schema identity.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        RHI_CONFIG_SCHEMA
    }

    /// Returns the exact admitted schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        RHI_CONFIG_SCHEMA_VERSION
    }

    /// Returns the bootstrap-selected network posture used during admission.
    #[must_use]
    pub const fn profile(&self) -> RhiConfigProfile {
        self.profile
    }

    /// Returns the deterministic redacted effective configuration projection.
    #[must_use]
    pub const fn effective(&self) -> &RhiEffectiveConfigV1 {
        &self.effective
    }

    pub(crate) const fn normalized(&self) -> &Value {
        &self.normalized
    }

    /// Returns the exact number of configured relay bindings.
    #[must_use]
    pub fn relay_count(&self) -> usize {
        self.normalized
            .pointer("/relays")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    }

    /// Returns the exact number of configured evidence sources.
    #[must_use]
    pub fn evidence_source_count(&self) -> usize {
        self.normalized
            .pointer("/evidence/sources")
            .and_then(Value::as_array)
            .map_or(0, Vec::len)
    }

    /// Returns the validated limits for the sole binary-owned Tokio runtime.
    #[must_use]
    pub const fn runtime_thread_limits(&self) -> RhiRuntimeThreadLimitsV1 {
        self.runtime_thread_limits
    }
}

impl fmt::Debug for RhiConfigDocumentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiConfigDocumentV1")
            .field("schema", &RHI_CONFIG_SCHEMA)
            .field("schema_version", &RHI_CONFIG_SCHEMA_VERSION)
            .field("profile", &self.profile)
            .field("effective", &self.effective)
            .field("runtime_thread_limits", &self.runtime_thread_limits)
            .finish()
    }
}

/// Parses and semantically validates one complete RHI configuration document.
pub fn parse_rhi_config_v1(
    bytes: &[u8],
    profile: RhiConfigProfile,
) -> Result<RhiConfigDocumentV1, RhiConfigV1Error> {
    if bytes.len() > RHI_CONFIG_DOCUMENT_MAX_UTF8_BYTES {
        return Err(error(RhiConfigV1ErrorKind::TooLarge));
    }
    let source =
        std::str::from_utf8(bytes).map_err(|_| error(RhiConfigV1ErrorKind::InvalidUtf8))?;
    let original = source
        .parse::<toml::Table>()
        .map_err(|_| error(RhiConfigV1ErrorKind::MalformedToml))?;
    validate_header(&original)?;

    let mut normalized = serde_json::to_value(toml::Value::Table(original.clone()))
        .map_err(|_| error(RhiConfigV1ErrorKind::InvalidDocument))?;
    let schema: Value =
        serde_json::from_str(CONFIG_SCHEMA).map_err(|_| error(RhiConfigV1ErrorKind::Encoding))?;
    let validator =
        jsonschema::validator_for(&schema).map_err(|_| error(RhiConfigV1ErrorKind::Encoding))?;
    if !validator.is_valid(&normalized) {
        return Err(error(RhiConfigV1ErrorKind::InvalidDocument));
    }
    apply_defaults(&mut normalized)?;
    if !validator.is_valid(&normalized) {
        return Err(error(RhiConfigV1ErrorKind::InvalidDocument));
    }
    validate_relationships(&normalized, profile)?;
    let effective = build_effective(&normalized, &original)?;
    let runtime_thread_limits = RhiRuntimeThreadLimitsV1 {
        worker_threads: usize::try_from(integer(
            &normalized,
            "/resource_limits/runtime/worker_threads",
        )?)
        .map_err(|_| error(RhiConfigV1ErrorKind::InvalidRelationship))?,
        blocking_threads: usize::try_from(integer(
            &normalized,
            "/resource_limits/runtime/blocking_threads",
        )?)
        .map_err(|_| error(RhiConfigV1ErrorKind::InvalidRelationship))?,
    };
    Ok(RhiConfigDocumentV1 {
        profile,
        normalized,
        effective,
        runtime_thread_limits,
    })
}

fn validate_header(header: &toml::Table) -> Result<(), RhiConfigV1Error> {
    let schema = header
        .get("schema")
        .ok_or_else(|| error(RhiConfigV1ErrorKind::MissingSchema))?
        .as_str()
        .ok_or_else(|| error(RhiConfigV1ErrorKind::InvalidSchema))?;
    if !valid_schema_id(schema) {
        return Err(error(RhiConfigV1ErrorKind::InvalidSchema));
    }
    if schema != RHI_CONFIG_SCHEMA {
        return Err(error(RhiConfigV1ErrorKind::SchemaMismatch));
    }
    let version = header
        .get("schema_version")
        .ok_or_else(|| error(RhiConfigV1ErrorKind::MissingSchemaVersion))?
        .as_integer()
        .ok_or_else(|| error(RhiConfigV1ErrorKind::InvalidSchemaVersion))?;
    let version =
        u32::try_from(version).map_err(|_| error(RhiConfigV1ErrorKind::InvalidSchemaVersion))?;
    if version == 0 {
        return Err(error(RhiConfigV1ErrorKind::InvalidSchemaVersion));
    }
    if version != RHI_CONFIG_SCHEMA_VERSION {
        return Err(error(RhiConfigV1ErrorKind::UnsupportedSchemaVersion));
    }
    Ok(())
}

fn valid_schema_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    !value.is_empty()
        && value.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[derive(Clone, Copy)]
struct DefaultEntry {
    path: &'static str,
    value: DefaultValue,
    authority: RhiConfigDefaultAuthority,
    enabled_pointer: Option<&'static str>,
}

#[derive(Clone, Copy)]
enum DefaultValue {
    Integer(u64),
    String(&'static str),
}

const DEFAULTS: &[DefaultEntry] = &[
    default(
        "/service/shutdown_grace_ms",
        30_000,
        RhiConfigDefaultAuthority::AcceptedServiceAuthority,
    ),
    default_string(
        "/logging/level",
        "info",
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default_string(
        "/logging/format",
        "json",
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    conditional_default(
        "/operations/limits/header_count",
        32,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/header_bytes",
        16_384,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/response_body_utf8_bytes",
        1_048_576,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/concurrent_connections",
        32,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/request_deadline_ms",
        15_000,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
        "/operations/enabled",
    ),
    conditional_default(
        "/operations/limits/idle_timeout_ms",
        30_000,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
        "/operations/enabled",
    ),
    default(
        "/database/busy_timeout_ms",
        5_000,
        RhiConfigDefaultAuthority::RadrootsServiceSqlite,
    ),
    default(
        "/database/max_connections",
        8,
        RhiConfigDefaultAuthority::RadrootsServiceSqlite,
    ),
    default(
        "/network/connect_deadline_ms",
        10_000,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/network/dns_answer_limit",
        16,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/reconciliation/concurrency",
        8,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/reconciliation/queue_capacity",
        4_096,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/reconciliation/lease_ms",
        30_000,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/reconciliation/lease_renewal_ms",
        10_000,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/reconciliation/max_attempts",
        10,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/reconciliation/initial_backoff_ms",
        250,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/reconciliation/maximum_backoff_ms",
        30_000,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/reconciliation/attempt_deadline_ms",
        30_000,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    conditional_default(
        "/publication/retry/max_attempts",
        10,
        RhiConfigDefaultAuthority::EngineeringSafety,
        "/publication/mode",
    ),
    conditional_default(
        "/publication/retry/initial_backoff_ms",
        250,
        RhiConfigDefaultAuthority::EngineeringSafety,
        "/publication/mode",
    ),
    conditional_default(
        "/publication/retry/maximum_backoff_ms",
        30_000,
        RhiConfigDefaultAuthority::EngineeringSafety,
        "/publication/mode",
    ),
    conditional_default(
        "/publication/retry/attempt_deadline_ms",
        15_000,
        RhiConfigDefaultAuthority::EngineeringSafety,
        "/publication/mode",
    ),
    default(
        "/resource_limits/admin/header_count",
        32,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/header_bytes",
        16_384,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/request_body_utf8_bytes",
        65_536,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/response_body_utf8_bytes",
        1_048_576,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/concurrent_connections",
        32,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/request_deadline_ms",
        15_000,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/idle_timeout_ms",
        30_000,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/admin/query_items",
        100,
        RhiConfigDefaultAuthority::AcceptedServiceAuthority,
    ),
    default(
        "/resource_limits/events/wire_bytes",
        262_144,
        RhiConfigDefaultAuthority::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/content_bytes",
        131_072,
        RhiConfigDefaultAuthority::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/tag_count",
        1_024,
        RhiConfigDefaultAuthority::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/tag_total_elements",
        4_096,
        RhiConfigDefaultAuthority::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/tag_element_bytes",
        4_096,
        RhiConfigDefaultAuthority::RadrootsEvent,
    ),
    default(
        "/resource_limits/events/tag_total_bytes",
        131_072,
        RhiConfigDefaultAuthority::RadrootsEvent,
    ),
    default(
        "/resource_limits/source_results/events",
        4_096,
        RhiConfigDefaultAuthority::RhiEvidencePolicy,
    ),
    default(
        "/resource_limits/source_results/bytes",
        8_388_608,
        RhiConfigDefaultAuthority::RhiEvidencePolicy,
    ),
    default(
        "/resource_limits/queues/ingress",
        1_024,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/resource_limits/queues/reconciliation",
        4_096,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/resource_limits/queues/publication",
        4_096,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/resource_limits/queues/presence",
        64,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/resource_limits/metrics/descriptors",
        64,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/metrics/samples",
        512,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/metrics/labels_per_sample",
        8,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/metrics/render_utf8_bytes",
        1_048_576,
        RhiConfigDefaultAuthority::RadrootsServiceHost,
    ),
    default(
        "/resource_limits/runtime/worker_threads",
        4,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
    default(
        "/resource_limits/runtime/blocking_threads",
        8,
        RhiConfigDefaultAuthority::EngineeringSafety,
    ),
];

const fn default(
    path: &'static str,
    value: u64,
    authority: RhiConfigDefaultAuthority,
) -> DefaultEntry {
    DefaultEntry {
        path,
        value: DefaultValue::Integer(value),
        authority,
        enabled_pointer: None,
    }
}

const fn conditional_default(
    path: &'static str,
    value: u64,
    authority: RhiConfigDefaultAuthority,
    enabled_pointer: &'static str,
) -> DefaultEntry {
    DefaultEntry {
        path,
        value: DefaultValue::Integer(value),
        authority,
        enabled_pointer: Some(enabled_pointer),
    }
}

const fn default_string(
    path: &'static str,
    value: &'static str,
    authority: RhiConfigDefaultAuthority,
) -> DefaultEntry {
    DefaultEntry {
        path,
        value: DefaultValue::String(value),
        authority,
        enabled_pointer: None,
    }
}

fn default_is_enabled(document: &Value, entry: &DefaultEntry) -> bool {
    match entry.enabled_pointer {
        Some("/operations/enabled") => {
            document.pointer("/operations/enabled") == Some(&Value::Bool(true))
        }
        Some("/publication/mode") => {
            document
                .pointer("/publication/mode")
                .and_then(Value::as_str)
                == Some("required")
        }
        Some(_) => false,
        None => true,
    }
}

fn apply_defaults(document: &mut Value) -> Result<(), RhiConfigV1Error> {
    for entry in DEFAULTS {
        if !default_is_enabled(document, entry) || document.pointer(entry.path).is_some() {
            continue;
        }
        insert_json_pointer(document, entry.path, entry.value)?;
    }
    Ok(())
}

fn insert_json_pointer(
    root: &mut Value,
    pointer: &str,
    value: DefaultValue,
) -> Result<(), RhiConfigV1Error> {
    let mut parts = pointer
        .split('/')
        .filter(|part| !part.is_empty())
        .peekable();
    let mut current = root;
    while let Some(part) = parts.next() {
        let object = current
            .as_object_mut()
            .ok_or_else(|| error(RhiConfigV1ErrorKind::InvalidDocument))?;
        if parts.peek().is_none() {
            object.insert(
                part.to_owned(),
                match value {
                    DefaultValue::Integer(value) => Value::Number(value.into()),
                    DefaultValue::String(value) => Value::String(value.to_owned()),
                },
            );
            return Ok(());
        }
        current = object
            .entry(part.to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    document_error()
}

fn validate_relationships(
    document: &Value,
    profile: RhiConfigProfile,
) -> Result<(), RhiConfigV1Error> {
    validate_utf8_byte_limits(document)?;
    validate_identity(document)?;
    let relays = validate_relays(document, profile)?;
    validate_evidence(document, relays)?;
    validate_reconciliation(document)?;
    validate_publication(document, relays)?;
    validate_presence(document, relays)?;
    validate_operations(document)?;
    validate_retention(document)?;
    validate_exact_policy_limits(document)
}

fn validate_utf8_byte_limits(document: &Value) -> Result<(), RhiConfigV1Error> {
    for (pointer, minimum, maximum) in [
        ("/identity/service/envelope_path", 1, 4_096),
        ("/identity/service/credential_reference", 1, 128),
        ("/identity/service/expected_public_key", 64, 64),
        ("/evidence/policy_id", 1, 64),
    ] {
        validate_string_bytes(string(document, pointer)?, minimum, maximum)?;
    }
    for relay in array(document, "/relays")? {
        validate_string_bytes(string_at(relay, "/id")?, 1, 64)?;
        validate_string_bytes(string_at(relay, "/url")?, 1, 2_048)?;
    }
    for source in array(document, "/evidence/sources")? {
        validate_string_bytes(string_at(source, "/source_id")?, 1, 64)?;
        validate_string_bytes(string_at(source, "/relay_id")?, 1, 64)?;
    }
    if bool_value(document, "/operations/enabled")? {
        validate_string_bytes(string(document, "/operations/listen")?, 1, 256)?;
    }
    Ok(())
}

fn validate_string_bytes(
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<(), RhiConfigV1Error> {
    if (minimum..=maximum).contains(&value.len()) {
        Ok(())
    } else {
        document_error()
    }
}

fn validate_identity(document: &Value) -> Result<(), RhiConfigV1Error> {
    let raw_path = string(document, "/identity/service/envelope_path")?;
    if raw_path.as_bytes().contains(&0)
        || raw_path == "/"
        || !raw_path.starts_with('/')
        || raw_path.ends_with('/')
        || raw_path
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || !valid_nostr_public_key(string(document, "/identity/service/expected_public_key")?)
    {
        return relationship_error();
    }
    Ok(())
}

fn valid_nostr_public_key(value: &str) -> bool {
    PublicKey::from_hex(value).is_ok_and(|public_key| public_key.xonly().is_ok())
}

fn validate_relays(
    document: &Value,
    profile: RhiConfigProfile,
) -> Result<&[Value], RhiConfigV1Error> {
    let relays = array(document, "/relays")?;
    let mut ids = BTreeSet::new();
    let mut urls = BTreeSet::new();
    for relay in relays {
        let id = string_at(relay, "/id")?;
        let raw_url = string_at(relay, "/url")?;
        canonical_relay_url(raw_url, profile)?;
        let read = bool_at(relay, "/read")?;
        let write = bool_at(relay, "/write")?;
        if !ids.insert(id) || !urls.insert(raw_url) || (!read && !write) {
            return relationship_error();
        }
    }
    Ok(relays)
}

fn canonical_relay_url(value: &str, profile: RhiConfigProfile) -> Result<Url, RhiConfigV1Error> {
    let parsed = Url::parse(value).map_err(|_| error(RhiConfigV1ErrorKind::InvalidDocument))?;
    if parsed.as_str() != value
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return document_error();
    }
    let allowed = match profile {
        RhiConfigProfile::Production => parsed.scheme() == "wss",
        RhiConfigProfile::RepoLocal => match parsed.scheme() {
            "wss" => true,
            "ws" => parsed
                .host_str()
                .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")),
            _ => false,
        },
    };
    if !allowed {
        return relationship_error();
    }
    Ok(parsed)
}

fn validate_evidence(document: &Value, relays: &[Value]) -> Result<(), RhiConfigV1Error> {
    let sources = array(document, "/evidence/sources")?;
    let mut source_ids = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    let mut required = false;
    let mut prior_source_id = None;
    for source in sources {
        let source_id = string_at(source, "/source_id")?;
        let kind = string_at(source, "/kind")?;
        let relay_id = string_at(source, "/relay_id")?;
        let selector = string_at(source, "/selector")?;
        if prior_source_id.is_some_and(|prior| prior >= source_id)
            || !source_ids.insert(source_id)
            || !bindings.insert((kind, relay_id, selector))
            || !relays.iter().any(|relay| {
                string_at(relay, "/id") == Ok(relay_id) && bool_at(relay, "/read") == Ok(true)
            })
            || integer_at(source, "/overlap_seconds")? > integer_at(source, "/lookback_seconds")?
        {
            return relationship_error();
        }
        prior_source_id = Some(source_id);
        required |= bool_at(source, "/required")?;
    }
    if !required {
        return relationship_error();
    }
    Ok(())
}

fn validate_reconciliation(document: &Value) -> Result<(), RhiConfigV1Error> {
    if integer(document, "/reconciliation/lease_renewal_ms")?
        >= integer(document, "/reconciliation/lease_ms")?
        || integer(document, "/reconciliation/initial_backoff_ms")?
            > integer(document, "/reconciliation/maximum_backoff_ms")?
    {
        return relationship_error();
    }
    let attempt_deadline = integer(document, "/reconciliation/attempt_deadline_ms")?;
    if array(document, "/evidence/sources")?.iter().any(|source| {
        integer_at(source, "/deadline_ms").map_or(true, |value| value > attempt_deadline)
    }) {
        return relationship_error();
    }
    Ok(())
}

fn validate_publication(document: &Value, relays: &[Value]) -> Result<(), RhiConfigV1Error> {
    if string(document, "/publication/mode")? == "disabled" {
        return Ok(());
    }
    validate_relay_targets(document, "/publication/target_relay_ids", relays)?;
    if integer(document, "/publication/retry/initial_backoff_ms")?
        > integer(document, "/publication/retry/maximum_backoff_ms")?
    {
        return relationship_error();
    }
    Ok(())
}

fn validate_presence(document: &Value, relays: &[Value]) -> Result<(), RhiConfigV1Error> {
    if !bool_value(document, "/presence/enabled")? {
        if bool_value(document, "/presence/profile")?
            || bool_value(document, "/presence/application_handler")?
        {
            return relationship_error();
        }
        return Ok(());
    }
    if !bool_value(document, "/presence/profile")?
        && !bool_value(document, "/presence/application_handler")?
    {
        return relationship_error();
    }
    validate_relay_targets(document, "/presence/target_relay_ids", relays)
}

fn validate_relay_targets(
    document: &Value,
    pointer: &str,
    relays: &[Value],
) -> Result<(), RhiConfigV1Error> {
    for relay_id in string_set(document, pointer)? {
        if !relays.iter().any(|relay| {
            string_at(relay, "/id") == Ok(relay_id) && bool_at(relay, "/write") == Ok(true)
        }) {
            return relationship_error();
        }
    }
    Ok(())
}

fn validate_operations(document: &Value) -> Result<(), RhiConfigV1Error> {
    if !bool_value(document, "/operations/enabled")? {
        return Ok(());
    }
    let address = string(document, "/operations/listen")?
        .parse::<SocketAddr>()
        .map_err(|_| error(RhiConfigV1ErrorKind::InvalidDocument))?;
    if address.port() == 0
        || (!address.ip().is_loopback()
            && string(document, "/operations/bind_policy")? != "explicit_public")
    {
        return relationship_error();
    }
    Ok(())
}

fn validate_retention(document: &Value) -> Result<(), RhiConfigV1Error> {
    let audit = integer(document, "/retention/audit_ms")?;
    for field in [
        "duplicate_observations_ms",
        "completed_jobs_ms",
        "terminal_publication_attempts_ms",
        "terminal_presence_attempts_ms",
        "operation_dedup_ms",
    ] {
        if integer(document, &format!("/retention/{field}"))? > audit {
            return relationship_error();
        }
    }
    Ok(())
}

fn validate_exact_policy_limits(document: &Value) -> Result<(), RhiConfigV1Error> {
    if integer(document, "/resource_limits/source_results/events")? != 4_096
        || integer(document, "/resource_limits/source_results/bytes")? != 8_388_608
    {
        return relationship_error();
    }
    Ok(())
}

fn array<'a>(value: &'a Value, pointer: &str) -> Result<&'a [Value], RhiConfigV1Error> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| error(RhiConfigV1ErrorKind::InvalidDocument))
}

fn string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, RhiConfigV1Error> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| error(RhiConfigV1ErrorKind::InvalidDocument))
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, RhiConfigV1Error> {
    string(value, pointer)
}

fn string_set<'a>(value: &'a Value, pointer: &str) -> Result<BTreeSet<&'a str>, RhiConfigV1Error> {
    array(value, pointer)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| error(RhiConfigV1ErrorKind::InvalidDocument))
        })
        .collect()
}

fn bool_value(value: &Value, pointer: &str) -> Result<bool, RhiConfigV1Error> {
    bool_at(value, pointer)
}

fn bool_at(value: &Value, pointer: &str) -> Result<bool, RhiConfigV1Error> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| error(RhiConfigV1ErrorKind::InvalidDocument))
}

fn integer(value: &Value, pointer: &str) -> Result<u64, RhiConfigV1Error> {
    integer_at(value, pointer)
}

fn integer_at(value: &Value, pointer: &str) -> Result<u64, RhiConfigV1Error> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| error(RhiConfigV1ErrorKind::InvalidDocument))
}

fn document_error<T>() -> Result<T, RhiConfigV1Error> {
    Err(error(RhiConfigV1ErrorKind::InvalidDocument))
}

fn relationship_error<T>() -> Result<T, RhiConfigV1Error> {
    Err(error(RhiConfigV1ErrorKind::InvalidRelationship))
}

const fn error(kind: RhiConfigV1ErrorKind) -> RhiConfigV1Error {
    RhiConfigV1Error::new(kind)
}

#[derive(Serialize)]
struct EffectiveProjection {
    schema: &'static str,
    schema_version: u32,
    fields: Vec<EffectiveField>,
}

#[derive(Serialize)]
struct EffectiveField {
    path: String,
    source: RhiConfigValueSource,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_authority: Option<RhiConfigDefaultAuthority>,
    value: Value,
}

fn build_effective(
    normalized: &Value,
    original: &toml::Table,
) -> Result<RhiEffectiveConfigV1, RhiConfigV1Error> {
    let mut flattened = BTreeMap::new();
    flatten_value("", normalized, &mut flattened);
    let original = toml::Value::Table(original.clone());
    let fields = flattened
        .into_iter()
        .map(|(path, value)| {
            let default_authority = default_entry(&path).and_then(|entry| {
                if toml_path(&original, &path).is_none() {
                    Some(entry.authority)
                } else {
                    None
                }
            });
            EffectiveField {
                source: if default_authority.is_some() {
                    RhiConfigValueSource::SafeDefault
                } else {
                    RhiConfigValueSource::Toml
                },
                default_authority,
                value: redacted_value(&path, value),
                path,
            }
        })
        .collect::<Vec<_>>();
    let field_count = fields.len();
    let canonical_json = serde_json::to_string(&EffectiveProjection {
        schema: "radroots.rhi.effective-config",
        schema_version: 1,
        fields,
    })
    .map_err(|_| error(RhiConfigV1ErrorKind::Encoding))?;
    if canonical_json.len() > RHI_CONFIG_EFFECTIVE_MAX_UTF8_BYTES {
        return Err(error(RhiConfigV1ErrorKind::Encoding));
    }
    Ok(RhiEffectiveConfigV1 {
        canonical_json: canonical_json.into_boxed_str(),
        field_count,
    })
}

fn flatten_value(path: &str, value: &Value, fields: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                flatten_value(&format!("{path}/{key}"), child, fields);
            }
        }
        Value::Array(array) if array.iter().all(Value::is_object) => {
            for (index, child) in array.iter().enumerate() {
                flatten_value(&format!("{path}/{index}"), child, fields);
            }
        }
        _ => {
            fields.insert(path.to_owned(), value.clone());
        }
    }
}

fn redacted_value(path: &str, value: Value) -> Value {
    let scalar_redaction = if path.ends_with("/envelope_path") {
        Some("[redacted-path]")
    } else if path.ends_with("/credential_reference") {
        Some("[redacted-credential-reference]")
    } else if path.ends_with("/expected_public_key") {
        Some("[redacted-public-key]")
    } else if path == "/operations/listen" {
        Some("[redacted-address]")
    } else if path == "/evidence/policy_id" {
        Some("[redacted-policy-id]")
    } else if path.starts_with("/relays/") && path.ends_with("/id") {
        Some("[redacted-relay-id]")
    } else if path.starts_with("/relays/") && path.ends_with("/url") {
        Some("[redacted-url]")
    } else if path.starts_with("/evidence/sources/") && path.ends_with("/source_id") {
        Some("[redacted-source-id]")
    } else if path.starts_with("/evidence/sources/") && path.ends_with("/relay_id") {
        Some("[redacted-relay-id]")
    } else {
        None
    };
    if let Some(redaction) = scalar_redaction {
        return Value::String(redaction.to_owned());
    }
    if matches!(
        path,
        "/publication/target_relay_ids" | "/presence/target_relay_ids"
    ) {
        return json!({
            "count": value.as_array().map_or(0, Vec::len),
            "values": "[redacted]"
        });
    }
    value
}

fn default_entry(path: &str) -> Option<&'static DefaultEntry> {
    DEFAULTS.iter().find(|entry| entry.path == path)
}

fn toml_path<'a>(root: &'a toml::Value, path: &str) -> Option<&'a toml::Value> {
    path.split('/')
        .filter(|part| !part.is_empty())
        .try_fold(root, |value, part| {
            if let Ok(index) = part.parse::<usize>() {
                value.as_array()?.get(index)
            } else {
                value.as_table()?.get(part)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    fn parse(source: &str) -> Result<RhiConfigDocumentV1, RhiConfigV1Error> {
        parse_rhi_config_v1(source.as_bytes(), RhiConfigProfile::Production)
    }

    fn replace(source: &str, old: &str, new: &str) -> String {
        assert!(source.contains(old), "missing fixture fragment: {old}");
        source.replacen(old, new, 1)
    }

    #[test]
    fn canonical_example_is_deterministic_bounded_and_redacted() {
        let first = parse(EXAMPLE).expect("canonical example");
        let second = parse(EXAMPLE).expect("canonical example again");
        assert_eq!(first.schema(), RHI_CONFIG_SCHEMA);
        assert_eq!(first.schema_version(), RHI_CONFIG_SCHEMA_VERSION);
        assert_eq!(first.profile(), RhiConfigProfile::Production);
        assert_eq!(first.relay_count(), 2);
        assert_eq!(first.evidence_source_count(), 1);
        assert_eq!(first.runtime_thread_limits().worker_threads(), 4);
        assert_eq!(first.runtime_thread_limits().blocking_threads(), 8);
        assert_eq!(first.effective(), second.effective());
        assert!(first.effective().field_count() > 75);
        let output = first.effective().canonical_json();
        assert!(output.starts_with(
            "{\"schema\":\"radroots.rhi.effective-config\",\"schema_version\":1,\"fields\":["
        ));
        assert!(output.len() <= RHI_CONFIG_EFFECTIVE_MAX_UTF8_BYTES);
        let projection: Value = serde_json::from_str(output).expect("effective projection");
        let fields = projection["fields"].as_array().expect("effective fields");
        assert_eq!(fields.len(), first.effective().field_count());
        let paths = fields
            .iter()
            .map(|field| field["path"].as_str().expect("effective path"))
            .collect::<Vec<_>>();
        assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(fields.iter().all(|field| {
            field["source"] == "toml" && field.get("default_authority").is_none()
        }));
        for forbidden in [
            "/var/lib/radroots",
            "2222222222222222",
            "relay.example.com",
            "relay-primary",
            "production-primary",
            "trade-primary",
            "service_wrapping_key",
        ] {
            assert!(!output.contains(forbidden), "leaked {forbidden}");
            assert!(!format!("{first:?}").contains(forbidden));
        }
    }

    #[test]
    fn exact_document_bound_precedes_utf8_and_toml_parsing() {
        let mut exact = EXAMPLE.as_bytes().to_vec();
        exact.extend_from_slice(b"\n#");
        exact.resize(RHI_CONFIG_DOCUMENT_MAX_UTF8_BYTES, b'a');
        assert!(parse_rhi_config_v1(&exact, RhiConfigProfile::Production).is_ok());
        exact.push(0xff);
        assert_eq!(
            parse_rhi_config_v1(&exact, RhiConfigProfile::Production)
                .unwrap_err()
                .kind(),
            RhiConfigV1ErrorKind::TooLarge
        );
    }

    #[test]
    fn invalid_utf8_duplicate_null_unknown_and_malformed_wire_fail() {
        assert_eq!(
            parse_rhi_config_v1(&[0xff], RhiConfigProfile::Production)
                .unwrap_err()
                .kind(),
            RhiConfigV1ErrorKind::InvalidUtf8
        );
        for source in [
            format!("schema = \"radroots.rhi.config\"\n{EXAMPLE}"),
            replace(
                EXAMPLE,
                "shutdown_grace_ms = 30000",
                "shutdown_grace_ms = null",
            ),
            replace(
                EXAMPLE,
                "shutdown_grace_ms = 30000",
                "shutdown_grace_ms = [null]",
            ),
            replace(
                EXAMPLE,
                "busy_timeout_ms = 5000",
                "busy_timeout_ms = 5000\nbusy_timeout_ms = 5000",
            ),
        ] {
            assert_eq!(
                parse(&source).unwrap_err().kind(),
                RhiConfigV1ErrorKind::MalformedToml
            );
        }
        let unknown = replace(
            EXAMPLE,
            "shutdown_grace_ms = 30000",
            "shutdown_grace_ms = 30000\nsecret = \"do-not-render\"",
        );
        assert_eq!(
            parse(&unknown).unwrap_err().kind(),
            RhiConfigV1ErrorKind::InvalidDocument
        );
    }

    #[test]
    fn header_failures_are_classified_before_document_admission() {
        for (source, expected) in [
            (
                EXAMPLE.replace("schema = \"radroots.rhi.config\"\n", ""),
                RhiConfigV1ErrorKind::MissingSchema,
            ),
            (
                replace(EXAMPLE, "schema = \"radroots.rhi.config\"", "schema = 1"),
                RhiConfigV1ErrorKind::InvalidSchema,
            ),
            (
                replace(EXAMPLE, "radroots.rhi.config", "radroots.myc.config"),
                RhiConfigV1ErrorKind::SchemaMismatch,
            ),
            (
                EXAMPLE.replace("schema_version = 1\n", ""),
                RhiConfigV1ErrorKind::MissingSchemaVersion,
            ),
            (
                replace(EXAMPLE, "schema_version = 1", "schema_version = \"1\""),
                RhiConfigV1ErrorKind::InvalidSchemaVersion,
            ),
            (
                replace(EXAMPLE, "schema_version = 1", "schema_version = 2"),
                RhiConfigV1ErrorKind::UnsupportedSchemaVersion,
            ),
        ] {
            assert_eq!(parse(&source).unwrap_err().kind(), expected);
        }
    }

    #[test]
    fn production_and_repo_local_relay_postures_are_distinct() {
        let local = replace(EXAMPLE, "wss://relay.example.com/", "ws://127.0.0.1:7777/");
        assert_eq!(
            parse(&local).unwrap_err().kind(),
            RhiConfigV1ErrorKind::InvalidRelationship
        );
        assert!(parse_rhi_config_v1(local.as_bytes(), RhiConfigProfile::RepoLocal).is_ok());
        let remote = replace(&local, "ws://127.0.0.1:7777/", "ws://relay.example.com/");
        assert_eq!(
            parse_rhi_config_v1(remote.as_bytes(), RhiConfigProfile::RepoLocal)
                .unwrap_err()
                .kind(),
            RhiConfigV1ErrorKind::InvalidRelationship
        );
    }

    #[test]
    fn identity_relay_and_evidence_relationships_fail_closed() {
        let cases = [
            replace(
                EXAMPLE,
                "/var/lib/radroots/services/rhi/default/secrets/service.identity.ncrypt",
                "/var/lib/radroots/../escape.ncrypt",
            ),
            replace(
                EXAMPLE,
                "2222222222222222222222222222222222222222222222222222222222222222",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            replace(
                EXAMPLE,
                "id = \"relay-secondary\"",
                "id = \"relay-primary\"",
            ),
            replace(
                EXAMPLE,
                "wss://relay-secondary.example.com/",
                "wss://relay.example.com/",
            ),
            replace(
                EXAMPLE,
                "read = true\nwrite = true",
                "read = false\nwrite = false",
            ),
            replace(
                EXAMPLE,
                "required = true\nselector",
                "required = false\nselector",
            ),
            replace(
                EXAMPLE,
                "relay_id = \"relay-primary\"",
                "relay_id = \"missing\"",
            ),
            replace(EXAMPLE, "overlap_seconds = 300", "overlap_seconds = 86401"),
            replace(
                EXAMPLE,
                "attempt_deadline_ms = 30000",
                "attempt_deadline_ms = 9999",
            ),
        ];
        for source in cases {
            assert!(matches!(
                parse(&source).unwrap_err().kind(),
                RhiConfigV1ErrorKind::InvalidDocument | RhiConfigV1ErrorKind::InvalidRelationship
            ));
        }

        let out_of_order = replace(
            &replace(
                EXAMPLE,
                "read = false\nwrite = true",
                "read = true\nwrite = true",
            ),
            "[reconciliation]",
            "[[evidence.sources]]\nsource_id = \"a-secondary\"\nkind = \"nostr_relay\"\nrelay_id = \"relay-secondary\"\nrequired = false\nselector = \"trade_mutation_lineage_v1\"\ndeadline_ms = 10000\nlookback_seconds = 86400\noverlap_seconds = 300\n\n[reconciliation]",
        );
        assert_eq!(
            parse(&out_of_order).unwrap_err().kind(),
            RhiConfigV1ErrorKind::InvalidRelationship
        );
    }

    #[test]
    fn publication_presence_operations_retention_and_policy_limits_fail_closed() {
        let cases = [
            replace(
                EXAMPLE,
                "initial_backoff_ms = 250",
                "initial_backoff_ms = 30001",
            ),
            replace(
                EXAMPLE,
                "target_relay_ids = [\"relay-primary\", \"relay-secondary\"]",
                "target_relay_ids = [\"missing\"]",
            ),
            replace(
                EXAMPLE,
                "profile = true\napplication_handler = true",
                "profile = false\napplication_handler = false",
            ),
            replace(EXAMPLE, "audit_ms = 31536000000", "audit_ms = 1000"),
            replace(EXAMPLE, "events = 4096", "events = 4095"),
            replace(EXAMPLE, "bytes = 8388608", "bytes = 8388607"),
        ];
        for source in cases {
            assert!(matches!(
                parse(&source).unwrap_err().kind(),
                RhiConfigV1ErrorKind::InvalidDocument | RhiConfigV1ErrorKind::InvalidRelationship
            ));
        }

        let public_loopback_policy = replace(
            EXAMPLE,
            "[operations]\nenabled = false",
            "[operations]\nenabled = true\nlisten = \"0.0.0.0:9460\"\nbind_policy = \"loopback_only\"\n\n[operations.limits]",
        );
        assert_eq!(
            parse(&public_loopback_policy).unwrap_err().kind(),
            RhiConfigV1ErrorKind::InvalidRelationship
        );
    }

    #[test]
    fn conditional_sections_remain_closed_when_disabled_and_default_when_enabled() {
        let mut disabled = EXAMPLE.parse::<toml::Table>().expect("example TOML");
        let publication = disabled
            .get_mut("publication")
            .and_then(toml::Value::as_table_mut)
            .expect("publication table");
        publication.insert(
            "mode".to_owned(),
            toml::Value::String("disabled".to_owned()),
        );
        publication.remove("target_relay_ids");
        publication.remove("retry");
        let presence = disabled
            .get_mut("presence")
            .and_then(toml::Value::as_table_mut)
            .expect("presence table");
        presence.insert("enabled".to_owned(), toml::Value::Boolean(false));
        presence.insert("profile".to_owned(), toml::Value::Boolean(false));
        presence.insert(
            "application_handler".to_owned(),
            toml::Value::Boolean(false),
        );
        presence.remove("target_relay_ids");
        let parsed =
            parse(&toml::to_string(&disabled).expect("disabled TOML")).expect("disabled sections");
        let effective = parsed.effective().canonical_json();
        assert!(!effective.contains("/publication/retry/"));
        assert!(!effective.contains("/operations/limits/"));

        let enabled_operations = replace(
            EXAMPLE,
            "[operations]\nenabled = false",
            "[operations]\nenabled = true\nlisten = \"127.0.0.1:9460\"\nbind_policy = \"loopback_only\"\n\n[operations.limits]",
        );
        let parsed = parse(&enabled_operations).expect("enabled operations defaults");
        assert!(
            parsed
                .effective()
                .canonical_json()
                .contains("/operations/limits/header_count")
        );
    }

    #[test]
    fn all_frozen_defaults_are_applied_with_exact_provenance() {
        assert_eq!(
            serde_json::to_value([
                RhiConfigValueSource::BootstrapCli,
                RhiConfigValueSource::Toml,
                RhiConfigValueSource::SafeDefault,
                RhiConfigValueSource::DerivedPath,
            ])
            .expect("serialize provenance vocabulary"),
            json!(["bootstrap_cli", "toml", "safe_default", "derived_path"])
        );
        assert_eq!(DEFAULTS.len(), 51);
        let schema: Value = serde_json::from_str(CONFIG_SCHEMA).expect("embedded schema");
        assert_eq!(count_schema_defaults(&schema), DEFAULTS.len());
        for entry in DEFAULTS {
            let pointer = schema_default_pointer(entry.path);
            let schema_default = schema
                .pointer(&format!("{pointer}/default"))
                .expect("schema default");
            let expected_default = match entry.value {
                DefaultValue::Integer(value) => json!(value),
                DefaultValue::String(value) => json!(value),
            };
            assert_eq!(schema_default, &expected_default, "{}", entry.path);
            let expected_authority =
                serde_json::to_value(entry.authority).expect("serialize default authority");
            assert_eq!(
                schema.pointer(&format!("{pointer}/x-radroots-default-source")),
                Some(&expected_authority),
                "{}",
                entry.path
            );
        }
        let mut table = EXAMPLE.parse::<toml::Table>().expect("example TOML");
        for entry in DEFAULTS {
            remove_toml_path(&mut table, entry.path);
        }
        let minimal = toml::to_string(&table).expect("minimal TOML");
        let parsed = parse(&minimal).expect("defaults admitted");
        let output = parsed.effective().canonical_json();
        for source in [
            "accepted_service_authority",
            "engineering_safety",
            "radroots_service_sqlite",
            "radroots_service_host",
            "radroots_event",
            "rhi_evidence_policy",
        ] {
            assert!(output.contains(&format!("\"default_authority\":\"{source}\"")));
        }
        assert!(output.contains("\"source\":\"safe_default\""));
        let projection: Value = serde_json::from_str(output).expect("effective projection");
        assert!(
            projection["fields"]
                .as_array()
                .expect("effective fields")
                .iter()
                .all(|field| match field["source"].as_str() {
                    Some("safe_default") => field.get("default_authority").is_some(),
                    Some("toml") => field.get("default_authority").is_none(),
                    _ => false,
                })
        );
        let explicit = parse(EXAMPLE).expect("explicit example");
        assert!(
            !explicit
                .effective()
                .canonical_json()
                .contains("default_authority")
        );
        assert!(
            explicit
                .effective()
                .canonical_json()
                .matches("\"source\":\"toml\"")
                .count()
                > output.matches("\"source\":\"toml\"").count()
        );
    }

    #[test]
    fn byte_limits_errors_and_debug_are_safe() {
        let exact_reference = "a".repeat(128);
        let exact = replace(EXAMPLE, "service_wrapping_key", &exact_reference);
        assert!(parse(&exact).is_ok());
        let over_reference = "a".repeat(129);
        let over = replace(EXAMPLE, "service_wrapping_key", &over_reference);
        assert_eq!(
            parse(&over).unwrap_err().kind(),
            RhiConfigV1ErrorKind::InvalidDocument
        );

        let exact_path = format!("/{}a", "é".repeat(2_047));
        assert_eq!(exact_path.len(), 4_096);
        let exact = replace(
            EXAMPLE,
            "/var/lib/radroots/services/rhi/default/secrets/service.identity.ncrypt",
            &exact_path,
        );
        assert!(parse(&exact).is_ok());
        let over_path = format!("/{}", "é".repeat(2_048));
        assert_eq!(over_path.len(), 4_097);
        let over = replace(
            EXAMPLE,
            "/var/lib/radroots/services/rhi/default/secrets/service.identity.ncrypt",
            &over_path,
        );
        assert_eq!(
            parse(&over).unwrap_err().kind(),
            RhiConfigV1ErrorKind::InvalidDocument
        );

        let secret = "credential-secret-value";
        let source = replace(
            EXAMPLE,
            "shutdown_grace_ms = 30000",
            &format!("unknown = \"{secret}\""),
        );
        let failure = parse(&source).unwrap_err();
        let rendered = format!("{failure} {failure:?}");
        assert!(!rendered.contains(secret));
        assert!(Error::source(&failure).is_none());
    }

    fn remove_toml_path(table: &mut toml::Table, pointer: &str) {
        let mut parts = pointer
            .split('/')
            .filter(|part| !part.is_empty())
            .peekable();
        let mut current = table;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                current.remove(part);
                return;
            }
            let Some(next) = current.get_mut(part).and_then(toml::Value::as_table_mut) else {
                return;
            };
            current = next;
        }
    }

    fn count_schema_defaults(value: &Value) -> usize {
        match value {
            Value::Object(object) => {
                usize::from(object.contains_key("default"))
                    + object.values().map(count_schema_defaults).sum::<usize>()
            }
            Value::Array(array) => array.iter().map(count_schema_defaults).sum(),
            _ => 0,
        }
    }

    fn schema_default_pointer(path: &str) -> String {
        for (prefix, definition) in [
            ("/operations/limits/", "operations_limits"),
            ("/publication/retry/", "retry"),
            ("/resource_limits/admin/", "admin_limits"),
            ("/resource_limits/events/", "event_limits"),
            ("/resource_limits/source_results/", "source_result_limits"),
            ("/resource_limits/queues/", "queue_limits"),
            ("/resource_limits/metrics/", "metrics_limits"),
            ("/resource_limits/runtime/", "runtime_limits"),
        ] {
            if let Some(field) = path.strip_prefix(prefix) {
                return format!("/$defs/{definition}/properties/{field}");
            }
        }
        let mut parts = path.split('/').filter(|part| !part.is_empty());
        let definition = parts.next().expect("default definition");
        let field = parts.next().expect("default field");
        assert!(parts.next().is_none(), "unmapped default path: {path}");
        format!("/$defs/{definition}/properties/{field}")
    }
}
