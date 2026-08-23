//! Immutable RHI-specific identity and policy evidence for one state host.

use core::fmt;
use std::{collections::BTreeMap, error::Error};

use nostr::PublicKey;
use radroots_service_sqlite::{
    ServiceDatabaseIdentity, ServiceDatabaseMetadata, ServiceSqliteApplicationId,
    ServiceSqlitePaths,
};
use radroots_storage::event::SourceGeneration;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    RHI_CONFIG_SCHEMA_VERSION, RHI_STATE_SCHEMA_VERSION, RhiBootstrapProfileV1,
    RhiConfigDocumentV1, RhiConfigProfile, RhiRuntimeContext,
};

const NORMALIZED_CONFIG_DIGEST_DOMAIN: &[u8] = b"radroots.rhi.normalized_config.v1\0";
const EVIDENCE_POLICY_DIGEST_DOMAIN: &[u8] = b"radroots:rhi-evidence-policy:v1\0";

/// SQLite application identity for RHI, encoded as ASCII `RDRH`.
pub const RHI_STATE_APPLICATION_ID: u32 = 0x5244_5248;

/// Exact version of the governed RHI admin/operator contract.
pub const RHI_ADMIN_CONTRACT_VERSION: u32 = 1;

/// Exact version of the governed RHI status contract.
pub const RHI_STATUS_CONTRACT_VERSION: u32 = 1;

/// Exact version of the governed RHI identity-provider contract.
pub const RHI_PROVIDER_CONTRACT_VERSION: u32 = 1;

/// SHA-256 identity of one fully defaulted normalized RHI configuration.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiNormalizedConfigDigest([u8; 32]);

impl RhiNormalizedConfigDigest {
    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RhiNormalizedConfigDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiNormalizedConfigDigest([redacted])")
    }
}

/// SHA-256 identity of the normalized configured evidence policy.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RhiEvidencePolicyDigest([u8; 32]);

impl RhiEvidencePolicyDigest {
    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RhiEvidencePolicyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiEvidencePolicyDigest([redacted])")
    }
}

/// One validated canonical expected RHI service public identity.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RhiExpectedPublicIdentity(Box<str>);

impl RhiExpectedPublicIdentity {
    /// Returns the canonical lowercase 32-byte x-only public key in hex.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    fn from_hex(value: &str) -> Result<Self, RhiStateMetadataError> {
        let public_key = PublicKey::from_hex(value)
            .map_err(|_| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Identity))?;
        public_key
            .xonly()
            .map_err(|_| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Identity))?;
        let canonical = public_key.to_hex();
        if canonical != value {
            return Err(RhiStateMetadataError::new(
                RhiStateMetadataErrorKind::Identity,
            ));
        }
        Ok(Self(canonical.into_boxed_str()))
    }
}

impl fmt::Debug for RhiExpectedPublicIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiExpectedPublicIdentity([redacted])")
    }
}

/// Exact shared contract versions bound to one RHI state-host session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RhiStatePolicyVersions {
    configuration: u32,
    state: u32,
    admin: u32,
    status: u32,
    provider: u32,
}

impl RhiStatePolicyVersions {
    const fn governed() -> Self {
        Self {
            configuration: RHI_CONFIG_SCHEMA_VERSION,
            state: RHI_STATE_SCHEMA_VERSION,
            admin: RHI_ADMIN_CONTRACT_VERSION,
            status: RHI_STATUS_CONTRACT_VERSION,
            provider: RHI_PROVIDER_CONTRACT_VERSION,
        }
    }

    /// Returns the exact configuration-contract version.
    #[must_use]
    pub const fn configuration(self) -> u32 {
        self.configuration
    }

    /// Returns the exact state-schema version.
    #[must_use]
    pub const fn state(self) -> u32 {
        self.state
    }

    /// Returns the exact admin/operator-contract version.
    #[must_use]
    pub const fn admin(self) -> u32 {
        self.admin
    }

    /// Returns the exact status-contract version.
    #[must_use]
    pub const fn status(self) -> u32 {
        self.status
    }

    /// Returns the exact identity-provider-contract version.
    #[must_use]
    pub const fn provider(self) -> u32 {
        self.provider
    }
}

/// Non-forgeable RHI metadata bound to one runtime context and configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct RhiStateMetadata {
    paths: ServiceSqlitePaths,
    database: ServiceDatabaseMetadata,
    configuration: RhiNormalizedConfigDigest,
    evidence_policy: RhiEvidencePolicyDigest,
    identity: RhiExpectedPublicIdentity,
    policy_versions: RhiStatePolicyVersions,
}

impl RhiStateMetadata {
    /// Derives all state evidence from one sealed runtime context, one admitted
    /// normalized configuration, and caller-injected generation/time evidence.
    pub fn new(
        runtime: &RhiRuntimeContext,
        configuration: &RhiConfigDocumentV1,
        source_generation: SourceGeneration,
        created_at_unix_ms: u64,
    ) -> Result<Self, RhiStateMetadataError> {
        require_profile_binding(runtime.profile(), configuration.profile())?;
        let paths = ServiceSqlitePaths::from_runtime_context(runtime.context())
            .map_err(|_| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Paths))?;
        let application_id = ServiceSqliteApplicationId::new(RHI_STATE_APPLICATION_ID)
            .map_err(|_| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Invariant))?;
        let state_schema_version = core::num::NonZeroU32::new(RHI_STATE_SCHEMA_VERSION)
            .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Invariant))?;
        let database = ServiceDatabaseMetadata::new(
            &paths,
            source_generation,
            state_schema_version,
            created_at_unix_ms,
            application_id,
        )
        .map_err(|_| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Database))?;
        let normalized = configuration.normalized();
        let configuration_digest = normalized_config_digest(configuration.profile(), normalized)?;
        let evidence_policy = evidence_policy_digest(normalized)?;
        let identity = expected_identity(normalized)?;
        let policy_versions = RhiStatePolicyVersions::governed();
        if [
            policy_versions.configuration,
            policy_versions.state,
            policy_versions.admin,
            policy_versions.status,
            policy_versions.provider,
        ]
        .contains(&0)
        {
            return Err(RhiStateMetadataError::new(
                RhiStateMetadataErrorKind::Invariant,
            ));
        }
        Ok(Self {
            paths,
            database,
            configuration: configuration_digest,
            evidence_policy,
            identity,
            policy_versions,
        })
    }

    /// Returns the shared immutable database metadata.
    #[must_use]
    pub const fn database(&self) -> &ServiceDatabaseMetadata {
        &self.database
    }

    /// Returns the reopen identity derived from the immutable database metadata.
    #[must_use]
    pub fn database_identity(&self) -> ServiceDatabaseIdentity {
        self.database.identity()
    }

    /// Returns the normalized configuration digest.
    #[must_use]
    pub const fn configuration_digest(&self) -> RhiNormalizedConfigDigest {
        self.configuration
    }

    /// Returns the normalized evidence-policy digest.
    #[must_use]
    pub const fn evidence_policy_digest(&self) -> RhiEvidencePolicyDigest {
        self.evidence_policy
    }

    /// Returns the exact configured service identity binding.
    #[must_use]
    pub const fn expected_identity(&self) -> &RhiExpectedPublicIdentity {
        &self.identity
    }

    /// Returns the exact governed policy versions.
    #[must_use]
    pub const fn policy_versions(&self) -> RhiStatePolicyVersions {
        self.policy_versions
    }

    pub(crate) fn matches_runtime(&self, runtime: &RhiRuntimeContext) -> bool {
        ServiceSqlitePaths::from_runtime_context(runtime.context())
            .is_ok_and(|paths| paths == self.paths)
    }

    pub(crate) const fn paths(&self) -> &ServiceSqlitePaths {
        &self.paths
    }

    pub(crate) fn matches_configuration(&self, configuration: &RhiConfigDocumentV1) -> bool {
        normalized_config_digest(configuration.profile(), configuration.normalized())
            .is_ok_and(|digest| digest == self.configuration)
            && evidence_policy_digest(configuration.normalized())
                .is_ok_and(|digest| digest == self.evidence_policy)
            && expected_identity(configuration.normalized())
                .is_ok_and(|identity| identity == self.identity)
    }
}

impl fmt::Debug for RhiStateMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStateMetadata")
            .field("database", &self.database)
            .field("configuration", &self.configuration)
            .field("evidence_policy", &self.evidence_policy)
            .field("identity", &"[redacted]")
            .field("policy_versions", &self.policy_versions)
            .field("paths", &"[redacted]")
            .finish()
    }
}

/// Stable source-free class for invalid RHI state metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiStateMetadataErrorKind {
    Profile,
    Paths,
    Configuration,
    EvidencePolicy,
    Identity,
    Database,
    Invariant,
}

/// Source-free RHI state-metadata construction failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiStateMetadataError {
    kind: RhiStateMetadataErrorKind,
}

impl RhiStateMetadataError {
    const fn new(kind: RhiStateMetadataErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> RhiStateMetadataErrorKind {
        self.kind
    }
}

impl fmt::Display for RhiStateMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiStateMetadataErrorKind::Profile => "RHI configuration profile is inconsistent",
            RhiStateMetadataErrorKind::Paths => "RHI state metadata paths are invalid",
            RhiStateMetadataErrorKind::Configuration => {
                "RHI normalized configuration identity is invalid"
            }
            RhiStateMetadataErrorKind::EvidencePolicy => {
                "RHI normalized evidence-policy identity is invalid"
            }
            RhiStateMetadataErrorKind::Identity => "RHI expected identity binding is invalid",
            RhiStateMetadataErrorKind::Database => "RHI database metadata is invalid",
            RhiStateMetadataErrorKind::Invariant => "RHI metadata contract is invalid",
        })
    }
}

impl fmt::Debug for RhiStateMetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStateMetadataError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiStateMetadataError {}

fn require_profile_binding(
    runtime: RhiBootstrapProfileV1,
    configuration: RhiConfigProfile,
) -> Result<(), RhiStateMetadataError> {
    let matches = match runtime {
        RhiBootstrapProfileV1::ServiceHost | RhiBootstrapProfileV1::Interactive => {
            configuration == RhiConfigProfile::Production
        }
        RhiBootstrapProfileV1::RepoLocal => configuration == RhiConfigProfile::RepoLocal,
    };
    matches
        .then_some(())
        .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Profile))
}

fn normalized_config_digest(
    profile: RhiConfigProfile,
    normalized: &Value,
) -> Result<RhiNormalizedConfigDigest, RhiStateMetadataError> {
    let bytes = serde_json::to_vec(normalized)
        .map_err(|_| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Configuration))?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Configuration))?;
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZED_CONFIG_DIGEST_DOMAIN);
    hasher.update([match profile {
        RhiConfigProfile::Production => 0,
        RhiConfigProfile::RepoLocal => 1,
    }]);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(RhiNormalizedConfigDigest(hasher.finalize().into()))
}

fn evidence_policy_digest(
    normalized: &Value,
) -> Result<RhiEvidencePolicyDigest, RhiStateMetadataError> {
    let relays = normalized
        .pointer("/relays")
        .and_then(Value::as_array)
        .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::EvidencePolicy))?;
    let mut relay_urls = BTreeMap::new();
    for relay in relays {
        let id = string(relay, "/id")?;
        let url = string(relay, "/url")?;
        if relay_urls.insert(id, url).is_some() {
            return Err(RhiStateMetadataError::new(
                RhiStateMetadataErrorKind::EvidencePolicy,
            ));
        }
    }

    let evidence = normalized
        .pointer("/evidence")
        .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::EvidencePolicy))?;
    let sources = evidence
        .pointer("/sources")
        .and_then(Value::as_array)
        .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::EvidencePolicy))?;
    let mut normalized_sources = Vec::with_capacity(sources.len());
    for source in sources {
        let relay_id = string(source, "/relay_id")?;
        let relay_url = relay_urls
            .get(relay_id)
            .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::EvidencePolicy))?;
        normalized_sources.push(json!({
            "completion": "nostr_eose_before_deadline",
            "deadline_ms": integer(source, "/deadline_ms")?,
            "kind": string(source, "/kind")?,
            "lookback_seconds": integer(source, "/lookback_seconds")?,
            "overlap_seconds": integer(source, "/overlap_seconds")?,
            "relay_id": relay_id,
            "relay_url": relay_url,
            "required": boolean(source, "/required")?,
            "selector": string(source, "/selector")?,
            "source_id": string(source, "/source_id")?,
        }));
    }
    normalized_sources
        .sort_by(|left, right| left["source_id"].as_str().cmp(&right["source_id"].as_str()));
    let policy = json!({
        "contract": string(evidence, "/contract")?,
        "contract_version": integer(evidence, "/contract_version")?,
        "policy_id": string(evidence, "/policy_id")?,
        "sources": normalized_sources,
    });
    let bytes = serde_json::to_vec(&policy)
        .map_err(|_| RhiStateMetadataError::new(RhiStateMetadataErrorKind::EvidencePolicy))?;
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_POLICY_DIGEST_DOMAIN);
    hasher.update(bytes);
    Ok(RhiEvidencePolicyDigest(hasher.finalize().into()))
}

fn expected_identity(
    normalized: &Value,
) -> Result<RhiExpectedPublicIdentity, RhiStateMetadataError> {
    normalized
        .pointer("/identity/service/expected_public_key")
        .and_then(Value::as_str)
        .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::Identity))
        .and_then(RhiExpectedPublicIdentity::from_hex)
}

fn string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, RhiStateMetadataError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::EvidencePolicy))
}

fn integer(value: &Value, pointer: &str) -> Result<u64, RhiStateMetadataError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::EvidencePolicy))
}

fn boolean(value: &Value, pointer: &str) -> Result<bool, RhiStateMetadataError> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| RhiStateMetadataError::new(RhiStateMetadataErrorKind::EvidencePolicy))
}
