#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod adapters;
mod cli_v1;
mod config_v1;
pub mod features;
mod identity_credential;
mod identity_envelope;
mod runtime_context;
mod state_catalog;
mod state_host;
mod state_metadata;
mod state_repository;

pub use cli_v1::{
    RhiBootstrapProfileV1, RhiCliInvocationV1, RhiCliOutputModeV1, RhiCliV1Error,
    RhiCliV1ErrorKind, RhiCommandV1, RhiConfigCommandV1, RhiIdentityCommandV1, RhiMetricsCommandV1,
    RhiPresenceCommandV1, RhiPublicationCommandV1, RhiReconciliationCommandV1, RhiSourcesCommandV1,
    RhiStateCommandV1, RhiTradeCommandV1, parse_rhi_cli_v1_from,
};
pub use config_v1::{
    RHI_CONFIG_DOCUMENT_MAX_UTF8_BYTES, RHI_CONFIG_EFFECTIVE_MAX_UTF8_BYTES, RHI_CONFIG_SCHEMA,
    RHI_CONFIG_SCHEMA_VERSION, RhiConfigDefaultAuthority, RhiConfigDocumentV1, RhiConfigProfile,
    RhiConfigV1Error, RhiConfigV1ErrorKind, RhiConfigValueSource, RhiEffectiveConfigV1,
    RhiRuntimeThreadLimitsV1, parse_rhi_config_v1,
};
pub use identity_credential::{
    RHI_WRAPPING_CREDENTIAL_ARTIFACT_BYTES, RHI_WRAPPING_CREDENTIAL_CONTRACT_VERSION,
    RhiCredentialResolutionError, RhiCredentialResolutionErrorKind,
    resolve_rhi_wrapping_credential,
};
pub use identity_envelope::{
    RHI_ENCRYPTED_IDENTITY_BACKUP_INCLUDED, RHI_ENCRYPTED_IDENTITY_ENVELOPE_CONTRACT_VERSION,
    RHI_ENCRYPTED_IDENTITY_ENVELOPE_MAX_BYTES, RhiDecryptedIdentity,
    RhiEncryptedIdentityEnvelopeError, RhiEncryptedIdentityEnvelopeErrorKind,
    RhiEncryptedIdentityProvisioningMaterial, RhiIdentityEnvelopeBinding, RhiIdentityProviderKind,
    RhiIdentityRole, RhiWrappingCredential, open_rhi_encrypted_identity,
    provision_rhi_encrypted_identity,
};
pub use radroots_runtime_paths::{
    INSTANCE_ID_MAX_BYTES, InstanceId, RadrootsHostEnvironment, RadrootsPathProfile,
    RadrootsPathResolver, RadrootsPlatform, RadrootsServiceInstanceArtifacts, RuntimeContext,
    RuntimeContextSource, ServiceId,
};
pub use runtime_context::{
    RhiRuntimeContext, RhiRuntimeContextError, RhiRuntimeContextErrorKind,
    resolve_rhi_runtime_context,
};
pub use state_catalog::{
    RHI_MIGRATION_CATALOG_SHA256, RHI_STATE_SCHEMA_CATALOG_SHA256, RHI_STATE_SCHEMA_VERSION,
    RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_1_SHA256,
    RhiStateCatalogError, RhiStateCatalogErrorKind, rhi_migration_catalog, rhi_schema_catalog,
    validate_rhi_state_catalogs,
};
pub use state_host::{
    RhiStateHost, RhiStateHostError, RhiStateHostErrorKind, RhiStateHostMode, initialize_rhi_state,
    open_rhi_state_inspection, open_rhi_state_read_write,
};
pub use state_metadata::{
    RHI_ADMIN_CONTRACT_VERSION, RHI_PROVIDER_CONTRACT_VERSION, RHI_STATE_APPLICATION_ID,
    RHI_STATUS_CONTRACT_VERSION, RhiEvidencePolicyDigest, RhiExpectedPublicIdentity,
    RhiNormalizedConfigDigest, RhiStateMetadata, RhiStateMetadataError, RhiStateMetadataErrorKind,
    RhiStatePolicyVersions,
};
pub use state_repository::{
    RHI_STATE_REPOSITORY_CONTRACT_VERSION, RHI_STATE_REPOSITORY_COUNT,
    RhiDesiredPresenceRepository, RhiDirtyTradeRepository, RhiEvidenceManifestRepository,
    RhiMutationRepository, RhiProjectionRepository, RhiProvenanceRepository,
    RhiPublicationAttemptRepository, RhiPublicationOutboxRepository,
    RhiPublicationTargetRepository, RhiReconciliationAttemptRepository,
    RhiReconciliationJobRepository, RhiReportRepository, RhiSignedAttestationEventRepository,
    RhiSignedEventRepository, RhiSourceCompletionRepository, RhiSourceCursorRepository,
    RhiSourceRepository, RhiStateRepositories, RhiStateRepositoryDescriptor,
    RhiStateRepositoryKind, RhiStateRepositoryWriteClass, RhiSupersessionRepository,
    rhi_state_repository_descriptors,
};
