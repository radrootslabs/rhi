#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod adapters;
mod cli_v1;
mod config_v1;
pub mod features;
pub mod host_identity;
pub mod identity_storage;
mod runtime_context;
mod state_catalog;

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
