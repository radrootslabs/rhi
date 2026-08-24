#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![forbid(unsafe_code)]
#![doc = include_str!("../README")]

mod adapters;
mod cli_v1;
mod config_v1;
mod features;
mod identity_credential;
mod identity_envelope;
mod publication;
mod publication_attempt;
mod publication_execution;
mod publication_submission;
mod reconciliation_attempt;
mod reconciliation_attestation;
mod reconciliation_commit;
mod reconciliation_finalization;
mod reconciliation_finalization_commit;
mod reconciliation_job;
mod reconciliation_manifest;
mod reconciliation_reducer;
mod reconciliation_replay;
mod runtime_adapters;
mod runtime_context;
mod runtime_foundation;
mod source_ingest;
mod state_catalog;
mod state_config;
mod state_host;
mod state_maintenance;
mod state_metadata;
mod state_repository;
mod state_trade;
mod trade_ingest;

pub use adapters::nostr::event::NostrEventAdapter;
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
pub use features::trade_agreement_attestation::{
    RHI_AGREEMENT_ATTESTATION_PROOF_SYSTEM_LOCAL_STATEMENT_HASH,
    RHI_AGREEMENT_ATTESTATION_PROTOCOL_ID, RHI_AGREEMENT_ATTESTATION_REPORT_VERSION,
    TradeAgreementAttestationBackend, TradeAgreementAttestationError,
    TradeAgreementAttestationErrorKind, TradeAgreementAttestationPolicy,
    TradeAgreementAttestationReportV1, TradeAgreementAttestationStatementV1,
    TradeAgreementAttestationValidatorSetBinding, attest_projection_claim,
    trade_mutation_subscription_kinds,
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
pub use publication::{
    RHI_PUBLICATION_CONTRACT_VERSION, RHI_PUBLICATION_MAX_ATTEMPTS, RHI_PUBLICATION_MAX_TARGETS,
    RhiPublicationAuthority, RhiPublicationError, RhiPublicationErrorKind, RhiPublicationMode,
    RhiPublicationRetryPolicy, RhiPublicationTarget,
};
pub use publication_attempt::{
    RHI_PUBLICATION_ATTEMPT_EVIDENCE_CONTRACT_VERSION, RHI_PUBLICATION_ATTEMPT_NUMBER_MAXIMUM,
    RHI_PUBLICATION_TARGET_ORDINAL_MAXIMUM, RhiPublicationAttemptEvidence,
    RhiPublicationAttemptEvidenceError, RhiPublicationAttemptEvidenceErrorKind,
    RhiPublicationAttemptId, RhiPublicationAttemptOutcome, RhiPublicationTargetState,
    RhiPublicationUnixMilliseconds,
};
pub use publication_execution::{
    RHI_PUBLICATION_EXECUTION_CONTRACT_VERSION, RhiExactPublicationSink,
    RhiPreparedPublicationAttempt, RhiPublicationAttemptCommit, RhiPublicationExecutionError,
    RhiPublicationExecutionErrorKind, RhiPublicationLease, RhiPublicationLeaseOwner,
    RhiPublicationOutboxState, RhiPublicationRetryDelayMilliseconds,
};
pub use publication_submission::{
    RHI_PUBLICATION_SUBMISSION_CONTRACT_VERSION, RhiCommittedPublication, RhiPublicationOutboxId,
    RhiPublicationSubmissionError, RhiPublicationSubmissionErrorKind,
};
pub use radroots_event::id::TradeId;
pub use radroots_runtime_paths::{
    INSTANCE_ID_MAX_BYTES, InstanceId, RadrootsHostEnvironment, RadrootsPathProfile,
    RadrootsPathResolver, RadrootsPlatform, RadrootsServiceInstanceArtifacts, RuntimeContext,
    RuntimeContextSource, ServiceId,
};
pub use radroots_service_host::{
    EntropyError, EntropySource, MonotonicClock, MonotonicClockError, MonotonicDeadline,
    MonotonicTime, UnixTimeSeconds, WallClock, WallClockError,
};
pub use reconciliation_attempt::{
    RHI_RECONCILIATION_ATTEMPT_CONTRACT_VERSION, RHI_RECONCILIATION_ATTEMPT_MAX_SOURCES,
    RhiReconciliationAttemptError, RhiReconciliationAttemptErrorKind, RhiReconciliationAttemptId,
    RhiReconciliationAttemptPlan, RhiReconciliationAttemptResults, RhiReconciliationSourceRequest,
    RhiReconciliationSourceRequestId, RhiReconciliationSourceResult,
    RhiReconciliationSourceSelectorDigest,
};
pub use reconciliation_attestation::{
    RHI_RECONCILIATION_ATTESTATION_CONTRACT_VERSION,
    RHI_RECONCILIATION_SIGNED_ATTESTATION_MAX_BYTES, RhiEvidenceAttestationSupersession,
    RhiReconciliationAttestationError, RhiReconciliationAttestationErrorKind,
    RhiSignedEvidenceAttestation, build_rhi_signed_evidence_attestation,
};
pub use reconciliation_commit::{
    RHI_RECONCILIATION_COMMIT_CONTRACT_VERSION, RhiReconciliationCommitError,
    RhiReconciliationCommitErrorKind, RhiReconciliationSourceCommitOutcome,
};
pub use reconciliation_finalization::{
    RHI_RECONCILIATION_FINALIZATION_CONTRACT_VERSION, RhiReconciliationFinalizationError,
    RhiReconciliationFinalizationErrorKind, RhiReconciliationFinalizationFence,
};
pub use reconciliation_finalization_commit::{
    RHI_RECONCILIATION_FINALIZATION_COMMIT_CONTRACT_VERSION,
    RhiReconciliationFinalizationCommitError, RhiReconciliationFinalizationCommitErrorKind,
    RhiReconciliationFinalizationCommitOutcome,
};
pub use reconciliation_job::{
    RHI_RECONCILIATION_JOB_CONTRACT_VERSION, RHI_RECONCILIATION_JOB_MAX_ACTIVE,
    RhiReconciliationJob, RhiReconciliationJobError, RhiReconciliationJobErrorKind,
    RhiReconciliationJobId, RhiReconciliationJobPolicy, RhiReconciliationJobState,
    RhiReconciliationLease, RhiReconciliationLeaseOwner, RhiReconciliationRetryDelayMilliseconds,
    RhiReconciliationScheduleOutcome, RhiReconciliationUnixMilliseconds,
};
pub use reconciliation_manifest::{
    RHI_RECONCILIATION_MANIFEST_CONTRACT_VERSION, RhiReconciliationManifest,
    RhiReconciliationManifestError, RhiReconciliationManifestErrorKind,
    RhiReconciliationScopePrerequisites,
};
pub use reconciliation_reducer::{
    RHI_RECONCILIATION_OUTCOME_CONTRACT_VERSION, RHI_RECONCILIATION_REDUCER_CONTRACT_VERSION,
    RhiReconciliationCoverage, RhiReconciliationEvaluation, RhiReconciliationOutcome,
    RhiReconciliationProjection, RhiReconciliationReasonCode, RhiReconciliationReducerError,
    RhiReconciliationReducerErrorKind, evaluate_rhi_reconciliation_claim,
    reduce_rhi_reconciliation_manifest,
};
pub use reconciliation_replay::{
    RHI_RECONCILIATION_REPLAY_CONTRACT_VERSION, RhiReconciliationReplayError,
    RhiReconciliationReplayErrorKind, RhiReconciliationSourceCursorEvidence,
    RhiReconciliationSourceReplay, RhiReconciliationSourceReplayId,
    RhiReconciliationSourceReplayPlan,
};
pub use runtime_adapters::{
    CanonicalRhiCredentialAccess, CanonicalRhiIdentityAccess, RHI_RUNTIME_ADAPTER_CONTRACT_VERSION,
    RHI_RUNTIME_JITTER_MAX_ENTROPY_DRAWS, RHI_RUNTIME_JITTER_MAX_MILLISECONDS, RhiCredentialAccess,
    RhiIdentityAccess, RhiIdentityCredentialAdapters, RhiJitterBoundMilliseconds,
    RhiJitterMilliseconds, RhiRuntimeAdapterError, RhiRuntimeAdapterErrorKind, RhiRuntimeAdapters,
    RhiTimeEntropyAdapters, RhiTransportAdapters,
};
pub use runtime_context::{
    RhiRuntimeContext, RhiRuntimeContextError, RhiRuntimeContextErrorKind,
    resolve_rhi_runtime_context,
};
pub use runtime_foundation::{
    RHI_RUNTIME_FOUNDATION_CONTRACT_VERSION, RhiRuntimeFoundation, RhiRuntimeFoundationError,
    RhiRuntimeFoundationErrorKind, RhiRuntimePrerequisite, RhiRuntimeReadiness,
    RhiRuntimeReadinessReason, open_rhi_runtime_foundation,
};
pub use source_ingest::{
    RHI_TRADE_SOURCE_INGEST_CONTRACT_VERSION, RHI_TRADE_SOURCE_RESULT_MAX_BYTES,
    RHI_TRADE_SOURCE_RESULT_MAX_EVENTS, RhiTradeDirtyGeneration, RhiTradeSourceAttempt,
    RhiTradeSourceCompletion, RhiTradeSourceCursor, RhiTradeSourceIngestError,
    RhiTradeSourceIngestErrorKind, RhiTradeSourceIngestOutcome, ingest_rhi_trade_source,
};
pub use state_catalog::{
    RHI_MIGRATION_CATALOG_SHA256, RHI_STATE_BASE_SCHEMA_VERSION, RHI_STATE_SCHEMA_CATALOG_SHA256,
    RHI_STATE_SCHEMA_VERSION, RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_1_SHA256, RHI_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_2_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_2_SHA256,
    RHI_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_3_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_3_SHA256, RHI_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_4_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_4_SHA256,
    RHI_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_5_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_5_SHA256, RHI_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_6_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_6_SHA256,
    RHI_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_7_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_7_SHA256, RhiStateCatalogError, RhiStateCatalogErrorKind,
    rhi_migration_catalog, rhi_schema_catalog, validate_rhi_state_catalogs,
};
pub use state_config::{
    RHI_CONFIG_BINDING_MAX_GENERATIONS, RhiConfigApplyError, RhiConfigApplyErrorKind,
    RhiConfigApplyOutcome,
};
pub use state_host::{
    RhiStateHost, RhiStateHostError, RhiStateHostErrorKind, RhiStateHostMode,
    apply_rhi_configuration, initialize_rhi_state, open_rhi_state_inspection,
    open_rhi_state_read_write, open_rhi_state_read_write_from_config,
};
pub use state_maintenance::{
    RhiStagedStateRestore, RhiStateMaintenanceError, RhiStateMaintenanceErrorKind,
    RhiVerifiedStateBackup, finalize_rhi_state_restore, stage_rhi_state_restore,
    verify_rhi_state_backup,
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
pub use state_trade::{
    RHI_TRADE_EVIDENCE_PERSISTENCE_CONTRACT_VERSION, RhiTradeEvidencePersistenceError,
    RhiTradeEvidencePersistenceErrorKind, RhiTradeEvidencePersistenceOutcome,
    RhiTradeSourceObservation,
};
pub use trade_ingest::{
    RHI_TRADE_EVENT_EXTRA_FIELD_MAX_COUNT, RHI_TRADE_EVENT_EXTRA_JSON_MAX_BYTES,
    RHI_TRADE_EVENT_ID_MAX_BYTES, RHI_TRADE_EVENT_PUBLIC_KEY_MAX_BYTES,
    RHI_TRADE_EVENT_SIGNATURE_MAX_BYTES, RHI_TRADE_INGEST_CONTRACT_VERSION,
    RhiAdmittedTradeMutationEvent, RhiTradeMutationAdmissionError,
    RhiTradeMutationAdmissionErrorKind, RhiTradeMutationAdmissionLimits,
    RhiTradeMutationAuthoredTimePolicy, RhiTradeMutationObservedAtUnixSeconds,
    admit_rhi_trade_mutation_event,
};
