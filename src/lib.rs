#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![forbid(unsafe_code)]
#![doc = include_str!("../README")]

mod adapters;
mod admin_v1;
mod cli_bootstrap;
mod cli_v1;
mod config_loader;
mod config_v1;
mod diagnostics_v1;
mod doctor_v1;
mod features;
mod identity_credential;
mod identity_envelope;
mod operations_v1;
mod presence_desired;
mod presence_publication;
mod process_result_v1;
mod process_v1;
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
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod runtime_admin;
mod runtime_context;
mod runtime_foundation;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod runtime_graph;
mod runtime_signal;
mod source_ingest;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod state_admin;
mod state_catalog;
mod state_config;
mod state_host;
mod state_maintenance;
mod state_metadata;
mod state_repository;
mod state_trade;
mod status_v1;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod system_doctor;
mod trade_ingest;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod transport_nostr_adapter;

pub use adapters::nostr::event::NostrEventAdapter;
pub use admin_v1::{
    RhiAdminCancellationToken, RhiAdminDocumentError, RhiAdminDocumentErrorKind, RhiAdminFuture,
    RhiAdminHandler, RhiAdminHandlerError, RhiAdminHandlerErrorKind, RhiAdminMethod,
    RhiAdminRequestDocument, RhiAdminResponseDocument, RhiAdminRoute, RhiAdminRouterError,
    RhiAdminServerError, RhiAdminServerErrorKind,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use admin_v1::{RhiAdminRouter, RhiAdminServer, RhiBoundAdminServer, build_rhi_admin_router};
pub use cli_v1::{
    RhiBootstrapProfileV1, RhiCliAdminOperationV1, RhiCliExecutionPlanV1, RhiCliInvocationV1,
    RhiCliOfflineOperationV1, RhiCliOutputModeV1, RhiCliPrimaryAuthorityV1, RhiCliV1Error,
    RhiCliV1ErrorKind, RhiCommandV1, RhiConfigApplyArgsV1, RhiConfigCommandV1,
    RhiIdentityCommandV1, RhiMetricsCommandV1, RhiPageQueryArgsV1, RhiPresenceCommandV1,
    RhiPresenceMutationArgsV1, RhiPublicationCommandV1, RhiPublicationRetryArgsV1,
    RhiReconciliationCommandV1, RhiReconciliationRefreshArgsV1, RhiSourcesCommandV1,
    RhiStateBackupArgsV1, RhiStateCommandV1, RhiStateRestoreArgsV1, RhiTradeArgsV1,
    RhiTradeCommandV1, RhiTradePageArgsV1, parse_rhi_cli_v1_from, plan_rhi_cli_v1,
};
pub use config_loader::{
    RhiConfigLoadError, RhiConfigLoadErrorKind, initialize_rhi_config_document,
    load_rhi_config_candidate, load_rhi_config_document,
};
pub use config_v1::{
    RHI_CONFIG_DOCUMENT_MAX_UTF8_BYTES, RHI_CONFIG_EFFECTIVE_MAX_UTF8_BYTES, RHI_CONFIG_SCHEMA,
    RHI_CONFIG_SCHEMA_VERSION, RhiConfigDefaultAuthority, RhiConfigDocumentV1, RhiConfigProfile,
    RhiConfigV1Error, RhiConfigV1ErrorKind, RhiConfigValueSource, RhiEffectiveConfigV1,
    RhiRuntimeThreadLimitsV1, parse_rhi_config_v1,
};
pub use diagnostics_v1::{
    RHI_DIAGNOSTICS_CONTRACT_VERSION, RHI_LOG_RECORD_MAX_UTF8_BYTES, RhiLogEvent, RhiLogLevel,
    RhiLogRecord,
};
pub use doctor_v1::{
    RHI_DOCTOR_CHECK_COUNT, RHI_DOCTOR_CONTRACT_VERSION, RHI_DOCTOR_REPORT_MAX_UTF8_BYTES,
    RHI_DOCTOR_SUMMARY_MAX_UTF8_BYTES, RhiDoctorAggregateStatus, RhiDoctorCheckDefinition,
    RhiDoctorCheckId, RhiDoctorCheckResult, RhiDoctorCheckStatus, RhiDoctorError,
    RhiDoctorErrorKind, RhiDoctorFuture, RhiDoctorObservation, RhiDoctorProbe,
    RhiDoctorRemediationCode, RhiDoctorReport, rhi_doctor_check_definitions, run_rhi_doctor,
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
pub use operations_v1::{
    RHI_LIVEZ_PATH, RHI_METRICS_PATH, RHI_OPERATIONS_CONTRACT_VERSION, RHI_READYZ_PATH,
    RhiBoundOperationsServer, RhiOperationsCancellationToken, RhiOperationsError,
    RhiOperationsErrorKind, RhiOperationsServer,
};
pub use presence_desired::{
    RHI_PRESENCE_DESIRED_CONTRACT_VERSION, RHI_PRESENCE_DESIRED_MAX_TARGETS,
    RhiPresenceDesiredAuthority, RhiPresenceDesiredCommitOutcome, RhiPresenceDesiredError,
    RhiPresenceDesiredErrorKind, RhiPresenceDesiredMode, RhiPresenceDesiredState,
    RhiPresenceDocumentKind, RhiPresenceTarget, validate_rhi_presence_desired_authority,
};
pub use presence_publication::{
    RHI_PRESENCE_MAX_ATTEMPTS, RHI_PRESENCE_PUBLICATION_CONTRACT_VERSION,
    RHI_PRESENCE_SIGNED_EVENT_MAX_BYTES, RhiExactPresenceSink, RhiPreparedPresenceAttempt,
    RhiPresenceAttemptCommit, RhiPresenceAttemptId, RhiPresenceAttemptOutcome,
    RhiPresenceCommitOutcome, RhiPresenceLease, RhiPresenceLeaseOwner, RhiPresenceOutboxId,
    RhiPresenceOutboxState, RhiPresencePublicationError, RhiPresencePublicationErrorKind,
    RhiPresenceRetryDelayMilliseconds, RhiPresenceTargetState, RhiPresenceUnixMilliseconds,
    RhiSignedPresenceDocument, RhiSignedPresenceDocuments, build_rhi_signed_presence_documents,
    validate_rhi_signed_presence_documents,
};
pub use process_result_v1::RhiProcessResult;
pub use process_v1::{execute_rhi_cli_v1, execute_rhi_cli_v1_with_signal_source};
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
pub use runtime_signal::{RhiProcessSignal, RhiProcessSignalFuture, RhiProcessSignalSource};
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
    RHI_STATE_SCHEMA_VERSION_7_SHA256, RHI_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_8_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_8_SHA256,
    RHI_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_9_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_9_SHA256, RHI_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_10_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_10_SHA256,
    RHI_STATE_SCHEMA_VERSION_11_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_11_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_11_SHA256, RhiStateCatalogError, RhiStateCatalogErrorKind,
    rhi_migration_catalog, rhi_schema_catalog, validate_rhi_state_catalogs,
};
pub use state_config::{
    RHI_CONFIG_BINDING_MAX_GENERATIONS, RhiConfigApplyError, RhiConfigApplyErrorKind,
    RhiConfigApplyOutcome,
};
pub use state_host::{
    RhiStateHost, RhiStateHostError, RhiStateHostErrorKind, RhiStateHostMode,
    apply_rhi_configuration, initialize_rhi_state, open_rhi_state_inspection,
    open_rhi_state_inspection_from_config, open_rhi_state_read_write,
    open_rhi_state_read_write_from_config,
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
    RhiMutationRepository, RhiPresenceAttemptRepository, RhiPresenceOutboxRepository,
    RhiPresenceTargetRepository, RhiProjectionRepository, RhiProvenanceRepository,
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
pub use status_v1::{
    RHI_DETAILED_STATUS_MAX_UTF8_BYTES, RHI_STATUS_CACHE_CONTRACT_VERSION,
    RHI_STATUS_REASON_CODE_COUNT, RhiEvidenceTransportStatusV1, RhiIdentityHealthV1,
    RhiIntegrityStateV1, RhiPersistenceHealthV1, RhiPersistenceStatusV1, RhiPresenceStatusV1,
    RhiProviderHealthV1, RhiProviderStatusV1, RhiPublicationStatusV1, RhiReconciliationStatusV1,
    RhiServicePhase, RhiStatusBuildInfoV1, RhiStatusBuildMode, RhiStatusCommonV1,
    RhiStatusConfigurationIdentityV1, RhiStatusConfigurationSource, RhiStatusError,
    RhiStatusErrorKind, RhiStatusObservationV1, RhiStatusPublisher, RhiStatusReader,
    RhiStatusReasonCode, RhiStatusReasonCodes, RhiStatusSnapshot, RhiStatusUnixSeconds,
    RhiTransportHealthV1, rhi_status_cache,
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
