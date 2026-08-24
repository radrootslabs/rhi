#![forbid(unsafe_code)]

const MANIFEST: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README");
const AGENTS: &str = include_str!("../AGENTS.md");
const ROOT: &str = include_str!("../src/lib.rs");
const ADMIN: &str = include_str!("../src/admin_v1.rs");
const ADAPTERS: &str = include_str!("../src/adapters/mod.rs");
const NOSTR_ADAPTERS: &str = include_str!("../src/adapters/nostr/mod.rs");
const FEATURES: &str = include_str!("../src/features/mod.rs");
const RUNTIME_ADAPTERS: &str = include_str!("../src/runtime_adapters.rs");
const RUNTIME_ADAPTER_CONTRACT: &str =
    include_str!("../contracts/services_hardening/runtime_adapters.v1.json");
const RUNTIME_FOUNDATION: &str = include_str!("../src/runtime_foundation.rs");
const PRESENCE_DESIRED: &str = include_str!("../src/presence_desired.rs");
const PRESENCE_DESIRED_CONTRACT: &str =
    include_str!("../contracts/services_hardening/presence_desired_state.v1.json");
const PRESENCE_PUBLICATION: &str = include_str!("../src/presence_publication.rs");
const PRESENCE_PUBLICATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/presence_publication.v1.json");
const PUBLICATION: &str = include_str!("../src/publication.rs");
const PUBLICATION_ATTEMPT: &str = include_str!("../src/publication_attempt.rs");
const PUBLICATION_ATTEMPT_CONTRACT: &str =
    include_str!("../contracts/services_hardening/publication_attempt_evidence.v1.json");
const PUBLICATION_EXECUTION: &str = include_str!("../src/publication_execution.rs");
const PUBLICATION_EXECUTION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/publication_execution.v1.json");
const PUBLICATION_WAVE_QUALIFICATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/publication_wave_qualification.v1.json");
const PUBLICATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/publication_outbox.v1.json");
const PUBLICATION_SUBMISSION: &str = include_str!("../src/publication_submission.rs");
const PUBLICATION_SUBMISSION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/publication_submission.v1.json");
const RECONCILIATION_ATTEMPTS: &str = include_str!("../src/reconciliation_attempt.rs");
const RECONCILIATION_COMMIT: &str = include_str!("../src/reconciliation_commit.rs");
const RECONCILIATION_ATTESTATION: &str = include_str!("../src/reconciliation_attestation.rs");
const RECONCILIATION_FINALIZATION: &str = include_str!("../src/reconciliation_finalization.rs");
const RECONCILIATION_FINALIZATION_COMMIT: &str =
    include_str!("../src/reconciliation_finalization_commit.rs");
const RECONCILIATION_MANIFEST: &str = include_str!("../src/reconciliation_manifest.rs");
const RECONCILIATION_REDUCER: &str = include_str!("../src/reconciliation_reducer.rs");
const RECONCILIATION_JOBS: &str = include_str!("../src/reconciliation_job.rs");
const RECONCILIATION_REPLAY: &str = include_str!("../src/reconciliation_replay.rs");
const RECONCILIATION_ATTEMPT_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_attempts.v1.json");
const RECONCILIATION_REPLAY_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_replay.v1.json");
const RECONCILIATION_COMMIT_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_commit.v1.json");
const RECONCILIATION_ATTESTATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_attestation.v1.json");
const RECONCILIATION_FINALIZATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_finalization.v1.json");
const RECONCILIATION_FINALIZATION_COMMIT_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_finalization_commit.v1.json");
const RECONCILIATION_MANIFEST_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_manifest.v1.json");
const RECONCILIATION_REDUCER_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_reducer.v1.json");
const RECONCILIATION_OUTCOME_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_outcome.v1.json");
const RUNTIME_FOUNDATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/runtime_foundation.v1.json");
const TRADE_INGEST_CONTRACT: &str =
    include_str!("../contracts/services_hardening/trade_ingest.v1.json");
const TRADE_EVIDENCE_PERSISTENCE_CONTRACT: &str =
    include_str!("../contracts/services_hardening/trade_evidence_persistence.v1.json");
const TRADE_SOURCE_INGEST_CONTRACT: &str =
    include_str!("../contracts/services_hardening/trade_source_ingest.v1.json");
const PUBLIC_API: &str = include_str!("../contracts/api_baselines/rhi.txt");
const SOURCES: &[&str] = &[
    include_str!("../src/adapters/nostr/event.rs"),
    include_str!("../src/admin_v1.rs"),
    include_str!("../src/cli_v1.rs"),
    include_str!("../src/config_v1.rs"),
    include_str!("../src/features/trade_agreement_attestation.rs"),
    include_str!("../src/identity_credential.rs"),
    include_str!("../src/identity_envelope.rs"),
    include_str!("../src/presence_desired.rs"),
    include_str!("../src/presence_publication.rs"),
    include_str!("../src/publication.rs"),
    include_str!("../src/publication_attempt.rs"),
    include_str!("../src/publication_execution.rs"),
    include_str!("../src/publication_submission.rs"),
    include_str!("../src/reconciliation_attempt.rs"),
    include_str!("../src/reconciliation_attestation.rs"),
    include_str!("../src/reconciliation_commit.rs"),
    include_str!("../src/reconciliation_finalization.rs"),
    include_str!("../src/reconciliation_finalization_commit.rs"),
    include_str!("../src/reconciliation_job.rs"),
    include_str!("../src/reconciliation_manifest.rs"),
    include_str!("../src/reconciliation_reducer.rs"),
    include_str!("../src/reconciliation_replay.rs"),
    include_str!("../src/runtime_context.rs"),
    include_str!("../src/runtime_adapters.rs"),
    include_str!("../src/runtime_foundation.rs"),
    include_str!("../src/source_ingest.rs"),
    include_str!("../src/state_catalog.rs"),
    include_str!("../src/state_config.rs"),
    include_str!("../src/state_host.rs"),
    include_str!("../src/state_maintenance.rs"),
    include_str!("../src/state_metadata.rs"),
    include_str!("../src/state_repository.rs"),
    include_str!("../src/state_trade.rs"),
    include_str!("../src/trade_ingest.rs"),
];

#[test]
fn package_identity_is_standalone_and_non_publishable() {
    assert!(MANIFEST.contains("name = \"rhi\""));
    assert!(MANIFEST.contains("repository = \"https://github.com/radrootslabs/rhi\""));
    assert!(MANIFEST.contains("readme = \"README\""));
    assert!(MANIFEST.contains("publish = false"));
    for forbidden in [
        "path = \"../",
        "path = \"../../",
        "enterprise/",
        "ops/",
        "foundation/",
    ] {
        assert!(
            !MANIFEST.contains(forbidden),
            "standalone package retains forbidden dependency surface {forbidden}"
        );
    }
}

#[test]
fn shared_runtime_contracts_are_curated_without_exposing_implementation_authority() {
    for forbidden in [
        "pub use radroots_service_sqlite",
        "pub mod service_host",
        "pub mod service_sqlite",
        "sqlx::Pool",
        "sqlx::SqliteConnection",
        "SystemEntropy",
        "SystemMonotonicClock",
        "SystemWallClock",
        "TaskSupervisor",
        "pub use radroots_service_host::CancellationToken",
    ] {
        assert!(
            !ROOT.contains(forbidden),
            "RHI public root exposes private host implementation {forbidden}"
        );
    }
    assert!(!PUBLIC_API.contains("radroots_service_host::HostError"));
    assert!(!PUBLIC_API.contains("radroots_service_host::TaskSupervisor"));
}

#[test]
fn state_catalog_module_is_private_and_root_api_is_curated() {
    for module in [
        "adapters",
        "admin_v1",
        "cli_v1",
        "config_v1",
        "features",
        "identity_credential",
        "identity_envelope",
        "presence_desired",
        "presence_publication",
        "publication",
        "publication_attempt",
        "publication_execution",
        "publication_submission",
        "reconciliation_attempt",
        "reconciliation_attestation",
        "reconciliation_commit",
        "reconciliation_finalization",
        "reconciliation_finalization_commit",
        "reconciliation_job",
        "reconciliation_manifest",
        "reconciliation_reducer",
        "reconciliation_replay",
        "runtime_context",
        "runtime_adapters",
        "runtime_foundation",
        "source_ingest",
        "state_catalog",
        "state_config",
        "state_host",
        "state_maintenance",
        "state_metadata",
        "state_repository",
        "state_trade",
        "trade_ingest",
    ] {
        assert!(
            ROOT.contains(&format!("mod {module};")),
            "RHI root is missing private module {module}"
        );
        assert!(
            !ROOT.contains(&format!("pub mod {module};")),
            "RHI root exposes module {module}"
        );
    }
    assert!(ADAPTERS.contains("pub(crate) mod nostr;"));
    assert!(NOSTR_ADAPTERS.contains("pub(crate) mod event;"));
    assert!(FEATURES.contains("pub(crate) mod trade_agreement_attestation;"));
    assert!(ROOT.contains("#![doc = include_str!(\"../README\")]"));
    for required in [
        "NostrEventAdapter",
        "TradeAgreementAttestationPolicy",
        "TradeAgreementAttestationErrorKind",
        "rhi_migration_catalog",
        "rhi_schema_catalog",
        "validate_rhi_state_catalogs",
        "RhiStateCatalogError",
        "RhiRuntimeAdapters",
        "RhiPublicationAuthority",
        "RhiPresenceDesiredAuthority",
        "RhiPresenceDesiredCommitOutcome",
        "RhiPresenceDesiredErrorKind",
        "RhiPresenceDesiredState",
        "validate_rhi_presence_desired_authority",
        "RHI_PRESENCE_DESIRED_CONTRACT_VERSION",
        "RhiExactPresenceSink",
        "RhiPreparedPresenceAttempt",
        "RhiPresenceAttemptCommit",
        "RhiPresenceAttemptOutcome",
        "RhiPresenceLease",
        "RhiPresenceLeaseOwner",
        "RhiPresenceOutboxState",
        "RhiPresencePublicationErrorKind",
        "RhiPresenceTargetState",
        "RhiSignedPresenceDocument",
        "RhiSignedPresenceDocuments",
        "build_rhi_signed_presence_documents",
        "validate_rhi_signed_presence_documents",
        "RHI_PRESENCE_PUBLICATION_CONTRACT_VERSION",
        "RhiAdminRoute",
        "RhiAdminRequestDocument",
        "RhiAdminResponseDocument",
        "RhiAdminHandler",
        "RhiAdminRouter",
        "RhiAdminServer",
        "RhiBoundAdminServer",
        "build_rhi_admin_router",
        "RhiPublicationErrorKind",
        "RhiPublicationMode",
        "RhiPublicationRetryPolicy",
        "RhiPublicationTarget",
        "RHI_PUBLICATION_CONTRACT_VERSION",
        "RhiPublicationAttemptEvidence",
        "RhiPublicationAttemptEvidenceErrorKind",
        "RhiPublicationAttemptId",
        "RhiPublicationAttemptOutcome",
        "RhiPublicationTargetState",
        "RhiPublicationUnixMilliseconds",
        "RHI_PUBLICATION_ATTEMPT_EVIDENCE_CONTRACT_VERSION",
        "RHI_PUBLICATION_ATTEMPT_NUMBER_MAXIMUM",
        "RHI_PUBLICATION_TARGET_ORDINAL_MAXIMUM",
        "RhiExactPublicationSink",
        "RhiPreparedPublicationAttempt",
        "RhiPublicationAttemptCommit",
        "RhiPublicationExecutionErrorKind",
        "RhiPublicationLease",
        "RhiPublicationLeaseOwner",
        "RhiPublicationOutboxState",
        "RhiPublicationRetryDelayMilliseconds",
        "RHI_PUBLICATION_EXECUTION_CONTRACT_VERSION",
        "RhiCommittedPublication",
        "RhiPublicationOutboxId",
        "RhiPublicationSubmissionErrorKind",
        "RHI_PUBLICATION_SUBMISSION_CONTRACT_VERSION",
        "RhiReconciliationAttemptPlan",
        "RhiReconciliationSourceRequest",
        "RhiReconciliationSourceResult",
        "RhiReconciliationAttemptResults",
        "RhiReconciliationSourceCommitOutcome",
        "RhiReconciliationCommitErrorKind",
        "RhiSignedEvidenceAttestation",
        "RhiEvidenceAttestationSupersession",
        "RhiReconciliationAttestationErrorKind",
        "RHI_RECONCILIATION_ATTESTATION_CONTRACT_VERSION",
        "RHI_RECONCILIATION_SIGNED_ATTESTATION_MAX_BYTES",
        "build_rhi_signed_evidence_attestation",
        "RhiReconciliationFinalizationFence",
        "RhiReconciliationFinalizationErrorKind",
        "RHI_RECONCILIATION_FINALIZATION_CONTRACT_VERSION",
        "RhiReconciliationFinalizationCommitOutcome",
        "RhiReconciliationFinalizationCommitErrorKind",
        "RHI_RECONCILIATION_FINALIZATION_COMMIT_CONTRACT_VERSION",
        "RhiReconciliationManifest",
        "RhiReconciliationManifestErrorKind",
        "RhiReconciliationScopePrerequisites",
        "RhiReconciliationProjection",
        "RhiReconciliationEvaluation",
        "RhiReconciliationCoverage",
        "RhiReconciliationOutcome",
        "RhiReconciliationReasonCode",
        "RHI_RECONCILIATION_OUTCOME_CONTRACT_VERSION",
        "RhiReconciliationReducerErrorKind",
        "evaluate_rhi_reconciliation_claim",
        "reduce_rhi_reconciliation_manifest",
        "RhiReconciliationSourceReplayPlan",
        "RhiReconciliationSourceReplay",
        "RhiReconciliationJobPolicy",
        "RhiReconciliationLease",
        "RhiTimeEntropyAdapters",
        "RhiTransportAdapters",
        "RhiCredentialAccess",
        "RhiIdentityAccess",
        "RhiRuntimeFoundation",
        "RhiRuntimeReadiness",
        "open_rhi_runtime_foundation",
        "apply_rhi_configuration",
        "RhiConfigApplyOutcome",
        "WallClock",
        "MonotonicClock",
        "EntropySource",
        "EntropyError",
        "WallClockError",
        "MonotonicClockError",
        "admit_rhi_trade_mutation_event",
        "RhiTradeMutationAdmissionLimits",
        "RhiAdmittedTradeMutationEvent",
        "RhiTradeEvidencePersistenceError",
        "RhiTradeEvidencePersistenceErrorKind",
        "RhiTradeEvidencePersistenceOutcome",
        "RhiTradeSourceObservation",
        "RHI_TRADE_EVIDENCE_PERSISTENCE_CONTRACT_VERSION",
        "ingest_rhi_trade_source",
        "RhiTradeDirtyGeneration",
        "RhiTradeSourceAttempt",
        "RhiTradeSourceCompletion",
        "RhiTradeSourceCursor",
        "RhiTradeSourceIngestError",
        "RhiTradeSourceIngestErrorKind",
        "RhiTradeSourceIngestOutcome",
        "RHI_TRADE_SOURCE_INGEST_CONTRACT_VERSION",
        "RHI_TRADE_SOURCE_RESULT_MAX_BYTES",
        "RHI_TRADE_SOURCE_RESULT_MAX_EVENTS",
    ] {
        assert!(
            ROOT.contains(required),
            "RHI root API is missing {required}"
        );
    }

    let public_modules = PUBLIC_API
        .lines()
        .filter(|line| line.starts_with("pub mod "))
        .collect::<Vec<_>>();
    assert_eq!(public_modules, ["pub mod rhi"]);
    assert!(PUBLIC_API.contains("pub struct rhi::NostrEventAdapter<'a>"));
    assert!(PUBLIC_API.contains("pub struct rhi::TradeAgreementAttestationError"));
    assert!(PUBLIC_API.contains("pub struct rhi::RhiPresenceDesiredAuthority"));
    assert!(PUBLIC_API.contains("pub struct rhi::RhiPresenceDesiredState"));
    assert!(PUBLIC_API.contains("pub enum rhi::RhiPresenceDesiredErrorKind"));
    assert!(PUBLIC_API.contains("pub struct rhi::RhiSignedPresenceDocument"));
    assert!(PUBLIC_API.contains("pub enum rhi::RhiPresencePublicationErrorKind"));
    assert!(!PUBLIC_API.contains("rhi::adapters::"));
    assert!(!PUBLIC_API.contains("rhi::features::"));
    assert!(!PUBLIC_API.contains("rhi::runtime_adapters::"));
    assert!(!PUBLIC_API.contains("rhi::publication::"));
    assert!(!PUBLIC_API.contains("rhi::publication_attempt::"));
    assert!(!PUBLIC_API.contains("rhi::publication_execution::"));
    assert!(!PUBLIC_API.contains("rhi::publication_submission::"));
    assert!(!PUBLIC_API.contains("rhi::presence_publication::"));
    assert!(!PUBLIC_API.contains("rhi::admin_v1::"));
}

#[test]
fn active_admin_boundary_hides_shared_transport_authority() {
    for required in [
        "pub struct RhiAdminRouter",
        "pub struct RhiAdminServer",
        "pub struct RhiBoundAdminServer",
        "pub trait RhiAdminHandler",
        "pub const COMMON: [Self; 7]",
        "pub const DOMAIN: [Self; 13]",
        "pub const ACTIVE: [Self; 20]",
    ] {
        assert!(
            ADMIN.contains(required),
            "missing common admin boundary `{required}`"
        );
    }
    for forbidden in [
        "pub fn into_inner",
        "pub fn router",
        "pub fn listener",
        "pub use radroots_service_host::AdminRouter",
        "pub use radroots_service_host::AdminServer",
        "pub use serde_json::Value",
    ] {
        assert!(!ROOT.contains(forbidden), "public root leaks `{forbidden}`");
        assert!(
            !PUBLIC_API.contains(forbidden),
            "API baseline leaks `{forbidden}`"
        );
    }
}

#[test]
fn presence_desired_state_is_config_bound_durable_and_effect_free() {
    let contract: serde_json::Value =
        serde_json::from_str(PRESENCE_DESIRED_CONTRACT).expect("presence-desired-state contract");
    assert_eq!(contract["schema"], "radroots.rhi.presence-desired-state");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["authority"]["maximum_targets"], 32);
    assert_eq!(contract["durable_state"]["write_class"], "compare_and_swap");
    assert_eq!(contract["durable_state"]["rows"], "exactly_zero_or_one");
    assert_eq!(contract["effects"]["network"], false);
    assert_eq!(contract["effects"]["relay_io"], false);
    for required in [
        "pub fn validate_rhi_presence_desired_authority(",
        "require_current_config(transaction, authority).await?",
        "LIMIT 1",
        "LIMIT 2",
        "ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown",
    ] {
        assert!(
            PRESENCE_DESIRED.contains(required),
            "presence desired-state boundary is missing {required}"
        );
    }
    for forbidden in [
        "SystemTime",
        "OsRng",
        "thread_rng",
        "tokio::spawn",
        "std::net",
        "EventSink",
        "sign_nostr_event",
    ] {
        assert!(
            !PRESENCE_DESIRED.contains(forbidden),
            "presence desired-state boundary gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod presence_desired"));
    assert!(!PUBLIC_API.contains("rhi::presence_desired::"));
}

#[test]
fn presence_publication_is_typed_verified_durable_and_exact_byte_only() {
    let contract: serde_json::Value =
        serde_json::from_str(PRESENCE_PUBLICATION_CONTRACT).expect("presence-publication contract");
    assert_eq!(contract["schema"], "radroots.rhi.presence-publication");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["step"], 205);
    assert_eq!(contract["durable_workflow"]["schema_version"], 10);
    assert_eq!(
        contract["durable_workflow"]["exact_signed_bytes_committed_before_io"],
        true
    );
    assert_eq!(
        contract["durable_workflow"]["target_submitted_committed_before_io"],
        true
    );
    assert_eq!(
        contract["durable_workflow"]["remote_io_inside_sql_transaction"],
        false
    );
    assert_eq!(
        contract["durable_workflow"]["commit_outcome_unknown"],
        "caller_retains_sealed_exact_bytes_and_rereads_exact_identity_before_retry"
    );
    assert_eq!(
        contract["construction"]["validation_input"],
        "sealed_documents_and_public_desired_authority_only"
    );
    assert_eq!(
        contract["resource_bounds"]["maximum_signed_event_bytes"],
        32_768
    );
    assert_eq!(
        contract["resource_bounds"]["maximum_attempts_per_target"],
        100
    );
    assert_eq!(
        contract["resource_bounds"]["maximum_authored_unix_seconds"],
        i64::MAX
    );
    for required in [
        "AuthoredProfile::new(PROFILE_NAME)",
        "ApplicationHandlerSpec::new(APPLICATION_HANDLER_KINDS.to_vec())",
        "validate_signed_document(",
        "pub fn validate_rhi_signed_presence_documents(\n    documents: &RhiSignedPresenceDocuments,\n    authority: &RhiPresenceDesiredAuthority,\n)",
        "verify_id(&event)",
        "verify(&event)",
        "pub trait RhiExactPresenceSink: Send + Sync",
        "pub async fn commit_signed_presence(\n        &self,\n        documents: &RhiSignedPresenceDocuments,",
        "pub async fn claim_next_presence(",
        "pub async fn prepare_next_presence_target(",
        "pub async fn record_presence_outcome(",
        "pub async fn recover_one_expired_presence(",
        "pub async fn execute_next_presence(",
        "state = 'submitted'",
        "INSERT INTO presence_attempts",
        "sink.submit_exact(&prepared).await",
        "ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown",
    ] {
        assert!(
            PRESENCE_PUBLICATION.contains(required),
            "presence publication is missing {required}"
        );
    }
    for forbidden in [
        "SystemTime",
        "thread_rng",
        "OsRng",
        "tokio::spawn",
        "std::net",
        "std::fs",
        "SqliteConnection",
        "SqlitePool",
        "EventSink",
    ] {
        assert!(
            !PRESENCE_PUBLICATION.contains(forbidden),
            "presence publication gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod presence_publication"));
    assert!(!PUBLIC_API.contains("rhi::presence_publication::"));
}

#[test]
fn publication_authority_is_config_derived_sealed_and_effect_free() {
    let contract: serde_json::Value =
        serde_json::from_str(PUBLICATION_CONTRACT).expect("publication contract");
    assert_eq!(contract["schema"], "radroots.rhi.publication-outbox");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["state_schema_version"], 7);
    assert_eq!(contract["effects"]["sqlite_query_or_mutation"], false);
    assert_eq!(contract["effects"]["relay_or_network"], false);
    for required in [
        "pub fn from_config(config: &RhiConfigDocumentV1)",
        "RhiPublicationMode::Required",
        "RhiPublicationMode::Disabled",
        "target_set_digest(&targets)?",
        "authority_digest(",
    ] {
        assert!(
            PUBLICATION.contains(required),
            "publication authority is missing {required}"
        );
    }
    for forbidden in [
        "sqlx::",
        "std::fs",
        "std::net",
        "tokio::",
        "SystemTime",
        "thread_rng",
        "OsRng",
    ] {
        assert!(
            !PUBLICATION.contains(forbidden),
            "publication authority gained forbidden effect {forbidden}"
        );
    }
}

#[test]
fn committed_publication_is_bounded_exact_and_never_reconstructed() {
    let contract: serde_json::Value = serde_json::from_str(PUBLICATION_SUBMISSION_CONTRACT)
        .expect("publication-submission contract");
    assert_eq!(contract["schema"], "radroots.rhi.publication-submission");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["source"]["maximum_signed_event_bytes"], 32_768);
    assert_eq!(contract["retry_and_recovery"]["parse_event"], false);
    assert_eq!(contract["retry_and_recovery"]["reserialize_event"], false);
    assert_eq!(contract["retry_and_recovery"]["resign_event"], false);
    for required in [
        "pub async fn read_committed_publication(",
        "READ_COMMITTED_PUBLICATION_SQL",
        "length(event.canonical_event_json) BETWEEN 1 AND 32768",
        "Sha256::digest(&exact_signed_event_bytes)",
        "pub const fn exact_signed_event_bytes(&self) -> &[u8]",
    ] {
        assert!(
            PUBLICATION_SUBMISSION.contains(required),
            "committed publication is missing {required}"
        );
    }
    for forbidden in [
        "serde_json",
        "Nip01EventWire",
        "SignedEvent",
        "sign_nostr_event",
        "EventSink",
        "std::net",
        "tokio::spawn",
        "SystemTime",
        "pub(crate) fn from_committed_parts",
    ] {
        assert!(
            !PUBLICATION_SUBMISSION.contains(forbidden),
            "committed publication gained reconstruction or I/O authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod publication_submission"));
    assert!(!PUBLIC_API.contains("rhi::publication_submission::"));
}

#[test]
fn publication_attempt_evidence_is_closed_bounded_and_effect_free() {
    let contract: serde_json::Value =
        serde_json::from_str(PUBLICATION_ATTEMPT_CONTRACT).expect("publication-attempt contract");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.publication-attempt-evidence"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["bounds"]["target_ordinal"]["maximum"], 31);
    assert_eq!(contract["bounds"]["attempt_number"]["maximum"], 100);
    assert_eq!(
        contract["evidence"]["result_code"],
        "exact_closed_outcome_code"
    );
    assert_eq!(contract["effects"]["sqlite_read_or_mutation"], false);
    assert_eq!(contract["effects"]["relay_or_network"], false);
    for required in [
        "pub enum RhiPublicationTargetState",
        "pub enum RhiPublicationAttemptOutcome",
        "pub struct RhiPublicationAttemptEvidence",
        "publication.outbox_id()",
        "publication.event_sha256()",
        "RHI_PUBLICATION_TARGET_ORDINAL_MAXIMUM",
        "RHI_PUBLICATION_ATTEMPT_NUMBER_MAXIMUM",
    ] {
        assert!(
            PUBLICATION_ATTEMPT.contains(required),
            "publication-attempt evidence is missing {required}"
        );
    }
    for forbidden in [
        "sqlx::",
        "serde_json",
        "EventSink",
        "SystemTime",
        "std::fs",
        "std::net",
        "tokio::spawn",
    ] {
        assert!(
            !PUBLICATION_ATTEMPT.contains(forbidden),
            "publication-attempt evidence gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod publication_attempt"));
    assert!(!PUBLIC_API.contains("rhi::publication_attempt::"));
}

#[test]
fn publication_execution_is_sqlx_owned_exact_byte_and_fail_closed() {
    let contract: serde_json::Value = serde_json::from_str(PUBLICATION_EXECUTION_CONTRACT)
        .expect("publication-execution contract");
    assert_eq!(contract["schema"], "radroots.rhi.publication-execution");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(
        contract["storage_authority"],
        "single_service_sqlite_host_sqlx_transactions"
    );
    assert_eq!(
        contract["claim"]["authority"],
        "exact_current_required_authority_and_target_set"
    );
    assert_eq!(contract["attempt"]["remote_io_outside_transaction"], true);
    assert_eq!(contract["exact_byte_sink"]["parse"], false);
    assert_eq!(contract["exact_byte_sink"]["reserialize"], false);
    assert_eq!(
        contract["cancellation_and_recovery"]["after_durable_submitted"],
        "unknown_until_independent_evidence"
    );
    for required in [
        "pub trait RhiExactPublicationSink: Send + Sync",
        "pub async fn claim_next_publication(",
        "pub async fn prepare_next_publication_target(",
        "pub async fn record_publication_outcome(",
        "pub async fn recover_one_expired_publication(",
        "pub async fn execute_next_publication(",
        "read_committed(transaction, lease.outbox.id)",
        "state = 'submitted'",
        "INSERT INTO publication_attempts",
        "ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown",
    ] {
        assert!(
            PUBLICATION_EXECUTION.contains(required),
            "publication execution is missing {required}"
        );
    }
    for forbidden in [
        "radroots_event_codec",
        "Nip01EventWire",
        "DeliveryPayload",
        "EventSink",
        "serde_json",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "tokio::spawn",
        "SqliteConnection",
        "SqlitePool",
    ] {
        assert!(
            !PUBLICATION_EXECUTION.contains(forbidden),
            "publication execution gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod publication_execution"));
    assert!(!PUBLIC_API.contains("rhi::publication_execution::"));
    let qualification: serde_json::Value =
        serde_json::from_str(PUBLICATION_WAVE_QUALIFICATION_CONTRACT)
            .expect("publication-wave qualification contract");
    assert_eq!(qualification["step"], 203);
    assert_eq!(qualification["state_schema_version"], 8);
    assert_eq!(
        qualification["invariants"]["production_failpoint_surface"],
        false
    );
}

#[test]
fn reconciliation_attestation_is_typed_signed_verified_and_effect_free() {
    let contract: serde_json::Value = serde_json::from_str(RECONCILIATION_ATTESTATION_CONTRACT)
        .expect("reconciliation-attestation contract");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.reconciliation-attestation"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["event"]["kind"], 3_441);
    assert_eq!(contract["effects"]["sqlite"], false);
    assert_eq!(contract["effects"]["publication"], false);
    for required in [
        "RadrootsRhiEvidenceReportV1::new(",
        "AuthoredEventBody::from_rhi_evidence_attestation(",
        "AuthoredEventPlan::bind(",
        "sign_nostr_event(unsigned, auxiliary)",
        "Nip01EventWire::parse_json_unverified_with_limits(",
        "verify_id(&event)",
        "verify(&event)",
        "rhi_evidence_attestation_from_event(&event)",
        "validate_against_manifest(manifest)",
    ] {
        assert!(
            RECONCILIATION_ATTESTATION.contains(required),
            "reconciliation attestation is missing {required}"
        );
    }
    for forbidden in ["sqlx::", "std::fs", "std::net", "tokio::", "SystemTime"] {
        assert!(
            !RECONCILIATION_ATTESTATION.contains(forbidden),
            "reconciliation attestation gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod reconciliation_attestation"));
    assert!(!PUBLIC_API.contains("rhi::reconciliation_attestation::"));
}

#[test]
fn reconciliation_commit_is_atomic_bounded_and_sealed() {
    let contract: serde_json::Value = serde_json::from_str(RECONCILIATION_COMMIT_CONTRACT)
        .expect("reconciliation-commit contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-commit");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["state_schema_version"], 6);
    assert_eq!(contract["effects"]["source_or_relay"], false);
    for required in [
        ".take(plan.requests().len().saturating_add(1))",
        "validate_exact_lease(transaction, lease)",
        "reconcile_existing(transaction, &plan, &parts)",
        "SOURCE_INVENTORY_DIGEST_DOMAIN",
        "accepted_inventory_sha256",
        "advance_dirty_generation(",
        "write_checkpoint(",
        "committed_cursor_evidence(",
    ] {
        assert!(
            RECONCILIATION_COMMIT.contains(required),
            "reconciliation commit is missing {required}"
        );
    }
    assert!(!ROOT.contains("pub mod reconciliation_commit"));
    assert!(!PUBLIC_API.contains("rhi::reconciliation_commit::"));
}

#[test]
fn reconciliation_finalization_is_attempt_bound_nonmutating_and_revalidated() {
    let contract: serde_json::Value = serde_json::from_str(RECONCILIATION_FINALIZATION_CONTRACT)
        .expect("reconciliation-finalization contract");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.reconciliation-finalization"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["effects"]["sqlite_read"], true);
    assert_eq!(contract["effects"]["sqlite_write"], false);
    assert_eq!(
        contract["durable_validation"]["preflight_is_commit_authority"],
        false
    );
    for required in [
        "pub async fn prepare_finalization(",
        "validate_finalization_fence(",
        "validate_exact_lease(transaction, lease)",
        "read_dirty(transaction, identity.trade_id)",
        "MATCH_COMMITTED_ATTEMPT_SQL",
        "attempt_id(job.id(), job.attempt_count())",
    ] {
        assert!(
            RECONCILIATION_FINALIZATION.contains(required),
            "reconciliation finalization is missing {required}"
        );
    }
    for forbidden in [
        "INSERT ",
        "UPDATE ",
        "DELETE ",
        "tokio::spawn",
        "SystemTime",
    ] {
        assert!(
            !RECONCILIATION_FINALIZATION.contains(forbidden),
            "reconciliation finalization gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod reconciliation_finalization"));
    assert!(!PUBLIC_API.contains("rhi::reconciliation_finalization::"));
}

#[test]
fn reconciliation_finalization_commit_is_atomic_idempotent_and_effect_bounded() {
    let contract: serde_json::Value =
        serde_json::from_str(RECONCILIATION_FINALIZATION_COMMIT_CONTRACT)
            .expect("reconciliation-finalization-commit contract");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.reconciliation-finalization-commit"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["transaction"]["count"], 1);
    assert_eq!(contract["effects"]["network"], false);
    for required in [
        "pub async fn commit_finalization(",
        "reconcile_existing(transaction, record)",
        "validate_finalization_identity(transaction, record.lease, record.identity, record.now)",
        "validate_source_inventory(transaction, record)",
        "validate_advanced_checkpoints(transaction, record)",
        "validate_supersession(transaction, record)",
        "COMPLETE_JOB_SQL",
    ] {
        assert!(
            RECONCILIATION_FINALIZATION_COMMIT.contains(required),
            "atomic finalization is missing {required}"
        );
    }
    for forbidden in ["tokio::spawn", "SystemTime", "std::fs", "reqwest"] {
        assert!(
            !RECONCILIATION_FINALIZATION_COMMIT.contains(forbidden),
            "atomic finalization gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod reconciliation_finalization_commit"));
    assert!(!PUBLIC_API.contains("rhi::reconciliation_finalization_commit::"));
}

#[test]
fn reconciliation_manifest_is_canonical_sealed_and_effect_free() {
    let contract: serde_json::Value = serde_json::from_str(RECONCILIATION_MANIFEST_CONTRACT)
        .expect("reconciliation-manifest contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-manifest");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(
        contract["construction_authority"],
        "confirmed_step_190_commit_outcome_only"
    );
    assert_eq!(contract["effects"]["sqlite"], false);
    for required in [
        "RadrootsTradeEvidenceManifestV1::new(",
        "SOURCE_RESULT_DIGEST_DOMAIN",
        "PROVENANCE_DIGEST_DOMAIN",
        "committed_inventory_digest(part)",
        "pub fn into_evidence_manifest(",
    ] {
        assert!(
            RECONCILIATION_MANIFEST.contains(required),
            "reconciliation manifest is missing {required}"
        );
    }
    for forbidden in ["sqlx::", "std::fs", "std::net", "tokio::", "SystemTime"] {
        assert!(
            !RECONCILIATION_MANIFEST.contains(forbidden),
            "reconciliation manifest gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod reconciliation_manifest"));
    assert!(!PUBLIC_API.contains("rhi::reconciliation_manifest::"));
}

#[test]
fn reconciliation_reducer_is_manifest_bound_sealed_and_effect_free() {
    let contract: serde_json::Value = serde_json::from_str(RECONCILIATION_REDUCER_CONTRACT)
        .expect("reconciliation-reducer contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-reducer");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["input"]["maximum_mutations"], 65_536);
    assert_eq!(
        contract["input"]["maximum_canonical_content_bytes"],
        134_217_728
    );
    assert_eq!(contract["effects"]["sqlite"], false);
    for required in [
        "trade_mutation_from_canonical_content",
        "reduce_trade_records(input)",
        "PROJECTION_DIGEST_DOMAIN",
        "manifest.digest()",
        "inner.evidence_policy_digest()",
        "pub fn reduce_rhi_reconciliation_manifest(",
        "RHI_REDUCER_MAXIMUM_MUTATION_MATERIAL_BYTES",
    ] {
        assert!(
            RECONCILIATION_REDUCER.contains(required),
            "reconciliation reducer is missing {required}"
        );
    }
    for forbidden in ["sqlx::", "std::fs", "std::net", "tokio::", "SystemTime"] {
        assert!(
            !RECONCILIATION_REDUCER.contains(forbidden),
            "reconciliation reducer gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod reconciliation_reducer"));
    assert!(!PUBLIC_API.contains("rhi::reconciliation_reducer::"));
    assert!(!PUBLIC_API.contains("RhiReconciliationProjection::shared_projection(&self)"));
}

#[test]
fn reconciliation_outcome_is_projection_bound_total_and_effect_free() {
    let contract: serde_json::Value = serde_json::from_str(RECONCILIATION_OUTCOME_CONTRACT)
        .expect("reconciliation-outcome contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-outcome");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["coverage"].as_array().expect("coverage").len(), 4);
    assert_eq!(contract["outcome"].as_array().expect("outcome").len(), 3);
    assert_eq!(contract["reason_inventory"]["cardinality"], 1);
    assert_eq!(contract["effects"]["sqlite"], false);
    for required in [
        "pub fn evaluate_rhi_reconciliation_claim(",
        "RhiReconciliationEvaluation",
        "RhiReconciliationReasonCode",
        "classify_evaluation(facts)",
        "projection: RhiReconciliationProjection",
        "claim_mutation_id: MutationId",
    ] {
        assert!(
            RECONCILIATION_REDUCER.contains(required),
            "reconciliation outcome is missing {required}"
        );
    }
    for forbidden in [
        "sqlx::",
        "std::fs",
        "std::net",
        "tokio::",
        "SystemTime",
        "caller_supplied_outcome",
    ] {
        assert!(
            !RECONCILIATION_REDUCER.contains(forbidden),
            "reconciliation outcome gained forbidden authority {forbidden}"
        );
    }
    assert!(!PUBLIC_API.contains("rhi::reconciliation_reducer::"));
    assert!(!PUBLIC_API.contains("RhiReconciliationEvaluation {"));
}

#[test]
fn public_errors_are_crate_owned_redacted_and_source_free() {
    let production = SOURCES.join("\n");
    assert!(!production.contains("fn source("));
    for forbidden in [
        "source: std::io::Error",
        "source: sqlx::Error",
        "source: serde_json::Error",
        "source: toml::de::Error",
        "source: url::ParseError",
    ] {
        assert!(
            !production.contains(forbidden),
            "raw error source `{forbidden}` escaped"
        );
    }
    for forbidden in [
        "serde_json::Error",
        "radroots_event::trade::TradeProtocolError",
        "sqlx::Error",
        "std::io::Error",
        "thiserror::",
    ] {
        assert!(
            !PUBLIC_API.contains(forbidden),
            "reviewed API exposes dependency error `{forbidden}`"
        );
    }
    let public_error_count = PUBLIC_API
        .lines()
        .filter(|line| line.starts_with("pub struct rhi::") && line.ends_with("Error"))
        .count();
    assert_eq!(public_error_count, 35);
}

#[test]
fn reconciliation_attempts_are_exact_bounded_and_effect_free() {
    let contract: serde_json::Value = serde_json::from_str(RECONCILIATION_ATTEMPT_CONTRACT)
        .expect("reconciliation-attempt contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-attempts");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["state_schema_version"], 5);
    assert_eq!(contract["plan"]["source_count_maximum"], 16);
    assert_eq!(contract["plan"]["result_event_maximum"], 4_096);
    assert_eq!(
        contract["plan"]["result_original_event_bytes_maximum"],
        8_388_608
    );
    assert_eq!(
        contract["result"]["inventory_ingestion_bound"],
        "configured_source_count_plus_one"
    );
    assert_eq!(contract["effects"]["sqlite"], false);
    assert_eq!(contract["effects"]["source_or_relay"], false);
    for required in [
        "state_metadata::evidence_policy_digest(normalized)",
        ".take(plan.requests.len().saturating_add(1))",
        "RhiTradeSourceCompletion::IncompleteTimeout",
        "RhiReconciliationSourceSelectorDigest",
    ] {
        assert!(
            RECONCILIATION_ATTEMPTS.contains(required),
            "attempt boundary is missing {required}"
        );
    }
    for forbidden in [
        "sqlx::",
        "std::fs",
        "std::net",
        "tokio::",
        "SystemTime",
        "thread_rng",
        "OsRng",
        "RhiTradeSourceCursor",
    ] {
        assert!(
            !RECONCILIATION_ATTEMPTS.contains(forbidden),
            "attempt boundary gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod reconciliation_attempt"));
    assert!(!PUBLIC_API.contains("rhi::reconciliation_attempt::"));
}

#[test]
fn reconciliation_replay_is_overlap_safe_bounded_and_effect_free() {
    let contract: serde_json::Value = serde_json::from_str(RECONCILIATION_REPLAY_CONTRACT)
        .expect("reconciliation-replay contract");
    assert_eq!(contract["schema"], "radroots.rhi.reconciliation-replay");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["state_schema_version"], 5);
    assert_eq!(contract["cursor"]["equal_timestamp_safe"], true);
    assert_eq!(
        contract["cursor"]["input"],
        "sealed_step_190_committed_cursor_evidence"
    );
    assert_eq!(
        contract["cursor"]["eligible_only_for"],
        "complete_and_strictly_after_prior_cursor"
    );
    assert_eq!(
        contract["inventory"]["input_ingestion_bound"],
        "request_maximum_events_plus_one"
    );
    assert_eq!(
        contract["inventory"]["first_provenance"],
        "earliest_injected_observation_time_retained"
    );
    assert_eq!(contract["effects"]["sqlite"], false);
    assert_eq!(contract["effects"]["source_or_relay"], false);
    for required in [
        ".take(maximum_events.saturating_add(1))",
        "saturating_sub(overlap_seconds)",
        "RhiReconciliationReplayErrorKind::MutationConflict",
        "RhiReconciliationReplayErrorKind::SignedEventConflict",
        "RhiReconciliationSourceCursorEvidence",
        "cursor_scope_matches(",
    ] {
        assert!(
            RECONCILIATION_REPLAY.contains(required),
            "replay boundary is missing {required}"
        );
    }
    for forbidden in [
        "sqlx::",
        "std::fs",
        "std::net",
        "tokio::",
        "SystemTime",
        "thread_rng",
        "OsRng",
    ] {
        assert!(
            !RECONCILIATION_REPLAY.contains(forbidden),
            "replay boundary gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod reconciliation_replay"));
    assert!(!PUBLIC_API.contains("rhi::reconciliation_replay::"));
}

#[test]
fn trade_source_ingest_is_exact_bounded_generation_fenced_and_sealed() {
    let contract: serde_json::Value =
        serde_json::from_str(TRADE_SOURCE_INGEST_CONTRACT).expect("trade-source ingest contract");
    assert_eq!(contract["schema"], "radroots.rhi.trade-source-ingest.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["source"]["kind"], "nostr_relay");
    assert_eq!(
        contract["source"]["selector"]["kinds"],
        serde_json::json!([3470, 3471, 3472, 3473, 3474])
    );
    assert_eq!(contract["source"]["selector"]["exact_tag"], "#d");
    assert_eq!(contract["source"]["page_events_maximum"], 1_000);
    assert_eq!(contract["source"]["result_events_maximum"], 4_096);
    assert_eq!(
        contract["source"]["result_original_event_bytes_maximum"],
        8_388_608
    );
    assert_eq!(
        contract["completion"]["complete"],
        "exact_target_eose_before_deadline"
    );
    assert_eq!(
        contract["admission"]["deduplicate_by"],
        serde_json::json!(["verified_event_id", "verified_event_signature"])
    );
    assert_eq!(
        contract["checkpoint"]["scope"],
        serde_json::json!([
            "source_id",
            "selector_id",
            "evidence_policy_sha256",
            "trade_id"
        ])
    );
    assert_eq!(contract["checkpoint"]["equal_timestamp_safe"], true);
    assert_eq!(
        contract["dirty_generation"]["do_not_advance_when"],
        serde_json::json!([
            "rejected_event",
            "duplicate_event",
            "repeated_source_observation",
            "operational_retry"
        ])
    );
    assert_eq!(
        contract["transaction"]["source_fetch_inside_transaction"],
        false
    );

    let source = include_str!("../src/source_ingest.rs");
    for required in [
        "with_kinds(EVENT_KINDS.to_vec())",
        "with_exact_tag_value('d', trade_id.to_hex())",
        "with_since_unix_seconds(since)",
        "admit_rhi_trade_mutation_event(",
        "read_checkpoint(transaction",
        "read_dirty(transaction",
        "compare_cursor(current.cursor, candidate).is_lt()",
        "new_relevant_evidence",
    ] {
        assert!(
            source.contains(required),
            "source ingest is missing {required}"
        );
    }
    for forbidden in [
        "pub fn host(",
        "pub fn sqlite_host(",
        "SystemTime",
        "std::fs",
        "std::net",
        "tokio::spawn",
    ] {
        assert!(
            !source.contains(forbidden),
            "source ingest gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod source_ingest"));
    assert!(!PUBLIC_API.contains("rhi::source_ingest::"));
}

#[test]
fn trade_ingest_is_sealed_bounded_verified_and_effect_free() {
    let contract: serde_json::Value =
        serde_json::from_str(TRADE_INGEST_CONTRACT).expect("trade-ingest contract");
    assert_eq!(contract["schema"], "radroots.rhi.trade-ingest.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["wire"]["original_wire_cap_before_parse"], true);
    assert_eq!(contract["wire"]["duplicate_fields"], "reject");
    assert_eq!(contract["authored_time"]["default"], "none");
    assert_eq!(contract["verification"]["event_id"], "recomputed_and_exact");
    assert_eq!(
        contract["verification"]["signature"],
        "bip340_schnorr_verified"
    );
    assert_eq!(contract["effects"]["filesystem"], false);
    assert_eq!(contract["effects"]["sqlite"], false);
    assert_eq!(contract["effects"]["network"], false);
    assert_eq!(
        contract["persistence_contract"],
        "contracts/services_hardening/trade_evidence_persistence.v1.json"
    );

    let source = include_str!("../src/trade_ingest.rs");
    for required in [
        "preflight_wire(source, limits)?",
        "verify_id(&event)",
        "verify(&event)",
        "trade_mutation_from_event(&event)",
        "original: original.into()",
    ] {
        assert!(
            source.contains(required),
            "trade ingest is missing {required}"
        );
    }
    for forbidden in [
        "sqlx::",
        "std::fs",
        "std::net",
        "tokio::",
        "SystemTime",
        "process::",
    ] {
        assert!(
            !source.contains(forbidden),
            "trade ingest gained effect authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod trade_ingest"));
    assert!(!PUBLIC_API.contains("rhi::trade_ingest::"));
}

#[test]
fn trade_evidence_persistence_is_typed_atomic_and_sealed() {
    let contract: serde_json::Value = serde_json::from_str(TRADE_EVIDENCE_PERSISTENCE_CONTRACT)
        .expect("trade-evidence persistence contract");
    assert_eq!(
        contract["schema"],
        "radroots.rhi.trade-evidence-persistence.v1"
    );
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["transaction"], "one_governed_sqlx_transaction");
    assert_eq!(contract["effects"]["checkpoint"], false);
    assert_eq!(contract["effects"]["dirty_generation"], false);
    assert_eq!(
        contract["facts"]["signed_event"]["identity"],
        serde_json::json!(["verified_event_id", "verified_event_signature"])
    );

    let source = include_str!("../src/state_trade.rs");
    for required in [
        "pub async fn persist_trade_evidence",
        "RhiAdmittedTradeMutationEvent",
        "RhiTradeSourceObservation",
        ".transaction(move |transaction|",
        "ON CONFLICT (event_id, event_signature) DO NOTHING",
    ] {
        assert!(
            source.contains(required),
            "trade evidence persistence is missing {required}"
        );
    }
    for forbidden in [
        "pub fn host(",
        "pub fn into_parts(",
        "pub fn event_signature_bytes(",
        "SystemTime",
        "std::fs",
        "std::net",
        "checkpoint",
        "dirty_generation",
    ] {
        assert!(
            !source.contains(forbidden),
            "trade evidence persistence gained forbidden authority {forbidden}"
        );
    }
    assert!(!ROOT.contains("pub mod state_trade"));
    assert!(!PUBLIC_API.contains("rhi::state_trade::"));
    assert!(!PUBLIC_API.contains("sqlx::"));
}

#[test]
fn runtime_foundation_is_existing_only_passive_and_process_neutral() {
    let contract: serde_json::Value =
        serde_json::from_str(RUNTIME_FOUNDATION_CONTRACT).expect("runtime foundation contract");
    assert_eq!(contract["schema"], "radroots.rhi.runtime-foundation");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["state_open"]["initialize_if_missing"], false);
    assert_eq!(
        contract["state_open"]["durable_configuration_binding_required"],
        true
    );
    assert_eq!(contract["transport"]["invoked_during_foundation"], false);
    assert_eq!(contract["task_ownership"]["task_handles_exposed"], false);
    for required in [
        "open_rhi_state_read_write_from_config",
        "RhiIdentityEnvelopeBinding::from_configuration",
        ".identity_credential()",
        "startup_readiness(&configuration)",
    ] {
        assert!(RUNTIME_FOUNDATION.contains(required));
    }
    for forbidden in [
        "tokio::runtime",
        "tokio::signal",
        "signal_hook",
        "tracing_subscriber",
        "std::process::exit",
        ".fetch(",
        ".subscribe(",
        ".deliver(",
    ] {
        assert!(!RUNTIME_FOUNDATION.contains(forbidden));
    }
}

#[test]
fn runtime_adapter_boundary_is_exact_bounded_and_process_neutral() {
    let contract: serde_json::Value =
        serde_json::from_str(RUNTIME_ADAPTER_CONTRACT).expect("runtime adapter contract");
    assert_eq!(contract["schema"], "radroots.rhi.runtime-adapters");
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(contract["jitter"]["inclusive_maximum"], 3_600_000);
    assert_eq!(contract["jitter"]["maximum_entropy_draws"], 16);
    assert_eq!(contract["jitter"]["wall_clock_derived"], false);
    assert_eq!(contract["transport"]["evidence_fetch"], "EventSource");
    assert_eq!(
        contract["transport"]["evidence_subscription"],
        "EventSubscriber"
    );
    assert_eq!(contract["transport"]["publication"], "EventSink");
    assert_eq!(
        contract["identity"]["order"],
        serde_json::json!(["credential", "encrypted_identity"])
    );
    assert_eq!(contract["identity"]["fallback"], false);
    assert_eq!(contract["identity"]["generation"], false);
    assert_eq!(contract["tasks"]["join_owned"], true);
    assert_eq!(contract["tasks"]["handles_exposed"], false);

    for required in [
        "Arc<dyn WallClock>",
        "Arc<dyn MonotonicClock>",
        "Arc<dyn EntropySource>",
        "Arc<dyn EventSource>",
        "Arc<dyn EventSubscriber>",
        "Arc<dyn EventSink>",
        "TaskSupervisor",
        "RHI_RUNTIME_JITTER_MAX_MILLISECONDS: u64 = 3_600_000",
        "RHI_RUNTIME_JITTER_MAX_ENTROPY_DRAWS: usize = 16",
        "u128::from(u64::from_be_bytes(bytes)) * u128::from(range)",
        "low >= rejection_threshold",
        "resolve_rhi_wrapping_credential(runtime, binding)",
        "open_rhi_encrypted_identity(binding, credential)",
    ] {
        assert!(
            RUNTIME_ADAPTERS.contains(required),
            "runtime adapter boundary is missing {required}"
        );
    }
    for forbidden in [
        "tokio::runtime::Runtime",
        "tokio::runtime::Builder",
        "tokio::signal",
        "signal_hook",
        "tracing_subscriber",
        "std::process::exit",
        "tokio::spawn",
        "std::thread::spawn",
        "SystemTime::now",
        "subsec_nanos",
        "rand::",
    ] {
        assert!(
            !RUNTIME_ADAPTERS.contains(forbidden),
            "runtime adapter boundary contains forbidden authority {forbidden}"
        );
    }
    assert!(MANIFEST.contains("radroots_transport ="));
    assert!(MANIFEST.contains("default-features = false, features = [\"std\"]"));
}

#[test]
fn readme_freezes_the_root_only_boundary_and_exact_baseline() {
    for required in [
        "## Public API boundary",
        "one curated crate-root API",
        "public errors use RHI-owned stable classifications",
        "shared clock and entropy traits and their source-free error values",
        "failures into stable RHI classifications",
        "```compile_fail",
        "[RHI API baseline](contracts/api_baselines/rhi.txt)",
        "[`trade_ingest.v1.json`](contracts/services_hardening/trade_ingest.v1.json)",
        "[`trade_evidence_persistence.v1.json`](contracts/services_hardening/trade_evidence_persistence.v1.json)",
        "## Bounded relay-source ingestion",
        "[`trade_source_ingest.v1.json`](contracts/services_hardening/trade_source_ingest.v1.json)",
        "## Durable reconciliation jobs",
        "[`reconciliation_jobs.v1.json`](contracts/services_hardening/reconciliation_jobs.v1.json)",
        "## Bounded reconciliation source attempts",
        "[`reconciliation_attempts.v1.json`](contracts/services_hardening/reconciliation_attempts.v1.json)",
        "## Overlap-safe reconciliation replay",
        "[`reconciliation_replay.v1.json`](contracts/services_hardening/reconciliation_replay.v1.json)",
        "## Atomic reconciliation result commit",
        "[`reconciliation_commit.v1.json`](contracts/services_hardening/reconciliation_commit.v1.json)",
        "## Immutable reconciliation manifest",
        "[`reconciliation_manifest.v1.json`](contracts/services_hardening/reconciliation_manifest.v1.json)",
        "## Pure reconciliation reducer",
        "[`reconciliation_reducer.v1.json`](contracts/services_hardening/reconciliation_reducer.v1.json)",
        "binds the promoted shared `radroots.trade.reducer.v1`",
        "[`reconciliation_outcome.v1.json`](contracts/services_hardening/reconciliation_outcome.v1.json)",
        "## Generation-fenced finalization preflight",
        "[`reconciliation_finalization.v1.json`](contracts/services_hardening/reconciliation_finalization.v1.json)",
        "Step 199 must rerun the same validator inside the final",
        "## Atomic reconciliation finalization commit",
        "[`reconciliation_finalization_commit.v1.json`](contracts/services_hardening/reconciliation_finalization_commit.v1.json)",
        "An exact retry returns",
        "Disabled publication creates no outbox or target row",
        "## Canonical signed reconciliation attestation",
        "[`reconciliation_attestation.v1.json`](contracts/services_hardening/reconciliation_attestation.v1.json)",
        "## Explicit publication authority and durable schema",
        "## Deterministic durable presence intent",
        "[`presence_desired_state.v1.json`](contracts/services_hardening/presence_desired_state.v1.json)",
        "## Durable exact-byte presence publication",
        "[`presence_publication.v1.json`](contracts/services_hardening/presence_publication.v1.json)",
        "Expired work from a",
        "superseded desired generation is recorded as `unknown`",
        "unknown commit result can be reconciled by replaying the same retained bytes",
        "[`publication_outbox.v1.json`](contracts/services_hardening/publication_outbox.v1.json)",
        "## Bounded publication attempt evidence",
        "[`publication_attempt_evidence.v1.json`](contracts/services_hardening/publication_attempt_evidence.v1.json)",
        "## Durable exact-byte publication execution",
        "[`publication_execution.v1.json`](contracts/services_hardening/publication_execution.v1.json)",
        "[`publication_wave_qualification.v1.json`](contracts/services_hardening/publication_wave_qualification.v1.json)",
        "The event body and exact kind-3441 structural tags",
        "without rebuilding, reserializing, or",
        "Coverage is exactly `Missing`, `Partial`, `ScopeSatisfied`, or `Unsupported`",
        "Missing, partial, unsupported,",
        "The Step 192 integration-wave qualification proves that concurrent exact",
        "lost-success retry converges after close/reopen",
        "inventory terminates at configured source count plus one before mutation",
        "configured queue capacity is enforced beneath a fixed 65,536-job",
        "from an unexpired claimed job lease",
        "can be omitted, duplicated, reordered, or appended beyond",
        "Planning and result validation are pure and perform no",
        "SQLite, source, relay, network, filesystem, task, clock, or entropy operation",
        "No ambient clock or entropy is read",
        "Only exact-target EOSE before the deadline is complete",
        "4,096 distinct signed-event identities (event ID plus signature) and 8 MiB",
        "observation, and operational retry do not",
        "schema-v6 immutable",
        "schema-v7 immutable report, signed-event,",
        "The schema-v7",
        "catalog is frozen by Step 198",
        "one canonical mutation",
        "every distinct valid signed",
        "does not advance reconciliation checkpoints or dirty generation",
        "## Injected runtime adapters",
        "whole-second wall UTC",
        "process-local monotonic time",
        "exact v1 maximum of 3,600,000",
        "fails closed after sixteen rejected entropy draws",
        "never derived from wall-clock",
        "Constructing the adapter set performs no clock read",
        "no signal handler, Tokio runtime, logger, or process-exit policy",
        "[`runtime_adapters.v1.json`](contracts/services_hardening/runtime_adapters.v1.json)",
        "## Existing-state runtime foundation",
        "opens only an already initialized database",
        "No evidence source, live subscription, or publication sink is",
        "[`runtime_foundation.v1.json`](contracts/services_hardening/runtime_foundation.v1.json)",
        "at most 1,024 consecutive generations",
        "never stores raw TOML, paths, relay URLs, credential",
        "## Unix-admin boundary",
        "seven common RHI routes",
        "thirteen reconciliation, job, source",
        "cursors use canonical base64url without padding",
        "two identity-sensitive mutations remain unregistered",
        "22-route/36-model inventory",
        "[`admin_common.v1.json`](contracts/services_hardening/admin_common.v1.json)",
        "[`admin_domain.v1.json`](contracts/services_hardening/admin_domain.v1.json)",
    ] {
        assert!(README.contains(required), "README is missing {required}");
    }
    for forbidden in [
        "SystemTime",
        "thread_rng",
        "OsRng",
        "pub mod reconciliation_job",
    ] {
        assert!(
            !RECONCILIATION_JOBS.contains(forbidden),
            "reconciliation jobs expose forbidden authority {forbidden}"
        );
    }
    for required in [
        "Keep every implementation module private",
        "contracts/api_baselines/rhi.txt",
        "Public errors must use RHI-owned stable classifications",
        "no raw dependency-owned source chain",
        "Compose those dependencies only through the sealed runtime-adapter boundary",
        "exposes no task handle or concrete transport handle",
        "admit_rhi_trade_mutation_event",
        "Persist each canonical",
        "independently signed Nostr event",
        "Commit a signed finalization only through the sealed attempt repository",
        "Build service-profile and application-handler presence only through the",
        "Preserve the\n  caller's sealed exact-byte capability",
        "Recover an expired stale",
    ] {
        assert!(AGENTS.contains(required), "AGENTS is missing {required}");
    }
}

#[test]
fn human_verification_contract_is_extbuild_only_through_rcld_170() {
    for required in [
        "cargo extbuild doctor",
        "cargo extbuild run -- cargo fmt --all --check",
        "cargo extbuild run -- cargo check --workspace --all-targets --locked",
        "cargo extbuild run -- cargo test --workspace --all-targets --locked",
        "cargo extbuild run -- cargo clippy --workspace --all-targets --locked -- -D warnings",
        "Nix-produced OCI artifacts are deferred and unclaimed",
    ] {
        assert!(README.contains(required), "README is missing {required}");
    }
    for forbidden in ["nix run", "nix develop", "nix build", "nix flake"] {
        assert!(
            !README.contains(forbidden),
            "README retains forbidden active Nix command {forbidden}"
        );
    }
}
