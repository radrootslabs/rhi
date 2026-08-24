#![forbid(unsafe_code)]

const MANIFEST: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README");
const AGENTS: &str = include_str!("../AGENTS.md");
const ROOT: &str = include_str!("../src/lib.rs");
const ADAPTERS: &str = include_str!("../src/adapters/mod.rs");
const NOSTR_ADAPTERS: &str = include_str!("../src/adapters/nostr/mod.rs");
const FEATURES: &str = include_str!("../src/features/mod.rs");
const RUNTIME_ADAPTERS: &str = include_str!("../src/runtime_adapters.rs");
const RUNTIME_ADAPTER_CONTRACT: &str =
    include_str!("../contracts/services_hardening/runtime_adapters.v1.json");
const RUNTIME_FOUNDATION: &str = include_str!("../src/runtime_foundation.rs");
const RECONCILIATION_ATTEMPTS: &str = include_str!("../src/reconciliation_attempt.rs");
const RECONCILIATION_COMMIT: &str = include_str!("../src/reconciliation_commit.rs");
const RECONCILIATION_MANIFEST: &str = include_str!("../src/reconciliation_manifest.rs");
const RECONCILIATION_JOBS: &str = include_str!("../src/reconciliation_job.rs");
const RECONCILIATION_REPLAY: &str = include_str!("../src/reconciliation_replay.rs");
const RECONCILIATION_ATTEMPT_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_attempts.v1.json");
const RECONCILIATION_REPLAY_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_replay.v1.json");
const RECONCILIATION_COMMIT_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_commit.v1.json");
const RECONCILIATION_MANIFEST_CONTRACT: &str =
    include_str!("../contracts/services_hardening/reconciliation_manifest.v1.json");
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
    include_str!("../src/cli_v1.rs"),
    include_str!("../src/config_v1.rs"),
    include_str!("../src/features/trade_agreement_attestation.rs"),
    include_str!("../src/identity_credential.rs"),
    include_str!("../src/identity_envelope.rs"),
    include_str!("../src/reconciliation_attempt.rs"),
    include_str!("../src/reconciliation_commit.rs"),
    include_str!("../src/reconciliation_job.rs"),
    include_str!("../src/reconciliation_manifest.rs"),
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
        "CancellationToken",
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
        "cli_v1",
        "config_v1",
        "features",
        "identity_credential",
        "identity_envelope",
        "reconciliation_attempt",
        "reconciliation_commit",
        "reconciliation_job",
        "reconciliation_manifest",
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
        "RhiReconciliationAttemptPlan",
        "RhiReconciliationSourceRequest",
        "RhiReconciliationSourceResult",
        "RhiReconciliationAttemptResults",
        "RhiReconciliationSourceCommitOutcome",
        "RhiReconciliationCommitErrorKind",
        "RhiReconciliationManifest",
        "RhiReconciliationManifestErrorKind",
        "RhiReconciliationScopePrerequisites",
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
    assert!(!PUBLIC_API.contains("rhi::adapters::"));
    assert!(!PUBLIC_API.contains("rhi::features::"));
    assert!(!PUBLIC_API.contains("rhi::runtime_adapters::"));
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
    assert_eq!(public_error_count, 21);
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
