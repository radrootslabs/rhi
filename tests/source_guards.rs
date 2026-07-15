use std::fs;
use std::path::Path;

#[test]
fn rhi_manifest_has_no_sdk_dependency() {
    let manifest = read_repo_file("Cargo.toml");

    assert!(
        !manifest.contains("radroots_sdk"),
        "RHI must not depend on radroots_sdk"
    );
}

#[test]
fn rhi_validation_receipt_paths_use_validator_set_contract() {
    let listing_events = read_repo_file("src/features/trade_listing/handlers/events.rs");
    let receipt_worker = read_repo_file("src/features/trade_validation_receipt.rs");

    assert!(
        listing_events.contains("publish_validation_receipt("),
        "trade listing event handler must publish V1 validation receipts from accepted orders"
    );
    assert!(
        !listing_events.contains("radroots_trade::dvm"),
        "trade listing handler must not import the removed DVM contract"
    );

    for required in [
        "validator_set_addr",
        "validator_set_event_id",
        "validator_set_address_from_str",
        "validation_receipt_event_build",
        "verify_validation_receipt_event",
        "MissingValidatorSetBinding",
        "mark_receipt_completed",
    ] {
        assert!(
            receipt_worker.contains(required),
            "trade validation receipt worker must retain validator-set receipt contract `{required}`"
        );
    }

    for forbidden in [
        "radroots_trade::dvm",
        "KIND_TRADE_TRANSITION_PROOF_REQUEST",
        "KIND_TRADE_TRANSITION_PROOF_RESULT",
        "RadrootsTradeTransitionProofRequest",
        "build_transition_proof_result_tags",
        "deterministic_none",
        "DeterministicNone",
    ] {
        assert!(
            !receipt_worker.contains(forbidden),
            "trade validation receipt worker must not retain retired contract `{forbidden}`"
        );
    }
}

#[test]
fn rhi_sources_do_not_import_removed_sdk_or_protocol_bypasses() {
    for (path, source) in rust_sources_under("src") {
        for forbidden in [
            "radroots_sdk",
            "radroots_sdk::protocol::order",
            "SdkDvmInventoryBinWitness",
            "TradeProtocolClient",
            "KIND_TRADE_LISTING_VALIDATE_REQ",
            "KIND_TRADE_LISTING_VALIDATION_REQUEST",
            "KIND_WORKER_TRADE_TRANSITION_PROOF_REQ",
            "KIND_TRADE_TRANSITION_PROOF_REQUEST",
            "KIND_TRADE_TRANSITION_PROOF_RESULT",
            "radroots_trade::dvm",
            "deterministic_none",
            "DeterministicNone",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} contains forbidden SDK adoption bypass `{forbidden}`"
            );
        }
    }
}

#[test]
fn rhi_processed_job_state_is_durable_workflow_authority() {
    let state = read_repo_file("src/features/trade_listing/state.rs");
    let processed_jobs = read_repo_file("src/features/trade_listing/processed_jobs.rs");
    let receipt_worker = read_repo_file("src/features/trade_validation_receipt.rs");

    assert!(
        !state.contains("rhi_processed_jobs: HashMap"),
        "RHI JSON subscriber state must not be the processed-job authority"
    );
    assert!(
        state.contains("processed_jobs: Arc<RhiProcessedJobStore>"),
        "TradeListingRuntime must own the processed-job SQLite store"
    );

    for required in [
        "CREATE TABLE IF NOT EXISTS rhi_processed_jobs",
        "request_id TEXT PRIMARY KEY",
        "CREATE UNIQUE INDEX IF NOT EXISTS rhi_processed_jobs_receipt_event_idx",
        "CREATE UNIQUE INDEX IF NOT EXISTS rhi_processed_jobs_result_event_idx",
        "pub async fn claim_job(",
        "pub async fn mark_receipt_publishing(",
        "pub async fn mark_receipt_published(",
        "pub async fn mark_result_publishing(",
        "pub async fn mark_completed(",
        "pub async fn mark_receipt_completed(",
        "RhiProcessedJobClaim::InProgress",
        "RhiProcessedJobClaim::RecoverReceipt",
        "RhiProcessedJobStatus::ReceiptPublishing",
        "RhiProcessedJobStatus::ResultPublishing",
        "RhiProcessedJobStatus::Completed",
        "receipt_event_json",
        "result_event_json",
        "proof_metadata_json",
        "DuplicateConflictingResult",
    ] {
        assert!(
            processed_jobs.contains(required),
            "RHI processed-job store must retain SQLite workflow authority `{required}`"
        );
    }

    for required in [
        "fn processed_job_for_receipt(",
        "async fn publish_receipt_with_processed_job(",
        "publish_signed_event_io(",
        "mark_receipt_completed(",
        "RhiProcessedJobClaim::Completed",
    ] {
        assert!(
            receipt_worker.contains(required),
            "RHI receipt worker must retain processed-job workflow guard `{required}`"
        );
    }
}

#[test]
fn rhi_validation_receipt_policy_is_enabled_and_validator_set_bound() {
    let config = read_repo_file("src/config.rs");
    let receipt_worker = read_repo_file("src/features/trade_validation_receipt.rs");

    for required in [
        "TradeValidationReceiptProverBackend::LocalExecute",
        "validator_binding(",
        "MissingValidatorSetBinding",
        "validator_set_addr",
        "validator_set_event_id",
        "ProverBackendRequiresNone",
    ] {
        assert!(
            receipt_worker.contains(required),
            "trade validation receipt policy must retain enabled validator-set governance `{required}`"
        );
    }

    assert!(
        !receipt_worker.contains("Disabled") && !receipt_worker.contains("DeterministicNone"),
        "RHI must not expose disabled or deterministic-none validation receipt backends"
    );

    for required in [
        "settings.config.trade_validation_receipt.validate()?",
        "TradeValidationReceiptProverBackend::LocalExecute",
    ] {
        assert!(
            config.contains(required),
            "RHI config loading must retain enabled validator-set policy validation `{required}`"
        );
    }
}

fn read_repo_file(relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    fs::read_to_string(path.as_path())
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn rust_sources_under(relative_root: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut paths = Vec::new();
    collect_rust_sources(root.join(relative_root).as_path(), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let relative_path = path
                .strip_prefix(root)
                .expect("source under manifest root")
                .to_string_lossy()
                .replace('\\', "/");
            let source = fs::read_to_string(path.as_path())
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            (relative_path, source)
        })
        .collect()
}

fn collect_rust_sources(path: &Path, paths: &mut Vec<std::path::PathBuf>) {
    if path.is_file() {
        if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            paths.push(path.to_path_buf());
        }
        return;
    }

    for entry in fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
    {
        let entry = entry.expect("source entry");
        collect_rust_sources(entry.path().as_path(), paths);
    }
}
