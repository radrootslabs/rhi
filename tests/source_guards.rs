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
fn rhi_dvm_transition_and_feedback_paths_use_trade_dvm_contract() {
    let listing_dvm = read_repo_file("src/features/trade_listing/handlers/dvm.rs");
    let receipt_worker = read_repo_file("src/features/trade_validation_receipt.rs");
    let listing_feedback_segment = source_segment(
        &listing_dvm,
        "pub async fn handle_error(",
        "\n#[cfg(test)]\n#[cfg_attr(coverage_nightly, coverage(off))]\nmod tests",
    );

    assert!(
        listing_dvm.contains(
            "use radroots_trade::dvm::{RadrootsTradeDvmFeedbackStatus, build_job_feedback_tags};"
        ),
        "trade listing DVM handler must import radroots_trade::dvm feedback contract"
    );
    assert!(
        listing_feedback_segment.contains("build_job_feedback_tags("),
        "trade listing DVM handler must build feedback tags through radroots_trade::dvm"
    );

    for required in [
        "RadrootsTradeTransitionProofRequestEnvelope",
        "RadrootsTradeTransitionProofResultBinding",
    ] {
        assert!(
            receipt_worker.contains(required),
            "trade validation receipt worker must use radroots_trade::dvm transition contract `{required}`"
        );
    }

    let result_segment = source_segment(
        &receipt_worker,
        "fn result_tags_from_dvm(",
        "fn expected_receipt_binding",
    );
    for required in [
        "parse_transition_proof_request_event(",
        "build_transition_proof_result_tags(",
    ] {
        assert!(
            result_segment.contains(required),
            "trade validation receipt worker must delegate result tags through radroots_trade::dvm `{required}`"
        );
    }
    assert!(
        !result_segment.contains("vec!["),
        "transition proof result tags must be delegated to radroots_trade::dvm"
    );
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
            "KIND_WORKER_TRADE_TRANSITION_PROOF_REQ",
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
    let receipt_worker = read_repo_file("src/features/trade_validation_receipt.rs");

    for required in [
        "rhi_processed_jobs: HashMap<String, RhiProcessedJobState>",
        "pub fn rhi_processed_job(&self, request_id: &str)",
        "pub fn upsert_rhi_processed_job(&mut self, job: RhiProcessedJobState)",
    ] {
        assert!(
            state.contains(required),
            "RHI state must retain processed-job storage contract `{required}`"
        );
    }

    for required in [
        "fn processed_job_for_request(",
        "async fn processed_job_action(",
        "mark_job_completed(",
        "RhiProcessedJobStatus::Completed",
    ] {
        assert!(
            receipt_worker.contains(required),
            "RHI receipt worker must retain processed-job workflow guard `{required}`"
        );
    }
}

fn read_repo_file(relative_path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    fs::read_to_string(path.as_path())
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn source_segment<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start_index = source.find(start).expect("source segment start");
    let end_index = source[start_index..]
        .find(end)
        .map(|index| start_index + index)
        .expect("source segment end");
    &source[start_index..end_index]
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
