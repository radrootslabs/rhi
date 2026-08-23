use std::fs;
use std::path::Path;

#[test]
fn rhi_manifest_has_no_sdk_or_legacy_proof_dependency() {
    let manifest = read_repo_file("Cargo.toml");

    for forbidden in [
        "radroots_sdk",
        "radroots_trade_sp1_guest",
        "radroots_trade_sp1_host",
        "sp1_verify",
        "sp1_proving",
        "sp1_cuda_proving",
        "reqwest",
        "libsqlite3-sys",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "RHI manifest must not retain retired dependency `{forbidden}`"
        );
    }
}

#[test]
fn rhi_manifest_exact_pins_radroots_contract() {
    let manifest: toml::Value = toml::from_str(&read_repo_file("Cargo.toml")).expect("manifest");
    let dependencies = manifest["dependencies"]
        .as_table()
        .expect("package dependencies");

    for (name, dependency) in dependencies {
        if !name.starts_with("radroots_") {
            continue;
        }
        let dependency = dependency
            .as_table()
            .unwrap_or_else(|| panic!("{name} must use an explicit dependency table"));
        assert_eq!(
            dependency.get("git").and_then(toml::Value::as_str),
            Some("https://github.com/radrootslabs/lib"),
            "RHI must source {name} from the governed public Lib repository"
        );
        assert_eq!(
            dependency.get("rev").and_then(toml::Value::as_str),
            Some("7d7b454b4c9ed86569671993bd03ca868b676665"),
            "RHI must source-lock {name} to the exact promoted Lib revision"
        );
        assert_eq!(
            dependency.get("version").and_then(toml::Value::as_str),
            Some("=0.1.0-alpha"),
            "RHI must exact-pin {name} to the governed event contract release"
        );
    }
}

#[test]
fn rhi_release_product_surface_has_no_order_or_receipt_modules() {
    for forbidden_path in [
        "src/features/trade_listing/mod.rs",
        "src/features/trade_validation_receipt.rs",
        "src/proof_smoke.rs",
        "src/remote_prove.rs",
    ] {
        assert!(
            !Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(forbidden_path)
                .exists(),
            "RHI must not retain retired source path `{forbidden_path}`"
        );
    }

    for (path, source) in rust_sources_under("src") {
        for forbidden in [
            "trade_listing",
            "trade_validation_receipt",
            "proof_smoke",
            "remote_prove",
            "KIND_ORDER",
            "RadrootsOrder",
            "radroots_trade::order",
            "radroots_event_codec::order",
            "AgreedPendingValidation",
            "ValidationExpired",
            "order_acceptance",
            "KIND_TRADE_VALIDATION_RECEIPT",
            "validation_receipt_event_build",
            "verify_validation_receipt_event",
            "radroots_trade_sp1",
            "proof_mode",
            "LocalExecute",
            "local_execute",
        ] {
            assert!(
                !source.contains(forbidden),
                "{path} retains retired order or proof surface `{forbidden}`"
            );
        }
    }
}

#[test]
fn rhi_agreement_attestation_is_release_product_optional_infrastructure() {
    let worker = read_repo_file("src/features/trade_agreement_attestation.rs");
    let lib = read_repo_file("src/lib.rs");
    let cli = read_repo_file("src/cli_v1.rs");
    let config = read_repo_file("src/config.rs");

    for required in [
        "RHI_AGREEMENT_ATTESTATION_PROTOCOL_ID",
        "TradeAgreementAttestationPolicy",
        "LocalStatementHash",
        "TradeAgreementAttestationRuntime",
        "handle_trade_mutation_event",
        "attest_projection_claim",
        "claim_mutation_id",
        "projection_digest",
        "RadrootsTradeAttestationResultV1::Valid",
        "RadrootsTradeAttestationResultV1::Invalid",
        "TRADE_MUTATION_EVENT_KINDS",
        "is_trade_mutation_event_kind",
        "no_agreement_authority",
        "expected_statement_contract_hash",
    ] {
        assert!(
            worker.contains(required),
            "agreement attestation worker must retain release-product requirement `{required}`"
        );
    }

    assert!(
        lib.contains("trade_mutation_subscription_kinds()")
            && lib.contains("TRADE_MUTATION_EVENT_KINDS")
            && lib.contains("AuthoredProfile")
            && lib.contains("ProfileBuilder")
            && lib.contains("build_profile")
            && lib.contains("build_application_handler")
            && lib.contains(".send_event(")
            && !lib.contains("radroots_nostr::prelude")
            && lib.contains("client.into_inner()"),
        "RHI service presence must advertise canonical release-product trade mutation kinds"
    );
    assert!(
        !cli.contains("AttestationSmoke")
            && !cli.contains("ProofSmoke")
            && !cli.contains("remote-prove"),
        "RHI CLI must not retain prototype smoke commands"
    );
    assert!(
        config.contains("settings.config.trade_agreement_attestation.validate()?"),
        "RHI config loading must validate the canonical attestation policy"
    );
}

#[test]
fn rhi_state_paths_are_named_for_agreement_attestation() {
    let config = read_repo_file("src/config.rs");
    let context = read_repo_file("src/runtime_context.rs");

    assert!(
        config.contains("trade-agreement-attestation"),
        "transitional RHI state paths must use agreement-attestation naming"
    );
    for source in [config.as_str(), context.as_str()] {
        assert!(
            !source.contains("trade-listing"),
            "RHI runtime state paths must not retain trade-listing naming"
        );
    }
    assert!(
        context.contains("default_service_instance_artifacts")
            && context.contains("service.identity.ncrypt"),
        "RHI path authority must derive exact common and credential artifacts"
    );
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
