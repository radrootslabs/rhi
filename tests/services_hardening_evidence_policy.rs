#![forbid(unsafe_code)]

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const POLICY: &str = include_str!("../contracts/services_hardening/evidence_policy.v1.json");
const CONSUMER_ROOT: &str = include_str!("../.radroots-consumer-root");

fn policy() -> Value {
    serde_json::from_str(POLICY).expect("evidence policy decision must be valid JSON")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decision_sections_digest(value: &Value) -> String {
    let sections = serde_json::json!({
        "completion": value["completion"],
        "configuration": value["configuration"],
        "configuration_fixture": value["configuration_fixture"],
        "cursor": value["cursor"],
        "fixed_vector": value["fixed_vector"],
        "policy_digest": value["policy_digest"],
        "publication_relationship": value["publication_relationship"],
        "required_optional_semantics": value["required_optional_semantics"],
        "selector": value["selector"],
        "source_kinds": value["source_kinds"],
        "configuration_vectors": value["configuration_vectors"],
        "completion_vectors": value["completion_vectors"],
        "cursor_vectors": value["cursor_vectors"],
        "coverage_vectors": value["coverage_vectors"]
    });
    sha256_hex(&serde_json::to_vec(&sections).expect("serialize decision sections"))
}

fn stable_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

fn mutate_config(base: &Value, mutation: &Value) -> Value {
    let mut config = base.clone();
    let object = config.as_object_mut().unwrap();
    match mutation["op"].as_str().unwrap() {
        "none" => {}
        "append_source" => object["sources"]
            .as_array_mut()
            .unwrap()
            .push(mutation["source"].clone()),
        "set_source_field" => {
            object["sources"][0][mutation["field"].as_str().unwrap()] = mutation["value"].clone();
        }
        "set_source_fields" => {
            for (field, value) in mutation["fields"].as_object().unwrap() {
                object["sources"][0][field] = value.clone();
            }
        }
        "remove_top_field" => {
            object.remove(mutation["field"].as_str().unwrap());
        }
        "set_top_field" => {
            object.insert(
                mutation["field"].as_str().unwrap().to_owned(),
                mutation["value"].clone(),
            );
        }
        "add_top_field" => {
            object.insert(
                mutation["field"].as_str().unwrap().to_owned(),
                mutation["value"].clone(),
            );
        }
        "repeat_sources" => {
            let template = object["sources"][0].clone();
            let count = mutation["count"].as_u64().unwrap();
            let sources = (0..count)
                .map(|index| {
                    let mut source = template.clone();
                    source["source_id"] = format!("trade-{index}").into();
                    source["relay_id"] = format!("relay-{index}").into();
                    source
                })
                .collect();
            object.insert("sources".to_owned(), Value::Array(sources));
        }
        "remove_source_field" => {
            object["sources"][0]
                .as_object_mut()
                .unwrap()
                .remove(mutation["field"].as_str().unwrap());
        }
        "add_source_field" => {
            object["sources"][0].as_object_mut().unwrap().insert(
                mutation["field"].as_str().unwrap().to_owned(),
                mutation["value"].clone(),
            );
        }
        operation => panic!("unknown configuration mutation {operation}"),
    }
    config
}

fn validate_config(config: &Value) -> Result<(), &'static str> {
    let Some(object) = config.as_object() else {
        return Err("invalid_config_type");
    };
    let required_top = BTreeSet::from(["contract", "contract_version", "policy_id", "sources"]);
    let actual_top = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if !required_top.is_subset(&actual_top) {
        return Err("missing_required_field");
    }
    if actual_top != required_top {
        return Err("unknown_field");
    }
    if config["contract"] != "radroots.rhi.evidence-policy" || config["contract_version"] != 1 {
        return Err("invalid_contract_identity");
    }
    if !config["policy_id"].as_str().is_some_and(stable_id) {
        return Err("invalid_policy_id");
    }
    let Some(sources) = config["sources"].as_array() else {
        return Err("invalid_sources_type");
    };
    if sources.is_empty() || sources.len() > 16 {
        return Err("source_count_out_of_range");
    }
    let required_source = BTreeSet::from([
        "deadline_ms",
        "kind",
        "lookback_seconds",
        "overlap_seconds",
        "relay_id",
        "required",
        "selector",
        "source_id",
    ]);
    for source in sources {
        let Some(source) = source.as_object() else {
            return Err("invalid_source_type");
        };
        let actual = source.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if !required_source.is_subset(&actual) {
            return Err("missing_required_field");
        }
        if actual != required_source {
            return Err("unknown_field");
        }
        if source["kind"] != "nostr_relay" {
            return Err("unsupported_source_kind");
        }
        if source["selector"] != "trade_mutation_lineage_v1" {
            return Err("unsupported_selector");
        }
        if !source["source_id"].as_str().is_some_and(stable_id)
            || !source["relay_id"].as_str().is_some_and(stable_id)
        {
            return Err("invalid_source_id");
        }
        if !source["required"].is_boolean() {
            return Err("invalid_required_type");
        }
        let deadline = source["deadline_ms"]
            .as_u64()
            .ok_or("invalid_deadline_type")?;
        if !(100..=30_000).contains(&deadline) {
            return Err("deadline_out_of_range");
        }
        let lookback = source["lookback_seconds"]
            .as_u64()
            .ok_or("invalid_lookback_type")?;
        if !(60..=2_678_400).contains(&lookback) {
            return Err("lookback_out_of_range");
        }
        let overlap = source["overlap_seconds"]
            .as_u64()
            .ok_or("invalid_overlap_type")?;
        if !(1..=86_400).contains(&overlap) {
            return Err("overlap_out_of_range");
        }
        if overlap > lookback {
            return Err("overlap_exceeds_lookback");
        }
    }
    let source_ids = sources
        .iter()
        .map(|source| source["source_id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    if source_ids.len() != sources.len() {
        return Err("duplicate_source_id");
    }
    let bindings = sources
        .iter()
        .map(|source| {
            format!(
                "{}|{}|{}",
                source["kind"].as_str().unwrap(),
                source["relay_id"].as_str().unwrap(),
                source["selector"].as_str().unwrap()
            )
        })
        .collect::<BTreeSet<_>>();
    if bindings.len() != sources.len() {
        return Err("duplicate_source_binding");
    }
    if !sources.iter().any(|source| source["required"] == true) {
        return Err("no_required_source");
    }
    Ok(())
}

fn completion(input: &Value) -> &'static str {
    if input["unsupported"] == true {
        "unsupported"
    } else if input["resource_limit"] == true {
        "incomplete_resource_limit"
    } else if input["disconnect"] == true || input["relay_error"] == true {
        "incomplete_unavailable"
    } else if let Some(eose_at) = input["eose_at_ms"].as_u64() {
        if eose_at < input["deadline_ms"].as_u64().unwrap() {
            "complete"
        } else {
            "incomplete_timeout"
        }
    } else if input["deadline_elapsed_without_eose"] == true {
        "incomplete_timeout"
    } else {
        "incomplete_unknown"
    }
}

fn coverage(vector: &Value) -> (&'static str, Vec<&'static str>) {
    let sources = vector["sources"].as_array().unwrap();
    if sources
        .iter()
        .any(|source| source["required"] == true && source["completion"] == "unsupported")
    {
        return ("Unsupported", vec!["Indeterminate"]);
    }
    let all_required_complete = sources
        .iter()
        .filter(|source| source["required"] == true)
        .all(|source| source["completion"] == "complete");
    if all_required_complete && vector["scope_prerequisites_satisfied"] == true {
        return ("ScopeSatisfied", vec!["Valid", "Invalid", "Indeterminate"]);
    }
    if sources.iter().any(|source| {
        source["completion"] == "complete" || source["admitted_events"].as_u64().unwrap() > 0
    }) {
        ("Partial", vec!["Indeterminate"])
    } else {
        ("Missing", vec!["Indeterminate"])
    }
}

#[test]
fn policy_identity_source_and_selector_are_exact() {
    assert_eq!(CONSUMER_ROOT, "rhi\n");
    let value = policy();
    assert_eq!(value["schema"], "radroots.rhi.evidence-policy-decision.v1");
    assert_eq!(value["contract_version"], 1);
    assert_eq!(value["decision_state"], "reserved_preimplementation");
    assert_eq!(
        value["source_kinds"]["qualified_v1"],
        serde_json::json!(["nostr_relay"])
    );
    assert_eq!(
        value["selector"],
        serde_json::json!({
            "id": "trade_mutation_lineage_v1",
            "trade_event_contract": {
                "repository": "https://github.com/radrootslabs/lib",
                "path": "contracts/architecture/decisions/services_hardening_events.v1.json",
                "schema": "radroots.services-hardening.event-decisions.v1",
                "contract_family": "radroots.trade.mutation-index.v1"
            },
            "event_kinds": [3470, 3471, 3472, 3473, 3474],
            "event_kind_meanings": ["proposal", "decision", "revision_proposal", "revision_decision", "cancellation"],
            "dynamic_filter": { "tag": "#d", "value": "exact_job_trade_id" },
            "required_structural_tags": ["contract", "d", "x:mutation", "p:buyer", "p:seller"],
            "nonproposal_additional_tags": ["x:root", "x:parent"],
            "author_policy": "validate_against_typed_trade_party_and_mutation_contract",
            "filter_extra_tags": false,
            "maximum_events_per_result": 4096,
            "maximum_result_bytes": 8_388_608
        })
    );
}

#[test]
fn cursor_completion_and_coverage_fail_closed() {
    let value = policy();
    assert_eq!(
        value["cursor"]["tuple"],
        serde_json::json!(["created_at_unix_seconds", "event_id_lowercase_hex"])
    );
    assert_eq!(value["cursor"]["equal_timestamp_safe"], true);
    assert_eq!(
        value["cursor"]["rejected_event"],
        "cannot_advance_cursor_or_completion_or_dirty_generation"
    );
    assert_eq!(
        value["completion"]["success_evidence"],
        "nostr_eose_received_before_source_deadline"
    );
    assert_eq!(
        value["completion"]["response_without_eose"],
        "incomplete_unknown"
    );
    assert_eq!(
        value["required_optional_semantics"]["coverage_precedence"],
        serde_json::json!(["Unsupported", "ScopeSatisfied", "Partial", "Missing"])
    );
    assert_eq!(
        value["required_optional_semantics"]["optional_incomplete"],
        "record_safe_source_result_without_blocking_scope_satisfied"
    );
    let base = &value["configuration_fixture"];
    for vector in value["configuration_vectors"].as_array().unwrap() {
        let candidate = mutate_config(base, &vector["mutation"]);
        let actual = validate_config(&candidate)
            .map(|()| "valid")
            .unwrap_or_else(|error| error);
        assert_eq!(
            actual,
            vector["expected"].as_str().unwrap(),
            "configuration vector {}",
            vector["case"]
        );
    }
    for vector in value["completion_vectors"].as_array().unwrap() {
        assert_eq!(
            completion(&vector["input"]),
            vector["expected"].as_str().unwrap(),
            "completion vector {}",
            vector["case"]
        );
    }
    for vector in value["cursor_vectors"].as_array().unwrap() {
        let current = &vector["current"];
        let candidate = &vector["candidate"];
        let next = if candidate["admitted"] == true
            && vector["source_complete"] == true
            && vector["generation_fence"] == true
            && (
                candidate["created_at_unix_seconds"].as_u64(),
                candidate["event_id_lowercase_hex"].as_str(),
            ) > (
                current["created_at_unix_seconds"].as_u64(),
                current["event_id_lowercase_hex"].as_str(),
            ) {
            candidate
        } else {
            current
        };
        let projected = serde_json::json!({
            "created_at_unix_seconds": next["created_at_unix_seconds"],
            "event_id_lowercase_hex": next["event_id_lowercase_hex"]
        });
        assert_eq!(
            projected, vector["expected"],
            "cursor vector {}",
            vector["case"]
        );
    }
    for vector in value["coverage_vectors"].as_array().unwrap() {
        let (actual_coverage, actual_outcomes) = coverage(vector);
        assert_eq!(actual_coverage, vector["expected_coverage"]);
        assert_eq!(
            actual_outcomes,
            vector["allowed_outcomes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|outcome| outcome.as_str().unwrap())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn policy_digest_vector_and_publication_independence_are_exact() {
    let value = policy();
    let vector = &value["fixed_vector"]["normalized_policy"];
    let canonical = serde_json::to_vec(vector).expect("canonical vector JSON");
    assert_eq!(
        canonical,
        value["fixed_vector"]["canonical_policy_utf8"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    let mut preimage = b"radroots:rhi-evidence-policy:v1\0".to_vec();
    preimage.extend_from_slice(&canonical);
    assert_eq!(
        preimage,
        value["fixed_vector"]["preimage_utf8"]
            .as_str()
            .unwrap()
            .as_bytes()
    );
    assert_eq!(
        sha256_hex(&preimage),
        value["fixed_vector"]["policy_digest"].as_str().unwrap()
    );
    assert_eq!(
        value["publication_relationship"],
        serde_json::json!({
            "relationship": "independent",
            "evidence_sources_are_publication_targets": false,
            "publication_targets_affect_coverage_or_outcome": false,
            "publication_failure_changes_report_or_attestation_content": false,
            "required_publication_failure": "publication_workflow_and_readiness_only",
            "disabled_publication": "no_target_or_network_work"
        })
    );
    assert_eq!(
        decision_sections_digest(&value),
        "242642269d9272d2a1bae50bae5a02a1329cab1a2dfb636d363aa362ce475011"
    );
}
