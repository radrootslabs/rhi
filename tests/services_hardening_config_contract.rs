#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Component, Path};

use nostr::PublicKey;
use serde_json::{Map, Value, json};

const CONFIG_SCHEMA: &str = include_str!("../contracts/services_hardening/config.v1.schema.json");
const CONFIG_EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const EVIDENCE_POLICY: &str =
    include_str!("../contracts/services_hardening/evidence_policy.v1.json");

#[derive(Clone, Copy)]
enum Profile {
    Production,
    RepoLocal,
}

fn schema() -> Value {
    serde_json::from_str(CONFIG_SCHEMA).expect("configuration schema must be valid JSON")
}

fn evidence_policy() -> Value {
    serde_json::from_str(EVIDENCE_POLICY).expect("evidence policy must be valid JSON")
}

fn example() -> Value {
    let value = toml::from_str::<toml::Value>(CONFIG_EXAMPLE)
        .expect("configuration example must be valid TOML");
    serde_json::to_value(value).expect("TOML value must convert to JSON")
}

fn schema_valid(value: &Value) -> bool {
    jsonschema::validator_for(&schema())
        .expect("configuration schema must compile")
        .is_valid(value)
}

fn string_array<'a>(value: &'a Value, pointer: &str) -> Vec<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .expect("string array")
        .iter()
        .map(|value| value.as_str().expect("string item"))
        .collect()
}

fn semantic_valid(value: &Value, profile: Profile) -> bool {
    if !schema_valid(value) {
        return false;
    }

    let relays = value["relays"].as_array().expect("relays");
    let relay_ids = relays
        .iter()
        .map(|relay| relay["id"].as_str().expect("relay id"))
        .collect::<Vec<_>>();
    let relay_urls = relays
        .iter()
        .map(|relay| relay["url"].as_str().expect("relay URL"))
        .collect::<Vec<_>>();
    let parsed_relay_urls = relay_urls
        .iter()
        .map(|raw| {
            url::Url::parse(raw)
                .ok()
                .filter(|parsed| parsed.as_str() == *raw)
        })
        .collect::<Vec<_>>();
    if relay_ids.iter().collect::<BTreeSet<_>>().len() != relay_ids.len()
        || relay_urls.iter().collect::<BTreeSet<_>>().len() != relay_urls.len()
        || parsed_relay_urls.iter().any(Option::is_none)
        || parsed_relay_urls.iter().flatten().any(|url| {
            !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
        })
        || relays.iter().any(|relay| {
            !relay["read"].as_bool().expect("read") && !relay["write"].as_bool().expect("write")
        })
    {
        return false;
    }
    if parsed_relay_urls.iter().flatten().any(|url| match profile {
        Profile::Production => url.scheme() != "wss",
        Profile::RepoLocal => match url.scheme() {
            "wss" => false,
            "ws" => !matches!(
                url.host_str(),
                Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
            ),
            _ => true,
        },
    }) {
        return false;
    }
    let relays_by_id = relays
        .iter()
        .map(|relay| (relay["id"].as_str().expect("relay id"), relay))
        .collect::<BTreeMap<_, _>>();

    let envelope_path = value["identity"]["service"]["envelope_path"]
        .as_str()
        .expect("envelope path");
    let path = Path::new(envelope_path);
    if envelope_path.len() > 4096
        || path == Path::new("/")
        || !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return false;
    }

    let Ok(public_key) = PublicKey::from_hex(
        value["identity"]["service"]["expected_public_key"]
            .as_str()
            .expect("public key"),
    ) else {
        return false;
    };
    if public_key.xonly().is_err() {
        return false;
    }

    let sources = value["evidence"]["sources"]
        .as_array()
        .expect("evidence sources");
    let source_ids = sources
        .iter()
        .map(|source| source["source_id"].as_str().expect("source id"))
        .collect::<Vec<_>>();
    let source_bindings = sources
        .iter()
        .map(|source| {
            (
                source["kind"].as_str().expect("kind"),
                source["relay_id"].as_str().expect("relay id"),
                source["selector"].as_str().expect("selector"),
            )
        })
        .collect::<Vec<_>>();
    if source_ids.iter().collect::<BTreeSet<_>>().len() != source_ids.len()
        || source_bindings.iter().collect::<BTreeSet<_>>().len() != source_bindings.len()
        || !sources
            .iter()
            .any(|source| source["required"].as_bool() == Some(true))
        || sources.iter().any(|source| {
            source["overlap_seconds"].as_u64() > source["lookback_seconds"].as_u64()
                || relays_by_id
                    .get(source["relay_id"].as_str().expect("relay id"))
                    .and_then(|relay| relay["read"].as_bool())
                    != Some(true)
        })
    {
        return false;
    }

    let reconciliation = &value["reconciliation"];
    let lease_ms = reconciliation["lease_ms"].as_u64().unwrap_or(30_000);
    let lease_renewal_ms = reconciliation["lease_renewal_ms"]
        .as_u64()
        .unwrap_or(10_000);
    let initial_backoff_ms = reconciliation["initial_backoff_ms"].as_u64().unwrap_or(250);
    let maximum_backoff_ms = reconciliation["maximum_backoff_ms"]
        .as_u64()
        .unwrap_or(30_000);
    let attempt_deadline_ms = reconciliation["attempt_deadline_ms"]
        .as_u64()
        .unwrap_or(30_000);
    if lease_renewal_ms >= lease_ms
        || initial_backoff_ms > maximum_backoff_ms
        || sources
            .iter()
            .any(|source| source["deadline_ms"].as_u64() > Some(attempt_deadline_ms))
    {
        return false;
    }

    let publication = &value["publication"];
    if publication["mode"] == "required"
        && (string_array(value, "/publication/target_relay_ids")
            .iter()
            .any(|id| {
                relays_by_id
                    .get(id)
                    .and_then(|relay| relay["write"].as_bool())
                    != Some(true)
            })
            || publication["retry"]["initial_backoff_ms"]
                .as_u64()
                .unwrap_or(250)
                > publication["retry"]["maximum_backoff_ms"]
                    .as_u64()
                    .unwrap_or(30_000))
    {
        return false;
    }

    let presence = &value["presence"];
    if presence["enabled"] == true {
        if !presence["profile"].as_bool().unwrap_or(false)
            && !presence["application_handler"].as_bool().unwrap_or(false)
        {
            return false;
        }
        if string_array(value, "/presence/target_relay_ids")
            .iter()
            .any(|id| {
                relays_by_id
                    .get(id)
                    .and_then(|relay| relay["write"].as_bool())
                    != Some(true)
            })
        {
            return false;
        }
    } else if presence["profile"] != false || presence["application_handler"] != false {
        return false;
    }

    let operations = &value["operations"];
    if operations["enabled"] == true {
        let Ok(listen) = operations["listen"]
            .as_str()
            .unwrap_or_default()
            .parse::<SocketAddr>()
        else {
            return false;
        };
        if listen.port() == 0
            || (operations["bind_policy"] == "loopback_only" && !listen.ip().is_loopback())
        {
            return false;
        }
    }
    true
}

fn assert_rejected(value: &Value, profile: Profile) {
    assert!(
        !semantic_valid(value, profile),
        "negative configuration vector unexpectedly passed"
    );
}

fn insert(value: &mut Value, pointer: &str, key: &str, replacement: Value) {
    value
        .pointer_mut(pointer)
        .and_then(Value::as_object_mut)
        .expect("object pointer")
        .insert(key.to_owned(), replacement);
}

fn defaults(value: &Value, pointer: &str, output: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(object) => {
            if let Some(default) = object.get("default") {
                assert!(
                    object.contains_key("x-radroots-default-source"),
                    "default without provenance at {pointer}"
                );
                output.insert(pointer.to_owned(), default.clone());
            }
            for (key, child) in object {
                defaults(child, &format!("{pointer}/{key}"), output);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                defaults(child, &format!("{pointer}/{index}"), output);
            }
        }
        _ => {}
    }
}

fn assert_integer_bounds(value: &Value, pointer: &str) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("integer".to_owned())) {
                assert!(
                    object.contains_key("minimum"),
                    "missing minimum at {pointer}"
                );
                assert!(
                    object.contains_key("maximum"),
                    "missing maximum at {pointer}"
                );
            }
            for (key, child) in object {
                assert_integer_bounds(child, &format!("{pointer}/{key}"));
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                assert_integer_bounds(child, &format!("{pointer}/{index}"));
            }
        }
        _ => {}
    }
}

fn assert_object_schemas_are_closed(value: &Value, pointer: &str) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".to_owned())) {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "open object schema at {pointer}"
                );
            }
            for (key, child) in object {
                assert_object_schemas_are_closed(child, &format!("{pointer}/{key}"));
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                assert_object_schemas_are_closed(child, &format!("{pointer}/{index}"));
            }
        }
        _ => {}
    }
}

#[test]
fn schema_identity_structure_and_machine_policy_are_exact() {
    let schema = schema();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["required"],
        json!([
            "schema",
            "schema_version",
            "service",
            "logging",
            "operations",
            "database",
            "identity",
            "relays",
            "network",
            "evidence",
            "reconciliation",
            "attestation",
            "publication",
            "presence",
            "resource_limits",
            "retention"
        ])
    );
    assert_eq!(
        schema["properties"]["schema"]["const"],
        "radroots.rhi.config"
    );
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(
        schema["x-radroots-contract"]["bootstrap_only"],
        json!(["profile", "instance", "repo_local_root", "config_path"])
    );
    assert_eq!(
        schema["x-radroots-contract"]["document_max_utf8_bytes"],
        1_048_576
    );
    assert_eq!(
        schema["x-radroots-contract"]["duplicate_keys"],
        "reject_on_original_wire"
    );
    assert_eq!(
        schema["x-radroots-contract"]["null_values"],
        "reject_on_original_wire"
    );
    assert_eq!(
        schema["x-radroots-contract"]["environment_overlay"],
        "forbidden"
    );
    assert_eq!(
        schema["x-radroots-contract"]["protected_material"],
        "forbidden"
    );
    assert_eq!(
        schema["x-radroots-contract"]["effective_output"],
        "deterministic_redacted_with_exact_provenance"
    );
    assert_eq!(
        schema["x-radroots-contract"]["evidence_policy_sha256"],
        "b4da4aa2863905975c577668bc75cbb03857106a67899278130915e085319dc8"
    );
    assert_integer_bounds(&schema, "");
    assert_object_schemas_are_closed(&schema, "");

    let mut found_defaults = BTreeMap::new();
    defaults(&schema, "", &mut found_defaults);
    assert!(!found_defaults.is_empty());
    for pointer in found_defaults.keys() {
        let source = schema.pointer(pointer).expect("default pointer")["x-radroots-default-source"]
            .as_str()
            .expect("default source");
        assert!(
            schema["x-radroots-contract"]["safe_default_sources"]
                .as_array()
                .expect("safe default sources")
                .iter()
                .any(|allowed| allowed == source)
        );
    }
}

#[test]
fn evidence_policy_is_consumed_without_reinterpretation() {
    let schema = schema();
    let policy = evidence_policy();
    assert_eq!(
        policy["configuration"]["contract"],
        schema["$defs"]["evidence"]["properties"]["contract"]["const"]
    );
    assert_eq!(
        policy["configuration"]["contract_version"],
        schema["$defs"]["evidence"]["properties"]["contract_version"]["const"]
    );
    assert_eq!(
        policy["configuration"]["sources"]["minimum_items"],
        schema["$defs"]["evidence"]["properties"]["sources"]["minItems"]
    );
    assert_eq!(
        policy["configuration"]["sources"]["maximum_items"],
        schema["$defs"]["evidence"]["properties"]["sources"]["maxItems"]
    );
    for field in ["deadline_ms", "lookback_seconds", "overlap_seconds"] {
        assert_eq!(
            policy["configuration"]["source"][field]["minimum"],
            schema["$defs"]["evidence_source"]["properties"][field]["minimum"]
        );
        assert_eq!(
            policy["configuration"]["source"][field]["maximum"],
            schema["$defs"]["evidence_source"]["properties"][field]["maximum"]
        );
    }
    assert_eq!(
        policy["source_kinds"]["qualified_v1"],
        json!(["nostr_relay"])
    );
    assert_eq!(policy["selector"]["id"], "trade_mutation_lineage_v1");
    assert_eq!(
        policy["completion"]["success_evidence"],
        "nostr_eose_received_before_source_deadline"
    );
    assert_eq!(
        policy["selector"]["maximum_events_per_result"],
        schema["$defs"]["source_result_limits"]["properties"]["events"]["maximum"]
    );
    assert_eq!(
        policy["selector"]["maximum_result_bytes"],
        schema["$defs"]["source_result_limits"]["properties"]["bytes"]["maximum"]
    );
}

#[test]
fn canonical_example_and_required_positive_variants_pass() {
    let value = example();
    let validator = jsonschema::validator_for(&schema()).expect("schema");
    let schema_errors = validator
        .iter_errors(&value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(schema_errors.is_empty(), "{schema_errors:?}");
    assert!(semantic_valid(&value, Profile::Production));
    assert_eq!(value["identity"]["service"]["provider"], "encrypted_file");
    assert_eq!(
        value["attestation"],
        json!({
            "contract": "radroots.rhi.evidence_attestation.v1",
            "contract_version": 1,
            "method": "signed_evidence_snapshot",
            "reducer_contract": "radroots.trade.reducer.v1",
            "reducer_contract_version": 1
        })
    );
    assert_eq!(
        value["evidence"],
        evidence_policy()["configuration_fixture"]
    );

    let mut publication_disabled = value.clone();
    publication_disabled["publication"] = json!({"mode": "disabled"});
    assert!(semantic_valid(&publication_disabled, Profile::Production));

    let mut presence_disabled = value.clone();
    presence_disabled["presence"] = json!({
        "enabled": false,
        "profile": false,
        "application_handler": false
    });
    assert!(semantic_valid(&presence_disabled, Profile::Production));

    let mut repo_local = value.clone();
    repo_local["relays"][0]["url"] = json!("ws://127.0.0.1:8080/");
    repo_local["relays"][1]["url"] = json!("ws://localhost:8081/");
    assert!(semantic_valid(&repo_local, Profile::RepoLocal));
    assert_rejected(&repo_local, Profile::Production);

    let mut enabled_operations = value;
    enabled_operations["operations"] = json!({
        "enabled": true,
        "listen": "127.0.0.1:9460",
        "bind_policy": "loopback_only",
        "limits": {}
    });
    assert!(semantic_valid(&enabled_operations, Profile::Production));

    let mut sparse_retry = example();
    sparse_retry["publication"]["retry"] = json!({"initial_backoff_ms": 250});
    assert!(semantic_valid(&sparse_retry, Profile::Production));
}

#[test]
fn structural_unknown_legacy_and_original_wire_vectors_fail() {
    let value = example();
    for (pointer, key) in [
        ("", "unknown"),
        ("/service", "shutdowm_grace_ms"),
        ("/identity/service", "wrapping_key_path"),
        ("/evidence/sources/0", "completion"),
        ("/resource_limits/admin", "body_bytes"),
    ] {
        let mut invalid = value.clone();
        insert(&mut invalid, pointer, key, json!(true));
        assert_rejected(&invalid, Profile::Production);
    }
    for field in schema()["x-radroots-contract"]["forbidden_prototype_fields"]
        .as_array()
        .expect("forbidden fields")
    {
        let mut invalid = value.clone();
        invalid.as_object_mut().expect("config object").insert(
            field.as_str().expect("field").to_owned(),
            Value::Object(Map::new()),
        );
        assert_rejected(&invalid, Profile::Production);
    }
    assert!(toml::from_str::<toml::Value>("schema='a'\nschema='b'\n").is_err());
    assert!(
        toml::from_str::<toml::Value>(
            "[service]\nshutdown_grace_ms=30000\nshutdown_grace_ms=30001\n"
        )
        .is_err()
    );
    assert!(toml::from_str::<toml::Value>("schema = null\n").is_err());
}

#[test]
fn identity_relay_and_network_authority_fail_closed() {
    let value = example();
    let mut relative = value.clone();
    relative["identity"]["service"]["envelope_path"] = json!("relative/path");
    assert_rejected(&relative, Profile::Production);
    for path in ["/", "/var/lib/radroots/../escape.ncrypt"] {
        let mut invalid = value.clone();
        invalid["identity"]["service"]["envelope_path"] = json!(path);
        assert_rejected(&invalid, Profile::Production);
    }
    for provider in [
        "plaintext_file",
        "external_command",
        "keyring",
        "managed_account",
    ] {
        let mut invalid = value.clone();
        invalid["identity"]["service"]["provider"] = json!(provider);
        assert_rejected(&invalid, Profile::Production);
    }
    let mut invalid = value.clone();
    invalid["identity"]["service"]["expected_public_key"] = json!("f".repeat(64));
    assert_rejected(&invalid, Profile::Production);
    let mut duplicate_id = value.clone();
    duplicate_id["relays"][1]["id"] = duplicate_id["relays"][0]["id"].clone();
    assert_rejected(&duplicate_id, Profile::Production);
    let mut duplicate_url = value.clone();
    duplicate_url["relays"][1]["url"] = duplicate_url["relays"][0]["url"].clone();
    assert_rejected(&duplicate_url, Profile::Production);
    let mut inactive = value.clone();
    inactive["relays"][0]["read"] = json!(false);
    inactive["relays"][0]["write"] = json!(false);
    assert_rejected(&inactive, Profile::Production);
    let mut insecure = value.clone();
    insecure["relays"][0]["url"] = json!("ws://127.0.0.1:8080/");
    assert_rejected(&insecure, Profile::Production);
    let mut noncanonical = value;
    noncanonical["relays"][0]["url"] = json!("WSS://relay.example.com");
    assert_rejected(&noncanonical, Profile::Production);
}

#[test]
fn evidence_scope_bounds_and_relationships_fail_closed() {
    let value = example();
    for (pointer, minimum, below, maximum, above) in [
        ("/evidence/sources/0/deadline_ms", 100, 99, 30_000, 30_001),
        (
            "/evidence/sources/0/lookback_seconds",
            60,
            59,
            2_678_400,
            2_678_401,
        ),
        ("/evidence/sources/0/overlap_seconds", 1, 0, 86_400, 86_401),
    ] {
        for valid in [minimum, maximum] {
            let mut candidate = value.clone();
            *candidate.pointer_mut(pointer).expect("bounded field") = json!(valid);
            if pointer.ends_with("lookback_seconds") && valid == 60 {
                candidate["evidence"]["sources"][0]["overlap_seconds"] = json!(60);
            }
            assert!(semantic_valid(&candidate, Profile::Production), "{pointer}");
        }
        for invalid in [below, above] {
            let mut candidate = value.clone();
            *candidate.pointer_mut(pointer).expect("bounded field") = json!(invalid);
            assert_rejected(&candidate, Profile::Production);
        }
    }
    let mut no_required = value.clone();
    no_required["evidence"]["sources"][0]["required"] = json!(false);
    assert_rejected(&no_required, Profile::Production);
    let mut overlap = value.clone();
    overlap["evidence"]["sources"][0]["lookback_seconds"] = json!(60);
    overlap["evidence"]["sources"][0]["overlap_seconds"] = json!(61);
    assert_rejected(&overlap, Profile::Production);
    let mut missing_relay = value.clone();
    missing_relay["evidence"]["sources"][0]["relay_id"] = json!("missing");
    assert_rejected(&missing_relay, Profile::Production);
    let mut write_only = value.clone();
    write_only["relays"][0]["read"] = json!(false);
    assert_rejected(&write_only, Profile::Production);
    for replacement in [json!("filesystem"), json!("publication_target")] {
        let mut invalid = value.clone();
        invalid["evidence"]["sources"][0]["kind"] = replacement;
        assert_rejected(&invalid, Profile::Production);
    }
    let mut selector = value.clone();
    selector["evidence"]["sources"][0]["selector"] = json!("all_events_v1");
    assert_rejected(&selector, Profile::Production);
    let mut seventeen = value;
    let source = seventeen["evidence"]["sources"][0].clone();
    seventeen["evidence"]["sources"] = Value::Array(vec![source; 17]);
    assert_rejected(&seventeen, Profile::Production);
}

#[test]
fn reconciliation_publication_presence_and_operations_fail_closed() {
    let value = example();
    let mut renewal = value.clone();
    renewal["reconciliation"]["lease_renewal_ms"] = renewal["reconciliation"]["lease_ms"].clone();
    assert_rejected(&renewal, Profile::Production);
    let mut backoff = value.clone();
    backoff["reconciliation"]["initial_backoff_ms"] = json!(30_001);
    assert_rejected(&backoff, Profile::Production);
    let mut attempt = value.clone();
    attempt["reconciliation"]["attempt_deadline_ms"] = json!(9_999);
    assert_rejected(&attempt, Profile::Production);
    let mut publication_relay = value.clone();
    publication_relay["publication"]["target_relay_ids"] = json!(["missing"]);
    assert_rejected(&publication_relay, Profile::Production);
    let mut disabled_leak = value.clone();
    disabled_leak["publication"]["mode"] = json!("disabled");
    assert_rejected(&disabled_leak, Profile::Production);
    let mut publication_backoff = value.clone();
    publication_backoff["publication"]["retry"]["initial_backoff_ms"] = json!(30_001);
    assert_rejected(&publication_backoff, Profile::Production);
    let mut presence_relay = value.clone();
    presence_relay["presence"]["target_relay_ids"] = json!(["missing"]);
    assert_rejected(&presence_relay, Profile::Production);
    let mut no_desired_presence = value.clone();
    no_desired_presence["presence"]["profile"] = json!(false);
    no_desired_presence["presence"]["application_handler"] = json!(false);
    assert_rejected(&no_desired_presence, Profile::Production);
    let mut disabled_presence_leak = value.clone();
    disabled_presence_leak["presence"]["enabled"] = json!(false);
    assert_rejected(&disabled_presence_leak, Profile::Production);
    let mut public_loopback_policy = value;
    public_loopback_policy["operations"] = json!({
        "enabled": true,
        "listen": "0.0.0.0:9460",
        "bind_policy": "loopback_only",
        "limits": {}
    });
    assert_rejected(&public_loopback_policy, Profile::Production);
}

#[test]
fn exact_resource_boundaries_and_safe_defaults_are_frozen() {
    let value = example();
    for (pointer, maximum, over) in [
        ("/database/busy_timeout_ms", 60_000_u64, 60_001_u64),
        ("/database/max_connections", 8, 9),
        ("/resource_limits/admin/header_count", 64, 65),
        ("/resource_limits/admin/query_items", 200, 201),
        ("/resource_limits/events/wire_bytes", 524_288, 524_289),
        ("/resource_limits/source_results/events", 4_096, 4_097),
        (
            "/resource_limits/source_results/bytes",
            8_388_608,
            8_388_609,
        ),
        ("/resource_limits/metrics/samples", 512, 513),
        ("/resource_limits/runtime/worker_threads", 32, 33),
    ] {
        let mut minimum = value.clone();
        *minimum.pointer_mut(pointer).expect("bounded field") = json!(1);
        if pointer.ends_with("worker_threads") {
            *minimum.pointer_mut(pointer).expect("bounded field") = json!(2);
        }
        assert!(
            semantic_valid(&minimum, Profile::Production),
            "minimum {pointer}"
        );
        let mut exact = value.clone();
        *exact.pointer_mut(pointer).expect("bounded field") = json!(maximum);
        assert!(
            semantic_valid(&exact, Profile::Production),
            "maximum {pointer}"
        );
        let mut zero = value.clone();
        *zero.pointer_mut(pointer).expect("bounded field") = json!(0);
        assert_rejected(&zero, Profile::Production);
        let mut excessive = value.clone();
        *excessive.pointer_mut(pointer).expect("bounded field") = json!(over);
        assert_rejected(&excessive, Profile::Production);
    }
    let mut exact_admin_response = value.clone();
    exact_admin_response["resource_limits"]["admin"]["response_body_utf8_bytes"] = json!(512);
    assert!(semantic_valid(&exact_admin_response, Profile::Production));
    let mut undersized = value.clone();
    undersized["resource_limits"]["admin"]["response_body_utf8_bytes"] = json!(511);
    assert_rejected(&undersized, Profile::Production);

    let mut omitted = value;
    omitted["service"] = json!({});
    omitted["logging"] = json!({});
    omitted["network"] = json!({});
    omitted["reconciliation"] = json!({});
    omitted["resource_limits"] = json!({});
    omitted["database"]
        .as_object_mut()
        .expect("database")
        .remove("busy_timeout_ms");
    omitted["database"]
        .as_object_mut()
        .expect("database")
        .remove("max_connections");
    assert!(semantic_valid(&omitted, Profile::Production));
}

#[test]
fn schema_version_authority_and_protected_material_are_closed() {
    let value = example();
    for replacement in [json!("radroots.rhi.config.v2"), json!("rhi")] {
        let mut invalid = value.clone();
        invalid["schema"] = replacement;
        assert_rejected(&invalid, Profile::Production);
    }
    for replacement in [json!(0), json!(2), json!("1")] {
        let mut invalid = value.clone();
        invalid["schema_version"] = replacement;
        assert_rejected(&invalid, Profile::Production);
    }
    for required in [
        "minimum_free_bytes",
        "identity",
        "relays",
        "evidence",
        "sources",
        "deadline_ms",
        "lookback_seconds",
        "overlap_seconds",
        "reconciliation",
        "attestation",
        "publication",
        "presence",
        "resource_limits",
        "retention",
    ] {
        assert!(
            CONFIG_SCHEMA.contains(required),
            "missing authority {required}"
        );
    }
    let lowercase = CONFIG_EXAMPLE.to_ascii_lowercase();
    for forbidden in [
        "private_key",
        "secret_key",
        "mnemonic",
        "nsec1",
        "wrapping_key =",
        "wrapping_key_path",
        "rhi_",
        "env_file",
        "plaintext_file",
        "keyring",
        "managed_account",
        "worker_root",
        "state_file",
        "json_state",
    ] {
        assert!(
            !lowercase.contains(forbidden),
            "forbidden material {forbidden}"
        );
    }
}
