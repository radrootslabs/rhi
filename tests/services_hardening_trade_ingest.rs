#![forbid(unsafe_code)]

use std::error::Error;

use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
use rhi::{
    RHI_TRADE_EVENT_EXTRA_FIELD_MAX_COUNT, RHI_TRADE_EVENT_EXTRA_JSON_MAX_BYTES,
    RHI_TRADE_EVENT_ID_MAX_BYTES, RHI_TRADE_EVENT_PUBLIC_KEY_MAX_BYTES,
    RHI_TRADE_EVENT_SIGNATURE_MAX_BYTES, RHI_TRADE_INGEST_CONTRACT_VERSION, RhiConfigProfile,
    RhiTradeMutationAdmissionErrorKind, RhiTradeMutationAdmissionLimits,
    RhiTradeMutationAuthoredTimePolicy, RhiTradeMutationObservedAtUnixSeconds,
    admit_rhi_trade_mutation_event, parse_rhi_config_v1,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");
const CONTRACT: &str = include_str!("../contracts/services_hardening/trade_ingest.v1.json");
const VECTOR: &str = include_str!("../contracts/conformance/vectors/trade_ingest_proposal.v1.json");

fn configuration(overrides: &[(&str, usize)]) -> rhi::RhiConfigDocumentV1 {
    let mut source = CONFIG.to_owned();
    for (field, value) in overrides {
        let prefix = format!("{field} = ");
        let original = source
            .lines()
            .find(|line| line.starts_with(&prefix))
            .expect("configured event limit")
            .to_owned();
        source = source.replacen(&original, &format!("{field} = {value}"), 1);
    }
    parse_rhi_config_v1(source.as_bytes(), RhiConfigProfile::RepoLocal).expect("test configuration")
}

fn limits(overrides: &[(&str, usize)]) -> RhiTradeMutationAdmissionLimits {
    RhiTradeMutationAdmissionLimits::from_config(&configuration(overrides)).expect("event limits")
}

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("trade-ingest vector")
}

fn valid_wire() -> Vec<u8> {
    vector()["raw_json"]
        .as_str()
        .expect("raw event")
        .as_bytes()
        .to_vec()
}

fn observed(value: u64) -> RhiTradeMutationObservedAtUnixSeconds {
    RhiTradeMutationObservedAtUnixSeconds::new(value).expect("observation")
}

fn policy(value: u64) -> RhiTradeMutationAuthoredTimePolicy {
    RhiTradeMutationAuthoredTimePolicy::new(value).expect("time policy")
}

fn error(bytes: &[u8]) -> RhiTradeMutationAdmissionErrorKind {
    admit_rhi_trade_mutation_event(limits(&[]), bytes, observed(1_784_347_200), policy(0))
        .expect_err("event must fail")
        .kind()
}

fn keys(seed: u8) -> Keys {
    Keys::parse(&format!("{seed:02x}{}", "00".repeat(31))).expect("test keys")
}

fn fixture_keys() -> Keys {
    Keys::parse("10c5304d6c9ae3a1a16f7860f1cc8f5e3a76225a2663b3a989a0d775919b7df5")
        .expect("approved fixture keys")
}

fn signed_variant(
    kind: u16,
    created_at: u64,
    content: String,
    tags: Vec<Tag>,
    keys: &Keys,
) -> Vec<u8> {
    let event = EventBuilder::new(Kind::Custom(kind), content)
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .expect("signed event");
    serde_json::to_vec(&event).expect("event JSON")
}

fn vector_parts() -> (String, Vec<Tag>, u64) {
    let event: Value = serde_json::from_slice(&valid_wire()).expect("event JSON");
    let content = event["content"].as_str().expect("content").to_owned();
    let tags = event["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .map(|tag| {
            let values = tag
                .as_array()
                .expect("tag")
                .iter()
                .map(|value| value.as_str().expect("tag element").to_owned())
                .collect::<Vec<_>>();
            Tag::parse(values).expect("typed tag")
        })
        .collect::<Vec<_>>();
    let created_at = event["created_at"].as_u64().expect("created_at");
    (content, tags, created_at)
}

#[test]
fn machine_contract_vector_and_configuration_projection_are_exact() {
    let contract: Value = serde_json::from_str(CONTRACT).expect("trade-ingest contract");
    assert_eq!(contract["schema"], "radroots.rhi.trade-ingest.v1");
    assert_eq!(contract["contract_version"], 1);
    assert_eq!(RHI_TRADE_INGEST_CONTRACT_VERSION, 1);
    assert_eq!(contract["wire"]["original_wire_cap_before_parse"], true);
    assert_eq!(
        contract["verification"]["registered_kinds"],
        json!([3470, 3471, 3472, 3473, 3474])
    );
    assert_eq!(contract["authored_time"]["default"], "none");
    assert_eq!(contract["effects"]["sqlite"], false);

    let digest = format!("{:x}", Sha256::digest(VECTOR.as_bytes()));
    assert_eq!(contract["conformance_vector"]["sha256"], digest);

    let limits = limits(&[]);
    assert_eq!(limits.wire_bytes(), 262_144);
    assert_eq!(limits.content_bytes(), 131_072);
    assert_eq!(limits.tag_count(), 1_024);
    assert_eq!(limits.tag_total_elements(), 4_096);
    assert_eq!(limits.tag_element_bytes(), 4_096);
    assert_eq!(limits.tag_total_bytes(), 131_072);
    assert_eq!(RHI_TRADE_EVENT_ID_MAX_BYTES, 64);
    assert_eq!(RHI_TRADE_EVENT_PUBLIC_KEY_MAX_BYTES, 64);
    assert_eq!(RHI_TRADE_EVENT_SIGNATURE_MAX_BYTES, 128);
    assert_eq!(RHI_TRADE_EVENT_EXTRA_FIELD_MAX_COUNT, 64);
    assert_eq!(RHI_TRADE_EVENT_EXTRA_JSON_MAX_BYTES, 65_536);
}

#[test]
fn promoted_lib_proposal_vector_is_verified_and_retained_exactly() {
    let bytes = valid_wire();
    let admitted =
        admit_rhi_trade_mutation_event(limits(&[]), &bytes, observed(1_784_347_200), policy(0))
            .expect("canonical signed mutation");
    assert_eq!(admitted.original_bytes(), bytes);
    assert_eq!(admitted.event_id().to_hex(), vector()["event_id"]);
    assert_eq!(admitted.event_kind(), 3470);
    assert_eq!(admitted.authored_at_unix_seconds(), 1_784_347_200);
    assert_eq!(
        admitted.mutation().mutation_id.as_ref(),
        Some(admitted.mutation_id())
    );

    let rendered = format!("{admitted:?}");
    assert!(!rendered.contains(vector()["event_id"].as_str().expect("event id")));
    assert!(!rendered.contains(&admitted.mutation_id().to_hex()));
    assert!(!rendered.contains("farm-1"));
}

#[test]
fn every_configured_wire_limit_is_exact_and_precedes_verification() {
    let bytes = valid_wire();
    let value: Value = serde_json::from_slice(&bytes).expect("event");
    let tags = value["tags"].as_array().expect("tags");
    let content_bytes = value["content"].as_str().expect("content").len();
    let tag_count = tags.len();
    let tag_elements = tags
        .iter()
        .map(|tag| tag.as_array().expect("tag").len())
        .sum::<usize>();
    let tag_bytes = tags
        .iter()
        .flat_map(|tag| tag.as_array().expect("tag"))
        .map(|value| value.as_str().expect("element").len())
        .sum::<usize>();
    let tag_element_bytes = tags
        .iter()
        .flat_map(|tag| tag.as_array().expect("tag"))
        .map(|value| value.as_str().expect("element").len())
        .max()
        .expect("element");

    for (field, exact, rejected) in [
        (
            "wire_bytes",
            bytes.len(),
            RhiTradeMutationAdmissionErrorKind::EventTooLarge,
        ),
        (
            "content_bytes",
            content_bytes,
            RhiTradeMutationAdmissionErrorKind::EventContentTooLarge,
        ),
        (
            "tag_count",
            tag_count,
            RhiTradeMutationAdmissionErrorKind::TooManyTags,
        ),
        (
            "tag_total_elements",
            tag_elements,
            RhiTradeMutationAdmissionErrorKind::TooManyTagElements,
        ),
        (
            "tag_element_bytes",
            tag_element_bytes,
            RhiTradeMutationAdmissionErrorKind::TagElementTooLarge,
        ),
        (
            "tag_total_bytes",
            tag_bytes,
            RhiTradeMutationAdmissionErrorKind::TagsTooLarge,
        ),
    ] {
        admit_rhi_trade_mutation_event(
            limits(&[(field, exact)]),
            &bytes,
            observed(1_784_347_200),
            policy(0),
        )
        .unwrap_or_else(|failure| panic!("{field} exact boundary failed: {failure}"));
        let failure = admit_rhi_trade_mutation_event(
            limits(&[(field, exact - 1)]),
            &bytes,
            observed(1_784_347_200),
            policy(0),
        )
        .expect_err("just below required capacity");
        assert_eq!(failure.kind(), rejected, "{field}");
    }
}

#[test]
fn original_bytes_identifiers_duplicates_utf8_and_required_shape_fail_closed() {
    assert_eq!(error(&[]), RhiTradeMutationAdmissionErrorKind::EmptyEvent);
    assert_eq!(
        error(&[0xff]),
        RhiTradeMutationAdmissionErrorKind::InvalidEventUtf8
    );

    let oversized = vec![b' '; limits(&[]).wire_bytes() + 1];
    assert_eq!(
        error(&oversized),
        RhiTradeMutationAdmissionErrorKind::EventTooLarge
    );

    let valid = String::from_utf8(valid_wire()).expect("UTF-8 event");
    let duplicate = valid.replacen("\"id\":", "\"id\":\"11\",\"id\":", 1);
    assert_eq!(
        error(duplicate.as_bytes()),
        RhiTradeMutationAdmissionErrorKind::DuplicateEventField
    );

    let mut value: Value = serde_json::from_str(&valid).expect("event");
    value["id"] = Value::String("1".repeat(65));
    assert_eq!(
        error(&serde_json::to_vec(&value).expect("event")),
        RhiTradeMutationAdmissionErrorKind::EventIdentifierTooLarge
    );
    value["id"] = Value::Null;
    assert_eq!(
        error(&serde_json::to_vec(&value).expect("event")),
        RhiTradeMutationAdmissionErrorKind::MalformedEvent
    );
}

#[test]
fn outer_extensions_are_bounded_but_never_gain_semantic_authority() {
    let mut exact: Value = serde_json::from_slice(&valid_wire()).expect("event");
    let object = exact.as_object_mut().expect("object");
    for index in 0..RHI_TRADE_EVENT_EXTRA_FIELD_MAX_COUNT {
        object.insert(format!("extension_{index:02}"), json!(index));
    }
    let exact_bytes = serde_json::to_vec(&exact).expect("event");
    admit_rhi_trade_mutation_event(
        limits(&[]),
        &exact_bytes,
        observed(1_784_347_200),
        policy(0),
    )
    .expect("exact extra count");
    exact
        .as_object_mut()
        .expect("object")
        .insert("extension_over".to_owned(), json!(true));
    assert_eq!(
        error(&serde_json::to_vec(&exact).expect("event")),
        RhiTradeMutationAdmissionErrorKind::TooManyExtraFields
    );

    let mut exact_bytes_value: Value = serde_json::from_slice(&valid_wire()).expect("event");
    exact_bytes_value
        .as_object_mut()
        .expect("object")
        .insert("extra".to_owned(), Value::String("x".repeat(65_526)));
    admit_rhi_trade_mutation_event(
        limits(&[]),
        &serde_json::to_vec(&exact_bytes_value).expect("event"),
        observed(1_784_347_200),
        policy(0),
    )
    .expect("exact extra byte budget");
    exact_bytes_value["extra"] = Value::String("x".repeat(65_527));
    assert_eq!(
        error(&serde_json::to_vec(&exact_bytes_value).expect("event")),
        RhiTradeMutationAdmissionErrorKind::ExtraFieldsTooLarge
    );
}

#[test]
fn event_id_signature_kind_author_content_and_tags_are_independent_checks() {
    let mut value: Value = serde_json::from_slice(&valid_wire()).expect("event");
    value["id"] = Value::String("0".repeat(64));
    assert_eq!(
        error(&serde_json::to_vec(&value).expect("event")),
        RhiTradeMutationAdmissionErrorKind::InvalidEventId
    );

    value = serde_json::from_slice(&valid_wire()).expect("event");
    value["sig"] = Value::String("0".repeat(128));
    assert_eq!(
        error(&serde_json::to_vec(&value).expect("event")),
        RhiTradeMutationAdmissionErrorKind::InvalidSignature
    );

    let (content, tags, created_at) = vector_parts();
    let unsupported = signed_variant(9_999, created_at, content.clone(), tags.clone(), &keys(9));
    assert_eq!(
        error(&unsupported),
        RhiTradeMutationAdmissionErrorKind::UnsupportedKind
    );
    let future_unsupported = signed_variant(
        9_999,
        created_at + 10,
        content.clone(),
        tags.clone(),
        &keys(9),
    );
    assert_eq!(
        error(&future_unsupported),
        RhiTradeMutationAdmissionErrorKind::UnsupportedKind
    );

    let wrong_author = signed_variant(3_470, created_at, content.clone(), tags.clone(), &keys(9));
    assert_eq!(
        error(&wrong_author),
        RhiTradeMutationAdmissionErrorKind::InvalidAuthor
    );

    assert_eq!(fixture_keys().public_key().to_hex(), vector()["pubkey"]);
    let mut noncanonical_content = content.clone();
    noncanonical_content.insert(1, ' ');
    let noncanonical = signed_variant(
        3_470,
        created_at,
        noncanonical_content.clone(),
        tags.clone(),
        &fixture_keys(),
    );
    assert_eq!(
        error(&noncanonical),
        RhiTradeMutationAdmissionErrorKind::InvalidMutation
    );
    let future_noncanonical = signed_variant(
        3_470,
        created_at + 10,
        noncanonical_content,
        tags.clone(),
        &fixture_keys(),
    );
    assert_eq!(
        error(&future_noncanonical),
        RhiTradeMutationAdmissionErrorKind::InvalidMutation
    );

    let mut duplicate_tags = tags;
    duplicate_tags.push(Tag::parse(["d", "99999999999999999999999999999999"]).expect("tag"));
    let duplicate = signed_variant(3_470, created_at, content, duplicate_tags, &fixture_keys());
    assert_eq!(
        error(&duplicate),
        RhiTradeMutationAdmissionErrorKind::InvalidMutation
    );
}

#[test]
fn authored_time_policy_is_explicit_inclusive_old_safe_and_overflow_bounded() {
    assert!(RhiTradeMutationObservedAtUnixSeconds::new(0).is_err());
    assert!(RhiTradeMutationObservedAtUnixSeconds::new(i64::MAX as u64).is_ok());
    assert!(RhiTradeMutationObservedAtUnixSeconds::new(i64::MAX as u64 + 1).is_err());
    assert!(RhiTradeMutationAuthoredTimePolicy::new(i64::MAX as u64).is_ok());
    assert!(RhiTradeMutationAuthoredTimePolicy::new(i64::MAX as u64 + 1).is_err());

    let bytes = valid_wire();
    admit_rhi_trade_mutation_event(limits(&[]), &bytes, observed(1_784_347_202), policy(0))
        .expect("old lineage event");
    admit_rhi_trade_mutation_event(limits(&[]), &bytes, observed(1_784_347_198), policy(2))
        .expect("inclusive future boundary");
    assert_eq!(
        admit_rhi_trade_mutation_event(limits(&[]), &bytes, observed(1_784_347_197), policy(2),)
            .expect_err("excessive future")
            .kind(),
        RhiTradeMutationAdmissionErrorKind::AuthoredTimeRejected
    );

    let (content, tags, _) = vector_parts();
    let unrepresentable =
        signed_variant(3_470, i64::MAX as u64 + 1, content, tags, &fixture_keys());
    assert_eq!(
        admit_rhi_trade_mutation_event(
            limits(&[]),
            &unrepresentable,
            observed(i64::MAX as u64),
            policy(0),
        )
        .expect_err("unrepresentable authored time")
        .kind(),
        RhiTradeMutationAdmissionErrorKind::InvalidAuthoredTime
    );
}

#[test]
fn errors_and_accepted_debug_are_source_free_and_redacted() {
    let secret = "trade-secret-evidence-marker";
    let malformed = format!("{{\"content\":\"{secret}\"}}");
    let failure =
        admit_rhi_trade_mutation_event(limits(&[]), malformed.as_bytes(), observed(1), policy(0))
            .expect_err("malformed event");
    assert!(failure.source().is_none());
    for rendered in [failure.to_string(), format!("{failure:?}")] {
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("content"));
        assert!(!rendered.contains("serde"));
    }
}

#[test]
fn extra_byte_measurement_matches_the_frozen_member_formula() {
    let mut object = Map::new();
    object.insert("extra".to_owned(), Value::String("x".repeat(65_526)));
    let encoded = serde_json::to_vec(&Value::Object(object)).expect("JSON");
    assert_eq!(encoded.len() - 2, RHI_TRADE_EVENT_EXTRA_JSON_MAX_BYTES);
}
