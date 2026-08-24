//! Immutable RHI schema and migration catalog identity.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    MigrationCatalog, MigrationChecksum, MigrationDescriptor, SchemaCatalog, SchemaDigest,
    SchemaObject, SchemaObjectKind, SchemaVersionCatalog,
};

/// The shared create-new baseline written before RHI migrations run.
pub const RHI_STATE_BASE_SCHEMA_VERSION: u32 = 1;

/// The newest governed RHI state schema understood by this binary.
pub const RHI_STATE_SCHEMA_VERSION: u32 = 11;

/// The shared metadata and migration-ledger objects present at schema v1.
pub const RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT: u32 = 6;

/// The shared objects plus the bounded append-only RHI configuration history.
pub const RHI_STATE_SCHEMA_VERSION_2_OBJECT_COUNT: u32 = 10;

/// The shared objects, configuration history, and immutable trade evidence.
pub const RHI_STATE_SCHEMA_VERSION_3_OBJECT_COUNT: u32 = 22;

/// The shared objects, immutable trade evidence, source cursors, and dirty generations.
pub const RHI_STATE_SCHEMA_VERSION_4_OBJECT_COUNT: u32 = 28;

/// The shared objects, canonical evidence, cursors, generations, and durable jobs.
pub const RHI_STATE_SCHEMA_VERSION_5_OBJECT_COUNT: u32 = 33;

/// The shared objects plus immutable reconciliation attempt/source results.
pub const RHI_STATE_SCHEMA_VERSION_6_OBJECT_COUNT: u32 = 39;

/// The shared objects plus immutable report and publication workflow state.
pub const RHI_STATE_SCHEMA_VERSION_7_OBJECT_COUNT: u32 = 63;

/// The shared objects plus fail-closed reconciliation-job shape guards.
pub const RHI_STATE_SCHEMA_VERSION_8_OBJECT_COUNT: u32 = 65;

/// The shared objects plus deterministic durable presence desired state.
pub const RHI_STATE_SCHEMA_VERSION_9_OBJECT_COUNT: u32 = 69;

/// The shared objects plus durable exact-byte presence delivery state.
pub const RHI_STATE_SCHEMA_VERSION_10_OBJECT_COUNT: u32 = 80;

/// The complete v10 state plus the bounded durable admin-operation journal.
pub const RHI_STATE_SCHEMA_VERSION_11_OBJECT_COUNT: u32 = 82;

/// SHA-256 identity of the ordered migration catalog rooted at schema v1.
pub const RHI_MIGRATION_CATALOG_SHA256: [u8; 32] = [
    0xe6, 0xcb, 0xac, 0xbd, 0x1e, 0xb6, 0x36, 0xc1, 0xa5, 0x60, 0xf8, 0x5e, 0xf8, 0xe5, 0x1e, 0x89,
    0xc9, 0xff, 0xe3, 0xb3, 0x42, 0xe6, 0x6b, 0xc5, 0xc0, 0xb4, 0x7a, 0xb3, 0x4e, 0x90, 0xc8, 0x18,
];

/// SHA-256 identity of the exact schema-v1 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_1_SHA256: [u8; 32] = [
    0x94, 0xdc, 0x66, 0xfb, 0xca, 0x60, 0x16, 0x79, 0x61, 0x5c, 0x05, 0x52, 0x29, 0xdc, 0x0d, 0xb6,
    0x11, 0x9f, 0x5b, 0xd9, 0x2b, 0x04, 0x39, 0x0c, 0x67, 0xf6, 0x98, 0xa0, 0x36, 0xfa, 0x78, 0xae,
];

/// SHA-256 identity of the schema-v2 configuration-binding migration.
pub const RHI_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256: [u8; 32] = [
    0xa2, 0xc1, 0xaa, 0x53, 0xf7, 0xfe, 0xee, 0x03, 0x85, 0xe7, 0x74, 0xde, 0x20, 0xe0, 0x72, 0x52,
    0x0f, 0x49, 0x26, 0xc5, 0x59, 0xc6, 0x42, 0x1a, 0xab, 0x59, 0x0e, 0x92, 0xba, 0x14, 0x4c, 0x55,
];

/// SHA-256 identity of the exact schema-v2 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_2_SHA256: [u8; 32] = [
    0xbc, 0xcb, 0xf1, 0xe6, 0x2f, 0xe7, 0x64, 0x4c, 0x9c, 0x37, 0x72, 0x05, 0xb2, 0x5a, 0x92, 0x29,
    0x8e, 0x08, 0x8b, 0x8c, 0x26, 0xd1, 0x5b, 0xa4, 0x51, 0x33, 0xca, 0x5e, 0x9b, 0x73, 0x15, 0xa9,
];

/// SHA-256 identity of the schema-v3 trade-evidence migration.
pub const RHI_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256: [u8; 32] = [
    0x07, 0xb0, 0x98, 0xc3, 0x93, 0x14, 0x0a, 0xfe, 0xc2, 0x22, 0xfc, 0xe7, 0x6e, 0xc6, 0x68, 0x69,
    0x8d, 0x50, 0xf1, 0xd2, 0x37, 0x85, 0x85, 0x68, 0x73, 0xe3, 0x04, 0x45, 0xaf, 0x1a, 0x01, 0x3f,
];

/// SHA-256 identity of the exact schema-v3 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_3_SHA256: [u8; 32] = [
    0xfd, 0x96, 0x22, 0x64, 0x05, 0xab, 0x68, 0x65, 0x5a, 0xee, 0x00, 0xf6, 0x83, 0xf6, 0x02, 0x3c,
    0x7a, 0xab, 0x2d, 0xbd, 0x23, 0xfe, 0xad, 0xac, 0x16, 0x53, 0x33, 0x49, 0x0d, 0x6f, 0x0a, 0xd5,
];

/// SHA-256 identity of the schema-v4 source-checkpoint migration.
pub const RHI_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256: [u8; 32] = [
    0x24, 0x41, 0xf7, 0xc4, 0xc1, 0x15, 0x94, 0xc6, 0xfd, 0xe7, 0x87, 0xdb, 0xb9, 0x4e, 0x44, 0xba,
    0x00, 0xb7, 0x2d, 0x2c, 0x97, 0x9b, 0x0e, 0x7f, 0xd3, 0xc7, 0x33, 0xea, 0xe9, 0x14, 0x4d, 0x78,
];

/// SHA-256 identity of the exact schema-v4 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_4_SHA256: [u8; 32] = [
    0x9c, 0xa7, 0x8a, 0x54, 0xb0, 0xea, 0x20, 0x13, 0xe7, 0xaa, 0x70, 0xd0, 0x9b, 0xea, 0xdc, 0xfb,
    0x6c, 0xdd, 0xe0, 0x7c, 0x40, 0x42, 0x9d, 0xff, 0xe9, 0x1c, 0xb8, 0x3c, 0x2a, 0x42, 0x5c, 0xea,
];

/// SHA-256 identity of the schema-v5 reconciliation-job migration.
pub const RHI_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256: [u8; 32] = [
    0x82, 0x75, 0xff, 0xb3, 0xd5, 0xc9, 0xfa, 0x0c, 0x76, 0x48, 0xf8, 0x9e, 0x8b, 0xfb, 0x92, 0x87,
    0x7b, 0x0d, 0xcd, 0x5e, 0xf3, 0xbf, 0x0b, 0x52, 0x54, 0xb7, 0xff, 0xd2, 0x58, 0x0b, 0xd4, 0x5d,
];

/// SHA-256 identity of the exact schema-v5 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_5_SHA256: [u8; 32] = [
    0xee, 0xf6, 0x7b, 0x48, 0x40, 0x0d, 0xee, 0x23, 0x4f, 0x6c, 0x36, 0xd4, 0x22, 0x55, 0x1c, 0x7e,
    0x99, 0x83, 0x15, 0x0b, 0x88, 0x7f, 0x26, 0x42, 0x50, 0xf9, 0xc8, 0x7a, 0x1a, 0x31, 0x3e, 0x60,
];

/// SHA-256 identity of the schema-v6 reconciliation-result migration.
pub const RHI_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256: [u8; 32] = [
    0x48, 0xa1, 0x4b, 0x27, 0x44, 0xc4, 0x11, 0x86, 0x49, 0x6d, 0x59, 0x7e, 0xc7, 0x80, 0xad, 0x99,
    0x8f, 0xa9, 0x30, 0x8a, 0x9c, 0x9d, 0x75, 0x40, 0xd4, 0x75, 0xdb, 0x3f, 0x4d, 0xcf, 0xc4, 0xbb,
];

/// SHA-256 identity of the exact schema-v6 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_6_SHA256: [u8; 32] = [
    0x5d, 0x1f, 0xa9, 0x50, 0x8b, 0x5b, 0x8a, 0x0c, 0x80, 0x65, 0xfd, 0x37, 0xf1, 0x1c, 0x68, 0x66,
    0xd5, 0x1f, 0x92, 0x94, 0xc7, 0x52, 0x72, 0x04, 0x1f, 0x34, 0x9e, 0x95, 0xce, 0xd5, 0x0f, 0xb4,
];

/// SHA-256 identity of the schema-v7 report/publication migration.
pub const RHI_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256: [u8; 32] = [
    0x9d, 0xeb, 0xf4, 0xf3, 0xca, 0xad, 0x4d, 0x01, 0x83, 0x11, 0xcb, 0x16, 0x9b, 0xf9, 0x28, 0x22,
    0x64, 0xd6, 0xab, 0xfc, 0x49, 0xe7, 0x18, 0x84, 0x0b, 0x9c, 0xbf, 0xad, 0x42, 0xed, 0x35, 0x7c,
];

/// SHA-256 identity of the exact schema-v7 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_7_SHA256: [u8; 32] = [
    0x84, 0x0a, 0xa8, 0x3c, 0x68, 0x9f, 0x9d, 0xf9, 0x9d, 0x26, 0xc5, 0xb4, 0xef, 0x11, 0x71, 0x31,
    0xc2, 0x70, 0xef, 0x75, 0x22, 0x67, 0x40, 0x37, 0xde, 0xf7, 0x96, 0x28, 0xa2, 0xb0, 0x39, 0x46,
];

/// SHA-256 identity of the schema-v8 reconciliation-job shape-guard migration.
pub const RHI_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256: [u8; 32] = [
    0x6d, 0x3a, 0xa0, 0x6e, 0x69, 0x08, 0xe4, 0x28, 0x1b, 0x50, 0x66, 0xed, 0x4a, 0x13, 0xe2, 0x28,
    0x7b, 0xda, 0xec, 0x05, 0xb0, 0xe5, 0x39, 0x21, 0x58, 0x91, 0x89, 0x2a, 0x5a, 0xfb, 0x58, 0x3b,
];

/// SHA-256 identity of the exact schema-v8 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_8_SHA256: [u8; 32] = [
    0x7c, 0xef, 0x55, 0x9a, 0xe1, 0xe6, 0xef, 0xe1, 0x58, 0xc5, 0xd1, 0xde, 0x50, 0x11, 0x4e, 0xba,
    0xcc, 0xac, 0x90, 0x53, 0x8e, 0x0c, 0xd4, 0x9a, 0x4e, 0xe2, 0x14, 0xcb, 0x0a, 0x39, 0xc6, 0x18,
];

/// SHA-256 identity of the schema-v9 presence desired-state migration.
pub const RHI_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256: [u8; 32] = [
    0x32, 0xda, 0xbe, 0x77, 0x72, 0x89, 0xe0, 0xfb, 0x6e, 0x64, 0xa4, 0xc1, 0xf8, 0x25, 0x78, 0x43,
    0xfc, 0x08, 0x01, 0x83, 0x21, 0xc3, 0xb7, 0xec, 0x5c, 0xa5, 0x84, 0xfa, 0x18, 0x62, 0xbd, 0xcc,
];

/// SHA-256 identity of the exact schema-v9 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_9_SHA256: [u8; 32] = [
    0x55, 0x51, 0xe8, 0x79, 0x05, 0x44, 0xa7, 0xc7, 0x8c, 0x83, 0x76, 0xc5, 0xcc, 0xf8, 0x3d, 0xd2,
    0xa8, 0x48, 0x6d, 0x2d, 0xc0, 0x8b, 0x6a, 0x78, 0x08, 0xbb, 0x20, 0x07, 0xc9, 0x43, 0x35, 0xec,
];

/// SHA-256 identity of the schema-v10 presence-publication migration.
pub const RHI_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256: [u8; 32] = [
    0x54, 0x1a, 0xd1, 0x3b, 0x2c, 0xb0, 0x8d, 0x59, 0x85, 0x72, 0x05, 0xe6, 0xff, 0xae, 0xc1, 0x9b,
    0x74, 0xde, 0x08, 0x53, 0x24, 0x0f, 0xdf, 0x11, 0xfa, 0x13, 0x40, 0xe4, 0x06, 0xc7, 0x11, 0x4e,
];

/// SHA-256 identity of the exact schema-v10 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_10_SHA256: [u8; 32] = [
    0xd2, 0xae, 0xd5, 0x1d, 0x0a, 0x6a, 0x2c, 0x01, 0xed, 0xa1, 0x84, 0x46, 0x08, 0x47, 0x2b, 0x2d,
    0xcd, 0x50, 0x2a, 0xba, 0xa8, 0xa4, 0xca, 0x30, 0xa4, 0x82, 0x35, 0x35, 0xb8, 0xbd, 0x0e, 0x45,
];

/// SHA-256 identity of the schema-v11 admin-operation-journal migration.
pub const RHI_STATE_SCHEMA_VERSION_11_MIGRATION_SHA256: [u8; 32] = [
    0xe3, 0xfb, 0xde, 0x51, 0x1e, 0x84, 0x24, 0xc9, 0x70, 0x80, 0xbe, 0x2c, 0x09, 0xed, 0x81, 0x0a,
    0xe2, 0x84, 0x63, 0x1d, 0x75, 0xeb, 0x25, 0xc2, 0xe8, 0x8a, 0x60, 0x76, 0xb7, 0x00, 0xaa, 0xef,
];

/// SHA-256 identity of the exact schema-v11 object snapshot.
pub const RHI_STATE_SCHEMA_VERSION_11_SHA256: [u8; 32] = [
    0xc2, 0x5e, 0xc6, 0x3b, 0x33, 0xb4, 0x11, 0x61, 0x80, 0x68, 0xee, 0x06, 0xa0, 0x4c, 0x99, 0xee,
    0x71, 0x66, 0xe0, 0x01, 0x4d, 0x97, 0x90, 0x39, 0xfa, 0xea, 0xea, 0x4d, 0xc1, 0xac, 0x7e, 0x62,
];

/// SHA-256 identity of the schema catalog bound to the migration catalog.
pub const RHI_STATE_SCHEMA_CATALOG_SHA256: [u8; 32] = [
    0xae, 0xc4, 0x82, 0x81, 0x8b, 0xd9, 0xa6, 0xf3, 0x3f, 0xd9, 0x2b, 0x55, 0xd1, 0x42, 0xc6, 0xb8,
    0x5a, 0xa6, 0xf0, 0x86, 0x85, 0x57, 0x01, 0xdf, 0xc4, 0xb7, 0x8f, 0x2a, 0x7e, 0xf5, 0xcf, 0x6d,
];

macro_rules! rhi_config_bindings_table_sql {
    () => {
        r#"CREATE TABLE rhi_config_bindings (
    generation INTEGER NOT NULL PRIMARY KEY CHECK (generation BETWEEN 1 AND 1024),
    normalized_config_sha256 BLOB NOT NULL CHECK (length(normalized_config_sha256) = 32),
    evidence_policy_sha256 BLOB NOT NULL CHECK (length(evidence_policy_sha256) = 32),
    service_public_key TEXT NOT NULL
        CHECK (length(CAST(service_public_key AS BLOB)) = 64)
        CHECK (service_public_key NOT GLOB '*[^0-9a-f]*'),
    config_contract_version INTEGER NOT NULL
        CHECK (config_contract_version BETWEEN 1 AND 4294967295),
    state_contract_version INTEGER NOT NULL
        CHECK (state_contract_version BETWEEN 1 AND 4294967295),
    admin_contract_version INTEGER NOT NULL
        CHECK (admin_contract_version BETWEEN 1 AND 4294967295),
    status_contract_version INTEGER NOT NULL
        CHECK (status_contract_version BETWEEN 1 AND 4294967295),
    provider_contract_version INTEGER NOT NULL
        CHECK (provider_contract_version BETWEEN 1 AND 4294967295),
    applied_at_unix_s INTEGER NOT NULL
        CHECK (applied_at_unix_s BETWEEN 0 AND 9223372036854775807),
    service_version TEXT NOT NULL
        CHECK (length(CAST(service_version AS BLOB)) BETWEEN 1 AND 128),
    service_commit TEXT NOT NULL
        CHECK (length(CAST(service_commit AS BLOB)) = 40),
    lib_revision TEXT NOT NULL
        CHECK (length(CAST(lib_revision AS BLOB)) = 40),
    rust_version TEXT NOT NULL
        CHECK (length(CAST(rust_version AS BLOB)) BETWEEN 1 AND 128),
    target TEXT NOT NULL CHECK (length(CAST(target AS BLOB)) BETWEEN 1 AND 128),
    feature_profile TEXT NOT NULL
        CHECK (length(CAST(feature_profile AS BLOB)) BETWEEN 1 AND 128)
) STRICT"#
    };
}

macro_rules! rhi_config_bindings_guard_insert_sql {
    () => {
        r#"CREATE TRIGGER rhi_config_bindings_guard_insert
BEFORE INSERT ON rhi_config_bindings
WHEN NEW.generation != COALESCE(
        (SELECT MAX(generation) + 1 FROM rhi_config_bindings), 1
    )
    OR (SELECT COUNT(*) FROM rhi_config_bindings) >= 1024
    OR NEW.applied_at_unix_s < COALESCE(
        (SELECT MAX(applied_at_unix_s) FROM rhi_config_bindings), 0
    )
BEGIN
    SELECT RAISE(ABORT, 'configuration binding sequence is invalid');
END"#
    };
}

macro_rules! rhi_config_bindings_no_update_sql {
    () => {
        r#"CREATE TRIGGER rhi_config_bindings_no_update
BEFORE UPDATE ON rhi_config_bindings
BEGIN
    SELECT RAISE(ABORT, 'configuration binding history is immutable');
END"#
    };
}

macro_rules! rhi_config_bindings_no_delete_sql {
    () => {
        r#"CREATE TRIGGER rhi_config_bindings_no_delete
BEFORE DELETE ON rhi_config_bindings
BEGIN
    SELECT RAISE(ABORT, 'configuration binding history is retained');
END"#
    };
}

pub(crate) const CREATE_RHI_CONFIG_BINDINGS_TABLE_SQL: &str = rhi_config_bindings_table_sql!();
const CREATE_RHI_CONFIG_BINDINGS_GUARD_INSERT_SQL: &str = rhi_config_bindings_guard_insert_sql!();
const CREATE_RHI_CONFIG_BINDINGS_NO_UPDATE_SQL: &str = rhi_config_bindings_no_update_sql!();
const CREATE_RHI_CONFIG_BINDINGS_NO_DELETE_SQL: &str = rhi_config_bindings_no_delete_sql!();
const CREATE_RHI_CONFIG_BINDINGS_MIGRATION_SQL: &str = concat!(
    rhi_config_bindings_table_sql!(),
    ";\n",
    rhi_config_bindings_guard_insert_sql!(),
    ";\n",
    rhi_config_bindings_no_update_sql!(),
    ";\n",
    rhi_config_bindings_no_delete_sql!(),
    ";",
);

macro_rules! trade_mutations_table_sql {
    () => {
        r#"CREATE TABLE trade_mutations (
    mutation_id BLOB NOT NULL PRIMARY KEY CHECK (length(mutation_id) = 32),
    trade_id BLOB NOT NULL CHECK (length(trade_id) = 16),
    contract_id TEXT NOT NULL CHECK (contract_id IN (
        'radroots.trade.proposal.v1',
        'radroots.trade.decision.v1',
        'radroots.trade.revision_proposal.v1',
        'radroots.trade.revision_decision.v1',
        'radroots.trade.cancellation.v1'
    )),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    event_kind INTEGER NOT NULL CHECK (event_kind IN (3470, 3471, 3472, 3473, 3474)),
    author_pubkey BLOB NOT NULL CHECK (length(author_pubkey) = 32),
    canonical_content BLOB NOT NULL
        CHECK (length(canonical_content) BETWEEN 1 AND 131072)
) STRICT"#
    };
}

macro_rules! trade_mutations_by_trade_sql {
    () => {
        r#"CREATE INDEX trade_mutations_by_trade
ON trade_mutations (trade_id, mutation_id)"#
    };
}

macro_rules! nostr_events_table_sql {
    () => {
        r#"CREATE TABLE nostr_events (
    event_id BLOB NOT NULL CHECK (length(event_id) = 32),
    event_signature BLOB NOT NULL CHECK (length(event_signature) = 64),
    mutation_id BLOB NOT NULL CHECK (length(mutation_id) = 32)
        REFERENCES trade_mutations (mutation_id),
    author_pubkey BLOB NOT NULL CHECK (length(author_pubkey) = 32),
    event_kind INTEGER NOT NULL CHECK (event_kind IN (3470, 3471, 3472, 3473, 3474)),
    authored_at_unix_s INTEGER NOT NULL
        CHECK (authored_at_unix_s BETWEEN 0 AND 9223372036854775807),
    canonical_event_json BLOB NOT NULL
        CHECK (length(canonical_event_json) BETWEEN 1 AND 524288),
    PRIMARY KEY (event_id, event_signature)
) STRICT"#
    };
}

macro_rules! nostr_events_by_mutation_sql {
    () => {
        r#"CREATE INDEX nostr_events_by_mutation
ON nostr_events (mutation_id, authored_at_unix_s, event_id)"#
    };
}

macro_rules! relay_observations_table_sql {
    () => {
        r#"CREATE TABLE relay_observations (
    source_id TEXT NOT NULL
        CHECK (length(CAST(source_id AS BLOB)) BETWEEN 1 AND 64)
        CHECK (source_id NOT GLOB '*[^a-z0-9_-]*')
        CHECK (substr(source_id, 1, 1) GLOB '[a-z]'),
    selector_id TEXT NOT NULL CHECK (selector_id = 'trade_mutation_lineage_v1'),
    evidence_policy_sha256 BLOB NOT NULL CHECK (length(evidence_policy_sha256) = 32),
    event_id BLOB NOT NULL CHECK (length(event_id) = 32),
    event_signature BLOB NOT NULL CHECK (length(event_signature) = 64),
    observed_at_unix_s INTEGER NOT NULL
        CHECK (observed_at_unix_s BETWEEN 1 AND 9223372036854775807),
    FOREIGN KEY (event_id, event_signature)
        REFERENCES nostr_events (event_id, event_signature),
    PRIMARY KEY (
        source_id, selector_id, evidence_policy_sha256, event_id, event_signature,
        observed_at_unix_s
    )
) STRICT"#
    };
}

macro_rules! relay_observations_by_event_sql {
    () => {
        r#"CREATE INDEX relay_observations_by_event
ON relay_observations (event_id, event_signature, observed_at_unix_s, source_id)"#
    };
}

macro_rules! immutable_no_update_sql {
    ($trigger:literal, $table:literal, $message:literal) => {
        concat!(
            "CREATE TRIGGER ",
            $trigger,
            "\nBEFORE UPDATE ON ",
            $table,
            "\nBEGIN\n    SELECT RAISE(ABORT, '",
            $message,
            "');\nEND"
        )
    };
}

macro_rules! immutable_no_delete_sql {
    ($trigger:literal, $table:literal, $message:literal) => {
        concat!(
            "CREATE TRIGGER ",
            $trigger,
            "\nBEFORE DELETE ON ",
            $table,
            "\nBEGIN\n    SELECT RAISE(ABORT, '",
            $message,
            "');\nEND"
        )
    };
}

pub(crate) const CREATE_TRADE_MUTATIONS_TABLE_SQL: &str = trade_mutations_table_sql!();
const CREATE_TRADE_MUTATIONS_BY_TRADE_SQL: &str = trade_mutations_by_trade_sql!();
pub(crate) const CREATE_NOSTR_EVENTS_TABLE_SQL: &str = nostr_events_table_sql!();
const CREATE_NOSTR_EVENTS_BY_MUTATION_SQL: &str = nostr_events_by_mutation_sql!();
pub(crate) const CREATE_RELAY_OBSERVATIONS_TABLE_SQL: &str = relay_observations_table_sql!();
const CREATE_RELAY_OBSERVATIONS_BY_EVENT_SQL: &str = relay_observations_by_event_sql!();
const CREATE_TRADE_MUTATIONS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "trade_mutations_no_update",
    "trade_mutations",
    "trade mutation evidence is immutable"
);
const CREATE_TRADE_MUTATIONS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "trade_mutations_no_delete",
    "trade_mutations",
    "trade mutation evidence is retained"
);
const CREATE_NOSTR_EVENTS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "nostr_events_no_update",
    "nostr_events",
    "signed event evidence is immutable"
);
const CREATE_NOSTR_EVENTS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "nostr_events_no_delete",
    "nostr_events",
    "signed event evidence is retained"
);
const CREATE_RELAY_OBSERVATIONS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "relay_observations_no_update",
    "relay_observations",
    "source observation evidence is immutable"
);
const CREATE_RELAY_OBSERVATIONS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "relay_observations_no_delete",
    "relay_observations",
    "source observation evidence is retained"
);
const CREATE_TRADE_EVIDENCE_MIGRATION_SQL: &str = concat!(
    trade_mutations_table_sql!(),
    ";\n",
    trade_mutations_by_trade_sql!(),
    ";\n",
    nostr_events_table_sql!(),
    ";\n",
    nostr_events_by_mutation_sql!(),
    ";\n",
    relay_observations_table_sql!(),
    ";\n",
    relay_observations_by_event_sql!(),
    ";\n",
    immutable_no_update_sql!(
        "trade_mutations_no_update",
        "trade_mutations",
        "trade mutation evidence is immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "trade_mutations_no_delete",
        "trade_mutations",
        "trade mutation evidence is retained"
    ),
    ";\n",
    immutable_no_update_sql!(
        "nostr_events_no_update",
        "nostr_events",
        "signed event evidence is immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "nostr_events_no_delete",
        "nostr_events",
        "signed event evidence is retained"
    ),
    ";\n",
    immutable_no_update_sql!(
        "relay_observations_no_update",
        "relay_observations",
        "source observation evidence is immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "relay_observations_no_delete",
        "relay_observations",
        "source observation evidence is retained"
    ),
    ";",
);

macro_rules! relay_checkpoints_table_sql {
    () => {
        r#"CREATE TABLE relay_checkpoints (
    source_id TEXT NOT NULL
        CHECK (length(CAST(source_id AS BLOB)) BETWEEN 1 AND 64)
        CHECK (source_id NOT GLOB '*[^a-z0-9_-]*')
        CHECK (substr(source_id, 1, 1) GLOB '[a-z]'),
    selector_id TEXT NOT NULL CHECK (selector_id = 'trade_mutation_lineage_v1'),
    evidence_policy_sha256 BLOB NOT NULL CHECK (length(evidence_policy_sha256) = 32),
    trade_id BLOB NOT NULL CHECK (length(trade_id) = 16),
    cursor_created_at_unix_s INTEGER NOT NULL
        CHECK (cursor_created_at_unix_s BETWEEN 0 AND 9223372036854775807),
    cursor_event_id BLOB NOT NULL CHECK (length(cursor_event_id) = 32),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9223372036854775807),
    completed_at_unix_s INTEGER NOT NULL
        CHECK (completed_at_unix_s BETWEEN 1 AND 9223372036854775807),
    PRIMARY KEY (source_id, selector_id, evidence_policy_sha256, trade_id)
) STRICT"#
    };
}

macro_rules! relay_checkpoints_guard_update_sql {
    () => {
        r#"CREATE TRIGGER relay_checkpoints_guard_update
BEFORE UPDATE ON relay_checkpoints
WHEN NEW.source_id != OLD.source_id
    OR NEW.selector_id != OLD.selector_id
    OR NEW.evidence_policy_sha256 != OLD.evidence_policy_sha256
    OR NEW.trade_id != OLD.trade_id
    OR NEW.revision != OLD.revision + 1
    OR NEW.completed_at_unix_s < OLD.completed_at_unix_s
    OR NEW.cursor_created_at_unix_s < OLD.cursor_created_at_unix_s
    OR (
        NEW.cursor_created_at_unix_s = OLD.cursor_created_at_unix_s
        AND NEW.cursor_event_id <= OLD.cursor_event_id
    )
BEGIN
    SELECT RAISE(ABORT, 'relay checkpoint transition is invalid');
END"#
    };
}

macro_rules! trade_dirty_generations_table_sql {
    () => {
        r#"CREATE TABLE trade_dirty_generations (
    trade_id BLOB NOT NULL PRIMARY KEY CHECK (length(trade_id) = 16),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 1 AND 9223372036854775807),
    evidence_policy_sha256 BLOB NOT NULL CHECK (length(evidence_policy_sha256) = 32),
    updated_at_unix_s INTEGER NOT NULL
        CHECK (updated_at_unix_s BETWEEN 0 AND 9223372036854775807)
) STRICT"#
    };
}

macro_rules! trade_dirty_generations_guard_update_sql {
    () => {
        r#"CREATE TRIGGER trade_dirty_generations_guard_update
BEFORE UPDATE ON trade_dirty_generations
WHEN NEW.trade_id != OLD.trade_id
    OR NEW.generation != OLD.generation + 1
    OR NEW.updated_at_unix_s < OLD.updated_at_unix_s
BEGIN
    SELECT RAISE(ABORT, 'trade dirty generation transition is invalid');
END"#
    };
}

pub(crate) const CREATE_RELAY_CHECKPOINTS_TABLE_SQL: &str = relay_checkpoints_table_sql!();
const CREATE_RELAY_CHECKPOINTS_GUARD_UPDATE_SQL: &str = relay_checkpoints_guard_update_sql!();
const CREATE_RELAY_CHECKPOINTS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "relay_checkpoints_no_delete",
    "relay_checkpoints",
    "relay checkpoints are retained"
);
pub(crate) const CREATE_TRADE_DIRTY_GENERATIONS_TABLE_SQL: &str =
    trade_dirty_generations_table_sql!();
const CREATE_TRADE_DIRTY_GENERATIONS_GUARD_UPDATE_SQL: &str =
    trade_dirty_generations_guard_update_sql!();
const CREATE_TRADE_DIRTY_GENERATIONS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "trade_dirty_generations_no_delete",
    "trade_dirty_generations",
    "trade dirty generations are retained"
);
const CREATE_SOURCE_CHECKPOINT_MIGRATION_SQL: &str = concat!(
    relay_checkpoints_table_sql!(),
    ";\n",
    relay_checkpoints_guard_update_sql!(),
    ";\n",
    immutable_no_delete_sql!(
        "relay_checkpoints_no_delete",
        "relay_checkpoints",
        "relay checkpoints are retained"
    ),
    ";\n",
    trade_dirty_generations_table_sql!(),
    ";\n",
    trade_dirty_generations_guard_update_sql!(),
    ";\n",
    immutable_no_delete_sql!(
        "trade_dirty_generations_no_delete",
        "trade_dirty_generations",
        "trade dirty generations are retained"
    ),
    ";",
);

macro_rules! reconciliation_jobs_table_sql {
    () => {
        r#"CREATE TABLE reconciliation_jobs (
    job_id BLOB NOT NULL PRIMARY KEY CHECK (length(job_id) = 32),
    trade_id BLOB NOT NULL CHECK (length(trade_id) = 16),
    input_generation INTEGER NOT NULL
        CHECK (input_generation BETWEEN 1 AND 9223372036854775807),
    evidence_policy_sha256 BLOB NOT NULL CHECK (length(evidence_policy_sha256) = 32),
    state TEXT NOT NULL
        CHECK (state IN ('ready', 'leased', 'exhausted', 'superseded', 'completed')),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9223372036854775807),
    attempt_count INTEGER NOT NULL CHECK (attempt_count BETWEEN 0 AND 100),
    failure_count INTEGER NOT NULL CHECK (failure_count BETWEEN 0 AND attempt_count),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    lease_duration_ms INTEGER NOT NULL CHECK (lease_duration_ms BETWEEN 1000 AND 300000),
    lease_renewal_ms INTEGER NOT NULL CHECK (lease_renewal_ms BETWEEN 100 AND 150000),
    initial_backoff_ms INTEGER NOT NULL CHECK (initial_backoff_ms BETWEEN 1 AND 60000),
    maximum_backoff_ms INTEGER NOT NULL CHECK (maximum_backoff_ms BETWEEN 1 AND 3600000),
    next_attempt_unix_ms INTEGER,
    lease_owner BLOB,
    lease_expires_unix_ms INTEGER,
    created_at_unix_ms INTEGER NOT NULL
        CHECK (created_at_unix_ms BETWEEN 0 AND 9223372036854775807),
    updated_at_unix_ms INTEGER NOT NULL
        CHECK (updated_at_unix_ms BETWEEN created_at_unix_ms AND 9223372036854775807),
    FOREIGN KEY (trade_id) REFERENCES trade_dirty_generations (trade_id),
    CHECK (lease_renewal_ms < lease_duration_ms),
    CHECK (initial_backoff_ms <= maximum_backoff_ms),
    CHECK (
        (state = 'ready'
            AND attempt_count < max_attempts
            AND next_attempt_unix_ms BETWEEN 0 AND 9223372036854775807
            AND lease_owner IS NULL
            AND lease_expires_unix_ms IS NULL)
        OR (state = 'leased'
            AND attempt_count BETWEEN 1 AND max_attempts
            AND next_attempt_unix_ms IS NULL
            AND length(lease_owner) = 16
            AND lease_expires_unix_ms BETWEEN 1 AND 9223372036854775807)
        OR (state IN ('exhausted', 'superseded', 'completed')
            AND next_attempt_unix_ms IS NULL
            AND lease_owner IS NULL
            AND lease_expires_unix_ms IS NULL)
    )
) STRICT"#
    };
}

macro_rules! reconciliation_jobs_one_active_sql {
    () => {
        r#"CREATE UNIQUE INDEX reconciliation_jobs_one_active_per_trade
ON reconciliation_jobs (trade_id)
WHERE state IN ('ready', 'leased')"#
    };
}

macro_rules! reconciliation_jobs_schedule_sql {
    () => {
        r#"CREATE INDEX reconciliation_jobs_by_schedule
ON reconciliation_jobs (
    state, next_attempt_unix_ms, lease_expires_unix_ms,
    created_at_unix_ms, job_id
)"#
    };
}

macro_rules! reconciliation_jobs_guard_update_sql {
    () => {
        r#"CREATE TRIGGER reconciliation_jobs_guard_update
BEFORE UPDATE ON reconciliation_jobs
WHEN NEW.job_id != OLD.job_id
    OR NEW.trade_id != OLD.trade_id
    OR NEW.input_generation != OLD.input_generation
    OR NEW.evidence_policy_sha256 != OLD.evidence_policy_sha256
    OR NEW.max_attempts != OLD.max_attempts
    OR NEW.lease_duration_ms != OLD.lease_duration_ms
    OR NEW.lease_renewal_ms != OLD.lease_renewal_ms
    OR NEW.initial_backoff_ms != OLD.initial_backoff_ms
    OR NEW.maximum_backoff_ms != OLD.maximum_backoff_ms
    OR NEW.created_at_unix_ms != OLD.created_at_unix_ms
    OR NEW.revision != OLD.revision + 1
    OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
    OR NOT (
        (OLD.state = 'ready' AND NEW.state IN ('leased', 'superseded'))
        OR (OLD.state = 'leased'
            AND NEW.state IN ('leased', 'ready', 'exhausted', 'superseded', 'completed'))
        OR (OLD.state = 'exhausted' AND NEW.state = 'superseded')
    )
BEGIN
    SELECT RAISE(ABORT, 'reconciliation job transition is invalid');
END"#
    };
}

pub(crate) const CREATE_RECONCILIATION_JOBS_TABLE_SQL: &str = reconciliation_jobs_table_sql!();
const CREATE_RECONCILIATION_JOBS_ONE_ACTIVE_SQL: &str = reconciliation_jobs_one_active_sql!();
const CREATE_RECONCILIATION_JOBS_SCHEDULE_SQL: &str = reconciliation_jobs_schedule_sql!();
const CREATE_RECONCILIATION_JOBS_GUARD_UPDATE_SQL: &str = reconciliation_jobs_guard_update_sql!();
const CREATE_RECONCILIATION_JOBS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "reconciliation_jobs_no_delete",
    "reconciliation_jobs",
    "reconciliation jobs are retained"
);
const CREATE_RECONCILIATION_JOBS_MIGRATION_SQL: &str = concat!(
    reconciliation_jobs_table_sql!(),
    ";\n",
    reconciliation_jobs_one_active_sql!(),
    ";\n",
    reconciliation_jobs_schedule_sql!(),
    ";\n",
    reconciliation_jobs_guard_update_sql!(),
    ";\n",
    immutable_no_delete_sql!(
        "reconciliation_jobs_no_delete",
        "reconciliation_jobs",
        "reconciliation jobs are retained"
    ),
    ";",
);

macro_rules! reconciliation_jobs_shape_guard_insert_sql {
    () => {
        r#"CREATE TRIGGER reconciliation_jobs_shape_guard_insert
BEFORE INSERT ON reconciliation_jobs
WHEN (NEW.state = 'ready' AND (
        NEW.attempt_count >= NEW.max_attempts
        OR typeof(NEW.next_attempt_unix_ms) != 'integer'
        OR NEW.next_attempt_unix_ms NOT BETWEEN 0 AND 9223372036854775807
        OR NEW.lease_owner IS NOT NULL
        OR NEW.lease_expires_unix_ms IS NOT NULL
    ))
    OR (NEW.state = 'leased' AND (
        NEW.attempt_count NOT BETWEEN 1 AND NEW.max_attempts
        OR NEW.next_attempt_unix_ms IS NOT NULL
        OR typeof(NEW.lease_owner) != 'blob'
        OR length(NEW.lease_owner) != 16
        OR typeof(NEW.lease_expires_unix_ms) != 'integer'
        OR NEW.lease_expires_unix_ms NOT BETWEEN 1 AND 9223372036854775807
    ))
    OR (NEW.state IN ('exhausted', 'superseded', 'completed') AND (
        NEW.next_attempt_unix_ms IS NOT NULL
        OR NEW.lease_owner IS NOT NULL
        OR NEW.lease_expires_unix_ms IS NOT NULL
    ))
BEGIN
    SELECT RAISE(ABORT, 'reconciliation job state shape is invalid');
END"#
    };
}

macro_rules! reconciliation_jobs_shape_guard_update_sql {
    () => {
        r#"CREATE TRIGGER reconciliation_jobs_shape_guard_update
BEFORE UPDATE ON reconciliation_jobs
WHEN (NEW.state = 'ready' AND (
        NEW.attempt_count >= NEW.max_attempts
        OR typeof(NEW.next_attempt_unix_ms) != 'integer'
        OR NEW.next_attempt_unix_ms NOT BETWEEN 0 AND 9223372036854775807
        OR NEW.lease_owner IS NOT NULL
        OR NEW.lease_expires_unix_ms IS NOT NULL
    ))
    OR (NEW.state = 'leased' AND (
        NEW.attempt_count NOT BETWEEN 1 AND NEW.max_attempts
        OR NEW.next_attempt_unix_ms IS NOT NULL
        OR typeof(NEW.lease_owner) != 'blob'
        OR length(NEW.lease_owner) != 16
        OR typeof(NEW.lease_expires_unix_ms) != 'integer'
        OR NEW.lease_expires_unix_ms NOT BETWEEN 1 AND 9223372036854775807
    ))
    OR (NEW.state IN ('exhausted', 'superseded', 'completed') AND (
        NEW.next_attempt_unix_ms IS NOT NULL
        OR NEW.lease_owner IS NOT NULL
        OR NEW.lease_expires_unix_ms IS NOT NULL
    ))
BEGIN
    SELECT RAISE(ABORT, 'reconciliation job state shape is invalid');
END"#
    };
}

const CREATE_RECONCILIATION_JOBS_SHAPE_GUARD_INSERT_SQL: &str =
    reconciliation_jobs_shape_guard_insert_sql!();
const CREATE_RECONCILIATION_JOBS_SHAPE_GUARD_UPDATE_SQL: &str =
    reconciliation_jobs_shape_guard_update_sql!();
const CREATE_RECONCILIATION_JOB_SHAPE_GUARDS_MIGRATION_SQL: &str = concat!(
    "CREATE TABLE reconciliation_jobs_shape_scan_v1 (\n",
    "    invalid INTEGER NOT NULL CHECK (invalid = 0)\n",
    ") STRICT;\n",
    "INSERT INTO reconciliation_jobs_shape_scan_v1 (invalid)\n",
    "SELECT 1 FROM reconciliation_jobs\n",
    "WHERE (state = 'ready' AND (\n",
    "        attempt_count >= max_attempts\n",
    "        OR typeof(next_attempt_unix_ms) != 'integer'\n",
    "        OR next_attempt_unix_ms NOT BETWEEN 0 AND 9223372036854775807\n",
    "        OR lease_owner IS NOT NULL\n",
    "        OR lease_expires_unix_ms IS NOT NULL\n",
    "    ))\n",
    "    OR (state = 'leased' AND (\n",
    "        attempt_count NOT BETWEEN 1 AND max_attempts\n",
    "        OR next_attempt_unix_ms IS NOT NULL\n",
    "        OR typeof(lease_owner) != 'blob'\n",
    "        OR length(lease_owner) != 16\n",
    "        OR typeof(lease_expires_unix_ms) != 'integer'\n",
    "        OR lease_expires_unix_ms NOT BETWEEN 1 AND 9223372036854775807\n",
    "    ))\n",
    "    OR (state IN ('exhausted', 'superseded', 'completed') AND (\n",
    "        next_attempt_unix_ms IS NOT NULL\n",
    "        OR lease_owner IS NOT NULL\n",
    "        OR lease_expires_unix_ms IS NOT NULL\n",
    "    ))\n",
    "LIMIT 1;\n",
    "DROP TABLE reconciliation_jobs_shape_scan_v1;\n",
    reconciliation_jobs_shape_guard_insert_sql!(),
    ";\n",
    reconciliation_jobs_shape_guard_update_sql!(),
    ";",
);

macro_rules! presence_desired_state_table_sql {
    () => {
        r#"CREATE TABLE presence_desired_state (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL
        CHECK (generation BETWEEN 1 AND 9223372036854775807),
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    profile INTEGER NOT NULL CHECK (profile IN (0, 1)),
    application_handler INTEGER NOT NULL CHECK (application_handler IN (0, 1)),
    target_set_sha256 BLOB NOT NULL CHECK (length(target_set_sha256) = 32),
    target_count INTEGER NOT NULL CHECK (target_count BETWEEN 0 AND 32),
    required_target_count INTEGER NOT NULL
        CHECK (required_target_count BETWEEN 0 AND target_count),
    queue_capacity INTEGER NOT NULL CHECK (queue_capacity BETWEEN 0 AND 4096),
    desired_sha256 BLOB NOT NULL UNIQUE CHECK (length(desired_sha256) = 32),
    CHECK (
        (enabled = 0 AND profile = 0 AND application_handler = 0
            AND target_count = 0 AND required_target_count = 0
            AND queue_capacity = 0)
        OR
        (enabled = 1 AND (profile = 1 OR application_handler = 1)
            AND target_count BETWEEN 1 AND 32
            AND queue_capacity BETWEEN 1 AND 4096)
    )
) STRICT"#
    };
}

macro_rules! presence_desired_state_guard_insert_sql {
    () => {
        r#"CREATE TRIGGER presence_desired_state_guard_insert
BEFORE INSERT ON presence_desired_state
WHEN NEW.generation != 1
    OR EXISTS (SELECT 1 FROM presence_desired_state)
BEGIN
    SELECT RAISE(ABORT, 'presence desired-state insertion is invalid');
END"#
    };
}

macro_rules! presence_desired_state_guard_update_sql {
    () => {
        r#"CREATE TRIGGER presence_desired_state_guard_update
BEFORE UPDATE ON presence_desired_state
WHEN NEW.singleton != OLD.singleton
    OR OLD.generation >= 9223372036854775807
    OR NEW.generation != OLD.generation + 1
    OR NEW.desired_sha256 = OLD.desired_sha256
BEGIN
    SELECT RAISE(ABORT, 'presence desired-state transition is invalid');
END"#
    };
}

macro_rules! presence_desired_state_no_delete_sql {
    () => {
        r#"CREATE TRIGGER presence_desired_state_no_delete
BEFORE DELETE ON presence_desired_state
BEGIN
    SELECT RAISE(ABORT, 'presence desired state is retained');
END"#
    };
}

const CREATE_PRESENCE_DESIRED_STATE_TABLE_SQL: &str = presence_desired_state_table_sql!();
const CREATE_PRESENCE_DESIRED_STATE_GUARD_INSERT_SQL: &str =
    presence_desired_state_guard_insert_sql!();
const CREATE_PRESENCE_DESIRED_STATE_GUARD_UPDATE_SQL: &str =
    presence_desired_state_guard_update_sql!();
const CREATE_PRESENCE_DESIRED_STATE_NO_DELETE_SQL: &str = presence_desired_state_no_delete_sql!();
const CREATE_PRESENCE_DESIRED_STATE_MIGRATION_SQL: &str = concat!(
    presence_desired_state_table_sql!(),
    ";\n",
    presence_desired_state_guard_insert_sql!(),
    ";\n",
    presence_desired_state_guard_update_sql!(),
    ";\n",
    presence_desired_state_no_delete_sql!(),
    ";",
);

macro_rules! presence_outbox_table_sql {
    () => {
        r#"CREATE TABLE presence_outbox (
    outbox_id BLOB NOT NULL PRIMARY KEY CHECK (length(outbox_id) = 32),
    desired_generation INTEGER NOT NULL
        CHECK (desired_generation BETWEEN 1 AND 9223372036854775807),
    document_kind TEXT NOT NULL
        CHECK (document_kind IN ('service_profile', 'application_handler')),
    desired_sha256 BLOB NOT NULL CHECK (length(desired_sha256) = 32),
    target_set_sha256 BLOB NOT NULL CHECK (length(target_set_sha256) = 32),
    event_id BLOB NOT NULL CHECK (length(event_id) = 32),
    event_sha256 BLOB NOT NULL CHECK (length(event_sha256) = 32),
    exact_signed_event_bytes BLOB NOT NULL
        CHECK (length(exact_signed_event_bytes) BETWEEN 1 AND 32768),
    authored_at_unix_s INTEGER NOT NULL
        CHECK (authored_at_unix_s BETWEEN 0 AND 9223372036854775807),
    service_public_key TEXT NOT NULL
        CHECK (length(CAST(service_public_key AS BLOB)) = 64)
        CHECK (service_public_key NOT GLOB '*[^0-9a-f]*'),
    target_count INTEGER NOT NULL CHECK (target_count BETWEEN 1 AND 32),
    required_target_count INTEGER NOT NULL
        CHECK (required_target_count BETWEEN 0 AND target_count),
    max_attempts INTEGER NOT NULL CHECK (max_attempts = 100),
    initial_backoff_ms INTEGER NOT NULL CHECK (initial_backoff_ms = 250),
    maximum_backoff_ms INTEGER NOT NULL CHECK (maximum_backoff_ms = 30000),
    attempt_deadline_ms INTEGER NOT NULL CHECK (attempt_deadline_ms = 15000),
    state TEXT NOT NULL
        CHECK (state IN ('pending', 'leased', 'complete', 'blocked', 'superseded')),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    next_attempt_unix_ms INTEGER
        CHECK (next_attempt_unix_ms IS NULL
            OR next_attempt_unix_ms BETWEEN 0 AND 9223372036854775807),
    lease_owner BLOB CHECK (lease_owner IS NULL OR length(lease_owner) = 16),
    lease_expires_unix_ms INTEGER
        CHECK (lease_expires_unix_ms IS NULL
            OR lease_expires_unix_ms BETWEEN 1 AND 9223372036854775807),
    created_at_unix_ms INTEGER NOT NULL
        CHECK (created_at_unix_ms BETWEEN 0 AND 9223372036854775807),
    updated_at_unix_ms INTEGER NOT NULL
        CHECK (updated_at_unix_ms BETWEEN created_at_unix_ms AND 9223372036854775807),
    UNIQUE (desired_generation, document_kind),
    CHECK (
        (state = 'pending' AND next_attempt_unix_ms IS NOT NULL
            AND lease_owner IS NULL AND lease_expires_unix_ms IS NULL)
        OR
        (state = 'leased' AND next_attempt_unix_ms IS NULL
            AND lease_owner IS NOT NULL AND lease_expires_unix_ms IS NOT NULL)
        OR
        (state IN ('complete', 'blocked', 'superseded')
            AND next_attempt_unix_ms IS NULL
            AND lease_owner IS NULL AND lease_expires_unix_ms IS NULL)
    )
) STRICT"#
    };
}

macro_rules! presence_outbox_schedule_sql {
    () => {
        r#"CREATE INDEX presence_outbox_by_schedule
ON presence_outbox (state, next_attempt_unix_ms, created_at_unix_ms, document_kind, outbox_id)"#
    };
}

macro_rules! presence_outbox_guard_update_sql {
    () => {
        r#"CREATE TRIGGER presence_outbox_guard_update
BEFORE UPDATE ON presence_outbox
WHEN NEW.outbox_id != OLD.outbox_id
    OR NEW.desired_generation != OLD.desired_generation
    OR NEW.document_kind != OLD.document_kind
    OR NEW.desired_sha256 != OLD.desired_sha256
    OR NEW.target_set_sha256 != OLD.target_set_sha256
    OR NEW.event_id != OLD.event_id
    OR NEW.event_sha256 != OLD.event_sha256
    OR NEW.exact_signed_event_bytes != OLD.exact_signed_event_bytes
    OR NEW.authored_at_unix_s != OLD.authored_at_unix_s
    OR NEW.service_public_key != OLD.service_public_key
    OR NEW.target_count != OLD.target_count
    OR NEW.required_target_count != OLD.required_target_count
    OR NEW.max_attempts != OLD.max_attempts
    OR NEW.initial_backoff_ms != OLD.initial_backoff_ms
    OR NEW.maximum_backoff_ms != OLD.maximum_backoff_ms
    OR NEW.attempt_deadline_ms != OLD.attempt_deadline_ms
    OR NEW.created_at_unix_ms != OLD.created_at_unix_ms
    OR NEW.revision != OLD.revision + 1
    OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
    OR NOT (
        (OLD.state = 'pending' AND NEW.state IN ('leased', 'superseded'))
        OR (OLD.state = 'leased'
            AND NEW.state IN ('pending', 'complete', 'blocked', 'superseded'))
        OR (OLD.state = 'blocked' AND NEW.state IN ('pending', 'superseded'))
    )
BEGIN
    SELECT RAISE(ABORT, 'presence outbox transition is invalid');
END"#
    };
}

macro_rules! presence_targets_table_sql {
    () => {
        r#"CREATE TABLE presence_targets (
    outbox_id BLOB NOT NULL CHECK (length(outbox_id) = 32),
    target_ordinal INTEGER NOT NULL CHECK (target_ordinal BETWEEN 0 AND 31),
    relay_id TEXT NOT NULL
        CHECK (length(CAST(relay_id AS BLOB)) BETWEEN 1 AND 64)
        CHECK (relay_id NOT GLOB '*[^a-z0-9_-]*')
        CHECK (substr(relay_id, 1, 1) GLOB '[a-z]'),
    required INTEGER NOT NULL CHECK (required IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN (
        'pending', 'submitted', 'accepted', 'rejected',
        'rate_limited', 'auth_required', 'failed', 'unknown'
    )),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    attempt_count INTEGER NOT NULL CHECK (attempt_count BETWEEN 0 AND 100),
    next_attempt_unix_ms INTEGER
        CHECK (next_attempt_unix_ms IS NULL
            OR next_attempt_unix_ms BETWEEN 0 AND 9223372036854775807),
    last_attempt_id BLOB
        CHECK (last_attempt_id IS NULL OR length(last_attempt_id) = 32),
    updated_at_unix_ms INTEGER NOT NULL
        CHECK (updated_at_unix_ms BETWEEN 0 AND 9223372036854775807),
    PRIMARY KEY (outbox_id, target_ordinal),
    UNIQUE (outbox_id, relay_id),
    FOREIGN KEY (outbox_id) REFERENCES presence_outbox (outbox_id),
    CHECK (
        (state = 'pending' AND attempt_count = 0
            AND next_attempt_unix_ms IS NOT NULL AND last_attempt_id IS NULL)
        OR
        (state = 'submitted' AND attempt_count BETWEEN 1 AND 100
            AND next_attempt_unix_ms IS NULL AND last_attempt_id IS NOT NULL)
        OR
        (state IN ('accepted', 'rejected', 'auth_required')
            AND attempt_count BETWEEN 1 AND 100
            AND next_attempt_unix_ms IS NULL AND last_attempt_id IS NOT NULL)
        OR
        (state IN ('rate_limited', 'failed', 'unknown')
            AND attempt_count BETWEEN 1 AND 99
            AND next_attempt_unix_ms IS NOT NULL AND last_attempt_id IS NOT NULL)
        OR
        (state IN ('rate_limited', 'failed', 'unknown')
            AND attempt_count = 100
            AND next_attempt_unix_ms IS NULL AND last_attempt_id IS NOT NULL)
    )
) STRICT"#
    };
}

macro_rules! presence_targets_schedule_sql {
    () => {
        r#"CREATE INDEX presence_targets_by_schedule
ON presence_targets (state, next_attempt_unix_ms, outbox_id, target_ordinal)"#
    };
}

macro_rules! presence_targets_guard_update_sql {
    () => {
        r#"CREATE TRIGGER presence_targets_guard_update
BEFORE UPDATE ON presence_targets
WHEN NEW.outbox_id != OLD.outbox_id
    OR NEW.target_ordinal != OLD.target_ordinal
    OR NEW.relay_id != OLD.relay_id
    OR NEW.required != OLD.required
    OR NEW.revision != OLD.revision + 1
    OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
    OR NOT (
        (OLD.state IN ('pending', 'rate_limited', 'failed', 'unknown')
            AND NEW.state = 'submitted'
            AND NEW.attempt_count = OLD.attempt_count + 1
            AND NEW.last_attempt_id IS NOT NULL
            AND NEW.last_attempt_id IS NOT OLD.last_attempt_id)
        OR
        (OLD.state = 'submitted'
            AND NEW.state IN (
                'accepted', 'rejected', 'rate_limited',
                'auth_required', 'failed', 'unknown'
            )
            AND NEW.attempt_count = OLD.attempt_count
            AND NEW.last_attempt_id = OLD.last_attempt_id)
    )
BEGIN
    SELECT RAISE(ABORT, 'presence target transition is invalid');
END"#
    };
}

macro_rules! presence_attempts_table_sql {
    () => {
        r#"CREATE TABLE presence_attempts (
    attempt_id BLOB NOT NULL PRIMARY KEY CHECK (length(attempt_id) = 32),
    outbox_id BLOB NOT NULL CHECK (length(outbox_id) = 32),
    target_ordinal INTEGER NOT NULL CHECK (target_ordinal BETWEEN 0 AND 31),
    attempt_number INTEGER NOT NULL CHECK (attempt_number BETWEEN 1 AND 100),
    event_sha256 BLOB NOT NULL CHECK (length(event_sha256) = 32),
    lease_owner BLOB NOT NULL CHECK (length(lease_owner) = 16),
    started_at_unix_ms INTEGER NOT NULL
        CHECK (started_at_unix_ms BETWEEN 0 AND 9223372036854775807),
    finished_at_unix_ms INTEGER NOT NULL
        CHECK (finished_at_unix_ms BETWEEN started_at_unix_ms AND 9223372036854775807),
    outcome TEXT NOT NULL CHECK (outcome IN (
        'accepted', 'rejected', 'rate_limited',
        'auth_required', 'failed', 'unknown'
    )),
    result_code TEXT NOT NULL
        CHECK (length(CAST(result_code AS BLOB)) BETWEEN 1 AND 64),
    UNIQUE (outbox_id, target_ordinal, attempt_number),
    FOREIGN KEY (outbox_id, target_ordinal)
        REFERENCES presence_targets (outbox_id, target_ordinal)
) STRICT"#
    };
}

const CREATE_PRESENCE_OUTBOX_TABLE_SQL: &str = presence_outbox_table_sql!();
const CREATE_PRESENCE_OUTBOX_SCHEDULE_SQL: &str = presence_outbox_schedule_sql!();
const CREATE_PRESENCE_OUTBOX_GUARD_UPDATE_SQL: &str = presence_outbox_guard_update_sql!();
const CREATE_PRESENCE_OUTBOX_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "presence_outbox_no_delete",
    "presence_outbox",
    "presence outbox rows are retained"
);
const CREATE_PRESENCE_TARGETS_TABLE_SQL: &str = presence_targets_table_sql!();
const CREATE_PRESENCE_TARGETS_SCHEDULE_SQL: &str = presence_targets_schedule_sql!();
const CREATE_PRESENCE_TARGETS_GUARD_UPDATE_SQL: &str = presence_targets_guard_update_sql!();
const CREATE_PRESENCE_TARGETS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "presence_targets_no_delete",
    "presence_targets",
    "presence targets are retained"
);
const CREATE_PRESENCE_ATTEMPTS_TABLE_SQL: &str = presence_attempts_table_sql!();
const CREATE_PRESENCE_ATTEMPTS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "presence_attempts_no_update",
    "presence_attempts",
    "presence attempts are immutable"
);
const CREATE_PRESENCE_ATTEMPTS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "presence_attempts_no_delete",
    "presence_attempts",
    "presence attempts are retained"
);

const CREATE_PRESENCE_PUBLICATION_MIGRATION_SQL: &str = concat!(
    presence_outbox_table_sql!(),
    ";\n",
    presence_outbox_schedule_sql!(),
    ";\n",
    presence_outbox_guard_update_sql!(),
    ";\n",
    immutable_no_delete_sql!(
        "presence_outbox_no_delete",
        "presence_outbox",
        "presence outbox rows are retained"
    ),
    ";\n",
    presence_targets_table_sql!(),
    ";\n",
    presence_targets_schedule_sql!(),
    ";\n",
    presence_targets_guard_update_sql!(),
    ";\n",
    immutable_no_delete_sql!(
        "presence_targets_no_delete",
        "presence_targets",
        "presence targets are retained"
    ),
    ";\n",
    presence_attempts_table_sql!(),
    ";\n",
    immutable_no_update_sql!(
        "presence_attempts_no_update",
        "presence_attempts",
        "presence attempts are immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "presence_attempts_no_delete",
        "presence_attempts",
        "presence attempts are retained"
    ),
    ";"
);

macro_rules! evidence_reconciliations_table_sql {
    () => {
        r#"CREATE TABLE evidence_reconciliations (
    attempt_id BLOB NOT NULL PRIMARY KEY CHECK (length(attempt_id) = 32),
    job_id BLOB NOT NULL CHECK (length(job_id) = 32),
    trade_id BLOB NOT NULL CHECK (length(trade_id) = 16),
    input_generation INTEGER NOT NULL
        CHECK (input_generation BETWEEN 1 AND 9223372036854775807),
    evidence_policy_sha256 BLOB NOT NULL CHECK (length(evidence_policy_sha256) = 32),
    attempt_started_unix_ms INTEGER NOT NULL
        CHECK (attempt_started_unix_ms BETWEEN 0 AND 9223372036854775807),
    deadline_unix_ms INTEGER NOT NULL
        CHECK (deadline_unix_ms BETWEEN attempt_started_unix_ms + 1 AND 9223372036854775807),
    source_count INTEGER NOT NULL CHECK (source_count BETWEEN 1 AND 16),
    FOREIGN KEY (job_id) REFERENCES reconciliation_jobs (job_id)
) STRICT"#
    };
}

macro_rules! evidence_reconciliation_sources_table_sql {
    () => {
        r#"CREATE TABLE evidence_reconciliation_sources (
    attempt_id BLOB NOT NULL CHECK (length(attempt_id) = 32),
    request_id BLOB NOT NULL CHECK (length(request_id) = 32),
    source_ordinal INTEGER NOT NULL CHECK (source_ordinal BETWEEN 0 AND 15),
    source_id TEXT NOT NULL
        CHECK (length(CAST(source_id AS BLOB)) BETWEEN 1 AND 64)
        CHECK (source_id NOT GLOB '*[^a-z0-9_-]*')
        CHECK (substr(source_id, 1, 1) GLOB '[a-z]'),
    trade_id BLOB NOT NULL CHECK (length(trade_id) = 16),
    required INTEGER NOT NULL CHECK (required IN (0, 1)),
    selector_sha256 BLOB NOT NULL CHECK (length(selector_sha256) = 32),
    replay_id BLOB NOT NULL CHECK (length(replay_id) = 32),
    completion TEXT NOT NULL CHECK (completion IN (
        'complete', 'incomplete_timeout', 'incomplete_unavailable',
        'incomplete_resource_limit', 'incomplete_unknown', 'unsupported'
    )),
    started_unix_ms INTEGER NOT NULL
        CHECK (started_unix_ms BETWEEN 0 AND 9223372036854775807),
    finished_unix_ms INTEGER NOT NULL
        CHECK (finished_unix_ms BETWEEN started_unix_ms AND 9223372036854775807),
    accepted_event_count INTEGER NOT NULL CHECK (accepted_event_count BETWEEN 0 AND 4096),
    accepted_event_bytes INTEGER NOT NULL CHECK (accepted_event_bytes BETWEEN 0 AND 8388608),
    accepted_inventory_sha256 BLOB NOT NULL CHECK (length(accepted_inventory_sha256) = 32),
    duplicate_observation_count INTEGER NOT NULL
        CHECK (duplicate_observation_count BETWEEN 0 AND 4096),
    first_observed_unix_s INTEGER
        CHECK (first_observed_unix_s BETWEEN 0 AND 9223372036854775807),
    prior_cursor_created_at_unix_s INTEGER
        CHECK (prior_cursor_created_at_unix_s BETWEEN 0 AND 9223372036854775807),
    prior_cursor_event_id BLOB CHECK (length(prior_cursor_event_id) = 32),
    overlap_seconds INTEGER NOT NULL CHECK (overlap_seconds BETWEEN 1 AND 86400),
    inclusive_since_unix_s INTEGER NOT NULL
        CHECK (inclusive_since_unix_s BETWEEN 0 AND 9223372036854775807),
    candidate_created_at_unix_s INTEGER
        CHECK (candidate_created_at_unix_s BETWEEN 0 AND 9223372036854775807),
    candidate_event_id BLOB CHECK (length(candidate_event_id) = 32),
    checkpoint_advanced INTEGER NOT NULL CHECK (checkpoint_advanced IN (0, 1)),
    PRIMARY KEY (attempt_id, request_id),
    UNIQUE (attempt_id, source_ordinal),
    FOREIGN KEY (attempt_id) REFERENCES evidence_reconciliations (attempt_id),
    CHECK ((accepted_event_count = 0) = (accepted_event_bytes = 0)),
    CHECK ((accepted_event_count = 0) = (first_observed_unix_s IS NULL)),
    CHECK ((accepted_event_count = 0) = (candidate_created_at_unix_s IS NULL)),
    CHECK ((candidate_created_at_unix_s IS NULL) = (candidate_event_id IS NULL)),
    CHECK ((prior_cursor_created_at_unix_s IS NULL) = (prior_cursor_event_id IS NULL)),
    CHECK (checkpoint_advanced = 0 OR completion = 'complete'),
    CHECK (checkpoint_advanced = 0 OR candidate_event_id IS NOT NULL)
) STRICT"#
    };
}

const CREATE_EVIDENCE_RECONCILIATIONS_TABLE_SQL: &str = evidence_reconciliations_table_sql!();
const CREATE_EVIDENCE_RECONCILIATIONS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "evidence_reconciliations_no_update",
    "evidence_reconciliations",
    "reconciliation attempts are immutable"
);
const CREATE_EVIDENCE_RECONCILIATIONS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "evidence_reconciliations_no_delete",
    "evidence_reconciliations",
    "reconciliation attempts are retained"
);
const CREATE_EVIDENCE_RECONCILIATION_SOURCES_TABLE_SQL: &str =
    evidence_reconciliation_sources_table_sql!();
const CREATE_EVIDENCE_RECONCILIATION_SOURCES_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "evidence_reconciliation_sources_no_update",
    "evidence_reconciliation_sources",
    "reconciliation source results are immutable"
);
const CREATE_EVIDENCE_RECONCILIATION_SOURCES_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "evidence_reconciliation_sources_no_delete",
    "evidence_reconciliation_sources",
    "reconciliation source results are retained"
);
const CREATE_RECONCILIATION_RESULTS_MIGRATION_SQL: &str = concat!(
    evidence_reconciliations_table_sql!(),
    ";\n",
    immutable_no_update_sql!(
        "evidence_reconciliations_no_update",
        "evidence_reconciliations",
        "reconciliation attempts are immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "evidence_reconciliations_no_delete",
        "evidence_reconciliations",
        "reconciliation attempts are retained"
    ),
    ";\n",
    evidence_reconciliation_sources_table_sql!(),
    ";\n",
    immutable_no_update_sql!(
        "evidence_reconciliation_sources_no_update",
        "evidence_reconciliation_sources",
        "reconciliation source results are immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "evidence_reconciliation_sources_no_delete",
        "evidence_reconciliation_sources",
        "reconciliation source results are retained"
    ),
    ";",
);

macro_rules! evidence_manifests_table_sql {
    () => {
        r#"CREATE TABLE evidence_manifests (
    manifest_sha256 BLOB NOT NULL PRIMARY KEY CHECK (length(manifest_sha256) = 32),
    attempt_id BLOB NOT NULL UNIQUE CHECK (length(attempt_id) = 32),
    trade_id BLOB NOT NULL CHECK (length(trade_id) = 16),
    trade_generation INTEGER NOT NULL
        CHECK (trade_generation BETWEEN 1 AND 9223372036854775807),
    evidence_policy_sha256 BLOB NOT NULL CHECK (length(evidence_policy_sha256) = 32),
    canonical_manifest BLOB NOT NULL
        CHECK (length(canonical_manifest) BETWEEN 1 AND 16777216),
    observed_at_unix_s INTEGER NOT NULL
        CHECK (observed_at_unix_s BETWEEN 0 AND 9223372036854775807),
    source_count INTEGER NOT NULL CHECK (source_count BETWEEN 1 AND 16),
    observation_count INTEGER NOT NULL CHECK (observation_count BETWEEN 0 AND 65536),
    FOREIGN KEY (attempt_id) REFERENCES evidence_reconciliations (attempt_id)
) STRICT"#
    };
}

macro_rules! trade_projections_table_sql {
    () => {
        r#"CREATE TABLE trade_projections (
    projection_sha256 BLOB NOT NULL PRIMARY KEY CHECK (length(projection_sha256) = 32),
    manifest_sha256 BLOB NOT NULL UNIQUE CHECK (length(manifest_sha256) = 32),
    shared_projection_sha256 BLOB NOT NULL CHECK (length(shared_projection_sha256) = 32),
    reducer_contract TEXT NOT NULL CHECK (reducer_contract = 'radroots.trade.reducer.v1'),
    reducer_contract_version INTEGER NOT NULL CHECK (reducer_contract_version = 1),
    issue_count INTEGER NOT NULL CHECK (issue_count BETWEEN 0 AND 65536),
    FOREIGN KEY (manifest_sha256) REFERENCES evidence_manifests (manifest_sha256)
) STRICT"#
    };
}

macro_rules! attestation_reports_table_sql {
    () => {
        r#"CREATE TABLE attestation_reports (
    statement_sha256 BLOB NOT NULL PRIMARY KEY CHECK (length(statement_sha256) = 32),
    manifest_sha256 BLOB NOT NULL CHECK (length(manifest_sha256) = 32),
    projection_sha256 BLOB NOT NULL CHECK (length(projection_sha256) = 32),
    trade_id BLOB NOT NULL CHECK (length(trade_id) = 16),
    claim_mutation_id BLOB NOT NULL CHECK (length(claim_mutation_id) = 32),
    issuer_public_key BLOB NOT NULL CHECK (length(issuer_public_key) = 32),
    outcome TEXT NOT NULL CHECK (outcome IN ('valid', 'invalid', 'indeterminate')),
    canonical_report BLOB NOT NULL CHECK (length(canonical_report) BETWEEN 1 AND 16384),
    observed_at_unix_s INTEGER NOT NULL
        CHECK (observed_at_unix_s BETWEEN 0 AND 9223372036854775807),
    supersedes_statement_sha256 BLOB CHECK (length(supersedes_statement_sha256) = 32),
    supersedes_event_id BLOB CHECK (length(supersedes_event_id) = 32),
    FOREIGN KEY (manifest_sha256) REFERENCES evidence_manifests (manifest_sha256),
    FOREIGN KEY (projection_sha256) REFERENCES trade_projections (projection_sha256),
    FOREIGN KEY (supersedes_statement_sha256)
        REFERENCES attestation_reports (statement_sha256),
    CHECK ((supersedes_statement_sha256 IS NULL) = (supersedes_event_id IS NULL))
) STRICT"#
    };
}

macro_rules! attestation_reports_supersession_sql {
    () => {
        r#"CREATE UNIQUE INDEX attestation_reports_one_successor
ON attestation_reports (supersedes_statement_sha256)
WHERE supersedes_statement_sha256 IS NOT NULL"#
    };
}

macro_rules! signed_attestation_events_table_sql {
    () => {
        r#"CREATE TABLE signed_attestation_events (
    event_id BLOB NOT NULL PRIMARY KEY CHECK (length(event_id) = 32),
    statement_sha256 BLOB NOT NULL UNIQUE CHECK (length(statement_sha256) = 32),
    event_sha256 BLOB NOT NULL UNIQUE CHECK (length(event_sha256) = 32),
    issuer_public_key BLOB NOT NULL CHECK (length(issuer_public_key) = 32),
    authored_at_unix_s INTEGER NOT NULL
        CHECK (authored_at_unix_s BETWEEN 0 AND 9223372036854775807),
    canonical_event_json BLOB NOT NULL
        CHECK (length(canonical_event_json) BETWEEN 1 AND 32768),
    FOREIGN KEY (statement_sha256) REFERENCES attestation_reports (statement_sha256)
) STRICT"#
    };
}

macro_rules! publication_outbox_table_sql {
    () => {
        r#"CREATE TABLE publication_outbox (
    outbox_id BLOB NOT NULL PRIMARY KEY CHECK (length(outbox_id) = 32),
    event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 32),
    event_sha256 BLOB NOT NULL CHECK (length(event_sha256) = 32),
    publication_authority_sha256 BLOB NOT NULL
        CHECK (length(publication_authority_sha256) = 32),
    target_set_sha256 BLOB NOT NULL CHECK (length(target_set_sha256) = 32),
    target_count INTEGER NOT NULL CHECK (target_count BETWEEN 1 AND 32),
    required_target_count INTEGER NOT NULL
        CHECK (required_target_count BETWEEN 0 AND target_count),
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
    initial_backoff_ms INTEGER NOT NULL CHECK (initial_backoff_ms BETWEEN 1 AND 60000),
    maximum_backoff_ms INTEGER NOT NULL CHECK (maximum_backoff_ms BETWEEN 1 AND 3600000),
    attempt_deadline_ms INTEGER NOT NULL CHECK (attempt_deadline_ms BETWEEN 100 AND 30000),
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'complete', 'blocked')),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9223372036854775807),
    next_attempt_unix_ms INTEGER,
    lease_owner BLOB,
    lease_expires_unix_ms INTEGER,
    created_at_unix_ms INTEGER NOT NULL
        CHECK (created_at_unix_ms BETWEEN 0 AND 9223372036854775807),
    updated_at_unix_ms INTEGER NOT NULL
        CHECK (updated_at_unix_ms BETWEEN created_at_unix_ms AND 9223372036854775807),
    FOREIGN KEY (event_id) REFERENCES signed_attestation_events (event_id),
    CHECK (initial_backoff_ms <= maximum_backoff_ms),
    CHECK (
        (state = 'pending'
            AND next_attempt_unix_ms IS NOT NULL
            AND next_attempt_unix_ms BETWEEN 0 AND 9223372036854775807
            AND lease_owner IS NULL AND lease_expires_unix_ms IS NULL)
        OR (state = 'leased'
            AND next_attempt_unix_ms IS NULL
            AND lease_owner IS NOT NULL
            AND length(lease_owner) = 16
            AND lease_expires_unix_ms IS NOT NULL
            AND lease_expires_unix_ms BETWEEN 1 AND 9223372036854775807)
        OR (state IN ('complete', 'blocked')
            AND next_attempt_unix_ms IS NULL
            AND lease_owner IS NULL AND lease_expires_unix_ms IS NULL)
    )
) STRICT"#
    };
}

macro_rules! publication_outbox_schedule_sql {
    () => {
        r#"CREATE INDEX publication_outbox_by_schedule
ON publication_outbox (
    state, next_attempt_unix_ms, lease_expires_unix_ms,
    created_at_unix_ms, outbox_id
)"#
    };
}

macro_rules! publication_outbox_guard_update_sql {
    () => {
        r#"CREATE TRIGGER publication_outbox_guard_update
BEFORE UPDATE ON publication_outbox
WHEN NEW.outbox_id != OLD.outbox_id
    OR NEW.event_id != OLD.event_id
    OR NEW.event_sha256 != OLD.event_sha256
    OR NEW.publication_authority_sha256 != OLD.publication_authority_sha256
    OR NEW.target_set_sha256 != OLD.target_set_sha256
    OR NEW.target_count != OLD.target_count
    OR NEW.required_target_count != OLD.required_target_count
    OR NEW.max_attempts != OLD.max_attempts
    OR NEW.initial_backoff_ms != OLD.initial_backoff_ms
    OR NEW.maximum_backoff_ms != OLD.maximum_backoff_ms
    OR NEW.attempt_deadline_ms != OLD.attempt_deadline_ms
    OR NEW.created_at_unix_ms != OLD.created_at_unix_ms
    OR NEW.revision != OLD.revision + 1
    OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
    OR NOT (
        (OLD.state = 'pending' AND NEW.state IN ('leased', 'blocked'))
        OR (OLD.state = 'leased'
            AND NEW.state IN ('leased', 'pending', 'complete', 'blocked'))
        OR (OLD.state = 'blocked' AND NEW.state = 'pending')
    )
BEGIN
    SELECT RAISE(ABORT, 'publication outbox transition is invalid');
END"#
    };
}

macro_rules! publication_targets_table_sql {
    () => {
        r#"CREATE TABLE publication_targets (
    outbox_id BLOB NOT NULL CHECK (length(outbox_id) = 32),
    target_ordinal INTEGER NOT NULL CHECK (target_ordinal BETWEEN 0 AND 31),
    relay_id TEXT NOT NULL
        CHECK (length(CAST(relay_id AS BLOB)) BETWEEN 1 AND 64)
        CHECK (relay_id NOT GLOB '*[^a-z0-9_-]*')
        CHECK (substr(relay_id, 1, 1) GLOB '[a-z]'),
    required INTEGER NOT NULL CHECK (required IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN (
        'pending', 'submitted', 'accepted', 'rejected', 'rate_limited',
        'auth_required', 'failed', 'unknown'
    )),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9223372036854775807),
    attempt_count INTEGER NOT NULL CHECK (attempt_count BETWEEN 0 AND 100),
    next_attempt_unix_ms INTEGER
        CHECK (next_attempt_unix_ms BETWEEN 0 AND 9223372036854775807),
    last_attempt_id BLOB CHECK (length(last_attempt_id) = 32),
    updated_at_unix_ms INTEGER NOT NULL
        CHECK (updated_at_unix_ms BETWEEN 0 AND 9223372036854775807),
    PRIMARY KEY (outbox_id, target_ordinal),
    UNIQUE (outbox_id, relay_id),
    FOREIGN KEY (outbox_id) REFERENCES publication_outbox (outbox_id),
    CHECK ((attempt_count = 0) = (last_attempt_id IS NULL))
) STRICT"#
    };
}

macro_rules! publication_targets_schedule_sql {
    () => {
        r#"CREATE INDEX publication_targets_by_schedule
ON publication_targets (state, next_attempt_unix_ms, updated_at_unix_ms, outbox_id, target_ordinal)"#
    };
}

macro_rules! publication_targets_guard_update_sql {
    () => {
        r#"CREATE TRIGGER publication_targets_guard_update
BEFORE UPDATE ON publication_targets
WHEN NEW.outbox_id != OLD.outbox_id
    OR NEW.target_ordinal != OLD.target_ordinal
    OR NEW.relay_id != OLD.relay_id
    OR NEW.required != OLD.required
    OR NEW.revision != OLD.revision + 1
    OR NEW.attempt_count < OLD.attempt_count
    OR NEW.attempt_count > OLD.attempt_count + 1
    OR NEW.updated_at_unix_ms < OLD.updated_at_unix_ms
    OR OLD.state = 'accepted'
BEGIN
    SELECT RAISE(ABORT, 'publication target transition is invalid');
END"#
    };
}

macro_rules! publication_attempts_table_sql {
    () => {
        r#"CREATE TABLE publication_attempts (
    attempt_id BLOB NOT NULL PRIMARY KEY CHECK (length(attempt_id) = 32),
    outbox_id BLOB NOT NULL CHECK (length(outbox_id) = 32),
    target_ordinal INTEGER NOT NULL CHECK (target_ordinal BETWEEN 0 AND 31),
    attempt_number INTEGER NOT NULL CHECK (attempt_number BETWEEN 1 AND 100),
    event_sha256 BLOB NOT NULL CHECK (length(event_sha256) = 32),
    lease_owner BLOB NOT NULL CHECK (length(lease_owner) = 16),
    started_at_unix_ms INTEGER NOT NULL
        CHECK (started_at_unix_ms BETWEEN 0 AND 9223372036854775807),
    finished_at_unix_ms INTEGER NOT NULL
        CHECK (finished_at_unix_ms BETWEEN started_at_unix_ms AND 9223372036854775807),
    outcome TEXT NOT NULL CHECK (outcome IN (
        'submitted', 'accepted', 'rejected', 'rate_limited',
        'auth_required', 'failed', 'unknown'
    )),
    result_code TEXT NOT NULL
        CHECK (length(CAST(result_code AS BLOB)) BETWEEN 1 AND 64)
        CHECK (result_code NOT GLOB '*[^a-z0-9_]*')
        CHECK (substr(result_code, 1, 1) GLOB '[a-z]'),
    UNIQUE (outbox_id, target_ordinal, attempt_number),
    FOREIGN KEY (outbox_id, target_ordinal)
        REFERENCES publication_targets (outbox_id, target_ordinal)
) STRICT"#
    };
}

const CREATE_EVIDENCE_MANIFESTS_TABLE_SQL: &str = evidence_manifests_table_sql!();
const CREATE_EVIDENCE_MANIFESTS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "evidence_manifests_no_update",
    "evidence_manifests",
    "evidence manifests are immutable"
);
const CREATE_EVIDENCE_MANIFESTS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "evidence_manifests_no_delete",
    "evidence_manifests",
    "evidence manifests are retained"
);
const CREATE_TRADE_PROJECTIONS_TABLE_SQL: &str = trade_projections_table_sql!();
const CREATE_TRADE_PROJECTIONS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "trade_projections_no_update",
    "trade_projections",
    "trade projections are immutable"
);
const CREATE_TRADE_PROJECTIONS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "trade_projections_no_delete",
    "trade_projections",
    "trade projections are retained"
);
const CREATE_ATTESTATION_REPORTS_TABLE_SQL: &str = attestation_reports_table_sql!();
const CREATE_ATTESTATION_REPORTS_SUPERSESSION_SQL: &str = attestation_reports_supersession_sql!();
const CREATE_ATTESTATION_REPORTS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "attestation_reports_no_update",
    "attestation_reports",
    "attestation reports are immutable"
);
const CREATE_ATTESTATION_REPORTS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "attestation_reports_no_delete",
    "attestation_reports",
    "attestation reports are retained"
);
const CREATE_SIGNED_ATTESTATION_EVENTS_TABLE_SQL: &str = signed_attestation_events_table_sql!();
const CREATE_SIGNED_ATTESTATION_EVENTS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "signed_attestation_events_no_update",
    "signed_attestation_events",
    "signed attestation events are immutable"
);
const CREATE_SIGNED_ATTESTATION_EVENTS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "signed_attestation_events_no_delete",
    "signed_attestation_events",
    "signed attestation events are retained"
);
const CREATE_PUBLICATION_OUTBOX_TABLE_SQL: &str = publication_outbox_table_sql!();
const CREATE_PUBLICATION_OUTBOX_SCHEDULE_SQL: &str = publication_outbox_schedule_sql!();
const CREATE_PUBLICATION_OUTBOX_GUARD_UPDATE_SQL: &str = publication_outbox_guard_update_sql!();
const CREATE_PUBLICATION_OUTBOX_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "publication_outbox_no_delete",
    "publication_outbox",
    "publication outbox rows are retained"
);
const CREATE_PUBLICATION_TARGETS_TABLE_SQL: &str = publication_targets_table_sql!();
const CREATE_PUBLICATION_TARGETS_SCHEDULE_SQL: &str = publication_targets_schedule_sql!();
const CREATE_PUBLICATION_TARGETS_GUARD_UPDATE_SQL: &str = publication_targets_guard_update_sql!();
const CREATE_PUBLICATION_TARGETS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "publication_targets_no_delete",
    "publication_targets",
    "publication targets are retained"
);
const CREATE_PUBLICATION_ATTEMPTS_TABLE_SQL: &str = publication_attempts_table_sql!();
const CREATE_PUBLICATION_ATTEMPTS_NO_UPDATE_SQL: &str = immutable_no_update_sql!(
    "publication_attempts_no_update",
    "publication_attempts",
    "publication attempts are immutable"
);
const CREATE_PUBLICATION_ATTEMPTS_NO_DELETE_SQL: &str = immutable_no_delete_sql!(
    "publication_attempts_no_delete",
    "publication_attempts",
    "publication attempts are retained"
);

const CREATE_REPORT_PUBLICATION_MIGRATION_SQL: &str = concat!(
    evidence_manifests_table_sql!(),
    ";\n",
    immutable_no_update_sql!(
        "evidence_manifests_no_update",
        "evidence_manifests",
        "evidence manifests are immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "evidence_manifests_no_delete",
        "evidence_manifests",
        "evidence manifests are retained"
    ),
    ";\n",
    trade_projections_table_sql!(),
    ";\n",
    immutable_no_update_sql!(
        "trade_projections_no_update",
        "trade_projections",
        "trade projections are immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "trade_projections_no_delete",
        "trade_projections",
        "trade projections are retained"
    ),
    ";\n",
    attestation_reports_table_sql!(),
    ";\n",
    attestation_reports_supersession_sql!(),
    ";\n",
    immutable_no_update_sql!(
        "attestation_reports_no_update",
        "attestation_reports",
        "attestation reports are immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "attestation_reports_no_delete",
        "attestation_reports",
        "attestation reports are retained"
    ),
    ";\n",
    signed_attestation_events_table_sql!(),
    ";\n",
    immutable_no_update_sql!(
        "signed_attestation_events_no_update",
        "signed_attestation_events",
        "signed attestation events are immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "signed_attestation_events_no_delete",
        "signed_attestation_events",
        "signed attestation events are retained"
    ),
    ";\n",
    publication_outbox_table_sql!(),
    ";\n",
    publication_outbox_schedule_sql!(),
    ";\n",
    publication_outbox_guard_update_sql!(),
    ";\n",
    immutable_no_delete_sql!(
        "publication_outbox_no_delete",
        "publication_outbox",
        "publication outbox rows are retained"
    ),
    ";\n",
    publication_targets_table_sql!(),
    ";\n",
    publication_targets_schedule_sql!(),
    ";\n",
    publication_targets_guard_update_sql!(),
    ";\n",
    immutable_no_delete_sql!(
        "publication_targets_no_delete",
        "publication_targets",
        "publication targets are retained"
    ),
    ";\n",
    publication_attempts_table_sql!(),
    ";\n",
    immutable_no_update_sql!(
        "publication_attempts_no_update",
        "publication_attempts",
        "publication attempts are immutable"
    ),
    ";\n",
    immutable_no_delete_sql!(
        "publication_attempts_no_delete",
        "publication_attempts",
        "publication attempts are retained"
    ),
    ";"
);

const EVIDENCE_RECONCILIATIONS_TABLE_SHA256: [u8; 32] = [
    0xaf, 0xed, 0xa3, 0xfb, 0xfb, 0x32, 0x6b, 0xd5, 0x27, 0x26, 0x42, 0x1d, 0x6c, 0x41, 0x5e, 0xff,
    0xf9, 0x71, 0xf7, 0x47, 0x72, 0x5e, 0xbf, 0x8b, 0x34, 0x26, 0x8f, 0x89, 0x6e, 0xa1, 0x2d, 0x9b,
];
const EVIDENCE_RECONCILIATIONS_NO_UPDATE_SHA256: [u8; 32] = [
    0xf4, 0x8f, 0xe6, 0x07, 0x7f, 0x32, 0x9c, 0x96, 0xc7, 0x8a, 0xad, 0xd4, 0x41, 0x53, 0x1a, 0xa3,
    0x24, 0x2b, 0x5d, 0x12, 0x63, 0x18, 0xdb, 0x39, 0xe7, 0x73, 0xbb, 0x0c, 0xa5, 0x40, 0xcd, 0xe9,
];
const EVIDENCE_RECONCILIATIONS_NO_DELETE_SHA256: [u8; 32] = [
    0x9a, 0x92, 0xf6, 0x89, 0x01, 0x75, 0xff, 0x89, 0x30, 0xee, 0x47, 0x8b, 0x8a, 0x6e, 0x10, 0x4f,
    0xc3, 0x88, 0x4f, 0x83, 0xc5, 0x01, 0x95, 0x9b, 0x72, 0x3e, 0xbd, 0xed, 0x87, 0x2b, 0x13, 0xdf,
];
const EVIDENCE_RECONCILIATION_SOURCES_TABLE_SHA256: [u8; 32] = [
    0xd1, 0x56, 0x84, 0x76, 0xc7, 0x52, 0xf8, 0x22, 0x5c, 0xa0, 0xce, 0x77, 0xa0, 0x1f, 0xc4, 0xc6,
    0x78, 0x22, 0x62, 0x61, 0x02, 0xaa, 0x92, 0x5c, 0xe5, 0x6d, 0x5c, 0x91, 0x4c, 0x8e, 0x1c, 0x5a,
];
const EVIDENCE_RECONCILIATION_SOURCES_NO_UPDATE_SHA256: [u8; 32] = [
    0x85, 0x8a, 0x6d, 0x3b, 0x97, 0x35, 0x91, 0x0b, 0x93, 0xe1, 0x9a, 0x73, 0x97, 0x6e, 0x47, 0x0e,
    0xe6, 0xb6, 0x38, 0x68, 0x31, 0x35, 0xf2, 0x1d, 0x3a, 0x30, 0xe1, 0xa6, 0x3f, 0xae, 0x07, 0x6b,
];
const EVIDENCE_RECONCILIATION_SOURCES_NO_DELETE_SHA256: [u8; 32] = [
    0x55, 0x75, 0xfc, 0xaf, 0xab, 0x07, 0xaf, 0x83, 0x0b, 0x69, 0x8d, 0xfa, 0x86, 0x56, 0xe9, 0xc6,
    0x98, 0x0b, 0x4c, 0xdc, 0xa2, 0xde, 0xce, 0xfc, 0x06, 0x41, 0x86, 0x69, 0x2e, 0xac, 0x00, 0x39,
];

const EVIDENCE_MANIFESTS_TABLE_SHA256: [u8; 32] = [
    0x95, 0x41, 0x37, 0x66, 0x31, 0x3e, 0x96, 0x83, 0x81, 0xdf, 0x0d, 0x8b, 0xc5, 0xd5, 0x50, 0x8b,
    0xde, 0x34, 0x3c, 0x68, 0xd6, 0x56, 0xea, 0xea, 0xab, 0x08, 0x87, 0x10, 0x9b, 0x23, 0xc6, 0xfb,
];
const EVIDENCE_MANIFESTS_NO_UPDATE_SHA256: [u8; 32] = [
    0x7f, 0xc1, 0x21, 0xaf, 0x5e, 0x9d, 0xc8, 0x32, 0xae, 0xc9, 0x98, 0x6d, 0x45, 0xc7, 0x68, 0xf3,
    0xc1, 0x76, 0x14, 0xbb, 0xf6, 0xbe, 0x41, 0x11, 0x6a, 0x7e, 0xa9, 0x22, 0x90, 0x27, 0x0e, 0xe5,
];
const EVIDENCE_MANIFESTS_NO_DELETE_SHA256: [u8; 32] = [
    0xd9, 0x9e, 0x5f, 0x55, 0xf7, 0xf2, 0x48, 0x5e, 0xfc, 0xc3, 0xb9, 0x11, 0x88, 0xf5, 0x8d, 0x3b,
    0xa0, 0x0c, 0x3e, 0xf7, 0x82, 0x3d, 0x88, 0xe0, 0x82, 0xc2, 0x60, 0xb8, 0x0f, 0xf4, 0xd6, 0xa4,
];
const TRADE_PROJECTIONS_TABLE_SHA256: [u8; 32] = [
    0xac, 0x04, 0x55, 0xd5, 0x1b, 0xed, 0xfb, 0x9b, 0x59, 0xfd, 0xc9, 0xea, 0x63, 0x1b, 0x85, 0x63,
    0x7a, 0x16, 0xf1, 0xb1, 0xfe, 0xad, 0x4d, 0x4c, 0xdf, 0xba, 0xad, 0xa3, 0xef, 0x85, 0x65, 0x43,
];
const TRADE_PROJECTIONS_NO_UPDATE_SHA256: [u8; 32] = [
    0x8f, 0xba, 0x6b, 0x06, 0x8e, 0xb8, 0x69, 0x84, 0x14, 0x4b, 0x64, 0x14, 0xbf, 0x8c, 0x4e, 0x95,
    0x47, 0x58, 0xaf, 0x09, 0x7d, 0xbb, 0x3a, 0xfe, 0x72, 0x06, 0x21, 0x00, 0x6a, 0x43, 0x32, 0xe0,
];
const TRADE_PROJECTIONS_NO_DELETE_SHA256: [u8; 32] = [
    0x94, 0x8a, 0x5c, 0xed, 0x5a, 0xaa, 0x0a, 0xb4, 0x90, 0x1c, 0xe4, 0x3a, 0xdb, 0x97, 0x69, 0xbf,
    0x5a, 0x19, 0x5d, 0x35, 0x95, 0xc9, 0x39, 0x54, 0x73, 0xe9, 0x6e, 0xea, 0x9c, 0x08, 0x26, 0xb2,
];
const ATTESTATION_REPORTS_TABLE_SHA256: [u8; 32] = [
    0x97, 0xc4, 0x83, 0x37, 0x56, 0x92, 0x23, 0x67, 0xb2, 0xb8, 0xd2, 0x00, 0xeb, 0xc9, 0x31, 0x0d,
    0xc8, 0xb9, 0x73, 0x38, 0xf6, 0xc5, 0x9c, 0xe5, 0xe5, 0x19, 0x87, 0x64, 0x19, 0x9d, 0x44, 0xd2,
];
const ATTESTATION_REPORTS_SUPERSESSION_SHA256: [u8; 32] = [
    0x57, 0xd5, 0x59, 0x2e, 0x2a, 0x7a, 0xd0, 0x03, 0x06, 0x42, 0x28, 0x16, 0x31, 0x8c, 0xe1, 0x25,
    0x30, 0x1c, 0xd3, 0x73, 0xff, 0xc3, 0x47, 0xf5, 0xf8, 0x65, 0xc0, 0x63, 0x73, 0x76, 0xad, 0x8e,
];
const ATTESTATION_REPORTS_NO_UPDATE_SHA256: [u8; 32] = [
    0x5f, 0x27, 0x19, 0x68, 0xe4, 0xd8, 0x32, 0x84, 0xe1, 0x04, 0x09, 0x37, 0x0b, 0xdc, 0x55, 0x9d,
    0xfa, 0x8f, 0xce, 0xa9, 0x0f, 0xd9, 0xd3, 0x47, 0xd4, 0xfa, 0xc8, 0x12, 0x53, 0x77, 0x17, 0x23,
];
const ATTESTATION_REPORTS_NO_DELETE_SHA256: [u8; 32] = [
    0xbe, 0xaf, 0xa1, 0x1a, 0xbe, 0x57, 0x27, 0xac, 0x3e, 0x43, 0x26, 0xd0, 0x8b, 0x0d, 0x39, 0x36,
    0xb3, 0x04, 0x11, 0x37, 0x48, 0x13, 0xd3, 0x2a, 0xc8, 0x24, 0x1f, 0x56, 0xa9, 0x2c, 0x51, 0xfc,
];
const SIGNED_ATTESTATION_EVENTS_TABLE_SHA256: [u8; 32] = [
    0x9b, 0x83, 0x5b, 0x84, 0x97, 0x1f, 0x52, 0xba, 0xc2, 0x8f, 0xf2, 0xba, 0x04, 0x9a, 0x1b, 0x9b,
    0xfc, 0xcc, 0x7c, 0xab, 0x39, 0xd0, 0x16, 0x53, 0x06, 0xa3, 0x9b, 0x93, 0x8c, 0x51, 0x72, 0xab,
];
const SIGNED_ATTESTATION_EVENTS_NO_UPDATE_SHA256: [u8; 32] = [
    0x36, 0x1d, 0xbe, 0xda, 0xae, 0xd4, 0xfc, 0x4c, 0xf3, 0xe8, 0xa8, 0x60, 0xeb, 0x63, 0xc8, 0xc7,
    0x3a, 0x31, 0x79, 0x7c, 0x4f, 0x92, 0x79, 0x8f, 0x7d, 0x3a, 0x9f, 0xec, 0x7f, 0x95, 0xa8, 0x44,
];
const SIGNED_ATTESTATION_EVENTS_NO_DELETE_SHA256: [u8; 32] = [
    0x06, 0x4d, 0x71, 0x90, 0x60, 0x9e, 0x6a, 0x8e, 0xac, 0x6d, 0x80, 0x44, 0xe1, 0xef, 0x53, 0x76,
    0x6a, 0xea, 0x6a, 0xb3, 0x68, 0xc9, 0x48, 0xb1, 0x64, 0x24, 0x9a, 0xf2, 0xc0, 0xc3, 0xeb, 0x9c,
];
const PUBLICATION_OUTBOX_TABLE_SHA256: [u8; 32] = [
    0x26, 0x2a, 0x56, 0x79, 0x77, 0x73, 0xcb, 0x84, 0xb6, 0x55, 0x1c, 0x19, 0x32, 0xe1, 0x0e, 0xb1,
    0x98, 0xf2, 0x4b, 0xf2, 0xb3, 0x5f, 0x90, 0x15, 0xac, 0xc1, 0x8f, 0x27, 0xfd, 0x89, 0x4b, 0x2d,
];
const PUBLICATION_OUTBOX_SCHEDULE_SHA256: [u8; 32] = [
    0xc0, 0x70, 0xb5, 0xb0, 0xd0, 0x1f, 0x05, 0x34, 0xe9, 0x1e, 0xfa, 0xee, 0x6c, 0xba, 0xdd, 0xf8,
    0x5c, 0xf1, 0x85, 0x33, 0xa7, 0x04, 0x5c, 0xfb, 0x65, 0x11, 0xdc, 0x80, 0x28, 0x7b, 0x4f, 0x6e,
];
const PUBLICATION_OUTBOX_GUARD_UPDATE_SHA256: [u8; 32] = [
    0x3e, 0xd0, 0x80, 0x98, 0x34, 0xb2, 0x24, 0x51, 0x5b, 0x7b, 0x06, 0x8e, 0x46, 0x8e, 0xbe, 0x8a,
    0x52, 0x8b, 0xdb, 0xcf, 0xb4, 0x0e, 0x33, 0xe5, 0x19, 0xc6, 0xfd, 0xef, 0x19, 0x80, 0xcd, 0x62,
];
const PUBLICATION_OUTBOX_NO_DELETE_SHA256: [u8; 32] = [
    0xc5, 0x77, 0x63, 0xa0, 0x90, 0xde, 0xe0, 0x11, 0x62, 0x2a, 0xda, 0x9f, 0x32, 0x24, 0x47, 0x59,
    0x54, 0xdf, 0x60, 0xd7, 0xe3, 0xf2, 0xf3, 0x42, 0x36, 0x14, 0x8e, 0xba, 0x52, 0x84, 0x3a, 0x6e,
];
const PUBLICATION_TARGETS_TABLE_SHA256: [u8; 32] = [
    0x23, 0xa0, 0x78, 0x7f, 0x7d, 0x90, 0x91, 0x8b, 0x41, 0x4a, 0x22, 0x37, 0xcc, 0x70, 0xa0, 0x83,
    0x1a, 0xe0, 0xfa, 0x05, 0x2e, 0x1b, 0x9f, 0x25, 0x50, 0xe3, 0x6f, 0xda, 0xd1, 0x53, 0xab, 0x7b,
];
const PUBLICATION_TARGETS_SCHEDULE_SHA256: [u8; 32] = [
    0xf8, 0xc4, 0x46, 0x10, 0xcb, 0x2d, 0xe4, 0xa3, 0x54, 0xd7, 0x93, 0x64, 0x9f, 0x8b, 0xa9, 0xf1,
    0x95, 0xfd, 0xba, 0x5d, 0xfc, 0xc1, 0xf9, 0x92, 0xe9, 0x08, 0x08, 0x7e, 0x56, 0x6a, 0x14, 0xde,
];
const PUBLICATION_TARGETS_GUARD_UPDATE_SHA256: [u8; 32] = [
    0x57, 0x10, 0x3b, 0xa2, 0xc3, 0xd7, 0x88, 0xd3, 0x83, 0x3a, 0xba, 0xed, 0xcd, 0xad, 0x49, 0x5e,
    0xce, 0xfe, 0x6e, 0xbd, 0x63, 0x2a, 0x98, 0x14, 0x04, 0x10, 0x86, 0xb9, 0x84, 0x10, 0x72, 0x0c,
];
const PUBLICATION_TARGETS_NO_DELETE_SHA256: [u8; 32] = [
    0x53, 0x97, 0x8a, 0xa5, 0xca, 0x4d, 0xef, 0x0e, 0xc4, 0x75, 0xc4, 0x55, 0xf6, 0x10, 0x43, 0xf7,
    0x1b, 0x10, 0x15, 0x6b, 0x2b, 0x56, 0xe0, 0x6c, 0x50, 0x4a, 0xc7, 0xee, 0x57, 0x3e, 0x74, 0x4e,
];
const PUBLICATION_ATTEMPTS_TABLE_SHA256: [u8; 32] = [
    0x7d, 0xa6, 0xea, 0xbe, 0xfc, 0x07, 0xeb, 0x16, 0xde, 0x5c, 0x47, 0xc9, 0x20, 0xfd, 0x64, 0x76,
    0xa9, 0xe9, 0x8d, 0xce, 0xe9, 0x31, 0x84, 0x45, 0x8d, 0xd2, 0x98, 0xb8, 0x53, 0x52, 0x03, 0x28,
];
const PUBLICATION_ATTEMPTS_NO_UPDATE_SHA256: [u8; 32] = [
    0xc3, 0xe5, 0x51, 0x35, 0x06, 0xad, 0x45, 0xca, 0xea, 0xe5, 0xaa, 0x7e, 0xa2, 0x40, 0xe7, 0x0a,
    0xde, 0x7c, 0xf7, 0x7f, 0x6d, 0x9a, 0x67, 0x76, 0x92, 0x5e, 0x12, 0x06, 0xc4, 0x55, 0xbf, 0x65,
];
const PUBLICATION_ATTEMPTS_NO_DELETE_SHA256: [u8; 32] = [
    0x6d, 0x8a, 0x4e, 0x03, 0x67, 0x52, 0x51, 0x1a, 0x4e, 0xe7, 0xaa, 0x41, 0x0c, 0x31, 0xaa, 0xc9,
    0xd3, 0x5c, 0x42, 0x48, 0xe3, 0x78, 0xfa, 0x39, 0x7c, 0x9b, 0x90, 0xa0, 0xe3, 0x72, 0x19, 0x29,
];

const RECONCILIATION_JOBS_TABLE_SHA256: [u8; 32] = [
    0xe7, 0x0b, 0x5c, 0xb7, 0x26, 0x91, 0x9d, 0x02, 0xef, 0xb3, 0xa6, 0x21, 0x58, 0x48, 0xce, 0x92,
    0x30, 0x88, 0x17, 0x2b, 0x3f, 0xe0, 0xc1, 0x40, 0xee, 0x4a, 0xc7, 0x1b, 0xd0, 0x3c, 0x66, 0xa7,
];
const RECONCILIATION_JOBS_ONE_ACTIVE_SHA256: [u8; 32] = [
    0xf9, 0xbe, 0x78, 0xc6, 0x46, 0x7a, 0x76, 0x2d, 0x38, 0xf4, 0xe0, 0xb4, 0x80, 0xd4, 0x1b, 0x37,
    0x6f, 0x66, 0x8c, 0x21, 0xd2, 0x96, 0xfd, 0x72, 0x12, 0x11, 0x9d, 0x2b, 0x9e, 0x3a, 0x14, 0x3f,
];
const RECONCILIATION_JOBS_SCHEDULE_SHA256: [u8; 32] = [
    0x31, 0xd9, 0xf7, 0x38, 0x3b, 0x87, 0x8d, 0xd8, 0x00, 0xda, 0xe6, 0x1f, 0x40, 0x54, 0xd8, 0xd2,
    0x99, 0xca, 0x93, 0xef, 0x38, 0xbe, 0x5b, 0x63, 0x63, 0x0e, 0x1c, 0x3f, 0x57, 0x2a, 0x1e, 0x75,
];
const RECONCILIATION_JOBS_GUARD_UPDATE_SHA256: [u8; 32] = [
    0xe4, 0x6a, 0x3a, 0xf2, 0x7e, 0xe1, 0xce, 0xe2, 0x4e, 0x29, 0x13, 0x56, 0x51, 0x6c, 0x72, 0x6d,
    0xf0, 0xd1, 0x11, 0x29, 0x01, 0x22, 0x97, 0x5e, 0xe1, 0x79, 0x76, 0xe3, 0x6a, 0x74, 0x13, 0x1b,
];
const RECONCILIATION_JOBS_NO_DELETE_SHA256: [u8; 32] = [
    0x1a, 0x86, 0xb1, 0x70, 0x05, 0x05, 0x4c, 0x27, 0x1b, 0xa4, 0x9a, 0xf2, 0x1a, 0x44, 0x9c, 0x9d,
    0xdc, 0xfb, 0xbc, 0xd9, 0x13, 0xfa, 0x2a, 0x8e, 0x64, 0x6d, 0x5a, 0x6d, 0x22, 0x69, 0x59, 0xa2,
];
const RECONCILIATION_JOBS_SHAPE_GUARD_INSERT_SHA256: [u8; 32] = [
    0x77, 0xf6, 0x83, 0x23, 0x27, 0xce, 0xe0, 0x16, 0xc4, 0x0c, 0x22, 0x6a, 0x61, 0xbe, 0x82, 0xe7,
    0x5b, 0xf0, 0x0b, 0xee, 0x07, 0xb7, 0x03, 0x6f, 0xf7, 0x0d, 0xd2, 0xc9, 0xe0, 0xdb, 0x26, 0xd5,
];
const RECONCILIATION_JOBS_SHAPE_GUARD_UPDATE_SHA256: [u8; 32] = [
    0xf7, 0xbb, 0x8e, 0xb8, 0x1a, 0x6a, 0x1c, 0x19, 0xa9, 0x84, 0x67, 0x51, 0x20, 0x30, 0xe3, 0x9c,
    0xb8, 0x0d, 0x51, 0x6c, 0x1e, 0x33, 0xe7, 0x78, 0x8c, 0xfc, 0x37, 0x9e, 0x4e, 0x9e, 0xf4, 0x61,
];

const RHI_CONFIG_BINDINGS_TABLE_SHA256: [u8; 32] = [
    0x4d, 0x6e, 0x8f, 0xff, 0xda, 0x43, 0xe6, 0xf5, 0x3e, 0x23, 0x77, 0xd2, 0x77, 0xa4, 0x52, 0x9e,
    0x63, 0x3e, 0xaf, 0xb6, 0xea, 0xa2, 0xad, 0xd7, 0x56, 0xde, 0x0d, 0xc9, 0x24, 0xc5, 0x77, 0xeb,
];
const RHI_CONFIG_BINDINGS_GUARD_INSERT_SHA256: [u8; 32] = [
    0xe9, 0xc1, 0x7d, 0x5c, 0x2b, 0xbe, 0x59, 0x20, 0x06, 0xe3, 0x7c, 0x5d, 0x93, 0xdc, 0x33, 0x51,
    0x42, 0x63, 0xb2, 0xd6, 0x1b, 0x67, 0x57, 0x81, 0x54, 0x63, 0x85, 0x6b, 0x3f, 0x9d, 0x9d, 0x25,
];
const RHI_CONFIG_BINDINGS_NO_UPDATE_SHA256: [u8; 32] = [
    0xca, 0xb4, 0xbf, 0x42, 0x05, 0x86, 0x03, 0x78, 0x27, 0x1a, 0xad, 0x5b, 0x57, 0x1f, 0x0e, 0x53,
    0x61, 0xe6, 0xb6, 0x62, 0xc1, 0xa9, 0xc1, 0x38, 0x07, 0x5f, 0xab, 0x07, 0xcd, 0xc8, 0x92, 0xe0,
];
const RHI_CONFIG_BINDINGS_NO_DELETE_SHA256: [u8; 32] = [
    0x5d, 0x26, 0x82, 0xe9, 0xf2, 0xdc, 0x84, 0x97, 0x61, 0xd1, 0xd7, 0x10, 0xdc, 0xda, 0x75, 0xea,
    0x40, 0x6d, 0x10, 0x95, 0xae, 0x1b, 0xc0, 0xad, 0xdf, 0x70, 0x64, 0xec, 0x8b, 0xed, 0x0b, 0x90,
];
const TRADE_MUTATIONS_TABLE_SHA256: [u8; 32] = [
    0x86, 0x4f, 0x45, 0xc0, 0x87, 0xe3, 0x87, 0x71, 0x53, 0xb8, 0x6a, 0xa1, 0x88, 0x6c, 0x73, 0x3e,
    0x56, 0x9f, 0x1b, 0x8b, 0xad, 0x8e, 0x9c, 0xbf, 0xab, 0xc4, 0x84, 0x7d, 0x33, 0x33, 0xea, 0xb5,
];
const TRADE_MUTATIONS_BY_TRADE_SHA256: [u8; 32] = [
    0xcf, 0xd1, 0x79, 0x90, 0xf6, 0x0a, 0x18, 0x94, 0x0a, 0xf9, 0xe6, 0xa8, 0x93, 0xda, 0x9e, 0x9a,
    0xc7, 0x5d, 0x2f, 0x69, 0x28, 0xd9, 0xb6, 0x7c, 0x25, 0x06, 0x64, 0x8d, 0x94, 0x9f, 0x97, 0x2e,
];
const NOSTR_EVENTS_TABLE_SHA256: [u8; 32] = [
    0xcd, 0x08, 0xad, 0x41, 0xb4, 0xd7, 0x88, 0xde, 0xc1, 0x23, 0xc9, 0x83, 0x27, 0x17, 0xb8, 0xab,
    0x26, 0x0d, 0x58, 0x5c, 0x71, 0x56, 0x68, 0x6c, 0xaa, 0xf0, 0x5f, 0x07, 0xba, 0xfc, 0x72, 0x12,
];
const NOSTR_EVENTS_BY_MUTATION_SHA256: [u8; 32] = [
    0x57, 0xd2, 0x8a, 0x14, 0xed, 0x74, 0x84, 0xef, 0xa4, 0x1f, 0x78, 0xe8, 0xbf, 0x6e, 0x85, 0x49,
    0xfa, 0x50, 0x76, 0x65, 0xc7, 0x95, 0x32, 0x34, 0xe0, 0xc5, 0xb4, 0xcb, 0x03, 0xb7, 0xa4, 0x18,
];
const RELAY_OBSERVATIONS_TABLE_SHA256: [u8; 32] = [
    0xb0, 0x4d, 0x44, 0x0b, 0xe0, 0x1b, 0x93, 0x2e, 0xea, 0x53, 0x0b, 0x6a, 0x2e, 0xb2, 0x13, 0xe5,
    0x19, 0xab, 0xbf, 0xc2, 0xd2, 0xff, 0xa3, 0xb8, 0x86, 0x98, 0xb1, 0xc7, 0x28, 0x17, 0x86, 0xfc,
];
const RELAY_OBSERVATIONS_BY_EVENT_SHA256: [u8; 32] = [
    0xdd, 0x69, 0x9f, 0x49, 0x98, 0x67, 0x0f, 0x78, 0xb4, 0x62, 0xcb, 0x1c, 0xd5, 0x17, 0x2a, 0xdb,
    0x8d, 0xa1, 0x68, 0x7c, 0x51, 0x74, 0xb3, 0x34, 0x43, 0xf1, 0xc6, 0x6f, 0x41, 0x03, 0xf7, 0x82,
];
const TRADE_MUTATIONS_NO_UPDATE_SHA256: [u8; 32] = [
    0xd7, 0xeb, 0x61, 0x74, 0x43, 0x6a, 0xe3, 0x46, 0xf8, 0x29, 0x31, 0x37, 0x33, 0x93, 0xc0, 0xe9,
    0x0c, 0xe7, 0xf3, 0x06, 0xd6, 0xad, 0xc9, 0xe7, 0xc1, 0xe0, 0x19, 0x3e, 0xa2, 0x46, 0x7d, 0xbe,
];
const TRADE_MUTATIONS_NO_DELETE_SHA256: [u8; 32] = [
    0xde, 0x61, 0x5b, 0xe4, 0x8f, 0xac, 0xc6, 0xd9, 0xae, 0xb1, 0x11, 0xe7, 0xbb, 0xd3, 0xc7, 0x31,
    0x17, 0x6e, 0xc6, 0xe4, 0x82, 0x61, 0x77, 0xba, 0x1c, 0xb7, 0x49, 0x44, 0x02, 0xb1, 0xba, 0xc4,
];
const NOSTR_EVENTS_NO_UPDATE_SHA256: [u8; 32] = [
    0x3e, 0x6e, 0xec, 0x38, 0x89, 0xd7, 0xfd, 0x25, 0xde, 0x26, 0xe2, 0x03, 0x6e, 0xa5, 0xa5, 0x2a,
    0xd5, 0xa0, 0xeb, 0xd6, 0x04, 0x62, 0x61, 0x08, 0xaa, 0x80, 0x72, 0x56, 0xe9, 0xb6, 0x0a, 0x89,
];
const NOSTR_EVENTS_NO_DELETE_SHA256: [u8; 32] = [
    0x17, 0x6b, 0x15, 0x16, 0xce, 0xe2, 0xf1, 0xfc, 0x62, 0xa7, 0x40, 0x90, 0x01, 0x79, 0x51, 0xae,
    0x15, 0x2c, 0xbe, 0x79, 0x53, 0xd0, 0x7c, 0x86, 0xa0, 0xae, 0xca, 0xd3, 0x19, 0x1e, 0xf5, 0xf6,
];
const RELAY_OBSERVATIONS_NO_UPDATE_SHA256: [u8; 32] = [
    0x6d, 0x20, 0xb3, 0xf0, 0xef, 0x1a, 0x26, 0x55, 0xff, 0xd7, 0x46, 0x5c, 0xce, 0xfa, 0x4c, 0x64,
    0x25, 0x26, 0x64, 0xe2, 0x1b, 0xdc, 0xd8, 0x59, 0xdc, 0xb2, 0xde, 0x15, 0xf0, 0x55, 0xf6, 0xaa,
];
const RELAY_OBSERVATIONS_NO_DELETE_SHA256: [u8; 32] = [
    0xe9, 0xaa, 0x66, 0xff, 0x29, 0xa0, 0x62, 0xc9, 0xf9, 0x97, 0x27, 0x0f, 0x59, 0xad, 0x63, 0x65,
    0xdc, 0x4d, 0x88, 0xc6, 0x59, 0x4b, 0xe5, 0xe5, 0xfe, 0x44, 0xf4, 0x44, 0x6d, 0x00, 0xb7, 0xe0,
];
const RELAY_CHECKPOINTS_TABLE_SHA256: [u8; 32] = [
    0x5f, 0xf7, 0xc3, 0x41, 0xa3, 0x48, 0x37, 0x3e, 0x92, 0xf5, 0x46, 0xe1, 0xff, 0xfd, 0x45, 0x4a,
    0x86, 0x6e, 0x23, 0x2c, 0xff, 0x60, 0x83, 0xbf, 0x3f, 0xfe, 0xc3, 0xfc, 0x65, 0x53, 0x2c, 0xb6,
];
const RELAY_CHECKPOINTS_GUARD_UPDATE_SHA256: [u8; 32] = [
    0x5c, 0xd7, 0x2a, 0xaf, 0x31, 0x2c, 0x17, 0xcf, 0xfa, 0xe4, 0xa8, 0x37, 0x91, 0x3c, 0x5e, 0x92,
    0xf2, 0xaa, 0x31, 0xea, 0x71, 0x3e, 0x86, 0x0e, 0x3a, 0xaa, 0x9f, 0xf7, 0x05, 0xd0, 0xc4, 0x92,
];
const RELAY_CHECKPOINTS_NO_DELETE_SHA256: [u8; 32] = [
    0x8d, 0xb0, 0x54, 0xf7, 0x75, 0x97, 0xd5, 0xe5, 0x42, 0xd0, 0x0c, 0x2e, 0xdc, 0xf2, 0xd9, 0x26,
    0xa9, 0x2b, 0x8e, 0xf5, 0x5a, 0x69, 0x54, 0xb2, 0x01, 0x6b, 0x93, 0x36, 0x48, 0x84, 0xfb, 0x1f,
];
const TRADE_DIRTY_GENERATIONS_TABLE_SHA256: [u8; 32] = [
    0xe9, 0x93, 0x53, 0x2c, 0x08, 0x36, 0xa2, 0x99, 0x40, 0xd2, 0xe3, 0x51, 0x5b, 0x11, 0x34, 0xea,
    0x68, 0xf7, 0xd3, 0x50, 0xe5, 0xbe, 0xdb, 0x3b, 0xc1, 0xb1, 0xa5, 0x6f, 0x7f, 0xa6, 0xe4, 0xd1,
];
const TRADE_DIRTY_GENERATIONS_GUARD_UPDATE_SHA256: [u8; 32] = [
    0x50, 0x31, 0xbc, 0x10, 0x4d, 0x51, 0x66, 0xae, 0xf2, 0xdc, 0x9a, 0x1b, 0xaf, 0x42, 0x0e, 0x47,
    0xc1, 0x6b, 0xa9, 0x70, 0x91, 0x6f, 0x5d, 0xc5, 0x6d, 0xb3, 0xc1, 0x70, 0x4e, 0x76, 0x16, 0xcb,
];
const TRADE_DIRTY_GENERATIONS_NO_DELETE_SHA256: [u8; 32] = [
    0x36, 0x66, 0x3a, 0x1a, 0xd4, 0x65, 0x41, 0x9f, 0x23, 0x1e, 0xe6, 0xcd, 0x1e, 0xd1, 0x6d, 0xa4,
    0x26, 0xac, 0x7d, 0x70, 0xde, 0xc3, 0x67, 0x75, 0x55, 0x62, 0xa8, 0x45, 0x52, 0x86, 0x54, 0x23,
];
const PRESENCE_DESIRED_STATE_TABLE_SHA256: [u8; 32] = [
    0x78, 0x4d, 0xfc, 0x23, 0xd5, 0x05, 0xba, 0x09, 0xb3, 0x73, 0x76, 0xf0, 0x18, 0xaa, 0x03, 0xc6,
    0x3d, 0x98, 0x77, 0x1e, 0xba, 0xd6, 0x73, 0x25, 0x4a, 0x38, 0x46, 0xe3, 0x72, 0xc0, 0x80, 0x40,
];
const PRESENCE_DESIRED_STATE_GUARD_INSERT_SHA256: [u8; 32] = [
    0xe5, 0x55, 0xa5, 0x87, 0xa9, 0x73, 0x2f, 0xae, 0x7c, 0x2d, 0x4e, 0xde, 0xb1, 0x88, 0x93, 0x33,
    0x4a, 0xa4, 0x23, 0x12, 0x22, 0x7a, 0x71, 0xca, 0x6c, 0x2b, 0x38, 0x1f, 0x0b, 0x56, 0xad, 0x8b,
];
const PRESENCE_DESIRED_STATE_GUARD_UPDATE_SHA256: [u8; 32] = [
    0xb3, 0x2a, 0xc0, 0x44, 0xd6, 0x8c, 0x40, 0xfa, 0x3e, 0xbc, 0x57, 0x8a, 0x2d, 0x59, 0xcb, 0x1b,
    0xd6, 0x87, 0xd5, 0x3d, 0xa0, 0xc7, 0xec, 0x99, 0xb5, 0x1e, 0x63, 0xc9, 0x72, 0xeb, 0x27, 0x14,
];
const PRESENCE_DESIRED_STATE_NO_DELETE_SHA256: [u8; 32] = [
    0xca, 0xcd, 0xcf, 0x6f, 0x3b, 0x34, 0xc0, 0x7d, 0x6c, 0xf1, 0x1a, 0xab, 0x03, 0xd5, 0x19, 0x7c,
    0xca, 0x44, 0xab, 0x2e, 0x4f, 0x77, 0x65, 0x29, 0x75, 0x02, 0x4b, 0xbf, 0x1f, 0x04, 0xdc, 0x3f,
];

const PRESENCE_OUTBOX_TABLE_SHA256: [u8; 32] = [
    0x7e, 0x59, 0xa4, 0xb4, 0x54, 0x09, 0x9e, 0x47, 0xf8, 0xad, 0x0d, 0xb8, 0x7f, 0xd2, 0xa0, 0xc5,
    0xf6, 0x69, 0x8d, 0x70, 0xda, 0x96, 0x8d, 0xb0, 0x57, 0x6a, 0xa8, 0x54, 0x28, 0xd1, 0x40, 0xdd,
];
const PRESENCE_OUTBOX_SCHEDULE_SHA256: [u8; 32] = [
    0xed, 0x0e, 0x52, 0xba, 0xc1, 0xa8, 0xc8, 0xe3, 0x25, 0xf0, 0x28, 0xe4, 0x2c, 0x8d, 0x88, 0x8f,
    0x0e, 0x8b, 0x42, 0x63, 0x7c, 0x95, 0x25, 0xf1, 0x02, 0x0c, 0x18, 0x41, 0x3b, 0xf0, 0xf0, 0x41,
];
const PRESENCE_OUTBOX_GUARD_UPDATE_SHA256: [u8; 32] = [
    0x1d, 0x80, 0x93, 0xa8, 0xe7, 0x70, 0x82, 0xc4, 0x2f, 0xb3, 0xe4, 0x79, 0xc6, 0x22, 0x6f, 0x39,
    0x92, 0x88, 0x80, 0xd4, 0x92, 0xa9, 0x6c, 0x04, 0x29, 0x6b, 0xf2, 0xcc, 0x56, 0x69, 0x6e, 0xce,
];
const PRESENCE_OUTBOX_NO_DELETE_SHA256: [u8; 32] = [
    0xc4, 0xe9, 0xb5, 0x5a, 0x02, 0x0b, 0x67, 0x1d, 0x7d, 0x6c, 0x81, 0xf6, 0x99, 0x90, 0x65, 0x52,
    0xd9, 0x5e, 0x97, 0xfd, 0xba, 0xac, 0xad, 0x7b, 0x01, 0xb5, 0x02, 0x3f, 0x6b, 0x5f, 0x79, 0xeb,
];
const PRESENCE_TARGETS_TABLE_SHA256: [u8; 32] = [
    0x1e, 0xfa, 0xc9, 0xe2, 0x8d, 0x55, 0xcf, 0x90, 0xa5, 0x5d, 0xc4, 0x13, 0x1a, 0x8e, 0xcb, 0xc3,
    0x86, 0x2e, 0xff, 0xa9, 0x3d, 0xb3, 0x63, 0xff, 0xed, 0xd4, 0xa1, 0xd6, 0xcd, 0xa4, 0xb7, 0x8c,
];
const PRESENCE_TARGETS_SCHEDULE_SHA256: [u8; 32] = [
    0x6d, 0xbc, 0xf6, 0x25, 0x20, 0x1e, 0x11, 0x2e, 0x1a, 0x54, 0xa7, 0xc8, 0x87, 0xaf, 0xbb, 0xb8,
    0x21, 0x0a, 0xdc, 0xf6, 0xfa, 0xc1, 0xc5, 0x99, 0xe1, 0xaa, 0x6c, 0xa5, 0xc4, 0x56, 0x74, 0x6a,
];
const PRESENCE_TARGETS_GUARD_UPDATE_SHA256: [u8; 32] = [
    0xa0, 0x8f, 0x28, 0x9e, 0x60, 0x32, 0x27, 0xfa, 0x74, 0x34, 0xea, 0x8d, 0x4a, 0xb5, 0x2a, 0x07,
    0x60, 0xdc, 0xd2, 0x8f, 0xe1, 0x35, 0x33, 0x51, 0xa3, 0x5c, 0x3e, 0x6c, 0x73, 0x5d, 0x12, 0x44,
];
const PRESENCE_TARGETS_NO_DELETE_SHA256: [u8; 32] = [
    0x8f, 0x0a, 0x46, 0x61, 0x55, 0x96, 0xa8, 0x33, 0x6f, 0x5f, 0x56, 0xa0, 0x3e, 0xa9, 0xd3, 0x5c,
    0x7d, 0xc3, 0x69, 0xb3, 0xa3, 0x1d, 0x91, 0x0c, 0x23, 0x05, 0xeb, 0xeb, 0xcb, 0x50, 0x71, 0x25,
];
const PRESENCE_ATTEMPTS_TABLE_SHA256: [u8; 32] = [
    0xed, 0x26, 0x46, 0x45, 0x6f, 0x96, 0x45, 0xde, 0x57, 0xcb, 0xef, 0x79, 0x62, 0xd6, 0xfe, 0x43,
    0x9d, 0xae, 0x10, 0xfd, 0x5e, 0x4c, 0x25, 0x90, 0x91, 0x62, 0x58, 0x8f, 0x58, 0x0d, 0x94, 0x9c,
];
const PRESENCE_ATTEMPTS_NO_UPDATE_SHA256: [u8; 32] = [
    0x8b, 0xe2, 0xd1, 0xa5, 0xe6, 0x5d, 0xb9, 0x96, 0xe3, 0x27, 0xb8, 0xee, 0x27, 0x29, 0xa3, 0xe9,
    0x1d, 0xa0, 0x68, 0x0e, 0x16, 0x05, 0x90, 0x77, 0x3a, 0x78, 0x1e, 0x80, 0x00, 0x35, 0xac, 0x44,
];
const PRESENCE_ATTEMPTS_NO_DELETE_SHA256: [u8; 32] = [
    0x8c, 0x59, 0xe5, 0x11, 0x0e, 0xe5, 0xa7, 0x45, 0x3d, 0xde, 0xca, 0x36, 0xc2, 0x87, 0xc3, 0x6e,
    0xbd, 0xf7, 0x74, 0xbb, 0x8d, 0x84, 0xc9, 0xab, 0xd9, 0x76, 0xe2, 0xae, 0x9c, 0xd2, 0x4a, 0x71,
];

macro_rules! rhi_admin_operations_table_sql {
    () => {
        r#"CREATE TABLE rhi_admin_operations (
    operation_id TEXT NOT NULL PRIMARY KEY
        CHECK (length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 128)
        CHECK (substr(operation_id, 1, 1) GLOB '[A-Za-z0-9]')
        CHECK (operation_id NOT GLOB '*[^A-Za-z0-9._:-]*'),
    route TEXT NOT NULL CHECK (length(CAST(route AS BLOB)) BETWEEN 1 AND 128),
    request_sha256 BLOB NOT NULL CHECK (length(request_sha256) = 32),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'completed')),
    response_model BLOB CHECK (response_model IS NULL OR
        length(response_model) BETWEEN 1 AND 8192),
    response_sha256 BLOB CHECK (response_sha256 IS NULL OR
        length(response_sha256) = 32),
    prepared_at_unix_ms INTEGER NOT NULL
        CHECK (prepared_at_unix_ms BETWEEN 0 AND 9223372036854775807),
    completed_at_unix_ms INTEGER
        CHECK (completed_at_unix_ms IS NULL OR
            completed_at_unix_ms BETWEEN prepared_at_unix_ms AND 9223372036854775807),
    expires_at_unix_ms INTEGER
        CHECK (expires_at_unix_ms IS NULL OR
            expires_at_unix_ms BETWEEN completed_at_unix_ms AND 9223372036854775807),
    CHECK ((state = 'prepared' AND response_model IS NULL
            AND response_sha256 IS NULL AND completed_at_unix_ms IS NULL
            AND expires_at_unix_ms IS NULL)
        OR (state = 'completed' AND response_model IS NOT NULL
            AND response_sha256 IS NOT NULL AND completed_at_unix_ms IS NOT NULL
            AND expires_at_unix_ms IS NOT NULL))
) STRICT"#
    };
}

macro_rules! rhi_admin_operations_guard_update_sql {
    () => {
        r#"CREATE TRIGGER rhi_admin_operations_guard_update
BEFORE UPDATE ON rhi_admin_operations
WHEN OLD.state != 'prepared' OR NEW.state != 'completed'
    OR NEW.operation_id != OLD.operation_id OR NEW.route != OLD.route
    OR NEW.request_sha256 != OLD.request_sha256
    OR NEW.prepared_at_unix_ms != OLD.prepared_at_unix_ms
    OR NEW.response_model IS NULL OR NEW.response_sha256 IS NULL
    OR NEW.completed_at_unix_ms IS NULL OR NEW.expires_at_unix_ms IS NULL
BEGIN
    SELECT RAISE(ABORT, 'admin operation transition is invalid');
END"#
    };
}

const CREATE_RHI_ADMIN_OPERATIONS_TABLE_SQL: &str = rhi_admin_operations_table_sql!();
const CREATE_RHI_ADMIN_OPERATIONS_GUARD_UPDATE_SQL: &str = rhi_admin_operations_guard_update_sql!();
const CREATE_RHI_ADMIN_OPERATIONS_MIGRATION_SQL: &str = concat!(
    rhi_admin_operations_table_sql!(),
    ";\n",
    rhi_admin_operations_guard_update_sql!(),
    ";",
);

const RHI_ADMIN_OPERATIONS_TABLE_SHA256: [u8; 32] = [
    0xf7, 0xa6, 0x22, 0x21, 0xc8, 0xec, 0x66, 0x2c, 0x17, 0x14, 0x43, 0x82, 0x2b, 0x11, 0xa9, 0x9b,
    0xc4, 0xde, 0x02, 0x13, 0xa1, 0x9e, 0x12, 0xaa, 0x70, 0x54, 0x7b, 0x7f, 0x9d, 0x50, 0x99, 0x21,
];
const RHI_ADMIN_OPERATIONS_GUARD_UPDATE_SHA256: [u8; 32] = [
    0xac, 0xe5, 0x7c, 0x97, 0xbc, 0xd5, 0xe9, 0xda, 0x0d, 0xfc, 0xe0, 0x23, 0x65, 0x6d, 0xae, 0xda,
    0x96, 0xe5, 0xbf, 0xb6, 0x89, 0x70, 0xa6, 0x06, 0x1b, 0x70, 0x7d, 0x21, 0xec, 0x1f, 0x6b, 0x39,
];

/// Stable classes for invalid embedded RHI catalog definitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiStateCatalogErrorKind {
    MigrationCatalog,
    SchemaCatalog,
    CatalogMismatch,
}

impl RhiStateCatalogErrorKind {
    /// Returns the stable machine-readable classification.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MigrationCatalog => "migration_catalog_invalid",
            Self::SchemaCatalog => "schema_catalog_invalid",
            Self::CatalogMismatch => "state_catalog_mismatch",
        }
    }
}

/// Source-free failure to construct or validate the embedded RHI catalogs.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiStateCatalogError {
    kind: RhiStateCatalogErrorKind,
}

impl RhiStateCatalogError {
    const fn new(kind: RhiStateCatalogErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiStateCatalogErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiStateCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiStateCatalogErrorKind::MigrationCatalog => {
                "RHI migration catalog definition is invalid"
            }
            RhiStateCatalogErrorKind::SchemaCatalog => "RHI schema catalog definition is invalid",
            RhiStateCatalogErrorKind::CatalogMismatch => {
                "RHI state catalogs do not match the governed identity"
            }
        })
    }
}

impl fmt::Debug for RhiStateCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStateCatalogError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiStateCatalogError {}

fn build_rhi_migration_catalog() -> Result<MigrationCatalog, RhiStateCatalogError> {
    let configuration = MigrationDescriptor::sql(
        2,
        "create_configuration_binding_history",
        CREATE_RHI_CONFIG_BINDINGS_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let trade_evidence = MigrationDescriptor::sql(
        3,
        "create_immutable_trade_evidence",
        CREATE_TRADE_EVIDENCE_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let source_checkpoints = MigrationDescriptor::sql(
        4,
        "create_source_checkpoints_and_dirty_generations",
        CREATE_SOURCE_CHECKPOINT_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let reconciliation_jobs = MigrationDescriptor::sql(
        5,
        "create_reconciliation_jobs",
        CREATE_RECONCILIATION_JOBS_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let reconciliation_results = MigrationDescriptor::sql(
        6,
        "create_reconciliation_source_results",
        CREATE_RECONCILIATION_RESULTS_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let report_publication = MigrationDescriptor::sql(
        7,
        "create_reports_and_publication_outbox",
        CREATE_REPORT_PUBLICATION_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let reconciliation_job_shape_guards = MigrationDescriptor::sql(
        8,
        "guard_reconciliation_job_state_shape",
        CREATE_RECONCILIATION_JOB_SHAPE_GUARDS_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let presence_desired_state = MigrationDescriptor::sql(
        9,
        "create_presence_desired_state",
        CREATE_PRESENCE_DESIRED_STATE_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let presence_publication = MigrationDescriptor::sql(
        10,
        "create_presence_publication_workflow",
        CREATE_PRESENCE_PUBLICATION_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let admin_operations = MigrationDescriptor::sql(
        11,
        "create_admin_operation_journal",
        CREATE_RHI_ADMIN_OPERATIONS_MIGRATION_SQL,
        MigrationChecksum::from_bytes(RHI_STATE_SCHEMA_VERSION_11_MIGRATION_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    let catalog = MigrationCatalog::new([
        configuration,
        trade_evidence,
        source_checkpoints,
        reconciliation_jobs,
        reconciliation_results,
        report_publication,
        reconciliation_job_shape_guards,
        presence_desired_state,
        presence_publication,
        admin_operations,
    ])
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    Ok(catalog)
}

/// Constructs the exact ordered RHI migration catalog.
pub fn rhi_migration_catalog() -> Result<MigrationCatalog, RhiStateCatalogError> {
    let catalog = build_rhi_migration_catalog()?;
    if catalog.current_version() != RHI_STATE_SCHEMA_VERSION
        || catalog.descriptors().len() != 10
        || catalog.digest().as_bytes() != &RHI_MIGRATION_CATALOG_SHA256
    {
        return Err(RhiStateCatalogError::new(
            RhiStateCatalogErrorKind::CatalogMismatch,
        ));
    }
    Ok(catalog)
}

/// Constructs the exact RHI schema catalog bound to the migration catalog.
pub fn rhi_schema_catalog() -> Result<SchemaCatalog, RhiStateCatalogError> {
    let migrations = rhi_migration_catalog()?;
    let catalog = build_rhi_schema_catalog(&migrations)?;
    validate_rhi_state_catalogs(&migrations, &catalog)?;
    Ok(catalog)
}

fn build_rhi_schema_catalog(
    migrations: &MigrationCatalog,
) -> Result<SchemaCatalog, RhiStateCatalogError> {
    let version_one = SchemaVersionCatalog::new(
        RHI_STATE_BASE_SCHEMA_VERSION,
        [],
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_1_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_two = SchemaVersionCatalog::new(
        2,
        rhi_config_binding_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_2_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_three = SchemaVersionCatalog::new(
        3,
        rhi_schema_version_three_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_3_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_four = SchemaVersionCatalog::new(
        4,
        rhi_schema_version_four_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_4_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_five = SchemaVersionCatalog::new(
        5,
        rhi_schema_version_five_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_5_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_six = SchemaVersionCatalog::new(
        6,
        rhi_schema_version_six_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_6_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_seven = SchemaVersionCatalog::new(
        7,
        rhi_schema_version_seven_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_7_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_eight = SchemaVersionCatalog::new(
        8,
        rhi_schema_version_eight_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_8_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_nine = SchemaVersionCatalog::new(
        9,
        rhi_schema_version_nine_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_9_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_ten = SchemaVersionCatalog::new(
        10,
        rhi_schema_version_ten_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_10_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let version_eleven = SchemaVersionCatalog::new(
        11,
        rhi_schema_version_eleven_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_11_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let catalog = SchemaCatalog::new(
        migrations,
        [
            version_one,
            version_two,
            version_three,
            version_four,
            version_five,
            version_six,
            version_seven,
            version_eight,
            version_nine,
            version_ten,
            version_eleven,
        ],
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    Ok(catalog)
}

/// Independently validates exact catalog versions, counts, and digests.
pub fn validate_rhi_state_catalogs(
    migrations: &MigrationCatalog,
    schema: &SchemaCatalog,
) -> Result<(), RhiStateCatalogError> {
    let versions = schema.versions();
    let valid = migrations.current_version() == RHI_STATE_SCHEMA_VERSION
        && migrations.descriptors().len() == 10
        && migrations.digest().as_bytes() == &RHI_MIGRATION_CATALOG_SHA256
        && schema.migration_catalog_digest() == migrations.digest()
        && versions.len() == 11
        && versions[0].version() == RHI_STATE_BASE_SCHEMA_VERSION
        && versions[0].object_count() == RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
        && versions[0].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_1_SHA256
        && versions[1].version() == 2
        && versions[1].object_count() == RHI_STATE_SCHEMA_VERSION_2_OBJECT_COUNT
        && versions[1].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_2_SHA256
        && versions[2].version() == 3
        && versions[2].object_count() == RHI_STATE_SCHEMA_VERSION_3_OBJECT_COUNT
        && versions[2].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_3_SHA256
        && versions[3].version() == 4
        && versions[3].object_count() == RHI_STATE_SCHEMA_VERSION_4_OBJECT_COUNT
        && versions[3].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_4_SHA256
        && versions[4].version() == 5
        && versions[4].object_count() == RHI_STATE_SCHEMA_VERSION_5_OBJECT_COUNT
        && versions[4].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_5_SHA256
        && versions[5].version() == 6
        && versions[5].object_count() == RHI_STATE_SCHEMA_VERSION_6_OBJECT_COUNT
        && versions[5].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_6_SHA256
        && versions[6].version() == 7
        && versions[6].object_count() == RHI_STATE_SCHEMA_VERSION_7_OBJECT_COUNT
        && versions[6].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_7_SHA256
        && versions[7].version() == 8
        && versions[7].object_count() == RHI_STATE_SCHEMA_VERSION_8_OBJECT_COUNT
        && versions[7].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_8_SHA256
        && versions[8].version() == 9
        && versions[8].object_count() == RHI_STATE_SCHEMA_VERSION_9_OBJECT_COUNT
        && versions[8].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_9_SHA256
        && versions[9].version() == 10
        && versions[9].object_count() == RHI_STATE_SCHEMA_VERSION_10_OBJECT_COUNT
        && versions[9].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_10_SHA256
        && versions[10].version() == RHI_STATE_SCHEMA_VERSION
        && versions[10].object_count() == RHI_STATE_SCHEMA_VERSION_11_OBJECT_COUNT
        && versions[10].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_11_SHA256
        && schema.digest().as_bytes() == &RHI_STATE_SCHEMA_CATALOG_SHA256;
    if valid {
        Ok(())
    } else {
        Err(RhiStateCatalogError::new(
            RhiStateCatalogErrorKind::CatalogMismatch,
        ))
    }
}

fn rhi_config_binding_objects() -> Result<[SchemaObject; 4], RhiStateCatalogError> {
    Ok([
        SchemaObject::new(
            SchemaObjectKind::Table,
            "rhi_config_bindings",
            "rhi_config_bindings",
            CREATE_RHI_CONFIG_BINDINGS_TABLE_SQL,
            SchemaDigest::from_bytes(RHI_CONFIG_BINDINGS_TABLE_SHA256),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?,
        SchemaObject::new(
            SchemaObjectKind::Trigger,
            "rhi_config_bindings_guard_insert",
            "rhi_config_bindings",
            CREATE_RHI_CONFIG_BINDINGS_GUARD_INSERT_SQL,
            SchemaDigest::from_bytes(RHI_CONFIG_BINDINGS_GUARD_INSERT_SHA256),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?,
        SchemaObject::new(
            SchemaObjectKind::Trigger,
            "rhi_config_bindings_no_update",
            "rhi_config_bindings",
            CREATE_RHI_CONFIG_BINDINGS_NO_UPDATE_SQL,
            SchemaDigest::from_bytes(RHI_CONFIG_BINDINGS_NO_UPDATE_SHA256),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?,
        SchemaObject::new(
            SchemaObjectKind::Trigger,
            "rhi_config_bindings_no_delete",
            "rhi_config_bindings",
            CREATE_RHI_CONFIG_BINDINGS_NO_DELETE_SQL,
            SchemaDigest::from_bytes(RHI_CONFIG_BINDINGS_NO_DELETE_SHA256),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?,
    ])
}

fn rhi_schema_version_three_objects() -> Result<Vec<SchemaObject>, RhiStateCatalogError> {
    let mut objects = rhi_config_binding_objects()?.to_vec();
    objects.extend(rhi_trade_evidence_objects()?);
    Ok(objects)
}

fn rhi_schema_version_four_objects() -> Result<Vec<SchemaObject>, RhiStateCatalogError> {
    let mut objects = rhi_schema_version_three_objects()?;
    objects.extend(rhi_source_checkpoint_objects()?);
    Ok(objects)
}

fn rhi_schema_version_five_objects() -> Result<Vec<SchemaObject>, RhiStateCatalogError> {
    let mut objects = rhi_schema_version_four_objects()?;
    objects.extend(rhi_reconciliation_job_objects()?);
    Ok(objects)
}

fn rhi_schema_version_six_objects() -> Result<Vec<SchemaObject>, RhiStateCatalogError> {
    let mut objects = rhi_schema_version_five_objects()?;
    objects.extend(rhi_reconciliation_result_objects()?);
    Ok(objects)
}

fn rhi_schema_version_seven_objects() -> Result<Vec<SchemaObject>, RhiStateCatalogError> {
    let mut objects = rhi_schema_version_six_objects()?;
    objects.extend(rhi_report_publication_objects()?);
    Ok(objects)
}

fn rhi_schema_version_eight_objects() -> Result<Vec<SchemaObject>, RhiStateCatalogError> {
    let mut objects = rhi_schema_version_seven_objects()?;
    objects.extend(rhi_reconciliation_job_shape_guard_objects()?);
    Ok(objects)
}

fn rhi_schema_version_nine_objects() -> Result<Vec<SchemaObject>, RhiStateCatalogError> {
    let mut objects = rhi_schema_version_eight_objects()?;
    objects.extend(rhi_presence_desired_state_objects()?);
    Ok(objects)
}

fn rhi_schema_version_ten_objects() -> Result<Vec<SchemaObject>, RhiStateCatalogError> {
    let mut objects = rhi_schema_version_nine_objects()?;
    objects.extend(rhi_presence_publication_objects()?);
    Ok(objects)
}

fn rhi_schema_version_eleven_objects() -> Result<Vec<SchemaObject>, RhiStateCatalogError> {
    let mut objects = rhi_schema_version_ten_objects()?;
    objects.extend(rhi_admin_operation_objects()?);
    Ok(objects)
}

fn rhi_admin_operation_objects() -> Result<[SchemaObject; 2], RhiStateCatalogError> {
    let object = |kind, name, sql, digest| {
        SchemaObject::new(
            kind,
            name,
            "rhi_admin_operations",
            sql,
            SchemaDigest::from_bytes(digest),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        object(
            SchemaObjectKind::Table,
            "rhi_admin_operations",
            CREATE_RHI_ADMIN_OPERATIONS_TABLE_SQL,
            RHI_ADMIN_OPERATIONS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "rhi_admin_operations_guard_update",
            CREATE_RHI_ADMIN_OPERATIONS_GUARD_UPDATE_SQL,
            RHI_ADMIN_OPERATIONS_GUARD_UPDATE_SHA256,
        )?,
    ])
}

fn rhi_presence_publication_objects() -> Result<[SchemaObject; 11], RhiStateCatalogError> {
    let object = |kind, name, table_name, sql, digest| {
        SchemaObject::new(
            kind,
            name,
            table_name,
            sql,
            SchemaDigest::from_bytes(digest),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        object(
            SchemaObjectKind::Table,
            "presence_outbox",
            "presence_outbox",
            CREATE_PRESENCE_OUTBOX_TABLE_SQL,
            PRESENCE_OUTBOX_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "presence_outbox_by_schedule",
            "presence_outbox",
            CREATE_PRESENCE_OUTBOX_SCHEDULE_SQL,
            PRESENCE_OUTBOX_SCHEDULE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "presence_outbox_guard_update",
            "presence_outbox",
            CREATE_PRESENCE_OUTBOX_GUARD_UPDATE_SQL,
            PRESENCE_OUTBOX_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "presence_outbox_no_delete",
            "presence_outbox",
            CREATE_PRESENCE_OUTBOX_NO_DELETE_SQL,
            PRESENCE_OUTBOX_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "presence_targets",
            "presence_targets",
            CREATE_PRESENCE_TARGETS_TABLE_SQL,
            PRESENCE_TARGETS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "presence_targets_by_schedule",
            "presence_targets",
            CREATE_PRESENCE_TARGETS_SCHEDULE_SQL,
            PRESENCE_TARGETS_SCHEDULE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "presence_targets_guard_update",
            "presence_targets",
            CREATE_PRESENCE_TARGETS_GUARD_UPDATE_SQL,
            PRESENCE_TARGETS_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "presence_targets_no_delete",
            "presence_targets",
            CREATE_PRESENCE_TARGETS_NO_DELETE_SQL,
            PRESENCE_TARGETS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "presence_attempts",
            "presence_attempts",
            CREATE_PRESENCE_ATTEMPTS_TABLE_SQL,
            PRESENCE_ATTEMPTS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "presence_attempts_no_update",
            "presence_attempts",
            CREATE_PRESENCE_ATTEMPTS_NO_UPDATE_SQL,
            PRESENCE_ATTEMPTS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "presence_attempts_no_delete",
            "presence_attempts",
            CREATE_PRESENCE_ATTEMPTS_NO_DELETE_SQL,
            PRESENCE_ATTEMPTS_NO_DELETE_SHA256,
        )?,
    ])
}

fn rhi_presence_desired_state_objects() -> Result<[SchemaObject; 4], RhiStateCatalogError> {
    let object = |kind, name, sql, digest| {
        SchemaObject::new(
            kind,
            name,
            "presence_desired_state",
            sql,
            SchemaDigest::from_bytes(digest),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        object(
            SchemaObjectKind::Table,
            "presence_desired_state",
            CREATE_PRESENCE_DESIRED_STATE_TABLE_SQL,
            PRESENCE_DESIRED_STATE_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "presence_desired_state_guard_insert",
            CREATE_PRESENCE_DESIRED_STATE_GUARD_INSERT_SQL,
            PRESENCE_DESIRED_STATE_GUARD_INSERT_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "presence_desired_state_guard_update",
            CREATE_PRESENCE_DESIRED_STATE_GUARD_UPDATE_SQL,
            PRESENCE_DESIRED_STATE_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "presence_desired_state_no_delete",
            CREATE_PRESENCE_DESIRED_STATE_NO_DELETE_SQL,
            PRESENCE_DESIRED_STATE_NO_DELETE_SHA256,
        )?,
    ])
}

fn rhi_reconciliation_job_shape_guard_objects() -> Result<[SchemaObject; 2], RhiStateCatalogError> {
    let object = |name, sql, digest| {
        SchemaObject::new(
            SchemaObjectKind::Trigger,
            name,
            "reconciliation_jobs",
            sql,
            SchemaDigest::from_bytes(digest),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        object(
            "reconciliation_jobs_shape_guard_insert",
            CREATE_RECONCILIATION_JOBS_SHAPE_GUARD_INSERT_SQL,
            RECONCILIATION_JOBS_SHAPE_GUARD_INSERT_SHA256,
        )?,
        object(
            "reconciliation_jobs_shape_guard_update",
            CREATE_RECONCILIATION_JOBS_SHAPE_GUARD_UPDATE_SQL,
            RECONCILIATION_JOBS_SHAPE_GUARD_UPDATE_SHA256,
        )?,
    ])
}

fn rhi_report_publication_objects() -> Result<[SchemaObject; 24], RhiStateCatalogError> {
    let object = |kind, name, table_name, sql, digest| {
        SchemaObject::new(
            kind,
            name,
            table_name,
            sql,
            SchemaDigest::from_bytes(digest),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        object(
            SchemaObjectKind::Table,
            "evidence_manifests",
            "evidence_manifests",
            CREATE_EVIDENCE_MANIFESTS_TABLE_SQL,
            EVIDENCE_MANIFESTS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "evidence_manifests_no_update",
            "evidence_manifests",
            CREATE_EVIDENCE_MANIFESTS_NO_UPDATE_SQL,
            EVIDENCE_MANIFESTS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "evidence_manifests_no_delete",
            "evidence_manifests",
            CREATE_EVIDENCE_MANIFESTS_NO_DELETE_SQL,
            EVIDENCE_MANIFESTS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "trade_projections",
            "trade_projections",
            CREATE_TRADE_PROJECTIONS_TABLE_SQL,
            TRADE_PROJECTIONS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "trade_projections_no_update",
            "trade_projections",
            CREATE_TRADE_PROJECTIONS_NO_UPDATE_SQL,
            TRADE_PROJECTIONS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "trade_projections_no_delete",
            "trade_projections",
            CREATE_TRADE_PROJECTIONS_NO_DELETE_SQL,
            TRADE_PROJECTIONS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "attestation_reports",
            "attestation_reports",
            CREATE_ATTESTATION_REPORTS_TABLE_SQL,
            ATTESTATION_REPORTS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "attestation_reports_one_successor",
            "attestation_reports",
            CREATE_ATTESTATION_REPORTS_SUPERSESSION_SQL,
            ATTESTATION_REPORTS_SUPERSESSION_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "attestation_reports_no_update",
            "attestation_reports",
            CREATE_ATTESTATION_REPORTS_NO_UPDATE_SQL,
            ATTESTATION_REPORTS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "attestation_reports_no_delete",
            "attestation_reports",
            CREATE_ATTESTATION_REPORTS_NO_DELETE_SQL,
            ATTESTATION_REPORTS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "signed_attestation_events",
            "signed_attestation_events",
            CREATE_SIGNED_ATTESTATION_EVENTS_TABLE_SQL,
            SIGNED_ATTESTATION_EVENTS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "signed_attestation_events_no_update",
            "signed_attestation_events",
            CREATE_SIGNED_ATTESTATION_EVENTS_NO_UPDATE_SQL,
            SIGNED_ATTESTATION_EVENTS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "signed_attestation_events_no_delete",
            "signed_attestation_events",
            CREATE_SIGNED_ATTESTATION_EVENTS_NO_DELETE_SQL,
            SIGNED_ATTESTATION_EVENTS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "publication_outbox",
            "publication_outbox",
            CREATE_PUBLICATION_OUTBOX_TABLE_SQL,
            PUBLICATION_OUTBOX_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "publication_outbox_by_schedule",
            "publication_outbox",
            CREATE_PUBLICATION_OUTBOX_SCHEDULE_SQL,
            PUBLICATION_OUTBOX_SCHEDULE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "publication_outbox_guard_update",
            "publication_outbox",
            CREATE_PUBLICATION_OUTBOX_GUARD_UPDATE_SQL,
            PUBLICATION_OUTBOX_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "publication_outbox_no_delete",
            "publication_outbox",
            CREATE_PUBLICATION_OUTBOX_NO_DELETE_SQL,
            PUBLICATION_OUTBOX_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "publication_targets",
            "publication_targets",
            CREATE_PUBLICATION_TARGETS_TABLE_SQL,
            PUBLICATION_TARGETS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "publication_targets_by_schedule",
            "publication_targets",
            CREATE_PUBLICATION_TARGETS_SCHEDULE_SQL,
            PUBLICATION_TARGETS_SCHEDULE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "publication_targets_guard_update",
            "publication_targets",
            CREATE_PUBLICATION_TARGETS_GUARD_UPDATE_SQL,
            PUBLICATION_TARGETS_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "publication_targets_no_delete",
            "publication_targets",
            CREATE_PUBLICATION_TARGETS_NO_DELETE_SQL,
            PUBLICATION_TARGETS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "publication_attempts",
            "publication_attempts",
            CREATE_PUBLICATION_ATTEMPTS_TABLE_SQL,
            PUBLICATION_ATTEMPTS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "publication_attempts_no_update",
            "publication_attempts",
            CREATE_PUBLICATION_ATTEMPTS_NO_UPDATE_SQL,
            PUBLICATION_ATTEMPTS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "publication_attempts_no_delete",
            "publication_attempts",
            CREATE_PUBLICATION_ATTEMPTS_NO_DELETE_SQL,
            PUBLICATION_ATTEMPTS_NO_DELETE_SHA256,
        )?,
    ])
}

fn rhi_reconciliation_result_objects() -> Result<[SchemaObject; 6], RhiStateCatalogError> {
    let object = |kind, name, table_name, sql, digest| {
        SchemaObject::new(
            kind,
            name,
            table_name,
            sql,
            SchemaDigest::from_bytes(digest),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        object(
            SchemaObjectKind::Table,
            "evidence_reconciliations",
            "evidence_reconciliations",
            CREATE_EVIDENCE_RECONCILIATIONS_TABLE_SQL,
            EVIDENCE_RECONCILIATIONS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "evidence_reconciliations_no_update",
            "evidence_reconciliations",
            CREATE_EVIDENCE_RECONCILIATIONS_NO_UPDATE_SQL,
            EVIDENCE_RECONCILIATIONS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "evidence_reconciliations_no_delete",
            "evidence_reconciliations",
            CREATE_EVIDENCE_RECONCILIATIONS_NO_DELETE_SQL,
            EVIDENCE_RECONCILIATIONS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "evidence_reconciliation_sources",
            "evidence_reconciliation_sources",
            CREATE_EVIDENCE_RECONCILIATION_SOURCES_TABLE_SQL,
            EVIDENCE_RECONCILIATION_SOURCES_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "evidence_reconciliation_sources_no_update",
            "evidence_reconciliation_sources",
            CREATE_EVIDENCE_RECONCILIATION_SOURCES_NO_UPDATE_SQL,
            EVIDENCE_RECONCILIATION_SOURCES_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "evidence_reconciliation_sources_no_delete",
            "evidence_reconciliation_sources",
            CREATE_EVIDENCE_RECONCILIATION_SOURCES_NO_DELETE_SQL,
            EVIDENCE_RECONCILIATION_SOURCES_NO_DELETE_SHA256,
        )?,
    ])
}

fn rhi_reconciliation_job_objects() -> Result<[SchemaObject; 5], RhiStateCatalogError> {
    let object = |kind, name, table_name, sql, digest| {
        SchemaObject::new(
            kind,
            name,
            table_name,
            sql,
            SchemaDigest::from_bytes(digest),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        object(
            SchemaObjectKind::Table,
            "reconciliation_jobs",
            "reconciliation_jobs",
            CREATE_RECONCILIATION_JOBS_TABLE_SQL,
            RECONCILIATION_JOBS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "reconciliation_jobs_one_active_per_trade",
            "reconciliation_jobs",
            CREATE_RECONCILIATION_JOBS_ONE_ACTIVE_SQL,
            RECONCILIATION_JOBS_ONE_ACTIVE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "reconciliation_jobs_by_schedule",
            "reconciliation_jobs",
            CREATE_RECONCILIATION_JOBS_SCHEDULE_SQL,
            RECONCILIATION_JOBS_SCHEDULE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "reconciliation_jobs_guard_update",
            "reconciliation_jobs",
            CREATE_RECONCILIATION_JOBS_GUARD_UPDATE_SQL,
            RECONCILIATION_JOBS_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "reconciliation_jobs_no_delete",
            "reconciliation_jobs",
            CREATE_RECONCILIATION_JOBS_NO_DELETE_SQL,
            RECONCILIATION_JOBS_NO_DELETE_SHA256,
        )?,
    ])
}

fn rhi_source_checkpoint_objects() -> Result<[SchemaObject; 6], RhiStateCatalogError> {
    let object = |kind, name, table_name, sql, digest| {
        SchemaObject::new(
            kind,
            name,
            table_name,
            sql,
            SchemaDigest::from_bytes(digest),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        object(
            SchemaObjectKind::Table,
            "relay_checkpoints",
            "relay_checkpoints",
            CREATE_RELAY_CHECKPOINTS_TABLE_SQL,
            RELAY_CHECKPOINTS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "relay_checkpoints_guard_update",
            "relay_checkpoints",
            CREATE_RELAY_CHECKPOINTS_GUARD_UPDATE_SQL,
            RELAY_CHECKPOINTS_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "relay_checkpoints_no_delete",
            "relay_checkpoints",
            CREATE_RELAY_CHECKPOINTS_NO_DELETE_SQL,
            RELAY_CHECKPOINTS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "trade_dirty_generations",
            "trade_dirty_generations",
            CREATE_TRADE_DIRTY_GENERATIONS_TABLE_SQL,
            TRADE_DIRTY_GENERATIONS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "trade_dirty_generations_guard_update",
            "trade_dirty_generations",
            CREATE_TRADE_DIRTY_GENERATIONS_GUARD_UPDATE_SQL,
            TRADE_DIRTY_GENERATIONS_GUARD_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "trade_dirty_generations_no_delete",
            "trade_dirty_generations",
            CREATE_TRADE_DIRTY_GENERATIONS_NO_DELETE_SQL,
            TRADE_DIRTY_GENERATIONS_NO_DELETE_SHA256,
        )?,
    ])
}

fn rhi_trade_evidence_objects() -> Result<[SchemaObject; 12], RhiStateCatalogError> {
    let object = |kind, name, table_name, sql, digest| {
        SchemaObject::new(
            kind,
            name,
            table_name,
            sql,
            SchemaDigest::from_bytes(digest),
        )
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))
    };
    Ok([
        object(
            SchemaObjectKind::Table,
            "trade_mutations",
            "trade_mutations",
            CREATE_TRADE_MUTATIONS_TABLE_SQL,
            TRADE_MUTATIONS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "trade_mutations_by_trade",
            "trade_mutations",
            CREATE_TRADE_MUTATIONS_BY_TRADE_SQL,
            TRADE_MUTATIONS_BY_TRADE_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "nostr_events",
            "nostr_events",
            CREATE_NOSTR_EVENTS_TABLE_SQL,
            NOSTR_EVENTS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "nostr_events_by_mutation",
            "nostr_events",
            CREATE_NOSTR_EVENTS_BY_MUTATION_SQL,
            NOSTR_EVENTS_BY_MUTATION_SHA256,
        )?,
        object(
            SchemaObjectKind::Table,
            "relay_observations",
            "relay_observations",
            CREATE_RELAY_OBSERVATIONS_TABLE_SQL,
            RELAY_OBSERVATIONS_TABLE_SHA256,
        )?,
        object(
            SchemaObjectKind::Index,
            "relay_observations_by_event",
            "relay_observations",
            CREATE_RELAY_OBSERVATIONS_BY_EVENT_SQL,
            RELAY_OBSERVATIONS_BY_EVENT_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "trade_mutations_no_update",
            "trade_mutations",
            CREATE_TRADE_MUTATIONS_NO_UPDATE_SQL,
            TRADE_MUTATIONS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "trade_mutations_no_delete",
            "trade_mutations",
            CREATE_TRADE_MUTATIONS_NO_DELETE_SQL,
            TRADE_MUTATIONS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "nostr_events_no_update",
            "nostr_events",
            CREATE_NOSTR_EVENTS_NO_UPDATE_SQL,
            NOSTR_EVENTS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "nostr_events_no_delete",
            "nostr_events",
            CREATE_NOSTR_EVENTS_NO_DELETE_SQL,
            NOSTR_EVENTS_NO_DELETE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "relay_observations_no_update",
            "relay_observations",
            CREATE_RELAY_OBSERVATIONS_NO_UPDATE_SQL,
            RELAY_OBSERVATIONS_NO_UPDATE_SHA256,
        )?,
        object(
            SchemaObjectKind::Trigger,
            "relay_observations_no_delete",
            "relay_observations",
            CREATE_RELAY_OBSERVATIONS_NO_DELETE_SQL,
            RELAY_OBSERVATIONS_NO_DELETE_SHA256,
        )?,
    ])
}
