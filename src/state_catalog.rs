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
pub const RHI_STATE_SCHEMA_VERSION: u32 = 3;

/// The shared metadata and migration-ledger objects present at schema v1.
pub const RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT: u32 = 6;

/// The shared objects plus the bounded append-only RHI configuration history.
pub const RHI_STATE_SCHEMA_VERSION_2_OBJECT_COUNT: u32 = 10;

/// The shared objects, configuration history, and immutable trade evidence.
pub const RHI_STATE_SCHEMA_VERSION_3_OBJECT_COUNT: u32 = 22;

/// SHA-256 identity of the ordered migration catalog rooted at schema v1.
pub const RHI_MIGRATION_CATALOG_SHA256: [u8; 32] = [
    0x14, 0x04, 0x60, 0x48, 0xb4, 0x68, 0x83, 0x6f, 0x26, 0x02, 0xec, 0x51, 0xe5, 0x38, 0xf2, 0xa9,
    0x8b, 0x71, 0xc9, 0x45, 0xf8, 0x3d, 0x93, 0x3d, 0xcc, 0xb8, 0x60, 0x3b, 0x84, 0xf8, 0x65, 0xf0,
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

/// SHA-256 identity of the schema catalog bound to the migration catalog.
pub const RHI_STATE_SCHEMA_CATALOG_SHA256: [u8; 32] = [
    0x13, 0x25, 0xa4, 0x1b, 0x90, 0xab, 0xfc, 0x7d, 0x52, 0x3b, 0xbf, 0xe8, 0x35, 0x00, 0xa1, 0xb1,
    0xa7, 0x3e, 0x49, 0x2c, 0xc9, 0x30, 0xd6, 0xea, 0xd6, 0xc7, 0x1e, 0x29, 0xd5, 0x44, 0x74, 0x36,
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

/// Constructs the exact ordered RHI migration catalog.
pub fn rhi_migration_catalog() -> Result<MigrationCatalog, RhiStateCatalogError> {
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
    let catalog = MigrationCatalog::new([configuration, trade_evidence])
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    if catalog.current_version() != RHI_STATE_SCHEMA_VERSION
        || catalog.descriptors().len() != 2
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
        RHI_STATE_SCHEMA_VERSION,
        rhi_schema_version_three_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_3_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let catalog = SchemaCatalog::new(&migrations, [version_one, version_two, version_three])
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    validate_rhi_state_catalogs(&migrations, &catalog)?;
    Ok(catalog)
}

/// Independently validates exact catalog versions, counts, and digests.
pub fn validate_rhi_state_catalogs(
    migrations: &MigrationCatalog,
    schema: &SchemaCatalog,
) -> Result<(), RhiStateCatalogError> {
    let versions = schema.versions();
    let valid = migrations.current_version() == RHI_STATE_SCHEMA_VERSION
        && migrations.descriptors().len() == 2
        && migrations.digest().as_bytes() == &RHI_MIGRATION_CATALOG_SHA256
        && schema.migration_catalog_digest() == migrations.digest()
        && versions.len() == 3
        && versions[0].version() == RHI_STATE_BASE_SCHEMA_VERSION
        && versions[0].object_count() == RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
        && versions[0].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_1_SHA256
        && versions[1].version() == 2
        && versions[1].object_count() == RHI_STATE_SCHEMA_VERSION_2_OBJECT_COUNT
        && versions[1].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_2_SHA256
        && versions[2].version() == RHI_STATE_SCHEMA_VERSION
        && versions[2].object_count() == RHI_STATE_SCHEMA_VERSION_3_OBJECT_COUNT
        && versions[2].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_3_SHA256
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
