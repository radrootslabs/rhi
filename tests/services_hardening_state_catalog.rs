#![forbid(unsafe_code)]

use std::error::Error;

use radroots_service_sqlite::{
    MigrationCatalog, MigrationChecksum, MigrationDescriptor, SchemaCatalog, SchemaObject,
    SchemaObjectKind, SchemaVersionCatalog,
};
use rhi::{
    RHI_MIGRATION_CATALOG_SHA256, RHI_STATE_BASE_SCHEMA_VERSION, RHI_STATE_SCHEMA_CATALOG_SHA256,
    RHI_STATE_SCHEMA_VERSION, RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_1_SHA256, RHI_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_2_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_2_SHA256,
    RHI_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_3_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_3_SHA256, RhiStateCatalogErrorKind, rhi_migration_catalog,
    rhi_schema_catalog, validate_rhi_state_catalogs,
};

const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn schema_v1_through_v3_catalogs_have_exact_literal_identities() {
    let migrations = rhi_migration_catalog().expect("RHI migration catalog");
    let schema = rhi_schema_catalog().expect("RHI schema catalog");

    assert_eq!(RHI_STATE_BASE_SCHEMA_VERSION, 1);
    assert_eq!(RHI_STATE_SCHEMA_VERSION, 3);
    assert_eq!(migrations.descriptors().len(), 2);
    assert_eq!(migrations.current_version(), 3);
    assert_eq!(migrations.descriptors()[0].target_version(), 2);
    assert_eq!(
        migrations.descriptors()[0].name().as_str(),
        "create_configuration_binding_history"
    );
    assert_eq!(
        migrations.descriptors()[0].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256
    );
    assert_eq!(migrations.descriptors()[1].target_version(), 3);
    assert_eq!(
        migrations.descriptors()[1].name().as_str(),
        "create_immutable_trade_evidence"
    );
    assert_eq!(
        migrations.descriptors()[1].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256
    );
    assert_eq!(
        migrations.digest().as_bytes(),
        &RHI_MIGRATION_CATALOG_SHA256
    );

    assert_eq!(schema.versions().len(), 3);
    let version = schema.versions()[0];
    assert_eq!(version.version(), 1);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 6);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_1_SHA256
    );
    let version = schema.versions()[1];
    assert_eq!(version.version(), 2);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_2_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 10);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_2_SHA256
    );
    let version = schema.versions()[2];
    assert_eq!(version.version(), 3);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_3_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 22);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_3_SHA256
    );
    assert_eq!(schema.digest().as_bytes(), &RHI_STATE_SCHEMA_CATALOG_SHA256);
    assert_eq!(schema.migration_catalog_digest(), migrations.digest());
    validate_rhi_state_catalogs(&migrations, &schema).expect("exact catalogs");

    assert_eq!(
        lower_hex(&RHI_MIGRATION_CATALOG_SHA256),
        "14046048b468836f2602ec51e538f2a98b71c945f83d933dccb8603b84f865f0"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_1_SHA256),
        "94dc66fbca601679615c055229dc0db6119f5bd92b04390c67f698a036fa78ae"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_2_MIGRATION_SHA256),
        "a2c1aa53f7feee0385e774de20e072520f4926c559c6421aab590e92ba144c55"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_2_SHA256),
        "bccbf1e62fe7644c9c377205b25a92298e088b8c26d15ba45133ca5e9b7315a9"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_3_MIGRATION_SHA256),
        "07b098c393140afec222fce76ec668698d50f1d23785856873e30445af1a013f"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_3_SHA256),
        "fd96226405ab68655aee00f683f6023c7aab2dbd23feadac165333490d6f0ad5"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_CATALOG_SHA256),
        "1325a41b90abfc7d523bbfe83500a1b1a73e492cc930d6ead6c71e29d5447436"
    );
}

#[test]
fn independent_validator_rejects_migration_or_schema_drift() {
    const SQL: &str = "CREATE TABLE unexpected (value INTEGER NOT NULL) STRICT";
    let migration =
        MigrationDescriptor::sql(2, "unexpected_schema", SQL, MigrationChecksum::for_sql(SQL))
            .expect("valid drift fixture");
    let migrations = MigrationCatalog::new([migration]).expect("drift migration catalog");
    let expected_schema = rhi_schema_catalog().expect("expected schema");
    assert_eq!(
        validate_rhi_state_catalogs(&migrations, &expected_schema)
            .expect_err("migration drift")
            .kind(),
        RhiStateCatalogErrorKind::CatalogMismatch
    );

    let exact_migrations = rhi_migration_catalog().expect("exact migrations");
    let object_digest =
        SchemaObject::computed_digest(SchemaObjectKind::Table, "unexpected", "unexpected", SQL)
            .expect("object digest");
    let object = SchemaObject::new(
        SchemaObjectKind::Table,
        "unexpected",
        "unexpected",
        SQL,
        object_digest,
    )
    .expect("schema object");
    let version_one = SchemaVersionCatalog::new(
        1,
        [],
        radroots_service_sqlite::SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_1_SHA256),
    )
    .expect("version one");
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(2, [object.clone()]).expect("snapshot digest");
    let version_two = SchemaVersionCatalog::new(2, [object], snapshot_digest).expect("version two");
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(3, [version_two_object()]).expect("v3 digest");
    let version_three = SchemaVersionCatalog::new(3, [version_two_object()], snapshot_digest)
        .expect("version three");
    let schema = SchemaCatalog::new(&exact_migrations, [version_one, version_two, version_three])
        .expect("drift schema catalog");
    assert_eq!(
        validate_rhi_state_catalogs(&exact_migrations, &schema)
            .expect_err("schema drift")
            .kind(),
        RhiStateCatalogErrorKind::CatalogMismatch
    );
}

#[test]
fn catalog_errors_are_stable_source_free_and_redacted() {
    let migrations = rhi_migration_catalog().expect("migration catalog");
    let object_digest = SchemaObject::computed_digest(
        SchemaObjectKind::Table,
        "secret_table",
        "secret_table",
        "secret SQL text",
    )
    .expect("object digest");
    let object = SchemaObject::new(
        SchemaObjectKind::Table,
        "secret_table",
        "secret_table",
        "secret SQL text",
        object_digest,
    )
    .expect("object");
    let version_one = SchemaVersionCatalog::new(
        1,
        [],
        radroots_service_sqlite::SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_1_SHA256),
    )
    .expect("version one");
    let snapshot =
        SchemaVersionCatalog::computed_digest(2, [object.clone()]).expect("snapshot digest");
    let version_two = SchemaVersionCatalog::new(2, [object], snapshot).expect("version two");
    let version_three_digest =
        SchemaVersionCatalog::computed_digest(3, [secret_object()]).expect("v3 digest");
    let version_three = SchemaVersionCatalog::new(3, [secret_object()], version_three_digest)
        .expect("version three");
    let schema = SchemaCatalog::new(&migrations, [version_one, version_two, version_three])
        .expect("schema catalog");
    let error = validate_rhi_state_catalogs(&migrations, &schema).expect_err("mismatch");

    assert_eq!(error.kind(), RhiStateCatalogErrorKind::CatalogMismatch);
    assert_eq!(error.code(), "state_catalog_mismatch");
    assert!(Error::source(&error).is_none());
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains(&lower_hex(snapshot.as_bytes())));
}

fn version_two_object() -> SchemaObject {
    const SQL: &str = "CREATE TABLE unexpected (value INTEGER NOT NULL) STRICT";
    let digest =
        SchemaObject::computed_digest(SchemaObjectKind::Table, "unexpected", "unexpected", SQL)
            .expect("object digest");
    SchemaObject::new(
        SchemaObjectKind::Table,
        "unexpected",
        "unexpected",
        SQL,
        digest,
    )
    .expect("schema object")
}

fn secret_object() -> SchemaObject {
    let digest = SchemaObject::computed_digest(
        SchemaObjectKind::Table,
        "secret_table",
        "secret_table",
        "secret SQL text",
    )
    .expect("object digest");
    SchemaObject::new(
        SchemaObjectKind::Table,
        "secret_table",
        "secret_table",
        "secret SQL text",
        digest,
    )
    .expect("object")
}

#[test]
fn catalog_source_is_pure_pinned_and_uses_only_the_shared_authority() {
    assert!(MANIFEST.contains(
        "radroots_service_sqlite = { git = \"https://github.com/radrootslabs/lib\", rev = \"79d7818c8fe22a425f9524b884ddf59d25f0ef89\", version = \"=0.1.0-alpha\" }"
    ));
    assert!(LIB_SOURCE.contains("mod state_catalog;"));
    assert!(!LIB_SOURCE.contains("pub mod state_catalog;"));
    assert!(CATALOG_SOURCE.contains("MigrationDescriptor::sql("));
    assert!(CATALOG_SOURCE.contains("CREATE TABLE rhi_config_bindings"));
    assert!(CATALOG_SOURCE.contains("SchemaDigest::from_bytes("));
    assert!(!CATALOG_SOURCE.contains("computed_digest"));
    for forbidden in [
        "sqlx::",
        "rusqlite",
        "libsqlite3_sys",
        "raw_sql",
        "std::fs",
        "std::path",
        "Connection",
        "Transaction",
    ] {
        assert!(
            !CATALOG_SOURCE.contains(forbidden),
            "found forbidden catalog authority `{forbidden}`"
        );
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
