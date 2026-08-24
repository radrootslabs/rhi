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
    RHI_STATE_SCHEMA_VERSION_3_SHA256, RHI_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_4_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_4_SHA256,
    RHI_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_5_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_5_SHA256, RhiStateCatalogErrorKind, rhi_migration_catalog,
    rhi_schema_catalog, validate_rhi_state_catalogs,
};

const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn schema_v1_through_v5_catalogs_have_exact_literal_identities() {
    let migrations = rhi_migration_catalog().expect("RHI migration catalog");
    let schema = rhi_schema_catalog().expect("RHI schema catalog");

    assert_eq!(RHI_STATE_BASE_SCHEMA_VERSION, 1);
    assert_eq!(RHI_STATE_SCHEMA_VERSION, 5);
    assert_eq!(migrations.descriptors().len(), 4);
    assert_eq!(migrations.current_version(), 5);
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
    assert_eq!(migrations.descriptors()[2].target_version(), 4);
    assert_eq!(
        migrations.descriptors()[2].name().as_str(),
        "create_source_checkpoints_and_dirty_generations"
    );
    assert_eq!(
        migrations.descriptors()[2].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256
    );
    assert_eq!(migrations.descriptors()[3].target_version(), 5);
    assert_eq!(
        migrations.descriptors()[3].name().as_str(),
        "create_reconciliation_jobs"
    );
    assert_eq!(
        migrations.descriptors()[3].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256
    );
    assert_eq!(
        migrations.digest().as_bytes(),
        &RHI_MIGRATION_CATALOG_SHA256
    );

    assert_eq!(schema.versions().len(), 5);
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
    let version = schema.versions()[3];
    assert_eq!(version.version(), 4);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_4_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 28);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_4_SHA256
    );
    let version = schema.versions()[4];
    assert_eq!(version.version(), 5);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_5_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 33);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_5_SHA256
    );
    assert_eq!(schema.digest().as_bytes(), &RHI_STATE_SCHEMA_CATALOG_SHA256);
    assert_eq!(schema.migration_catalog_digest(), migrations.digest());
    validate_rhi_state_catalogs(&migrations, &schema).expect("exact catalogs");

    assert_eq!(
        lower_hex(&RHI_MIGRATION_CATALOG_SHA256),
        "4ed32a5a71f5bf454262a9082ad74d0d6a13a556054659ac7b9d877259b816d8"
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
        lower_hex(&RHI_STATE_SCHEMA_VERSION_4_MIGRATION_SHA256),
        "2441f7c4c11594c6fde787dbb94e44ba00b72d2c979b0e7fd3c733eae9144d78"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_4_SHA256),
        "9ca78a54b0ea2013e7aa70d09beadcfb6cdde07c40429dffe91cb83c2a425cea"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_5_MIGRATION_SHA256),
        "8275ffb3d5c9fa0c7648f89e8bfb92877b0dcd5ef3bf0b5254b7ffd2580bd45d"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_5_SHA256),
        "eef67b48400dee234f6c36d422551c7e9983150b887f264250f9c87a1a313e60"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_CATALOG_SHA256),
        "0d2c595a3ca3fbc9b3bf6bfc6168a194ac788d4931c46200e2f1379ebb523ece"
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
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(4, [version_two_object()]).expect("v4 digest");
    let version_four = SchemaVersionCatalog::new(4, [version_two_object()], snapshot_digest)
        .expect("version four");
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(5, [version_two_object()]).expect("v5 digest");
    let version_five = SchemaVersionCatalog::new(5, [version_two_object()], snapshot_digest)
        .expect("version five");
    let schema = SchemaCatalog::new(
        &exact_migrations,
        [
            version_one,
            version_two,
            version_three,
            version_four,
            version_five,
        ],
    )
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
    let version_four_digest =
        SchemaVersionCatalog::computed_digest(4, [secret_object()]).expect("v4 digest");
    let version_four =
        SchemaVersionCatalog::new(4, [secret_object()], version_four_digest).expect("version four");
    let version_five_digest =
        SchemaVersionCatalog::computed_digest(5, [secret_object()]).expect("v5 digest");
    let version_five =
        SchemaVersionCatalog::new(5, [secret_object()], version_five_digest).expect("version five");
    let schema = SchemaCatalog::new(
        &migrations,
        [
            version_one,
            version_two,
            version_three,
            version_four,
            version_five,
        ],
    )
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
        "radroots_service_sqlite = { git = \"https://github.com/radrootslabs/lib\", rev = \"21b11e7a5120ea949f7ad0838c746873fc73aac2\", version = \"=0.1.0-alpha\" }"
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
