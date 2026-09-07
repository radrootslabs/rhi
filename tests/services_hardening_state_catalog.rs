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
    RHI_STATE_SCHEMA_VERSION_5_SHA256, RHI_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_6_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_6_SHA256,
    RHI_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_7_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_7_SHA256, RHI_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_8_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_8_SHA256,
    RHI_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_9_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_9_SHA256, RHI_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256,
    RHI_STATE_SCHEMA_VERSION_10_OBJECT_COUNT, RHI_STATE_SCHEMA_VERSION_10_SHA256,
    RHI_STATE_SCHEMA_VERSION_11_MIGRATION_SHA256, RHI_STATE_SCHEMA_VERSION_11_OBJECT_COUNT,
    RHI_STATE_SCHEMA_VERSION_11_SHA256, RhiStateCatalogErrorKind, rhi_migration_catalog,
    rhi_schema_catalog, validate_rhi_state_catalogs,
};

const CATALOG_SOURCE: &str = include_str!("../src/state_catalog.rs");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn schema_v1_through_v11_catalogs_have_exact_literal_identities() {
    let migrations = rhi_migration_catalog().expect("RHI migration catalog");
    let schema = rhi_schema_catalog().expect("RHI schema catalog");

    assert_eq!(RHI_STATE_BASE_SCHEMA_VERSION, 1);
    assert_eq!(RHI_STATE_SCHEMA_VERSION, 11);
    assert_eq!(migrations.descriptors().len(), 10);
    assert_eq!(migrations.current_version(), 11);
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
    assert_eq!(migrations.descriptors()[4].target_version(), 6);
    assert_eq!(
        migrations.descriptors()[4].name().as_str(),
        "create_reconciliation_source_results"
    );
    assert_eq!(
        migrations.descriptors()[4].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256
    );
    assert_eq!(migrations.descriptors()[5].target_version(), 7);
    assert_eq!(
        migrations.descriptors()[5].name().as_str(),
        "create_reports_and_publication_outbox"
    );
    assert_eq!(
        migrations.descriptors()[5].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256
    );
    assert_eq!(migrations.descriptors()[6].target_version(), 8);
    assert_eq!(
        migrations.descriptors()[6].name().as_str(),
        "guard_reconciliation_job_state_shape"
    );
    assert_eq!(
        migrations.descriptors()[6].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256
    );
    assert_eq!(migrations.descriptors()[7].target_version(), 9);
    assert_eq!(
        migrations.descriptors()[7].name().as_str(),
        "create_presence_desired_state"
    );
    assert_eq!(
        migrations.descriptors()[7].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256
    );
    assert_eq!(migrations.descriptors()[8].target_version(), 10);
    assert_eq!(
        migrations.descriptors()[8].name().as_str(),
        "create_presence_publication_workflow"
    );
    assert_eq!(
        migrations.descriptors()[8].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256
    );
    assert_eq!(migrations.descriptors()[9].target_version(), 11);
    assert_eq!(
        migrations.descriptors()[9].name().as_str(),
        "create_admin_operation_journal"
    );
    assert_eq!(
        migrations.descriptors()[9].checksum().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_11_MIGRATION_SHA256
    );
    assert_eq!(
        migrations.digest().as_bytes(),
        &RHI_MIGRATION_CATALOG_SHA256
    );

    assert_eq!(schema.versions().len(), 11);
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
    let version = schema.versions()[5];
    assert_eq!(version.version(), 6);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_6_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 39);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_6_SHA256
    );
    let version = schema.versions()[6];
    assert_eq!(version.version(), 7);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_7_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 63);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_7_SHA256
    );
    let version = schema.versions()[7];
    assert_eq!(version.version(), 8);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_8_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 65);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_8_SHA256
    );
    let version = schema.versions()[8];
    assert_eq!(version.version(), 9);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_9_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 69);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_9_SHA256
    );
    let version = schema.versions()[9];
    assert_eq!(version.version(), 10);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_10_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 80);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_10_SHA256
    );
    let version = schema.versions()[10];
    assert_eq!(version.version(), 11);
    assert_eq!(
        version.object_count(),
        RHI_STATE_SCHEMA_VERSION_11_OBJECT_COUNT
    );
    assert_eq!(version.object_count(), 82);
    assert_eq!(
        version.digest().as_bytes(),
        &RHI_STATE_SCHEMA_VERSION_11_SHA256
    );
    assert_eq!(schema.digest().as_bytes(), &RHI_STATE_SCHEMA_CATALOG_SHA256);
    assert_eq!(schema.migration_catalog_digest(), migrations.digest());
    validate_rhi_state_catalogs(&migrations, &schema).expect("exact catalogs");

    assert_eq!(
        lower_hex(&RHI_MIGRATION_CATALOG_SHA256),
        "e6cbacbd1eb636c1a560f85ef8e51e89c9ffe3b342e66bc5c0b47ab34e90c818"
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
        lower_hex(&RHI_STATE_SCHEMA_VERSION_6_MIGRATION_SHA256),
        "48a14b2744c41186496d597ec780ad998fa9308a9c9d7540d475db3f4dcfc4bb"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_6_SHA256),
        "5d1fa9508b5b8a0c8065fd37f11c6866d51f9294c75272041f349e95ced50fb4"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_7_MIGRATION_SHA256),
        "9debf4f3caad4d018311cb169bf9282264d6abfc49e718840b9cbfad42ed357c"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_7_SHA256),
        "840aa83c689f9df99d26c5b4ef117131c270ef7522674037def79628a2b03946"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_8_MIGRATION_SHA256),
        "6d3aa06e6908e4281b5066ed4a13e2287bdaec05b0e539215891892a5afb583b"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_8_SHA256),
        "7cef559ae1e6efe158c5d1de50114ebaccac90538e0cd49a4ee214cb0a39c618"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_9_MIGRATION_SHA256),
        "32dabe777289e0fb6e64a4c1f8257843fc08018321c3b7ec5ca584fa1862bdcc"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_9_SHA256),
        "5551e8790544a7c78c8376c5ccf83dd2a8486d2dc08b6a7808bb2007c94335ec"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_10_MIGRATION_SHA256),
        "541ad13b2cb08d59857205e6ffaec19b74de0853240fdf11fa1340e406c7114e"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_10_SHA256),
        "d2aed51d0a6a2c01eda1844608472b2dcd502abaa8a4ca30a4823535b8bd0e45"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_11_MIGRATION_SHA256),
        "e3fbde511e8424c97080be2c09ed810ae284631d75eb25c2e88a6076b700aaef"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_VERSION_11_SHA256),
        "c25ec63b33b411618068ee06a04c99ee7166e0014d979039faeaea4dc1ac7e62"
    );
    assert_eq!(
        lower_hex(&RHI_STATE_SCHEMA_CATALOG_SHA256),
        "aec482818bd9a6f33fd92b55d142c6b85aa6f086855701dfc4b78f2a7ef5cf6d"
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
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(6, [version_two_object()]).expect("v6 digest");
    let version_six =
        SchemaVersionCatalog::new(6, [version_two_object()], snapshot_digest).expect("version six");
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(7, [version_two_object()]).expect("v7 digest");
    let version_seven = SchemaVersionCatalog::new(7, [version_two_object()], snapshot_digest)
        .expect("version seven");
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(8, [version_two_object()]).expect("v8 digest");
    let version_eight = SchemaVersionCatalog::new(8, [version_two_object()], snapshot_digest)
        .expect("version eight");
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(9, [version_two_object()]).expect("v9 digest");
    let version_nine = SchemaVersionCatalog::new(9, [version_two_object()], snapshot_digest)
        .expect("version nine");
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(10, [version_two_object()]).expect("v10 digest");
    let version_ten = SchemaVersionCatalog::new(10, [version_two_object()], snapshot_digest)
        .expect("version ten");
    let snapshot_digest =
        SchemaVersionCatalog::computed_digest(11, [version_two_object()]).expect("v11 digest");
    let version_eleven = SchemaVersionCatalog::new(11, [version_two_object()], snapshot_digest)
        .expect("version eleven");
    let schema = SchemaCatalog::new(
        &exact_migrations,
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
    let version_six_digest =
        SchemaVersionCatalog::computed_digest(6, [secret_object()]).expect("v6 digest");
    let version_six =
        SchemaVersionCatalog::new(6, [secret_object()], version_six_digest).expect("version six");
    let version_seven_digest =
        SchemaVersionCatalog::computed_digest(7, [secret_object()]).expect("v7 digest");
    let version_seven = SchemaVersionCatalog::new(7, [secret_object()], version_seven_digest)
        .expect("version seven");
    let version_eight_digest =
        SchemaVersionCatalog::computed_digest(8, [secret_object()]).expect("v8 digest");
    let version_eight = SchemaVersionCatalog::new(8, [secret_object()], version_eight_digest)
        .expect("version eight");
    let version_nine_digest =
        SchemaVersionCatalog::computed_digest(9, [secret_object()]).expect("v9 digest");
    let version_nine =
        SchemaVersionCatalog::new(9, [secret_object()], version_nine_digest).expect("version nine");
    let version_ten_digest =
        SchemaVersionCatalog::computed_digest(10, [secret_object()]).expect("v10 digest");
    let version_ten =
        SchemaVersionCatalog::new(10, [secret_object()], version_ten_digest).expect("version ten");
    let version_eleven_digest =
        SchemaVersionCatalog::computed_digest(11, [secret_object()]).expect("v11 digest");
    let version_eleven = SchemaVersionCatalog::new(11, [secret_object()], version_eleven_digest)
        .expect("version eleven");
    let schema = SchemaCatalog::new(
        &migrations,
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
        "radroots_service_sqlite = { git = \"https://github.com/radrootslabs/lib\", rev = \"055096853fca95e15d0f813d33a14aca13be3881\", version = \"=0.1.0-alpha\" }"
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
