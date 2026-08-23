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
pub const RHI_STATE_SCHEMA_VERSION: u32 = 2;

/// The shared metadata and migration-ledger objects present at schema v1.
pub const RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT: u32 = 6;

/// The shared objects plus the bounded append-only RHI configuration history.
pub const RHI_STATE_SCHEMA_VERSION_2_OBJECT_COUNT: u32 = 10;

/// SHA-256 identity of the ordered migration catalog rooted at schema v1.
pub const RHI_MIGRATION_CATALOG_SHA256: [u8; 32] = [
    0xb6, 0x40, 0xa9, 0x09, 0x5d, 0x53, 0x18, 0xdb, 0xfd, 0x0a, 0xfb, 0xfb, 0xe6, 0xe0, 0x52, 0x81,
    0x11, 0x3a, 0x9c, 0xef, 0x45, 0x64, 0x80, 0x5c, 0x02, 0x1c, 0x36, 0x8c, 0x3c, 0x52, 0xfc, 0x08,
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

/// SHA-256 identity of the schema catalog bound to the migration catalog.
pub const RHI_STATE_SCHEMA_CATALOG_SHA256: [u8; 32] = [
    0x1b, 0x7f, 0x73, 0x59, 0xb6, 0x2e, 0xd7, 0xdc, 0xd4, 0x76, 0x28, 0x9e, 0x46, 0x69, 0x3d, 0x9b,
    0x3d, 0x13, 0x69, 0xdc, 0xaf, 0x7d, 0x59, 0x52, 0xf0, 0x32, 0x9a, 0x5c, 0x86, 0xf8, 0xb8, 0x5f,
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
    let catalog = MigrationCatalog::new([configuration])
        .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::MigrationCatalog))?;
    if catalog.current_version() != RHI_STATE_SCHEMA_VERSION
        || catalog.descriptors().len() != 1
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
        RHI_STATE_SCHEMA_VERSION,
        rhi_config_binding_objects()?,
        SchemaDigest::from_bytes(RHI_STATE_SCHEMA_VERSION_2_SHA256),
    )
    .map_err(|_| RhiStateCatalogError::new(RhiStateCatalogErrorKind::SchemaCatalog))?;
    let catalog = SchemaCatalog::new(&migrations, [version_one, version_two])
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
        && migrations.descriptors().len() == 1
        && migrations.digest().as_bytes() == &RHI_MIGRATION_CATALOG_SHA256
        && schema.migration_catalog_digest() == migrations.digest()
        && versions.len() == 2
        && versions[0].version() == RHI_STATE_BASE_SCHEMA_VERSION
        && versions[0].object_count() == RHI_STATE_SCHEMA_VERSION_1_OBJECT_COUNT
        && versions[0].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_1_SHA256
        && versions[1].version() == RHI_STATE_SCHEMA_VERSION
        && versions[1].object_count() == RHI_STATE_SCHEMA_VERSION_2_OBJECT_COUNT
        && versions[1].digest().as_bytes() == &RHI_STATE_SCHEMA_VERSION_2_SHA256
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
