//! Deterministic durable desired state for RHI service presence.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{
    ServiceSqliteTransaction, ServiceSqliteTransactionError, ServiceSqliteTransactionErrorKind,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::{
    RhiConfigDocumentV1, RhiDesiredPresenceRepository, RhiStateHostMode,
    state_metadata::normalized_config_digest,
};

/// Exact version of the deterministic presence desired-state contract.
pub const RHI_PRESENCE_DESIRED_CONTRACT_VERSION: u32 = 1;

/// Maximum number of configured relay targets in one desired state.
pub const RHI_PRESENCE_DESIRED_MAX_TARGETS: usize = 32;

const TARGET_SET_DOMAIN: &[u8] = b"radroots.rhi.presence_target_set.v1\0";
const DESIRED_STATE_DOMAIN: &[u8] = b"radroots.rhi.presence_desired_state.v1\0";

const READ_CURRENT_CONFIG_SQL: &str = r#"SELECT
    CASE WHEN typeof(normalized_config_sha256) = 'blob'
            AND length(normalized_config_sha256) = 32
        THEN normalized_config_sha256 ELSE NULL END AS normalized_config_sha256,
    length(CAST(service_public_key AS BLOB)) AS service_public_key_bytes,
    substr(service_public_key, 1, 65) AS service_public_key
FROM rhi_config_bindings
ORDER BY generation DESC
LIMIT 1"#;

const READ_DESIRED_SQL: &str = r#"SELECT singleton, generation,
    enabled, profile, application_handler,
    CASE WHEN typeof(target_set_sha256) = 'blob' AND length(target_set_sha256) = 32
        THEN target_set_sha256 ELSE NULL END AS target_set_sha256,
    target_count, required_target_count, queue_capacity,
    CASE WHEN typeof(desired_sha256) = 'blob' AND length(desired_sha256) = 32
        THEN desired_sha256 ELSE NULL END AS desired_sha256
FROM presence_desired_state
LIMIT 2"#;

const INSERT_DESIRED_SQL: &str = r#"INSERT INTO presence_desired_state (
    singleton, generation, enabled, profile, application_handler,
    target_set_sha256, target_count, required_target_count,
    queue_capacity, desired_sha256
) VALUES (1, 1, ?, ?, ?, ?, ?, ?, ?, ?)"#;

const UPDATE_DESIRED_SQL: &str = r#"UPDATE presence_desired_state
SET generation = generation + 1,
    enabled = ?, profile = ?, application_handler = ?,
    target_set_sha256 = ?, target_count = ?, required_target_count = ?,
    queue_capacity = ?, desired_sha256 = ?
WHERE singleton = 1 AND generation = ? AND desired_sha256 = ?"#;

/// Closed configured presence posture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiPresenceDesiredMode {
    Disabled,
    Enabled,
}

impl RhiPresenceDesiredMode {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
        }
    }
}

/// Closed ordered inventory of presence documents selected by configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiPresenceDocumentKind {
    ServiceProfile,
    ApplicationHandler,
}

impl RhiPresenceDocumentKind {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ServiceProfile => "service_profile",
            Self::ApplicationHandler => "application_handler",
        }
    }
}

/// One immutable presence relay target derived from the admitted configuration.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RhiPresenceTarget {
    ordinal: u8,
    relay_id: Box<str>,
    required: bool,
}

impl RhiPresenceTarget {
    /// Returns the stable zero-based target position.
    #[must_use]
    pub const fn ordinal(&self) -> u8 {
        self.ordinal
    }

    /// Returns the validated stable relay identifier.
    #[must_use]
    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    /// Returns whether this relay is required by the admitted relay authority.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

impl fmt::Debug for RhiPresenceTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPresenceTarget")
            .field("ordinal", &self.ordinal)
            .field("relay_id", &"[redacted]")
            .field("required", &self.required)
            .finish()
    }
}

/// Sealed deterministic presence authority derived from one admitted config.
///
/// This value contains desired document kinds and stable relay authority only.
/// It contains no rendered event, signature, delivery attempt, time, entropy,
/// connection, or retry state.
///
/// ```compile_fail
/// use rhi::RhiPresenceDesiredAuthority;
///
/// let _forged = RhiPresenceDesiredAuthority { mode: todo!() };
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct RhiPresenceDesiredAuthority {
    configuration_sha256: [u8; 32],
    service_public_key: Box<str>,
    mode: RhiPresenceDesiredMode,
    document_kinds: Box<[RhiPresenceDocumentKind]>,
    targets: Box<[RhiPresenceTarget]>,
    queue_capacity: u32,
    target_set_sha256: [u8; 32],
    desired_sha256: [u8; 32],
}

impl RhiPresenceDesiredAuthority {
    /// Derives the only presence desired-state authority from one admitted config.
    pub fn from_config(config: &RhiConfigDocumentV1) -> Result<Self, RhiPresenceDesiredError> {
        derive_authority(config.normalized(), config.profile())
    }

    /// Returns the explicit configured posture.
    #[must_use]
    pub const fn mode(&self) -> RhiPresenceDesiredMode {
        self.mode
    }

    /// Returns the exact ordered desired-document inventory.
    #[must_use]
    pub fn document_kinds(&self) -> &[RhiPresenceDocumentKind] {
        &self.document_kinds
    }

    /// Returns the exact ordered presence target inventory.
    #[must_use]
    pub fn targets(&self) -> &[RhiPresenceTarget] {
        &self.targets
    }

    /// Returns the configured presence work-queue capacity, or zero when disabled.
    #[must_use]
    pub const fn queue_capacity(&self) -> u32 {
        self.queue_capacity
    }

    /// Returns the domain-separated exact target-set identity.
    #[must_use]
    pub const fn target_set_sha256(&self) -> &[u8; 32] {
        &self.target_set_sha256
    }

    /// Returns the domain-separated semantic desired-state identity.
    #[must_use]
    pub const fn desired_sha256(&self) -> &[u8; 32] {
        &self.desired_sha256
    }

    pub(crate) fn service_public_key(&self) -> &str {
        &self.service_public_key
    }
}

impl fmt::Debug for RhiPresenceDesiredAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPresenceDesiredAuthority")
            .field("mode", &self.mode)
            .field("document_count", &self.document_kinds.len())
            .field("target_count", &self.targets.len())
            .field("queue_capacity", &self.queue_capacity)
            .finish_non_exhaustive()
    }
}

/// Independently re-derives and validates one desired-state authority.
pub fn validate_rhi_presence_desired_authority(
    config: &RhiConfigDocumentV1,
    authority: &RhiPresenceDesiredAuthority,
) -> Result<(), RhiPresenceDesiredError> {
    let expected = RhiPresenceDesiredAuthority::from_config(config)?;
    (expected == *authority)
        .then_some(())
        .ok_or_else(|| failure(RhiPresenceDesiredErrorKind::Binding))
}

/// One validated durable desired-state snapshot.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiPresenceDesiredState {
    generation: u64,
    mode: RhiPresenceDesiredMode,
    profile: bool,
    application_handler: bool,
    target_set_sha256: [u8; 32],
    target_count: u8,
    required_target_count: u8,
    queue_capacity: u32,
    desired_sha256: [u8; 32],
}

impl RhiPresenceDesiredState {
    /// Returns the monotonically committed desired-state generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the configured desired-state posture.
    #[must_use]
    pub const fn mode(self) -> RhiPresenceDesiredMode {
        self.mode
    }

    /// Returns whether the service-profile document is desired.
    #[must_use]
    pub const fn profile(self) -> bool {
        self.profile
    }

    /// Returns whether the application-handler document is desired.
    #[must_use]
    pub const fn application_handler(self) -> bool {
        self.application_handler
    }

    /// Returns the target-set identity without exposing relay endpoints.
    #[must_use]
    pub const fn target_set_sha256(&self) -> &[u8; 32] {
        &self.target_set_sha256
    }

    /// Returns the total configured target count.
    #[must_use]
    pub const fn target_count(self) -> u8 {
        self.target_count
    }

    /// Returns the number of configured required targets.
    #[must_use]
    pub const fn required_target_count(self) -> u8 {
        self.required_target_count
    }

    /// Returns the configured presence queue bound, or zero when disabled.
    #[must_use]
    pub const fn queue_capacity(self) -> u32 {
        self.queue_capacity
    }

    /// Returns the semantic desired-state identity.
    #[must_use]
    pub const fn desired_sha256(&self) -> &[u8; 32] {
        &self.desired_sha256
    }
}

impl fmt::Debug for RhiPresenceDesiredState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPresenceDesiredState")
            .field("generation", &self.generation)
            .field("mode", &self.mode)
            .field("profile", &self.profile)
            .field("application_handler", &self.application_handler)
            .field("target_count", &self.target_count)
            .field("required_target_count", &self.required_target_count)
            .field("queue_capacity", &self.queue_capacity)
            .field("digests", &"[redacted]")
            .finish()
    }
}

/// Result of one durable desired-state compare-and-swap operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiPresenceDesiredCommitOutcome {
    state: RhiPresenceDesiredState,
    changed: bool,
}

impl RhiPresenceDesiredCommitOutcome {
    /// Returns the exact committed state.
    #[must_use]
    pub const fn state(self) -> RhiPresenceDesiredState {
        self.state
    }

    /// Returns whether this operation created a new durable generation.
    #[must_use]
    pub const fn changed(self) -> bool {
        self.changed
    }
}

/// Stable source-free desired-state failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiPresenceDesiredErrorKind {
    InvalidConfiguration,
    TargetInventory,
    InvalidMode,
    Binding,
    ResourceExhausted,
    Storage,
    CommitOutcomeUnknown,
}

impl RhiPresenceDesiredErrorKind {
    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "presence_desired_configuration_invalid",
            Self::TargetInventory => "presence_desired_target_inventory_invalid",
            Self::InvalidMode => "presence_desired_mode_invalid",
            Self::Binding => "presence_desired_binding_invalid",
            Self::ResourceExhausted => "resource_exhausted",
            Self::Storage => "presence_desired_storage_failed",
            Self::CommitOutcomeUnknown => "presence_desired_commit_outcome_unknown",
        }
    }
}

/// Redacted source-free desired-state failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiPresenceDesiredError {
    kind: RhiPresenceDesiredErrorKind,
}

impl RhiPresenceDesiredError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(self) -> RhiPresenceDesiredErrorKind {
        self.kind
    }

    /// Returns the stable machine-readable failure code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Display for RhiPresenceDesiredError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiPresenceDesiredErrorKind::InvalidConfiguration => {
                "RHI presence desired-state configuration is invalid"
            }
            RhiPresenceDesiredErrorKind::TargetInventory => {
                "RHI presence desired-state target inventory is invalid"
            }
            RhiPresenceDesiredErrorKind::InvalidMode => {
                "RHI presence desired-state operation mode is invalid"
            }
            RhiPresenceDesiredErrorKind::Binding => "RHI presence desired-state binding is invalid",
            RhiPresenceDesiredErrorKind::ResourceExhausted => {
                "RHI presence desired-state capacity is exhausted"
            }
            RhiPresenceDesiredErrorKind::Storage => "RHI presence desired-state storage failed",
            RhiPresenceDesiredErrorKind::CommitOutcomeUnknown => {
                "RHI presence desired-state commit outcome is unknown"
            }
        })
    }
}

impl fmt::Debug for RhiPresenceDesiredError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiPresenceDesiredError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl Error for RhiPresenceDesiredError {}

impl RhiDesiredPresenceRepository<'_> {
    /// Commits one exact desired state before any presence rendering or relay I/O.
    pub async fn commit(
        &self,
        authority: &RhiPresenceDesiredAuthority,
    ) -> Result<RhiPresenceDesiredCommitOutcome, RhiPresenceDesiredError> {
        require_writable(self)?;
        let authority = authority.clone();
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { commit_desired(transaction, &authority).await })
            })
            .await
            .map_err(map_transaction_error)
    }

    /// Reads the current validated desired-state snapshot without mutation.
    pub async fn current(
        &self,
    ) -> Result<Option<RhiPresenceDesiredState>, RhiPresenceDesiredError> {
        self.host()
            .sqlite_host()
            .transaction(move |transaction| {
                Box::pin(async move { read_desired(transaction).await })
            })
            .await
            .map_err(map_transaction_error)
    }
}

fn derive_authority(
    document: &Value,
    profile: crate::RhiConfigProfile,
) -> Result<RhiPresenceDesiredAuthority, RhiPresenceDesiredError> {
    let configuration_sha256 = *normalized_config_digest(profile, document)
        .map_err(|_| failure(RhiPresenceDesiredErrorKind::InvalidConfiguration))?
        .as_bytes();
    let service_public_key = document
        .pointer("/identity/service/expected_public_key")
        .and_then(Value::as_str)
        .filter(|value| valid_public_key(value))
        .ok_or_else(|| failure(RhiPresenceDesiredErrorKind::InvalidConfiguration))?;
    let enabled = boolean(document, "/presence/enabled")?;
    let profile_document = boolean(document, "/presence/profile")?;
    let application_handler = boolean(document, "/presence/application_handler")?;
    let configured_queue =
        integer(document, "/resource_limits/queues/presence").and_then(|value| {
            u32::try_from(value)
                .map_err(|_| failure(RhiPresenceDesiredErrorKind::InvalidConfiguration))
        })?;
    if configured_queue == 0 || configured_queue > 4_096 {
        return Err(failure(RhiPresenceDesiredErrorKind::InvalidConfiguration));
    }

    let mode = if enabled {
        RhiPresenceDesiredMode::Enabled
    } else {
        RhiPresenceDesiredMode::Disabled
    };
    let mut document_kinds = Vec::with_capacity(2);
    let (targets, queue_capacity) = match mode {
        RhiPresenceDesiredMode::Disabled => {
            if profile_document
                || application_handler
                || document.pointer("/presence/target_relay_ids").is_some()
            {
                return Err(failure(RhiPresenceDesiredErrorKind::InvalidConfiguration));
            }
            (Vec::new(), 0)
        }
        RhiPresenceDesiredMode::Enabled => {
            if profile_document {
                document_kinds.push(RhiPresenceDocumentKind::ServiceProfile);
            }
            if application_handler {
                document_kinds.push(RhiPresenceDocumentKind::ApplicationHandler);
            }
            if document_kinds.is_empty() {
                return Err(failure(RhiPresenceDesiredErrorKind::InvalidConfiguration));
            }
            (
                derive_targets(document, "/presence/target_relay_ids")?,
                configured_queue,
            )
        }
    };
    let target_set_sha256 = target_set_digest(&targets)?;
    let desired_sha256 = desired_state_digest(
        mode,
        &document_kinds,
        &targets,
        queue_capacity,
        service_public_key,
    )?;
    Ok(RhiPresenceDesiredAuthority {
        configuration_sha256,
        service_public_key: service_public_key.into(),
        mode,
        document_kinds: document_kinds.into_boxed_slice(),
        targets: targets.into_boxed_slice(),
        queue_capacity,
        target_set_sha256,
        desired_sha256,
    })
}

fn derive_targets(
    document: &Value,
    pointer: &str,
) -> Result<Vec<RhiPresenceTarget>, RhiPresenceDesiredError> {
    let target_ids = document
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| failure(RhiPresenceDesiredErrorKind::TargetInventory))?;
    if target_ids.is_empty() || target_ids.len() > RHI_PRESENCE_DESIRED_MAX_TARGETS {
        return Err(failure(RhiPresenceDesiredErrorKind::TargetInventory));
    }
    let relays = document
        .pointer("/relays")
        .and_then(Value::as_array)
        .ok_or_else(|| failure(RhiPresenceDesiredErrorKind::TargetInventory))?;
    let mut targets = Vec::with_capacity(target_ids.len());
    for (ordinal, target_id) in target_ids.iter().enumerate() {
        let relay_id = target_id
            .as_str()
            .filter(|value| valid_relay_id(value))
            .ok_or_else(|| failure(RhiPresenceDesiredErrorKind::TargetInventory))?;
        if targets
            .iter()
            .any(|target: &RhiPresenceTarget| target.relay_id() == relay_id)
        {
            return Err(failure(RhiPresenceDesiredErrorKind::TargetInventory));
        }
        let relay = relays
            .iter()
            .find(|relay| relay.pointer("/id").and_then(Value::as_str) == Some(relay_id))
            .ok_or_else(|| failure(RhiPresenceDesiredErrorKind::TargetInventory))?;
        if relay.pointer("/write").and_then(Value::as_bool) != Some(true) {
            return Err(failure(RhiPresenceDesiredErrorKind::TargetInventory));
        }
        targets.push(RhiPresenceTarget {
            ordinal: u8::try_from(ordinal)
                .map_err(|_| failure(RhiPresenceDesiredErrorKind::TargetInventory))?,
            relay_id: relay_id.into(),
            required: relay
                .pointer("/required")
                .and_then(Value::as_bool)
                .ok_or_else(|| failure(RhiPresenceDesiredErrorKind::TargetInventory))?,
        });
    }
    Ok(targets)
}

fn target_set_digest(targets: &[RhiPresenceTarget]) -> Result<[u8; 32], RhiPresenceDesiredError> {
    let mut digest = Sha256::new();
    digest.update(TARGET_SET_DOMAIN);
    digest.update(
        u32::try_from(targets.len())
            .map_err(|_| failure(RhiPresenceDesiredErrorKind::TargetInventory))?
            .to_be_bytes(),
    );
    for target in targets {
        digest.update(u32::from(target.ordinal).to_be_bytes());
        digest.update(
            u64::try_from(target.relay_id.len())
                .map_err(|_| failure(RhiPresenceDesiredErrorKind::TargetInventory))?
                .to_be_bytes(),
        );
        digest.update(target.relay_id.as_bytes());
        digest.update([u8::from(target.required)]);
    }
    Ok(digest.finalize().into())
}

fn desired_state_digest(
    mode: RhiPresenceDesiredMode,
    document_kinds: &[RhiPresenceDocumentKind],
    targets: &[RhiPresenceTarget],
    queue_capacity: u32,
    service_public_key: &str,
) -> Result<[u8; 32], RhiPresenceDesiredError> {
    let mut digest = Sha256::new();
    digest.update(DESIRED_STATE_DOMAIN);
    digest.update([match mode {
        RhiPresenceDesiredMode::Disabled => 0,
        RhiPresenceDesiredMode::Enabled => 1,
    }]);
    digest.update(
        u32::try_from(document_kinds.len())
            .map_err(|_| failure(RhiPresenceDesiredErrorKind::InvalidConfiguration))?
            .to_be_bytes(),
    );
    for kind in document_kinds {
        digest.update([match kind {
            RhiPresenceDocumentKind::ServiceProfile => 0,
            RhiPresenceDocumentKind::ApplicationHandler => 1,
        }]);
    }
    digest.update(
        u32::try_from(targets.len())
            .map_err(|_| failure(RhiPresenceDesiredErrorKind::TargetInventory))?
            .to_be_bytes(),
    );
    for target in targets {
        digest.update(u32::from(target.ordinal).to_be_bytes());
        digest.update(
            u64::try_from(target.relay_id.len())
                .map_err(|_| failure(RhiPresenceDesiredErrorKind::TargetInventory))?
                .to_be_bytes(),
        );
        digest.update(target.relay_id.as_bytes());
        digest.update([u8::from(target.required)]);
    }
    digest.update(queue_capacity.to_be_bytes());
    digest.update(
        u64::try_from(service_public_key.len())
            .map_err(|_| failure(RhiPresenceDesiredErrorKind::InvalidConfiguration))?
            .to_be_bytes(),
    );
    digest.update(service_public_key.as_bytes());
    Ok(digest.finalize().into())
}

fn require_writable(
    repository: &RhiDesiredPresenceRepository<'_>,
) -> Result<(), RhiPresenceDesiredError> {
    if repository.host().mode() == RhiStateHostMode::ReadWriteExisting {
        Ok(())
    } else {
        Err(failure(RhiPresenceDesiredErrorKind::InvalidMode))
    }
}

async fn commit_desired(
    transaction: &mut ServiceSqliteTransaction<'_>,
    authority: &RhiPresenceDesiredAuthority,
) -> Result<RhiPresenceDesiredCommitOutcome, OperationError> {
    require_current_config(transaction, authority).await?;
    let current = read_desired(transaction).await?;
    if let Some(current) = current {
        if matches_authority(current, authority) {
            return Ok(RhiPresenceDesiredCommitOutcome {
                state: current,
                changed: false,
            });
        }
        if current.generation == i64::MAX as u64 {
            return Err(OperationError::ResourceExhausted);
        }
        let result = sqlx::query(UPDATE_DESIRED_SQL)
            .bind(bool_i64(authority.mode == RhiPresenceDesiredMode::Enabled))
            .bind(bool_i64(has_document(
                authority,
                RhiPresenceDocumentKind::ServiceProfile,
            )))
            .bind(bool_i64(has_document(
                authority,
                RhiPresenceDocumentKind::ApplicationHandler,
            )))
            .bind(authority.target_set_sha256.as_slice())
            .bind(i64_count(authority.targets.len())?)
            .bind(i64_count(
                authority
                    .targets
                    .iter()
                    .filter(|target| target.required)
                    .count(),
            )?)
            .bind(i64::from(authority.queue_capacity))
            .bind(authority.desired_sha256.as_slice())
            .bind(i64_value(current.generation)?)
            .bind(current.desired_sha256.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| OperationError::Storage)?;
        if result.rows_affected() != 1 {
            return Err(OperationError::Binding);
        }
    } else {
        let result = sqlx::query(INSERT_DESIRED_SQL)
            .bind(bool_i64(authority.mode == RhiPresenceDesiredMode::Enabled))
            .bind(bool_i64(has_document(
                authority,
                RhiPresenceDocumentKind::ServiceProfile,
            )))
            .bind(bool_i64(has_document(
                authority,
                RhiPresenceDocumentKind::ApplicationHandler,
            )))
            .bind(authority.target_set_sha256.as_slice())
            .bind(i64_count(authority.targets.len())?)
            .bind(i64_count(
                authority
                    .targets
                    .iter()
                    .filter(|target| target.required)
                    .count(),
            )?)
            .bind(i64::from(authority.queue_capacity))
            .bind(authority.desired_sha256.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(|_| OperationError::Storage)?;
        if result.rows_affected() != 1 {
            return Err(OperationError::Binding);
        }
    }
    let committed = read_desired(transaction)
        .await?
        .filter(|state| matches_authority(*state, authority))
        .ok_or(OperationError::Binding)?;
    Ok(RhiPresenceDesiredCommitOutcome {
        state: committed,
        changed: true,
    })
}

async fn require_current_config(
    transaction: &mut ServiceSqliteTransaction<'_>,
    authority: &RhiPresenceDesiredAuthority,
) -> Result<(), OperationError> {
    let rows = sqlx::query(READ_CURRENT_CONFIG_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    if rows.len() != 1 {
        return Err(OperationError::Binding);
    }
    let row = &rows[0];
    let configuration_sha256 = digest(row, "normalized_config_sha256")?;
    let key_bytes = row
        .try_get::<i64, _>("service_public_key_bytes")
        .ok()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value == 64)
        .ok_or(OperationError::Binding)?;
    let service_public_key = row
        .try_get::<String, _>("service_public_key")
        .map_err(|_| OperationError::Binding)?;
    if service_public_key.len() != key_bytes
        || !valid_public_key(&service_public_key)
        || configuration_sha256 != authority.configuration_sha256
        || service_public_key != authority.service_public_key.as_ref()
    {
        return Err(OperationError::Binding);
    }
    Ok(())
}

async fn read_desired(
    transaction: &mut ServiceSqliteTransaction<'_>,
) -> Result<Option<RhiPresenceDesiredState>, OperationError> {
    let rows = sqlx::query(READ_DESIRED_SQL)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|_| OperationError::Storage)?;
    match rows.as_slice() {
        [] => Ok(None),
        [row] => decode_desired(row).map(Some),
        _ => Err(OperationError::Binding),
    }
}

fn decode_desired(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<RhiPresenceDesiredState, OperationError> {
    if row.try_get::<i64, _>("singleton").ok() != Some(1) {
        return Err(OperationError::Binding);
    }
    let generation = positive_u64(row, "generation")?;
    let enabled = boolean_i64(row, "enabled")?;
    let profile = boolean_i64(row, "profile")?;
    let application_handler = boolean_i64(row, "application_handler")?;
    let target_set_sha256 = digest(row, "target_set_sha256")?;
    let target_count = count_u8(row, "target_count", RHI_PRESENCE_DESIRED_MAX_TARGETS)?;
    let required_target_count = count_u8(row, "required_target_count", usize::from(target_count))?;
    let queue_capacity = row
        .try_get::<i64, _>("queue_capacity")
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value <= 4_096)
        .ok_or(OperationError::Binding)?;
    let desired_sha256 = digest(row, "desired_sha256")?;
    let valid = if enabled {
        (profile || application_handler) && target_count > 0 && queue_capacity > 0
    } else {
        !profile
            && !application_handler
            && target_count == 0
            && required_target_count == 0
            && queue_capacity == 0
    };
    if !valid {
        return Err(OperationError::Binding);
    }
    Ok(RhiPresenceDesiredState {
        generation,
        mode: if enabled {
            RhiPresenceDesiredMode::Enabled
        } else {
            RhiPresenceDesiredMode::Disabled
        },
        profile,
        application_handler,
        target_set_sha256,
        target_count,
        required_target_count,
        queue_capacity,
        desired_sha256,
    })
}

fn matches_authority(
    state: RhiPresenceDesiredState,
    authority: &RhiPresenceDesiredAuthority,
) -> bool {
    state.mode == authority.mode
        && state.profile == has_document(authority, RhiPresenceDocumentKind::ServiceProfile)
        && state.application_handler
            == has_document(authority, RhiPresenceDocumentKind::ApplicationHandler)
        && state.target_set_sha256 == authority.target_set_sha256
        && usize::from(state.target_count) == authority.targets.len()
        && usize::from(state.required_target_count)
            == authority
                .targets
                .iter()
                .filter(|target| target.required)
                .count()
        && state.queue_capacity == authority.queue_capacity
        && state.desired_sha256 == authority.desired_sha256
}

pub(crate) fn presence_authority_matches_state(
    state: RhiPresenceDesiredState,
    authority: &RhiPresenceDesiredAuthority,
) -> bool {
    matches_authority(state, authority)
}

fn has_document(authority: &RhiPresenceDesiredAuthority, kind: RhiPresenceDocumentKind) -> bool {
    authority.document_kinds.contains(&kind)
}

fn digest(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<[u8; 32], OperationError> {
    row.try_get::<Vec<u8>, _>(field)
        .map_err(|_| OperationError::Binding)?
        .try_into()
        .map_err(|_| OperationError::Binding)
}

fn positive_u64(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<u64, OperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or(OperationError::Binding)
}

fn boolean_i64(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<bool, OperationError> {
    match row.try_get::<i64, _>(field) {
        Ok(0) => Ok(false),
        Ok(1) => Ok(true),
        Ok(_) | Err(_) => Err(OperationError::Binding),
    }
}

fn count_u8(
    row: &sqlx::sqlite::SqliteRow,
    field: &str,
    maximum: usize,
) -> Result<u8, OperationError> {
    row.try_get::<i64, _>(field)
        .ok()
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| usize::from(*value) <= maximum)
        .ok_or(OperationError::Binding)
}

fn bool_i64(value: bool) -> i64 {
    i64::from(value)
}

fn i64_count(value: usize) -> Result<i64, OperationError> {
    i64::try_from(value).map_err(|_| OperationError::InvalidInput)
}

fn i64_value(value: u64) -> Result<i64, OperationError> {
    i64::try_from(value).map_err(|_| OperationError::ResourceExhausted)
}

fn boolean(document: &Value, pointer: &str) -> Result<bool, RhiPresenceDesiredError> {
    document
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| failure(RhiPresenceDesiredErrorKind::InvalidConfiguration))
}

fn integer(document: &Value, pointer: &str) -> Result<u64, RhiPresenceDesiredError> {
    document
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| failure(RhiPresenceDesiredErrorKind::InvalidConfiguration))
}

fn valid_public_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && nostr::PublicKey::from_hex(value).is_ok_and(|key| key.xonly().is_ok())
}

fn valid_relay_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperationError {
    InvalidInput,
    Binding,
    ResourceExhausted,
    Storage,
}

fn map_transaction_error(
    error: ServiceSqliteTransactionError<OperationError>,
) -> RhiPresenceDesiredError {
    if error.kind() == ServiceSqliteTransactionErrorKind::CommitOutcomeUnknown {
        return failure(RhiPresenceDesiredErrorKind::CommitOutcomeUnknown);
    }
    failure(match error.operation_error().copied() {
        Some(OperationError::InvalidInput) => RhiPresenceDesiredErrorKind::InvalidConfiguration,
        Some(OperationError::Binding) => RhiPresenceDesiredErrorKind::Binding,
        Some(OperationError::ResourceExhausted) => RhiPresenceDesiredErrorKind::ResourceExhausted,
        Some(OperationError::Storage) | None => RhiPresenceDesiredErrorKind::Storage,
    })
}

const fn failure(kind: RhiPresenceDesiredErrorKind) -> RhiPresenceDesiredError {
    RhiPresenceDesiredError { kind }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RhiConfigProfile, parse_rhi_config_v1};

    const EXAMPLE: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

    fn config(source: &str) -> RhiConfigDocumentV1 {
        parse_rhi_config_v1(source.as_bytes(), RhiConfigProfile::RepoLocal).expect("config")
    }

    #[test]
    fn authority_is_deterministic_ordered_and_sealed() {
        let config = config(EXAMPLE);
        let first = RhiPresenceDesiredAuthority::from_config(&config).expect("authority");
        let second = RhiPresenceDesiredAuthority::from_config(&config).expect("authority");
        assert_eq!(first, second);
        validate_rhi_presence_desired_authority(&config, &first).expect("independent validation");
        assert_eq!(first.mode(), RhiPresenceDesiredMode::Enabled);
        assert_eq!(
            first.document_kinds(),
            &[
                RhiPresenceDocumentKind::ServiceProfile,
                RhiPresenceDocumentKind::ApplicationHandler,
            ]
        );
        assert_eq!(first.targets().len(), 2);
        assert_eq!(first.targets()[0].ordinal(), 0);
        assert_eq!(first.targets()[0].relay_id(), "relay-primary");
        assert!(first.targets()[0].required());
        assert_eq!(first.targets()[1].ordinal(), 1);
        assert_eq!(first.targets()[1].relay_id(), "relay-secondary");
        assert!(!first.targets()[1].required());
        assert_eq!(first.queue_capacity(), 64);
        assert_eq!(
            first.target_set_sha256(),
            &[
                0x95, 0x9f, 0x04, 0x01, 0x28, 0x41, 0xae, 0x6e, 0x9b, 0xf3, 0xe1, 0x09, 0x46, 0x8b,
                0x4f, 0x66, 0xcf, 0xa9, 0xd9, 0x66, 0xaa, 0xc1, 0xdf, 0x36, 0xdf, 0x09, 0xe4, 0x5c,
                0x1e, 0x1c, 0x48, 0xf9,
            ]
        );
        assert_eq!(
            first.desired_sha256(),
            &[
                0x72, 0x35, 0xf1, 0xe3, 0x86, 0xe8, 0x39, 0x42, 0x76, 0x25, 0xdc, 0x36, 0x4d, 0xf7,
                0xb5, 0x1e, 0xe7, 0x4d, 0x39, 0xd5, 0xf1, 0x70, 0xe1, 0x2b, 0x25, 0xcf, 0x2c, 0x42,
                0xfd, 0x77, 0x31, 0xf0,
            ]
        );
        let rendered = format!("{first:?} {:?}", first.targets()[0]);
        assert!(!rendered.contains("relay-primary"));
        assert!(!rendered.contains(&"2".repeat(64)));
    }

    #[test]
    fn semantic_changes_change_only_the_deterministic_authority() {
        let baseline =
            RhiPresenceDesiredAuthority::from_config(&config(EXAMPLE)).expect("baseline");
        for changed in [
            EXAMPLE.replace("profile = true", "profile = false"),
            EXAMPLE.replace(
                "target_relay_ids = [\"relay-primary\", \"relay-secondary\"]",
                "target_relay_ids = [\"relay-secondary\", \"relay-primary\"]",
            ),
            EXAMPLE.replacen("required = true", "required = false", 1),
            EXAMPLE.replace("presence = 64", "presence = 63"),
            EXAMPLE.replace(&"2".repeat(64), &"3".repeat(64)),
        ] {
            let changed = RhiPresenceDesiredAuthority::from_config(&config(&changed))
                .expect("changed authority");
            assert_ne!(changed.desired_sha256(), baseline.desired_sha256());
        }
    }

    #[test]
    fn disabled_authority_contains_no_document_target_or_queue_state() {
        let disabled = EXAMPLE.replace(
            "[presence]\nenabled = true\nprofile = true\napplication_handler = true\ntarget_relay_ids = [\"relay-primary\", \"relay-secondary\"]",
            "[presence]\nenabled = false\nprofile = false\napplication_handler = false",
        );
        let authority = RhiPresenceDesiredAuthority::from_config(&config(&disabled))
            .expect("disabled authority");
        assert_eq!(authority.mode(), RhiPresenceDesiredMode::Disabled);
        assert!(authority.document_kinds().is_empty());
        assert!(authority.targets().is_empty());
        assert_eq!(authority.queue_capacity(), 0);
    }

    #[test]
    fn diagnostics_are_closed_source_free_and_redacted() {
        for kind in [
            RhiPresenceDesiredErrorKind::InvalidConfiguration,
            RhiPresenceDesiredErrorKind::TargetInventory,
            RhiPresenceDesiredErrorKind::InvalidMode,
            RhiPresenceDesiredErrorKind::Binding,
            RhiPresenceDesiredErrorKind::ResourceExhausted,
            RhiPresenceDesiredErrorKind::Storage,
            RhiPresenceDesiredErrorKind::CommitOutcomeUnknown,
        ] {
            let error = failure(kind);
            assert_eq!(error.kind(), kind);
            assert!(!error.code().is_empty());
            assert!(Error::source(&error).is_none());
            let rendered = format!("{error} {error:?}");
            assert!(!rendered.contains("wss://"));
            assert!(!rendered.contains("relay-primary"));
            assert!(!rendered.contains(&"2".repeat(64)));
        }
    }
}
