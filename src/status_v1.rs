//! Passive, latest-value Rhi lifecycle and detailed-status publication.

use core::fmt;
use std::{error::Error, sync::Arc, time::Duration};

use radroots_service_host::{
    BoundedMetricsSnapshot, BuildInfo as HostBuildInfo,
    BuildInfoEnvironment as HostBuildInfoEnvironment, BuildMode as HostBuildMode,
    CachedServiceState, CachedServiceStatePublisher, CachedServiceStateReader, CommonMetricGroup,
    ConfigurationIdentity as HostConfigurationIdentity,
    ConfigurationSource as HostConfigurationSource, ContractVersions as HostContractVersions,
    InstanceId, IntegrityState as HostIntegrityState, MetricDescriptor, MetricKind, MetricLabel,
    MetricLabelKey, MetricName, MetricSample, MetricValue,
    PersistenceHealth as HostPersistenceHealth, PersistenceSummary as HostPersistenceSummary,
    Readiness as HostReadiness, ReasonCode as HostReasonCode, ReasonCodes as HostReasonCodes,
    ServiceId, ServiceOperationalState as HostServiceOperationalState,
    ServicePhase as HostServicePhase, ServiceStatus, ServiceStatusDetail,
    Sha256Digest as HostSha256Digest, StatusContractError, StatusEncodingError, StatusModelError,
    UptimeMillis as HostUptimeMillis, cached_service_state,
};
use serde::Serialize;

/// Exact version of the passive Rhi status-cache contract.
pub const RHI_STATUS_CACHE_CONTRACT_VERSION: u32 = 1;

/// Maximum encoded byte length of one detailed Rhi status response.
pub const RHI_DETAILED_STATUS_MAX_UTF8_BYTES: usize =
    radroots_service_host::SERVICE_STATUS_MAX_UTF8_BYTES;

/// Number of stable reason codes admitted by detailed Rhi status.
pub const RHI_STATUS_REASON_CODE_COUNT: usize = 13;

/// One closed stable source-free status reason code.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RhiStatusReasonCode {
    IdentityUnavailable,
    DatabaseSchemaMismatch,
    DatabaseReadOnly,
    DatabaseLowDisk,
    SourceUnavailable,
    SubscriptionInactive,
    RecoveryIncomplete,
    PublicationRecoveryIncomplete,
    PresenceStateUnavailable,
    ReconciliationBacklogExceeded,
    AdminListenerFailed,
    OperationsListenerFailed,
    ShutdownInProgress,
}

impl RhiStatusReasonCode {
    pub fn new(value: impl AsRef<str>) -> Result<Self, RhiStatusError> {
        match value.as_ref() {
            "identity_unavailable" => Ok(Self::IdentityUnavailable),
            "database_schema_mismatch" => Ok(Self::DatabaseSchemaMismatch),
            "database_read_only" => Ok(Self::DatabaseReadOnly),
            "database_low_disk" => Ok(Self::DatabaseLowDisk),
            "source_unavailable" => Ok(Self::SourceUnavailable),
            "subscription_inactive" => Ok(Self::SubscriptionInactive),
            "recovery_incomplete" => Ok(Self::RecoveryIncomplete),
            "publication_recovery_incomplete" => Ok(Self::PublicationRecoveryIncomplete),
            "presence_state_unavailable" => Ok(Self::PresenceStateUnavailable),
            "reconciliation_backlog_exceeded" => Ok(Self::ReconciliationBacklogExceeded),
            "admin_listener_failed" => Ok(Self::AdminListenerFailed),
            "operations_listener_failed" => Ok(Self::OperationsListenerFailed),
            "shutdown_in_progress" => Ok(Self::ShutdownInProgress),
            _ => Err(RhiStatusError::new(RhiStatusErrorKind::InvalidReasonCode)),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityUnavailable => "identity_unavailable",
            Self::DatabaseSchemaMismatch => "database_schema_mismatch",
            Self::DatabaseReadOnly => "database_read_only",
            Self::DatabaseLowDisk => "database_low_disk",
            Self::SourceUnavailable => "source_unavailable",
            Self::SubscriptionInactive => "subscription_inactive",
            Self::RecoveryIncomplete => "recovery_incomplete",
            Self::PublicationRecoveryIncomplete => "publication_recovery_incomplete",
            Self::PresenceStateUnavailable => "presence_state_unavailable",
            Self::ReconciliationBacklogExceeded => "reconciliation_backlog_exceeded",
            Self::AdminListenerFailed => "admin_listener_failed",
            Self::OperationsListenerFailed => "operations_listener_failed",
            Self::ShutdownInProgress => "shutdown_in_progress",
        }
    }
}

/// Canonically ordered, unique, bounded status reasons.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RhiStatusReasonCodes(Vec<RhiStatusReasonCode>);

impl RhiStatusReasonCodes {
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn new(
        values: impl IntoIterator<Item = RhiStatusReasonCode>,
    ) -> Result<Self, RhiStatusError> {
        let mut bounded = Vec::with_capacity(RHI_STATUS_REASON_CODE_COUNT);
        for value in values.into_iter().take(RHI_STATUS_REASON_CODE_COUNT + 1) {
            if bounded.len() == RHI_STATUS_REASON_CODE_COUNT {
                return Err(RhiStatusError::new(RhiStatusErrorKind::TooManyReasonCodes));
            }
            bounded.push(value);
        }
        bounded.sort_unstable();
        bounded.dedup();
        Ok(Self(bounded))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[RhiStatusReasonCode] {
        &self.0
    }

    fn into_host(self) -> Result<HostReasonCodes, RhiStatusError> {
        let values = self
            .0
            .into_iter()
            .map(|value| HostReasonCode::new(value.as_str()).map_err(map_contract_error))
            .collect::<Result<Vec<_>, _>>()?;
        HostReasonCodes::new(values).map_err(map_contract_error)
    }
}

/// Closed common lifecycle phase used by the Rhi public boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RhiServicePhase {
    Starting,
    Ready,
    Degraded,
    Unready,
    Stopping,
    Failed,
}

impl RhiServicePhase {
    const fn into_host(self) -> HostServicePhase {
        match self {
            Self::Starting => HostServicePhase::Starting,
            Self::Ready => HostServicePhase::Ready,
            Self::Degraded => HostServicePhase::Degraded,
            Self::Unready => HostServicePhase::Unready,
            Self::Stopping => HostServicePhase::Stopping,
            Self::Failed => HostServicePhase::Failed,
        }
    }

    const fn from_host(value: HostServicePhase) -> Self {
        match value {
            HostServicePhase::Starting => Self::Starting,
            HostServicePhase::Ready => Self::Ready,
            HostServicePhase::Degraded => Self::Degraded,
            HostServicePhase::Unready => Self::Unready,
            HostServicePhase::Stopping => Self::Stopping,
            HostServicePhase::Failed => Self::Failed,
        }
    }
}

/// Build-metadata admission mode for Rhi status identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiStatusBuildMode {
    Development,
    Release,
}

/// Complete deterministic build identity retained behind the Rhi boundary.
pub struct RhiStatusBuildInfoV1 {
    inner: HostBuildInfo,
}

impl RhiStatusBuildInfoV1 {
    /// Validates the complete build/source-lock identity with fixed Rhi contracts.
    pub fn new(
        mode: RhiStatusBuildMode,
        service_version: Option<&str>,
        service_commit: Option<&str>,
        lib_revision: Option<&str>,
        rust_version: Option<&str>,
        target: Option<&str>,
        feature_profile: Option<&str>,
    ) -> Result<Self, RhiStatusError> {
        let contract_versions = HostContractVersions::new(
            crate::RHI_CONFIG_SCHEMA_VERSION,
            crate::RHI_STATE_SCHEMA_VERSION,
            crate::RHI_ADMIN_CONTRACT_VERSION,
            crate::RHI_STATUS_CONTRACT_VERSION,
            crate::RHI_PROVIDER_CONTRACT_VERSION,
        )
        .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::InvalidBuildInfo))?;
        HostBuildInfo::from_compile_time(
            match mode {
                RhiStatusBuildMode::Development => HostBuildMode::Development,
                RhiStatusBuildMode::Release => HostBuildMode::Release,
            },
            HostBuildInfoEnvironment {
                service_version,
                service_commit,
                lib_revision,
                rust_version,
                target,
                feature_profile,
                contract_versions,
            },
        )
        .map(|inner| Self { inner })
        .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::InvalidBuildInfo))
    }
}

impl fmt::Debug for RhiStatusBuildInfoV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiStatusBuildInfoV1([redacted])")
    }
}

/// Exact configuration-source vocabulary exposed by detailed status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiStatusConfigurationSource {
    ExplicitConfig,
    DerivedRepoLocal,
}

/// Safe configuration identity retained behind the Rhi boundary.
pub struct RhiStatusConfigurationIdentityV1 {
    inner: HostConfigurationIdentity,
}

impl RhiStatusConfigurationIdentityV1 {
    pub fn new(
        digest: impl AsRef<str>,
        source: RhiStatusConfigurationSource,
    ) -> Result<Self, RhiStatusError> {
        let service = ServiceId::new("rhi")
            .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::InvalidConfiguration))?;
        let digest = HostSha256Digest::new(digest)
            .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::InvalidConfiguration))?;
        HostConfigurationIdentity::for_service(
            &service,
            digest,
            match source {
                RhiStatusConfigurationSource::ExplicitConfig => {
                    HostConfigurationSource::ExplicitConfig
                }
                RhiStatusConfigurationSource::DerivedRepoLocal => {
                    HostConfigurationSource::DerivedRepoLocal
                }
            },
        )
        .map(|inner| Self { inner })
        .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::InvalidConfiguration))
    }
}

impl fmt::Debug for RhiStatusConfigurationIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiStatusConfigurationIdentityV1([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiPersistenceHealthV1 {
    Ready,
    ReadOnly,
    RepairRequired,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiIntegrityStateV1 {
    Verified,
    VerificationRequired,
    Failed,
}

/// Validated persistence summary retained behind the Rhi boundary.
pub struct RhiPersistenceStatusV1 {
    inner: HostPersistenceSummary,
    ready: bool,
}

impl RhiPersistenceStatusV1 {
    pub fn new(
        health: RhiPersistenceHealthV1,
        schema_version: u32,
        generation: u64,
        integrity: RhiIntegrityStateV1,
        reason_codes: RhiStatusReasonCodes,
    ) -> Result<Self, RhiStatusError> {
        let reason_codes = reason_codes.into_host()?;
        let ready =
            health == RhiPersistenceHealthV1::Ready && integrity == RhiIntegrityStateV1::Verified;
        HostPersistenceSummary::new(
            match health {
                RhiPersistenceHealthV1::Ready => HostPersistenceHealth::Ready,
                RhiPersistenceHealthV1::ReadOnly => HostPersistenceHealth::ReadOnly,
                RhiPersistenceHealthV1::RepairRequired => HostPersistenceHealth::RepairRequired,
                RhiPersistenceHealthV1::Unavailable => HostPersistenceHealth::Unavailable,
            },
            schema_version,
            generation,
            match integrity {
                RhiIntegrityStateV1::Verified => HostIntegrityState::Verified,
                RhiIntegrityStateV1::VerificationRequired => {
                    HostIntegrityState::VerificationRequired
                }
                RhiIntegrityStateV1::Failed => HostIntegrityState::Failed,
            },
            reason_codes,
        )
        .map(|inner| Self { inner, ready })
        .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::InvalidPersistence))
    }
}

impl fmt::Debug for RhiPersistenceStatusV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiPersistenceStatusV1([redacted])")
    }
}

/// One validated Unix timestamp used only for an oldest pending work item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RhiStatusUnixSeconds(u64);

impl RhiStatusUnixSeconds {
    /// Constructs a timestamp representable by SQLite and the frozen wire contract.
    pub fn new(value: u64) -> Result<Self, RhiStatusError> {
        if value > i64::MAX as u64 {
            return Err(RhiStatusError::new(RhiStatusErrorKind::InvalidTime));
        }
        Ok(Self(value))
    }

    /// Returns exact whole Unix seconds.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Passive availability of one configured Rhi identity role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RhiIdentityHealthV1 {
    configured: bool,
    available: bool,
    reason_codes: RhiStatusReasonCodes,
}

impl RhiIdentityHealthV1 {
    /// Constructs one role observation, rejecting availability without configuration.
    pub fn new(
        configured: bool,
        available: bool,
        reason_codes: RhiStatusReasonCodes,
    ) -> Result<Self, RhiStatusError> {
        if available && !configured {
            return Err(RhiStatusError::new(
                RhiStatusErrorKind::InvalidIdentityHealth,
            ));
        }
        Ok(Self {
            configured,
            available,
            reason_codes,
        })
    }

    #[must_use]
    pub const fn is_configured(&self) -> bool {
        self.configured
    }

    #[must_use]
    pub const fn is_available(&self) -> bool {
        self.available
    }

    #[must_use]
    pub const fn reason_codes(&self) -> &RhiStatusReasonCodes {
        &self.reason_codes
    }
}

/// Passive projection for the single configured RHI service identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RhiProviderStatusV1 {
    health: RhiProviderHealthV1,
    identity: RhiIdentityHealthV1,
    reason_codes: RhiStatusReasonCodes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RhiProviderHealthV1 {
    Ready,
    Unavailable,
}

impl RhiProviderStatusV1 {
    /// Derives provider health from the sole configured service identity.
    pub fn new(
        identity: RhiIdentityHealthV1,
        reason_codes: RhiStatusReasonCodes,
    ) -> Result<Self, RhiStatusError> {
        if !identity.configured {
            return Err(RhiStatusError::new(
                RhiStatusErrorKind::InvalidProviderState,
            ));
        }
        let health = if identity.available {
            RhiProviderHealthV1::Ready
        } else {
            RhiProviderHealthV1::Unavailable
        };
        Ok(Self {
            health,
            identity,
            reason_codes,
        })
    }

    #[must_use]
    pub const fn health(&self) -> RhiProviderHealthV1 {
        self.health
    }

    #[must_use]
    pub const fn identity(&self) -> &RhiIdentityHealthV1 {
        &self.identity
    }

    #[must_use]
    pub const fn reason_codes(&self) -> &RhiStatusReasonCodes {
        &self.reason_codes
    }
}

/// Passive evidence-source transport projection for detailed status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RhiEvidenceTransportStatusV1 {
    health: RhiTransportHealthV1,
    required_sources_ready: bool,
    subscriber_active: bool,
    configured_source_count: u64,
    reachable_source_count: u64,
    reason_codes: RhiStatusReasonCodes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RhiTransportHealthV1 {
    Ready,
    Degraded,
    Unavailable,
}

impl RhiEvidenceTransportStatusV1 {
    /// Constructs one transport observation, rejecting contradictory ready state.
    pub fn new(
        health: RhiTransportHealthV1,
        required_sources_ready: bool,
        subscriber_active: bool,
        configured_source_count: u64,
        reachable_source_count: u64,
        reason_codes: RhiStatusReasonCodes,
    ) -> Result<Self, RhiStatusError> {
        if reachable_source_count > configured_source_count
            || (health == RhiTransportHealthV1::Ready
                && (!required_sources_ready
                    || !subscriber_active
                    || configured_source_count == 0
                    || reachable_source_count == 0))
        {
            return Err(RhiStatusError::new(
                RhiStatusErrorKind::InvalidTransportState,
            ));
        }
        Ok(Self {
            health,
            required_sources_ready,
            subscriber_active,
            configured_source_count,
            reachable_source_count,
            reason_codes,
        })
    }

    #[must_use]
    pub const fn health(&self) -> RhiTransportHealthV1 {
        self.health
    }

    #[must_use]
    pub const fn required_sources_ready(&self) -> bool {
        self.required_sources_ready
    }

    #[must_use]
    pub const fn subscriber_active(&self) -> bool {
        self.subscriber_active
    }

    #[must_use]
    pub const fn configured_source_count(&self) -> u64 {
        self.configured_source_count
    }

    #[must_use]
    pub const fn reachable_source_count(&self) -> u64 {
        self.reachable_source_count
    }

    #[must_use]
    pub const fn reason_codes(&self) -> &RhiStatusReasonCodes {
        &self.reason_codes
    }
}

/// Passive bounded reconciliation-work summary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RhiReconciliationStatusV1 {
    pending: u64,
    leased: u64,
    exhausted: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_pending_at_utc: Option<RhiStatusUnixSeconds>,
}

impl RhiReconciliationStatusV1 {
    #[must_use]
    pub const fn new(
        pending: u64,
        leased: u64,
        exhausted: u64,
        oldest_pending_at_utc: Option<RhiStatusUnixSeconds>,
    ) -> Self {
        Self {
            pending,
            leased,
            exhausted,
            oldest_pending_at_utc,
        }
    }

    #[must_use]
    pub const fn pending(self) -> u64 {
        self.pending
    }

    #[must_use]
    pub const fn leased(self) -> u64 {
        self.leased
    }

    #[must_use]
    pub const fn exhausted(self) -> u64 {
        self.exhausted
    }

    #[must_use]
    pub const fn oldest_pending_at_utc(self) -> Option<RhiStatusUnixSeconds> {
        self.oldest_pending_at_utc
    }
}

/// Passive publication-outbox summary derived before cache publication.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RhiPublicationStatusV1 {
    pending: u64,
    unknown: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    oldest_pending_at_utc: Option<RhiStatusUnixSeconds>,
}

impl RhiPublicationStatusV1 {
    #[must_use]
    pub const fn new(
        pending: u64,
        unknown: u64,
        oldest_pending_at_utc: Option<RhiStatusUnixSeconds>,
    ) -> Self {
        Self {
            pending,
            unknown,
            oldest_pending_at_utc,
        }
    }

    #[must_use]
    pub const fn pending(self) -> u64 {
        self.pending
    }

    #[must_use]
    pub const fn unknown(self) -> u64 {
        self.unknown
    }

    #[must_use]
    pub const fn oldest_pending_at_utc(self) -> Option<RhiStatusUnixSeconds> {
        self.oldest_pending_at_utc
    }
}

/// Passive desired-presence publication summary.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RhiPresenceStatusV1 {
    pending: u64,
    unknown: u64,
}

impl RhiPresenceStatusV1 {
    #[must_use]
    pub const fn new(pending: u64, unknown: u64) -> Self {
        Self { pending, unknown }
    }

    #[must_use]
    pub const fn pending(self) -> u64 {
        self.pending
    }

    #[must_use]
    pub const fn unknown(self) -> u64 {
        self.unknown
    }
}

#[derive(Serialize)]
struct RhiStatusDetailV1 {
    identity: RhiIdentityHealthV1,
    reconciliation: RhiReconciliationStatusV1,
    publication: RhiPublicationStatusV1,
    presence: RhiPresenceStatusV1,
}

impl ServiceStatusDetail for RhiStatusDetailV1 {
    type Provider = RhiProviderStatusV1;
    type Transport = RhiEvidenceTransportStatusV1;

    const FIELD_NAME: &'static str = "rhi";
}

/// Validated common fields shared by one detailed status publication.
///
/// Construction and publication perform validation and bounded encoding only.
/// They do not query SQLite, providers, sources, relays, DNS, credentials, or the clock.
pub struct RhiStatusCommonV1 {
    operational: HostServiceOperationalState,
    uptime: HostUptimeMillis,
    build: HostBuildInfo,
    configuration: HostConfigurationIdentity,
    persistence: HostPersistenceSummary,
    persistence_ready: bool,
}

impl RhiStatusCommonV1 {
    /// Validates the common lifecycle and detailed-status envelope fields.
    pub fn new(
        phase: RhiServicePhase,
        ready: bool,
        reason_codes: RhiStatusReasonCodes,
        uptime_millis: u64,
        build: RhiStatusBuildInfoV1,
        configuration: RhiStatusConfigurationIdentityV1,
        persistence: RhiPersistenceStatusV1,
    ) -> Result<Self, RhiStatusError> {
        let operational = HostServiceOperationalState::new(
            phase.into_host(),
            if ready {
                HostReadiness::READY
            } else {
                HostReadiness::NOT_READY
            },
            reason_codes.into_host()?,
        )
        .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::InvalidLifecycle))?;
        let uptime = HostUptimeMillis::from_duration(Duration::from_millis(uptime_millis))
            .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::InvalidTime))?;
        Ok(Self {
            operational,
            uptime,
            build: build.inner,
            configuration: configuration.inner,
            persistence: persistence.inner,
            persistence_ready: persistence.ready,
        })
    }
}

impl fmt::Debug for RhiStatusCommonV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiStatusCommonV1([redacted])")
    }
}

/// One complete, already-observed status publication input.
pub struct RhiStatusObservationV1 {
    common: RhiStatusCommonV1,
    provider: RhiProviderStatusV1,
    transport: RhiEvidenceTransportStatusV1,
    reconciliation: RhiReconciliationStatusV1,
    publication: RhiPublicationStatusV1,
    presence: RhiPresenceStatusV1,
}

impl RhiStatusObservationV1 {
    #[must_use]
    pub fn new(
        common: RhiStatusCommonV1,
        provider: RhiProviderStatusV1,
        transport: RhiEvidenceTransportStatusV1,
        reconciliation: RhiReconciliationStatusV1,
        publication: RhiPublicationStatusV1,
        presence: RhiPresenceStatusV1,
    ) -> Self {
        Self {
            common,
            provider,
            transport,
            reconciliation,
            publication,
            presence,
        }
    }

    fn into_cached(self, instance: &InstanceId) -> Result<PreparedRhiStatus, RhiStatusError> {
        let operational = self.common.operational.clone();
        if operational.readiness().is_ready()
            && (!self.common.persistence_ready
                || self.provider.health != RhiProviderHealthV1::Ready
                || !self.transport.required_sources_ready
                || !self.transport.subscriber_active)
        {
            return Err(RhiStatusError::new(RhiStatusErrorKind::InvalidLifecycle));
        }
        if operational.phase() == HostServicePhase::Ready
            && self.transport.health != RhiTransportHealthV1::Ready
        {
            return Err(RhiStatusError::new(RhiStatusErrorKind::InvalidLifecycle));
        }
        let operations_metrics = bounded_operations_metrics(&operational)?;
        let detail = RhiStatusDetailV1 {
            identity: self.provider.identity.clone(),
            reconciliation: self.reconciliation,
            publication: self.publication,
            presence: self.presence,
        };
        let service = ServiceId::new("rhi")
            .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::InvalidModel))?;
        let status = ServiceStatus::new(
            service,
            instance.clone(),
            self.common.operational,
            self.common.uptime,
            self.common.build,
            self.common.configuration,
            self.common.persistence,
            self.provider,
            self.transport,
            detail,
        )
        .map_err(map_model_error)?;
        let json = status.to_bounded_json().map_err(map_encoding_error)?;
        Ok(PreparedRhiStatus {
            detail: CachedServiceState::new(
                operational.clone(),
                RhiCachedStatus {
                    json: json.into_boxed_slice(),
                },
            ),
            operations: CachedServiceState::new(operational, operations_metrics),
        })
    }
}

impl fmt::Debug for RhiStatusObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiStatusObservationV1([redacted])")
    }
}

struct RhiCachedStatus {
    json: Box<[u8]>,
}

struct PreparedRhiStatus {
    detail: CachedServiceState<RhiCachedStatus>,
    operations: CachedServiceState<BoundedMetricsSnapshot>,
}

fn bounded_operations_metrics(
    operational: &HostServiceOperationalState,
) -> Result<BoundedMetricsSnapshot, RhiStatusError> {
    let phase_name = MetricName::new("radroots_rhi_service_phase").map_err(map_metrics_error)?;
    let ready_name = MetricName::new("radroots_rhi_service_ready").map_err(map_metrics_error)?;
    let descriptors = [
        MetricDescriptor::new(
            CommonMetricGroup::Phase,
            phase_name.clone(),
            "Current cached Rhi service phase.",
            MetricKind::Gauge,
            [MetricLabelKey::Phase],
        )
        .map_err(map_metrics_error)?,
        MetricDescriptor::new(
            CommonMetricGroup::Phase,
            ready_name.clone(),
            "Current cached Rhi readiness bit.",
            MetricKind::Gauge,
            [],
        )
        .map_err(map_metrics_error)?,
    ];
    let samples = [
        MetricSample::new(
            phase_name,
            MetricValue::Gauge(1),
            [MetricLabel::phase(operational.phase())],
        )
        .map_err(map_metrics_error)?,
        MetricSample::new(
            ready_name,
            MetricValue::Gauge(i64::from(operational.readiness().is_ready())),
            [],
        )
        .map_err(map_metrics_error)?,
    ];
    BoundedMetricsSnapshot::new(descriptors, samples).map_err(map_metrics_error)
}

fn map_metrics_error(_: radroots_service_host::MetricsContractError) -> RhiStatusError {
    RhiStatusError::new(RhiStatusErrorKind::InvalidModel)
}

impl fmt::Debug for RhiCachedStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiCachedStatus")
            .field("json_utf8_bytes", &self.json.len())
            .finish()
    }
}

/// Sole publication authority for one process-local Rhi status cache.
///
/// This type deliberately does not implement `Clone`. A successful publish
/// atomically replaces the one retained snapshot. A failed encoding or illegal
/// lifecycle transition leaves the previous snapshot unchanged.
pub struct RhiStatusPublisher {
    instance: InstanceId,
    inner: CachedServiceStatePublisher<RhiCachedStatus>,
    operations: CachedServiceStatePublisher<BoundedMetricsSnapshot>,
}

impl RhiStatusPublisher {
    /// Encodes one observation, publishes its passive operations projection,
    /// and then atomically replaces the detailed-status snapshot.
    pub fn publish(&mut self, next: RhiStatusObservationV1) -> Result<(), RhiStatusError> {
        let next = next.into_cached(&self.instance)?;
        self.operations
            .publish(next.operations)
            .map_err(map_contract_error)?;
        self.inner.publish(next.detail).map_err(map_contract_error)
    }

    /// Creates another passive reader without sharing publication authority.
    #[must_use]
    pub fn subscribe(&self) -> RhiStatusReader {
        RhiStatusReader {
            inner: self.inner.subscribe(),
            operations: self.operations.subscribe(),
        }
    }
}

impl fmt::Debug for RhiStatusPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiStatusPublisher([sealed])")
    }
}

/// Cloneable passive reader of the latest Rhi lifecycle and detailed status.
pub struct RhiStatusReader {
    inner: CachedServiceStateReader<RhiCachedStatus>,
    operations: CachedServiceStateReader<BoundedMetricsSnapshot>,
}

impl Clone for RhiStatusReader {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            operations: self.operations.clone(),
        }
    }
}

impl RhiStatusReader {
    /// Returns the latest immutable snapshot without awaiting or probing.
    #[must_use]
    pub fn snapshot(&self) -> RhiStatusSnapshot {
        RhiStatusSnapshot {
            inner: self.inner.snapshot(),
        }
    }

    /// Waits for a later publication and returns the newest retained value.
    pub async fn changed(&mut self) -> Result<RhiStatusSnapshot, RhiStatusError> {
        self.inner
            .changed()
            .await
            .map(|inner| RhiStatusSnapshot { inner })
            .map_err(|_| RhiStatusError::new(RhiStatusErrorKind::PublisherDropped))
    }

    pub(crate) fn operations_cache(&self) -> CachedServiceStateReader<BoundedMetricsSnapshot> {
        self.operations.clone()
    }
}

impl fmt::Debug for RhiStatusReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiStatusReader([passive])")
    }
}

/// One immutable point-in-time status snapshot backed by the retained cache `Arc`.
pub struct RhiStatusSnapshot {
    inner: Arc<CachedServiceState<RhiCachedStatus>>,
}

impl RhiStatusSnapshot {
    #[must_use]
    pub fn phase(&self) -> RhiServicePhase {
        RhiServicePhase::from_host(self.inner.operational().phase())
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.inner.operational().readiness().is_ready()
    }

    /// Returns the already-bounded canonical detailed-status JSON bytes.
    #[must_use]
    pub fn detailed_status_json(&self) -> &[u8] {
        &self.inner.metrics().json
    }
}

impl fmt::Debug for RhiStatusSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStatusSnapshot")
            .field("phase", &self.phase())
            .field("ready", &self.is_ready())
            .field("json_utf8_bytes", &self.detailed_status_json().len())
            .finish()
    }
}

/// Creates the single-writer, one-latest-value Rhi status cache.
pub fn rhi_status_cache(
    instance: InstanceId,
    initial: RhiStatusObservationV1,
) -> Result<(RhiStatusPublisher, RhiStatusReader), RhiStatusError> {
    let initial = initial.into_cached(&instance)?;
    let (inner, reader) = cached_service_state(initial.detail);
    let (operations, operations_reader) = cached_service_state(initial.operations);
    Ok((
        RhiStatusPublisher {
            instance,
            inner,
            operations,
        },
        RhiStatusReader {
            inner: reader,
            operations: operations_reader,
        },
    ))
}

/// Stable source-free status failure category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiStatusErrorKind {
    InvalidReasonCode,
    TooManyReasonCodes,
    InvalidLifecycle,
    InvalidBuildInfo,
    InvalidConfiguration,
    InvalidPersistence,
    InvalidIdentityHealth,
    InvalidProviderState,
    InvalidTransportState,
    InvalidTime,
    InvalidModel,
    Encoding,
    ResponseTooLarge,
    InvalidTransition,
    PublisherDropped,
}

impl RhiStatusErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidReasonCode => "status_reason_code_invalid",
            Self::TooManyReasonCodes => "status_reason_count_exceeded",
            Self::InvalidLifecycle => "status_lifecycle_invalid",
            Self::InvalidBuildInfo => "status_build_info_invalid",
            Self::InvalidConfiguration => "status_configuration_invalid",
            Self::InvalidPersistence => "status_persistence_invalid",
            Self::InvalidIdentityHealth => "status_identity_health_invalid",
            Self::InvalidProviderState => "status_provider_state_invalid",
            Self::InvalidTransportState => "status_transport_state_invalid",
            Self::InvalidTime => "status_time_invalid",
            Self::InvalidModel => "status_model_invalid",
            Self::Encoding => "status_encoding_failed",
            Self::ResponseTooLarge => "status_response_too_large",
            Self::InvalidTransition => "status_transition_invalid",
            Self::PublisherDropped => "status_publisher_dropped",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidReasonCode => "Rhi status reason code is invalid",
            Self::TooManyReasonCodes => "Rhi status has too many reason codes",
            Self::InvalidLifecycle => "Rhi lifecycle status is invalid",
            Self::InvalidBuildInfo => "Rhi status build identity is invalid",
            Self::InvalidConfiguration => "Rhi status configuration identity is invalid",
            Self::InvalidPersistence => "Rhi persistence status is invalid",
            Self::InvalidIdentityHealth => "Rhi identity health is invalid",
            Self::InvalidProviderState => "Rhi provider status is invalid",
            Self::InvalidTransportState => "Rhi transport status is invalid",
            Self::InvalidTime => "Rhi status time is invalid",
            Self::InvalidModel => "Rhi detailed status is invalid",
            Self::Encoding => "Rhi detailed status encoding failed",
            Self::ResponseTooLarge => "Rhi detailed status exceeds its byte limit",
            Self::InvalidTransition => "Rhi lifecycle transition is invalid",
            Self::PublisherDropped => "Rhi status publisher is unavailable",
        }
    }
}

/// One redacted source-free status failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiStatusError {
    kind: RhiStatusErrorKind,
}

impl RhiStatusError {
    const fn new(kind: RhiStatusErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RhiStatusErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for RhiStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiStatusError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiStatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for RhiStatusError {}

const fn map_model_error(_error: StatusModelError) -> RhiStatusError {
    RhiStatusError::new(RhiStatusErrorKind::InvalidModel)
}

const fn map_encoding_error(error: StatusEncodingError) -> RhiStatusError {
    match error {
        StatusEncodingError::EncodingFailed => RhiStatusError::new(RhiStatusErrorKind::Encoding),
        StatusEncodingError::ResponseTooLarge => {
            RhiStatusError::new(RhiStatusErrorKind::ResponseTooLarge)
        }
    }
}

const fn map_contract_error(_error: StatusContractError) -> RhiStatusError {
    RhiStatusError::new(RhiStatusErrorKind::InvalidTransition)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_status_inputs_fail_with_safe_source_free_errors() {
        assert_eq!(
            RhiIdentityHealthV1::new(false, true, RhiStatusReasonCodes::empty()),
            Err(RhiStatusError::new(
                RhiStatusErrorKind::InvalidIdentityHealth
            ))
        );
        assert_eq!(
            RhiProviderStatusV1::new(
                RhiIdentityHealthV1::new(false, false, RhiStatusReasonCodes::empty()).unwrap(),
                RhiStatusReasonCodes::empty(),
            ),
            Err(RhiStatusError::new(
                RhiStatusErrorKind::InvalidProviderState
            ))
        );
        assert_eq!(
            RhiEvidenceTransportStatusV1::new(
                RhiTransportHealthV1::Ready,
                false,
                true,
                1,
                0,
                RhiStatusReasonCodes::empty(),
            ),
            Err(RhiStatusError::new(
                RhiStatusErrorKind::InvalidTransportState
            ))
        );
        assert_eq!(
            RhiEvidenceTransportStatusV1::new(
                RhiTransportHealthV1::Ready,
                true,
                true,
                1,
                2,
                RhiStatusReasonCodes::empty(),
            ),
            Err(RhiStatusError::new(
                RhiStatusErrorKind::InvalidTransportState
            ))
        );
        assert_eq!(
            RhiStatusUnixSeconds::new(i64::MAX as u64 + 1),
            Err(RhiStatusError::new(RhiStatusErrorKind::InvalidTime))
        );
        for kind in [
            RhiStatusErrorKind::InvalidReasonCode,
            RhiStatusErrorKind::TooManyReasonCodes,
            RhiStatusErrorKind::InvalidLifecycle,
            RhiStatusErrorKind::InvalidBuildInfo,
            RhiStatusErrorKind::InvalidConfiguration,
            RhiStatusErrorKind::InvalidPersistence,
            RhiStatusErrorKind::InvalidIdentityHealth,
            RhiStatusErrorKind::InvalidProviderState,
            RhiStatusErrorKind::InvalidTransportState,
            RhiStatusErrorKind::InvalidTime,
            RhiStatusErrorKind::InvalidModel,
            RhiStatusErrorKind::Encoding,
            RhiStatusErrorKind::ResponseTooLarge,
            RhiStatusErrorKind::InvalidTransition,
            RhiStatusErrorKind::PublisherDropped,
        ] {
            let error = RhiStatusError::new(kind);
            assert!(!error.code().is_empty());
            assert!(Error::source(&error).is_none());
            assert!(!format!("{error} {error:?}").contains("source"));
        }
    }
}
