//! Exact RHI v1 Unix-admin route and model boundary.

use core::{fmt, future::Future, pin::Pin, time::Duration};
use std::{
    collections::BTreeSet,
    error::Error,
    sync::{Arc, OnceLock},
};

use radroots_service_host::{
    AdminCorrelationId, AdminError, AdminErrorCode, AdminErrorMessage, AdminHttpMethod,
    AdminMutationRequest, AdminOperationId, AdminRequest, AdminRouteFailure,
    AdminRouteFailureStatus, AdminRouteOutcome, AdminRouter as SharedAdminRouter,
    AdminServer as SharedAdminServer, AdminServerError as SharedAdminServerError,
    AdminTransportLimitValues, AdminTransportLimits, CancellationToken, UnixAdminSocketBinding,
    UnixAdminSocketWriterAuthority,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

// Original model admission is never permitted to exceed the complete response
// body cap enforced again by the shared host after envelope encoding.
const RHI_ADMIN_RESPONSE_BODY_MAX_UTF8_BYTES: usize = 1_048_576;

const OPERATOR_CONTRACT: &str =
    include_str!("../contracts/services_hardening/operator_contract.v1.json");

/// Closed RHI v1 admin method vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RhiAdminMethod {
    Get,
    Post,
}

/// Closed RHI v1 Unix-admin route inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RhiAdminRoute {
    Status,
    EffectiveConfig,
    IdentityStatus,
    IdentityPublic,
    StateStatus,
    StateBackup,
    MetricsSnapshot,
    ReconciliationStatus,
    ReconciliationJobs,
    ReconciliationRefresh,
    Sources,
    TradeProjection,
    TradeReportCurrent,
    TradeReports,
    PublicationBacklog,
    PublicationTargets,
    PublicationRetry,
    PresenceDesired,
    PresenceRender,
    PresenceRefresh,
}

impl RhiAdminRoute {
    /// Complete final machine-governed route inventory.
    pub const ALL: [Self; 20] = [
        Self::Status,
        Self::EffectiveConfig,
        Self::IdentityStatus,
        Self::IdentityPublic,
        Self::StateStatus,
        Self::StateBackup,
        Self::MetricsSnapshot,
        Self::ReconciliationStatus,
        Self::ReconciliationJobs,
        Self::ReconciliationRefresh,
        Self::Sources,
        Self::TradeProjection,
        Self::TradeReportCurrent,
        Self::TradeReports,
        Self::PublicationBacklog,
        Self::PublicationTargets,
        Self::PublicationRetry,
        Self::PresenceDesired,
        Self::PresenceRender,
        Self::PresenceRefresh,
    ];

    /// Common routes admitted by the Step 206 partial control surface.
    pub const COMMON: [Self; 7] = [
        Self::Status,
        Self::EffectiveConfig,
        Self::IdentityStatus,
        Self::IdentityPublic,
        Self::StateStatus,
        Self::StateBackup,
        Self::MetricsSnapshot,
    ];

    /// Domain routes admitted by the Step 207 control surface.
    pub const DOMAIN: [Self; 13] = [
        Self::ReconciliationStatus,
        Self::ReconciliationJobs,
        Self::ReconciliationRefresh,
        Self::Sources,
        Self::TradeProjection,
        Self::TradeReportCurrent,
        Self::TradeReports,
        Self::PublicationBacklog,
        Self::PublicationTargets,
        Self::PublicationRetry,
        Self::PresenceDesired,
        Self::PresenceRender,
        Self::PresenceRefresh,
    ];

    /// Routes admitted through Step 208, in final machine-contract order.
    pub const ACTIVE: [Self; 20] = Self::ALL;

    #[must_use]
    pub const fn method(self) -> RhiAdminMethod {
        match self {
            Self::Status
            | Self::EffectiveConfig
            | Self::IdentityStatus
            | Self::IdentityPublic
            | Self::StateStatus
            | Self::MetricsSnapshot
            | Self::ReconciliationStatus
            | Self::ReconciliationJobs
            | Self::Sources
            | Self::TradeProjection
            | Self::TradeReportCurrent
            | Self::TradeReports
            | Self::PublicationBacklog
            | Self::PublicationTargets
            | Self::PresenceDesired => RhiAdminMethod::Get,
            Self::StateBackup
            | Self::ReconciliationRefresh
            | Self::PublicationRetry
            | Self::PresenceRender
            | Self::PresenceRefresh => RhiAdminMethod::Post,
        }
    }

    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Status => "/v1/status",
            Self::EffectiveConfig => "/v1/config/effective",
            Self::IdentityStatus => "/v1/identity/status",
            Self::IdentityPublic => "/v1/identity/public",
            Self::StateStatus => "/v1/state/status",
            Self::StateBackup => "/v1/state/backup",
            Self::MetricsSnapshot => "/v1/metrics/snapshot",
            Self::ReconciliationStatus => "/v1/reconciliation/status",
            Self::ReconciliationJobs => "/v1/reconciliation/jobs",
            Self::ReconciliationRefresh => "/v1/reconciliation/refresh",
            Self::Sources => "/v1/sources",
            Self::TradeProjection => "/v1/trades/{trade_id}/projection",
            Self::TradeReportCurrent => "/v1/trades/{trade_id}/reports/current",
            Self::TradeReports => "/v1/trades/{trade_id}/reports",
            Self::PublicationBacklog => "/v1/publication/backlog",
            Self::PublicationTargets => "/v1/publication/targets",
            Self::PublicationRetry => "/v1/publication/retry",
            Self::PresenceDesired => "/v1/presence/desired",
            Self::PresenceRender => "/v1/presence/render",
            Self::PresenceRefresh => "/v1/presence/refresh",
        }
    }

    #[must_use]
    pub const fn operation_id(self) -> &'static str {
        match self {
            Self::Status => "radroots.rhi.status.get.v1",
            Self::EffectiveConfig => "radroots.rhi.config.effective.get.v1",
            Self::IdentityStatus => "radroots.rhi.identity.status.get.v1",
            Self::IdentityPublic => "radroots.rhi.identity.public.get.v1",
            Self::StateStatus => "radroots.rhi.state.status.get.v1",
            Self::StateBackup => "radroots.rhi.state.backup.create.v1",
            Self::MetricsSnapshot => "radroots.rhi.metrics.snapshot.get.v1",
            Self::ReconciliationStatus => "radroots.rhi.reconciliation.status.get.v1",
            Self::ReconciliationJobs => "radroots.rhi.reconciliation.jobs.list.v1",
            Self::ReconciliationRefresh => "radroots.rhi.reconciliation.refresh.v1",
            Self::Sources => "radroots.rhi.sources.list.v1",
            Self::TradeProjection => "radroots.rhi.trade.projection.get.v1",
            Self::TradeReportCurrent => "radroots.rhi.trade.report.current.get.v1",
            Self::TradeReports => "radroots.rhi.trade.reports.list.v1",
            Self::PublicationBacklog => "radroots.rhi.publication.backlog.list.v1",
            Self::PublicationTargets => "radroots.rhi.publication.targets.list.v1",
            Self::PublicationRetry => "radroots.rhi.publication.retry.v1",
            Self::PresenceDesired => "radroots.rhi.presence.desired.get.v1",
            Self::PresenceRender => "radroots.rhi.presence.render.v1",
            Self::PresenceRefresh => "radroots.rhi.presence.refresh.v1",
        }
    }

    #[must_use]
    pub const fn request_model(self) -> &'static str {
        match self {
            Self::Status
            | Self::EffectiveConfig
            | Self::StateStatus
            | Self::MetricsSnapshot
            | Self::ReconciliationStatus
            | Self::TradeProjection
            | Self::TradeReportCurrent
            | Self::PresenceDesired => "empty",
            Self::IdentityStatus => "identity_status_query_v1",
            Self::IdentityPublic => "identity_public_query_v1",
            Self::StateBackup => "state_backup_request_v1",
            Self::ReconciliationJobs => "reconciliation_jobs_query_v1",
            Self::ReconciliationRefresh => "reconciliation_refresh_request_v1",
            Self::Sources => "sources_query_v1",
            Self::TradeReports => "reports_query_v1",
            Self::PublicationBacklog => "publication_backlog_query_v1",
            Self::PublicationTargets => "publication_targets_query_v1",
            Self::PublicationRetry => "publication_retry_request_v1",
            Self::PresenceRender => "presence_render_request_v1",
            Self::PresenceRefresh => "presence_refresh_request_v1",
        }
    }

    #[must_use]
    pub const fn response_model(self) -> &'static str {
        match self {
            Self::Status => "service_status_v1",
            Self::EffectiveConfig => "effective_config_v1",
            Self::IdentityStatus => "identity_status_v1",
            Self::IdentityPublic => "identity_public_v1",
            Self::StateStatus => "state_status_v1",
            Self::StateBackup => "state_backup_receipt_v1",
            Self::MetricsSnapshot => "metrics_snapshot_v1",
            Self::ReconciliationStatus => "reconciliation_status_v1",
            Self::ReconciliationJobs => "reconciliation_jobs_page_v1",
            Self::ReconciliationRefresh => "reconciliation_refresh_receipt_v1",
            Self::Sources => "sources_page_v1",
            Self::TradeProjection => "trade_projection_v1",
            Self::TradeReportCurrent => "report_detail_v1",
            Self::TradeReports => "reports_page_v1",
            Self::PublicationBacklog => "publication_backlog_page_v1",
            Self::PublicationTargets => "publication_targets_page_v1",
            Self::PublicationRetry => "publication_retry_receipt_v1",
            Self::PresenceDesired => "presence_desired_v1",
            Self::PresenceRender => "presence_render_receipt_v1",
            Self::PresenceRefresh => "presence_refresh_receipt_v1",
        }
    }

    #[must_use]
    pub const fn is_mutation(self) -> bool {
        matches!(self.method(), RhiAdminMethod::Post)
    }

    const fn host_method(self) -> AdminHttpMethod {
        match self.method() {
            RhiAdminMethod::Get => AdminHttpMethod::Get,
            RhiAdminMethod::Post => AdminHttpMethod::Post,
        }
    }

    const fn parameter_binding(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::TradeProjection | Self::TradeReportCurrent | Self::TradeReports => {
                Some(("trade_id", "trade_id"))
            }
            _ => None,
        }
    }
}

/// One route-bound, already validated RHI admin request.
///
/// Construction is sealed to an admitted request from the shared server:
///
/// ```compile_fail
/// use rhi::{RhiAdminRequestDocument, RhiAdminRoute};
///
/// let _ = RhiAdminRequestDocument {
///     route: RhiAdminRoute::Status,
///     operation_id: None,
///     correlation_id: todo!(),
///     parameter: None,
///     model_bytes: Box::new([]),
/// };
/// ```
pub struct RhiAdminRequestDocument {
    route: RhiAdminRoute,
    operation_id: Option<AdminOperationId>,
    correlation_id: AdminCorrelationId,
    parameter: Option<(&'static str, Box<str>)>,
    model_bytes: Box<[u8]>,
}

impl RhiAdminRequestDocument {
    #[must_use]
    pub const fn route(&self) -> RhiAdminRoute {
        self.route
    }

    /// Returns the caller's durable idempotency identity for a mutation.
    #[must_use]
    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_ref().map(AdminOperationId::as_str)
    }

    #[must_use]
    pub fn correlation_id(&self) -> &str {
        self.correlation_id.as_str()
    }

    /// Returns a validated percent-decoded path parameter when this route has one.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameter
            .as_ref()
            .filter(|(parameter_name, _)| *parameter_name == name)
            .map(|(_, value)| value.as_ref())
    }

    /// Returns compact canonical JSON for the route's exact request model.
    #[must_use]
    pub fn model_bytes(&self) -> &[u8] {
        &self.model_bytes
    }
}

impl fmt::Debug for RhiAdminRequestDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiAdminRequestDocument")
            .field("route", &self.route)
            .field("mutation", &self.operation_id.is_some())
            .field("has_parameter", &self.parameter.is_some())
            .field("model", &"[redacted]")
            .finish()
    }
}

/// One exact validated response model for a fixed route.
pub struct RhiAdminResponseDocument {
    route: RhiAdminRoute,
    canonical_bytes: Box<[u8]>,
    value: Value,
}

impl RhiAdminResponseDocument {
    /// Admits only compact canonical JSON matching the route's response model.
    pub fn from_canonical_bytes(
        route: RhiAdminRoute,
        bytes: &[u8],
    ) -> Result<Self, RhiAdminDocumentError> {
        if bytes.is_empty() {
            return Err(RhiAdminDocumentError::new(
                RhiAdminDocumentErrorKind::Malformed,
            ));
        }
        if bytes.len() > RHI_ADMIN_RESPONSE_BODY_MAX_UTF8_BYTES {
            return Err(RhiAdminDocumentError::new(
                RhiAdminDocumentErrorKind::TooLarge,
            ));
        }
        let value = strict_json(bytes)?;
        validate_model(route.response_model(), &value)?;
        let canonical = serde_json::to_vec(&value)
            .map_err(|_| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::Malformed))?;
        if canonical.as_slice() != bytes {
            return Err(RhiAdminDocumentError::new(
                RhiAdminDocumentErrorKind::NonCanonical,
            ));
        }
        Ok(Self {
            route,
            canonical_bytes: canonical.into_boxed_slice(),
            value,
        })
    }

    #[must_use]
    pub const fn route(&self) -> RhiAdminRoute {
        self.route
    }

    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
}

impl fmt::Debug for RhiAdminResponseDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiAdminResponseDocument")
            .field("route", &self.route)
            .field("model", &"[redacted]")
            .finish()
    }
}

/// Stable classification for a rejected RHI admin document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiAdminDocumentErrorKind {
    TooLarge,
    Malformed,
    DuplicateField,
    NullForbidden,
    NonCanonical,
    InvalidModel,
}

/// Source-free and content-free RHI admin document error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiAdminDocumentError {
    kind: RhiAdminDocumentErrorKind,
}

impl RhiAdminDocumentError {
    const fn new(kind: RhiAdminDocumentErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RhiAdminDocumentErrorKind {
        self.kind
    }
}

impl fmt::Display for RhiAdminDocumentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RHI admin document is invalid")
    }
}

impl Error for RhiAdminDocumentError {}

/// Stable route-handler failure mapped to a bounded safe admin response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiAdminHandlerErrorKind {
    InvalidCursor,
    OperationIdConflict,
    NotFound,
    Conflict,
    Unavailable,
    Internal,
}

/// Source-free route-handler error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiAdminHandlerError {
    kind: RhiAdminHandlerErrorKind,
}

impl RhiAdminHandlerError {
    #[must_use]
    pub const fn new(kind: RhiAdminHandlerErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RhiAdminHandlerErrorKind {
        self.kind
    }
}

impl fmt::Display for RhiAdminHandlerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RHI admin operation failed")
    }
}

impl Error for RhiAdminHandlerError {}

/// Boxed route future used by the sealed RHI admin adapter.
pub type RhiAdminFuture<'a> = Pin<
    Box<dyn Future<Output = Result<RhiAdminResponseDocument, RhiAdminHandlerError>> + Send + 'a>,
>;

/// Domain port behind the exact RHI admin transport.
///
/// Implementations own authoritative local commit, durable operation-ID
/// replay/conflict handling, and any provider or outbox orchestration. Returning
/// success means that the operation's contract-defined local effect is already
/// committed; relay submission or delivery is not implied. Pagination cursors
/// must be authenticated and bound to the same route, filters, and snapshot;
/// mismatched or invalid cursors return [`RhiAdminHandlerErrorKind::InvalidCursor`].
/// Reusing an operation ID with identical canonical request bytes returns the
/// original committed response; reuse with different bytes returns
/// [`RhiAdminHandlerErrorKind::OperationIdConflict`].
pub trait RhiAdminHandler: Send + Sync + 'static {
    fn handle<'a>(&'a self, request: RhiAdminRequestDocument) -> RhiAdminFuture<'a>;
}

/// Source-free router-construction failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RhiAdminRouterError;

impl fmt::Display for RhiAdminRouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RHI admin router could not be constructed")
    }
}

impl Error for RhiAdminRouterError {}

/// Opaque RHI v1 router capability through Step 208.
///
/// The underlying shared-host router remains an implementation detail. The
/// later runtime-composition checkpoint consumes this capability without
/// exposing raw listener or transport authority.
///
/// ```compile_fail
/// use rhi::RhiAdminRouter;
///
/// let _ = RhiAdminRouter { inner: todo!() };
/// ```
pub struct RhiAdminRouter {
    inner: SharedAdminRouter,
}

impl fmt::Debug for RhiAdminRouter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { inner } = self;
        let _ = inner;
        formatter.write_str("RhiAdminRouter")
    }
}

impl RhiAdminRouter {
    fn into_inner(self) -> SharedAdminRouter {
        self.inner
    }
}

/// Cloneable cooperative cancellation for the RHI Unix-admin server.
#[derive(Clone, Default)]
pub struct RhiAdminCancellationToken {
    inner: CancellationToken,
}

impl RhiAdminCancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Repeated requests have no additional effect.
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
}

impl fmt::Debug for RhiAdminCancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiAdminCancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Stable source-free RHI Unix-admin server failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiAdminServerErrorKind {
    InvalidConfiguration,
    Router,
    ServerConfiguration,
    WriterAuthority,
    Bind,
    Listener,
    Accept,
    ConnectionTaskPanicked,
}

impl RhiAdminServerErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "admin_configuration_invalid",
            Self::Router => "admin_router_invalid",
            Self::ServerConfiguration => "admin_server_configuration_invalid",
            Self::WriterAuthority => "admin_writer_authority_unavailable",
            Self::Bind => "admin_bind_failed",
            Self::Listener => "admin_listener_failed",
            Self::Accept => "admin_accept_failed",
            Self::ConnectionTaskPanicked => "admin_connection_task_panicked",
        }
    }
}

/// One redacted source-free RHI Unix-admin server failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiAdminServerError {
    kind: RhiAdminServerErrorKind,
}

impl RhiAdminServerError {
    const fn new(kind: RhiAdminServerErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RhiAdminServerErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for RhiAdminServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiAdminServerError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiAdminServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RHI Unix-admin server failed")
    }
}

impl Error for RhiAdminServerError {}

/// Unbound RHI Unix-admin server through Step 208.
///
/// Construction projects only the already-admitted Rhi configuration, seals
/// the exact route inventory around the supplied domain handler, and uses the
/// shared host's system entropy. The raw shared router and server never cross
/// this boundary.
pub struct RhiAdminServer {
    inner: SharedAdminServer,
}

impl RhiAdminServer {
    pub fn new<H>(
        configuration: &crate::RhiConfigDocumentV1,
        handler: Arc<H>,
    ) -> Result<Self, RhiAdminServerError>
    where
        H: RhiAdminHandler,
    {
        let limits = admin_transport_limits(configuration)?;
        let router = build_rhi_admin_router(handler)
            .map_err(|_| RhiAdminServerError::new(RhiAdminServerErrorKind::Router))?;
        let inner = SharedAdminServer::with_system_entropy(router.into_inner(), limits)
            .map_err(|_| RhiAdminServerError::new(RhiAdminServerErrorKind::ServerConfiguration))?;
        Ok(Self { inner })
    }

    /// Acquires the canonical runtime-directory authority and binds `admin.sock`.
    ///
    /// Binding does not spawn a task or begin request admission. Unit 15 owns
    /// the final supervised server task and its shutdown phase.
    pub async fn bind(
        self,
        runtime: &crate::RhiRuntimeContext,
    ) -> Result<RhiBoundAdminServer, RhiAdminServerError> {
        let authority = UnixAdminSocketWriterAuthority::acquire(runtime.context().paths().run())
            .map_err(|_| RhiAdminServerError::new(RhiAdminServerErrorKind::WriterAuthority))?;
        let binding = UnixAdminSocketBinding::bind(authority, runtime.artifacts().admin_socket())
            .await
            .map_err(|_| RhiAdminServerError::new(RhiAdminServerErrorKind::Bind))?;
        Ok(RhiBoundAdminServer {
            inner: self.inner,
            binding,
        })
    }
}

impl fmt::Debug for RhiAdminServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiAdminServer([sealed])")
    }
}

/// Bound RHI Unix-admin server through Step 208.
pub struct RhiBoundAdminServer {
    inner: SharedAdminServer,
    binding: UnixAdminSocketBinding,
}

impl RhiBoundAdminServer {
    /// Serves until supervisor cancellation and then drains bounded connection work.
    pub async fn serve(
        self,
        cancellation: RhiAdminCancellationToken,
    ) -> Result<(), RhiAdminServerError> {
        self.inner
            .serve(self.binding, cancellation.inner)
            .await
            .map_err(map_admin_server_error)
    }
}

impl fmt::Debug for RhiBoundAdminServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiBoundAdminServer([sealed])")
    }
}

/// Registers the final seven common and thirteen domain routes through Step 208.
///
/// Live identity rekey and replace are absent by final offline-only policy.
pub fn build_rhi_admin_router<H>(handler: Arc<H>) -> Result<RhiAdminRouter, RhiAdminRouterError>
where
    H: RhiAdminHandler,
{
    if !operator_route_inventory_is_exact() {
        return Err(RhiAdminRouterError);
    }
    let mut router = SharedAdminRouter::new();
    for route in RhiAdminRoute::ACTIVE {
        let handler = Arc::clone(&handler);
        router
            .route(route.host_method(), route.path(), move |request| {
                let handler = Arc::clone(&handler);
                async move { dispatch_route(route, handler, request).await }
            })
            .map_err(|_| RhiAdminRouterError)?;
    }
    Ok(RhiAdminRouter { inner: router })
}

pub(crate) fn admin_transport_limits(
    configuration: &crate::RhiConfigDocumentV1,
) -> Result<AdminTransportLimits, RhiAdminServerError> {
    let admin = configuration
        .normalized()
        .pointer("/resource_limits/admin")
        .ok_or_else(invalid_admin_configuration)?;
    let values = AdminTransportLimitValues {
        header_count: admin_u32(admin, "/header_count")?,
        header_bytes: admin_u32(admin, "/header_bytes")?,
        request_body_utf8_bytes: admin_u32(admin, "/request_body_utf8_bytes")?,
        response_body_utf8_bytes: admin_u32(admin, "/response_body_utf8_bytes")?,
        concurrent_connections: admin_u32(admin, "/concurrent_connections")?,
        request_deadline: Duration::from_millis(admin_u64(admin, "/request_deadline_ms")?),
        idle_timeout: Duration::from_millis(admin_u64(admin, "/idle_timeout_ms")?),
        query_items: admin_u32(admin, "/query_items")?,
    };
    AdminTransportLimits::new(values).map_err(|_| invalid_admin_configuration())
}

fn admin_u64(value: &Value, pointer: &str) -> Result<u64, RhiAdminServerError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(invalid_admin_configuration)
}

fn admin_u32(value: &Value, pointer: &str) -> Result<u32, RhiAdminServerError> {
    u32::try_from(admin_u64(value, pointer)?).map_err(|_| invalid_admin_configuration())
}

const fn invalid_admin_configuration() -> RhiAdminServerError {
    RhiAdminServerError::new(RhiAdminServerErrorKind::InvalidConfiguration)
}

const fn map_admin_server_error(error: SharedAdminServerError) -> RhiAdminServerError {
    let kind = match error {
        SharedAdminServerError::ListenerClone { .. }
        | SharedAdminServerError::ListenerRegistration { .. } => RhiAdminServerErrorKind::Listener,
        SharedAdminServerError::Accept { .. } => RhiAdminServerErrorKind::Accept,
        SharedAdminServerError::ConnectionTaskPanicked => {
            RhiAdminServerErrorKind::ConnectionTaskPanicked
        }
    };
    RhiAdminServerError::new(kind)
}

async fn dispatch_route<H>(
    route: RhiAdminRoute,
    handler: Arc<H>,
    request: AdminRequest,
) -> AdminRouteOutcome
where
    H: RhiAdminHandler,
{
    let document = match request_document(route, &request) {
        Ok(document) => document,
        Err(_) => return failure(RhiAdminHandlerErrorKind::Conflict, true),
    };
    match handler.handle(document).await {
        Ok(response) if response.route == route => match request.success(&response.value) {
            Ok(outcome) => outcome,
            Err(_) => failure(RhiAdminHandlerErrorKind::Internal, false),
        },
        Ok(_) => failure(RhiAdminHandlerErrorKind::Internal, false),
        Err(error) => failure(error.kind, false),
    }
}

fn failure(kind: RhiAdminHandlerErrorKind, invalid_request: bool) -> AdminRouteOutcome {
    let (status, code, message) = if invalid_request {
        (
            AdminRouteFailureStatus::BadRequest,
            "invalid_request",
            "admin request does not match the route model",
        )
    } else {
        match kind {
            RhiAdminHandlerErrorKind::InvalidCursor => (
                AdminRouteFailureStatus::BadRequest,
                "invalid_cursor",
                "admin pagination cursor is invalid",
            ),
            RhiAdminHandlerErrorKind::OperationIdConflict => (
                AdminRouteFailureStatus::Conflict,
                "operation_id_conflict",
                "admin operation identity conflicts with retained state",
            ),
            RhiAdminHandlerErrorKind::NotFound => (
                AdminRouteFailureStatus::NotFound,
                "not_found",
                "admin resource was not found",
            ),
            RhiAdminHandlerErrorKind::Conflict => (
                AdminRouteFailureStatus::Conflict,
                "operation_conflict",
                "admin operation conflicts with current state",
            ),
            RhiAdminHandlerErrorKind::Unavailable => (
                AdminRouteFailureStatus::Unavailable,
                "service_unavailable",
                "admin operation is temporarily unavailable",
            ),
            RhiAdminHandlerErrorKind::Internal => (
                AdminRouteFailureStatus::Internal,
                "internal_error",
                "admin operation failed internally",
            ),
        }
    };
    let code = AdminErrorCode::new(code).expect("fixed admin error code");
    let message = AdminErrorMessage::new(message).expect("fixed admin error message");
    AdminRouteOutcome::failure(AdminRouteFailure::new(
        status,
        AdminError::new(code, message),
    ))
}

fn request_document(
    route: RhiAdminRoute,
    request: &AdminRequest,
) -> Result<RhiAdminRequestDocument, RhiAdminDocumentError> {
    let (operation_id, value) = match route.method() {
        RhiAdminMethod::Get => (None, query_model(route, request.query())?),
        RhiAdminMethod::Post => {
            let envelope = request
                .decode_json::<AdminMutationRequest<Value>>()
                .map_err(|_| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::Malformed))?;
            (
                Some(envelope.operation_id().clone()),
                envelope.into_request(),
            )
        }
    };
    validate_model(route.request_model(), &value)?;
    let model_bytes = serde_json::to_vec(&value)
        .map_err(|_| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::Malformed))?;
    let parameter = route
        .parameter_binding()
        .map(|(name, type_name)| {
            let value = request
                .parameter(name)
                .ok_or_else(|| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel))?
                .to_owned()
                .into_boxed_str();
            validate_type(type_name, &Value::String(value.to_string()), 0)?;
            Ok((name, value))
        })
        .transpose()?;
    Ok(RhiAdminRequestDocument {
        route,
        operation_id,
        correlation_id: request.correlation_id().clone(),
        parameter,
        model_bytes: model_bytes.into_boxed_slice(),
    })
}

fn query_model(route: RhiAdminRoute, query: Option<&str>) -> Result<Value, RhiAdminDocumentError> {
    let Some(query) = query else {
        return Ok(Value::Object(Map::new()));
    };
    if query.is_empty() {
        return Err(RhiAdminDocumentError::new(
            RhiAdminDocumentErrorKind::InvalidModel,
        ));
    }
    let fields = model_fields(route.request_model())?;
    let mut output = Map::new();
    for item in query.split('&') {
        let (raw_key, raw_value) = item
            .split_once('=')
            .ok_or_else(|| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel))?;
        if raw_key.is_empty()
            || !valid_percent_encoding(raw_key)
            || !valid_percent_encoding(raw_value)
        {
            return Err(RhiAdminDocumentError::new(
                RhiAdminDocumentErrorKind::InvalidModel,
            ));
        }
        let key = percent_decode(raw_key)?;
        let value = percent_decode(raw_value)?;
        if output.contains_key(&key) {
            return Err(RhiAdminDocumentError::new(
                RhiAdminDocumentErrorKind::DuplicateField,
            ));
        }
        let descriptor = fields
            .get(&key)
            .ok_or_else(|| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel))?;
        let type_name = descriptor
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel))?;
        output.insert(key, query_scalar(type_name, value)?);
    }
    Ok(Value::Object(output))
}

fn query_scalar(type_name: &str, value: String) -> Result<Value, RhiAdminDocumentError> {
    let descriptor = type_descriptor(type_name)?;
    match descriptor.get("kind").and_then(Value::as_str) {
        Some("integer") => {
            let canonical = value == "0"
                || (value.as_bytes().first().is_some_and(u8::is_ascii_digit)
                    && !value.starts_with('0')
                    && value.bytes().all(|byte| byte.is_ascii_digit()));
            if !canonical {
                return Err(RhiAdminDocumentError::new(
                    RhiAdminDocumentErrorKind::InvalidModel,
                ));
            }
            value
                .parse::<u64>()
                .map(Value::from)
                .map_err(|_| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel))
        }
        Some("boolean") => match value.as_str() {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ => Err(RhiAdminDocumentError::new(
                RhiAdminDocumentErrorKind::InvalidModel,
            )),
        },
        _ => Ok(Value::String(value)),
    }
}

fn percent_decode(value: &str) -> Result<String, RhiAdminDocumentError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let high = hex_nibble(bytes[index + 1]).ok_or_else(invalid_model_error)?;
                let low = hex_nibble(bytes[index + 2]).ok_or_else(invalid_model_error)?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| invalid_model_error())
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_percent_encoding(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn operator_contract() -> Result<&'static Value, RhiAdminDocumentError> {
    static CONTRACT: OnceLock<Option<Value>> = OnceLock::new();
    CONTRACT
        .get_or_init(|| serde_json::from_str(OPERATOR_CONTRACT).ok())
        .as_ref()
        .ok_or_else(invalid_model_error)
}

fn operator_route_inventory_is_exact() -> bool {
    let Ok(contract) = operator_contract() else {
        return false;
    };
    let Some(admin) = contract.get("admin") else {
        return false;
    };
    let Some(routes) = admin.get("routes").and_then(Value::as_array) else {
        return false;
    };
    let Some(models) = admin.get("models").and_then(Value::as_object) else {
        return false;
    };
    routes.len() == RhiAdminRoute::ALL.len()
        && models.len() == 33
        && admin
            .pointer("/model_wire_contract/response_body_max_utf8_bytes")
            .and_then(Value::as_u64)
            == Some(RHI_ADMIN_RESPONSE_BODY_MAX_UTF8_BYTES as u64)
        && routes.iter().zip(RhiAdminRoute::ALL).all(|(wire, route)| {
            wire.get("method").and_then(Value::as_str)
                == Some(match route.method() {
                    RhiAdminMethod::Get => "GET",
                    RhiAdminMethod::Post => "POST",
                })
                && wire.get("path").and_then(Value::as_str) == Some(route.path())
                && wire.get("operation_id").and_then(Value::as_str) == Some(route.operation_id())
                && wire.get("request_model").and_then(Value::as_str) == Some(route.request_model())
                && wire.get("response_model").and_then(Value::as_str)
                    == Some(route.response_model())
                && wire.get("mutation").and_then(Value::as_bool) == Some(route.is_mutation())
        })
}

fn model_fields(model_name: &str) -> Result<&'static Map<String, Value>, RhiAdminDocumentError> {
    operator_contract()?
        .pointer(&format!("/admin/models/{model_name}/fields"))
        .and_then(Value::as_object)
        .ok_or_else(|| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel))
}

fn type_descriptor(type_name: &str) -> Result<&'static Value, RhiAdminDocumentError> {
    operator_contract()?
        .pointer(&format!("/admin/types/{type_name}"))
        .ok_or_else(|| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel))
}

fn validate_model(model_name: &str, value: &Value) -> Result<(), RhiAdminDocumentError> {
    let object = value
        .as_object()
        .ok_or_else(|| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel))?;
    let fields = model_fields(model_name)?;
    for key in object.keys() {
        if !fields.contains_key(key) {
            return Err(RhiAdminDocumentError::new(
                RhiAdminDocumentErrorKind::InvalidModel,
            ));
        }
    }
    for (name, field) in fields {
        let required = field.get("presence").and_then(Value::as_str) == Some("required");
        let type_name = field
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel))?;
        match object.get(name) {
            Some(value) => validate_type(type_name, value, 0)?,
            None if required => {
                return Err(RhiAdminDocumentError::new(
                    RhiAdminDocumentErrorKind::InvalidModel,
                ));
            }
            None => {}
        }
    }
    Ok(())
}

fn validate_type(
    type_name: &str,
    value: &Value,
    depth: usize,
) -> Result<(), RhiAdminDocumentError> {
    if depth > 24 || value.is_null() {
        return Err(RhiAdminDocumentError::new(if value.is_null() {
            RhiAdminDocumentErrorKind::NullForbidden
        } else {
            RhiAdminDocumentErrorKind::InvalidModel
        }));
    }
    let descriptor = type_descriptor(type_name)?;
    match descriptor.get("kind").and_then(Value::as_str) {
        Some("literal") => {
            if descriptor.get("value") != Some(value) {
                return invalid_model();
            }
        }
        Some("boolean") => {
            if !value.is_boolean() {
                return invalid_model();
            }
        }
        Some("integer") => validate_integer(descriptor, value)?,
        Some("string") => validate_string(descriptor, value)?,
        Some("enum") => {
            if !descriptor
                .get("values")
                .and_then(Value::as_array)
                .is_some_and(|values| values.contains(value))
            {
                return invalid_model();
            }
        }
        Some("string_union") => validate_string_union(descriptor, value)?,
        Some("array") => validate_array(descriptor, value, depth + 1)?,
        Some("canonical_delimited_set") => {
            validate_delimited_set(descriptor, value, depth + 1)?;
        }
        Some("map") => validate_map(descriptor, value, depth + 1)?,
        Some("closed_object") => validate_closed_object(descriptor, value, depth + 1)?,
        Some("tagged_union") => validate_tagged_union(descriptor, value, depth + 1)?,
        Some("alias") => validate_type(
            descriptor
                .get("target")
                .and_then(Value::as_str)
                .ok_or_else(invalid_model_error)?,
            value,
            depth + 1,
        )?,
        Some("optional") => validate_type(
            descriptor
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(invalid_model_error)?,
            value,
            depth + 1,
        )?,
        Some("canonical_json_object") => {
            if !value.is_object()
                || serde_json::to_vec(value).ok().is_none_or(|bytes| {
                    bytes.len()
                        > descriptor
                            .get("maximum_utf8_bytes")
                            .and_then(Value::as_u64)
                            .and_then(|value| usize::try_from(value).ok())
                            .unwrap_or(0)
                })
            {
                return invalid_model();
            }
        }
        _ => return invalid_model(),
    }
    Ok(())
}

fn validate_integer(descriptor: &Value, value: &Value) -> Result<(), RhiAdminDocumentError> {
    let number = value.as_u64().ok_or_else(invalid_model_error)?;
    let minimum = descriptor
        .get("minimum")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let maximum = descriptor
        .get("maximum")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    if !(minimum..=maximum).contains(&number) {
        return invalid_model();
    }
    Ok(())
}

fn validate_string(descriptor: &Value, value: &Value) -> Result<(), RhiAdminDocumentError> {
    let string = value.as_str().ok_or_else(invalid_model_error)?;
    let exact = descriptor
        .get("utf8_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok());
    let minimum = descriptor
        .get("minimum_utf8_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    let maximum = descriptor
        .get("maximum_utf8_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(usize::MAX);
    if exact.is_some_and(|exact| string.len() != exact)
        || !(minimum..=maximum).contains(&string.len())
        || string.chars().any(char::is_control)
    {
        return invalid_model();
    }
    if let Some(pattern) = descriptor.get("pattern").and_then(Value::as_str) {
        let valid = match pattern {
            "^[A-Za-z0-9][A-Za-z0-9._:-]*$" => bounded_id(string),
            "^[a-z][a-z0-9_]*$" => safe_code(string),
            "^[a-z][a-z0-9_-]*$" => stable_id(string),
            "^[0-9a-f]{32}$" => lower_hex(string, 32),
            "^[0-9a-f]{64}$" => lower_hex(string, 64),
            "^[0-9a-f]{40}$" => lower_hex(string, 40),
            "^/" => string.starts_with('/'),
            _ => false,
        };
        if !valid {
            return invalid_model();
        }
    }
    if descriptor.get("encoding").and_then(Value::as_str) == Some("canonical_base64url_no_padding")
        && !canonical_base64url_no_padding(string)
    {
        return invalid_model();
    }
    if let Some(schemes) = descriptor.get("allowed_schemes").and_then(Value::as_array) {
        let parsed = url::Url::parse(string).map_err(|_| invalid_model_error())?;
        if !schemes
            .iter()
            .any(|scheme| scheme.as_str() == Some(parsed.scheme()))
        {
            return invalid_model();
        }
    }
    Ok(())
}

fn validate_string_union(descriptor: &Value, value: &Value) -> Result<(), RhiAdminDocumentError> {
    let string = value.as_str().ok_or_else(invalid_model_error)?;
    if descriptor
        .get("simple_values")
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(string)))
    {
        return Ok(());
    }
    let kind = string
        .strip_prefix("sign_event:kind:")
        .ok_or_else(invalid_model_error)?;
    if kind.is_empty()
        || (kind.len() > 1 && kind.starts_with('0'))
        || !kind.bytes().all(|byte| byte.is_ascii_digit())
        || kind.parse::<u32>().is_err()
        || string.len()
            > descriptor
                .get("maximum_utf8_bytes")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(0)
    {
        return invalid_model();
    }
    Ok(())
}

fn validate_array(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), RhiAdminDocumentError> {
    let values = value.as_array().ok_or_else(invalid_model_error)?;
    let maximum = descriptor
        .get("maximum_items")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    if values.len() > maximum {
        return invalid_model();
    }
    let item_type = descriptor
        .get("items")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    for item in values {
        validate_type(item_type, item, depth)?;
    }
    if descriptor.get("unique").and_then(Value::as_bool) == Some(true) {
        let mut unique = BTreeSet::new();
        for item in values {
            let encoded = serde_json::to_vec(item).map_err(|_| invalid_model_error())?;
            if !unique.insert(encoded) {
                return invalid_model();
            }
        }
    }
    if descriptor.get("canonical_sort").is_some() {
        let rendered = values
            .iter()
            .map(|value| value.as_str().ok_or_else(invalid_model_error))
            .collect::<Result<Vec<_>, _>>()?;
        if !rendered.windows(2).all(|pair| pair[0] < pair[1]) {
            return invalid_model();
        }
    }
    Ok(())
}

fn validate_delimited_set(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), RhiAdminDocumentError> {
    let rendered = value.as_str().ok_or_else(invalid_model_error)?;
    let maximum_bytes = descriptor
        .get("maximum_utf8_bytes")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    if rendered.len() > maximum_bytes {
        return invalid_model();
    }
    if rendered.is_empty() {
        return if descriptor.get("empty_allowed").and_then(Value::as_bool) == Some(true) {
            Ok(())
        } else {
            invalid_model()
        };
    }
    let delimiter = descriptor
        .get("delimiter")
        .and_then(Value::as_str)
        .filter(|delimiter| delimiter.len() == 1)
        .ok_or_else(invalid_model_error)?;
    let items = rendered.split(delimiter).collect::<Vec<_>>();
    let maximum_items = descriptor
        .get("maximum_items")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    if items.is_empty()
        || items.len() > maximum_items
        || items.iter().any(|item| item.is_empty())
        || !items.windows(2).all(|pair| pair[0] < pair[1])
    {
        return invalid_model();
    }
    let item_type = descriptor
        .get("items")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    for item in items {
        validate_type(item_type, &Value::String(item.to_owned()), depth)?;
    }
    Ok(())
}

fn validate_map(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), RhiAdminDocumentError> {
    let values = value.as_object().ok_or_else(invalid_model_error)?;
    let maximum_entries = descriptor
        .get("maximum_entries")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(0);
    if values.len() > maximum_entries {
        return invalid_model();
    }
    let key_type = descriptor
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    let value_type = descriptor
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    for (key, value) in values {
        validate_type(key_type, &Value::String(key.clone()), depth)?;
        validate_type(value_type, value, depth)?;
    }
    Ok(())
}

fn validate_closed_object(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), RhiAdminDocumentError> {
    let values = value.as_object().ok_or_else(invalid_model_error)?;
    let fields = descriptor
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(invalid_model_error)?;
    if values.keys().any(|key| !fields.contains_key(key)) {
        return invalid_model();
    }
    for (field, type_name) in fields {
        let type_name = type_name.as_str().ok_or_else(invalid_model_error)?;
        match values.get(field) {
            Some(value) => validate_type(type_name, value, depth)?,
            None if type_descriptor(type_name)?
                .get("kind")
                .and_then(Value::as_str)
                == Some("optional") => {}
            None => return invalid_model(),
        }
    }
    Ok(())
}

fn validate_tagged_union(
    descriptor: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), RhiAdminDocumentError> {
    let object = value.as_object().ok_or_else(invalid_model_error)?;
    let discriminator = descriptor
        .get("discriminator")
        .and_then(Value::as_str)
        .ok_or_else(invalid_model_error)?;
    let selected = object.get(discriminator).ok_or_else(invalid_model_error)?;
    let variants = descriptor
        .get("variants")
        .and_then(Value::as_array)
        .ok_or_else(invalid_model_error)?;
    let mut matched = None;
    for variant in variants {
        let variant = variant.as_str().ok_or_else(invalid_model_error)?;
        let fields = type_descriptor(variant)?
            .get("fields")
            .and_then(Value::as_object)
            .ok_or_else(invalid_model_error)?;
        let discriminator_type = fields
            .get(discriminator)
            .and_then(Value::as_str)
            .ok_or_else(invalid_model_error)?;
        if type_descriptor(discriminator_type)?.get("value") == Some(selected)
            && matched.replace(variant).is_some()
        {
            return invalid_model();
        }
    }
    validate_type(matched.ok_or_else(invalid_model_error)?, value, depth)
}

fn bounded_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn safe_code(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn stable_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn lower_hex(value: &str, exact: usize) -> bool {
    value.len() == exact
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_base64url_no_padding(value: &str) -> bool {
    if value.is_empty() || value.len() % 4 == 1 {
        return false;
    }
    let sextet = |byte: u8| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    let bytes = value.as_bytes();
    if bytes.iter().copied().any(|byte| sextet(byte).is_none()) {
        return false;
    }
    let Some(last) = sextet(bytes[bytes.len() - 1]) else {
        return false;
    };
    match value.len() % 4 {
        0 => true,
        2 => last & 0x0f == 0,
        3 => last & 0x03 == 0,
        _ => false,
    }
}

fn invalid_model<T>() -> Result<T, RhiAdminDocumentError> {
    Err(invalid_model_error())
}

const fn invalid_model_error() -> RhiAdminDocumentError {
    RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel)
}

const DUPLICATE_MARKER: &str = "rhi_admin_duplicate_field";
const NULL_MARKER: &str = "rhi_admin_null_forbidden";

fn strict_json(bytes: &[u8]) -> Result<Value, RhiAdminDocumentError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValueSeed
        .deserialize(&mut deserializer)
        .map_err(|error| {
            let message = error.to_string();
            if message.contains(DUPLICATE_MARKER) {
                RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::DuplicateField)
            } else if message.contains(NULL_MARKER) {
                RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::NullForbidden)
            } else {
                RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::Malformed)
            }
        })?;
    deserializer
        .end()
        .map_err(|_| RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::Malformed))?;
    Ok(value)
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a non-null JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(NULL_MARKER))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(NULL_MARKER))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(DUPLICATE_MARKER));
            }
            let value = object.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_model(model_name: &str) -> Value {
        let fields = model_fields(model_name).expect("governed model");
        let mut object = Map::new();
        for (name, field) in fields {
            if field.get("presence").and_then(Value::as_str) == Some("required") {
                let type_name = field
                    .get("type")
                    .and_then(Value::as_str)
                    .expect("field type");
                object.insert(name.clone(), sample_type(type_name).expect("required type"));
            }
        }
        Value::Object(object)
    }

    fn sample_type(type_name: &str) -> Option<Value> {
        let descriptor = type_descriptor(type_name).expect("governed type");
        match descriptor
            .get("kind")
            .and_then(Value::as_str)
            .expect("type kind")
        {
            "literal" => Some(descriptor.get("value").expect("literal value").clone()),
            "boolean" => Some(Value::Bool(false)),
            "integer" => Some(Value::from(
                descriptor
                    .get("minimum")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )),
            "string" => {
                let value = if descriptor.get("encoding").is_some() {
                    "AA".to_owned()
                } else if descriptor.get("allowed_schemes").is_some() {
                    "https://example.test/".to_owned()
                } else if descriptor.get("pattern").and_then(Value::as_str) == Some("^/") {
                    "/var/lib/radroots/rhi".to_owned()
                } else if let Some(length) = descriptor.get("utf8_bytes").and_then(Value::as_u64) {
                    "0".repeat(usize::try_from(length).expect("bounded sample length"))
                } else {
                    "x".to_owned()
                };
                Some(Value::String(value))
            }
            "enum" => descriptor
                .get("values")
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .cloned(),
            "string_union" => descriptor
                .get("simple_values")
                .and_then(Value::as_array)
                .and_then(|values| values.first())
                .cloned(),
            "array" => Some(Value::Array(Vec::new())),
            "canonical_delimited_set" => Some(Value::String(String::new())),
            "map" | "canonical_json_object" => Some(Value::Object(Map::new())),
            "closed_object" => {
                let mut object = Map::new();
                for (field, field_type) in descriptor
                    .get("fields")
                    .and_then(Value::as_object)
                    .expect("closed fields")
                {
                    if let Some(value) = sample_type(field_type.as_str().expect("closed type")) {
                        object.insert(field.clone(), value);
                    }
                }
                Some(Value::Object(object))
            }
            "tagged_union" => descriptor
                .get("variants")
                .and_then(Value::as_array)
                .and_then(|variants| variants.first())
                .and_then(Value::as_str)
                .and_then(sample_type),
            "alias" => descriptor
                .get("target")
                .and_then(Value::as_str)
                .and_then(sample_type),
            "optional" => None,
            kind => panic!("unsupported governed kind {kind}"),
        }
    }

    fn response_document(route: RhiAdminRoute) -> RhiAdminResponseDocument {
        let value = sample_model(route.response_model());
        validate_model(route.response_model(), &value).expect("generated response model");
        let bytes = serde_json::to_vec(&value).expect("canonical response bytes");
        RhiAdminResponseDocument::from_canonical_bytes(route, &bytes)
            .expect("admitted response document")
    }

    #[test]
    fn complete_route_and_model_inventory_matches_the_machine_contract() {
        assert!(operator_route_inventory_is_exact());
        assert_eq!(RhiAdminRoute::ALL.len(), 20);
        assert_eq!(RhiAdminRoute::COMMON.len(), 7);
        assert_eq!(RhiAdminRoute::DOMAIN.len(), 13);
        assert_eq!(RhiAdminRoute::ACTIVE.len(), 20);
        assert_eq!(
            RhiAdminRoute::ACTIVE,
            RhiAdminRoute::COMMON
                .into_iter()
                .chain(RhiAdminRoute::DOMAIN)
                .collect::<Vec<_>>()
                .as_slice()
        );
        let referenced = RhiAdminRoute::ALL
            .into_iter()
            .flat_map(|route| [route.request_model(), route.response_model()])
            .collect::<BTreeSet<_>>();
        let governed = operator_contract().expect("operator contract")["admin"]["models"]
            .as_object()
            .expect("model inventory")
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(referenced, governed);
        assert_eq!(governed.len(), 33);
        assert!(
            RhiAdminRoute::COMMON
                .into_iter()
                .all(|route| route.parameter_binding().is_none())
        );
        for route in [
            RhiAdminRoute::TradeProjection,
            RhiAdminRoute::TradeReportCurrent,
            RhiAdminRoute::TradeReports,
        ] {
            assert_eq!(route.parameter_binding(), Some(("trade_id", "trade_id")));
        }
        for model in governed {
            let value = sample_model(model);
            validate_model(model, &value).expect("minimum exact model");
        }
    }

    #[test]
    fn strict_response_admission_rejects_duplicates_null_and_noncanonical_bytes() {
        let route = RhiAdminRoute::IdentityPublic;
        let valid = response_document(route);
        assert_eq!(valid.route(), route);
        assert!(!valid.canonical_bytes().is_empty());

        let duplicate = br#"{"generation":0,"generation":1,"public_key":"0000000000000000000000000000000000000000000000000000000000000000","role":"service"}"#;
        assert_eq!(
            RhiAdminResponseDocument::from_canonical_bytes(route, duplicate)
                .expect_err("duplicate key")
                .kind(),
            RhiAdminDocumentErrorKind::DuplicateField
        );
        let nested_null = br#"{"generation":0,"public_key":null,"role":"service"}"#;
        assert_eq!(
            RhiAdminResponseDocument::from_canonical_bytes(route, nested_null)
                .expect_err("nested null")
                .kind(),
            RhiAdminDocumentErrorKind::NullForbidden
        );
        let noncanonical = format!(" {}", String::from_utf8_lossy(valid.canonical_bytes()));
        assert_eq!(
            RhiAdminResponseDocument::from_canonical_bytes(route, noncanonical.as_bytes())
                .expect_err("whitespace")
                .kind(),
            RhiAdminDocumentErrorKind::NonCanonical
        );
        let invalid = br#"{"generation":0,"public_key":"0000000000000000000000000000000000000000000000000000000000000000","role":"administrator"}"#;
        assert_eq!(
            RhiAdminResponseDocument::from_canonical_bytes(route, invalid)
                .expect_err("invalid model")
                .kind(),
            RhiAdminDocumentErrorKind::InvalidModel
        );
        assert_eq!(
            RhiAdminResponseDocument::from_canonical_bytes(route, b"")
                .expect_err("empty response")
                .kind(),
            RhiAdminDocumentErrorKind::Malformed
        );
        let oversized = vec![b' '; RHI_ADMIN_RESPONSE_BODY_MAX_UTF8_BYTES + 1];
        assert_eq!(
            RhiAdminResponseDocument::from_canonical_bytes(route, &oversized)
                .expect_err("oversized response")
                .kind(),
            RhiAdminDocumentErrorKind::TooLarge
        );
        assert_eq!(
            format!("{valid:?}"),
            "RhiAdminResponseDocument { route: IdentityPublic, model: \"[redacted]\" }"
        );
    }

    #[test]
    fn query_and_nested_type_admission_is_exact_and_bounded() {
        let identity = query_model(RhiAdminRoute::IdentityStatus, Some("role=service"))
            .expect("common identity query");
        validate_model("identity_status_query_v1", &identity).expect("identity query model");
        for invalid in [
            "",
            "role=service&role=service",
            "role=transport",
            "unknown=x",
        ] {
            let result = query_model(RhiAdminRoute::IdentityStatus, Some(invalid))
                .and_then(|value| validate_model("identity_status_query_v1", &value));
            assert!(
                result.is_err(),
                "common query `{invalid}` unexpectedly passed"
            );
        }

        let jobs = query_model(
            RhiAdminRoute::ReconciliationJobs,
            Some("cursor=AA&limit=200&state=pending"),
        )
        .expect("canonical query");
        validate_model("reconciliation_jobs_query_v1", &jobs).expect("query model");
        for invalid in [
            "limit=01",
            "limit=201",
            "limit=1&limit=2",
            "unknown=x",
            "cursor=%",
            "cursor=A&limit=1",
            "cursor=AB&limit=1",
            "cursor=A%3D%3D&limit=1",
            "state=unknown",
        ] {
            let result = query_model(RhiAdminRoute::ReconciliationJobs, Some(invalid))
                .and_then(|value| validate_model("reconciliation_jobs_query_v1", &value));
            assert!(result.is_err(), "query `{invalid}` unexpectedly passed");
        }
        validate_type("stable_id", &Value::String("source-1".to_owned()), 0)
            .expect("stable identifier");
        assert!(validate_type("stable_id", &Value::String("Source".to_owned()), 0).is_err());
        validate_type("trade_id", &Value::String("0".repeat(32)), 0).expect("trade identifier");
        assert!(validate_type("trade_id", &Value::String("0".repeat(31)), 0).is_err());
        validate_type(
            "absolute_path",
            &Value::String("/var/lib/radroots/rhi".to_owned()),
            0,
        )
        .expect("Unix absolute path");
        assert!(
            validate_type(
                "absolute_path",
                &Value::String("C:\\rhi\\state".to_owned()),
                0,
            )
            .is_err()
        );
        assert!(validate_type("bounded_id", &Value::String("../escape".to_owned()), 0).is_err());
    }

    #[test]
    fn public_diagnostics_are_source_free_and_content_free() {
        let document = RhiAdminDocumentError::new(RhiAdminDocumentErrorKind::InvalidModel);
        let handler = RhiAdminHandlerError::new(RhiAdminHandlerErrorKind::Internal);
        let server = RhiAdminServerError::new(RhiAdminServerErrorKind::Bind);
        for rendered in [
            format!("{document}"),
            format!("{document:?}"),
            format!("{handler}"),
            format!("{handler:?}"),
            format!("{server}"),
            format!("{server:?}"),
        ] {
            assert!(!rendered.contains("/tmp/protected"));
            assert!(!rendered.contains("credential"));
        }
        assert!(Error::source(&document).is_none());
        assert!(Error::source(&handler).is_none());
        assert!(Error::source(&server).is_none());
        assert_eq!(server.code(), "admin_bind_failed");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod native {
        use std::fs;
        use std::path::Path;
        use std::sync::Mutex;

        use radroots_service_host::{AdminClient, AdminClientTarget, AdminTransportLimits};

        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const CONFIG: &str = include_str!("../contracts/services_hardening/config.v1.example.toml");

        type FixtureCall = (RhiAdminRoute, Option<String>, Option<String>, Box<[u8]>);

        struct FixtureHandler {
            calls: Mutex<Vec<FixtureCall>>,
        }

        impl FixtureHandler {
            fn new() -> Self {
                Self {
                    calls: Mutex::new(Vec::new()),
                }
            }
        }

        impl RhiAdminHandler for FixtureHandler {
            fn handle<'a>(&'a self, request: RhiAdminRequestDocument) -> RhiAdminFuture<'a> {
                Box::pin(async move {
                    if request.operation_id() == Some("conflict") {
                        return Err(RhiAdminHandlerError::new(
                            RhiAdminHandlerErrorKind::OperationIdConflict,
                        ));
                    }
                    if request
                        .model_bytes()
                        .windows(15)
                        .any(|bytes| bytes == b"\"cursor\":\"AAAA\"")
                    {
                        return Err(RhiAdminHandlerError::new(
                            RhiAdminHandlerErrorKind::InvalidCursor,
                        ));
                    }
                    self.calls.lock().expect("calls").push((
                        request.route(),
                        request.operation_id().map(str::to_owned),
                        request.parameter("trade_id").map(str::to_owned),
                        request.model_bytes().into(),
                    ));
                    Ok(response_document(request.route()))
                })
            }
        }

        fn runtime_context() -> (
            tempfile::TempDir,
            crate::RhiRuntimeContext,
            crate::RhiConfigDocumentV1,
        ) {
            let root = tempfile::Builder::new()
                .prefix("rhi-admin-")
                .tempdir_in("/tmp")
                .expect("short runtime root");
            let root_path = root.path().to_str().expect("UTF-8 test root");
            let invocation = crate::parse_rhi_cli_v1_from([
                "rhi",
                "--profile",
                "repo-local",
                "--instance",
                "primary",
                "--repo-local-root",
                root_path,
                "run",
            ])
            .expect("test CLI");
            let resolver = crate::RadrootsPathResolver::new(
                crate::RadrootsPlatform::Linux,
                crate::RadrootsHostEnvironment::default(),
            );
            let runtime = crate::resolve_rhi_runtime_context(&resolver, &invocation)
                .expect("test runtime context");
            fs::create_dir_all(runtime.context().paths().run()).expect("runtime directory");
            let configuration =
                crate::parse_rhi_config_v1(CONFIG.as_bytes(), crate::RhiConfigProfile::RepoLocal)
                    .expect("test configuration");
            (root, runtime, configuration)
        }

        fn target_for(route: RhiAdminRoute, request: &Value) -> AdminClientTarget {
            let path = route
                .path()
                .replace("{trade_id}", "00000000000000000000000000000000");
            if !matches!(route.method(), RhiAdminMethod::Get)
                || request.as_object().is_some_and(Map::is_empty)
            {
                return AdminClientTarget::new(path).expect("route target");
            }
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in request.as_object().expect("query object") {
                let rendered = value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string());
                serializer.append_pair(name, &rendered);
            }
            AdminClientTarget::new(format!("{path}?{}", serializer.finish())).expect("query target")
        }

        async fn raw_post(socket: &Path, body: &str) -> String {
            let mut stream = tokio::net::UnixStream::connect(socket)
                .await
                .expect("raw connection");
            let request = format!(
                "POST /v1/state/backup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(request.as_bytes())
                .await
                .expect("raw request");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .expect("raw response");
            String::from_utf8(response).expect("HTTP response")
        }

        #[tokio::test]
        async fn twenty_active_routes_round_trip_over_the_hardened_unix_boundary() {
            let (_root, runtime, configuration) = runtime_context();
            let socket = runtime.artifacts().admin_socket().to_path_buf();
            let handler = Arc::new(FixtureHandler::new());
            let server = RhiAdminServer::new(&configuration, Arc::clone(&handler))
                .expect("production admin server")
                .bind(&runtime)
                .await
                .expect("canonical admin binding");
            let cancellation = RhiAdminCancellationToken::new();
            let server_cancellation = cancellation.clone();
            let task = tokio::spawn(async move {
                server
                    .serve(server_cancellation)
                    .await
                    .expect("serve RHI admin");
            });
            let client =
                AdminClient::new(&socket, AdminTransportLimits::DEFAULT).expect("admin client");

            for (index, route) in RhiAdminRoute::ACTIVE.into_iter().enumerate() {
                let request = sample_model(route.request_model());
                let target = target_for(route, &request);
                let response = match route.method() {
                    RhiAdminMethod::Get => client.get::<Value>(&target).await.expect("GET route"),
                    RhiAdminMethod::Post => {
                        let operation_id = AdminOperationId::new(format!("operation-{index}"))
                            .expect("operation ID");
                        client
                            .mutate::<_, Value>(&target, operation_id, None, &request)
                            .await
                            .expect("POST route")
                    }
                };
                validate_model(route.response_model(), response.result())
                    .expect("route response model");
            }

            let conflict_target =
                AdminClientTarget::new("/v1/state/backup").expect("mutation target");
            let conflict_error = client
                .mutate::<_, Value>(
                    &conflict_target,
                    AdminOperationId::new("conflict").expect("operation ID"),
                    None,
                    sample_model("state_backup_request_v1"),
                )
                .await
                .expect_err("operation conflict");
            assert_eq!(
                conflict_error
                    .failure()
                    .expect("failure envelope")
                    .error()
                    .code()
                    .as_str(),
                "operation_id_conflict"
            );

            for body in [
                r#"{"contract_version":1,"operation_id":"duplicate","request":{"confirmation":"confirm","expected_generation":0,"expected_generation":1,"target_path":"/tmp/backup"}}"#,
                r#"{"contract_version":1,"operation_id":"null","request":{"confirmation":"confirm","expected_generation":null,"target_path":"/tmp/backup"}}"#,
            ] {
                let response = raw_post(&socket, body).await;
                assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
            }

            let domain_target = AdminClientTarget::new("/v1/reconciliation/jobs?limit=201")
                .expect("bounded domain route");
            assert!(client.get::<Value>(&domain_target).await.is_err());

            let invalid_cursor_target =
                AdminClientTarget::new("/v1/reconciliation/jobs?cursor=AAAA&limit=1")
                    .expect("authenticated cursor route");
            let invalid_cursor = client
                .get::<Value>(&invalid_cursor_target)
                .await
                .expect_err("domain handler rejects unbound cursor");
            assert_eq!(
                invalid_cursor
                    .failure()
                    .expect("failure envelope")
                    .error()
                    .code()
                    .as_str(),
                "invalid_cursor"
            );

            let invalid_trade = AdminClientTarget::new("/v1/trades/not-hex/projection")
                .expect("trade route target");
            assert!(client.get::<Value>(&invalid_trade).await.is_err());

            for (index, path) in ["/v1/identity/rekey", "/v1/identity/replace"]
                .into_iter()
                .enumerate()
            {
                let removed_target =
                    AdminClientTarget::new(path).expect("removed live identity route");
                assert!(
                    client
                        .mutate::<_, Value>(
                            &removed_target,
                            AdminOperationId::new(format!("removed-identity-{index}"))
                                .expect("operation ID"),
                            None,
                            serde_json::json!({}),
                        )
                        .await
                        .is_err()
                );
            }

            {
                let calls = handler.calls.lock().expect("calls");
                assert_eq!(calls.len(), 20);
                for (index, (route, operation_id, parameter, request)) in calls.iter().enumerate() {
                    assert_eq!(*route, RhiAdminRoute::ACTIVE[index]);
                    assert_eq!(operation_id.is_some(), route.is_mutation());
                    assert_eq!(
                        parameter.is_some(),
                        matches!(
                            route,
                            RhiAdminRoute::TradeProjection
                                | RhiAdminRoute::TradeReportCurrent
                                | RhiAdminRoute::TradeReports
                        )
                    );
                    validate_model(
                        route.request_model(),
                        &serde_json::from_slice(request).expect("retained request model"),
                    )
                    .expect("retained exact model");
                }
            }
            cancellation.cancel();
            task.await.expect("server task");
            assert!(!socket.exists());
        }

        #[test]
        fn production_server_projects_exact_validated_admin_limits() {
            let (_root, _runtime, configuration) = runtime_context();
            assert_eq!(
                admin_transport_limits(&configuration).expect("admin limits"),
                AdminTransportLimits::DEFAULT
            );
        }
    }
}
