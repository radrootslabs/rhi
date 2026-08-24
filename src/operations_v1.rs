//! Rhi-owned adapter for the exact passive TCP operations surface.

use core::{fmt, time::Duration};
use std::{error::Error, net::SocketAddr};

use radroots_service_host::{
    BoundOperationsServer as HostBoundOperationsServer, CancellationToken as HostCancellationToken,
    OperationsBindPolicy as HostOperationsBindPolicy,
    OperationsListenAddress as HostOperationsListenAddress,
    OperationsListenerConfig as HostOperationsListenerConfig,
    OperationsServer as HostOperationsServer, OperationsServerError as HostOperationsServerError,
    OperationsTransportLimitValues as HostOperationsTransportLimitValues,
    OperationsTransportLimits as HostOperationsTransportLimits,
};
use serde_json::Value;

use crate::{RhiConfigDocumentV1, RhiStatusReader};

/// Exact Rhi TCP operations contract version.
pub const RHI_OPERATIONS_CONTRACT_VERSION: u32 = 1;

/// Exact liveness route exposed by the optional TCP listener.
pub const RHI_LIVEZ_PATH: &str = "/livez";

/// Exact readiness route exposed by the optional TCP listener.
pub const RHI_READYZ_PATH: &str = "/readyz";

/// Exact bounded metrics route exposed by the optional TCP listener.
pub const RHI_METRICS_PATH: &str = "/metrics";

/// Cloneable cooperative cancellation owned by the Rhi runtime supervisor.
#[derive(Clone, Default)]
pub struct RhiOperationsCancellationToken {
    inner: HostCancellationToken,
}

impl RhiOperationsCancellationToken {
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

impl fmt::Debug for RhiOperationsCancellationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiOperationsCancellationToken")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Unbound exact-route Rhi TCP operations server.
pub struct RhiOperationsServer {
    inner: HostOperationsServer,
}

impl RhiOperationsServer {
    /// Projects the already-validated Rhi configuration and passive status cache.
    pub fn new(
        config: &RhiConfigDocumentV1,
        status: &RhiStatusReader,
    ) -> Result<Self, RhiOperationsError> {
        let listener = listener_config(config)?;
        HostOperationsServer::new(listener, status.operations_cache())
            .map(|inner| Self { inner })
            .map_err(map_server_error)
    }

    /// Binds the exact configured address without starting admission.
    pub async fn bind(self) -> Result<RhiBoundOperationsServer, RhiOperationsError> {
        self.inner
            .bind()
            .await
            .map(|inner| RhiBoundOperationsServer { inner })
            .map_err(map_server_error)
    }
}

impl fmt::Debug for RhiOperationsServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiOperationsServer([sealed])")
    }
}

/// Successfully bound exact-route Rhi TCP operations server.
pub struct RhiBoundOperationsServer {
    inner: HostBoundOperationsServer,
}

impl RhiBoundOperationsServer {
    #[must_use]
    pub fn local_address(&self) -> SocketAddr {
        self.inner.local_address()
    }

    /// Serves until explicit supervisor cancellation, then drains owned work.
    pub async fn serve(
        self,
        cancellation: RhiOperationsCancellationToken,
    ) -> Result<(), RhiOperationsError> {
        self.inner
            .serve(cancellation.inner)
            .await
            .map_err(map_server_error)
    }
}

impl fmt::Debug for RhiBoundOperationsServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RhiBoundOperationsServer([sealed])")
    }
}

/// Stable source-free Rhi operations failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiOperationsErrorKind {
    Disabled,
    InvalidConfiguration,
    Bind,
    LocalAddress,
    Accept,
    ConnectionTaskPanicked,
}

impl RhiOperationsErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Disabled => "operations_disabled",
            Self::InvalidConfiguration => "operations_configuration_invalid",
            Self::Bind => "operations_bind_failed",
            Self::LocalAddress => "operations_local_address_failed",
            Self::Accept => "operations_accept_failed",
            Self::ConnectionTaskPanicked => "operations_connection_task_panicked",
        }
    }
}

/// One redacted source-free Rhi operations failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiOperationsError {
    kind: RhiOperationsErrorKind,
}

impl RhiOperationsError {
    const fn new(kind: RhiOperationsErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> RhiOperationsErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for RhiOperationsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiOperationsError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiOperationsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Rhi TCP operations failed")
    }
}

impl Error for RhiOperationsError {}

fn listener_config(
    config: &RhiConfigDocumentV1,
) -> Result<HostOperationsListenerConfig, RhiOperationsError> {
    let operations = config
        .normalized()
        .pointer("/operations")
        .ok_or_else(invalid_configuration)?;
    if !boolean(operations, "/enabled")? {
        return Err(RhiOperationsError::new(RhiOperationsErrorKind::Disabled));
    }
    let listen = string(operations, "/listen")?
        .parse::<SocketAddr>()
        .map_err(|_| invalid_configuration())?;
    let listen = HostOperationsListenAddress::new(listen).map_err(|_| invalid_configuration())?;
    let bind_policy = match string(operations, "/bind_policy")? {
        "loopback_only" => HostOperationsBindPolicy::LoopbackOnly,
        "explicit_public" => HostOperationsBindPolicy::Public,
        _ => return Err(invalid_configuration()),
    };
    let values = HostOperationsTransportLimitValues {
        header_count: unsigned_u32(operations, "/limits/header_count")?,
        header_bytes: unsigned_u32(operations, "/limits/header_bytes")?,
        response_body_utf8_bytes: unsigned_u32(operations, "/limits/response_body_utf8_bytes")?,
        concurrent_connections: unsigned_u32(operations, "/limits/concurrent_connections")?,
        request_deadline: Duration::from_millis(unsigned(
            operations,
            "/limits/request_deadline_ms",
        )?),
        idle_timeout: Duration::from_millis(unsigned(operations, "/limits/idle_timeout_ms")?),
    };
    let limits = HostOperationsTransportLimits::new(values).map_err(|_| invalid_configuration())?;
    HostOperationsListenerConfig::enabled(listen, bind_policy, limits)
        .map_err(|_| invalid_configuration())
}

fn boolean(value: &Value, pointer: &str) -> Result<bool, RhiOperationsError> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(invalid_configuration)
}

fn string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str, RhiOperationsError> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(invalid_configuration)
}

fn unsigned(value: &Value, pointer: &str) -> Result<u64, RhiOperationsError> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(invalid_configuration)
}

fn unsigned_u32(value: &Value, pointer: &str) -> Result<u32, RhiOperationsError> {
    u32::try_from(unsigned(value, pointer)?).map_err(|_| invalid_configuration())
}

const fn invalid_configuration() -> RhiOperationsError {
    RhiOperationsError::new(RhiOperationsErrorKind::InvalidConfiguration)
}

const fn map_server_error(error: HostOperationsServerError) -> RhiOperationsError {
    let kind = match error {
        HostOperationsServerError::Disabled => RhiOperationsErrorKind::Disabled,
        HostOperationsServerError::HeaderLimitBelowParserFloor => {
            RhiOperationsErrorKind::InvalidConfiguration
        }
        HostOperationsServerError::Bind { .. } => RhiOperationsErrorKind::Bind,
        HostOperationsServerError::LocalAddress { .. } => RhiOperationsErrorKind::LocalAddress,
        HostOperationsServerError::Accept { .. } => RhiOperationsErrorKind::Accept,
        HostOperationsServerError::ConnectionTaskPanicked => {
            RhiOperationsErrorKind::ConnectionTaskPanicked
        }
    };
    RhiOperationsError::new(kind)
}
