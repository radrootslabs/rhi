//! Closed process-result and structured stderr diagnostic contract.

use crate::{RhiProcessResult, RhiServicePhase};
use core::fmt;

/// Exact Rhi diagnostics contract version.
pub const RHI_DIAGNOSTICS_CONTRACT_VERSION: u32 = 1;

/// Hard maximum for one canonical Rhi structured log record, excluding newline.
pub const RHI_LOG_RECORD_MAX_UTF8_BYTES: usize = 512;

const LOG_SCHEMA: &str = "radroots.rhi.log.v1";

/// Closed structured-log severity vocabulary admitted by Rhi.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiLogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl RhiLogLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Closed structured-log event vocabulary required by the current runtime plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiLogEvent {
    ProcessResult,
    Lifecycle,
    CriticalTaskFailed,
    ShutdownRequested,
    ShutdownForced,
}

impl RhiLogEvent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessResult => "process_result",
            Self::Lifecycle => "lifecycle",
            Self::CriticalTaskFailed => "critical_task_failed",
            Self::ShutdownRequested => "shutdown_requested",
            Self::ShutdownForced => "shutdown_forced",
        }
    }
}

/// One sealed canonical structured log record containing only governed values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiLogRecord {
    level: RhiLogLevel,
    event: RhiLogEvent,
    code: &'static str,
    process_result: Option<RhiProcessResult>,
}

impl RhiLogRecord {
    /// Builds the exact terminal record for one governed process result.
    #[must_use]
    pub const fn process_result(result: RhiProcessResult) -> Self {
        let level = match result {
            RhiProcessResult::Success => RhiLogLevel::Info,
            RhiProcessResult::OperationRejectedOrConflict => RhiLogLevel::Warn,
            RhiProcessResult::UnexpectedInternal
            | RhiProcessResult::InputOrConfiguration
            | RhiProcessResult::ServiceOrDependencyUnavailable
            | RhiProcessResult::StateOrIdentityUnavailable
            | RhiProcessResult::DoctorRequiredCheckFailed => RhiLogLevel::Error,
        };
        Self {
            level,
            event: RhiLogEvent::ProcessResult,
            code: result.code(),
            process_result: Some(result),
        }
    }

    /// Builds the exact phase record from an already-published lifecycle value.
    #[must_use]
    pub const fn lifecycle(phase: RhiServicePhase) -> Self {
        let (level, code) = match phase {
            RhiServicePhase::Starting => (RhiLogLevel::Info, "starting"),
            RhiServicePhase::Ready => (RhiLogLevel::Info, "ready"),
            RhiServicePhase::Degraded => (RhiLogLevel::Warn, "degraded"),
            RhiServicePhase::Unready => (RhiLogLevel::Warn, "unready"),
            RhiServicePhase::Stopping => (RhiLogLevel::Info, "stopping"),
            RhiServicePhase::Failed => (RhiLogLevel::Error, "failed"),
        };
        Self {
            level,
            event: RhiLogEvent::Lifecycle,
            code,
            process_result: None,
        }
    }

    #[must_use]
    pub const fn critical_task_failed() -> Self {
        Self {
            level: RhiLogLevel::Error,
            event: RhiLogEvent::CriticalTaskFailed,
            code: "critical_task_failed",
            process_result: None,
        }
    }

    #[must_use]
    pub const fn shutdown_requested() -> Self {
        Self {
            level: RhiLogLevel::Info,
            event: RhiLogEvent::ShutdownRequested,
            code: "first_signal",
            process_result: None,
        }
    }

    #[must_use]
    pub const fn shutdown_forced() -> Self {
        Self {
            level: RhiLogLevel::Error,
            event: RhiLogEvent::ShutdownForced,
            code: "second_signal",
            process_result: None,
        }
    }

    #[must_use]
    pub const fn level(&self) -> RhiLogLevel {
        self.level
    }

    #[must_use]
    pub const fn event(&self) -> RhiLogEvent {
        self.event
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    #[must_use]
    pub const fn process_exit(&self) -> Option<RhiProcessResult> {
        self.process_result
    }
}

impl fmt::Debug for RhiLogRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiLogRecord")
            .field("level", &self.level)
            .field("event", &self.event)
            .field("code", &self.code)
            .field(
                "exit_code",
                &self.process_result.map(RhiProcessResult::exit_code_u8),
            )
            .finish()
    }
}

impl fmt::Display for RhiLogRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{{\"schema\":\"{LOG_SCHEMA}\",\"contract_version\":{RHI_DIAGNOSTICS_CONTRACT_VERSION},\"service\":\"rhi\",\"level\":\"{}\",\"event\":\"{}\",\"code\":\"{}\"",
            self.level.as_str(),
            self.event.as_str(),
            self.code,
        )?;
        if let Some(result) = self.process_result {
            write!(formatter, ",\"exit_code\":{}", result.exit_code_u8())?;
        }
        formatter.write_str("}")
    }
}
