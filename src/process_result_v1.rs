//! Closed process-result and exit-code contract.

use std::process::ExitCode;

/// Exact stable RHI process result and exit-code inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiProcessResult {
    Success,
    UnexpectedInternal,
    InputOrConfiguration,
    ServiceOrDependencyUnavailable,
    StateOrIdentityUnavailable,
    OperationRejectedOrConflict,
    DoctorRequiredCheckFailed,
}

impl RhiProcessResult {
    /// Returns the exact stable process exit code.
    #[must_use]
    pub const fn exit_code_u8(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::UnexpectedInternal => 1,
            Self::InputOrConfiguration => 2,
            Self::ServiceOrDependencyUnavailable => 3,
            Self::StateOrIdentityUnavailable => 4,
            Self::OperationRejectedOrConflict => 5,
            Self::DoctorRequiredCheckFailed => 6,
        }
    }

    /// Returns the stable machine code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::UnexpectedInternal => "unexpected_internal",
            Self::InputOrConfiguration => "input_or_configuration",
            Self::ServiceOrDependencyUnavailable => "service_or_dependency_unavailable",
            Self::StateOrIdentityUnavailable => "state_or_identity_unavailable",
            Self::OperationRejectedOrConflict => "operation_rejected_or_conflict",
            Self::DoctorRequiredCheckFailed => "doctor_required_check_failed",
        }
    }

    /// Returns the standard-library process exit value.
    #[must_use]
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(self.exit_code_u8())
    }
}
