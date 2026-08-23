//! Existing-state-only RHI runtime foundation.

use core::fmt;
use std::error::Error;

use radroots_service_sqlite::{MigrationAppliedAtUnixSeconds, MigrationBuildIdentity};

use crate::{
    RhiConfigDocumentV1, RhiDecryptedIdentity, RhiIdentityEnvelopeBinding, RhiRuntimeAdapters,
    RhiRuntimeContext, RhiStateHost, RhiStateMetadata, open_rhi_state_read_write_from_config,
};

#[cfg(test)]
const RUNTIME_FOUNDATION_CONTRACT: &str =
    include_str!("../contracts/services_hardening/runtime_foundation.v1.json");

/// Exact version of the RHI runtime-foundation contract.
pub const RHI_RUNTIME_FOUNDATION_CONTRACT_VERSION: u32 = 1;

/// Closed startup conditions required before the RHI service may be ready.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RhiRuntimePrerequisite {
    ExistingState,
    DurableConfiguration,
    VerifiedIdentity,
    ReconciliationRecovery,
    RequiredSourceConnectivity,
    RequiredSourceSubscription,
    PublicationRecovery,
    AdminListener,
    OperationsListener,
    PresenceDesiredState,
}

impl RhiRuntimePrerequisite {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExistingState => "existing_state",
            Self::DurableConfiguration => "durable_configuration",
            Self::VerifiedIdentity => "verified_identity",
            Self::ReconciliationRecovery => "reconciliation_recovery",
            Self::RequiredSourceConnectivity => "required_source_connectivity",
            Self::RequiredSourceSubscription => "required_source_subscription",
            Self::PublicationRecovery => "publication_recovery",
            Self::AdminListener => "admin_listener",
            Self::OperationsListener => "operations_listener",
            Self::PresenceDesiredState => "presence_desired_state",
        }
    }

    const fn reason(self) -> RhiRuntimeReadinessReason {
        match self {
            Self::ExistingState => RhiRuntimeReadinessReason::DatabaseUnavailable,
            Self::DurableConfiguration => RhiRuntimeReadinessReason::ConfigurationNotDurable,
            Self::VerifiedIdentity => RhiRuntimeReadinessReason::IdentityUnavailable,
            Self::ReconciliationRecovery => RhiRuntimeReadinessReason::RecoveryIncomplete,
            Self::RequiredSourceConnectivity => RhiRuntimeReadinessReason::SourceUnavailable,
            Self::RequiredSourceSubscription => RhiRuntimeReadinessReason::SubscriptionInactive,
            Self::PublicationRecovery => RhiRuntimeReadinessReason::PublicationRecoveryIncomplete,
            Self::AdminListener => RhiRuntimeReadinessReason::AdminListenerUnavailable,
            Self::OperationsListener => RhiRuntimeReadinessReason::OperationsListenerUnavailable,
            Self::PresenceDesiredState => RhiRuntimeReadinessReason::PresenceStateUnavailable,
        }
    }
}

/// Closed stable reason vocabulary for an unsatisfied prerequisite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RhiRuntimeReadinessReason {
    AdminListenerUnavailable,
    ConfigurationNotDurable,
    DatabaseUnavailable,
    IdentityUnavailable,
    OperationsListenerUnavailable,
    PresenceStateUnavailable,
    PublicationRecoveryIncomplete,
    RecoveryIncomplete,
    SourceUnavailable,
    SubscriptionInactive,
}

impl RhiRuntimeReadinessReason {
    /// Returns the exact machine-contract spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdminListenerUnavailable => "admin_listener_unavailable",
            Self::ConfigurationNotDurable => "configuration_not_durable",
            Self::DatabaseUnavailable => "database_unavailable",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::OperationsListenerUnavailable => "operations_listener_unavailable",
            Self::PresenceStateUnavailable => "presence_state_unavailable",
            Self::PublicationRecoveryIncomplete => "publication_recovery_incomplete",
            Self::RecoveryIncomplete => "recovery_incomplete",
            Self::SourceUnavailable => "source_unavailable",
            Self::SubscriptionInactive => "subscription_inactive",
        }
    }
}

/// Immutable passive readiness evidence derived at startup.
#[derive(Clone, PartialEq, Eq)]
pub struct RhiRuntimeReadiness {
    required: Box<[RhiRuntimePrerequisite]>,
    satisfied: Box<[RhiRuntimePrerequisite]>,
    reasons: Box<[RhiRuntimeReadinessReason]>,
}

impl RhiRuntimeReadiness {
    /// Returns true only after every exact prerequisite is satisfied.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.required.len() == self.satisfied.len()
            && self
                .required
                .iter()
                .all(|required| self.satisfied.contains(required))
    }

    /// Returns the exact ordered prerequisite inventory.
    #[must_use]
    pub fn required(&self) -> &[RhiRuntimePrerequisite] {
        &self.required
    }

    /// Returns the exact ordered prerequisites already proven.
    #[must_use]
    pub fn satisfied(&self) -> &[RhiRuntimePrerequisite] {
        &self.satisfied
    }

    /// Returns bounded stable reasons for missing prerequisites.
    #[must_use]
    pub const fn reasons(&self) -> &[RhiRuntimeReadinessReason] {
        &self.reasons
    }
}

impl fmt::Debug for RhiRuntimeReadiness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiRuntimeReadiness")
            .field("ready", &self.is_ready())
            .field("required", &self.required)
            .field("satisfied", &self.satisfied)
            .field("reasons", &self.reasons)
            .finish()
    }
}

/// Stable source-free runtime-foundation failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiRuntimeFoundationErrorKind {
    StateOpen,
    IdentityBinding,
    IdentityAccess,
    Readiness,
    TaskFailure,
    Close,
}

impl RhiRuntimeFoundationErrorKind {
    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::StateOpen => "runtime_state_open_failed",
            Self::IdentityBinding => "runtime_identity_binding_invalid",
            Self::IdentityAccess => "runtime_identity_access_failed",
            Self::Readiness => "runtime_readiness_invalid",
            Self::TaskFailure => "runtime_task_failed",
            Self::Close => "runtime_close_failed",
        }
    }
}

/// One redacted source-free runtime-foundation failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiRuntimeFoundationError {
    kind: RhiRuntimeFoundationErrorKind,
}

impl RhiRuntimeFoundationError {
    const fn new(kind: RhiRuntimeFoundationErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure kind.
    #[must_use]
    pub const fn kind(self) -> RhiRuntimeFoundationErrorKind {
        self.kind
    }

    /// Returns the stable machine-facing safe code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.kind.code()
    }
}

impl fmt::Debug for RhiRuntimeFoundationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiRuntimeFoundationError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiRuntimeFoundationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            RhiRuntimeFoundationErrorKind::StateOpen => "RHI existing state could not be opened",
            RhiRuntimeFoundationErrorKind::IdentityBinding => "RHI identity binding is invalid",
            RhiRuntimeFoundationErrorKind::IdentityAccess => "RHI identity startup failed",
            RhiRuntimeFoundationErrorKind::Readiness => "RHI readiness prerequisites are invalid",
            RhiRuntimeFoundationErrorKind::TaskFailure => "RHI supervised task failed",
            RhiRuntimeFoundationErrorKind::Close => "RHI runtime foundation could not close",
        })
    }
}

impl Error for RhiRuntimeFoundationError {}

/// Existing-only RHI foundation with sealed state, identity, adapters, and task ownership.
#[must_use = "the runtime foundation must be shut down so state and tasks are joined"]
pub struct RhiRuntimeFoundation {
    runtime: RhiRuntimeContext,
    configuration: RhiConfigDocumentV1,
    metadata: RhiStateMetadata,
    state: RhiStateHost,
    _identity: RhiDecryptedIdentity,
    adapters: RhiRuntimeAdapters,
    readiness: RhiRuntimeReadiness,
}

impl RhiRuntimeFoundation {
    /// Returns the immutable canonical instance context.
    #[must_use]
    pub const fn runtime_context(&self) -> &RhiRuntimeContext {
        &self.runtime
    }

    /// Returns the admitted immutable configuration.
    #[must_use]
    pub const fn configuration(&self) -> &RhiConfigDocumentV1 {
        &self.configuration
    }

    /// Returns metadata discovered and proven under retained state authority.
    #[must_use]
    pub const fn metadata(&self) -> &RhiStateMetadata {
        &self.metadata
    }

    /// Returns passive startup-readiness evidence without performing I/O.
    #[must_use]
    pub const fn readiness(&self) -> &RhiRuntimeReadiness {
        &self.readiness
    }

    /// Requests cancellation, joins owned tasks, and explicitly closes state.
    pub async fn shutdown(mut self) -> Result<(), RhiRuntimeFoundationError> {
        let supervised = self.adapters.shutdown().await;
        let closed = self.state.close().await;
        if supervised.is_err() {
            Err(RhiRuntimeFoundationError::new(
                RhiRuntimeFoundationErrorKind::TaskFailure,
            ))
        } else if closed.is_err() {
            Err(RhiRuntimeFoundationError::new(
                RhiRuntimeFoundationErrorKind::Close,
            ))
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for RhiRuntimeFoundation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiRuntimeFoundation")
            .field("runtime", &"[redacted]")
            .field("configuration", &"[redacted]")
            .field("metadata", &"[redacted]")
            .field("state", &"[sealed]")
            .field("identity", &"[redacted]")
            .field("adapters", &"[sealed]")
            .field("readiness", &self.readiness)
            .finish()
    }
}

/// Opens existing state and composes the non-I/O RHI startup foundation.
///
/// The durable configuration binding is verified before credential or identity
/// access. No source, subscription, or publication adapter is invoked, and no
/// final service task graph, signal handler, logger, runtime, or process-exit
/// authority is created here.
pub async fn open_rhi_runtime_foundation(
    runtime: RhiRuntimeContext,
    configuration: RhiConfigDocumentV1,
    adapters: RhiRuntimeAdapters,
    applied_at: MigrationAppliedAtUnixSeconds,
    build: &MigrationBuildIdentity,
) -> Result<RhiRuntimeFoundation, RhiRuntimeFoundationError> {
    let state = open_rhi_state_read_write_from_config(&runtime, &configuration, applied_at, build)
        .await
        .map_err(|_| RhiRuntimeFoundationError::new(RhiRuntimeFoundationErrorKind::StateOpen))?;
    let metadata = state.metadata().clone();
    let binding = match RhiIdentityEnvelopeBinding::from_configuration(&configuration, &metadata) {
        Ok(binding) => binding,
        Err(_) => {
            return Err(close_failure(state, RhiRuntimeFoundationErrorKind::IdentityBinding).await);
        }
    };
    let identity = match adapters
        .identity_credential()
        .open_existing(&runtime, &binding)
    {
        Ok(identity) => identity,
        Err(_) => {
            return Err(close_failure(state, RhiRuntimeFoundationErrorKind::IdentityAccess).await);
        }
    };
    let readiness = match startup_readiness(&configuration) {
        Ok(readiness) => readiness,
        Err(error) => return Err(close_failure(state, error.kind()).await),
    };
    Ok(RhiRuntimeFoundation {
        runtime,
        configuration,
        metadata,
        state,
        _identity: identity,
        adapters,
        readiness,
    })
}

async fn close_failure(
    state: RhiStateHost,
    fallback: RhiRuntimeFoundationErrorKind,
) -> RhiRuntimeFoundationError {
    if state.close().await.is_err() {
        RhiRuntimeFoundationError::new(RhiRuntimeFoundationErrorKind::Close)
    } else {
        RhiRuntimeFoundationError::new(fallback)
    }
}

fn startup_readiness(
    configuration: &RhiConfigDocumentV1,
) -> Result<RhiRuntimeReadiness, RhiRuntimeFoundationError> {
    let normalized = configuration.normalized();
    let operations_enabled = normalized
        .pointer("/operations/enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| RhiRuntimeFoundationError::new(RhiRuntimeFoundationErrorKind::Readiness))?;
    let presence_enabled = normalized
        .pointer("/presence/enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| RhiRuntimeFoundationError::new(RhiRuntimeFoundationErrorKind::Readiness))?;
    let mut required = vec![
        RhiRuntimePrerequisite::ExistingState,
        RhiRuntimePrerequisite::DurableConfiguration,
        RhiRuntimePrerequisite::VerifiedIdentity,
        RhiRuntimePrerequisite::ReconciliationRecovery,
        RhiRuntimePrerequisite::RequiredSourceConnectivity,
        RhiRuntimePrerequisite::RequiredSourceSubscription,
        RhiRuntimePrerequisite::PublicationRecovery,
        RhiRuntimePrerequisite::AdminListener,
    ];
    if operations_enabled {
        required.push(RhiRuntimePrerequisite::OperationsListener);
    }
    if presence_enabled {
        required.push(RhiRuntimePrerequisite::PresenceDesiredState);
    }
    let satisfied = vec![
        RhiRuntimePrerequisite::ExistingState,
        RhiRuntimePrerequisite::DurableConfiguration,
        RhiRuntimePrerequisite::VerifiedIdentity,
    ];
    let mut reasons = required
        .iter()
        .filter(|item| !satisfied.contains(item))
        .map(|item| item.reason())
        .collect::<Vec<_>>();
    reasons.sort_unstable();
    reasons.dedup();
    Ok(RhiRuntimeReadiness {
        required: required.into_boxed_slice(),
        satisfied: satisfied.into_boxed_slice(),
        reasons: reasons.into_boxed_slice(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_is_exact_and_errors_are_source_free() {
        let contract: serde_json::Value =
            serde_json::from_str(RUNTIME_FOUNDATION_CONTRACT).expect("foundation contract");
        assert_eq!(contract["schema_version"], 1);
        assert_eq!(contract["state_open"]["initialize_if_missing"], false);
        assert_eq!(contract["transport"]["invoked_during_foundation"], false);
        for kind in [
            RhiRuntimeFoundationErrorKind::StateOpen,
            RhiRuntimeFoundationErrorKind::IdentityBinding,
            RhiRuntimeFoundationErrorKind::IdentityAccess,
            RhiRuntimeFoundationErrorKind::Readiness,
            RhiRuntimeFoundationErrorKind::TaskFailure,
            RhiRuntimeFoundationErrorKind::Close,
        ] {
            let error = RhiRuntimeFoundationError::new(kind);
            assert!(!error.code().is_empty());
            assert!(!error.to_string().is_empty());
            assert!(Error::source(&error).is_none());
        }
    }
}
