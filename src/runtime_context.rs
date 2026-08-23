//! Sealed bootstrap binding for one canonical RHI service instance.

use core::fmt;
use std::{error::Error, path::Path};

use radroots_runtime_paths::{
    RadrootsPathProfile, RadrootsPathResolver, RadrootsServiceInstanceArtifacts, RuntimeContext,
    RuntimeContextBootstrap, RuntimeContextSource, ServiceCredentialArtifactName, ServiceId,
    default_service_instance_artifacts, service_credential_artifact_path,
};

use crate::{RhiBootstrapProfileV1, RhiCliInvocationV1};

const RHI_SERVICE_ID: &str = "rhi";
const RHI_IDENTITY_ARTIFACT_NAME: &str = "service.identity.ncrypt";

/// Stable source-free classification for RHI runtime-context failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RhiRuntimeContextErrorKind {
    InvalidServiceIdentity,
    InvalidBootstrapBinding,
    PathSelection,
}

impl RhiRuntimeContextErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidServiceIdentity => "RHI service identity is invalid",
            Self::InvalidBootstrapBinding => "RHI bootstrap selectors are inconsistent",
            Self::PathSelection => "RHI runtime path selection failed",
        }
    }
}

/// One redacted RHI runtime-context failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RhiRuntimeContextError {
    kind: RhiRuntimeContextErrorKind,
}

impl RhiRuntimeContextError {
    const fn new(kind: RhiRuntimeContextErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> RhiRuntimeContextErrorKind {
        self.kind
    }
}

impl fmt::Debug for RhiRuntimeContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiRuntimeContextError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for RhiRuntimeContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for RhiRuntimeContextError {}

/// Immutable canonical paths and bootstrap selection for one RHI instance.
///
/// Construction is sealed to the validated CLI invocation and the shared
/// runtime-path resolver. Callers cannot forge another service identity, path
/// set, artifact name, or selected configuration path:
///
/// ```compile_fail
/// use rhi::RhiRuntimeContext;
///
/// let _ = RhiRuntimeContext {
///     context: todo!(),
///     artifacts: todo!(),
///     selected_config_path: todo!(),
///     profile: todo!(),
/// };
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct RhiRuntimeContext {
    context: RuntimeContext,
    artifacts: RadrootsServiceInstanceArtifacts,
    identity_path: std::path::PathBuf,
    selected_config_path: std::path::PathBuf,
    profile: RhiBootstrapProfileV1,
}

impl RhiRuntimeContext {
    /// Returns the shared immutable service-instance context.
    #[must_use]
    pub const fn context(&self) -> &RuntimeContext {
        &self.context
    }

    /// Returns the exact common service artifacts.
    #[must_use]
    pub const fn artifacts(&self) -> &RadrootsServiceInstanceArtifacts {
        &self.artifacts
    }

    /// Returns the exact validated encrypted service-identity artifact path.
    #[must_use]
    pub fn identity_path(&self) -> &Path {
        &self.identity_path
    }

    /// Returns the explicit or canonical configuration artifact selected once.
    #[must_use]
    pub fn selected_config_path(&self) -> &Path {
        &self.selected_config_path
    }

    /// Returns the validated bootstrap profile.
    #[must_use]
    pub const fn profile(&self) -> RhiBootstrapProfileV1 {
        self.profile
    }
}

impl fmt::Debug for RhiRuntimeContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RhiRuntimeContext")
            .field("profile", &self.profile)
            .field("service", &RHI_SERVICE_ID)
            .field("instance", &"[redacted]")
            .field("paths", &"[redacted]")
            .finish()
    }
}

/// Resolves one validated CLI selection into the sole RHI path authority.
pub fn resolve_rhi_runtime_context(
    resolver: &RadrootsPathResolver,
    invocation: &RhiCliInvocationV1,
) -> Result<RhiRuntimeContext, RhiRuntimeContextError> {
    let profile = invocation.profile();
    let path_profile = match profile {
        RhiBootstrapProfileV1::ServiceHost => RadrootsPathProfile::ServiceHost,
        RhiBootstrapProfileV1::Interactive => RadrootsPathProfile::InteractiveUser,
        RhiBootstrapProfileV1::RepoLocal => RadrootsPathProfile::RepoLocal,
    };
    let bootstrap = RuntimeContextBootstrap::new(
        path_profile,
        invocation.repo_local_root().map(Path::to_path_buf),
        RuntimeContextSource::BootstrapCli,
        RuntimeContextSource::BootstrapCli,
    )
    .map_err(|_| {
        RhiRuntimeContextError::new(RhiRuntimeContextErrorKind::InvalidBootstrapBinding)
    })?;
    let service = ServiceId::new(RHI_SERVICE_ID).map_err(|_| {
        RhiRuntimeContextError::new(RhiRuntimeContextErrorKind::InvalidServiceIdentity)
    })?;
    let context =
        RuntimeContext::resolve(resolver, bootstrap, service, invocation.instance().clone())
            .map_err(|_| RhiRuntimeContextError::new(RhiRuntimeContextErrorKind::PathSelection))?;
    let artifacts = default_service_instance_artifacts(context.paths());
    let identity_name =
        ServiceCredentialArtifactName::new(RHI_IDENTITY_ARTIFACT_NAME).map_err(|_| {
            RhiRuntimeContextError::new(RhiRuntimeContextErrorKind::InvalidServiceIdentity)
        })?;
    let identity_path = service_credential_artifact_path(context.paths(), &identity_name);
    let selected_config_path = invocation
        .config_path()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| artifacts.config().to_path_buf());

    Ok(RhiRuntimeContext {
        context,
        artifacts,
        identity_path,
        selected_config_path,
        profile,
    })
}
