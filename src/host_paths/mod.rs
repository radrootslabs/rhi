//! RHI-owned host path policy.

mod error;
mod namespace;
mod platform;
mod roots;

pub use error::RadrootsRuntimePathsError;
pub use namespace::{RadrootsRuntimeNamespace, RadrootsRuntimeNamespaceKind};
pub use platform::{RadrootsHostEnvironment, RadrootsPathProfile, RadrootsPlatform};
pub use roots::{RadrootsPathOverrides, RadrootsPathResolver, RadrootsPaths};
