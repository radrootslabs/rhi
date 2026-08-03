use thiserror::Error;

use std::path::PathBuf;

use super::{RadrootsPathProfile, RadrootsPlatform};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RadrootsRuntimePathsError {
    #[error("interactive_user on {platform} requires a home directory")]
    MissingHomeDir { platform: RadrootsPlatform },

    #[error("interactive_user on windows requires APPDATA and LOCALAPPDATA roots")]
    MissingWindowsUserDirs,

    #[error("service_host on windows requires a ProgramData root")]
    MissingWindowsProgramDataDir,

    #[error("repo_local requires an explicit repo-local base root")]
    MissingRepoLocalRoot,

    #[error("mobile_native requires explicit logical roots")]
    MissingMobileRoots,

    #[error("{profile} is not supported on {platform}")]
    UnsupportedProfilePlatform {
        profile: RadrootsPathProfile,
        platform: RadrootsPlatform,
    },

    #[error("runtime namespace `{value}` must be one non-empty path component")]
    InvalidNamespaceComponent { value: String },

    #[error("shared accounts data root `{path:?}` has no parent shared data root")]
    SharedAccountsDataRootMissingParent { path: PathBuf },
}
