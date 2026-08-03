use std::path::{Path, PathBuf};

use super::{
    RadrootsHostEnvironment, RadrootsPathProfile, RadrootsPlatform, RadrootsRuntimeNamespace,
    RadrootsRuntimePathsError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadrootsPaths {
    pub config: PathBuf,
    pub data: PathBuf,
    pub cache: PathBuf,
    pub logs: PathBuf,
    pub run: PathBuf,
    pub secrets: PathBuf,
}

impl RadrootsPaths {
    #[must_use]
    pub fn from_base_root(base_root: impl AsRef<Path>) -> Self {
        let base_root = base_root.as_ref();
        Self {
            config: base_root.join("config"),
            data: base_root.join("data"),
            cache: base_root.join("cache"),
            logs: base_root.join("logs"),
            run: base_root.join("run"),
            secrets: base_root.join("secrets"),
        }
    }

    #[must_use]
    pub fn namespaced(&self, namespace: &RadrootsRuntimeNamespace) -> Self {
        let relative = namespace.relative_path();
        Self {
            config: self.config.join(&relative),
            data: self.data.join(&relative),
            cache: self.cache.join(&relative),
            logs: self.logs.join(&relative),
            run: self.run.join(&relative),
            secrets: self.secrets.join(relative),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RadrootsPathOverrides {
    pub repo_local_root: Option<PathBuf>,
    pub mobile_roots: Option<RadrootsPaths>,
}

impl RadrootsPathOverrides {
    #[must_use]
    pub fn repo_local(base_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_local_root: Some(base_root.into()),
            mobile_roots: None,
        }
    }

    #[must_use]
    pub fn mobile(roots: RadrootsPaths) -> Self {
        Self {
            repo_local_root: None,
            mobile_roots: Some(roots),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadrootsPathResolver {
    platform: RadrootsPlatform,
    host_environment: RadrootsHostEnvironment,
}

impl RadrootsPathResolver {
    #[must_use]
    pub fn new(platform: RadrootsPlatform, host_environment: RadrootsHostEnvironment) -> Self {
        Self {
            platform,
            host_environment,
        }
    }

    #[must_use]
    pub fn current() -> Self {
        Self::new(
            RadrootsPlatform::current(),
            RadrootsHostEnvironment::from_current_process(),
        )
    }

    #[must_use]
    pub fn platform(&self) -> RadrootsPlatform {
        self.platform
    }

    pub fn resolve(
        &self,
        profile: RadrootsPathProfile,
        overrides: &RadrootsPathOverrides,
    ) -> Result<RadrootsPaths, RadrootsRuntimePathsError> {
        match profile {
            RadrootsPathProfile::InteractiveUser => self.resolve_interactive_user(),
            RadrootsPathProfile::ServiceHost => self.resolve_service_host(),
            RadrootsPathProfile::RepoLocal => overrides
                .repo_local_root
                .as_ref()
                .map(RadrootsPaths::from_base_root)
                .ok_or(RadrootsRuntimePathsError::MissingRepoLocalRoot),
            RadrootsPathProfile::MobileNative => match self.platform {
                RadrootsPlatform::Android | RadrootsPlatform::Ios => overrides
                    .mobile_roots
                    .clone()
                    .ok_or(RadrootsRuntimePathsError::MissingMobileRoots),
                _ => Err(RadrootsRuntimePathsError::UnsupportedProfilePlatform {
                    profile,
                    platform: self.platform,
                }),
            },
        }
    }

    fn resolve_interactive_user(&self) -> Result<RadrootsPaths, RadrootsRuntimePathsError> {
        match self.platform {
            RadrootsPlatform::Linux | RadrootsPlatform::Macos => self
                .host_environment
                .home_dir
                .as_ref()
                .map(|home| RadrootsPaths::from_base_root(home.join(".radroots")))
                .ok_or(RadrootsRuntimePathsError::MissingHomeDir {
                    platform: self.platform,
                }),
            RadrootsPlatform::Windows => {
                let appdata = self
                    .host_environment
                    .appdata_dir
                    .as_ref()
                    .ok_or(RadrootsRuntimePathsError::MissingWindowsUserDirs)?;
                let localappdata = self
                    .host_environment
                    .localappdata_dir
                    .as_ref()
                    .ok_or(RadrootsRuntimePathsError::MissingWindowsUserDirs)?;
                let config_root = appdata.join("Radroots");
                let local_root = localappdata.join("Radroots");
                Ok(RadrootsPaths {
                    config: config_root.join("config"),
                    data: local_root.join("data"),
                    cache: local_root.join("cache"),
                    logs: local_root.join("logs"),
                    run: local_root.join("run"),
                    secrets: config_root.join("secrets"),
                })
            }
            RadrootsPlatform::Android | RadrootsPlatform::Ios => {
                Err(RadrootsRuntimePathsError::UnsupportedProfilePlatform {
                    profile: RadrootsPathProfile::InteractiveUser,
                    platform: self.platform,
                })
            }
        }
    }

    fn resolve_service_host(&self) -> Result<RadrootsPaths, RadrootsRuntimePathsError> {
        match self.platform {
            RadrootsPlatform::Windows => {
                let programdata = self
                    .host_environment
                    .programdata_dir
                    .as_ref()
                    .ok_or(RadrootsRuntimePathsError::MissingWindowsProgramDataDir)?;
                let base = programdata.join("Radroots");
                Ok(RadrootsPaths {
                    config: base.join("config"),
                    data: base.join("data"),
                    cache: base.join("cache"),
                    logs: base.join("logs"),
                    run: base.join("run"),
                    secrets: base.join("secrets"),
                })
            }
            RadrootsPlatform::Linux | RadrootsPlatform::Macos => Ok(RadrootsPaths {
                config: PathBuf::from("/etc/radroots"),
                data: PathBuf::from("/var/lib/radroots"),
                cache: PathBuf::from("/var/cache/radroots"),
                logs: PathBuf::from("/var/log/radroots"),
                run: PathBuf::from("/run/radroots"),
                secrets: PathBuf::from("/etc/radroots/secrets"),
            }),
            RadrootsPlatform::Android | RadrootsPlatform::Ios => {
                Err(RadrootsRuntimePathsError::UnsupportedProfilePlatform {
                    profile: RadrootsPathProfile::ServiceHost,
                    platform: self.platform,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        RadrootsHostEnvironment, RadrootsPathProfile, RadrootsPlatform, RadrootsRuntimePathsError,
    };
    use super::{RadrootsPathOverrides, RadrootsPathResolver, RadrootsPaths};

    #[test]
    fn path_override_helpers_only_populate_their_owned_slot() {
        let repo_local = RadrootsPathOverrides::repo_local("/repo/.local/radroots");
        assert_eq!(
            repo_local.repo_local_root,
            Some(PathBuf::from("/repo/.local/radroots"))
        );
        assert!(repo_local.mobile_roots.is_none());

        let mobile_roots = RadrootsPaths::from_base_root("/sandbox");
        let mobile = RadrootsPathOverrides::mobile(mobile_roots.clone());
        assert!(mobile.repo_local_root.is_none());
        assert_eq!(mobile.mobile_roots, Some(mobile_roots));
    }

    #[test]
    fn resolver_current_uses_process_platform_and_environment() {
        let resolver = RadrootsPathResolver::current();
        assert_eq!(resolver.platform(), RadrootsPlatform::current());
        assert_eq!(
            resolver,
            RadrootsPathResolver::new(
                RadrootsPlatform::current(),
                RadrootsHostEnvironment::from_current_process()
            )
        );
    }

    #[test]
    fn mobile_profile_is_rejected_on_non_mobile_platforms() {
        let resolver =
            RadrootsPathResolver::new(RadrootsPlatform::Linux, RadrootsHostEnvironment::default());

        let err = resolver
            .resolve(
                RadrootsPathProfile::MobileNative,
                &RadrootsPathOverrides::default(),
            )
            .expect_err("mobile profile should be rejected on linux");

        assert_eq!(
            err,
            RadrootsRuntimePathsError::UnsupportedProfilePlatform {
                profile: RadrootsPathProfile::MobileNative,
                platform: RadrootsPlatform::Linux,
            }
        );
    }

    #[test]
    fn interactive_user_is_rejected_on_mobile_platforms() {
        for platform in [RadrootsPlatform::Android, RadrootsPlatform::Ios] {
            let resolver = RadrootsPathResolver::new(platform, RadrootsHostEnvironment::default());
            let err = resolver
                .resolve(
                    RadrootsPathProfile::InteractiveUser,
                    &RadrootsPathOverrides::default(),
                )
                .expect_err("interactive_user should be unsupported on mobile");
            assert_eq!(
                err,
                RadrootsRuntimePathsError::UnsupportedProfilePlatform {
                    profile: RadrootsPathProfile::InteractiveUser,
                    platform,
                }
            );
        }
    }

    #[test]
    fn service_host_windows_requires_programdata() {
        let resolver = RadrootsPathResolver::new(
            RadrootsPlatform::Windows,
            RadrootsHostEnvironment::default(),
        );

        let err = resolver
            .resolve(
                RadrootsPathProfile::ServiceHost,
                &RadrootsPathOverrides::default(),
            )
            .expect_err("service_host on windows should require programdata");

        assert_eq!(err, RadrootsRuntimePathsError::MissingWindowsProgramDataDir);
    }

    #[test]
    fn service_host_is_rejected_on_mobile_platforms() {
        for platform in [RadrootsPlatform::Android, RadrootsPlatform::Ios] {
            let resolver = RadrootsPathResolver::new(platform, RadrootsHostEnvironment::default());
            let err = resolver
                .resolve(
                    RadrootsPathProfile::ServiceHost,
                    &RadrootsPathOverrides::default(),
                )
                .expect_err("service_host should be unsupported on mobile");
            assert_eq!(
                err,
                RadrootsRuntimePathsError::UnsupportedProfilePlatform {
                    profile: RadrootsPathProfile::ServiceHost,
                    platform,
                }
            );
        }
    }
}
