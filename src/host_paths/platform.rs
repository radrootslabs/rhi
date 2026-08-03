use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadrootsPlatform {
    Linux,
    Macos,
    Windows,
    Android,
    Ios,
}

impl RadrootsPlatform {
    #[must_use]
    #[cfg(target_os = "android")]
    pub fn current() -> Self {
        Self::Android
    }

    #[must_use]
    #[cfg(target_os = "ios")]
    pub fn current() -> Self {
        Self::Ios
    }

    #[must_use]
    #[cfg(target_os = "macos")]
    pub fn current() -> Self {
        Self::Macos
    }

    #[must_use]
    #[cfg(target_os = "windows")]
    pub fn current() -> Self {
        Self::Windows
    }

    #[must_use]
    #[cfg(all(
        not(target_os = "android"),
        not(target_os = "ios"),
        not(target_os = "macos"),
        not(target_os = "windows")
    ))]
    pub fn current() -> Self {
        Self::Linux
    }

    #[must_use]
    pub fn is_unix_like(self) -> bool {
        matches!(self, Self::Linux | Self::Macos)
    }
}

impl fmt::Display for RadrootsPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Android => "android",
            Self::Ios => "ios",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadrootsPathProfile {
    InteractiveUser,
    ServiceHost,
    RepoLocal,
    MobileNative,
}

impl fmt::Display for RadrootsPathProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InteractiveUser => "interactive_user",
            Self::ServiceHost => "service_host",
            Self::RepoLocal => "repo_local",
            Self::MobileNative => "mobile_native",
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RadrootsHostEnvironment {
    pub home_dir: Option<PathBuf>,
    pub appdata_dir: Option<PathBuf>,
    pub localappdata_dir: Option<PathBuf>,
    pub programdata_dir: Option<PathBuf>,
}

impl RadrootsHostEnvironment {
    #[must_use]
    pub fn from_current_process() -> Self {
        Self {
            home_dir: std::env::var_os("HOME").map(PathBuf::from),
            appdata_dir: std::env::var_os("APPDATA").map(PathBuf::from),
            localappdata_dir: std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
            programdata_dir: std::env::var_os("ProgramData").map(PathBuf::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{RadrootsHostEnvironment, RadrootsPathProfile, RadrootsPlatform};

    #[test]
    fn current_matches_compiled_target_platform() {
        #[cfg(target_os = "android")]
        let expected = RadrootsPlatform::Android;
        #[cfg(target_os = "ios")]
        let expected = RadrootsPlatform::Ios;
        #[cfg(target_os = "macos")]
        let expected = RadrootsPlatform::Macos;
        #[cfg(target_os = "windows")]
        let expected = RadrootsPlatform::Windows;
        #[cfg(all(
            not(target_os = "android"),
            not(target_os = "ios"),
            not(target_os = "macos"),
            not(target_os = "windows")
        ))]
        let expected = RadrootsPlatform::Linux;

        assert_eq!(RadrootsPlatform::current(), expected);
    }

    #[test]
    fn unix_like_classification_is_explicit() {
        assert!(RadrootsPlatform::Linux.is_unix_like());
        assert!(RadrootsPlatform::Macos.is_unix_like());
        assert!(!RadrootsPlatform::Windows.is_unix_like());
        assert!(!RadrootsPlatform::Android.is_unix_like());
        assert!(!RadrootsPlatform::Ios.is_unix_like());
    }

    #[test]
    fn display_uses_canonical_labels() {
        assert_eq!(RadrootsPlatform::Linux.to_string(), "linux");
        assert_eq!(RadrootsPlatform::Macos.to_string(), "macos");
        assert_eq!(RadrootsPlatform::Windows.to_string(), "windows");
        assert_eq!(RadrootsPlatform::Android.to_string(), "android");
        assert_eq!(RadrootsPlatform::Ios.to_string(), "ios");

        assert_eq!(
            RadrootsPathProfile::InteractiveUser.to_string(),
            "interactive_user"
        );
        assert_eq!(RadrootsPathProfile::ServiceHost.to_string(), "service_host");
        assert_eq!(RadrootsPathProfile::RepoLocal.to_string(), "repo_local");
        assert_eq!(
            RadrootsPathProfile::MobileNative.to_string(),
            "mobile_native"
        );
    }

    #[test]
    fn host_environment_reads_current_process_variables() {
        let env = RadrootsHostEnvironment::from_current_process();
        assert_eq!(env.home_dir, std::env::var_os("HOME").map(PathBuf::from));
        assert_eq!(
            env.appdata_dir,
            std::env::var_os("APPDATA").map(PathBuf::from)
        );
        assert_eq!(
            env.localappdata_dir,
            std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
        );
        assert_eq!(
            env.programdata_dir,
            std::env::var_os("ProgramData").map(PathBuf::from)
        );
    }
}
