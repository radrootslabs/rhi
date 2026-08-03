use std::path::PathBuf;

use super::RadrootsRuntimePathsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadrootsRuntimeNamespaceKind {
    App,
    Service,
    Worker,
    Shared,
}

impl RadrootsRuntimeNamespaceKind {
    #[must_use]
    pub fn path_segment(self) -> &'static str {
        match self {
            Self::App => "apps",
            Self::Service => "services",
            Self::Worker => "workers",
            Self::Shared => "shared",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadrootsRuntimeNamespace {
    kind: RadrootsRuntimeNamespaceKind,
    value: String,
}

impl RadrootsRuntimeNamespace {
    pub fn app(value: impl Into<String>) -> Result<Self, RadrootsRuntimePathsError> {
        Self::new(RadrootsRuntimeNamespaceKind::App, value)
    }

    pub fn service(value: impl Into<String>) -> Result<Self, RadrootsRuntimePathsError> {
        Self::new(RadrootsRuntimeNamespaceKind::Service, value)
    }

    pub fn worker(value: impl Into<String>) -> Result<Self, RadrootsRuntimePathsError> {
        Self::new(RadrootsRuntimeNamespaceKind::Worker, value)
    }

    pub fn shared(value: impl Into<String>) -> Result<Self, RadrootsRuntimePathsError> {
        Self::new(RadrootsRuntimeNamespaceKind::Shared, value)
    }

    pub fn new(
        kind: RadrootsRuntimeNamespaceKind,
        value: impl Into<String>,
    ) -> Result<Self, RadrootsRuntimePathsError> {
        let value = value.into();
        validate_component(&value)?;
        Ok(Self { kind, value })
    }

    #[must_use]
    pub fn kind(&self) -> RadrootsRuntimeNamespaceKind {
        self.kind
    }

    #[must_use]
    pub fn value(&self) -> &str {
        self.value.as_str()
    }

    #[must_use]
    pub fn relative_path(&self) -> PathBuf {
        PathBuf::from(self.kind.path_segment()).join(self.value.as_str())
    }
}

fn validate_component(value: &str) -> Result<(), RadrootsRuntimePathsError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return Err(RadrootsRuntimePathsError::InvalidNamespaceComponent {
            value: value.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::RadrootsRuntimePathsError;
    use super::{RadrootsRuntimeNamespace, RadrootsRuntimeNamespaceKind};

    #[test]
    fn namespace_kind_path_segments_are_canonical() {
        assert_eq!(RadrootsRuntimeNamespaceKind::App.path_segment(), "apps");
        assert_eq!(
            RadrootsRuntimeNamespaceKind::Service.path_segment(),
            "services"
        );
        assert_eq!(
            RadrootsRuntimeNamespaceKind::Worker.path_segment(),
            "workers"
        );
        assert_eq!(
            RadrootsRuntimeNamespaceKind::Shared.path_segment(),
            "shared"
        );
    }

    #[test]
    fn namespace_constructors_preserve_kind_and_value() {
        let app = RadrootsRuntimeNamespace::app("cli").expect("app namespace");
        assert_eq!(app.kind(), RadrootsRuntimeNamespaceKind::App);
        assert_eq!(app.value(), "cli");
        assert_eq!(app.relative_path(), PathBuf::from("apps/cli"));

        let service = RadrootsRuntimeNamespace::service("myc").expect("service namespace");
        assert_eq!(service.kind(), RadrootsRuntimeNamespaceKind::Service);
        assert_eq!(service.value(), "myc");
        assert_eq!(service.relative_path(), PathBuf::from("services/myc"));

        let worker = RadrootsRuntimeNamespace::worker("rhi").expect("worker namespace");
        assert_eq!(worker.kind(), RadrootsRuntimeNamespaceKind::Worker);
        assert_eq!(worker.value(), "rhi");
        assert_eq!(worker.relative_path(), PathBuf::from("workers/rhi"));

        let shared = RadrootsRuntimeNamespace::shared("runtime").expect("shared namespace");
        assert_eq!(shared.kind(), RadrootsRuntimeNamespaceKind::Shared);
        assert_eq!(shared.value(), "runtime");
        assert_eq!(shared.relative_path(), PathBuf::from("shared/runtime"));
    }

    #[test]
    fn namespace_validation_rejects_invalid_components() {
        for invalid in ["", "   ", ".", "..", "a/b", r"a\b"] {
            let err = RadrootsRuntimeNamespace::new(RadrootsRuntimeNamespaceKind::App, invalid)
                .expect_err("invalid namespace component should fail");
            assert_eq!(
                err,
                RadrootsRuntimePathsError::InvalidNamespaceComponent {
                    value: invalid.to_owned(),
                }
            );
        }
    }
}
