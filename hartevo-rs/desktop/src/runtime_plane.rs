use std::env;
use std::path::{Path, PathBuf};

use hartevo_runtime_adapter::{
    AdapterError, OPENINTERPRETER_RELEASE, VerifiedRuntimeArtifact, host_openinterpreter_target,
    pinned_runtime_artifact, verify_pinned_runtime_artifact,
};

pub const RUNTIME_PROGRAM_ENV: &str = "HARTEVO_OPENINTERPRETER_BIN";
pub const RUNTIME_PROVIDER_ENV: &str = "HARTEVO_RUNTIME_PROVIDER";
pub const RUNTIME_MODEL_ENV: &str = "HARTEVO_RUNTIME_MODEL";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopRuntimeAvailabilityStatus {
    NotConfigured,
    ConfigurationRequired,
    EvidenceMissing,
    ReadyDevelopment,
    ReadyDistribution,
    BlockedEnvironment,
    IntegrityError,
    UnsupportedHost,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopRuntimeProjection {
    pub status: DesktopRuntimeAvailabilityStatus,
    pub target: Option<String>,
    pub release: String,
    pub program_sha256: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub distribution_signature_evidence: Option<String>,
    /// This remains false while Desktop uses the conservative UTF-8 byte
    /// budget. It prevents the Journey from being counted as production
    /// tokenizer/model-revision evidence.
    pub exact_tokenizer_evidence: bool,
}

impl DesktopRuntimeProjection {
    fn with_status(status: DesktopRuntimeAvailabilityStatus, target: Option<String>) -> Self {
        Self {
            status,
            target,
            release: OPENINTERPRETER_RELEASE.into(),
            program_sha256: None,
            provider: normalized_env(RUNTIME_PROVIDER_ENV),
            model: normalized_env(RUNTIME_MODEL_ENV),
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        }
    }
}

pub(crate) struct DesktopRuntimeConfiguration {
    pub projection: DesktopRuntimeProjection,
    pub artifact: VerifiedRuntimeArtifact,
    pub provider: String,
    pub model: String,
}

impl std::fmt::Debug for DesktopRuntimeConfiguration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeConfiguration")
            .field("projection", &self.projection)
            .field("artifact", &self.artifact)
            .finish_non_exhaustive()
    }
}

pub(crate) struct DesktopRuntimeDiscovery {
    pub projection: DesktopRuntimeProjection,
    pub configuration: Option<DesktopRuntimeConfiguration>,
}

pub(crate) fn discover_runtime() -> DesktopRuntimeDiscovery {
    let target = match host_openinterpreter_target() {
        Ok(target) => target.to_owned(),
        Err(_) => {
            return unavailable(DesktopRuntimeAvailabilityStatus::UnsupportedHost, None);
        }
    };
    let pinned = match pinned_runtime_artifact(&target) {
        Ok(pinned) => pinned,
        Err(AdapterError::RuntimeArtifactEvidenceMissing) => {
            return unavailable(
                DesktopRuntimeAvailabilityStatus::EvidenceMissing,
                Some(target),
            );
        }
        Err(AdapterError::RuntimeHostUnsupported | AdapterError::RuntimeArtifactUnavailable) => {
            return unavailable(
                DesktopRuntimeAvailabilityStatus::UnsupportedHost,
                Some(target),
            );
        }
        Err(_) => {
            return unavailable(
                DesktopRuntimeAvailabilityStatus::IntegrityError,
                Some(target),
            );
        }
    };
    if pinned.entrypoint_sha256.is_none() || pinned.package_metadata_sha256.is_none() {
        return unavailable(
            DesktopRuntimeAvailabilityStatus::EvidenceMissing,
            Some(target),
        );
    }
    let Some(program) = configured_or_bundled_program() else {
        return unavailable(
            DesktopRuntimeAvailabilityStatus::NotConfigured,
            Some(target),
        );
    };
    let artifact = match verify_pinned_runtime_artifact(&program, &target) {
        Ok(artifact) => artifact,
        Err(AdapterError::RuntimeArtifactEvidenceMissing) => {
            return unavailable(
                DesktopRuntimeAvailabilityStatus::EvidenceMissing,
                Some(target),
            );
        }
        Err(AdapterError::Io(_)) => {
            return unavailable(
                DesktopRuntimeAvailabilityStatus::BlockedEnvironment,
                Some(target),
            );
        }
        Err(_) => {
            return unavailable(
                DesktopRuntimeAvailabilityStatus::IntegrityError,
                Some(target),
            );
        }
    };
    let (Some(provider), Some(model)) = (
        normalized_env(RUNTIME_PROVIDER_ENV),
        normalized_env(RUNTIME_MODEL_ENV),
    ) else {
        let mut projection = DesktopRuntimeProjection::with_status(
            DesktopRuntimeAvailabilityStatus::ConfigurationRequired,
            Some(target),
        );
        projection.program_sha256 = Some(artifact.program_sha256.clone());
        projection.distribution_signature_evidence =
            Some(artifact.distribution_signature_evidence.clone());
        return DesktopRuntimeDiscovery {
            projection,
            configuration: None,
        };
    };
    let status = if artifact.distribution_ready() {
        DesktopRuntimeAvailabilityStatus::ReadyDistribution
    } else {
        DesktopRuntimeAvailabilityStatus::ReadyDevelopment
    };
    let projection = DesktopRuntimeProjection {
        status,
        target: Some(target),
        release: artifact.release.clone(),
        program_sha256: Some(artifact.program_sha256.clone()),
        provider: Some(provider.clone()),
        model: Some(model.clone()),
        distribution_signature_evidence: Some(artifact.distribution_signature_evidence.clone()),
        exact_tokenizer_evidence: false,
    };
    DesktopRuntimeDiscovery {
        projection: projection.clone(),
        configuration: Some(DesktopRuntimeConfiguration {
            projection,
            artifact,
            provider,
            model,
        }),
    }
}

fn unavailable(
    status: DesktopRuntimeAvailabilityStatus,
    target: Option<String>,
) -> DesktopRuntimeDiscovery {
    DesktopRuntimeDiscovery {
        projection: DesktopRuntimeProjection::with_status(status, target),
        configuration: None,
    }
}

fn normalized_env(name: &str) -> Option<String> {
    let value = env::var(name).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn configured_or_bundled_program() -> Option<PathBuf> {
    if let Some(program) = env::var_os(RUNTIME_PROGRAM_ENV) {
        return Some(PathBuf::from(program));
    }
    bundled_runtime_program()
}

fn bundled_runtime_program() -> Option<PathBuf> {
    let executable = env::current_exe().ok()?;
    let executable_directory = executable.parent()?;
    let file_name = if cfg!(windows) {
        "interpreter.exe"
    } else {
        "interpreter"
    };
    let mut candidates = vec![
        executable_directory
            .join("resources")
            .join("runtime")
            .join("openinterpreter")
            .join("bin")
            .join(file_name),
    ];
    if cfg!(target_os = "macos") {
        candidates.push(
            executable_directory
                .parent()?
                .join("Resources")
                .join("runtime")
                .join("openinterpreter")
                .join("bin")
                .join(file_name),
        );
    }
    candidates.into_iter().find(|candidate| candidate.is_file())
}

pub(crate) fn ensure_project_runtime_home(
    project_root: &Path,
    mission_scope_digest: &str,
) -> std::io::Result<PathBuf> {
    if mission_scope_digest.len() != 64
        || !mission_scope_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid mission scope digest",
        ));
    }
    let project_root = project_root.canonicalize()?;
    if !project_root.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotADirectory,
            "project root is not a directory",
        ));
    }
    let mut cursor = project_root.join(".hartevo");
    ensure_directory_without_symlink(&cursor)?;
    for segment in ["runtime", "openinterpreter", mission_scope_digest] {
        cursor = cursor.join(segment);
        ensure_directory_without_symlink(&cursor)?;
    }
    let canonical = cursor.canonicalize()?;
    if !canonical.starts_with(&project_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "runtime home escaped the project root",
        ));
    }
    Ok(canonical)
}

fn ensure_directory_without_symlink(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "runtime directory is not a real directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path)?;
        }
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn runtime_home_is_project_scoped_and_symlink_fenced() {
        let project = tempfile::tempdir().expect("project");
        let digest = format!("{:x}", Sha256::digest(b"mission-runtime-home"));
        let home = ensure_project_runtime_home(project.path(), &digest).expect("runtime home");
        assert!(home.starts_with(project.path().canonicalize().expect("canonical project")));
        assert!(home.ends_with(&digest));
        assert_eq!(
            ensure_project_runtime_home(project.path(), &digest).expect("idempotent home"),
            home
        );
        assert!(ensure_project_runtime_home(project.path(), "../escape").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn runtime_home_rejects_symlink_component() {
        use std::os::unix::fs::symlink;

        let project = tempfile::tempdir().expect("project");
        let foreign = tempfile::tempdir().expect("foreign");
        std::fs::create_dir(project.path().join(".hartevo")).expect("private root");
        symlink(foreign.path(), project.path().join(".hartevo/runtime")).expect("symlink");
        let digest = format!("{:x}", Sha256::digest(b"mission-runtime-home-symlink"));
        assert!(ensure_project_runtime_home(project.path(), &digest).is_err());
        assert!(!foreign.path().join("openinterpreter").exists());
    }
}
