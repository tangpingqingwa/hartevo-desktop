use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hartevo_application::llm_deepseek::{
    DEEPSEEK_PROVIDER_ID, DeepSeekAdapterError, DeepSeekCredentialResolver,
};
use hartevo_runtime_adapter::{
    AdapterError, OPENINTERPRETER_RELEASE, VerifiedRuntimeArtifact, host_openinterpreter_target,
    pinned_runtime_artifact, verify_pinned_runtime_artifact,
};
use hartevo_storage::{SecretBytes, SecretReference, SecretStore, SecretStoreError};
use zeroize::Zeroizing;

pub const RUNTIME_PROGRAM_ENV: &str = "HARTEVO_OPENINTERPRETER_BIN";
pub const RUNTIME_PROVIDER_ENV: &str = "HARTEVO_RUNTIME_PROVIDER";
pub const RUNTIME_MODEL_ENV: &str = "HARTEVO_RUNTIME_MODEL";
pub(crate) const DEEPSEEK_CREDENTIAL_ENV: &str = "DEEPSEEK_API_KEY";
const CORDIS_NATIVE_TARGET: &str = "cordis-native";
const DEEPSEEK_NATIVE_RELEASE: &str = "deepseek-harness-cd5ef814/cordis-v1";
const NATIVE_PROFILE_MAGIC: &[u8] = b"hartevo-desktop-deepseek-profile-v1\0";
const MAX_NATIVE_MODEL_BYTES: usize = 1_024;
const MAX_NATIVE_CREDENTIAL_BYTES: usize = 4_096;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesktopNativeCredentialSource {
    DesktopProfile,
    Environment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopRuntimeProjection {
    pub status: DesktopRuntimeAvailabilityStatus,
    pub target: Option<String>,
    pub release: String,
    pub program_sha256: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub native_credential_source: Option<DesktopNativeCredentialSource>,
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
            native_credential_source: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        }
    }

    pub(crate) fn is_cordis_native(&self) -> bool {
        self.target.as_deref() == Some(CORDIS_NATIVE_TARGET)
    }
}

pub(crate) struct DesktopRuntimeConfiguration {
    pub projection: DesktopRuntimeProjection,
    pub artifact: Option<VerifiedRuntimeArtifact>,
    pub provider: String,
    pub model: String,
    pub native_profile_reference: Option<SecretReference>,
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

struct DesktopNativeDeepSeekProfile {
    model: String,
    credential: Zeroizing<String>,
}

impl DesktopNativeDeepSeekProfile {
    fn new(
        model: impl Into<String>,
        credential: Zeroizing<String>,
    ) -> Result<Self, SecretStoreError> {
        let model = model.into();
        if !valid_native_deepseek_settings(&model, &credential) {
            return Err(SecretStoreError::InvalidSecret);
        }
        Ok(Self { model, credential })
    }

    fn encode(&self) -> Result<SecretBytes, SecretStoreError> {
        let model_len =
            u32::try_from(self.model.len()).map_err(|_| SecretStoreError::InvalidSecret)?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(
            NATIVE_PROFILE_MAGIC.len() + 4 + self.model.len() + self.credential.len(),
        ));
        encoded.extend_from_slice(NATIVE_PROFILE_MAGIC);
        encoded.extend_from_slice(&model_len.to_be_bytes());
        encoded.extend_from_slice(self.model.as_bytes());
        encoded.extend_from_slice(self.credential.as_bytes());
        SecretBytes::new(encoded.to_vec())
    }

    fn decode(secret: &SecretBytes) -> Result<Self, SecretStoreError> {
        let bytes = secret.as_slice();
        let length_offset = NATIVE_PROFILE_MAGIC.len();
        let max_encoded_bytes =
            NATIVE_PROFILE_MAGIC.len() + 4 + MAX_NATIVE_MODEL_BYTES + MAX_NATIVE_CREDENTIAL_BYTES;
        if !bytes.starts_with(NATIVE_PROFILE_MAGIC)
            || bytes.len() < length_offset + 4
            || bytes.len() > max_encoded_bytes
        {
            return Err(SecretStoreError::InvalidSecret);
        }
        let model_len = u32::from_be_bytes(
            bytes[length_offset..length_offset + 4]
                .try_into()
                .map_err(|_| SecretStoreError::InvalidSecret)?,
        ) as usize;
        if model_len > MAX_NATIVE_MODEL_BYTES {
            return Err(SecretStoreError::InvalidSecret);
        }
        let model_start = length_offset + 4;
        let model_end = model_start
            .checked_add(model_len)
            .filter(|end| *end < bytes.len())
            .ok_or(SecretStoreError::InvalidSecret)?;
        if bytes.len() - model_end > MAX_NATIVE_CREDENTIAL_BYTES {
            return Err(SecretStoreError::InvalidSecret);
        }
        let model = String::from_utf8(bytes[model_start..model_end].to_vec())
            .map_err(|_| SecretStoreError::InvalidSecret)?;
        let credential = String::from_utf8(bytes[model_end..].to_vec())
            .map(Zeroizing::new)
            .map_err(|_| SecretStoreError::InvalidSecret)?;
        Self::new(model, credential)
    }
}

pub(crate) struct DesktopNativeDeepSeekCredentialResolver<S> {
    store: Arc<S>,
    reference: SecretReference,
    expected_model: String,
}

impl<S> DesktopNativeDeepSeekCredentialResolver<S> {
    pub(crate) fn new(store: Arc<S>, reference: SecretReference, expected_model: String) -> Self {
        Self {
            store,
            reference,
            expected_model,
        }
    }
}

impl<S> std::fmt::Debug for DesktopNativeDeepSeekCredentialResolver<S> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DesktopNativeDeepSeekCredentialResolver")
            .field("reference", &self.reference)
            .field("expected_model", &self.expected_model)
            .finish_non_exhaustive()
    }
}

impl<S> DeepSeekCredentialResolver for DesktopNativeDeepSeekCredentialResolver<S>
where
    S: SecretStore + 'static,
{
    fn resolve(&self, name: &str) -> Result<Zeroizing<String>, DeepSeekAdapterError> {
        if name != DEEPSEEK_CREDENTIAL_ENV {
            return Err(DeepSeekAdapterError::InvalidConnection);
        }
        let secret = self
            .store
            .get(&self.reference)
            .map_err(|error| match error {
                SecretStoreError::SecretNotFound | SecretStoreError::BackendUnavailable => {
                    DeepSeekAdapterError::CredentialUnavailable
                }
                _ => DeepSeekAdapterError::InvalidCredential,
            })?;
        let profile = DesktopNativeDeepSeekProfile::decode(&secret)
            .map_err(|_| DeepSeekAdapterError::InvalidCredential)?;
        if profile.model != self.expected_model {
            return Err(DeepSeekAdapterError::InvalidConnection);
        }
        Ok(profile.credential)
    }
}

pub(crate) fn put_native_deepseek_profile(
    store: &impl SecretStore,
    reference: &SecretReference,
    model: impl Into<String>,
    credential: Zeroizing<String>,
) -> Result<(), SecretStoreError> {
    let profile = DesktopNativeDeepSeekProfile::new(model, credential)?;
    store.put(reference, &profile.encode()?)
}

pub(crate) fn clear_native_deepseek_profile(
    store: &impl SecretStore,
    reference: &SecretReference,
) -> Result<(), SecretStoreError> {
    match store.delete(reference) {
        Ok(()) | Err(SecretStoreError::SecretNotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopRuntimeBackend {
    CordisNative,
    OpenInterpreter,
}

enum NativeCredentialSource {
    Environment,
    DesktopProfile(SecretReference),
}

enum EnvironmentCredentialState {
    Missing,
    Ready,
    Invalid,
}

fn runtime_backend(provider: Option<&str>) -> DesktopRuntimeBackend {
    match provider {
        None | Some(DEEPSEEK_PROVIDER_ID) => DesktopRuntimeBackend::CordisNative,
        Some(_) => DesktopRuntimeBackend::OpenInterpreter,
    }
}

pub(crate) fn discover_runtime() -> DesktopRuntimeDiscovery {
    match runtime_backend(normalized_env(RUNTIME_PROVIDER_ENV).as_deref()) {
        DesktopRuntimeBackend::CordisNative => discover_environment_native_deepseek(),
        DesktopRuntimeBackend::OpenInterpreter => discover_openinterpreter(),
    }
}

pub(crate) fn discover_runtime_with_native_profile(
    store: &impl SecretStore,
    reference: &SecretReference,
) -> DesktopRuntimeDiscovery {
    match runtime_backend(normalized_env(RUNTIME_PROVIDER_ENV).as_deref()) {
        DesktopRuntimeBackend::OpenInterpreter => discover_openinterpreter(),
        DesktopRuntimeBackend::CordisNative => match load_native_deepseek_profile(store, reference)
        {
            Ok(profile) => discover_native_deepseek(
                Some(profile.model),
                Some(NativeCredentialSource::DesktopProfile(reference.clone())),
            ),
            Err(SecretStoreError::SecretNotFound) => discover_environment_native_deepseek(),
            Err(SecretStoreError::BackendUnavailable) => native_unavailable(
                DesktopRuntimeAvailabilityStatus::BlockedEnvironment,
                normalized_env(RUNTIME_MODEL_ENV),
            ),
            Err(_) => native_unavailable(
                DesktopRuntimeAvailabilityStatus::IntegrityError,
                normalized_env(RUNTIME_MODEL_ENV),
            ),
        },
    }
}

fn load_native_deepseek_profile(
    store: &impl SecretStore,
    reference: &SecretReference,
) -> Result<DesktopNativeDeepSeekProfile, SecretStoreError> {
    let secret = store.get(reference)?;
    DesktopNativeDeepSeekProfile::decode(&secret)
}

fn discover_openinterpreter() -> DesktopRuntimeDiscovery {
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
    let status = runtime_ready_status(&artifact);
    let projection = DesktopRuntimeProjection {
        status,
        target: Some(target),
        release: artifact.release.clone(),
        program_sha256: Some(artifact.program_sha256.clone()),
        provider: Some(provider.clone()),
        model: Some(model.clone()),
        native_credential_source: None,
        distribution_signature_evidence: Some(artifact.distribution_signature_evidence.clone()),
        exact_tokenizer_evidence: false,
    };
    DesktopRuntimeDiscovery {
        projection: projection.clone(),
        configuration: Some(DesktopRuntimeConfiguration {
            projection,
            artifact: Some(artifact),
            provider,
            model,
            native_profile_reference: None,
        }),
    }
}

fn runtime_ready_status(artifact: &VerifiedRuntimeArtifact) -> DesktopRuntimeAvailabilityStatus {
    if artifact.distribution_ready() {
        DesktopRuntimeAvailabilityStatus::ReadyDistribution
    } else {
        DesktopRuntimeAvailabilityStatus::ReadyDevelopment
    }
}

fn discover_environment_native_deepseek() -> DesktopRuntimeDiscovery {
    let model = normalized_env(RUNTIME_MODEL_ENV);
    match environment_credential_state() {
        EnvironmentCredentialState::Ready => {
            discover_native_deepseek(model, Some(NativeCredentialSource::Environment))
        }
        EnvironmentCredentialState::Missing => discover_native_deepseek(model, None),
        EnvironmentCredentialState::Invalid => {
            native_unavailable(DesktopRuntimeAvailabilityStatus::IntegrityError, model)
        }
    }
}

fn discover_native_deepseek(
    model: Option<String>,
    credentials: Option<NativeCredentialSource>,
) -> DesktopRuntimeDiscovery {
    let status = if model.is_some() && credentials.is_some() {
        DesktopRuntimeAvailabilityStatus::ReadyDistribution
    } else {
        DesktopRuntimeAvailabilityStatus::ConfigurationRequired
    };
    let native_credential_source = credentials.as_ref().map(|credentials| match credentials {
        NativeCredentialSource::Environment => DesktopNativeCredentialSource::Environment,
        NativeCredentialSource::DesktopProfile(_) => DesktopNativeCredentialSource::DesktopProfile,
    });
    let projection = DesktopRuntimeProjection {
        status,
        target: Some(CORDIS_NATIVE_TARGET.into()),
        release: DEEPSEEK_NATIVE_RELEASE.into(),
        program_sha256: None,
        provider: Some(DEEPSEEK_PROVIDER_ID.into()),
        model: model.clone(),
        native_credential_source,
        distribution_signature_evidence: None,
        exact_tokenizer_evidence: false,
    };
    let configuration = model.zip(credentials).map(|(model, credentials)| {
        let native_profile_reference = match credentials {
            NativeCredentialSource::Environment => None,
            NativeCredentialSource::DesktopProfile(reference) => Some(reference),
        };
        DesktopRuntimeConfiguration {
            projection: projection.clone(),
            artifact: None,
            provider: DEEPSEEK_PROVIDER_ID.into(),
            model,
            native_profile_reference,
        }
    });
    DesktopRuntimeDiscovery {
        projection,
        configuration,
    }
}

fn native_unavailable(
    status: DesktopRuntimeAvailabilityStatus,
    model: Option<String>,
) -> DesktopRuntimeDiscovery {
    DesktopRuntimeDiscovery {
        projection: DesktopRuntimeProjection {
            status,
            target: Some(CORDIS_NATIVE_TARGET.into()),
            release: DEEPSEEK_NATIVE_RELEASE.into(),
            program_sha256: None,
            provider: Some(DEEPSEEK_PROVIDER_ID.into()),
            model,
            native_credential_source: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        },
        configuration: None,
    }
}

fn environment_credential_state() -> EnvironmentCredentialState {
    match env::var(DEEPSEEK_CREDENTIAL_ENV) {
        Ok(value) => {
            let value = Zeroizing::new(value);
            if valid_native_credential(&value) {
                EnvironmentCredentialState::Ready
            } else {
                EnvironmentCredentialState::Invalid
            }
        }
        Err(env::VarError::NotUnicode(_)) => EnvironmentCredentialState::Invalid,
        Err(env::VarError::NotPresent) => EnvironmentCredentialState::Missing,
    }
}

fn valid_native_model(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NATIVE_MODEL_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn valid_native_credential(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NATIVE_CREDENTIAL_BYTES
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

pub(crate) fn valid_native_deepseek_settings(model: &str, credential: &str) -> bool {
    valid_native_model(model) && valid_native_credential(credential)
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
    use hartevo_domain_kernel::{ProjectId, TenantId};
    use hartevo_storage::MemorySecretStore;
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn cordis_native_is_the_default_and_openinterpreter_requires_explicit_selection() {
        assert_eq!(runtime_backend(None), DesktopRuntimeBackend::CordisNative);
        assert_eq!(
            runtime_backend(Some(DEEPSEEK_PROVIDER_ID)),
            DesktopRuntimeBackend::CordisNative
        );
        assert_eq!(
            runtime_backend(Some("openai")),
            DesktopRuntimeBackend::OpenInterpreter
        );

        let missing_model =
            discover_native_deepseek(None, Some(NativeCredentialSource::Environment));
        assert_eq!(
            missing_model.projection.status,
            DesktopRuntimeAvailabilityStatus::ConfigurationRequired
        );
        assert!(missing_model.projection.is_cordis_native());
        assert_eq!(
            missing_model.projection.provider.as_deref(),
            Some(DEEPSEEK_PROVIDER_ID)
        );
        assert_eq!(
            missing_model.projection.native_credential_source,
            Some(DesktopNativeCredentialSource::Environment)
        );
        assert!(missing_model.configuration.is_none());

        let missing_credential = discover_native_deepseek(Some("deepseek-chat".into()), None);
        assert_eq!(
            missing_credential.projection.status,
            DesktopRuntimeAvailabilityStatus::ConfigurationRequired
        );
        assert_eq!(missing_credential.projection.native_credential_source, None);
        assert!(missing_credential.configuration.is_none());
    }

    #[test]
    fn native_deepseek_discovery_needs_no_openinterpreter_artifact() {
        let discovery = discover_native_deepseek(
            Some("deepseek-chat".into()),
            Some(NativeCredentialSource::Environment),
        );
        assert_eq!(
            discovery.projection.status,
            DesktopRuntimeAvailabilityStatus::ReadyDistribution
        );
        assert_eq!(
            discovery.projection.target.as_deref(),
            Some(CORDIS_NATIVE_TARGET)
        );
        assert_eq!(
            discovery.projection.native_credential_source,
            Some(DesktopNativeCredentialSource::Environment)
        );
        assert!(discovery.projection.program_sha256.is_none());
        let configuration = discovery.configuration.expect("native configuration");
        assert_eq!(configuration.provider, DEEPSEEK_PROVIDER_ID);
        assert_eq!(configuration.model, "deepseek-chat");
        assert!(configuration.artifact.is_none());
        assert!(configuration.native_profile_reference.is_none());
    }

    #[test]
    fn native_credential_source_projection_is_typed_and_reference_free() {
        let reference = SecretReference {
            tenant_id: TenantId::from("local-desktop-installation"),
            project_id: ProjectId::from("desktop-runtime"),
            provider: DEEPSEEK_PROVIDER_ID.into(),
            account_scope: "private-data-root-reference".into(),
            purpose: "native_llm_profile".into(),
            version: 1,
        };
        let stored = discover_native_deepseek(
            Some("deepseek-chat".into()),
            Some(NativeCredentialSource::DesktopProfile(reference.clone())),
        );
        assert_eq!(
            stored.projection.native_credential_source,
            Some(DesktopNativeCredentialSource::DesktopProfile)
        );
        assert!(!format!("{:?}", stored.projection).contains("private-data-root-reference"));
        assert_eq!(
            stored
                .configuration
                .expect("stored native configuration")
                .native_profile_reference,
            Some(reference)
        );

        let environment = discover_native_deepseek(
            Some("deepseek-chat".into()),
            Some(NativeCredentialSource::Environment),
        );
        assert_eq!(
            environment.projection.native_credential_source,
            Some(DesktopNativeCredentialSource::Environment)
        );
        assert_eq!(
            native_unavailable(
                DesktopRuntimeAvailabilityStatus::IntegrityError,
                Some("deepseek-chat".into()),
            )
            .projection
            .native_credential_source,
            None
        );
        assert_eq!(
            DesktopRuntimeProjection::with_status(
                DesktopRuntimeAvailabilityStatus::NotConfigured,
                Some("openinterpreter-target".into()),
            )
            .native_credential_source,
            None
        );
    }

    #[test]
    fn native_profile_is_one_opaque_secret_and_resolves_only_its_exact_model() {
        let store = Arc::new(MemorySecretStore::default());
        let reference = SecretReference {
            tenant_id: TenantId::from("local-desktop-installation"),
            project_id: ProjectId::from("desktop-runtime"),
            provider: DEEPSEEK_PROVIDER_ID.into(),
            account_scope: "data-root:profile-a".into(),
            purpose: "native_llm_profile".into(),
            version: 1,
        };
        put_native_deepseek_profile(
            store.as_ref(),
            &reference,
            "deepseek-chat",
            Zeroizing::new("secret-deepseek-key".into()),
        )
        .expect("store profile");
        assert_eq!(store.entry_count().expect("entry count"), 1);

        let stored =
            load_native_deepseek_profile(store.as_ref(), &reference).expect("load profile");
        assert_eq!(stored.model, "deepseek-chat");
        assert_eq!(stored.credential.as_str(), "secret-deepseek-key");

        let resolver = DesktopNativeDeepSeekCredentialResolver::new(
            Arc::clone(&store),
            reference.clone(),
            "deepseek-chat".into(),
        );
        assert!(!format!("{resolver:?}").contains("secret-deepseek-key"));
        assert_eq!(
            resolver
                .resolve(DEEPSEEK_CREDENTIAL_ENV)
                .expect("resolve profile")
                .as_str(),
            "secret-deepseek-key"
        );

        put_native_deepseek_profile(
            store.as_ref(),
            &reference,
            "deepseek-reasoner",
            Zeroizing::new("rotated-deepseek-key".into()),
        )
        .expect("rotate profile");
        assert_eq!(store.entry_count().expect("entry count"), 1);
        assert_eq!(
            resolver.resolve(DEEPSEEK_CREDENTIAL_ENV),
            Err(DeepSeekAdapterError::InvalidConnection)
        );

        clear_native_deepseek_profile(store.as_ref(), &reference).expect("clear profile");
        clear_native_deepseek_profile(store.as_ref(), &reference).expect("idempotent clear");
        assert_eq!(store.entry_count().expect("entry count"), 0);
    }

    #[test]
    fn malformed_native_profile_is_rejected_without_secret_disclosure() {
        let store = MemorySecretStore::default();
        let reference = SecretReference {
            tenant_id: TenantId::from("local-desktop-installation"),
            project_id: ProjectId::from("desktop-runtime"),
            provider: DEEPSEEK_PROVIDER_ID.into(),
            account_scope: "data-root:profile-b".into(),
            purpose: "native_llm_profile".into(),
            version: 1,
        };
        assert!(matches!(
            put_native_deepseek_profile(
                &store,
                &reference,
                " deepseek-chat",
                Zeroizing::new("secret-deepseek-key".into()),
            ),
            Err(SecretStoreError::InvalidSecret)
        ));
        assert!(matches!(
            put_native_deepseek_profile(
                &store,
                &reference,
                "deepseek-chat",
                Zeroizing::new(" secret-deepseek-key".into()),
            ),
            Err(SecretStoreError::InvalidSecret)
        ));
        assert_eq!(store.entry_count().expect("entry count"), 0);

        let malformed = SecretBytes::new(b"not-a-native-profile".to_vec()).expect("secret bytes");
        store
            .put(&reference, &malformed)
            .expect("inject malformed profile");
        assert!(matches!(
            load_native_deepseek_profile(&store, &reference),
            Err(SecretStoreError::InvalidSecret)
        ));
        assert!(!format!("{malformed:?}").contains("not-a-native-profile"));
    }

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
