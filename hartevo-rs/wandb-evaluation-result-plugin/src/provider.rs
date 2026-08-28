//! Recording-only W&B provider boundary.

use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    PluginVersion, canonical_digest,
    model::{
        Digest, EvidenceSource, NativeStatus, ProviderState, SecretReference, WandbEvaluationError,
        WandbEvaluationPage, WandbEvaluationReadRequest, WandbEvaluationScope, WandbPermission,
        WandbPermissionSnapshot, WandbPluginRegistration,
    },
};

pub use crate::model::{CredentialResolutionError, WandbProviderError};

/// The W&B Public API references pinned by the contract.  This is a
/// description-only manifest; it is not an HTTP client.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbApiManifest {
    pub api_version: String,
    pub public_api_guide: String,
    pub python_public_api: String,
    pub operations: Vec<String>,
    pub api_digest: Digest,
}

impl WandbApiManifest {
    #[must_use]
    pub fn fixture(host: &crate::WandbHost) -> Self {
        let operations = vec![
            String::from("read_one_run"),
            String::from("read_allowlisted_summary_metrics"),
            String::from("read_sampled_history"),
            String::from("read_run_state_and_timestamps"),
            String::from("read_artifact_metadata"),
        ];
        let api_version = String::from(crate::WANDB_EVALUATION_RESULT_API_VERSION);
        let public_api_guide = String::from("https://docs.wandb.ai/models/track/public-api-guide");
        let python_public_api = String::from("https://docs.wandb.ai/models/ref/python/public-api");
        let api_digest = Digest::from_text(&format!(
            "{}|{}|GET /api/v1/runs/{{entity}}/{{project}}/{{run}}|summary_metrics|sampled_history|run_state|artifact_metadata",
            crate::WANDB_EVALUATION_RESULT_API_VERSION,
            host.as_str()
        ));
        Self {
            api_version,
            public_api_guide,
            python_public_api,
            operations,
            api_digest,
        }
    }

    pub fn validate(&self, scope: &WandbEvaluationScope) -> Result<(), WandbEvaluationError> {
        let expected = Self::fixture(&scope.host);
        if self != &expected || self.api_digest != scope.api_digest {
            return Err(WandbEvaluationError::ApiDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbProviderManifest {
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub api_version: String,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub metric_digest: Digest,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub metric_writes: bool,
    pub artifact_upload: bool,
    pub artifact_download: bool,
    pub sweep_launch: bool,
    pub raw_history: bool,
    pub raw_dataset: bool,
    pub raw_media: bool,
    pub generic_telemetry: bool,
    pub provider_digest: Digest,
    pub manifest_digest: Digest,
}

impl WandbProviderManifest {
    fn new(
        scope: &WandbEvaluationScope,
        permission: &WandbPermissionSnapshot,
        api: &WandbApiManifest,
        source: EvidenceSource,
    ) -> Result<Self, WandbEvaluationError> {
        scope.validate()?;
        permission.validate()?;
        api.validate(scope)?;
        if permission.digest != scope.permission_digest {
            return Err(WandbEvaluationError::PermissionDrift);
        }
        let mut manifest = Self {
            provider_id: String::from(crate::WANDB_EVALUATION_RESULT_PROVIDER_ID),
            provider_version: PluginVersion::V1,
            api_version: api.api_version.clone(),
            api_digest: api.api_digest.clone(),
            permission_digest: permission.digest.clone(),
            scope_digest: scope.digest().clone(),
            revision_digest: scope.revision_digest.clone(),
            metric_digest: scope.metric_digest.clone(),
            evidence_source: source,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            external_writes: false,
            metric_writes: false,
            artifact_upload: false,
            artifact_download: false,
            sweep_launch: false,
            raw_history: false,
            raw_dataset: false,
            raw_media: false,
            generic_telemetry: false,
            provider_digest: Digest::from_text("uninitialized-wandb-provider"),
            manifest_digest: Digest::from_text("uninitialized-wandb-manifest"),
        };
        manifest.provider_digest = canonical_digest(&ProviderIdentity {
            provider_id: manifest.provider_id.clone(),
            provider_version: manifest.provider_version,
            api_version: manifest.api_version.clone(),
            api_digest: manifest.api_digest.clone(),
            permission_digest: manifest.permission_digest.clone(),
            scope_digest: manifest.scope_digest.clone(),
            revision_digest: manifest.revision_digest.clone(),
            metric_digest: manifest.metric_digest.clone(),
            evidence_source: manifest.evidence_source,
            native_status: manifest.native_status,
            connected: manifest.connected,
            native: manifest.native,
            external_writes: manifest.external_writes,
            metric_writes: manifest.metric_writes,
            artifact_upload: manifest.artifact_upload,
            artifact_download: manifest.artifact_download,
            sweep_launch: manifest.sweep_launch,
            raw_history: manifest.raw_history,
            raw_dataset: manifest.raw_dataset,
            raw_media: manifest.raw_media,
            generic_telemetry: manifest.generic_telemetry,
        });
        manifest.manifest_digest = manifest.calculated_manifest_digest();
        Ok(manifest)
    }

    pub fn validate(
        &self,
        registration: &WandbPluginRegistration,
        scope: &WandbEvaluationScope,
        permission: &WandbPermissionSnapshot,
    ) -> Result<(), WandbEvaluationError> {
        let api = WandbApiManifest::fixture(&scope.host);
        let expected = Self::new(scope, permission, &api, self.evidence_source)?;
        if self != &expected
            || self.provider_digest != registration.provider_digest
            || self.api_digest != registration.api_digest
            || self.permission_digest != registration.permission_digest
            || self.scope_digest != registration.scope_digest
            || self.revision_digest != registration.revision_digest
            || self.metric_digest != registration.metric_digest
            || self.native_status != NativeStatus::BlockedEnv
            || self.connected
            || self.native
            || self.external_writes
            || self.metric_writes
            || self.artifact_upload
            || self.artifact_download
            || self.sweep_launch
            || self.raw_history
            || self.raw_dataset
            || self.raw_media
            || self.generic_telemetry
        {
            return Err(WandbEvaluationError::ProviderManifestDrift);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.manifest_digest
    }

    fn calculated_manifest_digest(&self) -> Digest {
        canonical_digest(&ManifestIdentity {
            provider_digest: self.provider_digest.clone(),
            evidence_source: self.evidence_source,
            native_status: self.native_status,
            connected: self.connected,
            native: self.native,
            manifest_flags: [
                self.external_writes,
                self.metric_writes,
                self.artifact_upload,
                self.artifact_download,
                self.sweep_launch,
                self.raw_history,
                self.raw_dataset,
                self.raw_media,
                self.generic_telemetry,
            ],
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProviderIdentity {
    provider_id: String,
    provider_version: PluginVersion,
    api_version: String,
    api_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
    metric_digest: Digest,
    evidence_source: EvidenceSource,
    native_status: NativeStatus,
    connected: bool,
    native: bool,
    external_writes: bool,
    metric_writes: bool,
    artifact_upload: bool,
    artifact_download: bool,
    sweep_launch: bool,
    raw_history: bool,
    raw_dataset: bool,
    raw_media: bool,
    generic_telemetry: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManifestIdentity {
    provider_digest: Digest,
    evidence_source: EvidenceSource,
    native_status: NativeStatus,
    connected: bool,
    native: bool,
    manifest_flags: [bool; 9],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum WandbProviderCall {
    ReadOneRun {
        host_digest: Digest,
        entity_digest: Digest,
        project_digest: Digest,
        run_digest: Digest,
        api_digest: Digest,
        permission_digest: Digest,
        metric_digest: Digest,
        revision_digest: Digest,
        page_size: u16,
        history_limit: usize,
        max_response_bytes: usize,
    },
}

/// A non-serializable material projection used only by a Layer-2 resolver.
/// It contains length and digest, never token bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretMaterial {
    byte_length: usize,
    digest: Digest,
}

impl SecretMaterial {
    #[must_use]
    pub const fn byte_length(&self) -> usize {
        self.byte_length
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field("byte_length", &self.byte_length)
            .field("digest", &self.digest)
            .finish()
    }
}

pub trait WandbCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, CredentialResolutionError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl WandbCredentialResolver for BlockedEnvCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, CredentialResolutionError> {
        Err(CredentialResolutionError::BlockedEnv)
    }
}

#[derive(Clone)]
pub struct StaticCredentialResolver {
    material: SecretMaterial,
}

impl StaticCredentialResolver {
    pub fn new(opaque_value: impl AsRef<str>) -> Result<Self, CredentialResolutionError> {
        let value = opaque_value.as_ref();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(CredentialResolutionError::InvalidReference);
        }
        Ok(Self {
            material: SecretMaterial {
                byte_length: value.len(),
                digest: Digest::from_text(value),
            },
        })
    }
}

impl fmt::Debug for StaticCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticCredentialResolver { material: <redacted> }")
    }
}

impl WandbCredentialResolver for StaticCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, CredentialResolutionError> {
        Ok(self.material.clone())
    }
}

#[derive(Clone, Debug)]
pub struct WandbAuthenticationPlan {
    pub required: bool,
    pub scheme: &'static str,
    pub secret_reference_digest: Digest,
    pub native_resolution: NativeStatus,
}

#[derive(Clone)]
pub struct WandbProvider {
    scope: WandbEvaluationScope,
    permission: WandbPermissionSnapshot,
    secret_reference_digest: Digest,
    api: WandbApiManifest,
    manifest: WandbProviderManifest,
    registration: Arc<Mutex<WandbPluginRegistration>>,
    source: EvidenceSource,
    state: Arc<Mutex<ProviderState>>,
    responses: Arc<Mutex<VecDeque<Result<WandbEvaluationPage, WandbProviderError>>>>,
    calls: Arc<Mutex<Vec<WandbProviderCall>>>,
}

impl fmt::Debug for WandbProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WandbProvider")
            .field("scope_digest", &self.scope.digest())
            .field("permission_digest", &self.permission.digest)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .field("api_digest", &self.api.api_digest)
            .field("provider_digest", &self.manifest.provider_digest)
            .field("source", &self.source)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl WandbProvider {
    pub fn new(
        scope: WandbEvaluationScope,
        secret_reference: SecretReference,
        source: EvidenceSource,
    ) -> Result<Self, WandbEvaluationError> {
        let permission = WandbPermissionSnapshot::read_only(scope.permission_revision.clone())?;
        Self::with_permission(scope, secret_reference, permission, source)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn with_permission(
        scope: WandbEvaluationScope,
        secret_reference: SecretReference,
        permission: WandbPermissionSnapshot,
        source: EvidenceSource,
    ) -> Result<Self, WandbEvaluationError> {
        scope.validate()?;
        permission.validate()?;
        secret_reference.validate()?;
        if secret_reference.scope_digest() != scope.digest()
            || secret_reference.revision() != &scope.permission_revision
        {
            return Err(WandbEvaluationError::ScopeMismatch);
        }
        let api = WandbApiManifest::fixture(&scope.host);
        let manifest = WandbProviderManifest::new(&scope, &permission, &api, source)?;
        let registration = WandbPluginRegistration::new(
            &scope,
            &permission,
            manifest.provider_digest.clone(),
            manifest.api_digest.clone(),
        )?;
        let state = if source.is_blocked_env() {
            ProviderState::BlockedEnv
        } else {
            ProviderState::Ready
        };
        Ok(Self {
            scope,
            permission,
            secret_reference_digest: secret_reference.reference_digest().clone(),
            api,
            manifest,
            registration: Arc::new(Mutex::new(registration)),
            source,
            state: Arc::new(Mutex::new(state)),
            responses: Arc::new(Mutex::new(VecDeque::new())),
            calls: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn fixture(scope: WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        let secret = SecretReference::api_token(
            "fixture-wandb-api-token-handle",
            scope.digest().clone(),
            scope.permission_revision.clone(),
        )?;
        let provider = Self::new(scope, secret, EvidenceSource::Fixture)?;
        provider.set_page(WandbEvaluationPage::fixture(&provider.scope())?);
        Ok(provider)
    }

    pub fn recording(scope: WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        let secret = SecretReference::api_token(
            "recording-wandb-api-token-handle",
            scope.digest().clone(),
            scope.permission_revision.clone(),
        )?;
        let provider = Self::new(scope, secret, EvidenceSource::Recording)?;
        provider.set_page(WandbEvaluationPage::fixture(&provider.scope())?);
        Ok(provider)
    }

    pub fn loopback(scope: WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        let secret = SecretReference::api_token(
            "loopback-wandb-api-token-handle",
            scope.digest().clone(),
            scope.permission_revision.clone(),
        )?;
        let provider = Self::new(scope, secret, EvidenceSource::Loopback)?;
        provider.set_page(WandbEvaluationPage::fixture(&provider.scope())?);
        Ok(provider)
    }

    pub fn fake(scope: WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        Self::recording(scope)
    }

    pub fn blocked_env(scope: WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        let secret = SecretReference::api_token(
            "blocked-env-wandb-api-token-handle",
            scope.digest().clone(),
            scope.permission_revision.clone(),
        )?;
        Self::new(scope, secret, EvidenceSource::BlockedEnv)
    }

    #[must_use]
    pub fn scope(&self) -> WandbEvaluationScope {
        self.scope.clone()
    }

    #[must_use]
    pub fn permission(&self) -> WandbPermissionSnapshot {
        self.permission.clone()
    }

    #[must_use]
    pub fn registration(&self) -> WandbPluginRegistration {
        self.registration
            .lock()
            .expect("W&B registration mutex is not poisoned")
            .clone()
    }

    #[must_use]
    pub fn provider_manifest(&self) -> WandbProviderManifest {
        self.manifest.clone()
    }

    #[must_use]
    pub fn api_manifest(&self) -> WandbApiManifest {
        self.api.clone()
    }

    #[must_use]
    pub fn provenance(&self) -> EvidenceSource {
        self.source
    }

    #[must_use]
    pub fn state(&self) -> ProviderState {
        *self
            .state
            .lock()
            .expect("W&B provider state mutex is not poisoned")
    }

    #[must_use]
    pub fn native_transport(&self) -> bool {
        false
    }

    #[must_use]
    pub fn native_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub fn external_write_available(&self) -> bool {
        false
    }

    #[must_use]
    pub fn calls(&self) -> Vec<WandbProviderCall> {
        self.calls
            .lock()
            .expect("W&B provider calls mutex is not poisoned")
            .clone()
    }

    pub fn authentication_plan(&self) -> WandbAuthenticationPlan {
        WandbAuthenticationPlan {
            required: true,
            scheme: "api_token_via_secret_reference",
            secret_reference_digest: self.secret_reference_digest.clone(),
            native_resolution: NativeStatus::BlockedEnv,
        }
    }

    pub fn describe_capabilities(&self) -> Result<WandbProviderManifest, WandbEvaluationError> {
        let registration = self.registration();
        self.manifest
            .validate(&registration, &self.scope, &self.permission)?;
        Ok(self.manifest.clone())
    }

    pub fn read_run(
        &self,
        request: &WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationPage, WandbProviderError> {
        let registration = self.registration();
        if !registration.active {
            return Err(WandbProviderError::RegistrationRevoked);
        }
        if request.scope.digest() != self.scope.digest() {
            return Err(WandbProviderError::ScopeMismatch);
        }
        if request.scope.permission_revision != self.permission.revision {
            return Err(WandbProviderError::PermissionDrift);
        }
        if !self.permission.allows(WandbPermission::ReadRun)
            || !self.permission.allows(WandbPermission::ReadSummaryMetrics)
            || !self.permission.allows(WandbPermission::ReadHistorySamples)
            || !self
                .permission
                .allows(WandbPermission::ReadArtifactMetadata)
        {
            return Err(WandbProviderError::PermissionDrift);
        }
        match self.state() {
            ProviderState::BlockedEnv => return Err(WandbProviderError::BlockedEnv),
            ProviderState::AccessLost => return Err(WandbProviderError::AccessLoss),
            ProviderState::Revoked => return Err(WandbProviderError::RegistrationRevoked),
            ProviderState::Ready => {}
        }
        self.calls
            .lock()
            .expect("W&B provider calls mutex is not poisoned")
            .push(WandbProviderCall::ReadOneRun {
                host_digest: Digest::from_text(self.scope.host.as_str()),
                entity_digest: Digest::from_text(self.scope.entity.as_str()),
                project_digest: self.scope.project.digest.clone(),
                run_digest: self.scope.run.digest.clone(),
                api_digest: self.scope.api_digest.clone(),
                permission_digest: self.scope.permission_digest.clone(),
                metric_digest: self.scope.metric_digest.clone(),
                revision_digest: self.scope.revision_digest.clone(),
                page_size: request.page_size,
                history_limit: request.history_limit,
                max_response_bytes: request.max_response_bytes,
            });
        if request.cursor.is_some() {
            return Err(WandbProviderError::CursorLoop);
        }
        let response = self
            .responses
            .lock()
            .expect("W&B responses mutex is not poisoned")
            .pop_front();
        let page = response.unwrap_or_else(|| {
            WandbEvaluationPage::fixture(&self.scope)
                .map_err(|_| WandbProviderError::InvalidResponse)
        })?;
        if page.run.sampled_history.len() > request.history_limit
            || page.response_bytes > request.max_response_bytes
        {
            return Err(WandbProviderError::InvalidResponse);
        }
        Ok(page)
    }

    pub fn read_evaluation(
        &self,
        request: &WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationPage, WandbProviderError> {
        self.read_run(request)
    }

    pub fn read_one_run(
        &self,
        request: &WandbEvaluationReadRequest,
    ) -> Result<WandbEvaluationPage, WandbProviderError> {
        self.read_run(request)
    }

    pub fn set_response(&self, response: Result<WandbEvaluationPage, WandbProviderError>) {
        let mut responses = self
            .responses
            .lock()
            .expect("W&B responses mutex is not poisoned");
        responses.clear();
        responses.push_back(response);
    }

    pub fn set_responses<I>(&self, responses: I)
    where
        I: IntoIterator<Item = Result<WandbEvaluationPage, WandbProviderError>>,
    {
        let mut queue = self
            .responses
            .lock()
            .expect("W&B responses mutex is not poisoned");
        queue.clear();
        queue.extend(responses);
    }

    pub fn set_page(&self, page: WandbEvaluationPage) {
        self.set_response(Ok(page));
    }

    pub fn set_error(&self, error: WandbProviderError) {
        self.set_response(Err(error));
    }

    pub fn revoke(
        &self,
        reason: impl AsRef<str>,
    ) -> Result<crate::RegistrationRevocation, WandbEvaluationError> {
        let mut registration = self
            .registration
            .lock()
            .expect("W&B registration mutex is not poisoned");
        let revocation = registration.revoke(reason, &self.scope, &self.permission)?;
        *self
            .state
            .lock()
            .expect("W&B provider state mutex is not poisoned") = ProviderState::Revoked;
        Ok(revocation)
    }

    pub fn restore(&self) -> Result<(), WandbEvaluationError> {
        let mut registration = self
            .registration
            .lock()
            .expect("W&B registration mutex is not poisoned");
        registration.restore(&self.scope, &self.permission)?;
        let state = if self.source.is_blocked_env() {
            ProviderState::BlockedEnv
        } else {
            ProviderState::Ready
        };
        *self
            .state
            .lock()
            .expect("W&B provider state mutex is not poisoned") = state;
        Ok(())
    }

    pub fn credential_probe(&self) -> Result<SecretMaterial, WandbProviderError> {
        Err(WandbProviderError::Credential(
            CredentialResolutionError::BlockedEnv,
        ))
    }

    pub fn mark_access_lost(&self) {
        *self
            .state
            .lock()
            .expect("W&B provider state mutex is not poisoned") = ProviderState::AccessLost;
    }
}
