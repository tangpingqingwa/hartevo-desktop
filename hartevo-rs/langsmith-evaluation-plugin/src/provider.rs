use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    Digest, PluginVersion, canonical_digest,
    model::{
        LangSmithEvaluationError, LangSmithEvaluationPage, LangSmithEvaluationReadRequest,
        LangSmithPermission, LangSmithPluginRegistration, SecretKind, SecretReference,
    },
};

pub use crate::model::{CredentialResolutionError, LangSmithProviderError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeStatus {
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl EvidenceSource {
    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithProviderManifest {
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub evidence_source: EvidenceSource,
    pub native_status: NativeStatus,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
    pub raw_response_bodies: bool,
    pub raw_secrets: bool,
    pub arbitrary_trace_export: bool,
    pub tool_execution: bool,
    pub manifest_digest: Digest,
}

impl LangSmithProviderManifest {
    fn new(
        registration: &LangSmithPluginRegistration,
        evidence_source: EvidenceSource,
    ) -> Result<Self, LangSmithEvaluationError> {
        let mut manifest = Self {
            provider_id: registration.provider_id.clone(),
            provider_version: registration.provider_version,
            evidence_source,
            native_status: NativeStatus::BlockedEnv,
            connected: false,
            native: false,
            external_writes: false,
            raw_response_bodies: false,
            raw_secrets: false,
            arbitrary_trace_export: false,
            tool_execution: false,
            manifest_digest: Digest::from_text("uninitialized-langsmith-provider-manifest"),
        };
        manifest.manifest_digest = manifest.calculated_digest();
        manifest.validate(registration)?;
        Ok(manifest)
    }

    pub fn validate(
        &self,
        registration: &LangSmithPluginRegistration,
    ) -> Result<(), LangSmithEvaluationError> {
        if self.provider_id != registration.provider_id
            || self.provider_version != registration.provider_version
            || self.native_status != NativeStatus::BlockedEnv
            || self.connected
            || self.native
            || self.external_writes
            || self.raw_response_bodies
            || self.raw_secrets
            || self.arbitrary_trace_export
            || self.tool_execution
            || self.manifest_digest != self.calculated_digest()
        {
            return Err(LangSmithEvaluationError::ProviderManifestDrift);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.manifest_digest
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&ManifestIdentity {
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version,
            evidence_source: self.evidence_source,
            native_status: self.native_status,
            connected: self.connected,
            native: self.native,
            external_writes: self.external_writes,
            raw_response_bodies: self.raw_response_bodies,
            raw_secrets: self.raw_secrets,
            arbitrary_trace_export: self.arbitrary_trace_export,
            tool_execution: self.tool_execution,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManifestIdentity {
    provider_id: String,
    provider_version: PluginVersion,
    evidence_source: EvidenceSource,
    native_status: NativeStatus,
    connected: bool,
    native: bool,
    external_writes: bool,
    raw_response_bodies: bool,
    raw_secrets: bool,
    arbitrary_trace_export: bool,
    tool_execution: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderState {
    Ready,
    BlockedEnv,
    Revoked,
    AccessLoss,
    PermissionDrift,
    VersionDrift,
    Stale,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum LangSmithProviderCall {
    DescribeCapabilities {
        scope_digest: Digest,
    },
    ReadEvaluation {
        scope_digest: Digest,
        page: u16,
        cursor_digest: Option<Digest>,
    },
    Revoke {
        registration_digest: Digest,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretMaterial {
    byte_length: usize,
    digest: Digest,
}

impl SecretMaterial {
    fn from_opaque_value(value: &str) -> Result<Self, CredentialResolutionError> {
        if value.is_empty() {
            return Err(CredentialResolutionError::InvalidReference);
        }
        Ok(Self {
            byte_length: value.len(),
            digest: Digest::from_text(value),
        })
    }

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

pub trait LangSmithCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(
        &self,
        reference: &SecretReference,
    ) -> Result<SecretMaterial, CredentialResolutionError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvCredentialResolver;

impl LangSmithCredentialResolver for BlockedEnvCredentialResolver {
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
    pub fn new(opaque_value: &str) -> Result<Self, CredentialResolutionError> {
        Ok(Self {
            material: SecretMaterial::from_opaque_value(opaque_value)?,
        })
    }
}

impl fmt::Debug for StaticCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StaticCredentialResolver")
            .field("material", &self.material)
            .finish()
    }
}

impl LangSmithCredentialResolver for StaticCredentialResolver {
    fn resolve(
        &self,
        _reference: &SecretReference,
    ) -> Result<SecretMaterial, CredentialResolutionError> {
        Ok(self.material.clone())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithAuthenticationPlan {
    pub required: bool,
    pub kind: Option<SecretKind>,
    pub secret_reference_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub native_resolution: bool,
    pub connected: bool,
}

#[derive(Debug)]
struct ProviderInner {
    registration: LangSmithPluginRegistration,
    manifest: LangSmithProviderManifest,
    source: EvidenceSource,
    state: ProviderState,
    secret_reference: Option<SecretReference>,
    resolver: Arc<dyn LangSmithCredentialResolver>,
    responses: VecDeque<Result<LangSmithEvaluationPage, LangSmithProviderError>>,
    calls: Vec<LangSmithProviderCall>,
}

/// The bounded provider seam. Its transport is a recording/fake/loopback or
/// BLOCKED_ENV queue; it has no native HTTP implementation.
#[derive(Clone)]
pub struct LangSmithProvider {
    inner: Arc<Mutex<ProviderInner>>,
}

impl fmt::Debug for LangSmithProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock().map_err(|_| fmt::Error)?;
        formatter
            .debug_struct("LangSmithProvider")
            .field(
                "registration_digest",
                &inner.registration.registration_digest,
            )
            .field("manifest_digest", &inner.manifest.manifest_digest)
            .field("source", &inner.source)
            .field("state", &inner.state)
            .field("queued_responses", &inner.responses.len())
            .field("calls_count", &inner.calls.len())
            .finish()
    }
}

impl LangSmithProvider {
    pub fn new(
        registration: LangSmithPluginRegistration,
    ) -> Result<Self, LangSmithEvaluationError> {
        Self::with_source(registration, EvidenceSource::Recording)
    }

    pub fn with_source(
        registration: LangSmithPluginRegistration,
        source: EvidenceSource,
    ) -> Result<Self, LangSmithEvaluationError> {
        Self::with_source_and_resolver(
            registration,
            source,
            Arc::new(BlockedEnvCredentialResolver),
            None,
        )
    }

    pub fn with_secret(
        registration: LangSmithPluginRegistration,
        source: EvidenceSource,
        secret_reference: SecretReference,
    ) -> Result<Self, LangSmithEvaluationError> {
        if secret_reference.scope_digest != *registration.scope.digest() {
            return Err(LangSmithEvaluationError::ScopeMismatch);
        }
        Self::with_source_and_resolver(
            registration,
            source,
            Arc::new(BlockedEnvCredentialResolver),
            Some(secret_reference),
        )
    }

    pub fn with_resolver(
        registration: LangSmithPluginRegistration,
        source: EvidenceSource,
        secret_reference: SecretReference,
        resolver: Arc<dyn LangSmithCredentialResolver>,
    ) -> Result<Self, LangSmithEvaluationError> {
        if secret_reference.scope_digest != *registration.scope.digest() {
            return Err(LangSmithEvaluationError::ScopeMismatch);
        }
        Self::with_source_and_resolver(registration, source, resolver, Some(secret_reference))
    }

    fn with_source_and_resolver(
        registration: LangSmithPluginRegistration,
        source: EvidenceSource,
        resolver: Arc<dyn LangSmithCredentialResolver>,
        secret_reference: Option<SecretReference>,
    ) -> Result<Self, LangSmithEvaluationError> {
        registration.validate()?;
        if let Some(reference) = &secret_reference {
            reference.validate()?;
        }
        let manifest = LangSmithProviderManifest::new(&registration, source)?;
        let fixture = LangSmithEvaluationPage::fixture(&registration.scope)?;
        let state = if source.is_blocked_env() {
            ProviderState::BlockedEnv
        } else {
            ProviderState::Ready
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(ProviderInner {
                registration,
                manifest,
                source,
                state,
                secret_reference,
                resolver,
                responses: VecDeque::from([Ok(fixture)]),
                calls: Vec::new(),
            })),
        })
    }

    pub fn fixture(
        scope: crate::LangSmithEvaluationScope,
    ) -> Result<Self, LangSmithEvaluationError> {
        let registration = LangSmithPluginRegistration::fixture(scope)?;
        Self::with_source(registration, EvidenceSource::Fixture)
    }

    pub fn recording(
        scope: crate::LangSmithEvaluationScope,
    ) -> Result<Self, LangSmithEvaluationError> {
        let registration = LangSmithPluginRegistration::fixture(scope)?;
        Self::with_source(registration, EvidenceSource::Recording)
    }

    pub fn fake(scope: crate::LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        let registration = LangSmithPluginRegistration::fixture(scope)?;
        Self::with_source(registration, EvidenceSource::Fake)
    }

    pub fn loopback(
        scope: crate::LangSmithEvaluationScope,
    ) -> Result<Self, LangSmithEvaluationError> {
        let registration = LangSmithPluginRegistration::fixture(scope)?;
        Self::with_source(registration, EvidenceSource::Loopback)
    }

    pub fn blocked_env(
        scope: crate::LangSmithEvaluationScope,
    ) -> Result<Self, LangSmithEvaluationError> {
        let registration = LangSmithPluginRegistration::fixture(scope)?;
        Self::with_source(registration, EvidenceSource::BlockedEnv)
    }

    #[must_use]
    pub fn registration(&self) -> LangSmithPluginRegistration {
        self.inner
            .lock()
            .expect("LangSmith provider mutex is not poisoned")
            .registration
            .clone()
    }

    #[must_use]
    pub fn provider_manifest(&self) -> LangSmithProviderManifest {
        self.inner
            .lock()
            .expect("LangSmith provider mutex is not poisoned")
            .manifest
            .clone()
    }

    #[must_use]
    pub fn provenance(&self) -> EvidenceSource {
        self.inner
            .lock()
            .expect("LangSmith provider mutex is not poisoned")
            .source
    }

    #[must_use]
    pub fn state(&self) -> ProviderState {
        self.inner
            .lock()
            .expect("LangSmith provider mutex is not poisoned")
            .state
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
    pub fn calls(&self) -> Vec<LangSmithProviderCall> {
        self.inner
            .lock()
            .expect("LangSmith provider mutex is not poisoned")
            .calls
            .clone()
    }

    pub fn authentication_plan(
        &self,
    ) -> Result<LangSmithAuthenticationPlan, LangSmithEvaluationError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| LangSmithEvaluationError::InvalidResponse)?;
        Ok(LangSmithAuthenticationPlan {
            required: inner.secret_reference.is_some(),
            kind: inner
                .secret_reference
                .as_ref()
                .map(|reference| reference.kind),
            secret_reference_digest: inner
                .secret_reference
                .as_ref()
                .map(|reference| reference.reference_digest.clone()),
            scope_digest: inner.registration.scope.digest().clone(),
            native_resolution: false,
            connected: false,
        })
    }

    pub fn describe_capabilities(
        &self,
    ) -> Result<LangSmithProviderManifest, LangSmithEvaluationError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| LangSmithEvaluationError::InvalidResponse)?;
        inner.registration.ensure_active()?;
        inner.manifest.validate(&inner.registration)?;
        let scope_digest = inner.registration.scope.digest().clone();
        inner
            .calls
            .push(LangSmithProviderCall::DescribeCapabilities { scope_digest });
        Ok(inner.manifest.clone())
    }

    pub fn read_evaluation(
        &self,
        request: &LangSmithEvaluationReadRequest,
    ) -> Result<LangSmithEvaluationPage, LangSmithProviderError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| LangSmithProviderError::InvalidResponse)?;
        if let Err(error) = inner.registration.ensure_active() {
            inner.state = ProviderState::Revoked;
            return Err(map_registration_error(error));
        }
        if request.scope.digest() != inner.registration.scope.digest() {
            inner.state = ProviderState::VersionDrift;
            return Err(LangSmithProviderError::ScopeMismatch);
        }
        if request.scope.permission_revision != inner.registration.permission.revision {
            inner.state = ProviderState::PermissionDrift;
            return Err(LangSmithProviderError::PermissionDrift);
        }
        if inner.source.is_blocked_env() {
            inner.state = ProviderState::BlockedEnv;
            return Err(LangSmithProviderError::BlockedEnv);
        }
        let required = [
            LangSmithPermission::ReadRuns,
            LangSmithPermission::ReadTraces,
            LangSmithPermission::ReadDatasets,
            LangSmithPermission::ReadEvaluators,
            LangSmithPermission::ReadFeedback,
            LangSmithPermission::ReadExperiments,
        ];
        if required
            .into_iter()
            .any(|permission| !inner.registration.permission.allows(permission))
        {
            inner.state = ProviderState::PermissionDrift;
            return Err(LangSmithProviderError::PermissionDrift);
        }
        let expected_page = request.cursor.as_ref().map_or(1, |cursor| cursor.page);
        let cursor_digest = request
            .cursor
            .as_ref()
            .map(|cursor| cursor.cursor_digest.clone());
        inner.calls.push(LangSmithProviderCall::ReadEvaluation {
            scope_digest: request.scope.digest().clone(),
            page: expected_page,
            cursor_digest,
        });
        let response = inner.responses.pop_front().ok_or_else(|| {
            inner.state = ProviderState::Failed;
            LangSmithProviderError::InvalidResponse
        })?;
        let response = response?;
        if response.scope_digest != *request.scope.digest() || response.page != expected_page {
            inner.state = ProviderState::VersionDrift;
            return Err(LangSmithProviderError::ScopeMismatch);
        }
        inner.state = ProviderState::Ready;
        Ok(response)
    }

    pub fn set_response(&self, response: Result<LangSmithEvaluationPage, LangSmithProviderError>) {
        let mut inner = self
            .inner
            .lock()
            .expect("LangSmith provider mutex is not poisoned");
        inner.responses.clear();
        inner.responses.push_back(response);
    }

    pub fn set_responses<I>(&self, responses: I)
    where
        I: IntoIterator<Item = Result<LangSmithEvaluationPage, LangSmithProviderError>>,
    {
        let mut inner = self
            .inner
            .lock()
            .expect("LangSmith provider mutex is not poisoned");
        inner.responses = responses.into_iter().collect();
    }

    pub fn set_page(&self, page: LangSmithEvaluationPage) {
        self.set_response(Ok(page));
    }

    pub fn set_error(&self, error: LangSmithProviderError) {
        self.set_response(Err(error));
    }

    pub fn revoke(
        &self,
        reason: &str,
    ) -> Result<crate::RegistrationRevocation, LangSmithEvaluationError> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| LangSmithEvaluationError::InvalidResponse)?;
        let revocation = inner.registration.revoke(reason)?;
        inner.state = ProviderState::Revoked;
        inner.calls.push(LangSmithProviderCall::Revoke {
            registration_digest: revocation.registration_digest.clone(),
        });
        Ok(revocation)
    }

    pub fn credential_probe(&self) -> Result<SecretMaterial, LangSmithProviderError> {
        let inner = self
            .inner
            .lock()
            .map_err(|_| LangSmithProviderError::InvalidResponse)?;
        let reference = inner
            .secret_reference
            .as_ref()
            .ok_or(LangSmithProviderError::BlockedEnv)?;
        inner.resolver.resolve(reference).map_err(Into::into)
    }
}

fn map_registration_error(error: LangSmithEvaluationError) -> LangSmithProviderError {
    match error {
        LangSmithEvaluationError::RegistrationRevoked => {
            LangSmithProviderError::RegistrationRevoked
        }
        LangSmithEvaluationError::Provider(provider_error) => provider_error,
        _ => LangSmithProviderError::InvalidResponse,
    }
}
