//! Local replay/fixture provider and digest-bound registration.
//!
//! No implementation in this module resolves credentials or performs HTTP.
//! The operation-location and status methods are typed seams over a bounded
//! recorded frame so a later Layer-2 provider can be introduced without
//! changing the Layer-1 contract.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION, AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION,
    AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_ID, AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION,
    AzureDocumentIntelligenceError, MAX_DOCUMENT_INTELLIGENCE_RESPONSE_BYTES, contract_digest,
    digest_serializable,
    model::{
        AnalyzeResultProjection, AzureDocumentIntelligenceScope, Digest, DocumentAnalysisRequest,
        DocumentIntelligencePermission, OperationLocation, OperationStatus, OperationStatusFrame,
        ProviderMode, ProviderRevision, SecretReference,
    },
    plugin_version_digest,
};

/// Local registration lifecycle.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

/// Reason attached to a reversible local revocation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserRequested,
    ScopeChanged,
    PermissionChanged,
    SourceDigestChanged,
    CredentialRotated,
    Test,
}

/// A local lifecycle event, not a provider or kernel receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Revocation {
    pub registration_digest: Digest,
    pub reason: RevocationReason,
    pub state: RegistrationState,
}

/// Inputs to one exact registration. The secret handle is deliberately not
/// serializable and is only used to derive a digest-bound opaque identity.
#[derive(Clone, Debug)]
pub struct AzureDocumentIntelligenceRegistrationRequest {
    pub scope: AzureDocumentIntelligenceScope,
    pub secret_reference: SecretReference,
    pub provider_revision: ProviderRevision,
}

impl AzureDocumentIntelligenceRegistrationRequest {
    pub fn baseline(
        scope: AzureDocumentIntelligenceScope,
        secret_reference: SecretReference,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        let provider_revision =
            ProviderRevision::parse(AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION)?;
        if !secret_reference.matches_tenant(scope.tenant_id()) {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "secret reference tenant does not match the registered tenant".to_owned(),
            ));
        }
        Ok(Self {
            scope,
            secret_reference,
            provider_revision,
        })
    }

    pub fn with_provider_revision(
        mut self,
        provider_revision: impl Into<String>,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        self.provider_revision = ProviderRevision::parse(provider_revision)?;
        Ok(self)
    }
}

/// Reversible, digest-bound registration for the exact provider and document
/// scope. This type is intentionally not serializable because it contains an
/// opaque `SecretReference`.
#[derive(Clone, Debug)]
pub struct AzureDocumentIntelligenceRegistration {
    scope: AzureDocumentIntelligenceScope,
    secret_reference: SecretReference,
    provider_revision: ProviderRevision,
    plugin_version_digest: Digest,
    contract_digest: Digest,
    provider_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    source_digest: Digest,
    secret_reference_digest: Digest,
    registration_digest: Digest,
    state: RegistrationState,
}

impl AzureDocumentIntelligenceRegistration {
    pub fn new(
        request: AzureDocumentIntelligenceRegistrationRequest,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        request.scope.validate()?;
        if !request
            .secret_reference
            .matches_tenant(request.scope.tenant_id())
        {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "secret reference tenant does not match the registered tenant".to_owned(),
            ));
        }
        if request.provider_revision.as_str() != AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION {
            return Err(AzureDocumentIntelligenceError::ProviderRevisionMismatch);
        }
        let plugin_version_digest = plugin_version_digest();
        let contract_digest = contract_digest();
        let provider_digest = provider_digest(&request.provider_revision);
        let permission_digest = digest_serializable(&request.scope.permission().as_str());
        let scope_digest = request.scope.digest();
        let source_digest = request.scope.source_digest().clone();
        let secret_reference_digest = request.secret_reference.reference_digest();
        let registration_digest = registration_digest(
            &plugin_version_digest,
            &contract_digest,
            &provider_digest,
            &permission_digest,
            &scope_digest,
            &source_digest,
            &secret_reference_digest,
            &request.provider_revision,
        );
        Ok(Self {
            scope: request.scope,
            secret_reference: request.secret_reference,
            provider_revision: request.provider_revision,
            plugin_version_digest,
            contract_digest,
            provider_digest,
            permission_digest,
            scope_digest,
            source_digest,
            secret_reference_digest,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn plugin_version(&self) -> &'static str {
        AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION
    }

    pub fn plugin_version_digest(&self) -> &Digest {
        &self.plugin_version_digest
    }

    pub fn contract_version(&self) -> &'static str {
        AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &'static str {
        AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_ID
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn scope(&self) -> &AzureDocumentIntelligenceScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn source_digest(&self) -> &Digest {
        &self.source_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn validate_against(
        &self,
        scope: &AzureDocumentIntelligenceScope,
        provider_revision: &ProviderRevision,
    ) -> Result<(), AzureDocumentIntelligenceError> {
        if !self.is_active() {
            return Err(AzureDocumentIntelligenceError::RegistrationRevoked);
        }
        if self.plugin_version_digest != plugin_version_digest() {
            return Err(AzureDocumentIntelligenceError::RegistrationDrift(
                "plugin version digest".to_owned(),
            ));
        }
        if self.contract_digest != contract_digest() {
            return Err(AzureDocumentIntelligenceError::ContractDigestMismatch);
        }
        if self.provider_revision != *provider_revision {
            return Err(AzureDocumentIntelligenceError::ProviderRevisionMismatch);
        }
        if self.scope_digest != scope.digest() {
            return Err(AzureDocumentIntelligenceError::RegistrationDrift(
                "scope digest".to_owned(),
            ));
        }
        if self.source_digest != *scope.source_digest() {
            return Err(AzureDocumentIntelligenceError::SourceDigestMismatch);
        }
        if self.permission_digest != digest_serializable(&scope.permission().as_str()) {
            return Err(AzureDocumentIntelligenceError::PermissionMismatch);
        }
        let expected = registration_digest(
            &self.plugin_version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.source_digest,
            &self.secret_reference_digest,
            &self.provider_revision,
        );
        if self.registration_digest != expected {
            return Err(AzureDocumentIntelligenceError::RegistrationDrift(
                "registration digest".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, AzureDocumentIntelligenceError> {
        if !self.is_active() {
            return Err(AzureDocumentIntelligenceError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(Revocation {
            registration_digest: self.registration_digest.clone(),
            reason,
            state: self.state,
        })
    }

    pub fn restore(&mut self) -> Result<(), AzureDocumentIntelligenceError> {
        if self.registration_digest
            != registration_digest(
                &self.plugin_version_digest,
                &self.contract_digest,
                &self.provider_digest,
                &self.permission_digest,
                &self.scope_digest,
                &self.source_digest,
                &self.secret_reference_digest,
                &self.provider_revision,
            )
        {
            return Err(AzureDocumentIntelligenceError::RegistrationDrift(
                "registration digest".to_owned(),
            ));
        }
        self.state = RegistrationState::Active;
        Ok(())
    }
}

fn provider_digest(provider_revision: &ProviderRevision) -> Digest {
    digest_serializable(&(AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_ID, provider_revision))
}

#[allow(clippy::too_many_arguments)]
fn registration_digest(
    plugin_version_digest: &Digest,
    contract_digest: &Digest,
    provider_digest: &Digest,
    permission_digest: &Digest,
    scope_digest: &Digest,
    source_digest: &Digest,
    secret_reference_digest: &Digest,
    provider_revision: &ProviderRevision,
) -> Digest {
    digest_serializable(&(
        plugin_version_digest,
        contract_digest,
        provider_digest,
        permission_digest,
        scope_digest,
        source_digest,
        secret_reference_digest,
        provider_revision,
    ))
}

/// Parsed provider response with raw bytes discarded immediately.
#[derive(Clone, Debug)]
pub struct RecordedProviderResponse {
    request_digest: Digest,
    operation_location: Option<OperationLocation>,
    status: OperationStatus,
    provider_revision: ProviderRevision,
    response_digest: Digest,
    response_bytes: usize,
    failure_digest: Option<Digest>,
    result: Option<AnalyzeResultProjection>,
}

impl RecordedProviderResponse {
    /// Parse one bounded JSON recording. The input is borrowed and never
    /// retained; only safe projections and response metadata survive.
    pub fn from_json(
        request: &DocumentAnalysisRequest,
        operation_location: impl AsRef<str>,
        status_code: u16,
        provider_revision: impl Into<String>,
        body: &[u8],
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        Self::from_json_with_redaction(
            request,
            operation_location,
            status_code,
            provider_revision,
            body,
            request.redaction(),
        )
    }

    pub fn from_json_with_redaction(
        request: &DocumentAnalysisRequest,
        operation_location: impl AsRef<str>,
        status_code: u16,
        provider_revision: impl Into<String>,
        body: &[u8],
        redaction: crate::model::RedactionPolicy,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        if body.len() > MAX_DOCUMENT_INTELLIGENCE_RESPONSE_BYTES {
            return Err(AzureDocumentIntelligenceError::ResponseTooLarge(body.len()));
        }
        if !(200..=299).contains(&status_code) {
            return Err(AzureDocumentIntelligenceError::InvalidInput(
                "recorded status code must be a successful HTTP status".to_owned(),
            ));
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|error| AzureDocumentIntelligenceError::Decode(error.to_string()))?;
        let status = parse_status(&value, status_code)?;
        let provider_revision = ProviderRevision::parse(provider_revision.into())?;
        if provider_revision.as_str() != AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION {
            return Err(AzureDocumentIntelligenceError::ProviderRevisionMismatch);
        }
        let operation_location = Some(OperationLocation::from_url(operation_location)?);
        let result = if status.is_success() {
            let result_value = value.get("analyzeResult").ok_or_else(|| {
                AzureDocumentIntelligenceError::Decode(
                    "succeeded response has no analyzeResult".to_owned(),
                )
            })?;
            Some(AnalyzeResultProjection::from_azure_json(
                request.model(),
                request.source_digest(),
                request.page_range(),
                result_value,
                redaction,
            )?)
        } else {
            None
        };
        let failure_digest = value
            .get("error")
            .and_then(Value::as_object)
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str)
            .map(|code| Digest::from_text(code.as_bytes()));
        Ok(Self {
            request_digest: request.digest().clone(),
            operation_location,
            status,
            provider_revision,
            response_digest: Digest::from_bytes(body),
            response_bytes: body.len(),
            failure_digest,
            result,
        })
    }

    pub fn succeeded(
        request: &DocumentAnalysisRequest,
        operation_location: impl AsRef<str>,
        result: AnalyzeResultProjection,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        let operation_location = OperationLocation::from_url(operation_location)?;
        let response_digest = digest_serializable(&result);
        Ok(Self {
            request_digest: request.digest().clone(),
            operation_location: Some(operation_location),
            status: OperationStatus::Succeeded,
            provider_revision: ProviderRevision::parse(
                AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION,
            )?,
            response_digest,
            response_bytes: 0,
            failure_digest: None,
            result: Some(result),
        })
    }

    pub fn pending(
        request: &DocumentAnalysisRequest,
        operation_location: impl AsRef<str>,
        status: OperationStatus,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        if !matches!(
            status,
            OperationStatus::NotStarted | OperationStatus::Running
        ) {
            return Err(AzureDocumentIntelligenceError::InvalidInput(
                "pending response must be not_started or running".to_owned(),
            ));
        }
        Ok(Self {
            request_digest: request.digest().clone(),
            operation_location: Some(OperationLocation::from_url(operation_location)?),
            status,
            provider_revision: ProviderRevision::parse(
                AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION,
            )?,
            response_digest: digest_serializable(&(request.digest(), status)),
            response_bytes: 0,
            failure_digest: None,
            result: None,
        })
    }

    pub fn failed(
        request: &DocumentAnalysisRequest,
        operation_location: impl AsRef<str>,
        status: OperationStatus,
        failure_code: impl AsRef<str>,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        if !matches!(status, OperationStatus::Failed | OperationStatus::Canceled) {
            return Err(AzureDocumentIntelligenceError::InvalidInput(
                "failed response must be failed or canceled".to_owned(),
            ));
        }
        Ok(Self {
            request_digest: request.digest().clone(),
            operation_location: Some(OperationLocation::from_url(operation_location)?),
            status,
            provider_revision: ProviderRevision::parse(
                AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION,
            )?,
            response_digest: digest_serializable(&(
                request.digest(),
                status,
                failure_code.as_ref(),
            )),
            response_bytes: 0,
            failure_digest: Some(Digest::from_text(failure_code.as_ref())),
            result: None,
        })
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn operation_location(&self) -> Option<&OperationLocation> {
        self.operation_location.as_ref()
    }

    pub const fn status(&self) -> OperationStatus {
        self.status
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    pub fn result(&self) -> Option<&AnalyzeResultProjection> {
        self.result.as_ref()
    }

    pub(crate) fn into_frame(self, provenance: ProviderMode) -> OperationStatusFrame {
        OperationStatusFrame::new(
            self.operation_location,
            self.status,
            self.provider_revision,
            provenance,
            self.response_digest,
            self.response_bytes,
            self.failure_digest,
            self.result,
        )
    }
}

fn parse_status(
    value: &Value,
    status_code: u16,
) -> Result<OperationStatus, AzureDocumentIntelligenceError> {
    if let Some(status) = value.get("status").and_then(Value::as_str) {
        return match status {
            "notStarted" | "not_started" => Ok(OperationStatus::NotStarted),
            "running" => Ok(OperationStatus::Running),
            "succeeded" => Ok(OperationStatus::Succeeded),
            "failed" => Ok(OperationStatus::Failed),
            "canceled" | "cancelled" => Ok(OperationStatus::Canceled),
            "BLOCKED_ENV" => Ok(OperationStatus::BlockedEnv),
            _ => Err(AzureDocumentIntelligenceError::Decode(
                "status is not allowlisted".to_owned(),
            )),
        };
    }
    if value.get("analyzeResult").is_some() && status_code == 200 {
        Ok(OperationStatus::Succeeded)
    } else if status_code == 202 {
        Ok(OperationStatus::NotStarted)
    } else {
        Err(AzureDocumentIntelligenceError::Decode(
            "recorded response has no typed status".to_owned(),
        ))
    }
}

/// Local provider with no native transport.
#[derive(Clone)]
pub struct AzureDocumentIntelligenceProvider {
    scope: AzureDocumentIntelligenceScope,
    registration: AzureDocumentIntelligenceRegistration,
    mode: ProviderMode,
    responses: VecDeque<RecordedProviderResponse>,
    active_frame: Option<OperationStatusFrame>,
}

impl fmt::Debug for AzureDocumentIntelligenceProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureDocumentIntelligenceProvider")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("mode", &self.mode)
            .field("queued_response_count", &self.responses.len())
            .field("has_active_frame", &self.active_frame.is_some())
            .field("native_connected_claim", &false)
            .finish()
    }
}

impl AzureDocumentIntelligenceProvider {
    pub fn new(
        scope: AzureDocumentIntelligenceScope,
        secret_reference: SecretReference,
        mode: ProviderMode,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        let request = AzureDocumentIntelligenceRegistrationRequest::baseline(
            scope.clone(),
            secret_reference,
        )?;
        let registration = AzureDocumentIntelligenceRegistration::new(request)?;
        Ok(Self {
            scope,
            registration,
            mode,
            responses: VecDeque::new(),
            active_frame: None,
        })
    }

    pub fn recording(
        scope: AzureDocumentIntelligenceScope,
        secret_reference: SecretReference,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        Self::new(scope, secret_reference, ProviderMode::Recording)
    }

    pub fn fixture(
        scope: AzureDocumentIntelligenceScope,
        secret_reference: SecretReference,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        Self::new(scope, secret_reference, ProviderMode::Fixture)
    }

    pub fn loopback(
        scope: AzureDocumentIntelligenceScope,
        secret_reference: SecretReference,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        Self::new(scope, secret_reference, ProviderMode::Loopback)
    }

    pub fn blocked_env(
        scope: AzureDocumentIntelligenceScope,
        secret_reference: SecretReference,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        Self::new(scope, secret_reference, ProviderMode::BlockedEnv)
    }

    #[must_use]
    pub fn with_response(mut self, response: RecordedProviderResponse) -> Self {
        self.responses.push_back(response);
        self
    }

    pub fn push_response(&mut self, response: RecordedProviderResponse) {
        self.responses.push_back(response);
    }

    pub fn scope(&self) -> &AzureDocumentIntelligenceScope {
        &self.scope
    }

    pub fn registration(&self) -> &AzureDocumentIntelligenceRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AzureDocumentIntelligenceRegistration {
        &mut self.registration
    }

    pub const fn mode(&self) -> ProviderMode {
        self.mode
    }

    pub const fn provenance(&self) -> ProviderMode {
        self.mode
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn native_connected_claim(&self) -> bool {
        false
    }

    pub fn response_count(&self) -> usize {
        self.responses.len()
    }

    pub fn begin_analysis(
        &mut self,
        request: &DocumentAnalysisRequest,
    ) -> Result<OperationLocation, AzureDocumentIntelligenceError> {
        self.ensure_request(request)?;
        if self.mode == ProviderMode::BlockedEnv {
            return Err(AzureDocumentIntelligenceError::BlockedEnv);
        }
        let response = self
            .responses
            .pop_front()
            .ok_or(AzureDocumentIntelligenceError::NoRecordedResponse)?;
        if response.request_digest() != request.digest() {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "recorded response request digest differs".to_owned(),
            ));
        }
        let operation_location = response
            .operation_location()
            .cloned()
            .ok_or(AzureDocumentIntelligenceError::OperationMismatch)?;
        if response.provider_revision() != self.registration.provider_revision() {
            return Err(AzureDocumentIntelligenceError::ProviderRevisionMismatch);
        }
        self.active_frame = Some(response.into_frame(self.mode));
        Ok(operation_location)
    }

    pub fn poll_analysis(
        &self,
        operation_location: &OperationLocation,
    ) -> Result<OperationStatusFrame, AzureDocumentIntelligenceError> {
        self.ensure_active()?;
        let frame = self
            .active_frame
            .as_ref()
            .ok_or(AzureDocumentIntelligenceError::NoRecordedResponse)?;
        if frame.operation_location() != Some(operation_location) {
            return Err(AzureDocumentIntelligenceError::OperationMismatch);
        }
        Ok(frame.clone())
    }

    pub fn analyze(
        &mut self,
        request: &DocumentAnalysisRequest,
    ) -> Result<OperationStatusFrame, AzureDocumentIntelligenceError> {
        let operation_location = self.begin_analysis(request)?;
        self.poll_analysis(&operation_location)
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, AzureDocumentIntelligenceError> {
        self.registration.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), AzureDocumentIntelligenceError> {
        self.registration.restore()
    }

    fn ensure_active(&self) -> Result<(), AzureDocumentIntelligenceError> {
        self.registration
            .validate_against(&self.scope, self.registration.provider_revision())
    }

    fn ensure_request(
        &self,
        request: &DocumentAnalysisRequest,
    ) -> Result<(), AzureDocumentIntelligenceError> {
        self.ensure_active()?;
        if request.scope_digest() != &self.scope.digest() {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "request scope digest differs".to_owned(),
            ));
        }
        if request.model() != self.scope.model()
            || request.document_id() != self.scope.document_id()
            || request.source_digest() != self.scope.source_digest()
            || request.page_range() != self.scope.page_range()
        {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "request model, document, source digest, or page range differs".to_owned(),
            ));
        }
        if self.scope.permission() != DocumentIntelligencePermission::AnalyzeRead {
            return Err(AzureDocumentIntelligenceError::PermissionMismatch);
        }
        Ok(())
    }
}
