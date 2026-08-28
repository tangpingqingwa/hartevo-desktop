//! Typed service descriptor and local execution/projection seam.

use serde::{Deserialize, Serialize};

use crate::{
    AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION, AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_NAME,
    AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION, AZURE_DOCUMENT_INTELLIGENCE_SERVICE_ID,
    AZURE_DOCUMENT_INTELLIGENCE_SERVICE_NAME, AzureDocumentIntelligenceError, contract_digest,
    model::{
        AzureDocumentIntelligenceScope, DocumentAnalysisRequest, DocumentIntelligenceEvidence,
        Layer1Authority, OperationStatus, OperationStatusFrame, ProviderMode, RedactionPolicy,
    },
    provider::{
        AzureDocumentIntelligenceProvider, RegistrationState, Revocation, RevocationReason,
    },
};

/// Operations exposed by the typed, read-only service descriptor.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureDocumentIntelligenceOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    CompileAnalysisRequest,
    BeginAnalysisSeam,
    PollAnalysisSeam,
    ProjectRedactedResult,
    ConsumeMissionProjection,
}

impl AzureDocumentIntelligenceOperation {
    pub const ALL: [Self; 8] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::CompileAnalysisRequest,
        Self::BeginAnalysisSeam,
        Self::PollAnalysisSeam,
        Self::ProjectRedactedResult,
        Self::ConsumeMissionProjection,
    ];

    pub const fn is_read_only(self) -> bool {
        true
    }
}

/// Capability metadata; it grants no kernel or external authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDocumentIntelligenceCapability {
    pub capability_id: String,
    pub operation: AzureDocumentIntelligenceOperation,
    pub read_only: bool,
    pub mutates_external_system: bool,
    pub native_evidence: bool,
}

/// Azure Document Intelligence service owned by the standalone plugin root.
#[derive(Clone, Debug)]
pub struct AzureDocumentIntelligenceService {
    scope: AzureDocumentIntelligenceScope,
    provider: AzureDocumentIntelligenceProvider,
    capabilities: Vec<AzureDocumentIntelligenceCapability>,
}

impl AzureDocumentIntelligenceService {
    pub fn new(
        scope: AzureDocumentIntelligenceScope,
        provider: AzureDocumentIntelligenceProvider,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        if provider.scope() != &scope {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "service and provider scopes differ".to_owned(),
            ));
        }
        provider
            .registration()
            .validate_against(&scope, provider.registration().provider_revision())?;
        let capabilities = capability_set();
        Ok(Self {
            scope,
            provider,
            capabilities,
        })
    }

    pub fn from_scope(
        scope: AzureDocumentIntelligenceScope,
        secret_reference: crate::SecretReference,
        mode: ProviderMode,
    ) -> Result<Self, AzureDocumentIntelligenceError> {
        let provider =
            AzureDocumentIntelligenceProvider::new(scope.clone(), secret_reference, mode)?;
        Self::new(scope, provider)
    }

    pub fn service_id(&self) -> &'static str {
        AZURE_DOCUMENT_INTELLIGENCE_SERVICE_ID
    }

    pub fn service_name(&self) -> &'static str {
        AZURE_DOCUMENT_INTELLIGENCE_SERVICE_NAME
    }

    pub fn provider_name(&self) -> &'static str {
        AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_NAME
    }

    pub fn plugin_version(&self) -> &'static str {
        AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION
    }

    pub fn provider_revision(&self) -> &'static str {
        AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION
    }

    pub const fn read_only(&self) -> bool {
        true
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub fn scope(&self) -> &AzureDocumentIntelligenceScope {
        &self.scope
    }

    pub fn provider(&self) -> &AzureDocumentIntelligenceProvider {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AzureDocumentIntelligenceProvider {
        &mut self.provider
    }

    pub fn registration(&self) -> &crate::AzureDocumentIntelligenceRegistration {
        self.provider.registration()
    }

    pub fn capabilities(&self) -> &[AzureDocumentIntelligenceCapability] {
        &self.capabilities
    }

    pub fn describe_capabilities(&self) -> Vec<AzureDocumentIntelligenceCapability> {
        self.capabilities.clone()
    }

    pub fn validate(&self) -> Result<(), AzureDocumentIntelligenceError> {
        if self.service_id() != AZURE_DOCUMENT_INTELLIGENCE_SERVICE_ID
            || self.service_name() != AZURE_DOCUMENT_INTELLIGENCE_SERVICE_NAME
            || self.provider_name() != AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_NAME
            || !self.read_only()
            || self.native_connected()
            || self.provider.is_connected()
            || self.provider.is_native()
            || self.capabilities.is_empty()
            || self.capabilities.iter().any(|capability| {
                !capability.read_only
                    || capability.mutates_external_system
                    || capability.native_evidence
            })
        {
            return Err(AzureDocumentIntelligenceError::InvalidInput(
                "Azure Document Intelligence service descriptor drifted".to_owned(),
            ));
        }
        Ok(())
    }

    /// Compile an exact request containing only source digest and scope data.
    pub fn compile_analysis_request(
        &self,
        redaction: RedactionPolicy,
    ) -> Result<DocumentAnalysisRequest, AzureDocumentIntelligenceError> {
        self.ensure_active()?;
        Ok(DocumentAnalysisRequest::for_scope(&self.scope, redaction))
    }

    /// Digest-only request convenience method.
    pub fn compile_request(
        &self,
    ) -> Result<DocumentAnalysisRequest, AzureDocumentIntelligenceError> {
        self.compile_analysis_request(RedactionPolicy::digest_only())
    }

    /// Replay one bounded provider frame and project it into local evidence.
    pub fn analyze(
        &mut self,
        request: &DocumentAnalysisRequest,
    ) -> Result<DocumentIntelligenceEvidence, AzureDocumentIntelligenceError> {
        self.ensure_active()?;
        self.validate_request(request)?;
        let frame = match self.provider.analyze(request) {
            Ok(frame) => frame,
            Err(AzureDocumentIntelligenceError::BlockedEnv) => blocked_frame(&self.provider),
            Err(error) => return Err(error),
        };
        self.project_frame(request, &frame)
    }

    /// Compile a request with the selected redaction policy and replay it.
    pub fn read(
        &mut self,
        redaction: RedactionPolicy,
    ) -> Result<DocumentIntelligenceEvidence, AzureDocumentIntelligenceError> {
        let request = self.compile_analysis_request(redaction)?;
        self.analyze(&request)
    }

    /// Record a BLOCKED_ENV seam without pretending that native analysis ran.
    pub fn record_blocked_env(
        &self,
        redaction: RedactionPolicy,
    ) -> Result<DocumentIntelligenceEvidence, AzureDocumentIntelligenceError> {
        self.ensure_active()?;
        if self.provider.mode() != ProviderMode::BlockedEnv {
            return Err(AzureDocumentIntelligenceError::InvalidInput(
                "BLOCKED_ENV recording requires BLOCKED_ENV provider mode".to_owned(),
            ));
        }
        let request = DocumentAnalysisRequest::for_scope(&self.scope, redaction);
        let frame = blocked_frame(&self.provider);
        self.project_frame(&request, &frame)
    }

    pub fn consume_evidence(
        &self,
        evidence: DocumentIntelligenceEvidence,
    ) -> Result<DocumentIntelligenceEvidence, AzureDocumentIntelligenceError> {
        self.ensure_active()?;
        self.validate_evidence(&evidence)?;
        Ok(evidence)
    }

    /// Local digest/binding validation only; this is not kernel Verification.
    pub fn validate_evidence(
        &self,
        evidence: &DocumentIntelligenceEvidence,
    ) -> Result<(), AzureDocumentIntelligenceError> {
        evidence
            .validate_integrity()
            .map_err(|_| AzureDocumentIntelligenceError::StaleEvidence)?;
        if evidence.contract_digest != contract_digest()
            || evidence.contract_version != crate::AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION
            || evidence.plugin_version != crate::AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION
            || evidence.service_id != crate::AZURE_DOCUMENT_INTELLIGENCE_SERVICE_ID
            || evidence.provider_id != crate::AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_ID
            || evidence.provider_revision != *self.registration().provider_revision()
            || evidence.scope_digest != self.scope.digest()
            || evidence.source_digest != *self.scope.source_digest()
            || evidence.model != self.scope.model()
            || evidence.document_id != *self.scope.document_id()
            || evidence.page_range != self.scope.page_range()
            || evidence.registration_digest != *self.registration().registration_digest()
            || evidence.authority != Layer1Authority::layer_one()
            || evidence.provenance != self.provider.provenance()
        {
            return Err(AzureDocumentIntelligenceError::StaleEvidence);
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, AzureDocumentIntelligenceError> {
        self.provider.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), AzureDocumentIntelligenceError> {
        self.provider.restore()
    }

    pub fn registration_state(&self) -> RegistrationState {
        self.provider.registration().state()
    }

    fn ensure_active(&self) -> Result<(), AzureDocumentIntelligenceError> {
        self.provider.registration().validate_against(
            &self.scope,
            self.provider.registration().provider_revision(),
        )
    }

    fn validate_request(
        &self,
        request: &DocumentAnalysisRequest,
    ) -> Result<(), AzureDocumentIntelligenceError> {
        if request.scope_digest() != &self.scope.digest()
            || request.model() != self.scope.model()
            || request.document_id() != self.scope.document_id()
            || request.source_digest() != self.scope.source_digest()
            || request.page_range() != self.scope.page_range()
        {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "request does not match service scope".to_owned(),
            ));
        }
        Ok(())
    }

    fn project_frame(
        &self,
        request: &DocumentAnalysisRequest,
        frame: &OperationStatusFrame,
    ) -> Result<DocumentIntelligenceEvidence, AzureDocumentIntelligenceError> {
        if frame.response_bytes() > crate::MAX_DOCUMENT_INTELLIGENCE_RESPONSE_BYTES {
            return Err(AzureDocumentIntelligenceError::ResponseTooLarge(
                frame.response_bytes(),
            ));
        }
        if frame.status() == OperationStatus::Succeeded && frame.result().is_none() {
            return Err(AzureDocumentIntelligenceError::ResultUnavailable);
        }
        if let Some(result) = frame.result()
            && (result.model() != request.model()
                || result.source_digest() != request.source_digest()
                || result.page_range() != request.page_range())
        {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "result is not bound to the request".to_owned(),
            ));
        }
        let evidence = DocumentIntelligenceEvidence::new(
            request,
            &self.scope,
            self.registration().registration_digest(),
            frame.provider_revision().clone(),
            frame,
            contract_digest(),
        );
        evidence
            .validate_integrity()
            .map_err(|_| AzureDocumentIntelligenceError::StaleEvidence)?;
        Ok(evidence)
    }
}

fn capability_set() -> Vec<AzureDocumentIntelligenceCapability> {
    AzureDocumentIntelligenceOperation::ALL
        .into_iter()
        .map(|operation| AzureDocumentIntelligenceCapability {
            capability_id: format!(
                "azure.document-intelligence.{}",
                serde_json::to_string(&operation)
                    .expect("operation serializes")
                    .trim_matches('"')
            ),
            operation,
            read_only: true,
            mutates_external_system: false,
            native_evidence: false,
        })
        .collect()
}

fn blocked_frame(provider: &AzureDocumentIntelligenceProvider) -> OperationStatusFrame {
    OperationStatusFrame::new(
        None,
        OperationStatus::BlockedEnv,
        provider.registration().provider_revision().clone(),
        ProviderMode::BlockedEnv,
        crate::model::sha256_digest(b"BLOCKED_ENV"),
        0,
        None,
        None,
    )
}
