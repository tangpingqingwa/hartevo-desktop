//! Mission/Work Product consumer for the redacted provider projection.

use serde::{Deserialize, Serialize};

use crate::{
    AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION, AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION,
    AzureDocumentIntelligenceError, MISSION_DOCUMENT_INTELLIGENCE_CONSUMER_ID, contract_digest,
    model::{
        Digest, DocumentAnalysisRequest, DocumentIntelligenceEvidence, OperationStatus,
        RedactionPolicy,
    },
    service::AzureDocumentIntelligenceService,
};

/// Local disposition of a provider frame. It is proposal/evidence state, not
/// a kernel Outcome or Verification state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentIntelligenceDisposition {
    Projected,
    Pending,
    ProviderFailed,
    Canceled,
    BlockedEnv,
}

/// Mission-scoped observation metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MissionDocumentIntelligenceObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub disposition: DocumentIntelligenceDisposition,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted: bool,
    pub kernel_truth_authority: bool,
    pub kernel_receipt_authority: bool,
    pub kernel_verification_authority: bool,
    pub kernel_outcome_authority: bool,
    pub observation_digest: Digest,
}

impl MissionDocumentIntelligenceObservation {
    fn from_evidence(
        evidence: &DocumentIntelligenceEvidence,
        scope: &crate::AzureDocumentIntelligenceScope,
    ) -> Self {
        let disposition = match evidence.operation.status() {
            OperationStatus::Succeeded => DocumentIntelligenceDisposition::Projected,
            OperationStatus::NotStarted | OperationStatus::Running => {
                DocumentIntelligenceDisposition::Pending
            }
            OperationStatus::Failed => DocumentIntelligenceDisposition::ProviderFailed,
            OperationStatus::Canceled => DocumentIntelligenceDisposition::Canceled,
            OperationStatus::BlockedEnv => DocumentIntelligenceDisposition::BlockedEnv,
        };
        let mut observation = Self {
            contract_version: AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: MISSION_DOCUMENT_INTELLIGENCE_CONSUMER_ID.to_owned(),
            consumer_version: AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION.to_owned(),
            project_id: scope.project().id().to_string(),
            project_revision: scope.project().revision(),
            mission_id: scope.mission().id().to_string(),
            mission_revision: scope.mission().revision(),
            work_product_id: scope.work_product().id().to_string(),
            work_product_revision: scope.work_product().revision(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            disposition,
            proposal_only: true,
            connected: false,
            native: false,
            adopted: false,
            kernel_truth_authority: false,
            kernel_receipt_authority: false,
            kernel_verification_authority: false,
            kernel_outcome_authority: false,
            observation_digest: Digest::from_text("pending-observation-digest"),
        };
        observation.observation_digest = crate::digest_serializable(&ObservationMaterial {
            contract_version: &observation.contract_version,
            contract_digest: &observation.contract_digest,
            consumer_id: &observation.consumer_id,
            consumer_version: &observation.consumer_version,
            project_id: &observation.project_id,
            project_revision: observation.project_revision,
            mission_id: &observation.mission_id,
            mission_revision: observation.mission_revision,
            work_product_id: &observation.work_product_id,
            work_product_revision: observation.work_product_revision,
            scope_digest: &observation.scope_digest,
            evidence_digest: &observation.evidence_digest,
            disposition: observation.disposition,
            proposal_only: observation.proposal_only,
            connected: observation.connected,
            native: observation.native,
            adopted: observation.adopted,
            kernel_truth_authority: observation.kernel_truth_authority,
            kernel_receipt_authority: observation.kernel_receipt_authority,
            kernel_verification_authority: observation.kernel_verification_authority,
            kernel_outcome_authority: observation.kernel_outcome_authority,
        });
        observation
    }

    pub fn validate(
        &self,
        scope: &crate::AzureDocumentIntelligenceScope,
    ) -> Result<(), AzureDocumentIntelligenceError> {
        let expected_digest = crate::digest_serializable(&ObservationMaterial {
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            consumer_id: &self.consumer_id,
            consumer_version: &self.consumer_version,
            project_id: &self.project_id,
            project_revision: self.project_revision,
            mission_id: &self.mission_id,
            mission_revision: self.mission_revision,
            work_product_id: &self.work_product_id,
            work_product_revision: self.work_product_revision,
            scope_digest: &self.scope_digest,
            evidence_digest: &self.evidence_digest,
            disposition: self.disposition,
            proposal_only: self.proposal_only,
            connected: self.connected,
            native: self.native,
            adopted: self.adopted,
            kernel_truth_authority: self.kernel_truth_authority,
            kernel_receipt_authority: self.kernel_receipt_authority,
            kernel_verification_authority: self.kernel_verification_authority,
            kernel_outcome_authority: self.kernel_outcome_authority,
        });
        if self.contract_version != AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.consumer_id != MISSION_DOCUMENT_INTELLIGENCE_CONSUMER_ID
            || self.consumer_version != AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION
            || self.project_id != scope.project().id().as_str()
            || self.project_revision != scope.project().revision()
            || self.mission_id != scope.mission().id().as_str()
            || self.mission_revision != scope.mission().revision()
            || self.work_product_id != scope.work_product().id().as_str()
            || self.work_product_revision != scope.work_product().revision()
            || self.scope_digest != scope.digest()
            || !self.proposal_only
            || self.connected
            || self.native
            || self.adopted
            || self.kernel_truth_authority
            || self.kernel_receipt_authority
            || self.kernel_verification_authority
            || self.kernel_outcome_authority
            || self.observation_digest != expected_digest
        {
            return Err(AzureDocumentIntelligenceError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ObservationMaterial<'a> {
    contract_version: &'a str,
    contract_digest: &'a Digest,
    consumer_id: &'a str,
    consumer_version: &'a str,
    project_id: &'a str,
    project_revision: u64,
    mission_id: &'a str,
    mission_revision: u64,
    work_product_id: &'a str,
    work_product_revision: u64,
    scope_digest: &'a Digest,
    evidence_digest: &'a Digest,
    disposition: DocumentIntelligenceDisposition,
    proposal_only: bool,
    connected: bool,
    native: bool,
    adopted: bool,
    kernel_truth_authority: bool,
    kernel_receipt_authority: bool,
    kernel_verification_authority: bool,
    kernel_outcome_authority: bool,
}

/// Proposal-only mission result. Nothing here adopts a Work Product.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionDocumentIntelligenceResult {
    pub observation: MissionDocumentIntelligenceObservation,
    pub evidence: DocumentIntelligenceEvidence,
}

impl MissionDocumentIntelligenceResult {
    pub fn validate(
        &self,
        scope: &crate::AzureDocumentIntelligenceScope,
    ) -> Result<(), AzureDocumentIntelligenceError> {
        self.evidence
            .validate_integrity()
            .map_err(|_| AzureDocumentIntelligenceError::StaleEvidence)?;
        self.observation.validate(scope)?;
        if self.observation.evidence_digest != self.evidence.evidence_digest
            || self.evidence.scope_digest != scope.digest()
        {
            return Err(AzureDocumentIntelligenceError::StaleEvidence);
        }
        Ok(())
    }

    pub fn proposal_only(&self) -> bool {
        self.observation.proposal_only
    }

    pub fn connected(&self) -> bool {
        self.observation.connected
    }

    pub fn native(&self) -> bool {
        self.observation.native
    }

    pub fn adopted(&self) -> bool {
        self.observation.adopted
    }
}

/// Consumer bound to one exact Project/Mission/Work Product scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionDocumentIntelligenceConsumer {
    scope: crate::AzureDocumentIntelligenceScope,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
}

impl MissionDocumentIntelligenceConsumer {
    pub fn new(scope: crate::AzureDocumentIntelligenceScope) -> Self {
        Self {
            scope,
            plugin_version: AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION.to_owned(),
            contract_version: AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
        }
    }

    pub fn scope(&self) -> &crate::AzureDocumentIntelligenceScope {
        &self.scope
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn consume_evidence(
        &self,
        evidence: DocumentIntelligenceEvidence,
    ) -> Result<MissionDocumentIntelligenceResult, AzureDocumentIntelligenceError> {
        evidence
            .validate_integrity()
            .map_err(|_| AzureDocumentIntelligenceError::StaleEvidence)?;
        if evidence.contract_digest != self.contract_digest
            || evidence.contract_version != self.contract_version
            || evidence.plugin_version != self.plugin_version
            || evidence.service_id != crate::AZURE_DOCUMENT_INTELLIGENCE_SERVICE_ID
            || evidence.provider_id != crate::AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_ID
            || evidence.scope_digest != self.scope.digest()
            || evidence.source_digest != *self.scope.source_digest()
            || evidence.model != self.scope.model()
            || evidence.document_id != *self.scope.document_id()
            || evidence.page_range != self.scope.page_range()
            || !evidence.registration_digest.is_sha256()
        {
            return Err(AzureDocumentIntelligenceError::StaleEvidence);
        }
        let observation =
            MissionDocumentIntelligenceObservation::from_evidence(&evidence, &self.scope);
        let result = MissionDocumentIntelligenceResult {
            observation,
            evidence,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn read(
        &self,
        service: &mut AzureDocumentIntelligenceService,
        redaction: RedactionPolicy,
    ) -> Result<MissionDocumentIntelligenceResult, AzureDocumentIntelligenceError> {
        if service.scope() != &self.scope {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "consumer and service scopes differ".to_owned(),
            ));
        }
        let evidence = service.read(redaction)?;
        self.consume_evidence(evidence)
    }

    pub fn read_digest_only(
        &self,
        service: &mut AzureDocumentIntelligenceService,
    ) -> Result<MissionDocumentIntelligenceResult, AzureDocumentIntelligenceError> {
        self.read(service, RedactionPolicy::digest_only())
    }

    pub fn consume(
        &self,
        service: &AzureDocumentIntelligenceService,
        evidence: DocumentIntelligenceEvidence,
    ) -> Result<MissionDocumentIntelligenceResult, AzureDocumentIntelligenceError> {
        if service.scope() != &self.scope {
            return Err(AzureDocumentIntelligenceError::ScopeMismatch(
                "consumer and service scopes differ".to_owned(),
            ));
        }
        self.consume_evidence(evidence)
    }

    /// Request binding helper for hosts that want to inspect the proposal
    /// before handing it to a provider seam.
    pub fn request_matches_scope(&self, request: &DocumentAnalysisRequest) -> bool {
        request.scope_digest() == &self.scope.digest()
            && request.model() == self.scope.model()
            && request.document_id() == self.scope.document_id()
            && request.source_digest() == self.scope.source_digest()
            && request.page_range() == self.scope.page_range()
    }
}
