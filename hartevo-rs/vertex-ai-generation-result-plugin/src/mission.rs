//! Mission/Project/Work Product consumer projection.

use serde::Serialize;

use crate::{
    digest_bytes, digest_serializable,
    model::{
        GenerationRequest, GenerationResultEvidence, GenerationResultProposal, ModelDescription,
        PluginRegistration, ResponseByteAccounting, ResponseState, Revocation, RevocationReason,
        VertexAiGenerationError, VertexAiGenerationScope, response_accounting_policy_digest,
    },
    provider::{RecordedVertexAiResponse, VertexAiGenerationProvider},
    service::VertexAiGenerationResultService,
};

/// A proposal-only Mission projection. It carries bounded evidence identity
/// but has no kernel Outcome, Truth, Receipt, or Work Product adoption power.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionVertexAiResult {
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub consent_digest: crate::model::Digest,
    pub proposal_digest: crate::model::Digest,
    pub request_digest: crate::model::Digest,
    pub request_source_fence: crate::model::Digest,
    pub response_accounting_policy_digest: crate::model::Digest,
    pub response_byte_accounting: ResponseByteAccounting,
    pub evidence_digest: crate::model::Digest,
    pub output_digest: Option<crate::model::Digest>,
    pub state: ResponseState,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_receipt: bool,
    pub independent_read_back: bool,
    pub adopted_outcome: bool,
    mission_result_digest: crate::model::Digest,
}

pub type MissionResultProjection = MissionVertexAiResult;

impl MissionVertexAiResult {
    fn from_result(
        scope: &VertexAiGenerationScope,
        proposal: &GenerationResultProposal,
        evidence: &GenerationResultEvidence,
    ) -> Self {
        let mut result = Self {
            project_id: scope.project().id().to_owned(),
            project_revision: scope.project().revision(),
            mission_id: scope.mission().id().to_owned(),
            mission_revision: scope.mission().revision(),
            work_product_id: scope.work_product().id().to_owned(),
            work_product_revision: scope.work_product().revision(),
            consent_digest: scope.consent().consent_digest().clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            request_digest: proposal.request.request_digest().clone(),
            request_source_fence: proposal.request.source_fence().clone(),
            response_accounting_policy_digest: evidence.response_accounting_policy_digest.clone(),
            response_byte_accounting: evidence.response_byte_accounting,
            evidence_digest: evidence.evidence_digest.clone(),
            output_digest: evidence.output_digest.clone(),
            state: evidence.state,
            proposal_only: true,
            connected: false,
            native: false,
            durable_receipt: false,
            independent_read_back: false,
            adopted_outcome: false,
            mission_result_digest: digest_bytes(b"uninitialized-vertex-ai-mission-result-digest"),
        };
        result.mission_result_digest = result.compute_result_digest();
        result
    }

    pub const fn proposal_only(&self) -> bool {
        self.proposal_only
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn adopted_outcome(&self) -> bool {
        self.adopted_outcome
    }

    pub fn result_digest(&self) -> &crate::model::Digest {
        &self.mission_result_digest
    }

    pub fn verify_integrity(&self) -> Result<(), VertexAiGenerationError> {
        if self.response_accounting_policy_digest != response_accounting_policy_digest()
            || !self.response_accounting_policy_digest.is_sha256()
            || self.response_byte_accounting.validate_metadata().is_err()
            || self.connected
            || self.native
            || self.durable_receipt
            || self.independent_read_back
            || self.adopted_outcome
            || self.mission_result_digest != self.compute_result_digest()
        {
            Err(VertexAiGenerationError::EvidenceTampered)
        } else {
            Ok(())
        }
    }

    pub fn scope_digest(&self) -> crate::model::Digest {
        digest_serializable(&(
            "vertex-ai-mission-result-scope/v1",
            &self.project_id,
            self.project_revision,
            &self.mission_id,
            self.mission_revision,
            &self.work_product_id,
            self.work_product_revision,
            &self.consent_digest,
            &self.response_accounting_policy_digest,
            self.response_byte_accounting,
        ))
    }

    fn compute_result_digest(&self) -> crate::model::Digest {
        digest_serializable(&MissionResultMaterial {
            version: "vertex-ai-mission-result/v2",
            project_id: &self.project_id,
            project_revision: self.project_revision,
            mission_id: &self.mission_id,
            mission_revision: self.mission_revision,
            work_product_id: &self.work_product_id,
            work_product_revision: self.work_product_revision,
            consent_digest: &self.consent_digest,
            proposal_digest: &self.proposal_digest,
            request_digest: &self.request_digest,
            request_source_fence: &self.request_source_fence,
            response_accounting_policy_digest: &self.response_accounting_policy_digest,
            response_byte_accounting: self.response_byte_accounting,
            evidence_digest: &self.evidence_digest,
            output_digest: self.output_digest.as_ref(),
            state: self.state,
            proposal_only: self.proposal_only,
            connected: self.connected,
            native: self.native,
            durable_receipt: self.durable_receipt,
            independent_read_back: self.independent_read_back,
            adopted_outcome: self.adopted_outcome,
        })
    }
}

#[derive(Serialize)]
struct MissionResultMaterial<'a> {
    version: &'static str,
    project_id: &'a str,
    project_revision: u64,
    mission_id: &'a str,
    mission_revision: u64,
    work_product_id: &'a str,
    work_product_revision: u64,
    consent_digest: &'a crate::model::Digest,
    proposal_digest: &'a crate::model::Digest,
    request_digest: &'a crate::model::Digest,
    request_source_fence: &'a crate::model::Digest,
    response_accounting_policy_digest: &'a crate::model::Digest,
    response_byte_accounting: ResponseByteAccounting,
    evidence_digest: &'a crate::model::Digest,
    output_digest: Option<&'a crate::model::Digest>,
    state: ResponseState,
    proposal_only: bool,
    connected: bool,
    native: bool,
    durable_receipt: bool,
    independent_read_back: bool,
    adopted_outcome: bool,
}

/// Mission consumer for one exact regional Gemini model snapshot and policy
/// binding.
#[derive(Clone, Debug)]
pub struct MissionVertexAiResultConsumer {
    service: VertexAiGenerationResultService,
}

impl MissionVertexAiResultConsumer {
    pub fn new(
        scope: VertexAiGenerationScope,
        provider: VertexAiGenerationProvider,
    ) -> Result<Self, VertexAiGenerationError> {
        Ok(Self {
            service: VertexAiGenerationResultService::new(scope, provider)?,
        })
    }

    pub fn from_service(service: VertexAiGenerationResultService) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &VertexAiGenerationResultService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut VertexAiGenerationResultService {
        &mut self.service
    }

    pub fn registration(&self) -> &PluginRegistration {
        self.service.registration()
    }

    pub fn describe_model(&self) -> Result<ModelDescription, VertexAiGenerationError> {
        self.service.describe_model()
    }

    pub fn compile_generation_proposal(
        &self,
        request: &GenerationRequest,
    ) -> Result<GenerationResultProposal, VertexAiGenerationError> {
        self.service.compile_generation_proposal(request)
    }

    pub fn consume_recorded_result(
        &mut self,
        proposal: &GenerationResultProposal,
        response: &RecordedVertexAiResponse,
    ) -> Result<MissionVertexAiResult, VertexAiGenerationError> {
        let evidence = self.service.record_generation_result(proposal, response)?;
        self.service.verify_generation_result(proposal, &evidence)?;
        let result = MissionVertexAiResult::from_result(self.service.scope(), proposal, &evidence);
        result.verify_integrity()?;
        Ok(result)
    }

    pub fn record_generation_result(
        &mut self,
        proposal: &GenerationResultProposal,
        response: &RecordedVertexAiResponse,
    ) -> Result<GenerationResultEvidence, VertexAiGenerationError> {
        self.service.record_generation_result(proposal, response)
    }

    pub fn verify_generation_result(
        &self,
        proposal: &GenerationResultProposal,
        evidence: &GenerationResultEvidence,
    ) -> Result<(), VertexAiGenerationError> {
        self.service.verify_generation_result(proposal, evidence)
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, VertexAiGenerationError> {
        self.service.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), VertexAiGenerationError> {
        self.service.restore()
    }
}
