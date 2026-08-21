//! Mission/Project/Work Product consumer projection.

use serde::Serialize;

use crate::{
    digest_serializable,
    model::{
        GenerationRequest, GenerationResultEvidence, GenerationResultProposal, ModelDescription,
        PluginRegistration, ResponseState, Revocation, RevocationReason, VertexAiGenerationError,
        VertexAiGenerationScope,
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
    pub evidence_digest: crate::model::Digest,
    pub output_digest: Option<crate::model::Digest>,
    pub state: ResponseState,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_receipt: bool,
    pub independent_read_back: bool,
    pub adopted_outcome: bool,
}

pub type MissionResultProjection = MissionVertexAiResult;

impl MissionVertexAiResult {
    fn from_result(
        scope: &VertexAiGenerationScope,
        proposal: &GenerationResultProposal,
        evidence: &GenerationResultEvidence,
    ) -> Self {
        Self {
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
            evidence_digest: evidence.evidence_digest.clone(),
            output_digest: evidence.output_digest.clone(),
            state: evidence.state,
            proposal_only: true,
            connected: false,
            native: false,
            durable_receipt: false,
            independent_read_back: false,
            adopted_outcome: false,
        }
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
        ))
    }
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
        Ok(MissionVertexAiResult::from_result(
            self.service.scope(),
            proposal,
            &evidence,
        ))
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
