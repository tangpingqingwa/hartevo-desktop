use crate::error::CircleCiPipelineResultError;
use crate::model::{
    CircleCiMissionPipelineResult, CircleCiPipelineReadRequest, CircleCiPipelineResultEvidence,
    CircleCiPipelineResultProposal, CircleCiPipelineResultReceipt, MissionWorkProduct,
    VerifiedCircleCiPipelineResult,
};
use crate::provider::CircleCiCredentialResolver;
use crate::service::CircleCiPipelineResultService;
use crate::transport::CircleCiTransport;

/// Mission-scoped consumer for a CircleCI pipeline-result read/proposal seam.
/// It has no Outcome, Effect, deployment, scheduler, or UI authority.
#[derive(Debug)]
pub struct MissionCircleCiPipelineConsumer<T, R>
where
    T: CircleCiTransport,
    R: CircleCiCredentialResolver,
{
    service: CircleCiPipelineResultService<T, R>,
}

impl<T, R> MissionCircleCiPipelineConsumer<T, R>
where
    T: CircleCiTransport,
    R: CircleCiCredentialResolver,
{
    pub fn new(service: CircleCiPipelineResultService<T, R>) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &CircleCiPipelineResultService<T, R> {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut CircleCiPipelineResultService<T, R> {
        &mut self.service
    }

    pub fn read_pipeline_result(
        &mut self,
        request: &CircleCiPipelineReadRequest,
    ) -> Result<CircleCiPipelineResultEvidence, CircleCiPipelineResultError> {
        self.service.read_pipeline_result(request)
    }

    pub fn compose_pipeline_result(
        &self,
        work_product: MissionWorkProduct,
        evidence: CircleCiPipelineResultEvidence,
    ) -> Result<CircleCiPipelineResultProposal, CircleCiPipelineResultError> {
        self.service.compile_pipeline_result(work_product, evidence)
    }

    pub fn record_pipeline_result(
        &self,
        proposal: &CircleCiPipelineResultProposal,
    ) -> Result<CircleCiPipelineResultReceipt, CircleCiPipelineResultError> {
        self.service.record_pipeline_result(proposal)
    }

    pub fn verify_pipeline_result(
        &self,
        proposal: &CircleCiPipelineResultProposal,
        receipt: &CircleCiPipelineResultReceipt,
    ) -> Result<VerifiedCircleCiPipelineResult, CircleCiPipelineResultError> {
        self.service.verify_pipeline_result(proposal, receipt)
    }

    pub fn consume_pipeline_result(
        &mut self,
        request: &CircleCiPipelineReadRequest,
        work_product: MissionWorkProduct,
    ) -> Result<CircleCiMissionPipelineResult, CircleCiPipelineResultError> {
        let evidence = self.read_pipeline_result(request)?;
        let proposal = self.compose_pipeline_result(work_product, evidence.clone())?;
        let receipt = self.record_pipeline_result(&proposal)?;
        let verification = self.verify_pipeline_result(&proposal, &receipt)?;
        let result = CircleCiMissionPipelineResult {
            evidence,
            proposal,
            receipt,
            verification,
        };
        result.evidence.validate(&request.scope)?;
        result.verification.validate()?;
        Ok(result)
    }
}
