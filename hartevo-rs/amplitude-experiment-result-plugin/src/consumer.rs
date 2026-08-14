//! Mission-scoped consumer for proposal-only Amplitude experiment evidence.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AmplitudeEffectReceipt, AmplitudeExperimentResultProposal, AmplitudeExperimentResultRead,
    AmplitudeExperimentResultService, AmplitudeReadConsent, AmplitudeReadbackReceipt,
    AmplitudeRegistration, AmplitudeResultError, AmplitudeResultState, AmplitudeTransport, Digest,
    MissionBinding, ProjectBinding, ResultRecommendation, VariantBinding, WorkProductBinding,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionExperimentResultProjection {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub experiment: crate::ExperimentBinding,
    pub result_state: AmplitudeResultState,
    pub recommended_variant: Option<VariantBinding>,
    pub recommendation: ResultRecommendation,
    pub source_evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub effect_receipt: AmplitudeEffectReceipt,
    pub readback: AmplitudeReadbackReceipt,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub adopts_outcome: bool,
}

#[derive(Debug, Error)]
pub enum MissionAmplitudeExperimentConsumerError {
    #[error(transparent)]
    Result(#[from] AmplitudeResultError),
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("Work Product revision is stale")]
    StaleWorkProduct,
}

#[derive(Debug)]
pub struct MissionAmplitudeExperimentConsumer<T = crate::BlockedEnvAmplitudeTransport>
where
    T: AmplitudeTransport,
{
    service: AmplitudeExperimentResultService<T>,
}

impl<T> MissionAmplitudeExperimentConsumer<T>
where
    T: AmplitudeTransport,
{
    pub fn new(
        provider: crate::AmplitudeProvider<T>,
    ) -> Result<Self, MissionAmplitudeExperimentConsumerError> {
        Ok(Self {
            service: AmplitudeExperimentResultService::new(provider)?,
        })
    }

    #[must_use]
    pub fn from_service(service: AmplitudeExperimentResultService<T>) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn service(&self) -> &AmplitudeExperimentResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut AmplitudeExperimentResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub fn scope(&self) -> &crate::AmplitudeExperimentScope {
        self.service.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &AmplitudeRegistration {
        self.service.registration()
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> AmplitudeReadConsent {
        self.service.issue_read_consent()
    }

    pub fn compile_experiment_result_proposal(
        &mut self,
        operation: AmplitudeExperimentResultRead,
    ) -> Result<AmplitudeExperimentResultProposal, MissionAmplitudeExperimentConsumerError> {
        Ok(self.service.compile_experiment_result_proposal(operation)?)
    }

    pub fn compile_with_consent(
        &mut self,
        operation: AmplitudeExperimentResultRead,
        consent: &AmplitudeReadConsent,
    ) -> Result<AmplitudeExperimentResultProposal, MissionAmplitudeExperimentConsumerError> {
        Ok(self
            .service
            .compile_proposal_with_consent(operation, consent)?)
    }

    pub fn consume(
        &mut self,
        proposal: &AmplitudeExperimentResultProposal,
    ) -> Result<MissionExperimentResultProjection, MissionAmplitudeExperimentConsumerError> {
        let current_mission = self.scope().mission().clone();
        let current_work_product = self.scope().work_product().clone();
        self.consume_at_revisions(proposal, &current_mission, &current_work_product)
    }

    pub fn consume_at_mission(
        &mut self,
        proposal: &AmplitudeExperimentResultProposal,
        current_mission: &MissionBinding,
    ) -> Result<MissionExperimentResultProjection, MissionAmplitudeExperimentConsumerError> {
        let current_work_product = self.scope().work_product().clone();
        self.consume_at_revisions(proposal, current_mission, &current_work_product)
    }

    pub fn consume_at_revisions(
        &mut self,
        proposal: &AmplitudeExperimentResultProposal,
        current_mission: &MissionBinding,
        current_work_product: &WorkProductBinding,
    ) -> Result<MissionExperimentResultProjection, MissionAmplitudeExperimentConsumerError> {
        if current_mission != self.scope().mission() {
            return Err(MissionAmplitudeExperimentConsumerError::StaleMission);
        }
        if current_work_product != self.scope().work_product() {
            return Err(MissionAmplitudeExperimentConsumerError::StaleWorkProduct);
        }
        let effect_receipt = self
            .service
            .record_experiment_result_observation(proposal)?;
        let readback = self.service.read_back_experiment_result(proposal)?;
        Ok(MissionExperimentResultProjection {
            project: self.scope().project().clone(),
            mission: self.scope().mission().clone(),
            work_product: self.scope().work_product().clone(),
            experiment: self.scope().experiment().clone(),
            result_state: proposal.result_state(),
            recommended_variant: proposal.recommendation.recommended_variant.clone(),
            recommendation: proposal.recommendation.clone(),
            source_evidence_digest: proposal.source_evidence_digest.clone(),
            proposal_digest: proposal.digest(),
            effect_receipt,
            readback,
            proposal_only: true,
            connected: false,
            native: false,
            adopts_outcome: false,
        })
    }

    pub fn verify_experiment_result(
        &self,
        proposal: &AmplitudeExperimentResultProposal,
    ) -> Result<AmplitudeReadbackReceipt, MissionAmplitudeExperimentConsumerError> {
        Ok(self.service.read_back_experiment_result(proposal)?)
    }

    pub fn revoke(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<crate::RegistrationRevocationReceipt, MissionAmplitudeExperimentConsumerError> {
        Ok(self.service.revoke(reason)?)
    }

    pub fn restore(&mut self) -> Result<(), MissionAmplitudeExperimentConsumerError> {
        Ok(self.service.restore()?)
    }
}
