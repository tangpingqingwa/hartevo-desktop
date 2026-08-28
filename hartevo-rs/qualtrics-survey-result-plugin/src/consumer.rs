use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    model::{ConsentId, Digest, MissionId, ProjectId, QualtricsScope},
    service::{QualtricsRegistration, QualtricsResultState, QualtricsSurveyResultProposal},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission consumer scope does not match the registration")]
    ScopeMismatch,
    #[error("Mission consumer received a proposal from a different registration")]
    RegistrationMismatch,
    #[error("Mission consumer cannot adopt a Layer-1 proposal")]
    AdoptionForbidden,
    #[error("Mission consumer received a proposal with native or Truth authority")]
    AuthorityViolation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionQualtricsSurveyResult {
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub consent_id: ConsentId,
    pub state: QualtricsResultState,
    pub source_result_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub answer_count: usize,
    pub export_progress_state: Option<crate::model::ExportProgressState>,
    pub adoption: AdoptionAvailability,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub truth_authority: bool,
}

pub struct MissionQualtricsSurveyConsumer {
    mission_id: MissionId,
    project_id: ProjectId,
    consent_id: ConsentId,
    scope_digest: Digest,
    registration_digest: Digest,
}

impl std::fmt::Debug for MissionQualtricsSurveyConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionQualtricsSurveyConsumer")
            .field("mission_id", &self.mission_id)
            .field("project_id", &self.project_id)
            .field("consent_id", &self.consent_id)
            .field("scope_digest", &self.scope_digest)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl MissionQualtricsSurveyConsumer {
    pub fn new(
        scope: QualtricsScope,
        registration: &QualtricsRegistration,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active() || registration.scope_digest() != scope.scope_digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            mission_id: scope.mission().clone(),
            project_id: scope.project().clone(),
            consent_id: scope.consent().id().clone(),
            scope_digest: scope.scope_digest().clone(),
            registration_digest: registration.registration_digest().clone(),
        })
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn consent_id(&self) -> &ConsentId {
        &self.consent_id
    }

    pub fn consume(
        &self,
        proposal: QualtricsSurveyResultProposal,
    ) -> Result<MissionQualtricsSurveyResult, ConsumerError> {
        if proposal.scope_digest() != &self.scope_digest {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.registration_digest() != &self.registration_digest {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.is_adopted() || !proposal.proposal_only() {
            return Err(ConsumerError::AdoptionForbidden);
        }
        let authority = proposal.authority();
        if authority.connected()
            || authority.native()
            || authority.truth()
            || authority.adopted_outcome()
        {
            return Err(ConsumerError::AuthorityViolation);
        }
        Ok(MissionQualtricsSurveyResult {
            mission_id: self.mission_id.clone(),
            project_id: self.project_id.clone(),
            consent_id: self.consent_id.clone(),
            state: proposal.state(),
            source_result_digest: proposal.evidence().result_digest().clone(),
            registration_digest: proposal.registration_digest().clone(),
            provider_digest: proposal.provider_digest().clone(),
            answer_count: proposal.evidence().answers().len(),
            export_progress_state: proposal
                .evidence()
                .export_progress()
                .map(crate::model::ResponseExportProgress::state),
            adoption: AdoptionAvailability::NotAdoptedLayer2,
            proposal_only: true,
            connected: false,
            native: false,
            truth_authority: false,
        })
    }
}
