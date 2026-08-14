//! Mission-scoped consumer for bounded Frame.io review evidence.

use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    Digest, FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION, FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION,
    FrameIoAuthority, FrameIoRegistration, FrameIoReviewProposal, FrameIoReviewResultService,
    FrameIoReviewStatus, FrameIoScope, FrameIoServiceError, MissionId, ProjectId, Revision,
    WorkProductId, contract_digest, model::digest_serializable,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionFrameIoReviewState {
    PendingDecision,
    Partial,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Frame.io Mission consumer registration is invalid")]
    InvalidRegistration,
    #[error("Frame.io Mission consumer received stale, tampered, or duplicate evidence")]
    StaleEvidence,
    #[error("Frame.io Mission consumer received a duplicate proposal")]
    DuplicateProposal,
    #[error(transparent)]
    Service(#[from] FrameIoServiceError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionFrameIoReviewResult {
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub state: MissionFrameIoReviewState,
    pub status: FrameIoReviewStatus,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub native_evidence: bool,
    pub connected: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub authority: FrameIoAuthority,
    pub result_digest: Digest,
}

impl MissionFrameIoReviewResult {
    fn new(proposal: &FrameIoReviewProposal) -> Result<Self, ConsumerError> {
        let state = match proposal.status() {
            FrameIoReviewStatus::Partial => MissionFrameIoReviewState::Partial,
            FrameIoReviewStatus::AccessLost => MissionFrameIoReviewState::AccessLost,
            FrameIoReviewStatus::ProviderUnknown => MissionFrameIoReviewState::ProviderUnknown,
            _ => MissionFrameIoReviewState::PendingDecision,
        };
        let mut result = Self {
            project_id: proposal.project_id.clone(),
            project_revision: proposal.project_revision,
            mission_id: proposal.mission_id.clone(),
            mission_revision: proposal.mission_revision,
            work_product_id: proposal.work_product_id.clone(),
            work_product_revision: proposal.work_product_revision,
            state,
            status: proposal.status(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            native_evidence: false,
            connected: false,
            outcome_authority: false,
            work_product_adoption: false,
            authority: FrameIoAuthority::layer_one(),
            result_digest: Digest::from_text("uninitialized-frameio-consumer-result"),
        };
        result.result_digest = digest_serializable(&result_material(&result))
            .map_err(FrameIoServiceError::Model)
            .map_err(ConsumerError::Service)?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MissionFrameIoReviewResultMaterial {
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    state: MissionFrameIoReviewState,
    status: FrameIoReviewStatus,
    proposal_digest: Digest,
    evidence_digest: Digest,
    native_evidence: bool,
    connected: bool,
    outcome_authority: bool,
    work_product_adoption: bool,
    authority: FrameIoAuthority,
}

fn result_material(result: &MissionFrameIoReviewResult) -> MissionFrameIoReviewResultMaterial {
    MissionFrameIoReviewResultMaterial {
        project_id: result.project_id.clone(),
        project_revision: result.project_revision,
        mission_id: result.mission_id.clone(),
        mission_revision: result.mission_revision,
        work_product_id: result.work_product_id.clone(),
        work_product_revision: result.work_product_revision,
        state: result.state,
        status: result.status,
        proposal_digest: result.proposal_digest.clone(),
        evidence_digest: result.evidence_digest.clone(),
        native_evidence: result.native_evidence,
        connected: result.connected,
        outcome_authority: result.outcome_authority,
        work_product_adoption: result.work_product_adoption,
        authority: result.authority,
    }
}

pub struct MissionFrameIoReviewConsumer {
    scope: FrameIoScope,
    registration: FrameIoRegistration,
    consumed_proposals: BTreeSet<Digest>,
}

impl fmt::Debug for MissionFrameIoReviewConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionFrameIoReviewConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration_digest", self.registration.digest())
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl MissionFrameIoReviewConsumer {
    pub fn new(
        scope: FrameIoScope,
        registration: &FrameIoRegistration,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active()
            || registration.scope_digest != scope.digest()
            || registration.contract_digest != contract_digest()
            || registration.plugin_version != FRAME_IO_REVIEW_RESULT_PLUGIN_VERSION
            || registration.contract_version != FRAME_IO_REVIEW_RESULT_CONTRACT_VERSION
        {
            return Err(ConsumerError::InvalidRegistration);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            consumed_proposals: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &FrameIoScope {
        &self.scope
    }

    pub fn registration(&self) -> &FrameIoRegistration {
        &self.registration
    }

    pub fn consume(
        &mut self,
        proposal: FrameIoReviewProposal,
    ) -> Result<MissionFrameIoReviewResult, ConsumerError> {
        proposal
            .validate_bindings(&self.scope, &self.registration)
            .map_err(|error| match error {
                FrameIoServiceError::StaleEvidence => ConsumerError::StaleEvidence,
                other => ConsumerError::Service(other),
            })?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(ConsumerError::DuplicateProposal);
        }
        MissionFrameIoReviewResult::new(&proposal)
    }

    pub fn validate_only(&self, proposal: &FrameIoReviewProposal) -> Result<(), ConsumerError> {
        proposal
            .validate_bindings(&self.scope, &self.registration)
            .map_err(|error| match error {
                FrameIoServiceError::StaleEvidence => ConsumerError::StaleEvidence,
                other => ConsumerError::Service(other),
            })
    }
}

impl<T: crate::FrameIoTransport> From<&FrameIoReviewResultService<T>>
    for MissionFrameIoReviewConsumer
{
    fn from(service: &FrameIoReviewResultService<T>) -> Self {
        Self {
            scope: service.scope().clone(),
            registration: service.registration().clone(),
            consumed_proposals: BTreeSet::new(),
        }
    }
}
