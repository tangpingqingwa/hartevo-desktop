use std::fmt;

use thiserror::Error;

use crate::{
    model::{
        Digest, HoneycombRegistration, HoneycombTraceScope, MissionId, ProjectId, QueryResultState,
        RegistrationState, Revision, WorkProductId,
    },
    service::{HoneycombResultEvidence, HoneycombResultProposal},
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Honeycomb consumer registration is revoked or mismatched")]
    RegistrationMismatch,
    #[error("Mission Honeycomb consumer is revoked")]
    Revoked,
    #[error("proposal scope, revision, permission, consent, or redaction fence is stale")]
    FenceMismatch,
    #[error("proposal is not a valid Honeycomb aggregate-result proposal")]
    InvalidProposal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionHoneycombTraceResult {
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub projection: QueryResultState,
    pub state: MissionResultState,
    pub evidence: HoneycombResultEvidence,
    pub proposal_digest: Digest,
    pub adoption: AdoptionAvailability,
}

pub struct MissionHoneycombTraceConsumer {
    scope: HoneycombTraceScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl fmt::Debug for MissionHoneycombTraceConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionHoneycombTraceConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionHoneycombTraceConsumer {
    pub fn new(
        scope: HoneycombTraceScope,
        registration: &HoneycombRegistration,
    ) -> Result<Self, ConsumerError> {
        registration
            .validate(&scope)
            .map_err(|_| ConsumerError::RegistrationMismatch)?;
        if registration.state != RegistrationState::Active
            || registration.scope_digest != *scope.digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                revision: registration.revision,
                state: registration.state,
            },
            active: true,
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &HoneycombTraceScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.active {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        } else {
            Err(ConsumerError::Revoked)
        }
    }

    pub fn consume(
        &self,
        proposal: HoneycombResultProposal,
    ) -> Result<MissionHoneycombTraceResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        validate_proposal(&self.scope, &self.registration, &proposal)?;
        let state = match proposal.projection {
            QueryResultState::Complete | QueryResultState::Empty => {
                MissionResultState::PendingDecision
            }
            QueryResultState::Queued
            | QueryResultState::Running
            | QueryResultState::Partial
            | QueryResultState::RateLimited
            | QueryResultState::AccessLost
            | QueryResultState::ProviderUnknown => MissionResultState::Layer2AdoptionRequired,
        };
        Ok(MissionHoneycombTraceResult {
            mission_id: self.scope.mission.id.clone(),
            mission_revision: self.scope.mission.revision,
            project_id: self.scope.project.id.clone(),
            project_revision: self.scope.project.revision,
            work_product_id: self.scope.work_product.id.clone(),
            work_product_revision: self.scope.work_product.revision,
            projection: proposal.projection,
            state,
            evidence: proposal.evidence,
            proposal_digest: proposal.proposal_digest,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        })
    }
}

pub type MissionTraceConsumer = MissionHoneycombTraceConsumer;
pub type MissionTraceResult = MissionHoneycombTraceResult;

fn validate_proposal(
    scope: &HoneycombTraceScope,
    registration: &ConsumerRegistration,
    proposal: &HoneycombResultProposal,
) -> Result<(), ConsumerError> {
    let evidence = &proposal.evidence;
    if proposal.registration_digest != registration.registration_digest
        || proposal.registration_revision != registration.revision
        || proposal.projection != evidence.projection
        || proposal.query_id != evidence.snapshot.query_id
        || proposal.query_result_id != evidence.snapshot.query_result_id
        || evidence.scope_digest != *scope.digest()
        || evidence.permission_digest != *scope.permission_digest()
        || evidence.consent_digest != *scope.consent_digest()
        || evidence.query_digest != *scope.query_digest()
        || evidence.query_window_digest != *scope.time_window.digest()
        || evidence.deployment_marker_digest != *scope.deployment_marker.digest()
        || evidence.mission_digest != scope.mission.digest
        || evidence.project_digest != scope.project.digest
        || evidence.work_product_digest != scope.work_product.digest
        || evidence.redaction_policy_digest != *scope.redaction_policy.digest()
        || evidence.registration_digest != registration.registration_digest
        || evidence.snapshot.region != scope.region
        || evidence.snapshot.api_version != scope.api_version
        || evidence.snapshot.team != scope.team
        || evidence.snapshot.environment != scope.environment
        || evidence.snapshot.dataset != scope.dataset
        || evidence.snapshot.scope_digest != *scope.digest()
        || evidence.snapshot.query_digest != *scope.query_digest()
        || evidence.snapshot.deployment_marker_digest != *scope.deployment_marker.digest()
        || evidence.snapshot.time_window_digest != *scope.time_window.digest()
        || evidence.snapshot.redaction_policy_digest != *scope.redaction_policy.digest()
    {
        return Err(ConsumerError::FenceMismatch);
    }
    if evidence.snapshot.validate_digest().is_err() {
        return Err(ConsumerError::InvalidProposal);
    }
    if proposal.validate_digest().is_err() {
        return Err(ConsumerError::InvalidProposal);
    }
    if evidence.evidence_digest().as_str().len() != 64 {
        return Err(ConsumerError::InvalidProposal);
    }
    Ok(())
}
