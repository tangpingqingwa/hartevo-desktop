//! Mission-scoped, non-authoritative AWS ELB target-health consumer.

use std::collections::BTreeSet;

use serde::Serialize;
use thiserror::Error;

use crate::{
    CONSUMER_ID,
    model::{
        AwsElbScope, Digest, EvidenceState, MissionBinding, ProjectBinding, RegistrationState,
        WorkProductBinding,
    },
    service::{AwsElbRegistration, AwsElbTargetHealthProposal, AwsElbTargetHealthServiceError},
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS ELB consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS ELB consumer registration is reversed")]
    RegistrationReversed,
    #[error("Mission AWS ELB consumer scope or registration does not match")]
    ScopeMismatch,
    #[error("Mission AWS ELB consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS ELB consumer evidence is fail-closed")]
    FailClosed,
    #[error("Mission AWS ELB consumer proposal was replayed")]
    Replay,
    #[error("Mission AWS ELB consumer service validation failed: {0}")]
    Service(#[from] AwsElbTargetHealthServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsElbDecisionState {
    HealthyReview,
    UnhealthyReview,
    InitialFailClosed,
    UnavailableFailClosed,
    StaleFailClosed,
    PartialFailClosed,
    ScopeDriftFailClosed,
    TargetGroupDriftFailClosed,
    AccessLossFailClosed,
    ProviderFailureFailClosed,
    TamperedFailClosed,
    ReplayFailClosed,
    RegistrationRevokedFailClosed,
}

impl MissionAwsElbDecisionState {
    pub const fn from_evidence(state: &EvidenceState) -> Self {
        match state {
            EvidenceState::Healthy => Self::HealthyReview,
            EvidenceState::Unhealthy => Self::UnhealthyReview,
            EvidenceState::Initial => Self::InitialFailClosed,
            EvidenceState::Unavailable => Self::UnavailableFailClosed,
            EvidenceState::Stale => Self::StaleFailClosed,
            EvidenceState::Partial => Self::PartialFailClosed,
            EvidenceState::ScopeDrift => Self::ScopeDriftFailClosed,
            EvidenceState::TargetGroupDrift => Self::TargetGroupDriftFailClosed,
            EvidenceState::AccessLoss
            | EvidenceState::BadRequest
            | EvidenceState::Unauthorized
            | EvidenceState::Forbidden
            | EvidenceState::NotFound
            | EvidenceState::Conflict
            | EvidenceState::Throttled
            | EvidenceState::ServerFailure
            | EvidenceState::Timeout
            | EvidenceState::ProviderUnknown => Self::ProviderFailureFailClosed,
            EvidenceState::Tampered => Self::TamperedFailClosed,
            EvidenceState::Replay => Self::ReplayFailClosed,
            EvidenceState::RegistrationRevoked => Self::RegistrationRevokedFailClosed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsElbResult {
    pub consumer_id: &'static str,
    pub decision_state: MissionAwsElbDecisionState,
    pub observed_evidence_state: EvidenceState,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub load_balancer_digest: Digest,
    pub target_group_digest: Digest,
    pub target_health_digest: Digest,
    pub topology_digest: Digest,
    pub health_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub accepted: bool,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub availability_certification: bool,
    pub adopted_outcome: bool,
    pub truth_authority: bool,
    pub work_product_adoption: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsElbResult {
    pub recording_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub request_digest: Digest,
    pub cost_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsElbConsumer {
    scope: AwsElbScope,
    registration: AwsElbRegistration,
    recorded_keys: BTreeSet<Digest>,
}

impl MissionAwsElbConsumer {
    pub fn new(
        scope: AwsElbScope,
        registration: AwsElbRegistration,
    ) -> Result<Self, ConsumerError> {
        registration
            .verify()
            .map_err(|_| ConsumerError::ScopeMismatch)?;
        if registration.state != RegistrationState::Active
            || registration.scope_digest != scope.scope_digest
            || registration.permission_digest != scope.permission_digest
            || registration.target_group_digest != scope.target_group.digest()
            || registration.target_group_revision != scope.target_group.revision
            || registration.target_health_digest != scope.target_health_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            recorded_keys: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &AwsElbScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsElbRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: AwsElbTargetHealthProposal,
    ) -> Result<MissionAwsElbResult, ConsumerError> {
        self.ensure_active()?;
        proposal
            .validate(&self.scope, &self.registration)
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.digests.scope_digest != self.scope.scope_digest
            || proposal.evidence.digests.permission_digest != self.registration.permission_digest
            || proposal.evidence.digests.target_group_digest != self.scope.target_group.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.evidence.state.is_fail_closed() {
            return Err(ConsumerError::FailClosed);
        }
        let decision_state = MissionAwsElbDecisionState::from_evidence(&proposal.state);
        let decision_digest = Digest::from_parts(
            "hartevo-mission-aws-elb-target-health-decision/v1",
            &[
                ("scope", self.scope.scope_digest.to_string()),
                (
                    "registration",
                    self.registration.registration_digest.to_string(),
                ),
                (
                    "evidence",
                    proposal.evidence.digests.evidence_digest.to_string(),
                ),
                ("proposal", proposal.proposal_digest.to_string()),
                ("decision", format!("{decision_state:?}")),
            ],
        );
        Ok(MissionAwsElbResult {
            consumer_id: CONSUMER_ID,
            decision_state,
            observed_evidence_state: proposal.state,
            project: self.scope.project.clone(),
            mission: self.scope.mission.clone(),
            work_product: self.scope.work_product.clone(),
            load_balancer_digest: self.scope.load_balancer.digest(),
            target_group_digest: self.scope.target_group.digest(),
            target_health_digest: proposal.evidence.digests.target_health_digest,
            topology_digest: proposal.evidence.topology_digest,
            health_digest: proposal.evidence.health_digest,
            scope_digest: self.scope.scope_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest,
            proposal_digest: proposal.proposal_digest,
            accepted: true,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            availability_certification: false,
            adopted_outcome: false,
            truth_authority: false,
            work_product_adoption: false,
            decision_digest,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsElbTargetHealthProposal,
        recording_key: impl AsRef<str>,
    ) -> Result<RecordedAwsElbResult, ConsumerError> {
        self.ensure_active()?;
        proposal
            .validate(&self.scope, &self.registration)
            .map_err(|_| ConsumerError::ProposalTampered)?;
        let key_digest = Digest::from_parts(
            "aws-elb-mission-recording-key/v1",
            &[("key", recording_key.as_ref().to_owned())],
        );
        if !self.recorded_keys.insert(key_digest.clone()) {
            return Err(ConsumerError::Replay);
        }
        let recording_digest = Digest::from_parts(
            "aws-elb-mission-recording/v1",
            &[
                ("key", key_digest.to_string()),
                ("proposal", proposal.proposal_digest.to_string()),
                (
                    "registration",
                    self.registration.registration_digest.to_string(),
                ),
            ],
        );
        Ok(RecordedAwsElbResult {
            recording_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digests.evidence_digest.clone(),
            request_digest: proposal.evidence.digests.request_digest.clone(),
            cost_digest: proposal.evidence.digests.cost_digest.clone(),
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &crate::service::AwsElbTargetHealthEvidence,
    ) -> Result<(), ConsumerError> {
        evidence
            .validate(&self.scope, &self.registration)
            .map_err(|_| ConsumerError::ProposalTampered)
    }

    fn ensure_active(&self) -> Result<(), ConsumerError> {
        self.registration
            .verify()
            .map_err(|_| ConsumerError::ScopeMismatch)?;
        match self.registration.state {
            RegistrationState::Active => Ok(()),
            RegistrationState::Reversed => Err(ConsumerError::RegistrationReversed),
            RegistrationState::Revoked => Err(ConsumerError::RegistrationRevoked),
        }
    }
}

pub type MissionAwsElbTargetHealthConsumer = MissionAwsElbConsumer;
pub type MissionAwsElbTargetHealthResult = MissionAwsElbResult;
pub type MissionAwsElbConsumerError = ConsumerError;
