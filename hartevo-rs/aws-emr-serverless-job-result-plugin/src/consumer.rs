//! Mission-scoped, review-only proposal consumption.

use serde::Serialize;
use thiserror::Error;

use crate::error::Result;
use crate::model::{
    AwsEmrServerlessJobResultScope, Digest, JobRunEvidence, JobRunState, Revision,
    TransportProvenance,
};
use crate::service::{AwsEmrServerlessJobResultProposal, AwsEmrServerlessJobResultRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission EMR Serverless consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Work Product scope")]
    ScopeMismatch,
    #[error("proposal evidence fence is stale")]
    FenceMismatch,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("proposal was not produced by the governed EMR Serverless service")]
    InvalidProposal,
    #[error("proposal evidence is tampered")]
    TamperedEvidence,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultDisposition {
    EvidenceReady,
    Partial,
    Expired,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<JobRunState> for MissionResultDisposition {
    fn from(value: JobRunState) -> Self {
        match value {
            JobRunState::Success | JobRunState::Failed | JobRunState::Cancelled => {
                Self::EvidenceReady
            }
            JobRunState::Partial => Self::Partial,
            JobRunState::Expired => Self::Expired,
            JobRunState::AccessLost => Self::AccessLost,
            JobRunState::Tampered => Self::Tampered,
            JobRunState::Revoked => Self::Revoked,
            JobRunState::Submitted
            | JobRunState::Pending
            | JobRunState::Scheduled
            | JobRunState::Queued
            | JobRunState::Running
            | JobRunState::ProviderUnknown
            | JobRunState::Cancelling => Self::ProviderUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsEmrServerlessResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub status: JobRunState,
    pub state: MissionResultState,
    pub disposition: MissionResultDisposition,
    pub evidence: Option<JobRunEvidence>,
    pub provider_errors: Vec<crate::model::ProviderErrorEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsEmrServerlessResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.verification_authority
            || self.outcome_authority
            || self.work_product_adopted
        {
            return Err(crate::error::AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        if let Some(evidence) = &self.evidence {
            evidence.validate_integrity()?;
        }
        Ok(())
    }
}

pub struct MissionAwsEmrServerlessConsumer {
    scope: AwsEmrServerlessJobResultScope,
    registration_digest: Digest,
    registration_revision: u64,
    active: bool,
    expected_mission_revision: Revision,
}

impl MissionAwsEmrServerlessConsumer {
    pub fn new(
        scope: AwsEmrServerlessJobResultScope,
        registration: &AwsEmrServerlessJobResultRegistration,
    ) -> std::result::Result<Self, ConsumerError> {
        Self::new_with_mission_revision(
            scope,
            registration,
            registration.scope().mission_revision(),
        )
    }

    pub fn new_with_mission_revision(
        scope: AwsEmrServerlessJobResultScope,
        registration: &AwsEmrServerlessJobResultRegistration,
        expected_mission_revision: Revision,
    ) -> std::result::Result<Self, ConsumerError> {
        if !registration.is_active() {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if registration.scope_digest() != scope.scope_digest()
            || expected_mission_revision != scope.mission_revision()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest().clone(),
            registration_revision: registration.registration_revision(),
            active: true,
            expected_mission_revision,
        })
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub fn scope(&self) -> &AwsEmrServerlessJobResultScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> std::result::Result<(), ConsumerError> {
        if !self.active {
            Err(ConsumerError::Revoked)
        } else {
            self.active = false;
            Ok(())
        }
    }

    pub fn consume(
        &self,
        proposal: AwsEmrServerlessJobResultProposal,
    ) -> std::result::Result<MissionAwsEmrServerlessResult, ConsumerError> {
        self.consume_at(proposal, self.expected_mission_revision)
    }

    pub fn consume_at(
        &self,
        proposal: AwsEmrServerlessJobResultProposal,
        current_mission_revision: Revision,
    ) -> std::result::Result<MissionAwsEmrServerlessResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if current_mission_revision != self.expected_mission_revision {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.registration_digest != self.registration_digest
            || proposal.registration_revision != self.registration_revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != *self.scope.scope_digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.service_id != SERVICE_ID || proposal.consumer_id != CONSUMER_ID {
            return Err(ConsumerError::InvalidProposal);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if let Some(evidence) = &proposal.evidence {
            if evidence.scope_digest != *self.scope.scope_digest()
                || evidence.project_digest != self.scope.project_digest()
                || evidence.mission_digest != self.scope.mission_digest()
                || evidence.work_product_digest != self.scope.work_product_digest()
                || evidence.mission_revision != self.scope.mission_revision()
                || evidence.work_product_revision != self.scope.work_product_revision()
                || evidence.attempt != self.scope.attempt()
                || evidence.execution_role_digest != *self.scope.execution_role_digest()
                || evidence.job_driver_digest != *self.scope.job_driver_digest()
            {
                return Err(ConsumerError::FenceMismatch);
            }
        }
        let disposition = proposal.status.into();
        let state = if matches!(disposition, MissionResultDisposition::EvidenceReady) {
            MissionResultState::PendingDecision
        } else {
            MissionResultState::Layer2AdoptionRequired
        };
        let result = MissionAwsEmrServerlessResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest,
            scope_digest: proposal.scope_digest,
            project_digest: self.scope.project_digest(),
            mission_digest: self.scope.mission_digest(),
            work_product_digest: self.scope.work_product_digest(),
            mission_revision: self.scope.mission_revision(),
            work_product_revision: self.scope.work_product_revision(),
            status: proposal.status,
            state,
            disposition,
            evidence: proposal.evidence,
            provider_errors: proposal.provider_errors,
            provenance: proposal.provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            verification_authority: false,
            outcome_authority: false,
            work_product_adopted: false,
        };
        result
            .validate_integrity()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        Ok(result)
    }
}

impl std::fmt::Debug for MissionAwsEmrServerlessConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAwsEmrServerlessConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .field("active", &self.active)
            .field("expected_mission_revision", &self.expected_mission_revision)
            .finish()
    }
}
