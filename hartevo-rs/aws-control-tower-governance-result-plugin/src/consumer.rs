//! Mission boundary for consuming Control Tower evidence.
//!
//! A consumer can bind evidence to a Project/Mission/Work Product and ask
//! for a review decision.  It cannot adopt a kernel Outcome, authorize an
//! effect, or assert that a deployment is compliant or successful.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::{
    CONSUMER_ID,
    model::{AwsControlTowerScope, Digest, EvidenceStatus, MissionBinding, ReadOperation},
    service::{
        AwsControlTowerGovernanceEvidence, AwsControlTowerGovernanceProposal,
        AwsControlTowerRecordReceipt, AwsControlTowerRegistration, AwsControlTowerServiceError,
        RegistrationStatus,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration does not match the Mission scope")]
    RegistrationMismatch,
    #[error("proposal or evidence was tampered")]
    TamperedEvidence,
    #[error("proposal belongs to a stale Mission")]
    StaleMission,
    #[error("proposal is outside the exact scope")]
    ScopeMismatch,
    #[error("permission binding was lost")]
    PermissionLoss,
    #[error("evidence is not eligible for review")]
    NotReviewEligible,
    #[error(transparent)]
    Service(#[from] AwsControlTowerServiceError),
}

impl ConsumerError {
    pub(crate) fn into_service_error(self) -> AwsControlTowerServiceError {
        match self {
            Self::Service(error) => error,
            Self::RegistrationRevoked => AwsControlTowerServiceError::RegistrationRevoked,
            Self::RegistrationReversed => AwsControlTowerServiceError::RegistrationReversed,
            Self::RegistrationMismatch => AwsControlTowerServiceError::RegistrationMismatch,
            Self::TamperedEvidence => AwsControlTowerServiceError::TamperedEvidence,
            Self::StaleMission | Self::ScopeMismatch => AwsControlTowerServiceError::OutOfScope,
            Self::PermissionLoss => AwsControlTowerServiceError::PermissionLoss,
            Self::NotReviewEligible => AwsControlTowerServiceError::IncompleteRecord,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsControlTowerDecisionState {
    Review,
    Blocked,
    Unknown,
}

impl MissionAwsControlTowerDecisionState {
    pub const fn from_evidence(state: EvidenceStatus) -> Self {
        match state {
            EvidenceStatus::Complete | EvidenceStatus::Partial => Self::Review,
            EvidenceStatus::BlockedEnv
            | EvidenceStatus::ProviderUnknown
            | EvidenceStatus::AccessLoss
            | EvidenceStatus::NotFound
            | EvidenceStatus::Conflict
            | EvidenceStatus::Throttled
            | EvidenceStatus::RetentionExpired
            | EvidenceStatus::ScopeDrift
            | EvidenceStatus::RegionMismatch
            | EvidenceStatus::PaginationIncomplete => Self::Blocked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsControlTowerResult {
    pub consumer_id: &'static str,
    pub operation: ReadOperation,
    pub decision_state: MissionAwsControlTowerDecisionState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub adopted_outcome: bool,
    pub adopted_work_product: bool,
    pub truth_authority: bool,
    pub compliance_claim: bool,
    pub deployment_success_claim: bool,
    pub decision_digest: Digest,
}

pub type MissionAwsControlTowerDecision = MissionAwsControlTowerResult;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedMissionAwsControlTower {
    pub recorded: bool,
    pub replayed: bool,
    pub recorded_at: DateTime<Utc>,
    pub recording_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub durable_receipt: bool,
    pub connected: bool,
    pub native: bool,
}

pub type RecordedAwsControlTowerResult = RecordedMissionAwsControlTower;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAwsControlTowerConsumer {
    scope: AwsControlTowerScope,
    registration: AwsControlTowerRegistration,
    mission: MissionBinding,
    recordings: BTreeMap<String, Digest>,
}

impl MissionAwsControlTowerConsumer {
    pub fn new(
        scope: AwsControlTowerScope,
        registration: AwsControlTowerRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.verify().map_err(AwsControlTowerServiceError::from)?;
        registration.validate()?;
        if registration.scope_digest != scope.scope_digest {
            return Err(ConsumerError::RegistrationMismatch);
        }
        match registration.status {
            RegistrationStatus::Active => {}
            RegistrationStatus::Revoked => return Err(ConsumerError::RegistrationRevoked),
            RegistrationStatus::Reversed => return Err(ConsumerError::RegistrationReversed),
        }
        Ok(Self {
            mission: scope.mission.clone(),
            scope,
            registration,
            recordings: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsControlTowerScope {
        &self.scope
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn registration(&self) -> &AwsControlTowerRegistration {
        &self.registration
    }

    pub fn bind_registration(
        &mut self,
        registration: AwsControlTowerRegistration,
    ) -> Result<(), ConsumerError> {
        registration.validate()?;
        if registration.scope_digest != self.scope.scope_digest {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if !registration.is_active() {
            return Err(
                if matches!(registration.status, RegistrationStatus::Reversed) {
                    ConsumerError::RegistrationReversed
                } else {
                    ConsumerError::RegistrationRevoked
                },
            );
        }
        self.registration = registration;
        Ok(())
    }

    pub fn replace_mission(&mut self, mission: MissionBinding) {
        self.mission = mission;
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: &AwsControlTowerGovernanceProposal,
    ) -> Result<MissionAwsControlTowerResult, ConsumerError> {
        self.verify_proposal(proposal)?;
        let decision_state = MissionAwsControlTowerDecisionState::from_evidence(proposal.state);
        let decision_digest = Digest::from_parts(
            "aws-control-tower-mission-decision/v1",
            &[
                self.scope.scope_digest.to_string(),
                self.registration.digest().to_string(),
                self.mission.digest().to_string(),
                proposal.evidence.evidence_digest().to_string(),
                proposal.proposal_digest.to_string(),
                format!("{decision_state:?}"),
            ],
        );
        Ok(MissionAwsControlTowerResult {
            consumer_id: CONSUMER_ID,
            operation: proposal.operation.clone(),
            decision_state,
            scope_digest: self.scope.scope_digest.clone(),
            registration_digest: self.registration.digest(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            adopted_outcome: false,
            adopted_work_product: false,
            truth_authority: false,
            compliance_claim: false,
            deployment_success_claim: false,
            decision_digest,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AwsControlTowerGovernanceProposal,
    ) -> Result<(), ConsumerError> {
        if !self.registration.is_active() {
            return Err(
                if matches!(self.registration.status, RegistrationStatus::Reversed) {
                    ConsumerError::RegistrationReversed
                } else {
                    ConsumerError::RegistrationRevoked
                },
            );
        }
        proposal
            .verify_integrity()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if proposal.registration_digest != self.registration.digest()
            || proposal.scope_digest != self.scope.scope_digest
            || proposal.evidence.digests.scope_digest != self.scope.scope_digest
            || proposal.evidence.account_digest != self.scope.account_id.digest()
            || proposal.evidence.home_region_digest != self.scope.home_region.digest()
            || proposal.evidence.landing_zone_digest != self.scope.landing_zone.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.mission != self.mission {
            return Err(ConsumerError::StaleMission);
        }
        if proposal.evidence.digests.permission_digest != self.scope.permission.permission_digest {
            return Err(ConsumerError::PermissionLoss);
        }
        Ok(())
    }

    pub fn verify_evidence(
        &self,
        evidence: &AwsControlTowerGovernanceEvidence,
    ) -> Result<(), ConsumerError> {
        evidence
            .verify_integrity()
            .map_err(|_| ConsumerError::TamperedEvidence)?;
        if evidence.digests.scope_digest != self.scope.scope_digest
            || evidence.account_digest != self.scope.account_id.digest()
            || evidence.home_region_digest != self.scope.home_region.digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn record_at(
        &mut self,
        proposal: &AwsControlTowerGovernanceProposal,
        recording_key: &str,
        recorded_at: DateTime<Utc>,
    ) -> Result<RecordedMissionAwsControlTower, ConsumerError> {
        self.verify_proposal(proposal)?;
        if recording_key.trim().is_empty() || recording_key.chars().any(char::is_control) {
            return Err(ConsumerError::ScopeMismatch);
        }
        let key_digest = Digest::from_text(recording_key);
        let key = key_digest.to_string();
        let replayed = self.recordings.contains_key(&key);
        if self
            .recordings
            .get(&key)
            .is_some_and(|digest| digest != &proposal.proposal_digest)
        {
            return Err(ConsumerError::TamperedEvidence);
        }
        self.recordings
            .insert(key, proposal.proposal_digest.clone());
        let receipt_digest = Digest::from_parts(
            "aws-control-tower-mission-record/v1",
            &[
                replayed.to_string(),
                recorded_at.to_rfc3339(),
                key_digest.to_string(),
                proposal.proposal_digest.to_string(),
                proposal.evidence.evidence_digest().to_string(),
            ],
        );
        Ok(RecordedMissionAwsControlTower {
            recorded: true,
            replayed,
            recorded_at,
            recording_key_digest: key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest().clone(),
            receipt_digest,
            durable_receipt: false,
            connected: false,
            native: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &AwsControlTowerGovernanceProposal,
    ) -> Result<RecordedMissionAwsControlTower, ConsumerError> {
        self.record_at(proposal, "aws-control-tower-mission-record", Utc::now())
    }

    pub fn record_count(&self) -> usize {
        self.recordings.len()
    }
}

impl From<AwsControlTowerRecordReceipt> for RecordedMissionAwsControlTower {
    fn from(value: AwsControlTowerRecordReceipt) -> Self {
        Self {
            recorded: value.recorded,
            replayed: value.replayed,
            recorded_at: value.recorded_at,
            recording_key_digest: value.recording_key_digest,
            proposal_digest: value.proposal_digest,
            evidence_digest: value.evidence_digest,
            receipt_digest: value.receipt_digest,
            durable_receipt: value.durable_receipt,
            connected: value.connected,
            native: value.native,
        }
    }
}
