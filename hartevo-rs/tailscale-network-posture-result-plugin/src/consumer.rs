use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Digest, EvidenceState, TailscaleNetworkPostureScope};
use crate::service::{
    RecordDisposition, RegistrationState, TailscaleNetworkPostureProposal, TailscaleRegistration,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Tailscale proposal digest or evidence was tampered")]
    ProposalTampered,
    #[error("Tailscale proposal scope does not match this Mission consumer")]
    ScopeMismatch,
    #[error("Tailscale registration does not match this Mission consumer")]
    RegistrationMismatch,
    #[error("Tailscale proposal was replayed into this Mission consumer")]
    ReplayDetected,
    #[error("Tailscale recording key was reused for another proposal")]
    RecordingConflict,
    #[error("Tailscale proposal is not consumable")]
    InvalidProposal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionTailscaleNetworkDecisionState {
    ReviewRequired,
    Allowed,
    Denied,
    Expired,
    Unknown,
    Partial,
    RateLimited,
    ProviderUnknown,
    Tamper,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionTailscaleNetworkResult {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: EvidenceState,
    pub decision_state: MissionTailscaleNetworkDecisionState,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub review_only: bool,
    pub requires_human_review: bool,
    pub accepted_for_review: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub network_reachability_claim: bool,
    pub effective_authorization_claim: bool,
    pub access_certification_claim: bool,
    pub truth_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionTailscaleNetworkResult {
    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedTailscaleNetworkResult {
    pub proposal_digest: Digest,
    pub recording_key_digest: Digest,
    pub record_digest: Digest,
    pub disposition: RecordDisposition,
    pub durable: bool,
    pub provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub work_product_adopted: bool,
}

pub struct MissionTailscaleNetworkConsumer {
    scope: TailscaleNetworkPostureScope,
    registration: TailscaleRegistration,
    consumed: BTreeSet<Digest>,
    records: BTreeMap<Digest, RecordedTailscaleNetworkResult>,
}

impl std::fmt::Debug for MissionTailscaleNetworkConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionTailscaleNetworkConsumer")
            .field("scope", &self.scope)
            .field("registration", &self.registration)
            .field("consumed_count", &self.consumed.len())
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionTailscaleNetworkConsumer {
    pub fn new(
        scope: TailscaleNetworkPostureScope,
        registration: TailscaleRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate().map_err(|_| ConsumerError::ScopeMismatch)?;
        if registration.scope_digest != scope.digest()
            || registration.revision_fence_digest != scope.revision_fence_digest()
            || registration.device_digest != scope.device_digest()
            || registration.posture_digest != scope.posture_digest()
            || registration.policy_digest != scope.policy_digest()
            || registration.state == RegistrationState::Revoked
            || registration.connected
            || registration.native
            || registration.first_party
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration,
            consumed: BTreeSet::new(),
            records: BTreeMap::new(),
        })
    }

    pub fn new_bound(
        scope: TailscaleNetworkPostureScope,
        registration: TailscaleRegistration,
    ) -> Result<Self, ConsumerError> {
        Self::new(scope, registration)
    }

    #[must_use]
    pub fn scope(&self) -> &TailscaleNetworkPostureScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &TailscaleRegistration {
        &self.registration
    }

    pub fn verify_proposal(
        &self,
        proposal: &TailscaleNetworkPostureProposal,
    ) -> Result<(), ConsumerError> {
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.revision_fence_digest != self.scope.revision_fence_digest()
            || proposal.evidence.registration_digest != self.registration.registration_digest
            || proposal.request.validate(&self.scope).is_err()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if self.registration.state == RegistrationState::Revoked {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(())
    }

    pub fn consume(
        &mut self,
        proposal: TailscaleNetworkPostureProposal,
    ) -> Result<MissionTailscaleNetworkResult, ConsumerError> {
        self.verify_proposal(&proposal)?;
        if !self.consumed.insert(proposal.proposal_digest.clone()) {
            return Err(ConsumerError::ReplayDetected);
        }
        let decision_state = match proposal.state {
            EvidenceState::Allowed => MissionTailscaleNetworkDecisionState::ReviewRequired,
            EvidenceState::Denied => MissionTailscaleNetworkDecisionState::Denied,
            EvidenceState::Expired => MissionTailscaleNetworkDecisionState::Expired,
            EvidenceState::Unknown => MissionTailscaleNetworkDecisionState::Unknown,
            EvidenceState::Partial => MissionTailscaleNetworkDecisionState::Partial,
            EvidenceState::RateLimited => MissionTailscaleNetworkDecisionState::RateLimited,
            EvidenceState::ProviderUnknown => MissionTailscaleNetworkDecisionState::ProviderUnknown,
            EvidenceState::Tamper => MissionTailscaleNetworkDecisionState::Tamper,
            EvidenceState::AccessLoss => MissionTailscaleNetworkDecisionState::ProviderUnknown,
            EvidenceState::RegistrationRevoked => {
                MissionTailscaleNetworkDecisionState::ProviderUnknown
            }
        };
        Ok(MissionTailscaleNetworkResult {
            proposal_digest: proposal.proposal_digest,
            evidence_digest: proposal.evidence.evidence_digest,
            state: proposal.state,
            decision_state,
            project_digest: self.scope.project.digest(),
            mission_digest: self.scope.mission.digest(),
            work_product_digest: self.scope.work_product.digest(),
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            review_only: true,
            requires_human_review: true,
            accepted_for_review: true,
            connected: false,
            native: false,
            first_party: false,
            network_reachability_claim: false,
            effective_authorization_claim: false,
            access_certification_claim: false,
            truth_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &TailscaleNetworkPostureProposal,
        recording_key: impl AsRef<str>,
    ) -> Result<RecordedTailscaleNetworkResult, ConsumerError> {
        self.verify_proposal(proposal)?;
        let recording_key_digest = crate::domain_digest(
            "hartevo:tailscale-network-posture:mission-recording-key:v1",
            &recording_key.as_ref(),
        );
        if let Some(existing) = self.records.get(&recording_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.disposition = RecordDisposition::Replay;
            replay.record_digest = crate::domain_digest(
                "hartevo:tailscale-network-posture:mission-record:v1",
                &(
                    &replay.proposal_digest,
                    &replay.recording_key_digest,
                    replay.disposition,
                    replay.durable,
                    replay.provider_receipt,
                    replay.connected,
                    replay.native,
                    replay.first_party,
                    replay.work_product_adopted,
                ),
            );
            return Ok(replay);
        }
        let mut record = RecordedTailscaleNetworkResult {
            proposal_digest: proposal.proposal_digest.clone(),
            recording_key_digest: recording_key_digest.clone(),
            record_digest: String::new(),
            disposition: RecordDisposition::New,
            durable: false,
            provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            work_product_adopted: false,
        };
        record.record_digest = crate::domain_digest(
            "hartevo:tailscale-network-posture:mission-record:v1",
            &(
                &record.proposal_digest,
                &record.recording_key_digest,
                record.disposition,
                record.durable,
                record.provider_receipt,
                record.connected,
                record.native,
                record.first_party,
                record.work_product_adopted,
            ),
        );
        self.records.insert(recording_key_digest, record.clone());
        Ok(record)
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
}
