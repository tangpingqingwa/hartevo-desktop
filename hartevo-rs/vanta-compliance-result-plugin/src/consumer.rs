//! Mission-scoped Vanta proposal consumer.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ComplianceObjective, Digest, RegistrationState, VantaComplianceProjection,
    VantaComplianceResultProposal, VantaComplianceScope, VantaRegistration,
};
use crate::{MISSION_VANTA_CONSUMER_ID, VANTA_CONTRACT_VERSION, VANTA_PLUGIN_VERSION_TEXT};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VantaConsumerError {
    #[error("Mission Vanta consumer is revoked")]
    Revoked,
    #[error("Mission Vanta consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission Vanta consumer scope does not match the proposal")]
    ScopeMismatch,
    #[error("Mission Vanta consumer proposal is stale or tampered")]
    StaleProposal,
    #[error("Mission Vanta consumer received an invalid proposal")]
    InvalidProposal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionVantaDecisionState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionVantaComplianceResult {
    pub consumer_id: String,
    pub consumer_version: String,
    pub mission_id: crate::model::MissionId,
    pub project_id: crate::model::ProjectId,
    pub objective: ComplianceObjective,
    pub projection: VantaComplianceProjection,
    pub decision_state: MissionVantaDecisionState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub native: bool,
    pub connected: bool,
    pub certification_claim: bool,
    pub adopted_outcome: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionVantaComplianceConsumer {
    scope: VantaComplianceScope,
    registration: VantaRegistration,
    active: bool,
}

impl MissionVantaComplianceConsumer {
    pub fn new(
        scope: VantaComplianceScope,
        registration: &VantaRegistration,
    ) -> Result<Self, VantaConsumerError> {
        if !registration.is_active()
            || registration.scope_digest != scope.digest()
            || registration.audit_digest != scope.audit_digest()
            || registration.audit_revision != scope.audit.revision
            || registration.permission_digest != scope.permission_digest
            || registration.consent_digest != scope.consent.digest
            || registration.mission_revision != scope.mission.revision
            || registration.project_revision != scope.project.revision
            || registration.plugin_version != VANTA_PLUGIN_VERSION_TEXT
            || registration.contract_version != VANTA_CONTRACT_VERSION
            || registration
                .recompute_digest()
                .map_or(true, |digest| registration.registration_digest != digest)
        {
            return Err(VantaConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            active: true,
        })
    }

    pub fn scope(&self) -> &VantaComplianceScope {
        &self.scope
    }

    pub fn registration(&self) -> &VantaRegistration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), VantaConsumerError> {
        if !self.active {
            return Err(VantaConsumerError::Revoked);
        }
        self.active = false;
        self.registration.state = RegistrationState::Revoked;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: VantaComplianceResultProposal,
    ) -> Result<MissionVantaComplianceResult, VantaConsumerError> {
        if !self.active {
            return Err(VantaConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
        {
            return Err(VantaConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.audit_digest != self.scope.audit_digest()
            || proposal.objective != self.scope.objective
        {
            return Err(VantaConsumerError::ScopeMismatch);
        }
        proposal
            .validate(&self.scope, &self.registration)
            .map_err(|_| VantaConsumerError::StaleProposal)?;
        let decision_state = if matches!(
            proposal.projection.state,
            crate::model::VantaComplianceState::Complete
                | crate::model::VantaComplianceState::Open
                | crate::model::VantaComplianceState::Overdue
                | crate::model::VantaComplianceState::Blocked
        ) {
            MissionVantaDecisionState::PendingDecision
        } else {
            MissionVantaDecisionState::Layer2AdoptionRequired
        };
        Ok(MissionVantaComplianceResult {
            consumer_id: MISSION_VANTA_CONSUMER_ID.to_owned(),
            consumer_version: VANTA_PLUGIN_VERSION_TEXT.to_owned(),
            mission_id: self.scope.mission.id.clone(),
            project_id: self.scope.project.id.clone(),
            objective: self.scope.objective.clone(),
            projection: proposal.projection,
            decision_state,
            proposal_digest: proposal.proposal_digest,
            evidence_digest: proposal.evidence_digest,
            registration_digest: proposal.registration_digest,
            native: false,
            connected: false,
            certification_claim: false,
            adopted_outcome: false,
        })
    }
}

impl fmt::Display for MissionVantaComplianceConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MissionVantaComplianceConsumer(active={})",
            self.active
        )
    }
}

pub const MISSION_VANTA_CONSUMER_CONTRACT_VERSION: &str = VANTA_CONTRACT_VERSION;
