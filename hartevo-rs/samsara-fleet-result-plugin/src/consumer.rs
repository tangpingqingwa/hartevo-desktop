use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    Layer1Authority, SAMSARA_FLEET_RESULT_CONSUMER_ID, SamsaraFleetResultServiceDefinition,
    model::{Digest, FleetProjection, RegistrationState, Revision, SamsaraFleetScope},
    service::{
        SamsaraAuthorityEvidence, SamsaraFleetResultEvidence, SamsaraFleetResultProposal,
        SamsaraRegistration,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Samsara fleet consumer is revoked")]
    Revoked,
    #[error("Mission consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission consumer scope or revision fence does not match")]
    ScopeMismatch,
    #[error("Mission consumer received a tampered or native proposal")]
    InvalidProposal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsumerRegistration {
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionSamsaraFleetResult {
    pub mission_id: String,
    pub mission_revision: Revision,
    pub project_id: String,
    pub project_revision: Revision,
    pub consent_id: String,
    pub consent_revision: Revision,
    pub projection: FleetProjection,
    pub state: MissionResultState,
    pub evidence: SamsaraFleetResultEvidence,
    pub proposal_digest: Digest,
    pub authority: SamsaraAuthorityEvidence,
    pub connected: bool,
    pub native: bool,
    pub adopted_outcome: bool,
}

pub struct MissionSamsaraFleetConsumer {
    scope: SamsaraFleetScope,
    registration: ConsumerRegistration,
    active: bool,
}

impl fmt::Debug for MissionSamsaraFleetConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionSamsaraFleetConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionSamsaraFleetConsumer {
    pub fn new(
        scope: SamsaraFleetScope,
        registration: &SamsaraRegistration,
    ) -> Result<Self, ConsumerError> {
        if registration.state != RegistrationState::Active
            || registration.scope_digest != *scope.scope_digest()
            || registration.consumer_id != SAMSARA_FLEET_RESULT_CONSUMER_ID
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                consumer_id: SAMSARA_FLEET_RESULT_CONSUMER_ID.to_owned(),
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

    pub fn scope(&self) -> &SamsaraFleetScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            Err(ConsumerError::Revoked)
        } else {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    pub fn consume(
        &self,
        proposal: SamsaraFleetResultProposal,
    ) -> Result<MissionSamsaraFleetResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if !proposal.validate_digest()
            || proposal.is_native()
            || proposal.is_connected()
            || proposal.is_adopted()
            || proposal.evidence.scope_digest != self.registration.scope_digest
            || proposal.evidence.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.mission_id != self.scope.mission().mission_id.as_str()
            || proposal.evidence.mission_revision != self.scope.mission().revision
            || proposal.evidence.project_id != self.scope.project().project_id.as_str()
            || proposal.evidence.project_revision != self.scope.project().revision
            || proposal.evidence.consent_id != self.scope.consent().consent_id.as_str()
            || proposal.evidence.consent_revision != self.scope.consent().revision
            || proposal.evidence.permission_digest != *self.scope.permission_digest()
            || !proposal
                .evidence
                .receipts
                .iter()
                .all(crate::ResponseReceipt::is_redacted)
            || proposal.evidence.authority != SamsaraAuthorityEvidence::default()
        {
            return Err(ConsumerError::InvalidProposal);
        }
        let state = match proposal.projection {
            FleetProjection::Operational | FleetProjection::Healthy => {
                MissionResultState::PendingDecision
            }
            FleetProjection::Degraded
            | FleetProjection::Offline
            | FleetProjection::SafetyAlert
            | FleetProjection::MaintenanceDue
            | FleetProjection::Partial
            | FleetProjection::RetentionGap
            | FleetProjection::AccessLost
            | FleetProjection::ProviderUnknown => MissionResultState::Layer2AdoptionRequired,
        };
        let evidence = proposal.evidence;
        Ok(MissionSamsaraFleetResult {
            mission_id: self.scope.mission().mission_id.as_str().to_owned(),
            mission_revision: self.scope.mission().revision,
            project_id: self.scope.project().project_id.as_str().to_owned(),
            project_revision: self.scope.project().revision,
            consent_id: self.scope.consent().consent_id.as_str().to_owned(),
            consent_revision: self.scope.consent().revision,
            projection: proposal.projection,
            state,
            evidence,
            proposal_digest: proposal.proposal_digest,
            authority: SamsaraAuthorityEvidence::default(),
            connected: Layer1Authority::connected(),
            native: Layer1Authority::native_provider(),
            adopted_outcome: Layer1Authority::adopted_outcome(),
        })
    }

    pub fn definition(&self) -> SamsaraFleetResultServiceDefinition {
        SamsaraFleetResultServiceDefinition::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConsentId, ConsentScope, MissionId, MissionScope, OrganizationId, ProjectId, ProjectScope,
        Revision, SamsaraFleetResultRequest, SamsaraFleetResultService, SecretReference,
        TimeWindow, provider::BlockedEnvTransport,
    };

    fn scope() -> SamsaraFleetScope {
        SamsaraFleetScope::minimal(
            OrganizationId::new("org-1").expect("organization"),
            MissionScope::new(
                MissionId::new("mission-1").expect("mission"),
                Revision::new(1).expect("revision"),
            ),
            ProjectScope::new(
                ProjectId::new("project-1").expect("project"),
                Revision::new(1).expect("revision"),
            ),
            ConsentScope::new(
                ConsentId::new("consent-1").expect("consent"),
                Revision::new(1).expect("revision"),
            ),
            crate::Digest::from_text("permission"),
            TimeWindow::new(100, 200).expect("window"),
        )
        .expect("scope")
    }

    #[test]
    fn mission_consumer_keeps_provider_unknown_outside_adoption() {
        let scope = scope();
        let secret =
            SecretReference::new("vault/samsara", scope.scope_digest(), 1).expect("secret");
        let mut service =
            SamsaraFleetResultService::new(scope.clone(), secret.clone(), BlockedEnvTransport)
                .expect("service");
        let request =
            SamsaraFleetResultRequest::new(&scope, scope.trips().window).expect("request");
        let proposal = service.propose(request).expect("proposal");
        let consumer =
            MissionSamsaraFleetConsumer::new(scope, service.registration()).expect("consumer");
        let result = consumer.consume(proposal).expect("consume");
        assert_eq!(result.state, MissionResultState::Layer2AdoptionRequired);
        assert!(!result.native);
        assert!(!result.connected);
        assert!(!result.adopted_outcome);
    }
}
