//! Mission-facing consumer for normalized Gong conversation evidence.

use std::fmt;

use thiserror::Error;

use crate::{
    Digest, GONG_CONVERSATION_RESULT_SERVICE_ID, GongConversationResultProjection,
    GongConversationResultProposal, GongConversationScope, GongProviderDefinition,
    GongResultEvidence, MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID,
    MissionGongConversationConsumerDefinition, PluginVersion, RegistrationReceipt,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Gong conversation consumer is revoked")]
    Revoked,
    #[error("Mission consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission consumer scope does not match the proposal")]
    ScopeMismatch,
    #[error("Mission consumer proposal digest or evidence fence is invalid")]
    InvalidProposal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionConversationState {
    PendingDecision,
    NeedsReconciliation,
    ConsentBlocked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGongConversationResult {
    pub mission_id: crate::MissionId,
    pub project_id: crate::ProjectId,
    pub mission_revision: crate::Revision,
    pub project_revision: crate::Revision,
    pub projection: GongConversationResultProjection,
    pub state: MissionConversationState,
    pub evidence: GongResultEvidence,
    pub proposal_digest: Digest,
    pub native: bool,
    pub connected: bool,
    pub outcome_authority: bool,
    pub deal_health: Option<bool>,
    pub customer_intent: Option<bool>,
}

pub struct MissionGongConversationConsumer {
    scope: GongConversationScope,
    registration_digest: Digest,
    registration_revision: u64,
    provider_digest: Digest,
    active: bool,
}

impl fmt::Debug for MissionGongConversationConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGongConversationConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .field("provider_digest", &self.provider_digest)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionGongConversationConsumer {
    pub fn new(
        scope: GongConversationScope,
        registration: &RegistrationReceipt,
    ) -> Result<Self, ConsumerError> {
        Self::from_registration(scope, registration)
    }

    pub fn new_with_provider(
        scope: GongConversationScope,
        registration: &RegistrationReceipt,
        provider: &GongProviderDefinition,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active()
            || registration.scope_digest != scope.digest()
            || registration.provider_digest != provider.provider_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provider_digest: provider.provider_digest(),
            active: true,
        })
    }

    /// Convenience constructor for callers that already possess the
    /// registration's provider digest but do not need to retain the provider.
    pub fn from_registration(
        scope: GongConversationScope,
        registration: &RegistrationReceipt,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active() || registration.scope_digest != scope.digest() {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            provider_digest: registration.provider_digest.clone(),
            active: true,
        })
    }

    #[must_use]
    pub fn definition(&self) -> MissionGongConversationConsumerDefinition {
        MissionGongConversationConsumerDefinition {
            id: MISSION_GONG_CONVERSATION_RESULT_CONSUMER_ID.to_owned(),
            service_id: GONG_CONVERSATION_RESULT_SERVICE_ID.to_owned(),
            version: PluginVersion::V1,
            kind: "mission_conversation_result_proposal".to_owned(),
            binding: vec![
                "account_id".to_owned(),
                "team_id".to_owned(),
                "user_ids".to_owned(),
                "call_id_and_revision".to_owned(),
                "meeting_id".to_owned(),
                "deal_id".to_owned(),
                "context_ids".to_owned(),
                "context_revision".to_owned(),
                "scorecard_ids".to_owned(),
                "scorecard_revision".to_owned(),
                "tracker_ids".to_owned(),
                "mission_id_and_revision".to_owned(),
                "project_id_and_revision".to_owned(),
                "consent_id_and_revision".to_owned(),
                "registration_digest".to_owned(),
                "source_result_digest".to_owned(),
            ],
        }
    }

    #[must_use]
    pub fn scope(&self) -> &GongConversationScope {
        &self.scope
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        self.active = false;
        Ok(())
    }

    pub fn consume(
        &self,
        proposal: GongConversationResultProposal,
    ) -> Result<MissionGongConversationResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if proposal.registration_digest != self.registration_digest
            || proposal.registration_revision != self.registration_revision
            || proposal.provider_digest != self.provider_digest
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.consent_digest != self.scope.consent.digest()
            || proposal.project != self.scope.project
            || proposal.mission != self.scope.mission
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        proposal
            .validate_for_consumer(
                &self.scope,
                &self.registration_digest,
                self.registration_revision,
                &self.provider_digest,
            )
            .map_err(|_| ConsumerError::InvalidProposal)?;
        let state = match proposal.projection {
            GongConversationResultProjection::Analyzed
            | GongConversationResultProjection::Processing => {
                MissionConversationState::PendingDecision
            }
            GongConversationResultProjection::ConsentBlocked => {
                MissionConversationState::ConsentBlocked
            }
            GongConversationResultProjection::Partial(_)
            | GongConversationResultProjection::RetentionGap
            | GongConversationResultProjection::AccessLost
            | GongConversationResultProjection::ProviderUnknown => {
                MissionConversationState::NeedsReconciliation
            }
        };
        Ok(MissionGongConversationResult {
            mission_id: self.scope.mission.id.clone(),
            project_id: self.scope.project.id.clone(),
            mission_revision: self.scope.mission.revision,
            project_revision: self.scope.project.revision,
            projection: proposal.projection,
            state,
            evidence: proposal.evidence,
            proposal_digest: proposal.proposal_digest,
            native: false,
            connected: false,
            outcome_authority: false,
            deal_health: None,
            customer_intent: None,
        })
    }
}
