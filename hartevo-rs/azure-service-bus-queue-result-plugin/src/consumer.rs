//! Mission-scoped, non-authoritative Azure Service Bus posture consumer.

use std::collections::BTreeSet;

use serde::Serialize;
use thiserror::Error;

use crate::{
    CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID,
    contract_digest,
    model::{AzureServiceBusQueueEvidence, AzureServiceBusScope, Digest, QueuePostureState},
    service::{
        AzureServiceBusQueueResultProposal, AzureServiceBusQueueResultServiceError,
        AzureServiceBusRegistration, AzureServiceBusRegistrationState,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Azure Service Bus consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission Azure Service Bus consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission Azure Service Bus consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission Azure Service Bus consumer proposal was replayed")]
    Replay,
    #[error("Mission Azure Service Bus consumer could not validate service evidence: {0}")]
    Service(#[from] AzureServiceBusQueueResultServiceError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissionAzureServiceBusDecisionState {
    Active,
    Disabled,
    SendDisabled,
    ReceiveDisabled,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<QueuePostureState> for MissionAzureServiceBusDecisionState {
    fn from(state: QueuePostureState) -> Self {
        match state {
            QueuePostureState::Active => Self::Active,
            QueuePostureState::Disabled => Self::Disabled,
            QueuePostureState::SendDisabled => Self::SendDisabled,
            QueuePostureState::ReceiveDisabled => Self::ReceiveDisabled,
            QueuePostureState::Partial => Self::Partial,
            QueuePostureState::AccessLost => Self::AccessLost,
            QueuePostureState::ProviderUnknown => Self::ProviderUnknown,
            QueuePostureState::Tampered => Self::Tampered,
            QueuePostureState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAzureServiceBusResult {
    pub consumer_id: &'static str,
    pub decision_state: MissionAzureServiceBusDecisionState,
    pub observed_state: QueuePostureState,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal_digest: Digest,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub adopted_outcome: bool,
    pub queue_count_is_delivery_verification: bool,
    pub decision_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct MissionAzureServiceBusConsumer {
    scope: AzureServiceBusScope,
    registration: AzureServiceBusRegistration,
    consumed_proposals: BTreeSet<Digest>,
}

impl MissionAzureServiceBusConsumer {
    pub fn new(
        scope: AzureServiceBusScope,
        registration: AzureServiceBusRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate().map_err(|_| ConsumerError::ScopeMismatch)?;
        if registration.state != AzureServiceBusRegistrationState::Active
            || registration.plugin_version != PLUGIN_VERSION
            || registration.contract_version != CONTRACT_VERSION
            || registration.contract_digest != contract_digest()
            || registration.provider_id.as_str() != PROVIDER_ID
            || registration.provider_version != PLUGIN_VERSION
            || registration.provider_revision.as_str() != PROVIDER_API_REVISION
            || registration.scope_digest != scope.digest()
            || registration.permission_digest != *scope.permission_digest()
            || !valid_digest(&registration.provider_digest)
            || !valid_digest(&registration.api_digest)
            || !valid_digest(&registration.evidence_digest)
            || !valid_digest(&registration.secret_reference_digest)
            || !valid_digest(&registration.registration_digest)
            || registration.registration_digest != registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            consumed_proposals: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &AzureServiceBusScope {
        &self.scope
    }

    pub fn registration(&self) -> &AzureServiceBusRegistration {
        &self.registration
    }

    pub fn consume(
        &mut self,
        proposal: AzureServiceBusQueueResultProposal,
    ) -> Result<MissionAzureServiceBusResult, ConsumerError> {
        if self.registration.state != AzureServiceBusRegistrationState::Active {
            return Err(ConsumerError::RegistrationRevoked);
        }
        proposal
            .validate(&self.scope)
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.registration.permission_digest
            || proposal.state != proposal.evidence.state
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(ConsumerError::Replay);
        }
        let decision_state = MissionAzureServiceBusDecisionState::from(proposal.state);
        let decision_digest = Digest::from_fields(
            "hartevo-mission-azure-service-bus-decision/v1",
            &[
                ("scope", self.scope.digest().to_string()),
                (
                    "registration",
                    self.registration.registration_digest.to_string(),
                ),
                ("evidence", proposal.evidence.evidence_digest.to_string()),
                ("proposal", proposal.proposal_digest.to_string()),
                ("state", format!("{decision_state:?}")),
            ],
        );
        Ok(MissionAzureServiceBusResult {
            consumer_id: CONSUMER_ID,
            decision_state,
            observed_state: proposal.state,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest,
            proposal_digest: proposal.proposal_digest,
            requires_human_review: true,
            safe_to_promote: false,
            connected: false,
            native: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            adopted_outcome: false,
            queue_count_is_delivery_verification: false,
            decision_digest,
        })
    }

    pub fn verify_evidence(
        &self,
        evidence: &AzureServiceBusQueueEvidence,
    ) -> Result<(), ConsumerError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.permission_digest != self.registration.permission_digest
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        evidence
            .validate(&self.scope)
            .map_err(|_| ConsumerError::ProposalTampered)
    }
}

fn valid_digest(value: &Digest) -> bool {
    *value != Digest::zero() && Digest::parse(value.as_str().to_owned()).is_ok()
}

pub type MissionAzureServiceBusQueueResultConsumer = MissionAzureServiceBusConsumer;
pub type MissionAzureServiceBusQueueResult = MissionAzureServiceBusResult;
pub type MissionAzureServiceBusConsumerError = ConsumerError;
