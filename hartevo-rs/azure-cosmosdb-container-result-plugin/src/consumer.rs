//! Mission-scoped consumer for Azure Cosmos DB container posture evidence.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{AzureCosmosEvidence, AzureCosmosScope, Digest, EvidenceState, ModelError};
use crate::service::{AzureCosmosContainerProposal, AzureCosmosRegistration, RegistrationState};
use crate::{
    AZURE_COSMOS_CONSUMER_ID, AZURE_COSMOS_CONTRACT_VERSION, AZURE_COSMOS_PLUGIN_VERSION,
    contract_digest,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission Azure Cosmos consumer model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("Mission Azure Cosmos consumer registration is invalid")]
    RegistrationMismatch,
    #[error("Mission Azure Cosmos evidence is stale or tampered")]
    StaleEvidence,
    #[error("Mission Azure Cosmos evidence is revoked")]
    Revoked,
    #[error("Mission Azure Cosmos evidence is a fail-closed provider state")]
    FailClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissionDecisionState {
    ReviewRequired,
    DegradedConfiguration,
    Partial,
    Absent,
    AccessLoss,
    RevisionDrift,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<EvidenceState> for MissionDecisionState {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Present => Self::ReviewRequired,
            EvidenceState::DegradedConfiguration => Self::DegradedConfiguration,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::NotFound => Self::Absent,
            EvidenceState::AccessLost => Self::AccessLoss,
            EvidenceState::RevisionDrift => Self::RevisionDrift,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::Tampered => Self::Tampered,
            EvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MissionAzureCosmosContainerObservation {
    pub consumer_id: String,
    pub consumer_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub decision_state: MissionDecisionState,
    pub read_only: bool,
    pub native_evidence: bool,
    pub connected: bool,
    pub first_party: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub outcome_authority: bool,
    pub adopted_work_product: bool,
    pub observation_digest: Digest,
}

impl MissionAzureCosmosContainerObservation {
    fn from_evidence(
        scope: &AzureCosmosScope,
        evidence: &AzureCosmosEvidence,
    ) -> Result<Self, ConsumerError> {
        let mut observation = Self {
            consumer_id: AZURE_COSMOS_CONSUMER_ID.to_owned(),
            consumer_version: AZURE_COSMOS_PLUGIN_VERSION.to_owned(),
            contract_version: AZURE_COSMOS_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            scope_digest: scope.digest(),
            evidence_digest: evidence.evidence_digest.clone(),
            decision_state: evidence.state.into(),
            read_only: true,
            native_evidence: false,
            connected: false,
            first_party: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            outcome_authority: false,
            adopted_work_product: false,
            observation_digest: Digest::zero(),
        };
        observation.observation_digest = crate::model::digest_serializable(&(
            &observation.consumer_id,
            &observation.consumer_version,
            &observation.contract_version,
            &observation.contract_digest,
            &observation.scope_digest,
            &observation.evidence_digest,
            observation.decision_state,
            observation.read_only,
            observation.native_evidence,
            observation.connected,
            observation.first_party,
            observation.truth_authority,
            observation.consent_authority,
            observation.effect_authority,
            observation.outcome_authority,
            observation.adopted_work_product,
        ))?;
        Ok(observation)
    }

    pub fn validate(
        &self,
        scope: &AzureCosmosScope,
        evidence: &AzureCosmosEvidence,
    ) -> Result<(), ConsumerError> {
        let expected = Self::from_evidence(scope, evidence)?;
        if self != &expected {
            return Err(ConsumerError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MissionAzureCosmosContainerResult {
    pub observation: MissionAzureCosmosContainerObservation,
    pub evidence: AzureCosmosEvidence,
    pub decision_state: MissionDecisionState,
    pub requires_human_review: bool,
    pub safe_to_promote: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub outcome_authority: bool,
    pub adopted_work_product: bool,
}

impl MissionAzureCosmosContainerResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate(&self, scope: &AzureCosmosScope) -> Result<(), ConsumerError> {
        self.evidence.validate()?;
        self.observation.validate(scope, &self.evidence)?;
        if self.decision_state != self.evidence.state.into()
            || !self.requires_human_review
            || self.safe_to_promote
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.outcome_authority
            || self.adopted_work_product
        {
            return Err(ConsumerError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAzureCosmosContainerConsumer {
    scope: AzureCosmosScope,
    registration: AzureCosmosRegistration,
}

impl MissionAzureCosmosContainerConsumer {
    pub fn new(
        scope: AzureCosmosScope,
        registration: AzureCosmosRegistration,
    ) -> Result<Self, ConsumerError> {
        scope.validate()?;
        if registration.scope_digest != scope.digest()
            || registration.state != RegistrationState::Active
            || registration.contract_digest != contract_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn scope(&self) -> &AzureCosmosScope {
        &self.scope
    }

    pub fn registration(&self) -> &AzureCosmosRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: &AzureCosmosContainerProposal,
    ) -> Result<MissionAzureCosmosContainerResult, ConsumerError> {
        if self.registration.state != RegistrationState::Active {
            return Err(ConsumerError::Revoked);
        }
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::StaleEvidence)?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.contract_digest != contract_digest()
            || proposal.evidence.scope_digest != self.scope.digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.evidence.state == EvidenceState::Revoked {
            return Err(ConsumerError::Revoked);
        }
        if proposal.evidence.state == EvidenceState::Tampered {
            return Err(ConsumerError::StaleEvidence);
        }
        let observation =
            MissionAzureCosmosContainerObservation::from_evidence(&self.scope, &proposal.evidence)?;
        let result = MissionAzureCosmosContainerResult {
            decision_state: proposal.evidence.state.into(),
            requires_human_review: true,
            safe_to_promote: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            outcome_authority: false,
            adopted_work_product: false,
            observation,
            evidence: proposal.evidence.clone(),
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn consume_evidence(
        &self,
        evidence: AzureCosmosEvidence,
        registration_digest: &Digest,
    ) -> Result<MissionAzureCosmosContainerResult, ConsumerError> {
        if registration_digest != &self.registration.registration_digest {
            return Err(ConsumerError::RegistrationMismatch);
        }
        let proposal =
            AzureCosmosContainerProposal::new(&self.registration, evidence, chrono::Utc::now())
                .map_err(|_| ConsumerError::StaleEvidence)?;
        self.consume(&proposal)
    }
}

pub type MissionAzureCosmosConsumer = MissionAzureCosmosContainerConsumer;
