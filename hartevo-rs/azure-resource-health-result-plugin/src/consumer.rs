//! Mission-scoped projection of Azure Resource Health proposals.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{AzureResourceHealthScope, Digest, EvidenceState};
use crate::provider::AzureResourceHealthTransport;
use crate::service::{
    AzureResourceHealthProposal, AzureResourceHealthService, AzureResourceHealthServiceError,
    AzureResourceHealthVerification,
};
use crate::{
    AZURE_RESOURCE_HEALTH_CONTRACT_VERSION, AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT,
    MISSION_AZURE_RESOURCE_HEALTH_CONSUMER_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAzureResourceHealthState {
    Complete,
    Empty,
    Partial,
    Unknown,
    AccessLost,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    ProviderUnknown,
    Expired,
    Revoked,
}

impl From<EvidenceState> for MissionAzureResourceHealthState {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Complete => Self::Complete,
            EvidenceState::Empty => Self::Empty,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::Unknown => Self::Unknown,
            EvidenceState::AccessLost => Self::AccessLost,
            EvidenceState::NotFound => Self::NotFound,
            EvidenceState::Conflict => Self::Conflict,
            EvidenceState::Throttled => Self::Throttled,
            EvidenceState::TimedOut => Self::TimedOut,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::Expired => Self::Expired,
            EvidenceState::Revoked => Self::Revoked,
        }
    }
}

pub type MissionResultState = MissionAzureResourceHealthState;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionAzureResourceHealthConsumerError {
    #[error("proposal does not match the Mission, Project, Work Product, or resource scope")]
    ScopeMismatch,
    #[error("proposal has already been consumed")]
    ReplayDetected,
    #[error("proposal or evidence digest verification failed")]
    Tampered,
    #[error("proposal contract, provider, or consumer identity drifted")]
    ContractDrift,
    #[error("service failed while producing a proposal: {0}")]
    Service(String),
}

pub type ConsumerError = MissionAzureResourceHealthConsumerError;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAzureResourceHealthResult {
    pub consumer_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub mission_id: String,
    pub mission_revision: crate::Revision,
    pub project_id: String,
    pub project_revision: crate::Revision,
    pub work_product_id: String,
    pub work_product_revision: crate::Revision,
    pub state: MissionAzureResourceHealthState,
    pub decision_ready: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub proposal: AzureResourceHealthProposal,
    pub verification: AzureResourceHealthVerification,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub causal_authority: bool,
    pub recovery_authority: bool,
    pub outcome_authority: bool,
    pub adopted_outcome: bool,
}

pub struct MissionAzureResourceHealthConsumer {
    scope: AzureResourceHealthScope,
    registration_digest: Option<Digest>,
    consumed: BTreeSet<Digest>,
}

impl std::fmt::Debug for MissionAzureResourceHealthConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionAzureResourceHealthConsumer")
            .field("scope_digest", self.scope.scope_digest())
            .field("registration_digest", &self.registration_digest)
            .field("consumed_count", &self.consumed.len())
            .finish()
    }
}

impl MissionAzureResourceHealthConsumer {
    #[must_use]
    pub fn new(scope: AzureResourceHealthScope) -> Self {
        Self {
            scope,
            registration_digest: None,
            consumed: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn new_bound(scope: AzureResourceHealthScope, registration_digest: Digest) -> Self {
        Self {
            scope,
            registration_digest: Some(registration_digest),
            consumed: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn scope(&self) -> &AzureResourceHealthScope {
        &self.scope
    }

    #[must_use]
    pub fn consumer_id(&self) -> &'static str {
        MISSION_AZURE_RESOURCE_HEALTH_CONSUMER_ID
    }

    #[must_use]
    pub fn contract_version(&self) -> &'static str {
        AZURE_RESOURCE_HEALTH_CONTRACT_VERSION
    }

    #[must_use]
    pub fn contract_digest(&self) -> Digest {
        contract_digest()
    }

    #[must_use]
    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    #[must_use]
    pub fn has_consumed(&self, proposal_digest: &Digest) -> bool {
        self.consumed.contains(proposal_digest)
    }

    pub fn consume(
        &mut self,
        proposal: AzureResourceHealthProposal,
    ) -> Result<MissionAzureResourceHealthResult, MissionAzureResourceHealthConsumerError> {
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.permission_digest != *self.scope.permission_digest()
            || proposal.tenant_digest != *self.scope.tenant_digest()
            || proposal.resource_digest != *self.scope.resource_digest()
            || proposal.resource_revision != self.scope.resource_revision()
            || proposal.event_window_digest != *self.scope.event_window().digest()
        {
            return Err(MissionAzureResourceHealthConsumerError::ScopeMismatch);
        }
        if self
            .registration_digest
            .as_ref()
            .is_some_and(|digest| digest != &proposal.registration_digest)
        {
            return Err(MissionAzureResourceHealthConsumerError::ScopeMismatch);
        }
        if proposal.plugin_version != AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT
            || proposal.contract_version != AZURE_RESOURCE_HEALTH_CONTRACT_VERSION
            || proposal.contract_digest != contract_digest()
            || proposal.provider_id != crate::AZURE_RESOURCE_HEALTH_PROVIDER_ID
            || !proposal.proposal_only
            || !proposal.read_only
            || proposal.native_provider
            || proposal.connected
            || proposal.external_write_performed
            || proposal.causal_authority
            || proposal.recovery_authority
            || proposal.outcome_authority
        {
            return Err(MissionAzureResourceHealthConsumerError::ContractDrift);
        }
        if self.consumed.contains(&proposal.proposal_digest) {
            return Err(MissionAzureResourceHealthConsumerError::ReplayDetected);
        }
        proposal
            .verify_integrity()
            .map_err(|_| MissionAzureResourceHealthConsumerError::Tampered)?;
        if self.registration_digest.is_none() {
            self.registration_digest = Some(proposal.registration_digest.clone());
        }
        let verification = proposal_verification(&proposal);
        self.consumed.insert(proposal.proposal_digest.clone());
        Ok(MissionAzureResourceHealthResult {
            consumer_id: MISSION_AZURE_RESOURCE_HEALTH_CONSUMER_ID.to_owned(),
            plugin_version: AZURE_RESOURCE_HEALTH_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AZURE_RESOURCE_HEALTH_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            scope_digest: self.scope.scope_digest().clone(),
            mission_id: self.scope.mission_id().to_owned(),
            mission_revision: self.scope.mission_revision(),
            project_id: self.scope.project_id().to_owned(),
            project_revision: self.scope.project_revision(),
            work_product_id: self.scope.work_product_id().to_owned(),
            work_product_revision: self.scope.work_product_revision(),
            state: proposal.state.into(),
            decision_ready: proposal.decision_ready,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            proposal,
            verification,
            proposal_only: true,
            native: false,
            connected: false,
            causal_authority: false,
            recovery_authority: false,
            outcome_authority: false,
            adopted_outcome: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: AzureResourceHealthProposal,
    ) -> Result<MissionAzureResourceHealthResult, MissionAzureResourceHealthConsumerError> {
        self.consume(proposal)
    }

    pub fn read<T: AzureResourceHealthTransport>(
        &mut self,
        service: &mut AzureResourceHealthService<T>,
    ) -> Result<MissionAzureResourceHealthResult, MissionAzureResourceHealthConsumerError> {
        if service.scope().scope_digest() != self.scope.scope_digest() {
            return Err(MissionAzureResourceHealthConsumerError::ScopeMismatch);
        }
        if let Some(registration_digest) = self.registration_digest.as_ref() {
            if registration_digest != &service.registration().registration_digest {
                return Err(MissionAzureResourceHealthConsumerError::ScopeMismatch);
            }
        } else {
            self.registration_digest = Some(service.registration().registration_digest.clone());
        }
        let proposal = service.propose().map_err(|error| match error {
            AzureResourceHealthServiceError::RegistrationRevoked
            | AzureResourceHealthServiceError::SecretRevoked
            | AzureResourceHealthServiceError::ScopeMismatch => {
                MissionAzureResourceHealthConsumerError::ScopeMismatch
            }
            AzureResourceHealthServiceError::DefinitionDrift => {
                MissionAzureResourceHealthConsumerError::ContractDrift
            }
            other => MissionAzureResourceHealthConsumerError::Service(other.to_string()),
        })?;
        self.consume(proposal)
    }
}

fn proposal_verification(
    proposal: &AzureResourceHealthProposal,
) -> AzureResourceHealthVerification {
    let mut verification = AzureResourceHealthVerification {
        verification_digest: Digest::from_text(b"azure-resource-health-verification-uninitialized"),
        proposal_digest: proposal.proposal_digest.clone(),
        evidence_digest: proposal.evidence_digest.clone(),
        verified: true,
        independent_native_readback: false,
        native: false,
        connected: false,
        causal_authority: false,
        outcome_authority: false,
    };
    verification.verification_digest = verification.digest();
    verification
}
