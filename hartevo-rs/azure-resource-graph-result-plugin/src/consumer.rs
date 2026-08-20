//! Mission-scoped consumer for bounded Azure Resource Graph inventory
//! evidence. It performs no mutation and never adopts kernel Outcome.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AZURE_RESOURCE_GRAPH_CONTRACT_VERSION, AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT,
    AzureResourceGraphError, AzureResourceGraphEvidence, AzureResourceGraphEvidenceState,
    AzureResourceGraphProposal, AzureResourceGraphProvider, AzureResourceGraphScope, Digest,
    MissionBinding, ProjectBinding, WorkProductBinding, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAzureResourceResultState {
    DecisionReady,
    NeedsMoreEvidence,
    AccessLost,
    RateLimited,
    ProviderUnavailable,
    BlockedEnv,
}

pub type MissionResultState = MissionAzureResourceResultState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct MissionAzureResourceResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: AzureResourceGraphEvidence,
    pub proposal_digest: Digest,
    pub state: MissionAzureResourceResultState,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub adopts_outcome: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionAzureResourceConsumerError {
    #[error("Mission Azure Resource Graph consumer is revoked")]
    Revoked,
    #[error("Mission Azure Resource Graph registration does not match")]
    RegistrationMismatch,
    #[error("Mission Azure Resource Graph proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Azure Resource Graph proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] AzureResourceGraphError),
}

pub struct MissionAzureResourceConsumer {
    scope: AzureResourceGraphScope,
    registration_digest: Option<Digest>,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl fmt::Debug for MissionAzureResourceConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAzureResourceConsumer")
            .field("scope_digest", self.scope.scope_digest())
            .field("registration_bound", &self.registration_digest.is_some())
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl MissionAzureResourceConsumer {
    #[must_use]
    pub fn new(scope: AzureResourceGraphScope) -> Self {
        Self {
            scope,
            registration_digest: None,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    pub fn from_registration(
        scope: AzureResourceGraphScope,
        registration_digest: Digest,
    ) -> Result<Self, MissionAzureResourceConsumerError> {
        scope
            .validate()
            .map_err(|error| MissionAzureResourceConsumerError::Service(error.into()))?;
        Ok(Self {
            scope,
            registration_digest: Some(registration_digest),
            active: true,
            consumed_proposals: BTreeSet::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &AzureResourceGraphScope {
        &self.scope
    }

    #[must_use]
    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn bind_registration(
        &mut self,
        registration_digest: Digest,
    ) -> Result<(), MissionAzureResourceConsumerError> {
        if let Some(existing) = &self.registration_digest {
            if existing != &registration_digest {
                return Err(MissionAzureResourceConsumerError::RegistrationMismatch);
            }
        } else {
            self.registration_digest = Some(registration_digest);
        }
        Ok(())
    }

    pub fn compile_proposal<T, R>(
        &mut self,
        provider: &mut AzureResourceGraphProvider<T, R>,
    ) -> Result<AzureResourceGraphProposal, MissionAzureResourceConsumerError>
    where
        T: crate::AzureResourceGraphTransport,
        R: crate::CredentialResolver,
    {
        self.ensure_active()?;
        self.bind_registration(provider.registration().registration_digest().clone())?;
        if provider.registration().scope() != &self.scope {
            return Err(MissionAzureResourceConsumerError::RegistrationMismatch);
        }
        Ok(provider.compile_proposal()?)
    }

    pub fn read<T, R>(
        &mut self,
        provider: &mut AzureResourceGraphProvider<T, R>,
    ) -> Result<MissionAzureResourceResult, MissionAzureResourceConsumerError>
    where
        T: crate::AzureResourceGraphTransport,
        R: crate::CredentialResolver,
    {
        let proposal = self.compile_proposal(provider)?;
        self.consume(&proposal)
    }

    pub fn consume(
        &mut self,
        proposal: &AzureResourceGraphProposal,
    ) -> Result<MissionAzureResourceResult, MissionAzureResourceConsumerError> {
        self.ensure_active()?;
        proposal
            .validate()
            .map_err(|error| MissionAzureResourceConsumerError::Service(error.into()))?;
        if proposal.scope != self.scope
            || proposal.contract_digest != contract_digest()
            || proposal.evidence.contract_version != AZURE_RESOURCE_GRAPH_CONTRACT_VERSION
            || proposal.evidence.plugin_version != AZURE_RESOURCE_GRAPH_PLUGIN_VERSION_TEXT
            || proposal.evidence.scope_digest != *self.scope.scope_digest()
            || proposal.query_digest != self.scope.query_digest()
            || proposal.permission_digest != self.scope.permission().digest()
        {
            return Err(MissionAzureResourceConsumerError::RegistrationMismatch);
        }
        self.bind_registration(proposal.registration_digest.clone())?;
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionAzureResourceConsumerError::ReplayDetected);
        }
        Ok(MissionAzureResourceResult {
            project: self.scope.project().clone(),
            mission: self.scope.mission().clone(),
            work_product: self.scope.work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: result_state(proposal.evidence.state),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
        })
    }

    pub fn revoke(&mut self) -> Result<(), MissionAzureResourceConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionAzureResourceConsumerError> {
        if self.active {
            Err(MissionAzureResourceConsumerError::InvalidProposal)
        } else {
            self.active = true;
            Ok(())
        }
    }

    fn ensure_active(&self) -> Result<(), MissionAzureResourceConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionAzureResourceConsumerError::Revoked)
        }
    }
}

fn result_state(state: AzureResourceGraphEvidenceState) -> MissionAzureResourceResultState {
    match state {
        AzureResourceGraphEvidenceState::Complete => MissionAzureResourceResultState::DecisionReady,
        AzureResourceGraphEvidenceState::Empty
        | AzureResourceGraphEvidenceState::Partial
        | AzureResourceGraphEvidenceState::Truncated => {
            MissionAzureResourceResultState::NeedsMoreEvidence
        }
        AzureResourceGraphEvidenceState::Forbidden
        | AzureResourceGraphEvidenceState::Unauthorized
        | AzureResourceGraphEvidenceState::NotFound => MissionAzureResourceResultState::AccessLost,
        AzureResourceGraphEvidenceState::RateLimited => {
            MissionAzureResourceResultState::RateLimited
        }
        AzureResourceGraphEvidenceState::BadRequest
        | AzureResourceGraphEvidenceState::Conflict
        | AzureResourceGraphEvidenceState::ProviderUnavailable
        | AzureResourceGraphEvidenceState::Timeout => {
            MissionAzureResourceResultState::ProviderUnavailable
        }
        AzureResourceGraphEvidenceState::BlockedEnv => MissionAzureResourceResultState::BlockedEnv,
    }
}
