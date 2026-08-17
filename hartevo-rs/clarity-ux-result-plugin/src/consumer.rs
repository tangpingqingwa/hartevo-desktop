//! Mission-scoped consumer for bounded Clarity aggregate UX evidence.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::model::{ClarityUxScope, Digest, ResultStatus};
use crate::provider::{ClarityProvider, ClarityProviderDefinition};
use crate::query::ClarityUxResultRequest;
use crate::service::{
    ClarityUxResultProposal, ClarityUxResultReceipt, ClarityUxResultService,
    ClarityUxResultServiceError,
};
use crate::{CLARITY_UX_RESULT_CONSUMER_ID, CLARITY_UX_RESULT_CONTRACT_VERSION, contract_digest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResultState {
    Complete,
    Partial,
    Empty,
    RateLimited,
    Expired,
    AccessLost,
    ProviderUnknown,
}

impl From<ResultStatus> for MissionResultState {
    fn from(status: ResultStatus) -> Self {
        match status {
            ResultStatus::Complete => Self::Complete,
            ResultStatus::Partial => Self::Partial,
            ResultStatus::Empty => Self::Empty,
            ResultStatus::RateLimited => Self::RateLimited,
            ResultStatus::Expired => Self::Expired,
            ResultStatus::AccessLost => Self::AccessLost,
            ResultStatus::ProviderUnknown => Self::ProviderUnknown,
        }
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("proposal does not match the Mission and Work Product scope")]
    ScopeMismatch,
    #[error("proposal has already been consumed")]
    Replay,
    #[error("proposal or evidence digest is invalid")]
    Tampered,
    #[error("proposal contract or consumer identity drifted")]
    ContractDrift,
    #[error("provider definition drifted")]
    ProviderDrift,
    #[error("service failed while producing a proposal: {0}")]
    Service(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionClarityUxResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub mission_id: crate::model::MissionId,
    pub mission_revision: crate::model::Revision,
    pub work_product_id: crate::model::WorkProductId,
    pub work_product_revision: crate::model::Revision,
    pub state: MissionResultState,
    pub proposal_digest: Digest,
    pub receipt: ClarityUxResultReceipt,
    pub proposal: ClarityUxResultProposal,
    pub adopted_work_product: bool,
    pub outcome_authority: bool,
}

#[derive(Debug)]
pub struct MissionClarityUxConsumer {
    scope: ClarityUxScope,
    registration_digest: Option<Digest>,
    consumed: BTreeSet<Digest>,
}

impl MissionClarityUxConsumer {
    pub fn new(scope: ClarityUxScope) -> Self {
        Self {
            scope,
            registration_digest: None,
            consumed: BTreeSet::new(),
        }
    }

    pub fn new_bound(scope: ClarityUxScope, registration_digest: Digest) -> Self {
        Self {
            scope,
            registration_digest: Some(registration_digest),
            consumed: BTreeSet::new(),
        }
    }

    pub fn scope(&self) -> &ClarityUxScope {
        &self.scope
    }

    pub fn consumer_id(&self) -> &'static str {
        CLARITY_UX_RESULT_CONSUMER_ID
    }

    pub fn contract_version(&self) -> &'static str {
        CLARITY_UX_RESULT_CONTRACT_VERSION
    }

    pub fn contract_digest(&self) -> Digest {
        contract_digest()
    }

    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    pub fn has_consumed(&self, proposal_digest: &Digest) -> bool {
        self.consumed.contains(proposal_digest)
    }

    pub fn consume(
        &mut self,
        proposal: ClarityUxResultProposal,
    ) -> Result<MissionClarityUxResult, ConsumerError> {
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_revision != self.scope.mission().revision()
            || proposal.work_product_revision != self.scope.work_product().revision()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if self
            .registration_digest
            .as_ref()
            .is_some_and(|digest| digest != &proposal.registration_digest)
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if proposal.contract_version != CLARITY_UX_RESULT_CONTRACT_VERSION
            || proposal.contract_digest != contract_digest()
            || proposal.outcome_authority
            || proposal.native_provider
            || proposal.connected
            || !proposal.read_only
        {
            return Err(ConsumerError::ContractDrift);
        }
        if proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.status != proposal.status
            || proposal.evidence.provenance != proposal.provenance
        {
            return Err(ConsumerError::Tampered);
        }
        if !proposal.validate_for_consumer(&self.scope, &ClarityProviderDefinition::new()) {
            return Err(ConsumerError::Tampered);
        }
        if self.consumed.contains(&proposal.proposal_digest) {
            return Err(ConsumerError::Replay);
        }
        let receipt = proposal.receipt();
        self.consumed.insert(proposal.proposal_digest.clone());
        Ok(MissionClarityUxResult {
            consumer_id: CLARITY_UX_RESULT_CONSUMER_ID.to_owned(),
            contract_version: CLARITY_UX_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            mission_id: self.scope.mission().mission_id().clone(),
            mission_revision: self.scope.mission().revision(),
            work_product_id: self.scope.work_product().work_product_id().clone(),
            work_product_revision: self.scope.work_product().revision(),
            state: proposal.status.into(),
            proposal_digest: proposal.proposal_digest.clone(),
            receipt,
            proposal,
            adopted_work_product: false,
            outcome_authority: false,
        })
    }

    pub fn read<P>(
        &mut self,
        service: &mut ClarityUxResultService<P>,
        request: &ClarityUxResultRequest,
    ) -> Result<MissionClarityUxResult, ConsumerError>
    where
        P: ClarityProvider,
    {
        if service.scope().digest() != self.scope.digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        if let Some(registration_digest) = self.registration_digest.as_ref() {
            if registration_digest != &service.registration().registration_digest {
                return Err(ConsumerError::ScopeMismatch);
            }
        } else {
            self.registration_digest = Some(service.registration().registration_digest.clone());
        }
        let proposal = service.propose(request).map_err(|error| match error {
            ClarityUxResultServiceError::DefinitionDrift => ConsumerError::ProviderDrift,
            ClarityUxResultServiceError::RequestOutOfScope
            | ClarityUxResultServiceError::RegistrationRevoked
            | ClarityUxResultServiceError::SecretRevoked => ConsumerError::ScopeMismatch,
            other => ConsumerError::Service(other.to_string()),
        })?;
        self.consume(proposal)
    }
}
