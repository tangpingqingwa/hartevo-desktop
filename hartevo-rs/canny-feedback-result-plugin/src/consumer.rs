use std::collections::BTreeSet;

use thiserror::Error;

use crate::model::{
    CannyFeedbackResultStatus, CannyFeedbackScope, Digest, MissionId, ProviderProvenance, Revision,
    WorkProductId,
};
use crate::provider::{CannyFeedbackTransport, CannyProviderDefinition};
use crate::service::{
    CannyFeedbackResultProposal, CannyFeedbackResultReceipt, CannyFeedbackResultService,
    CannyFeedbackResultServiceError, CannyFeedbackServiceDefinition,
};
use crate::{
    CANNY_FEEDBACK_RESULT_CONSUMER_ID, CANNY_FEEDBACK_RESULT_CONTRACT_VERSION, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionResultState {
    Open,
    Planned,
    Complete,
    Duplicate,
    Unknown,
    Partial,
    AccessLost,
    Denied,
    RateLimited,
    ProviderUnknown,
    Tampered,
}

impl From<CannyFeedbackResultStatus> for MissionResultState {
    fn from(status: CannyFeedbackResultStatus) -> Self {
        match status {
            CannyFeedbackResultStatus::Open => Self::Open,
            CannyFeedbackResultStatus::Planned => Self::Planned,
            CannyFeedbackResultStatus::Complete => Self::Complete,
            CannyFeedbackResultStatus::Duplicate => Self::Duplicate,
            CannyFeedbackResultStatus::Unknown => Self::Unknown,
            CannyFeedbackResultStatus::Partial => Self::Partial,
            CannyFeedbackResultStatus::AccessLost => Self::AccessLost,
            CannyFeedbackResultStatus::Denied => Self::Denied,
            CannyFeedbackResultStatus::RateLimited => Self::RateLimited,
            CannyFeedbackResultStatus::ProviderUnknown => Self::ProviderUnknown,
            CannyFeedbackResultStatus::Tampered => Self::Tampered,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
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
pub struct MissionCannyFeedbackResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub state: MissionResultState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub receipt: CannyFeedbackResultReceipt,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native_provider: bool,
    pub feedback_mutation: bool,
    pub voter_pii: bool,
    pub causal_demand_claim: bool,
    pub adopted_work_product: bool,
    pub outcome_authority: bool,
}

pub type MissionFeedbackResult = MissionCannyFeedbackResult;

#[derive(Debug)]
pub struct MissionCannyFeedbackConsumer {
    scope: CannyFeedbackScope,
    registration_digest: Option<Digest>,
    consumed: BTreeSet<Digest>,
}

pub type MissionFeedbackConsumer = MissionCannyFeedbackConsumer;

impl MissionCannyFeedbackConsumer {
    pub fn new(scope: CannyFeedbackScope) -> Self {
        Self {
            scope,
            registration_digest: None,
            consumed: BTreeSet::new(),
        }
    }

    pub fn new_bound(scope: CannyFeedbackScope, registration_digest: Digest) -> Self {
        Self {
            scope,
            registration_digest: Some(registration_digest),
            consumed: BTreeSet::new(),
        }
    }

    pub fn scope(&self) -> &CannyFeedbackScope {
        &self.scope
    }

    pub const fn consumer_id(&self) -> &'static str {
        CANNY_FEEDBACK_RESULT_CONSUMER_ID
    }

    pub const fn contract_version(&self) -> &'static str {
        CANNY_FEEDBACK_RESULT_CONTRACT_VERSION
    }

    pub fn contract_digest(&self) -> Digest {
        contract_digest()
    }

    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    pub fn has_consumed(&self, proposal_digest: &Digest) -> bool {
        self.consumed.contains(proposal_digest)
    }

    pub fn consume(
        &mut self,
        proposal: CannyFeedbackResultProposal,
    ) -> Result<MissionCannyFeedbackResult, ConsumerError> {
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_revision != self.scope.mission.revision
            || proposal.work_product_revision != self.scope.work_product.revision
            || proposal.request.validate_against(&self.scope).is_err()
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
        if proposal.contract_version != CANNY_FEEDBACK_RESULT_CONTRACT_VERSION
            || proposal.contract_digest != contract_digest()
            || !proposal.read_only
            || !proposal.proposal_only
            || proposal.connected
            || proposal.native_provider
            || proposal.first_party
            || proposal.https_transport
            || proposal.feedback_mutation
            || proposal.raw_api_body_included
            || proposal.comment_body_included
            || proposal.voter_pii_included
            || proposal.author_pii_included
            || proposal.causal_demand_claim
            || proposal.outcome_authority
            || proposal.adopted_work_product
        {
            return Err(ConsumerError::ContractDrift);
        }
        if proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.status != proposal.status
            || proposal.evidence.provenance != proposal.provenance
            || !proposal.validate_for_consumer(
                &self.scope,
                &CannyProviderDefinition::new(),
                &CannyFeedbackServiceDefinition::new(),
            )
        {
            return Err(ConsumerError::Tampered);
        }
        if self.consumed.contains(&proposal.proposal_digest) {
            return Err(ConsumerError::Replay);
        }
        let receipt = proposal.receipt();
        self.consumed.insert(proposal.proposal_digest.clone());
        if self.registration_digest.is_none() {
            self.registration_digest = Some(proposal.registration_digest.clone());
        }
        Ok(MissionCannyFeedbackResult {
            consumer_id: CANNY_FEEDBACK_RESULT_CONSUMER_ID.to_owned(),
            contract_version: CANNY_FEEDBACK_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            mission_id: self.scope.mission.id.clone(),
            mission_revision: self.scope.mission.revision,
            work_product_id: self.scope.work_product.id.clone(),
            work_product_revision: self.scope.work_product.revision,
            state: proposal.status.into(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            receipt,
            provenance: proposal.provenance,
            connected: false,
            native_provider: false,
            feedback_mutation: false,
            voter_pii: false,
            causal_demand_claim: false,
            adopted_work_product: false,
            outcome_authority: false,
        })
    }

    pub fn read<T>(
        &mut self,
        service: &mut CannyFeedbackResultService<T>,
        request: crate::CannyFeedbackResultRequest,
    ) -> Result<MissionCannyFeedbackResult, ConsumerError>
    where
        T: CannyFeedbackTransport,
    {
        if service.scope().digest() != self.scope.digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        if let Some(registration_digest) = self.registration_digest.as_ref() {
            if registration_digest != service.registration_digest() {
                return Err(ConsumerError::ScopeMismatch);
            }
        } else {
            self.registration_digest = Some(service.registration_digest().clone());
        }
        let proposal = service.read(request).map_err(|error| match error {
            CannyFeedbackResultServiceError::DefinitionDrift => ConsumerError::ProviderDrift,
            CannyFeedbackResultServiceError::RequestOutOfScope
            | CannyFeedbackResultServiceError::RegistrationRevoked
            | CannyFeedbackResultServiceError::SecretRevoked => ConsumerError::ScopeMismatch,
            other => ConsumerError::Service(other.to_string()),
        })?;
        self.consume(proposal)
    }
}
