use std::collections::BTreeSet;

use thiserror::Error;

use crate::model::{Digest, MixpanelAnalyticsScope, ResultStatus};
use crate::provider::MixpanelProviderDefinition;
use crate::service::{MixpanelAnalyticsResultProposal, MixpanelAnalyticsResultReceipt};
use crate::{
    MIXPANEL_ANALYTICS_RESULT_CONSUMER_ID, MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION,
    contract_digest,
};

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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionMixpanelAnalyticsResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub mission_id: crate::model::MissionId,
    pub mission_revision: crate::model::Revision,
    pub work_product_id: crate::model::WorkProductId,
    pub work_product_revision: crate::model::Revision,
    pub state: MissionResultState,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub receipt: MixpanelAnalyticsResultReceipt,
    pub adopted_work_product: bool,
    pub outcome_authority: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
}

#[derive(Debug)]
pub struct MissionMixpanelAnalyticsConsumer {
    scope: MixpanelAnalyticsScope,
    registration_digest: Option<Digest>,
    consumed: BTreeSet<Digest>,
}

impl MissionMixpanelAnalyticsConsumer {
    pub fn new(scope: MixpanelAnalyticsScope) -> Self {
        Self {
            scope,
            registration_digest: None,
            consumed: BTreeSet::new(),
        }
    }

    pub fn new_bound(scope: MixpanelAnalyticsScope, registration_digest: Digest) -> Self {
        Self {
            scope,
            registration_digest: Some(registration_digest),
            consumed: BTreeSet::new(),
        }
    }

    pub fn scope(&self) -> &MixpanelAnalyticsScope {
        &self.scope
    }

    pub const fn consumer_id(&self) -> &'static str {
        MIXPANEL_ANALYTICS_RESULT_CONSUMER_ID
    }

    pub const fn contract_version(&self) -> &'static str {
        MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION
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
        proposal: MixpanelAnalyticsResultProposal,
    ) -> Result<MissionMixpanelAnalyticsResult, ConsumerError> {
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission_revision != self.scope.mission().revision()
            || proposal.work_product_revision != self.scope.work_product().revision()
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
        if proposal.contract_version != MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION
            || proposal.contract_digest != contract_digest()
            || proposal.outcome_authority
            || proposal.native_provider
            || proposal.connected
            || proposal.first_party
            || proposal.https_transport
            || !proposal.read_only
            || proposal.raw_events_included
            || proposal.user_pii_included
            || proposal.causal_claim
        {
            return Err(ConsumerError::ContractDrift);
        }
        if proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.status != proposal.status
            || proposal.evidence.provenance != proposal.provenance
            || !proposal.validate_integrity(&self.scope, &MixpanelProviderDefinition::new())
        {
            return Err(ConsumerError::Tampered);
        }
        if self.consumed.contains(&proposal.proposal_digest) {
            return Err(ConsumerError::Replay);
        }
        let receipt = proposal.receipt();
        self.consumed.insert(proposal.proposal_digest.clone());
        Ok(MissionMixpanelAnalyticsResult {
            consumer_id: MIXPANEL_ANALYTICS_RESULT_CONSUMER_ID.to_owned(),
            contract_version: MIXPANEL_ANALYTICS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            mission_id: self.scope.mission().mission_id().clone(),
            mission_revision: self.scope.mission().revision(),
            work_product_id: self.scope.work_product().work_product_id().clone(),
            work_product_revision: self.scope.work_product().revision(),
            state: proposal.status.into(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            receipt,
            adopted_work_product: false,
            outcome_authority: false,
            connected: false,
            native_provider: false,
            first_party: false,
        })
    }
}
