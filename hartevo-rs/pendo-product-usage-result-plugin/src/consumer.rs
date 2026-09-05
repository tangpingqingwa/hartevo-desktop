use std::collections::BTreeSet;

use thiserror::Error;

use crate::{
    Digest, EvidenceState, PendoObservationReceipt, PendoProductUsageProposal,
    PendoProductUsageResultService, PendoProductUsageScope, PendoProductUsageServiceError,
    PendoUsageRequest, PendoVerification,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionPendoUsageResultState {
    Present,
    Partial,
    Stale,
    AccessLost,
    ProviderUnknown,
    RateLimited,
    Tampered,
    Revoked,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum MissionPendoUsageConsumerError {
    #[error("Mission/Product Usage scope mismatch")]
    ScopeMismatch,
    #[error("Pendo Layer-1 contract drifted")]
    ContractDrift,
    #[error("Pendo proposal is tampered")]
    Tampered,
    #[error("Pendo proposal was replayed")]
    Replay,
    #[error("Mission Pendo Usage consumer is revoked")]
    Revoked,
    #[error("Pendo service rejected the consumer operation: {0}")]
    Service(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionPendoUsageResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: MissionPendoUsageResultState,
    pub observation: PendoObservationReceipt,
    pub verification: PendoVerification,
    pub adopted_work_product: bool,
    pub outcome_authority: bool,
    pub causal_claim: bool,
}

#[derive(Debug)]
pub struct MissionPendoUsageConsumer {
    scope: PendoProductUsageScope,
    registration_digest: Option<Digest>,
    consumed: BTreeSet<Digest>,
    active: bool,
}

impl MissionPendoUsageConsumer {
    #[must_use]
    pub fn new(scope: PendoProductUsageScope) -> Self {
        Self {
            scope,
            registration_digest: None,
            consumed: BTreeSet::new(),
            active: true,
        }
    }

    #[must_use]
    pub fn new_bound(scope: PendoProductUsageScope, registration_digest: Digest) -> Self {
        Self {
            scope,
            registration_digest: Some(registration_digest),
            consumed: BTreeSet::new(),
            active: true,
        }
    }

    #[must_use]
    pub fn scope(&self) -> &PendoProductUsageScope {
        &self.scope
    }

    #[must_use]
    pub fn consumer_id(&self) -> &'static str {
        crate::PENDO_PRODUCT_USAGE_RESULT_CONSUMER_ID
    }

    #[must_use]
    pub fn contract_version(&self) -> &'static str {
        crate::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION
    }

    #[must_use]
    pub fn contract_digest(&self) -> Digest {
        crate::contract_digest()
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
        proposal: PendoProductUsageProposal,
    ) -> Result<MissionPendoUsageResult, MissionPendoUsageConsumerError> {
        self.ensure_active()?;
        if proposal.scope != self.scope
            || proposal.scope_digest != self.scope.digest()
            || proposal.contract_digest != crate::contract_digest()
            || proposal.provider_digest.is_empty()
            || proposal.registration_digest.is_empty()
            || proposal.evidence.provider_digest != proposal.provider_digest
            || proposal.evidence.contract_digest != proposal.contract_digest
            || proposal.contract_version != crate::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION
            || proposal.evidence.contract_version != proposal.contract_version
            || proposal.permission_digest != proposal.evidence.permission_digest
            || proposal.query_digest != proposal.evidence.query_digest
            || proposal.source_evidence_digest != proposal.evidence.evidence_digest
            || proposal.proposal_digest != proposal.digest()
            || !proposal.proposal_only
            || !proposal.read_only
            || !proposal.aggregate_only
            || proposal.connected
            || proposal.native_provider
            || proposal.first_party
            || proposal.external_writes
            || proposal.causal_claim
            || proposal.adopted_work_product
            || proposal.outcome_authority
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.evidence_digest != proposal.evidence.digest()
            || !proposal.evidence.is_bounded_non_native()
        {
            return Err(MissionPendoUsageConsumerError::Tampered);
        }
        if self
            .registration_digest
            .as_ref()
            .is_some_and(|digest| digest != &proposal.registration_digest)
        {
            return Err(MissionPendoUsageConsumerError::ScopeMismatch);
        }
        if self.consumed.contains(&proposal.proposal_digest) {
            return Err(MissionPendoUsageConsumerError::Replay);
        }
        let observation = proposal.observation_receipt();
        let verification = PendoVerification {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            contract_digest: crate::contract_digest(),
            verified: true,
            tamper_evident: true,
            independent_native_readback: false,
            native: false,
            connected: false,
        };
        self.registration_digest = Some(proposal.registration_digest.clone());
        self.consumed.insert(proposal.proposal_digest.clone());
        Ok(MissionPendoUsageResult {
            consumer_id: crate::PENDO_PRODUCT_USAGE_RESULT_CONSUMER_ID.to_owned(),
            contract_version: crate::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            scope_digest: self.scope.digest(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            state: result_state(proposal.evidence.state),
            observation,
            verification,
            adopted_work_product: false,
            outcome_authority: false,
            causal_claim: false,
        })
    }

    pub fn read<T: crate::PendoTransport>(
        &mut self,
        service: &mut PendoProductUsageResultService<T>,
        request: &PendoUsageRequest,
    ) -> Result<MissionPendoUsageResult, MissionPendoUsageConsumerError> {
        self.ensure_active()?;
        if service.scope().digest() != self.scope.digest() {
            return Err(MissionPendoUsageConsumerError::ScopeMismatch);
        }
        if self
            .registration_digest
            .as_ref()
            .is_some_and(|registration_digest| {
                registration_digest != service.registration().registration_digest()
            })
        {
            return Err(MissionPendoUsageConsumerError::ScopeMismatch);
        }
        let proposal = service.propose(request).map_err(map_service_error)?;
        self.consume(proposal)
    }

    pub fn verify<T: crate::PendoTransport>(
        &self,
        service: &PendoProductUsageResultService<T>,
        proposal: &PendoProductUsageProposal,
    ) -> Result<PendoVerification, MissionPendoUsageConsumerError> {
        if service.scope().digest() != self.scope.digest() {
            return Err(MissionPendoUsageConsumerError::ScopeMismatch);
        }
        service.verify_proposal(proposal).map_err(map_service_error)
    }

    pub fn revoke(&mut self) -> Result<(), MissionPendoUsageConsumerError> {
        self.ensure_active()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionPendoUsageConsumerError> {
        if self.active {
            return Err(MissionPendoUsageConsumerError::Service(
                "consumer is already active".to_owned(),
            ));
        }
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionPendoUsageConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionPendoUsageConsumerError::Revoked)
        }
    }
}

fn result_state(state: EvidenceState) -> MissionPendoUsageResultState {
    match state {
        EvidenceState::Present => MissionPendoUsageResultState::Present,
        EvidenceState::Partial => MissionPendoUsageResultState::Partial,
        EvidenceState::Stale => MissionPendoUsageResultState::Stale,
        EvidenceState::AccessLost => MissionPendoUsageResultState::AccessLost,
        EvidenceState::ProviderUnknown => MissionPendoUsageResultState::ProviderUnknown,
        EvidenceState::RateLimited => MissionPendoUsageResultState::RateLimited,
        EvidenceState::Tampered => MissionPendoUsageResultState::Tampered,
        EvidenceState::Revoked => MissionPendoUsageResultState::Revoked,
    }
}

fn map_service_error(error: PendoProductUsageServiceError) -> MissionPendoUsageConsumerError {
    match error {
        PendoProductUsageServiceError::RegistrationRevoked
        | PendoProductUsageServiceError::SecretRevoked => MissionPendoUsageConsumerError::Revoked,
        PendoProductUsageServiceError::RequestOutOfScope
        | PendoProductUsageServiceError::ConsentMismatch => {
            MissionPendoUsageConsumerError::ScopeMismatch
        }
        PendoProductUsageServiceError::EvidenceMismatch
        | PendoProductUsageServiceError::Tampered
        | PendoProductUsageServiceError::DefinitionDrift => {
            MissionPendoUsageConsumerError::Tampered
        }
        PendoProductUsageServiceError::Model(model) => {
            MissionPendoUsageConsumerError::Service(model.to_string())
        }
    }
}
