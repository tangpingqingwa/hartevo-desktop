use std::collections::BTreeMap;

use crate::{
    CONTRACT_VERSION, contract_digest,
    error::{FastlyServiceResultError, Result},
    model::{
        Digest, FastlyMissionServiceResult, FastlyObservationReceipt, FastlyServiceResultProposal,
        FastlyServiceResultScope, FastlyServiceResultState,
    },
    provider::FastlyServiceResultRegistration,
};

#[derive(Clone, Debug)]
pub struct MissionFastlyServiceConsumer {
    scope: FastlyServiceResultScope,
    registration: FastlyServiceResultRegistration,
    recorded: BTreeMap<Digest, Digest>,
}

impl MissionFastlyServiceConsumer {
    pub fn new(
        scope: FastlyServiceResultScope,
        registration: FastlyServiceResultRegistration,
    ) -> Result<Self> {
        if registration.scope_digest() != &scope.digest()
            || registration.contract_digest() != &contract_digest()
            || registration.contract_version() != CONTRACT_VERSION
        {
            return Err(FastlyServiceResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            recorded: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &FastlyServiceResultScope {
        &self.scope
    }

    #[must_use]
    pub fn registration(&self) -> &FastlyServiceResultRegistration {
        &self.registration
    }

    pub fn consume(
        &self,
        proposal: &FastlyServiceResultProposal,
    ) -> Result<FastlyMissionServiceResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(FastlyServiceResultError::RegistrationRevoked);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.contract_digest != contract_digest()
            || proposal.mission_revision != self.scope.mission().revision()
            || proposal.work_product_revision != self.scope.work_product().revision()
        {
            return Err(FastlyServiceResultError::StaleRevision);
        }
        Ok(FastlyMissionServiceResult {
            scope_digest: proposal.scope_digest.clone(),
            mission_digest: self.scope.mission().digest(),
            evidence_digest: proposal.evidence_digest.clone(),
            state: proposal.state,
            review_only: true,
            verified: true,
            can_adopt_work_product: false,
            kernel_authority: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &FastlyServiceResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<FastlyObservationReceipt> {
        let result = self.consume(proposal)?;
        let idempotency_digest = Digest::from_text(idempotency_key.as_ref());
        let replayed = match self.recorded.get(&idempotency_digest) {
            Some(previous) if previous == &result.evidence_digest => true,
            Some(_) => return Err(FastlyServiceResultError::Replay),
            None => {
                self.recorded
                    .insert(idempotency_digest.clone(), result.evidence_digest.clone());
                false
            }
        };
        let receipt_digest = Digest::from_parts(
            "fastly-observation-receipt/v1",
            &[
                ("idempotency", idempotency_digest.to_string()),
                ("evidence", result.evidence_digest.to_string()),
                ("proposal", proposal.proposal_digest.to_string()),
                ("replayed", replayed.to_string()),
                ("recorded", (!replayed).to_string()),
            ],
        );
        Ok(FastlyObservationReceipt {
            idempotency_digest,
            evidence_digest: result.evidence_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            replayed,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
            kernel_authority: false,
            recorded: !replayed,
            receipt_digest,
        })
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.recorded.len()
    }

    #[must_use]
    pub fn can_adopt_work_product(&self, state: FastlyServiceResultState) -> bool {
        let _ = state;
        false
    }
}

pub type FastlyServiceConsumer = MissionFastlyServiceConsumer;
pub type MissionFastlyConsumer = MissionFastlyServiceConsumer;
