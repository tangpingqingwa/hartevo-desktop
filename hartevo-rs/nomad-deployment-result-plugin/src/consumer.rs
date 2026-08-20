use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{NomadDeploymentResultError, Result};
use crate::model::{
    Digest, NomadDeploymentEvidence, NomadDeploymentProposal, NomadDeploymentReceipt,
    NomadDeploymentScope, NomadDeploymentState, ProviderProvenance, RegistrationStatus,
};
use crate::service::NomadDeploymentRegistration;

/// Mission-facing review-only projection. It never adopts a Hartevo Outcome or
/// Work Product and never upgrades fixture/recording evidence to a receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionNomadDeploymentResult {
    pub service_id: String,
    pub consumer_id: String,
    pub scope: NomadDeploymentScope,
    pub proposal_digest: Digest,
    pub state: NomadDeploymentState,
    pub evidence: NomadDeploymentEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionNomadDeploymentResult {
    fn from_proposal(
        proposal: &NomadDeploymentProposal,
        scope: &NomadDeploymentScope,
    ) -> Result<Self> {
        let value = Self {
            service_id: crate::SERVICE_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            scope: scope.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            evidence: proposal.evidence.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        value.validate_integrity(proposal)
    }

    pub fn validate_integrity(&self, proposal: &NomadDeploymentProposal) -> Result<Self> {
        proposal.validate_integrity()?;
        if self.service_id != crate::SERVICE_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.scope != proposal.scope
            || self.proposal_digest != proposal.proposal_digest
            || self.state != proposal.state
            || self.evidence != proposal.evidence
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
        {
            return Err(NomadDeploymentResultError::TamperedEvidence);
        }
        Ok(self.clone())
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// Consumer scoped to one exact Nomad registration and Mission fence.
pub struct MissionNomadDeploymentConsumer {
    scope: NomadDeploymentScope,
    registration: NomadDeploymentRegistration,
    records: BTreeMap<Digest, Digest>,
}

impl fmt::Debug for MissionNomadDeploymentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionNomadDeploymentConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionNomadDeploymentConsumer {
    pub fn new(
        scope: NomadDeploymentScope,
        registration: NomadDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(NomadDeploymentResultError::RegistrationInactive);
        }
        if registration.scope().digest() != scope.digest() {
            return Err(NomadDeploymentResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &NomadDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut NomadDeploymentRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &NomadDeploymentScope {
        &self.scope
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke_registration(&mut self) -> Result<crate::RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<crate::RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn reverse_registration(&mut self) -> Result<crate::RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn consume(
        &self,
        proposal: &NomadDeploymentProposal,
    ) -> Result<MissionNomadDeploymentResult> {
        self.registration.validate()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope.digest() != self.scope.digest()
            || proposal.registration_revision != self.registration.registration_revision()
            || proposal.scope.project != self.scope.project
            || proposal.scope.mission != self.scope.mission
            || proposal.scope.work_product != self.scope.work_product
        {
            return Err(NomadDeploymentResultError::InvalidProposal);
        }
        MissionNomadDeploymentResult::from_proposal(proposal, &self.scope)
    }

    pub fn project(
        &self,
        proposal: &NomadDeploymentProposal,
    ) -> Result<MissionNomadDeploymentResult> {
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &NomadDeploymentProposal,
        idempotency_key: impl AsRef<str>,
        recorded_at: u64,
    ) -> Result<NomadDeploymentReceipt> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::model::MAX_IDENTIFIER_BYTES * 4 {
            return Err(NomadDeploymentResultError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        let replayed = match self.records.get(&key_digest) {
            Some(existing) if existing == &proposal.proposal_digest => true,
            Some(_) => return Err(NomadDeploymentResultError::RecordingConflict),
            None => false,
        };
        self.records
            .entry(key_digest.clone())
            .or_insert_with(|| proposal.proposal_digest.clone());
        let result = NomadDeploymentReceipt::new(proposal, key_digest, recorded_at, replayed);
        result.validate_integrity()?;
        Ok(result)
    }

    #[must_use]
    pub fn status(&self) -> RegistrationStatus {
        self.registration.status()
    }

    #[must_use]
    pub fn provenance(&self, evidence: &NomadDeploymentEvidence) -> ProviderProvenance {
        evidence.provenance
    }
}
