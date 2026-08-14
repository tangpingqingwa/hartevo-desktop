//! Mission-facing projection.  This module creates a canonical, non-mutating
//! proposal and never registers itself as kernel Truth/Consent/Effect/
//! Receipt/Verification/Outcome authority.

use std::fmt;

use serde::Serialize;

use crate::RampSpendOutcomeError;
use crate::model::{
    Digest, MissionBinding, OutcomeProposal, ProjectBinding, SpendEvidence, WorkProductBinding,
    canonical_digest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionRampSpendConsumer {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
}

impl MissionRampSpendConsumer {
    pub fn new(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self, RampSpendOutcomeError> {
        if project.revision == 0 || mission.revision == 0 || work_product.revision == 0 {
            return Err(RampSpendOutcomeError::ConsumerBindingMismatch);
        }
        Ok(Self {
            project,
            mission,
            work_product,
        })
    }

    pub fn from_evidence_scope(
        scope: &crate::RampSpendScope,
    ) -> Result<Self, RampSpendOutcomeError> {
        Self::new(
            scope.project.clone(),
            scope.mission.clone(),
            scope.work_product.clone(),
        )
    }

    pub fn compile_adoption_proposal(
        &self,
        proposal: &OutcomeProposal,
    ) -> Result<MissionRampSpendAdoptionProposal, RampSpendOutcomeError> {
        proposal.validate()?;
        if proposal.project != self.project
            || proposal.mission != self.mission
            || proposal.work_product != self.work_product
        {
            return Err(RampSpendOutcomeError::ConsumerBindingMismatch);
        }
        Ok(MissionRampSpendAdoptionProposal::from_parts(self, proposal))
    }

    pub fn compile_adoption_proposal_from_evidence(
        &self,
        evidence: &SpendEvidence,
        service: &crate::RampSpendOutcomeService<impl crate::RampTransport>,
    ) -> Result<MissionRampSpendAdoptionProposal, RampSpendOutcomeError> {
        let outcome = service.compile_outcome_proposal(evidence)?;
        self.compile_adoption_proposal(&outcome)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionRampSpendAdoptionProposal {
    pub proposal_kind: String,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub source_scope_digest: Digest,
    pub source_registration_digest: Digest,
    pub source_provider_digest: Digest,
    pub source_contract_digest: Digest,
    pub source_evidence_digest: Digest,
    pub policy_revision: u64,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub native: bool,
    pub connected: bool,
    pub mutates_provider: bool,
    pub adoption_digest: Digest,
}

impl MissionRampSpendAdoptionProposal {
    fn from_parts(consumer: &MissionRampSpendConsumer, proposal: &OutcomeProposal) -> Self {
        let mut adoption = Self {
            proposal_kind: "mission_ramp_spend_evidence_adoption_proposal".to_owned(),
            project: consumer.project.clone(),
            mission: consumer.mission.clone(),
            work_product: consumer.work_product.clone(),
            source_scope_digest: proposal.scope_digest.clone(),
            source_registration_digest: proposal.registration_digest.clone(),
            source_provider_digest: proposal.provider_digest.clone(),
            source_contract_digest: proposal.contract_digest.clone(),
            source_evidence_digest: proposal.evidence_digest.clone(),
            policy_revision: proposal.policy_revision,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            native: false,
            connected: false,
            mutates_provider: false,
            adoption_digest: String::new(),
        };
        adoption.adoption_digest = adoption.computed_digest();
        adoption
    }

    pub fn validate(&self) -> Result<(), RampSpendOutcomeError> {
        if self.proposal_kind != "mission_ramp_spend_evidence_adoption_proposal"
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
            || self.native
            || self.connected
            || self.mutates_provider
            || self.adoption_digest != self.computed_digest()
        {
            return Err(RampSpendOutcomeError::ConsumerBindingMismatch);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Digest {
        canonical_digest(&AdoptionFingerprint {
            proposal_kind: &self.proposal_kind,
            project: &self.project,
            mission: &self.mission,
            work_product: &self.work_product,
            source_scope_digest: &self.source_scope_digest,
            source_registration_digest: &self.source_registration_digest,
            source_provider_digest: &self.source_provider_digest,
            source_contract_digest: &self.source_contract_digest,
            source_evidence_digest: &self.source_evidence_digest,
            policy_revision: self.policy_revision,
            truth_authority: self.truth_authority,
            consent_authority: self.consent_authority,
            effect_authority: self.effect_authority,
            receipt_authority: self.receipt_authority,
            verification_authority: self.verification_authority,
            outcome_authority: self.outcome_authority,
            native: self.native,
            connected: self.connected,
            mutates_provider: self.mutates_provider,
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdoptionFingerprint<'a> {
    proposal_kind: &'a str,
    project: &'a ProjectBinding,
    mission: &'a MissionBinding,
    work_product: &'a WorkProductBinding,
    source_scope_digest: &'a str,
    source_registration_digest: &'a str,
    source_provider_digest: &'a str,
    source_contract_digest: &'a str,
    source_evidence_digest: &'a str,
    policy_revision: u64,
    truth_authority: bool,
    consent_authority: bool,
    effect_authority: bool,
    receipt_authority: bool,
    verification_authority: bool,
    outcome_authority: bool,
    native: bool,
    connected: bool,
    mutates_provider: bool,
}

impl fmt::Display for MissionRampSpendAdoptionProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.adoption_digest)
    }
}
