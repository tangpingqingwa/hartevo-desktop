//! Mission-facing projection.  This module creates a canonical, non-mutating
//! proposal and never registers itself as kernel Truth/Consent/Effect/
//! Receipt/Verification/Outcome authority.

use std::fmt;

use serde::Serialize;

use crate::RampSpendOutcomeError;
use crate::model::{
    Digest, EvidenceVerification, MissionBinding, OutcomeProposal, ProjectBinding, SpendEvidence,
    WorkProductBinding, canonical_digest, validate_digest,
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
        project.validate("project id")?;
        mission.validate("mission id")?;
        work_product.validate("work product id")?;
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

    pub fn validate(&self) -> Result<(), RampSpendOutcomeError> {
        self.project.validate("project id")?;
        self.mission.validate("mission id")?;
        self.work_product.validate("work product id")?;
        Ok(())
    }

    pub fn compile_adoption_proposal(
        &self,
        proposal: &OutcomeProposal,
        evidence: &SpendEvidence,
        verification: &EvidenceVerification,
    ) -> Result<MissionRampSpendAdoptionProposal, RampSpendOutcomeError> {
        self.validate()?;
        proposal.validate()?;
        evidence.validate()?;
        verification.validate()?;
        if proposal.scope_digest != evidence.scope_digest
            || proposal.registration_digest != evidence.registration_digest
            || proposal.provider_digest != evidence.provider_digest
            || proposal.contract_digest != evidence.contract_digest
            || proposal.evidence_digest != evidence.evidence_digest
            || proposal.spend_constraints_digest != evidence.spend_constraints_digest
            || proposal.currency_code != evidence.currency_code
            || proposal.category_id_digests != evidence.category_id_digests
            || proposal.category_name_digests != evidence.category_name_digests
            || proposal.spend_total_minor != evidence.spend_total_minor
            || proposal.max_spend_total_minor != evidence.max_spend_total_minor
            || proposal.expected_spend_total_minor != evidence.expected_spend_total_minor
            || verification.evidence_digest != evidence.evidence_digest
            || verification.scope_digest != proposal.scope_digest
            || verification.provider_digest != proposal.provider_digest
            || verification.contract_digest != proposal.contract_digest
            || verification.evidence_status != crate::EvidenceStatus::Complete
            || !verification.independent_state_valid
            || !verification.verified
            || verification.adoptable
            || verification.native
            || verification.connected
        {
            return Err(RampSpendOutcomeError::EvidenceStateRequired);
        }
        if proposal.project != self.project
            || proposal.mission != self.mission
            || proposal.work_product != self.work_product
        {
            return Err(RampSpendOutcomeError::ConsumerBindingMismatch);
        }
        Ok(MissionRampSpendAdoptionProposal::from_parts(
            self,
            proposal,
            verification,
        ))
    }

    pub fn compile_adoption_proposal_from_evidence(
        &self,
        evidence: &SpendEvidence,
        service: &crate::RampSpendOutcomeService<impl crate::RampTransport>,
    ) -> Result<MissionRampSpendAdoptionProposal, RampSpendOutcomeError> {
        let outcome = service.compile_outcome_proposal(evidence)?;
        let receipt = service.record_evidence(evidence)?;
        let verification = service.verify_evidence(&receipt, evidence)?;
        self.compile_adoption_proposal(&outcome, evidence, &verification)
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
    pub source_verification_digest: Digest,
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
    fn from_parts(
        consumer: &MissionRampSpendConsumer,
        proposal: &OutcomeProposal,
        verification: &EvidenceVerification,
    ) -> Self {
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
            source_verification_digest: verification.verification_digest.clone(),
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
        self.project.validate("project id")?;
        self.mission.validate("mission id")?;
        self.work_product.validate("work product id")?;
        if self.policy_revision == 0 {
            return Err(RampSpendOutcomeError::ConsumerBindingMismatch);
        }
        for (field, digest) in [
            ("scope", &self.source_scope_digest),
            ("registration", &self.source_registration_digest),
            ("provider", &self.source_provider_digest),
            ("contract", &self.source_contract_digest),
            ("evidence", &self.source_evidence_digest),
            ("verification", &self.source_verification_digest),
        ] {
            validate_digest(digest, field)?;
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
            source_verification_digest: &self.source_verification_digest,
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
    source_verification_digest: &'a str,
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
