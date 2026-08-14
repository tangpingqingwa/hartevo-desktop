//! Mission-scoped non-adoptable NinjaOne result consumer.

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::model::{
    Digest, NinjaOneDeviceResultEvidence, NinjaOneDeviceResultProposal, NinjaOneDeviceState,
    NinjaOneError, NinjaOneScope, Revision,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionNinjaOneDeviceObservation {
    pub mission_id: crate::MissionId,
    pub project_id: crate::ProjectId,
    pub consent_id: crate::ConsentId,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub consent_revision: Revision,
    pub scope_digest: Digest,
    pub result_state: NinjaOneDeviceState,
    pub states: Vec<NinjaOneDeviceState>,
    pub partial: bool,
    pub non_adoptable: bool,
    pub work_product_adopted: bool,
    pub outcome_adopted: bool,
    pub kernel_authority: bool,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionNinjaOneDeviceResult {
    pub observation: MissionNinjaOneDeviceObservation,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recording_only: bool,
}

/// Consumer bound to the exact Mission/Project/Consent and provider scope.
#[derive(Clone, Debug)]
pub struct MissionNinjaOneDeviceConsumer {
    scope: NinjaOneScope,
}

impl MissionNinjaOneDeviceConsumer {
    pub fn new(scope: NinjaOneScope) -> Self {
        Self { scope }
    }

    pub fn from_scope(scope: &NinjaOneScope) -> Self {
        Self::new(scope.clone())
    }

    pub fn scope(&self) -> &NinjaOneScope {
        &self.scope
    }

    pub fn consume(
        &self,
        proposal: NinjaOneDeviceResultProposal,
        evidence: NinjaOneDeviceResultEvidence,
    ) -> Result<MissionNinjaOneDeviceResult> {
        proposal.verify_integrity()?;
        evidence.verify_integrity()?;
        if proposal.scope_digest != *self.scope.scope_digest()
            || evidence.scope_digest != *self.scope.scope_digest()
            || proposal.evidence_digest != *evidence.digest()
            || proposal.mission_id != *self.scope.mission_id()
            || proposal.project_id != *self.scope.project_id()
            || proposal.consent_id != *self.scope.consent_id()
            || proposal.mission_revision != self.scope.revisions().mission
            || proposal.project_revision != self.scope.revisions().project
            || proposal.consent_revision != self.scope.revisions().consent
        {
            return Err(NinjaOneError::MissionScopeMismatch);
        }
        if !proposal.non_mutating
            || proposal.external_write
            || proposal.work_product_adopted
            || proposal.outcome_adopted
            || proposal.kernel_authority
            || evidence.connected
            || evidence.native
        {
            return Err(NinjaOneError::ProposalTampered);
        }
        let observation = MissionNinjaOneDeviceObservation {
            mission_id: proposal.mission_id.clone(),
            project_id: proposal.project_id.clone(),
            consent_id: proposal.consent_id.clone(),
            mission_revision: proposal.mission_revision,
            project_revision: proposal.project_revision,
            consent_revision: proposal.consent_revision,
            scope_digest: proposal.scope_digest.clone(),
            result_state: proposal.projection.primary_state,
            states: proposal.projection.states.clone(),
            partial: proposal.projection.partial,
            non_adoptable: true,
            work_product_adopted: false,
            outcome_adopted: false,
            kernel_authority: false,
            connected: false,
            native: false,
        };
        Ok(MissionNinjaOneDeviceResult {
            observation,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            recording_only: true,
        })
    }

    pub fn consume_result(
        &self,
        proposal: NinjaOneDeviceResultProposal,
        evidence: NinjaOneDeviceResultEvidence,
    ) -> Result<MissionNinjaOneDeviceResult> {
        self.consume(proposal, evidence)
    }
}
