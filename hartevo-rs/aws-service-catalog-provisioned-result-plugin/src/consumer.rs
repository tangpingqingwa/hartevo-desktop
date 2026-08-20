//! Mission-scoped, review-only consumer seam.

use serde::Serialize;

use crate::{
    CONSUMER_ID,
    error::{AwsServiceCatalogError, Result},
    model::{
        AwsServiceCatalogScope, EvidenceState, MissionProjection, ProjectProjection,
        TransportProvenance, WorkProductProjection,
    },
    service::{AwsServiceCatalogProvisionedResultProposal, AwsServiceCatalogRegistration},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    ReviewOnly,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsServiceCatalogResult {
    pub consumer_id: String,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub proposal_digest: crate::model::Digest,
    pub evidence_digest: crate::model::Digest,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub verified_work_product: bool,
}

pub type RecordedAwsServiceCatalogResult = MissionAwsServiceCatalogResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAwsServiceCatalogConsumer {
    scope: AwsServiceCatalogScope,
    registration: AwsServiceCatalogRegistration,
}

impl MissionAwsServiceCatalogConsumer {
    pub fn new(
        scope: AwsServiceCatalogScope,
        registration: AwsServiceCatalogRegistration,
    ) -> Result<Self> {
        if scope.digest() != *registration.scope_digest() {
            return Err(AwsServiceCatalogError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
        })
    }

    pub fn scope(&self) -> &AwsServiceCatalogScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsServiceCatalogRegistration {
        &self.registration
    }

    pub const fn can_adopt_outcome(&self) -> bool {
        false
    }

    pub const fn can_adopt_work_product(&self) -> bool {
        false
    }

    pub fn accept(
        &self,
        proposal: &AwsServiceCatalogProvisionedResultProposal,
    ) -> Result<MissionAwsServiceCatalogResult> {
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.registration.scope_digest()
            || proposal.mission.mission_id_digest != self.scope.mission.mission_id_digest
            || proposal.mission.mission_revision != self.scope.mission.revision
        {
            return Err(AwsServiceCatalogError::StaleMission);
        }
        if proposal.connected
            || proposal.native
            || proposal.outcome_adopted
            || proposal.work_product_adopted
        {
            return Err(AwsServiceCatalogError::TamperedEvidence);
        }
        let disposition = if proposal.state == EvidenceState::Available {
            ProposalDisposition::ReviewOnly
        } else {
            ProposalDisposition::Rejected
        };
        Ok(MissionAwsServiceCatalogResult {
            consumer_id: CONSUMER_ID.to_owned(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            state: proposal.state,
            disposition,
            provenance: proposal.provenance,
            connected: false,
            native: false,
            outcome_adopted: false,
            work_product_adopted: false,
            verified_work_product: false,
        })
    }

    pub fn review(
        &self,
        proposal: &AwsServiceCatalogProvisionedResultProposal,
    ) -> Result<MissionAwsServiceCatalogResult> {
        self.accept(proposal)
    }
}
