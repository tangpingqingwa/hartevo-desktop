use serde::{Deserialize, Serialize};

use crate::{
    HartevoProjectId, OrganizationId, ProjectId,
    error::Result,
    model::{
        BatchStatus, Digest, EvidenceDisposition, MissionId, OpenAiBatchEvidence,
        OpenAiBatchRegistration, OpenAiBatchScope, ProviderProvenance, Revision, WorkProductId,
    },
    provider::OpenAiBatchProvider,
    service::{OpenAiBatchResultProposal, OpenAiBatchResultService},
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionResultState {
    MetadataAvailable,
    NonTerminalMetadata,
    FailedMetadata,
    ExpiredMetadata,
    CancelledMetadata,
    AccessLost,
    ProviderUnknown,
    BlockedEnv,
}

/// Mission-facing projection.  It binds an evidence digest to the exact
/// Mission/Project/Work Product identifiers but cannot adopt the Work Product
/// or mint kernel authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionOpenAiBatchResult {
    pub organization_id: OrganizationId,
    pub project_id: ProjectId,
    pub batch_ids: Vec<crate::BatchId>,
    pub hartevo_project_id: HartevoProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub evidence_digest: Digest,
    pub disposition: EvidenceDisposition,
    pub state: MissionResultState,
    pub provenance: ProviderProvenance,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub work_product_adopted: bool,
    pub kernel_authority: bool,
}

impl MissionOpenAiBatchResult {
    pub fn validate(&self) -> Result<()> {
        self.organization_id.validate()?;
        self.project_id.validate()?;
        for batch_id in &self.batch_ids {
            batch_id.validate()?;
        }
        self.hartevo_project_id.validate()?;
        self.mission_id.validate()?;
        self.work_product_id.validate()?;
        self.evidence_digest.validate("evidence_digest")?;
        if !self.proposal_only
            || self.connected
            || self.native
            || self.work_product_adopted
            || self.kernel_authority
        {
            return Err(crate::OpenAiBatchResultError::EvidenceTampered);
        }
        Ok(())
    }
}

/// Mission consumer for one exact OpenAI organization/project/batch and
/// Hartevo Mission/Project/Work Product binding.
#[derive(Clone, Debug)]
pub struct MissionOpenAiBatchConsumer {
    service: OpenAiBatchResultService,
}

impl MissionOpenAiBatchConsumer {
    pub fn new(scope: OpenAiBatchScope, provider: OpenAiBatchProvider) -> Result<Self> {
        Ok(Self {
            service: OpenAiBatchResultService::new(scope, provider)?,
        })
    }

    #[must_use]
    pub fn from_service(service: OpenAiBatchResultService) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn service(&self) -> &OpenAiBatchResultService {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut OpenAiBatchResultService {
        &mut self.service
    }

    #[must_use]
    pub fn registration(&self) -> &OpenAiBatchRegistration {
        self.service.registration()
    }

    pub fn consume(&self, evidence: &OpenAiBatchEvidence) -> Result<MissionOpenAiBatchResult> {
        self.service.verify_evidence(evidence)?;
        let result = MissionOpenAiBatchResult {
            organization_id: self.service.scope().identity().organization_id.clone(),
            project_id: self.service.scope().identity().project_id.clone(),
            batch_ids: evidence
                .batches
                .iter()
                .map(|batch| batch.batch_id.clone())
                .collect(),
            hartevo_project_id: self.service.scope().identity().hartevo_project_id.clone(),
            mission_id: self.service.scope().identity().mission_id.clone(),
            work_product_id: self.service.scope().identity().work_product_id.clone(),
            project_revision: self.service.scope().identity().project_revision,
            mission_revision: self.service.scope().identity().mission_revision,
            work_product_revision: self.service.scope().identity().work_product_revision,
            evidence_digest: evidence.evidence_digest.clone(),
            disposition: evidence.disposition,
            state: mission_state(evidence),
            provenance: evidence.provenance,
            proposal_only: true,
            connected: false,
            native: false,
            work_product_adopted: false,
            kernel_authority: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn consume_proposal(
        &self,
        proposal: &OpenAiBatchResultProposal,
        evidence: &OpenAiBatchEvidence,
    ) -> Result<MissionOpenAiBatchResult> {
        self.service.verify_result_proposal(proposal, evidence)?;
        self.consume(evidence)
    }

    pub fn read_and_consume_batch(
        &mut self,
        batch_id: crate::BatchId,
        minimum_observed_at: u64,
    ) -> Result<MissionOpenAiBatchResult> {
        let evidence = self.service.read_batch(batch_id, minimum_observed_at)?;
        self.consume(&evidence)
    }
}

fn mission_state(evidence: &OpenAiBatchEvidence) -> MissionResultState {
    match evidence.disposition {
        EvidenceDisposition::BlockedEnv => MissionResultState::BlockedEnv,
        EvidenceDisposition::AccessLost => MissionResultState::AccessLost,
        EvidenceDisposition::ProviderUnknown | EvidenceDisposition::Partial => {
            MissionResultState::ProviderUnknown
        }
        EvidenceDisposition::Empty => MissionResultState::MetadataAvailable,
        EvidenceDisposition::Present => match evidence.batches.first().map(|batch| batch.status) {
            Some(BatchStatus::Failed) => MissionResultState::FailedMetadata,
            Some(BatchStatus::Expired) => MissionResultState::ExpiredMetadata,
            Some(BatchStatus::Cancelled) => MissionResultState::CancelledMetadata,
            Some(BatchStatus::Completed) | None => MissionResultState::MetadataAvailable,
            Some(
                BatchStatus::Validating
                | BatchStatus::InProgress
                | BatchStatus::Finalizing
                | BatchStatus::Cancelling,
            ) => MissionResultState::NonTerminalMetadata,
        },
    }
}
