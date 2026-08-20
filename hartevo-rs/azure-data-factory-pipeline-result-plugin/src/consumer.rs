//! Mission-scoped, below-kernel consumer for Azure Data Factory proposals.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::model::{AzureDataFactoryScope, Digest, PipelineStatus};
use crate::provider::AzureDataFactoryTransport;
use crate::service::{
    AzureDataFactoryPipelineResultProposal, AzureDataFactoryPipelineResultRecord,
    AzureDataFactoryPipelineResultService,
};
use crate::{
    AzureDataFactoryPipelineResultError, CONSUMER_ID, CONTRACT_VERSION, Result, contract_digest,
};

pub type MissionAzureDataFactoryConsumerError = AzureDataFactoryPipelineResultError;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAzureDataFactoryResult {
    pub consumer_id: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub status: PipelineStatus,
    pub complete: bool,
    pub proposal: AzureDataFactoryPipelineResultProposal,
    pub review_only: bool,
    pub decision_ready: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub result_digest: Digest,
}

impl MissionAzureDataFactoryResult {
    fn new(proposal: AzureDataFactoryPipelineResultProposal) -> Self {
        let mut result = Self {
            consumer_id: CONSUMER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            project_digest: proposal.evidence.project_digest.clone(),
            mission_digest: proposal.evidence.mission_digest.clone(),
            work_product_digest: proposal.evidence.work_product_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            evidence_binding_digest: proposal.evidence_binding_digest.clone(),
            status: proposal.evidence.status,
            complete: proposal.evidence.complete,
            proposal,
            review_only: true,
            decision_ready: false,
            outcome_authority: false,
            work_product_adoption: false,
            result_digest: Digest::from_text("pending"),
        };
        result.decision_ready = result.complete
            && !matches!(
                result.status,
                PipelineStatus::Partial
                    | PipelineStatus::AccessLost
                    | PipelineStatus::ProviderUnknown
                    | PipelineStatus::Tampered
                    | PipelineStatus::Revoked
            );
        result.result_digest = result.digest();
        result
    }

    fn digest(&self) -> Digest {
        Digest::from_serialized(&(
            "azure-data-factory-mission-result/v1",
            (
                &self.consumer_id,
                &self.contract_version,
                &self.contract_digest,
            ),
            (
                &self.project_digest,
                &self.mission_digest,
                &self.work_product_digest,
                &self.scope_digest,
                &self.registration_digest,
                &self.evidence_digest,
                &self.evidence_binding_digest,
            ),
            (
                self.status,
                self.complete,
                self.review_only,
                self.decision_ready,
                self.outcome_authority,
                self.work_product_adoption,
            ),
        ))
    }

    pub fn validate(&self) -> Result<()> {
        self.proposal.validate_integrity()?;
        if self.consumer_id != CONSUMER_ID
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.scope_digest != self.proposal.scope_digest
            || self.registration_digest != self.proposal.registration_digest
            || self.evidence_digest != self.proposal.evidence_digest
            || self.evidence_binding_digest != self.proposal.evidence_binding_digest
            || self.status != self.proposal.evidence.status
            || self.complete != self.proposal.evidence.complete
            || !self.review_only
            || self.outcome_authority
            || self.work_product_adoption
        {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        let expected_result_digest = self.digest();
        if self.result_digest != expected_result_digest {
            return Err(AzureDataFactoryPipelineResultError::Tampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct MissionAzureDataFactoryConsumer {
    scope: AzureDataFactoryScope,
    consumed: BTreeMap<Digest, Digest>,
}

impl MissionAzureDataFactoryConsumer {
    #[must_use]
    pub fn new(scope: AzureDataFactoryScope) -> Self {
        Self {
            scope,
            consumed: BTreeMap::new(),
        }
    }

    pub fn try_new(scope: AzureDataFactoryScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self::new(scope))
    }

    #[must_use]
    pub fn scope(&self) -> &AzureDataFactoryScope {
        &self.scope
    }

    pub fn consume(
        &mut self,
        proposal: AzureDataFactoryPipelineResultProposal,
    ) -> Result<MissionAzureDataFactoryResult> {
        proposal.validate_integrity()?;
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.evidence.project_digest != *self.scope.project_digest()
            || proposal.evidence.mission_digest != *self.scope.mission_digest()
            || proposal.evidence.work_product_digest != *self.scope.work_product_digest()
        {
            return Err(AzureDataFactoryPipelineResultError::ScopeMismatch);
        }
        if let Some(existing) = self.consumed.get(&proposal.evidence_digest) {
            if existing != &proposal.proposal_digest {
                return Err(AzureDataFactoryPipelineResultError::ReplayConflict);
            }
            return Err(AzureDataFactoryPipelineResultError::ReplayConflict);
        }
        self.consumed.insert(
            proposal.evidence_digest.clone(),
            proposal.proposal_digest.clone(),
        );
        let result = MissionAzureDataFactoryResult::new(proposal);
        result.validate()?;
        Ok(result)
    }

    pub fn read<T: AzureDataFactoryTransport>(
        &mut self,
        service: &mut AzureDataFactoryPipelineResultService<T>,
    ) -> Result<MissionAzureDataFactoryResult> {
        let proposal = service.propose()?;
        self.consume(proposal)
    }

    pub fn record(
        &mut self,
        proposal: &AzureDataFactoryPipelineResultProposal,
        idempotency_key: &str,
    ) -> Result<AzureDataFactoryPipelineResultRecord> {
        proposal.validate_integrity()?;
        if proposal.scope_digest != *self.scope.scope_digest() {
            return Err(AzureDataFactoryPipelineResultError::ScopeMismatch);
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.consumed.get(&key_digest) {
            if existing == &proposal.proposal_digest {
                return Ok(AzureDataFactoryPipelineResultRecord::replay_of(
                    proposal,
                    idempotency_key,
                ));
            }
            return Err(AzureDataFactoryPipelineResultError::ReplayConflict);
        }
        self.consumed
            .insert(key_digest, proposal.proposal_digest.clone());
        Ok(AzureDataFactoryPipelineResultRecord::new_from_consumer(
            proposal,
            idempotency_key,
        ))
    }

    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }
}
