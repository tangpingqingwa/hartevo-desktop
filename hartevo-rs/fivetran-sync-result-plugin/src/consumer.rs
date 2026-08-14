//! Mission-scoped consumer for Fivetran sync evidence.

use serde::{Deserialize, Serialize};

use crate::model::{
    FivetranError, FivetranResultState, FivetranScope, FivetranSyncEvidence,
    FivetranSyncResultProposal, TransportMode,
};
use crate::provider::FivetranProvider;
use crate::transport::FivetranTransport;
use crate::{CONSUMER_ID, CONTRACT_VERSION, PLUGIN_VERSION, Result, contract_digest};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionFivetranSyncObservation {
    pub contract_version: String,
    pub contract_digest: crate::Digest,
    pub consumer_id: String,
    pub plugin_version: crate::Version,
    pub scope_digest: crate::Digest,
    pub evidence_digest: crate::Digest,
    pub mission_revision: u64,
    pub result_state: FivetranResultState,
    pub provenance: TransportMode,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_write_performed: bool,
    pub webhook_ingested: bool,
    pub durable_receipt: bool,
    pub destination_read_back: bool,
    pub kernel_authority: bool,
    pub work_product_adopted: bool,
    pub observation_digest: crate::Digest,
}

impl MissionFivetranSyncObservation {
    fn from_evidence(evidence: &FivetranSyncEvidence) -> Self {
        let mut observation = Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_version: PLUGIN_VERSION,
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            mission_revision: evidence.mission_revision,
            result_state: evidence.result_state,
            provenance: evidence.provenance.mode,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_write_performed: false,
            webhook_ingested: false,
            durable_receipt: false,
            destination_read_back: false,
            kernel_authority: false,
            work_product_adopted: false,
            observation_digest: crate::Digest::pending(),
        };
        observation.observation_digest = observation.compute_digest();
        observation
    }

    fn compute_digest(&self) -> crate::Digest {
        crate::Digest::from_serializable(&serde_json::json!([
            &self.contract_version,
            &self.contract_digest,
            &self.consumer_id,
            &self.plugin_version,
            &self.scope_digest,
            &self.evidence_digest,
            self.mission_revision,
            self.result_state,
            self.provenance,
            self.read_only,
            self.proposal_only,
            self.recording_only,
            self.external_write_performed,
            self.webhook_ingested,
            self.durable_receipt,
            self.destination_read_back,
            self.kernel_authority,
            self.work_product_adopted,
        ]))
    }

    pub fn validate(&self, evidence: &FivetranSyncEvidence) -> Result<()> {
        if self.contract_version != CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.consumer_id != CONSUMER_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.scope_digest != evidence.scope_digest
            || self.evidence_digest != evidence.evidence_digest
            || self.mission_revision != evidence.mission_revision
            || self.result_state != evidence.result_state
            || self.provenance != evidence.provenance.mode
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.external_write_performed
            || self.webhook_ingested
            || self.durable_receipt
            || self.destination_read_back
            || self.kernel_authority
            || self.work_product_adopted
            || self.observation_digest != self.compute_digest()
        {
            return Err(FivetranError::TamperDetected {
                subject: "Mission Fivetran observation",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionFivetranSyncResult {
    pub observation: MissionFivetranSyncObservation,
    pub evidence: FivetranSyncEvidence,
    pub proposal: FivetranSyncResultProposal,
}

impl MissionFivetranSyncResult {
    pub fn validate(&self, scope: &FivetranScope) -> Result<()> {
        self.evidence.validate()?;
        self.proposal.validate(&self.evidence)?;
        self.observation.validate(&self.evidence)?;
        if self.evidence.scope_digest != scope.digest()
            || self.evidence.mission_revision != scope.mission_revision
        {
            return Err(FivetranError::StaleMissionRevision {
                expected: scope.mission_revision,
                observed: self.evidence.mission_revision,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionFivetranSyncConsumer {
    scope: FivetranScope,
    contract_digest: crate::Digest,
}

impl MissionFivetranSyncConsumer {
    pub fn new(scope: FivetranScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope,
            contract_digest: contract_digest(),
        })
    }

    pub fn from_registration(registration: &crate::FivetranRegistration) -> Result<Self> {
        registration.validate()?;
        if registration.status != crate::RegistrationStatus::Active {
            return Err(FivetranError::RegistrationNotActive);
        }
        Self::new(registration.scope.clone())
    }

    pub fn scope(&self) -> &FivetranScope {
        &self.scope
    }

    pub fn contract_digest(&self) -> &crate::Digest {
        &self.contract_digest
    }

    pub fn consume_evidence(
        &self,
        evidence: FivetranSyncEvidence,
    ) -> Result<MissionFivetranSyncResult> {
        if evidence.scope.mission_revision != self.scope.mission_revision
            || evidence.mission_revision != self.scope.mission_revision
        {
            return Err(FivetranError::StaleMissionRevision {
                expected: self.scope.mission_revision,
                observed: evidence.mission_revision,
            });
        }
        if evidence.scope_digest != self.scope.digest()
            || evidence.contract_digest != self.contract_digest
        {
            return Err(FivetranError::ScopeDrift {
                field: "Mission Fivetran scope",
            });
        }
        evidence.validate()?;
        let proposal = FivetranSyncResultProposal::from_evidence(&evidence);
        self.consume_result(proposal, evidence)
    }

    pub fn consume_result(
        &self,
        proposal: FivetranSyncResultProposal,
        evidence: FivetranSyncEvidence,
    ) -> Result<MissionFivetranSyncResult> {
        if evidence.mission_revision != self.scope.mission_revision {
            return Err(FivetranError::StaleMissionRevision {
                expected: self.scope.mission_revision,
                observed: evidence.mission_revision,
            });
        }
        if evidence.scope_digest != self.scope.digest() {
            return Err(FivetranError::ScopeDrift {
                field: "Project/Mission/Work Product scope",
            });
        }
        evidence.validate()?;
        proposal.validate(&evidence)?;
        let observation = MissionFivetranSyncObservation::from_evidence(&evidence);
        let result = MissionFivetranSyncResult {
            observation,
            evidence,
            proposal,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn consume(
        &self,
        proposal: FivetranSyncResultProposal,
        evidence: FivetranSyncEvidence,
    ) -> Result<MissionFivetranSyncResult> {
        self.consume_result(proposal, evidence)
    }

    pub fn read<T>(&self, provider: &mut FivetranProvider<T>) -> Result<MissionFivetranSyncResult>
    where
        T: FivetranTransport,
    {
        if provider.scope() != &self.scope {
            return Err(FivetranError::ScopeDrift {
                field: "provider/consumer scope",
            });
        }
        let evidence = provider.read_sync_evidence()?;
        let proposal = provider.compile_sync_result_proposal(&evidence)?;
        self.consume_result(proposal, evidence)
    }
}
