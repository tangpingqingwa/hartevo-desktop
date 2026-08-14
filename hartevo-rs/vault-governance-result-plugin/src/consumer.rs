//! Mission-scoped consumer for bounded Vault governance evidence.

use serde::{Deserialize, Serialize};

use crate::model::{
    AdoptionAvailability, Digest, HealthStatus, LeaseStatus, MissionId, ProjectId, TokenStatus,
    VaultGovernanceEvidence, VaultReadRequest, VaultScope, digest_serializable,
};
use crate::provider::VaultProvider;
use crate::service::{VaultGovernanceRecord, VaultGovernanceResultService};
use crate::transport::VaultTransport;
use crate::{
    MISSION_VAULT_GOVERNANCE_CONSUMER_ID, VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION,
    VAULT_GOVERNANCE_RESULT_SERVICE_VERSION, VaultGovernanceError, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionVaultGovernanceState {
    PendingDecision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionVaultGovernanceObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub health_status: Option<HealthStatus>,
    pub token_status: Option<TokenStatus>,
    pub lease_status: Option<LeaseStatus>,
    pub capability_digest: Option<Digest>,
    pub state: MissionVaultGovernanceState,
    pub native_authority: bool,
    pub truth_authority: bool,
    pub adopted_outcome: bool,
    pub observation_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionVaultGovernanceResult {
    pub observation: MissionVaultGovernanceObservation,
    pub evidence: VaultGovernanceEvidence,
    pub adoption: AdoptionAvailability,
}

impl MissionVaultGovernanceResult {
    pub fn validate(&self, scope: &VaultScope) -> Result<(), VaultGovernanceError> {
        self.evidence.validate()?;
        if self.evidence.scope_digest != scope.scope_digest()
            || self.observation.scope_digest != scope.scope_digest()
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.observation.contract_digest != contract_digest()
            || self.observation.contract_version != VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION
            || self.observation.consumer_id != MISSION_VAULT_GOVERNANCE_CONSUMER_ID
            || self.observation.consumer_version != VAULT_GOVERNANCE_RESULT_SERVICE_VERSION
            || self.observation.native_authority
            || self.observation.truth_authority
            || self.observation.adopted_outcome
            || self.adoption.is_adopted()
        {
            return Err(VaultGovernanceError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionVaultGovernanceConsumer {
    scope: VaultScope,
    contract_digest: Digest,
    registration_digest: Option<Digest>,
}

impl MissionVaultGovernanceConsumer {
    pub fn new(scope: VaultScope) -> Self {
        Self {
            scope,
            contract_digest: contract_digest(),
            registration_digest: None,
        }
    }

    #[must_use]
    pub fn with_registration_digest(mut self, registration_digest: Digest) -> Self {
        self.registration_digest = Some(registration_digest);
        self
    }

    pub fn scope(&self) -> &VaultScope {
        &self.scope
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    pub fn consume(
        &self,
        record: &VaultGovernanceRecord,
    ) -> Result<MissionVaultGovernanceResult, VaultGovernanceError> {
        record.validate()?;
        self.consume_evidence(record.evidence.clone())
    }

    pub fn consume_evidence(
        &self,
        evidence: VaultGovernanceEvidence,
    ) -> Result<MissionVaultGovernanceResult, VaultGovernanceError> {
        evidence.validate()?;
        if evidence.scope_digest != self.scope.scope_digest()
            || evidence.contract_digest != self.contract_digest
            || evidence.contract_version != VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION
            || evidence.consumer_id != MISSION_VAULT_GOVERNANCE_CONSUMER_ID
            || self
                .registration_digest
                .as_ref()
                .is_some_and(|digest| digest != &evidence.registration_digest)
        {
            return Err(VaultGovernanceError::StaleEvidence);
        }
        let capability_digest = if evidence.capabilities.is_empty() {
            None
        } else {
            Some(digest_serializable(&evidence.capabilities))
        };
        let mut observation = MissionVaultGovernanceObservation {
            contract_version: VAULT_GOVERNANCE_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: self.contract_digest.clone(),
            consumer_id: MISSION_VAULT_GOVERNANCE_CONSUMER_ID.to_owned(),
            consumer_version: VAULT_GOVERNANCE_RESULT_SERVICE_VERSION.to_owned(),
            mission_id: self.scope.mission_id().clone(),
            project_id: self.scope.project_id().clone(),
            scope_digest: self.scope.scope_digest(),
            evidence_digest: evidence.evidence_digest.clone(),
            health_status: evidence.health.as_ref().map(|health| health.status),
            token_status: evidence.token.as_ref().map(|token| token.status),
            lease_status: evidence.lease.as_ref().map(|lease| lease.status),
            capability_digest,
            state: MissionVaultGovernanceState::PendingDecision,
            native_authority: false,
            truth_authority: false,
            adopted_outcome: false,
            observation_digest: Digest::zero(),
        };
        observation.observation_digest = digest_serializable(&(
            &observation.contract_version,
            &observation.contract_digest,
            &observation.consumer_id,
            &observation.consumer_version,
            &observation.mission_id,
            &observation.project_id,
            &observation.scope_digest,
            &observation.evidence_digest,
            observation.health_status,
            observation.token_status,
            observation.lease_status,
            &observation.capability_digest,
            observation.state,
            observation.native_authority,
            observation.truth_authority,
            observation.adopted_outcome,
        ));
        let result = MissionVaultGovernanceResult {
            observation,
            evidence,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn read<T: VaultTransport>(
        &self,
        service: &VaultGovernanceResultService,
        provider: &mut VaultProvider<T>,
        request: &VaultReadRequest,
    ) -> Result<MissionVaultGovernanceResult, VaultGovernanceError> {
        let proposal = service.propose(provider, request)?;
        let record = service.record(proposal)?;
        self.consume(&record)
    }
}
