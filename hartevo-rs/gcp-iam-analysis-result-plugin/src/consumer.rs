//! Mission-scoped consumer for bounded GCP IAM analysis evidence.

use serde::{Deserialize, Serialize};

use crate::model::{
    AccessClassification, AdoptionAvailability, Digest, GcpIamAnalysisEvidence, GcpIamReadRequest,
    GcpIamScope, MissionId, ProjectId, WorkProductId, digest_serializable,
};
use crate::service::{GcpIamAnalysisRecord, GcpIamAnalysisService};
use crate::transport::GcpCloudAssetTransport;
use crate::{
    GCP_IAM_ANALYSIS_CONTRACT_VERSION, GCP_IAM_ANALYSIS_SERVICE_VERSION, GcpIamAnalysisError,
    MISSION_GCP_IAM_CONSUMER_ID, contract_digest,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionGcpIamState {
    PendingDecision,
    AccessObserved,
    PartialEvidence,
    AccessLoss,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionGcpIamObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub work_product_id: WorkProductId,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub policy_digest: Digest,
    pub query_digest: Digest,
    pub evidence_digest: Digest,
    pub access_classification: AccessClassification,
    pub partial: bool,
    pub access_loss: bool,
    pub state: MissionGcpIamState,
    pub native_authority: bool,
    pub truth_authority: bool,
    pub effective_authorization: bool,
    pub adopted_outcome: bool,
    pub observation_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionGcpIamResult {
    pub observation: MissionGcpIamObservation,
    pub evidence: GcpIamAnalysisEvidence,
    pub adoption: AdoptionAvailability,
}

impl MissionGcpIamResult {
    pub fn validate(&self, scope: &GcpIamScope) -> Result<(), GcpIamAnalysisError> {
        self.evidence
            .validate_for_scope(scope, None)
            .map_err(|_| GcpIamAnalysisError::StaleEvidence)?;
        if self.observation.scope_digest != scope.scope_digest
            || self.observation.permission_digest != scope.permission_digest
            || self.observation.policy_digest != scope.policy_digest()
            || self.observation.query_digest != scope.query_digest
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.observation.contract_digest != contract_digest()
            || self.observation.contract_version != GCP_IAM_ANALYSIS_CONTRACT_VERSION
            || self.observation.consumer_id != MISSION_GCP_IAM_CONSUMER_ID
            || self.observation.consumer_version != GCP_IAM_ANALYSIS_SERVICE_VERSION
            || self.observation.mission_id != scope.mission.id
            || self.observation.project_id != scope.project.id
            || self.observation.work_product_id != scope.work_product.id
            || self.observation.partial != self.evidence.partial
            || self.observation.access_loss != self.evidence.access_loss
            || self.observation.native_authority
            || self.observation.truth_authority
            || self.observation.effective_authorization
            || self.observation.adopted_outcome
            || self.adoption.is_adopted()
            || self.observation.observation_digest != observation_digest(&self.observation)
        {
            return Err(GcpIamAnalysisError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGcpIamConsumer {
    scope: GcpIamScope,
    contract_digest: Digest,
    registration_digest: Option<Digest>,
}

impl MissionGcpIamConsumer {
    #[must_use]
    pub fn new(scope: GcpIamScope) -> Self {
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

    #[must_use]
    pub fn scope(&self) -> &GcpIamScope {
        &self.scope
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    #[must_use]
    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    pub fn consume(
        &self,
        record: &GcpIamAnalysisRecord,
    ) -> Result<MissionGcpIamResult, GcpIamAnalysisError> {
        record.validate()?;
        self.consume_evidence(record.evidence.clone())
    }

    pub fn consume_evidence(
        &self,
        evidence: GcpIamAnalysisEvidence,
    ) -> Result<MissionGcpIamResult, GcpIamAnalysisError> {
        evidence
            .validate_for_scope(&self.scope, self.registration_digest.as_ref())
            .map_err(|_| GcpIamAnalysisError::StaleEvidence)?;
        let access_classification = evidence
            .analysis_pages
            .first()
            .map_or(AccessClassification::NoMatch, |page| page.classification);
        let state = if evidence.access_loss {
            MissionGcpIamState::AccessLoss
        } else if evidence.partial {
            MissionGcpIamState::PartialEvidence
        } else if evidence.analysis_pages.is_empty() {
            MissionGcpIamState::PendingDecision
        } else {
            MissionGcpIamState::AccessObserved
        };
        let mut observation = MissionGcpIamObservation {
            contract_version: GCP_IAM_ANALYSIS_CONTRACT_VERSION.to_owned(),
            contract_digest: self.contract_digest.clone(),
            consumer_id: MISSION_GCP_IAM_CONSUMER_ID.to_owned(),
            consumer_version: GCP_IAM_ANALYSIS_SERVICE_VERSION.to_owned(),
            mission_id: self.scope.mission.id.clone(),
            project_id: self.scope.project.id.clone(),
            work_product_id: self.scope.work_product.id.clone(),
            scope_digest: self.scope.scope_digest(),
            permission_digest: self.scope.permission_digest.clone(),
            policy_digest: self.scope.policy_digest(),
            query_digest: self.scope.query_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            access_classification,
            partial: evidence.partial,
            access_loss: evidence.access_loss,
            state,
            native_authority: false,
            truth_authority: false,
            effective_authorization: false,
            adopted_outcome: false,
            observation_digest: Digest::zero(),
        };
        observation.observation_digest = observation_digest(&observation);
        let result = MissionGcpIamResult {
            observation,
            evidence,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn read<T: GcpCloudAssetTransport>(
        &self,
        service: &GcpIamAnalysisService,
        provider: &mut crate::GcpCloudAssetProvider<T>,
        request: &GcpIamReadRequest,
    ) -> Result<MissionGcpIamResult, GcpIamAnalysisError> {
        let proposal = service.propose(provider, request)?;
        let record = service.record(proposal)?;
        self.consume(&record)
    }
}

fn observation_digest(observation: &MissionGcpIamObservation) -> Digest {
    let mut material = observation.clone();
    material.observation_digest = Digest::zero();
    Digest::from_serialized(&material)
}

#[allow(dead_code)]
fn _digest_helper_for_public_consumer(value: &MissionGcpIamObservation) -> Digest {
    digest_serializable(value)
}
