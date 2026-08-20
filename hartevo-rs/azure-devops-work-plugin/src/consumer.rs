//! Mission-scoped consumer for Azure DevOps Work observations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{
    AzureDevOpsReadRequest, AzureDevOpsScope, AzureDevOpsWorkEvidence, Digest, TransportProvenance,
    compute_evidence_digest, digest_serializable,
};
use crate::provider::{AzureDevOpsServicesProvider, EntraCredentialResolver};
use crate::transport::AzureDevOpsWorkTransport;
use crate::{
    AZURE_DEVOPS_WORK_CONTRACT_VERSION, AZURE_DEVOPS_WORK_PLUGIN_VERSION_TEXT,
    AzureDevOpsWorkError, contract_digest,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureDevOpsWorkObservation {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub consumer_id: String,
    pub consumer_version: String,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub native_evidence: bool,
    pub external_write_performed: bool,
    pub outcome_authority: bool,
    pub observation_digest: Digest,
}

impl AzureDevOpsWorkObservation {
    fn from_evidence(evidence: &AzureDevOpsWorkEvidence) -> Result<Self, AzureDevOpsWorkError> {
        let mut observation = Self {
            contract_version: AZURE_DEVOPS_WORK_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
            consumer_id: crate::MISSION_AZURE_DEVOPS_WORK_CONSUMER_ID.to_owned(),
            consumer_version: AZURE_DEVOPS_WORK_PLUGIN_VERSION_TEXT.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            provenance: evidence.provenance,
            read_only: true,
            native_evidence: false,
            external_write_performed: false,
            outcome_authority: false,
            observation_digest: Digest::parse(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )?,
        };
        observation.observation_digest = digest_serializable(&(
            &observation.contract_version,
            &observation.contract_digest,
            &observation.consumer_id,
            &observation.consumer_version,
            &observation.scope_digest,
            &observation.evidence_digest,
            observation.provenance,
            observation.read_only,
            observation.native_evidence,
            observation.external_write_performed,
            observation.outcome_authority,
        ))?;
        Ok(observation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAzureDevOpsWorkReadResult {
    pub observation: AzureDevOpsWorkObservation,
    pub evidence: AzureDevOpsWorkEvidence,
}

impl MissionAzureDevOpsWorkReadResult {
    pub fn validate(&self, scope: &AzureDevOpsScope) -> Result<(), AzureDevOpsWorkError> {
        self.evidence.validate()?;
        if self.evidence.scope_digest != scope.digest()
            || self.observation.scope_digest != scope.digest()
            || self.observation.evidence_digest != self.evidence.evidence_digest
            || self.observation.contract_digest != contract_digest()
            || self.observation.contract_version != AZURE_DEVOPS_WORK_CONTRACT_VERSION
            || self.observation.consumer_id != crate::MISSION_AZURE_DEVOPS_WORK_CONSUMER_ID
            || self.observation.consumer_version != AZURE_DEVOPS_WORK_PLUGIN_VERSION_TEXT
            || !self.observation.read_only
            || self.observation.native_evidence
            || self.observation.external_write_performed
            || self.observation.outcome_authority
        {
            return Err(AzureDevOpsWorkError::StaleEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionAzureDevOpsWorkConsumer {
    scope: AzureDevOpsScope,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
}

impl MissionAzureDevOpsWorkConsumer {
    pub fn new(scope: AzureDevOpsScope) -> Self {
        Self {
            scope,
            plugin_version: AZURE_DEVOPS_WORK_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: AZURE_DEVOPS_WORK_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
        }
    }

    pub fn scope(&self) -> &AzureDevOpsScope {
        &self.scope
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn consume_evidence(
        &self,
        evidence: AzureDevOpsWorkEvidence,
    ) -> Result<MissionAzureDevOpsWorkReadResult, AzureDevOpsWorkError> {
        if evidence.scope_digest != self.scope.digest()
            || evidence.contract_digest != self.contract_digest
            || evidence.contract_version != self.contract_version
            || compute_evidence_digest(&evidence)? != evidence.evidence_digest
        {
            return Err(AzureDevOpsWorkError::StaleEvidence);
        }
        evidence.validate()?;
        let observation = AzureDevOpsWorkObservation::from_evidence(&evidence)?;
        let result = MissionAzureDevOpsWorkReadResult {
            observation,
            evidence,
        };
        result.validate(&self.scope)?;
        Ok(result)
    }

    pub fn read<T, R>(
        &self,
        provider: &mut AzureDevOpsServicesProvider<T, R>,
        request: &AzureDevOpsReadRequest,
        at: DateTime<Utc>,
    ) -> Result<MissionAzureDevOpsWorkReadResult, AzureDevOpsWorkError>
    where
        T: AzureDevOpsWorkTransport,
        R: EntraCredentialResolver,
    {
        if provider.registration().scope() != &self.scope {
            return Err(AzureDevOpsWorkError::ScopeMismatch(
                "consumer and provider registration scopes differ".to_owned(),
            ));
        }
        let evidence = provider.read(request, at)?;
        self.consume_evidence(evidence)
    }
}
