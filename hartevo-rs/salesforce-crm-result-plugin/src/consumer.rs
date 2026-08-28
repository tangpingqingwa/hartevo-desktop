use serde::{Deserialize, Serialize};

use crate::{
    MISSION_SALESFORCE_CRM_CONSUMER_ID, SALESFORCE_CRM_RESULT_CONTRACT_VERSION,
    SALESFORCE_CRM_RESULT_PLUGIN_VERSION_TEXT, SalesforceCrmResultError, SalesforceTransport,
    contract_digest,
    model::{
        Digest, MissionId, PluginVersion, ProjectId, SalesforceRecordProjection,
        SalesforceRegistration, SalesforceResultStatus, SalesforceScope, WorkProductId,
        canonical_digest,
    },
    service::{
        SalesforceCrmResultService, SalesforceEvidence, SalesforceReadResult,
        SalesforceVerification,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionSalesforceResultState {
    PendingDecision,
    Partial,
    AccessLost,
    NotFound,
    ProviderUnknown,
    FinalError,
}

impl From<SalesforceResultStatus> for MissionSalesforceResultState {
    fn from(status: SalesforceResultStatus) -> Self {
        match status {
            SalesforceResultStatus::Complete => Self::PendingDecision,
            SalesforceResultStatus::Partial => Self::Partial,
            SalesforceResultStatus::AccessLost => Self::AccessLost,
            SalesforceResultStatus::NotFound => Self::NotFound,
            SalesforceResultStatus::ProviderUnknown => Self::ProviderUnknown,
            SalesforceResultStatus::FinalError => Self::FinalError,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionSalesforceCrmResult {
    pub consumer_id: String,
    pub consumer_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub mission_id: MissionId,
    pub mission_revision: crate::Revision,
    pub project_id: ProjectId,
    pub project_revision: crate::Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: crate::Revision,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub provider_digest: Digest,
    pub state: MissionSalesforceResultState,
    pub records: Vec<SalesforceRecordProjection>,
    pub read_only: bool,
    pub native_evidence: bool,
    pub external_write_performed: bool,
    pub approval_mutation_performed: bool,
    pub inbox_authority: bool,
    pub truth_authority: bool,
    pub adoption_available: bool,
    pub evidence: SalesforceEvidence,
    pub verification: SalesforceVerification,
    pub result_digest: Digest,
}

#[derive(Serialize)]
struct MissionResultDigestMaterial<'a> {
    consumer_id: &'a String,
    consumer_version: PluginVersion,
    contract_version: &'a String,
    contract_digest: &'a Digest,
    scope_digest: &'a Digest,
    mission_id: &'a MissionId,
    mission_revision: crate::Revision,
    project_id: &'a ProjectId,
    project_revision: crate::Revision,
    work_product_id: &'a WorkProductId,
    work_product_revision: crate::Revision,
    proposal_digest: &'a Digest,
    evidence_digest: &'a Digest,
    provider_digest: &'a Digest,
    state: MissionSalesforceResultState,
    records: &'a Vec<SalesforceRecordProjection>,
    read_only: bool,
    native_evidence: bool,
    external_write_performed: bool,
    approval_mutation_performed: bool,
    inbox_authority: bool,
    truth_authority: bool,
    adoption_available: bool,
    verification: &'a SalesforceVerification,
}

impl MissionSalesforceCrmResult {
    pub fn validate(&self, scope: &SalesforceScope) -> Result<(), SalesforceCrmResultError> {
        self.evidence.validate()?;
        if self.consumer_id != MISSION_SALESFORCE_CRM_CONSUMER_ID
            || self.consumer_version != PluginVersion::new(1, 0, 0)
            || self.contract_version != SALESFORCE_CRM_RESULT_CONTRACT_VERSION
            || self.contract_digest != contract_digest()
            || self.scope_digest != scope.scope_digest()
            || self.mission_id != *scope.mission_id()
            || self.mission_revision != scope.mission_revision()
            || self.project_id != *scope.project_id()
            || self.project_revision != scope.project_revision()
            || self.work_product_id != *scope.work_product_id()
            || self.work_product_revision != scope.work_product_revision()
            || self.proposal_digest != self.evidence.proposal_digest
            || self.evidence_digest != self.evidence.evidence_digest
            || self.provider_digest != self.evidence.provider_digest
            || self.records != self.evidence.records
            || !self.read_only
            || self.native_evidence
            || self.external_write_performed
            || self.approval_mutation_performed
            || self.inbox_authority
            || self.truth_authority
            || self.adoption_available
            || self.result_digest != self.compute_digest()
        {
            return Err(SalesforceCrmResultError::Consumer(
                "Mission result is stale, tampered, or outside the Layer-1 authority boundary"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&MissionResultDigestMaterial {
            consumer_id: &self.consumer_id,
            consumer_version: self.consumer_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            scope_digest: &self.scope_digest,
            mission_id: &self.mission_id,
            mission_revision: self.mission_revision,
            project_id: &self.project_id,
            project_revision: self.project_revision,
            work_product_id: &self.work_product_id,
            work_product_revision: self.work_product_revision,
            proposal_digest: &self.proposal_digest,
            evidence_digest: &self.evidence_digest,
            provider_digest: &self.provider_digest,
            state: self.state,
            records: &self.records,
            read_only: self.read_only,
            native_evidence: self.native_evidence,
            external_write_performed: self.external_write_performed,
            approval_mutation_performed: self.approval_mutation_performed,
            inbox_authority: self.inbox_authority,
            truth_authority: self.truth_authority,
            adoption_available: self.adoption_available,
            verification: &self.verification,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionSalesforceCrmConsumer {
    scope: SalesforceScope,
    registration_digest: Digest,
    consumer_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
}

impl MissionSalesforceCrmConsumer {
    pub fn new(
        scope: SalesforceScope,
        registration: &SalesforceRegistration,
    ) -> Result<Self, SalesforceCrmResultError> {
        registration
            .validate()
            .map_err(|error| SalesforceCrmResultError::RegistrationDrift(error.to_string()))?;
        if !registration.is_active() || registration.scope_digest != scope.scope_digest() {
            return Err(SalesforceCrmResultError::ScopeMismatch(
                "Mission consumer and registration scopes differ".to_owned(),
            ));
        }
        Ok(Self {
            scope,
            registration_digest: registration.registration_digest.clone(),
            consumer_version: PluginVersion::new(1, 0, 0),
            contract_version: SALESFORCE_CRM_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: contract_digest(),
        })
    }

    pub fn from_service<T: SalesforceTransport>(
        service: &SalesforceCrmResultService<T>,
    ) -> Result<Self, SalesforceCrmResultError> {
        Self::new(service.scope().clone(), service.registration())
    }

    pub fn scope(&self) -> &SalesforceScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn consume(
        &self,
        result: SalesforceReadResult,
    ) -> Result<MissionSalesforceCrmResult, SalesforceCrmResultError> {
        let provider_definition =
            crate::SalesforceProviderDefinition::new(result.evidence.provenance)
                .map_err(|error| SalesforceCrmResultError::Consumer(error.to_string()))?;
        result
            .validate(&self.scope, &provider_definition)
            .map_err(|error| SalesforceCrmResultError::Consumer(error.to_string()))?;
        if result.evidence.contract_digest != self.contract_digest
            || result.evidence.contract_version != self.contract_version
        {
            return Err(SalesforceCrmResultError::Consumer(
                "Mission consumer contract binding drifted".to_owned(),
            ));
        }
        let mut mission_result = MissionSalesforceCrmResult {
            consumer_id: MISSION_SALESFORCE_CRM_CONSUMER_ID.to_owned(),
            consumer_version: self.consumer_version,
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            scope_digest: self.scope.scope_digest(),
            mission_id: self.scope.mission_id().clone(),
            mission_revision: self.scope.mission_revision(),
            project_id: self.scope.project_id().clone(),
            project_revision: self.scope.project_revision(),
            work_product_id: self.scope.work_product_id().clone(),
            work_product_revision: self.scope.work_product_revision(),
            proposal_digest: result.proposal.proposal_digest.clone(),
            evidence_digest: result.evidence.evidence_digest.clone(),
            provider_digest: result.evidence.provider_digest.clone(),
            state: result.evidence.status.into(),
            records: result.evidence.records.clone(),
            read_only: true,
            native_evidence: false,
            external_write_performed: false,
            approval_mutation_performed: false,
            inbox_authority: false,
            truth_authority: false,
            adoption_available: false,
            evidence: result.evidence,
            verification: result.verification,
            result_digest: Digest::from_text("placeholder"),
        };
        mission_result.result_digest = mission_result.compute_digest();
        mission_result.validate(&self.scope)?;
        Ok(mission_result)
    }

    pub fn read<T: SalesforceTransport>(
        &self,
        service: &mut SalesforceCrmResultService<T>,
        request: crate::SalesforceReadRequest,
    ) -> Result<MissionSalesforceCrmResult, SalesforceCrmResultError> {
        if service.scope().scope_digest() != self.scope.scope_digest() {
            return Err(SalesforceCrmResultError::ScopeMismatch(
                "Mission consumer and service scopes differ".to_owned(),
            ));
        }
        self.consume(service.read(request)?)
    }
}

pub type MissionSalesforceResultConsumer = MissionSalesforceCrmConsumer;

#[allow(dead_code)]
fn _consumer_version_text() -> &'static str {
    SALESFORCE_CRM_RESULT_PLUGIN_VERSION_TEXT
}
