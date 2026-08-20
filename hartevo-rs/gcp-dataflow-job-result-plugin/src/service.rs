//! Service, reversible registration, bounded read, recording, and verification seams.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    DataflowEvidence, DataflowJobSelector, DataflowJobSummary, DataflowMetricSummary,
    DataflowOperation, DataflowRequestReceipt, DataflowResponseReceipt, Digest, EvidenceDigests,
    EvidenceState, GcpDataflowJobResultScope, MAX_JOBS, MAX_PAGE_SIZE, MAX_PAGES, ModelError,
    Revision, SecretReference, TransportProvenance, aggregate_job_digest, aggregate_metric_digest,
    aggregate_request_digest, aggregate_response_digest, aggregate_stage_digest,
};
use crate::provider::{
    DataflowReadProposal, DataflowReadRecord, DataflowReadRequest, GCP_DATAFLOW_API_REVISION,
    GCP_DATAFLOW_PROVIDER_REVISION, GcpDataflowProvider, GcpDataflowProviderDefinition,
    GcpDataflowProviderError, GcpDataflowTransport, ProviderDefinitionError,
};
use crate::{
    GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION, GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT,
    GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID, GCP_DATAFLOW_JOB_RESULT_PROVIDER_VERSION_TEXT,
    GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION, GCP_DATAFLOW_JOB_RESULT_SERVICE_ID,
    GCP_DATAFLOW_JOB_RESULT_SERVICE_NAME, MISSION_GCP_DATAFLOW_CONSUMER_ID, contract_digest,
    plugin_version_digest,
};

pub const GCP_DATAFLOW_JOB_RESULT_SERVICE_VERSION: &str = "1.0.0";
pub const GCP_DATAFLOW_JOB_RESULT_SERVICE_SCHEMA: &str =
    "hartevo.gcp-dataflow-job-result-service/v1";
pub const GCP_DATAFLOW_JOB_RESULT_EVIDENCE_POLICY: &str =
    "dataflow-job-v1-state-stage-metric-digests-revision-fenced";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpDataflowJobResultOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    RestoreRegistration,
    ProposeJobsList,
    ProposeJobGet,
    ProposeJobMetrics,
    ReadJobsListBounded,
    ReadJobGet,
    ReadJobMetrics,
    RecordObservation,
    VerifyProposal,
    VerifyObservation,
    ConsumeMissionProjection,
}

impl GcpDataflowJobResultOperation {
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        !matches!(
            self,
            Self::Register | Self::RevokeRegistration | Self::RestoreRegistration
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpDataflowCapability {
    pub operation: GcpDataflowJobResultOperation,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub external_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpDataflowJobResultServiceDefinition {
    pub service_id: String,
    pub service_name: String,
    pub service_version: String,
    pub schema_version: String,
    pub contract_version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub capabilities: Vec<GcpDataflowCapability>,
}

impl Default for GcpDataflowJobResultServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl GcpDataflowJobResultServiceDefinition {
    #[must_use]
    pub fn new() -> Self {
        let operations = [
            GcpDataflowJobResultOperation::DescribeCapabilities,
            GcpDataflowJobResultOperation::Register,
            GcpDataflowJobResultOperation::RevokeRegistration,
            GcpDataflowJobResultOperation::RestoreRegistration,
            GcpDataflowJobResultOperation::ProposeJobsList,
            GcpDataflowJobResultOperation::ProposeJobGet,
            GcpDataflowJobResultOperation::ProposeJobMetrics,
            GcpDataflowJobResultOperation::ReadJobsListBounded,
            GcpDataflowJobResultOperation::ReadJobGet,
            GcpDataflowJobResultOperation::ReadJobMetrics,
            GcpDataflowJobResultOperation::RecordObservation,
            GcpDataflowJobResultOperation::VerifyProposal,
            GcpDataflowJobResultOperation::VerifyObservation,
            GcpDataflowJobResultOperation::ConsumeMissionProjection,
        ];
        Self {
            service_id: GCP_DATAFLOW_JOB_RESULT_SERVICE_ID.to_owned(),
            service_name: GCP_DATAFLOW_JOB_RESULT_SERVICE_NAME.to_owned(),
            service_version: GCP_DATAFLOW_JOB_RESULT_SERVICE_VERSION.to_owned(),
            schema_version: GCP_DATAFLOW_JOB_RESULT_SERVICE_SCHEMA.to_owned(),
            contract_version: GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION.to_owned(),
            read_only: true,
            proposal_only: true,
            native: false,
            connected: false,
            external_writes: false,
            capabilities: operations
                .into_iter()
                .map(|operation| GcpDataflowCapability {
                    read_only: operation.is_read_only(),
                    operation,
                    native: false,
                    connected: false,
                    external_write: false,
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> Vec<GcpDataflowCapability> {
        self.capabilities.clone()
    }

    pub fn validate(&self) -> Result<(), GcpDataflowJobResultServiceError> {
        if self.service_id != GCP_DATAFLOW_JOB_RESULT_SERVICE_ID
            || self.service_name != GCP_DATAFLOW_JOB_RESULT_SERVICE_NAME
            || self.service_version != GCP_DATAFLOW_JOB_RESULT_SERVICE_VERSION
            || self.schema_version != GCP_DATAFLOW_JOB_RESULT_SERVICE_SCHEMA
            || self.contract_version != GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION
            || !self.read_only
            || !self.proposal_only
            || self.native
            || self.connected
            || self.external_writes
            || self.capabilities.iter().any(|capability| {
                capability.native || capability.connected || capability.external_write
            })
        {
            return Err(GcpDataflowJobResultServiceError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RegistrationError {
    #[error("Dataflow registration is already revoked")]
    AlreadyRevoked,
    #[error("Dataflow registration is not revoked")]
    NotRevoked,
    #[error("Dataflow registration revision overflowed")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpDataflowRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub pipeline_type_digest: Digest,
    pub stage_allowlist_digest: Digest,
    pub metric_allowlist_digest: Digest,
    pub job_revision: Revision,
    pub evidence_policy_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl GcpDataflowRegistration {
    pub fn new(
        scope: &GcpDataflowJobResultScope,
        secret_reference: &SecretReference,
        provider_definition: &GcpDataflowProviderDefinition,
    ) -> Result<Self, GcpDataflowJobResultServiceError> {
        scope.validate()?;
        provider_definition.validate()?;
        secret_reference
            .validate(scope)
            .map_err(|_| GcpDataflowJobResultServiceError::ScopeMismatch)?;
        let mut registration = Self {
            schema_version: GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            version_digest: plugin_version_digest(),
            contract_digest: contract_digest(),
            provider_id: provider_definition.provider_id.clone(),
            provider_version: provider_definition.provider_version.clone(),
            provider_revision: provider_definition.provider_revision.clone(),
            provider_digest: provider_definition.provider_digest(),
            api_digest: Digest::from_text(GCP_DATAFLOW_API_REVISION),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest(),
            pipeline_type_digest: scope.pipeline_type_digest(),
            stage_allowlist_digest: scope.stage_allowlist_digest(),
            metric_allowlist_digest: scope.metric_allowlist_digest(),
            job_revision: scope.job_revision,
            evidence_policy_digest: Digest::from_text(GCP_DATAFLOW_JOB_RESULT_EVIDENCE_POLICY),
            evidence_digest: Digest::from_text(GCP_DATAFLOW_JOB_RESULT_EVIDENCE_POLICY),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            credential_revision: secret_reference.revision(),
            registration_revision: Revision::new(1)?,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("unsealed-dataflow-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        Ok(registration)
    }

    fn calculate_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct RegistrationDigestInput<'a> {
            schema_version: &'a str,
            contract_version: &'a str,
            plugin_version: &'a str,
            version_digest: &'a Digest,
            contract_digest: &'a Digest,
            provider_id: &'a str,
            provider_version: &'a str,
            provider_revision: &'a str,
            provider_digest: &'a Digest,
            api_digest: &'a Digest,
            permission_digest: &'a Digest,
            scope_digest: &'a Digest,
            pipeline_type_digest: &'a Digest,
            stage_allowlist_digest: &'a Digest,
            metric_allowlist_digest: &'a Digest,
            job_revision: Revision,
            evidence_policy_digest: &'a Digest,
            evidence_digest: &'a Digest,
            secret_reference_digest: &'a Digest,
            credential_revision: Revision,
            registration_revision: Revision,
            state: RegistrationState,
        }
        Digest::from_serializable(&RegistrationDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            version_digest: &self.version_digest,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            pipeline_type_digest: &self.pipeline_type_digest,
            stage_allowlist_digest: &self.stage_allowlist_digest,
            metric_allowlist_digest: &self.metric_allowlist_digest,
            job_revision: self.job_revision,
            evidence_policy_digest: &self.evidence_policy_digest,
            evidence_digest: &self.evidence_digest,
            secret_reference_digest: &self.secret_reference_digest,
            credential_revision: self.credential_revision,
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.schema_version == GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION
            && self.contract_version == GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION
            && self.plugin_version == GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT
            && self.version_digest == plugin_version_digest()
            && self.contract_digest == contract_digest()
            && self.provider_id == GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID
            && self.provider_version == GCP_DATAFLOW_JOB_RESULT_PROVIDER_VERSION_TEXT
            && self.provider_revision == GCP_DATAFLOW_PROVIDER_REVISION
            && self.api_digest == Digest::from_text(GCP_DATAFLOW_API_REVISION)
            && self.evidence_policy_digest
                == Digest::from_text(GCP_DATAFLOW_JOB_RESULT_EVIDENCE_POLICY)
            && self.evidence_digest == self.evidence_policy_digest
            && self.registration_digest == self.calculate_digest()
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, RegistrationError> {
        if !self.is_active() {
            return Err(RegistrationError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(|_| RegistrationError::RevisionOverflow)?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            state: self.state,
        })
    }

    pub fn restore(&mut self) -> Result<(), RegistrationError> {
        if self.is_active() {
            return Err(RegistrationError::NotRevoked);
        }
        self.registration_revision = self
            .registration_revision
            .next()
            .map_err(|_| RegistrationError::RevisionOverflow)?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.calculate_digest();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadBounds {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_jobs: u16,
}

impl ReadBounds {
    pub fn new(max_pages: u16, page_size: u16, max_jobs: u16) -> Result<Self, ModelError> {
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::OutsideBound { field: "max pages" });
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::OutsideBound { field: "page size" });
        }
        if max_jobs == 0 || usize::from(max_jobs) > MAX_JOBS {
            return Err(ModelError::OutsideBound { field: "max jobs" });
        }
        Ok(Self {
            max_pages,
            page_size,
            max_jobs,
        })
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
            max_jobs: MAX_JOBS as u16,
        }
    }
}

pub type GcpDataflowJobResultBounds = ReadBounds;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpDataflowJobResultServiceError {
    #[error("Dataflow service contract drifted")]
    ContractDrift,
    #[error("Dataflow registration is revoked or invalid")]
    RegistrationRevoked,
    #[error("Dataflow secret reference is revoked")]
    SecretRevoked,
    #[error("Dataflow scope mismatch")]
    ScopeMismatch,
    #[error("Dataflow permission scope mismatch")]
    PermissionMismatch,
    #[error("Dataflow proposal is tampered or stale")]
    ProposalTampered,
    #[error("Dataflow provider record is tampered or stale")]
    RecordTampered,
    #[error("Dataflow observation is tampered or stale")]
    ObservationTampered,
    #[error("Mission revision is stale: expected {expected}, actual {actual}")]
    StaleMissionRevision {
        expected: Revision,
        actual: Revision,
    },
    #[error("Dataflow pagination loop detected")]
    PaginationLoop,
    #[error("unsupported Dataflow operation")]
    UnsupportedOperation,
    #[error("Dataflow model error: {0}")]
    Model(#[from] ModelError),
    #[error("Dataflow provider definition error: {0}")]
    ProviderDefinition(#[from] ProviderDefinitionError),
    #[error("Dataflow provider error: {0}")]
    Provider(#[from] GcpDataflowProviderError),
    #[error("Dataflow registration transition error: {0}")]
    Registration(#[from] RegistrationError),
}

pub struct GcpDataflowJobResultService<T>
where
    T: GcpDataflowTransport,
{
    definition: GcpDataflowJobResultServiceDefinition,
    provider: GcpDataflowProvider<T>,
    registration: GcpDataflowRegistration,
    bounds: ReadBounds,
}

impl<T> fmt::Debug for GcpDataflowJobResultService<T>
where
    T: GcpDataflowTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpDataflowJobResultService")
            .field("scope_digest", &self.provider.scope().scope_digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T> GcpDataflowJobResultService<T>
where
    T: GcpDataflowTransport,
{
    pub fn new(provider: GcpDataflowProvider<T>) -> Result<Self, GcpDataflowJobResultServiceError> {
        Self::with_bounds(provider, ReadBounds::default())
    }

    pub fn with_bounds(
        provider: GcpDataflowProvider<T>,
        bounds: ReadBounds,
    ) -> Result<Self, GcpDataflowJobResultServiceError> {
        let definition = GcpDataflowJobResultServiceDefinition::new();
        definition.validate()?;
        let registration = GcpDataflowRegistration::new(
            provider.scope(),
            provider.secret_reference(),
            provider.definition(),
        )?;
        Ok(Self {
            definition,
            provider,
            registration,
            bounds,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &GcpDataflowJobResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> Vec<GcpDataflowCapability> {
        self.definition.describe_capabilities()
    }

    #[must_use]
    pub fn scope(&self) -> &GcpDataflowJobResultScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &GcpDataflowRegistration {
        &self.registration
    }

    #[must_use]
    pub fn provider(&self) -> &GcpDataflowProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut GcpDataflowProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn bounds(&self) -> ReadBounds {
        self.bounds
    }

    #[must_use]
    pub fn provider_provenance(&self) -> TransportProvenance {
        self.provider.provenance()
    }

    pub fn compile_proposal(
        &self,
    ) -> Result<DataflowReadProposal, GcpDataflowJobResultServiceError> {
        match self.scope().job_selector {
            DataflowJobSelector::Any => self.propose_jobs_list(None),
            DataflowJobSelector::Exact { .. } => self.propose_job_get(),
        }
    }

    pub fn propose_jobs_list(
        &self,
        page_token: Option<crate::OpaquePageToken>,
    ) -> Result<DataflowReadProposal, GcpDataflowJobResultServiceError> {
        self.validate_active()?;
        let request = DataflowReadRequest::list(
            self.scope(),
            self.registration.provider_digest.clone(),
            self.registration.registration_digest.clone(),
            self.bounds.page_size,
            page_token,
        )?;
        Ok(DataflowReadProposal::new(
            request,
            self.registration.registration_digest.clone(),
        )?)
    }

    pub fn propose_job_get(
        &self,
    ) -> Result<DataflowReadProposal, GcpDataflowJobResultServiceError> {
        self.validate_active()?;
        let request = DataflowReadRequest::get(
            self.scope(),
            self.registration.provider_digest.clone(),
            self.registration.registration_digest.clone(),
        )?;
        Ok(DataflowReadProposal::new(
            request,
            self.registration.registration_digest.clone(),
        )?)
    }

    pub fn propose_job_metrics(
        &self,
    ) -> Result<DataflowReadProposal, GcpDataflowJobResultServiceError> {
        self.validate_active()?;
        let request = DataflowReadRequest::metrics(
            self.scope(),
            self.registration.provider_digest.clone(),
            self.registration.registration_digest.clone(),
        )?;
        Ok(DataflowReadProposal::new(
            request,
            self.registration.registration_digest.clone(),
        )?)
    }

    pub fn record_observation(
        &mut self,
        proposal: &DataflowReadProposal,
    ) -> Result<DataflowReadRecord, GcpDataflowJobResultServiceError> {
        self.validate_proposal(proposal)?;
        Ok(self.provider.execute(&proposal.request)?)
    }

    pub fn record_list_jobs(
        &mut self,
    ) -> Result<DataflowReadRecord, GcpDataflowJobResultServiceError> {
        let proposal = self.propose_jobs_list(None)?;
        self.record_observation(&proposal)
    }

    pub fn record_job_get(
        &mut self,
    ) -> Result<DataflowReadRecord, GcpDataflowJobResultServiceError> {
        let proposal = self.propose_job_get()?;
        self.record_observation(&proposal)
    }

    pub fn record_job_metrics(
        &mut self,
    ) -> Result<DataflowReadRecord, GcpDataflowJobResultServiceError> {
        let proposal = self.propose_job_metrics()?;
        self.record_observation(&proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &DataflowReadProposal,
        record: &DataflowReadRecord,
    ) -> Result<(), GcpDataflowJobResultServiceError> {
        self.validate_proposal(proposal)?;
        if !record.verify_digest()
            || record.request_digest != proposal.request.request_digest
            || record.registration_digest != self.registration.registration_digest
            || record.provider_digest != self.registration.provider_digest
            || record.scope_digest != self.scope().scope_digest()
            || record.permission_digest != self.scope().permission_digest()
            || record
                .jobs
                .iter()
                .any(|job| !job.matches_scope(self.scope()))
        {
            return Err(GcpDataflowJobResultServiceError::RecordTampered);
        }
        Ok(())
    }

    pub fn verify_observation(
        &self,
        evidence: &DataflowEvidence,
    ) -> Result<(), GcpDataflowJobResultServiceError> {
        self.validate_active()?;
        if !evidence.verify_digest()
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.provider_digest != self.registration.provider_digest
            || evidence.scope_digest != self.scope().scope_digest()
            || evidence.permission_digest != self.scope().permission_digest()
            || evidence
                .jobs
                .iter()
                .any(|job| !job.matches_scope(self.scope()))
        {
            return Err(GcpDataflowJobResultServiceError::ObservationTampered);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &DataflowReadProposal,
        record: &DataflowReadRecord,
    ) -> Result<(), GcpDataflowJobResultServiceError> {
        self.verify_proposal(proposal, record)
    }

    pub fn read(&mut self) -> Result<DataflowEvidence, GcpDataflowJobResultServiceError> {
        match self.scope().job_selector {
            DataflowJobSelector::Any => self.read_jobs_list_bounded(),
            DataflowJobSelector::Exact { .. } => self.read_job_bounded(),
        }
    }

    pub fn read_jobs_list_bounded(
        &mut self,
    ) -> Result<DataflowEvidence, GcpDataflowJobResultServiceError> {
        self.validate_active()?;
        let mut records = Vec::new();
        let mut page_token = None;
        let mut seen = BTreeSet::new();
        let mut state = EvidenceState::Complete;
        let mut failure_digest = None;
        for _ in 0..self.bounds.max_pages {
            let proposal = self.propose_jobs_list(page_token.clone())?;
            match self.record_observation(&proposal) {
                Ok(record) => {
                    if matches!(record.response_status, crate::ResponseStatus::Partial) {
                        state = EvidenceState::Partial;
                    }
                    page_token = record.next_page_token().cloned();
                    records.push(record);
                    let Some(token) = page_token.as_ref() else {
                        break;
                    };
                    if !seen.insert(token.digest()) {
                        state = EvidenceState::Partial;
                        failure_digest = Some(Digest::from_text("dataflow-pagination-loop"));
                        page_token = None;
                        break;
                    }
                }
                Err(GcpDataflowJobResultServiceError::Provider(error)) => {
                    state = error.evidence_state();
                    failure_digest = Some(error.diagnostic_digest());
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        if page_token.is_some() && failure_digest.is_none() {
            state = EvidenceState::Partial;
            failure_digest = Some(Digest::from_text("dataflow-page-bound-exceeded"));
        }
        self.build_evidence(&records, state, failure_digest)
    }

    pub fn read_list_bounded(
        &mut self,
    ) -> Result<DataflowEvidence, GcpDataflowJobResultServiceError> {
        self.read_jobs_list_bounded()
    }

    pub fn read_job_bounded(
        &mut self,
    ) -> Result<DataflowEvidence, GcpDataflowJobResultServiceError> {
        self.validate_active()?;
        let get_proposal = self.propose_job_get()?;
        let get_record = match self.record_observation(&get_proposal) {
            Ok(record) => record,
            Err(GcpDataflowJobResultServiceError::Provider(error)) => {
                return self.build_evidence(
                    &[],
                    error.evidence_state(),
                    Some(error.diagnostic_digest()),
                );
            }
            Err(error) => return Err(error),
        };
        let metrics_proposal = self.propose_job_metrics()?;
        let mut records = vec![get_record];
        let mut state = EvidenceState::Complete;
        let mut failure_digest = None;
        match self.record_observation(&metrics_proposal) {
            Ok(record) => {
                if matches!(record.response_status, crate::ResponseStatus::Partial) {
                    state = EvidenceState::Partial;
                }
                records.push(record);
            }
            Err(GcpDataflowJobResultServiceError::Provider(error)) => {
                state = match error.evidence_state() {
                    EvidenceState::AccessLost
                    | EvidenceState::NotFound
                    | EvidenceState::Conflict
                    | EvidenceState::ProviderUnknown
                    | EvidenceState::TimedOut
                    | EvidenceState::RateLimited => error.evidence_state(),
                    _ => EvidenceState::Partial,
                };
                failure_digest = Some(error.diagnostic_digest());
            }
            Err(error) => return Err(error),
        }
        self.build_evidence(&records, state, failure_digest)
    }

    pub fn read_get_bounded(
        &mut self,
    ) -> Result<DataflowEvidence, GcpDataflowJobResultServiceError> {
        self.read_job_bounded()
    }

    pub fn read_at_mission_revision(
        &self,
        actual: u64,
    ) -> Result<DataflowEvidence, GcpDataflowJobResultServiceError> {
        self.validate_active()?;
        let actual = Revision::new(actual)?;
        if actual != self.scope().mission.revision {
            return self.build_evidence(
                &[],
                EvidenceState::Stale,
                Some(Digest::from_serializable(&("stale-mission", actual))),
            );
        }
        self.build_evidence(&[], EvidenceState::Complete, None)
    }

    pub fn evidence_from_record(
        &self,
        record: &DataflowReadRecord,
    ) -> Result<DataflowEvidence, GcpDataflowJobResultServiceError> {
        self.validate_active()?;
        if record.registration_digest != self.registration.registration_digest {
            return Err(GcpDataflowJobResultServiceError::RecordTampered);
        }
        self.build_evidence(std::slice::from_ref(record), record.state, None)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, GcpDataflowJobResultServiceError> {
        Ok(self.registration.revoke()?)
    }

    pub fn restore_registration(&mut self) -> Result<(), GcpDataflowJobResultServiceError> {
        Ok(self.registration.restore()?)
    }

    pub fn consumer(
        self,
    ) -> Result<crate::MissionGcpDataflowConsumer<T>, GcpDataflowJobResultServiceError> {
        crate::MissionGcpDataflowConsumer::new(self)
            .map_err(|_| GcpDataflowJobResultServiceError::ContractDrift)
    }

    fn validate_active(&self) -> Result<(), GcpDataflowJobResultServiceError> {
        self.definition.validate()?;
        self.scope().consent.validate_at(Utc::now())?;
        if !self.registration.is_active() || !self.registration.verify_digest() {
            return Err(GcpDataflowJobResultServiceError::RegistrationRevoked);
        }
        self.provider
            .secret_reference()
            .validate(self.scope())
            .map_err(|_| GcpDataflowJobResultServiceError::SecretRevoked)
    }

    fn validate_proposal(
        &self,
        proposal: &DataflowReadProposal,
    ) -> Result<(), GcpDataflowJobResultServiceError> {
        self.validate_active()?;
        if !proposal.verify_digest()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.provider_digest != self.registration.provider_digest
            || proposal.request.scope_digest != self.scope().scope_digest()
            || proposal.request.permission_digest != self.scope().permission_digest()
        {
            return Err(GcpDataflowJobResultServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn build_evidence(
        &self,
        records: &[DataflowReadRecord],
        mut state: EvidenceState,
        failure_digest: Option<Digest>,
    ) -> Result<DataflowEvidence, GcpDataflowJobResultServiceError> {
        let mut jobs = BTreeMap::<crate::JobId, DataflowJobSummary>::new();
        let mut metrics = BTreeMap::<Digest, DataflowMetricSummary>::new();
        let mut request_receipts = Vec::<DataflowRequestReceipt>::new();
        let mut response_receipts = Vec::<DataflowResponseReceipt>::new();
        let mut record_digests = Vec::new();
        for record in records {
            if !record.verify_digest()
                || record.registration_digest != self.registration.registration_digest
                || record.provider_digest != self.registration.provider_digest
                || record.scope_digest != self.scope().scope_digest()
                || record.permission_digest != self.scope().permission_digest()
                || record
                    .jobs
                    .iter()
                    .any(|job| !job.matches_scope(self.scope()))
            {
                return Err(GcpDataflowJobResultServiceError::RecordTampered);
            }
            if matches!(record.response_status, crate::ResponseStatus::Partial) {
                state = EvidenceState::Partial;
            }
            request_receipts.push(record.request_receipt.clone());
            response_receipts.push(record.response_receipt.clone());
            record_digests.push(record.record_digest.clone());
            for job in &record.jobs {
                if let Some(existing) = jobs.get(&job.job_id) {
                    if existing.job_digest != job.job_digest {
                        return Err(GcpDataflowJobResultServiceError::RecordTampered);
                    }
                } else {
                    jobs.insert(job.job_id.clone(), job.clone());
                }
                if matches!(job.state, crate::DataflowJobState::ProviderUnknown) {
                    state = EvidenceState::ProviderUnknown;
                }
            }
            for metric in &record.metrics {
                if let Some(existing) = metrics.get(&metric.metric_digest) {
                    if existing != metric {
                        return Err(GcpDataflowJobResultServiceError::RecordTampered);
                    }
                } else {
                    metrics.insert(metric.metric_digest.clone(), metric.clone());
                }
            }
        }
        let jobs = jobs
            .into_values()
            .take(usize::from(self.bounds.max_jobs))
            .collect::<Vec<_>>();
        let metrics = metrics
            .into_values()
            .take(crate::model::MAX_METRICS_PER_JOB)
            .collect::<Vec<_>>();
        let request_digest = aggregate_request_digest(&request_receipts);
        let response_digest = aggregate_response_digest(&response_receipts);
        let result_digest = Digest::from_serializable(&(&jobs, &metrics));
        let mut digests = EvidenceDigests::new(
            self.registration.provider_digest.clone(),
            self.scope().permission_digest(),
            self.scope().scope_digest(),
            self.registration.registration_digest.clone(),
        );
        digests.job_digest = aggregate_job_digest(&jobs);
        digests.stage_digest = aggregate_stage_digest(&jobs);
        digests.metric_digest = aggregate_metric_digest(&metrics);
        digests.request_digest = request_digest;
        digests.response_digest = response_digest;
        digests.result_digest = result_digest;
        let operation = records
            .first()
            .map_or(DataflowOperation::ListJobs, |record| record.operation);
        let mut evidence = DataflowEvidence {
            schema_version: GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_DATAFLOW_JOB_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            operation,
            state,
            scope_digest: self.scope().scope_digest(),
            permission_digest: self.scope().permission_digest(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.registration.provider_digest.clone(),
            page_count: u16::try_from(records.len()).unwrap_or(u16::MAX),
            job_count: u16::try_from(jobs.len()).unwrap_or(u16::MAX),
            metric_count: u16::try_from(metrics.len()).unwrap_or(u16::MAX),
            jobs,
            metrics,
            request_receipts,
            response_receipts,
            record_digests,
            failure_digest,
            native: false,
            connected: false,
            first_party: false,
            provider_receipt: false,
            proposal_only: true,
            outcome_authority: false,
            work_product_adoption: false,
            digests: digests.clone(),
        };
        digests.evidence_digest = evidence.calculate_evidence_digest();
        evidence.digests = digests;
        Ok(evidence)
    }
}

pub type GcpDataflowService<T> = GcpDataflowJobResultService<T>;
pub type GcpDataflowResultService<T> = GcpDataflowJobResultService<T>;
pub type GcpDataflowRegistrationContract = GcpDataflowRegistration;

#[must_use]
pub fn service_id() -> &'static str {
    GCP_DATAFLOW_JOB_RESULT_SERVICE_ID
}

#[must_use]
pub fn provider_id() -> &'static str {
    GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID
}

#[must_use]
pub fn consumer_id() -> &'static str {
    MISSION_GCP_DATAFLOW_CONSUMER_ID
}

#[must_use]
pub fn provider_version_digest() -> Digest {
    Digest::from_text(GCP_DATAFLOW_JOB_RESULT_PROVIDER_VERSION_TEXT)
}

#[must_use]
pub fn evidence_policy_digest() -> Digest {
    Digest::from_text(GCP_DATAFLOW_JOB_RESULT_EVIDENCE_POLICY)
}

#[must_use]
pub fn permission_digest() -> Digest {
    Digest::from_serializable(&crate::PermissionScope::read_only())
}

#[must_use]
pub fn provider_provenance_is_layer1(provenance: TransportProvenance) -> bool {
    !provenance.is_native() && !provenance.is_connected() && !provenance.is_first_party()
}
