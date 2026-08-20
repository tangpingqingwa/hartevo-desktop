//! Provider and transport seams for bounded Dataflow job, list, and metric reads.
//!
//! The transport accepts fixture/recording/loopback responses only. No type in
//! this module resolves credentials or performs live HTTPS.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use thiserror::Error;

use crate::model::{
    DataflowJobSelector, DataflowJobState, DataflowJobSummary, DataflowMetricSummary,
    DataflowOperation, DataflowPipelineType, DataflowRequestReceipt, DataflowResponseReceipt,
    DataflowStageSummary, Digest, EvidenceState, GcpDataflowJobResultScope, JobId, Location,
    MAX_JOBS, MAX_METRICS_PER_JOB, MAX_OPAQUE_FILTER_BYTES, MAX_OPAQUE_PAGE_TOKEN_BYTES,
    MAX_RESPONSE_BYTES, MAX_STAGES_PER_JOB, MetricScalar, ModelError, ProjectId, ResponseStatus,
    TransportProvenance,
};
use crate::{
    GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID, GCP_DATAFLOW_JOB_RESULT_PROVIDER_SCHEMA,
    GCP_DATAFLOW_JOB_RESULT_PROVIDER_VERSION_TEXT, GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION,
};

pub const GCP_DATAFLOW_API_VERSION: &str = "v1b3";
pub const GCP_DATAFLOW_API_REVISION: &str =
    "dataflow-rest-v1b3-projects-locations-jobs-list-get-getMetrics";
pub const GCP_DATAFLOW_BASE_URL: &str = "https://dataflow.googleapis.com";
pub const GCP_DATAFLOW_PROVIDER_REVISION: &str = "gcp-dataflow-jobs-v1-r1";

/// An opaque page token. Only its digest can cross a proposal, receipt, or log boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken(String);

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ModelError::OutsideBound {
                field: "opaque page token",
            });
        }
        if value.len() > MAX_OPAQUE_PAGE_TOKEN_BYTES || value.chars().any(char::is_control) {
            return Err(ModelError::OutsideBound {
                field: "opaque page token",
            });
        }
        Ok(Self(value))
    }

    pub fn for_page(page: u16) -> Result<Self, ModelError> {
        Self::new(format!("fixture-dataflow-page-{page}"))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

pub type OpaqueCursor = OpaquePageToken;
pub type PageToken = OpaquePageToken;

/// An opaque provider filter bound to the complete exact scope.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueFilter(String);

impl OpaqueFilter {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_OPAQUE_FILTER_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::OutsideBound {
                field: "opaque Dataflow filter",
            });
        }
        Ok(Self(value))
    }

    pub fn for_scope(scope: &GcpDataflowJobResultScope) -> Result<Self, ModelError> {
        Self::new(format!(
            "project={}&location={}&job={:?}&pipelineType={}&stageAllowlistDigest={}&metricAllowlistDigest={}&revision={}",
            scope.gcp_project,
            scope.location,
            scope.job_selector,
            scope.pipeline_type,
            scope.stage_allowlist.digest(),
            scope.metric_allowlist.digest(),
            scope.job_revision
        ))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl fmt::Debug for OpaqueFilter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueFilter")
            .field("digest", &self.digest())
            .field("bytes", &self.0.len())
            .finish()
    }
}

impl Serialize for OpaqueFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest().as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    Server,
    Malformed,
    Network,
    BlockedEnvironment,
    RequestMismatch,
    PaginationLoop,
}

impl ProviderFailureClass {
    #[must_use]
    pub const fn evidence_state(self) -> EvidenceState {
        match self {
            Self::Unauthorized | Self::Forbidden => EvidenceState::AccessLost,
            Self::NotFound => EvidenceState::NotFound,
            Self::Conflict => EvidenceState::Conflict,
            Self::RateLimited => EvidenceState::RateLimited,
            Self::Timeout => EvidenceState::TimedOut,
            Self::PaginationLoop => EvidenceState::Partial,
            Self::Server
            | Self::Malformed
            | Self::Network
            | Self::BlockedEnvironment
            | Self::RequestMismatch => EvidenceState::ProviderUnknown,
        }
    }

    #[must_use]
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited => Some(429),
            Self::Timeout => Some(408),
            Self::Server => Some(500),
            Self::Malformed
            | Self::Network
            | Self::BlockedEnvironment
            | Self::RequestMismatch
            | Self::PaginationLoop => None,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpDataflowProviderError {
    #[error("Dataflow provider returned a bounded failure")]
    Failure {
        class: ProviderFailureClass,
        status_code: Option<u16>,
        diagnostic_digest: Digest,
        provenance: TransportProvenance,
    },
    #[error("Dataflow provider response was malformed or outside the allowlist")]
    InvalidResponse {
        diagnostic_digest: Digest,
        provenance: TransportProvenance,
    },
    #[error("Dataflow request did not match its exact bound")]
    RequestMismatch,
    #[error("Dataflow pagination loop detected")]
    PaginationLoop,
    #[error("unsupported Dataflow operation")]
    UnsupportedOperation,
    #[error("Dataflow provider definition error: {0}")]
    Definition(#[from] ProviderDefinitionError),
}

impl GcpDataflowProviderError {
    #[must_use]
    pub fn failure(
        class: ProviderFailureClass,
        status_code: Option<u16>,
        provenance: TransportProvenance,
    ) -> Self {
        let label = format!("dataflow-provider-{class:?}-{status_code:?}");
        Self::Failure {
            class,
            status_code,
            diagnostic_digest: Digest::from_text(label),
            provenance,
        }
    }

    #[must_use]
    pub fn from_status(status_code: u16, provenance: TransportProvenance) -> Self {
        let class = match status_code {
            401 => ProviderFailureClass::Unauthorized,
            403 => ProviderFailureClass::Forbidden,
            404 => ProviderFailureClass::NotFound,
            409 => ProviderFailureClass::Conflict,
            408 | 504 => ProviderFailureClass::Timeout,
            429 => ProviderFailureClass::RateLimited,
            500..=599 => ProviderFailureClass::Server,
            _ => ProviderFailureClass::Malformed,
        };
        Self::failure(class, Some(status_code), provenance)
    }

    #[must_use]
    pub fn blocked_env() -> Self {
        Self::failure(
            ProviderFailureClass::BlockedEnvironment,
            None,
            TransportProvenance::BlockedEnv,
        )
    }

    #[must_use]
    pub fn class(&self) -> Option<ProviderFailureClass> {
        match self {
            Self::Failure { class, .. } => Some(*class),
            Self::InvalidResponse { .. } => Some(ProviderFailureClass::Malformed),
            Self::RequestMismatch => Some(ProviderFailureClass::RequestMismatch),
            Self::PaginationLoop => Some(ProviderFailureClass::PaginationLoop),
            Self::UnsupportedOperation => None,
            Self::Definition(_) => Some(ProviderFailureClass::Malformed),
        }
    }

    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Failure { status_code, .. } => *status_code,
            _ => self.class().and_then(ProviderFailureClass::status_code),
        }
    }

    #[must_use]
    pub fn diagnostic_digest(&self) -> Digest {
        match self {
            Self::Failure {
                diagnostic_digest, ..
            }
            | Self::InvalidResponse {
                diagnostic_digest, ..
            } => diagnostic_digest.clone(),
            Self::RequestMismatch => Digest::from_text("dataflow-request-mismatch"),
            Self::PaginationLoop => Digest::from_text("dataflow-pagination-loop"),
            Self::UnsupportedOperation => Digest::from_text("dataflow-unsupported-operation"),
            Self::Definition(_) => Digest::from_text("dataflow-provider-definition"),
        }
    }

    #[must_use]
    pub fn evidence_state(&self) -> EvidenceState {
        self.class().map_or(
            EvidenceState::ProviderUnknown,
            ProviderFailureClass::evidence_state,
        )
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        match self {
            Self::Failure { provenance, .. } | Self::InvalidResponse { provenance, .. } => {
                *provenance
            }
            _ => TransportProvenance::Recording,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Dataflow provider version or revision is empty")]
    InvalidVersion,
    #[error("Dataflow provider definition is not the expected read-only Layer-1 definition")]
    InvalidDefinition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpDataflowProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub api_version: String,
    pub permission_names: Vec<String>,
    pub capability_digest: Digest,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl GcpDataflowProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provider_revision: impl Into<String>,
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        let provider_revision = provider_revision.into();
        if provider_version.trim().is_empty() || provider_revision.trim().is_empty() {
            return Err(ProviderDefinitionError::InvalidVersion);
        }
        let permission_names = permission_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let capability_digest = capability_digest(&permission_names);
        Ok(Self {
            schema_version: GCP_DATAFLOW_JOB_RESULT_PROVIDER_SCHEMA.to_owned(),
            provider_id: GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID.to_owned(),
            provider_version,
            provider_revision,
            api_version: GCP_DATAFLOW_API_VERSION.to_owned(),
            permission_names,
            capability_digest,
            provenance,
            read_only: true,
            native: false,
            connected: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        let expected_permissions = permission_names()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if self.schema_version != GCP_DATAFLOW_JOB_RESULT_PROVIDER_SCHEMA
            || self.provider_id != GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID
            || self.api_version != GCP_DATAFLOW_API_VERSION
            || self.permission_names != expected_permissions
            || self.capability_digest != capability_digest(&expected_permissions)
            || !self.read_only
            || self.native
            || self.connected
            || self.first_party
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
        {
            return Err(ProviderDefinitionError::InvalidDefinition);
        }
        Ok(())
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }
}

/// Raw response bytes are retained only inside a transport invocation.
#[derive(Clone, Eq, PartialEq)]
pub struct DataflowResponse {
    status_code: u16,
    body: Vec<u8>,
    provenance: TransportProvenance,
}

impl fmt::Debug for DataflowResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataflowResponse")
            .field("status_code", &self.status_code)
            .field("body_digest", &Digest::from_bytes(&self.body))
            .field("body_bytes", &self.body.len())
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl Serialize for DataflowResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DataflowResponse", 4)?;
        state.serialize_field("statusCode", &self.status_code)?;
        state.serialize_field("bodyDigest", &Digest::from_bytes(&self.body))?;
        state.serialize_field("bodyBytes", &self.body.len())?;
        state.serialize_field("provenance", &self.provenance)?;
        state.end()
    }
}

impl DataflowResponse {
    #[must_use]
    pub fn json<T: Serialize>(status_code: u16, value: &T) -> Self {
        Self::json_with_provenance(status_code, value, TransportProvenance::Fixture)
    }

    #[must_use]
    ///
    /// # Panics
    ///
    /// Panics only if the supplied fixture value cannot be serialized. The
    /// intended fixture values are bounded JSON-compatible models.
    pub fn json_with_provenance<T: Serialize>(
        status_code: u16,
        value: &T,
        provenance: TransportProvenance,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("Dataflow fixture JSON serializes");
        Self {
            status_code,
            body,
            provenance,
        }
    }

    #[must_use]
    pub fn new(status_code: u16, body: Vec<u8>) -> Self {
        Self {
            status_code,
            body,
            provenance: TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    fn body(&self) -> &[u8] {
        &self.body
    }

    fn receipt(&self) -> DataflowResponseReceipt {
        let body_digest = Digest::from_bytes(&self.body);
        DataflowResponseReceipt {
            status_code: self.status_code,
            body_digest: body_digest.clone(),
            body_bytes: self.body.len(),
            provenance: self.provenance,
            response_digest: Digest::from_serializable(&(
                self.status_code,
                &body_digest,
                self.body.len(),
                self.provenance,
            )),
        }
    }
}

/// A request is serializable only as a redacted projection.
#[derive(Clone, Eq, PartialEq)]
pub struct DataflowReadRequest {
    pub operation: DataflowOperation,
    pub method: String,
    pub path: String,
    pub project_id: ProjectId,
    pub location: Location,
    pub job_id: Option<JobId>,
    pub page_size: Option<u16>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    page_token: Option<OpaquePageToken>,
    filter: OpaqueFilter,
    pub request_digest: Digest,
}

impl fmt::Debug for DataflowReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataflowReadRequest")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("project_id", &self.project_id)
            .field("location", &self.location)
            .field("job_id", &self.job_id)
            .field("page_size", &self.page_size)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("provider_digest", &self.provider_digest)
            .field("registration_digest", &self.registration_digest)
            .field(
                "page_token_digest",
                &self.page_token.as_ref().map(OpaquePageToken::digest),
            )
            .field("filter_digest", &self.filter.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for DataflowReadRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("DataflowReadRequest", 15)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("projectId", &self.project_id)?;
        state.serialize_field("location", &self.location)?;
        state.serialize_field("jobId", &self.job_id)?;
        state.serialize_field("pageSize", &self.page_size)?;
        state.serialize_field(
            "pageTokenDigest",
            &self.page_token.as_ref().map(OpaquePageToken::digest),
        )?;
        state.serialize_field("filterDigest", &self.filter.digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

impl DataflowReadRequest {
    pub fn list(
        scope: &GcpDataflowJobResultScope,
        provider_digest: Digest,
        registration_digest: Digest,
        page_size: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > crate::model::MAX_PAGE_SIZE {
            return Err(ModelError::OutsideBound {
                field: "Dataflow page size",
            });
        }
        Self::build(
            DataflowOperation::ListJobs,
            scope,
            provider_digest,
            registration_digest,
            None,
            Some(page_size),
            page_token,
        )
    }

    pub fn get(
        scope: &GcpDataflowJobResultScope,
        provider_digest: Digest,
        registration_digest: Digest,
    ) -> Result<Self, ModelError> {
        let job_id = scope
            .job_selector
            .job_id()
            .cloned()
            .ok_or(ModelError::ScopeDrift)?;
        Self::build(
            DataflowOperation::GetJob,
            scope,
            provider_digest,
            registration_digest,
            Some(job_id),
            None,
            None,
        )
    }

    pub fn metrics(
        scope: &GcpDataflowJobResultScope,
        provider_digest: Digest,
        registration_digest: Digest,
    ) -> Result<Self, ModelError> {
        let job_id = scope
            .job_selector
            .job_id()
            .cloned()
            .ok_or(ModelError::ScopeDrift)?;
        Self::build(
            DataflowOperation::GetMetrics,
            scope,
            provider_digest,
            registration_digest,
            Some(job_id),
            None,
            None,
        )
    }

    fn build(
        operation: DataflowOperation,
        scope: &GcpDataflowJobResultScope,
        provider_digest: Digest,
        registration_digest: Digest,
        job_id: Option<JobId>,
        page_size: Option<u16>,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        let filter = OpaqueFilter::for_scope(scope)?;
        let path = match (&operation, &job_id) {
            (DataflowOperation::ListJobs, _) => format!(
                "/{GCP_DATAFLOW_API_VERSION}/projects/{}/locations/{}/jobs",
                scope.gcp_project, scope.location
            ),
            (DataflowOperation::GetJob, Some(job_id)) => format!(
                "/{GCP_DATAFLOW_API_VERSION}/projects/{}/locations/{}/jobs/{job_id}",
                scope.gcp_project, scope.location
            ),
            (DataflowOperation::GetMetrics, Some(job_id)) => format!(
                "/{GCP_DATAFLOW_API_VERSION}/projects/{}/locations/{}/jobs/{job_id}/getMetrics",
                scope.gcp_project, scope.location
            ),
            _ => return Err(ModelError::ScopeDrift),
        };
        let method = "GET".to_owned();
        let mut request = Self {
            operation,
            method,
            path,
            project_id: scope.gcp_project.clone(),
            location: scope.location.clone(),
            job_id,
            page_size,
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest(),
            provider_digest,
            registration_digest,
            page_token,
            filter,
            request_digest: Digest::from_text("unsealed-dataflow-request"),
        };
        request.request_digest = request.calculate_digest();
        Ok(request)
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.operation,
            &self.method,
            &self.path,
            &self.project_id,
            &self.location,
            &self.job_id,
            self.page_size,
            &self.page_token.as_ref().map(OpaquePageToken::digest),
            &self.filter.digest(),
            &self.scope_digest,
            &self.permission_digest,
            &self.provider_digest,
            &self.registration_digest,
        ))
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.request_digest == self.calculate_digest()
    }

    #[must_use]
    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaquePageToken::digest)
    }

    #[must_use]
    pub fn filter_digest(&self) -> Digest {
        self.filter.digest()
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub fn request_receipt(&self) -> DataflowRequestReceipt {
        DataflowRequestReceipt {
            operation: self.operation,
            method: self.method.clone(),
            path_digest: Digest::from_text(&self.path),
            project_digest: self.project_id.digest(),
            location_digest: self.location.digest(),
            job_digest: self.job_id.as_ref().map(JobId::digest),
            filter_digest: self.filter.digest(),
            page_token_digest: self.page_token_digest(),
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataflowReadProposal {
    pub request: DataflowReadRequest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
}

impl DataflowReadProposal {
    pub fn new(
        request: DataflowReadRequest,
        registration_digest: Digest,
    ) -> Result<Self, GcpDataflowProviderError> {
        if !request.verify_digest() {
            return Err(GcpDataflowProviderError::RequestMismatch);
        }
        let provider_digest = request.provider_digest.clone();
        let proposal_digest = Digest::from_serializable(&(
            &request.request_digest,
            &provider_digest,
            &registration_digest,
        ));
        Ok(Self {
            request,
            provider_digest,
            registration_digest,
            proposal_digest,
        })
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.request.verify_digest()
            && self.provider_digest == self.request.provider_digest
            && self.proposal_digest
                == Digest::from_serializable(&(
                    &self.request.request_digest,
                    &self.provider_digest,
                    &self.registration_digest,
                ))
    }

    #[must_use]
    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataflowReadRecord {
    pub operation: DataflowOperation,
    pub request_digest: Digest,
    pub provider_digest: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub jobs: Vec<DataflowJobSummary>,
    pub metrics: Vec<DataflowMetricSummary>,
    pub next_page_token_digest: Option<Digest>,
    pub request_receipt: DataflowRequestReceipt,
    pub response_receipt: DataflowResponseReceipt,
    pub response_status: ResponseStatus,
    pub state: EvidenceState,
    pub record_digest: Digest,
    #[serde(skip)]
    next_page_token: Option<OpaquePageToken>,
}

impl DataflowReadRecord {
    fn new(
        request: &DataflowReadRequest,
        jobs: Vec<DataflowJobSummary>,
        metrics: Vec<DataflowMetricSummary>,
        next_page_token: Option<OpaquePageToken>,
        response_receipt: DataflowResponseReceipt,
        response_status: ResponseStatus,
        state: EvidenceState,
    ) -> Self {
        let mut record = Self {
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            provider_digest: request.provider_digest.clone(),
            registration_digest: request.registration_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            jobs,
            metrics,
            next_page_token_digest: next_page_token.as_ref().map(OpaquePageToken::digest),
            request_receipt: request.request_receipt(),
            response_receipt,
            response_status,
            state,
            record_digest: Digest::from_text("unsealed-dataflow-record"),
            next_page_token,
        };
        record.record_digest = record.calculate_digest();
        record
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.operation,
            &self.request_digest,
            &self.provider_digest,
            &self.registration_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.jobs,
            &self.metrics,
            &self.next_page_token_digest,
            &self.request_receipt,
            &self.response_receipt,
            &self.response_status,
            self.state,
        ))
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.record_digest == self.calculate_digest()
            && self.jobs.iter().all(DataflowJobSummary::verify_digest)
    }

    #[must_use]
    pub fn next_page_token(&self) -> Option<&OpaquePageToken> {
        self.next_page_token.as_ref()
    }
}

pub type DataflowObservation = DataflowReadRecord;

/// Transport surface for the three allowlisted Dataflow GET operations.
pub trait GcpDataflowTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_jobs(
        &mut self,
        request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError>;

    fn get_job(
        &mut self,
        request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError>;

    fn get_metrics(
        &mut self,
        request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError>;
}

/// Typed provider with no credential resolution and no live HTTP authority.
pub struct GcpDataflowProvider<T>
where
    T: GcpDataflowTransport,
{
    scope: GcpDataflowJobResultScope,
    secret_reference: crate::SecretReference,
    definition: GcpDataflowProviderDefinition,
    transport: T,
}

impl<T> fmt::Debug for GcpDataflowProvider<T>
where
    T: GcpDataflowTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpDataflowProvider")
            .field("scope_digest", &self.scope.scope_digest())
            .field("provider_digest", &self.definition.provider_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provenance", &self.definition.provenance)
            .finish_non_exhaustive()
    }
}

impl<T> GcpDataflowProvider<T>
where
    T: GcpDataflowTransport,
{
    pub fn new(
        scope: GcpDataflowJobResultScope,
        secret_reference: crate::SecretReference,
        transport: T,
    ) -> Result<Self, GcpDataflowProviderError> {
        scope
            .validate()
            .map_err(|_| GcpDataflowProviderError::RequestMismatch)?;
        secret_reference
            .validate(&scope)
            .map_err(|_| GcpDataflowProviderError::RequestMismatch)?;
        let definition = GcpDataflowProviderDefinition::new(
            GCP_DATAFLOW_JOB_RESULT_PROVIDER_VERSION_TEXT,
            GCP_DATAFLOW_PROVIDER_REVISION,
            transport.provenance(),
        )?;
        definition.validate()?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            transport,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GcpDataflowJobResultScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &crate::SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &GcpDataflowProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn execute(
        &mut self,
        request: &DataflowReadRequest,
    ) -> Result<DataflowReadRecord, GcpDataflowProviderError> {
        if !request.verify_digest()
            || request.scope_digest != self.scope.scope_digest()
            || request.permission_digest != self.scope.permission_digest()
            || request.provider_digest != self.provider_digest()
        {
            return Err(GcpDataflowProviderError::RequestMismatch);
        }
        let response = match request.operation {
            DataflowOperation::ListJobs => self.transport.list_jobs(request),
            DataflowOperation::GetJob => self.transport.get_job(request),
            DataflowOperation::GetMetrics => self.transport.get_metrics(request),
        }?;
        self.parse_response(request, response)
    }

    pub fn read(
        &mut self,
        request: &DataflowReadRequest,
    ) -> Result<DataflowReadRecord, GcpDataflowProviderError> {
        self.execute(request)
    }

    fn parse_response(
        &self,
        request: &DataflowReadRequest,
        response: DataflowResponse,
    ) -> Result<DataflowReadRecord, GcpDataflowProviderError> {
        let receipt = response.receipt();
        if response.body().len() > MAX_RESPONSE_BYTES {
            return Err(GcpDataflowProviderError::InvalidResponse {
                diagnostic_digest: Digest::from_text("dataflow-response-too-large"),
                provenance: response.provenance,
            });
        }
        if response.status_code != 200 {
            return Err(GcpDataflowProviderError::from_status(
                response.status_code,
                response.provenance,
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(response.body()).map_err(|_| {
            GcpDataflowProviderError::InvalidResponse {
                diagnostic_digest: Digest::from_text("dataflow-response-invalid-json"),
                provenance: response.provenance,
            }
        })?;
        match request.operation {
            DataflowOperation::ListJobs => {
                let array = value.get("jobs").and_then(serde_json::Value::as_array);
                let Some(array) = array else {
                    return Ok(DataflowReadRecord::new(
                        request,
                        Vec::new(),
                        Vec::new(),
                        None,
                        receipt,
                        ResponseStatus::Partial,
                        EvidenceState::Partial,
                    ));
                };
                let mut jobs = array
                    .iter()
                    .map(|job| self.parse_job(job))
                    .collect::<Result<Vec<_>, _>>()?;
                jobs.sort_by(|left, right| left.job_id.cmp(&right.job_id));
                jobs.truncate(MAX_JOBS);
                let next_page_token = value
                    .get("nextPageToken")
                    .and_then(serde_json::Value::as_str)
                    .filter(|token| !token.is_empty())
                    .map(OpaquePageToken::new)
                    .transpose()
                    .map_err(|_| GcpDataflowProviderError::InvalidResponse {
                        diagnostic_digest: Digest::from_text("dataflow-page-token-invalid"),
                        provenance: response.provenance,
                    })?;
                Ok(DataflowReadRecord::new(
                    request,
                    jobs,
                    Vec::new(),
                    next_page_token,
                    receipt,
                    ResponseStatus::Complete,
                    EvidenceState::Complete,
                ))
            }
            DataflowOperation::GetJob => {
                let job = self.parse_job(&value)?;
                Ok(DataflowReadRecord::new(
                    request,
                    vec![job],
                    Vec::new(),
                    None,
                    receipt,
                    ResponseStatus::Complete,
                    EvidenceState::Complete,
                ))
            }
            DataflowOperation::GetMetrics => {
                let array = value.get("metrics").and_then(serde_json::Value::as_array);
                let Some(array) = array else {
                    return Ok(DataflowReadRecord::new(
                        request,
                        Vec::new(),
                        Vec::new(),
                        None,
                        receipt,
                        ResponseStatus::Partial,
                        EvidenceState::Partial,
                    ));
                };
                let mut metrics = array
                    .iter()
                    .filter_map(|metric| match self.parse_metric(metric) {
                        Ok(Some(metric)) => Some(Ok(metric)),
                        Ok(None) => None,
                        Err(error) => Some(Err(error)),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                metrics.sort_by(|left, right| left.metric_digest.cmp(&right.metric_digest));
                metrics.truncate(MAX_METRICS_PER_JOB);
                Ok(DataflowReadRecord::new(
                    request,
                    Vec::new(),
                    metrics,
                    None,
                    receipt,
                    ResponseStatus::Complete,
                    EvidenceState::Complete,
                ))
            }
        }
    }

    fn parse_job(
        &self,
        value: &serde_json::Value,
    ) -> Result<DataflowJobSummary, GcpDataflowProviderError> {
        let object =
            value
                .as_object()
                .ok_or_else(|| GcpDataflowProviderError::InvalidResponse {
                    diagnostic_digest: Digest::from_text("dataflow-job-not-object"),
                    provenance: self.provenance(),
                })?;
        let job_id = object
            .get("id")
            .or_else(|| object.get("jobId"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| GcpDataflowProviderError::InvalidResponse {
                diagnostic_digest: Digest::from_text("dataflow-job-id-missing"),
                provenance: self.provenance(),
            })?;
        let job_id = JobId::new(job_id).map_err(|_| GcpDataflowProviderError::InvalidResponse {
            diagnostic_digest: Digest::from_text("dataflow-job-id-invalid"),
            provenance: self.provenance(),
        })?;
        if self
            .scope
            .job_selector
            .job_id()
            .is_some_and(|expected| expected != &job_id)
        {
            return Err(GcpDataflowProviderError::InvalidResponse {
                diagnostic_digest: Digest::from_text("dataflow-job-id-drift"),
                provenance: self.provenance(),
            });
        }
        let project_id = object
            .get("projectId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(self.scope.gcp_project.as_str());
        let project_id =
            ProjectId::new(project_id).map_err(|_| GcpDataflowProviderError::InvalidResponse {
                diagnostic_digest: Digest::from_text("dataflow-project-id-invalid"),
                provenance: self.provenance(),
            })?;
        let location = object
            .get("location")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(self.scope.location.as_str());
        let location =
            Location::new(location).map_err(|_| GcpDataflowProviderError::InvalidResponse {
                diagnostic_digest: Digest::from_text("dataflow-location-invalid"),
                provenance: self.provenance(),
            })?;
        let pipeline_type = object
            .get("type")
            .or_else(|| object.get("pipelineType"))
            .and_then(serde_json::Value::as_str)
            .map_or(
                DataflowPipelineType::Unknown,
                DataflowPipelineType::from_provider,
            );
        if project_id != self.scope.gcp_project
            || location != self.scope.location
            || pipeline_type != self.scope.pipeline_type
        {
            return Err(GcpDataflowProviderError::InvalidResponse {
                diagnostic_digest: Digest::from_text("dataflow-job-scope-drift"),
                provenance: self.provenance(),
            });
        }
        let state = object
            .get("currentState")
            .or_else(|| object.get("state"))
            .and_then(serde_json::Value::as_str)
            .map_or(
                DataflowJobState::ProviderUnknown,
                DataflowJobState::from_provider,
            );
        let create_time = parse_time(object.get("createTime"));
        let start_time = parse_time(object.get("startTime"));
        let state_time = parse_time(
            object
                .get("currentStateTime")
                .or_else(|| object.get("stateTime")),
        );
        let end_time = parse_time(object.get("endTime").or_else(|| object.get("finishTime")));
        if let (Some(start), Some(create)) = (start_time, create_time)
            && start < create
        {
            return Err(GcpDataflowProviderError::InvalidResponse {
                diagnostic_digest: Digest::from_text("dataflow-job-timing-invalid"),
                provenance: self.provenance(),
            });
        }
        let name_digest = object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .map(Digest::from_text);
        let replacement_job_digest = object
            .get("replaceJobId")
            .or_else(|| object.get("replacedByJobId"))
            .and_then(serde_json::Value::as_str)
            .map(Digest::from_text);
        let stages = self.parse_stages(object);
        let error_digest = object.get("error").map(|error| {
            let bytes = serde_json::to_vec(error).unwrap_or_default();
            Digest::from_bytes(&bytes[..bytes.len().min(crate::model::MAX_DIAGNOSTIC_BYTES)])
        });
        Ok(DataflowJobSummary::new(
            job_id,
            project_id,
            location,
            pipeline_type,
            self.scope.job_revision,
            state,
            create_time,
            start_time,
            state_time,
            end_time,
            name_digest,
            replacement_job_digest,
            stages,
            error_digest,
        ))
    }

    fn parse_stages(
        &self,
        object: &serde_json::Map<String, serde_json::Value>,
    ) -> Vec<DataflowStageSummary> {
        let Some(array) = object
            .get("steps")
            .or_else(|| object.get("stages"))
            .or_else(|| object.get("stageSummaries"))
            .and_then(serde_json::Value::as_array)
        else {
            return Vec::new();
        };
        let mut stages = array
            .iter()
            .filter_map(|stage| {
                let object = stage.as_object()?;
                let name = object
                    .get("name")
                    .or_else(|| object.get("id"))
                    .or_else(|| object.get("stageName"))
                    .or_else(|| object.get("stepName"))
                    .and_then(serde_json::Value::as_str)?;
                if !self.scope.stage_allowlist.contains(name) {
                    return None;
                }
                let state = object
                    .get("state")
                    .or_else(|| object.get("status"))
                    .and_then(serde_json::Value::as_str)
                    .map(DataflowJobState::from_provider);
                let metric_count = object
                    .get("metricCount")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
                    .min(u64::from(u16::MAX)) as u16;
                DataflowStageSummary::new(name, state, metric_count).ok()
            })
            .collect::<Vec<_>>();
        stages.sort_by(|left, right| left.stage_digest.cmp(&right.stage_digest));
        stages.dedup_by(|left, right| left.stage_digest == right.stage_digest);
        stages.truncate(MAX_STAGES_PER_JOB);
        stages
    }

    fn parse_metric(
        &self,
        value: &serde_json::Value,
    ) -> Result<Option<DataflowMetricSummary>, GcpDataflowProviderError> {
        let object =
            value
                .as_object()
                .ok_or_else(|| GcpDataflowProviderError::InvalidResponse {
                    diagnostic_digest: Digest::from_text("dataflow-metric-not-object"),
                    provenance: self.provenance(),
                })?;
        let name = object
            .get("name")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                object
                    .get("metricName")
                    .and_then(serde_json::Value::as_object)
                    .and_then(|metric| metric.get("name"))
                    .and_then(serde_json::Value::as_str)
            });
        let Some(name) = name else {
            return Ok(None);
        };
        if !self.scope.metric_allowlist.contains(name) {
            return Ok(None);
        }
        let scalar = object.get("scalar").and_then(parse_scalar);
        let unit = object.get("unit").and_then(serde_json::Value::as_str);
        let tentative = object
            .get("tentative")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let update_time = parse_time(object.get("updateTime"));
        DataflowMetricSummary::new(name, scalar, unit, tentative, update_time)
            .map(Some)
            .map_err(|_| GcpDataflowProviderError::InvalidResponse {
                diagnostic_digest: Digest::from_text("dataflow-metric-invalid"),
                provenance: self.provenance(),
            })
    }
}

fn parse_time(value: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    value
        .and_then(serde_json::Value::as_str)
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(|time| time.with_timezone(&Utc))
}

fn parse_scalar(value: &serde_json::Value) -> Option<MetricScalar> {
    let candidate = value
        .get("integerValue")
        .or_else(|| value.get("doubleValue"))
        .or_else(|| value.get("floatValue"))
        .unwrap_or(value);
    if let Some(integer) = candidate.as_i64() {
        return Some(MetricScalar::Integer(integer));
    }
    if let Some(integer) = candidate.as_str().and_then(|text| text.parse::<i64>().ok()) {
        return Some(MetricScalar::Integer(integer));
    }
    if let Some(decimal) = candidate.as_f64() {
        let text = decimal.to_string();
        return (text.len() <= crate::model::MAX_METRIC_VALUE_BYTES)
            .then_some(MetricScalar::Decimal(text));
    }
    candidate.as_str().and_then(|text| {
        (text.len() <= crate::model::MAX_METRIC_VALUE_BYTES)
            .then_some(MetricScalar::Decimal(text.to_owned()))
    })
}

fn capability_digest(permission_names: &[String]) -> Digest {
    Digest::from_serializable(&(
        GCP_DATAFLOW_JOB_RESULT_SCHEMA_VERSION,
        GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID,
        GCP_DATAFLOW_API_REVISION,
        permission_names,
        "list_getMetrics_lifecycle_stage_metric_projection",
        "no_create_update_cancel_drain_logs_options_workers_secrets",
    ))
}

#[must_use]
pub fn permission_names() -> [&'static str; 3] {
    [
        "dataflow.jobs.list",
        "dataflow.jobs.get",
        "dataflow.jobs.getMetrics",
    ]
}

#[must_use]
pub fn provider_failure_projection(error: &GcpDataflowProviderError) -> EvidenceState {
    error.evidence_state()
}

#[must_use]
pub fn project_digest(project: &ProjectId) -> Digest {
    project.digest()
}

#[must_use]
pub fn job_selector_digest(selector: &DataflowJobSelector) -> Digest {
    selector.digest()
}

#[must_use]
pub fn job_state_projection(state: DataflowJobState) -> Digest {
    Digest::from_serializable(&state)
}

/// Fixture transport. It is deterministic and always non-native/non-connected.
#[derive(Clone, Debug, Default)]
pub struct FixtureGcpDataflowTransport {
    list: VecDeque<Result<DataflowResponse, GcpDataflowProviderError>>,
    get: VecDeque<Result<DataflowResponse, GcpDataflowProviderError>>,
    metrics: VecDeque<Result<DataflowResponse, GcpDataflowProviderError>>,
}

impl FixtureGcpDataflowTransport {
    #[must_use]
    pub fn new(response: DataflowResponse) -> Self {
        let response = response.with_provenance(TransportProvenance::Fixture);
        Self {
            list: VecDeque::from([Ok(response.clone())]),
            get: VecDeque::from([Ok(response.clone())]),
            metrics: VecDeque::from([Ok(response)]),
        }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_response(response: DataflowResponse) -> Self {
        Self::new(response)
    }

    pub fn from_responses(
        list: Option<DataflowResponse>,
        get: Option<DataflowResponse>,
        metrics: Option<DataflowResponse>,
    ) -> Self {
        let mut transport = Self::empty();
        if let Some(response) = list {
            transport.push_list_response(response);
        }
        if let Some(response) = get {
            transport.push_get_response(response);
        }
        if let Some(response) = metrics {
            transport.push_metrics_response(response);
        }
        transport
    }

    pub fn push_list_response(&mut self, response: DataflowResponse) {
        self.list
            .push_back(Ok(response.with_provenance(TransportProvenance::Fixture)));
    }

    pub fn push_get_response(&mut self, response: DataflowResponse) {
        self.get
            .push_back(Ok(response.with_provenance(TransportProvenance::Fixture)));
    }

    pub fn push_metrics_response(&mut self, response: DataflowResponse) {
        self.metrics
            .push_back(Ok(response.with_provenance(TransportProvenance::Fixture)));
    }

    fn pop(
        queue: &mut VecDeque<Result<DataflowResponse, GcpDataflowProviderError>>,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        queue.pop_front().unwrap_or_else(|| {
            Err(GcpDataflowProviderError::failure(
                ProviderFailureClass::Server,
                None,
                TransportProvenance::Fixture,
            ))
        })
    }
}

impl GcpDataflowTransport for FixtureGcpDataflowTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_jobs(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        Self::pop(&mut self.list)
    }

    fn get_job(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        Self::pop(&mut self.get)
    }

    fn get_metrics(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        Self::pop(&mut self.metrics)
    }
}

pub type FakeGcpDataflowTransport = FixtureGcpDataflowTransport;

/// Recording transport used by deterministic tests and replay recordings.
#[derive(Clone, Debug, Default)]
pub struct RecordingGcpDataflowTransport {
    list: VecDeque<Result<DataflowResponse, GcpDataflowProviderError>>,
    get: VecDeque<Result<DataflowResponse, GcpDataflowProviderError>>,
    metrics: VecDeque<Result<DataflowResponse, GcpDataflowProviderError>>,
}

impl RecordingGcpDataflowTransport {
    #[must_use]
    pub fn new(response: DataflowResponse) -> Self {
        let mut transport = Self::empty();
        transport.push_list_response(response);
        transport
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn from_response(response: DataflowResponse) -> Self {
        Self::new(response)
    }

    pub fn push_list_response(&mut self, response: DataflowResponse) {
        self.list
            .push_back(Ok(response.with_provenance(TransportProvenance::Recording)));
    }

    pub fn push_get_response(&mut self, response: DataflowResponse) {
        self.get
            .push_back(Ok(response.with_provenance(TransportProvenance::Recording)));
    }

    pub fn push_metrics_response(&mut self, response: DataflowResponse) {
        self.metrics
            .push_back(Ok(response.with_provenance(TransportProvenance::Recording)));
    }

    pub fn push_list_failure(&mut self, error: GcpDataflowProviderError) {
        self.list.push_back(Err(error));
    }

    pub fn push_get_failure(&mut self, error: GcpDataflowProviderError) {
        self.get.push_back(Err(error));
    }

    pub fn push_metrics_failure(&mut self, error: GcpDataflowProviderError) {
        self.metrics.push_back(Err(error));
    }

    fn pop(
        queue: &mut VecDeque<Result<DataflowResponse, GcpDataflowProviderError>>,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        queue.pop_front().unwrap_or_else(|| {
            Err(GcpDataflowProviderError::failure(
                ProviderFailureClass::Server,
                None,
                TransportProvenance::Recording,
            ))
        })
    }
}

impl GcpDataflowTransport for RecordingGcpDataflowTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn list_jobs(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        Self::pop(&mut self.list)
    }

    fn get_job(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        Self::pop(&mut self.get)
    }

    fn get_metrics(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        Self::pop(&mut self.metrics)
    }
}

pub type RecordingTransport = RecordingGcpDataflowTransport;

/// Loopback transport never represents a connected provider.
#[derive(Clone, Debug, Default)]
pub struct LoopbackGcpDataflowTransport {
    responses: VecDeque<DataflowResponse>,
}

impl LoopbackGcpDataflowTransport {
    #[must_use]
    pub fn new(responses: Vec<DataflowResponse>) -> Self {
        Self {
            responses: responses
                .into_iter()
                .map(|response| response.with_provenance(TransportProvenance::Loopback))
                .collect(),
        }
    }

    fn pop(&mut self) -> Result<DataflowResponse, GcpDataflowProviderError> {
        self.responses.pop_front().ok_or_else(|| {
            GcpDataflowProviderError::failure(
                ProviderFailureClass::Network,
                None,
                TransportProvenance::Loopback,
            )
        })
    }
}

impl GcpDataflowTransport for LoopbackGcpDataflowTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_jobs(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        self.pop()
    }

    fn get_job(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        self.pop()
    }

    fn get_metrics(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        self.pop()
    }
}

pub type LoopbackTransport = LoopbackGcpDataflowTransport;

/// Explicitly blocked native environment marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpDataflowTransport;

impl GcpDataflowTransport for BlockedEnvGcpDataflowTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_jobs(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        Err(GcpDataflowProviderError::blocked_env())
    }

    fn get_job(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        Err(GcpDataflowProviderError::blocked_env())
    }

    fn get_metrics(
        &mut self,
        _request: &DataflowReadRequest,
    ) -> Result<DataflowResponse, GcpDataflowProviderError> {
        Err(GcpDataflowProviderError::blocked_env())
    }
}

pub type BlockedEnvTransport = BlockedEnvGcpDataflowTransport;

pub fn fake_page_token_for_page(page: u16) -> Result<OpaquePageToken, ModelError> {
    OpaquePageToken::for_page(page)
}
