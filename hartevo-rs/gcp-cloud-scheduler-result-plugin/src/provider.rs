//! Provider and transport seams for bounded Cloud Scheduler list/get reads.
//!
//! There is deliberately no HTTP client, credential resolver, or mutation
//! method in this module. The only transport implementations are fixture,
//! recording, loopback, and explicit BLOCKED_ENV seams.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use serde_json::{Value, json};
use thiserror::Error;

use crate::model::{
    CloudSchedulerOperation, CloudSchedulerRequestReceipt, CloudSchedulerResponseReceipt, Digest,
    GcpCloudSchedulerScope, JobId, Location, MAX_JOBS, MAX_OPAQUE_PAGE_TOKEN_BYTES, MAX_PAGE_SIZE,
    MAX_RESPONSE_BYTES, ModelError, ProjectId, Revision, ScheduleExpression, SchedulerJobState,
    SchedulerJobSummary, SecretReference, TargetKind, TargetSummary, TransportProvenance,
};
use crate::{
    GCP_CLOUD_SCHEDULER_BLOCKED_ENV, GCP_CLOUD_SCHEDULER_PROVIDER_ID,
    GCP_CLOUD_SCHEDULER_PROVIDER_SCHEMA, GCP_CLOUD_SCHEDULER_PROVIDER_VERSION_TEXT,
    GCP_CLOUD_SCHEDULER_SCHEMA_VERSION,
};

pub const GCP_CLOUD_SCHEDULER_API_VERSION: &str = "v1";
pub const GCP_CLOUD_SCHEDULER_API_REVISION: &str =
    "cloud-scheduler-rest-v1-projects-locations-jobs-list-get";
pub const GCP_CLOUD_SCHEDULER_BASE_URL: &str = "https://cloudscheduler.googleapis.com";
pub const GCP_CLOUD_SCHEDULER_PROVIDER_REVISION: &str = "gcp-cloud-scheduler-v1-r1";

/// A page token stays private to the provider. Debug and serde expose only a
/// digest, so recordings cannot accidentally become credential-like material.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    value: String,
    digest: Digest,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_OPAQUE_PAGE_TOKEN_BYTES {
            return Err(ModelError::InvalidText {
                field: "opaque page token",
            });
        }
        if value.trim() != value || value.chars().any(char::is_control) {
            return Err(ModelError::InvalidText {
                field: "opaque page token",
            });
        }
        Ok(Self {
            digest: Digest::from_text(&value),
            value,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for OpaquePageToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpaquePageToken", 1)?;
        state.serialize_field("digest", &self.digest)?;
        state.end()
    }
}

pub type OpaqueCursor = OpaquePageToken;
pub type PageToken = OpaquePageToken;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Server,
    Timeout,
    Malformed,
    ScopeDrift,
    PaginationLoop,
    RequestTampered,
    ResponseTampered,
    BlockedEnv,
}

impl ProviderFailureClass {
    #[must_use]
    pub const fn evidence_state(self) -> crate::EvidenceState {
        match self {
            Self::Unauthorized | Self::Forbidden | Self::BlockedEnv => {
                crate::EvidenceState::AccessLost
            }
            Self::NotFound => crate::EvidenceState::NotFound,
            Self::Conflict => crate::EvidenceState::Conflict,
            Self::RateLimited => crate::EvidenceState::RateLimited,
            Self::Timeout => crate::EvidenceState::Timeout,
            Self::ScopeDrift => crate::EvidenceState::Stale,
            Self::PaginationLoop | Self::Malformed => crate::EvidenceState::Partial,
            Self::Server | Self::RequestTampered | Self::ResponseTampered => {
                crate::EvidenceState::ProviderUnknown
            }
        }
    }

    #[must_use]
    pub const fn from_status(status: u16) -> Option<Self> {
        match status {
            408 => Some(Self::Timeout),
            401 => Some(Self::Unauthorized),
            403 => Some(Self::Forbidden),
            404 => Some(Self::NotFound),
            409 => Some(Self::Conflict),
            429 => Some(Self::RateLimited),
            500..=599 => Some(Self::Server),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpCloudSchedulerProviderError {
    #[error("Cloud Scheduler provider failure: {class:?} ({status_code:?})")]
    Failure {
        class: ProviderFailureClass,
        status_code: Option<u16>,
        response_digest: Option<Digest>,
        diagnostic_digest: Digest,
        provenance: TransportProvenance,
    },
    #[error("Cloud Scheduler request model is invalid: {0}")]
    InvalidRequest(#[from] ModelError),
}

impl GcpCloudSchedulerProviderError {
    #[must_use]
    pub fn failure(
        class: ProviderFailureClass,
        status_code: Option<u16>,
        response_digest: Option<Digest>,
        provenance: TransportProvenance,
    ) -> Self {
        let diagnostic_digest = Digest::from_serializable(&(class, status_code, &response_digest));
        Self::Failure {
            class,
            status_code,
            response_digest,
            diagnostic_digest,
            provenance,
        }
    }

    #[must_use]
    pub fn blocked_env() -> Self {
        Self::failure(
            ProviderFailureClass::BlockedEnv,
            None,
            Some(Digest::from_text(GCP_CLOUD_SCHEDULER_BLOCKED_ENV)),
            TransportProvenance::BlockedEnv,
        )
    }

    #[must_use]
    pub fn timeout(provenance: TransportProvenance) -> Self {
        Self::failure(ProviderFailureClass::Timeout, Some(408), None, provenance)
    }

    #[must_use]
    pub const fn class(&self) -> Option<ProviderFailureClass> {
        match self {
            Self::Failure { class, .. } => Some(*class),
            Self::InvalidRequest(_) => None,
        }
    }

    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Failure { status_code, .. } => *status_code,
            Self::InvalidRequest(_) => None,
        }
    }

    #[must_use]
    pub fn diagnostic_digest(&self) -> Digest {
        match self {
            Self::Failure {
                diagnostic_digest, ..
            } => diagnostic_digest.clone(),
            Self::InvalidRequest(error) => Digest::from_text(error.to_string()),
        }
    }

    #[must_use]
    pub fn response_digest(&self) -> Option<Digest> {
        match self {
            Self::Failure {
                response_digest, ..
            } => response_digest.clone(),
            Self::InvalidRequest(_) => None,
        }
    }

    #[must_use]
    pub const fn provenance(&self) -> TransportProvenance {
        match self {
            Self::Failure { provenance, .. } => *provenance,
            Self::InvalidRequest(_) => TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn evidence_state(&self) -> crate::EvidenceState {
        match self.class() {
            Some(class) => class.evidence_state(),
            None => crate::EvidenceState::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("provider secret reference is revoked or not bound to the exact scope")]
    InvalidSecret,
    #[error("provider definition is invalid: {0}")]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudSchedulerProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub api_version: String,
    pub capability_digest: Digest,
    pub provenance: TransportProvenance,
    pub jobs_list: bool,
    pub jobs_get: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
}

impl GcpCloudSchedulerProviderDefinition {
    pub fn new(provenance: TransportProvenance) -> Result<Self, ProviderDefinitionError> {
        let provider_version = GCP_CLOUD_SCHEDULER_PROVIDER_VERSION_TEXT.to_owned();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        let capability_digest = Digest::from_serializable(&(
            GCP_CLOUD_SCHEDULER_PROVIDER_SCHEMA,
            GCP_CLOUD_SCHEDULER_PROVIDER_ID,
            &provider_version,
            GCP_CLOUD_SCHEDULER_PROVIDER_REVISION,
            GCP_CLOUD_SCHEDULER_API_VERSION,
            provenance,
            ["jobs.list", "jobs.get"],
            ["live_execution=false", "native=false", "connected=false"],
        ));
        Ok(Self {
            schema_version: GCP_CLOUD_SCHEDULER_SCHEMA_VERSION.to_owned(),
            provider_id: GCP_CLOUD_SCHEDULER_PROVIDER_ID.to_owned(),
            provider_version,
            provider_revision: GCP_CLOUD_SCHEDULER_PROVIDER_REVISION.to_owned(),
            api_version: GCP_CLOUD_SCHEDULER_API_VERSION.to_owned(),
            capability_digest,
            provenance,
            jobs_list: true,
            jobs_get: true,
            live_execution: false,
            native: false,
            connected: false,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.schema_version != GCP_CLOUD_SCHEDULER_SCHEMA_VERSION
            || self.provider_id != GCP_CLOUD_SCHEDULER_PROVIDER_ID
            || self.provider_version != GCP_CLOUD_SCHEDULER_PROVIDER_VERSION_TEXT
            || self.provider_revision != GCP_CLOUD_SCHEDULER_PROVIDER_REVISION
            || self.api_version != GCP_CLOUD_SCHEDULER_API_VERSION
            || !self.jobs_list
            || !self.jobs_get
            || self.live_execution
            || self.native
            || self.connected
        {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        Ok(())
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn is_native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

pub type GcpCloudSchedulerProviderContract = GcpCloudSchedulerProviderDefinition;

#[derive(Clone, Eq, PartialEq)]
pub struct CloudSchedulerResponse {
    status_code: u16,
    body: Vec<u8>,
    provenance: TransportProvenance,
}

impl fmt::Debug for CloudSchedulerResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudSchedulerResponse")
            .field("status_code", &self.status_code)
            .field("body_digest", &Digest::from_bytes(&self.body))
            .field("body_bytes", &self.body.len())
            .field("provenance", &self.provenance)
            .finish()
    }
}

impl Serialize for CloudSchedulerResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CloudSchedulerResponse", 4)?;
        state.serialize_field("statusCode", &self.status_code)?;
        state.serialize_field("bodyDigest", &Digest::from_bytes(&self.body))?;
        state.serialize_field("bodyBytes", &self.body.len())?;
        state.serialize_field("provenance", &self.provenance)?;
        state.end()
    }
}

impl CloudSchedulerResponse {
    #[must_use]
    pub fn json(status_code: u16, value: &Value) -> Self {
        Self::json_with_provenance(status_code, value, TransportProvenance::Fixture)
    }

    #[must_use]
    pub fn json_with_provenance(
        status_code: u16,
        value: &Value,
        provenance: TransportProvenance,
    ) -> Self {
        Self {
            status_code,
            body: serde_json::to_vec(value).expect("bounded Scheduler response serializes"),
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

    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    #[must_use]
    pub fn receipt(&self) -> CloudSchedulerResponseReceipt {
        CloudSchedulerResponseReceipt {
            status_code: self.status_code,
            body_digest: Digest::from_bytes(&self.body),
            body_bytes: self.body.len(),
            provenance: self.provenance,
        }
    }

    #[must_use]
    pub const fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudSchedulerReadRequest {
    pub operation: CloudSchedulerOperation,
    pub method: String,
    pub path: String,
    pub project_id: ProjectId,
    pub location: Location,
    pub job_id: Option<JobId>,
    pub page_size: u16,
    pub page_token: Option<OpaquePageToken>,
    pub schedule_digest: Digest,
    pub target_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub secret_reference_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub credential_revision: Revision,
    pub request_digest: Digest,
}

impl CloudSchedulerReadRequest {
    pub fn list(
        scope: &GcpCloudSchedulerScope,
        provider_digest: Digest,
        registration_digest: Digest,
        page_size: u16,
        page_token: Option<OpaquePageToken>,
        secret_reference: &SecretReference,
    ) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::OutsideBound { field: "page size" });
        }
        let path = format!(
            "/{GCP_CLOUD_SCHEDULER_API_VERSION}/projects/{}/locations/{}/jobs",
            scope.gcp_project.as_str(),
            scope.location.as_str()
        );
        let mut request = Self {
            operation: CloudSchedulerOperation::List,
            method: "GET".to_owned(),
            path,
            project_id: scope.gcp_project.clone(),
            location: scope.location.clone(),
            job_id: None,
            page_size,
            page_token,
            schedule_digest: scope.schedule_digest(),
            target_digest: scope.target_digest(),
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest(),
            registration_digest,
            provider_digest: provider_digest.clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            project_revision: scope.project_revision(),
            mission_revision: scope.mission_revision(),
            work_product_revision: scope.work_product_revision(),
            credential_revision: secret_reference.revision(),
            request_digest: Digest::from_text("placeholder"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn get(
        scope: &GcpCloudSchedulerScope,
        provider_digest: Digest,
        registration_digest: Digest,
        secret_reference: &SecretReference,
    ) -> Result<Self, ModelError> {
        let job_id = scope.job_id().cloned().ok_or(ModelError::InvalidScope)?;
        let path = format!(
            "/{GCP_CLOUD_SCHEDULER_API_VERSION}/projects/{}/locations/{}/jobs/{}",
            scope.gcp_project.as_str(),
            scope.location.as_str(),
            job_id.as_str()
        );
        let mut request = Self {
            operation: CloudSchedulerOperation::Get,
            method: "GET".to_owned(),
            path,
            project_id: scope.gcp_project.clone(),
            location: scope.location.clone(),
            job_id: Some(job_id),
            page_size: 1,
            page_token: None,
            schedule_digest: scope.schedule_digest(),
            target_digest: scope.target_digest(),
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest(),
            registration_digest,
            provider_digest,
            secret_reference_digest: secret_reference.reference_digest().clone(),
            project_revision: scope.project_revision(),
            mission_revision: scope.mission_revision(),
            work_product_revision: scope.work_product_revision(),
            credential_revision: secret_reference.revision(),
            request_digest: Digest::from_text("placeholder"),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Input<'a> {
            operation: CloudSchedulerOperation,
            method: &'a str,
            path: &'a str,
            project_id: &'a ProjectId,
            location: &'a Location,
            job_id: &'a Option<JobId>,
            page_size: u16,
            page_token_digest: &'a Option<Digest>,
            schedule_digest: &'a Digest,
            target_digest: &'a Digest,
            scope_digest: &'a Digest,
            permission_digest: &'a Digest,
            registration_digest: &'a Digest,
            provider_digest: &'a Digest,
            secret_reference_digest: &'a Digest,
            project_revision: Revision,
            mission_revision: Revision,
            work_product_revision: Revision,
            credential_revision: Revision,
        }
        let page_token_digest = self.page_token.as_ref().map(OpaquePageToken::digest);
        Digest::from_serializable(&Input {
            operation: self.operation,
            method: &self.method,
            path: &self.path,
            project_id: &self.project_id,
            location: &self.location,
            job_id: &self.job_id,
            page_size: self.page_size,
            page_token_digest: &page_token_digest,
            schedule_digest: &self.schedule_digest,
            target_digest: &self.target_digest,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            secret_reference_digest: &self.secret_reference_digest,
            project_revision: self.project_revision,
            mission_revision: self.mission_revision,
            work_product_revision: self.work_product_revision,
            credential_revision: self.credential_revision,
        })
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.request_digest == self.compute_digest()
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaquePageToken::digest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudSchedulerReadProposal {
    pub operation: CloudSchedulerOperation,
    pub request: CloudSchedulerReadRequest,
    pub registration_digest: Digest,
    pub mission_revision: Revision,
    pub proposal_digest: Digest,
}

impl CloudSchedulerReadProposal {
    #[must_use]
    pub fn new(request: CloudSchedulerReadRequest) -> Self {
        let registration_digest = request.registration_digest.clone();
        let mission_revision = request.mission_revision;
        let proposal_digest =
            Digest::from_serializable(&(&request, &registration_digest, mission_revision));
        Self {
            operation: request.operation,
            request,
            registration_digest,
            mission_revision,
            proposal_digest,
        }
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.proposal_digest
            == Digest::from_serializable(&(
                &self.request,
                &self.registration_digest,
                self.mission_revision,
            ))
    }

    #[must_use]
    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }

    #[must_use]
    pub fn request(&self) -> &CloudSchedulerReadRequest {
        &self.request
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudSchedulerReadRecord {
    pub operation: CloudSchedulerOperation,
    pub request: CloudSchedulerReadRequest,
    pub jobs: Vec<SchedulerJobSummary>,
    pub next_page_token: Option<OpaquePageToken>,
    pub response: CloudSchedulerResponseReceipt,
    pub registration_digest: Digest,
    pub record_digest: Digest,
}

impl CloudSchedulerReadRecord {
    fn new(
        request: CloudSchedulerReadRequest,
        jobs: Vec<SchedulerJobSummary>,
        next_page_token: Option<OpaquePageToken>,
        response: CloudSchedulerResponseReceipt,
    ) -> Self {
        let registration_digest = request.registration_digest.clone();
        let mut record = Self {
            operation: request.operation,
            request,
            jobs,
            next_page_token,
            response,
            registration_digest,
            record_digest: Digest::from_text("placeholder"),
        };
        record.record_digest = record.compute_digest();
        record
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.operation,
            &self.request,
            &self.jobs,
            &self.next_page_token.as_ref().map(OpaquePageToken::digest),
            &self.response,
            &self.registration_digest,
        ))
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.jobs.iter().all(SchedulerJobSummary::verify_digest)
            && self.record_digest == self.compute_digest()
    }

    #[must_use]
    pub fn record_digest(&self) -> &Digest {
        &self.record_digest
    }

    #[must_use]
    pub fn next_page_token(&self) -> Option<&OpaquePageToken> {
        self.next_page_token.as_ref()
    }
}

pub type GcpCloudSchedulerReadRequest = CloudSchedulerReadRequest;
pub type GcpCloudSchedulerReadProposal = CloudSchedulerReadProposal;
pub type GcpCloudSchedulerReadRecord = CloudSchedulerReadRecord;
pub type GcpCloudSchedulerResultProposal = CloudSchedulerReadProposal;
pub type GcpCloudSchedulerResultRecord = CloudSchedulerReadRecord;

pub trait GcpCloudSchedulerTransport: fmt::Debug {
    fn list_jobs(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError>;

    fn get_job(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError>;

    fn provenance(&self) -> TransportProvenance;
}

pub struct GcpCloudSchedulerProvider<T>
where
    T: GcpCloudSchedulerTransport,
{
    scope: GcpCloudSchedulerScope,
    secret_reference: SecretReference,
    definition: GcpCloudSchedulerProviderDefinition,
    transport: T,
}

impl<T> fmt::Debug for GcpCloudSchedulerProvider<T>
where
    T: GcpCloudSchedulerTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudSchedulerProvider")
            .field("scope_digest", &self.scope.scope_digest())
            .field("secret_reference", &self.secret_reference)
            .field("provider_digest", &self.definition.provider_digest())
            .field("provenance", &self.definition.provenance)
            .finish_non_exhaustive()
    }
}

impl<T> GcpCloudSchedulerProvider<T>
where
    T: GcpCloudSchedulerTransport,
{
    pub fn new(
        scope: GcpCloudSchedulerScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ProviderDefinitionError> {
        scope.validate()?;
        if secret_reference.is_revoked() || secret_reference.scope_digest() != &scope.scope_digest()
        {
            return Err(ProviderDefinitionError::InvalidSecret);
        }
        let definition = GcpCloudSchedulerProviderDefinition::new(transport.provenance())?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            transport,
        })
    }

    pub fn layer1(
        scope: GcpCloudSchedulerScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(scope, secret_reference, transport)
    }

    #[must_use]
    pub fn scope(&self) -> &GcpCloudSchedulerScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &GcpCloudSchedulerProviderDefinition {
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
    pub fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        false
    }

    pub fn list(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerReadRecord, GcpCloudSchedulerProviderError> {
        self.validate_request(request, CloudSchedulerOperation::List)?;
        let response = self.transport.list_jobs(request)?;
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(GcpCloudSchedulerProviderError::failure(
                ProviderFailureClass::Malformed,
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance,
            ));
        }
        Self::ensure_success(&response)?;
        self.parse_list_payload(request, response)
    }

    pub fn get(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerReadRecord, GcpCloudSchedulerProviderError> {
        self.validate_request(request, CloudSchedulerOperation::Get)?;
        let response = self.transport.get_job(request)?;
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(GcpCloudSchedulerProviderError::failure(
                ProviderFailureClass::Malformed,
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance,
            ));
        }
        Self::ensure_success(&response)?;
        self.parse_get_payload(request, response)
    }

    fn validate_request(
        &self,
        request: &CloudSchedulerReadRequest,
        operation: CloudSchedulerOperation,
    ) -> Result<(), GcpCloudSchedulerProviderError> {
        if request.operation != operation
            || !request.verify_digest()
            || request.provider_digest != self.definition.provider_digest()
            || request.scope_digest != self.scope.scope_digest()
            || request.permission_digest != self.scope.permission_digest()
            || request.secret_reference_digest != *self.secret_reference.reference_digest()
            || request.credential_revision != self.secret_reference.revision()
            || self.secret_reference.is_revoked()
        {
            return Err(GcpCloudSchedulerProviderError::failure(
                ProviderFailureClass::RequestTampered,
                None,
                None,
                self.provenance(),
            ));
        }
        Ok(())
    }

    fn ensure_success(
        response: &CloudSchedulerResponse,
    ) -> Result<(), GcpCloudSchedulerProviderError> {
        if (200..300).contains(&response.status_code) {
            Ok(())
        } else {
            Err(GcpCloudSchedulerProviderError::failure(
                ProviderFailureClass::from_status(response.status_code)
                    .unwrap_or(ProviderFailureClass::Server),
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance,
            ))
        }
    }

    fn parse_list_payload(
        &self,
        request: &CloudSchedulerReadRequest,
        response: CloudSchedulerResponse,
    ) -> Result<CloudSchedulerReadRecord, GcpCloudSchedulerProviderError> {
        let value = serde_json::from_slice::<Value>(&response.body).map_err(|_| {
            GcpCloudSchedulerProviderError::failure(
                ProviderFailureClass::Malformed,
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance,
            )
        })?;
        let object = value.as_object().ok_or_else(|| {
            GcpCloudSchedulerProviderError::failure(
                ProviderFailureClass::Malformed,
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance,
            )
        })?;
        let jobs_value = object
            .get("jobs")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                GcpCloudSchedulerProviderError::failure(
                    ProviderFailureClass::Malformed,
                    Some(response.status_code),
                    Some(response.receipt().body_digest),
                    response.provenance,
                )
            })?;
        if jobs_value.len() > MAX_JOBS {
            return Err(GcpCloudSchedulerProviderError::failure(
                ProviderFailureClass::Malformed,
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance,
            ));
        }
        let mut jobs = Vec::with_capacity(jobs_value.len());
        for job in jobs_value {
            jobs.push(self.parse_job(request, job).map_err(|error| {
                let class = if error == ModelError::ScopeDrift {
                    ProviderFailureClass::ScopeDrift
                } else {
                    ProviderFailureClass::Malformed
                };
                GcpCloudSchedulerProviderError::failure(
                    class,
                    Some(response.status_code),
                    Some(response.receipt().body_digest),
                    response.provenance,
                )
            })?);
        }
        let next_page_token = match object.get("nextPageToken") {
            None => None,
            Some(value) => Some(
                OpaquePageToken::new(value.as_str().ok_or(ModelError::InvalidProviderPayload)?)
                    .map_err(GcpCloudSchedulerProviderError::InvalidRequest)?,
            ),
        };
        Ok(CloudSchedulerReadRecord::new(
            request.clone(),
            jobs,
            next_page_token,
            response.receipt(),
        ))
    }

    fn parse_get_payload(
        &self,
        request: &CloudSchedulerReadRequest,
        response: CloudSchedulerResponse,
    ) -> Result<CloudSchedulerReadRecord, GcpCloudSchedulerProviderError> {
        let value = serde_json::from_slice::<Value>(&response.body).map_err(|_| {
            GcpCloudSchedulerProviderError::failure(
                ProviderFailureClass::Malformed,
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance,
            )
        })?;
        let value = value.get("job").unwrap_or(&value);
        let job = self.parse_job(request, value).map_err(|error| {
            let class = if error == ModelError::ScopeDrift {
                ProviderFailureClass::ScopeDrift
            } else {
                ProviderFailureClass::Malformed
            };
            GcpCloudSchedulerProviderError::failure(
                class,
                Some(response.status_code),
                Some(response.receipt().body_digest),
                response.provenance,
            )
        })?;
        Ok(CloudSchedulerReadRecord::new(
            request.clone(),
            vec![job],
            None,
            response.receipt(),
        ))
    }

    fn parse_job(
        &self,
        request: &CloudSchedulerReadRequest,
        value: &Value,
    ) -> Result<SchedulerJobSummary, ModelError> {
        let object = value
            .as_object()
            .ok_or(ModelError::InvalidProviderPayload)?;
        let name = object.get("name").and_then(Value::as_str);
        let (project_id, location, job_id) = parse_job_name(name, object, request)?;
        let schedule = ScheduleExpression::new(
            object
                .get("schedule")
                .and_then(Value::as_str)
                .ok_or(ModelError::InvalidProviderPayload)?,
        )?;
        let target = parse_target(object)?;
        let state = SchedulerJobState::parse(object.get("state").and_then(Value::as_str));
        let status = object
            .get("lastAttemptStatus")
            .or_else(|| object.get("status"));
        let last_attempt_status = status
            .and_then(Value::as_object)
            .and_then(|status| status.get("code"))
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok());
        let status_digest = status
            .and_then(Value::as_object)
            .and_then(|status| status.get("message"))
            .and_then(Value::as_str)
            .map(Digest::from_text);
        let resource_revision = object
            .get("revision")
            .and_then(Value::as_u64)
            .or_else(|| object.get("resourceRevision").and_then(Value::as_u64))
            .unwrap_or(1);
        let job = SchedulerJobSummary::new(
            job_id,
            project_id,
            location,
            schedule,
            target,
            state,
            last_attempt_status,
            status_digest,
            Revision::new(resource_revision)?,
        )?;
        if !job.matches_scope(&self.scope)
            || request
                .job_id
                .as_ref()
                .is_some_and(|expected| expected != &job.job_id)
        {
            return Err(ModelError::ScopeDrift);
        }
        Ok(job)
    }
}

fn parse_job_name(
    name: Option<&str>,
    object: &serde_json::Map<String, Value>,
    request: &CloudSchedulerReadRequest,
) -> Result<(ProjectId, Location, JobId), ModelError> {
    if let Some(name) = name {
        let parts = name.split('/').collect::<Vec<_>>();
        if parts.len() != 6
            || parts[0] != "projects"
            || parts[2] != "locations"
            || parts[4] != "jobs"
        {
            return Err(ModelError::InvalidProviderPayload);
        }
        let project_id = ProjectId::new(parts[1])?;
        let location = Location::new(parts[3])?;
        let job_id = JobId::new(parts[5])?;
        if project_id != request.project_id || location != request.location {
            return Err(ModelError::ScopeDrift);
        }
        return Ok((project_id, location, job_id));
    }
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or(ModelError::InvalidProviderPayload)?;
    Ok((
        request.project_id.clone(),
        request.location.clone(),
        JobId::new(id)?,
    ))
}

fn parse_target(object: &serde_json::Map<String, Value>) -> Result<TargetSummary, ModelError> {
    let target_fields = [
        ("httpTarget", TargetKind::Http),
        ("pubsubTarget", TargetKind::PubSub),
        ("appEngineHttpTarget", TargetKind::AppEngine),
    ];
    if target_fields
        .iter()
        .filter(|(field, _)| object.contains_key(*field))
        .count()
        > 1
    {
        return Err(ModelError::InvalidTarget);
    }
    for (field, kind) in target_fields {
        if let Some(target) = object.get(field) {
            let target_object = target.as_object().ok_or(ModelError::InvalidTarget)?;
            let endpoint = target_object
                .get("uri")
                .or_else(|| target_object.get("topicName"))
                .or_else(|| target_object.get("relativeUri"))
                .and_then(Value::as_str)
                .map(Digest::from_text);
            let payload = target_object
                .get("body")
                .or_else(|| target_object.get("data"))
                .map(Digest::from_serializable);
            let target_digest = Digest::from_serializable(target);
            return TargetSummary::new(kind, target_digest, endpoint, payload);
        }
    }
    TargetSummary::new(
        TargetKind::Unknown,
        Digest::from_serializable(&json!({"target": "absent"})),
        None,
        None,
    )
}

pub struct FixtureGcpCloudSchedulerTransport {
    list_responses: VecDeque<Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError>>,
    get_responses: VecDeque<Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError>>,
    requests: Vec<CloudSchedulerReadRequest>,
}

impl fmt::Debug for FixtureGcpCloudSchedulerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureGcpCloudSchedulerTransport")
            .field("list_responses", &self.list_responses.len())
            .field("get_responses", &self.get_responses.len())
            .field("requests", &self.requests.len())
            .finish()
    }
}

impl FixtureGcpCloudSchedulerTransport {
    #[must_use]
    pub fn new(jobs: impl IntoIterator<Item = SchedulerJobSummary>) -> Self {
        let jobs = jobs
            .into_iter()
            .map(|job| {
                json!({
                    "name": format!(
                        "projects/{}/locations/{}/jobs/{}",
                        job.project_id.as_str(), job.location.as_str(), job.job_id.as_str()
                    ),
                    "schedule": job.schedule.as_str(),
                    "state": job.state.as_str(),
                    "revision": job.resource_revision.get(),
                    "httpTarget": {"uri": job.target.target_digest.as_str()}
                })
            })
            .collect::<Vec<_>>();
        Self::from_response(CloudSchedulerResponse::json(200, &json!({"jobs": jobs})))
    }

    #[must_use]
    pub fn from_response(response: CloudSchedulerResponse) -> Self {
        let mut transport = Self::empty();
        transport.push_response(response);
        transport
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            list_responses: VecDeque::new(),
            get_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: CloudSchedulerResponse) {
        self.list_responses.push_back(Ok(response.clone()));
        self.get_responses.push_back(Ok(response));
    }

    pub fn push_list_response(&mut self, response: CloudSchedulerResponse) {
        self.list_responses.push_back(Ok(response));
    }

    pub fn push_get_response(&mut self, response: CloudSchedulerResponse) {
        self.get_responses.push_back(Ok(response));
    }

    pub fn push_list_failure(&mut self, error: GcpCloudSchedulerProviderError) {
        self.list_responses.push_back(Err(error));
    }

    pub fn push_get_failure(&mut self, error: GcpCloudSchedulerProviderError) {
        self.get_responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[CloudSchedulerReadRequest] {
        &self.requests
    }
}

impl GcpCloudSchedulerTransport for FixtureGcpCloudSchedulerTransport {
    fn list_jobs(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError> {
        self.requests.push(request.clone());
        self.list_responses
            .pop_front()
            .unwrap_or_else(|| Err(GcpCloudSchedulerProviderError::timeout(self.provenance())))
    }

    fn get_job(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError> {
        self.requests.push(request.clone());
        self.get_responses
            .pop_front()
            .unwrap_or_else(|| Err(GcpCloudSchedulerProviderError::timeout(self.provenance())))
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }
}

pub type FakeGcpCloudSchedulerTransport = FixtureGcpCloudSchedulerTransport;

pub struct RecordingGcpCloudSchedulerTransport {
    list_responses: VecDeque<Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError>>,
    get_responses: VecDeque<Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError>>,
    requests: Vec<CloudSchedulerReadRequest>,
}

impl fmt::Debug for RecordingGcpCloudSchedulerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingGcpCloudSchedulerTransport")
            .field("list_responses", &self.list_responses.len())
            .field("get_responses", &self.get_responses.len())
            .field("requests", &self.requests.len())
            .finish()
    }
}

impl RecordingGcpCloudSchedulerTransport {
    #[must_use]
    pub fn new(response: CloudSchedulerResponse) -> Self {
        let mut transport = Self::empty();
        transport.push_response(response);
        transport
    }

    #[must_use]
    pub fn empty() -> Self {
        Self {
            list_responses: VecDeque::new(),
            get_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_response(&mut self, response: CloudSchedulerResponse) {
        self.list_responses.push_back(Ok(response.clone()));
        self.get_responses.push_back(Ok(response));
    }

    pub fn push_list_response(&mut self, response: CloudSchedulerResponse) {
        self.list_responses.push_back(Ok(response));
    }

    pub fn push_get_response(&mut self, response: CloudSchedulerResponse) {
        self.get_responses.push_back(Ok(response));
    }

    pub fn push_list_failure(&mut self, error: GcpCloudSchedulerProviderError) {
        self.list_responses.push_back(Err(error));
    }

    pub fn push_get_failure(&mut self, error: GcpCloudSchedulerProviderError) {
        self.get_responses.push_back(Err(error));
    }

    #[must_use]
    pub fn requests(&self) -> &[CloudSchedulerReadRequest] {
        &self.requests
    }
}

impl GcpCloudSchedulerTransport for RecordingGcpCloudSchedulerTransport {
    fn list_jobs(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError> {
        self.requests.push(request.clone());
        self.list_responses
            .pop_front()
            .unwrap_or_else(|| Err(GcpCloudSchedulerProviderError::timeout(self.provenance())))
    }

    fn get_job(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError> {
        self.requests.push(request.clone());
        self.get_responses
            .pop_front()
            .unwrap_or_else(|| Err(GcpCloudSchedulerProviderError::timeout(self.provenance())))
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }
}

pub type RecordingTransport = RecordingGcpCloudSchedulerTransport;

pub struct LoopbackGcpCloudSchedulerTransport {
    inner: FixtureGcpCloudSchedulerTransport,
}

impl fmt::Debug for LoopbackGcpCloudSchedulerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackGcpCloudSchedulerTransport")
            .field("requests", &self.inner.requests.len())
            .finish()
    }
}

impl LoopbackGcpCloudSchedulerTransport {
    #[must_use]
    pub fn new(jobs: impl IntoIterator<Item = SchedulerJobSummary>) -> Self {
        Self {
            inner: FixtureGcpCloudSchedulerTransport::new(jobs),
        }
    }

    #[must_use]
    pub fn from_responses(responses: impl IntoIterator<Item = CloudSchedulerResponse>) -> Self {
        let mut inner = FixtureGcpCloudSchedulerTransport::empty();
        for response in responses {
            inner.push_response(response);
        }
        Self { inner }
    }

    #[must_use]
    pub fn requests(&self) -> &[CloudSchedulerReadRequest] {
        self.inner.requests()
    }
}

impl GcpCloudSchedulerTransport for LoopbackGcpCloudSchedulerTransport {
    fn list_jobs(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError> {
        self.inner
            .list_jobs(request)
            .map(|response| response.with_provenance(TransportProvenance::Loopback))
    }

    fn get_job(
        &mut self,
        request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError> {
        self.inner
            .get_job(request)
            .map(|response| response.with_provenance(TransportProvenance::Loopback))
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }
}

pub type LoopbackTransport = LoopbackGcpCloudSchedulerTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpCloudSchedulerTransport;

impl GcpCloudSchedulerTransport for BlockedEnvGcpCloudSchedulerTransport {
    fn list_jobs(
        &mut self,
        _request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError> {
        Err(GcpCloudSchedulerProviderError::blocked_env())
    }

    fn get_job(
        &mut self,
        _request: &CloudSchedulerReadRequest,
    ) -> Result<CloudSchedulerResponse, GcpCloudSchedulerProviderError> {
        Err(GcpCloudSchedulerProviderError::blocked_env())
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

pub type BlockedEnvTransport = BlockedEnvGcpCloudSchedulerTransport;

// Keep these helper aliases stable for callers that use the generic result
// naming from other standalone result roots.
pub type CloudSchedulerProviderError = GcpCloudSchedulerProviderError;
pub type CloudSchedulerProviderDefinition = GcpCloudSchedulerProviderDefinition;
pub type CloudSchedulerRead = CloudSchedulerReadRecord;
pub type RequestReceipt = CloudSchedulerRequestReceipt;
pub type ResponseReceipt = CloudSchedulerResponseReceipt;
