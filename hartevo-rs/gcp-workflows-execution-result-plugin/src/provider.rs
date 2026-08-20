//! Provider and transport seams for bounded Workflows execution reads.
//!
//! The transport trait is intentionally a test/recording boundary.  There is
//! no HTTP client, credential resolver, callback invoker, or mutation method
//! in this crate.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::model::{
    Digest, EvidenceState, ExecutionId, ExecutionSelector, ExecutionState, ExecutionSummary,
    GcpWorkflowsScope, Location, MAX_EXECUTIONS, MAX_OPAQUE_CURSOR_BYTES, MAX_PAGE_SIZE, MAX_PAGES,
    ModelError, PermissionAction, ProjectId, Revision, SecretReference, StepMetadata, WorkflowId,
    WorkflowRevisionId,
};

// `OpaquePageToken` is defined below.  The import alias above is deliberately
// not used; keeping all cursor code in this module makes the no-raw-cursor
// boundary easy to audit.

pub const GCP_WORKFLOWS_EXECUTION_API_VERSION: &str = "v1";
pub const GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION: &str = "gcp-workflows-executions-v1-r1";
pub const GCP_WORKFLOWS_EXECUTION_BASE_URL: &str = "https://workflowexecutions.googleapis.com";

#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    value: String,
    digest: Digest,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_OPAQUE_CURSOR_BYTES || value.trim() != value {
            return Err(ModelError::InvalidText {
                field: "opaque page token",
            });
        }
        if value.chars().any(char::is_control) {
            return Err(ModelError::InvalidText {
                field: "opaque page token",
            });
        }
        let digest = Digest::from_text(&value);
        Ok(Self { value, digest })
    }

    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }

    pub const fn is_empty(&self) -> bool {
        self.value.is_empty()
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

pub type OpaqueCursor = OpaquePageToken;
pub type PageToken = OpaquePageToken;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFailureClass {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Server,
    Timeout,
    Partial,
    BlockedEnv,
    Malformed,
    Unknown,
}

impl ProviderFailureClass {
    pub const fn evidence_state(self) -> EvidenceState {
        match self {
            Self::Unauthorized | Self::Forbidden => EvidenceState::AccessLost,
            Self::NotFound => EvidenceState::NotFound,
            Self::Conflict => EvidenceState::Conflict,
            Self::RateLimited => EvidenceState::RateLimited,
            Self::Timeout => EvidenceState::Timeout,
            Self::Partial => EvidenceState::Partial,
            Self::BadRequest
            | Self::Server
            | Self::BlockedEnv
            | Self::Malformed
            | Self::Unknown => EvidenceState::ProviderUnknown,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpWorkflowsProviderError {
    #[error("GCP Workflows provider definition drifted")]
    DefinitionDrift,
    #[error("GCP Workflows request was replayed")]
    ReplayDetected,
    #[error("GCP Workflows request is invalid")]
    InvalidRequest,
    #[error("GCP Workflows response is invalid or outside bounds")]
    InvalidResponse,
    #[error("GCP Workflows record does not match its request")]
    RequestMismatch,
    #[error("GCP Workflows transport does not implement this read")]
    UnsupportedOperation,
    #[error("GCP Workflows provider failure: {class:?}")]
    Failure {
        class: ProviderFailureClass,
        status_code: Option<u16>,
        diagnostic_digest: Digest,
    },
}

impl GcpWorkflowsProviderError {
    pub fn failure(class: ProviderFailureClass, status_code: Option<u16>) -> Self {
        Self::Failure {
            diagnostic_digest: Digest::from_serializable(&(class, status_code)),
            class,
            status_code,
        }
    }

    pub const fn class(&self) -> Option<ProviderFailureClass> {
        match self {
            Self::Failure { class, .. } => Some(*class),
            _ => None,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Failure { status_code, .. } => *status_code,
            _ => None,
        }
    }

    pub fn diagnostic_digest(&self) -> Digest {
        match self {
            Self::Failure {
                diagnostic_digest, ..
            } => diagnostic_digest.clone(),
            Self::DefinitionDrift => Digest::from_text("gcp-workflows-definition-drift"),
            Self::ReplayDetected => Digest::from_text("gcp-workflows-replay"),
            Self::InvalidRequest => Digest::from_text("gcp-workflows-invalid-request"),
            Self::InvalidResponse => Digest::from_text("gcp-workflows-invalid-response"),
            Self::RequestMismatch => Digest::from_text("gcp-workflows-request-mismatch"),
            Self::UnsupportedOperation => Digest::from_text("gcp-workflows-unsupported-operation"),
        }
    }

    pub fn evidence_state(&self) -> EvidenceState {
        self.class().map_or(
            EvidenceState::ProviderUnknown,
            ProviderFailureClass::evidence_state,
        )
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version or revision is empty or invalid")]
    InvalidVersion,
    #[error("provider definition is not the expected Layer-1 read-only definition")]
    InvalidDefinition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpWorkflowsProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub api_version: String,
    pub permission_names: Vec<String>,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

impl GcpWorkflowsProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provider_revision: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        let provider_revision = provider_revision.into();
        if provider_version.trim().is_empty() || provider_revision.trim().is_empty() {
            return Err(ProviderDefinitionError::InvalidVersion);
        }
        let permission_names = vec![
            "workflows.executions.list".to_owned(),
            "workflows.executions.get".to_owned(),
        ];
        let capability_digest = Digest::from_serializable(&(
            crate::GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION,
            crate::GCP_WORKFLOWS_EXECUTION_PROVIDER_ID,
            GCP_WORKFLOWS_EXECUTION_API_VERSION,
            &permission_names,
            "list_get_metadata_only",
            "no_create_cancel_retry_resume",
        ));
        Ok(Self {
            schema_version: crate::GCP_WORKFLOWS_EXECUTION_PROVIDER_SCHEMA.to_owned(),
            provider_id: crate::GCP_WORKFLOWS_EXECUTION_PROVIDER_ID.to_owned(),
            provider_version,
            provider_revision,
            api_version: GCP_WORKFLOWS_EXECUTION_API_VERSION.to_owned(),
            permission_names,
            capability_digest,
            provenance,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        let expected_permissions = vec![
            "workflows.executions.list".to_owned(),
            "workflows.executions.get".to_owned(),
        ];
        let expected_capability_digest = Digest::from_serializable(&(
            crate::GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION,
            crate::GCP_WORKFLOWS_EXECUTION_PROVIDER_ID,
            GCP_WORKFLOWS_EXECUTION_API_VERSION,
            &expected_permissions,
            "list_get_metadata_only",
            "no_create_cancel_retry_resume",
        ));
        if self.schema_version != crate::GCP_WORKFLOWS_EXECUTION_PROVIDER_SCHEMA
            || self.provider_id != crate::GCP_WORKFLOWS_EXECUTION_PROVIDER_ID
            || self.api_version != GCP_WORKFLOWS_EXECUTION_API_VERSION
            || self.permission_names != expected_permissions
            || self.capability_digest != expected_capability_digest
            || !self.read_only
            || self.live_execution
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

    pub fn is_layer1(&self) -> bool {
        self.validate().is_ok()
            && self.provider_version == crate::GCP_WORKFLOWS_EXECUTION_PROVIDER_VERSION_TEXT
            && self.provider_revision == GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionView {
    Metadata,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOperation {
    ListExecutions,
    GetExecution,
}

impl ExecutionOperation {
    pub const fn is_list(self) -> bool {
        matches!(self, Self::ListExecutions)
    }

    pub const fn is_get(self) -> bool {
        matches!(self, Self::GetExecution)
    }
}

/// A request contains exact safe scope identifiers and only a digest for the
/// opaque cursor.  The raw cursor is retained solely inside the transport
/// seam and is never serializable or printable.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionReadRequest {
    pub operation: ExecutionOperation,
    pub api_version: String,
    pub project_id: ProjectId,
    pub location: Location,
    pub workflow_id: WorkflowId,
    pub workflow_revision: WorkflowRevisionId,
    pub execution_id: Option<ExecutionId>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub page_size: u16,
    pub page_number: u16,
    pub page_token_digest: Option<Digest>,
    pub view: ExecutionView,
    pub request_digest: Digest,
    page_token: Option<OpaquePageToken>,
}

impl fmt::Debug for ExecutionReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionReadRequest")
            .field("operation", &self.operation)
            .field("api_version", &self.api_version)
            .field("project_id", &self.project_id)
            .field("location", &self.location)
            .field("workflow_id", &self.workflow_id)
            .field("workflow_revision", &self.workflow_revision)
            .field("execution_id", &self.execution_id)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("page_token_digest", &self.page_token_digest)
            .field("view", &self.view)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for ExecutionReadRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SafeRequest<'a> {
            operation: ExecutionOperation,
            api_version: &'a str,
            project_id: &'a ProjectId,
            location: &'a Location,
            workflow_id: &'a WorkflowId,
            workflow_revision: &'a WorkflowRevisionId,
            execution_id: &'a Option<ExecutionId>,
            scope_digest: &'a Digest,
            permission_digest: &'a Digest,
            page_size: u16,
            page_number: u16,
            page_token_digest: &'a Option<Digest>,
            view: ExecutionView,
            request_digest: &'a Digest,
        }
        SafeRequest {
            operation: self.operation,
            api_version: &self.api_version,
            project_id: &self.project_id,
            location: &self.location,
            workflow_id: &self.workflow_id,
            workflow_revision: &self.workflow_revision,
            execution_id: &self.execution_id,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            page_size: self.page_size,
            page_number: self.page_number,
            page_token_digest: &self.page_token_digest,
            view: self.view,
            request_digest: &self.request_digest,
        }
        .serialize(serializer)
    }
}

impl ExecutionReadRequest {
    pub fn list(
        scope: &GcpWorkflowsScope,
        provider_digest: Digest,
        page_number: u16,
        page_size: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        Self::build(
            ExecutionOperation::ListExecutions,
            scope,
            provider_digest,
            page_number,
            page_size,
            page_token,
            None,
        )
    }

    pub fn get(scope: &GcpWorkflowsScope, provider_digest: Digest) -> Result<Self, ModelError> {
        let execution_id = scope
            .execution
            .id()
            .cloned()
            .ok_or(ModelError::InvalidIdentifier {
                field: "exact execution selector",
            })?;
        Self::build(
            ExecutionOperation::GetExecution,
            scope,
            provider_digest,
            1,
            1,
            None,
            Some(execution_id),
        )
    }

    fn build(
        operation: ExecutionOperation,
        scope: &GcpWorkflowsScope,
        provider_digest: Digest,
        page_number: u16,
        page_size: u16,
        page_token: Option<OpaquePageToken>,
        execution_id: Option<ExecutionId>,
    ) -> Result<Self, ModelError> {
        if page_number == 0
            || page_number > crate::MAX_PAGES
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
            || (operation.is_get() && page_token.is_some())
            || (operation.is_list() && execution_id.is_some())
        {
            return Err(ModelError::InvalidIdentifier {
                field: "bounded execution read request",
            });
        }
        let page_token_digest = page_token.as_ref().map(OpaquePageToken::digest);
        let mut request = Self {
            operation,
            api_version: GCP_WORKFLOWS_EXECUTION_API_VERSION.to_owned(),
            project_id: scope.project.id.clone(),
            location: scope.location.clone(),
            workflow_id: scope.workflow.id.clone(),
            workflow_revision: scope.workflow.revision.clone(),
            execution_id,
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest(),
            page_size,
            page_number,
            page_token_digest,
            view: ExecutionView::Metadata,
            request_digest: Digest::from_text("placeholder"),
            page_token,
        };
        request.request_digest = request.compute_digest(&provider_digest);
        Ok(request)
    }

    pub fn compute_digest(&self, provider_digest: &Digest) -> Digest {
        #[derive(Serialize)]
        struct RequestDigestInput<'a> {
            provider_digest: &'a Digest,
            scope_digest: &'a Digest,
            api_version: &'a str,
            project_id: &'a ProjectId,
            location: &'a Location,
            workflow_id: &'a WorkflowId,
            workflow_revision: &'a WorkflowRevisionId,
            execution_id: &'a Option<ExecutionId>,
            permission_digest: &'a Digest,
            page_size: u16,
            page_number: u16,
            page_token_digest: &'a Option<Digest>,
            view: ExecutionView,
        }
        Digest::from_serializable(&RequestDigestInput {
            provider_digest,
            scope_digest: &self.scope_digest,
            api_version: &self.api_version,
            project_id: &self.project_id,
            location: &self.location,
            workflow_id: &self.workflow_id,
            workflow_revision: &self.workflow_revision,
            execution_id: &self.execution_id,
            permission_digest: &self.permission_digest,
            page_size: self.page_size,
            page_number: self.page_number,
            page_token_digest: &self.page_token_digest,
            view: self.view,
        })
    }

    pub fn verify_digest(&self, provider_digest: &Digest) -> bool {
        self.request_digest == self.compute_digest(provider_digest)
            && self.api_version == GCP_WORKFLOWS_EXECUTION_API_VERSION
            && self.page_number > 0
            && self.page_number <= MAX_PAGES
            && self.page_size > 0
            && self.page_size <= MAX_PAGE_SIZE
            && self.operation.is_get() == self.execution_id.is_some()
            && self.operation.is_list() == self.execution_id.is_none()
            && (!self.operation.is_get() || self.page_token.is_none())
            && self.page_token_digest == self.page_token.as_ref().map(OpaquePageToken::digest)
            && self
                .page_token
                .as_ref()
                .is_none_or(|token| token.value.len() <= MAX_OPAQUE_CURSOR_BYTES)
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn provider_path(&self) -> String {
        let base = format!(
            "{GCP_WORKFLOWS_EXECUTION_BASE_URL}/{}/locations/{}/workflows/{}",
            self.project_id, self.location, self.workflow_id
        );
        match (&self.operation, &self.execution_id) {
            (ExecutionOperation::ListExecutions, None) => format!("{base}/executions"),
            (ExecutionOperation::GetExecution, Some(execution_id)) => {
                format!("{base}/executions/{execution_id}")
            }
            _ => base,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionPage {
    pub page_number: u16,
    pub request_digest: Digest,
    pub provider_revision: String,
    pub response_status: ResponseStatus,
    pub executions: Vec<ExecutionSummary>,
    next_page_token: Option<OpaquePageToken>,
    pub next_page_token_digest: Option<Digest>,
    pub response_digest: Digest,
}

impl fmt::Debug for ExecutionPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionPage")
            .field("page_number", &self.page_number)
            .field("request_digest", &self.request_digest)
            .field("provider_revision", &self.provider_revision)
            .field("response_status", &self.response_status)
            .field("execution_count", &self.executions.len())
            .field("next_page_token_digest", &self.next_page_token_digest)
            .field("response_digest", &self.response_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for ExecutionPage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SafePage<'a> {
            page_number: u16,
            request_digest: &'a Digest,
            provider_revision: &'a str,
            response_status: ResponseStatus,
            executions: &'a [ExecutionSummary],
            next_page_token_digest: &'a Option<Digest>,
            response_digest: &'a Digest,
        }
        SafePage {
            page_number: self.page_number,
            request_digest: &self.request_digest,
            provider_revision: &self.provider_revision,
            response_status: self.response_status,
            executions: &self.executions,
            next_page_token_digest: &self.next_page_token_digest,
            response_digest: &self.response_digest,
        }
        .serialize(serializer)
    }
}

impl ExecutionPage {
    pub fn new(
        request: &ExecutionReadRequest,
        provider_revision: impl Into<String>,
        executions: Vec<ExecutionSummary>,
        next_page_token: Option<OpaquePageToken>,
        response_status: ResponseStatus,
    ) -> Result<Self, GcpWorkflowsProviderError> {
        let provider_revision = provider_revision.into();
        if !request.operation.is_list()
            || provider_revision.trim().is_empty()
            || executions.len() > usize::from(request.page_size)
            || executions.len() > MAX_EXECUTIONS
            || executions
                .iter()
                .any(|execution| !execution.verify_digest())
        {
            return Err(GcpWorkflowsProviderError::InvalidResponse);
        }
        let next_page_token_digest = next_page_token.as_ref().map(OpaquePageToken::digest);
        let mut page = Self {
            page_number: request.page_number,
            request_digest: request.request_digest.clone(),
            provider_revision,
            response_status,
            executions,
            next_page_token,
            next_page_token_digest,
            response_digest: Digest::from_text("placeholder"),
        };
        page.response_digest = page.compute_digest();
        Ok(page)
    }

    fn canonical(
        &self,
    ) -> (
        &Digest,
        &str,
        ResponseStatus,
        &[ExecutionSummary],
        &Option<Digest>,
    ) {
        (
            &self.request_digest,
            &self.provider_revision,
            self.response_status,
            &self.executions,
            &self.next_page_token_digest,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&self.canonical())
    }

    pub fn verify_digest(&self, request: &ExecutionReadRequest) -> bool {
        request.operation.is_list()
            && self.request_digest == request.request_digest
            && self.page_number == request.page_number
            && self.page_number > 0
            && self.page_number <= MAX_PAGES
            && !self.provider_revision.trim().is_empty()
            && self.next_page_token_digest
                == self.next_page_token.as_ref().map(OpaquePageToken::digest)
            && self.executions.len() <= usize::from(request.page_size)
            && self.executions.iter().all(ExecutionSummary::verify_digest)
            && self.response_digest == self.compute_digest()
    }

    pub fn next_page_token(&self) -> Option<&OpaquePageToken> {
        self.next_page_token.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionGetResponse {
    pub request_digest: Digest,
    pub provider_revision: String,
    pub response_status: ResponseStatus,
    pub execution: ExecutionSummary,
    pub response_digest: Digest,
}

impl ExecutionGetResponse {
    pub fn new(
        request: &ExecutionReadRequest,
        provider_revision: impl Into<String>,
        execution: ExecutionSummary,
        response_status: ResponseStatus,
    ) -> Result<Self, GcpWorkflowsProviderError> {
        let provider_revision = provider_revision.into();
        if !request.operation.is_get()
            || provider_revision.trim().is_empty()
            || !execution.verify_digest()
        {
            return Err(GcpWorkflowsProviderError::InvalidResponse);
        }
        let mut response = Self {
            request_digest: request.request_digest.clone(),
            provider_revision,
            response_status,
            execution,
            response_digest: Digest::from_text("placeholder"),
        };
        response.response_digest = response.compute_digest();
        Ok(response)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.request_digest,
            &self.provider_revision,
            self.response_status,
            &self.execution,
        ))
    }

    pub fn verify_digest(&self, request: &ExecutionReadRequest) -> bool {
        request.operation.is_get()
            && self.request_digest == request.request_digest
            && !self.provider_revision.trim().is_empty()
            && self.execution.verify_digest()
            && self.response_digest == self.compute_digest()
    }
}

/// A proposal is the digest-fenced bridge between service intent and one
/// provider list/get read.
#[derive(Clone, Eq, PartialEq)]
pub struct ExecutionReadProposal {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub operation: ExecutionOperation,
    pub request_digest: Digest,
    pub proposal_digest: Digest,
    request: ExecutionReadRequest,
}

impl fmt::Debug for ExecutionReadProposal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionReadProposal")
            .field("registration_digest", &self.registration_digest)
            .field("registration_revision", &self.registration_revision)
            .field("provider_digest", &self.provider_digest)
            .field("provider_revision", &self.provider_revision)
            .field("operation", &self.operation)
            .field("request_digest", &self.request_digest)
            .field("proposal_digest", &self.proposal_digest)
            .finish_non_exhaustive()
    }
}

impl Serialize for ExecutionReadProposal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct SafeProposal<'a> {
            registration_digest: &'a Digest,
            registration_revision: Revision,
            provider_digest: &'a Digest,
            provider_revision: &'a str,
            operation: ExecutionOperation,
            request_digest: &'a Digest,
            proposal_digest: &'a Digest,
            request: &'a ExecutionReadRequest,
        }
        SafeProposal {
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            operation: self.operation,
            request_digest: &self.request_digest,
            proposal_digest: &self.proposal_digest,
            request: &self.request,
        }
        .serialize(serializer)
    }
}

impl ExecutionReadProposal {
    pub fn new(
        registration_digest: Digest,
        registration_revision: Revision,
        provider_digest: Digest,
        provider_revision: impl Into<String>,
        request: ExecutionReadRequest,
    ) -> Self {
        let provider_revision = provider_revision.into();
        let mut proposal = Self {
            registration_digest,
            registration_revision,
            provider_digest,
            provider_revision,
            operation: request.operation,
            request_digest: request.request_digest.clone(),
            proposal_digest: Digest::from_text("placeholder"),
            request,
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.registration_digest,
            self.registration_revision,
            &self.provider_digest,
            &self.provider_revision,
            self.operation,
            &self.request_digest,
            &self.request,
        ))
    }

    pub fn verify_digest(&self) -> bool {
        self.proposal_digest == self.compute_digest()
            && self.operation == self.request.operation
            && self.request_digest == self.request.request_digest
            && self.request.verify_digest(&self.provider_digest)
    }

    pub fn request(&self) -> &ExecutionReadRequest {
        &self.request
    }

    pub fn proposal_digest(&self) -> &Digest {
        &self.proposal_digest
    }
}

pub type GcpWorkflowsExecutionProposal = ExecutionReadProposal;
pub type ExecutionProposal = ExecutionReadProposal;
pub type ListExecutionsProposal = ExecutionReadProposal;
pub type GetExecutionProposal = ExecutionReadProposal;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionReadRecord {
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub operation: ExecutionOperation,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub response_status: ResponseStatus,
    pub page_number: u16,
    pub executions: Vec<ExecutionSummary>,
    pub execution: Option<ExecutionSummary>,
    pub next_page_token_digest: Option<Digest>,
    pub record_digest: Digest,
}

impl ExecutionReadRecord {
    pub fn from_list(
        proposal: &ExecutionReadProposal,
        page: &ExecutionPage,
        scope: &GcpWorkflowsScope,
        secret_reference: &SecretReference,
    ) -> Result<Self, GcpWorkflowsProviderError> {
        if !proposal.verify_digest()
            || !page.verify_digest(proposal.request())
            || !proposal.operation.is_list()
            || page.provider_revision != proposal.provider_revision
            || page
                .executions
                .iter()
                .any(|execution| !execution.matches_scope(scope) || !execution.verify_digest())
        {
            return Err(GcpWorkflowsProviderError::RequestMismatch);
        }
        let mut record = Self {
            registration_digest: proposal.registration_digest.clone(),
            registration_revision: proposal.registration_revision,
            provider_digest: proposal.provider_digest.clone(),
            provider_revision: proposal.provider_revision.clone(),
            operation: proposal.operation,
            permission_digest: proposal.request.permission_digest.clone(),
            scope_digest: proposal.request.scope_digest.clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            request_digest: proposal.request_digest.clone(),
            response_digest: page.response_digest.clone(),
            response_status: page.response_status,
            page_number: page.page_number,
            executions: page.executions.clone(),
            execution: None,
            next_page_token_digest: page.next_page_token_digest.clone(),
            record_digest: Digest::from_text("placeholder"),
        };
        record.record_digest = record.compute_digest();
        Ok(record)
    }

    pub fn from_get(
        proposal: &ExecutionReadProposal,
        response: &ExecutionGetResponse,
        scope: &GcpWorkflowsScope,
        secret_reference: &SecretReference,
    ) -> Result<Self, GcpWorkflowsProviderError> {
        if !proposal.verify_digest()
            || !response.verify_digest(proposal.request())
            || !proposal.operation.is_get()
            || response.provider_revision != proposal.provider_revision
            || !response.execution.matches_scope(scope)
        {
            return Err(GcpWorkflowsProviderError::RequestMismatch);
        }
        let mut record = Self {
            registration_digest: proposal.registration_digest.clone(),
            registration_revision: proposal.registration_revision,
            provider_digest: proposal.provider_digest.clone(),
            provider_revision: proposal.provider_revision.clone(),
            operation: proposal.operation,
            permission_digest: proposal.request.permission_digest.clone(),
            scope_digest: proposal.request.scope_digest.clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            request_digest: proposal.request_digest.clone(),
            response_digest: response.response_digest.clone(),
            response_status: response.response_status,
            page_number: 1,
            executions: Vec::new(),
            execution: Some(response.execution.clone()),
            next_page_token_digest: None,
            record_digest: Digest::from_text("placeholder"),
        };
        record.record_digest = record.compute_digest();
        Ok(record)
    }

    pub fn compute_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct RecordDigestInput<'a> {
            registration_digest: &'a Digest,
            registration_revision: Revision,
            provider_digest: &'a Digest,
            provider_revision: &'a str,
            operation: ExecutionOperation,
            permission_digest: &'a Digest,
            scope_digest: &'a Digest,
            secret_reference_digest: &'a Digest,
            request_digest: &'a Digest,
            response_digest: &'a Digest,
            response_status: ResponseStatus,
            page_number: u16,
            executions: &'a [ExecutionSummary],
            execution: &'a Option<ExecutionSummary>,
            next_page_token_digest: &'a Option<Digest>,
        }
        Digest::from_serializable(&RecordDigestInput {
            registration_digest: &self.registration_digest,
            registration_revision: self.registration_revision,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            operation: self.operation,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            secret_reference_digest: &self.secret_reference_digest,
            request_digest: &self.request_digest,
            response_digest: &self.response_digest,
            response_status: self.response_status,
            page_number: self.page_number,
            executions: &self.executions,
            execution: &self.execution,
            next_page_token_digest: &self.next_page_token_digest,
        })
    }

    pub fn verify_integrity(&self) -> bool {
        self.record_digest == self.compute_digest()
            && self.page_number > 0
            && self.page_number <= MAX_PAGES
            && self.executions.len() <= MAX_EXECUTIONS
            && match self.operation {
                ExecutionOperation::ListExecutions => self.execution.is_none(),
                ExecutionOperation::GetExecution => {
                    self.page_number == 1 && self.executions.is_empty() && self.execution.is_some()
                }
            }
            && self.executions.iter().all(ExecutionSummary::verify_digest)
            && self
                .execution
                .as_ref()
                .is_none_or(ExecutionSummary::verify_digest)
    }
}

pub type GcpWorkflowsExecutionRecord = ExecutionReadRecord;
pub type ExecutionRecord = ExecutionReadRecord;
pub type ListExecutionsRecord = ExecutionReadRecord;
pub type GetExecutionRecord = ExecutionReadRecord;

pub trait GcpWorkflowsTransport: fmt::Debug {
    fn list_executions(
        &mut self,
        _request: &ExecutionReadRequest,
    ) -> Result<ExecutionPage, GcpWorkflowsProviderError> {
        Err(GcpWorkflowsProviderError::UnsupportedOperation)
    }

    fn get_execution(
        &mut self,
        _request: &ExecutionReadRequest,
    ) -> Result<ExecutionGetResponse, GcpWorkflowsProviderError> {
        Err(GcpWorkflowsProviderError::UnsupportedOperation)
    }

    fn provenance(&self) -> ProviderProvenance;
}

pub use GcpWorkflowsTransport as GcpWorkflowsExecutionTransport;

/// Provider wrapper that verifies request/response digests and rejects request
/// replay before a transport is called.
pub struct GcpWorkflowsProvider<T>
where
    T: GcpWorkflowsTransport,
{
    transport: T,
    definition: GcpWorkflowsProviderDefinition,
    seen_request_digests: BTreeSet<Digest>,
}

impl<T> fmt::Debug for GcpWorkflowsProvider<T>
where
    T: GcpWorkflowsTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpWorkflowsProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .field("seen_request_count", &self.seen_request_digests.len())
            .finish_non_exhaustive()
    }
}

impl<T> GcpWorkflowsProvider<T>
where
    T: GcpWorkflowsTransport,
{
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ProviderDefinitionError> {
        let provenance = transport.provenance();
        let definition =
            GcpWorkflowsProviderDefinition::new(provider_version, provider_revision, provenance)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
            seen_request_digests: BTreeSet::new(),
        })
    }

    pub fn layer1(transport: T) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            transport,
            crate::GCP_WORKFLOWS_EXECUTION_PROVIDER_VERSION_TEXT,
            GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION,
        )
    }

    pub fn definition(&self) -> &GcpWorkflowsProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn read(
        &mut self,
        request: &ExecutionReadRequest,
    ) -> Result<ExecutionTransportResponse, GcpWorkflowsProviderError> {
        self.validate_request(request)?;
        if self.provenance() != self.definition.provenance || !self.definition.is_layer1() {
            return Err(GcpWorkflowsProviderError::DefinitionDrift);
        }
        if !self
            .seen_request_digests
            .insert(request.request_digest.clone())
        {
            return Err(GcpWorkflowsProviderError::ReplayDetected);
        }
        if request.operation.is_list() {
            let page = self.transport.list_executions(request)?;
            if page.provider_revision != self.definition.provider_revision {
                return Err(GcpWorkflowsProviderError::DefinitionDrift);
            }
            if !page.verify_digest(request) {
                return Err(GcpWorkflowsProviderError::InvalidResponse);
            }
            Ok(ExecutionTransportResponse::List(page))
        } else {
            let response = self.transport.get_execution(request)?;
            if response.provider_revision != self.definition.provider_revision {
                return Err(GcpWorkflowsProviderError::DefinitionDrift);
            }
            if !response.verify_digest(request) {
                return Err(GcpWorkflowsProviderError::InvalidResponse);
            }
            Ok(ExecutionTransportResponse::Get(response))
        }
    }

    pub fn list(
        &mut self,
        request: &ExecutionReadRequest,
    ) -> Result<ExecutionPage, GcpWorkflowsProviderError> {
        match self.read(request)? {
            ExecutionTransportResponse::List(page) => Ok(page),
            ExecutionTransportResponse::Get(_) => Err(GcpWorkflowsProviderError::RequestMismatch),
        }
    }

    pub fn get(
        &mut self,
        request: &ExecutionReadRequest,
    ) -> Result<ExecutionGetResponse, GcpWorkflowsProviderError> {
        match self.read(request)? {
            ExecutionTransportResponse::Get(response) => Ok(response),
            ExecutionTransportResponse::List(_) => Err(GcpWorkflowsProviderError::RequestMismatch),
        }
    }

    fn validate_request(
        &self,
        request: &ExecutionReadRequest,
    ) -> Result<(), GcpWorkflowsProviderError> {
        if !request.verify_digest(&self.provider_digest())
            || request.api_version != GCP_WORKFLOWS_EXECUTION_API_VERSION
            || request.view != ExecutionView::Metadata
        {
            return Err(GcpWorkflowsProviderError::DefinitionDrift);
        }
        if request.operation.is_get() != request.execution_id.is_some()
            || (request.operation.is_list() && request.page_number == 0)
        {
            return Err(GcpWorkflowsProviderError::InvalidRequest);
        }
        Ok(())
    }

    pub fn record_list(
        &self,
        proposal: &ExecutionReadProposal,
        page: &ExecutionPage,
        scope: &GcpWorkflowsScope,
        secret_reference: &SecretReference,
    ) -> Result<ExecutionReadRecord, GcpWorkflowsProviderError> {
        ExecutionReadRecord::from_list(proposal, page, scope, secret_reference)
    }

    pub fn record_get(
        &self,
        proposal: &ExecutionReadProposal,
        response: &ExecutionGetResponse,
        scope: &GcpWorkflowsScope,
        secret_reference: &SecretReference,
    ) -> Result<ExecutionReadRecord, GcpWorkflowsProviderError> {
        ExecutionReadRecord::from_get(proposal, response, scope, secret_reference)
    }

    pub fn verify(
        &self,
        proposal: &ExecutionReadProposal,
        record: &ExecutionReadRecord,
    ) -> Result<(), GcpWorkflowsProviderError> {
        if !proposal.verify_digest()
            || !record.verify_integrity()
            || record.registration_digest != proposal.registration_digest
            || record.registration_revision != proposal.registration_revision
            || record.provider_digest != self.provider_digest()
            || record.provider_revision != self.definition.provider_revision
            || record.operation != proposal.operation
            || record.request_digest != proposal.request_digest
        {
            return Err(GcpWorkflowsProviderError::RequestMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionTransportResponse {
    List(ExecutionPage),
    Get(ExecutionGetResponse),
}

#[derive(Clone, Debug)]
pub struct FixtureGcpWorkflowsTransport {
    executions: Vec<ExecutionSummary>,
    requests: Vec<ExecutionReadRequest>,
    next_failure: Option<GcpWorkflowsProviderError>,
}

impl FixtureGcpWorkflowsTransport {
    pub fn new(executions: impl IntoIterator<Item = ExecutionSummary>) -> Self {
        Self {
            executions: executions.into_iter().collect(),
            requests: Vec::new(),
            next_failure: None,
        }
    }

    pub fn push_failure(&mut self, error: GcpWorkflowsProviderError) {
        self.next_failure = Some(error);
    }

    pub fn requests(&self) -> &[ExecutionReadRequest] {
        &self.requests
    }

    pub fn executions(&self) -> &[ExecutionSummary] {
        &self.executions
    }
}

impl GcpWorkflowsTransport for FixtureGcpWorkflowsTransport {
    fn list_executions(
        &mut self,
        request: &ExecutionReadRequest,
    ) -> Result<ExecutionPage, GcpWorkflowsProviderError> {
        self.requests.push(request.clone());
        if let Some(error) = self.next_failure.take() {
            return Err(error);
        }
        let expected_token = if request.page_number == 1 {
            None
        } else {
            Some(
                fake_page_token_for_page(request.page_number)
                    .map_err(|_| GcpWorkflowsProviderError::InvalidRequest)?,
            )
        };
        if request.page_token_digest != expected_token.as_ref().map(OpaquePageToken::digest) {
            return Err(GcpWorkflowsProviderError::RequestMismatch);
        }
        let mut matches: Vec<_> = self
            .executions
            .iter()
            .filter(|execution| execution.workflow_revision == request.workflow_revision)
            .cloned()
            .collect();
        matches.sort_by(|left, right| {
            right
                .timing
                .start_time
                .cmp(&left.timing.start_time)
                .then_with(|| left.id.cmp(&right.id))
        });
        let page_size = usize::from(request.page_size);
        let page_start = usize::from(request.page_number.saturating_sub(1)) * page_size;
        let total = matches.len();
        let executions: Vec<_> = matches
            .into_iter()
            .skip(page_start)
            .take(page_size)
            .collect();
        let has_more = page_start.saturating_add(executions.len()) < total;
        let next_page_token = has_more
            .then(|| fake_page_token_for_page(request.page_number.saturating_add(1)))
            .transpose()
            .map_err(|_| GcpWorkflowsProviderError::InvalidResponse)?;
        ExecutionPage::new(
            request,
            GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION,
            executions,
            next_page_token,
            ResponseStatus::Complete,
        )
    }

    fn get_execution(
        &mut self,
        request: &ExecutionReadRequest,
    ) -> Result<ExecutionGetResponse, GcpWorkflowsProviderError> {
        self.requests.push(request.clone());
        if let Some(error) = self.next_failure.take() {
            return Err(error);
        }
        let execution_id = request
            .execution_id
            .as_ref()
            .ok_or(GcpWorkflowsProviderError::InvalidRequest)?;
        let execution = self
            .executions
            .iter()
            .find(|execution| {
                &execution.id == execution_id
                    && execution.workflow_revision == request.workflow_revision
            })
            .cloned()
            .ok_or_else(|| {
                GcpWorkflowsProviderError::failure(ProviderFailureClass::NotFound, Some(404))
            })?;
        ExecutionGetResponse::new(
            request,
            GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION,
            execution,
            ResponseStatus::Complete,
        )
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }
}

pub type FakeGcpWorkflowsTransport = FixtureGcpWorkflowsTransport;

#[derive(Clone, Debug)]
pub struct RecordingGcpWorkflowsTransport {
    list_responses: VecDeque<Result<ExecutionPage, GcpWorkflowsProviderError>>,
    get_responses: VecDeque<Result<ExecutionGetResponse, GcpWorkflowsProviderError>>,
    requests: Vec<ExecutionReadRequest>,
}

impl RecordingGcpWorkflowsTransport {
    pub fn new(
        list_responses: impl IntoIterator<Item = Result<ExecutionPage, GcpWorkflowsProviderError>>,
    ) -> Self {
        Self {
            list_responses: list_responses.into_iter().collect(),
            get_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn empty() -> Self {
        Self::new(std::iter::empty())
    }

    pub fn push_list_response(
        &mut self,
        response: Result<ExecutionPage, GcpWorkflowsProviderError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_response(
        &mut self,
        response: Result<ExecutionGetResponse, GcpWorkflowsProviderError>,
    ) {
        self.get_responses.push_back(response);
    }

    pub fn requests(&self) -> &[ExecutionReadRequest] {
        &self.requests
    }

    pub fn remaining_list_responses(&self) -> usize {
        self.list_responses.len()
    }

    pub fn remaining_get_responses(&self) -> usize {
        self.get_responses.len()
    }
}

impl GcpWorkflowsTransport for RecordingGcpWorkflowsTransport {
    fn list_executions(
        &mut self,
        request: &ExecutionReadRequest,
    ) -> Result<ExecutionPage, GcpWorkflowsProviderError> {
        self.requests.push(request.clone());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(GcpWorkflowsProviderError::failure(
                ProviderFailureClass::Unknown,
                None,
            )))
    }

    fn get_execution(
        &mut self,
        request: &ExecutionReadRequest,
    ) -> Result<ExecutionGetResponse, GcpWorkflowsProviderError> {
        self.requests.push(request.clone());
        self.get_responses
            .pop_front()
            .unwrap_or(Err(GcpWorkflowsProviderError::failure(
                ProviderFailureClass::Unknown,
                None,
            )))
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackGcpWorkflowsTransport {
    fixture: FixtureGcpWorkflowsTransport,
}

impl LoopbackGcpWorkflowsTransport {
    pub fn new(executions: impl IntoIterator<Item = ExecutionSummary>) -> Self {
        Self {
            fixture: FixtureGcpWorkflowsTransport::new(executions),
        }
    }

    pub fn requests(&self) -> &[ExecutionReadRequest] {
        self.fixture.requests()
    }
}

impl GcpWorkflowsTransport for LoopbackGcpWorkflowsTransport {
    fn list_executions(
        &mut self,
        request: &ExecutionReadRequest,
    ) -> Result<ExecutionPage, GcpWorkflowsProviderError> {
        self.fixture.list_executions(request)
    }

    fn get_execution(
        &mut self,
        request: &ExecutionReadRequest,
    ) -> Result<ExecutionGetResponse, GcpWorkflowsProviderError> {
        self.fixture.get_execution(request)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvGcpWorkflowsTransport;

impl GcpWorkflowsTransport for BlockedEnvGcpWorkflowsTransport {
    fn list_executions(
        &mut self,
        _request: &ExecutionReadRequest,
    ) -> Result<ExecutionPage, GcpWorkflowsProviderError> {
        Err(GcpWorkflowsProviderError::failure(
            ProviderFailureClass::BlockedEnv,
            None,
        ))
    }

    fn get_execution(
        &mut self,
        _request: &ExecutionReadRequest,
    ) -> Result<ExecutionGetResponse, GcpWorkflowsProviderError> {
        Err(GcpWorkflowsProviderError::failure(
            ProviderFailureClass::BlockedEnv,
            None,
        ))
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }
}

pub type BlockedEnvTransport = BlockedEnvGcpWorkflowsTransport;
pub type LoopbackTransport = LoopbackGcpWorkflowsTransport;
pub type RecordingTransport = RecordingGcpWorkflowsTransport;
pub type FakeGcpWorkflowsProvider = GcpWorkflowsProvider<FakeGcpWorkflowsTransport>;

pub fn fake_page_token_for_page(page: u16) -> Result<OpaquePageToken, ModelError> {
    OpaquePageToken::new(format!("fixture-page:{page}"))
}

pub fn provider_failure_projection(error: &GcpWorkflowsProviderError) -> EvidenceState {
    error.evidence_state()
}

pub fn permission_names() -> [PermissionAction; 2] {
    [
        PermissionAction::WorkflowsExecutionsList,
        PermissionAction::WorkflowsExecutionsGet,
    ]
}

pub fn execution_selector_digest(selector: &ExecutionSelector) -> Digest {
    selector.digest()
}

pub fn execution_state_digest(state: ExecutionState) -> Digest {
    Digest::from_serializable(&state)
}

pub fn step_digest(step: &StepMetadata) -> Digest {
    step.digest()
}

pub fn project_digest(project: &ProjectId) -> Digest {
    project.digest()
}

pub fn provider_revision_number_digest(revision: &Revision) -> Digest {
    Digest::from_serializable(revision)
}
