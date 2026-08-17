use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    GITHUB_ACTIONS_API_REVISION, GITHUB_ACTIONS_PROVIDER_ID, GITHUB_ACTIONS_PROVIDER_VERSION,
    canonical_digest,
    model::{
        GithubActionsConclusion, GithubActionsRegistration, GithubActionsScope,
        GithubArtifactMetadata, GithubAuthKind, GithubJobMetadata, GithubJobStatus,
        GithubRunAttempt, GithubTimestamp, GithubWorkflowRunMetadata, GithubWorkflowRunStatus,
        Layer1Authority, MAX_ARTIFACT_NAME_BYTES, MAX_ARTIFACT_SIZE_BYTES, MAX_ARTIFACTS,
        MAX_IDENTIFIER_BYTES, MAX_JOBS, MAX_PAGES, MAX_RESPONSE_BYTES, ModelError, OpaqueEtag,
        OpaquePageToken, RegistrationState, SecretReference, TransportProvenance,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubActionsOperation {
    WorkflowRun,
    Jobs,
    Artifacts,
}

impl GithubActionsOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkflowRun => "workflow_run",
            Self::Jobs => "jobs",
            Self::Artifacts => "artifacts",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GithubActionsHttpMethod {
    Get,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsRequest {
    pub operation: GithubActionsOperation,
    pub method: GithubActionsHttpMethod,
    pub path: String,
    pub page: u16,
    pub installation_digest: String,
    pub permission_digest: String,
    pub etag_digest: Option<String>,
    pub page_token_digest: Option<String>,
    pub request_digest: String,
    #[serde(skip)]
    etag: Option<OpaqueEtag>,
    #[serde(skip)]
    page_token: Option<OpaquePageToken>,
}

impl GithubActionsRequest {
    pub(crate) fn new(
        scope: &GithubActionsScope,
        operation: GithubActionsOperation,
        page: u16,
        etag: Option<OpaqueEtag>,
        page_token: Option<OpaquePageToken>,
    ) -> Self {
        let spec = scope.spec();
        let base = format!(
            "/repos/{}/{}/actions/runs/{}",
            spec.organization.as_str(),
            spec.repository.name.as_str(),
            spec.run_id.get()
        );
        let path = match operation {
            GithubActionsOperation::WorkflowRun => base,
            GithubActionsOperation::Jobs => format!("{base}/attempts/{}/jobs", spec.attempt.get()),
            GithubActionsOperation::Artifacts => format!("{base}/artifacts"),
        };
        let etag_digest = etag.as_ref().map(|value| value.digest().clone());
        let page_token_digest = page_token.as_ref().map(|value| value.digest().clone());
        let request_digest = canonical_digest(&(
            "github-actions-request/v1",
            operation,
            GithubActionsHttpMethod::Get,
            &path,
            page,
            scope.installation_digest(),
            scope.permission_digest(),
            &etag_digest,
            &page_token_digest,
        ));
        Self {
            operation,
            method: GithubActionsHttpMethod::Get,
            path,
            page,
            installation_digest: scope.installation_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            etag_digest,
            page_token_digest,
            request_digest,
            etag,
            page_token,
        }
    }

    #[must_use]
    pub fn etag(&self) -> Option<&OpaqueEtag> {
        self.etag.as_ref()
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.method == GithubActionsHttpMethod::Get
            && self.path.starts_with("/repos/")
            && match self.operation {
                GithubActionsOperation::WorkflowRun => {
                    self.path.ends_with("/actions/runs/".trim_end_matches('/'))
                        || self.path.contains("/actions/runs/")
                }
                GithubActionsOperation::Jobs => {
                    self.path.contains("/actions/runs/") && self.path.ends_with("/jobs")
                }
                GithubActionsOperation::Artifacts => {
                    self.path.contains("/actions/runs/") && self.path.ends_with("/artifacts")
                }
            }
    }

    #[must_use]
    pub fn request_receipt(&self) -> GithubActionsRequestReceipt {
        GithubActionsRequestReceipt {
            operation: self.operation,
            method: self.method,
            path_digest: canonical_digest(&self.path),
            page: self.page,
            installation_digest: self.installation_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            etag_digest: self.etag_digest.clone(),
            page_token_digest: self.page_token_digest.clone(),
            request_digest: self.request_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsRequestReceipt {
    pub operation: GithubActionsOperation,
    pub method: GithubActionsHttpMethod,
    pub path_digest: String,
    pub page: u16,
    pub installation_digest: String,
    pub permission_digest: String,
    pub etag_digest: Option<String>,
    pub page_token_digest: Option<String>,
    pub request_digest: String,
}

/// A bounded response shell. The JSON body is private to the provider parser,
/// while serialized/debug output exposes only size and digest metadata.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsResponse {
    pub status: u16,
    pub response_digest: String,
    pub response_bytes: usize,
    pub etag_digest: Option<String>,
    pub page_token_digest: Option<String>,
    #[serde(skip)]
    pub(crate) body: Vec<u8>,
    #[serde(skip)]
    pub(crate) etag: Option<OpaqueEtag>,
    #[serde(skip)]
    pub(crate) next_page: Option<OpaquePageToken>,
}

impl fmt::Debug for GithubActionsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubActionsResponse")
            .field("status", &self.status)
            .field("response_digest", &self.response_digest)
            .field("response_bytes", &self.response_bytes)
            .field("etag_digest", &self.etag_digest)
            .field("page_token_digest", &self.page_token_digest)
            .finish_non_exhaustive()
    }
}

pub type GithubActionsApiResponse = GithubActionsResponse;

impl GithubActionsResponse {
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Self::json_with_headers(status, value, None, None)
    }

    #[must_use]
    pub fn json_with_headers<T: Serialize>(
        status: u16,
        value: &T,
        etag: Option<OpaqueEtag>,
        next_page: Option<OpaquePageToken>,
    ) -> Self {
        let body = serde_json::to_vec(value).expect("GitHub Actions fixture payload serializes");
        Self::new(status, body, etag, next_page)
    }

    #[must_use]
    pub fn new(
        status: u16,
        body: Vec<u8>,
        etag: Option<OpaqueEtag>,
        next_page: Option<OpaquePageToken>,
    ) -> Self {
        let response_digest = crate::sha256_digest(&body);
        let etag_digest = etag.as_ref().map(|value| value.digest().clone());
        let page_token_digest = next_page.as_ref().map(|value| value.digest().clone());
        Self {
            status,
            response_digest,
            response_bytes: body.len(),
            etag_digest,
            page_token_digest,
            body,
            etag,
            next_page,
        }
    }

    #[must_use]
    pub fn not_modified(etag: OpaqueEtag) -> Self {
        Self::new(304, Vec::new(), Some(etag), None)
    }

    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    #[must_use]
    pub fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    #[must_use]
    pub fn etag(&self) -> Option<&OpaqueEtag> {
        self.etag.as_ref()
    }

    #[must_use]
    pub fn next_page(&self) -> Option<&OpaquePageToken> {
        self.next_page.as_ref()
    }

    pub(crate) fn json_value(&self) -> Result<Value, GithubActionsProviderError> {
        serde_json::from_slice(&self.body).map_err(|_| {
            GithubActionsProviderError::new(
                GithubActionsProviderErrorKind::MalformedResponse,
                Some(self.status),
                "malformed response",
                Vec::new(),
            )
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsResponseReceipt {
    pub operation: GithubActionsOperation,
    pub page: u16,
    pub http_status: u16,
    pub request_digest: String,
    pub response_digest: String,
    pub response_bytes: usize,
    pub etag_digest: Option<String>,
    pub page_token_digest: Option<String>,
    pub from_cache: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GithubActionsTransportError {
    #[error("GitHub Actions native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("GitHub Actions transport timed out")]
    Timeout,
    #[error("GitHub Actions transport failed without a native response")]
    ProviderUnknown,
}

pub trait GithubActionsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &GithubActionsRequest,
    ) -> Result<GithubActionsResponse, GithubActionsTransportError>;
}

#[derive(Clone, Debug)]
pub struct GithubActionsFixture {
    pub workflow_run: GithubActionsResponse,
    pub jobs: Vec<GithubActionsResponse>,
    pub artifacts: Vec<GithubActionsResponse>,
}

impl GithubActionsFixture {
    #[must_use]
    pub fn new(
        workflow_run: GithubActionsResponse,
        jobs: Vec<GithubActionsResponse>,
        artifacts: Vec<GithubActionsResponse>,
    ) -> Self {
        Self {
            workflow_run,
            jobs,
            artifacts,
        }
    }

    #[must_use]
    pub fn single(response: GithubActionsResponse) -> Self {
        Self {
            workflow_run: response.clone(),
            jobs: vec![response.clone()],
            artifacts: vec![response],
        }
    }

    #[must_use]
    pub fn from_responses(responses: Vec<GithubActionsResponse>) -> Self {
        let fallback = responses
            .last()
            .cloned()
            .unwrap_or_else(|| GithubActionsResponse::new(500, Vec::new(), None, None));
        Self {
            workflow_run: responses
                .first()
                .cloned()
                .unwrap_or_else(|| fallback.clone()),
            jobs: vec![
                responses
                    .get(1)
                    .cloned()
                    .unwrap_or_else(|| fallback.clone()),
            ],
            artifacts: vec![responses.get(2).cloned().unwrap_or(fallback)],
        }
    }

    fn response_for(
        &self,
        operation: GithubActionsOperation,
        page: usize,
    ) -> GithubActionsResponse {
        let responses = match operation {
            GithubActionsOperation::WorkflowRun => std::slice::from_ref(&self.workflow_run),
            GithubActionsOperation::Jobs => self.jobs.as_slice(),
            GithubActionsOperation::Artifacts => self.artifacts.as_slice(),
        };
        responses
            .get(page)
            .or_else(|| responses.last())
            .cloned()
            .unwrap_or_else(|| GithubActionsResponse::new(500, Vec::new(), None, None))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureGithubActionsTransport {
    fixture: GithubActionsFixture,
}

impl FixtureGithubActionsTransport {
    #[must_use]
    pub fn new(fixture: GithubActionsFixture) -> Self {
        Self { fixture }
    }

    #[must_use]
    pub fn from_responses(responses: Vec<GithubActionsResponse>) -> Self {
        Self::new(GithubActionsFixture::from_responses(responses))
    }

    #[must_use]
    pub fn fixture(&self) -> &GithubActionsFixture {
        &self.fixture
    }
}

impl GithubActionsTransport for FixtureGithubActionsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &GithubActionsRequest,
    ) -> Result<GithubActionsResponse, GithubActionsTransportError> {
        Ok(self
            .fixture
            .response_for(request.operation, usize::from(request.page)))
    }
}

#[derive(Clone, Debug)]
pub struct RecordingGithubActionsTransport {
    fixture: GithubActionsFixture,
    requests: Vec<GithubActionsRequest>,
}

impl RecordingGithubActionsTransport {
    #[must_use]
    pub fn new(fixture: GithubActionsFixture) -> Self {
        Self {
            fixture,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_responses(responses: Vec<GithubActionsResponse>) -> Self {
        Self::new(GithubActionsFixture::from_responses(responses))
    }

    #[must_use]
    pub fn requests(&self) -> &[GithubActionsRequest] {
        &self.requests
    }
}

impl GithubActionsTransport for RecordingGithubActionsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &GithubActionsRequest,
    ) -> Result<GithubActionsResponse, GithubActionsTransportError> {
        self.requests.push(request.clone());
        Ok(self
            .fixture
            .response_for(request.operation, usize::from(request.page)))
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackGithubActionsTransport {
    fixture: GithubActionsFixture,
    requests: Vec<GithubActionsRequest>,
}

impl LoopbackGithubActionsTransport {
    #[must_use]
    pub fn new(fixture: GithubActionsFixture) -> Self {
        Self {
            fixture,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_responses(responses: Vec<GithubActionsResponse>) -> Self {
        Self::new(GithubActionsFixture::from_responses(responses))
    }

    #[must_use]
    pub fn requests(&self) -> &[GithubActionsRequest] {
        &self.requests
    }
}

impl GithubActionsTransport for LoopbackGithubActionsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &GithubActionsRequest,
    ) -> Result<GithubActionsResponse, GithubActionsTransportError> {
        self.requests.push(request.clone());
        Ok(self
            .fixture
            .response_for(request.operation, usize::from(request.page)))
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvGithubActionsTransport;

impl GithubActionsTransport for BlockedEnvGithubActionsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &GithubActionsRequest,
    ) -> Result<GithubActionsResponse, GithubActionsTransportError> {
        Err(GithubActionsTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GithubActionsProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("native GitHub Actions providers are forbidden in Layer 1")]
    NativeProviderForbidden,
    #[error("provider definition is tampered")]
    TamperedDefinition,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub api_digest: String,
    pub scope_digest: String,
    pub installation_digest: String,
    pub permission_digest: String,
    pub provenance: TransportProvenance,
    pub max_pages: usize,
    pub max_jobs: usize,
    pub max_artifacts: usize,
    pub max_response_bytes: usize,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub provider_digest: String,
}

impl GithubActionsProviderDefinition {
    pub fn new(
        scope: &GithubActionsScope,
        provider_version: impl Into<String>,
        provenance: TransportProvenance,
    ) -> Result<Self, GithubActionsProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(GithubActionsProviderDefinitionError::EmptyVersion);
        }
        let mut definition = Self {
            provider_id: GITHUB_ACTIONS_PROVIDER_ID.to_owned(),
            provider_version,
            api_revision: GITHUB_ACTIONS_API_REVISION.to_owned(),
            api_digest: canonical_digest(&GITHUB_ACTIONS_API_REVISION),
            scope_digest: scope.digest().clone(),
            installation_digest: scope.installation_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            provenance,
            max_pages: MAX_PAGES,
            max_jobs: MAX_JOBS,
            max_artifacts: MAX_ARTIFACTS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
            provider_digest: String::new(),
        };
        definition.provider_digest = definition.compute_digest();
        Ok(definition)
    }

    fn compute_digest(&self) -> String {
        let mut value = self.clone();
        value.provider_digest.clear();
        canonical_digest(&value)
    }

    pub fn validate(
        &self,
        scope: &GithubActionsScope,
    ) -> Result<(), GithubActionsProviderDefinitionError> {
        if self.provider_id != GITHUB_ACTIONS_PROVIDER_ID
            || self.provider_version != GITHUB_ACTIONS_PROVIDER_VERSION
            || self.api_revision != GITHUB_ACTIONS_API_REVISION
            || self.api_digest != canonical_digest(&GITHUB_ACTIONS_API_REVISION)
            || self.scope_digest != *scope.digest()
            || self.installation_digest != *scope.installation_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.max_pages != MAX_PAGES
            || self.max_jobs != MAX_JOBS
            || self.max_artifacts != MAX_ARTIFACTS
            || self.max_response_bytes != MAX_RESPONSE_BYTES
            || !self.read_only
            || self.live_execution
            || self.native
            || self.connected
            || self.provider_digest != self.compute_digest()
        {
            return Err(GithubActionsProviderDefinitionError::TamperedDefinition);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &String {
        &self.provider_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubActionsProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnv,
    ProviderUnknown,
    MalformedResponse,
    ResponseTooLarge,
    PaginationMismatch,
    EtagMismatch,
    StaleHead,
    AttemptMismatch,
    ScopeMismatch,
    PartialMetadata,
    ArtifactExpired,
    Tampered,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubActionsProviderError {
    pub kind: GithubActionsProviderErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: String,
    pub response_receipts: Vec<GithubActionsResponseReceipt>,
}

impl std::error::Error for GithubActionsProviderError {}

impl fmt::Display for GithubActionsProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GitHub Actions provider failed with {:?} ({:?})",
            self.kind, self.status_code
        )
    }
}

impl GithubActionsProviderError {
    #[must_use]
    pub fn new(
        kind: GithubActionsProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: &str,
        response_receipts: Vec<GithubActionsResponseReceipt>,
    ) -> Self {
        let diagnostic_bytes = diagnostic.as_bytes();
        let bounded = &diagnostic_bytes[..diagnostic_bytes
            .len()
            .min(crate::model::MAX_DIAGNOSTIC_BYTES)];
        Self {
            kind,
            status_code,
            diagnostic_digest: crate::sha256_digest(bounded),
            response_receipts,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubActionsObservation {
    pub run: GithubWorkflowRunMetadata,
    pub jobs: Vec<GithubJobMetadata>,
    pub artifacts: Vec<GithubArtifactMetadata>,
    pub response_receipts: Vec<GithubActionsResponseReceipt>,
    pub provenance: TransportProvenance,
    pub authority: Layer1Authority,
}

#[derive(Clone)]
pub struct GithubActionsProvider<T> {
    scope: GithubActionsScope,
    secret_reference: SecretReference,
    definition: GithubActionsProviderDefinition,
    registration: GithubActionsRegistration,
    transport: T,
    cache: BTreeMap<String, GithubActionsResponse>,
}

impl<T: GithubActionsTransport> fmt::Debug for GithubActionsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubActionsProvider")
            .field("scope_digest", self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("transport", &"<redacted transport>")
            .field("cache_entries", &self.cache.len())
            .finish()
    }
}

impl<T: GithubActionsTransport> GithubActionsProvider<T> {
    pub fn new(
        scope: GithubActionsScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, GithubActionsProviderDefinitionError> {
        scope.validate()?;
        if secret_reference.scope_digest() != scope.digest()
            || !matches!(
                secret_reference.auth_kind(),
                GithubAuthKind::App | GithubAuthKind::OAuth
            )
        {
            return Err(GithubActionsProviderDefinitionError::Model(
                ModelError::InvalidScope("secret reference scope"),
            ));
        }
        let definition = GithubActionsProviderDefinition::new(
            &scope,
            GITHUB_ACTIONS_PROVIDER_VERSION,
            transport.provenance(),
        )?;
        let registration = GithubActionsRegistration::bind(
            &scope,
            &secret_reference,
            definition.provider_digest.clone(),
            definition.provider_version.clone(),
        );
        Ok(Self {
            scope,
            secret_reference,
            definition,
            registration,
            transport,
            cache: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GithubActionsScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &GithubActionsProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn registration(&self) -> &GithubActionsRegistration {
        &self.registration
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn provider_digest(&self) -> &String {
        self.definition.digest()
    }

    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    pub fn validate_registration(&self) -> Result<(), GithubActionsProviderError> {
        if self.secret_reference.is_revoked()
            || self.registration.state != RegistrationState::Active
        {
            return Err(self.error(
                GithubActionsProviderErrorKind::RegistrationRevoked,
                None,
                "registration revoked",
                Vec::new(),
            ));
        }
        self.definition.validate(&self.scope).map_err(|_| {
            self.error(
                GithubActionsProviderErrorKind::Tampered,
                None,
                "definition drift",
                Vec::new(),
            )
        })?;
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.definition.digest(),
                &self.definition.provider_version,
            )
            .map_err(|_| {
                self.error(
                    GithubActionsProviderErrorKind::Tampered,
                    None,
                    "registration drift",
                    Vec::new(),
                )
            })
    }

    pub fn read(&mut self) -> Result<GithubActionsObservation, GithubActionsProviderError> {
        self.validate_registration()?;
        let mut response_receipts = Vec::new();
        let run_responses =
            self.fetch_pages(GithubActionsOperation::WorkflowRun, &mut response_receipts)?;
        if run_responses.len() != 1 {
            return Err(self.error(
                GithubActionsProviderErrorKind::PaginationMismatch,
                None,
                "workflow run returned multiple pages",
                response_receipts,
            ));
        }
        let run = self.parse_run(&run_responses[0], &response_receipts)?;
        let job_responses =
            self.fetch_pages(GithubActionsOperation::Jobs, &mut response_receipts)?;
        let jobs = self.parse_jobs(&job_responses, &response_receipts)?;
        let artifact_responses =
            self.fetch_pages(GithubActionsOperation::Artifacts, &mut response_receipts)?;
        let artifacts = self.parse_artifacts(&artifact_responses, &response_receipts)?;
        Ok(GithubActionsObservation {
            run,
            jobs,
            artifacts,
            response_receipts,
            provenance: self.provenance(),
            authority: Layer1Authority::default(),
        })
    }

    pub fn revoke(&mut self) -> Result<crate::RegistrationRevocationReceipt, ModelError> {
        self.registration.revoke()
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        self.registration.restore()
    }

    #[allow(clippy::unused_self)]
    fn error(
        &self,
        kind: GithubActionsProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: &str,
        response_receipts: Vec<GithubActionsResponseReceipt>,
    ) -> GithubActionsProviderError {
        GithubActionsProviderError::new(kind, status_code, diagnostic, response_receipts)
    }

    fn fetch_pages(
        &mut self,
        operation: GithubActionsOperation,
        response_receipts: &mut Vec<GithubActionsResponseReceipt>,
    ) -> Result<Vec<GithubActionsResponse>, GithubActionsProviderError> {
        let mut responses = Vec::new();
        let mut next_page = None;
        let mut seen_tokens = BTreeSet::new();
        for page in 0..MAX_PAGES {
            if operation == GithubActionsOperation::WorkflowRun && page > 0 {
                return Err(self.error(
                    GithubActionsProviderErrorKind::PaginationMismatch,
                    None,
                    "workflow run pagination",
                    response_receipts.clone(),
                ));
            }
            let cache_key = format!(
                "{}:{}",
                operation.as_str(),
                next_page.as_ref().map_or_else(
                    || "first".to_owned(),
                    |token: &OpaquePageToken| token.digest().clone()
                )
            );
            let etag = self
                .cache
                .get(&cache_key)
                .and_then(|response| response.etag.clone());
            let request = GithubActionsRequest::new(
                &self.scope,
                operation,
                u16::try_from(page).expect("bounded page fits u16"),
                etag,
                next_page.clone(),
            );
            if !request.is_allowlisted() {
                return Err(self.error(
                    GithubActionsProviderErrorKind::Tampered,
                    None,
                    "request path is not allowlisted",
                    response_receipts.clone(),
                ));
            }
            let response = self.transport.execute(&request).map_err(|error| {
                let (kind, diagnostic) = match error {
                    GithubActionsTransportError::BlockedEnv => {
                        (GithubActionsProviderErrorKind::BlockedEnv, "BLOCKED_ENV")
                    }
                    GithubActionsTransportError::Timeout => {
                        (GithubActionsProviderErrorKind::Timeout, "timeout")
                    }
                    GithubActionsTransportError::ProviderUnknown => (
                        GithubActionsProviderErrorKind::ProviderUnknown,
                        "transport unknown",
                    ),
                };
                self.error(kind, None, diagnostic, response_receipts.clone())
            })?;
            let http_status = response.status;
            let request_receipt = request.request_receipt();
            let (effective, from_cache) = match http_status {
                200 => {
                    if response.response_bytes > MAX_RESPONSE_BYTES {
                        return Err(self.error(
                            GithubActionsProviderErrorKind::ResponseTooLarge,
                            Some(response.status),
                            "response too large",
                            response_receipts.clone(),
                        ));
                    }
                    self.cache.insert(cache_key, response.clone());
                    (response, false)
                }
                304 => {
                    let cached = self.cache.get(&cache_key).cloned().ok_or_else(|| {
                        self.error(
                            GithubActionsProviderErrorKind::EtagMismatch,
                            Some(304),
                            "304 without cached response",
                            response_receipts.clone(),
                        )
                    })?;
                    if response.etag.as_ref().map(OpaqueEtag::digest)
                        != cached.etag.as_ref().map(OpaqueEtag::digest)
                    {
                        return Err(self.error(
                            GithubActionsProviderErrorKind::EtagMismatch,
                            Some(304),
                            "etag mismatch",
                            response_receipts.clone(),
                        ));
                    }
                    (cached, true)
                }
                status => {
                    let kind = classify_http_status(status);
                    let receipt = GithubActionsResponseReceipt {
                        operation,
                        page: request.page,
                        http_status: status,
                        request_digest: request.request_digest.clone(),
                        response_digest: response.response_digest.clone(),
                        response_bytes: response.response_bytes,
                        etag_digest: response.etag_digest.clone(),
                        page_token_digest: response.page_token_digest.clone(),
                        from_cache: false,
                    };
                    response_receipts.push(receipt);
                    return Err(self.error(
                        kind,
                        Some(status),
                        "provider HTTP status",
                        response_receipts.clone(),
                    ));
                }
            };
            response_receipts.push(GithubActionsResponseReceipt {
                operation,
                page: request.page,
                http_status,
                request_digest: request_receipt.request_digest,
                response_digest: effective.response_digest.clone(),
                response_bytes: effective.response_bytes,
                etag_digest: effective.etag_digest.clone(),
                page_token_digest: effective.page_token_digest.clone(),
                from_cache,
            });
            responses.push(effective.clone());
            let returned_token = effective.next_page.clone();
            if let Some(token) = &returned_token
                && !seen_tokens.insert(token.digest().clone())
            {
                return Err(self.error(
                    GithubActionsProviderErrorKind::PaginationMismatch,
                    Some(effective.status),
                    "pagination cursor repeated",
                    response_receipts.clone(),
                ));
            }
            next_page = returned_token;
            if next_page.is_none() {
                return Ok(responses);
            }
        }
        Err(self.error(
            GithubActionsProviderErrorKind::PaginationMismatch,
            None,
            "pagination exceeded bound",
            response_receipts.clone(),
        ))
    }

    fn parse_run(
        &self,
        response: &GithubActionsResponse,
        receipts: &[GithubActionsResponseReceipt],
    ) -> Result<GithubWorkflowRunMetadata, GithubActionsProviderError> {
        let value = response.json_value().map_err(|_| {
            self.error(
                GithubActionsProviderErrorKind::MalformedResponse,
                Some(response.status),
                "workflow run JSON",
                receipts.to_vec(),
            )
        })?;
        let value = value.get("workflow_run").unwrap_or(&value).clone();
        let wire: WorkflowRunWire = serde_json::from_value(value).map_err(|_| {
            self.error(
                GithubActionsProviderErrorKind::MalformedResponse,
                Some(response.status),
                "workflow run fields",
                receipts.to_vec(),
            )
        })?;
        let id = positive_run_id(wire.id, self, receipts)?;
        let workflow_id = positive_workflow_id(wire.workflow_id, self, receipts)?;
        let attempt = GithubRunAttempt::new(wire.run_attempt).map_err(|_| {
            self.error(
                GithubActionsProviderErrorKind::AttemptMismatch,
                Some(response.status),
                "invalid run attempt",
                receipts.to_vec(),
            )
        })?;
        let status = GithubWorkflowRunStatus::parse(&wire.status);
        let conclusion = GithubActionsConclusion::parse(wire.conclusion.as_deref());
        if conclusion == Some(GithubActionsConclusion::Unknown) {
            return Err(self.error(
                GithubActionsProviderErrorKind::Tampered,
                Some(response.status),
                "unknown workflow run conclusion",
                receipts.to_vec(),
            ));
        }
        let commit = crate::GithubCommitSha::new(wire.head_sha).map_err(|_| {
            self.error(
                GithubActionsProviderErrorKind::MalformedResponse,
                Some(response.status),
                "workflow run commit",
                receipts.to_vec(),
            )
        })?;
        let created_at = GithubTimestamp::new(wire.created_at).map_err(|_| {
            self.error(
                GithubActionsProviderErrorKind::MalformedResponse,
                Some(response.status),
                "workflow run timestamp",
                receipts.to_vec(),
            )
        })?;
        let updated_at = GithubTimestamp::new(wire.updated_at).map_err(|_| {
            self.error(
                GithubActionsProviderErrorKind::MalformedResponse,
                Some(response.status),
                "workflow run timestamp",
                receipts.to_vec(),
            )
        })?;
        let run_started_at = wire
            .run_started_at
            .map(GithubTimestamp::new)
            .transpose()
            .map_err(|_| {
                self.error(
                    GithubActionsProviderErrorKind::MalformedResponse,
                    Some(response.status),
                    "workflow run timestamp",
                    receipts.to_vec(),
                )
            })?;
        if id != self.scope.spec().run_id
            || workflow_id != self.scope.spec().workflow_id
            || attempt != self.scope.spec().attempt
        {
            return Err(self.error(
                GithubActionsProviderErrorKind::AttemptMismatch,
                Some(response.status),
                "workflow run scope mismatch",
                receipts.to_vec(),
            ));
        }
        if commit != self.scope.spec().commit {
            return Err(self.error(
                GithubActionsProviderErrorKind::StaleHead,
                Some(response.status),
                "workflow run head does not match scope",
                receipts.to_vec(),
            ));
        }
        if status == GithubWorkflowRunStatus::Unknown {
            return Err(self.error(
                GithubActionsProviderErrorKind::Tampered,
                Some(response.status),
                "unknown workflow run status",
                receipts.to_vec(),
            ));
        }
        Ok(GithubWorkflowRunMetadata {
            id,
            workflow_id,
            attempt,
            status,
            conclusion,
            commit,
            created_at,
            updated_at,
            run_started_at,
            metadata_digest: String::new(),
        }
        .with_digest())
    }

    fn parse_jobs(
        &self,
        responses: &[GithubActionsResponse],
        receipts: &[GithubActionsResponseReceipt],
    ) -> Result<Vec<GithubJobMetadata>, GithubActionsProviderError> {
        let mut jobs = Vec::new();
        let mut total_count = None;
        for response in responses {
            let value = response.json_value().map_err(|_| {
                self.error(
                    GithubActionsProviderErrorKind::MalformedResponse,
                    Some(response.status),
                    "jobs JSON",
                    receipts.to_vec(),
                )
            })?;
            let value = match value.get("jobs") {
                Some(candidate) if candidate.is_object() => candidate.clone(),
                _ => value,
            };
            let wire: JobsWire = serde_json::from_value(value).map_err(|_| {
                self.error(
                    GithubActionsProviderErrorKind::MalformedResponse,
                    Some(response.status),
                    "jobs fields",
                    receipts.to_vec(),
                )
            })?;
            total_count = Some(total_count.unwrap_or(wire.total_count));
            if total_count != Some(wire.total_count) || wire.total_count > MAX_JOBS {
                return Err(self.error(
                    GithubActionsProviderErrorKind::PartialMetadata,
                    Some(response.status),
                    "jobs count drift or bound",
                    receipts.to_vec(),
                ));
            }
            for job in wire.jobs {
                let id = crate::GithubJobId::new(job.id).map_err(|_| {
                    self.error(
                        GithubActionsProviderErrorKind::MalformedResponse,
                        Some(response.status),
                        "job id",
                        receipts.to_vec(),
                    )
                })?;
                if jobs
                    .iter()
                    .any(|candidate: &GithubJobMetadata| candidate.id == id)
                {
                    return Err(self.error(
                        GithubActionsProviderErrorKind::Tampered,
                        Some(response.status),
                        "duplicate job id",
                        receipts.to_vec(),
                    ));
                }
                if job.name.len() > MAX_IDENTIFIER_BYTES {
                    return Err(self.error(
                        GithubActionsProviderErrorKind::PartialMetadata,
                        Some(response.status),
                        "job name bound",
                        receipts.to_vec(),
                    ));
                }
                if job.name.trim() != job.name || job.name.chars().any(char::is_control) {
                    return Err(self.error(
                        GithubActionsProviderErrorKind::MalformedResponse,
                        Some(response.status),
                        "job name characters",
                        receipts.to_vec(),
                    ));
                }
                if job
                    .run_id
                    .is_some_and(|run_id| run_id != self.scope.spec().run_id.get())
                    || job
                        .run_attempt
                        .is_some_and(|attempt| attempt != self.scope.spec().attempt.get())
                {
                    return Err(self.error(
                        GithubActionsProviderErrorKind::AttemptMismatch,
                        Some(response.status),
                        "job attempt scope mismatch",
                        receipts.to_vec(),
                    ));
                }
                let status = GithubJobStatus::parse(&job.status);
                if status == GithubJobStatus::Unknown {
                    return Err(self.error(
                        GithubActionsProviderErrorKind::Tampered,
                        Some(response.status),
                        "unknown job status",
                        receipts.to_vec(),
                    ));
                }
                let started_at = job
                    .started_at
                    .map(GithubTimestamp::new)
                    .transpose()
                    .map_err(|_| {
                        self.error(
                            GithubActionsProviderErrorKind::MalformedResponse,
                            Some(response.status),
                            "job timestamp",
                            receipts.to_vec(),
                        )
                    })?;
                let completed_at = job
                    .completed_at
                    .map(GithubTimestamp::new)
                    .transpose()
                    .map_err(|_| {
                        self.error(
                            GithubActionsProviderErrorKind::MalformedResponse,
                            Some(response.status),
                            "job timestamp",
                            receipts.to_vec(),
                        )
                    })?;
                let conclusion = GithubActionsConclusion::parse(job.conclusion.as_deref());
                if conclusion == Some(GithubActionsConclusion::Unknown) {
                    return Err(self.error(
                        GithubActionsProviderErrorKind::Tampered,
                        Some(response.status),
                        "unknown job conclusion",
                        receipts.to_vec(),
                    ));
                }
                jobs.push(
                    GithubJobMetadata {
                        id,
                        name: job.name,
                        status,
                        conclusion,
                        started_at,
                        completed_at,
                        metadata_digest: String::new(),
                    }
                    .with_digest(),
                );
            }
        }
        jobs.sort_by_key(|job| job.id);
        let expected = total_count.unwrap_or(0);
        if expected != jobs.len() || jobs.len() > MAX_JOBS {
            return Err(self.error(
                GithubActionsProviderErrorKind::PartialMetadata,
                None,
                "job page is incomplete",
                receipts.to_vec(),
            ));
        }
        if !jobs.iter().any(|job| job.id == self.scope.spec().job_id) {
            return Err(self.error(
                GithubActionsProviderErrorKind::ScopeMismatch,
                None,
                "scoped job is missing",
                receipts.to_vec(),
            ));
        }
        Ok(jobs)
    }

    fn parse_artifacts(
        &self,
        responses: &[GithubActionsResponse],
        receipts: &[GithubActionsResponseReceipt],
    ) -> Result<Vec<GithubArtifactMetadata>, GithubActionsProviderError> {
        let mut artifacts = Vec::new();
        let mut total_count = None;
        for response in responses {
            let value = response.json_value().map_err(|_| {
                self.error(
                    GithubActionsProviderErrorKind::MalformedResponse,
                    Some(response.status),
                    "artifacts JSON",
                    receipts.to_vec(),
                )
            })?;
            let value = match value.get("artifacts") {
                Some(candidate) if candidate.is_object() => candidate.clone(),
                _ => value,
            };
            let wire: ArtifactsWire = serde_json::from_value(value).map_err(|_| {
                self.error(
                    GithubActionsProviderErrorKind::MalformedResponse,
                    Some(response.status),
                    "artifacts fields",
                    receipts.to_vec(),
                )
            })?;
            total_count = Some(total_count.unwrap_or(wire.total_count));
            if total_count != Some(wire.total_count) || wire.total_count > MAX_ARTIFACTS {
                return Err(self.error(
                    GithubActionsProviderErrorKind::PartialMetadata,
                    Some(response.status),
                    "artifact count drift or bound",
                    receipts.to_vec(),
                ));
            }
            for artifact in wire.artifacts {
                if artifact.id == 0
                    || artifact.name.is_empty()
                    || artifact.name.len() > MAX_ARTIFACT_NAME_BYTES
                    || artifact.name.trim() != artifact.name
                    || artifact.name.chars().any(char::is_control)
                    || artifact.size_in_bytes > MAX_ARTIFACT_SIZE_BYTES
                {
                    return Err(self.error(
                        GithubActionsProviderErrorKind::PartialMetadata,
                        Some(response.status),
                        "artifact metadata bound",
                        receipts.to_vec(),
                    ));
                }
                if artifacts
                    .iter()
                    .any(|candidate: &GithubArtifactMetadata| candidate.id == artifact.id)
                {
                    return Err(self.error(
                        GithubActionsProviderErrorKind::Tampered,
                        Some(response.status),
                        "duplicate artifact id",
                        receipts.to_vec(),
                    ));
                }
                let digest =
                    normalize_artifact_digest(artifact.digest.as_deref()).ok_or_else(|| {
                        self.error(
                            GithubActionsProviderErrorKind::PartialMetadata,
                            Some(response.status),
                            "artifact digest missing",
                            receipts.to_vec(),
                        )
                    })?;
                let expires_at = artifact
                    .expires_at
                    .map(GithubTimestamp::new)
                    .transpose()
                    .map_err(|_| {
                        self.error(
                            GithubActionsProviderErrorKind::MalformedResponse,
                            Some(response.status),
                            "artifact expiration timestamp",
                            receipts.to_vec(),
                        )
                    })?;
                if artifact.expired {
                    return Err(self.error(
                        GithubActionsProviderErrorKind::ArtifactExpired,
                        Some(response.status),
                        "artifact expired",
                        receipts.to_vec(),
                    ));
                }
                artifacts.push(
                    GithubArtifactMetadata {
                        id: artifact.id,
                        name: artifact.name,
                        size_bytes: artifact.size_in_bytes,
                        digest,
                        expired: false,
                        expires_at,
                        metadata_digest: String::new(),
                    }
                    .with_digest(),
                );
            }
        }
        artifacts.sort_by_key(|artifact| artifact.id);
        if total_count.unwrap_or(0) != artifacts.len() || artifacts.len() > MAX_ARTIFACTS {
            return Err(self.error(
                GithubActionsProviderErrorKind::PartialMetadata,
                None,
                "artifact page is incomplete",
                receipts.to_vec(),
            ));
        }
        Ok(artifacts)
    }
}

fn classify_http_status(status: u16) -> GithubActionsProviderErrorKind {
    match status {
        400 => GithubActionsProviderErrorKind::BadRequest,
        401 => GithubActionsProviderErrorKind::Unauthenticated,
        403 => GithubActionsProviderErrorKind::PermissionDenied,
        404 => GithubActionsProviderErrorKind::NotFound,
        409 => GithubActionsProviderErrorKind::Conflict,
        429 => GithubActionsProviderErrorKind::RateLimited,
        500..=599 => GithubActionsProviderErrorKind::ServerFailure,
        _ => GithubActionsProviderErrorKind::ProviderUnknown,
    }
}

fn normalize_artifact_digest(value: Option<&str>) -> Option<String> {
    let value = value?;
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

fn positive_run_id(
    value: u64,
    provider: &GithubActionsProvider<impl GithubActionsTransport>,
    receipts: &[GithubActionsResponseReceipt],
) -> Result<crate::GithubWorkflowRunId, GithubActionsProviderError> {
    crate::GithubWorkflowRunId::new(value).map_err(|_| {
        provider.error(
            GithubActionsProviderErrorKind::MalformedResponse,
            None,
            "run id",
            receipts.to_vec(),
        )
    })
}

fn positive_workflow_id(
    value: u64,
    provider: &GithubActionsProvider<impl GithubActionsTransport>,
    receipts: &[GithubActionsResponseReceipt],
) -> Result<crate::GithubWorkflowId, GithubActionsProviderError> {
    crate::GithubWorkflowId::new(value).map_err(|_| {
        provider.error(
            GithubActionsProviderErrorKind::MalformedResponse,
            None,
            "workflow id",
            receipts.to_vec(),
        )
    })
}

#[derive(Debug, Deserialize)]
struct WorkflowRunWire {
    id: u64,
    workflow_id: u64,
    run_attempt: u32,
    status: String,
    conclusion: Option<String>,
    head_sha: String,
    created_at: String,
    updated_at: String,
    run_started_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JobsWire {
    total_count: usize,
    jobs: Vec<JobWire>,
}

#[derive(Debug, Deserialize)]
struct JobWire {
    id: u64,
    name: String,
    run_id: Option<u64>,
    run_attempt: Option<u32>,
    status: String,
    conclusion: Option<String>,
    started_at: Option<String>,
    completed_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArtifactsWire {
    total_count: usize,
    artifacts: Vec<ArtifactWire>,
}

#[derive(Debug, Deserialize)]
struct ArtifactWire {
    id: u64,
    name: String,
    size_in_bytes: u64,
    digest: Option<String>,
    expired: bool,
    expires_at: Option<String>,
}
