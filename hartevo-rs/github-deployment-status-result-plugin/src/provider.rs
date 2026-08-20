use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    GITHUB_DEPLOYMENT_STATUS_API_REVISION, GITHUB_DEPLOYMENT_STATUS_PROVIDER_ID,
    GITHUB_DEPLOYMENT_STATUS_PROVIDER_VERSION, GithubAuthKind, GithubDeploymentMetadata,
    GithubDeploymentStatusMetadata, GithubDeploymentStatusRegistration,
    GithubDeploymentStatusScope, GithubDeploymentStatusState, GithubEnvironment, GithubTimestamp,
    HISTORY_SECONDS, Layer1Authority, MAX_DIAGNOSTIC_BYTES, MAX_HISTORY_DAYS, MAX_PAGES,
    MAX_RESPONSE_BYTES, MAX_STATUSES, ModelError, OpaqueEtag, OpaquePageToken,
    RegistrationRevocationReceipt, RegistrationState, SecretReference, TransportProvenance,
    canonical_digest, model::digest_url,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubDeploymentStatusOperation {
    Deployment,
    Statuses,
}

impl GithubDeploymentStatusOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Statuses => "statuses",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GithubDeploymentStatusHttpMethod {
    Get,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusRequest {
    pub operation: GithubDeploymentStatusOperation,
    pub method: GithubDeploymentStatusHttpMethod,
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

impl GithubDeploymentStatusRequest {
    fn new(
        scope: &GithubDeploymentStatusScope,
        operation: GithubDeploymentStatusOperation,
        page: usize,
        etag: Option<OpaqueEtag>,
        page_token: Option<OpaquePageToken>,
    ) -> Self {
        let page = u16::try_from(page).unwrap_or(u16::MAX);
        let path = match operation {
            GithubDeploymentStatusOperation::Deployment => format!(
                "/repos/{}/{}/deployments/{}",
                scope.organization().as_str(),
                scope.repository().name.as_str(),
                scope.deployment_id().value()
            ),
            GithubDeploymentStatusOperation::Statuses => format!(
                "/repos/{}/{}/deployments/{}/statuses?per_page={}&page={}",
                scope.organization().as_str(),
                scope.repository().name.as_str(),
                scope.deployment_id().value(),
                MAX_STATUSES,
                page
            ),
        };
        let etag_digest = etag.as_ref().map(|value| value.digest().clone());
        let page_token_digest = page_token.as_ref().map(|value| value.digest().clone());
        let mut request = Self {
            operation,
            method: GithubDeploymentStatusHttpMethod::Get,
            path,
            page,
            installation_digest: scope.installation_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            etag_digest,
            page_token_digest,
            request_digest: String::new(),
            etag,
            page_token,
        };
        request.request_digest = canonical_digest(&(
            "github-deployment-status-request/v1",
            request.operation,
            request.method,
            &request.path,
            request.page,
            &request.installation_digest,
            &request.permission_digest,
            &request.etag_digest,
            &request.page_token_digest,
        ));
        request
    }

    #[must_use]
    pub fn path_and_query(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    #[must_use]
    pub fn etag(&self) -> Option<&OpaqueEtag> {
        self.etag.as_ref()
    }

    #[must_use]
    pub fn receipt(&self) -> GithubDeploymentStatusRequestReceipt {
        GithubDeploymentStatusRequestReceipt {
            operation: self.operation,
            method: self.method,
            path_digest: crate::sha256_digest(self.path.as_bytes()),
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
pub struct GithubDeploymentStatusRequestReceipt {
    pub operation: GithubDeploymentStatusOperation,
    pub method: GithubDeploymentStatusHttpMethod,
    pub path_digest: String,
    pub page: u16,
    pub installation_digest: String,
    pub permission_digest: String,
    pub etag_digest: Option<String>,
    pub page_token_digest: Option<String>,
    pub request_digest: String,
}

/// Response shell that exposes only bounded digest/size/header metadata. The
/// JSON body is private to the provider parser.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusResponse {
    pub status: u16,
    pub response_digest: String,
    pub response_bytes: usize,
    pub etag_digest: Option<String>,
    pub next_page_digest: Option<String>,
    #[serde(skip)]
    pub(crate) body: Vec<u8>,
    #[serde(skip)]
    pub(crate) etag: Option<OpaqueEtag>,
    #[serde(skip)]
    pub(crate) next_page: Option<OpaquePageToken>,
}

pub type GithubDeploymentStatusApiResponse = GithubDeploymentStatusResponse;

impl fmt::Debug for GithubDeploymentStatusResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeploymentStatusResponse")
            .field("status", &self.status)
            .field("response_digest", &self.response_digest)
            .field("response_bytes", &self.response_bytes)
            .field("etag_digest", &self.etag_digest)
            .field("next_page_digest", &self.next_page_digest)
            .finish_non_exhaustive()
    }
}

impl GithubDeploymentStatusResponse {
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
        let body = serde_json::to_vec(value).expect("fixture response serializes");
        let response_digest =
            canonical_digest(&("github-deployment-status-response/v1", status, &body));
        let etag_digest = etag.as_ref().map(|value| value.digest().clone());
        let next_page_digest = next_page.as_ref().map(|value| value.digest().clone());
        Self {
            status,
            response_digest,
            response_bytes: body.len(),
            etag_digest,
            next_page_digest,
            body,
            etag,
            next_page,
        }
    }

    fn json_value(&self) -> Result<Value, GithubDeploymentStatusProviderErrorKind> {
        serde_json::from_slice(&self.body)
            .map_err(|_| GithubDeploymentStatusProviderErrorKind::MalformedResponse)
    }

    fn next_page_token(&self) -> Option<&OpaquePageToken> {
        self.next_page.as_ref()
    }

    fn response_receipt(
        &self,
        request: &GithubDeploymentStatusRequest,
    ) -> GithubDeploymentStatusResponseReceipt {
        GithubDeploymentStatusResponseReceipt {
            operation: request.operation,
            page: request.page,
            http_status: self.status,
            request_digest: request.request_digest.clone(),
            response_digest: self.response_digest.clone(),
            response_bytes: self.response_bytes,
            etag_digest: self.etag_digest.clone(),
            next_page_digest: self.next_page_digest.clone(),
            from_cache: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusResponseReceipt {
    pub operation: GithubDeploymentStatusOperation,
    pub page: u16,
    pub http_status: u16,
    pub request_digest: String,
    pub response_digest: String,
    pub response_bytes: usize,
    pub etag_digest: Option<String>,
    pub next_page_digest: Option<String>,
    pub from_cache: bool,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GithubDeploymentStatusTransportError {
    #[error("GitHub Deployment native transport is unavailable: BLOCKED_ENV")]
    BlockedEnv,
    #[error("GitHub Deployment transport timed out")]
    Timeout,
    #[error("GitHub Deployment transport failed without a native response")]
    ProviderUnknown,
}

pub trait GithubDeploymentStatusTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &mut self,
        request: &GithubDeploymentStatusRequest,
    ) -> Result<GithubDeploymentStatusResponse, GithubDeploymentStatusTransportError>;
}

#[derive(Clone, Debug)]
pub struct GithubDeploymentStatusFixture {
    pub deployment: GithubDeploymentStatusResponse,
    pub status_pages: Vec<GithubDeploymentStatusResponse>,
}

impl GithubDeploymentStatusFixture {
    #[must_use]
    pub fn new(
        deployment: GithubDeploymentStatusResponse,
        status_pages: Vec<GithubDeploymentStatusResponse>,
    ) -> Self {
        Self {
            deployment,
            status_pages,
        }
    }

    #[must_use]
    pub fn from_responses(responses: Vec<GithubDeploymentStatusResponse>) -> Self {
        let mut responses = responses.into_iter();
        let deployment = responses.next().unwrap_or_else(|| {
            GithubDeploymentStatusResponse::json(
                500,
                &serde_json::json!({
                    "message": "fixture deployment response missing"
                }),
            )
        });
        Self::new(deployment, responses.collect())
    }

    fn response_for(
        &self,
        request: &GithubDeploymentStatusRequest,
    ) -> Result<GithubDeploymentStatusResponse, GithubDeploymentStatusTransportError> {
        match request.operation {
            GithubDeploymentStatusOperation::Deployment if request.page == 0 => {
                Ok(self.deployment.clone())
            }
            GithubDeploymentStatusOperation::Deployment => {
                Err(GithubDeploymentStatusTransportError::ProviderUnknown)
            }
            GithubDeploymentStatusOperation::Statuses => self
                .status_pages
                .get(usize::from(request.page))
                .cloned()
                .ok_or(GithubDeploymentStatusTransportError::ProviderUnknown),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FixtureGithubDeploymentStatusTransport {
    fixture: GithubDeploymentStatusFixture,
}

impl FixtureGithubDeploymentStatusTransport {
    #[must_use]
    pub fn new(fixture: GithubDeploymentStatusFixture) -> Self {
        Self { fixture }
    }

    #[must_use]
    pub fn fixture(&self) -> &GithubDeploymentStatusFixture {
        &self.fixture
    }
}

impl GithubDeploymentStatusTransport for FixtureGithubDeploymentStatusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &mut self,
        request: &GithubDeploymentStatusRequest,
    ) -> Result<GithubDeploymentStatusResponse, GithubDeploymentStatusTransportError> {
        self.fixture.response_for(request)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingGithubDeploymentStatusTransport {
    fixture: GithubDeploymentStatusFixture,
    requests: Vec<GithubDeploymentStatusRequest>,
}

impl RecordingGithubDeploymentStatusTransport {
    #[must_use]
    pub fn new(fixture: GithubDeploymentStatusFixture) -> Self {
        Self {
            fixture,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_responses(responses: Vec<GithubDeploymentStatusResponse>) -> Self {
        Self::new(GithubDeploymentStatusFixture::from_responses(responses))
    }

    #[must_use]
    pub fn requests(&self) -> &[GithubDeploymentStatusRequest] {
        &self.requests
    }
}

impl GithubDeploymentStatusTransport for RecordingGithubDeploymentStatusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &mut self,
        request: &GithubDeploymentStatusRequest,
    ) -> Result<GithubDeploymentStatusResponse, GithubDeploymentStatusTransportError> {
        self.requests.push(request.clone());
        self.fixture.response_for(request)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackGithubDeploymentStatusTransport {
    fixture: GithubDeploymentStatusFixture,
    requests: Vec<GithubDeploymentStatusRequest>,
}

impl LoopbackGithubDeploymentStatusTransport {
    #[must_use]
    pub fn new(fixture: GithubDeploymentStatusFixture) -> Self {
        Self {
            fixture,
            requests: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_responses(responses: Vec<GithubDeploymentStatusResponse>) -> Self {
        Self::new(GithubDeploymentStatusFixture::from_responses(responses))
    }

    #[must_use]
    pub fn requests(&self) -> &[GithubDeploymentStatusRequest] {
        &self.requests
    }
}

impl GithubDeploymentStatusTransport for LoopbackGithubDeploymentStatusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &mut self,
        request: &GithubDeploymentStatusRequest,
    ) -> Result<GithubDeploymentStatusResponse, GithubDeploymentStatusTransportError> {
        self.requests.push(request.clone());
        self.fixture.response_for(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvGithubDeploymentStatusTransport;

impl GithubDeploymentStatusTransport for BlockedEnvGithubDeploymentStatusTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &GithubDeploymentStatusRequest,
    ) -> Result<GithubDeploymentStatusResponse, GithubDeploymentStatusTransportError> {
        Err(GithubDeploymentStatusTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GithubDeploymentStatusProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("native GitHub Deployment providers are forbidden in Layer 1")]
    NativeProviderForbidden,
    #[error("provider definition is tampered")]
    TamperedDefinition,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub api_digest: String,
    pub scope_digest: String,
    pub installation_digest: String,
    pub permission_digest: String,
    pub provenance: TransportProvenance,
    pub max_pages: usize,
    pub max_statuses: usize,
    pub max_history_days: i64,
    pub max_response_bytes: usize,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub provider_digest: String,
}

impl GithubDeploymentStatusProviderDefinition {
    pub fn new(
        scope: &GithubDeploymentStatusScope,
        provider_version: impl Into<String>,
        provenance: TransportProvenance,
    ) -> Result<Self, GithubDeploymentStatusProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(GithubDeploymentStatusProviderDefinitionError::EmptyVersion);
        }
        let mut definition = Self {
            provider_id: GITHUB_DEPLOYMENT_STATUS_PROVIDER_ID.to_owned(),
            provider_version,
            api_revision: GITHUB_DEPLOYMENT_STATUS_API_REVISION.to_owned(),
            api_digest: canonical_digest(&GITHUB_DEPLOYMENT_STATUS_API_REVISION),
            scope_digest: scope.digest().clone(),
            installation_digest: scope.installation_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            provenance,
            max_pages: MAX_PAGES,
            max_statuses: MAX_STATUSES,
            max_history_days: MAX_HISTORY_DAYS,
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
        scope: &GithubDeploymentStatusScope,
    ) -> Result<(), GithubDeploymentStatusProviderDefinitionError> {
        if self.provider_id != GITHUB_DEPLOYMENT_STATUS_PROVIDER_ID
            || self.provider_version != GITHUB_DEPLOYMENT_STATUS_PROVIDER_VERSION
            || self.api_revision != GITHUB_DEPLOYMENT_STATUS_API_REVISION
            || self.api_digest != canonical_digest(&GITHUB_DEPLOYMENT_STATUS_API_REVISION)
            || self.scope_digest != *scope.digest()
            || self.installation_digest != *scope.installation_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.max_pages != MAX_PAGES
            || self.max_statuses != MAX_STATUSES
            || self.max_history_days != MAX_HISTORY_DAYS
            || self.max_response_bytes != MAX_RESPONSE_BYTES
            || !self.read_only
            || self.live_execution
            || self.native
            || self.connected
            || self.provider_digest != self.compute_digest()
        {
            return Err(GithubDeploymentStatusProviderDefinitionError::TamperedDefinition);
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
pub enum GithubDeploymentStatusProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    UnprocessableEntity,
    RateLimited,
    ServerFailure,
    Timeout,
    BlockedEnv,
    ProviderUnknown,
    MalformedResponse,
    ResponseTooLarge,
    PaginationMismatch,
    EtagMismatch,
    ScopeMismatch,
    StaleState,
    Tampered,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubDeploymentStatusProviderError {
    pub kind: GithubDeploymentStatusProviderErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: String,
    pub request_receipts: Vec<GithubDeploymentStatusRequestReceipt>,
    pub response_receipts: Vec<GithubDeploymentStatusResponseReceipt>,
}

impl std::error::Error for GithubDeploymentStatusProviderError {}

impl fmt::Display for GithubDeploymentStatusProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "GitHub Deployment Status provider failed with {:?} ({:?})",
            self.kind, self.status_code
        )
    }
}

impl GithubDeploymentStatusProviderError {
    #[must_use]
    pub fn new(
        kind: GithubDeploymentStatusProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: &str,
        request_receipts: Vec<GithubDeploymentStatusRequestReceipt>,
        response_receipts: Vec<GithubDeploymentStatusResponseReceipt>,
    ) -> Self {
        let bounded = &diagnostic.as_bytes()[..diagnostic.len().min(MAX_DIAGNOSTIC_BYTES)];
        Self {
            kind,
            status_code,
            diagnostic_digest: crate::sha256_digest(bounded),
            request_receipts,
            response_receipts,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubDeploymentStatusObservation {
    pub deployment: GithubDeploymentMetadata,
    pub statuses: Vec<GithubDeploymentStatusMetadata>,
    pub history_truncated: bool,
    pub pages_read: usize,
    pub request_receipts: Vec<GithubDeploymentStatusRequestReceipt>,
    pub response_receipts: Vec<GithubDeploymentStatusResponseReceipt>,
    pub provenance: TransportProvenance,
    pub authority: Layer1Authority,
}

#[derive(Clone)]
pub struct GithubDeploymentStatusProvider<T> {
    scope: GithubDeploymentStatusScope,
    secret_reference: SecretReference,
    definition: GithubDeploymentStatusProviderDefinition,
    registration: GithubDeploymentStatusRegistration,
    transport: T,
}

impl<T: GithubDeploymentStatusTransport> fmt::Debug for GithubDeploymentStatusProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GithubDeploymentStatusProvider")
            .field("scope_digest", self.scope.digest())
            .field("secret_reference", &self.secret_reference)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("transport", &"<redacted transport>")
            .finish()
    }
}

impl<T: GithubDeploymentStatusTransport> GithubDeploymentStatusProvider<T> {
    pub fn new(
        scope: GithubDeploymentStatusScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, GithubDeploymentStatusProviderDefinitionError> {
        scope.validate()?;
        if secret_reference.scope_digest() != scope.digest()
            || !matches!(
                secret_reference.auth_kind(),
                GithubAuthKind::App | GithubAuthKind::OAuth
            )
        {
            return Err(GithubDeploymentStatusProviderDefinitionError::Model(
                ModelError::InvalidScope("secret reference scope"),
            ));
        }
        let definition = GithubDeploymentStatusProviderDefinition::new(
            &scope,
            GITHUB_DEPLOYMENT_STATUS_PROVIDER_VERSION,
            transport.provenance(),
        )?;
        let registration = GithubDeploymentStatusRegistration::bind(
            &scope,
            &secret_reference,
            definition.provider_digest.clone(),
        );
        Ok(Self {
            scope,
            secret_reference,
            definition,
            registration,
            transport,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &GithubDeploymentStatusScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn definition(&self) -> &GithubDeploymentStatusProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn registration(&self) -> &GithubDeploymentStatusRegistration {
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

    pub fn validate_registration(&self) -> Result<(), GithubDeploymentStatusProviderError> {
        if self.secret_reference.is_revoked()
            || self.registration.state != RegistrationState::Active
        {
            return Err(self.error(
                GithubDeploymentStatusProviderErrorKind::RegistrationRevoked,
                None,
                "registration revoked",
                Vec::new(),
                Vec::new(),
            ));
        }
        self.definition.validate(&self.scope).map_err(|_| {
            self.error(
                GithubDeploymentStatusProviderErrorKind::Tampered,
                None,
                "definition drift",
                Vec::new(),
                Vec::new(),
            )
        })?;
        self.registration
            .validate(
                &self.scope,
                &self.secret_reference,
                self.definition.digest(),
            )
            .map_err(|_| {
                self.error(
                    GithubDeploymentStatusProviderErrorKind::Tampered,
                    None,
                    "registration drift",
                    Vec::new(),
                    Vec::new(),
                )
            })
    }

    pub fn read(
        &mut self,
    ) -> Result<GithubDeploymentStatusObservation, GithubDeploymentStatusProviderError> {
        self.validate_registration()?;
        let mut request_receipts = Vec::new();
        let mut response_receipts = Vec::new();
        let deployment_request = GithubDeploymentStatusRequest::new(
            &self.scope,
            GithubDeploymentStatusOperation::Deployment,
            0,
            None,
            None,
        );
        let deployment_response = self.execute_request(
            &deployment_request,
            &mut request_receipts,
            &mut response_receipts,
        )?;
        let deployment = self.parse_deployment(&deployment_response, &response_receipts)?;

        let mut statuses = Vec::new();
        let mut history_truncated = false;
        let mut seen_statuses = BTreeSet::new();
        let mut seen_tokens = BTreeSet::new();
        let mut next_page: Option<OpaquePageToken> = None;
        let mut page = 0_usize;
        let mut pages_read = 0_usize;

        loop {
            let request = GithubDeploymentStatusRequest::new(
                &self.scope,
                GithubDeploymentStatusOperation::Statuses,
                page,
                None,
                next_page.clone(),
            );
            let response =
                self.execute_request(&request, &mut request_receipts, &mut response_receipts)?;
            let (page_statuses, response_next_page) =
                self.parse_status_page(&response, &deployment, &response_receipts)?;
            pages_read += 1;
            for status in page_statuses {
                if !seen_statuses.insert(status.id) {
                    return Err(self.error(
                        GithubDeploymentStatusProviderErrorKind::MalformedResponse,
                        Some(response.status),
                        "duplicate deployment status id",
                        request_receipts,
                        response_receipts,
                    ));
                }
                statuses.push(status);
            }

            let Some(token) = response_next_page else {
                break;
            };
            if !seen_tokens.insert(token.digest().clone()) {
                return Err(self.error(
                    GithubDeploymentStatusProviderErrorKind::PaginationMismatch,
                    Some(response.status),
                    "pagination token replay",
                    request_receipts,
                    response_receipts,
                ));
            }
            if token
                .scope_digest()
                .is_some_and(|value| value != self.scope.digest())
                || token.request_digest().is_some_and(|value| {
                    value
                        != &request_receipts
                            .last()
                            .expect("request receipt")
                            .request_digest
                })
            {
                return Err(self.error(
                    GithubDeploymentStatusProviderErrorKind::PaginationMismatch,
                    Some(response.status),
                    "pagination token binding mismatch",
                    request_receipts,
                    response_receipts,
                ));
            }
            if page + 1 >= MAX_PAGES {
                history_truncated = true;
                break;
            }
            page += 1;
            next_page = Some(token);
        }

        let mut history_anchor = deployment.updated_at.epoch_seconds();
        for status in &statuses {
            history_anchor = history_anchor.max(status.updated_at.epoch_seconds());
        }
        let cutoff = history_anchor.saturating_sub(HISTORY_SECONDS);
        let before_truncation = statuses.len();
        statuses.retain(|status| status.updated_at.epoch_seconds() >= cutoff);
        history_truncated |= statuses.len() != before_truncation;
        statuses.sort_by(|left, right| {
            right
                .updated_at
                .epoch_seconds()
                .cmp(&left.updated_at.epoch_seconds())
                .then_with(|| right.id.cmp(&left.id))
        });

        Ok(GithubDeploymentStatusObservation {
            deployment,
            statuses,
            history_truncated,
            pages_read,
            request_receipts,
            response_receipts,
            provenance: self.provenance(),
            authority: Layer1Authority::default(),
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ModelError> {
        self.registration.revoke()
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        self.registration.restore()
    }

    fn execute_request(
        &mut self,
        request: &GithubDeploymentStatusRequest,
        request_receipts: &mut Vec<GithubDeploymentStatusRequestReceipt>,
        response_receipts: &mut Vec<GithubDeploymentStatusResponseReceipt>,
    ) -> Result<GithubDeploymentStatusResponse, GithubDeploymentStatusProviderError> {
        request_receipts.push(request.receipt());
        let response = self.transport.execute(request).map_err(|error| {
            let kind = match error {
                GithubDeploymentStatusTransportError::BlockedEnv => {
                    GithubDeploymentStatusProviderErrorKind::BlockedEnv
                }
                GithubDeploymentStatusTransportError::Timeout => {
                    GithubDeploymentStatusProviderErrorKind::Timeout
                }
                GithubDeploymentStatusTransportError::ProviderUnknown => {
                    GithubDeploymentStatusProviderErrorKind::ProviderUnknown
                }
            };
            self.error(
                kind,
                None,
                "transport failed",
                request_receipts.clone(),
                response_receipts.clone(),
            )
        })?;
        let receipt = response.response_receipt(request);
        response_receipts.push(receipt);
        if response.response_bytes > MAX_RESPONSE_BYTES {
            return Err(self.error(
                GithubDeploymentStatusProviderErrorKind::ResponseTooLarge,
                Some(response.status),
                "response exceeds Layer-1 byte bound",
                request_receipts.clone(),
                response_receipts.clone(),
            ));
        }
        if response.status != 200 {
            return Err(self.error(
                status_kind(response.status),
                Some(response.status),
                "provider returned a non-success status",
                request_receipts.clone(),
                response_receipts.clone(),
            ));
        }
        Ok(response)
    }

    fn parse_deployment(
        &self,
        response: &GithubDeploymentStatusResponse,
        response_receipts: &[GithubDeploymentStatusResponseReceipt],
    ) -> Result<GithubDeploymentMetadata, GithubDeploymentStatusProviderError> {
        let value = response.json_value().map_err(|kind| {
            self.error(
                kind,
                Some(response.status),
                "malformed deployment response",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })?;
        let object = value.as_object().ok_or_else(|| {
            self.error(
                GithubDeploymentStatusProviderErrorKind::MalformedResponse,
                Some(response.status),
                "deployment response is not an object",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })?;
        let id = required_u64(object, "id").ok_or_else(|| {
            self.error(
                GithubDeploymentStatusProviderErrorKind::MalformedResponse,
                Some(response.status),
                "deployment id missing",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })?;
        let ref_name = required_string(object, "ref").and_then(|value| {
            crate::GithubRef::new(value)
                .map_err(|_| GithubDeploymentStatusProviderErrorKind::ScopeMismatch)
        });
        let commit = required_string(object, "sha").and_then(|value| {
            crate::GithubCommitSha::new(value)
                .map_err(|_| GithubDeploymentStatusProviderErrorKind::ScopeMismatch)
        });
        let environment = required_string(object, "environment").and_then(|value| {
            GithubEnvironment::new(value)
                .map_err(|_| GithubDeploymentStatusProviderErrorKind::ScopeMismatch)
        });
        let ref_name = ref_name.map_err(|kind| {
            self.error(
                kind,
                Some(response.status),
                "deployment scope mismatch",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })?;
        let commit = commit.map_err(|kind| {
            self.error(
                kind,
                Some(response.status),
                "deployment scope mismatch",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })?;
        let environment = environment.map_err(|kind| {
            self.error(
                kind,
                Some(response.status),
                "deployment scope mismatch",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })?;
        if id != self.scope.deployment_id().value()
            || ref_name != *self.scope.ref_name()
            || commit != *self.scope.commit()
            || environment != *self.scope.environment()
        {
            return Err(self.error(
                GithubDeploymentStatusProviderErrorKind::ScopeMismatch,
                Some(response.status),
                "deployment identity does not match scope",
                Vec::new(),
                response_receipts.to_vec(),
            ));
        }
        let created_at = parse_timestamp(object, "created_at").map_err(|kind| {
            self.error(
                kind,
                Some(response.status),
                "deployment timestamp missing",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })?;
        let updated_at = match object.get("updated_at") {
            Some(value) if !value.is_null() => parse_timestamp_value(value).map_err(|kind| {
                self.error(
                    kind,
                    Some(response.status),
                    "deployment timestamp malformed",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?,
            _ => created_at.clone(),
        };
        let url_digests = parse_url_digests(
            object,
            &[
                "url",
                "statuses_url",
                "target_url",
                "environment_url",
                "log_url",
            ],
        )
        .map_err(|kind| {
            self.error(
                kind,
                Some(response.status),
                "deployment URL metadata malformed",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })?;
        GithubDeploymentMetadata::new(
            self.scope.deployment_id().clone(),
            ref_name,
            commit,
            environment,
            created_at,
            updated_at,
            url_digests,
        )
        .map_err(|_| {
            self.error(
                GithubDeploymentStatusProviderErrorKind::StaleState,
                Some(response.status),
                "deployment timestamps are stale",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })
    }

    fn parse_status_page(
        &self,
        response: &GithubDeploymentStatusResponse,
        deployment: &GithubDeploymentMetadata,
        response_receipts: &[GithubDeploymentStatusResponseReceipt],
    ) -> Result<
        (Vec<GithubDeploymentStatusMetadata>, Option<OpaquePageToken>),
        GithubDeploymentStatusProviderError,
    > {
        let value = response.json_value().map_err(|kind| {
            self.error(
                kind,
                Some(response.status),
                "malformed status response",
                Vec::new(),
                response_receipts.to_vec(),
            )
        })?;
        let values = value
            .as_array()
            .cloned()
            .or_else(|| value.get("statuses").and_then(Value::as_array).cloned())
            .ok_or_else(|| {
                self.error(
                    GithubDeploymentStatusProviderErrorKind::MalformedResponse,
                    Some(response.status),
                    "status response is not an array",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?;
        if values.len() > MAX_STATUSES {
            return Err(self.error(
                GithubDeploymentStatusProviderErrorKind::ResponseTooLarge,
                Some(response.status),
                "status page exceeds count bound",
                Vec::new(),
                response_receipts.to_vec(),
            ));
        }
        let mut statuses = Vec::with_capacity(values.len());
        for value in values {
            let object = value.as_object().ok_or_else(|| {
                self.error(
                    GithubDeploymentStatusProviderErrorKind::MalformedResponse,
                    Some(response.status),
                    "status entry is not an object",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?;
            let id = required_u64(object, "id").ok_or_else(|| {
                self.error(
                    GithubDeploymentStatusProviderErrorKind::MalformedResponse,
                    Some(response.status),
                    "status id missing",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?;
            let deployment_id = match object.get("deployment_id").and_then(Value::as_u64) {
                Some(value) => crate::GithubDeploymentId::new(value).map_err(|_| {
                    self.error(
                        GithubDeploymentStatusProviderErrorKind::ScopeMismatch,
                        Some(response.status),
                        "status deployment id malformed",
                        Vec::new(),
                        response_receipts.to_vec(),
                    )
                })?,
                None => self.scope.deployment_id().clone(),
            };
            if deployment_id != *self.scope.deployment_id() {
                return Err(self.error(
                    GithubDeploymentStatusProviderErrorKind::ScopeMismatch,
                    Some(response.status),
                    "status deployment id does not match scope",
                    Vec::new(),
                    response_receipts.to_vec(),
                ));
            }
            if let Some(environment) = object.get("environment").and_then(Value::as_str)
                && environment != self.scope.environment().as_str()
            {
                return Err(self.error(
                    GithubDeploymentStatusProviderErrorKind::ScopeMismatch,
                    Some(response.status),
                    "status environment does not match scope",
                    Vec::new(),
                    response_receipts.to_vec(),
                ));
            }
            let state = required_state(object).ok_or_else(|| {
                self.error(
                    GithubDeploymentStatusProviderErrorKind::MalformedResponse,
                    Some(response.status),
                    "status state is not allowlisted",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?;
            let created_at = parse_timestamp(object, "created_at").map_err(|kind| {
                self.error(
                    kind,
                    Some(response.status),
                    "status created_at malformed",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?;
            let updated_at = parse_timestamp(object, "updated_at").map_err(|kind| {
                self.error(
                    kind,
                    Some(response.status),
                    "status updated_at malformed",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?;
            if created_at.epoch_seconds() < deployment.created_at.epoch_seconds() {
                return Err(self.error(
                    GithubDeploymentStatusProviderErrorKind::StaleState,
                    Some(response.status),
                    "status predates deployment",
                    Vec::new(),
                    response_receipts.to_vec(),
                ));
            }
            let url_digests = parse_url_digests(
                object,
                &[
                    "deployment_url",
                    "environment_url",
                    "target_url",
                    "log_url",
                    "url",
                ],
            )
            .map_err(|kind| {
                self.error(
                    kind,
                    Some(response.status),
                    "status URL metadata malformed",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?;
            let status = GithubDeploymentStatusMetadata::new(
                id,
                deployment_id,
                self.scope.environment().clone(),
                state,
                created_at,
                updated_at,
                url_digests,
            )
            .map_err(|_| {
                self.error(
                    GithubDeploymentStatusProviderErrorKind::StaleState,
                    Some(response.status),
                    "status timestamps are stale",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?;
            status.validate_integrity().map_err(|_| {
                self.error(
                    GithubDeploymentStatusProviderErrorKind::Tampered,
                    Some(response.status),
                    "status digest mismatch",
                    Vec::new(),
                    response_receipts.to_vec(),
                )
            })?;
            statuses.push(status);
        }
        Ok((statuses, response.next_page_token().cloned()))
    }

    #[allow(clippy::unused_self)]
    fn error(
        &self,
        kind: GithubDeploymentStatusProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: &str,
        request_receipts: Vec<GithubDeploymentStatusRequestReceipt>,
        response_receipts: Vec<GithubDeploymentStatusResponseReceipt>,
    ) -> GithubDeploymentStatusProviderError {
        GithubDeploymentStatusProviderError::new(
            kind,
            status_code,
            diagnostic,
            request_receipts,
            response_receipts,
        )
    }
}

fn status_kind(status: u16) -> GithubDeploymentStatusProviderErrorKind {
    match status {
        400 => GithubDeploymentStatusProviderErrorKind::BadRequest,
        401 => GithubDeploymentStatusProviderErrorKind::Unauthenticated,
        403 => GithubDeploymentStatusProviderErrorKind::PermissionDenied,
        404 => GithubDeploymentStatusProviderErrorKind::NotFound,
        409 => GithubDeploymentStatusProviderErrorKind::Conflict,
        422 => GithubDeploymentStatusProviderErrorKind::UnprocessableEntity,
        429 => GithubDeploymentStatusProviderErrorKind::RateLimited,
        500..=599 => GithubDeploymentStatusProviderErrorKind::ServerFailure,
        _ => GithubDeploymentStatusProviderErrorKind::ProviderUnknown,
    }
}

fn required_u64(object: &serde_json::Map<String, Value>, field: &str) -> Option<u64> {
    object.get(field).and_then(Value::as_u64)
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, GithubDeploymentStatusProviderErrorKind> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(GithubDeploymentStatusProviderErrorKind::MalformedResponse)
}

fn parse_timestamp(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<GithubTimestamp, GithubDeploymentStatusProviderErrorKind> {
    let value = required_string(object, field)?;
    parse_timestamp_text(value)
}

fn parse_timestamp_value(
    value: &Value,
) -> Result<GithubTimestamp, GithubDeploymentStatusProviderErrorKind> {
    value
        .as_str()
        .ok_or(GithubDeploymentStatusProviderErrorKind::MalformedResponse)
        .and_then(parse_timestamp_text)
}

fn parse_timestamp_text(
    value: &str,
) -> Result<GithubTimestamp, GithubDeploymentStatusProviderErrorKind> {
    GithubTimestamp::new(value)
        .map_err(|_| GithubDeploymentStatusProviderErrorKind::MalformedResponse)
}

fn required_state(object: &serde_json::Map<String, Value>) -> Option<GithubDeploymentStatusState> {
    object
        .get("state")
        .and_then(Value::as_str)
        .and_then(|value| match value {
            "queued" => Some(GithubDeploymentStatusState::Queued),
            "pending" => Some(GithubDeploymentStatusState::Pending),
            "in_progress" => Some(GithubDeploymentStatusState::InProgress),
            "success" => Some(GithubDeploymentStatusState::Success),
            "failure" => Some(GithubDeploymentStatusState::Failure),
            "error" => Some(GithubDeploymentStatusState::Error),
            "inactive" => Some(GithubDeploymentStatusState::Inactive),
            _ => None,
        })
}

fn parse_url_digests(
    object: &serde_json::Map<String, Value>,
    fields: &[&str; 5],
) -> Result<crate::GithubUrlDigests, GithubDeploymentStatusProviderErrorKind> {
    let mut digests = Vec::with_capacity(fields.len());
    for field in fields {
        let digest = match object.get(*field) {
            None | Some(Value::Null) => None,
            Some(value) => {
                let url = value
                    .as_str()
                    .ok_or(GithubDeploymentStatusProviderErrorKind::MalformedResponse)?;
                Some(
                    digest_url(url)
                        .map_err(|_| GithubDeploymentStatusProviderErrorKind::MalformedResponse)?,
                )
            }
        };
        digests.push(digest);
    }
    Ok(match fields {
        [
            "url",
            "statuses_url",
            "target_url",
            "environment_url",
            "log_url",
        ] => crate::GithubUrlDigests {
            deployment_url_digest: digests[0].clone(),
            statuses_url_digest: digests[1].clone(),
            target_url_digest: digests[2].clone(),
            environment_url_digest: digests[3].clone(),
            log_url_digest: digests[4].clone(),
        },
        [
            "deployment_url",
            "environment_url",
            "target_url",
            "log_url",
            "url",
        ] => crate::GithubUrlDigests {
            deployment_url_digest: digests[0].clone(),
            statuses_url_digest: None,
            target_url_digest: digests[2].clone(),
            environment_url_digest: digests[1].clone(),
            log_url_digest: digests[3].clone().or_else(|| digests[4].clone()),
        },
        _ => return Err(GithubDeploymentStatusProviderErrorKind::MalformedResponse),
    })
}
