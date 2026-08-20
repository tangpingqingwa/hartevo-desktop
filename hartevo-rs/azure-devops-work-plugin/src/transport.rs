//! Narrow GET-only Azure DevOps REST 7.1 transport seams.
//!
//! The transport decodes provider JSON directly into normalized payloads and
//! drops the original bytes before returning.  It has no POST/PATCH/DELETE
//! method and cannot download logs or artifact content.

use std::{collections::VecDeque, fmt, time::Duration as StdDuration};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

use crate::model::{
    ArtifactPayload, AzureDevOpsResponseBody, AzureDevOpsResponseReceipt, BuildPayload, Digest,
    ProviderRevision, PullRequestPayload, TimelineRecordPayload, TransportProvenance,
    WorkItemPayload, WorkItemRelationPayload, digest_serializable, sha256_digest,
};
use crate::{
    AZURE_DEVOPS_API_ORIGIN, AZURE_DEVOPS_API_VERSION, AZURE_DEVOPS_MAX_PAGES,
    AZURE_DEVOPS_PAGE_SIZE, AZURE_DEVOPS_WORK_PROVIDER_REVISION, AzureDevOpsWorkError,
};
use crate::{model::AzureDevOpsReadRequest, provider::EntraAccessToken};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureDevOpsTransportError {
    #[error("Azure DevOps credential is unavailable")]
    CredentialUnavailable,
    #[error("BLOCKED_ENV: Azure DevOps native transport is disabled")]
    BlockedEnv,
    #[error("Azure DevOps request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Azure DevOps response body is unexpected for the endpoint")]
    UnexpectedBody,
    #[error("Azure DevOps response could not be decoded: {0}")]
    Decode(String),
    #[error("Azure DevOps HTTPS transport failed: {0}")]
    Transport(String),
}

impl From<AzureDevOpsTransportError> for AzureDevOpsWorkError {
    fn from(error: AzureDevOpsTransportError) -> Self {
        match error {
            AzureDevOpsTransportError::BlockedEnv
            | AzureDevOpsTransportError::CredentialUnavailable => Self::BlockedEnv,
            AzureDevOpsTransportError::InvalidRequest(detail)
            | AzureDevOpsTransportError::Decode(detail)
            | AzureDevOpsTransportError::Transport(detail) => Self::Transport(detail),
            AzureDevOpsTransportError::UnexpectedBody => {
                Self::Decode("unexpected Azure DevOps response body".to_owned())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBounds {
    pub max_response_bytes: usize,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_work_item_relations: usize,
    pub max_builds: usize,
    pub max_timeline_records: usize,
    pub max_artifacts: usize,
}

impl Default for RequestBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: crate::AZURE_DEVOPS_MAX_RESPONSE_BYTES,
            max_pages: AZURE_DEVOPS_MAX_PAGES,
            page_size: AZURE_DEVOPS_PAGE_SIZE,
            max_work_item_relations: crate::model::MAX_RELATIONS,
            max_builds: crate::model::MAX_BUILDS,
            max_timeline_records: crate::model::MAX_TIMELINE_RECORDS,
            max_artifacts: crate::model::MAX_ARTIFACTS,
        }
    }
}

impl RequestBounds {
    pub fn new(
        max_response_bytes: usize,
        max_pages: u16,
        page_size: u16,
        max_work_item_relations: usize,
        max_builds: usize,
        max_timeline_records: usize,
        max_artifacts: usize,
    ) -> Result<Self, AzureDevOpsWorkError> {
        if max_response_bytes == 0
            || max_response_bytes > crate::AZURE_DEVOPS_MAX_RESPONSE_BYTES
            || max_pages == 0
            || max_pages > AZURE_DEVOPS_MAX_PAGES
            || page_size == 0
            || page_size > AZURE_DEVOPS_PAGE_SIZE
            || max_work_item_relations == 0
            || max_work_item_relations > crate::model::MAX_RELATIONS
            || max_builds == 0
            || max_builds > crate::model::MAX_BUILDS
            || max_timeline_records == 0
            || max_timeline_records > crate::model::MAX_TIMELINE_RECORDS
            || max_artifacts == 0
            || max_artifacts > crate::model::MAX_ARTIFACTS
        {
            return Err(AzureDevOpsWorkError::InvalidInput(
                "Azure DevOps request bounds are outside the contract maximums".to_owned(),
            ));
        }
        Ok(Self {
            max_response_bytes,
            max_pages,
            page_size,
            max_work_item_relations,
            max_builds,
            max_timeline_records,
            max_artifacts,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AzureDevOpsEndpoint {
    WorkItem {
        organization: String,
        project: String,
        work_item_id: u64,
    },
    PullRequest {
        organization: String,
        project: String,
        repository_id: String,
        pull_request_id: u64,
    },
    Builds {
        organization: String,
        project: String,
        repository_id: String,
        pull_request_id: u64,
        page: u16,
        top: u16,
        continuation_token: Option<String>,
    },
    Timeline {
        organization: String,
        project: String,
        build_id: u64,
        page: u16,
        top: u16,
        continuation_token: Option<String>,
    },
    Artifacts {
        organization: String,
        project: String,
        build_id: u64,
        page: u16,
        top: u16,
        continuation_token: Option<String>,
    },
}

impl AzureDevOpsEndpoint {
    #[allow(clippy::too_many_lines)]
    pub fn path_and_query(&self) -> Result<String, AzureDevOpsTransportError> {
        let mut url = Url::parse(AZURE_DEVOPS_API_ORIGIN)
            .map_err(|error| AzureDevOpsTransportError::Transport(error.to_string()))?;
        match self {
            Self::WorkItem {
                organization,
                project,
                work_item_id,
            } => {
                let mut segments = path_segments(&mut url)?;
                segments
                    .push(organization)
                    .push(project)
                    .push("_apis")
                    .push("wit")
                    .push("workitems")
                    .push(&work_item_id.to_string());
                drop(segments);
                url.query_pairs_mut()
                    .append_pair("$expand", "relations")
                    .append_pair("api-version", AZURE_DEVOPS_API_VERSION);
            }
            Self::PullRequest {
                organization,
                project,
                repository_id,
                pull_request_id,
            } => {
                let mut segments = path_segments(&mut url)?;
                segments
                    .push(organization)
                    .push(project)
                    .push("_apis")
                    .push("git")
                    .push("repositories")
                    .push(repository_id)
                    .push("pullrequests")
                    .push(&pull_request_id.to_string());
                drop(segments);
                url.query_pairs_mut()
                    .append_pair("api-version", AZURE_DEVOPS_API_VERSION);
            }
            Self::Builds {
                organization,
                project,
                repository_id,
                pull_request_id,
                page,
                top,
                continuation_token,
            } => {
                let mut segments = path_segments(&mut url)?;
                segments
                    .push(organization)
                    .push(project)
                    .push("_apis")
                    .push("build")
                    .push("builds");
                drop(segments);
                let branch = format!("refs/pull/{pull_request_id}/merge");
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("repositoryId", repository_id)
                    .append_pair("repositoryType", "TfsGit")
                    .append_pair("branchName", &branch)
                    .append_pair("queryOrder", "queueTimeDescending")
                    .append_pair("$top", &top.to_string())
                    .append_pair("page", &page.to_string())
                    .append_pair("api-version", AZURE_DEVOPS_API_VERSION);
                if let Some(token) = continuation_token {
                    query.append_pair("continuationToken", token);
                }
            }
            Self::Timeline {
                organization,
                project,
                build_id,
                page,
                top,
                continuation_token,
            } => {
                let mut segments = path_segments(&mut url)?;
                segments
                    .push(organization)
                    .push(project)
                    .push("_apis")
                    .push("build")
                    .push("builds")
                    .push(&build_id.to_string())
                    .push("timeline");
                drop(segments);
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("$top", &top.to_string())
                    .append_pair("page", &page.to_string())
                    .append_pair("api-version", AZURE_DEVOPS_API_VERSION);
                if let Some(token) = continuation_token {
                    query.append_pair("continuationToken", token);
                }
            }
            Self::Artifacts {
                organization,
                project,
                build_id,
                page,
                top,
                continuation_token,
            } => {
                let mut segments = path_segments(&mut url)?;
                segments
                    .push(organization)
                    .push(project)
                    .push("_apis")
                    .push("build")
                    .push("builds")
                    .push(&build_id.to_string())
                    .push("artifacts");
                drop(segments);
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("$top", &top.to_string())
                    .append_pair("page", &page.to_string())
                    .append_pair("api-version", AZURE_DEVOPS_API_VERSION);
                if let Some(token) = continuation_token {
                    query.append_pair("continuationToken", token);
                }
            }
        }
        Ok(url.to_string())
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::WorkItem { .. } => "work_item",
            Self::PullRequest { .. } => "pull_request",
            Self::Builds { .. } => "builds",
            Self::Timeline { .. } => "timeline",
            Self::Artifacts { .. } => "artifacts",
        }
    }
}

fn path_segments(url: &mut Url) -> Result<url::PathSegmentsMut<'_>, AzureDevOpsTransportError> {
    url.path_segments_mut().map_err(|()| {
        AzureDevOpsTransportError::Transport(
            "Azure DevOps API origin cannot accept path segments".to_owned(),
        )
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureDevOpsHttpRequest {
    pub endpoint: AzureDevOpsEndpoint,
    pub api_version: String,
    pub max_response_bytes: usize,
    pub observed_at: DateTime<Utc>,
}

impl AzureDevOpsHttpRequest {
    pub fn new(
        endpoint: AzureDevOpsEndpoint,
        observed_at: DateTime<Utc>,
        max_response_bytes: usize,
    ) -> Result<Self, AzureDevOpsTransportError> {
        if max_response_bytes == 0 || max_response_bytes > crate::AZURE_DEVOPS_MAX_RESPONSE_BYTES {
            return Err(AzureDevOpsTransportError::InvalidRequest(
                "response bound is outside the Layer-1 maximum".to_owned(),
            ));
        }
        Ok(Self {
            endpoint,
            api_version: AZURE_DEVOPS_API_VERSION.to_owned(),
            max_response_bytes,
            observed_at,
        })
    }

    pub fn path_and_query(&self) -> Result<String, AzureDevOpsTransportError> {
        self.endpoint.path_and_query()
    }

    pub fn digest(&self) -> Result<Digest, AzureDevOpsTransportError> {
        let canonical = json!({
            "endpoint": self.path_and_query()?,
            "apiVersion": self.api_version,
            "maxResponseBytes": self.max_response_bytes,
        });
        digest_serializable(&canonical)
            .map_err(|error| AzureDevOpsTransportError::InvalidRequest(error.to_string()))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AzureDevOpsHttpResponse {
    body: AzureDevOpsResponseBody,
    receipt: AzureDevOpsResponseReceipt,
    continuation_token: Option<String>,
}

impl fmt::Debug for AzureDevOpsHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureDevOpsHttpResponse")
            .field("body_kind", &self.body_kind())
            .field("receipt", &self.receipt)
            .field(
                "continuation_token_present",
                &self.continuation_token.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl AzureDevOpsHttpResponse {
    pub fn from_body(
        request: &AzureDevOpsHttpRequest,
        body: AzureDevOpsResponseBody,
    ) -> Result<Self, AzureDevOpsTransportError> {
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| AzureDevOpsTransportError::InvalidRequest(error.to_string()))?;
        Self::new(
            request,
            200,
            request.api_version.clone(),
            body,
            bytes.len(),
            sha256_digest(&bytes),
            ProviderRevision::parse(AZURE_DEVOPS_WORK_PROVIDER_REVISION)
                .map_err(|error| AzureDevOpsTransportError::InvalidRequest(error.to_string()))?,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &AzureDevOpsHttpRequest,
        status: u16,
        api_version: String,
        body: AzureDevOpsResponseBody,
        response_size: usize,
        response_digest: Digest,
        provider_revision: ProviderRevision,
        etag: Option<String>,
        continuation_token: Option<String>,
    ) -> Result<Self, AzureDevOpsTransportError> {
        if response_size > request.max_response_bytes {
            return Err(AzureDevOpsTransportError::InvalidRequest(
                "response exceeds the request bound".to_owned(),
            ));
        }
        let receipt = AzureDevOpsResponseReceipt {
            request_digest: request.digest()?,
            response_digest,
            endpoint: request.path_and_query()?,
            api_version,
            status,
            response_size,
            provider_revision,
            etag,
            continuation_token_present: continuation_token.is_some(),
            raw_payload_retained: false,
            raw_logs_retained: false,
            raw_artifacts_retained: false,
            credential_material_retained: false,
            observed_at: request.observed_at,
        };
        Ok(Self {
            body,
            receipt,
            continuation_token,
        })
    }

    pub fn body(&self) -> &AzureDevOpsResponseBody {
        &self.body
    }

    pub fn receipt(&self) -> &AzureDevOpsResponseReceipt {
        &self.receipt
    }

    pub fn continuation_token(&self) -> Option<&str> {
        self.continuation_token.as_deref()
    }

    pub fn body_kind(&self) -> &'static str {
        match self.body {
            AzureDevOpsResponseBody::WorkItem(_) => "work_item",
            AzureDevOpsResponseBody::PullRequest(_) => "pull_request",
            AzureDevOpsResponseBody::Builds(_) => "builds",
            AzureDevOpsResponseBody::Timeline(_) => "timeline",
            AzureDevOpsResponseBody::Artifacts(_) => "artifacts",
        }
    }
}

/// GET-only authenticated transport.  The token is borrowed for one request
/// and is never copied into a request, response, receipt, or recording.
pub trait AzureDevOpsWorkTransport: fmt::Debug {
    fn execute(
        &mut self,
        token: &EntraAccessToken,
        request: &AzureDevOpsHttpRequest,
    ) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError>;

    fn provenance(&self) -> TransportProvenance;

    fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct RecordingAzureDevOpsTransport {
    responses: VecDeque<Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError>>,
    requests: Vec<AzureDevOpsHttpRequest>,
    provenance: TransportProvenance,
}

impl RecordingAzureDevOpsTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Recording,
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: TransportProvenance::Fixture,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_response(
        &mut self,
        response: Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError>,
    ) {
        self.responses.push_back(response);
    }

    pub fn requests(&self) -> &[AzureDevOpsHttpRequest] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl AzureDevOpsWorkTransport for RecordingAzureDevOpsTransport {
    fn execute(
        &mut self,
        token: &EntraAccessToken,
        request: &AzureDevOpsHttpRequest,
    ) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
        if token.as_str().trim().is_empty() {
            return Err(AzureDevOpsTransportError::CredentialUnavailable);
        }
        if request.api_version != AZURE_DEVOPS_API_VERSION {
            return Err(AzureDevOpsTransportError::InvalidRequest(
                "recording request used an unsupported API version".to_owned(),
            ));
        }
        request.path_and_query()?;
        self.requests.push(request.clone());
        self.responses.pop_front().ok_or_else(|| {
            AzureDevOpsTransportError::Transport("recording response queue exhausted".to_owned())
        })?
    }

    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
}

pub type FakeAzureDevOpsTransport = RecordingAzureDevOpsTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AzureDevOpsWorkTransport for BlockedEnvTransport {
    fn execute(
        &mut self,
        _token: &EntraAccessToken,
        _request: &AzureDevOpsHttpRequest,
    ) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
        Err(AzureDevOpsTransportError::BlockedEnv)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

/// Production read transport.  It can issue only the bounded GET endpoints
/// represented by `AzureDevOpsEndpoint`; Layer 1 still reports no native
/// Connected status and requires a host-provided token resolver.
pub struct UreqAzureDevOpsTransport {
    origin: String,
    agent: ureq::Agent,
}

impl fmt::Debug for UreqAzureDevOpsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqAzureDevOpsTransport")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl UreqAzureDevOpsTransport {
    pub fn new(origin: impl Into<String>) -> Result<Self, AzureDevOpsWorkError> {
        let origin = origin.into().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&origin).map_err(|error| {
            AzureDevOpsWorkError::InvalidInput(format!("Azure DevOps origin is invalid: {error}"))
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != ""
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(AzureDevOpsWorkError::InvalidInput(
                "Azure DevOps origin must be HTTPS without credentials, path, or query".to_owned(),
            ));
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-azure-devops-work/1")
            .timeout_global(Some(StdDuration::from_secs(30)))
            .build()
            .into();
        Ok(Self { origin, agent })
    }

    pub fn azure_devops() -> Result<Self, AzureDevOpsWorkError> {
        Self::new(AZURE_DEVOPS_API_ORIGIN)
    }

    fn endpoint_url(
        &self,
        endpoint: &AzureDevOpsEndpoint,
    ) -> Result<String, AzureDevOpsTransportError> {
        let mut url = Url::parse(&self.origin)
            .map_err(|error| AzureDevOpsTransportError::Transport(error.to_string()))?;
        let relative = endpoint.path_and_query()?;
        let relative = Url::parse(&relative)
            .map_err(|error| AzureDevOpsTransportError::Transport(error.to_string()))?;
        url.set_path(relative.path());
        url.set_query(relative.query());
        Ok(url.to_string())
    }

    fn get_json(
        &self,
        token: &EntraAccessToken,
        request: &AzureDevOpsHttpRequest,
    ) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
        let url = self.endpoint_url(&request.endpoint)?;
        let mut response = self
            .agent
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.as_str()))
            .header("Accept", "application/json")
            .call()
            .map_err(classify_ureq_error)?;
        let status = response.status().as_u16();
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let continuation_token = response
            .headers()
            .get("x-ms-continuationtoken")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let provider_revision = response
            .headers()
            .get("x-ms-vss-resourceversion")
            .and_then(|value| value.to_str().ok())
            .map_or_else(
                || AZURE_DEVOPS_WORK_PROVIDER_REVISION.to_owned(),
                str::to_owned,
            );
        // Read at most one byte beyond the contract maximum.  The extra byte
        // lets ureq distinguish an exactly-at-limit body from an oversized
        // body without ever buffering an unbounded server response.
        let response_limit = u64::try_from(request.max_response_bytes)
            .map_err(|error| AzureDevOpsTransportError::Transport(error.to_string()))?
            .saturating_add(1);
        let body = response
            .body_mut()
            .with_config()
            .limit(response_limit)
            .read_to_string()
            .map_err(classify_ureq_error)?;
        let response_size = body.len();
        if response_size > request.max_response_bytes {
            return Err(AzureDevOpsTransportError::InvalidRequest(
                "Azure DevOps response exceeds the configured bound".to_owned(),
            ));
        }
        let response_digest = sha256_digest(body.as_bytes());
        let value = serde_json::from_str::<Value>(&body)
            .map_err(|error| AzureDevOpsTransportError::Decode(error.to_string()))?;
        let normalized_body = decode_body(&request.endpoint, &value)?;
        let provider_revision = ProviderRevision::parse(provider_revision)
            .map_err(|error| AzureDevOpsTransportError::Decode(error.to_string()))?;
        AzureDevOpsHttpResponse::new(
            request,
            status,
            request.api_version.clone(),
            normalized_body,
            response_size,
            response_digest,
            provider_revision,
            etag,
            continuation_token,
        )
    }
}

impl AzureDevOpsWorkTransport for UreqAzureDevOpsTransport {
    fn execute(
        &mut self,
        token: &EntraAccessToken,
        request: &AzureDevOpsHttpRequest,
    ) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
        if token.as_str().trim().is_empty() || token.as_str().chars().any(char::is_control) {
            return Err(AzureDevOpsTransportError::CredentialUnavailable);
        }
        if request.api_version != AZURE_DEVOPS_API_VERSION {
            return Err(AzureDevOpsTransportError::InvalidRequest(
                "Azure DevOps REST API version is not 7.1".to_owned(),
            ));
        }
        self.get_json(token, request)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::ProductionRead
    }
}

fn classify_ureq_error(error: ureq::Error) -> AzureDevOpsTransportError {
    match error {
        ureq::Error::StatusCode(status) => AzureDevOpsTransportError::Transport(format!(
            "Azure DevOps returned HTTP status {status}"
        )),
        other => AzureDevOpsTransportError::Transport(other.to_string()),
    }
}

fn decode_body(
    endpoint: &AzureDevOpsEndpoint,
    value: &Value,
) -> Result<AzureDevOpsResponseBody, AzureDevOpsTransportError> {
    match endpoint {
        AzureDevOpsEndpoint::WorkItem { .. } => {
            parse_work_item(value).map(AzureDevOpsResponseBody::WorkItem)
        }
        AzureDevOpsEndpoint::PullRequest { .. } => {
            parse_pull_request(value).map(AzureDevOpsResponseBody::PullRequest)
        }
        AzureDevOpsEndpoint::Builds { .. } => {
            parse_builds(value).map(AzureDevOpsResponseBody::Builds)
        }
        AzureDevOpsEndpoint::Timeline { .. } => {
            parse_timeline(value).map(AzureDevOpsResponseBody::Timeline)
        }
        AzureDevOpsEndpoint::Artifacts { .. } => {
            parse_artifacts(value).map(AzureDevOpsResponseBody::Artifacts)
        }
    }
}

fn parse_work_item(value: &Value) -> Result<WorkItemPayload, AzureDevOpsTransportError> {
    let id = required_u64(value, "id")?;
    let rev = required_u64(value, "rev")?;
    let fields = value.get("fields").and_then(Value::as_object);
    let title = bounded_optional_string(
        fields.and_then(|fields| fields.get("System.Title")),
        "work item title",
    )?;
    let state = bounded_optional_string(
        fields.and_then(|fields| fields.get("System.State")),
        "work item state",
    )?;
    let work_item_type = bounded_optional_string(
        fields.and_then(|fields| fields.get("System.WorkItemType")),
        "work item type",
    )?;
    let relations = value
        .get("relations")
        .and_then(Value::as_array)
        .map(|relations| {
            relations
                .iter()
                .map(|relation| {
                    let relation_type = relation
                        .get("rel")
                        .and_then(Value::as_str)
                        .ok_or(AzureDevOpsTransportError::UnexpectedBody)?
                        .to_owned();
                    let url = relation
                        .get("url")
                        .and_then(Value::as_str)
                        .ok_or(AzureDevOpsTransportError::UnexpectedBody)?
                        .to_owned();
                    Ok(WorkItemRelationPayload { relation_type, url })
                })
                .collect::<Result<Vec<_>, AzureDevOpsTransportError>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(WorkItemPayload {
        id,
        rev,
        title,
        state,
        work_item_type,
        relations,
    })
}

fn parse_pull_request(value: &Value) -> Result<PullRequestPayload, AzureDevOpsTransportError> {
    let repository = value
        .get("repository")
        .and_then(Value::as_object)
        .ok_or(AzureDevOpsTransportError::UnexpectedBody)?;
    let repository_id = required_string(repository.get("id"), "repository id")?;
    let pull_request_id = required_u64(value, "pullRequestId")?;
    let status = required_string(value.get("status"), "pull request status")?;
    let source_ref_name = required_string(value.get("sourceRefName"), "source ref")?;
    let target_ref_name = required_string(value.get("targetRefName"), "target ref")?;
    Ok(PullRequestPayload {
        pull_request_id,
        repository_id,
        status,
        title: bounded_optional_string(value.get("title"), "pull request title")?,
        source_ref_name,
        target_ref_name,
        source_commit: optional_nested_string(value.get("lastMergeSourceCommit"), "commitId")?,
        target_commit: optional_nested_string(value.get("lastMergeTargetCommit"), "commitId")?,
        last_merge_source_commit: optional_nested_string(
            value.get("lastMergeSourceCommit"),
            "commitId",
        )?,
        last_merge_target_commit: optional_nested_string(
            value.get("lastMergeTargetCommit"),
            "commitId",
        )?,
    })
}

fn parse_builds(value: &Value) -> Result<Vec<BuildPayload>, AzureDevOpsTransportError> {
    let values = value
        .get("value")
        .and_then(Value::as_array)
        .ok_or(AzureDevOpsTransportError::UnexpectedBody)?;
    values.iter().map(parse_build).collect()
}

fn parse_build(value: &Value) -> Result<BuildPayload, AzureDevOpsTransportError> {
    let repository_id = value
        .get("repository")
        .and_then(Value::as_object)
        .and_then(|repository| repository.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(BuildPayload {
        id: required_u64(value, "id")?,
        build_number: bounded_optional_string(value.get("buildNumber"), "build number")?,
        status: bounded_optional_string(value.get("status"), "build status")?,
        result: bounded_optional_string(value.get("result"), "build result")?,
        source_version: required_string(value.get("sourceVersion"), "build source version")?,
        source_branch: required_string(value.get("sourceBranch"), "build source branch")?,
        repository_id,
        queue_time: optional_datetime(value.get("queueTime"))?,
        start_time: optional_datetime(value.get("startTime"))?,
        finish_time: optional_datetime(value.get("finishTime"))?,
        definition_name: value
            .get("definition")
            .and_then(Value::as_object)
            .and_then(|definition| definition.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn parse_timeline(value: &Value) -> Result<Vec<TimelineRecordPayload>, AzureDevOpsTransportError> {
    let records = value
        .get("records")
        .and_then(Value::as_array)
        .ok_or(AzureDevOpsTransportError::UnexpectedBody)?;
    records
        .iter()
        .map(|record| {
            Ok(TimelineRecordPayload {
                id: required_string(record.get("id"), "timeline record id")?,
                record_type: bounded_optional_string(record.get("type"), "timeline type")?,
                name: bounded_optional_string(record.get("name"), "timeline name")?,
                state: bounded_optional_string(record.get("state"), "timeline state")?,
                result: bounded_optional_string(record.get("result"), "timeline result")?,
                order: record.get("order").and_then(Value::as_i64),
                start_time: optional_datetime(record.get("startTime"))?,
                finish_time: optional_datetime(record.get("finishTime"))?,
                error_count: record
                    .get("errorCount")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
                warning_count: record
                    .get("warningCount")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
                // The log object, URL, and line content are deliberately not
                // represented in the returned payload.
                log_reference_present: false,
            })
        })
        .collect()
}

fn parse_artifacts(value: &Value) -> Result<Vec<ArtifactPayload>, AzureDevOpsTransportError> {
    let values = value
        .get("value")
        .and_then(Value::as_array)
        .ok_or(AzureDevOpsTransportError::UnexpectedBody)?;
    values
        .iter()
        .map(|artifact| {
            Ok(ArtifactPayload {
                id: required_string(artifact.get("id"), "artifact id")?,
                name: required_string(artifact.get("name"), "artifact name")?,
                artifact_type: bounded_optional_string(
                    artifact
                        .get("resource")
                        .and_then(Value::as_object)
                        .and_then(|resource| resource.get("type")),
                    "artifact type",
                )?,
            })
        })
        .collect()
}

fn required_u64(value: &Value, field: &'static str) -> Result<u64, AzureDevOpsTransportError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or(AzureDevOpsTransportError::UnexpectedBody)
}

fn required_string(
    value: Option<&Value>,
    _field: &'static str,
) -> Result<String, AzureDevOpsTransportError> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= crate::model::MAX_IDENTIFIER_LENGTH)
        .map(str::to_owned)
        .ok_or(AzureDevOpsTransportError::UnexpectedBody)
}

fn bounded_optional_string(
    value: Option<&Value>,
    _field: &'static str,
) -> Result<Option<String>, AzureDevOpsTransportError> {
    value
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= crate::model::MAX_TITLE_LENGTH)
                .map(str::to_owned)
                .ok_or(AzureDevOpsTransportError::UnexpectedBody)
        })
        .transpose()
}

fn optional_nested_string(
    value: Option<&Value>,
    field: &'static str,
) -> Result<Option<String>, AzureDevOpsTransportError> {
    value
        .map(|value| {
            required_string(
                value.as_object().and_then(|object| object.get(field)),
                field,
            )
        })
        .transpose()
}

fn optional_datetime(
    value: Option<&Value>,
) -> Result<Option<DateTime<Utc>>, AzureDevOpsTransportError> {
    value
        .map(|value| {
            serde_json::from_value::<DateTime<Utc>>(value.clone())
                .map_err(|_| AzureDevOpsTransportError::UnexpectedBody)
        })
        .transpose()
}

#[allow(dead_code)]
fn _read_request_type_is_used(value: &AzureDevOpsReadRequest) -> &AzureDevOpsReadRequest {
    value
}
