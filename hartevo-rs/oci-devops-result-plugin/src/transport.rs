//! Allowlisted OCI DevOps REST transport and redacting response decoders.

use std::{collections::VecDeque, fmt, time::Duration as StdDuration};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::model::{
    Digest, OciBuildRunPayload, OciDeploymentPayload, OciResponseBody, OciStagePayload,
    OciWorkRequestPayload, ProviderRevision, digest_serializable, sha256_digest,
};
use crate::provider::OciAccessCredential;
use crate::{
    OCI_DEVOPS_API_ORIGIN_PATTERN, OCI_DEVOPS_API_VERSION, OCI_DEVOPS_MAX_ARTIFACT_METADATA,
    OCI_DEVOPS_MAX_RESPONSE_BYTES, OCI_DEVOPS_MAX_STAGES, OCI_DEVOPS_PROVIDER_REVISION,
    OciDevopsError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OciDevopsEndpoint {
    ListDeployments {
        compartment_id: String,
        project_id: String,
        pipeline_id: String,
        limit: u16,
        page_token: Option<String>,
    },
    GetDeployment {
        deployment_id: String,
    },
    ListBuildRuns {
        compartment_id: String,
        project_id: String,
        pipeline_id: String,
        limit: u16,
        page_token: Option<String>,
    },
    GetBuildRun {
        build_run_id: String,
    },
    ListWorkRequests {
        compartment_id: String,
        project_id: String,
        limit: u16,
        page_token: Option<String>,
    },
    GetWorkRequest {
        work_request_id: String,
    },
}

impl OciDevopsEndpoint {
    fn validate(&self) -> Result<(), OciTransportError> {
        let validate_component = |value: &str, field: &str| {
            if value.is_empty()
                || value.len() > crate::model::MAX_IDENTIFIER_LENGTH
                || value.chars().any(char::is_control)
                || value
                    .chars()
                    .any(|character| matches!(character, '/' | '?' | '#'))
            {
                return Err(OciTransportError::InvalidRequest(format!(
                    "{field} is not a safe OCI path component"
                )));
            }
            Ok(())
        };
        let validate_page_token = |value: &str| {
            if value.is_empty()
                || value.len() > crate::OCI_DEVOPS_MAX_NEXT_PAGE_TOKEN_BYTES
                || value.chars().any(char::is_control)
            {
                return Err(OciTransportError::InvalidRequest(
                    "next page token is outside the configured bound".to_owned(),
                ));
            }
            Ok(())
        };
        match self {
            Self::ListDeployments {
                compartment_id,
                project_id,
                pipeline_id,
                limit,
                page_token,
            }
            | Self::ListBuildRuns {
                compartment_id,
                project_id,
                pipeline_id,
                limit,
                page_token,
            } => {
                validate_component(compartment_id, "compartment id")?;
                validate_component(project_id, "project id")?;
                validate_component(pipeline_id, "pipeline id")?;
                if !(1..=crate::OCI_DEVOPS_MAX_RESULTS).contains(limit) {
                    return Err(OciTransportError::InvalidRequest(
                        "list limit is outside the Layer-1 maximum".to_owned(),
                    ));
                }
                if let Some(page_token) = page_token {
                    validate_page_token(page_token)?;
                }
            }
            Self::ListWorkRequests {
                compartment_id,
                project_id,
                limit,
                page_token,
            } => {
                validate_component(compartment_id, "compartment id")?;
                validate_component(project_id, "project id")?;
                if !(1..=crate::OCI_DEVOPS_MAX_RESULTS).contains(limit) {
                    return Err(OciTransportError::InvalidRequest(
                        "list limit is outside the Layer-1 maximum".to_owned(),
                    ));
                }
                if let Some(page_token) = page_token {
                    validate_page_token(page_token)?;
                }
            }
            Self::GetDeployment { deployment_id } => {
                validate_component(deployment_id, "deployment id")?;
            }
            Self::GetBuildRun { build_run_id } => {
                validate_component(build_run_id, "build run id")?;
            }
            Self::GetWorkRequest { work_request_id } => {
                validate_component(work_request_id, "work request id")?;
            }
        }
        Ok(())
    }

    pub fn path_and_query(&self) -> Result<String, OciTransportError> {
        self.validate()?;
        let mut url = Url::parse("https://oci.invalid")
            .map_err(|error| OciTransportError::Transport(error.to_string()))?;
        match self {
            Self::ListDeployments {
                compartment_id,
                project_id,
                pipeline_id,
                limit,
                page_token,
            } => {
                url.set_path("/20210630/deployments");
                add_list_query(
                    &mut url,
                    compartment_id,
                    project_id,
                    Some(pipeline_id),
                    *limit,
                    page_token.as_deref(),
                );
            }
            Self::GetDeployment { deployment_id } => {
                url.set_path(&format!("/20210630/deployments/{deployment_id}"));
            }
            Self::ListBuildRuns {
                compartment_id,
                project_id,
                pipeline_id,
                limit,
                page_token,
            } => {
                url.set_path("/20210630/buildRuns");
                add_list_query(
                    &mut url,
                    compartment_id,
                    project_id,
                    Some(pipeline_id),
                    *limit,
                    page_token.as_deref(),
                );
            }
            Self::GetBuildRun { build_run_id } => {
                url.set_path(&format!("/20210630/buildRuns/{build_run_id}"));
            }
            Self::ListWorkRequests {
                compartment_id,
                project_id,
                limit,
                page_token,
            } => {
                url.set_path("/20210630/workRequests");
                add_list_query(
                    &mut url,
                    compartment_id,
                    project_id,
                    None,
                    *limit,
                    page_token.as_deref(),
                );
            }
            Self::GetWorkRequest { work_request_id } => {
                url.set_path(&format!("/20210630/workRequests/{work_request_id}"));
            }
        }
        let mut result = url.path().to_owned();
        if let Some(query) = url.query() {
            result.push('?');
            result.push_str(query);
        }
        Ok(result)
    }

    pub fn safe_path_and_query(&self) -> Result<String, OciTransportError> {
        let mut value = self.clone();
        match &mut value {
            Self::ListDeployments { page_token, .. }
            | Self::ListBuildRuns { page_token, .. }
            | Self::ListWorkRequests { page_token, .. } => {
                *page_token = page_token
                    .as_ref()
                    .map(|token| sha256_digest(token.as_bytes()).to_string());
            }
            _ => {}
        }
        value.path_and_query()
    }

    pub fn operation(&self) -> &'static str {
        match self {
            Self::ListDeployments { .. } => "list_deployments",
            Self::GetDeployment { .. } => "get_deployment",
            Self::ListBuildRuns { .. } => "list_build_runs",
            Self::GetBuildRun { .. } => "get_build_run",
            Self::ListWorkRequests { .. } => "list_work_requests",
            Self::GetWorkRequest { .. } => "get_work_request",
        }
    }

    pub fn collection(&self) -> &'static str {
        match self {
            Self::ListDeployments { .. } | Self::GetDeployment { .. } => "deployments",
            Self::ListBuildRuns { .. } | Self::GetBuildRun { .. } => "buildRuns",
            Self::ListWorkRequests { .. } | Self::GetWorkRequest { .. } => "workRequests",
        }
    }
}

fn add_list_query(
    url: &mut Url,
    compartment_id: &str,
    project_id: &str,
    pipeline_id: Option<&str>,
    limit: u16,
    page_token: Option<&str>,
) {
    let mut query = url.query_pairs_mut();
    query
        .append_pair("compartmentId", compartment_id)
        .append_pair("projectId", project_id)
        .append_pair("limit", &limit.to_string());
    if let Some(pipeline_id) = pipeline_id {
        query.append_pair("pipelineId", pipeline_id);
    }
    if let Some(page_token) = page_token {
        query.append_pair("page", page_token);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OciDevopsHttpRequest {
    pub endpoint: OciDevopsEndpoint,
    pub api_version: String,
    pub max_response_bytes: usize,
    pub observed_at: DateTime<Utc>,
}

impl OciDevopsHttpRequest {
    pub fn new(
        endpoint: OciDevopsEndpoint,
        observed_at: DateTime<Utc>,
        max_response_bytes: usize,
    ) -> Result<Self, OciTransportError> {
        if max_response_bytes == 0 || max_response_bytes > OCI_DEVOPS_MAX_RESPONSE_BYTES {
            return Err(OciTransportError::InvalidRequest(
                "response bound is outside the Layer-1 maximum".to_owned(),
            ));
        }
        if !matches!(
            endpoint,
            OciDevopsEndpoint::ListDeployments { limit, .. }
                | OciDevopsEndpoint::ListBuildRuns { limit, .. }
                | OciDevopsEndpoint::ListWorkRequests { limit, .. }
                if (1..=crate::OCI_DEVOPS_MAX_RESULTS).contains(&limit)
        ) && matches!(
            endpoint,
            OciDevopsEndpoint::ListDeployments { .. }
                | OciDevopsEndpoint::ListBuildRuns { .. }
                | OciDevopsEndpoint::ListWorkRequests { .. }
        ) {
            return Err(OciTransportError::InvalidRequest(
                "list limit is outside the Layer-1 maximum".to_owned(),
            ));
        }
        Ok(Self {
            endpoint,
            api_version: OCI_DEVOPS_API_VERSION.to_owned(),
            max_response_bytes,
            observed_at,
        })
    }

    pub fn path_and_query(&self) -> Result<String, OciTransportError> {
        self.endpoint.path_and_query()
    }

    pub fn safe_path_and_query(&self) -> Result<String, OciTransportError> {
        self.endpoint.safe_path_and_query()
    }

    pub fn digest(&self) -> Result<Digest, OciTransportError> {
        let canonical = json!({
            "endpoint": self.safe_path_and_query()?,
            "apiVersion": self.api_version,
            "maxResponseBytes": self.max_response_bytes,
        });
        digest_serializable(&canonical)
            .map_err(|error| OciTransportError::InvalidRequest(error.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OciTransportError {
    BlockedEnv,
    CredentialUnavailable,
    InvalidRequest(String),
    Decode(String),
    Status(u16),
    Timeout,
    Transport(String),
    UnexpectedBody,
}

impl fmt::Display for OciTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockedEnv => formatter.write_str("BLOCKED_ENV"),
            Self::CredentialUnavailable => formatter.write_str("credential unavailable"),
            Self::InvalidRequest(value) => write!(formatter, "invalid request: {value}"),
            Self::Decode(value) => write!(formatter, "decode failed: {value}"),
            Self::Status(status) => write!(formatter, "OCI returned HTTP status {status}"),
            Self::Timeout => formatter.write_str("OCI request timed out"),
            Self::Transport(value) => write!(formatter, "transport failed: {value}"),
            Self::UnexpectedBody => formatter.write_str("unexpected OCI response body"),
        }
    }
}

impl std::error::Error for OciTransportError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciRequestReceipt {
    pub operation: String,
    pub endpoint: String,
    pub request_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub limit: Option<u16>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct OciDevopsHttpResponse {
    body: OciResponseBody,
    receipt: crate::model::OciResponseReceipt,
    next_page_token: Option<String>,
}

impl fmt::Debug for OciDevopsHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OciDevopsHttpResponse")
            .field("body_kind", &self.body_kind())
            .field("receipt", &self.receipt)
            .field("next_page_token_present", &self.next_page_token.is_some())
            .finish_non_exhaustive()
    }
}

impl OciDevopsHttpResponse {
    pub fn from_body(
        request: &OciDevopsHttpRequest,
        body: OciResponseBody,
    ) -> Result<Self, OciTransportError> {
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| OciTransportError::InvalidRequest(error.to_string()))?;
        Self::new(request, 200, body, sha256_digest(&bytes), None)
    }

    pub fn from_body_with_next_page(
        request: &OciDevopsHttpRequest,
        body: OciResponseBody,
        next_page_token: Option<String>,
    ) -> Result<Self, OciTransportError> {
        let bytes = serde_json::to_vec(&body)
            .map_err(|error| OciTransportError::InvalidRequest(error.to_string()))?;
        Self::new(request, 200, body, sha256_digest(&bytes), next_page_token)
    }

    pub fn new(
        request: &OciDevopsHttpRequest,
        status: u16,
        body: OciResponseBody,
        response_digest: Digest,
        next_page_token: Option<String>,
    ) -> Result<Self, OciTransportError> {
        if next_page_token
            .as_deref()
            .is_some_and(|token| token.len() > crate::OCI_DEVOPS_MAX_NEXT_PAGE_TOKEN_BYTES)
        {
            return Err(OciTransportError::InvalidRequest(
                "next page token exceeds the configured bound".to_owned(),
            ));
        }
        if next_page_token
            .as_deref()
            .is_some_and(|token| token.chars().any(char::is_control))
        {
            return Err(OciTransportError::InvalidRequest(
                "next page token contains a control character".to_owned(),
            ));
        }
        let page_token_digest = match &request.endpoint {
            OciDevopsEndpoint::ListDeployments { page_token, .. }
            | OciDevopsEndpoint::ListBuildRuns { page_token, .. }
            | OciDevopsEndpoint::ListWorkRequests { page_token, .. } => page_token
                .as_ref()
                .map(|token| sha256_digest(token.as_bytes())),
            _ => None,
        };
        let receipt = crate::model::OciResponseReceipt {
            request_digest: request.digest()?,
            response_digest,
            endpoint: request.safe_path_and_query()?,
            api_version: request.api_version.clone(),
            status,
            response_size: serde_json::to_vec(&body)
                .map_err(|error| OciTransportError::InvalidRequest(error.to_string()))?
                .len(),
            provider_revision: ProviderRevision::parse(OCI_DEVOPS_PROVIDER_REVISION)
                .map_err(|error| OciTransportError::InvalidRequest(error.to_string()))?,
            page_token_digest,
            next_page_token_present: next_page_token.is_some(),
            raw_provider_payload_retained: false,
            raw_logs_retained: false,
            raw_artifacts_retained: false,
            credential_material_retained: false,
            observed_at: request.observed_at,
        };
        Ok(Self {
            body,
            receipt,
            next_page_token,
        })
    }

    pub fn body(&self) -> &OciResponseBody {
        &self.body
    }

    pub fn receipt(&self) -> &crate::model::OciResponseReceipt {
        &self.receipt
    }

    pub fn next_page_token(&self) -> Option<&str> {
        self.next_page_token.as_deref()
    }

    pub fn body_kind(&self) -> &'static str {
        match self.body {
            OciResponseBody::Deployments(_) => "deployments",
            OciResponseBody::Deployment(_) => "deployment",
            OciResponseBody::BuildRuns(_) => "build_runs",
            OciResponseBody::BuildRun(_) => "build_run",
            OciResponseBody::WorkRequests(_) => "work_requests",
            OciResponseBody::WorkRequest(_) => "work_request",
        }
    }
}

pub trait OciDevopsTransport: fmt::Debug {
    fn execute(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsHttpRequest,
    ) -> Result<OciDevopsHttpResponse, OciTransportError>;

    fn provenance(&self) -> crate::model::TransportProvenance;

    fn is_native(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct RecordingOciDevopsTransport {
    responses: VecDeque<Result<OciDevopsHttpResponse, OciTransportError>>,
    requests: Vec<OciRequestReceipt>,
    provenance: crate::model::TransportProvenance,
}

impl RecordingOciDevopsTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<OciDevopsHttpResponse, OciTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: crate::model::TransportProvenance::Recording,
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<OciDevopsHttpResponse, OciTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: crate::model::TransportProvenance::Fixture,
        }
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = Result<OciDevopsHttpResponse, OciTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            provenance: crate::model::TransportProvenance::Loopback,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: crate::model::TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn requests(&self) -> &[OciRequestReceipt] {
        &self.requests
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }

    pub fn push_response(&mut self, response: Result<OciDevopsHttpResponse, OciTransportError>) {
        self.responses.push_back(response);
    }
}

impl OciDevopsTransport for RecordingOciDevopsTransport {
    fn execute(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsHttpRequest,
    ) -> Result<OciDevopsHttpResponse, OciTransportError> {
        if credential.is_empty() {
            return Err(OciTransportError::CredentialUnavailable);
        }
        let limit = match &request.endpoint {
            OciDevopsEndpoint::ListDeployments { limit, .. }
            | OciDevopsEndpoint::ListBuildRuns { limit, .. }
            | OciDevopsEndpoint::ListWorkRequests { limit, .. } => Some(*limit),
            _ => None,
        };
        let page_token_digest = match &request.endpoint {
            OciDevopsEndpoint::ListDeployments { page_token, .. }
            | OciDevopsEndpoint::ListBuildRuns { page_token, .. }
            | OciDevopsEndpoint::ListWorkRequests { page_token, .. } => page_token
                .as_ref()
                .map(|token| sha256_digest(token.as_bytes())),
            _ => None,
        };
        self.requests.push(OciRequestReceipt {
            operation: request.endpoint.operation().to_owned(),
            endpoint: request.safe_path_and_query()?,
            request_digest: request.digest()?,
            page_token_digest,
            limit,
        });
        self.responses.pop_front().ok_or_else(|| {
            OciTransportError::Transport("recording response queue exhausted".to_owned())
        })?
    }

    fn provenance(&self) -> crate::model::TransportProvenance {
        self.provenance
    }
}

pub type FakeOciDevopsTransport = RecordingOciDevopsTransport;
pub type LoopbackOciDevopsTransport = RecordingOciDevopsTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvOciDevopsTransport;

impl OciDevopsTransport for BlockedEnvOciDevopsTransport {
    fn execute(
        &mut self,
        _credential: &OciAccessCredential,
        _request: &OciDevopsHttpRequest,
    ) -> Result<OciDevopsHttpResponse, OciTransportError> {
        Err(OciTransportError::BlockedEnv)
    }

    fn provenance(&self) -> crate::model::TransportProvenance {
        crate::model::TransportProvenance::BlockedEnv
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBounds {
    pub max_response_bytes: usize,
    pub max_results: u16,
    pub max_pages: u16,
}

impl Default for RequestBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: OCI_DEVOPS_MAX_RESPONSE_BYTES,
            max_results: crate::OCI_DEVOPS_MAX_RESULTS,
            max_pages: crate::OCI_DEVOPS_MAX_PAGES,
        }
    }
}

/// Production read seam. It is deliberately not a native Connected
/// implementation; the host must later supply authoritative OCI signing.
pub struct UreqOciDevopsTransport {
    origin: String,
    agent: ureq::Agent,
}

impl fmt::Debug for UreqOciDevopsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqOciDevopsTransport")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl UreqOciDevopsTransport {
    pub fn new(region: impl Into<String>) -> Result<Self, OciDevopsError> {
        let region = region.into();
        if region.trim().is_empty()
            || region.chars().any(char::is_control)
            || region.contains('/')
            || region.contains('.')
        {
            return Err(OciDevopsError::InvalidInput(
                "OCI region is invalid".to_owned(),
            ));
        }
        let origin = OCI_DEVOPS_API_ORIGIN_PATTERN.replace("{region}", &region);
        let parsed = Url::parse(&origin).map_err(|error| {
            OciDevopsError::InvalidInput(format!("OCI DevOps origin is invalid: {error}"))
        })?;
        if parsed.scheme() != "https"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.path() != ""
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(OciDevopsError::InvalidInput(
                "OCI DevOps origin must be HTTPS without credentials, path, or query".to_owned(),
            ));
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-oci-devops-result/1")
            .timeout_global(Some(StdDuration::from_secs(30)))
            .build()
            .into();
        Ok(Self { origin, agent })
    }

    fn endpoint_url(&self, endpoint: &OciDevopsEndpoint) -> Result<String, OciTransportError> {
        let mut url = Url::parse(&self.origin)
            .map_err(|error| OciTransportError::Transport(error.to_string()))?;
        let relative = Url::parse(&format!(
            "https://oci.invalid{}",
            endpoint.path_and_query()?
        ))
        .map_err(|error| OciTransportError::Transport(error.to_string()))?;
        url.set_path(relative.path());
        url.set_query(relative.query());
        Ok(url.to_string())
    }

    fn get_json(
        &self,
        credential: &OciAccessCredential,
        request: &OciDevopsHttpRequest,
    ) -> Result<OciDevopsHttpResponse, OciTransportError> {
        let url = self.endpoint_url(&request.endpoint)?;
        let mut response = self
            .agent
            .get(&url)
            .header("Authorization", credential.authorization_header())
            .header("Accept", "application/json")
            .call()
            .map_err(classify_ureq_error)?;
        let status = response.status().as_u16();
        let next_page_token = response
            .headers()
            .get("opc-next-page")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let response_limit = u64::try_from(request.max_response_bytes)
            .map_err(|error| OciTransportError::Transport(error.to_string()))?
            .saturating_add(1);
        let body = response
            .body_mut()
            .with_config()
            .limit(response_limit)
            .read_to_string()
            .map_err(classify_ureq_error)?;
        if body.len() > request.max_response_bytes {
            return Err(OciTransportError::InvalidRequest(
                "OCI response exceeds the configured bound".to_owned(),
            ));
        }
        let response_digest = sha256_digest(body.as_bytes());
        if status != 200 {
            return Err(OciTransportError::Status(status));
        }
        let value = serde_json::from_str::<Value>(&body)
            .map_err(|error| OciTransportError::Decode(error.to_string()))?;
        let normalized = decode_body(&request.endpoint, &value)?;
        OciDevopsHttpResponse::new(
            request,
            status,
            normalized,
            response_digest,
            next_page_token,
        )
    }
}

impl OciDevopsTransport for UreqOciDevopsTransport {
    fn execute(
        &mut self,
        credential: &OciAccessCredential,
        request: &OciDevopsHttpRequest,
    ) -> Result<OciDevopsHttpResponse, OciTransportError> {
        if credential.is_empty() {
            return Err(OciTransportError::CredentialUnavailable);
        }
        if request.api_version != OCI_DEVOPS_API_VERSION {
            return Err(OciTransportError::InvalidRequest(
                "OCI DevOps API version is not 20210630".to_owned(),
            ));
        }
        self.get_json(credential, request)
    }

    fn provenance(&self) -> crate::model::TransportProvenance {
        crate::model::TransportProvenance::ProductionRead
    }
}

fn classify_ureq_error(error: ureq::Error) -> OciTransportError {
    match error {
        ureq::Error::StatusCode(status) => OciTransportError::Status(status),
        other => {
            let text = other.to_string();
            if text.to_ascii_lowercase().contains("timeout") {
                OciTransportError::Timeout
            } else {
                OciTransportError::Transport(text)
            }
        }
    }
}

fn decode_body(
    endpoint: &OciDevopsEndpoint,
    value: &Value,
) -> Result<OciResponseBody, OciTransportError> {
    match endpoint {
        OciDevopsEndpoint::ListDeployments { .. } => {
            parse_items(value, parse_deployment).map(OciResponseBody::Deployments)
        }
        OciDevopsEndpoint::GetDeployment { .. } => {
            parse_deployment(value).map(OciResponseBody::Deployment)
        }
        OciDevopsEndpoint::ListBuildRuns { .. } => {
            parse_items(value, parse_build_run).map(OciResponseBody::BuildRuns)
        }
        OciDevopsEndpoint::GetBuildRun { .. } => {
            parse_build_run(value).map(OciResponseBody::BuildRun)
        }
        OciDevopsEndpoint::ListWorkRequests { .. } => {
            parse_items(value, parse_work_request).map(OciResponseBody::WorkRequests)
        }
        OciDevopsEndpoint::GetWorkRequest { .. } => {
            parse_work_request(value).map(OciResponseBody::WorkRequest)
        }
    }
}

fn parse_items<T>(
    value: &Value,
    parser: fn(&Value) -> Result<T, OciTransportError>,
) -> Result<Vec<T>, OciTransportError> {
    let values = value
        .get("items")
        .and_then(Value::as_array)
        .or_else(|| value.as_array())
        .ok_or(OciTransportError::UnexpectedBody)?;
    values.iter().map(parser).collect()
}

fn parse_deployment(value: &Value) -> Result<OciDeploymentPayload, OciTransportError> {
    let stages = parse_stages(value)?;
    let (artifact_count, artifact_metadata_fingerprint) = parse_artifacts(value)?;
    Ok(OciDeploymentPayload {
        id: required_string(value, "id")?,
        compartment_id: required_string(value, "compartmentId")?,
        project_id: first_string(value, &["projectId", "devopsProjectId"])
            .ok_or(OciTransportError::UnexpectedBody)?,
        pipeline_id: first_string(
            value,
            &["pipelineId", "deploymentPipelineId", "deployPipelineId"],
        )
        .ok_or(OciTransportError::UnexpectedBody)?,
        build_run_id: first_string(value, &["buildRunId", "buildRunOCID"]),
        lifecycle_state: first_string(value, &["lifecycleState", "status"])
            .ok_or(OciTransportError::UnexpectedBody)?,
        revision: revision(value),
        time_created: optional_datetime(value, "timeCreated")?,
        time_started: optional_datetime(value, "timeStarted")?,
        time_finished: optional_datetime(value, "timeFinished")?,
        stages,
        artifact_count,
        artifact_metadata_fingerprint,
        log_metadata_fingerprint: metadata_fingerprint(value, &["logs", "logEntries", "logUri"]),
    })
}

fn parse_build_run(value: &Value) -> Result<OciBuildRunPayload, OciTransportError> {
    let stages = parse_stages(value)?;
    let (artifact_count, artifact_metadata_fingerprint) = parse_artifacts(value)?;
    Ok(OciBuildRunPayload {
        id: required_string(value, "id")?,
        compartment_id: required_string(value, "compartmentId")?,
        project_id: first_string(value, &["projectId", "devopsProjectId"])
            .ok_or(OciTransportError::UnexpectedBody)?,
        pipeline_id: first_string(value, &["pipelineId", "buildPipelineId"])
            .ok_or(OciTransportError::UnexpectedBody)?,
        lifecycle_state: first_string(value, &["lifecycleState", "status"])
            .ok_or(OciTransportError::UnexpectedBody)?,
        revision: revision(value),
        time_created: optional_datetime(value, "timeCreated")?,
        time_started: optional_datetime(value, "timeStarted")?,
        time_finished: optional_datetime(value, "timeFinished")?,
        stages,
        artifact_count,
        artifact_metadata_fingerprint,
        log_metadata_fingerprint: metadata_fingerprint(value, &["logs", "logEntries", "logUri"]),
    })
}

fn parse_work_request(value: &Value) -> Result<OciWorkRequestPayload, OciTransportError> {
    let percent_complete = value
        .get("percentComplete")
        .and_then(Value::as_u64)
        .map(|value| u8::try_from(value.min(100)).expect("percent complete is bounded"));
    Ok(OciWorkRequestPayload {
        id: required_string(value, "id")?,
        compartment_id: required_string(value, "compartmentId")?,
        project_id: first_string(value, &["projectId", "devopsProjectId"])
            .ok_or(OciTransportError::UnexpectedBody)?,
        resource_id: first_string(value, &["resourceId", "resourceIdInPath"]),
        operation_type: first_string(value, &["operationType", "operation"]),
        status: first_string(value, &["status", "lifecycleState"])
            .ok_or(OciTransportError::UnexpectedBody)?,
        percent_complete,
        revision: revision(value),
        time_accepted: optional_datetime(value, "timeAccepted")?,
        time_started: optional_datetime(value, "timeStarted")?,
        time_finished: optional_datetime(value, "timeFinished")?,
    })
}

fn parse_stages(value: &Value) -> Result<Vec<OciStagePayload>, OciTransportError> {
    let candidates = [
        "stages",
        "deploymentExecutionPlan",
        "buildPipelineStageRuns",
    ];
    let Some(array) = candidates
        .iter()
        .find_map(|field| value.get(*field).and_then(Value::as_array))
    else {
        return Ok(Vec::new());
    };
    if array.len() > OCI_DEVOPS_MAX_STAGES {
        return Err(OciTransportError::InvalidRequest(
            "OCI stage bound exceeded".to_owned(),
        ));
    }
    array
        .iter()
        .map(|stage| {
            Ok(OciStagePayload {
                id: first_string(stage, &["id", "stageId", "deploymentStageId"])
                    .ok_or(OciTransportError::UnexpectedBody)?,
                state: first_string(stage, &["state", "status", "lifecycleState"])
                    .ok_or(OciTransportError::UnexpectedBody)?,
                revision: revision(stage),
            })
        })
        .collect()
}

fn parse_artifacts(value: &Value) -> Result<(u32, Option<Digest>), OciTransportError> {
    let candidates = ["artifacts", "deployArtifacts", "buildArtifacts"];
    let Some(array) = candidates
        .iter()
        .find_map(|field| value.get(*field).and_then(Value::as_array))
    else {
        return Ok((0, None));
    };
    if array.len() > OCI_DEVOPS_MAX_ARTIFACT_METADATA {
        return Err(OciTransportError::InvalidRequest(
            "OCI artifact metadata bound exceeded".to_owned(),
        ));
    }
    let bytes =
        serde_json::to_vec(array).map_err(|error| OciTransportError::Decode(error.to_string()))?;
    Ok((
        u32::try_from(array.len()).map_err(|error| OciTransportError::Decode(error.to_string()))?,
        Some(sha256_digest(&bytes)),
    ))
}

fn metadata_fingerprint(value: &Value, fields: &[&str]) -> Option<Digest> {
    let selected = fields
        .iter()
        .filter_map(|field| value.get(*field).map(|value| (*field, value)))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        None
    } else {
        serde_json::to_vec(&selected)
            .ok()
            .map(|bytes| sha256_digest(&bytes))
    }
}

fn revision(value: &Value) -> u64 {
    value
        .get("revision")
        .and_then(Value::as_u64)
        .or_else(|| value.get("version").and_then(Value::as_u64))
        .or_else(|| value.get("resourceVersion").and_then(Value::as_u64))
        .unwrap_or(1)
}

fn required_string(value: &Value, field: &'static str) -> Result<String, OciTransportError> {
    first_string(value, &[field]).ok_or(OciTransportError::UnexpectedBody)
}

fn first_string(value: &Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| {
        value
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= crate::model::MAX_IDENTIFIER_LENGTH)
            .map(str::to_owned)
    })
}

fn optional_datetime(
    value: &Value,
    field: &'static str,
) -> Result<Option<DateTime<Utc>>, OciTransportError> {
    value
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or(OciTransportError::UnexpectedBody)
                .and_then(|value| {
                    DateTime::parse_from_rfc3339(value)
                        .map(|date| date.with_timezone(&Utc))
                        .map_err(|_| OciTransportError::UnexpectedBody)
                })
        })
        .transpose()
}
