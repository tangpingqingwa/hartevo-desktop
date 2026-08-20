use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use hartevo_connector_sdk::ProviderProvenanceClass;
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::model::{
    GithubEndpoint, GithubHttpRequest, GithubHttpResponse, GithubHttpResponseBody,
    GithubHttpResponseReceipt, GithubRateLimitReceipt,
};
use crate::{GITHUB_WORK_API_BASE_URL, GithubWorkError};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GithubTransportError {
    #[error("GitHub credential is unavailable")]
    CredentialUnavailable,
    #[error("GitHub returned HTTP 401")]
    Unauthorized,
    #[error("GitHub returned HTTP 403")]
    Forbidden,
    #[error("GitHub returned HTTP 404")]
    NotFound,
    #[error("GitHub returned HTTP 304 Not Modified")]
    NotModified,
    #[error("GitHub rate limit is exhausted until {reset_at}")]
    RateLimited { reset_at: String },
    #[error("GitHub request is invalid: {0}")]
    InvalidRequest(String),
    #[error("GitHub response is missing header {0}")]
    MissingHeader(&'static str),
    #[error("GitHub response body is unexpected for the endpoint")]
    UnexpectedBody,
    #[error("GitHub response could not be decoded: {0}")]
    Decode(String),
    #[error("GitHub HTTPS transport failed: {0}")]
    Transport(String),
}

impl From<GithubTransportError> for GithubWorkError {
    fn from(error: GithubTransportError) -> Self {
        match error {
            GithubTransportError::CredentialUnavailable => Self::BlockedEnv,
            GithubTransportError::Unauthorized => Self::Unauthorized("HTTP 401".to_owned()),
            GithubTransportError::Forbidden => Self::Unauthorized("HTTP 403".to_owned()),
            GithubTransportError::NotFound => Self::RepositoryRevoked,
            GithubTransportError::NotModified => Self::NotModified,
            GithubTransportError::RateLimited { reset_at } => Self::RateLimited { reset_at },
            GithubTransportError::InvalidRequest(detail)
            | GithubTransportError::Transport(detail)
            | GithubTransportError::Decode(detail) => Self::Transport(detail),
            GithubTransportError::MissingHeader(header) => {
                Self::Transport(format!("missing GitHub response header {header}"))
            }
            GithubTransportError::UnexpectedBody => {
                Self::Decode("unexpected GitHub response body".to_owned())
            }
        }
    }
}

/// A narrow authenticated HTTP seam.  The token is borrowed for one request
/// and the request/response types contain no credential material.
pub trait GithubWorkHttpTransport: Send {
    fn execute(
        &self,
        token: &str,
        request: &GithubHttpRequest,
    ) -> Result<GithubHttpResponse, GithubTransportError>;

    fn provenance_class(&self) -> ProviderProvenanceClass;

    fn is_native(&self) -> bool {
        false
    }
}

/// Deterministic response queue for scoped tests.  It records the exact
/// request headers and endpoint so tests can prove API version, ETag, and
/// pagination behavior without pretending the loopback is a connected App.
#[derive(Clone, Debug)]
pub struct LoopbackGithubWorkTransport {
    responses: Arc<Mutex<VecDeque<Result<GithubHttpResponse, GithubTransportError>>>>,
    requests: Arc<Mutex<Vec<GithubHttpRequest>>>,
    provenance: ProviderProvenanceClass,
}

impl LoopbackGithubWorkTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<GithubHttpResponse, GithubTransportError>>,
    ) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
            requests: Arc::new(Mutex::new(Vec::new())),
            provenance: ProviderProvenanceClass::ControlledProvider,
        }
    }

    #[must_use]
    pub fn with_provenance(mut self, provenance: ProviderProvenanceClass) -> Self {
        self.provenance = provenance;
        self
    }

    pub fn push_response(&self, response: Result<GithubHttpResponse, GithubTransportError>) {
        if let Ok(mut responses) = self.responses.lock() {
            responses.push_back(response);
        }
    }

    pub fn requests(&self) -> Vec<GithubHttpRequest> {
        self.requests
            .lock()
            .map_or_else(|_| Vec::new(), |requests| requests.clone())
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.lock().map_or(0, |responses| responses.len())
    }
}

impl GithubWorkHttpTransport for LoopbackGithubWorkTransport {
    fn execute(
        &self,
        token: &str,
        request: &GithubHttpRequest,
    ) -> Result<GithubHttpResponse, GithubTransportError> {
        if token.trim().is_empty() || token.chars().any(char::is_control) {
            return Err(GithubTransportError::CredentialUnavailable);
        }
        request
            .validate()
            .map_err(|error| GithubTransportError::InvalidRequest(error.to_string()))?;
        self.requests
            .lock()
            .map_err(|_| {
                GithubTransportError::Transport("loopback request log poisoned".to_owned())
            })?
            .push(request.clone());
        let response = self
            .responses
            .lock()
            .map_err(|_| {
                GithubTransportError::Transport("loopback response queue poisoned".to_owned())
            })?
            .pop_front()
            .ok_or_else(|| {
                GithubTransportError::Transport("loopback response queue exhausted".to_owned())
            })??;
        Ok(response)
    }

    fn provenance_class(&self) -> ProviderProvenanceClass {
        self.provenance
    }
}

/// Production HTTPS transport.  It uses the GitHub REST API directly; the
/// `gh` CLI is not involved in this path.
pub struct UreqGithubAppTransport {
    base_url: String,
    agent: ureq::Agent,
}

impl fmt::Debug for UreqGithubAppTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqGithubAppTransport")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl UreqGithubAppTransport {
    pub fn new(base_url: impl Into<String>) -> Result<Self, GithubWorkError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&base_url).map_err(|error| {
            GithubWorkError::InvalidInput(format!("GitHub API base URL is invalid: {error}"))
        })?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(GithubWorkError::InvalidInput(
                "GitHub API base URL must be HTTPS without credentials or query".to_owned(),
            ));
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-github-work/1")
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .into();
        Ok(Self { base_url, agent })
    }

    pub fn github_api() -> Result<Self, GithubWorkError> {
        Self::new(GITHUB_WORK_API_BASE_URL)
    }

    fn endpoint_url(&self, endpoint: &GithubEndpoint) -> Result<String, GithubTransportError> {
        let mut url = Url::parse(&self.base_url)
            .map_err(|error| GithubTransportError::Transport(error.to_string()))?;
        match endpoint {
            GithubEndpoint::Installation { .. } => {
                url.path_segments_mut()
                    .map_err(|()| {
                        GithubTransportError::Transport(
                            "GitHub API base URL cannot accept path segments".to_owned(),
                        )
                    })?
                    .push("installation");
            }
            GithubEndpoint::Repository { owner, repository } => {
                let mut segments = url.path_segments_mut().map_err(|()| {
                    GithubTransportError::Transport(
                        "GitHub API base URL cannot accept path segments".to_owned(),
                    )
                })?;
                segments.push("repos").push(owner).push(repository);
            }
            GithubEndpoint::Issues {
                owner,
                repository,
                page,
                per_page,
            } => {
                let mut segments = url.path_segments_mut().map_err(|()| {
                    GithubTransportError::Transport(
                        "GitHub API base URL cannot accept path segments".to_owned(),
                    )
                })?;
                segments
                    .push("repos")
                    .push(owner)
                    .push(repository)
                    .push("issues");
                drop(segments);
                url.query_pairs_mut()
                    .append_pair("state", "all")
                    .append_pair("page", &page.to_string())
                    .append_pair("per_page", &per_page.to_string());
            }
            GithubEndpoint::PullRequests {
                owner,
                repository,
                page,
                per_page,
            } => {
                let mut segments = url.path_segments_mut().map_err(|()| {
                    GithubTransportError::Transport(
                        "GitHub API base URL cannot accept path segments".to_owned(),
                    )
                })?;
                segments
                    .push("repos")
                    .push(owner)
                    .push(repository)
                    .push("pulls");
                drop(segments);
                url.query_pairs_mut()
                    .append_pair("state", "all")
                    .append_pair("page", &page.to_string())
                    .append_pair("per_page", &per_page.to_string());
            }
            GithubEndpoint::CheckRuns {
                owner,
                repository,
                reference,
                page,
                per_page,
            } => {
                let mut segments = url.path_segments_mut().map_err(|()| {
                    GithubTransportError::Transport(
                        "GitHub API base URL cannot accept path segments".to_owned(),
                    )
                })?;
                segments
                    .push("repos")
                    .push(owner)
                    .push(repository)
                    .push("commits")
                    .push(reference)
                    .push("check-runs");
                drop(segments);
                url.query_pairs_mut()
                    .append_pair("page", &page.to_string())
                    .append_pair("per_page", &per_page.to_string());
            }
        }
        Ok(url.to_string())
    }

    fn get_json(
        &self,
        token: &str,
        request: &GithubHttpRequest,
    ) -> Result<GithubHttpResponse, GithubTransportError> {
        let url = self.endpoint_url(&request.endpoint)?;
        let mut builder = self
            .agent
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", request.headers.accept.clone())
            .header("X-GitHub-Api-Version", request.headers.api_version.clone());
        if let Some(etag) = &request.headers.if_none_match {
            builder = builder.header("If-None-Match", etag.clone());
        }
        let mut response = builder.call().map_err(classify_ureq_error)?;
        let status = response.status().as_u16();
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let request_id = response
            .headers()
            .get("x-github-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let next_page = response
            .headers()
            .get("link")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_next_page);
        let rate_limit = parse_rate_limit(response.headers())?;
        let body = response
            .body_mut()
            .read_to_string()
            .map_err(|error| GithubTransportError::Transport(error.to_string()))?;
        let value = serde_json::from_str::<Value>(&body)
            .map_err(|error| GithubTransportError::Decode(error.to_string()))?;
        let body = decode_body(&request.endpoint, value)?;
        let receipt = GithubHttpResponseReceipt::new(
            status,
            request.headers.api_version.clone(),
            etag,
            rate_limit,
            next_page,
            request_id,
            request.observed_at,
        )
        .map_err(|error| GithubTransportError::InvalidRequest(error.to_string()))?;
        GithubHttpResponse::new(Some(body), receipt)
            .map_err(|error| GithubTransportError::InvalidRequest(error.to_string()))
    }
}

impl GithubWorkHttpTransport for UreqGithubAppTransport {
    fn execute(
        &self,
        token: &str,
        request: &GithubHttpRequest,
    ) -> Result<GithubHttpResponse, GithubTransportError> {
        if token.trim().is_empty() || token.chars().any(char::is_control) {
            return Err(GithubTransportError::CredentialUnavailable);
        }
        request
            .validate()
            .map_err(|error| GithubTransportError::InvalidRequest(error.to_string()))?;
        self.get_json(token, request)
    }

    fn provenance_class(&self) -> ProviderProvenanceClass {
        ProviderProvenanceClass::ProductionProvider
    }

    fn is_native(&self) -> bool {
        true
    }
}

fn decode_body(
    endpoint: &GithubEndpoint,
    value: Value,
) -> Result<GithubHttpResponseBody, GithubTransportError> {
    match endpoint {
        GithubEndpoint::Installation { .. } => serde_json::from_value(value)
            .map(GithubHttpResponseBody::Installation)
            .map_err(|error| GithubTransportError::Decode(error.to_string())),
        GithubEndpoint::Repository { .. } => serde_json::from_value(value)
            .map(GithubHttpResponseBody::Repository)
            .map_err(|error| GithubTransportError::Decode(error.to_string())),
        GithubEndpoint::Issues { .. } => serde_json::from_value(value)
            .map(GithubHttpResponseBody::Issues)
            .map_err(|error| GithubTransportError::Decode(error.to_string())),
        GithubEndpoint::PullRequests { .. } => serde_json::from_value(value)
            .map(GithubHttpResponseBody::PullRequests)
            .map_err(|error| GithubTransportError::Decode(error.to_string())),
        GithubEndpoint::CheckRuns { .. } => {
            let runs = value
                .get("check_runs")
                .cloned()
                .ok_or(GithubTransportError::UnexpectedBody)?;
            serde_json::from_value(runs)
                .map(GithubHttpResponseBody::CheckRuns)
                .map_err(|error| GithubTransportError::Decode(error.to_string()))
        }
    }
}

fn parse_rate_limit(
    headers: &ureq::http::HeaderMap,
) -> Result<GithubRateLimitReceipt, GithubTransportError> {
    let parse = |name: &'static str| {
        headers
            .get(name)
            .ok_or(GithubTransportError::MissingHeader(name))?
            .to_str()
            .map_err(|_| GithubTransportError::MissingHeader(name))?
            .parse::<u64>()
            .map_err(|_| GithubTransportError::MissingHeader(name))
    };
    let limit = parse("x-ratelimit-limit")?;
    let remaining = parse("x-ratelimit-remaining")?;
    let reset = parse("x-ratelimit-reset")?;
    let reset_at = DateTime::<Utc>::from_timestamp(i64::try_from(reset).unwrap_or(i64::MAX), 0)
        .ok_or(GithubTransportError::MissingHeader("x-ratelimit-reset"))?;
    GithubRateLimitReceipt::new(limit, remaining, reset_at)
        .map_err(|error| GithubTransportError::InvalidRequest(error.to_string()))
}

fn parse_next_page(link: &str) -> Option<u32> {
    link.split(',').find_map(|entry| {
        if !entry.contains("rel=\"next\"") {
            return None;
        }
        let start = entry.find('<')? + 1;
        let end = entry[start..].find('>')? + start;
        let url = Url::parse(&entry[start..end]).ok()?;
        url.query_pairs()
            .find(|(key, _)| key == "page")
            .and_then(|(_, value)| value.parse::<u32>().ok())
            .filter(|page| *page > 0)
    })
}

fn classify_ureq_error(error: ureq::Error) -> GithubTransportError {
    match error {
        ureq::Error::StatusCode(401) => GithubTransportError::Unauthorized,
        ureq::Error::StatusCode(403) => GithubTransportError::Forbidden,
        ureq::Error::StatusCode(404) => GithubTransportError::NotFound,
        ureq::Error::StatusCode(304) => GithubTransportError::NotModified,
        ureq::Error::StatusCode(429) => GithubTransportError::RateLimited {
            reset_at: "unknown".to_owned(),
        },
        ureq::Error::StatusCode(status) => GithubTransportError::Transport(format!(
            "GitHub returned unexpected HTTP status {status}"
        )),
        other => GithubTransportError::Transport(other.to_string()),
    }
}

#[allow(dead_code)]
fn _assert_response_timestamp_is_utc(value: DateTime<Utc>) -> DateTime<Utc> {
    value
}
