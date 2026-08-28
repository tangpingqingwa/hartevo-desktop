//! Allowlisted, normalized Bitbucket REST seams.
//!
//! Layer 1 intentionally has no live HTTPS implementation.  Fixture,
//! recording, fake, loopback, and BLOCKED_ENV transports all make the native
//! boundary explicit while exercising the same bounded request/response
//! contract.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;
use url::Url;

use crate::model::{
    BitbucketAccessToken, BitbucketDeliveryScope, BitbucketHttpMethod, BitbucketResponseBody,
    BitbucketResponseReceipt, CommitStatusPayload, DeploymentPayload, Digest, OpaquePageToken,
    PipelinePayload, ProviderRevision, PullRequestPayload, RepositoryPayload, Revision,
    TransportProvenance, digest_serializable, sha256_digest,
};
use crate::{
    BITBUCKET_API_ORIGIN, BITBUCKET_API_REVISION, BITBUCKET_PROVIDER_REVISION, MAX_RESPONSE_BYTES,
    MAX_RETRY_AFTER_SECONDS, PAGE_SIZE,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum BitbucketTransportError {
    #[error("Bitbucket credential is unavailable")]
    CredentialUnavailable,
    #[error("BLOCKED_ENV: native Bitbucket transport is disabled")]
    BlockedEnv,
    #[error("Bitbucket request is invalid: {0}")]
    InvalidRequest(String),
    #[error("Bitbucket response body is unexpected for the endpoint")]
    UnexpectedBody,
    #[error("Bitbucket response could not be decoded: {0}")]
    Decode(String),
    #[error("Bitbucket transport failed: {0}")]
    Transport(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestBounds {
    pub max_response_bytes: usize,
    pub max_pages: u16,
    pub page_size: u16,
}

impl Default for RequestBounds {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_pages: crate::MAX_PAGES,
            page_size: PAGE_SIZE,
        }
    }
}

impl RequestBounds {
    pub fn new(
        max_response_bytes: usize,
        max_pages: u16,
        page_size: u16,
    ) -> Result<Self, BitbucketTransportError> {
        if max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
            || max_pages == 0
            || max_pages > crate::MAX_PAGES
            || page_size == 0
            || page_size > PAGE_SIZE
        {
            return Err(BitbucketTransportError::InvalidRequest(
                "Bitbucket request bounds exceed the Layer-1 maximum".to_owned(),
            ));
        }
        Ok(Self {
            max_response_bytes,
            max_pages,
            page_size,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum BitbucketEndpoint {
    Repository {
        workspace: String,
        repository: String,
    },
    PullRequest {
        workspace: String,
        repository: String,
        pull_request_id: u64,
    },
    CommitStatuses {
        workspace: String,
        repository: String,
        commit: String,
        page_token: Option<OpaquePageToken>,
        page_size: u16,
    },
    Pipeline {
        workspace: String,
        repository: String,
        pipeline_uuid: String,
    },
    Deployment {
        workspace: String,
        repository: String,
        deployment_uuid: String,
    },
}

impl fmt::Debug for BitbucketEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Repository {
                workspace,
                repository,
            } => formatter
                .debug_struct("Repository")
                .field("workspace", workspace)
                .field("repository", repository)
                .finish(),
            Self::PullRequest {
                workspace,
                repository,
                pull_request_id,
            } => formatter
                .debug_struct("PullRequest")
                .field("workspace", workspace)
                .field("repository", repository)
                .field("pull_request_id", pull_request_id)
                .finish(),
            Self::CommitStatuses {
                workspace,
                repository,
                commit,
                page_token,
                page_size,
            } => formatter
                .debug_struct("CommitStatuses")
                .field("workspace", workspace)
                .field("repository", repository)
                .field("commit_digest", &sha256_digest(commit.as_bytes()))
                .field("page_token", page_token)
                .field("page_size", page_size)
                .finish(),
            Self::Pipeline {
                workspace,
                repository,
                pipeline_uuid,
            } => formatter
                .debug_struct("Pipeline")
                .field("workspace", workspace)
                .field("repository", repository)
                .field(
                    "pipeline_uuid_digest",
                    &sha256_digest(pipeline_uuid.as_bytes()),
                )
                .finish(),
            Self::Deployment {
                workspace,
                repository,
                deployment_uuid,
            } => formatter
                .debug_struct("Deployment")
                .field("workspace", workspace)
                .field("repository", repository)
                .field(
                    "deployment_uuid_digest",
                    &sha256_digest(deployment_uuid.as_bytes()),
                )
                .finish(),
        }
    }
}

impl BitbucketEndpoint {
    pub fn path_and_query(&self) -> Result<String, BitbucketTransportError> {
        let mut url = Url::parse(BITBUCKET_API_ORIGIN)
            .map_err(|error| BitbucketTransportError::Transport(error.to_string()))?;
        match self {
            Self::Repository {
                workspace,
                repository,
            } => {
                push_segments(&mut url, &["2.0", "repositories", workspace, repository])?;
            }
            Self::PullRequest {
                workspace,
                repository,
                pull_request_id,
            } => {
                push_segments(
                    &mut url,
                    &[
                        "2.0",
                        "repositories",
                        workspace,
                        repository,
                        "pullrequests",
                        &pull_request_id.to_string(),
                    ],
                )?;
            }
            Self::CommitStatuses {
                workspace,
                repository,
                commit,
                page_token,
                page_size,
            } => {
                push_segments(
                    &mut url,
                    &[
                        "2.0",
                        "repositories",
                        workspace,
                        repository,
                        "commit",
                        commit,
                        "statuses",
                    ],
                )?;
                url.query_pairs_mut()
                    .append_pair("pagelen", &page_size.to_string());
                if let Some(page_token) = page_token {
                    url.query_pairs_mut()
                        .append_pair("page", page_token.as_str());
                }
            }
            Self::Pipeline {
                workspace,
                repository,
                pipeline_uuid,
            } => {
                push_segments(
                    &mut url,
                    &[
                        "2.0",
                        "repositories",
                        workspace,
                        repository,
                        "pipelines",
                        pipeline_uuid,
                    ],
                )?;
            }
            Self::Deployment {
                workspace,
                repository,
                deployment_uuid,
            } => {
                push_segments(
                    &mut url,
                    &[
                        "2.0",
                        "repositories",
                        workspace,
                        repository,
                        "deployments",
                        deployment_uuid,
                    ],
                )?;
            }
        }
        let mut path_and_query = url.path().to_owned();
        if let Some(query) = url.query() {
            path_and_query.push('?');
            path_and_query.push_str(query);
        }
        Ok(path_and_query)
    }

    pub fn safe_path_and_query(&self) -> Result<String, BitbucketTransportError> {
        let raw = self.path_and_query()?;
        match self {
            Self::CommitStatuses { page_token, .. } if page_token.is_some() => {
                let raw_without_page = raw.split("&page=").next().unwrap_or(&raw).to_owned();
                Ok(format!(
                    "{raw_without_page}&page_digest={}",
                    page_token.as_ref().map_or_else(
                        || Digest::parse("0".repeat(64)).expect("zero digest"),
                        OpaquePageToken::digest
                    )
                ))
            }
            _ => Ok(raw),
        }
    }

    pub const fn method(&self) -> BitbucketHttpMethod {
        BitbucketHttpMethod::Get
    }

    pub fn page_token_digest(&self) -> Option<Digest> {
        match self {
            Self::CommitStatuses { page_token, .. } => {
                page_token.as_ref().map(OpaquePageToken::digest)
            }
            _ => None,
        }
    }

    fn body_kind(&self) -> &'static str {
        match self {
            Self::Repository { .. } => "repository",
            Self::PullRequest { .. } => "pull_request",
            Self::CommitStatuses { .. } => "commit_statuses",
            Self::Pipeline { .. } => "pipeline",
            Self::Deployment { .. } => "deployment",
        }
    }
}

fn push_segments(url: &mut Url, segments: &[&str]) -> Result<(), BitbucketTransportError> {
    let mut path = url.path_segments_mut().map_err(|()| {
        BitbucketTransportError::Transport("Bitbucket URL cannot be a base".to_owned())
    })?;
    for segment in segments {
        if segment.is_empty()
            || segment.chars().any(char::is_control)
            || segment.contains('/')
            || segment.contains('?')
            || segment.contains('#')
            || *segment == "."
            || *segment == ".."
        {
            return Err(BitbucketTransportError::InvalidRequest(
                "Bitbucket path segment is invalid".to_owned(),
            ));
        }
        path.push(segment);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitbucketHttpRequest {
    pub endpoint: BitbucketEndpoint,
    pub observed_at: DateTime<Utc>,
    pub max_response_bytes: usize,
    pub api_revision: String,
    request_digest: Digest,
}

impl BitbucketHttpRequest {
    pub fn new(
        endpoint: BitbucketEndpoint,
        observed_at: DateTime<Utc>,
        max_response_bytes: usize,
    ) -> Result<Self, BitbucketTransportError> {
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(BitbucketTransportError::InvalidRequest(
                "Bitbucket response bound is outside the contract".to_owned(),
            ));
        }
        let request_digest = digest_serializable(&(
            endpoint.method(),
            endpoint.safe_path_and_query()?,
            endpoint.page_token_digest(),
            BITBUCKET_API_REVISION,
            max_response_bytes,
        ))
        .map_err(|error| BitbucketTransportError::Transport(error.to_string()))?;
        Ok(Self {
            endpoint,
            observed_at,
            max_response_bytes,
            api_revision: BITBUCKET_API_REVISION.to_owned(),
            request_digest,
        })
    }

    pub fn path_and_query(&self) -> Result<String, BitbucketTransportError> {
        self.endpoint.path_and_query()
    }

    pub fn safe_path_and_query(&self) -> Result<String, BitbucketTransportError> {
        self.endpoint.safe_path_and_query()
    }

    pub fn digest(&self) -> Digest {
        self.request_digest.clone()
    }

    pub fn is_allowlisted(&self) -> bool {
        self.endpoint.method() == BitbucketHttpMethod::Get
            && self
                .path_and_query()
                .is_ok_and(|path| path.starts_with("/2.0/repositories/"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitbucketHttpResponse {
    body: BitbucketResponseBody,
    receipt: BitbucketResponseReceipt,
    next_page_token: Option<OpaquePageToken>,
}

impl BitbucketHttpResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn from_body(
        request: &BitbucketHttpRequest,
        status: u16,
        body: BitbucketResponseBody,
        response_size: usize,
        provider_revision: impl Into<String>,
        retry_after_seconds: Option<u32>,
        next_page_token: Option<String>,
    ) -> Result<Self, BitbucketTransportError> {
        let provider_revision = ProviderRevision::parse(provider_revision.into())
            .map_err(|error| BitbucketTransportError::InvalidRequest(error.to_string()))?;
        let next_page_token = next_page_token
            .map(OpaquePageToken::new)
            .transpose()
            .map_err(|error| BitbucketTransportError::InvalidRequest(error.to_string()))?;
        if response_size > request.max_response_bytes
            || retry_after_seconds
                .is_some_and(|value| value == 0 || value > MAX_RETRY_AFTER_SECONDS)
        {
            return Err(BitbucketTransportError::InvalidRequest(
                "Bitbucket response exceeds the configured bound".to_owned(),
            ));
        }
        if status == 200 && body_kind(&body) != request.endpoint.body_kind() {
            return Err(BitbucketTransportError::UnexpectedBody);
        }
        let normalized = serde_json::to_vec(&body)
            .map_err(|error| BitbucketTransportError::Decode(error.to_string()))?;
        let receipt = BitbucketResponseReceipt {
            request_digest: request.digest(),
            path_and_query: request.safe_path_and_query()?,
            api_revision: request.api_revision.clone(),
            response_status: status,
            response_size,
            response_digest: sha256_digest(&normalized),
            provider_revision,
            page_token_digest: request.endpoint.page_token_digest(),
            retry_after_seconds,
            raw_provider_payload_retained: false,
            raw_credential_material_retained: false,
            raw_pagination_token_retained: false,
            observed_at: request.observed_at,
        };
        Ok(Self {
            body,
            receipt,
            next_page_token,
        })
    }

    pub fn from_json(
        request: &BitbucketHttpRequest,
        status: u16,
        bytes: &[u8],
        retry_after_seconds: Option<u32>,
        next_page_token: Option<String>,
    ) -> Result<Self, BitbucketTransportError> {
        if bytes.len() > request.max_response_bytes {
            return Err(BitbucketTransportError::InvalidRequest(
                "Bitbucket response exceeds the configured bound".to_owned(),
            ));
        }
        let (body, inferred_next_page_token) = if status == 200 {
            let value = serde_json::from_slice::<Value>(bytes)
                .map_err(|error| BitbucketTransportError::Decode(error.to_string()))?;
            let next_page_token = next_page_token_from_value(&request.endpoint, &value)?;
            (decode_body(&request.endpoint, &value)?, next_page_token)
        } else {
            // Error bodies are represented only by bounded status/receipt
            // metadata and are dropped before crossing the provider seam.
            (BitbucketResponseBody::Empty, None)
        };
        let next_page_token = next_page_token.or(inferred_next_page_token);
        let mut response = Self::from_body(
            request,
            status,
            body,
            bytes.len(),
            BITBUCKET_PROVIDER_REVISION,
            retry_after_seconds,
            next_page_token,
        )?;
        response.receipt.response_digest = sha256_digest(bytes);
        Ok(response)
    }

    pub fn body(&self) -> &BitbucketResponseBody {
        &self.body
    }

    pub fn receipt(&self) -> &BitbucketResponseReceipt {
        &self.receipt
    }

    pub fn next_page_token(&self) -> Option<&OpaquePageToken> {
        self.next_page_token.as_ref()
    }
}

fn next_page_token_from_value(
    endpoint: &BitbucketEndpoint,
    value: &Value,
) -> Result<Option<String>, BitbucketTransportError> {
    if !matches!(endpoint, BitbucketEndpoint::CommitStatuses { .. }) {
        return Ok(None);
    }
    let Some(next) = value.get("next").and_then(Value::as_str) else {
        return Ok(None);
    };
    let next_url = Url::parse(next).map_err(|error| {
        BitbucketTransportError::Decode(format!("invalid Bitbucket next page URL: {error}"))
    })?;
    Ok(next_url
        .query_pairs()
        .find(|(key, _)| key == "page")
        .map(|(_, token)| token.into_owned()))
}

fn body_kind(body: &BitbucketResponseBody) -> &'static str {
    match body {
        BitbucketResponseBody::Repository(_) => "repository",
        BitbucketResponseBody::PullRequest(_) => "pull_request",
        BitbucketResponseBody::CommitStatuses(_) => "commit_statuses",
        BitbucketResponseBody::Pipeline(_) => "pipeline",
        BitbucketResponseBody::Deployment(_) => "deployment",
        BitbucketResponseBody::Empty => "empty",
    }
}

/// The token is borrowed for one request and is never copied into a request,
/// response, receipt, recording, or evidence value.
pub trait BitbucketDeliveryTransport: fmt::Debug {
    fn execute(
        &mut self,
        token: &BitbucketAccessToken,
        request: &BitbucketHttpRequest,
    ) -> Result<BitbucketHttpResponse, BitbucketTransportError>;

    fn provenance(&self) -> TransportProvenance;
}

#[derive(Clone, Debug)]
struct QueuedBitbucketTransport {
    responses: VecDeque<Result<BitbucketHttpResponse, BitbucketTransportError>>,
    requests: Vec<BitbucketHttpRequest>,
}

impl QueuedBitbucketTransport {
    fn new(
        responses: impl IntoIterator<Item = Result<BitbucketHttpResponse, BitbucketTransportError>>,
        _provenance: TransportProvenance,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    fn execute(
        &mut self,
        token: &BitbucketAccessToken,
        request: &BitbucketHttpRequest,
    ) -> Result<BitbucketHttpResponse, BitbucketTransportError> {
        if token.as_str().trim().is_empty() || !request.is_allowlisted() {
            return Err(BitbucketTransportError::CredentialUnavailable);
        }
        if request.api_revision != BITBUCKET_API_REVISION {
            return Err(BitbucketTransportError::InvalidRequest(
                "Bitbucket API revision drifted".to_owned(),
            ));
        }
        self.requests.push(request.clone());
        self.responses.pop_front().ok_or_else(|| {
            BitbucketTransportError::Transport("recording response queue exhausted".to_owned())
        })?
    }

    fn requests(&self) -> &[BitbucketHttpRequest] {
        &self.requests
    }

    fn remaining_responses(&self) -> usize {
        self.responses.len()
    }

    fn push_response(&mut self, response: Result<BitbucketHttpResponse, BitbucketTransportError>) {
        self.responses.push_back(response);
    }
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name(QueuedBitbucketTransport);

        impl $name {
            pub fn new(
                responses: impl IntoIterator<
                    Item = Result<BitbucketHttpResponse, BitbucketTransportError>,
                >,
            ) -> Self {
                Self(QueuedBitbucketTransport::new(responses, $provenance))
            }

            pub fn requests(&self) -> &[BitbucketHttpRequest] {
                self.0.requests()
            }

            pub fn remaining_responses(&self) -> usize {
                self.0.remaining_responses()
            }

            pub fn push_response(
                &mut self,
                response: Result<BitbucketHttpResponse, BitbucketTransportError>,
            ) {
                self.0.push_response(response);
            }
        }

        impl BitbucketDeliveryTransport for $name {
            fn execute(
                &mut self,
                token: &BitbucketAccessToken,
                request: &BitbucketHttpRequest,
            ) -> Result<BitbucketHttpResponse, BitbucketTransportError> {
                self.0.execute(token, request)
            }

            fn provenance(&self) -> TransportProvenance {
                $provenance
            }
        }
    };
}

queued_transport!(RecordingBitbucketTransport, TransportProvenance::Recording);
queued_transport!(FixtureBitbucketTransport, TransportProvenance::Fixture);
queued_transport!(FakeBitbucketTransport, TransportProvenance::Fake);
queued_transport!(LoopbackBitbucketTransport, TransportProvenance::Loopback);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvBitbucketTransport;

impl BitbucketDeliveryTransport for BlockedEnvBitbucketTransport {
    fn execute(
        &mut self,
        _token: &BitbucketAccessToken,
        _request: &BitbucketHttpRequest,
    ) -> Result<BitbucketHttpResponse, BitbucketTransportError> {
        Err(BitbucketTransportError::BlockedEnv)
    }

    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
}

pub type BlockedEnvTransport = BlockedEnvBitbucketTransport;

fn decode_body(
    endpoint: &BitbucketEndpoint,
    value: &Value,
) -> Result<BitbucketResponseBody, BitbucketTransportError> {
    match endpoint {
        BitbucketEndpoint::Repository { .. } => {
            parse_repository(value).map(BitbucketResponseBody::Repository)
        }
        BitbucketEndpoint::PullRequest { .. } => {
            parse_pull_request(value).map(BitbucketResponseBody::PullRequest)
        }
        BitbucketEndpoint::CommitStatuses { .. } => {
            parse_commit_statuses(value).map(BitbucketResponseBody::CommitStatuses)
        }
        BitbucketEndpoint::Pipeline { .. } => {
            parse_pipeline(value).map(BitbucketResponseBody::Pipeline)
        }
        BitbucketEndpoint::Deployment { .. } => {
            parse_deployment(value).map(BitbucketResponseBody::Deployment)
        }
    }
}

fn parse_repository(value: &Value) -> Result<RepositoryPayload, BitbucketTransportError> {
    let workspace = value
        .get("workspace")
        .and_then(|item| item.get("slug").or_else(|| item.get("uuid")))
        .and_then(Value::as_str)
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    Ok(RepositoryPayload {
        uuid: required_string(value.get("uuid"))?,
        workspace: workspace.to_owned(),
        slug: required_string(value.get("slug"))?,
        name: optional_bounded_string(value.get("name"))?,
        is_private: value
            .get("is_private")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        revision: revision_from(value)?,
    })
}

fn parse_pull_request(value: &Value) -> Result<PullRequestPayload, BitbucketTransportError> {
    let repository_uuid = value
        .get("destination")
        .and_then(|item| item.get("repository"))
        .and_then(|item| item.get("uuid"))
        .and_then(Value::as_str)
        .or_else(|| value.get("repository_uuid").and_then(Value::as_str))
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    let source_commit = value
        .get("source")
        .and_then(|item| item.get("commit"))
        .and_then(|item| item.get("hash"))
        .and_then(Value::as_str)
        .or_else(|| value.get("source_commit").and_then(Value::as_str))
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    let destination_commit = value
        .get("destination")
        .and_then(|item| item.get("commit"))
        .and_then(|item| item.get("hash"))
        .and_then(Value::as_str)
        .or_else(|| value.get("destination_commit").and_then(Value::as_str))
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    Ok(PullRequestPayload {
        id: value
            .get("id")
            .and_then(Value::as_u64)
            .ok_or(BitbucketTransportError::UnexpectedBody)?,
        repository_uuid: repository_uuid.to_owned(),
        state: required_string(value.get("state"))?,
        title: optional_bounded_string(value.get("title"))?,
        source_commit: source_commit.to_owned(),
        destination_commit: destination_commit.to_owned(),
        revision: revision_from(value)?,
    })
}

fn parse_commit_statuses(
    value: &Value,
) -> Result<Vec<CommitStatusPayload>, BitbucketTransportError> {
    let values = value
        .get("values")
        .and_then(Value::as_array)
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    values
        .iter()
        .map(|item| {
            let target_url_digest = item
                .get("url")
                .and_then(Value::as_str)
                .map(|url| sha256_digest(url.as_bytes()));
            Ok(CommitStatusPayload {
                key: required_string(item.get("key"))?,
                name: optional_bounded_string(item.get("name"))?,
                state: required_string(item.get("state"))?,
                revision: revision_from(item)?,
                target_url_digest,
            })
        })
        .collect()
}

fn parse_pipeline(value: &Value) -> Result<PipelinePayload, BitbucketTransportError> {
    let state = value
        .get("state")
        .and_then(|item| item.get("name").or(Some(item)))
        .and_then(Value::as_str)
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    let result = value
        .get("state")
        .and_then(|item| item.get("result"))
        .and_then(|item| item.get("name").or(Some(item)))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let commit = value
        .get("target")
        .and_then(|item| item.get("commit"))
        .and_then(|item| item.get("hash"))
        .and_then(Value::as_str)
        .or_else(|| value.get("commit").and_then(Value::as_str))
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    let target_ref = value
        .get("target")
        .and_then(|item| item.get("ref_name"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(PipelinePayload {
        uuid: required_string(value.get("uuid"))?,
        build_number: value
            .get("build_number")
            .and_then(Value::as_u64)
            .ok_or(BitbucketTransportError::UnexpectedBody)?,
        state: state.to_owned(),
        result,
        commit: commit.to_owned(),
        target_ref,
        revision: revision_from(value)?,
    })
}

fn parse_deployment(value: &Value) -> Result<DeploymentPayload, BitbucketTransportError> {
    let pipeline_uuid = value
        .get("pipeline")
        .and_then(|item| item.get("uuid"))
        .and_then(Value::as_str)
        .or_else(|| value.get("pipeline_uuid").and_then(Value::as_str))
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    let commit = value
        .get("commit")
        .and_then(|item| item.get("hash"))
        .and_then(Value::as_str)
        .or_else(|| value.get("commit").and_then(Value::as_str))
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    let state = value
        .get("state")
        .and_then(|item| item.get("name").or(Some(item)))
        .and_then(Value::as_str)
        .ok_or(BitbucketTransportError::UnexpectedBody)?;
    let environment = value
        .get("environment")
        .and_then(|item| item.get("name").or(Some(item)))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(DeploymentPayload {
        uuid: required_string(value.get("uuid"))?,
        pipeline_uuid: pipeline_uuid.to_owned(),
        commit: commit.to_owned(),
        state: state.to_owned(),
        environment,
        revision: revision_from(value)?,
    })
}

fn required_string(value: Option<&Value>) -> Result<String, BitbucketTransportError> {
    value
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= crate::MAX_IDENTIFIER_BYTES
                && value.trim() == *value
                && !value.chars().any(char::is_control)
        })
        .map(str::to_owned)
        .ok_or(BitbucketTransportError::UnexpectedBody)
}

fn optional_bounded_string(
    value: Option<&Value>,
) -> Result<Option<String>, BitbucketTransportError> {
    value
        .map(|value| {
            value
                .as_str()
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= crate::model::MAX_TITLE_BYTES
                        && value.trim() == *value
                        && !value.chars().any(char::is_control)
                })
                .map(str::to_owned)
                .ok_or(BitbucketTransportError::UnexpectedBody)
        })
        .transpose()
}

fn revision_from(value: &Value) -> Result<String, BitbucketTransportError> {
    value
        .get("revision")
        .or_else(|| value.get("updated_on"))
        .or_else(|| value.get("completed_on"))
        .or_else(|| value.get("created_on"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= crate::MAX_IDENTIFIER_BYTES)
        .map(str::to_owned)
        .or_else(|| value.get("uuid").and_then(Value::as_str).map(str::to_owned))
        .ok_or(BitbucketTransportError::UnexpectedBody)
}

// Keep these imports and the scope type visible to downstream callers that
// use the transport module as their request-construction boundary.
#[allow(dead_code)]
fn _scope_type_is_part_of_transport_contract(_scope: &BitbucketDeliveryScope) {}

#[allow(dead_code)]
fn _revision_type_is_part_of_transport_contract(_revision: &Revision) {}
