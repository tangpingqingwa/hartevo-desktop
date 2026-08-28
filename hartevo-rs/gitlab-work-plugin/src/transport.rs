//! Deterministic transport seams for the Layer-1 provider.
//!
//! The transport boundary accepts an opaque secret reference only.  A
//! response body is available to the provider for bounded parsing, but its
//! `Debug` output and every provider receipt redact it completely.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Digest, ProviderProvenance, SecretKind, SecretReference, sha256_digest};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestOperation {
    Issue,
    MergeRequest,
    Approvals,
    Pipeline,
    PipelineJobs,
}

impl RequestOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::MergeRequest => "merge_request",
            Self::Approvals => "approvals",
            Self::Pipeline => "pipeline",
            Self::PipelineJobs => "pipeline_jobs",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportRequest {
    pub operation: RequestOperation,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub page: u16,
    pub per_page: u16,
    pub scope_fence: Digest,
}

impl TransportRequest {
    pub fn new(
        operation: RequestOperation,
        path: impl Into<String>,
        query: BTreeMap<String, String>,
        page: u16,
        per_page: u16,
        scope_fence: Digest,
    ) -> Result<Self, TransportError> {
        let path = path.into();
        if !path.starts_with('/') || path.len() > 512 || path.chars().any(char::is_whitespace) {
            return Err(TransportError::InvalidRequest);
        }
        if page == 0 || per_page == 0 {
            return Err(TransportError::InvalidRequest);
        }
        Ok(Self {
            operation,
            path,
            query,
            page,
            per_page,
            scope_fence,
        })
    }
}

#[derive(Clone)]
pub struct TransportResponse {
    status: u16,
    final_url: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl TransportResponse {
    pub fn new(
        status: u16,
        final_url: impl Into<String>,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            final_url: final_url.into(),
            headers,
            body,
        }
    }

    pub fn json<T: Serialize>(
        status: u16,
        final_url: impl Into<String>,
        provider_revision: &str,
        value: &T,
    ) -> Result<Self, TransportError> {
        let body = serde_json::to_vec(value).map_err(|_| TransportError::FixtureEncoding)?;
        let mut headers = BTreeMap::new();
        headers.insert(
            "x-gitlab-provider-revision".to_owned(),
            provider_revision.to_owned(),
        );
        Ok(Self::new(status, final_url, headers, body))
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub fn final_url(&self) -> &str {
        &self.final_url
    }

    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

impl fmt::Debug for TransportResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportResponse")
            .field("status", &self.status)
            .field("final_url", &self.final_url)
            .field("headers", &"<redacted>")
            .field("body_len", &self.body.len())
            .field("body", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum TransportError {
    #[error("transport is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("recording transport has no response left")]
    RecordingExhausted,
    #[error("transport request is invalid")]
    InvalidRequest,
    #[error("fixture response could not be encoded")]
    FixtureEncoding,
    #[error("transport fixture failed")]
    FixtureFailure,
}

pub trait GitLabWorkTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn execute(
        &mut self,
        request: TransportRequest,
        credential: &SecretReference,
    ) -> Result<TransportResponse, TransportError>;
}

/// A deterministic fake/recording/loopback transport.  It records request
/// metadata and credential kinds, never credential handles or response bodies.
pub struct RecordingTransport {
    provenance: ProviderProvenance,
    responses: VecDeque<TransportResponse>,
    requests: Vec<TransportRequest>,
    credential_kinds: Vec<SecretKind>,
}

impl RecordingTransport {
    pub fn new(
        provenance: ProviderProvenance,
        responses: impl IntoIterator<Item = TransportResponse>,
    ) -> Self {
        Self {
            provenance,
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
            credential_kinds: Vec::new(),
        }
    }

    pub fn fixture(responses: impl IntoIterator<Item = TransportResponse>) -> Self {
        Self::new(ProviderProvenance::Fixture, responses)
    }

    pub fn recording(responses: impl IntoIterator<Item = TransportResponse>) -> Self {
        Self::new(ProviderProvenance::Recording, responses)
    }

    pub fn loopback(responses: impl IntoIterator<Item = TransportResponse>) -> Self {
        Self::new(ProviderProvenance::Loopback, responses)
    }

    pub fn requests(&self) -> &[TransportRequest] {
        &self.requests
    }

    pub fn credential_kinds(&self) -> &[SecretKind] {
        &self.credential_kinds
    }

    pub fn remaining_responses(&self) -> usize {
        self.responses.len()
    }
}

impl fmt::Debug for RecordingTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingTransport")
            .field("provenance", &self.provenance)
            .field("response_count", &self.responses.len())
            .field("request_count", &self.requests.len())
            .field("credential_kinds", &self.credential_kinds)
            .field("response_bodies", &"<redacted>")
            .finish()
    }
}

impl GitLabWorkTransport for RecordingTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn execute(
        &mut self,
        request: TransportRequest,
        credential: &SecretReference,
    ) -> Result<TransportResponse, TransportError> {
        self.requests.push(request);
        self.credential_kinds.push(credential.kind().clone());
        self.responses
            .pop_front()
            .ok_or(TransportError::RecordingExhausted)
    }
}

pub type FakeGitLabWorkTransport = RecordingTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl GitLabWorkTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: TransportRequest,
        _credential: &SecretReference,
    ) -> Result<TransportResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub(crate) fn request_fingerprint(request: &TransportRequest) -> Digest {
    crate::model::digest_serializable(request)
}

pub(crate) fn response_digest(response: &TransportResponse) -> Digest {
    sha256_digest(response.body())
}
