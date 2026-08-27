//! GET-only Jenkins Remote Access JSON provider.
//!
//! The transport boundary accepts JSON only long enough to normalize the
//! allowlisted fields. The provider returns typed projections and redacted
//! receipts; it never returns the original JSON value.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    fmt::Write as _,
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::model::{
    CommitSha, Digest, JenkinsArtifactMetadata, JenkinsBranchProjection, JenkinsBuildNumber,
    JenkinsBuildProjection, JenkinsBuildResultScope, JenkinsBuildResultStatus,
    JenkinsCommitProjection, JenkinsControllerProjection, JenkinsCursor, JenkinsEndpoint,
    JenkinsFailureCode, JenkinsFolderProjection, JenkinsJobProjection, JenkinsModelError,
    JenkinsPermissionSnapshot, JenkinsReadOperation, JenkinsReadReceipt, JenkinsTestSummary,
    MAX_ARTIFACTS, MAX_JOBS, MAX_REQUESTS_PER_MINUTE, MAX_RESPONSE_BYTES, MAX_TEST_COUNT,
    TransportProvenance, digest_serializable, sha256_digest,
};
use crate::{
    JENKINS_API_REVISION, JENKINS_PROVIDER_ID, JENKINS_PROVIDER_IMPLEMENTATION,
    JENKINS_PROVIDER_VERSION,
};

/// The provider has exactly one HTTP method.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JenkinsHttpMethod {
    Get,
}

impl JenkinsHttpMethod {
    pub const fn as_str(self) -> &'static str {
        "GET"
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum JenkinsTransportError {
    #[error("BLOCKED_ENV: Jenkins native credentials and HTTPS transport are unavailable")]
    BlockedEnv,
    #[error("Jenkins access was lost")]
    AccessLost,
    #[error("Jenkins request was unauthorized")]
    Unauthorized,
    #[error("Jenkins request was forbidden")]
    Forbidden,
    #[error("Jenkins resource was not found")]
    NotFound,
    #[error("Jenkins request was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Jenkins transport timed out")]
    Timeout,
    #[error("Jenkins provider returned a server error")]
    Server { status: u16 },
    #[error("Jenkins response exceeded the Layer-1 response bound")]
    ResponseTooLarge,
    #[error("Jenkins response was malformed")]
    MalformedResponse,
    #[error("Jenkins request was not allowlisted")]
    RequestRejected,
    #[error("Jenkins response receipt was tampered")]
    ResponseTampered,
    #[error("Jenkins cursor did not match the exact scope")]
    CursorMismatch,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum JenkinsProviderError {
    #[error("Jenkins provider model error: {0}")]
    Model(#[from] JenkinsModelError),
    #[error("Jenkins provider transport error: {0}")]
    Transport(JenkinsTransportError),
    #[error("Jenkins provider definition is incompatible with the Layer-1 contract")]
    Incompatible,
    #[error("Jenkins provider scope does not match the request")]
    ScopeMismatch,
    #[error("Jenkins provider permission snapshot drifted")]
    PermissionMismatch,
    #[error("Jenkins provider revision drifted")]
    ProviderRevisionMismatch,
    #[error("Jenkins SecretReference is revoked")]
    SecretRevoked,
    #[error("Jenkins request was tampered")]
    RequestTampered,
    #[error("Jenkins response was tampered")]
    ResponseTampered,
    #[error("Jenkins response could not be normalized")]
    MalformedResponse,
    #[error("Jenkins provider request rate limit exceeded")]
    RateLimited { retry_after_seconds: u64 },
    #[error("Jenkins provider access was lost")]
    AccessLost,
    #[error("Jenkins provider is unavailable in BLOCKED_ENV")]
    BlockedEnv,
    #[error("Jenkins provider is unknown or unavailable")]
    ProviderUnknown,
}

impl JenkinsProviderError {
    pub const fn failure_code(&self) -> JenkinsFailureCode {
        match self {
            Self::BlockedEnv => JenkinsFailureCode::BlockedEnv,
            Self::AccessLost | Self::SecretRevoked => JenkinsFailureCode::AccessLost,
            Self::RateLimited { .. } => JenkinsFailureCode::RateLimited,
            Self::ResponseTampered => JenkinsFailureCode::ResponseTampered,
            Self::MalformedResponse => JenkinsFailureCode::MalformedResponse,
            Self::RequestTampered | Self::Incompatible => JenkinsFailureCode::RequestRejected,
            Self::ScopeMismatch | Self::ProviderRevisionMismatch | Self::PermissionMismatch => {
                JenkinsFailureCode::RequestRejected
            }
            Self::ProviderUnknown | Self::Transport(_) | Self::Model(_) => {
                JenkinsFailureCode::ProviderUnknown
            }
        }
    }
}

impl From<JenkinsTransportError> for JenkinsProviderError {
    fn from(error: JenkinsTransportError) -> Self {
        match error {
            JenkinsTransportError::BlockedEnv => Self::BlockedEnv,
            JenkinsTransportError::AccessLost
            | JenkinsTransportError::Unauthorized
            | JenkinsTransportError::Forbidden
            | JenkinsTransportError::NotFound => Self::AccessLost,
            JenkinsTransportError::RateLimited {
                retry_after_seconds,
            } => Self::RateLimited {
                retry_after_seconds: retry_after_seconds.unwrap_or(60),
            },
            JenkinsTransportError::ResponseTooLarge | JenkinsTransportError::MalformedResponse => {
                Self::MalformedResponse
            }
            JenkinsTransportError::ResponseTampered => Self::ResponseTampered,
            JenkinsTransportError::CursorMismatch => Self::ScopeMismatch,
            JenkinsTransportError::RequestRejected => Self::RequestTampered,
            JenkinsTransportError::Timeout | JenkinsTransportError::Server { .. } => {
                Self::ProviderUnknown
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsHttpRequest {
    pub operation: JenkinsReadOperation,
    pub method: JenkinsHttpMethod,
    pub origin: String,
    pub path_and_query: String,
    pub scope_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub redacted: bool,
}

impl fmt::Debug for JenkinsHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JenkinsHttpRequest")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("origin_digest", &sha256_digest(self.origin.as_bytes()))
            .field(
                "path_digest",
                &sha256_digest(self.path_and_query.as_bytes()),
            )
            .field("scope_digest", &self.scope_digest)
            .field("cursor_digest", &self.cursor_digest)
            .field("request_digest", &self.request_digest)
            .field("redacted", &self.redacted)
            .finish()
    }
}

#[derive(Clone)]
pub struct JenkinsHttpResponse {
    pub status: u16,
    pub body: Value,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provenance: TransportProvenance,
}

impl fmt::Debug for JenkinsHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JenkinsHttpResponse")
            .field("status", &self.status)
            .field("response_bytes", &self.response_bytes)
            .field("response_digest", &self.response_digest)
            .field("provenance", &self.provenance)
            .field("raw_body_retained", &false)
            .finish_non_exhaustive()
    }
}

impl JenkinsHttpResponse {
    pub fn new(
        status: u16,
        body: Value,
        provenance: TransportProvenance,
    ) -> Result<Self, JenkinsTransportError> {
        let canonical = canonical_json_bytes(&body);
        if canonical.len() > MAX_RESPONSE_BYTES {
            return Err(JenkinsTransportError::ResponseTooLarge);
        }
        Ok(Self {
            status,
            body,
            response_bytes: canonical.len(),
            response_digest: sha256_digest(&canonical),
            provenance,
        })
    }

    pub fn json(
        status: u16,
        body: &Value,
        provenance: TransportProvenance,
    ) -> Result<Self, JenkinsTransportError> {
        Self::new(status, body.clone(), provenance)
    }

    fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self
    }
}

pub trait JenkinsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn send(
        &mut self,
        request: &JenkinsHttpRequest,
    ) -> Result<JenkinsHttpResponse, JenkinsTransportError>;
}

#[derive(Clone, Debug)]
pub struct JenkinsProviderDefinition {
    pub id: String,
    pub implementation: String,
    pub version: String,
    pub api_revision: String,
    pub allowed_methods: Vec<JenkinsHttpMethod>,
    pub allowed_operations: Vec<JenkinsReadOperation>,
    pub permissions: JenkinsPermissionSnapshot,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub raw_response_body: bool,
    pub raw_artifacts: bool,
    pub raw_source: bool,
    pub raw_scripts: bool,
    pub provider_digest: Digest,
}

impl JenkinsProviderDefinition {
    pub fn baseline() -> Result<Self, JenkinsProviderError> {
        let permissions = JenkinsPermissionSnapshot::for_layer_one(1)?;
        let mut definition = Self {
            id: JENKINS_PROVIDER_ID.to_owned(),
            implementation: JENKINS_PROVIDER_IMPLEMENTATION.to_owned(),
            version: JENKINS_PROVIDER_VERSION.to_owned(),
            api_revision: JENKINS_API_REVISION.to_owned(),
            allowed_methods: vec![JenkinsHttpMethod::Get],
            allowed_operations: JenkinsReadOperation::ALL.to_vec(),
            permissions,
            native: false,
            connected: false,
            external_writes: false,
            raw_response_body: false,
            raw_artifacts: false,
            raw_source: false,
            raw_scripts: false,
            provider_digest: Digest::zero(),
        };
        definition.provider_digest = definition.recompute_digest();
        definition.validate()?;
        Ok(definition)
    }

    fn recompute_digest(&self) -> Digest {
        Digest::from_fields([
            self.id.as_str(),
            self.implementation.as_str(),
            self.version.as_str(),
            self.api_revision.as_str(),
            self.allowed_methods
                .iter()
                .map(|method| method.as_str())
                .collect::<Vec<_>>()
                .join(",")
                .as_str(),
            self.allowed_operations
                .iter()
                .map(|operation| operation.as_str())
                .collect::<Vec<_>>()
                .join(",")
                .as_str(),
            self.permissions.digest().as_str(),
            "native=false",
            "connected=false",
            "external_writes=false",
            "raw_response_body=false",
            "raw_artifacts=false",
            "raw_source=false",
            "raw_scripts=false",
        ])
    }

    pub fn validate(&self) -> Result<(), JenkinsProviderError> {
        let expected = JenkinsReadOperation::ALL.to_vec();
        if self.id != JENKINS_PROVIDER_ID
            || self.implementation != JENKINS_PROVIDER_IMPLEMENTATION
            || self.version != JENKINS_PROVIDER_VERSION
            || self.api_revision != JENKINS_API_REVISION
            || self.allowed_methods != [JenkinsHttpMethod::Get]
            || self.allowed_operations != expected
            || self.permissions.validate_exact().is_err()
            || self.native
            || self.connected
            || self.external_writes
            || self.raw_response_body
            || self.raw_artifacts
            || self.raw_source
            || self.raw_scripts
            || self.provider_digest != self.recompute_digest()
        {
            return Err(JenkinsProviderError::Incompatible);
        }
        Ok(())
    }

    pub fn permission_digest(&self) -> &Digest {
        self.permissions.digest()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JenkinsReadRequest {
    scope: JenkinsBuildResultScope,
    endpoint: JenkinsEndpoint,
    cursor: Option<JenkinsCursor>,
    request_digest: Digest,
}

impl JenkinsReadRequest {
    pub fn new(
        scope: &JenkinsBuildResultScope,
        endpoint: JenkinsEndpoint,
        cursor: Option<JenkinsCursor>,
    ) -> Result<Self, JenkinsProviderError> {
        scope.validate()?;
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate(scope)?;
        }
        if matches!(endpoint, JenkinsEndpoint::Branch) && scope.branch_name().is_none() {
            return Err(JenkinsProviderError::ScopeMismatch);
        }
        let path_and_query = path_and_query(scope, endpoint.operation());
        let request_digest = Digest::from_fields([
            endpoint.operation().as_str(),
            scope.controller().origin(),
            path_and_query.as_str(),
            scope.digest().as_str(),
            cursor
                .as_ref()
                .map_or("", |value| value.cursor_digest().as_str()),
            JENKINS_API_REVISION,
        ]);
        Ok(Self {
            scope: scope.clone(),
            endpoint,
            cursor,
            request_digest,
        })
    }

    pub fn for_operation(
        scope: &JenkinsBuildResultScope,
        operation: JenkinsReadOperation,
    ) -> Result<Self, JenkinsProviderError> {
        let endpoint = match operation {
            JenkinsReadOperation::ReadController => JenkinsEndpoint::Controller,
            JenkinsReadOperation::ReadFolder => JenkinsEndpoint::Folder,
            JenkinsReadOperation::ReadJob => JenkinsEndpoint::Job,
            JenkinsReadOperation::ReadBranch => JenkinsEndpoint::Branch,
            JenkinsReadOperation::ReadBuild => JenkinsEndpoint::Build,
            JenkinsReadOperation::ReadCommit => JenkinsEndpoint::Commit,
            JenkinsReadOperation::ReadTestSummary => JenkinsEndpoint::TestSummary,
            JenkinsReadOperation::ReadArtifactMetadata => JenkinsEndpoint::ArtifactMetadata,
        };
        Self::new(scope, endpoint, None)
    }

    pub fn scope(&self) -> &JenkinsBuildResultScope {
        &self.scope
    }

    pub const fn endpoint(&self) -> &JenkinsEndpoint {
        &self.endpoint
    }

    pub const fn operation(&self) -> JenkinsReadOperation {
        self.endpoint.operation()
    }

    pub fn cursor(&self) -> Option<&JenkinsCursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        path_and_query(&self.scope, self.operation())
    }

    pub fn http_request(&self) -> Result<JenkinsHttpRequest, JenkinsProviderError> {
        let path_and_query = self.path_and_query();
        Ok(JenkinsHttpRequest {
            operation: self.operation(),
            method: JenkinsHttpMethod::Get,
            origin: self.scope.controller().origin().to_owned(),
            path_and_query,
            scope_digest: self.scope.digest().clone(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.cursor_digest().clone()),
            request_digest: self.request_digest.clone(),
            redacted: true,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum JenkinsPayload {
    Controller(JenkinsControllerProjection),
    Folder(JenkinsFolderProjection),
    Job(JenkinsJobProjection),
    Branch(JenkinsBranchProjection),
    Build(JenkinsBuildProjection),
    Commit(JenkinsCommitProjection),
    TestSummary(JenkinsTestSummary),
    ArtifactMetadata(JenkinsArtifactMetadata),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JenkinsProviderRead {
    pub operation: JenkinsReadOperation,
    pub payload: JenkinsPayload,
    pub receipt: JenkinsReadReceipt,
    pub provenance: TransportProvenance,
}

impl JenkinsProviderRead {
    pub fn evidence_digest(&self) -> Result<Digest, JenkinsModelError> {
        digest_serializable(&(
            self.operation,
            &self.payload,
            &self.receipt,
            self.provenance,
        ))
    }
}

pub struct JenkinsProvider<T> {
    definition: JenkinsProviderDefinition,
    scope: JenkinsBuildResultScope,
    secret: crate::SecretReference,
    transport: T,
    window_started: Option<Instant>,
    requests_in_window: u8,
}

impl<T: fmt::Debug> fmt::Debug for JenkinsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JenkinsProvider")
            .field("definition", &self.definition)
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("transport", &self.transport)
            .field("window_started", &self.window_started)
            .field("requests_in_window", &self.requests_in_window)
            .finish()
    }
}

impl<T: JenkinsTransport> JenkinsProvider<T> {
    pub fn new(
        scope: JenkinsBuildResultScope,
        secret: crate::SecretReference,
        transport: T,
    ) -> Result<Self, JenkinsProviderError> {
        scope.validate()?;
        secret.validate_for_scope(&scope)?;
        let definition = JenkinsProviderDefinition::baseline()?;
        Ok(Self {
            definition,
            scope,
            secret,
            transport,
            window_started: None,
            requests_in_window: 0,
        })
    }

    pub fn definition(&self) -> &JenkinsProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.definition.provider_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        self.definition.permission_digest()
    }

    pub fn scope(&self) -> &JenkinsBuildResultScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &crate::SecretReference {
        &self.secret
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn read(
        &mut self,
        request: &JenkinsReadRequest,
    ) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        self.definition.validate()?;
        if self.secret.is_revoked() {
            return Err(JenkinsProviderError::SecretRevoked);
        }
        self.secret.validate_for_scope(&self.scope)?;
        if request.scope() != &self.scope {
            return Err(JenkinsProviderError::ScopeMismatch);
        }
        if !self
            .definition
            .allowed_operations
            .contains(&request.operation())
        {
            return Err(JenkinsProviderError::RequestTampered);
        }
        self.check_budget()?;
        let http_request = request.http_request()?;
        if !http_request.redacted
            || http_request.method != JenkinsHttpMethod::Get
            || http_request.scope_digest != *self.scope.digest()
            || http_request.request_digest != *request.request_digest()
        {
            return Err(JenkinsProviderError::RequestTampered);
        }
        let response = self
            .transport
            .send(&http_request)
            .map_err(JenkinsProviderError::from)?;
        self.validate_response(request, &http_request, &response)?;
        let payload = normalize_payload(request.operation(), &response.body, &self.scope)?;
        let receipt = JenkinsReadReceipt {
            operation: request.operation(),
            method: JenkinsHttpMethod::Get.as_str().to_owned(),
            path_digest: sha256_digest(http_request.path_and_query.as_bytes()),
            request_digest: request.request_digest().clone(),
            response_status: response.status,
            response_bytes: response.response_bytes,
            response_digest: response.response_digest.clone(),
            provider_digest: self.provider_digest().clone(),
            permission_digest: self.permission_digest().clone(),
            provenance: response.provenance,
            cursor_digest: http_request.cursor_digest.clone(),
            redacted: true,
        };
        Ok(JenkinsProviderRead {
            operation: request.operation(),
            payload,
            receipt,
            provenance: response.provenance,
        })
    }

    pub fn read_operation(
        &mut self,
        operation: JenkinsReadOperation,
    ) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        let request = JenkinsReadRequest::for_operation(&self.scope, operation)?;
        self.read(&request)
    }

    pub fn read_controller(&mut self) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        self.read_operation(JenkinsReadOperation::ReadController)
    }

    pub fn read_folder(&mut self) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        self.read_operation(JenkinsReadOperation::ReadFolder)
    }

    pub fn read_job(&mut self) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        self.read_operation(JenkinsReadOperation::ReadJob)
    }

    pub fn read_branch(&mut self) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        self.read_operation(JenkinsReadOperation::ReadBranch)
    }

    pub fn read_build(&mut self) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        self.read_operation(JenkinsReadOperation::ReadBuild)
    }

    pub fn read_commit(&mut self) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        self.read_operation(JenkinsReadOperation::ReadCommit)
    }

    pub fn read_test_summary(&mut self) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        self.read_operation(JenkinsReadOperation::ReadTestSummary)
    }

    pub fn read_artifact_metadata(&mut self) -> Result<JenkinsProviderRead, JenkinsProviderError> {
        self.read_operation(JenkinsReadOperation::ReadArtifactMetadata)
    }

    fn check_budget(&mut self) -> Result<(), JenkinsProviderError> {
        let now = Instant::now();
        if self
            .window_started
            .is_some_and(|started| started.elapsed() >= Duration::from_mins(1))
        {
            self.window_started = Some(now);
            self.requests_in_window = 0;
        } else if self.window_started.is_none() {
            self.window_started = Some(now);
        }
        if self.requests_in_window >= MAX_REQUESTS_PER_MINUTE {
            return Err(JenkinsProviderError::RateLimited {
                retry_after_seconds: 60,
            });
        }
        self.requests_in_window = self.requests_in_window.saturating_add(1);
        Ok(())
    }

    fn validate_response(
        &self,
        request: &JenkinsReadRequest,
        http_request: &JenkinsHttpRequest,
        response: &JenkinsHttpResponse,
    ) -> Result<(), JenkinsProviderError> {
        if response.provenance != self.provenance()
            || response.response_bytes > MAX_RESPONSE_BYTES
            || response.response_bytes != canonical_json_bytes(&response.body).len()
            || response.response_digest != sha256_digest(&canonical_json_bytes(&response.body))
            || http_request.method != JenkinsHttpMethod::Get
            || http_request.operation != request.operation()
            || http_request.path_and_query != request.path_and_query()
        {
            return Err(JenkinsProviderError::ResponseTampered);
        }
        if response.status != 200 {
            return Err(match response.status {
                401 | 403 | 404 => JenkinsProviderError::AccessLost,
                429 => JenkinsProviderError::RateLimited {
                    retry_after_seconds: 60,
                },
                400 => JenkinsProviderError::MalformedResponse,
                _ => JenkinsProviderError::ProviderUnknown,
            });
        }
        Ok(())
    }
}

fn operation_tree(operation: JenkinsReadOperation) -> &'static str {
    match operation {
        JenkinsReadOperation::ReadController => "jobs[name,url],views[name],mode",
        JenkinsReadOperation::ReadFolder => "jobs[name,url],views[name]",
        JenkinsReadOperation::ReadJob | JenkinsReadOperation::ReadBranch => {
            "name,fullName,lastBuild[number,result,building,timestamp,duration]"
        }
        JenkinsReadOperation::ReadBuild => {
            "number,result,building,queued,timestamp,duration,displayName,fullDisplayName,changeSet[items[commitId]],artifacts[fileName,relativePath,size]"
        }
        JenkinsReadOperation::ReadCommit => "changeSet[items[commitId]]",
        JenkinsReadOperation::ReadTestSummary => "failCount,skipCount,passCount,totalCount",
        JenkinsReadOperation::ReadArtifactMetadata => "artifacts[fileName,relativePath,size]",
    }
}

fn percent_encode_segment(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(byte as char);
        } else {
            output.push('%');
            let _ = write!(output, "{byte:02X}");
        }
    }
    output
}

fn job_path(scope: &JenkinsBuildResultScope, include_branch: bool) -> String {
    let mut path = String::new();
    for segment in scope.folder_path().segments() {
        path.push_str("/job/");
        path.push_str(&percent_encode_segment(segment));
    }
    path.push_str("/job/");
    path.push_str(&percent_encode_segment(scope.job_name().as_str()));
    if include_branch && let Some(branch) = scope.branch_name() {
        path.push_str("/job/");
        path.push_str(&percent_encode_segment(branch.as_str()));
    }
    path
}

fn path_and_query(scope: &JenkinsBuildResultScope, operation: JenkinsReadOperation) -> String {
    let path = match operation {
        JenkinsReadOperation::ReadController => "/api/json".to_owned(),
        JenkinsReadOperation::ReadFolder => {
            if scope.folder_path().segments().is_empty() {
                "/api/json".to_owned()
            } else {
                let mut path = String::new();
                for segment in scope.folder_path().segments() {
                    path.push_str("/job/");
                    path.push_str(&percent_encode_segment(segment));
                }
                path.push_str("/api/json");
                path
            }
        }
        JenkinsReadOperation::ReadJob => format!("{}/api/json", job_path(scope, false)),
        JenkinsReadOperation::ReadBranch => format!("{}/api/json", job_path(scope, true)),
        JenkinsReadOperation::ReadBuild
        | JenkinsReadOperation::ReadCommit
        | JenkinsReadOperation::ReadArtifactMetadata => format!(
            "{}/{}/api/json",
            job_path(scope, scope.branch_name().is_some()),
            scope.build_number().get()
        ),
        JenkinsReadOperation::ReadTestSummary => format!(
            "{}/{}/testReport/api/json",
            job_path(scope, scope.branch_name().is_some()),
            scope.build_number().get()
        ),
    };
    format!("{path}?tree={}", operation_tree(operation))
}

fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let canonical = canonicalize_json(value);
    serde_json::to_vec(&canonical).expect("canonical JSON value serializes")
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut ordered = Map::new();
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (key, value) in entries {
                ordered.insert(key.clone(), canonicalize_json(value));
            }
            Value::Object(ordered)
        }
        Value::Array(values) => {
            let mut canonical_values = values.iter().map(canonicalize_json).collect::<Vec<_>>();
            canonical_values.sort_by(|left, right| {
                let left = serde_json::to_vec(left).expect("canonical JSON value serializes");
                let right = serde_json::to_vec(right).expect("canonical JSON value serializes");
                left.cmp(&right)
            });
            Value::Array(canonical_values)
        }
        _ => value.clone(),
    }
}

fn value_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64)
}

fn test_count(value: Option<&Value>) -> Result<u32, JenkinsProviderError> {
    let count = value_u64(value).unwrap_or(0);
    if count > u64::from(MAX_TEST_COUNT) {
        return Err(JenkinsProviderError::MalformedResponse);
    }
    Ok(count as u32)
}

fn value_string(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn bounded_array(
    value: Option<&Value>,
    maximum: usize,
) -> Result<Vec<&Value>, JenkinsProviderError> {
    let Some(array) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    if array.len() > maximum {
        return Err(JenkinsProviderError::MalformedResponse);
    }
    Ok(array.iter().collect())
}

fn digest_strings(values: impl IntoIterator<Item = String>, prefix: &str) -> Digest {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    let fields = std::iter::once(prefix.to_owned()).chain(values);
    Digest::from_fields(fields)
}

fn commit_values(body: &Value) -> Vec<String> {
    let from_change_set = body
        .get("changeSet")
        .and_then(|value| value.get("items"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| value_string(item.get("commitId")))
        .map(str::to_owned);
    let from_actions = body
        .get("actions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|action| {
            action
                .get("lastBuiltRevision")
                .and_then(|revision| value_string(revision.get("SHA1")))
        })
        .map(str::to_owned);
    from_change_set.chain(from_actions).collect()
}

fn commit_digest(body: &Value) -> (Digest, u16) {
    let values = commit_values(body);
    let count = values.len().min(u16::MAX as usize) as u16;
    (
        digest_strings(values, "jenkins-commit-identifiers/v1"),
        count,
    )
}

fn artifact_digest(
    body: &Value,
) -> Result<(JenkinsArtifactMetadata, Digest), JenkinsProviderError> {
    let artifacts = bounded_array(body.get("artifacts"), MAX_ARTIFACTS)?;
    let mut entries = artifacts
        .iter()
        .map(|artifact| {
            (
                value_string(artifact.get("fileName"))
                    .unwrap_or("")
                    .to_owned(),
                value_string(artifact.get("relativePath"))
                    .unwrap_or("")
                    .to_owned(),
                value_u64(artifact.get("size")).unwrap_or(0),
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    let total_bytes = entries
        .iter()
        .map(|(_, _, size)| *size)
        .fold(0_u64, u64::saturating_add);
    let mut fields = Vec::with_capacity(entries.len() * 3 + 1);
    fields.push("jenkins-artifact-metadata/v1".to_owned());
    for (file_name, relative_path, size) in entries {
        fields.push(
            Digest::from_fields([file_name, relative_path])
                .as_str()
                .to_owned(),
        );
        fields.push(size.to_string());
    }
    let metadata_digest = Digest::from_fields(fields);
    let metadata =
        JenkinsArtifactMetadata::new(artifacts.len(), total_bytes, metadata_digest.clone())
            .map_err(JenkinsProviderError::from)?;
    Ok((metadata, metadata_digest))
}

fn status_from_object(body: &Value) -> JenkinsBuildResultStatus {
    JenkinsBuildResultStatus::from_wire(
        value_string(body.get("result")),
        body.get("building")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        body.get("queued").and_then(Value::as_bool).unwrap_or(false),
    )
}

fn build_projection(
    body: &Value,
    scope: &JenkinsBuildResultScope,
) -> Result<JenkinsBuildProjection, JenkinsProviderError> {
    let number = value_u64(body.get("number")).ok_or(JenkinsProviderError::MalformedResponse)?;
    let number = JenkinsBuildNumber::new(number).map_err(JenkinsProviderError::from)?;
    if number != scope.build_number() {
        return Err(JenkinsProviderError::ScopeMismatch);
    }
    let status = status_from_object(body);
    let branch_digest = value_string(body.get("branchName")).map(Digest::from_text);
    let (commit_digest, _) = commit_digest(body);
    let commit_digest = (!commit_values(body).is_empty()).then_some(commit_digest);
    let artifact_metadata_digest = if body.get("artifacts").is_some() {
        Some(artifact_digest(body)?.1)
    } else {
        None
    };
    let metadata_digest = digest_serializable(&(
        number,
        status,
        value_u64(body.get("timestamp")),
        value_u64(body.get("duration")),
        &branch_digest,
        &commit_digest,
        &artifact_metadata_digest,
    ))
    .map_err(JenkinsProviderError::from)?;
    Ok(JenkinsBuildProjection {
        build_number: number,
        status,
        timestamp_millis: value_u64(body.get("timestamp"))
            .and_then(|value| i64::try_from(value).ok()),
        duration_millis: value_u64(body.get("duration")),
        branch_digest,
        commit_digest,
        test_summary_digest: None,
        artifact_metadata_digest,
        metadata_digest,
    })
}

fn latest_build(
    value: Option<&Value>,
) -> Result<(Option<JenkinsBuildNumber>, Option<JenkinsBuildResultStatus>), JenkinsProviderError> {
    let Some(build) = value else {
        return Ok((None, None));
    };
    let number = value_u64(build.get("number"))
        .map(JenkinsBuildNumber::new)
        .transpose()
        .map_err(JenkinsProviderError::from)?;
    let status = number.map(|_| status_from_object(build));
    Ok((number, status))
}

fn normalize_payload(
    operation: JenkinsReadOperation,
    body: &Value,
    scope: &JenkinsBuildResultScope,
) -> Result<JenkinsPayload, JenkinsProviderError> {
    if !body.is_object() {
        return Err(JenkinsProviderError::MalformedResponse);
    }
    match operation {
        JenkinsReadOperation::ReadController => {
            let jobs = bounded_array(body.get("jobs"), MAX_JOBS)?;
            let folders = bounded_array(body.get("views"), MAX_JOBS)?;
            let version_digest = value_string(body.get("version")).map(Digest::from_text);
            let metadata_digest =
                digest_serializable(&(&version_digest, jobs.len(), folders.len()))
                    .map_err(JenkinsProviderError::from)?;
            Ok(JenkinsPayload::Controller(JenkinsControllerProjection {
                version_digest,
                job_count: jobs.len() as u16,
                folder_count: folders.len() as u16,
                metadata_digest,
            }))
        }
        JenkinsReadOperation::ReadFolder => {
            let jobs = bounded_array(body.get("jobs"), MAX_JOBS)?;
            let folders = bounded_array(body.get("views"), MAX_JOBS)?;
            let metadata_digest =
                digest_serializable(&(scope.folder_path().digest(), jobs.len(), folders.len()))
                    .map_err(JenkinsProviderError::from)?;
            Ok(JenkinsPayload::Folder(JenkinsFolderProjection {
                folder_digest: scope.folder_path().digest(),
                job_count: jobs.len() as u16,
                folder_count: folders.len() as u16,
                metadata_digest,
            }))
        }
        JenkinsReadOperation::ReadJob => {
            let branches = bounded_array(body.get("jobs"), MAX_JOBS)?;
            let (latest_build_number, latest_build_status) = latest_build(body.get("lastBuild"))?;
            let metadata_digest = digest_serializable(&(
                scope.job_name().as_str(),
                branches.len(),
                latest_build_number,
                latest_build_status,
            ))
            .map_err(JenkinsProviderError::from)?;
            Ok(JenkinsPayload::Job(JenkinsJobProjection {
                job_digest: Digest::from_text(scope.job_name().as_str()),
                branch_count: branches.len() as u16,
                latest_build_number,
                latest_build_status,
                metadata_digest,
            }))
        }
        JenkinsReadOperation::ReadBranch => {
            let branch = scope
                .branch_name()
                .ok_or(JenkinsProviderError::ScopeMismatch)?;
            let (latest_build_number, latest_build_status) = latest_build(body.get("lastBuild"))?;
            let (commit_digest, _) = commit_digest(body);
            let commit_digest = (!commit_values(body).is_empty()).then_some(commit_digest);
            let metadata_digest = digest_serializable(&(
                branch.as_str(),
                latest_build_number,
                latest_build_status,
                &commit_digest,
            ))
            .map_err(JenkinsProviderError::from)?;
            Ok(JenkinsPayload::Branch(JenkinsBranchProjection {
                branch_digest: Digest::from_text(branch.as_str()),
                latest_build_number,
                latest_build_status,
                commit_digest,
                metadata_digest,
            }))
        }
        JenkinsReadOperation::ReadBuild => {
            Ok(JenkinsPayload::Build(build_projection(body, scope)?))
        }
        JenkinsReadOperation::ReadCommit => {
            let (commit_digest, commit_count) = commit_digest(body);
            let metadata_digest =
                digest_serializable(&(&commit_digest, commit_count, scope.build_number()))
                    .map_err(JenkinsProviderError::from)?;
            Ok(JenkinsPayload::Commit(JenkinsCommitProjection {
                commit_digest,
                commit_count,
                metadata_digest,
            }))
        }
        JenkinsReadOperation::ReadTestSummary => {
            let passed = test_count(body.get("passCount"))?;
            let failed = test_count(body.get("failCount"))?;
            let skipped = test_count(body.get("skipCount"))?;
            if let Some(total) = value_u64(body.get("totalCount"))
                && total != u64::from(passed) + u64::from(failed) + u64::from(skipped)
            {
                return Err(JenkinsProviderError::MalformedResponse);
            }
            Ok(JenkinsPayload::TestSummary(
                JenkinsTestSummary::new(passed, failed, skipped)
                    .map_err(JenkinsProviderError::from)?,
            ))
        }
        JenkinsReadOperation::ReadArtifactMetadata => {
            Ok(JenkinsPayload::ArtifactMetadata(artifact_digest(body)?.0))
        }
    }
}

#[derive(Clone, Debug)]
pub struct FixtureJenkinsTransport {
    responses: BTreeMap<JenkinsReadOperation, JenkinsHttpResponse>,
    fallback: Option<JenkinsHttpResponse>,
}

impl FixtureJenkinsTransport {
    pub fn new(response: JenkinsHttpResponse) -> Self {
        Self {
            responses: BTreeMap::new(),
            fallback: Some(response.with_provenance(TransportProvenance::Fixture)),
        }
    }

    pub fn from_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = (JenkinsReadOperation, JenkinsHttpResponse)>,
    {
        Self {
            responses: responses
                .into_iter()
                .map(|(operation, response)| {
                    (
                        operation,
                        response.with_provenance(TransportProvenance::Fixture),
                    )
                })
                .collect(),
            fallback: None,
        }
    }

    #[must_use]
    pub fn with_response(
        mut self,
        operation: JenkinsReadOperation,
        response: JenkinsHttpResponse,
    ) -> Self {
        self.responses.insert(
            operation,
            response.with_provenance(TransportProvenance::Fixture),
        );
        self
    }

    pub fn for_scope(scope: &JenkinsBuildResultScope) -> Result<Self, JenkinsTransportError> {
        let commit = scope.commit_sha().map_or(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            CommitSha::as_str,
        );
        let build = scope.build_number().get();
        let mut transport = Self::from_responses(Vec::new());
        let bodies = [
            (
                JenkinsReadOperation::ReadController,
                json!({"version":"2.452.3","jobs":[{"name":"fixture-job"}],"views":[{"name":"fixture-folder"}]}),
            ),
            (
                JenkinsReadOperation::ReadFolder,
                json!({"jobs":[{"name":scope.job_name().as_str()}],"views":[]}),
            ),
            (
                JenkinsReadOperation::ReadJob,
                json!({"name":scope.job_name().as_str(),"jobs":[{"name":scope.branch_name().map_or("main", |value| value.as_str())}],"lastBuild":{"number":build,"result":"SUCCESS","building":false}}),
            ),
            (
                JenkinsReadOperation::ReadBranch,
                json!({"name":scope.branch_name().map_or("main", |value| value.as_str()),"lastBuild":{"number":build,"result":"SUCCESS","building":false},"changeSet":{"items":[{"commitId":commit}]}}),
            ),
            (
                JenkinsReadOperation::ReadBuild,
                json!({"number":build,"result":"SUCCESS","building":false,"timestamp":1_787_000_000_000_u64,"duration":1200,"changeSet":{"items":[{"commitId":commit}]},"artifacts":[{"fileName":"result.json","relativePath":"result.json","size":128}]}),
            ),
            (
                JenkinsReadOperation::ReadCommit,
                json!({"changeSet":{"items":[{"commitId":commit}]}}),
            ),
            (
                JenkinsReadOperation::ReadTestSummary,
                json!({"passCount":10,"failCount":0,"skipCount":1,"totalCount":11}),
            ),
            (
                JenkinsReadOperation::ReadArtifactMetadata,
                json!({"artifacts":[{"fileName":"result.json","relativePath":"result.json","size":128}]}),
            ),
        ];
        for (operation, body) in bodies {
            let response = JenkinsHttpResponse::new(200, body, TransportProvenance::Fixture)?;
            transport = transport.with_response(operation, response);
        }
        Ok(transport)
    }
}

impl JenkinsTransport for FixtureJenkinsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn send(
        &mut self,
        request: &JenkinsHttpRequest,
    ) -> Result<JenkinsHttpResponse, JenkinsTransportError> {
        self.responses
            .get(&request.operation)
            .or(self.fallback.as_ref())
            .cloned()
            .ok_or(JenkinsTransportError::NotFound)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingJenkinsTransport {
    responses: BTreeMap<
        JenkinsReadOperation,
        VecDeque<Result<JenkinsHttpResponse, JenkinsTransportError>>,
    >,
    requests: Vec<JenkinsHttpRequest>,
}

impl RecordingJenkinsTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(
        &mut self,
        operation: JenkinsReadOperation,
        response: Result<JenkinsHttpResponse, JenkinsTransportError>,
    ) {
        self.responses
            .entry(operation)
            .or_default()
            .push_back(response.map(|value| value.with_provenance(TransportProvenance::Recording)));
    }

    pub fn requests(&self) -> &[JenkinsHttpRequest] {
        &self.requests
    }
}

impl JenkinsTransport for RecordingJenkinsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn send(
        &mut self,
        request: &JenkinsHttpRequest,
    ) -> Result<JenkinsHttpResponse, JenkinsTransportError> {
        self.requests.push(request.clone());
        self.responses
            .get_mut(&request.operation)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Err(JenkinsTransportError::NotFound))
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackJenkinsTransport {
    responses: BTreeMap<
        JenkinsReadOperation,
        VecDeque<Result<JenkinsHttpResponse, JenkinsTransportError>>,
    >,
    requests: Vec<JenkinsHttpRequest>,
}

impl LoopbackJenkinsTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(
        &mut self,
        operation: JenkinsReadOperation,
        response: Result<JenkinsHttpResponse, JenkinsTransportError>,
    ) {
        self.responses
            .entry(operation)
            .or_default()
            .push_back(response.map(|value| value.with_provenance(TransportProvenance::Loopback)));
    }

    pub fn requests(&self) -> &[JenkinsHttpRequest] {
        &self.requests
    }
}

impl JenkinsTransport for LoopbackJenkinsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn send(
        &mut self,
        request: &JenkinsHttpRequest,
    ) -> Result<JenkinsHttpResponse, JenkinsTransportError> {
        self.requests.push(request.clone());
        self.responses
            .get_mut(&request.operation)
            .and_then(VecDeque::pop_front)
            .unwrap_or(Err(JenkinsTransportError::NotFound))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvJenkinsTransport;

impl JenkinsTransport for BlockedEnvJenkinsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn send(
        &mut self,
        _request: &JenkinsHttpRequest,
    ) -> Result<JenkinsHttpResponse, JenkinsTransportError> {
        Err(JenkinsTransportError::BlockedEnv)
    }
}

pub type BlockedEnvTransport = BlockedEnvJenkinsTransport;
pub type FixtureTransport = FixtureJenkinsTransport;
pub type RecordingTransport = RecordingJenkinsTransport;
pub type LoopbackTransport = LoopbackJenkinsTransport;
