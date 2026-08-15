use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

use crate::error::{ArgoCdDeploymentError, ArgoCdTransportError, Result};
use crate::model::{
    ArgoCdDeploymentScope, ArgoFixtureSet, Digest, MAX_RESPONSE_BYTES, MAX_RETRY_ATTEMPTS,
    ProviderProvenance,
};

/// The only provider operations admitted by the Layer-1 Argo CD boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgoCdOperation {
    ReadApplication,
    ReadResourceTree,
    ReadSyncStatus,
    ReadOperation,
}

impl ArgoCdOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadApplication => "read_application",
            Self::ReadResourceTree => "read_resource_tree",
            Self::ReadSyncStatus => "read_sync_status",
            Self::ReadOperation => "read_operation",
        }
    }

    #[must_use]
    pub const fn is_read(self) -> bool {
        true
    }
}

/// Redacted GET request envelope. The raw URL is available only to the
/// deterministic transport implementation and is never serialized or debug
/// printed by this type.
#[derive(Clone, Eq, PartialEq)]
pub struct ArgoCdRequest {
    operation: ArgoCdOperation,
    method: String,
    path: String,
    scope_digest: Digest,
    path_digest: Digest,
    request_digest: Digest,
}

impl fmt::Debug for ArgoCdRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArgoCdRequest")
            .field("operation", &self.operation)
            .field("method", &self.method)
            .field("scope_digest", &self.scope_digest)
            .field("path_digest", &self.path_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for ArgoCdRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ArgoCdRequest", 5)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("pathDigest", &self.path_digest)?;
        state.serialize_field("requestDigest", &self.request_digest)?;
        state.end()
    }
}

impl ArgoCdRequest {
    pub(crate) fn for_scope(scope: &ArgoCdDeploymentScope, operation: ArgoCdOperation) -> Self {
        let application = scope.application().as_str();
        let project = scope.project().as_str();
        let suffix = match operation {
            ArgoCdOperation::ReadApplication => "",
            ArgoCdOperation::ReadResourceTree => "/resource-tree",
            ArgoCdOperation::ReadSyncStatus => "/sync",
            ArgoCdOperation::ReadOperation => "/operation",
        };
        let path = format!("/api/v1/applications/{application}{suffix}?project={project}");
        let path_digest = Digest::from_text(path.as_bytes());
        let request_digest = Digest::from_parts(
            "argocd-request/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("method", "GET".to_owned()),
                ("path", path_digest.as_str().to_owned()),
                ("scope", scope.digest().as_str().to_owned()),
            ],
        );
        Self {
            operation,
            method: "GET".to_owned(),
            path,
            scope_digest: scope.digest(),
            path_digest,
            request_digest,
        }
    }

    #[must_use]
    pub const fn operation(&self) -> ArgoCdOperation {
        self.operation
    }

    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn path_digest(&self) -> &Digest {
        &self.path_digest
    }

    #[must_use]
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    #[must_use]
    pub fn is_get(&self) -> bool {
        self.method == "GET"
    }

    #[must_use]
    pub fn is_allowlisted(&self) -> bool {
        self.is_get()
            && self.operation.is_read()
            && self.path.starts_with("/api/v1/applications/")
            && match self.operation {
                ArgoCdOperation::ReadApplication => self.path.contains("?project="),
                ArgoCdOperation::ReadResourceTree => self.path.contains("/resource-tree?project="),
                ArgoCdOperation::ReadSyncStatus => self.path.contains("/sync?project="),
                ArgoCdOperation::ReadOperation => self.path.contains("/operation?project="),
            }
    }
}

/// Response envelope with a bounded body and an optional declared digest.
/// The body is never serialized or included in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct ArgoCdResponse {
    status: u16,
    body: Vec<u8>,
    response_digest: Digest,
    declared_digest: Digest,
}

impl fmt::Debug for ArgoCdResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArgoCdResponse")
            .field("status", &self.status)
            .field("response_bytes", &self.body.len())
            .field("response_digest", &self.response_digest)
            .field("declared_digest", &self.declared_digest)
            .finish()
    }
}

impl Serialize for ArgoCdResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ArgoCdResponse", 4)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("responseBytes", &self.body.len())?;
        state.serialize_field("responseDigest", &self.response_digest)?;
        state.serialize_field("declaredDigest", &self.declared_digest)?;
        state.end()
    }
}

impl ArgoCdResponse {
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        let response_digest = Digest::from_bytes(&body);
        Self {
            status,
            body,
            declared_digest: response_digest.clone(),
            response_digest,
        }
    }

    pub fn json<T: serde::Serialize>(status: u16, value: &T) -> Result<Self> {
        serde_json::to_vec(value)
            .map(|body| Self::new(status, body))
            .map_err(|_| ArgoCdDeploymentError::InvalidResponse)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, declared_digest: Digest) -> Self {
        self.declared_digest = declared_digest;
        self
    }

    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    #[must_use]
    pub fn response_bytes(&self) -> usize {
        self.body.len()
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        self.response_digest.clone()
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn validate_size_and_digest(&self) -> Result<()> {
        if self.body.len() > MAX_RESPONSE_BYTES {
            return Err(ArgoCdDeploymentError::ResponseTooLarge);
        }
        if self.response_digest != Digest::from_bytes(&self.body)
            || self.declared_digest != self.response_digest
        {
            return Err(ArgoCdDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

pub trait ArgoCdTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn execute(
        &mut self,
        request: &ArgoCdRequest,
    ) -> std::result::Result<ArgoCdResponse, ArgoCdTransportError>;
}

#[derive(Clone, Debug)]
struct ScriptedEntry {
    operation: Option<ArgoCdOperation>,
    result: std::result::Result<ArgoCdResponse, ArgoCdTransportError>,
}

#[derive(Clone, Debug, Default)]
struct QueueState {
    entries: VecDeque<ScriptedEntry>,
    fallback: Option<std::result::Result<ArgoCdResponse, ArgoCdTransportError>>,
    requests: Vec<ArgoCdRequest>,
}

impl QueueState {
    fn from_scope(scope: &ArgoCdDeploymentScope) -> Result<Self> {
        let fixtures = ArgoFixtureSet::for_scope(scope);
        let mut state = Self::default();
        state.push_operation(
            ArgoCdOperation::ReadApplication,
            Ok(ArgoCdResponse::json(200, &fixtures.application)?),
        );
        state.push_operation(
            ArgoCdOperation::ReadResourceTree,
            Ok(ArgoCdResponse::json(200, &fixtures.resource_tree)?),
        );
        state.push_operation(
            ArgoCdOperation::ReadSyncStatus,
            Ok(ArgoCdResponse::json(200, &fixtures.sync_status)?),
        );
        state.push_operation(
            ArgoCdOperation::ReadOperation,
            Ok(ArgoCdResponse::json(200, &fixtures.operation)?),
        );
        Ok(state)
    }

    fn push(
        &mut self,
        operation: Option<ArgoCdOperation>,
        result: std::result::Result<ArgoCdResponse, ArgoCdTransportError>,
    ) {
        self.entries.push_back(ScriptedEntry { operation, result });
    }

    fn push_operation(
        &mut self,
        operation: ArgoCdOperation,
        result: std::result::Result<ArgoCdResponse, ArgoCdTransportError>,
    ) {
        self.push(Some(operation), result);
    }

    fn take(
        &mut self,
        request: &ArgoCdRequest,
    ) -> std::result::Result<ArgoCdResponse, ArgoCdTransportError> {
        self.requests.push(request.clone());
        let index = self.entries.iter().position(|entry| {
            entry.operation.is_none() || entry.operation == Some(request.operation())
        });
        if let Some(index) = index {
            return self
                .entries
                .remove(index)
                .expect("position identifies a queue entry")
                .result;
        }
        self.fallback
            .clone()
            .unwrap_or(Err(ArgoCdTransportError::ProviderUnknown))
    }
}

macro_rules! scripted_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            state: QueueState,
        }

        impl $name {
            #[must_use]
            pub fn new(response: ArgoCdResponse) -> Self {
                let mut state = QueueState::default();
                state.fallback = Some(Ok(response));
                Self { state }
            }

            pub fn push_response(&mut self, response: ArgoCdResponse) {
                self.state.push(None, Ok(response));
            }

            pub fn push_error(&mut self, error: ArgoCdTransportError) {
                self.state.push(None, Err(error));
            }

            pub fn push_operation_response(
                &mut self,
                operation: ArgoCdOperation,
                response: ArgoCdResponse,
            ) {
                self.state.push_operation(operation, Ok(response));
            }

            pub fn push_operation_error(
                &mut self,
                operation: ArgoCdOperation,
                error: ArgoCdTransportError,
            ) {
                self.state.push_operation(operation, Err(error));
            }

            #[must_use]
            pub fn requests(&self) -> &[ArgoCdRequest] {
                &self.state.requests
            }
        }

        impl ArgoCdTransport for $name {
            fn provenance(&self) -> ProviderProvenance {
                $provenance
            }

            fn execute(
                &mut self,
                request: &ArgoCdRequest,
            ) -> std::result::Result<ArgoCdResponse, ArgoCdTransportError> {
                self.state.take(request)
            }
        }
    };
}

scripted_transport!(RecordingTransport, ProviderProvenance::Recording);
scripted_transport!(FixtureTransport, ProviderProvenance::Fixture);
scripted_transport!(FakeTransport, ProviderProvenance::Fake);
scripted_transport!(LoopbackTransport, ProviderProvenance::Loopback);

impl RecordingTransport {
    #[must_use]
    pub fn from_responses<I>(responses: I) -> Self
    where
        I: IntoIterator<Item = ArgoCdResponse>,
    {
        let mut transport = Self::default();
        for response in responses {
            transport.push_response(response);
        }
        transport
    }
}

impl FixtureTransport {
    pub fn for_scope(scope: &ArgoCdDeploymentScope) -> Result<Self> {
        Ok(Self {
            state: QueueState::from_scope(scope)?,
        })
    }
}

impl FakeTransport {
    pub fn for_scope(scope: &ArgoCdDeploymentScope) -> Result<Self> {
        Ok(Self {
            state: QueueState::from_scope(scope)?,
        })
    }
}

impl LoopbackTransport {
    pub fn for_scope(scope: &ArgoCdDeploymentScope) -> Result<Self> {
        Ok(Self {
            state: QueueState::from_scope(scope)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl ArgoCdTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &ArgoCdRequest,
    ) -> std::result::Result<ArgoCdResponse, ArgoCdTransportError> {
        Err(ArgoCdTransportError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub base_backoff_seconds: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: MAX_RETRY_ATTEMPTS,
            base_backoff_seconds: 1,
        }
    }
}

impl RetryPolicy {
    #[must_use]
    pub fn backoff_seconds(self, attempt: u8) -> u32 {
        self.base_backoff_seconds
            .saturating_mul(u32::from(attempt))
            .min(crate::model::MAX_BACKOFF_SECONDS)
    }
}
