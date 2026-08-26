//! Bounded, transport-agnostic AWS ECS provider seam.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver, HTTP
//! client or arbitrary operation escape hatch in this module. A transport can
//! only provide normalized pages for the four allowlisted read operations.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_ECS_API_REVISION, AWS_ECS_API_VERSION, AWS_ECS_CONTRACT_JSON, AWS_ECS_PROVIDER_ID,
    AWS_ECS_PROVIDER_VERSION,
    model::{
        DescribeServicesPage, DescribeServicesRequest, DescribeTaskDefinitionPage,
        DescribeTaskDefinitionRequest, DescribeTasksPage, DescribeTasksRequest, Digest,
        ListTasksPage, ListTasksRequest, ModelError, ProviderErrorEvidence, ProviderErrorKind,
        ProviderRevision, ReadOperation, TransportProvenance,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn native(self) -> bool {
        false
    }

    pub const fn connected(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn as_transport(self) -> TransportProvenance {
        match self {
            Self::Fixture => TransportProvenance::Fixture,
            Self::Recording => TransportProvenance::Recording,
            Self::Loopback => TransportProvenance::Loopback,
            Self::BlockedEnv => TransportProvenance::BlockedEnv,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportFailure {
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    Server,
    Timeout,
    BlockedEnv,
    Malformed,
}

impl TransportFailure {
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::Server => Some(500),
            Self::Timeout | Self::BlockedEnv | Self::Malformed => None,
        }
    }

    pub const fn from_status(status: u16) -> Self {
        match status {
            401 => Self::Unauthorized,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            400 | 402 | 405..=408 => Self::BadRequest,
            409 => Self::Conflict,
            429 => Self::Throttled,
            500..=599 => Self::Server,
            _ => Self::Malformed,
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(self, Self::Throttled | Self::Server | Self::Timeout)
    }

    pub const fn kind(self) -> ProviderErrorKind {
        match self {
            Self::BadRequest => ProviderErrorKind::BadRequest,
            Self::Unauthorized => ProviderErrorKind::Unauthorized,
            Self::AccessDenied => ProviderErrorKind::AccessDenied,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::Conflict => ProviderErrorKind::Conflict,
            Self::Throttled => ProviderErrorKind::Throttled,
            Self::Server => ProviderErrorKind::Server,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::BlockedEnv => ProviderErrorKind::BlockedEnv,
            Self::Malformed => ProviderErrorKind::Malformed,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("AWS ECS transport failure: {failure:?}")]
#[serde(rename_all = "camelCase")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
    pub retry_after_seconds: Option<u64>,
}

impl TransportError {
    pub fn new(failure: TransportFailure) -> Self {
        Self {
            status_code: failure.status_code(),
            error_digest: Digest::from_text(match failure {
                TransportFailure::BadRequest => "400",
                TransportFailure::Unauthorized => "401",
                TransportFailure::AccessDenied => "403",
                TransportFailure::NotFound => "404",
                TransportFailure::Conflict => "409",
                TransportFailure::Throttled => "429",
                TransportFailure::Server => "5xx",
                TransportFailure::Timeout => "timeout",
                TransportFailure::BlockedEnv => "BLOCKED_ENV",
                TransportFailure::Malformed => "malformed",
            }),
            failure,
            retry_after_seconds: None,
        }
    }

    pub fn from_status(status: u16) -> Self {
        Self::new(TransportFailure::from_status(status))
    }

    pub fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        Self {
            retry_after_seconds,
            ..Self::new(TransportFailure::Throttled)
        }
    }

    pub fn timeout() -> Self {
        Self::new(TransportFailure::Timeout)
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv)
    }

    pub fn malformed() -> Self {
        Self::new(TransportFailure::Malformed)
    }

    pub const fn retryable(&self) -> bool {
        self.failure.retryable()
    }

    pub fn evidence(&self) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            kind: self.failure.kind(),
            status_code: self.status_code,
            error_digest: self.error_digest.clone(),
            retryable: self.retryable(),
        }
    }
}

pub fn is_access_loss(error: &TransportError) -> bool {
    matches!(
        error.failure,
        TransportFailure::Unauthorized | TransportFailure::AccessDenied
    )
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EcsProviderError {
    #[error(transparent)]
    Transport(TransportError),
    #[error(transparent)]
    Model(ModelError),
    #[error("ECS provider page binding is invalid")]
    PageBinding,
    #[error("ECS provider revision is incompatible")]
    ProviderRevision,
    #[error("ECS provider response contains a duplicate normalized item")]
    DuplicateItem,
    #[error("ECS provider request is not allowed by the typed provider")]
    RequestNotAllowed,
}

impl From<TransportError> for EcsProviderError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<ModelError> for EcsProviderError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

impl EcsProviderError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Transport(error) => error.status_code,
            _ => None,
        }
    }

    pub const fn transport_failure(&self) -> Option<TransportFailure> {
        match self {
            Self::Transport(error) => Some(error.failure),
            _ => None,
        }
    }
}

pub trait EcsTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn describe_services(
        &mut self,
        request: &DescribeServicesRequest,
    ) -> Result<DescribeServicesPage, TransportError>;

    fn describe_tasks(
        &mut self,
        request: &DescribeTasksRequest,
    ) -> Result<DescribeTasksPage, TransportError>;

    fn describe_task_definition(
        &mut self,
        request: &DescribeTaskDefinitionRequest,
    ) -> Result<DescribeTaskDefinitionPage, TransportError>;

    fn list_tasks(&mut self, request: &ListTasksRequest) -> Result<ListTasksPage, TransportError>;
}

pub trait EcsProviderTransport: EcsTransport {}

impl<T: EcsTransport> EcsProviderTransport for T {}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

pub type BlockedEnvEcsTransport = BlockedEnvTransport;

impl EcsTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn describe_services(
        &mut self,
        _request: &DescribeServicesRequest,
    ) -> Result<DescribeServicesPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn describe_tasks(
        &mut self,
        _request: &DescribeTasksRequest,
    ) -> Result<DescribeTasksPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn describe_task_definition(
        &mut self,
        _request: &DescribeTaskDefinitionRequest,
    ) -> Result<DescribeTaskDefinitionPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn list_tasks(&mut self, _request: &ListTasksRequest) -> Result<ListTasksPage, TransportError> {
        Err(TransportError::blocked_env())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportCall {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
}

#[derive(Clone, Debug)]
pub struct RecordingEcsTransport {
    provenance: ProviderProvenance,
    describe_services: VecDeque<Result<DescribeServicesPage, TransportError>>,
    describe_tasks: VecDeque<Result<DescribeTasksPage, TransportError>>,
    describe_task_definition: VecDeque<Result<DescribeTaskDefinitionPage, TransportError>>,
    list_tasks: VecDeque<Result<ListTasksPage, TransportError>>,
    calls: Vec<TransportCall>,
}

pub type FixtureEcsTransport = RecordingEcsTransport;
pub type LoopbackEcsTransport = RecordingEcsTransport;
pub type RecordingAwsEcsTransport = RecordingEcsTransport;
pub type FixtureAwsEcsTransport = RecordingEcsTransport;

impl Default for RecordingEcsTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingEcsTransport {
    pub fn new() -> Self {
        Self {
            provenance: ProviderProvenance::Recording,
            describe_services: VecDeque::new(),
            describe_tasks: VecDeque::new(),
            describe_task_definition: VecDeque::new(),
            list_tasks: VecDeque::new(),
            calls: Vec::new(),
        }
    }

    pub fn fixture() -> Self {
        Self {
            provenance: ProviderProvenance::Fixture,
            ..Self::new()
        }
    }

    pub fn loopback() -> Self {
        Self {
            provenance: ProviderProvenance::Loopback,
            ..Self::new()
        }
    }

    pub fn queue_describe_services(
        &mut self,
        response: Result<DescribeServicesPage, TransportError>,
    ) {
        self.describe_services.push_back(response);
    }

    pub fn queue_describe_tasks(&mut self, response: Result<DescribeTasksPage, TransportError>) {
        self.describe_tasks.push_back(response);
    }

    pub fn queue_describe_task_definition(
        &mut self,
        response: Result<DescribeTaskDefinitionPage, TransportError>,
    ) {
        self.describe_task_definition.push_back(response);
    }

    pub fn queue_list_tasks(&mut self, response: Result<ListTasksPage, TransportError>) {
        self.list_tasks.push_back(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    pub fn clear_calls(&mut self) {
        self.calls.clear();
    }

    fn record_call(
        &mut self,
        operation: ReadOperation,
        request_digest: Digest,
        cursor_digest: Option<Digest>,
    ) {
        self.calls.push(TransportCall {
            operation,
            request_digest,
            cursor_digest,
        });
    }

    fn missing_response() -> TransportError {
        TransportError::malformed()
    }
}

impl EcsTransport for RecordingEcsTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn describe_services(
        &mut self,
        request: &DescribeServicesRequest,
    ) -> Result<DescribeServicesPage, TransportError> {
        self.record_call(
            ReadOperation::DescribeServices,
            request.request_digest(),
            None,
        );
        self.describe_services
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn describe_tasks(
        &mut self,
        request: &DescribeTasksRequest,
    ) -> Result<DescribeTasksPage, TransportError> {
        self.record_call(ReadOperation::DescribeTasks, request.request_digest(), None);
        self.describe_tasks
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn describe_task_definition(
        &mut self,
        request: &DescribeTaskDefinitionRequest,
    ) -> Result<DescribeTaskDefinitionPage, TransportError> {
        self.record_call(
            ReadOperation::DescribeTaskDefinition,
            request.request_digest(),
            None,
        );
        self.describe_task_definition
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn list_tasks(&mut self, request: &ListTasksRequest) -> Result<ListTasksPage, TransportError> {
        self.record_call(
            ReadOperation::ListTasks,
            request.request_digest(),
            request.cursor.as_ref().map(crate::OpaqueCursor::digest),
        );
        self.list_tasks
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsProviderIdentity {
    pub provider_id: String,
    pub api_version: String,
    pub provider_version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub contract_digest: Digest,
    pub provenance: ProviderProvenance,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

pub type EcsProviderDefinition = EcsProviderIdentity;

impl EcsProviderIdentity {
    pub fn for_provenance(provenance: ProviderProvenance) -> Result<Self, EcsProviderError> {
        let api_revision = ProviderRevision::new(AWS_ECS_API_REVISION)?;
        let api_digest = Digest::from_parts(
            "aws-ecs-api-allowlist/v1",
            &[
                "DescribeServices".to_owned(),
                "DescribeTasks".to_owned(),
                "DescribeTaskDefinition".to_owned(),
                "ListTasks".to_owned(),
                AWS_ECS_API_VERSION.to_owned(),
            ],
        );
        let provider_digest = Digest::from_parts(
            "aws-ecs-provider/v1",
            &[
                AWS_ECS_PROVIDER_ID.to_owned(),
                AWS_ECS_PROVIDER_VERSION.to_owned(),
                api_revision.as_str().to_owned(),
                api_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            provider_id: AWS_ECS_PROVIDER_ID.to_owned(),
            api_version: AWS_ECS_API_VERSION.to_owned(),
            provider_version: AWS_ECS_PROVIDER_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            contract_digest: Digest::from_text(AWS_ECS_CONTRACT_JSON),
            provenance,
            native: false,
            connected: false,
            first_party: false,
        })
    }
}

#[derive(Clone)]
pub struct EcsProvider<T> {
    transport: T,
    identity: EcsProviderIdentity,
    last_retry_count: u8,
}

impl<T: EcsTransport> fmt::Debug for EcsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EcsProvider")
            .field("provider_id", &self.identity.provider_id)
            .field("api_revision", &self.identity.api_revision)
            .field("provider_digest", &self.identity.provider_digest)
            .field("api_digest", &self.identity.api_digest)
            .field("provenance", &self.identity.provenance)
            .finish_non_exhaustive()
    }
}

impl Default for EcsProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("static ECS provider identity")
    }
}

impl<T: EcsTransport> EcsProvider<T> {
    pub fn new(transport: T) -> Result<Self, EcsProviderError> {
        let identity = EcsProviderIdentity::for_provenance(transport.provenance())?;
        Ok(Self {
            transport,
            identity,
            last_retry_count: 0,
        })
    }

    pub fn identity(&self) -> &EcsProviderIdentity {
        &self.identity
    }

    pub fn definition(&self) -> &EcsProviderIdentity {
        &self.identity
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.identity.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn last_retry_count(&self) -> u8 {
        self.last_retry_count
    }

    fn record_retry(&mut self) {
        self.last_retry_count = self.last_retry_count.saturating_add(1);
    }

    pub fn describe_services(
        &mut self,
        request: &DescribeServicesRequest,
    ) -> Result<DescribeServicesPage, EcsProviderError> {
        self.last_retry_count = 0;
        loop {
            match self.transport.describe_services(request) {
                Ok(page) => {
                    page.validate_for(request)
                        .map_err(|_| EcsProviderError::PageBinding)?;
                    self.ensure_revision(&page.provider_revision)?;
                    return Ok(page);
                }
                Err(error)
                    if error.retryable() && self.last_retry_count < request.bounds.max_retries =>
                {
                    self.record_retry();
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn describe_tasks(
        &mut self,
        request: &DescribeTasksRequest,
    ) -> Result<DescribeTasksPage, EcsProviderError> {
        self.last_retry_count = 0;
        loop {
            match self.transport.describe_tasks(request) {
                Ok(page) => {
                    page.validate_for(request)
                        .map_err(|_| EcsProviderError::PageBinding)?;
                    self.ensure_revision(&page.provider_revision)?;
                    return Ok(page);
                }
                Err(error)
                    if error.retryable() && self.last_retry_count < request.bounds.max_retries =>
                {
                    self.record_retry();
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn describe_task_definition(
        &mut self,
        request: &DescribeTaskDefinitionRequest,
    ) -> Result<DescribeTaskDefinitionPage, EcsProviderError> {
        self.last_retry_count = 0;
        loop {
            match self.transport.describe_task_definition(request) {
                Ok(page) => {
                    page.validate_for(request)
                        .map_err(|_| EcsProviderError::PageBinding)?;
                    self.ensure_revision(&page.provider_revision)?;
                    return Ok(page);
                }
                Err(error)
                    if error.retryable() && self.last_retry_count < request.bounds.max_retries =>
                {
                    self.record_retry();
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn list_tasks(
        &mut self,
        request: &ListTasksRequest,
    ) -> Result<ListTasksPage, EcsProviderError> {
        self.last_retry_count = 0;
        loop {
            match self.transport.list_tasks(request) {
                Ok(page) => {
                    page.validate_for(request)
                        .map_err(|_| EcsProviderError::PageBinding)?;
                    self.ensure_revision(&page.provider_revision)?;
                    return Ok(page);
                }
                Err(error) if error.retryable() && self.last_retry_count < request.max_retries => {
                    self.record_retry();
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn ensure_revision(&self, revision: &ProviderRevision) -> Result<(), EcsProviderError> {
        if revision != &self.identity.api_revision {
            Err(EcsProviderError::ProviderRevision)
        } else {
            Ok(())
        }
    }
}

pub type AwsEcsProvider<T> = EcsProvider<T>;
