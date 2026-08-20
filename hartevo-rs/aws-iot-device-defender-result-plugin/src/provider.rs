//! Read-only bounded AWS IoT Device Defender provider boundary.
//!
//! A transport receives typed, digest-bound requests and returns typed pages
//! that contain only redacted metadata. There is intentionally no signer,
//! credential resolver, HTTP client, mutation operation, or arbitrary AWS
//! operation escape hatch in this module.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};

use crate::{
    API_REVISION, MAX_CHECKS, MAX_FINDINGS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
    PROVIDER_ID, PROVIDER_VERSION,
    error::{AwsIotDeviceDefenderError, AwsIotDeviceDefenderTransportError},
    model::{
        AuditCheckSummary, AuditFinding, AuditTaskMetadata, AwsIotDeviceDefenderScope,
        DescribeAuditTaskRequest, Digest, ListAuditFindingsRequest, ListAuditTasksRequest,
        ModelError, OpaqueCursor, ProviderId, ProviderRevision, TransportProvenance,
    },
};

pub type ProviderResult<T> = std::result::Result<T, AwsIotDeviceDefenderProviderError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsIotDeviceDefenderProviderDefinition {
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsIotDeviceDefenderProviderDefinition {
    pub fn for_provenance(provenance: TransportProvenance) -> Result<Self, ModelError> {
        let provider_id = ProviderId::new(PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(API_REVISION)?;
        let provider_digest = Digest::from_parts(
            "aws-iot-device-defender-provider/v1",
            &[
                provider_id.digest().to_string(),
                PROVIDER_VERSION.to_owned(),
                api_revision.digest().to_string(),
                provenance.as_str().to_owned(),
            ],
        );
        let api_digest = Digest::from_parts(
            "aws-iot-device-defender-api-allowlist/v1",
            &[
                "ListAuditTasks".to_owned(),
                "DescribeAuditTask".to_owned(),
                "ListAuditFindings".to_owned(),
                "POST".to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            provider_version: PROVIDER_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }

    pub fn validate(&self) -> Result<(), AwsIotDeviceDefenderProviderError> {
        if self.provider_id.as_str() != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.api_revision.as_str() != API_REVISION
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provider_digest
                != Self::for_provenance(self.provenance)
                    .map_err(AwsIotDeviceDefenderProviderError::Model)?
                    .provider_digest
            || self.api_digest
                != Self::for_provenance(self.provenance)
                    .map_err(AwsIotDeviceDefenderProviderError::Model)?
                    .api_digest
        {
            return Err(AwsIotDeviceDefenderProviderError::DefinitionMismatch);
        }
        Ok(())
    }
}

pub type AwsIotDeviceDefenderProviderIdentity = AwsIotDeviceDefenderProviderDefinition;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsIotDeviceDefenderProviderError {
    Model(ModelError),
    Transport(AwsIotDeviceDefenderTransportError),
    PageBinding,
    ProviderRevision,
    DefinitionMismatch,
}

impl fmt::Display for AwsIotDeviceDefenderProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "provider model error: {error}"),
            Self::Transport(error) => write!(formatter, "provider transport error: {error}"),
            Self::PageBinding => formatter.write_str("provider page binding or digest is invalid"),
            Self::ProviderRevision => formatter.write_str("provider API revision is incompatible"),
            Self::DefinitionMismatch => formatter.write_str("provider definition is invalid"),
        }
    }
}

impl std::error::Error for AwsIotDeviceDefenderProviderError {}

impl From<ModelError> for AwsIotDeviceDefenderProviderError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<AwsIotDeviceDefenderTransportError> for AwsIotDeviceDefenderProviderError {
    fn from(error: AwsIotDeviceDefenderTransportError) -> Self {
        Self::Transport(error)
    }
}

/// A Layer-1 transport can be fixture, recording, loopback, or BLOCKED_ENV.
pub trait AwsIotDeviceDefenderTransport: Send {
    fn provenance(&self) -> TransportProvenance;

    fn list_audit_tasks(
        &mut self,
        request: &ListAuditTasksRequest,
    ) -> std::result::Result<ListAuditTasksResponse, AwsIotDeviceDefenderTransportError>;

    fn describe_audit_task(
        &mut self,
        request: &DescribeAuditTaskRequest,
    ) -> std::result::Result<DescribeAuditTaskResponse, AwsIotDeviceDefenderTransportError>;

    fn list_audit_findings(
        &mut self,
        request: &ListAuditFindingsRequest,
    ) -> std::result::Result<ListAuditFindingsResponse, AwsIotDeviceDefenderTransportError>;
}

#[derive(Clone)]
pub struct AwsIotDeviceDefenderProvider<T> {
    transport: T,
    definition: AwsIotDeviceDefenderProviderDefinition,
}

impl<T> fmt::Debug for AwsIotDeviceDefenderProvider<T>
where
    T: AwsIotDeviceDefenderTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsIotDeviceDefenderProvider")
            .field("provider_id", &self.definition.provider_id)
            .field("provider_version", &self.definition.provider_version)
            .field("api_revision", &self.definition.api_revision)
            .field("provider_digest", &self.definition.provider_digest)
            .field("api_digest", &self.definition.api_digest)
            .field("provenance", &self.definition.provenance)
            .finish_non_exhaustive()
    }
}

impl<T> AwsIotDeviceDefenderProvider<T>
where
    T: AwsIotDeviceDefenderTransport,
{
    pub fn new(transport: T) -> ProviderResult<Self> {
        let definition =
            AwsIotDeviceDefenderProviderDefinition::for_provenance(transport.provenance())?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsIotDeviceDefenderProviderDefinition {
        &self.definition
    }

    pub fn identity(&self) -> &AwsIotDeviceDefenderProviderDefinition {
        self.definition()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_audit_tasks(
        &mut self,
        request: &ListAuditTasksRequest,
    ) -> ProviderResult<ListAuditTasksResponse> {
        let response = self.transport.list_audit_tasks(request)?;
        response
            .validate_for(request)
            .map_err(|_| AwsIotDeviceDefenderProviderError::PageBinding)?;
        self.validate_revision(response.provider_revision())?;
        Ok(response)
    }

    pub fn describe_audit_task(
        &mut self,
        request: &DescribeAuditTaskRequest,
    ) -> ProviderResult<DescribeAuditTaskResponse> {
        let response = self.transport.describe_audit_task(request)?;
        response
            .validate_for(request)
            .map_err(|_| AwsIotDeviceDefenderProviderError::PageBinding)?;
        self.validate_revision(response.provider_revision())?;
        Ok(response)
    }

    pub fn list_audit_findings(
        &mut self,
        request: &ListAuditFindingsRequest,
    ) -> ProviderResult<ListAuditFindingsResponse> {
        let response = self.transport.list_audit_findings(request)?;
        response
            .validate_for(request)
            .map_err(|_| AwsIotDeviceDefenderProviderError::PageBinding)?;
        self.validate_revision(response.provider_revision())?;
        Ok(response)
    }

    fn validate_revision(&self, revision: &ProviderRevision) -> ProviderResult<()> {
        if revision != &self.definition.api_revision {
            Err(AwsIotDeviceDefenderProviderError::ProviderRevision)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedRequest {
    ListAuditTasks(ListAuditTasksRequest),
    DescribeAuditTask(DescribeAuditTaskRequest),
    ListAuditFindings(ListAuditFindingsRequest),
}

#[derive(Clone, Debug, Default)]
struct QueuedTransport {
    list_audit_tasks:
        VecDeque<std::result::Result<ListAuditTasksResponse, AwsIotDeviceDefenderTransportError>>,
    describe_audit_task: VecDeque<
        std::result::Result<DescribeAuditTaskResponse, AwsIotDeviceDefenderTransportError>,
    >,
    list_audit_findings: VecDeque<
        std::result::Result<ListAuditFindingsResponse, AwsIotDeviceDefenderTransportError>,
    >,
    requests: Vec<RecordedRequest>,
}

impl QueuedTransport {
    fn list_audit_tasks(
        &mut self,
        request: &ListAuditTasksRequest,
    ) -> std::result::Result<ListAuditTasksResponse, AwsIotDeviceDefenderTransportError> {
        self.requests
            .push(RecordedRequest::ListAuditTasks(request.clone()));
        self.list_audit_tasks
            .pop_front()
            .unwrap_or(Err(AwsIotDeviceDefenderTransportError::Timeout))
    }

    fn describe_audit_task(
        &mut self,
        request: &DescribeAuditTaskRequest,
    ) -> std::result::Result<DescribeAuditTaskResponse, AwsIotDeviceDefenderTransportError> {
        self.requests
            .push(RecordedRequest::DescribeAuditTask(request.clone()));
        self.describe_audit_task
            .pop_front()
            .unwrap_or(Err(AwsIotDeviceDefenderTransportError::Timeout))
    }

    fn list_audit_findings(
        &mut self,
        request: &ListAuditFindingsRequest,
    ) -> std::result::Result<ListAuditFindingsResponse, AwsIotDeviceDefenderTransportError> {
        self.requests
            .push(RecordedRequest::ListAuditFindings(request.clone()));
        self.list_audit_findings
            .pop_front()
            .unwrap_or(Err(AwsIotDeviceDefenderTransportError::Timeout))
    }
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone, Debug, Default)]
        pub struct $name {
            queue: QueuedTransport,
        }

        impl $name {
            pub fn push_list_audit_tasks(
                &mut self,
                response: std::result::Result<
                    ListAuditTasksResponse,
                    AwsIotDeviceDefenderTransportError,
                >,
            ) {
                self.queue.list_audit_tasks.push_back(response);
            }

            pub fn push_describe_audit_task(
                &mut self,
                response: std::result::Result<
                    DescribeAuditTaskResponse,
                    AwsIotDeviceDefenderTransportError,
                >,
            ) {
                self.queue.describe_audit_task.push_back(response);
            }

            pub fn push_list_audit_findings(
                &mut self,
                response: std::result::Result<
                    ListAuditFindingsResponse,
                    AwsIotDeviceDefenderTransportError,
                >,
            ) {
                self.queue.list_audit_findings.push_back(response);
            }

            pub fn requests(&self) -> &[RecordedRequest] {
                &self.queue.requests
            }
        }

        impl AwsIotDeviceDefenderTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn list_audit_tasks(
                &mut self,
                request: &ListAuditTasksRequest,
            ) -> std::result::Result<ListAuditTasksResponse, AwsIotDeviceDefenderTransportError>
            {
                self.queue.list_audit_tasks(request)
            }

            fn describe_audit_task(
                &mut self,
                request: &DescribeAuditTaskRequest,
            ) -> std::result::Result<DescribeAuditTaskResponse, AwsIotDeviceDefenderTransportError>
            {
                self.queue.describe_audit_task(request)
            }

            fn list_audit_findings(
                &mut self,
                request: &ListAuditFindingsRequest,
            ) -> std::result::Result<ListAuditFindingsResponse, AwsIotDeviceDefenderTransportError>
            {
                self.queue.list_audit_findings(request)
            }
        }
    };
}

queued_transport!(
    RecordingAwsIotDeviceDefenderTransport,
    TransportProvenance::Recording
);
queued_transport!(
    FixtureAwsIotDeviceDefenderTransport,
    TransportProvenance::Fixture
);
queued_transport!(
    LoopbackAwsIotDeviceDefenderTransport,
    TransportProvenance::Loopback
);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsIotDeviceDefenderTransport;

impl AwsIotDeviceDefenderTransport for BlockedEnvAwsIotDeviceDefenderTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_audit_tasks(
        &mut self,
        _request: &ListAuditTasksRequest,
    ) -> std::result::Result<ListAuditTasksResponse, AwsIotDeviceDefenderTransportError> {
        Err(AwsIotDeviceDefenderTransportError::BlockedEnv)
    }

    fn describe_audit_task(
        &mut self,
        _request: &DescribeAuditTaskRequest,
    ) -> std::result::Result<DescribeAuditTaskResponse, AwsIotDeviceDefenderTransportError> {
        Err(AwsIotDeviceDefenderTransportError::BlockedEnv)
    }

    fn list_audit_findings(
        &mut self,
        _request: &ListAuditFindingsRequest,
    ) -> std::result::Result<ListAuditFindingsResponse, AwsIotDeviceDefenderTransportError> {
        Err(AwsIotDeviceDefenderTransportError::BlockedEnv)
    }
}

pub type RecordingTransport = RecordingAwsIotDeviceDefenderTransport;
pub type FixtureTransport = FixtureAwsIotDeviceDefenderTransport;
pub type LoopbackTransport = LoopbackAwsIotDeviceDefenderTransport;
pub type BlockedEnvTransport = BlockedEnvAwsIotDeviceDefenderTransport;
pub type FakeAwsIotDeviceDefenderTransport = FixtureAwsIotDeviceDefenderTransport;
pub type ProviderProvenance = TransportProvenance;
pub type TransportError = AwsIotDeviceDefenderTransportError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListAuditTasksResponse {
    request_digest: Digest,
    pub page_number: u16,
    pub tasks: Vec<AuditTaskMetadata>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    provider_revision: ProviderRevision,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl ListAuditTasksResponse {
    pub fn new(
        request: &ListAuditTasksRequest,
        page_number: u16,
        tasks: Vec<AuditTaskMetadata>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        let next_cursor = bind_response_cursor(next_cursor, request, page_number)?;
        let mut response = Self {
            request_digest: request.digest(),
            page_number,
            tasks,
            next_cursor,
            response_bytes,
            provider_revision: ProviderRevision::new(API_REVISION)?,
            provenance,
            response_digest: Digest::zero(),
        };
        response.response_digest = response.recomputed_digest();
        response.validate_for(request)?;
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.response_digest = digest;
        self
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn validate_for(&self, request: &ListAuditTasksRequest) -> Result<(), ModelError> {
        if self.request_digest != request.digest()
            || self.page_number == 0
            || self.page_number > MAX_PAGES
            || self.tasks.len() > MAX_PAGE_SIZE as usize
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.tasks.iter().any(|task| task.validate().is_err())
            || !valid_next_cursor(self.next_cursor.as_ref(), request, self.page_number)
            || self.response_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "ListAuditTasks page",
            });
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-list-audit-tasks-response/v1",
            &[
                self.request_digest.to_string(),
                self.page_number.to_string(),
                self.tasks
                    .iter()
                    .map(|task| task.task_digest.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                self.next_cursor
                    .as_ref()
                    .map_or_else(String::new, |cursor| cursor.digest().to_string()),
                self.response_bytes.to_string(),
                self.provider_revision.digest().to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DescribeAuditTaskResponse {
    request_digest: Digest,
    pub task: AuditTaskMetadata,
    pub checks: Vec<AuditCheckSummary>,
    pub response_bytes: usize,
    provider_revision: ProviderRevision,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl DescribeAuditTaskResponse {
    pub fn new(
        request: &DescribeAuditTaskRequest,
        task: AuditTaskMetadata,
        checks: Vec<AuditCheckSummary>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        let mut response = Self {
            request_digest: request.digest(),
            task,
            checks,
            response_bytes,
            provider_revision: ProviderRevision::new(API_REVISION)?,
            provenance,
            response_digest: Digest::zero(),
        };
        response.response_digest = response.recomputed_digest();
        response.validate_for(request)?;
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.response_digest = digest;
        self
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn validate_for(&self, request: &DescribeAuditTaskRequest) -> Result<(), ModelError> {
        if self.request_digest != request.digest()
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.task.validate().is_err()
            || self.checks.len() > MAX_CHECKS
            || self.checks.iter().any(|check| check.validate().is_err())
            || self.response_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "DescribeAuditTask response",
            });
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-describe-audit-task-response/v1",
            &[
                self.request_digest.to_string(),
                self.task.task_digest.to_string(),
                self.checks
                    .iter()
                    .map(|check| check.check_digest.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                self.response_bytes.to_string(),
                self.provider_revision.digest().to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListAuditFindingsResponse {
    request_digest: Digest,
    pub page_number: u16,
    pub findings: Vec<AuditFinding>,
    pub next_cursor: Option<OpaqueCursor>,
    pub response_bytes: usize,
    provider_revision: ProviderRevision,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl ListAuditFindingsResponse {
    pub fn new(
        request: &ListAuditFindingsRequest,
        page_number: u16,
        findings: Vec<AuditFinding>,
        next_cursor: Option<OpaqueCursor>,
        response_bytes: usize,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        if findings.len() > crate::MAX_FINDINGS_PER_PAGE {
            return Err(ModelError::TooMany {
                field: "findings per page",
            });
        }
        let next_cursor = bind_response_cursor(next_cursor, request, page_number)?;
        let mut response = Self {
            request_digest: request.digest(),
            page_number,
            findings,
            next_cursor,
            response_bytes,
            provider_revision: ProviderRevision::new(API_REVISION)?,
            provenance,
            response_digest: Digest::zero(),
        };
        response.response_digest = response.recomputed_digest();
        response.validate_for(request)?;
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.response_digest = digest;
        self
    }

    pub fn provider_revision(&self) -> &ProviderRevision {
        &self.provider_revision
    }

    pub fn validate_for(&self, request: &ListAuditFindingsRequest) -> Result<(), ModelError> {
        if self.request_digest != request.digest()
            || self.page_number == 0
            || self.page_number > MAX_PAGES
            || self.findings.len() > crate::MAX_FINDINGS_PER_PAGE
            || self.response_bytes == 0
            || self.response_bytes > MAX_RESPONSE_BYTES
            || self.findings.len() > MAX_FINDINGS
            || self
                .findings
                .iter()
                .any(|finding| finding.validate().is_err())
            || !valid_next_cursor(self.next_cursor.as_ref(), request, self.page_number)
            || self.response_digest != self.recomputed_digest()
        {
            return Err(ModelError::ScopeMismatch {
                field: "ListAuditFindings page",
            });
        }
        Ok(())
    }

    fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-device-defender-list-audit-findings-response/v1",
            &[
                self.request_digest.to_string(),
                self.page_number.to_string(),
                self.findings
                    .iter()
                    .map(|finding| finding.finding_digest.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                self.next_cursor
                    .as_ref()
                    .map_or_else(String::new, |cursor| cursor.digest().to_string()),
                self.response_bytes.to_string(),
                self.provider_revision.digest().to_string(),
                self.provenance.as_str().to_owned(),
            ],
        )
    }
}

fn bind_response_cursor<C>(
    cursor: Option<OpaqueCursor>,
    request: &C,
    page_number: u16,
) -> Result<Option<OpaqueCursor>, ModelError>
where
    C: RequestDigest,
{
    cursor
        .map(|cursor| {
            if cursor.is_unbound() {
                Ok(cursor.bind_to(&request.request_digest(), page_number.saturating_add(1)))
            } else if cursor.binding_digest() != &request.request_digest()
                || cursor.page() != page_number.saturating_add(1)
            {
                Err(ModelError::ScopeMismatch {
                    field: "response cursor binding",
                })
            } else {
                Ok(cursor)
            }
        })
        .transpose()
}

fn valid_next_cursor<C: RequestDigest>(
    cursor: Option<&OpaqueCursor>,
    request: &C,
    page_number: u16,
) -> bool {
    cursor.is_none_or(|cursor| {
        cursor.binding_digest() == &request.request_digest()
            && cursor.page() == page_number.saturating_add(1)
    })
}

trait RequestDigest {
    fn request_digest(&self) -> Digest;
}

impl RequestDigest for ListAuditTasksRequest {
    fn request_digest(&self) -> Digest {
        self.digest()
    }
}

impl RequestDigest for ListAuditFindingsRequest {
    fn request_digest(&self) -> Digest {
        self.digest()
    }
}

pub fn transport_error_for_status(status_code: u16) -> AwsIotDeviceDefenderTransportError {
    match status_code {
        400 => AwsIotDeviceDefenderTransportError::BadRequest,
        401 => AwsIotDeviceDefenderTransportError::Unauthorized,
        403 => AwsIotDeviceDefenderTransportError::Forbidden,
        404 => AwsIotDeviceDefenderTransportError::NotFound,
        429 => AwsIotDeviceDefenderTransportError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => AwsIotDeviceDefenderTransportError::ServerFailure {
            status_code: Some(status_code),
        },
        _ => AwsIotDeviceDefenderTransportError::MalformedResponse,
    }
}

pub fn default_request_bounds() -> (u16, u16) {
    (MAX_PAGE_SIZE, MAX_PAGES)
}

pub fn timestamp_for_test() -> DateTime<Utc> {
    Utc::now()
}

impl From<AwsIotDeviceDefenderProviderError> for AwsIotDeviceDefenderError {
    fn from(error: AwsIotDeviceDefenderProviderError) -> Self {
        match error {
            AwsIotDeviceDefenderProviderError::Model(error) => Self::Model(error),
            AwsIotDeviceDefenderProviderError::Transport(error) => Self::Transport(error),
            AwsIotDeviceDefenderProviderError::PageBinding => Self::EvidenceTampered,
            AwsIotDeviceDefenderProviderError::ProviderRevision => Self::ProviderRevision,
            AwsIotDeviceDefenderProviderError::DefinitionMismatch => {
                Self::ProviderDefinition("definition mismatch".to_owned())
            }
        }
    }
}

#[allow(dead_code)]
fn _scope_is_only_used_for_typed_signatures(_scope: &AwsIotDeviceDefenderScope) {}
