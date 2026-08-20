//! Read-only AWS Config provider boundary.
//!
//! The provider exposes only the two documented compliance read operations.
//! A transport receives a typed request and returns a typed, already-redacted
//! page. There is deliberately no signer, credential resolver, write method,
//! configuration-item type, or arbitrary AWS operation escape hatch here.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AWS_CONFIG_API_REVISION, AWS_CONFIG_PROVIDER_ID, AWS_CONFIG_PROVIDER_VERSION,
    model::{
        AwsConfigReadOperation, AwsConfigReadPage, AwsConfigReadRequest, ComplianceEvaluation,
        ComplianceState, Digest, ModelError, OpaqueCursor, ProviderErrorKind, ProviderId,
        ProviderRevision, ResourceId, ResourceType, TransportError, TransportProvenance,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS Config provider id is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Config provider revision is incompatible")]
    RevisionMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsConfigProviderIdentity {
    pub provider_id: ProviderId,
    pub version: String,
    pub api_revision: ProviderRevision,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub provenance: TransportProvenance,
}

impl AwsConfigProviderIdentity {
    pub fn for_provenance(
        provenance: TransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_id = ProviderId::new(AWS_CONFIG_PROVIDER_ID)?;
        let api_revision = ProviderRevision::new(AWS_CONFIG_API_REVISION)?;
        let provider_digest = Digest::from_parts(
            "hartevo-aws-config-provider/v1",
            &[
                provider_id.as_str().to_owned(),
                AWS_CONFIG_PROVIDER_VERSION.to_owned(),
                api_revision.as_str().to_owned(),
            ],
        );
        let api_digest = Digest::from_parts(
            "hartevo-aws-config-api-allowlist/v1",
            &[
                "GetComplianceDetailsByConfigRule".to_owned(),
                "DescribeComplianceByResource".to_owned(),
                "POST".to_owned(),
            ],
        );
        Ok(Self {
            provider_id,
            version: AWS_CONFIG_PROVIDER_VERSION.to_owned(),
            api_revision,
            provider_digest,
            api_digest,
            provenance,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsConfigProviderError {
    #[error("AWS Config provider request is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("AWS Config provider transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("AWS Config provider page binding or digest is invalid")]
    PageBinding,
    #[error("AWS Config provider page revision is incompatible")]
    ProviderRevision,
}

/// A Layer-1 transport can be fixture, recording, loopback, or BLOCKED_ENV.
/// It has no native credential or HTTP client contract.
pub trait AwsConfigTransport: Send {
    fn provenance(&self) -> TransportProvenance;

    fn read(&mut self, request: &AwsConfigReadRequest)
    -> Result<AwsConfigReadPage, TransportError>;
}

#[derive(Clone)]
pub struct AwsConfigProvider<T> {
    transport: T,
    identity: AwsConfigProviderIdentity,
}

impl<T> fmt::Debug for AwsConfigProvider<T>
where
    T: AwsConfigTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsConfigProvider")
            .field("provider_id", &self.identity.provider_id)
            .field("version", &self.identity.version)
            .field("api_revision", &self.identity.api_revision)
            .field("provider_digest", &self.identity.provider_digest)
            .field("api_digest", &self.identity.api_digest)
            .field("provenance", &self.identity.provenance)
            .finish_non_exhaustive()
    }
}

impl<T> AwsConfigProvider<T>
where
    T: AwsConfigTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        let identity = AwsConfigProviderIdentity::for_provenance(transport.provenance())?;
        Ok(Self {
            transport,
            identity,
        })
    }

    pub fn identity(&self) -> &AwsConfigProviderIdentity {
        &self.identity
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &AwsConfigReadRequest,
    ) -> Result<AwsConfigReadPage, AwsConfigProviderError> {
        if let Some(cursor) = &request.cursor
            && cursor.binding_digest() != Some(&request.query_digest())
        {
            return Err(AwsConfigProviderError::Model(ModelError::ScopeMismatch {
                field: "cursor query binding",
            }));
        }
        let page = self.transport.read(request)?;
        page.validate_for(request)
            .map_err(|_| AwsConfigProviderError::PageBinding)?;
        if page.provider_revision != self.identity.api_revision {
            return Err(AwsConfigProviderError::ProviderRevision);
        }
        Ok(page)
    }

    /// Parse only the documented compliance fields from an already bounded
    /// response. Unknown fields, including configuration snapshots, tags,
    /// annotations, and environment values, are ignored and never retained.
    pub fn parse_json_page(
        request: &AwsConfigReadRequest,
        page_number: u16,
        status_code: u16,
        body: &[u8],
        provider_revision: ProviderRevision,
    ) -> Result<AwsConfigReadPage, AwsConfigProviderError> {
        if status_code != 200 {
            return Err(AwsConfigProviderError::Transport(
                transport_error_for_status(status_code),
            ));
        }
        if body.is_empty() || body.len() > request.max_response_bytes {
            return Err(AwsConfigProviderError::Model(ModelError::Invalid {
                field: "provider response bytes",
            }));
        }
        let value = serde_json::from_slice::<Value>(body)
            .map_err(|_| AwsConfigProviderError::Transport(TransportError::MalformedResponse))?;
        let next_cursor = value
            .get("NextToken")
            .and_then(Value::as_str)
            .map(OpaqueCursor::new)
            .transpose()?;
        let evaluations = match request.operation {
            AwsConfigReadOperation::GetComplianceDetailsByConfigRule => {
                parse_rule_evaluations(request, &value)?
            }
            AwsConfigReadOperation::DescribeComplianceByResource => {
                parse_resource_evaluations(request, &value)?
            }
        };
        AwsConfigReadPage::new(
            request,
            page_number,
            evaluations,
            next_cursor,
            body.len(),
            provider_revision,
        )
        .map_err(AwsConfigProviderError::Model)
    }
}

fn transport_error_for_status(status_code: u16) -> TransportError {
    match status_code {
        400 => TransportError::InvalidRequest,
        401 => TransportError::Unauthorized,
        403 => TransportError::Forbidden,
        404 => TransportError::NotFound,
        409 => TransportError::Conflict,
        429 => TransportError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => TransportError::ServerFailure {
            status_code: Some(status_code),
        },
        _ => TransportError::Unknown,
    }
}

fn parse_rule_evaluations(
    request: &AwsConfigReadRequest,
    value: &Value,
) -> Result<Vec<ComplianceEvaluation>, AwsConfigProviderError> {
    let items = value
        .get("EvaluationResults")
        .or_else(|| value.get("results"))
        .and_then(Value::as_array)
        .ok_or(AwsConfigProviderError::Transport(
            TransportError::MalformedResponse,
        ))?;
    let mut evaluations = Vec::with_capacity(items.len());
    for item in items {
        let qualifier = item
            .get("EvaluationResultIdentifier")
            .and_then(|identifier| identifier.get("EvaluationResultQualifier"))
            .unwrap_or(item);
        let resource_type = required_string(qualifier, "ResourceType")
            .and_then(ResourceType::new)
            .map_err(AwsConfigProviderError::Model)?;
        let resource_id = required_string(qualifier, "ResourceId")
            .and_then(ResourceId::new)
            .map_err(AwsConfigProviderError::Model)?;
        let state = required_string(item, "ComplianceType")
            .and_then(ComplianceState::parse_api)
            .map_err(AwsConfigProviderError::Model)?;
        let rule_revision = required_revision(item, "RuleRevision")?;
        let resource_revision = required_revision(item, "ResourceRevision")?;
        let evaluation_revision = required_revision(item, "EvaluationRevision")?;
        let ordering_timestamp = required_timestamp(item, "OrderingTimestamp")?;
        let result_recorded_timestamp = required_timestamp(item, "ResultRecordedTime")?;
        evaluations.push(
            ComplianceEvaluation::new(
                request.config_rule_name.clone(),
                rule_revision,
                resource_type,
                resource_id,
                resource_revision,
                evaluation_revision,
                state,
                ordering_timestamp,
                result_recorded_timestamp,
            )
            .map_err(AwsConfigProviderError::Model)?,
        );
    }
    Ok(evaluations)
}

fn parse_resource_evaluations(
    request: &AwsConfigReadRequest,
    value: &Value,
) -> Result<Vec<ComplianceEvaluation>, AwsConfigProviderError> {
    let items = value
        .get("ComplianceByResources")
        .or_else(|| value.get("results"))
        .and_then(Value::as_array)
        .ok_or(AwsConfigProviderError::Transport(
            TransportError::MalformedResponse,
        ))?;
    let resource = request
        .resource
        .as_ref()
        .ok_or(AwsConfigProviderError::Model(ModelError::Invalid {
            field: "resource selector",
        }))?;
    let mut evaluations = Vec::with_capacity(items.len());
    for item in items {
        let resource_type = item
            .get("ResourceType")
            .and_then(Value::as_str)
            .map_or_else(|| Ok(resource.resource_type.clone()), ResourceType::new)
            .map_err(AwsConfigProviderError::Model)?;
        let resource_id = item
            .get("ResourceId")
            .and_then(Value::as_str)
            .map_or_else(|| Ok(resource.resource_id.clone()), ResourceId::new)
            .map_err(AwsConfigProviderError::Model)?;
        let state = required_string(item, "Compliance")
            .and_then(ComplianceState::parse_api)
            .map_err(AwsConfigProviderError::Model)?;
        let rule_revision = required_revision(item, "RuleRevision")?;
        let resource_revision = required_revision(item, "ResourceRevision")?;
        let evaluation_revision = required_revision(item, "EvaluationRevision")?;
        let ordering_timestamp = required_timestamp(item, "OrderingTimestamp")?;
        let result_recorded_timestamp = required_timestamp(item, "ResultRecordedTime")?;
        evaluations.push(
            ComplianceEvaluation::new(
                request.config_rule_name.clone(),
                rule_revision,
                resource_type,
                resource_id,
                resource_revision,
                evaluation_revision,
                state,
                ordering_timestamp,
                result_recorded_timestamp,
            )
            .map_err(AwsConfigProviderError::Model)?,
        );
    }
    Ok(evaluations)
}

fn required_string<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, ModelError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ModelError::Invalid { field })
}

fn required_revision(
    value: &Value,
    field: &'static str,
) -> Result<crate::Revision, AwsConfigProviderError> {
    let number = value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(AwsConfigProviderError::Model(ModelError::Invalid { field }))?;
    crate::Revision::new(number).map_err(AwsConfigProviderError::Model)
}

fn required_timestamp(
    value: &Value,
    field: &'static str,
) -> Result<DateTime<Utc>, AwsConfigProviderError> {
    let text = required_string(value, field).map_err(AwsConfigProviderError::Model)?;
    DateTime::parse_from_rfc3339(text)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| AwsConfigProviderError::Transport(TransportError::MalformedResponse))
}

#[derive(Clone, Debug, Default)]
struct QueuedTransport {
    responses: VecDeque<Result<AwsConfigReadPage, TransportError>>,
    requests: Vec<AwsConfigReadRequest>,
}

impl QueuedTransport {
    fn push_response(&mut self, response: Result<AwsConfigReadPage, TransportError>) {
        self.responses.push_back(response);
    }

    fn requests(&self) -> &[AwsConfigReadRequest] {
        &self.requests
    }

    fn read(
        &mut self,
        request: &AwsConfigReadRequest,
    ) -> Result<AwsConfigReadPage, TransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .unwrap_or(Err(TransportError::Timeout))
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingAwsConfigTransport {
    queue: QueuedTransport,
}

impl RecordingAwsConfigTransport {
    pub fn push_response(&mut self, response: Result<AwsConfigReadPage, TransportError>) {
        self.queue.push_response(response);
    }

    pub fn requests(&self) -> &[AwsConfigReadRequest] {
        self.queue.requests()
    }
}

impl AwsConfigTransport for RecordingAwsConfigTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read(
        &mut self,
        request: &AwsConfigReadRequest,
    ) -> Result<AwsConfigReadPage, TransportError> {
        self.queue.read(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureAwsConfigTransport {
    queue: QueuedTransport,
}

impl FixtureAwsConfigTransport {
    pub fn push_response(&mut self, response: Result<AwsConfigReadPage, TransportError>) {
        self.queue.push_response(response);
    }

    pub fn requests(&self) -> &[AwsConfigReadRequest] {
        self.queue.requests()
    }
}

impl AwsConfigTransport for FixtureAwsConfigTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read(
        &mut self,
        request: &AwsConfigReadRequest,
    ) -> Result<AwsConfigReadPage, TransportError> {
        self.queue.read(request)
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackAwsConfigTransport {
    queue: QueuedTransport,
}

impl LoopbackAwsConfigTransport {
    pub fn push_response(&mut self, response: Result<AwsConfigReadPage, TransportError>) {
        self.queue.push_response(response);
    }

    pub fn requests(&self) -> &[AwsConfigReadRequest] {
        self.queue.requests()
    }
}

impl AwsConfigTransport for LoopbackAwsConfigTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read(
        &mut self,
        request: &AwsConfigReadRequest,
    ) -> Result<AwsConfigReadPage, TransportError> {
        self.queue.read(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsConfigTransport;

impl AwsConfigTransport for BlockedEnvAwsConfigTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(
        &mut self,
        _request: &AwsConfigReadRequest,
    ) -> Result<AwsConfigReadPage, TransportError> {
        Err(TransportError::BlockedEnvironment)
    }
}

pub type FakeAwsConfigTransport = FixtureAwsConfigTransport;
pub type BlockedEnvTransport = BlockedEnvAwsConfigTransport;
pub type ProviderProvenance = TransportProvenance;

pub fn is_access_loss(error: &TransportError) -> bool {
    matches!(
        error.kind(),
        ProviderErrorKind::Unauthorized
            | ProviderErrorKind::Forbidden
            | ProviderErrorKind::NotFound
    )
}
