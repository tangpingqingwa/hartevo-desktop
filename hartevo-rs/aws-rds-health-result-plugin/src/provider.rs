//! Typed provider definition and deterministic non-native transports.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::model::{
    AwsRdsHealthScope, AwsRdsReadOperation, AwsRdsReadPage, AwsRdsReadRequest, Digest,
    EndpointPresence, EngineFamily, EngineVersionFamily, ModelError, OpaqueCursor,
    ProviderErrorEvidence, ProviderErrorKind, RdsDatabaseObservation, RdsEventCategory,
    RdsEventSeverity, RdsEventSummary, RdsMaintenanceCategory, RdsMaintenanceStatus,
    RdsMaintenanceSummary, RdsTimeWindow, TransportProvenance,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("AWS RDS provider definition is invalid: {0}")]
    Model(#[from] ModelError),
    #[error("AWS RDS provider definition drifted")]
    Drift,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsRdsProviderDefinition {
    pub provider_id: String,
    pub version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub allowlisted_operations: Vec<String>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl Default for AwsRdsProviderDefinition {
    fn default() -> Self {
        let allowlisted_operations = [
            AwsRdsReadOperation::DescribeDbInstances,
            AwsRdsReadOperation::DescribeDbClusters,
            AwsRdsReadOperation::DescribeEvents,
            AwsRdsReadOperation::DescribePendingMaintenanceActions,
        ]
        .into_iter()
        .map(|operation| operation.api_name().to_owned())
        .collect::<Vec<_>>();
        let api_digest = Digest::from_parts(
            "aws-rds-api-allowlist/v1",
            &allowlisted_operations
                .iter()
                .enumerate()
                .map(|(index, operation)| ("operation", format!("{index}:{operation}")))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-rds-provider/v1",
            &[
                ("id", crate::PROVIDER_ID.to_owned()),
                ("version", crate::PLUGIN_VERSION.to_owned()),
                ("revision", crate::PROVIDER_API_REVISION.to_owned()),
                ("api", api_digest.to_string()),
            ],
        );
        Self {
            provider_id: crate::PROVIDER_ID.to_owned(),
            version: crate::PLUGIN_VERSION.to_owned(),
            api_revision: crate::PROVIDER_API_REVISION.to_owned(),
            provider_digest,
            api_digest,
            allowlisted_operations,
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
        }
    }
}

impl AwsRdsProviderDefinition {
    pub fn baseline() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        let expected = Self::default();
        if self.provider_id != expected.provider_id
            || self.version != expected.version
            || self.api_revision != expected.api_revision
            || self.provider_digest != expected.provider_digest
            || self.api_digest != expected.api_digest
            || self.allowlisted_operations != expected.allowlisted_operations
            || !self.read_only
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(ProviderDefinitionError::Drift);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.provider_digest.clone()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsRdsTransportError {
    #[error("AWS RDS request is invalid")]
    InvalidRequest,
    #[error("AWS RDS credentials were not authorized")]
    Unauthorized,
    #[error("AWS RDS access was forbidden")]
    Forbidden,
    #[error("AWS RDS target was not found")]
    NotFound,
    #[error("AWS RDS provider was rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("AWS RDS provider returned a server failure")]
    ServerFailure {
        status_code: Option<u16>,
        response_digest: Option<Digest>,
    },
    #[error("AWS RDS transport timed out")]
    Timeout,
    #[error("AWS RDS native transport is unavailable in BLOCKED_ENV")]
    BlockedEnvironment,
    #[error("AWS RDS provider returned a partial response")]
    Partial,
    #[error("AWS RDS provider state conflicted with the request")]
    Conflict,
    #[error("AWS RDS response was malformed")]
    MalformedResponse { response_digest: Option<Digest> },
    #[error("AWS RDS response did not match the request")]
    RequestMismatch,
    #[error("AWS RDS deterministic transport has no response")]
    FixtureExhausted,
}

impl AwsRdsTransportError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::InvalidRequest => ProviderErrorKind::InvalidRequest,
            Self::Unauthorized => ProviderErrorKind::Unauthorized,
            Self::Forbidden => ProviderErrorKind::Forbidden,
            Self::NotFound => ProviderErrorKind::NotFound,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::ServerFailure { .. } => ProviderErrorKind::ServerFailure,
            Self::Timeout => ProviderErrorKind::Timeout,
            Self::BlockedEnvironment => ProviderErrorKind::BlockedEnvironment,
            Self::Partial => ProviderErrorKind::Partial,
            Self::Conflict => ProviderErrorKind::Conflict,
            Self::MalformedResponse { .. } => ProviderErrorKind::MalformedResponse,
            Self::RequestMismatch => ProviderErrorKind::RequestMismatch,
            Self::FixtureExhausted => ProviderErrorKind::FixtureExhausted,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::InvalidRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code, .. } => *status_code,
            Self::BlockedEnvironment
            | Self::Timeout
            | Self::Partial
            | Self::Conflict
            | Self::MalformedResponse { .. }
            | Self::RequestMismatch
            | Self::FixtureExhausted => None,
        }
    }

    pub const fn is_access_loss(&self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden)
    }

    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::RateLimited { .. } | Self::Timeout)
    }

    pub fn evidence(&self, operation: AwsRdsReadOperation) -> ProviderErrorEvidence {
        ProviderErrorEvidence {
            operation,
            kind: self.kind(),
            status_code: self.status_code(),
            retry_after_seconds: match self {
                Self::RateLimited {
                    retry_after_seconds,
                } => *retry_after_seconds,
                _ => None,
            },
            response_digest: match self {
                Self::ServerFailure {
                    response_digest, ..
                }
                | Self::MalformedResponse { response_digest } => response_digest.clone(),
                _ => None,
            },
        }
    }
}

pub trait AwsRdsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn read(&mut self, request: &AwsRdsReadRequest)
    -> Result<AwsRdsReadPage, AwsRdsTransportError>;
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AwsRdsProviderError {
    #[error("AWS RDS provider definition drifted")]
    DefinitionDrift,
    #[error("AWS RDS provider model error: {0}")]
    Model(#[from] ModelError),
    #[error("AWS RDS provider transport error: {0}")]
    Transport(#[from] AwsRdsTransportError),
    #[error("AWS RDS provider page binding failed")]
    PageBinding,
}

#[derive(Clone)]
pub struct AwsRdsProvider<T>
where
    T: AwsRdsTransport,
{
    transport: T,
    definition: AwsRdsProviderDefinition,
}

impl<T> fmt::Debug for AwsRdsProvider<T>
where
    T: AwsRdsTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRdsProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T> AwsRdsProvider<T>
where
    T: AwsRdsTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        Self::with_definition(transport, AwsRdsProviderDefinition::default())
    }

    pub fn with_definition(
        transport: T,
        definition: AwsRdsProviderDefinition,
    ) -> Result<Self, ProviderDefinitionError> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsRdsProviderDefinition {
        &self.definition
    }

    pub fn identity(&self) -> &AwsRdsProviderDefinition {
        &self.definition
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
        request: &AwsRdsReadRequest,
    ) -> Result<AwsRdsReadPage, AwsRdsProviderError> {
        self.definition
            .validate()
            .map_err(|_| AwsRdsProviderError::DefinitionDrift)?;
        let page = self.transport.read(request)?;
        page.validate_against(request)
            .map_err(|_| AwsRdsProviderError::PageBinding)?;
        Ok(page.with_provenance(self.transport.provenance()))
    }

    /// Parse an AWS JSON response into an allowlisted normalized page. The
    /// raw body is hashed and dropped before the page leaves this function.
    pub fn parse_json_page(
        request: &AwsRdsReadRequest,
        status: u16,
        raw: &[u8],
    ) -> Result<AwsRdsReadPage, AwsRdsTransportError> {
        if raw.len() as u64 > request.max_response_bytes {
            return Err(AwsRdsTransportError::Partial);
        }
        if status != 200 {
            return Err(match status {
                400 => AwsRdsTransportError::InvalidRequest,
                401 => AwsRdsTransportError::Unauthorized,
                403 => AwsRdsTransportError::Forbidden,
                404 => AwsRdsTransportError::NotFound,
                429 => AwsRdsTransportError::RateLimited {
                    retry_after_seconds: None,
                },
                500..=599 => AwsRdsTransportError::ServerFailure {
                    status_code: Some(status),
                    response_digest: Some(crate::sha256_digest(raw)),
                },
                _ => AwsRdsTransportError::MalformedResponse {
                    response_digest: Some(crate::sha256_digest(raw)),
                },
            });
        }
        let value = serde_json::from_slice::<Value>(raw).map_err(|_| {
            AwsRdsTransportError::MalformedResponse {
                response_digest: Some(crate::sha256_digest(raw)),
            }
        })?;
        match request.operation {
            AwsRdsReadOperation::DescribeDbInstances | AwsRdsReadOperation::DescribeDbClusters => {
                parse_database_page(request, &value)
            }
            AwsRdsReadOperation::DescribeEvents => parse_events_page(request, &value),
            AwsRdsReadOperation::DescribePendingMaintenanceActions => {
                parse_maintenance_page(request, &value)
            }
        }
    }
}

fn parse_database_page(
    request: &AwsRdsReadRequest,
    value: &Value,
) -> Result<AwsRdsReadPage, AwsRdsTransportError> {
    let field = match request.operation {
        AwsRdsReadOperation::DescribeDbInstances => "DBInstances",
        AwsRdsReadOperation::DescribeDbClusters => "DBClusters",
        _ => return Err(AwsRdsTransportError::InvalidRequest),
    };
    let items = value.get(field).and_then(Value::as_array).ok_or(
        AwsRdsTransportError::MalformedResponse {
            response_digest: None,
        },
    )?;
    let identifier_field = match request.operation {
        AwsRdsReadOperation::DescribeDbInstances => "DBInstanceIdentifier",
        AwsRdsReadOperation::DescribeDbClusters => "DBClusterIdentifier",
        _ => unreachable!(),
    };
    let arn_field = match request.operation {
        AwsRdsReadOperation::DescribeDbInstances => "DBInstanceArn",
        AwsRdsReadOperation::DescribeDbClusters => "DBClusterArn",
        _ => unreachable!(),
    };
    let item = items
        .iter()
        .find(|item| {
            item.get(identifier_field)
                .and_then(Value::as_str)
                .is_some_and(|identifier| identifier == request.target.identifier().as_str())
        })
        .ok_or(AwsRdsTransportError::NotFound)?;
    if let Some(arn) = item.get(arn_field).and_then(Value::as_str)
        && arn != request.target.arn().as_str()
    {
        return Err(AwsRdsTransportError::RequestMismatch);
    }
    let engine = item
        .get("Engine")
        .and_then(Value::as_str)
        .ok_or(AwsRdsTransportError::MalformedResponse {
            response_digest: None,
        })
        .and_then(|value| {
            EngineFamily::aws(value).map_err(|_| AwsRdsTransportError::MalformedResponse {
                response_digest: None,
            })
        })?;
    let version_raw = item.get("EngineVersion").and_then(Value::as_str).ok_or(
        AwsRdsTransportError::MalformedResponse {
            response_digest: None,
        },
    )?;
    let version_family = normalize_version_family(version_raw, &request.engine.version_family)?;
    let status = item
        .get("DBInstanceStatus")
        .or_else(|| item.get("Status"))
        .and_then(Value::as_str)
        .map_or(crate::RdsDbStatus::Unknown, crate::RdsDbStatus::parse_api);
    let endpoint_presence = if item.get("Endpoint").is_some_and(Value::is_object) {
        EndpointPresence::Present
    } else {
        EndpointPresence::Absent
    };
    let scope = scope_from_request(request);
    let mut observation =
        RdsDatabaseObservation::for_scope(&scope, status, endpoint_presence, scope.db_revision);
    observation.engine = engine;
    observation.version_family = version_family;
    observation.observation_digest = observation.recomputed_digest();
    let marker = marker(value);
    AwsRdsReadPage::database(request, observation, marker, item_count_bytes(value))
        .map_err(map_model_transport_error)
}

fn parse_events_page(
    request: &AwsRdsReadRequest,
    value: &Value,
) -> Result<AwsRdsReadPage, AwsRdsTransportError> {
    let items = value.get("Events").and_then(Value::as_array).ok_or(
        AwsRdsTransportError::MalformedResponse {
            response_digest: None,
        },
    )?;
    if items.len() > usize::from(request.max_events) {
        return Err(AwsRdsTransportError::Partial);
    }
    let mut events = Vec::new();
    for item in items {
        let source = item
            .get("SourceIdentifier")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if source != request.target.identifier().as_str() {
            continue;
        }
        let occurred_at = item
            .get("Date")
            .and_then(Value::as_str)
            .and_then(parse_datetime)
            .ok_or(AwsRdsTransportError::MalformedResponse {
                response_digest: None,
            })?;
        if !request.time_window.contains(occurred_at) {
            continue;
        }
        let event_id = item
            .get("EventId")
            .and_then(Value::as_str)
            .unwrap_or("event-without-id");
        let category = item
            .get("EventCategories")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str)
            .map_or(RdsEventCategory::Unknown, RdsEventCategory::parse_api);
        let severity = item
            .get("Severity")
            .and_then(Value::as_str)
            .map_or(RdsEventSeverity::Unknown, RdsEventSeverity::parse_api);
        let message = item
            .get("Message")
            .and_then(Value::as_str)
            .unwrap_or("redacted-provider-message");
        events.push(
            RdsEventSummary::new(event_id, source, category, severity, occurred_at, message)
                .map_err(map_model_transport_error)?,
        );
    }
    AwsRdsReadPage::events(request, events, marker(value), item_count_bytes(value))
        .map_err(map_model_transport_error)
}

fn parse_maintenance_page(
    request: &AwsRdsReadRequest,
    value: &Value,
) -> Result<AwsRdsReadPage, AwsRdsTransportError> {
    let items = value
        .get("PendingMaintenanceActions")
        .and_then(Value::as_array)
        .ok_or(AwsRdsTransportError::MalformedResponse {
            response_digest: None,
        })?;
    if items.len() > usize::from(request.max_maintenance_actions) {
        return Err(AwsRdsTransportError::Partial);
    }
    let mut maintenance = Vec::new();
    for item in items {
        let resource = item
            .get("ResourceIdentifier")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if resource != request.target.arn().as_str() {
            continue;
        }
        let details = item
            .get("PendingMaintenanceActionDetails")
            .and_then(Value::as_array)
            .ok_or(AwsRdsTransportError::MalformedResponse {
                response_digest: None,
            })?;
        for detail in details {
            let action = detail
                .get("Action")
                .and_then(Value::as_str)
                .unwrap_or("unknown-action");
            let status = detail.get("Status").and_then(Value::as_str).map_or(
                RdsMaintenanceStatus::Pending,
                RdsMaintenanceStatus::parse_api,
            );
            let category = RdsMaintenanceCategory::parse_api(action);
            let apply_at = detail
                .get("CurrentApplyDate")
                .or_else(|| detail.get("AutoAppliedAfterDate"))
                .and_then(Value::as_str)
                .and_then(parse_datetime);
            let description = detail
                .get("Description")
                .and_then(Value::as_str)
                .unwrap_or("redacted-maintenance-detail");
            maintenance.push(
                RdsMaintenanceSummary::new(action, category, status, apply_at, description)
                    .map_err(map_model_transport_error)?,
            );
            if maintenance.len() > usize::from(request.max_maintenance_actions) {
                return Err(AwsRdsTransportError::Partial);
            }
        }
    }
    AwsRdsReadPage::maintenance(request, maintenance, marker(value), item_count_bytes(value))
        .map_err(map_model_transport_error)
}

fn scope_from_request(request: &AwsRdsReadRequest) -> AwsRdsHealthScope {
    AwsRdsHealthScope {
        deployment: crate::DeploymentBinding::new(
            crate::DeploymentId::new("parsed-deployment").expect("bounded parser binding"),
            crate::Revision::new(1).expect("bounded parser revision"),
        ),
        mission: crate::MissionBinding::new(
            crate::MissionId::new("parsed-mission").expect("bounded parser binding"),
            crate::Revision::new(1).expect("bounded parser revision"),
        ),
        project: crate::ProjectBinding::new(
            crate::ProjectId::new("parsed-project").expect("bounded parser binding"),
            crate::Revision::new(1).expect("bounded parser revision"),
        ),
        work_product: crate::WorkProductBinding::new(
            crate::WorkProductId::new("parsed-work-product").expect("bounded parser binding"),
            crate::Revision::new(1).expect("bounded parser revision"),
        ),
        account_id: request.account_id.clone(),
        region: request.region.clone(),
        target: request.target.clone(),
        engine: request.engine.clone(),
        db_revision: request.db_revision,
        time_window: request.time_window.clone(),
        permission_digest: request.permission_digest.clone(),
        scope_digest: request.scope_digest.clone(),
    }
}

fn normalize_version_family(
    raw: &str,
    expected: &EngineVersionFamily,
) -> Result<EngineVersionFamily, AwsRdsTransportError> {
    if raw == expected.as_str() || raw.starts_with(&format!("{}.", expected.as_str())) {
        return Ok(expected.clone());
    }
    EngineVersionFamily::aws(raw).map_err(map_model_transport_error)
}

fn parse_datetime(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn marker(value: &Value) -> Option<&str> {
    value
        .get("Marker")
        .or_else(|| value.get("NextToken"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn item_count_bytes(value: &Value) -> u64 {
    serde_json::to_vec(value).map_or(0, |value| value.len() as u64)
}

fn map_model_transport_error(error: ModelError) -> AwsRdsTransportError {
    match error {
        ModelError::ResponseTooLarge | ModelError::PartialEvidence => AwsRdsTransportError::Partial,
        ModelError::ScopeMismatch { .. }
        | ModelError::RevisionMismatch { .. }
        | ModelError::InvalidScope => AwsRdsTransportError::RequestMismatch,
        _ => AwsRdsTransportError::MalformedResponse {
            response_digest: None,
        },
    }
}

macro_rules! queued_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone)]
        pub struct $name {
            responses: VecDeque<Result<AwsRdsReadPage, AwsRdsTransportError>>,
            requests: Vec<AwsRdsReadRequest>,
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("provenance", &$provenance)
                    .field("queued_responses", &self.responses.len())
                    .field("request_count", &self.requests.len())
                    .finish()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new(std::iter::empty())
            }
        }

        impl $name {
            pub fn new<I>(responses: I) -> Self
            where
                I: IntoIterator<Item = Result<AwsRdsReadPage, AwsRdsTransportError>>,
            {
                Self {
                    responses: responses.into_iter().collect(),
                    requests: Vec::new(),
                }
            }

            pub fn push_response(
                &mut self,
                response: Result<AwsRdsReadPage, AwsRdsTransportError>,
            ) {
                self.responses.push_back(response);
            }

            pub fn requests(&self) -> &[AwsRdsReadRequest] {
                &self.requests
            }
        }

        impl AwsRdsTransport for $name {
            fn provenance(&self) -> TransportProvenance {
                $provenance
            }

            fn read(
                &mut self,
                request: &AwsRdsReadRequest,
            ) -> Result<AwsRdsReadPage, AwsRdsTransportError> {
                self.requests.push(request.clone());
                let response = self
                    .responses
                    .pop_front()
                    .ok_or(AwsRdsTransportError::FixtureExhausted)??;
                Ok(response.with_provenance($provenance))
            }
        }
    };
}

queued_transport!(RecordingAwsRdsTransport, TransportProvenance::Recording);
queued_transport!(FixtureAwsRdsTransport, TransportProvenance::Fixture);
queued_transport!(LoopbackAwsRdsTransport, TransportProvenance::Loopback);

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsRdsTransport;

impl AwsRdsTransport for BlockedEnvAwsRdsTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read(
        &mut self,
        _request: &AwsRdsReadRequest,
    ) -> Result<AwsRdsReadPage, AwsRdsTransportError> {
        Err(AwsRdsTransportError::BlockedEnvironment)
    }
}

pub type RecordingTransport = RecordingAwsRdsTransport;
pub type FixtureTransport = FixtureAwsRdsTransport;
pub type LoopbackTransport = LoopbackAwsRdsTransport;
pub type BlockedEnvTransport = BlockedEnvAwsRdsTransport;
pub type ProviderProvenance = TransportProvenance;
pub type AwsRdsProviderIdentity = AwsRdsProviderDefinition;

pub fn is_access_loss(error: &AwsRdsTransportError) -> bool {
    error.is_access_loss()
}

pub fn opaque_cursor_for_request(
    token: impl AsRef<str>,
    request: &AwsRdsReadRequest,
    page_number: u16,
) -> Result<OpaqueCursor, ModelError> {
    OpaqueCursor::new(token)?.bind(&request.query_digest(), page_number)
}

fn _keep_scope_type_visible(_: &AwsRdsHealthScope, _: &RdsTimeWindow) {}
