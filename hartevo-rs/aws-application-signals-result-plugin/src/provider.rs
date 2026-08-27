//! Provider and transport seams for bounded Application Signals reads.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AWS_APPLICATION_SIGNALS_API_VERSION, AWS_APPLICATION_SIGNALS_PLUGIN_VERSION_TEXT,
    AWS_APPLICATION_SIGNALS_PROVIDER_REVISION, AWS_APPLICATION_SIGNALS_SERVICE_ID,
    model::{
        AccountId, AwsApplicationSignalsScope, Digest, EvidenceStatus, ModelError, OpaquePageToken,
        OperationName, ReadBounds, ReadOperation, Region, ServiceDetail, ServiceName,
        ServiceSummary, SloDetail, SloId, SloSummary, TimeWindow, digest_serializable,
    },
};

// `ListRequestMarker` is a private implementation marker kept in this module's
// digest inputs. It is declared below so request digests cannot accidentally
// include a raw provider cursor.

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn connected(self) -> bool {
        false
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
    Server5xx,
    Timeout,
    BlockedEnv,
    Malformed,
}

impl TransportFailure {
    #[must_use]
    pub const fn status_code(self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::AccessDenied => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::Throttled => Some(429),
            Self::Server5xx => Some(500),
            Self::Timeout | Self::BlockedEnv | Self::Malformed => None,
        }
    }

    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::AccessDenied,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::Throttled,
            500..=599 => Self::Server5xx,
            _ => Self::Malformed,
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadRequest => "HTTP_400",
            Self::Unauthorized => "HTTP_401",
            Self::AccessDenied => "HTTP_403",
            Self::NotFound => "HTTP_404",
            Self::Conflict => "HTTP_409",
            Self::Throttled => "HTTP_429",
            Self::Server5xx => "HTTP_5XX",
            Self::Timeout => "TIMEOUT",
            Self::BlockedEnv => "BLOCKED_ENV",
            Self::Malformed => "MALFORMED",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("AWS Application Signals transport failure {code}")]
pub struct TransportError {
    pub failure: TransportFailure,
    pub status_code: Option<u16>,
    pub retry_after_seconds: Option<u64>,
    pub code: String,
}

pub type AwsApplicationSignalsTransportError = TransportError;

impl TransportError {
    #[must_use]
    pub fn new(failure: TransportFailure) -> Self {
        Self {
            status_code: failure.status_code(),
            code: failure.code().to_owned(),
            failure,
            retry_after_seconds: None,
        }
    }

    #[must_use]
    pub fn from_status(status: u16) -> Self {
        let mut error = Self::new(TransportFailure::from_status(status));
        error.status_code = Some(status);
        error
    }

    #[must_use]
    pub fn rate_limited(retry_after_seconds: Option<u64>) -> Self {
        let mut error = Self::new(TransportFailure::Throttled);
        error.retry_after_seconds = retry_after_seconds;
        error
    }

    #[must_use]
    pub fn blocked_env() -> Self {
        Self::new(TransportFailure::BlockedEnv)
    }

    #[must_use]
    pub fn timeout() -> Self {
        Self::new(TransportFailure::Timeout)
    }

    #[must_use]
    pub fn status_code(&self) -> Option<u16> {
        self.status_code
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("the provider request is not internally consistent")]
    InvalidRequest,
    #[error("the provider response request digest does not match")]
    RequestDigestMismatch,
    #[error("the provider response scope or permission fence does not match")]
    PageBindingMismatch,
    #[error("the provider response cursor is bound to a different request")]
    CursorBindingMismatch,
    #[error("the provider returned a duplicate item")]
    DuplicateItem,
    #[error("the provider returned more items than the bounded request allows")]
    ItemBoundExceeded,
    #[error("the provider returned more pages than the bounded request allows")]
    PaginationBoundExceeded,
    #[error("the provider returned a repeated page cursor")]
    PageLoop,
    #[error("the provider response digest or record was tampered")]
    RecordTampered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListServicesRequest {
    pub account_id: AccountId,
    pub region: Region,
    pub service_name: Option<ServiceName>,
    pub time_window: TimeWindow,
    pub bounds: ReadBounds,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub cursor: Option<OpaquePageToken>,
}

impl ListServicesRequest {
    pub fn new(scope: &AwsApplicationSignalsScope, bounds: ReadBounds) -> Result<Self, ModelError> {
        scope.validate()?;
        bounds.validate()?;
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            service_name: scope.service_name.clone(),
            time_window: scope.time_window.clone(),
            bounds,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            cursor: None,
        })
    }

    pub fn from_parts(
        account_id: AccountId,
        region: Region,
        service_name: Option<ServiceName>,
        time_window: TimeWindow,
        bounds: ReadBounds,
        scope_digest: Digest,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let request = Self {
            account_id,
            region,
            service_name,
            time_window,
            bounds,
            scope_digest,
            permission_digest,
            cursor: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.time_window.validate()?;
        self.bounds.validate()?;
        if self.scope_digest.as_str().len() != 64 || self.permission_digest.as_str().len() != 64 {
            return Err(ModelError::InvalidDigest {
                field: "request fence",
            });
        }
        Ok(())
    }

    pub fn base_binding_digest(&self) -> Result<Digest, ModelError> {
        self.validate()?;
        digest_serializable(&(
            ListRequestMarker::ListServices,
            &self.account_id,
            &self.region,
            &self.service_name,
            &self.time_window,
            &self.bounds,
            &self.scope_digest,
            &self.permission_digest,
        ))
    }

    pub fn request_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            self.base_binding_digest()?,
            self.cursor.as_ref().map(OpaquePageToken::digest),
        ))
    }

    pub fn with_cursor(&self, cursor: Option<OpaquePageToken>) -> Result<Self, ModelError> {
        let binding = self.base_binding_digest()?;
        let cursor = cursor
            .map(|cursor| {
                if cursor
                    .binding_digest()
                    .is_some_and(|cursor_binding| cursor_binding != &binding)
                {
                    return Err(ModelError::CursorBindingMismatch);
                }
                Ok(if cursor.is_bound() {
                    cursor
                } else {
                    cursor.bind(binding)
                })
            })
            .transpose()?;
        Ok(Self {
            cursor,
            ..self.clone()
        })
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&OpaquePageToken> {
        self.cursor.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetServiceRequest {
    pub account_id: AccountId,
    pub region: Region,
    pub service_name: ServiceName,
    pub time_window: TimeWindow,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl GetServiceRequest {
    pub fn new(scope: &AwsApplicationSignalsScope) -> Result<Self, ModelError> {
        scope.validate()?;
        let service_name = scope.service_name.clone().ok_or(ModelError::InvalidScope)?;
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            service_name,
            time_window: scope.time_window.clone(),
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.time_window.validate()?;
        if self.scope_digest.as_str().len() != 64 || self.permission_digest.as_str().len() != 64 {
            return Err(ModelError::InvalidDigest {
                field: "request fence",
            });
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<Digest, ModelError> {
        self.validate()?;
        digest_serializable(&(
            ListRequestMarker::GetService,
            &self.account_id,
            &self.region,
            &self.service_name,
            &self.time_window,
            &self.scope_digest,
            &self.permission_digest,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListServiceLevelObjectivesRequest {
    pub account_id: AccountId,
    pub region: Region,
    pub service_name: ServiceName,
    pub time_window: TimeWindow,
    pub bounds: ReadBounds,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub cursor: Option<OpaquePageToken>,
}

impl ListServiceLevelObjectivesRequest {
    pub fn new(scope: &AwsApplicationSignalsScope, bounds: ReadBounds) -> Result<Self, ModelError> {
        scope.validate()?;
        bounds.validate()?;
        let service_name = scope.service_name.clone().ok_or(ModelError::InvalidScope)?;
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            service_name,
            time_window: scope.time_window.clone(),
            bounds,
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
            cursor: None,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.time_window.validate()?;
        self.bounds.validate()?;
        if self.scope_digest.as_str().len() != 64 || self.permission_digest.as_str().len() != 64 {
            return Err(ModelError::InvalidDigest {
                field: "request fence",
            });
        }
        Ok(())
    }

    pub fn base_binding_digest(&self) -> Result<Digest, ModelError> {
        self.validate()?;
        digest_serializable(&(
            ListRequestMarker::ListServiceLevelObjectives,
            &self.account_id,
            &self.region,
            &self.service_name,
            &self.time_window,
            &self.bounds,
            &self.scope_digest,
            &self.permission_digest,
        ))
    }

    pub fn request_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            self.base_binding_digest()?,
            self.cursor.as_ref().map(OpaquePageToken::digest),
        ))
    }

    pub fn with_cursor(&self, cursor: Option<OpaquePageToken>) -> Result<Self, ModelError> {
        let binding = self.base_binding_digest()?;
        let cursor = cursor
            .map(|cursor| {
                if cursor
                    .binding_digest()
                    .is_some_and(|cursor_binding| cursor_binding != &binding)
                {
                    return Err(ModelError::CursorBindingMismatch);
                }
                Ok(if cursor.is_bound() {
                    cursor
                } else {
                    cursor.bind(binding)
                })
            })
            .transpose()?;
        Ok(Self {
            cursor,
            ..self.clone()
        })
    }

    #[must_use]
    pub fn cursor(&self) -> Option<&OpaquePageToken> {
        self.cursor.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetServiceLevelObjectiveRequest {
    pub account_id: AccountId,
    pub region: Region,
    pub service_name: ServiceName,
    pub slo_id: SloId,
    pub operation_name: OperationName,
    pub time_window: TimeWindow,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
}

impl GetServiceLevelObjectiveRequest {
    pub fn new(scope: &AwsApplicationSignalsScope) -> Result<Self, ModelError> {
        scope.validate()?;
        Ok(Self {
            account_id: scope.account_id.clone(),
            region: scope.region.clone(),
            service_name: scope.service_name.clone().ok_or(ModelError::InvalidScope)?,
            slo_id: scope.slo_id.clone().ok_or(ModelError::InvalidScope)?,
            operation_name: scope
                .operation_name
                .clone()
                .ok_or(ModelError::InvalidScope)?,
            time_window: scope.time_window.clone(),
            scope_digest: scope.scope_digest.clone(),
            permission_digest: scope.permissions.permission_digest.clone(),
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.time_window.validate()?;
        if self.scope_digest.as_str().len() != 64 || self.permission_digest.as_str().len() != 64 {
            return Err(ModelError::InvalidDigest {
                field: "request fence",
            });
        }
        Ok(())
    }

    pub fn request_digest(&self) -> Result<Digest, ModelError> {
        self.validate()?;
        digest_serializable(&(
            ListRequestMarker::GetServiceLevelObjective,
            &self.account_id,
            &self.region,
            &self.service_name,
            &self.slo_id,
            &self.operation_name,
            &self.time_window,
            &self.scope_digest,
            &self.permission_digest,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AwsApplicationSignalsReadRequest {
    ListServices(ListServicesRequest),
    GetService(GetServiceRequest),
    ListServiceLevelObjectives(ListServiceLevelObjectivesRequest),
    GetServiceLevelObjective(GetServiceLevelObjectiveRequest),
}

impl AwsApplicationSignalsReadRequest {
    #[must_use]
    pub const fn operation(&self) -> ReadOperation {
        match self {
            Self::ListServices(_) => ReadOperation::ListServices,
            Self::GetService(_) => ReadOperation::GetService,
            Self::ListServiceLevelObjectives(_) => ReadOperation::ListServiceLevelObjectives,
            Self::GetServiceLevelObjective(_) => ReadOperation::GetServiceLevelObjective,
        }
    }

    pub fn request_digest(&self) -> Result<Digest, ModelError> {
        match self {
            Self::ListServices(request) => request.request_digest(),
            Self::GetService(request) => request.request_digest(),
            Self::ListServiceLevelObjectives(request) => request.request_digest(),
            Self::GetServiceLevelObjective(request) => request.request_digest(),
        }
    }

    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::ListServices(request) => &request.scope_digest,
            Self::GetService(request) => &request.scope_digest,
            Self::ListServiceLevelObjectives(request) => &request.scope_digest,
            Self::GetServiceLevelObjective(request) => &request.scope_digest,
        }
    }

    pub fn permission_digest(&self) -> &Digest {
        match self {
            Self::ListServices(request) => &request.permission_digest,
            Self::GetService(request) => &request.permission_digest,
            Self::ListServiceLevelObjectives(request) => &request.permission_digest,
            Self::GetServiceLevelObjective(request) => &request.permission_digest,
        }
    }

    pub fn time_window(&self) -> &TimeWindow {
        match self {
            Self::ListServices(request) => &request.time_window,
            Self::GetService(request) => &request.time_window,
            Self::ListServiceLevelObjectives(request) => &request.time_window,
            Self::GetServiceLevelObjective(request) => &request.time_window,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListServicesPage {
    pub services: Vec<ServiceSummary>,
    pub next_cursor: Option<OpaquePageToken>,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub status: EvidenceStatus,
}

impl ListServicesPage {
    pub fn new(
        request: &ListServicesRequest,
        services: Vec<ServiceSummary>,
        next_cursor: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        let status = if services.is_empty() {
            EvidenceStatus::NoData
        } else {
            EvidenceStatus::Complete
        };
        let binding = request.base_binding_digest()?;
        Ok(Self {
            services,
            next_cursor: next_cursor.map(|cursor| cursor.bind(binding)),
            request_digest: request.request_digest()?,
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            status,
        })
    }

    #[must_use]
    pub fn with_status(mut self, status: EvidenceStatus) -> Self {
        self.status = status;
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetServiceResponse {
    pub service: ServiceDetail,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub status: EvidenceStatus,
}

impl GetServiceResponse {
    pub fn new(
        request: &GetServiceRequest,
        service: ServiceDetail,
        status: EvidenceStatus,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            service,
            request_digest: request.request_digest()?,
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListServiceLevelObjectivesPage {
    pub slos: Vec<SloSummary>,
    pub next_cursor: Option<OpaquePageToken>,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub status: EvidenceStatus,
}

impl ListServiceLevelObjectivesPage {
    pub fn new(
        request: &ListServiceLevelObjectivesRequest,
        slos: Vec<SloSummary>,
        next_cursor: Option<OpaquePageToken>,
    ) -> Result<Self, ModelError> {
        let status = if slos.is_empty() {
            EvidenceStatus::NoData
        } else {
            EvidenceStatus::Complete
        };
        let binding = request.base_binding_digest()?;
        Ok(Self {
            slos,
            next_cursor: next_cursor.map(|cursor| cursor.bind(binding)),
            request_digest: request.request_digest()?,
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            status,
        })
    }

    #[must_use]
    pub fn with_status(mut self, status: EvidenceStatus) -> Self {
        self.status = status;
        self
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetServiceLevelObjectiveResponse {
    pub slo: SloDetail,
    pub request_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub status: EvidenceStatus,
}

impl GetServiceLevelObjectiveResponse {
    pub fn new(
        request: &GetServiceLevelObjectiveRequest,
        slo: SloDetail,
        status: EvidenceStatus,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            slo,
            request_digest: request.request_digest()?,
            scope_digest: request.scope_digest.clone(),
            permission_digest: request.permission_digest.clone(),
            status,
        })
    }
}

pub trait AwsApplicationSignalsTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_services(
        &mut self,
        request: &ListServicesRequest,
    ) -> Result<ListServicesPage, TransportError>;

    fn get_service(
        &mut self,
        request: &GetServiceRequest,
    ) -> Result<GetServiceResponse, TransportError>;

    fn list_service_level_objectives(
        &mut self,
        request: &ListServiceLevelObjectivesRequest,
    ) -> Result<ListServiceLevelObjectivesPage, TransportError>;

    fn get_service_level_objective(
        &mut self,
        request: &GetServiceLevelObjectiveRequest,
    ) -> Result<GetServiceLevelObjectiveResponse, TransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportCall {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
}

#[derive(Clone, Debug)]
pub struct RecordingAwsApplicationSignalsTransport {
    provenance: ProviderProvenance,
    list_services: VecDeque<Result<ListServicesPage, TransportError>>,
    get_services: VecDeque<Result<GetServiceResponse, TransportError>>,
    list_slos: VecDeque<Result<ListServiceLevelObjectivesPage, TransportError>>,
    get_slos: VecDeque<Result<GetServiceLevelObjectiveResponse, TransportError>>,
    calls: Vec<TransportCall>,
}

pub type FixtureAwsApplicationSignalsTransport = RecordingAwsApplicationSignalsTransport;
pub type LoopbackAwsApplicationSignalsTransport = RecordingAwsApplicationSignalsTransport;

impl Default for RecordingAwsApplicationSignalsTransport {
    fn default() -> Self {
        Self::recording()
    }
}

impl RecordingAwsApplicationSignalsTransport {
    #[must_use]
    pub fn new() -> Self {
        Self::recording()
    }

    #[must_use]
    pub fn recording() -> Self {
        Self {
            provenance: ProviderProvenance::Recording,
            list_services: VecDeque::new(),
            get_services: VecDeque::new(),
            list_slos: VecDeque::new(),
            get_slos: VecDeque::new(),
            calls: Vec::new(),
        }
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self {
            provenance: ProviderProvenance::Fixture,
            ..Self::recording()
        }
    }

    #[must_use]
    pub fn loopback() -> Self {
        Self {
            provenance: ProviderProvenance::Loopback,
            ..Self::recording()
        }
    }

    pub fn queue_list_services(&mut self, response: Result<ListServicesPage, TransportError>) {
        self.list_services.push_back(response);
    }

    pub fn queue_get_service(&mut self, response: Result<GetServiceResponse, TransportError>) {
        self.get_services.push_back(response);
    }

    pub fn queue_list_service_level_objectives(
        &mut self,
        response: Result<ListServiceLevelObjectivesPage, TransportError>,
    ) {
        self.list_slos.push_back(response);
    }

    pub fn queue_get_service_level_objective(
        &mut self,
        response: Result<GetServiceLevelObjectiveResponse, TransportError>,
    ) {
        self.get_slos.push_back(response);
    }

    #[must_use]
    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }

    fn missing_response() -> TransportError {
        TransportError::new(TransportFailure::Malformed)
    }

    fn push_call(
        &mut self,
        operation: ReadOperation,
        request_digest: Result<Digest, ModelError>,
        cursor_digest: Option<Digest>,
    ) -> Result<(), TransportError> {
        self.calls.push(TransportCall {
            operation,
            request_digest: request_digest.map_err(|_| Self::missing_response())?,
            cursor_digest,
        });
        Ok(())
    }
}

impl AwsApplicationSignalsTransport for RecordingAwsApplicationSignalsTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn list_services(
        &mut self,
        request: &ListServicesRequest,
    ) -> Result<ListServicesPage, TransportError> {
        self.push_call(
            ReadOperation::ListServices,
            request.request_digest(),
            request.cursor().map(OpaquePageToken::digest),
        )?;
        self.list_services
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn get_service(
        &mut self,
        request: &GetServiceRequest,
    ) -> Result<GetServiceResponse, TransportError> {
        self.push_call(ReadOperation::GetService, request.request_digest(), None)?;
        self.get_services
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn list_service_level_objectives(
        &mut self,
        request: &ListServiceLevelObjectivesRequest,
    ) -> Result<ListServiceLevelObjectivesPage, TransportError> {
        self.push_call(
            ReadOperation::ListServiceLevelObjectives,
            request.request_digest(),
            request.cursor().map(OpaquePageToken::digest),
        )?;
        self.list_slos
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn get_service_level_objective(
        &mut self,
        request: &GetServiceLevelObjectiveRequest,
    ) -> Result<GetServiceLevelObjectiveResponse, TransportError> {
        self.push_call(
            ReadOperation::GetServiceLevelObjective,
            request.request_digest(),
            None,
        )?;
        self.get_slos
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAwsApplicationSignalsTransport;
pub type BlockedEnvTransport = BlockedEnvAwsApplicationSignalsTransport;

impl AwsApplicationSignalsTransport for BlockedEnvAwsApplicationSignalsTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_services(
        &mut self,
        _request: &ListServicesRequest,
    ) -> Result<ListServicesPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_service(
        &mut self,
        _request: &GetServiceRequest,
    ) -> Result<GetServiceResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn list_service_level_objectives(
        &mut self,
        _request: &ListServiceLevelObjectivesRequest,
    ) -> Result<ListServiceLevelObjectivesPage, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get_service_level_objective(
        &mut self,
        _request: &GetServiceLevelObjectiveRequest,
    ) -> Result<GetServiceLevelObjectiveResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsApplicationSignalsProviderDefinition {
    pub id: String,
    pub service_id: String,
    pub provider_version: String,
    pub provider_revision: String,
    pub api_version: String,
    pub implementation: String,
    pub allowed_operations: Vec<ReadOperation>,
    pub iam_permissions: Vec<String>,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub opaque_pagination: bool,
    pub max_page_size: u16,
    pub max_page_count: u16,
    pub max_item_count: usize,
}

impl AwsApplicationSignalsProviderDefinition {
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: crate::AWS_APPLICATION_SIGNALS_PROVIDER_ID.to_owned(),
            service_id: AWS_APPLICATION_SIGNALS_SERVICE_ID.to_owned(),
            provider_version: AWS_APPLICATION_SIGNALS_PLUGIN_VERSION_TEXT.to_owned(),
            provider_revision: AWS_APPLICATION_SIGNALS_PROVIDER_REVISION.to_owned(),
            api_version: AWS_APPLICATION_SIGNALS_API_VERSION.to_owned(),
            implementation: crate::AWS_APPLICATION_SIGNALS_PROVIDER_NAME.to_owned(),
            allowed_operations: ReadOperation::ALL.to_vec(),
            iam_permissions: vec![
                "application-signals:ListServices".to_owned(),
                "application-signals:GetService".to_owned(),
                "application-signals:ListServiceLevelObjectives".to_owned(),
                "application-signals:GetServiceLevelObjective".to_owned(),
            ],
            read_only: true,
            native: false,
            connected: false,
            opaque_pagination: true,
            max_page_size: crate::model::MAX_PAGE_SIZE,
            max_page_count: crate::model::MAX_PAGE_COUNT,
            max_item_count: crate::model::MAX_ITEM_COUNT,
        }
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self != &Self::new() {
            return Err(ProviderError::InvalidRequest);
        }
        Ok(())
    }

    pub fn provider_digest(&self) -> Digest {
        digest_serializable(self).expect("typed provider definition serializes")
    }
}

impl Default for AwsApplicationSignalsProviderDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AwsApplicationSignalsRecordPage {
    Services {
        services: Vec<ServiceSummary>,
        next_cursor_digest: Option<Digest>,
        status: EvidenceStatus,
        response_digest: Digest,
    },
    Service {
        service: ServiceDetail,
        status: EvidenceStatus,
        response_digest: Digest,
    },
    ServiceLevelObjectives {
        slos: Vec<SloSummary>,
        next_cursor_digest: Option<Digest>,
        status: EvidenceStatus,
        response_digest: Digest,
    },
    ServiceLevelObjective {
        slo: SloDetail,
        status: EvidenceStatus,
        response_digest: Digest,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsApplicationSignalsReadRecord {
    pub operation: ReadOperation,
    pub request_digest: Digest,
    pub pages: Vec<AwsApplicationSignalsRecordPage>,
    pub page_count: usize,
    pub item_count: usize,
    pub complete: bool,
    pub status: EvidenceStatus,
    pub provenance: ProviderProvenance,
    pub redactions: crate::RedactionSummary,
    pub record_digest: Digest,
}

impl AwsApplicationSignalsReadRecord {
    fn new(
        operation: ReadOperation,
        request_digest: Digest,
        pages: Vec<AwsApplicationSignalsRecordPage>,
        item_count: usize,
        complete: bool,
        status: EvidenceStatus,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderError> {
        let mut record = Self {
            operation,
            request_digest,
            page_count: pages.len(),
            pages,
            item_count,
            complete,
            status,
            provenance,
            redactions: crate::RedactionSummary::layer1(),
            record_digest: Digest::from_text("pending-record-digest"),
        };
        record.record_digest = record.compute_digest()?;
        Ok(record)
    }

    fn compute_digest(&self) -> Result<Digest, ProviderError> {
        Ok(digest_serializable(&(
            self.operation,
            &self.request_digest,
            &self.pages,
            self.page_count,
            self.item_count,
            self.complete,
            self.status,
            self.provenance,
            &self.redactions,
        ))?)
    }

    pub fn verify(&self) -> Result<(), ProviderError> {
        self.redactions.validate()?;
        if self.page_count != self.pages.len()
            || self.record_digest != self.compute_digest()?
            || self.pages.is_empty()
        {
            return Err(ProviderError::RecordTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn cursor_digests(&self) -> Vec<Digest> {
        self.pages
            .iter()
            .filter_map(|page| match page {
                AwsApplicationSignalsRecordPage::Services {
                    next_cursor_digest, ..
                }
                | AwsApplicationSignalsRecordPage::ServiceLevelObjectives {
                    next_cursor_digest,
                    ..
                } => next_cursor_digest.clone(),
                AwsApplicationSignalsRecordPage::Service { .. }
                | AwsApplicationSignalsRecordPage::ServiceLevelObjective { .. } => None,
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct AwsApplicationSignalsProvider<T = BlockedEnvAwsApplicationSignalsTransport>
where
    T: AwsApplicationSignalsTransport,
{
    definition: AwsApplicationSignalsProviderDefinition,
    transport: T,
}

impl Default for AwsApplicationSignalsProvider<BlockedEnvAwsApplicationSignalsTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvAwsApplicationSignalsTransport)
            .expect("static blocked-environment provider definition")
    }
}

impl<T> AwsApplicationSignalsProvider<T>
where
    T: AwsApplicationSignalsTransport,
{
    pub fn new(transport: T) -> Result<Self, ProviderError> {
        let definition = AwsApplicationSignalsProviderDefinition::new();
        definition.validate()?;
        if transport.provenance().native() || transport.provenance().connected() {
            return Err(ProviderError::InvalidRequest);
        }
        Ok(Self {
            definition,
            transport,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &AwsApplicationSignalsProviderDefinition {
        &self.definition
    }

    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    #[must_use]
    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: AwsApplicationSignalsReadRequest,
    ) -> Result<AwsApplicationSignalsReadRecord, ProviderError> {
        match request {
            AwsApplicationSignalsReadRequest::ListServices(request) => {
                self.read_list_services(request)
            }
            AwsApplicationSignalsReadRequest::GetService(request) => self.read_get_service(request),
            AwsApplicationSignalsReadRequest::ListServiceLevelObjectives(request) => {
                self.read_list_slos(request)
            }
            AwsApplicationSignalsReadRequest::GetServiceLevelObjective(request) => {
                self.read_get_slo(request)
            }
        }
    }

    pub fn list_services(
        &mut self,
        request: ListServicesRequest,
    ) -> Result<AwsApplicationSignalsReadRecord, ProviderError> {
        self.read(AwsApplicationSignalsReadRequest::ListServices(request))
    }

    pub fn get_service(
        &mut self,
        request: GetServiceRequest,
    ) -> Result<AwsApplicationSignalsReadRecord, ProviderError> {
        self.read(AwsApplicationSignalsReadRequest::GetService(request))
    }

    pub fn list_service_level_objectives(
        &mut self,
        request: ListServiceLevelObjectivesRequest,
    ) -> Result<AwsApplicationSignalsReadRecord, ProviderError> {
        self.read(AwsApplicationSignalsReadRequest::ListServiceLevelObjectives(request))
    }

    pub fn get_service_level_objective(
        &mut self,
        request: GetServiceLevelObjectiveRequest,
    ) -> Result<AwsApplicationSignalsReadRecord, ProviderError> {
        self.read(AwsApplicationSignalsReadRequest::GetServiceLevelObjective(
            request,
        ))
    }

    fn read_list_services(
        &mut self,
        request: ListServicesRequest,
    ) -> Result<AwsApplicationSignalsReadRecord, ProviderError> {
        request.validate()?;
        let request_digest = request.request_digest()?;
        let mut current = request;
        let mut pages = Vec::new();
        let mut seen = BTreeSet::new();
        let mut seen_cursors = BTreeSet::new();
        let mut services = Vec::new();
        let mut status = EvidenceStatus::Complete;
        let mut complete = false;

        for _ in 0..current.bounds.max_pages {
            let page = self
                .transport
                .list_services(&current)
                .map_err(ProviderError::Transport)?;
            Self::validate_page_binding(
                page.request_digest.clone(),
                page.scope_digest.clone(),
                page.permission_digest.clone(),
                current.request_digest()?,
                &current.scope_digest,
                &current.permission_digest,
            )?;
            if page.services.len() > usize::from(current.bounds.max_results) {
                return Err(ProviderError::ItemBoundExceeded);
            }
            for service in &page.services {
                Self::validate_service_summary(service, &current)?;
                if !seen.insert((
                    service.account_id.clone(),
                    service.region.clone(),
                    service.service_name.clone(),
                )) {
                    return Err(ProviderError::DuplicateItem);
                }
                services.push(service.clone());
            }
            status = merge_status(status, page.status, !services.is_empty());
            let next_cursor = page.next_cursor.clone();
            let response_digest = digest_serializable(&(
                &page.services,
                &next_cursor.as_ref().map(OpaquePageToken::digest),
                page.status,
            ))?;
            pages.push(AwsApplicationSignalsRecordPage::Services {
                services: page.services,
                next_cursor_digest: next_cursor.as_ref().map(OpaquePageToken::digest),
                status: page.status,
                response_digest,
            });
            if services.len() > current.bounds.max_items {
                return Err(ProviderError::ItemBoundExceeded);
            }
            if let Some(cursor) = next_cursor {
                let cursor_digest = cursor.digest();
                if !seen_cursors.insert(cursor_digest) {
                    return Err(ProviderError::PageLoop);
                }
                current = current
                    .with_cursor(Some(cursor))
                    .map_err(|error| match error {
                        ModelError::CursorBindingMismatch => ProviderError::CursorBindingMismatch,
                        other => ProviderError::Model(other),
                    })?;
            } else {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(ProviderError::PaginationBoundExceeded);
        }
        AwsApplicationSignalsReadRecord::new(
            ReadOperation::ListServices,
            request_digest,
            pages,
            services.len(),
            complete,
            finalize_status(status, services.is_empty()),
            self.provenance(),
        )
    }

    fn read_get_service(
        &mut self,
        request: GetServiceRequest,
    ) -> Result<AwsApplicationSignalsReadRecord, ProviderError> {
        request.validate()?;
        let request_digest = request.request_digest()?;
        let response = self
            .transport
            .get_service(&request)
            .map_err(ProviderError::Transport)?;
        Self::validate_page_binding(
            response.request_digest.clone(),
            response.scope_digest.clone(),
            response.permission_digest.clone(),
            request_digest.clone(),
            &request.scope_digest,
            &request.permission_digest,
        )?;
        Self::validate_service_detail(&response.service, &request)?;
        let response_digest = digest_serializable(&(&response.service, response.status))?;
        AwsApplicationSignalsReadRecord::new(
            ReadOperation::GetService,
            request_digest,
            vec![AwsApplicationSignalsRecordPage::Service {
                service: response.service,
                status: response.status,
                response_digest,
            }],
            1,
            true,
            response.status,
            self.provenance(),
        )
    }

    fn read_list_slos(
        &mut self,
        request: ListServiceLevelObjectivesRequest,
    ) -> Result<AwsApplicationSignalsReadRecord, ProviderError> {
        request.validate()?;
        let request_digest = request.request_digest()?;
        let mut current = request;
        let mut pages = Vec::new();
        let mut seen = BTreeSet::new();
        let mut seen_cursors = BTreeSet::new();
        let mut slos = Vec::new();
        let mut status = EvidenceStatus::Complete;
        let mut complete = false;

        for _ in 0..current.bounds.max_pages {
            let page = self
                .transport
                .list_service_level_objectives(&current)
                .map_err(ProviderError::Transport)?;
            Self::validate_page_binding(
                page.request_digest.clone(),
                page.scope_digest.clone(),
                page.permission_digest.clone(),
                current.request_digest()?,
                &current.scope_digest,
                &current.permission_digest,
            )?;
            if page.slos.len() > usize::from(current.bounds.max_results) {
                return Err(ProviderError::ItemBoundExceeded);
            }
            for slo in &page.slos {
                Self::validate_slo_summary(slo, &current)?;
                if !seen.insert((
                    slo.account_id.clone(),
                    slo.region.clone(),
                    slo.service_name.clone(),
                    slo.slo_id.clone(),
                    slo.operation_name.clone(),
                )) {
                    return Err(ProviderError::DuplicateItem);
                }
                slos.push(slo.clone());
            }
            status = merge_status(status, page.status, !slos.is_empty());
            let next_cursor = page.next_cursor.clone();
            let response_digest = digest_serializable(&(
                &page.slos,
                &next_cursor.as_ref().map(OpaquePageToken::digest),
                page.status,
            ))?;
            pages.push(AwsApplicationSignalsRecordPage::ServiceLevelObjectives {
                slos: page.slos,
                next_cursor_digest: next_cursor.as_ref().map(OpaquePageToken::digest),
                status: page.status,
                response_digest,
            });
            if slos.len() > current.bounds.max_items {
                return Err(ProviderError::ItemBoundExceeded);
            }
            if let Some(cursor) = next_cursor {
                let cursor_digest = cursor.digest();
                if !seen_cursors.insert(cursor_digest) {
                    return Err(ProviderError::PageLoop);
                }
                current = current
                    .with_cursor(Some(cursor))
                    .map_err(|error| match error {
                        ModelError::CursorBindingMismatch => ProviderError::CursorBindingMismatch,
                        other => ProviderError::Model(other),
                    })?;
            } else {
                complete = true;
                break;
            }
        }
        if !complete {
            return Err(ProviderError::PaginationBoundExceeded);
        }
        AwsApplicationSignalsReadRecord::new(
            ReadOperation::ListServiceLevelObjectives,
            request_digest,
            pages,
            slos.len(),
            complete,
            finalize_status(status, slos.is_empty()),
            self.provenance(),
        )
    }

    fn read_get_slo(
        &mut self,
        request: GetServiceLevelObjectiveRequest,
    ) -> Result<AwsApplicationSignalsReadRecord, ProviderError> {
        request.validate()?;
        let request_digest = request.request_digest()?;
        let response = self
            .transport
            .get_service_level_objective(&request)
            .map_err(ProviderError::Transport)?;
        Self::validate_page_binding(
            response.request_digest.clone(),
            response.scope_digest.clone(),
            response.permission_digest.clone(),
            request_digest.clone(),
            &request.scope_digest,
            &request.permission_digest,
        )?;
        Self::validate_slo_detail(&response.slo, &request)?;
        let response_digest = digest_serializable(&(&response.slo, response.status))?;
        AwsApplicationSignalsReadRecord::new(
            ReadOperation::GetServiceLevelObjective,
            request_digest,
            vec![AwsApplicationSignalsRecordPage::ServiceLevelObjective {
                slo: response.slo,
                status: response.status,
                response_digest,
            }],
            1,
            true,
            response.status,
            self.provenance(),
        )
    }

    fn validate_page_binding(
        response_request_digest: Digest,
        response_scope_digest: Digest,
        response_permission_digest: Digest,
        request_digest: Digest,
        scope_digest: &Digest,
        permission_digest: &Digest,
    ) -> Result<(), ProviderError> {
        if response_request_digest != request_digest
            || response_scope_digest != *scope_digest
            || response_permission_digest != *permission_digest
        {
            return Err(ProviderError::PageBindingMismatch);
        }
        Ok(())
    }

    fn validate_service_summary(
        service: &ServiceSummary,
        request: &ListServicesRequest,
    ) -> Result<(), ProviderError> {
        service.validate()?;
        if service.account_id != request.account_id
            || service.region != request.region
            || request
                .service_name
                .as_ref()
                .is_some_and(|expected| expected != &service.service_name)
        {
            return Err(ProviderError::PageBindingMismatch);
        }
        Ok(())
    }

    fn validate_service_detail(
        service: &ServiceDetail,
        request: &GetServiceRequest,
    ) -> Result<(), ProviderError> {
        service.validate()?;
        if service.summary.account_id != request.account_id
            || service.summary.region != request.region
            || service.summary.service_name != request.service_name
        {
            return Err(ProviderError::PageBindingMismatch);
        }
        if service
            .operations
            .iter()
            .any(|operation| operation.as_str().is_empty())
        {
            return Err(ProviderError::PageBindingMismatch);
        }
        Ok(())
    }

    fn validate_slo_summary(
        slo: &SloSummary,
        request: &ListServiceLevelObjectivesRequest,
    ) -> Result<(), ProviderError> {
        slo.validate()?;
        if slo.account_id != request.account_id
            || slo.region != request.region
            || slo.service_name != request.service_name
        {
            return Err(ProviderError::PageBindingMismatch);
        }
        Ok(())
    }

    fn validate_slo_detail(
        slo: &SloDetail,
        request: &GetServiceLevelObjectiveRequest,
    ) -> Result<(), ProviderError> {
        slo.validate()?;
        if slo.summary.account_id != request.account_id
            || slo.summary.region != request.region
            || slo.summary.service_name != request.service_name
            || slo.summary.slo_id != request.slo_id
            || slo.summary.operation_name != request.operation_name
            || slo.window != request.time_window
        {
            return Err(ProviderError::PageBindingMismatch);
        }
        Ok(())
    }
}

fn merge_status(current: EvidenceStatus, next: EvidenceStatus, has_items: bool) -> EvidenceStatus {
    match (current, next) {
        (EvidenceStatus::ProviderUnknown, _) | (_, EvidenceStatus::ProviderUnknown) => {
            EvidenceStatus::ProviderUnknown
        }
        (EvidenceStatus::AccessLost, _) | (_, EvidenceStatus::AccessLost) => {
            EvidenceStatus::AccessLost
        }
        (EvidenceStatus::Expired, _) | (_, EvidenceStatus::Expired) => EvidenceStatus::Expired,
        (EvidenceStatus::Partial, _) | (_, EvidenceStatus::Partial) => EvidenceStatus::Partial,
        (EvidenceStatus::NoData, EvidenceStatus::Complete) if has_items => EvidenceStatus::Complete,
        (EvidenceStatus::Complete, EvidenceStatus::NoData) if has_items => EvidenceStatus::Complete,
        (_, EvidenceStatus::NoData) if has_items => EvidenceStatus::Complete,
        (_, next) => next,
    }
}

fn finalize_status(status: EvidenceStatus, empty: bool) -> EvidenceStatus {
    if empty && status == EvidenceStatus::Complete {
        EvidenceStatus::NoData
    } else {
        status
    }
}

/// Marker values are intentionally not provider API payloads.
#[derive(Clone, Copy, Debug, Serialize)]
enum ListRequestMarker {
    ListServices,
    GetService,
    ListServiceLevelObjectives,
    GetServiceLevelObjective,
}
