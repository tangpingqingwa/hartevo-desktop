use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    SAMSARA_API_VERSION, SAMSARA_FLEET_RESULT_PROVIDER_ID, SAMSARA_FLEET_RESULT_PROVIDER_VERSION,
    SAMSARA_FLEET_RESULT_SCHEMA_VERSION, canonical_digest,
    model::{
        AlertId, AlertRecord, Digest, DvirRecord, EquipmentId, MAX_OBSERVATION_WINDOW_SECONDS,
        MAX_PAGE_SIZE, MAX_PAGES, MAX_RECORDS_PER_READ, MAX_RESPONSE_BYTES, MaintenanceRecord,
        ModelError, OpaqueCursor, PageInfo, SafetyEventRecord, SamsaraFleetScope, SecretReference,
        TagId, TimeWindow, TripRecord, VehicleId, VehicleRecord,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SamsaraEndpoint {
    Vehicles,
    VehicleTrips,
    SafetySignals,
    MaintenanceStatus,
    DvirStatus,
    Alerts,
}

pub type SamsaraEndpointKind = SamsaraEndpoint;

impl SamsaraEndpoint {
    pub const fn path(self) -> &'static str {
        match self {
            Self::Vehicles => "/fleet/vehicles",
            Self::VehicleTrips => "/trips/stream",
            Self::SafetySignals => "/safety-events/stream",
            Self::MaintenanceStatus => "/v1/fleet/maintenance/list",
            Self::DvirStatus => "/fleet/dvirs/history",
            Self::Alerts => "/alerts/incidents/stream",
        }
    }

    pub const fn operation(self) -> &'static str {
        match self {
            Self::Vehicles => "vehicles",
            Self::VehicleTrips => "vehicle_trips",
            Self::SafetySignals => "safety_signals",
            Self::MaintenanceStatus => "maintenance_status",
            Self::DvirStatus => "dvir_status",
            Self::Alerts => "bounded_alerts",
        }
    }

    pub const fn requires_window(self) -> bool {
        matches!(
            self,
            Self::VehicleTrips | Self::SafetySignals | Self::DvirStatus | Self::Alerts
        )
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("Samsara provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native Samsara provider")]
    NativeProviderForbidden,
    #[error("Samsara provider identity is invalid")]
    InvalidIdentity,
    #[error("Samsara SecretReference is bound to a different scope")]
    SecretScopeMismatch,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub allowed_endpoints: Vec<String>,
    pub read_only: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
}

impl SamsaraProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        let allowed_endpoints = [
            SamsaraEndpoint::Vehicles,
            SamsaraEndpoint::VehicleTrips,
            SamsaraEndpoint::SafetySignals,
            SamsaraEndpoint::MaintenanceStatus,
            SamsaraEndpoint::DvirStatus,
            SamsaraEndpoint::Alerts,
        ]
        .into_iter()
        .map(|endpoint| endpoint.operation().to_owned())
        .collect::<Vec<_>>();
        let capability_digest = Digest::from_fields(
            "samsara-provider-capability/v1",
            &[
                SAMSARA_FLEET_RESULT_SCHEMA_VERSION.to_owned(),
                SAMSARA_FLEET_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                format!("{provenance:?}"),
                allowed_endpoints.join(","),
                "read_only=true".to_owned(),
                "live_execution=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: SAMSARA_FLEET_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: SAMSARA_FLEET_RESULT_PROVIDER_ID.to_owned(),
            provider_version,
            api_version: SAMSARA_API_VERSION.to_owned(),
            capability_digest,
            provenance,
            allowed_endpoints,
            read_only: true,
            live_execution: false,
            native: false,
            connected: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub const fn is_native(&self) -> bool {
        self.native
    }

    pub const fn is_connected(&self) -> bool {
        self.connected
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportErrorKind {
    BlockedEnv,
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    Timeout,
    ServerFailure,
    ResponseTooLarge,
    InvalidResponse,
    ScopeMismatch,
    SecretRevoked,
    QueueExhausted,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    #[error("BLOCKED_ENV: native Samsara credentials and HTTPS transport are unavailable")]
    BlockedEnv,
    #[error("Samsara returned HTTP 401")]
    Unauthorized,
    #[error("Samsara returned HTTP 403")]
    Forbidden,
    #[error("Samsara returned HTTP 404")]
    NotFound,
    #[error("Samsara returned HTTP 429")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("Samsara request timed out")]
    Timeout,
    #[error("Samsara returned HTTP {status}")]
    ServerFailure { status: u16 },
    #[error("Samsara response exceeded the Layer-1 byte bound")]
    ResponseTooLarge,
    #[error("Samsara response did not match the allowlisted typed endpoint")]
    InvalidResponse,
    #[error("Samsara request or response crossed the registered scope fence")]
    ScopeMismatch,
    #[error("Samsara SecretReference is revoked")]
    SecretRevoked,
    #[error("recording transport has no queued response")]
    QueueExhausted,
}

impl TransportError {
    pub const fn kind(&self) -> TransportErrorKind {
        match self {
            Self::BlockedEnv => TransportErrorKind::BlockedEnv,
            Self::Unauthorized => TransportErrorKind::Unauthorized,
            Self::Forbidden => TransportErrorKind::Forbidden,
            Self::NotFound => TransportErrorKind::NotFound,
            Self::RateLimited { .. } => TransportErrorKind::RateLimited,
            Self::Timeout => TransportErrorKind::Timeout,
            Self::ServerFailure { .. } => TransportErrorKind::ServerFailure,
            Self::ResponseTooLarge => TransportErrorKind::ResponseTooLarge,
            Self::InvalidResponse => TransportErrorKind::InvalidResponse,
            Self::ScopeMismatch => TransportErrorKind::ScopeMismatch,
            Self::SecretRevoked => TransportErrorKind::SecretRevoked,
            Self::QueueExhausted => TransportErrorKind::QueueExhausted,
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status } => Some(*status),
            _ => None,
        }
    }

    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::Timeout | Self::ServerFailure { .. }
        )
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => *retry_after_seconds,
            _ => None,
        }
    }

    pub const fn access_lost(&self) -> bool {
        matches!(self, Self::Unauthorized | Self::Forbidden)
    }

    pub const fn blocked_env(&self) -> bool {
        matches!(self, Self::BlockedEnv)
    }

    pub fn diagnostic_digest(&self) -> Digest {
        Digest::from_text(format!("{:?}:{:?}", self.kind(), self.status_code()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraReadOptions {
    window: TimeWindow,
    page: u16,
    page_size: u16,
    cursor: Option<OpaqueCursor>,
}

impl SamsaraReadOptions {
    pub fn new(window: TimeWindow) -> Self {
        Self {
            window,
            page: 1,
            page_size: MAX_PAGE_SIZE,
            cursor: None,
        }
    }

    pub fn with_page(mut self, page: u16) -> Result<Self, ModelError> {
        if page == 0 || page > MAX_PAGES {
            Err(ModelError::InvalidScope)
        } else {
            self.page = page;
            Ok(self)
        }
    }

    pub fn with_page_size(mut self, page_size: u16) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            Err(ModelError::InvalidScope)
        } else {
            self.page_size = page_size;
            Ok(self)
        }
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: OpaqueCursor) -> Self {
        self.cursor = Some(cursor);
        self
    }

    pub const fn window(&self) -> TimeWindow {
        self.window
    }

    pub const fn page(&self) -> u16 {
        self.page
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraHttpRequest {
    method: String,
    endpoint: SamsaraEndpoint,
    path_and_query: String,
    api_version: String,
    organization_digest: Digest,
    scope_digest: Digest,
    page: u16,
    page_size: u16,
    cursor_digest: Option<Digest>,
    window: TimeWindow,
    max_response_bytes: usize,
}

impl SamsaraHttpRequest {
    pub fn new(
        scope: &SamsaraFleetScope,
        endpoint: SamsaraEndpoint,
        options: &SamsaraReadOptions,
    ) -> Result<Self, TransportError> {
        if options.window().duration_seconds() > MAX_OBSERVATION_WINDOW_SECONDS
            || options.page() > MAX_PAGES
            || options.page_size() > MAX_PAGE_SIZE
        {
            return Err(TransportError::ScopeMismatch);
        }
        if endpoint.requires_window() && options.window().duration_seconds() <= 0 {
            return Err(TransportError::ScopeMismatch);
        }
        let scope_window = match endpoint {
            SamsaraEndpoint::Vehicles => None,
            SamsaraEndpoint::VehicleTrips => Some(scope.trips().window),
            SamsaraEndpoint::SafetySignals => Some(scope.safety_events().window),
            SamsaraEndpoint::MaintenanceStatus => Some(scope.maintenance().window),
            SamsaraEndpoint::DvirStatus => Some(scope.dvir().window),
            SamsaraEndpoint::Alerts => Some(scope.alerts().window),
        };
        if scope_window.is_some_and(|allowed| !window_contains(allowed, options.window())) {
            return Err(TransportError::ScopeMismatch);
        }
        if endpoint == SamsaraEndpoint::Alerts && options.page_size() > scope.alerts().max_alerts {
            return Err(TransportError::ScopeMismatch);
        }
        let path_and_query = build_path_and_query(scope, endpoint, options);
        Ok(Self {
            method: "GET".to_owned(),
            endpoint,
            path_and_query,
            api_version: SAMSARA_API_VERSION.to_owned(),
            organization_digest: scope.organization().digest(),
            scope_digest: scope.scope_digest().clone(),
            page: options.page(),
            page_size: options.page_size(),
            cursor_digest: options.cursor().map(|cursor| cursor.digest().clone()),
            window: options.window(),
            max_response_bytes: MAX_RESPONSE_BYTES,
        })
    }

    pub const fn endpoint(&self) -> SamsaraEndpoint {
        self.endpoint
    }

    pub const fn method(&self) -> &'static str {
        "GET"
    }

    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub fn organization_digest(&self) -> &Digest {
        &self.organization_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn page(&self) -> u16 {
        self.page
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn cursor_digest(&self) -> Option<&Digest> {
        self.cursor_digest.as_ref()
    }

    pub const fn window(&self) -> TimeWindow {
        self.window
    }

    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

fn window_contains(outer: TimeWindow, inner: TimeWindow) -> bool {
    inner.start_epoch_seconds() >= outer.start_epoch_seconds()
        && inner.end_epoch_seconds() <= outer.end_epoch_seconds()
}

fn build_path_and_query(
    scope: &SamsaraFleetScope,
    endpoint: SamsaraEndpoint,
    options: &SamsaraReadOptions,
) -> String {
    let mut query = vec![
        format!("limit={}", options.page_size()),
        format!("page={}", options.page()),
    ];
    if let Some(cursor) = options.cursor() {
        query.push(format!("afterDigest={}", cursor.digest().as_str()));
    }
    if !scope.tags().tag_ids.is_empty() {
        let tags = scope
            .tags()
            .tag_ids
            .iter()
            .map(TagId::as_str)
            .collect::<Vec<_>>()
            .join(",");
        query.push(format!("tagIds={tags}"));
    }
    match endpoint {
        SamsaraEndpoint::Vehicles => {}
        SamsaraEndpoint::VehicleTrips | SamsaraEndpoint::SafetySignals => {
            let vehicles = scope
                .vehicles()
                .vehicle_ids
                .iter()
                .map(VehicleId::as_str)
                .collect::<Vec<_>>()
                .join(",");
            if !vehicles.is_empty() {
                query.push(format!("vehicleIds={vehicles}"));
            }
        }
        SamsaraEndpoint::MaintenanceStatus | SamsaraEndpoint::DvirStatus => {
            let vehicles = scope
                .vehicles()
                .vehicle_ids
                .iter()
                .map(VehicleId::as_str)
                .collect::<Vec<_>>()
                .join(",");
            let equipment = scope
                .equipment()
                .equipment_ids
                .iter()
                .map(EquipmentId::as_str)
                .collect::<Vec<_>>()
                .join(",");
            if !vehicles.is_empty() {
                query.push(format!("vehicleIds={vehicles}"));
            }
            if !equipment.is_empty() {
                query.push(format!("equipmentIds={equipment}"));
            }
        }
        SamsaraEndpoint::Alerts => {
            query.push(format!("maxAlerts={}", scope.alerts().max_alerts));
            if !scope.alerts().alert_ids.is_empty() {
                let alerts = scope
                    .alerts()
                    .alert_ids
                    .iter()
                    .map(AlertId::as_str)
                    .collect::<Vec<_>>()
                    .join(",");
                query.push(format!("configurationIds={alerts}"));
            }
        }
    }
    if endpoint.requires_window() {
        query.push(format!(
            "startTime={}&endTime={}",
            options.window().start_epoch_seconds(),
            options.window().end_epoch_seconds()
        ));
    }
    format!("{}?{}", endpoint.path(), query.join("&"))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum SamsaraResponseBody {
    Vehicles {
        records: Vec<VehicleRecord>,
        page: PageInfo,
    },
    VehicleTrips {
        records: Vec<TripRecord>,
        page: PageInfo,
    },
    SafetySignals {
        records: Vec<SafetyEventRecord>,
        page: PageInfo,
    },
    MaintenanceStatus {
        records: Vec<MaintenanceRecord>,
        page: PageInfo,
    },
    DvirStatus {
        records: Vec<DvirRecord>,
        page: PageInfo,
    },
    Alerts {
        records: Vec<AlertRecord>,
        page: PageInfo,
    },
}

impl SamsaraResponseBody {
    pub const fn endpoint(&self) -> SamsaraEndpoint {
        match self {
            Self::Vehicles { .. } => SamsaraEndpoint::Vehicles,
            Self::VehicleTrips { .. } => SamsaraEndpoint::VehicleTrips,
            Self::SafetySignals { .. } => SamsaraEndpoint::SafetySignals,
            Self::MaintenanceStatus { .. } => SamsaraEndpoint::MaintenanceStatus,
            Self::DvirStatus { .. } => SamsaraEndpoint::DvirStatus,
            Self::Alerts { .. } => SamsaraEndpoint::Alerts,
        }
    }

    pub fn page(&self) -> &PageInfo {
        match self {
            Self::Vehicles { page, .. }
            | Self::VehicleTrips { page, .. }
            | Self::SafetySignals { page, .. }
            | Self::MaintenanceStatus { page, .. }
            | Self::DvirStatus { page, .. }
            | Self::Alerts { page, .. } => page,
        }
    }

    pub const fn record_count(&self) -> usize {
        match self {
            Self::Vehicles { records, .. } => records.len(),
            Self::VehicleTrips { records, .. } => records.len(),
            Self::SafetySignals { records, .. } => records.len(),
            Self::MaintenanceStatus { records, .. } => records.len(),
            Self::DvirStatus { records, .. } => records.len(),
            Self::Alerts { records, .. } => records.len(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraHttpResponse {
    endpoint: SamsaraEndpoint,
    status_code: u16,
    provider_revision: String,
    body: SamsaraResponseBody,
    response_size: usize,
    response_digest: Digest,
}

impl SamsaraHttpResponse {
    pub fn new(
        endpoint: SamsaraEndpoint,
        status_code: u16,
        body: SamsaraResponseBody,
    ) -> Result<Self, TransportError> {
        if endpoint != body.endpoint() || body.record_count() > MAX_RECORDS_PER_READ {
            return Err(TransportError::InvalidResponse);
        }
        let bytes = serde_json::to_vec(&body).map_err(|_| TransportError::InvalidResponse)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(TransportError::ResponseTooLarge);
        }
        Ok(Self {
            endpoint,
            status_code,
            provider_revision: SAMSARA_FLEET_RESULT_PROVIDER_VERSION.to_owned(),
            response_size: bytes.len(),
            response_digest: Digest::from_bytes(bytes),
            body,
        })
    }

    pub const fn endpoint(&self) -> SamsaraEndpoint {
        self.endpoint
    }

    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn body(&self) -> &SamsaraResponseBody {
        &self.body
    }

    pub const fn response_size(&self) -> usize {
        self.response_size
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    pub fn receipt_for(
        &self,
        request: &SamsaraHttpRequest,
    ) -> Result<ResponseReceipt, TransportError> {
        if self.endpoint != request.endpoint {
            return Err(TransportError::ScopeMismatch);
        }
        Ok(ResponseReceipt {
            method: request.method.clone(),
            endpoint: self.endpoint,
            request_path_and_query: request.path_and_query.clone(),
            api_version: request.api_version.clone(),
            response_status: self.status_code,
            response_size: self.response_size,
            response_digest: self.response_digest.clone(),
            provider_revision: self.provider_revision.clone(),
            raw_provider_payload: false,
            credential_material: false,
            native: false,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResponseReceipt {
    pub method: String,
    pub endpoint: SamsaraEndpoint,
    pub request_path_and_query: String,
    pub api_version: String,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: String,
    pub raw_provider_payload: bool,
    pub credential_material: bool,
    pub native: bool,
}

impl ResponseReceipt {
    pub const fn is_redacted(&self) -> bool {
        !self.raw_provider_payload && !self.credential_material && !self.native
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SamsaraReadResponse {
    pub body: SamsaraResponseBody,
    pub receipt: ResponseReceipt,
}

pub trait SamsaraTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;
    fn get(&mut self, request: &SamsaraHttpRequest) -> Result<SamsaraHttpResponse, TransportError>;
}

#[derive(Debug)]
pub struct SamsaraProvider<T> {
    scope: SamsaraFleetScope,
    secret_reference: SecretReference,
    definition: SamsaraProviderDefinition,
    transport: T,
}

impl<T: SamsaraTransport> SamsaraProvider<T> {
    pub fn new(
        scope: SamsaraFleetScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, ProviderDefinitionError> {
        if secret_reference.scope_digest() != scope.scope_digest() {
            return Err(ProviderDefinitionError::SecretScopeMismatch);
        }
        let definition = SamsaraProviderDefinition::new(
            SAMSARA_FLEET_RESULT_PROVIDER_VERSION,
            transport.provenance(),
        )?;
        Ok(Self {
            scope,
            secret_reference,
            definition,
            transport,
        })
    }

    pub fn definition(&self) -> &SamsaraProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub fn scope(&self) -> &SamsaraFleetScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn revoke_secret(&mut self) -> Result<(), ModelError> {
        self.secret_reference.revoke()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub const fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn read_vehicles(
        &mut self,
        options: &SamsaraReadOptions,
    ) -> Result<SamsaraReadResponse, TransportError> {
        self.read_endpoint(SamsaraEndpoint::Vehicles, options)
    }

    pub fn read_vehicle_trips(
        &mut self,
        options: &SamsaraReadOptions,
    ) -> Result<SamsaraReadResponse, TransportError> {
        self.read_endpoint(SamsaraEndpoint::VehicleTrips, options)
    }

    pub fn read_safety_signals(
        &mut self,
        options: &SamsaraReadOptions,
    ) -> Result<SamsaraReadResponse, TransportError> {
        self.read_endpoint(SamsaraEndpoint::SafetySignals, options)
    }

    pub fn read_maintenance_status(
        &mut self,
        options: &SamsaraReadOptions,
    ) -> Result<SamsaraReadResponse, TransportError> {
        self.read_endpoint(SamsaraEndpoint::MaintenanceStatus, options)
    }

    pub fn read_dvir_status(
        &mut self,
        options: &SamsaraReadOptions,
    ) -> Result<SamsaraReadResponse, TransportError> {
        self.read_endpoint(SamsaraEndpoint::DvirStatus, options)
    }

    pub fn read_alerts(
        &mut self,
        options: &SamsaraReadOptions,
    ) -> Result<SamsaraReadResponse, TransportError> {
        self.read_endpoint(SamsaraEndpoint::Alerts, options)
    }

    pub fn read_endpoint(
        &mut self,
        endpoint: SamsaraEndpoint,
        options: &SamsaraReadOptions,
    ) -> Result<SamsaraReadResponse, TransportError> {
        if self.secret_reference.is_revoked() {
            return Err(TransportError::SecretRevoked);
        }
        let request = SamsaraHttpRequest::new(&self.scope, endpoint, options)?;
        if request.scope_digest() != self.scope.scope_digest() {
            return Err(TransportError::ScopeMismatch);
        }
        let response = self.transport.get(&request)?;
        if response.endpoint() != endpoint {
            return Err(TransportError::InvalidResponse);
        }
        if response.provider_revision() != self.definition.provider_version {
            return Err(TransportError::InvalidResponse);
        }
        if !(200..=299).contains(&response.status_code()) {
            return Err(match response.status_code() {
                401 => TransportError::Unauthorized,
                403 => TransportError::Forbidden,
                404 => TransportError::NotFound,
                429 => TransportError::RateLimited {
                    retry_after_seconds: None,
                },
                status if status >= 500 => TransportError::ServerFailure { status },
                _ => TransportError::InvalidResponse,
            });
        }
        if response.response_size() > request.max_response_bytes() {
            return Err(TransportError::ResponseTooLarge);
        }
        let receipt = response.receipt_for(&request)?;
        Ok(SamsaraReadResponse {
            body: response.body().clone(),
            receipt,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RecordingSamsaraTransport {
    provenance: ProviderProvenance,
    responses: VecDeque<Result<SamsaraHttpResponse, TransportError>>,
    requests: Vec<SamsaraHttpRequest>,
}

impl RecordingSamsaraTransport {
    pub fn new(
        responses: impl IntoIterator<Item = Result<SamsaraHttpResponse, TransportError>>,
    ) -> Self {
        Self {
            provenance: ProviderProvenance::Recording,
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn fixture(
        responses: impl IntoIterator<Item = Result<SamsaraHttpResponse, TransportError>>,
    ) -> Self {
        Self {
            provenance: ProviderProvenance::Fixture,
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn loopback(
        responses: impl IntoIterator<Item = Result<SamsaraHttpResponse, TransportError>>,
    ) -> Self {
        Self {
            provenance: ProviderProvenance::Loopback,
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    pub fn requests(&self) -> &[SamsaraHttpRequest] {
        &self.requests
    }

    pub fn queued_response_count(&self) -> usize {
        self.responses.len()
    }
}

impl SamsaraTransport for RecordingSamsaraTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn get(&mut self, request: &SamsaraHttpRequest) -> Result<SamsaraHttpResponse, TransportError> {
        self.requests.push(request.clone());
        let response = self
            .responses
            .pop_front()
            .ok_or(TransportError::QueueExhausted)??;
        if response.endpoint() != request.endpoint() {
            Err(TransportError::InvalidResponse)
        } else {
            Ok(response)
        }
    }
}

pub type LoopbackTransport = RecordingSamsaraTransport;

#[derive(Debug, Default)]
pub struct BlockedEnvTransport;

impl SamsaraTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn get(
        &mut self,
        _request: &SamsaraHttpRequest,
    ) -> Result<SamsaraHttpResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        ConsentId, ConsentScope, MissionId, MissionScope, OrganizationId, ProjectId, ProjectScope,
        Revision, SamsaraFleetScope, TimeWindow,
    };

    fn scope() -> SamsaraFleetScope {
        SamsaraFleetScope::minimal(
            OrganizationId::new("org-1").expect("organization"),
            MissionScope::new(
                MissionId::new("mission-1").expect("mission"),
                Revision::new(1).expect("revision"),
            ),
            ProjectScope::new(
                ProjectId::new("project-1").expect("project"),
                Revision::new(1).expect("revision"),
            ),
            ConsentScope::new(
                ConsentId::new("consent-1").expect("consent"),
                Revision::new(1).expect("revision"),
            ),
            Digest::from_text("permission"),
            TimeWindow::new(100, 200).expect("window"),
        )
        .expect("scope")
    }

    #[test]
    fn request_is_get_only_allowlisted_and_redacted() {
        let scope = scope();
        let secret =
            SecretReference::new("vault/samsara", scope.scope_digest(), 1).expect("secret");
        let mut provider =
            SamsaraProvider::new(scope.clone(), secret, BlockedEnvTransport).expect("provider");
        let result = provider.read_alerts(&SamsaraReadOptions::new(scope.alerts().window));
        assert_eq!(result, Err(TransportError::BlockedEnv));
        assert!(!provider.is_native());
        assert!(!provider.is_connected());
        assert!(
            provider
                .definition()
                .allowed_endpoints
                .contains(&"bounded_alerts".to_owned())
        );
    }

    #[test]
    fn fixture_receipt_contains_digest_not_payload_or_secret() {
        let scope = scope();
        let secret =
            SecretReference::new("vault/samsara", scope.scope_digest(), 1).expect("secret");
        let vehicle = VehicleRecord {
            vehicle_id: crate::VehicleId::new("vehicle-1").expect("vehicle"),
            condition: crate::AssetCondition::Healthy,
            observed_at_epoch_seconds: 100,
        };
        let response = SamsaraHttpResponse::new(
            SamsaraEndpoint::Vehicles,
            200,
            SamsaraResponseBody::Vehicles {
                records: vec![vehicle],
                page: PageInfo::complete(),
            },
        )
        .expect("response");
        let transport = RecordingSamsaraTransport::fixture([Ok(response)]);
        let mut provider =
            SamsaraProvider::new(scope.clone(), secret, transport).expect("provider");
        let result = provider
            .read_vehicles(&SamsaraReadOptions::new(scope.trips().window))
            .expect("fixture read");
        assert!(result.receipt.is_redacted());
        let serialized = serde_json::to_string(&result).expect("receipt JSON");
        assert!(!serialized.contains("Bearer"));
        assert!(!serialized.contains("fixture-token"));
        assert!(!serialized.contains("vin"));
    }
}
