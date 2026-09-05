use std::{
    fmt,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    RUDDERSTACK_API_ORIGIN, RUDDERSTACK_API_REVISION, RUDDERSTACK_EVENT_QUALITY_PROVIDER_ID,
    RUDDERSTACK_EVENT_QUALITY_PROVIDER_VERSION_TEXT, RUDDERSTACK_MAX_PAGE_SIZE,
    RUDDERSTACK_MAX_REQUESTS_PER_MINUTE, RUDDERSTACK_MAX_RESPONSE_BYTES,
    RUDDERSTACK_MAX_VIOLATIONS, canonical_digest,
    model::{
        CursorReceipt, DateWindow, Digest, ModelError, PrivacyPolicy, ProviderErrorKind,
        RateLimitReceipt, RudderStackDeliveryHealthAggregate, RudderStackEventQualityScope,
        RudderStackGovernanceMetrics, RudderStackPermission, RudderStackPermissionSet,
        RudderStackSchemaViolationAggregate, RudderStackScope, RudderStackSourceMetadata,
        RudderStackTrackingPlanVersion, SecretReference, TransportProvenance,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RudderStackHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RudderStackOperation {
    SourceMetadataRead,
    TrackingPlanVersionsRead,
    SchemaViolationsRead,
    DeliveryHealthRead,
    GovernanceMetricsRead,
}

impl RudderStackOperation {
    pub const fn permission(self) -> RudderStackPermission {
        match self {
            Self::SourceMetadataRead => RudderStackPermission::SourceMetadataRead,
            Self::TrackingPlanVersionsRead => RudderStackPermission::TrackingPlanVersionsRead,
            Self::SchemaViolationsRead => RudderStackPermission::SchemaViolationsRead,
            Self::DeliveryHealthRead => RudderStackPermission::DeliveryHealthRead,
            Self::GovernanceMetricsRead => RudderStackPermission::GovernanceMetricsRead,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::SourceMetadataRead => "source.metadata.read",
            Self::TrackingPlanVersionsRead => "tracking_plan.versions.read",
            Self::SchemaViolationsRead => "schema.violations.read",
            Self::DeliveryHealthRead => "delivery.health.read",
            Self::GovernanceMetricsRead => "governance.metrics.read",
        }
    }

    pub const fn path_prefix(self) -> &'static str {
        match self {
            Self::SourceMetadataRead => "/v1/sources/",
            Self::TrackingPlanVersionsRead => "/v1/tracking-plans/",
            Self::SchemaViolationsRead => "/v1/sources/",
            Self::DeliveryHealthRead => "/v1/destinations/",
            Self::GovernanceMetricsRead => "/v1/sources/",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackRequest {
    pub method: RudderStackHttpMethod,
    pub operation: RudderStackOperation,
    pub origin: String,
    pub path: String,
    pub page_size: u16,
    pub cursor_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl RudderStackRequest {
    pub fn is_allowlisted(&self) -> bool {
        self.method == RudderStackHttpMethod::Get
            && self.origin == RUDDERSTACK_API_ORIGIN
            && self.page_size > 0
            && usize::from(self.page_size) <= RUDDERSTACK_MAX_PAGE_SIZE
            && match self.operation {
                RudderStackOperation::SourceMetadataRead => {
                    self.path.starts_with("/v1/sources/") && self.path.ends_with("/metadata")
                }
                RudderStackOperation::TrackingPlanVersionsRead => {
                    self.path.starts_with("/v1/tracking-plans/") && self.path.ends_with("/versions")
                }
                RudderStackOperation::SchemaViolationsRead => {
                    self.path.starts_with("/v1/sources/")
                        && self.path.ends_with("/schema-violations")
                }
                RudderStackOperation::DeliveryHealthRead => {
                    self.path.starts_with("/v1/destinations/")
                        && self.path.ends_with("/delivery-health")
                }
                RudderStackOperation::GovernanceMetricsRead => {
                    self.path.starts_with("/v1/sources/")
                        && self.path.ends_with("/governance-metrics")
                }
            }
    }

    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            self.method,
            self.operation,
            &self.origin,
            &self.path,
            self.page_size,
            &self.cursor_digest,
            &self.scope_digest,
            &self.permission_digest,
            &self.secret_reference_digest,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackResponse {
    pub status_code: u16,
    pub source_metadata: Option<RudderStackSourceMetadata>,
    pub tracking_plan_versions: Vec<RudderStackTrackingPlanVersion>,
    pub violations: Vec<RudderStackSchemaViolationAggregate>,
    pub delivery_health: Vec<RudderStackDeliveryHealthAggregate>,
    pub governance_metrics: Option<RudderStackGovernanceMetrics>,
    pub cursor_receipt: Option<CursorReceipt>,
    pub rate_limit: RateLimitReceipt,
    pub reported_response_bytes: usize,
    pub declared_response_digest: Option<Digest>,
    pub response_digest: Digest,
}

impl RudderStackResponse {
    pub fn empty(status_code: u16) -> Self {
        let mut response = Self::with_status(status_code);
        response.reported_response_bytes = response.encoded_size();
        response
    }

    pub fn with_status(status_code: u16) -> Self {
        let mut response = Self {
            status_code,
            source_metadata: None,
            tracking_plan_versions: Vec::new(),
            violations: Vec::new(),
            delivery_health: Vec::new(),
            governance_metrics: None,
            cursor_receipt: None,
            rate_limit: RateLimitReceipt::default(),
            reported_response_bytes: 0,
            declared_response_digest: None,
            response_digest: Digest::zero(),
        };
        response.refresh_digest();
        response
    }

    pub fn complete(
        source_metadata: Option<RudderStackSourceMetadata>,
        tracking_plan_versions: Vec<RudderStackTrackingPlanVersion>,
        violations: Vec<RudderStackSchemaViolationAggregate>,
        delivery_health: Vec<RudderStackDeliveryHealthAggregate>,
        governance_metrics: Option<RudderStackGovernanceMetrics>,
    ) -> Self {
        Self::builder(200)
            .source_metadata(source_metadata)
            .tracking_plan_versions(tracking_plan_versions)
            .violations(violations)
            .delivery_health(delivery_health)
            .governance_metrics(governance_metrics)
            .build()
    }

    pub fn builder(status_code: u16) -> RudderStackResponseBuilder {
        RudderStackResponseBuilder {
            response: Self::with_status(status_code),
        }
    }

    pub fn computed_digest(&self) -> Digest {
        let mut tracking_plan_versions = self.tracking_plan_versions.clone();
        let mut violations = self.violations.clone();
        let mut delivery_health = self.delivery_health.clone();
        tracking_plan_versions.sort_by_key(RudderStackTrackingPlanVersion::digest);
        violations.sort_by_key(RudderStackSchemaViolationAggregate::digest);
        delivery_health.sort_by_key(RudderStackDeliveryHealthAggregate::digest);
        canonical_digest(&(
            self.status_code,
            &self.source_metadata,
            &tracking_plan_versions,
            &violations,
            &delivery_health,
            &self.governance_metrics,
            &self.cursor_receipt,
            &self.rate_limit,
        ))
    }

    pub fn validate(&self) -> Result<(), RudderStackResponseValidation> {
        if self.reported_response_bytes > RUDDERSTACK_MAX_RESPONSE_BYTES {
            return Err(RudderStackResponseValidation::ResponseTooLarge {
                response_bytes: self.reported_response_bytes,
            });
        }
        self.rate_limit
            .validate()
            .map_err(RudderStackResponseValidation::Model)?;
        if let Some(cursor) = &self.cursor_receipt {
            cursor
                .validate()
                .map_err(RudderStackResponseValidation::Model)?;
        }
        if self.violations.len() > RUDDERSTACK_MAX_VIOLATIONS {
            return Err(RudderStackResponseValidation::Model(
                ModelError::BoundExceeded,
            ));
        }
        if let Some(source) = &self.source_metadata {
            source
                .validate()
                .map_err(RudderStackResponseValidation::Model)?;
        }
        for value in &self.tracking_plan_versions {
            value
                .validate()
                .map_err(RudderStackResponseValidation::Model)?;
        }
        for value in &self.violations {
            value
                .validate()
                .map_err(RudderStackResponseValidation::Model)?;
        }
        for value in &self.delivery_health {
            value
                .validate()
                .map_err(RudderStackResponseValidation::Model)?;
        }
        if let Some(value) = &self.governance_metrics {
            value
                .validate()
                .map_err(RudderStackResponseValidation::Model)?;
        }
        if self.response_digest != self.computed_digest()
            || self
                .declared_response_digest
                .as_ref()
                .is_some_and(|digest| digest != &self.response_digest)
        {
            return Err(RudderStackResponseValidation::Tamper);
        }
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.source_metadata.is_none()
            && self.tracking_plan_versions.is_empty()
            && self.violations.is_empty()
            && self.delivery_health.is_empty()
            && self.governance_metrics.is_none()
    }

    pub fn encoded_size(&self) -> usize {
        serde_json::to_vec(&(
            self.status_code,
            &self.source_metadata,
            &self.tracking_plan_versions,
            &self.violations,
            &self.delivery_health,
            &self.governance_metrics,
            &self.cursor_receipt,
            &self.rate_limit,
        ))
        .map_or(usize::MAX, |bytes| bytes.len())
    }

    fn refresh_digest(&mut self) {
        self.response_digest = self.computed_digest();
    }
}

#[derive(Clone, Debug)]
pub struct RudderStackResponseBuilder {
    response: RudderStackResponse,
}

impl RudderStackResponseBuilder {
    #[must_use]
    pub fn source_metadata(mut self, value: Option<RudderStackSourceMetadata>) -> Self {
        self.response.source_metadata = value;
        self
    }

    #[must_use]
    pub fn tracking_plan_versions(mut self, value: Vec<RudderStackTrackingPlanVersion>) -> Self {
        self.response.tracking_plan_versions = value;
        self
    }

    #[must_use]
    pub fn violations(mut self, value: Vec<RudderStackSchemaViolationAggregate>) -> Self {
        self.response.violations = value;
        self
    }

    #[must_use]
    pub fn delivery_health(mut self, value: Vec<RudderStackDeliveryHealthAggregate>) -> Self {
        self.response.delivery_health = value;
        self
    }

    #[must_use]
    pub fn governance_metrics(mut self, value: Option<RudderStackGovernanceMetrics>) -> Self {
        self.response.governance_metrics = value;
        self
    }

    #[must_use]
    pub fn cursor(mut self, value: Option<CursorReceipt>) -> Self {
        self.response.cursor_receipt = value;
        self
    }

    pub fn cursor_from_opaque(
        mut self,
        value: Option<&str>,
        page: u32,
        page_size: u16,
        has_more: bool,
        request_digest: Digest,
    ) -> Result<Self, ModelError> {
        self.response.cursor_receipt = Some(CursorReceipt::from_opaque(
            value,
            page,
            page_size,
            has_more,
            request_digest,
        )?);
        Ok(self)
    }

    #[must_use]
    pub fn rate_limit(mut self, value: RateLimitReceipt) -> Self {
        self.response.rate_limit = value;
        self
    }

    #[must_use]
    pub fn reported_response_bytes(mut self, value: usize) -> Self {
        self.response.reported_response_bytes = value;
        self
    }

    #[must_use]
    pub fn declared_response_digest(mut self, value: Digest) -> Self {
        self.response.declared_response_digest = Some(value);
        self
    }

    pub fn build(mut self) -> RudderStackResponse {
        self.response.refresh_digest();
        if self.response.reported_response_bytes == 0 {
            self.response.reported_response_bytes = self.response.encoded_size();
        }
        self.response
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RudderStackResponseValidation {
    #[error("response is too large: {response_bytes} bytes")]
    ResponseTooLarge { response_bytes: usize },
    #[error("response is tampered")]
    Tamper,
    #[error("response model is invalid: {0}")]
    Model(ModelError),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RudderStackTransportError {
    #[error("BLOCKED_ENV")]
    BlockedEnv,
    #[error("transport is unavailable")]
    Unavailable { diagnostic_digest: Digest },
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RudderStackProviderError {
    #[error("RudderStack SecretReference is revoked")]
    SecretRevoked,
    #[error("RudderStack registration is revoked")]
    RegistrationRevoked,
    #[error("permission is not granted for {operation:?}")]
    PermissionDenied { operation: RudderStackOperation },
    #[error("the scope is missing a required {kind}")]
    MissingScope { kind: &'static str },
    #[error("request is not allowlisted")]
    RequestNotAllowlisted,
    #[error("provider response is tampered")]
    Tamper {
        operation: RudderStackOperation,
        response_digest: Digest,
    },
    #[error("provider response is too large")]
    ResponseTooLarge {
        operation: RudderStackOperation,
        response_bytes: usize,
        response_digest: Digest,
    },
    #[error("provider response is malformed")]
    MalformedResponse {
        operation: RudderStackOperation,
        response_digest: Digest,
    },
    #[error("provider returned HTTP status {status_code}")]
    HttpStatus {
        operation: RudderStackOperation,
        status_code: u16,
        response_digest: Digest,
        rate_limit: RateLimitReceipt,
    },
    #[error("provider rate limited the read")]
    RateLimited {
        operation: RudderStackOperation,
        response_digest: Digest,
        rate_limit: RateLimitReceipt,
    },
    #[error("provider transport failed")]
    Transport {
        operation: RudderStackOperation,
        error: RudderStackTransportError,
    },
    #[error("provider model is invalid: {0}")]
    Model(ModelError),
}

impl RudderStackProviderError {
    pub const fn kind(&self) -> ProviderErrorKind {
        match self {
            Self::SecretRevoked | Self::RegistrationRevoked => ProviderErrorKind::AccessLost,
            Self::PermissionDenied { .. } | Self::MissingScope { .. } => {
                ProviderErrorKind::PermissionDenied
            }
            Self::Tamper { .. } => ProviderErrorKind::Tamper,
            Self::ResponseTooLarge { .. } => ProviderErrorKind::ResponseTooLarge,
            Self::MalformedResponse { .. } | Self::Model(_) => ProviderErrorKind::MalformedResponse,
            Self::RateLimited { .. } => ProviderErrorKind::RateLimited,
            Self::HttpStatus { status_code, .. } => match status_code {
                401 | 403 | 404 => ProviderErrorKind::AccessLost,
                429 => ProviderErrorKind::RateLimited,
                _ => ProviderErrorKind::ProviderUnknown,
            },
            Self::Transport { error, .. } => match error {
                RudderStackTransportError::BlockedEnv => ProviderErrorKind::BlockedEnv,
                RudderStackTransportError::Unavailable { .. } => ProviderErrorKind::ProviderUnknown,
            },
            Self::RequestNotAllowlisted => ProviderErrorKind::MalformedResponse,
        }
    }

    pub fn operation(&self) -> Option<RudderStackOperation> {
        match self {
            Self::Tamper { operation, .. }
            | Self::ResponseTooLarge { operation, .. }
            | Self::MalformedResponse { operation, .. }
            | Self::HttpStatus { operation, .. }
            | Self::RateLimited { operation, .. }
            | Self::Transport { operation, .. }
            | Self::PermissionDenied { operation } => Some(*operation),
            Self::SecretRevoked
            | Self::RegistrationRevoked
            | Self::MissingScope { .. }
            | Self::RequestNotAllowlisted
            | Self::Model(_) => None,
        }
    }

    pub fn response_digest(&self) -> Option<Digest> {
        match self {
            Self::Tamper {
                response_digest, ..
            }
            | Self::ResponseTooLarge {
                response_digest, ..
            }
            | Self::MalformedResponse {
                response_digest, ..
            }
            | Self::HttpStatus {
                response_digest, ..
            }
            | Self::RateLimited {
                response_digest, ..
            } => Some(response_digest.clone()),
            _ => None,
        }
    }

    pub fn rate_limit(&self) -> Option<RateLimitReceipt> {
        match self {
            Self::HttpStatus { rate_limit, .. } | Self::RateLimited { rate_limit, .. } => {
                Some(rate_limit.clone())
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RudderStackProviderDefinition {
    pub id: String,
    pub version: String,
    pub api_revision: String,
    pub origin: String,
    pub allowed_operations: Vec<RudderStackOperation>,
    pub max_page_size: u16,
    pub max_response_bytes: usize,
    pub max_requests_per_minute: u16,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub writes: bool,
    pub provider_digest: Digest,
}

impl RudderStackProviderDefinition {
    pub fn layer1() -> Self {
        let mut value = Self {
            id: RUDDERSTACK_EVENT_QUALITY_PROVIDER_ID.to_owned(),
            version: RUDDERSTACK_EVENT_QUALITY_PROVIDER_VERSION_TEXT.to_owned(),
            api_revision: RUDDERSTACK_API_REVISION.to_owned(),
            origin: RUDDERSTACK_API_ORIGIN.to_owned(),
            allowed_operations: vec![
                RudderStackOperation::SourceMetadataRead,
                RudderStackOperation::TrackingPlanVersionsRead,
                RudderStackOperation::SchemaViolationsRead,
                RudderStackOperation::DeliveryHealthRead,
                RudderStackOperation::GovernanceMetricsRead,
            ],
            max_page_size: u16::try_from(RUDDERSTACK_MAX_PAGE_SIZE).expect("page size fits u16"),
            max_response_bytes: RUDDERSTACK_MAX_RESPONSE_BYTES,
            max_requests_per_minute: RUDDERSTACK_MAX_REQUESTS_PER_MINUTE,
            native: false,
            connected: false,
            first_party: false,
            writes: false,
            provider_digest: Digest::zero(),
        };
        value.provider_digest = value.compute_digest();
        value
    }

    pub fn digest(&self) -> Digest {
        self.provider_digest.clone()
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&(
            &self.id,
            &self.version,
            &self.api_revision,
            &self.origin,
            &self.allowed_operations,
            self.max_page_size,
            self.max_response_bytes,
            self.max_requests_per_minute,
            self.native,
            self.connected,
            self.first_party,
            self.writes,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct RudderStackProviderRead {
    pub operation: RudderStackOperation,
    pub request: RudderStackRequest,
    pub response: RudderStackResponse,
    pub provenance: TransportProvenance,
}

#[derive(Clone, Debug)]
pub struct RudderStackOperationFailure {
    pub operation: Option<RudderStackOperation>,
    pub request_digest: Option<Digest>,
    pub kind: ProviderErrorKind,
    pub response_digest: Option<Digest>,
    pub rate_limit: Option<RateLimitReceipt>,
}

impl RudderStackOperationFailure {
    fn from_error(error: &RudderStackProviderError, request_digest: Option<Digest>) -> Self {
        Self {
            operation: error.operation(),
            request_digest,
            kind: error.kind(),
            response_digest: error.response_digest(),
            rate_limit: error.rate_limit(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RudderStackBatchRead {
    pub reads: Vec<RudderStackProviderRead>,
    pub failures: Vec<RudderStackOperationFailure>,
    pub page_count: u16,
    pub complete_pagination: bool,
}

impl RudderStackBatchRead {
    pub fn response_digests(&self) -> Vec<Digest> {
        let mut digests = self
            .reads
            .iter()
            .map(|read| read.response.response_digest.clone())
            .chain(
                self.failures
                    .iter()
                    .filter_map(|failure| failure.response_digest.clone()),
            )
            .collect::<Vec<_>>();
        digests.sort();
        digests.dedup();
        digests
    }

    pub fn rate_limit_receipts(&self) -> Vec<RateLimitReceipt> {
        let mut receipts = self
            .reads
            .iter()
            .map(|read| read.response.rate_limit.clone())
            .chain(
                self.failures
                    .iter()
                    .filter_map(|failure| failure.rate_limit.clone()),
            )
            .collect::<Vec<_>>();
        receipts.sort_by_key(RateLimitReceipt::digest);
        receipts
    }

    pub fn cursor_receipts(&self) -> Vec<CursorReceipt> {
        let mut receipts = self
            .reads
            .iter()
            .filter_map(|read| read.response.cursor_receipt.clone())
            .collect::<Vec<_>>();
        receipts.sort_by_key(CursorReceipt::digest);
        receipts
    }
}

pub trait RudderStackTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn execute(
        &self,
        request: &RudderStackRequest,
    ) -> Result<RudderStackResponse, RudderStackTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureRudderStackTransport {
    response: RudderStackResponse,
}

impl FixtureRudderStackTransport {
    pub fn new(response: RudderStackResponse) -> Self {
        Self { response }
    }

    pub fn response(&self) -> &RudderStackResponse {
        &self.response
    }
}

impl RudderStackTransport for FixtureRudderStackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn execute(
        &self,
        _request: &RudderStackRequest,
    ) -> Result<RudderStackResponse, RudderStackTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct RecordingRudderStackTransport {
    response: RudderStackResponse,
    requests: Arc<Mutex<Vec<RudderStackRequest>>>,
}

impl RecordingRudderStackTransport {
    pub fn new(response: RudderStackResponse) -> Self {
        Self {
            response,
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn requests(&self) -> Vec<RudderStackRequest> {
        self.requests
            .lock()
            .map_or_else(|_| Vec::new(), |requests| requests.clone())
    }
}

impl RudderStackTransport for RecordingRudderStackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn execute(
        &self,
        request: &RudderStackRequest,
    ) -> Result<RudderStackResponse, RudderStackTransportError> {
        if let Ok(mut requests) = self.requests.lock() {
            requests.push(request.clone());
        }
        Ok(self.response.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackRudderStackTransport {
    response: RudderStackResponse,
}

impl LoopbackRudderStackTransport {
    pub fn new(response: RudderStackResponse) -> Self {
        Self { response }
    }
}

impl RudderStackTransport for LoopbackRudderStackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn execute(
        &self,
        _request: &RudderStackRequest,
    ) -> Result<RudderStackResponse, RudderStackTransportError> {
        Ok(self.response.clone())
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvRudderStackTransport;

impl RudderStackTransport for BlockedEnvRudderStackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn execute(
        &self,
        _request: &RudderStackRequest,
    ) -> Result<RudderStackResponse, RudderStackTransportError> {
        Err(RudderStackTransportError::BlockedEnv)
    }
}

pub type FakeRudderStackTransport = FixtureRudderStackTransport;
pub type BlockedEnvTransport = BlockedEnvRudderStackTransport;
pub type FixtureTransport = FixtureRudderStackTransport;
pub type RecordingTransport = RecordingRudderStackTransport;
pub type LoopbackTransport = LoopbackRudderStackTransport;

#[derive(Debug)]
pub struct RudderStackProvider<T = BlockedEnvRudderStackTransport> {
    scope: RudderStackScope,
    secret_reference: SecretReference,
    permissions: RudderStackPermissionSet,
    definition: RudderStackProviderDefinition,
    transport: T,
}

impl<T> RudderStackProvider<T>
where
    T: RudderStackTransport,
{
    pub fn new(
        scope: RudderStackScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, RudderStackProviderError> {
        Self::with_definition(
            scope,
            secret_reference,
            RudderStackProviderDefinition::layer1(),
            transport,
        )
    }

    pub fn with_definition(
        scope: RudderStackScope,
        secret_reference: SecretReference,
        definition: RudderStackProviderDefinition,
        transport: T,
    ) -> Result<Self, RudderStackProviderError> {
        scope.validate().map_err(RudderStackProviderError::Model)?;
        if definition.provider_digest != definition.compute_digest() {
            return Err(RudderStackProviderError::Model(ModelError::DigestMismatch));
        }
        Ok(Self {
            permissions: scope.permissions.clone(),
            scope,
            secret_reference,
            definition,
            transport,
        })
    }

    pub fn scope(&self) -> &RudderStackScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_mut(&mut self) -> &mut SecretReference {
        &mut self.secret_reference
    }

    pub fn permissions(&self) -> &RudderStackPermissionSet {
        &self.permissions
    }

    pub fn definition(&self) -> &RudderStackProviderDefinition {
        &self.definition
    }

    pub fn provider_digest(&self) -> Digest {
        self.definition.digest()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &self,
        operation: RudderStackOperation,
    ) -> Result<RudderStackProviderRead, RudderStackProviderError> {
        if self.secret_reference.is_revoked() {
            return Err(RudderStackProviderError::SecretRevoked);
        }
        let permission = operation.permission();
        if !self.permissions.has(permission) {
            return Err(RudderStackProviderError::PermissionDenied { operation });
        }
        let path = self.path_for(operation)?;
        let mut request = RudderStackRequest {
            method: RudderStackHttpMethod::Get,
            operation,
            origin: RUDDERSTACK_API_ORIGIN.to_owned(),
            path,
            page_size: self.definition.max_page_size,
            cursor_digest: None,
            scope_digest: self.scope.digest(),
            permission_digest: self.permissions.digest(),
            secret_reference_digest: self.secret_reference.digest(),
            request_digest: Digest::zero(),
        };
        request.request_digest = request.digest();
        if !request.is_allowlisted() {
            return Err(RudderStackProviderError::RequestNotAllowlisted);
        }
        let response = self
            .transport
            .execute(&request)
            .map_err(|error| RudderStackProviderError::Transport { operation, error })?;
        match response.validate() {
            Ok(()) => {}
            Err(RudderStackResponseValidation::ResponseTooLarge { response_bytes }) => {
                return Err(RudderStackProviderError::ResponseTooLarge {
                    operation,
                    response_bytes,
                    response_digest: response.response_digest.clone(),
                });
            }
            Err(RudderStackResponseValidation::Tamper) => {
                return Err(RudderStackProviderError::Tamper {
                    operation,
                    response_digest: response.response_digest.clone(),
                });
            }
            Err(RudderStackResponseValidation::Model(_)) => {
                return Err(RudderStackProviderError::MalformedResponse {
                    operation,
                    response_digest: response.response_digest.clone(),
                });
            }
        }
        if response.status_code == 429 || response.rate_limit.throttled {
            return Err(RudderStackProviderError::RateLimited {
                operation,
                response_digest: response.response_digest.clone(),
                rate_limit: response.rate_limit.clone(),
            });
        }
        if !(200..300).contains(&response.status_code) {
            return Err(RudderStackProviderError::HttpStatus {
                operation,
                status_code: response.status_code,
                response_digest: response.response_digest.clone(),
                rate_limit: response.rate_limit.clone(),
            });
        }
        Ok(RudderStackProviderRead {
            operation,
            request,
            response,
            provenance: self.transport.provenance(),
        })
    }

    pub fn read_all(&self) -> Result<RudderStackBatchRead, RudderStackProviderError> {
        if self.secret_reference.is_revoked() {
            return Err(RudderStackProviderError::SecretRevoked);
        }
        let mut operations = vec![
            RudderStackOperation::SourceMetadataRead,
            RudderStackOperation::SchemaViolationsRead,
            RudderStackOperation::GovernanceMetricsRead,
        ];
        if self.scope.tracking_plan.is_some() {
            operations.push(RudderStackOperation::TrackingPlanVersionsRead);
        }
        if self.scope.destination.is_some() {
            operations.push(RudderStackOperation::DeliveryHealthRead);
        }
        operations.sort();
        let mut batch = RudderStackBatchRead {
            reads: Vec::new(),
            failures: Vec::new(),
            page_count: 0,
            complete_pagination: true,
        };
        for operation in operations {
            match self.read(operation) {
                Ok(read) => {
                    batch.page_count = batch.page_count.saturating_add(1);
                    if read
                        .response
                        .cursor_receipt
                        .as_ref()
                        .is_some_and(|cursor| cursor.has_more)
                    {
                        batch.complete_pagination = false;
                    }
                    batch.reads.push(read);
                }
                Err(
                    error @ (RudderStackProviderError::SecretRevoked
                    | RudderStackProviderError::RegistrationRevoked),
                ) => return Err(error),
                Err(error) => {
                    batch
                        .failures
                        .push(RudderStackOperationFailure::from_error(&error, None));
                }
            }
        }
        Ok(batch)
    }

    fn path_for(
        &self,
        operation: RudderStackOperation,
    ) -> Result<String, RudderStackProviderError> {
        let path = match operation {
            RudderStackOperation::SourceMetadataRead => {
                format!("/v1/sources/{}/metadata", self.scope.source.id.as_str())
            }
            RudderStackOperation::TrackingPlanVersionsRead => {
                let Some(plan) = &self.scope.tracking_plan else {
                    return Err(RudderStackProviderError::MissingScope {
                        kind: "tracking plan",
                    });
                };
                format!("/v1/tracking-plans/{}/versions", plan.id.as_str())
            }
            RudderStackOperation::SchemaViolationsRead => {
                format!(
                    "/v1/sources/{}/schema-violations",
                    self.scope.source.id.as_str()
                )
            }
            RudderStackOperation::DeliveryHealthRead => {
                let Some(destination) = &self.scope.destination else {
                    return Err(RudderStackProviderError::MissingScope {
                        kind: "destination",
                    });
                };
                format!(
                    "/v1/destinations/{}/delivery-health",
                    destination.id.as_str()
                )
            }
            RudderStackOperation::GovernanceMetricsRead => {
                format!(
                    "/v1/sources/{}/governance-metrics",
                    self.scope.source.id.as_str()
                )
            }
        };
        Ok(path)
    }
}

impl Default for RudderStackProvider<BlockedEnvRudderStackTransport> {
    fn default() -> Self {
        let scope = default_scope();
        let secret = SecretReference::new("blocked-env-api-token", 1)
            .expect("default blocked environment SecretReference");
        Self::new(scope, secret, BlockedEnvRudderStackTransport)
            .expect("default blocked environment provider")
    }
}

fn default_scope() -> RudderStackEventQualityScope {
    RudderStackScope::new(
        crate::model::OrganizationScope::new("blocked-org", 1).expect("valid default org"),
        crate::model::WorkspaceScope::new("blocked-workspace", 1).expect("valid default workspace"),
        crate::model::SourceScope::new("blocked-source", 1).expect("valid default source"),
        Some(
            crate::model::DestinationScope::new("blocked-destination", 1)
                .expect("valid default destination"),
        ),
        Some(
            crate::model::TrackingPlanScope::new("blocked-plan", 1)
                .expect("valid default tracking plan"),
        ),
        crate::model::ViolationScope::all(1).expect("valid default violation scope"),
        crate::model::ProjectScope::new("blocked-project", 1).expect("valid default project"),
        crate::model::MissionScope::new("blocked-mission", 1).expect("valid default mission"),
        crate::model::WorkProductScope::new("blocked-work-product", 1)
            .expect("valid default work product"),
        DateWindow::new("2026-01-01", "2026-01-01").expect("valid default window"),
        RudderStackPermissionSet::least_privilege(1).expect("valid default permissions"),
        PrivacyPolicy::strict_v1(),
    )
    .expect("valid default scope")
}
