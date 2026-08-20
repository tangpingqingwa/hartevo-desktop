//! Read-only AWS Control Tower provider boundary.
//!
//! The provider accepts only typed, digest-bound requests and returns bounded
//! pages or projections.  It has no credential resolver, signer, HTTP client,
//! mutation method, or arbitrary operation escape hatch.

use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::{
    API_DIGEST, API_REVISION, API_VERSION, MAX_ITEMS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
    PROVIDER_ID, PROVIDER_VERSION,
    model::{
        AccountId, AwsControlTowerScope, AwsRegion, BaselineId, Digest, EnabledBaselineSummary,
        LandingZoneDetail, LandingZoneIdentity, LandingZoneOperation, LandingZoneSummary,
        ModelError, OpaqueCursor, OperationId, ReadBounds, ReadOperation, Result as ModelResult,
        TargetReference,
    },
};

pub type ProviderResult<T> = std::result::Result<T, ProviderError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportError {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited { retry_after_seconds: Option<u64> },
    ServerFailure { status_code: Option<u16> },
    Timeout,
    BlockedEnv,
    InvalidResponse,
}

impl TransportError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::BadRequest => Some(400),
            Self::Unauthorized => Some(401),
            Self::Forbidden => Some(403),
            Self::NotFound => Some(404),
            Self::Conflict => Some(409),
            Self::RateLimited { .. } => Some(429),
            Self::ServerFailure { status_code } => *status_code,
            Self::Timeout | Self::BlockedEnv | Self::InvalidResponse => None,
        }
    }

    pub const fn category(&self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::ServerFailure { .. } => "server_failure",
            Self::Timeout => "timeout",
            Self::BlockedEnv => "blocked_env",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

impl std::error::Error for TransportError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderError {
    Model(ModelError),
    Transport(TransportError),
    DefinitionMismatch,
    ScopeMismatch,
    PermissionLoss,
    RegionMismatch,
    AccountMismatch,
    LandingZoneDrift,
    BaselineDrift,
    ChildBaselineUnexpected,
    DuplicateItem,
    PaginationIncomplete,
    ResponseTooLarge,
    ResponseItemBound,
    RetentionExpired,
    RequestDrift,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(error) => write!(formatter, "provider model error: {error}"),
            Self::Transport(error) => write!(formatter, "provider transport error: {error}"),
            Self::DefinitionMismatch => formatter.write_str("provider definition mismatch"),
            Self::ScopeMismatch => formatter.write_str("provider scope digest mismatch"),
            Self::PermissionLoss => formatter.write_str("provider permission digest mismatch"),
            Self::RegionMismatch => formatter.write_str("provider region mismatch"),
            Self::AccountMismatch => formatter.write_str("provider account mismatch"),
            Self::LandingZoneDrift => formatter.write_str("landing zone drifted from scope"),
            Self::BaselineDrift => formatter.write_str("baseline drifted from scope"),
            Self::ChildBaselineUnexpected => formatter.write_str("unexpected child baseline"),
            Self::DuplicateItem => formatter.write_str("provider returned a duplicate item"),
            Self::PaginationIncomplete => formatter.write_str("provider pagination is incomplete"),
            Self::ResponseTooLarge => {
                formatter.write_str("provider response exceeded the byte bound")
            }
            Self::ResponseItemBound => {
                formatter.write_str("provider response exceeded the item bound")
            }
            Self::RetentionExpired => formatter.write_str("operation detail exceeded retention"),
            Self::RequestDrift => formatter.write_str("provider request digest drifted"),
        }
    }
}

impl std::error::Error for ProviderError {}

impl From<ModelError> for ProviderError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

impl From<TransportError> for ProviderError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsControlTowerProviderDefinition {
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub api_revision: String,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub provenance: ProviderProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl AwsControlTowerProviderDefinition {
    pub fn for_provenance(provenance: ProviderProvenance) -> Self {
        let provider_digest = Digest::from_parts(
            "aws-control-tower-provider/v1",
            &[
                PROVIDER_ID.to_owned(),
                PROVIDER_VERSION.to_owned(),
                API_VERSION.to_owned(),
                API_REVISION.to_owned(),
                format!("{provenance:?}"),
            ],
        );
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            api_version: API_VERSION.to_owned(),
            api_revision: API_REVISION.to_owned(),
            api_digest: Digest::from_text(API_DIGEST),
            provider_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn validate(&self) -> ProviderResult<()> {
        let expected = Self::for_provenance(self.provenance);
        if self.provider_id != expected.provider_id
            || self.provider_version != expected.provider_version
            || self.api_version != expected.api_version
            || self.api_revision != expected.api_revision
            || self.api_digest != expected.api_digest
            || self.provider_digest != expected.provider_digest
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
        {
            return Err(ProviderError::DefinitionMismatch);
        }
        Ok(())
    }
}

pub type AwsControlTowerProviderIdentity = AwsControlTowerProviderDefinition;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListLandingZonesRequest {
    pub account_id: AccountId,
    pub home_region: AwsRegion,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<OpaqueCursor>,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
}

impl ListLandingZonesRequest {
    pub fn new(
        scope: &AwsControlTowerScope,
        bounds: &ReadBounds,
        cursor: Option<OpaqueCursor>,
    ) -> ModelResult<Self> {
        Self::for_scope(scope, bounds, cursor)
    }

    pub fn for_scope(
        scope: &AwsControlTowerScope,
        bounds: &ReadBounds,
        cursor: Option<OpaqueCursor>,
    ) -> ModelResult<Self> {
        let mut request = Self {
            account_id: scope.account_id.clone(),
            home_region: scope.home_region.clone(),
            page_size: bounds.page_size.min(1),
            max_pages: bounds.max_pages,
            cursor,
            permission_digest: scope.permission.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            request_digest: Digest::zero(),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: Option<OpaqueCursor>) -> Self {
        self.cursor = cursor;
        self.request_digest = self.compute_digest();
        self
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-list-landing-zones-request/v1",
            &[
                self.account_id.digest().to_string(),
                self.home_region.digest().to_string(),
                self.page_size.to_string(),
                self.max_pages.to_string(),
                self.cursor
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |cursor| cursor.digest().to_string()),
                self.permission_digest.to_string(),
                self.scope_digest.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLandingZoneRequest {
    pub account_id: AccountId,
    pub home_region: AwsRegion,
    pub landing_zone: LandingZoneIdentity,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
}

impl GetLandingZoneRequest {
    pub fn new(scope: &AwsControlTowerScope) -> ModelResult<Self> {
        Self::for_scope(scope)
    }

    pub fn for_scope(scope: &AwsControlTowerScope) -> ModelResult<Self> {
        let mut request = Self {
            account_id: scope.account_id.clone(),
            home_region: scope.home_region.clone(),
            landing_zone: scope.landing_zone.clone(),
            permission_digest: scope.permission.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            request_digest: Digest::zero(),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-get-landing-zone-request/v1",
            &[
                self.account_id.digest().to_string(),
                self.home_region.digest().to_string(),
                self.landing_zone.digest().to_string(),
                self.permission_digest.to_string(),
                self.scope_digest.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetLandingZoneOperationRequest {
    pub account_id: AccountId,
    pub home_region: AwsRegion,
    pub landing_zone: LandingZoneIdentity,
    pub operation_id: OperationId,
    pub observed_at: DateTime<Utc>,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
}

impl GetLandingZoneOperationRequest {
    pub fn new(
        scope: &AwsControlTowerScope,
        operation_id: OperationId,
        observed_at: DateTime<Utc>,
    ) -> ModelResult<Self> {
        if !scope.allows_operation(&operation_id) {
            return Err(ModelError::OutOfScope {
                field: "operation id",
            });
        }
        let mut request = Self {
            account_id: scope.account_id.clone(),
            home_region: scope.home_region.clone(),
            landing_zone: scope.landing_zone.clone(),
            operation_id,
            observed_at,
            permission_digest: scope.permission.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            request_digest: Digest::zero(),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    pub fn for_scope(
        scope: &AwsControlTowerScope,
        operation_id: OperationId,
        observed_at: DateTime<Utc>,
    ) -> ModelResult<Self> {
        Self::new(scope, operation_id, observed_at)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-get-landing-zone-operation-request/v1",
            &[
                self.account_id.digest().to_string(),
                self.home_region.digest().to_string(),
                self.landing_zone.digest().to_string(),
                self.operation_id.digest().to_string(),
                self.observed_at.to_rfc3339(),
                self.permission_digest.to_string(),
                self.scope_digest.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnabledBaselineFilter {
    pub baseline_ids: BTreeSet<BaselineId>,
    pub target_ids: BTreeSet<TargetReference>,
}

impl EnabledBaselineFilter {
    pub fn exact(scope: &AwsControlTowerScope) -> Self {
        Self {
            baseline_ids: scope.baseline_ids.clone(),
            target_ids: scope.target_ids.clone(),
        }
    }

    pub fn digest(&self) -> Digest {
        let mut parts = self
            .baseline_ids
            .iter()
            .map(BaselineId::digest)
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        parts.extend(
            self.target_ids
                .iter()
                .map(TargetReference::digest)
                .map(|value| value.to_string()),
        );
        Digest::from_parts("aws-control-tower-enabled-baseline-filter/v1", &parts)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListEnabledBaselinesRequest {
    pub account_id: AccountId,
    pub home_region: AwsRegion,
    pub filter: EnabledBaselineFilter,
    pub include_children: bool,
    pub page_size: u16,
    pub max_pages: u16,
    pub cursor: Option<OpaqueCursor>,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
}

impl ListEnabledBaselinesRequest {
    pub fn new(
        scope: &AwsControlTowerScope,
        include_children: bool,
        bounds: &ReadBounds,
        cursor: Option<OpaqueCursor>,
    ) -> ModelResult<Self> {
        Self::for_scope(scope, include_children, bounds, cursor)
    }

    pub fn for_scope(
        scope: &AwsControlTowerScope,
        include_children: bool,
        bounds: &ReadBounds,
        cursor: Option<OpaqueCursor>,
    ) -> ModelResult<Self> {
        let mut request = Self {
            account_id: scope.account_id.clone(),
            home_region: scope.home_region.clone(),
            filter: EnabledBaselineFilter::exact(scope),
            include_children,
            page_size: bounds.page_size,
            max_pages: bounds.max_pages,
            cursor,
            permission_digest: scope.permission.permission_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            request_digest: Digest::zero(),
        };
        request.request_digest = request.compute_digest();
        Ok(request)
    }

    #[must_use]
    pub fn with_filter(mut self, filter: EnabledBaselineFilter) -> Self {
        self.filter = filter;
        self.request_digest = self.compute_digest();
        self
    }

    #[must_use]
    pub fn with_cursor(mut self, cursor: Option<OpaqueCursor>) -> Self {
        self.cursor = cursor;
        self.request_digest = self.compute_digest();
        self
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-control-tower-list-enabled-baselines-request/v1",
            &[
                self.account_id.digest().to_string(),
                self.home_region.digest().to_string(),
                self.filter.digest().to_string(),
                self.include_children.to_string(),
                self.page_size.to_string(),
                self.max_pages.to_string(),
                self.cursor
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |cursor| cursor.digest().to_string()),
                self.permission_digest.to_string(),
                self.scope_digest.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsControlTowerReadRequest {
    ListLandingZones(ListLandingZonesRequest),
    GetLandingZone(GetLandingZoneRequest),
    GetLandingZoneOperation(GetLandingZoneOperationRequest),
    ListEnabledBaselines(ListEnabledBaselinesRequest),
}

impl AwsControlTowerReadRequest {
    pub const fn operation(&self) -> ReadOperation {
        match self {
            Self::ListLandingZones(_) => ReadOperation::ListLandingZones,
            Self::GetLandingZone(_) => ReadOperation::GetLandingZone,
            Self::GetLandingZoneOperation(_) => ReadOperation::GetLandingZoneOperation,
            Self::ListEnabledBaselines(_) => ReadOperation::ListEnabledBaselines,
        }
    }

    pub fn request_digest(&self) -> Digest {
        match self {
            Self::ListLandingZones(request) => request.request_digest.clone(),
            Self::GetLandingZone(request) => request.request_digest.clone(),
            Self::GetLandingZoneOperation(request) => request.request_digest.clone(),
            Self::ListEnabledBaselines(request) => request.request_digest.clone(),
        }
    }

    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::ListLandingZones(request) => &request.scope_digest,
            Self::GetLandingZone(request) => &request.scope_digest,
            Self::GetLandingZoneOperation(request) => &request.scope_digest,
            Self::ListEnabledBaselines(request) => &request.scope_digest,
        }
    }

    pub fn permission_digest(&self) -> &Digest {
        match self {
            Self::ListLandingZones(request) => &request.permission_digest,
            Self::GetLandingZone(request) => &request.permission_digest,
            Self::GetLandingZoneOperation(request) => &request.permission_digest,
            Self::ListEnabledBaselines(request) => &request.permission_digest,
        }
    }
}

impl Serialize for AwsControlTowerReadRequest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsControlTowerReadRequest", 2)?;
        state.serialize_field("operation", &self.operation())?;
        state.serialize_field("requestDigest", &self.request_digest())?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListLandingZonesPage {
    pub landing_zones: Vec<LandingZoneSummary>,
    pub next_token: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub response_bytes: usize,
    pub provenance: ProviderProvenance,
    pub page_digest: Digest,
}

impl ListLandingZonesPage {
    pub fn new(
        landing_zones: Vec<LandingZoneSummary>,
        next_token: Option<OpaqueCursor>,
        scope_digest: Digest,
        permission_digest: Digest,
    ) -> Self {
        Self::for_provenance(
            landing_zones,
            next_token,
            scope_digest,
            permission_digest,
            ProviderProvenance::Fixture,
        )
    }

    pub fn for_provenance(
        landing_zones: Vec<LandingZoneSummary>,
        next_token: Option<OpaqueCursor>,
        scope_digest: Digest,
        permission_digest: Digest,
        provenance: ProviderProvenance,
    ) -> Self {
        let page_digest = Digest::from_parts(
            "aws-control-tower-list-landing-zones-page/v1",
            &landing_zones
                .iter()
                .map(|item| item.arn_digest.to_string())
                .chain(next_token.as_ref().map(|token| token.digest().to_string()))
                .collect::<Vec<_>>(),
        );
        Self {
            landing_zones,
            next_token,
            scope_digest,
            permission_digest,
            response_bytes: 512,
            provenance,
            page_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListLandingZonesResponse {
    pub landing_zones: Vec<LandingZoneSummary>,
    pub pages_observed: u16,
    pub complete: bool,
    pub cursor_digests: Vec<Digest>,
    pub response_digest: Digest,
    pub provenance: ProviderProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetLandingZoneResponse {
    pub landing_zone: LandingZoneDetail,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provenance: ProviderProvenance,
}

impl GetLandingZoneResponse {
    pub fn new(
        landing_zone: LandingZoneDetail,
        response_bytes: usize,
        provenance: ProviderProvenance,
    ) -> Self {
        let response_digest = Digest::from_parts(
            "aws-control-tower-get-landing-zone-response/v1",
            &[
                landing_zone.arn_digest.to_string(),
                landing_zone.status_digest.to_string(),
                landing_zone.drift_status_digest.to_string(),
                landing_zone.version_digest.to_string(),
                landing_zone.timestamp_digest.to_string(),
            ],
        );
        Self {
            landing_zone,
            response_bytes,
            response_digest,
            provenance,
        }
    }
}

impl Serialize for GetLandingZoneResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GetLandingZoneResponse", 3)?;
        state.serialize_field("landingZone", &self.landing_zone)?;
        state.serialize_field("responseDigest", &self.response_digest)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetLandingZoneOperationResponse {
    pub operation: LandingZoneOperation,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provenance: ProviderProvenance,
}

impl GetLandingZoneOperationResponse {
    pub fn new(
        operation: LandingZoneOperation,
        response_bytes: usize,
        provenance: ProviderProvenance,
    ) -> Self {
        let response_digest = Digest::from_parts(
            "aws-control-tower-get-landing-zone-operation-response/v1",
            &[
                operation.operation_identifier_digest.to_string(),
                operation.status_digest.to_string(),
                operation.start_timestamp_digest.to_string(),
                operation
                    .end_timestamp_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), ToString::to_string),
            ],
        );
        Self {
            operation,
            response_bytes,
            response_digest,
            provenance,
        }
    }
}

impl Serialize for GetLandingZoneOperationResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("GetLandingZoneOperationResponse", 3)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("responseDigest", &self.response_digest)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListEnabledBaselinesPage {
    pub enabled_baselines: Vec<EnabledBaselineSummary>,
    pub next_token: Option<OpaqueCursor>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub response_bytes: usize,
    pub provenance: ProviderProvenance,
    pub page_digest: Digest,
}

impl ListEnabledBaselinesPage {
    pub fn new(
        enabled_baselines: Vec<EnabledBaselineSummary>,
        next_token: Option<OpaqueCursor>,
        scope_digest: Digest,
        permission_digest: Digest,
    ) -> Self {
        Self::for_provenance(
            enabled_baselines,
            next_token,
            scope_digest,
            permission_digest,
            ProviderProvenance::Fixture,
        )
    }

    pub fn for_provenance(
        enabled_baselines: Vec<EnabledBaselineSummary>,
        next_token: Option<OpaqueCursor>,
        scope_digest: Digest,
        permission_digest: Digest,
        provenance: ProviderProvenance,
    ) -> Self {
        let page_digest = Digest::from_parts(
            "aws-control-tower-list-enabled-baselines-page/v1",
            &enabled_baselines
                .iter()
                .map(|item| item.baseline_identifier_digest.to_string())
                .chain(next_token.as_ref().map(|token| token.digest().to_string()))
                .collect::<Vec<_>>(),
        );
        Self {
            enabled_baselines,
            next_token,
            scope_digest,
            permission_digest,
            response_bytes: 512,
            provenance,
            page_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListEnabledBaselinesResponse {
    pub enabled_baselines: Vec<EnabledBaselineSummary>,
    pub pages_observed: u16,
    pub complete: bool,
    pub cursor_digests: Vec<Digest>,
    pub response_digest: Digest,
    pub provenance: ProviderProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AwsControlTowerProviderResponse {
    ListLandingZones(ListLandingZonesResponse),
    GetLandingZone(GetLandingZoneResponse),
    GetLandingZoneOperation(GetLandingZoneOperationResponse),
    ListEnabledBaselines(ListEnabledBaselinesResponse),
}

impl AwsControlTowerProviderResponse {
    pub const fn operation(&self) -> ReadOperation {
        match self {
            Self::ListLandingZones(_) => ReadOperation::ListLandingZones,
            Self::GetLandingZone(_) => ReadOperation::GetLandingZone,
            Self::GetLandingZoneOperation(_) => ReadOperation::GetLandingZoneOperation,
            Self::ListEnabledBaselines(_) => ReadOperation::ListEnabledBaselines,
        }
    }

    pub fn response_digest(&self) -> Digest {
        match self {
            Self::ListLandingZones(response) => response.response_digest.clone(),
            Self::GetLandingZone(response) => response.response_digest.clone(),
            Self::GetLandingZoneOperation(response) => response.response_digest.clone(),
            Self::ListEnabledBaselines(response) => response.response_digest.clone(),
        }
    }
}

impl Serialize for AwsControlTowerProviderResponse {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsControlTowerProviderResponse", 2)?;
        state.serialize_field("operation", &self.operation())?;
        state.serialize_field("responseDigest", &self.response_digest())?;
        state.end()
    }
}

/// The transport boundary is intentionally narrower than a general AWS
/// client: every method corresponds to one of the four Layer-1 reads.
pub trait AwsControlTowerTransport: Clone + fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_landing_zones(
        &mut self,
        request: &ListLandingZonesRequest,
    ) -> std::result::Result<ListLandingZonesPage, TransportError>;

    fn get_landing_zone(
        &mut self,
        request: &GetLandingZoneRequest,
    ) -> std::result::Result<GetLandingZoneResponse, TransportError>;

    fn get_landing_zone_operation(
        &mut self,
        request: &GetLandingZoneOperationRequest,
    ) -> std::result::Result<GetLandingZoneOperationResponse, TransportError>;

    fn list_enabled_baselines(
        &mut self,
        request: &ListEnabledBaselinesRequest,
    ) -> std::result::Result<ListEnabledBaselinesPage, TransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedRequest {
    ListLandingZones(Digest),
    GetLandingZone(Digest),
    GetLandingZoneOperation(Digest),
    ListEnabledBaselines(Digest),
}

#[derive(Clone, Debug, Default)]
struct TransportQueues {
    list_landing_zones: VecDeque<std::result::Result<ListLandingZonesPage, TransportError>>,
    get_landing_zone: VecDeque<std::result::Result<GetLandingZoneResponse, TransportError>>,
    get_landing_zone_operation:
        VecDeque<std::result::Result<GetLandingZoneOperationResponse, TransportError>>,
    list_enabled_baselines: VecDeque<std::result::Result<ListEnabledBaselinesPage, TransportError>>,
}

#[derive(Clone, Debug, Default)]
pub struct FixtureAwsControlTowerTransport {
    queues: TransportQueues,
}

pub type FixtureTransport = FixtureAwsControlTowerTransport;

impl FixtureAwsControlTowerTransport {
    pub const fn fixture() -> Self {
        Self {
            queues: TransportQueues {
                list_landing_zones: VecDeque::new(),
                get_landing_zone: VecDeque::new(),
                get_landing_zone_operation: VecDeque::new(),
                list_enabled_baselines: VecDeque::new(),
            },
        }
    }

    pub fn push_list_landing_zones(
        &mut self,
        value: std::result::Result<ListLandingZonesPage, TransportError>,
    ) {
        self.queues.list_landing_zones.push_back(value);
    }

    pub fn queue_list_landing_zones(
        &mut self,
        value: std::result::Result<ListLandingZonesPage, TransportError>,
    ) {
        self.push_list_landing_zones(value);
    }

    pub fn push_get_landing_zone(
        &mut self,
        value: std::result::Result<GetLandingZoneResponse, TransportError>,
    ) {
        self.queues.get_landing_zone.push_back(value);
    }

    pub fn queue_get_landing_zone(
        &mut self,
        value: std::result::Result<GetLandingZoneResponse, TransportError>,
    ) {
        self.push_get_landing_zone(value);
    }

    pub fn push_get_landing_zone_operation(
        &mut self,
        value: std::result::Result<GetLandingZoneOperationResponse, TransportError>,
    ) {
        self.queues.get_landing_zone_operation.push_back(value);
    }

    pub fn queue_get_landing_zone_operation(
        &mut self,
        value: std::result::Result<GetLandingZoneOperationResponse, TransportError>,
    ) {
        self.push_get_landing_zone_operation(value);
    }

    pub fn push_list_enabled_baselines(
        &mut self,
        value: std::result::Result<ListEnabledBaselinesPage, TransportError>,
    ) {
        self.queues.list_enabled_baselines.push_back(value);
    }

    pub fn queue_list_enabled_baselines(
        &mut self,
        value: std::result::Result<ListEnabledBaselinesPage, TransportError>,
    ) {
        self.push_list_enabled_baselines(value);
    }
}

impl AwsControlTowerTransport for FixtureAwsControlTowerTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn list_landing_zones(
        &mut self,
        request: &ListLandingZonesRequest,
    ) -> std::result::Result<ListLandingZonesPage, TransportError> {
        self.queues
            .list_landing_zones
            .pop_front()
            .unwrap_or_else(|| {
                Ok(ListLandingZonesPage::for_provenance(
                    Vec::new(),
                    None,
                    request.scope_digest.clone(),
                    request.permission_digest.clone(),
                    ProviderProvenance::Fixture,
                ))
            })
    }

    fn get_landing_zone(
        &mut self,
        _request: &GetLandingZoneRequest,
    ) -> std::result::Result<GetLandingZoneResponse, TransportError> {
        self.queues
            .get_landing_zone
            .pop_front()
            .ok_or(TransportError::NotFound)?
    }

    fn get_landing_zone_operation(
        &mut self,
        _request: &GetLandingZoneOperationRequest,
    ) -> std::result::Result<GetLandingZoneOperationResponse, TransportError> {
        self.queues
            .get_landing_zone_operation
            .pop_front()
            .ok_or(TransportError::NotFound)?
    }

    fn list_enabled_baselines(
        &mut self,
        request: &ListEnabledBaselinesRequest,
    ) -> std::result::Result<ListEnabledBaselinesPage, TransportError> {
        self.queues
            .list_enabled_baselines
            .pop_front()
            .unwrap_or_else(|| {
                Ok(ListEnabledBaselinesPage::for_provenance(
                    Vec::new(),
                    None,
                    request.scope_digest.clone(),
                    request.permission_digest.clone(),
                    ProviderProvenance::Fixture,
                ))
            })
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingAwsControlTowerTransport {
    queues: TransportQueues,
    calls: Vec<RecordedRequest>,
}

pub type RecordingTransport = RecordingAwsControlTowerTransport;

impl RecordingAwsControlTowerTransport {
    pub fn push_list_landing_zones(
        &mut self,
        value: std::result::Result<ListLandingZonesPage, TransportError>,
    ) {
        self.queues.list_landing_zones.push_back(value);
    }

    pub fn queue_list_landing_zones(
        &mut self,
        value: std::result::Result<ListLandingZonesPage, TransportError>,
    ) {
        self.push_list_landing_zones(value);
    }

    pub fn push_get_landing_zone(
        &mut self,
        value: std::result::Result<GetLandingZoneResponse, TransportError>,
    ) {
        self.queues.get_landing_zone.push_back(value);
    }

    pub fn queue_get_landing_zone(
        &mut self,
        value: std::result::Result<GetLandingZoneResponse, TransportError>,
    ) {
        self.push_get_landing_zone(value);
    }

    pub fn push_get_landing_zone_operation(
        &mut self,
        value: std::result::Result<GetLandingZoneOperationResponse, TransportError>,
    ) {
        self.queues.get_landing_zone_operation.push_back(value);
    }

    pub fn queue_get_landing_zone_operation(
        &mut self,
        value: std::result::Result<GetLandingZoneOperationResponse, TransportError>,
    ) {
        self.push_get_landing_zone_operation(value);
    }

    pub fn push_list_enabled_baselines(
        &mut self,
        value: std::result::Result<ListEnabledBaselinesPage, TransportError>,
    ) {
        self.queues.list_enabled_baselines.push_back(value);
    }

    pub fn queue_list_enabled_baselines(
        &mut self,
        value: std::result::Result<ListEnabledBaselinesPage, TransportError>,
    ) {
        self.push_list_enabled_baselines(value);
    }

    pub fn calls(&self) -> &[RecordedRequest] {
        &self.calls
    }
}

impl AwsControlTowerTransport for RecordingAwsControlTowerTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn list_landing_zones(
        &mut self,
        request: &ListLandingZonesRequest,
    ) -> std::result::Result<ListLandingZonesPage, TransportError> {
        self.calls.push(RecordedRequest::ListLandingZones(
            request.request_digest.clone(),
        ));
        self.queues
            .list_landing_zones
            .pop_front()
            .ok_or(TransportError::NotFound)?
    }

    fn get_landing_zone(
        &mut self,
        request: &GetLandingZoneRequest,
    ) -> std::result::Result<GetLandingZoneResponse, TransportError> {
        self.calls.push(RecordedRequest::GetLandingZone(
            request.request_digest.clone(),
        ));
        self.queues
            .get_landing_zone
            .pop_front()
            .ok_or(TransportError::NotFound)?
    }

    fn get_landing_zone_operation(
        &mut self,
        request: &GetLandingZoneOperationRequest,
    ) -> std::result::Result<GetLandingZoneOperationResponse, TransportError> {
        self.calls.push(RecordedRequest::GetLandingZoneOperation(
            request.request_digest.clone(),
        ));
        self.queues
            .get_landing_zone_operation
            .pop_front()
            .ok_or(TransportError::NotFound)?
    }

    fn list_enabled_baselines(
        &mut self,
        request: &ListEnabledBaselinesRequest,
    ) -> std::result::Result<ListEnabledBaselinesPage, TransportError> {
        self.calls.push(RecordedRequest::ListEnabledBaselines(
            request.request_digest.clone(),
        ));
        self.queues
            .list_enabled_baselines
            .pop_front()
            .ok_or(TransportError::NotFound)?
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackAwsControlTowerTransport;

pub type LoopbackTransport = LoopbackAwsControlTowerTransport;

impl AwsControlTowerTransport for LoopbackAwsControlTowerTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn list_landing_zones(
        &mut self,
        request: &ListLandingZonesRequest,
    ) -> std::result::Result<ListLandingZonesPage, TransportError> {
        Ok(ListLandingZonesPage::for_provenance(
            Vec::new(),
            None,
            request.scope_digest.clone(),
            request.permission_digest.clone(),
            ProviderProvenance::Loopback,
        ))
    }

    fn get_landing_zone(
        &mut self,
        _request: &GetLandingZoneRequest,
    ) -> std::result::Result<GetLandingZoneResponse, TransportError> {
        Err(TransportError::NotFound)
    }

    fn get_landing_zone_operation(
        &mut self,
        _request: &GetLandingZoneOperationRequest,
    ) -> std::result::Result<GetLandingZoneOperationResponse, TransportError> {
        Err(TransportError::NotFound)
    }

    fn list_enabled_baselines(
        &mut self,
        request: &ListEnabledBaselinesRequest,
    ) -> std::result::Result<ListEnabledBaselinesPage, TransportError> {
        Ok(ListEnabledBaselinesPage::for_provenance(
            Vec::new(),
            None,
            request.scope_digest.clone(),
            request.permission_digest.clone(),
            ProviderProvenance::Loopback,
        ))
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAwsControlTowerTransport;

pub type BlockedEnvTransport = BlockedEnvAwsControlTowerTransport;

impl AwsControlTowerTransport for BlockedEnvAwsControlTowerTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_landing_zones(
        &mut self,
        _request: &ListLandingZonesRequest,
    ) -> std::result::Result<ListLandingZonesPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn get_landing_zone(
        &mut self,
        _request: &GetLandingZoneRequest,
    ) -> std::result::Result<GetLandingZoneResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn get_landing_zone_operation(
        &mut self,
        _request: &GetLandingZoneOperationRequest,
    ) -> std::result::Result<GetLandingZoneOperationResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn list_enabled_baselines(
        &mut self,
        _request: &ListEnabledBaselinesRequest,
    ) -> std::result::Result<ListEnabledBaselinesPage, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

pub struct AwsControlTowerProvider<T> {
    transport: T,
    definition: AwsControlTowerProviderDefinition,
    bounds: ReadBounds,
}

impl<T: AwsControlTowerTransport> fmt::Debug for AwsControlTowerProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsControlTowerProvider")
            .field("definition", &self.definition)
            .field("bounds", &self.bounds)
            .finish_non_exhaustive()
    }
}

impl<T: AwsControlTowerTransport> AwsControlTowerProvider<T> {
    pub fn new(transport: T) -> Self {
        let provenance = transport.provenance();
        Self {
            transport,
            definition: AwsControlTowerProviderDefinition::for_provenance(provenance),
            bounds: ReadBounds::default(),
        }
    }

    pub fn with_bounds(transport: T, bounds: ReadBounds) -> Self {
        let provenance = transport.provenance();
        Self {
            transport,
            definition: AwsControlTowerProviderDefinition::for_provenance(provenance),
            bounds,
        }
    }

    pub fn definition(&self) -> &AwsControlTowerProviderDefinition {
        &self.definition
    }

    pub fn bounds(&self) -> &ReadBounds {
        &self.bounds
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn validate(&self) -> ProviderResult<()> {
        self.definition.validate()?;
        Ok(())
    }

    pub fn read(
        &mut self,
        request: &AwsControlTowerReadRequest,
    ) -> ProviderResult<AwsControlTowerProviderResponse> {
        self.validate()?;
        match request {
            AwsControlTowerReadRequest::ListLandingZones(request) => {
                Ok(AwsControlTowerProviderResponse::ListLandingZones(
                    self.list_landing_zones(request)?,
                ))
            }
            AwsControlTowerReadRequest::GetLandingZone(request) => Ok(
                AwsControlTowerProviderResponse::GetLandingZone(self.get_landing_zone(request)?),
            ),
            AwsControlTowerReadRequest::GetLandingZoneOperation(request) => {
                Ok(AwsControlTowerProviderResponse::GetLandingZoneOperation(
                    self.get_landing_zone_operation(request)?,
                ))
            }
            AwsControlTowerReadRequest::ListEnabledBaselines(request) => {
                Ok(AwsControlTowerProviderResponse::ListEnabledBaselines(
                    self.list_enabled_baselines(request)?,
                ))
            }
        }
    }

    pub fn list_landing_zones(
        &mut self,
        request: &ListLandingZonesRequest,
    ) -> ProviderResult<ListLandingZonesResponse> {
        Self::validate_list_request(request, ReadOperation::ListLandingZones)?;
        let mut cursor = request.cursor.clone();
        let mut pages_observed = 0;
        let complete = true;
        let mut cursor_digests = Vec::new();
        let mut landing_zones = Vec::new();
        let mut identities = BTreeSet::new();
        loop {
            if pages_observed >= request.max_pages {
                return Err(ProviderError::PaginationIncomplete);
            }
            let page_request = request.clone().with_cursor(cursor.clone());
            let page = self.transport.list_landing_zones(&page_request)?;
            self.validate_page_common(
                &page.scope_digest,
                &page.permission_digest,
                page.provenance,
                page.response_bytes,
            )?;
            if page.scope_digest != request.scope_digest {
                return Err(ProviderError::ScopeMismatch);
            }
            if page.permission_digest != request.permission_digest {
                return Err(ProviderError::PermissionLoss);
            }
            if page.landing_zones.len() > request.page_size as usize {
                return Err(ProviderError::ResponseItemBound);
            }
            for item in page.landing_zones {
                item.verify()?;
                item.landing_zone
                    .verify_against(&request.account_id, &request.home_region)
                    .map_err(|error| match error {
                        ModelError::AccountMismatch { .. } => ProviderError::AccountMismatch,
                        ModelError::RegionMismatch { .. } => ProviderError::RegionMismatch,
                        other => ProviderError::Model(other),
                    })?;
                if !identities.insert(item.arn_digest.clone()) {
                    return Err(ProviderError::DuplicateItem);
                }
                landing_zones.push(item);
                if landing_zones.len() > MAX_ITEMS {
                    return Err(ProviderError::ResponseItemBound);
                }
            }
            pages_observed += 1;
            cursor = page.next_token;
            if let Some(next) = &cursor {
                cursor_digests.push(next.digest());
            } else {
                break;
            }
        }
        let response_digest = digest_items(
            "aws-control-tower-list-landing-zones-response/v1",
            landing_zones.iter().map(|item| item.arn_digest.clone()),
            &cursor_digests,
        );
        Ok(ListLandingZonesResponse {
            landing_zones,
            pages_observed,
            complete,
            cursor_digests,
            response_digest,
            provenance: self.definition.provenance,
        })
    }

    pub fn get_landing_zone(
        &mut self,
        request: &GetLandingZoneRequest,
    ) -> ProviderResult<GetLandingZoneResponse> {
        Self::validate_request_digest(request.request_digest.clone(), request.compute_digest())?;
        if request.landing_zone.account_id().as_ref() != Some(&request.account_id)
            || request.landing_zone.region().as_ref() != Some(&request.home_region)
        {
            return Err(ProviderError::RegionMismatch);
        }
        let response = self.transport.get_landing_zone(request)?;
        if response.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        response.landing_zone.verify()?;
        response
            .landing_zone
            .landing_zone
            .verify_against(&request.account_id, &request.home_region)
            .map_err(|error| match error {
                ModelError::AccountMismatch { .. } => ProviderError::AccountMismatch,
                ModelError::RegionMismatch { .. } => ProviderError::RegionMismatch,
                other => ProviderError::Model(other),
            })?;
        if response.landing_zone.landing_zone != request.landing_zone {
            return Err(ProviderError::LandingZoneDrift);
        }
        if response.provenance != self.definition.provenance {
            return Err(ProviderError::DefinitionMismatch);
        }
        Ok(response)
    }

    pub fn get_landing_zone_operation(
        &mut self,
        request: &GetLandingZoneOperationRequest,
    ) -> ProviderResult<GetLandingZoneOperationResponse> {
        Self::validate_request_digest(request.request_digest.clone(), request.compute_digest())?;
        let response = self.transport.get_landing_zone_operation(request)?;
        if response.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        response.operation.verify()?;
        if response.operation.operation_id != request.operation_id
            || response.operation.landing_zone != request.landing_zone
        {
            return Err(ProviderError::ScopeMismatch);
        }
        response
            .operation
            .landing_zone
            .verify_against(&request.account_id, &request.home_region)
            .map_err(|error| match error {
                ModelError::AccountMismatch { .. } => ProviderError::AccountMismatch,
                ModelError::RegionMismatch { .. } => ProviderError::RegionMismatch,
                other => ProviderError::Model(other),
            })?;
        response
            .operation
            .verify_retention(request.observed_at)
            .map_err(|_| ProviderError::RetentionExpired)?;
        if response.provenance != self.definition.provenance {
            return Err(ProviderError::DefinitionMismatch);
        }
        Ok(response)
    }

    pub fn list_enabled_baselines(
        &mut self,
        request: &ListEnabledBaselinesRequest,
    ) -> ProviderResult<ListEnabledBaselinesResponse> {
        Self::validate_list_request(request, ReadOperation::ListEnabledBaselines)?;
        if request.filter.baseline_ids.is_empty() || request.filter.target_ids.is_empty() {
            return Err(ProviderError::ScopeMismatch);
        }
        let mut cursor = request.cursor.clone();
        let mut pages_observed = 0;
        let complete = true;
        let mut cursor_digests = Vec::new();
        let mut enabled_baselines = Vec::new();
        let mut identities = BTreeSet::new();
        loop {
            if pages_observed >= request.max_pages {
                return Err(ProviderError::PaginationIncomplete);
            }
            let page_request = request.clone().with_cursor(cursor.clone());
            let page = self.transport.list_enabled_baselines(&page_request)?;
            self.validate_page_common(
                &page.scope_digest,
                &page.permission_digest,
                page.provenance,
                page.response_bytes,
            )?;
            if page.scope_digest != request.scope_digest {
                return Err(ProviderError::ScopeMismatch);
            }
            if page.permission_digest != request.permission_digest {
                return Err(ProviderError::PermissionLoss);
            }
            if page.enabled_baselines.len() > request.page_size as usize {
                return Err(ProviderError::ResponseItemBound);
            }
            for item in page.enabled_baselines {
                item.verify()?;
                if item
                    .target
                    .account_id()
                    .as_ref()
                    .is_some_and(|account| account != &request.account_id)
                {
                    return Err(ProviderError::AccountMismatch);
                }
                if item
                    .baseline_id
                    .arn_account_region()
                    .is_some_and(|(account, region)| {
                        account != request.account_id || region != request.home_region
                    })
                {
                    return Err(ProviderError::RegionMismatch);
                }
                if item.is_child && !request.include_children {
                    return Err(ProviderError::ChildBaselineUnexpected);
                }
                if !request.filter.baseline_ids.contains(&item.baseline_id)
                    || !request.filter.target_ids.contains(&item.target)
                    || (item.is_child
                        && item
                            .parent_target
                            .as_ref()
                            .is_none_or(|parent| !request.filter.target_ids.contains(parent)))
                {
                    return Err(ProviderError::BaselineDrift);
                }
                if !identities.insert(item.baseline_identifier_digest.clone()) {
                    return Err(ProviderError::DuplicateItem);
                }
                enabled_baselines.push(item);
                if enabled_baselines.len() > MAX_ITEMS {
                    return Err(ProviderError::ResponseItemBound);
                }
            }
            pages_observed += 1;
            cursor = page.next_token;
            if let Some(next) = &cursor {
                cursor_digests.push(next.digest());
            } else {
                break;
            }
        }
        let response_digest = digest_items(
            "aws-control-tower-list-enabled-baselines-response/v1",
            enabled_baselines
                .iter()
                .map(|item| item.baseline_identifier_digest.clone()),
            &cursor_digests,
        );
        Ok(ListEnabledBaselinesResponse {
            enabled_baselines,
            pages_observed,
            complete,
            cursor_digests,
            response_digest,
            provenance: self.definition.provenance,
        })
    }

    fn validate_list_request<R>(request: &R, _operation: ReadOperation) -> ProviderResult<()>
    where
        R: RequestDigest,
    {
        Self::validate_request_digest(
            request.request_digest_value(),
            request.compute_request_digest(),
        )?;
        if request.page_size_value() == 0
            || request.page_size_value() > MAX_PAGE_SIZE
            || request.max_pages_value() == 0
            || request.max_pages_value() > MAX_PAGES
        {
            return Err(ProviderError::RequestDrift);
        }
        Ok(())
    }

    fn validate_page_common(
        &self,
        scope_digest: &Digest,
        permission_digest: &Digest,
        provenance: ProviderProvenance,
        response_bytes: usize,
    ) -> ProviderResult<()> {
        if scope_digest.is_zero() || permission_digest.is_zero() {
            return Err(ProviderError::ScopeMismatch);
        }
        if provenance != self.definition.provenance {
            return Err(ProviderError::DefinitionMismatch);
        }
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTooLarge);
        }
        Ok(())
    }

    fn validate_request_digest(actual: Digest, expected: Digest) -> ProviderResult<()> {
        if actual != expected {
            Err(ProviderError::RequestDrift)
        } else {
            Ok(())
        }
    }
}

trait RequestDigest {
    fn request_digest_value(&self) -> Digest;
    fn compute_request_digest(&self) -> Digest;
    fn page_size_value(&self) -> u16;
    fn max_pages_value(&self) -> u16;
}

impl RequestDigest for ListLandingZonesRequest {
    fn request_digest_value(&self) -> Digest {
        self.request_digest.clone()
    }
    fn compute_request_digest(&self) -> Digest {
        self.compute_digest()
    }
    fn page_size_value(&self) -> u16 {
        self.page_size
    }
    fn max_pages_value(&self) -> u16 {
        self.max_pages
    }
}

impl RequestDigest for ListEnabledBaselinesRequest {
    fn request_digest_value(&self) -> Digest {
        self.request_digest.clone()
    }
    fn compute_request_digest(&self) -> Digest {
        self.compute_digest()
    }
    fn page_size_value(&self) -> u16 {
        self.page_size
    }
    fn max_pages_value(&self) -> u16 {
        self.max_pages
    }
}

fn digest_items<I>(domain: &str, items: I, cursor_digests: &[Digest]) -> Digest
where
    I: IntoIterator<Item = Digest>,
{
    let mut parts = items
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>();
    parts.extend(cursor_digests.iter().map(ToString::to_string));
    Digest::from_parts(domain, &parts)
}

pub type AwsControlTowerReadRecord = AwsControlTowerProviderResponse;
