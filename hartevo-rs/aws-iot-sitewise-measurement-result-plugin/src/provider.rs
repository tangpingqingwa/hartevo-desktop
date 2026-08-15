//! Allowlisted provider seams and deterministic non-native transports.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsIoTSiteWiseMeasurementError, AwsIoTSiteWiseTransportError, Result};
use crate::model::{
    AssetDescription, AssetProjection, AwsIoTSiteWiseMeasurementScope, Cursor, Digest,
    MeasurementAggregate, MeasurementPoint, MeasurementSample, PropertyDescription, SiteWiseCursor,
    TransportProvenance,
};
use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_API_REVISION, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AwsIoTSiteWiseOperation {
    ListAssets,
    DescribeAsset,
    DescribeAssetProperty,
    GetAssetPropertyValueHistory,
}

impl AwsIoTSiteWiseOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListAssets => "ListAssets",
            Self::DescribeAsset => "DescribeAsset",
            Self::DescribeAssetProperty => "DescribeAssetProperty",
            Self::GetAssetPropertyValueHistory => "GetAssetPropertyValueHistory",
        }
    }
}

pub trait AwsIoTSiteWiseTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_assets(
        &mut self,
        request: &ListAssetsRequest,
    ) -> std::result::Result<ListAssetsResponse, AwsIoTSiteWiseTransportError>;

    fn describe_asset(
        &mut self,
        request: &DescribeAssetRequest,
    ) -> std::result::Result<DescribeAssetResponse, AwsIoTSiteWiseTransportError>;

    fn describe_asset_property(
        &mut self,
        request: &DescribeAssetPropertyRequest,
    ) -> std::result::Result<DescribeAssetPropertyResponse, AwsIoTSiteWiseTransportError>;

    fn get_asset_property_value_history(
        &mut self,
        request: &GetAssetPropertyValueHistoryRequest,
    ) -> std::result::Result<MeasurementHistoryResponse, AwsIoTSiteWiseTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsIoTSiteWiseOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub path_digest: Digest,
}

fn list_assets_binding(scope: &AwsIoTSiteWiseMeasurementScope) -> Digest {
    Digest::from_parts(
        "aws-iot-sitewise-list-assets-filter/v1",
        &[
            ("scope", scope.digest().as_str().to_owned()),
            (
                "asset_model",
                scope.asset_model_id().digest().as_str().to_owned(),
            ),
            ("max_page_size", crate::MAX_PAGE_SIZE.to_string()),
        ],
    )
}

fn history_binding(scope: &AwsIoTSiteWiseMeasurementScope) -> Digest {
    Digest::from_parts(
        "aws-iot-sitewise-history-filter/v1",
        &[
            ("scope", scope.digest().as_str().to_owned()),
            ("window_start", scope.time_window().start.to_rfc3339()),
            ("window_end", scope.time_window().end.to_rfc3339()),
            ("quality", format!("{:?}", scope.quality())),
            ("max_points", scope.bounds().max_points.to_string()),
            ("max_pages", scope.bounds().max_pages.to_string()),
            ("order", "ASCENDING".to_owned()),
        ],
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListAssetsRequest {
    scope: AwsIoTSiteWiseMeasurementScope,
    cursor: Option<Cursor>,
    binding_digest: Digest,
    request_digest: Digest,
    page_number: u16,
}

impl ListAssetsRequest {
    pub fn for_scope(
        scope: &AwsIoTSiteWiseMeasurementScope,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        let binding_digest = list_assets_binding(scope);
        let page_number = cursor.as_ref().map_or(1, SiteWiseCursor::page_number);
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &binding_digest)?;
        }
        let request_digest = Digest::from_parts(
            "aws-iot-sitewise-list-assets-request/v1",
            &[
                ("binding", binding_digest.as_str().to_owned()),
                ("page", page_number.to_string()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |cursor| {
                        cursor.token_digest().as_str().to_owned()
                    }),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            cursor,
            binding_digest,
            request_digest,
            page_number,
        })
    }

    pub fn scope(&self) -> &AwsIoTSiteWiseMeasurementScope {
        &self.scope
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/assets?assetModelIdDigest={}&maxResults={}&nextTokenDigest={}",
            self.scope.asset_model_id().digest().as_str(),
            crate::MAX_PAGE_SIZE,
            self.cursor
                .as_ref()
                .map_or_else(String::new, |cursor| cursor
                    .token_digest()
                    .as_str()
                    .to_owned()),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsIoTSiteWiseOperation::ListAssets,
            scope_digest: self.scope.digest(),
            request_digest: self.request_digest.clone(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for ListAssetsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListAssetsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("binding_digest", &self.binding_digest)
            .field("request_digest", &self.request_digest)
            .field("cursor", &self.cursor)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeAssetRequest {
    scope: AwsIoTSiteWiseMeasurementScope,
    request_digest: Digest,
}

impl DescribeAssetRequest {
    pub fn for_scope(scope: &AwsIoTSiteWiseMeasurementScope) -> Result<Self> {
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-iot-sitewise-describe-asset-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("asset", scope.asset_id().digest().as_str().to_owned()),
                    ("model", scope.asset_model_id().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsIoTSiteWiseMeasurementScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/assets/{}/?assetModelIdDigest={}",
            self.scope.asset_id().digest().as_str(),
            self.scope.asset_model_id().digest().as_str(),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsIoTSiteWiseOperation::DescribeAsset,
            scope_digest: self.scope.digest(),
            request_digest: self.request_digest.clone(),
            cursor_digest: None,
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for DescribeAssetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeAssetRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct DescribeAssetPropertyRequest {
    scope: AwsIoTSiteWiseMeasurementScope,
    request_digest: Digest,
}

impl DescribeAssetPropertyRequest {
    pub fn for_scope(scope: &AwsIoTSiteWiseMeasurementScope) -> Result<Self> {
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-iot-sitewise-describe-asset-property-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("asset", scope.asset_id().digest().as_str().to_owned()),
                    ("model", scope.asset_model_id().digest().as_str().to_owned()),
                    ("property", scope.property_id().digest().as_str().to_owned()),
                    (
                        "alias",
                        scope
                            .property_alias()
                            .map_or_else(String::new, |alias| alias.digest().as_str().to_owned()),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsIoTSiteWiseMeasurementScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/assets/{}/properties/{}?assetModelIdDigest={}",
            self.scope.asset_id().digest().as_str(),
            self.scope.property_id().digest().as_str(),
            self.scope.asset_model_id().digest().as_str(),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsIoTSiteWiseOperation::DescribeAssetProperty,
            scope_digest: self.scope.digest(),
            request_digest: self.request_digest.clone(),
            cursor_digest: None,
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for DescribeAssetPropertyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescribeAssetPropertyRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetAssetPropertyValueHistoryRequest {
    scope: AwsIoTSiteWiseMeasurementScope,
    cursor: Option<Cursor>,
    binding_digest: Digest,
    request_digest: Digest,
    page_number: u16,
}

impl GetAssetPropertyValueHistoryRequest {
    pub fn for_scope(
        scope: &AwsIoTSiteWiseMeasurementScope,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        let binding_digest = history_binding(scope);
        let page_number = cursor.as_ref().map_or(1, SiteWiseCursor::page_number);
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &binding_digest)?;
        }
        let request_digest = Digest::from_parts(
            "aws-iot-sitewise-history-request/v1",
            &[
                ("binding", binding_digest.as_str().to_owned()),
                ("page", page_number.to_string()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |cursor| {
                        cursor.token_digest().as_str().to_owned()
                    }),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            cursor,
            binding_digest,
            request_digest,
            page_number,
        })
    }

    pub fn scope(&self) -> &AwsIoTSiteWiseMeasurementScope {
        &self.scope
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn page_point_limit(&self) -> u32 {
        if self.scope.bounds().max_points < u32::from(crate::MAX_PAGE_SIZE) {
            self.scope.bounds().max_points
        } else {
            u32::from(crate::MAX_PAGE_SIZE)
        }
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/assets/{}/properties/{}/propertyValueHistory?assetModelIdDigest={}&startDate={}&endDate={}&quality={:?}&orderBy=ASCENDING&maxResults={}&nextTokenDigest={}",
            self.scope.asset_id().digest().as_str(),
            self.scope.property_id().digest().as_str(),
            self.scope.asset_model_id().digest().as_str(),
            self.scope.time_window().start,
            self.scope.time_window().end,
            self.scope.quality(),
            self.page_point_limit(),
            self.cursor
                .as_ref()
                .map_or_else(String::new, |cursor| cursor
                    .token_digest()
                    .as_str()
                    .to_owned()),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsIoTSiteWiseOperation::GetAssetPropertyValueHistory,
            scope_digest: self.scope.digest(),
            request_digest: self.request_digest.clone(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.token_digest().clone()),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetAssetPropertyValueHistoryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetAssetPropertyValueHistoryRequest")
            .field("scope_digest", &self.scope.digest())
            .field("binding_digest", &self.binding_digest)
            .field("request_digest", &self.request_digest)
            .field("cursor", &self.cursor)
            .field("page_number", &self.page_number)
            .field("page_point_limit", &self.page_point_limit())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListAssetsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub assets: Vec<AssetProjection>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListAssetsResponse {
    pub fn new(
        request: &ListAssetsRequest,
        assets: Vec<AssetProjection>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes, request.scope())?;
        validate_next_cursor(
            next_cursor.as_ref(),
            request.scope(),
            request.binding_digest(),
            request.page_number(),
        )?;
        if assets.len() > crate::MAX_PAGE_SIZE as usize {
            return Err(AwsIoTSiteWiseMeasurementError::PointLimitExceeded);
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            assets,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-iot-sitewise-list-assets"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self.evidence_digest = self.calculate_digest();
        self
    }

    pub const fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListAssetsRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes, request.scope())?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.assets.len() > crate::MAX_PAGE_SIZE as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
        }
        validate_next_cursor(
            self.next_cursor.as_ref(),
            request.scope(),
            request.binding_digest(),
            request.page_number(),
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-list-assets-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "assets",
                    self.assets
                        .iter()
                        .map(AssetProjection::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAssetResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub asset: AssetDescription,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeAssetResponse {
    pub fn new(
        request: &DescribeAssetRequest,
        asset: AssetDescription,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes, request.scope())?;
        asset.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            asset,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-iot-sitewise-describe-asset"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self.evidence_digest = self.calculate_digest();
        self
    }

    pub fn validate_integrity(&self, request: &DescribeAssetRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes, request.scope())?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
        }
        self.asset.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-describe-asset-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("asset", self.asset.digest().as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeAssetPropertyResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub property: PropertyDescription,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl DescribeAssetPropertyResponse {
    pub fn new(
        request: &DescribeAssetPropertyRequest,
        property: PropertyDescription,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes, request.scope())?;
        property.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            property,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-iot-sitewise-describe-property"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self.evidence_digest = self.calculate_digest();
        self
    }

    pub fn validate_integrity(&self, request: &DescribeAssetPropertyRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes, request.scope())?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
        }
        self.property.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-describe-property-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("property", self.property.digest().as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasurementHistoryResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub points: Vec<MeasurementPoint>,
    pub aggregate: MeasurementAggregate,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl MeasurementHistoryResponse {
    pub fn from_samples(
        request: &GetAssetPropertyValueHistoryRequest,
        samples: Vec<MeasurementSample>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        if samples.len() > request.page_point_limit() as usize {
            return Err(AwsIoTSiteWiseMeasurementError::PointLimitExceeded);
        }
        let points = samples
            .iter()
            .map(MeasurementPoint::from_sample)
            .collect::<Result<Vec<_>>>()?;
        let aggregate = MeasurementAggregate::from_samples(&samples, &points)?;
        Self::new(
            request,
            points,
            aggregate,
            next_cursor,
            response_bytes,
            provenance,
        )
    }

    pub fn from_points(
        request: &GetAssetPropertyValueHistoryRequest,
        points: Vec<MeasurementPoint>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let aggregate = MeasurementAggregate::from_points(&points);
        Self::new(
            request,
            points,
            aggregate,
            next_cursor,
            response_bytes,
            provenance,
        )
    }

    pub fn new(
        request: &GetAssetPropertyValueHistoryRequest,
        points: Vec<MeasurementPoint>,
        aggregate: MeasurementAggregate,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes, request.scope())?;
        if points.len() > request.page_point_limit() as usize {
            return Err(AwsIoTSiteWiseMeasurementError::PointLimitExceeded);
        }
        validate_next_cursor(
            next_cursor.as_ref(),
            request.scope(),
            request.binding_digest(),
            request.page_number(),
        )?;
        validate_points(request.scope(), &points)?;
        aggregate.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            points,
            aggregate,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-iot-sitewise-history"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn with_provenance(mut self, provenance: TransportProvenance) -> Self {
        self.provenance = provenance;
        self.evidence_digest = self.calculate_digest();
        self
    }

    pub const fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &GetAssetPropertyValueHistoryRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes, request.scope())?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.points.len() > request.page_point_limit() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
        }
        validate_points(request.scope(), &self.points)?;
        validate_aggregate_points(&self.aggregate, &self.points)?;
        self.aggregate.validate()?;
        validate_next_cursor(
            self.next_cursor.as_ref(),
            request.scope(),
            request.binding_digest(),
            request.page_number(),
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-history-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "points",
                    self.points
                        .iter()
                        .map(MeasurementPoint::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "aggregate",
                    self.aggregate.aggregate_digest.as_str().to_owned(),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.token_digest().as_str().to_owned()
                        }),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

fn validate_points(
    scope: &AwsIoTSiteWiseMeasurementScope,
    points: &[MeasurementPoint],
) -> Result<()> {
    let mut previous = None;
    for point in points {
        point.validate_against(scope)?;
        if let Some(previous) = previous {
            if point.timestamp < previous {
                return Err(AwsIoTSiteWiseMeasurementError::OrderingViolation);
            }
        }
        previous = Some(point.timestamp);
    }
    Ok(())
}

fn validate_aggregate_points(
    aggregate: &MeasurementAggregate,
    points: &[MeasurementPoint],
) -> Result<()> {
    let expected = MeasurementAggregate::from_points(points);
    if aggregate.count != expected.count
        || aggregate.quality_counts != expected.quality_counts
        || aggregate.timestamp_digest != expected.timestamp_digest
        || aggregate.value_digest != expected.value_digest
    {
        return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
    }
    Ok(())
}

fn validate_next_cursor(
    cursor: Option<&Cursor>,
    scope: &AwsIoTSiteWiseMeasurementScope,
    binding_digest: &Digest,
    page_number: u16,
) -> Result<()> {
    if let Some(cursor) = cursor {
        cursor.validate_against(scope, binding_digest)?;
        if cursor.page_number() != page_number.saturating_add(1) {
            return Err(AwsIoTSiteWiseMeasurementError::CursorMismatch);
        }
    }
    Ok(())
}

fn validate_response_bytes(
    response_bytes: u64,
    scope: &AwsIoTSiteWiseMeasurementScope,
) -> Result<()> {
    if response_bytes > scope.bounds().max_response_bytes {
        Err(AwsIoTSiteWiseMeasurementError::ResponseTooLarge)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsIoTSiteWiseProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AwsIoTSiteWiseProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsIoTSiteWiseMeasurementError::ProviderDrift);
        }
        let capability_digest = provider_capability_digest();
        let provider_digest = Digest::from_parts(
            "aws-iot-sitewise-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
                ("connected", "false".to_owned()),
                ("native", "false".to_owned()),
                ("first_party", "false".to_owned()),
            ],
        );
        let definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        };
        definition.validate()?;
        Ok(definition)
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != PROVIDER_API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(AwsIoTSiteWiseMeasurementError::ProviderDrift);
        }
        self.capability_digest.validate()?;
        self.provider_digest.validate()?;
        if self.capability_digest != provider_capability_digest()
            || self.provider_digest != self.calculate_digest()
        {
            return Err(AwsIoTSiteWiseMeasurementError::ProviderDrift);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-provider/v1",
            &[
                ("provider_id", self.provider_id.clone()),
                ("revision", self.provider_revision.to_string()),
                ("api_revision", self.api_revision.clone()),
                ("contract", self.contract_version.clone()),
                ("release", self.release.clone()),
                ("capability", self.capability_digest.as_str().to_owned()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
            ],
        )
    }
}

fn provider_capability_digest() -> Digest {
    Digest::from_parts(
        "aws-iot-sitewise-provider-capabilities/v1",
        &LAYER1_PERMISSIONS
            .iter()
            .map(|permission| ("permission", (*permission).to_owned()))
            .chain(
                [
                    "ListAssets",
                    "DescribeAsset",
                    "DescribeAssetProperty",
                    "GetAssetPropertyValueHistory",
                ]
                .into_iter()
                .map(|operation| ("operation", operation.to_owned())),
            )
            .collect::<Vec<_>>(),
    )
}

impl Serialize for AwsIoTSiteWiseProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsIoTSiteWiseProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

pub struct AwsIoTSiteWiseProvider<T> {
    transport: T,
    definition: AwsIoTSiteWiseProviderDefinition,
}

impl<T: AwsIoTSiteWiseTransport> fmt::Debug for AwsIoTSiteWiseProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsIoTSiteWiseProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsIoTSiteWiseTransport> AwsIoTSiteWiseProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(
            transport,
            AwsIoTSiteWiseProviderDefinition::new(1, "l1-recording-1")?,
        )
    }

    pub fn with_identity(
        transport: T,
        definition: AwsIoTSiteWiseProviderDefinition,
    ) -> Result<Self> {
        definition.validate()?;
        if transport.provenance().is_native() || transport.provenance().is_connected() {
            return Err(AwsIoTSiteWiseMeasurementError::ProviderDrift);
        }
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsIoTSiteWiseProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn list_assets(&mut self, request: &ListAssetsRequest) -> Result<ListAssetsResponse> {
        let response = self.transport.list_assets(request)?;
        response.validate_integrity(request)?;
        Ok(response)
    }

    pub fn describe_asset(
        &mut self,
        request: &DescribeAssetRequest,
    ) -> Result<DescribeAssetResponse> {
        let response = self.transport.describe_asset(request)?;
        response.validate_integrity(request)?;
        Ok(response)
    }

    pub fn describe_asset_property(
        &mut self,
        request: &DescribeAssetPropertyRequest,
    ) -> Result<DescribeAssetPropertyResponse> {
        let response = self.transport.describe_asset_property(request)?;
        response.validate_integrity(request)?;
        Ok(response)
    }

    pub fn get_asset_property_value_history(
        &mut self,
        request: &GetAssetPropertyValueHistoryRequest,
    ) -> Result<MeasurementHistoryResponse> {
        let response = self.transport.get_asset_property_value_history(request)?;
        response.validate_integrity(request)?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsIoTSiteWiseProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked environment provider identity")
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_assets: VecDeque<std::result::Result<ListAssetsResponse, AwsIoTSiteWiseTransportError>>,
    describe_asset:
        VecDeque<std::result::Result<DescribeAssetResponse, AwsIoTSiteWiseTransportError>>,
    describe_property:
        VecDeque<std::result::Result<DescribeAssetPropertyResponse, AwsIoTSiteWiseTransportError>>,
    history:
        VecDeque<std::result::Result<MeasurementHistoryResponse, AwsIoTSiteWiseTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Result<Self> {
        if provenance == TransportProvenance::BlockedEnv {
            return Err(AwsIoTSiteWiseMeasurementError::InvalidRequest);
        }
        Ok(Self {
            provenance,
            list_assets: VecDeque::new(),
            describe_asset: VecDeque::new(),
            describe_property: VecDeque::new(),
            history: VecDeque::new(),
            requests: Vec::new(),
        })
    }

    pub fn push_list_assets_response(
        &mut self,
        response: std::result::Result<ListAssetsResponse, AwsIoTSiteWiseTransportError>,
    ) {
        self.list_assets.push_back(response);
    }

    pub fn push_describe_asset_response(
        &mut self,
        response: std::result::Result<DescribeAssetResponse, AwsIoTSiteWiseTransportError>,
    ) {
        self.describe_asset.push_back(response);
    }

    pub fn push_describe_asset_property_response(
        &mut self,
        response: std::result::Result<DescribeAssetPropertyResponse, AwsIoTSiteWiseTransportError>,
    ) {
        self.describe_property.push_back(response);
    }

    pub fn push_history_response(
        &mut self,
        response: std::result::Result<MeasurementHistoryResponse, AwsIoTSiteWiseTransportError>,
    ) {
        self.history.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording).expect("recording transport provenance")
    }
}

impl AwsIoTSiteWiseTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_assets(
        &mut self,
        request: &ListAssetsRequest,
    ) -> std::result::Result<ListAssetsResponse, AwsIoTSiteWiseTransportError> {
        self.requests.push(request.recorded_request());
        self.list_assets.pop_front().unwrap_or({
            Err(AwsIoTSiteWiseTransportError::MissingRecording(
                AwsIoTSiteWiseOperation::ListAssets,
            ))
        })
    }

    fn describe_asset(
        &mut self,
        request: &DescribeAssetRequest,
    ) -> std::result::Result<DescribeAssetResponse, AwsIoTSiteWiseTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_asset.pop_front().unwrap_or({
            Err(AwsIoTSiteWiseTransportError::MissingRecording(
                AwsIoTSiteWiseOperation::DescribeAsset,
            ))
        })
    }

    fn describe_asset_property(
        &mut self,
        request: &DescribeAssetPropertyRequest,
    ) -> std::result::Result<DescribeAssetPropertyResponse, AwsIoTSiteWiseTransportError> {
        self.requests.push(request.recorded_request());
        self.describe_property.pop_front().unwrap_or({
            Err(AwsIoTSiteWiseTransportError::MissingRecording(
                AwsIoTSiteWiseOperation::DescribeAssetProperty,
            ))
        })
    }

    fn get_asset_property_value_history(
        &mut self,
        request: &GetAssetPropertyValueHistoryRequest,
    ) -> std::result::Result<MeasurementHistoryResponse, AwsIoTSiteWiseTransportError> {
        self.requests.push(request.recorded_request());
        self.history.pop_front().unwrap_or({
            Err(AwsIoTSiteWiseTransportError::MissingRecording(
                AwsIoTSiteWiseOperation::GetAssetPropertyValueHistory,
            ))
        })
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsIoTSiteWiseMeasurementScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsIoTSiteWiseMeasurementScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn samples(&self) -> Result<Vec<MeasurementSample>> {
        let window = self.scope.time_window();
        let span = window.duration().num_seconds();
        let first = window.start + Duration::seconds((span / 3).max(0));
        let anchor = if window.contains(self.observed_at) {
            self.observed_at
        } else {
            window.end
        };
        let second_offset = (anchor - window.start)
            .num_seconds()
            .min(span.saturating_mul(2) / 3)
            .max(0);
        let second = window.start + Duration::seconds(second_offset);
        let second_quality = if self
            .scope
            .quality()
            .accepts(crate::MeasurementQuality::Uncertain)
        {
            crate::MeasurementQuality::Uncertain
        } else {
            crate::MeasurementQuality::Good
        };
        Ok(vec![
            MeasurementSample::double(first, crate::MeasurementQuality::Good, 42.5)?,
            MeasurementSample::double(second, second_quality, 43.0)?,
        ])
    }
}

impl AwsIoTSiteWiseTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_assets(
        &mut self,
        request: &ListAssetsRequest,
    ) -> std::result::Result<ListAssetsResponse, AwsIoTSiteWiseTransportError> {
        ListAssetsResponse::new(
            request,
            vec![AssetProjection::for_scope(request.scope()).map_err(|_| {
                AwsIoTSiteWiseTransportError::Malformed(AwsIoTSiteWiseOperation::ListAssets)
            })?],
            None,
            1024,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsIoTSiteWiseTransportError::Malformed(AwsIoTSiteWiseOperation::ListAssets))
    }

    fn describe_asset(
        &mut self,
        request: &DescribeAssetRequest,
    ) -> std::result::Result<DescribeAssetResponse, AwsIoTSiteWiseTransportError> {
        DescribeAssetResponse::new(
            request,
            AssetDescription::for_scope(request.scope()).map_err(|_| {
                AwsIoTSiteWiseTransportError::Malformed(AwsIoTSiteWiseOperation::DescribeAsset)
            })?,
            1024,
            TransportProvenance::Fixture,
        )
        .map_err(|_| {
            AwsIoTSiteWiseTransportError::Malformed(AwsIoTSiteWiseOperation::DescribeAsset)
        })
    }

    fn describe_asset_property(
        &mut self,
        request: &DescribeAssetPropertyRequest,
    ) -> std::result::Result<DescribeAssetPropertyResponse, AwsIoTSiteWiseTransportError> {
        DescribeAssetPropertyResponse::new(
            request,
            PropertyDescription::for_scope(request.scope()).map_err(|_| {
                AwsIoTSiteWiseTransportError::Malformed(
                    AwsIoTSiteWiseOperation::DescribeAssetProperty,
                )
            })?,
            1024,
            TransportProvenance::Fixture,
        )
        .map_err(|_| {
            AwsIoTSiteWiseTransportError::Malformed(AwsIoTSiteWiseOperation::DescribeAssetProperty)
        })
    }

    fn get_asset_property_value_history(
        &mut self,
        request: &GetAssetPropertyValueHistoryRequest,
    ) -> std::result::Result<MeasurementHistoryResponse, AwsIoTSiteWiseTransportError> {
        MeasurementHistoryResponse::from_samples(
            request,
            self.samples().map_err(|_| {
                AwsIoTSiteWiseTransportError::Malformed(
                    AwsIoTSiteWiseOperation::GetAssetPropertyValueHistory,
                )
            })?,
            None,
            2048,
            TransportProvenance::Fixture,
        )
        .map_err(|_| {
            AwsIoTSiteWiseTransportError::Malformed(
                AwsIoTSiteWiseOperation::GetAssetPropertyValueHistory,
            )
        })
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    scope: AwsIoTSiteWiseMeasurementScope,
    observed_at: DateTime<Utc>,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsIoTSiteWiseMeasurementScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn fixture(&self) -> FixtureTransport {
        FixtureTransport::for_scope(&self.scope, self.observed_at)
    }
}

impl AwsIoTSiteWiseTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_assets(
        &mut self,
        request: &ListAssetsRequest,
    ) -> std::result::Result<ListAssetsResponse, AwsIoTSiteWiseTransportError> {
        FixtureTransport::list_assets(&mut self.fixture(), request)
            .map(|response| response.with_provenance(TransportProvenance::Loopback))
    }

    fn describe_asset(
        &mut self,
        request: &DescribeAssetRequest,
    ) -> std::result::Result<DescribeAssetResponse, AwsIoTSiteWiseTransportError> {
        FixtureTransport::describe_asset(&mut self.fixture(), request)
            .map(|response| response.with_provenance(TransportProvenance::Loopback))
    }

    fn describe_asset_property(
        &mut self,
        request: &DescribeAssetPropertyRequest,
    ) -> std::result::Result<DescribeAssetPropertyResponse, AwsIoTSiteWiseTransportError> {
        FixtureTransport::describe_asset_property(&mut self.fixture(), request)
            .map(|response| response.with_provenance(TransportProvenance::Loopback))
    }

    fn get_asset_property_value_history(
        &mut self,
        request: &GetAssetPropertyValueHistoryRequest,
    ) -> std::result::Result<MeasurementHistoryResponse, AwsIoTSiteWiseTransportError> {
        FixtureTransport::get_asset_property_value_history(&mut self.fixture(), request)
            .map(|response| response.with_provenance(TransportProvenance::Loopback))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl AwsIoTSiteWiseTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_assets(
        &mut self,
        _request: &ListAssetsRequest,
    ) -> std::result::Result<ListAssetsResponse, AwsIoTSiteWiseTransportError> {
        Err(AwsIoTSiteWiseTransportError::BlockedEnv(
            AwsIoTSiteWiseOperation::ListAssets,
        ))
    }

    fn describe_asset(
        &mut self,
        _request: &DescribeAssetRequest,
    ) -> std::result::Result<DescribeAssetResponse, AwsIoTSiteWiseTransportError> {
        Err(AwsIoTSiteWiseTransportError::BlockedEnv(
            AwsIoTSiteWiseOperation::DescribeAsset,
        ))
    }

    fn describe_asset_property(
        &mut self,
        _request: &DescribeAssetPropertyRequest,
    ) -> std::result::Result<DescribeAssetPropertyResponse, AwsIoTSiteWiseTransportError> {
        Err(AwsIoTSiteWiseTransportError::BlockedEnv(
            AwsIoTSiteWiseOperation::DescribeAssetProperty,
        ))
    }

    fn get_asset_property_value_history(
        &mut self,
        _request: &GetAssetPropertyValueHistoryRequest,
    ) -> std::result::Result<MeasurementHistoryResponse, AwsIoTSiteWiseTransportError> {
        Err(AwsIoTSiteWiseTransportError::BlockedEnv(
            AwsIoTSiteWiseOperation::GetAssetPropertyValueHistory,
        ))
    }
}
