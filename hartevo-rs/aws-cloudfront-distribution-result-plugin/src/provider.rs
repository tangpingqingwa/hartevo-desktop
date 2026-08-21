use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AwsCloudFrontDistributionError, AwsCloudFrontTransportError, Result};
use crate::model::{
    AwsCloudFrontDistributionScope, CostReceipt, Digest, DistributionConfigInput,
    DistributionConfigMetadata, DistributionStatus, DistributionSummary, RequestReceipt,
    TransportProvenance, validate_page_number, validate_page_size,
};
use crate::{API_REVISION, CONTRACT_VERSION, MAX_RESPONSE_BYTES, PROVIDER_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AwsCloudFrontOperation {
    ListDistributions,
    GetDistribution,
    GetDistributionConfig,
}

impl AwsCloudFrontOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListDistributions => "ListDistributions",
            Self::GetDistribution => "GetDistribution",
            Self::GetDistributionConfig => "GetDistributionConfig",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct Cursor {
    marker_digest: Digest,
    scope_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new(
        opaque_marker: impl Into<String>,
        scope: &AwsCloudFrontDistributionScope,
        page_number: u16,
    ) -> Result<Self> {
        let marker = opaque_marker.into();
        if marker.is_empty() || marker.len() > crate::MAX_IDENTIFIER_BYTES || page_number < 2 {
            return Err(AwsCloudFrontDistributionError::InvalidRequest);
        }
        let cursor = Self {
            marker_digest: Digest::from_parts(
                "aws-cloudfront-opaque-marker/v1",
                &[
                    ("marker", marker),
                    ("scope", scope.digest().as_str().to_owned()),
                ],
            ),
            scope_digest: scope.digest(),
            page_number,
        };
        cursor.validate(scope)?;
        Ok(cursor)
    }

    pub fn marker_digest(&self) -> &Digest {
        &self.marker_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    fn validate(&self, scope: &AwsCloudFrontDistributionScope) -> Result<()> {
        validate_page_number(self.page_number)?;
        if self.scope_digest != scope.digest() {
            return Err(AwsCloudFrontDistributionError::CursorMismatch);
        }
        self.marker_digest.validate()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("marker_digest", &self.marker_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsCloudFrontOperation,
    pub scope_digest: Digest,
    pub distribution_digest: Digest,
    pub page_number: Option<u16>,
    pub marker_digest: Option<Digest>,
    pub expected_etag_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub redacted: bool,
}

impl RecordedRequest {
    pub fn receipt(&self) -> RequestReceipt {
        RequestReceipt::new(
            self.operation.as_str(),
            self.request_digest.clone(),
            self.path_digest.clone(),
        )
    }

    fn validate(&self) -> Result<()> {
        if !self.redacted {
            return Err(AwsCloudFrontDistributionError::TamperedEvidence);
        }
        self.scope_digest.validate()?;
        self.distribution_digest.validate()?;
        self.marker_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.expected_etag_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.request_digest.validate()?;
        self.path_digest.validate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListDistributionsRequest {
    scope: AwsCloudFrontDistributionScope,
    page_size: u16,
    page_number: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListDistributionsRequest {
    pub fn new(
        scope: &AwsCloudFrontDistributionScope,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        let page_number = cursor.as_ref().map_or(1, Cursor::page_number);
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate(scope)?;
        }
        let request_digest = Digest::from_parts(
            "aws-cloudfront-list-distributions-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "marker",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.marker_digest().as_str().to_owned()
                    }),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_number,
            cursor,
            request_digest,
        })
    }

    pub fn first(scope: &AwsCloudFrontDistributionScope, page_size: u16) -> Result<Self> {
        Self::new(scope, page_size, None)
    }

    pub fn scope(&self) -> &AwsCloudFrontDistributionScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/2020-05-31/distribution?Marker={}&MaxItems={}",
            self.cursor
                .as_ref()
                .map_or_else(String::new, |cursor| cursor.marker_digest().as_str()[..16]
                    .to_owned()),
            self.page_size
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCloudFrontOperation::ListDistributions,
            scope_digest: self.scope.digest(),
            distribution_digest: self.scope.distribution().digest(),
            page_number: Some(self.page_number),
            marker_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.marker_digest().clone()),
            expected_etag_digest: self.scope.expected_etag_digest().cloned(),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
            redacted: true,
        }
    }
}

impl fmt::Debug for ListDistributionsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListDistributionsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetDistributionRequest {
    scope: AwsCloudFrontDistributionScope,
    request_digest: Digest,
}

impl GetDistributionRequest {
    pub fn for_scope(scope: &AwsCloudFrontDistributionScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-cloudfront-get-distribution-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    (
                        "distribution",
                        scope.distribution().digest().as_str().to_owned(),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsCloudFrontDistributionScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/2020-05-31/distribution/{}",
            &self.scope.distribution().id_digest().as_str()[..16]
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCloudFrontOperation::GetDistribution,
            scope_digest: self.scope.digest(),
            distribution_digest: self.scope.distribution().digest(),
            page_number: None,
            marker_digest: None,
            expected_etag_digest: self.scope.expected_etag_digest().cloned(),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
            redacted: true,
        }
    }
}

impl fmt::Debug for GetDistributionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetDistributionRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetDistributionConfigRequest {
    scope: AwsCloudFrontDistributionScope,
    expected_etag_digest: Digest,
    request_digest: Digest,
}

impl GetDistributionConfigRequest {
    pub fn new(
        scope: &AwsCloudFrontDistributionScope,
        expected_etag_digest: Digest,
    ) -> Result<Self> {
        scope.validate()?;
        expected_etag_digest.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-cloudfront-get-distribution-config-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    (
                        "distribution",
                        scope.distribution().digest().as_str().to_owned(),
                    ),
                    ("etag", expected_etag_digest.as_str().to_owned()),
                ],
            ),
            expected_etag_digest,
        })
    }

    pub fn for_scope(scope: &AwsCloudFrontDistributionScope) -> Result<Self> {
        let expected = scope
            .expected_etag_digest()
            .cloned()
            .unwrap_or_else(|| Digest::from_text("unbound-layer1-etag"));
        Self::new(scope, expected)
    }

    pub fn scope(&self) -> &AwsCloudFrontDistributionScope {
        &self.scope
    }

    pub fn expected_etag_digest(&self) -> &Digest {
        &self.expected_etag_digest
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/2020-05-31/distribution/{}/config?IfMatch={}",
            &self.scope.distribution().id_digest().as_str()[..16],
            &self.expected_etag_digest.as_str()[..16]
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsCloudFrontOperation::GetDistributionConfig,
            scope_digest: self.scope.digest(),
            distribution_digest: self.scope.distribution().digest(),
            page_number: None,
            marker_digest: None,
            expected_etag_digest: Some(self.expected_etag_digest.clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
            redacted: true,
        }
    }
}

impl fmt::Debug for GetDistributionConfigRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetDistributionConfigRequest")
            .field("scope_digest", &self.scope.digest())
            .field("expected_etag_digest", &self.expected_etag_digest)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDistributionsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub distributions: Vec<DistributionSummary>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl ListDistributionsResponse {
    pub fn new(
        request: &ListDistributionsRequest,
        distributions: Vec<DistributionSummary>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if distributions.len() > request.page_size() as usize {
            return Err(AwsCloudFrontDistributionError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate(request.scope())?;
            if cursor.page_number() != request.page_number().saturating_add(1)
                || request
                    .cursor()
                    .is_some_and(|previous| previous.marker_digest() == cursor.marker_digest())
            {
                return Err(AwsCloudFrontDistributionError::PaginationLoop);
            }
        }
        for distribution in &distributions {
            distribution.validate_against(request.scope())?;
        }
        let request_record = request.recorded_request();
        request_record.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            distributions,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-cloudfront-list-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: request_record.receipt(),
            cost_receipt: CostReceipt::new(
                AwsCloudFrontOperation::ListDistributions.as_str(),
                response_bytes,
            )?,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListDistributionsRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.distributions.len() > request.page_size() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsCloudFrontDistributionError::TamperedEvidence);
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        for distribution in &self.distributions {
            distribution.validate_against(request.scope())?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate(request.scope())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsCloudFrontDistributionError::CursorMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-list-distributions-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "distributions",
                    crate::model::join_digests(
                        self.distributions.iter().map(DistributionSummary::digest),
                    ),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.marker_digest().as_str().to_owned()
                        }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDistributionResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub distribution: DistributionSummary,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl GetDistributionResponse {
    pub fn new(
        request: &GetDistributionRequest,
        distribution: DistributionSummary,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        distribution.validate_against(request.scope())?;
        let request_record = request.recorded_request();
        request_record.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            distribution,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-cloudfront-get-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: request_record.receipt(),
            cost_receipt: CostReceipt::new(
                AwsCloudFrontOperation::GetDistribution.as_str(),
                response_bytes,
            )?,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetDistributionRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsCloudFrontDistributionError::TamperedEvidence);
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        self.distribution.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-get-distribution-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "distribution",
                    self.distribution.digest().as_str().to_owned(),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDistributionConfigResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub config: DistributionConfigMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl GetDistributionConfigResponse {
    pub fn new(
        request: &GetDistributionConfigRequest,
        config: DistributionConfigMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        config.validate_against(request.scope(), request.expected_etag_digest())?;
        let request_record = request.recorded_request();
        request_record.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            config,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-cloudfront-config-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: request_record.receipt(),
            cost_receipt: CostReceipt::new(
                AwsCloudFrontOperation::GetDistributionConfig.as_str(),
                response_bytes,
            )?,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetDistributionConfigRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsCloudFrontDistributionError::TamperedEvidence);
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        self.config
            .validate_against(request.scope(), request.expected_etag_digest())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-get-distribution-config-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("config", self.config.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

fn validate_response_bytes(response_bytes: u64) -> Result<()> {
    if response_bytes > MAX_RESPONSE_BYTES {
        Err(AwsCloudFrontDistributionError::PartialEvidence)
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AwsCloudFrontProviderDefinition {
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

impl AwsCloudFrontProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsCloudFrontDistributionError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-cloudfront-provider-capabilities/v1",
            &crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-cloudfront-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            Err(AwsCloudFrontDistributionError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsCloudFrontProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsCloudFrontProviderDefinition", 10)?;
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

pub trait AwsCloudFrontTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_distributions(
        &mut self,
        request: &ListDistributionsRequest,
    ) -> std::result::Result<ListDistributionsResponse, AwsCloudFrontTransportError>;

    fn get_distribution(
        &mut self,
        request: &GetDistributionRequest,
    ) -> std::result::Result<GetDistributionResponse, AwsCloudFrontTransportError>;

    fn get_distribution_config(
        &mut self,
        request: &GetDistributionConfigRequest,
    ) -> std::result::Result<GetDistributionConfigResponse, AwsCloudFrontTransportError>;
}

pub struct AwsCloudFrontProvider<T> {
    transport: T,
    definition: AwsCloudFrontProviderDefinition,
}

impl<T: AwsCloudFrontTransport> fmt::Debug for AwsCloudFrontProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudFrontProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsCloudFrontTransport> AwsCloudFrontProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsCloudFrontProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsCloudFrontProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn list_distributions(
        &mut self,
        request: &ListDistributionsRequest,
    ) -> std::result::Result<ListDistributionsResponse, AwsCloudFrontTransportError> {
        let response = self.transport.list_distributions(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn get_distribution(
        &mut self,
        request: &GetDistributionRequest,
    ) -> std::result::Result<GetDistributionResponse, AwsCloudFrontTransportError> {
        let response = self.transport.get_distribution(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn get_distribution_config(
        &mut self,
        request: &GetDistributionConfigRequest,
    ) -> std::result::Result<GetDistributionConfigResponse, AwsCloudFrontTransportError> {
        let response = self.transport.get_distribution_config(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

fn validate_response(
    validation: Result<()>,
    response_provenance: TransportProvenance,
    expected_provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
) -> std::result::Result<(), AwsCloudFrontTransportError> {
    match validation {
        Ok(()) => {}
        Err(AwsCloudFrontDistributionError::ConfigDrift) => {
            return Err(AwsCloudFrontTransportError::ConfigDrift);
        }
        Err(AwsCloudFrontDistributionError::PaginationLoop) => {
            return Err(AwsCloudFrontTransportError::PaginationLoop);
        }
        Err(AwsCloudFrontDistributionError::TamperedEvidence) => {
            return Err(AwsCloudFrontTransportError::Tampered);
        }
        Err(_) => return Err(AwsCloudFrontTransportError::InvalidResponse),
    }
    if response_provenance != expected_provenance
        || connected
        || native
        || first_party
        || provider_receipt
        || response_provenance.is_native()
        || response_provenance.is_connected()
        || response_provenance.is_first_party()
    {
        return Err(AwsCloudFrontTransportError::InvalidResponse);
    }
    Ok(())
}

impl Default for AwsCloudFrontProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked CloudFront provider definition")
    }
}

impl<T: AwsCloudFrontTransport> AwsCloudFrontProvider<T> {
    pub fn from_registration(
        registration: &crate::service::AwsCloudFrontDistributionRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsCloudFrontDistributionError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses:
        VecDeque<std::result::Result<ListDistributionsResponse, AwsCloudFrontTransportError>>,
    get_responses:
        VecDeque<std::result::Result<GetDistributionResponse, AwsCloudFrontTransportError>>,
    config_responses:
        VecDeque<std::result::Result<GetDistributionConfigResponse, AwsCloudFrontTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            get_responses: VecDeque::new(),
            config_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListDistributionsResponse, AwsCloudFrontTransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_response(
        &mut self,
        response: std::result::Result<GetDistributionResponse, AwsCloudFrontTransportError>,
    ) {
        self.get_responses.push_back(response);
    }

    pub fn push_config_response(
        &mut self,
        response: std::result::Result<GetDistributionConfigResponse, AwsCloudFrontTransportError>,
    ) {
        self.config_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl AwsCloudFrontTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn list_distributions(
        &mut self,
        request: &ListDistributionsRequest,
    ) -> std::result::Result<ListDistributionsResponse, AwsCloudFrontTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AwsCloudFrontTransportError::InvalidResponse))
    }

    fn get_distribution(
        &mut self,
        request: &GetDistributionRequest,
    ) -> std::result::Result<GetDistributionResponse, AwsCloudFrontTransportError> {
        self.requests.push(request.recorded_request());
        self.get_responses
            .pop_front()
            .unwrap_or(Err(AwsCloudFrontTransportError::InvalidResponse))
    }

    fn get_distribution_config(
        &mut self,
        request: &GetDistributionConfigRequest,
    ) -> std::result::Result<GetDistributionConfigResponse, AwsCloudFrontTransportError> {
        self.requests.push(request.recorded_request());
        self.config_responses
            .pop_front()
            .unwrap_or(Err(AwsCloudFrontTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsCloudFrontDistributionScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsCloudFrontDistributionScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn summary(&self) -> Result<DistributionSummary> {
        DistributionSummary::new(
            self.scope.distribution().clone(),
            DistributionStatus::Deployed,
            true,
            self.observed_at - Duration::minutes(5),
            "fixture-etag",
        )
    }

    fn config(&self) -> Result<DistributionConfigMetadata> {
        let input = DistributionConfigInput::new(
            "fixture-etag",
            "fixture-config-revision",
            vec![
                "www.example.com".to_owned(),
                "assets.example.com".to_owned(),
            ],
            vec![crate::model::OriginMetadataInput::new(
                "origin-primary",
                "origin.example.com",
                "https-only",
                Some("oac-fixture"),
                3,
                10,
            )?],
            vec![crate::model::CacheBehaviorMetadataInput::new(
                "/*",
                "origin-primary",
                "redirect-to-https",
                Some("cache-policy-fixture"),
                Some("origin-request-fixture"),
                Some("response-headers-fixture"),
            )?],
            crate::model::ViewerCertificateInput::new("acm", "TLSv1.2_2021", "sni-only", false)?,
            Some("waf-fixture"),
        )?;
        DistributionConfigMetadata::new(&self.scope, input)
    }

    fn list_response(
        &self,
        request: &ListDistributionsRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<ListDistributionsResponse, AwsCloudFrontTransportError> {
        ListDistributionsResponse::new(
            request,
            vec![
                self.summary()
                    .map_err(|_| AwsCloudFrontTransportError::InvalidResponse)?,
            ],
            None,
            1_024,
            provenance,
        )
        .map_err(|_| AwsCloudFrontTransportError::InvalidResponse)
    }

    fn get_response(
        &self,
        request: &GetDistributionRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<GetDistributionResponse, AwsCloudFrontTransportError> {
        GetDistributionResponse::new(
            request,
            self.summary()
                .map_err(|_| AwsCloudFrontTransportError::InvalidResponse)?,
            1_024,
            provenance,
        )
        .map_err(|_| AwsCloudFrontTransportError::InvalidResponse)
    }

    fn config_response(
        &self,
        request: &GetDistributionConfigRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<GetDistributionConfigResponse, AwsCloudFrontTransportError> {
        GetDistributionConfigResponse::new(
            request,
            self.config().map_err(|error| match error {
                AwsCloudFrontDistributionError::ConfigDrift => {
                    AwsCloudFrontTransportError::ConfigDrift
                }
                _ => AwsCloudFrontTransportError::InvalidResponse,
            })?,
            1_024,
            provenance,
        )
        .map_err(|error| match error {
            AwsCloudFrontDistributionError::ConfigDrift => AwsCloudFrontTransportError::ConfigDrift,
            _ => AwsCloudFrontTransportError::InvalidResponse,
        })
    }
}

impl AwsCloudFrontTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_distributions(
        &mut self,
        request: &ListDistributionsRequest,
    ) -> std::result::Result<ListDistributionsResponse, AwsCloudFrontTransportError> {
        self.list_response(request, TransportProvenance::Fixture)
    }

    fn get_distribution(
        &mut self,
        request: &GetDistributionRequest,
    ) -> std::result::Result<GetDistributionResponse, AwsCloudFrontTransportError> {
        self.get_response(request, TransportProvenance::Fixture)
    }

    fn get_distribution_config(
        &mut self,
        request: &GetDistributionConfigRequest,
    ) -> std::result::Result<GetDistributionConfigResponse, AwsCloudFrontTransportError> {
        self.config_response(request, TransportProvenance::Fixture)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsCloudFrontDistributionScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsCloudFrontTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_distributions(
        &mut self,
        request: &ListDistributionsRequest,
    ) -> std::result::Result<ListDistributionsResponse, AwsCloudFrontTransportError> {
        self.inner
            .list_response(request, TransportProvenance::Loopback)
    }

    fn get_distribution(
        &mut self,
        request: &GetDistributionRequest,
    ) -> std::result::Result<GetDistributionResponse, AwsCloudFrontTransportError> {
        self.inner
            .get_response(request, TransportProvenance::Loopback)
    }

    fn get_distribution_config(
        &mut self,
        request: &GetDistributionConfigRequest,
    ) -> std::result::Result<GetDistributionConfigResponse, AwsCloudFrontTransportError> {
        self.inner
            .config_response(request, TransportProvenance::Loopback)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsCloudFrontTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_distributions(
        &mut self,
        _request: &ListDistributionsRequest,
    ) -> std::result::Result<ListDistributionsResponse, AwsCloudFrontTransportError> {
        Err(AwsCloudFrontTransportError::BlockedEnv)
    }

    fn get_distribution(
        &mut self,
        _request: &GetDistributionRequest,
    ) -> std::result::Result<GetDistributionResponse, AwsCloudFrontTransportError> {
        Err(AwsCloudFrontTransportError::BlockedEnv)
    }

    fn get_distribution_config(
        &mut self,
        _request: &GetDistributionConfigRequest,
    ) -> std::result::Result<GetDistributionConfigResponse, AwsCloudFrontTransportError> {
        Err(AwsCloudFrontTransportError::BlockedEnv)
    }
}
