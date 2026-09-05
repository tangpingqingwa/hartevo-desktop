//! Digest-only Amazon DataZone provider seams.
//!
//! There is intentionally no AWS SDK, SigV4 signer, credential resolver, HTTP
//! client, principal resolver, schema/form path, data-access path, or
//! subscription/grant effect path in this Layer-1 crate.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;

use crate::error::{AwsDataZoneSubscriptionResultError, AwsDataZoneTransportError, Result};
use crate::model::{
    AssetMetadata, AssetMetadataInput, AwsDataZoneSubscriptionScope, Cursor, Digest,
    SubscriptionMetadata, SubscriptionRequestFilter, SubscriptionRequestMetadata,
    SubscriptionRequestStatus, SubscriptionStatus, TransportProvenance, validate_response_bytes,
};
use crate::service::AwsDataZoneSubscriptionResultRegistration;
use crate::{CONTRACT_VERSION, LAYER1_PERMISSIONS, PROVIDER_API_REVISION, PROVIDER_ID};

pub const GET_ASSET_OPERATION_PATH: &str = "/domains/{domainIdentifier}/assets/{identifier}";
pub const GET_SUBSCRIPTION_REQUEST_DETAILS_OPERATION_PATH: &str =
    "/domains/{domainIdentifier}/subscription-requests/{identifier}";
pub const GET_SUBSCRIPTION_OPERATION_PATH: &str =
    "/domains/{domainIdentifier}/subscriptions/{identifier}";
pub const LIST_SUBSCRIPTION_REQUESTS_OPERATION_PATH: &str =
    "/domains/{domainIdentifier}/subscription-requests";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsDataZoneOperation {
    GetAsset,
    GetSubscriptionRequestDetails,
    GetSubscription,
    ListSubscriptionRequests,
}

impl AwsDataZoneOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetAsset => "GetAsset",
            Self::GetSubscriptionRequestDetails => "GetSubscriptionRequestDetails",
            Self::GetSubscription => "GetSubscription",
            Self::ListSubscriptionRequests => "ListSubscriptionRequests",
        }
    }
}

/// The only provider transport trait exposed by Layer 1.
pub trait AwsDataZoneTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_asset(
        &mut self,
        request: &GetAssetRequest,
    ) -> std::result::Result<GetAssetResponse, AwsDataZoneTransportError>;

    fn get_subscription_request_details(
        &mut self,
        request: &GetSubscriptionRequestDetailsRequest,
    ) -> std::result::Result<GetSubscriptionRequestDetailsResponse, AwsDataZoneTransportError>;

    fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequest,
    ) -> std::result::Result<GetSubscriptionResponse, AwsDataZoneTransportError>;

    fn list_subscription_requests(
        &mut self,
        request: &ListSubscriptionRequestsRequest,
    ) -> std::result::Result<ListSubscriptionRequestsResponse, AwsDataZoneTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AwsDataZoneOperation,
    pub scope_digest: Digest,
    pub filter_digest: Option<Digest>,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetAssetRequest {
    scope: AwsDataZoneSubscriptionScope,
    request_digest: Digest,
}

impl GetAssetRequest {
    pub fn for_scope(scope: &AwsDataZoneSubscriptionScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-datazone-get-asset-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("asset", scope.asset().digest().as_str().to_owned()),
                    (
                        "revision",
                        scope.asset().revision_digest().as_str().to_owned(),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsDataZoneSubscriptionScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{GET_ASSET_OPERATION_PATH}?domainDigest={}&assetDigest={}&revisionDigest={}",
            self.scope.domain().digest().as_str(),
            self.scope.asset().id().digest().as_str(),
            self.scope.asset().revision_digest().as_str(),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsDataZoneOperation::GetAsset,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetAssetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetAssetRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetSubscriptionRequestDetailsRequest {
    scope: AwsDataZoneSubscriptionScope,
    request_digest: Digest,
}

impl GetSubscriptionRequestDetailsRequest {
    pub fn for_scope(scope: &AwsDataZoneSubscriptionScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-datazone-get-subscription-request-details-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    (
                        "subscription_request",
                        scope.subscription_request().digest().as_str().to_owned(),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsDataZoneSubscriptionScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{GET_SUBSCRIPTION_REQUEST_DETAILS_OPERATION_PATH}?domainDigest={}&requestDigest={}",
            self.scope.domain().digest().as_str(),
            self.scope.subscription_request().digest().as_str(),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsDataZoneOperation::GetSubscriptionRequestDetails,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetSubscriptionRequestDetailsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetSubscriptionRequestDetailsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetSubscriptionRequestForSubscription {
    scope: AwsDataZoneSubscriptionScope,
    request_digest: Digest,
}

impl GetSubscriptionRequestForSubscription {
    pub fn for_scope(scope: &AwsDataZoneSubscriptionScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "aws-datazone-get-subscription-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    (
                        "subscription",
                        scope.subscription().digest().as_str().to_owned(),
                    ),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &AwsDataZoneSubscriptionScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{GET_SUBSCRIPTION_OPERATION_PATH}?domainDigest={}&subscriptionDigest={}",
            self.scope.domain().digest().as_str(),
            self.scope.subscription().digest().as_str(),
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsDataZoneOperation::GetSubscription,
            scope_digest: self.scope.digest(),
            filter_digest: None,
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }
}

impl fmt::Debug for GetSubscriptionRequestForSubscription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetSubscriptionRequestForSubscription")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

pub type GetSubscriptionRequest = GetSubscriptionRequestForSubscription;
pub type GetSubscriptionRequestV1 = GetSubscriptionRequestForSubscription;

#[derive(Clone, Eq, PartialEq)]
pub struct ListSubscriptionRequestsRequest {
    scope: AwsDataZoneSubscriptionScope,
    filter: SubscriptionRequestFilter,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListSubscriptionRequestsRequest {
    pub fn new(
        scope: &AwsDataZoneSubscriptionScope,
        filter: SubscriptionRequestFilter,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        filter.validate_against(scope)?;
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, &filter)?;
            if cursor.page_number() == 1 {
                return Err(AwsDataZoneSubscriptionResultError::CursorMismatch);
            }
        }
        let request_digest = Digest::from_parts(
            "aws-datazone-list-subscription-requests-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("filter", filter.digest().as_str().to_owned()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                (
                    "page",
                    cursor
                        .as_ref()
                        .map_or_else(|| "1".to_owned(), |value| value.page_number().to_string()),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            filter,
            cursor,
            request_digest,
        })
    }

    pub fn scope(&self) -> &AwsDataZoneSubscriptionScope {
        &self.scope
    }

    pub fn filter(&self) -> &SubscriptionRequestFilter {
        &self.filter
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn page_number(&self) -> u16 {
        self.cursor.as_ref().map_or(1, Cursor::page_number)
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AwsDataZoneOperation::ListSubscriptionRequests,
            scope_digest: self.scope.digest(),
            filter_digest: Some(self.filter.digest()),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|value| value.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
        }
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{LIST_SUBSCRIPTION_REQUESTS_OPERATION_PATH}?domainDigest={}&assetDigest={}&maxResults={}&status={}&nextTokenDigest={}",
            self.scope.domain().digest().as_str(),
            self.filter.asset_digest().as_str(),
            self.filter.max_results(),
            self.filter
                .status()
                .map_or_else(String::new, |value| value.as_str().to_owned()),
            self.cursor.as_ref().map_or_else(String::new, |value| value
                .token_digest()
                .as_str()
                .to_owned()),
        )
    }
}

impl fmt::Debug for ListSubscriptionRequestsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListSubscriptionRequestsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("filter", &self.filter)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAssetResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: AssetMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetAssetResponse {
    pub fn new(
        request: &GetAssetRequest,
        metadata: AssetMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-datazone-get-asset-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetAssetRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::TamperedEvidence);
        }
        self.metadata.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-get-asset-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSubscriptionRequestDetailsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: SubscriptionRequestMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetSubscriptionRequestDetailsResponse {
    pub fn new(
        request: &GetSubscriptionRequestDetailsRequest,
        metadata: SubscriptionRequestMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text(
                "unsealed-aws-datazone-get-subscription-request-details-response",
            ),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetSubscriptionRequestDetailsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::TamperedEvidence);
        }
        self.metadata.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-get-subscription-request-details-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSubscriptionResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: SubscriptionMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetSubscriptionResponse {
    pub fn new(
        request: &GetSubscriptionRequestForSubscription,
        metadata: SubscriptionMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-datazone-get-subscription-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(
        &self,
        request: &GetSubscriptionRequestForSubscription,
    ) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::TamperedEvidence);
        }
        self.metadata.validate_against(request.scope())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-get-subscription-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSubscriptionRequestsResponse {
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub items: Vec<SubscriptionRequestMetadata>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListSubscriptionRequestsResponse {
    pub fn new(
        request: &ListSubscriptionRequestsRequest,
        items: Vec<SubscriptionRequestMetadata>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if items.len() > request.filter().max_results() as usize {
            return Err(AwsDataZoneSubscriptionResultError::PartialEvidence);
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsDataZoneSubscriptionResultError::CursorMismatch);
            }
        }
        for item in &items {
            item.validate_against(request.scope())?;
            if item.asset_digest != *request.filter().asset_digest() {
                return Err(AwsDataZoneSubscriptionResultError::FilterMismatch);
            }
        }
        let mut response = Self {
            scope_digest: request.scope().digest(),
            filter_digest: request.filter().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            items,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-aws-datazone-list-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListSubscriptionRequestsRequest) -> Result<()> {
        if self.scope_digest != request.scope().digest()
            || self.filter_digest != request.filter().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.items.len() > request.filter().max_results() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AwsDataZoneSubscriptionResultError::TamperedEvidence);
        }
        for item in &self.items {
            item.validate_against(request.scope())?;
            if item.asset_digest != *request.filter().asset_digest() {
                return Err(AwsDataZoneSubscriptionResultError::FilterMismatch);
            }
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.filter())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AwsDataZoneSubscriptionResultError::CursorMismatch);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-datazone-list-subscription-requests-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "items",
                    self.items
                        .iter()
                        .map(SubscriptionRequestMetadata::digest)
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
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct AwsDataZoneProviderDefinition {
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

impl AwsDataZoneProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AwsDataZoneSubscriptionResultError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "aws-datazone-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "aws-datazone-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", PROVIDER_API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
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
        })
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
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            Err(AwsDataZoneSubscriptionResultError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AwsDataZoneProviderDefinition {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AwsDataZoneProviderDefinition", 10)?;
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

pub struct AwsDataZoneProvider<T> {
    transport: T,
    definition: AwsDataZoneProviderDefinition,
}

impl<T: AwsDataZoneTransport> fmt::Debug for AwsDataZoneProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsDataZoneProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AwsDataZoneTransport> AwsDataZoneProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AwsDataZoneProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AwsDataZoneProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn get_asset(
        &mut self,
        request: &GetAssetRequest,
    ) -> std::result::Result<GetAssetResponse, AwsDataZoneTransportError> {
        let response = self.transport.get_asset(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        self.validate_response_provenance(
            response.provenance,
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn get_subscription_request_details(
        &mut self,
        request: &GetSubscriptionRequestDetailsRequest,
    ) -> std::result::Result<GetSubscriptionRequestDetailsResponse, AwsDataZoneTransportError> {
        let response = self.transport.get_subscription_request_details(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        self.validate_response_provenance(
            response.provenance,
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequestForSubscription,
    ) -> std::result::Result<GetSubscriptionResponse, AwsDataZoneTransportError> {
        let response = self.transport.get_subscription(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        self.validate_response_provenance(
            response.provenance,
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn list_subscription_requests(
        &mut self,
        request: &ListSubscriptionRequestsRequest,
    ) -> std::result::Result<ListSubscriptionRequestsResponse, AwsDataZoneTransportError> {
        let response = self.transport.list_subscription_requests(request)?;
        response
            .validate_integrity(request)
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        self.validate_response_provenance(
            response.provenance,
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    fn validate_response_provenance(
        &self,
        provenance: TransportProvenance,
        connected: bool,
        native: bool,
        first_party: bool,
        provider_receipt: bool,
    ) -> std::result::Result<(), AwsDataZoneTransportError> {
        if provenance != self.provenance() || connected || native || first_party || provider_receipt
        {
            Err(AwsDataZoneTransportError::InvalidResponse)
        } else {
            Ok(())
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl Default for AwsDataZoneProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked Amazon DataZone provider definition")
    }
}

impl<T: AwsDataZoneTransport> AwsDataZoneProvider<T> {
    pub fn from_registration(
        registration: &AwsDataZoneSubscriptionResultRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AwsDataZoneSubscriptionResultError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    get_asset_responses: VecDeque<std::result::Result<GetAssetResponse, AwsDataZoneTransportError>>,
    get_subscription_request_details_responses: VecDeque<
        std::result::Result<GetSubscriptionRequestDetailsResponse, AwsDataZoneTransportError>,
    >,
    get_subscription_responses:
        VecDeque<std::result::Result<GetSubscriptionResponse, AwsDataZoneTransportError>>,
    list_subscription_requests_responses:
        VecDeque<std::result::Result<ListSubscriptionRequestsResponse, AwsDataZoneTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            get_asset_responses: VecDeque::new(),
            get_subscription_request_details_responses: VecDeque::new(),
            get_subscription_responses: VecDeque::new(),
            list_subscription_requests_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_get_asset_response(
        &mut self,
        response: std::result::Result<GetAssetResponse, AwsDataZoneTransportError>,
    ) {
        self.get_asset_responses.push_back(response);
    }

    pub fn push_get_subscription_request_details_response(
        &mut self,
        response: std::result::Result<
            GetSubscriptionRequestDetailsResponse,
            AwsDataZoneTransportError,
        >,
    ) {
        self.get_subscription_request_details_responses
            .push_back(response);
    }

    pub fn push_get_subscription_response(
        &mut self,
        response: std::result::Result<GetSubscriptionResponse, AwsDataZoneTransportError>,
    ) {
        self.get_subscription_responses.push_back(response);
    }

    pub fn push_list_subscription_requests_response(
        &mut self,
        response: std::result::Result<ListSubscriptionRequestsResponse, AwsDataZoneTransportError>,
    ) {
        self.list_subscription_requests_responses
            .push_back(response);
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

impl AwsDataZoneTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn get_asset(
        &mut self,
        request: &GetAssetRequest,
    ) -> std::result::Result<GetAssetResponse, AwsDataZoneTransportError> {
        self.requests.push(request.recorded_request());
        self.get_asset_responses
            .pop_front()
            .unwrap_or(Err(AwsDataZoneTransportError::InvalidResponse))
    }

    fn get_subscription_request_details(
        &mut self,
        request: &GetSubscriptionRequestDetailsRequest,
    ) -> std::result::Result<GetSubscriptionRequestDetailsResponse, AwsDataZoneTransportError> {
        self.requests.push(request.recorded_request());
        self.get_subscription_request_details_responses
            .pop_front()
            .unwrap_or(Err(AwsDataZoneTransportError::InvalidResponse))
    }

    fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequestForSubscription,
    ) -> std::result::Result<GetSubscriptionResponse, AwsDataZoneTransportError> {
        self.requests.push(request.recorded_request());
        self.get_subscription_responses
            .pop_front()
            .unwrap_or(Err(AwsDataZoneTransportError::InvalidResponse))
    }

    fn list_subscription_requests(
        &mut self,
        request: &ListSubscriptionRequestsRequest,
    ) -> std::result::Result<ListSubscriptionRequestsResponse, AwsDataZoneTransportError> {
        self.requests.push(request.recorded_request());
        self.list_subscription_requests_responses
            .pop_front()
            .unwrap_or(Err(AwsDataZoneTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AwsDataZoneSubscriptionScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AwsDataZoneSubscriptionScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn asset(&self) -> Result<AssetMetadata> {
        AssetMetadata::new(
            &self.scope,
            AssetMetadataInput {
                status: "PUBLISHED".to_owned(),
                revision: self.scope.asset().revision().to_owned(),
                type_identifier: "amazon.datazone.asset".to_owned(),
                type_revision: "1".to_owned(),
                listing_id: self.scope.listing().as_str().to_owned(),
                owning_project_id: self.scope.datazone_project().as_str().to_owned(),
                created_at: self.observed_at - Duration::hours(2),
                updated_at: self.observed_at - Duration::hours(1),
            },
        )
    }

    fn request_details(&self) -> Result<SubscriptionRequestMetadata> {
        SubscriptionRequestMetadata::for_scope(
            &self.scope,
            SubscriptionRequestStatus::Accepted,
            format!("request-revision-{}", self.observed_at.timestamp()),
            "catalog-approver",
        )
    }

    fn subscription(&self) -> Result<SubscriptionMetadata> {
        SubscriptionMetadata::for_scope(
            &self.scope,
            SubscriptionStatus::Approved,
            format!("subscription-revision-{}", self.observed_at.timestamp()),
        )
    }
}

impl AwsDataZoneTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get_asset(
        &mut self,
        request: &GetAssetRequest,
    ) -> std::result::Result<GetAssetResponse, AwsDataZoneTransportError> {
        let asset = self
            .asset()
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        GetAssetResponse::new(request, asset, 768, TransportProvenance::Fixture)
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)
    }

    fn get_subscription_request_details(
        &mut self,
        request: &GetSubscriptionRequestDetailsRequest,
    ) -> std::result::Result<GetSubscriptionRequestDetailsResponse, AwsDataZoneTransportError> {
        let metadata = self
            .request_details()
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        GetSubscriptionRequestDetailsResponse::new(
            request,
            metadata,
            768,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsDataZoneTransportError::InvalidResponse)
    }

    fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequestForSubscription,
    ) -> std::result::Result<GetSubscriptionResponse, AwsDataZoneTransportError> {
        let metadata = self
            .subscription()
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        GetSubscriptionResponse::new(request, metadata, 768, TransportProvenance::Fixture)
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)
    }

    fn list_subscription_requests(
        &mut self,
        request: &ListSubscriptionRequestsRequest,
    ) -> std::result::Result<ListSubscriptionRequestsResponse, AwsDataZoneTransportError> {
        let metadata = self
            .request_details()
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        ListSubscriptionRequestsResponse::new(
            request,
            vec![metadata],
            None,
            768,
            TransportProvenance::Fixture,
        )
        .map_err(|_| AwsDataZoneTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AwsDataZoneSubscriptionScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AwsDataZoneTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get_asset(
        &mut self,
        request: &GetAssetRequest,
    ) -> std::result::Result<GetAssetResponse, AwsDataZoneTransportError> {
        let asset = self
            .inner
            .asset()
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        GetAssetResponse::new(request, asset, 768, TransportProvenance::Loopback)
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)
    }

    fn get_subscription_request_details(
        &mut self,
        request: &GetSubscriptionRequestDetailsRequest,
    ) -> std::result::Result<GetSubscriptionRequestDetailsResponse, AwsDataZoneTransportError> {
        let metadata = self
            .inner
            .request_details()
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        GetSubscriptionRequestDetailsResponse::new(
            request,
            metadata,
            768,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsDataZoneTransportError::InvalidResponse)
    }

    fn get_subscription(
        &mut self,
        request: &GetSubscriptionRequestForSubscription,
    ) -> std::result::Result<GetSubscriptionResponse, AwsDataZoneTransportError> {
        let metadata = self
            .inner
            .subscription()
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        GetSubscriptionResponse::new(request, metadata, 768, TransportProvenance::Loopback)
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)
    }

    fn list_subscription_requests(
        &mut self,
        request: &ListSubscriptionRequestsRequest,
    ) -> std::result::Result<ListSubscriptionRequestsResponse, AwsDataZoneTransportError> {
        let metadata = self
            .inner
            .request_details()
            .map_err(|_| AwsDataZoneTransportError::InvalidResponse)?;
        ListSubscriptionRequestsResponse::new(
            request,
            vec![metadata],
            None,
            768,
            TransportProvenance::Loopback,
        )
        .map_err(|_| AwsDataZoneTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AwsDataZoneTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_asset(
        &mut self,
        _request: &GetAssetRequest,
    ) -> std::result::Result<GetAssetResponse, AwsDataZoneTransportError> {
        Err(AwsDataZoneTransportError::BlockedEnv)
    }

    fn get_subscription_request_details(
        &mut self,
        _request: &GetSubscriptionRequestDetailsRequest,
    ) -> std::result::Result<GetSubscriptionRequestDetailsResponse, AwsDataZoneTransportError> {
        Err(AwsDataZoneTransportError::BlockedEnv)
    }

    fn get_subscription(
        &mut self,
        _request: &GetSubscriptionRequestForSubscription,
    ) -> std::result::Result<GetSubscriptionResponse, AwsDataZoneTransportError> {
        Err(AwsDataZoneTransportError::BlockedEnv)
    }

    fn list_subscription_requests(
        &mut self,
        _request: &ListSubscriptionRequestsRequest,
    ) -> std::result::Result<ListSubscriptionRequestsResponse, AwsDataZoneTransportError> {
        Err(AwsDataZoneTransportError::BlockedEnv)
    }
}
