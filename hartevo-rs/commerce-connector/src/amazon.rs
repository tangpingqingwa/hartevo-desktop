//! Amazon Selling Partner API read and asynchronous-lifecycle seam.
//!
//! LWA and SP-API credentials are represented by opaque references or token
//! digests.  The crate does not store a refresh token in a fixture and does
//! not expose create/execute listing effects.  Reports, notification
//! subscriptions, response rate headers, and account scope are observed as
//! typed read evidence.

use chrono::{DateTime, Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use url::Url;

use crate::canonical::{CanonicalIdentityError, CanonicalTime, MarketId, MarketIdentity};

pub const AMAZON_PROVIDER_ID: &str = "amazon-sp-api";
pub const LWA_TOKEN_ENDPOINT: &str = "https://api.amazon.com/auth/o2/token";
pub const REPORTS_API_VERSION: &str = "2021-06-30";
pub const NOTIFICATIONS_API_VERSION: &str = "v1";
pub const RATE_LIMIT_HEADER: &str = "x-amzn-RateLimit-Limit";
pub const REQUEST_ID_HEADER: &str = "x-amzn-RequestId";
pub const ERROR_TYPE_HEADER: &str = "x-amzn-ErrorType";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmazonRegion {
    NorthAmerica,
    Europe,
    FarEast,
}

impl AmazonRegion {
    pub const fn endpoint(self) -> &'static str {
        match self {
            Self::NorthAmerica => "https://sellingpartnerapi-na.amazon.com",
            Self::Europe => "https://sellingpartnerapi-eu.amazon.com",
            Self::FarEast => "https://sellingpartnerapi-fe.amazon.com",
        }
    }

    pub const fn aws_region(self) -> &'static str {
        match self {
            Self::NorthAmerica => "us-east-1",
            Self::Europe => "eu-west-1",
            Self::FarEast => "us-west-2",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AmazonAccountIdentity {
    Seller { seller_id: String },
    Vendor { vendor_code: String },
}

impl AmazonAccountIdentity {
    pub fn seller(seller_id: impl Into<String>) -> Result<Self, AmazonError> {
        let seller_id = seller_id.into();
        validate_token(&seller_id, "seller id")?;
        Ok(Self::Seller { seller_id })
    }

    pub fn vendor(vendor_code: impl Into<String>) -> Result<Self, AmazonError> {
        let vendor_code = vendor_code.into();
        validate_token(&vendor_code, "vendor code")?;
        Ok(Self::Vendor { vendor_code })
    }

    pub fn account_id(&self) -> &str {
        match self {
            Self::Seller { seller_id } => seller_id,
            Self::Vendor { vendor_code } => vendor_code,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonMarketplace {
    pub marketplace_id: String,
    pub country_code: String,
    pub region: AmazonRegion,
}

impl AmazonMarketplace {
    pub fn new(
        marketplace_id: impl Into<String>,
        country_code: impl Into<String>,
        region: AmazonRegion,
    ) -> Result<Self, AmazonError> {
        let marketplace_id = marketplace_id.into();
        let country_code = country_code.into().to_ascii_uppercase();
        validate_token(&marketplace_id, "marketplace id")?;
        if country_code.len() != 2 || !country_code.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(AmazonError::InvalidCountryCode(country_code));
        }
        Ok(Self {
            marketplace_id,
            country_code,
            region,
        })
    }

    pub fn us() -> Self {
        Self::new("ATVPDKIKX0DER", "US", AmazonRegion::NorthAmerica)
            .expect("static Amazon US marketplace is valid")
    }

    pub fn uk() -> Self {
        Self::new("A1F83G8C2ARO7P", "GB", AmazonRegion::Europe)
            .expect("static Amazon UK marketplace is valid")
    }

    pub fn japan() -> Self {
        Self::new("A1VC38T7YXB528", "JP", AmazonRegion::FarEast)
            .expect("static Amazon JP marketplace is valid")
    }

    pub fn as_market_identity(
        &self,
        locale: Option<String>,
    ) -> Result<MarketIdentity, AmazonError> {
        Ok(MarketIdentity::new(
            MarketId::parse(&self.marketplace_id)?,
            locale,
        )?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AmazonRole(String);

impl AmazonRole {
    pub fn parse(value: impl Into<String>) -> Result<Self, AmazonError> {
        let value = value.into();
        validate_token(&value, "Amazon role")?;
        Ok(Self(value))
    }

    pub fn product_listing() -> Self {
        Self("Product Listing".into())
    }

    pub fn inventory() -> Self {
        Self("Inventory".into())
    }

    pub fn reports() -> Self {
        Self("Reports".into())
    }

    pub fn notifications() -> Self {
        Self("Notifications".into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonAccountScope {
    pub account: AmazonAccountIdentity,
    pub marketplace: AmazonMarketplace,
    pub roles: BTreeSet<AmazonRole>,
}

impl AmazonAccountScope {
    pub fn new(
        account: AmazonAccountIdentity,
        marketplace: AmazonMarketplace,
        roles: BTreeSet<AmazonRole>,
    ) -> Result<Self, AmazonError> {
        if roles.is_empty() {
            return Err(AmazonError::MissingRoles);
        }
        Ok(Self {
            account,
            marketplace,
            roles,
        })
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles
            .iter()
            .any(|candidate| candidate.as_str() == role)
    }

    pub fn market_identity(&self) -> Result<MarketIdentity, AmazonError> {
        self.marketplace.as_market_identity(None)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LwaCredentialReference {
    pub client_id: String,
    pub client_secret_reference: String,
    pub refresh_token_reference: String,
}

impl LwaCredentialReference {
    pub fn new(
        client_id: impl Into<String>,
        client_secret_reference: impl Into<String>,
        refresh_token_reference: impl Into<String>,
    ) -> Result<Self, AmazonError> {
        let reference = Self {
            client_id: client_id.into(),
            client_secret_reference: client_secret_reference.into(),
            refresh_token_reference: refresh_token_reference.into(),
        };
        validate_token(&reference.client_id, "LWA client id")?;
        validate_token(
            &reference.client_secret_reference,
            "LWA client-secret reference",
        )?;
        validate_token(
            &reference.refresh_token_reference,
            "LWA refresh-token reference",
        )?;
        Ok(reference)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LwaRefreshRequest {
    pub endpoint: String,
    pub credential: LwaCredentialReference,
    pub grant_type: String,
}

impl LwaRefreshRequest {
    pub fn new(credential: LwaCredentialReference) -> Self {
        Self {
            endpoint: LWA_TOKEN_ENDPOINT.into(),
            credential,
            grant_type: "refresh_token".into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LwaAccessTokenObservation {
    pub token_digest: String,
    pub issued_at: CanonicalTime,
    pub expires_at: CanonicalTime,
}

impl LwaAccessTokenObservation {
    pub fn from_raw_token(
        raw_token: &[u8],
        issued_at: DateTime<Utc>,
        expires_in_seconds: u64,
    ) -> Result<Self, AmazonError> {
        if raw_token.is_empty() || expires_in_seconds == 0 || expires_in_seconds > 3_600 {
            return Err(AmazonError::InvalidLwaTokenLifetime);
        }
        let expires_in =
            i64::try_from(expires_in_seconds).map_err(|_| AmazonError::InvalidLwaTokenLifetime)?;
        let expires_at = issued_at
            .checked_add_signed(Duration::seconds(expires_in))
            .ok_or(AmazonError::InvalidLwaTokenLifetime)?;
        let mut digest = Sha256::new();
        digest.update(raw_token);
        Ok(Self {
            token_digest: format!("{:x}", digest.finalize()),
            issued_at: CanonicalTime::from_datetime(issued_at),
            expires_at: CanonicalTime::from_datetime(expires_at),
        })
    }

    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        now >= self.issued_at.as_datetime() && now < self.expires_at.as_datetime()
    }
}

pub trait AmazonLwaTransport {
    fn refresh(
        &mut self,
        request: LwaRefreshRequest,
    ) -> Result<LwaAccessTokenObservation, AmazonTransportError>;
}

pub fn refresh_lwa<T: AmazonLwaTransport>(
    transport: &mut T,
    credential: LwaCredentialReference,
) -> Result<LwaAccessTokenObservation, AmazonError> {
    let observation = transport
        .refresh(LwaRefreshRequest::new(credential))
        .map_err(|error| AmazonError::Transport(error.to_string()))?;
    if observation.token_digest.len() != 64
        || !observation
            .token_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || observation.expires_at.as_datetime() <= observation.issued_at.as_datetime()
    {
        return Err(AmazonError::InvalidLwaObservation);
    }
    Ok(observation)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmazonOperation {
    MarketplaceParticipations,
    ReportsList,
    ReportsGet,
    ReportsDocument,
    NotificationsDestinations,
    NotificationsSubscriptions,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonSpApiRequest {
    pub scope: AmazonAccountScope,
    pub operation: AmazonOperation,
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub access_token: LwaAccessTokenObservation,
}

impl AmazonSpApiRequest {
    pub fn endpoint(&self) -> Result<Url, AmazonError> {
        if !self.path.starts_with('/') || self.path.contains("//") || self.path.contains("..") {
            return Err(AmazonError::InvalidPath(self.path.clone()));
        }
        let mut endpoint = Url::parse(self.scope.marketplace.region.endpoint())
            .map_err(|_| AmazonError::InvalidEndpoint)?;
        endpoint.set_path(&self.path);
        for (key, value) in &self.query {
            endpoint.query_pairs_mut().append_pair(key, value);
        }
        Ok(endpoint)
    }
}

pub trait AmazonSpApiTransport {
    fn execute(
        &mut self,
        request: AmazonSpApiRequest,
    ) -> Result<AmazonSpApiResponse, AmazonTransportError>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonSpApiResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}

impl AmazonSpApiResponse {
    pub fn json<T: DeserializeOwned>(&self) -> Result<T, AmazonError> {
        if !(200..300).contains(&self.status) {
            return Err(AmazonError::HttpStatus(self.status));
        }
        serde_json::from_value(self.body.clone())
            .map_err(|error| AmazonError::MalformedResponse(error.to_string()))
    }

    pub fn metadata(&self) -> Result<AmazonResponseMetadata, AmazonError> {
        Ok(AmazonResponseMetadata {
            request_id: header(&self.headers, REQUEST_ID_HEADER).map(str::to_owned),
            error_type: header(&self.headers, ERROR_TYPE_HEADER).map(str::to_owned),
            rate_limit: header(&self.headers, RATE_LIMIT_HEADER)
                .map(AmazonRateLimit::parse)
                .transpose()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonResponseMetadata {
    pub request_id: Option<String>,
    pub error_type: Option<String>,
    pub rate_limit: Option<AmazonRateLimit>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonRateLimit {
    pub raw: String,
    pub requests_per_second: f64,
}

impl AmazonRateLimit {
    pub fn parse(value: &str) -> Result<Self, AmazonError> {
        let requests_per_second = value
            .parse::<f64>()
            .map_err(|_| AmazonError::InvalidRateLimit(value.into()))?;
        if !requests_per_second.is_finite() || requests_per_second <= 0.0 {
            return Err(AmazonError::InvalidRateLimit(value.into()));
        }
        Ok(Self {
            raw: value.into(),
            requests_per_second,
        })
    }
}

pub fn marketplace_participations_request(
    scope: AmazonAccountScope,
    access_token: LwaAccessTokenObservation,
) -> AmazonSpApiRequest {
    AmazonSpApiRequest {
        scope,
        operation: AmazonOperation::MarketplaceParticipations,
        method: "GET".into(),
        path: "/sellers/v1/marketplaceParticipations".into(),
        query: BTreeMap::new(),
        access_token,
    }
}

pub fn list_reports_request(
    scope: AmazonAccountScope,
    access_token: LwaAccessTokenObservation,
    next_token: Option<String>,
) -> Result<AmazonSpApiRequest, AmazonError> {
    let mut query = BTreeMap::new();
    if let Some(next_token) = next_token {
        validate_token(&next_token, "reports next token")?;
        query.insert("nextToken".into(), next_token);
    }
    Ok(AmazonSpApiRequest {
        scope,
        operation: AmazonOperation::ReportsList,
        method: "GET".into(),
        path: format!("/reports/{REPORTS_API_VERSION}/reports"),
        query,
        access_token,
    })
}

pub fn get_report_request(
    scope: AmazonAccountScope,
    access_token: LwaAccessTokenObservation,
    report_id: impl Into<String>,
) -> Result<AmazonSpApiRequest, AmazonError> {
    let report_id = report_id.into();
    validate_path_segment(&report_id, "report id")?;
    Ok(AmazonSpApiRequest {
        scope,
        operation: AmazonOperation::ReportsGet,
        method: "GET".into(),
        path: format!("/reports/{REPORTS_API_VERSION}/reports/{report_id}"),
        query: BTreeMap::new(),
        access_token,
    })
}

pub fn get_report_document_request(
    scope: AmazonAccountScope,
    access_token: LwaAccessTokenObservation,
    document_id: impl Into<String>,
) -> Result<AmazonSpApiRequest, AmazonError> {
    let document_id = document_id.into();
    validate_path_segment(&document_id, "report document id")?;
    Ok(AmazonSpApiRequest {
        scope,
        operation: AmazonOperation::ReportsDocument,
        method: "GET".into(),
        path: format!("/reports/{REPORTS_API_VERSION}/documents/{document_id}"),
        query: BTreeMap::new(),
        access_token,
    })
}

pub fn notification_destinations_request(
    scope: AmazonAccountScope,
    access_token: LwaAccessTokenObservation,
) -> AmazonSpApiRequest {
    AmazonSpApiRequest {
        scope,
        operation: AmazonOperation::NotificationsDestinations,
        method: "GET".into(),
        path: format!("/notifications/{NOTIFICATIONS_API_VERSION}/destinations"),
        query: BTreeMap::new(),
        access_token,
    }
}

pub fn notification_subscriptions_request(
    scope: AmazonAccountScope,
    access_token: LwaAccessTokenObservation,
    notification_type: impl Into<String>,
) -> Result<AmazonSpApiRequest, AmazonError> {
    let notification_type = notification_type.into();
    validate_path_segment(&notification_type, "notification type")?;
    Ok(AmazonSpApiRequest {
        scope,
        operation: AmazonOperation::NotificationsSubscriptions,
        method: "GET".into(),
        path: format!(
            "/notifications/{NOTIFICATIONS_API_VERSION}/subscriptions/{notification_type}"
        ),
        query: BTreeMap::new(),
        access_token,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AmazonReportStatus {
    InQueue,
    InProgress,
    Done,
    Cancelled,
    Fatal,
}

impl AmazonReportStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Cancelled | Self::Fatal)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonReport {
    pub report_id: String,
    pub report_type: String,
    pub status: AmazonReportStatus,
    pub document_id: Option<String>,
    pub created_at: CanonicalTime,
    pub processing_end_time: Option<CanonicalTime>,
}

impl AmazonReport {
    pub fn new(
        report_id: impl Into<String>,
        report_type: impl Into<String>,
        status: AmazonReportStatus,
        document_id: Option<String>,
        created_at: DateTime<Utc>,
        processing_end_time: Option<DateTime<Utc>>,
    ) -> Result<Self, AmazonError> {
        let report_id = report_id.into();
        let report_type = report_type.into();
        validate_path_segment(&report_id, "report id")?;
        validate_token(&report_type, "report type")?;
        if status == AmazonReportStatus::Done && document_id.is_none() {
            return Err(AmazonError::CompletedReportMissingDocument);
        }
        Ok(Self {
            report_id,
            report_type,
            status,
            document_id,
            created_at: CanonicalTime::from_datetime(created_at),
            processing_end_time: processing_end_time.map(CanonicalTime::from_datetime),
        })
    }

    pub fn from_api_payload(value: Value) -> Result<Self, AmazonError> {
        let payload = serde_json::from_value::<AmazonReportPayload>(value)
            .map_err(|error| AmazonError::MalformedResponse(error.to_string()))?;
        payload.into_report()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AmazonReportsPage {
    pub reports: Vec<AmazonReport>,
    pub next_token: Option<String>,
}

pub fn parse_reports_page(
    response: &AmazonSpApiResponse,
) -> Result<AmazonReportsPage, AmazonError> {
    let payload = response.json::<AmazonReportsPagePayload>()?;
    let reports = payload
        .reports
        .into_iter()
        .map(AmazonReportPayload::into_report)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AmazonReportsPage {
        reports,
        next_token: payload.next_token,
    })
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AmazonReportsPagePayload {
    reports: Vec<AmazonReportPayload>,
    next_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AmazonReportPayload {
    report_id: String,
    report_type: String,
    processing_status: String,
    report_document_id: Option<String>,
    created_time: String,
    processing_end_time: Option<String>,
}

impl AmazonReportPayload {
    fn into_report(self) -> Result<AmazonReport, AmazonError> {
        let status = match self.processing_status.as_str() {
            "CANCELLED" => AmazonReportStatus::Cancelled,
            "DONE" => AmazonReportStatus::Done,
            "FATAL" => AmazonReportStatus::Fatal,
            "IN_PROGRESS" => AmazonReportStatus::InProgress,
            "IN_QUEUE" => AmazonReportStatus::InQueue,
            status => return Err(AmazonError::InvalidReportStatus(status.into())),
        };
        let created_at = parse_amazon_timestamp(&self.created_time)?;
        let processing_end_time = self
            .processing_end_time
            .as_deref()
            .map(parse_amazon_timestamp)
            .transpose()?;
        AmazonReport::new(
            self.report_id,
            self.report_type,
            status,
            self.report_document_id,
            created_at,
            processing_end_time,
        )
    }
}

fn parse_amazon_timestamp(value: &str) -> Result<DateTime<Utc>, AmazonError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| AmazonError::InvalidTimestamp(value.into()))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmazonReportLifecycleState {
    Queued,
    InProgress,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonReportLifecycle {
    pub report_id: String,
    pub state: AmazonReportLifecycleState,
    pub document_id: Option<String>,
}

impl AmazonReportLifecycle {
    pub fn from_report(report: &AmazonReport) -> Self {
        let state = match report.status {
            AmazonReportStatus::InQueue => AmazonReportLifecycleState::Queued,
            AmazonReportStatus::InProgress => AmazonReportLifecycleState::InProgress,
            AmazonReportStatus::Done => AmazonReportLifecycleState::Succeeded,
            AmazonReportStatus::Cancelled => AmazonReportLifecycleState::Cancelled,
            AmazonReportStatus::Fatal => AmazonReportLifecycleState::Failed,
        };
        Self {
            report_id: report.report_id.clone(),
            state,
            document_id: report.document_id.clone(),
        }
    }

    pub fn can_transition_to(&self, next: AmazonReportLifecycleState) -> bool {
        matches!(
            (&self.state, next),
            (
                AmazonReportLifecycleState::Queued,
                AmazonReportLifecycleState::InProgress
                    | AmazonReportLifecycleState::Succeeded
                    | AmazonReportLifecycleState::Failed
                    | AmazonReportLifecycleState::Cancelled
            ) | (
                AmazonReportLifecycleState::InProgress,
                AmazonReportLifecycleState::Succeeded
                    | AmazonReportLifecycleState::Failed
                    | AmazonReportLifecycleState::Cancelled
            )
        )
    }

    pub fn advance(
        &self,
        next: AmazonReportLifecycleState,
        document_id: Option<String>,
    ) -> Result<Self, AmazonAsyncLifecycleError> {
        if !self.can_transition_to(next) {
            return Err(AmazonAsyncLifecycleError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: format!("{next:?}"),
            });
        }
        if next == AmazonReportLifecycleState::Succeeded && document_id.is_none() {
            return Err(AmazonAsyncLifecycleError::MissingDocument);
        }
        Ok(Self {
            report_id: self.report_id.clone(),
            state: next,
            document_id,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmazonNotificationLifecycleState {
    Requested,
    DestinationReady,
    SubscriptionActive,
    DeliveryObserved,
    Failed,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonNotificationLifecycle {
    pub notification_type: String,
    pub state: AmazonNotificationLifecycleState,
    pub last_delivery_id: Option<String>,
}

impl AmazonNotificationLifecycle {
    pub fn requested(notification_type: impl Into<String>) -> Result<Self, AmazonError> {
        let notification_type = notification_type.into();
        validate_path_segment(&notification_type, "notification type")?;
        Ok(Self {
            notification_type,
            state: AmazonNotificationLifecycleState::Requested,
            last_delivery_id: None,
        })
    }

    pub fn advance(
        &self,
        next: AmazonNotificationLifecycleState,
        delivery_id: Option<String>,
    ) -> Result<Self, AmazonAsyncLifecycleError> {
        let valid = matches!(
            (&self.state, next),
            (
                AmazonNotificationLifecycleState::Requested,
                AmazonNotificationLifecycleState::DestinationReady,
            ) | (
                AmazonNotificationLifecycleState::DestinationReady,
                AmazonNotificationLifecycleState::SubscriptionActive,
            ) | (
                AmazonNotificationLifecycleState::SubscriptionActive
                    | AmazonNotificationLifecycleState::DeliveryObserved,
                AmazonNotificationLifecycleState::DeliveryObserved,
            ) | (
                AmazonNotificationLifecycleState::SubscriptionActive,
                AmazonNotificationLifecycleState::Failed
                    | AmazonNotificationLifecycleState::Deleted,
            )
        );
        if !valid {
            return Err(AmazonAsyncLifecycleError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: format!("{next:?}"),
            });
        }
        if next == AmazonNotificationLifecycleState::DeliveryObserved && delivery_id.is_none() {
            return Err(AmazonAsyncLifecycleError::MissingDeliveryId);
        }
        Ok(Self {
            notification_type: self.notification_type.clone(),
            state: next,
            last_delivery_id: delivery_id.or_else(|| self.last_delivery_id.clone()),
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AmazonTransportError {
    #[error("Amazon transport failed: {0}")]
    Failed(String),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AmazonAsyncLifecycleError {
    #[error("invalid Amazon async lifecycle transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },
    #[error("a successful Amazon report requires a document id")]
    MissingDocument,
    #[error("an observed notification delivery requires a delivery id")]
    MissingDeliveryId,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AmazonError {
    #[error("invalid {kind}: {value}")]
    InvalidToken { kind: &'static str, value: String },
    #[error("invalid country code {0}")]
    InvalidCountryCode(String),
    #[error("Amazon account scope has no roles")]
    MissingRoles,
    #[error("invalid LWA token lifetime")]
    InvalidLwaTokenLifetime,
    #[error("invalid LWA token observation")]
    InvalidLwaObservation,
    #[error("Amazon transport failed: {0}")]
    Transport(String),
    #[error("invalid Amazon request path {0}")]
    InvalidPath(String),
    #[error("invalid Amazon endpoint")]
    InvalidEndpoint,
    #[error("Amazon HTTP status {0}")]
    HttpStatus(u16),
    #[error("invalid Amazon rate-limit header {0}")]
    InvalidRateLimit(String),
    #[error("malformed Amazon response: {0}")]
    MalformedResponse(String),
    #[error("completed Amazon report has no document id")]
    CompletedReportMissingDocument,
    #[error("invalid Amazon report status {0}")]
    InvalidReportStatus(String),
    #[error("invalid Amazon timestamp {0}")]
    InvalidTimestamp(String),
    #[error("invalid Amazon path segment {kind}: {value}")]
    InvalidPathSegment { kind: &'static str, value: String },
    #[error("canonical identity error: {0}")]
    CanonicalIdentity(#[from] CanonicalIdentityError),
    #[error("invalid currency {0}")]
    InvalidCurrency(String),
}

fn validate_token(value: &str, kind: &'static str) -> Result<(), AmazonError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(AmazonError::InvalidToken {
            kind,
            value: value.into(),
        });
    }
    Ok(())
}

fn validate_path_segment(value: &str, kind: &'static str) -> Result<(), AmazonError> {
    validate_token(value, kind)?;
    if value.contains('/') || value.contains('?') || value.contains('#') {
        return Err(AmazonError::InvalidPathSegment {
            kind,
            value: value.into(),
        });
    }
    Ok(())
}

fn header<'a>(headers: &'a BTreeMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_keeps_seller_vendor_marketplace_role_and_region() {
        let scope = AmazonAccountScope::new(
            AmazonAccountIdentity::seller("A1SELLER01").expect("seller"),
            AmazonMarketplace::us(),
            BTreeSet::from([AmazonRole::product_listing(), AmazonRole::reports()]),
        )
        .expect("scope");
        assert_eq!(scope.account.account_id(), "A1SELLER01");
        assert_eq!(scope.marketplace.region, AmazonRegion::NorthAmerica);
        assert!(scope.has_role("Reports"));
        assert_eq!(
            scope.marketplace.region.endpoint(),
            "https://sellingpartnerapi-na.amazon.com"
        );
    }

    #[test]
    fn rate_limit_header_is_optional_but_strict_when_present() {
        let response = AmazonSpApiResponse {
            status: 200,
            headers: BTreeMap::from([
                ("X-AMZN-REQUESTID".into(), "request-1".into()),
                ("x-amzn-ratelimit-limit".into(), "2.0".into()),
            ]),
            body: Value::Null,
        };
        let metadata = response.metadata().expect("headers");
        assert_eq!(metadata.request_id.as_deref(), Some("request-1"));
        assert_eq!(metadata.rate_limit.expect("rate").raw, "2.0");
    }

    #[test]
    fn reports_and_notifications_are_fail_closed_lifecycles() {
        let now = Utc::now();
        let report = AmazonReport::new(
            "report-1",
            "GET_MERCHANT_LISTINGS_ALL_DATA",
            AmazonReportStatus::InQueue,
            None,
            now,
            None,
        )
        .expect("report");
        let lifecycle = AmazonReportLifecycle::from_report(&report);
        assert!(
            lifecycle
                .advance(AmazonReportLifecycleState::InProgress, None)
                .is_ok()
        );
        assert!(
            lifecycle
                .advance(AmazonReportLifecycleState::Succeeded, None)
                .is_err()
        );

        let notifications =
            AmazonNotificationLifecycle::requested("ANY_OFFER_CHANGED").expect("notification");
        assert!(
            notifications
                .advance(AmazonNotificationLifecycleState::DestinationReady, None)
                .is_ok()
        );
    }
}
