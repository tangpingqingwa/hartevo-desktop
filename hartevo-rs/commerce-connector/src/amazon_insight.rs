//! Durable Amazon SP-API report/notification reads for Mission consumers.
//!
//! This module is the second Amazon vertical slice on top of [`crate::amazon`].
//! It owns a provider-specific durable cursor and a Mission-adoptable result,
//! but it never creates a report, destination, subscription, listing, order,
//! or fulfillment.  A report must arrive as an externally pre-authorized job;
//! the provider seam below exposes only read operations.
//!
//! `SecretReference` and the LWA token observation are held in memory only.
//! Durable checkpoints retain their opaque reference identity, credential
//! revision, account/market/region fence, cursors, digests, quota, and
//! freshness evidence.  An observed LWA token is deliberately not Connected
//! authority, and this module keeps live execution `BLOCKED_ENV` until the
//! host supplies a real provider boundary and explicitly enables the live
//! probe gate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::{ProviderProvenanceClass, SecretReference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::amazon::{
    AMAZON_LIVE_VALIDATION_STATUS, AMAZON_PROVIDER_ID, AMAZON_READ_EVIDENCE_LEVEL,
    AmazonAccountIdentity, AmazonAccountScope, AmazonError, AmazonLwaAuthState,
    AmazonNotificationCursor, AmazonOperation, AmazonRateLimit, AmazonRegion, AmazonReport,
    AmazonReportStatus, AmazonSpApiRequest, LwaAccessTokenObservation, get_report_document_request,
    get_report_request, list_notification_subscriptions_request,
};

pub const AMAZON_INSIGHT_CAPABILITY_ID: &str = "commerce.insight.read";
pub const AMAZON_INSIGHT_LIVE_PROBE_ENV: &str = "HARTEVO_AMAZON_SP_API_LIVE";
pub const AMAZON_REPORT_CREATION_POLICY: &str = "PREAUTHORIZED_REPORT_JOB_ONLY";
pub const AMAZON_INSIGHT_MAX_PAGE_SIZE: u32 = 500;
pub const AMAZON_REPORT_DOCUMENT_URL_TTL_SECONDS: i64 = 300;
pub const AMAZON_INSIGHT_LIVE_VALIDATION_STATUS: &str = AMAZON_LIVE_VALIDATION_STATUS;
pub const AMAZON_INSIGHT_LIVE_READ_STATUS: &str = "LIVE_READ_E1";

/// A provider credential/generation fence.  The value is also required to
/// equal the SDK `SecretReference` credential revision for this slice.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AmazonProviderGeneration(u64);

impl AmazonProviderGeneration {
    pub fn new(value: u64) -> Result<Self, AmazonInsightError> {
        if value == 0 {
            return Err(AmazonInsightError::InvalidProviderGeneration);
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

macro_rules! amazon_string_identity {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, AmazonInsightError> {
                let value = value.into();
                validate_identity_token(&value, $kind)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

amazon_string_identity!(AmazonReportType, "report type");
amazon_string_identity!(AmazonReportId, "report id");
amazon_string_identity!(AmazonReportDocumentId, "report document id");
amazon_string_identity!(AmazonDocumentCursor, "report document cursor");
amazon_string_identity!(AmazonNotificationType, "notification type");

/// Stable account + marketplace + region + role fence used by every durable
/// record.  It is intentionally distinct from a generic account-only token.
pub fn amazon_scope_digest(scope: &AmazonAccountScope) -> String {
    let (account_kind, account_id) = match &scope.account {
        AmazonAccountIdentity::Seller { seller_id } => ("seller", seller_id.as_str()),
        AmazonAccountIdentity::Vendor { vendor_code } => ("vendor", vendor_code.as_str()),
    };
    let region = match scope.marketplace.region {
        AmazonRegion::NorthAmerica => "na",
        AmazonRegion::Europe => "eu",
        AmazonRegion::FarEast => "fe",
    };
    let roles = scope
        .roles
        .iter()
        .map(crate::amazon::AmazonRole::as_str)
        .collect::<Vec<_>>()
        .join(",");
    sha256_digest([
        AMAZON_PROVIDER_ID.to_owned(),
        account_kind.to_owned(),
        account_id.to_owned(),
        scope.marketplace.marketplace_id.clone(),
        scope.marketplace.country_code.clone(),
        region.to_owned(),
        roles,
    ])
}

/// A report job created outside this read-only adapter.  The adapter can poll
/// this job and retrieve its document, but has no create-report method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonPreauthorizedReportJob {
    pub report_id: AmazonReportId,
    pub report_type: AmazonReportType,
    pub scope_digest: String,
    pub provider_generation: AmazonProviderGeneration,
    pub processing_job_digest: String,
    pub authorization_digest: String,
    pub accepted_at: DateTime<Utc>,
}

impl AmazonPreauthorizedReportJob {
    pub fn new(
        scope: &AmazonAccountScope,
        provider_generation: AmazonProviderGeneration,
        report_id: impl Into<String>,
        report_type: impl Into<String>,
        authorization_digest: impl Into<String>,
        accepted_at: DateTime<Utc>,
    ) -> Result<Self, AmazonInsightError> {
        let report_id = AmazonReportId::parse(report_id)?;
        let report_type = AmazonReportType::parse(report_type)?;
        let authorization_digest = authorization_digest.into();
        if !is_sha256(&authorization_digest) {
            return Err(AmazonInsightError::InvalidAuthorizationDigest);
        }
        let scope_digest = amazon_scope_digest(scope);
        let processing_job_digest = sha256_digest([
            scope_digest.clone(),
            provider_generation.value().to_string(),
            report_id.as_str().to_owned(),
            report_type.as_str().to_owned(),
            authorization_digest.clone(),
            accepted_at.to_rfc3339(),
        ]);
        Ok(Self {
            report_id,
            report_type,
            scope_digest,
            provider_generation,
            processing_job_digest,
            authorization_digest,
            accepted_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonNotificationFeed {
    pub notification_type: AmazonNotificationType,
    pub payload_version: String,
    pub subscription_id: String,
}

impl AmazonNotificationFeed {
    pub fn new(
        notification_type: impl Into<String>,
        payload_version: impl Into<String>,
        subscription_id: impl Into<String>,
    ) -> Result<Self, AmazonInsightError> {
        let payload_version = payload_version.into();
        let subscription_id = subscription_id.into();
        validate_identity_token(&payload_version, "notification payload version")?;
        validate_identity_token(&subscription_id, "notification subscription id")?;
        Ok(Self {
            notification_type: AmazonNotificationType::parse(notification_type)?,
            payload_version,
            subscription_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AmazonInsightSource {
    Report { job: AmazonPreauthorizedReportJob },
    Notifications { feed: AmazonNotificationFeed },
}

impl AmazonInsightSource {
    pub const fn kind(&self) -> AmazonInsightSourceKind {
        match self {
            Self::Report { .. } => AmazonInsightSourceKind::Report,
            Self::Notifications { .. } => AmazonInsightSourceKind::Notifications,
        }
    }

    fn binding_digest(&self) -> String {
        match self {
            Self::Report { job } => sha256_digest([
                "report".to_owned(),
                job.scope_digest.clone(),
                job.provider_generation.value().to_string(),
                job.report_id.as_str().to_owned(),
                job.report_type.as_str().to_owned(),
                job.processing_job_digest.clone(),
            ]),
            Self::Notifications { feed } => sha256_digest([
                "notifications".to_owned(),
                feed.notification_type.as_str().to_owned(),
                feed.payload_version.clone(),
                feed.subscription_id.clone(),
            ]),
        }
    }

    fn validate_scope(
        &self,
        scope: &AmazonAccountScope,
        provider_generation: AmazonProviderGeneration,
    ) -> Result<(), AmazonInsightError> {
        let scope_digest = amazon_scope_digest(scope);
        match self {
            Self::Report { job } => {
                if job.scope_digest != scope_digest
                    || job.provider_generation != provider_generation
                {
                    return Err(AmazonInsightError::ScopeDrift);
                }
            }
            Self::Notifications { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmazonInsightSourceKind {
    Report,
    Notifications,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonInsightReadRequest {
    pub research_id: String,
    pub scope: AmazonAccountScope,
    pub provider_generation: AmazonProviderGeneration,
    pub source: AmazonInsightSource,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub page_size: u32,
}

impl AmazonInsightReadRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        research_id: impl Into<String>,
        scope: AmazonAccountScope,
        provider_generation: AmazonProviderGeneration,
        source: AmazonInsightSource,
        requested_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        page_size: u32,
    ) -> Result<Self, AmazonInsightError> {
        let research_id = research_id.into();
        validate_identity_token(&research_id, "research id")?;
        if !(1..=AMAZON_INSIGHT_MAX_PAGE_SIZE).contains(&page_size) || expires_at <= requested_at {
            return Err(AmazonInsightError::InvalidReadWindow);
        }
        let request = Self {
            research_id,
            scope,
            provider_generation,
            source,
            requested_at,
            expires_at,
            page_size,
        };
        request
            .source
            .validate_scope(&request.scope, provider_generation)?;
        Ok(request)
    }

    pub fn request_digest(&self) -> String {
        sha256_digest([
            self.research_id.clone(),
            amazon_scope_digest(&self.scope),
            self.provider_generation.value().to_string(),
            self.source.binding_digest(),
            self.requested_at.to_rfc3339(),
            self.expires_at.to_rfc3339(),
            self.page_size.to_string(),
        ])
    }

    fn validate_at(&self, now: DateTime<Utc>) -> Result<(), AmazonInsightError> {
        if now < self.requested_at || now >= self.expires_at {
            return Err(AmazonInsightError::RequestExpired);
        }
        self.source
            .validate_scope(&self.scope, self.provider_generation)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmazonInsightClassification {
    ReportRecord,
    NotificationEvent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonInsightRecord {
    pub record_id: String,
    pub content_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl AmazonInsightRecord {
    pub fn new(
        record_id: impl Into<String>,
        content_digest: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, AmazonInsightError> {
        let record_id = record_id.into();
        let content_digest = content_digest.into();
        validate_identity_token(&record_id, "report record id")?;
        if !is_sha256(&content_digest) {
            return Err(AmazonInsightError::InvalidContentDigest);
        }
        Ok(Self {
            record_id,
            content_digest,
            observed_at,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonNotificationEvent {
    pub delivery_id: String,
    pub sequence: u64,
    pub notification_type: AmazonNotificationType,
    pub event_time: DateTime<Utc>,
    pub payload_digest: String,
}

impl AmazonNotificationEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        delivery_id: impl Into<String>,
        sequence: u64,
        notification_type: AmazonNotificationType,
        event_time: DateTime<Utc>,
        payload_digest: impl Into<String>,
    ) -> Result<Self, AmazonInsightError> {
        let delivery_id = delivery_id.into();
        let payload_digest = payload_digest.into();
        validate_identity_token(&delivery_id, "notification delivery id")?;
        if sequence == 0 || !is_sha256(&payload_digest) {
            return Err(AmazonInsightError::InvalidNotificationEvent);
        }
        Ok(Self {
            delivery_id,
            sequence,
            notification_type,
            event_time,
            payload_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonQuotaCostEvidence {
    pub operation: AmazonOperation,
    pub rate_limit: Option<AmazonRateLimit>,
    pub retry_after_seconds: Option<u64>,
    pub cost_units: u32,
    pub request_id: Option<String>,
}

impl AmazonQuotaCostEvidence {
    pub fn new(
        operation: AmazonOperation,
        rate_limit: Option<AmazonRateLimit>,
        retry_after_seconds: Option<u64>,
        cost_units: u32,
        request_id: Option<String>,
    ) -> Result<Self, AmazonInsightError> {
        if cost_units == 0 || retry_after_seconds == Some(0) {
            return Err(AmazonInsightError::InvalidQuotaEvidence);
        }
        Ok(Self {
            operation,
            rate_limit,
            retry_after_seconds,
            cost_units,
            request_id,
        })
    }

    fn digest(&self) -> String {
        sha256_digest([
            format!("{:?}", self.operation),
            self.rate_limit
                .as_ref()
                .map_or_else(String::new, |rate| rate.raw.clone()),
            self.retry_after_seconds
                .map_or_else(String::new, |seconds| seconds.to_string()),
            self.cost_units.to_string(),
            self.request_id.clone().unwrap_or_default(),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonFreshnessEvidence {
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub source_revision: u64,
}

impl AmazonFreshnessEvidence {
    pub fn new(
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        source_revision: u64,
    ) -> Result<Self, AmazonInsightError> {
        if valid_until <= observed_at || source_revision == 0 {
            return Err(AmazonInsightError::InvalidFreshnessEvidence);
        }
        Ok(Self {
            observed_at,
            valid_until,
            source_revision,
        })
    }

    fn validate_at(&self, now: DateTime<Utc>) -> Result<(), AmazonInsightError> {
        if self.observed_at > now || now >= self.valid_until {
            return Err(AmazonInsightError::FreshnessExpired);
        }
        Ok(())
    }

    fn digest(&self) -> String {
        sha256_digest([
            self.observed_at.to_rfc3339(),
            self.valid_until.to_rfc3339(),
            self.source_revision.to_string(),
        ])
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonReportStatusPage {
    pub report: AmazonReport,
    pub quota: AmazonQuotaCostEvidence,
    pub freshness: AmazonFreshnessEvidence,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonReportDocumentPage {
    pub document_id: AmazonReportDocumentId,
    pub document_url_digest: String,
    pub document_url_expires_at: DateTime<Utc>,
    pub requested_cursor: Option<AmazonDocumentCursor>,
    pub page_sequence: u64,
    pub next_cursor: Option<AmazonDocumentCursor>,
    pub records: Vec<AmazonInsightRecord>,
    pub observed_at: DateTime<Utc>,
    pub quota: AmazonQuotaCostEvidence,
    pub freshness: AmazonFreshnessEvidence,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonNotificationPage {
    pub notification_type: AmazonNotificationType,
    pub requested_cursor: Option<AmazonNotificationCursor>,
    pub page_sequence: u64,
    pub next_cursor: Option<AmazonNotificationCursor>,
    pub events: Vec<AmazonNotificationEvent>,
    pub observed_at: DateTime<Utc>,
    pub quota: AmazonQuotaCostEvidence,
    pub freshness: AmazonFreshnessEvidence,
}

#[derive(Debug)]
pub struct AmazonReportStatusRequest {
    pub scope: AmazonAccountScope,
    pub job: AmazonPreauthorizedReportJob,
    pub access_token: LwaAccessTokenObservation,
    pub provider_generation: AmazonProviderGeneration,
    pub at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct AmazonReportDocumentPageRequest {
    pub scope: AmazonAccountScope,
    pub document_id: AmazonReportDocumentId,
    pub access_token: LwaAccessTokenObservation,
    pub provider_generation: AmazonProviderGeneration,
    pub requested_cursor: Option<AmazonDocumentCursor>,
    pub page_size: u32,
    pub at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct AmazonNotificationPageRequest {
    pub scope: AmazonAccountScope,
    pub feed: AmazonNotificationFeed,
    pub access_token: LwaAccessTokenObservation,
    pub provider_generation: AmazonProviderGeneration,
    pub requested_cursor: Option<AmazonNotificationCursor>,
    pub page_size: u32,
    pub at: DateTime<Utc>,
}

/// The Amazon SP-API provider seam.  Every method is read-only.  A concrete
/// adapter may compose the existing GET request builders and an encrypted
/// document downloader, but report creation and notification subscription
/// mutations are intentionally impossible through this trait.
pub trait AmazonSpApiInsightAdapter {
    fn read_report_status(
        &mut self,
        request: AmazonReportStatusRequest,
    ) -> Result<AmazonReportStatusPage, AmazonInsightProviderError>;

    fn read_report_document_page(
        &mut self,
        request: AmazonReportDocumentPageRequest,
    ) -> Result<AmazonReportDocumentPage, AmazonInsightProviderError>;

    fn read_notification_page(
        &mut self,
        request: AmazonNotificationPageRequest,
    ) -> Result<AmazonNotificationPage, AmazonInsightProviderError>;
}

/// Builds the existing GET-only SP-API request for report processing status.
pub fn report_status_sp_api_request(
    request: &AmazonReportStatusRequest,
) -> Result<AmazonSpApiRequest, AmazonError> {
    get_report_request(
        request.scope.clone(),
        request.access_token.clone(),
        request.job.report_id.as_str(),
    )
}

/// Builds the existing GET-only SP-API request for a report document URL.
/// Downloading and paginating the short-lived URL remains behind the provider
/// adapter and never places the URL itself in durable state.
pub fn report_document_sp_api_request(
    request: &AmazonReportDocumentPageRequest,
) -> Result<AmazonSpApiRequest, AmazonError> {
    get_report_document_request(
        request.scope.clone(),
        request.access_token.clone(),
        request.document_id.as_str(),
    )
}

/// Builds the existing GET-only SP-API request for a notification subscription
/// cursor.  Event delivery cursors themselves are consumed by the host's
/// queue/EventBridge adapter; this helper never creates a subscription.
pub fn notification_cursor_sp_api_request(
    request: &AmazonNotificationPageRequest,
) -> Result<AmazonSpApiRequest, AmazonError> {
    list_notification_subscriptions_request(
        request.scope.clone(),
        request.access_token.clone(),
        request.feed.notification_type.as_str(),
        Some(request.feed.payload_version.clone()),
        request.page_size,
        request.requested_cursor.clone(),
    )
}

#[derive(Debug, Error)]
pub enum AmazonInsightProviderError {
    #[error("Amazon SP-API rate limited; retry after {retry_after_seconds}s")]
    RateLimited {
        retry_after_seconds: u64,
        quota: AmazonQuotaCostEvidence,
    },
    #[error("Amazon report document URL expired")]
    ExpiredDocumentUrl,
    #[error("Amazon provider scope or generation drifted")]
    ScopeDrift,
    #[error("Amazon provider rejected the read")]
    Unauthorized,
    #[error("Amazon provider transport failed: {0}")]
    Transport(String),
    #[error("Amazon provider returned malformed insight data: {0}")]
    Malformed(String),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmazonInsightCheckpointState {
    Active,
    Complete,
    FailedClosed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum AmazonInsightCursor {
    Report(Option<AmazonDocumentCursor>),
    Notifications(Option<AmazonNotificationCursor>),
}

impl AmazonInsightCursor {
    fn initial(source: &AmazonInsightSource) -> Self {
        match source {
            AmazonInsightSource::Report { .. } => Self::Report(None),
            AmazonInsightSource::Notifications { .. } => Self::Notifications(None),
        }
    }

    fn digest(&self) -> String {
        match self {
            Self::Report(cursor) => sha256_digest([
                "report".to_owned(),
                cursor
                    .as_ref()
                    .map_or_else(|| "<start>".to_owned(), |value| value.as_str().to_owned()),
            ]),
            Self::Notifications(cursor) => sha256_digest([
                "notifications".to_owned(),
                cursor
                    .as_ref()
                    .map_or_else(|| "<start>".to_owned(), |value| value.as_str().to_owned()),
            ]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonInsightItem {
    pub item_id: String,
    pub content_digest: String,
    pub observed_at: DateTime<Utc>,
    pub delivery_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionCommerceInsightResult {
    pub capability_id: String,
    pub research_id: String,
    pub scope: AmazonAccountScope,
    pub scope_digest: String,
    pub provider_generation: AmazonProviderGeneration,
    pub source: AmazonInsightSourceKind,
    pub classification: AmazonInsightClassification,
    pub report_type: Option<AmazonReportType>,
    pub processing_job_digest: Option<String>,
    pub document_id: Option<AmazonReportDocumentId>,
    pub cursor: AmazonInsightCursor,
    pub next_cursor: AmazonInsightCursor,
    pub page_sequence: u64,
    pub items: Vec<AmazonInsightItem>,
    pub content_digest: String,
    pub result_digest: String,
    pub observed_at: DateTime<Utc>,
    pub provider_request_id: Option<String>,
    pub quota: AmazonQuotaCostEvidence,
    pub freshness: AmazonFreshnessEvidence,
    pub provenance_class: ProviderProvenanceClass,
    pub evidence_level: String,
    pub live_validation_status: String,
    pub replayed: bool,
}

impl MissionCommerceInsightResult {
    pub fn is_connected(&self) -> bool {
        false
    }

    pub fn is_first_party(&self) -> bool {
        self.provenance_class == ProviderProvenanceClass::ProductionProvider
            && self.live_validation_status != AMAZON_LIVE_VALIDATION_STATUS
    }

    pub fn is_mission_adoptable(&self) -> bool {
        self.capability_id == AMAZON_INSIGHT_CAPABILITY_ID
            && self.evidence_level == AMAZON_READ_EVIDENCE_LEVEL
            && !self.is_connected()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionCommerceInsightCapability {
    pub capability_id: String,
    pub provider_id: String,
    pub scope_digest: String,
    pub source: AmazonInsightSourceKind,
    pub read_only: bool,
    pub connected: bool,
}

impl MissionCommerceInsightCapability {
    pub fn for_request(request: &AmazonInsightReadRequest) -> Self {
        Self {
            capability_id: AMAZON_INSIGHT_CAPABILITY_ID.to_owned(),
            provider_id: AMAZON_PROVIDER_ID.to_owned(),
            scope_digest: amazon_scope_digest(&request.scope),
            source: request.source.kind(),
            read_only: true,
            connected: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AmazonInsightStoreLifecycle {
    Mounted,
    Revoked,
    Unmounted,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonInsightCheckpoint {
    pub request: AmazonInsightReadRequest,
    pub request_digest: String,
    pub scope_digest: String,
    pub provider_generation: AmazonProviderGeneration,
    pub secret_reference_id: String,
    pub credential_revision: u64,
    pub state: AmazonInsightCheckpointState,
    pub page_sequence: u64,
    pub cursor: AmazonInsightCursor,
    pub seen_cursor_digests: BTreeSet<String>,
    pub seen_item_identities: BTreeMap<String, String>,
    pub seen_delivery_identities: BTreeMap<String, String>,
    pub last_notification_sequence: Option<u64>,
    pub report: Option<AmazonReport>,
    pub document_id: Option<AmazonReportDocumentId>,
    pub retry_after_until: Option<DateTime<Utc>>,
    pub last_quota: Option<AmazonQuotaCostEvidence>,
    pub last_freshness: Option<AmazonFreshnessEvidence>,
    pub emitted_results: BTreeMap<String, MissionCommerceInsightResult>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmazonInsightDurableStore {
    lifecycle: AmazonInsightStoreLifecycle,
    scope_digest: String,
    provider_generation: AmazonProviderGeneration,
    secret_reference_id: String,
    credential_revision: u64,
    checkpoints: BTreeMap<String, AmazonInsightCheckpoint>,
}

impl AmazonInsightDurableStore {
    pub fn new(
        scope: &AmazonAccountScope,
        secret_reference: &SecretReference,
        provider_generation: AmazonProviderGeneration,
    ) -> Result<Self, AmazonInsightError> {
        validate_secret_binding(scope, secret_reference, provider_generation)?;
        Ok(Self {
            lifecycle: AmazonInsightStoreLifecycle::Mounted,
            scope_digest: amazon_scope_digest(scope),
            provider_generation,
            secret_reference_id: secret_reference.reference_id().to_owned(),
            credential_revision: secret_reference.credential_revision(),
            checkpoints: BTreeMap::new(),
        })
    }

    pub const fn lifecycle(&self) -> AmazonInsightStoreLifecycle {
        self.lifecycle
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn provider_generation(&self) -> AmazonProviderGeneration {
        self.provider_generation
    }

    pub fn secret_reference_id(&self) -> &str {
        &self.secret_reference_id
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub fn checkpoints(&self) -> &BTreeMap<String, AmazonInsightCheckpoint> {
        &self.checkpoints
    }

    fn checkpoint(&self, research_id: &str) -> Option<&AmazonInsightCheckpoint> {
        self.checkpoints.get(research_id)
    }

    fn checkpoint_mut(&mut self, research_id: &str) -> Option<&mut AmazonInsightCheckpoint> {
        self.checkpoints.get_mut(research_id)
    }

    fn insert_checkpoint(
        &mut self,
        request: &AmazonInsightReadRequest,
        secret_reference: &SecretReference,
    ) {
        let cursor = AmazonInsightCursor::initial(&request.source);
        self.checkpoints.insert(
            request.research_id.clone(),
            AmazonInsightCheckpoint {
                request: request.clone(),
                request_digest: request.request_digest(),
                scope_digest: amazon_scope_digest(&request.scope),
                provider_generation: request.provider_generation,
                secret_reference_id: secret_reference.reference_id().to_owned(),
                credential_revision: secret_reference.credential_revision(),
                state: AmazonInsightCheckpointState::Active,
                page_sequence: 0,
                seen_cursor_digests: BTreeSet::from([cursor.digest()]),
                cursor,
                seen_item_identities: BTreeMap::new(),
                seen_delivery_identities: BTreeMap::new(),
                last_notification_sequence: None,
                report: None,
                document_id: None,
                retry_after_until: None,
                last_quota: None,
                last_freshness: None,
                emitted_results: BTreeMap::new(),
            },
        );
    }

    fn revoke(&mut self) {
        self.checkpoints.clear();
        self.lifecycle = AmazonInsightStoreLifecycle::Revoked;
    }

    fn unmount(&mut self) {
        self.checkpoints.clear();
        self.lifecycle = AmazonInsightStoreLifecycle::Unmounted;
    }

    fn rotate(
        &mut self,
        scope: &AmazonAccountScope,
        secret_reference: &SecretReference,
        provider_generation: AmazonProviderGeneration,
    ) -> Result<(), AmazonInsightError> {
        if provider_generation <= self.provider_generation {
            return Err(AmazonInsightError::GenerationMustIncrease);
        }
        validate_secret_binding(scope, secret_reference, provider_generation)?;
        self.scope_digest = amazon_scope_digest(scope);
        self.provider_generation = provider_generation;
        secret_reference
            .reference_id()
            .clone_into(&mut self.secret_reference_id);
        self.credential_revision = secret_reference.credential_revision();
        self.checkpoints.clear();
        self.lifecycle = AmazonInsightStoreLifecycle::Mounted;
        Ok(())
    }
}

/// Host-facing read service.  It is the provider-specific plugin seam; a
/// Mission consumer receives only `MissionCommerceInsightResult` and cannot
/// obtain a token, create a report, or claim Connected authority from it.
#[derive(Debug)]
pub struct CommerceInsightReadService<P>
where
    P: AmazonSpApiInsightAdapter,
{
    provider: P,
    secret_reference: SecretReference,
    scope: AmazonAccountScope,
    provider_generation: AmazonProviderGeneration,
    auth_state: AmazonLwaAuthState,
    provenance_class: ProviderProvenanceClass,
    store: AmazonInsightDurableStore,
}

impl<P> CommerceInsightReadService<P>
where
    P: AmazonSpApiInsightAdapter,
{
    pub fn new(
        provider: P,
        secret_reference: SecretReference,
        scope: AmazonAccountScope,
        provider_generation: AmazonProviderGeneration,
        auth_state: AmazonLwaAuthState,
        provenance_class: ProviderProvenanceClass,
        store: AmazonInsightDurableStore,
    ) -> Result<Self, AmazonInsightError> {
        validate_secret_binding(&scope, &secret_reference, provider_generation)?;
        if store.scope_digest() != amazon_scope_digest(&scope)
            || store.provider_generation() != provider_generation
            || store.secret_reference_id() != secret_reference.reference_id()
            || store.credential_revision() != secret_reference.credential_revision()
        {
            return Err(AmazonInsightError::StoreBindingMismatch);
        }
        Ok(Self {
            provider,
            secret_reference,
            scope,
            provider_generation,
            auth_state,
            provenance_class,
            store,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn store(&self) -> &AmazonInsightDurableStore {
        &self.store
    }

    pub const fn lifecycle(&self) -> AmazonInsightStoreLifecycle {
        self.store.lifecycle()
    }

    pub const fn auth_status(&self) -> crate::amazon::AmazonLwaAuthStatus {
        self.auth_state.status()
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn live_validation_status(&self) -> &'static str {
        if self.provenance_class == ProviderProvenanceClass::ProductionProvider {
            AMAZON_INSIGHT_LIVE_READ_STATUS
        } else {
            AMAZON_INSIGHT_LIVE_VALIDATION_STATUS
        }
    }

    pub fn capability(
        &self,
        request: &AmazonInsightReadRequest,
    ) -> MissionCommerceInsightCapability {
        MissionCommerceInsightCapability::for_request(request)
    }

    pub fn read(
        &mut self,
        request: &AmazonInsightReadRequest,
        now: DateTime<Utc>,
    ) -> Result<MissionCommerceInsightResult, AmazonInsightError> {
        self.ensure_operable(request, now)?;
        let research_id = request.research_id.as_str();
        if let Some(checkpoint) = self.store.checkpoint(research_id) {
            self.validate_checkpoint(checkpoint, request)?;
            if checkpoint.state == AmazonInsightCheckpointState::FailedClosed {
                return Err(AmazonInsightError::PreviouslyFailedClosed);
            }
            if checkpoint.state == AmazonInsightCheckpointState::Complete {
                return Err(AmazonInsightError::ResearchComplete);
            }
            if let Some(retry_after_until) = checkpoint.retry_after_until
                && now < retry_after_until
            {
                return Err(AmazonInsightError::RetryAfterNotElapsed {
                    until: retry_after_until,
                });
            }
        } else {
            self.store
                .insert_checkpoint(request, &self.secret_reference);
        }
        match request.source {
            AmazonInsightSource::Report { .. } => self.read_report(request, now),
            AmazonInsightSource::Notifications { .. } => self.read_notifications(request, now),
        }
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<(), AmazonInsightError> {
        self.secret_reference
            .revoke(at)
            .map_err(|error| AmazonInsightError::SecretReference(error.to_string()))?;
        self.store.revoke();
        Ok(())
    }

    pub fn unmount(&mut self) {
        self.store.unmount();
    }

    pub fn rotate_generation(
        &mut self,
        secret_reference: SecretReference,
        scope: AmazonAccountScope,
        provider_generation: AmazonProviderGeneration,
        auth_state: AmazonLwaAuthState,
    ) -> Result<(), AmazonInsightError> {
        self.store
            .rotate(&scope, &secret_reference, provider_generation)?;
        self.secret_reference = secret_reference;
        self.scope = scope;
        self.provider_generation = provider_generation;
        self.auth_state = auth_state;
        Ok(())
    }

    fn ensure_operable(
        &self,
        request: &AmazonInsightReadRequest,
        now: DateTime<Utc>,
    ) -> Result<(), AmazonInsightError> {
        if self.lifecycle() != AmazonInsightStoreLifecycle::Mounted {
            return Err(AmazonInsightError::ConsumerNotMounted);
        }
        if self.provenance_class == ProviderProvenanceClass::ProductionProvider
            && !live_probe_enabled()
        {
            return Err(AmazonInsightError::BlockedEnv);
        }
        request.validate_at(now)?;
        if request.scope != self.scope
            || request.provider_generation != self.provider_generation
            || amazon_scope_digest(&request.scope) != self.store.scope_digest()
        {
            return Err(AmazonInsightError::ScopeDrift);
        }
        if self.auth_state.status() != crate::amazon::AmazonLwaAuthStatus::TokenObserved
            || !self.auth_state.can_issue_read_at(now)
        {
            return Err(AmazonInsightError::BlockedEnv);
        }
        Ok(())
    }

    fn access_token(
        &self,
        now: DateTime<Utc>,
    ) -> Result<crate::amazon::LwaAccessTokenObservation, AmazonInsightError> {
        self.auth_state
            .token()
            .filter(|token| token.is_valid_at(now))
            .cloned()
            .ok_or(AmazonInsightError::BlockedEnv)
    }

    fn validate_checkpoint(
        &self,
        checkpoint: &AmazonInsightCheckpoint,
        request: &AmazonInsightReadRequest,
    ) -> Result<(), AmazonInsightError> {
        if checkpoint.request != *request
            || checkpoint.request_digest != request.request_digest()
            || checkpoint.scope_digest != amazon_scope_digest(&request.scope)
            || checkpoint.provider_generation != self.provider_generation
            || checkpoint.secret_reference_id != self.secret_reference.reference_id()
            || checkpoint.credential_revision != self.secret_reference.credential_revision()
        {
            return Err(AmazonInsightError::CursorBindingMismatch);
        }
        Ok(())
    }

    fn read_report(
        &mut self,
        request: &AmazonInsightReadRequest,
        now: DateTime<Utc>,
    ) -> Result<MissionCommerceInsightResult, AmazonInsightError> {
        let key = request.research_id.as_str();
        let checkpoint = self
            .store
            .checkpoint(key)
            .cloned()
            .ok_or(AmazonInsightError::DurableCheckpointMissing)?;
        let job = match &request.source {
            AmazonInsightSource::Report { job } => job,
            AmazonInsightSource::Notifications { .. } => {
                return Err(AmazonInsightError::SourceMismatch);
            }
        };
        let access_token = self.access_token(now)?;
        let document_id = if let Some(document_id) = checkpoint.document_id.clone() {
            document_id
        } else {
            let status_page = self
                .provider
                .read_report_status(AmazonReportStatusRequest {
                    scope: request.scope.clone(),
                    job: job.clone(),
                    access_token,
                    provider_generation: request.provider_generation,
                    at: now,
                })
                .map_err(|error| self.map_provider_error(key, now, error))?;
            if let Err(error) = Self::validate_report_status(request, job, &status_page, now) {
                return self.fail_closed(key, error);
            }
            if !status_page.report.status.is_terminal() {
                if let Some(checkpoint) = self.store.checkpoint_mut(key) {
                    checkpoint.report = Some(status_page.report);
                    checkpoint.last_quota = Some(status_page.quota);
                    checkpoint.last_freshness = Some(status_page.freshness);
                    checkpoint.retry_after_until = None;
                }
                return Err(AmazonInsightError::ReportPending);
            }
            if status_page.report.status != AmazonReportStatus::Done {
                return self.fail_closed(key, AmazonInsightError::ReportUnavailable);
            }
            let Some(document_id) = status_page.report.document_id.clone() else {
                return self.fail_closed(key, AmazonInsightError::MissingReportDocument);
            };
            let document_id = AmazonReportDocumentId::parse(document_id)?;
            if let Some(checkpoint) = self.store.checkpoint_mut(key) {
                checkpoint.report = Some(status_page.report);
                checkpoint.document_id = Some(document_id.clone());
                checkpoint.last_quota = Some(status_page.quota);
                checkpoint.last_freshness = Some(status_page.freshness);
                checkpoint.retry_after_until = None;
            }
            document_id
        };
        let requested_cursor = match checkpoint.cursor {
            AmazonInsightCursor::Report(cursor) => cursor,
            AmazonInsightCursor::Notifications(_) => {
                return self.fail_closed(key, AmazonInsightError::CursorBindingMismatch);
            }
        };
        let page = self
            .provider
            .read_report_document_page(AmazonReportDocumentPageRequest {
                scope: request.scope.clone(),
                document_id,
                access_token: self.access_token(now)?,
                provider_generation: request.provider_generation,
                requested_cursor,
                page_size: request.page_size,
                at: now,
            })
            .map_err(|error| self.map_provider_error(key, now, error))?;
        self.commit_report_page(request, &page, now)
    }

    fn read_notifications(
        &mut self,
        request: &AmazonInsightReadRequest,
        now: DateTime<Utc>,
    ) -> Result<MissionCommerceInsightResult, AmazonInsightError> {
        let key = request.research_id.as_str();
        let checkpoint = self
            .store
            .checkpoint(key)
            .cloned()
            .ok_or(AmazonInsightError::DurableCheckpointMissing)?;
        let feed = match &request.source {
            AmazonInsightSource::Notifications { feed } => feed,
            AmazonInsightSource::Report { .. } => {
                return Err(AmazonInsightError::SourceMismatch);
            }
        };
        let requested_cursor = match checkpoint.cursor {
            AmazonInsightCursor::Notifications(cursor) => cursor,
            AmazonInsightCursor::Report(_) => {
                return self.fail_closed(key, AmazonInsightError::CursorBindingMismatch);
            }
        };
        let page = self
            .provider
            .read_notification_page(AmazonNotificationPageRequest {
                scope: request.scope.clone(),
                feed: feed.clone(),
                access_token: self.access_token(now)?,
                provider_generation: request.provider_generation,
                requested_cursor,
                page_size: request.page_size,
                at: now,
            })
            .map_err(|error| self.map_provider_error(key, now, error))?;
        self.commit_notification_page(request, &page, now)
    }

    fn validate_report_status(
        request: &AmazonInsightReadRequest,
        job: &AmazonPreauthorizedReportJob,
        page: &AmazonReportStatusPage,
        now: DateTime<Utc>,
    ) -> Result<(), AmazonInsightError> {
        page.freshness.validate_at(now)?;
        validate_quota(&page.quota, AmazonOperation::ReportsGet)?;
        if page.report.report_id != job.report_id.as_str()
            || page.report.report_type != job.report_type.as_str()
            || job.scope_digest != amazon_scope_digest(&request.scope)
            || job.provider_generation != request.provider_generation
        {
            return Err(AmazonInsightError::ReportFenceMismatch);
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn commit_report_page(
        &mut self,
        request: &AmazonInsightReadRequest,
        page: &AmazonReportDocumentPage,
        now: DateTime<Utc>,
    ) -> Result<MissionCommerceInsightResult, AmazonInsightError> {
        let key = request.research_id.as_str();
        if let Err(error) = page.freshness.validate_at(now) {
            return self.fail_closed(key, error);
        }
        if let Err(error) = validate_quota(&page.quota, AmazonOperation::ReportsDocument) {
            return self.fail_closed(key, error);
        }
        if page.document_url_expires_at <= now
            || page.document_url_expires_at
                > page.observed_at + Duration::seconds(AMAZON_REPORT_DOCUMENT_URL_TTL_SECONDS)
            || !is_sha256(&page.document_url_digest)
        {
            return self.fail_closed(key, AmazonInsightError::DocumentUrlExpired);
        }
        let checkpoint = self
            .store
            .checkpoint(key)
            .cloned()
            .ok_or(AmazonInsightError::DurableCheckpointMissing)?;
        let expected_cursor = match &checkpoint.cursor {
            AmazonInsightCursor::Report(cursor) => cursor.clone(),
            AmazonInsightCursor::Notifications(_) => {
                return self.fail_closed(key, AmazonInsightError::CursorBindingMismatch);
            }
        };
        if page.document_id
            != checkpoint
                .document_id
                .clone()
                .ok_or(AmazonInsightError::MissingReportDocument)?
            || page.requested_cursor != expected_cursor
        {
            return self.fail_closed(key, AmazonInsightError::CursorBindingMismatch);
        }
        let page_digest = report_page_digest(page);
        if let Some(previous) = checkpoint.emitted_results.get(&page_digest) {
            let mut replay = previous.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        if page.page_sequence != checkpoint.page_sequence.saturating_add(1) {
            return self.fail_closed(key, AmazonInsightError::CursorRollback);
        }
        let next_cursor = AmazonInsightCursor::Report(page.next_cursor.clone());
        if let Err(error) = Self::validate_next_cursor(&checkpoint, &next_cursor) {
            return self.fail_closed(key, error);
        }
        let mut items = Vec::with_capacity(page.records.len());
        let mut page_ids = BTreeSet::new();
        for record in &page.records {
            let item_digest =
                sha256_digest([record.record_id.clone(), record.content_digest.clone()]);
            if !page_ids.insert(record.record_id.clone())
                || checkpoint
                    .seen_item_identities
                    .contains_key(&record.record_id)
            {
                return self.fail_closed(key, AmazonInsightError::DuplicateReportRecord);
            }
            items.push(AmazonInsightItem {
                item_id: record.record_id.clone(),
                content_digest: item_digest,
                observed_at: record.observed_at,
                delivery_id: None,
            });
        }
        let result = self.build_result(
            request,
            AmazonInsightClassification::ReportRecord,
            AmazonInsightCursor::Report(expected_cursor),
            next_cursor.clone(),
            page.page_sequence,
            items,
            page.records
                .iter()
                .map(|record| record.content_digest.clone()),
            page.observed_at,
            page.quota.clone(),
            page.freshness.clone(),
            Some(page.document_id.clone()),
            Some(match &request.source {
                AmazonInsightSource::Report { job } => job.report_type.clone(),
                AmazonInsightSource::Notifications { .. } => {
                    return self.fail_closed(key, AmazonInsightError::SourceMismatch);
                }
            }),
            Some(match &request.source {
                AmazonInsightSource::Report { job } => job.processing_job_digest.clone(),
                AmazonInsightSource::Notifications { .. } => {
                    return self.fail_closed(key, AmazonInsightError::SourceMismatch);
                }
            }),
        );
        self.persist_result(
            key,
            page_digest,
            result,
            &page
                .records
                .iter()
                .map(|record| {
                    (
                        record.record_id.clone(),
                        sha256_digest([record.record_id.clone(), record.content_digest.clone()]),
                    )
                })
                .collect::<Vec<_>>(),
            &[],
            &next_cursor,
            page.page_sequence,
            &page.quota,
            &page.freshness,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn commit_notification_page(
        &mut self,
        request: &AmazonInsightReadRequest,
        page: &AmazonNotificationPage,
        now: DateTime<Utc>,
    ) -> Result<MissionCommerceInsightResult, AmazonInsightError> {
        let key = request.research_id.as_str();
        if let Err(error) = page.freshness.validate_at(now) {
            return self.fail_closed(key, error);
        }
        if let Err(error) =
            validate_quota(&page.quota, AmazonOperation::NotificationsSubscriptionsList)
        {
            return self.fail_closed(key, error);
        }
        let checkpoint = self
            .store
            .checkpoint(key)
            .cloned()
            .ok_or(AmazonInsightError::DurableCheckpointMissing)?;
        let feed = match &request.source {
            AmazonInsightSource::Notifications { feed } => feed,
            AmazonInsightSource::Report { .. } => {
                return self.fail_closed(key, AmazonInsightError::SourceMismatch);
            }
        };
        let expected_cursor = match &checkpoint.cursor {
            AmazonInsightCursor::Notifications(cursor) => cursor.clone(),
            AmazonInsightCursor::Report(_) => {
                return self.fail_closed(key, AmazonInsightError::CursorBindingMismatch);
            }
        };
        if page.notification_type != feed.notification_type
            || page.requested_cursor != expected_cursor
        {
            return self.fail_closed(key, AmazonInsightError::CursorBindingMismatch);
        }
        let page_digest = notification_page_digest(page);
        if let Some(previous) = checkpoint.emitted_results.get(&page_digest) {
            let mut replay = previous.clone();
            replay.replayed = true;
            return Ok(replay);
        }
        if page.page_sequence != checkpoint.page_sequence.saturating_add(1) {
            return self.fail_closed(key, AmazonInsightError::CursorRollback);
        }
        let next_cursor = AmazonInsightCursor::Notifications(page.next_cursor.clone());
        if let Err(error) = Self::validate_next_cursor(&checkpoint, &next_cursor) {
            return self.fail_closed(key, error);
        }
        let mut items = Vec::new();
        let mut page_delivery_ids = BTreeSet::new();
        let mut last_sequence = checkpoint.last_notification_sequence;
        let mut new_delivery_identities = Vec::new();
        for event in &page.events {
            if event.notification_type != feed.notification_type
                || !page_delivery_ids.insert(event.delivery_id.clone())
            {
                return self.fail_closed(key, AmazonInsightError::DuplicateNotification);
            }
            let item_digest = sha256_digest([
                event.delivery_id.clone(),
                event.sequence.to_string(),
                event.payload_digest.clone(),
            ]);
            if let Some(previous_digest) =
                checkpoint.seen_delivery_identities.get(&event.delivery_id)
            {
                if previous_digest != &item_digest {
                    return self.fail_closed(key, AmazonInsightError::NotificationMismatch);
                }
                continue;
            }
            if last_sequence.is_some_and(|previous| event.sequence <= previous) {
                return self.fail_closed(key, AmazonInsightError::OutOfOrderNotification);
            }
            last_sequence = Some(event.sequence);
            new_delivery_identities.push((event.delivery_id.clone(), item_digest.clone()));
            items.push(AmazonInsightItem {
                item_id: event.delivery_id.clone(),
                content_digest: item_digest,
                observed_at: event.event_time,
                delivery_id: Some(event.delivery_id.clone()),
            });
        }
        let result = self.build_result(
            request,
            AmazonInsightClassification::NotificationEvent,
            AmazonInsightCursor::Notifications(expected_cursor),
            next_cursor.clone(),
            page.page_sequence,
            items,
            page.events.iter().map(|event| event.payload_digest.clone()),
            page.observed_at,
            page.quota.clone(),
            page.freshness.clone(),
            None,
            None,
            None,
        );
        let result = self.persist_result(
            key,
            page_digest,
            result,
            &[],
            &new_delivery_identities,
            &next_cursor,
            page.page_sequence,
            &page.quota,
            &page.freshness,
        )?;
        if let Some(checkpoint) = self.store.checkpoint_mut(key) {
            checkpoint.last_notification_sequence = last_sequence;
        }
        Ok(result)
    }

    fn validate_next_cursor(
        checkpoint: &AmazonInsightCheckpoint,
        next_cursor: &AmazonInsightCursor,
    ) -> Result<(), AmazonInsightError> {
        if checkpoint.cursor == *next_cursor
            && !matches!(next_cursor, AmazonInsightCursor::Report(None))
            && !matches!(next_cursor, AmazonInsightCursor::Notifications(None))
        {
            return Err(AmazonInsightError::CursorRollback);
        }
        if (!matches!(next_cursor, AmazonInsightCursor::Report(None))
            && !matches!(next_cursor, AmazonInsightCursor::Notifications(None)))
            && checkpoint
                .seen_cursor_digests
                .contains(&next_cursor.digest())
        {
            return Err(AmazonInsightError::CursorRollback);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn build_result<I>(
        &self,
        request: &AmazonInsightReadRequest,
        classification: AmazonInsightClassification,
        cursor: AmazonInsightCursor,
        next_cursor: AmazonInsightCursor,
        page_sequence: u64,
        items: Vec<AmazonInsightItem>,
        content_parts: I,
        observed_at: DateTime<Utc>,
        quota: AmazonQuotaCostEvidence,
        freshness: AmazonFreshnessEvidence,
        document_id: Option<AmazonReportDocumentId>,
        report_type: Option<AmazonReportType>,
        processing_job_digest: Option<String>,
    ) -> MissionCommerceInsightResult
    where
        I: IntoIterator<Item = String>,
    {
        let content_digest = sha256_digest(
            [
                request.request_digest(),
                format!("{classification:?}"),
                page_sequence.to_string(),
                cursor.digest(),
                next_cursor.digest(),
            ]
            .into_iter()
            .chain(content_parts),
        );
        let result_digest = sha256_digest([
            request.request_digest(),
            content_digest.clone(),
            quota.digest(),
            freshness.digest(),
        ]);
        MissionCommerceInsightResult {
            capability_id: AMAZON_INSIGHT_CAPABILITY_ID.to_owned(),
            research_id: request.research_id.clone(),
            scope: request.scope.clone(),
            scope_digest: amazon_scope_digest(&request.scope),
            provider_generation: request.provider_generation,
            source: request.source.kind(),
            classification,
            report_type,
            processing_job_digest,
            document_id,
            cursor,
            next_cursor,
            page_sequence,
            items,
            content_digest,
            result_digest,
            observed_at,
            provider_request_id: quota.request_id.clone(),
            quota,
            freshness,
            provenance_class: self.provenance_class,
            evidence_level: AMAZON_READ_EVIDENCE_LEVEL.to_owned(),
            live_validation_status: self.live_validation_status().to_owned(),
            replayed: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn persist_result(
        &mut self,
        key: &str,
        page_digest: String,
        result: MissionCommerceInsightResult,
        report_items: &[(String, String)],
        notification_items: &[(String, String)],
        next_cursor: &AmazonInsightCursor,
        page_sequence: u64,
        quota: &AmazonQuotaCostEvidence,
        freshness: &AmazonFreshnessEvidence,
    ) -> Result<MissionCommerceInsightResult, AmazonInsightError> {
        let Some(checkpoint) = self.store.checkpoint_mut(key) else {
            return Err(AmazonInsightError::DurableCheckpointMissing);
        };
        for (item_id, item_digest) in report_items {
            checkpoint
                .seen_item_identities
                .insert(item_id.clone(), item_digest.clone());
        }
        for (delivery_id, item_digest) in notification_items {
            checkpoint
                .seen_delivery_identities
                .insert(delivery_id.clone(), item_digest.clone());
        }
        checkpoint.seen_cursor_digests.insert(next_cursor.digest());
        checkpoint.cursor = next_cursor.clone();
        checkpoint.page_sequence = page_sequence;
        checkpoint.state = if matches!(next_cursor, AmazonInsightCursor::Report(None))
            || matches!(next_cursor, AmazonInsightCursor::Notifications(None))
        {
            AmazonInsightCheckpointState::Complete
        } else {
            AmazonInsightCheckpointState::Active
        };
        checkpoint.retry_after_until = None;
        checkpoint.last_quota = Some(quota.clone());
        checkpoint.last_freshness = Some(freshness.clone());
        checkpoint
            .emitted_results
            .insert(page_digest, result.clone());
        Ok(result)
    }

    fn map_provider_error(
        &mut self,
        key: &str,
        now: DateTime<Utc>,
        error: AmazonInsightProviderError,
    ) -> AmazonInsightError {
        match error {
            AmazonInsightProviderError::RateLimited {
                retry_after_seconds,
                quota,
            } => {
                let until = now
                    .checked_add_signed(Duration::seconds(
                        i64::try_from(retry_after_seconds).unwrap_or(i64::MAX),
                    ))
                    .unwrap_or(now);
                if let Some(checkpoint) = self.store.checkpoint_mut(key) {
                    checkpoint.retry_after_until = Some(until);
                    checkpoint.last_quota = Some(quota);
                }
                AmazonInsightError::RetryAfter { until }
            }
            AmazonInsightProviderError::ExpiredDocumentUrl => {
                self.mark_failed_closed(key);
                AmazonInsightError::DocumentUrlExpired
            }
            AmazonInsightProviderError::ScopeDrift | AmazonInsightProviderError::Unauthorized => {
                self.mark_failed_closed(key);
                AmazonInsightError::ScopeDrift
            }
            AmazonInsightProviderError::Transport(message)
            | AmazonInsightProviderError::Malformed(message) => {
                AmazonInsightError::Provider(message)
            }
        }
    }

    fn mark_failed_closed(&mut self, key: &str) {
        if let Some(checkpoint) = self.store.checkpoint_mut(key) {
            checkpoint.state = AmazonInsightCheckpointState::FailedClosed;
        }
    }

    fn fail_closed<T>(
        &mut self,
        key: &str,
        error: AmazonInsightError,
    ) -> Result<T, AmazonInsightError> {
        self.mark_failed_closed(key);
        Err(error)
    }
}

fn validate_secret_binding(
    scope: &AmazonAccountScope,
    secret_reference: &SecretReference,
    provider_generation: AmazonProviderGeneration,
) -> Result<(), AmazonInsightError> {
    if secret_reference.scope().provider_id() != AMAZON_PROVIDER_ID
        || secret_reference.scope().account_id() != scope.account.account_id()
        || secret_reference.credential_revision() != provider_generation.value()
    {
        return Err(AmazonInsightError::ScopeDrift);
    }
    Ok(())
}

fn validate_quota(
    quota: &AmazonQuotaCostEvidence,
    expected_operation: AmazonOperation,
) -> Result<(), AmazonInsightError> {
    if quota.operation != expected_operation || quota.cost_units == 0 {
        return Err(AmazonInsightError::InvalidQuotaEvidence);
    }
    if quota
        .retry_after_seconds
        .is_some_and(|seconds| seconds == 0)
    {
        return Err(AmazonInsightError::InvalidQuotaEvidence);
    }
    Ok(())
}

fn report_page_digest(page: &AmazonReportDocumentPage) -> String {
    let mut parts = vec![
        page.document_id.as_str().to_owned(),
        page.document_url_digest.clone(),
        page.document_url_expires_at.to_rfc3339(),
        page.requested_cursor
            .as_ref()
            .map_or_else(String::new, |cursor| cursor.as_str().to_owned()),
        page.next_cursor
            .as_ref()
            .map_or_else(String::new, |cursor| cursor.as_str().to_owned()),
        page.page_sequence.to_string(),
    ];
    parts.extend(page.records.iter().flat_map(|record| {
        [
            record.record_id.clone(),
            record.content_digest.clone(),
            record.observed_at.to_rfc3339(),
        ]
    }));
    sha256_digest(parts)
}

fn notification_page_digest(page: &AmazonNotificationPage) -> String {
    let mut parts = vec![
        page.notification_type.as_str().to_owned(),
        page.requested_cursor
            .as_ref()
            .map_or_else(String::new, |cursor| cursor.as_str().to_owned()),
        page.next_cursor
            .as_ref()
            .map_or_else(String::new, |cursor| cursor.as_str().to_owned()),
        page.page_sequence.to_string(),
    ];
    parts.extend(page.events.iter().flat_map(|event| {
        [
            event.delivery_id.clone(),
            event.sequence.to_string(),
            event.payload_digest.clone(),
            event.event_time.to_rfc3339(),
        ]
    }));
    sha256_digest(parts)
}

fn validate_identity_token(value: &str, kind: &'static str) -> Result<(), AmazonInsightError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('?')
        || value.contains('#')
    {
        return Err(AmazonInsightError::InvalidIdentity {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_digest<I>(parts: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_string().as_bytes());
        digest.update(b":");
        digest.update(part.as_bytes());
        digest.update(b"|");
    }
    let bytes = digest.finalize();
    let mut output = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub fn live_probe_enabled() -> bool {
    std::env::var(AMAZON_INSIGHT_LIVE_PROBE_ENV).is_ok_and(|value| value == "1")
}

#[derive(Debug, Error)]
pub enum AmazonInsightError {
    #[error("Amazon provider generation is invalid")]
    InvalidProviderGeneration,
    #[error("invalid Amazon {kind}: {value}")]
    InvalidIdentity { kind: &'static str, value: String },
    #[error("Amazon report job authorization digest is invalid")]
    InvalidAuthorizationDigest,
    #[error("Amazon report/read window or page size is invalid")]
    InvalidReadWindow,
    #[error("Amazon insight content digest is invalid")]
    InvalidContentDigest,
    #[error("Amazon notification event is invalid")]
    InvalidNotificationEvent,
    #[error("Amazon quota/cost evidence is invalid")]
    InvalidQuotaEvidence,
    #[error("Amazon freshness evidence is invalid")]
    InvalidFreshnessEvidence,
    #[error("Amazon service is BLOCKED_ENV: no live read credentials/probe")]
    BlockedEnv,
    #[error("Amazon insight request is expired or not yet active")]
    RequestExpired,
    #[error("Amazon seller/vendor, marketplace, region, account, or role scope drifted")]
    ScopeDrift,
    #[error("Amazon durable store binding does not match the read service")]
    StoreBindingMismatch,
    #[error("Amazon insight consumer is revoked or unmounted")]
    ConsumerNotMounted,
    #[error("Amazon insight source does not match the durable cursor")]
    SourceMismatch,
    #[error("Amazon durable cursor binding does not match the Mission request")]
    CursorBindingMismatch,
    #[error("Amazon durable cursor rolled back or repeated")]
    CursorRollback,
    #[error("Amazon insight report is still processing")]
    ReportPending,
    #[error("Amazon report ended without readable data")]
    ReportUnavailable,
    #[error("Amazon report id, type, scope, or generation fence mismatched")]
    ReportFenceMismatch,
    #[error("Amazon report document id is missing")]
    MissingReportDocument,
    #[error("Amazon report document URL is expired or invalid")]
    DocumentUrlExpired,
    #[error("Amazon report contains a duplicate record")]
    DuplicateReportRecord,
    #[error("Amazon notifications contain a duplicate delivery")]
    DuplicateNotification,
    #[error("Amazon notification delivery identity changed")]
    NotificationMismatch,
    #[error("Amazon notification delivery is out of order")]
    OutOfOrderNotification,
    #[error("Amazon read freshness is expired or from the future")]
    FreshnessExpired,
    #[error("Amazon SP-API retry-after has not elapsed: {until}")]
    RetryAfterNotElapsed { until: DateTime<Utc> },
    #[error("Amazon SP-API requested retry after {until}")]
    RetryAfter { until: DateTime<Utc> },
    #[error("Amazon research has no more pages")]
    ResearchComplete,
    #[error("Amazon durable checkpoint is missing")]
    DurableCheckpointMissing,
    #[error("Amazon research was previously failed closed")]
    PreviouslyFailedClosed,
    #[error("Amazon provider generation must increase on rotation")]
    GenerationMustIncrease,
    #[error("Amazon secret reference operation failed: {0}")]
    SecretReference(String),
    #[error("Amazon provider read failed: {0}")]
    Provider(String),
    #[error("Amazon adapter error: {0}")]
    Amazon(#[from] AmazonError),
}
