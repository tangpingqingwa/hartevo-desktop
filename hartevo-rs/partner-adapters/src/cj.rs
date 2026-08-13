//! CJ Affiliate publisher-side authenticated read adapter.
//!
//! The production transport targets CJ's documented Advertiser Lookup REST
//! API with a Bearer personal access token.  This module owns only CJ-native
//! identities, request/response evidence, and a read-only Mission consumer;
//! authentication, probe fencing, cursor validation, and worker lifecycle are
//! delegated to the existing Connector SDK.

use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use hartevo_connector_sdk::{
    AuthSession, BeginAuthRequest, ConnectorAdapter, ConnectorAuth, ConnectorDescriptor,
    ConnectorError, ConnectorScope, ConnectorWorker, CredentialLease, Cursor, DispatchBudget,
    ExecuteRequest, FreshnessWindow, PrepareEffectRequest, PreparedEffect, ProbeObservation,
    ProbeRequest, ProbeResult, ProbeStatus, ProviderAdapterIdentity, ProviderAdapterOperation,
    ProviderAdapterRegistry, ProviderCapabilityKey, ProviderCapabilitySupport,
    ProviderEvidenceClass, ProviderProvenanceClass, ReadObservation, ReadRequest, ReceiptCandidate,
    ReconcileRequest, ReconciliationObservation, RefreshAuthRequest, RevokeRequest,
    SecretReference, VerificationObservation, VerifyRequest, WebhookEnvelope, WebhookObservation,
    WebhookRequest, WebhookSigningKey,
};
use hartevo_domain_kernel::Mission;
use hartevo_effect_broker::ProviderEvidenceSupport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use ureq::Agent;
use url::form_urlencoded;
use zeroize::Zeroizing;

#[path = "cj_reconcile.rs"]
pub mod reconcile;

pub const CJ_PROVIDER_ID: &str = "cj";
pub const CJ_ADAPTER_ID: &str = "hartevo.cj";
pub const CJ_ADAPTER_VERSION: u32 = 1;
pub const CJ_SERVICE_ID: &str = "partner.cj.authenticated-read/v1";
pub const CJ_RECONCILE_SERVICE_ID: &str = "partner.cj.cursor-reconcile/v1";
pub const CJ_MISSION_CAPABILITY: &str = "partner.cj.authenticated-read";
pub const CJ_RECONCILE_MISSION_CAPABILITY: &str = "partner.cj.cursor-reconcile";
pub const CJ_CONNECTION_CAPABILITY: &str = "connection.probe";
pub const CJ_ADVERTISER_READ_CAPABILITY: &str = "partner.advertiser.read";
pub const CJ_ADVERTISER_LOOKUP_ENDPOINT: &str =
    "https://advertiser-lookup.api.cj.com/v2/advertiser-lookup";
pub const CJ_CALL_LIMIT_PER_MINUTE: u64 = 25;
pub const CJ_DEFAULT_FRESHNESS_SECONDS: i64 = 60;
pub const CJ_READ_COST_UNITS: i64 = 1;
pub const CJ_MAX_PAGE_SIZE: u32 = 100;

const CJ_SCHEMA_VERSION: &str = "hartevo-cj-authenticated-read/v1";
const CJ_PROBE_TTL_SECONDS: i64 = 90;

macro_rules! numeric_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, CjError> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > 32
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || value.parse::<u64>().ok().is_none_or(|number| number == 0)
                {
                    return Err(CjError::InvalidIdentity);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

numeric_id!(CjPublisherId);
numeric_id!(CjAdvertiserId);
numeric_id!(CjProgramId);

/// Exact CJ publisher account and advertiser relationship scope.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjScope {
    tenant_id: String,
    project_id: String,
    publisher_id: CjPublisherId,
    advertiser_id: CjAdvertiserId,
}

impl CjScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        publisher_id: CjPublisherId,
        advertiser_id: CjAdvertiserId,
    ) -> Result<Self, CjError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            publisher_id,
            advertiser_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn publisher_id(&self) -> &CjPublisherId {
        &self.publisher_id
    }

    pub fn advertiser_id(&self) -> &CjAdvertiserId {
        &self.advertiser_id
    }

    pub fn connector_scope(&self) -> Result<ConnectorScope, CjError> {
        ConnectorScope::new(
            self.tenant_id.clone(),
            self.project_id.clone(),
            CJ_PROVIDER_ID,
            self.publisher_id.to_string(),
            [
                CJ_MISSION_CAPABILITY.to_owned(),
                CJ_ADVERTISER_READ_CAPABILITY.to_owned(),
                format!("advertiser:{}", self.advertiser_id),
            ],
        )
        .map_err(CjError::from)
    }

    pub fn digest(&self) -> Result<String, CjError> {
        Ok(self.connector_scope()?.digest())
    }

    fn validate(&self) -> Result<(), CjError> {
        if !valid_identifier(&self.tenant_id) || !valid_identifier(&self.project_id) {
            return Err(CjError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CjReadResource {
    AdvertiserLookup,
}

impl CjReadResource {
    pub const fn capability(self) -> &'static str {
        CJ_ADVERTISER_READ_CAPABILITY
    }
}

/// The documented Advertiser Lookup query.  Pagination is provider page
/// pagination; the durable cursor stores the next page number, never a token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjReadPlan {
    resource: CjReadResource,
    records_per_page: u32,
    relationship: String,
}

impl CjReadPlan {
    pub fn new(records_per_page: u32, relationship: impl Into<String>) -> Result<Self, CjError> {
        let relationship = relationship.into();
        if !(1..=CJ_MAX_PAGE_SIZE).contains(&records_per_page)
            || !matches!(relationship.as_str(), "joined" | "notjoined" | "all")
        {
            return Err(CjError::InvalidReadPlan);
        }
        Ok(Self {
            resource: CjReadResource::AdvertiserLookup,
            records_per_page,
            relationship,
        })
    }

    pub fn resource(&self) -> CjReadResource {
        self.resource
    }

    pub const fn records_per_page(&self) -> u32 {
        self.records_per_page
    }

    pub fn relationship(&self) -> &str {
        &self.relationship
    }

    pub fn query_digest(&self, scope: &CjScope) -> Result<String, CjError> {
        let scope_digest = scope.digest()?;
        Ok(digest_parts([
            CJ_SCHEMA_VERSION,
            self.resource.capability(),
            &self.records_per_page.to_string(),
            &self.relationship,
            scope_digest.as_str(),
        ]))
    }
}

/// Scope/query-bound continuation for CJ's page-number response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjDurableCursor {
    schema_version: String,
    resource: CjReadResource,
    scope_digest: String,
    query_digest: String,
    next_page: u32,
    token_digest: String,
    cursor_digest: String,
}

impl CjDurableCursor {
    fn new(
        plan: &CjReadPlan,
        scope: &CjScope,
        query_digest: &str,
        next_page: u32,
    ) -> Result<Self, CjError> {
        if next_page == 0 {
            return Err(CjError::CursorDrift);
        }
        let scope_digest = scope.digest()?;
        let token_digest = digest_parts([
            CJ_SCHEMA_VERSION,
            scope_digest.as_str(),
            query_digest,
            &next_page.to_string(),
        ]);
        let cursor_digest = digest_parts([
            CJ_SCHEMA_VERSION,
            &format!("{:?}", plan.resource),
            scope_digest.as_str(),
            query_digest,
            &next_page.to_string(),
            token_digest.as_str(),
        ]);
        Ok(Self {
            schema_version: CJ_SCHEMA_VERSION.to_owned(),
            resource: plan.resource,
            scope_digest,
            query_digest: query_digest.to_owned(),
            next_page,
            token_digest,
            cursor_digest,
        })
    }

    pub const fn next_page(&self) -> u32 {
        self.next_page
    }

    pub fn resource(&self) -> CjReadResource {
        self.resource
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub fn cursor_digest(&self) -> &str {
        &self.cursor_digest
    }

    pub fn to_sdk_cursor(&self, scope: &ConnectorScope) -> Result<Cursor, CjError> {
        if self.schema_version != CJ_SCHEMA_VERSION
            || self.scope_digest != scope.digest()
            || !is_sha256(&self.query_digest)
            || !is_sha256(&self.token_digest)
            || !is_sha256(&self.cursor_digest)
            || self.cursor_digest != self.calculated_cursor_digest()
        {
            return Err(CjError::CursorDrift);
        }
        Cursor::new(
            scope,
            self.query_digest.clone(),
            u64::from(self.next_page),
            self.token_digest.clone(),
        )
        .map_err(CjError::from)
    }

    fn validate_against(
        &self,
        plan: &CjReadPlan,
        scope: &CjScope,
        query_digest: &str,
    ) -> Result<(), CjError> {
        if self.resource != plan.resource
            || self.scope_digest != scope.digest()?
            || self.query_digest != query_digest
            || self.next_page == 0
            || !is_sha256(&self.token_digest)
            || self.token_digest
                != digest_parts([
                    CJ_SCHEMA_VERSION,
                    &self.scope_digest,
                    query_digest,
                    &self.next_page.to_string(),
                ])
            || self.cursor_digest != self.calculated_cursor_digest()
        {
            return Err(CjError::CursorDrift);
        }
        Ok(())
    }

    fn calculated_cursor_digest(&self) -> String {
        digest_parts([
            CJ_SCHEMA_VERSION,
            &format!("{:?}", self.resource),
            &self.scope_digest,
            &self.query_digest,
            &self.next_page.to_string(),
            &self.token_digest,
        ])
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjBudget {
    rate_remaining: u64,
    rate_reset_at: DateTime<Utc>,
    quota_limit: u64,
    quota_used: u64,
    cost_limit_units: i64,
    cost_used_units: i64,
}

impl CjBudget {
    pub fn new(
        rate_remaining: u64,
        rate_reset_at: DateTime<Utc>,
        quota_limit: u64,
        cost_limit_units: i64,
    ) -> Result<Self, CjError> {
        if cost_limit_units < 0 {
            return Err(CjError::InvalidBudget);
        }
        Ok(Self {
            rate_remaining,
            rate_reset_at,
            quota_limit,
            quota_used: 0,
            cost_limit_units,
            cost_used_units: 0,
        })
    }

    pub const fn rate_remaining(&self) -> u64 {
        self.rate_remaining
    }

    pub fn rate_reset_at(&self) -> DateTime<Utc> {
        self.rate_reset_at
    }

    pub const fn quota_limit(&self) -> u64 {
        self.quota_limit
    }

    pub const fn quota_used(&self) -> u64 {
        self.quota_used
    }

    pub const fn quota_remaining(&self) -> u64 {
        self.quota_limit.saturating_sub(self.quota_used)
    }

    pub const fn cost_limit_units(&self) -> i64 {
        self.cost_limit_units
    }

    pub const fn cost_used_units(&self) -> i64 {
        self.cost_used_units
    }

    pub const fn cost_remaining_units(&self) -> i64 {
        self.cost_limit_units.saturating_sub(self.cost_used_units)
    }

    fn admit(&mut self, at: DateTime<Utc>, cost_units: i64) -> Result<(), CjError> {
        if at >= self.rate_reset_at && self.rate_remaining == 0 {
            self.rate_remaining = CJ_CALL_LIMIT_PER_MINUTE;
        }
        if self.rate_remaining == 0 {
            return Err(CjError::RateLimited);
        }
        if self.quota_used >= self.quota_limit {
            return Err(CjError::QuotaExceeded);
        }
        if cost_units < 0
            || self
                .cost_used_units
                .checked_add(cost_units)
                .is_none_or(|total| total > self.cost_limit_units)
        {
            return Err(CjError::CostLimitExceeded);
        }
        self.rate_remaining -= 1;
        self.quota_used += 1;
        self.cost_used_units += cost_units;
        Ok(())
    }
}

#[derive(Clone)]
pub struct CjAccessToken(Zeroizing<String>);

impl fmt::Debug for CjAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CjAccessToken(REDACTED)")
    }
}

impl CjAccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, CjError> {
        let value = value.into();
        if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
            return Err(CjError::InvalidCredential);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

pub trait CjCredentialResolver: Send {
    fn resolve(
        &mut self,
        reference: &SecretReference,
        scope: &CjScope,
        at: DateTime<Utc>,
    ) -> Result<CjAccessToken, CjProviderError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvCjCredentialResolver;

impl CjCredentialResolver for BlockedEnvCjCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &SecretReference,
        _scope: &CjScope,
        _at: DateTime<Utc>,
    ) -> Result<CjAccessToken, CjProviderError> {
        Err(CjProviderError::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CjProbeStatus {
    Reachable,
    Disconnected,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CjObservationClassification {
    FirstParty,
    Disconnected,
    BlockedEnv,
    CredentialExpired,
    CredentialRevoked,
    RateLimited,
    ScopeDrift,
    Fixture,
    ProviderRejected,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CjProviderError {
    #[error("BLOCKED_ENV: CJ credential is not available in the configured secret store")]
    BlockedEnv,
    #[error("CJ credential is expired")]
    CredentialExpired,
    #[error("CJ credential was revoked")]
    CredentialRevoked,
    #[error("CJ provider rate limit is exhausted")]
    RateLimited,
    #[error("CJ provider response drifted from the exact account/advertiser scope")]
    ScopeDrift,
    #[error("CJ provider returned HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("CJ provider returned an invalid XML response")]
    InvalidResponse,
    #[error("CJ transport failed")]
    Transport,
}

#[derive(Clone, Debug)]
pub struct CjProbeRequest {
    pub scope: CjScope,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct CjProbeResponse {
    pub publisher_id: CjPublisherId,
    pub advertiser_ids: BTreeSet<CjAdvertiserId>,
    pub source_uri: String,
    pub source_digest: String,
    pub source_revision: u64,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct CjProviderReadRequest {
    pub scope: CjScope,
    pub resource: CjReadResource,
    pub relationship: String,
    pub page_number: u32,
    pub records_per_page: u32,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct CjProviderPage {
    pub resource: CjReadResource,
    pub publisher_id: CjPublisherId,
    pub advertiser_ids: BTreeSet<CjAdvertiserId>,
    pub page_number: u32,
    pub total_matched: u64,
    pub records_returned: u32,
    pub source_uri: String,
    pub source_digest: String,
    pub source_revision: u64,
    pub observed_at: DateTime<Utc>,
    pub payload: String,
}

pub trait CjTransport: Send {
    fn provenance_class(&self) -> ProviderProvenanceClass;

    fn probe(
        &mut self,
        token: &CjAccessToken,
        request: &CjProbeRequest,
    ) -> Result<CjProbeResponse, CjProviderError>;

    fn read(
        &mut self,
        token: &CjAccessToken,
        request: &CjProviderReadRequest,
    ) -> Result<CjProviderPage, CjProviderError>;
}

/// Official CJ Advertiser Lookup REST transport.  No browser or catalog
/// simulation is used by this implementation.
pub struct CjHttpTransport {
    base_url: String,
    agent: Agent,
}

impl fmt::Debug for CjHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CjHttpTransport")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl CjHttpTransport {
    pub fn official() -> Self {
        Self {
            base_url: CJ_ADVERTISER_LOOKUP_ENDPOINT.to_owned(),
            agent: Agent::new(),
        }
    }

    pub fn new(base_url: impl Into<String>) -> Result<Self, CjError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if !base_url.starts_with("https://") || base_url.contains('?') {
            return Err(CjError::InvalidTransportBaseUrl);
        }
        Ok(Self {
            base_url,
            agent: Agent::new(),
        })
    }

    fn get_xml(
        &self,
        token: &CjAccessToken,
        query: Vec<(String, String)>,
    ) -> Result<(String, String), CjProviderError> {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in query {
            serializer.append_pair(&key, &value);
        }
        let url = format!("{}?{}", self.base_url, serializer.finish());
        let response = self
            .agent
            .get(&url)
            .set("Authorization", &format!("Bearer {}", token.as_str()))
            .set("Accept", "application/xml")
            .call()
            .map_err(|error| match error {
                ureq::Error::Status(status, response) => CjProviderError::HttpStatus {
                    status,
                    retry_after_seconds: response
                        .header("Retry-After")
                        .and_then(|value| value.parse::<u64>().ok()),
                },
                ureq::Error::Transport(_) => CjProviderError::Transport,
            })?;
        let body = response
            .into_string()
            .map_err(|_| CjProviderError::Transport)?;
        Ok((url, body))
    }

    fn request(
        &self,
        token: &CjAccessToken,
        request: &CjProviderReadRequest,
    ) -> Result<CjProviderPage, CjProviderError> {
        let query = vec![
            (
                "requestor-cid".to_owned(),
                request.scope.publisher_id.to_string(),
            ),
            (
                "advertiser-ids".to_owned(),
                request.scope.advertiser_id.to_string(),
            ),
            ("relationship".to_owned(), request.relationship.clone()),
            (
                "records-per-page".to_owned(),
                request.records_per_page.to_string(),
            ),
            ("page-number".to_owned(), request.page_number.to_string()),
        ];
        let (url, body) = self.get_xml(token, query)?;
        let source_digest = sha256_hex(&body);
        let source_revision = revision_from_digest(&source_digest);
        let advertiser_ids = extract_xml_ids(&body, "advertiser-id")?;
        if !advertiser_ids.contains(request.scope.advertiser_id()) {
            return Err(CjProviderError::ScopeDrift);
        }
        let page_number = extract_xml_u64(&body, "page-number")
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(CjProviderError::InvalidResponse)?;
        let total_matched =
            extract_xml_u64(&body, "total-matched").ok_or(CjProviderError::InvalidResponse)?;
        let records_returned = extract_xml_u64(&body, "records-returned")
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(CjProviderError::InvalidResponse)?;
        if page_number != request.page_number || records_returned == 0 {
            return Err(CjProviderError::InvalidResponse);
        }
        Ok(CjProviderPage {
            resource: request.resource,
            publisher_id: request.scope.publisher_id.clone(),
            advertiser_ids,
            page_number,
            total_matched,
            records_returned,
            source_uri: url,
            source_digest,
            source_revision,
            observed_at: request.observed_at,
            payload: body,
        })
    }
}

impl CjTransport for CjHttpTransport {
    fn provenance_class(&self) -> ProviderProvenanceClass {
        ProviderProvenanceClass::ProductionProvider
    }

    fn probe(
        &mut self,
        token: &CjAccessToken,
        request: &CjProbeRequest,
    ) -> Result<CjProbeResponse, CjProviderError> {
        let page = self.request(
            token,
            &CjProviderReadRequest {
                scope: request.scope.clone(),
                resource: CjReadResource::AdvertiserLookup,
                relationship: "all".to_owned(),
                page_number: 1,
                records_per_page: 1,
                observed_at: request.observed_at,
            },
        )?;
        Ok(CjProbeResponse {
            publisher_id: page.publisher_id,
            advertiser_ids: page.advertiser_ids,
            source_uri: page.source_uri,
            source_digest: page.source_digest,
            source_revision: page.source_revision,
            observed_at: page.observed_at,
        })
    }

    fn read(
        &mut self,
        token: &CjAccessToken,
        request: &CjProviderReadRequest,
    ) -> Result<CjProviderPage, CjProviderError> {
        self.request(token, request)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CjError {
    #[error("CJ identity is invalid")]
    InvalidIdentity,
    #[error("CJ scope is invalid")]
    InvalidScope,
    #[error("CJ read plan is invalid")]
    InvalidReadPlan,
    #[error("CJ budget is invalid")]
    InvalidBudget,
    #[error("CJ credential is invalid")]
    InvalidCredential,
    #[error("CJ transport base URL is invalid")]
    InvalidTransportBaseUrl,
    #[error("CJ service is not authenticated")]
    MissingAuthentication,
    #[error("CJ service is disconnected or the probe is not live")]
    Disconnected,
    #[error("CJ service is revoked")]
    Revoked,
    #[error("CJ service is unmounted")]
    Unmounted,
    #[error("CJ cursor drifted from the exact scope/query")]
    CursorDrift,
    #[error("CJ quota is exhausted")]
    QuotaExceeded,
    #[error("CJ cost boundary is exhausted")]
    CostLimitExceeded,
    #[error("CJ provider is rate limited")]
    RateLimited,
    #[error("CJ provider rejected the request")]
    ProviderRejected,
    #[error("CJ provider generation drifted from the authenticated read")]
    GenerationDrift,
    #[error("CJ delivery is invalid for the exact provider scope")]
    InvalidDelivery,
    #[error("CJ reconcile checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("CJ evidence root is still open")]
    EvidenceRootOpen,
    #[error("CJ evidence root is already closed")]
    EvidenceRootClosed,
    #[error("CJ source bytes are missing")]
    MissingSourceBytes,
    #[error("CJ source digest does not match the source bytes")]
    DigestMismatch,
    #[error("CJ delivery cursor rolled back")]
    CursorRollback,
    #[error("CJ provider event identity drifted")]
    ProviderEventMismatch,
    #[error("CJ webhook event was replayed")]
    WebhookReplay,
    #[error("CJ Mission consumer rejected the exact binding")]
    MissionBinding,
    #[error("CJ service state is poisoned")]
    StatePoisoned,
    #[error("Connector SDK error: {0}")]
    Connector(#[from] ConnectorError),
    #[error("CJ provider error: {0}")]
    Provider(#[from] CjProviderError),
    #[error("provider contract error: {0}")]
    ProviderContract(String),
    #[error("Mission error: {0}")]
    Mission(String),
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjProbeObservation {
    pub status: CjProbeStatus,
    pub classification: CjObservationClassification,
    pub provider_id: String,
    pub publisher_id: CjPublisherId,
    pub advertiser_id: CjAdvertiserId,
    pub credential_revision: u64,
    pub source_revision: Option<u64>,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub source_uri: String,
    pub source_digest: String,
    pub evidence_digest: String,
}

impl CjProbeObservation {
    fn reachable(
        scope: &CjScope,
        credential_revision: u64,
        response: &CjProbeResponse,
        provenance: ProviderProvenanceClass,
    ) -> Self {
        let valid_until = response
            .observed_at
            .checked_add_signed(Duration::seconds(CJ_PROBE_TTL_SECONDS))
            .unwrap_or(response.observed_at);
        let evidence_digest = digest_parts([
            CJ_SCHEMA_VERSION,
            CJ_PROVIDER_ID,
            scope.publisher_id().as_str(),
            scope.advertiser_id().as_str(),
            &credential_revision.to_string(),
            &response.source_revision.to_string(),
            &format!("{provenance:?}"),
            response.source_digest.as_str(),
        ]);
        Self {
            status: CjProbeStatus::Reachable,
            classification: if provenance == ProviderProvenanceClass::ProductionProvider {
                CjObservationClassification::FirstParty
            } else {
                CjObservationClassification::Fixture
            },
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: response.publisher_id.clone(),
            advertiser_id: scope.advertiser_id().clone(),
            credential_revision,
            source_revision: Some(response.source_revision),
            observed_at: response.observed_at,
            valid_until,
            source_uri: response.source_uri.clone(),
            source_digest: response.source_digest.clone(),
            evidence_digest,
        }
    }

    fn rejected(
        scope: &CjScope,
        credential_revision: u64,
        at: DateTime<Utc>,
        error: &CjProviderError,
        provenance: ProviderProvenanceClass,
    ) -> Self {
        let classification = match error {
            CjProviderError::BlockedEnv => CjObservationClassification::BlockedEnv,
            CjProviderError::CredentialExpired => CjObservationClassification::CredentialExpired,
            CjProviderError::CredentialRevoked
            | CjProviderError::HttpStatus {
                status: 401 | 403, ..
            } => CjObservationClassification::CredentialRevoked,
            CjProviderError::RateLimited => CjObservationClassification::RateLimited,
            CjProviderError::ScopeDrift => CjObservationClassification::ScopeDrift,
            CjProviderError::HttpStatus { status: 429, .. } => {
                CjObservationClassification::RateLimited
            }
            CjProviderError::Transport => CjObservationClassification::Disconnected,
            _ => CjObservationClassification::ProviderRejected,
        };
        let source_digest = sha256_hex(&error.to_string());
        let evidence_digest = digest_parts([
            CJ_SCHEMA_VERSION,
            CJ_PROVIDER_ID,
            scope.publisher_id().as_str(),
            scope.advertiser_id().as_str(),
            &credential_revision.to_string(),
            &format!("{classification:?}"),
            &format!("{provenance:?}"),
            source_digest.as_str(),
        ]);
        let valid_until = at
            .checked_add_signed(Duration::seconds(60))
            .unwrap_or(at + Duration::seconds(1));
        Self {
            status: CjProbeStatus::Rejected,
            classification,
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: scope.publisher_id().clone(),
            advertiser_id: scope.advertiser_id().clone(),
            credential_revision,
            source_revision: None,
            observed_at: at,
            valid_until,
            source_uri: "cj://rejected".to_owned(),
            source_digest,
            evidence_digest,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjReadData {
    pub resource: CjReadResource,
    pub page_number: u32,
    pub records_returned: u32,
    pub total_matched: u64,
    pub payload: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjCostReceipt {
    pub cost_units: i64,
    pub rate_remaining: u64,
    pub rate_reset_at: DateTime<Utc>,
    pub quota_limit: u64,
    pub quota_used: u64,
    pub quota_remaining: u64,
    pub cost_limit_units: i64,
    pub cost_used_units: i64,
    pub cost_remaining_units: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjResultEnvelope {
    pub schema_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub publisher_id: CjPublisherId,
    pub advertiser_id: CjAdvertiserId,
    pub resource: CjReadResource,
    pub scope_digest: String,
    pub query_digest: String,
    pub credential_revision: u64,
    pub source_revision: u64,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub source_uri: String,
    pub source_digest: String,
    pub content_digest: String,
    pub classification: CjObservationClassification,
    pub cursor: Option<CjDurableCursor>,
    pub cost: CjCostReceipt,
    pub data: CjReadData,
    pub result_digest: String,
}

#[derive(Clone, Debug)]
pub struct CjProbeReceipt {
    pub connector_result: ProbeResult,
    pub observation: CjProbeObservation,
    pub credential_revision: u64,
}

#[derive(Clone, Debug)]
pub struct CjReadResult {
    pub connector_observation: ReadObservation,
    pub envelope: CjResultEnvelope,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjLifecycleReceipt {
    pub service_id: String,
    pub provider_id: String,
    pub scope_digest: String,
    pub action: String,
    pub at: DateTime<Utc>,
    pub receipt_digest: String,
}

#[derive(Debug)]
struct ActiveCjCredential {
    credential_revision: u64,
    token: CjAccessToken,
}

#[derive(Debug, Default)]
struct CjAdapterState {
    active_credential: Option<ActiveCjCredential>,
    last_probe: Option<CjProbeObservation>,
    last_page: Option<CjProviderPage>,
    revoked: bool,
}

#[derive(Clone, Debug)]
pub struct CjServiceDefinition {
    pub schema_version: &'static str,
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub adapter: ProviderAdapterIdentity,
    pub capabilities: BTreeSet<String>,
}

impl CjServiceDefinition {
    pub fn new() -> Result<Self, CjError> {
        let adapter = ProviderAdapterIdentity::new(CJ_ADAPTER_ID, CJ_ADAPTER_VERSION)
            .map_err(|error| CjError::ProviderContract(error.to_string()))?;
        Ok(Self {
            schema_version: CJ_SCHEMA_VERSION,
            service_id: CJ_SERVICE_ID,
            provider_id: CJ_PROVIDER_ID,
            adapter,
            capabilities: [CJ_MISSION_CAPABILITY, CJ_ADVERTISER_READ_CAPABILITY]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        })
    }

    pub fn registry(&self) -> Result<ProviderAdapterRegistry, CjError> {
        let registrations = [
            registration(
                CJ_CONNECTION_CAPABILITY,
                ProviderAdapterOperation::Probe,
                ProviderEvidenceClass::ProbeObservation,
                &self.adapter,
            )?,
            registration(
                CJ_ADVERTISER_READ_CAPABILITY,
                ProviderAdapterOperation::Read,
                ProviderEvidenceClass::ReadObservation,
                &self.adapter,
            )?,
        ];
        ProviderAdapterRegistry::new("cj-plugin-v1", registrations)
            .map_err(|error| CjError::ProviderContract(error.to_string()))
    }
}

fn registration(
    capability: &str,
    operation: ProviderAdapterOperation,
    evidence_class: ProviderEvidenceClass,
    adapter: &ProviderAdapterIdentity,
) -> Result<ProviderCapabilitySupport, CjError> {
    let key = ProviderCapabilityKey::new(CJ_PROVIDER_ID, capability)
        .map_err(|error| CjError::ProviderContract(error.to_string()))?;
    let evidence = [
        ProviderProvenanceClass::ControlledProvider,
        ProviderProvenanceClass::ProductionProvider,
    ]
    .into_iter()
    .map(|provenance| ProviderEvidenceSupport::new(operation, evidence_class, provenance))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| CjError::ProviderContract(error.to_string()))?;
    ProviderCapabilitySupport::new(key, adapter.clone(), evidence)
        .map_err(|error| CjError::ProviderContract(error.to_string()))
}

struct CjConnectorAdapter<T, C>
where
    T: CjTransport,
    C: CjCredentialResolver,
{
    descriptor: ConnectorDescriptor,
    scope: CjScope,
    connector_scope: ConnectorScope,
    plan: CjReadPlan,
    transport: T,
    credentials: C,
    state: Arc<Mutex<CjAdapterState>>,
}

impl<T, C> fmt::Debug for CjConnectorAdapter<T, C>
where
    T: CjTransport,
    C: CjCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CjConnectorAdapter")
            .field("adapter", &self.descriptor.identity())
            .field("scope_digest", &self.connector_scope.digest())
            .field("resource", &self.plan.resource)
            .finish_non_exhaustive()
    }
}

impl<T, C> CjConnectorAdapter<T, C>
where
    T: CjTransport,
    C: CjCredentialResolver,
{
    fn new(
        scope: CjScope,
        plan: CjReadPlan,
        transport: T,
        credentials: C,
        state: Arc<Mutex<CjAdapterState>>,
    ) -> Result<Self, CjError> {
        let definition = CjServiceDefinition::new()?;
        let connector_scope = scope.connector_scope()?;
        let registry = definition.registry()?;
        let descriptor = ConnectorDescriptor::new(
            definition.adapter.clone(),
            registry.registrations().to_vec(),
        )
        .map_err(CjError::from)?;
        Ok(Self {
            descriptor,
            scope,
            connector_scope,
            plan,
            transport,
            credentials,
            state,
        })
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, CjAdapterState>, ConnectorError> {
        self.state
            .lock()
            .map_err(|_| ConnectorError::ProviderRejected)
    }

    fn validate_probe_response(&self, response: &CjProbeResponse) -> Result<(), CjProviderError> {
        if response.publisher_id != *self.scope.publisher_id()
            || !response.advertiser_ids.contains(self.scope.advertiser_id())
            || response.source_revision == 0
            || !is_sha256(&response.source_digest)
            || !response.source_uri.starts_with("https://")
        {
            return Err(CjProviderError::ScopeDrift);
        }
        Ok(())
    }

    fn validate_page(&self, page: &CjProviderPage) -> Result<(), CjProviderError> {
        if page.resource != self.plan.resource
            || page.publisher_id != *self.scope.publisher_id()
            || !page.advertiser_ids.contains(self.scope.advertiser_id())
            || page.page_number == 0
            || page.records_returned == 0
            || page.records_returned > self.plan.records_per_page
            || u64::from(page.records_returned) > page.total_matched
            || page.source_revision == 0
            || !is_sha256(&page.source_digest)
            || page.source_digest != sha256_hex(&page.payload)
            || !page.source_uri.starts_with("https://")
        {
            return Err(CjProviderError::ScopeDrift);
        }
        Ok(())
    }

    fn provider_rejection(
        &mut self,
        error: &CjProviderError,
        credential_revision: u64,
        at: DateTime<Utc>,
    ) -> Result<ProbeObservation, ConnectorError> {
        let observation = CjProbeObservation::rejected(
            &self.scope,
            credential_revision,
            at,
            error,
            self.transport.provenance_class(),
        );
        self.state()?.last_probe = Some(observation.clone());
        ProbeObservation::new(
            ProbeStatus::Rejected,
            self.transport.provenance_class(),
            observation.observed_at,
            observation.valid_until,
            observation.evidence_digest,
        )
    }
}

impl<T, C> ConnectorAdapter for CjConnectorAdapter<T, C>
where
    T: CjTransport,
    C: CjCredentialResolver,
{
    fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    fn begin_auth(&mut self, request: BeginAuthRequest) -> Result<AuthSession, ConnectorError> {
        if request.scope != self.connector_scope {
            return Err(ConnectorError::ScopeMismatch);
        }
        ConnectorAuth::begin_auth_session(
            &request.secret_reference,
            &request.credential_lease,
            format!("auth-session-cj-{}", request.auth_revision),
            request.auth_revision,
            request.issued_at,
            request.expires_at,
        )
    }

    fn refresh_auth(&mut self, request: RefreshAuthRequest) -> Result<AuthSession, ConnectorError> {
        if request.scope != self.connector_scope || request.session.scope() != &self.connector_scope
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        ConnectorAuth::begin_auth_session(
            &request.secret_reference,
            &request.credential_lease,
            format!("auth-session-cj-refresh-{}", request.auth_revision),
            request.auth_revision,
            request.issued_at,
            request.expires_at,
        )
    }

    fn probe(&mut self, request: ProbeRequest) -> Result<ProbeObservation, ConnectorError> {
        if request.scope != self.connector_scope || request.session.scope() != &self.connector_scope
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        let credential_revision = request.secret_reference.credential_revision();
        let token =
            match self
                .credentials
                .resolve(&request.secret_reference, &self.scope, request.at)
            {
                Ok(token) => token,
                Err(error) => {
                    return self.provider_rejection(&error, credential_revision, request.at);
                }
            };
        let response = match self.transport.probe(
            &token,
            &CjProbeRequest {
                scope: self.scope.clone(),
                observed_at: request.at,
            },
        ) {
            Ok(response) => response,
            Err(error) => return self.provider_rejection(&error, credential_revision, request.at),
        };
        if let Err(error) = self.validate_probe_response(&response) {
            return self.provider_rejection(&error, credential_revision, request.at);
        }
        let observation = CjProbeObservation::reachable(
            &self.scope,
            credential_revision,
            &response,
            self.transport.provenance_class(),
        );
        self.state()?.active_credential = Some(ActiveCjCredential {
            credential_revision,
            token,
        });
        self.state()?.last_probe = Some(observation.clone());
        ProbeObservation::new(
            ProbeStatus::Reachable,
            self.transport.provenance_class(),
            observation.observed_at,
            observation.valid_until,
            observation.evidence_digest,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn read(&mut self, request: ReadRequest) -> Result<ReadObservation, ConnectorError> {
        if request.scope != self.connector_scope
            || request.capability.capability_id() != self.plan.resource.capability()
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        let (token, revoked) = {
            let state = self.state()?;
            let Some(active) = &state.active_credential else {
                return Err(ConnectorError::ProviderRejected);
            };
            (active.token.clone(), state.revoked)
        };
        if revoked {
            return Err(ConnectorError::ProviderRejected);
        }
        let page_number = request
            .cursor
            .as_ref()
            .map_or(1, |cursor| u32::try_from(cursor.sequence()).unwrap_or(0));
        if page_number == 0
            || request.cursor.as_ref().is_some_and(|cursor| {
                cursor.scope_digest() != self.connector_scope.digest()
                    || cursor.request_digest() != request.query_digest
                    || cursor.token_digest()
                        != digest_parts([
                            CJ_SCHEMA_VERSION,
                            cursor.scope_digest(),
                            &request.query_digest,
                            &page_number.to_string(),
                        ])
            })
        {
            return Err(ConnectorError::CursorMismatch);
        }
        let page = self
            .transport
            .read(
                &token,
                &CjProviderReadRequest {
                    scope: self.scope.clone(),
                    resource: self.plan.resource,
                    relationship: self.plan.relationship.clone(),
                    page_number,
                    records_per_page: self.plan.records_per_page,
                    observed_at: request.at,
                },
            )
            .map_err(|error| match error {
                CjProviderError::RateLimited | CjProviderError::HttpStatus { status: 429, .. } => {
                    ConnectorError::RateLimited
                }
                CjProviderError::ScopeDrift => ConnectorError::ScopeMismatch,
                _ => ConnectorError::ProviderRejected,
            })?;
        self.validate_page(&page)
            .map_err(|_| ConnectorError::ProviderRejected)?;
        if page.page_number != page_number {
            return Err(ConnectorError::CursorMismatch);
        }
        let freshness = FreshnessWindow::new(
            request.at,
            request.at + Duration::seconds(CJ_DEFAULT_FRESHNESS_SECONDS),
            page.source_revision,
        )?;
        let has_more = u64::from(page.page_number.saturating_sub(1))
            .saturating_mul(u64::from(self.plan.records_per_page))
            .saturating_add(u64::from(page.records_returned))
            < page.total_matched;
        let next_cursor = if has_more {
            let next_page = page_number.saturating_add(1);
            Some(
                Cursor::new(
                    &self.connector_scope,
                    request.query_digest.clone(),
                    u64::from(next_page),
                    digest_parts([
                        CJ_SCHEMA_VERSION,
                        &self.connector_scope.digest(),
                        &request.query_digest,
                        &next_page.to_string(),
                    ]),
                )
                .map_err(|_| ConnectorError::CursorMismatch)?,
            )
        } else {
            None
        };
        let content_digest = sha256_hex(&page.payload);
        let observation = ReadObservation::new(
            format!(
                "read-observation-cj-{}-{}",
                &page.source_digest[..12],
                page_number
            ),
            self.connector_scope.clone(),
            request.capability,
            self.descriptor.identity().clone(),
            request.query_digest,
            page.source_digest.clone(),
            content_digest,
            self.transport.provenance_class(),
            freshness,
            u64::from(page_number),
            page.records_returned,
            next_cursor,
        )?;
        self.state()?.last_page = Some(page);
        Ok(observation)
    }

    fn prepare_effect(
        &mut self,
        _request: PrepareEffectRequest,
    ) -> Result<PreparedEffect, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn execute(&mut self, _request: ExecuteRequest) -> Result<ReceiptCandidate, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn reconcile(
        &mut self,
        _request: ReconcileRequest,
    ) -> Result<ReconciliationObservation, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn verify(
        &mut self,
        _request: VerifyRequest,
    ) -> Result<VerificationObservation, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
    }

    fn handle_webhook(
        &mut self,
        request: WebhookRequest,
    ) -> Result<WebhookObservation, ConnectorError> {
        if request.scope != self.connector_scope
            || request.envelope.provider_id() != CJ_PROVIDER_ID
            || request.envelope.account_id() != self.scope.publisher_id().as_str()
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        if request.envelope.adapter().adapter_id() != CJ_ADAPTER_ID
            || request.envelope.adapter().adapter_version() != CJ_ADAPTER_VERSION
        {
            return Err(ConnectorError::AdapterMetadataMismatch);
        }
        WebhookObservation::from_envelope(
            &request.envelope,
            self.connector_scope.clone(),
            request.at,
        )
    }

    fn revoke(&mut self, _request: RevokeRequest) -> Result<(), ConnectorError> {
        let mut state = self.state()?;
        state.active_credential = None;
        state.last_probe = None;
        state.last_page = None;
        state.revoked = true;
        Ok(())
    }
}

pub struct CjService<T, C>
where
    T: CjTransport,
    C: CjCredentialResolver,
{
    definition: CjServiceDefinition,
    scope: CjScope,
    connector_scope: ConnectorScope,
    plan: CjReadPlan,
    query_digest: String,
    state: Arc<Mutex<CjAdapterState>>,
    worker: ConnectorWorker<CjConnectorAdapter<T, C>>,
    budget: CjBudget,
    secret_reference: Option<SecretReference>,
    credential_lease: Option<CredentialLease>,
    auth_session: Option<AuthSession>,
    probe_result: Option<ProbeResult>,
    reconcile_authority: reconcile::CjReconcileAuthority,
    mounted: bool,
}

impl<T, C> fmt::Debug for CjService<T, C>
where
    T: CjTransport,
    C: CjCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CjService")
            .field("service_id", &self.definition.service_id)
            .field("scope_digest", &self.connector_scope.digest())
            .field("resource", &self.plan.resource)
            .field("mounted", &self.mounted)
            .finish_non_exhaustive()
    }
}

impl<T, C> CjService<T, C>
where
    T: CjTransport,
    C: CjCredentialResolver,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_id: impl Into<String>,
        scope: CjScope,
        plan: CjReadPlan,
        transport: T,
        credentials: C,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
        budget: CjBudget,
    ) -> Result<Self, CjError> {
        let definition = CjServiceDefinition::new()?;
        let connector_scope = scope.connector_scope()?;
        let query_digest = plan.query_digest(&scope)?;
        let state = Arc::new(Mutex::new(CjAdapterState::default()));
        let adapter = CjConnectorAdapter::new(
            scope.clone(),
            plan.clone(),
            transport,
            credentials,
            state.clone(),
        )?;
        let worker = ConnectorWorker::new(
            worker_id,
            adapter,
            definition.registry()?,
            connector_scope.clone(),
            now,
            lease_expires_at,
        )
        .map_err(CjError::from)?;
        Ok(Self {
            definition,
            scope,
            connector_scope,
            plan,
            query_digest,
            state,
            worker,
            budget,
            secret_reference: None,
            credential_lease: None,
            auth_session: None,
            probe_result: None,
            reconcile_authority: reconcile::CjReconcileAuthority::new(),
            mounted: true,
        })
    }

    pub fn definition(&self) -> &CjServiceDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &CjScope {
        &self.scope
    }

    pub fn connector_scope(&self) -> &ConnectorScope {
        &self.connector_scope
    }

    pub fn plan(&self) -> &CjReadPlan {
        &self.plan
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub fn budget(&self) -> &CjBudget {
        &self.budget
    }

    pub fn reconcile_authority(&self) -> &reconcile::CjReconcileAuthority {
        &self.reconcile_authority
    }

    pub fn begin_auth(
        &mut self,
        secret_reference: SecretReference,
        credential_lease: CredentialLease,
        auth_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<AuthSession, CjError> {
        self.ensure_mounted()?;
        if secret_reference.scope() != &self.connector_scope
            || credential_lease.scope() != &self.connector_scope
        {
            return Err(CjError::Connector(ConnectorError::ScopeMismatch));
        }
        let session = self.worker.begin_auth(BeginAuthRequest {
            dispatch: self.worker.dispatch_fence(),
            scope: self.connector_scope.clone(),
            secret_reference: secret_reference.clone(),
            credential_lease: credential_lease.clone(),
            auth_revision,
            issued_at,
            expires_at,
        })?;
        self.reconcile_authority.invalidate()?;
        self.secret_reference = Some(secret_reference);
        self.credential_lease = Some(credential_lease);
        self.auth_session = Some(session.clone());
        self.probe_result = None;
        Ok(session)
    }

    pub fn refresh_auth(
        &mut self,
        secret_reference: SecretReference,
        credential_lease: CredentialLease,
        session: AuthSession,
        auth_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<AuthSession, CjError> {
        self.ensure_mounted()?;
        let refreshed = self.worker.refresh_auth(RefreshAuthRequest {
            dispatch: self.worker.dispatch_fence(),
            scope: self.connector_scope.clone(),
            secret_reference: secret_reference.clone(),
            credential_lease: credential_lease.clone(),
            session,
            auth_revision,
            issued_at,
            expires_at,
        })?;
        self.reconcile_authority.invalidate()?;
        self.secret_reference = Some(secret_reference);
        self.credential_lease = Some(credential_lease);
        self.auth_session = Some(refreshed.clone());
        self.probe_result = None;
        Ok(refreshed)
    }

    pub fn probe(
        &mut self,
        probe_revision: u64,
        result_id: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Result<CjProbeReceipt, CjError> {
        self.ensure_mounted()?;
        self.reconcile_authority.invalidate()?;
        let secret_reference = self
            .secret_reference
            .clone()
            .ok_or(CjError::MissingAuthentication)?;
        let credential_lease = self
            .credential_lease
            .clone()
            .ok_or(CjError::MissingAuthentication)?;
        let session = self
            .auth_session
            .clone()
            .ok_or(CjError::MissingAuthentication)?;
        let connector_result = self.worker.probe(ProbeRequest {
            dispatch: self.worker.dispatch_fence(),
            scope: self.connector_scope.clone(),
            secret_reference,
            credential_lease,
            session,
            probe_revision,
            result_id: result_id.into(),
            at,
        })?;
        let observation = self
            .state
            .lock()
            .map_err(|_| CjError::StatePoisoned)?
            .last_probe
            .clone()
            .ok_or(CjError::Disconnected)?;
        if observation.status == CjProbeStatus::Reachable
            && observation.classification == CjObservationClassification::FirstParty
        {
            self.reconcile_authority.activate()?;
        }
        self.probe_result = Some(connector_result.clone());
        Ok(CjProbeReceipt {
            credential_revision: observation.credential_revision,
            connector_result,
            observation,
        })
    }

    pub fn reconcile_session(
        &self,
        probe: &CjProbeReceipt,
        program_id: CjProgramId,
        expected_webhook_events: u64,
    ) -> Result<reconcile::CjReconcileSession, CjError> {
        self.ensure_mounted()?;
        if self.probe_result.as_ref() != Some(&probe.connector_result) {
            return Err(CjError::GenerationDrift);
        }
        let generation =
            reconcile::CjProviderGeneration::from_probe(self.scope(), program_id, probe)?;
        reconcile::CjReconcileSession::new(
            self.scope.clone(),
            self.plan.clone(),
            generation,
            self.reconcile_authority.clone(),
            expected_webhook_events,
        )
    }

    pub fn handle_webhook(
        &mut self,
        envelope: WebhookEnvelope,
        key: &WebhookSigningKey,
        at: DateTime<Utc>,
    ) -> Result<WebhookObservation, CjError> {
        self.ensure_mounted()?;
        self.worker
            .handle_webhook(
                WebhookRequest {
                    dispatch: self.worker.dispatch_fence(),
                    scope: self.connector_scope.clone(),
                    envelope,
                    at,
                },
                key,
            )
            .map_err(CjError::from)
    }

    #[allow(clippy::too_many_lines)]
    pub fn read(
        &mut self,
        cursor: Option<&CjDurableCursor>,
        at: DateTime<Utc>,
    ) -> Result<CjReadResult, CjError> {
        self.ensure_mounted()?;
        let probe = self.probe_result.as_ref().ok_or(CjError::Disconnected)?;
        let live_probe = self
            .worker
            .authorize_probe(probe, at)
            .map_err(|error| match error {
                ConnectorError::ProbeNotLive
                | ConnectorError::ProbeExpired
                | ConnectorError::UnsupportedProvenance => CjError::Disconnected,
                other => CjError::Connector(other),
            })?;
        let sdk_cursor = if let Some(cursor) = cursor {
            cursor.validate_against(&self.plan, &self.scope, &self.query_digest)?;
            Some(cursor.to_sdk_cursor(&self.connector_scope)?)
        } else {
            None
        };
        self.budget.admit(at, CJ_READ_COST_UNITS)?;
        let sdk_budget =
            DispatchBudget::new(CJ_CALL_LIMIT_PER_MINUTE, at + Duration::minutes(1), 1, 0)
                .map_err(CjError::from)?;
        let capability =
            ProviderCapabilityKey::new(CJ_PROVIDER_ID, self.plan.resource.capability())
                .map_err(|error| CjError::ProviderContract(error.to_string()))?;
        let connector_observation = self
            .worker
            .read(ReadRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.connector_scope.clone(),
                live_probe,
                capability,
                query_digest: self.query_digest.clone(),
                cursor: sdk_cursor,
                page_size: self.plan.records_per_page,
                at,
                budget: sdk_budget,
            })
            .map_err(|error| match error {
                ConnectorError::RateLimited => CjError::RateLimited,
                ConnectorError::QuotaExceeded => CjError::QuotaExceeded,
                ConnectorError::CostLimitExceeded => CjError::CostLimitExceeded,
                ConnectorError::ProbeNotLive
                | ConnectorError::ProbeExpired
                | ConnectorError::UnsupportedProvenance => CjError::Disconnected,
                other => CjError::Connector(other),
            })?;
        let page = self
            .state
            .lock()
            .map_err(|_| CjError::StatePoisoned)?
            .last_page
            .clone()
            .ok_or(CjError::ProviderRejected)?;
        let credential_revision = self
            .state
            .lock()
            .map_err(|_| CjError::StatePoisoned)?
            .active_credential
            .as_ref()
            .map(|active| active.credential_revision)
            .ok_or(CjError::MissingAuthentication)?;
        let next_cursor = if connector_observation.next_cursor().is_some() {
            Some(CjDurableCursor::new(
                &self.plan,
                &self.scope,
                &self.query_digest,
                page.page_number.saturating_add(1),
            )?)
        } else {
            None
        };
        let content_digest = connector_observation.content_digest().to_owned();
        let freshness = connector_observation.freshness();
        let data = CjReadData {
            resource: page.resource,
            page_number: page.page_number,
            records_returned: page.records_returned,
            total_matched: page.total_matched,
            payload: page.payload.clone(),
        };
        let cost = CjCostReceipt {
            cost_units: CJ_READ_COST_UNITS,
            rate_remaining: self.budget.rate_remaining,
            rate_reset_at: self.budget.rate_reset_at,
            quota_limit: self.budget.quota_limit,
            quota_used: self.budget.quota_used,
            quota_remaining: self.budget.quota_remaining(),
            cost_limit_units: self.budget.cost_limit_units,
            cost_used_units: self.budget.cost_used_units,
            cost_remaining_units: self.budget.cost_remaining_units(),
        };
        let result_digest = digest_parts([
            CJ_SCHEMA_VERSION,
            CJ_SERVICE_ID,
            &self.connector_scope.digest(),
            &self.query_digest,
            &credential_revision.to_string(),
            &page.source_revision.to_string(),
            page.source_digest.as_str(),
            content_digest.as_str(),
            &page.page_number.to_string(),
        ]);
        let envelope = CjResultEnvelope {
            schema_version: CJ_SCHEMA_VERSION.to_owned(),
            service_id: CJ_SERVICE_ID.to_owned(),
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: self.scope.publisher_id().clone(),
            advertiser_id: self.scope.advertiser_id().clone(),
            resource: page.resource,
            scope_digest: self.connector_scope.digest(),
            query_digest: self.query_digest.clone(),
            credential_revision,
            source_revision: page.source_revision,
            observed_at: freshness.observed_at(),
            valid_until: freshness.valid_until(),
            source_uri: page.source_uri,
            source_digest: page.source_digest,
            content_digest,
            classification: if connector_observation.provenance_class()
                == ProviderProvenanceClass::ProductionProvider
            {
                CjObservationClassification::FirstParty
            } else {
                CjObservationClassification::Fixture
            },
            cursor: next_cursor,
            cost,
            data,
            result_digest,
        };
        Ok(CjReadResult {
            connector_observation,
            envelope,
        })
    }

    pub fn revoke(
        &mut self,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<CjLifecycleReceipt, CjError> {
        self.ensure_mounted()?;
        let reason_digest = sha256_hex(reason);
        self.worker.revoke(RevokeRequest {
            dispatch: self.worker.dispatch_fence(),
            scope: self.connector_scope.clone(),
            reason_digest: reason_digest.clone(),
            at,
        })?;
        self.secret_reference = None;
        self.credential_lease = None;
        self.auth_session = None;
        self.probe_result = None;
        self.reconcile_authority.invalidate()?;
        let scope_digest = self.connector_scope.digest();
        Ok(lifecycle_receipt(
            "revoke",
            &scope_digest,
            at,
            &reason_digest,
        ))
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) -> Result<CjLifecycleReceipt, CjError> {
        if !self.mounted {
            return Err(CjError::Unmounted);
        }
        self.secret_reference = None;
        self.credential_lease = None;
        self.auth_session = None;
        self.probe_result = None;
        self.reconcile_authority.invalidate()?;
        if let Ok(mut state) = self.state.lock() {
            state.active_credential = None;
            state.last_probe = None;
            state.last_page = None;
        }
        self.mounted = false;
        let scope_digest = self.connector_scope.digest();
        Ok(lifecycle_receipt("unmount", &scope_digest, at, "unmount"))
    }

    fn ensure_mounted(&self) -> Result<(), CjError> {
        if !self.mounted {
            return Err(CjError::Unmounted);
        }
        if self
            .state
            .lock()
            .map_err(|_| CjError::StatePoisoned)?
            .revoked
        {
            return Err(CjError::Revoked);
        }
        Ok(())
    }
}

impl CjService<CjHttpTransport, BlockedEnvCjCredentialResolver> {
    pub fn production(
        worker_id: impl Into<String>,
        scope: CjScope,
        plan: CjReadPlan,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
        budget: CjBudget,
    ) -> Result<Self, CjError> {
        Self::new(
            worker_id,
            scope,
            plan,
            CjHttpTransport::official(),
            BlockedEnvCjCredentialResolver,
            now,
            lease_expires_at,
            budget,
        )
    }
}

#[derive(Clone, Debug)]
pub struct CjServiceProvider {
    definition: CjServiceDefinition,
    scope: CjScope,
    mounted_at: DateTime<Utc>,
    active: bool,
    revoked: bool,
}

impl CjServiceProvider {
    pub fn mount(scope: CjScope, at: DateTime<Utc>) -> Result<Self, CjError> {
        Ok(Self {
            definition: CjServiceDefinition::new()?,
            scope,
            mounted_at: at,
            active: true,
            revoked: false,
        })
    }

    pub fn definition(&self) -> &CjServiceDefinition {
        &self.definition
    }

    pub fn registration_receipt(&self) -> Result<CjLifecycleReceipt, CjError> {
        if !self.active || self.revoked {
            return Err(CjError::Unmounted);
        }
        let scope_digest = self.scope.digest()?;
        Ok(lifecycle_receipt(
            "mount",
            &scope_digest,
            self.mounted_at,
            CJ_SERVICE_ID,
        ))
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<CjLifecycleReceipt, CjError> {
        if !self.active {
            return Err(CjError::Unmounted);
        }
        self.revoked = true;
        self.active = false;
        let scope_digest = self.scope.digest()?;
        Ok(lifecycle_receipt(
            "revoke",
            &scope_digest,
            at,
            "provider-revoke",
        ))
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) -> Result<CjLifecycleReceipt, CjError> {
        if !self.active {
            return Err(CjError::Unmounted);
        }
        self.active = false;
        let scope_digest = self.scope.digest()?;
        Ok(lifecycle_receipt(
            "unmount",
            &scope_digest,
            at,
            "provider-unmount",
        ))
    }
}

#[derive(Clone, Debug)]
pub struct CjMissionReadExpectation {
    pub mission_id: String,
    pub mission_revision: u64,
    pub provider_id: String,
    pub publisher_id: CjPublisherId,
    pub advertiser_id: CjAdvertiserId,
    pub credential_revision: u64,
    pub probe_revision: u64,
    pub source_revision: u64,
    pub capability: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CjMissionReadReceipt {
    pub mission_id: String,
    pub mission_revision: u64,
    pub provider_id: String,
    pub publisher_id: CjPublisherId,
    pub advertiser_id: CjAdvertiserId,
    pub credential_revision: u64,
    pub probe_revision: u64,
    pub source_revision: u64,
    pub result_digest: String,
}

#[derive(Clone, Debug, Default)]
pub struct CjMissionConsumer;

impl CjMissionConsumer {
    pub fn consume(
        &self,
        mission: &Mission,
        scope: &CjScope,
        probe: &CjProbeReceipt,
        result: &CjReadResult,
        expected: &CjMissionReadExpectation,
        at: DateTime<Utc>,
    ) -> Result<CjMissionReadReceipt, CjError> {
        mission
            .contract
            .validate(at)
            .map_err(|error| CjError::Mission(error.to_string()))?;
        let scope_digest = scope.digest()?;
        let mission_scope = scope.connector_scope()?;
        let envelope = &result.envelope;
        let observation = &result.connector_observation;
        let exact = mission.id.as_str() == expected.mission_id
            && mission.revision == expected.mission_revision
            && mission.tenant_id.as_str() == scope.tenant_id()
            && mission.project_id.as_str() == scope.project_id()
            && mission
                .contract
                .enabled_capabilities
                .contains(CJ_MISSION_CAPABILITY)
            && expected.provider_id == CJ_PROVIDER_ID
            && expected.publisher_id == *scope.publisher_id()
            && expected.advertiser_id == *scope.advertiser_id()
            && expected.capability == envelope.resource.capability()
            && envelope.provider_id == CJ_PROVIDER_ID
            && envelope.publisher_id == *scope.publisher_id()
            && envelope.advertiser_id == *scope.advertiser_id()
            && envelope.scope_digest == scope_digest
            && probe.observation.status == CjProbeStatus::Reachable
            && probe.observation.classification == CjObservationClassification::FirstParty
            && probe.observation.provider_id == CJ_PROVIDER_ID
            && probe.observation.publisher_id == *scope.publisher_id()
            && probe.observation.advertiser_id == *scope.advertiser_id()
            && probe.connector_result.status() == ProbeStatus::Reachable
            && probe.connector_result.provenance_class()
                == ProviderProvenanceClass::ProductionProvider
            && probe.connector_result.evidence_digest() == probe.observation.evidence_digest
            && probe.connector_result.probe_revision() == expected.probe_revision
            && probe.credential_revision == expected.credential_revision
            && envelope.credential_revision == expected.credential_revision
            && envelope.source_revision == expected.source_revision
            && observation.provenance_class() == ProviderProvenanceClass::ProductionProvider
            && observation.scope() == &mission_scope
            && at >= observation.freshness().observed_at()
            && at < observation.freshness().valid_until();
        if !exact {
            return Err(CjError::MissionBinding);
        }
        Ok(CjMissionReadReceipt {
            mission_id: expected.mission_id.clone(),
            mission_revision: expected.mission_revision,
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: expected.publisher_id.clone(),
            advertiser_id: expected.advertiser_id.clone(),
            credential_revision: expected.credential_revision,
            probe_revision: expected.probe_revision,
            source_revision: expected.source_revision,
            result_digest: envelope.result_digest.clone(),
        })
    }
}

fn lifecycle_receipt(
    action: &str,
    scope_digest: &str,
    at: DateTime<Utc>,
    reason: &str,
) -> CjLifecycleReceipt {
    CjLifecycleReceipt {
        service_id: CJ_SERVICE_ID.to_owned(),
        provider_id: CJ_PROVIDER_ID.to_owned(),
        scope_digest: scope_digest.to_owned(),
        action: action.to_owned(),
        at,
        receipt_digest: digest_parts([
            CJ_SCHEMA_VERSION,
            CJ_SERVICE_ID,
            action,
            scope_digest,
            &at.to_rfc3339(),
            reason,
        ]),
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn extract_xml_values(body: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut values = Vec::new();
    let mut remainder = body;
    while let Some(start) = remainder.find(&open) {
        let content = &remainder[start + open.len()..];
        let Some(end) = content.find(&close) else {
            break;
        };
        values.push(content[..end].trim().to_owned());
        remainder = &content[end + close.len()..];
    }
    values
}

fn extract_xml_u64(body: &str, tag: &str) -> Option<u64> {
    extract_xml_values(body, tag)
        .first()
        .and_then(|value| value.parse::<u64>().ok())
}

fn extract_xml_ids(body: &str, tag: &str) -> Result<BTreeSet<CjAdvertiserId>, CjProviderError> {
    extract_xml_values(body, tag)
        .into_iter()
        .map(|value| CjAdvertiserId::new(value).map_err(|_| CjProviderError::InvalidResponse))
        .collect()
}

fn digest_parts(parts: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    let material = parts
        .into_iter()
        .map(|part| {
            let part = part.as_ref();
            format!("{}:{}", part.len(), part)
        })
        .collect::<Vec<_>>()
        .join("|");
    sha256_hex(&material)
}

fn sha256_hex(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn revision_from_digest(digest: &str) -> u64 {
    u64::from_str_radix(&digest[..16], 16).unwrap_or(1).max(1)
}

#[cfg(test)]
mod tests {
    use super::reconcile::{
        CjMissionReconcileConsumer, CjMissionReconcileExpectation, CjPageDelivery,
        CjReconcileOutcome, CjReconcileScope, CjWebhookDelivery,
    };
    use super::*;
    use hartevo_connector_sdk::ConnectorAuth;
    use hartevo_connector_sdk::{ProviderAdapterIdentity, WebhookObservation, WebhookSigningKey};
    use hartevo_domain_kernel::{Mission, MissionContract, MissionId, ProjectId, TenantId};

    const NOW: &str = "2026-08-14T00:00:00Z";

    #[derive(Debug)]
    struct ContractTransport {
        provenance: ProviderProvenanceClass,
        reads: u32,
        wrong_scope: bool,
    }

    impl ContractTransport {
        fn production() -> Self {
            Self {
                provenance: ProviderProvenanceClass::ProductionProvider,
                reads: 0,
                wrong_scope: false,
            }
        }

        fn wrong_scope() -> Self {
            Self {
                wrong_scope: true,
                ..Self::production()
            }
        }
    }

    impl CjTransport for ContractTransport {
        fn provenance_class(&self) -> ProviderProvenanceClass {
            self.provenance
        }

        fn probe(
            &mut self,
            _token: &CjAccessToken,
            request: &CjProbeRequest,
        ) -> Result<CjProbeResponse, CjProviderError> {
            let advertiser_id = if self.wrong_scope {
                CjAdvertiserId::new("99999").expect("wrong advertiser")
            } else {
                request.scope.advertiser_id().clone()
            };
            let source_digest = sha256_hex("cj-contract-probe");
            Ok(CjProbeResponse {
                publisher_id: request.scope.publisher_id().clone(),
                advertiser_ids: [advertiser_id].into_iter().collect(),
                source_uri: CJ_ADVERTISER_LOOKUP_ENDPOINT.to_owned(),
                source_digest: source_digest.clone(),
                source_revision: revision_from_digest(&source_digest),
                observed_at: request.observed_at,
            })
        }

        fn read(
            &mut self,
            _token: &CjAccessToken,
            request: &CjProviderReadRequest,
        ) -> Result<CjProviderPage, CjProviderError> {
            self.reads = self.reads.saturating_add(1);
            let payload = format!(
                "<cj-api><advertisers><total-matched>2</total-matched><records-returned>1</records-returned><page-number>{}</page-number><advertiser><advertiser-id>{}</advertiser-id><program-id>555</program-id><program-name>CJ Contract Program</program-name></advertiser></advertisers></cj-api>",
                request.page_number,
                request.scope.advertiser_id()
            );
            let source_digest = sha256_hex(&payload);
            Ok(CjProviderPage {
                resource: request.resource,
                publisher_id: request.scope.publisher_id().clone(),
                advertiser_ids: [request.scope.advertiser_id().clone()]
                    .into_iter()
                    .collect(),
                page_number: request.page_number,
                total_matched: 2,
                records_returned: 1,
                source_uri: CJ_ADVERTISER_LOOKUP_ENDPOINT.to_owned(),
                source_digest: source_digest.clone(),
                source_revision: revision_from_digest(&source_digest),
                observed_at: request.observed_at,
                payload,
            })
        }
    }

    #[derive(Clone, Debug)]
    struct ContractResolver {
        available: bool,
    }

    impl CjCredentialResolver for ContractResolver {
        fn resolve(
            &mut self,
            reference: &SecretReference,
            scope: &CjScope,
            _at: DateTime<Utc>,
        ) -> Result<CjAccessToken, CjProviderError> {
            if !self.available {
                return Err(CjProviderError::BlockedEnv);
            }
            if reference.scope()
                != &scope
                    .connector_scope()
                    .map_err(|_| CjProviderError::ScopeDrift)?
            {
                return Err(CjProviderError::ScopeDrift);
            }
            CjAccessToken::new("contract-cj-token").map_err(|_| CjProviderError::InvalidResponse)
        }
    }

    fn now() -> DateTime<Utc> {
        NOW.parse().expect("deterministic time")
    }

    fn scope() -> CjScope {
        CjScope::new(
            "tenant-cj",
            "project-cj",
            CjPublisherId::new("12345").expect("publisher"),
            CjAdvertiserId::new("98765").expect("advertiser"),
        )
        .expect("scope")
    }

    fn plan() -> CjReadPlan {
        CjReadPlan::new(1, "all").expect("plan")
    }

    fn budget() -> CjBudget {
        CjBudget::new(25, now() + Duration::minutes(1), 10, 10).expect("budget")
    }

    fn auth_material(scope: &CjScope) -> (SecretReference, CredentialLease) {
        auth_material_with_revision(scope, 7)
    }

    fn auth_material_with_revision(
        scope: &CjScope,
        credential_revision: u64,
    ) -> (SecretReference, CredentialLease) {
        let connector_scope = scope.connector_scope().expect("connector scope");
        let secret =
            SecretReference::new("secret-ref-cj-test", connector_scope, credential_revision)
                .expect("secret reference");
        let adapter =
            ProviderAdapterIdentity::new(CJ_ADAPTER_ID, CJ_ADAPTER_VERSION).expect("adapter");
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            adapter,
            "lease-cj-test",
            3,
            now(),
            now() + Duration::minutes(10),
        )
        .expect("lease");
        (secret, lease)
    }

    fn service<R>(transport: ContractTransport, resolver: R) -> CjService<ContractTransport, R>
    where
        R: CjCredentialResolver,
    {
        CjService::new(
            "worker-cj-test",
            scope(),
            plan(),
            transport,
            resolver,
            now(),
            now() + Duration::minutes(10),
            budget(),
        )
        .expect("service")
    }

    fn authenticated_service() -> (
        CjService<ContractTransport, ContractResolver>,
        CjProbeReceipt,
    ) {
        let mut service = service(
            ContractTransport::production(),
            ContractResolver { available: true },
        );
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(1, "probe-result-cj-test", now())
            .expect("probe");
        (service, probe)
    }

    #[test]
    fn service_definition_registers_only_cj_probe_and_read() {
        let definition = CjServiceDefinition::new().expect("definition");
        let registry = definition.registry().expect("registry");
        assert_eq!(registry.registrations().len(), 2);
        assert!(
            registry
                .registrations()
                .iter()
                .all(|registration| registration.adapter() == &definition.adapter)
        );
        assert_eq!(definition.provider_id, CJ_PROVIDER_ID);
        assert!(definition.capabilities.contains(CJ_MISSION_CAPABILITY));
        assert_eq!(
            CJ_ADVERTISER_LOOKUP_ENDPOINT,
            CjHttpTransport::official().base_url
        );
    }

    #[test]
    fn missing_credential_is_blocked_env_and_cannot_authorize_read() {
        let mut service = service(
            ContractTransport::production(),
            ContractResolver { available: false },
        );
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(1, "probe-result-cj-blocked", now())
            .expect("probe");
        assert_eq!(probe.observation.status, CjProbeStatus::Rejected);
        assert_eq!(
            probe.observation.classification,
            CjObservationClassification::BlockedEnv
        );
        assert!(matches!(
            service.read(None, now()),
            Err(CjError::Disconnected)
        ));
    }

    #[test]
    fn authenticated_read_emits_exact_scope_metadata_and_durable_cursor() {
        let (mut service, probe) = authenticated_service();
        assert_eq!(
            probe.observation.classification,
            CjObservationClassification::FirstParty
        );
        let first = service.read(None, now()).expect("first read");
        assert_eq!(first.envelope.provider_id, CJ_PROVIDER_ID);
        assert_eq!(first.envelope.publisher_id, *service.scope().publisher_id());
        assert_eq!(
            first.envelope.advertiser_id,
            *service.scope().advertiser_id()
        );
        assert_eq!(first.envelope.credential_revision, 7);
        assert_eq!(first.envelope.cost.cost_units, CJ_READ_COST_UNITS);
        assert_eq!(first.envelope.cost.quota_limit, 10);
        assert_eq!(first.envelope.cost.quota_used, 1);
        assert_eq!(first.envelope.cost.cost_limit_units, 10);
        assert_eq!(first.envelope.cost.cost_used_units, 1);
        assert_eq!(first.envelope.data.page_number, 1);
        assert_eq!(
            first
                .envelope
                .cursor
                .as_ref()
                .expect("next cursor")
                .next_page(),
            2
        );
        assert_eq!(service.budget().cost_used_units(), CJ_READ_COST_UNITS);
        let cursor = first.envelope.cursor.clone().expect("cursor");
        let second = service.read(Some(&cursor), now()).expect("second read");
        assert!(second.envelope.cursor.is_none());
        assert_eq!(second.envelope.data.page_number, 2);
    }

    #[test]
    fn credential_rotation_invalidates_prior_probe() {
        let (mut service, _probe) = authenticated_service();
        let (secret, lease) = auth_material_with_revision(service.scope(), 8);
        service
            .begin_auth(secret, lease, 2, now(), now() + Duration::minutes(5))
            .expect("rotated auth metadata");
        assert!(matches!(
            service.read(None, now()),
            Err(CjError::Disconnected)
        ));
        let probe = service
            .probe(2, "probe-result-cj-rotated", now())
            .expect("rotated probe");
        assert_eq!(probe.credential_revision, 8);
        assert!(service.read(None, now()).is_ok());
    }

    #[test]
    fn cursor_drift_is_rejected_before_provider_read() {
        let (service, _probe) = authenticated_service();
        let query_digest = service.query_digest().to_owned();
        let mut cursor = CjDurableCursor::new(service.plan(), service.scope(), &query_digest, 2)
            .expect("cursor");
        cursor.query_digest = sha256_hex("different-query");
        assert_eq!(
            cursor.validate_against(service.plan(), service.scope(), &query_digest),
            Err(CjError::CursorDrift)
        );
    }

    #[test]
    fn budget_boundaries_fail_closed_before_provider_read() {
        for (budget, expected) in [
            (
                CjBudget::new(0, now() + Duration::minutes(1), 10, 10).expect("rate"),
                CjError::RateLimited,
            ),
            (
                CjBudget::new(25, now() + Duration::minutes(1), 0, 10).expect("quota"),
                CjError::QuotaExceeded,
            ),
            (
                CjBudget::new(25, now() + Duration::minutes(1), 10, 0).expect("cost"),
                CjError::CostLimitExceeded,
            ),
        ] {
            let mut service = CjService::new(
                "worker-cj-budget",
                scope(),
                plan(),
                ContractTransport::production(),
                ContractResolver { available: true },
                now(),
                now() + Duration::minutes(10),
                budget,
            )
            .expect("service");
            let (secret, lease) = auth_material(service.scope());
            service
                .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
                .expect("auth metadata");
            service
                .probe(1, "probe-result-cj-budget", now())
                .expect("probe");
            assert!(matches!(service.read(None, now()), Err(error) if error == expected));
        }
    }

    #[test]
    fn provider_scope_drift_is_rejected_and_stays_disconnected() {
        let mut service = service(
            ContractTransport::wrong_scope(),
            ContractResolver { available: true },
        );
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(1, "probe-result-cj-drift", now())
            .expect("probe");
        assert_eq!(
            probe.observation.classification,
            CjObservationClassification::ScopeDrift
        );
        assert!(matches!(
            service.read(None, now()),
            Err(CjError::Disconnected)
        ));
    }

    #[test]
    fn revoke_and_unmount_reclaim_provider_material() {
        let (mut service, _probe) = authenticated_service();
        let receipt = service.revoke("user-revoked", now()).expect("revoke");
        assert_eq!(receipt.action, "revoke");
        assert!(matches!(service.read(None, now()), Err(CjError::Revoked)));
        assert_eq!(service.unmount(now()).expect("unmount").action, "unmount");
        assert!(matches!(service.read(None, now()), Err(CjError::Unmounted)));

        let mut provider = CjServiceProvider::mount(scope(), now()).expect("mount");
        assert_eq!(
            provider
                .registration_receipt()
                .expect("mount receipt")
                .action,
            "mount"
        );
        assert_eq!(
            provider.revoke(now()).expect("provider revoke").action,
            "revoke"
        );
        assert!(matches!(
            provider.registration_receipt(),
            Err(CjError::Unmounted)
        ));
    }

    #[test]
    fn mission_consumer_requires_exact_provider_account_and_revision() {
        let (mut service, probe) = authenticated_service();
        let result = service.read(None, now()).expect("read");
        let mission = Mission::compile(
            TenantId::from("tenant-cj"),
            MissionId::from("mission-cj"),
            ProjectId::from("project-cj"),
            "Read CJ advertiser data",
            MissionContract::bootstrap(
                "Read CJ partner data",
                [CJ_MISSION_CAPABILITY.to_owned()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        let expected = CjMissionReadExpectation {
            mission_id: mission.id.as_str().to_owned(),
            mission_revision: mission.revision,
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: scope().publisher_id().clone(),
            advertiser_id: scope().advertiser_id().clone(),
            credential_revision: probe.credential_revision,
            probe_revision: probe.connector_result.probe_revision(),
            source_revision: result.envelope.source_revision,
            capability: result.envelope.resource.capability().to_owned(),
        };
        let receipt = CjMissionConsumer
            .consume(&mission, service.scope(), &probe, &result, &expected, now())
            .expect("mission binding");
        assert_eq!(receipt.provider_id, CJ_PROVIDER_ID);
        assert_eq!(receipt.advertiser_id, *service.scope().advertiser_id());

        let mut tampered = expected;
        tampered.publisher_id = CjPublisherId::new("54321").expect("other account");
        assert!(matches!(
            CjMissionConsumer.consume(&mission, service.scope(), &probe, &result, &tampered, now()),
            Err(CjError::MissionBinding)
        ));
    }

    fn reconcile_fixture() -> (
        CjService<ContractTransport, ContractResolver>,
        CjProbeReceipt,
        CjReadResult,
        CjReadResult,
        reconcile::CjReconcileSession,
    ) {
        let (mut service, probe) = authenticated_service();
        let first = service.read(None, now()).expect("first page");
        let cursor = first.envelope.cursor.clone().expect("second page cursor");
        let second = service.read(Some(&cursor), now()).expect("second page");
        let session = service
            .reconcile_session(&probe, CjProgramId::new("555").expect("program"), 2)
            .expect("reconcile session");
        (service, probe, first, second, session)
    }

    fn page_delivery(
        session: &reconcile::CjReconcileSession,
        result: &CjReadResult,
        input_cursor: Option<&reconcile::CjReconcileCursor>,
    ) -> CjPageDelivery {
        CjPageDelivery::from_read(
            session.scope(),
            session.plan(),
            session.generation(),
            input_cursor,
            result,
            now(),
        )
        .expect("page delivery")
    }

    fn webhook_bytes(sequence: u64) -> Vec<u8> {
        format!(
            "<cj-event><advertiser-id>98765</advertiser-id><program-id>555</program-id><sequence>{sequence}</sequence></cj-event>"
        )
        .into_bytes()
    }

    fn signed_webhook(
        scope: &ConnectorScope,
        key: &WebhookSigningKey,
        sequence: u64,
        bytes: &[u8],
    ) -> WebhookEnvelope {
        WebhookEnvelope::sign(
            scope,
            ProviderAdapterIdentity::new(CJ_ADAPTER_ID, CJ_ADAPTER_VERSION).expect("adapter"),
            format!("webhook-event-cj-{sequence}"),
            sequence,
            now(),
            now(),
            sha256_hex(std::str::from_utf8(bytes).expect("utf8")),
            key,
        )
        .expect("signed webhook")
    }

    fn webhook_delivery(
        session: &reconcile::CjReconcileSession,
        sequence: u64,
        key: &WebhookSigningKey,
    ) -> CjWebhookDelivery {
        let bytes = webhook_bytes(sequence);
        let connector_scope = session.scope().base().connector_scope().expect("scope");
        let envelope = signed_webhook(&connector_scope, key, sequence, &bytes);
        let observation = WebhookObservation::from_envelope(&envelope, connector_scope, now())
            .expect("webhook observation");
        CjWebhookDelivery::from_verified_webhook(
            session.scope(),
            session.generation(),
            envelope,
            &observation,
            bytes,
            now(),
        )
        .expect("webhook delivery")
    }

    #[test]
    fn reconcile_deduplicates_pages_and_webhooks_exactly_once() {
        let (_service, _probe, first, second, mut session) = reconcile_fixture();
        let page_one = page_delivery(&session, &first, None);
        let page_two = page_delivery(&session, &second, page_one.next_cursor());
        assert!(matches!(
            session.accept_page(page_two.clone(), now()),
            Ok(CjReconcileOutcome::OutOfOrder(_))
        ));
        assert!(matches!(
            session.accept_page(page_one.clone(), now()),
            Ok(CjReconcileOutcome::Applied(_))
        ));
        assert!(matches!(
            session.accept_page(page_one, now()),
            Ok(CjReconcileOutcome::Duplicate(_))
        ));
        assert!(matches!(
            session.accept_page(page_two.clone(), now()),
            Ok(CjReconcileOutcome::Applied(_))
        ));
        assert!(matches!(
            session.accept_page(page_two, now()),
            Ok(CjReconcileOutcome::Duplicate(_))
        ));

        let key = WebhookSigningKey::new(b"cj-reconcile-webhook-key").expect("webhook key");
        let webhook_two = webhook_delivery(&session, 2, &key);
        let webhook_one = webhook_delivery(&session, 1, &key);
        assert!(matches!(
            session.accept_webhook(webhook_two.clone(), now()),
            Ok(CjReconcileOutcome::OutOfOrder(_))
        ));
        assert!(matches!(
            session.accept_webhook(webhook_one.clone(), now()),
            Ok(CjReconcileOutcome::Applied(_))
        ));
        assert!(matches!(
            session.accept_webhook(webhook_one, now()),
            Ok(CjReconcileOutcome::Duplicate(_))
        ));
        assert!(matches!(
            session.accept_webhook(webhook_two.clone(), now()),
            Ok(CjReconcileOutcome::Applied(_))
        ));
        let duplicate = session
            .accept_webhook(webhook_two, now())
            .expect("duplicate webhook");
        assert!(matches!(duplicate, CjReconcileOutcome::Duplicate(_)));
    }

    #[test]
    fn service_webhook_path_uses_sdk_signature_and_replay_fence() {
        let (mut service, _probe) = authenticated_service();
        let key = WebhookSigningKey::new(b"cj-reconcile-webhook-key").expect("webhook key");
        let bytes = webhook_bytes(1);
        let envelope = signed_webhook(service.connector_scope(), &key, 1, &bytes);
        let observation = service
            .handle_webhook(envelope.clone(), &key, now())
            .expect("verified webhook");
        assert_eq!(observation.event_id(), envelope.event_id());
        assert_eq!(observation.payload_digest(), envelope.payload_digest());
        assert!(matches!(
            service.handle_webhook(envelope, &key, now()),
            Err(CjError::Connector(ConnectorError::WebhookReplay))
        ));
    }

    #[test]
    fn reconcile_closes_only_after_complete_evidence_and_consumes_mission_result() {
        let (_service, probe, first, second, mut session) = reconcile_fixture();
        let page_one = page_delivery(&session, &first, None);
        let page_two = page_delivery(&session, &second, page_one.next_cursor());
        session.accept_page(page_one, now()).expect("page one");
        session.accept_page(page_two, now()).expect("page two");
        let key = WebhookSigningKey::new(b"cj-reconcile-webhook-key").expect("webhook key");
        session
            .accept_webhook(webhook_delivery(&session, 1, &key), now())
            .expect("webhook one");
        assert_eq!(session.close_result(now()), Err(CjError::EvidenceRootOpen));
        session
            .accept_webhook(webhook_delivery(&session, 2, &key), now())
            .expect("webhook two");
        let result = session.close_result(now()).expect("closed result");
        assert_eq!(result.page_count, 2);
        assert_eq!(result.webhook_count, 2);
        assert_eq!(result.evidence_root.nodes().len(), 4);
        assert_eq!(
            result.evidence_root_digest,
            result.evidence_root.root_digest()
        );
        assert_eq!(result.generation_digest, session.generation().digest());

        let mission = Mission::compile(
            TenantId::from("tenant-cj"),
            MissionId::from("mission-cj-reconcile"),
            ProjectId::from("project-cj"),
            "Reconcile CJ delivery",
            MissionContract::bootstrap(
                "Reconcile CJ partner delivery",
                [CJ_RECONCILE_MISSION_CAPABILITY.to_owned()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        let expected = CjMissionReconcileExpectation {
            mission_id: mission.id.as_str().to_owned(),
            mission_revision: mission.revision,
            provider_id: CJ_PROVIDER_ID.to_owned(),
            publisher_id: scope().publisher_id().clone(),
            advertiser_id: scope().advertiser_id().clone(),
            program_id: CjProgramId::new("555").expect("program"),
            credential_revision: probe.credential_revision,
            probe_revision: probe.connector_result.probe_revision(),
            provider_generation: session.generation().provider_generation(),
            generation_digest: session.generation().digest().to_owned(),
            evidence_root_digest: result.evidence_root_digest.clone(),
        };
        let receipt = CjMissionReconcileConsumer
            .consume(&mission, session.scope(), &result, &expected, now())
            .expect("mission result");
        assert_eq!(receipt.result_digest, result.result_digest);
    }

    #[test]
    fn reconcile_checkpoint_reopens_and_revoke_invalidates_old_generation() {
        let (mut service, probe, first, _second, mut session) = reconcile_fixture();
        let page_one = page_delivery(&session, &first, None);
        session
            .accept_page(page_one.clone(), now())
            .expect("page one");
        let checkpoint = session.checkpoint().expect("checkpoint");
        let reopened = reconcile::CjReconcileSession::reopen(
            checkpoint.clone(),
            scope(),
            plan(),
            session.generation().clone(),
            service.reconcile_authority().clone(),
        )
        .expect("reopen");
        assert_eq!(reopened.next_page(), 2);
        service.revoke("reconcile-revoke", now()).expect("revoke");
        assert_eq!(reopened.checkpoint(), Err(CjError::GenerationDrift));
        assert!(matches!(
            reconcile::CjReconcileSession::reopen(
                checkpoint.clone(),
                scope(),
                plan(),
                session.generation().clone(),
                service.reconcile_authority().clone(),
            ),
            Err(CjError::GenerationDrift)
        ));

        let mut tampered_value = serde_json::to_value(&checkpoint).expect("checkpoint json");
        tampered_value["checkpointDigest"] = serde_json::Value::String(sha256_hex("tampered"));
        let tampered: reconcile::CjReconcileCheckpoint =
            serde_json::from_value(tampered_value).expect("tampered checkpoint");
        assert_eq!(tampered.validate(), Err(CjError::InvalidCheckpoint));
        let _ = probe;
    }

    #[test]
    fn reconcile_missing_source_tampered_digest_cursor_and_account_drift_fail_closed() {
        let (_service, _probe, first, second, session) = reconcile_fixture();
        let mut missing_source = first.clone();
        missing_source.envelope.data.payload.clear();
        assert!(matches!(
            CjPageDelivery::from_read(
                session.scope(),
                session.plan(),
                session.generation(),
                None,
                &missing_source,
                now(),
            ),
            Err(CjError::MissingSourceBytes | CjError::InvalidDelivery)
        ));

        let mut tampered_digest = first.clone();
        tampered_digest.envelope.data.payload.push_str("tampered");
        assert!(
            CjPageDelivery::from_read(
                session.scope(),
                session.plan(),
                session.generation(),
                None,
                &tampered_digest,
                now(),
            )
            .is_err()
        );

        let rollback_cursor = CjDurableCursor::new(
            session.plan(),
            session.scope().base(),
            session.query_digest(),
            1,
        )
        .expect("rollback cursor");
        assert_eq!(
            CjPageDelivery::from_read(
                session.scope(),
                session.plan(),
                session.generation(),
                Some(
                    &reconcile::CjReconcileCursor::from_durable(
                        rollback_cursor,
                        session.scope(),
                        session.plan(),
                        session.generation(),
                    )
                    .expect("reconcile cursor")
                ),
                &second,
                now(),
            ),
            Err(CjError::CursorRollback)
        );

        let drift_scope = CjReconcileScope::new(
            CjScope::new(
                "tenant-cj",
                "project-cj",
                CjPublisherId::new("12345").expect("publisher"),
                CjAdvertiserId::new("11111").expect("other advertiser"),
            )
            .expect("drift scope"),
            CjProgramId::new("555").expect("program"),
        )
        .expect("reconcile drift scope");
        assert!(matches!(
            CjPageDelivery::from_read(
                &drift_scope,
                session.plan(),
                session.generation(),
                None,
                &first,
                now(),
            ),
            Err(CjError::GenerationDrift)
        ));
    }
}
