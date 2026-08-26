//! Awin publisher-side authenticated read adapter.
//!
//! This module owns only Awin-native identities, request shapes, provider
//! transport, service registration, and the Mission read consumer.  It uses
//! the Connector SDK for authentication fencing, probe liveness, observation
//! binding, quota admission, and revocation; it does not recreate those SDK
//! contracts.

use std::collections::BTreeSet;
use std::fmt;
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
    SecretReference, VerificationObservation, VerifyRequest, WebhookObservation, WebhookRequest,
};
use hartevo_domain_kernel::Mission;
use hartevo_effect_broker::ProviderEvidenceSupport;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use ureq::Agent;
use url::form_urlencoded;
use zeroize::Zeroizing;

pub const AWIN_PROVIDER_ID: &str = "awin";
pub const AWIN_ADAPTER_ID: &str = "hartevo.awin";
pub const AWIN_ADAPTER_VERSION: u32 = 1;
pub const AWIN_SERVICE_ID: &str = "partner.awin.authenticated-read/v1";
pub const AWIN_MISSION_CAPABILITY: &str = "partner.awin.authenticated-read";
pub const AWIN_CONNECTION_CAPABILITY: &str = "connection.probe";
pub const AWIN_PROGRAMME_CAPABILITY: &str = "partner.programme.read";
pub const AWIN_TRANSACTION_CAPABILITY: &str = "partner.transaction.read";
pub const AWIN_REPORT_CAPABILITY: &str = "partner.report.read";
pub const AWIN_API_BASE_URL: &str = "https://api.awin.com";
pub const AWIN_MAX_WINDOW_DAYS: i64 = 31;
pub const AWIN_DEFAULT_FRESHNESS_SECONDS: i64 = 60;
pub const AWIN_RATE_LIMIT_PER_MINUTE: u64 = 20;

const AWIN_SCHEMA_VERSION: &str = "hartevo-awin-authenticated-read/v1";
const AWIN_ADAPTER_PROBE_TTL_SECONDS: i64 = 90;
const AWIN_READ_COST_UNITS: i64 = 1;

macro_rules! numeric_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, AwinError> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > 32
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || value.parse::<u64>().ok().is_none_or(|number| number == 0)
                {
                    return Err(AwinError::InvalidIdentity);
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

numeric_id!(AwinPublisherId);
numeric_id!(AwinAdvertiserId);
numeric_id!(AwinProgramId);

/// Awin account/program scope.  The publisher account is always required;
/// advertiser and programme identities narrow the same network relationship.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinScope {
    tenant_id: String,
    project_id: String,
    publisher_id: AwinPublisherId,
    advertiser_id: Option<AwinAdvertiserId>,
    program_id: Option<AwinProgramId>,
}

impl AwinScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        publisher_id: AwinPublisherId,
        advertiser_id: Option<AwinAdvertiserId>,
        program_id: Option<AwinProgramId>,
    ) -> Result<Self, AwinError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            publisher_id,
            advertiser_id,
            program_id,
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

    pub fn publisher_id(&self) -> &AwinPublisherId {
        &self.publisher_id
    }

    pub fn advertiser_id(&self) -> Option<&AwinAdvertiserId> {
        self.advertiser_id.as_ref()
    }

    pub fn program_id(&self) -> Option<&AwinProgramId> {
        self.program_id.as_ref()
    }

    pub fn connector_scope(&self) -> Result<ConnectorScope, AwinError> {
        let mut scopes = vec![
            AWIN_MISSION_CAPABILITY.to_owned(),
            AWIN_PROGRAMME_CAPABILITY.to_owned(),
            AWIN_TRANSACTION_CAPABILITY.to_owned(),
            AWIN_REPORT_CAPABILITY.to_owned(),
        ];
        if let Some(advertiser_id) = &self.advertiser_id {
            scopes.push(format!("advertiser:{}", advertiser_id.as_str()));
        }
        if let Some(program_id) = &self.program_id {
            scopes.push(format!("program:{}", program_id.as_str()));
        }
        ConnectorScope::new(
            self.tenant_id.clone(),
            self.project_id.clone(),
            AWIN_PROVIDER_ID,
            self.publisher_id.to_string(),
            scopes,
        )
        .map_err(AwinError::from)
    }

    pub fn digest(&self) -> Result<String, AwinError> {
        Ok(self.connector_scope()?.digest())
    }

    fn validate(&self) -> Result<(), AwinError> {
        if !valid_hartevo_identifier(&self.tenant_id)
            || !valid_hartevo_identifier(&self.project_id)
            || self
                .program_id
                .as_ref()
                .is_some_and(|_| self.advertiser_id.is_none())
        {
            return Err(AwinError::InvalidScope);
        }
        Ok(())
    }
}

/// The two network reads in this first layer plus the programme relationship
/// read used by the authenticated probe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwinReadResource {
    Programmes,
    Transactions,
    AdvertiserPerformanceReport,
}

impl AwinReadResource {
    pub const fn capability(self) -> &'static str {
        match self {
            Self::Programmes => AWIN_PROGRAMME_CAPABILITY,
            Self::Transactions => AWIN_TRANSACTION_CAPABILITY,
            Self::AdvertiserPerformanceReport => AWIN_REPORT_CAPABILITY,
        }
    }
}

/// A logical date-range plan.  Awin transaction reads document a maximum
/// 31-day range, so the adapter advances this plan by durable date windows
/// rather than inventing an undocumented provider page parameter.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinReadPlan {
    resource: AwinReadResource,
    start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    region: Option<String>,
}

impl AwinReadPlan {
    pub fn new(
        resource: AwinReadResource,
        start_at: DateTime<Utc>,
        end_at: DateTime<Utc>,
        region: Option<String>,
    ) -> Result<Self, AwinError> {
        let plan = Self {
            resource,
            start_at,
            end_at,
            region,
        };
        plan.validate()?;
        Ok(plan)
    }

    pub fn resource(&self) -> AwinReadResource {
        self.resource
    }

    pub const fn start_at(&self) -> DateTime<Utc> {
        self.start_at
    }

    pub const fn end_at(&self) -> DateTime<Utc> {
        self.end_at
    }

    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    pub fn query_digest(&self, scope: &AwinScope) -> Result<String, AwinError> {
        let scope_digest = scope.digest()?;
        Ok(digest_parts([
            AWIN_SCHEMA_VERSION,
            self.resource.capability(),
            &self.start_at.to_rfc3339(),
            &self.end_at.to_rfc3339(),
            self.region.as_deref().unwrap_or(""),
            scope_digest.as_str(),
        ]))
    }

    fn window_for(
        &self,
        completed_page_sequence: u64,
    ) -> Result<(DateTime<Utc>, DateTime<Utc>), AwinError> {
        let offset_days = completed_page_sequence
            .checked_mul(AWIN_MAX_WINDOW_DAYS as u64)
            .and_then(|days| i64::try_from(days).ok())
            .ok_or(AwinError::CursorDrift)?;
        let start_at = self
            .start_at
            .checked_add_signed(Duration::days(offset_days))
            .ok_or(AwinError::CursorDrift)?;
        if start_at >= self.end_at {
            return Err(AwinError::CursorDrift);
        }
        let candidate_end = start_at
            .checked_add_signed(Duration::days(AWIN_MAX_WINDOW_DAYS))
            .ok_or(AwinError::CursorDrift)?;
        Ok((start_at, candidate_end.min(self.end_at)))
    }

    fn validate(&self) -> Result<(), AwinError> {
        if self.end_at <= self.start_at
            || self.resource == AwinReadResource::AdvertiserPerformanceReport
                && !self.region.as_deref().is_some_and(valid_region)
            || self
                .region
                .as_deref()
                .is_some_and(|region| !valid_region(region))
        {
            return Err(AwinError::InvalidReadPlan);
        }
        Ok(())
    }
}

/// A serializable, scope/query-bound continuation.  The provider cursor is
/// represented by the next date window and a digest; no token or secret is
/// persisted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinDurableCursor {
    schema_version: String,
    resource: AwinReadResource,
    scope_digest: String,
    query_digest: String,
    next_start_at: DateTime<Utc>,
    end_at: DateTime<Utc>,
    sequence: u64,
    token_digest: String,
    cursor_digest: String,
}

impl AwinDurableCursor {
    fn new(
        plan: &AwinReadPlan,
        scope: &AwinScope,
        query_digest: &str,
        sequence: u64,
    ) -> Result<Self, AwinError> {
        if sequence == 0 {
            return Err(AwinError::CursorDrift);
        }
        let scope_digest = scope.digest()?;
        let (next_start_at, _) = plan.window_for(sequence)?;
        let token_digest = cursor_token_digest(plan, &scope_digest, query_digest, sequence);
        let cursor_digest = digest_parts([
            AWIN_SCHEMA_VERSION,
            &format!("{:?}", plan.resource),
            &scope_digest,
            query_digest,
            &next_start_at.to_rfc3339(),
            &plan.end_at.to_rfc3339(),
            &sequence.to_string(),
            &token_digest,
        ]);
        Ok(Self {
            schema_version: AWIN_SCHEMA_VERSION.to_owned(),
            resource: plan.resource,
            scope_digest,
            query_digest: query_digest.to_owned(),
            next_start_at,
            end_at: plan.end_at,
            sequence,
            token_digest,
            cursor_digest,
        })
    }

    pub fn resource(&self) -> AwinReadResource {
        self.resource
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn next_start_at(&self) -> DateTime<Utc> {
        self.next_start_at
    }

    pub const fn end_at(&self) -> DateTime<Utc> {
        self.end_at
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn token_digest(&self) -> &str {
        &self.token_digest
    }

    pub fn cursor_digest(&self) -> &str {
        &self.cursor_digest
    }

    pub fn to_sdk_cursor(&self, scope: &ConnectorScope) -> Result<Cursor, AwinError> {
        if self.scope_digest != scope.digest()
            || self.schema_version != AWIN_SCHEMA_VERSION
            || !is_sha256(&self.query_digest)
            || !is_sha256(&self.token_digest)
            || !is_sha256(&self.cursor_digest)
            || self.cursor_digest != self.calculated_cursor_digest()
        {
            return Err(AwinError::CursorDrift);
        }
        Cursor::new(
            scope,
            self.query_digest.clone(),
            self.sequence,
            self.token_digest.clone(),
        )
        .map_err(AwinError::from)
    }

    fn validate_against(
        &self,
        plan: &AwinReadPlan,
        scope: &AwinScope,
        query_digest: &str,
    ) -> Result<(), AwinError> {
        if self.resource != plan.resource
            || self.scope_digest != scope.digest()?
            || self.query_digest != query_digest
            || self.end_at != plan.end_at
            || self.sequence == 0
            || self.next_start_at != plan.window_for(self.sequence)?.0
            || self.token_digest
                != cursor_token_digest(plan, &self.scope_digest, query_digest, self.sequence)
            || self.cursor_digest != self.calculated_cursor_digest()
        {
            return Err(AwinError::CursorDrift);
        }
        Ok(())
    }

    fn calculated_cursor_digest(&self) -> String {
        digest_parts([
            AWIN_SCHEMA_VERSION,
            &format!("{:?}", self.resource),
            &self.scope_digest,
            &self.query_digest,
            &self.next_start_at.to_rfc3339(),
            &self.end_at.to_rfc3339(),
            &self.sequence.to_string(),
            &self.token_digest,
        ])
    }
}

/// Local admission state layered on the Connector SDK budget.  Awin's API
/// does not charge Hartevo money per request, so `cost_units` is an explicit
/// internal quota/cost boundary rather than a fabricated settlement amount.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinBudget {
    rate_remaining: u64,
    rate_reset_at: DateTime<Utc>,
    quota_limit: u64,
    quota_used: u64,
    cost_limit_units: i64,
    cost_used_units: i64,
}

impl AwinBudget {
    pub fn new(
        rate_remaining: u64,
        rate_reset_at: DateTime<Utc>,
        quota_limit: u64,
        cost_limit_units: i64,
    ) -> Result<Self, AwinError> {
        if cost_limit_units < 0 {
            return Err(AwinError::InvalidBudget);
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

    pub fn rate_remaining(&self) -> u64 {
        self.rate_remaining
    }

    pub const fn rate_reset_at(&self) -> DateTime<Utc> {
        self.rate_reset_at
    }

    pub const fn quota_limit(&self) -> u64 {
        self.quota_limit
    }

    pub const fn quota_used(&self) -> u64 {
        self.quota_used
    }

    pub const fn cost_limit_units(&self) -> i64 {
        self.cost_limit_units
    }

    pub const fn cost_used_units(&self) -> i64 {
        self.cost_used_units
    }

    fn admit(&mut self, at: DateTime<Utc>, cost_units: i64) -> Result<(), AwinError> {
        if at >= self.rate_reset_at && self.rate_remaining == 0 {
            self.rate_remaining = AWIN_RATE_LIMIT_PER_MINUTE;
        }
        if self.rate_remaining == 0 {
            return Err(AwinError::RateLimited);
        }
        if self.quota_used >= self.quota_limit {
            return Err(AwinError::QuotaExceeded);
        }
        if cost_units < 0
            || self
                .cost_used_units
                .checked_add(cost_units)
                .is_none_or(|total| total > self.cost_limit_units)
        {
            return Err(AwinError::CostLimitExceeded);
        }
        self.rate_remaining -= 1;
        self.quota_used += 1;
        self.cost_used_units += cost_units;
        Ok(())
    }
}

/// Redacted bearer credential.  Only the provider transport can access the
/// token bytes; a `SecretReference` remains the identity used by the SDK.
pub struct AwinAccessToken(Zeroizing<String>);

impl Clone for AwinAccessToken {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.to_string()))
    }
}

impl fmt::Debug for AwinAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AwinAccessToken(REDACTED)")
    }
}

impl AwinAccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, AwinError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(AwinError::InvalidCredential);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// The only credential lookup seam.  Production code must provide a real
/// keyring-backed implementation; the default resolver intentionally returns
/// `BLOCKED_ENV` and never claims a connected network.
pub trait AwinCredentialResolver: Send {
    fn resolve(
        &mut self,
        reference: &SecretReference,
        scope: &AwinScope,
        at: DateTime<Utc>,
    ) -> Result<AwinAccessToken, AwinProviderError>;
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvAwinCredentialResolver;

impl AwinCredentialResolver for BlockedEnvAwinCredentialResolver {
    fn resolve(
        &mut self,
        _reference: &SecretReference,
        _scope: &AwinScope,
        _at: DateTime<Utc>,
    ) -> Result<AwinAccessToken, AwinProviderError> {
        Err(AwinProviderError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwinProbeStatus {
    Reachable,
    Disconnected,
    Rejected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwinObservationClassification {
    FirstParty,
    Disconnected,
    BlockedEnv,
    CredentialExpired,
    CredentialRevoked,
    RateLimited,
    ScopeDrift,
    CursorDrift,
    Fixture,
    ProviderRejected,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwinProviderError {
    #[error("BLOCKED_ENV: Awin credential is not available in the configured secret store")]
    BlockedEnv,
    #[error("Awin credential is expired")]
    CredentialExpired,
    #[error("Awin credential was revoked")]
    CredentialRevoked,
    #[error("Awin provider rate limit is exhausted")]
    RateLimited,
    #[error("Awin response scope drifted from the requested account/program")]
    ScopeDrift,
    #[error("Awin cursor drifted from the durable request")]
    CursorDrift,
    #[error("Awin returned HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("Awin returned an invalid JSON response")]
    InvalidResponse,
    #[error("Awin transport failed")]
    Transport,
}

/// Provider-native probe request.  It is deliberately narrower than the SDK
/// `ProbeRequest` and never carries secret material.
#[derive(Clone, Debug)]
pub struct AwinProbeRequest {
    pub scope: AwinScope,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AwinProbeResponse {
    pub publisher_id: AwinPublisherId,
    pub advertiser_ids: BTreeSet<AwinAdvertiserId>,
    pub source_uri: String,
    pub source_digest: String,
    pub source_revision: u64,
    pub observed_at: DateTime<Utc>,
}

/// Provider-native read request.  The date window is the official Awin API
/// query boundary; `page_size` remains the SDK observation bound.
#[derive(Clone, Debug)]
pub struct AwinProviderReadRequest {
    pub scope: AwinScope,
    pub resource: AwinReadResource,
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
    pub region: Option<String>,
    pub page_size: u32,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinProviderPage {
    pub resource: AwinReadResource,
    pub publisher_id: Option<AwinPublisherId>,
    pub advertiser_ids: BTreeSet<AwinAdvertiserId>,
    pub source_uri: String,
    pub source_digest: String,
    pub source_revision: u64,
    pub observed_at: DateTime<Utc>,
    pub payload: Value,
}

/// Awin-specific network transport.  The real HTTP implementation is the
/// only production provenance; fixture transports belong in contract tests.
pub trait AwinTransport: Send {
    fn provenance_class(&self) -> ProviderProvenanceClass;

    fn probe(
        &mut self,
        token: &AwinAccessToken,
        request: &AwinProbeRequest,
    ) -> Result<AwinProbeResponse, AwinProviderError>;

    fn read(
        &mut self,
        token: &AwinAccessToken,
        request: &AwinProviderReadRequest,
    ) -> Result<AwinProviderPage, AwinProviderError>;
}

/// Official Awin REST transport.  It uses the documented Bearer header and
/// publisher-side endpoints only.
pub struct AwinHttpTransport {
    base_url: String,
    agent: Agent,
}

impl fmt::Debug for AwinHttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwinHttpTransport")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl AwinHttpTransport {
    pub fn official() -> Self {
        Self {
            base_url: AWIN_API_BASE_URL.to_owned(),
            agent: Agent::new(),
        }
    }

    pub fn new(base_url: impl Into<String>) -> Result<Self, AwinError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if !base_url.starts_with("https://") || base_url.contains('?') {
            return Err(AwinError::InvalidTransportBaseUrl);
        }
        Ok(Self {
            base_url,
            agent: Agent::new(),
        })
    }

    fn get_json(
        &self,
        token: &AwinAccessToken,
        path: &str,
        query: Vec<(String, String)>,
    ) -> Result<(String, Value), AwinProviderError> {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in query {
            serializer.append_pair(&key, &value);
        }
        let query = serializer.finish();
        let url = if query.is_empty() {
            format!("{}{}", self.base_url, path)
        } else {
            format!("{}{}?{}", self.base_url, path, query)
        };
        let response = self
            .agent
            .get(&url)
            .set("Authorization", &format!("Bearer {}", token.as_str()))
            .set("Accept", "application/json")
            .call()
            .map_err(|error| match error {
                ureq::Error::Status(status, response) => AwinProviderError::HttpStatus {
                    status,
                    retry_after_seconds: response
                        .header("Retry-After")
                        .and_then(|value| value.parse::<u64>().ok()),
                },
                ureq::Error::Transport(_) => AwinProviderError::Transport,
            })?;
        let body = response
            .into_string()
            .map_err(|_| AwinProviderError::Transport)?;
        let value =
            serde_json::from_str::<Value>(&body).map_err(|_| AwinProviderError::InvalidResponse)?;
        Ok((body, value))
    }

    fn probe_endpoint(
        &self,
        token: &AwinAccessToken,
        request: &AwinProbeRequest,
    ) -> Result<AwinProbeResponse, AwinProviderError> {
        let publisher_id = request.scope.publisher_id().clone();
        let (path, query) = if let Some(advertiser_id) = request.scope.advertiser_id() {
            (
                format!("/publishers/{publisher_id}/programmedetails"),
                vec![
                    ("advertiserId".to_owned(), advertiser_id.to_string()),
                    ("relationship".to_owned(), "any".to_owned()),
                ],
            )
        } else {
            (
                format!("/publishers/{publisher_id}/programmes"),
                vec![("relationship".to_owned(), "joined".to_owned())],
            )
        };
        let (body, value) = self.get_json(token, &path, query)?;
        let advertiser_ids = extract_ids(&value, &["advertiserId", "advertiser_id"])?;
        if request
            .scope
            .advertiser_id()
            .is_some_and(|advertiser| !advertiser_ids.contains(advertiser))
        {
            return Err(AwinProviderError::ScopeDrift);
        }
        Ok(AwinProbeResponse {
            publisher_id,
            advertiser_ids,
            source_uri: format!("{}{}", self.base_url, path),
            source_digest: sha256_hex(&body),
            source_revision: revision_from_digest(&sha256_hex(&body)),
            observed_at: request.observed_at,
        })
    }
}

impl AwinTransport for AwinHttpTransport {
    fn provenance_class(&self) -> ProviderProvenanceClass {
        ProviderProvenanceClass::ProductionProvider
    }

    fn probe(
        &mut self,
        token: &AwinAccessToken,
        request: &AwinProbeRequest,
    ) -> Result<AwinProbeResponse, AwinProviderError> {
        self.probe_endpoint(token, request)
    }

    fn read(
        &mut self,
        token: &AwinAccessToken,
        request: &AwinProviderReadRequest,
    ) -> Result<AwinProviderPage, AwinProviderError> {
        let publisher_id = request.scope.publisher_id().clone();
        let mut query = Vec::new();
        let path = match request.resource {
            AwinReadResource::Programmes => {
                query.push(("relationship".to_owned(), "joined".to_owned()));
                format!("/publishers/{publisher_id}/programmes")
            }
            AwinReadResource::Transactions => {
                query.extend([
                    ("startDate".to_owned(), request.start_at.to_rfc3339()),
                    ("endDate".to_owned(), request.end_at.to_rfc3339()),
                    ("timezone".to_owned(), "UTC".to_owned()),
                    ("showBasketProducts".to_owned(), "false".to_owned()),
                ]);
                if let Some(advertiser_id) = request.scope.advertiser_id() {
                    query.push(("advertiserId".to_owned(), advertiser_id.to_string()));
                }
                format!("/publishers/{publisher_id}/transactions/")
            }
            AwinReadResource::AdvertiserPerformanceReport => {
                query.extend([
                    (
                        "startDate".to_owned(),
                        request.start_at.format("%Y-%m-%d").to_string(),
                    ),
                    (
                        "endDate".to_owned(),
                        request.end_at.format("%Y-%m-%d").to_string(),
                    ),
                    (
                        "region".to_owned(),
                        request.region.as_deref().unwrap_or("GB").to_owned(),
                    ),
                    ("timezone".to_owned(), "UTC".to_owned()),
                ]);
                format!("/publishers/{publisher_id}/reports/advertiser")
            }
        };
        let (body, value) = self.get_json(token, &path, query)?;
        let source_digest = sha256_hex(&body);
        let advertiser_ids = extract_ids(&value, &["advertiserId", "advertiser_id"])?;
        if request
            .scope
            .advertiser_id()
            .is_some_and(|advertiser| !advertiser_ids.contains(advertiser))
        {
            return Err(AwinProviderError::ScopeDrift);
        }
        Ok(AwinProviderPage {
            resource: request.resource,
            publisher_id: Some(publisher_id),
            advertiser_ids,
            source_uri: format!("{}{}", self.base_url, path),
            source_digest: source_digest.clone(),
            source_revision: revision_from_digest(&source_digest),
            observed_at: request.observed_at,
            payload: value,
        })
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AwinError {
    #[error("Awin identity is invalid")]
    InvalidIdentity,
    #[error("Awin scope is invalid")]
    InvalidScope,
    #[error("Awin read plan is invalid")]
    InvalidReadPlan,
    #[error("Awin budget is invalid")]
    InvalidBudget,
    #[error("Awin credential is invalid")]
    InvalidCredential,
    #[error("Awin transport base URL is invalid")]
    InvalidTransportBaseUrl,
    #[error("Awin service is not authenticated")]
    MissingAuthentication,
    #[error("Awin service is disconnected or the probe is not live")]
    Disconnected,
    #[error("Awin service is revoked")]
    Revoked,
    #[error("Awin service is unmounted")]
    Unmounted,
    #[error("Awin cursor drifted from the exact scope/query")]
    CursorDrift,
    #[error("Awin quota is exhausted")]
    QuotaExceeded,
    #[error("Awin cost boundary is exhausted")]
    CostLimitExceeded,
    #[error("Awin provider is rate limited")]
    RateLimited,
    #[error("Awin provider rejected the request")]
    ProviderRejected,
    #[error("Awin Mission consumer rejected the exact binding")]
    MissionBinding,
    #[error("Awin service state is poisoned")]
    StatePoisoned,
    #[error("Connector SDK error: {0}")]
    Connector(#[from] ConnectorError),
    #[error("Awin provider error: {0}")]
    Provider(#[from] AwinProviderError),
    #[error("provider contract error: {0}")]
    ProviderContract(String),
    #[error("Mission error: {0}")]
    Mission(String),
}

impl From<hartevo_effect_broker::ProviderContractError> for AwinError {
    fn from(error: hartevo_effect_broker::ProviderContractError) -> Self {
        Self::ProviderContract(error.to_string())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinProbeObservation {
    pub status: AwinProbeStatus,
    pub classification: AwinObservationClassification,
    pub provider_id: String,
    pub publisher_id: AwinPublisherId,
    pub advertiser_id: Option<AwinAdvertiserId>,
    pub program_id: Option<AwinProgramId>,
    pub credential_revision: u64,
    pub source_revision: Option<u64>,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub source_uri: String,
    pub source_digest: String,
    pub evidence_digest: String,
}

impl AwinProbeObservation {
    fn reachable(
        scope: &AwinScope,
        credential_revision: u64,
        response: &AwinProbeResponse,
        provenance: ProviderProvenanceClass,
    ) -> Self {
        let valid_until = response
            .observed_at
            .checked_add_signed(Duration::seconds(AWIN_ADAPTER_PROBE_TTL_SECONDS))
            .unwrap_or(response.observed_at);
        let evidence_digest = digest_parts([
            AWIN_SCHEMA_VERSION,
            AWIN_PROVIDER_ID,
            scope.publisher_id().as_str(),
            scope.advertiser_id().map_or("", AwinAdvertiserId::as_str),
            scope.program_id().map_or("", AwinProgramId::as_str),
            &credential_revision.to_string(),
            &response.source_revision.to_string(),
            &format!("{provenance:?}"),
            response.source_digest.as_str(),
        ]);
        Self {
            status: AwinProbeStatus::Reachable,
            classification: if provenance == ProviderProvenanceClass::ProductionProvider {
                AwinObservationClassification::FirstParty
            } else {
                AwinObservationClassification::Fixture
            },
            provider_id: AWIN_PROVIDER_ID.to_owned(),
            publisher_id: response.publisher_id.clone(),
            advertiser_id: scope.advertiser_id().cloned(),
            program_id: scope.program_id().cloned(),
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
        scope: &AwinScope,
        credential_revision: u64,
        at: DateTime<Utc>,
        error: &AwinProviderError,
        provenance: ProviderProvenanceClass,
    ) -> Self {
        let classification = match error {
            AwinProviderError::BlockedEnv => AwinObservationClassification::BlockedEnv,
            AwinProviderError::CredentialExpired => {
                AwinObservationClassification::CredentialExpired
            }
            AwinProviderError::CredentialRevoked => {
                AwinObservationClassification::CredentialRevoked
            }
            AwinProviderError::RateLimited => AwinObservationClassification::RateLimited,
            AwinProviderError::ScopeDrift => AwinObservationClassification::ScopeDrift,
            AwinProviderError::CursorDrift => AwinObservationClassification::CursorDrift,
            AwinProviderError::Transport => AwinObservationClassification::Disconnected,
            AwinProviderError::HttpStatus { status: 429, .. } => {
                AwinObservationClassification::RateLimited
            }
            AwinProviderError::HttpStatus { status, .. } if *status == 401 || *status == 403 => {
                AwinObservationClassification::CredentialRevoked
            }
            _ => AwinObservationClassification::ProviderRejected,
        };
        let source_digest = sha256_hex(&error.to_string());
        let evidence_digest = digest_parts([
            AWIN_SCHEMA_VERSION,
            AWIN_PROVIDER_ID,
            scope.publisher_id().as_str(),
            &credential_revision.to_string(),
            &format!("{classification:?}"),
            &format!("{provenance:?}"),
            &source_digest,
        ]);
        let valid_until = at
            .checked_add_signed(Duration::seconds(60))
            .unwrap_or(at + Duration::seconds(1));
        Self {
            status: AwinProbeStatus::Rejected,
            classification,
            provider_id: AWIN_PROVIDER_ID.to_owned(),
            publisher_id: scope.publisher_id().clone(),
            advertiser_id: scope.advertiser_id().cloned(),
            program_id: scope.program_id().cloned(),
            credential_revision,
            source_revision: None,
            observed_at: at,
            valid_until,
            source_uri: "awin://rejected".to_owned(),
            source_digest,
            evidence_digest,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinReadData {
    pub resource: AwinReadResource,
    pub record_count: u32,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinCostReceipt {
    pub cost_units: i64,
    pub rate_remaining: u64,
    pub quota_remaining: u64,
    pub cost_remaining_units: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinResultEnvelope {
    pub schema_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub publisher_id: AwinPublisherId,
    pub advertiser_id: Option<AwinAdvertiserId>,
    pub program_id: Option<AwinProgramId>,
    pub resource: AwinReadResource,
    pub scope_digest: String,
    pub query_digest: String,
    pub credential_revision: u64,
    pub source_revision: u64,
    pub observed_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub source_uri: String,
    pub source_digest: String,
    pub content_digest: String,
    pub classification: AwinObservationClassification,
    pub cursor: Option<AwinDurableCursor>,
    pub cost: AwinCostReceipt,
    pub data: AwinReadData,
    pub result_digest: String,
}

#[derive(Clone, Debug)]
pub struct AwinProbeReceipt {
    pub connector_result: ProbeResult,
    pub observation: AwinProbeObservation,
    pub credential_revision: u64,
}

#[derive(Clone, Debug)]
pub struct AwinReadResult {
    pub connector_observation: ReadObservation,
    pub envelope: AwinResultEnvelope,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinLifecycleReceipt {
    pub service_id: String,
    pub provider_id: String,
    pub scope_digest: String,
    pub action: String,
    pub at: DateTime<Utc>,
    pub receipt_digest: String,
}

#[derive(Debug)]
struct ActiveAwinCredential {
    credential_revision: u64,
    token: AwinAccessToken,
}

#[derive(Debug, Default)]
struct AwinAdapterState {
    active_credential: Option<ActiveAwinCredential>,
    last_probe: Option<AwinProbeObservation>,
    last_page: Option<AwinProviderPage>,
    revoked: bool,
}

#[derive(Clone, Debug)]
pub struct AwinServiceDefinition {
    pub schema_version: &'static str,
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub adapter: ProviderAdapterIdentity,
    pub capabilities: BTreeSet<String>,
}

impl AwinServiceDefinition {
    pub fn new() -> Result<Self, AwinError> {
        let adapter = ProviderAdapterIdentity::new(AWIN_ADAPTER_ID, AWIN_ADAPTER_VERSION)
            .map_err(|error| AwinError::ProviderContract(error.to_string()))?;
        Ok(Self {
            schema_version: AWIN_SCHEMA_VERSION,
            service_id: AWIN_SERVICE_ID,
            provider_id: AWIN_PROVIDER_ID,
            adapter,
            capabilities: [
                AWIN_MISSION_CAPABILITY,
                AWIN_PROGRAMME_CAPABILITY,
                AWIN_TRANSACTION_CAPABILITY,
                AWIN_REPORT_CAPABILITY,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        })
    }

    pub fn registry(&self) -> Result<ProviderAdapterRegistry, AwinError> {
        let registrations = [
            (AWIN_CONNECTION_CAPABILITY, ProviderAdapterOperation::Probe),
            (AWIN_PROGRAMME_CAPABILITY, ProviderAdapterOperation::Read),
            (AWIN_TRANSACTION_CAPABILITY, ProviderAdapterOperation::Read),
            (AWIN_REPORT_CAPABILITY, ProviderAdapterOperation::Read),
        ]
        .into_iter()
        .map(|(capability, operation)| {
            let key = ProviderCapabilityKey::new(AWIN_PROVIDER_ID, capability)
                .map_err(|error| AwinError::ProviderContract(error.to_string()))?;
            let evidence_class = match operation {
                ProviderAdapterOperation::Probe => ProviderEvidenceClass::ProbeObservation,
                ProviderAdapterOperation::Read => ProviderEvidenceClass::ReadObservation,
                _ => unreachable!("Awin read registry only declares probe/read"),
            };
            let evidence = ProviderEvidenceSupport::new(
                operation,
                evidence_class,
                ProviderProvenanceClass::ProductionProvider,
            )
            .map_err(|error| AwinError::ProviderContract(error.to_string()))?;
            ProviderCapabilitySupport::new(key, self.adapter.clone(), [evidence])
                .map_err(|error| AwinError::ProviderContract(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
        ProviderAdapterRegistry::new("awin-authenticated-read-01", registrations)
            .map_err(|error| AwinError::ProviderContract(error.to_string()))
    }
}

pub struct AwinConnectorAdapter<T, C>
where
    T: AwinTransport,
    C: AwinCredentialResolver,
{
    descriptor: ConnectorDescriptor,
    scope: AwinScope,
    connector_scope: ConnectorScope,
    plan: AwinReadPlan,
    transport: T,
    credentials: C,
    state: Arc<Mutex<AwinAdapterState>>,
}

impl<T, C> fmt::Debug for AwinConnectorAdapter<T, C>
where
    T: AwinTransport,
    C: AwinCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwinConnectorAdapter")
            .field("adapter", self.descriptor.identity())
            .field("scope_digest", &self.connector_scope.digest())
            .field("resource", &self.plan.resource)
            .finish_non_exhaustive()
    }
}

impl<T, C> AwinConnectorAdapter<T, C>
where
    T: AwinTransport,
    C: AwinCredentialResolver,
{
    fn new(
        scope: AwinScope,
        plan: AwinReadPlan,
        transport: T,
        credentials: C,
        state: Arc<Mutex<AwinAdapterState>>,
    ) -> Result<Self, AwinError> {
        let definition = AwinServiceDefinition::new()?;
        let connector_scope = scope.connector_scope()?;
        let descriptor = ConnectorDescriptor::new(
            definition.adapter.clone(),
            definition.registry()?.registrations().iter().cloned(),
        )
        .map_err(AwinError::from)?;
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

    fn state(&self) -> Result<std::sync::MutexGuard<'_, AwinAdapterState>, ConnectorError> {
        self.state
            .lock()
            .map_err(|_| ConnectorError::ProviderRejected)
    }

    fn provider_rejection(
        &self,
        error: &AwinProviderError,
        credential_revision: u64,
        at: DateTime<Utc>,
    ) -> Result<ProbeObservation, ConnectorError> {
        let observation = AwinProbeObservation::rejected(
            &self.scope,
            credential_revision,
            at,
            error,
            self.transport.provenance_class(),
        );
        let provenance = if matches!(error, AwinProviderError::BlockedEnv) {
            ProviderProvenanceClass::ComponentHarness
        } else {
            self.transport.provenance_class()
        };
        self.state()?.last_probe = Some(observation.clone());
        ProbeObservation::new(
            ProbeStatus::Rejected,
            provenance,
            observation.observed_at,
            observation.valid_until,
            observation.evidence_digest,
        )
    }

    fn validate_probe_response(
        &self,
        response: &AwinProbeResponse,
    ) -> Result<(), AwinProviderError> {
        if response.publisher_id != *self.scope.publisher_id()
            || self
                .scope
                .advertiser_id()
                .is_some_and(|advertiser| !response.advertiser_ids.contains(advertiser))
        {
            return Err(AwinProviderError::ScopeDrift);
        }
        Ok(())
    }

    fn validate_page(&self, page: &AwinProviderPage) -> Result<(), AwinProviderError> {
        if page.publisher_id.as_ref() != Some(self.scope.publisher_id())
            || page.resource != self.plan.resource
            || self
                .scope
                .advertiser_id()
                .is_some_and(|advertiser| !page.advertiser_ids.contains(advertiser))
        {
            return Err(AwinProviderError::ScopeDrift);
        }
        if !is_sha256(&page.source_digest) || page.source_revision == 0 {
            return Err(AwinProviderError::InvalidResponse);
        }
        Ok(())
    }
}

impl<T, C> ConnectorAdapter for AwinConnectorAdapter<T, C>
where
    T: AwinTransport,
    C: AwinCredentialResolver,
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
            format!("auth-session-awin-{}", request.auth_revision),
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
            format!("auth-session-awin-refresh-{}", request.auth_revision),
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
        let probe_request = AwinProbeRequest {
            scope: self.scope.clone(),
            observed_at: request.at,
        };
        let response = match self.transport.probe(&token, &probe_request) {
            Ok(response) => response,
            Err(error) => return self.provider_rejection(&error, credential_revision, request.at),
        };
        if let Err(error) = self.validate_probe_response(&response) {
            return self.provider_rejection(&error, credential_revision, request.at);
        }
        let observation = AwinProbeObservation::reachable(
            &self.scope,
            credential_revision,
            &response,
            self.transport.provenance_class(),
        );
        self.state()?.active_credential = Some(ActiveAwinCredential {
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
        let (token, credential_revision, revoked) = {
            let state = self.state()?;
            let Some(active) = &state.active_credential else {
                return Err(ConnectorError::ProviderRejected);
            };
            (
                active.token.clone(),
                active.credential_revision,
                state.revoked,
            )
        };
        if revoked {
            return Err(ConnectorError::ProviderRejected);
        }
        let completed_page_sequence = request.cursor.as_ref().map_or(0, Cursor::sequence);
        if let Some(cursor) = &request.cursor
            && (cursor.scope_digest() != self.connector_scope.digest()
                || cursor.request_digest() != request.query_digest
                || cursor.token_digest()
                    != cursor_token_digest(
                        &self.plan,
                        cursor.scope_digest(),
                        &request.query_digest,
                        completed_page_sequence,
                    ))
        {
            return Err(ConnectorError::CursorMismatch);
        }
        let (start_at, end_at) = self
            .plan
            .window_for(completed_page_sequence)
            .map_err(|_| ConnectorError::CursorMismatch)?;
        let provider_request = AwinProviderReadRequest {
            scope: self.scope.clone(),
            resource: self.plan.resource,
            start_at,
            end_at,
            region: self.plan.region().map(str::to_owned),
            page_size: request.page_size,
            observed_at: request.at,
        };
        let page = self
            .transport
            .read(&token, &provider_request)
            .map_err(|error| match error {
                AwinProviderError::RateLimited
                | AwinProviderError::HttpStatus { status: 429, .. } => ConnectorError::RateLimited,
                AwinProviderError::CursorDrift => ConnectorError::CursorMismatch,
                AwinProviderError::ScopeDrift => ConnectorError::ScopeMismatch,
                _ => ConnectorError::ProviderRejected,
            })?;
        self.validate_page(&page)
            .map_err(|_| ConnectorError::ProviderRejected)?;
        let page_sequence = completed_page_sequence.saturating_add(1);
        let freshness = FreshnessWindow::new(
            request.at,
            request.at + Duration::seconds(AWIN_DEFAULT_FRESHNESS_SECONDS),
            page.source_revision,
        )?;
        let next_cursor = if end_at < self.plan.end_at {
            Some(
                AwinDurableCursor::new(
                    &self.plan,
                    &self.scope,
                    &request.query_digest,
                    page_sequence,
                )
                .map_err(|_| ConnectorError::CursorMismatch)?
                .to_sdk_cursor(&self.connector_scope)
                .map_err(|_| ConnectorError::CursorMismatch)?,
            )
        } else {
            None
        };
        let content_digest = sha256_json(&page.payload);
        let observation = ReadObservation::new(
            format!(
                "read-observation-awin-{}-{}",
                &page.source_digest[..12],
                page_sequence
            ),
            self.connector_scope.clone(),
            request.capability,
            self.descriptor.identity().clone(),
            request.query_digest,
            page.source_digest.clone(),
            content_digest,
            self.transport.provenance_class(),
            freshness,
            page_sequence,
            value_record_count(&page.payload),
            next_cursor,
        )?;
        self.state()?.last_page = Some(page);
        let _ = credential_revision;
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
        _request: WebhookRequest,
    ) -> Result<WebhookObservation, ConnectorError> {
        Err(ConnectorError::ProviderRejected)
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

pub struct AwinService<T, C>
where
    T: AwinTransport,
    C: AwinCredentialResolver,
{
    definition: AwinServiceDefinition,
    scope: AwinScope,
    connector_scope: ConnectorScope,
    plan: AwinReadPlan,
    query_digest: String,
    state: Arc<Mutex<AwinAdapterState>>,
    worker: ConnectorWorker<AwinConnectorAdapter<T, C>>,
    budget: AwinBudget,
    secret_reference: Option<SecretReference>,
    credential_lease: Option<CredentialLease>,
    auth_session: Option<AuthSession>,
    probe_result: Option<ProbeResult>,
    mounted: bool,
}

impl<T, C> fmt::Debug for AwinService<T, C>
where
    T: AwinTransport,
    C: AwinCredentialResolver,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwinService")
            .field("service_id", &self.definition.service_id)
            .field("scope_digest", &self.connector_scope.digest())
            .field("resource", &self.plan.resource)
            .field("mounted", &self.mounted)
            .finish_non_exhaustive()
    }
}

impl<T, C> AwinService<T, C>
where
    T: AwinTransport,
    C: AwinCredentialResolver,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_id: impl Into<String>,
        scope: AwinScope,
        plan: AwinReadPlan,
        transport: T,
        credentials: C,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
        budget: AwinBudget,
    ) -> Result<Self, AwinError> {
        let definition = AwinServiceDefinition::new()?;
        let connector_scope = scope.connector_scope()?;
        let query_digest = plan.query_digest(&scope)?;
        let state = Arc::new(Mutex::new(AwinAdapterState::default()));
        let adapter = AwinConnectorAdapter::new(
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
        .map_err(AwinError::from)?;
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
            mounted: true,
        })
    }

    pub fn definition(&self) -> &AwinServiceDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &AwinScope {
        &self.scope
    }

    pub fn connector_scope(&self) -> &ConnectorScope {
        &self.connector_scope
    }

    pub fn plan(&self) -> &AwinReadPlan {
        &self.plan
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub fn budget(&self) -> &AwinBudget {
        &self.budget
    }

    pub fn begin_auth(
        &mut self,
        secret_reference: SecretReference,
        credential_lease: CredentialLease,
        auth_revision: u64,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<AuthSession, AwinError> {
        self.ensure_mounted()?;
        if secret_reference.scope() != &self.connector_scope
            || credential_lease.scope() != &self.connector_scope
        {
            return Err(AwinError::Connector(ConnectorError::ScopeMismatch));
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
        self.secret_reference = Some(secret_reference);
        self.credential_lease = Some(credential_lease);
        self.auth_session = Some(session.clone());
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
    ) -> Result<AuthSession, AwinError> {
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
        self.secret_reference = Some(secret_reference);
        self.credential_lease = Some(credential_lease);
        self.auth_session = Some(refreshed.clone());
        Ok(refreshed)
    }

    pub fn probe(
        &mut self,
        probe_revision: u64,
        result_id: impl Into<String>,
        at: DateTime<Utc>,
    ) -> Result<AwinProbeReceipt, AwinError> {
        self.ensure_mounted()?;
        let secret_reference = self
            .secret_reference
            .clone()
            .ok_or(AwinError::MissingAuthentication)?;
        let credential_lease = self
            .credential_lease
            .clone()
            .ok_or(AwinError::MissingAuthentication)?;
        let session = self
            .auth_session
            .clone()
            .ok_or(AwinError::MissingAuthentication)?;
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
            .map_err(|_| AwinError::StatePoisoned)?
            .last_probe
            .clone()
            .ok_or(AwinError::Disconnected)?;
        self.probe_result = Some(connector_result.clone());
        Ok(AwinProbeReceipt {
            credential_revision: observation.credential_revision,
            connector_result,
            observation,
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn read(
        &mut self,
        cursor: Option<&AwinDurableCursor>,
        page_size: u32,
        at: DateTime<Utc>,
    ) -> Result<AwinReadResult, AwinError> {
        self.ensure_mounted()?;
        let probe = self.probe_result.as_ref().ok_or(AwinError::Disconnected)?;
        let live_probe = self
            .worker
            .authorize_probe(probe, at)
            .map_err(|error| match error {
                ConnectorError::ProbeNotLive | ConnectorError::UnsupportedProvenance => {
                    AwinError::Disconnected
                }
                other => AwinError::Connector(other),
            })?;
        let sdk_cursor = if let Some(cursor) = &cursor {
            cursor.validate_against(&self.plan, &self.scope, &self.query_digest)?;
            Some(cursor.to_sdk_cursor(&self.connector_scope)?)
        } else {
            None
        };
        self.budget.admit(at, AWIN_READ_COST_UNITS)?;
        let sdk_budget =
            DispatchBudget::new(1, at + Duration::seconds(1), 1, 0).map_err(AwinError::from)?;
        let capability =
            ProviderCapabilityKey::new(AWIN_PROVIDER_ID, self.plan.resource.capability())
                .map_err(|error| AwinError::ProviderContract(error.to_string()))?;
        let connector_observation = self
            .worker
            .read(ReadRequest {
                dispatch: self.worker.dispatch_fence(),
                scope: self.connector_scope.clone(),
                live_probe,
                capability,
                query_digest: self.query_digest.clone(),
                cursor: sdk_cursor,
                page_size,
                at,
                budget: sdk_budget,
            })
            .map_err(|error| match error {
                ConnectorError::RateLimited => AwinError::RateLimited,
                ConnectorError::QuotaExceeded => AwinError::QuotaExceeded,
                ConnectorError::CostLimitExceeded => AwinError::CostLimitExceeded,
                ConnectorError::ProbeExpired => AwinError::Connector(ConnectorError::ProbeExpired),
                ConnectorError::ProbeNotLive | ConnectorError::UnsupportedProvenance => {
                    AwinError::Disconnected
                }
                other => AwinError::Connector(other),
            })?;
        let page = self
            .state
            .lock()
            .map_err(|_| AwinError::StatePoisoned)?
            .last_page
            .clone()
            .ok_or(AwinError::ProviderRejected)?;
        let credential_revision = self
            .state
            .lock()
            .map_err(|_| AwinError::StatePoisoned)?
            .active_credential
            .as_ref()
            .map(|active| active.credential_revision)
            .ok_or(AwinError::MissingAuthentication)?;
        let next_cursor = if connector_observation.next_cursor().is_some() {
            Some(AwinDurableCursor::new(
                &self.plan,
                &self.scope,
                &self.query_digest,
                connector_observation.page_sequence(),
            )?)
        } else {
            None
        };
        let content_digest = connector_observation.content_digest().to_owned();
        let freshness = connector_observation.freshness();
        let data = AwinReadData {
            resource: page.resource,
            record_count: connector_observation.item_count(),
            payload: page.payload.clone(),
        };
        let cost = AwinCostReceipt {
            cost_units: AWIN_READ_COST_UNITS,
            rate_remaining: self.budget.rate_remaining(),
            quota_remaining: self
                .budget
                .quota_limit
                .saturating_sub(self.budget.quota_used),
            cost_remaining_units: self
                .budget
                .cost_limit_units
                .saturating_sub(self.budget.cost_used_units),
        };
        let result_digest = digest_parts([
            AWIN_SCHEMA_VERSION,
            AWIN_SERVICE_ID,
            &self.connector_scope.digest(),
            &self.query_digest,
            &credential_revision.to_string(),
            &page.source_revision.to_string(),
            page.source_digest.as_str(),
            content_digest.as_str(),
            &connector_observation.page_sequence().to_string(),
        ]);
        let envelope = AwinResultEnvelope {
            schema_version: AWIN_SCHEMA_VERSION.to_owned(),
            service_id: AWIN_SERVICE_ID.to_owned(),
            provider_id: AWIN_PROVIDER_ID.to_owned(),
            publisher_id: self.scope.publisher_id().clone(),
            advertiser_id: self.scope.advertiser_id().cloned(),
            program_id: self.scope.program_id().cloned(),
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
                AwinObservationClassification::FirstParty
            } else {
                AwinObservationClassification::Fixture
            },
            cursor: next_cursor,
            cost,
            data,
            result_digest,
        };
        Ok(AwinReadResult {
            connector_observation,
            envelope,
        })
    }

    pub fn revoke(
        &mut self,
        reason: &str,
        at: DateTime<Utc>,
    ) -> Result<AwinLifecycleReceipt, AwinError> {
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
        let scope_digest = self.connector_scope.digest();
        Ok(lifecycle_receipt(
            "revoke",
            &scope_digest,
            at,
            &reason_digest,
        ))
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) -> Result<AwinLifecycleReceipt, AwinError> {
        if !self.mounted {
            return Err(AwinError::Unmounted);
        }
        self.secret_reference = None;
        self.credential_lease = None;
        self.auth_session = None;
        self.probe_result = None;
        if let Ok(mut state) = self.state.lock() {
            state.active_credential = None;
            state.last_probe = None;
            state.last_page = None;
        }
        self.mounted = false;
        let scope_digest = self.connector_scope.digest();
        Ok(lifecycle_receipt("unmount", &scope_digest, at, "unmount"))
    }

    fn ensure_mounted(&self) -> Result<(), AwinError> {
        if !self.mounted {
            return Err(AwinError::Unmounted);
        }
        if self
            .state
            .lock()
            .map_err(|_| AwinError::StatePoisoned)?
            .revoked
        {
            return Err(AwinError::Revoked);
        }
        Ok(())
    }
}

impl AwinService<AwinHttpTransport, BlockedEnvAwinCredentialResolver> {
    pub fn production(
        worker_id: impl Into<String>,
        scope: AwinScope,
        plan: AwinReadPlan,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
        budget: AwinBudget,
    ) -> Result<Self, AwinError> {
        Self::new(
            worker_id,
            scope,
            plan,
            AwinHttpTransport::official(),
            BlockedEnvAwinCredentialResolver,
            now,
            lease_expires_at,
            budget,
        )
    }
}

#[derive(Clone, Debug)]
pub struct AwinServiceProvider {
    definition: AwinServiceDefinition,
    scope: AwinScope,
    mounted_at: DateTime<Utc>,
    active: bool,
    revoked: bool,
}

impl AwinServiceProvider {
    pub fn mount(scope: AwinScope, at: DateTime<Utc>) -> Result<Self, AwinError> {
        Ok(Self {
            definition: AwinServiceDefinition::new()?,
            scope,
            mounted_at: at,
            active: true,
            revoked: false,
        })
    }

    pub fn definition(&self) -> &AwinServiceDefinition {
        &self.definition
    }

    pub fn registration_receipt(&self) -> Result<AwinLifecycleReceipt, AwinError> {
        if !self.active || self.revoked {
            return Err(AwinError::Unmounted);
        }
        let scope_digest = self.scope.digest()?;
        Ok(lifecycle_receipt(
            "mount",
            &scope_digest,
            self.mounted_at,
            AWIN_SERVICE_ID,
        ))
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) -> Result<AwinLifecycleReceipt, AwinError> {
        if !self.active {
            return Err(AwinError::Unmounted);
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

    pub fn unmount(&mut self, at: DateTime<Utc>) -> Result<AwinLifecycleReceipt, AwinError> {
        if !self.active {
            return Err(AwinError::Unmounted);
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
pub struct AwinMissionReadExpectation {
    pub mission_id: String,
    pub mission_revision: u64,
    pub provider_id: String,
    pub publisher_id: AwinPublisherId,
    pub advertiser_id: Option<AwinAdvertiserId>,
    pub program_id: Option<AwinProgramId>,
    pub credential_revision: u64,
    pub probe_revision: u64,
    pub source_revision: u64,
    pub capability: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinMissionReadReceipt {
    pub mission_id: String,
    pub mission_revision: u64,
    pub provider_id: String,
    pub publisher_id: AwinPublisherId,
    pub credential_revision: u64,
    pub probe_revision: u64,
    pub source_revision: u64,
    pub result_digest: String,
}

#[derive(Clone, Debug, Default)]
pub struct AwinMissionConsumer;

impl AwinMissionConsumer {
    pub fn consume(
        &self,
        mission: &Mission,
        scope: &AwinScope,
        probe: &AwinProbeReceipt,
        result: &AwinReadResult,
        expected: &AwinMissionReadExpectation,
        at: DateTime<Utc>,
    ) -> Result<AwinMissionReadReceipt, AwinError> {
        mission
            .contract
            .validate(at)
            .map_err(|error| AwinError::Mission(error.to_string()))?;
        let scope_digest = scope.digest()?;
        let connector_observation = &result.connector_observation;
        let envelope = &result.envelope;
        let mission_scope = scope.connector_scope()?;
        let exact = mission.id.as_str() == expected.mission_id
            && mission.revision == expected.mission_revision
            && mission.tenant_id.as_str() == scope.tenant_id()
            && mission.project_id.as_str() == scope.project_id()
            && mission
                .contract
                .enabled_capabilities
                .contains(AWIN_MISSION_CAPABILITY)
            && expected.provider_id == AWIN_PROVIDER_ID
            && expected.publisher_id == *scope.publisher_id()
            && expected.advertiser_id == scope.advertiser_id().cloned()
            && expected.program_id == scope.program_id().cloned()
            && expected.capability == envelope.resource.capability()
            && envelope.provider_id == AWIN_PROVIDER_ID
            && envelope.publisher_id == *scope.publisher_id()
            && envelope.advertiser_id == scope.advertiser_id().cloned()
            && envelope.program_id == scope.program_id().cloned()
            && envelope.scope_digest == scope_digest
            && probe.observation.status == AwinProbeStatus::Reachable
            && probe.observation.classification == AwinObservationClassification::FirstParty
            && probe.observation.provider_id == AWIN_PROVIDER_ID
            && probe.observation.publisher_id == *scope.publisher_id()
            && probe.observation.advertiser_id == scope.advertiser_id().cloned()
            && probe.observation.program_id == scope.program_id().cloned()
            && probe.connector_result.status() == ProbeStatus::Reachable
            && probe.connector_result.provenance_class()
                == ProviderProvenanceClass::ProductionProvider
            && probe.connector_result.evidence_digest() == probe.observation.evidence_digest
            && probe.connector_result.probe_revision() == expected.probe_revision
            && probe.credential_revision == expected.credential_revision
            && envelope.credential_revision == expected.credential_revision
            && envelope.source_revision == expected.source_revision
            && connector_observation.provenance_class()
                == ProviderProvenanceClass::ProductionProvider
            && connector_observation.scope() == &mission_scope
            && at >= connector_observation.freshness().observed_at()
            && at < connector_observation.freshness().valid_until();
        if !exact {
            return Err(AwinError::MissionBinding);
        }
        Ok(AwinMissionReadReceipt {
            mission_id: expected.mission_id.clone(),
            mission_revision: expected.mission_revision,
            provider_id: AWIN_PROVIDER_ID.to_owned(),
            publisher_id: expected.publisher_id.clone(),
            credential_revision: expected.credential_revision,
            probe_revision: expected.probe_revision,
            source_revision: expected.source_revision,
            result_digest: envelope.result_digest.clone(),
        })
    }
}

fn valid_hartevo_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_region(value: &str) -> bool {
    matches!(
        value,
        "AT" | "AU"
            | "BE"
            | "BR"
            | "BU"
            | "CA"
            | "CH"
            | "DE"
            | "DK"
            | "ES"
            | "FI"
            | "FR"
            | "GB"
            | "IE"
            | "IT"
            | "NL"
            | "NO"
            | "PL"
            | "SE"
            | "US"
    )
}

fn canonical_material(parts: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    parts
        .into_iter()
        .map(|part| {
            let part = part.as_ref();
            format!("{}:{}", part.len(), part)
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn digest_parts(parts: impl IntoIterator<Item = impl AsRef<str>>) -> String {
    sha256_hex(&canonical_material(parts))
}

fn sha256_hex(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    hex_encode(&digest.finalize())
}

fn sha256_json(value: &Value) -> String {
    serde_json::to_string(value)
        .map_or_else(|_| sha256_hex("invalid-json"), |json| sha256_hex(&json))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

fn revision_from_digest(digest: &str) -> u64 {
    u64::from_str_radix(&digest[..16], 16).unwrap_or(1).max(1)
}

fn cursor_token_digest(
    plan: &AwinReadPlan,
    scope_digest: &str,
    query_digest: &str,
    sequence: u64,
) -> String {
    digest_parts([
        AWIN_SCHEMA_VERSION,
        &format!("{:?}", plan.resource),
        scope_digest,
        query_digest,
        &sequence.to_string(),
        &plan.start_at.to_rfc3339(),
        &plan.end_at.to_rfc3339(),
    ])
}

fn extract_ids(
    value: &Value,
    keys: &[&str],
) -> Result<BTreeSet<AwinAdvertiserId>, AwinProviderError> {
    let mut ids = BTreeSet::new();
    extract_ids_into(value, keys, &mut ids)?;
    Ok(ids)
}

fn extract_ids_into(
    value: &Value,
    keys: &[&str],
    ids: &mut BTreeSet<AwinAdvertiserId>,
) -> Result<(), AwinProviderError> {
    match value {
        Value::Array(values) => {
            for value in values {
                extract_ids_into(value, keys, ids)?;
            }
        }
        Value::Object(object) => {
            for key in keys {
                if let Some(value) = object.get(*key) {
                    let raw = match value {
                        Value::Number(number) => number.to_string(),
                        Value::String(string) => string.clone(),
                        _ => continue,
                    };
                    let id = AwinAdvertiserId::new(raw)
                        .map_err(|_| AwinProviderError::InvalidResponse)?;
                    ids.insert(id);
                }
            }
            for value in object.values() {
                extract_ids_into(value, keys, ids)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn value_record_count(value: &Value) -> u32 {
    match value {
        Value::Array(values) => u32::try_from(values.len()).unwrap_or(u32::MAX),
        Value::Object(object) => object
            .get("data")
            .or_else(|| object.get("rows"))
            .map_or(1, value_record_count),
        _ => 1,
    }
}

fn lifecycle_receipt(
    action: &str,
    scope_digest: &str,
    at: DateTime<Utc>,
    reason: &str,
) -> AwinLifecycleReceipt {
    let receipt_digest = digest_parts([
        AWIN_SCHEMA_VERSION,
        AWIN_SERVICE_ID,
        action,
        scope_digest,
        &at.to_rfc3339(),
        reason,
    ]);
    AwinLifecycleReceipt {
        service_id: AWIN_SERVICE_ID.to_owned(),
        provider_id: AWIN_PROVIDER_ID.to_owned(),
        scope_digest: scope_digest.to_owned(),
        action: action.to_owned(),
        at,
        receipt_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hartevo_connector_sdk::ConnectorAuth;
    use hartevo_domain_kernel::{Mission, MissionContract, MissionId, ProjectId, TenantId};

    const NOW: &str = "2026-08-14T00:00:00Z";

    #[derive(Debug)]
    struct ContractTransport {
        provenance: ProviderProvenanceClass,
        reads: u32,
    }

    impl ContractTransport {
        fn production() -> Self {
            Self {
                provenance: ProviderProvenanceClass::ProductionProvider,
                reads: 0,
            }
        }
    }

    impl AwinTransport for ContractTransport {
        fn provenance_class(&self) -> ProviderProvenanceClass {
            self.provenance
        }

        fn probe(
            &mut self,
            _token: &AwinAccessToken,
            request: &AwinProbeRequest,
        ) -> Result<AwinProbeResponse, AwinProviderError> {
            let mut advertiser_ids = BTreeSet::new();
            if let Some(advertiser_id) = request.scope.advertiser_id() {
                advertiser_ids.insert(advertiser_id.clone());
            }
            let source_digest = sha256_hex("fixture-awin-probe");
            Ok(AwinProbeResponse {
                publisher_id: request.scope.publisher_id().clone(),
                advertiser_ids,
                source_uri: "https://api.awin.com/publishers/123/programmes".to_owned(),
                source_digest: source_digest.clone(),
                source_revision: revision_from_digest(&source_digest),
                observed_at: request.observed_at,
            })
        }

        fn read(
            &mut self,
            _token: &AwinAccessToken,
            request: &AwinProviderReadRequest,
        ) -> Result<AwinProviderPage, AwinProviderError> {
            self.reads = self.reads.saturating_add(1);
            let payload = serde_json::json!({
                "data": [{
                    "advertiserId": request.scope.advertiser_id().map_or("100", AwinAdvertiserId::as_str),
                    "publisherId": request.scope.publisher_id().as_str(),
                    "page": self.reads,
                    "startDate": request.start_at.to_rfc3339(),
                    "endDate": request.end_at.to_rfc3339()
                }]
            });
            let source_digest = sha256_json(&payload);
            let mut advertiser_ids = BTreeSet::new();
            if let Some(advertiser_id) = request.scope.advertiser_id() {
                advertiser_ids.insert(advertiser_id.clone());
            } else {
                advertiser_ids.insert(
                    AwinAdvertiserId::new("100").map_err(|_| AwinProviderError::InvalidResponse)?,
                );
            }
            Ok(AwinProviderPage {
                resource: request.resource,
                publisher_id: Some(request.scope.publisher_id().clone()),
                advertiser_ids,
                source_uri: "https://api.awin.com/publishers/123/transactions/".to_owned(),
                source_revision: revision_from_digest(&source_digest),
                source_digest,
                observed_at: request.observed_at,
                payload,
            })
        }
    }

    #[derive(Clone, Debug)]
    struct ContractResolver {
        available: bool,
    }

    impl AwinCredentialResolver for ContractResolver {
        fn resolve(
            &mut self,
            reference: &SecretReference,
            scope: &AwinScope,
            _at: DateTime<Utc>,
        ) -> Result<AwinAccessToken, AwinProviderError> {
            if !self.available {
                return Err(AwinProviderError::BlockedEnv);
            }
            if reference.scope()
                != &scope
                    .connector_scope()
                    .map_err(|_| AwinProviderError::ScopeDrift)?
            {
                return Err(AwinProviderError::ScopeDrift);
            }
            AwinAccessToken::new("fixture-token").map_err(|_| AwinProviderError::InvalidResponse)
        }
    }

    fn now() -> DateTime<Utc> {
        NOW.parse().expect("deterministic time")
    }

    fn scope() -> AwinScope {
        AwinScope::new(
            "tenant-awin",
            "project-awin",
            AwinPublisherId::new("123").expect("publisher"),
            Some(AwinAdvertiserId::new("100").expect("advertiser")),
            Some(AwinProgramId::new("100").expect("program")),
        )
        .expect("scope")
    }

    fn plan() -> AwinReadPlan {
        AwinReadPlan::new(
            AwinReadResource::Transactions,
            now(),
            now() + Duration::days(62),
            None,
        )
        .expect("plan")
    }

    fn budget() -> AwinBudget {
        AwinBudget::new(20, now() + Duration::minutes(1), 10, 10).expect("budget")
    }

    fn auth_material(scope: &AwinScope) -> (SecretReference, CredentialLease) {
        let connector_scope = scope.connector_scope().expect("connector scope");
        let secret = SecretReference::new("secret-ref-awin-test", connector_scope, 7)
            .expect("secret reference");
        let adapter =
            ProviderAdapterIdentity::new(AWIN_ADAPTER_ID, AWIN_ADAPTER_VERSION).expect("adapter");
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            adapter,
            "lease-awin-test",
            3,
            now(),
            now() + Duration::minutes(10),
        )
        .expect("lease");
        (secret, lease)
    }

    fn service<R>(resolver: R) -> AwinService<ContractTransport, R>
    where
        R: AwinCredentialResolver,
    {
        service_with_budget(resolver, budget())
    }

    fn service_with_budget<R>(
        resolver: R,
        read_budget: AwinBudget,
    ) -> AwinService<ContractTransport, R>
    where
        R: AwinCredentialResolver,
    {
        AwinService::new(
            "worker-awin-test",
            scope(),
            plan(),
            ContractTransport::production(),
            resolver,
            now(),
            now() + Duration::minutes(10),
            read_budget,
        )
        .expect("service")
    }

    #[test]
    fn service_definition_registers_only_awin_probe_and_reads() {
        let definition = AwinServiceDefinition::new().expect("definition");
        let registry = definition.registry().expect("registry");
        assert_eq!(registry.registrations().len(), 4);
        assert!(
            registry
                .registrations()
                .iter()
                .all(|registration| registration.adapter() == &definition.adapter)
        );
        assert!(definition.capabilities.contains(AWIN_MISSION_CAPABILITY));
        assert_eq!(definition.provider_id, AWIN_PROVIDER_ID);
    }

    #[test]
    fn missing_credential_is_blocked_env_and_cannot_authorize_read() {
        let mut service = service(BlockedEnvAwinCredentialResolver);
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(1, "probe-result-awin-blocked", now())
            .expect("probe");
        assert_eq!(probe.observation.status, AwinProbeStatus::Rejected);
        assert_eq!(
            probe.observation.classification,
            AwinObservationClassification::BlockedEnv
        );
        assert_eq!(probe.connector_result.status(), ProbeStatus::Rejected);
        assert!(matches!(
            service.read(None, 100, now()),
            Err(AwinError::Disconnected)
        ));
    }

    #[test]
    fn authenticated_read_emits_first_party_envelope_and_durable_window_cursor() {
        let mut service = service(ContractResolver { available: true });
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(1, "probe-result-awin-live", now())
            .expect("probe");
        assert_eq!(
            probe.observation.classification,
            AwinObservationClassification::FirstParty
        );
        let first = service.read(None, 100, now()).expect("first read");
        assert_eq!(
            first.envelope.classification,
            AwinObservationClassification::FirstParty
        );
        assert_eq!(first.envelope.resource, AwinReadResource::Transactions);
        assert_eq!(first.envelope.credential_revision, 7);
        assert_eq!(
            first
                .envelope
                .cursor
                .as_ref()
                .expect("next cursor")
                .sequence(),
            1
        );
        assert_eq!(service.budget().cost_used_units(), AWIN_READ_COST_UNITS);
        let cursor = first.envelope.cursor.clone().expect("cursor");
        let second = service
            .read(Some(&cursor), 100, now())
            .expect("second read");
        assert!(second.envelope.cursor.is_none());
        assert!(second.envelope.source_revision > 0);
        let sdk_cursor = cursor
            .to_sdk_cursor(service.connector_scope())
            .expect("sdk cursor");
        assert_eq!(sdk_cursor.sequence(), 1);
    }

    #[test]
    fn cursor_drift_is_rejected_before_provider_read() {
        let read_plan = plan();
        let query_digest = read_plan.query_digest(&scope()).expect("query digest");
        let mut cursor =
            AwinDurableCursor::new(&read_plan, &scope(), &query_digest, 1).expect("cursor");
        cursor.query_digest = sha256_hex("different-query");
        assert_eq!(
            cursor.validate_against(&read_plan, &scope(), &query_digest),
            Err(AwinError::CursorDrift)
        );
    }

    #[test]
    fn expired_credential_and_rate_limit_are_fail_closed() {
        #[derive(Clone, Debug)]
        struct FailingResolver {
            error: AwinProviderError,
        }

        impl AwinCredentialResolver for FailingResolver {
            fn resolve(
                &mut self,
                _reference: &SecretReference,
                _scope: &AwinScope,
                _at: DateTime<Utc>,
            ) -> Result<AwinAccessToken, AwinProviderError> {
                Err(self.error.clone())
            }
        }

        let mut expired = service(FailingResolver {
            error: AwinProviderError::CredentialExpired,
        });
        let (secret, lease) = auth_material(expired.scope());
        expired
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = expired
            .probe(1, "probe-result-awin-expired", now())
            .expect("probe");
        assert_eq!(
            probe.observation.classification,
            AwinObservationClassification::CredentialExpired
        );
        assert!(matches!(
            expired.read(None, 100, now()),
            Err(AwinError::Disconnected)
        ));

        let mut rate_limited = service_with_budget(
            ContractResolver { available: true },
            AwinBudget::new(0, now() + Duration::minutes(1), 10, 10).expect("rate budget"),
        );
        let (secret, lease) = auth_material(rate_limited.scope());
        rate_limited
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        rate_limited
            .probe(1, "probe-result-awin-rate", now())
            .expect("probe");
        assert!(matches!(
            rate_limited.read(None, 100, now()),
            Err(AwinError::RateLimited)
        ));
    }

    #[test]
    fn revoke_and_unmount_reclaim_provider_material() {
        let mut service = service(ContractResolver { available: true });
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        service
            .probe(1, "probe-result-awin-revoke", now())
            .expect("probe");
        let receipt = service.revoke("user-revoked", now()).expect("revoke");
        assert_eq!(receipt.action, "revoke");
        assert!(matches!(
            service.read(None, 100, now()),
            Err(AwinError::Revoked)
        ));
        assert_eq!(
            service.unmount(now()).expect("unmount after revoke").action,
            "unmount"
        );
        assert!(matches!(
            service.read(None, 100, now()),
            Err(AwinError::Unmounted)
        ));

        let mut provider = AwinServiceProvider::mount(scope(), now()).expect("mount");
        assert_eq!(
            provider.registration_receipt().expect("receipt").action,
            "mount"
        );
        assert_eq!(
            provider.revoke(now()).expect("provider revoke").action,
            "revoke"
        );
        assert!(matches!(
            provider.registration_receipt(),
            Err(AwinError::Unmounted)
        ));
    }

    #[test]
    fn mission_consumer_requires_exact_provider_account_revision_and_freshness() {
        let mut service = service(ContractResolver { available: true });
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(9, "probe-result-awin-mission", now())
            .expect("probe");
        let result = service.read(None, 100, now()).expect("read");
        let mission = Mission::compile(
            TenantId::from("tenant-awin"),
            MissionId::from("mission-awin"),
            ProjectId::from("project-awin"),
            "Awin read mission",
            MissionContract::bootstrap(
                "Read Awin partner data",
                [AWIN_MISSION_CAPABILITY.to_owned()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        let expected = AwinMissionReadExpectation {
            mission_id: "mission-awin".to_owned(),
            mission_revision: mission.revision,
            provider_id: AWIN_PROVIDER_ID.to_owned(),
            publisher_id: scope().publisher_id().clone(),
            advertiser_id: scope().advertiser_id().cloned(),
            program_id: scope().program_id().cloned(),
            credential_revision: probe.credential_revision,
            probe_revision: probe.connector_result.probe_revision(),
            source_revision: result.envelope.source_revision,
            capability: result.envelope.resource.capability().to_owned(),
        };
        let receipt = AwinMissionConsumer
            .consume(&mission, service.scope(), &probe, &result, &expected, now())
            .expect("exact mission binding");
        assert_eq!(receipt.provider_id, AWIN_PROVIDER_ID);
        assert_eq!(receipt.credential_revision, 7);
    }
}
