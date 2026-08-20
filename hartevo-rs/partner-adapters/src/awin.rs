//! Awin publisher-side authenticated read adapter.
//!
//! This module owns only Awin-native identities, request shapes, provider
//! transport, service registration, and the Mission read consumer.  It uses
//! the Connector SDK for authentication fencing, probe liveness, observation
//! binding, quota admission, and revocation; it does not recreate those SDK
//! contracts.

use std::collections::{BTreeMap, BTreeSet};
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
pub const AWIN_RECONCILE_SERVICE_ID: &str = "partner.awin.cursor-reconcile/v1";

const AWIN_SCHEMA_VERSION: &str = "hartevo-awin-authenticated-read/v1";
const AWIN_RECONCILE_SCHEMA_VERSION: &str = "hartevo-awin-cursor-reconcile/v1";
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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

    #[cfg(test)]
    fn loopback(base_url: impl Into<String>) -> Result<Self, AwinError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        if !base_url.starts_with("http://127.0.0.1:") || base_url.contains('?') {
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
    #[error("Awin cursor drifted from the exact provider generation")]
    GenerationDrift,
    #[error("Awin page delivery is invalid")]
    InvalidDelivery,
    #[error("Awin evidence root is still open")]
    EvidenceRootOpen,
    #[error("Awin evidence root is already closed")]
    EvidenceRootClosed,
    #[error("Awin reconcile checkpoint is invalid")]
    InvalidCheckpoint,
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

/// The exact network generation that produced an authenticated observation.
/// A cursor is never portable across a credential, probe, or provider-source
/// generation, even when the logical Awin scope remains unchanged.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinProviderGeneration {
    provider_id: String,
    publisher_id: AwinPublisherId,
    advertiser_id: Option<AwinAdvertiserId>,
    program_id: Option<AwinProgramId>,
    credential_revision: u64,
    adapter_id: String,
    adapter_version: u32,
    probe_revision: u64,
    provider_generation: u64,
    generation_digest: String,
}

impl AwinProviderGeneration {
    pub fn from_probe(scope: &AwinScope, probe: &AwinProbeReceipt) -> Result<Self, AwinError> {
        let scope_digest = scope.digest()?;
        let observation = &probe.observation;
        let connector_result = &probe.connector_result;
        let source_revision = observation.source_revision.ok_or(AwinError::Disconnected)?;
        let adapter = connector_result.adapter();
        let exact = observation.status == AwinProbeStatus::Reachable
            && observation.classification == AwinObservationClassification::FirstParty
            && observation.provider_id == AWIN_PROVIDER_ID
            && observation.publisher_id == *scope.publisher_id()
            && observation.advertiser_id == scope.advertiser_id().cloned()
            && observation.program_id == scope.program_id().cloned()
            && observation.credential_revision == probe.credential_revision
            && connector_result.status() == ProbeStatus::Reachable
            && connector_result.provenance_class() == ProviderProvenanceClass::ProductionProvider
            && connector_result.scope() == &scope.connector_scope()?
            && adapter.adapter_id() == AWIN_ADAPTER_ID
            && adapter.adapter_version() == AWIN_ADAPTER_VERSION
            && connector_result.evidence_digest() == observation.evidence_digest
            && is_sha256(&observation.source_digest)
            && is_sha256(&observation.evidence_digest);
        if !exact || source_revision == 0 || connector_result.probe_revision() == 0 {
            return Err(AwinError::GenerationDrift);
        }
        let generation_digest = digest_parts([
            AWIN_RECONCILE_SCHEMA_VERSION,
            AWIN_PROVIDER_ID,
            scope_digest.as_str(),
            scope.publisher_id().as_str(),
            scope.advertiser_id().map_or("", AwinAdvertiserId::as_str),
            scope.program_id().map_or("", AwinProgramId::as_str),
            &probe.credential_revision.to_string(),
            adapter.adapter_id(),
            &adapter.adapter_version().to_string(),
            &connector_result.probe_revision().to_string(),
            &source_revision.to_string(),
            observation.source_digest.as_str(),
            observation.evidence_digest.as_str(),
        ]);
        Ok(Self {
            provider_id: AWIN_PROVIDER_ID.to_owned(),
            publisher_id: scope.publisher_id().clone(),
            advertiser_id: scope.advertiser_id().cloned(),
            program_id: scope.program_id().cloned(),
            credential_revision: probe.credential_revision,
            adapter_id: adapter.adapter_id().to_owned(),
            adapter_version: adapter.adapter_version(),
            probe_revision: connector_result.probe_revision(),
            provider_generation: source_revision,
            generation_digest,
        })
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
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

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn probe_revision(&self) -> u64 {
        self.probe_revision
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub fn adapter_id(&self) -> &str {
        &self.adapter_id
    }

    pub const fn adapter_version(&self) -> u32 {
        self.adapter_version
    }

    pub fn digest(&self) -> &str {
        &self.generation_digest
    }

    fn validate_scope(&self, scope: &AwinScope) -> Result<(), AwinError> {
        let exact = self.provider_id == AWIN_PROVIDER_ID
            && self.publisher_id == *scope.publisher_id()
            && self.advertiser_id == scope.advertiser_id().cloned()
            && self.program_id == scope.program_id().cloned()
            && self.adapter_id == AWIN_ADAPTER_ID
            && self.adapter_version == AWIN_ADAPTER_VERSION
            && self.credential_revision > 0
            && self.probe_revision > 0
            && self.provider_generation > 0
            && is_sha256(&self.generation_digest);
        if exact {
            Ok(())
        } else {
            Err(AwinError::GenerationDrift)
        }
    }
}

#[derive(Debug, Default)]
struct AwinReconcileAuthorityState {
    active_generation: Option<String>,
    invalidated: bool,
    epoch: u64,
}

/// Shared fencing authority.  A service refresh, revoke, probe replacement,
/// or unmount invalidates all sessions that hold an older generation-bound
/// cursor, including sessions reopened after a process crash.
#[derive(Clone, Debug, Default)]
pub struct AwinReconcileAuthority {
    state: Arc<Mutex<AwinReconcileAuthorityState>>,
}

impl AwinReconcileAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    fn bind(&self, generation: &AwinProviderGeneration) -> Result<(), AwinError> {
        let mut state = self.state.lock().map_err(|_| AwinError::StatePoisoned)?;
        state.active_generation = Some(generation.digest().to_owned());
        state.invalidated = false;
        state.epoch = state.epoch.saturating_add(1);
        Ok(())
    }

    fn ensure_generation(&self, generation: &AwinProviderGeneration) -> Result<(), AwinError> {
        let mut state = self.state.lock().map_err(|_| AwinError::StatePoisoned)?;
        match state.active_generation.as_deref() {
            Some(active) if active == generation.digest() => Ok(()),
            Some(_) => Err(AwinError::GenerationDrift),
            None if state.invalidated => Err(AwinError::GenerationDrift),
            None => {
                state.active_generation = Some(generation.digest().to_owned());
                state.epoch = state.epoch.saturating_add(1);
                Ok(())
            }
        }
    }

    pub fn invalidate(&self) -> Result<(), AwinError> {
        let mut state = self.state.lock().map_err(|_| AwinError::StatePoisoned)?;
        state.active_generation = None;
        state.invalidated = true;
        state.epoch = state.epoch.saturating_add(1);
        Ok(())
    }

    fn validate(&self, generation: &AwinProviderGeneration) -> Result<(), AwinError> {
        let state = self.state.lock().map_err(|_| AwinError::StatePoisoned)?;
        if state.active_generation.as_deref() == Some(generation.digest()) {
            Ok(())
        } else {
            Err(AwinError::GenerationDrift)
        }
    }
}

/// A durable continuation that binds the first-layer date cursor to the
/// exact provider/account/advertiser/program and credential generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinReconcileCursor {
    schema_version: String,
    resource: AwinReadResource,
    scope_digest: String,
    query_digest: String,
    generation_digest: String,
    credential_revision: u64,
    provider_generation: u64,
    page_cursor: AwinDurableCursor,
    cursor_digest: String,
}

impl AwinReconcileCursor {
    pub fn from_durable(
        page_cursor: AwinDurableCursor,
        scope: &AwinScope,
        plan: &AwinReadPlan,
        generation: &AwinProviderGeneration,
    ) -> Result<Self, AwinError> {
        generation.validate_scope(scope)?;
        let query_digest = plan.query_digest(scope)?;
        page_cursor.validate_against(plan, scope, &query_digest)?;
        let cursor = Self {
            schema_version: AWIN_RECONCILE_SCHEMA_VERSION.to_owned(),
            resource: plan.resource,
            scope_digest: scope.digest()?,
            query_digest,
            generation_digest: generation.digest().to_owned(),
            credential_revision: generation.credential_revision(),
            provider_generation: generation.provider_generation(),
            page_cursor,
            cursor_digest: String::new(),
        };
        let cursor_digest = cursor.calculated_cursor_digest();
        Ok(Self {
            cursor_digest,
            ..cursor
        })
    }

    pub fn resource(&self) -> AwinReadResource {
        self.resource
    }

    pub fn sequence(&self) -> u64 {
        self.page_cursor.sequence()
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }

    pub fn cursor_digest(&self) -> &str {
        &self.cursor_digest
    }

    pub fn page_cursor(&self) -> &AwinDurableCursor {
        &self.page_cursor
    }

    fn validate_against(
        &self,
        scope: &AwinScope,
        plan: &AwinReadPlan,
        generation: &AwinProviderGeneration,
    ) -> Result<(), AwinError> {
        generation.validate_scope(scope)?;
        let query_digest = plan.query_digest(scope)?;
        if self.schema_version != AWIN_RECONCILE_SCHEMA_VERSION
            || self.resource != plan.resource
            || self.scope_digest != scope.digest()?
            || self.query_digest != query_digest
            || self.generation_digest != generation.digest()
            || self.credential_revision != generation.credential_revision()
            || self.provider_generation != generation.provider_generation()
            || !is_sha256(&self.cursor_digest)
            || self.cursor_digest != self.calculated_cursor_digest()
        {
            return Err(AwinError::GenerationDrift);
        }
        self.page_cursor
            .validate_against(plan, scope, &query_digest)
    }

    fn calculated_cursor_digest(&self) -> String {
        digest_parts([
            AWIN_RECONCILE_SCHEMA_VERSION,
            &format!("{:?}", self.resource),
            &self.scope_digest,
            &self.query_digest,
            &self.generation_digest,
            &self.credential_revision.to_string(),
            &self.provider_generation.to_string(),
            self.page_cursor.cursor_digest(),
        ])
    }
}

/// A first-party page plus all receipt material required to reconcile it
/// exactly once after retries or process recovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinPageDelivery {
    resource: AwinReadResource,
    sequence: u64,
    scope_digest: String,
    generation_digest: String,
    provider_generation: u64,
    source_revision: u64,
    publisher_id: AwinPublisherId,
    advertiser_id: Option<AwinAdvertiserId>,
    program_id: Option<AwinProgramId>,
    input_cursor: Option<AwinReconcileCursor>,
    next_cursor: Option<AwinReconcileCursor>,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_uri: String,
    source_digest: String,
    content_digest: String,
    result_digest: String,
    item_count: u32,
    idempotency_key: String,
    delivery_digest: String,
}

impl AwinPageDelivery {
    #[allow(clippy::too_many_lines)]
    pub fn from_read(
        scope: &AwinScope,
        plan: &AwinReadPlan,
        generation: &AwinProviderGeneration,
        input_cursor: Option<&AwinReconcileCursor>,
        result: &AwinReadResult,
        at: DateTime<Utc>,
    ) -> Result<Self, AwinError> {
        generation.validate_scope(scope)?;
        let scope_digest = scope.digest()?;
        let envelope = &result.envelope;
        let observation = &result.connector_observation;
        let exact_scope = envelope.scope_digest == scope_digest
            && envelope.provider_id == AWIN_PROVIDER_ID
            && envelope.publisher_id == *scope.publisher_id()
            && envelope.advertiser_id == scope.advertiser_id().cloned()
            && envelope.program_id == scope.program_id().cloned()
            && envelope.resource == plan.resource
            && envelope.query_digest == plan.query_digest(scope)?
            && envelope.credential_revision == generation.credential_revision()
            && envelope.source_revision > 0
            && envelope.classification == AwinObservationClassification::FirstParty
            && envelope.service_id == AWIN_SERVICE_ID
            && observation.scope() == &scope.connector_scope()?
            && observation.adapter().adapter_id() == AWIN_ADAPTER_ID
            && observation.adapter().adapter_version() == AWIN_ADAPTER_VERSION
            && observation.provenance_class() == ProviderProvenanceClass::ProductionProvider
            && observation.request_digest() == envelope.query_digest
            && observation.response_digest() == envelope.source_digest
            && observation.content_digest() == envelope.content_digest
            && observation.page_sequence() > 0
            && observation.next_cursor().is_some() == envelope.cursor.is_some()
            && observation.freshness().observed_at() == envelope.observed_at
            && observation.freshness().valid_until() == envelope.valid_until
            && at >= envelope.observed_at
            && at < envelope.valid_until
            && envelope.valid_until > envelope.observed_at
            && is_provider_source_uri(&envelope.source_uri)
            && is_sha256(&envelope.source_digest)
            && is_sha256(&envelope.content_digest)
            && is_sha256(&envelope.result_digest)
            && envelope.content_digest == sha256_json(&envelope.data.payload)
            && envelope.data.resource == plan.resource;
        if !exact_scope {
            return Err(AwinError::InvalidDelivery);
        }
        let sequence = observation.page_sequence();
        let input_cursor = input_cursor.cloned();
        if sequence == 1 {
            if input_cursor.is_some() {
                return Err(AwinError::InvalidDelivery);
            }
        } else if input_cursor
            .as_ref()
            .is_none_or(|cursor| cursor.sequence().saturating_add(1) != sequence)
        {
            return Err(AwinError::InvalidDelivery);
        }
        if let Some(cursor) = &input_cursor {
            cursor.validate_against(scope, plan, generation)?;
        }
        let next_cursor = envelope
            .cursor
            .clone()
            .map(|cursor| AwinReconcileCursor::from_durable(cursor, scope, plan, generation))
            .transpose()?;
        if next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.sequence() != sequence)
        {
            return Err(AwinError::InvalidDelivery);
        }
        let idempotency_key = digest_parts([
            AWIN_RECONCILE_SCHEMA_VERSION,
            generation.digest(),
            &sequence.to_string(),
            envelope.source_digest.as_str(),
            envelope.content_digest.as_str(),
            envelope.result_digest.as_str(),
        ]);
        let mut delivery = Self {
            resource: plan.resource,
            sequence,
            scope_digest,
            generation_digest: generation.digest().to_owned(),
            provider_generation: generation.provider_generation(),
            source_revision: envelope.source_revision,
            publisher_id: scope.publisher_id().clone(),
            advertiser_id: scope.advertiser_id().cloned(),
            program_id: scope.program_id().cloned(),
            input_cursor,
            next_cursor,
            observed_at: envelope.observed_at,
            valid_until: envelope.valid_until,
            source_uri: envelope.source_uri.clone(),
            source_digest: envelope.source_digest.clone(),
            content_digest: envelope.content_digest.clone(),
            result_digest: envelope.result_digest.clone(),
            item_count: observation.item_count(),
            idempotency_key,
            delivery_digest: String::new(),
        };
        delivery.delivery_digest = delivery.calculated_delivery_digest();
        Ok(delivery)
    }

    pub fn resource(&self) -> AwinReadResource {
        self.resource
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn input_cursor(&self) -> Option<&AwinReconcileCursor> {
        self.input_cursor.as_ref()
    }

    pub fn next_cursor(&self) -> Option<&AwinReconcileCursor> {
        self.next_cursor.as_ref()
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn delivery_digest(&self) -> &str {
        &self.delivery_digest
    }

    fn validate_against(
        &self,
        scope: &AwinScope,
        plan: &AwinReadPlan,
        generation: &AwinProviderGeneration,
    ) -> Result<(), AwinError> {
        generation.validate_scope(scope)?;
        let exact = self.resource == plan.resource
            && self.scope_digest == scope.digest()?
            && self.generation_digest == generation.digest()
            && self.provider_generation == generation.provider_generation()
            && self.source_revision > 0
            && self.publisher_id == *scope.publisher_id()
            && self.advertiser_id == scope.advertiser_id().cloned()
            && self.program_id == scope.program_id().cloned()
            && self.sequence > 0
            && self.observed_at < self.valid_until
            && is_provider_source_uri(&self.source_uri)
            && is_sha256(&self.source_digest)
            && is_sha256(&self.content_digest)
            && is_sha256(&self.result_digest)
            && is_sha256(&self.idempotency_key)
            && self.delivery_digest == self.calculated_delivery_digest();
        if !exact {
            return Err(AwinError::InvalidDelivery);
        }
        if let Some(cursor) = &self.input_cursor {
            cursor.validate_against(scope, plan, generation)?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(scope, plan, generation)?;
            if cursor.sequence() != self.sequence {
                return Err(AwinError::InvalidDelivery);
            }
        }
        if (self.sequence == 1 && self.input_cursor.is_some())
            || (self.sequence > 1
                && self
                    .input_cursor
                    .as_ref()
                    .is_none_or(|cursor| cursor.sequence().saturating_add(1) != self.sequence))
            || self.idempotency_key != self.calculated_idempotency_key()
        {
            return Err(AwinError::InvalidDelivery);
        }
        Ok(())
    }

    fn calculated_idempotency_key(&self) -> String {
        digest_parts([
            AWIN_RECONCILE_SCHEMA_VERSION,
            &self.generation_digest,
            &self.sequence.to_string(),
            &self.source_digest,
            &self.content_digest,
            &self.result_digest,
        ])
    }

    fn calculated_delivery_digest(&self) -> String {
        digest_parts([
            AWIN_RECONCILE_SCHEMA_VERSION,
            &format!("{:?}", self.resource),
            &self.sequence.to_string(),
            &self.scope_digest,
            &self.generation_digest,
            &self.provider_generation.to_string(),
            &self.source_revision.to_string(),
            self.publisher_id.as_str(),
            self.advertiser_id
                .as_ref()
                .map_or("", AwinAdvertiserId::as_str),
            self.program_id.as_ref().map_or("", AwinProgramId::as_str),
            self.input_cursor
                .as_ref()
                .map_or("", AwinReconcileCursor::cursor_digest),
            self.next_cursor
                .as_ref()
                .map_or("", AwinReconcileCursor::cursor_digest),
            &self.observed_at.to_rfc3339(),
            &self.valid_until.to_rfc3339(),
            &self.source_uri,
            &self.source_digest,
            &self.content_digest,
            &self.result_digest,
            &self.item_count.to_string(),
            &self.idempotency_key,
        ])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinEvidenceNode {
    sequence: u64,
    idempotency_key: String,
    delivery_digest: String,
    source_uri: String,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_revision: u64,
    source_digest: String,
    content_digest: String,
    node_digest: String,
}

impl AwinEvidenceNode {
    fn from_delivery(delivery: &AwinPageDelivery) -> Self {
        let node_digest = digest_parts([
            AWIN_RECONCILE_SCHEMA_VERSION,
            &delivery.sequence.to_string(),
            &delivery.idempotency_key,
            &delivery.delivery_digest,
            &delivery.source_uri,
            &delivery.observed_at.to_rfc3339(),
            &delivery.valid_until.to_rfc3339(),
            &delivery.source_revision.to_string(),
            &delivery.source_digest,
            &delivery.content_digest,
        ]);
        Self {
            sequence: delivery.sequence,
            idempotency_key: delivery.idempotency_key.clone(),
            delivery_digest: delivery.delivery_digest.clone(),
            source_uri: delivery.source_uri.clone(),
            observed_at: delivery.observed_at,
            valid_until: delivery.valid_until,
            source_revision: delivery.source_revision,
            source_digest: delivery.source_digest.clone(),
            content_digest: delivery.content_digest.clone(),
            node_digest,
        }
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn node_digest(&self) -> &str {
        &self.node_digest
    }

    fn validate_against_delivery(&self, delivery: &AwinPageDelivery) -> bool {
        self == &Self::from_delivery(delivery)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinEvidenceRoot {
    schema_version: String,
    scope_digest: String,
    generation_digest: String,
    provider_generation: u64,
    resource: AwinReadResource,
    query_digest: String,
    nodes: Vec<AwinEvidenceNode>,
    root_digest: String,
    closed_at: DateTime<Utc>,
}

impl AwinEvidenceRoot {
    fn new(
        scope: &AwinScope,
        plan: &AwinReadPlan,
        generation: &AwinProviderGeneration,
        nodes: Vec<AwinEvidenceNode>,
        closed_at: DateTime<Utc>,
    ) -> Result<Self, AwinError> {
        let scope_digest = scope.digest()?;
        let query_digest = plan.query_digest(scope)?;
        let resource = format!("{:?}", plan.resource);
        let root_digest = digest_parts(
            std::iter::once(AWIN_RECONCILE_SCHEMA_VERSION)
                .chain(std::iter::once(scope_digest.as_str()))
                .chain(std::iter::once(generation.digest()))
                .chain(std::iter::once(resource.as_str()))
                .chain(std::iter::once(query_digest.as_str()))
                .chain(nodes.iter().map(AwinEvidenceNode::node_digest)),
        );
        Ok(Self {
            schema_version: AWIN_RECONCILE_SCHEMA_VERSION.to_owned(),
            scope_digest,
            generation_digest: generation.digest().to_owned(),
            provider_generation: generation.provider_generation(),
            resource: plan.resource,
            query_digest,
            nodes,
            root_digest,
            closed_at,
        })
    }

    pub fn is_closed(&self) -> bool {
        true
    }

    pub fn root_digest(&self) -> &str {
        &self.root_digest
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }

    pub fn resource(&self) -> AwinReadResource {
        self.resource
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub fn nodes(&self) -> &[AwinEvidenceNode] {
        &self.nodes
    }

    pub const fn closed_at(&self) -> DateTime<Utc> {
        self.closed_at
    }

    fn validate_against(
        &self,
        scope: &AwinScope,
        plan: &AwinReadPlan,
        generation: &AwinProviderGeneration,
        nodes: &[AwinEvidenceNode],
    ) -> Result<(), AwinError> {
        let expected = Self::new(scope, plan, generation, nodes.to_vec(), self.closed_at)?;
        if self.schema_version == expected.schema_version
            && self.scope_digest == expected.scope_digest
            && self.generation_digest == expected.generation_digest
            && self.provider_generation == expected.provider_generation
            && self.resource == expected.resource
            && self.query_digest == expected.query_digest
            && self.nodes == expected.nodes
            && self.root_digest == expected.root_digest
        {
            Ok(())
        } else {
            Err(AwinError::InvalidCheckpoint)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwinDeliveryStatus {
    Applied,
    Duplicate,
    OutOfOrder,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinDeliveryReceipt {
    status: AwinDeliveryStatus,
    sequence: u64,
    expected_sequence: u64,
    next_sequence: u64,
    idempotency_key: String,
    generation_digest: String,
    evidence_root_digest: Option<String>,
    receipt_digest: String,
}

impl AwinDeliveryReceipt {
    pub fn status(&self) -> &AwinDeliveryStatus {
        &self.status
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }

    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn evidence_root_digest(&self) -> Option<&str> {
        self.evidence_root_digest.as_deref()
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinRetryAfterReceipt {
    sequence: u64,
    expected_sequence: u64,
    retry_after: DateTime<Utc>,
    generation_digest: String,
    receipt_digest: String,
}

impl AwinRetryAfterReceipt {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }

    pub const fn retry_after(&self) -> DateTime<Utc> {
        self.retry_after
    }

    pub fn generation_digest(&self) -> &str {
        &self.generation_digest
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwinReconcileOutcome {
    Applied(AwinDeliveryReceipt),
    Duplicate(AwinDeliveryReceipt),
    OutOfOrder(AwinDeliveryReceipt),
    RetryAfter(AwinRetryAfterReceipt),
}

/// Crash-safe serialized reconcile state.  It contains only typed cursors
/// and evidence digests; provider tokens and secret bytes never enter the
/// checkpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinReconcileCheckpoint {
    schema_version: String,
    scope: AwinScope,
    plan: AwinReadPlan,
    generation: AwinProviderGeneration,
    next_sequence: u64,
    pending_cursor: Option<AwinReconcileCursor>,
    deliveries: BTreeMap<u64, AwinPageDelivery>,
    evidence_nodes: BTreeMap<u64, AwinEvidenceNode>,
    retry_after: Option<DateTime<Utc>>,
    evidence_root: Option<AwinEvidenceRoot>,
    checkpoint_digest: String,
}

impl AwinReconcileCheckpoint {
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn pending_cursor(&self) -> Option<&AwinReconcileCursor> {
        self.pending_cursor.as_ref()
    }

    pub fn evidence_root(&self) -> Option<&AwinEvidenceRoot> {
        self.evidence_root.as_ref()
    }

    pub fn validate(&self) -> Result<(), AwinError> {
        if self.schema_version != AWIN_RECONCILE_SCHEMA_VERSION
            || self.plan.validate().is_err()
            || self.generation.validate_scope(&self.scope).is_err()
            || !is_sha256(&self.checkpoint_digest)
            || self.checkpoint_digest != self.calculated_checkpoint_digest()?
        {
            return Err(AwinError::InvalidCheckpoint);
        }
        if self.next_sequence == 0 || self.deliveries.len() as u64 >= self.next_sequence {
            return Err(AwinError::InvalidCheckpoint);
        }
        for (index, delivery) in &self.deliveries {
            if *index != delivery.sequence
                || delivery
                    .validate_against(&self.scope, &self.plan, &self.generation)
                    .is_err()
            {
                return Err(AwinError::InvalidCheckpoint);
            }
            let expected_input = if *index == 1 {
                None
            } else {
                self.deliveries
                    .get(&index.saturating_sub(1))
                    .and_then(|previous| previous.next_cursor.clone())
            };
            if delivery.input_cursor != expected_input {
                return Err(AwinError::InvalidCheckpoint);
            }
            if self
                .evidence_nodes
                .get(index)
                .is_none_or(|node| !node.validate_against_delivery(delivery))
            {
                return Err(AwinError::InvalidCheckpoint);
            }
        }
        if self.evidence_nodes.len() != self.deliveries.len() {
            return Err(AwinError::InvalidCheckpoint);
        }
        let expected_pending = self
            .deliveries
            .values()
            .next_back()
            .and_then(|delivery| delivery.next_cursor.clone());
        if self.pending_cursor != expected_pending {
            return Err(AwinError::InvalidCheckpoint);
        }
        if let Some(root) = &self.evidence_root {
            if self.retry_after.is_some()
                || self.pending_cursor.is_some()
                || self.next_sequence != self.deliveries.len() as u64 + 1
            {
                return Err(AwinError::InvalidCheckpoint);
            }
            let nodes = self.evidence_nodes.values().cloned().collect::<Vec<_>>();
            root.validate_against(&self.scope, &self.plan, &self.generation, &nodes)?;
        }
        Ok(())
    }

    fn calculated_checkpoint_digest(&self) -> Result<String, AwinError> {
        let mut unsigned = self.clone();
        unsigned.checkpoint_digest.clear();
        let value = serde_json::to_value(unsigned).map_err(|_| AwinError::InvalidCheckpoint)?;
        Ok(sha256_json(&value))
    }
}

#[derive(Clone, Debug)]
pub struct AwinReconcileSession {
    scope: AwinScope,
    plan: AwinReadPlan,
    query_digest: String,
    generation: AwinProviderGeneration,
    authority: AwinReconcileAuthority,
    next_sequence: u64,
    pending_cursor: Option<AwinReconcileCursor>,
    deliveries: BTreeMap<u64, AwinPageDelivery>,
    evidence_nodes: BTreeMap<u64, AwinEvidenceNode>,
    retry_after: Option<DateTime<Utc>>,
    evidence_root: Option<AwinEvidenceRoot>,
}

impl AwinReconcileSession {
    pub fn new(
        scope: AwinScope,
        plan: AwinReadPlan,
        generation: AwinProviderGeneration,
        authority: AwinReconcileAuthority,
    ) -> Result<Self, AwinError> {
        plan.validate()?;
        generation.validate_scope(&scope)?;
        authority.ensure_generation(&generation)?;
        let query_digest = plan.query_digest(&scope)?;
        Ok(Self {
            scope,
            plan,
            query_digest,
            generation,
            authority,
            next_sequence: 1,
            pending_cursor: None,
            deliveries: BTreeMap::new(),
            evidence_nodes: BTreeMap::new(),
            retry_after: None,
            evidence_root: None,
        })
    }

    pub fn scope(&self) -> &AwinScope {
        &self.scope
    }

    pub fn plan(&self) -> &AwinReadPlan {
        &self.plan
    }

    pub fn query_digest(&self) -> &str {
        &self.query_digest
    }

    pub fn generation(&self) -> &AwinProviderGeneration {
        &self.generation
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn pending_cursor(&self) -> Option<&AwinReconcileCursor> {
        self.pending_cursor.as_ref()
    }

    pub fn deliveries(&self) -> impl Iterator<Item = &AwinPageDelivery> {
        self.deliveries.values()
    }

    pub fn evidence_root(&self) -> Option<&AwinEvidenceRoot> {
        self.evidence_root.as_ref()
    }

    pub fn accept(
        &mut self,
        delivery: AwinPageDelivery,
        at: DateTime<Utc>,
    ) -> Result<AwinReconcileOutcome, AwinError> {
        self.authority.validate(&self.generation)?;
        if self.evidence_root.is_some() {
            return Err(AwinError::EvidenceRootClosed);
        }
        delivery.validate_against(&self.scope, &self.plan, &self.generation)?;
        if let Some(existing) = self.deliveries.get(&delivery.sequence) {
            if existing.delivery_digest == delivery.delivery_digest {
                return Ok(AwinReconcileOutcome::Duplicate(self.delivery_receipt(
                    AwinDeliveryStatus::Duplicate,
                    delivery.sequence,
                    self.next_sequence,
                    self.next_sequence,
                    &delivery.idempotency_key,
                )));
            }
            return Err(AwinError::InvalidDelivery);
        }
        if self
            .deliveries
            .values()
            .any(|existing| existing.idempotency_key == delivery.idempotency_key)
        {
            return Err(AwinError::InvalidDelivery);
        }
        if at < delivery.observed_at || at >= delivery.valid_until {
            return Err(AwinError::Disconnected);
        }
        if self.retry_after.is_some_and(|retry_after| at < retry_after) {
            return Ok(AwinReconcileOutcome::RetryAfter(
                self.retry_after_receipt(delivery.sequence)?,
            ));
        }
        if delivery.sequence > self.next_sequence {
            return Ok(AwinReconcileOutcome::OutOfOrder(self.delivery_receipt(
                AwinDeliveryStatus::OutOfOrder,
                delivery.sequence,
                self.next_sequence,
                self.next_sequence,
                &delivery.idempotency_key,
            )));
        }
        if delivery.sequence < self.next_sequence {
            return Err(AwinError::InvalidDelivery);
        }
        if delivery.input_cursor != self.pending_cursor {
            return Err(AwinError::InvalidDelivery);
        }
        let sequence = delivery.sequence;
        let idempotency_key = delivery.idempotency_key.clone();
        let next_cursor = delivery.next_cursor.clone();
        let node = AwinEvidenceNode::from_delivery(&delivery);
        self.evidence_nodes.insert(sequence, node);
        self.deliveries.insert(sequence, delivery);
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.pending_cursor.clone_from(&next_cursor);
        self.retry_after = None;
        Ok(AwinReconcileOutcome::Applied(self.delivery_receipt(
            AwinDeliveryStatus::Applied,
            sequence,
            sequence,
            self.next_sequence,
            &idempotency_key,
        )))
    }

    pub fn record_rate_limit(
        &mut self,
        sequence: u64,
        retry_after: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> Result<AwinRetryAfterReceipt, AwinError> {
        self.authority.validate(&self.generation)?;
        if self.evidence_root.is_some() {
            return Err(AwinError::EvidenceRootClosed);
        }
        if sequence < self.next_sequence || retry_after <= at {
            return Err(AwinError::RateLimited);
        }
        if self
            .retry_after
            .is_none_or(|existing| retry_after > existing)
        {
            self.retry_after = Some(retry_after);
        }
        self.retry_after_receipt(sequence)
    }

    pub fn close_evidence(&mut self, at: DateTime<Utc>) -> Result<AwinEvidenceRoot, AwinError> {
        self.authority.validate(&self.generation)?;
        if self.evidence_root.is_some() {
            return Err(AwinError::EvidenceRootClosed);
        }
        if self.retry_after.is_some()
            || self.pending_cursor.is_some()
            || self.deliveries.is_empty()
            || self.next_sequence != self.deliveries.len() as u64 + 1
        {
            return Err(AwinError::EvidenceRootOpen);
        }
        let nodes = self.evidence_nodes.values().cloned().collect::<Vec<_>>();
        if nodes.len() != self.deliveries.len()
            || nodes
                .iter()
                .enumerate()
                .any(|(index, node)| node.sequence != index as u64 + 1)
            || nodes
                .iter()
                .any(|node| at < node.observed_at || at >= node.valid_until)
        {
            return Err(AwinError::EvidenceRootOpen);
        }
        let root = AwinEvidenceRoot::new(&self.scope, &self.plan, &self.generation, nodes, at)?;
        self.evidence_root = Some(root.clone());
        Ok(root)
    }

    pub fn closed_evidence_root(&self, at: DateTime<Utc>) -> Result<&AwinEvidenceRoot, AwinError> {
        self.authority.validate(&self.generation)?;
        let root = self
            .evidence_root
            .as_ref()
            .ok_or(AwinError::EvidenceRootOpen)?;
        if at < root.closed_at() {
            return Err(AwinError::EvidenceRootOpen);
        }
        Ok(root)
    }

    pub fn checkpoint(&self) -> Result<AwinReconcileCheckpoint, AwinError> {
        self.authority.validate(&self.generation)?;
        self.validate_state()?;
        let mut checkpoint = AwinReconcileCheckpoint {
            schema_version: AWIN_RECONCILE_SCHEMA_VERSION.to_owned(),
            scope: self.scope.clone(),
            plan: self.plan.clone(),
            generation: self.generation.clone(),
            next_sequence: self.next_sequence,
            pending_cursor: self.pending_cursor.clone(),
            deliveries: self.deliveries.clone(),
            evidence_nodes: self.evidence_nodes.clone(),
            retry_after: self.retry_after,
            evidence_root: self.evidence_root.clone(),
            checkpoint_digest: String::new(),
        };
        checkpoint.checkpoint_digest = checkpoint.calculated_checkpoint_digest()?;
        Ok(checkpoint)
    }

    pub fn reopen(
        checkpoint: AwinReconcileCheckpoint,
        scope: AwinScope,
        plan: AwinReadPlan,
        generation: AwinProviderGeneration,
        authority: AwinReconcileAuthority,
    ) -> Result<Self, AwinError> {
        checkpoint.validate()?;
        if checkpoint.scope != scope
            || checkpoint.plan != plan
            || checkpoint.generation != generation
        {
            return Err(AwinError::GenerationDrift);
        }
        let mut session = Self::new(scope, plan, generation, authority)?;
        session.next_sequence = checkpoint.next_sequence;
        session.pending_cursor = checkpoint.pending_cursor;
        session.deliveries = checkpoint.deliveries;
        session.evidence_nodes = checkpoint.evidence_nodes;
        session.retry_after = checkpoint.retry_after;
        session.evidence_root = checkpoint.evidence_root;
        session.validate_state()?;
        Ok(session)
    }

    fn delivery_receipt(
        &self,
        status: AwinDeliveryStatus,
        sequence: u64,
        expected_sequence: u64,
        next_sequence: u64,
        idempotency_key: &str,
    ) -> AwinDeliveryReceipt {
        let status_digest = format!("{status:?}");
        let evidence_root_digest = self
            .evidence_root
            .as_ref()
            .map(|root| root.root_digest().to_owned());
        let receipt_digest = digest_parts([
            AWIN_RECONCILE_SCHEMA_VERSION,
            &status_digest,
            &sequence.to_string(),
            &expected_sequence.to_string(),
            &next_sequence.to_string(),
            idempotency_key,
            self.generation.digest(),
            evidence_root_digest.as_deref().unwrap_or(""),
        ]);
        AwinDeliveryReceipt {
            status,
            sequence,
            expected_sequence,
            next_sequence,
            idempotency_key: idempotency_key.to_owned(),
            generation_digest: self.generation.digest().to_owned(),
            evidence_root_digest,
            receipt_digest,
        }
    }

    fn retry_after_receipt(&self, sequence: u64) -> Result<AwinRetryAfterReceipt, AwinError> {
        let retry_after = self.retry_after.ok_or(AwinError::StatePoisoned)?;
        let receipt_digest = digest_parts([
            AWIN_RECONCILE_SCHEMA_VERSION,
            "retry_after",
            &sequence.to_string(),
            &self.next_sequence.to_string(),
            &retry_after.to_rfc3339(),
            self.generation.digest(),
        ]);
        Ok(AwinRetryAfterReceipt {
            sequence,
            expected_sequence: self.next_sequence,
            retry_after,
            generation_digest: self.generation.digest().to_owned(),
            receipt_digest,
        })
    }

    fn validate_state(&self) -> Result<(), AwinError> {
        self.plan.validate()?;
        self.generation.validate_scope(&self.scope)?;
        if self.query_digest != self.plan.query_digest(&self.scope)?
            || self.next_sequence == 0
            || self.deliveries.len() as u64 >= self.next_sequence
        {
            return Err(AwinError::InvalidCheckpoint);
        }
        for (index, delivery) in &self.deliveries {
            if *index != delivery.sequence
                || *index == 0
                || *index >= self.next_sequence
                || delivery
                    .validate_against(&self.scope, &self.plan, &self.generation)
                    .is_err()
            {
                return Err(AwinError::InvalidCheckpoint);
            }
            let expected_input = if *index == 1 {
                None
            } else {
                self.deliveries
                    .get(&index.saturating_sub(1))
                    .and_then(|previous| previous.next_cursor.clone())
            };
            if delivery.input_cursor != expected_input {
                return Err(AwinError::InvalidCheckpoint);
            }
        }
        if self.evidence_nodes.len() != self.deliveries.len()
            || self.evidence_nodes.iter().any(|(index, node)| {
                self.deliveries
                    .get(index)
                    .is_none_or(|delivery| !node.validate_against_delivery(delivery))
            })
        {
            return Err(AwinError::InvalidCheckpoint);
        }
        let expected_pending = self
            .deliveries
            .values()
            .next_back()
            .and_then(|delivery| delivery.next_cursor.clone());
        if self.pending_cursor != expected_pending {
            return Err(AwinError::InvalidCheckpoint);
        }
        if let Some(root) = &self.evidence_root
            && (self.retry_after.is_some()
                || self.pending_cursor.is_some()
                || root.nodes.len() != self.evidence_nodes.len()
                || root.nodes != self.evidence_nodes.values().cloned().collect::<Vec<_>>())
        {
            return Err(AwinError::InvalidCheckpoint);
        }
        if let Some(root) = &self.evidence_root {
            let nodes = self.evidence_nodes.values().cloned().collect::<Vec<_>>();
            root.validate_against(&self.scope, &self.plan, &self.generation, &nodes)?;
        }
        Ok(())
    }
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
    reconcile_authority: AwinReconcileAuthority,
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
            reconcile_authority: AwinReconcileAuthority::new(),
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

    pub fn reconcile_authority(&self) -> &AwinReconcileAuthority {
        &self.reconcile_authority
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
        self.reconcile_authority.invalidate()?;
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
        self.reconcile_authority.invalidate()?;
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
        self.reconcile_authority.invalidate()?;
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
        let receipt = AwinProbeReceipt {
            credential_revision: observation.credential_revision,
            connector_result,
            observation,
        };
        if receipt.observation.status == AwinProbeStatus::Reachable
            && receipt.observation.classification == AwinObservationClassification::FirstParty
        {
            let generation = AwinProviderGeneration::from_probe(&self.scope, &receipt)?;
            self.reconcile_authority.bind(&generation)?;
        }
        self.probe_result = Some(receipt.connector_result.clone());
        Ok(receipt)
    }

    pub fn reconcile_session(
        &self,
        probe: &AwinProbeReceipt,
    ) -> Result<AwinReconcileSession, AwinError> {
        self.ensure_mounted()?;
        if self.probe_result.as_ref() != Some(&probe.connector_result) {
            return Err(AwinError::GenerationDrift);
        }
        let generation = AwinProviderGeneration::from_probe(&self.scope, probe)?;
        AwinReconcileSession::new(
            self.scope.clone(),
            self.plan.clone(),
            generation,
            self.reconcile_authority.clone(),
        )
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
        self.reconcile_authority.invalidate()?;
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

#[derive(Clone, Debug)]
pub struct AwinMissionReconcileExpectation {
    pub base: AwinMissionReadExpectation,
    pub generation_digest: String,
    pub provider_generation: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwinMissionReconcileResult {
    pub mission_id: String,
    pub mission_revision: u64,
    pub provider_id: String,
    pub publisher_id: AwinPublisherId,
    pub advertiser_id: Option<AwinAdvertiserId>,
    pub program_id: Option<AwinProgramId>,
    pub credential_revision: u64,
    pub probe_revision: u64,
    pub provider_generation: u64,
    pub generation_digest: String,
    pub evidence_root_digest: String,
    pub page_count: u64,
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

    pub fn consume_reconciled(
        &self,
        mission: &Mission,
        scope: &AwinScope,
        session: &AwinReconcileSession,
        expected: &AwinMissionReconcileExpectation,
        at: DateTime<Utc>,
    ) -> Result<AwinMissionReconcileResult, AwinError> {
        mission
            .contract
            .validate(at)
            .map_err(|error| AwinError::Mission(error.to_string()))?;
        let root = session.closed_evidence_root(at)?;
        let generation = session.generation();
        let scope_digest = scope.digest()?;
        let exact =
            session.scope() == scope
                && expected.base.mission_id == mission.id.as_str()
                && expected.base.mission_revision == mission.revision
                && mission.tenant_id.as_str() == scope.tenant_id()
                && mission.project_id.as_str() == scope.project_id()
                && mission
                    .contract
                    .enabled_capabilities
                    .contains(AWIN_MISSION_CAPABILITY)
                && expected.base.provider_id == AWIN_PROVIDER_ID
                && expected.base.publisher_id == *scope.publisher_id()
                && expected.base.advertiser_id == scope.advertiser_id().cloned()
                && expected.base.program_id == scope.program_id().cloned()
                && expected.base.capability == session.plan.resource.capability()
                && expected.base.credential_revision == generation.credential_revision()
                && expected.base.probe_revision == generation.probe_revision()
                && session.deliveries.values().next().is_some_and(|delivery| {
                    expected.base.source_revision == delivery.source_revision
                })
                && expected.generation_digest == generation.digest()
                && expected.provider_generation == generation.provider_generation()
                && generation.provider_id() == AWIN_PROVIDER_ID
                && generation.publisher_id() == scope.publisher_id()
                && generation.advertiser_id() == scope.advertiser_id()
                && generation.program_id() == scope.program_id()
                && root.schema_version == AWIN_RECONCILE_SCHEMA_VERSION
                && root.scope_digest == scope_digest
                && root.generation_digest == generation.digest()
                && root.provider_generation == generation.provider_generation()
                && root.resource == session.plan.resource
                && root.query_digest == session.query_digest
                && !root.nodes.is_empty();
        if !exact {
            return Err(AwinError::MissionBinding);
        }
        let result_digest = digest_parts([
            AWIN_RECONCILE_SCHEMA_VERSION,
            mission.id.as_str(),
            &mission.revision.to_string(),
            scope_digest.as_str(),
            generation.digest(),
            root.root_digest(),
            &root.nodes.len().to_string(),
        ]);
        Ok(AwinMissionReconcileResult {
            mission_id: mission.id.as_str().to_owned(),
            mission_revision: mission.revision,
            provider_id: AWIN_PROVIDER_ID.to_owned(),
            publisher_id: scope.publisher_id().clone(),
            advertiser_id: scope.advertiser_id().cloned(),
            program_id: scope.program_id().cloned(),
            credential_revision: generation.credential_revision(),
            probe_revision: generation.probe_revision(),
            provider_generation: generation.provider_generation(),
            generation_digest: generation.digest().to_owned(),
            evidence_root_digest: root.root_digest().to_owned(),
            page_count: root.nodes.len() as u64,
            result_digest,
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

fn is_provider_source_uri(value: &str) -> bool {
    value.starts_with(AWIN_API_BASE_URL) || {
        #[cfg(test)]
        {
            value.starts_with("http://127.0.0.1:")
        }
        #[cfg(not(test))]
        {
            false
        }
    }
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
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    const NOW: &str = "2026-08-14T00:00:00Z";

    struct LoopbackServer {
        base_url: String,
        join: Option<JoinHandle<()>>,
    }

    impl LoopbackServer {
        fn start(expected_requests: usize) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener");
            let port = listener.local_addr().expect("loopback address").port();
            let join = thread::spawn(move || {
                for _ in 0..expected_requests {
                    let (mut stream, _) = listener.accept().expect("loopback request");
                    let request = read_http_request(&mut stream);
                    let body = loopback_response(&request);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("loopback response");
                    stream.flush().expect("loopback flush");
                }
            });
            Self {
                base_url: format!("http://127.0.0.1:{port}"),
                join: Some(join),
            }
        }

        fn base_url(&self) -> &str {
            &self.base_url
        }

        fn finish(mut self) {
            self.join
                .take()
                .expect("loopback join handle")
                .join()
                .expect("loopback server");
        }
    }

    fn read_http_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let count = stream.read(&mut buffer).expect("loopback request bytes");
            assert!(count > 0, "loopback request ended before headers");
            bytes.extend_from_slice(&buffer[..count]);
            assert!(
                bytes.len() <= 16 * 1024,
                "loopback request headers too large"
            );
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(bytes).expect("loopback request utf8")
    }

    fn loopback_response(request: &str) -> String {
        let mut lines = request.split("\r\n");
        let request_line = lines.next().expect("loopback request line");
        let mut request_parts = request_line.split_whitespace();
        assert_eq!(request_parts.next(), Some("GET"));
        let target = request_parts.next().expect("loopback target");
        assert_eq!(request_parts.next(), Some("HTTP/1.1"));
        let (path, query) = target.split_once('?').expect("loopback query");

        let headers = lines
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer fixture-token")
        );
        assert_eq!(
            headers.get("accept").map(String::as_str),
            Some("application/json")
        );

        let query = form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect::<BTreeMap<_, _>>();
        match path {
            "/publishers/123/programmedetails" => {
                assert_eq!(query.len(), 2);
                assert_eq!(query.get("advertiserId").map(String::as_str), Some("100"));
                assert_eq!(query.get("relationship").map(String::as_str), Some("any"));
                serde_json::json!({
                    "programmes": [{
                        "advertiserId": 100,
                        "publisherId": 123,
                        "programId": 100
                    }]
                })
            }
            "/publishers/123/transactions/" => {
                assert_eq!(query.len(), 5);
                assert_eq!(query.get("advertiserId").map(String::as_str), Some("100"));
                assert_eq!(query.get("timezone").map(String::as_str), Some("UTC"));
                assert_eq!(
                    query.get("showBasketProducts").map(String::as_str),
                    Some("false")
                );
                let start = DateTime::parse_from_rfc3339(
                    query.get("startDate").expect("transaction start"),
                )
                .expect("transaction start timestamp")
                .with_timezone(&Utc);
                let end =
                    DateTime::parse_from_rfc3339(query.get("endDate").expect("transaction end"))
                        .expect("transaction end timestamp")
                        .with_timezone(&Utc);
                assert_eq!(end - start, Duration::days(31));
                let sequence = if start == now() {
                    1
                } else if start == now() + Duration::days(31) {
                    2
                } else {
                    panic!("unexpected Awin transaction window: {start}");
                };
                serde_json::json!({
                    "data": [{
                        "advertiserId": 100,
                        "publisherId": 123,
                        "programId": 100,
                        "transactionId": format!("awin-loopback-{sequence}"),
                        "window": sequence
                    }]
                })
            }
            _ => panic!("unexpected Awin loopback path: {path}"),
        }
        .to_string()
    }

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
        auth_material_with_revision(scope, 7)
    }

    fn auth_material_with_revision(
        scope: &AwinScope,
        credential_revision: u64,
    ) -> (SecretReference, CredentialLease) {
        let connector_scope = scope.connector_scope().expect("connector scope");
        let secret = SecretReference::new(
            format!("secret-ref-awin-test-{credential_revision}"),
            connector_scope,
            credential_revision,
        )
        .expect("secret reference");
        let adapter =
            ProviderAdapterIdentity::new(AWIN_ADAPTER_ID, AWIN_ADAPTER_VERSION).expect("adapter");
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            adapter,
            format!("lease-awin-test-{credential_revision}"),
            credential_revision,
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn official_http_loopback_transaction_windows_reconcile_exactly_once() {
        let server = LoopbackServer::start(3);
        assert!(matches!(
            AwinHttpTransport::new(server.base_url()),
            Err(AwinError::InvalidTransportBaseUrl)
        ));
        let transport = AwinHttpTransport::loopback(server.base_url()).expect("loopback transport");
        let mut service = AwinService::new(
            "worker-awin-loopback",
            scope(),
            plan(),
            transport,
            ContractResolver { available: true },
            now(),
            now() + Duration::minutes(10),
            budget(),
        )
        .expect("loopback service");
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("loopback auth");
        let probe = service
            .probe(1, "probe-result-awin-loopback", now())
            .expect("loopback probe");
        assert_eq!(
            probe.observation.classification,
            AwinObservationClassification::FirstParty
        );
        assert!(
            probe
                .observation
                .source_uri
                .starts_with("http://127.0.0.1:")
        );

        let first = service
            .read(None, 100, now())
            .expect("loopback first transaction window");
        let first_cursor = first.envelope.cursor.clone().expect("loopback cursor");
        let second = service
            .read(Some(&first_cursor), 100, now())
            .expect("loopback second transaction window");
        assert_eq!(first.envelope.publisher_id, *service.scope().publisher_id());
        assert_eq!(
            first.envelope.advertiser_id,
            service.scope().advertiser_id().cloned()
        );
        assert_eq!(
            first.envelope.program_id,
            service.scope().program_id().cloned()
        );
        assert_eq!(
            first
                .envelope
                .cursor
                .as_ref()
                .map(AwinDurableCursor::sequence),
            Some(1)
        );
        assert!(second.envelope.cursor.is_none());
        assert_eq!(service.budget().cost_used_units(), AWIN_READ_COST_UNITS * 2);
        assert_eq!(first.envelope.cost.cost_units, AWIN_READ_COST_UNITS);
        assert_eq!(second.envelope.cost.cost_units, AWIN_READ_COST_UNITS);

        let generation =
            AwinProviderGeneration::from_probe(service.scope(), &probe).expect("generation");
        let input_cursor = AwinReconcileCursor::from_durable(
            first_cursor,
            service.scope(),
            service.plan(),
            &generation,
        )
        .expect("reconcile cursor");
        let first_delivery = AwinPageDelivery::from_read(
            service.scope(),
            service.plan(),
            &generation,
            None,
            &first,
            now(),
        )
        .expect("first delivery");
        let second_delivery = AwinPageDelivery::from_read(
            service.scope(),
            service.plan(),
            &generation,
            Some(&input_cursor),
            &second,
            now(),
        )
        .expect("second delivery");
        let mut session = service.reconcile_session(&probe).expect("session");
        assert!(matches!(
            session.accept(second_delivery.clone(), now()),
            Ok(AwinReconcileOutcome::OutOfOrder(_))
        ));
        assert!(matches!(
            session.accept(first_delivery.clone(), now()),
            Ok(AwinReconcileOutcome::Applied(_))
        ));
        assert!(matches!(
            session.accept(first_delivery, now()),
            Ok(AwinReconcileOutcome::Duplicate(_))
        ));
        assert!(matches!(
            session.accept(second_delivery.clone(), now()),
            Ok(AwinReconcileOutcome::Applied(_))
        ));
        assert!(matches!(
            session.accept(second_delivery, now()),
            Ok(AwinReconcileOutcome::Duplicate(_))
        ));
        let root = session.close_evidence(now()).expect("closed evidence");
        assert!(root.is_closed());
        assert_eq!(root.nodes().len(), 2);

        let mission = Mission::compile(
            TenantId::from("tenant-awin"),
            MissionId::from("mission-awin-loopback"),
            ProjectId::from("project-awin"),
            "Reconcile Awin loopback transactions",
            MissionContract::bootstrap(
                "Reconcile Awin loopback transactions",
                [AWIN_MISSION_CAPABILITY.to_owned()],
                now(),
            ),
            now(),
        )
        .expect("loopback mission");
        let expected = AwinMissionReconcileExpectation {
            base: AwinMissionReadExpectation {
                mission_id: mission.id.as_str().to_owned(),
                mission_revision: mission.revision,
                provider_id: AWIN_PROVIDER_ID.to_owned(),
                publisher_id: scope().publisher_id().clone(),
                advertiser_id: scope().advertiser_id().cloned(),
                program_id: scope().program_id().cloned(),
                credential_revision: probe.credential_revision,
                probe_revision: probe.connector_result.probe_revision(),
                source_revision: first.envelope.source_revision,
                capability: first.envelope.resource.capability().to_owned(),
            },
            generation_digest: generation.digest().to_owned(),
            provider_generation: generation.provider_generation(),
        };
        let result = AwinMissionConsumer
            .consume_reconciled(&mission, service.scope(), &session, &expected, now())
            .expect("loopback Mission result");
        assert_eq!(result.page_count, 2);
        assert_eq!(result.provider_id, AWIN_PROVIDER_ID);
        assert_eq!(result.publisher_id, *service.scope().publisher_id());
        server.finish();
    }

    #[test]
    fn reconcile_deduplicates_and_rejects_out_of_order_pages_exactly_once() {
        let mut service = service(ContractResolver { available: true });
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(1, "probe-result-awin-reconcile-order", now())
            .expect("probe");
        let generation =
            AwinProviderGeneration::from_probe(service.scope(), &probe).expect("generation");
        let first = service.read(None, 100, now()).expect("first read");
        let first_cursor = first.envelope.cursor.clone().expect("continuation");
        let second = service
            .read(Some(&first_cursor), 100, now())
            .expect("second read");
        let input_cursor = AwinReconcileCursor::from_durable(
            first_cursor,
            service.scope(),
            service.plan(),
            &generation,
        )
        .expect("input cursor");
        let first_delivery = AwinPageDelivery::from_read(
            service.scope(),
            service.plan(),
            &generation,
            None,
            &first,
            now(),
        )
        .expect("first delivery");
        let second_delivery = AwinPageDelivery::from_read(
            service.scope(),
            service.plan(),
            &generation,
            Some(&input_cursor),
            &second,
            now(),
        )
        .expect("second delivery");
        let mut session = service.reconcile_session(&probe).expect("session");

        let out_of_order = session
            .accept(second_delivery.clone(), now())
            .expect("out-of-order receipt");
        let AwinReconcileOutcome::OutOfOrder(receipt) = out_of_order else {
            panic!("page two must not apply before page one");
        };
        assert_eq!(receipt.status(), &AwinDeliveryStatus::OutOfOrder);
        assert_eq!(session.next_sequence(), 1);

        let applied_first = session
            .accept(first_delivery.clone(), now())
            .expect("first apply");
        assert!(matches!(applied_first, AwinReconcileOutcome::Applied(_)));
        let duplicate_first = session
            .accept(first_delivery, now())
            .expect("first duplicate receipt");
        assert!(matches!(
            duplicate_first,
            AwinReconcileOutcome::Duplicate(_)
        ));
        let applied_second = session
            .accept(second_delivery.clone(), now())
            .expect("second apply");
        assert!(matches!(applied_second, AwinReconcileOutcome::Applied(_)));
        let duplicate_second = session
            .accept(second_delivery, now())
            .expect("second duplicate receipt");
        assert!(matches!(
            duplicate_second,
            AwinReconcileOutcome::Duplicate(_)
        ));

        let root = session.close_evidence(now()).expect("closed evidence");
        assert!(root.is_closed());
        assert_eq!(root.nodes().len(), 2);
        assert_eq!(root.nodes()[0].sequence(), 1);
        assert_eq!(root.nodes()[1].sequence(), 2);
        assert!(matches!(
            session.accept(
                AwinPageDelivery::from_read(
                    service.scope(),
                    service.plan(),
                    &generation,
                    None,
                    &first,
                    now(),
                )
                .expect("closed duplicate"),
                now(),
            ),
            Err(AwinError::EvidenceRootClosed)
        ));
    }

    #[test]
    fn reconcile_retry_after_checkpoint_reopen_resumes_without_replaying() {
        let mut service = service(ContractResolver { available: true });
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(1, "probe-result-awin-reconcile-reopen", now())
            .expect("probe");
        let generation =
            AwinProviderGeneration::from_probe(service.scope(), &probe).expect("generation");
        let first = service.read(None, 100, now()).expect("first read");
        let first_cursor = first.envelope.cursor.clone().expect("continuation");
        let second = service
            .read(Some(&first_cursor), 100, now())
            .expect("second read");
        let input_cursor = AwinReconcileCursor::from_durable(
            first_cursor,
            service.scope(),
            service.plan(),
            &generation,
        )
        .expect("input cursor");
        let first_delivery = AwinPageDelivery::from_read(
            service.scope(),
            service.plan(),
            &generation,
            None,
            &first,
            now(),
        )
        .expect("first delivery");
        let second_delivery = AwinPageDelivery::from_read(
            service.scope(),
            service.plan(),
            &generation,
            Some(&input_cursor),
            &second,
            now(),
        )
        .expect("second delivery");
        let mut session = service.reconcile_session(&probe).expect("session");
        let retry = session
            .record_rate_limit(1, now() + Duration::seconds(30), now())
            .expect("retry receipt");
        assert_eq!(retry.expected_sequence(), 1);
        assert_eq!(retry.retry_after(), now() + Duration::seconds(30));
        assert!(matches!(
            session.accept(first_delivery.clone(), now() + Duration::seconds(10)),
            Ok(AwinReconcileOutcome::RetryAfter(_))
        ));
        assert!(matches!(
            session.accept(first_delivery.clone(), now() + Duration::seconds(31)),
            Ok(AwinReconcileOutcome::Applied(_))
        ));

        let checkpoint = session.checkpoint().expect("checkpoint");
        let encoded = serde_json::to_string(&checkpoint).expect("checkpoint encoding");
        assert!(!encoded.contains("fixture-token"));
        let mut reopened = AwinReconcileSession::reopen(
            checkpoint,
            service.scope().clone(),
            service.plan().clone(),
            generation,
            service.reconcile_authority().clone(),
        )
        .expect("reopen");
        assert_eq!(reopened.next_sequence(), 2);
        assert!(matches!(
            reopened.accept(first_delivery, now() + Duration::seconds(31)),
            Ok(AwinReconcileOutcome::Duplicate(_))
        ));
        assert!(matches!(
            reopened.accept(second_delivery, now() + Duration::seconds(31)),
            Ok(AwinReconcileOutcome::Applied(_))
        ));
        assert_eq!(
            reopened
                .close_evidence(now() + Duration::seconds(31))
                .expect("closed evidence")
                .nodes()
                .len(),
            2
        );
    }

    #[test]
    fn mission_reconcile_requires_closed_complete_evidence_root() {
        let mut service = service(ContractResolver { available: true });
        let (secret, lease) = auth_material(service.scope());
        service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(9, "probe-result-awin-reconcile-mission", now())
            .expect("probe");
        let generation =
            AwinProviderGeneration::from_probe(service.scope(), &probe).expect("generation");
        let first = service.read(None, 100, now()).expect("first read");
        let first_cursor = first.envelope.cursor.clone().expect("continuation");
        let second = service
            .read(Some(&first_cursor), 100, now())
            .expect("second read");
        let input_cursor = AwinReconcileCursor::from_durable(
            first_cursor,
            service.scope(),
            service.plan(),
            &generation,
        )
        .expect("input cursor");
        let first_delivery = AwinPageDelivery::from_read(
            service.scope(),
            service.plan(),
            &generation,
            None,
            &first,
            now(),
        )
        .expect("first delivery");
        let second_delivery = AwinPageDelivery::from_read(
            service.scope(),
            service.plan(),
            &generation,
            Some(&input_cursor),
            &second,
            now(),
        )
        .expect("second delivery");
        let mut session = service.reconcile_session(&probe).expect("session");
        session.accept(first_delivery, now()).expect("first apply");
        session
            .accept(second_delivery, now())
            .expect("second apply");
        let mission = Mission::compile(
            TenantId::from("tenant-awin"),
            MissionId::from("mission-awin-reconcile"),
            ProjectId::from("project-awin"),
            "Reconcile Awin report",
            MissionContract::bootstrap(
                "Reconcile Awin partner data",
                [AWIN_MISSION_CAPABILITY.to_owned()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        let expected = AwinMissionReconcileExpectation {
            base: AwinMissionReadExpectation {
                mission_id: mission.id.as_str().to_owned(),
                mission_revision: mission.revision,
                provider_id: AWIN_PROVIDER_ID.to_owned(),
                publisher_id: scope().publisher_id().clone(),
                advertiser_id: scope().advertiser_id().cloned(),
                program_id: scope().program_id().cloned(),
                credential_revision: generation.credential_revision(),
                probe_revision: generation.probe_revision(),
                source_revision: first.envelope.source_revision,
                capability: first.envelope.resource.capability().to_owned(),
            },
            generation_digest: generation.digest().to_owned(),
            provider_generation: generation.provider_generation(),
        };
        assert!(matches!(
            AwinMissionConsumer.consume_reconciled(
                &mission,
                service.scope(),
                &session,
                &expected,
                now(),
            ),
            Err(AwinError::EvidenceRootOpen)
        ));
        session.close_evidence(now()).expect("evidence close");
        let result = AwinMissionConsumer
            .consume_reconciled(&mission, service.scope(), &session, &expected, now())
            .expect("closed mission result");
        assert_eq!(result.page_count, 2);
        assert_eq!(result.provider_id, AWIN_PROVIDER_ID);
        assert_eq!(result.credential_revision, 7);
    }

    #[test]
    fn credential_rotation_revoke_and_unmount_fence_old_reconcile_cursors() {
        let mut service = service(ContractResolver { available: true });
        let (secret, lease) = auth_material(service.scope());
        let auth_session = service
            .begin_auth(secret, lease, 1, now(), now() + Duration::minutes(5))
            .expect("auth metadata");
        let probe = service
            .probe(1, "probe-result-awin-reconcile-fence", now())
            .expect("probe");
        let generation =
            AwinProviderGeneration::from_probe(service.scope(), &probe).expect("generation");
        let first = service.read(None, 100, now()).expect("read");
        let mut session = service.reconcile_session(&probe).expect("session");
        let first_delivery = AwinPageDelivery::from_read(
            service.scope(),
            service.plan(),
            &generation,
            None,
            &first,
            now(),
        )
        .expect("delivery");
        session.accept(first_delivery, now()).expect("apply");
        let checkpoint = session.checkpoint().expect("checkpoint");
        let (rotated_secret, rotated_lease) = auth_material_with_revision(service.scope(), 8);
        service
            .refresh_auth(
                rotated_secret,
                rotated_lease,
                auth_session,
                2,
                now(),
                now() + Duration::minutes(5),
            )
            .expect("credential rotation");
        assert!(matches!(
            session.record_rate_limit(2, now() + Duration::seconds(30), now()),
            Err(AwinError::GenerationDrift)
        ));
        assert!(matches!(
            AwinReconcileSession::reopen(
                checkpoint,
                service.scope().clone(),
                service.plan().clone(),
                generation,
                service.reconcile_authority().clone(),
            ),
            Err(AwinError::GenerationDrift)
        ));
        service.revoke("rotation-revoke", now()).expect("revoke");
        assert!(matches!(
            session.record_rate_limit(2, now() + Duration::seconds(30), now()),
            Err(AwinError::GenerationDrift)
        ));
        service.unmount(now()).expect("unmount");
        assert!(matches!(
            session.record_rate_limit(2, now() + Duration::seconds(30), now()),
            Err(AwinError::GenerationDrift)
        ));
    }
}
