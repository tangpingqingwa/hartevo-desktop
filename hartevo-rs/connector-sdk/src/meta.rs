//! Meta Graph / Instagram Graph authenticated insight-read boundary.
//!
//! This module is intentionally self-contained. It does not copy the old
//! generic paid-social abstraction and it does not register a provider in the
//! central adapter registry. A successful provider probe produces a
//! mount-scoped, read-only observation; it never upgrades the connection to
//! Connected or grants Effect authority.

use chrono::{DateTime, Duration, Utc};
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ConnectorError, ConnectorScope, CredentialLease, FreshnessWindow, ProviderProvenanceClass,
    SecretReference,
};

pub const META_ADAPTER_ID: &str = "meta.graph.instagram-insight-read";
pub const META_ADAPTER_VERSION: u32 = 1;
pub const META_INSIGHT_READ_SCHEMA: &str = "hartevo-meta-instagram-insight-read/v1";
pub const META_SERVICE_ID: &str = "PaidSocialInsightReadService";
pub const META_PROVIDER_ID: &str = "meta";
pub const META_ACCESS_TOKEN_ENV: &str = "HARTEVO_META_ACCESS_TOKEN";
pub const META_APP_SECRET_ENV: &str = "HARTEVO_META_APP_SECRET";
pub const META_RUN_PROBE_ENV: &str = "HARTEVO_RUN_META_CREDENTIAL_PROBE";
pub const META_RUN_WEBHOOK_RECONCILE_ENV: &str = "HARTEVO_RUN_META_WEBHOOK_RECONCILE";
pub const META_WEBHOOK_SUBSCRIPTION_ENV: &str = "HARTEVO_META_WEBHOOK_SUBSCRIPTION_ID";
pub const META_API_VERSION_ENV: &str = "HARTEVO_META_API_VERSION";
pub const META_DEFAULT_API_VERSION: &str = "v25.0";
pub const META_FACEBOOK_GRAPH_HOST: &str = "https://graph.facebook.com";
pub const META_INSTAGRAM_GRAPH_HOST: &str = "https://graph.instagram.com";
pub const META_REGISTRATIONS: &[()] = &[];
pub const META_WEBHOOK_REGISTRATIONS: &[()] = &[];

const MAX_CURSOR_BYTES: usize = 4096;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_WEBHOOK_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_FRESHNESS_SECONDS: i64 = 900;
const META_WEBHOOK_SCHEMA: &str = "hartevo-meta-instagram-webhook-reconcile/v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaGraphHost {
    Facebook,
    Instagram,
}

impl MetaGraphHost {
    pub const fn base_url(self) -> &'static str {
        match self {
            Self::Facebook => META_FACEBOOK_GRAPH_HOST,
            Self::Instagram => META_INSTAGRAM_GRAPH_HOST,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaApiBinding {
    pub host: MetaGraphHost,
    pub api_version: String,
}

impl MetaApiBinding {
    pub fn new(
        host: MetaGraphHost,
        api_version: impl Into<String>,
    ) -> Result<Self, MetaConnectorError> {
        let api_version = api_version.into();
        if !valid_api_version(&api_version) {
            return Err(MetaConnectorError::InvalidApiVersion);
        }
        Ok(Self { host, api_version })
    }

    pub fn from_env(host: MetaGraphHost) -> Result<Self, MetaConnectorError> {
        let version = std::env::var(META_API_VERSION_ENV)
            .unwrap_or_else(|_| META_DEFAULT_API_VERSION.to_owned());
        Self::new(host, version)
    }

    pub fn digest(&self) -> String {
        sha256(&format!("{}:{}", self.host.base_url(), self.api_version))
    }

    pub fn versioned_path(&self, path: &str) -> String {
        format!("/{}/{}", self.api_version, path.trim_start_matches('/'))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct MetaScope {
    business_id: String,
    ad_account_id: Option<String>,
    page_id: Option<String>,
    instagram_account_id: Option<String>,
}

impl MetaScope {
    pub fn new(
        business_id: impl Into<String>,
        ad_account_id: Option<String>,
        page_id: Option<String>,
        instagram_account_id: Option<String>,
    ) -> Result<Self, MetaConnectorError> {
        let scope = Self {
            business_id: business_id.into(),
            ad_account_id: ad_account_id
                .map(|value| normalize_ad_account(&value))
                .transpose()?,
            page_id,
            instagram_account_id,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn business_id(&self) -> &str {
        &self.business_id
    }

    pub fn ad_account_id(&self) -> Option<&str> {
        self.ad_account_id.as_deref()
    }

    pub fn page_id(&self) -> Option<&str> {
        self.page_id.as_deref()
    }

    pub fn instagram_account_id(&self) -> Option<&str> {
        self.instagram_account_id.as_deref()
    }

    pub fn digest(&self) -> String {
        sha256(
            &serde_json::to_string(self)
                .expect("MetaScope only contains infallible JSON scalar fields"),
        )
    }

    fn validate(&self) -> Result<(), MetaConnectorError> {
        if !numeric_id(&self.business_id)
            || self
                .ad_account_id
                .as_deref()
                .is_some_and(|id| normalize_ad_account(id).is_err())
            || self.page_id.as_deref().is_some_and(|id| !numeric_id(id))
            || self
                .instagram_account_id
                .as_deref()
                .is_some_and(|id| !numeric_id(id))
        {
            return Err(MetaConnectorError::InvalidScope);
        }
        Ok(())
    }

    fn validate_against_connector(&self, scope: &ConnectorScope) -> Result<(), MetaConnectorError> {
        if scope.provider_id() != META_PROVIDER_ID || scope.account_id() != self.business_id {
            return Err(MetaConnectorError::ScopeMismatch);
        }
        Ok(())
    }
}

fn has_any_scope(scope: &ConnectorScope, required: &[&str]) -> bool {
    required
        .iter()
        .any(|required| scope.scopes().iter().any(|granted| granted == required))
}

fn validate_probe_permissions(
    connector_scope: &ConnectorScope,
    meta_scope: &MetaScope,
    api: &MetaApiBinding,
) -> Result<(), MetaConnectorError> {
    match api.host {
        MetaGraphHost::Facebook => {
            if !has_any_scope(connector_scope, &["business_management"]) {
                return Err(MetaConnectorError::PermissionDenied);
            }
            if meta_scope.ad_account_id().is_some()
                && !has_any_scope(connector_scope, &["ads_read", "ads_management"])
            {
                return Err(MetaConnectorError::PermissionDenied);
            }
            if meta_scope.page_id().is_some()
                && !has_any_scope(connector_scope, &["pages_read_engagement"])
            {
                return Err(MetaConnectorError::PermissionDenied);
            }
            if meta_scope.instagram_account_id().is_some()
                && (!has_any_scope(
                    connector_scope,
                    &["instagram_basic", "instagram_business_basic"],
                ) || !has_any_scope(
                    connector_scope,
                    &[
                        "instagram_manage_insights",
                        "instagram_business_manage_insights",
                    ],
                ))
            {
                return Err(MetaConnectorError::PermissionDenied);
            }
        }
        MetaGraphHost::Instagram => {
            if meta_scope.ad_account_id().is_some() || meta_scope.page_id().is_some() {
                return Err(MetaConnectorError::InvalidProviderRequest);
            }
            if meta_scope.instagram_account_id().is_none()
                || !has_any_scope(
                    connector_scope,
                    &["instagram_basic", "instagram_business_basic"],
                )
                || !has_any_scope(
                    connector_scope,
                    &[
                        "instagram_manage_insights",
                        "instagram_business_manage_insights",
                    ],
                )
            {
                return Err(MetaConnectorError::PermissionDenied);
            }
        }
    }
    Ok(())
}

fn validate_target_permissions(
    connector_scope: &ConnectorScope,
    target: &MetaReadTarget,
) -> Result<(), MetaConnectorError> {
    let allowed = match target {
        MetaReadTarget::BusinessFacts => has_any_scope(connector_scope, &["business_management"]),
        MetaReadTarget::AdAccountFacts | MetaReadTarget::AdAccountInsights => {
            has_any_scope(connector_scope, &["ads_read", "ads_management"])
        }
        MetaReadTarget::PageFacts | MetaReadTarget::PageInsights => {
            has_any_scope(connector_scope, &["pages_read_engagement"])
        }
        MetaReadTarget::InstagramAccountFacts
        | MetaReadTarget::InstagramAccountInsights
        | MetaReadTarget::InstagramMediaInsights { .. } => {
            has_any_scope(
                connector_scope,
                &["instagram_basic", "instagram_business_basic"],
            ) && has_any_scope(
                connector_scope,
                &[
                    "instagram_manage_insights",
                    "instagram_business_manage_insights",
                ],
            )
        }
    };
    allowed
        .then_some(())
        .ok_or(MetaConnectorError::PermissionDenied)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaReadTarget {
    BusinessFacts,
    AdAccountFacts,
    AdAccountInsights,
    PageFacts,
    PageInsights,
    InstagramAccountFacts,
    InstagramAccountInsights,
    InstagramMediaInsights { media_id: String },
}

impl MetaReadTarget {
    pub const fn is_facts(&self) -> bool {
        matches!(
            self,
            Self::BusinessFacts
                | Self::AdAccountFacts
                | Self::PageFacts
                | Self::InstagramAccountFacts
        )
    }

    pub const fn classification(&self) -> MetaSurface {
        match self {
            Self::BusinessFacts => MetaSurface::Business,
            Self::AdAccountFacts | Self::AdAccountInsights => MetaSurface::Marketing,
            Self::PageFacts | Self::PageInsights => MetaSurface::Page,
            Self::InstagramAccountFacts | Self::InstagramAccountInsights => {
                MetaSurface::InstagramAccount
            }
            Self::InstagramMediaInsights { .. } => MetaSurface::InstagramMedia,
        }
    }

    fn validate_scope(&self, scope: &MetaScope) -> Result<(), MetaConnectorError> {
        match self {
            Self::BusinessFacts => Ok(()),
            Self::AdAccountFacts | Self::AdAccountInsights => {
                if scope.ad_account_id().is_some() {
                    Ok(())
                } else {
                    Err(MetaConnectorError::ScopeMismatch)
                }
            }
            Self::PageFacts | Self::PageInsights => {
                if scope.page_id().is_some() {
                    Ok(())
                } else {
                    Err(MetaConnectorError::ScopeMismatch)
                }
            }
            Self::InstagramAccountFacts | Self::InstagramAccountInsights => {
                if scope.instagram_account_id().is_some() {
                    Ok(())
                } else {
                    Err(MetaConnectorError::ScopeMismatch)
                }
            }
            Self::InstagramMediaInsights { media_id } => {
                if scope.instagram_account_id().is_some() && numeric_id(media_id) {
                    Ok(())
                } else {
                    Err(MetaConnectorError::ScopeMismatch)
                }
            }
        }
    }

    fn object_path(&self, scope: &MetaScope) -> Result<String, MetaConnectorError> {
        self.validate_scope(scope)?;
        match self {
            Self::BusinessFacts => Ok(scope.business_id().to_owned()),
            Self::AdAccountFacts | Self::AdAccountInsights => Ok(scope
                .ad_account_id()
                .ok_or(MetaConnectorError::ScopeMismatch)?
                .to_owned()),
            Self::PageFacts | Self::PageInsights => Ok(scope
                .page_id()
                .ok_or(MetaConnectorError::ScopeMismatch)?
                .to_owned()),
            Self::InstagramAccountFacts | Self::InstagramAccountInsights => Ok(scope
                .instagram_account_id()
                .ok_or(MetaConnectorError::ScopeMismatch)?
                .to_owned()),
            Self::InstagramMediaInsights { media_id } => Ok(media_id.clone()),
        }
    }

    fn requires_facebook_host(&self) -> bool {
        matches!(
            self,
            Self::BusinessFacts
                | Self::AdAccountFacts
                | Self::AdAccountInsights
                | Self::PageFacts
                | Self::PageInsights
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaSurface {
    Business,
    Marketing,
    Page,
    InstagramAccount,
    InstagramMedia,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaGranularity {
    Total,
    Daily,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum MetaAttributionModel {
    AdsActionReportTime {
        action_report_time: String,
    },
    PagePeriod {
        period: String,
    },
    InstagramPeriod {
        period: String,
        metric_type: Option<String>,
    },
    NotApplicable,
}

impl MetaAttributionModel {
    fn validate_for(&self, target: &MetaReadTarget) -> Result<(), MetaConnectorError> {
        if target.is_facts() {
            if matches!(self, Self::NotApplicable) {
                return Ok(());
            }
            return Err(MetaConnectorError::InvalidAttribution);
        }
        match (target.classification(), self) {
            (MetaSurface::Marketing, Self::AdsActionReportTime { action_report_time })
                if matches!(action_report_time.as_str(), "impression" | "conversion") =>
            {
                Ok(())
            }
            (MetaSurface::Page, Self::PagePeriod { period }) if valid_period(period) => Ok(()),
            (
                MetaSurface::InstagramAccount | MetaSurface::InstagramMedia,
                Self::InstagramPeriod {
                    period,
                    metric_type,
                },
            ) if valid_period(period)
                && metric_type
                    .as_deref()
                    .is_none_or(|value| matches!(value, "total_value" | "time_series")) =>
            {
                Ok(())
            }
            _ => Err(MetaConnectorError::InvalidAttribution),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaInsightQuery {
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    metrics: Vec<String>,
    granularity: MetaGranularity,
    attribution: MetaAttributionModel,
}

impl MetaInsightQuery {
    pub fn new(
        since: DateTime<Utc>,
        until: DateTime<Utc>,
        metrics: impl IntoIterator<Item = String>,
        granularity: MetaGranularity,
        attribution: MetaAttributionModel,
    ) -> Result<Self, MetaConnectorError> {
        let query = Self {
            since,
            until,
            metrics: metrics.into_iter().collect(),
            granularity,
            attribution,
        };
        query.validate(false)?;
        Ok(query)
    }

    pub fn facts(observed_at: DateTime<Utc>) -> Self {
        Self {
            since: observed_at,
            until: observed_at + Duration::seconds(1),
            metrics: Vec::new(),
            granularity: MetaGranularity::Total,
            attribution: MetaAttributionModel::NotApplicable,
        }
    }

    pub fn since(&self) -> DateTime<Utc> {
        self.since
    }

    pub fn until(&self) -> DateTime<Utc> {
        self.until
    }

    pub fn metrics(&self) -> &[String] {
        &self.metrics
    }

    pub const fn granularity(&self) -> MetaGranularity {
        self.granularity
    }

    pub fn attribution(&self) -> &MetaAttributionModel {
        &self.attribution
    }

    fn validate(&self, facts: bool) -> Result<(), MetaConnectorError> {
        if self.until <= self.since || self.until - self.since > Duration::days(90) {
            return Err(MetaConnectorError::InvalidWindow);
        }
        if !facts
            && (self.metrics.is_empty() || self.metrics.iter().any(|metric| !valid_metric(metric)))
        {
            return Err(MetaConnectorError::InvalidMetrics);
        }
        if self.metrics.iter().any(|metric| !valid_metric(metric)) {
            return Err(MetaConnectorError::InvalidMetrics);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MetaAccessToken(Zeroizing<String>);

impl MetaAccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, MetaConnectorError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 16_384 {
            return Err(MetaConnectorError::MissingCredential);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for MetaAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MetaAccessToken(REDACTED)")
    }
}

impl Drop for MetaAccessToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// An app secret is resolved only inside the signature verifier.  It is never
/// serialized, debug-printed, or included in a webhook receipt.
pub struct MetaAppSecret(Zeroizing<String>);

impl Clone for MetaAppSecret {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl MetaAppSecret {
    pub fn new(value: impl Into<String>) -> Result<Self, MetaConnectorError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 16_384 {
            return Err(MetaConnectorError::MissingCredential);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for MetaAppSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MetaAppSecret(REDACTED)")
    }
}

impl Drop for MetaAppSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub trait MetaCredentialResolver: fmt::Debug + Send + Sync {
    fn resolve(&self, reference: &SecretReference) -> Result<MetaAccessToken, MetaConnectorError>;
}

pub trait MetaWebhookSecretResolver: fmt::Debug + Send + Sync {
    fn resolve(&self, reference: &SecretReference) -> Result<MetaAppSecret, MetaConnectorError>;
}

#[derive(Clone, Default)]
pub struct InMemoryMetaCredentialResolver {
    values: BTreeMap<String, MetaAccessToken>,
}

impl fmt::Debug for InMemoryMetaCredentialResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryMetaCredentialResolver")
            .field("references", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl InMemoryMetaCredentialResolver {
    pub fn insert(
        &mut self,
        reference: &SecretReference,
        token: impl Into<String>,
    ) -> Result<(), MetaConnectorError> {
        self.values.insert(
            reference.reference_id().to_owned(),
            MetaAccessToken::new(token)?,
        );
        Ok(())
    }
}

impl MetaCredentialResolver for InMemoryMetaCredentialResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<MetaAccessToken, MetaConnectorError> {
        self.values
            .get(reference.reference_id())
            .cloned()
            .ok_or(MetaConnectorError::MissingCredential)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EnvironmentMetaCredentialResolver;

impl MetaCredentialResolver for EnvironmentMetaCredentialResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<MetaAccessToken, MetaConnectorError> {
        let token =
            std::env::var(META_ACCESS_TOKEN_ENV).map_err(|_| MetaConnectorError::BlockedEnv)?;
        MetaAccessToken::new(token)
    }
}

#[derive(Clone, Default)]
pub struct InMemoryMetaWebhookSecretResolver {
    values: BTreeMap<String, MetaAppSecret>,
}

impl fmt::Debug for InMemoryMetaWebhookSecretResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryMetaWebhookSecretResolver")
            .field("references", &self.values.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl InMemoryMetaWebhookSecretResolver {
    pub fn insert(
        &mut self,
        reference: &SecretReference,
        app_secret: impl Into<String>,
    ) -> Result<(), MetaConnectorError> {
        self.values.insert(
            reference.reference_id().to_owned(),
            MetaAppSecret::new(app_secret)?,
        );
        Ok(())
    }
}

impl MetaWebhookSecretResolver for InMemoryMetaWebhookSecretResolver {
    fn resolve(&self, reference: &SecretReference) -> Result<MetaAppSecret, MetaConnectorError> {
        self.values
            .get(reference.reference_id())
            .cloned()
            .ok_or(MetaConnectorError::MissingCredential)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EnvironmentMetaWebhookSecretResolver;

impl MetaWebhookSecretResolver for EnvironmentMetaWebhookSecretResolver {
    fn resolve(&self, _reference: &SecretReference) -> Result<MetaAppSecret, MetaConnectorError> {
        let app_secret =
            std::env::var(META_APP_SECRET_ENV).map_err(|_| MetaConnectorError::BlockedEnv)?;
        MetaAppSecret::new(app_secret)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MetaHttpRequest {
    pub api: MetaApiBinding,
    pub path: String,
    pub query: Vec<(String, String)>,
}

impl MetaHttpRequest {
    fn url(&self) -> String {
        let query = self
            .query
            .iter()
            .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
            .collect::<Vec<_>>()
            .join("&");
        if query.is_empty() {
            format!("{}{}", self.api.host.base_url(), self.path)
        } else {
            format!("{}{}?{}", self.api.host.base_url(), self.path, query)
        }
    }
}

impl fmt::Debug for MetaHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let query = self
            .query
            .iter()
            .map(|(key, value)| {
                if key == "after" {
                    (key, format!("digest:{}", sha256(value)))
                } else {
                    (key, value.clone())
                }
            })
            .collect::<Vec<_>>();
        formatter
            .debug_struct("MetaHttpRequest")
            .field("api", &self.api)
            .field("path", &self.path)
            .field("query", &query)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MetaHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl fmt::Debug for MetaHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetaHttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_digest", &sha256(&self.body))
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl MetaHttpResponse {
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: BTreeMap::new(),
            body: body.into(),
        }
    }

    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .insert(name.into().to_ascii_lowercase(), value.into());
        self
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    fn status_is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub trait MetaHttpTransport: fmt::Debug + Send + Sync {
    fn provenance_class(&self) -> ProviderProvenanceClass {
        ProviderProvenanceClass::ProductionProvider
    }

    fn get(
        &self,
        request: &MetaHttpRequest,
        token: &MetaAccessToken,
    ) -> Result<MetaHttpResponse, MetaConnectorError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MetaCurlHttpsTransport;

impl MetaHttpTransport for MetaCurlHttpsTransport {
    fn get(
        &self,
        request: &MetaHttpRequest,
        token: &MetaAccessToken,
    ) -> Result<MetaHttpResponse, MetaConnectorError> {
        let url = request.url();
        if !url.starts_with("https://")
            || url.contains('\n')
            || url.contains('\r')
            || url.contains('"')
        {
            return Err(MetaConnectorError::InvalidProviderRequest);
        }
        let config = format!(
            "silent\nshow-error\ndump-header = \"-\"\nrequest = \"GET\"\nurl = \"{}\"\nheader = \"Authorization: Bearer {}\"\nheader = \"Accept: application/json\"\n",
            url,
            curl_config_escape(token.expose())?
        );
        let mut child = Command::new("curl")
            .args(["--config", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| MetaConnectorError::Transport(error.to_string()))?;
        child
            .stdin
            .take()
            .ok_or(MetaConnectorError::Transport(
                "curl stdin unavailable".to_owned(),
            ))?
            .write_all(config.as_bytes())
            .map_err(|error| MetaConnectorError::Transport(error.to_string()))?;
        let output = child
            .wait_with_output()
            .map_err(|error| MetaConnectorError::Transport(error.to_string()))?;
        if output.stdout.len() > MAX_RESPONSE_BYTES {
            return Err(MetaConnectorError::ResponseTooLarge);
        }
        let raw = String::from_utf8(output.stdout)
            .map_err(|_| MetaConnectorError::InvalidProviderResponse)?;
        parse_curl_response(&raw)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MetaConnectorError {
    #[error("connector SDK error: {0}")]
    Sdk(ConnectorError),
    #[error("Meta API version is invalid")]
    InvalidApiVersion,
    #[error("Meta scope is invalid")]
    InvalidScope,
    #[error("Meta scope does not match connector scope")]
    ScopeMismatch,
    #[error("Meta insight window is invalid")]
    InvalidWindow,
    #[error("Meta insight metrics are invalid")]
    InvalidMetrics,
    #[error("Meta attribution model is invalid for this target")]
    InvalidAttribution,
    #[error("Meta credential is missing")]
    MissingCredential,
    #[error("Meta credential probe is blocked by the environment")]
    BlockedEnv,
    #[error("Meta credential lease is invalid, expired, or revoked")]
    InvalidCredentialLease,
    #[error("Meta probe observation is invalid or stale")]
    InvalidProbe,
    #[error("Meta provider request is invalid")]
    InvalidProviderRequest,
    #[error("Meta provider response is invalid")]
    InvalidProviderResponse,
    #[error("Meta provider response could not be parsed")]
    ResponseParse,
    #[error("Meta HTTPS transport failed: {0}")]
    Transport(String),
    #[error("Meta provider response exceeded the size bound")]
    ResponseTooLarge,
    #[error("Meta provider rejected the request")]
    ProviderRejected,
    #[error("Meta provider is unavailable")]
    ProviderUnavailable,
    #[error("Meta access token was rejected")]
    Unauthorized,
    #[error("Meta permission is missing or was downgraded")]
    PermissionDenied,
    #[error("Meta provider scope is not accessible")]
    ScopeNotAccessible,
    #[error("Meta provider rate limit is exhausted")]
    RateLimited {
        reset_at: Option<DateTime<Utc>>,
        retry_after_seconds: Option<u64>,
    },
    #[error("Meta pagination cursor does not match the request")]
    CursorMismatch,
    #[error("Meta pagination cursor moved backwards")]
    CursorRollback,
    #[error("Meta page is a duplicate")]
    DuplicatePage,
    #[error("Meta observation is a duplicate")]
    DuplicateObservation,
    #[error("Meta connection is not mounted")]
    NotMounted,
    #[error("Meta probe is stale")]
    ProbeStale,
    #[error("Meta credential or session is revoked")]
    Revoked,
    #[error("Meta credential revision changed during refresh")]
    RefreshDrift,
    #[error("Meta pagination cursor is invalid")]
    InvalidCursor,
    #[error("Meta read budget is exhausted")]
    BudgetExceeded,
    #[error("Meta freshness window has expired")]
    FreshnessExpired,
    #[error("Meta writes are disabled for this slice")]
    WritesDisabled,
    #[error("Meta observation is invalid")]
    InvalidObservation,
    #[error("Meta durable checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("Meta webhook signature is invalid")]
    InvalidWebhookSignature,
    #[error("Meta webhook delivery is invalid")]
    InvalidWebhookDelivery,
    #[error("Meta webhook delivery is already pending")]
    DuplicateWebhookDelivery,
    #[error("Meta webhook delivery is not pending")]
    WebhookDeliveryNotPending,
    #[error("Meta webhook durable state is invalid")]
    InvalidWebhookState,
}

impl From<ConnectorError> for MetaConnectorError {
    fn from(error: ConnectorError) -> Self {
        Self::Sdk(error)
    }
}

fn valid_api_version(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('v') else {
        return false;
    };
    let mut parts = rest.split('.');
    parts.next().is_some_and(|part| {
        !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
    }) && parts.next().is_some_and(|part| {
        !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
    }) && parts.next().is_none()
}

fn numeric_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|character| character.is_ascii_digit())
}

fn normalize_ad_account(value: &str) -> Result<String, MetaConnectorError> {
    let numeric = value.strip_prefix("act_").unwrap_or(value);
    if !numeric_id(numeric) {
        return Err(MetaConnectorError::InvalidScope);
    }
    Ok(format!("act_{numeric}"))
}

fn valid_webhook_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        })
}

fn webhook_object_matches_scope(object: &str, scope: &MetaScope) -> bool {
    match object {
        "business" => numeric_id(scope.business_id()),
        "ad_account" => scope.ad_account_id().is_some(),
        "page" => scope.page_id().is_some(),
        "instagram" => scope.instagram_account_id().is_some(),
        _ => false,
    }
}

fn webhook_scope_entry_matches(object: &str, entry_id: &str, scope: &MetaScope) -> bool {
    match object {
        "business" => entry_id == scope.business_id(),
        "ad_account" => scope
            .ad_account_id()
            .and_then(|id| normalize_ad_account(id).ok())
            .is_some_and(|id| {
                normalize_ad_account(entry_id)
                    .ok()
                    .is_some_and(|entry| id == entry)
            }),
        "page" => scope.page_id() == Some(entry_id),
        "instagram" => scope.instagram_account_id() == Some(entry_id),
        _ => false,
    }
}

fn webhook_surface(object: &str) -> Result<MetaSurface, MetaConnectorError> {
    match object {
        "business" => Ok(MetaSurface::Business),
        "ad_account" => Ok(MetaSurface::Marketing),
        "page" => Ok(MetaSurface::Page),
        "instagram" => Ok(MetaSurface::InstagramAccount),
        _ => Err(MetaConnectorError::InvalidWebhookDelivery),
    }
}

fn parse_webhook_signature(signature: &str) -> Result<Vec<u8>, MetaConnectorError> {
    let encoded = signature
        .strip_prefix("sha256=")
        .ok_or(MetaConnectorError::InvalidWebhookSignature)?;
    if encoded.len() != 64 {
        return Err(MetaConnectorError::InvalidWebhookSignature);
    }
    let mut bytes = Vec::with_capacity(32);
    let mut chars = encoded.chars();
    while let (Some(high), Some(low)) = (chars.next(), chars.next()) {
        let high = high
            .to_digit(16)
            .ok_or(MetaConnectorError::InvalidWebhookSignature)?;
        let low = low
            .to_digit(16)
            .ok_or(MetaConnectorError::InvalidWebhookSignature)?;
        bytes.push(
            u8::try_from((high << 4) | low)
                .map_err(|_| MetaConnectorError::InvalidWebhookSignature)?,
        );
    }
    if bytes.len() == 32 {
        Ok(bytes)
    } else {
        Err(MetaConnectorError::InvalidWebhookSignature)
    }
}

fn parse_webhook_payload(
    request: &MetaWebhookDeliveryRequest,
) -> Result<MetaWebhookVerifiedDelivery, MetaConnectorError> {
    let body: Value = serde_json::from_str(request.body())
        .map_err(|_| MetaConnectorError::InvalidProviderResponse)?;
    let object = body
        .get("object")
        .and_then(Value::as_str)
        .ok_or(MetaConnectorError::InvalidWebhookDelivery)?
        .to_owned();
    if object != request.subscription.object()
        || !webhook_object_matches_scope(&object, &request.reconcile_request.meta_scope)
    {
        return Err(MetaConnectorError::RefreshDrift);
    }
    let entries = body
        .get("entry")
        .and_then(Value::as_array)
        .filter(|entries| !entries.is_empty())
        .ok_or(MetaConnectorError::InvalidWebhookDelivery)?;
    let mut entry_ids = BTreeSet::new();
    let mut change_fields = BTreeSet::new();
    let mut timestamps = Vec::new();
    for entry in entries {
        let entry_id = entry
            .get("id")
            .and_then(Value::as_str)
            .ok_or(MetaConnectorError::InvalidWebhookDelivery)?;
        if !webhook_scope_entry_matches(&object, entry_id, &request.reconcile_request.meta_scope) {
            return Err(MetaConnectorError::ScopeNotAccessible);
        }
        entry_ids.insert(entry_id.to_owned());
        let timestamp = entry
            .get("time")
            .and_then(Value::as_i64)
            .filter(|time| *time > 0)
            .ok_or(MetaConnectorError::InvalidWebhookDelivery)?;
        timestamps.push(timestamp);
        let changes = entry
            .get("changes")
            .and_then(Value::as_array)
            .filter(|changes| !changes.is_empty())
            .ok_or(MetaConnectorError::InvalidWebhookDelivery)?;
        for change in changes {
            let field = change
                .get("field")
                .and_then(Value::as_str)
                .filter(|field| valid_metric(field))
                .ok_or(MetaConnectorError::InvalidWebhookDelivery)?;
            change_fields.insert(field.to_owned());
        }
    }
    if entry_ids.is_empty() || change_fields.is_empty() {
        return Err(MetaConnectorError::InvalidWebhookDelivery);
    }
    let payload_digest = request.payload_digest();
    let event_digest = digest_json(&(
        &object,
        &entry_ids,
        &change_fields,
        &timestamps,
        &payload_digest,
    ));
    Ok(MetaWebhookVerifiedDelivery {
        object,
        entry_ids,
        change_fields,
        event_timestamp: timestamps.into_iter().max().unwrap_or_default(),
        payload_digest,
        event_digest,
        signature_digest: request.signature_digest(),
    })
}

fn valid_metric(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | ':')
        })
}

fn valid_period(value: &str) -> bool {
    matches!(
        value,
        "day" | "week" | "days_28" | "lifetime" | "total_over_range"
    )
}

fn sha256(value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    format!("{:x}", digest.finalize())
}

fn digest_json<T: Serialize>(value: &T) -> String {
    sha256(&serde_json::to_string(value).expect("Meta contract values serialize"))
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            other => format!("%{other:02X}").chars().collect(),
        })
        .collect()
}

fn curl_config_escape(value: &str) -> Result<String, MetaConnectorError> {
    if value.contains('\n') || value.contains('\r') || value.contains('"') {
        return Err(MetaConnectorError::InvalidProviderRequest);
    }
    Ok(value.to_owned())
}

fn parse_curl_response(raw: &str) -> Result<MetaHttpResponse, MetaConnectorError> {
    let header_start = raw
        .rfind("HTTP/")
        .ok_or(MetaConnectorError::InvalidProviderResponse)?;
    let header_end = raw[header_start..]
        .find("\r\n\r\n")
        .map(|offset| header_start + offset)
        .or_else(|| {
            raw[header_start..]
                .find("\n\n")
                .map(|offset| header_start + offset)
        })
        .ok_or(MetaConnectorError::InvalidProviderResponse)?;
    let header_block = &raw[header_start..header_end];
    let mut lines = header_block.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or(MetaConnectorError::InvalidProviderResponse)?;
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let body_start = if raw[header_end..].starts_with("\r\n\r\n") {
        header_end + 4
    } else {
        header_end + 2
    };
    Ok(MetaHttpResponse {
        status,
        headers,
        body: raw[body_start..].to_owned(),
    })
}

fn unix_seconds(value: DateTime<Utc>) -> i64 {
    value.timestamp()
}

fn response_request_id(response: &MetaHttpResponse, body: &Value) -> String {
    response
        .header("x-fb-trace-id")
        .or_else(|| response.header("x-fb-rev"))
        .or_else(|| body.get("__request_id").and_then(Value::as_str))
        .map_or_else(|| sha256(&response.body), ToOwned::to_owned)
}

fn rate_limit_receipt(
    response: &MetaHttpResponse,
    observed_at: DateTime<Utc>,
) -> MetaRateLimitReceipt {
    let remaining = response
        .header("x-app-usage")
        .or_else(|| response.header("x-ad-account-usage"))
        .map(sha256);
    let retry_after_seconds = response
        .header("retry-after")
        .and_then(|value| value.parse::<u64>().ok());
    let reset_at = response
        .header("x-rate-limit-reset")
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0));
    MetaRateLimitReceipt {
        usage_digest: remaining,
        reset_at,
        retry_after_seconds,
        observed_at,
    }
}

#[derive(Clone, Debug)]
pub struct MetaProbeRequest {
    pub connector_scope: ConnectorScope,
    pub meta_scope: MetaScope,
    pub api: MetaApiBinding,
    pub secret_reference: SecretReference,
    pub lease: CredentialLease,
    pub at: DateTime<Utc>,
}

impl MetaProbeRequest {
    pub fn new(
        connector_scope: ConnectorScope,
        meta_scope: MetaScope,
        api: MetaApiBinding,
        secret_reference: SecretReference,
        lease: CredentialLease,
        at: DateTime<Utc>,
    ) -> Result<Self, MetaConnectorError> {
        let request = Self {
            connector_scope,
            meta_scope,
            api,
            secret_reference,
            lease,
            at,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), MetaConnectorError> {
        self.meta_scope
            .validate_against_connector(&self.connector_scope)?;
        validate_probe_permissions(&self.connector_scope, &self.meta_scope, &self.api)?;
        if self.secret_reference.scope() != &self.connector_scope
            || self.lease.scope() != &self.connector_scope
            || self.lease.adapter().adapter_id() != META_ADAPTER_ID
            || self.lease.adapter().adapter_version() != META_ADAPTER_VERSION
            || self.secret_reference.is_revoked_at(self.at)
            || self.lease.is_revoked_at(self.at)
            || self.at < self.lease.issued_at()
            || self.at >= self.lease.expires_at()
        {
            return Err(MetaConnectorError::InvalidCredentialLease);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MetaInsightReadRequest {
    pub connector_scope: ConnectorScope,
    pub meta_scope: MetaScope,
    pub api: MetaApiBinding,
    pub target: MetaReadTarget,
    pub query: MetaInsightQuery,
    pub secret_reference: SecretReference,
    pub lease: CredentialLease,
    pub cursor: Option<MetaPaginationCursor>,
    pub at: DateTime<Utc>,
}

impl MetaInsightReadRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        connector_scope: ConnectorScope,
        meta_scope: MetaScope,
        api: MetaApiBinding,
        target: MetaReadTarget,
        query: MetaInsightQuery,
        secret_reference: SecretReference,
        lease: CredentialLease,
        cursor: Option<MetaPaginationCursor>,
        at: DateTime<Utc>,
    ) -> Result<Self, MetaConnectorError> {
        let request = Self {
            connector_scope,
            meta_scope,
            api,
            target,
            query,
            secret_reference,
            lease,
            cursor,
            at,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn request_digest(&self) -> String {
        digest_json(&(
            &self.connector_scope,
            &self.meta_scope,
            &self.api,
            &self.target,
            &self.query,
        ))
    }

    fn validate(&self) -> Result<(), MetaConnectorError> {
        self.meta_scope
            .validate_against_connector(&self.connector_scope)?;
        self.target.validate_scope(&self.meta_scope)?;
        validate_target_permissions(&self.connector_scope, &self.target)?;
        self.query.validate(self.target.is_facts())?;
        self.query.attribution().validate_for(&self.target)?;
        if self.target.requires_facebook_host() && self.api.host != MetaGraphHost::Facebook {
            return Err(MetaConnectorError::InvalidProviderRequest);
        }
        if self.secret_reference.scope() != &self.connector_scope
            || self.lease.scope() != &self.connector_scope
            || self.lease.adapter().adapter_id() != META_ADAPTER_ID
            || self.lease.adapter().adapter_version() != META_ADAPTER_VERSION
            || self.secret_reference.is_revoked_at(self.at)
            || self.lease.is_revoked_at(self.at)
            || self.at < self.lease.issued_at()
            || self.at >= self.lease.expires_at()
        {
            return Err(MetaConnectorError::InvalidCredentialLease);
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate(&self.connector_scope, &self.request_digest())?;
        }
        Ok(())
    }
}

fn provider_query_digest(request: &MetaInsightReadRequest) -> String {
    digest_json(&(
        &request.api,
        &request.target,
        &request.query,
        request
            .cursor
            .as_ref()
            .map(MetaPaginationCursor::token_digest),
    ))
}

fn webhook_cursor_token_digest(request: &MetaInsightReadRequest) -> Option<String> {
    request
        .cursor
        .as_ref()
        .map(|cursor| cursor.token_digest().to_owned())
}

fn webhook_credential_binding_digest(request: &MetaInsightReadRequest) -> String {
    digest_json(&(
        request.secret_reference.reference_id(),
        request.secret_reference.scope().digest(),
        request.secret_reference.credential_revision(),
        request.lease.lease_id(),
        request.lease.scope().digest(),
        request.lease.adapter().adapter_id(),
        request.lease.adapter().adapter_version(),
        request.lease.credential_revision(),
        request.lease.lease_revision(),
        request.lease.issued_at(),
        request.lease.expires_at(),
    ))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaWebhookSubscription {
    subscription_id: String,
    connector_scope_digest: String,
    meta_scope_digest: String,
    api_digest: String,
    object: String,
    revision: u64,
    expires_at: Option<DateTime<Utc>>,
}

impl MetaWebhookSubscription {
    pub fn new(
        subscription_id: impl Into<String>,
        connector_scope: &ConnectorScope,
        meta_scope: &MetaScope,
        api: &MetaApiBinding,
        object: impl Into<String>,
        revision: u64,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Self, MetaConnectorError> {
        let subscription = Self {
            subscription_id: subscription_id.into(),
            connector_scope_digest: connector_scope.digest(),
            meta_scope_digest: meta_scope.digest(),
            api_digest: api.digest(),
            object: object.into(),
            revision,
            expires_at,
        };
        subscription.validate()?;
        Ok(subscription)
    }

    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }

    pub fn object(&self) -> &str {
        &self.object
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    pub fn digest(&self) -> String {
        digest_json(self)
    }

    fn validate(&self) -> Result<(), MetaConnectorError> {
        if !valid_webhook_identity(&self.subscription_id)
            || !is_sha256(&self.connector_scope_digest)
            || !is_sha256(&self.meta_scope_digest)
            || !is_sha256(&self.api_digest)
            || !matches!(
                self.object.as_str(),
                "business" | "ad_account" | "page" | "instagram"
            )
            || self.revision == 0
            || self
                .expires_at
                .is_some_and(|expires_at| expires_at <= Utc::now())
        {
            return Err(MetaConnectorError::InvalidWebhookDelivery);
        }
        Ok(())
    }

    fn validate_for(&self, request: &MetaInsightReadRequest) -> Result<(), MetaConnectorError> {
        self.validate()?;
        if self.connector_scope_digest != request.connector_scope.digest()
            || self.meta_scope_digest != request.meta_scope.digest()
            || self.api_digest != request.api.digest()
            || self
                .expires_at
                .is_some_and(|expires_at| request.at >= expires_at)
            || !webhook_object_matches_scope(self.object.as_str(), &request.meta_scope)
        {
            return Err(MetaConnectorError::RefreshDrift);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct MetaWebhookDeliveryRequest {
    pub subscription: MetaWebhookSubscription,
    pub delivery_id: String,
    pub event_id: String,
    signature: String,
    body: String,
    pub reconcile_request: MetaInsightReadRequest,
    pub at: DateTime<Utc>,
}

impl fmt::Debug for MetaWebhookDeliveryRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetaWebhookDeliveryRequest")
            .field("subscription", &self.subscription)
            .field("delivery_id", &self.delivery_id)
            .field("event_id", &self.event_id)
            .field("signature_digest", &sha256(&self.signature))
            .field("payload_digest", &sha256(&self.body))
            .field("body_bytes", &self.body.len())
            .field("reconcile_request", &self.reconcile_request)
            .field("at", &self.at)
            .finish()
    }
}

impl MetaWebhookDeliveryRequest {
    pub fn new(
        subscription: MetaWebhookSubscription,
        delivery_id: impl Into<String>,
        event_id: impl Into<String>,
        signature: impl Into<String>,
        body: impl Into<String>,
        reconcile_request: MetaInsightReadRequest,
        at: DateTime<Utc>,
    ) -> Result<Self, MetaConnectorError> {
        let request = Self {
            subscription,
            delivery_id: delivery_id.into(),
            event_id: event_id.into(),
            signature: signature.into(),
            body: body.into(),
            reconcile_request,
            at,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn payload_digest(&self) -> String {
        sha256(&self.body)
    }

    pub fn signature_digest(&self) -> String {
        sha256(&self.signature)
    }

    pub fn request_digest(&self) -> String {
        digest_json(&(
            self.subscription.digest(),
            &self.delivery_id,
            &self.event_id,
            self.payload_digest(),
            self.reconcile_request.request_digest(),
            webhook_cursor_token_digest(&self.reconcile_request),
            webhook_credential_binding_digest(&self.reconcile_request),
        ))
    }

    fn validate(&self) -> Result<(), MetaConnectorError> {
        self.reconcile_request.validate()?;
        if self.at != self.reconcile_request.at
            || !valid_webhook_identity(&self.delivery_id)
            || !valid_webhook_identity(&self.event_id)
            || self.body.is_empty()
            || self.body.len() > MAX_WEBHOOK_BODY_BYTES
        {
            return Err(MetaConnectorError::InvalidWebhookDelivery);
        }
        self.subscription.validate_for(&self.reconcile_request)?;
        parse_webhook_signature(&self.signature)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetaWebhookVerifiedDelivery {
    pub object: String,
    pub entry_ids: BTreeSet<String>,
    pub change_fields: BTreeSet<String>,
    pub event_timestamp: i64,
    pub payload_digest: String,
    pub event_digest: String,
    pub signature_digest: String,
}

pub trait MetaWebhookProvider: fmt::Debug + Send + Sync {
    fn verify(
        &self,
        request: &MetaWebhookDeliveryRequest,
        app_secret: &MetaAppSecret,
    ) -> Result<MetaWebhookVerifiedDelivery, MetaConnectorError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct MetaGraphWebhookAdapter;

impl MetaWebhookProvider for MetaGraphWebhookAdapter {
    fn verify(
        &self,
        request: &MetaWebhookDeliveryRequest,
        app_secret: &MetaAppSecret,
    ) -> Result<MetaWebhookVerifiedDelivery, MetaConnectorError> {
        request.validate()?;
        let signature = parse_webhook_signature(request.signature())?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, app_secret.expose().as_bytes());
        hmac::verify(&key, request.body().as_bytes(), &signature)
            .map_err(|_| MetaConnectorError::InvalidWebhookSignature)?;
        parse_webhook_payload(request)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaCausalStatus {
    NotClaimed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaReviewState {
    Required,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaSourceReceipt {
    pub provider: String,
    pub surface: MetaSurface,
    pub host: String,
    pub api_version: String,
    pub method: String,
    pub path: String,
    pub query_digest: String,
    pub status: u16,
    pub provider_request_id: String,
    pub response_digest: String,
    pub content_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl MetaSourceReceipt {
    fn validate(&self) -> Result<(), MetaConnectorError> {
        if self.provider != META_PROVIDER_ID
            || self.method != "GET"
            || !self.path.starts_with('/')
            || !is_sha256(&self.query_digest)
            || !is_sha256(&self.response_digest)
            || !is_sha256(&self.content_digest)
            || self.status == 0
            || self.provider_request_id.is_empty()
        {
            return Err(MetaConnectorError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaRateLimitReceipt {
    pub usage_digest: Option<String>,
    pub reset_at: Option<DateTime<Utc>>,
    pub retry_after_seconds: Option<u64>,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaFreshnessReceipt {
    pub window: FreshnessWindow,
    pub query_since: DateTime<Utc>,
    pub query_until: DateTime<Utc>,
}

impl MetaFreshnessReceipt {
    fn validate(&self) -> Result<(), MetaConnectorError> {
        self.window
            .validate_at(self.window.observed_at())
            .map_err(MetaConnectorError::from)?;
        if self.query_until <= self.query_since
            || self.query_until - self.query_since > Duration::days(90)
        {
            return Err(MetaConnectorError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaQuotaReceipt {
    pub limit: u64,
    pub used: u64,
    pub remaining: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaCostReceipt {
    pub unit: String,
    pub amount_minor: i64,
    pub limit_minor: i64,
    pub used_minor: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaClassificationReceipt {
    pub provenance_class: ProviderProvenanceClass,
    pub surface: MetaSurface,
    pub attribution: MetaAttributionModel,
    pub causal_status: MetaCausalStatus,
    pub first_party: bool,
    pub review_state: MetaReviewState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaWebhookSourceReceipt {
    pub source: String,
    pub provider: String,
    pub host: String,
    pub api_version: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub delivery_id: String,
    pub request_digest: String,
    pub response_digest: String,
    pub payload_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl MetaWebhookSourceReceipt {
    fn validate(&self) -> Result<(), MetaConnectorError> {
        if self.source != "meta_webhook"
            || self.provider != META_PROVIDER_ID
            || self.method != "POST"
            || self.path != "/meta/webhook"
            || self.status != 202
            || !valid_webhook_identity(&self.delivery_id)
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.response_digest)
            || !is_sha256(&self.payload_digest)
        {
            return Err(MetaConnectorError::InvalidWebhookDelivery);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaWebhookDeliveryReceipt {
    pub schema: String,
    pub provider: String,
    pub subscription_id: String,
    pub subscription_digest: String,
    pub scope_digest: String,
    pub meta_scope_digest: String,
    pub api_digest: String,
    pub delivery_id: String,
    pub event_id: String,
    pub event_digest: String,
    pub payload_digest: String,
    pub signature_digest: String,
    pub request_digest: String,
    pub reconcile_request_digest: String,
    pub reconcile_cursor_token_digest: Option<String>,
    pub credential_binding_digest: String,
    pub response_digest: String,
    pub source: MetaWebhookSourceReceipt,
    pub classification: MetaClassificationReceipt,
    pub causal_status: MetaCausalStatus,
    pub durable_logged: bool,
}

impl MetaWebhookDeliveryReceipt {
    fn validate(&self) -> Result<(), MetaConnectorError> {
        self.source.validate()?;
        if self.schema != META_WEBHOOK_SCHEMA
            || self.provider != META_PROVIDER_ID
            || !valid_webhook_identity(&self.subscription_id)
            || !valid_webhook_identity(&self.delivery_id)
            || !valid_webhook_identity(&self.event_id)
            || !is_sha256(&self.subscription_digest)
            || !is_sha256(&self.scope_digest)
            || !is_sha256(&self.meta_scope_digest)
            || !is_sha256(&self.api_digest)
            || !is_sha256(&self.event_digest)
            || !is_sha256(&self.payload_digest)
            || !is_sha256(&self.signature_digest)
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.reconcile_request_digest)
            || self
                .reconcile_cursor_token_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || !is_sha256(&self.credential_binding_digest)
            || !is_sha256(&self.response_digest)
            || self.source.delivery_id != self.delivery_id
            || self.source.request_digest != self.request_digest
            || self.source.payload_digest != self.payload_digest
            || self.classification.causal_status != MetaCausalStatus::NotClaimed
            || self.causal_status != MetaCausalStatus::NotClaimed
            || !self.durable_logged
        {
            return Err(MetaConnectorError::InvalidWebhookDelivery);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MetaValue {
    String(String),
    Integer(i64),
    Float(String),
    Boolean(bool),
    Null,
    ObjectDigest(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaInsightRecord {
    pub target: MetaReadTarget,
    pub metric: String,
    pub value: MetaValue,
    pub dimensions: BTreeMap<String, String>,
    pub period: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub attribution: MetaAttributionModel,
    pub native_payload_digest: String,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaPaginationCursor {
    scope_digest: String,
    request_digest: String,
    token: String,
    token_digest: String,
    sequence: u64,
    complete: bool,
    page_digest: String,
}

impl fmt::Debug for MetaPaginationCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetaPaginationCursor")
            .field("scope_digest", &self.scope_digest)
            .field("request_digest", &self.request_digest)
            .field("token_digest", &self.token_digest)
            .field("sequence", &self.sequence)
            .field("complete", &self.complete)
            .field("page_digest", &self.page_digest)
            .finish_non_exhaustive()
    }
}

impl MetaPaginationCursor {
    pub fn new(
        scope: &ConnectorScope,
        request_digest: impl Into<String>,
        token: impl Into<String>,
        sequence: u64,
        page_digest: impl Into<String>,
    ) -> Result<Self, MetaConnectorError> {
        let token = token.into();
        let cursor = Self {
            scope_digest: scope.digest(),
            request_digest: request_digest.into(),
            token_digest: sha256(&token),
            token,
            sequence,
            complete: false,
            page_digest: page_digest.into(),
        };
        cursor.validate(scope, &cursor.request_digest)?;
        Ok(cursor)
    }

    pub fn checkpoint(&self) -> Result<Self, MetaConnectorError> {
        if self.token.len() > MAX_CURSOR_BYTES {
            return Err(MetaConnectorError::InvalidCursor);
        }
        Ok(self.clone())
    }

    pub fn next_token(&self) -> &str {
        &self.token
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn token_digest(&self) -> &str {
        &self.token_digest
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn complete(&self) -> bool {
        self.complete
    }

    pub fn page_digest(&self) -> &str {
        &self.page_digest
    }

    fn validate(
        &self,
        scope: &ConnectorScope,
        request_digest: &str,
    ) -> Result<(), MetaConnectorError> {
        if self.scope_digest != scope.digest()
            || self.request_digest != request_digest
            || self.token.is_empty()
            || self.token.len() > MAX_CURSOR_BYTES
            || self.sequence == 0
            || self.token_digest != sha256(&self.token)
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.page_digest)
        {
            return Err(MetaConnectorError::InvalidCursor);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaCursorReceipt {
    pub scope_digest: String,
    pub request_digest: String,
    pub token_digest: String,
    pub sequence: u64,
    pub complete: bool,
    pub page_digest: String,
}

impl MetaCursorReceipt {
    fn from_cursor(cursor: &MetaPaginationCursor) -> Self {
        Self {
            scope_digest: cursor.scope_digest.clone(),
            request_digest: cursor.request_digest.clone(),
            token_digest: cursor.token_digest.clone(),
            sequence: cursor.sequence,
            complete: cursor.complete,
            page_digest: cursor.page_digest.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MetaProviderPage {
    pub records: Vec<MetaInsightRecord>,
    pub next_cursor: Option<MetaPaginationCursor>,
    pub source: MetaSourceReceipt,
    pub freshness: MetaFreshnessReceipt,
    pub quota: MetaQuotaReceipt,
    pub cost: MetaCostReceipt,
    pub rate_limit: MetaRateLimitReceipt,
    pub provider_request_id: String,
    pub response_digest: String,
    pub content_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl MetaProviderPage {
    fn validate(&self, request: &MetaInsightReadRequest) -> Result<(), MetaConnectorError> {
        self.source.validate()?;
        if self.provider_request_id != self.source.provider_request_id
            || !is_sha256(&self.response_digest)
            || !is_sha256(&self.content_digest)
            || self.source.query_digest != provider_query_digest(request)
            || self.freshness.window.observed_at() != self.observed_at
            || self.freshness.query_since != request.query.since()
            || self.freshness.query_until != request.query.until()
        {
            return Err(MetaConnectorError::InvalidObservation);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate(&request.connector_scope, &request.request_digest())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MetaProbeObservation {
    pub scope_digest: String,
    pub api_digest: String,
    pub observed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub sources: Vec<MetaSourceReceipt>,
    pub binding_digest: String,
    pub connected_claim: bool,
    pub classification: MetaClassificationReceipt,
}

impl MetaProbeObservation {
    fn validate(&self, request: &MetaProbeRequest) -> Result<(), MetaConnectorError> {
        if self.scope_digest != request.connector_scope.digest()
            || self.api_digest != request.api.digest()
            || self.sources.is_empty()
            || self.expires_at <= self.observed_at
            || self.expires_at - self.observed_at > Duration::seconds(DEFAULT_FRESHNESS_SECONDS)
            || self.connected_claim
            || self.classification.causal_status != MetaCausalStatus::NotClaimed
            || self.classification.first_party
                != (self.classification.provenance_class
                    == ProviderProvenanceClass::ProductionProvider)
            || self.classification.review_state != MetaReviewState::Required
        {
            return Err(MetaConnectorError::InvalidProbe);
        }
        for source in &self.sources {
            source.validate()?;
            if source.observed_at != self.observed_at {
                return Err(MetaConnectorError::InvalidProbe);
            }
        }
        if self.binding_digest
            != digest_json(&(
                &self.scope_digest,
                &self.api_digest,
                &self.observed_at,
                &self.expires_at,
                &self.sources,
            ))
        {
            return Err(MetaConnectorError::InvalidProbe);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        self.binding_digest.clone()
    }
}

pub trait MetaInsightProvider: fmt::Debug + Send + Sync {
    fn probe(
        &self,
        request: &MetaProbeRequest,
        token: &MetaAccessToken,
    ) -> Result<MetaProbeObservation, MetaConnectorError>;

    fn read(
        &self,
        request: &MetaInsightReadRequest,
        token: &MetaAccessToken,
    ) -> Result<MetaProviderPage, MetaConnectorError>;
}

#[derive(Clone)]
pub struct MetaGraphApiAdapter {
    transport: Arc<dyn MetaHttpTransport>,
    default_api: MetaApiBinding,
}

impl fmt::Debug for MetaGraphApiAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetaGraphApiAdapter")
            .field("default_api", &self.default_api)
            .finish_non_exhaustive()
    }
}

impl MetaGraphApiAdapter {
    pub fn new(transport: Arc<dyn MetaHttpTransport>, default_api: MetaApiBinding) -> Self {
        Self {
            transport,
            default_api,
        }
    }

    pub fn production() -> Result<Self, MetaConnectorError> {
        Ok(Self::new(
            Arc::new(MetaCurlHttpsTransport),
            MetaApiBinding::from_env(MetaGraphHost::Facebook)?,
        ))
    }

    fn validate_binding(&self, api: &MetaApiBinding) -> Result<(), MetaConnectorError> {
        if api.api_version != self.default_api.api_version {
            return Err(MetaConnectorError::InvalidApiVersion);
        }
        Ok(())
    }

    fn get(
        &self,
        api: &MetaApiBinding,
        path: String,
        query: Vec<(String, String)>,
        token: &MetaAccessToken,
    ) -> Result<(MetaHttpResponse, Value, String, String), MetaConnectorError> {
        let request = MetaHttpRequest {
            api: api.clone(),
            path,
            query,
        };
        let response = self.transport.get(&request, token)?;
        let body: Value = match serde_json::from_str(&response.body) {
            Ok(body) => body,
            Err(_) if !response.status_is_success() => Value::Null,
            Err(_) => return Err(MetaConnectorError::ResponseParse),
        };
        if !response.status_is_success() {
            return Err(provider_error(&response, &body));
        }
        let response_digest = sha256(&response.body);
        let request_id = response_request_id(&response, &body);
        let content_digest = digest_json(&body);
        Ok((
            response,
            body,
            request_id,
            format!("{response_digest}:{content_digest}"),
        ))
    }

    fn probe_object(
        &self,
        request: &MetaProbeRequest,
        token: &MetaAccessToken,
        path: &str,
        surface: MetaSurface,
        fields: &str,
    ) -> Result<MetaSourceReceipt, MetaConnectorError> {
        let api = &request.api;
        let query = vec![("fields".to_owned(), fields.to_owned())];
        let (response, body, provider_request_id, digest_pair) =
            self.get(api, api.versioned_path(path), query, token)?;
        let object = body
            .as_object()
            .ok_or(MetaConnectorError::InvalidProviderResponse)?;
        let expected = path.trim_start_matches('/');
        let returned_id = object
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| object.get("account_id").and_then(Value::as_str))
            .ok_or(MetaConnectorError::InvalidProviderResponse)?;
        let expected_ad = normalize_ad_account(expected).ok();
        if expected != "me"
            && returned_id != expected
            && expected_ad.as_deref() != Some(returned_id)
        {
            return Err(MetaConnectorError::ScopeNotAccessible);
        }
        let (response_digest, content_digest) = split_digest_pair(&digest_pair)?;
        Ok(MetaSourceReceipt {
            provider: META_PROVIDER_ID.to_owned(),
            surface,
            host: api.host.base_url().to_owned(),
            api_version: api.api_version.clone(),
            method: "GET".to_owned(),
            path: api.versioned_path(path),
            query_digest: digest_json(&(
                &api,
                &api.versioned_path(path),
                &vec![("fields".to_owned(), fields.to_owned())],
            )),
            status: response.status,
            provider_request_id,
            response_digest,
            content_digest,
            observed_at: request.at,
        })
    }

    fn target_request(
        request: &MetaInsightReadRequest,
    ) -> Result<(String, Vec<(String, String)>), MetaConnectorError> {
        let object = request.target.object_path(&request.meta_scope)?;
        let path = match request.target {
            MetaReadTarget::BusinessFacts
            | MetaReadTarget::AdAccountFacts
            | MetaReadTarget::PageFacts
            | MetaReadTarget::InstagramAccountFacts => {
                request.target.object_path(&request.meta_scope)?
            }
            MetaReadTarget::AdAccountInsights => {
                format!("{object}/insights")
            }
            MetaReadTarget::PageInsights
            | MetaReadTarget::InstagramAccountInsights
            | MetaReadTarget::InstagramMediaInsights { .. } => format!("{object}/insights"),
        };
        let mut query = Vec::new();
        if request.target.is_facts() {
            query.push((
                "fields".to_owned(),
                facts_fields(&request.target).to_owned(),
            ));
        } else if matches!(request.target, MetaReadTarget::AdAccountInsights) {
            query.push(("fields".to_owned(), request.query.metrics().join(",")));
            query.push(("level".to_owned(), "account".to_owned()));
            query.push((
                "time_increment".to_owned(),
                match request.query.granularity() {
                    MetaGranularity::Total => "0",
                    MetaGranularity::Daily => "1",
                }
                .to_owned(),
            ));
            query.push((
                "time_range".to_owned(),
                serde_json::json!({
                    "since": date_string(request.query.since()),
                    "until": date_string(request.query.until()),
                })
                .to_string(),
            ));
            if let MetaAttributionModel::AdsActionReportTime { action_report_time } =
                request.query.attribution()
            {
                query.push(("action_report_time".to_owned(), action_report_time.clone()));
            }
        } else {
            query.push(("metric".to_owned(), request.query.metrics().join(",")));
            if let MetaAttributionModel::PagePeriod { period }
            | MetaAttributionModel::InstagramPeriod { period, .. } = request.query.attribution()
            {
                query.push(("period".to_owned(), period.clone()));
            }
            if let MetaAttributionModel::InstagramPeriod {
                metric_type: Some(metric_type),
                ..
            } = request.query.attribution()
            {
                query.push(("metric_type".to_owned(), metric_type.clone()));
            }
            query.push((
                "since".to_owned(),
                unix_seconds(request.query.since()).to_string(),
            ));
            query.push((
                "until".to_owned(),
                unix_seconds(request.query.until()).to_string(),
            ));
        }
        query.push(("limit".to_owned(), "100".to_owned()));
        if let Some(cursor) = &request.cursor {
            query.push(("after".to_owned(), cursor.next_token().to_owned()));
        }
        Ok((request.api.versioned_path(&path), query))
    }
}

impl MetaInsightProvider for MetaGraphApiAdapter {
    fn probe(
        &self,
        request: &MetaProbeRequest,
        token: &MetaAccessToken,
    ) -> Result<MetaProbeObservation, MetaConnectorError> {
        request.validate()?;
        self.validate_binding(&request.api)?;
        let mut sources = Vec::new();
        sources.push(self.probe_object(request, token, "me", MetaSurface::Business, "id,name")?);
        if request.api.host == MetaGraphHost::Facebook {
            sources.push(self.probe_object(
                request,
                token,
                request.meta_scope.business_id(),
                MetaSurface::Business,
                "id,name",
            )?);
            if let Some(ad_account_id) = request.meta_scope.ad_account_id() {
                sources.push(self.probe_object(
                    request,
                    token,
                    &normalize_ad_account(ad_account_id)?,
                    MetaSurface::Marketing,
                    "id,account_id,name,account_status,currency",
                )?);
            }
            if let Some(page_id) = request.meta_scope.page_id() {
                sources.push(self.probe_object(
                    request,
                    token,
                    page_id,
                    MetaSurface::Page,
                    "id,name,instagram_business_account",
                )?);
            }
        }
        if let Some(instagram_account_id) = request.meta_scope.instagram_account_id() {
            sources.push(self.probe_object(
                request,
                token,
                instagram_account_id,
                MetaSurface::InstagramAccount,
                "id,username,name,account_type",
            )?);
        }
        let expires_at = request.at + Duration::seconds(DEFAULT_FRESHNESS_SECONDS);
        let api_digest = request.api.digest();
        let scope_digest = request.connector_scope.digest();
        let binding_digest = digest_json(&(
            &scope_digest,
            &api_digest,
            &request.at,
            &expires_at,
            &sources,
        ));
        let provenance_class = self.transport.provenance_class();
        Ok(MetaProbeObservation {
            scope_digest,
            api_digest,
            observed_at: request.at,
            expires_at,
            sources,
            binding_digest,
            connected_claim: false,
            classification: MetaClassificationReceipt {
                provenance_class,
                surface: MetaSurface::Business,
                attribution: MetaAttributionModel::NotApplicable,
                causal_status: MetaCausalStatus::NotClaimed,
                first_party: provenance_class == ProviderProvenanceClass::ProductionProvider,
                review_state: MetaReviewState::Required,
            },
        })
    }

    fn read(
        &self,
        request: &MetaInsightReadRequest,
        token: &MetaAccessToken,
    ) -> Result<MetaProviderPage, MetaConnectorError> {
        request.validate()?;
        self.validate_binding(&request.api)?;
        let (path, query) = Self::target_request(request)?;
        let (response, body, provider_request_id, digest_pair) =
            self.get(&request.api, path.clone(), query.clone(), token)?;
        let records = parse_records(&request.target, &request.query, &body)?;
        let (response_digest, content_digest) = split_digest_pair(&digest_pair)?;
        let observed_at = request.at;
        let source = MetaSourceReceipt {
            provider: META_PROVIDER_ID.to_owned(),
            surface: request.target.classification(),
            host: request.api.host.base_url().to_owned(),
            api_version: request.api.api_version.clone(),
            method: "GET".to_owned(),
            path: path.clone(),
            query_digest: provider_query_digest(request),
            status: response.status,
            provider_request_id: provider_request_id.clone(),
            response_digest: response_digest.clone(),
            content_digest: content_digest.clone(),
            observed_at,
        };
        let page_digest = digest_json(&(
            &response_digest,
            &content_digest,
            &provider_request_id,
            &records,
        ));
        let next_cursor = body
            .get("paging")
            .and_then(Value::as_object)
            .and_then(|paging| paging.get("cursors"))
            .and_then(Value::as_object)
            .and_then(|cursors| cursors.get("after"))
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(|token| {
                MetaPaginationCursor::new(
                    &request.connector_scope,
                    request.request_digest(),
                    token.to_owned(),
                    request
                        .cursor
                        .as_ref()
                        .map_or(1, |cursor| cursor.sequence + 1),
                    page_digest.clone(),
                )
            })
            .transpose()?;
        let freshness = MetaFreshnessReceipt {
            window: FreshnessWindow::new(
                observed_at,
                observed_at + Duration::seconds(DEFAULT_FRESHNESS_SECONDS),
                1,
            )?,
            query_since: request.query.since(),
            query_until: request.query.until(),
        };
        let rate_limit = rate_limit_receipt(&response, observed_at);
        let cost = MetaCostReceipt {
            unit: "provider_read_request".to_owned(),
            amount_minor: 1,
            limit_minor: 1_000,
            used_minor: 1,
        };
        let quota = MetaQuotaReceipt {
            limit: 1,
            used: 1,
            remaining: Some(0),
        };
        let page = MetaProviderPage {
            records,
            next_cursor,
            source,
            freshness,
            quota,
            cost,
            rate_limit,
            provider_request_id,
            response_digest,
            content_digest,
            observed_at,
        };
        page.validate(request)?;
        Ok(page)
    }
}

fn split_digest_pair(value: &str) -> Result<(String, String), MetaConnectorError> {
    let (response_digest, content_digest) = value
        .split_once(':')
        .ok_or(MetaConnectorError::InvalidProviderResponse)?;
    if !is_sha256(response_digest) || !is_sha256(content_digest) {
        return Err(MetaConnectorError::InvalidProviderResponse);
    }
    Ok((response_digest.to_owned(), content_digest.to_owned()))
}

fn provider_error(response: &MetaHttpResponse, body: &Value) -> MetaConnectorError {
    let code = body
        .get("error")
        .and_then(Value::as_object)
        .and_then(|error| error.get("code"))
        .and_then(Value::as_i64);
    match response.status {
        401 => MetaConnectorError::Unauthorized,
        403 => MetaConnectorError::PermissionDenied,
        404 => MetaConnectorError::ScopeNotAccessible,
        429 => {
            let rate = rate_limit_receipt(response, Utc::now());
            MetaConnectorError::RateLimited {
                reset_at: rate.reset_at,
                retry_after_seconds: rate.retry_after_seconds,
            }
        }
        400 if matches!(code, Some(10 | 200 | 2001 | 190)) => MetaConnectorError::PermissionDenied,
        500..=599 => MetaConnectorError::ProviderUnavailable,
        _ => MetaConnectorError::ProviderRejected,
    }
}

fn facts_fields(target: &MetaReadTarget) -> &'static str {
    match target {
        MetaReadTarget::BusinessFacts => "id,name",
        MetaReadTarget::AdAccountFacts => "id,account_id,name,account_status,currency",
        MetaReadTarget::PageFacts => "id,name,instagram_business_account",
        MetaReadTarget::InstagramAccountFacts => "id,username,name,account_type",
        _ => "",
    }
}

#[allow(clippy::too_many_lines)]
fn parse_records(
    target: &MetaReadTarget,
    query: &MetaInsightQuery,
    body: &Value,
) -> Result<Vec<MetaInsightRecord>, MetaConnectorError> {
    if target.is_facts() {
        let object = body
            .as_object()
            .ok_or(MetaConnectorError::InvalidProviderResponse)?;
        let fields = facts_fields(target)
            .split(',')
            .filter(|field| !field.is_empty())
            .collect::<BTreeSet<_>>();
        let mut records = Vec::new();
        for (field, value) in object {
            if !fields.contains(field.as_str()) {
                continue;
            }
            records.push(MetaInsightRecord {
                target: target.clone(),
                metric: field.clone(),
                value: meta_value(value),
                dimensions: BTreeMap::new(),
                period: None,
                start_time: None,
                end_time: None,
                attribution: MetaAttributionModel::NotApplicable,
                native_payload_digest: digest_json(value),
            });
        }
        if records.is_empty() {
            return Err(MetaConnectorError::InvalidProviderResponse);
        }
        return Ok(records);
    }
    let data = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or(MetaConnectorError::InvalidProviderResponse)?;
    let mut records = Vec::new();
    for item in data {
        let object = item
            .as_object()
            .ok_or(MetaConnectorError::InvalidProviderResponse)?;
        if let Some(values) = object.get("values").and_then(Value::as_array) {
            let metric = object
                .get("name")
                .and_then(Value::as_str)
                .ok_or(MetaConnectorError::InvalidProviderResponse)?;
            for value_item in values {
                let value_object = value_item
                    .as_object()
                    .ok_or(MetaConnectorError::InvalidProviderResponse)?;
                let mut dimensions = BTreeMap::new();
                if let Some(metric_type) = object.get("metric_type").and_then(Value::as_str) {
                    dimensions.insert("metric_type".to_owned(), metric_type.to_owned());
                }
                records.push(MetaInsightRecord {
                    target: target.clone(),
                    metric: metric.to_owned(),
                    value: value_object
                        .get("value")
                        .map_or(MetaValue::Null, meta_value),
                    dimensions,
                    period: object
                        .get("period")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    start_time: value_object
                        .get("start_time")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    end_time: value_object
                        .get("end_time")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    attribution: query.attribution().clone(),
                    native_payload_digest: digest_json(value_item),
                });
            }
            continue;
        }
        for (field, value) in object {
            if matches!(field.as_str(), "date_start" | "date_stop") {
                continue;
            }
            let mut dimensions = BTreeMap::new();
            if field == "account_id" || field == "account_name" || field == "campaign_id" {
                dimensions.insert(field.clone(), value_to_dimension(value));
                continue;
            }
            if !valid_metric(field) {
                continue;
            }
            records.push(MetaInsightRecord {
                target: target.clone(),
                metric: field.clone(),
                value: meta_value(value),
                dimensions,
                period: None,
                start_time: object
                    .get("date_start")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                end_time: object
                    .get("date_stop")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                attribution: query.attribution().clone(),
                native_payload_digest: digest_json(item),
            });
        }
    }
    Ok(records)
}

fn meta_value(value: &Value) -> MetaValue {
    match value {
        Value::Null => MetaValue::Null,
        Value::Bool(value) => MetaValue::Boolean(*value),
        Value::Number(value) => value
            .as_i64()
            .map_or_else(|| MetaValue::Float(value.to_string()), MetaValue::Integer),
        Value::String(value) => MetaValue::String(value.clone()),
        Value::Array(_) | Value::Object(_) => MetaValue::ObjectDigest(digest_json(value)),
    }
}

fn value_to_dimension(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_owned(),
        Value::Array(_) | Value::Object(_) => digest_json(value),
    }
}

fn date_string(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%d").to_string()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaConnectionState {
    Disconnected,
    Mounted,
    Stale,
    Revoked,
}

#[derive(Clone, Debug)]
pub struct MetaMount {
    connector_scope: ConnectorScope,
    meta_scope: MetaScope,
    api: MetaApiBinding,
    secret_reference: SecretReference,
    lease: CredentialLease,
    probe: MetaProbeObservation,
    state: MetaConnectionState,
}

impl MetaMount {
    pub fn new(
        request: &MetaProbeRequest,
        probe: MetaProbeObservation,
    ) -> Result<Self, MetaConnectorError> {
        probe.validate(request)?;
        Ok(Self {
            connector_scope: request.connector_scope.clone(),
            meta_scope: request.meta_scope.clone(),
            api: request.api.clone(),
            secret_reference: request.secret_reference.clone(),
            lease: request.lease.clone(),
            probe,
            state: MetaConnectionState::Mounted,
        })
    }

    pub fn connector_scope(&self) -> &ConnectorScope {
        &self.connector_scope
    }

    pub fn meta_scope(&self) -> &MetaScope {
        &self.meta_scope
    }

    pub fn api(&self) -> &MetaApiBinding {
        &self.api
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn lease(&self) -> &CredentialLease {
        &self.lease
    }

    pub fn probe(&self) -> &MetaProbeObservation {
        &self.probe
    }

    pub const fn state(&self) -> MetaConnectionState {
        self.state
    }

    fn validate_request(&self, request: &MetaInsightReadRequest) -> Result<(), MetaConnectorError> {
        if self.state != MetaConnectionState::Mounted
            || self.connector_scope != request.connector_scope
            || self.meta_scope != request.meta_scope
            || self.api != request.api
            || self.secret_reference != request.secret_reference
            || self.lease != request.lease
        {
            return Err(MetaConnectorError::RefreshDrift);
        }
        if request.at < self.probe.observed_at {
            return Err(MetaConnectorError::ProbeStale);
        }
        if request.at >= self.probe.expires_at {
            return Err(MetaConnectorError::FreshnessExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetaCapability {
    PaidSocialInsightRead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaMissionCapabilityGrant {
    pub capability: MetaCapability,
    pub connection_state: MetaConnectionState,
    pub scope_digest: String,
    pub probe_digest: String,
    pub connected_claim: bool,
    pub write_authority: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaInsightObservation {
    pub schema: String,
    pub observation_id: String,
    pub connector_scope: ConnectorScope,
    pub meta_scope: MetaScope,
    pub api: MetaApiBinding,
    pub target: MetaReadTarget,
    pub records: Vec<MetaInsightRecord>,
    pub source: MetaSourceReceipt,
    pub freshness: MetaFreshnessReceipt,
    pub quota: MetaQuotaReceipt,
    pub cost: MetaCostReceipt,
    pub rate_limit: MetaRateLimitReceipt,
    pub request_digest: String,
    pub provider_query_digest: String,
    pub response_digest: String,
    pub content_digest: String,
    pub cursor: Option<MetaCursorReceipt>,
    pub page_sequence: u64,
    pub classification: MetaClassificationReceipt,
    pub durable_logged: bool,
    pub causal_status: MetaCausalStatus,
}

impl MetaInsightObservation {
    fn validate(&self) -> Result<(), MetaConnectorError> {
        self.source.validate()?;
        self.freshness.validate()?;
        if self.schema != META_INSIGHT_READ_SCHEMA
            || self.observation_id.is_empty()
            || self.connector_scope.provider_id() != META_PROVIDER_ID
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.provider_query_digest)
            || !is_sha256(&self.response_digest)
            || !is_sha256(&self.content_digest)
            || self.source.query_digest != self.provider_query_digest
            || self.source.response_digest != self.response_digest
            || self.source.content_digest != self.content_digest
            || self.source.observed_at != self.freshness.window.observed_at()
            || self.freshness.query_until <= self.freshness.query_since
            || self.quota.used > self.quota.limit
            || self.cost.amount_minor < 0
            || self.cost.used_minor < self.cost.amount_minor
            || self.cost.used_minor > self.cost.limit_minor
            || self.page_sequence == 0
            || !self.durable_logged
            || self.causal_status != MetaCausalStatus::NotClaimed
            || self.classification.causal_status != MetaCausalStatus::NotClaimed
            || self.classification.first_party
                != (self.classification.provenance_class
                    == ProviderProvenanceClass::ProductionProvider)
            || self.classification.review_state != MetaReviewState::Required
        {
            return Err(MetaConnectorError::InvalidObservation);
        }
        self.connector_scope
            .provider_id()
            .eq(META_PROVIDER_ID)
            .then_some(())
            .ok_or(MetaConnectorError::InvalidObservation)?;
        Ok(())
    }

    pub fn digest(&self) -> String {
        digest_json(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaMissionInsightResult {
    pub result_id: String,
    pub capability: MetaCapability,
    pub observation: MetaInsightObservation,
    pub durable_logged: bool,
    pub connected_claim: bool,
    pub write_authority: bool,
}

impl MetaMissionInsightResult {
    fn validate(&self) -> Result<(), MetaConnectorError> {
        self.observation.validate()?;
        if self.result_id.is_empty()
            || self.capability != MetaCapability::PaidSocialInsightRead
            || !self.durable_logged
            || !self.observation.durable_logged
            || self.connected_claim
            || self.write_authority
        {
            return Err(MetaConnectorError::InvalidObservation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaDurableObservationLog {
    pub schema: String,
    pub entries: Vec<MetaInsightObservation>,
}

impl Default for MetaDurableObservationLog {
    fn default() -> Self {
        Self {
            schema: META_INSIGHT_READ_SCHEMA.to_owned(),
            entries: Vec::new(),
        }
    }
}

impl MetaDurableObservationLog {
    pub fn entries(&self) -> &[MetaInsightObservation] {
        &self.entries
    }

    fn append(&mut self, observation: MetaInsightObservation) -> Result<(), MetaConnectorError> {
        observation.validate()?;
        if self
            .entries
            .iter()
            .any(|entry| entry.digest() == observation.digest())
        {
            return Err(MetaConnectorError::DuplicateObservation);
        }
        self.entries.push(observation);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaDurableState {
    pub schema: String,
    pub log: MetaDurableObservationLog,
    pub seen_page_digests: BTreeSet<String>,
    pub seen_cursor_token_digests: BTreeSet<String>,
    pub current_cursor: Option<MetaPaginationCursor>,
    pub next_observation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaReadBudget {
    rate_remaining: u64,
    rate_reset_at: DateTime<Utc>,
    quota_limit: u64,
    quota_used: u64,
    cost_limit_minor: i64,
    cost_used_minor: i64,
}

impl MetaReadBudget {
    pub fn new(
        rate_remaining: u64,
        rate_reset_at: DateTime<Utc>,
        quota_limit: u64,
        cost_limit_minor: i64,
    ) -> Result<Self, MetaConnectorError> {
        if cost_limit_minor < 0 {
            return Err(MetaConnectorError::BudgetExceeded);
        }
        Ok(Self {
            rate_remaining,
            rate_reset_at,
            quota_limit,
            quota_used: 0,
            cost_limit_minor,
            cost_used_minor: 0,
        })
    }

    pub const fn rate_remaining(&self) -> u64 {
        self.rate_remaining
    }

    pub const fn quota_used(&self) -> u64 {
        self.quota_used
    }

    pub const fn cost_used_minor(&self) -> i64 {
        self.cost_used_minor
    }

    fn admit(&mut self, at: DateTime<Utc>) -> Result<(), MetaConnectorError> {
        if at >= self.rate_reset_at && self.rate_remaining == 0 {
            self.rate_remaining = 1;
        }
        if self.rate_remaining == 0
            || self.quota_used >= self.quota_limit
            || self.cost_used_minor >= self.cost_limit_minor
        {
            return Err(MetaConnectorError::BudgetExceeded);
        }
        self.rate_remaining -= 1;
        self.quota_used += 1;
        self.cost_used_minor += 1;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaWebhookPendingDelivery {
    pub delivery: MetaWebhookDeliveryReceipt,
}

impl MetaWebhookPendingDelivery {
    fn validate(&self) -> Result<(), MetaConnectorError> {
        self.delivery.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaWebhookMissionResult {
    pub result_id: String,
    pub delivery: MetaWebhookDeliveryReceipt,
    pub observation: MetaInsightObservation,
    pub durable_logged: bool,
    pub connected_claim: bool,
    pub write_authority: bool,
}

impl MetaWebhookMissionResult {
    fn validate(&self) -> Result<(), MetaConnectorError> {
        self.delivery.validate()?;
        self.observation.validate()?;
        if !valid_webhook_identity(&self.result_id)
            || self.delivery.scope_digest != self.observation.connector_scope.digest()
            || self.delivery.meta_scope_digest != self.observation.meta_scope.digest()
            || self.delivery.api_digest != self.observation.api.digest()
            || self.delivery.reconcile_request_digest != self.observation.request_digest
            || !self.durable_logged
            || !self.observation.durable_logged
            || self.connected_claim
            || self.write_authority
        {
            return Err(MetaConnectorError::InvalidWebhookState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaWebhookDurableState {
    pub schema: String,
    pub pending: BTreeMap<String, MetaWebhookPendingDelivery>,
    pub completed: BTreeMap<String, MetaWebhookMissionResult>,
    pub next_result: u64,
}

impl Default for MetaWebhookDurableState {
    fn default() -> Self {
        Self {
            schema: META_WEBHOOK_SCHEMA.to_owned(),
            pending: BTreeMap::new(),
            completed: BTreeMap::new(),
            next_result: 1,
        }
    }
}

impl MetaWebhookDurableState {
    fn validate(&self) -> Result<(), MetaConnectorError> {
        if self.schema != META_WEBHOOK_SCHEMA || self.next_result == 0 {
            return Err(MetaConnectorError::InvalidWebhookState);
        }
        if self
            .pending
            .keys()
            .chain(self.completed.keys())
            .any(|delivery_id| !valid_webhook_identity(delivery_id))
        {
            return Err(MetaConnectorError::InvalidWebhookState);
        }
        if self
            .pending
            .keys()
            .any(|delivery_id| self.completed.contains_key(delivery_id))
        {
            return Err(MetaConnectorError::InvalidWebhookState);
        }
        for (delivery_id, pending) in &self.pending {
            pending.validate()?;
            if pending.delivery.delivery_id != *delivery_id {
                return Err(MetaConnectorError::InvalidWebhookState);
            }
        }
        for (delivery_id, result) in &self.completed {
            result.validate()?;
            if result.delivery.delivery_id != *delivery_id {
                return Err(MetaConnectorError::InvalidWebhookState);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetaWebhookReconcileCheckpoint {
    pub schema: String,
    pub insight: MetaDurableState,
    pub webhooks: MetaWebhookDurableState,
}

#[derive(Clone)]
pub struct MetaWebhookReconcileService {
    insight: PaidSocialInsightReadService,
    webhook_provider: Arc<dyn MetaWebhookProvider>,
    webhooks: MetaWebhookDurableState,
}

impl fmt::Debug for MetaWebhookReconcileService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MetaWebhookReconcileService")
            .field("connection_state", &self.insight.connection_state())
            .field("pending_deliveries", &self.webhooks.pending.len())
            .field("completed_deliveries", &self.webhooks.completed.len())
            .finish_non_exhaustive()
    }
}

impl MetaWebhookReconcileService {
    pub fn new(insight: PaidSocialInsightReadService) -> Self {
        Self::with_webhook_provider(insight, Arc::new(MetaGraphWebhookAdapter))
    }

    pub fn with_webhook_provider(
        insight: PaidSocialInsightReadService,
        webhook_provider: Arc<dyn MetaWebhookProvider>,
    ) -> Self {
        Self {
            insight,
            webhook_provider,
            webhooks: MetaWebhookDurableState::default(),
        }
    }

    pub fn service(&self) -> &PaidSocialInsightReadService {
        &self.insight
    }

    pub fn service_mut(&mut self) -> &mut PaidSocialInsightReadService {
        &mut self.insight
    }

    pub fn webhook_state(&self) -> &MetaWebhookDurableState {
        &self.webhooks
    }

    pub fn pending_delivery_ids(&self) -> Vec<String> {
        self.webhooks.pending.keys().cloned().collect()
    }

    pub fn read<R: MetaCredentialResolver>(
        &mut self,
        request: &MetaInsightReadRequest,
        resolver: &R,
        budget: &mut MetaReadBudget,
    ) -> Result<MetaMissionInsightResult, MetaConnectorError> {
        self.insight.read(request, resolver, budget)
    }

    pub fn accept_webhook<S: MetaWebhookSecretResolver>(
        &mut self,
        request: &MetaWebhookDeliveryRequest,
        resolver: &S,
    ) -> Result<MetaWebhookDeliveryReceipt, MetaConnectorError> {
        request.validate()?;
        let mount = self
            .insight
            .mount
            .as_ref()
            .ok_or(MetaConnectorError::NotMounted)?;
        mount.validate_request(&request.reconcile_request)?;
        let app_secret = resolver.resolve(&request.reconcile_request.secret_reference)?;
        let verified = self.webhook_provider.verify(request, &app_secret)?;
        let subscription_digest = request.subscription.digest();
        if verified.payload_digest != request.payload_digest()
            || verified.signature_digest != request.signature_digest()
            || verified.object != request.subscription.object()
        {
            return Err(MetaConnectorError::InvalidWebhookDelivery);
        }

        if let Some(result) = self.webhooks.completed.get(&request.delivery_id) {
            if !same_webhook_identity(&result.delivery, request, &verified, &subscription_digest) {
                return Err(MetaConnectorError::InvalidWebhookDelivery);
            }
            return Ok(result.delivery.clone());
        }
        if let Some(pending) = self.webhooks.pending.get(&request.delivery_id) {
            if !same_webhook_identity(&pending.delivery, request, &verified, &subscription_digest) {
                return Err(MetaConnectorError::InvalidWebhookDelivery);
            }
            return Ok(pending.delivery.clone());
        }

        let response_digest = sha256(&format!(
            "accepted:{}:{}",
            request.delivery_id, verified.event_digest
        ));
        let request_digest = request.request_digest();
        let source = MetaWebhookSourceReceipt {
            source: "meta_webhook".to_owned(),
            provider: META_PROVIDER_ID.to_owned(),
            host: request.reconcile_request.api.host.base_url().to_owned(),
            api_version: request.reconcile_request.api.api_version.clone(),
            method: "POST".to_owned(),
            path: "/meta/webhook".to_owned(),
            status: 202,
            delivery_id: request.delivery_id.clone(),
            request_digest: request_digest.clone(),
            response_digest: response_digest.clone(),
            payload_digest: verified.payload_digest.clone(),
            observed_at: request.at,
        };
        let provenance_class = mount.probe.classification.provenance_class;
        let receipt = MetaWebhookDeliveryReceipt {
            schema: META_WEBHOOK_SCHEMA.to_owned(),
            provider: META_PROVIDER_ID.to_owned(),
            subscription_id: request.subscription.subscription_id.clone(),
            subscription_digest,
            scope_digest: request.reconcile_request.connector_scope.digest(),
            meta_scope_digest: request.reconcile_request.meta_scope.digest(),
            api_digest: request.reconcile_request.api.digest(),
            delivery_id: request.delivery_id.clone(),
            event_id: request.event_id.clone(),
            event_digest: verified.event_digest,
            payload_digest: verified.payload_digest,
            signature_digest: verified.signature_digest,
            request_digest,
            reconcile_request_digest: request.reconcile_request.request_digest(),
            reconcile_cursor_token_digest: webhook_cursor_token_digest(&request.reconcile_request),
            credential_binding_digest: webhook_credential_binding_digest(
                &request.reconcile_request,
            ),
            response_digest,
            source,
            classification: MetaClassificationReceipt {
                provenance_class,
                surface: webhook_surface(&verified.object)?,
                attribution: MetaAttributionModel::NotApplicable,
                causal_status: MetaCausalStatus::NotClaimed,
                first_party: provenance_class == ProviderProvenanceClass::ProductionProvider,
                review_state: MetaReviewState::Required,
            },
            causal_status: MetaCausalStatus::NotClaimed,
            durable_logged: true,
        };
        receipt.validate()?;
        self.webhooks.pending.insert(
            request.delivery_id.clone(),
            MetaWebhookPendingDelivery {
                delivery: receipt.clone(),
            },
        );
        Ok(receipt)
    }

    pub fn reconcile_webhook<R: MetaCredentialResolver>(
        &mut self,
        delivery_id: &str,
        request: &MetaInsightReadRequest,
        resolver: &R,
        budget: &mut MetaReadBudget,
    ) -> Result<MetaWebhookMissionResult, MetaConnectorError> {
        self.validate_reconcile_request(delivery_id, request)?;
        if let Some(result) = self.webhooks.completed.get(delivery_id) {
            return Ok(result.clone());
        }
        let pending = self
            .webhooks
            .pending
            .get(delivery_id)
            .cloned()
            .ok_or(MetaConnectorError::WebhookDeliveryNotPending)?;
        let next_result = self
            .webhooks
            .next_result
            .checked_add(1)
            .ok_or(MetaConnectorError::InvalidWebhookState)?;
        let insight = self.insight.read(request, resolver, budget)?;
        if pending.delivery.classification.provenance_class
            != insight.observation.classification.provenance_class
        {
            return Err(MetaConnectorError::InvalidWebhookState);
        }
        let result = MetaWebhookMissionResult {
            result_id: format!("meta-webhook-result-{}", self.webhooks.next_result),
            delivery: pending.delivery,
            observation: insight.observation,
            durable_logged: true,
            connected_claim: false,
            write_authority: false,
        };
        result.validate()?;
        self.webhooks.pending.remove(delivery_id);
        self.webhooks
            .completed
            .insert(delivery_id.to_owned(), result.clone());
        self.webhooks.next_result = next_result;
        Ok(result)
    }

    pub fn deliver_and_reconcile<S: MetaWebhookSecretResolver, R: MetaCredentialResolver>(
        &mut self,
        request: &MetaWebhookDeliveryRequest,
        secret_resolver: &S,
        credential_resolver: &R,
        budget: &mut MetaReadBudget,
    ) -> Result<MetaWebhookMissionResult, MetaConnectorError> {
        self.accept_webhook(request, secret_resolver)?;
        self.reconcile_webhook(
            &request.delivery_id,
            &request.reconcile_request,
            credential_resolver,
            budget,
        )
    }

    pub fn checkpoint(&self) -> MetaWebhookReconcileCheckpoint {
        MetaWebhookReconcileCheckpoint {
            schema: META_WEBHOOK_SCHEMA.to_owned(),
            insight: self.insight.checkpoint(),
            webhooks: self.webhooks.clone(),
        }
    }

    pub fn restore_checkpoint(
        &mut self,
        checkpoint: MetaWebhookReconcileCheckpoint,
    ) -> Result<(), MetaConnectorError> {
        if checkpoint.schema != META_WEBHOOK_SCHEMA {
            return Err(MetaConnectorError::InvalidWebhookState);
        }
        checkpoint.webhooks.validate()?;
        self.insight.restore_checkpoint(checkpoint.insight)?;
        self.webhooks = checkpoint.webhooks;
        Ok(())
    }

    pub fn unmount(&mut self) {
        self.insight.unmount();
        self.webhooks.pending.clear();
        self.webhooks.completed.clear();
    }

    pub fn revoke(&mut self) {
        self.insight.revoke();
        self.webhooks.pending.clear();
        self.webhooks.completed.clear();
    }

    fn validate_reconcile_request(
        &self,
        delivery_id: &str,
        request: &MetaInsightReadRequest,
    ) -> Result<(), MetaConnectorError> {
        request.validate()?;
        let mount = self
            .insight
            .mount
            .as_ref()
            .ok_or(MetaConnectorError::NotMounted)?;
        mount.validate_request(request)?;
        let receipt = self
            .webhooks
            .completed
            .get(delivery_id)
            .map(|result| &result.delivery)
            .or_else(|| {
                self.webhooks
                    .pending
                    .get(delivery_id)
                    .map(|pending| &pending.delivery)
            })
            .ok_or(MetaConnectorError::WebhookDeliveryNotPending)?;
        if receipt.scope_digest != request.connector_scope.digest()
            || receipt.meta_scope_digest != request.meta_scope.digest()
            || receipt.api_digest != request.api.digest()
            || receipt.reconcile_request_digest != request.request_digest()
            || receipt.reconcile_cursor_token_digest != webhook_cursor_token_digest(request)
            || receipt.credential_binding_digest != webhook_credential_binding_digest(request)
        {
            return Err(MetaConnectorError::RefreshDrift);
        }
        Ok(())
    }
}

fn same_webhook_identity(
    receipt: &MetaWebhookDeliveryReceipt,
    request: &MetaWebhookDeliveryRequest,
    verified: &MetaWebhookVerifiedDelivery,
    subscription_digest: &str,
) -> bool {
    receipt.delivery_id == request.delivery_id
        && receipt.event_id == request.event_id
        && receipt.subscription_digest == subscription_digest
        && receipt.payload_digest == verified.payload_digest
        && receipt.event_digest == verified.event_digest
        && receipt.signature_digest == verified.signature_digest
        && receipt.request_digest == request.request_digest()
        && receipt.reconcile_request_digest == request.reconcile_request.request_digest()
        && receipt.reconcile_cursor_token_digest
            == webhook_cursor_token_digest(&request.reconcile_request)
        && receipt.credential_binding_digest
            == webhook_credential_binding_digest(&request.reconcile_request)
}

#[derive(Clone)]
pub struct PaidSocialInsightReadService {
    provider: Arc<dyn MetaInsightProvider>,
    mount: Option<MetaMount>,
    state: MetaConnectionState,
    log: MetaDurableObservationLog,
    seen_page_digests: BTreeSet<String>,
    seen_cursor_token_digests: BTreeSet<String>,
    current_cursor: Option<MetaPaginationCursor>,
    next_observation: u64,
}

impl fmt::Debug for PaidSocialInsightReadService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(META_SERVICE_ID)
            .field("state", &self.state)
            .field("mounted", &self.mount.is_some())
            .field("observation_count", &self.log.entries.len())
            .field("current_cursor", &self.current_cursor)
            .finish_non_exhaustive()
    }
}

impl PaidSocialInsightReadService {
    pub fn new(provider: Arc<dyn MetaInsightProvider>) -> Self {
        Self {
            provider,
            mount: None,
            state: MetaConnectionState::Disconnected,
            log: MetaDurableObservationLog::default(),
            seen_page_digests: BTreeSet::new(),
            seen_cursor_token_digests: BTreeSet::new(),
            current_cursor: None,
            next_observation: 1,
        }
    }

    pub fn probe_and_mount<R: MetaCredentialResolver>(
        &mut self,
        request: &MetaProbeRequest,
        resolver: &R,
    ) -> Result<MetaMissionCapabilityGrant, MetaConnectorError> {
        let token = resolver.resolve(&request.secret_reference)?;
        let probe = self.provider.probe(request, &token)?;
        let mount = MetaMount::new(request, probe)?;
        let grant = Self::grant_for(&mount);
        self.mount = Some(mount);
        self.state = MetaConnectionState::Mounted;
        self.current_cursor = None;
        self.seen_page_digests.clear();
        self.seen_cursor_token_digests.clear();
        Ok(grant)
    }

    pub fn refresh_mount<R: MetaCredentialResolver>(
        &mut self,
        request: &MetaProbeRequest,
        resolver: &R,
    ) -> Result<MetaMissionCapabilityGrant, MetaConnectorError> {
        let existing = self.mount.as_ref().ok_or(MetaConnectorError::NotMounted)?;
        if existing.connector_scope != request.connector_scope
            || existing.meta_scope != request.meta_scope
            || existing.api != request.api
            || existing.secret_reference != request.secret_reference
            || existing.lease != request.lease
        {
            self.state = MetaConnectionState::Stale;
            return Err(MetaConnectorError::RefreshDrift);
        }
        self.probe_and_mount(request, resolver)
    }

    pub fn mount(
        &mut self,
        mount: MetaMount,
    ) -> Result<MetaMissionCapabilityGrant, MetaConnectorError> {
        if mount.state != MetaConnectionState::Mounted {
            return Err(MetaConnectorError::InvalidProbe);
        }
        let grant = Self::grant_for(&mount);
        self.mount = Some(mount);
        self.state = MetaConnectionState::Mounted;
        Ok(grant)
    }

    pub const fn connection_state(&self) -> MetaConnectionState {
        self.state
    }

    pub fn grant(&self) -> MetaMissionCapabilityGrant {
        self.mount.as_ref().map_or(
            MetaMissionCapabilityGrant {
                capability: MetaCapability::PaidSocialInsightRead,
                connection_state: self.state,
                scope_digest: String::new(),
                probe_digest: String::new(),
                connected_claim: false,
                write_authority: false,
            },
            Self::grant_for,
        )
    }

    pub fn durable_log(&self) -> &MetaDurableObservationLog {
        &self.log
    }

    pub fn current_cursor(&self) -> Option<&MetaPaginationCursor> {
        self.current_cursor.as_ref()
    }

    #[allow(clippy::too_many_lines)]
    pub fn read<R: MetaCredentialResolver>(
        &mut self,
        request: &MetaInsightReadRequest,
        resolver: &R,
        budget: &mut MetaReadBudget,
    ) -> Result<MetaMissionInsightResult, MetaConnectorError> {
        request.validate()?;
        let mount = self.mount.as_ref().ok_or(MetaConnectorError::NotMounted)?;
        mount.validate_request(request)?;
        let provenance_class = mount.probe.classification.provenance_class;
        let first_party = mount.probe.classification.first_party;
        if let Some(current) = &self.current_cursor {
            if request.cursor.as_ref() != Some(current) {
                return Err(MetaConnectorError::CursorMismatch);
            }
        } else if request.cursor.is_some() {
            return Err(MetaConnectorError::CursorMismatch);
        }
        let token = resolver.resolve(&request.secret_reference)?;
        budget.admit(request.at)?;
        let mut page = match self.provider.read(request, &token) {
            Ok(page) => page,
            Err(
                error @ (MetaConnectorError::Unauthorized | MetaConnectorError::PermissionDenied),
            ) => {
                self.state = MetaConnectionState::Stale;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        page.quota = MetaQuotaReceipt {
            limit: budget.quota_limit,
            used: budget.quota_used,
            remaining: Some(budget.quota_limit.saturating_sub(budget.quota_used)),
        };
        page.cost = MetaCostReceipt {
            unit: "provider_read_request".to_owned(),
            amount_minor: 1,
            limit_minor: budget.cost_limit_minor,
            used_minor: budget.cost_used_minor,
        };
        let page_digest = digest_json(&(
            &page.response_digest,
            &page.content_digest,
            &page.provider_request_id,
            &page.records,
        ));
        if !self.seen_page_digests.insert(page_digest) {
            return Err(MetaConnectorError::DuplicatePage);
        }
        if let Some(cursor) = &request.cursor
            && !self
                .seen_cursor_token_digests
                .insert(cursor.token_digest().to_owned())
        {
            return Err(MetaConnectorError::DuplicatePage);
        }
        if let (Some(previous), Some(next)) = (&self.current_cursor, &page.next_cursor)
            && next.sequence() <= previous.sequence()
        {
            return Err(MetaConnectorError::CursorRollback);
        }
        let page_sequence = page.next_cursor.as_ref().map_or_else(
            || {
                self.current_cursor
                    .as_ref()
                    .map_or(1, |cursor| cursor.sequence() + 1)
            },
            MetaPaginationCursor::sequence,
        );
        let observation = MetaInsightObservation {
            schema: META_INSIGHT_READ_SCHEMA.to_owned(),
            observation_id: format!("meta-observation-{}", self.next_observation),
            connector_scope: request.connector_scope.clone(),
            meta_scope: request.meta_scope.clone(),
            api: request.api.clone(),
            target: request.target.clone(),
            records: page.records.clone(),
            source: page.source.clone(),
            freshness: page.freshness.clone(),
            quota: page.quota.clone(),
            cost: page.cost.clone(),
            rate_limit: page.rate_limit.clone(),
            request_digest: request.request_digest(),
            provider_query_digest: page.source.query_digest.clone(),
            response_digest: page.response_digest.clone(),
            content_digest: page.content_digest.clone(),
            cursor: page
                .next_cursor
                .as_ref()
                .map(MetaCursorReceipt::from_cursor),
            page_sequence,
            classification: MetaClassificationReceipt {
                provenance_class,
                surface: request.target.classification(),
                attribution: request.query.attribution().clone(),
                causal_status: MetaCausalStatus::NotClaimed,
                first_party,
                review_state: MetaReviewState::Required,
            },
            durable_logged: true,
            causal_status: MetaCausalStatus::NotClaimed,
        };
        observation.validate()?;
        self.log.append(observation.clone())?;
        self.next_observation += 1;
        self.current_cursor.clone_from(&page.next_cursor);
        let result = MetaMissionInsightResult {
            result_id: format!("meta-result-{}", self.next_observation - 1),
            capability: MetaCapability::PaidSocialInsightRead,
            observation,
            durable_logged: true,
            connected_claim: false,
            write_authority: false,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn checkpoint(&self) -> MetaDurableState {
        MetaDurableState {
            schema: META_INSIGHT_READ_SCHEMA.to_owned(),
            log: self.log.clone(),
            seen_page_digests: self.seen_page_digests.clone(),
            seen_cursor_token_digests: self.seen_cursor_token_digests.clone(),
            current_cursor: self.current_cursor.clone(),
            next_observation: self.next_observation,
        }
    }

    pub fn restore_checkpoint(
        &mut self,
        state: MetaDurableState,
    ) -> Result<(), MetaConnectorError> {
        if state.schema != META_INSIGHT_READ_SCHEMA
            || state.next_observation == 0
            || state.log.schema != META_INSIGHT_READ_SCHEMA
            || state
                .current_cursor
                .as_ref()
                .is_some_and(|cursor| !is_sha256(cursor.request_digest()))
            || state
                .seen_page_digests
                .iter()
                .any(|digest| !is_sha256(digest))
            || state
                .seen_cursor_token_digests
                .iter()
                .any(|digest| !is_sha256(digest))
        {
            return Err(MetaConnectorError::InvalidCheckpoint);
        }
        let mut log_digests = BTreeSet::new();
        for entry in &state.log.entries {
            if entry.validate().is_err() || !log_digests.insert(entry.digest()) {
                return Err(MetaConnectorError::InvalidCheckpoint);
            }
        }
        self.log = state.log;
        self.seen_page_digests = state.seen_page_digests;
        self.seen_cursor_token_digests = state.seen_cursor_token_digests;
        self.current_cursor = state.current_cursor;
        self.next_observation = state.next_observation;
        Ok(())
    }

    pub fn unmount(&mut self) {
        self.mount = None;
        self.current_cursor = None;
        self.seen_page_digests.clear();
        self.seen_cursor_token_digests.clear();
        self.state = MetaConnectionState::Disconnected;
    }

    pub fn revoke(&mut self) {
        self.mount = None;
        self.current_cursor = None;
        self.seen_page_digests.clear();
        self.seen_cursor_token_digests.clear();
        self.state = MetaConnectionState::Revoked;
    }

    pub fn prepare_effect(&self) -> Result<(), MetaConnectorError> {
        Err(MetaConnectorError::WritesDisabled)
    }

    fn grant_for(mount: &MetaMount) -> MetaMissionCapabilityGrant {
        MetaMissionCapabilityGrant {
            capability: MetaCapability::PaidSocialInsightRead,
            connection_state: mount.state,
            scope_digest: mount.connector_scope.digest(),
            probe_digest: mount.probe.digest(),
            connected_claim: false,
            write_authority: false,
        }
    }
}

pub type MetaInsightReadService = PaidSocialInsightReadService;

#[derive(Clone, Debug)]
pub struct MetaMissionInsightConsumer {
    service: MetaWebhookReconcileService,
}

impl MetaMissionInsightConsumer {
    pub fn new(service: PaidSocialInsightReadService) -> Self {
        Self {
            service: MetaWebhookReconcileService::new(service),
        }
    }

    pub fn with_webhook_provider(
        service: PaidSocialInsightReadService,
        webhook_provider: Arc<dyn MetaWebhookProvider>,
    ) -> Self {
        Self {
            service: MetaWebhookReconcileService::with_webhook_provider(service, webhook_provider),
        }
    }

    pub fn service(&self) -> &PaidSocialInsightReadService {
        self.service.service()
    }

    pub fn service_mut(&mut self) -> &mut PaidSocialInsightReadService {
        self.service.service_mut()
    }

    pub fn webhook_service(&self) -> &MetaWebhookReconcileService {
        &self.service
    }

    pub fn webhook_service_mut(&mut self) -> &mut MetaWebhookReconcileService {
        &mut self.service
    }

    pub fn read<R: MetaCredentialResolver>(
        &mut self,
        request: &MetaInsightReadRequest,
        resolver: &R,
        budget: &mut MetaReadBudget,
    ) -> Result<MetaMissionInsightResult, MetaConnectorError> {
        self.service.read(request, resolver, budget)
    }

    pub fn handle_webhook<S: MetaWebhookSecretResolver, R: MetaCredentialResolver>(
        &mut self,
        request: &MetaWebhookDeliveryRequest,
        secret_resolver: &S,
        credential_resolver: &R,
        budget: &mut MetaReadBudget,
    ) -> Result<MetaWebhookMissionResult, MetaConnectorError> {
        self.service
            .deliver_and_reconcile(request, secret_resolver, credential_resolver, budget)
    }

    pub fn checkpoint(&self) -> MetaWebhookReconcileCheckpoint {
        self.service.checkpoint()
    }

    pub fn restore_checkpoint(
        &mut self,
        checkpoint: MetaWebhookReconcileCheckpoint,
    ) -> Result<(), MetaConnectorError> {
        self.service.restore_checkpoint(checkpoint)
    }

    pub fn unmount(&mut self) {
        self.service.unmount();
    }

    pub fn revoke(&mut self) {
        self.service.revoke();
    }
}

pub fn run_env_gated_probe(
    request: &MetaProbeRequest,
) -> Result<MetaProbeObservation, MetaConnectorError> {
    if std::env::var(META_RUN_PROBE_ENV).ok().as_deref() != Some("1") {
        return Err(MetaConnectorError::BlockedEnv);
    }
    let resolver = EnvironmentMetaCredentialResolver;
    let token = resolver.resolve(&request.secret_reference)?;
    let adapter = MetaGraphApiAdapter::production()?;
    adapter.probe(request, &token)
}

pub fn run_env_gated_webhook_reconcile(
    service: &mut MetaWebhookReconcileService,
    request: &MetaWebhookDeliveryRequest,
    budget: &mut MetaReadBudget,
) -> Result<MetaWebhookMissionResult, MetaConnectorError> {
    if std::env::var(META_RUN_WEBHOOK_RECONCILE_ENV)
        .ok()
        .as_deref()
        != Some("1")
    {
        return Err(MetaConnectorError::BlockedEnv);
    }
    let subscription_id =
        std::env::var(META_WEBHOOK_SUBSCRIPTION_ENV).map_err(|_| MetaConnectorError::BlockedEnv)?;
    if subscription_id != request.subscription.subscription_id {
        return Err(MetaConnectorError::BlockedEnv);
    }
    let secret_resolver = EnvironmentMetaWebhookSecretResolver;
    let credential_resolver = EnvironmentMetaCredentialResolver;
    service.deliver_and_reconcile(request, &secret_resolver, &credential_resolver, budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectorAuth, ProviderAdapterIdentity};
    use std::collections::VecDeque;
    use std::fmt::Write as _;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct ScriptedMetaTransport {
        responses: Mutex<VecDeque<MetaHttpResponse>>,
        requests: Mutex<Vec<MetaHttpRequest>>,
    }

    impl ScriptedMetaTransport {
        fn new(responses: impl IntoIterator<Item = MetaHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<MetaHttpRequest> {
            self.requests.lock().expect("request lock").clone()
        }
    }

    impl MetaHttpTransport for ScriptedMetaTransport {
        fn provenance_class(&self) -> ProviderProvenanceClass {
            ProviderProvenanceClass::ComponentHarness
        }

        fn get(
            &self,
            request: &MetaHttpRequest,
            _token: &MetaAccessToken,
        ) -> Result<MetaHttpResponse, MetaConnectorError> {
            self.requests
                .lock()
                .expect("request lock")
                .push(request.clone());
            self.responses
                .lock()
                .expect("response lock")
                .pop_front()
                .ok_or(MetaConnectorError::Transport(
                    "scripted response queue exhausted".to_owned(),
                ))
        }
    }

    fn fixture() -> (
        ConnectorScope,
        MetaScope,
        MetaApiBinding,
        SecretReference,
        CredentialLease,
        InMemoryMetaCredentialResolver,
        DateTime<Utc>,
    ) {
        let connector_scope = ConnectorScope::new(
            "tenant",
            "project",
            META_PROVIDER_ID,
            "123",
            [
                "business_management".to_owned(),
                "ads_read".to_owned(),
                "instagram_basic".to_owned(),
                "instagram_manage_insights".to_owned(),
                "pages_read_engagement".to_owned(),
            ],
        )
        .expect("connector scope");
        let meta_scope = MetaScope::new(
            "123",
            Some("act_123".to_owned()),
            Some("456".to_owned()),
            Some("789".to_owned()),
        )
        .expect("Meta scope");
        let api = MetaApiBinding::new(MetaGraphHost::Facebook, META_DEFAULT_API_VERSION)
            .expect("API binding");
        let secret = SecretReference::new("secret-ref-meta", connector_scope.clone(), 1)
            .expect("secret reference");
        let now = Utc::now();
        let adapter = ProviderAdapterIdentity::new(META_ADAPTER_ID, META_ADAPTER_VERSION)
            .expect("adapter identity");
        let lease = ConnectorAuth::issue_credential_lease(
            &secret,
            adapter,
            "meta-lease",
            1,
            now - Duration::seconds(1),
            now + Duration::seconds(300),
        )
        .expect("credential lease");
        let mut resolver = InMemoryMetaCredentialResolver::default();
        resolver
            .insert(&secret, "meta-token-never-in-debug")
            .expect("credential");
        (
            connector_scope,
            meta_scope,
            api,
            secret,
            lease,
            resolver,
            now,
        )
    }

    fn probe_responses() -> Vec<MetaHttpResponse> {
        [
            r#"{"id":"user-1","name":"operator"}"#,
            r#"{"id":"123","name":"Business"}"#,
            r#"{"id":"act_123","account_id":"123","name":"Account","account_status":1,"currency":"USD"}"#,
            r#"{"id":"456","name":"Page","instagram_business_account":{"id":"789"}}"#,
            r#"{"id":"789","username":"brand","name":"Brand","account_type":"BUSINESS"}"#,
        ]
        .into_iter()
        .map(|body| MetaHttpResponse::json(200, body))
        .collect()
    }

    fn probe_request(
        connector_scope: ConnectorScope,
        meta_scope: MetaScope,
        api: MetaApiBinding,
        secret_reference: SecretReference,
        lease: CredentialLease,
        at: DateTime<Utc>,
    ) -> MetaProbeRequest {
        MetaProbeRequest::new(
            connector_scope,
            meta_scope,
            api,
            secret_reference,
            lease,
            at,
        )
        .expect("probe request")
    }

    #[allow(clippy::too_many_arguments)]
    fn read_request(
        connector_scope: ConnectorScope,
        meta_scope: MetaScope,
        api: MetaApiBinding,
        secret_reference: SecretReference,
        lease: CredentialLease,
        target: MetaReadTarget,
        query: MetaInsightQuery,
        cursor: Option<MetaPaginationCursor>,
        at: DateTime<Utc>,
    ) -> MetaInsightReadRequest {
        MetaInsightReadRequest::new(
            connector_scope,
            meta_scope,
            api,
            target,
            query,
            secret_reference,
            lease,
            cursor,
            at,
        )
        .expect("read request")
    }

    fn query(at: DateTime<Utc>, attribution: MetaAttributionModel) -> MetaInsightQuery {
        MetaInsightQuery::new(
            at - Duration::days(1),
            at,
            [
                "impressions".to_owned(),
                "reach".to_owned(),
                "actions".to_owned(),
            ],
            MetaGranularity::Daily,
            attribution,
        )
        .expect("insight query")
    }

    fn webhook_signature(app_secret: &str, body: &str) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, app_secret.as_bytes());
        let tag = hmac::sign(&key, body.as_bytes());
        let mut encoded = String::with_capacity(64);
        for byte in tag.as_ref() {
            write!(&mut encoded, "{byte:02x}").expect("hex buffer write");
        }
        format!("sha256={encoded}")
    }

    fn webhook_request(
        connector: &ConnectorScope,
        scope: &MetaScope,
        api: &MetaApiBinding,
        secret: SecretReference,
        lease: CredentialLease,
        at: DateTime<Utc>,
    ) -> MetaWebhookDeliveryRequest {
        let read = read_request(
            connector.clone(),
            scope.clone(),
            api.clone(),
            secret,
            lease,
            MetaReadTarget::PageInsights,
            query(
                at,
                MetaAttributionModel::PagePeriod {
                    period: "day".to_owned(),
                },
            ),
            None,
            at,
        );
        let subscription =
            MetaWebhookSubscription::new("meta-sub-page-1", connector, scope, api, "page", 1, None)
                .expect("webhook subscription");
        let body = r#"{"object":"page","entry":[{"id":"456","time":1723593600,"changes":[{"field":"feed","value":{"id":"post-1"}}]}]}"#;
        MetaWebhookDeliveryRequest::new(
            subscription,
            "meta-delivery-1",
            "meta-event-1",
            webhook_signature("meta-app-secret", body),
            body,
            read,
            at,
        )
        .expect("webhook request")
    }

    #[test]
    fn registrations_empty_and_writes_disabled() {
        assert!(META_REGISTRATIONS.is_empty());
        let transport = Arc::new(ScriptedMetaTransport::default());
        let api = MetaApiBinding::new(MetaGraphHost::Facebook, META_DEFAULT_API_VERSION)
            .expect("API binding");
        let provider = Arc::new(MetaGraphApiAdapter::new(transport, api));
        let service = MetaInsightReadService::new(provider);
        assert_eq!(
            service.connection_state(),
            MetaConnectionState::Disconnected
        );
        assert!(!service.grant().connected_claim);
        assert!(!service.grant().write_authority);
        assert_eq!(
            MetaCurlHttpsTransport.provenance_class(),
            ProviderProvenanceClass::ProductionProvider
        );
        assert_eq!(
            service.prepare_effect(),
            Err(MetaConnectorError::WritesDisabled)
        );
    }

    #[test]
    fn exact_scope_and_host_validation() {
        assert!(MetaScope::new("123", Some("act_nope".to_owned()), None, None).is_err());
        assert_eq!(
            MetaScope::new("123", Some("456".to_owned()), None, None)
                .expect("canonical ad account")
                .ad_account_id(),
            Some("act_456")
        );
        let (connector, scope, api, secret, lease, _, at) = fixture();
        let query = query(
            at,
            MetaAttributionModel::InstagramPeriod {
                period: "day".to_owned(),
                metric_type: None,
            },
        );
        let instagram_api =
            MetaApiBinding::new(MetaGraphHost::Instagram, "v25.0").expect("Instagram binding");
        let request = MetaInsightReadRequest::new(
            connector.clone(),
            scope.clone(),
            instagram_api,
            MetaReadTarget::PageInsights,
            query.clone(),
            secret.clone(),
            lease.clone(),
            None,
            at,
        );
        assert!(matches!(
            request,
            Err(MetaConnectorError::InvalidAttribution)
        ));
        let ig_request = read_request(
            connector,
            scope,
            api,
            secret,
            lease,
            MetaReadTarget::InstagramAccountInsights,
            query,
            None,
            at,
        );
        assert!(ig_request.request_digest().len() == 64);
    }

    #[test]
    fn probe_checks_exact_ids_and_stays_disconnected_claim() {
        let (connector, scope, api, secret, lease, resolver, at) = fixture();
        let transport = Arc::new(ScriptedMetaTransport::new(probe_responses()));
        let adapter = Arc::new(MetaGraphApiAdapter::new(transport.clone(), api.clone()));
        let mut service = MetaInsightReadService::new(adapter);
        let request = probe_request(connector, scope, api, secret, lease, at);
        let grant = service
            .probe_and_mount(&request, &resolver)
            .expect("probe and mount");
        assert_eq!(service.connection_state(), MetaConnectionState::Mounted);
        assert!(!grant.connected_claim);
        assert!(!grant.write_authority);
        assert_eq!(grant.connection_state, MetaConnectionState::Mounted);
        assert_eq!(service.grant().probe_digest.len(), 64);
        assert_eq!(
            service
                .mount
                .as_ref()
                .expect("mount")
                .probe
                .classification
                .provenance_class,
            ProviderProvenanceClass::ComponentHarness
        );
        assert!(
            !service
                .mount
                .as_ref()
                .expect("mount")
                .probe
                .classification
                .first_party
        );
        assert_eq!(service.durable_log().entries().len(), 0);
        let requests = transport.requests();
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[0].path, "/v25.0/me");
        assert_eq!(requests[2].path, "/v25.0/act_123");
        assert!(
            requests
                .iter()
                .all(|request| request.api.host == MetaGraphHost::Facebook)
        );
    }

    #[test]
    fn read_preserves_receipts_and_native_marketing_attribution() {
        let (connector, scope, api, secret, lease, resolver, at) = fixture();
        let mut responses = probe_responses();
        responses.push(
            MetaHttpResponse::json(
                200,
                r#"{"__request_id":"trace-1","data":[{"account_id":"123","impressions":"10","reach":"8","actions":[{"action_type":"link_click","value":"2"}],"date_start":"2026-08-13","date_stop":"2026-08-14"}],"paging":{"cursors":{"after":"after-1"}}}"#,
            )
            .with_header("x-app-usage", "{\"call_count\":1}"),
        );
        let transport = Arc::new(ScriptedMetaTransport::new(responses));
        let adapter = Arc::new(MetaGraphApiAdapter::new(transport, api.clone()));
        let mut service = MetaInsightReadService::new(adapter);
        let probe = probe_request(
            connector.clone(),
            scope.clone(),
            api.clone(),
            secret.clone(),
            lease.clone(),
            at,
        );
        service.probe_and_mount(&probe, &resolver).expect("mount");
        let request = read_request(
            connector,
            scope,
            api,
            secret,
            lease,
            MetaReadTarget::AdAccountInsights,
            query(
                at,
                MetaAttributionModel::AdsActionReportTime {
                    action_report_time: "conversion".to_owned(),
                },
            ),
            None,
            at,
        );
        let mut budget = MetaReadBudget::new(3, at + Duration::seconds(60), 3, 20).expect("budget");
        let result = service
            .read(&request, &resolver, &mut budget)
            .expect("read");
        assert_eq!(result.observation.source.provider_request_id, "trace-1");
        assert_eq!(result.observation.records.len(), 3);
        assert_eq!(
            result.observation.classification.attribution,
            MetaAttributionModel::AdsActionReportTime {
                action_report_time: "conversion".to_owned()
            }
        );
        assert_eq!(
            result.observation.causal_status,
            MetaCausalStatus::NotClaimed
        );
        assert!(result.observation.durable_logged);
        assert_eq!(result.observation.source.status, 200);
        assert_eq!(budget.quota_used(), 1);
        assert_eq!(budget.cost_used_minor(), 1);
        assert_eq!(result.observation.quota.limit, 3);
        assert_eq!(result.observation.quota.used, 1);
        assert_eq!(result.observation.cost.limit_minor, 20);
        assert_eq!(result.observation.cost.used_minor, 1);
        assert!(result.observation.cursor.is_some());
    }

    #[test]
    fn instagram_period_query_keeps_provider_model() {
        let (connector, scope, _, secret, lease, _, at) = fixture();
        let api = MetaApiBinding::new(MetaGraphHost::Instagram, "v25.0").expect("API");
        let transport = Arc::new(ScriptedMetaTransport::new([MetaHttpResponse::json(
            200,
            r#"{"data":[{"name":"reach","period":"day","values":[{"value":42,"end_time":"2026-08-14T00:00:00+0000"}]}]}"#,
        )]));
        let adapter = MetaGraphApiAdapter::new(transport.clone(), api.clone());
        let request = read_request(
            connector,
            scope,
            api,
            secret,
            lease,
            MetaReadTarget::InstagramAccountInsights,
            query(
                at,
                MetaAttributionModel::InstagramPeriod {
                    period: "day".to_owned(),
                    metric_type: Some("time_series".to_owned()),
                },
            ),
            None,
            at,
        );
        let token = MetaAccessToken::new("token").expect("token");
        let page = adapter.read(&request, &token).expect("Instagram read");
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].metric, "reach");
        assert_eq!(
            page.records[0].attribution,
            MetaAttributionModel::InstagramPeriod {
                period: "day".to_owned(),
                metric_type: Some("time_series".to_owned())
            }
        );
        let request_log = transport.requests();
        assert_eq!(request_log[0].api.host, MetaGraphHost::Instagram);
        assert!(
            request_log[0]
                .query
                .iter()
                .any(|(key, value)| key == "metric_type" && value == "time_series")
        );
    }

    #[test]
    fn durable_pagination_restores_exact_cursor_without_duplicate_pages() {
        let (connector, scope, api, secret, lease, resolver, at) = fixture();
        let mut responses = probe_responses();
        responses.extend([
            MetaHttpResponse::json(
                200,
                r#"{"data":[{"impressions":"10"}],"paging":{"cursors":{"after":"after-1"}}}"#,
            ),
            MetaHttpResponse::json(200, r#"{"data":[{"impressions":"11"}]}"#),
        ]);
        let transport = Arc::new(ScriptedMetaTransport::new(responses));
        let adapter = Arc::new(MetaGraphApiAdapter::new(transport.clone(), api.clone()));
        let mut service = MetaInsightReadService::new(adapter.clone());
        let probe_request = probe_request(
            connector.clone(),
            scope.clone(),
            api.clone(),
            secret.clone(),
            lease.clone(),
            at,
        );
        let token = resolver.resolve(&secret).expect("token");
        let probe = adapter.probe(&probe_request, &token).expect("probe");
        let mount = MetaMount::new(&probe_request, probe.clone()).expect("mount");
        service.mount(mount).expect("mount service");
        let first = read_request(
            connector.clone(),
            scope.clone(),
            api.clone(),
            secret.clone(),
            lease.clone(),
            MetaReadTarget::AdAccountInsights,
            query(
                at,
                MetaAttributionModel::AdsActionReportTime {
                    action_report_time: "impression".to_owned(),
                },
            ),
            None,
            at,
        );
        let mut budget = MetaReadBudget::new(5, at + Duration::seconds(60), 5, 20).expect("budget");
        let first_result = service
            .read(&first, &resolver, &mut budget)
            .expect("first page");
        let cursor = first_result.observation.cursor.as_ref().expect("cursor");
        assert_eq!(cursor.sequence, 1);
        let checkpoint = service.checkpoint();
        let checkpoint_json = serde_json::to_string(&checkpoint).expect("durable JSON");
        assert!(checkpoint_json.contains("after-1"));
        assert!(
            !serde_json::to_string(&first_result)
                .expect("model result JSON")
                .contains("after-1")
        );
        let checkpoint: MetaDurableState =
            serde_json::from_str(&checkpoint_json).expect("durable checkpoint");
        let mut restarted = MetaInsightReadService::new(adapter);
        restarted
            .restore_checkpoint(checkpoint)
            .expect("restore checkpoint");
        restarted
            .mount(MetaMount::new(&probe_request, probe).expect("mount after restart"))
            .expect("mount restarted");
        let second = read_request(
            connector.clone(),
            scope.clone(),
            api.clone(),
            secret.clone(),
            lease.clone(),
            MetaReadTarget::AdAccountInsights,
            query(
                at,
                MetaAttributionModel::AdsActionReportTime {
                    action_report_time: "impression".to_owned(),
                },
            ),
            Some(restarted.current_cursor().expect("restored cursor").clone()),
            at,
        );
        let second_result = restarted
            .read(&second, &resolver, &mut budget)
            .expect("second page");
        assert_eq!(second_result.observation.page_sequence, 2);
        assert_eq!(restarted.durable_log().entries().len(), 2);
        assert!(restarted.current_cursor().is_none());
        let requests = transport.requests();
        assert_eq!(requests[5].path, "/v25.0/act_123/insights");
        assert!(
            requests[6]
                .query
                .iter()
                .any(|(key, value)| key == "after" && value == "after-1")
        );
    }

    #[test]
    fn typed_provider_failures_and_lifecycle_cleanup_are_fail_closed() {
        let (connector, scope, api, secret, lease, resolver, at) = fixture();
        for (status, expected) in [
            (401, MetaConnectorError::Unauthorized),
            (403, MetaConnectorError::PermissionDenied),
            (
                429,
                MetaConnectorError::RateLimited {
                    reset_at: None,
                    retry_after_seconds: Some(30),
                },
            ),
        ] {
            let response = MetaHttpResponse::json(status, r#"{"error":{"code":190}}"#)
                .with_header("retry-after", "30");
            let transport = Arc::new(ScriptedMetaTransport::new([response]));
            let adapter = MetaGraphApiAdapter::new(transport, api.clone());
            let request = read_request(
                connector.clone(),
                scope.clone(),
                api.clone(),
                secret.clone(),
                lease.clone(),
                MetaReadTarget::AdAccountInsights,
                query(
                    at,
                    MetaAttributionModel::AdsActionReportTime {
                        action_report_time: "impression".to_owned(),
                    },
                ),
                None,
                at,
            );
            let error = adapter
                .read(&request, &MetaAccessToken::new("token").expect("token"))
                .expect_err("typed provider error");
            assert_eq!(error, expected);
        }
        let transport = Arc::new(ScriptedMetaTransport::new(probe_responses()));
        let adapter = Arc::new(MetaGraphApiAdapter::new(transport, api.clone()));
        let mut service = MetaInsightReadService::new(adapter);
        let request = probe_request(connector, scope, api, secret, lease, at);
        service.probe_and_mount(&request, &resolver).expect("mount");
        service.revoke();
        assert_eq!(service.connection_state(), MetaConnectionState::Revoked);
        assert!(service.current_cursor().is_none());
        assert!(!service.grant().connected_claim);
        service.unmount();
        assert_eq!(
            service.connection_state(),
            MetaConnectionState::Disconnected
        );
    }

    #[test]
    fn secret_and_cursor_debug_are_redacted_and_env_probe_is_blocked_without_flag() {
        let (connector, scope, api, secret, lease, _, at) = fixture();
        let token = MetaAccessToken::new("super-secret-token").expect("token");
        assert!(!format!("{token:?}").contains("super-secret-token"));
        let cursor = MetaPaginationCursor::new(
            &connector,
            sha256("request"),
            "provider-cursor-secret",
            1,
            sha256("page"),
        )
        .expect("cursor");
        assert!(!format!("{cursor:?}").contains("provider-cursor-secret"));
        let request_debug = format!(
            "{:?}",
            MetaHttpRequest {
                api: api.clone(),
                path: "/v25.0/123/insights".to_owned(),
                query: vec![("after".to_owned(), "provider-cursor-secret".to_owned())],
            }
        );
        assert!(!request_debug.contains("provider-cursor-secret"));
        let request = probe_request(connector, scope, api, secret, lease, at);
        if std::env::var(META_RUN_PROBE_ENV).ok().as_deref() != Some("1") {
            assert!(matches!(
                run_env_gated_probe(&request),
                Err(MetaConnectorError::BlockedEnv)
            ));
        }
    }

    #[test]
    fn webhook_signature_is_verified_and_reconciles_one_adoptable_result() {
        let (connector, scope, api, secret, lease, resolver, at) = fixture();
        let mut responses = probe_responses();
        responses.push(MetaHttpResponse::json(
            200,
            r#"{"__request_id":"webhook-read-1","data":[{"name":"page_impressions","period":"day","values":[{"value":7,"end_time":"2026-08-14T00:00:00+0000"}]}]}"#,
        ));
        let transport = Arc::new(ScriptedMetaTransport::new(responses));
        let adapter = Arc::new(MetaGraphApiAdapter::new(transport, api.clone()));
        let mut insight = PaidSocialInsightReadService::new(adapter);
        let probe = probe_request(
            connector.clone(),
            scope.clone(),
            api.clone(),
            secret.clone(),
            lease.clone(),
            at,
        );
        insight.probe_and_mount(&probe, &resolver).expect("mount");
        let mut service = MetaWebhookReconcileService::new(insight);
        let request = webhook_request(&connector, &scope, &api, secret.clone(), lease, at);
        let mut app_secrets = InMemoryMetaWebhookSecretResolver::default();
        app_secrets
            .insert(&secret, "meta-app-secret")
            .expect("app secret");
        let mut budget = MetaReadBudget::new(3, at + Duration::seconds(60), 3, 20).expect("budget");
        let result = service
            .deliver_and_reconcile(&request, &app_secrets, &resolver, &mut budget)
            .expect("webhook reconciliation");
        assert_eq!(result.delivery.source.method, "POST");
        assert_eq!(result.observation.records.len(), 1);
        assert_eq!(budget.quota_used(), 1);
        assert_eq!(budget.cost_used_minor(), 1);
        assert!(is_sha256(&result.delivery.request_digest));
        assert!(is_sha256(&result.delivery.response_digest));
        assert_eq!(
            result.observation.causal_status,
            MetaCausalStatus::NotClaimed
        );
        assert!(!result.connected_claim);
        assert!(!result.write_authority);
        assert_eq!(service.webhook_state().pending.len(), 0);
        assert_eq!(service.webhook_state().completed.len(), 1);
        assert_eq!(service.service().durable_log().entries().len(), 1);
        let result_json = serde_json::to_string(&result).expect("result JSON");
        assert!(!result_json.contains("meta-app-secret"));
        assert!(!result_json.contains("feed"));

        let replay = service
            .deliver_and_reconcile(&request, &app_secrets, &resolver, &mut budget)
            .expect("idempotent webhook replay");
        assert_eq!(replay.result_id, result.result_id);
        assert_eq!(service.webhook_state().completed.len(), 1);
        assert_eq!(service.service().durable_log().entries().len(), 1);
    }

    #[test]
    fn webhook_checkpoint_resumes_pending_delivery_after_restart() {
        let (connector, scope, api, secret, lease, resolver, at) = fixture();
        let transport = Arc::new(ScriptedMetaTransport::new(probe_responses()));
        let adapter = Arc::new(MetaGraphApiAdapter::new(transport, api.clone()));
        let mut insight = PaidSocialInsightReadService::new(adapter);
        let probe_request = probe_request(
            connector.clone(),
            scope.clone(),
            api.clone(),
            secret.clone(),
            lease.clone(),
            at,
        );
        let probe = {
            let token = resolver.resolve(&secret).expect("token");
            insight
                .provider
                .probe(&probe_request, &token)
                .expect("probe")
        };
        insight
            .mount(MetaMount::new(&probe_request, probe.clone()).expect("mount"))
            .expect("mount service");
        let mut service = MetaWebhookReconcileService::new(insight);
        let request = webhook_request(&connector, &scope, &api, secret.clone(), lease.clone(), at);
        let mut app_secrets = InMemoryMetaWebhookSecretResolver::default();
        app_secrets
            .insert(&secret, "meta-app-secret")
            .expect("app secret");
        service
            .accept_webhook(&request, &app_secrets)
            .expect("durable pending delivery");
        let checkpoint = service.checkpoint();
        let checkpoint_json = serde_json::to_string(&checkpoint).expect("checkpoint JSON");
        assert!(!checkpoint_json.contains("meta-app-secret"));
        assert!(!checkpoint_json.contains("feed"));

        let read_response = MetaHttpResponse::json(
            200,
            r#"{"__request_id":"webhook-read-restart","data":[{"name":"page_impressions","period":"day","values":[{"value":8,"end_time":"2026-08-14T00:00:00+0000"}]}]}"#,
        );
        let restarted_adapter = Arc::new(MetaGraphApiAdapter::new(
            Arc::new(ScriptedMetaTransport::new([read_response])),
            api.clone(),
        ));
        let mut restarted =
            MetaWebhookReconcileService::new(PaidSocialInsightReadService::new(restarted_adapter));
        restarted
            .restore_checkpoint(checkpoint)
            .expect("restore webhook checkpoint");
        restarted
            .service_mut()
            .mount(MetaMount::new(&probe_request, probe).expect("restart mount"))
            .expect("mount after restart");
        let mut budget = MetaReadBudget::new(2, at + Duration::seconds(60), 2, 20).expect("budget");
        let result = restarted
            .reconcile_webhook(
                &request.delivery_id,
                &request.reconcile_request,
                &resolver,
                &mut budget,
            )
            .expect("reconcile pending delivery");
        assert_eq!(result.delivery.delivery_id, "meta-delivery-1");
        assert_eq!(restarted.pending_delivery_ids(), Vec::<String>::new());
        assert_eq!(restarted.webhook_state().completed.len(), 1);
        assert_eq!(restarted.service().durable_log().entries().len(), 1);
    }

    #[test]
    fn webhook_invalid_signature_drift_and_cleanup_fail_closed() {
        let (connector, scope, api, secret, lease, resolver, at) = fixture();
        let transport = Arc::new(ScriptedMetaTransport::new(probe_responses()));
        let adapter = Arc::new(MetaGraphApiAdapter::new(transport, api.clone()));
        let mut insight = PaidSocialInsightReadService::new(adapter);
        let probe = probe_request(
            connector.clone(),
            scope.clone(),
            api.clone(),
            secret.clone(),
            lease.clone(),
            at,
        );
        insight.probe_and_mount(&probe, &resolver).expect("mount");
        let mut service = MetaWebhookReconcileService::new(insight);
        let request = webhook_request(&connector, &scope, &api, secret.clone(), lease, at);
        let mut app_secrets = InMemoryMetaWebhookSecretResolver::default();
        app_secrets
            .insert(&secret, "wrong-secret")
            .expect("wrong app secret");
        assert_eq!(
            service.accept_webhook(&request, &app_secrets),
            Err(MetaConnectorError::InvalidWebhookSignature)
        );
        assert!(service.pending_delivery_ids().is_empty());

        let mut correct_secrets = InMemoryMetaWebhookSecretResolver::default();
        correct_secrets
            .insert(&secret, "meta-app-secret")
            .expect("app secret");
        service
            .accept_webhook(&request, &correct_secrets)
            .expect("pending delivery");
        let mut pending = request.clone();
        pending.reconcile_request = MetaInsightReadRequest::new(
            pending.reconcile_request.connector_scope.clone(),
            pending.reconcile_request.meta_scope.clone(),
            pending.reconcile_request.api.clone(),
            MetaReadTarget::PageInsights,
            query(
                at,
                MetaAttributionModel::PagePeriod {
                    period: "week".to_owned(),
                },
            ),
            pending.reconcile_request.secret_reference.clone(),
            pending.reconcile_request.lease.clone(),
            None,
            at,
        )
        .expect("drifted read request");
        assert_eq!(
            service.accept_webhook(&pending, &correct_secrets),
            Err(MetaConnectorError::InvalidWebhookDelivery)
        );

        service.unmount();
        assert!(service.pending_delivery_ids().is_empty());
        assert_eq!(
            service.service().connection_state(),
            MetaConnectionState::Disconnected
        );
        service.revoke();
        assert!(service.pending_delivery_ids().is_empty());
        assert!(!service.service().grant().connected_claim);
    }

    #[test]
    fn env_gated_webhook_reconcile_requires_native_configuration() {
        let (connector, scope, api, secret, lease, _resolver, at) = fixture();
        let service = PaidSocialInsightReadService::new(Arc::new(MetaGraphApiAdapter::new(
            Arc::new(ScriptedMetaTransport::default()),
            api.clone(),
        )));
        let mut service = MetaWebhookReconcileService::new(service);
        let request = webhook_request(&connector, &scope, &api, secret, lease, at);
        let mut budget = MetaReadBudget::new(1, at + Duration::seconds(60), 1, 1).expect("budget");
        if std::env::var(META_RUN_WEBHOOK_RECONCILE_ENV)
            .ok()
            .as_deref()
            != Some("1")
        {
            assert_eq!(
                run_env_gated_webhook_reconcile(&mut service, &request, &mut budget),
                Err(MetaConnectorError::BlockedEnv)
            );
        }
        assert!(META_WEBHOOK_REGISTRATIONS.is_empty());
    }
}
