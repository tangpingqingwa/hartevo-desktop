//! Meta, X Ads, and LinkedIn paid-social read adapters.
//!
//! The adapters preserve provider-specific permission, review, rate-limit, and
//! attribution metadata while emitting only normalized observations. They do not
//! expose write operations.

use crate::http::{HttpRequest, HttpResponse, HttpTransport, oauth1_authorization, query_digest};
use crate::paid_social_types::{
    AttributionSelection, CausalStatus, ConnectorError, CredentialResolver, CursorKind,
    Granularity, InsightLevel, InsightsQuery, ObservationRecord, OpaqueCursor,
    PaginationObservation, PaidSocialReadAdapter, PermissionObservation, PreparedEffect,
    ProviderAttribution, ProviderValue, READ_OBSERVATION_SCHEMA, RateLimitKind,
    RateLimitObservation, ReadCommand, ReadObservation, ReadRequest, ReadSurface, RequestEvidence,
    ResolvedCredential, ResourceKind, ReviewState, digest_bytes, digest_json,
};
use chrono::{DateTime, Datelike, Utc};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use url::Url;

const META_DEFAULT_GRAPH_BASE: &str = "https://graph.facebook.com";
const META_DEFAULT_API_VERSION: &str = "v25.0";
const X_DEFAULT_ADS_BASE: &str = "https://ads-api.x.com";
const X_DEFAULT_API_VERSION: &str = "12";
const LINKEDIN_DEFAULT_API_BASE: &str = "https://api.linkedin.com";
const LINKEDIN_DEFAULT_MARKETING_VERSION: &str = "202603";

type MetaRequestPlan = (
    HttpRequest,
    BTreeSet<String>,
    ReviewState,
    Option<ProviderAttribution>,
);
type RequestPlan = (
    HttpRequest,
    BTreeSet<String>,
    ReviewState,
    Option<ProviderAttribution>,
    bool,
);

struct ObservationParts {
    records: Vec<ObservationRecord>,
    pagination: PaginationObservation,
    permissions: PermissionObservation,
    rate_limit: RateLimitObservation,
    review_state: ReviewState,
    provider_attribution_models: Vec<ProviderAttribution>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaidSocialProvider {
    Meta,
    X,
    LinkedIn,
}

impl PaidSocialProvider {
    pub const fn provider_id(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::X => "x",
            Self::LinkedIn => "linkedin",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstagramLoginMode {
    FacebookLogin,
    InstagramLogin,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MetaConfig {
    pub graph_base_url: String,
    pub instagram_graph_base_url: String,
    pub api_version: String,
    pub instagram_login_mode: InstagramLoginMode,
}

impl Default for MetaConfig {
    fn default() -> Self {
        Self {
            graph_base_url: META_DEFAULT_GRAPH_BASE.to_owned(),
            instagram_graph_base_url: "https://graph.instagram.com".to_owned(),
            api_version: META_DEFAULT_API_VERSION.to_owned(),
            instagram_login_mode: InstagramLoginMode::FacebookLogin,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct XAdsConfig {
    pub ads_base_url: String,
    pub api_version: String,
}

impl Default for XAdsConfig {
    fn default() -> Self {
        Self {
            ads_base_url: X_DEFAULT_ADS_BASE.to_owned(),
            api_version: X_DEFAULT_API_VERSION.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LinkedInConfig {
    pub api_base_url: String,
    pub marketing_version: String,
}

impl Default for LinkedInConfig {
    fn default() -> Self {
        Self {
            api_base_url: LINKEDIN_DEFAULT_API_BASE.to_owned(),
            marketing_version: LINKEDIN_DEFAULT_MARKETING_VERSION.to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MetaAdapter {
    pub config: MetaConfig,
    pub transport: Arc<dyn HttpTransport>,
}

impl MetaAdapter {
    pub fn new(
        config: MetaConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, ConnectorError> {
        validate_base_url(&config.graph_base_url)?;
        validate_base_url(&config.instagram_graph_base_url)?;
        validate_version(&config.api_version)?;
        Ok(Self { config, transport })
    }

    fn read_request(
        &self,
        request: &ReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<ReadObservation, ConnectorError> {
        request.validate()?;
        if request.scope.provider_id() != PaidSocialProvider::Meta.provider_id() {
            return Err(ConnectorError::ScopeMismatch);
        }
        let (http_request, required_scopes, review_state, attribution) = match request.surface {
            ReadSurface::MetaMarketing => self.build_marketing_request(request)?,
            ReadSurface::MetaInstagram => self.build_instagram_request(request)?,
            _ => return Err(ConnectorError::ScopeMismatch),
        };
        let permissions =
            PermissionObservation::from_scope(required_scopes, &request.scope, review_state);
        if !permissions.missing_scopes.is_empty() {
            return Err(ConnectorError::MissingPermission);
        }
        let credential = resolver.resolve(&request.secret_reference)?;
        let mut http_request = http_request;
        apply_bearer(&mut http_request, &credential)?;
        let (value, response, rate_limit) = execute_json(
            self.transport.as_ref(),
            &http_request,
            PaidSocialProvider::Meta,
        )?;
        let command_kind = request.command.kind().to_owned();
        let is_insights = matches!(request.command, ReadCommand::Insights { .. });
        let records = parse_records(&value, &command_kind, attribution.as_ref(), is_insights);
        let pagination = parse_meta_pagination(&value, request.surface, is_insights)?;
        let observation = make_observation(
            request,
            &http_request,
            &response,
            ObservationParts {
                records,
                pagination,
                permissions,
                rate_limit,
                review_state,
                provider_attribution_models: attribution.into_iter().collect(),
            },
        )?;
        observation.validate()?;
        Ok(observation)
    }

    fn build_marketing_request(
        &self,
        request: &ReadRequest,
    ) -> Result<MetaRequestPlan, ConnectorError> {
        let account = meta_account_id(request.scope.account_id())?;
        let (path, query, attribution) = match &request.command {
            ReadCommand::Resource(kind) => {
                let resource = match kind {
                    ResourceKind::Account => account.clone(),
                    ResourceKind::Campaigns => format!("{account}/campaigns"),
                    ResourceKind::AdGroups => format!("{account}/adsets"),
                    ResourceKind::Ads => format!("{account}/ads"),
                    ResourceKind::Creatives => format!("{account}/adcreatives"),
                    ResourceKind::Media => return Err(ConnectorError::UnsupportedOperation),
                };
                (resource, meta_resource_query(*kind), None)
            }
            ReadCommand::Insights { query, cursor } => {
                let attribution = Some(meta_attribution(query));
                (
                    format!("{account}/insights"),
                    meta_insights_query(query, cursor.as_ref()),
                    attribution,
                )
            }
        };
        let url = self.url(&path);
        let required = BTreeSet::from(["ads_read".to_owned()]);
        Ok((
            HttpRequest::get(url).with_query(query),
            required,
            ReviewState::Required,
            attribution,
        ))
    }

    fn build_instagram_request(
        &self,
        request: &ReadRequest,
    ) -> Result<
        (
            HttpRequest,
            BTreeSet<String>,
            ReviewState,
            Option<ProviderAttribution>,
        ),
        ConnectorError,
    > {
        let account = path_segment(request.scope.account_id())?;
        let (path, query, attribution) = match &request.command {
            ReadCommand::Resource(kind) => {
                let path = match kind {
                    ResourceKind::Account => account.clone(),
                    ResourceKind::Media => format!("{account}/media"),
                    ResourceKind::Campaigns
                    | ResourceKind::AdGroups
                    | ResourceKind::Ads
                    | ResourceKind::Creatives => return Err(ConnectorError::UnsupportedOperation),
                };
                (path, instagram_resource_query(*kind), None)
            }
            ReadCommand::Insights { query, .. } => (
                format!("{account}/insights"),
                instagram_insights_query(query)?,
                Some(instagram_attribution(query)),
            ),
        };
        let url = self.instagram_url(&path);
        let required = match self.config.instagram_login_mode {
            InstagramLoginMode::FacebookLogin => BTreeSet::from([
                "instagram_basic".to_owned(),
                "instagram_manage_insights".to_owned(),
                "pages_read_engagement".to_owned(),
            ]),
            InstagramLoginMode::InstagramLogin => BTreeSet::from([
                "instagram_business_basic".to_owned(),
                "instagram_business_manage_insights".to_owned(),
            ]),
        };
        Ok((
            HttpRequest::get(url).with_query(query),
            required,
            ReviewState::Required,
            attribution,
        ))
    }

    fn url(&self, path: &str) -> String {
        let base = self.config.graph_base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/{}/{path}", self.config.api_version)
    }

    fn instagram_url(&self, path: &str) -> String {
        let base = match self.config.instagram_login_mode {
            InstagramLoginMode::FacebookLogin => &self.config.graph_base_url,
            InstagramLoginMode::InstagramLogin => &self.config.instagram_graph_base_url,
        }
        .trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/{}/{path}", self.config.api_version)
    }
}

impl PaidSocialReadAdapter for MetaAdapter {
    fn provider(&self) -> PaidSocialProvider {
        PaidSocialProvider::Meta
    }

    fn read(
        &self,
        request: ReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<ReadObservation, ConnectorError> {
        self.read_request(&request, resolver)
    }

    fn prepare_effect(&self, operation: &str) -> Result<PreparedEffect, ConnectorError> {
        let _ = operation;
        Err(ConnectorError::WritesDisabled {
            provider: PaidSocialProvider::Meta,
        })
    }
}

#[derive(Clone, Debug)]
pub struct XAdsAdapter {
    pub config: XAdsConfig,
    pub transport: Arc<dyn HttpTransport>,
}

impl XAdsAdapter {
    pub fn new(
        config: XAdsConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, ConnectorError> {
        validate_base_url(&config.ads_base_url)?;
        validate_version(&config.api_version)?;
        Ok(Self { config, transport })
    }

    fn read_request(
        &self,
        request: &ReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<ReadObservation, ConnectorError> {
        request.validate()?;
        if request.scope.provider_id() != PaidSocialProvider::X.provider_id()
            || request.surface != ReadSurface::XAds
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        let (mut http_request, required_scopes, review_state, attribution, analytics) =
            self.build_request(request)?;
        let permissions =
            PermissionObservation::from_scope(required_scopes, &request.scope, review_state);
        if !permissions.missing_scopes.is_empty() {
            return Err(ConnectorError::MissingPermission);
        }
        let credential = resolver.resolve(&request.secret_reference)?;
        apply_oauth1(&mut http_request, &credential)?;
        let (value, response, rate_limit) = execute_json(
            self.transport.as_ref(),
            &http_request,
            PaidSocialProvider::X,
        )?;
        let command_kind = request.command.kind().to_owned();
        let records = parse_records(&value, &command_kind, attribution.as_ref(), analytics);
        let pagination = parse_x_pagination(&value, analytics)?;
        let observation = make_observation(
            request,
            &http_request,
            &response,
            ObservationParts {
                records,
                pagination,
                permissions,
                rate_limit,
                review_state,
                provider_attribution_models: attribution.into_iter().collect(),
            },
        )?;
        observation.validate()?;
        Ok(observation)
    }

    fn build_request(&self, request: &ReadRequest) -> Result<RequestPlan, ConnectorError> {
        let account = path_segment(request.scope.account_id())?;
        let (path, query, attribution, analytics) = match &request.command {
            ReadCommand::Resource(kind) => {
                let path = match kind {
                    ResourceKind::Account => format!("accounts/{account}"),
                    ResourceKind::Campaigns => format!("accounts/{account}/campaigns"),
                    ResourceKind::AdGroups => format!("accounts/{account}/line_items"),
                    ResourceKind::Ads => format!("accounts/{account}/promoted_tweets"),
                    ResourceKind::Creatives | ResourceKind::Media => {
                        return Err(ConnectorError::UnsupportedOperation);
                    }
                };
                (path, x_resource_query(*kind), None, false)
            }
            ReadCommand::Insights { query, cursor } => (
                format!("stats/accounts/{account}"),
                x_insights_query(query, cursor.as_ref())?,
                Some(x_attribution(query)),
                true,
            ),
        };
        let url = self.url(&path);
        let required = if analytics {
            BTreeSet::from([
                "x_ads_api.standard_access".to_owned(),
                "x_ads_api.analytics_read".to_owned(),
            ])
        } else {
            BTreeSet::from(["x_ads_api.standard_access".to_owned()])
        };
        Ok((
            HttpRequest::get(url).with_query(query),
            required,
            ReviewState::Required,
            attribution,
            analytics,
        ))
    }

    fn url(&self, path: &str) -> String {
        let base = self.config.ads_base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/{}/{path}", self.config.api_version)
    }
}

impl PaidSocialReadAdapter for XAdsAdapter {
    fn provider(&self) -> PaidSocialProvider {
        PaidSocialProvider::X
    }

    fn read(
        &self,
        request: ReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<ReadObservation, ConnectorError> {
        self.read_request(&request, resolver)
    }

    fn prepare_effect(&self, operation: &str) -> Result<PreparedEffect, ConnectorError> {
        let _ = operation;
        Err(ConnectorError::WritesDisabled {
            provider: PaidSocialProvider::X,
        })
    }
}

#[derive(Clone, Debug)]
pub struct LinkedInAdapter {
    pub config: LinkedInConfig,
    pub transport: Arc<dyn HttpTransport>,
}

impl LinkedInAdapter {
    pub fn new(
        config: LinkedInConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, ConnectorError> {
        validate_base_url(&config.api_base_url)?;
        validate_version(&config.marketing_version)?;
        Ok(Self { config, transport })
    }

    fn read_request(
        &self,
        request: &ReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<ReadObservation, ConnectorError> {
        request.validate()?;
        if request.scope.provider_id() != PaidSocialProvider::LinkedIn.provider_id()
            || request.surface != ReadSurface::LinkedInAds
        {
            return Err(ConnectorError::ScopeMismatch);
        }
        let (mut http_request, required_scopes, review_state, attribution, analytics) =
            self.build_request(request)?;
        let permissions =
            PermissionObservation::from_scope(required_scopes, &request.scope, review_state);
        if !permissions.missing_scopes.is_empty() {
            return Err(ConnectorError::MissingPermission);
        }
        let credential = resolver.resolve(&request.secret_reference)?;
        apply_bearer(&mut http_request, &credential)?;
        http_request.set_header("Linkedin-Version", &self.config.marketing_version);
        http_request.set_header("X-Restli-Protocol-Version", "2.0.0");
        let (value, response, rate_limit) = execute_json(
            self.transport.as_ref(),
            &http_request,
            PaidSocialProvider::LinkedIn,
        )?;
        let command_kind = request.command.kind().to_owned();
        let records = parse_records(&value, &command_kind, attribution.as_ref(), analytics);
        let pagination = parse_linkedin_pagination(&value, analytics)?;
        let observation = make_observation(
            request,
            &http_request,
            &response,
            ObservationParts {
                records,
                pagination,
                permissions,
                rate_limit,
                review_state,
                provider_attribution_models: attribution.into_iter().collect(),
            },
        )?;
        observation.validate()?;
        Ok(observation)
    }

    fn build_request(&self, request: &ReadRequest) -> Result<RequestPlan, ConnectorError> {
        let account = path_segment(request.scope.account_id())?;
        let account_urn = format!("urn:li:sponsoredAccount:{account}");
        let (path, query, attribution, analytics) = match &request.command {
            ReadCommand::Resource(kind) => {
                let (path, query) = match kind {
                    ResourceKind::Account => (format!("adAccounts/{account}"), Vec::new()),
                    ResourceKind::Campaigns => (
                        "adCampaigns".to_owned(),
                        linkedin_search_query(&account_urn),
                    ),
                    ResourceKind::AdGroups => (
                        "adCampaignGroups".to_owned(),
                        linkedin_search_query(&account_urn),
                    ),
                    ResourceKind::Ads | ResourceKind::Creatives => (
                        "adCreatives".to_owned(),
                        linkedin_search_query(&account_urn),
                    ),
                    ResourceKind::Media => return Err(ConnectorError::UnsupportedOperation),
                };
                (path, query, None, false)
            }
            ReadCommand::Insights { query, .. } => (
                "adAnalytics".to_owned(),
                linkedin_insights_query(query, &account_urn)?,
                Some(linkedin_attribution(query)),
                true,
            ),
        };
        let url = self.url(&path);
        let required = if analytics {
            BTreeSet::from(["r_ads".to_owned(), "r_ads_reporting".to_owned()])
        } else {
            BTreeSet::from(["r_ads".to_owned()])
        };
        Ok((
            HttpRequest::get(url).with_query(query),
            required,
            ReviewState::Required,
            attribution,
            analytics,
        ))
    }

    fn url(&self, path: &str) -> String {
        let base = self.config.api_base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{base}/rest/{path}")
    }
}

impl PaidSocialReadAdapter for LinkedInAdapter {
    fn provider(&self) -> PaidSocialProvider {
        PaidSocialProvider::LinkedIn
    }

    fn read(
        &self,
        request: ReadRequest,
        resolver: &dyn CredentialResolver,
    ) -> Result<ReadObservation, ConnectorError> {
        self.read_request(&request, resolver)
    }

    fn prepare_effect(&self, operation: &str) -> Result<PreparedEffect, ConnectorError> {
        let _ = operation;
        Err(ConnectorError::WritesDisabled {
            provider: PaidSocialProvider::LinkedIn,
        })
    }
}

fn validate_base_url(value: &str) -> Result<(), ConnectorError> {
    let url = Url::parse(value).map_err(|_| ConnectorError::InvalidRequest)?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(ConnectorError::InvalidRequest);
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), ConnectorError> {
    if value.is_empty()
        || value.len() > 32
        || value
            .chars()
            .any(|character| !character.is_ascii_alphanumeric() && character != '.')
    {
        return Err(ConnectorError::InvalidRequest);
    }
    Ok(())
}

fn path_segment(value: &str) -> Result<String, ConnectorError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|character| !character.is_ascii_alphanumeric() && !matches!(character, '_' | '-'))
    {
        return Err(ConnectorError::InvalidRequest);
    }
    Ok(value.to_owned())
}

fn meta_account_id(value: &str) -> Result<String, ConnectorError> {
    let value = value.strip_prefix("act_").unwrap_or(value);
    Ok(format!("act_{}", path_segment(value)?))
}

fn apply_bearer(
    request: &mut HttpRequest,
    credential: &ResolvedCredential,
) -> Result<(), ConnectorError> {
    match credential {
        ResolvedCredential::Bearer(token) => {
            request.set_header("Authorization", format!("Bearer {}", token.expose()));
            Ok(())
        }
        ResolvedCredential::OAuth1(_) => Err(ConnectorError::CredentialTypeMismatch),
    }
}

fn apply_oauth1(
    request: &mut HttpRequest,
    credential: &ResolvedCredential,
) -> Result<(), ConnectorError> {
    match credential {
        ResolvedCredential::OAuth1(credentials) => {
            let authorization = oauth1_authorization(request, credentials, Utc::now())?;
            request.set_header("Authorization", authorization);
            Ok(())
        }
        ResolvedCredential::Bearer(_) => Err(ConnectorError::CredentialTypeMismatch),
    }
}

fn meta_resource_query(kind: ResourceKind) -> Vec<(String, String)> {
    let fields = match kind {
        ResourceKind::Account => "id,name,account_status,currency,timezone_name",
        ResourceKind::Campaigns => "id,name,status,effective_status,objective,updated_time",
        ResourceKind::AdGroups => "id,name,campaign_id,status,effective_status,updated_time",
        ResourceKind::Ads => {
            "id,name,adset_id,campaign_id,status,effective_status,creative{id,name}"
        }
        ResourceKind::Creatives => "id,name,status,object_story_spec",
        ResourceKind::Media => "id",
    };
    vec![("fields".to_owned(), fields.to_owned())]
}

fn meta_insights_query(
    query: &InsightsQuery,
    cursor: Option<&OpaqueCursor>,
) -> Vec<(String, String)> {
    let mut values = vec![
        (
            "fields".to_owned(),
            query.fields.iter().cloned().collect::<Vec<_>>().join(","),
        ),
        ("level".to_owned(), meta_level(query.level).to_owned()),
        (
            "time_range".to_owned(),
            serde_json::json!({
                "since": query.since.format("%Y-%m-%d").to_string(),
                "until": query.until.format("%Y-%m-%d").to_string()
            })
            .to_string(),
        ),
    ];
    if matches!(query.granularity, Granularity::Daily) {
        values.push(("time_increment".to_owned(), "1".to_owned()));
    }
    match &query.attribution {
        AttributionSelection::Explicit(windows) => values.push((
            "action_attribution_windows".to_owned(),
            windows.iter().cloned().collect::<Vec<_>>().join(","),
        )),
        AttributionSelection::ProviderConfigured => values.push((
            "use_account_attribution_setting".to_owned(),
            "true".to_owned(),
        )),
        AttributionSelection::NotApplicable => {}
    }
    if let Some(cursor) = cursor {
        values.push(("after".to_owned(), cursor.value().to_owned()));
    }
    values.extend(
        query
            .parameters
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    values
}

fn instagram_resource_query(kind: ResourceKind) -> Vec<(String, String)> {
    let fields = match kind {
        ResourceKind::Account => "id,username,name,account_type,followers_count,media_count",
        ResourceKind::Media => "id,caption,media_type,timestamp,permalink",
        _ => "id",
    };
    vec![("fields".to_owned(), fields.to_owned())]
}

fn instagram_insights_query(
    query: &InsightsQuery,
) -> Result<Vec<(String, String)>, ConnectorError> {
    if !matches!(query.granularity, Granularity::Daily | Granularity::Total) {
        return Err(ConnectorError::UnsupportedOperation);
    }
    let fields = query.fields.iter().cloned().collect::<Vec<_>>().join(",");
    let mut values = vec![
        ("metric".to_owned(), fields),
        ("period".to_owned(), "day".to_owned()),
        ("since".to_owned(), query.since.timestamp().to_string()),
        ("until".to_owned(), query.until.timestamp().to_string()),
    ];
    values.extend(
        query
            .parameters
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    Ok(values)
}

fn x_resource_query(kind: ResourceKind) -> Vec<(String, String)> {
    if matches!(kind, ResourceKind::Account) {
        Vec::new()
    } else {
        vec![
            ("count".to_owned(), "200".to_owned()),
            ("with_deleted".to_owned(), "false".to_owned()),
        ]
    }
}

fn x_insights_query(
    query: &InsightsQuery,
    cursor: Option<&OpaqueCursor>,
) -> Result<Vec<(String, String)>, ConnectorError> {
    if matches!(query.granularity, Granularity::Total) {
        return Err(ConnectorError::UnsupportedOperation);
    }
    let entity = match query.level {
        InsightLevel::Account => "ACCOUNT",
        InsightLevel::Campaign => "CAMPAIGN",
        InsightLevel::AdGroup => "LINE_ITEM",
        InsightLevel::Ad | InsightLevel::Creative | InsightLevel::Media => "PROMOTED_TWEET",
    };
    let mut values = vec![
        ("entity".to_owned(), entity.to_owned()),
        (
            "start_time".to_owned(),
            query
                .since
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
        (
            "end_time".to_owned(),
            query
                .until
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
        (
            "granularity".to_owned(),
            match query.granularity {
                Granularity::Daily => "DAY",
                Granularity::Hourly => "HOUR",
                Granularity::Total => "TOTAL",
            }
            .to_owned(),
        ),
        ("metric_groups".to_owned(), "ENGAGEMENT,BILLING".to_owned()),
        ("placement".to_owned(), "ALL_ON_TWITTER".to_owned()),
        (
            "entity_ids".to_owned(),
            query
                .parameters
                .get("entity_ids")
                .cloned()
                .unwrap_or_default(),
        ),
    ];
    if let Some(cursor) = cursor {
        values.push(("cursor".to_owned(), cursor.value().to_owned()));
    }
    values.extend(
        query
            .parameters
            .iter()
            .filter(|(name, _)| name.as_str() != "entity_ids")
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    Ok(values)
}

fn linkedin_search_query(account_urn: &str) -> Vec<(String, String)> {
    vec![
        ("q".to_owned(), "search".to_owned()),
        (
            "search.account.values[0]".to_owned(),
            account_urn.to_owned(),
        ),
        ("count".to_owned(), "100".to_owned()),
    ]
}

fn linkedin_insights_query(
    query: &InsightsQuery,
    account_urn: &str,
) -> Result<Vec<(String, String)>, ConnectorError> {
    if matches!(query.granularity, Granularity::Hourly) {
        return Err(ConnectorError::UnsupportedOperation);
    }
    let pivot = match query.level {
        InsightLevel::Account => "ACCOUNT",
        InsightLevel::Campaign => "CAMPAIGN",
        InsightLevel::AdGroup => "CAMPAIGN_GROUP",
        InsightLevel::Ad | InsightLevel::Creative => "CREATIVE",
        InsightLevel::Media => return Err(ConnectorError::UnsupportedOperation),
    };
    let date_range = format!(
        "(start:(year:{},month:{},day:{}),end:(year:{},month:{},day:{}))",
        query.since.year(),
        query.since.month(),
        query.since.day(),
        query.until.year(),
        query.until.month(),
        query.until.day()
    );
    let mut values = vec![
        ("q".to_owned(), "analytics".to_owned()),
        ("pivot".to_owned(), pivot.to_owned()),
        (
            "timeGranularity".to_owned(),
            match query.granularity {
                Granularity::Daily => "DAILY",
                Granularity::Total => "ALL",
                Granularity::Hourly => "HOURLY",
            }
            .to_owned(),
        ),
        ("dateRange".to_owned(), date_range),
        ("accounts".to_owned(), format!("List({account_urn})")),
        (
            "fields".to_owned(),
            query.fields.iter().cloned().collect::<Vec<_>>().join(","),
        ),
    ];
    values.extend(
        query
            .parameters
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    Ok(values)
}

fn meta_level(level: InsightLevel) -> &'static str {
    match level {
        InsightLevel::Account => "account",
        InsightLevel::Campaign => "campaign",
        InsightLevel::AdGroup => "adset",
        InsightLevel::Ad | InsightLevel::Creative | InsightLevel::Media => "ad",
    }
}

fn meta_attribution(query: &InsightsQuery) -> ProviderAttribution {
    let mut parameters = query.parameters.clone();
    let windows = match &query.attribution {
        AttributionSelection::Explicit(windows) => windows.iter().cloned().collect(),
        AttributionSelection::ProviderConfigured => {
            parameters.insert(
                "use_account_attribution_setting".to_owned(),
                "true".to_owned(),
            );
            Vec::new()
        }
        AttributionSelection::NotApplicable => Vec::new(),
    };
    ProviderAttribution {
        model: "meta_ads_insights".to_owned(),
        windows,
        parameters,
        causal_status: CausalStatus::NotClaimed,
    }
}

fn instagram_attribution(query: &InsightsQuery) -> ProviderAttribution {
    ProviderAttribution {
        model: "instagram_period_metric".to_owned(),
        windows: Vec::new(),
        parameters: query.parameters.clone(),
        causal_status: CausalStatus::NotClaimed,
    }
}

fn x_attribution(query: &InsightsQuery) -> ProviderAttribution {
    let mut parameters = query.parameters.clone();
    parameters.insert("metric_groups".to_owned(), "ENGAGEMENT,BILLING".to_owned());
    parameters.insert("placement".to_owned(), "ALL_ON_TWITTER".to_owned());
    ProviderAttribution {
        model: "x_ads_analytics".to_owned(),
        windows: Vec::new(),
        parameters,
        causal_status: CausalStatus::NotClaimed,
    }
}

fn linkedin_attribution(query: &InsightsQuery) -> ProviderAttribution {
    let mut parameters = query.parameters.clone();
    parameters.insert("finder".to_owned(), "adAnalytics".to_owned());
    parameters.insert(
        "time_granularity".to_owned(),
        format!("{:?}", query.granularity),
    );
    ProviderAttribution {
        model: "linkedin_ad_analytics".to_owned(),
        windows: Vec::new(),
        parameters,
        causal_status: CausalStatus::NotClaimed,
    }
}

fn execute_json(
    transport: &dyn HttpTransport,
    request: &HttpRequest,
    provider: PaidSocialProvider,
) -> Result<(Value, HttpResponse, RateLimitObservation), ConnectorError> {
    let response = transport.send(request).map_err(ConnectorError::Transport)?;
    let rate_limit = parse_rate_limit(&response, provider);
    if response.status == 401 {
        return Err(ConnectorError::Unauthorized {
            status: response.status,
        });
    }
    if response.status == 403 {
        return Err(ConnectorError::PermissionDenied {
            status: response.status,
        });
    }
    if response.status == 429 {
        return Err(ConnectorError::RateLimited {
            status: response.status,
            rate_limit,
        });
    }
    if response.status >= 500 {
        return Err(ConnectorError::ProviderUnavailable {
            status: response.status,
        });
    }
    if !(200..300).contains(&response.status) {
        return Err(ConnectorError::InvalidProviderResponse {
            status: response.status,
        });
    }
    let value =
        serde_json::from_slice(&response.body).map_err(|_| ConnectorError::ResponseParse {
            status: response.status,
        })?;
    Ok((value, response, rate_limit))
}

fn parse_records(
    value: &Value,
    command_kind: &str,
    attribution: Option<&ProviderAttribution>,
    is_insights: bool,
) -> Vec<ObservationRecord> {
    let values = value
        .get("data")
        .or_else(|| value.get("results"))
        .or_else(|| value.get("elements"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| {
            if value.is_object() {
                vec![value.clone()]
            } else {
                Vec::new()
            }
        });
    values
        .iter()
        .filter_map(|value| value.as_object())
        .map(|object| record_from_object(object, command_kind, attribution.cloned(), is_insights))
        .collect()
}

fn record_from_object(
    object: &Map<String, Value>,
    command_kind: &str,
    attribution: Option<ProviderAttribution>,
    is_insights: bool,
) -> ObservationRecord {
    let external_id = first_string(object, &["id", "account_id", "pivotValue", "pivotValues"]);
    let parent_external_id = first_string(object, &["campaign_id", "adset_id", "line_item_id"]);
    let name = first_string(object, &["name", "campaign_name", "adset_name", "ad_name"]);
    let status = first_string(object, &["status", "effective_status", "state"]);
    let mut provider_fields = BTreeMap::new();
    let mut metrics = BTreeMap::new();
    for (key, value) in object {
        let converted = provider_value(value);
        if is_insights || command_kind == "insights" {
            metrics.insert(key.clone(), converted);
        } else {
            provider_fields.insert(key.clone(), converted);
        }
    }
    let period = first_string(object, &["date", "start_time", "end_time"]);
    ObservationRecord {
        kind: command_kind.to_owned(),
        external_id,
        parent_external_id,
        name,
        status,
        provider_fields,
        metrics,
        period,
        attribution,
    }
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(value_to_string))
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(values) => {
            let values = values
                .iter()
                .filter_map(value_to_string)
                .collect::<Vec<_>>();
            (!values.is_empty()).then(|| values.join("|"))
        }
        _ => None,
    }
}

fn provider_value(value: &Value) -> ProviderValue {
    match value {
        Value::Null => ProviderValue::Null,
        Value::Bool(value) => ProviderValue::Boolean(*value),
        Value::String(value) => ProviderValue::String(value.clone()),
        Value::Number(value) => value.as_i64().map_or_else(
            || ProviderValue::Decimal(value.to_string()),
            ProviderValue::Integer,
        ),
        Value::Array(_) | Value::Object(_) => ProviderValue::Digest(digest_json(value)),
    }
}

fn parse_meta_pagination(
    value: &Value,
    surface: ReadSurface,
    insights: bool,
) -> Result<PaginationObservation, ConnectorError> {
    let paging = value.get("paging");
    let after = paging
        .and_then(|paging| paging.get("cursors"))
        .and_then(|cursors| cursors.get("after"))
        .and_then(Value::as_str)
        .map(|after| OpaqueCursor::new(after, CursorKind::MetaGraphAfter))
        .transpose()?;
    let has_next = paging.and_then(|paging| paging.get("next")).is_some();
    Ok(PaginationObservation {
        next: after,
        provider_supports_cursor: !matches!(surface, ReadSurface::MetaInstagram) || !insights,
        complete: !has_next,
    })
}

fn parse_x_pagination(
    value: &Value,
    analytics: bool,
) -> Result<PaginationObservation, ConnectorError> {
    let next = if analytics {
        None
    } else {
        value
            .get("next_cursor")
            .or_else(|| value.get("next_cursor_str"))
            .and_then(Value::as_str)
            .map(|cursor| OpaqueCursor::new(cursor, CursorKind::XEntity))
            .transpose()?
    };
    Ok(PaginationObservation {
        next,
        provider_supports_cursor: !analytics,
        complete: analytics || value.get("next_cursor").is_none(),
    })
}

fn parse_linkedin_pagination(
    value: &Value,
    analytics: bool,
) -> Result<PaginationObservation, ConnectorError> {
    let next = if analytics {
        None
    } else {
        value
            .get("paging")
            .and_then(|paging| paging.get("start"))
            .and_then(Value::as_i64)
            .and_then(|start| {
                value
                    .get("paging")
                    .and_then(|paging| paging.get("count"))
                    .and_then(Value::as_i64)
                    .map(|count| start + count)
            })
            .map(|start| OpaqueCursor::new(start.to_string(), CursorKind::LinkedInAccount))
            .transpose()?
    };
    Ok(PaginationObservation {
        next,
        provider_supports_cursor: !analytics,
        complete: analytics || value.get("paging").is_none(),
    })
}

fn parse_rate_limit(response: &HttpResponse, provider: PaidSocialProvider) -> RateLimitObservation {
    let mut observation = RateLimitObservation {
        kind: if provider == PaidSocialProvider::LinkedIn {
            RateLimitKind::LinkedInAssignedQuota
        } else {
            RateLimitKind::Unknown
        },
        ..RateLimitObservation::default()
    };
    let headers = &response.headers;
    if let Some(value) = headers.get("x-business-use-case-usage") {
        observation.kind = RateLimitKind::MetaBusinessUseCase;
        observation
            .evidence_headers
            .insert("x-business-use-case-usage".to_owned());
        parse_usage_header(value, &mut observation.usage);
    }
    if let Some(value) = headers.get("x-ad-account-usage") {
        observation.kind = RateLimitKind::MetaAdAccount;
        observation
            .evidence_headers
            .insert("x-ad-account-usage".to_owned());
        parse_usage_header(value, &mut observation.usage);
    }
    if let Some(value) = headers.get("x-app-usage") {
        if observation.kind == RateLimitKind::Unknown {
            observation.kind = RateLimitKind::MetaBusinessUseCase;
        }
        observation
            .evidence_headers
            .insert("x-app-usage".to_owned());
        parse_usage_header(value, &mut observation.usage);
    }
    let account_limit = parse_u64(headers.get("x-account-rate-limit-limit"));
    let account_remaining = parse_u64(headers.get("x-account-rate-limit-remaining"));
    let account_reset = parse_timestamp(headers.get("x-account-rate-limit-reset"));
    if account_limit.is_some() || account_remaining.is_some() || account_reset.is_some() {
        observation.kind = RateLimitKind::XAccount;
        observation.limit = account_limit;
        observation.remaining = account_remaining;
        observation.reset_at = account_reset;
        observation.evidence_headers.extend([
            "x-account-rate-limit-limit".to_owned(),
            "x-account-rate-limit-remaining".to_owned(),
            "x-account-rate-limit-reset".to_owned(),
        ]);
    } else {
        let user_limit = parse_u64(headers.get("x-rate-limit-limit"));
        let user_remaining = parse_u64(headers.get("x-rate-limit-remaining"));
        let user_reset = parse_timestamp(headers.get("x-rate-limit-reset"));
        if user_limit.is_some() || user_remaining.is_some() || user_reset.is_some() {
            observation.kind = RateLimitKind::XUser;
            observation.limit = user_limit;
            observation.remaining = user_remaining;
            observation.reset_at = user_reset;
            observation.evidence_headers.extend([
                "x-rate-limit-limit".to_owned(),
                "x-rate-limit-remaining".to_owned(),
                "x-rate-limit-reset".to_owned(),
            ]);
        }
    }
    if let Some(value) = headers.get("x-ratelimit-limit") {
        observation.kind = RateLimitKind::LinkedInAssignedQuota;
        observation.limit = value.parse().ok();
        observation
            .evidence_headers
            .insert("x-ratelimit-limit".to_owned());
    }
    if let Some(value) = headers.get("x-ratelimit-remaining") {
        observation.kind = RateLimitKind::LinkedInAssignedQuota;
        observation.remaining = value.parse().ok();
        observation
            .evidence_headers
            .insert("x-ratelimit-remaining".to_owned());
    }
    if let Some(value) = headers.get("x-ratelimit-reset") {
        observation.kind = RateLimitKind::LinkedInAssignedQuota;
        observation.reset_at = parse_timestamp(Some(value));
        observation
            .evidence_headers
            .insert("x-ratelimit-reset".to_owned());
    }
    observation.retry_after_seconds = parse_u64(headers.get("retry-after"));
    if headers.contains_key("retry-after") {
        observation
            .evidence_headers
            .insert("retry-after".to_owned());
    }
    observation
}

fn parse_usage_header(value: &str, usage: &mut BTreeMap<String, ProviderValue>) {
    if let Ok(parsed) = serde_json::from_str::<Value>(value)
        && let Some(object) = parsed.as_object()
    {
        for (key, value) in object {
            usage.insert(key.clone(), provider_value(value));
        }
    }
}

fn parse_u64(value: Option<&String>) -> Option<u64> {
    value.and_then(|value| value.parse().ok())
}

fn parse_timestamp(value: Option<&String>) -> Option<DateTime<Utc>> {
    value
        .and_then(|value| value.parse::<i64>().ok())
        .and_then(|value| DateTime::from_timestamp(value, 0))
}

fn make_observation(
    request: &ReadRequest,
    http_request: &HttpRequest,
    response: &HttpResponse,
    parts: ObservationParts,
) -> Result<ReadObservation, ConnectorError> {
    let path = http_request.path()?;
    let query_digest = query_digest(&http_request.query);
    let response_digest = digest_bytes(&response.body);
    let observation_id = format!(
        "obs-{}",
        digest_bytes(
            format!(
                "{}:{}:{}:{}",
                request.scope.digest(),
                path,
                query_digest,
                response_digest
            )
            .as_bytes(),
        )
    );
    Ok(ReadObservation {
        schema_version: READ_OBSERVATION_SCHEMA.to_owned(),
        observation_id,
        scope: request.scope.clone(),
        connection_id: request.connection_id.clone(),
        surface: request.surface,
        command_kind: request.command.kind().to_owned(),
        request_evidence: RequestEvidence {
            method: http_request.method.as_str().to_owned(),
            path,
            query_digest,
            status: response.status,
            provider_request_id: provider_request_id(response),
            response_digest,
        },
        records: parts.records,
        pagination: parts.pagination,
        permissions: parts.permissions,
        rate_limit: parts.rate_limit,
        review_state: parts.review_state,
        provider_attribution_models: parts.provider_attribution_models,
        provenance: request.provenance,
        observed_at: response.received_at,
        causal_status: CausalStatus::NotClaimed,
    })
}

fn provider_request_id(response: &HttpResponse) -> Option<String> {
    ["x-fb-trace-id", "x-request-id", "x-linkedin-request-id"]
        .iter()
        .find_map(|header| response.headers.get(*header).cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpTransport, HttpTransportError};
    use crate::paid_social_types::{
        ConnectorScope, InMemoryCredentialResolver, OAuth1Credentials, ProvenanceClass,
        SecretReference, SecretString,
    };
    use crate::{ConnectorAuth, ProviderAdapterIdentity};
    use chrono::Duration;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct StubTransport {
        requests: Mutex<Vec<HttpRequest>>,
        response: HttpResponse,
    }

    impl StubTransport {
        fn json(body: &str, headers: &[(&str, &str)]) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                response: HttpResponse {
                    status: 200,
                    headers: headers
                        .iter()
                        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                        .collect(),
                    body: body.as_bytes().to_vec(),
                    received_at: Utc::now(),
                },
            }
        }
    }

    impl HttpTransport for StubTransport {
        fn send(&self, request: &HttpRequest) -> Result<HttpResponse, HttpTransportError> {
            self.requests
                .lock()
                .expect("requests")
                .push(request.clone());
            Ok(self.response.clone())
        }
    }

    fn request(
        provider: PaidSocialProvider,
        surface: ReadSurface,
        command: ReadCommand,
        scope_names: &[&str],
    ) -> (ReadRequest, InMemoryCredentialResolver) {
        let granted_scopes = if scope_names.is_empty() {
            vec!["placeholder.scope".to_owned()]
        } else {
            scope_names
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        };
        let scope = ConnectorScope::new(
            "tenant-1",
            "project-1",
            provider.provider_id(),
            "account-1",
            granted_scopes,
        )
        .expect("scope");
        let now = Utc::now();
        let reference = SecretReference::new("secret-ref-1", scope.clone(), 1).expect("reference");
        let adapter =
            ProviderAdapterIdentity::new(format!("paid-social.{}", provider.provider_id()), 1)
                .expect("adapter identity");
        let lease = ConnectorAuth::issue_credential_lease(
            &reference,
            adapter,
            "lease-1",
            1,
            now - Duration::seconds(1),
            now + Duration::seconds(60),
        )
        .expect("lease");
        (
            ReadRequest {
                scope,
                connection_id: "connection-1".to_owned(),
                secret_reference: reference.clone(),
                lease,
                surface,
                command,
                provenance: ProvenanceClass::ComponentHarness,
                requested_at: now,
            },
            {
                let mut resolver = InMemoryCredentialResolver::default();
                resolver.insert_bearer(&reference, "test-token");
                resolver
            },
        )
    }

    fn insights() -> ReadCommand {
        ReadCommand::Insights {
            query: InsightsQuery {
                since: Utc::now() - Duration::days(1),
                until: Utc::now(),
                level: InsightLevel::Campaign,
                granularity: Granularity::Daily,
                fields: BTreeSet::from(["impressions".to_owned(), "clicks".to_owned()]),
                attribution: AttributionSelection::Explicit(BTreeSet::from(
                    ["7d_click".to_owned()],
                )),
                parameters: BTreeMap::new(),
            },
            cursor: None,
        }
    }

    #[test]
    fn meta_uses_bearer_scope_and_preserves_attribution_window() {
        let transport = Arc::new(StubTransport::json(
            r#"{"data":[{"campaign_id":"c1","impressions":3,"actions":[{"action_type":"purchase","value":1}]}],"paging":{"cursors":{"after":"next"}}}"#,
            &[
                ("x-fb-trace-id", "trace-1"),
                ("x-ad-account-usage", r#"{"act_1":{"call_count":2}}"#),
            ],
        ));
        let adapter = MetaAdapter::new(
            MetaConfig {
                graph_base_url: "https://graph.example.test".to_owned(),
                api_version: "v1".to_owned(),
                ..MetaConfig::default()
            },
            transport.clone(),
        )
        .expect("adapter");
        let (request, resolver) = request(
            PaidSocialProvider::Meta,
            ReadSurface::MetaMarketing,
            insights(),
            &["ads_read"],
        );
        let observation = adapter.read(request, &resolver).expect("observation");
        assert_eq!(observation.records.len(), 1);
        assert_eq!(observation.rate_limit.kind, RateLimitKind::MetaAdAccount);
        assert_eq!(
            observation.provider_attribution_models[0].windows,
            vec!["7d_click"]
        );
        assert_eq!(observation.causal_status, CausalStatus::NotClaimed);
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].headers.get("Authorization"),
            Some(&"Bearer test-token".to_owned())
        );
        assert!(requests[0].url.ends_with("/v1/act_account-1/insights"));
    }

    #[test]
    fn meta_instagram_uses_login_specific_scopes_and_credentialed_read_path() {
        let transport = Arc::new(StubTransport::json(
            r#"{"data":[{"id":"media-1","media_type":"IMAGE","timestamp":"2026-08-13T00:00:00+0000"}]}"#,
            &[("x-fb-trace-id", "instagram-trace")],
        ));
        let adapter = MetaAdapter::new(
            MetaConfig {
                graph_base_url: "https://graph.instagram.example.test".to_owned(),
                instagram_graph_base_url: "https://graph.instagram.example.test".to_owned(),
                api_version: "v1".to_owned(),
                instagram_login_mode: InstagramLoginMode::InstagramLogin,
            },
            transport.clone(),
        )
        .expect("adapter");
        let (request, resolver) = request(
            PaidSocialProvider::Meta,
            ReadSurface::MetaInstagram,
            ReadCommand::Resource(ResourceKind::Media),
            &[
                "instagram_business_basic",
                "instagram_business_manage_insights",
            ],
        );
        let observation = adapter.read(request, &resolver).expect("observation");
        assert_eq!(
            observation.records[0].external_id.as_deref(),
            Some("media-1")
        );
        assert_eq!(observation.permissions.review_state, ReviewState::Required);
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(
            requests[0].headers.get("Authorization"),
            Some(&"Bearer test-token".to_owned())
        );
        assert!(requests[0].url.ends_with("/v1/account-1/media"));
    }

    #[test]
    fn missing_permission_is_rejected_before_provider_transport() {
        let transport = Arc::new(StubTransport::json(
            r#"{"data":[{"id":"must-not-be-read"}]}"#,
            &[],
        ));
        let adapter = MetaAdapter::new(
            MetaConfig {
                graph_base_url: "https://graph.example.test".to_owned(),
                api_version: "v1".to_owned(),
                ..MetaConfig::default()
            },
            transport.clone(),
        )
        .expect("adapter");
        let (request, resolver) = request(
            PaidSocialProvider::Meta,
            ReadSurface::MetaMarketing,
            ReadCommand::Resource(ResourceKind::Account),
            &[],
        );
        assert!(matches!(
            adapter.read(request, &resolver),
            Err(ConnectorError::MissingPermission)
        ));
        assert!(transport.requests.lock().expect("requests").is_empty());
    }

    #[test]
    fn rate_limit_error_preserves_provider_header_evidence() {
        let mut stub = StubTransport::json(
            r#"{"error":{"message":"rate limited"}}"#,
            &[
                ("x-ad-account-usage", r#"{"act_1":{"call_count":100}}"#),
                ("retry-after", "30"),
            ],
        );
        stub.response.status = 429;
        let transport = Arc::new(stub);
        let adapter = MetaAdapter::new(
            MetaConfig {
                graph_base_url: "https://graph.example.test".to_owned(),
                api_version: "v1".to_owned(),
                ..MetaConfig::default()
            },
            transport,
        )
        .expect("adapter");
        let (request, resolver) = request(
            PaidSocialProvider::Meta,
            ReadSurface::MetaMarketing,
            ReadCommand::Resource(ResourceKind::Account),
            &["ads_read"],
        );
        let error = adapter.read(request, &resolver).expect_err("429");
        match error {
            ConnectorError::RateLimited { rate_limit, .. } => {
                assert_eq!(rate_limit.kind, RateLimitKind::MetaAdAccount);
                assert_eq!(rate_limit.retry_after_seconds, Some(30));
                assert!(rate_limit.evidence_headers.contains("retry-after"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn x_requires_oauth1_and_prefers_account_rate_headers() {
        let transport = Arc::new(StubTransport::json(
            r#"{"data":[{"id":"campaign-1","name":"Campaign"}],"next_cursor":"next"}"#,
            &[
                ("x-account-rate-limit-limit", "100"),
                ("x-account-rate-limit-remaining", "99"),
                ("x-account-rate-limit-reset", "1700000000"),
                ("x-rate-limit-limit", "5"),
            ],
        ));
        let adapter = XAdsAdapter::new(
            XAdsConfig {
                ads_base_url: "https://ads.example.test".to_owned(),
                api_version: "12".to_owned(),
            },
            transport.clone(),
        )
        .expect("adapter");
        let (request, _) = request(
            PaidSocialProvider::X,
            ReadSurface::XAds,
            ReadCommand::Resource(ResourceKind::Campaigns),
            &["x_ads_api.standard_access"],
        );
        let reference = request.secret_reference.clone();
        let mut resolver = InMemoryCredentialResolver::default();
        resolver.insert_oauth1(
            &reference,
            OAuth1Credentials {
                consumer_key: SecretString::new("consumer"),
                consumer_secret: SecretString::new("consumer-secret"),
                access_token: SecretString::new("access"),
                access_token_secret: SecretString::new("access-secret"),
            },
        );
        let observation = adapter.read(request, &resolver).expect("observation");
        assert_eq!(observation.rate_limit.kind, RateLimitKind::XAccount);
        assert_eq!(observation.rate_limit.limit, Some(100));
        assert_eq!(
            observation.pagination.next.expect("next").kind,
            CursorKind::XEntity
        );
        let requests = transport.requests.lock().expect("requests");
        assert!(
            requests[0]
                .headers
                .get("Authorization")
                .is_some_and(|header| header.starts_with("OAuth "))
        );
    }

    #[test]
    fn linkedin_reporting_preserves_no_pagination_contract() {
        let transport = Arc::new(StubTransport::json(
            r#"{"elements":[{"pivotValues":["urn:li:sponsoredCampaign:1"],"impressions":12}]}"#,
            &[],
        ));
        let adapter = LinkedInAdapter::new(
            LinkedInConfig {
                api_base_url: "https://linkedin.example.test".to_owned(),
                marketing_version: "202603".to_owned(),
            },
            transport.clone(),
        )
        .expect("adapter");
        let (request, resolver) = request(
            PaidSocialProvider::LinkedIn,
            ReadSurface::LinkedInAds,
            insights(),
            &["r_ads", "r_ads_reporting"],
        );
        let observation = adapter.read(request, &resolver).expect("observation");
        assert!(!observation.pagination.provider_supports_cursor);
        assert!(observation.pagination.complete);
        assert_eq!(
            observation.rate_limit.kind,
            RateLimitKind::LinkedInAssignedQuota
        );
        let requests = transport.requests.lock().expect("requests");
        assert_eq!(
            requests[0].headers.get("Linkedin-Version"),
            Some(&"202603".to_owned())
        );
        assert_eq!(
            requests[0].headers.get("X-Restli-Protocol-Version"),
            Some(&"2.0.0".to_owned())
        );
    }

    #[test]
    fn every_provider_write_gate_is_closed() {
        let meta = MetaAdapter::new(
            MetaConfig::default(),
            Arc::new(StubTransport::json("{}", &[])),
        )
        .expect("meta");
        let x = XAdsAdapter::new(
            XAdsConfig::default(),
            Arc::new(StubTransport::json("{}", &[])),
        )
        .expect("x");
        let linkedin = LinkedInAdapter::new(
            LinkedInConfig::default(),
            Arc::new(StubTransport::json("{}", &[])),
        )
        .expect("linkedin");
        assert!(matches!(
            meta.prepare_effect("campaign.create"),
            Err(ConnectorError::WritesDisabled { .. })
        ));
        assert!(matches!(
            x.prepare_effect("campaign.create"),
            Err(ConnectorError::WritesDisabled { .. })
        ));
        assert!(matches!(
            linkedin.prepare_effect("campaign.create"),
            Err(ConnectorError::WritesDisabled { .. })
        ));
    }
}
