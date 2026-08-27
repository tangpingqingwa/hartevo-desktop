//! TikTok Display API contracts and authenticated read plugin seams.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::transport::{ScopeName, sha256_json};

mod consumer;
mod provider;
mod service;

pub mod testkit;

pub use consumer::{MissionTiktokReadConsumer, TiktokMissionAcceptedRead};
pub use provider::TiktokDisplayApiProvider;
pub use service::{TiktokAuthenticatedReadService, TiktokRealReadGate, execute_real_read_gate};

pub use crate::transport::SecretReference;

pub const DISPLAY_API_BASE_URL: &str = "https://open.tiktokapis.com/v2";
pub const USER_INFO_PATH: &str = "/user/info/";
pub const VIDEO_LIST_PATH: &str = "/video/list/";
pub const VIDEO_QUERY_PATH: &str = "/video/query/";
pub const REAL_READ_ENABLE_ENV: &str = "HARTEVO_TIKTOK_REAL_READ";
pub const REAL_READ_SECRET_REFERENCE_ENV: &str = "HARTEVO_TIKTOK_SECRET_REFERENCE";
pub const DEFAULT_VIDEO_PAGE_SIZE: u8 = 20;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    Tiktok,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokOAuthScope {
    UserInfoBasic,
    VideoList,
}

impl TiktokOAuthScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserInfoBasic => "user.info.basic",
            Self::VideoList => "video.list",
        }
    }

    pub fn name(self) -> Result<ScopeName, TiktokError> {
        ScopeName::new(self.as_str())
            .map_err(|_| TiktokError::InvalidRequest("invalid TikTok scope"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokApiOperation {
    UserInfo,
    VideoList,
    VideoQuery,
}

impl TiktokApiOperation {
    pub const fn required_scope(self) -> TiktokOAuthScope {
        match self {
            Self::UserInfo => TiktokOAuthScope::UserInfoBasic,
            Self::VideoList | Self::VideoQuery => TiktokOAuthScope::VideoList,
        }
    }

    pub const fn path(self) -> &'static str {
        match self {
            Self::UserInfo => USER_INFO_PATH,
            Self::VideoList => VIDEO_LIST_PATH,
            Self::VideoQuery => VIDEO_QUERY_PATH,
        }
    }

    pub const fn cost(self) -> TiktokRequestCost {
        TiktokRequestCost {
            request_units: 1,
            monetary_micros: None,
        }
    }
}

macro_rules! opaque_id {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, TiktokError> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > 256
                    || value.chars().any(|character| {
                        !character.is_ascii()
                            || character.is_ascii_control()
                            || character.is_whitespace()
                    })
                {
                    return Err(TiktokError::InvalidRequest(
                        "invalid TikTok scope identifier",
                    ));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

opaque_id!(TenantId);
opaque_id!(BusinessId);
opaque_id!(TiktokAccountId);

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TiktokVideoId(String);

impl TiktokVideoId {
    pub fn new(value: impl Into<String>) -> Result<Self, TiktokError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 20
            || !value.chars().all(|character| character.is_ascii_digit())
        {
            return Err(TiktokError::InvalidRequest(
                "TikTok video IDs must be int64 strings",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TiktokVideoId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TiktokCursor(i64);

impl TiktokCursor {
    pub fn new(value: i64) -> Result<Self, TiktokError> {
        if value <= 0 {
            return Err(TiktokError::InvalidResponse {
                field: "data.cursor".to_owned(),
            });
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokReadScope {
    tenant: TenantId,
    business: BusinessId,
    account: TiktokAccountId,
}

impl TiktokReadScope {
    pub fn new(tenant: TenantId, business: BusinessId, account: TiktokAccountId) -> Self {
        Self {
            tenant,
            business,
            account,
        }
    }

    pub const fn provider(&self) -> ProviderId {
        ProviderId::Tiktok
    }

    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub const fn business(&self) -> &BusinessId {
        &self.business
    }

    pub const fn account(&self) -> &TiktokAccountId {
        &self.account
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokAccountIdentity {
    open_id: TiktokAccountId,
    display_name: Option<String>,
    username: Option<String>,
}

impl TiktokAccountIdentity {
    pub fn new(
        open_id: TiktokAccountId,
        display_name: Option<String>,
        username: Option<String>,
    ) -> Result<Self, TiktokError> {
        for value in [display_name.as_deref(), username.as_deref()]
            .into_iter()
            .flatten()
        {
            if value.chars().any(char::is_control) {
                return Err(TiktokError::InvalidResponse {
                    field: "data.user.profile".to_owned(),
                });
            }
        }
        Ok(Self {
            open_id,
            display_name,
            username,
        })
    }

    pub const fn open_id(&self) -> &TiktokAccountId {
        &self.open_id
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokVideoIdentity {
    account: TiktokAccountId,
    video_id: TiktokVideoId,
}

impl TiktokVideoIdentity {
    pub const fn new(account: TiktokAccountId, video_id: TiktokVideoId) -> Self {
        Self { account, video_id }
    }

    pub const fn account(&self) -> &TiktokAccountId {
        &self.account
    }

    pub const fn video_id(&self) -> &TiktokVideoId {
        &self.video_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokRevisionIdentity {
    Account {
        account: TiktokAccountId,
        digest: String,
        observed_at: DateTime<Utc>,
    },
    Video {
        account: TiktokAccountId,
        video_id: TiktokVideoId,
        digest: String,
        observed_at: DateTime<Utc>,
    },
}

impl TiktokRevisionIdentity {
    fn account(account: TiktokAccountId, digest: String, observed_at: DateTime<Utc>) -> Self {
        Self::Account {
            account,
            digest,
            observed_at,
        }
    }

    fn video(
        account: TiktokAccountId,
        video_id: TiktokVideoId,
        digest: String,
        observed_at: DateTime<Utc>,
    ) -> Self {
        Self::Video {
            account,
            video_id,
            digest,
            observed_at,
        }
    }

    pub const fn account_id(&self) -> &TiktokAccountId {
        match self {
            Self::Account { account, .. } | Self::Video { account, .. } => account,
        }
    }

    pub fn digest(&self) -> &str {
        match self {
            Self::Account { digest, .. } | Self::Video { digest, .. } => digest,
        }
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        match self {
            Self::Account { observed_at, .. } | Self::Video { observed_at, .. } => *observed_at,
        }
    }

    pub const fn provider(&self) -> ProviderId {
        ProviderId::Tiktok
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct OAuthCredential {
    secret_reference: SecretReference,
    scope: TiktokReadScope,
    granted_scopes: BTreeSet<TiktokOAuthScope>,
    access_token_expires_at: DateTime<Utc>,
    refresh_token_expires_at: Option<DateTime<Utc>>,
    generation: u64,
    revoked_at: Option<DateTime<Utc>>,
}

impl OAuthCredential {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret_reference: SecretReference,
        scope: TiktokReadScope,
        granted_scopes: BTreeSet<TiktokOAuthScope>,
        access_token_expires_at: DateTime<Utc>,
        refresh_token_expires_at: Option<DateTime<Utc>>,
        generation: u64,
    ) -> Result<Self, TiktokError> {
        if generation == 0 {
            return Err(TiktokError::InvalidRequest(
                "credential generation must be positive",
            ));
        }
        Ok(Self {
            secret_reference,
            scope,
            granted_scopes,
            access_token_expires_at,
            refresh_token_expires_at,
            generation,
            revoked_at: None,
        })
    }

    pub const fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub const fn scope(&self) -> &TiktokReadScope {
        &self.scope
    }

    pub fn granted_scopes(&self) -> &BTreeSet<TiktokOAuthScope> {
        &self.granted_scopes
    }

    pub const fn access_token_expires_at(&self) -> DateTime<Utc> {
        self.access_token_expires_at
    }

    pub const fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.refresh_token_expires_at
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) {
        self.revoked_at = Some(at);
    }

    pub const fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    pub fn require_for(
        &self,
        operation: TiktokApiOperation,
        expected_scope: &TiktokReadScope,
        now: DateTime<Utc>,
    ) -> Result<(), TiktokError> {
        if &self.scope != expected_scope {
            return Err(TiktokError::ScopeMismatch);
        }
        if self.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
            return Err(TiktokError::CredentialRevoked);
        }
        if self.access_token_expires_at <= now {
            return Err(TiktokError::CredentialExpired);
        }
        let required_scope = operation.required_scope();
        if !self.granted_scopes.contains(&required_scope) {
            return Err(TiktokError::MissingScope {
                scope: required_scope,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenance {
    Fixture,
    ControlledProvider,
    ProductionProvider,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokConnectionState {
    Reachable,
    Disconnected,
    Expired,
    Revoked,
    RateLimited,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TiktokFreshnessPolicy {
    probe_ttl: Duration,
    read_ttl: Duration,
}

impl Default for TiktokFreshnessPolicy {
    fn default() -> Self {
        Self::new(Duration::seconds(120), Duration::minutes(5))
            .expect("default TikTok freshness windows are positive")
    }
}

impl TiktokFreshnessPolicy {
    pub fn new(probe_ttl: Duration, read_ttl: Duration) -> Result<Self, TiktokError> {
        if probe_ttl <= Duration::zero() || read_ttl <= Duration::zero() {
            return Err(TiktokError::InvalidRequest(
                "freshness windows must be positive",
            ));
        }
        Ok(Self {
            probe_ttl,
            read_ttl,
        })
    }

    fn valid_until(
        &self,
        operation: TiktokApiOperation,
        observed_at: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, TiktokError> {
        observed_at
            .checked_add_signed(match operation {
                TiktokApiOperation::UserInfo => self.probe_ttl,
                TiktokApiOperation::VideoList | TiktokApiOperation::VideoQuery => self.read_ttl,
            })
            .ok_or(TiktokError::InvalidRequest("freshness timestamp overflow"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokFreshness {
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    source_generation: u64,
}

impl TiktokFreshness {
    pub fn new(
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        source_generation: u64,
    ) -> Result<Self, TiktokError> {
        if valid_until <= observed_at || source_generation == 0 {
            return Err(TiktokError::InvalidRequest("invalid freshness envelope"));
        }
        Ok(Self {
            observed_at,
            valid_until,
            source_generation,
        })
    }

    pub const fn observed_at(self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(self) -> DateTime<Utc> {
        self.valid_until
    }

    pub const fn source_generation(self) -> u64 {
        self.source_generation
    }

    pub fn validate_at(self, now: DateTime<Utc>) -> Result<(), TiktokError> {
        if now < self.observed_at || now >= self.valid_until {
            return Err(TiktokError::FreshnessExpired {
                observed_at: self.observed_at,
                valid_until: self.valid_until,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokRequestCost {
    request_units: u32,
    monetary_micros: Option<u64>,
}

impl TiktokRequestCost {
    pub const fn request_units(self) -> u32 {
        self.request_units
    }

    pub const fn monetary_micros(self) -> Option<u64> {
        self.monetary_micros
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokQuotaReservation {
    operation: TiktokApiOperation,
    cost: TiktokRequestCost,
    observed_at: DateTime<Utc>,
}

impl TiktokQuotaReservation {
    pub const fn operation(&self) -> TiktokApiOperation {
        self.operation
    }

    pub const fn cost(&self) -> TiktokRequestCost {
        self.cost
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokQuotaLedger {
    per_minute_limit: u32,
    calls: BTreeMap<TiktokApiOperation, Vec<DateTime<Utc>>>,
    reservations: Vec<TiktokQuotaReservation>,
    last_observed_at: Option<DateTime<Utc>>,
}

impl Default for TiktokQuotaLedger {
    fn default() -> Self {
        Self::new(600).expect("default TikTok rate limit is positive")
    }
}

impl TiktokQuotaLedger {
    pub fn new(per_minute_limit: u32) -> Result<Self, TiktokError> {
        if per_minute_limit == 0 {
            return Err(TiktokError::InvalidRequest(
                "TikTok rate limit must be positive",
            ));
        }
        Ok(Self {
            per_minute_limit,
            calls: BTreeMap::new(),
            reservations: Vec::new(),
            last_observed_at: None,
        })
    }

    pub const fn per_minute_limit(&self) -> u32 {
        self.per_minute_limit
    }

    pub fn reservations(&self) -> &[TiktokQuotaReservation] {
        &self.reservations
    }

    pub fn remaining(&self, operation: TiktokApiOperation, now: DateTime<Utc>) -> u32 {
        let count = self.calls.get(&operation).map_or(0, |calls| {
            u32::try_from(
                calls
                    .iter()
                    .filter(|observed_at| **observed_at > now - Duration::minutes(1))
                    .count(),
            )
            .unwrap_or(u32::MAX)
        });
        self.per_minute_limit.saturating_sub(count)
    }

    pub fn reserve(
        &mut self,
        operation: TiktokApiOperation,
        now: DateTime<Utc>,
    ) -> Result<TiktokRequestCost, TiktokError> {
        if self.last_observed_at.is_some_and(|last| now < last) {
            return Err(TiktokError::InvalidRequest("quota clock moved backwards"));
        }
        let calls = self.calls.entry(operation).or_default();
        calls.retain(|observed_at| *observed_at > now - Duration::minutes(1));
        if calls.len() >= self.per_minute_limit as usize {
            return Err(TiktokError::QuotaExhausted { operation });
        }
        calls.push(now);
        let cost = operation.cost();
        self.reservations.push(TiktokQuotaReservation {
            operation,
            cost,
            observed_at: now,
        });
        self.last_observed_at = Some(now);
        Ok(cost)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokVideoListCursor {
    scope: TiktokReadScope,
    generation: u64,
    page_size: u8,
    next_cursor: Option<TiktokCursor>,
    has_more: bool,
    request_fingerprint: String,
    last_page_digest: Option<String>,
    updated_at: Option<DateTime<Utc>>,
    freshness: Option<TiktokFreshness>,
}

impl TiktokVideoListCursor {
    pub fn new(scope: TiktokReadScope) -> Result<Self, TiktokError> {
        Self::new_with_page_size(scope, DEFAULT_VIDEO_PAGE_SIZE)
    }

    pub fn new_with_page_size(scope: TiktokReadScope, page_size: u8) -> Result<Self, TiktokError> {
        if !(1..=DEFAULT_VIDEO_PAGE_SIZE).contains(&page_size) {
            return Err(TiktokError::InvalidRequest(
                "TikTok video.list max_count must be one through twenty",
            ));
        }
        let cursor = Self {
            scope,
            generation: 0,
            page_size,
            next_cursor: None,
            has_more: true,
            request_fingerprint: video_list_request_fingerprint(page_size),
            last_page_digest: None,
            updated_at: None,
            freshness: None,
        };
        cursor.validate()?;
        Ok(cursor)
    }

    pub const fn scope(&self) -> &TiktokReadScope {
        &self.scope
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn page_size(&self) -> u8 {
        self.page_size
    }

    pub const fn next_cursor(&self) -> Option<TiktokCursor> {
        self.next_cursor
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    pub(super) fn require_page_size(&self, page_size: u8) -> Result<(), TiktokError> {
        if self.page_size != page_size {
            return Err(TiktokError::CursorDrift);
        }
        Ok(())
    }

    pub fn last_page_digest(&self) -> Option<&str> {
        self.last_page_digest.as_deref()
    }

    pub const fn freshness(&self) -> Option<TiktokFreshness> {
        self.freshness
    }

    pub fn require_fresh(&self, now: DateTime<Utc>) -> Result<TiktokFreshness, TiktokError> {
        let freshness = self.freshness.ok_or(TiktokError::FreshnessUnavailable)?;
        freshness.validate_at(now)?;
        Ok(freshness)
    }

    pub fn checkpoint_json(&self) -> Result<String, TiktokError> {
        self.validate()?;
        serde_json::to_string(self)
            .map_err(|_| TiktokError::InvalidRequest("cursor checkpoint serialization failed"))
    }

    pub fn from_checkpoint_json(value: &str) -> Result<Self, TiktokError> {
        let cursor: Self = serde_json::from_str(value)
            .map_err(|_| TiktokError::InvalidRequest("invalid cursor checkpoint"))?;
        cursor.validate()?;
        Ok(cursor)
    }

    pub fn durable_digest(&self) -> String {
        serde_json::to_value(self).map_or_else(|_| "0".repeat(64), |value| sha256_json(&value))
    }

    pub fn apply_page(
        &mut self,
        expected_generation: u64,
        page: &TiktokVideoPage,
    ) -> Result<TiktokCursorDisposition, TiktokError> {
        self.validate()?;
        page.validate()?;
        if page.scope != self.scope
            || page.request_fingerprint != self.request_fingerprint
            || page.requested_cursor != self.next_cursor
        {
            return Err(TiktokError::CursorDrift);
        }
        if self
            .last_page_digest
            .as_deref()
            .is_some_and(|digest| digest == page.page_digest)
        {
            return Ok(TiktokCursorDisposition::Duplicate);
        }
        if expected_generation != self.generation
            || self
                .updated_at
                .is_some_and(|updated| page.observed_at < updated)
        {
            return Err(TiktokError::CursorDrift);
        }
        if page.has_more {
            let next = page.next_cursor.ok_or(TiktokError::CursorDrift)?;
            if self
                .next_cursor
                .is_some_and(|current| next.value() <= current.value())
            {
                return Err(TiktokError::CursorDrift);
            }
        } else if page.next_cursor.is_some() {
            return Err(TiktokError::CursorDrift);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(TiktokError::CursorDrift)?;
        self.next_cursor = page.next_cursor;
        self.has_more = page.has_more;
        self.last_page_digest = Some(page.page_digest.clone());
        self.updated_at = Some(page.observed_at);
        self.freshness = Some(page.freshness);
        Ok(TiktokCursorDisposition::Applied)
    }

    fn validate(&self) -> Result<(), TiktokError> {
        if !(1..=DEFAULT_VIDEO_PAGE_SIZE).contains(&self.page_size)
            || self.request_fingerprint != video_list_request_fingerprint(self.page_size)
            || (self.generation == 0
                && (self.last_page_digest.is_some()
                    || self.updated_at.is_some()
                    || self.freshness.is_some()))
            || (self.generation > 0 && self.has_more != self.next_cursor.is_some())
            || self
                .last_page_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(TiktokError::CursorDrift);
        }
        if self.generation > 0 && (self.updated_at.is_none() || self.freshness.is_none()) {
            return Err(TiktokError::CursorDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokCursorDisposition {
    Applied,
    Duplicate,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_field_names)]
#[serde(rename_all = "snake_case")]
pub struct TiktokPerformanceObservation {
    like_count: Option<u64>,
    comment_count: Option<u64>,
    share_count: Option<u64>,
    view_count: Option<u64>,
}

impl TiktokPerformanceObservation {
    pub const fn like_count(&self) -> Option<u64> {
        self.like_count
    }

    pub const fn comment_count(&self) -> Option<u64> {
        self.comment_count
    }

    pub const fn share_count(&self) -> Option<u64> {
        self.share_count
    }

    pub const fn view_count(&self) -> Option<u64> {
        self.view_count
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokVideoObservation {
    identity: TiktokVideoIdentity,
    created_at: Option<DateTime<Utc>>,
    title: Option<String>,
    description: Option<String>,
    share_url: Option<String>,
    performance: TiktokPerformanceObservation,
}

impl TiktokVideoObservation {
    pub const fn identity(&self) -> &TiktokVideoIdentity {
        &self.identity
    }

    pub const fn created_at(&self) -> Option<DateTime<Utc>> {
        self.created_at
    }

    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    pub fn share_url(&self) -> Option<&str> {
        self.share_url.as_deref()
    }

    pub const fn performance(&self) -> &TiktokPerformanceObservation {
        &self.performance
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokAccountObservation {
    identity: TiktokAccountIdentity,
}

impl TiktokAccountObservation {
    pub const fn identity(&self) -> &TiktokAccountIdentity {
        &self.identity
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokReadObservation {
    Account(TiktokAccountObservation),
    Video(TiktokVideoObservation),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokObservationEnvelope {
    provider: ProviderId,
    scope: TiktokReadScope,
    account: TiktokAccountIdentity,
    revision: TiktokRevisionIdentity,
    freshness: TiktokFreshness,
    provenance: EvidenceProvenance,
    observation: TiktokReadObservation,
}

impl TiktokObservationEnvelope {
    pub(crate) fn new(
        scope: TiktokReadScope,
        account: TiktokAccountIdentity,
        revision: TiktokRevisionIdentity,
        freshness: TiktokFreshness,
        provenance: EvidenceProvenance,
        observation: TiktokReadObservation,
    ) -> Result<Self, TiktokError> {
        let envelope = Self {
            provider: ProviderId::Tiktok,
            scope,
            account,
            revision,
            freshness,
            provenance,
            observation,
        };
        envelope.validate_integrity()?;
        Ok(envelope)
    }

    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    pub const fn scope(&self) -> &TiktokReadScope {
        &self.scope
    }

    pub const fn account(&self) -> &TiktokAccountIdentity {
        &self.account
    }

    pub const fn revision(&self) -> &TiktokRevisionIdentity {
        &self.revision
    }

    pub const fn freshness(&self) -> TiktokFreshness {
        self.freshness
    }

    pub const fn provenance(&self) -> EvidenceProvenance {
        self.provenance
    }

    pub const fn observation(&self) -> &TiktokReadObservation {
        &self.observation
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), TiktokError> {
        self.validate_integrity()?;
        self.freshness.validate_at(now)
    }

    fn validate_integrity(&self) -> Result<(), TiktokError> {
        if self.provider != ProviderId::Tiktok
            || self.scope.account() != self.account.open_id()
            || self.revision.provider() != ProviderId::Tiktok
            || self.revision.account_id() != self.account.open_id()
        {
            return Err(TiktokError::IdentityMismatch);
        }
        match &self.observation {
            TiktokReadObservation::Account(observation) => {
                if observation.identity.open_id() != self.account.open_id()
                    || !matches!(self.revision, TiktokRevisionIdentity::Account { .. })
                {
                    return Err(TiktokError::RevisionMismatch);
                }
            }
            TiktokReadObservation::Video(observation) => {
                let TiktokRevisionIdentity::Video {
                    video_id: revision_video_id,
                    ..
                } = &self.revision
                else {
                    return Err(TiktokError::RevisionMismatch);
                };
                if observation.identity.account() != self.account.open_id()
                    || observation.identity.video_id() != revision_video_id
                {
                    return Err(TiktokError::RevisionMismatch);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokVideoPageEnvelope {
    provider: ProviderId,
    scope: TiktokReadScope,
    account: TiktokAccountIdentity,
    requested_cursor: Option<TiktokCursor>,
    next_cursor: Option<TiktokCursor>,
    has_more: bool,
    page_digest: String,
    cursor_generation: u64,
    freshness: TiktokFreshness,
    provenance: EvidenceProvenance,
    observations: Vec<TiktokObservationEnvelope>,
}

impl TiktokVideoPageEnvelope {
    pub fn observations(&self) -> &[TiktokObservationEnvelope] {
        &self.observations
    }

    pub const fn next_cursor(&self) -> Option<TiktokCursor> {
        self.next_cursor
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn page_digest(&self) -> &str {
        &self.page_digest
    }

    pub const fn cursor_generation(&self) -> u64 {
        self.cursor_generation
    }

    pub const fn freshness(&self) -> TiktokFreshness {
        self.freshness
    }

    pub const fn provenance(&self) -> EvidenceProvenance {
        self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokVideoPage {
    scope: TiktokReadScope,
    requested_cursor: Option<TiktokCursor>,
    next_cursor: Option<TiktokCursor>,
    has_more: bool,
    page_digest: String,
    request_fingerprint: String,
    observed_at: DateTime<Utc>,
    observations: Vec<TiktokObservationEnvelope>,
    freshness: TiktokFreshness,
}

impl TiktokVideoPage {
    fn validate(&self) -> Result<(), TiktokError> {
        let provenance = self
            .observations
            .first()
            .map(TiktokObservationEnvelope::provenance);
        if !is_sha256(&self.page_digest)
            || !is_sha256(&self.request_fingerprint)
            || self.observations.iter().any(|observation| {
                observation.scope() != &self.scope
                    || provenance.is_some_and(|expected| observation.provenance() != expected)
            })
        {
            return Err(TiktokError::CursorDrift);
        }
        if self.has_more != self.next_cursor.is_some() {
            return Err(TiktokError::CursorDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TiktokError {
    #[error("invalid TikTok read request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid TikTok provider response: {field}")]
    InvalidResponse { field: String },
    #[error("TikTok OAuth scope is missing: {scope:?}")]
    MissingScope { scope: TiktokOAuthScope },
    #[error("TikTok OAuth credential is expired")]
    CredentialExpired,
    #[error("TikTok OAuth credential is revoked or invalid")]
    CredentialRevoked,
    #[error("TikTok credential reference does not match the production gate")]
    CredentialReferenceMismatch,
    #[error("TikTok read scope does not match the exact tenant/business/account scope")]
    ScopeMismatch,
    #[error("TikTok provider/account identity mismatch")]
    IdentityMismatch,
    #[error("TikTok observation revision mismatch")]
    RevisionMismatch,
    #[error("TikTok evidence provenance is not admissible to Mission")]
    ProvenanceRejected,
    #[error("TikTok provider is disconnected")]
    Disconnected,
    #[error("TikTok API rate limited for {operation:?}")]
    RateLimited {
        operation: TiktokApiOperation,
        retry_after_seconds: Option<u64>,
    },
    #[error("TikTok API quota exhausted for {operation:?}")]
    QuotaExhausted { operation: TiktokApiOperation },
    #[error("TikTok durable cursor drifted")]
    CursorDrift,
    #[error("TikTok durable cursor has no more pages")]
    CursorExhausted,
    #[error("TikTok freshness expired: valid until {valid_until}")]
    FreshnessExpired {
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    #[error("TikTok freshness is not established")]
    FreshnessUnavailable,
    #[error("TikTok provider rejected the request with status {status}")]
    ProviderRejected { status: u16, code: Option<String> },
    #[error("TikTok production read is blocked by environment: {requirement}")]
    BlockedEnvironment { requirement: &'static str },
    #[error("TikTok observation revision is not the exact Mission revision")]
    MissionRevisionMismatch,
    #[error("TikTok observation revision was already admitted")]
    DuplicateRevision,
}

impl From<crate::transport::ChannelAdapterError> for TiktokError {
    fn from(error: crate::transport::ChannelAdapterError) -> Self {
        match error {
            crate::transport::ChannelAdapterError::InvalidRequest(message) => {
                Self::InvalidRequest(message)
            }
            crate::transport::ChannelAdapterError::InvalidResponse { field, .. } => {
                Self::InvalidResponse { field }
            }
            _ => Self::InvalidRequest("invalid TikTok provider request"),
        }
    }
}

impl TiktokError {
    pub const fn connection_state(&self) -> Option<TiktokConnectionState> {
        match self {
            Self::Disconnected => Some(TiktokConnectionState::Disconnected),
            Self::CredentialExpired => Some(TiktokConnectionState::Expired),
            Self::CredentialRevoked => Some(TiktokConnectionState::Revoked),
            Self::RateLimited { .. } | Self::QuotaExhausted { .. } => {
                Some(TiktokConnectionState::RateLimited)
            }
            _ => None,
        }
    }
}

fn video_list_request_fingerprint(page_size: u8) -> String {
    sha256_json(&serde_json::json!({
        "provider": "tiktok",
        "operation": "video_list",
        "max_count": page_size,
        "fields": [
            "id",
            "create_time",
            "title",
            "video_description",
            "share_url",
            "like_count",
            "comment_count",
            "share_count",
            "view_count"
        ]
    }))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
