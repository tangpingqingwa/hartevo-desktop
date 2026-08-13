//! Durable, authenticated TikTok creator/content insight reads.
//!
//! This module owns only the provider-specific read boundary. It does not
//! issue OAuth authority, store a token in a checkpoint, publish content, or
//! decide Mission policy. A Mission consumer can adopt only an exact,
//! complete production result whose creator/account scope and evidence root
//! match its capability.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Write,
    process::{Command, Stdio},
};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::identity::{
    ContentIdentity, ProviderId, RevisionIdentity, TiktokAccountIdentity, TiktokContentIdentity,
    TiktokCreatorIdentity, TiktokOpenId, TiktokPublishId, TiktokRevisionIdentity, WebhookEventId,
};
use crate::tiktok::{
    TIKTOK_USER_INFO_BASIC_SCOPE, TIKTOK_VIDEO_LIST_SCOPE, TiktokAuditState, TiktokAuthorization,
    TiktokContentStatus, TiktokModerationState, TiktokScope,
};
use crate::transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderReadRequest,
    ProviderResponse, ReadOnlyTransport, ReadOperation, ScopeName, TransportError,
};
use crate::webhook::WebhookEnvelope;

pub const TIKTOK_DISPLAY_API_BASE_URL: &str = "https://open.tiktokapis.com/v2";
pub const TIKTOK_USER_INFO_PATH: &str = "/user/info/";
pub const TIKTOK_VIDEO_LIST_PATH: &str = "/video/list/";
pub const TIKTOK_INSIGHT_DEFAULT_PAGE_SIZE: u8 = 20;
pub const TIKTOK_REAL_INSIGHT_ENABLE_ENV: &str = "HARTEVO_TIKTOK_REAL_INSIGHT_READ";
pub const TIKTOK_REAL_INSIGHT_SECRET_REFERENCE_ENV: &str = "HARTEVO_TIKTOK_SECRET_REFERENCE";
pub const TIKTOK_REAL_INSIGHT_ACCESS_TOKEN_ENV: &str = "HARTEVO_TIKTOK_ACCESS_TOKEN";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokInsightOperation {
    AuthenticatedProbe,
    VideoList,
    ContentStatus,
}

impl TiktokInsightOperation {
    pub const fn cost(self) -> TiktokInsightRequestCost {
        TiktokInsightRequestCost {
            request_units: 1,
            monetary_micros: None,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TiktokInsightError {
    #[error("TikTok channel adapter error: {0}")]
    Adapter(ChannelAdapterError),
    #[error("invalid TikTok insight request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid TikTok insight response: {0}")]
    InvalidResponse(&'static str),
    #[error("TikTok authenticated insight read is blocked by environment: {requirement}")]
    BlockedEnvironment { requirement: &'static str },
    #[error("TikTok insight credential is expired")]
    CredentialExpired,
    #[error("TikTok insight credential is revoked")]
    CredentialRevoked,
    #[error("TikTok insight credential is unmounted")]
    CredentialUnmounted,
    #[error("TikTok insight credential generation or reference rotated")]
    CredentialRotated,
    #[error("TikTok insight scope does not match the exact app/account/creator")]
    ScopeMismatch,
    #[error("TikTok insight scope is missing: {scope}")]
    MissingScope { scope: &'static str },
    #[error("TikTok unaudited client is limited to the private content boundary")]
    UnauditedPrivateBoundary,
    #[error("TikTok insight provider is disconnected")]
    Disconnected,
    #[error("TikTok insight provider rejected the request with status {status}")]
    ProviderRejected { status: u16, code: Option<String> },
    #[error("TikTok insight API is rate limited")]
    RateLimited {
        receipt: Box<TiktokRetryAfterReceipt>,
    },
    #[error("TikTok insight quota exhausted for {operation:?}")]
    QuotaExhausted { operation: TiktokInsightOperation },
    #[error("TikTok durable insight cursor drifted")]
    CursorDrift,
    #[error("TikTok durable insight cursor is exhausted")]
    CursorExhausted,
    #[error("TikTok insight freshness expired")]
    FreshnessExpired {
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    },
    #[error("TikTok insight freshness is not established")]
    FreshnessUnavailable,
    #[error("TikTok provider response arrived out of order")]
    LateResponse {
        observed_at: DateTime<Utc>,
        last_observed_at: DateTime<Utc>,
    },
    #[error("TikTok insight webhook arrived out of order")]
    OutOfOrderWebhook,
    #[error("TikTok insight webhook was already ingested")]
    DuplicateWebhook,
    #[error("TikTok insight result has non-exact provider/account/creator identity")]
    IdentityMismatch,
    #[error("TikTok insight result has non-exact content or revision identity")]
    RevisionMismatch,
    #[error("TikTok fixture or controlled evidence is not admissible to Mission")]
    ProvenanceRejected,
    #[error("TikTok Mission capability requires a complete page sequence")]
    IncompleteSequence,
    #[error("TikTok Mission capability does not match the exact result")]
    MissionCapabilityMismatch,
}

impl From<ChannelAdapterError> for TiktokInsightError {
    fn from(error: ChannelAdapterError) -> Self {
        Self::Adapter(error)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TiktokInsightAppId(String);

impl TiktokInsightAppId {
    pub fn new(value: impl Into<String>) -> Result<Self, TiktokInsightError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 256
            || value
                .chars()
                .any(|character| !character.is_ascii() || character.is_ascii_control())
        {
            return Err(TiktokInsightError::InvalidRequest(
                "TikTok app identity must be opaque and non-empty",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightScope {
    app: TiktokInsightAppId,
    account: TiktokAccountIdentity,
    creator: TiktokCreatorIdentity,
}

impl TiktokInsightScope {
    pub fn new(
        app: TiktokInsightAppId,
        account: TiktokAccountIdentity,
        creator: TiktokCreatorIdentity,
    ) -> Result<Self, TiktokInsightError> {
        if creator.account() != &account {
            return Err(TiktokInsightError::ScopeMismatch);
        }
        Ok(Self {
            app,
            account,
            creator,
        })
    }

    pub const fn provider(&self) -> ProviderId {
        ProviderId::Tiktok
    }

    pub const fn app(&self) -> &TiktokInsightAppId {
        &self.app
    }

    pub const fn account(&self) -> &TiktokAccountIdentity {
        &self.account
    }

    pub const fn creator(&self) -> &TiktokCreatorIdentity {
        &self.creator
    }
}

pub use crate::transport::CredentialReference as TiktokSecretReference;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TiktokInsightCredential {
    secret_reference: CredentialReference,
    authorization: TiktokAuthorization,
    token_generation: u64,
    revoked_at: Option<DateTime<Utc>>,
    unmounted_at: Option<DateTime<Utc>>,
}

impl TiktokInsightCredential {
    pub fn new(
        secret_reference: CredentialReference,
        authorization: TiktokAuthorization,
        token_generation: u64,
    ) -> Result<Self, TiktokInsightError> {
        if token_generation == 0 {
            return Err(TiktokInsightError::InvalidRequest(
                "TikTok token generation must be positive",
            ));
        }
        Ok(Self {
            secret_reference,
            authorization,
            token_generation,
            revoked_at: None,
            unmounted_at: None,
        })
    }

    pub const fn secret_reference(&self) -> &CredentialReference {
        &self.secret_reference
    }

    pub const fn authorization(&self) -> &TiktokAuthorization {
        &self.authorization
    }

    pub const fn token_generation(&self) -> u64 {
        self.token_generation
    }

    pub fn scope_digest(&self) -> String {
        sha256_json(&serde_json::json!({
            "app_approved_scopes": self.authorization.app_approved_scopes(),
            "user_granted_scopes": self.authorization.user_granted_scopes(),
            "audit_state": self.authorization.audit_state(),
        }))
    }

    pub fn secret_reference_digest(&self) -> String {
        sha256_json(&serde_json::json!({
            "secret_reference": self.secret_reference.as_str(),
        }))
    }

    pub fn revoke(&mut self, at: DateTime<Utc>) {
        self.revoked_at = Some(at);
    }

    pub const fn revoked_at(&self) -> Option<DateTime<Utc>> {
        self.revoked_at
    }

    pub fn unmount(&mut self, at: DateTime<Utc>) {
        self.unmounted_at = Some(at);
    }

    pub const fn unmounted_at(&self) -> Option<DateTime<Utc>> {
        self.unmounted_at
    }

    fn require_for(
        &self,
        operation: TiktokInsightOperation,
        scope: &TiktokInsightScope,
        now: DateTime<Utc>,
    ) -> Result<(), TiktokInsightError> {
        if self.authorization.identity() != scope.account() {
            return Err(TiktokInsightError::ScopeMismatch);
        }
        if self
            .unmounted_at
            .is_some_and(|unmounted_at| unmounted_at <= now)
        {
            return Err(TiktokInsightError::CredentialUnmounted);
        }
        if self.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
            return Err(TiktokInsightError::CredentialRevoked);
        }
        if self
            .authorization
            .access_token_expires_at()
            .is_some_and(|expires_at| expires_at <= now)
        {
            return Err(TiktokInsightError::CredentialExpired);
        }
        let required = match operation {
            TiktokInsightOperation::AuthenticatedProbe => TiktokScope::UserInfoBasic,
            TiktokInsightOperation::VideoList => TiktokScope::VideoList,
            TiktokInsightOperation::ContentStatus => {
                if self
                    .authorization
                    .app_approved_scopes()
                    .contains(&TiktokScope::VideoPublish)
                    && self
                        .authorization
                        .user_granted_scopes()
                        .contains(&TiktokScope::VideoPublish)
                {
                    TiktokScope::VideoPublish
                } else {
                    TiktokScope::VideoUpload
                }
            }
        };
        if !self.authorization.app_approved_scopes().contains(&required) {
            return Err(TiktokInsightError::Adapter(
                ChannelAdapterError::AuthorizationRequired {
                    provider: ProviderId::Tiktok,
                    reason: AuthorizationReason::MissingApproval,
                },
            ));
        }
        if !self.authorization.user_granted_scopes().contains(&required) {
            return Err(TiktokInsightError::Adapter(
                ChannelAdapterError::AuthorizationRequired {
                    provider: ProviderId::Tiktok,
                    reason: AuthorizationReason::MissingScope,
                },
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokInsightProvenance {
    Fixture,
    ControlledProvider,
    ProductionProvider,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightFreshness {
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    token_generation: u64,
}

impl TiktokInsightFreshness {
    fn new(
        observed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
        token_generation: u64,
    ) -> Result<Self, TiktokInsightError> {
        if valid_until <= observed_at || token_generation == 0 {
            return Err(TiktokInsightError::InvalidResponse("freshness fence"));
        }
        Ok(Self {
            observed_at,
            valid_until,
            token_generation,
        })
    }

    pub const fn observed_at(self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(self) -> DateTime<Utc> {
        self.valid_until
    }

    pub const fn token_generation(self) -> u64 {
        self.token_generation
    }

    fn validate_at(self, now: DateTime<Utc>) -> Result<(), TiktokInsightError> {
        if now < self.observed_at || now >= self.valid_until {
            return Err(TiktokInsightError::FreshnessExpired {
                observed_at: self.observed_at,
                valid_until: self.valid_until,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct TiktokInsightFreshnessPolicy {
    probe_ttl: Duration,
    page_ttl: Duration,
    status_ttl: Duration,
}

impl Default for TiktokInsightFreshnessPolicy {
    fn default() -> Self {
        Self::new(
            Duration::minutes(2),
            Duration::minutes(5),
            Duration::minutes(2),
        )
        .expect("default TikTok freshness windows are positive")
    }
}

impl TiktokInsightFreshnessPolicy {
    pub fn new(
        probe_ttl: Duration,
        page_ttl: Duration,
        status_ttl: Duration,
    ) -> Result<Self, TiktokInsightError> {
        if probe_ttl <= Duration::zero()
            || page_ttl <= Duration::zero()
            || status_ttl <= Duration::zero()
        {
            return Err(TiktokInsightError::InvalidRequest(
                "TikTok freshness windows must be positive",
            ));
        }
        Ok(Self {
            probe_ttl,
            page_ttl,
            status_ttl,
        })
    }

    fn valid_until(
        &self,
        operation: TiktokInsightOperation,
        observed_at: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, TiktokInsightError> {
        observed_at
            .checked_add_signed(match operation {
                TiktokInsightOperation::AuthenticatedProbe => self.probe_ttl,
                TiktokInsightOperation::VideoList => self.page_ttl,
                TiktokInsightOperation::ContentStatus => self.status_ttl,
            })
            .ok_or(TiktokInsightError::InvalidResponse("freshness timestamp"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightRequestCost {
    request_units: u32,
    monetary_micros: Option<u64>,
}

impl TiktokInsightRequestCost {
    pub const fn request_units(self) -> u32 {
        self.request_units
    }

    pub const fn monetary_micros(self) -> Option<u64> {
        self.monetary_micros
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightQuotaReservation {
    operation: TiktokInsightOperation,
    cost: TiktokInsightRequestCost,
    observed_at: DateTime<Utc>,
    remaining_in_window: u32,
}

impl TiktokInsightQuotaReservation {
    pub const fn operation(&self) -> TiktokInsightOperation {
        self.operation
    }

    pub const fn cost(&self) -> TiktokInsightRequestCost {
        self.cost
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn remaining_in_window(&self) -> u32 {
        self.remaining_in_window
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightQuotaLedger {
    per_minute_limit: u32,
    calls: BTreeMap<TiktokInsightOperation, Vec<DateTime<Utc>>>,
    reservations: Vec<TiktokInsightQuotaReservation>,
    last_observed_at: Option<DateTime<Utc>>,
}

impl Default for TiktokInsightQuotaLedger {
    fn default() -> Self {
        Self::new(600).expect("default TikTok insight quota is positive")
    }
}

impl TiktokInsightQuotaLedger {
    pub fn new(per_minute_limit: u32) -> Result<Self, TiktokInsightError> {
        if per_minute_limit == 0 {
            return Err(TiktokInsightError::InvalidRequest(
                "TikTok insight quota must be positive",
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

    pub fn reservations(&self) -> &[TiktokInsightQuotaReservation] {
        &self.reservations
    }

    pub fn remaining(&self, operation: TiktokInsightOperation, now: DateTime<Utc>) -> u32 {
        let count = self
            .calls
            .get(&operation)
            .map(|calls| {
                calls
                    .iter()
                    .filter(|observed_at| **observed_at > now - Duration::minutes(1))
                    .count()
                    .try_into()
                    .unwrap_or(u32::MAX)
            })
            .unwrap_or_default();
        self.per_minute_limit.saturating_sub(count)
    }

    pub fn reserve(
        &mut self,
        operation: TiktokInsightOperation,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightQuotaReservation, TiktokInsightError> {
        if self.last_observed_at.is_some_and(|last| now < last) {
            return Err(TiktokInsightError::InvalidRequest(
                "TikTok insight quota clock moved backwards",
            ));
        }
        let calls = self.calls.entry(operation).or_default();
        calls.retain(|observed_at| *observed_at > now - Duration::minutes(1));
        if calls.len() >= self.per_minute_limit as usize {
            return Err(TiktokInsightError::QuotaExhausted { operation });
        }
        calls.push(now);
        let reservation = TiktokInsightQuotaReservation {
            operation,
            cost: operation.cost(),
            observed_at: now,
            remaining_in_window: self
                .per_minute_limit
                .saturating_sub(calls.len().try_into().unwrap_or(u32::MAX)),
        };
        self.reservations.push(reservation.clone());
        self.last_observed_at = Some(now);
        Ok(reservation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct TiktokInsightVideoId(String);

impl TiktokInsightVideoId {
    pub fn new(value: impl Into<String>) -> Result<Self, TiktokInsightError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 20
            || !value.chars().all(|character| character.is_ascii_digit())
        {
            return Err(TiktokInsightError::InvalidResponse("video id"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TiktokInsightVideoId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightContentIdentity {
    account: TiktokAccountIdentity,
    video_id: TiktokInsightVideoId,
}

impl TiktokInsightContentIdentity {
    fn new(account: TiktokAccountIdentity, video_id: TiktokInsightVideoId) -> Self {
        Self { account, video_id }
    }

    pub const fn account(&self) -> &TiktokAccountIdentity {
        &self.account
    }

    pub const fn video_id(&self) -> &TiktokInsightVideoId {
        &self.video_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightRevision {
    content: TiktokInsightContentIdentity,
    digest: String,
    observed_at: DateTime<Utc>,
}

impl TiktokInsightRevision {
    fn new(
        content: TiktokInsightContentIdentity,
        digest: String,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, TiktokInsightError> {
        if !is_sha256(&digest) {
            return Err(TiktokInsightError::InvalidResponse(
                "content revision digest",
            ));
        }
        Ok(Self {
            content,
            digest,
            observed_at,
        })
    }

    pub const fn content(&self) -> &TiktokInsightContentIdentity {
        &self.content
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::struct_field_names)]
pub struct TiktokInsightPerformance {
    like_count: Option<u64>,
    comment_count: Option<u64>,
    share_count: Option<u64>,
    view_count: Option<u64>,
}

impl TiktokInsightPerformance {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokInsightModerationClassification {
    PubliclyAvailable,
    PrivateOnlyUnaudited,
    NotPublic,
    NoLongerPublic,
    Failed,
    Processing,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightContentObservation {
    identity: TiktokInsightContentIdentity,
    revision: TiktokInsightRevision,
    created_at: Option<DateTime<Utc>>,
    title: Option<String>,
    description: Option<String>,
    share_url: Option<String>,
    performance: TiktokInsightPerformance,
    moderation: TiktokInsightModerationClassification,
    observed_at: DateTime<Utc>,
}

impl TiktokInsightContentObservation {
    pub const fn identity(&self) -> &TiktokInsightContentIdentity {
        &self.identity
    }

    pub const fn revision(&self) -> &TiktokInsightRevision {
        &self.revision
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

    pub const fn performance(&self) -> &TiktokInsightPerformance {
        &self.performance
    }

    pub const fn moderation(&self) -> TiktokInsightModerationClassification {
        self.moderation
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    fn sort_key(&self) -> TiktokInsightSortKey {
        TiktokInsightSortKey {
            created_at: self.created_at.map_or(0, |value| value.timestamp()),
            video_id: self.identity.video_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TiktokInsightSortKey {
    created_at: i64,
    video_id: TiktokInsightVideoId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokAuthenticatedCreatorProbe {
    provider: ProviderId,
    scope: TiktokInsightScope,
    account: TiktokAccountIdentity,
    creator: TiktokCreatorIdentity,
    token_generation: u64,
    audit_state: TiktokAuditState,
    response_digest: String,
    observed_at: DateTime<Utc>,
    freshness: TiktokInsightFreshness,
    provenance: TiktokInsightProvenance,
    quota: Option<TiktokInsightQuotaReservation>,
}

impl TiktokAuthenticatedCreatorProbe {
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    pub const fn scope(&self) -> &TiktokInsightScope {
        &self.scope
    }

    pub const fn account(&self) -> &TiktokAccountIdentity {
        &self.account
    }

    pub const fn creator(&self) -> &TiktokCreatorIdentity {
        &self.creator
    }

    pub const fn token_generation(&self) -> u64 {
        self.token_generation
    }

    pub const fn audit_state(&self) -> TiktokAuditState {
        self.audit_state
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn freshness(&self) -> TiktokInsightFreshness {
        self.freshness
    }

    pub const fn provenance(&self) -> TiktokInsightProvenance {
        self.provenance
    }

    pub const fn quota(&self) -> Option<&TiktokInsightQuotaReservation> {
        self.quota.as_ref()
    }

    fn with_quota(mut self, quota: TiktokInsightQuotaReservation) -> Self {
        self.quota = Some(quota);
        self
    }

    fn validate_at(
        &self,
        scope: &TiktokInsightScope,
        token_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<(), TiktokInsightError> {
        if self.provider != ProviderId::Tiktok
            || self.scope != *scope
            || self.account != *scope.account()
            || self.creator != *scope.creator()
            || self.token_generation != token_generation
            || !is_sha256(&self.response_digest)
            || self.freshness.token_generation() != token_generation
            || self.quota.as_ref().is_some_and(|quota| {
                quota.operation() != TiktokInsightOperation::AuthenticatedProbe
            })
        {
            return Err(TiktokInsightError::IdentityMismatch);
        }
        self.freshness.validate_at(now)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightPage {
    scope: TiktokInsightScope,
    requested_cursor: Option<i64>,
    next_cursor: Option<i64>,
    has_more: bool,
    page_digest: String,
    observed_at: DateTime<Utc>,
    freshness: TiktokInsightFreshness,
    provenance: TiktokInsightProvenance,
    observations: Vec<TiktokInsightContentObservation>,
}

impl TiktokInsightPage {
    pub const fn scope(&self) -> &TiktokInsightScope {
        &self.scope
    }

    pub const fn requested_cursor(&self) -> Option<i64> {
        self.requested_cursor
    }

    pub const fn next_cursor(&self) -> Option<i64> {
        self.next_cursor
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn page_digest(&self) -> &str {
        &self.page_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn freshness(&self) -> TiktokInsightFreshness {
        self.freshness
    }

    pub const fn provenance(&self) -> TiktokInsightProvenance {
        self.provenance
    }

    pub fn observations(&self) -> &[TiktokInsightContentObservation] {
        &self.observations
    }

    fn validate(
        &self,
        scope: &TiktokInsightScope,
        generation: u64,
    ) -> Result<(), TiktokInsightError> {
        if self.scope != *scope
            || !is_sha256(&self.page_digest)
            || self.has_more != self.next_cursor.is_some()
            || self.next_cursor.is_some_and(|cursor| cursor <= 0)
            || self.freshness.token_generation() == 0
            || self.freshness.observed_at() != self.observed_at
            || self.freshness.token_generation() != generation
            || self.observations.is_empty() && self.has_more
        {
            return Err(TiktokInsightError::CursorDrift);
        }
        if self
            .observations
            .windows(2)
            .any(|pair| pair[0].sort_key() <= pair[1].sort_key())
        {
            return Err(TiktokInsightError::CursorDrift);
        }
        let mut ids = BTreeSet::new();
        for observation in &self.observations {
            if observation.identity.account() != scope.account()
                || observation.revision.content() != observation.identity()
                || observation.revision.observed_at() != self.observed_at
                || !ids.insert(observation.identity.video_id().clone())
            {
                return Err(TiktokInsightError::RevisionMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokRetryAfterReceipt {
    provider: ProviderId,
    operation: TiktokInsightOperation,
    scope: TiktokInsightScope,
    requested_cursor: Option<i64>,
    token_generation: u64,
    observed_at: DateTime<Utc>,
    response_digest: String,
    retry_after_seconds: Option<u64>,
    provider_reset_at: Option<DateTime<Utc>>,
}

impl TiktokRetryAfterReceipt {
    fn new(
        operation: TiktokInsightOperation,
        scope: TiktokInsightScope,
        requested_cursor: Option<i64>,
        token_generation: u64,
        response: &ProviderResponse,
    ) -> Result<Self, TiktokInsightError> {
        let retry_after_seconds = response
            .header("retry-after")
            .and_then(|value| value.parse::<u64>().ok());
        let provider_reset_at = response
            .header("x-ratelimit-reset")
            .or_else(|| response.header("x-rate-limit-reset"))
            .and_then(|value| value.parse::<i64>().ok())
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
            .or_else(|| {
                retry_after_seconds.and_then(|seconds| {
                    i64::try_from(seconds).ok().and_then(|seconds| {
                        response
                            .observed_at()
                            .checked_add_signed(Duration::seconds(seconds))
                    })
                })
            });
        if provider_reset_at.is_some_and(|reset| reset <= response.observed_at())
            || !is_sha256(&response.body_digest())
        {
            return Err(TiktokInsightError::InvalidResponse("rate-limit reset"));
        }
        Ok(Self {
            provider: ProviderId::Tiktok,
            operation,
            scope,
            requested_cursor,
            token_generation,
            observed_at: response.observed_at(),
            response_digest: response.body_digest(),
            retry_after_seconds,
            provider_reset_at,
        })
    }

    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    pub const fn operation(&self) -> TiktokInsightOperation {
        self.operation
    }

    pub const fn scope(&self) -> &TiktokInsightScope {
        &self.scope
    }

    pub const fn requested_cursor(&self) -> Option<i64> {
        self.requested_cursor
    }

    pub const fn token_generation(&self) -> u64 {
        self.token_generation
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub const fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }

    pub const fn provider_reset_at(&self) -> Option<DateTime<Utc>> {
        self.provider_reset_at
    }

    pub fn retry_is_due(&self, now: DateTime<Utc>) -> bool {
        self.provider_reset_at.is_some_and(|reset| now >= reset)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightWebhookEvidence {
    event_id: WebhookEventId,
    content: TiktokContentIdentity,
    revision: TiktokRevisionIdentity,
    occurred_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    classification: TiktokInsightModerationClassification,
    source_digest: String,
}

impl TiktokInsightWebhookEvidence {
    pub const fn event_id(&self) -> &WebhookEventId {
        &self.event_id
    }

    pub const fn content(&self) -> &TiktokContentIdentity {
        &self.content
    }

    pub const fn revision(&self) -> &TiktokRevisionIdentity {
        &self.revision
    }

    pub const fn occurred_at(&self) -> DateTime<Utc> {
        self.occurred_at
    }

    pub const fn received_at(&self) -> DateTime<Utc> {
        self.received_at
    }

    pub const fn classification(&self) -> TiktokInsightModerationClassification {
        self.classification
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokInsightInvalidationReason {
    CredentialRotated,
    CredentialRevoked,
    CredentialUnmounted,
    CredentialExpired,
    ScopeDrift,
    AuditStateDrift,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokInsightCheckpointPhase {
    Active,
    Complete,
    Invalidated {
        reason: TiktokInsightInvalidationReason,
        at: DateTime<Utc>,
    },
}

impl TiktokInsightCheckpointPhase {
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightPageReceipt {
    provider: ProviderId,
    scope: TiktokInsightScope,
    requested_cursor: Option<i64>,
    next_cursor: Option<i64>,
    page_digest: String,
    observation_count: usize,
    previous_source_digest: String,
    source_digest: String,
    observed_at: DateTime<Utc>,
    generation: u64,
}

impl TiktokInsightPageReceipt {
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    pub const fn scope(&self) -> &TiktokInsightScope {
        &self.scope
    }

    pub const fn requested_cursor(&self) -> Option<i64> {
        self.requested_cursor
    }

    pub const fn next_cursor(&self) -> Option<i64> {
        self.next_cursor
    }

    pub fn page_digest(&self) -> &str {
        &self.page_digest
    }

    pub const fn observation_count(&self) -> usize {
        self.observation_count
    }

    pub fn previous_source_digest(&self) -> &str {
        &self.previous_source_digest
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightDuplicatePageReceipt {
    provider: ProviderId,
    scope: TiktokInsightScope,
    requested_cursor: Option<i64>,
    page_digest: String,
    original_generation: u64,
    observed_at: DateTime<Utc>,
}

impl TiktokInsightDuplicatePageReceipt {
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    pub const fn scope(&self) -> &TiktokInsightScope {
        &self.scope
    }

    pub const fn requested_cursor(&self) -> Option<i64> {
        self.requested_cursor
    }

    pub fn page_digest(&self) -> &str {
        &self.page_digest
    }

    pub const fn original_generation(&self) -> u64 {
        self.original_generation
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TiktokInsightPageApply {
    Applied(TiktokInsightPageReceipt),
    Duplicate(TiktokInsightDuplicatePageReceipt),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightCheckpoint {
    scope: TiktokInsightScope,
    page_size: u8,
    phase: TiktokInsightCheckpointPhase,
    audit_state: TiktokAuditState,
    token_generation: u64,
    secret_reference_digest: String,
    scope_digest: String,
    probe: Option<TiktokAuthenticatedCreatorProbe>,
    next_cursor: Option<i64>,
    has_more: bool,
    initial_source_digest: String,
    source_digest: String,
    last_page_digest: Option<String>,
    last_observed_at: DateTime<Utc>,
    accepted_pages: Vec<TiktokInsightPageReceipt>,
    observations: Vec<TiktokInsightContentObservation>,
    quota_reservations: Vec<TiktokInsightQuotaReservation>,
    retry_after: Option<TiktokRetryAfterReceipt>,
    webhook_event_ids: BTreeSet<WebhookEventId>,
    webhook_latest_by_content: BTreeMap<TiktokContentIdentity, DateTime<Utc>>,
    webhook_evidence: Vec<TiktokInsightWebhookEvidence>,
}

impl TiktokInsightCheckpoint {
    pub fn new(
        scope: TiktokInsightScope,
        page_size: u8,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) -> Result<Self, TiktokInsightError> {
        if !(1..=TIKTOK_INSIGHT_DEFAULT_PAGE_SIZE).contains(&page_size) {
            return Err(TiktokInsightError::InvalidRequest(
                "TikTok page size must be between 1 and 20",
            ));
        }
        credential.require_for(TiktokInsightOperation::AuthenticatedProbe, &scope, now)?;
        let source_digest = sha256_json(&serde_json::json!({
            "provider": ProviderId::Tiktok,
            "app": scope.app(),
            "account": scope.account(),
            "creator": scope.creator(),
            "page_size": page_size,
            "token_generation": credential.token_generation(),
            "secret_reference_digest": credential.secret_reference_digest(),
            "scope_digest": credential.scope_digest(),
        }));
        Ok(Self {
            scope,
            page_size,
            phase: TiktokInsightCheckpointPhase::Active,
            audit_state: credential.authorization().audit_state(),
            token_generation: credential.token_generation(),
            secret_reference_digest: credential.secret_reference_digest(),
            scope_digest: credential.scope_digest(),
            probe: None,
            next_cursor: None,
            has_more: true,
            initial_source_digest: source_digest.clone(),
            source_digest,
            last_page_digest: None,
            last_observed_at: now,
            accepted_pages: Vec::new(),
            observations: Vec::new(),
            quota_reservations: Vec::new(),
            retry_after: None,
            webhook_event_ids: BTreeSet::new(),
            webhook_latest_by_content: BTreeMap::new(),
            webhook_evidence: Vec::new(),
        })
    }

    pub const fn scope(&self) -> &TiktokInsightScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u8 {
        self.page_size
    }

    pub const fn phase(&self) -> &TiktokInsightCheckpointPhase {
        &self.phase
    }

    pub const fn token_generation(&self) -> u64 {
        self.token_generation
    }

    pub fn secret_reference_digest(&self) -> &str {
        &self.secret_reference_digest
    }

    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn probe(&self) -> Option<&TiktokAuthenticatedCreatorProbe> {
        self.probe.as_ref()
    }

    pub const fn next_cursor(&self) -> Option<i64> {
        self.next_cursor
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub fn initial_source_digest(&self) -> &str {
        &self.initial_source_digest
    }

    pub fn last_page_digest(&self) -> Option<&str> {
        self.last_page_digest.as_deref()
    }

    pub const fn last_observed_at(&self) -> DateTime<Utc> {
        self.last_observed_at
    }

    pub fn accepted_pages(&self) -> &[TiktokInsightPageReceipt] {
        &self.accepted_pages
    }

    pub fn observations(&self) -> &[TiktokInsightContentObservation] {
        &self.observations
    }

    pub fn quota_reservations(&self) -> &[TiktokInsightQuotaReservation] {
        &self.quota_reservations
    }

    pub const fn retry_after(&self) -> Option<&TiktokRetryAfterReceipt> {
        self.retry_after.as_ref()
    }

    pub fn webhook_evidence(&self) -> &[TiktokInsightWebhookEvidence] {
        &self.webhook_evidence
    }

    pub fn durable_digest(&self) -> String {
        sha256_json(&self.durable_value())
    }

    pub fn checkpoint_json(&self) -> Result<String, TiktokInsightError> {
        serde_json::to_string(self)
            .map_err(|_| TiktokInsightError::InvalidResponse("checkpoint serialization"))
    }

    pub fn from_checkpoint_json(value: &str) -> Result<Self, TiktokInsightError> {
        let checkpoint = serde_json::from_str::<Self>(value)
            .map_err(|_| TiktokInsightError::InvalidResponse("checkpoint serialization"))?;
        checkpoint.validate_durable()?;
        Ok(checkpoint)
    }

    pub fn bind(
        &mut self,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) -> Result<(), TiktokInsightError> {
        if credential.token_generation() != self.token_generation {
            self.invalidate(TiktokInsightInvalidationReason::CredentialRotated, now);
            return Err(TiktokInsightError::CredentialRotated);
        }
        if credential.secret_reference_digest() != self.secret_reference_digest {
            self.invalidate(TiktokInsightInvalidationReason::CredentialRotated, now);
            return Err(TiktokInsightError::CredentialRotated);
        }
        if credential.authorization().audit_state() != self.audit_state {
            self.invalidate(TiktokInsightInvalidationReason::AuditStateDrift, now);
            return Err(TiktokInsightError::ScopeMismatch);
        }
        if credential.scope_digest() != self.scope_digest {
            self.invalidate(TiktokInsightInvalidationReason::ScopeDrift, now);
            return Err(TiktokInsightError::ScopeMismatch);
        }
        if let Err(error) =
            credential.require_for(TiktokInsightOperation::VideoList, &self.scope, now)
        {
            let reason = match error {
                TiktokInsightError::CredentialRevoked => {
                    TiktokInsightInvalidationReason::CredentialRevoked
                }
                TiktokInsightError::CredentialUnmounted => {
                    TiktokInsightInvalidationReason::CredentialUnmounted
                }
                TiktokInsightError::CredentialExpired => {
                    TiktokInsightInvalidationReason::CredentialExpired
                }
                _ => TiktokInsightInvalidationReason::ScopeDrift,
            };
            self.invalidate(reason, now);
            return Err(error);
        }
        if !self.phase.is_active() && !self.phase.is_complete() {
            return Err(TiktokInsightError::CursorDrift);
        }
        Ok(())
    }

    pub fn invalidate_for_credential(
        &mut self,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) {
        let reason = if credential.token_generation() != self.token_generation
            || credential.secret_reference_digest() != self.secret_reference_digest
        {
            TiktokInsightInvalidationReason::CredentialRotated
        } else if credential.revoked_at().is_some_and(|at| at <= now) {
            TiktokInsightInvalidationReason::CredentialRevoked
        } else if credential.unmounted_at().is_some_and(|at| at <= now) {
            TiktokInsightInvalidationReason::CredentialUnmounted
        } else if credential.authorization().audit_state() != self.audit_state {
            TiktokInsightInvalidationReason::AuditStateDrift
        } else {
            TiktokInsightInvalidationReason::ScopeDrift
        };
        self.invalidate(reason, now);
    }

    fn invalidate(&mut self, reason: TiktokInsightInvalidationReason, at: DateTime<Utc>) {
        self.phase = TiktokInsightCheckpointPhase::Invalidated { reason, at };
        self.retry_after = None;
    }

    pub fn record_probe(
        &mut self,
        probe: TiktokAuthenticatedCreatorProbe,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) -> Result<(), TiktokInsightError> {
        self.bind(credential, now)?;
        probe.validate_at(&self.scope, self.token_generation, now)?;
        if probe.observed_at() < self.last_observed_at {
            return Err(TiktokInsightError::LateResponse {
                observed_at: probe.observed_at(),
                last_observed_at: self.last_observed_at,
            });
        }
        self.last_observed_at = probe.observed_at();
        self.probe = Some(probe);
        Ok(())
    }

    pub fn apply_retry_after(
        &mut self,
        receipt: TiktokRetryAfterReceipt,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) -> Result<(), TiktokInsightError> {
        self.bind(credential, now)?;
        if receipt.provider() != ProviderId::Tiktok
            || receipt.scope() != &self.scope
            || receipt.token_generation() != self.token_generation
            || receipt.requested_cursor() != self.next_cursor
        {
            return Err(TiktokInsightError::CursorDrift);
        }
        if receipt.observed_at() < self.last_observed_at {
            return Err(TiktokInsightError::LateResponse {
                observed_at: receipt.observed_at(),
                last_observed_at: self.last_observed_at,
            });
        }
        self.last_observed_at = receipt.observed_at();
        self.retry_after = Some(receipt);
        Ok(())
    }

    pub fn retry_is_due(&self, now: DateTime<Utc>) -> bool {
        self.retry_after
            .as_ref()
            .is_some_and(|receipt| receipt.retry_is_due(now))
    }

    #[allow(clippy::too_many_lines)]
    pub fn apply_page(
        &mut self,
        page: &TiktokInsightPage,
        quota: TiktokInsightQuotaReservation,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightPageApply, TiktokInsightError> {
        self.bind(credential, now)?;
        page.validate(&self.scope, self.token_generation)?;
        if let Some(receipt) = self
            .accepted_pages
            .iter()
            .find(|receipt| receipt.requested_cursor() == page.requested_cursor())
        {
            if receipt.page_digest() == page.page_digest() {
                return Ok(TiktokInsightPageApply::Duplicate(
                    TiktokInsightDuplicatePageReceipt {
                        provider: ProviderId::Tiktok,
                        scope: self.scope.clone(),
                        requested_cursor: page.requested_cursor(),
                        page_digest: page.page_digest().to_owned(),
                        original_generation: receipt.generation(),
                        observed_at: page.observed_at(),
                    },
                ));
            }
            return Err(TiktokInsightError::CursorDrift);
        }
        if self.phase.is_complete() || !self.has_more {
            return Err(TiktokInsightError::CursorExhausted);
        }
        if page.requested_cursor() != self.next_cursor {
            return Err(TiktokInsightError::CursorDrift);
        }
        if page.observed_at() < self.last_observed_at {
            return Err(TiktokInsightError::LateResponse {
                observed_at: page.observed_at(),
                last_observed_at: self.last_observed_at,
            });
        }
        if let Some(previous) = self.observations.last()
            && page
                .observations()
                .first()
                .is_some_and(|current| current.sort_key() >= previous.sort_key())
        {
            return Err(TiktokInsightError::CursorDrift);
        }
        if quota.operation() != TiktokInsightOperation::VideoList
            || quota.observed_at() != page.observed_at()
        {
            return Err(TiktokInsightError::InvalidRequest(
                "TikTok page quota fence does not match response",
            ));
        }
        let known_ids = self
            .observations
            .iter()
            .map(|observation| observation.identity().video_id().clone())
            .collect::<BTreeSet<_>>();
        if page
            .observations()
            .iter()
            .any(|observation| known_ids.contains(observation.identity().video_id()))
        {
            return Err(TiktokInsightError::CursorDrift);
        }
        let generation = u64::try_from(self.accepted_pages.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(TiktokInsightError::CursorDrift)?;
        let previous_source_digest = self.source_digest.clone();
        let source_digest = sha256_json(&serde_json::json!({
            "previous": previous_source_digest,
            "page": page.page_digest(),
            "requested_cursor": page.requested_cursor(),
            "next_cursor": page.next_cursor(),
            "generation": generation,
            "observed_at": page.observed_at(),
            "video_ids": page
                .observations()
                .iter()
                .map(|observation| observation.identity().video_id().as_str())
                .collect::<Vec<_>>(),
        }));
        let receipt = TiktokInsightPageReceipt {
            provider: ProviderId::Tiktok,
            scope: self.scope.clone(),
            requested_cursor: page.requested_cursor(),
            next_cursor: page.next_cursor(),
            page_digest: page.page_digest().to_owned(),
            observation_count: page.observations().len(),
            previous_source_digest,
            source_digest: source_digest.clone(),
            observed_at: page.observed_at(),
            generation,
        };
        self.source_digest = source_digest;
        self.last_page_digest = Some(page.page_digest().to_owned());
        self.last_observed_at = page.observed_at();
        self.next_cursor = page.next_cursor();
        self.has_more = page.has_more();
        self.accepted_pages.push(receipt.clone());
        self.observations
            .extend(page.observations().iter().cloned());
        self.quota_reservations.push(quota);
        self.retry_after = None;
        if !self.has_more {
            self.phase = TiktokInsightCheckpointPhase::Complete;
        }
        Ok(TiktokInsightPageApply::Applied(receipt))
    }

    pub fn ingest_webhook(&mut self, event: &WebhookEnvelope) -> Result<(), TiktokInsightError> {
        if event.provider() != ProviderId::Tiktok {
            return Err(TiktokInsightError::IdentityMismatch);
        }
        if self.webhook_event_ids.contains(event.event_id()) {
            return Err(TiktokInsightError::DuplicateWebhook);
        }
        let (content, revision) = match (event.content(), event.revision()) {
            (ContentIdentity::Tiktok(content), RevisionIdentity::Tiktok(revision))
                if revision.content() == event.content() =>
            {
                (content, revision)
            }
            _ => return Err(TiktokInsightError::IdentityMismatch),
        };
        if content.creator_open_id() != self.scope.account().open_id()
            || revision.content() != event.content()
        {
            return Err(TiktokInsightError::IdentityMismatch);
        }
        if self
            .webhook_latest_by_content
            .get(content)
            .is_some_and(|latest| event.occurred_at() < *latest)
            || event.occurred_at() < self.last_observed_at
            || event.received_at() < self.last_observed_at
        {
            return Err(TiktokInsightError::OutOfOrderWebhook);
        }
        let source_digest = sha256_json(&serde_json::json!({
            "event_id": event.event_id(),
            "provider": event.provider(),
            "content": event.content(),
            "revision": event.revision(),
            "occurred_at": event.occurred_at(),
            "received_at": event.received_at(),
        }));
        self.webhook_event_ids.insert(event.event_id().clone());
        self.webhook_latest_by_content
            .insert(content.clone(), event.occurred_at());
        self.webhook_evidence.push(TiktokInsightWebhookEvidence {
            event_id: event.event_id().clone(),
            content: content.clone(),
            revision: revision.clone(),
            occurred_at: event.occurred_at(),
            received_at: event.received_at(),
            classification: webhook_classification(revision.state_key()),
            source_digest,
        });
        self.last_observed_at = self.last_observed_at.max(event.received_at());
        Ok(())
    }

    fn durable_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}))
    }

    fn validate_durable(&self) -> Result<(), TiktokInsightError> {
        if self.provider_is_valid()
            && self.page_size >= 1
            && self.page_size <= TIKTOK_INSIGHT_DEFAULT_PAGE_SIZE
            && self.token_generation > 0
            && is_sha256(&self.secret_reference_digest)
            && is_sha256(&self.scope_digest)
            && is_sha256(&self.initial_source_digest)
            && is_sha256(&self.source_digest)
            && self.last_page_digest.as_deref().is_none_or(is_sha256)
            && self.accepted_pages.len() == self.observations_page_count()
            && self.observations.len()
                == self
                    .accepted_pages
                    .iter()
                    .map(TiktokInsightPageReceipt::observation_count)
                    .sum::<usize>()
            && self.webhook_event_ids.len() == self.webhook_evidence.len()
        {
            let mut previous_cursor = None;
            let mut previous_source = self.initial_source_digest.as_str();
            let mut previous_observed_at = None;
            for (index, receipt) in self.accepted_pages.iter().enumerate() {
                if receipt.provider() != ProviderId::Tiktok
                    || receipt.scope() != &self.scope
                    || receipt.generation() != u64::try_from(index + 1).unwrap_or_default()
                    || receipt.requested_cursor() != previous_cursor
                    || receipt.previous_source_digest() != previous_source
                    || !is_sha256(receipt.page_digest())
                    || !is_sha256(receipt.previous_source_digest())
                    || !is_sha256(receipt.source_digest())
                    || previous_observed_at
                        .is_some_and(|observed_at| receipt.observed_at() < observed_at)
                {
                    return Err(TiktokInsightError::CursorDrift);
                }
                previous_cursor = receipt.next_cursor();
                previous_source = receipt.source_digest();
                previous_observed_at = Some(receipt.observed_at());
            }
            if previous_source != self.source_digest
                || previous_cursor != self.next_cursor
                || (!self.accepted_pages.is_empty() && self.has_more != self.next_cursor.is_some())
            {
                return Err(TiktokInsightError::CursorDrift);
            }
            let mut event_ids = BTreeSet::new();
            let mut latest_by_content: BTreeMap<TiktokContentIdentity, DateTime<Utc>> =
                BTreeMap::new();
            for evidence in &self.webhook_evidence {
                if !event_ids.insert(evidence.event_id().clone())
                    || !self.webhook_event_ids.contains(evidence.event_id())
                    || evidence.content().creator_open_id() != self.scope.account().open_id()
                    || evidence.revision().content()
                        != &ContentIdentity::Tiktok(evidence.content().clone())
                    || !is_sha256(evidence.source_digest())
                    || evidence.received_at() < evidence.occurred_at()
                {
                    return Err(TiktokInsightError::CursorDrift);
                }
                latest_by_content
                    .entry(evidence.content().clone())
                    .and_modify(|latest| *latest = (*latest).max(evidence.occurred_at()))
                    .or_insert(evidence.occurred_at());
            }
            if latest_by_content != self.webhook_latest_by_content {
                return Err(TiktokInsightError::CursorDrift);
            }
            return Ok(());
        }
        Err(TiktokInsightError::CursorDrift)
    }

    fn observations_page_count(&self) -> usize {
        self.accepted_pages
            .windows(2)
            .map(|pair| usize::from(pair[0].next_cursor() == pair[1].requested_cursor()))
            .sum::<usize>()
            .saturating_add(self.accepted_pages.first().map_or(0, |_| 1))
    }

    fn provider_is_valid(&self) -> bool {
        self.scope.provider() == ProviderId::Tiktok
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightReadResult {
    provider: ProviderId,
    scope: TiktokInsightScope,
    account: TiktokAccountIdentity,
    creator: TiktokCreatorIdentity,
    token_generation: u64,
    audit_state: TiktokAuditState,
    sequence_generation: u64,
    requested_cursor: Option<i64>,
    next_cursor: Option<i64>,
    has_more: bool,
    sequence_complete: bool,
    page_digest: String,
    probe: TiktokAuthenticatedCreatorProbe,
    observations: Vec<TiktokInsightContentObservation>,
    all_observations: Vec<TiktokInsightContentObservation>,
    freshness: TiktokInsightFreshness,
    quota: TiktokInsightQuotaReservation,
    source_digest: String,
    observed_at: DateTime<Utc>,
    provenance: TiktokInsightProvenance,
    webhook_evidence: Vec<TiktokInsightWebhookEvidence>,
}

impl TiktokInsightReadResult {
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    pub const fn scope(&self) -> &TiktokInsightScope {
        &self.scope
    }

    pub const fn account(&self) -> &TiktokAccountIdentity {
        &self.account
    }

    pub const fn creator(&self) -> &TiktokCreatorIdentity {
        &self.creator
    }

    pub const fn token_generation(&self) -> u64 {
        self.token_generation
    }

    pub const fn audit_state(&self) -> TiktokAuditState {
        self.audit_state
    }

    pub const fn sequence_generation(&self) -> u64 {
        self.sequence_generation
    }

    pub const fn requested_cursor(&self) -> Option<i64> {
        self.requested_cursor
    }

    pub const fn next_cursor(&self) -> Option<i64> {
        self.next_cursor
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    pub const fn sequence_complete(&self) -> bool {
        self.sequence_complete
    }

    pub fn page_digest(&self) -> &str {
        &self.page_digest
    }

    pub const fn probe(&self) -> &TiktokAuthenticatedCreatorProbe {
        &self.probe
    }

    pub fn observations(&self) -> &[TiktokInsightContentObservation] {
        &self.observations
    }

    pub fn all_observations(&self) -> &[TiktokInsightContentObservation] {
        &self.all_observations
    }

    pub const fn freshness(&self) -> TiktokInsightFreshness {
        self.freshness
    }

    pub const fn quota(&self) -> &TiktokInsightQuotaReservation {
        &self.quota
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn provenance(&self) -> TiktokInsightProvenance {
        self.provenance
    }

    pub fn webhook_evidence(&self) -> &[TiktokInsightWebhookEvidence] {
        &self.webhook_evidence
    }

    fn validate_for(
        &self,
        scope: &TiktokInsightScope,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) -> Result<(), TiktokInsightError> {
        if self.provider != ProviderId::Tiktok
            || self.scope != *scope
            || self.account != *scope.account()
            || self.creator != *scope.creator()
            || self.token_generation != credential.token_generation()
            || self.audit_state != credential.authorization().audit_state()
            || !is_sha256(&self.page_digest)
            || !is_sha256(&self.source_digest)
            || self.probe.scope() != scope
            || self.probe.token_generation() != self.token_generation
            || self.has_more != self.next_cursor.is_some()
            || self.sequence_complete == self.has_more
            || self.freshness.token_generation() != self.token_generation
            || self.quota.operation() != TiktokInsightOperation::VideoList
        {
            return Err(TiktokInsightError::MissionCapabilityMismatch);
        }
        if self
            .all_observations
            .iter()
            .any(|observation| observation.identity().account() != scope.account())
        {
            return Err(TiktokInsightError::RevisionMismatch);
        }
        self.probe.validate_at(scope, self.token_generation, now)?;
        if self.probe.quota().is_none() {
            return Err(TiktokInsightError::MissionCapabilityMismatch);
        }
        self.freshness.validate_at(now)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokInsightModerationResult {
    provider: ProviderId,
    scope: TiktokInsightScope,
    content: TiktokContentIdentity,
    revision: TiktokRevisionIdentity,
    classification: TiktokInsightModerationClassification,
    status: TiktokContentStatus,
    audit_state: TiktokAuditState,
    token_generation: u64,
    freshness: TiktokInsightFreshness,
    quota: TiktokInsightQuotaReservation,
    source_digest: String,
    observed_at: DateTime<Utc>,
    provenance: TiktokInsightProvenance,
}

impl TiktokInsightModerationResult {
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    pub const fn scope(&self) -> &TiktokInsightScope {
        &self.scope
    }

    pub const fn content(&self) -> &TiktokContentIdentity {
        &self.content
    }

    pub const fn revision(&self) -> &TiktokRevisionIdentity {
        &self.revision
    }

    pub const fn classification(&self) -> TiktokInsightModerationClassification {
        self.classification
    }

    pub const fn status(&self) -> TiktokContentStatus {
        self.status
    }

    pub const fn audit_state(&self) -> TiktokAuditState {
        self.audit_state
    }

    pub const fn token_generation(&self) -> u64 {
        self.token_generation
    }

    pub const fn freshness(&self) -> TiktokInsightFreshness {
        self.freshness
    }

    pub const fn quota(&self) -> &TiktokInsightQuotaReservation {
        &self.quota
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn provenance(&self) -> TiktokInsightProvenance {
        self.provenance
    }

    fn with_quota(mut self, quota: TiktokInsightQuotaReservation) -> Self {
        self.quota = quota;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TiktokInsightReadDispatch {
    Applied(TiktokInsightReadResult),
    Duplicate(TiktokInsightDuplicatePageReceipt),
    RetryAfter(TiktokRetryAfterReceipt),
    Retryable {
        operation: TiktokInsightOperation,
        checkpoint_digest: String,
    },
    AlreadyComplete(TiktokInsightReadResult),
}

pub trait TiktokInsightProvider {
    fn provenance(&self) -> TiktokInsightProvenance;

    fn authenticated_probe(
        &mut self,
        credential: &TiktokInsightCredential,
        scope: &TiktokInsightScope,
        policy: &TiktokInsightFreshnessPolicy,
        now: DateTime<Utc>,
    ) -> Result<TiktokAuthenticatedCreatorProbe, TiktokInsightError>;

    fn list_page(
        &mut self,
        credential: &TiktokInsightCredential,
        scope: &TiktokInsightScope,
        page_size: u8,
        requested_cursor: Option<i64>,
        policy: &TiktokInsightFreshnessPolicy,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightPage, TiktokInsightError>;

    fn content_status(
        &mut self,
        credential: &TiktokInsightCredential,
        scope: &TiktokInsightScope,
        publish_id: TiktokPublishId,
        policy: &TiktokInsightFreshnessPolicy,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightModerationResult, TiktokInsightError>;
}

#[derive(Clone, Debug)]
pub struct ChannelInsightReadService<P> {
    provider: P,
    quota: TiktokInsightQuotaLedger,
    freshness: TiktokInsightFreshnessPolicy,
}

impl<P> ChannelInsightReadService<P> {
    pub fn new(
        provider: P,
        quota: TiktokInsightQuotaLedger,
        freshness: TiktokInsightFreshnessPolicy,
    ) -> Self {
        Self {
            provider,
            quota,
            freshness,
        }
    }

    pub const fn provider(&self) -> &P {
        &self.provider
    }

    pub const fn quota(&self) -> &TiktokInsightQuotaLedger {
        &self.quota
    }

    pub const fn freshness(&self) -> &TiktokInsightFreshnessPolicy {
        &self.freshness
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }
}

impl<P: TiktokInsightProvider> ChannelInsightReadService<P> {
    pub fn probe(
        &mut self,
        credential: &TiktokInsightCredential,
        scope: &TiktokInsightScope,
        now: DateTime<Utc>,
    ) -> Result<TiktokAuthenticatedCreatorProbe, TiktokInsightError> {
        credential.require_for(TiktokInsightOperation::AuthenticatedProbe, scope, now)?;
        let quota = self
            .quota
            .reserve(TiktokInsightOperation::AuthenticatedProbe, now)?;
        self.provider
            .authenticated_probe(credential, scope, &self.freshness, now)
            .map(|probe| probe.with_quota(quota))
    }

    pub fn start_checkpoint(
        &self,
        credential: &TiktokInsightCredential,
        scope: TiktokInsightScope,
        page_size: u8,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightCheckpoint, TiktokInsightError> {
        TiktokInsightCheckpoint::new(scope, page_size, credential, now)
    }

    pub fn read_next(
        &mut self,
        checkpoint: &mut TiktokInsightCheckpoint,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightReadDispatch, TiktokInsightError> {
        checkpoint.bind(credential, now)?;
        if let Some(retry) = checkpoint.retry_after()
            && !retry.retry_is_due(now)
        {
            return Ok(TiktokInsightReadDispatch::RetryAfter(retry.clone()));
        }
        if checkpoint.phase().is_complete() {
            let result = self.result_from_checkpoint(checkpoint, credential, now)?;
            return Ok(TiktokInsightReadDispatch::AlreadyComplete(result));
        }
        if checkpoint.probe().is_none() {
            let probe = self.probe(credential, checkpoint.scope(), now)?;
            checkpoint.record_probe(probe, credential, now)?;
        }
        let requested_cursor = checkpoint.next_cursor();
        let quota = self.quota.reserve(TiktokInsightOperation::VideoList, now)?;
        let page = match self.provider.list_page(
            credential,
            checkpoint.scope(),
            checkpoint.page_size(),
            requested_cursor,
            &self.freshness,
            now,
        ) {
            Ok(page) => page,
            Err(TiktokInsightError::RateLimited { receipt }) => {
                checkpoint.apply_retry_after(*receipt, credential, now)?;
                return Ok(TiktokInsightReadDispatch::RetryAfter(
                    checkpoint
                        .retry_after()
                        .expect("retry receipt was stored")
                        .clone(),
                ));
            }
            Err(TiktokInsightError::Disconnected) => {
                return Ok(TiktokInsightReadDispatch::Retryable {
                    operation: TiktokInsightOperation::VideoList,
                    checkpoint_digest: checkpoint.durable_digest(),
                });
            }
            Err(error) => return Err(error),
        };
        match checkpoint.apply_page(&page, quota, credential, now)? {
            TiktokInsightPageApply::Applied(_) => Ok(TiktokInsightReadDispatch::Applied(
                self.result_from_checkpoint(checkpoint, credential, now)?,
            )),
            TiktokInsightPageApply::Duplicate(receipt) => {
                Ok(TiktokInsightReadDispatch::Duplicate(receipt))
            }
        }
    }

    pub fn read_content_status(
        &mut self,
        credential: &TiktokInsightCredential,
        scope: &TiktokInsightScope,
        publish_id: TiktokPublishId,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightModerationResult, TiktokInsightError> {
        credential.require_for(TiktokInsightOperation::ContentStatus, scope, now)?;
        let quota = self
            .quota
            .reserve(TiktokInsightOperation::ContentStatus, now)?;
        let result =
            self.provider
                .content_status(credential, scope, publish_id, &self.freshness, now)?;
        Ok(result.with_quota(quota))
    }

    pub fn ingest_webhook(
        &self,
        checkpoint: &mut TiktokInsightCheckpoint,
        event: &WebhookEnvelope,
    ) -> Result<(), TiktokInsightError> {
        checkpoint.ingest_webhook(event)
    }

    fn result_from_checkpoint(
        &self,
        checkpoint: &TiktokInsightCheckpoint,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightReadResult, TiktokInsightError> {
        let probe = checkpoint
            .probe()
            .ok_or(TiktokInsightError::FreshnessUnavailable)?;
        probe.validate_at(checkpoint.scope(), credential.token_generation(), now)?;
        let receipt = checkpoint
            .accepted_pages()
            .last()
            .ok_or(TiktokInsightError::FreshnessUnavailable)?;
        let page_observations = checkpoint
            .observations()
            .iter()
            .filter(|observation| observation.observed_at() == receipt.observed_at())
            .cloned()
            .collect::<Vec<_>>();
        let freshness = TiktokInsightFreshness::new(
            receipt.observed_at(),
            self.freshness
                .valid_until(TiktokInsightOperation::VideoList, receipt.observed_at())?,
            credential.token_generation(),
        )?;
        let quota = checkpoint
            .quota_reservations()
            .last()
            .cloned()
            .ok_or(TiktokInsightError::FreshnessUnavailable)?;
        let result = TiktokInsightReadResult {
            provider: ProviderId::Tiktok,
            scope: checkpoint.scope().clone(),
            account: checkpoint.scope().account().clone(),
            creator: checkpoint.scope().creator().clone(),
            token_generation: credential.token_generation(),
            audit_state: credential.authorization().audit_state(),
            sequence_generation: receipt.generation(),
            requested_cursor: receipt.requested_cursor(),
            next_cursor: receipt.next_cursor(),
            has_more: checkpoint.has_more(),
            sequence_complete: checkpoint.phase().is_complete(),
            page_digest: receipt.page_digest().to_owned(),
            probe: probe.clone(),
            observations: page_observations,
            all_observations: checkpoint.observations().to_vec(),
            freshness,
            quota,
            source_digest: checkpoint.source_digest().to_owned(),
            observed_at: receipt.observed_at(),
            provenance: self.provider.provenance(),
            webhook_evidence: checkpoint.webhook_evidence().to_vec(),
        };
        result.validate_for(checkpoint.scope(), credential, now)?;
        Ok(result)
    }
}

#[derive(Clone, Debug)]
pub struct TiktokAuditedOAuthAdapter<T> {
    transport: T,
    provenance: TiktokInsightProvenance,
}

impl<T> TiktokAuditedOAuthAdapter<T> {
    pub fn new(transport: T, provenance: TiktokInsightProvenance) -> Self {
        Self {
            transport,
            provenance,
        }
    }

    pub fn fixture(transport: T) -> Self {
        Self::new(transport, TiktokInsightProvenance::Fixture)
    }

    pub fn controlled(transport: T) -> Self {
        Self::new(transport, TiktokInsightProvenance::ControlledProvider)
    }

    pub fn production(transport: T) -> Self {
        Self::new(transport, TiktokInsightProvenance::ProductionProvider)
    }

    pub const fn provenance(&self) -> TiktokInsightProvenance {
        self.provenance
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    fn send(
        &mut self,
        request: &ProviderReadRequest,
        operation: TiktokInsightOperation,
        scope: &TiktokInsightScope,
        requested_cursor: Option<i64>,
        token_generation: u64,
    ) -> Result<ProviderResponse, TiktokInsightError>
    where
        T: ReadOnlyTransport,
    {
        let response = self
            .transport
            .send(request)
            .map_err(|_| TiktokInsightError::Disconnected)?;
        if (200..300).contains(&response.status()) {
            return Ok(response);
        }
        let code = response
            .json(ProviderId::Tiktok)
            .ok()
            .and_then(|body| provider_error_code(&body));
        if response.status() == 429 {
            let receipt = TiktokRetryAfterReceipt::new(
                operation,
                scope.clone(),
                requested_cursor,
                token_generation,
                &response,
            )?;
            return Err(TiktokInsightError::RateLimited {
                receipt: Box::new(receipt),
            });
        }
        if response.status() == 401 {
            return Err(TiktokInsightError::CredentialRevoked);
        }
        if response.status() == 403
            && code
                .as_deref()
                .is_some_and(|value| value.contains("scope") || value.contains("auth"))
        {
            return Err(TiktokInsightError::Adapter(
                ChannelAdapterError::AuthorizationRequired {
                    provider: ProviderId::Tiktok,
                    reason: AuthorizationReason::MissingScope,
                },
            ));
        }
        if response.status() == 408 || response.status() >= 500 {
            return Err(TiktokInsightError::Disconnected);
        }
        Err(TiktokInsightError::ProviderRejected {
            status: response.status(),
            code,
        })
    }
}

impl<T: ReadOnlyTransport> TiktokInsightProvider for TiktokAuditedOAuthAdapter<T> {
    fn provenance(&self) -> TiktokInsightProvenance {
        self.provenance
    }

    fn authenticated_probe(
        &mut self,
        credential: &TiktokInsightCredential,
        scope: &TiktokInsightScope,
        policy: &TiktokInsightFreshnessPolicy,
        now: DateTime<Utc>,
    ) -> Result<TiktokAuthenticatedCreatorProbe, TiktokInsightError> {
        credential.require_for(TiktokInsightOperation::AuthenticatedProbe, scope, now)?;
        let url = Url::parse(&format!(
            "{TIKTOK_DISPLAY_API_BASE_URL}{TIKTOK_USER_INFO_PATH}?fields=open_id,display_name"
        ))
        .map_err(|_| TiktokInsightError::InvalidRequest("TikTok user info endpoint"))?;
        let request = ProviderReadRequest::new(
            ProviderId::Tiktok,
            ReadOperation::Probe,
            HttpMethod::Get,
            url,
            [ScopeName::new(TIKTOK_USER_INFO_BASIC_SCOPE)?],
            credential.secret_reference().clone(),
            None,
        )?;
        let response = self.send(
            &request,
            TiktokInsightOperation::AuthenticatedProbe,
            scope,
            None,
            credential.token_generation(),
        )?;
        let body = response.json(ProviderId::Tiktok)?;
        let user = body
            .pointer("/data/user")
            .or_else(|| body.get("data"))
            .ok_or(TiktokInsightError::InvalidResponse("data.user"))?;
        let open_id = user
            .get("open_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(TiktokInsightError::InvalidResponse("data.user.open_id"))?;
        let open_id = TiktokOpenId::new(open_id.to_owned())
            .map_err(|_| TiktokInsightError::InvalidResponse("data.user.open_id"))?;
        if open_id != *scope.account().open_id() {
            return Err(TiktokInsightError::IdentityMismatch);
        }
        if let Some(username) = user.get("username").and_then(serde_json::Value::as_str) {
            let username = crate::identity::TiktokCreatorUsername::new(username.to_owned())
                .map_err(|_| TiktokInsightError::InvalidResponse("data.user.username"))?;
            if username != *scope.creator().username() {
                return Err(TiktokInsightError::IdentityMismatch);
            }
        }
        let observed_at = response.observed_at();
        let freshness = TiktokInsightFreshness::new(
            observed_at,
            policy.valid_until(TiktokInsightOperation::AuthenticatedProbe, observed_at)?,
            credential.token_generation(),
        )?;
        Ok(TiktokAuthenticatedCreatorProbe {
            provider: ProviderId::Tiktok,
            scope: scope.clone(),
            account: scope.account().clone(),
            creator: scope.creator().clone(),
            token_generation: credential.token_generation(),
            audit_state: credential.authorization().audit_state(),
            response_digest: response.body_digest(),
            observed_at,
            freshness,
            provenance: self.provenance,
            quota: None,
        })
    }

    fn list_page(
        &mut self,
        credential: &TiktokInsightCredential,
        scope: &TiktokInsightScope,
        page_size: u8,
        requested_cursor: Option<i64>,
        policy: &TiktokInsightFreshnessPolicy,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightPage, TiktokInsightError> {
        credential.require_for(TiktokInsightOperation::VideoList, scope, now)?;
        if credential.authorization().audit_state() != TiktokAuditState::Approved {
            return Err(TiktokInsightError::UnauditedPrivateBoundary);
        }
        if !(1..=TIKTOK_INSIGHT_DEFAULT_PAGE_SIZE).contains(&page_size) {
            return Err(TiktokInsightError::InvalidRequest("TikTok page size"));
        }
        let url = Url::parse(&format!(
            "{TIKTOK_DISPLAY_API_BASE_URL}{TIKTOK_VIDEO_LIST_PATH}?fields=id,create_time,title,video_description,share_url,like_count,comment_count,share_count,view_count"
        ))
        .map_err(|_| TiktokInsightError::InvalidRequest("TikTok video list endpoint"))?;
        let mut request_body = serde_json::Map::new();
        request_body.insert(
            "max_count".to_owned(),
            serde_json::Value::from(u64::from(page_size)),
        );
        if let Some(cursor) = requested_cursor {
            if cursor <= 0 {
                return Err(TiktokInsightError::CursorDrift);
            }
            request_body.insert("cursor".to_owned(), serde_json::Value::from(cursor));
        }
        let request = ProviderReadRequest::new(
            ProviderId::Tiktok,
            ReadOperation::Analytics,
            HttpMethod::Post,
            url,
            [ScopeName::new(TIKTOK_VIDEO_LIST_SCOPE)?],
            credential.secret_reference().clone(),
            Some(serde_json::Value::Object(request_body)),
        )?;
        let response = self.send(
            &request,
            TiktokInsightOperation::VideoList,
            scope,
            requested_cursor,
            credential.token_generation(),
        )?;
        let body = response.json(ProviderId::Tiktok)?;
        let data = body
            .get("data")
            .ok_or(TiktokInsightError::InvalidResponse("data"))?;
        let videos = data
            .get("videos")
            .and_then(serde_json::Value::as_array)
            .ok_or(TiktokInsightError::InvalidResponse("data.videos"))?;
        let observations = videos
            .iter()
            .map(|video| parse_video_observation(scope, video, response.observed_at()))
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = data
            .get("has_more")
            .and_then(serde_json::Value::as_bool)
            .ok_or(TiktokInsightError::InvalidResponse("data.has_more"))?;
        let raw_cursor = data
            .get("cursor")
            .and_then(json_i64)
            .filter(|cursor| *cursor > 0);
        let next_cursor = if has_more { raw_cursor } else { None };
        if has_more && next_cursor.is_none() {
            return Err(TiktokInsightError::CursorDrift);
        }
        let observed_at = response.observed_at();
        let freshness = TiktokInsightFreshness::new(
            observed_at,
            policy.valid_until(TiktokInsightOperation::VideoList, observed_at)?,
            credential.token_generation(),
        )?;
        let page = TiktokInsightPage {
            scope: scope.clone(),
            requested_cursor,
            next_cursor,
            has_more,
            page_digest: response.body_digest(),
            observed_at,
            freshness,
            provenance: self.provenance,
            observations,
        };
        page.validate(scope, credential.token_generation())?;
        Ok(page)
    }

    fn content_status(
        &mut self,
        credential: &TiktokInsightCredential,
        scope: &TiktokInsightScope,
        publish_id: TiktokPublishId,
        policy: &TiktokInsightFreshnessPolicy,
        now: DateTime<Utc>,
    ) -> Result<TiktokInsightModerationResult, TiktokInsightError> {
        credential.require_for(TiktokInsightOperation::ContentStatus, scope, now)?;
        let request = crate::tiktok::content_status_request(
            credential.authorization(),
            &publish_id,
            credential.secret_reference().clone(),
        )?;
        let response = self.send(
            &request,
            TiktokInsightOperation::ContentStatus,
            scope,
            None,
            credential.token_generation(),
        )?;
        let observation =
            crate::tiktok::parse_content_status(credential.authorization(), publish_id, &response)?;
        if credential.authorization().audit_state() == TiktokAuditState::Unaudited
            && !observation.publicly_available_post_ids().is_empty()
        {
            return Err(TiktokInsightError::UnauditedPrivateBoundary);
        }
        let classification = match observation.moderation() {
            TiktokModerationState::PubliclyAvailable => {
                TiktokInsightModerationClassification::PubliclyAvailable
            }
            TiktokModerationState::NotPublic => {
                if credential.authorization().audit_state() == TiktokAuditState::Unaudited {
                    TiktokInsightModerationClassification::PrivateOnlyUnaudited
                } else {
                    TiktokInsightModerationClassification::NotPublic
                }
            }
            TiktokModerationState::NoLongerPublic => {
                TiktokInsightModerationClassification::NoLongerPublic
            }
            TiktokModerationState::Failed => TiktokInsightModerationClassification::Failed,
            TiktokModerationState::Unknown => TiktokInsightModerationClassification::Processing,
        };
        let observed_at = observation.observed_at();
        let freshness = TiktokInsightFreshness::new(
            observed_at,
            policy.valid_until(TiktokInsightOperation::ContentStatus, observed_at)?,
            credential.token_generation(),
        )?;
        let source_digest = response.body_digest();
        Ok(TiktokInsightModerationResult {
            provider: ProviderId::Tiktok,
            scope: scope.clone(),
            content: observation.identity().clone(),
            revision: observation.revision().clone(),
            classification,
            status: observation.status(),
            audit_state: credential.authorization().audit_state(),
            token_generation: credential.token_generation(),
            freshness,
            quota: TiktokInsightQuotaReservation {
                operation: TiktokInsightOperation::ContentStatus,
                cost: TiktokInsightOperation::ContentStatus.cost(),
                observed_at,
                remaining_in_window: 0,
            },
            source_digest,
            observed_at,
            provenance: self.provenance,
        })
    }
}

pub trait TiktokOAuthTokenSource {
    fn access_token(&mut self, reference: &CredentialReference) -> Result<String, TransportError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TiktokEnvironmentOAuthTokenSource;

impl TiktokOAuthTokenSource for TiktokEnvironmentOAuthTokenSource {
    fn access_token(&mut self, _reference: &CredentialReference) -> Result<String, TransportError> {
        let token = std::env::var(TIKTOK_REAL_INSIGHT_ACCESS_TOKEN_ENV)
            .map_err(|_| TransportError::Unavailable)?;
        if token.is_empty()
            || token.len() > 8192
            || token
                .chars()
                .any(|character| character.is_ascii_control() || matches!(character, '"' | '\\'))
        {
            return Err(TransportError::Unavailable);
        }
        Ok(token)
    }
}

#[derive(Clone)]
pub struct TiktokHttpsTransport<S> {
    token_source: S,
}

impl<S> fmt::Debug for TiktokHttpsTransport<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TiktokHttpsTransport")
            .field("token_source", &"<opaque>")
            .finish()
    }
}

impl<S> TiktokHttpsTransport<S> {
    pub const fn new(token_source: S) -> Self {
        Self { token_source }
    }

    pub fn token_source(&self) -> &S {
        &self.token_source
    }

    pub fn token_source_mut(&mut self) -> &mut S {
        &mut self.token_source
    }
}

impl<S: TiktokOAuthTokenSource> ReadOnlyTransport for TiktokHttpsTransport<S> {
    fn send(&mut self, request: &ProviderReadRequest) -> Result<ProviderResponse, TransportError> {
        if request.provider() != ProviderId::Tiktok
            || request.url().scheme() != "https"
            || request.url().host_str() != Some("open.tiktokapis.com")
        {
            return Err(TransportError::Unavailable);
        }
        let token = self.token_source.access_token(request.credential())?;
        let body = request
            .body()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| TransportError::Unavailable)?;
        let mut command = Command::new("curl");
        command
            .arg("--silent")
            .arg("--show-error")
            .arg("--config")
            .arg("-")
            .arg("--request")
            .arg(request.method().to_string())
            .arg("--dump-header")
            .arg("-")
            .arg("--write-out")
            .arg("\n__HARTEVO_TIKTOK_STATUS__%{http_code}")
            .arg("--connect-timeout")
            .arg("15")
            .arg("--max-time")
            .arg("60");
        if let Some(body) = body {
            command.arg("--data-raw").arg(body);
        }
        command.arg(request.url().as_str());
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| TransportError::Unavailable)?;
        if let Some(mut stdin) = child.stdin.take() {
            let config = format!(
                "header = \"Authorization: Bearer {token}\"\nheader = \"Accept: application/json\"\nheader = \"Content-Type: application/json\"\n"
            );
            stdin
                .write_all(config.as_bytes())
                .map_err(|_| TransportError::Unavailable)?;
        }
        let output = child
            .wait_with_output()
            .map_err(|_| TransportError::Unavailable)?;
        if !output.status.success() {
            return Err(TransportError::Unavailable);
        }
        parse_curl_response(&output.stdout)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TiktokRealInsightGate {
    secret_reference: CredentialReference,
}

impl TiktokRealInsightGate {
    pub fn from_env() -> Result<Self, TiktokInsightError> {
        let enabled = std::env::var(TIKTOK_REAL_INSIGHT_ENABLE_ENV).ok();
        let secret_reference = std::env::var(TIKTOK_REAL_INSIGHT_SECRET_REFERENCE_ENV).ok();
        let access_token = std::env::var(TIKTOK_REAL_INSIGHT_ACCESS_TOKEN_ENV).ok();
        Self::from_environment_values(
            enabled.as_deref(),
            secret_reference.as_deref(),
            access_token.as_deref(),
        )
    }

    pub fn from_environment_values(
        enabled: Option<&str>,
        secret_reference: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<Self, TiktokInsightError> {
        if enabled != Some("1") {
            return Err(TiktokInsightError::BlockedEnvironment {
                requirement: TIKTOK_REAL_INSIGHT_ENABLE_ENV,
            });
        }
        let secret_reference = secret_reference.ok_or(TiktokInsightError::BlockedEnvironment {
            requirement: TIKTOK_REAL_INSIGHT_SECRET_REFERENCE_ENV,
        })?;
        let access_token = access_token.ok_or(TiktokInsightError::BlockedEnvironment {
            requirement: TIKTOK_REAL_INSIGHT_ACCESS_TOKEN_ENV,
        })?;
        if access_token.is_empty()
            || access_token.len() > 8192
            || access_token
                .chars()
                .any(|character| character.is_ascii_control() || matches!(character, '"' | '\\'))
        {
            return Err(TiktokInsightError::BlockedEnvironment {
                requirement: TIKTOK_REAL_INSIGHT_ACCESS_TOKEN_ENV,
            });
        }
        let secret_reference = CredentialReference::new(secret_reference.to_owned())?;
        Ok(Self { secret_reference })
    }

    pub const fn secret_reference(&self) -> &CredentialReference {
        &self.secret_reference
    }
}

pub fn execute_real_channel_insight_probe(
    gate: &TiktokRealInsightGate,
    credential: &TiktokInsightCredential,
    scope: &TiktokInsightScope,
    now: DateTime<Utc>,
) -> Result<TiktokAuthenticatedCreatorProbe, TiktokInsightError> {
    if credential.secret_reference() != gate.secret_reference() {
        return Err(TiktokInsightError::CredentialRotated);
    }
    let transport = TiktokHttpsTransport::new(TiktokEnvironmentOAuthTokenSource);
    let mut adapter = TiktokAuditedOAuthAdapter::production(transport);
    adapter.authenticated_probe(
        credential,
        scope,
        &TiktokInsightFreshnessPolicy::default(),
        now,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TiktokMissionInsightCapability {
    scope: TiktokInsightScope,
    capability_revision: String,
}

impl TiktokMissionInsightCapability {
    pub fn new(
        scope: TiktokInsightScope,
        capability_revision: impl Into<String>,
    ) -> Result<Self, TiktokInsightError> {
        let capability_revision = capability_revision.into();
        if !is_sha256(&capability_revision) {
            return Err(TiktokInsightError::InvalidRequest(
                "Mission capability revision must be sha256",
            ));
        }
        Ok(Self {
            scope,
            capability_revision,
        })
    }

    pub const fn scope(&self) -> &TiktokInsightScope {
        &self.scope
    }

    pub fn capability_revision(&self) -> &str {
        &self.capability_revision
    }
}

#[derive(Clone, Debug)]
pub struct MissionTiktokInsightConsumer {
    capability: TiktokMissionInsightCapability,
}

impl MissionTiktokInsightConsumer {
    pub fn new(capability: TiktokMissionInsightCapability) -> Self {
        Self { capability }
    }

    pub const fn capability(&self) -> &TiktokMissionInsightCapability {
        &self.capability
    }

    pub fn accept(
        &self,
        result: TiktokInsightReadResult,
        credential: &TiktokInsightCredential,
        now: DateTime<Utc>,
    ) -> Result<TiktokMissionAcceptedInsight, TiktokInsightError> {
        if result.provenance() != TiktokInsightProvenance::ProductionProvider
            || result.audit_state() != TiktokAuditState::Approved
            || !result.sequence_complete()
            || result.scope() != self.capability.scope()
            || result.provider() != ProviderId::Tiktok
            || result.token_generation() != credential.token_generation()
            || result.source_digest().is_empty()
            || !is_sha256(result.source_digest())
        {
            return Err(TiktokInsightError::MissionCapabilityMismatch);
        }
        result.validate_for(self.capability.scope(), credential, now)?;
        if result.all_observations().iter().any(|observation| {
            observation.identity().account() != self.capability.scope().account()
        }) {
            return Err(TiktokInsightError::RevisionMismatch);
        }
        Ok(TiktokMissionAcceptedInsight {
            capability_revision: self.capability.capability_revision.clone(),
            result,
            adopted_at: now,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokMissionAcceptedInsight {
    capability_revision: String,
    result: TiktokInsightReadResult,
    adopted_at: DateTime<Utc>,
}

impl TiktokMissionAcceptedInsight {
    pub fn capability_revision(&self) -> &str {
        &self.capability_revision
    }

    pub const fn result(&self) -> &TiktokInsightReadResult {
        &self.result
    }

    pub const fn adopted_at(&self) -> DateTime<Utc> {
        self.adopted_at
    }
}

fn parse_video_observation(
    scope: &TiktokInsightScope,
    video: &serde_json::Value,
    observed_at: DateTime<Utc>,
) -> Result<TiktokInsightContentObservation, TiktokInsightError> {
    let video_id = video
        .get("id")
        .and_then(json_string_or_number)
        .ok_or(TiktokInsightError::InvalidResponse("data.videos[].id"))?;
    let video_id = TiktokInsightVideoId::new(video_id)?;
    let identity = TiktokInsightContentIdentity::new(scope.account().clone(), video_id);
    let revision = TiktokInsightRevision::new(identity.clone(), sha256_json(video), observed_at)?;
    let created_at = video
        .get("create_time")
        .and_then(json_i64)
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0));
    Ok(TiktokInsightContentObservation {
        identity,
        revision,
        created_at,
        title: json_string(video.get("title")),
        description: json_string(video.get("video_description")),
        share_url: json_string(video.get("share_url")),
        performance: TiktokInsightPerformance {
            like_count: json_u64(video.get("like_count")),
            comment_count: json_u64(video.get("comment_count")),
            share_count: json_u64(video.get("share_count")),
            view_count: json_u64(video.get("view_count")),
        },
        moderation: if scope.provider() == ProviderId::Tiktok {
            TiktokInsightModerationClassification::PubliclyAvailable
        } else {
            TiktokInsightModerationClassification::Unknown
        },
        observed_at,
    })
}

fn parse_curl_response(output: &[u8]) -> Result<ProviderResponse, TransportError> {
    const MARKER: &str = "__HARTEVO_TIKTOK_STATUS__";
    let output = String::from_utf8(output.to_vec()).map_err(|_| TransportError::Unavailable)?;
    let (payload, status) = output
        .rsplit_once(MARKER)
        .ok_or(TransportError::Unavailable)?;
    let status = status
        .trim()
        .parse::<u16>()
        .map_err(|_| TransportError::Unavailable)?;
    let body = payload
        .find("\r\n\r\n")
        .map(|index| &payload[index + 4..])
        .or_else(|| payload.find("\n\n").map(|index| &payload[index + 2..]))
        .ok_or(TransportError::Unavailable)?;
    let mut headers = Vec::new();
    let header_end = payload.find("\r\n\r\n").or_else(|| payload.find("\n\n"));
    if let Some(header_end) = header_end {
        let header_text = &payload[..header_end];
        for line in header_text.lines().skip(1) {
            if let Some((name, value)) = line.split_once(':')
                && (name.eq_ignore_ascii_case("retry-after")
                    || name.eq_ignore_ascii_case("x-ratelimit-reset")
                    || name.eq_ignore_ascii_case("x-rate-limit-reset"))
            {
                headers.push((name.to_owned(), value.trim().to_owned()));
            }
        }
    }
    Ok(ProviderResponse::new(status, headers, body, Utc::now()))
}

fn provider_error_code(body: &serde_json::Value) -> Option<String> {
    body.pointer("/error/code")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            body.pointer("/error/message")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_owned)
}

fn webhook_classification(state_key: &str) -> TiktokInsightModerationClassification {
    if state_key.contains("no_longer_public") {
        TiktokInsightModerationClassification::NoLongerPublic
    } else if state_key.contains("publicly_available") {
        TiktokInsightModerationClassification::PubliclyAvailable
    } else if state_key.contains("failed") {
        TiktokInsightModerationClassification::Failed
    } else {
        TiktokInsightModerationClassification::Unknown
    }
}

fn json_string(value: Option<&serde_json::Value>) -> Option<String> {
    value.and_then(serde_json::Value::as_str).map(str::to_owned)
}

fn json_string_or_number(value: &serde_json::Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_owned)
        .or_else(|| value.as_u64().map(|number| number.to_string()))
}

fn json_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse::<i64>().ok()))
}

fn json_u64(value: Option<&serde_json::Value>) -> Option<u64> {
    value.and_then(serde_json::Value::as_u64).or_else(|| {
        value
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse().ok())
    })
}

fn sha256_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex_digest(digest.finalize())
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
