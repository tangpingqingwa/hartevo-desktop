//! YouTube provider-specific controlled publish contracts.
//!
//! The provider boundary models the documented YouTube Data API resumable
//! upload flow, but this crate does not own the HTTP client, asset bytes,
//! credential store, or Effect authority. A transport implementation resolves
//! opaque references and returns typed provider observations.

use std::fmt::Write as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::transport::YouTubeSecretReference;

mod consumer;
mod effect;
mod provider;
mod service;
mod verification;

#[path = "../youtube.rs"]
mod read;

pub mod testkit;

pub use consumer::{MissionYouTubePublishConsumer, YouTubeMissionAcceptedPublish};
pub use effect::{
    YOUTUBE_PUBLISH_PLUGIN_ID, YOUTUBE_PUBLISH_PLUGIN_REVISION, YouTubeAuthorizedPublishEffect,
    YouTubeEffectId, YouTubePluginIdentity,
};
pub use provider::{
    YouTubeDataApiProvider, YouTubeHttpMethod, YouTubeProductionTransport, YouTubeProviderRequest,
    YouTubeProviderResponse, YouTubePublishTransport,
};
pub use read::{
    ANALYTICS_API_BASE_URL, DATA_API_BASE_URL, YOUTUBE_ANALYTICS_MONETARY_READONLY_SCOPE,
    YOUTUBE_ANALYTICS_READONLY_SCOPE, YOUTUBE_MANAGE_SCOPE, YOUTUBE_READONLY_SCOPE,
    YoutubeAnalyticsDimension, YoutubeAnalyticsMetric, YoutubeAnalyticsQuery,
    YoutubeChannelProbeObservation, YoutubeCommentModerationFilter, YoutubeCommentObservation,
    YoutubeModerationState, YoutubeQuotaEntry, YoutubeQuotaLedger, YoutubeQuotaOperation,
    YoutubeReadError, YoutubeReadObservation, YoutubeReadResult, YoutubeReadTarget, YoutubeScope,
    YoutubeVideoObservation, YoutubeVisibility, channel_identity_request, parse_channel_identity,
    parse_read_response,
};
pub use service::{YouTubePublishService, YouTubeRealPublishGate, execute_real_publish_gate};
pub use verification::{
    YouTubeEvidenceId, YouTubePublishOutcomeEvidence, YouTubePublishReceiptEvidence,
    YouTubePublishVerificationCheckpoint, YouTubePublishVerificationDispatchResult,
    YouTubePublishVerificationEvidence, YouTubePublishVerificationPhase,
    YouTubePublishVerificationService, YouTubeVerificationInvalidationReason,
    YouTubeVerificationStatus, execute_real_publish_verification_gate,
};

pub const YOUTUBE_API_BASE_URL: &str = "https://www.googleapis.com/youtube/v3";
pub const YOUTUBE_UPLOAD_BASE_URL: &str = "https://www.googleapis.com/upload/youtube/v3";
pub const REAL_PUBLISH_ENABLE_ENV: &str = "HARTEVO_YOUTUBE_REAL_PUBLISH";
pub const REAL_PUBLISH_SECRET_REFERENCE_ENV: &str = "HARTEVO_YOUTUBE_SECRET_REFERENCE";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeProviderId {
    YouTube,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YouTubeTenantId(String);

impl YouTubeTenantId {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        Ok(Self(valid_id(value.into(), "YouTube tenant", 128)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YouTubeBusinessId(String);

impl YouTubeBusinessId {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        Ok(Self(valid_id(value.into(), "YouTube business", 128)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YouTubeAccountId(String);

impl YouTubeAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        Ok(Self(valid_id(value.into(), "YouTube account", 256)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YouTubeChannelId(String);

impl YouTubeChannelId {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        Ok(Self(valid_id(value.into(), "YouTube channel", 128)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct YouTubeVideoId(String);

impl YouTubeVideoId {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        Ok(Self(valid_id(value.into(), "YouTube video", 128)?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_id(value: String, label: &'static str, max_len: usize) -> Result<String, YouTubeError> {
    if value.is_empty()
        || value.len() > max_len
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(YouTubeError::InvalidRequest(label));
    }
    Ok(value)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubePublishBinding {
    tenant_id: YouTubeTenantId,
    business_id: YouTubeBusinessId,
    account_id: YouTubeAccountId,
    channel_id: YouTubeChannelId,
    provider_generation: u64,
}

impl YouTubePublishBinding {
    pub fn new(
        tenant_id: YouTubeTenantId,
        business_id: YouTubeBusinessId,
        account_id: YouTubeAccountId,
        channel_id: YouTubeChannelId,
        provider_generation: u64,
    ) -> Result<Self, YouTubeError> {
        if provider_generation == 0 {
            return Err(YouTubeError::InvalidRequest(
                "YouTube provider generation must be positive",
            ));
        }
        Ok(Self {
            tenant_id,
            business_id,
            account_id,
            channel_id,
            provider_generation,
        })
    }

    pub const fn provider(&self) -> YouTubeProviderId {
        YouTubeProviderId::YouTube
    }

    pub const fn tenant_id(&self) -> &YouTubeTenantId {
        &self.tenant_id
    }

    pub const fn business_id(&self) -> &YouTubeBusinessId {
        &self.business_id
    }

    pub const fn account_id(&self) -> &YouTubeAccountId {
        &self.account_id
    }

    pub const fn channel_id(&self) -> &YouTubeChannelId {
        &self.channel_id
    }

    pub const fn provider_generation(&self) -> u64 {
        self.provider_generation
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeOAuthScope {
    YoutubeReadonly,
    YoutubeUpload,
}

impl YouTubeOAuthScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::YoutubeReadonly => "https://www.googleapis.com/auth/youtube.readonly",
            Self::YoutubeUpload => "https://www.googleapis.com/auth/youtube.upload",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeAssetDigest(String);

impl YouTubeAssetDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        let value = value.into();
        if !is_sha256(&value) {
            return Err(YouTubeError::InvalidRequest(
                "YouTube asset digest must be a SHA-256 hex digest",
            ));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex_digest(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeAssetDescriptor {
    digest: YouTubeAssetDigest,
    byte_length: u64,
    content_type: String,
}

impl YouTubeAssetDescriptor {
    pub fn new(
        digest: YouTubeAssetDigest,
        byte_length: u64,
        content_type: impl Into<String>,
    ) -> Result<Self, YouTubeError> {
        let content_type = content_type.into();
        if byte_length == 0
            || content_type.is_empty()
            || content_type.chars().any(char::is_whitespace)
            || !(content_type.starts_with("video/") || content_type == "application/octet-stream")
        {
            return Err(YouTubeError::InvalidRequest(
                "YouTube publish asset must be a non-empty video or octet-stream",
            ));
        }
        Ok(Self {
            digest,
            byte_length,
            content_type,
        })
    }

    pub const fn digest(&self) -> &YouTubeAssetDigest {
        &self.digest
    }

    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn content_type(&self) -> &str {
        &self.content_type
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeVisibility {
    Public,
    Private,
    Unlisted,
}

impl YouTubeVisibility {
    pub const fn as_api_value(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Unlisted => "unlisted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeSchedule {
    publish_at: DateTime<Utc>,
}

impl YouTubeSchedule {
    pub const fn new(publish_at: DateTime<Utc>) -> Self {
        Self { publish_at }
    }

    pub const fn publish_at(&self) -> DateTime<Utc> {
        self.publish_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeApprovalRevision {
    approval_id: String,
    revision: u64,
    approved_at: DateTime<Utc>,
}

impl YouTubeApprovalRevision {
    pub fn new(
        approval_id: impl Into<String>,
        revision: u64,
        approved_at: DateTime<Utc>,
    ) -> Result<Self, YouTubeError> {
        let approval_id = valid_id(approval_id.into(), "YouTube approval ID", 256)?;
        if revision == 0 {
            return Err(YouTubeError::InvalidRequest(
                "YouTube approval revision must be positive",
            ));
        }
        Ok(Self {
            approval_id,
            revision,
            approved_at,
        })
    }

    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn approved_at(&self) -> DateTime<Utc> {
        self.approved_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct YouTubeIdempotencyKey(String);

impl YouTubeIdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        Ok(Self(valid_id(
            value.into(),
            "YouTube publish idempotency key",
            256,
        )?))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DraftVideoPublishRequest {
    binding: YouTubePublishBinding,
    asset: YouTubeAssetDescriptor,
    title: String,
    visibility: YouTubeVisibility,
    schedule: Option<YouTubeSchedule>,
    approval: YouTubeApprovalRevision,
    idempotency_key: YouTubeIdempotencyKey,
    created_at: DateTime<Utc>,
}

impl DraftVideoPublishRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: YouTubePublishBinding,
        asset: YouTubeAssetDescriptor,
        title: impl Into<String>,
        visibility: YouTubeVisibility,
        schedule: Option<YouTubeSchedule>,
        approval: YouTubeApprovalRevision,
        idempotency_key: YouTubeIdempotencyKey,
        created_at: DateTime<Utc>,
    ) -> Result<Self, YouTubeError> {
        let title = title.into();
        if title.trim().is_empty() || title.chars().count() > 100 {
            return Err(YouTubeError::InvalidRequest(
                "YouTube title must contain one through one hundred characters",
            ));
        }
        let request = Self {
            binding,
            asset,
            title,
            visibility,
            schedule,
            approval,
            idempotency_key,
            created_at,
        };
        request.validate_at(created_at)?;
        Ok(request)
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub const fn asset(&self) -> &YouTubeAssetDescriptor {
        &self.asset
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub const fn visibility(&self) -> &YouTubeVisibility {
        &self.visibility
    }

    pub const fn schedule(&self) -> Option<YouTubeSchedule> {
        self.schedule
    }

    pub const fn approval(&self) -> &YouTubeApprovalRevision {
        &self.approval
    }

    pub const fn idempotency_key(&self) -> &YouTubeIdempotencyKey {
        &self.idempotency_key
    }

    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn request_digest(&self) -> String {
        sha256_json(&serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({})))
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), YouTubeError> {
        if self.title.trim().is_empty()
            || self.title.chars().count() > 100
            || self.approval.revision == 0
            || self.idempotency_key.0.is_empty()
        {
            return Err(YouTubeError::InvalidRequest(
                "YouTube draft publish request is incomplete",
            ));
        }
        if let Some(schedule) = self.schedule
            && (!matches!(self.visibility, YouTubeVisibility::Private)
                || schedule.publish_at <= now)
        {
            return Err(YouTubeError::InvalidSchedule);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeDispatchOperation {
    AuthenticatedProbe,
    BeginResumableUpload,
    UploadChunk,
    Readback,
}

impl YouTubeDispatchOperation {
    pub const fn quota_bucket(self) -> YouTubeQuotaBucket {
        match self {
            Self::AuthenticatedProbe => YouTubeQuotaBucket::Probe,
            Self::BeginResumableUpload | Self::UploadChunk => YouTubeQuotaBucket::Publish,
            Self::Readback => YouTubeQuotaBucket::Readback,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeQuotaBucket {
    Probe,
    Publish,
    Readback,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeQuotaLedger {
    remaining: BTreeMap<YouTubeQuotaBucket, u64>,
    consumed: BTreeMap<YouTubeQuotaBucket, u64>,
}

impl Default for YouTubeQuotaLedger {
    fn default() -> Self {
        Self::new(10_000, 100, 10_000)
    }
}

impl YouTubeQuotaLedger {
    pub fn new(probe_units: u64, publish_units: u64, readback_units: u64) -> Self {
        Self {
            remaining: BTreeMap::from([
                (YouTubeQuotaBucket::Probe, probe_units),
                (YouTubeQuotaBucket::Publish, publish_units),
                (YouTubeQuotaBucket::Readback, readback_units),
            ]),
            consumed: BTreeMap::new(),
        }
    }

    pub fn reserve(&mut self, operation: YouTubeDispatchOperation) -> Result<(), YouTubeError> {
        let bucket = operation.quota_bucket();
        let remaining = self.remaining.entry(bucket).or_default();
        if *remaining == 0 {
            return Err(YouTubeError::QuotaExhausted { bucket });
        }
        *remaining -= 1;
        *self.consumed.entry(bucket).or_default() += 1;
        Ok(())
    }

    pub fn remaining(&self, bucket: YouTubeQuotaBucket) -> u64 {
        self.remaining.get(&bucket).copied().unwrap_or_default()
    }

    pub fn consumed(&self, bucket: YouTubeQuotaBucket) -> u64 {
        self.consumed.get(&bucket).copied().unwrap_or_default()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct YouTubeCredential {
    secret_reference: YouTubeSecretReference,
    binding: YouTubePublishBinding,
    granted_scopes: BTreeSet<YouTubeOAuthScope>,
    access_token_expires_at: DateTime<Utc>,
    refresh_token_expires_at: Option<DateTime<Utc>>,
    generation: u64,
    revoked_at: Option<DateTime<Utc>>,
    unmounted_at: Option<DateTime<Utc>>,
}

impl YouTubeCredential {
    pub fn new(
        secret_reference: YouTubeSecretReference,
        binding: YouTubePublishBinding,
        granted_scopes: BTreeSet<YouTubeOAuthScope>,
        access_token_expires_at: DateTime<Utc>,
        refresh_token_expires_at: Option<DateTime<Utc>>,
        generation: u64,
    ) -> Result<Self, YouTubeError> {
        if generation == 0 || generation != binding.provider_generation() {
            return Err(YouTubeError::InvalidRequest(
                "YouTube credential generation must equal binding provider generation",
            ));
        }
        Ok(Self {
            secret_reference,
            binding,
            granted_scopes,
            access_token_expires_at,
            refresh_token_expires_at,
            generation,
            revoked_at: None,
            unmounted_at: None,
        })
    }

    pub const fn secret_reference(&self) -> &YouTubeSecretReference {
        &self.secret_reference
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub fn granted_scopes(&self) -> &BTreeSet<YouTubeOAuthScope> {
        &self.granted_scopes
    }

    pub fn scope_digest(&self) -> String {
        sha256_json(&serde_json::json!({
            "scopes": self
                .granted_scopes
                .iter()
                .map(|scope| scope.as_str())
                .collect::<Vec<_>>(),
        }))
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

    pub fn unmount(&mut self, at: DateTime<Utc>) {
        self.unmounted_at = Some(at);
    }

    pub const fn unmounted_at(&self) -> Option<DateTime<Utc>> {
        self.unmounted_at
    }

    pub fn require_for(
        &self,
        operation: YouTubeDispatchOperation,
        binding: &YouTubePublishBinding,
        now: DateTime<Utc>,
    ) -> Result<(), YouTubeError> {
        if &self.binding != binding {
            if self.binding.provider_generation() != binding.provider_generation()
                && self.binding.tenant_id() == binding.tenant_id()
                && self.binding.business_id() == binding.business_id()
                && self.binding.account_id() == binding.account_id()
                && self.binding.channel_id() == binding.channel_id()
            {
                return Err(YouTubeError::CredentialGenerationMismatch);
            }
            return Err(YouTubeError::ScopeMismatch);
        }
        if self
            .unmounted_at
            .is_some_and(|unmounted_at| unmounted_at <= now)
        {
            return Err(YouTubeError::CredentialUnmounted);
        }
        if self.revoked_at.is_some_and(|revoked_at| revoked_at <= now) {
            return Err(YouTubeError::CredentialRevoked);
        }
        if self.access_token_expires_at <= now {
            return Err(YouTubeError::CredentialExpired);
        }
        let required_scope = match operation {
            YouTubeDispatchOperation::AuthenticatedProbe | YouTubeDispatchOperation::Readback => {
                YouTubeOAuthScope::YoutubeReadonly
            }
            YouTubeDispatchOperation::BeginResumableUpload
            | YouTubeDispatchOperation::UploadChunk => YouTubeOAuthScope::YoutubeUpload,
        };
        if !self.granted_scopes.contains(&required_scope) {
            return Err(YouTubeError::MissingScope {
                scope: required_scope,
            });
        }
        Ok(())
    }

    pub fn require_publish(
        &self,
        binding: &YouTubePublishBinding,
        now: DateTime<Utc>,
    ) -> Result<(), YouTubeError> {
        self.require_for(YouTubeDispatchOperation::AuthenticatedProbe, binding, now)?;
        self.require_for(YouTubeDispatchOperation::BeginResumableUpload, binding, now)
    }
}

impl fmt::Debug for YouTubeCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("YouTubeCredential")
            .field("secret_reference", &self.secret_reference)
            .field("binding", &self.binding)
            .field("granted_scopes", &self.granted_scopes)
            .field("access_token_expires_at", &self.access_token_expires_at)
            .field("refresh_token_expires_at", &self.refresh_token_expires_at)
            .field("generation", &self.generation)
            .field("revoked_at", &self.revoked_at)
            .field("unmounted_at", &self.unmounted_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeEvidenceProvenance {
    Fixture,
    ControlledProvider,
    ProductionProvider,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeAuthenticatedProbe {
    provider: YouTubeProviderId,
    binding: YouTubePublishBinding,
    credential_generation: u64,
    channel_title: Option<String>,
    response_digest: String,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    provenance: YouTubeEvidenceProvenance,
}

impl YouTubeAuthenticatedProbe {
    pub const fn provider(&self) -> YouTubeProviderId {
        self.provider
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub fn channel_title(&self) -> Option<&str> {
        self.channel_title.as_deref()
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub const fn provenance(&self) -> YouTubeEvidenceProvenance {
        self.provenance
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), YouTubeError> {
        if self.provider != YouTubeProviderId::YouTube
            || self.credential_generation != self.binding.provider_generation()
            || !is_sha256(&self.response_digest)
            || self.valid_until <= self.observed_at
        {
            return Err(YouTubeError::InvalidResponse("YouTube probe receipt"));
        }
        if now >= self.valid_until {
            return Err(YouTubeError::ProbeExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct YouTubeUploadSessionReference(String);

impl YouTubeUploadSessionReference {
    pub fn new(value: impl Into<String>) -> Result<Self, YouTubeError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 512
            || value.chars().any(char::is_whitespace)
            || value.to_ascii_lowercase().contains("bearer ")
        {
            return Err(YouTubeError::InvalidRequest(
                "YouTube upload session reference must be opaque",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for YouTubeUploadSessionReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("YouTubeUploadSessionReference(<opaque>)")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeProviderReceipt {
    provider: YouTubeProviderId,
    binding: YouTubePublishBinding,
    request_digest: String,
    provider_request_digest: String,
    idempotency_key: YouTubeIdempotencyKey,
    video_id: YouTubeVideoId,
    session: YouTubeUploadSessionReference,
    response_digest: String,
    observed_at: DateTime<Utc>,
    provenance: YouTubeEvidenceProvenance,
}

impl YouTubeProviderReceipt {
    pub const fn provider(&self) -> YouTubeProviderId {
        self.provider
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn provider_request_digest(&self) -> &str {
        &self.provider_request_digest
    }

    pub const fn idempotency_key(&self) -> &YouTubeIdempotencyKey {
        &self.idempotency_key
    }

    pub const fn video_id(&self) -> &YouTubeVideoId {
        &self.video_id
    }

    pub const fn session(&self) -> &YouTubeUploadSessionReference {
        &self.session
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn provenance(&self) -> YouTubeEvidenceProvenance {
        self.provenance
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeVideoProcessingState {
    Uploaded,
    Processing,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeReadbackReceipt {
    provider: YouTubeProviderId,
    binding: YouTubePublishBinding,
    request_digest: String,
    provider_request_digest: String,
    video_id: YouTubeVideoId,
    channel_id: YouTubeChannelId,
    title: String,
    visibility: YouTubeVisibility,
    schedule: Option<YouTubeSchedule>,
    upload_status: String,
    processing_state: YouTubeVideoProcessingState,
    response_digest: String,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    provenance: YouTubeEvidenceProvenance,
}

impl YouTubeReadbackReceipt {
    pub const fn provider(&self) -> YouTubeProviderId {
        self.provider
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn provider_request_digest(&self) -> &str {
        &self.provider_request_digest
    }

    pub const fn video_id(&self) -> &YouTubeVideoId {
        &self.video_id
    }

    pub const fn channel_id(&self) -> &YouTubeChannelId {
        &self.channel_id
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub const fn visibility(&self) -> &YouTubeVisibility {
        &self.visibility
    }

    pub const fn schedule(&self) -> Option<YouTubeSchedule> {
        self.schedule
    }

    pub fn upload_status(&self) -> &str {
        &self.upload_status
    }

    pub const fn processing_state(&self) -> YouTubeVideoProcessingState {
        self.processing_state
    }

    pub fn response_digest(&self) -> &str {
        &self.response_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub const fn provenance(&self) -> YouTubeEvidenceProvenance {
        self.provenance
    }

    pub fn verify_against(
        &self,
        request: &DraftVideoPublishRequest,
        provider_receipt: &YouTubeProviderReceipt,
    ) -> Result<(), YouTubeError> {
        if self.provider != YouTubeProviderId::YouTube
            || self.binding != *request.binding()
            || self.binding != *provider_receipt.binding()
            || self.request_digest != request.request_digest()
            || self.request_digest != provider_receipt.request_digest()
            || self.video_id != *provider_receipt.video_id()
            || self.channel_id != *request.binding().channel_id()
            || self.provenance != provider_receipt.provenance()
            || self.title != request.title()
            || self.visibility != *request.visibility()
            || self.schedule != request.schedule()
            || !is_sha256(&self.provider_request_digest)
            || !is_sha256(provider_receipt.provider_request_digest())
            || !is_sha256(provider_receipt.response_digest())
            || !is_sha256(&self.response_digest)
            || self.valid_until <= self.observed_at
        {
            return Err(YouTubeError::ReadbackMismatch);
        }
        if matches!(self.processing_state, YouTubeVideoProcessingState::Failed)
            || self.upload_status == "failed"
        {
            return Err(YouTubeError::ReadbackMismatch);
        }
        Ok(())
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), YouTubeError> {
        if self.valid_until <= self.observed_at || !is_sha256(&self.response_digest) {
            return Err(YouTubeError::InvalidResponse("YouTube readback receipt"));
        }
        if now >= self.valid_until {
            return Err(YouTubeError::ReadbackExpired);
        }
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.upload_status == "uploaded"
            && matches!(self.processing_state, YouTubeVideoProcessingState::Uploaded)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeRetryAfterReceipt {
    provider: YouTubeProviderId,
    operation: YouTubeDispatchOperation,
    binding: YouTubePublishBinding,
    request_digest: String,
    observed_at: DateTime<Utc>,
    response_digest: String,
    retry_after_seconds: Option<u64>,
    provider_reset_at: Option<DateTime<Utc>>,
}

impl YouTubeRetryAfterReceipt {
    pub fn retry_is_due(&self, now: DateTime<Utc>) -> bool {
        self.provider_reset_at.is_none_or(|reset| now >= reset)
    }

    pub const fn operation(&self) -> YouTubeDispatchOperation {
        self.operation
    }

    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeReconciliationReason {
    UploadStartAmbiguous,
    ProviderReceiptMissing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubeReconciliationReceipt {
    binding: YouTubePublishBinding,
    request_digest: String,
    reason: YouTubeReconciliationReason,
    observed_at: DateTime<Utc>,
}

impl YouTubeReconciliationReceipt {
    pub const fn binding(&self) -> &YouTubePublishBinding {
        &self.binding
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn reason(&self) -> YouTubeReconciliationReason {
        self.reason
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeUploadProgress {
    InProgress {
        session: YouTubeUploadSessionReference,
        uploaded_bytes: u64,
        response_digest: String,
        observed_at: DateTime<Utc>,
    },
    Completed(YouTubeProviderReceipt),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubePublishedVideo {
    request_digest: String,
    probe: YouTubeAuthenticatedProbe,
    provider_receipt: YouTubeProviderReceipt,
    readback: YouTubeReadbackReceipt,
    credential_generation: u64,
    provenance: YouTubeEvidenceProvenance,
}

impl YouTubePublishedVideo {
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub const fn probe(&self) -> &YouTubeAuthenticatedProbe {
        &self.probe
    }

    pub const fn provider_receipt(&self) -> &YouTubeProviderReceipt {
        &self.provider_receipt
    }

    pub const fn readback(&self) -> &YouTubeReadbackReceipt {
        &self.readback
    }

    pub const fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub const fn provenance(&self) -> YouTubeEvidenceProvenance {
        self.provenance
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeCredentialInvalidationReason {
    Rotated,
    Revoked,
    Unmounted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubePublishPhase {
    Draft,
    ProbeVerified,
    Uploading,
    ReceiptCaptured,
    Completed,
    ReconciliationRequired,
    Invalidated {
        reason: YouTubeCredentialInvalidationReason,
        at: DateTime<Utc>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YouTubePublishCheckpoint {
    request: DraftVideoPublishRequest,
    phase: YouTubePublishPhase,
    credential_generation: Option<u64>,
    credential_reference_digest: Option<String>,
    probe: Option<YouTubeAuthenticatedProbe>,
    session: Option<YouTubeUploadSessionReference>,
    uploaded_bytes: u64,
    provider_receipt: Option<YouTubeProviderReceipt>,
    readback: Option<YouTubeReadbackReceipt>,
    retry_after: Option<YouTubeRetryAfterReceipt>,
    reconciliation: Option<YouTubeReconciliationReceipt>,
}

impl YouTubePublishCheckpoint {
    pub fn new(request: DraftVideoPublishRequest) -> Result<Self, YouTubeError> {
        request.validate_at(request.created_at())?;
        let checkpoint = Self {
            request,
            phase: YouTubePublishPhase::Draft,
            credential_generation: None,
            credential_reference_digest: None,
            probe: None,
            session: None,
            uploaded_bytes: 0,
            provider_receipt: None,
            readback: None,
            retry_after: None,
            reconciliation: None,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub const fn request(&self) -> &DraftVideoPublishRequest {
        &self.request
    }

    pub const fn phase(&self) -> &YouTubePublishPhase {
        &self.phase
    }

    pub const fn probe(&self) -> Option<&YouTubeAuthenticatedProbe> {
        self.probe.as_ref()
    }

    pub const fn session(&self) -> Option<&YouTubeUploadSessionReference> {
        self.session.as_ref()
    }

    pub const fn uploaded_bytes(&self) -> u64 {
        self.uploaded_bytes
    }

    pub const fn provider_receipt(&self) -> Option<&YouTubeProviderReceipt> {
        self.provider_receipt.as_ref()
    }

    pub const fn readback(&self) -> Option<&YouTubeReadbackReceipt> {
        self.readback.as_ref()
    }

    pub const fn retry_after(&self) -> Option<&YouTubeRetryAfterReceipt> {
        self.retry_after.as_ref()
    }

    pub const fn reconciliation(&self) -> Option<&YouTubeReconciliationReceipt> {
        self.reconciliation.as_ref()
    }

    pub const fn credential_generation(&self) -> Option<u64> {
        self.credential_generation
    }

    pub fn credential_reference_digest(&self) -> Option<&str> {
        self.credential_reference_digest.as_deref()
    }

    pub fn checkpoint_json(&self) -> Result<String, YouTubeError> {
        self.validate()?;
        serde_json::to_string(self)
            .map_err(|_| YouTubeError::InvalidRequest("YouTube checkpoint serialization failed"))
    }

    pub fn from_checkpoint_json(value: &str) -> Result<Self, YouTubeError> {
        let checkpoint: Self = serde_json::from_str(value)
            .map_err(|_| YouTubeError::InvalidRequest("invalid YouTube publish checkpoint"))?;
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn durable_digest(&self) -> String {
        serde_json::to_value(self).map_or_else(|_| "0".repeat(64), |value| sha256_json(&value))
    }

    pub(crate) fn require_dispatchable(&self) -> Result<(), YouTubeError> {
        match self.phase {
            YouTubePublishPhase::Invalidated { .. } => Err(YouTubeError::CheckpointInvalidated),
            _ => Ok(()),
        }
    }

    pub(crate) fn bind_credential(
        &mut self,
        credential: &YouTubeCredential,
        now: DateTime<Utc>,
    ) -> Result<(), YouTubeError> {
        self.require_dispatchable()?;
        if credential.binding() != self.request.binding() {
            if credential.binding().tenant_id() == self.request.binding().tenant_id()
                && credential.binding().business_id() == self.request.binding().business_id()
                && credential.binding().account_id() == self.request.binding().account_id()
                && credential.binding().channel_id() == self.request.binding().channel_id()
            {
                self.invalidate(YouTubeCredentialInvalidationReason::Rotated, now);
                return Err(YouTubeError::CheckpointInvalidated);
            }
            return Err(YouTubeError::ScopeMismatch);
        }
        let reference_digest = credential_reference_digest(credential);
        let bound = self.credential_generation.is_some();
        if bound
            && (self.credential_generation != Some(credential.generation())
                || self.credential_reference_digest.as_deref() != Some(&reference_digest))
        {
            self.invalidate(YouTubeCredentialInvalidationReason::Rotated, now);
            return Err(YouTubeError::CheckpointInvalidated);
        }
        if bound
            && credential
                .unmounted_at()
                .is_some_and(|unmounted_at| unmounted_at <= now)
        {
            self.invalidate(YouTubeCredentialInvalidationReason::Unmounted, now);
            return Err(YouTubeError::CheckpointInvalidated);
        }
        if bound
            && credential
                .revoked_at()
                .is_some_and(|revoked_at| revoked_at <= now)
        {
            self.invalidate(YouTubeCredentialInvalidationReason::Revoked, now);
            return Err(YouTubeError::CheckpointInvalidated);
        }
        if !bound {
            if credential
                .unmounted_at()
                .is_some_and(|unmounted_at| unmounted_at <= now)
            {
                return Err(YouTubeError::CredentialUnmounted);
            }
            if credential
                .revoked_at()
                .is_some_and(|revoked_at| revoked_at <= now)
            {
                return Err(YouTubeError::CredentialRevoked);
            }
            self.credential_generation = Some(credential.generation());
            self.credential_reference_digest = Some(reference_digest);
        }
        Ok(())
    }

    pub(crate) fn retry_after_if_waiting(
        &self,
        now: DateTime<Utc>,
    ) -> Option<&YouTubeRetryAfterReceipt> {
        self.retry_after
            .as_ref()
            .filter(|receipt| !receipt.retry_is_due(now))
    }

    pub(crate) fn clear_retry_after(&mut self) {
        self.retry_after = None;
    }

    pub(crate) fn set_retry_after(&mut self, receipt: YouTubeRetryAfterReceipt) {
        self.retry_after = Some(receipt);
    }

    pub(crate) fn set_probe(&mut self, probe: YouTubeAuthenticatedProbe) {
        self.probe = Some(probe);
        self.phase = YouTubePublishPhase::ProbeVerified;
    }

    pub(crate) fn set_session(&mut self, session: YouTubeUploadSessionReference) {
        self.session = Some(session);
        self.phase = YouTubePublishPhase::Uploading;
    }

    pub(crate) fn set_uploaded_bytes(&mut self, uploaded_bytes: u64) -> Result<(), YouTubeError> {
        if uploaded_bytes > self.request.asset.byte_length {
            return Err(YouTubeError::InvalidResponse("YouTube upload offset"));
        }
        self.uploaded_bytes = uploaded_bytes;
        self.phase = YouTubePublishPhase::Uploading;
        Ok(())
    }

    pub(crate) fn set_provider_receipt(&mut self, receipt: YouTubeProviderReceipt) {
        self.provider_receipt = Some(receipt);
        self.phase = YouTubePublishPhase::ReceiptCaptured;
    }

    pub(crate) fn set_readback(&mut self, readback: YouTubeReadbackReceipt) {
        self.readback = Some(readback);
    }

    pub(crate) fn mark_completed(&mut self) {
        self.phase = YouTubePublishPhase::Completed;
    }

    pub(crate) fn mark_reconciliation_required(
        &mut self,
        reason: YouTubeReconciliationReason,
        observed_at: DateTime<Utc>,
    ) {
        self.reconciliation = Some(YouTubeReconciliationReceipt {
            binding: self.request.binding.clone(),
            request_digest: self.request.request_digest(),
            reason,
            observed_at,
        });
        self.phase = YouTubePublishPhase::ReconciliationRequired;
    }

    pub(crate) fn published_video(&self) -> Result<YouTubePublishedVideo, YouTubeError> {
        if !matches!(self.phase, YouTubePublishPhase::Completed) {
            return Err(YouTubeError::InvalidRequest(
                "YouTube publish is not complete",
            ));
        }
        Ok(YouTubePublishedVideo {
            request_digest: self.request.request_digest(),
            probe: self.probe.clone().ok_or(YouTubeError::ReadbackMismatch)?,
            provider_receipt: self
                .provider_receipt
                .clone()
                .ok_or(YouTubeError::ReadbackMismatch)?,
            readback: self
                .readback
                .clone()
                .ok_or(YouTubeError::ReadbackMismatch)?,
            credential_generation: self
                .credential_generation
                .ok_or(YouTubeError::CredentialGenerationMismatch)?,
            provenance: self
                .probe
                .as_ref()
                .ok_or(YouTubeError::ReadbackMismatch)?
                .provenance(),
        })
    }

    pub(crate) fn invalidate(
        &mut self,
        reason: YouTubeCredentialInvalidationReason,
        at: DateTime<Utc>,
    ) {
        self.phase = YouTubePublishPhase::Invalidated { reason, at };
        self.retry_after = None;
    }

    fn validate(&self) -> Result<(), YouTubeError> {
        self.request.validate_at(self.request.created_at())?;
        if self.credential_generation.is_some() != self.credential_reference_digest.is_some()
            || self
                .credential_reference_digest
                .as_deref()
                .is_some_and(|digest| !is_sha256(digest))
            || self.uploaded_bytes > self.request.asset.byte_length
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        if let Some(probe) = &self.probe
            && (probe.binding() != self.request.binding()
                || self.credential_generation != Some(probe.credential_generation()))
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        if let Some(receipt) = &self.provider_receipt
            && (receipt.binding() != self.request.binding()
                || receipt.request_digest() != self.request.request_digest()
                || receipt.idempotency_key() != self.request.idempotency_key())
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        if let Some(readback) = &self.readback
            && (readback.binding() != self.request.binding()
                || readback.request_digest() != self.request.request_digest())
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        if self.provider_receipt.as_ref().is_some_and(|receipt| {
            !is_sha256(receipt.provider_request_digest()) || !is_sha256(receipt.response_digest())
        }) || self.readback.as_ref().is_some_and(|readback| {
            !is_sha256(readback.provider_request_digest()) || !is_sha256(readback.response_digest())
        }) {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        if let (Some(provider_receipt), Some(readback)) =
            (self.provider_receipt.as_ref(), self.readback.as_ref())
        {
            readback.verify_against(&self.request, provider_receipt)?;
        }
        if let Some(retry_after) = &self.retry_after
            && (retry_after.binding() != self.request.binding()
                || retry_after.request_digest() != self.request.request_digest())
        {
            return Err(YouTubeError::InvalidCheckpoint);
        }
        match self.phase {
            YouTubePublishPhase::Draft => {
                if self.probe.is_some()
                    || self.session.is_some()
                    || self.provider_receipt.is_some()
                    || self.readback.is_some()
                {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
            YouTubePublishPhase::ProbeVerified => {
                if self.probe.is_none() || self.session.is_some() {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
            YouTubePublishPhase::Uploading => {
                if self.probe.is_none() || self.session.is_none() || self.provider_receipt.is_some()
                {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
            YouTubePublishPhase::ReceiptCaptured => {
                if self.probe.is_none() || self.session.is_none() || self.provider_receipt.is_none()
                {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
            YouTubePublishPhase::Completed => {
                if self.probe.is_none()
                    || self.provider_receipt.is_none()
                    || self.readback.is_none()
                    || !self
                        .readback
                        .as_ref()
                        .is_some_and(YouTubeReadbackReceipt::is_ready)
                {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
            YouTubePublishPhase::ReconciliationRequired => {
                if self.reconciliation.is_none() || self.probe.is_none() {
                    return Err(YouTubeError::InvalidCheckpoint);
                }
            }
            YouTubePublishPhase::Invalidated { .. } => {}
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum YouTubePublishDispatchResult {
    RetryAfter(YouTubeRetryAfterReceipt),
    Retryable {
        operation: YouTubeDispatchOperation,
        checkpoint_digest: String,
    },
    Uploading {
        session: YouTubeUploadSessionReference,
        uploaded_bytes: u64,
    },
    ReadbackPending(YouTubeReadbackReceipt),
    Completed(YouTubePublishedVideo),
    AlreadyCompleted(YouTubePublishedVideo),
    ReconciliationRequired(YouTubeReconciliationReceipt),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum YouTubeError {
    #[error("invalid YouTube publish request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid YouTube provider response: {0}")]
    InvalidResponse(&'static str),
    #[error("YouTube provider rejected the request: {0}")]
    ProviderRejected(String),
    #[error("YouTube provider returned a retryable failure for {operation:?}")]
    RetryableProvider { operation: YouTubeDispatchOperation },
    #[error("YouTube provider is disconnected")]
    Disconnected,
    #[error("YouTube API is rate limited")]
    RetryAfter(Box<YouTubeRetryAfterReceipt>),
    #[error("YouTube quota exhausted for {bucket:?}")]
    QuotaExhausted { bucket: YouTubeQuotaBucket },
    #[error("YouTube credential generation does not match the publish binding")]
    CredentialGenerationMismatch,
    #[error("YouTube credential is expired")]
    CredentialExpired,
    #[error("YouTube credential is revoked")]
    CredentialRevoked,
    #[error("YouTube credential is unmounted")]
    CredentialUnmounted,
    #[error("YouTube credential scope is not sufficient: {scope:?}")]
    MissingScope { scope: YouTubeOAuthScope },
    #[error("YouTube publish scope does not match the exact tenant/business/account/channel")]
    ScopeMismatch,
    #[error("YouTube publish schedule is invalid")]
    InvalidSchedule,
    #[error("YouTube authenticated probe has expired")]
    ProbeExpired,
    #[error("YouTube readback has expired")]
    ReadbackExpired,
    #[error("YouTube provider readback did not match the approved draft")]
    ReadbackMismatch,
    #[error("YouTube readback is still processing")]
    ReadbackPending,
    #[error("YouTube publish checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("YouTube publish checkpoint was invalidated")]
    CheckpointInvalidated,
    #[error("YouTube publish requires external reconciliation before retry")]
    ReconciliationRequired,
    #[error("YouTube production publish is blocked by environment: {requirement}")]
    BlockedEnvironment { requirement: &'static str },
    #[error("YouTube authorized publish effect boundary does not match")]
    EffectBoundaryMismatch,
    #[error("YouTube authorized publish effect has expired")]
    EffectExpired,
    #[error("YouTube publish plugin identity or revision does not match")]
    PluginRevisionMismatch,
    #[error("YouTube publish effect revision does not match")]
    EffectRevisionMismatch,
    #[error("YouTube publish effect scope digest does not match the live credential")]
    ScopeDigestMismatch,
    #[error("YouTube verification checkpoint was invalidated")]
    VerificationCheckpointInvalidated,
    #[error("YouTube publish readback verification was rejected")]
    VerificationRejected,
}

impl YouTubeError {
    pub(crate) const fn is_retryable(&self) -> bool {
        matches!(self, Self::Disconnected | Self::RetryableProvider { .. })
    }
}

fn credential_reference_digest(credential: &YouTubeCredential) -> String {
    sha256_json(&serde_json::json!({
        "secret_reference": credential.secret_reference().as_str(),
    }))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut digest = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut digest, "{byte:02x}").expect("writing to String cannot fail");
    }
    digest
}

fn sha256_json(value: &serde_json::Value) -> String {
    hex_digest(value.to_string().as_bytes())
}
