//! TikTok Login Kit and Content Posting API read-only boundary.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::identity::{
    AccountIdentity, ChannelIdentity, ContentIdentity, TiktokAccountIdentity,
    TiktokContentIdentity, TiktokCreatorIdentity, TiktokCreatorUsername, TiktokOpenId,
    TiktokPostId, TiktokPublishId, TiktokRevisionIdentity, WebhookEventId,
};
use crate::transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderReadRequest,
    ProviderResponse, ReadOperation, ScopeName, provider_code, retry_after,
};
use crate::webhook::{WebhookEnvelope, WebhookError};

pub const OPEN_API_BASE_URL: &str = "https://open.tiktokapis.com/v2/";
pub const TIKTOK_USER_INFO_BASIC_SCOPE: &str = "user.info.basic";
pub const TIKTOK_VIDEO_PUBLISH_SCOPE: &str = "video.publish";
pub const TIKTOK_VIDEO_UPLOAD_SCOPE: &str = "video.upload";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokScope {
    UserInfoBasic,
    VideoPublish,
    VideoUpload,
}

impl TiktokScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserInfoBasic => TIKTOK_USER_INFO_BASIC_SCOPE,
            Self::VideoPublish => TIKTOK_VIDEO_PUBLISH_SCOPE,
            Self::VideoUpload => TIKTOK_VIDEO_UPLOAD_SCOPE,
        }
    }

    fn name(self) -> Result<ScopeName, ChannelAdapterError> {
        ScopeName::new(self.as_str())
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            TIKTOK_USER_INFO_BASIC_SCOPE => Some(Self::UserInfoBasic),
            TIKTOK_VIDEO_PUBLISH_SCOPE => Some(Self::VideoPublish),
            TIKTOK_VIDEO_UPLOAD_SCOPE => Some(Self::VideoUpload),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokAuditState {
    Approved,
    Unaudited,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokAuthorization {
    identity: TiktokAccountIdentity,
    app_approved_scopes: BTreeSet<TiktokScope>,
    user_granted_scopes: BTreeSet<TiktokScope>,
    audit_state: TiktokAuditState,
    access_token_expires_at: Option<DateTime<Utc>>,
    refresh_token_expires_at: Option<DateTime<Utc>>,
}

impl TiktokAuthorization {
    pub fn new(
        identity: TiktokAccountIdentity,
        app_approved_scopes: BTreeSet<TiktokScope>,
        user_granted_scopes: BTreeSet<TiktokScope>,
        audit_state: TiktokAuditState,
        access_token_expires_at: Option<DateTime<Utc>>,
        refresh_token_expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            identity,
            app_approved_scopes,
            user_granted_scopes,
            audit_state,
            access_token_expires_at,
            refresh_token_expires_at,
        }
    }

    pub const fn identity(&self) -> &TiktokAccountIdentity {
        &self.identity
    }

    pub const fn audit_state(&self) -> TiktokAuditState {
        self.audit_state
    }

    pub fn app_approved_scopes(&self) -> &BTreeSet<TiktokScope> {
        &self.app_approved_scopes
    }

    pub fn user_granted_scopes(&self) -> &BTreeSet<TiktokScope> {
        &self.user_granted_scopes
    }

    pub const fn access_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.access_token_expires_at
    }

    pub const fn refresh_token_expires_at(&self) -> Option<DateTime<Utc>> {
        self.refresh_token_expires_at
    }

    fn require_scope(&self, scope: TiktokScope) -> Result<(), ChannelAdapterError> {
        if !self.app_approved_scopes.contains(&scope) {
            return Err(ChannelAdapterError::AuthorizationRequired {
                provider: crate::identity::ProviderId::Tiktok,
                reason: AuthorizationReason::MissingApproval,
            });
        }
        if !self.user_granted_scopes.contains(&scope) {
            return Err(ChannelAdapterError::AuthorizationRequired {
                provider: crate::identity::ProviderId::Tiktok,
                reason: AuthorizationReason::MissingScope,
            });
        }
        Ok(())
    }

    fn require_status_scope(&self) -> Result<TiktokScope, ChannelAdapterError> {
        if self
            .app_approved_scopes
            .contains(&TiktokScope::VideoPublish)
            && self
                .user_granted_scopes
                .contains(&TiktokScope::VideoPublish)
        {
            return Ok(TiktokScope::VideoPublish);
        }
        if self.app_approved_scopes.contains(&TiktokScope::VideoUpload)
            && self.user_granted_scopes.contains(&TiktokScope::VideoUpload)
        {
            return Ok(TiktokScope::VideoUpload);
        }
        if !self
            .app_approved_scopes
            .contains(&TiktokScope::VideoPublish)
            && !self.app_approved_scopes.contains(&TiktokScope::VideoUpload)
        {
            return Err(ChannelAdapterError::AuthorizationRequired {
                provider: crate::identity::ProviderId::Tiktok,
                reason: AuthorizationReason::MissingApproval,
            });
        }
        Err(ChannelAdapterError::AuthorizationRequired {
            provider: crate::identity::ProviderId::Tiktok,
            reason: AuthorizationReason::MissingScope,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokOAuthIdentityObservation {
    authorization: TiktokAuthorization,
    observed_at: DateTime<Utc>,
}

impl TiktokOAuthIdentityObservation {
    pub const fn authorization(&self) -> &TiktokAuthorization {
        &self.authorization
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

pub fn parse_oauth_identity(
    response: &ProviderResponse,
    app_approved_scopes: BTreeSet<TiktokScope>,
    audit_state: TiktokAuditState,
) -> Result<TiktokOAuthIdentityObservation, ChannelAdapterError> {
    let body = successful_json(response)?;
    let open_id = TiktokOpenId::new(required_string(&body, "open_id")?)
        .map_err(|_| invalid_response("open_id"))?;
    let granted = body
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter_map(TiktokScope::parse)
        .collect::<BTreeSet<_>>();
    let expires_in = body
        .get("expires_in")
        .and_then(serde_json::Value::as_i64)
        .ok_or(invalid_response("expires_in"))?;
    let refresh_expires_in = body
        .get("refresh_expires_in")
        .and_then(serde_json::Value::as_i64)
        .ok_or(invalid_response("refresh_expires_in"))?;
    if expires_in < 0 || refresh_expires_in < 0 {
        return Err(invalid_response("token expiry"));
    }
    let observed_at = response.observed_at();
    let authorization = TiktokAuthorization::new(
        TiktokAccountIdentity::new(open_id),
        app_approved_scopes,
        granted,
        audit_state,
        Some(observed_at + chrono::Duration::seconds(expires_in)),
        Some(observed_at + chrono::Duration::seconds(refresh_expires_in)),
    );
    Ok(TiktokOAuthIdentityObservation {
        authorization,
        observed_at,
    })
}

pub fn creator_info_request(
    authorization: &TiktokAuthorization,
    credential: CredentialReference,
) -> Result<ProviderReadRequest, ChannelAdapterError> {
    authorization.require_scope(TiktokScope::VideoPublish)?;
    let url = Url::parse(&format!(
        "{OPEN_API_BASE_URL}post/publish/creator_info/query/"
    ))
    .map_err(|_| invalid_endpoint())?;
    ProviderReadRequest::new(
        crate::identity::ProviderId::Tiktok,
        ReadOperation::Identity,
        HttpMethod::Post,
        url,
        [TiktokScope::VideoPublish.name()?],
        credential,
        None,
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TiktokPrivacyLevel {
    PublicToEveryone,
    FollowerOfCreator,
    MutualFollowFriends,
    SelfOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokEffectiveVisibility {
    PublicEligible,
    PrivateOnlyUnaudited,
    NotPublic,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokCreatorPolicy {
    privacy_level_options: BTreeSet<TiktokPrivacyLevel>,
    comment_disabled: bool,
    duet_disabled: bool,
    stitch_disabled: bool,
    max_video_post_duration_sec: u32,
    audit_state: TiktokAuditState,
    effective_visibility: TiktokEffectiveVisibility,
}

impl TiktokCreatorPolicy {
    pub fn privacy_level_options(&self) -> &BTreeSet<TiktokPrivacyLevel> {
        &self.privacy_level_options
    }

    pub const fn effective_visibility(&self) -> TiktokEffectiveVisibility {
        self.effective_visibility
    }

    pub const fn audit_state(&self) -> TiktokAuditState {
        self.audit_state
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokCreatorObservation {
    account: AccountIdentity,
    creator: ChannelIdentity,
    policy: TiktokCreatorPolicy,
    observed_at: DateTime<Utc>,
}

impl TiktokCreatorObservation {
    pub const fn account(&self) -> &AccountIdentity {
        &self.account
    }

    pub const fn creator(&self) -> &ChannelIdentity {
        &self.creator
    }

    pub const fn policy(&self) -> &TiktokCreatorPolicy {
        &self.policy
    }
}

pub fn parse_creator_info(
    authorization: &TiktokAuthorization,
    response: &ProviderResponse,
) -> Result<TiktokCreatorObservation, ChannelAdapterError> {
    authorization.require_scope(TiktokScope::VideoPublish)?;
    let body = successful_json(response)?;
    let data = body.get("data").ok_or(invalid_response("data"))?;
    let username = TiktokCreatorUsername::new(required_string(data, "creator_username")?)
        .map_err(|_| invalid_response("data.creator_username"))?;
    let options = data
        .get("privacy_level_options")
        .and_then(serde_json::Value::as_array)
        .ok_or(invalid_response("data.privacy_level_options"))?
        .iter()
        .map(|value| {
            serde_json::from_value::<TiktokPrivacyLevel>(value.clone())
                .map_err(|_| invalid_response("data.privacy_level_options"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let max_duration = data
        .get("max_video_post_duration_sec")
        .and_then(serde_json::Value::as_u64)
        .ok_or(invalid_response("data.max_video_post_duration_sec"))?;
    let max_duration = u32::try_from(max_duration)
        .map_err(|_| invalid_response("data.max_video_post_duration_sec"))?;
    let effective_visibility = match authorization.audit_state {
        TiktokAuditState::Approved => TiktokEffectiveVisibility::PublicEligible,
        TiktokAuditState::Unaudited => TiktokEffectiveVisibility::PrivateOnlyUnaudited,
        TiktokAuditState::Unknown => TiktokEffectiveVisibility::Unknown,
    };
    let policy = TiktokCreatorPolicy {
        privacy_level_options: options,
        comment_disabled: required_bool(data, "comment_disabled")?,
        duet_disabled: required_bool(data, "duet_disabled")?,
        stitch_disabled: required_bool(data, "stitch_disabled")?,
        max_video_post_duration_sec: max_duration,
        audit_state: authorization.audit_state,
        effective_visibility,
    };
    let creator = TiktokCreatorIdentity::new(authorization.identity.clone(), username);
    Ok(TiktokCreatorObservation {
        account: AccountIdentity::Tiktok(authorization.identity.clone()),
        creator: ChannelIdentity::Tiktok(creator),
        policy,
        observed_at: response.observed_at(),
    })
}

pub fn content_status_request(
    authorization: &TiktokAuthorization,
    publish_id: &TiktokPublishId,
    credential: CredentialReference,
) -> Result<ProviderReadRequest, ChannelAdapterError> {
    let scope = authorization.require_status_scope()?;
    let url = Url::parse(&format!("{OPEN_API_BASE_URL}post/publish/status/fetch/"))
        .map_err(|_| invalid_endpoint())?;
    ProviderReadRequest::new(
        crate::identity::ProviderId::Tiktok,
        ReadOperation::Status,
        HttpMethod::Post,
        url,
        [scope.name()?],
        credential,
        Some(serde_json::json!({ "publish_id": publish_id.as_str() })),
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TiktokContentStatus {
    ProcessingUpload,
    ProcessingDownload,
    SendToUserInbox,
    PublishComplete,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokModerationState {
    NotPublic,
    PubliclyAvailable,
    NoLongerPublic,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokContentStatusObservation {
    identity: TiktokContentIdentity,
    revision: TiktokRevisionIdentity,
    status: TiktokContentStatus,
    moderation: TiktokModerationState,
    fail_reason: Option<String>,
    publicly_available_post_ids: Vec<TiktokPostId>,
    uploaded_bytes: Option<u64>,
    downloaded_bytes: Option<u64>,
    observed_at: DateTime<Utc>,
}

impl TiktokContentStatusObservation {
    pub const fn identity(&self) -> &TiktokContentIdentity {
        &self.identity
    }

    pub const fn revision(&self) -> &TiktokRevisionIdentity {
        &self.revision
    }

    pub const fn status(&self) -> TiktokContentStatus {
        self.status
    }

    pub const fn moderation(&self) -> TiktokModerationState {
        self.moderation
    }

    pub fn fail_reason(&self) -> Option<&str> {
        self.fail_reason.as_deref()
    }

    pub fn publicly_available_post_ids(&self) -> &[TiktokPostId] {
        &self.publicly_available_post_ids
    }
}

pub fn parse_content_status(
    authorization: &TiktokAuthorization,
    publish_id: TiktokPublishId,
    response: &ProviderResponse,
) -> Result<TiktokContentStatusObservation, ChannelAdapterError> {
    authorization.require_status_scope()?;
    let body = successful_json(response)?;
    let data = body.get("data").ok_or(invalid_response("data"))?;
    let status = serde_json::from_value::<TiktokContentStatus>(
        data.get("status")
            .cloned()
            .ok_or(invalid_response("data.status"))?,
    )
    .map_err(|_| invalid_response("data.status"))?;
    let public_ids = data
        .get("publicaly_available_post_id")
        .or_else(|| data.get("publicly_available_post_id"))
        .and_then(serde_json::Value::as_array)
        .ok_or(invalid_response("data.publicaly_available_post_id"))?
        .iter()
        .map(|value| {
            let value = match value {
                serde_json::Value::String(value) => value.clone(),
                serde_json::Value::Number(value) => value.to_string(),
                _ => return Err(invalid_response("data.publicaly_available_post_id")),
            };
            TiktokPostId::new(value)
                .map_err(|_| invalid_response("data.publicaly_available_post_id"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let identity = TiktokContentIdentity::new(
        authorization.identity.open_id().clone(),
        publish_id,
        public_ids.first().cloned(),
    );
    let moderation = match status {
        TiktokContentStatus::PublishComplete if public_ids.is_empty() => {
            TiktokModerationState::NotPublic
        }
        TiktokContentStatus::PublishComplete => TiktokModerationState::PubliclyAvailable,
        TiktokContentStatus::Failed => TiktokModerationState::Failed,
        _ => TiktokModerationState::Unknown,
    };
    let state_key = format!(
        "{:?}-{}",
        status,
        public_ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("_")
    );
    let revision = TiktokRevisionIdentity::new(
        ContentIdentity::Tiktok(identity.clone()),
        state_key,
        response.observed_at(),
    )
    .map_err(|_| invalid_response("data.revision"))?;
    Ok(TiktokContentStatusObservation {
        identity,
        revision,
        status,
        moderation,
        fail_reason: data
            .get("fail_reason")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        publicly_available_post_ids: public_ids,
        uploaded_bytes: optional_u64(data, "uploaded_bytes"),
        downloaded_bytes: optional_u64(data, "downloaded_bytes"),
        observed_at: response.observed_at(),
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TiktokWebhookKind {
    PublishFailed,
    PublishComplete,
    InboxDelivered,
    PubliclyAvailable,
    NoLongerPubliclyAvailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokWebhookObservation {
    event_id: WebhookEventId,
    kind: TiktokWebhookKind,
    content: TiktokContentIdentity,
    revision: TiktokRevisionIdentity,
    received_at: DateTime<Utc>,
}

impl TiktokWebhookObservation {
    pub const fn event_id(&self) -> &WebhookEventId {
        &self.event_id
    }

    pub const fn kind(&self) -> TiktokWebhookKind {
        self.kind
    }

    pub const fn content(&self) -> &TiktokContentIdentity {
        &self.content
    }

    pub const fn revision(&self) -> &TiktokRevisionIdentity {
        &self.revision
    }

    pub fn envelope(
        &self,
        occurred_at: DateTime<Utc>,
        received_at: DateTime<Utc>,
    ) -> Result<WebhookEnvelope, WebhookError> {
        WebhookEnvelope::new(
            self.event_id.clone(),
            crate::identity::ProviderId::Tiktok,
            ContentIdentity::Tiktok(self.content.clone()),
            crate::identity::RevisionIdentity::Tiktok(self.revision.clone()),
            occurred_at,
            received_at,
        )
    }
}

pub fn parse_webhook(
    response: &ProviderResponse,
) -> Result<TiktokWebhookObservation, ChannelAdapterError> {
    let body = successful_json(response)?;
    let event = required_string(&body, "event")?;
    let kind = match event.as_str() {
        "post.publish.failed" => TiktokWebhookKind::PublishFailed,
        "post.publish.complete" => TiktokWebhookKind::PublishComplete,
        "post.publish.inbox_delivered" => TiktokWebhookKind::InboxDelivered,
        "post.publish.publicly_available" => TiktokWebhookKind::PubliclyAvailable,
        "post.publish.no_longer_publicaly_available"
        | "post.publish.no_longer_publicly_available" => {
            TiktokWebhookKind::NoLongerPubliclyAvailable
        }
        _ => return Err(invalid_response("event")),
    };
    let publish_id = TiktokPublishId::new(required_string(&body, "publish_id")?)
        .map_err(|_| invalid_response("publish_id"))?;
    let post_id = body
        .get("post_id")
        .and_then(serde_json::Value::as_str)
        .map(|value| TiktokPostId::new(value.to_owned()))
        .transpose()
        .map_err(|_| invalid_response("post_id"))?;
    let content = TiktokContentIdentity::new(
        TiktokOpenId::new(required_string(&body, "open_id")?)
            .map_err(|_| invalid_response("open_id"))?,
        publish_id,
        post_id,
    );
    let state_key = format!("{event}-{}", response.body_digest());
    let revision = TiktokRevisionIdentity::new(
        ContentIdentity::Tiktok(content.clone()),
        state_key,
        response.observed_at(),
    )
    .map_err(|_| invalid_response("revision"))?;
    let event_id =
        WebhookEventId::new(response.body_digest()).map_err(|_| invalid_response("event_id"))?;
    Ok(TiktokWebhookObservation {
        event_id,
        kind,
        content,
        revision,
        received_at: response.observed_at(),
    })
}

fn successful_json(response: &ProviderResponse) -> Result<serde_json::Value, ChannelAdapterError> {
    let provider = crate::identity::ProviderId::Tiktok;
    if (200..300).contains(&response.status()) {
        return response.json(provider);
    }
    let body = response.json(provider).ok();
    let code = body.as_ref().and_then(provider_code);
    if response.status() == 401 {
        return Err(ChannelAdapterError::AuthorizationRequired {
            provider,
            reason: if code
                .as_deref()
                .is_some_and(|code| code.contains("scope") || code.contains("auth"))
            {
                AuthorizationReason::ScopeRevoked
            } else {
                AuthorizationReason::CredentialExpired
            },
        });
    }
    if response.status() == 429 {
        return Err(ChannelAdapterError::RateLimited {
            provider,
            retry_after_seconds: retry_after(response),
        });
    }
    if response.status() == 403
        && code
            .as_deref()
            .is_some_and(|code| code.contains("scope") || code.contains("auth"))
    {
        return Err(ChannelAdapterError::AuthorizationRequired {
            provider,
            reason: AuthorizationReason::MissingScope,
        });
    }
    Err(ChannelAdapterError::ProviderRejected {
        provider,
        status: response.status(),
        code,
    })
}

fn required_string(object: &serde_json::Value, key: &str) -> Result<String, ChannelAdapterError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(invalid_response(key))
}

fn required_bool(object: &serde_json::Value, key: &str) -> Result<bool, ChannelAdapterError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_bool)
        .ok_or(invalid_response(key))
}

fn optional_u64(object: &serde_json::Value, key: &str) -> Option<u64> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse().ok())
        })
}

fn invalid_endpoint() -> ChannelAdapterError {
    ChannelAdapterError::InvalidRequest("invalid provider endpoint")
}

fn invalid_response(field: impl Into<String>) -> ChannelAdapterError {
    ChannelAdapterError::InvalidResponse {
        provider: crate::identity::ProviderId::Tiktok,
        field: field.into(),
    }
}
