//! Reddit official API and Devvit read-only boundary.
//!
//! The planner only admits an explicitly approved Reddit Data API integration
//! or an installed Devvit app with the Reddit API permission.  There is no
//! browser fallback in this module.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::identity::{
    AccountIdentity, ChannelIdentity, ContentIdentity, RedditAccountId, RedditAccountIdentity,
    RedditCommunityIdentity, RedditRevisionIdentity, RedditRevisionKey, RedditSubredditId,
    RedditSubredditName, RedditThingId, RedditThingKind,
};
use crate::transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderReadRequest,
    ProviderResponse, ReadOperation, ScopeName, provider_code, retry_after,
};

pub const REDDIT_OAUTH_API_BASE_URL: &str = "https://oauth.reddit.com/";
pub const REDDIT_IDENTITY_SCOPE: &str = "identity";
pub const REDDIT_READ_SCOPE: &str = "read";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditScope {
    Identity,
    Read,
}

impl RedditScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => REDDIT_IDENTITY_SCOPE,
            Self::Read => REDDIT_READ_SCOPE,
        }
    }

    fn name(self) -> Result<ScopeName, ChannelAdapterError> {
        ScopeName::new(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditDataApiApproval {
    approval_reference: String,
    scopes: BTreeSet<RedditScope>,
    approved_at: DateTime<Utc>,
}

impl RedditDataApiApproval {
    pub fn new(
        approval_reference: impl Into<String>,
        scopes: BTreeSet<RedditScope>,
        approved_at: DateTime<Utc>,
    ) -> Result<Self, ChannelAdapterError> {
        let approval_reference = approval_reference.into();
        if approval_reference.is_empty() || approval_reference.chars().any(char::is_whitespace) {
            return Err(ChannelAdapterError::InvalidRequest(
                "Reddit approval reference must be opaque",
            ));
        }
        Ok(Self {
            approval_reference,
            scopes,
            approved_at,
        })
    }

    pub fn approval_reference(&self) -> &str {
        &self.approval_reference
    }

    pub const fn approved_at(&self) -> DateTime<Utc> {
        self.approved_at
    }

    pub fn scopes(&self) -> &BTreeSet<RedditScope> {
        &self.scopes
    }

    fn allows(&self, scope: RedditScope) -> bool {
        self.scopes.contains(&scope)
    }

    fn supports_channel_read(&self) -> bool {
        self.allows(RedditScope::Identity) && self.allows(RedditScope::Read)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditDevvitInstallation {
    app_slug: String,
    installation_id: String,
    community: RedditCommunityIdentity,
    reddit_api_enabled: bool,
}

impl RedditDevvitInstallation {
    pub fn new(
        app_slug: impl Into<String>,
        installation_id: impl Into<String>,
        community: RedditCommunityIdentity,
        reddit_api_enabled: bool,
    ) -> Result<Self, ChannelAdapterError> {
        let app_slug = app_slug.into();
        let installation_id = installation_id.into();
        if app_slug.is_empty()
            || installation_id.is_empty()
            || app_slug.chars().any(char::is_whitespace)
            || installation_id.chars().any(char::is_whitespace)
        {
            return Err(ChannelAdapterError::InvalidRequest(
                "Devvit installation identity must be non-empty and opaque",
            ));
        }
        Ok(Self {
            app_slug,
            installation_id,
            community,
            reddit_api_enabled,
        })
    }

    pub fn app_slug(&self) -> &str {
        &self.app_slug
    }

    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    pub const fn community(&self) -> &RedditCommunityIdentity {
        &self.community
    }

    pub const fn reddit_api_enabled(&self) -> bool {
        self.reddit_api_enabled
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditAuthorizationSnapshot {
    data_api: Option<RedditDataApiApproval>,
    devvit: Option<RedditDevvitInstallation>,
}

impl RedditAuthorizationSnapshot {
    pub fn new(
        data_api: Option<RedditDataApiApproval>,
        devvit: Option<RedditDevvitInstallation>,
    ) -> Self {
        Self { data_api, devvit }
    }

    pub const fn data_api(&self) -> Option<&RedditDataApiApproval> {
        self.data_api.as_ref()
    }

    pub const fn devvit(&self) -> Option<&RedditDevvitInstallation> {
        self.devvit.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditIntegrationMode {
    DataApi(RedditDataApiApproval),
    Devvit(RedditDevvitInstallation),
    AuthorizationRequired { reason: AuthorizationReason },
}

impl RedditIntegrationMode {
    pub const fn is_authorized(&self) -> bool {
        !matches!(self, Self::AuthorizationRequired { .. })
    }
}

/// Selects an official Reddit integration using only recorded authorization
/// facts. A missing approval never degrades into browser automation.
pub fn determine_integration_mode(snapshot: &RedditAuthorizationSnapshot) -> RedditIntegrationMode {
    if let Some(approval) = snapshot.data_api.as_ref()
        && approval.supports_channel_read()
    {
        return RedditIntegrationMode::DataApi(approval.clone());
    }
    if let Some(devvit) = snapshot.devvit.as_ref()
        && devvit.reddit_api_enabled()
    {
        return RedditIntegrationMode::Devvit(devvit.clone());
    }
    let reason = match snapshot.data_api.as_ref() {
        Some(approval)
            if !approval.allows(RedditScope::Identity) || !approval.allows(RedditScope::Read) =>
        {
            AuthorizationReason::MissingScope
        }
        _ => AuthorizationReason::NoApprovedIntegration,
    };
    RedditIntegrationMode::AuthorizationRequired { reason }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditReadTarget {
    Account,
    Community {
        name: RedditSubredditName,
    },
    Listing {
        community: RedditSubredditName,
        after: Option<RedditThingId>,
        limit: u32,
    },
    Content {
        thing_id: RedditThingId,
    },
}

impl RedditReadTarget {
    pub fn listing(
        community: RedditSubredditName,
        after: Option<RedditThingId>,
        limit: u32,
    ) -> Result<Self, ChannelAdapterError> {
        let target = Self::Listing {
            community,
            after,
            limit,
        };
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<(), ChannelAdapterError> {
        if let Self::Listing { limit, .. } = self
            && !(1..=100).contains(limit)
        {
            return Err(ChannelAdapterError::InvalidRequest(
                "Reddit listing limit must be between 1 and 100",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum RedditReadPlan {
    DataApi(ProviderReadRequest),
    Devvit(RedditDevvitReadRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditDevvitReadRequest {
    installation_id: String,
    community: RedditCommunityIdentity,
    target: RedditDevvitReadTarget,
}

impl RedditDevvitReadRequest {
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    pub const fn community(&self) -> &RedditCommunityIdentity {
        &self.community
    }

    pub const fn target(&self) -> &RedditDevvitReadTarget {
        &self.target
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditDevvitReadTarget {
    Community,
    Listing {
        after: Option<RedditThingId>,
        limit: u32,
    },
    Content {
        thing_id: RedditThingId,
    },
}

pub fn plan_read(
    mode: &RedditIntegrationMode,
    target: &RedditReadTarget,
    credential: Option<CredentialReference>,
) -> Result<RedditReadPlan, ChannelAdapterError> {
    target.validate()?;
    match mode {
        RedditIntegrationMode::AuthorizationRequired { reason } => {
            Err(ChannelAdapterError::AuthorizationRequired {
                provider: crate::identity::ProviderId::Reddit,
                reason: *reason,
            })
        }
        RedditIntegrationMode::DataApi(approval) => {
            let credential = credential.ok_or(ChannelAdapterError::InvalidRequest(
                "Reddit Data API reads require a credential reference",
            ))?;
            plan_data_api(approval, target, credential).map(RedditReadPlan::DataApi)
        }
        RedditIntegrationMode::Devvit(installation) => {
            plan_devvit(installation, target).map(RedditReadPlan::Devvit)
        }
    }
}

fn plan_data_api(
    approval: &RedditDataApiApproval,
    target: &RedditReadTarget,
    credential: CredentialReference,
) -> Result<ProviderReadRequest, ChannelAdapterError> {
    let mut url = Url::parse(REDDIT_OAUTH_API_BASE_URL).map_err(|_| invalid_endpoint())?;
    let scope = match target {
        RedditReadTarget::Account => {
            if !approval.allows(RedditScope::Identity) {
                return Err(missing_scope(RedditScope::Identity));
            }
            url.path_segments_mut()
                .map_err(|()| invalid_endpoint())?
                .extend(["api", "v1", "me"]);
            RedditScope::Identity
        }
        RedditReadTarget::Community { name } => {
            require_read_scope(approval)?;
            url.path_segments_mut()
                .map_err(|()| invalid_endpoint())?
                .extend(["r", name.as_str(), "about"]);
            RedditScope::Read
        }
        RedditReadTarget::Listing {
            community,
            after,
            limit,
        } => {
            require_read_scope(approval)?;
            url.path_segments_mut()
                .map_err(|()| invalid_endpoint())?
                .extend(["r", community.as_str(), "new.json"]);
            url.query_pairs_mut()
                .append_pair("limit", &limit.to_string());
            if let Some(after) = after {
                url.query_pairs_mut().append_pair("after", after.as_str());
            }
            RedditScope::Read
        }
        RedditReadTarget::Content { thing_id } => {
            require_read_scope(approval)?;
            url.path_segments_mut()
                .map_err(|()| invalid_endpoint())?
                .extend(["api", "info"]);
            url.query_pairs_mut().append_pair("id", thing_id.as_str());
            RedditScope::Read
        }
    };
    ProviderReadRequest::new(
        crate::identity::ProviderId::Reddit,
        ReadOperation::Content,
        HttpMethod::Get,
        url,
        [scope.name()?],
        credential,
        None,
    )
}

fn plan_devvit(
    installation: &RedditDevvitInstallation,
    target: &RedditReadTarget,
) -> Result<RedditDevvitReadRequest, ChannelAdapterError> {
    let target = match target {
        RedditReadTarget::Account => {
            return Err(ChannelAdapterError::UnsupportedSurface {
                provider: crate::identity::ProviderId::Reddit,
                surface: "Devvit account identity",
            });
        }
        RedditReadTarget::Community { name } => {
            if name != installation.community().name() {
                return Err(ChannelAdapterError::UnsupportedSurface {
                    provider: crate::identity::ProviderId::Reddit,
                    surface: "Devvit installation community",
                });
            }
            RedditDevvitReadTarget::Community
        }
        RedditReadTarget::Listing {
            community,
            after,
            limit,
        } => {
            if community != installation.community().name() {
                return Err(ChannelAdapterError::UnsupportedSurface {
                    provider: crate::identity::ProviderId::Reddit,
                    surface: "Devvit installation community",
                });
            }
            RedditDevvitReadTarget::Listing {
                after: after.clone(),
                limit: *limit,
            }
        }
        RedditReadTarget::Content { thing_id } => RedditDevvitReadTarget::Content {
            thing_id: thing_id.clone(),
        },
    };
    Ok(RedditDevvitReadRequest {
        installation_id: installation.installation_id.clone(),
        community: installation.community.clone(),
        target,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditAccountObservation {
    account: AccountIdentity,
    observed_at: DateTime<Utc>,
}

impl RedditAccountObservation {
    pub const fn account(&self) -> &AccountIdentity {
        &self.account
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditCommunityObservation {
    channel: ChannelIdentity,
    observed_at: DateTime<Utc>,
}

impl RedditCommunityObservation {
    pub const fn channel(&self) -> &ChannelIdentity {
        &self.channel
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditRemovalReason {
    Moderator,
    Reddit,
    AutomodFiltered,
    Spam,
    AuthorDeleted,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditModerationState {
    Visible,
    RemovedByModerator,
    RemovedByReddit,
    Filtered,
    DeletedByAuthor,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditContentObservation {
    content: ContentIdentity,
    revision: RedditRevisionIdentity,
    moderation: RedditModerationState,
    removal_reason: Option<RedditRemovalReason>,
    observed_at: DateTime<Utc>,
}

impl RedditContentObservation {
    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn revision(&self) -> &RedditRevisionIdentity {
        &self.revision
    }

    pub const fn moderation(&self) -> RedditModerationState {
        self.moderation
    }

    pub const fn removal_reason(&self) -> Option<RedditRemovalReason> {
        self.removal_reason
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditReadResult {
    account: Option<RedditAccountObservation>,
    community: Option<RedditCommunityObservation>,
    content: Vec<RedditContentObservation>,
}

impl RedditReadResult {
    pub fn account(&self) -> Option<&RedditAccountObservation> {
        self.account.as_ref()
    }

    pub fn community(&self) -> Option<&RedditCommunityObservation> {
        self.community.as_ref()
    }

    pub fn content(&self) -> &[RedditContentObservation] {
        &self.content
    }
}

pub fn parse_read_response(
    target: &RedditReadTarget,
    response: &ProviderResponse,
) -> Result<RedditReadResult, ChannelAdapterError> {
    let body = successful_json(response)?;
    match target {
        RedditReadTarget::Account => parse_account(&body, response.observed_at()),
        RedditReadTarget::Community { name } => {
            parse_community(&body, name, response.observed_at())
        }
        RedditReadTarget::Listing { .. } => {
            let children = listing_children(&body)?;
            let content = children
                .iter()
                .map(|child| parse_content(child, response.observed_at()))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(RedditReadResult {
                content,
                ..RedditReadResult::default()
            })
        }
        RedditReadTarget::Content { .. } => {
            let children = info_children(&body)?;
            let content = children
                .iter()
                .map(|child| parse_content(child, response.observed_at()))
                .collect::<Result<Vec<_>, _>>()?;
            if content.is_empty() {
                return Err(ChannelAdapterError::ContentNotFound {
                    provider: crate::identity::ProviderId::Reddit,
                });
            }
            Ok(RedditReadResult {
                content,
                ..RedditReadResult::default()
            })
        }
    }
}

fn parse_account(
    body: &serde_json::Value,
    observed_at: DateTime<Utc>,
) -> Result<RedditReadResult, ChannelAdapterError> {
    let account_id =
        RedditAccountId::new(required_string(body, "id")?).map_err(|_| invalid_response("id"))?;
    let username = body
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Ok(RedditReadResult {
        account: Some(RedditAccountObservation {
            account: AccountIdentity::Reddit(RedditAccountIdentity::new(account_id, username)),
            observed_at,
        }),
        ..RedditReadResult::default()
    })
}

fn parse_community(
    body: &serde_json::Value,
    requested_name: &RedditSubredditName,
    observed_at: DateTime<Utc>,
) -> Result<RedditReadResult, ChannelAdapterError> {
    let data = body.get("data").unwrap_or(body);
    let subreddit_id = RedditSubredditId::new(required_string(data, "id")?)
        .map_err(|_| invalid_response("data.id"))?;
    let name = data
        .get("display_name")
        .or_else(|| data.get("name"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| requested_name.as_str());
    let name = RedditSubredditName::new(name.to_owned())
        .map_err(|_| invalid_response("data.display_name"))?;
    Ok(RedditReadResult {
        community: Some(RedditCommunityObservation {
            channel: ChannelIdentity::Reddit(RedditCommunityIdentity::new(subreddit_id, name)),
            observed_at,
        }),
        ..RedditReadResult::default()
    })
}

fn listing_children(body: &serde_json::Value) -> Result<&[serde_json::Value], ChannelAdapterError> {
    body.pointer("/data/children")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .ok_or(invalid_response("data.children"))
}

fn info_children(body: &serde_json::Value) -> Result<&[serde_json::Value], ChannelAdapterError> {
    body.get("data")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .ok_or(invalid_response("data"))
}

fn parse_content(
    child: &serde_json::Value,
    observed_at: DateTime<Utc>,
) -> Result<RedditContentObservation, ChannelAdapterError> {
    let kind_text = required_string(child, "kind")?;
    let data = child.get("data").ok_or(invalid_response("data"))?;
    let kind = parse_kind(&kind_text, data)?;
    let name = required_string(data, "name")?;
    let thing_id = RedditThingId::new(name.clone()).map_err(|_| invalid_response("data.name"))?;
    let subreddit_id = data
        .get("subreddit_id")
        .and_then(serde_json::Value::as_str)
        .map(|value| RedditSubredditId::new(value.to_owned()))
        .transpose()
        .map_err(|_| invalid_response("data.subreddit_id"))?;
    let parent_post_id = data
        .get("link_id")
        .or_else(|| data.get("parent_id"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| value.starts_with("t3_"))
        .map(|value| RedditThingId::new(value.to_owned()))
        .transpose()
        .map_err(|_| invalid_response("data.parent_id"))?;
    let content_identity =
        crate::identity::RedditContentIdentity::new(thing_id, kind, subreddit_id, parent_post_id);
    let (moderation, removal_reason) = moderation_state(data);
    let revision_key = RedditRevisionKey::new(revision_key(data, removal_reason))
        .map_err(|_| invalid_response("data.revision"))?;
    let revision = RedditRevisionIdentity::new(
        ContentIdentity::Reddit(content_identity.clone()),
        revision_key,
        observed_at,
    )
    .map_err(|_| invalid_response("data.revision"))?;
    Ok(RedditContentObservation {
        content: ContentIdentity::Reddit(content_identity),
        revision,
        moderation,
        removal_reason,
        observed_at,
    })
}

fn parse_kind(
    kind: &str,
    data: &serde_json::Value,
) -> Result<RedditThingKind, ChannelAdapterError> {
    match kind {
        "t3" => Ok(RedditThingKind::Post),
        "t1" => Ok(RedditThingKind::Comment),
        _ => match data
            .get("name")
            .and_then(serde_json::Value::as_str)
            .and_then(|name| name.get(..3))
        {
            Some("t3_") => Ok(RedditThingKind::Post),
            Some("t1_") => Ok(RedditThingKind::Comment),
            _ => Err(invalid_response("kind")),
        },
    }
}

fn moderation_state(
    data: &serde_json::Value,
) -> (RedditModerationState, Option<RedditRemovalReason>) {
    let category = data
        .get("removed_by_category")
        .and_then(serde_json::Value::as_str);
    if let Some(category) = category {
        return match category {
            "moderator" => (
                RedditModerationState::RemovedByModerator,
                Some(RedditRemovalReason::Moderator),
            ),
            "reddit" | "content_policy" => (
                RedditModerationState::RemovedByReddit,
                Some(RedditRemovalReason::Reddit),
            ),
            "automod_filtered" => (
                RedditModerationState::Filtered,
                Some(RedditRemovalReason::AutomodFiltered),
            ),
            "author" | "deleted" => (
                RedditModerationState::DeletedByAuthor,
                Some(RedditRemovalReason::AuthorDeleted),
            ),
            "spam" => (
                RedditModerationState::Filtered,
                Some(RedditRemovalReason::Spam),
            ),
            _ => (
                RedditModerationState::Unknown,
                Some(RedditRemovalReason::Other),
            ),
        };
    }
    if data.get("author").is_some_and(serde_json::Value::is_null)
        || data.get("selftext").and_then(serde_json::Value::as_str) == Some("[deleted]")
    {
        return (
            RedditModerationState::DeletedByAuthor,
            Some(RedditRemovalReason::AuthorDeleted),
        );
    }
    if data.get("selftext").and_then(serde_json::Value::as_str) == Some("[removed]") {
        return (
            RedditModerationState::RemovedByModerator,
            Some(RedditRemovalReason::Moderator),
        );
    }
    (RedditModerationState::Visible, None)
}

fn revision_key(data: &serde_json::Value, removal_reason: Option<RedditRemovalReason>) -> String {
    let edited = scalar_key(data.get("edited"));
    let deleted = scalar_key(data.get("deleted"));
    let locked = scalar_key(data.get("locked"));
    let removal = removal_reason.map_or("none", removal_reason_code);
    format!("edited-{edited}-deleted-{deleted}-locked-{locked}-removed-{removal}")
}

fn removal_reason_code(reason: RedditRemovalReason) -> &'static str {
    match reason {
        RedditRemovalReason::Moderator => "moderator",
        RedditRemovalReason::Reddit => "reddit",
        RedditRemovalReason::AutomodFiltered => "automod_filtered",
        RedditRemovalReason::Spam => "spam",
        RedditRemovalReason::AuthorDeleted => "author_deleted",
        RedditRemovalReason::Other => "other",
    }
}

fn scalar_key(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::Bool(value)) => value.to_string(),
        Some(serde_json::Value::Number(value)) => value.to_string(),
        Some(serde_json::Value::String(value)) => value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character
                } else {
                    '_'
                }
            })
            .collect(),
        _ => "none".to_owned(),
    }
}

fn successful_json(response: &ProviderResponse) -> Result<serde_json::Value, ChannelAdapterError> {
    let provider = crate::identity::ProviderId::Reddit;
    if (200..300).contains(&response.status()) {
        return response.json(provider);
    }
    let body = response.json(provider).ok();
    let code = body.as_ref().and_then(provider_code);
    match response.status() {
        401 => Err(ChannelAdapterError::CredentialRevoked {
            provider,
            reason: AuthorizationReason::ScopeRevoked,
            account: None,
        }),
        403 => Err(ChannelAdapterError::AuthorizationRequired {
            provider,
            reason: AuthorizationReason::MissingScope,
        }),
        404 => Err(ChannelAdapterError::ContentNotFound { provider }),
        429 => Err(ChannelAdapterError::RateLimited {
            provider,
            retry_after_seconds: retry_after(response),
        }),
        status => Err(ChannelAdapterError::ProviderRejected {
            provider,
            status,
            code,
        }),
    }
}

fn require_read_scope(approval: &RedditDataApiApproval) -> Result<(), ChannelAdapterError> {
    if approval.allows(RedditScope::Read) {
        Ok(())
    } else {
        Err(missing_scope(RedditScope::Read))
    }
}

fn missing_scope(scope: RedditScope) -> ChannelAdapterError {
    ChannelAdapterError::ScopeNotGranted {
        provider: crate::identity::ProviderId::Reddit,
        scope: scope.name().expect("static Reddit scope names are valid"),
    }
}

fn required_string(object: &serde_json::Value, key: &str) -> Result<String, ChannelAdapterError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid_response(key))
}

fn invalid_endpoint() -> ChannelAdapterError {
    ChannelAdapterError::InvalidRequest("invalid Reddit endpoint")
}

fn invalid_response(field: impl Into<String>) -> ChannelAdapterError {
    ChannelAdapterError::InvalidResponse {
        provider: crate::identity::ProviderId::Reddit,
        field: field.into(),
    }
}
