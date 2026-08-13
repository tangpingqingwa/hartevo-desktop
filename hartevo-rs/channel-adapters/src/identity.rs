//! Exact provider/account/channel/content/revision identity types.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    Youtube,
    Tiktok,
    Reddit,
}

impl ProviderId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Youtube => "youtube",
            Self::Tiktok => "tiktok",
            Self::Reddit => "reddit",
        }
    }
}

impl fmt::Display for ProviderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentityError {
    #[error("identity is empty")]
    Empty,
    #[error("identity is too long")]
    TooLong,
    #[error("identity contains unsupported characters")]
    UnsupportedCharacters,
}

fn validate_identifier(value: &str, allow: impl Fn(char) -> bool) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty);
    }
    if value.len() > 512 {
        return Err(IdentityError::TooLong);
    }
    if value.chars().any(|character| !allow(character)) {
        return Err(IdentityError::UnsupportedCharacters);
    }
    Ok(())
}

fn ascii_identifier(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
}

fn provider_identifier(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '~' | '.')
}

macro_rules! identifier_type {
    ($name:ident, $allow:ident) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
                let value = value.into();
                validate_identifier(&value, $allow)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

identifier_type!(YoutubeChannelId, ascii_identifier);
identifier_type!(YoutubePlaylistId, ascii_identifier);
identifier_type!(YoutubeVideoId, ascii_identifier);
identifier_type!(YoutubeCommentThreadId, ascii_identifier);
identifier_type!(YoutubeEtag, provider_identifier);
identifier_type!(TiktokOpenId, provider_identifier);
identifier_type!(TiktokCreatorUsername, provider_identifier);
identifier_type!(TiktokPublishId, provider_identifier);
identifier_type!(TiktokPostId, provider_identifier);
identifier_type!(RedditAccountId, ascii_identifier);
identifier_type!(RedditSubredditId, ascii_identifier);
identifier_type!(RedditSubredditName, ascii_identifier);
identifier_type!(RedditThingId, ascii_identifier);
identifier_type!(RedditRevisionKey, provider_identifier);
identifier_type!(WebhookEventId, provider_identifier);

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeAccountIdentity {
    channel_id: YoutubeChannelId,
}

impl YoutubeAccountIdentity {
    pub const fn channel_id(&self) -> &YoutubeChannelId {
        &self.channel_id
    }

    pub const fn new(channel_id: YoutubeChannelId) -> Self {
        Self { channel_id }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeChannelIdentity {
    account: YoutubeAccountIdentity,
    channel_id: YoutubeChannelId,
    etag: YoutubeEtag,
    uploads_playlist_id: Option<YoutubePlaylistId>,
}

impl YoutubeChannelIdentity {
    pub fn new(
        channel_id: YoutubeChannelId,
        etag: YoutubeEtag,
        uploads_playlist_id: Option<YoutubePlaylistId>,
    ) -> Self {
        Self {
            account: YoutubeAccountIdentity::new(channel_id.clone()),
            channel_id,
            etag,
            uploads_playlist_id,
        }
    }

    pub const fn account(&self) -> &YoutubeAccountIdentity {
        &self.account
    }

    pub const fn channel_id(&self) -> &YoutubeChannelId {
        &self.channel_id
    }

    pub const fn etag(&self) -> &YoutubeEtag {
        &self.etag
    }

    pub const fn uploads_playlist_id(&self) -> Option<&YoutubePlaylistId> {
        self.uploads_playlist_id.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeVideoIdentity {
    channel_id: YoutubeChannelId,
    video_id: YoutubeVideoId,
}

impl YoutubeVideoIdentity {
    pub const fn new(channel_id: YoutubeChannelId, video_id: YoutubeVideoId) -> Self {
        Self {
            channel_id,
            video_id,
        }
    }

    pub const fn channel_id(&self) -> &YoutubeChannelId {
        &self.channel_id
    }

    pub const fn video_id(&self) -> &YoutubeVideoId {
        &self.video_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::struct_field_names)]
pub struct YoutubeCommentIdentity {
    channel_id: Option<YoutubeChannelId>,
    video_id: Option<YoutubeVideoId>,
    thread_id: YoutubeCommentThreadId,
}

impl YoutubeCommentIdentity {
    pub const fn new(
        channel_id: Option<YoutubeChannelId>,
        video_id: Option<YoutubeVideoId>,
        thread_id: YoutubeCommentThreadId,
    ) -> Self {
        Self {
            channel_id,
            video_id,
            thread_id,
        }
    }

    pub const fn channel_id(&self) -> Option<&YoutubeChannelId> {
        self.channel_id.as_ref()
    }

    pub const fn video_id(&self) -> Option<&YoutubeVideoId> {
        self.video_id.as_ref()
    }

    pub const fn thread_id(&self) -> &YoutubeCommentThreadId {
        &self.thread_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokAccountIdentity {
    open_id: TiktokOpenId,
}

impl TiktokAccountIdentity {
    pub const fn new(open_id: TiktokOpenId) -> Self {
        Self { open_id }
    }

    pub const fn open_id(&self) -> &TiktokOpenId {
        &self.open_id
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokCreatorIdentity {
    account: TiktokAccountIdentity,
    username: TiktokCreatorUsername,
}

impl TiktokCreatorIdentity {
    pub const fn new(account: TiktokAccountIdentity, username: TiktokCreatorUsername) -> Self {
        Self { account, username }
    }

    pub const fn account(&self) -> &TiktokAccountIdentity {
        &self.account
    }

    pub const fn username(&self) -> &TiktokCreatorUsername {
        &self.username
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::struct_field_names)]
pub struct TiktokContentIdentity {
    creator_open_id: TiktokOpenId,
    publish_id: TiktokPublishId,
    post_id: Option<TiktokPostId>,
}

impl TiktokContentIdentity {
    pub const fn new(
        creator_open_id: TiktokOpenId,
        publish_id: TiktokPublishId,
        post_id: Option<TiktokPostId>,
    ) -> Self {
        Self {
            creator_open_id,
            publish_id,
            post_id,
        }
    }

    pub const fn creator_open_id(&self) -> &TiktokOpenId {
        &self.creator_open_id
    }

    pub const fn publish_id(&self) -> &TiktokPublishId {
        &self.publish_id
    }

    pub const fn post_id(&self) -> Option<&TiktokPostId> {
        self.post_id.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditAccountIdentity {
    account_id: RedditAccountId,
    username: Option<String>,
}

impl RedditAccountIdentity {
    pub fn new(account_id: RedditAccountId, username: Option<String>) -> Self {
        Self {
            account_id,
            username,
        }
    }

    pub const fn account_id(&self) -> &RedditAccountId {
        &self.account_id
    }

    pub const fn username(&self) -> Option<&String> {
        self.username.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditCommunityIdentity {
    subreddit_id: RedditSubredditId,
    name: RedditSubredditName,
}

impl RedditCommunityIdentity {
    pub const fn new(subreddit_id: RedditSubredditId, name: RedditSubredditName) -> Self {
        Self { subreddit_id, name }
    }

    pub const fn subreddit_id(&self) -> &RedditSubredditId {
        &self.subreddit_id
    }

    pub const fn name(&self) -> &RedditSubredditName {
        &self.name
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedditThingKind {
    Post,
    Comment,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditContentIdentity {
    thing_id: RedditThingId,
    kind: RedditThingKind,
    subreddit_id: Option<RedditSubredditId>,
    parent_post_id: Option<RedditThingId>,
}

impl RedditContentIdentity {
    pub const fn new(
        thing_id: RedditThingId,
        kind: RedditThingKind,
        subreddit_id: Option<RedditSubredditId>,
        parent_post_id: Option<RedditThingId>,
    ) -> Self {
        Self {
            thing_id,
            kind,
            subreddit_id,
            parent_post_id,
        }
    }

    pub const fn thing_id(&self) -> &RedditThingId {
        &self.thing_id
    }

    pub const fn kind(&self) -> RedditThingKind {
        self.kind
    }

    pub const fn subreddit_id(&self) -> Option<&RedditSubredditId> {
        self.subreddit_id.as_ref()
    }

    pub const fn parent_post_id(&self) -> Option<&RedditThingId> {
        self.parent_post_id.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountIdentity {
    Youtube(YoutubeAccountIdentity),
    Tiktok(TiktokAccountIdentity),
    Reddit(RedditAccountIdentity),
}

impl AccountIdentity {
    pub const fn provider(&self) -> ProviderId {
        match self {
            Self::Youtube(_) => ProviderId::Youtube,
            Self::Tiktok(_) => ProviderId::Tiktok,
            Self::Reddit(_) => ProviderId::Reddit,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentity {
    Youtube(YoutubeChannelIdentity),
    Tiktok(TiktokCreatorIdentity),
    Reddit(RedditCommunityIdentity),
}

impl ChannelIdentity {
    pub const fn provider(&self) -> ProviderId {
        match self {
            Self::Youtube(_) => ProviderId::Youtube,
            Self::Tiktok(_) => ProviderId::Tiktok,
            Self::Reddit(_) => ProviderId::Reddit,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentIdentity {
    YoutubeVideo(YoutubeVideoIdentity),
    YoutubeComment(YoutubeCommentIdentity),
    Tiktok(TiktokContentIdentity),
    Reddit(RedditContentIdentity),
}

impl ContentIdentity {
    pub const fn provider(&self) -> ProviderId {
        match self {
            Self::YoutubeVideo(_) | Self::YoutubeComment(_) => ProviderId::Youtube,
            Self::Tiktok(_) => ProviderId::Tiktok,
            Self::Reddit(_) => ProviderId::Reddit,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct YoutubeRevisionIdentity {
    content: ContentIdentity,
    etag: YoutubeEtag,
    observed_at: DateTime<Utc>,
}

impl YoutubeRevisionIdentity {
    pub fn new(
        content: ContentIdentity,
        etag: YoutubeEtag,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, IdentityError> {
        if content.provider() != ProviderId::Youtube {
            return Err(IdentityError::UnsupportedCharacters);
        }
        Ok(Self {
            content,
            etag,
            observed_at,
        })
    }

    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn etag(&self) -> &YoutubeEtag {
        &self.etag
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct TiktokRevisionIdentity {
    content: ContentIdentity,
    state_key: String,
    observed_at: DateTime<Utc>,
}

impl TiktokRevisionIdentity {
    pub fn new(
        content: ContentIdentity,
        state_key: impl Into<String>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, IdentityError> {
        if content.provider() != ProviderId::Tiktok {
            return Err(IdentityError::UnsupportedCharacters);
        }
        let state_key = state_key.into();
        validate_identifier(&state_key, provider_identifier)?;
        Ok(Self {
            content,
            state_key,
            observed_at,
        })
    }

    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub fn state_key(&self) -> &str {
        &self.state_key
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct RedditRevisionIdentity {
    content: ContentIdentity,
    revision_key: RedditRevisionKey,
    observed_at: DateTime<Utc>,
}

impl RedditRevisionIdentity {
    pub fn new(
        content: ContentIdentity,
        revision_key: RedditRevisionKey,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, IdentityError> {
        if content.provider() != ProviderId::Reddit {
            return Err(IdentityError::UnsupportedCharacters);
        }
        Ok(Self {
            content,
            revision_key,
            observed_at,
        })
    }

    pub const fn content(&self) -> &ContentIdentity {
        &self.content
    }

    pub const fn revision_key(&self) -> &RedditRevisionKey {
        &self.revision_key
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionIdentity {
    Youtube(YoutubeRevisionIdentity),
    Tiktok(TiktokRevisionIdentity),
    Reddit(RedditRevisionIdentity),
}

impl RevisionIdentity {
    pub const fn provider(&self) -> ProviderId {
        match self {
            Self::Youtube(_) => ProviderId::Youtube,
            Self::Tiktok(_) => ProviderId::Tiktok,
            Self::Reddit(_) => ProviderId::Reddit,
        }
    }

    pub const fn content(&self) -> &ContentIdentity {
        match self {
            Self::Youtube(revision) => revision.content(),
            Self::Tiktok(revision) => revision.content(),
            Self::Reddit(revision) => revision.content(),
        }
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        match self {
            Self::Youtube(revision) => revision.observed_at(),
            Self::Tiktok(revision) => revision.observed_at(),
            Self::Reddit(revision) => revision.observed_at(),
        }
    }
}
