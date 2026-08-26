//! Exact YouTube account/channel/content/revision identity types.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderId {
    Youtube,
}

impl ProviderId {
    pub const fn as_str(self) -> &'static str {
        "youtube"
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
pub enum AccountIdentity {
    Youtube(YoutubeAccountIdentity),
}

impl AccountIdentity {
    pub const fn provider(&self) -> ProviderId {
        ProviderId::Youtube
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentity {
    Youtube(YoutubeChannelIdentity),
}

impl ChannelIdentity {
    pub const fn provider(&self) -> ProviderId {
        ProviderId::Youtube
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentIdentity {
    YoutubeVideo(YoutubeVideoIdentity),
    YoutubeComment(YoutubeCommentIdentity),
}

impl ContentIdentity {
    pub const fn provider(&self) -> ProviderId {
        ProviderId::Youtube
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
pub enum RevisionIdentity {
    Youtube(YoutubeRevisionIdentity),
}

impl RevisionIdentity {
    pub const fn provider(&self) -> ProviderId {
        ProviderId::Youtube
    }

    pub const fn content(&self) -> &ContentIdentity {
        match self {
            Self::Youtube(revision) => revision.content(),
        }
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        match self {
            Self::Youtube(revision) => revision.observed_at(),
        }
    }
}
