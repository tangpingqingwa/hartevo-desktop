//! Secret-free deterministic provider worlds for phase-one contract tests.

use chrono::{DateTime, Utc};

use crate::identity::ProviderId;
use crate::transport::ProviderResponse;

pub const FIXED_NOW_RFC3339: &str = "2026-01-02T03:04:05Z";

pub fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(FIXED_NOW_RFC3339)
        .expect("the deterministic fixture timestamp is valid")
        .with_timezone(&Utc)
}

pub fn response(status: u16, body: &str) -> ProviderResponse {
    ProviderResponse::new(
        status,
        [("content-type".to_owned(), "application/json".to_owned())],
        body,
        fixed_now(),
    )
}

pub fn youtube_channel_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "etag":"channel-list-etag-1",
          "items":[{
            "id":"UCchannel01",
            "etag":"channel-etag-1",
            "contentDetails":{"relatedPlaylists":{"uploads":"UUchannel01"}}
          }]
        }"#,
    )
}

pub fn youtube_video_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "etag":"video-list-etag-1",
          "items":[{
            "id":"video01",
            "etag":"video-etag-1",
            "snippet":{"channelId":"UCchannel01"},
            "statistics":{"viewCount":"42","likeCount":"3","commentCount":"1"},
            "status":{"privacyStatus":"public","uploadStatus":"processed"}
          }]
        }"#,
    )
}

pub fn youtube_comment_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "nextPageToken":"comments-page-2",
          "items":[{
            "id":"thread01",
            "etag":"comment-etag-1",
            "snippet":{"channelId":"UCchannel01","videoId":"video01","moderationStatus":"published"}
          }]
        }"#,
    )
}

pub fn youtube_analytics_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "columnHeaders":[{"name":"views"},{"name":"likes"}],
          "rows":[["42","3"]]
        }"#,
    )
}

pub fn youtube_quota_response() -> ProviderResponse {
    response(403, r#"{"error":{"errors":[{"reason":"quotaExceeded"}]}}"#)
}

pub fn youtube_revoked_response() -> ProviderResponse {
    response(401, r#"{"error":{"errors":[{"reason":"invalidToken"}]}}"#)
}

pub fn tiktok_oauth_identity_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "open_id":"open01",
          "scope":"user.info.basic,video.publish,video.upload",
          "expires_in":86400,
          "refresh_expires_in":31536000
        }"#,
    )
}

pub fn tiktok_creator_info_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":{
            "creator_username":"creator01",
            "privacy_level_options":["PUBLIC_TO_EVERYONE","SELF_ONLY"],
            "comment_disabled":false,
            "duet_disabled":true,
            "stitch_disabled":false,
            "max_video_post_duration_sec":60
          },
          "error":{"code":"ok","message":""}
        }"#,
    )
}

pub fn tiktok_private_status_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":{
            "status":"PUBLISH_COMPLETE",
            "publicaly_available_post_id":[],
            "uploaded_bytes":"12",
            "downloaded_bytes":"12"
          }
        }"#,
    )
}

pub fn tiktok_public_status_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":{
            "status":"PUBLISH_COMPLETE",
            "publicaly_available_post_id":["post01"],
            "uploaded_bytes":"12",
            "downloaded_bytes":"12"
          }
        }"#,
    )
}

pub fn tiktok_publicly_available_webhook_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "event":"post.publish.publicly_available",
          "publish_id":"publish01",
          "post_id":"post01",
          "open_id":"open01"
        }"#,
    )
}

pub fn tiktok_no_longer_public_webhook_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "event":"post.publish.no_longer_publicaly_available",
          "publish_id":"publish01",
          "open_id":"open01"
        }"#,
    )
}

pub fn reddit_me_response() -> ProviderResponse {
    response(200, r#"{"id":"account01","name":"builder01"}"#)
}

pub fn reddit_community_response() -> ProviderResponse {
    response(
        200,
        r#"{"kind":"t5","data":{"id":"t5_sub01","display_name":"phaseone"}}"#,
    )
}

pub fn reddit_visible_listing_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":{
            "children":[{
              "kind":"t3",
              "data":{
                "name":"t3_post01",
                "subreddit_id":"t5_sub01",
                "author":"builder01",
                "selftext":"hello",
                "edited":false,
                "deleted":false,
                "locked":false
              }
            }]
          }
        }"#,
    )
}

pub fn reddit_removed_listing_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":{
            "children":[{
              "kind":"t3",
              "data":{
                "name":"t3_post01",
                "subreddit_id":"t5_sub01",
                "author":null,
                "selftext":"[removed]",
                "removed_by_category":"moderator",
                "edited":false,
                "deleted":false,
                "locked":false
              }
            }]
          }
        }"#,
    )
}

pub fn reddit_info_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":[{
            "kind":"t3",
            "data":{
              "name":"t3_post01",
              "subreddit_id":"t5_sub01",
              "author":"builder01",
              "selftext":"hello",
              "edited":false,
              "deleted":false,
              "locked":false
            }
          }]
        }"#,
    )
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DeterministicWorld {
    YoutubeHealthyRead,
    YoutubeQuotaExhausted,
    YoutubeCredentialRevoked,
    TiktokUnauditedPrivate,
    TiktokModerationRemoval,
    RedditAuthorizationRequired,
    RedditModerationRemoval,
    LateWebhookDelivery,
}

impl DeterministicWorld {
    pub const fn provider(self) -> Option<ProviderId> {
        match self {
            Self::YoutubeHealthyRead
            | Self::YoutubeQuotaExhausted
            | Self::YoutubeCredentialRevoked => Some(ProviderId::Youtube),
            Self::TiktokUnauditedPrivate | Self::TiktokModerationRemoval => {
                Some(ProviderId::Tiktok)
            }
            Self::RedditAuthorizationRequired | Self::RedditModerationRemoval => {
                Some(ProviderId::Reddit)
            }
            Self::LateWebhookDelivery => None,
        }
    }
}
