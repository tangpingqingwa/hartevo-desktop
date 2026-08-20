//! Secret-free deterministic YouTube provider worlds for contract tests.

use chrono::{DateTime, Utc};

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
