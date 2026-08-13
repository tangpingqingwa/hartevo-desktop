//! Deterministic YouTube provider worlds.
//!
//! These helpers are explicitly Fixture evidence. They never create a
//! ProductionProvider receipt and are rejected by the Mission consumer.

use chrono::{DateTime, Utc};

use crate::youtube::provider::YouTubeProviderResponse;

pub const FIXED_NOW_RFC3339: &str = "2026-01-02T03:04:05Z";

pub fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(FIXED_NOW_RFC3339)
        .expect("fixture timestamp is valid")
        .with_timezone(&Utc)
}

pub fn response(status: u16, body: &str) -> YouTubeProviderResponse {
    YouTubeProviderResponse::new(
        status,
        [("content-type".to_owned(), "application/json".to_owned())],
        body,
        fixed_now(),
    )
}

pub fn probe_response() -> YouTubeProviderResponse {
    response(
        200,
        r#"{
          "kind":"youtube#channelListResponse",
          "items":[{"id":"UCfixture01","snippet":{"title":"Fixture Channel"}}]
        }"#,
    )
}

pub fn upload_session_response() -> YouTubeProviderResponse {
    YouTubeProviderResponse::new(
        200,
        [
            ("content-type".to_owned(), "application/json".to_owned()),
            (
                "location".to_owned(),
                "https://uploads.youtube.test/session/fixture-upload-session-01".to_owned(),
            ),
        ],
        "{}",
        fixed_now(),
    )
}

pub fn upload_in_progress_response(uploaded_bytes: u64) -> YouTubeProviderResponse {
    let last_byte = uploaded_bytes.saturating_sub(1);
    YouTubeProviderResponse::new(
        308,
        [
            ("content-type".to_owned(), "application/json".to_owned()),
            ("range".to_owned(), format!("bytes=0-{last_byte}")),
        ],
        "",
        fixed_now(),
    )
}

pub fn upload_complete_response() -> YouTubeProviderResponse {
    response(
        201,
        r#"{
          "kind":"youtube#video",
          "id":"fixture-video-01"
        }"#,
    )
}

pub fn readback_response(
    title: &str,
    visibility: &str,
    processing_status: &str,
) -> YouTubeProviderResponse {
    let body = format!(
        r#"{{
          "kind":"youtube#videoListResponse",
          "items":[{{
            "id":"fixture-video-01",
            "snippet":{{"channelId":"UCfixture01","title":"{title}"}},
            "status":{{"uploadStatus":"uploaded","privacyStatus":"{visibility}"}},
            "processingDetails":{{"processingStatus":"{processing_status}"}}
          }}]
        }}"#
    );
    response(200, &body)
}

pub fn rate_limited_response() -> YouTubeProviderResponse {
    YouTubeProviderResponse::new(
        429,
        [
            ("content-type".to_owned(), "application/json".to_owned()),
            ("retry-after".to_owned(), "30".to_owned()),
        ],
        r#"{"error":{"errors":[{"reason":"userRateLimitExceeded"}]}}"#,
        fixed_now(),
    )
}

pub fn ambiguous_response() -> YouTubeProviderResponse {
    response(503, r#"{"error":{"status":"UNAVAILABLE"}}"#)
}
