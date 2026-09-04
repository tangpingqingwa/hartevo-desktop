//! Deterministic TikTok response worlds.
//!
//! These responses are explicitly fixture provenance. They are useful for
//! contract replay, but the authenticated service only labels them
//! [`super::EvidenceProvenance::Fixture`], never `ProductionProvider`.

use chrono::{DateTime, Utc};

use crate::transport::ProviderResponse;

#[cfg(feature = "production-testkit")]
use std::collections::VecDeque;

#[cfg(feature = "production-testkit")]
use crate::transport::{ProviderReadRequest, ReadOnlyTransport, TransportError};

#[cfg(feature = "production-testkit")]
use super::{
    OAuthCredential, TiktokAuthenticatedReadService, TiktokError, TiktokFreshnessPolicy,
    TiktokMissionPageProgress, TiktokReadScope, TiktokRealReadGate, TiktokVideoSequenceSession,
};

pub const FIXED_NOW_RFC3339: &str = "2026-01-02T03:04:05Z";

pub fn fixed_now() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(FIXED_NOW_RFC3339)
        .expect("fixture timestamp is valid")
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

pub fn profile_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":{"user":{"open_id":"open01","display_name":"Creator 01"}},
          "error":{"code":"ok","message":"","log_id":"fixture-profile-01"}
        }"#,
    )
}

pub fn first_video_page_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":{
            "videos":[{
              "id":"7340000000000000001",
              "create_time":1767301445,
              "title":"First fixture video",
              "video_description":"Deterministic fixture",
              "share_url":"https://www.tiktok.com/@creator/video/7340000000000000001",
              "like_count":11,
              "comment_count":2,
              "share_count":3,
              "view_count":101
            }],
            "cursor":1767301445000,
            "has_more":true
          },
          "error":{"code":"ok","message":"","log_id":"fixture-list-01"}
        }"#,
    )
}

pub fn final_video_page_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":{
            "videos":[{
              "id":"7340000000000000002",
              "create_time":1767300445,
              "title":"Second fixture video",
              "video_description":"Second deterministic fixture",
              "share_url":"https://www.tiktok.com/@creator/video/7340000000000000002",
              "like_count":12,
              "comment_count":4,
              "share_count":5,
              "view_count":202
            }],
            "cursor":1767300445000,
            "has_more":false
          },
          "error":{"code":"ok","message":"","log_id":"fixture-list-02"}
        }"#,
    )
}

pub fn query_video_response() -> ProviderResponse {
    response(
        200,
        r#"{
          "data":{"videos":[{
            "id":"7340000000000000001",
            "create_time":1767301445,
            "title":"First fixture video refreshed",
            "video_description":"Updated deterministic fixture",
            "share_url":"https://www.tiktok.com/@creator/video/7340000000000000001",
            "like_count":21,
            "comment_count":5,
            "share_count":8,
            "view_count":303
          }]},
          "error":{"code":"ok","message":"","log_id":"fixture-query-01"}
        }"#,
    )
}

pub fn revoked_response() -> ProviderResponse {
    response(
        401,
        r#"{"error":{"code":"access_token_invalid","message":"invalid","log_id":"fixture-revoked"}}"#,
    )
}

pub fn missing_scope_response() -> ProviderResponse {
    response(
        401,
        r#"{"error":{"code":"scope_not_authorized","message":"missing","log_id":"fixture-scope"}}"#,
    )
}

pub fn rate_limited_response() -> ProviderResponse {
    ProviderResponse::new(
        429,
        [
            ("content-type".to_owned(), "application/json".to_owned()),
            ("retry-after".to_owned(), "30".to_owned()),
        ],
        r#"{"error":{"code":"rate_limit_exceeded","message":"slow down","log_id":"fixture-rate"}}"#,
        fixed_now(),
    )
}

/// Build deterministic production-provenance checkpoints for downstream
/// integration tests. This seam exists only behind the explicit test feature;
/// production callers must use `execute_real_read_gate` and a native transport.
#[cfg(feature = "production-testkit")]
pub fn production_sequence_checkpoints(
    scope: &TiktokReadScope,
    credential: &OAuthCredential,
    now: DateTime<Utc>,
) -> Result<(String, String), TiktokError> {
    struct SequenceTransport {
        responses: VecDeque<ProviderResponse>,
    }

    impl ReadOnlyTransport for SequenceTransport {
        fn send(
            &mut self,
            _request: &ProviderReadRequest,
        ) -> Result<ProviderResponse, TransportError> {
            self.responses
                .pop_front()
                .ok_or(TransportError::Unavailable)
        }
    }

    fn at(response: &ProviderResponse, now: DateTime<Utc>) -> ProviderResponse {
        ProviderResponse::new(
            response.status(),
            [("content-type".to_owned(), "application/json".to_owned())],
            response
                .json_value()
                .expect("built-in TikTok fixture JSON is valid")
                .to_string(),
            now,
        )
    }

    credential.require_for(super::TiktokApiOperation::VideoList, scope, now)?;
    let gate = TiktokRealReadGate::from_environment_values(
        Some("1"),
        Some(credential.secret_reference().as_str()),
    )?;
    let mut service = TiktokAuthenticatedReadService::production(
        SequenceTransport {
            responses: [
                at(&first_video_page_response(), now),
                at(&final_video_page_response(), now),
            ]
            .into_iter()
            .collect(),
        },
        gate,
        TiktokFreshnessPolicy::default(),
    );
    let mut session = TiktokVideoSequenceSession::new(scope.clone(), 20)?;
    if !matches!(
        service.read_video_sequence_step(credential, &mut session, now)?,
        TiktokMissionPageProgress::Pending { .. }
    ) {
        return Err(TiktokError::CursorCheckpointIncompatible);
    }
    let pending = session.checkpoint_json()?;
    if !matches!(
        service.read_video_sequence_step(credential, &mut session, now)?,
        TiktokMissionPageProgress::Complete(_)
    ) {
        return Err(TiktokError::CursorCheckpointIncompatible);
    }
    Ok((pending, session.checkpoint_json()?))
}
