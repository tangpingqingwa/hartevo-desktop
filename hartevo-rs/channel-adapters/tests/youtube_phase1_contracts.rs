use std::collections::BTreeMap;

use chrono::NaiveDate;
use hartevo_channel_adapters::identity::{
    ChannelIdentity, ProviderId, YoutubeChannelId, YoutubeVideoId,
};
use hartevo_channel_adapters::testkit::{
    fixed_now, youtube_analytics_response, youtube_channel_response, youtube_comment_response,
    youtube_quota_response, youtube_revoked_response, youtube_video_response,
};
use hartevo_channel_adapters::transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderReadRequest,
    ProviderResponse, ReadOnlyTransport, ReadOperation, TransportError,
};
use hartevo_channel_adapters::youtube::{
    YoutubeAnalyticsDimension, YoutubeAnalyticsMetric, YoutubeAnalyticsQuery,
    YoutubeCommentModerationFilter, YoutubeQuotaLedger, YoutubeQuotaOperation,
    YoutubeReadObservation, YoutubeReadTarget, YoutubeScope, YoutubeVisibility,
    channel_identity_request, parse_channel_identity, parse_read_response,
};
use hartevo_channel_adapters::youtube_read::{YoutubeReadConsumer, YoutubeReadService};
use serde_json::json;
use url::Url;

fn fixture_credential() -> CredentialReference {
    CredentialReference::new("secret://youtube-account-01")
        .expect("fixture credential reference is opaque")
}

#[test]
fn youtube_channel_probe_preserves_account_and_channel_identity() {
    let credential = fixture_credential();
    let channel_request = channel_identity_request(credential.clone()).expect("channel request");
    assert_eq!(channel_request.provider(), ProviderId::Youtube);
    assert_eq!(channel_request.operation(), ReadOperation::Probe);
    assert_eq!(channel_request.method(), HttpMethod::Get);
    assert!(
        channel_request
            .url()
            .query_pairs()
            .any(|(key, value)| key == "mine" && value == "true")
    );
    assert_eq!(channel_request.required_scopes().len(), 1);

    let channels = parse_channel_identity(&youtube_channel_response()).expect("channel response");
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].account().provider(), ProviderId::Youtube);
    assert_eq!(channels[0].channel().provider(), ProviderId::Youtube);
    assert_eq!(channels[0].observed_at(), fixed_now());
}

#[test]
fn youtube_content_reads_preserve_revision_visibility_and_moderation() {
    let credential = fixture_credential();
    let video_id = YoutubeVideoId::new("video01").expect("fixture video id");
    let videos_target = YoutubeReadTarget::Videos {
        ids: vec![video_id.clone()],
    };
    let videos_request = videos_target
        .request(credential.clone())
        .expect("videos request");
    assert_eq!(videos_request.operation(), ReadOperation::Content);
    let videos = parse_read_response(&videos_target, &youtube_video_response()).expect("videos");
    assert_eq!(videos.observations().len(), 1);
    match &videos.observations()[0] {
        YoutubeReadObservation::Video(video) => {
            assert_eq!(video.identity().video_id(), &video_id);
            assert_eq!(video.identity().channel_id().as_str(), "UCchannel01");
            assert_eq!(video.revision().observed_at(), fixed_now());
            assert_eq!(video.visibility(), YoutubeVisibility::Public);
        }
        other => panic!("expected video observation, got {other:?}"),
    }

    let comments_target = YoutubeReadTarget::CommentThreads {
        channel_id: None,
        video_id: Some(video_id),
        page_token: None,
        moderation: YoutubeCommentModerationFilter::Published,
    };
    let comments_request = comments_target
        .request(credential.clone())
        .expect("comments request");
    assert!(
        comments_request
            .url()
            .query_pairs()
            .any(|(key, value)| key == "moderationStatus" && value == "published")
    );
    let comments =
        parse_read_response(&comments_target, &youtube_comment_response()).expect("comments");
    assert_eq!(comments.next_page_token(), Some("comments-page-2"));
    assert!(matches!(
        comments.observations().first(),
        Some(YoutubeReadObservation::Comment(comment))
            if comment.revision().observed_at() == fixed_now()
    ));
}

#[test]
fn youtube_analytics_and_data_api_quota_are_distinct() {
    let credential = fixture_credential();
    let channel_id = YoutubeChannelId::new("UCchannel01").expect("fixture channel id");
    let query = YoutubeAnalyticsQuery::new(
        channel_id,
        NaiveDate::from_ymd_opt(2026, 1, 1).expect("date"),
        NaiveDate::from_ymd_opt(2026, 1, 2).expect("date"),
        vec![YoutubeAnalyticsMetric::new("views").expect("metric")],
        vec![YoutubeAnalyticsDimension::new("day").expect("dimension")],
        BTreeMap::new(),
        false,
    )
    .expect("analytics query");
    let analytics_target = YoutubeReadTarget::Analytics(query);
    let analytics_request = analytics_target
        .request(credential.clone())
        .expect("analytics request");
    assert_eq!(analytics_request.required_scopes().len(), 1);
    assert_eq!(
        analytics_request
            .required_scopes()
            .first()
            .expect("analytics scope")
            .as_str(),
        YoutubeScope::AnalyticsReadonly.as_str()
    );
    let analytics =
        parse_read_response(&analytics_target, &youtube_analytics_response()).expect("analytics");
    match analytics.observations().first() {
        Some(YoutubeReadObservation::Analytics(observation)) => {
            assert_eq!(observation.rows().len(), 1);
            assert_eq!(observation.rows()[0], vec!["42".to_owned(), "3".to_owned()]);
        }
        other => panic!("expected analytics observation, got {other:?}"),
    }

    let mut quota = YoutubeQuotaLedger::new(1);
    quota
        .reserve(YoutubeQuotaOperation::ChannelsList, fixed_now())
        .expect("first data API unit");
    quota
        .reserve(YoutubeQuotaOperation::AnalyticsReportQuery, fixed_now())
        .expect("analytics quota is tracked separately");
    assert_eq!(quota.data_api_units_used(), 1);
    assert_eq!(quota.analytics_request_count(), 1);
    assert!(matches!(
        quota.reserve(YoutubeQuotaOperation::VideosList, fixed_now()),
        Err(ChannelAdapterError::QuotaExhausted {
            provider: ProviderId::Youtube,
            ..
        })
    ));

    let videos_target = YoutubeReadTarget::Videos {
        ids: vec![YoutubeVideoId::new("video01").expect("fixture video id")],
    };
    assert!(matches!(
        parse_read_response(&videos_target, &youtube_quota_response()),
        Err(ChannelAdapterError::QuotaExhausted {
            provider: ProviderId::Youtube,
            ..
        })
    ));
    assert!(matches!(
        parse_read_response(&videos_target, &youtube_revoked_response()),
        Err(ChannelAdapterError::AuthorizationRequired {
            provider: ProviderId::Youtube,
            reason: AuthorizationReason::ScopeRevoked,
        })
    ));
}

#[test]
fn youtube_requests_use_opaque_credentials_and_https_only() {
    let credential = CredentialReference::new("secret://youtube-account-01")
        .expect("fixture credential reference is opaque");
    assert_eq!(format!("{credential:?}"), "CredentialReference(<opaque>)");

    let target = YoutubeReadTarget::Videos {
        ids: vec![YoutubeVideoId::new("video01").expect("fixture video id")],
    };
    let request = target.request(credential).expect("request");
    let debug = format!("{request:?}");
    assert!(!debug.contains("secret://youtube-account-01"));
    assert_eq!(request.url().scheme(), "https");

    let rejected = hartevo_channel_adapters::transport::ProviderReadRequest::new(
        ProviderId::Youtube,
        ReadOperation::Content,
        HttpMethod::Get,
        Url::parse("https://www.googleapis.com/youtube/v3/videos").expect("url"),
        [],
        CredentialReference::new("secret://youtube-account-01").expect("credential"),
        Some(json!({ "access_token": "must-not-enter-a-request" })),
    );
    assert!(matches!(
        rejected,
        Err(ChannelAdapterError::InvalidRequest(
            "read-only request body contains secret material"
        ))
    ));
}

#[derive(Debug)]
struct FixtureTransport {
    response: Option<ProviderResponse>,
}

impl ReadOnlyTransport for FixtureTransport {
    fn send(&mut self, _request: &ProviderReadRequest) -> Result<ProviderResponse, TransportError> {
        self.response.take().ok_or(TransportError::Unavailable)
    }
}

#[test]
fn youtube_service_dispatches_read_and_consumer_requires_exact_channel() {
    let channels = parse_channel_identity(&youtube_channel_response()).expect("channel response");
    let channel = match channels[0].channel() {
        ChannelIdentity::Youtube(channel) => channel.clone(),
    };
    let target = YoutubeReadTarget::Videos {
        ids: vec![YoutubeVideoId::new("video01").expect("fixture video id")],
    };
    let mut service = YoutubeReadService::with_quota(
        FixtureTransport {
            response: Some(youtube_video_response()),
        },
        YoutubeQuotaLedger::new(1),
    );
    let result = service
        .read(&target, fixture_credential(), fixed_now())
        .expect("fixture transport read");
    assert_eq!(service.quota().data_api_units_used(), 1);

    let consumer = YoutubeReadConsumer::for_channel(channel);
    let accepted = consumer
        .accept(result.observations()[0].clone())
        .expect("exact channel observation");
    assert_eq!(accepted.account().provider(), ProviderId::Youtube);
    assert_eq!(accepted.channel().provider(), ProviderId::Youtube);

    let wrong_channel = hartevo_channel_adapters::transport::ProviderResponse::new(
        200,
        [("content-type".to_owned(), "application/json".to_owned())],
        r#"{"items":[{"id":"video02","etag":"video-etag-2","snippet":{"channelId":"UCother01"},"status":{"privacyStatus":"public","uploadStatus":"processed"}}]}"#,
        fixed_now(),
    );
    let wrong = parse_read_response(&target, &wrong_channel).expect("wrong channel parses");
    assert!(matches!(
        consumer.accept(wrong.observations()[0].clone()),
        Err(ChannelAdapterError::InvalidResponse {
            field,
            provider: ProviderId::Youtube,
        }) if field == "consumer.channel_id_mismatch"
    ));
}
