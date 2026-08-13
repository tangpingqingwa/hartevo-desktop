use std::collections::{BTreeMap, BTreeSet};

use chrono::Duration;

use hartevo_channel_adapters::identity::{
    ContentIdentity, ProviderId, RedditCommunityIdentity, RedditSubredditId, RedditSubredditName,
    RevisionIdentity, TiktokPublishId, WebhookEventId, YoutubeChannelId, YoutubeVideoId,
};
use hartevo_channel_adapters::reddit::{
    RedditAuthorizationSnapshot, RedditDataApiApproval, RedditDevvitInstallation,
    RedditIntegrationMode, RedditModerationState, RedditReadPlan, RedditReadTarget, RedditScope,
    determine_integration_mode, parse_read_response as parse_reddit_response, plan_read,
};
use hartevo_channel_adapters::testkit::{
    fixed_now, reddit_community_response, reddit_me_response, reddit_removed_listing_response,
    tiktok_creator_info_response, tiktok_no_longer_public_webhook_response,
    tiktok_oauth_identity_response, tiktok_private_status_response, tiktok_public_status_response,
    youtube_analytics_response, youtube_channel_response, youtube_quota_response,
    youtube_revoked_response, youtube_video_response,
};
use hartevo_channel_adapters::tiktok::{
    TiktokAuditState, TiktokEffectiveVisibility, TiktokModerationState, TiktokScope,
    content_status_request, creator_info_request, parse_content_status, parse_creator_info,
    parse_oauth_identity, parse_webhook,
};
use hartevo_channel_adapters::transport::{
    AuthorizationReason, ChannelAdapterError, CredentialReference, HttpMethod, ProviderReadRequest,
    ProviderResponse, ReadOperation,
};
use hartevo_channel_adapters::webhook::{WebhookDisposition, WebhookEnvelope, WebhookLedger};
use hartevo_channel_adapters::youtube::{
    YoutubeAnalyticsDimension, YoutubeAnalyticsMetric, YoutubeAnalyticsQuery,
    YoutubeCommentModerationFilter, YoutubeQuotaLedger, YoutubeQuotaOperation, YoutubeReadTarget,
    YoutubeScope, channel_identity_request, parse_channel_identity, parse_read_response,
};

fn credential(name: &str) -> CredentialReference {
    CredentialReference::new(name.to_owned()).expect("fixture credential references are opaque")
}

fn youtube_channel_id() -> YoutubeChannelId {
    YoutubeChannelId::new("UCchannel01").expect("fixture channel id is valid")
}

fn reddit_community() -> RedditCommunityIdentity {
    RedditCommunityIdentity::new(
        RedditSubredditId::new("t5_sub01").expect("fixture subreddit id is valid"),
        RedditSubredditName::new("phaseone").expect("fixture subreddit name is valid"),
    )
}

#[test]
fn youtube_phase1_reads_identity_content_analytics_and_quota() {
    let request = channel_identity_request(credential("youtube-credential"))
        .expect("channel probe request is valid");
    assert_eq!(request.provider(), ProviderId::Youtube);
    assert_eq!(request.operation(), ReadOperation::Probe);
    assert_eq!(request.method(), HttpMethod::Get);
    assert!(request.url().as_str().contains("mine=true"));
    assert!(
        request
            .required_scopes()
            .iter()
            .any(|scope| scope.as_str() == YoutubeScope::YoutubeReadonly.as_str())
    );

    let channels = parse_channel_identity(&youtube_channel_response()).expect("channel parses");
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].channel().provider(), ProviderId::Youtube);

    let videos = YoutubeReadTarget::Videos {
        ids: vec![YoutubeVideoId::new("video01").expect("fixture video id is valid")],
    };
    let video_request = videos
        .request(credential("youtube-credential"))
        .expect("video read request is valid");
    assert_eq!(video_request.operation(), ReadOperation::Content);
    let video_result =
        parse_read_response(&videos, &youtube_video_response()).expect("video response parses");
    assert_eq!(video_result.observations().len(), 1);

    let comments = YoutubeReadTarget::CommentThreads {
        channel_id: Some(youtube_channel_id()),
        video_id: None,
        page_token: None,
        moderation: YoutubeCommentModerationFilter::Published,
    };
    let comment_request = comments
        .request(credential("youtube-credential"))
        .expect("comment read request is valid");
    assert!(
        comment_request
            .url()
            .as_str()
            .contains("moderationStatus=published")
    );

    let query = YoutubeAnalyticsQuery::new(
        youtube_channel_id(),
        chrono::NaiveDate::from_ymd_opt(2026, 1, 1).expect("fixture date is valid"),
        chrono::NaiveDate::from_ymd_opt(2026, 1, 2).expect("fixture date is valid"),
        vec![YoutubeAnalyticsMetric::new("views").expect("fixture metric is valid")],
        vec![YoutubeAnalyticsDimension::new("day").expect("fixture dimension is valid")],
        BTreeMap::new(),
        false,
    )
    .expect("analytics query is valid");
    let analytics = YoutubeReadTarget::Analytics(query);
    let analytics_request = analytics
        .request(credential("youtube-credential"))
        .expect("analytics request is valid");
    assert_eq!(analytics_request.operation(), ReadOperation::Analytics);
    assert!(
        analytics_request
            .required_scopes()
            .iter()
            .any(|scope| scope.as_str()
                == hartevo_channel_adapters::youtube::YOUTUBE_ANALYTICS_READONLY_SCOPE)
    );
    assert_eq!(
        parse_read_response(&analytics, &youtube_analytics_response())
            .expect("analytics response parses")
            .observations()
            .len(),
        1
    );

    let mut quota = YoutubeQuotaLedger::new(1);
    quota
        .reserve(YoutubeQuotaOperation::ChannelsList, fixed_now())
        .expect("one data API unit remains within the fixture limit");
    assert_eq!(quota.data_api_units_remaining(), 0);
    assert!(matches!(
        quota.reserve(YoutubeQuotaOperation::VideosList, fixed_now()),
        Err(ChannelAdapterError::QuotaExhausted { .. })
    ));
    quota
        .reserve(YoutubeQuotaOperation::AnalyticsReportQuery, fixed_now())
        .expect("analytics request count is tracked separately");
    assert_eq!(quota.analytics_request_count(), 1);
    assert!(matches!(
        parse_read_response(&videos, &youtube_quota_response()),
        Err(ChannelAdapterError::QuotaExhausted { .. })
    ));
    assert!(matches!(
        parse_read_response(&videos, &youtube_revoked_response()),
        Err(ChannelAdapterError::AuthorizationRequired {
            reason: AuthorizationReason::ScopeRevoked,
            ..
        })
    ));
}

#[test]
fn tiktok_phase1_tracks_oauth_approval_visibility_status_and_removal() {
    let all_scopes = BTreeSet::from([
        TiktokScope::UserInfoBasic,
        TiktokScope::VideoPublish,
        TiktokScope::VideoUpload,
    ]);
    let oauth = parse_oauth_identity(
        &tiktok_oauth_identity_response(),
        all_scopes.clone(),
        TiktokAuditState::Unaudited,
    )
    .expect("TikTok OAuth identity parses");
    let authorization = oauth.authorization().clone();
    assert_eq!(authorization.identity().open_id().as_str(), "open01");
    let creator_request = creator_info_request(&authorization, credential("tiktok-credential"))
        .expect("creator info request is valid");
    assert_eq!(creator_request.method(), HttpMethod::Post);
    assert_eq!(creator_request.operation(), ReadOperation::Identity);
    let creator = parse_creator_info(&authorization, &tiktok_creator_info_response())
        .expect("creator info parses");
    assert_eq!(
        creator.policy().effective_visibility(),
        TiktokEffectiveVisibility::PrivateOnlyUnaudited
    );

    let publish_id = TiktokPublishId::new("publish01").expect("fixture publish id is valid");
    let status_request =
        content_status_request(&authorization, &publish_id, credential("tiktok-credential"))
            .expect("status request is valid");
    assert_eq!(status_request.operation(), ReadOperation::Status);
    assert_eq!(
        status_request
            .body()
            .and_then(|body| body.get("publish_id"))
            .and_then(|id| id.as_str()),
        Some("publish01")
    );
    let private = parse_content_status(
        &authorization,
        publish_id.clone(),
        &tiktok_private_status_response(),
    )
    .expect("private status parses");
    assert_eq!(private.moderation(), TiktokModerationState::NotPublic);
    assert!(private.publicly_available_post_ids().is_empty());
    let public = parse_content_status(&authorization, publish_id, &tiktok_public_status_response())
        .expect("public status parses");
    assert_eq!(
        public.moderation(),
        TiktokModerationState::PubliclyAvailable
    );
    assert_eq!(public.publicly_available_post_ids()[0].as_str(), "post01");

    let removed = parse_webhook(&tiktok_no_longer_public_webhook_response())
        .expect("TikTok removal webhook parses");
    assert_eq!(
        removed.kind(),
        hartevo_channel_adapters::tiktok::TiktokWebhookKind::NoLongerPubliclyAvailable
    );
    assert_eq!(removed.content().post_id(), None);

    let no_upload_scope = BTreeSet::from([TiktokScope::UserInfoBasic]);
    let unauthorized = parse_oauth_identity(
        &tiktok_oauth_identity_response(),
        no_upload_scope,
        TiktokAuditState::Unknown,
    )
    .expect("OAuth identity still parses without publish approval");
    assert!(matches!(
        creator_info_request(
            &unauthorized.authorization().clone(),
            credential("tiktok-credential")
        ),
        Err(ChannelAdapterError::AuthorizationRequired {
            reason: AuthorizationReason::MissingApproval,
            ..
        })
    ));
}

#[test]
fn reddit_phase1_requires_approval_and_limits_official_surfaces() {
    let approval = RedditDataApiApproval::new(
        "reddit-approval-01",
        BTreeSet::from([RedditScope::Identity, RedditScope::Read]),
        fixed_now(),
    )
    .expect("fixture Reddit approval is valid");
    let community = reddit_community();
    let snapshot = RedditAuthorizationSnapshot::new(Some(approval), None);
    let mode = determine_integration_mode(&snapshot);
    assert!(matches!(mode, RedditIntegrationMode::DataApi(_)));

    let account_plan = plan_read(
        &mode,
        &RedditReadTarget::Account,
        Some(credential("reddit-credential")),
    )
    .expect("approved account read is planned");
    let RedditReadPlan::DataApi(account_request) = account_plan else {
        panic!("approved Data API mode must produce a Data API plan");
    };
    assert!(account_request.url().as_str().ends_with("/api/v1/me"));
    assert_eq!(
        parse_reddit_response(&RedditReadTarget::Account, &reddit_me_response())
            .expect("account response parses")
            .account()
            .expect("account observation exists")
            .account()
            .provider(),
        ProviderId::Reddit
    );

    let community_target = RedditReadTarget::Community {
        name: community.name().clone(),
    };
    let community_result = parse_reddit_response(&community_target, &reddit_community_response())
        .expect("community response parses");
    assert_eq!(
        community_result
            .community()
            .expect("community observation exists")
            .channel()
            .provider(),
        ProviderId::Reddit
    );
    let listing_target = RedditReadTarget::listing(community.name().clone(), None, 25)
        .expect("listing target is valid");
    let removed = parse_reddit_response(&listing_target, &reddit_removed_listing_response())
        .expect("moderation response parses");
    assert_eq!(
        removed.content()[0].moderation(),
        RedditModerationState::RemovedByModerator
    );

    let no_approval = determine_integration_mode(&RedditAuthorizationSnapshot::default());
    assert!(matches!(
        no_approval,
        RedditIntegrationMode::AuthorizationRequired {
            reason: AuthorizationReason::NoApprovedIntegration
        }
    ));
    assert!(matches!(
        plan_read(&no_approval, &RedditReadTarget::Account, None),
        Err(ChannelAdapterError::AuthorizationRequired {
            provider: ProviderId::Reddit,
            reason: AuthorizationReason::NoApprovedIntegration
        })
    ));

    let devvit = RedditDevvitInstallation::new("app-channel", "install-01", community, true)
        .expect("fixture Devvit installation is valid");
    let devvit_mode =
        determine_integration_mode(&RedditAuthorizationSnapshot::new(None, Some(devvit)));
    let devvit_plan = plan_read(
        &devvit_mode,
        &RedditReadTarget::Community {
            name: RedditSubredditName::new("phaseone").expect("fixture name is valid"),
        },
        None,
    )
    .expect("approved Devvit community read is planned");
    assert!(matches!(devvit_plan, RedditReadPlan::Devvit(_)));
    assert!(matches!(
        plan_read(&devvit_mode, &RedditReadTarget::Account, None),
        Err(ChannelAdapterError::UnsupportedSurface { .. })
    ));
}

#[test]
fn exact_webhook_identity_deduplicates_and_marks_late_delivery() {
    let observed = hartevo_channel_adapters::tiktok::parse_webhook(
        &hartevo_channel_adapters::testkit::tiktok_publicly_available_webhook_response(),
    )
    .expect("TikTok webhook parses");
    let received_at = fixed_now();
    let applied = observed
        .envelope(received_at, received_at)
        .expect("webhook envelope identity is exact");
    let late = WebhookEnvelope::new(
        WebhookEventId::new("late-event").expect("fixture event id is valid"),
        ProviderId::Tiktok,
        ContentIdentity::Tiktok(observed.content().clone()),
        RevisionIdentity::Tiktok(observed.revision().clone()),
        received_at - Duration::minutes(1),
        received_at,
    )
    .expect("late envelope remains valid");
    let mut ledger = WebhookLedger::default();
    assert_eq!(ledger.ingest(&applied), WebhookDisposition::Applied);
    assert_eq!(ledger.ingest(&applied), WebhookDisposition::Duplicate);
    assert_eq!(ledger.ingest(&late), WebhookDisposition::Late);
    assert_eq!(ledger.seen_event_count(), 2);
}

#[test]
fn transport_rejects_secret_bodies_and_redacts_debug() {
    assert!(CredentialReference::new("Bearer raw-token").is_err());
    let url = url::Url::parse("https://example.invalid/read").expect("fixture URL is valid");
    assert!(
        ProviderReadRequest::new(
            ProviderId::Tiktok,
            ReadOperation::Status,
            HttpMethod::Post,
            url.clone(),
            [],
            credential("fixture-credential"),
            Some(serde_json::json!({"access_token":"secret"})),
        )
        .is_err()
    );
    let response = ProviderResponse::new(
        200,
        [],
        r#"{"access_token":"secret","refresh_token":"secret-2"}"#,
        fixed_now(),
    );
    let debug = format!("{response:?}");
    assert!(!debug.contains("secret"));
    assert!(!format!("{response:?}").contains("access_token"));
    let _ = response;
}
