use chrono::Duration;

use hartevo_channel_adapters::identity::{
    ProviderId, WebhookEventId, YoutubeChannelId, YoutubeChannelIdentity, YoutubeEtag,
    YoutubePlaylistId, YoutubeVideoId,
};
use hartevo_channel_adapters::testkit::{
    fixed_now, youtube_uploads_response, youtube_video_response,
};
use hartevo_channel_adapters::transport::{
    ChannelAdapterError, CredentialReference, ProviderReadRequest, ProviderResponse,
    ReadOnlyTransport, TransportError,
};
use hartevo_channel_adapters::youtube::{YoutubeReadTarget, parse_read_response};
use hartevo_channel_adapters::youtube_sync::{
    YoutubeCursorDisposition, YoutubeDurableCursor, YoutubeFreshnessPolicy, YoutubeRealReadGate,
    YoutubeReconciliationDisposition, YoutubeReconciliationLedger, YoutubeReconciliationSource,
    YoutubeWebhookHint, execute_env_gated_incremental_read, parse_incremental_page,
};

fn credential(name: &str) -> CredentialReference {
    CredentialReference::new(name.to_owned()).expect("fixture credential references are opaque")
}

fn channel() -> YoutubeChannelIdentity {
    YoutubeChannelIdentity::new(
        YoutubeChannelId::new("UCchannel01").expect("fixture channel id is valid"),
        YoutubeEtag::new("channel-etag-1").expect("fixture channel etag is valid"),
        Some(YoutubePlaylistId::new("UUchannel01").expect("fixture playlist id is valid")),
    )
}

fn video_target() -> YoutubeReadTarget {
    YoutubeReadTarget::Videos {
        ids: vec![YoutubeVideoId::new("video01").expect("fixture video id is valid")],
    }
}

#[test]
fn youtube_cursor_replay_is_durable_and_freshness_is_bounded() {
    let now = fixed_now();
    let freshness = YoutubeFreshnessPolicy::new(Duration::minutes(2))
        .expect("fixture freshness policy is positive");
    let mut cursor = YoutubeDurableCursor::new(channel(), now, &freshness)
        .expect("uploads cursor has an exact playlist identity");
    let page = parse_incremental_page(&cursor, &youtube_uploads_response())
        .expect("uploads page parses into exact video identities");
    assert_eq!(page.observations().len(), 1);
    assert_eq!(
        page.observations()[0].identity().video_id().as_str(),
        "video01"
    );

    let request = cursor
        .read_target(50)
        .expect("cursor creates a bounded playlist read target")
        .request(credential("youtube-credential"))
        .expect("playlist read request is valid");
    assert!(request.url().path().ends_with("/playlistItems"));
    assert!(request.url().as_str().contains("maxResults=50"));
    assert_eq!(request.provider(), ProviderId::Youtube);

    assert_eq!(
        cursor
            .apply_page(cursor.generation(), &page, &freshness)
            .expect("first page commits"),
        YoutubeCursorDisposition::Applied
    );
    assert_eq!(cursor.generation(), 1);
    assert_eq!(
        cursor
            .next_page_token()
            .map(hartevo_channel_adapters::youtube::YoutubePageToken::as_str),
        Some("uploads-page-2")
    );
    let checkpoint = cursor
        .checkpoint_json()
        .expect("cursor checkpoint serializes without secrets");
    let restored = YoutubeDurableCursor::from_checkpoint_json(&checkpoint)
        .expect("cursor checkpoint restores with validation");
    assert_eq!(restored, cursor);
    assert_eq!(restored.durable_digest(), cursor.durable_digest());

    assert_eq!(
        cursor
            .apply_page(cursor.generation(), &page, &freshness)
            .expect("replaying the same provider page is idempotent"),
        YoutubeCursorDisposition::Duplicate
    );
    assert_eq!(
        cursor.checkpoint_json().expect("checkpoint remains valid"),
        checkpoint
    );
    assert!(cursor.require_fresh(now + Duration::minutes(1)).is_ok());
    assert!(matches!(
        cursor.require_fresh(now + Duration::minutes(2)),
        Err(ChannelAdapterError::FreshnessExpired {
            provider: ProviderId::Youtube,
            ..
        })
    ));
    assert!(matches!(
        cursor.apply_page(0, &page, &freshness),
        Ok(YoutubeCursorDisposition::Duplicate)
    ));
}

#[test]
fn youtube_webhook_hint_requires_poll_and_late_reads_do_not_regress_head() {
    let now = fixed_now();
    let channel_id = YoutubeChannelId::new("UCchannel01").expect("fixture channel id is valid");
    let video_id = YoutubeVideoId::new("video01").expect("fixture video id is valid");
    let hint = YoutubeWebhookHint::new(
        WebhookEventId::new("youtube-event-01").expect("fixture event id is valid"),
        channel_id.clone(),
        video_id.clone(),
        now,
        now,
    )
    .expect("webhook hint has ordered delivery timestamps");
    let mut ledger = YoutubeReconciliationLedger::default();
    let applied = ledger.ingest_webhook_hint(&hint);
    assert_eq!(
        applied.disposition(),
        YoutubeReconciliationDisposition::Applied
    );
    assert_eq!(applied.source(), YoutubeReconciliationSource::WebhookHint);
    assert!(applied.head().is_none());
    assert!(applied.poll_required());
    assert_eq!(ledger.pending_poll_count(), 1);

    let duplicate = ledger.ingest_webhook_hint(&hint);
    assert_eq!(
        duplicate.disposition(),
        YoutubeReconciliationDisposition::Duplicate
    );
    assert!(duplicate.poll_required());
    let poll_request = ledger
        .poll_request(credential("youtube-credential"), 50)
        .expect("webhook pending video creates a bounded readback request");
    assert!(poll_request.url().path().ends_with("/videos"));
    assert!(poll_request.url().as_str().contains("id=video01"));

    let current = parse_read_response(&video_target(), &youtube_video_response())
        .expect("current video poll parses");
    let current_outcomes = ledger
        .apply_poll_result(&current)
        .expect("current poll observations reconcile");
    assert_eq!(current_outcomes.len(), 1);
    assert_eq!(
        current_outcomes[0].disposition(),
        YoutubeReconciliationDisposition::Applied
    );
    assert_eq!(ledger.pending_poll_count(), 0);
    let content = current_outcomes[0].content().clone();
    let head_before_late = ledger
        .head(&content)
        .expect("poll creates exact head")
        .clone();
    assert_eq!(head_before_late.source(), YoutubeReconciliationSource::Poll);

    let late_response = ProviderResponse::new(
        200,
        [("content-type".to_owned(), "application/json".to_owned())],
        r#"{
          "items":[{
            "id":"video01",
            "etag":"video-etag-1",
            "snippet":{"channelId":"UCchannel01"},
            "status":{"privacyStatus":"private","uploadStatus":"processed"}
          }]
        }"#,
        now - Duration::minutes(1),
    );
    let late = parse_read_response(&video_target(), &late_response)
        .expect("late video poll still parses as an observation");
    let late_outcome = ledger
        .apply_poll_result(&late)
        .expect("late poll remains a typed reconciliation outcome");
    assert_eq!(
        late_outcome[0].disposition(),
        YoutubeReconciliationDisposition::Late
    );
    assert_eq!(ledger.head(&content), Some(&head_before_late));

    let late_hint = YoutubeWebhookHint::new(
        WebhookEventId::new("youtube-event-late").expect("fixture event id is valid"),
        channel_id,
        video_id,
        now - Duration::minutes(1),
        now,
    )
    .expect("late webhook hint remains admissible");
    let late_hint_outcome = ledger.ingest_webhook_hint(&late_hint);
    assert_eq!(
        late_hint_outcome.disposition(),
        YoutubeReconciliationDisposition::Late
    );
    assert!(late_hint_outcome.poll_required());
}

struct FixtureTransport {
    response: Option<ProviderResponse>,
    request: Option<String>,
}

impl ReadOnlyTransport for FixtureTransport {
    fn send(&mut self, request: &ProviderReadRequest) -> Result<ProviderResponse, TransportError> {
        self.request = Some(request.to_string());
        self.response.take().ok_or(TransportError::Unavailable)
    }
}

#[test]
fn youtube_real_read_requires_explicit_gate_and_accounts_quota() {
    assert!(matches!(
        YoutubeRealReadGate::from_environment_values(Some("0"), Some("youtube-credential")),
        Err(ChannelAdapterError::BlockedEnvironment {
            provider: ProviderId::Youtube,
            ..
        })
    ));
    assert!(matches!(
        YoutubeRealReadGate::from_environment_values(Some("1"), None),
        Err(ChannelAdapterError::BlockedEnvironment {
            provider: ProviderId::Youtube,
            ..
        })
    ));

    let gate = YoutubeRealReadGate::from_environment_values(Some("1"), Some("youtube-credential"))
        .expect("explicit test gate enables the injected read transport");
    let freshness = YoutubeFreshnessPolicy::default();
    let mut cursor = YoutubeDurableCursor::new(channel(), fixed_now(), &freshness)
        .expect("uploads cursor is valid");
    let mut quota = hartevo_channel_adapters::youtube::YoutubeQuotaLedger::new(1);
    let mut transport = FixtureTransport {
        response: Some(youtube_uploads_response()),
        request: None,
    };
    let outcome = execute_env_gated_incremental_read(
        &gate,
        &mut transport,
        &mut cursor,
        &mut quota,
        &freshness,
        50,
    )
    .expect("explicitly gated fixture read succeeds");
    assert_eq!(
        outcome.cursor_disposition(),
        YoutubeCursorDisposition::Applied
    );
    assert_eq!(outcome.page().observations().len(), 1);
    assert_eq!(quota.data_api_units_used(), 1);
    assert!(
        transport
            .request
            .expect("transport observed request")
            .contains("playlistItems")
    );
}
