use std::collections::{BTreeSet, VecDeque};

use chrono::{Duration, Utc};

use hartevo_channel_adapters::identity::{
    TiktokAccountIdentity, TiktokCreatorIdentity, TiktokCreatorUsername, TiktokOpenId,
    TiktokPublishId,
};
use hartevo_channel_adapters::testkit::fixed_now;
use hartevo_channel_adapters::tiktok::{
    TiktokAuditState, TiktokAuthorization, TiktokScope, parse_webhook,
};
use hartevo_channel_adapters::tiktok_insight::{
    ChannelInsightReadService, MissionTiktokInsightConsumer, TIKTOK_REAL_INSIGHT_ACCESS_TOKEN_ENV,
    TIKTOK_REAL_INSIGHT_ENABLE_ENV, TIKTOK_REAL_INSIGHT_SECRET_REFERENCE_ENV,
    TiktokAuditedOAuthAdapter, TiktokEnvironmentOAuthTokenSource, TiktokHttpsTransport,
    TiktokInsightCheckpointPhase, TiktokInsightCredential, TiktokInsightError,
    TiktokInsightFreshnessPolicy, TiktokInsightModerationClassification, TiktokInsightOperation,
    TiktokInsightProvenance, TiktokInsightQuotaLedger, TiktokInsightReadDispatch,
    TiktokMissionInsightCapability, TiktokRealInsightGate,
};
use hartevo_channel_adapters::{
    CredentialReference, HttpMethod, ProviderReadRequest, ProviderResponse, ReadOnlyTransport,
    TransportError,
};

#[derive(Clone, Debug)]
struct FixtureTransport {
    responses: VecDeque<ProviderResponse>,
    requests: Vec<ProviderReadRequest>,
}

impl FixtureTransport {
    fn new(responses: impl IntoIterator<Item = ProviderResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
            requests: Vec::new(),
        }
    }
}

impl ReadOnlyTransport for FixtureTransport {
    fn send(&mut self, request: &ProviderReadRequest) -> Result<ProviderResponse, TransportError> {
        self.requests.push(request.clone());
        self.responses
            .pop_front()
            .ok_or(TransportError::Unavailable)
    }
}

fn credential(audit_state: TiktokAuditState, generation: u64) -> TiktokInsightCredential {
    let account =
        TiktokAccountIdentity::new(TiktokOpenId::new("open01").expect("fixture open id is valid"));
    let scopes = BTreeSet::from([
        TiktokScope::UserInfoBasic,
        TiktokScope::VideoList,
        TiktokScope::VideoPublish,
        TiktokScope::VideoUpload,
    ]);
    let authorization = TiktokAuthorization::new(
        account,
        scopes.clone(),
        scopes,
        audit_state,
        Some(fixed_now() + Duration::days(1)),
        Some(fixed_now() + Duration::days(30)),
    );
    TiktokInsightCredential::new(
        CredentialReference::new("keychain://tiktok/open01").expect("opaque reference is valid"),
        authorization,
        generation,
    )
    .expect("fixture credential is valid")
}

fn scope() -> hartevo_channel_adapters::tiktok_insight::TiktokInsightScope {
    let account =
        TiktokAccountIdentity::new(TiktokOpenId::new("open01").expect("fixture open id is valid"));
    let creator = TiktokCreatorIdentity::new(
        account.clone(),
        TiktokCreatorUsername::new("creator01").expect("fixture username is valid"),
    );
    hartevo_channel_adapters::tiktok_insight::TiktokInsightScope::new(
        hartevo_channel_adapters::tiktok_insight::TiktokInsightAppId::new("app01")
            .expect("fixture app id is valid"),
        account,
        creator,
    )
    .expect("fixture scope is exact")
}

fn response_at(at: chrono::DateTime<Utc>, body: &str) -> ProviderResponse {
    ProviderResponse::new(
        200,
        [("content-type".to_owned(), "application/json".to_owned())],
        body,
        at,
    )
}

fn probe_response(at: chrono::DateTime<Utc>) -> ProviderResponse {
    response_at(
        at,
        r#"{"data":{"user":{"open_id":"open01","username":"creator01"}}}"#,
    )
}

fn page_response(
    at: chrono::DateTime<Utc>,
    video_id: &str,
    create_time: i64,
    has_more: bool,
    cursor: Option<i64>,
) -> ProviderResponse {
    let cursor = cursor.map_or_else(|| "null".to_owned(), |value| value.to_string());
    response_at(
        at,
        &format!(
            r#"{{"data":{{"videos":[{{"id":"{video_id}","create_time":{create_time},"title":"video {video_id}","video_description":"description","share_url":"https://www.tiktok.com/@creator01/video/{video_id}","like_count":3,"comment_count":1,"share_count":2,"view_count":42}}],"cursor":{cursor},"has_more":{has_more}}}}}"#
        ),
    )
}

fn retry_response(at: chrono::DateTime<Utc>, with_reset: bool) -> ProviderResponse {
    let headers = if with_reset {
        vec![("retry-after".to_owned(), "30".to_owned())]
    } else {
        Vec::new()
    };
    ProviderResponse::new(
        429,
        headers,
        r#"{"error":{"code":"rate_limit","message":"slow down"}}"#,
        at,
    )
}

fn service(
    responses: impl IntoIterator<Item = ProviderResponse>,
) -> ChannelInsightReadService<TiktokAuditedOAuthAdapter<FixtureTransport>> {
    ChannelInsightReadService::new(
        TiktokAuditedOAuthAdapter::fixture(FixtureTransport::new(responses)),
        TiktokInsightQuotaLedger::default(),
        TiktokInsightFreshnessPolicy::default(),
    )
}

#[test]
fn authenticated_probe_is_exact_and_fixture_is_not_mission_production() {
    let now = fixed_now();
    let scope = scope();
    let credential = credential(TiktokAuditState::Approved, 1);
    let mut service = service([probe_response(now + Duration::seconds(5))]);

    let probe = service
        .probe(&credential, &scope, now + Duration::seconds(5))
        .expect("authenticated fixture probe succeeds");
    assert_eq!(probe.account(), scope.account());
    assert_eq!(probe.creator(), scope.creator());
    assert_eq!(probe.token_generation(), 1);
    assert_eq!(probe.provenance(), TiktokInsightProvenance::Fixture);
    assert_eq!(
        probe.quota().expect("probe quota is recorded").operation(),
        TiktokInsightOperation::AuthenticatedProbe
    );
    assert_eq!(
        service.provider().transport().requests[0].method(),
        HttpMethod::Get
    );
    assert!(
        service.provider().transport().requests[0]
            .url()
            .as_str()
            .contains("/v2/user/info/?fields=open_id,display_name")
    );
    assert_eq!(
        service.provider().transport().requests[0]
            .required_scopes()
            .iter()
            .next()
            .expect("probe scope is present")
            .as_str(),
        "user.info.basic"
    );
    assert!(!format!("{credential:?}").contains("keychain://"));
    assert!(!format!("{probe:?}").contains("access_token"));
}

#[test]
fn approved_pages_resume_from_durable_checkpoint_without_duplicates() {
    let now = fixed_now();
    let scope = scope();
    let credential = credential(TiktokAuditState::Approved, 1);
    let mut first = service([
        probe_response(now + Duration::seconds(5)),
        page_response(now + Duration::seconds(10), "100", 200, true, Some(300)),
    ]);
    let mut checkpoint = first
        .start_checkpoint(&credential, scope.clone(), 1, now)
        .expect("checkpoint starts");
    let first_result = match first
        .read_next(&mut checkpoint, &credential, now + Duration::seconds(10))
        .expect("first page reads")
    {
        TiktokInsightReadDispatch::Applied(result) => result,
        other => panic!("expected applied page, got {other:?}"),
    };
    assert!(first_result.has_more());
    assert_eq!(first_result.observations().len(), 1);
    assert_eq!(
        first_result.quota().operation(),
        TiktokInsightOperation::VideoList
    );
    assert_eq!(checkpoint.accepted_pages().len(), 1);
    assert_eq!(
        first.provider().transport().requests[1]
            .body()
            .and_then(|body| body.get("max_count"))
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );

    let checkpoint_json = checkpoint.checkpoint_json().expect("checkpoint serializes");
    let durable_digest = checkpoint.durable_digest();
    let mut reopened =
        hartevo_channel_adapters::tiktok_insight::TiktokInsightCheckpoint::from_checkpoint_json(
            &checkpoint_json,
        )
        .expect("checkpoint reopens");
    assert_eq!(reopened.durable_digest(), durable_digest);

    let mut resumed = service([page_response(
        now + Duration::seconds(20),
        "099",
        100,
        false,
        None,
    )]);
    let final_result = match resumed
        .read_next(&mut reopened, &credential, now + Duration::seconds(20))
        .expect("second page reads")
    {
        TiktokInsightReadDispatch::Applied(result) => result,
        other => panic!("expected final applied page, got {other:?}"),
    };
    assert!(final_result.sequence_complete());
    assert_eq!(final_result.all_observations().len(), 2);
    assert_eq!(final_result.observations().len(), 1);
    assert_eq!(
        final_result.observations()[0]
            .identity()
            .video_id()
            .as_str(),
        "099"
    );
    assert_eq!(
        final_result.all_observations()[0]
            .performance()
            .view_count(),
        Some(42)
    );
    assert_eq!(
        final_result.all_observations()[0].moderation(),
        TiktokInsightModerationClassification::PubliclyAvailable
    );
    assert_eq!(reopened.accepted_pages().len(), 2);
    assert_eq!(resumed.provider().transport().requests.len(), 1);
    assert_eq!(
        resumed.provider().transport().requests[0]
            .body()
            .and_then(|body| body.get("cursor"))
            .and_then(serde_json::Value::as_i64),
        Some(300)
    );

    let already_complete = resumed
        .read_next(&mut reopened, &credential, now + Duration::seconds(21))
        .expect("completed checkpoint is readable");
    assert!(matches!(
        already_complete,
        TiktokInsightReadDispatch::AlreadyComplete(_)
    ));
    assert_eq!(resumed.provider().transport().requests.len(), 1);
}

#[test]
fn duplicate_or_out_of_order_page_fails_closed() {
    let now = fixed_now();
    let scope = scope();
    let credential = credential(TiktokAuditState::Approved, 1);
    let mut service = service([
        probe_response(now + Duration::seconds(5)),
        page_response(now + Duration::seconds(10), "100", 200, true, Some(300)),
        page_response(now + Duration::seconds(20), "101", 300, false, None),
    ]);
    let mut checkpoint = service
        .start_checkpoint(&credential, scope, 1, now)
        .expect("checkpoint starts");
    service
        .read_next(&mut checkpoint, &credential, now + Duration::seconds(10))
        .expect("first page reads");
    assert!(matches!(
        service.read_next(&mut checkpoint, &credential, now + Duration::seconds(20)),
        Err(TiktokInsightError::CursorDrift)
    ));
}

#[test]
fn rate_limit_receipt_survives_reopen_and_missing_reset_stays_blocked() {
    let now = fixed_now();
    let scope = scope();
    let credential = credential(TiktokAuditState::Approved, 1);
    let mut limited = service([
        probe_response(now + Duration::seconds(5)),
        retry_response(now + Duration::seconds(10), true),
    ]);
    let mut checkpoint = limited
        .start_checkpoint(&credential, scope.clone(), 1, now)
        .expect("checkpoint starts");
    let receipt = match limited
        .read_next(&mut checkpoint, &credential, now + Duration::seconds(10))
        .expect("rate limit is a durable result")
    {
        TiktokInsightReadDispatch::RetryAfter(receipt) => receipt,
        other => panic!("expected retry receipt, got {other:?}"),
    };
    assert_eq!(receipt.retry_after_seconds(), Some(30));
    let checkpoint_json = checkpoint.checkpoint_json().expect("checkpoint serializes");
    let mut reopened =
        hartevo_channel_adapters::tiktok_insight::TiktokInsightCheckpoint::from_checkpoint_json(
            &checkpoint_json,
        )
        .expect("rate limit checkpoint reopens");
    let mut resumed = service([page_response(
        now + Duration::seconds(41),
        "100",
        200,
        false,
        None,
    )]);
    assert!(matches!(
        resumed.read_next(&mut reopened, &credential, now + Duration::seconds(20)),
        Ok(TiktokInsightReadDispatch::RetryAfter(_))
    ));
    assert!(resumed.provider().transport().requests.is_empty());
    assert!(matches!(
        resumed.read_next(&mut reopened, &credential, now + Duration::seconds(41)),
        Ok(TiktokInsightReadDispatch::Applied(_))
    ));

    let mut no_reset = service([
        probe_response(now + Duration::seconds(5)),
        retry_response(now + Duration::seconds(10), false),
    ]);
    let mut no_reset_checkpoint = no_reset
        .start_checkpoint(&credential, scope, 1, now)
        .expect("checkpoint starts");
    assert!(matches!(
        no_reset.read_next(
            &mut no_reset_checkpoint,
            &credential,
            now + Duration::seconds(10)
        ),
        Ok(TiktokInsightReadDispatch::RetryAfter(_))
    ));
    assert!(!no_reset_checkpoint.retry_is_due(now + Duration::days(1)));
}

#[test]
fn rotation_revocation_and_unmount_invalidate_old_cursor() {
    let now = fixed_now();
    let scope = scope();
    let original = credential(TiktokAuditState::Approved, 1);
    let service = service([]);
    let mut rotated_checkpoint = service
        .start_checkpoint(&original, scope.clone(), 1, now)
        .expect("checkpoint starts");
    let rotated = credential(TiktokAuditState::Approved, 2);
    assert!(matches!(
        rotated_checkpoint.bind(&rotated, now + Duration::seconds(1)),
        Err(TiktokInsightError::CredentialRotated)
    ));
    assert!(matches!(
        rotated_checkpoint.phase(),
        TiktokInsightCheckpointPhase::Invalidated { .. }
    ));

    let mut revoked_checkpoint = service
        .start_checkpoint(&original, scope.clone(), 1, now)
        .expect("checkpoint starts");
    let mut revoked = original.clone();
    revoked.revoke(now);
    assert!(matches!(
        revoked_checkpoint.bind(&revoked, now + Duration::seconds(1)),
        Err(TiktokInsightError::CredentialRevoked)
    ));

    let mut unmounted_checkpoint = service
        .start_checkpoint(&original, scope, 1, now)
        .expect("checkpoint starts");
    let mut unmounted = original;
    unmounted.unmount(now);
    assert!(matches!(
        unmounted_checkpoint.bind(&unmounted, now + Duration::seconds(1)),
        Err(TiktokInsightError::CredentialUnmounted)
    ));
}

#[test]
fn unaudited_list_is_private_boundary_and_status_classifies_private_content() {
    let now = fixed_now();
    let scope = scope();
    let credential = credential(TiktokAuditState::Unaudited, 1);
    let mut list_service = service([probe_response(now + Duration::seconds(5))]);
    let mut checkpoint = list_service
        .start_checkpoint(&credential, scope.clone(), 1, now)
        .expect("unaudited checkpoint can be created for private boundary");
    assert!(matches!(
        list_service.read_next(&mut checkpoint, &credential, now + Duration::seconds(5)),
        Err(TiktokInsightError::UnauditedPrivateBoundary)
    ));

    let mut status_service = service([response_at(
        now + Duration::seconds(6),
        r#"{"data":{"status":"PUBLISH_COMPLETE","publicaly_available_post_id":[]}}"#,
    )]);
    let result = status_service
        .read_content_status(
            &credential,
            &scope,
            TiktokPublishId::new("publish01").expect("publish id is valid"),
            now + Duration::seconds(6),
        )
        .expect("private status is an allowed boundary");
    assert_eq!(
        result.classification(),
        TiktokInsightModerationClassification::PrivateOnlyUnaudited
    );
    assert_eq!(result.provenance(), TiktokInsightProvenance::Fixture);
}

#[test]
fn webhook_removal_is_exactly_bound_and_late_delivery_is_rejected() {
    let now = fixed_now();
    let scope = scope();
    let credential = credential(TiktokAuditState::Approved, 1);
    let mut service = service([
        probe_response(now + Duration::seconds(5)),
        page_response(now + Duration::seconds(10), "100", 200, false, None),
    ]);
    let mut checkpoint = service
        .start_checkpoint(&credential, scope, 1, now)
        .expect("checkpoint starts");
    service
        .read_next(&mut checkpoint, &credential, now + Duration::seconds(10))
        .expect("page reads");

    let removal = parse_webhook(&response_at(
        now + Duration::seconds(30),
        r#"{"event":"post.publish.no_longer_publicly_available","publish_id":"publish01","open_id":"open01"}"#,
    ))
    .expect("removal webhook parses");
    let event = removal
        .envelope(now + Duration::seconds(30), now + Duration::seconds(31))
        .expect("webhook envelope is exact");
    service
        .ingest_webhook(&mut checkpoint, &event)
        .expect("removal webhook is admitted");
    assert_eq!(checkpoint.webhook_evidence().len(), 1);
    assert_eq!(
        checkpoint.webhook_evidence()[0].classification(),
        TiktokInsightModerationClassification::NoLongerPublic
    );
    assert!(matches!(
        service.ingest_webhook(&mut checkpoint, &event),
        Err(TiktokInsightError::DuplicateWebhook)
    ));

    let late = parse_webhook(&response_at(
        now + Duration::seconds(32),
        r#"{"event":"post.publish.no_longer_publicaly_available","publish_id":"publish01","open_id":"open01","post_id":"post01"}"#,
    ))
    .expect("late webhook parses");
    let late_event = late
        .envelope(now + Duration::seconds(29), now + Duration::seconds(32))
        .expect("late webhook envelope is structurally valid");
    assert!(matches!(
        service.ingest_webhook(&mut checkpoint, &late_event),
        Err(TiktokInsightError::OutOfOrderWebhook)
    ));
}

#[test]
fn real_probe_requires_explicit_environment_and_never_uses_fixture_as_production() {
    let blocked = TiktokRealInsightGate::from_environment_values(None, None, None);
    assert!(matches!(
        blocked,
        Err(TiktokInsightError::BlockedEnvironment { requirement })
            if requirement == TIKTOK_REAL_INSIGHT_ENABLE_ENV
    ));
    let blocked_secret =
        TiktokRealInsightGate::from_environment_values(Some("1"), None, Some("opaque-token"));
    assert!(matches!(
        blocked_secret,
        Err(TiktokInsightError::BlockedEnvironment { requirement })
            if requirement == TIKTOK_REAL_INSIGHT_SECRET_REFERENCE_ENV
    ));
    let blocked_token = TiktokRealInsightGate::from_environment_values(
        Some("1"),
        Some("keychain://tiktok/open01"),
        None,
    );
    assert!(matches!(
        blocked_token,
        Err(TiktokInsightError::BlockedEnvironment { requirement })
            if requirement == TIKTOK_REAL_INSIGHT_ACCESS_TOKEN_ENV
    ));
    assert!(!format!("{TiktokEnvironmentOAuthTokenSource:?}").contains("token"));
    let transport = TiktokHttpsTransport::new(TiktokEnvironmentOAuthTokenSource);
    assert!(!format!("{transport:?}").contains("opaque-token"));
    let capability = TiktokMissionInsightCapability::new(
        scope(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )
    .expect("capability revision is exact");
    let consumer = MissionTiktokInsightConsumer::new(capability);
    let mut service = service([
        probe_response(fixed_now() + Duration::seconds(5)),
        page_response(fixed_now() + Duration::seconds(10), "100", 200, false, None),
    ]);
    let credential = credential(TiktokAuditState::Approved, 1);
    let mut checkpoint = service
        .start_checkpoint(&credential, scope(), 1, fixed_now())
        .expect("checkpoint starts");
    let result = match service
        .read_next(
            &mut checkpoint,
            &credential,
            fixed_now() + Duration::seconds(10),
        )
        .expect("fixture result reads")
    {
        TiktokInsightReadDispatch::Applied(result) => result,
        other => panic!("expected applied result, got {other:?}"),
    };
    assert!(matches!(
        consumer.accept(result, &credential, fixed_now() + Duration::seconds(10)),
        Err(TiktokInsightError::MissionCapabilityMismatch)
    ));
}
