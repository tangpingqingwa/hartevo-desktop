use std::{
    cell::RefCell,
    collections::{BTreeSet, VecDeque},
    rc::Rc,
};

use chrono::{Duration, Utc};
use hartevo_channel_adapters::{
    BusinessId, EvidenceProvenance, HttpMethod, MissionTiktokReadConsumer, OAuthCredential,
    ProviderReadRequest, ProviderResponse, ReadOnlyTransport, SecretReference, TenantId,
    TiktokAccountId, TiktokApiOperation, TiktokAuthenticatedReadService, TiktokConnectionState,
    TiktokCursor, TiktokError, TiktokFreshnessPolicy, TiktokOAuthScope, TiktokReadObservation,
    TiktokReadScope, TiktokRevisionIdentity, TiktokVideoId, TiktokVideoListCursor,
    TiktokVideoPageEnvelope, TiktokVideoPageResult, TransportError,
};

use hartevo_channel_adapters::tiktok::testkit::{
    final_video_page_response, first_video_page_response, fixed_now, missing_scope_response,
    profile_response, query_video_response, rate_limited_response, response, revoked_response,
};

#[derive(Clone)]
struct FixtureTransport {
    responses: Rc<RefCell<VecDeque<Result<ProviderResponse, TransportError>>>>,
    requests: Rc<RefCell<Vec<ProviderReadRequest>>>,
}

impl FixtureTransport {
    fn from_results(
        responses: impl IntoIterator<Item = Result<ProviderResponse, TransportError>>,
    ) -> Self {
        Self {
            responses: Rc::new(RefCell::new(responses.into_iter().collect())),
            requests: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn responses(responses: impl IntoIterator<Item = ProviderResponse>) -> Self {
        Self::from_results(responses.into_iter().map(Ok))
    }
}

impl ReadOnlyTransport for FixtureTransport {
    fn send(&mut self, request: &ProviderReadRequest) -> Result<ProviderResponse, TransportError> {
        self.requests.borrow_mut().push(request.clone());
        self.responses
            .borrow_mut()
            .pop_front()
            .unwrap_or(Err(TransportError::Unavailable))
    }
}

fn scope() -> TiktokReadScope {
    TiktokReadScope::new(
        TenantId::new("tenant-01").unwrap(),
        BusinessId::new("business-01").unwrap(),
        TiktokAccountId::new("open01").unwrap(),
    )
}

fn credential(scope: &TiktokReadScope, now: chrono::DateTime<Utc>) -> OAuthCredential {
    credential_with(scope, now, "keychain://tiktok/open01", 1)
}

fn credential_with(
    scope: &TiktokReadScope,
    now: chrono::DateTime<Utc>,
    secret_reference: &str,
    generation: u64,
) -> OAuthCredential {
    OAuthCredential::new(
        SecretReference::new(secret_reference).unwrap(),
        scope.clone(),
        [TiktokOAuthScope::UserInfoBasic, TiktokOAuthScope::VideoList]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        now + Duration::hours(1),
        Some(now + Duration::days(30)),
        generation,
    )
    .unwrap()
}

fn page(result: Result<TiktokVideoPageResult, TiktokError>) -> TiktokVideoPageEnvelope {
    match result.unwrap() {
        TiktokVideoPageResult::Page(page) => page,
        other => panic!("expected a page result, got {other:?}"),
    }
}

#[test]
fn authenticated_probe_uses_official_display_api_and_fixture_is_not_first_party() {
    let now = fixed_now();
    let transport = FixtureTransport::responses([profile_response()]);
    let requests = Rc::clone(&transport.requests);
    let read_scope = scope();
    let read_credential = credential(&read_scope, now);
    let mut service =
        TiktokAuthenticatedReadService::fixture(transport, TiktokFreshnessPolicy::default());

    let envelope = service.probe(&read_credential, now).unwrap();

    assert_eq!(service.provenance(), EvidenceProvenance::Fixture);
    assert_eq!(
        envelope.provider(),
        hartevo_channel_adapters::ProviderId::Tiktok
    );
    assert_eq!(envelope.scope(), &read_scope);
    assert_eq!(envelope.account().open_id(), read_scope.account());
    assert!(matches!(
        envelope.revision(),
        TiktokRevisionIdentity::Account { .. }
    ));
    assert!(matches!(
        envelope.observation(),
        TiktokReadObservation::Account(_)
    ));
    assert_eq!(envelope.freshness().source_generation(), 1);
    assert_eq!(
        envelope.validate_at(now + Duration::minutes(2)),
        Err(TiktokError::FreshnessExpired {
            observed_at: now,
            valid_until: now + Duration::minutes(2),
        })
    );

    let request = &requests.borrow()[0];
    assert_eq!(request.operation(), TiktokApiOperation::UserInfo);
    assert_eq!(request.method(), HttpMethod::Get);
    assert_eq!(request.url().path(), "/v2/user/info/");
    assert_eq!(
        request
            .url()
            .query_pairs()
            .find(|(key, _)| key == "fields")
            .map(|(_, value)| value.into_owned()),
        Some("open_id,display_name".to_owned())
    );
    assert!(
        request
            .required_scopes()
            .iter()
            .any(|scope| scope.as_str() == "user.info.basic")
    );
    let debug = format!("{request:?}");
    assert!(debug.contains("SecretReference(<opaque>)"));
    assert!(!debug.contains("keychain://tiktok/open01"));

    let mut mission = MissionTiktokReadConsumer::new(read_scope);
    mission
        .bind_exact_revision(envelope.revision().clone())
        .unwrap();
    assert_eq!(
        mission.accept(envelope, &read_credential, now),
        Err(TiktokError::ProvenanceRejected)
    );
}

#[test]
fn video_list_is_durable_cursor_pagination_with_performance_observations() {
    let now = fixed_now();
    let transport = FixtureTransport::responses([
        first_video_page_response(),
        first_video_page_response(),
        final_video_page_response(),
    ]);
    let requests = Rc::clone(&transport.requests);
    let read_scope = scope();
    let read_credential = credential(&read_scope, now);
    let mut service =
        TiktokAuthenticatedReadService::fixture(transport, TiktokFreshnessPolicy::default());
    let mut cursor = TiktokVideoListCursor::new(read_scope.clone()).unwrap();

    let first = page(service.list_videos(&read_credential, &mut cursor, now, 20));
    assert_eq!(first.provenance(), EvidenceProvenance::Fixture);
    assert!(first.has_more());
    assert_eq!(first.cursor_generation(), 1);
    assert_eq!(first.observations().len(), 1);
    let first_observation = &first.observations()[0];
    assert!(matches!(
        first_observation.observation(),
        TiktokReadObservation::Video(video)
            if video.identity().video_id().as_str() == "7340000000000000001"
                && video.performance().view_count() == Some(101)
    ));
    assert_eq!(cursor.next_cursor().unwrap().value(), 1_767_301_445_000);
    assert_eq!(cursor.generation(), 1);
    cursor.require_fresh(now).unwrap();

    let checkpoint = cursor.checkpoint_json().unwrap();
    let restored = TiktokVideoListCursor::from_checkpoint_json(&checkpoint).unwrap();
    assert_eq!(restored, cursor);
    assert_eq!(restored.durable_digest(), cursor.durable_digest());

    assert_eq!(
        service.list_videos(&read_credential, &mut cursor, now, 10),
        Err(TiktokError::CursorDrift)
    );

    let duplicate = service
        .list_videos(&read_credential, &mut cursor, now, 20)
        .unwrap();
    assert!(matches!(
        duplicate,
        TiktokVideoPageResult::Duplicate(receipt)
            if receipt.sequence().generation() == 1
                && receipt.page_digest() == first.page_digest()
    ));
    assert_eq!(cursor.generation(), 1);

    let final_page = page(service.list_videos(&read_credential, &mut cursor, now, 20));
    assert!(!final_page.has_more());
    assert_eq!(final_page.next_cursor(), None);
    assert_eq!(final_page.cursor_generation(), 2);
    assert!(!cursor.has_more());
    assert_eq!(cursor.generation(), 2);
    assert_eq!(
        service.list_videos(&read_credential, &mut cursor, now, 20),
        Err(TiktokError::CursorExhausted)
    );

    let requests = requests.borrow();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].operation(), TiktokApiOperation::VideoList);
    assert_eq!(requests[0].method(), HttpMethod::Post);
    assert_eq!(requests[0].url().path(), "/v2/video/list/");
    assert_eq!(requests[0].body().unwrap()["max_count"], 20);
    assert_eq!(requests[1].body().unwrap()["cursor"], 1_767_301_445_000_i64);
}

#[test]
fn rate_limit_recovery_persists_provider_reset_without_advancing_data() {
    let now = fixed_now();
    let read_scope = scope();
    let read_credential = credential(&read_scope, now);
    let transport =
        FixtureTransport::responses([rate_limited_response(), first_video_page_response()]);
    let requests = Rc::clone(&transport.requests);
    let mut service =
        TiktokAuthenticatedReadService::fixture(transport, TiktokFreshnessPolicy::default());
    let mut cursor = TiktokVideoListCursor::new(read_scope).unwrap();

    let retry = service
        .list_videos(&read_credential, &mut cursor, now, 20)
        .unwrap();
    let retry_receipt = match &retry {
        TiktokVideoPageResult::RetryAfter(receipt) => receipt,
        other => panic!("expected RetryAfter, got {other:?}"),
    };
    assert_eq!(retry_receipt.cursor_generation(), 0);
    assert_eq!(
        retry_receipt.provider_reset_at(),
        Some(now + Duration::seconds(30))
    );
    assert_eq!(retry_receipt.retry_after_seconds(), Some(30));
    assert_eq!(cursor.generation(), 0);
    assert_eq!(cursor.accepted_page_count(), 0);
    assert!(cursor.last_page_digest().is_none());

    let checkpoint = cursor.checkpoint_json().unwrap();
    let mut reopened_cursor = TiktokVideoListCursor::from_checkpoint_json(&checkpoint).unwrap();
    assert_eq!(reopened_cursor, cursor);
    assert!(reopened_cursor.retry_after().is_some());

    let replayed_retry = service
        .list_videos(
            &read_credential,
            &mut reopened_cursor,
            now + Duration::seconds(1),
            20,
        )
        .unwrap();
    assert_eq!(replayed_retry, retry);
    assert_eq!(requests.borrow().len(), 1);

    let recovered = page(service.list_videos(
        &read_credential,
        &mut reopened_cursor,
        now + Duration::seconds(31),
        20,
    ));
    assert_eq!(recovered.cursor_generation(), 1);
    assert!(reopened_cursor.retry_after().is_none());
    assert_eq!(reopened_cursor.accepted_page_count(), 1);
    assert_eq!(requests.borrow().len(), 2);
}

#[test]
fn rate_limit_without_provider_reset_does_not_fabricate_wait_or_data() {
    let now = fixed_now();
    let read_scope = scope();
    let read_credential = credential(&read_scope, now);
    let response_without_reset = ProviderResponse::new(
        429,
        [("content-type".to_owned(), "application/json".to_owned())],
        r#"{"error":{"code":"rate_limit_exceeded"}}"#,
        now,
    );
    let mut service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([response_without_reset]),
        Default::default(),
    );
    let mut cursor = TiktokVideoListCursor::new(read_scope).unwrap();

    let result = service
        .list_videos(&read_credential, &mut cursor, now, 20)
        .unwrap();
    let receipt = match result {
        TiktokVideoPageResult::RetryAfter(receipt) => receipt,
        other => panic!("expected RetryAfter, got {other:?}"),
    };
    assert_eq!(receipt.retry_after_seconds(), None);
    assert_eq!(receipt.provider_reset_at(), None);
    assert_eq!(cursor.generation(), 0);
    assert_eq!(cursor.accepted_page_count(), 0);
}

#[test]
fn crash_reopen_resumes_bound_cursor_and_evidence_root_exactly_once() {
    let now = fixed_now();
    let read_scope = scope();
    let read_credential = credential(&read_scope, now);
    let first_transport = FixtureTransport::responses([first_video_page_response()]);
    let mut first_service =
        TiktokAuthenticatedReadService::fixture(first_transport, TiktokFreshnessPolicy::default());
    let mut cursor = TiktokVideoListCursor::new(read_scope.clone()).unwrap();
    let first = page(first_service.list_videos(&read_credential, &mut cursor, now, 20));
    let checkpoint = cursor.checkpoint_json().unwrap();
    assert!(!checkpoint.contains("keychain://tiktok/open01"));

    let restored = TiktokVideoListCursor::from_checkpoint_json(&checkpoint).unwrap();
    assert_eq!(restored, cursor);
    let transport = FixtureTransport::responses([final_video_page_response()]);
    let requests = Rc::clone(&transport.requests);
    let mut reopened_service =
        TiktokAuthenticatedReadService::fixture(transport, TiktokFreshnessPolicy::default());
    let mut reopened_cursor = restored;
    let final_page =
        page(reopened_service.list_videos(&read_credential, &mut reopened_cursor, now, 20));

    assert_eq!(final_page.cursor_generation(), 2);
    assert_eq!(reopened_cursor.generation(), 2);
    assert_eq!(reopened_cursor.accepted_page_count(), 2);
    assert_ne!(first.evidence_root(), final_page.evidence_root());
    assert_eq!(
        requests.borrow()[0].body().unwrap()["cursor"],
        1_767_301_445_000_i64
    );
    assert_eq!(
        TiktokVideoListCursor::from_checkpoint_json(&reopened_cursor.checkpoint_json().unwrap())
            .unwrap(),
        reopened_cursor
    );
}

#[test]
fn provider_generation_sorts_video_observations_and_rejects_out_of_order_cursor() {
    let now = fixed_now();
    let read_scope = scope();
    let read_credential = credential(&read_scope, now);
    let unsorted = response(
        200,
        r#"{
          "data":{
            "videos":[
              {"id":"7340000000000000002","create_time":1767300445,"view_count":2},
              {"id":"7340000000000000001","create_time":1767301445,"view_count":1}
            ],
            "cursor":1767301445000,
            "has_more":false
          },
          "error":{"code":"ok"}
        }"#,
    );
    let mut service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([unsorted]),
        Default::default(),
    );
    let mut cursor = TiktokVideoListCursor::new(read_scope).unwrap();
    let sorted_page = page(service.list_videos(&read_credential, &mut cursor, now, 20));
    let ids = sorted_page
        .observations()
        .iter()
        .map(|observation| match observation.observation() {
            TiktokReadObservation::Video(video) => video.identity().video_id().as_str(),
            TiktokReadObservation::Account(_) => "account",
        })
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["7340000000000000001", "7340000000000000002"]);
    assert_eq!(sorted_page.sequence().account(), cursor.scope().account());
    assert_eq!(sorted_page.sequence().generation(), 1);

    let out_of_order = response(
        200,
        r#"{
          "data":{
            "videos":[{"id":"7340000000000000003","view_count":3}],
            "cursor":1767301445000,
            "has_more":true
          },
          "error":{"code":"ok"}
        }"#,
    );
    let mut drift_service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([first_video_page_response(), out_of_order]),
        Default::default(),
    );
    let mut drift_cursor = TiktokVideoListCursor::new(scope()).unwrap();
    let _ = drift_service.list_videos(&read_credential, &mut drift_cursor, now, 20);
    assert_eq!(
        drift_service
            .list_videos(&read_credential, &mut drift_cursor, now, 20)
            .unwrap_err(),
        TiktokError::CursorDrift
    );
    assert_eq!(drift_cursor.generation(), 1);
    assert_eq!(drift_cursor.accepted_page_count(), 1);
}

#[test]
fn credential_rotation_revocation_and_unmount_invalidate_old_cursor() {
    let now = fixed_now();
    let read_scope = scope();

    let mut rotated_cursor = TiktokVideoListCursor::new(read_scope.clone()).unwrap();
    let mut seed_service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([first_video_page_response()]),
        Default::default(),
    );
    let original = credential(&read_scope, now);
    let _ = seed_service
        .list_videos(&original, &mut rotated_cursor, now, 20)
        .unwrap();
    let rotated = credential_with(&read_scope, now, "keychain://tiktok/open01-rotated", 2);
    let mut rotated_service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([final_video_page_response()]),
        Default::default(),
    );
    assert_eq!(
        rotated_service
            .list_videos(&rotated, &mut rotated_cursor, now, 20)
            .unwrap_err(),
        TiktokError::CursorInvalidated {
            reason: hartevo_channel_adapters::TiktokCursorInvalidationReason::CredentialRotated,
        }
    );
    assert!(matches!(
        rotated_cursor.lifecycle(),
        hartevo_channel_adapters::TiktokCursorLifecycle::Invalidated {
            reason: hartevo_channel_adapters::TiktokCursorInvalidationReason::CredentialRotated,
            ..
        }
    ));

    let mut revoked_cursor = TiktokVideoListCursor::new(read_scope.clone()).unwrap();
    let mut revoked_seed = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([first_video_page_response()]),
        Default::default(),
    );
    let mut revoked = original.clone();
    revoked_seed
        .list_videos(&revoked, &mut revoked_cursor, now, 20)
        .unwrap();
    revoked.revoke(now);
    let mut revoked_service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([final_video_page_response()]),
        Default::default(),
    );
    assert!(matches!(
        revoked_service
            .list_videos(&revoked, &mut revoked_cursor, now, 20)
            .unwrap_err(),
        TiktokError::CursorInvalidated {
            reason: hartevo_channel_adapters::TiktokCursorInvalidationReason::CredentialRevoked,
        }
    ));

    let mut unmounted_cursor = TiktokVideoListCursor::new(read_scope.clone()).unwrap();
    let mut unmounted_seed = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([first_video_page_response()]),
        Default::default(),
    );
    let mut unmounted = original;
    unmounted_seed
        .list_videos(&unmounted, &mut unmounted_cursor, now, 20)
        .unwrap();
    unmounted.unmount(now);
    let mut unmounted_service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([final_video_page_response()]),
        Default::default(),
    );
    assert!(matches!(
        unmounted_service
            .list_videos(&unmounted, &mut unmounted_cursor, now, 20)
            .unwrap_err(),
        TiktokError::CursorInvalidated {
            reason: hartevo_channel_adapters::TiktokCursorInvalidationReason::CredentialUnmounted,
        }
    ));
}

#[test]
fn query_returns_video_performance_and_exact_revision_envelope() {
    let now = fixed_now();
    let transport = FixtureTransport::responses([query_video_response()]);
    let requests = Rc::clone(&transport.requests);
    let read_scope = scope();
    let read_credential = credential(&read_scope, now);
    let video_id = TiktokVideoId::new("7340000000000000001").unwrap();
    let mut service =
        TiktokAuthenticatedReadService::fixture(transport, TiktokFreshnessPolicy::default());

    let observations = service
        .query_videos(
            &read_credential,
            &read_scope,
            std::slice::from_ref(&video_id),
            now,
        )
        .unwrap();

    assert_eq!(observations.len(), 1);
    let observation = &observations[0];
    assert!(matches!(
        observation.observation(),
        TiktokReadObservation::Video(video)
            if video.identity().video_id() == &video_id
                && video.performance().like_count() == Some(21)
                && video.performance().view_count() == Some(303)
    ));
    assert!(matches!(
        observation.revision(),
        TiktokRevisionIdentity::Video { video_id: revision_id, .. }
            if revision_id == &video_id
    ));

    let request = &requests.borrow()[0];
    assert_eq!(request.operation(), TiktokApiOperation::VideoQuery);
    assert_eq!(request.url().path(), "/v2/video/query/");
    assert_eq!(
        request.body().unwrap()["filters"]["video_ids"][0],
        "7340000000000000001"
    );
}

#[test]
fn authenticated_read_fails_closed_for_expiry_revocation_rate_limit_and_disconnect() {
    let now = fixed_now();
    let read_scope = scope();

    let expired = OAuthCredential::new(
        SecretReference::new("keychain://tiktok/open01").unwrap(),
        read_scope.clone(),
        [TiktokOAuthScope::UserInfoBasic].into_iter().collect(),
        now,
        None,
        1,
    )
    .unwrap();
    let mut expired_service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([]),
        Default::default(),
    );
    let expired_error = expired_service.probe(&expired, now).unwrap_err();
    assert_eq!(expired_error, TiktokError::CredentialExpired);
    assert_eq!(
        expired_error.connection_state(),
        Some(TiktokConnectionState::Expired)
    );

    let mut revoked = credential(&read_scope, now);
    revoked.revoke(now);
    let mut revoked_service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([]),
        Default::default(),
    );
    let revoked_error = revoked_service.probe(&revoked, now).unwrap_err();
    assert_eq!(revoked_error, TiktokError::CredentialRevoked);
    assert_eq!(
        revoked_error.connection_state(),
        Some(TiktokConnectionState::Revoked)
    );

    let mut provider_revoked = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([revoked_response()]),
        Default::default(),
    );
    let provider_revoked_error = provider_revoked
        .probe(&credential(&read_scope, now), now)
        .unwrap_err();
    assert_eq!(provider_revoked_error, TiktokError::CredentialRevoked);

    let mut rate_limited = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([rate_limited_response()]),
        Default::default(),
    );
    let rate_error = rate_limited
        .probe(&credential(&read_scope, now), now)
        .unwrap_err();
    assert_eq!(
        rate_error,
        TiktokError::RateLimited {
            operation: TiktokApiOperation::UserInfo,
            retry_after_seconds: Some(30),
        }
    );
    assert_eq!(
        rate_error.connection_state(),
        Some(TiktokConnectionState::RateLimited)
    );

    let mut disconnected = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::from_results([Err(TransportError::Unavailable)]),
        Default::default(),
    );
    let disconnected_error = disconnected
        .probe(&credential(&read_scope, now), now)
        .unwrap_err();
    assert_eq!(disconnected_error, TiktokError::Disconnected);
    assert_eq!(
        disconnected_error.connection_state(),
        Some(TiktokConnectionState::Disconnected)
    );

    let no_video_scope = OAuthCredential::new(
        SecretReference::new("keychain://tiktok/open01").unwrap(),
        read_scope.clone(),
        [TiktokOAuthScope::UserInfoBasic].into_iter().collect(),
        now + Duration::hours(1),
        None,
        1,
    )
    .unwrap();
    let mut missing_scope = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([]),
        Default::default(),
    );
    let mut cursor = TiktokVideoListCursor::new(read_scope.clone()).unwrap();
    assert_eq!(
        missing_scope
            .list_videos(&no_video_scope, &mut cursor, now, 20)
            .unwrap_err(),
        TiktokError::MissingScope {
            scope: TiktokOAuthScope::VideoList,
        }
    );

    let drifted_page = response(
        200,
        r#"{
          "data":{
            "videos":[{
              "id":"7340000000000000001",
              "create_time":1767301445,
              "title":"Drifted page",
              "like_count":999
            }],
            "cursor":1767301445000,
            "has_more":true
          },
          "error":{"code":"ok"}
        }"#,
    );
    let mut drifted = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([first_video_page_response(), drifted_page]),
        Default::default(),
    );
    let read_credential = credential(&read_scope, now);
    let mut drift_cursor = TiktokVideoListCursor::new(read_scope).unwrap();
    drifted
        .list_videos(&read_credential, &mut drift_cursor, now, 20)
        .unwrap();
    assert_eq!(
        drifted
            .list_videos(&read_credential, &mut drift_cursor, now, 20)
            .unwrap_err(),
        TiktokError::CursorDrift
    );
    assert_eq!(drift_cursor.generation(), 1);
}

#[test]
fn quota_scope_and_real_read_gate_are_explicit() {
    let now = fixed_now();
    let read_scope = scope();
    let read_credential = credential(&read_scope, now);
    let quota = hartevo_channel_adapters::TiktokQuotaLedger::new(1).unwrap();
    let mut service = TiktokAuthenticatedReadService::fixture_with_quota(
        FixtureTransport::responses([profile_response(), profile_response()]),
        Default::default(),
        quota,
    );
    service.probe(&read_credential, now).unwrap();
    assert_eq!(
        service.probe(&read_credential, now).unwrap_err(),
        TiktokError::QuotaExhausted {
            operation: TiktokApiOperation::UserInfo,
        }
    );
    assert_eq!(service.quota().reservations().len(), 1);
    assert_eq!(service.quota().reservations()[0].cost().request_units(), 1);
    assert_eq!(
        service.quota().reservations()[0].cost().monetary_micros(),
        None
    );

    let mut missing_scope_service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([missing_scope_response()]),
        Default::default(),
    );
    let user_only = OAuthCredential::new(
        SecretReference::new("keychain://tiktok/open01").unwrap(),
        read_scope.clone(),
        [TiktokOAuthScope::UserInfoBasic].into_iter().collect(),
        now + Duration::hours(1),
        None,
        1,
    )
    .unwrap();
    assert_eq!(
        missing_scope_service.probe(&user_only, now).unwrap_err(),
        TiktokError::MissingScope {
            scope: TiktokOAuthScope::UserInfoBasic,
        }
    );
}

#[test]
fn typed_id_and_cursor_boundaries_are_not_stringly_typed() {
    assert!(TiktokCursor::new(0).is_err());
    assert!(TiktokVideoId::new("not-a-numeric-id").is_err());
    assert!(TiktokVideoId::new("7340000000000000001").is_ok());
    assert!(SecretReference::new("bearer access-token").is_err());
    assert!(SecretReference::new("keychain://tiktok/open01").is_ok());
}

#[test]
fn mission_consumer_requires_exact_scope_and_revision_before_admission() {
    let now = fixed_now();
    let read_scope = scope();
    let read_credential = credential(&read_scope, now);
    let transport = FixtureTransport::responses([profile_response()]);
    let mut service =
        TiktokAuthenticatedReadService::fixture(transport, TiktokFreshnessPolicy::default());
    let envelope = service.probe(&read_credential, now).unwrap();

    let mut consumer = MissionTiktokReadConsumer::new(read_scope.clone());
    assert_eq!(
        consumer
            .accept(envelope.clone(), &read_credential, now)
            .unwrap_err(),
        TiktokError::MissionRevisionMismatch
    );
    consumer
        .bind_exact_revision(envelope.revision().clone())
        .unwrap();
    assert_eq!(
        consumer.accept(envelope.clone(), &read_credential, now),
        Err(TiktokError::ProvenanceRejected)
    );

    let wrong_scope = TiktokReadScope::new(
        TenantId::new("other-tenant").unwrap(),
        BusinessId::new("business-01").unwrap(),
        TiktokAccountId::new("open01").unwrap(),
    );
    let wrong_scope_credential = credential(&wrong_scope, now);
    let mut wrong_scope_service = TiktokAuthenticatedReadService::fixture(
        FixtureTransport::responses([profile_response()]),
        TiktokFreshnessPolicy::default(),
    );
    let wrong_scope_envelope = wrong_scope_service
        .probe(&wrong_scope_credential, now)
        .unwrap();
    let mut exact_scope_consumer = MissionTiktokReadConsumer::new(read_scope);
    exact_scope_consumer
        .bind_exact_revision(wrong_scope_envelope.revision().clone())
        .unwrap();
    assert_eq!(
        exact_scope_consumer
            .accept(wrong_scope_envelope, &read_credential, now)
            .unwrap_err(),
        TiktokError::ScopeMismatch
    );
}
