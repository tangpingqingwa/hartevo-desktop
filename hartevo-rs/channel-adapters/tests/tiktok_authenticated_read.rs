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
    TiktokReadScope, TiktokRevisionIdentity, TiktokVideoId, TiktokVideoListCursor, TransportError,
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
    OAuthCredential::new(
        SecretReference::new("keychain://tiktok/open01").unwrap(),
        scope.clone(),
        [TiktokOAuthScope::UserInfoBasic, TiktokOAuthScope::VideoList]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        now + Duration::hours(1),
        Some(now + Duration::days(30)),
        1,
    )
    .unwrap()
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

    let first = service
        .list_videos(&read_credential, &mut cursor, now, 20)
        .unwrap();
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
    assert_eq!(duplicate.cursor_generation(), 1);
    assert_eq!(duplicate.page_digest(), first.page_digest());
    assert_eq!(cursor.generation(), 1);

    let final_page = service
        .list_videos(&read_credential, &mut cursor, now, 20)
        .unwrap();
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
