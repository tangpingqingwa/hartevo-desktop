use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_brex_spend_result_plugin::{
    BrexSpendObservation, BrexSpendProvider, BrexSpendReadRequest, BrexSpendResponse,
    BrexSpendResultService, BrexSpendScope, BrexSpendTransport, BrexSpendTransportError, CardId,
    ConsentScope, FixtureTransport, LimitObservation, LoopbackTransport, MAX_RESPONSE_BYTES,
    MissionBinding, MissionBrexSpendResultState, Money, ObservationStatus, OrganizationId,
    PageCursor, PermissionScope, PolicyObservation, PolicyStatus, ProjectBinding, QueryConfig,
    RecordingTransport, RevisionId, SecretReference, SpendEvidenceState, SpendObservation,
    SpendOperation, SpendQuery, TransactionId, TransportProvenance, UserId, WorkProductBinding,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_SECRET: &str = "opaque-brex-credential-handle";
const RAW_USER: &str = "user_private_fixture_123";
const RAW_CARD: &str = "card_private_fixture_456";
const RAW_MERCHANT: &str = "private-merchant-name";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> BrexSpendScope {
    let consent = ConsentScope::for_layer_one("consent-opaque", 4, now() + Duration::days(7))
        .expect("consent");
    let organization = OrganizationId::new("org_fixture_123").expect("organization");
    let mission = MissionBinding::new("mission-fixture", 6, consent.digest()).expect("mission");
    let permissions = PermissionScope::all(&organization, RevisionId::from_number(8), &consent)
        .expect("permissions");
    BrexSpendScope::new(
        organization,
        vec![UserId::new(RAW_USER).expect("user")],
        vec![CardId::new(RAW_CARD).expect("card")],
        vec![TransactionId::new("txn_fixture_789").expect("transaction")],
        vec![hartevo_brex_spend_result_plugin::LimitId::new("limit_fixture").expect("limit")],
        vec![hartevo_brex_spend_result_plugin::PolicyId::new("policy_fixture").expect("policy")],
        ProjectBinding::new("project-fixture", 2).expect("project"),
        mission,
        WorkProductBinding::new("work-product-fixture", 3).expect("work product"),
        RevisionId::from_number(9),
        consent,
        permissions,
    )
    .expect("scope")
}

fn secret(scope: &BrexSpendScope) -> SecretReference {
    SecretReference::new(
        RAW_SECRET,
        scope.scope_digest.clone(),
        scope.consent.digest(),
        scope.scope_revision.clone(),
    )
    .expect("secret")
}

fn recording_service(transport: RecordingTransport) -> BrexSpendResultService<RecordingTransport> {
    let value = scope();
    BrexSpendResultService::new(
        value.clone(),
        secret(&value),
        BrexSpendProvider::new(transport).expect("provider"),
        now(),
    )
    .expect("service")
}

fn spend_observation(scope: &BrexSpendScope) -> SpendObservation {
    SpendObservation::aggregate(
        &scope.scope_digest,
        Some(&scope.users[0]),
        Some(&scope.cards[0]),
        Some(&scope.transactions[0]),
        Some(RAW_MERCHANT),
        now() - Duration::hours(24),
        now(),
        Money::new("USD", 12_500).expect("money"),
        3,
        ObservationStatus::Observed,
    )
    .expect("spend observation")
}

fn response(
    request: &BrexSpendReadRequest,
    observations: Vec<BrexSpendObservation>,
    cursor: Option<PageCursor>,
) -> BrexSpendResponse {
    BrexSpendResponse::new(
        request,
        observations,
        cursor,
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
}

#[test]
fn scope_revision_consent_and_registration_are_digest_fenced() {
    let value = scope();
    assert!(value.verify().is_ok());
    assert_eq!(value.users.len(), 1);
    assert_eq!(value.cards.len(), 1);
    assert_eq!(value.transactions.len(), 1);
    assert_eq!(value.limits.len(), 1);
    assert_eq!(value.policies.len(), 1);

    let mut service = recording_service(RecordingTransport::default());
    assert!(service.registration().validate().is_ok());
    assert!(service.registration().reversible);
    assert!(service.registration().revocable);
    assert!(!service.provider().definition().connected);
    assert!(!service.provider().definition().native);
    assert!(!service.provider().definition().first_party);

    let request = service.default_request(now()).expect("request");
    let mut proposal = service.propose(request).expect("proposal");
    proposal.scope_revision = RevisionId::from_number(99);
    assert!(service.verify_proposal(&proposal).is_err());

    service.set_now(now() + Duration::days(8));
    assert!(service.default_request(now() + Duration::days(8)).is_err());

    service.revoke_registration().expect("revoke");
    assert!(service.default_request(now()).is_err());
}

#[test]
fn secret_and_cursor_debug_and_json_are_redacted() {
    let value = scope();
    let secret = secret(&value);
    let secret_debug = format!("{secret:?}");
    assert!(!secret_debug.contains(RAW_SECRET));
    assert!(
        !serde_json::to_string(&value)
            .expect("scope JSON")
            .contains(RAW_USER)
    );
    assert!(
        !serde_json::to_string(&value)
            .expect("scope JSON")
            .contains(RAW_CARD)
    );

    let service = recording_service(RecordingTransport::default());
    let request = service.default_request(now()).expect("request");
    let cursor = PageCursor::new(
        "opaque-provider-cursor",
        value.scope_digest.clone(),
        request.query_digest(),
        request.config_digest(),
        2,
    )
    .expect("cursor");
    let debug = format!("{cursor:?}");
    let json = serde_json::to_string(&cursor).expect("cursor JSON");
    assert!(!debug.contains("opaque-provider-cursor"));
    assert!(!json.contains("opaque-provider-cursor"));
    assert!(
        !serde_json::to_string(service.registration())
            .expect("registration JSON")
            .contains(RAW_SECRET)
    );
}

#[test]
fn complete_spend_is_redacted_review_only_and_idempotent() {
    let value = scope();
    let mut service = recording_service(RecordingTransport::default());
    let request = service.default_request(now()).expect("request");
    let page = response(
        &request,
        vec![BrexSpendObservation::Spend(spend_observation(&value))],
        None,
    );
    service
        .provider_mut()
        .transport_mut()
        .push_read_response(page);

    let proposal = service.propose(request.clone()).expect("proposal");
    let record = service.record(&proposal).expect("record");
    let replay = service.record(&proposal).expect("replay");
    assert!(!record.replayed);
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);

    let evidence = service.verify(&proposal, &record).expect("evidence");
    assert_eq!(evidence.status, SpendEvidenceState::Complete);
    assert!(evidence.pagination.complete);
    assert!(!evidence.can_be_adopted());
    assert!(evidence.is_review_only());
    assert!(!evidence.authority.connected);
    assert!(!evidence.authority.native);
    assert!(!evidence.authority.first_party);
    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    for raw in [RAW_USER, RAW_CARD, RAW_MERCHANT, RAW_SECRET] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    assert!(evidence.verify().is_ok());

    let mut consumer = service.consumer().expect("consumer");
    let mission = consumer.consume(&evidence).expect("consume");
    assert_eq!(mission.state, MissionBrexSpendResultState::DecisionReady);
    assert!(!mission.adopts_outcome);
    assert!(!mission.adopts_work_product);
    assert!(consumer.consume(&evidence).is_err());
    let recorded = consumer.record(&evidence).expect("consumer record");
    let consumer_replay = consumer.record(&evidence).expect("consumer replay");
    assert!(!recorded.replayed);
    assert!(consumer_replay.replayed);
}

#[test]
fn bounded_pagination_becomes_partial_and_carries_only_cursor_digest() {
    let value = scope();
    let mut service = recording_service(RecordingTransport::default());
    let config = QueryConfig::new(
        10,
        1,
        128,
        MAX_RESPONSE_BYTES,
        hartevo_brex_spend_result_plugin::RetryPolicy::default(),
    )
    .expect("bounded config");
    let request = service
        .request(SpendOperation::ReadSpend, config, now())
        .expect("request");
    let cursor = PageCursor::new(
        "opaque-next-page",
        value.scope_digest.clone(),
        request.query_digest(),
        request.config_digest(),
        2,
    )
    .expect("cursor");
    service
        .provider_mut()
        .transport_mut()
        .push_read_response(response(
            &request,
            vec![BrexSpendObservation::Spend(spend_observation(&value))],
            Some(cursor),
        ));
    let result = service.read(request).expect("partial result");
    assert_eq!(result.evidence.status, SpendEvidenceState::Partial);
    assert!(!result.evidence.pagination.complete);
    assert_eq!(result.evidence.pagination.pages_observed, 1);
    assert_eq!(result.evidence.pagination.cursor_digests.len(), 1);
    assert!(
        !serde_json::to_string(&result.evidence)
            .expect("evidence JSON")
            .contains("opaque-next-page")
    );
}

#[test]
fn denied_expired_rate_limited_and_blocked_env_are_typed_non_native_states() {
    let cases = [
        (
            BrexSpendTransportError::Denied {
                status_code: Some(403),
            },
            SpendEvidenceState::Denied,
        ),
        (
            BrexSpendTransportError::Expired,
            SpendEvidenceState::Expired,
        ),
        (
            BrexSpendTransportError::RateLimited {
                status_code: Some(429),
                retry_after_seconds: Some(11),
            },
            SpendEvidenceState::RateLimited,
        ),
    ];
    for (error, expected) in cases {
        let mut transport = RecordingTransport::default();
        transport.push_response(Err(error));
        let mut service = recording_service(transport);
        let result = service.read_spend(now()).expect("typed provider result");
        assert_eq!(result.evidence.status, expected);
        assert!(!result.evidence.authority.connected);
        assert!(!result.evidence.authority.native);
        if expected == SpendEvidenceState::RateLimited {
            assert_eq!(
                result
                    .evidence
                    .backoff
                    .expect("backoff")
                    .retry_after_seconds,
                Some(11)
            );
        }
    }

    let value = scope();
    let mut blocked = BrexSpendResultService::new(
        value.clone(),
        secret(&value),
        BrexSpendProvider::default(),
        now(),
    )
    .expect("blocked service");
    let result = blocked.read_spend(now()).expect("blocked result");
    assert_eq!(result.evidence.status, SpendEvidenceState::ProviderUnknown);
    assert_eq!(result.evidence.provenance, TransportProvenance::BlockedEnv);
    assert!(!result.evidence.provenance.connected());
    assert!(!result.evidence.provenance.native());
    assert!(!result.evidence.provenance.first_party());
}

#[test]
fn fixture_recording_fake_loopback_are_never_connected_or_native() {
    let value = scope();
    assert_transport(
        BrexSpendProvider::new(FixtureTransport::for_scope(&value, now()))
            .expect("fixture provider"),
        value.clone(),
        TransportProvenance::Fixture,
    );
    assert_transport(
        BrexSpendProvider::new(LoopbackTransport::for_scope(&value, now()))
            .expect("loopback provider"),
        value.clone(),
        TransportProvenance::Loopback,
    );

    let mut fake = hartevo_brex_spend_result_plugin::FakeTransport::default();
    let provider = BrexSpendProvider::new(std::mem::take(&mut fake)).expect("fake provider");
    assert_eq!(provider.provenance(), TransportProvenance::Fake);
    assert!(!provider.provenance().connected());
    assert!(!provider.provenance().native());
    assert!(!provider.provenance().first_party());
}

fn assert_transport<T: BrexSpendTransport>(
    provider: BrexSpendProvider<T>,
    value: BrexSpendScope,
    expected: TransportProvenance,
) {
    let mut service = BrexSpendResultService::new(value.clone(), secret(&value), provider, now())
        .expect("service");
    let result = service.read_spend(now()).expect("result");
    assert_eq!(result.evidence.provenance, expected);
    assert!(!result.evidence.provenance.connected());
    assert!(!result.evidence.provenance.native());
    assert!(!result.evidence.provenance.first_party());
}

#[test]
fn tampered_record_and_proposal_fail_closed() {
    let value = scope();
    let mut service = recording_service(RecordingTransport::default());
    let request = service.default_request(now()).expect("request");
    service
        .provider_mut()
        .transport_mut()
        .push_read_response(response(
            &request,
            vec![BrexSpendObservation::Spend(spend_observation(&value))],
            None,
        ));
    let proposal = service.propose(request).expect("proposal");
    let mut tampered_proposal = proposal.clone();
    tampered_proposal.scope_digest = hartevo_brex_spend_result_plugin::Digest::from_text("drift");
    assert!(service.record(&tampered_proposal).is_err());
    let mut tampered_query = proposal.clone();
    tampered_query.request.query = SpendQuery::Limits {
        include_utilization: false,
    };
    assert!(service.record(&tampered_query).is_err());

    let record = service.record(&proposal).expect("record");
    let mut tampered_record = record.clone();
    tampered_record.pages[0].response_bytes += 1;
    assert!(service.verify(&proposal, &tampered_record).is_err());
}

#[test]
fn limit_and_policy_reads_remain_bounded_and_read_only() {
    let value = scope();
    let limit = LimitObservation::new(
        &value,
        Some(&value.limits[0]),
        now() - Duration::days(30),
        now(),
        Money::new("USD", 100_000).expect("limit"),
        Money::new("USD", 10_000).expect("spent"),
        Money::new("USD", 90_000).expect("remaining"),
        ObservationStatus::Observed,
    )
    .expect("limit observation");
    let policy = PolicyObservation::new(
        &value,
        Some(&value.policies[0]),
        hartevo_brex_spend_result_plugin::Digest::from_text("policy-revision"),
        PolicyStatus::Active,
        3,
    )
    .expect("policy observation");
    assert!(limit.validate().is_ok());
    assert!(policy.validate().is_ok());
    assert!(!hartevo_brex_spend_result_plugin::Layer1Authority::external_writes());
    assert!(!hartevo_brex_spend_result_plugin::Layer1Authority::effective_authorization());
}
