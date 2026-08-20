use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_connect_contact_result_plugin::{
    AgentId, AttributeKeyClass, AttributeValueInput, AwsAccountId, AwsConnectContactResultError,
    AwsConnectContactResultService, AwsConnectContactScope, AwsConnectProvider,
    AwsConnectTransportError, ConnectInstanceId, ConsentScope, ContactChannel,
    ContactEvidenceState, ContactFilter, ContactLifecycle, ContactRecord, ContactSort,
    ContactSortField, ContactState, DescribeContactRequest, DescribeContactResponse, Digest,
    FixtureTransport, GetContactAttributesRequest, GetContactAttributesResponse, InitiationMethod,
    LoopbackTransport, MissionIdentity, OpaqueNextToken, PermissionSnapshot, ProjectIdentity,
    QueueId, RecordingTransport, SearchContactsRequest, SearchContactsResponse, SearchCursor,
    SecretReference, SortDirection, TransportProvenance, UtcTimeWindow, WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_CONTACT_ID: &str = "contact-fixture-001";
const RAW_INSTANCE_ID: &str = "instance-fixture-001";
const RAW_QUEUE_ID: &str = "queue-fixture-001";
const RAW_AGENT_ID: &str = "agent-fixture-001";
const RAW_PHONE: &str = "+1-202-555-0100";
const RAW_EMAIL: &str = "customer@example.invalid";
const RAW_TRANSCRIPT: &str = "private transcript must never be retained";
const RAW_RECORDING: &str = "s3://private-recording/object";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsConnectContactScope {
    AwsConnectContactScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_connect_contact_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        ConnectInstanceId::new(RAW_INSTANCE_ID).expect("instance"),
        hartevo_aws_connect_contact_result_plugin::ContactId::new(RAW_CONTACT_ID).expect("contact"),
        QueueId::new(RAW_QUEUE_ID).expect("queue"),
        AgentId::new(RAW_AGENT_ID).expect("agent"),
        ContactChannel::Voice,
        UtcTimeWindow::new(now() - Duration::hours(2), now() + Duration::hours(2)).expect("window"),
        ProjectIdentity::new("project-contact", 11).expect("project"),
        MissionIdentity::new("mission-contact", 7).expect("mission"),
        WorkProductIdentity::new("work-product-contact", 13).expect("work product"),
    )
    .expect("scope")
}

fn secret(scope: &AwsConnectContactScope) -> SecretReference {
    SecretReference::sigv4("opaque-native-credential-handle", scope, 1).expect("secret")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-contact", 4, now() + Duration::days(7)).expect("consent")
}

fn lifecycle(scope: &AwsConnectContactScope) -> ContactLifecycle {
    let initiated = scope.time_window().start() + Duration::minutes(10);
    let connected = initiated + Duration::minutes(2);
    let ended = connected + Duration::minutes(5);
    ContactLifecycle::new(
        initiated,
        Some(connected),
        ended,
        Some(ended),
        ContactState::Ended,
        InitiationMethod::Inbound,
        Some(hartevo_aws_connect_contact_result_plugin::DisconnectReasonClass::AgentDisconnect),
    )
    .expect("lifecycle")
}

fn contact(scope: &AwsConnectContactScope) -> ContactRecord {
    ContactRecord::for_scope(scope, lifecycle(scope)).expect("contact")
}

fn fixture_service() -> AwsConnectContactResultService<FixtureTransport> {
    let exact_scope = scope();
    let provider = AwsConnectProvider::new(FixtureTransport::for_scope(&exact_scope, now()))
        .expect("fixture provider");
    AwsConnectContactResultService::new(
        exact_scope.clone(),
        secret(&exact_scope),
        consent(),
        provider,
        now(),
    )
    .expect("fixture service")
}

fn recording_service() -> AwsConnectContactResultService<RecordingTransport> {
    let exact_scope = scope();
    let provider =
        AwsConnectProvider::new(RecordingTransport::default()).expect("recording provider");
    AwsConnectContactResultService::new(
        exact_scope.clone(),
        secret(&exact_scope),
        consent(),
        provider,
        now(),
    )
    .expect("recording service")
}

#[test]
fn registration_and_contract_are_exactly_bound_and_redacted() {
    let service = fixture_service();
    service.registration().validate().expect("registration");
    assert_eq!(
        service.registration().contract_digest().as_str(),
        hartevo_aws_connect_contact_result_plugin::CONTRACT_DIGEST
    );
    assert_eq!(
        service.registration().scope_digest(),
        &service.scope().digest()
    );
    assert_eq!(service.describe_capabilities().operations.len(), 3);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert!(!service.describe_capabilities().outcome_adoption);
    assert!(!service.describe_capabilities().work_product_adoption);

    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    let registration_debug = format!("{:?}", service.registration());
    for raw in [
        "opaque-native-credential-handle",
        RAW_CONTACT_ID,
        RAW_INSTANCE_ID,
        RAW_QUEUE_ID,
        RAW_AGENT_ID,
    ] {
        assert!(
            !registration_json.contains(raw),
            "raw value leaked in JSON: {raw}"
        );
        assert!(
            !registration_debug.contains(raw),
            "raw value leaked in Debug: {raw}"
        );
    }
}

#[test]
fn fixture_proposal_describes_contact_and_only_digest_attributes() {
    let mut service = fixture_service();
    let request = service
        .request_with_attributes(
            now(),
            vec![
                AttributeKeyClass::CaseReference,
                AttributeKeyClass::Language,
            ],
        )
        .expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, ContactEvidenceState::Completed);
    assert!(proposal.search.list_complete);
    assert_eq!(proposal.search.pages, 1);
    assert!(proposal.contact.is_some());
    assert_eq!(
        proposal
            .attributes
            .as_ref()
            .expect("attributes")
            .attributes
            .len(),
        2
    );
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.durable_receipt);
    assert!(!proposal.independent_readback);
    assert!(!proposal.outcome_adopted);
    assert!(!proposal.work_product_adopted);
    proposal.validate_integrity().expect("proposal integrity");
    assert!(service.verify(&proposal).review_eligible);

    let json = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for raw in [
        RAW_CONTACT_ID,
        RAW_INSTANCE_ID,
        RAW_QUEUE_ID,
        RAW_AGENT_ID,
        RAW_PHONE,
        RAW_EMAIL,
        RAW_TRANSCRIPT,
        RAW_RECORDING,
    ] {
        assert!(!json.contains(raw), "raw value leaked in JSON: {raw}");
        assert!(!debug.contains(raw), "raw value leaked in Debug: {raw}");
    }
}

#[test]
fn consumer_records_redacted_candidate_deterministically() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    let first = consumer
        .record(&proposal, "mission-contact-result-1")
        .expect("record");
    let replay = consumer
        .record(&proposal, "mission-contact-result-1")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.candidate_digest, replay.candidate_digest);
    assert_eq!(consumer.record_count(), 1);
    first.validate_integrity().expect("candidate integrity");
    assert!(!first.durable);
    assert!(!first.provider_receipt);
    assert!(!first.independent_readback);
    assert!(!first.outcome_adopted);
    assert!(!first.work_product_adopted);
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_connected_or_native() {
    let exact_scope = scope();
    let mut loopback = AwsConnectContactResultService::new(
        exact_scope.clone(),
        secret(&exact_scope),
        consent(),
        AwsConnectProvider::new(LoopbackTransport::for_scope(&exact_scope, now()))
            .expect("loopback"),
        now(),
    )
    .expect("loopback service");
    let loopback_proposal = loopback
        .propose(loopback.default_request(now()).expect("request"))
        .expect("loopback proposal");
    assert_eq!(loopback_proposal.provenance, TransportProvenance::Loopback);
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);

    let mut blocked = AwsConnectContactResultService::new(
        exact_scope.clone(),
        secret(&exact_scope),
        consent(),
        AwsConnectProvider::new(hartevo_aws_connect_contact_result_plugin::BlockedEnvTransport)
            .expect("blocked provider"),
        now(),
    )
    .expect("blocked service");
    let blocked_proposal = blocked
        .propose(blocked.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(
        blocked_proposal.state,
        ContactEvidenceState::ProviderUnknown
    );
    assert_eq!(blocked_proposal.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        blocked_proposal.failure.as_ref().expect("failure").category,
        "search_contacts:blocked_env"
    );
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);
}

#[test]
fn utc_window_page_bounds_and_allowlists_fail_closed() {
    assert!(UtcTimeWindow::new(now(), now()).is_err());
    assert!(UtcTimeWindow::new(now(), now() + Duration::days(32)).is_err());
    let exact_scope = scope();
    assert!(SearchContactsRequest::for_scope(&exact_scope, 101, 1, now()).is_err());
    assert!(SearchContactsRequest::for_scope(&exact_scope, 1, 5, now()).is_err());
    assert!(AttributeKeyClass::from_wire_key("phone_number").is_err());
    assert!(AttributeKeyClass::from_wire_key("email").is_err());
    assert!(AttributeKeyClass::from_wire_key("transcript").is_err());

    let wrong_window = UtcTimeWindow::new(now() - Duration::hours(1), now() + Duration::hours(1))
        .expect("wrong but valid window");
    assert!(
        SearchContactsRequest::new(
            &exact_scope,
            wrong_window,
            vec![ContactFilter::ContactId(exact_scope.contact().clone())],
            ContactSort::new(
                ContactSortField::InitiationTimestamp,
                SortDirection::Ascending
            ),
            1,
            1,
            Vec::new(),
            now(),
        )
        .is_err()
    );
}

#[test]
fn attribute_values_are_hashed_at_the_boundary() {
    let exact_scope = scope();
    let request = GetContactAttributesRequest::for_scope(
        &exact_scope,
        vec![AttributeKeyClass::CaseReference],
    )
    .expect("attribute request");
    let input = AttributeValueInput::from_raw(
        AttributeKeyClass::CaseReference,
        format!("{RAW_EMAIL};{RAW_PHONE};{RAW_TRANSCRIPT};{RAW_RECORDING}"),
    )
    .expect("digest input");
    let response = GetContactAttributesResponse::new(
        &request,
        vec![input],
        256,
        TransportProvenance::Recording,
    )
    .expect("attribute response");
    let json = serde_json::to_string(response.evidence()).expect("evidence JSON");
    let debug = format!("{response:?}");
    for raw in [RAW_PHONE, RAW_EMAIL, RAW_TRANSCRIPT, RAW_RECORDING] {
        assert!(!json.contains(raw), "raw attribute leaked in JSON: {raw}");
        assert!(!debug.contains(raw), "raw attribute leaked in Debug: {raw}");
    }
    response
        .validate_integrity(&request)
        .expect("attribute integrity");
    assert_eq!(response.evidence().attributes.len(), 1);
    assert!(
        GetContactAttributesResponse::new(
            &request,
            vec![
                AttributeValueInput::from_raw(AttributeKeyClass::Language, "en-US").expect("input")
            ],
            256,
            TransportProvenance::Recording,
        )
        .is_err()
    );
}

#[test]
fn partial_search_is_non_adoptable_and_next_token_is_opaque() {
    let mut service = recording_service();
    let exact_scope = service.scope().clone();
    let request = SearchContactsRequest::for_scope(&exact_scope, 1, 1, now())
        .expect("bounded request")
        .bind(
            service.provider().definition().provider_digest.clone(),
            service.registration().registration_digest().clone(),
        );
    let record = contact(&exact_scope);
    let token = OpaqueNextToken::new("provider-next-token-secret").expect("token");
    let search_response = SearchContactsResponse::new(
        &request,
        vec![record.clone()],
        Some(token.clone()),
        512,
        TransportProvenance::Recording,
    )
    .expect("search response");
    let describe_request =
        DescribeContactRequest::for_scope(&exact_scope).expect("describe request");
    let describe_response = DescribeContactResponse::new(
        &describe_request,
        record,
        512,
        TransportProvenance::Recording,
    )
    .expect("describe response");
    service
        .provider_mut()
        .transport_mut()
        .push_search_response(Ok(search_response));
    service
        .provider_mut()
        .transport_mut()
        .push_describe_response(Ok(describe_response));
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, ContactEvidenceState::Partial);
    assert!(!proposal.search.list_complete);
    assert_eq!(proposal.search.pages, 1);
    assert_eq!(proposal.search.cursor_digest, Some(token.digest()));
    assert!(!service.verify(&proposal).review_eligible);
    let token_debug = format!("{token:?}");
    assert!(!token_debug.contains("provider-next-token-secret"));
}

#[test]
fn repeated_cursor_is_rejected_before_unbounded_replay() {
    let mut service = recording_service();
    let exact_scope = service.scope().clone();
    let request = SearchContactsRequest::for_scope(&exact_scope, 1, 4, now())
        .expect("request")
        .bind(
            service.provider().definition().provider_digest.clone(),
            service.registration().registration_digest().clone(),
        );
    let record = contact(&exact_scope);
    let token = OpaqueNextToken::new("loop-token").expect("token");
    let first = SearchContactsResponse::new(
        &request,
        vec![record.clone()],
        Some(token.clone()),
        512,
        TransportProvenance::Recording,
    )
    .expect("first");
    let cursor = SearchCursor::new(token.clone(), &request, 2).expect("cursor");
    let second_request = request.with_cursor(cursor).expect("second request");
    let second = SearchContactsResponse::new(
        &second_request,
        vec![record],
        Some(token),
        512,
        TransportProvenance::Recording,
    )
    .expect("second");
    service
        .provider_mut()
        .transport_mut()
        .push_search_response(Ok(first));
    service
        .provider_mut()
        .transport_mut()
        .push_search_response(Ok(second));
    assert!(matches!(
        service.propose(request),
        Err(AwsConnectContactResultError::CursorLoop)
    ));
}

#[test]
fn transport_failures_project_explicit_non_adoptable_states() {
    let cases = [
        (
            AwsConnectTransportError::BadRequest,
            ContactEvidenceState::ProviderUnknown,
        ),
        (
            AwsConnectTransportError::Unauthorized,
            ContactEvidenceState::AccessLoss,
        ),
        (
            AwsConnectTransportError::Forbidden,
            ContactEvidenceState::AccessLoss,
        ),
        (
            AwsConnectTransportError::RateLimited {
                retry_after_seconds: Some(10),
            },
            ContactEvidenceState::Throttled,
        ),
        (
            AwsConnectTransportError::ServerError { status: 500 },
            ContactEvidenceState::ProviderUnknown,
        ),
        (
            AwsConnectTransportError::Timeout,
            ContactEvidenceState::ProviderUnknown,
        ),
        (
            AwsConnectTransportError::AccessLost,
            ContactEvidenceState::AccessLoss,
        ),
        (
            AwsConnectTransportError::Partial,
            ContactEvidenceState::Partial,
        ),
    ];
    for (error, expected) in cases {
        let mut service = recording_service();
        service
            .provider_mut()
            .transport_mut()
            .push_search_response(Err(error));
        let request = service.default_request(now()).expect("request");
        let proposal = service.propose(request).expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert!(!proposal.can_be_adopted());
        assert!(!service.verify(&proposal).review_eligible);
    }
}

#[test]
fn retention_loss_and_access_loss_are_distinct_projections() {
    let mut service = recording_service();
    let exact_scope = service.scope().clone();
    let request = service.default_request(now()).expect("request");
    let record = contact(&exact_scope);
    let search = SearchContactsResponse::new(
        &request,
        vec![record.clone()],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("search");
    service
        .provider_mut()
        .transport_mut()
        .push_search_response(Ok(search));
    service
        .provider_mut()
        .transport_mut()
        .push_describe_response(Err(AwsConnectTransportError::NotFound));
    let retention = service.propose(request).expect("retention proposal");
    assert_eq!(retention.state, ContactEvidenceState::RetentionExpired);
    assert!(retention.failure.is_some());

    let mut access = recording_service();
    access
        .provider_mut()
        .transport_mut()
        .push_search_response(Err(AwsConnectTransportError::Forbidden));
    let access_proposal = access
        .propose(access.default_request(now()).expect("request"))
        .expect("access proposal");
    assert_eq!(access_proposal.state, ContactEvidenceState::AccessLoss);
}

#[test]
fn registration_revision_and_replay_fences_reject_stale_material() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let old_registration_digest = service.registration().registration_digest().clone();
    let revoked = service.revoke().expect("revoke");
    assert_ne!(old_registration_digest, revoked.registration_digest);
    assert!(
        service
            .propose(service.default_request(now()).expect("request"))
            .is_err()
    );
    let report = service.verify(&proposal);
    assert!(!report.valid);
    assert!(report.failures.contains(
        &hartevo_aws_connect_contact_result_plugin::VerificationFailure::RegistrationInactive
    ));
    let restored = service.restore_registration().expect("restore");
    assert_ne!(revoked.registration_digest, restored.registration_digest);
    assert!(service.registration().validate().is_ok());

    let mut consumer = service.consumer().expect("consumer");
    let new_proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("new proposal");
    let first = consumer
        .record(&new_proposal, "same-key")
        .expect("first record");
    let mut tampered = new_proposal.clone();
    tampered.state = ContactEvidenceState::Partial;
    assert!(matches!(
        consumer.consume(&tampered),
        Err(AwsConnectContactResultError::TamperedEvidence)
    ));
    assert!(!first.replayed);
}

#[test]
fn stale_mission_revision_is_rejected_by_consumer_scope_fence() {
    let service = fixture_service();
    let registration = service.registration().clone();
    let stale_scope = AwsConnectContactScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_connect_contact_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        ConnectInstanceId::new(RAW_INSTANCE_ID).expect("instance"),
        hartevo_aws_connect_contact_result_plugin::ContactId::new(RAW_CONTACT_ID).expect("contact"),
        QueueId::new(RAW_QUEUE_ID).expect("queue"),
        AgentId::new(RAW_AGENT_ID).expect("agent"),
        ContactChannel::Voice,
        UtcTimeWindow::new(now() - Duration::hours(2), now() + Duration::hours(2)).expect("window"),
        ProjectIdentity::new("project-contact", 11).expect("project"),
        MissionIdentity::new("mission-contact", 8).expect("stale mission"),
        WorkProductIdentity::new("work-product-contact", 13).expect("work product"),
    )
    .expect("stale scope");
    assert!(
        hartevo_aws_connect_contact_result_plugin::MissionAwsConnectContactConsumer::new(
            stale_scope,
            registration,
        )
        .is_err()
    );
}

#[test]
fn response_bytes_and_contact_scope_are_bounded() {
    let exact_scope = scope();
    let request = SearchContactsRequest::for_scope(&exact_scope, 1, 1, now()).expect("request");
    let record = contact(&exact_scope);
    assert!(
        SearchContactsResponse::new(
            &request,
            vec![record.clone(), record.clone()],
            None,
            512,
            TransportProvenance::Recording,
        )
        .is_err()
    );
    assert!(
        SearchContactsResponse::new(
            &request,
            vec![record],
            None,
            2 * 1024 * 1024,
            TransportProvenance::Recording,
        )
        .is_err()
    );
}

#[test]
fn permission_snapshot_rejects_mutation_and_only_exposes_read_actions() {
    let valid = PermissionSnapshot::for_layer_one(1);
    assert!(!valid.permissions.is_empty());
    let invalid = PermissionSnapshot::new(1, ["connect:UpdateContactAttributes"]);
    assert!(invalid.is_err());
    assert!(valid.permissions.iter().all(|permission| {
        permission.contains("SearchContacts")
            || permission.contains("DescribeContact")
            || permission.contains("GetContactAttributes")
            || permission == "mission.scope"
    }));
}

#[test]
fn provider_definition_and_provenance_are_digest_bound() {
    let exact_scope = scope();
    let provider = AwsConnectProvider::new(FixtureTransport::for_scope(&exact_scope, now()))
        .expect("provider");
    provider.definition().validate().expect("definition");
    assert_eq!(provider.provenance(), &TransportProvenance::Fixture);
    assert!(!provider.provenance().is_native());
    assert!(!provider.provenance().is_connected());
    let debug = format!("{provider:?}");
    assert!(!debug.contains(RAW_PHONE));
    assert!(!debug.contains(RAW_EMAIL));
}

#[test]
fn digest_parse_rejects_non_sha_values() {
    assert!(Digest::parse("not-a-digest").is_err());
    let digest = Digest::from_text("stable");
    assert_eq!(digest.as_str().len(), 64);
}

#[test]
fn request_cursor_binding_rejects_query_drift() {
    let exact_scope = scope();
    let request = SearchContactsRequest::for_scope(&exact_scope, 10, 4, now()).expect("request");
    let token = OpaqueNextToken::new("token-a").expect("token");
    let cursor = SearchCursor::new(token, &request, 2).expect("cursor");
    let drifted = SearchContactsRequest::new(
        &exact_scope,
        exact_scope.time_window().clone(),
        vec![
            ContactFilter::ContactId(exact_scope.contact().clone()),
            ContactFilter::InstanceId(exact_scope.instance().clone()),
            ContactFilter::QueueId(exact_scope.queue().clone()),
            ContactFilter::AgentId(exact_scope.agent().clone()),
            ContactFilter::Channel(ContactChannel::Chat),
        ],
        ContactSort::default_initiation(),
        10,
        4,
        Vec::new(),
        now(),
    );
    assert!(drifted.is_err());
    assert!(cursor.validate_against(&request).is_ok());
    assert!(
        cursor
            .validate_against(
                &SearchContactsRequest::for_scope(&exact_scope, 9, 4, now())
                    .expect("drifted request")
            )
            .is_err()
    );
}
