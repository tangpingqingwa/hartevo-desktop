use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_clean_rooms_query_result_plugin::{
    AnalysisTemplateArn, AnalysisTemplateIdentity, AwsAccountId, AwsCleanRoomsOperation,
    AwsCleanRoomsProvider, AwsCleanRoomsQueryResultScope, AwsCleanRoomsQueryResultService,
    AwsCleanRoomsTransportError, BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_JSON,
    CONTRACT_SCHEMA, CollaborationId, CollaborationIdentity, ConsentScope, Cursor, EVIDENCE_LEVEL,
    FixtureTransport, GetProtectedQueryRequest, GetProtectedQueryResponse,
    ListProtectedQueriesRequest, ListProtectedQueriesResponse, LoopbackTransport, MembershipId,
    MembershipIdentity, MissionIdentity, PermissionSnapshot, PrivacyBudgetId,
    PrivacyBudgetIdentity, ProjectIdentity, ProtectedQueryFilter, ProtectedQueryId,
    ProtectedQueryIdentity, ProtectedQueryMetadata, ProtectedQueryMetadataInput,
    ProtectedQueryStatus, RecordingTransport, SecretReference, TransportProvenance,
    WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_SECRET: &str = "opaque-sigv4-secret-handle";
const RAW_SQL: &str = "SELECT member_id, revenue FROM private_member_table";
const RAW_OUTPUT: &str = "s3://private-bucket/results/protected-query.csv";
const RAW_MEMBER_A: &str = "member-raw-a";
const RAW_MEMBER_B: &str = "member-raw-b";
const RAW_PROVIDER_ERROR: &str = "private provider error text";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsCleanRoomsQueryResultScope {
    AwsCleanRoomsQueryResultScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_clean_rooms_query_result_plugin::AwsRegion::new("us-east-1")
            .expect("region"),
        CollaborationIdentity::with_arn(
            CollaborationId::new("collaboration-1").expect("collaboration"),
            "arn:aws:cleanrooms:us-east-1:123456789012:collaboration/collaboration-1",
        )
        .expect("collaboration identity"),
        MembershipIdentity::with_arn(
            MembershipId::new("membership-1").expect("membership"),
            "arn:aws:cleanrooms:us-east-1:123456789012:membership/membership-1",
        )
        .expect("membership identity"),
        AnalysisTemplateIdentity::with_revision(
            AnalysisTemplateArn::new(
                "arn:aws:cleanrooms:us-east-1:123456789012:membership/membership-1/analysistemplate/template-1",
            )
            .expect("analysis template"),
            "template-revision-3",
        )
        .expect("analysis template identity"),
        ProtectedQueryIdentity::with_arn(
            ProtectedQueryId::new("protected-query-1").expect("protected query"),
            "arn:aws:cleanrooms:us-east-1:123456789012:protectedQuery/protected-query-1",
        )
        .expect("protected query identity"),
        PrivacyBudgetIdentity::with_revision(
            PrivacyBudgetId::new("privacy-budget-1").expect("privacy budget"),
            "budget-revision-2",
        )
        .expect("privacy budget identity"),
        ProjectIdentity::new("project-1", 11).expect("project"),
        MissionIdentity::new("mission-1", 7).expect("mission"),
        WorkProductIdentity::new("work-product-1", 13).expect("work product"),
    )
    .expect("scope")
}

fn secret(scope: &AwsCleanRoomsQueryResultScope) -> SecretReference {
    SecretReference::sigv4(RAW_SECRET, scope, 1).expect("secret reference")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-1", 4, now() + Duration::days(7)).expect("consent")
}

fn metadata_input(status: ProtectedQueryStatus) -> ProtectedQueryMetadataInput {
    ProtectedQueryMetadataInput {
        status,
        created_at: now() - Duration::hours(2),
        last_updated_at: Some(now() - Duration::minutes(30)),
        duration_millis: Some(4_200),
        billed_units: Some(8),
        sql_text: Some(RAW_SQL.to_owned()),
        member_ids: vec![RAW_MEMBER_A.to_owned(), RAW_MEMBER_B.to_owned()],
        output_reference: Some(RAW_OUTPUT.to_owned()),
        provider_error: Some(RAW_PROVIDER_ERROR.to_owned()),
        query_compute_payer_account_id: Some("210987654321".to_owned()),
    }
}

fn metadata(
    scope: &AwsCleanRoomsQueryResultScope,
    status: ProtectedQueryStatus,
) -> ProtectedQueryMetadata {
    ProtectedQueryMetadata::new(scope, metadata_input(status)).expect("metadata")
}

fn recording_service(
    status: ProtectedQueryStatus,
) -> AwsCleanRoomsQueryResultService<RecordingTransport> {
    let scope = scope();
    let filter = ProtectedQueryFilter::for_scope(&scope, 20, None).expect("filter");
    let list_request =
        ListProtectedQueriesRequest::new(&scope, filter, None).expect("list request");
    let get_request = GetProtectedQueryRequest::for_scope(&scope).expect("get request");
    let query = metadata(&scope, status);
    let list_response = ListProtectedQueriesResponse::new(
        &list_request,
        vec![query.clone()],
        None,
        768,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let get_response =
        GetProtectedQueryResponse::new(&get_request, query, 768, TransportProvenance::Recording)
            .expect("get response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(list_response));
    transport.push_get_response(Ok(get_response));
    let provider = AwsCleanRoomsProvider::new(transport).expect("provider");
    AwsCleanRoomsQueryResultService::new(scope.clone(), secret(&scope), consent(), provider, now())
        .expect("service")
}

#[test]
fn contract_scope_registration_and_read_endpoints_are_digest_fenced() {
    let scope = scope();
    let filter = ProtectedQueryFilter::for_scope(&scope, 10, Some(ProtectedQueryStatus::Success))
        .expect("filter");
    let cursor = Cursor::new("opaque-next-token", &scope, &filter, 2).expect("cursor");
    let list_request =
        ListProtectedQueriesRequest::new(&scope, filter.clone(), Some(cursor.clone()))
            .expect("list request");
    let get_request = GetProtectedQueryRequest::for_scope(&scope).expect("get request");
    assert!(list_request.path_and_query().contains("/memberships/"));
    assert!(list_request.path_and_query().contains("nextToken="));
    assert!(!list_request.path_and_query().contains("opaque-next-token"));
    assert!(!get_request.path_and_query().contains("protected-query-1"));
    assert_eq!(list_request.filter().digest(), filter.digest());
    assert_eq!(
        list_request.cursor().expect("cursor").filter_digest(),
        &filter.digest()
    );

    let provider = AwsCleanRoomsProvider::default();
    let service = AwsCleanRoomsQueryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service");
    assert!(service.registration().validate().is_ok());
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
    assert_eq!(service.describe_capabilities().operations.len(), 2);
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
    assert_eq!(CONTRACT_SCHEMA, "hartevo.aws-clean-rooms-query-result/v1");
    assert_eq!(CONTRACT_DIGEST.len(), 64);
    assert!(CONTRACT_JSON.contains(CONTRACT_DIGEST));
    assert_eq!(EVIDENCE_LEVEL, "L1_PROVIDER_CONTRACT");
}

#[test]
fn fixture_and_loopback_are_deterministic_and_non_native() {
    let scope = scope();
    let fixture_provider = AwsCleanRoomsProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    let mut fixture_service = AwsCleanRoomsQueryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        fixture_provider,
        now(),
    )
    .expect("fixture service");
    let proposal = fixture_service
        .propose(fixture_service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, ProtectedQueryStatus::Success);
    assert!(proposal.list_complete);
    assert_eq!(proposal.list_pages, 1);
    assert!(proposal.protected_query.is_some());
    assert!(proposal.evidence.status_digest.is_some());
    assert!(proposal.evidence.duration_digest.is_some());
    assert!(proposal.evidence.billed_units_digest.is_some());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    assert!(fixture_service.verify(&proposal).review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for raw in [
        RAW_SQL,
        RAW_OUTPUT,
        RAW_MEMBER_A,
        RAW_MEMBER_B,
        RAW_PROVIDER_ERROR,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked in JSON: {raw}");
        assert!(!debug.contains(raw), "raw value leaked in Debug: {raw}");
    }

    let loopback_provider = AwsCleanRoomsProvider::new(LoopbackTransport::for_scope(&scope, now()))
        .expect("loopback provider");
    let mut loopback_service = AwsCleanRoomsQueryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        loopback_provider,
        now(),
    )
    .expect("loopback service");
    let loopback_proposal = loopback_service
        .propose(loopback_service.default_request(now()).expect("request"))
        .expect("loopback proposal");
    assert_eq!(loopback_proposal.state, ProtectedQueryStatus::Success);
    assert_eq!(loopback_proposal.provenance, TransportProvenance::Loopback);
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);
    assert!(!loopback_proposal.first_party);
}

#[test]
fn blocked_env_is_explicit_and_never_native() {
    let scope = scope();
    let provider: AwsCleanRoomsProvider<BlockedEnvTransport> = AwsCleanRoomsProvider::default();
    let mut service = AwsCleanRoomsQueryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, ProtectedQueryStatus::ProviderUnknown);
    assert_eq!(proposal.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!service.verify(&proposal).valid);
}

#[test]
fn all_provider_statuses_are_projected_without_gaining_effect_authority() {
    for status in [
        ProtectedQueryStatus::Submitted,
        ProtectedQueryStatus::Started,
        ProtectedQueryStatus::Cancelling,
        ProtectedQueryStatus::Success,
        ProtectedQueryStatus::Failed,
        ProtectedQueryStatus::Cancelled,
        ProtectedQueryStatus::TimedOut,
    ] {
        let mut service = recording_service(status);
        let proposal = service
            .propose(service.default_request(now()).expect("request"))
            .expect("proposal");
        assert_eq!(proposal.state, status);
        assert!(!proposal.can_be_adopted());
        assert!(proposal.validate_integrity().is_ok());
    }
}

#[test]
fn recording_replay_is_idempotent_and_conflict_is_digest_fenced() {
    let mut service = recording_service(ProtectedQueryStatus::Success);
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    let first = consumer
        .record(&proposal, "record-key-1")
        .expect("first record");
    let replay = consumer.record(&proposal, "record-key-1").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert_eq!(first.proposal_digest, replay.proposal_digest);
    assert!(replay.validate_integrity().is_ok());

    let mut other_service = recording_service(ProtectedQueryStatus::Failed);
    let other_proposal = other_service
        .propose(other_service.default_request(now()).expect("request"))
        .expect("other proposal");
    assert!(consumer.record(&other_proposal, "record-key-1").is_err());
}

#[test]
fn registration_revoke_reverse_restore_fences_proposals() {
    let mut service = recording_service(ProtectedQueryStatus::Success);
    let request = service.default_request(now()).expect("request");
    let revoked = service.revoke().expect("revoke");
    assert_eq!(
        revoked.new_status,
        hartevo_aws_clean_rooms_query_result_plugin::RegistrationStatus::Revoked
    );
    assert!(service.propose(request.clone()).is_err());
    service.restore_registration().expect("restore");
    let proposal = service.propose(request).expect("proposal after restore");
    assert_eq!(proposal.state, ProtectedQueryStatus::Success);
    service.reverse().expect("reverse");
    assert!(service.restore_registration().is_err());
}

#[test]
fn pagination_is_bounded_opaque_and_loop_fenced() {
    let scope = scope();
    let filter = ProtectedQueryFilter::for_scope(&scope, 10, None).expect("filter");
    let first_request =
        ListProtectedQueriesRequest::new(&scope, filter.clone(), None).expect("first request");
    let cursor = Cursor::new("page-two-token", &scope, &filter, 2).expect("cursor");
    let second_request =
        ListProtectedQueriesRequest::new(&scope, filter.clone(), Some(cursor.clone()))
            .expect("second request");
    let other_query =
        ProtectedQueryIdentity::new(ProtectedQueryId::new("other-query").expect("other query"))
            .expect("other identity");
    let first_page = ListProtectedQueriesResponse::new(
        &first_request,
        vec![
            ProtectedQueryMetadata::for_query(
                &scope,
                other_query,
                metadata_input(ProtectedQueryStatus::Started),
            )
            .expect("other metadata"),
        ],
        Some(cursor.clone()),
        640,
        TransportProvenance::Recording,
    )
    .expect("first page");
    let target = metadata(&scope, ProtectedQueryStatus::Success);
    let second_page = ListProtectedQueriesResponse::new(
        &second_request,
        vec![target.clone()],
        None,
        640,
        TransportProvenance::Recording,
    )
    .expect("second page");
    let get_request = GetProtectedQueryRequest::for_scope(&scope).expect("get request");
    let get_response =
        GetProtectedQueryResponse::new(&get_request, target, 640, TransportProvenance::Recording)
            .expect("get response");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Ok(first_page));
    transport.push_list_response(Ok(second_page));
    transport.push_get_response(Ok(get_response));
    let provider = AwsCleanRoomsProvider::new(transport).expect("provider");
    let mut service = AwsCleanRoomsQueryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service");
    let request = service.request(filter, 2, now()).expect("evidence request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, ProtectedQueryStatus::Success);
    assert_eq!(proposal.list_pages, 2);
    assert!(proposal.list_complete);

    let loop_cursor = Cursor::new(
        "loop-token",
        &scope,
        &ProtectedQueryFilter::for_scope(&scope, 10, None).expect("filter"),
        2,
    )
    .expect("loop cursor");
    let loop_filter = ProtectedQueryFilter::for_scope(&scope, 10, None).expect("loop filter");
    let loop_first_request = ListProtectedQueriesRequest::new(&scope, loop_filter.clone(), None)
        .expect("loop first request");
    let loop_second_request =
        ListProtectedQueriesRequest::new(&scope, loop_filter.clone(), Some(loop_cursor.clone()))
            .expect("loop second request");
    let repeated_cursor =
        Cursor::new("loop-token", &scope, &loop_filter, 3).expect("repeat cursor");
    let page_one = ListProtectedQueriesResponse::new(
        &loop_first_request,
        vec![],
        Some(loop_cursor),
        256,
        TransportProvenance::Recording,
    )
    .expect("loop page one");
    let page_two = ListProtectedQueriesResponse::new(
        &loop_second_request,
        vec![],
        Some(repeated_cursor),
        256,
        TransportProvenance::Recording,
    )
    .expect("loop page two");
    let mut loop_transport = RecordingTransport::default();
    loop_transport.push_list_response(Ok(page_one));
    loop_transport.push_list_response(Ok(page_two));
    let loop_provider = AwsCleanRoomsProvider::new(loop_transport).expect("loop provider");
    let mut loop_service = AwsCleanRoomsQueryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        loop_provider,
        now(),
    )
    .expect("loop service");
    let loop_proposal = loop_service
        .request(loop_filter, 3, now())
        .and_then(|request| loop_service.propose(request))
        .expect("loop proposal");
    assert_eq!(loop_proposal.state, ProtectedQueryStatus::Partial);
    assert_eq!(
        loop_proposal.failure.as_ref().expect("failure").category,
        "pagination_loop"
    );
}

#[test]
fn provider_and_permission_drift_are_rejected() {
    let scope = scope();
    let wrong_permissions =
        PermissionSnapshot::new(1, ["cleanrooms:GetProtectedQuery", "mission.scope"]);
    assert!(wrong_permissions.is_err());
    let provider =
        AwsCleanRoomsProvider::new(FixtureTransport::for_scope(&scope, now())).expect("provider");
    let registration = AwsCleanRoomsQueryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service")
    .registration()
    .clone();
    let tampered_definition =
        hartevo_aws_clean_rooms_query_result_plugin::Digest::from_text("drift");
    assert_ne!(tampered_definition, *registration.provider_digest());
    assert!(
        AwsCleanRoomsProvider::from_registration(
            &registration,
            FixtureTransport::for_scope(&scope, now()),
        )
        .is_ok()
    );
}

#[test]
fn transport_failures_preserve_access_loss_and_partial_states() {
    let scope = scope();
    let filter = ProtectedQueryFilter::for_scope(&scope, 10, None).expect("filter");
    let list_request = ListProtectedQueriesRequest::new(&scope, filter, None).expect("request");
    let mut transport = RecordingTransport::default();
    transport.push_list_response(Err(AwsCleanRoomsTransportError::Forbidden));
    let provider = AwsCleanRoomsProvider::new(transport).expect("provider");
    let mut service = AwsCleanRoomsQueryResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("service");
    let request = service
        .request(list_request.filter().clone(), 1, now())
        .expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, ProtectedQueryStatus::AccessLost);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").operation,
        AwsCleanRoomsOperation::ListProtectedQueries
    );
}

#[test]
fn non_serializing_secret_reference_has_no_material_surface() {
    let scope = scope();
    let reference = secret(&scope);
    let debug = format!("{reference:?}");
    assert!(!debug.contains(RAW_SECRET));
    assert!(debug.contains("reference_digest"));
    assert_eq!(reference.scope_digest(), &scope.digest());
    let mut revoked = reference.clone();
    revoked.revoke();
    assert!(revoked.is_revoked());
}
