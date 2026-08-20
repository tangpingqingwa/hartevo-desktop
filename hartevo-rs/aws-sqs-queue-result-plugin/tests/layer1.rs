use chrono::{Duration, TimeZone, Utc};

use hartevo_aws_sqs_queue_result_plugin::{
    ApproximateQueueCounts, AwsAccountId, AwsRegion, AwsSqsProvider, AwsSqsQueueContract,
    AwsSqsQueueScope, AwsSqsQueueService, AwsSqsQueueTransportError, BlockedEnvTransport,
    ConsumerDeployment, Cursor, FixtureTransport, GetQueueAttributesRequest,
    GetQueueAttributesResponse, GetQueueUrlRequest, GetQueueUrlResponse, ListQueuesRequest,
    ListQueuesResponse, MissionId, MissionIdentity, PermissionSnapshot, ProjectId, ProjectIdentity,
    QueueArn, QueueAttributesInput, QueueEvidenceState, QueueFailureClass, QueueIdentity,
    QueueKind, QueueListFilter, QueueName, QueueUrl, RecordingTransport, RedrivePolicyInput,
    Revision, SecretReference, TransportProvenance, VerificationFailure, WorkProductId,
    WorkProductIdentity,
};

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().expect("timestamp")
}

fn scope() -> AwsSqsQueueScope {
    let account = AwsAccountId::new("123456789012").expect("account");
    let region = AwsRegion::new("us-east-1").expect("region");
    let queue_name = QueueName::new("mission-work").expect("queue name");
    let queue_url = QueueUrl::new("https://sqs.us-east-1.amazonaws.com/123456789012/mission-work")
        .expect("queue URL");
    let queue_arn =
        QueueArn::new("arn:aws:sqs:us-east-1:123456789012:mission-work").expect("queue ARN");
    let dead_letter_name = QueueName::new("mission-work-dlq").expect("DLQ name");
    let dead_letter_url =
        QueueUrl::new("https://sqs.us-east-1.amazonaws.com/123456789012/mission-work-dlq")
            .expect("DLQ URL");
    let dead_letter_arn =
        QueueArn::new("arn:aws:sqs:us-east-1:123456789012:mission-work-dlq").expect("DLQ ARN");
    AwsSqsQueueScope::new(
        account,
        region,
        QueueIdentity::new(queue_name, Some(queue_url), Some(queue_arn)).expect("queue"),
        Some(
            QueueIdentity::new(
                dead_letter_name,
                Some(dead_letter_url),
                Some(dead_letter_arn),
            )
            .expect("DLQ"),
        ),
        ConsumerDeployment::new(
            hartevo_aws_sqs_queue_result_plugin::DeploymentId::new("consumer-deployment")
                .expect("deployment"),
            Revision::new(7).expect("deployment revision"),
        )
        .expect("consumer deployment"),
        MissionIdentity::new(
            MissionId::new("mission-636").expect("mission"),
            Revision::new(3).expect("mission revision"),
        )
        .expect("mission"),
        ProjectIdentity::new(
            ProjectId::new("project-636").expect("project"),
            Revision::new(4).expect("project revision"),
        )
        .expect("project"),
        WorkProductIdentity::new(
            WorkProductId::new("work-product-636").expect("work product"),
            Revision::new(5).expect("work product revision"),
        )
        .expect("work product"),
    )
    .expect("scope")
}

fn fixture_service() -> hartevo_aws_sqs_queue_result_plugin::AwsSqsQueueService<FixtureTransport> {
    let scope = scope();
    let observed_at = at(1_700_000_000);
    let provider =
        AwsSqsProvider::new(FixtureTransport::for_scope(&scope, observed_at)).expect("provider");
    let secret = SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret");
    let permissions = PermissionSnapshot::for_layer_one(1).expect("permissions");
    AwsSqsQueueService::new(scope, secret, permissions, provider, observed_at).expect("service")
}

#[test]
fn contract_and_capability_allowlist_are_layer_one_and_read_only() {
    AwsSqsQueueContract::baseline().expect("contract");
    let service = fixture_service();
    let capabilities = service.describe_capabilities();
    assert_eq!(
        capabilities.allowlisted_api_operations,
        [
            "ListQueues",
            "GetQueueUrl",
            "GetQueueAttributes",
            "ListDeadLetterSourceQueues"
        ]
    );
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(capabilities.recording_only);
    assert!(!capabilities.live_execution);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.external_writes);
    assert!(!capabilities.raw_queue_attributes);
    assert!(!capabilities.message_bodies);
    assert!(!capabilities.message_attributes);
    assert!(!capabilities.approximate_count_delivery_proof);
    assert!(!capabilities.kernel_authority);
    assert!(!capabilities.outcome_authority);
    assert!(
        QueueName::new("mission-work.fifo")
            .expect("FIFO queue name")
            .is_fifo()
    );
    let operations = capabilities.operations.join(" ").to_ascii_lowercase();
    for forbidden in ["send", "receive", "delete", "purge", "create", "set"] {
        assert!(
            !operations.contains(forbidden),
            "forbidden operation surfaced: {forbidden}"
        );
    }
}

#[test]
fn secret_cursor_and_requests_never_serialize_raw_material() {
    let scope = scope();
    let secret =
        SecretReference::for_scope("raw-sigv4-handle-must-not-escape", &scope).expect("secret");
    assert_eq!(
        serde_json::to_string(&secret).expect("secret JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{secret:?}").contains("raw-sigv4-handle"));

    let filter = QueueListFilter::for_scope(&scope, 10).expect("filter");
    let cursor = Cursor::new("raw-provider-next-token", &scope, &filter, 2).expect("cursor");
    assert_eq!(
        serde_json::to_string(&cursor).expect("cursor JSON"),
        r#"{"opaque":true}"#
    );
    let request = ListQueuesRequest::new(&scope, filter, 2, Some(cursor)).expect("request");
    let encoded = serde_json::to_string(&request).expect("request JSON");
    assert!(!encoded.contains("raw-provider-next-token"));
    assert!(encoded.contains("requestDigest"));
    assert!(!request.path_and_query().contains("raw-provider-next-token"));
    assert!(
        !serde_json::to_string(&scope)
            .expect("scope JSON")
            .contains("sqs.us-east-1.amazonaws.com")
    );
}

#[test]
fn fixture_read_projects_queue_and_dlq_posture_without_native_claims() {
    let observed_at = at(1_700_000_000);
    let mut service = fixture_service();
    let request = service.default_request(observed_at).expect("read request");
    let evidence = service.read_bounded(request.clone()).expect("evidence");
    assert_eq!(evidence.state, QueueEvidenceState::Healthy);
    assert!(evidence.list_complete);
    assert_eq!(evidence.list_pages, 1);
    assert!(evidence.counts_fresh);
    assert_eq!(evidence.counts_age_seconds, Some(0));
    assert!(evidence.approximate_counts.as_ref().is_some_and(|counts| {
        counts.is_approximate() && !counts.delivery_proof && counts.eventually_consistent
    }));
    assert!(
        evidence
            .redrive
            .as_ref()
            .is_some_and(hartevo_aws_sqs_queue_result_plugin::RedrivePosture::is_configured)
    );
    assert_eq!(evidence.dead_letter_source_queues.len(), 1);
    assert_eq!(evidence.validate_integrity(), Ok(()));
    assert!(!evidence.can_be_adopted());
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    assert!(!evidence.provider_receipt);
    assert!(!evidence.approximate_counts_are_delivery_proof);

    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, QueueEvidenceState::Healthy);
    assert!(service.verify(&proposal).valid);
    assert!(service.verify(&proposal).review_eligible);
    assert!(!proposal.can_be_adopted());
    let first = service
        .record(&proposal, "queue-health-record")
        .expect("record");
    let replay = service
        .record(&proposal, "queue-health-record")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);

    let mut consumer = service.consumer().expect("Mission consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(result.review_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.outcome_adopted);
    assert!(!result.work_product_adopted);
    let consumer_record = consumer
        .record(&proposal, "mission-record")
        .expect("record");
    assert!(consumer_record.validate_integrity().is_ok());
}

#[test]
fn blocked_environment_fails_closed_and_stays_non_native() {
    let scope = scope();
    let observed_at = at(1_700_000_000);
    let provider = AwsSqsProvider::new(BlockedEnvTransport).expect("provider");
    let secret = SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret");
    let permissions = PermissionSnapshot::for_layer_one(1).expect("permissions");
    let mut service = AwsSqsQueueService::new(scope, secret, permissions, provider, observed_at)
        .expect("service");
    let proposal = service
        .propose(service.default_request(observed_at).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, QueueEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal
            .evidence
            .failure
            .as_ref()
            .map(|failure| failure.classification),
        Some(QueueFailureClass::BlockedEnv)
    );
    assert!(!service.verify(&proposal).valid);
    assert!(
        service
            .verify(&proposal)
            .failures
            .contains(&VerificationFailure::ProviderUnknown)
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
}

#[test]
fn registration_is_digest_bound_and_reversible_until_reversed() {
    let observed_at = at(1_700_000_000);
    let mut service = fixture_service();
    let initial = service.registration().registration_digest().clone();
    assert!(service.registration().validate().is_ok());
    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(
        revoked.new_status,
        hartevo_aws_sqs_queue_result_plugin::RegistrationStatus::Revoked
    );
    assert_ne!(service.registration().registration_digest(), &initial);
    assert!(!service.is_active());
    assert!(service.restore_registration().is_ok());
    assert!(service.is_active());
    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(
        reversed.new_status,
        hartevo_aws_sqs_queue_result_plugin::RegistrationStatus::Reversed
    );
    assert!(!service.is_active());
    assert!(
        service
            .propose(service.default_request(observed_at).expect("request"))
            .is_err()
    );
    assert!(matches!(
        service.restore_registration(),
        Err(hartevo_aws_sqs_queue_result_plugin::AwsSqsQueueError::RegistrationReversed)
    ));
}

#[test]
fn stale_approximate_counts_are_not_review_eligible() {
    let scope = scope();
    let observed_at = at(1_700_000_000);
    let request = ListQueuesRequest::new(
        &scope,
        QueueListFilter::for_scope(&scope, 100).expect("filter"),
        1,
        None,
    )
    .expect("list request");
    let queue_url = scope.queue().url().expect("queue URL").clone();
    let list = ListQueuesResponse::new(
        &request,
        vec![
            hartevo_aws_sqs_queue_result_plugin::QueueSummary::new(queue_url.clone())
                .expect("summary"),
        ],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let get_url_request = GetQueueUrlRequest::for_scope(&scope).expect("URL request");
    let get_url = GetQueueUrlResponse::new(
        &get_url_request,
        queue_url.clone(),
        512,
        TransportProvenance::Recording,
    )
    .expect("URL response");
    let attributes_request =
        GetQueueAttributesRequest::new(&scope, queue_url).expect("attrs request");
    let counts =
        ApproximateQueueCounts::new(4, 2, 1, observed_at - Duration::seconds(301)).expect("counts");
    let attrs = QueueAttributesInput::new(
        scope.queue().clone(),
        QueueKind::Standard,
        counts,
        observed_at - Duration::hours(1),
        observed_at,
    )
    .expect("attrs");
    let attributes = GetQueueAttributesResponse::new(
        &attributes_request,
        attrs,
        512,
        TransportProvenance::Recording,
    )
    .expect("attrs response");
    let mut transport = RecordingTransport::default();
    transport.push_list_queues_response(Ok(list));
    transport.push_get_queue_url_response(Ok(get_url));
    transport.push_get_queue_attributes_response(Ok(attributes));
    let provider = AwsSqsProvider::new(transport).expect("provider");
    let secret = SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret");
    let permissions = PermissionSnapshot::for_layer_one(1).expect("permissions");
    let mut service = AwsSqsQueueService::new(scope, secret, permissions, provider, observed_at)
        .expect("service");
    let proposal = service
        .propose(service.default_request(observed_at).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, QueueEvidenceState::Stale);
    assert!(!proposal.counts_fresh);
    assert!(!service.verify(&proposal).review_eligible);
    assert!(
        service
            .verify(&proposal)
            .failures
            .contains(&VerificationFailure::StaleObservation)
    );
}

#[test]
fn queue_replacement_is_fail_closed_when_listing_returns_same_name_elsewhere() {
    let scope = scope();
    let observed_at = at(1_700_000_000);
    let filter = QueueListFilter::for_scope(&scope, 100).expect("filter");
    let request = ListQueuesRequest::new(&scope, filter, 1, None).expect("list request");
    let replacement_url =
        QueueUrl::new("https://sqs.us-east-1.amazonaws.com/999999999999/mission-work")
            .expect("replacement URL");
    let response = ListQueuesResponse::new(
        &request,
        vec![
            hartevo_aws_sqs_queue_result_plugin::QueueSummary::new(replacement_url)
                .expect("replacement summary"),
        ],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let mut transport = RecordingTransport::default();
    transport.push_list_queues_response(Ok(response));
    let provider = AwsSqsProvider::new(transport).expect("provider");
    let secret = SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret");
    let permissions = PermissionSnapshot::for_layer_one(1).expect("permissions");
    let mut service = AwsSqsQueueService::new(scope, secret, permissions, provider, observed_at)
        .expect("service");
    let proposal = service
        .propose(service.default_request(observed_at).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, QueueEvidenceState::QueueReplaced);
    assert_eq!(
        proposal
            .failure
            .as_ref()
            .map(|failure| failure.classification),
        Some(QueueFailureClass::QueueReplaced)
    );
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn redrive_attribute_drift_is_not_review_eligible() {
    let scope = scope();
    let observed_at = at(1_700_000_000);
    let queue_url = scope.queue().url().expect("queue URL").clone();
    let list_request = ListQueuesRequest::new(
        &scope,
        QueueListFilter::for_scope(&scope, 100).expect("filter"),
        1,
        None,
    )
    .expect("list request");
    let list = ListQueuesResponse::new(
        &list_request,
        vec![
            hartevo_aws_sqs_queue_result_plugin::QueueSummary::new(queue_url.clone())
                .expect("summary"),
        ],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response");
    let get_url_request = GetQueueUrlRequest::for_scope(&scope).expect("URL request");
    let get_url = GetQueueUrlResponse::new(
        &get_url_request,
        queue_url.clone(),
        512,
        TransportProvenance::Recording,
    )
    .expect("URL response");
    let attributes_request =
        GetQueueAttributesRequest::new(&scope, queue_url).expect("attributes request");
    let counts = ApproximateQueueCounts::new(1, 0, 0, observed_at).expect("counts");
    let wrong_dlq =
        QueueArn::new("arn:aws:sqs:us-east-1:123456789012:other-dlq").expect("wrong DLQ");
    let attributes_input = QueueAttributesInput::new(
        scope.queue().clone(),
        QueueKind::Standard,
        counts,
        observed_at - Duration::hours(1),
        observed_at,
    )
    .expect("attributes")
    .with_redrive(RedrivePolicyInput::new(wrong_dlq, 5).expect("redrive"));
    let attributes = GetQueueAttributesResponse::new(
        &attributes_request,
        attributes_input,
        512,
        TransportProvenance::Recording,
    )
    .expect("attributes response");
    let mut transport = RecordingTransport::default();
    transport.push_list_queues_response(Ok(list));
    transport.push_get_queue_url_response(Ok(get_url));
    transport.push_get_queue_attributes_response(Ok(attributes));
    let provider = AwsSqsProvider::new(transport).expect("provider");
    let secret = SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret");
    let permissions = PermissionSnapshot::for_layer_one(1).expect("permissions");
    let mut service = AwsSqsQueueService::new(scope, secret, permissions, provider, observed_at)
        .expect("service");
    let proposal = service
        .propose(service.default_request(observed_at).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, QueueEvidenceState::AttributeDrift);
    assert_eq!(
        proposal
            .failure
            .as_ref()
            .map(|failure| failure.classification),
        Some(QueueFailureClass::AttributeDrift)
    );
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn pagination_cursor_reuse_is_bounded_and_not_review_eligible() {
    let scope = scope();
    let observed_at = at(1_700_000_000);
    let filter = QueueListFilter::for_scope(&scope, 100).expect("filter");
    let first_request =
        ListQueuesRequest::new(&scope, filter.clone(), 1, None).expect("first list request");
    let first_cursor = Cursor::new("looping-cursor", &scope, &filter, 2).expect("cursor");
    let first = ListQueuesResponse::new(
        &first_request,
        vec![
            hartevo_aws_sqs_queue_result_plugin::QueueSummary::for_scope(&scope).expect("summary"),
        ],
        Some(first_cursor.clone()),
        512,
        TransportProvenance::Recording,
    )
    .expect("first response");
    let second_request =
        ListQueuesRequest::new(&scope, filter.clone(), 2, Some(first_cursor)).expect("second");
    let repeated_cursor = Cursor::new("looping-cursor", &scope, &filter, 3).expect("cursor");
    let second = ListQueuesResponse::new(
        &second_request,
        Vec::new(),
        Some(repeated_cursor),
        512,
        TransportProvenance::Recording,
    )
    .expect("second response");
    let mut transport = RecordingTransport::default();
    transport.push_list_queues_response(Ok(first));
    transport.push_list_queues_response(Ok(second));
    let provider = AwsSqsProvider::new(transport).expect("provider");
    let secret = SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret");
    let permissions = PermissionSnapshot::for_layer_one(1).expect("permissions");
    let mut service = AwsSqsQueueService::new(scope, secret, permissions, provider, observed_at)
        .expect("service");
    let proposal = service
        .propose(service.default_request(observed_at).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, QueueEvidenceState::PaginationLoop);
    assert_eq!(
        proposal
            .failure
            .as_ref()
            .map(|failure| failure.classification),
        Some(QueueFailureClass::PaginationLoop)
    );
    assert_eq!(proposal.list_pages, 2);
    assert!(!proposal.list_complete);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn listed_transport_failures_fail_closed_with_status_evidence() {
    let cases = [
        (AwsSqsQueueTransportError::BadRequest, 400),
        (AwsSqsQueueTransportError::Unauthorized, 401),
        (AwsSqsQueueTransportError::Forbidden, 403),
        (AwsSqsQueueTransportError::NotFound, 404),
        (
            AwsSqsQueueTransportError::RateLimited {
                retry_after_seconds: Some(9),
            },
            429,
        ),
        (AwsSqsQueueTransportError::Timeout, 0),
    ];
    for (error, status_code) in cases {
        let scope = scope();
        let observed_at = at(1_700_000_000);
        let mut transport = RecordingTransport::default();
        transport.push_list_queues_response(Err(error));
        let provider = AwsSqsProvider::new(transport).expect("provider");
        let secret = SecretReference::for_scope("opaque-sigv4-handle", &scope).expect("secret");
        let permissions = PermissionSnapshot::for_layer_one(1).expect("permissions");
        let mut service =
            AwsSqsQueueService::new(scope, secret, permissions, provider, observed_at)
                .expect("service");
        let proposal = service
            .propose(service.default_request(observed_at).expect("request"))
            .expect("proposal");
        let failure = proposal.failure.as_ref().expect("failure");
        assert_eq!(
            failure.status_code,
            (status_code != 0).then_some(status_code)
        );
        assert!(!proposal.connected);
        assert!(!proposal.native);
        assert!(!service.verify(&proposal).review_eligible);
    }
}
