use chrono::{DateTime, Utc};
use hartevo_aws_cloudformation_drift_result_plugin::{
    AwsAccountId, AwsCloudFormationDriftContract, AwsCloudFormationDriftError,
    AwsCloudFormationDriftScope, AwsCloudFormationDriftService, AwsCloudFormationProvider,
    AwsCloudFormationTransportError, BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_SCHEMA,
    CONTRACT_VERSION, CloudFormationEvidenceState, CloudFormationStackStatus, ConsentScope,
    DescribeStackDriftDetectionStatusRequest, DescribeStackDriftDetectionStatusResponse,
    DescribeStackEventsRequest, DescribeStackEventsResponse, DescribeStackResourceDriftsRequest,
    DescribeStackResourceDriftsResponse, DescribeStacksRequest, DescribeStacksResponse,
    DetectStackDriftRequest, DetectStackDriftResponse, DriftDetectionStatus, FixtureTransport,
    LAYER1_PERMISSIONS, LogicalResourceId, MissionIdentity, OpaqueCursor, PermissionSnapshot,
    ProjectIdentity, ProviderProvenance, QueuedTransport, RecordedRequestKind, RecordingTransport,
    ResourceDrift, ResourceDriftFilter, ResourceDriftStatus, SecretReference,
    StackDriftDetectionId, StackDriftStatus, StackEvent, StackName, StackSummary,
    TransportProvenance, WorkProductIdentity,
};

fn at(day: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-08-{day:02}T00:00:00Z"))
        .expect("fixture timestamp")
        .with_timezone(&Utc)
}

fn scope() -> AwsCloudFormationDriftScope {
    AwsCloudFormationDriftScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_cloudformation_drift_result_plugin::AwsRegion::new("us-east-1")
            .expect("region"),
        StackName::new("fixture-stack").expect("stack"),
        7,
        MissionIdentity::new("mission-594", 4).expect("mission"),
        ProjectIdentity::new("project-594", 3).expect("project"),
        WorkProductIdentity::new("work-product-594", 2).expect("work product"),
    )
    .expect("scope")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-594", 1, at(20)).expect("consent")
}

fn secret(scope: &AwsCloudFormationDriftScope) -> SecretReference {
    SecretReference::sigv4("keyring://opaque-cloudformation-594", scope, 1).expect("secret")
}

fn service_with<T>(
    scope: &AwsCloudFormationDriftScope,
    transport: T,
) -> AwsCloudFormationDriftService<T>
where
    T: hartevo_aws_cloudformation_drift_result_plugin::AwsCloudFormationTransport,
{
    AwsCloudFormationDriftService::new(
        scope.clone(),
        secret(scope),
        consent(),
        AwsCloudFormationProvider::new(transport).expect("provider"),
        at(1),
    )
    .expect("service")
}

fn enqueue_standard(
    transport: &mut RecordingTransport,
    scope: &AwsCloudFormationDriftScope,
    stack_drift_status: StackDriftStatus,
    detection_statuses: &[DriftDetectionStatus],
    resource_status: ResourceDriftStatus,
) {
    let stacks_request = DescribeStacksRequest::new(scope, 100, 4, None).expect("stacks request");
    let summary = StackSummary::new(
        scope,
        CloudFormationStackStatus::UpdateComplete,
        at(1),
        Some(at(2)),
        None,
        Some(stack_drift_status),
        Some(at(2)),
        Some("provider reason is digest-only"),
    )
    .expect("summary");
    transport.push_describe_stacks_response(Ok(DescribeStacksResponse::new(
        &stacks_request,
        vec![summary],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("stacks response")));

    let events_request =
        DescribeStackEventsRequest::new(scope, 100, 4, None).expect("events request");
    let event = StackEvent::new(
        scope,
        "event-594",
        "FixtureResource",
        "AWS::S3::Bucket",
        CloudFormationStackStatus::UpdateComplete,
        at(2),
        Some("raw reason must not survive"),
    )
    .expect("event");
    transport.push_describe_stack_events_response(Ok(DescribeStackEventsResponse::new(
        &events_request,
        vec![event],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("events response")));

    let detect_request = DetectStackDriftRequest::new(scope, Vec::<LogicalResourceId>::new())
        .expect("detect request");
    let detection_id = StackDriftDetectionId::new("detection-594").expect("detection id");
    transport.push_detect_stack_drift_response(Ok(DetectStackDriftResponse::new(
        &detect_request,
        detection_id.clone(),
        256,
        TransportProvenance::Recording,
    )
    .expect("detect response")));

    let status_request =
        DescribeStackDriftDetectionStatusRequest::new(scope, detection_id).expect("status request");
    for status in detection_statuses {
        transport.push_detection_status_response(Ok(
            DescribeStackDriftDetectionStatusResponse::new(
                &status_request,
                *status,
                Some("async status reason is digest-only"),
                (status == &DriftDetectionStatus::DetectionComplete).then_some(1),
                (*status == DriftDetectionStatus::DetectionComplete).then_some(stack_drift_status),
                at(3),
                384,
                TransportProvenance::Recording,
            )
            .expect("status response"),
        ));
    }

    if detection_statuses
        .last()
        .is_some_and(|status| *status == DriftDetectionStatus::DetectionComplete)
    {
        let resource_request = DescribeStackResourceDriftsRequest::new(
            scope,
            ResourceDriftFilter::all(),
            100,
            4,
            None,
        )
        .expect("resource request");
        let resource = ResourceDrift::new(
            scope,
            "FixtureResource",
            Some("physical-id-must-be-digested"),
            "AWS::S3::Bucket",
            resource_status,
            at(3),
            u16::from(resource_status == ResourceDriftStatus::Modified),
            (resource_status == ResourceDriftStatus::Modified).then(|| {
                hartevo_aws_cloudformation_drift_result_plugin::Digest::from_text("raw-properties")
            }),
        )
        .expect("resource drift");
        transport.push_resource_drift_response(Ok(DescribeStackResourceDriftsResponse::new(
            &resource_request,
            vec![resource],
            None,
            512,
            TransportProvenance::Recording,
        )
        .expect("resource response")));
    }
}

#[test]
fn contract_scope_registration_and_capabilities_are_layer_one() {
    let contract = AwsCloudFormationDriftContract::baseline().expect("contract");
    assert_eq!(contract.value()["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(contract.value()["contractVersion"], CONTRACT_VERSION);
    assert_eq!(contract.value()["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(LAYER1_PERMISSIONS.len(), 6);

    let scope = scope();
    let service = service_with(&scope, FixtureTransport::for_scope(&scope, at(3)));
    let capabilities = service.describe_capabilities();
    assert_eq!(capabilities.operations.len(), 5);
    assert!(capabilities.read_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.outcome_adoption);
    assert_eq!(
        service.registration().status(),
        hartevo_aws_cloudformation_drift_result_plugin::RegistrationStatus::Active
    );
}

#[test]
fn fixture_complete_evidence_is_async_aware_redacted_and_non_native() {
    let scope = scope();
    let mut service = service_with(&scope, FixtureTransport::for_scope(&scope, at(3)));
    let proposal = service
        .propose(service.default_request(at(3)).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, CloudFormationEvidenceState::Completed);
    assert_eq!(
        proposal.observed_drift_status,
        Some(StackDriftStatus::InSync)
    );
    assert_eq!(proposal.evidence.polls_observed, 1);
    assert!(proposal.evidence.complete);
    assert_eq!(proposal.evidence.resource_drifts.len(), 1);
    assert!(!proposal.drift_claim);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.can_be_adopted());

    let encoded = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for forbidden in [
        "fixture-physical-id",
        "FixtureResource",
        "raw reason must not survive",
        "raw-properties",
        "keyring://opaque-cloudformation-594",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "raw value leaked in JSON: {forbidden}"
        );
        assert!(
            !debug.contains(forbidden),
            "raw value leaked in Debug: {forbidden}"
        );
    }
    assert!(encoded.contains("physicalResourceIdDigest"));
    assert!(encoded.contains("statusReasonDigest"));
}

#[test]
fn modified_resource_is_observed_without_a_remediation_claim() {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    enqueue_standard(
        &mut transport,
        &scope,
        StackDriftStatus::Drifted,
        &[DriftDetectionStatus::DetectionComplete],
        ResourceDriftStatus::Modified,
    );
    let mut service = service_with(&scope, transport);
    let proposal = service
        .propose(service.default_request(at(3)).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, CloudFormationEvidenceState::Completed);
    assert_eq!(
        proposal.observed_drift_status,
        Some(StackDriftStatus::Drifted)
    );
    assert!(proposal.drift_claim);
    assert!(!proposal.evidence.remediation_available);
    assert!(!proposal.outcome_adopted);
    assert_eq!(
        proposal.evidence.resource_drifts[0].status,
        ResourceDriftStatus::Modified
    );
}

#[test]
fn in_progress_detection_stays_non_adoptable_and_bounded() {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    enqueue_standard(
        &mut transport,
        &scope,
        StackDriftStatus::Unknown,
        &[
            DriftDetectionStatus::DetectionInProgress,
            DriftDetectionStatus::DetectionInProgress,
            DriftDetectionStatus::DetectionInProgress,
            DriftDetectionStatus::DetectionInProgress,
        ],
        ResourceDriftStatus::Unknown,
    );
    let mut service = service_with(&scope, transport);
    let proposal = service
        .propose(service.default_request(at(3)).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, CloudFormationEvidenceState::InProgress);
    assert_eq!(proposal.evidence.polls_observed, 4);
    assert!(!proposal.evidence.complete);
    assert!(proposal.state.is_non_adoptable());
    assert!(
        service
            .provider()
            .transport()
            .requests()
            .iter()
            .all(|request| {
                request.operation != RecordedRequestKind::DescribeStackResourceDrifts
            })
    );
}

#[test]
fn blocked_env_fixture_and_loopback_never_claim_connected_or_native() {
    let scope = scope();
    let mut blocked = service_with(&scope, BlockedEnvTransport);
    let blocked_proposal = blocked
        .propose(blocked.default_request(at(3)).expect("request"))
        .expect("blocked proposal");
    assert_eq!(
        blocked_proposal.state,
        CloudFormationEvidenceState::ProviderUnknown
    );
    assert_eq!(blocked_proposal.provenance, ProviderProvenance::BlockedEnv);
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);

    let mut loopback = service_with(&scope, QueuedTransport::loopback_for_scope(&scope, at(3)));
    let loopback_proposal = loopback
        .propose(loopback.default_request(at(3)).expect("request"))
        .expect("loopback proposal");
    assert_eq!(loopback_proposal.provenance, TransportProvenance::Loopback);
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);
}

#[test]
fn transport_errors_map_to_explicit_non_adoptable_states() {
    let cases = [
        (
            AwsCloudFormationTransportError::Unauthorized,
            CloudFormationEvidenceState::AccessLoss,
        ),
        (
            AwsCloudFormationTransportError::Forbidden,
            CloudFormationEvidenceState::AccessLoss,
        ),
        (
            AwsCloudFormationTransportError::NotFound,
            CloudFormationEvidenceState::NotFound,
        ),
        (
            AwsCloudFormationTransportError::RateLimited {
                retry_after_seconds: Some(4),
            },
            CloudFormationEvidenceState::Throttled,
        ),
        (
            AwsCloudFormationTransportError::Timeout,
            CloudFormationEvidenceState::ProviderUnknown,
        ),
    ];
    for (error, expected) in cases {
        let scope = scope();
        let mut transport = RecordingTransport::default();
        for _ in 0..=2 {
            transport.push_describe_stacks_response(Err(error.clone()));
        }
        let mut service = service_with(&scope, transport);
        let proposal = service
            .propose(service.default_request(at(3)).expect("request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert!(proposal.evidence.provider_errors.len() <= 3);
        assert!(proposal.state.is_non_adoptable());
        assert!(!proposal.connected);
        assert!(!proposal.native);
    }
}

#[test]
fn cursor_scope_revision_and_tamper_fences_fail_closed() {
    let scope = scope();
    let query = DescribeStacksRequest::new(&scope, 100, 4, None).expect("request");
    let cursor = OpaqueCursor::new("opaque-provider-token").expect("cursor");
    let bound = cursor.bind(&query.query_digest(), 2);
    let wrong_query = hartevo_aws_cloudformation_drift_result_plugin::AwsRegion::new("us-west-2")
        .expect("region");
    let other_scope = AwsCloudFormationDriftScope::new(
        scope.account().clone(),
        wrong_query,
        scope.stack().clone(),
        scope.stack_revision(),
        scope.mission().clone(),
        scope.project().clone(),
        scope.work_product().clone(),
    )
    .expect("other scope");
    assert!(DescribeStacksRequest::new(&other_scope, 100, 4, Some(bound.clone())).is_err());
    assert!(
        !serde_json::to_string(&bound)
            .expect("cursor JSON")
            .contains("opaque-provider-token")
    );

    let mut summary = StackSummary::new(
        &scope,
        CloudFormationStackStatus::UpdateComplete,
        at(1),
        None,
        None,
        Some(StackDriftStatus::InSync),
        None,
        None,
    )
    .expect("summary");
    summary.stack_revision = 99;
    assert!(summary.validate_against(&scope).is_err());

    let mut transport = RecordingTransport::default();
    let stacks_request = DescribeStacksRequest::new(&scope, 100, 4, None).expect("request");
    let mut mismatched_summary = StackSummary::new(
        &scope,
        CloudFormationStackStatus::UpdateComplete,
        at(1),
        None,
        None,
        Some(StackDriftStatus::InSync),
        None,
        None,
    )
    .expect("summary");
    mismatched_summary.stack_digest =
        hartevo_aws_cloudformation_drift_result_plugin::Digest::from_text("wrong-stack");
    mismatched_summary.summary_digest = mismatched_summary.recomputed_digest();
    assert!(
        DescribeStacksResponse::new(
            &stacks_request,
            vec![mismatched_summary],
            None,
            512,
            TransportProvenance::Recording,
        )
        .is_err()
    );
    let clean_summary = StackSummary::new(
        &scope,
        CloudFormationStackStatus::UpdateComplete,
        at(1),
        None,
        None,
        Some(StackDriftStatus::InSync),
        None,
        None,
    )
    .expect("summary");
    transport.push_describe_stacks_response(Ok(DescribeStacksResponse::new(
        &stacks_request,
        vec![clean_summary],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(
        hartevo_aws_cloudformation_drift_result_plugin::Digest::from_text("tampered"),
    )));
    let mut service = service_with(&scope, transport);
    let proposal = service
        .propose(service.default_request(at(3)).expect("request"))
        .expect("tampered proposal");
    assert_eq!(proposal.state, CloudFormationEvidenceState::ProviderUnknown);
    assert!(!proposal.evidence.complete);
}

#[test]
fn registration_reversal_revocation_and_recording_are_reversible_but_bounded() {
    let scope = scope();
    let mut service = service_with(&scope, FixtureTransport::for_scope(&scope, at(3)));
    let proposal = service
        .propose(service.default_request(at(3)).expect("request"))
        .expect("proposal");
    let first = service
        .record(&proposal, "recording-key-594")
        .expect("record");
    let replay = service
        .record(&proposal, "recording-key-594")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(service.recording_count(), 1);

    let mut tampered = proposal.clone();
    tampered.native = true;
    assert!(service.verify(&tampered).failures.contains(
        &hartevo_aws_cloudformation_drift_result_plugin::VerificationFailure::TamperedEvidence
    ));
    let mut aggregate_tampered = proposal.clone();
    aggregate_tampered.evidence.evidence.evidence_digest =
        hartevo_aws_cloudformation_drift_result_plugin::Digest::from_text("tampered-aggregate");
    assert!(service.verify(&aggregate_tampered).failures.contains(
        &hartevo_aws_cloudformation_drift_result_plugin::VerificationFailure::TamperedEvidence
    ));

    service.revoke().expect("revoke");
    assert!(!service.registration().is_active());
    assert!(service.default_request(at(3)).is_ok());
    assert!(
        service
            .propose(service.default_request(at(3)).expect("request"))
            .is_err()
    );
    assert!(service.verify(&proposal).failures.contains(
        &hartevo_aws_cloudformation_drift_result_plugin::VerificationFailure::RegistrationInactive
    ));
    service.restore_registration().expect("restore");
    service.reverse().expect("reverse");
    assert!(service.restore_registration().is_err());
    assert!(matches!(
        service.record(&proposal, "new-key"),
        Err(AwsCloudFormationDriftError::RegistrationInactive
            | AwsCloudFormationDriftError::InvalidRegistration,)
    ));
}

#[test]
fn pagination_replay_and_page_budget_are_partial() {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    let first_request = DescribeStacksRequest::new(&scope, 100, 4, None).expect("request");
    let summary = StackSummary::new(
        &scope,
        CloudFormationStackStatus::UpdateComplete,
        at(1),
        None,
        None,
        Some(StackDriftStatus::InSync),
        None,
        None,
    )
    .expect("summary");
    let cursor = OpaqueCursor::new("same-token").expect("cursor");
    let cursor = cursor.bind(&first_request.query_digest(), 2);
    transport.push_describe_stacks_response(Ok(DescribeStacksResponse::new(
        &first_request,
        vec![summary.clone()],
        Some(cursor.clone()),
        512,
        TransportProvenance::Recording,
    )
    .expect("first page")));
    let second_request =
        DescribeStacksRequest::new(&scope, 100, 4, Some(cursor.clone())).expect("second request");
    let replay_cursor = cursor.bind(&second_request.query_digest(), 3);
    transport.push_describe_stacks_response(Ok(DescribeStacksResponse::new(
        &second_request,
        vec![summary],
        Some(replay_cursor),
        512,
        TransportProvenance::Recording,
    )
    .expect("second page")));
    let mut service = service_with(&scope, transport);
    let request = service
        .request(
            Vec::<LogicalResourceId>::new(),
            ResourceDriftFilter::all(),
            100,
            4,
            1,
            0,
            at(3),
        )
        .expect("bounded request");
    let proposal = service.propose(request).expect("partial proposal");
    assert_eq!(proposal.state, CloudFormationEvidenceState::Partial);
    assert!(proposal.evidence.truncated);
    assert!(
        proposal
            .evidence
            .provider_errors
            .iter()
            .any(|error| error.category == "cursor_replay" || error.category == "invalid_response")
    );
}

#[test]
fn permission_and_secret_boundaries_are_explicit() {
    let scope = scope();
    assert!(PermissionSnapshot::new(1, ["cloudformation:UpdateStack"]).is_err());
    let secret = secret(&scope);
    let encoded_registration = serde_json::to_string(
        &service_with(&scope, FixtureTransport::for_scope(&scope, at(3))).registration(),
    )
    .expect("registration JSON");
    assert!(encoded_registration.contains("secretReferenceDigest"));
    assert!(!encoded_registration.contains("keyring://opaque-cloudformation-594"));
    assert!(!format!("{secret:?}").contains("keyring://opaque-cloudformation-594"));
    assert_eq!(secret.scope_digest(), &scope.digest());
    assert_eq!(
        secret.kind(),
        hartevo_aws_cloudformation_drift_result_plugin::SecretKind::Sigv4Credential
    );
}
