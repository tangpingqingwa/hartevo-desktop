use chrono::{Duration, TimeZone, Utc};
use proptest::prelude::*;

use hartevo_aws_emr_serverless_job_result_plugin::{
    ApplicationRecord, ApplicationState, AwsAccountId, AwsEmrServerlessJobResultScope,
    AwsEmrServerlessJobResultService, AwsEmrServerlessProvider, AwsEmrServerlessScopeInput,
    AwsEmrServerlessTransportError, BlockedEnvTransport, Digest, FixtureTransport,
    GetApplicationResponse, GetJobRunResponse, JobRunMode, JobRunRecord, JobRunRecordInput,
    JobRunState, JobRunSummary, ListJobRunsRequest, ListJobRunsResponse, LoopbackTransport,
    MAX_PAGE_SIZE, MissionAwsEmrServerlessConsumer, MissionId, MissionResultDisposition,
    MissionScope, OpaqueNextToken, ProjectId, ProjectScope, RecordingTransport, ReleaseLabel,
    ResourceMetadata, Revision, SecretReference, StateDetails, TransportProvenance, WorkProductId,
    WorkProductScope,
};

type Service = AwsEmrServerlessJobResultService<RecordingTransport>;

#[derive(Clone)]
struct Fixture {
    scope: AwsEmrServerlessJobResultScope,
    application: ApplicationRecord,
    job_run: JobRunRecord,
    now: chrono::DateTime<Utc>,
}

fn time(second: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_725_000_000 + second, 0)
        .single()
        .expect("fixture timestamp")
}

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn fixture_with_state(state: JobRunState) -> Fixture {
    let now = time(100);
    let project = ProjectScope::new(
        ProjectId::new("project-1").expect("project"),
        Revision::new(2).expect("project revision"),
    );
    let mission = MissionScope::new(
        MissionId::new("mission-1").expect("mission"),
        Revision::new(7).expect("mission revision"),
        now + Duration::hours(2),
    );
    let work_product = WorkProductScope::new(
        WorkProductId::new("work-product-1").expect("work product"),
        Revision::new(11).expect("work product revision"),
    );
    let input = AwsEmrServerlessScopeInput::new(
        AwsAccountId::new("123456789012").expect("account"),
        hartevo_aws_emr_serverless_job_result_plugin::AwsRegion::new("us-east-1").expect("region"),
        hartevo_aws_emr_serverless_job_result_plugin::ApplicationId::new("app123")
            .expect("application"),
        hartevo_aws_emr_serverless_job_result_plugin::JobRunId::new("run123").expect("job run"),
        1,
        digest("execution-role-digest"),
        ReleaseLabel::new("emr-7.0.0").expect("release"),
        digest("job-driver-digest"),
        project,
        mission,
        work_product,
    )
    .expect("scope input");
    let secret = SecretReference::new(
        "sigv4-reference-that-must-not-print",
        &input.base_digest(),
        Revision::new(3).expect("credential revision"),
    )
    .expect("secret reference");
    let scope = AwsEmrServerlessJobResultScope::new(input, secret).expect("scope");
    let application = ApplicationRecord::new(
        scope.application_id().clone(),
        ApplicationState::Started,
        scope.release_label().clone(),
        time(0),
        time(10),
    )
    .expect("application");
    let job_run = JobRunRecord::new(JobRunRecordInput {
        application_id: scope.application_id().clone(),
        job_run_id: scope.job_run_id().clone(),
        attempt: scope.attempt(),
        state,
        mode: JobRunMode::Batch,
        release_label: scope.release_label().clone(),
        execution_role_digest: scope.execution_role_digest().clone(),
        job_driver_digest: scope.job_driver_digest().clone(),
        created_at: time(20),
        attempt_created_at: time(21),
        attempt_updated_at: time(70),
        started_at: Some(time(30)),
        ended_at: matches!(state, JobRunState::Success | JobRunState::Failed).then(|| time(90)),
        updated_at: time(70),
        queued_duration_millis: 4_000,
        total_execution_duration_seconds: Some(40),
        state_details: Some(StateDetails::new("provider state details").expect("state details")),
        resources: ResourceMetadata::new(3, 1_500, 4_000, 900, Some(12_345)).expect("resource"),
    })
    .expect("job run");
    Fixture {
        scope,
        application,
        job_run,
        now,
    }
}

fn fixture() -> Fixture {
    fixture_with_state(JobRunState::Success)
}

fn push_standard_responses(transport: &mut RecordingTransport, fixture: &Fixture) {
    let credential_revision = fixture.scope.secret_reference().credential_revision();
    transport.push_application_response(Ok(GetApplicationResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        fixture.application.clone(),
    )));
    transport.push_job_run_response(Ok(GetJobRunResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        fixture.job_run.clone(),
    )));
    transport.push_list_response(Ok(ListJobRunsResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        vec![JobRunSummary::from_record(&fixture.job_run)],
        None,
    )
    .expect("list response")));
}

fn service_with_standard_fixture(fixture: &Fixture) -> Service {
    let mut transport = RecordingTransport::default();
    push_standard_responses(&mut transport, fixture);
    let provider =
        AwsEmrServerlessProvider::new(transport, "offline-recording-1").expect("provider");
    AwsEmrServerlessJobResultService::register("registration-1", fixture.scope.clone(), provider, 1)
        .expect("service")
}

#[test]
fn complete_read_is_typed_bounded_and_review_only() {
    let fixture = fixture();
    let mut service = service_with_standard_fixture(&fixture);
    let proposal = service.propose_at(fixture.now).expect("proposal");

    assert_eq!(proposal.status(), JobRunState::Success);
    assert!(proposal.is_complete());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.truth_authority);
    assert!(!proposal.consent_authority);
    assert!(!proposal.effect_authority);
    assert!(!proposal.verification_authority);
    assert!(!proposal.outcome_authority);
    assert!(!proposal.work_product_adopted);
    assert_eq!(proposal.provenance, TransportProvenance::Recording);
    let evidence = proposal.evidence.as_ref().expect("evidence");
    assert_eq!(evidence.attempt, 1);
    assert_eq!(evidence.status, JobRunState::Success);
    assert!(evidence.state_details_digest.is_some());
    assert_eq!(evidence.resource.worker_count, 3);
    assert!(!format!("{:?}", fixture.scope).contains("sigv4-reference-that-must-not-print"));
    assert!(
        !format!("{:?}", fixture.scope.secret_reference())
            .contains("sigv4-reference-that-must-not-print")
    );
    assert!(!format!("{:?}", fixture.job_run).contains("provider state details"));
    assert!(!format!("{proposal:?}").contains("provider state details"));
    proposal.validate_integrity().expect("proposal integrity");

    let registration = service.registration().clone();
    let consumer = MissionAwsEmrServerlessConsumer::new(fixture.scope.clone(), &registration)
        .expect("consumer");
    let result = consumer.consume(proposal).expect("Mission result");
    assert_eq!(result.status, JobRunState::Success);
    assert_eq!(result.disposition, MissionResultDisposition::EvidenceReady);
    assert!(!result.can_be_adopted());
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    result
        .validate_integrity()
        .expect("Mission result integrity");
}

#[test]
fn exact_scope_and_secret_reference_are_digest_bound() {
    let fixture = fixture();
    let input = AwsEmrServerlessScopeInput::new(
        fixture.scope.account_id().clone(),
        fixture.scope.region().clone(),
        fixture.scope.application_id().clone(),
        fixture.scope.job_run_id().clone(),
        fixture.scope.attempt(),
        fixture.scope.execution_role_digest().clone(),
        fixture.scope.release_label().clone(),
        fixture.scope.job_driver_digest().clone(),
        fixture.scope.project().clone(),
        fixture.scope.mission().clone(),
        fixture.scope.work_product().clone(),
    )
    .expect("same input");
    assert_eq!(input.base_digest(), fixture.scope.base_digest());
    let wrong_secret = SecretReference::new(
        "another-reference",
        &input.base_digest(),
        Revision::new(3).expect("revision"),
    )
    .expect("secret");
    let changed_scope = AwsEmrServerlessJobResultScope::new(input, wrong_secret).expect("scope");
    assert_ne!(changed_scope.scope_digest(), fixture.scope.scope_digest());
    assert_ne!(
        changed_scope.secret_reference().reference_digest(),
        fixture.scope.secret_reference().reference_digest()
    );
    assert!(
        SecretReference::new(
            "invalid reference with whitespace",
            fixture.scope.scope_digest(),
            Revision::new(1).expect("revision"),
        )
        .is_err()
    );
    let list_binding = ListJobRunsRequest::binding_digest_for(
        fixture.scope.scope_digest(),
        fixture.scope.application_id(),
        MAX_PAGE_SIZE,
    );
    let token = OpaqueNextToken::new("next-1", &list_binding).expect("token");
    assert!(ListJobRunsRequest::new(&fixture.scope, MAX_PAGE_SIZE, Some(token)).is_ok());
    let wrong_binding = OpaqueNextToken::new("next-2", &digest("wrong-binding"))
        .expect("opaque token can be created before request binding");
    assert!(ListJobRunsRequest::new(&fixture.scope, MAX_PAGE_SIZE, Some(wrong_binding)).is_err());
}

#[test]
fn registration_is_reversible_and_revocation_is_fail_closed() {
    let fixture = fixture();
    let mut service = service_with_standard_fixture(&fixture);
    let active_digest = service.registration().registration_digest().clone();
    let transition = service.revoke().expect("revoke");
    assert_eq!(transition.previous_status.as_str(), "active");
    assert_eq!(service.registration().status().as_str(), "revoked");
    assert_ne!(service.registration().registration_digest(), &active_digest);
    let revoked = service.propose_at(fixture.now).expect("revoked proposal");
    assert_eq!(revoked.status(), JobRunState::Revoked);
    assert!(service.revoke().is_err());
    service.restore().expect("restore");
    let active_again = service.propose_at(fixture.now).expect("active proposal");
    assert_eq!(active_again.status(), JobRunState::Success);
    service.reverse().expect("reverse");
    assert_eq!(
        service
            .propose_at(fixture.now)
            .expect("reversed proposal")
            .status(),
        JobRunState::Revoked
    );
    assert!(service.restore().is_err());
}

#[test]
fn pagination_is_opaque_bounded_and_exact_attempt_scoped() {
    let fixture = fixture();
    let mut transport = RecordingTransport::default();
    let credential_revision = fixture.scope.secret_reference().credential_revision();
    transport.push_application_response(Ok(GetApplicationResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        fixture.application.clone(),
    )));
    transport.push_job_run_response(Ok(GetJobRunResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        fixture.job_run.clone(),
    )));
    let binding = ListJobRunsRequest::binding_digest_for(
        fixture.scope.scope_digest(),
        fixture.scope.application_id(),
        MAX_PAGE_SIZE,
    );
    let token = OpaqueNextToken::new("page-2", &binding).expect("page token");
    let other_job = JobRunRecord::new(JobRunRecordInput {
        application_id: fixture.scope.application_id().clone(),
        job_run_id: hartevo_aws_emr_serverless_job_result_plugin::JobRunId::new("other123")
            .expect("other job"),
        attempt: 1,
        state: JobRunState::Running,
        mode: JobRunMode::Streaming,
        release_label: fixture.scope.release_label().clone(),
        execution_role_digest: fixture.scope.execution_role_digest().clone(),
        job_driver_digest: fixture.scope.job_driver_digest().clone(),
        created_at: time(22),
        attempt_created_at: time(23),
        attempt_updated_at: time(24),
        started_at: Some(time(24)),
        ended_at: None,
        updated_at: time(24),
        queued_duration_millis: 1,
        total_execution_duration_seconds: None,
        state_details: None,
        resources: ResourceMetadata::new(1, 1, 1, 1, None).expect("resource"),
    })
    .expect("other job record");
    transport.push_list_response(Ok(ListJobRunsResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        vec![JobRunSummary::from_record(&other_job)],
        Some(token),
    )
    .expect("page one")));
    transport.push_list_response(Ok(ListJobRunsResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        vec![JobRunSummary::from_record(&fixture.job_run)],
        None,
    )
    .expect("page two")));
    let provider =
        AwsEmrServerlessProvider::new(transport, "offline-recording-1").expect("provider");
    let mut service = AwsEmrServerlessJobResultService::register(
        "registration-pagination",
        fixture.scope.clone(),
        provider,
        1,
    )
    .expect("service");
    let proposal = service.propose_at(fixture.now).expect("proposal");
    assert_eq!(proposal.status(), JobRunState::Success);
}

#[test]
fn page_cap_and_repeated_token_fail_closed() {
    let fixture = fixture();
    let credential_revision = fixture.scope.secret_reference().credential_revision();
    let binding = ListJobRunsRequest::binding_digest_for(
        fixture.scope.scope_digest(),
        fixture.scope.application_id(),
        MAX_PAGE_SIZE,
    );
    let mut transport = RecordingTransport::default();
    transport.push_application_response(Ok(GetApplicationResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        fixture.application.clone(),
    )));
    transport.push_job_run_response(Ok(GetJobRunResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        fixture.job_run.clone(),
    )));
    for index in 0..4 {
        let token = OpaqueNextToken::new(format!("page-{index}"), &binding).expect("token");
        transport.push_list_response(Ok(ListJobRunsResponse::new(
            fixture.scope.scope_digest().clone(),
            credential_revision,
            Vec::new(),
            Some(token),
        )
        .expect("page")));
    }
    let provider =
        AwsEmrServerlessProvider::new(transport, "offline-recording-1").expect("provider");
    let mut service = AwsEmrServerlessJobResultService::register(
        "registration-page-cap",
        fixture.scope.clone(),
        provider,
        1,
    )
    .expect("service");
    let proposal = service.propose_at(fixture.now).expect("proposal");
    assert_eq!(proposal.status(), JobRunState::Partial);
    assert_eq!(
        proposal.partial_reason,
        Some(hartevo_aws_emr_serverless_job_result_plugin::PartialReason::MissingExactJobRun)
    );

    let mut loop_transport = RecordingTransport::default();
    loop_transport.push_application_response(Ok(GetApplicationResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        fixture.application.clone(),
    )));
    loop_transport.push_job_run_response(Ok(GetJobRunResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        fixture.job_run.clone(),
    )));
    let repeated = OpaqueNextToken::new("repeated", &binding).expect("repeated token");
    loop_transport.push_list_response(Ok(ListJobRunsResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        Vec::new(),
        Some(repeated.clone()),
    )
    .expect("first page")));
    loop_transport.push_list_response(Ok(ListJobRunsResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        Vec::new(),
        Some(repeated),
    )
    .expect("second page")));
    let provider =
        AwsEmrServerlessProvider::new(loop_transport, "offline-recording-1").expect("provider");
    let mut service =
        AwsEmrServerlessJobResultService::register("registration-loop", fixture.scope, provider, 1)
            .expect("service");
    assert_eq!(
        service.propose_at(fixture.now).expect("proposal").status(),
        JobRunState::Tampered
    );
}

#[test]
fn lifecycle_regression_and_scope_drift_are_tampered() {
    let first = fixture_with_state(JobRunState::Running);
    let second = fixture_with_state(JobRunState::Pending);
    let credential_revision = first.scope.secret_reference().credential_revision();
    let mut transport = RecordingTransport::default();
    for value in [
        (&first.application, &first.job_run),
        (&second.application, &second.job_run),
    ] {
        transport.push_application_response(Ok(GetApplicationResponse::new(
            first.scope.scope_digest().clone(),
            credential_revision,
            value.0.clone(),
        )));
        transport.push_job_run_response(Ok(GetJobRunResponse::new(
            first.scope.scope_digest().clone(),
            credential_revision,
            value.1.clone(),
        )));
        transport.push_list_response(Ok(ListJobRunsResponse::new(
            first.scope.scope_digest().clone(),
            credential_revision,
            vec![JobRunSummary::from_record(value.1)],
            None,
        )
        .expect("list")));
    }
    let provider =
        AwsEmrServerlessProvider::new(transport, "offline-recording-1").expect("provider");
    let mut service = AwsEmrServerlessJobResultService::register(
        "registration-regression",
        first.scope.clone(),
        provider,
        1,
    )
    .expect("service");
    assert_eq!(
        service.propose_at(first.now).expect("first").status(),
        JobRunState::Running
    );
    assert_eq!(
        service.propose_at(first.now).expect("regression").status(),
        JobRunState::Tampered
    );

    let mut drift_transport = RecordingTransport::default();
    let wrong_scope_digest = digest("wrong-scope");
    drift_transport.push_application_response(Ok(GetApplicationResponse::new(
        wrong_scope_digest,
        credential_revision,
        first.application,
    )));
    let provider =
        AwsEmrServerlessProvider::new(drift_transport, "offline-recording-1").expect("provider");
    let mut drift_service = AwsEmrServerlessJobResultService::register(
        "registration-scope-drift",
        first.scope,
        provider,
        1,
    )
    .expect("service");
    assert_eq!(
        drift_service.propose_at(time(100)).expect("drift").status(),
        JobRunState::Tampered
    );
}

#[test]
fn identical_recordings_replay_to_the_same_proposal_and_evidence_digests() {
    let fixture = fixture();
    let mut first_service = service_with_standard_fixture(&fixture);
    let mut replay_service = service_with_standard_fixture(&fixture);
    let first = first_service
        .propose_at(fixture.now)
        .expect("first proposal");
    let replay = replay_service
        .propose_at(fixture.now)
        .expect("replayed proposal");
    assert_eq!(first.proposal_digest, replay.proposal_digest);
    assert_eq!(first.registration_digest, replay.registration_digest);
    assert_eq!(first.evidence_digests(), replay.evidence_digests());
    assert_eq!(first.provider_errors, replay.provider_errors);
}

#[test]
fn provider_errors_map_to_explicit_fail_closed_states() {
    let fixture = fixture();
    for (error, expected) in [
        (
            AwsEmrServerlessTransportError::Unauthorized,
            JobRunState::AccessLost,
        ),
        (
            AwsEmrServerlessTransportError::Timeout,
            JobRunState::Partial,
        ),
        (
            AwsEmrServerlessTransportError::NotFound,
            JobRunState::Expired,
        ),
        (
            AwsEmrServerlessTransportError::ServerError { status: 503 },
            JobRunState::ProviderUnknown,
        ),
    ] {
        let mut transport = RecordingTransport::default();
        transport.push_application_response(Err(error));
        let provider =
            AwsEmrServerlessProvider::new(transport, "offline-recording-1").expect("provider");
        let mut service = AwsEmrServerlessJobResultService::register(
            "registration-error",
            fixture.scope.clone(),
            provider,
            1,
        )
        .expect("service");
        let proposal = service.propose_at(fixture.now).expect("proposal");
        assert_eq!(proposal.status(), expected);
        assert!(!proposal.connected);
        assert_eq!(proposal.provider_errors.len(), 1);
    }

    let provider = AwsEmrServerlessProvider::new(BlockedEnvTransport, "blocked-env")
        .expect("blocked provider");
    assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
    assert!(!provider.provenance().connected());
    assert!(!provider.provenance().native());
    assert!(!provider.provenance().first_party());
}

#[test]
fn resource_cost_and_payload_bounds_are_enforced() {
    assert!(ResourceMetadata::new(1, 1, 1, 1, Some(12_345)).is_ok());
    assert!(ResourceMetadata::new(1, 10_000_000_001, 1, 1, None).is_err());
    assert!(ResourceMetadata::new(1, 1, 1, 1, Some(10_000_000_000_001)).is_err());

    let fixture = fixture();
    let credential_revision = fixture.scope.secret_reference().credential_revision();
    let mut transport = RecordingTransport::default();
    transport.push_application_response(Ok(GetApplicationResponse::new(
        fixture.scope.scope_digest().clone(),
        credential_revision,
        fixture.application,
    )
    .with_payload_bytes(1_048_577)));
    let provider =
        AwsEmrServerlessProvider::new(transport, "offline-recording-1").expect("provider");
    let mut service = AwsEmrServerlessJobResultService::register(
        "registration-payload-cap",
        fixture.scope,
        provider,
        1,
    )
    .expect("service");
    assert_eq!(
        service.propose_at(time(100)).expect("proposal").status(),
        JobRunState::Partial
    );
}

#[test]
fn stale_mission_and_consumer_revocation_are_rejected() {
    let fixture = fixture();
    let mut service = service_with_standard_fixture(&fixture);
    let proposal = service.propose_at(fixture.now).expect("proposal");
    let registration = service.registration().clone();
    let consumer = MissionAwsEmrServerlessConsumer::new(fixture.scope.clone(), &registration)
        .expect("consumer");
    assert!(matches!(
        consumer.consume_at(proposal.clone(), Revision::new(8).expect("revision")),
        Err(hartevo_aws_emr_serverless_job_result_plugin::consumer::ConsumerError::StaleMission)
    ));
    let mut revoked_consumer = consumer;
    revoked_consumer.revoke().expect("consumer revoke");
    assert!(revoked_consumer.consume(proposal).is_err());
}

#[test]
fn all_offline_transport_provenance_is_non_native() {
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
    let _fixture_provider = AwsEmrServerlessProvider::new(FixtureTransport::default(), "fixture")
        .expect("fixture provider");
    let _loopback_provider =
        AwsEmrServerlessProvider::new(LoopbackTransport::default(), "loopback")
            .expect("loopback provider");
}

#[test]
fn lifecycle_names_are_exact_and_explicit() {
    let states = [
        JobRunState::Submitted,
        JobRunState::Pending,
        JobRunState::Scheduled,
        JobRunState::Queued,
        JobRunState::Running,
        JobRunState::Success,
        JobRunState::Failed,
        JobRunState::Cancelling,
        JobRunState::Cancelled,
        JobRunState::Partial,
        JobRunState::Expired,
        JobRunState::AccessLost,
        JobRunState::ProviderUnknown,
        JobRunState::Tampered,
        JobRunState::Revoked,
    ];
    assert_eq!(
        states
            .iter()
            .map(|state| state.as_str())
            .collect::<Vec<_>>(),
        vec![
            "SUBMITTED",
            "PENDING",
            "SCHEDULED",
            "QUEUED",
            "RUNNING",
            "SUCCESS",
            "FAILED",
            "CANCELLING",
            "CANCELLED",
            "PARTIAL",
            "EXPIRED",
            "ACCESS_LOST",
            "PROVIDER_UNKNOWN",
            "TAMPERED",
            "REVOKED",
        ]
    );
}

proptest! {
    #[test]
    fn arbitrary_next_tokens_never_escape_the_opaque_boundary(bytes in prop::collection::vec(any::<u8>(), 0..1200)) {
        let binding = Digest::from_text("list-binding");
        let value = String::from_utf8_lossy(&bytes).into_owned();
        if let Ok(token) = OpaqueNextToken::new(value, &binding) {
            prop_assert!(token.binding_digest() == &binding);
            prop_assert_eq!(token.digest().as_str().len(), 64);
            let token_debug = format!("{token:?}");
            prop_assert!(!token_debug.contains("list-binding"));
        }
    }
}
