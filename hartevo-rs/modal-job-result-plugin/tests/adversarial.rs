use hartevo_modal_job_result_plugin::{
    AppDeploymentKind, AppIdentity, FailureCode, FunctionCallProjection, JobStatus,
    ModalJobResultError, ModalJobResultRecordingLog, ModalJobResultService, ModalProviderError,
    ModalScope, ModalTransportError, PermissionSnapshot, ProviderCallResponse, ProviderIdentity,
    RegistrationId, ResultEvidence, RetryPolicy, SecretReference, TransportProvenance,
    UsageEvidence,
};
use hartevo_modal_job_result_plugin::{InputIdentity, RecordingTransport};

fn registration(scope: &ModalScope) -> hartevo_modal_job_result_plugin::ModalRegistration {
    hartevo_modal_job_result_plugin::ModalRegistration::new(
        RegistrationId::new("registration-1", 1).expect("registration"),
        scope.clone(),
        SecretReference::modal_api_token("opaque-modal-handle", 1).expect("secret reference"),
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "recording-fixture").expect("provider"),
        1,
    )
    .expect("registration")
}

fn service_with_transport(
    scope: &ModalScope,
    transport: RecordingTransport,
) -> ModalJobResultService<RecordingTransport> {
    ModalJobResultService::new(registration(scope), transport).expect("service")
}

fn response(
    scope: &ModalScope,
    status: JobStatus,
    observed_at: u64,
    poll_count: u8,
) -> ProviderCallResponse {
    ProviderCallResponse::for_scope(
        scope,
        status,
        observed_at,
        poll_count,
        UsageEvidence::for_input(&scope.input, poll_count).expect("usage"),
    )
    .expect("response")
}

fn lookup_and_spawn(
    service: &mut ModalJobResultService<RecordingTransport>,
) -> FunctionCallProjection {
    let handle = service.lookup_function().expect("lookup");
    service.spawn_function_call(&handle).expect("spawn")
}

#[test]
fn deployed_lookup_succeeds_and_ephemeral_lookup_is_refused() {
    let deployed_scope = ModalScope::for_fixture();
    let deployed_transport =
        RecordingTransport::for_scope(&deployed_scope, TransportProvenance::Recording)
            .expect("transport");
    let mut deployed_service = service_with_transport(&deployed_scope, deployed_transport);
    let handle = deployed_service.lookup_function().expect("deployed lookup");
    assert_eq!(handle.app.deployment_kind, AppDeploymentKind::Deployed);
    assert!(!handle.connected);
    assert!(!handle.native);
    assert!(!handle.first_party);

    let mut ephemeral_scope = deployed_scope.clone();
    ephemeral_scope.app = AppIdentity::new("app-1", "serve-1", 8, AppDeploymentKind::Ephemeral)
        .expect("ephemeral app");
    let ephemeral_transport =
        RecordingTransport::for_scope(&ephemeral_scope, TransportProvenance::Recording)
            .expect("transport");
    let mut ephemeral_service = service_with_transport(&ephemeral_scope, ephemeral_transport);
    assert_eq!(
        ephemeral_service.lookup_function(),
        Err(ModalJobResultError::Provider(
            ModalProviderError::EphemeralAppLookup
        ))
    );
}

#[test]
fn all_intermediate_and_terminal_statuses_are_projected() {
    for status in [
        JobStatus::Queued,
        JobStatus::Running,
        JobStatus::Succeeded,
        JobStatus::Failed,
        JobStatus::Canceled,
        JobStatus::Expired,
        JobStatus::ProviderUnknown,
    ] {
        let scope = ModalScope::for_fixture();
        let transport = RecordingTransport::for_scope(&scope, TransportProvenance::Fake)
            .expect("transport")
            .with_spawn_response(Ok(response(&scope, status, 10, 0)));
        let mut service = service_with_transport(&scope, transport);
        let projection = lookup_and_spawn(&mut service);
        assert_eq!(projection.status, status);
        assert!(projection.matches_scope(&scope));
        assert!(!projection.connected);
        assert!(!projection.native);
        assert!(!projection.first_party);
        assert_eq!(projection.is_terminal(), status.is_terminal());
    }
}

#[test]
fn bounded_observation_records_retry_usage_expiry_and_backoff() {
    let scope = ModalScope::for_fixture();
    let mut transport =
        RecordingTransport::for_scope(&scope, TransportProvenance::Loopback).expect("transport");
    transport.push_poll_response(Ok(response(&scope, JobStatus::Running, 20, 1)));
    transport.push_poll_response(Ok(response(&scope, JobStatus::Succeeded, 30, 2)));
    let mut service = service_with_transport(&scope, transport);

    let projection = service.observe_bounded().expect("bounded observation");
    assert_eq!(projection.status, JobStatus::Succeeded);
    assert_eq!(projection.poll_count, 2);
    assert_eq!(projection.next_poll_delay_millis, 0);
    let result = projection.result.as_ref().expect("success metadata");
    assert!(result.result_digest.is_some());
    assert!(result.expires_at_epoch_seconds.is_some());
    assert_eq!(result.usage.poll_count, 2);
    assert!(scope.retry.poll_delay_millis(0) <= scope.retry.poll_backoff_max_millis);
    assert!(scope.retry.poll_delay_millis(1) >= scope.retry.poll_delay_millis(0));
    assert!(scope.retry.poll_delay_millis(99) <= scope.retry.poll_backoff_max_millis);

    let poll_requests = service
        .provider()
        .transport()
        .requests()
        .iter()
        .filter_map(|request| match request.kind {
            hartevo_modal_job_result_plugin::RecordedRequestKind::Poll {
                poll_index,
                backoff_millis,
            } => Some((poll_index, backoff_millis)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(poll_requests, vec![(1, 250), (2, 500)]);
}

#[test]
fn poll_exhaustion_becomes_provider_unknown_without_unbounded_work() {
    let mut scope = ModalScope::for_fixture();
    scope.retry = RetryPolicy::new(99, 2, 1000, 2, 10, 20).expect("small retry bound");
    let mut transport =
        RecordingTransport::for_scope(&scope, TransportProvenance::Recording).expect("transport");
    transport.push_poll_response(Ok(response(&scope, JobStatus::Running, 20, 1)));
    transport.push_poll_response(Ok(response(&scope, JobStatus::Running, 30, 2)));
    let mut service = service_with_transport(&scope, transport);

    let projection = service
        .observe_bounded()
        .expect("provider unknown projection");
    assert_eq!(projection.status, JobStatus::ProviderUnknown);
    assert_eq!(projection.failure_code, Some(FailureCode::ProviderUnknown));
    assert_eq!(projection.poll_count, 2);
    assert!(projection.is_non_adoptable());
    let poll_count = service
        .provider()
        .transport()
        .requests()
        .iter()
        .filter(|request| {
            matches!(
                request.kind,
                hartevo_modal_job_result_plugin::RecordedRequestKind::Poll { .. }
            )
        })
        .count();
    assert_eq!(poll_count, 2);
}

#[test]
fn timeout_and_server_failures_are_classified_and_bounded_observer_is_unknown() {
    let scope = ModalScope::for_fixture();
    let mut timeout_transport =
        RecordingTransport::for_scope(&scope, TransportProvenance::Recording).expect("transport");
    timeout_transport.push_poll_response(Err(ModalTransportError::Timeout));
    let mut timeout_service = service_with_transport(&scope, timeout_transport);
    let timeout_initial = lookup_and_spawn(&mut timeout_service);
    let timeout_handle = timeout_service.lookup_function().expect("handle");
    assert_eq!(
        timeout_service.poll_function_call(&timeout_handle, &timeout_initial),
        Err(ModalJobResultError::Provider(ModalProviderError::Timeout))
    );

    let scope = ModalScope::for_fixture();
    let mut server_transport =
        RecordingTransport::for_scope(&scope, TransportProvenance::Recording).expect("transport");
    server_transport.push_poll_response(Err(ModalTransportError::Http(
        hartevo_modal_job_result_plugin::ModalHttpStatus::new(503).expect("status"),
    )));
    let mut server_service = service_with_transport(&scope, server_transport);
    let server_projection = server_service.observe_bounded().expect("unknown result");
    assert_eq!(server_projection.status, JobStatus::ProviderUnknown);
    assert_eq!(
        server_projection.failure_code,
        Some(FailureCode::ServerError)
    );
}

#[test]
fn http_statuses_and_access_loss_are_safe_classifications() {
    for (status, expected) in [
        (401, ModalProviderError::Unauthorized),
        (403, ModalProviderError::Forbidden),
        (404, ModalProviderError::NotFound),
        (409, ModalProviderError::Conflict),
        (429, ModalProviderError::RateLimited),
        (500, ModalProviderError::ServerError { status: 500 }),
        (599, ModalProviderError::ServerError { status: 599 }),
    ] {
        let scope = ModalScope::for_fixture();
        let transport = RecordingTransport::for_scope(&scope, TransportProvenance::Recording)
            .expect("transport")
            .with_lookup_response(Err(ModalTransportError::Http(
                hartevo_modal_job_result_plugin::ModalHttpStatus::new(status).expect("status"),
            )));
        let mut service = service_with_transport(&scope, transport);
        assert_eq!(
            service.lookup_function(),
            Err(ModalJobResultError::Provider(expected))
        );
    }

    let scope = ModalScope::for_fixture();
    let transport = RecordingTransport::for_scope(&scope, TransportProvenance::BlockedEnv)
        .expect("transport")
        .with_lookup_response(Err(ModalTransportError::AccessLost));
    let mut service = service_with_transport(&scope, transport);
    assert_eq!(
        service.lookup_function(),
        Err(ModalJobResultError::Provider(
            ModalProviderError::AccessLost
        ))
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn size_serialization_redaction_truncation_and_tamper_are_explicit() {
    assert_eq!(
        InputIdentity::from_bounded_bytes(
            "too-large",
            1,
            &vec![
                0_u8;
                usize::try_from(hartevo_modal_job_result_plugin::MAX_SERIALIZED_INPUT_BYTES)
                    .expect("test bound")
                    + 1
            ],
        ),
        Err(ModalJobResultError::SerializationLimit)
    );
    assert_eq!(
        ResultEvidence::from_bounded_bytes(
            &vec![
                0_u8;
                usize::try_from(hartevo_modal_job_result_plugin::MAX_CAPTURED_RESULT_BYTES)
                    .expect("test bound")
                    + 1
            ],
            100,
            UsageEvidence::new(1, 0, None, 0, 0).expect("usage"),
        ),
        Err(ModalJobResultError::ResultTooLarge)
    );
    assert_eq!(
        ResultEvidence::metadata(
            Some(hartevo_modal_job_result_plugin::Digest::from_text("result")),
            10,
            Some(10),
            true,
            None,
            Some(10),
            None,
            None,
            Some(100),
            false,
            false,
            UsageEvidence::new(1, 10, None, 0, 0).expect("usage"),
        ),
        Err(ModalJobResultError::SerializationLimit)
    );

    let scope = ModalScope::for_fixture();
    let usage = UsageEvidence::new(20, 20, Some(10), 2, 1).expect("usage");
    let redacted = ResultEvidence::redacted(usage).expect("redacted evidence");
    let transport = RecordingTransport::for_scope(&scope, TransportProvenance::Recording)
        .expect("transport")
        .with_spawn_response(Ok(
            response(&scope, JobStatus::Succeeded, 10, 0).with_result(redacted)
        ));
    let mut service = service_with_transport(&scope, transport);
    let projection = lookup_and_spawn(&mut service);
    assert_eq!(
        projection.completeness,
        hartevo_modal_job_result_plugin::ProjectionCompleteness::Partial
    );
    assert!(projection.is_non_adoptable());
    let proposal = service
        .compile_job_result_proposal(&projection, "redacted-key")
        .expect("proposal");
    assert_eq!(
        proposal.disposition,
        hartevo_modal_job_result_plugin::ProposalDisposition::RedactedEvidence
    );

    let truncated = ResultEvidence::metadata(
        Some(hartevo_modal_job_result_plugin::Digest::from_text(
            "truncated",
        )),
        64,
        Some(1000),
        true,
        Some(hartevo_modal_job_result_plugin::Digest::from_text(
            "truncated",
        )),
        Some(64),
        None,
        None,
        Some(100),
        true,
        false,
        UsageEvidence::new(20, 64, None, 0, 0).expect("usage"),
    )
    .expect("truncated evidence");
    assert!(truncated.is_non_adoptable());

    let expired = ResultEvidence::metadata(
        Some(hartevo_modal_job_result_plugin::Digest::from_text(
            "expired",
        )),
        8,
        Some(8),
        true,
        Some(hartevo_modal_job_result_plugin::Digest::from_text(
            "expired",
        )),
        Some(8),
        None,
        None,
        Some(10),
        false,
        false,
        UsageEvidence::new(20, 8, None, 0, 0).expect("usage"),
    )
    .expect("expired metadata");
    let expired_transport = RecordingTransport::for_scope(&scope, TransportProvenance::Recording)
        .expect("transport")
        .with_spawn_response(Ok(
            response(&scope, JobStatus::Succeeded, 10, 0).with_result(expired)
        ));
    let mut expired_service = service_with_transport(&scope, expired_transport);
    let expired_projection = lookup_and_spawn(&mut expired_service);
    assert_eq!(expired_projection.status, JobStatus::Expired);
    let expired_proposal = expired_service
        .compile_job_result_proposal(&expired_projection, "expired-key")
        .expect("expired proposal");
    assert_eq!(
        expired_proposal.disposition,
        hartevo_modal_job_result_plugin::ProposalDisposition::Expired
    );

    let mut tampered = projection;
    tampered.status = JobStatus::Failed;
    assert_eq!(
        tampered.validate_integrity(),
        Err(ModalJobResultError::TamperedEvidence)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn every_provider_scope_dimension_is_fenced() {
    let scope = ModalScope::for_fixture();
    let identity_cases = [(
        "host",
        scope.host.clone(),
        scope.host.clone(),
        hartevo_modal_job_result_plugin::ModalJobResultError::HostDrift,
    )];
    assert_eq!(identity_cases.len(), 1);

    let mut host = scope.host.clone();
    host.revision += 1;
    assert_eq!(
        scope.matches_provider_identities(
            &host,
            &scope.workspace,
            &scope.app,
            &scope.function,
            &scope.environment,
            &scope.call,
            &scope.input,
            &scope.retry,
        ),
        Err(ModalJobResultError::HostDrift)
    );
    let mut workspace = scope.workspace.clone();
    workspace.revision += 1;
    assert_eq!(
        scope.matches_provider_identities(
            &scope.host,
            &workspace,
            &scope.app,
            &scope.function,
            &scope.environment,
            &scope.call,
            &scope.input,
            &scope.retry,
        ),
        Err(ModalJobResultError::WorkspaceDrift)
    );
    let mut app = scope.app.clone();
    app.revision += 1;
    assert_eq!(
        scope.matches_provider_identities(
            &scope.host,
            &scope.workspace,
            &app,
            &scope.function,
            &scope.environment,
            &scope.call,
            &scope.input,
            &scope.retry,
        ),
        Err(ModalJobResultError::AppDrift)
    );
    let mut function = scope.function.clone();
    function.revision += 1;
    assert_eq!(
        scope.matches_provider_identities(
            &scope.host,
            &scope.workspace,
            &scope.app,
            &function,
            &scope.environment,
            &scope.call,
            &scope.input,
            &scope.retry,
        ),
        Err(ModalJobResultError::FunctionDrift)
    );
    let mut environment = scope.environment.clone();
    environment.revision += 1;
    assert_eq!(
        scope.matches_provider_identities(
            &scope.host,
            &scope.workspace,
            &scope.app,
            &scope.function,
            &environment,
            &scope.call,
            &scope.input,
            &scope.retry,
        ),
        Err(ModalJobResultError::EnvironmentDrift)
    );
    let mut call = scope.call.clone();
    call.revision += 1;
    assert_eq!(
        scope.matches_provider_identities(
            &scope.host,
            &scope.workspace,
            &scope.app,
            &scope.function,
            &scope.environment,
            &call,
            &scope.input,
            &scope.retry,
        ),
        Err(ModalJobResultError::CallDrift)
    );
    let mut input = scope.input.clone();
    input.revision += 1;
    assert_eq!(
        scope.matches_provider_identities(
            &scope.host,
            &scope.workspace,
            &scope.app,
            &scope.function,
            &scope.environment,
            &scope.call,
            &input,
            &scope.retry,
        ),
        Err(ModalJobResultError::InputDrift)
    );
    let mut retry = scope.retry.clone();
    retry.revision += 1;
    assert_eq!(
        scope.matches_provider_identities(
            &scope.host,
            &scope.workspace,
            &scope.app,
            &scope.function,
            &scope.environment,
            &scope.call,
            &scope.input,
            &retry,
        ),
        Err(ModalJobResultError::RetryDrift)
    );
}

#[test]
fn proposal_and_recording_are_mission_fenced_and_idempotent() {
    let scope = ModalScope::for_fixture();
    let transport = RecordingTransport::for_scope(&scope, TransportProvenance::Recording)
        .expect("transport")
        .with_spawn_response(Ok(response(&scope, JobStatus::Succeeded, 10, 0)));
    let mut service = service_with_transport(&scope, transport);
    let projection = lookup_and_spawn(&mut service);
    let proposal = service
        .compile_job_result_proposal(&projection, "same-key")
        .expect("proposal");
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.outcome_adopted);
    assert_eq!(proposal.mission_revision, scope.mission.revision);
    assert_eq!(proposal.project_revision, scope.project.revision);
    assert_eq!(proposal.work_product_revision, scope.work_product.revision);
    proposal.validate_integrity().expect("proposal integrity");

    let mut log = ModalJobResultRecordingLog::default();
    let first = service
        .record_job_result(&proposal, "same-key", &mut log)
        .expect("first record");
    let replay = service
        .record_job_result(&proposal, "same-key", &mut log)
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);
    replay.validate_integrity().expect("recording integrity");

    let mut project_drift = proposal.clone();
    project_drift.project_revision += 1;
    assert_eq!(
        service.record_job_result(&project_drift, "same-key", &mut log),
        Err(ModalJobResultError::TamperedEvidence)
    );
    let mut work_product_drift = proposal.clone();
    work_product_drift.work_product_revision += 1;
    assert_eq!(
        service.record_job_result(&work_product_drift, "same-key", &mut log),
        Err(ModalJobResultError::TamperedEvidence)
    );

    let queued_projection = {
        let queued = ModalScope::for_fixture();
        let transport = RecordingTransport::for_scope(&queued, TransportProvenance::Recording)
            .expect("transport")
            .with_spawn_response(Ok(response(&queued, JobStatus::Queued, 10, 0)));
        let mut queued_service = service_with_transport(&queued, transport);
        lookup_and_spawn(&mut queued_service)
    };
    let conflicting = hartevo_modal_job_result_plugin::MissionModalJobConsumer::new(scope.clone())
        .compile_proposal(&queued_projection, "same-key")
        .expect("conflicting proposal");
    assert_eq!(
        service.record_job_result(&conflicting, "same-key", &mut log),
        Err(ModalJobResultError::ReplayConflict)
    );

    let duplicate_handle = service.lookup_function().expect("lookup after spawn");
    assert_eq!(
        service.spawn_function_call(&duplicate_handle),
        Err(ModalJobResultError::Provider(
            ModalProviderError::DuplicateSpawn
        ))
    );
}

#[test]
fn stale_mission_revision_and_revocation_fail_closed() {
    let scope = ModalScope::for_fixture();
    let transport = RecordingTransport::for_scope(&scope, TransportProvenance::Recording)
        .expect("transport")
        .with_spawn_response(Ok(response(&scope, JobStatus::Succeeded, 10, 0)));
    let mut service = service_with_transport(&scope, transport);
    let projection = lookup_and_spawn(&mut service);
    assert_eq!(
        service.compile_job_result_proposal_at_revision(
            &projection,
            "stale-key",
            scope.mission.revision + 1,
        ),
        Err(ModalJobResultError::StaleMissionRevision)
    );

    service.registration_mut().secret_reference_mut().revoke();
    assert_eq!(
        service.lookup_function(),
        Err(ModalJobResultError::SecretRevoked)
    );

    let scope = ModalScope::for_fixture();
    let transport =
        RecordingTransport::for_scope(&scope, TransportProvenance::Recording).expect("transport");
    let mut service = service_with_transport(&scope, transport);
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.lookup_function(),
        Err(ModalJobResultError::RegistrationRevoked)
    );
    service.restore_registration().expect("restore");
    service.reverse_registration().expect("reverse");
    assert_eq!(
        service.lookup_function(),
        Err(ModalJobResultError::RegistrationReversed)
    );
}

#[test]
fn secret_reference_is_opaque_and_all_fixture_provenance_claims_are_false() {
    let scope = ModalScope::for_fixture();
    let registration_value = registration(&scope);
    let serialized = serde_json::to_string(&registration_value).expect("safe registration");
    assert!(!serialized.contains("opaque-modal-handle"));
    assert!(format!("{registration_value:?}").contains("reference_digest"));
    assert!(!format!("{registration_value:?}").contains("opaque-modal-handle"));

    let capability = ModalJobResultService::new(
        registration_value,
        RecordingTransport::for_scope(&scope, TransportProvenance::Recording).expect("transport"),
    )
    .expect("service")
    .describe_capabilities();
    assert!(capability.read_only);
    assert!(!capability.connected);
    assert!(!capability.native);
    assert!(!capability.first_party);
    assert!(!capability.provider_receipt);
    assert!(!capability.outcome_adoption);

    let description = ModalJobResultService::new(
        registration(&scope),
        RecordingTransport::for_scope(&scope, TransportProvenance::Recording).expect("transport"),
    )
    .expect("service")
    .describe_scope();
    assert_eq!(description.scope_digest, scope.digest());
    assert_eq!(description.app.revision, scope.app.revision);
    assert_eq!(description.app.deployment_id, scope.app.deployment_id);
    assert_eq!(description.function.revision, scope.function.revision);
    assert_eq!(description.environment.revision, scope.environment.revision);
    assert_eq!(description.call.revision, scope.call.revision);
    assert_eq!(description.input.revision, scope.input.revision);
    assert_eq!(description.retry.revision, scope.retry.revision);
    assert_eq!(description.mission.revision, scope.mission.revision);
    assert_eq!(description.project.revision, scope.project.revision);
    assert_eq!(
        description.work_product.revision,
        scope.work_product.revision
    );
    assert_eq!(description.permissions.len(), 7);
    assert!(!description.connected);
    assert!(!description.native);
    assert!(!description.first_party);
}
