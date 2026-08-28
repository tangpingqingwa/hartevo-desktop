use hartevo_aws_lambda_invocation_result_plugin as lambda;

use lambda::{
    AwsLambdaHttpStatus, AwsLambdaInvocationResultError, AwsLambdaInvocationResultService,
    AwsLambdaProviderError, AwsLambdaRegistration, AwsLambdaScope, AwsLambdaTransportError,
    ConfigId, Digest, FailureCode, InputId, InputIdentity, InvocationConfig, InvocationStatus,
    InvocationType, LogType, MissionAwsLambdaResultConsumer, PermissionSnapshot, ProviderIdentity,
    ProviderInvocationResponse, PublishedVersion, RecordingTransport, SecretReference,
    TransportProvenance, UsageEvidence, fixture_scope,
};

fn registration(scope: &AwsLambdaScope) -> AwsLambdaRegistration {
    AwsLambdaRegistration::new(
        lambda::RegistrationId::new("registration-391", 1).expect("registration id"),
        scope.clone(),
        SecretReference::for_scope("opaque-sigv4-reference", scope, 3).expect("secret"),
        PermissionSnapshot::for_layer_one(2),
        ProviderIdentity::new(4, "fixture-provider").expect("provider"),
        5,
    )
    .expect("registration")
}

fn recording_service(
    scope: &AwsLambdaScope,
) -> AwsLambdaInvocationResultService<RecordingTransport> {
    AwsLambdaInvocationResultService::new(
        registration(scope),
        RecordingTransport::for_scope(scope, TransportProvenance::Recording).expect("transport"),
    )
    .expect("service")
}

#[test]
fn contract_and_registration_are_exact_reversible_and_opaque() {
    let document: serde_json::Value =
        serde_json::from_str(lambda::CONTRACT_JSON).expect("contract");
    assert_eq!(document["schemaVersion"], lambda::CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], lambda::CONTRACT_VERSION);
    assert_eq!(document["layer"], 1);
    assert_eq!(document["objectiveType"], lambda::OBJECTIVE_TYPE);
    assert_eq!(document["service"]["externalWrites"], false);
    assert_eq!(document["provider"]["connectedEvidence"], false);
    assert_eq!(document["provider"]["nativeEvidence"], false);
    assert_eq!(document["provider"]["firstPartyEvidence"], false);
    assert_eq!(document["contractDigest"], lambda::contract_digest());

    let scope = fixture_scope();
    let mut registration = registration(&scope);
    let serialized = serde_json::to_string(&registration).expect("safe registration");
    let debug = format!("{registration:?}");
    assert!(!serialized.contains("opaque-sigv4-reference"));
    assert!(!debug.contains("opaque-sigv4-reference"));
    assert!(debug.contains("reference_digest"));
    assert_eq!(registration.status(), lambda::RegistrationStatus::Active);
    registration.revoke().expect("revoke");
    registration.restore().expect("restore");
    registration.reverse().expect("reverse");
    assert_eq!(
        registration.restore(),
        Err(AwsLambdaInvocationResultError::RegistrationReversed)
    );
}

#[test]
fn qualified_arns_and_unpublished_versions_are_rejected() {
    assert_eq!(
        lambda::FunctionArn::new(
            "arn:aws:lambda:us-east-1:123456789012:function:deployment-verifier:7"
        ),
        Err(AwsLambdaInvocationResultError::InvalidAwsIdentity)
    );
    assert_eq!(
        PublishedVersion::new("$LATEST"),
        Err(AwsLambdaInvocationResultError::InvalidAwsIdentity)
    );
    assert_eq!(
        PublishedVersion::new("0"),
        Err(AwsLambdaInvocationResultError::InvalidAwsIdentity)
    );
}

#[test]
fn synchronous_proposal_result_verification_and_idempotent_recording_are_fenced() {
    let scope = fixture_scope();
    let mut service = recording_service(&scope);
    let invocation = service
        .compile_invocation_proposal()
        .expect("invocation proposal");
    assert_eq!(invocation.invocation_type, InvocationType::RequestResponse);
    assert_eq!(invocation.input.input_digest, scope.input.input_digest);
    assert!(!invocation.canonical_contains_raw_payload());

    let projection = service
        .project_invocation_result(&invocation)
        .expect("projection");
    assert_eq!(projection.status, InvocationStatus::Succeeded);
    assert!(projection.output_digest.is_some());
    assert_eq!(projection.usage.input_bytes, scope.input.serialized_bytes);
    assert!(!projection.connected);
    assert!(!projection.native);
    assert!(!projection.first_party);

    let proposal = service
        .compile_execution_result_proposal(&projection, "decision-391")
        .expect("result proposal");
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.outcome_adopted);
    proposal.validate_integrity().expect("proposal integrity");
    let report = service
        .verify_execution_result(&invocation, &projection, &proposal)
        .expect("verification report");
    assert!(report.verified());

    let mut log = lambda::AwsLambdaResultRecordingLog::default();
    let first = service
        .record_execution_result(&proposal, "decision-391", &mut log)
        .expect("first record");
    let replay = service
        .record_execution_result(&proposal, "decision-391", &mut log)
        .expect("same replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);
    replay.validate_integrity().expect("recording integrity");

    let mut tampered = proposal.clone();
    tampered.output_digest = Some(Digest::from_text("different-output"));
    assert_eq!(
        tampered.validate_integrity(),
        Err(AwsLambdaInvocationResultError::TamperedEvidence)
    );
    let report = service
        .verify_execution_result(&invocation, &projection, &tampered)
        .expect("tamper report");
    assert!(!report.verified());
    assert!(
        report
            .failures()
            .contains(&lambda::VerificationFailure::OutputDigestMismatch)
    );
}

#[test]
fn request_response_and_event_payload_bounds_are_type_specific() {
    let mut scope = fixture_scope();
    let too_large_sync = vec![
        0_u8;
        usize::try_from(lambda::MAX_SYNCHRONOUS_INPUT_BYTES + 1)
            .expect("test bound fits usize")
    ];
    let input = InputIdentity::new(
        InputId::new("too-large-sync", 1).expect("input id"),
        1,
        Digest::from_bytes(&too_large_sync),
        too_large_sync.len() as u64,
    );
    assert_eq!(input, Err(AwsLambdaInvocationResultError::InvalidScope));

    let event_input = InputIdentity::new(
        InputId::new("event-input", 1).expect("event input id"),
        1,
        Digest::from_text("one-megabyte-event"),
        lambda::MAX_ASYNCHRONOUS_INPUT_BYTES,
    )
    .expect("event input");
    scope.invocation_type = InvocationType::Event;
    let event_scope = AwsLambdaScope::new(
        scope.account.clone(),
        scope.region.clone(),
        scope.function.clone(),
        InvocationType::Event,
        event_input,
        scope.config.clone(),
        scope.retry.clone(),
        scope.mission.clone(),
        scope.project.clone(),
        scope.work_product.clone(),
    )
    .expect("event scope");
    let mut service = recording_service(&event_scope);
    let proposal = service
        .compile_invocation_proposal()
        .expect("event proposal");
    let projection = service
        .project_invocation_result(&proposal)
        .expect("event accepted projection");
    assert_eq!(projection.status, InvocationStatus::Accepted);
    assert_eq!(projection.http_status.expect("status").as_u16(), 202);
    assert!(projection.output_digest.is_none());
}

#[test]
fn function_error_is_distinct_from_http_acceptance() {
    let scope = fixture_scope();
    let first = recording_service(&scope);
    let invocation = first.compile_invocation_proposal().expect("proposal");
    let response = ProviderInvocationResponse::for_proposal(
        &invocation,
        InvocationStatus::FunctionError,
        Some(FailureCode::ProviderUnknown),
        Some(AwsLambdaHttpStatus::new(200).expect("status")),
        true,
        None,
        Some(Digest::from_text("function-error")),
        UsageEvidence::for_input(&scope.input).expect("usage"),
        256,
        false,
        100,
        TransportProvenance::Recording,
    )
    .expect("function error response");
    let transport =
        RecordingTransport::new(TransportProvenance::Recording).with_invoke_response(Ok(response));
    let mut service =
        AwsLambdaInvocationResultService::new(registration(&scope), transport).expect("service");
    let invocation = service.compile_invocation_proposal().expect("proposal");
    let projection = service
        .project_invocation_result(&invocation)
        .expect("projection");
    assert_eq!(projection.status, InvocationStatus::FunctionError);
    assert_eq!(projection.http_status.expect("status").as_u16(), 200);
    assert!(projection.function_error);
    assert!(projection.error_digest.is_some());
    assert!(projection.output_digest.is_none());
}

#[test]
fn retry_and_async_success_claims_are_bounded() {
    let scope = fixture_scope();
    assert_eq!(
        UsageEvidence::new(scope.input.serialized_bytes, 0, None, 1, 1),
        Err(AwsLambdaInvocationResultError::InvalidScope)
    );

    let mut event_scope = scope.clone();
    event_scope.invocation_type = InvocationType::Event;
    let event_scope = AwsLambdaScope::new(
        event_scope.account.clone(),
        event_scope.region.clone(),
        event_scope.function.clone(),
        InvocationType::Event,
        event_scope.input.clone(),
        event_scope.config.clone(),
        event_scope.retry.clone(),
        event_scope.mission.clone(),
        event_scope.project.clone(),
        event_scope.work_product.clone(),
    )
    .expect("event scope");
    let event_registration = registration(&event_scope);
    let proposal = lambda::InvocationProposal::new(
        event_registration.id().clone(),
        event_registration.binding_digest().clone(),
        &event_scope,
        TransportProvenance::Loopback,
    )
    .expect("proposal");
    let response = ProviderInvocationResponse::for_proposal(
        &proposal,
        InvocationStatus::Succeeded,
        None,
        Some(AwsLambdaHttpStatus::new(202).expect("status")),
        false,
        Some(Digest::from_text("event-output")),
        None,
        UsageEvidence::for_input(&event_scope.input).expect("usage"),
        256,
        false,
        100,
        TransportProvenance::Loopback,
    )
    .expect("response fixture");
    let transport =
        RecordingTransport::new(TransportProvenance::Loopback).with_invoke_response(Ok(response));
    let mut service =
        AwsLambdaInvocationResultService::new(event_registration, transport).expect("service");
    assert_eq!(
        service.project_invocation_result(&proposal),
        Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration)
    );
}

#[test]
fn bounded_failure_projection_covers_throttle_timeout_http_errors_and_partial() {
    let cases = [
        (
            Err(AwsLambdaTransportError::Http(
                AwsLambdaHttpStatus::new(429).expect("429"),
            )),
            InvocationStatus::Throttled,
            Some(FailureCode::RateLimited),
        ),
        (
            Err(AwsLambdaTransportError::Timeout),
            InvocationStatus::Timeout,
            Some(FailureCode::Timeout),
        ),
        (
            Err(AwsLambdaTransportError::Http(
                AwsLambdaHttpStatus::new(500).expect("500"),
            )),
            InvocationStatus::ProviderUnknown,
            Some(FailureCode::ServerError),
        ),
        (
            Err(AwsLambdaTransportError::MalformedResponse),
            InvocationStatus::Partial,
            Some(FailureCode::MalformedResponse),
        ),
    ];
    for (error, expected_status, expected_failure) in cases {
        let scope = fixture_scope();
        let transport =
            RecordingTransport::new(TransportProvenance::Fake).with_invoke_response(error);
        let mut service = AwsLambdaInvocationResultService::new(registration(&scope), transport)
            .expect("service");
        let invocation = service.compile_invocation_proposal().expect("proposal");
        let projection = service
            .observe_bounded(&invocation)
            .expect("bounded failure");
        assert_eq!(projection.status, expected_status);
        assert_eq!(projection.failure_code, expected_failure);
        assert!(projection.is_non_adoptable());
    }
}

#[test]
fn all_required_http_classifications_are_bounded_and_body_free() {
    let statuses = [
        (400, AwsLambdaProviderError::BadRequest),
        (401, AwsLambdaProviderError::Unauthorized),
        (403, AwsLambdaProviderError::Forbidden),
        (404, AwsLambdaProviderError::NotFound),
        (409, AwsLambdaProviderError::Conflict),
        (
            429,
            AwsLambdaProviderError::RateLimited {
                retry_after_seconds: None,
            },
        ),
        (500, AwsLambdaProviderError::ServerError { status: 500 }),
    ];
    for (status, expected) in statuses {
        let scope = fixture_scope();
        let transport = RecordingTransport::new(TransportProvenance::Recording)
            .with_lookup_response(Err(AwsLambdaTransportError::Http(
                AwsLambdaHttpStatus::new(status).expect("status"),
            )));
        let mut service = AwsLambdaInvocationResultService::new(registration(&scope), transport)
            .expect("service");
        assert_eq!(
            service.read_function_metadata(),
            Err(AwsLambdaInvocationResultError::Provider(expected))
        );
    }
}

#[test]
fn duplicate_invocation_stale_mission_revocation_and_blocked_env_fail_closed() {
    let scope = fixture_scope();
    let mut service = recording_service(&scope);
    let invocation = service.compile_invocation_proposal().expect("proposal");
    let projection = service
        .project_invocation_result(&invocation)
        .expect("projection");
    assert_eq!(
        service.project_invocation_result(&invocation),
        Err(AwsLambdaInvocationResultError::Provider(
            AwsLambdaProviderError::DuplicateInvocation,
        ))
    );
    let consumer = MissionAwsLambdaResultConsumer::new(scope.clone());
    assert_eq!(
        consumer.compile_proposal_at_revision(&projection, "stale", scope.mission.revision + 1),
        Err(AwsLambdaInvocationResultError::StaleMissionRevision)
    );

    let mut revoked = recording_service(&scope);
    let proposal = revoked.compile_invocation_proposal().expect("proposal");
    revoked.revoke_registration().expect("revoke");
    assert_eq!(
        revoked.project_invocation_result(&proposal),
        Err(AwsLambdaInvocationResultError::RegistrationRevoked)
    );

    let mut blocked =
        AwsLambdaInvocationResultService::new(registration(&scope), lambda::BlockedEnvTransport)
            .expect("blocked service");
    let blocked_proposal = blocked.compile_invocation_proposal().expect("proposal");
    assert_eq!(
        blocked.observe_bounded(&blocked_proposal),
        Err(AwsLambdaInvocationResultError::Transport(
            AwsLambdaTransportError::BlockedEnv,
        ))
    );
    assert_eq!(
        blocked.provider().provenance(),
        TransportProvenance::BlockedEnv
    );
    assert!(!blocked.provider().connected());
    assert!(!blocked.provider().native());
    assert!(!blocked.provider().first_party());
}

#[test]
fn function_version_alias_code_and_config_drift_are_rejected() {
    let scope = fixture_scope();
    let service = recording_service(&scope);
    let proposal = service.compile_invocation_proposal().expect("proposal");
    let mut changed = proposal.clone();
    changed.function.version = PublishedVersion::new("8").expect("version");
    assert_eq!(
        changed.validate_integrity(),
        Err(AwsLambdaInvocationResultError::TamperedEvidence)
    );

    let mut function = scope.function.clone();
    function.code_sha256 = Digest::from_text("different-code");
    let mut response = ProviderInvocationResponse::for_proposal(
        &proposal,
        InvocationStatus::Succeeded,
        None,
        Some(AwsLambdaHttpStatus::new(200).expect("status")),
        false,
        Some(Digest::from_text("output")),
        None,
        UsageEvidence::for_input(&scope.input).expect("usage"),
        100,
        false,
        100,
        TransportProvenance::Recording,
    )
    .expect("response");
    response.function = function;
    let transport =
        RecordingTransport::new(TransportProvenance::Recording).with_invoke_response(Ok(response));
    let mut drift_service =
        AwsLambdaInvocationResultService::new(registration(&scope), transport).expect("service");
    let drift_proposal = drift_service
        .compile_invocation_proposal()
        .expect("proposal");
    assert_eq!(
        drift_service.project_invocation_result(&drift_proposal),
        Err(AwsLambdaInvocationResultError::TamperedEvidence)
    );
}

#[test]
fn recording_fake_loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = fixture_scope();
    let transports = [
        TransportProvenance::Recording,
        TransportProvenance::Fake,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ];
    for provenance in transports {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
    let capability = recording_service(&scope).describe_capabilities();
    assert!(capability.read_only);
    assert!(!capability.connected);
    assert!(!capability.native);
    assert!(!capability.first_party);
    assert!(!capability.provider_receipt);
    assert!(!capability.outcome_adoption);
}

#[test]
fn invalid_tail_logs_and_forbidden_permissions_are_rejected() {
    let scope = fixture_scope();
    assert_eq!(
        InvocationConfig::new(
            ConfigId::new("logs", 1).expect("config"),
            1,
            1_000,
            lambda::MAX_RESPONSE_BYTES,
            LogType::Tail,
        ),
        Err(AwsLambdaInvocationResultError::InvalidInvocationConfiguration)
    );
    assert_eq!(
        PermissionSnapshot::new(1, ["function.write"]),
        Err(AwsLambdaInvocationResultError::InvalidPermissionSnapshot)
    );
    let secret = SecretReference::for_scope("opaque", &scope, 1).expect("secret");
    assert!(!format!("{secret:?}").contains("opaque"));
}
