use chrono::{DateTime, Duration, Utc};
use serde_json::to_string;

use hartevo_aws_synthetics_canary_result_plugin::{
    AWS_SYNTHETICS_API_REVISION, AccountId, AwsRegion, AwsSyntheticsCanaryContract,
    AwsSyntheticsCanaryProposal, AwsSyntheticsCanaryService, AwsSyntheticsCanaryServiceError,
    AwsSyntheticsEvidenceState, AwsSyntheticsProvider, AwsSyntheticsReadRequest,
    AwsSyntheticsScope, AwsSyntheticsTarget, BlockedEnvAwsSyntheticsTransport, CanaryName,
    CanaryReadOperation, CanaryRun, CanaryRunOutcome, CanaryRunPage, DeploymentBinding, Digest,
    EndpointId, EvidenceState, FixtureAwsSyntheticsTransport, LoopbackAwsSyntheticsTransport,
    MissionAwsSyntheticsConsumer, MissionAwsSyntheticsDecisionState, MissionBinding, OpaqueCursor,
    PermissionFence, PermissionId, ProjectBinding, ProviderRevision,
    RecordingAwsSyntheticsTransport, RegistrationError, RegistrationState, Revision, RunId,
    SecretReference, TransportError, TransportProvenance, WorkProductBinding,
};

type RecordingService = AwsSyntheticsCanaryService<RecordingAwsSyntheticsTransport>;

fn at(seconds: i64) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-08-15T00:00:00Z")
        .expect("valid timestamp")
        .with_timezone(&Utc)
        + Duration::seconds(seconds)
}

fn scope_for() -> (AwsSyntheticsScope, PermissionFence, SecretReference) {
    let permission = PermissionFence::readonly(
        PermissionId::new("aws-synthetics-read").expect("permission"),
        Revision::new(3).expect("permission revision"),
    )
    .expect("permission fence");
    let target = AwsSyntheticsTarget::new(
        AccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        CanaryName::new("checkout-canary").expect("canary"),
        Revision::new(7).expect("canary revision"),
        EndpointId::new("checkout-endpoint").expect("endpoint"),
        Digest::from_text("https://example.invalid/checkout"),
    )
    .expect("target");
    let scope = AwsSyntheticsScope::new(
        DeploymentBinding::new(
            hartevo_aws_synthetics_canary_result_plugin::DeploymentId::new("deployment-1")
                .expect("Deployment"),
            Revision::new(4).expect("Deployment revision"),
        ),
        MissionBinding::new(
            hartevo_aws_synthetics_canary_result_plugin::MissionId::new("mission-1")
                .expect("Mission"),
            Revision::new(8).expect("Mission revision"),
        ),
        ProjectBinding::new(
            hartevo_aws_synthetics_canary_result_plugin::ProjectId::new("project-1")
                .expect("Project"),
            Revision::new(5).expect("Project revision"),
        ),
        WorkProductBinding::new(
            hartevo_aws_synthetics_canary_result_plugin::WorkProductId::new("work-product-1")
                .expect("Work Product"),
            Revision::new(6).expect("Work Product revision"),
        ),
        target,
        permission.digest(),
    )
    .expect("scope");
    let secret = SecretReference::for_synthetics("sigv4-keyring-ref", &scope.target)
        .expect("opaque secret reference");
    (scope, permission, secret)
}

fn recording_service() -> (AwsSyntheticsScope, RecordingService) {
    let (scope, permission, secret) = scope_for();
    let provider =
        AwsSyntheticsProvider::new(RecordingAwsSyntheticsTransport::default()).expect("provider");
    let service = AwsSyntheticsCanaryService::new(scope.clone(), secret, permission, provider)
        .expect("service");
    (scope, service)
}

fn run(
    scope: &AwsSyntheticsScope,
    id: usize,
    revision: u64,
    outcome: CanaryRunOutcome,
    seconds: i64,
) -> CanaryRun {
    CanaryRun::new(
        RunId::new(format!("run-{id}")).expect("run id"),
        scope.target.canary_name.clone(),
        Revision::new(scope.target.canary_revision.get()).expect("canary revision"),
        scope.target.endpoint_digest.clone(),
        Revision::new(revision).expect("run revision"),
        outcome,
        at(seconds),
        Some(at(seconds + 1)),
    )
    .expect("run")
}

fn page(number: u16, runs: Vec<CanaryRun>, next: Option<OpaqueCursor>) -> CanaryRunPage {
    CanaryRunPage::new(
        number,
        runs,
        next,
        512,
        ProviderRevision::new(AWS_SYNTHETICS_API_REVISION).expect("provider revision"),
    )
    .expect("page")
}

fn request(scope: &AwsSyntheticsScope, max_pages: u16) -> AwsSyntheticsReadRequest {
    AwsSyntheticsReadRequest::for_scope(scope, 50, max_pages).expect("read request")
}

fn push_page(service: &mut RecordingService, page: CanaryRunPage) {
    service.provider_mut().transport_mut().push_page(page);
}

#[test]
fn contract_scope_registration_and_capabilities_are_explicit() {
    AwsSyntheticsCanaryContract::baseline().expect("contract");
    let (scope, service) = recording_service();
    let capabilities = RecordingService::describe_capabilities();
    assert_eq!(capabilities.allowlisted_api_operations, ["GetCanaryRuns"]);
    assert_eq!(capabilities.allowlisted_method, "POST");
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(!capabilities.live_execution);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.verification_authority);
    assert!(!capabilities.outcome_authority);
    assert_eq!(scope.target.account_id.as_str(), "123456789012");
    assert_eq!(scope.target.region.as_str(), "us-east-1");
    assert_eq!(scope.target.canary_name.as_str(), "checkout-canary");
    assert_eq!(scope.project.id.as_str(), "project-1");
    assert_eq!(scope.mission.id.as_str(), "mission-1");
    assert_eq!(scope.work_product.id.as_str(), "work-product-1");
    assert!(service.is_active());
    assert_ne!(service.registration().scope_digest, Digest::zero());
    assert_ne!(service.registration().permission_digest, Digest::zero());
    assert_ne!(service.registration().evidence_digest, Digest::zero());
}

#[test]
fn secret_and_cursor_are_opaque_and_non_serializing() {
    let (scope, service) = recording_service();
    let secret = service.secret_reference();
    assert_eq!(
        to_string(secret).expect("secret JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{secret:?}").contains("sigv4-keyring-ref"));
    assert!(
        !to_string(secret)
            .expect("secret JSON")
            .contains("sigv4-keyring-ref")
    );

    let cursor = OpaqueCursor::new("provider-next-token-secret").expect("cursor");
    assert_eq!(
        to_string(&cursor).expect("cursor JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{cursor:?}").contains("provider-next-token-secret"));
    let bound = request(&scope, 4)
        .with_cursor(Some(cursor))
        .expect("bound cursor");
    assert!(
        !to_string(&bound)
            .expect("request JSON")
            .contains("provider-next-token-secret")
    );
}

#[test]
fn passed_run_produces_review_only_mission_decision_and_record() {
    let (scope, mut service) = recording_service();
    push_page(
        &mut service,
        page(
            1,
            vec![run(&scope, 1, 1, CanaryRunOutcome::Passed, 10)],
            None,
        ),
    );
    let proposal = service
        .propose(request(&scope, 4), at(20))
        .expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Passed);
    assert!(proposal.read_only);
    assert!(!proposal.live_execution);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.verification_authority);
    assert!(!proposal.certification_claim);
    assert!(!proposal.adopted_outcome);

    let consumer = MissionAwsSyntheticsConsumer::new(scope.clone(), service.registration().clone())
        .expect("Mission consumer");
    let decision = consumer.consume(proposal.clone()).expect("decision");
    assert_eq!(
        decision.decision_state,
        MissionAwsSyntheticsDecisionState::ObservedPassReview
    );
    assert_eq!(decision.project.id.as_str(), "project-1");
    assert_eq!(decision.mission.id.as_str(), "mission-1");
    assert_eq!(decision.work_product.id.as_str(), "work-product-1");
    assert!(decision.requires_human_review);
    assert!(!decision.safe_to_promote);
    assert!(!decision.connected);
    assert!(!decision.native);
    assert!(!decision.first_party);
    assert!(!decision.verification_authority);
    assert!(!decision.certification_claim);
    assert!(!decision.adopted_outcome);
    assert!(!decision.truth_authority);

    let receipt = service
        .record_at(&proposal, at(21))
        .expect("record receipt");
    assert!(receipt.recorded);
    assert!(!receipt.raw_provider_payload_retained);
    assert!(!receipt.endpoint_url_retained);
    assert!(!receipt.durable_receipt);
    assert!(!receipt.connected);
    assert!(!receipt.native);
    assert!(!receipt.first_party);
    let verified = service.verify(&receipt).expect("verify receipt");
    assert!(verified.verified);
    assert!(!verified.verification_authority);
    assert!(!verified.adopted_outcome);
}

#[test]
fn run_revision_and_endpoint_scope_mismatch_fail_closed_as_partial() {
    let (scope, mut service) = recording_service();
    let stale = run(&scope, 1, 1, CanaryRunOutcome::Passed, 10);
    let mut stale_revision = stale.clone();
    stale_revision.canary_revision = Revision::new(6).expect("stale revision");
    stale_revision.run_digest = stale_revision.recomputed_digest();
    push_page(&mut service, page(1, vec![stale_revision], None));
    let result = service.read(request(&scope, 4)).expect("partial read");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::StaleRevision)
    );

    let (scope, mut service) = recording_service();
    let mut wrong_endpoint = run(&scope, 2, 1, CanaryRunOutcome::Passed, 10);
    wrong_endpoint.endpoint_digest = Digest::from_text("other-endpoint");
    wrong_endpoint.run_digest = wrong_endpoint.recomputed_digest();
    push_page(&mut service, page(1, vec![wrong_endpoint], None));
    let result = service
        .read(request(&scope, 4))
        .expect("partial scope read");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::ScopeMismatch)
    );
}

#[test]
fn pagination_loop_and_page_budget_are_bounded() {
    let (scope, mut service) = recording_service();
    let cursor = OpaqueCursor::new("cursor-one").expect("cursor");
    push_page(
        &mut service,
        page(
            1,
            vec![run(&scope, 1, 1, CanaryRunOutcome::Passed, 1)],
            Some(cursor.clone()),
        ),
    );
    push_page(
        &mut service,
        page(
            2,
            vec![run(&scope, 2, 2, CanaryRunOutcome::Passed, 2)],
            Some(cursor),
        ),
    );
    let result = service.read(request(&scope, 4)).expect("loop read");
    assert_eq!(result.evidence.pages_read, 2);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::PaginationLoop)
    );
    assert!(result.evidence.truncated);

    let (scope, mut service) = recording_service();
    push_page(
        &mut service,
        page(
            1,
            vec![run(&scope, 3, 1, CanaryRunOutcome::Passed, 3)],
            Some(OpaqueCursor::new("cursor-page-budget").expect("cursor")),
        ),
    );
    let result = service.read(request(&scope, 1)).expect("page budget read");
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::PageBudget)
    );
}

#[test]
fn cursor_binding_and_page_digest_tamper_fail_closed() {
    let (scope, mut service) = recording_service();
    let wrong_binding = OpaqueCursor::new("wrong-binding")
        .expect("cursor")
        .bind(&Digest::from_text("another-query"));
    push_page(
        &mut service,
        page(
            1,
            vec![run(&scope, 1, 1, CanaryRunOutcome::Passed, 1)],
            Some(wrong_binding),
        ),
    );
    let result = service.read(request(&scope, 4)).expect("binding read");
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::ScopeMismatch)
    );

    let (scope, mut service) = recording_service();
    let mut tampered_page = page(
        1,
        vec![run(&scope, 2, 1, CanaryRunOutcome::Passed, 1)],
        None,
    );
    tampered_page.runs[0].outcome = CanaryRunOutcome::Failed;
    push_page(&mut service, tampered_page);
    let result = service
        .read(request(&scope, 4))
        .expect("tampered page read");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::MalformedPage)
    );
    assert_eq!(
        result.evidence.provider_errors[0].kind,
        hartevo_aws_synthetics_canary_result_plugin::ProviderErrorKind::Malformed
    );
}

#[test]
fn run_budget_and_empty_evidence_are_not_success() {
    let (scope, mut service) = recording_service();
    let runs_one = (0..50)
        .map(|index| {
            run(
                &scope,
                index,
                1,
                CanaryRunOutcome::Passed,
                i64::try_from(index).expect("small fixture index"),
            )
        })
        .collect();
    let runs_two = (50..100)
        .map(|index| {
            run(
                &scope,
                index,
                1,
                CanaryRunOutcome::Passed,
                i64::try_from(index).expect("small fixture index"),
            )
        })
        .collect();
    let runs_three = (100..129)
        .map(|index| {
            run(
                &scope,
                index,
                1,
                CanaryRunOutcome::Passed,
                i64::try_from(index).expect("small fixture index"),
            )
        })
        .collect();
    push_page(
        &mut service,
        page(
            1,
            runs_one,
            Some(OpaqueCursor::new("run-budget-1").expect("cursor")),
        ),
    );
    push_page(
        &mut service,
        page(
            2,
            runs_two,
            Some(OpaqueCursor::new("run-budget-2").expect("cursor")),
        ),
    );
    push_page(&mut service, page(3, runs_three, None));
    let result = service.read(request(&scope, 4)).expect("run budget read");
    assert_eq!(result.evidence.runs.len(), 128);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::RunBudget)
    );

    let (scope, mut service) = recording_service();
    push_page(&mut service, page(1, Vec::new(), None));
    let result = service
        .read(request(&scope, 4))
        .expect("empty evidence read");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::MissingRuns)
    );
}

#[test]
fn access_loss_throttle_and_timeout_are_redacted_evidence() {
    let (scope, mut service) = recording_service();
    service
        .provider_mut()
        .transport_mut()
        .push_response(Err(TransportError::AccessDenied));
    let result = service
        .read(request(&scope, 4))
        .expect("access loss evidence");
    assert_eq!(result.evidence.state, EvidenceState::AccessLoss);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::AccessLoss)
    );
    assert_eq!(
        result.evidence.provider_errors[0].kind,
        hartevo_aws_synthetics_canary_result_plugin::ProviderErrorKind::AccessDenied
    );
    assert!(
        !serde_json::to_string(&result.evidence)
            .expect("evidence JSON")
            .contains("provider access denied")
    );

    let (scope, mut service) = recording_service();
    for _ in 0..2 {
        service
            .provider_mut()
            .transport_mut()
            .push_response(Err(TransportError::Throttled));
    }
    push_page(
        &mut service,
        page(
            1,
            vec![run(&scope, 1, 1, CanaryRunOutcome::Passed, 1)],
            None,
        ),
    );
    let result = service.read(request(&scope, 4)).expect("throttle retry");
    assert_eq!(result.evidence.state, EvidenceState::Passed);
    assert_eq!(result.evidence.retries, 2);
    assert_eq!(result.evidence.requests_made, 3);

    let (scope, mut service) = recording_service();
    for _ in 0..3 {
        service
            .provider_mut()
            .transport_mut()
            .push_response(Err(TransportError::Timeout));
    }
    let result = service.read(request(&scope, 4)).expect("timeout evidence");
    assert_eq!(result.evidence.state, EvidenceState::Timeout);
    assert_eq!(result.evidence.retries, 2);
    assert_eq!(result.evidence.requests_made, 3);
}

#[test]
fn blocked_env_fixture_recording_and_loopback_provenance_never_claim_authority() {
    let (scope, permission, secret) = scope_for();
    let provider =
        AwsSyntheticsProvider::new(BlockedEnvAwsSyntheticsTransport).expect("blocked provider");
    let mut service = AwsSyntheticsCanaryService::new(scope.clone(), secret, permission, provider)
        .expect("blocked service");
    let result = service
        .read(request(&scope, 4))
        .expect("BLOCKED_ENV evidence");
    assert_eq!(result.evidence.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(result.evidence.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::BlockedEnv)
    );
    assert!(!result.evidence.provenance.connected());
    assert!(!result.evidence.provenance.native());
    assert!(!result.evidence.provenance.first_party());

    let fixture = FixtureAwsSyntheticsTransport::with_provenance(TransportProvenance::Fixture);
    let loopback = LoopbackAwsSyntheticsTransport::loopback();
    assert_eq!(fixture.provenance(), TransportProvenance::Fixture);
    assert_eq!(loopback.provenance(), TransportProvenance::Loopback);
    assert!(!fixture.provenance().connected());
    assert!(!loopback.provenance().native());
}

#[test]
fn proposal_registration_and_record_tampering_are_rejected() {
    let (scope, mut service) = recording_service();
    push_page(
        &mut service,
        page(
            1,
            vec![run(&scope, 1, 1, CanaryRunOutcome::Passed, 1)],
            None,
        ),
    );
    let proposal = service
        .propose(request(&scope, 4), at(5))
        .expect("proposal");
    let mut tampered_proposal: AwsSyntheticsCanaryProposal = proposal.clone();
    tampered_proposal.evidence.state = EvidenceState::Failed;
    assert!(service.verify_proposal(&tampered_proposal).is_err());
    let mut flags_tampered = proposal.clone();
    flags_tampered.native = true;
    assert!(service.verify_proposal(&flags_tampered).is_err());

    let receipt = service.record_at(&proposal, at(6)).expect("receipt");
    let mut tampered_receipt = receipt.clone();
    tampered_receipt.retained_run_count += 1;
    assert!(service.verify(&tampered_receipt).is_err());

    let original_registration = service.registration().clone();
    service.registration_mut().scope_digest = Digest::zero();
    assert!(matches!(
        service.read(request(&scope, 4)),
        Err(AwsSyntheticsCanaryServiceError::RegistrationDrift(_))
    ));
    let consumer = MissionAwsSyntheticsConsumer::new(scope, original_registration)
        .expect("untampered registration copy");
    assert!(consumer.verify_evidence(&proposal.evidence).is_ok());
}

#[test]
fn registration_revocation_is_reversible_and_fail_closed() {
    let (scope, mut service) = recording_service();
    let registration = service.registration().clone();
    service.revoke_registration().expect("revoke");
    assert_eq!(service.registration().state, RegistrationState::Revoked);
    assert!(!service.is_active());
    assert!(matches!(
        service.read(request(&scope, 4)),
        Err(AwsSyntheticsCanaryServiceError::RegistrationRevoked)
    ));
    assert!(matches!(
        service.revoke_registration(),
        Err(AwsSyntheticsCanaryServiceError::Registration(
            RegistrationError::AlreadyRevoked
        ))
    ));
    assert!(MissionAwsSyntheticsConsumer::new(scope, registration).is_ok());
}

#[test]
fn request_scope_revision_and_provider_revision_drift_are_rejected() {
    let (scope, permission, secret) = scope_for();
    let provider =
        AwsSyntheticsProvider::new(RecordingAwsSyntheticsTransport::default()).expect("provider");
    let mut service = AwsSyntheticsCanaryService::new(scope.clone(), secret, permission, provider)
        .expect("service");
    let mut wrong_scope_request = request(&scope, 4);
    wrong_scope_request.scope_digest = Digest::from_text("other-scope");
    assert!(service.read(wrong_scope_request).is_err());

    let (scope, mut service) = recording_service();
    let wrong_revision_page = CanaryRunPage::new(
        1,
        vec![run(&scope, 1, 1, CanaryRunOutcome::Passed, 1)],
        None,
        512,
        ProviderRevision::new("aws-synthetics-read-r2").expect("drift revision"),
    )
    .expect("page");
    push_page(&mut service, wrong_revision_page);
    let result = service.read(request(&scope, 4)).expect("revision evidence");
    assert_eq!(result.evidence.state, EvidenceState::Partial);
    assert_eq!(
        result.evidence.partial_reason,
        Some(hartevo_aws_synthetics_canary_result_plugin::PartialReason::StaleRevision)
    );
}

#[test]
fn provider_unknown_recording_exhaustion_is_not_connected() {
    let (scope, mut service) = recording_service();
    let result = service
        .read(request(&scope, 4))
        .expect("exhausted recording");
    assert_eq!(result.evidence.state, EvidenceState::ProviderUnknown);
    assert_eq!(result.evidence.provenance, TransportProvenance::Recording);
    assert_eq!(
        result.evidence.provider_errors[0].kind,
        hartevo_aws_synthetics_canary_result_plugin::ProviderErrorKind::Replay
    );
    assert!(!result.evidence.provenance.connected());
    assert!(!result.evidence.provenance.native());
    assert!(!result.evidence.provenance.first_party());
}

#[test]
fn evidence_state_alias_is_typed_and_read_operation_is_allowlisted() {
    let state: AwsSyntheticsEvidenceState = EvidenceState::Passed;
    assert_eq!(state, EvidenceState::Passed);
    assert_eq!(
        CanaryReadOperation::GetCanaryRuns,
        CanaryReadOperation::GetCanaryRuns
    );
    assert_eq!(AWS_SYNTHETICS_API_REVISION, "aws-synthetics-read-r1");
}
