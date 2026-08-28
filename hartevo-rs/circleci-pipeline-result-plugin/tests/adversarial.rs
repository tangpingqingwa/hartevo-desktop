use std::collections::BTreeSet;

use hartevo_circleci_pipeline_result_plugin::{
    BlockedEnvCredentialResolver, CircleCiApprovalState, CircleCiCredentialKind, CircleCiFixture,
    CircleCiFixtureTransport, CircleCiPermission, CircleCiPermissionSnapshot,
    CircleCiPipelineReadRequest, CircleCiPipelineResultError, CircleCiPipelineResultService,
    CircleCiProvider, CircleCiProviderError, CircleCiProviderState, CircleCiRevisions,
    CircleCiScope, CircleCiStatus, CircleCiTransportOutcome, FixtureFailure,
    MissionCircleCiPipelineConsumer, MissionWorkProduct, RawApproval, RawArtifactMetadata, RawJob,
    RawPipeline, RawWorkflow, ReadOnlyAuthority, SecretReference, StaticCircleCiCredentialResolver,
    contract_digest, digest_parts, sha256_digest,
};

const TOKEN: &str = "circleci-fixture-token-never-in-evidence";
const OIDC_ASSERTION: &str = "circleci-oidc-assertion-never-in-evidence";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const WORKFLOW_NAME: &str = "build-and-test-confidential";
const JOB_NAME: &str = "run-private-tests";
const ARTIFACT_NAME: &str = "private-report.xml";
const ARTIFACT_PATH: &str = "test-results/private-report.xml";

fn digest(value: &str) -> String {
    sha256_digest(value.as_bytes())
}

fn make_scope() -> CircleCiScope {
    CircleCiScope::new(
        "https://circleci.com",
        "acme",
        "gh/acme/repo",
        "pipeline-1",
        "workflow-1",
        42,
        "attempt-1",
        COMMIT,
        "mission-1",
        "project-1",
        "work-product-1",
    )
    .expect("scope")
    .with_revisions(CircleCiRevisions::new(3, 4, 5, 6, 7, 8, 9, 10, 11))
    .expect("revisions")
}

fn registration(
    scope: &CircleCiScope,
) -> hartevo_circleci_pipeline_result_plugin::CircleCiRegistration {
    let secret = SecretReference::token("circleci-secret-reference", scope.digest(), 2)
        .expect("secret reference");
    let permissions = CircleCiPermissionSnapshot::new(
        BTreeSet::from([
            CircleCiPermission::PipelineRead,
            CircleCiPermission::WorkflowRead,
            CircleCiPermission::JobRead,
            CircleCiPermission::ApprovalRead,
            CircleCiPermission::ArtifactMetadataRead,
        ]),
        scope.revisions.permission,
    )
    .expect("permissions");
    hartevo_circleci_pipeline_result_plugin::CircleCiRegistration::new(
        scope.clone(),
        secret,
        permissions,
    )
    .expect("registration")
}

fn base_fixture(scope: &CircleCiScope) -> CircleCiFixture {
    let pipeline = RawPipeline::new(scope, "success").expect("pipeline");
    let workflow = RawWorkflow::new(scope, "success", WORKFLOW_NAME).expect("workflow");
    let job = RawJob::new(scope, "success", JOB_NAME).expect("job");
    let approval = RawApproval::new(scope, "not_required").expect("approval");
    let artifact =
        RawArtifactMetadata::new(scope, ARTIFACT_NAME, ARTIFACT_PATH, 128).expect("artifact");
    CircleCiFixture::new(pipeline)
        .with_workflows(vec![workflow])
        .with_jobs(vec![job])
        .with_approvals(vec![approval])
        .with_artifact_metadata(vec![artifact])
}

fn make_service(
    scope: &CircleCiScope,
    transport: CircleCiFixtureTransport,
) -> CircleCiPipelineResultService<CircleCiFixtureTransport, StaticCircleCiCredentialResolver> {
    let provider = CircleCiProvider::new(
        registration(scope),
        transport,
        StaticCircleCiCredentialResolver::new(TOKEN),
    )
    .expect("provider");
    CircleCiPipelineResultService::new(provider).expect("service")
}

fn request(scope: &CircleCiScope) -> CircleCiPipelineReadRequest {
    CircleCiPipelineReadRequest::new(scope.clone()).expect("request")
}

fn work_product() -> MissionWorkProduct {
    MissionWorkProduct::new(
        "mission-1",
        "project-1",
        "work-product-1",
        8,
        9,
        10,
        digest("work-product-content"),
        digest("mission-objective"),
    )
    .expect("work product")
}

#[test]
fn fixture_recording_loopback_and_blocked_env_are_honest() {
    let scope = make_scope();
    for (transport, expected) in [
        (
            CircleCiFixtureTransport::fixture(base_fixture(&scope)),
            hartevo_circleci_pipeline_result_plugin::CircleCiProvenance::Fixture,
        ),
        (
            CircleCiFixtureTransport::recording(base_fixture(&scope)),
            hartevo_circleci_pipeline_result_plugin::CircleCiProvenance::Recording,
        ),
        (
            CircleCiFixtureTransport::loopback(base_fixture(&scope)),
            hartevo_circleci_pipeline_result_plugin::CircleCiProvenance::Loopback,
        ),
    ] {
        let mut service = make_service(&scope, transport);
        let description = service.describe_scope().expect("description");
        assert_eq!(description.provenance, expected);
        assert!(!description.native_transport);
        assert!(!description.native_connected);
        let evidence = service
            .read_pipeline_result(&request(&scope))
            .expect("evidence");
        assert_eq!(evidence.provenance, expected);
        assert!(!evidence.native_transport);
        assert!(!evidence.native_connected);
        assert!(!evidence.raw_logs_retained);
        assert!(!evidence.artifact_bytes_downloaded);
        let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
        assert!(!serialized.contains(TOKEN));
        assert!(!serialized.contains(WORKFLOW_NAME));
        assert!(!serialized.contains(JOB_NAME));
        assert!(!serialized.contains(ARTIFACT_NAME));
        assert!(!serialized.contains(ARTIFACT_PATH));
        let debug = format!("{:?} {:?}", service.provider(), service.definition());
        assert!(!debug.contains(TOKEN));
        assert!(!debug.contains(OIDC_ASSERTION));
    }

    let transport = CircleCiFixtureTransport::fixture(base_fixture(&scope));
    let provider = CircleCiProvider::new(
        registration(&scope),
        transport,
        BlockedEnvCredentialResolver,
    )
    .expect("blocked provider construction");
    let mut service = CircleCiPipelineResultService::new(provider).expect("service");
    assert_eq!(
        service.read_pipeline_result(&request(&scope)),
        Err(CircleCiPipelineResultError::Provider(
            CircleCiProviderError::BlockedEnv
        ))
    );
    assert_eq!(
        service.provider().state(),
        CircleCiProviderState::BlockedEnv
    );
}

#[test]
fn mission_consumer_compiles_records_and_verifies_without_adoption() {
    let scope = make_scope();
    let provider = CircleCiProvider::new(
        registration(&scope),
        CircleCiFixtureTransport::recording(base_fixture(&scope)),
        StaticCircleCiCredentialResolver::new(TOKEN),
    )
    .expect("provider");
    let service = CircleCiPipelineResultService::new(provider).expect("service");
    let mut consumer = MissionCircleCiPipelineConsumer::new(service);
    let result = consumer
        .consume_pipeline_result(&request(&scope), work_product())
        .expect("mission result");
    assert!(result.proposal.non_mutating);
    assert!(!result.proposal.external_write_performed);
    assert!(!result.proposal.durable_native_receipt);
    assert!(!result.proposal.kernel_outcome_authority);
    assert!(result.receipt.recording_only);
    assert!(result.verification.verified);
    assert!(!result.verification.adopted);
    assert!(!result.verification.native_connected);
    assert_eq!(result.evidence.contract_digest, contract_digest());
    let receipt_json = serde_json::to_string(&result.receipt).expect("receipt JSON");
    assert!(!receipt_json.contains(TOKEN));
    assert!(!receipt_json.contains(WORKFLOW_NAME));
    assert!(!receipt_json.contains(JOB_NAME));
}

#[test]
fn status_and_approval_projections_cover_lifecycle_without_raw_state() {
    let statuses = [
        ("created", CircleCiStatus::Created),
        ("queued", CircleCiStatus::Queued),
        ("running", CircleCiStatus::Running),
        ("success", CircleCiStatus::Successful),
        ("successful", CircleCiStatus::Successful),
        ("failed", CircleCiStatus::Failed),
        ("canceled", CircleCiStatus::Canceled),
        ("on_hold", CircleCiStatus::OnHold),
        ("not_run", CircleCiStatus::NotRun),
        ("blocked", CircleCiStatus::Blocked),
        ("provider-added-later", CircleCiStatus::Unknown),
    ];
    for (raw, expected) in statuses {
        assert_eq!(CircleCiStatus::project(raw), expected);
    }
    assert_eq!(
        CircleCiApprovalState::project("on_hold"),
        CircleCiApprovalState::Pending
    );
    assert_eq!(
        CircleCiApprovalState::project("approved"),
        CircleCiApprovalState::Approved
    );
    assert_eq!(
        CircleCiApprovalState::project("rejected"),
        CircleCiApprovalState::Rejected
    );
    assert_eq!(
        CircleCiApprovalState::project("future-state"),
        CircleCiApprovalState::Unknown
    );

    let scope = make_scope();
    let pending = RawApproval::new(&scope, "pending").expect("pending");
    let approved = RawApproval::new(&scope, "approved").expect("approved");
    let fixture = base_fixture(&scope).with_approval_pages(vec![vec![pending], vec![approved]]);
    let mut service = make_service(&scope, CircleCiFixtureTransport::fixture(fixture));
    let evidence = service
        .read_pipeline_result(&request(&scope))
        .expect("approval evidence");
    assert_eq!(evidence.approvals.len(), 2);
    assert_eq!(evidence.approvals[0].state, CircleCiApprovalState::Pending);
    assert_eq!(evidence.approvals[1].state, CircleCiApprovalState::Approved);
}

#[test]
fn opaque_page_tokens_are_bounded_and_paginated() {
    let scope = make_scope();
    let workflow = RawWorkflow::new(&scope, "running", WORKFLOW_NAME).expect("workflow");
    let job = RawJob::new(&scope, "running", JOB_NAME).expect("job");
    let pending = RawApproval::new(&scope, "pending").expect("pending");
    let approved = RawApproval::new(&scope, "approved").expect("approved");
    let artifact_one =
        RawArtifactMetadata::new(&scope, ARTIFACT_NAME, ARTIFACT_PATH, 128).expect("artifact one");
    let artifact_two = RawArtifactMetadata::new(&scope, "private-summary.json", "summary.json", 64)
        .expect("artifact two");
    let fixture = base_fixture(&scope)
        .with_workflow_pages(vec![vec![], vec![workflow]])
        .with_job_pages(vec![vec![], vec![job]])
        .with_approval_pages(vec![vec![pending], vec![approved]])
        .with_artifact_metadata_pages(vec![vec![artifact_one], vec![artifact_two]]);
    let transport = CircleCiFixtureTransport::recording(fixture);
    let mut service = make_service(&scope, transport.clone());
    let evidence = service
        .read_pipeline_result(&request(&scope))
        .expect("paginated evidence");
    assert_eq!(evidence.workflows.len(), 1);
    assert_eq!(evidence.jobs.len(), 1);
    assert_eq!(evidence.approvals.len(), 2);
    assert_eq!(evidence.artifact_metadata.len(), 2);
    let operations = transport.operations();
    assert_eq!(operations.len(), 9);
    assert!(operations.iter().skip(1).any(|operation| {
        operation.page_token_digest.is_some()
            && matches!(operation.outcome, CircleCiTransportOutcome::Success)
    }));
    let operation_json = serde_json::to_string(&operations).expect("operation JSON");
    assert!(!operation_json.contains("workflows:1"));
    assert!(!operation_json.contains("jobs:1"));
    assert!(!operation_json.contains("circleci-loop-token"));
}

#[test]
fn repeated_page_tokens_and_duplicate_attempts_fail_closed() {
    let scope = make_scope();
    let transport = CircleCiFixtureTransport::fixture(base_fixture(&scope));
    transport.update_fixture(|fixture| fixture.set_cursor_loop(true));
    let mut service = make_service(&scope, transport);
    assert_eq!(
        service.read_pipeline_result(&request(&scope)),
        Err(CircleCiPipelineResultError::PageTokenRepeated)
    );

    let scope_two = make_scope();
    let job = RawJob::new(&scope_two, "success", JOB_NAME).expect("job");
    let duplicate_fixture = base_fixture(&scope_two).with_jobs(vec![job.clone(), job]);
    let mut service = make_service(
        &scope_two,
        CircleCiFixtureTransport::fixture(duplicate_fixture),
    );
    assert_eq!(
        service.read_pipeline_result(&request(&scope_two)),
        Err(CircleCiPipelineResultError::ReplayDetected)
    );
}

#[test]
fn revision_permission_identity_tamper_and_access_fences_are_explicit() {
    let scope = make_scope();
    let transport = CircleCiFixtureTransport::fixture(base_fixture(&scope));
    transport.update_fixture(|fixture| {
        fixture.pipeline_mut().status = String::from("tampered");
    });
    let mut service = make_service(&scope, transport);
    assert_eq!(
        service.read_pipeline_result(&request(&scope)),
        Err(CircleCiPipelineResultError::TamperedEvidence)
    );

    let scope_two = make_scope();
    let transport = CircleCiFixtureTransport::fixture(base_fixture(&scope_two));
    transport.update_fixture(|fixture| {
        fixture.pipeline_mut().revision = 99;
        fixture.pipeline_mut().refresh_digest();
    });
    let mut service = make_service(&scope_two, transport);
    assert_eq!(
        service.read_pipeline_result(&request(&scope_two)),
        Err(CircleCiPipelineResultError::RevisionDrift {
            resource: "pipeline"
        })
    );

    let scope_three = make_scope();
    let transport = CircleCiFixtureTransport::fixture(base_fixture(&scope_three));
    transport.update_fixture(|fixture| fixture.set_permission_digest(digest("permission-drift")));
    let mut service = make_service(&scope_three, transport);
    assert_eq!(
        service.read_pipeline_result(&request(&scope_three)),
        Err(CircleCiPipelineResultError::PermissionDrift)
    );

    let scope_four = make_scope();
    let transport = CircleCiFixtureTransport::fixture(base_fixture(&scope_four));
    transport.update_fixture(|fixture| {
        fixture.pipeline_mut().host = String::from("https://other.circleci.example");
        fixture.pipeline_mut().refresh_digest();
    });
    let mut service = make_service(&scope_four, transport);
    assert_eq!(
        service.read_pipeline_result(&request(&scope_four)),
        Err(CircleCiPipelineResultError::HostDrift)
    );

    let scope_five = make_scope();
    let transport = CircleCiFixtureTransport::fixture(base_fixture(&scope_five));
    transport.update_fixture(|fixture| fixture.set_access_lost(true));
    let mut service = make_service(&scope_five, transport);
    assert_eq!(
        service.read_pipeline_result(&request(&scope_five)),
        Err(CircleCiPipelineResultError::AccessLost)
    );
    assert_eq!(
        service.provider().state(),
        CircleCiProviderState::AccessLost
    );
}

#[test]
fn typed_http_failures_and_retry_receipts_never_become_success() {
    let cases = [
        (
            FixtureFailure::BadRequest,
            CircleCiProviderError::BadRequest,
        ),
        (
            FixtureFailure::Unauthorized,
            CircleCiProviderError::Unauthorized,
        ),
        (FixtureFailure::Forbidden, CircleCiProviderError::Forbidden),
        (FixtureFailure::NotFound, CircleCiProviderError::NotFound),
        (FixtureFailure::Conflict, CircleCiProviderError::Conflict),
        (
            FixtureFailure::RateLimited {
                retry_after_seconds: Some(7),
            },
            CircleCiProviderError::RateLimited {
                retry_after_seconds: Some(7),
            },
        ),
        (FixtureFailure::Timeout, CircleCiProviderError::Timeout),
        (
            FixtureFailure::ServerFailure { status: 503 },
            CircleCiProviderError::ServerFailure { status: 503 },
        ),
        (
            FixtureFailure::MalformedResponse,
            CircleCiProviderError::MalformedResponse,
        ),
    ];
    for (failure, expected) in cases {
        let scope = make_scope();
        let transport =
            CircleCiFixtureTransport::fixture(base_fixture(&scope).with_failure(failure.clone()));
        let mut service = make_service(&scope, transport.clone());
        assert_eq!(
            service.read_pipeline_result(&request(&scope)),
            Err(CircleCiPipelineResultError::Provider(expected))
        );
        if matches!(failure, FixtureFailure::RateLimited { .. }) {
            assert_eq!(transport.operations()[0].retry_after_seconds, Some(7));
        }
    }
}

#[test]
fn proposal_mission_revision_receipt_and_registration_fences_hold() {
    let scope = make_scope();
    let mut service = make_service(
        &scope,
        CircleCiFixtureTransport::recording(base_fixture(&scope)),
    );
    let evidence = service
        .read_pipeline_result(&request(&scope))
        .expect("evidence");
    let mut stale_work_product = work_product();
    stale_work_product.mission_revision = 999;
    assert_eq!(
        service.compile_pipeline_result(stale_work_product, evidence.clone()),
        Err(CircleCiPipelineResultError::MissionRevisionDrift)
    );

    let proposal = service
        .compile_pipeline_result(work_product(), evidence)
        .expect("proposal");
    let mut tampered_proposal = proposal.clone();
    tampered_proposal.evidence_digest = digest("tampered-evidence");
    assert_eq!(
        service.record_pipeline_result(&tampered_proposal),
        Err(CircleCiPipelineResultError::ProposalMismatch)
    );

    let receipt = service.record_pipeline_result(&proposal).expect("receipt");
    let mut tampered_receipt = receipt.clone();
    tampered_receipt.receipt_digest = digest("tampered-receipt");
    assert_eq!(
        service.verify_pipeline_result(&proposal, &tampered_receipt),
        Err(CircleCiPipelineResultError::ReceiptMismatch)
    );

    service.provider_mut().revoke();
    assert_eq!(
        service.read_pipeline_result(&request(&scope)),
        Err(CircleCiPipelineResultError::RegistrationRevoked)
    );

    let scope_two = make_scope();
    let mut reversed = make_service(
        &scope_two,
        CircleCiFixtureTransport::fixture(base_fixture(&scope_two)),
    );
    reversed.provider_mut().reverse();
    assert_eq!(
        reversed.read_pipeline_result(&request(&scope_two)),
        Err(CircleCiPipelineResultError::RegistrationReversed)
    );
}

#[test]
fn oidc_reference_is_opaque_and_read_only_authority_is_false() {
    let scope = make_scope();
    let secret = SecretReference::oidc("oidc-reference", scope.digest(), 3).expect("OIDC ref");
    assert_eq!(secret.credential_kind(), CircleCiCredentialKind::Oidc);
    let secret_json = serde_json::to_string(&secret).expect("secret JSON");
    assert!(!secret_json.contains("oidc-reference"));
    assert!(!secret_json.contains(OIDC_ASSERTION));
    let debug = format!("{secret:?}");
    assert!(!debug.contains("oidc-reference"));
    assert!(!debug.contains(OIDC_ASSERTION));

    let provider = CircleCiProvider::new(
        registration_with_secret(scope.clone(), secret),
        CircleCiFixtureTransport::fixture(base_fixture(&scope)),
        StaticCircleCiCredentialResolver::oidc(OIDC_ASSERTION),
    )
    .expect("OIDC provider");
    let mut service = CircleCiPipelineResultService::new(provider).expect("service");
    let evidence = service
        .read_pipeline_result(&request(&scope))
        .expect("OIDC evidence");
    assert!(
        !serde_json::to_string(&evidence)
            .expect("evidence JSON")
            .contains(OIDC_ASSERTION)
    );
    assert!(!ReadOnlyAuthority::external_write());
    assert!(!ReadOnlyAuthority::trigger());
    assert!(!ReadOnlyAuthority::rerun());
    assert!(!ReadOnlyAuthority::cancel());
    assert!(!ReadOnlyAuthority::approve());
    assert!(!ReadOnlyAuthority::config_mutation());
    assert!(!ReadOnlyAuthority::ssh_or_debug());
    assert!(!ReadOnlyAuthority::raw_logs());
    assert!(!ReadOnlyAuthority::artifact_bytes());
    assert!(!ReadOnlyAuthority::generic_ci_registry());
    assert!(!ReadOnlyAuthority::deployment_scheduler());
    assert!(!ReadOnlyAuthority::kernel_authority());
    assert!(!ReadOnlyAuthority::outcome_adoption());
    assert!(!ReadOnlyAuthority::durable_native_receipt());
    assert!(!ReadOnlyAuthority::native_connected());
}

fn registration_with_secret(
    scope: CircleCiScope,
    secret: SecretReference,
) -> hartevo_circleci_pipeline_result_plugin::CircleCiRegistration {
    let permissions =
        CircleCiPermissionSnapshot::all_read(scope.revisions.permission).expect("permissions");
    hartevo_circleci_pipeline_result_plugin::CircleCiRegistration::new(scope, secret, permissions)
        .expect("registration")
}

#[test]
fn exact_scope_digest_excludes_secret_material_and_has_reversible_registration_metadata() {
    let scope = make_scope();
    let registration = registration(&scope);
    let original_digest = registration.digest();
    assert_eq!(registration.scope.digest(), scope.digest());
    assert_eq!(registration.contract_version, "EXT-CIRCLECI-01-L1/v1");
    assert_eq!(registration.provider_id, "CircleCiProvider");
    assert!(registration.is_active());
    let mut revoked = registration.clone();
    let revocation = revoked.revoke();
    assert!(revocation.revoked);
    assert!(!revoked.is_active());
    assert_ne!(original_digest, revoked.digest());
    let mut reversed = registration;
    let reversal = reversed.reverse();
    assert!(reversal.reversed);
    assert!(!reversed.is_active());
    assert_ne!(original_digest, reversed.digest());
    assert!(!format!("{revoked:?}").contains(TOKEN));
    assert!(!format!("{reversed:?}").contains(TOKEN));
    assert_eq!(digest_parts(["a", "b"]).len(), 64);
}
