use serde_json::json;

use super::*;

fn scope() -> GcpCloudDeployScope {
    GcpCloudDeployScope::new(
        "checkout-prod",
        "us-central1",
        "delivery-pipeline",
        "release-2026-08-15",
        "production",
        "commit-abc123",
        MissionScope::new("mission-deploy-evidence", 7).expect("mission"),
        ProjectScope::new("project-checkout", 4).expect("project"),
        WorkProductScope::new("work-product-release-evidence", 3).expect("work product"),
        PermissionScope::least_privilege(),
        ConsentScope::read_only("consent-cloud-deploy-read", 2).expect("consent"),
    )
    .expect("scope")
}

fn secret(scope: &GcpCloudDeployScope) -> SecretReference {
    SecretReference::oauth("oauth-keychain-binding", scope, 5).expect("secret")
}

fn release(
    scope: &GcpCloudDeployScope,
    phase: ReleasePhase,
    status: ReleaseStatus,
) -> ReleaseSnapshot {
    ReleaseSnapshot::recorded(
        scope,
        phase,
        status,
        Timestamp::new(1_723_680_000).expect("timestamp"),
        Digest::from_text("recorded-release-response"),
    )
    .expect("release")
}

fn rollout(
    scope: &GcpCloudDeployScope,
    phase: RolloutPhase,
    status: RolloutStatus,
) -> RolloutSnapshot {
    RolloutSnapshot::recorded(
        scope,
        "rollout-1",
        phase,
        status,
        Timestamp::new(1_723_680_001).expect("timestamp"),
        Digest::from_text("recorded-rollout-response"),
    )
    .expect("rollout")
}

fn job_run(
    scope: &GcpCloudDeployScope,
    sequence: u32,
    phase: JobRunPhase,
    status: JobRunStatus,
) -> JobRunSnapshot {
    JobRunSnapshot::recorded(
        scope,
        "rollout-1",
        format!("job-run-{sequence}"),
        sequence,
        phase,
        status,
        Timestamp::new(1_723_680_002 + i64::from(sequence)).expect("timestamp"),
        Digest::from_text(format!("recorded-job-run-response-{sequence}")),
    )
    .expect("job run")
}

fn complete_responses(
    scope: &GcpCloudDeployScope,
    release_phase: ReleasePhase,
    release_status: ReleaseStatus,
    rollout_phase: RolloutPhase,
    rollout_status: RolloutStatus,
    job_phase: JobRunPhase,
    job_status: JobRunStatus,
) -> Vec<Result<GcpCloudDeployResponse, GcpCloudDeployTransportError>> {
    let release = release(scope, release_phase, release_status);
    let rollout = rollout(scope, rollout_phase, rollout_status);
    let job_run = job_run(scope, 1, job_phase, job_status);
    vec![
        Ok(GcpCloudDeployResponse::Release(release)),
        Ok(GcpCloudDeployResponse::Rollouts(
            RolloutPage::new(vec![rollout], None).expect("rollout page"),
        )),
        Ok(GcpCloudDeployResponse::JobRuns(
            JobRunPage::new(vec![job_run], None).expect("job-run page"),
        )),
    ]
}

fn service_with(
    scope: GcpCloudDeployScope,
    responses: Vec<Result<GcpCloudDeployResponse, GcpCloudDeployTransportError>>,
) -> GcpCloudDeployService<RecordingGcpCloudDeployTransport> {
    let mut transport = RecordingGcpCloudDeployTransport::default();
    for response in responses {
        transport.push_response(response);
    }
    let provider =
        GcpCloudDeployProvider::new(transport, scope.clone(), ProviderProvenance::Recording)
            .expect("provider");
    GcpCloudDeployService::new(scope.clone(), secret(&scope), provider).expect("service")
}

#[test]
fn contract_registration_and_all_fences_are_digest_bound_and_reversible() {
    validate_contract().expect("contract");
    let scope = scope();
    let provider = GcpCloudDeployProvider::new(
        RecordingGcpCloudDeployTransport::default(),
        scope.clone(),
        ProviderProvenance::Recording,
    )
    .expect("provider");
    let service =
        GcpCloudDeployService::new(scope.clone(), secret(&scope), provider).expect("service");
    let registration = service.registration();
    assert_eq!(registration.scope_digest(), &scope.digest());
    assert_eq!(registration.release_digest(), &scope.release_digest());
    assert_eq!(
        registration.permission_digest(),
        &scope.permissions().digest()
    );
    assert_eq!(
        registration.api_digest(),
        &GcpCloudDeployApiVersion::V1.digest()
    );
    assert_eq!(registration.version_digest(), &Digest::from_text("1.0.0"));
    assert_eq!(
        registration.contract_digest(),
        &Digest::from_text(GCP_CLOUD_DEPLOY_CONTRACT_JSON)
    );
    assert!(registration.reversible());
    assert!(registration.revocable());
    assert!(service.definition().read_only());
    assert!(!service.definition().live_execution());
}

#[test]
fn opaque_secret_reference_is_non_serializing_and_never_retains_raw_identifier() {
    let scope = scope();
    let secret = SecretReference::service_account("service-account-key", &scope, 8)
        .expect("service account reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("service-account-key"));
    assert!(!debug.contains("raw-token"));
    assert_eq!(secret.kind(), SecretKind::ServiceAccount);
    assert_eq!(secret.scope_digest(), &scope.digest());

    let release = ReleaseSnapshot::new(
        scope.release_identity(),
        scope.target_id().clone(),
        scope.commit_id().clone(),
        ReleasePhase::Succeeded,
        ReleaseStatus::Succeeded,
        Revision::new(1).expect("revision"),
        Timestamp::new(1_723_680_000).expect("timestamp"),
        Digest::from_text("provider-body"),
        Some(Digest::from_text("raw-log-body")),
        Some(Digest::from_text("raw-artifact-body")),
    )
    .expect("release");
    let serialized = serde_json::to_string(&release).expect("snapshot JSON");
    assert!(!serialized.contains("raw-log-body"));
    assert!(!serialized.contains("raw-artifact-body"));
    assert!(serialized.contains("logDigest"));
    assert!(release.validate_digest().is_ok());
}

#[test]
fn provider_paths_are_typed_bounded_get_list_and_always_non_native() {
    let scope = scope();
    let mut transport = RecordingGcpCloudDeployTransport::default();
    transport.push_response(Ok(GcpCloudDeployResponse::Release(release(
        &scope,
        ReleasePhase::Succeeded,
        ReleaseStatus::Succeeded,
    ))));
    transport.push_response(Ok(GcpCloudDeployResponse::Releases(
        ReleasePage::new(
            vec![release(
                &scope,
                ReleasePhase::Succeeded,
                ReleaseStatus::Succeeded,
            )],
            None,
        )
        .expect("release page"),
    )));
    let mut provider =
        GcpCloudDeployProvider::new(transport, scope.clone(), ProviderProvenance::Fixture)
            .expect("provider");
    assert!(!provider.connected());
    assert!(!provider.native());
    assert!(!provider.https_transport());
    assert!(!provider.readback());
    assert!(!provider.definition().connected());
    assert!(!provider.definition().native());
    assert!(!ProviderProvenance::Fixture.is_native());
    assert!(!ProviderProvenance::Loopback.is_native());
    assert!(!ProviderProvenance::BlockedEnv.is_native());
    provider.get_release().expect("get release");
    provider.list_releases(None).expect("list releases");
}

#[test]
fn mission_consumer_projects_evidence_without_work_product_or_outcome_adoption() {
    let scope = scope();
    let mut service = service_with(
        scope.clone(),
        complete_responses(
            &scope,
            ReleasePhase::Succeeded,
            ReleaseStatus::Succeeded,
            RolloutPhase::Succeeded,
            RolloutStatus::Succeeded,
            JobRunPhase::Succeeded,
            JobRunStatus::Succeeded,
        ),
    );
    let mut consumer = MissionGcpCloudDeployConsumer::new(scope.clone(), service.registration())
        .expect("consumer");
    let result = consumer.read(&mut service).expect("mission result");
    assert_eq!(result.projection(), EvidenceProjection::Complete);
    assert_eq!(result.state(), MissionResultState::PendingDecision);
    assert_eq!(result.mission_id().as_str(), "mission-deploy-evidence");
    assert_eq!(result.project_id().as_str(), "project-checkout");
    assert_eq!(
        result.work_product_id().as_str(),
        "work-product-release-evidence"
    );
    assert_eq!(result.adoption(), AdoptionAvailability::NotAdoptedLayer2);
    assert!(!result.connected());
    assert!(!result.native());
    assert!(!result.deployment_success_claimed());
    assert!(!result.work_product_adopted());
    assert!(!result.outcome_adopted());
    consumer.revoke().expect("consumer revocation");
    assert!(consumer.read(&mut service).is_err());
}

#[test]
fn phase_transitions_are_monotonic_and_terminal_regression_fails_closed() {
    let scope = scope();
    let mut responses = complete_responses(
        &scope,
        ReleasePhase::InProgress,
        ReleaseStatus::Running,
        RolloutPhase::InProgress,
        RolloutStatus::Running,
        JobRunPhase::InProgress,
        JobRunStatus::Running,
    );
    responses.extend(complete_responses(
        &scope,
        ReleasePhase::Succeeded,
        ReleaseStatus::Succeeded,
        RolloutPhase::Succeeded,
        RolloutStatus::Succeeded,
        JobRunPhase::Succeeded,
        JobRunStatus::Succeeded,
    ));
    let mut service = service_with(scope.clone(), responses);
    assert_eq!(
        service.propose().expect("first proposal").projection(),
        EvidenceProjection::Partial
    );
    assert_eq!(
        service.propose().expect("terminal proposal").projection(),
        EvidenceProjection::Complete
    );

    let mut regression_service = service_with(scope.clone(), {
        let mut values = complete_responses(
            &scope,
            ReleasePhase::Succeeded,
            ReleaseStatus::Succeeded,
            RolloutPhase::Succeeded,
            RolloutStatus::Succeeded,
            JobRunPhase::Succeeded,
            JobRunStatus::Succeeded,
        );
        values.extend(complete_responses(
            &scope,
            ReleasePhase::InProgress,
            ReleaseStatus::Running,
            RolloutPhase::InProgress,
            RolloutStatus::Running,
            JobRunPhase::InProgress,
            JobRunStatus::Running,
        ));
        values
    });
    regression_service
        .propose()
        .expect("initial terminal proposal");
    assert_eq!(
        regression_service
            .propose()
            .expect_err("terminal regression"),
        GcpCloudDeployServiceError::PhaseRegression
    );
}

#[test]
fn job_run_order_is_strict_and_duplicate_or_backwards_pages_are_rejected() {
    let scope = scope();
    let later = job_run(&scope, 2, JobRunPhase::Succeeded, JobRunStatus::Succeeded);
    let earlier = job_run(&scope, 1, JobRunPhase::Succeeded, JobRunStatus::Succeeded);
    assert_eq!(
        JobRunPage::new(vec![later.clone(), earlier.clone()], None).expect_err("backwards order"),
        ModelError::InvalidJobRunOrdering
    );
    assert_eq!(
        JobRunPage::new(vec![later.clone(), later], None).expect_err("duplicate order"),
        ModelError::InvalidJobRunOrdering
    );
    let ordered = JobRunPage::new(vec![earlier], None).expect("ordered page");
    assert_eq!(ordered.items().len(), 1);
}

#[test]
fn pagination_is_opaque_and_cursor_binding_cannot_cross_scope_or_operation() {
    let scope = scope();
    let other_scope = GcpCloudDeployScope::new(
        "other-project",
        "us-central1",
        "delivery-pipeline",
        "release-2026-08-15",
        "production",
        "commit-abc123",
        MissionScope::new("mission-deploy-evidence", 7).expect("mission"),
        ProjectScope::new("project-checkout", 4).expect("project"),
        WorkProductScope::new("work-product-release-evidence", 3).expect("work product"),
        PermissionScope::least_privilege(),
        ConsentScope::read_only("consent-cloud-deploy-read", 2).expect("consent"),
    )
    .expect("other scope");
    let foreign_cursor =
        PageCursor::from_scope(&other_scope, ListOperation::Releases, 1).expect("foreign cursor");
    assert!(!format!("{foreign_cursor:?}").contains("other-project"));
    assert!(!foreign_cursor.matches(&scope, ListOperation::Releases));
    assert!(!foreign_cursor.matches(&other_scope, ListOperation::Rollouts));

    let mut service = service_with(
        scope.clone(),
        vec![Ok(GcpCloudDeployResponse::Releases(
            ReleasePage::new(
                vec![release(
                    &scope,
                    ReleasePhase::Succeeded,
                    ReleaseStatus::Succeeded,
                )],
                Some(foreign_cursor.clone()),
            )
            .expect("page"),
        ))],
    );
    assert!(matches!(
        service.list_releases(None),
        Err(GcpCloudDeployServiceError::Provider(
            GcpCloudDeployProviderError::CursorMismatch
        ))
    ));
    assert!(matches!(
        service.list_releases(Some(foreign_cursor)),
        Err(GcpCloudDeployServiceError::Provider(
            GcpCloudDeployProviderError::CursorMismatch
        ))
    ));
}

#[test]
fn permission_scope_and_secret_scope_fail_closed() {
    assert!(PermissionScope::new([GcpCloudDeployPermission::ReleasesGet]).is_err());
    assert!(
        PermissionScope::new([
            GcpCloudDeployPermission::ReleasesGet,
            GcpCloudDeployPermission::ReleasesGet,
            GcpCloudDeployPermission::ReleasesList,
            GcpCloudDeployPermission::RolloutsGet,
            GcpCloudDeployPermission::RolloutsList,
            GcpCloudDeployPermission::JobRunsGet,
            GcpCloudDeployPermission::JobRunsList,
            GcpCloudDeployPermission::TargetsGet,
        ])
        .is_err()
    );
    let scope = scope();
    let other = GcpCloudDeployScope::new(
        "checkout-prod",
        "us-central1",
        "delivery-pipeline",
        "other-release",
        "production",
        "commit-abc123",
        MissionScope::new("mission-deploy-evidence", 7).expect("mission"),
        ProjectScope::new("project-checkout", 4).expect("project"),
        WorkProductScope::new("work-product-release-evidence", 3).expect("work product"),
        PermissionScope::least_privilege(),
        ConsentScope::read_only("consent-cloud-deploy-read", 2).expect("consent"),
    )
    .expect("other scope");
    let provider = GcpCloudDeployProvider::new(
        RecordingGcpCloudDeployTransport::default(),
        scope.clone(),
        ProviderProvenance::Fake,
    )
    .expect("provider");
    let wrong_secret = secret(&other);
    assert_eq!(
        GcpCloudDeployService::new(scope, wrong_secret, provider).expect_err("secret fence"),
        GcpCloudDeployServiceError::ScopeMismatch
    );
}

#[test]
fn stale_target_and_commit_are_not_accepted_as_current_evidence() {
    let scope = scope();
    let stale_target = ReleaseSnapshot::new(
        scope.release_identity(),
        TargetId::new("stale-target").expect("target"),
        scope.commit_id().clone(),
        ReleasePhase::Succeeded,
        ReleaseStatus::Succeeded,
        Revision::new(1).expect("revision"),
        Timestamp::new(1_723_680_000).expect("timestamp"),
        Digest::from_text("stale-target-response"),
        None,
        None,
    )
    .expect("stale target snapshot");
    let mut transport = RecordingGcpCloudDeployTransport::default();
    transport.push_response(Ok(GcpCloudDeployResponse::Release(stale_target)));
    let mut provider =
        GcpCloudDeployProvider::new(transport, scope.clone(), ProviderProvenance::Recording)
            .expect("provider");
    assert_eq!(
        provider.get_release().expect_err("stale target"),
        GcpCloudDeployProviderError::StaleTarget
    );

    let stale_commit = ReleaseSnapshot::new(
        scope.release_identity(),
        scope.target_id().clone(),
        CommitId::new("stale-commit").expect("commit"),
        ReleasePhase::Succeeded,
        ReleaseStatus::Succeeded,
        Revision::new(1).expect("revision"),
        Timestamp::new(1_723_680_000).expect("timestamp"),
        Digest::from_text("stale-commit-response"),
        None,
        None,
    )
    .expect("stale commit snapshot");
    let mut transport = RecordingGcpCloudDeployTransport::default();
    transport.push_response(Ok(GcpCloudDeployResponse::Release(stale_commit)));
    let mut provider = GcpCloudDeployProvider::new(transport, scope, ProviderProvenance::Recording)
        .expect("provider");
    assert_eq!(
        provider.get_release().expect_err("stale commit"),
        GcpCloudDeployProviderError::StaleCommit
    );
}

#[test]
fn provider_statuses_and_timeouts_project_to_bounded_honest_states() {
    let cases = [
        (
            GcpCloudDeployTransportError::http_status(401, "unauth"),
            EvidenceProjection::AccessLost,
        ),
        (
            GcpCloudDeployTransportError::http_status(403, "forbidden"),
            EvidenceProjection::AccessLost,
        ),
        (
            GcpCloudDeployTransportError::http_status(404, "not-found"),
            EvidenceProjection::Unknown,
        ),
        (
            GcpCloudDeployTransportError::http_status(409, "conflict"),
            EvidenceProjection::Partial,
        ),
        (
            GcpCloudDeployTransportError::http_status(429, "rate-limit"),
            EvidenceProjection::RateLimited,
        ),
        (
            GcpCloudDeployTransportError::http_status(500, "server"),
            EvidenceProjection::Partial,
        ),
        (
            GcpCloudDeployTransportError::timeout("timeout"),
            EvidenceProjection::Partial,
        ),
    ];
    for (error, expected) in cases {
        let scope = scope();
        let mut service = service_with(scope, vec![Err(error)]);
        let proposal = service.propose().expect("honest error proposal");
        assert_eq!(proposal.projection(), expected);
        assert!(proposal.release().is_none());
        assert!(proposal.evidence().error().is_some());
        assert!(proposal.validate_digest().is_ok());
    }
}

#[test]
fn partial_unknown_and_blocked_environment_never_become_connected() {
    let scope = scope();
    let mut partial = service_with(
        scope.clone(),
        vec![
            Ok(GcpCloudDeployResponse::Release(release(
                &scope,
                ReleasePhase::InProgress,
                ReleaseStatus::Running,
            ))),
            Ok(GcpCloudDeployResponse::Rollouts(
                RolloutPage::new(Vec::new(), None).expect("empty rollout page"),
            )),
        ],
    );
    let proposal = partial.propose().expect("partial proposal");
    assert_eq!(proposal.projection(), EvidenceProjection::Partial);
    assert!(!proposal.deployment_success_claimed());
    assert!(!GcpCloudDeployLayer1Authority::connected());
    assert!(!GcpCloudDeployLayer1Authority::native());

    let blocked_provider = GcpCloudDeployProvider::new(
        BlockedEnvGcpCloudDeployTransport,
        scope.clone(),
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let blocked_secret = secret(&scope);
    let mut blocked_service = GcpCloudDeployService::new(scope, blocked_secret, blocked_provider)
        .expect("blocked service");
    let blocked = blocked_service.propose().expect("blocked proposal");
    assert_eq!(blocked.projection(), EvidenceProjection::Unknown);
    assert_eq!(
        blocked.evidence().provenance(),
        ProviderProvenance::BlockedEnv
    );
    assert_eq!(
        blocked.evidence().error().map(|error| error.kind),
        Some(ProviderErrorKind::BlockedEnv)
    );
    assert!(!GcpCloudDeployLayer1Authority::connected());
    assert!(!GcpCloudDeployLayer1Authority::native());
}

#[test]
fn proposal_record_verify_is_digest_only_and_detects_tamper_and_revocation() {
    let scope = scope();
    let mut service = service_with(
        scope.clone(),
        complete_responses(
            &scope,
            ReleasePhase::Succeeded,
            ReleaseStatus::Succeeded,
            RolloutPhase::Succeeded,
            RolloutStatus::Succeeded,
            JobRunPhase::Succeeded,
            JobRunStatus::Succeeded,
        ),
    );
    let proposal = service.propose().expect("proposal");
    let record = service.record(&proposal).expect("record");
    assert!(record.validate_digest().is_ok());
    assert!(!record.connected());
    assert!(!record.native());
    assert!(!record.durable());
    let verified = service.verify(&record, &proposal).expect("verification");
    assert_eq!(verified.status(), VerificationStatus::Verified);
    assert!(verified.is_valid());

    let mut tampered_value = serde_json::to_value(&proposal).expect("proposal JSON");
    tampered_value["projection"] = json!("unknown");
    let tampered: GcpCloudDeployProposal =
        serde_json::from_value(tampered_value).expect("tampered proposal shape");
    let tampered_verification = service
        .verify(&record, &tampered)
        .expect("tamper verification");
    assert_eq!(tampered_verification.status(), VerificationStatus::Tampered);
    assert!(tampered_verification.is_tampered());

    service.revoke().expect("registration revocation");
    let revoked = service
        .verify(&record, &proposal)
        .expect("revocation verification");
    assert_eq!(revoked.status(), VerificationStatus::Revoked);
    assert!(revoked.is_revoked());
    assert!(service.propose().is_err());
}

#[test]
fn secret_revocation_blocks_reads_and_registration_revocation_is_reversible_evidence() {
    let first_scope = scope();
    let mut service = service_with(
        first_scope.clone(),
        vec![Err(GcpCloudDeployTransportError::timeout("not reached"))],
    );
    service.secret_mut().revoke().expect("secret revocation");
    assert_eq!(
        service.propose().expect_err("revoked secret"),
        GcpCloudDeployServiceError::SecretRevoked
    );

    let scope = scope();
    let provider = GcpCloudDeployProvider::new(
        RecordingGcpCloudDeployTransport::default(),
        scope.clone(),
        ProviderProvenance::Loopback,
    )
    .expect("provider");
    let mut service =
        GcpCloudDeployService::new(scope.clone(), secret(&scope), provider).expect("service");
    let registration_digest = service.registration().registration_digest().clone();
    let revocation = service.revoke().expect("registration revocation");
    assert_eq!(revocation.registration_digest(), &registration_digest);
    assert!(revocation.reversible());
    assert!(!service.registration().is_active());
}
