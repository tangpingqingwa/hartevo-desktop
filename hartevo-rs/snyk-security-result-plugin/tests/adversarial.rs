use hartevo_snyk_security_result_plugin::{
    BlockedEnvTransport, CommitIdentity, Evidence, FakeTransport, FindingStatus, FixMetadata,
    GroupIdentity, IaCSeverity, IacEvidence, LicenseEvidence, LicenseRisk, LoopbackTransport,
    MissionSnykSecurityConsumer, OrganizationIdentity, PackageIdentity, PathIdentity,
    PermissionSnapshot, ProjectContextIdentity, ProjectIdentity, ProjectSnapshotReadRequest,
    ProjectSnapshotResponse, ProjectionCompleteness, ProviderIdentity, RecordingTransport,
    RegionIdentity, RegistrationId, RegistrationStatus, SecretReference, Severity,
    SnapshotIdentity, SnykProvider, SnykProviderError, SnykRegistration, SnykRegistrationRegistry,
    SnykScope, SnykSecurityResultError, SnykSecurityResultService, SnykTransport,
    SnykTransportError, TargetIdentity, TransportProvenance, VulnerabilityEvidence,
    WorkProductIdentity,
};

fn scope() -> SnykScope {
    SnykScope::new(
        RegionIdentity::new("us", "https://api.snyk.io", 1).expect("region"),
        OrganizationIdentity::new("org-snyk-1", 1).expect("organization"),
        GroupIdentity::new("group-snyk-1", 1).expect("group"),
        TargetIdentity::new("target-snyk-1", 1).expect("target"),
        ProjectIdentity::new("project-snyk-1", 1).expect("Snyk project"),
        SnapshotIdentity::new("snapshot-snyk-1", 1).expect("snapshot"),
        hartevo_snyk_security_result_plugin::IssueIdentity::new("issue-snyk-1", 1).expect("issue"),
        PackageIdentity::new("package-snyk-1", 1).expect("package"),
        PathIdentity::new("path-snyk-1", 1).expect("path"),
        CommitIdentity::new("commit-snyk-1", 1).expect("commit"),
        hartevo_snyk_security_result_plugin::MissionIdentity::new("mission-snyk-1", 1)
            .expect("Mission"),
        ProjectContextIdentity::new("project-hartevo-1", 1).expect("Project"),
        WorkProductIdentity::new("work-product-snyk-1", 1).expect("Work Product"),
    )
    .expect("scope")
}

fn registration(scope: SnykScope) -> SnykRegistration {
    SnykRegistration::new(
        RegistrationId::new("registration-snyk-1").expect("registration id"),
        scope,
        SecretReference::api_token("opaque-api-token-handle", 1).expect("API token ref"),
        PermissionSnapshot::read_only(1).expect("permissions"),
        ProviderIdentity::new(1, "snyk-layer1-recording-1").expect("provider"),
        1,
    )
    .expect("registration")
}

fn vulnerability(scope: &SnykScope, status: FindingStatus) -> VulnerabilityEvidence {
    VulnerabilityEvidence::new(
        scope.issue.id.clone(),
        scope.package.id.clone(),
        scope.path.id.clone(),
        scope.commit.id.clone(),
        "SNYK-JAVA-EXAMPLE-1",
        "redacted vulnerability title",
        Severity::High,
        status,
        FixMetadata::available("2.0.0", "upgrade-package"),
    )
    .expect("vulnerability")
}

fn response(scope: &SnykScope, evidence: Vec<Evidence>) -> ProjectSnapshotResponse {
    ProjectSnapshotResponse::with_evidence(scope, evidence, TransportProvenance::Fake)
}

#[test]
fn contract_and_capabilities_are_layer_one_read_only() {
    let scope = scope();
    let service = SnykSecurityResultService::new(
        registration(scope.clone()),
        FakeTransport::new(ProjectSnapshotResponse::for_scope(
            &scope,
            TransportProvenance::Fake,
        )),
    )
    .expect("service");
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.can_ignore);
    assert!(!capabilities.can_remediate);
    assert!(!capabilities.can_import_project);
    assert!(!capabilities.can_delete_project);
    assert!(!capabilities.can_export_source);
    assert!(!capabilities.can_retain_dependency_graph);
    assert!(!capabilities.can_adopt_outcome);
    assert_eq!(
        hartevo_snyk_security_result_plugin::contract_digest(),
        hartevo_snyk_security_result_plugin::CONTRACT_DIGEST
    );
}

#[test]
fn opaque_api_token_and_oauth_references_never_debug_raw_material() {
    let api = SecretReference::api_token("raw-api-token-must-not-leak", 1).expect("API token");
    let oauth = SecretReference::oauth("raw-oauth-handle-must-not-leak", 2).expect("OAuth");
    assert!(!format!("{api:?}").contains("raw-api-token-must-not-leak"));
    assert!(!format!("{oauth:?}").contains("raw-oauth-handle-must-not-leak"));
    assert_eq!(
        api.kind(),
        hartevo_snyk_security_result_plugin::SecretKind::ApiToken
    );
    assert_eq!(
        oauth.kind(),
        hartevo_snyk_security_result_plugin::SecretKind::OAuth
    );
}

#[test]
fn all_finding_statuses_and_allowlisted_evidence_are_projected() {
    for status in [
        FindingStatus::Open,
        FindingStatus::Fixed,
        FindingStatus::Ignored,
        FindingStatus::Introduced,
        FindingStatus::Unknown,
    ] {
        let expected = scope();
        let evidence = vec![
            Evidence::Vulnerability(vulnerability(&expected, status)),
            Evidence::License(
                LicenseEvidence::new(
                    expected.issue.id.clone(),
                    expected.package.id.clone(),
                    expected.path.id.clone(),
                    expected.commit.id.clone(),
                    "MIT",
                    "MIT License",
                    LicenseRisk::Low,
                    status,
                )
                .expect("license"),
            ),
            Evidence::Iac(
                IacEvidence::new(
                    expected.issue.id.clone(),
                    expected.path.id.clone(),
                    expected.commit.id.clone(),
                    "CKV_EXAMPLE_1",
                    "aws_instance",
                    "redacted IaC message",
                    IaCSeverity::Medium,
                    status,
                    FixMetadata::unavailable(),
                )
                .expect("IaC"),
            ),
        ];
        let mut provider = SnykProvider::new(
            registration(expected.clone()),
            FakeTransport::new(response(&expected, evidence)),
        )
        .expect("provider");
        let projection = provider
            .read_project_snapshot("status-matrix")
            .expect("projection");
        assert_eq!(projection.vulnerability_count(), 1);
        assert_eq!(projection.license_count(), 1);
        assert_eq!(projection.iac_count(), 1);
        assert!(projection.is_complete());
        assert!(!projection.connected);
        assert!(!projection.native);
        assert!(!projection.raw_dependency_graph_retained);
        assert!(!projection.arbitrary_source_export);
    }
}

#[test]
fn every_exact_scope_component_drift_fails_closed() {
    let expected = scope();
    let cases = [
        ("region", SnykProviderError::RegionDrift),
        ("organization", SnykProviderError::OrganizationDrift),
        ("group", SnykProviderError::GroupDrift),
        ("target", SnykProviderError::TargetDrift),
        ("project", SnykProviderError::ProjectDrift),
        ("snapshot", SnykProviderError::SnapshotDrift),
        ("issue", SnykProviderError::IssueDrift),
        ("package", SnykProviderError::PackageDrift),
        ("path", SnykProviderError::PathDrift),
        ("commit", SnykProviderError::CommitDrift),
        ("mission", SnykProviderError::MissionDrift),
        ("project-context", SnykProviderError::ProjectContextDrift),
        ("work-product", SnykProviderError::WorkProductDrift),
    ];
    for (component, expected_error) in cases {
        let mut drifted = expected.clone();
        match component {
            "region" => {
                drifted.region = RegionIdentity::new("eu", "https://api.eu.snyk.io", 2).unwrap();
            }
            "organization" => {
                drifted.organization = OrganizationIdentity::new("org-drift", 2).unwrap();
            }
            "group" => drifted.group = GroupIdentity::new("group-drift", 2).unwrap(),
            "target" => drifted.target = TargetIdentity::new("target-drift", 2).unwrap(),
            "project" => drifted.project = ProjectIdentity::new("project-drift", 2).unwrap(),
            "snapshot" => drifted.snapshot = SnapshotIdentity::new("snapshot-drift", 2).unwrap(),
            "issue" => {
                drifted.issue =
                    hartevo_snyk_security_result_plugin::IssueIdentity::new("issue-drift", 2)
                        .unwrap();
            }
            "package" => drifted.package = PackageIdentity::new("package-drift", 2).unwrap(),
            "path" => drifted.path = PathIdentity::new("path-drift", 2).unwrap(),
            "commit" => drifted.commit = CommitIdentity::new("commit-drift", 2).unwrap(),
            "mission" => {
                drifted.mission =
                    hartevo_snyk_security_result_plugin::MissionIdentity::new("mission-drift", 2)
                        .unwrap();
            }
            "project-context" => {
                drifted.hartevo_project =
                    ProjectContextIdentity::new("project-context-drift", 2).unwrap();
            }
            "work-product" => {
                drifted.work_product = WorkProductIdentity::new("work-product-drift", 2).unwrap();
            }
            _ => unreachable!(),
        }
        let mut provider = SnykProvider::new(
            registration(expected.clone()),
            FakeTransport::new(ProjectSnapshotResponse::for_scope(
                &drifted,
                TransportProvenance::Fake,
            )),
        )
        .expect("provider");
        assert_eq!(
            provider.read_project_snapshot(component).unwrap_err(),
            expected_error
        );
    }
}

#[test]
fn stale_mission_revision_is_not_accepted_by_consumer() {
    let expected = scope();
    let mut stale = expected.clone();
    stale.mission =
        hartevo_snyk_security_result_plugin::MissionIdentity::new(expected.mission.id.as_str(), 2)
            .expect("stale Mission");
    let mut provider = SnykProvider::new(
        registration(expected.clone()),
        FakeTransport::new(ProjectSnapshotResponse::for_scope(
            &stale,
            TransportProvenance::Fake,
        )),
    )
    .expect("provider");
    assert_eq!(
        provider.read_project_snapshot("stale-mission").unwrap_err(),
        SnykProviderError::MissionDrift
    );

    let mut good_provider = SnykProvider::new(
        registration(expected.clone()),
        FakeTransport::new(ProjectSnapshotResponse::for_scope(
            &expected,
            TransportProvenance::Fake,
        )),
    )
    .expect("provider");
    let projection = good_provider
        .read_project_snapshot("good-mission")
        .expect("projection");
    let consumer = MissionSnykSecurityConsumer::new(stale);
    assert_eq!(
        consumer
            .compile_proposal(&projection, "stale-proposal")
            .unwrap_err(),
        SnykSecurityResultError::ScopeMismatch
    );
}

#[test]
fn bounded_pagination_detects_replay_and_limit() {
    let expected = scope();
    let repeated = ProjectSnapshotResponse::for_scope(&expected, TransportProvenance::Fake)
        .with_next_page_token("same-page-token");
    let mut repeated_provider =
        SnykProvider::new(registration(expected.clone()), FakeTransport::new(repeated))
            .expect("provider");
    assert_eq!(
        repeated_provider
            .read_project_snapshot("repeat")
            .unwrap_err(),
        SnykProviderError::PaginationLoop
    );

    let mut endless_provider = SnykProvider::new(
        registration(expected.clone()),
        EndlessTransport {
            scope: expected.clone(),
            page: 0,
        },
    )
    .expect("provider");
    assert_eq!(
        endless_provider.read_project_snapshot("limit").unwrap_err(),
        SnykProviderError::PaginationLimit
    );
}

#[derive(Clone, Debug)]
struct EndlessTransport {
    scope: SnykScope,
    page: usize,
}

impl SnykTransport for EndlessTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn read_project_snapshot(
        &mut self,
        request: &ProjectSnapshotReadRequest,
    ) -> std::result::Result<ProjectSnapshotResponse, SnykTransportError> {
        self.page += 1;
        let mut response = ProjectSnapshotResponse::for_scope(&self.scope, self.provenance());
        response.request_page_token.clone_from(&request.page_token);
        response.next_page_token = Some(format!("page-{}", self.page));
        Ok(response)
    }
}

#[test]
fn transport_http_classes_and_blocked_environment_are_finite() {
    let errors = [
        SnykTransportError::Unauthorized401,
        SnykTransportError::Forbidden403,
        SnykTransportError::NotFound404,
        SnykTransportError::Conflict409,
        SnykTransportError::RateLimited429,
        SnykTransportError::Timeout,
        SnykTransportError::Server5xx { status: 503 },
        SnykTransportError::AccessLost,
    ];
    for error in errors {
        let expected = scope();
        let mut provider = SnykProvider::new(
            registration(expected.clone()),
            FakeTransport::new(ProjectSnapshotResponse::for_scope(
                &expected,
                TransportProvenance::Fake,
            ))
            .with_error(error.clone()),
        )
        .expect("provider");
        assert_eq!(
            provider.read_project_snapshot("transport").unwrap_err(),
            SnykProviderError::Transport(error)
        );
    }

    let expected = scope();
    let mut blocked = SnykProvider::new(registration(expected), BlockedEnvTransport::new())
        .expect("blocked provider");
    assert_eq!(
        blocked.read_project_snapshot("blocked").unwrap_err(),
        SnykProviderError::Transport(SnykTransportError::EnvironmentBlocked)
    );
}

#[test]
fn recording_fake_and_loopback_are_non_native_and_recording_is_bounded() {
    let expected = scope();
    let fixture = ProjectSnapshotResponse::for_scope(&expected, TransportProvenance::Fake);
    let mut recording = SnykProvider::new(
        registration(expected.clone()),
        RecordingTransport::new(fixture.clone()),
    )
    .expect("recording provider");
    let recording_projection = recording
        .read_project_snapshot("recording")
        .expect("projection");
    assert_eq!(
        recording_projection.provenance,
        TransportProvenance::Recording
    );
    assert!(!recording_projection.provenance.is_native());
    assert!(!recording_projection.provenance.claims_connected());
    assert_eq!(recording.transport().request_count(), 1);

    let mut loopback = SnykProvider::new(registration(expected), LoopbackTransport::new(fixture))
        .expect("loopback provider");
    let projection = loopback
        .read_project_snapshot("loopback")
        .expect("projection");
    assert_eq!(projection.provenance, TransportProvenance::Loopback);
    assert!(!projection.connected);
    assert!(!projection.native);
}

#[test]
fn tamper_redaction_and_truncation_fail_or_remain_review_only() {
    let expected = scope();
    let mut provider = SnykProvider::new(
        registration(expected.clone()),
        FakeTransport::new(
            ProjectSnapshotResponse::for_scope(&expected, TransportProvenance::Fake)
                .with_truncated(true),
        ),
    )
    .expect("provider");
    let projection = provider
        .read_project_snapshot("truncated")
        .expect("projection");
    assert_eq!(projection.completeness, ProjectionCompleteness::Truncated);
    assert!(projection.response_truncated);
    let consumer = MissionSnykSecurityConsumer::new(expected.clone());
    let proposal = consumer
        .compile_proposal(&projection, "truncated-key")
        .expect("proposal");
    assert_eq!(
        proposal.disposition,
        hartevo_snyk_security_result_plugin::ProposalDisposition::Truncated
    );
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());

    let mut tampered = projection.clone();
    tampered.connected = true;
    assert_eq!(
        tampered.validate_integrity().unwrap_err(),
        SnykSecurityResultError::TamperedEvidence
    );

    let rawish: VulnerabilityEvidence = serde_json::from_value(serde_json::json!({
        "issueId": "issue-snyk-1",
        "packageId": "package-snyk-1",
        "pathId": "path-snyk-1",
        "commitId": "commit-snyk-1",
        "vulnerabilityId": "SNYK-JAVA-EXAMPLE-1",
        "titleDigest": "not-a-digest",
        "severity": "high",
        "status": "open",
        "fix": { "availability": "unavailable", "fixedVersionDigest": null, "remediationPathDigest": null }
    }))
    .expect("fixture deserializes before validation");
    let mut redaction_provider = SnykProvider::new(
        registration(scope()),
        FakeTransport::new(response(&scope(), vec![Evidence::Vulnerability(rawish)])),
    )
    .expect("provider");
    assert_eq!(
        redaction_provider
            .read_project_snapshot("redaction")
            .unwrap_err(),
        SnykProviderError::TamperedEvidence
    );
}

#[test]
fn registration_is_reversible_duplicate_safe_and_secret_revocation_blocks_provider() {
    let expected = scope();
    let original = registration(expected.clone());
    let mut registry = SnykRegistrationRegistry::default();
    registry.register(original.clone()).expect("register");
    assert_eq!(
        registry.register(original.clone()).unwrap_err(),
        SnykSecurityResultError::RegistrationAlreadyExists
    );
    let id = original.id().clone();
    registry.revoke(&id).expect("revoke");
    assert_eq!(
        registry.get(&id).expect("registration").status(),
        RegistrationStatus::Revoked
    );
    registry.restore(&id).expect("restore");
    registry.reverse(&id).expect("reverse");
    assert_eq!(
        registry.get(&id).expect("registration").status(),
        RegistrationStatus::Reversed
    );

    let mut revoked_registration = registration(expected.clone());
    revoked_registration.revoke().expect("revoke registration");
    assert_eq!(
        SnykProvider::new(
            revoked_registration,
            FakeTransport::new(ProjectSnapshotResponse::for_scope(
                &expected,
                TransportProvenance::Fake,
            )),
        )
        .unwrap_err(),
        SnykProviderError::RegistrationRevoked
    );

    let mut revoked_secret_registration = registration(expected.clone());
    revoked_secret_registration.revoke_secret_reference();
    assert_eq!(
        SnykProvider::new(
            revoked_secret_registration,
            FakeTransport::new(ProjectSnapshotResponse::for_scope(
                &expected,
                TransportProvenance::Fake,
            )),
        )
        .unwrap_err(),
        SnykProviderError::SecretRevoked
    );
}

#[test]
fn replay_and_idempotency_conflict_are_detected_without_outcome_adoption() {
    let expected = scope();
    let mut first_provider = SnykProvider::new(
        registration(expected.clone()),
        FakeTransport::new(response(
            &expected,
            vec![Evidence::Vulnerability(vulnerability(
                &expected,
                FindingStatus::Open,
            ))],
        )),
    )
    .expect("first provider");
    let first_projection = first_provider
        .read_project_snapshot("first")
        .expect("projection");
    let consumer = MissionSnykSecurityConsumer::new(expected.clone());
    let first = consumer
        .compile_proposal(&first_projection, "same-idempotency")
        .expect("proposal");
    let mut log = hartevo_snyk_security_result_plugin::SecurityResultRecordingLog::default();
    let recorded = consumer.record(&first, &mut log).expect("recording");
    assert!(!recorded.replayed);
    assert!(!recorded.provider_receipt);
    assert!(!recorded.outcome_adopted);
    let replay = consumer.record(&first, &mut log).expect("replay");
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);

    let mut second_provider = SnykProvider::new(
        registration(expected.clone()),
        FakeTransport::new(response(
            &expected,
            vec![Evidence::Vulnerability(vulnerability(
                &expected,
                FindingStatus::Fixed,
            ))],
        )),
    )
    .expect("second provider");
    let second_projection = second_provider
        .read_project_snapshot("second")
        .expect("projection");
    let second = consumer
        .compile_proposal(&second_projection, "same-idempotency")
        .expect("proposal");
    assert_eq!(
        consumer.record(&second, &mut log).unwrap_err(),
        SnykSecurityResultError::ReplayConflict
    );
}
