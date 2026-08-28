use hartevo_semgrep_security_result_plugin::{
    AdoptionDisposition, Digest, Finding, FindingLocation, FindingStatus, MissionScopeBinding,
    MissionSemgrepSecurityConsumer, ProjectSnapshot, Reachability, ReadLimits,
    RecordingDisposition, RecordingSemgrepTransport, RuleCategory, RuleMetadata, ScanSnapshot,
    ScanStatus, SecretReference, SecurityDecision, SecurityProjection, SemgrepApiVersion,
    SemgrepError, SemgrepFindingType, SemgrepPermission, SemgrepProvider,
    SemgrepSecurityReadRequest, SemgrepSecurityResultService, SemgrepSecurityScope,
    SemgrepTransportError, Severity, TransportKind,
};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OBSERVED_AT: u64 = 1_700_000_000;

fn mission() -> MissionScopeBinding {
    MissionScopeBinding::new(
        "project-01",
        "mission-01",
        "work-product-01",
        3,
        4,
        5,
        Digest::from_text("policy-revision-3"),
        Digest::from_text("consent-revision-4"),
    )
    .expect("mission")
}

fn repository() -> hartevo_semgrep_security_result_plugin::RepositoryIdentity {
    hartevo_semgrep_security_result_plugin::RepositoryIdentity::new(
        "github",
        "tangpingqingwa",
        "hartevo",
        "https://github.com/tangpingqingwa/hartevo",
    )
    .expect("repository")
}

fn permissions() -> [SemgrepPermission; 6] {
    [
        SemgrepPermission::OrganizationRead,
        SemgrepPermission::ProjectRead,
        SemgrepPermission::ScanRead,
        SemgrepPermission::FindingRead,
        SemgrepPermission::RuleRead,
        SemgrepPermission::SecretsRead,
    ]
}

fn scope(types: impl IntoIterator<Item = SemgrepFindingType>) -> SemgrepSecurityScope {
    SemgrepSecurityScope::new(
        SemgrepApiVersion::V1,
        "semgrep.dev",
        "org-01",
        "hartevo-org",
        "github/tangpingqingwa/hartevo",
        repository(),
        "refs/heads/main",
        "scan-01",
        COMMIT,
        Vec::<String>::new(),
        ["rule-sast".into(), "rule-secrets".into(), "rule-sca".into()],
        types,
        mission(),
        permissions(),
    )
    .expect("scope")
}

fn finding(
    scope: &SemgrepSecurityScope,
    id: &str,
    finding_type: SemgrepFindingType,
    status: FindingStatus,
    severity: Severity,
    rule_id: &str,
) -> Finding {
    Finding::for_scope(
        scope,
        id,
        finding_type,
        status,
        severity,
        rule_id,
        Digest::from_text(format!("path:{id}")),
        (finding_type == SemgrepFindingType::Sca).then_some(Reachability::Reachable),
    )
    .expect("finding")
}

fn queue_success(
    transport: &mut RecordingSemgrepTransport,
    scope: &SemgrepSecurityScope,
    findings: Vec<Finding>,
) {
    transport.push_project_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ProjectSnapshot::for_scope(scope).expect("project"),
        ),
    ));
    transport.push_scan_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ScanSnapshot::for_scope(scope, ScanStatus::Completed).expect("scan"),
        ),
    ));
    transport.push_findings_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPage::new(0, None, None, findings),
    ));
}

fn service(
    scope: SemgrepSecurityScope,
    transport: RecordingSemgrepTransport,
) -> SemgrepSecurityResultService<RecordingSemgrepTransport> {
    let secret = SecretReference::new("opaque-semgrep-api-token", &scope, 1).expect("secret");
    SemgrepSecurityResultService::new(SemgrepProvider::new(transport), scope, secret)
        .expect("service")
}

#[test]
fn definition_and_scope_are_layer1_read_proposal_recording_only() {
    let definition = SemgrepSecurityResultService::<RecordingSemgrepTransport>::definition();
    assert_eq!(definition.layer, 1);
    assert!(definition.read_only);
    assert!(definition.proposal_only);
    assert!(definition.recording_only);
    assert!(!definition.connected);
    assert!(!definition.native);
    assert!(!definition.first_party);
    for forbidden in [
        "triage_finding",
        "ignore_finding",
        "mutate_code",
        "write_pull_request",
        "write_jira",
        "export_raw_source",
        "export_unbounded_findings",
        "execute_tool",
        "adopt_kernel_outcome",
    ] {
        assert!(
            definition
                .forbidden_effects
                .iter()
                .any(|value| value == forbidden)
        );
    }

    let scope = scope([SemgrepFindingType::Sast]);
    assert!(scope.scope_digest().is_valid());
    assert!(scope.repository_digest().is_valid());
    assert!(scope.scan_digest().is_valid());
    assert!(scope.rule_digest().is_valid());
    let oidc = SecretReference::oidc("opaque-oidc-reference", &scope, 2).expect("OIDC secret");
    assert_eq!(
        oidc.kind(),
        hartevo_semgrep_security_result_plugin::SecretReferenceKind::Oidc
    );
    let debug = format!("{oidc:?}");
    assert!(!debug.contains("opaque-oidc-reference"));
    assert!(!debug.contains("fixture-token"));
}

#[test]
fn successful_evidence_proposal_recording_and_mission_replay_are_bound() {
    let scope = scope([SemgrepFindingType::Sast]);
    let statuses = [
        FindingStatus::Open,
        FindingStatus::Reviewing,
        FindingStatus::ToFix,
        FindingStatus::Fixed,
        FindingStatus::Ignored,
        FindingStatus::Removed,
        FindingStatus::ProvisionallyIgnored,
        FindingStatus::Unknown,
    ];
    let findings = statuses
        .into_iter()
        .enumerate()
        .map(|(index, status)| {
            finding(
                &scope,
                &format!("finding-{index}"),
                SemgrepFindingType::Sast,
                status,
                if index == 0 {
                    Severity::Critical
                } else {
                    Severity::Low
                },
                "rule-sast",
            )
        })
        .collect();
    let mut transport = RecordingSemgrepTransport::fixture();
    queue_success(&mut transport, &scope, findings);
    let mut service = service(scope.clone(), transport);
    let evidence = service
        .read_security_evidence(OBSERVED_AT)
        .expect("evidence");
    assert_eq!(evidence.findings.len(), 8);
    assert_eq!(evidence.pages_read, 1);
    assert_eq!(evidence.projection, SecurityProjection::FindingsPresent);
    assert_eq!(evidence.summary.high_risk_actionable, 1);
    assert_eq!(
        evidence.summary.by_status[&FindingStatus::ProvisionallyIgnored],
        1
    );
    assert!(evidence.provenance.recording_only);
    assert!(evidence.provenance.redacted);
    assert!(!evidence.provenance.connected);
    assert!(!evidence.provenance.native);
    assert!(!evidence.provenance.first_party);

    let proposal = service
        .compile_security_decision_proposal(&evidence)
        .expect("proposal");
    assert_eq!(proposal.decision, SecurityDecision::Block);
    assert_eq!(proposal.adoption, AdoptionDisposition::Layer2Required);
    assert!(proposal.redacted);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);

    let evidence_recording = service
        .record_security_receipt(&evidence)
        .expect("evidence recording");
    assert_eq!(evidence_recording.disposition, RecordingDisposition::Fresh);
    let evidence_replay = service
        .record_security_receipt(&evidence)
        .expect("evidence replay");
    assert_eq!(evidence_replay.disposition, RecordingDisposition::Replay);
    let proposal_recording = service
        .record_security_receipt(&proposal)
        .expect("proposal recording");
    assert_eq!(proposal_recording.disposition, RecordingDisposition::Fresh);
    assert!(!proposal_recording.durable);
    assert!(!proposal_recording.connected);
    assert!(!proposal_recording.native);
    assert!(!proposal_recording.first_party);

    let mut consumer = MissionSemgrepSecurityConsumer::new(&scope).expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert_eq!(result.mission_id, "mission-01");
    assert_eq!(result.work_product_id, "work-product-01");
    assert!(!result.adopted);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    let replay = consumer.consume(&proposal).expect("mission replay");
    assert_eq!(
        replay.disposition,
        hartevo_semgrep_security_result_plugin::MissionConsumptionDisposition::Replay
    );

    let serialized = serde_json::to_string(&proposal_recording).expect("recording JSON");
    assert!(!serialized.contains("opaque-semgrep-api-token"));
    assert!(!serialized.contains("fixture-token"));
    assert!(!serialized.contains("source_excerpt"));
    assert!(!serialized.contains("raw_source"));
}

#[test]
fn categories_reachability_and_rule_metadata_are_separated() {
    let scope = scope([
        SemgrepFindingType::Sast,
        SemgrepFindingType::Secrets,
        SemgrepFindingType::Sca,
    ]);
    let mut transport = RecordingSemgrepTransport::fixture();
    transport.push_project_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ProjectSnapshot::for_scope(&scope).expect("project"),
        ),
    ));
    transport.push_scan_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ScanSnapshot::for_scope(&scope, ScanStatus::Completed).expect("scan"),
        ),
    ));
    for (index, (kind, rule)) in [
        (SemgrepFindingType::Sast, "rule-sast"),
        (SemgrepFindingType::Secrets, "rule-secrets"),
        (SemgrepFindingType::Sca, "rule-sca"),
    ]
    .into_iter()
    .enumerate()
    {
        transport.push_findings_response(Ok(
            hartevo_semgrep_security_result_plugin::SemgrepPage::new(
                0,
                None,
                None,
                vec![finding(
                    &scope,
                    &format!("category-{index}"),
                    kind,
                    FindingStatus::Open,
                    Severity::Medium,
                    rule,
                )],
            ),
        ));
    }
    let mut service = service(scope, transport);
    let request =
        SemgrepSecurityReadRequest::for_scope(service.scope(), OBSERVED_AT).expect("request");
    let evidence = service
        .read_security_evidence(request)
        .expect("category evidence");
    assert_eq!(evidence.summary.total_findings, 3);
    assert_eq!(evidence.summary.by_type[&SemgrepFindingType::Sast], 1);
    assert_eq!(evidence.summary.by_type[&SemgrepFindingType::Secrets], 1);
    assert_eq!(evidence.summary.by_type[&SemgrepFindingType::Sca], 1);
    assert_eq!(
        evidence.findings[1].secret_validation,
        Some(hartevo_semgrep_security_result_plugin::SecretValidationState::Unknown)
    );
    assert_eq!(
        evidence.findings[2].reachability,
        Some(Reachability::Reachable)
    );
    assert_eq!(evidence.findings[0].rule.category, RuleCategory::Security);
    assert_eq!(evidence.findings[1].rule.category, RuleCategory::Secrets);
    assert_eq!(
        evidence.findings[2].rule.category,
        RuleCategory::SupplyChain
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn pagination_duplicate_and_boundaries_fail_closed() {
    let scope = scope([SemgrepFindingType::Sast]);
    let first = finding(
        &scope,
        "finding-page-1",
        SemgrepFindingType::Sast,
        FindingStatus::Open,
        Severity::Low,
        "rule-sast",
    );
    let second = finding(
        &scope,
        "finding-page-2",
        SemgrepFindingType::Sast,
        FindingStatus::Fixed,
        Severity::Low,
        "rule-sast",
    );
    let mut paged = RecordingSemgrepTransport::fixture();
    paged.push_project_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ProjectSnapshot::for_scope(&scope).expect("project"),
        ),
    ));
    paged.push_scan_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ScanSnapshot::for_scope(&scope, ScanStatus::Completed).expect("scan"),
        ),
    ));
    paged.push_findings_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPage::new(
            0,
            None,
            None,
            vec![first.clone()],
        )
        .with_next_page(Some(1)),
    ));
    paged.push_findings_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPage::new(1, None, None, vec![second]),
    ));
    let mut paged_service = service(scope.clone(), paged);
    let evidence = paged_service
        .read_security_evidence(OBSERVED_AT)
        .expect("paged evidence");
    assert_eq!(evidence.pages_read, 2);

    let mut duplicate = RecordingSemgrepTransport::fixture();
    duplicate.push_project_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ProjectSnapshot::for_scope(&scope).expect("project"),
        ),
    ));
    duplicate.push_scan_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ScanSnapshot::for_scope(&scope, ScanStatus::Completed).expect("scan"),
        ),
    ));
    duplicate.push_findings_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPage::new(
            0,
            None,
            None,
            vec![first.clone()],
        )
        .with_next_page(Some(1)),
    ));
    duplicate.push_findings_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPage::new(1, None, None, vec![first]),
    ));
    let mut duplicate_service = service(scope.clone(), duplicate);
    assert_eq!(
        duplicate_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::DuplicateFinding)
    );

    let mut repeated_cursor = RecordingSemgrepTransport::fixture();
    repeated_cursor.push_project_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ProjectSnapshot::for_scope(&scope).expect("project"),
        ),
    ));
    repeated_cursor.push_scan_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ScanSnapshot::for_scope(&scope, ScanStatus::Completed).expect("scan"),
        ),
    ));
    repeated_cursor.push_findings_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPage::new(
            0,
            None,
            Some("cursor-1".into()),
            vec![finding(
                &scope,
                "cursor-1-finding",
                SemgrepFindingType::Sast,
                FindingStatus::Open,
                Severity::Low,
                "rule-sast",
            )],
        ),
    ));
    repeated_cursor.push_findings_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPage::new(
            1,
            Some("cursor-1".into()),
            Some("cursor-1".into()),
            vec![finding(
                &scope,
                "cursor-2-finding",
                SemgrepFindingType::Sast,
                FindingStatus::Open,
                Severity::Low,
                "rule-sast",
            )],
        ),
    ));
    let mut repeated_service = service(scope.clone(), repeated_cursor);
    assert_eq!(
        repeated_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::PaginationRepeatedCursor)
    );

    let mut limited = RecordingSemgrepTransport::fixture();
    queue_success(&mut limited, &scope, vec![]);
    let limited_provider = SemgrepProvider::with_limits(
        limited,
        ReadLimits {
            max_response_bytes: 10,
            max_page_items: 1,
            max_pages: 1,
            max_total_findings: 1,
        },
    )
    .expect("limits");
    let secret = SecretReference::new("limited", &scope, 1).expect("secret");
    let mut limited_service = SemgrepSecurityResultService::new(limited_provider, scope, secret)
        .expect("limited service");
    assert_eq!(
        limited_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::ResponseTooLarge)
    );
}

#[test]
fn drift_tamper_redaction_truncation_access_loss_and_http_errors_are_explicit() {
    let scope = scope([SemgrepFindingType::Sast]);
    let mut drift_transport = RecordingSemgrepTransport::fixture();
    drift_transport.push_project_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ProjectSnapshot::new(
                scope.organization_id.clone(),
                scope.organization_slug.clone(),
                scope.project_id.clone(),
                scope.repository.clone(),
                "refs/heads/other",
                scope.commit_sha.clone(),
                scope.permissions.clone(),
                scope.mission.project_revision,
            )
            .expect("drifted project"),
        ),
    ));
    let mut drift_service = service(scope.clone(), drift_transport);
    assert_eq!(
        drift_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::RefMismatch)
    );

    let mut tampered = RecordingSemgrepTransport::fixture();
    tampered.push_project_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ProjectSnapshot::for_scope(&scope).expect("project"),
        )
        .with_metadata(128, Digest::from_text("wrong-payload-digest"), true, false),
    ));
    let mut tampered_service = service(scope.clone(), tampered);
    assert_eq!(
        tampered_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::PayloadTampered)
    );

    let mut unredacted = RecordingSemgrepTransport::fixture();
    let mut project_payload = hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
        ProjectSnapshot::for_scope(&scope).expect("project"),
    );
    project_payload.redacted = false;
    unredacted.push_project_response(Ok(project_payload));
    let mut unredacted_service = service(scope.clone(), unredacted);
    assert_eq!(
        unredacted_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::PayloadNotRedacted)
    );

    let mut truncated = RecordingSemgrepTransport::fixture();
    let mut project_payload = hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
        ProjectSnapshot::for_scope(&scope).expect("project"),
    );
    project_payload.truncated = true;
    truncated.push_project_response(Ok(project_payload));
    let mut truncated_service = service(scope.clone(), truncated);
    assert_eq!(
        truncated_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::PayloadTruncated)
    );

    let cases = [
        (401, SecurityProjection::AccessLoss),
        (403, SecurityProjection::AccessLoss),
        (404, SecurityProjection::ProviderUnknown),
        (409, SecurityProjection::ProviderUnknown),
        (429, SecurityProjection::ProviderUnknown),
        (500, SecurityProjection::ProviderUnknown),
        (503, SecurityProjection::ProviderUnknown),
    ];
    for (status, projection) in cases {
        let mut transport = RecordingSemgrepTransport::fixture();
        transport.fail_with(SemgrepTransportError::HttpStatus {
            status,
            retry_after_seconds: (status == 429).then_some(3),
        });
        let mut current_service = service(scope.clone(), transport);
        let error = current_service
            .read_security_evidence(OBSERVED_AT)
            .expect_err("HTTP error");
        assert_eq!(error.status(), Some(status));
        assert_eq!(current_service.projection_for_error(&error), projection);
    }
    let mut timeout = RecordingSemgrepTransport::fixture();
    timeout.fail_with(SemgrepTransportError::Timeout);
    let mut timeout_service = service(scope.clone(), timeout);
    assert_eq!(
        timeout_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::Timeout)
    );
    let mut blocked = service(scope.clone(), RecordingSemgrepTransport::blocked_env());
    assert_eq!(
        blocked.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::BlockedEnv)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn scan_commit_rule_mission_revision_and_registration_lifecycle_fail_closed() {
    let scope = scope([SemgrepFindingType::Sast]);

    let mut scan_drift = RecordingSemgrepTransport::fixture();
    scan_drift.push_project_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ProjectSnapshot::for_scope(&scope).expect("project"),
        ),
    ));
    let scan = ScanSnapshot::new(
        scope.scan_id.clone(),
        scope.project_id.clone(),
        scope.repository.clone(),
        scope.git_ref.clone(),
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        scope.rule_revision_digest.clone(),
        scope.finding_types.clone(),
        ScanStatus::Completed,
    )
    .expect("drifted scan");
    scan_drift.push_scan_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(scan),
    ));
    let mut scan_service = service(scope.clone(), scan_drift);
    assert_eq!(
        scan_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::CommitMismatch)
    );

    let mut rule_drift = RecordingSemgrepTransport::fixture();
    rule_drift.push_project_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ProjectSnapshot::for_scope(&scope).expect("project"),
        ),
    ));
    rule_drift.push_scan_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
            ScanSnapshot::for_scope(&scope, ScanStatus::Completed).expect("scan"),
        ),
    ));
    let mut rule =
        RuleMetadata::for_scope(&scope, "rule-sast", RuleCategory::Security, Severity::Low)
            .expect("rule");
    rule.revision_digest = Digest::from_text("new-rule-revision");
    rule_drift.push_findings_response(Ok(
        hartevo_semgrep_security_result_plugin::SemgrepPage::new(
            0,
            None,
            None,
            vec![
                Finding::new(
                    "rule-drift-finding",
                    SemgrepFindingType::Sast,
                    FindingStatus::Open,
                    Severity::Low,
                    scope.repository.clone(),
                    scope.git_ref.clone(),
                    scope.scan_id.clone(),
                    scope.commit_sha.clone(),
                    rule,
                    FindingLocation::new(Digest::from_text("path"), 1, 1).expect("location"),
                    None,
                    None,
                    Digest::from_text("fingerprint"),
                )
                .expect("finding"),
            ],
        ),
    ));
    let mut rule_service = service(scope.clone(), rule_drift);
    assert_eq!(
        rule_service.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::RuleMismatch)
    );

    let mut good_transport = RecordingSemgrepTransport::fixture();
    queue_success(
        &mut good_transport,
        &scope,
        vec![finding(
            &scope,
            "mission-finding",
            SemgrepFindingType::Sast,
            FindingStatus::Ignored,
            Severity::Low,
            "rule-sast",
        )],
    );
    let mut good_service = service(scope.clone(), good_transport);
    let evidence = good_service
        .read_security_evidence(OBSERVED_AT)
        .expect("evidence");
    let mut proposal = good_service
        .compile_security_decision_proposal(&evidence)
        .expect("proposal");
    let mut tampered_proposal = proposal.clone();
    tampered_proposal.decision = SecurityDecision::Block;
    let mut tamper_consumer = MissionSemgrepSecurityConsumer::new(&scope).expect("consumer");
    assert_eq!(
        tamper_consumer.consume(&tampered_proposal),
        Err(SemgrepError::ProposalTampered)
    );
    proposal.mission.mission_revision += 1;
    proposal.proposal_digest = proposal.compute_digest();
    let mut consumer = MissionSemgrepSecurityConsumer::new(&scope).expect("consumer");
    assert_eq!(
        consumer.consume(&proposal),
        Err(SemgrepError::StaleMissionRevision)
    );
    consumer.unmount();
    assert_eq!(
        consumer.consume(
            &good_service
                .compile_security_decision_proposal(&evidence)
                .expect("fresh proposal")
        ),
        Err(SemgrepError::ConsumerInactive)
    );

    let mut lifecycle_transport = RecordingSemgrepTransport::fixture();
    queue_success(&mut lifecycle_transport, &scope, vec![]);
    let mut lifecycle = service(scope, lifecycle_transport);
    lifecycle.unmount().expect("unmount");
    assert_eq!(
        lifecycle.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::RegistrationInactive)
    );
    lifecycle.remount().expect("remount");
    lifecycle
        .read_security_evidence(OBSERVED_AT)
        .expect("remounted read");
    let revoked = lifecycle.revoke();
    assert_eq!(
        revoked.status,
        hartevo_semgrep_security_result_plugin::RegistrationStatus::Revoked
    );
    assert!(!revoked.connected);
    assert!(!revoked.native);
    assert!(!revoked.first_party);
    assert_eq!(
        lifecycle.read_security_evidence(OBSERVED_AT),
        Err(SemgrepError::RegistrationRevoked)
    );
}

#[test]
fn all_non_native_transport_kinds_keep_honesty_flags() {
    let scope = scope([SemgrepFindingType::Sast]);
    for kind in [
        TransportKind::Fixture,
        TransportKind::Recording,
        TransportKind::Fake,
        TransportKind::Loopback,
        TransportKind::BlockedEnv,
    ] {
        let mut transport = RecordingSemgrepTransport::new(kind).expect("transport");
        transport.push_project_response(Ok(
            hartevo_semgrep_security_result_plugin::SemgrepPayload::new(
                ProjectSnapshot::for_scope(&scope).expect("project"),
            ),
        ));
        let secret = SecretReference::new("transport-secret", &scope, 1).expect("secret");
        let mut provider = SemgrepProvider::new(transport);
        let _ = provider.describe_project(&scope, &secret);
        assert!(
            provider
                .transport()
                .requests()
                .iter()
                .all(|request| !request.connected && !request.native && !request.first_party)
        );
    }
}

#[test]
fn custom_limits_are_bounded() {
    let valid = ReadLimits::default();
    assert_eq!(
        SemgrepProvider::with_limits(RecordingSemgrepTransport::fixture(), valid)
            .expect("valid limits")
            .limits(),
        valid
    );
    assert_eq!(
        SemgrepProvider::with_limits(
            RecordingSemgrepTransport::fixture(),
            ReadLimits {
                max_response_bytes: 0,
                max_page_items: 1,
                max_pages: 1,
                max_total_findings: 1,
            },
        )
        .expect_err("invalid limits")
        .to_string(),
        "Semgrep read limits are invalid"
    );
}
