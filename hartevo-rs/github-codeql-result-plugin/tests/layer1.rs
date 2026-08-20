use std::collections::BTreeSet;

use hartevo_github_codeql_result_plugin::{
    AlertPage, AlertRecord, AlertSeverity, AlertState, AnalysisPage, AnalysisRecord,
    AnalysisStatus, CodeScanningTool, CommitSha, FixtureTransport, GithubAuthKind,
    GithubCodeScanningProvider, GithubCodeqlResultService, GithubCodeqlScope,
    MissionCodeqlDecisionState, MissionGithubCodeqlConsumer, MissionId, MissionScopeBinding,
    Permission, PermissionSnapshot, ProjectId, ProjectionState, ProviderProvenance, ReadLimits,
    ReadScript, RecordingTransport, RedactedLocation, RefName, RepositoryIdentity, Revision,
    RuleAllowlist, RuleId, SecretReference, TransportError, TransportProvenance, Version,
    WorkProductId, validate_contract,
};

const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

struct Fixture {
    scope: GithubCodeqlScope,
    secret: SecretReference,
    alert: AlertRecord,
    analysis: AnalysisRecord,
}

fn fixture() -> Fixture {
    let rule = RuleId::new("js/sql-injection").expect("rule");
    let scope = GithubCodeqlScope::new(
        hartevo_github_codeql_result_plugin::InstallationId::new("installation-17")
            .expect("installation"),
        RepositoryIdentity::new("acme", "checkout", "https://github.com/acme/checkout")
            .expect("repository"),
        RefName::new("refs/heads/main").expect("ref"),
        CommitSha::new(COMMIT).expect("commit"),
        hartevo_github_codeql_result_plugin::AnalysisId::new("analysis-1").expect("analysis id"),
        CodeScanningTool::CodeQL,
        rule.clone(),
        RuleAllowlist::new([rule]).expect("rule allowlist"),
        hartevo_github_codeql_result_plugin::AlertNumber::new(17).expect("alert number"),
        hartevo_github_codeql_result_plugin::AlertFingerprint::new("fingerprint-17")
            .expect("fingerprint"),
        AlertState::Open,
        PermissionSnapshot::least_privilege(),
        MissionScopeBinding::new(
            ProjectId::new("project-checkout").expect("project"),
            Revision::new(3).expect("project revision"),
            MissionId::new("mission-security").expect("mission"),
            Revision::new(11).expect("mission revision"),
            WorkProductId::new("work-product-codeql").expect("work product"),
            Revision::new(4).expect("work product revision"),
        )
        .expect("Mission scope"),
    )
    .expect("scope");
    let location =
        RedactedLocation::new("src/db.js", 42, 42, "private source region").expect("location");
    let alert =
        AlertRecord::from_scope(&scope, AlertSeverity::High, vec![location]).expect("alert");
    let analysis = AnalysisRecord::from_scope(&scope, AnalysisStatus::Complete).expect("analysis");
    let secret = SecretReference::new(
        "opaque-github-app-reference",
        &scope,
        2,
        GithubAuthKind::App,
    )
    .expect("secret");
    Fixture {
        scope,
        secret,
        alert,
        analysis,
    }
}

fn recording_service(fixture: &Fixture) -> GithubCodeqlResultService<RecordingTransport> {
    let alert_summary =
        hartevo_github_codeql_result_plugin::AlertSummary::from_record(&fixture.alert);
    let analysis_summary =
        hartevo_github_codeql_result_plugin::AnalysisSummary::from_record(&fixture.analysis);
    let alert_page = AlertPage::new(1, vec![alert_summary], None).expect("alert page");
    let analysis_page = AnalysisPage::new(1, vec![analysis_summary], None).expect("analysis page");
    let script = ReadScript::new(
        [Ok(alert_page)],
        [Ok(fixture.alert.clone())],
        [Ok(analysis_page)],
    );
    let provider = GithubCodeScanningProvider::new(
        RecordingTransport::new(script),
        Version::new(0, 1, 0),
        ProviderProvenance::Recording,
    )
    .expect("provider");
    GithubCodeqlResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
        ReadLimits::default(),
    )
    .expect("service")
}

#[test]
fn contract_scope_registration_and_consumer_are_layer_one_bound() {
    validate_contract().expect("contract");
    let fixture = fixture();
    fixture.scope.validate().expect("scope");
    assert_eq!(fixture.scope.tool.as_str(), "CodeQL");
    assert_eq!(fixture.scope.repository.full_name(), "acme/checkout");
    assert!(
        fixture
            .scope
            .rule_allowlist
            .contains(&fixture.scope.rule_id)
    );

    let secret_debug = format!("{:?}", fixture.secret);
    assert!(!secret_debug.contains("opaque-github-app-reference"));
    assert!(!fixture.secret.is_revoked());

    let mut service = recording_service(&fixture);
    let registration = service.registration().clone();
    assert_eq!(
        registration.contract_version,
        hartevo_github_codeql_result_plugin::CONTRACT_VERSION
    );
    assert_eq!(
        registration.provider_id,
        hartevo_github_codeql_result_plugin::PROVIDER_ID
    );
    assert_eq!(registration.scope_digest, *fixture.scope.digest());
    assert_eq!(
        registration.permission_digest,
        *fixture.scope.permissions.digest()
    );
    assert_eq!(registration.alert_digest, fixture.scope.alert_digest());

    service.unmount().expect("unmount");
    assert!(service.read_evidence().is_err());
    service.remount().expect("remount");
    service.revoke_registration().expect("revoke");
    assert!(service.read_evidence().is_err());
}

#[test]
fn successful_recording_retains_redacted_alert_evidence_only() {
    let fixture = fixture();
    let mut service = recording_service(&fixture);
    let proposal = service
        .compile_result_proposal("mission-security-decision-1")
        .expect("proposal");
    let projection = &proposal.projection;
    assert_eq!(projection.state, ProjectionState::AlertEvidence);
    assert!(!projection.connected);
    assert!(!projection.native);
    assert!(!projection.first_party);
    assert_eq!(projection.provenance, TransportProvenance::Recording);
    let evidence = projection.evidence.as_ref().expect("alert evidence");
    let alert = evidence.alert.as_ref().expect("alert");
    assert_eq!(alert.alert_number.get(), 17);
    assert_eq!(alert.rule_id.as_str(), "js/sql-injection");
    assert_eq!(alert.locations[0].start_line, 42);
    let serialized = serde_json::to_string(&projection).expect("projection JSON");
    assert!(!serialized.contains("src/db.js"));
    assert!(!serialized.contains("private source region"));
    assert!(!serialized.contains("SARIF"));

    assert!(!proposal.can_adopt_outcome());
    let recording = service.record_result(&proposal).expect("recording");
    service.verify_recording(&recording).expect("verify");

    let consumer = MissionGithubCodeqlConsumer::new(fixture.scope.clone(), service.registration())
        .expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        mission_result.state,
        MissionCodeqlDecisionState::ReviewRequired
    );
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    assert!(!mission_result.outcome_adopted);
    assert!(!mission_result.can_adopt_outcome());
}

#[test]
fn all_fixture_provenances_are_truthfully_non_native() {
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        assert_eq!(provenance.as_str(), TransportProvenance::as_str(provenance));
    }

    let fixture = fixture();
    let provider = GithubCodeScanningProvider::new(
        hartevo_github_codeql_result_plugin::BlockedEnvTransport::new(),
        Version::new(0, 1, 0),
        ProviderProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut service = GithubCodeqlResultService::new(
        fixture.scope,
        fixture.secret,
        provider,
        ReadLimits::default(),
    )
    .expect("blocked service");
    let projection = service.read_evidence().expect("bounded blocked projection");
    assert_eq!(projection.state, ProjectionState::ProviderUnknown);
    assert_eq!(projection.provenance, ProviderProvenance::BlockedEnv);
    assert!(projection.provider_errors[0].blocked_env);
    assert!(!projection.connected);
    assert!(!projection.native);
    assert!(!projection.first_party);
}

#[test]
fn provider_http_failures_are_non_adoptable_and_fail_closed() {
    for status in [401, 403, 404, 409, 422, 429, 500, 503] {
        let fixture = fixture();
        let analysis_error = TransportError::http(status, "provider diagnostic");
        let script = ReadScript::new([], [], [Err(analysis_error)]);
        let provider = GithubCodeScanningProvider::new(
            FixtureTransport::new(script),
            Version::new(0, 1, 0),
            ProviderProvenance::Fixture,
        )
        .expect("provider");
        let mut service = GithubCodeqlResultService::new(
            fixture.scope,
            fixture.secret,
            provider,
            ReadLimits::default(),
        )
        .expect("service");
        let projection = service.read_evidence().expect("error projection");
        let expected = if status == 401 || status == 403 {
            ProjectionState::AccessLoss
        } else {
            ProjectionState::ProviderUnknown
        };
        assert_eq!(projection.state, expected);
        assert_eq!(projection.provider_errors[0].status_code, Some(status));
        assert!(!projection.connected);
        assert!(!projection.native);
        assert!(!projection.first_party);
    }
    let fixture = fixture();
    let script = ReadScript::new([], [], [Err(TransportError::timeout())]);
    let provider = GithubCodeScanningProvider::new(
        FixtureTransport::new(script),
        Version::new(0, 1, 0),
        ProviderProvenance::Fixture,
    )
    .expect("provider");
    let mut service = GithubCodeqlResultService::new(
        fixture.scope,
        fixture.secret,
        provider,
        ReadLimits::default(),
    )
    .expect("service");
    assert_eq!(
        service.read_evidence().expect("timeout projection").state,
        ProjectionState::ProviderUnknown
    );
}

#[test]
fn stale_state_rule_drift_and_pagination_loops_fail_closed() {
    let fixture1 = fixture();
    let stale_alert = AlertRecord::new(
        fixture1.scope.alert_number,
        fixture1.scope.alert_fingerprint.clone(),
        AlertState::Fixed,
        AlertSeverity::High,
        fixture1.scope.tool,
        fixture1.scope.rule_id.clone(),
        fixture1.scope.repository_digest(),
        fixture1.scope.ref_digest(),
        fixture1.scope.commit_sha.clone(),
        fixture1.scope.analysis_id.clone(),
        Vec::new(),
    )
    .expect("stale alert");
    let analysis =
        AnalysisRecord::from_scope(&fixture1.scope, AnalysisStatus::Complete).expect("analysis");
    let page = AlertPage::new(
        1,
        vec![hartevo_github_codeql_result_plugin::AlertSummary::from_record(&stale_alert)],
        None,
    )
    .expect("page");
    let analysis_page = AnalysisPage::new(
        1,
        vec![hartevo_github_codeql_result_plugin::AnalysisSummary::from_record(&analysis)],
        None,
    )
    .expect("analysis page");
    let service = GithubCodeqlResultService::new(
        fixture1.scope.clone(),
        fixture1.secret.clone(),
        GithubCodeScanningProvider::new(
            FixtureTransport::new(ReadScript::new(
                [Ok(page)],
                [Ok(stale_alert)],
                [Ok(analysis_page)],
            )),
            Version::new(0, 1, 0),
            ProviderProvenance::Fixture,
        )
        .expect("provider"),
        ReadLimits::default(),
    )
    .expect("service");
    let mut service = service;
    assert!(matches!(
        service.read_evidence(),
        Err(hartevo_github_codeql_result_plugin::ServiceError::StaleAlertState)
    ));

    let fixture2 = fixture();
    let token =
        hartevo_github_codeql_result_plugin::OpaquePageToken::new("opaque-token").expect("token");
    let first_page = AlertPage::new(1, Vec::new(), Some(token.clone())).expect("first page");
    let second_page = AlertPage::new(2, Vec::new(), Some(token)).expect("second page");
    let analysis =
        AnalysisRecord::from_scope(&fixture2.scope, AnalysisStatus::Complete).expect("analysis");
    let analysis_page = AnalysisPage::new(
        1,
        vec![hartevo_github_codeql_result_plugin::AnalysisSummary::from_record(&analysis)],
        None,
    )
    .expect("analysis page");
    let provider = GithubCodeScanningProvider::new(
        FixtureTransport::new(ReadScript::new(
            [Ok(first_page), Ok(second_page)],
            [],
            [Ok(analysis_page)],
        )),
        Version::new(0, 1, 0),
        ProviderProvenance::Fixture,
    )
    .expect("provider");
    let mut service = GithubCodeqlResultService::new(
        fixture2.scope,
        fixture2.secret,
        provider,
        ReadLimits::default(),
    )
    .expect("service");
    assert!(matches!(
        service.read_evidence(),
        Err(hartevo_github_codeql_result_plugin::ServiceError::PageLoop)
    ));
}

#[test]
fn permissions_and_rule_allowlists_are_read_only_and_bounded() {
    assert!(PermissionSnapshot::new([Permission::SecurityEventsRead]).is_err());
    assert!(RuleAllowlist::new(BTreeSet::new()).is_err());
    let duplicate_rule = RuleId::new("js/sql-injection").expect("rule");
    assert!(RuleAllowlist::new([duplicate_rule.clone(), duplicate_rule]).is_err());
    assert!(RefName::new("main").is_err());
    assert!(CommitSha::new("ABCDEF").is_err());
}
