use chrono::{DateTime, TimeZone, Utc};
use hartevo_gitguardian_secret_result_plugin::{
    BlockedEnvTransport, DetectorId, DetectorKind, DetectorStatus, Digest, EvidenceStatus,
    GitGuardianAuthKind, GitGuardianDetector, GitGuardianDetectorResponse, GitGuardianHealth,
    GitGuardianIncident, GitGuardianIncidentInput, GitGuardianIncidentResponse,
    GitGuardianOccurrence, GitGuardianOccurrenceInput, GitGuardianOperation, GitGuardianProvider,
    GitGuardianQuery, GitGuardianRequest, GitGuardianResponse, GitGuardianScope,
    GitGuardianSecretResultService, GitGuardianStatusResponse, IncidentId, IncidentStatus,
    MissionGitGuardianSecretConsumer, MissionGitGuardianSecretDecisionState, MissionId, ModelError,
    OccurrenceId, OccurrencePresence, PerimeterId, PermissionSnapshot, ProjectId,
    RecordingTransport, RedactedRateReceipt, RepositoryIdentity, Revision, SecretReference,
    Severity, TransportProvenance, ValidityStatus, WorkProductId, WorkspaceId,
    contract_bounds_tripwire, contract_digest, native_probe_from_environment,
};

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NOW_SECONDS: i64 = 1_800_000_000;

fn at() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture time")
}

fn scope() -> GitGuardianScope {
    GitGuardianScope::new(
        WorkspaceId::new("workspace-1").expect("workspace"),
        PerimeterId::new("perimeter-1").expect("perimeter"),
        IncidentId::new("incident-1").expect("incident"),
        OccurrenceId::new("occurrence-1").expect("occurrence"),
        DetectorId::new("aws_iam").expect("detector"),
        RepositoryIdentity::from_parts("acme", "payments").expect("repository"),
        hartevo_gitguardian_secret_result_plugin::CommitSha::new(COMMIT).expect("commit"),
        ProjectId::new("project-1").expect("project"),
        Revision::new(1).expect("project revision"),
        MissionId::new("mission-1").expect("mission"),
        Revision::new(2).expect("mission revision"),
        WorkProductId::new("work-product-1").expect("work product"),
        Revision::new(3).expect("work product revision"),
        PermissionSnapshot::least_privilege(),
        GitGuardianQuery::all(),
    )
    .expect("scope")
}

fn detector(scope: &GitGuardianScope) -> GitGuardianDetector {
    GitGuardianDetector::from_provider_text(
        scope.detector_id.as_str(),
        "Cloud Provider",
        DetectorKind::Specific,
        DetectorStatus::Active,
        true,
        2,
        1,
        3,
    )
    .expect("detector evidence")
}

fn incident(scope: &GitGuardianScope, status: IncidentStatus) -> GitGuardianIncident {
    GitGuardianIncident::new(GitGuardianIncidentInput {
        incident_id: scope.incident_id.clone(),
        status,
        severity: Severity::High,
        validity: ValidityStatus::Unknown,
        detector_digest: scope.detector_id.digest(),
        workspace_digest: scope.workspace_id.digest(),
        perimeter_digest: scope.perimeter_id.digest(),
        repository_digest: scope.repository.digest(),
        commit_digest: scope.commit.digest(),
        occurrence_count: 1,
        opened_at: Some(at()),
        resolved_at: (status == IncidentStatus::Resolved).then_some(at()),
        has_more_occurrences: false,
    })
    .expect("incident evidence")
}

fn occurrence(scope: &GitGuardianScope, incident: &GitGuardianIncident) -> GitGuardianOccurrence {
    GitGuardianOccurrence::new(GitGuardianOccurrenceInput {
        occurrence_id: scope.occurrence_id.clone(),
        incident_digest: incident.incident_digest.clone(),
        detector_digest: scope.detector_id.digest(),
        workspace_digest: scope.workspace_id.digest(),
        perimeter_digest: scope.perimeter_id.digest(),
        repository_digest: scope.repository.digest(),
        commit_digest: scope.commit.digest(),
        status: incident.status,
        presence: OccurrencePresence::Present,
        location_digest: Digest::from_text("bounded-path-and-region"),
        first_seen_at: Some(at()),
        last_seen_at: Some(at()),
    })
    .expect("occurrence evidence")
}

fn response_set(
    scope: &GitGuardianScope,
) -> [Result<GitGuardianResponse, hartevo_gitguardian_secret_result_plugin::ProviderError>; 3] {
    let incident = incident(scope, IncidentStatus::Open);
    let occurrence = occurrence(scope, &incident);
    let detector = detector(scope);
    let incident_request = GitGuardianRequest::get_incident(scope).expect("incident request");
    let occurrence_request =
        GitGuardianRequest::list_occurrences(scope, 1, None).expect("occurrence request");
    let detector_request = GitGuardianRequest::get_detector(scope).expect("detector request");
    [
        Ok(GitGuardianResponse::Incident(
            GitGuardianIncidentResponse::new(
                incident,
                incident_request.request_digest.clone(),
                512,
                RedactedRateReceipt::empty(),
            )
            .expect("incident response"),
        )),
        Ok(GitGuardianResponse::OccurrencePage(
            hartevo_gitguardian_secret_result_plugin::GitGuardianOccurrencePage::new(
                GitGuardianOperation::ListOccurrences,
                1,
                vec![occurrence],
                None,
                occurrence_request.request_digest.clone(),
                640,
                RedactedRateReceipt::empty(),
            )
            .expect("occurrence response"),
        )),
        Ok(GitGuardianResponse::Detector(
            GitGuardianDetectorResponse::new(
                detector,
                detector_request.request_digest.clone(),
                384,
                RedactedRateReceipt::empty(),
            )
            .expect("detector response"),
        )),
    ]
}

fn service() -> GitGuardianSecretResultService<RecordingTransport> {
    let scope = scope();
    let secret = SecretReference::new(
        "api-key-reference-never-retained",
        &scope,
        Revision::new(1).expect("secret revision"),
        GitGuardianAuthKind::ApiKey,
    )
    .expect("opaque reference");
    let provider = GitGuardianProvider::new(RecordingTransport::fixture(response_set(&scope)))
        .expect("provider");
    GitGuardianSecretResultService::new(scope, secret, provider).expect("service")
}

#[test]
fn contract_secret_reference_and_provenance_are_honest() {
    assert!(contract_bounds_tripwire());
    assert_eq!(contract_digest().as_str().len(), 64);
    let probe = native_probe_from_environment();
    assert_eq!(
        probe.status,
        hartevo_gitguardian_secret_result_plugin::NativeProbeStatus::BlockedEnv
    );
    assert!(!probe.connected && !probe.native && !probe.first_party);

    let scope = scope();
    let secret = SecretReference::new(
        "super-sensitive-api-key-reference",
        &scope,
        Revision::new(1).expect("revision"),
        GitGuardianAuthKind::ServiceAccount,
    )
    .expect("secret reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("super-sensitive-api-key-reference"));
    assert!(secret.is_opaque());
    assert!(!secret.is_revoked());
    assert!(!TransportProvenance::Fixture.connected());
    assert!(!TransportProvenance::Recording.native());
    assert!(!TransportProvenance::Loopback.first_party());
    assert_eq!(TransportProvenance::BlockedEnv.as_str(), "BLOCKED_ENV");
}

#[test]
fn bounded_evidence_is_redacted_digest_bound_and_get_only() {
    let mut service = service();
    let evidence = service.read_evidence().expect("bounded evidence");
    assert_eq!(evidence.state, EvidenceStatus::Open);
    assert_eq!(evidence.response_receipts.len(), 3);
    assert!(evidence.evidence_digest.validate().is_ok());
    assert!(!evidence.connected && !evidence.native && !evidence.first_party);
    assert!(evidence.occurrence.is_some());
    assert!(evidence.detector.is_some());
    assert!(
        evidence
            .response_receipts
            .iter()
            .all(|receipt| receipt.method == "GET")
    );
    let requests = service.provider().transport().requests();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[0]
            .path_and_query()
            .contains("/v1/incidents/secrets/incident-1")
    );
    assert!(
        requests[1]
            .path_and_query()
            .contains("incident_id=incident-1")
    );
    assert!(
        requests[2]
            .path_and_query()
            .contains("/v1/secret_detectors/aws_iam")
    );
    assert!(requests.iter().all(|request| request.method() == "GET"));
    assert!(
        requests
            .iter()
            .all(|request| { !request.path_and_query().contains("api-key-reference") })
    );
}

#[test]
fn proposal_record_consumer_and_reversible_registration_stay_below_kernel() {
    let mut service = service();
    let proposal = service.propose("mission-1").expect("proposal");
    assert!(proposal.read_only && proposal.proposal_only);
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!proposal.adopts_kernel_outcome);

    let consumer =
        MissionGitGuardianSecretConsumer::new(service.scope().clone(), service.registration())
            .expect("consumer");
    let decision = consumer
        .decide(
            &proposal,
            hartevo_gitguardian_secret_result_plugin::GitGuardianRemediationDecision::RotateOutsideLayer1,
        )
        .expect("decision proposal");
    assert_eq!(decision.state, MissionGitGuardianSecretDecisionState::Open);
    assert!(decision.unresolved);
    assert!(!decision.adopted);
    assert!(!decision.creates_effect);
    assert!(!decision.mutates_consent);
    assert!(!decision.truth_authority);
    assert!(!decision.receipt_authority);
    assert!(!decision.verification_authority);
    assert!(!decision.outcome_authority);
    assert!(!decision.security_certification_authority);

    let recording = service.record(&proposal).expect("local recording");
    let replay = service.record(&proposal).expect("idempotent replay");
    assert_eq!(recording, replay);
    assert!(!recording.provider_mutated);
    assert!(!recording.durable_provider_receipt);
    let verified = service
        .verify_recording(&proposal, &recording)
        .expect("local verification");
    assert!(verified.integrity_valid);
    assert!(!verified.provider_readback_performed);
    assert!(!verified.security_certification_authority);

    service.reverse_registration().expect("reverse");
    assert!(!service.is_active());
    assert!(matches!(
        service.read_evidence(),
        Err(hartevo_gitguardian_secret_result_plugin::ServiceError::RegistrationInactive)
    ));
    service.restore_registration().expect("restore");
    assert!(service.is_active());
    service.revoke_registration().expect("revoke");
    assert!(!service.is_active());
    assert!(matches!(
        service.read_evidence(),
        Err(hartevo_gitguardian_secret_result_plugin::ServiceError::SecretRevoked)
    ));
}

#[test]
fn provider_statuses_fail_closed_and_blocked_env_is_never_connected() {
    let provider = GitGuardianProvider::new(BlockedEnvTransport).expect("provider");
    assert_eq!(provider.provenance(), TransportProvenance::BlockedEnv);
    assert!(!provider.provenance().connected());
    assert!(!provider.provenance().native());
    assert!(!provider.provenance().first_party());

    let scope = scope();
    let request = GitGuardianRequest::get_status(&scope).expect("status request");
    let status = GitGuardianStatusResponse::new(
        GitGuardianHealth::Healthy,
        request.request_digest.clone(),
        128,
        RedactedRateReceipt::empty(),
    )
    .expect("status response");
    let mut fixture = GitGuardianProvider::new(RecordingTransport::fixture([Ok(
        GitGuardianResponse::Status(status),
    )]))
    .expect("recording provider");
    assert_eq!(
        fixture
            .read(&scope, &request)
            .expect("status read")
            .operation(),
        GitGuardianOperation::GetStatus
    );
}

#[test]
fn request_and_response_tamper_is_rejected_without_replay_authority() {
    let scope = scope();
    let request = GitGuardianRequest::get_incident(&scope).expect("request");
    let GitGuardianResponse::Incident(mut response) =
        response_set(&scope)[0].clone().expect("fixture response")
    else {
        panic!("incident response expected")
    };
    response.response_digest = Digest::from_text("tampered-response");
    let mut provider = GitGuardianProvider::new(RecordingTransport::fixture([Ok(
        GitGuardianResponse::Incident(response),
    )]))
    .expect("provider");
    assert!(matches!(
        provider.read(&scope, &request),
        Err(error) if error.kind == hartevo_gitguardian_secret_result_plugin::ProviderErrorKind::Tampered
    ));

    let mut blocked = GitGuardianProvider::new(BlockedEnvTransport).expect("blocked provider");
    assert!(matches!(
        blocked.read(&scope, &request),
        Err(error) if error.kind == hartevo_gitguardian_secret_result_plugin::ProviderErrorKind::BlockedEnv
    ));
}

#[test]
fn typed_statuses_include_partial_and_access_boundaries() {
    assert_eq!(EvidenceStatus::Open, IncidentStatus::Open.evidence_state());
    assert_eq!(
        EvidenceStatus::Resolved,
        IncidentStatus::Resolved.evidence_state()
    );
    assert_eq!(
        EvidenceStatus::Ignored,
        IncidentStatus::Ignored.evidence_state()
    );
    assert_eq!(
        EvidenceStatus::Unknown,
        IncidentStatus::Unknown.evidence_state()
    );
    assert!(matches!(
        hartevo_gitguardian_secret_result_plugin::classify_provider_error(
            hartevo_gitguardian_secret_result_plugin::ProviderErrorKind::RateLimited
        ),
        EvidenceStatus::RateLimited
    ));
    assert!(matches!(
        hartevo_gitguardian_secret_result_plugin::classify_provider_error(
            hartevo_gitguardian_secret_result_plugin::ProviderErrorKind::Forbidden
        ),
        EvidenceStatus::Denied
    ));
    assert_eq!(
        ModelError::InvalidDigest.to_string(),
        "digest is not a lowercase SHA-256 hex digest"
    );
}
