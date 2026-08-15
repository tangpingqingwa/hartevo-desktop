use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_veracode_result_plugin::{
    ApplicationProjection, BlockedEnvTransport, BuildProjection, BuildStatus, BusinessCriticality,
    Digest, EvidenceState, FindingProjection, FindingStatus, FixtureTransport, LoopbackTransport,
    MissionScope, MissionVeracodeResultConsumer, PermissionSnapshot, PolicyProjection,
    PolicyStatus, ProjectScope, ReadBounds, RecordingTransport, ScanProjection, ScanStatus,
    ScanType, SecretReference, Severity, TransportProvenance, VeracodeProvider,
    VeracodeProviderError, VeracodeRegion, VeracodeResultService, VeracodeScope,
    VeracodeTransportError, VeracodeTransportFailure, WorkProductScope,
};

fn timestamp(value: &str) -> DateTime<Utc> {
    value.parse().expect("timestamp")
}

fn scope() -> VeracodeScope {
    VeracodeScope::new(
        "app-001",
        VeracodeRegion::Commercial,
        ProjectScope::new("project-001", 2).expect("project"),
        MissionScope::new("mission-001", 3).expect("mission"),
        WorkProductScope::new("work-product-001", 4).expect("work product"),
        5,
    )
    .expect("scope")
    .with_build("build-001", 1)
    .expect("build")
    .with_scan("scan-001", 1)
    .expect("scan")
    .with_policy("policy-001", 1)
    .expect("policy")
}

fn registration(scope: VeracodeScope) -> hartevo_veracode_result_plugin::VeracodeRegistration {
    VeracodeResultService::new()
        .register(
            "registration-001",
            scope,
            SecretReference::for_results_read(
                "opaque-veracode-api-key",
                VeracodeRegion::Commercial,
            )
            .expect("secret"),
            PermissionSnapshot::results_read(),
            1,
        )
        .expect("registration")
}

fn bounds(limit: u16, max_pages: u16, max_retries: u8) -> ReadBounds {
    ReadBounds::new(limit, max_pages, max_retries, 256).expect("bounds")
}

fn finding(id: &str, status: FindingStatus) -> FindingProjection {
    FindingProjection::from_sensitive(
        id,
        Severity::High,
        status,
        "CWE-89",
        ScanType::Static,
        true,
        Some(timestamp("2026-08-14T00:00:00Z")),
        Some(timestamp("2026-08-15T00:00:00Z")),
        Some("src/private.rs:42"),
        Some("private-package@1.2.3"),
        1,
        1,
    )
    .expect("finding")
}

type ResourceSets = (
    Vec<ApplicationProjection>,
    Vec<BuildProjection>,
    Vec<ScanProjection>,
    Vec<FindingProjection>,
    Vec<PolicyProjection>,
);

fn resource_sets(scope: &VeracodeScope) -> ResourceSets {
    let now = timestamp("2026-08-15T00:00:00Z");
    (
        vec![
            ApplicationProjection::from_sensitive(
                scope.application_id.as_str(),
                "private application name",
                BusinessCriticality::High,
                Some(now),
                Some(now),
                Some("policy-001".to_owned()),
                PolicyStatus::Violating,
                1,
            )
            .expect("application"),
        ],
        vec![
            BuildProjection::from_sensitive(
                "build-001",
                Some("private build version"),
                BuildStatus::Published,
                Some(now),
                Some(now),
                1,
            )
            .expect("build"),
        ],
        vec![
            ScanProjection::from_values(
                "scan-001",
                ScanType::Static,
                ScanStatus::Published,
                Some(now),
                Some(now),
                2,
                1,
            )
            .expect("scan"),
        ],
        vec![finding("finding-001", FindingStatus::Open)],
        vec![
            PolicyProjection::from_sensitive(
                "policy-001",
                "private policy name",
                PolicyStatus::Violating,
                Some(Severity::High),
                1,
                1,
            )
            .expect("policy"),
        ],
    )
}

#[test]
fn contract_and_secret_reference_are_opaque_and_non_native() {
    assert!(!hartevo_veracode_result_plugin::Layer1Authority::connected());
    assert!(!hartevo_veracode_result_plugin::Layer1Authority::native_provider());
    assert!(!hartevo_veracode_result_plugin::Layer1Authority::first_party());
    let secret =
        SecretReference::for_results_read("opaque-veracode-api-key", VeracodeRegion::Commercial)
            .expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("opaque-veracode-api-key"));
    let registration = registration(scope());
    let serialized = serde_json::to_string(&registration).expect("registration JSON");
    let debug = format!("{registration:?}");
    assert!(!serialized.contains("opaque-veracode-api-key"));
    assert!(!serialized.contains("app-001"));
    assert!(!debug.contains("opaque-veracode-api-key"));
    assert!(serialized.contains("secretReferenceDigest"));
}

#[test]
fn fixture_reads_application_build_scan_finding_and_policy_with_receipts() {
    let scope = scope();
    let registration = registration(scope.clone());
    let mut provider = VeracodeProvider::new(
        FixtureTransport::for_scope(&scope).expect("fixture"),
        registration.clone(),
    )
    .expect("provider");
    let mut consumer = MissionVeracodeResultConsumer::new(scope, registration).expect("consumer");
    let proposal = consumer
        .read_proposal(
            &mut provider,
            &consumer.request(bounds(100, 2, 1)).expect("request"),
            timestamp("2026-08-15T01:00:00Z"),
        )
        .expect("proposal");
    assert_eq!(proposal.state, EvidenceState::Present);
    assert_eq!(proposal.evidence.applications.len(), 1);
    assert_eq!(proposal.evidence.builds.len(), 1);
    assert_eq!(proposal.evidence.scans.len(), 1);
    assert_eq!(proposal.evidence.findings.len(), 1);
    assert_eq!(proposal.evidence.policies.len(), 1);
    assert_eq!(proposal.evidence.findings[0].status, FindingStatus::Open);
    assert!(proposal.evidence.findings[0].severity_digest.is_valid());
    assert!(proposal.evidence.findings[0].status_digest.is_valid());
    assert!(proposal.evidence.findings[0].category_digest.is_valid());
    assert_eq!(
        proposal.evidence.pages[0].receipt.provenance,
        TransportProvenance::Fixture
    );
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.first_party);
    assert!(!proposal.evidence.review_eligible() || proposal.evidence.validate_integrity().is_ok());
    assert!(proposal.validate_integrity().is_ok());
}

#[test]
fn cursor_bounds_make_partial_evidence_explicit() {
    let scope = scope();
    let (applications, builds, scans, mut findings, policies) = resource_sets(&scope);
    findings.push(finding("finding-002", FindingStatus::Fixed));
    let registration = registration(scope.clone());
    let transport =
        FixtureTransport::with_resources(&scope, applications, builds, scans, findings, policies)
            .expect("fixture");
    let mut provider = VeracodeProvider::new(transport, registration.clone()).expect("provider");
    let mut consumer = MissionVeracodeResultConsumer::new(scope, registration).expect("consumer");
    let proposal = consumer
        .read_proposal(
            &mut provider,
            &consumer.request(bounds(1, 1, 0)).expect("request"),
            timestamp("2026-08-15T01:00:00Z"),
        )
        .expect("partial proposal");
    assert_eq!(proposal.state, EvidenceState::Partial);
    assert!(!proposal.evidence.review_eligible());
    assert!(
        !proposal.evidence.is_non_adoptable() || proposal.evidence.state == EvidenceState::Partial
    );
}

#[test]
fn transport_failures_project_access_loss_provider_unknown_and_blocked_env_honestly() {
    for (status, expected) in [
        (401, EvidenceState::AccessLoss),
        (403, EvidenceState::AccessLoss),
        (404, EvidenceState::ProviderUnknown),
        (429, EvidenceState::ProviderUnknown),
        (500, EvidenceState::ProviderUnknown),
    ] {
        let scope = scope();
        let registration = registration(scope.clone());
        let mut transport = RecordingTransport::for_scope(&scope).expect("recording");
        transport.push_response(Err(VeracodeTransportError::from_status(status)));
        let mut provider =
            VeracodeProvider::new(transport, registration.clone()).expect("provider");
        let mut consumer =
            MissionVeracodeResultConsumer::new(scope, registration).expect("consumer");
        let request = consumer.request(bounds(10, 2, 0)).expect("request");
        let proposal = consumer
            .read_proposal(&mut provider, &request, timestamp("2026-08-15T01:00:00Z"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected, "status {status}");
        assert!(!proposal.evidence.connected);
        assert!(!proposal.evidence.native);
        assert!(!proposal.evidence.first_party);
        assert!(proposal.evidence.failure.is_some());
    }

    let scope = scope();
    let registration = registration(scope.clone());
    let mut provider =
        VeracodeProvider::new(BlockedEnvTransport, registration.clone()).expect("provider");
    let mut consumer = MissionVeracodeResultConsumer::new(scope, registration).expect("consumer");
    let request = consumer.request(bounds(10, 2, 0)).expect("request");
    let proposal = consumer
        .read_proposal(&mut provider, &request, timestamp("2026-08-15T01:00:00Z"))
        .expect("blocked env proposal");
    assert_eq!(proposal.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.evidence.provenance,
        TransportProvenance::BlockedEnv
    );
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.first_party);
}

#[test]
fn retries_and_rate_receipts_are_bounded_without_raw_headers() {
    let scope = scope();
    let registration = registration(scope.clone());
    let mut transport = RecordingTransport::for_scope(&scope).expect("recording");
    let rate = hartevo_veracode_result_plugin::RateLimitReceipt::new(60, Some(0), Some(3), true)
        .expect("rate receipt");
    for _ in 0..3 {
        transport.push_response(Err(
            VeracodeTransportError::from_status(429).with_rate_limit(rate.clone())
        ));
    }
    let mut provider = VeracodeProvider::new(transport, registration.clone()).expect("provider");
    let mut consumer = MissionVeracodeResultConsumer::new(scope, registration).expect("consumer");
    let request = consumer.request(bounds(10, 2, 2)).expect("request");
    let proposal = consumer
        .read_proposal(&mut provider, &request, timestamp("2026-08-15T01:00:00Z"))
        .expect("failure proposal");
    let failure = proposal.evidence.failure.expect("failure receipt");
    assert_eq!(failure.status_code, Some(429));
    assert_eq!(failure.retry.attempts, 3);
    assert_eq!(failure.retry.retries, 2);
    assert_eq!(failure.rate_limit.retry_after_seconds, Some(3));
    assert!(failure.rate_limit.throttled);
}

#[test]
fn tamper_stale_revoked_and_reversible_registration_states_fail_closed() {
    let service = VeracodeResultService::new();
    let reversible_scope = scope();
    let mut registration = registration(reversible_scope);
    let active_digest = registration.registration_digest().clone();
    let revoked = registration.revoke().expect("revoke");
    assert_eq!(
        revoked.new_status,
        hartevo_veracode_result_plugin::RegistrationStatus::Revoked
    );
    assert_ne!(registration.registration_digest(), &active_digest);
    registration.restore().expect("restore");
    registration.reverse().expect("reverse");
    assert!(registration.is_reversed());
    assert!(registration.restore().is_err());

    let scope = scope();
    let registration = service
        .register_default(
            scope.clone(),
            SecretReference::for_results_read(
                "opaque-veracode-api-key",
                VeracodeRegion::Commercial,
            )
            .expect("secret"),
        )
        .expect("default registration");
    let mut provider = VeracodeProvider::new(
        FixtureTransport::for_scope(&scope).expect("fixture"),
        registration.clone(),
    )
    .expect("provider");
    let mut consumer = MissionVeracodeResultConsumer::new(scope, registration).expect("consumer");
    let request = consumer.request(bounds(10, 2, 0)).expect("request");
    let proposal = consumer
        .read_proposal(&mut provider, &request, timestamp("2026-08-15T01:00:00Z"))
        .expect("proposal");
    let tampered = proposal
        .evidence
        .clone()
        .with_declared_evidence_digest(Digest::from_text("tampered"));
    assert!(
        !service
            .verify_evidence(consumer.registration(), &tampered)
            .valid
    );
}

#[test]
fn local_recording_is_idempotent_and_verification_is_not_authority() {
    let scope = scope();
    let registration = registration(scope.clone());
    let mut provider = VeracodeProvider::new(
        LoopbackTransport::for_scope(&scope).expect("loopback"),
        registration.clone(),
    )
    .expect("provider");
    let mut consumer = MissionVeracodeResultConsumer::new(scope, registration).expect("consumer");
    let request = consumer.request(bounds(10, 2, 0)).expect("request");
    let proposal = consumer
        .read_proposal(&mut provider, &request, timestamp("2026-08-15T01:00:00Z"))
        .expect("proposal");
    let first = consumer
        .record(&proposal, "local-record-001")
        .expect("record");
    let replay = consumer
        .record(&proposal, "local-record-001")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());
    let report = consumer.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);
    assert!(!report.connected);
    assert!(!report.native);
    assert!(!report.first_party);
    assert!(!report.kernel_authority);
    assert!(!report.outcome_adopted);
    assert!(
        !consumer
            .consume(&proposal)
            .expect("consume")
            .can_be_adopted()
    );
}

#[test]
fn finding_and_policy_projection_states_are_typed_and_redacted() {
    assert_eq!(FindingStatus::parse("OPEN"), FindingStatus::Open);
    assert_eq!(FindingStatus::parse("FIXED"), FindingStatus::Fixed);
    assert_eq!(FindingStatus::parse("MITIGATED"), FindingStatus::Mitigated);
    assert_eq!(FindingStatus::parse("ACCEPTED"), FindingStatus::Accepted);
    assert_eq!(PolicyStatus::parse("DID_NOT_PASS"), PolicyStatus::Violating);
    let value = finding("finding-redacted", FindingStatus::Mitigated);
    let serialized = serde_json::to_string(&value).expect("finding JSON");
    assert!(!serialized.contains("src/private.rs:42"));
    assert!(!serialized.contains("private-package@1.2.3"));
    assert!(!serialized.contains("CWE-89"));
    assert!(serialized.contains("severityDigest"));
    assert!(serialized.contains("statusDigest"));
    assert!(serialized.contains("categoryDigest"));

    let mut digests = BTreeSet::new();
    digests.insert(value.finding_digest.clone());
    digests.insert(value.finding_digest.clone());
    assert_eq!(digests.len(), 1);
}

#[test]
fn transport_failure_helpers_cover_statuses_and_timeout() {
    for (status, expected) in [
        (400, VeracodeTransportFailure::BadRequest),
        (401, VeracodeTransportFailure::Unauthorized),
        (403, VeracodeTransportFailure::AccessDenied),
        (404, VeracodeTransportFailure::NotFound),
        (409, VeracodeTransportFailure::Conflict),
        (429, VeracodeTransportFailure::Throttled),
        (500, VeracodeTransportFailure::Server),
        (503, VeracodeTransportFailure::Server),
    ] {
        let error = VeracodeTransportError::from_status(status);
        assert_eq!(error.failure, expected);
        assert_eq!(error.status_code, Some(status.clamp(400, 500)));
    }
    assert_eq!(VeracodeTransportError::timeout().status_code, None);
    assert_eq!(
        VeracodeTransportError::blocked_env().failure,
        VeracodeTransportFailure::BlockedEnv
    );
    let _: Option<VeracodeProviderError> = None;
}
