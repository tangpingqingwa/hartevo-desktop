use std::collections::BTreeMap;

use hartevo_aws_guardduty_finding_result_plugin as plugin;
use plugin::{
    ActionabilityLabel, AwsGuardDutyFinding, AwsGuardDutyFindingScope, AwsGuardDutyFindingService,
    AwsGuardDutyProvider, ConfidenceBand, DetectorDiscovery, Digest, EvidenceStatus,
    FindingCriteria, FindingId, FindingSeverity, FindingStatistics, FindingStatus, FindingType,
    FixtureTransport, GuardDutyFindingQuery, ListDetectorsRequest, ListDetectorsResponse,
    ListFindingsRequest, ListFindingsResponse, MissionAwsGuardDutyConsumer, Operation,
    ResourceKind, SecretReference, TransportFailure,
};

fn scope() -> AwsGuardDutyFindingScope {
    AwsGuardDutyFindingScope::new(
        "123456789012",
        "us-east-1",
        "detector-1",
        "mission-1",
        1,
        "project-1",
        1,
        "work-product-1",
        1,
    )
    .expect("scope")
}

fn query() -> GuardDutyFindingQuery {
    GuardDutyFindingQuery::new(FindingCriteria::default()).expect("query")
}

fn secret(scope: &AwsGuardDutyFindingScope) -> SecretReference {
    SecretReference::sigv4("opaque-sigv4-handle-must-not-leak", scope, 7).expect("secret")
}

fn finding(id: &str, status: FindingStatus) -> AwsGuardDutyFinding {
    AwsGuardDutyFinding::new(
        FindingId::new(id).expect("finding id"),
        FindingType::new("Backdoor:EC2/GuardDutyFixture").expect("finding type"),
        FindingSeverity::High,
        ConfidenceBand::High,
        plugin::Timestamp::new("2026-08-15T00:00:00Z").expect("created timestamp"),
        plugin::Timestamp::new("2026-08-15T00:01:00Z").expect("updated timestamp"),
        ResourceKind::Ec2Instance,
        status,
        vec![
            ActionabilityLabel::Actionable,
            ActionabilityLabel::ReviewRequired,
        ],
        "resource-reference-never-retained",
    )
    .expect("finding projection")
}

struct FixtureSetup {
    consumer: MissionAwsGuardDutyConsumer,
    provider: AwsGuardDutyProvider<FixtureTransport>,
    query: GuardDutyFindingQuery,
}

fn complete_setup(status: FindingStatus, include_statistics: bool) -> FixtureSetup {
    let scope = scope();
    let query = query().with_statistics(include_statistics);
    let service = AwsGuardDutyFindingService::new();
    let registration = service
        .register(scope.clone(), query.clone(), secret(&scope))
        .expect("registration");
    let consumer = MissionAwsGuardDutyConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");

    let detector_request = ListDetectorsRequest::new(&scope).expect("detector request");
    let detector_response = ListDetectorsResponse::new(
        &detector_request,
        vec![scope.detector_id.clone()],
        true,
        128,
    )
    .expect("detector response");
    let list_request = ListFindingsRequest::first(&scope, &query).expect("list request");
    let id = FindingId::new("finding-1").expect("finding id");
    let list_response =
        ListFindingsResponse::new(&list_request, vec![id.clone()], None::<&str>, false, 512)
            .expect("list response");
    let allowlist = plugin::FindingIdAllowlist::new(
        vec![id],
        list_response.response_digest.clone(),
        &scope,
        &query,
    )
    .expect("allowlist");
    let get_request =
        plugin::GetFindingsRequest::new(&scope, &query, allowlist).expect("get request");
    let projected_finding = finding("finding-1", status);
    let get_response = plugin::GetFindingsResponse::new(
        &get_request,
        vec![projected_finding.clone()],
        Vec::new(),
        false,
        768,
    )
    .expect("get response");

    let mut transport = FixtureTransport::new();
    transport.push_detectors(Ok(detector_response));
    transport.push_list_findings(Ok(list_response));
    transport.push_get_findings(Ok(get_response));
    if include_statistics {
        let statistics_request =
            plugin::StatisticsRequest::new(&scope, &query).expect("statistics request");
        let mut severity_counts = BTreeMap::new();
        severity_counts.insert(FindingSeverity::High, 1);
        let mut resource_counts = BTreeMap::new();
        resource_counts.insert(ResourceKind::Ec2Instance, 1);
        let statistics_projection =
            FindingStatistics::new(1, severity_counts, resource_counts).expect("statistics");
        transport.push_statistics(Ok(plugin::StatisticsResponse::new(
            &statistics_request,
            statistics_projection,
            false,
            256,
        )
        .expect("statistics response")));
    }
    let provider = AwsGuardDutyProvider::new(transport);
    FixtureSetup {
        consumer,
        provider,
        query,
    }
}

#[test]
fn contract_and_typed_runtime_are_layer_one_read_only() {
    plugin::validate_contract_document().expect("contract");
    let service = AwsGuardDutyFindingService::new();
    service.validate().expect("service");
    assert_eq!(service.service_name(), "AwsGuardDutyFindingService");
    assert_eq!(service.capabilities().len(), 11);
    assert!(service.capabilities().iter().all(|capability| {
        capability.read_only
            && !capability.mutates_provider
            && !capability.native
            && !capability.connected
            && !capability.first_party
            && !capability.adopts_outcome
    }));
    assert_eq!(plugin::contract_digest().as_str().len(), 64);
    assert_eq!(plugin::api_digest().as_str().len(), 64);
    assert_eq!(plugin::permission_digest().as_str().len(), 64);
}

#[test]
fn secret_reference_is_opaque_and_registration_serialization_is_redacted() {
    let scope = scope();
    let secret_ref = secret(&scope);
    let debug = format!("{secret_ref:?}");
    let display = secret_ref.to_string();
    assert!(!debug.contains("opaque-sigv4-handle-must-not-leak"));
    assert!(!display.contains("opaque-sigv4-handle-must-not-leak"));
    assert!(serde_json::to_string(&secret_ref).is_err());

    let query = query();
    let registration = AwsGuardDutyFindingService::new()
        .register(scope, query, secret_ref)
        .expect("registration");
    let encoded = serde_json::to_string(&registration).expect("redacted registration JSON");
    assert!(encoded.contains("secretReferenceDigest"));
    assert!(!encoded.contains("opaque-sigv4-handle-must-not-leak"));
    assert!(!format!("{registration:?}").contains("opaque-sigv4-handle-must-not-leak"));
}

#[test]
fn fixture_read_projects_only_bounded_metadata_and_optional_statistics() {
    let mut setup = complete_setup(FindingStatus::Active, true);
    let result = setup
        .consumer
        .read(&mut setup.provider, &setup.query)
        .expect("complete fixture read");
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);
    assert_eq!(result.evidence.findings.len(), 1);
    assert!(result.evidence.statistics.is_some());
    assert!(!result.evidence.connected);
    assert!(!result.evidence.native);
    assert!(!result.evidence.first_party);
    assert!(!result.evidence.can_be_adopted());
    assert!(result.evidence.review_eligible());
    assert_eq!(
        result.evidence.redaction,
        plugin::RedactionSummary::default()
    );
    assert!(result.evidence.receipts.iter().all(|receipt| {
        receipt.redacted && receipt.cost.redacted && receipt.request_digest.as_str().len() == 64
    }));
    let encoded = serde_json::to_string(&result).expect("result JSON");
    assert!(!encoded.contains("resource-reference-never-retained"));
    assert!(!encoded.contains("description"));
    assert!(!encoded.contains("accessKeyDetails"));
    assert!(!encoded.contains("threatIntelPayloadValue"));
    result
        .validate(&scope(), &setup.query)
        .expect("result integrity");
}

#[test]
fn archived_stale_and_unknown_projections_fail_closed() {
    for (status, expected) in [
        (FindingStatus::Archived, EvidenceStatus::Archived),
        (FindingStatus::Stale, EvidenceStatus::Stale),
        (FindingStatus::Unknown, EvidenceStatus::Unknown),
    ] {
        let mut setup = complete_setup(status, false);
        let result = setup
            .consumer
            .read(&mut setup.provider, &setup.query)
            .expect("non-adoptable read");
        assert_eq!(result.evidence.status, expected);
        assert!(!result.evidence.review_eligible());
        assert!(!result.can_be_adopted());
    }
}

#[test]
fn all_non_native_transport_provenances_remain_false() {
    let fixture = FixtureTransport::new();
    let recording = plugin::RecordingTransport::new();
    let loopback = plugin::LoopbackTransport::new();
    let blocked = plugin::BlockedEnvTransport::new();
    for provenance in [
        plugin::AwsGuardDutyTransport::provenance(&fixture),
        plugin::AwsGuardDutyTransport::provenance(&recording),
        plugin::AwsGuardDutyTransport::provenance(&loopback),
        plugin::AwsGuardDutyTransport::provenance(&blocked),
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
}

#[test]
fn bounded_pagination_and_list_to_get_allowlist_are_digest_fenced() {
    let scope = scope();
    let query = query();
    let service = AwsGuardDutyFindingService::new();
    let registration = service
        .register(scope.clone(), query.clone(), secret(&scope))
        .expect("registration");
    let consumer = MissionAwsGuardDutyConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");

    let detector_request = ListDetectorsRequest::new(&scope).expect("detector request");
    let detector_response = ListDetectorsResponse::new(
        &detector_request,
        vec![scope.detector_id.clone()],
        true,
        100,
    )
    .expect("detector response");
    let first_request = ListFindingsRequest::first(&scope, &query).expect("first request");
    let first_id = FindingId::new("finding-1").expect("first id");
    let first_page = ListFindingsResponse::new(
        &first_request,
        vec![first_id.clone()],
        Some("opaque-page-2"),
        false,
        100,
    )
    .expect("first page");
    let second_request = first_request
        .next_page(first_page.next_page.clone().expect("next page"))
        .expect("second request");
    let second_id = FindingId::new("finding-2").expect("second id");
    let second_page = ListFindingsResponse::new(
        &second_request,
        vec![second_id.clone()],
        None::<&str>,
        false,
        100,
    )
    .expect("second page");
    let first_allowlist = plugin::FindingIdAllowlist::new(
        vec![first_id],
        first_page.response_digest.clone(),
        &scope,
        &query,
    )
    .expect("first allowlist");
    let second_allowlist = plugin::FindingIdAllowlist::new(
        vec![second_id],
        second_page.response_digest.clone(),
        &scope,
        &query,
    )
    .expect("second allowlist");
    let first_get =
        plugin::GetFindingsRequest::new(&scope, &query, first_allowlist).expect("first get");
    let second_get =
        plugin::GetFindingsRequest::new(&scope, &query, second_allowlist).expect("second get");
    let first_get_response = plugin::GetFindingsResponse::new(
        &first_get,
        vec![finding("finding-1", FindingStatus::Active)],
        Vec::new(),
        false,
        100,
    )
    .expect("first get response");
    let second_get_response = plugin::GetFindingsResponse::new(
        &second_get,
        vec![finding("finding-2", FindingStatus::Active)],
        Vec::new(),
        false,
        100,
    )
    .expect("second get response");
    let mut transport = FixtureTransport::new();
    transport.push_detectors(Ok(detector_response));
    transport.push_list_findings(Ok(first_page));
    transport.push_list_findings(Ok(second_page));
    transport.push_get_findings(Ok(first_get_response));
    transport.push_get_findings(Ok(second_get_response));
    let mut provider = AwsGuardDutyProvider::new(transport);
    let result = consumer.read(&mut provider, &query).expect("two-page read");
    assert_eq!(result.evidence.findings.len(), 2);
    assert_eq!(result.evidence.status, EvidenceStatus::Complete);

    let mut tampered = result.clone();
    tampered.evidence.findings[0].finding_id = FindingId::new("different-id").expect("id");
    assert!(tampered.validate(&scope, &query).is_err());
}

#[test]
fn repeated_cursor_is_rejected_fail_closed() {
    let scope = scope();
    let query = query();
    let registration = AwsGuardDutyFindingService::new()
        .register(scope.clone(), query.clone(), secret(&scope))
        .expect("registration");
    let consumer = MissionAwsGuardDutyConsumer::with_registration(scope.clone(), registration)
        .expect("consumer");
    let detector_request = ListDetectorsRequest::new(&scope).expect("detector request");
    let detector_response = ListDetectorsResponse::new(
        &detector_request,
        vec![scope.detector_id.clone()],
        true,
        100,
    )
    .expect("detector response");
    let first_request = ListFindingsRequest::first(&scope, &query).expect("first request");
    let first_page =
        ListFindingsResponse::new(&first_request, Vec::new(), Some("same-token"), false, 100)
            .expect("first page");
    let second_request = first_request
        .next_page(first_page.next_page.clone().expect("second request token"))
        .expect("second request");
    let second_page =
        ListFindingsResponse::new(&second_request, Vec::new(), Some("same-token"), false, 100)
            .expect("second page");
    let mut transport = FixtureTransport::new();
    transport.push_detectors(Ok(detector_response));
    transport.push_list_findings(Ok(first_page));
    transport.push_list_findings(Ok(second_page));
    let mut provider = AwsGuardDutyProvider::new(transport);
    assert!(matches!(
        consumer.read(&mut provider, &query),
        Err(plugin::AwsGuardDutyFindingResultError::PaginationReplay)
    ));
}

#[test]
fn required_http_failures_and_timeout_become_explicit_non_adoptable_states() {
    for failure in [
        TransportFailure::BadRequest,
        TransportFailure::Unauthorized,
        TransportFailure::Forbidden,
        TransportFailure::NotFound,
        TransportFailure::Conflict,
        TransportFailure::Throttled,
        TransportFailure::ServerError,
        TransportFailure::Timeout,
    ] {
        let mut setup = complete_setup(FindingStatus::Active, false);
        // Replace the successful list response with a bounded provider failure.
        let scope = scope();
        let query = setup.query.clone();
        let detector_request = ListDetectorsRequest::new(&scope).expect("detector request");
        let detector_response = ListDetectorsResponse::new(
            &detector_request,
            vec![scope.detector_id.clone()],
            true,
            100,
        )
        .expect("detector response");
        let mut transport = FixtureTransport::new();
        transport.push_detectors(Ok(detector_response));
        transport.push_list_findings(Err(plugin::TransportError::new(failure)));
        setup.provider = AwsGuardDutyProvider::new(transport);
        let result = setup
            .consumer
            .read(&mut setup.provider, &query)
            .expect("failure is recorded, not adopted");
        assert_eq!(result.evidence.status, failure.evidence_status());
        assert!(!result.evidence.review_eligible());
        assert!(!result.evidence.connected);
        assert!(!result.evidence.native);
        assert!(!result.evidence.first_party);
    }
}

#[test]
fn secret_and_registration_revocation_fail_closed() {
    let scope = scope();
    let query = query();
    let secret_ref = secret(&scope);
    let service = AwsGuardDutyFindingService::new();
    let registration = service
        .register(scope.clone(), query.clone(), secret_ref.clone())
        .expect("registration");
    secret_ref.revoke();
    assert!(matches!(
        MissionAwsGuardDutyConsumer::with_registration(scope.clone(), registration),
        Err(plugin::AwsGuardDutyFindingResultError::SecretRevoked)
    ));

    let registration = service
        .register(scope.clone(), query.clone(), secret(&scope))
        .expect("second registration");
    let mut consumer =
        MissionAwsGuardDutyConsumer::with_registration(scope, registration).expect("consumer");
    consumer
        .revoke_registration(2)
        .expect("revoke registration");
    let mut provider = AwsGuardDutyProvider::default();
    assert!(matches!(
        consumer.read(&mut provider, &query),
        Err(plugin::AwsGuardDutyFindingResultError::RegistrationRevoked)
    ));
}

#[test]
fn provider_and_cost_receipts_never_retain_raw_requests() {
    let setup = complete_setup(FindingStatus::Active, false);
    let request = setup.provider.recorded_requests().first().cloned();
    assert!(request.is_none());
    let scope = scope();
    let query = query();
    let list_request = ListFindingsRequest::first(&scope, &query).expect("list request");
    let receipt = plugin::RequestReceipt::failure(
        Operation::ListFindings,
        list_request.request_digest,
        TransportFailure::Timeout,
    );
    let encoded = serde_json::to_string(&receipt).expect("receipt JSON");
    assert!(encoded.contains("requestDigest"));
    assert!(encoded.contains("redacted"));
    assert!(!encoded.contains("opaque"));
}

#[test]
fn statistics_projection_is_bounded_and_digest_checked() {
    let stats = FindingStatistics::new(1, BTreeMap::new(), BTreeMap::new()).expect("stats");
    assert_eq!(stats.compute_digest(), stats.statistics_digest);
    let mut tampered = stats;
    tampered.total = 9;
    assert!(tampered.validate().is_err());
}

#[test]
fn detector_discovery_rejects_scope_drift() {
    let scope = scope();
    let query = query();
    let request = ListDetectorsRequest::new(&scope).expect("request");
    let response = ListDetectorsResponse::new(
        &request,
        vec![
            DetectorDiscovery::new(
                vec![scope.detector_id.clone()],
                true,
                Digest::from_text("response"),
            )
            .expect("discovery")
            .detector_ids[0]
                .clone(),
        ],
        true,
        100,
    )
    .expect("response");
    let mut tampered = response;
    tampered.request_binding = Digest::from_text("drift");
    assert!(tampered.validate_for(&request).is_err());
    assert!(query.validate().is_ok());
}
