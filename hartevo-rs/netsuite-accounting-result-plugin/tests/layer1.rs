use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use hartevo_netsuite_accounting_result_plugin::{
    AccountId, BlockedEnvNetSuiteTransport, CollectionFilter, CollectionFilterField,
    CollectionFilterOperator, CollectionFilterValue, ConsentScope, DataCenter, Digest,
    FixtureNetSuiteTransport, LoopbackNetSuiteTransport, MissionId,
    MissionNetSuiteAccountingConsumer, NETSUITE_ACCOUNTING_RESULT_CONTRACT_VERSION,
    NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION, NetSuiteAccountingProposal,
    NetSuiteAccountingProposalRequest, NetSuiteAccountingResultService, NetSuiteAccountingStatus,
    NetSuiteBounds, NetSuiteCollectionSummary, NetSuiteGetRequest, NetSuiteHttpMethod,
    NetSuiteProviderError, NetSuiteReadOperation, NetSuiteRecordMetadata, NetSuiteRecordStatus,
    NetSuiteRecordType, NetSuiteSafeRecordField, NetSuiteScope, NetSuiteSelectedRecordSummary,
    NetSuiteSnapshot, NetSuiteSuiteQlField, NetSuiteSuiteTalkProvider, NetSuiteTransportError,
    NetSuiteTransportProvenance, ObservationWindow, OpaqueCursor, ProjectId,
    ProviderDefinitionError, RecordingNetSuiteTransport, Revision, RoleId, SecretReference,
    WorkProductId, contract_digest,
};

const AT: &str = "2026-08-14T12:00:00Z";

fn at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(AT)
        .expect("fixed test time")
        .with_timezone(&Utc)
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("non-zero revision")
}

fn operations() -> [NetSuiteReadOperation; 4] {
    [
        NetSuiteReadOperation::RecordMetadata,
        NetSuiteReadOperation::RecordCollectionFilter,
        NetSuiteReadOperation::SelectedRecord,
        NetSuiteReadOperation::SuiteQlProposal,
    ]
}

struct Fixture {
    scope: NetSuiteScope,
    secret: SecretReference,
    window: ObservationWindow,
    snapshot: NetSuiteSnapshot,
}

fn fixture() -> Fixture {
    let now = at();
    let window = ObservationWindow::new(now - Duration::hours(2), now - Duration::hours(1))
        .expect("bounded observation window");
    let consent = ConsentScope::new(
        operations(),
        now + Duration::days(2),
        Digest::from_text("human-consent-netsuite-accounting-v1"),
    )
    .expect("consent scope");
    let filter = CollectionFilter::new(
        CollectionFilterField::LastModifiedDate,
        CollectionFilterOperator::OnOrAfter,
        CollectionFilterValue::Timestamp(window.start()),
    )
    .expect("allowlisted collection filter");
    let scope = NetSuiteScope::new(
        AccountId::new("account-123").expect("account"),
        DataCenter::new("1234567.suitetalk.api.netsuite.com").expect("data center"),
        RoleId::new("role-3").expect("role"),
        NetSuiteRecordType::Invoice,
        Some(hartevo_netsuite_accounting_result_plugin::RecordId::new("invoice-17").expect("id")),
        filter,
        window.clone(),
        Digest::from_text("permission-snapshot-v1"),
        ProjectId::new("project-1").expect("project"),
        revision(4),
        MissionId::new("mission-1").expect("mission"),
        revision(9),
        WorkProductId::new("work-product-1").expect("work product"),
        revision(12),
        consent,
    )
    .expect("scope");
    let secret = SecretReference::new(
        "netsuite-secret-reference-1",
        &scope,
        revision(3),
        hartevo_netsuite_accounting_result_plugin::NetSuiteAuthKind::OAuth2,
    )
    .expect("opaque secret reference");
    let metadata = NetSuiteRecordMetadata::new(
        NetSuiteRecordType::Invoice,
        vec![
            NetSuiteSafeRecordField::InternalId,
            NetSuiteSafeRecordField::RecordType,
            NetSuiteSafeRecordField::LastModifiedDate,
            NetSuiteSafeRecordField::Status,
            NetSuiteSafeRecordField::Amount,
        ],
        revision(20),
        now - Duration::minutes(90),
    )
    .expect("metadata summary");
    let mut statuses = BTreeMap::new();
    statuses.insert(NetSuiteRecordStatus::Open, 1);
    let collection =
        NetSuiteCollectionSummary::new(NetSuiteRecordType::Invoice, 1, 1, false, statuses)
            .expect("collection summary");
    let selected = NetSuiteSelectedRecordSummary::new(
        NetSuiteRecordType::Invoice,
        scope.record_id().expect("selected id"),
        NetSuiteRecordStatus::Open,
        now - Duration::minutes(80),
        revision(21),
    );
    let snapshot = NetSuiteSnapshot::new(
        &scope,
        &secret,
        "suitetalk-recording-r1",
        Some(metadata),
        vec![collection],
        vec![None],
        Some(selected),
    )
    .expect("fixture snapshot");
    Fixture {
        scope,
        secret,
        window,
        snapshot,
    }
}

fn fixture_service() -> NetSuiteAccountingResultService<FixtureNetSuiteTransport> {
    let fixture = fixture();
    let provider = NetSuiteSuiteTalkProvider::new(
        FixtureNetSuiteTransport::new(fixture.snapshot.clone()),
        "suitetalk-recording-r1",
        NetSuiteTransportProvenance::Fixture,
    )
    .expect("fixture provider");
    NetSuiteAccountingResultService::new(fixture.scope, fixture.secret, provider)
        .expect("accounting result service")
}

fn request(fixture: &Fixture) -> NetSuiteAccountingProposalRequest {
    NetSuiteAccountingProposalRequest::new(
        [
            NetSuiteReadOperation::RecordMetadata,
            NetSuiteReadOperation::RecordCollectionFilter,
            NetSuiteReadOperation::SelectedRecord,
        ],
        NetSuiteBounds::default(),
        fixture.window.clone(),
        fixture.scope.work_product_revision(),
    )
    .expect("proposal request")
}

#[test]
fn fixture_read_is_bounded_redacted_and_mission_scoped() {
    let fixture = fixture();
    let proposal_request = request(&fixture);
    let provider = NetSuiteSuiteTalkProvider::new(
        FixtureNetSuiteTransport::new(fixture.snapshot),
        "suitetalk-recording-r1",
        NetSuiteTransportProvenance::Fixture,
    )
    .expect("provider");
    let mut service = NetSuiteAccountingResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
    )
    .expect("service");
    let proposal = service.propose(proposal_request, at()).expect("proposal");
    assert_eq!(proposal.status, NetSuiteAccountingStatus::Observed);
    assert_eq!(proposal.evidence.receipts.len(), 3);
    assert!(proposal.evidence.redactions.raw_provider_payload);
    assert!(proposal.evidence.redactions.raw_financial_values);
    assert!(proposal.evidence.redactions.bank_tax_payment_identifiers);
    assert!(!proposal.connected);
    assert!(!proposal.native_evidence);
    assert!(!proposal.outcome_authority);
    assert!(!proposal.is_adopted());
    assert!(
        !serde_json::to_string(&proposal)
            .expect("safe proposal JSON")
            .contains("netsuite-secret-reference-1")
    );
    assert!(!format!("{:?}", fixture.secret).contains("netsuite-secret-reference-1"));

    let mut consumer =
        MissionNetSuiteAccountingConsumer::new(fixture.scope, service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(proposal).expect("Mission result");
    assert_eq!(result.project_id.as_str(), "project-1");
    assert_eq!(result.mission_id.as_str(), "mission-1");
    assert_eq!(result.work_product_id.as_str(), "work-product-1");
    assert_eq!(
        result.state,
        hartevo_netsuite_accounting_result_plugin::MissionNetSuiteAccountingState::Observed
    );
    assert!(!result.connected);
    assert!(!result.native_evidence);
    assert!(!result.outcome_authority);
    assert!(!result.work_product_adoption);
}

#[test]
fn blocked_environment_is_unknown_and_never_connected_or_native() {
    let fixture = fixture();
    let provider = NetSuiteSuiteTalkProvider::new(
        BlockedEnvNetSuiteTransport,
        "suitetalk-blocked-env-r1",
        NetSuiteTransportProvenance::BlockedEnv,
    )
    .expect("blocked provider");
    let mut service = NetSuiteAccountingResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
    )
    .expect("service");
    let proposal = service.propose(request(&fixture), at()).expect("proposal");
    assert_eq!(proposal.status, NetSuiteAccountingStatus::ProviderUnknown);
    assert!(proposal.evidence.receipts.is_empty());
    assert_eq!(proposal.evidence.failures.len(), 3);
    assert_eq!(
        proposal.evidence.provenance,
        NetSuiteTransportProvenance::BlockedEnv
    );
    assert!(!proposal.connected);
    assert!(!proposal.native_evidence);
    assert!(!service.provider().is_connected());
    assert!(!service.provider().is_native());
}

#[test]
fn recording_retries_are_bounded_and_receipts_are_digest_bound() {
    let fixture = fixture();
    let bounds = NetSuiteBounds::default();
    let operations = [
        NetSuiteReadOperation::RecordMetadata,
        NetSuiteReadOperation::RecordCollectionFilter,
        NetSuiteReadOperation::SelectedRecord,
    ];
    let mut recording = RecordingNetSuiteTransport::default();
    recording.push_error(NetSuiteTransportError::rate_limited());
    for operation in operations {
        let get_request = NetSuiteGetRequest::new(
            &fixture.scope,
            &fixture.secret,
            operation,
            bounds.clone(),
            fixture.window.clone(),
            1,
            None,
        )
        .expect("get request");
        recording.push_response(
            fixture
                .snapshot
                .response_for(&get_request)
                .expect("fixture response"),
        );
    }
    let provider = NetSuiteSuiteTalkProvider::new(
        recording,
        "suitetalk-recording-r1",
        NetSuiteTransportProvenance::Recording,
    )
    .expect("provider");
    let mut service = NetSuiteAccountingResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
    )
    .expect("service");
    let proposal = service.propose(request(&fixture), at()).expect("proposal");
    assert_eq!(proposal.status, NetSuiteAccountingStatus::Observed);
    assert_eq!(proposal.evidence.retries.len(), 1);
    assert_eq!(proposal.evidence.receipts[0].attempts, 2);
    assert_eq!(proposal.evidence.receipts.len(), 3);
    assert_eq!(
        proposal.evidence.receipts[0].scope_digest,
        fixture.scope.digest()
    );
    assert_eq!(
        service.provider().transport().requests()[0].method(),
        NetSuiteHttpMethod::Get
    );
}

#[test]
fn suiteql_is_allowlisted_parameterized_and_never_executed() {
    let fixture = fixture();
    let provider = NetSuiteSuiteTalkProvider::new(
        LoopbackNetSuiteTransport::new(fixture.snapshot.clone()),
        "suitetalk-loopback-r1",
        NetSuiteTransportProvenance::Loopback,
    )
    .expect("provider");
    let service = NetSuiteAccountingResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
    )
    .expect("service");
    let proposal = service
        .compile_parameterized_suiteql_proposal(
            vec![
                NetSuiteSuiteQlField::InternalId,
                NetSuiteSuiteQlField::RecordType,
                NetSuiteSuiteQlField::Status,
            ],
            NetSuiteBounds::default(),
            fixture.window.clone(),
            at(),
        )
        .expect("SuiteQL proposal");
    assert!(!proposal.executed);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert_eq!(proposal.provenance, NetSuiteTransportProvenance::Loopback);
    assert!(proposal.statement.query_template().contains(":p_filter"));
    assert!(
        proposal
            .statement
            .query_template()
            .contains(":p_window_start")
    );
    assert_eq!(proposal.statement.parameters().len(), 4);
    assert!(!proposal.statement.query_template().contains("invoice-17"));
    assert!(!proposal.statement.executed());
    let record = service
        .record_suiteql_proposal(&proposal, fixture.window.end())
        .expect("record proposal");
    assert!(!record.executed);
    assert!(!record.connected);
    assert!(!record.native);
}

#[test]
fn tampering_replay_and_scope_filters_are_rejected() {
    let fixture = fixture();
    let mut service = fixture_service();
    let proposal = service.propose(request(&fixture), at()).expect("proposal");
    let mut consumer = MissionNetSuiteAccountingConsumer::new(
        fixture.scope.clone(),
        service.registration().clone(),
    )
    .expect("consumer");
    let mut tampered: NetSuiteAccountingProposal = proposal.clone();
    tampered.status = NetSuiteAccountingStatus::Partial;
    assert!(consumer.validate_only(&tampered).is_err());
    let first = consumer.consume(proposal.clone()).expect("first consume");
    assert_eq!(first.status, NetSuiteAccountingStatus::Observed);
    assert!(consumer.consume(proposal).is_err());

    assert!(
        CollectionFilter::new(
            CollectionFilterField::Status,
            CollectionFilterOperator::OnOrAfter,
            CollectionFilterValue::Timestamp(at()),
        )
        .is_err()
    );
    assert!(OpaqueCursor::new("").is_err());
    assert!(NetSuiteBounds::new(5, 50, 200, 1_048_576, 4).is_err());
}

#[test]
fn contract_registration_and_endpoints_are_exactly_bound() {
    let contract =
        hartevo_netsuite_accounting_result_plugin::NetSuiteContract::baseline().expect("contract");
    assert_eq!(
        contract.contract_version,
        NETSUITE_ACCOUNTING_RESULT_CONTRACT_VERSION
    );
    assert_eq!(
        contract.service.version,
        NETSUITE_ACCOUNTING_RESULT_PLUGIN_VERSION
    );
    assert_eq!(contract.digest(), contract_digest());
    let fixture = fixture();
    let bounds = NetSuiteBounds::default();
    let metadata = NetSuiteGetRequest::new(
        &fixture.scope,
        &fixture.secret,
        NetSuiteReadOperation::RecordMetadata,
        bounds.clone(),
        fixture.window.clone(),
        1,
        None,
    )
    .expect("metadata request");
    assert_eq!(
        metadata.endpoint().path(),
        "/services/rest/record/v1/metadata-catalog"
    );
    let selected = NetSuiteGetRequest::new(
        &fixture.scope,
        &fixture.secret,
        NetSuiteReadOperation::SelectedRecord,
        bounds,
        fixture.window,
        1,
        None,
    )
    .expect("selected request");
    assert_eq!(
        selected.endpoint().path(),
        "/services/rest/record/v1/invoice/invoice-17"
    );
    assert_eq!(selected.method(), NetSuiteHttpMethod::Get);
}

#[test]
fn transport_boundary_is_sealed_and_provenance_bound() {
    let fixture = fixture();
    let result = NetSuiteSuiteTalkProvider::new(
        FixtureNetSuiteTransport::new(fixture.snapshot.clone()),
        "suitetalk-mismatch-r1",
        NetSuiteTransportProvenance::Loopback,
    );
    assert!(matches!(
        result,
        Err(ProviderDefinitionError::ProvenanceMismatch)
    ));
}

#[test]
fn receipt_and_proposal_debug_json_redact_record_identity_and_endpoint() {
    let fixture = fixture();
    let provider = NetSuiteSuiteTalkProvider::new(
        FixtureNetSuiteTransport::new(fixture.snapshot.clone()),
        "suitetalk-recording-r1",
        NetSuiteTransportProvenance::Fixture,
    )
    .expect("provider");
    let mut service = NetSuiteAccountingResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
    )
    .expect("service");
    let proposal = service.propose(request(&fixture), at()).expect("proposal");
    let json = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for rendered in [json, debug] {
        assert!(!rendered.contains("invoice-17"));
        assert!(!rendered.contains("/services/rest/record/v1/invoice/invoice-17"));
    }
    assert!(
        proposal.evidence.receipts[2]
            .endpoint_identity
            .record_id_digest
            .is_some()
    );
    assert!(
        proposal.evidence.receipts[2]
            .endpoint_identity
            .endpoint_digest
            .as_str()
            .len()
            == 64
    );
}

#[test]
fn transport_request_and_response_debug_json_redact_record_identity_and_endpoint() {
    let fixture = fixture();
    let selected = NetSuiteGetRequest::new(
        &fixture.scope,
        &fixture.secret,
        NetSuiteReadOperation::SelectedRecord,
        NetSuiteBounds::default(),
        fixture.window.clone(),
        1,
        None,
    )
    .expect("selected request");
    let response = fixture
        .snapshot
        .response_for(&selected)
        .expect("selected response");
    for rendered in [
        serde_json::to_string(&selected).expect("request JSON"),
        format!("{selected:?}"),
        serde_json::to_string(&response).expect("response JSON"),
        format!("{response:?}"),
        serde_json::to_string(selected.endpoint()).expect("endpoint JSON"),
        format!("{:?}", selected.endpoint()),
    ] {
        assert!(!rendered.contains("invoice-17"));
        assert!(!rendered.contains("/services/rest/record/v1/invoice/invoice-17"));
    }
    let request_json = serde_json::to_string(&selected).expect("request JSON");
    assert!(request_json.contains("recordIdDigest"));
    assert!(request_json.contains("endpointDigest"));
}

#[test]
fn mission_boundary_rejects_claim_tampering_for_accounting_and_suiteql() {
    let fixture = fixture();
    let provider = NetSuiteSuiteTalkProvider::new(
        FixtureNetSuiteTransport::new(fixture.snapshot.clone()),
        "suitetalk-recording-r1",
        NetSuiteTransportProvenance::Fixture,
    )
    .expect("provider");
    let mut service = NetSuiteAccountingResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
    )
    .expect("service");
    let proposal = service.propose(request(&fixture), at()).expect("proposal");
    let consumer = MissionNetSuiteAccountingConsumer::new(
        fixture.scope.clone(),
        service.registration().clone(),
    )
    .expect("consumer");
    let wrong_secret = SecretReference::new(
        "netsuite-repair-wrong-secret",
        &fixture.scope,
        revision(3),
        hartevo_netsuite_accounting_result_plugin::NetSuiteAuthKind::OAuth2,
    )
    .expect("wrong secret shape");
    assert!(
        MissionNetSuiteAccountingConsumer::new_with_secret(
            fixture.scope.clone(),
            wrong_secret,
            service.registration().clone(),
        )
        .is_err()
    );

    let mut accounting_flags = proposal.clone();
    accounting_flags.connected = true;
    assert!(consumer.validate_only(&accounting_flags).is_err());

    let mut accounting_provider = proposal.clone();
    accounting_provider.provider_id = "untrusted-provider".to_owned();
    assert!(consumer.validate_only(&accounting_provider).is_err());

    let mut accounting_revision = proposal;
    accounting_revision.evidence.receipts[0].provider_revision =
        "suitetalk-foreign-revision".to_owned();
    assert!(consumer.validate_only(&accounting_revision).is_err());

    let suiteql = service
        .compile_parameterized_suiteql_proposal(
            vec![NetSuiteSuiteQlField::InternalId],
            NetSuiteBounds::default(),
            fixture.window.clone(),
            at(),
        )
        .expect("SuiteQL proposal");
    let mut suiteql_flags = suiteql.clone();
    suiteql_flags.native = true;
    assert!(consumer.validate_suiteql_only(&suiteql_flags).is_err());

    let mut suiteql_authority = suiteql.clone();
    suiteql_authority.outcome_authority = true;
    assert!(consumer.validate_suiteql_only(&suiteql_authority).is_err());

    let mut suiteql_provider = suiteql;
    suiteql_provider.provider_definition_digest = Digest::from_text("tampered-provider-definition");
    assert!(consumer.validate_suiteql_only(&suiteql_provider).is_err());
}

#[test]
fn revocation_and_replay_fences_are_monotonic_across_clones_and_consumers() {
    let fixture = fixture();
    let provider = NetSuiteSuiteTalkProvider::new(
        FixtureNetSuiteTransport::new(fixture.snapshot.clone()),
        "suitetalk-replay-r1",
        NetSuiteTransportProvenance::Fixture,
    )
    .expect("provider");
    let mut service = NetSuiteAccountingResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
    )
    .expect("service");
    let proposal = service.propose(request(&fixture), at()).expect("proposal");
    let registration = service.registration().clone();
    let mut first =
        MissionNetSuiteAccountingConsumer::new(fixture.scope.clone(), registration.clone())
            .expect("first consumer");
    let mut second = MissionNetSuiteAccountingConsumer::new(fixture.scope.clone(), registration)
        .expect("cloned-registration consumer");
    let fresh_provider = NetSuiteSuiteTalkProvider::new(
        FixtureNetSuiteTransport::new(fixture.snapshot.clone()),
        "suitetalk-recording-r1",
        NetSuiteTransportProvenance::Fixture,
    )
    .expect("fresh provider");
    let fresh_service = NetSuiteAccountingResultService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        fresh_provider,
    )
    .expect("fresh registration service");
    let mut fresh_consumer = MissionNetSuiteAccountingConsumer::new(
        fixture.scope.clone(),
        fresh_service.registration().clone(),
    )
    .expect("fresh consumer");
    assert!(fresh_consumer.consume(proposal.clone()).is_err());
    first.consume(proposal.clone()).expect("first consume");
    assert!(second.consume(proposal).is_err());

    let revocation_secret = SecretReference::new(
        "netsuite-repair-revocation-secret",
        &fixture.scope,
        revision(3),
        hartevo_netsuite_accounting_result_plugin::NetSuiteAuthKind::OAuth2,
    )
    .expect("revocation secret");
    let revocation_secret_clone = revocation_secret.clone();
    let revocation_provider = NetSuiteSuiteTalkProvider::new(
        FixtureNetSuiteTransport::new(fixture.snapshot),
        "suitetalk-revocation-r1",
        NetSuiteTransportProvenance::Fixture,
    )
    .expect("revocation provider");
    let mut revocation_service = NetSuiteAccountingResultService::new(
        fixture.scope.clone(),
        revocation_secret,
        revocation_provider,
    )
    .expect("revocation service");
    revocation_service.revoke_secret().expect("revoke secret");
    assert!(revocation_secret_clone.is_revoked());
    assert!(
        SecretReference::new(
            "netsuite-repair-revocation-secret",
            &fixture.scope,
            revision(3),
            hartevo_netsuite_accounting_result_plugin::NetSuiteAuthKind::OAuth2,
        )
        .is_err()
    );

    let mut registration_clone = revocation_service.registration().clone();
    registration_clone
        .revoke()
        .expect("revoke cloned registration");
    assert!(!revocation_service.registration().is_active());
}

#[test]
fn provider_revision_and_observation_window_bounds_fail_closed() {
    let fixture = fixture();
    let outside_timestamp = fixture.window.end() + Duration::seconds(1);
    let outside_filter = CollectionFilter::new(
        CollectionFilterField::LastModifiedDate,
        CollectionFilterOperator::OnOrAfter,
        CollectionFilterValue::Timestamp(outside_timestamp),
    )
    .expect("filter shape");
    assert!(outside_filter.validate_for_window(&fixture.window).is_err());

    let outside_metadata = NetSuiteRecordMetadata::new(
        NetSuiteRecordType::Invoice,
        vec![NetSuiteSafeRecordField::RecordType],
        revision(30),
        outside_timestamp,
    )
    .expect("metadata shape");
    assert!(
        NetSuiteSnapshot::new(
            &fixture.scope,
            &fixture.secret,
            "suitetalk-window-r1",
            Some(outside_metadata),
            Vec::new(),
            Vec::new(),
            None,
        )
        .is_err()
    );

    assert!(
        NetSuiteSnapshot::new(
            &fixture.scope,
            &fixture.secret,
            "r".repeat(65),
            None,
            Vec::new(),
            Vec::new(),
            None,
        )
        .is_err()
    );

    let mut mismatched_provider = NetSuiteSuiteTalkProvider::new(
        FixtureNetSuiteTransport::new(fixture.snapshot.clone()),
        "registered-provider-revision",
        NetSuiteTransportProvenance::Fixture,
    )
    .expect("provider with registered revision");
    let metadata_request = NetSuiteGetRequest::new(
        &fixture.scope,
        &fixture.secret,
        NetSuiteReadOperation::RecordMetadata,
        NetSuiteBounds::default(),
        fixture.window.clone(),
        1,
        None,
    )
    .expect("metadata request");
    assert!(matches!(
        mismatched_provider.read(&metadata_request, NetSuiteBounds::default()),
        Err(NetSuiteProviderError::RevisionMismatch)
    ));
}
