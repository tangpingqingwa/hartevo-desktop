use std::collections::BTreeMap;

use crate::{
    AccountId, AggregateValue, CampaignFlowMetadata, CostEvidence, CurrencyCode, DeliveryState,
    Digest, KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION, KlaviyoCampaignOutcomeService,
    KlaviyoOutcomeRequest, KlaviyoPermission, KlaviyoProvider, KlaviyoScope, Layer1Authority,
    MessageChannel, MetricId, MetricSelection, MissionKlaviyoCampaignConsumer, ModelError,
    OpaquePageCursor, PermissionSnapshot, ProviderProvenance, ReportKind, ReportPage, ReportWindow,
    ResourceId, ResourceKind, Revision, ScopeRevisions, SecretKind, SecretReference,
    SeriesInterval, Statistic, Timeframe, TransportError, VariationSelector,
};
use crate::{RecordingKlaviyoTransport, provider::CampaignMetadataResponse};

struct Fixture {
    scope: KlaviyoScope,
    secret: SecretReference,
    metadata: CampaignMetadataResponse,
    report_digest: Digest,
    row: crate::ReportRow,
    currency: CurrencyCode,
}

fn new_fixture() -> Fixture {
    let project_id = crate::ProjectId::new("project-1").expect("project");
    let account_id = AccountId::new("account-1").expect("account");
    let resource = ResourceId::campaign("campaign-1").expect("campaign");
    let metric_id = MetricId::new("purchase").expect("metric");
    let metrics = MetricSelection::new([
        Statistic::Opens,
        Statistic::OpenRate,
        Statistic::Clicks,
        Statistic::Conversions,
        Statistic::ConversionRate,
        Statistic::TextMessageSpend,
    ])
    .expect("metrics")
    .with_conversion_metric(&metric_id);
    let window = ReportWindow::new(1_700_000_000_u64, 1_700_086_400_u64, SeriesInterval::Day)
        .expect("window");
    let revisions = ScopeRevisions::new(
        Revision::new(11).expect("project revision"),
        Revision::new(12).expect("mission revision"),
        Revision::new(13).expect("work product revision"),
        Revision::new(14).expect("account revision"),
        Revision::new(15).expect("resource revision"),
    );
    let permissions = PermissionSnapshot::new(
        SecretKind::OAuth,
        account_id.clone(),
        KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION,
        [
            KlaviyoPermission::CampaignsRead,
            KlaviyoPermission::MetricsRead,
        ],
        revisions.account_revision,
    )
    .expect("permissions");
    let scope = KlaviyoScope::new(
        project_id,
        account_id.clone(),
        resource.clone(),
        crate::MissionId::new("mission-1").expect("mission"),
        crate::WorkProductId::new("work-product-1").expect("work product"),
        revisions,
        KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION,
        metrics,
        window,
        VariationSelector::All,
        permissions,
        Digest::from_text("consent-scope-v1"),
    )
    .expect("scope");
    let secret = SecretReference::new("opaque-secret-reference", &scope, 21, SecretKind::OAuth)
        .expect("secret");
    let metadata = CampaignMetadataResponse::new(
        account_id,
        CampaignFlowMetadata::new(resource, DeliveryState::Sent, scope.resource_revision()),
        scope.fence(),
        crate::RedactionEvidence::new(2, 1),
    );
    let report_request =
        crate::provider::ReportRequest::from_scope(&scope, &secret, ReportKind::Values, 10, 4)
            .expect("report request");
    let currency = CurrencyCode::new("USD").expect("currency");
    let row = crate::ReportRow::new(
        None,
        Some(MessageChannel::Email),
        [
            (Statistic::Opens, AggregateValue::count(80)),
            (
                Statistic::OpenRate,
                AggregateValue::rate(80, 100).expect("open rate"),
            ),
            (Statistic::Clicks, AggregateValue::count(12)),
            (Statistic::Conversions, AggregateValue::count(3)),
            (
                Statistic::ConversionRate,
                AggregateValue::rate(3, 12).expect("conversion rate"),
            ),
            (
                Statistic::TextMessageSpend,
                AggregateValue::money(275, currency.clone()),
            ),
        ],
    )
    .expect("row");
    Fixture {
        scope,
        secret,
        metadata,
        report_digest: report_request.report_digest().clone(),
        row,
        currency,
    }
}

fn page(
    fixture: &Fixture,
    page_number: u8,
    rows: Vec<crate::ReportRow>,
    next_cursor: Option<OpaquePageCursor>,
    complete: bool,
    no_data: bool,
    expired: bool,
) -> ReportPage {
    page_for(
        fixture,
        ReportKind::Values,
        fixture.report_digest.clone(),
        page_number,
        rows,
        next_cursor,
        complete,
        no_data,
        expired,
    )
}

fn page_for(
    fixture: &Fixture,
    report_kind: ReportKind,
    report_digest: Digest,
    page_number: u8,
    rows: Vec<crate::ReportRow>,
    next_cursor: Option<OpaquePageCursor>,
    complete: bool,
    no_data: bool,
    expired: bool,
) -> ReportPage {
    ReportPage::new(
        report_kind,
        fixture.scope.account_id.clone(),
        fixture.scope.resource.clone(),
        report_digest,
        page_number,
        rows,
        next_cursor,
        complete,
        no_data,
        expired,
        fixture.scope.fence(),
        fixture.scope.window.window_digest.clone(),
        fixture.scope.metrics.metric_digest.clone(),
        fixture.scope.variation.digest(),
        CostEvidence::new(
            1,
            4,
            1,
            Some(120),
            fixture.scope.window.window_digest.clone(),
        )
        .expect("cost"),
        crate::RedactionEvidence::clean(),
    )
    .expect("page")
}

fn service_with(
    fixture: &Fixture,
    report_responses: impl IntoIterator<Item = Result<ReportPage, TransportError>>,
    provenance: ProviderProvenance,
) -> KlaviyoCampaignOutcomeService<KlaviyoProvider<RecordingKlaviyoTransport>> {
    service_with_kind(fixture, ReportKind::Values, report_responses, provenance)
}

fn service_with_kind(
    fixture: &Fixture,
    report_kind: ReportKind,
    report_responses: impl IntoIterator<Item = Result<ReportPage, TransportError>>,
    provenance: ProviderProvenance,
) -> KlaviyoCampaignOutcomeService<KlaviyoProvider<RecordingKlaviyoTransport>> {
    let mut transport = RecordingKlaviyoTransport::default();
    transport.push_metadata_response(Ok(fixture.metadata.clone()));
    for response in report_responses {
        match report_kind {
            ReportKind::Values => transport.push_values_response(response),
            ReportKind::Series => transport.push_series_response(response),
        }
    }
    let provider = KlaviyoProvider::new(transport, "1.0.0", provenance).expect("provider");
    KlaviyoCampaignOutcomeService::new(
        fixture.scope.clone(),
        fixture.secret.clone(),
        provider,
        crate::RetryPolicy::default(),
    )
    .expect("service")
}

#[test]
fn complete_values_report_projects_only_redacted_aggregates() {
    let fixture = new_fixture();
    let mut service = service_with(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![fixture.row.clone()],
            None,
            true,
            false,
            false,
        ))],
        ProviderProvenance::Recording,
    );
    let request = KlaviyoOutcomeRequest::values(&fixture.scope, 10, 4).expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.status(), crate::OutcomeProjection::Complete);
    assert_eq!(proposal.evidence.delivery_state, DeliveryState::Sent);
    assert_eq!(proposal.evidence.count(Statistic::Opens), Some(80));
    assert_eq!(proposal.evidence.count(Statistic::Clicks), Some(12));
    assert_eq!(proposal.evidence.count(Statistic::Conversions), Some(3));
    assert_eq!(proposal.evidence.spend(&fixture.currency), Some(275));
    assert_eq!(proposal.evidence.pages_observed, 1);
    assert_eq!(proposal.evidence.redaction.profile_fields_redacted, 2);
    assert!(!proposal.evidence.authority.connected);
    assert!(!proposal.evidence.authority.native);
    assert!(!proposal.evidence.authority.first_party);
    assert!(!proposal.is_adopted());
    assert!(!format!("{service:?}").contains("opaque-secret-reference"));
    assert!(!format!("{proposal:?}").contains("opaque-secret-reference"));
    assert!(!format!("{proposal:?}").contains("Holiday Sale"));

    let consumer =
        MissionKlaviyoCampaignConsumer::new(fixture.scope.clone(), service.registration())
            .expect("consumer");
    let outcome = consumer.consume(proposal).expect("Mission outcome");
    assert_eq!(outcome.state, crate::MissionOutcomeState::PendingDecision);
    assert!(!outcome.connected());
    assert!(!outcome.native());
    assert!(!outcome.first_party());
    assert!(!outcome.is_adopted());
}

#[test]
fn series_pagination_is_bounded_and_retries_are_recorded() {
    let fixture = new_fixture();
    let cursor = OpaquePageCursor::new("opaque-page-cursor").expect("cursor");
    let series_request = crate::provider::ReportRequest::from_scope(
        &fixture.scope,
        &fixture.secret,
        ReportKind::Series,
        10,
        4,
    )
    .expect("series request");
    let first = page_for(
        &fixture,
        ReportKind::Series,
        series_request.report_digest().clone(),
        1,
        vec![fixture.row.clone()],
        Some(cursor.clone()),
        false,
        false,
        false,
    );
    let second = page_for(
        &fixture,
        ReportKind::Series,
        series_request.report_digest().clone(),
        2,
        vec![fixture.row.clone()],
        None,
        true,
        false,
        false,
    );
    let mut service = service_with_kind(
        &fixture,
        ReportKind::Series,
        [Ok(first), Err(TransportError::rate_limited()), Ok(second)],
        ProviderProvenance::Loopback,
    );
    let request = KlaviyoOutcomeRequest::series(&fixture.scope, 10, 4).expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.status(), crate::OutcomeProjection::Complete);
    assert_eq!(proposal.evidence.pages_observed, 2);
    assert_eq!(proposal.evidence.rows_observed, 2);
    assert_eq!(proposal.evidence.retries.len(), 1);
    assert_eq!(proposal.evidence.retries[0].status_code, Some(429));
}

#[test]
fn stale_fence_and_tampered_page_fail_closed() {
    let fixture = new_fixture();
    let mut tampered = page(
        &fixture,
        1,
        vec![fixture.row.clone()],
        None,
        true,
        false,
        false,
    );
    tampered.observed_fence.project_revision = Revision::new(999).expect("revision");
    let mut service = service_with(&fixture, [Ok(tampered)], ProviderProvenance::Fake);
    let request = KlaviyoOutcomeRequest::values(&fixture.scope, 10, 4).expect("request");
    assert_eq!(
        service.propose(request).expect_err("fence drift"),
        crate::KlaviyoServiceError::TamperedEvidence
    );

    let fixture = new_fixture();
    let mut tampered = page(
        &fixture,
        1,
        vec![fixture.row.clone()],
        None,
        true,
        false,
        false,
    );
    tampered.page_digest = Digest::from_text("tampered-page");
    let mut service = service_with(&fixture, [Ok(tampered)], ProviderProvenance::Fixture);
    let request = KlaviyoOutcomeRequest::values(&fixture.scope, 10, 4).expect("request");
    assert_eq!(
        service.propose(request).expect_err("page tamper"),
        crate::KlaviyoServiceError::TamperedEvidence
    );
}

#[test]
fn repeated_cursor_is_rejected_and_bounds_are_enforced() {
    let fixture = new_fixture();
    let cursor = OpaquePageCursor::new("cursor-loop").expect("cursor");
    let first = page(
        &fixture,
        1,
        vec![fixture.row.clone()],
        Some(cursor.clone()),
        false,
        false,
        false,
    );
    let second = page(
        &fixture,
        2,
        vec![fixture.row.clone()],
        Some(cursor),
        false,
        false,
        false,
    );
    let mut service = service_with(
        &fixture,
        [Ok(first), Ok(second)],
        ProviderProvenance::Recording,
    );
    let request = KlaviyoOutcomeRequest::values(&fixture.scope, 10, 4).expect("request");
    assert_eq!(
        service.propose(request).expect_err("cursor loop"),
        crate::KlaviyoServiceError::PageLoop
    );
    assert!(matches!(
        ReportWindow::new(1_u64, 1_u64, SeriesInterval::Day),
        Err(ModelError::InvalidWindow)
    ));
    assert!(matches!(
        KlaviyoOutcomeRequest::values(&fixture.scope, 0, 4),
        Err(ModelError::InvalidReport)
    ));
}

#[test]
fn transport_failures_are_redacted_typed_and_non_native() {
    let failures = [
        TransportError::unauthorized(),
        TransportError::forbidden(),
        TransportError::not_found(),
        TransportError::conflict(),
        TransportError::rate_limited(),
        TransportError::server_failure(503),
        TransportError::timeout(),
        TransportError::blocked_env(),
    ];
    for failure in failures {
        let expected = if matches!(
            failure.kind,
            crate::ProviderErrorKind::NotFound404 | crate::ProviderErrorKind::Conflict409
        ) {
            crate::OutcomeProjection::NoData
        } else {
            crate::OutcomeProjection::ProviderUnknown
        };
        let fixture = new_fixture();
        let mut service = service_with(&fixture, [Err(failure)], ProviderProvenance::BlockedEnv);
        let request = KlaviyoOutcomeRequest::values(&fixture.scope, 10, 4).expect("request");
        let proposal = service.propose(request).expect("typed failure proposal");
        assert_eq!(proposal.status(), expected);
        assert!(!proposal.evidence.authority.connected);
        assert!(!proposal.evidence.authority.native);
        assert!(!proposal.evidence.authority.first_party);
        assert!(!proposal.evidence.provider_errors.is_empty());
    }
}

#[test]
fn no_data_expired_and_partial_are_explicit_states() {
    let fixture = new_fixture();
    let mut service = service_with(
        &fixture,
        [Ok(page(&fixture, 1, Vec::new(), None, true, true, false))],
        ProviderProvenance::Recording,
    );
    let request = KlaviyoOutcomeRequest::values(&fixture.scope, 10, 4).expect("request");
    assert_eq!(
        service.propose(request).expect("no data").status(),
        crate::OutcomeProjection::NoData
    );

    let fixture = new_fixture();
    let mut service = service_with(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![fixture.row.clone()],
            None,
            true,
            false,
            true,
        ))],
        ProviderProvenance::Recording,
    );
    let request = KlaviyoOutcomeRequest::values(&fixture.scope, 10, 4).expect("request");
    assert_eq!(
        service.propose(request).expect("expired").status(),
        crate::OutcomeProjection::Expired
    );

    let fixture = new_fixture();
    let cursor = OpaquePageCursor::new("missing-next-page").expect("cursor");
    let mut service = service_with(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![fixture.row.clone()],
            Some(cursor),
            false,
            false,
            false,
        ))],
        ProviderProvenance::Recording,
    );
    let request = KlaviyoOutcomeRequest::values(&fixture.scope, 1, 1).expect("request");
    assert_eq!(
        service.propose(request).expect("partial").status(),
        crate::OutcomeProjection::Partial
    );
}

#[test]
fn secret_registration_and_consumer_are_reversible() {
    let fixture = new_fixture();
    let mut service = service_with(
        &fixture,
        [Ok(page(
            &fixture,
            1,
            vec![fixture.row.clone()],
            None,
            true,
            false,
            false,
        ))],
        ProviderProvenance::Recording,
    );
    let mut consumer =
        MissionKlaviyoCampaignConsumer::new(fixture.scope.clone(), service.registration())
            .expect("consumer");
    assert!(consumer.is_active());
    consumer.unmount().expect("consumer unmount");
    assert!(!consumer.is_active());
    assert_eq!(
        consumer.unmount().expect_err("double unmount"),
        crate::ConsumerError::RegistrationRevoked
    );
    service.unmount().expect("service unmount");
    assert!(matches!(
        service.propose(KlaviyoOutcomeRequest::values(&fixture.scope, 10, 4).expect("request")),
        Err(crate::KlaviyoServiceError::RegistrationRevoked)
    ));

    let fixture = new_fixture();
    let mut service = service_with(&fixture, [], ProviderProvenance::Recording);
    service.revoke_secret().expect("secret revoke");
    assert!(matches!(
        service.propose(KlaviyoOutcomeRequest::values(&fixture.scope, 10, 4).expect("request")),
        Err(crate::KlaviyoServiceError::SecretRevoked)
    ));
}

#[test]
fn api_and_scope_types_reject_unbounded_or_opaque_leaks() {
    assert_eq!(Timeframe::Last30Days.label(), "last_30_days");
    assert_eq!(ResourceKind::Campaign.label(), "campaign");
    assert_eq!(
        ResourceId::flow("flow-1").expect("flow").kind(),
        ResourceKind::Flow
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::first_party());
    let cursor = OpaquePageCursor::new("secret-page-token").expect("cursor");
    assert!(!format!("{cursor:?}").contains("secret-page-token"));
    let scope = new_fixture().scope;
    assert!(scope.validate().is_ok());
    assert_eq!(scope.api_revision, KLAVIYO_CAMPAIGN_OUTCOME_API_REVISION);
}

#[test]
fn public_aggregate_json_contains_no_raw_content() {
    let fixture = new_fixture();
    let row = &fixture.row;
    let json = serde_json::to_string(row).expect("aggregate row serializes");
    assert!(!json.contains("opaque-secret-reference"));
    assert!(!json.contains("Holiday Sale"));
    let mut map = BTreeMap::new();
    map.insert(Statistic::Clicks, AggregateValue::count(1));
    assert_eq!(
        map.get(&Statistic::Clicks)
            .and_then(AggregateValue::as_count),
        Some(1)
    );
}
