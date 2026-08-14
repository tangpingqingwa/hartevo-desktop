#![allow(clippy::too_many_arguments, clippy::too_many_lines)]

use std::collections::BTreeMap;

use hartevo_aws_cost_explorer_outcome_plugin::{
    AccountId, AwsAccountBinding, AwsCostExplorerOutcomeService, AwsCostExplorerProposal,
    AwsCostExplorerProvider, AwsCostExplorerScope, AwsCostExplorerServiceError, AwsOperation,
    AwsRegion, BillingViewArn, BlockedEnvAwsCostExplorerTransport, CostControlObjective,
    CostFilter, CostGroup, CostMetric, CostResultByTime, CostUsagePage, CostUsageProposalRequest,
    Date, Digest, DimensionKey, DimensionValue, DimensionValuesPage,
    DimensionValuesProposalRequest, EvidenceBinding, EvidenceBounds, EvidenceState, FilterClause,
    ForecastPoint, Granularity, GroupDefinition, MatchOption, MetricMap, MetricValue,
    MissionAwsCostConsumer, MissionId, NextMissionStep, ObjectiveId, OpaqueNextPageToken,
    PermissionId, PermissionRegistration, ProjectId, ProviderProvenance,
    RecordingAwsCostExplorerTransport, Revision, SecretReference, TagKey, TimePeriod,
    TransportError, UsageForecastProposalRequest, UsageForecastResponse, WorkProductId,
};

type RecordingProvider = AwsCostExplorerProvider<RecordingAwsCostExplorerTransport>;
type RecordingService = AwsCostExplorerOutcomeService<RecordingProvider>;

fn period(start: &str, end: &str) -> TimePeriod {
    TimePeriod::new(Date::new(start).unwrap(), Date::new(end).unwrap()).unwrap()
}

fn objective() -> CostControlObjective {
    CostControlObjective::reduce_spend(
        ObjectiveId::new("spend-objective").unwrap(),
        CostMetric::BlendedCost,
    )
}

fn fixture() -> (AwsCostExplorerScope, RecordingService) {
    let permission = PermissionRegistration::readonly_default(
        PermissionId::new("aws-read").unwrap(),
        Revision::new(1).unwrap(),
    )
    .unwrap();
    let scope = AwsCostExplorerScope::new(
        ProjectId::new("project-1").unwrap(),
        MissionId::new("mission-1").unwrap(),
        WorkProductId::new("work-product-1").unwrap(),
        Revision::new(7).unwrap(),
        AwsAccountBinding::account(AccountId::new("123456789012").unwrap()),
        permission.permission_digest().clone(),
        Digest::from_text("consent-v1"),
    );
    let secret = SecretReference::new(
        "aws-keyring-ref",
        &scope,
        Revision::new(3).unwrap(),
        AwsRegion::new("us-east-1").unwrap(),
    )
    .unwrap();
    let provider = AwsCostExplorerProvider::new(
        RecordingAwsCostExplorerTransport::default(),
        "1.0.0",
        ProviderProvenance::Recording,
    )
    .unwrap();
    let service =
        AwsCostExplorerOutcomeService::new(scope.clone(), secret, permission, provider).unwrap();
    (scope, service)
}

fn cost_request(period: TimePeriod) -> CostUsageProposalRequest {
    CostUsageProposalRequest::new(
        period,
        Granularity::Daily,
        [CostMetric::BlendedCost, CostMetric::BlendedCost],
        CostFilter::empty(),
        [],
        objective(),
    )
    .unwrap()
}

fn metric_map(amount: &str, unit: &str) -> MetricMap {
    let mut metrics = BTreeMap::new();
    metrics.insert(
        CostMetric::BlendedCost,
        MetricValue::new(amount, unit).unwrap(),
    );
    metrics
}

fn cost_page(
    binding: EvidenceBinding,
    period: TimePeriod,
    page_number: u8,
    group_by: Vec<GroupDefinition>,
    groups: Vec<CostGroup>,
    next_page_token: Option<OpaqueNextPageToken>,
    estimated: bool,
    incomplete: bool,
) -> CostUsagePage {
    CostUsagePage::new(
        binding,
        page_number,
        vec![CostMetric::BlendedCost],
        group_by,
        vec![CostResultByTime::new(
            period,
            estimated,
            metric_map("12.5000", "usd"),
            groups,
        )],
        next_page_token,
        estimated,
        incomplete,
    )
    .unwrap()
}

fn push_cost_page(
    service: &mut RecordingService,
    scope: &AwsCostExplorerScope,
    request: &CostUsageProposalRequest,
    page: CostUsagePage,
) {
    let _ = (scope, request);
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(page));
}

#[test]
fn inclusive_exclusive_period_and_metric_currency_normalization_are_bound() {
    let (scope, mut service) = fixture();
    let requested_period = period("2026-01-01", "2026-02-01");
    assert_eq!(requested_period.span_days(), 31);
    assert_eq!(
        CostMetric::parse("blended_costs").unwrap(),
        CostMetric::BlendedCost
    );
    let normalized = MetricValue::new("00012.5000", "usd").unwrap();
    assert_eq!(normalized.amount().as_str(), "12.5");
    assert_eq!(normalized.unit(), "USD");

    let request = cost_request(requested_period.clone());
    let binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    push_cost_page(
        &mut service,
        &scope,
        &request,
        cost_page(
            binding,
            requested_period.clone(),
            1,
            Vec::new(),
            Vec::new(),
            None,
            false,
            false,
        ),
    );
    let proposal = service.propose_cost_and_usage(request).unwrap();
    assert_eq!(proposal.state(), EvidenceState::Complete);
    assert_eq!(
        proposal.evidence.results_by_time[0].time_period,
        requested_period
    );
    assert_eq!(
        proposal.evidence.results_by_time[0]
            .total
            .get(&CostMetric::BlendedCost)
            .unwrap()
            .unit(),
        "USD"
    );
}

#[test]
fn bounded_group_and_tag_filters_are_normalized() {
    let (scope, mut service) = fixture();
    let service_key = DimensionKey::new("service").unwrap();
    let tag_key = TagKey::new("Environment").unwrap();
    let filter = CostFilter::new([
        FilterClause::dimension(service_key.clone(), ["Amazon S3"], MatchOption::Equals).unwrap(),
        FilterClause::tag(tag_key.clone(), ["prod"], MatchOption::CaseSensitive).unwrap(),
    ])
    .unwrap();
    let request = CostUsageProposalRequest::new(
        period("2026-01-01", "2026-01-02"),
        Granularity::Daily,
        [CostMetric::UnblendedCost],
        filter,
        [
            GroupDefinition::dimension(service_key),
            GroupDefinition::tag(tag_key),
        ],
        objective(),
    )
    .unwrap();
    let binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    let mut total = BTreeMap::new();
    total.insert(
        CostMetric::UnblendedCost,
        MetricValue::new("2", "USD").unwrap(),
    );
    let page = CostUsagePage::new(
        binding,
        1,
        vec![CostMetric::UnblendedCost],
        request.group_by().to_vec(),
        vec![CostResultByTime::new(
            request.period().clone(),
            false,
            total.clone(),
            vec![CostGroup::new(["Amazon S3", "prod"], total)],
        )],
        None,
        false,
        false,
    )
    .unwrap();
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(page));
    let proposal = service.propose_cost_and_usage(request).unwrap();
    assert_eq!(proposal.state(), EvidenceState::Complete);
}

#[test]
fn opaque_page_tokens_detect_pagination_loops_and_incomplete_pages() {
    let (scope, mut service) = fixture();
    let request = cost_request(period("2026-01-01", "2026-01-03"));
    let token = OpaqueNextPageToken::new("opaque-next-token").unwrap();
    let binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    let first = cost_page(
        binding.clone(),
        request.period().clone(),
        1,
        Vec::new(),
        Vec::new(),
        Some(token.clone()),
        false,
        false,
    );
    let second = cost_page(
        binding,
        request.period().clone(),
        2,
        Vec::new(),
        Vec::new(),
        Some(token.clone()),
        false,
        true,
    );
    assert!(!format!("{token:?}").contains("opaque-next-token"));
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(first));
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(second));
    let proposal = service.propose_cost_and_usage(request).unwrap();
    assert_eq!(proposal.state(), EvidenceState::Partial);
    assert_eq!(
        proposal.evidence.partial_reason,
        Some(hartevo_aws_cost_explorer_outcome_plugin::PartialReason::PaginationLoop)
    );
    assert!(proposal.is_incomplete());
}

#[test]
fn bounded_group_caps_project_partial_without_unbounded_detail() {
    let (scope, mut service) = fixture();
    let service_key = DimensionKey::new("SERVICE").unwrap();
    let request = CostUsageProposalRequest::new(
        period("2026-01-01", "2026-01-02"),
        Granularity::Daily,
        [CostMetric::BlendedCost],
        CostFilter::empty(),
        [GroupDefinition::dimension(service_key)],
        objective(),
    )
    .unwrap()
    .with_bounds(EvidenceBounds::new(2, 1, 10, 10_000, 1).unwrap());
    let binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    let page = cost_page(
        binding,
        request.period().clone(),
        1,
        request.group_by().to_vec(),
        vec![
            CostGroup::new(["Amazon S3"], metric_map("1", "USD")),
            CostGroup::new(["Amazon EC2"], metric_map("2", "USD")),
        ],
        None,
        false,
        false,
    );
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(page));
    let proposal = service.propose_cost_and_usage(request).unwrap();
    assert_eq!(proposal.state(), EvidenceState::Partial);
    assert_eq!(proposal.evidence.results_by_time[0].groups.len(), 1);
    assert!(proposal.evidence.truncated);
}

#[test]
fn forecast_horizon_and_forecast_unavailable_are_typed() {
    let too_long = UsageForecastProposalRequest::new(
        period("2026-01-01", "2026-04-10"),
        Granularity::Daily,
        CostMetric::BlendedCost,
        CostFilter::empty(),
        Some(80),
        objective(),
    );
    assert!(too_long.is_err());

    let (scope, mut service) = fixture();
    let request = UsageForecastProposalRequest::new(
        period("2026-03-01", "2026-04-01"),
        Granularity::Daily,
        CostMetric::BlendedCost,
        CostFilter::empty(),
        Some(80),
        objective(),
    )
    .unwrap();
    service
        .provider_mut()
        .transport_mut()
        .push_usage_forecast_response(Err(TransportError::invalid_request()));
    let proposal = service.propose_usage_forecast(request).unwrap();
    assert_eq!(proposal.state(), EvidenceState::ForecastUnavailable);
    assert!(!proposal.is_forecast_available());
    assert_eq!(proposal.evidence.provider_errors[0].status_code, Some(400));
    let _ = scope;
}

#[test]
fn forecast_evidence_is_estimated_and_digest_fenced() {
    let (scope, mut service) = fixture();
    let request = UsageForecastProposalRequest::new(
        period("2026-03-01", "2026-04-01"),
        Granularity::Daily,
        CostMetric::BlendedCost,
        CostFilter::empty(),
        Some(90),
        objective(),
    )
    .unwrap();
    let binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    let response = UsageForecastResponse::new(
        binding,
        request.horizon().clone(),
        Granularity::Daily,
        CostMetric::BlendedCost,
        vec![ForecastPoint::new(
            period("2026-03-01", "2026-03-02"),
            MetricValue::new("15.00", "usd").unwrap(),
            Some(MetricValue::new("10", "USD").unwrap()),
            Some(MetricValue::new("20", "USD").unwrap()),
        )],
        MetricValue::new("465", "USD").unwrap(),
        false,
    )
    .unwrap();
    service
        .provider_mut()
        .transport_mut()
        .push_usage_forecast_response(Ok(response));
    let proposal = service.propose_usage_forecast(request).unwrap();
    assert_eq!(proposal.state(), EvidenceState::Estimated);
    assert!(proposal.is_forecast_available());
    assert_eq!(proposal.evidence.total.amount().as_str(), "465");
}

#[test]
fn dimension_values_are_bounded_and_page_digested() {
    let (scope, mut service) = fixture();
    let request = DimensionValuesProposalRequest::new(
        period("2026-01-01", "2026-02-01"),
        DimensionKey::new("SERVICE").unwrap(),
        CostFilter::empty(),
        25,
        Some("Amazon".to_owned()),
        objective(),
    )
    .unwrap();
    let binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    let value = DimensionValue::new("Amazon S3", BTreeMap::new()).unwrap();
    let page = DimensionValuesPage::new(
        binding,
        request.period().clone(),
        request.dimension().clone(),
        vec![value],
        None,
        Some(1),
    )
    .unwrap();
    service
        .provider_mut()
        .transport_mut()
        .push_dimension_values_response(Ok(page));
    let proposal = service.propose_dimension_values(request).unwrap();
    assert_eq!(proposal.state(), EvidenceState::Complete);
    assert_eq!(proposal.evidence.values.len(), 1);
}

#[test]
fn error_families_retries_and_access_loss_are_projected_without_raw_diagnostics() {
    for (error, expected) in [
        (
            TransportError::invalid_request(),
            EvidenceState::ProviderUnknown,
        ),
        (
            TransportError::rate_limited(),
            EvidenceState::ProviderUnknown,
        ),
        (TransportError::timeout(), EvidenceState::ProviderUnknown),
        (
            TransportError::server_failure(),
            EvidenceState::ProviderUnknown,
        ),
        (TransportError::access_denied(), EvidenceState::AccessLoss),
        (TransportError::not_found(), EvidenceState::AccessLoss),
    ] {
        let (scope, mut service) = fixture();
        let request = cost_request(period("2026-01-01", "2026-01-02"));
        for _ in 0..3 {
            service
                .provider_mut()
                .transport_mut()
                .push_cost_and_usage_response(Err(error.clone()));
        }
        let proposal = service.propose_cost_and_usage(request).unwrap();
        assert_eq!(proposal.state(), expected);
        assert!(!proposal.evidence.provider_errors.is_empty());
        assert!(!format!("{:?}", proposal.evidence.provider_errors[0]).contains("invalid-request"));
        let _ = scope;
    }
}

#[test]
fn blocked_environment_is_provider_unknown_and_not_native() {
    let permission = PermissionRegistration::readonly_default(
        PermissionId::new("aws-read").unwrap(),
        Revision::new(1).unwrap(),
    )
    .unwrap();
    let scope = AwsCostExplorerScope::new(
        ProjectId::new("project-1").unwrap(),
        MissionId::new("mission-1").unwrap(),
        WorkProductId::new("work-product-1").unwrap(),
        Revision::new(7).unwrap(),
        AwsAccountBinding::account(AccountId::new("123456789012").unwrap()),
        permission.permission_digest().clone(),
        Digest::from_text("consent-v1"),
    );
    let secret = SecretReference::new(
        "aws-keyring-ref",
        &scope,
        Revision::new(3).unwrap(),
        AwsRegion::new("us-east-1").unwrap(),
    )
    .unwrap();
    let provider = AwsCostExplorerProvider::new(
        BlockedEnvAwsCostExplorerTransport,
        "1.0.0",
        ProviderProvenance::BlockedEnv,
    )
    .unwrap();
    let mut service =
        AwsCostExplorerOutcomeService::new(scope, secret, permission, provider).unwrap();
    let proposal = service
        .propose_cost_and_usage(cost_request(period("2026-01-01", "2026-01-02")))
        .unwrap();
    assert_eq!(proposal.state(), EvidenceState::ProviderUnknown);
    assert_eq!(
        service.provider_definition().provenance(),
        ProviderProvenance::BlockedEnv
    );
    assert!(!service.provider_definition().native());
}

#[test]
fn account_and_revision_drift_fail_closed_and_secret_revocation_closes_slice() {
    let (scope, mut service) = fixture();
    let request = cost_request(period("2026-01-01", "2026-01-02"));
    let mut binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    binding.account_or_billing_view =
        AwsAccountBinding::account(AccountId::new("999999999999").unwrap());
    let page = cost_page(
        binding,
        request.period().clone(),
        1,
        Vec::new(),
        Vec::new(),
        None,
        false,
        false,
    );
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(page));
    let drift = service.propose_cost_and_usage(request.clone()).unwrap_err();
    assert_eq!(drift, AwsCostExplorerServiceError::AccountDrift);

    service.revoke_secret().unwrap();
    assert_eq!(
        service.propose_cost_and_usage(request).unwrap_err(),
        AwsCostExplorerServiceError::SecretRevoked
    );
}

#[test]
fn tampered_pages_are_rejected_and_secret_and_token_debug_are_redacted() {
    let (scope, mut service) = fixture();
    let request = cost_request(period("2026-01-01", "2026-01-02"));
    let binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    let mut page = cost_page(
        binding,
        request.period().clone(),
        1,
        Vec::new(),
        Vec::new(),
        None,
        false,
        false,
    );
    page.page_digest = Digest::from_text("tampered-page");
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(page));
    assert_eq!(
        service.propose_cost_and_usage(request).unwrap_err(),
        AwsCostExplorerServiceError::TamperedEvidence
    );
    assert!(!format!("{:?}", service.secret_reference()).contains("aws-keyring-ref"));
    assert!(
        !format!(
            "{:?}",
            OpaqueNextPageToken::new("sensitive-provider-token").unwrap()
        )
        .contains("sensitive-provider-token")
    );
}

#[test]
fn billing_view_and_mission_revision_drift_are_distinct_fences() {
    let permission = PermissionRegistration::readonly_default(
        PermissionId::new("aws-read").unwrap(),
        Revision::new(1).unwrap(),
    )
    .unwrap();
    let scope = AwsCostExplorerScope::new(
        ProjectId::new("project-1").unwrap(),
        MissionId::new("mission-1").unwrap(),
        WorkProductId::new("work-product-1").unwrap(),
        Revision::new(7).unwrap(),
        AwsAccountBinding::billing_view(
            BillingViewArn::new("arn:aws:billing::123456789012:billingview/view-1").unwrap(),
        ),
        permission.permission_digest().clone(),
        Digest::from_text("consent-v1"),
    );
    let secret = SecretReference::new(
        "aws-keyring-ref",
        &scope,
        Revision::new(3).unwrap(),
        AwsRegion::new("us-east-1").unwrap(),
    )
    .unwrap();
    let provider = AwsCostExplorerProvider::new(
        RecordingAwsCostExplorerTransport::default(),
        "1.0.0",
        ProviderProvenance::Recording,
    )
    .unwrap();
    let mut service =
        AwsCostExplorerOutcomeService::new(scope.clone(), secret, permission, provider).unwrap();
    let request = cost_request(period("2026-01-01", "2026-01-02"));
    let mut binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    binding.account_or_billing_view = AwsAccountBinding::billing_view(
        BillingViewArn::new("arn:aws:billing::123456789012:billingview/view-2").unwrap(),
    );
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(cost_page(
            binding,
            request.period().clone(),
            1,
            Vec::new(),
            Vec::new(),
            None,
            false,
            false,
        )));
    assert_eq!(
        service.propose_cost_and_usage(request).unwrap_err(),
        AwsCostExplorerServiceError::BillingViewDrift
    );

    let (scope, mut service) = fixture();
    let request = cost_request(period("2026-01-01", "2026-01-02"));
    let mut binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    binding.mission_revision = Revision::new(8).unwrap();
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(cost_page(
            binding,
            request.period().clone(),
            1,
            Vec::new(),
            Vec::new(),
            None,
            false,
            false,
        )));
    assert_eq!(
        service.propose_cost_and_usage(request).unwrap_err(),
        AwsCostExplorerServiceError::MissionRevisionDrift
    );
}

#[test]
fn registration_revoke_and_consumer_duplicate_replay_are_reversible_and_idempotent() {
    let (scope, mut service) = fixture();
    let request = cost_request(period("2026-01-01", "2026-01-02"));
    let binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    let page = cost_page(
        binding,
        request.period().clone(),
        1,
        Vec::new(),
        Vec::new(),
        None,
        true,
        false,
    );
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(page.clone()));
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(page));
    let first = service.propose_cost_and_usage(request.clone()).unwrap();
    let second = service.propose_cost_and_usage(request).unwrap();
    assert_eq!(first.proposal_digest(), second.proposal_digest());

    let mut consumer = MissionAwsCostConsumer::new(&scope, service.registration());
    let first_decision = consumer
        .consume(&AwsCostExplorerProposal::CostAndUsage(first))
        .unwrap();
    let second_decision = consumer
        .consume(&AwsCostExplorerProposal::CostAndUsage(second))
        .unwrap();
    assert_eq!(
        first_decision.decision_digest(),
        second_decision.decision_digest()
    );
    assert!(first_decision.requires_review);
    assert!(!first_decision.is_adopted_outcome());
    assert_eq!(
        first_decision.next_step,
        NextMissionStep::ReviewSpendEvidence
    );

    service.revoke_registration().unwrap();
    assert_eq!(
        service
            .propose_cost_and_usage(cost_request(period("2026-01-01", "2026-01-02")))
            .unwrap_err(),
        AwsCostExplorerServiceError::RegistrationRevoked
    );
}

#[test]
fn resource_reads_require_explicit_operation_and_ec2_resource_filter() {
    let permission = PermissionRegistration::new(
        PermissionId::new("aws-resource-read").unwrap(),
        [
            AwsOperation::GetCostAndUsage,
            AwsOperation::GetCostAndUsageWithResources,
        ],
        Revision::new(1).unwrap(),
    )
    .unwrap();
    let scope = AwsCostExplorerScope::new(
        ProjectId::new("project-1").unwrap(),
        MissionId::new("mission-1").unwrap(),
        WorkProductId::new("work-product-1").unwrap(),
        Revision::new(7).unwrap(),
        AwsAccountBinding::account(AccountId::new("123456789012").unwrap()),
        permission.permission_digest().clone(),
        Digest::from_text("consent-v1"),
    );
    let secret = SecretReference::new(
        "aws-keyring-ref",
        &scope,
        Revision::new(3).unwrap(),
        AwsRegion::new("us-east-1").unwrap(),
    )
    .unwrap();
    let provider = AwsCostExplorerProvider::new_with_operations(
        RecordingAwsCostExplorerTransport::default(),
        "1.0.0",
        ProviderProvenance::Loopback,
        [
            AwsOperation::GetCostAndUsage,
            AwsOperation::GetCostAndUsageWithResources,
        ],
    )
    .unwrap();
    let mut service =
        AwsCostExplorerOutcomeService::new(scope.clone(), secret, permission, provider).unwrap();
    let resource_key = DimensionKey::new("RESOURCE_ID").unwrap();
    let request_without_service = CostUsageProposalRequest::new(
        period("2026-01-01", "2026-01-02"),
        Granularity::Daily,
        [CostMetric::BlendedCost],
        CostFilter::new([FilterClause::dimension(
            resource_key.clone(),
            ["i-abc"],
            MatchOption::Equals,
        )
        .unwrap()])
        .unwrap(),
        [GroupDefinition::dimension(resource_key.clone())],
        objective(),
    )
    .unwrap()
    .with_resource_detail();
    assert_eq!(
        service
            .propose_cost_and_usage(request_without_service)
            .unwrap_err(),
        AwsCostExplorerServiceError::ResourceOperationNotAllowlisted
    );

    let filter = CostFilter::new([
        FilterClause::dimension(
            DimensionKey::new("SERVICE").unwrap(),
            ["Amazon Elastic Compute Cloud - Compute"],
            MatchOption::Equals,
        )
        .unwrap(),
        FilterClause::dimension(resource_key.clone(), ["i-abc"], MatchOption::Equals).unwrap(),
    ])
    .unwrap();
    let request = CostUsageProposalRequest::new(
        period("2026-01-01", "2026-01-02"),
        Granularity::Daily,
        [CostMetric::BlendedCost],
        filter,
        [GroupDefinition::dimension(resource_key)],
        objective(),
    )
    .unwrap()
    .with_resource_detail();
    let binding = EvidenceBinding::new(
        &scope,
        service.registration().registration_digest(),
        request.query_digest(&scope),
    );
    let page = cost_page(
        binding,
        request.period().clone(),
        1,
        request.group_by().to_vec(),
        vec![CostGroup::new(["i-abc"], metric_map("3", "USD"))],
        None,
        false,
        false,
    );
    service
        .provider_mut()
        .transport_mut()
        .push_cost_and_usage_response(Ok(page));
    assert_eq!(
        service.propose_cost_and_usage(request).unwrap().state(),
        EvidenceState::Complete
    );
}
