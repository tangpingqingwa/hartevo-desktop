use std::fmt;

use super::*;

#[derive(Clone, Copy, Debug)]
enum FixtureMode {
    Complete,
    Empty,
    Partial,
    Truncated,
    Timeout,
    AccessLost,
    BlockedEnv,
    Unknown,
    Tampered,
    ResponseTooLarge,
    CostTooLarge,
    SchemaDrift,
}

#[derive(Clone, Debug)]
struct DynamicTransport {
    mode: FixtureMode,
}

impl fmt::Display for FixtureMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl AzureMonitorLogsTransport for DynamicTransport {
    fn query(
        &mut self,
        request: &AzureMonitorLogsRequest,
    ) -> Result<AzureMonitorLogsResponse, ProviderError> {
        match self.mode {
            FixtureMode::Timeout => Err(ProviderError::timeout()),
            FixtureMode::AccessLost => Err(ProviderError::access_lost()),
            FixtureMode::BlockedEnv => Err(ProviderError::blocked_env()),
            FixtureMode::Unknown => Err(ProviderError::unknown()),
            mode => {
                let category = ColumnName::new("Category").expect("safe fixture column");
                let count = ColumnName::new("count_").expect("safe fixture column");
                let schema = AggregateSchema::new(vec![
                    AggregateColumn::new(category, AggregateColumnType::Category, false)
                        .expect("safe category"),
                    AggregateColumn::new(
                        if matches!(mode, FixtureMode::SchemaDrift) {
                            ColumnName::new("different_count").expect("safe drift column")
                        } else {
                            count
                        },
                        AggregateColumnType::Integer,
                        false,
                    )
                    .expect("safe count"),
                ])
                .map_err(|_| ProviderError::malformed())?;
                let rows = if matches!(mode, FixtureMode::Empty) {
                    Vec::new()
                } else if matches!(mode, FixtureMode::ResponseTooLarge) {
                    (0..300)
                        .map(|index| {
                            AggregateRow::new(vec![
                                AggregateCell::Text(format!("category-{index}")),
                                AggregateCell::Integer(index),
                            ])
                        })
                        .collect()
                } else {
                    vec![AggregateRow::new(vec![
                        AggregateCell::Text("Administrative".to_owned()),
                        AggregateCell::Integer(3),
                    ])]
                };
                let status = match mode {
                    FixtureMode::Empty => ProviderResultStatus::Empty,
                    FixtureMode::Partial => ProviderResultStatus::Partial,
                    FixtureMode::Truncated | FixtureMode::ResponseTooLarge => {
                        ProviderResultStatus::Truncated
                    }
                    _ => ProviderResultStatus::Complete,
                };
                let response_bytes = if matches!(mode, FixtureMode::ResponseTooLarge) {
                    MAX_RESPONSE_BYTES + 1
                } else {
                    128
                };
                let cost = if matches!(mode, FixtureMode::CostTooLarge) {
                    MAX_COST_MICROUNITS + 1
                } else {
                    1
                };
                let mut response = AzureMonitorLogsResponse::for_request(
                    request,
                    status,
                    schema,
                    rows,
                    Some(3),
                    response_bytes,
                    10,
                    cost,
                    Revision::new(1).expect("valid provider revision"),
                )
                .map_err(|_| ProviderError::malformed())?;
                if matches!(mode, FixtureMode::Tampered) {
                    response.query_digest = Digest::from_text("tampered");
                }
                Ok(response)
            }
        }
    }
}

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn scope(table: &str) -> AzureMonitorLogsScope {
    AzureMonitorLogsScope::new(
        TenantId::new("tenant-1").expect("tenant"),
        SubscriptionId::new("subscription-1").expect("subscription"),
        WorkspaceId::new("workspace-1").expect("workspace"),
        TableName::new(table).expect("table"),
        ProjectId::new("project-1").expect("project"),
        Revision::new(7).expect("project revision"),
        MissionId::new("mission-1").expect("mission"),
        Revision::new(11).expect("mission revision"),
        WorkProductId::new("work-product-1").expect("work product"),
        Revision::new(13).expect("work product revision"),
        digest("permission"),
        digest("consent"),
    )
    .expect("scope")
}

fn template(table: &str) -> QueryTemplate {
    let category = ColumnName::new("Category").expect("category");
    QueryTemplate::new(
        QueryTemplateId::new("template-1").expect("template id"),
        TableName::new(table).expect("table"),
        ColumnName::new("TimeGenerated").expect("time column"),
        vec![category.clone()],
        vec![AggregateSpec::count(ColumnName::new("count_").expect("count alias")).expect("count")],
        vec![FilterClause::equals(
            category,
            ParameterName::new("category").expect("parameter name"),
        )],
    )
    .expect("template")
}

fn plan_for(table: &str) -> QueryPlan {
    QueryPlan::new(
        template(table),
        vec![
            QueryParameter::new(
                ParameterName::new("category").expect("parameter"),
                ParameterValue::Text("Administrative".to_owned()),
            )
            .expect("parameter"),
        ],
        TimeWindow::new("2026-08-01T00:00:00Z", "2026-08-01T01:00:00Z").expect("window"),
        QueryBounds::default(),
    )
    .expect("plan")
}

fn service(
    mode: FixtureMode,
) -> AzureMonitorLogsResultService<AzureMonitorLogsProvider<DynamicTransport>> {
    let scope = scope("AzureActivity");
    let secret = SecretReference::new("entra-ref-1", &scope, 4).expect("secret reference");
    let provider = AzureMonitorLogsProvider::new(
        DynamicTransport { mode },
        "1.0.0",
        ProviderProvenance::Fixture,
    )
    .expect("provider");
    AzureMonitorLogsResultService::new(scope, secret, provider, plan_for("AzureActivity"))
        .expect("service")
}

#[test]
fn secret_reference_is_opaque_and_scope_bound() {
    let scope = scope("AzureActivity");
    let secret =
        SecretReference::new("do-not-print-this-reference", &scope, 1).expect("secret reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("do-not-print-this-reference"));
    assert_eq!(secret.scope_digest(), &scope.scope_digest());
    assert_eq!(secret.credential_revision().get(), 1);
}

#[test]
fn query_ast_rejects_raw_kql_injection_and_user_identifiers() {
    assert!(ColumnName::new("user_id").is_err());
    assert!(
        ParameterValue::Text("x' | union SecretTable".to_owned())
            .validate()
            .is_err()
    );
    assert!(
        QueryTemplate::from_kql(
            QueryTemplateId::new("raw").expect("id"),
            TableName::new("AzureActivity").expect("table"),
            "AzureActivity | summarize count() | join SecretTable on id"
        )
        .is_err()
    );
    let dynamic_column = ColumnName::new("Properties");
    assert!(dynamic_column.is_err());
    let raw_schema = AggregateColumn::new(
        ColumnName::new("Category").expect("safe column"),
        AggregateColumnType::Dynamic,
        false,
    );
    assert!(raw_schema.is_err());
}

#[test]
fn query_and_parameter_digests_are_order_stable() {
    let category = ColumnName::new("Category").expect("category");
    let level = ColumnName::new("Level").expect("level");
    let template = QueryTemplate::new(
        QueryTemplateId::new("stable").expect("template"),
        TableName::new("AzureActivity").expect("table"),
        ColumnName::new("TimeGenerated").expect("time"),
        vec![category.clone()],
        vec![AggregateSpec::count(ColumnName::new("count_").expect("alias")).expect("count")],
        vec![
            FilterClause::equals(category, ParameterName::new("category").expect("name")),
            FilterClause::equals(level, ParameterName::new("level").expect("name")),
        ],
    )
    .expect("template");
    let window = TimeWindow::new("2026-08-01T00:00:00Z", "2026-08-01T01:00:00Z").expect("window");
    let first = QueryPlan::new(
        template.clone(),
        vec![
            QueryParameter::new(
                ParameterName::new("category").expect("name"),
                ParameterValue::Text("Administrative".to_owned()),
            )
            .expect("parameter"),
            QueryParameter::new(
                ParameterName::new("level").expect("name"),
                ParameterValue::Integer(2),
            )
            .expect("parameter"),
        ],
        window.clone(),
        QueryBounds::default(),
    )
    .expect("plan");
    let second = QueryPlan::new(
        template,
        vec![
            QueryParameter::new(
                ParameterName::new("level").expect("name"),
                ParameterValue::Integer(2),
            )
            .expect("parameter"),
            QueryParameter::new(
                ParameterName::new("category").expect("name"),
                ParameterValue::Text("Administrative".to_owned()),
            )
            .expect("parameter"),
        ],
        window,
        QueryBounds::default(),
    )
    .expect("plan");
    assert_eq!(first.parameter_digest(), second.parameter_digest());
    assert_eq!(first.query_digest(), second.query_digest());
}

#[test]
fn cross_workspace_and_time_or_bound_drift_fail_closed() {
    let mismatched_plan = plan_for("OtherWorkspaceTable");
    assert!(
        mismatched_plan
            .matches_scope(&scope("AzureActivity"))
            .is_err()
    );
    assert!(TimeWindow::new("2026-08-01T01:00:00Z", "2026-08-01T00:00:00Z").is_err());
    assert!(TimeWindow::new("2026-08-01T00:00:00Z", "2026-09-02T00:00:00Z").is_err());
    assert!(QueryBounds::new(0, 1, 1, 1).is_err());
    assert!(QueryBounds::new(1, MAX_RESPONSE_BYTES + 1, 1, 1).is_err());
}

#[test]
fn status_taxonomy_and_bounds_are_projected_without_unbounded_rows() {
    assert_eq!(
        service(FixtureMode::Complete)
            .query()
            .expect("query")
            .status,
        ResultStatus::Complete
    );
    assert_eq!(
        service(FixtureMode::Empty).query().expect("query").status,
        ResultStatus::Empty
    );
    assert_eq!(
        service(FixtureMode::Partial).query().expect("query").status,
        ResultStatus::Partial
    );
    assert_eq!(
        service(FixtureMode::Truncated)
            .query()
            .expect("query")
            .status,
        ResultStatus::Truncated
    );
    let too_large = service(FixtureMode::ResponseTooLarge)
        .query()
        .expect("query");
    assert_eq!(too_large.status, ResultStatus::Truncated);
    assert!(too_large.rows.len() <= MAX_RESPONSE_ROWS);
    assert_eq!(
        service(FixtureMode::CostTooLarge)
            .query()
            .expect("query")
            .status,
        ResultStatus::Truncated
    );
}

#[test]
fn provider_failures_have_separate_fail_closed_statuses() {
    assert_eq!(
        service(FixtureMode::Timeout).query().expect("query").status,
        ResultStatus::Timeout
    );
    assert_eq!(
        service(FixtureMode::AccessLost)
            .query()
            .expect("query")
            .status,
        ResultStatus::AccessLost
    );
    assert_eq!(
        service(FixtureMode::BlockedEnv)
            .query()
            .expect("query")
            .status,
        ResultStatus::ProviderUnknown
    );
    assert_eq!(
        service(FixtureMode::Unknown).query().expect("query").status,
        ResultStatus::ProviderUnknown
    );
}

#[test]
fn tampered_response_and_schema_drift_never_become_complete() {
    let result = service(FixtureMode::Tampered).query().expect("query");
    assert_eq!(result.status, ResultStatus::Tampered);
    assert!(!result.eligible_for_decision());
    let schema = AggregateSchema::new(vec![
        AggregateColumn::new(
            ColumnName::new("Category").expect("category"),
            AggregateColumnType::Category,
            false,
        )
        .expect("schema"),
    ])
    .expect("schema");
    let invalid_row = AggregateRow::new(vec![AggregateCell::Integer(1)]);
    assert!(invalid_row.validate_against(&schema).is_err());
    assert_eq!(
        service(FixtureMode::SchemaDrift)
            .query()
            .expect("query")
            .status,
        ResultStatus::Tampered
    );
}

#[test]
fn registration_is_reversible_revocable_and_digest_bound() {
    let mut service = service(FixtureMode::Complete);
    let first = service.registration().registration_digest.clone();
    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(reversed.current, RegistrationState::Reversed);
    assert_eq!(
        service.query().expect("query").status,
        ResultStatus::Revoked
    );
    let restored = service.restore_registration().expect("restore");
    assert_eq!(restored.current, RegistrationState::Active);
    assert_ne!(first, service.registration().registration_digest);
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service.query().expect("query").status,
        ResultStatus::Revoked
    );
    assert!(service.registration().validate_digest().is_ok());
}

#[test]
fn mission_consumer_rejects_stale_and_replayed_evidence() {
    let mut service = service(FixtureMode::Complete);
    let result = service.query().expect("query");
    let mut consumer = MissionAzureMonitorLogsConsumer::new(scope("AzureActivity"));
    let observation = consumer.consume(&result).expect("consume");
    assert!(observation.decision_eligible);
    assert!(!observation.adopted_outcome);
    assert!(matches!(
        consumer.consume(&result),
        Err(ConsumerError::Replay)
    ));

    let stale_scope = AzureMonitorLogsScope::new(
        TenantId::new("tenant-1").expect("tenant"),
        SubscriptionId::new("subscription-1").expect("subscription"),
        WorkspaceId::new("workspace-1").expect("workspace"),
        TableName::new("AzureActivity").expect("table"),
        ProjectId::new("project-1").expect("project"),
        Revision::new(7).expect("project revision"),
        MissionId::new("mission-1").expect("mission"),
        Revision::new(12).expect("stale mission revision"),
        WorkProductId::new("work-product-1").expect("work product"),
        Revision::new(13).expect("work product revision"),
        digest("permission"),
        digest("consent"),
    )
    .expect("stale scope");
    let mut stale_consumer = MissionAzureMonitorLogsConsumer::new(stale_scope);
    assert!(matches!(
        stale_consumer.consume(&result),
        Err(ConsumerError::StaleMission)
    ));
}

#[test]
fn every_layer_one_provenance_mode_is_non_native() {
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        assert_eq!(provenance_flags(provenance), (false, false, false));
    }
    let provider = AzureMonitorLogsProvider::blocked_env().expect("blocked provider");
    assert!(!provider.definition().connected);
    assert!(!provider.definition().native);
    assert!(!provider.definition().first_party);
    let result = service(FixtureMode::Complete)
        .query()
        .expect("fixture query");
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
}

#[test]
fn bounded_text_and_user_identifier_cells_are_rejected() {
    let schema = AggregateSchema::new(vec![
        AggregateColumn::new(
            ColumnName::new("Category").expect("category"),
            AggregateColumnType::Category,
            false,
        )
        .expect("schema"),
    ])
    .expect("schema");
    assert!(
        AggregateRow::new(vec![AggregateCell::Text(
            "a".repeat(MAX_CELL_TEXT_BYTES + 1)
        )])
        .validate_against(&schema)
        .is_err()
    );
    assert!(
        AggregateRow::new(vec![AggregateCell::Text("user@example.com".to_owned())])
            .validate_against(&schema)
            .is_err()
    );
}
