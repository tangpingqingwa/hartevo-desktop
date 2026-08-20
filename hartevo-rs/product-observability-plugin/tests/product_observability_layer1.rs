use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hartevo_product_observability_plugin::{
    AccessMode, EvidenceClassification, KeysetPagination, LoopbackFault, LoopbackPostHogTransport,
    MissionOutcomeBinding, MissionOutcomeEvidenceConsumer, PollPolicy, PostHogOutcomeProvider,
    PostHogQueryRequest, PostHogQueryTemplate, ProductObservabilityPluginDefinition,
    ProductObservabilityScope, QueryBudget, QueryCancellationToken, QueryReceiptStatus,
    QueryWindow,
};

fn at(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("fixture timestamp")
        .with_timezone(&Utc)
}

fn binding() -> MissionOutcomeBinding {
    MissionOutcomeBinding::new(
        "mission-test",
        11,
        "result-test",
        5,
        "deployment-test",
        4,
        "release-test",
        8,
    )
    .expect("binding")
}

fn request() -> PostHogQueryRequest {
    let binding = binding();
    PostHogQueryRequest::new(
        ProductObservabilityScope::new(
            "tenant-test",
            "project-test",
            "mission-test",
            "posthog-project-test",
        )
        .expect("scope"),
        binding.clone(),
        PostHogQueryTemplate::outcome_by_result(&binding),
        QueryWindow::new(at("2026-08-14T00:00:00Z"), at("2026-08-14T00:05:00Z")).expect("window"),
        QueryBudget::new(10, 10_000, 20).expect("budget"),
        KeysetPagination::new(2, 10).expect("pagination"),
        PollPolicy::immediate(),
        at("2026-08-14T00:05:01Z"),
    )
    .expect("request")
}

#[test]
fn standalone_contract_is_typed_and_read_only() {
    let definition = ProductObservabilityPluginDefinition::layer1().expect("definition");
    assert_eq!(definition.service.access, AccessMode::ReadOnly);
    assert_eq!(definition.provider.id, "product.observability.posthog");
    assert_eq!(definition.consumer.id, "mission.outcome-evidence.consumer");
    assert!(definition.reversible);
}

#[tokio::test]
async fn mission_consumer_preserves_exact_revision_binding() {
    let provider = PostHogOutcomeProvider::new(LoopbackPostHogTransport::demo().expect("loopback"));
    let request = request();
    let execution = provider
        .execute(&request, &QueryCancellationToken::default())
        .await
        .expect("execution");
    let evidence = MissionOutcomeEvidenceConsumer
        .consume(&request, &execution)
        .expect("consumer");
    assert_eq!(evidence.binding.mission_revision, 11);
    assert_eq!(evidence.binding.result_revision, 5);
    assert_eq!(evidence.binding.deployment_revision, 4);
    assert_eq!(evidence.binding.release_revision, 8);
    assert_eq!(
        evidence.classification,
        EvidenceClassification::ControlledLoopback
    );
    assert!(!evidence.native);
}

#[tokio::test]
async fn response_tamper_never_reaches_the_mission_consumer() {
    let provider = PostHogOutcomeProvider::new(
        LoopbackPostHogTransport::demo()
            .expect("loopback")
            .with_fault(LoopbackFault::ResponseTampered),
    );
    assert!(
        provider
            .execute(&request(), &QueryCancellationToken::default())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn keyset_cursor_is_strictly_monotonic() {
    let mut first = BTreeMap::new();
    first.insert(
        "timestamp".into(),
        serde_json::Value::String("2026-08-14T00:00:00Z".into()),
    );
    first.insert("uuid".into(), serde_json::Value::String("event-001".into()));
    let mut second = BTreeMap::new();
    second.insert(
        "timestamp".into(),
        serde_json::Value::String("2026-08-14T00:01:00Z".into()),
    );
    second.insert("uuid".into(), serde_json::Value::String("event-002".into()));
    let page = hartevo_product_observability_plugin::PostHogRowPage::new(
        vec![first, second],
        None,
        128,
        3,
    );
    let provider = PostHogOutcomeProvider::new(LoopbackPostHogTransport::new(vec![page]));
    let execution = provider
        .execute(&request(), &QueryCancellationToken::default())
        .await
        .expect("execution");
    assert_eq!(execution.receipt.status, QueryReceiptStatus::Completed);
    assert_eq!(execution.receipt.rows_read, 2);
}

#[tokio::test]
async fn cancellation_returns_a_bounded_receipt() {
    let provider = PostHogOutcomeProvider::new(
        LoopbackPostHogTransport::demo()
            .expect("loopback")
            .with_fault(LoopbackFault::NeverCompletes),
    );
    let cancellation = QueryCancellationToken::default();
    cancellation.cancel();
    let execution = provider
        .execute(&request(), &cancellation)
        .await
        .expect("cancel receipt");
    assert_eq!(execution.receipt.status, QueryReceiptStatus::Cancelled);
    assert!(!execution.receipt.provenance.is_native());
}

#[tokio::test]
async fn provider_faults_fail_closed_for_query_limits_rate_limits_and_revocation() {
    for fault in [
        LoopbackFault::QueryLimit,
        LoopbackFault::RateLimited,
        LoopbackFault::TokenRevoked,
    ] {
        let provider = PostHogOutcomeProvider::new(
            LoopbackPostHogTransport::demo()
                .expect("loopback")
                .with_fault(fault),
        );
        assert!(
            provider
                .execute(&request(), &QueryCancellationToken::default())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn cost_budget_returns_a_receipt_without_promoting_the_result() {
    let mut bounded = request();
    bounded.budget = QueryBudget::new(10, 10_000, 1).expect("budget");
    let provider = PostHogOutcomeProvider::new(LoopbackPostHogTransport::demo().expect("loopback"));
    let execution = provider
        .execute(&bounded, &QueryCancellationToken::default())
        .await
        .expect("budget receipt");
    assert_eq!(execution.receipt.status, QueryReceiptStatus::BudgetExceeded);
    assert!(execution.result.is_none());
}

#[test]
fn registration_is_scope_and_digest_bound_and_revocable() {
    let definition = ProductObservabilityPluginDefinition::layer1().expect("definition");
    let scope = ProductObservabilityScope::new(
        "tenant-test",
        "project-test",
        "mission-test",
        "posthog-project-test",
    )
    .expect("scope");
    let receipt = definition.bind(scope, 3).expect("registration");
    assert_eq!(receipt.generation, 3);
    assert_eq!(receipt.scope.mission_id, "mission-test");
    let revocation = receipt.revoke();
    assert_eq!(
        revocation.status,
        hartevo_product_observability_plugin::RegistrationStatus::Revoked
    );
    assert_eq!(revocation.generation, 3);
}
