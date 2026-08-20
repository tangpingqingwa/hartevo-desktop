use chrono::{Duration, TimeZone, Utc};
use hartevo_azure_data_factory_pipeline_result_plugin::{
    ActivityRunMetadata, ActivityRunsQueryResponse, AzureDataFactoryPipelineResultService,
    AzureDataFactoryProvider, AzureDataFactoryScope, AzureDataFactoryScopeInput,
    AzureDataFactoryTransport, BlockedEnvTransport, Digest, FixtureTransport, GetPipelineResponse,
    GetPipelineRunResponse, MissionAzureDataFactoryConsumer, PermissionScope, PipelineMetadata,
    PipelineRunMetadata, PipelineStatus, ProjectBinding, RecordingTransport, SecretReference,
    TransportProvenance, contract_digest, validate_contract,
};
use serde_json::Value;

const NOW: i64 = 1_780_000_000;

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(NOW, 0)
        .single()
        .expect("fixture timestamp")
}

fn scope() -> AzureDataFactoryScope {
    AzureDataFactoryScope::new(AzureDataFactoryScopeInput {
        tenant_id: "tenant-825".to_owned(),
        subscription_id: "subscription-825".to_owned(),
        resource_group_name: "rg-825".to_owned(),
        factory_name: "factory-825".to_owned(),
        pipeline_name: "pipeline_825".to_owned(),
        pipeline_run_id: "run-825".to_owned(),
        pipeline_revision: 7,
        project: ProjectBinding::new("project-825", 11).expect("project"),
        mission: hartevo_azure_data_factory_pipeline_result_plugin::MissionBinding::new(
            "mission-825",
            13,
        )
        .expect("mission"),
        work_product: hartevo_azure_data_factory_pipeline_result_plugin::WorkProductBinding::new(
            "work-product-825",
            17,
        )
        .expect("work product"),
        activity_window: hartevo_azure_data_factory_pipeline_result_plugin::ActivityWindow::new(
            now() - Duration::hours(1),
            now() + Duration::hours(1),
        )
        .expect("window"),
        permissions: PermissionScope::least_privilege(),
    })
    .expect("scope")
}

fn secret() -> SecretReference {
    SecretReference::new("keyring/entra/adf-825", "tenant-825", 3).expect("secret")
}

fn service_with<T: AzureDataFactoryTransport>(
    scope: AzureDataFactoryScope,
    transport: T,
) -> AzureDataFactoryPipelineResultService<T> {
    AzureDataFactoryPipelineResultService::new(
        AzureDataFactoryProvider::new(scope, secret(), transport).expect("provider"),
    )
    .expect("service")
}

fn fixture_responses(
    scope: &AzureDataFactoryScope,
) -> (
    GetPipelineResponse,
    GetPipelineRunResponse,
    ActivityRunsQueryResponse,
) {
    let pipeline_request =
        hartevo_azure_data_factory_pipeline_result_plugin::GetPipelineRequest::get_pipeline(scope)
            .expect("pipeline request");
    let pipeline = GetPipelineResponse::new(
        &pipeline_request,
        PipelineMetadata::fixture(scope, now()),
        512,
        TransportProvenance::Fixture,
    )
    .expect("pipeline response");
    let run_request =
        hartevo_azure_data_factory_pipeline_result_plugin::GetPipelineRunRequest::get_pipeline_run(
            scope,
        )
        .expect("run request");
    let run = GetPipelineRunResponse::new(
        &run_request,
        PipelineRunMetadata::fixture(scope, now()),
        768,
        TransportProvenance::Fixture,
    )
    .expect("run response");
    let activity_request =
        hartevo_azure_data_factory_pipeline_result_plugin::ActivityRunsQueryRequest::query_activity_runs(
            scope, None,
        )
        .expect("activity request");
    let activities = vec![
        ActivityRunMetadata::fixture(0, now()),
        ActivityRunMetadata::fixture(1, now()),
    ];
    let activity = ActivityRunsQueryResponse::new(
        &activity_request,
        activities,
        None,
        768,
        TransportProvenance::Fixture,
    )
    .expect("activity response");
    (pipeline, run, activity)
}

#[test]
fn contract_registration_and_secret_are_version_bound_without_leaks() {
    validate_contract().expect("contract");
    assert_eq!(
        contract_digest().as_str(),
        "827af5bbbec5f50c420017403fea68cdcb90edb5c38e2fd1144bfe85e689fab5"
    );
    assert_eq!(
        PipelineStatus::parse("not-a-status"),
        PipelineStatus::ProviderUnknown
    );

    let scope = scope();
    let service = service_with(scope.clone(), FixtureTransport::for_scope(&scope));
    let registration = service.registration();
    assert!(registration.is_active());
    assert!(
        registration
            .validate(&scope, service.provider().secret_reference())
            .is_ok()
    );
    let encoded = serde_json::to_string(registration).expect("registration JSON");
    let debug = format!("{registration:?}");
    assert!(!encoded.contains("keyring/entra/adf-825"));
    assert!(!debug.contains("keyring/entra/adf-825"));
    assert!(encoded.contains("secretReferenceDigest"));
    assert_eq!(service.describe_capabilities().operations.len(), 3);
    assert!(!service.describe_capabilities().triggers_pipelines);
    assert!(!service.describe_capabilities().cancels_pipelines);
    assert!(!service.describe_capabilities().reruns_pipelines);
    assert!(!service.describe_capabilities().kernel_authority);
}

#[test]
fn fixture_read_is_bounded_redacted_and_mission_scoped() {
    let scope = scope();
    let mut service = service_with(scope.clone(), FixtureTransport::for_scope(&scope));
    let proposal = service.propose().expect("proposal");
    assert_eq!(proposal.evidence.status, PipelineStatus::Succeeded);
    assert!(proposal.evidence.complete);
    assert_eq!(proposal.evidence.activity_runs.len(), 2);
    assert_eq!(proposal.evidence.receipts.len(), 3);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(proposal.validate_integrity().is_ok());
    assert!(service.verify(&proposal).valid);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        "keyring/entra/adf-825",
        "private activity input",
        "private activity output",
        "fixture pipeline description",
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    assert!(serialized.contains("inputDigest"));
    assert!(
        proposal
            .evidence
            .receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );

    let mut consumer = MissionAzureDataFactoryConsumer::new(scope.clone());
    let result = consumer.consume(proposal.clone()).expect("mission result");
    assert_eq!(result.project_digest, *scope.project_digest());
    assert_eq!(result.mission_digest, *scope.mission_digest());
    assert_eq!(result.work_product_digest, *scope.work_product_digest());
    assert!(result.review_only);
    assert!(!result.outcome_authority);
    assert!(!result.work_product_adoption);
    assert!(result.validate().is_ok());

    let first = service.record(&proposal, "record-key-825").expect("record");
    let replay = service.record(&proposal, "record-key-825").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(service.record_count(), 1);
}

#[test]
fn recording_and_loopback_are_non_native_and_request_receipts_are_redacted() {
    let scope = scope();
    let mut service = service_with(scope.clone(), RecordingTransport::for_scope(&scope));
    let proposal = service.propose().expect("recording proposal");
    assert_eq!(proposal.evidence.provenance, TransportProvenance::Recording);
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert_eq!(service.provider().transport().requests().len(), 3);
    assert!(
        service
            .provider()
            .transport()
            .requests()
            .iter()
            .all(|request| request.path_template.contains("{subscriptionId}")
                && request.path_template.contains("{factoryName}")
                && request.scope_digest == *scope.scope_digest())
    );
    assert!(
        service
            .provider()
            .transport()
            .requests()
            .iter()
            .all(|request| !request.path_template.contains("subscription-825"))
    );
}

#[test]
fn blocked_env_is_honest_provider_unknown() {
    let scope = scope();
    let mut service = service_with(scope, BlockedEnvTransport);
    let proposal = service.propose().expect("blocked proposal");
    assert_eq!(proposal.evidence.status, PipelineStatus::ProviderUnknown);
    assert_eq!(
        proposal.evidence.failure_code.as_deref(),
        Some("BLOCKED_ENV")
    );
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn registration_is_reversible_and_old_proposals_fail_closed() {
    let scope = scope();
    let mut service = service_with(scope.clone(), FixtureTransport::for_scope(&scope));
    let active = service.propose().expect("active proposal");
    let old_registration = service.registration().registration_digest.clone();
    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(
        revoked.status,
        hartevo_azure_data_factory_pipeline_result_plugin::RegistrationStatus::Revoked
    );
    assert_ne!(revoked.registration_digest, old_registration);
    let revoked_proposal = service.propose().expect("revoked proposal");
    assert_eq!(revoked_proposal.evidence.status, PipelineStatus::Revoked);
    assert!(!service.verify(&active).valid);
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    service.reverse_registration().expect("reverse");
    assert!(!service.registration().is_active());
    assert!(service.propose().is_ok());
}

#[test]
fn opaque_continuation_is_scope_bound_and_pagination_is_bounded() {
    let scope = scope();
    let (pipeline, run, _) = fixture_responses(&scope);
    let first_request =
        hartevo_azure_data_factory_pipeline_result_plugin::ActivityRunsQueryRequest::query_activity_runs(
            &scope, None,
        )
        .expect("first request");
    let continuation = hartevo_azure_data_factory_pipeline_result_plugin::OpaqueContinuation::new(
        "opaque-next-page-token",
        &scope,
        2,
    )
    .expect("continuation");
    let first = ActivityRunsQueryResponse::new(
        &first_request,
        vec![ActivityRunMetadata::fixture(0, now())],
        Some(continuation.clone()),
        256,
        TransportProvenance::Fixture,
    )
    .expect("first page");
    let second_request =
        hartevo_azure_data_factory_pipeline_result_plugin::ActivityRunsQueryRequest::query_activity_runs(
            &scope,
            Some(&continuation),
        )
        .expect("second request");
    let second = ActivityRunsQueryResponse::new(
        &second_request,
        vec![ActivityRunMetadata::fixture(1, now())],
        None,
        256,
        TransportProvenance::Fixture,
    )
    .expect("second page");
    let transport = FixtureTransport::new(pipeline, run, [first, second]);
    let mut service = service_with(scope.clone(), transport);
    let proposal = service.propose().expect("paginated proposal");
    assert_eq!(proposal.evidence.status, PipelineStatus::Succeeded);
    assert_eq!(proposal.evidence.activity_runs.len(), 2);
    assert!(proposal.evidence.continuation_digest.is_none());
    assert!(!format!("{continuation:?}").contains("opaque-next-page-token"));
    let encoded = serde_json::to_string(&continuation).expect("safe cursor JSON");
    assert!(!encoded.contains("opaque-next-page-token"));
    let different = hartevo_azure_data_factory_pipeline_result_plugin::OpaqueContinuation::new(
        "different-token",
        &scope,
        2,
    )
    .expect("different continuation");
    assert_ne!(different.digest(), continuation.digest());
}

#[test]
fn tampered_response_becomes_tampered_status_before_projection() {
    let scope = scope();
    let (pipeline, run, activity) = fixture_responses(&scope);
    let pipeline = pipeline.with_declared_digest(Digest::from_text("tampered-response"));
    let transport = FixtureTransport::new(pipeline, run, [activity]);
    let mut service = service_with(scope, transport);
    let proposal = service.propose().expect("tampered proposal");
    assert_eq!(proposal.evidence.status, PipelineStatus::Tampered);
    assert!(!proposal.evidence.complete);
    assert_eq!(proposal.evidence.failure_code.as_deref(), Some("tampered"));
    let value: Value = serde_json::to_value(&proposal).expect("proposal value");
    assert_eq!(value["evidence"]["connected"], false);
    assert_eq!(value["evidence"]["outcomeAuthority"], false);
}
