use hartevo_aws_appflow_flow_result_plugin::{
    AppFlowOperation, AppFlowScopeInput, AwsAppFlowProvider, AwsAppFlowResultError,
    AwsAppFlowResultProposal, AwsAppFlowResultService, AwsAppFlowScope, BlockedEnvTransport,
    BoundedCounter, ConsentScope, Cursor, Digest, ErrorClass, ExecutionEvidenceState,
    ExecutionStatus, FixtureTransport, FlowDefinitionInput, FlowListItemProjection, FlowStatus,
    ListFlowsRequest, LoopbackTransport, MissionAwsAppFlowConsumer, PermissionSnapshot, ReadLimits,
    RecordingTransport, SecretReference, TransportProvenance, TriggerType, validate_contract,
};
use proptest::prelude::*;
use serde_json::Value;

const NOW_MS: u64 = 1_000_000;
const CONSENT_EXPIRY_MS: u64 = NOW_MS + 86_400_000;
const ACCOUNT: &str = "123456789012";
const REGION: &str = "us-east-1";
const FLOW: &str = "orders_to_warehouse";
const EXECUTION: &str = "execution-2026-08-15-001";
const SOURCE: &str = "salesforce-private-source";
const TARGET: &str = "s3-private-target";
const RAW_HANDLE: &str = "host-owned-opaque-sigv4-handle";
const RAW_FLOW_ARN: &str = "arn:aws:appflow:us-east-1:123456789012:flow/orders_to_warehouse";
const RAW_ERROR: &str = "Unauthorized private connector response 401";

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-appflow-1", 2, CONSENT_EXPIRY_MS).expect("consent")
}

fn scope() -> AwsAppFlowScope {
    let consent = consent();
    AwsAppFlowScope::new(AppFlowScopeInput {
        account_id: ACCOUNT.to_owned(),
        region: REGION.to_owned(),
        flow_name: FLOW.to_owned(),
        execution_id: EXECUTION.to_owned(),
        source_connector: SOURCE.to_owned(),
        target_connector: TARGET.to_owned(),
        trigger_type: "OnDemand".to_owned(),
        flow_revision: 7,
        execution_revision: 11,
        project_id: "project-appflow-1".to_owned(),
        project_revision: 13,
        mission_id: "mission-appflow-1".to_owned(),
        mission_revision: 17,
        work_product_id: "work-product-appflow-1".to_owned(),
        work_product_revision: 19,
        consent_digest: consent.digest().clone(),
    })
    .expect("AppFlow scope")
}

fn secret(scope: &AwsAppFlowScope) -> SecretReference {
    SecretReference::sigv4(RAW_HANDLE, scope, 3).expect("opaque secret")
}

fn fixture_service() -> AwsAppFlowResultService<FixtureTransport> {
    let scope = scope();
    let provider = AwsAppFlowProvider::new(
        FixtureTransport::for_scope(&scope, NOW_MS - 2_000).expect("fixture"),
    )
    .expect("provider");
    let secret = secret(&scope);
    AwsAppFlowResultService::new(scope, secret, consent(), provider, NOW_MS).expect("service")
}

fn service_for_scope(scope: AwsAppFlowScope) -> AwsAppFlowResultService<FixtureTransport> {
    let provider = AwsAppFlowProvider::new(
        FixtureTransport::for_scope(&scope, NOW_MS - 2_000).expect("fixture"),
    )
    .expect("provider");
    let secret = secret(&scope);
    AwsAppFlowResultService::new(scope, secret, consent(), provider, NOW_MS).expect("service")
}

fn recording_service_with_list_error(
    error: hartevo_aws_appflow_flow_result_plugin::AwsAppFlowTransportError,
) -> AwsAppFlowResultService<RecordingTransport> {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    transport.push_list_flows_response(Err(error));
    let provider = AwsAppFlowProvider::new(transport).expect("provider");
    let secret = secret(&scope);
    AwsAppFlowResultService::new(scope, secret, consent(), provider, NOW_MS).expect("service")
}

fn list_item(scope: &AwsAppFlowScope) -> FlowListItemProjection {
    FlowListItemProjection {
        flow_digest: scope.flow_digest(),
        flow_arn_digest: Digest::from_text(RAW_FLOW_ARN),
        source_digest: scope.source_digest().clone(),
        target_digest: scope.target_digest().clone(),
        trigger: TriggerType::OnDemand,
        status: FlowStatus::Active,
        flow_revision: scope.flow_revision(),
        updated_at_ms: Some(NOW_MS - 3_000),
        last_execution_status: Some(ExecutionStatus::Successful),
    }
}

#[test]
fn contract_plugin_descriptor_and_capability_boundary_are_versioned() {
    validate_contract().expect("contract validates");
    let descriptor = hartevo_aws_appflow_flow_result_plugin::plugin_descriptor();
    assert_eq!(descriptor.plugin_id, "aws.appflow.flow-result");
    assert_eq!(descriptor.contract_version, "EXT-AWS-APPFLOW-01-L1/v1");
    assert_eq!(
        descriptor.contract_digest,
        hartevo_aws_appflow_flow_result_plugin::contract_digest()
    );

    let service = fixture_service();
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(capabilities.recording_only);
    assert!(!capabilities.external_writes);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.provider_receipt);
    assert!(!capabilities.outcome_authority);
    assert_eq!(capabilities.operations.len(), 3);
    let forbidden = capabilities
        .forbidden_operations
        .join(" ")
        .to_ascii_lowercase();
    assert!(forbidden.contains("startflow"));
    assert!(forbidden.contains("stopflow"));
    assert!(forbidden.contains("deleteflow"));
    assert!(forbidden.contains("updateflow"));
}

#[test]
fn fixture_proposal_is_bounded_review_only_and_redacted() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(NOW_MS).expect("request"))
        .expect("proposal");
    proposal
        .validate(service.scope())
        .expect("proposal integrity");
    assert_eq!(proposal.state, ExecutionEvidenceState::Completed);
    assert_eq!(
        proposal.decision,
        hartevo_aws_appflow_flow_result_plugin::DecisionProposal::ReviewOnly
    );
    assert_eq!(proposal.list_pages, 1);
    assert_eq!(proposal.record_pages, 1);
    assert!(proposal.list_complete);
    assert!(proposal.records_complete);
    assert_eq!(proposal.execution_records.len(), 1);
    assert_eq!(
        proposal
            .execution
            .as_ref()
            .expect("execution")
            .records_processed
            .value,
        24
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.adoptable);
    assert!(proposal.is_review_only());
    assert!(service.verify(&proposal).valid);
    assert!(service.verify(&proposal).review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [RAW_HANDLE, ACCOUNT, SOURCE, TARGET, RAW_FLOW_ARN, RAW_ERROR] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(!registration_json.contains(RAW_HANDLE));
    let debug = format!("{:?}", service.secret_reference());
    assert!(!debug.contains(RAW_HANDLE));
}

#[test]
fn mission_consumer_records_idempotently_without_adoption() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(NOW_MS).expect("request"))
        .expect("proposal");
    let mut consumer = service.consumer().expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        mission_result.disposition,
        hartevo_aws_appflow_flow_result_plugin::ProposalDisposition::ReviewOnly
    );
    assert!(!mission_result.adopted);
    assert!(!mission_result.kernel_authority);
    assert!(!mission_result.work_product_adopted);

    let first = consumer
        .record(&proposal, "mission-record-1")
        .expect("record");
    let replay = consumer
        .record(&proposal, "mission-record-1")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    first
        .validate_integrity(consumer.scope())
        .expect("record integrity");

    let mut wrong_scope = proposal.clone();
    wrong_scope.scope_digest = Digest::from_text("wrong-scope");
    assert_eq!(
        consumer.consume(&wrong_scope),
        Err(AwsAppFlowResultError::ProposalTampered)
    );
    assert_eq!(
        consumer.record(&proposal, ""),
        Err(AwsAppFlowResultError::InvalidIdentifier)
    );
}

#[test]
fn secret_scope_and_registration_are_reversible_but_fail_closed() {
    let scope = scope();
    let secret = secret(&scope);
    assert_eq!(
        secret.kind(),
        hartevo_aws_appflow_flow_result_plugin::SecretKind::Sigv4Credential
    );
    assert_eq!(secret.scope_digest(), &scope.digest());
    assert!(!secret.is_revoked());
    assert!(!format!("{secret:?}").contains(RAW_HANDLE));
    let scope_json = serde_json::to_string(&scope).expect("safe scope JSON");
    assert!(!scope_json.contains(ACCOUNT));
    assert!(!scope_json.contains(SOURCE));
    assert!(!scope_json.contains(TARGET));

    let mut service = service_for_scope(scope);
    assert_eq!(
        service.registration().status(),
        hartevo_aws_appflow_flow_result_plugin::RegistrationStatus::Active
    );
    service
        .reverse_registration()
        .expect("reverse registration");
    assert_eq!(
        service.propose(service.default_request(NOW_MS).expect("request")),
        Err(AwsAppFlowResultError::RegistrationReversed)
    );
    service
        .restore_registration()
        .expect("restore registration");
    service.revoke_registration().expect("revoke registration");
    assert_eq!(
        service.propose(service.default_request(NOW_MS).expect("request")),
        Err(AwsAppFlowResultError::RegistrationRevoked)
    );

    let mut secret_service = fixture_service();
    secret_service.revoke_secret().expect("revoke secret");
    assert_eq!(
        secret_service.propose(secret_service.default_request(NOW_MS).expect("request")),
        Err(AwsAppFlowResultError::SecretRevoked)
    );
}

#[test]
fn fixture_loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = scope();
    let loopback_provider = AwsAppFlowProvider::new(
        LoopbackTransport::for_scope(&scope, NOW_MS - 2_000).expect("loopback"),
    )
    .expect("loopback provider");
    assert!(!loopback_provider.connected());
    assert!(!loopback_provider.native());
    assert!(!loopback_provider.first_party());
    let mut loopback = AwsAppFlowResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        loopback_provider,
        NOW_MS,
    )
    .expect("loopback service");
    let loopback_proposal = loopback
        .propose(loopback.default_request(NOW_MS).expect("request"))
        .expect("loopback proposal");
    assert_eq!(loopback_proposal.provenance, TransportProvenance::Loopback);
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);
    assert!(!loopback_proposal.first_party);

    let blocked_provider = AwsAppFlowProvider::new(BlockedEnvTransport).expect("blocked provider");
    let mut blocked = AwsAppFlowResultService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        blocked_provider,
        NOW_MS,
    )
    .expect("blocked service");
    let blocked_proposal = blocked
        .propose(blocked.default_request(NOW_MS).expect("request"))
        .expect("blocked proposal");
    assert_eq!(
        blocked_proposal.state,
        ExecutionEvidenceState::ProviderUnknown
    );
    assert_eq!(blocked_proposal.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        blocked_proposal.failure.as_ref().expect("failure").class,
        ErrorClass::BlockedEnv
    );
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);
    assert!(!blocked_proposal.first_party);
}

#[test]
fn opaque_pagination_is_bound_to_operation_scope_page_size_and_revisions() {
    let scope = scope();
    let cursor = Cursor::new(
        "opaque-provider-next-token",
        &scope,
        AppFlowOperation::ListFlows,
        2,
    )
    .expect("cursor");
    let cursor_json = serde_json::to_string(&cursor).expect("cursor JSON");
    assert!(!cursor_json.contains("opaque-provider-next-token"));
    let request = ListFlowsRequest::new(&scope, 100, Some(cursor.clone())).expect("request");
    assert!(
        !request
            .path_and_query()
            .contains("opaque-provider-next-token")
    );
    assert!(ListFlowsRequest::new(&scope, 99, Some(cursor.clone())).is_err());
    assert!(
        ListFlowsRequest::new(
            &scope,
            100,
            Some(
                Cursor::new(
                    "opaque-provider-next-token",
                    &scope,
                    AppFlowOperation::DescribeFlow,
                    2,
                )
                .expect("wrong operation cursor")
            )
        )
        .is_err()
    );

    let other_input = AppFlowScopeInput {
        account_id: ACCOUNT.to_owned(),
        region: "us-west-2".to_owned(),
        flow_name: FLOW.to_owned(),
        execution_id: EXECUTION.to_owned(),
        source_connector: SOURCE.to_owned(),
        target_connector: TARGET.to_owned(),
        trigger_type: "OnDemand".to_owned(),
        flow_revision: 7,
        execution_revision: 11,
        project_id: "project-appflow-1".to_owned(),
        project_revision: 13,
        mission_id: "mission-appflow-1".to_owned(),
        mission_revision: 17,
        work_product_id: "work-product-appflow-1".to_owned(),
        work_product_revision: 19,
        consent_digest: consent().digest().clone(),
    };
    let other_scope = AwsAppFlowScope::new(other_input).expect("other scope");
    assert!(ListFlowsRequest::new(&other_scope, 100, Some(cursor)).is_err());
}

#[test]
fn response_tamper_scope_drift_and_transport_failures_project_non_adoptable_states() {
    let scope = scope();
    let list_request = ListFlowsRequest::new(&scope, 100, None).expect("list request");
    let tampered = hartevo_aws_appflow_flow_result_plugin::ListFlowsResponse::new(
        &list_request,
        vec![list_item(&scope)],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered"));
    assert_eq!(
        tampered.validate_integrity(&list_request),
        Err(AwsAppFlowResultError::ResponseTampered)
    );

    let mut transport = RecordingTransport::default();
    transport.push_list_flows_response(Ok(tampered));
    let provider = AwsAppFlowProvider::new(transport).expect("provider");
    let mut service =
        AwsAppFlowResultService::new(scope.clone(), secret(&scope), consent(), provider, NOW_MS)
            .expect("service");
    let tamper_proposal = service
        .propose(service.default_request(NOW_MS).expect("request"))
        .expect("tamper proposal");
    assert_eq!(tamper_proposal.state, ExecutionEvidenceState::Tamper);
    assert!(!tamper_proposal.adoptable);

    for (error, expected) in [
        (
            hartevo_aws_appflow_flow_result_plugin::AwsAppFlowTransportError::Unauthorized,
            ExecutionEvidenceState::AccessLoss,
        ),
        (
            hartevo_aws_appflow_flow_result_plugin::AwsAppFlowTransportError::NotFound,
            ExecutionEvidenceState::NotFound,
        ),
        (
            hartevo_aws_appflow_flow_result_plugin::AwsAppFlowTransportError::RateLimited {
                retry_after_seconds: Some(5),
            },
            ExecutionEvidenceState::Throttled,
        ),
        (
            hartevo_aws_appflow_flow_result_plugin::AwsAppFlowTransportError::ReplayMismatch,
            ExecutionEvidenceState::Replay,
        ),
    ] {
        let mut service = recording_service_with_list_error(error);
        let proposal = service
            .propose(service.default_request(NOW_MS).expect("request"))
            .expect("failure proposal");
        assert_eq!(proposal.state, expected);
        assert!(!proposal.adoptable);
        assert!(!proposal.connected);
        assert!(!proposal.native);
    }
}

#[test]
fn bounded_counters_timing_status_and_error_projections_are_loss_limited() {
    let counter = BoundedCounter::from_raw(u64::MAX);
    assert_eq!(
        counter.value,
        hartevo_aws_appflow_flow_result_plugin::MAX_COUNTER_VALUE
    );
    assert!(counter.truncated);
    assert_eq!(
        ErrorClass::from_message(RAW_ERROR),
        ErrorClass::Authentication
    );
    assert_eq!(
        ExecutionStatus::parse("Successful"),
        ExecutionStatus::Successful
    );
    assert_eq!(
        ExecutionStatus::parse("InProgress"),
        ExecutionStatus::InProgress
    );
    assert_eq!(
        ExecutionStatus::parse("unknown provider state"),
        ExecutionStatus::Unknown
    );
    assert!(TriggerType::parse("Scheduled").is_ok());
    assert!(TriggerType::parse("\nraw-trigger").is_err());
    assert!(
        serde_json::to_string(&counter)
            .expect("counter JSON")
            .contains(&hartevo_aws_appflow_flow_result_plugin::MAX_COUNTER_VALUE.to_string())
    );

    let input = FlowDefinitionInput {
        flow_name: FLOW.to_owned(),
        flow_arn: RAW_FLOW_ARN.to_owned(),
        source_connector: SOURCE.to_owned(),
        target_connector: TARGET.to_owned(),
        trigger_type: "OnDemand".to_owned(),
        status: "Active".to_owned(),
        flow_revision: 7,
        updated_at_ms: Some(NOW_MS),
        last_execution_status: Some("Successful".to_owned()),
    };
    let projection = hartevo_aws_appflow_flow_result_plugin::FlowDefinitionProjection::from_input(
        &scope(),
        input,
    )
    .expect("flow projection");
    let json = serde_json::to_string(&projection).expect("projection JSON");
    assert!(!json.contains(RAW_FLOW_ARN));
    assert!(!json.contains(SOURCE));
    assert!(!json.contains(TARGET));
}

#[test]
fn permission_snapshot_is_exact_and_has_no_flow_effect_authority() {
    let snapshot = PermissionSnapshot::for_layer_one(1);
    snapshot.validate().expect("permissions");
    assert!(snapshot.permissions.contains("appflow:ListFlows"));
    assert!(snapshot.permissions.contains("appflow:DescribeFlow"));
    assert!(snapshot.permissions.iter().all(|permission| {
        !permission.to_ascii_lowercase().contains("start")
            && !permission.to_ascii_lowercase().contains("update")
            && !permission.to_ascii_lowercase().contains("delete")
    }));
}

proptest! {
    #[test]
    fn arbitrary_opaque_cursor_values_never_serialize_as_raw_tokens(token in "[A-Za-z0-9_]{1,64}") {
        let scope = scope();
        let opaque = format!("opaque-{token}");
        let cursor = Cursor::new(opaque.clone(), &scope, AppFlowOperation::ListFlows, 2)
            .expect("bounded cursor");
        let json = serde_json::to_string(&cursor).expect("cursor JSON");
        let debug = format!("{cursor:?}");
        prop_assert!(!json.contains(&opaque));
        prop_assert!(!debug.contains(&opaque));
    }

    #[test]
    fn page_size_limit_is_closed(value in 0u16..=110u16) {
        let result = ListFlowsRequest::new(&scope(), value, None);
        prop_assert_eq!(result.is_ok(), (1..=100).contains(&value));
    }
}

#[allow(dead_code)]
fn assert_proposal_type(_: AwsAppFlowResultProposal) {}

#[allow(dead_code)]
fn assert_consumer_type(_: MissionAwsAppFlowConsumer) {}

#[allow(dead_code)]
fn assert_value_type(_: Value) {}

#[allow(dead_code)]
fn assert_limits(_: ReadLimits) {}
