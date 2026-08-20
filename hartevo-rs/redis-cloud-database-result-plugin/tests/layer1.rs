use hartevo_redis_cloud_database_result_plugin::{
    BlockedEnvRedisCloudTransport, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA,
    CONTRACT_VERSION, Digest, EVIDENCE_LEVEL, FixtureTransport, MissionBinding,
    MissionRedisCloudDatabaseConsumer, PLUGIN_ID, PROVIDER_ID, ProviderProvenance,
    RedisCloudAccountId, RedisCloudDatabaseId, RedisCloudDatabasePosture,
    RedisCloudDatabaseResultContract, RedisCloudDatabaseResultError,
    RedisCloudDatabaseResultService, RedisCloudDatabaseScope, RedisCloudEndpointPosture,
    RedisCloudEvidenceState, RedisCloudOperation, RedisCloudPlanTier, RedisCloudProvider,
    RedisCloudReplicationMode, RedisCloudReplicationPosture, RedisCloudResourceStatus,
    RedisCloudResponse, RedisCloudShardingPosture, RedisCloudSubscriptionId,
    RedisCloudSubscriptionPosture, RedisCloudTransportError, SERVICE_ID, SecretReference,
    contract_digest,
};
use serde_json::Value;

const RAW_ACCOUNT: &str = "123456789012";
const RAW_SUBSCRIPTION: &str = "987654";
const RAW_DATABASE: &str = "543210";
const RAW_SECRET: &str = "opaque-api-secret-reference";
const RAW_ENDPOINT: &str = "redis://user:password@cache.example:16379";
const RAW_VALUE: &str = "raw-data-value";

fn scope() -> RedisCloudDatabaseScope {
    RedisCloudDatabaseScope::new(
        RedisCloudAccountId::new(RAW_ACCOUNT).expect("account"),
        RedisCloudSubscriptionId::new(RAW_SUBSCRIPTION).expect("subscription"),
        RedisCloudDatabaseId::new(RAW_DATABASE).expect("database"),
        MissionBinding::new("mission-862", 7).expect("mission"),
        MissionBinding::new("project-862", 11).expect("project"),
        MissionBinding::new("work-product-862", 13).expect("work product"),
    )
    .expect("scope")
}

fn fixture_service() -> RedisCloudDatabaseResultService<FixtureTransport> {
    let scope = scope();
    let account_request = hartevo_redis_cloud_database_result_plugin::RedisCloudReadRequest::first(
        &scope,
        RedisCloudOperation::GetAccount,
    )
    .expect("account request");
    let subscription_request =
        hartevo_redis_cloud_database_result_plugin::RedisCloudReadRequest::first(
            &scope,
            RedisCloudOperation::GetSubscription,
        )
        .expect("subscription request");
    let database_request =
        hartevo_redis_cloud_database_result_plugin::RedisCloudReadRequest::first(
            &scope,
            RedisCloudOperation::GetDatabase,
        )
        .expect("database request");
    let replication =
        RedisCloudReplicationPosture::new(true, RedisCloudReplicationMode::MultiZone, Some(1))
            .expect("replication");
    let subscription = RedisCloudSubscriptionPosture::new(
        &scope,
        RedisCloudResourceStatus::Active,
        "pro-plan-862",
        RedisCloudPlanTier::Pro,
        vec!["us-east-1".to_owned(), "us-west-2".to_owned()],
        replication,
        b"subscription-revision-1",
    )
    .expect("subscription posture");
    let endpoint_posture =
        RedisCloudEndpointPosture::from_raw([RAW_ENDPOINT.to_owned()], true, false, true)
            .expect("endpoint posture");
    let database = RedisCloudDatabasePosture::new(
        &scope,
        RedisCloudResourceStatus::Active,
        "pro-plan-862",
        RedisCloudPlanTier::Pro,
        vec!["us-east-1".to_owned()],
        RedisCloudShardingPosture::new(true, Some(3), true).expect("sharding"),
        replication,
        endpoint_posture,
        b"database-revision-1",
    )
    .expect("database posture");
    let account_response = RedisCloudResponse::account(
        &account_request,
        &scope,
        format!(r#"{{"account":"{RAW_ACCOUNT}","value":"{RAW_VALUE}"}}"#),
        ProviderProvenance::Fixture,
    )
    .expect("account response");
    let subscription_response = RedisCloudResponse::subscription(
        &subscription_request,
        subscription,
        format!(r#"{{"subscription":"{RAW_SUBSCRIPTION}","endpoint":"{RAW_ENDPOINT}"}}"#),
        ProviderProvenance::Fixture,
    )
    .expect("subscription response");
    let database_response = RedisCloudResponse::database(
        &database_request,
        database,
        format!(r#"{{"database":"{RAW_DATABASE}","key":"{RAW_SECRET}","value":"{RAW_VALUE}"}}"#),
        ProviderProvenance::Fixture,
    )
    .expect("database response");
    let provider = RedisCloudProvider::new(FixtureTransport::from_responses([
        Ok(account_response),
        Ok(subscription_response),
        Ok(database_response),
    ]))
    .expect("provider");
    let secret = SecretReference::new(RAW_SECRET, &scope, 1).expect("secret");
    RedisCloudDatabaseResultService::new(scope, secret, provider).expect("service")
}

#[test]
fn contract_registration_and_secret_are_digest_bound_and_redacted() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    RedisCloudDatabaseResultContract::baseline().expect("contract validation");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["pluginId"], PLUGIN_ID);
    assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(contract_digest(), CONTRACT_DIGEST);
    let service = fixture_service();
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
    assert!(service.registration().validate().is_ok());
    assert_eq!(service.describe_capabilities().operations.len(), 3);
    assert_eq!(service.describe_capabilities().provider_id, PROVIDER_ID);
    assert_eq!(service.describe_capabilities().service_id, SERVICE_ID);
}

#[test]
fn ready_proposal_is_bounded_review_only_and_recording_is_not_provider_receipt() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, RedisCloudEvidenceState::Ready);
    assert!(proposal.subscription.is_some());
    assert!(proposal.database.is_some());
    assert_eq!(proposal.request_receipts.len(), 3);
    assert_eq!(proposal.cost_receipts.len(), 3);
    assert!(
        proposal
            .request_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(
        proposal
            .cost_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.truth_authority);
    assert!(!proposal.consent_authority);
    assert!(!proposal.effect_authority);
    assert!(!proposal.receipt_authority);
    assert!(!proposal.verification_authority);
    assert!(!proposal.outcome_authority);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.is_review_only());
    assert!(proposal.validate_integrity().is_ok());
    assert!(service.verify(&proposal).valid);
    assert!(service.verify(&proposal).review_eligible);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_ACCOUNT,
        RAW_SUBSCRIPTION,
        RAW_DATABASE,
        RAW_SECRET,
        RAW_ENDPOINT,
        RAW_VALUE,
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    assert!(!result.provider_receipt);
    let recorded = consumer
        .record(&proposal, "idempotency-862")
        .expect("record");
    assert!(!recorded.replayed);
    assert!(!recorded.durable_provider_receipt);
    assert!(recorded.validate_integrity().is_ok());
    let replay = consumer
        .record(&proposal, "idempotency-862")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn blocked_environment_is_provider_unknown_and_never_native() {
    let scope = scope();
    let provider = RedisCloudProvider::new(BlockedEnvRedisCloudTransport).expect("provider");
    let secret = SecretReference::new(RAW_SECRET, &scope, 1).expect("secret");
    let mut service =
        RedisCloudDatabaseResultService::new(scope, secret, provider).expect("service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, RedisCloudEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn tamper_and_pagination_are_rejected_before_projection() {
    let scope = scope();
    let request = hartevo_redis_cloud_database_result_plugin::RedisCloudReadRequest::first(
        &scope,
        RedisCloudOperation::GetAccount,
    )
    .expect("request");
    let tampered = RedisCloudResponse::account(
        &request,
        &scope,
        b"tampered raw response",
        ProviderProvenance::Recording,
    )
    .expect("response")
    .with_declared_digest(Digest::from_text("tampered-declared-evidence"));
    let provider = RedisCloudProvider::new(FixtureTransport::new(Ok(tampered))).expect("provider");
    let secret = SecretReference::new(RAW_SECRET, &scope, 1).expect("secret");
    let mut service =
        RedisCloudDatabaseResultService::new(scope.clone(), secret, provider).expect("service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, RedisCloudEvidenceState::Tampered);
    assert!(!proposal.can_be_adopted());

    let request = hartevo_redis_cloud_database_result_plugin::RedisCloudReadRequest::first(
        &scope,
        RedisCloudOperation::GetAccount,
    )
    .expect("request");
    let cursor = hartevo_redis_cloud_database_result_plugin::OpaquePageToken::new(
        "opaque-next-page-token",
        &scope,
        RedisCloudOperation::GetAccount.as_str(),
        2,
    )
    .expect("cursor");
    let paginated = RedisCloudResponse::account(
        &request,
        &scope,
        b"bounded account response",
        ProviderProvenance::Fixture,
    )
    .expect("response")
    .with_next_cursor(cursor);
    let provider = RedisCloudProvider::new(FixtureTransport::new(Ok(paginated))).expect("provider");
    let secret = SecretReference::new(RAW_SECRET, &scope, 1).expect("secret");
    let mut service =
        RedisCloudDatabaseResultService::new(scope, secret, provider).expect("service");
    let proposal = service
        .propose(service.default_request().expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, RedisCloudEvidenceState::PaginationRejected);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "pagination_rejected"
    );
}

#[test]
fn registration_revocation_reversal_and_secret_revocation_fail_closed() {
    let mut service = fixture_service();
    let request = service.default_request().expect("request");
    service.revoke_registration().expect("revoke");
    assert!(!service.registration().is_active());
    assert_eq!(
        service.propose(request).expect_err("revoked registration"),
        RedisCloudDatabaseResultError::RegistrationRevoked
    );
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    service.reverse_registration().expect("reverse");
    assert_eq!(
        service
            .restore_registration()
            .expect_err("reversed registration"),
        RedisCloudDatabaseResultError::RegistrationReversed
    );
    let mut service = fixture_service();
    service.revoke_secret_reference().expect("secret revoke");
    assert_eq!(
        service
            .propose(service.default_request().expect("request"))
            .expect_err("revoked secret"),
        RedisCloudDatabaseResultError::SecretRevoked
    );
}

#[test]
fn all_layer_one_provenances_are_never_connected_native_or_first_party() {
    for provenance in [
        ProviderProvenance::Recording,
        ProviderProvenance::Fixture,
        ProviderProvenance::Fake,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_connected());
        assert!(!provenance.is_native());
        assert!(!provenance.is_first_party());
    }
}

#[test]
fn transport_error_never_exposes_raw_response_material() {
    let error = RedisCloudTransportError::from_status(
        RedisCloudOperation::GetDatabase.as_str(),
        403,
        format!(r#"{{"endpoint":"{RAW_ENDPOINT}","secret":"{RAW_SECRET}"}}"#),
    );
    let displayed = error.to_string();
    let debug = format!("{error:?}");
    assert!(!displayed.contains(RAW_ENDPOINT));
    assert!(!displayed.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_ENDPOINT));
    assert!(!debug.contains(RAW_SECRET));
    assert!(error.is_access_loss());
}

#[test]
fn mission_consumer_is_explicitly_below_kernel_authority() {
    let consumer = fixture_service().consumer().expect("consumer");
    let debug = format!("{consumer:?}");
    assert!(!debug.contains(RAW_SECRET));
    assert!(
        !MissionRedisCloudDatabaseConsumer::new(scope(), consumer.registration().clone())
            .expect("consumer")
            .registration()
            .secret_reference()
            .is_revoked()
    );
}
