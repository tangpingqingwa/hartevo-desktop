use chrono::{Duration, Utc};
use serde_json::json;

use hartevo_sift_fraud_result_plugin::{
    BLOCKED_ENV, BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA,
    CONTRACT_VERSION, ConsentScope, Digest, FixtureTransport, MissionIdentity,
    MissionSiftFraudConsumer, PLUGIN_ID, PROVIDER_ID, ProjectIdentity, RecordingTransport,
    SERVICE_ID, SiftAccountId, SiftDecisionId, SiftFraudResultError, SiftFraudResultScope,
    SiftFraudResultService, SiftFraudResultState, SiftOperation, SiftOrderId, SiftProvider,
    SiftReadReceipt, SiftResponse, SiftReviewId, SiftScoreId, SiftTransportError, SiftUserId,
    TransportProvenance, WorkProductIdentity, contract_digest, validate_contract,
};

const RAW_SECRET: &str = "sift-api-key-do-not-print";
const RAW_ACCOUNT: &str = "account-private-748";
const RAW_USER: &str = "user-private-748";
const RAW_ORDER: &str = "order-private-748";
const RAW_DECISION: &str = "decision-private-748";
const RAW_SCORE: &str = "payment_abuse-private-748";
const RAW_REVIEW: &str = "review-private-748";

fn now() -> chrono::DateTime<Utc> {
    Utc::now()
}

fn scope() -> SiftFraudResultScope {
    SiftFraudResultScope::new(
        SiftAccountId::new(RAW_ACCOUNT).expect("account"),
        SiftUserId::new(RAW_USER).expect("user"),
        SiftOrderId::new(RAW_ORDER).expect("order"),
        SiftDecisionId::new(RAW_DECISION).expect("decision"),
        SiftScoreId::new(RAW_SCORE).expect("score"),
        SiftReviewId::new(RAW_REVIEW).expect("review"),
        ProjectIdentity::new("project-fraud-748", 7).expect("project"),
        MissionIdentity::new("mission-fraud-748", 11).expect("mission"),
        WorkProductIdentity::new("work-product-fraud-748", 13).expect("work product"),
    )
    .expect("scope")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-fraud-748", 3, now() + Duration::days(30))
        .expect("consent")
}

fn response() -> SiftResponse {
    SiftResponse::json(
        200,
        &json!({
            "decision": {
                "id": "decision-provider-private-748",
                "category": "WATCH",
                "abuse_type": "payment_abuse",
                "time": 1_700_000_000_000_u64,
                "revision": 4
            },
            "scores": {
                "payment_abuse": {
                    "id": "score-provider-private-748",
                    "score": 0.72,
                    "time": 1_700_000_000_000_u64,
                    "revision": 4
                }
            },
            "workflow_statuses": {
                "status": "running",
                "revision": 4,
                "review": {
                    "id": "review-provider-private-748",
                    "queue_id": "queue-provider-private-748",
                    "status": "pending"
                }
            }
        }),
    )
}

fn fixture_service() -> SiftFraudResultService<FixtureTransport> {
    let scope = scope();
    let provider =
        SiftProvider::new(FixtureTransport::for_scope(&scope, now())).expect("fixture provider");
    let secret =
        hartevo_sift_fraud_result_plugin::SecretReference::api_key(RAW_SECRET, 1).expect("secret");
    SiftFraudResultService::new(scope, secret, consent(), provider, now()).expect("service")
}

#[test]
fn contract_is_locked_and_layer_one_honest() {
    assert!(validate_contract().is_ok());
    let document: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["pluginId"], PLUGIN_ID);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
    assert_eq!(document["service"]["id"], SERVICE_ID);
    assert_eq!(document["provider"]["id"], PROVIDER_ID);
    assert_eq!(document["authority"]["connected"], false);
    assert_eq!(document["authority"]["fraudCertainty"], false);
}

#[test]
fn fixture_proposal_is_digest_only_redacted_and_review_only() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");

    assert_eq!(proposal.state, SiftFraudResultState::Review);
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.fraud_certainty);
    assert!(proposal.validate_integrity().is_ok());
    assert!(service.verify(&proposal).review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    let debug = format!("{proposal:?}");
    for raw in [
        RAW_SECRET,
        RAW_ACCOUNT,
        RAW_USER,
        RAW_ORDER,
        RAW_DECISION,
        RAW_SCORE,
        RAW_REVIEW,
        "decision-provider-private-748",
        "score-provider-private-748",
        "review-provider-private-748",
    ] {
        assert!(!serialized.contains(raw), "raw value leaked in JSON: {raw}");
        assert!(!debug.contains(raw), "raw value leaked in Debug: {raw}");
    }
    assert!(serialized.contains("scopeDigest"));
    assert!(serialized.contains("responseDigest"));

    let secret =
        hartevo_sift_fraud_result_plugin::SecretReference::api_key(RAW_SECRET, 1).expect("secret");
    assert!(serde_json::to_string(&secret).is_err());
    assert!(!format!("{secret:?}").contains(RAW_SECRET));
}

#[test]
fn requests_and_scope_are_redacted_and_allowlisted() {
    let request =
        hartevo_sift_fraud_result_plugin::SiftRequest::new(&scope(), SiftOperation::DecisionStatus)
            .expect("request");
    assert!(request.is_allowlisted());
    assert!(!request.path_and_query().contains(RAW_ACCOUNT));
    assert!(!request.path_and_query().contains(RAW_USER));
    assert!(!request.path_and_query().contains(RAW_ORDER));
    let serialized_scope = serde_json::to_string(&scope()).expect("scope JSON");
    assert!(!serialized_scope.contains(RAW_ACCOUNT));
    assert!(!serialized_scope.contains(RAW_USER));
    assert!(!serialized_scope.contains(RAW_ORDER));
    assert!(serialized_scope.contains("scopeDigest"));

    let provider = SiftProvider::new(FixtureTransport::new(response())).expect("provider");
    assert!(!provider.definition().connected);
    assert!(!provider.definition().native);
    assert!(!provider.definition().first_party);
    assert!(!provider.definition().provider_receipt);
    assert_eq!(provider.provenance(), TransportProvenance::Fixture);
}

#[test]
fn blocked_environment_is_typed_unknown_and_never_connected() {
    let scope = scope();
    let provider = SiftProvider::new(BlockedEnvTransport).expect("blocked provider");
    let secret =
        hartevo_sift_fraud_result_plugin::SecretReference::sift(RAW_SECRET, 1).expect("secret");
    let mut service =
        SiftFraudResultService::new(scope, secret, consent(), provider, now()).expect("service");
    assert_eq!(service.provider().provenance().as_str(), BLOCKED_ENV);
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, SiftFraudResultState::ProviderUnknown);
    assert!(proposal.failures.iter().any(|failure| {
        matches!(
            failure,
            hartevo_sift_fraud_result_plugin::ObservationFailure::BlockedEnv
        )
    }));
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn registration_revoke_restore_and_revision_fences_are_reversible() {
    let mut service = fixture_service();
    let original = service.registration().registration_digest().clone();
    let request = service.default_request(now()).expect("request");
    service.revoke_registration().expect("revoke");
    assert!(!service.registration().is_active());
    assert!(service.propose(request).is_err());
    let revoked_digest = service.registration().registration_digest().clone();
    assert_ne!(original, revoked_digest);
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    assert_ne!(
        revoked_digest,
        service.registration().registration_digest().clone()
    );

    let mut tampered_request = service.default_request(now()).expect("request");
    tampered_request.project_revision += 1;
    assert!(matches!(
        tampered_request.validate(service.scope(), service.registration()),
        Err(SiftFraudResultError::RevisionMismatch)
    ));

    let mut tampered_digest = service.default_request(now()).expect("request");
    tampered_digest.request_digest = Digest::from_text("tampered-request-digest");
    assert!(matches!(
        tampered_digest.validate(service.scope(), service.registration()),
        Err(SiftFraudResultError::TamperedEvidence)
    ));

    let drifted_scope = SiftFraudResultScope::new(
        SiftAccountId::new(RAW_ACCOUNT).expect("account"),
        SiftUserId::new(RAW_USER).expect("user"),
        SiftOrderId::new(RAW_ORDER).expect("order"),
        SiftDecisionId::new(RAW_DECISION).expect("decision"),
        SiftScoreId::new(RAW_SCORE).expect("score"),
        SiftReviewId::new(RAW_REVIEW).expect("review"),
        ProjectIdentity::new("project-fraud-748", 7).expect("project"),
        MissionIdentity::new("mission-fraud-748", 12).expect("drifted mission"),
        WorkProductIdentity::new("work-product-fraud-748", 13).expect("work product"),
    )
    .expect("drifted scope");
    assert!(matches!(
        MissionSiftFraudConsumer::new(drifted_scope, service.registration().clone()),
        Err(SiftFraudResultError::ScopeMismatch)
    ));
}

#[test]
fn recording_is_idempotent_and_conflicts_fail_closed() {
    let mut transport = RecordingTransport::default();
    for _ in 0..6 {
        transport.push_response(response());
    }
    let scope = scope();
    let provider = SiftProvider::new(transport).expect("recording provider");
    let secret =
        hartevo_sift_fraud_result_plugin::SecretReference::api_key(RAW_SECRET, 1).expect("secret");
    let mut service =
        SiftFraudResultService::new(scope, secret, consent(), provider, now()).expect("service");
    let first = service
        .propose(
            service
                .request("same-idempotency-key", now())
                .expect("request"),
        )
        .expect("first proposal");
    let second = service
        .propose(
            service
                .request("same-idempotency-key", now() + Duration::seconds(1))
                .expect("second request"),
        )
        .expect("second proposal");
    assert_ne!(first.proposal_digest, second.proposal_digest);

    let mut consumer = service.consumer().expect("consumer");
    let recorded = consumer
        .record(&first, "same-idempotency-key")
        .expect("record");
    assert!(!recorded.replayed);
    let replay = consumer
        .record(&first, "same-idempotency-key")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(matches!(
        consumer.record(&second, "same-idempotency-key"),
        Err(SiftFraudResultError::RecordingConflict)
    ));
}

#[test]
fn tamper_rate_limit_partial_and_access_loss_are_typed() {
    let mut tampered_service = fixture_service();
    let proposal = tampered_service
        .propose(tampered_service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.connected = true;
    assert!(matches!(
        tampered_service
            .consumer()
            .expect("consumer")
            .consume(&tampered),
        Err(SiftFraudResultError::TamperedProposal)
    ));

    let mut rate_transport = RecordingTransport::default();
    rate_transport.push_error(SiftTransportError::RateLimited {
        retry_after_seconds: 37,
    });
    rate_transport.push_error(SiftTransportError::ProviderUnknown);
    rate_transport.push_error(SiftTransportError::ProviderUnknown);
    let scope = scope();
    let provider = SiftProvider::new(rate_transport).expect("rate provider");
    let secret =
        hartevo_sift_fraud_result_plugin::SecretReference::api_key(RAW_SECRET, 1).expect("secret");
    let mut rate_service =
        SiftFraudResultService::new(scope.clone(), secret, consent(), provider, now())
            .expect("rate service");
    let rate = rate_service
        .propose(rate_service.default_request(now()).expect("request"))
        .expect("rate proposal");
    assert_eq!(rate.state, SiftFraudResultState::RateLimited);
    assert!(rate.failures.iter().any(|failure| {
        matches!(
            failure,
            hartevo_sift_fraud_result_plugin::ObservationFailure::RateLimited {
                retry_after_seconds: 37
            }
        )
    }));

    let mut not_found_transport = RecordingTransport::default();
    for _ in 0..3 {
        not_found_transport.push_response(SiftResponse::new(404, b"{}".to_vec()));
    }
    let provider = SiftProvider::new(not_found_transport).expect("not-found provider");
    let secret =
        hartevo_sift_fraud_result_plugin::SecretReference::api_key(RAW_SECRET, 1).expect("secret");
    let mut not_found_service =
        SiftFraudResultService::new(scope.clone(), secret, consent(), provider, now())
            .expect("not-found service");
    let not_found = not_found_service
        .propose(not_found_service.default_request(now()).expect("request"))
        .expect("not-found proposal");
    assert_eq!(not_found.state, SiftFraudResultState::NotFound);

    let mut partial_transport = RecordingTransport::default();
    partial_transport.push_response(response());
    partial_transport.push_error(SiftTransportError::AccessLoss);
    partial_transport.push_response(response());
    let provider = SiftProvider::new(partial_transport).expect("partial provider");
    let secret =
        hartevo_sift_fraud_result_plugin::SecretReference::api_key(RAW_SECRET, 1).expect("secret");
    let mut partial_service =
        SiftFraudResultService::new(scope, secret, consent(), provider, now())
            .expect("partial service");
    let partial = partial_service
        .propose(partial_service.default_request(now()).expect("request"))
        .expect("partial proposal");
    assert_eq!(partial.state, SiftFraudResultState::Partial);
    assert!(partial.failures.iter().any(|failure| {
        matches!(
            failure,
            hartevo_sift_fraud_result_plugin::ObservationFailure::AccessLoss
        )
    }));
    assert!(partial.validate_integrity().is_ok());
}

#[test]
fn provider_read_receipts_are_redacted_and_bounded() {
    let scope = scope();
    let request = hartevo_sift_fraud_result_plugin::SiftRequest::new(&scope, SiftOperation::Score)
        .expect("request");
    let receipt = SiftReadReceipt::failure(&request, TransportProvenance::BlockedEnv);
    let serialized = serde_json::to_string(&receipt).expect("receipt JSON");
    assert!(serialized.contains("redacted"));
    assert!(!serialized.contains(RAW_USER));
    assert_eq!(receipt.provenance, TransportProvenance::BlockedEnv);
    assert!(receipt.digest().validate().is_ok());
    assert!(Digest::from_text("private-value").validate().is_ok());
}
