use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_openfga_authorization_result_plugin::{
    AuthorizationCheckRequest, AuthorizationCheckResponse, AuthorizationDecision,
    AuthorizationModelIdentity, BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_JSON,
    CONTRACT_SCHEMA, CONTRACT_VERSION, ConsentScope, Cursor, Digest, EVIDENCE_LEVEL, FakeTransport,
    FixtureTransport, Layer1Authority, LoopbackTransport, MissionIdentity, ModelReadRequest,
    ModelReadResponse, OpenFgaAuthorizationResultError, OpenFgaAuthorizationResultService,
    OpenFgaEvidenceState, OpenFgaProvider, OpenFgaScope, OpenFgaTransport, OpenFgaTransportError,
    PLUGIN_ID, PROVIDER_ID, ProjectIdentity, RecordingTransport, RegistrationStatus, SERVICE_ID,
    SecretReference, StoreIdentity, TransportProvenance, TupleReadRequest, TupleReadResponse,
    TupleScope, WorkProductIdentity, contract_digest,
};
use serde_json::Value;

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_SECRET: &str = "opaque-openfga-fixture-secret";
const RAW_USER: &str = "user:alice";
const RAW_OBJECT: &str = "document:alpha";
const RAW_RELATION: &str = "viewer";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> OpenFgaScope {
    OpenFgaScope::new(
        StoreIdentity::new("store:620", 7).expect("store"),
        AuthorizationModelIdentity::new("model:620", 11).expect("model"),
        ProjectIdentity::new("project:620", 13).expect("project"),
        MissionIdentity::new("mission:620", 17).expect("mission"),
        WorkProductIdentity::new("work-product:620", 19).expect("work product"),
    )
    .expect("scope")
}

fn service() -> OpenFgaAuthorizationResultService<FixtureTransport> {
    let scope = scope();
    let provider =
        OpenFgaProvider::new(FixtureTransport::for_scope(&scope, now()).expect("provider"))
            .expect("provider wrapper");
    let secret = SecretReference::openfga(RAW_SECRET, &scope, 1).expect("secret");
    let consent = ConsentScope::for_scope("consent:620", 1, now() + Duration::days(7), &scope)
        .expect("consent");
    OpenFgaAuthorizationResultService::new(scope, secret, consent, provider, now())
        .expect("service")
}

#[test]
fn contract_and_registration_are_digest_bound_and_secret_redacted() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["pluginId"], PLUGIN_ID);
    assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);

    let service = service();
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
fn fixture_proposal_is_bounded_digest_only_and_review_only() {
    let mut service = service();
    let request = service.default_request(now()).expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, OpenFgaEvidenceState::Ready);
    assert!(proposal.tuple_complete);
    assert!(proposal.model.is_some());
    assert!(proposal.check.is_some());
    assert_eq!(proposal.tuples.len(), 1);
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
    assert!(!proposal.authorization_granted);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.validate_integrity().is_ok());
    let verification = service.verify(&proposal);
    assert!(verification.valid);
    assert!(verification.review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [
        RAW_USER,
        RAW_OBJECT,
        RAW_RELATION,
        RAW_SECRET,
        "model:620",
        "store:620",
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    let recorded = consumer
        .record(&proposal, "idempotency:620")
        .expect("record");
    assert!(!recorded.replayed);
    assert!(recorded.validate_integrity().is_ok());
    let replay = consumer
        .record(&proposal, "idempotency:620")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn denied_check_is_evidence_not_authorization_authority() {
    let scope = scope();
    let provider = OpenFgaProvider::new(
        FixtureTransport::with_decision(&scope, AuthorizationDecision::Denied).expect("fixture"),
    )
    .expect("provider");
    let secret = SecretReference::openfga(RAW_SECRET, &scope, 1).expect("secret");
    let consent = ConsentScope::for_scope("consent:denied", 1, now() + Duration::days(1), &scope)
        .expect("consent");
    let mut service =
        OpenFgaAuthorizationResultService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, OpenFgaEvidenceState::Denied);
    assert!(!proposal.authorization_granted);
    assert!(!proposal.can_be_adopted());
    assert!(service.verify(&proposal).review_eligible);
}

#[test]
fn blocked_environment_is_unknown_and_never_connected_or_native() {
    let scope = scope();
    let provider = OpenFgaProvider::new(BlockedEnvTransport).expect("provider");
    let secret = SecretReference::openfga(RAW_SECRET, &scope, 1).expect("secret");
    let consent = ConsentScope::for_scope("consent:blocked", 1, now() + Duration::days(1), &scope)
        .expect("consent");
    let mut service =
        OpenFgaAuthorizationResultService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, OpenFgaEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).review_eligible);
}

#[test]
fn rate_limit_is_typed_and_receipt_is_redacted() {
    let scope = scope();
    let model_request =
        hartevo_openfga_authorization_result_plugin::ModelReadRequest::for_scope(&scope)
            .expect("model request");
    let mut transport = RecordingTransport::default();
    transport.push_model_response(Err(OpenFgaTransportError::RateLimited {
        retry_after_seconds: Some(3),
    }));
    let provider = OpenFgaProvider::new(transport).expect("provider");
    let secret = SecretReference::openfga(RAW_SECRET, &scope, 1).expect("secret");
    let consent = ConsentScope::for_scope("consent:rate", 1, now() + Duration::days(1), &scope)
        .expect("consent");
    let mut service =
        OpenFgaAuthorizationResultService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, OpenFgaEvidenceState::RateLimited);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").status_code,
        Some(429)
    );
    assert_eq!(proposal.request_receipts.len(), 1);
    assert!(proposal.request_receipts[0].redacted);
    assert_eq!(model_request.scope().digest(), proposal.scope_digest);
}

#[test]
fn model_check_revision_drift_is_typed_stale_evidence() {
    let scope = scope();
    let model_request = ModelReadRequest::for_scope(&scope).expect("model request");
    let check_request =
        AuthorizationCheckRequest::new(&scope, "user:fixture", "viewer", "document:fixture", 1)
            .expect("check request");
    let tuple_scope =
        TupleScope::new("user:fixture", "viewer", "document:fixture", 1).expect("tuple scope");
    let tuple_request = TupleReadRequest::first(&scope, tuple_scope, 25).expect("tuple request");
    let model = ModelReadResponse::new(
        &model_request,
        3,
        5,
        Digest::from_text("rules"),
        128,
        TransportProvenance::Recording,
    )
    .expect("model response");
    let check = AuthorizationCheckResponse::new(
        &check_request,
        AuthorizationDecision::Allowed,
        Digest::from_text("stale-model"),
        128,
        TransportProvenance::Recording,
    )
    .expect("check response");
    let tuple = TupleReadResponse::new(
        &tuple_request,
        vec![
            hartevo_openfga_authorization_result_plugin::TupleKey::new(
                "user:fixture",
                "viewer",
                "document:fixture",
            )
            .expect("tuple"),
        ],
        None,
        128,
        TransportProvenance::Recording,
    )
    .expect("tuple response");
    let mut transport = RecordingTransport::default();
    transport.push_model_response(Ok(model));
    transport.push_check_response(Ok(check));
    transport.push_tuple_response(Ok(tuple));
    let provider = OpenFgaProvider::new(transport).expect("provider");
    let secret = SecretReference::openfga(RAW_SECRET, &scope, 1).expect("secret");
    let consent = ConsentScope::for_scope("consent:stale", 1, now() + Duration::days(1), &scope)
        .expect("consent");
    let mut service =
        OpenFgaAuthorizationResultService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, OpenFgaEvidenceState::Stale);
    assert!(!service.verify(&proposal).valid);
}

#[test]
fn registration_revoke_and_restore_are_digest_bound_and_reversible() {
    let mut service = service();
    let request = service.default_request(now()).expect("request");
    let before = service.registration().registration_digest().clone();
    let transition = service.revoke().expect("revoke");
    assert_eq!(transition.to, RegistrationStatus::Reversed);
    assert!(!service.registration().is_active());
    assert_ne!(before, *service.registration().registration_digest());
    assert!(matches!(
        service.propose(request),
        Err(OpenFgaAuthorizationResultError::RegistrationInactive)
    ));
    assert!(service.consumer().is_err());
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    assert!(service.consumer().is_ok());
}

#[test]
fn cursor_is_bound_to_exact_scope_query_page_and_size() {
    let scope = scope();
    let tuple_scope = TupleScope::new(RAW_USER, RAW_RELATION, RAW_OBJECT, 1).expect("tuple scope");
    let query_digest = tuple_scope.digest();
    let cursor = Cursor::new("opaque-cursor", &scope, query_digest.clone(), 10, 2).expect("cursor");
    assert!(TupleReadRequest::new(&scope, tuple_scope.clone(), 10, Some(cursor.clone())).is_ok());
    let wrong_query = TupleScope::new("user:bob", RAW_RELATION, RAW_OBJECT, 1).expect("query");
    assert!(TupleReadRequest::new(&scope, wrong_query, 10, Some(cursor)).is_err());
    assert!(format!("{query_digest:?}").contains(query_digest.as_str()));
}

#[test]
fn tamper_and_replay_conflicts_fail_closed() {
    let mut service = service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    let mut tampered = proposal.clone();
    tampered.tuple_complete = false;
    assert!(!service.verify(&tampered).valid);
    assert!(
        service
            .consumer()
            .expect("consumer")
            .record(&proposal, "same-key")
            .is_ok()
    );
    let mut consumer = service.consumer().expect("consumer");
    consumer.record(&proposal, "conflict-key").expect("record");
    let mut other = proposal.clone();
    other.proposal_digest = Digest::from_text("different-proposal");
    assert!(matches!(
        consumer.record(&other, "conflict-key"),
        Err(OpenFgaAuthorizationResultError::TamperedEvidence
            | OpenFgaAuthorizationResultError::RecordingConflict,)
    ));
}

#[test]
fn all_layer_one_transports_are_non_native() {
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native());
    assert!(!Layer1Authority::authorization_authority());
    for provenance in [
        FixtureTransport::default().provenance(),
        FakeTransport::default().provenance(),
        LoopbackTransport::default().provenance(),
        BlockedEnvTransport.provenance(),
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        assert!(!provenance.provider_receipt());
    }
}

#[test]
fn custom_scope_preserves_exact_user_object_relation_fences() {
    let mut service = service();
    let request = hartevo_openfga_authorization_result_plugin::OpenFgaEvidenceRequest::for_scope(
        service.scope(),
        service.registration(),
        service.consent(),
        RAW_USER,
        RAW_RELATION,
        RAW_OBJECT,
        2,
        3,
        20,
        now(),
    )
    .expect("request");
    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, OpenFgaEvidenceState::Ready);
    assert!(proposal.check.as_ref().expect("check").user_digest != Digest::from_text(RAW_USER));
    assert!(proposal.validate_integrity().is_ok());
}
