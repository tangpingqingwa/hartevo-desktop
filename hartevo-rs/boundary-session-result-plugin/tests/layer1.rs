use chrono::{DateTime, TimeZone, Utc};
use hartevo_boundary_session_result_plugin::*;
use serde_json::{Value, json};

fn observed_at() -> DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000, 0)
        .single()
        .expect("test timestamp is valid")
}

fn scope() -> BoundaryScope {
    BoundaryScope::fixture().expect("fixture scope is valid")
}

fn session_payload(scope: &BoundaryScope, state: &str, version: u64) -> Value {
    json!({
        "id": scope.session_id().as_str(),
        "target_id": scope.target_id().as_str(),
        "scope_id": scope.scope_id().as_str(),
        "version": version,
        "type": "tcp",
        "status": state,
        "created_time": "2027-01-15T08:00:00Z",
        "updated_time": "2027-01-15T08:01:00Z",
        "expiration_time": "2027-01-15T09:00:00Z",
        "host_id": scope.host_id().as_str(),
        "organization_id": scope.organization_id().as_str(),
        "project_id": scope.project_id().as_str(),
        "auth_method_id": scope.auth_method_id().as_str(),
        "account_id": scope.account_id().as_str(),
        "principal_digest": scope.principal_digest().as_str(),
        "connections": [{
            "connection_id": "connection-raw",
            "endpoint": "10.0.0.8:22",
            "username": "alice",
            "recording_bytes": "raw-recording"
        }],
        "host_set_id": "host-set-raw",
        "auth_token": "provider-token-raw",
        "recording": "recording-bytes-raw"
    })
}

fn target_payload(scope: &BoundaryScope) -> Value {
    json!({
        "id": scope.target_id().as_str(),
        "scope_id": scope.scope_id().as_str(),
        "version": scope.target.revision.get(),
        "organization_id": scope.organization_id().as_str(),
        "project_id": scope.project_id().as_str(),
        "type": "tcp",
        "name": "production-target-name",
        "description": "production-target-description",
        "address": "10.0.0.8",
        "session_max_seconds": 3600,
        "session_connection_limit": 2,
        "host_set_ids": ["host-set-raw"],
        "credentials": [{"username": "alice", "token": "provider-token-raw"}]
    })
}

fn list_payload(
    scope: &BoundaryScope,
    state: &str,
    version: u64,
    list_token: Option<&str>,
    response_type: &str,
) -> Value {
    let mut payload = json!({
        "items": [session_payload(scope, state, version)],
        "response_type": response_type,
        "est_item_count": 1,
        "removed_ids": ["removed-session-raw"]
    });
    if let Some(list_token) = list_token {
        payload["list_token"] = json!(list_token);
    }
    payload
}

fn parsed_response(
    request: &BoundaryReadRequest,
    status: u16,
    payload: &Value,
) -> BoundaryHttpResponse {
    let bytes = serde_json::to_vec(&payload).expect("test JSON serializes");
    response_from_json(request, status, &bytes).expect("test response is valid")
}

fn session_response(scope: &BoundaryScope, state: &str, version: u64) -> BoundaryHttpResponse {
    parsed_response(
        &BoundaryReadRequest::session(scope),
        200,
        &session_payload(scope, state, version),
    )
}

fn target_response(scope: &BoundaryScope) -> BoundaryHttpResponse {
    parsed_response(
        &BoundaryReadRequest::target(scope),
        200,
        &target_payload(scope),
    )
}

fn list_response(
    scope: &BoundaryScope,
    state: &str,
    version: u64,
    list_token: Option<&str>,
    response_type: &str,
) -> BoundaryHttpResponse {
    let request = BoundaryReadRequest::list(scope, BOUNDARY_DEFAULT_PAGE_SIZE, None)
        .expect("test page request is valid");
    parsed_response(
        &request,
        200,
        &list_payload(scope, state, version, list_token, response_type),
    )
}

fn session_service(
    responses: impl IntoIterator<Item = Result<BoundaryHttpResponse, BoundaryTransportError>>,
) -> BoundarySessionResultService<FixtureBoundaryTransport> {
    let provider = BoundaryProvider::new(FixtureBoundaryTransport::new(responses))
        .expect("fixture provider is valid");
    BoundarySessionResultService::new(
        scope(),
        SecretReference::token("fixture-secret-reference").expect("secret reference is valid"),
        provider,
    )
    .expect("fixture service is valid")
}

#[test]
fn contract_identity_and_authority_are_fail_closed() {
    let contract = BoundarySessionResultContract::baseline().expect("contract is valid");
    assert_eq!(contract.digest(), contract_digest());
    assert_eq!(contract.value()["layer"], "Layer-1");
    assert_eq!(
        contract.value()["service"]["implementation"],
        "BoundarySessionResultService"
    );
    assert_eq!(
        contract.value()["provider"]["implementation"],
        "BoundaryProvider"
    );
    assert_eq!(
        contract.value()["consumer"]["implementation"],
        "MissionBoundarySessionConsumer"
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::first_party());
    assert!(!Layer1Authority::authorize());
    assert!(!Layer1Authority::connect());
    assert!(!Layer1Authority::cancel());
    assert!(!Layer1Authority::durable_provider_receipt());
    assert!(!Layer1Authority::kernel_authority());
    assert!(!Layer1Authority::outcome_authority());
}

#[test]
fn secret_and_transport_provenance_are_opaque_and_non_native() {
    let raw_secret = "fixture-secret-reference";
    let secret = SecretReference::token(raw_secret).expect("secret reference is valid");
    assert!(!format!("{secret:?}").contains(raw_secret));
    assert!(!secret.reference_digest().as_str().contains(raw_secret));
    assert!(secret.is_opaque());

    let provenances = [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Fake,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ];
    for provenance in provenances {
        assert!(!provenance.is_connected());
        assert!(!provenance.is_native());
        assert!(!provenance.is_first_party());
    }
}

#[test]
fn exact_session_and_target_reads_retain_only_allowlisted_digests() {
    let mut session_reader = session_service([Ok(session_response(&scope(), "ACTIVE", 1))]);
    let session_proposal = session_reader
        .read_session(observed_at())
        .expect("exact session read succeeds");
    assert_eq!(session_proposal.state(), BoundarySessionResultState::Active);
    assert_eq!(session_proposal.evidence.sessions.len(), 1);
    assert_eq!(session_proposal.evidence.sessions[0].connection_count, 1);
    assert_eq!(
        session_proposal.evidence.sessions[0].active_connection_count,
        1
    );
    assert!(!session_proposal.connected);
    assert!(!session_proposal.native);
    assert!(!session_proposal.first_party);
    assert!(!session_proposal.authorize);
    assert!(!session_proposal.connect);
    assert!(!session_proposal.cancel);
    assert!(!session_proposal.credential_brokering);
    assert!(!session_proposal.adopted_by_kernel);
    let session_json = serde_json::to_string(&session_proposal).expect("proposal serializes");
    for forbidden in [
        "provider-token-raw",
        "host-set-raw",
        "10.0.0.8:22",
        "alice",
        "recording-bytes-raw",
    ] {
        assert!(
            !session_json.contains(forbidden),
            "retained forbidden value: {forbidden}"
        );
    }

    let mut target_service = session_service([Ok(target_response(&scope()))]);
    let target_proposal = target_service
        .read_target(observed_at())
        .expect("exact target read succeeds");
    let target = target_proposal
        .evidence
        .target
        .as_ref()
        .expect("target metadata is present");
    assert!(target.name_digest.is_some());
    assert!(target.description_digest.is_some());
    assert!(target.address_digest.is_some());
    let target_json = serde_json::to_string(&target_proposal).expect("target proposal serializes");
    for forbidden in [
        "production-target-name",
        "production-target-description",
        "10.0.0.8",
        "provider-token-raw",
        "alice",
    ] {
        assert!(
            !target_json.contains(forbidden),
            "retained forbidden value: {forbidden}"
        );
    }
}

#[test]
fn exact_scope_drift_is_rejected_and_provider_drift_closes_registration() {
    let principal_drift = Digest::from_text("principal-drift");
    for (field, value) in [
        ("host_id", json!("h-drift")),
        ("scope_id", json!("s-drift")),
        ("organization_id", json!("org-drift")),
        ("project_id", json!("p-drift")),
        ("target_id", json!("t-drift")),
        ("id", json!("ss-drift")),
        ("auth_method_id", json!("amoid-drift")),
        ("account_id", json!("acct-drift")),
        ("principal_digest", json!(principal_drift.as_str())),
    ] {
        let mut payload = session_payload(&scope(), "ACTIVE", 1);
        payload[field] = value;
        let drifted_response =
            parsed_response(&BoundaryReadRequest::session(&scope()), 200, &payload);
        let mut service = session_service([Ok(drifted_response)]);
        let error = service
            .read_session(observed_at())
            .expect_err("exact scope drift must fail");
        assert!(matches!(
            error,
            BoundarySessionResultServiceError::Provider(BoundaryProviderError::ScopeMismatch(_))
        ));
    }

    let mut service = session_service([]);
    service.provider_mut().definition_mut().provider_revision = "drifted".to_owned();
    let error = service
        .read_session(observed_at())
        .expect_err("provider revision drift must fail closed");
    assert!(matches!(
        error,
        BoundarySessionResultServiceError::RegistrationDrift(_)
    ));
}

#[test]
fn lifecycle_expiry_and_regression_are_projected_safely() {
    let mut expired_payload = session_payload(&scope(), "ACTIVE", 1);
    expired_payload["expiration_time"] = json!("2027-01-15T07:00:00Z");
    let expired_response = parsed_response(
        &BoundaryReadRequest::session(&scope()),
        200,
        &expired_payload,
    );
    let mut service = session_service([Ok(expired_response)]);
    let expired = service
        .read_session(observed_at())
        .expect("expired session read succeeds as a projection");
    assert_eq!(expired.state(), BoundarySessionResultState::Expired);
    assert!(expired.projection.is_fail_closed());

    let mut service = session_service([
        Ok(session_response(&scope(), "ACTIVE", 1)),
        Ok(session_response(&scope(), "PENDING", 1)),
    ]);
    let active = service
        .read_session(observed_at())
        .expect("initial active read succeeds");
    assert_eq!(active.state(), BoundarySessionResultState::Active);
    let regressed = service
        .read_session(observed_at())
        .expect("regression is projected as tampered");
    assert_eq!(regressed.state(), BoundarySessionResultState::Tampered);
    assert!(regressed.projection.tampered);
}

#[test]
fn pagination_loops_and_delta_pages_are_bounded() {
    let mut service = session_service([
        Ok(list_response(
            &scope(),
            "ACTIVE",
            1,
            Some("opaque-page-token"),
            "COMPLETE",
        )),
        Ok(list_response(
            &scope(),
            "ACTIVE",
            1,
            Some("opaque-page-token"),
            "COMPLETE",
        )),
    ]);
    let looped = service
        .list_sessions(observed_at())
        .expect("pagination loop is projected as partial");
    assert_eq!(looped.state(), BoundarySessionResultState::Partial);
    assert!(looped.projection.partial);
    assert_eq!(service.provider().transport().requests().len(), 2);
    let request_json = serde_json::to_string(&service.provider().transport().requests()[1])
        .expect("request serializes safely");
    assert!(!request_json.contains("opaque-page-token"));

    let mut service = session_service([Ok(list_response(&scope(), "ACTIVE", 1, None, "DELTA"))]);
    let delta = service
        .list_sessions(observed_at())
        .expect("delta page is projected as partial");
    assert_eq!(delta.state(), BoundarySessionResultState::Partial);
    assert!(delta.projection.partial);
}

#[test]
fn access_loss_timeout_replay_and_revocation_are_fail_closed() {
    let mut access_lost = session_service([Ok(BoundaryHttpResponse::empty(403))]);
    let proposal = access_lost
        .read_session(observed_at())
        .expect("access loss is a typed projection");
    assert_eq!(proposal.state(), BoundarySessionResultState::AccessLost);
    assert!(proposal.projection.access_lost);

    let mut unknown = session_service([Err(BoundaryTransportError::Timeout)]);
    let proposal = unknown
        .read_session(observed_at())
        .expect("timeout is a typed provider-unknown projection");
    assert_eq!(
        proposal.state(),
        BoundarySessionResultState::ProviderUnknown
    );
    assert!(proposal.projection.provider_unknown);

    let mut service = session_service([Ok(session_response(&scope(), "ACTIVE", 1))]);
    let proposal = service
        .read_session(observed_at())
        .expect("session read succeeds");
    let record = service
        .record_local(&proposal)
        .expect("local proposal recording succeeds once");
    assert!(record.recorded);
    assert!(!record.durable_provider_receipt);
    assert!(!record.provider_mutated);
    assert!(matches!(
        service.record_local(&proposal),
        Err(BoundarySessionResultServiceError::ReplayDetected)
    ));
    let integrity = service
        .verify_integrity(&proposal)
        .expect("integrity verifies");
    assert!(integrity.valid);
    assert!(!integrity.provider_readback_performed);
    assert!(!integrity.authorization_correctness_authority);

    let mut tampered = proposal.clone();
    tampered.projection.state = BoundarySessionResultState::Tampered;
    assert!(matches!(
        service.verify_integrity(&tampered),
        Err(BoundarySessionResultServiceError::ProposalTampered)
    ));

    let mut consumer = MissionBoundarySessionConsumer::new(&scope(), service.registration())
        .expect("consumer registration succeeds");
    let observation = consumer
        .consume(&proposal)
        .expect("mission consumer accepts proposal");
    assert!(observation.accepted);
    assert!(!observation.truth_authority);
    assert!(!observation.consent_authority);
    assert!(!observation.effect_authority);
    assert!(!observation.receipt_authority);
    assert!(!observation.verification_authority);
    assert!(!observation.outcome_authority);
    assert!(!observation.work_product_adopted);

    let mut stale = proposal.clone();
    stale.scope_digest = Digest::from_text("stale-mission-scope");
    stale.evidence.scope_digest = stale.scope_digest.clone();
    stale.evidence.evidence_digest = stale.evidence.recompute_digest();
    stale.proposal_digest = stale.recompute_digest();
    assert!(matches!(
        consumer.consume(&stale),
        Err(MissionBoundarySessionConsumerError::StaleMission)
    ));

    consumer.revoke().expect("consumer revocation succeeds");
    assert!(matches!(
        consumer.consume(&proposal),
        Err(MissionBoundarySessionConsumerError::RegistrationRevoked)
    ));

    service
        .revoke_registration()
        .expect("registration revocation succeeds");
    assert!(matches!(
        service.read_session(observed_at()),
        Err(BoundarySessionResultServiceError::RegistrationRevoked)
    ));
}

#[test]
fn secret_revocation_and_blocked_environment_never_look_connected() {
    let mut service = session_service([]);
    service.revoke_secret().expect("secret revocation succeeds");
    assert!(!service.is_active());
    assert!(matches!(
        service.read_session(observed_at()),
        Err(BoundarySessionResultServiceError::SecretRevoked)
    ));

    let blocked = BlockedEnvBoundaryTransport;
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    assert!(!blocked.provenance().is_connected());
    assert!(!blocked.provenance().is_native());
    assert!(!blocked.provenance().is_first_party());
}
