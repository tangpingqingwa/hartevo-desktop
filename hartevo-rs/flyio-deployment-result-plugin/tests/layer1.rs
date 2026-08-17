use chrono::{Duration, TimeZone, Utc};

use hartevo_flyio_deployment_result_plugin::{
    AppEvidence, AppPage, BlockedEnvTransport, ConsentScope, Digest, EvidenceState,
    FixtureResponse, FlyioDeploymentResultContract, FlyioDeploymentResultRegistration,
    FlyioDeploymentResultService, FlyioDeploymentScope, FlyioDeploymentScopeInput,
    FlyioMachinesProvider, FlyioTransportError, MachineEvidence, MachineState,
    MissionFlyioDeploymentConsumer, PermissionSnapshot, RecordingTransport, SecretReference,
    TransportProvenance,
};

const NOW_SECONDS: i64 = 1_787_000_000;

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> FlyioDeploymentScope {
    FlyioDeploymentScope::new(FlyioDeploymentScopeInput {
        organization: "acme".to_owned(),
        app_id: "app-123".to_owned(),
        app_name: "delivery-app".to_owned(),
        machine_id: "machine-123".to_owned(),
        instance_id: "instance-7".to_owned(),
        release_id: "release-42".to_owned(),
        image_digest: format!("sha256:{}", "a".repeat(64)),
        region: "hkg".to_owned(),
        process_group: "web".to_owned(),
        project_id: "project-1".to_owned(),
        project_revision: 4,
        mission_id: "mission-1".to_owned(),
        mission_revision: 5,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 6,
    })
    .expect("scope")
}

fn pages(
    scope: &FlyioDeploymentScope,
    state: MachineState,
    sequence: u64,
    truncated: bool,
) -> (
    AppPage,
    AppPage,
    hartevo_flyio_deployment_result_plugin::MachinePage,
    hartevo_flyio_deployment_result_plugin::MachinePage,
) {
    let at = now();
    let app = AppEvidence::for_scope(scope, "started", 1);
    let machine = MachineEvidence::for_scope(scope, state, sequence, at, at + Duration::seconds(1))
        .expect("machine evidence");
    let app_list = AppPage::new(
        vec![app.clone()],
        None,
        512,
        Digest::from_text("app-list"),
        truncated,
    )
    .expect("app list");
    let app_detail = AppPage::new(
        vec![app],
        None,
        256,
        Digest::from_text("app-detail"),
        truncated,
    )
    .expect("app detail");
    let machine_list = hartevo_flyio_deployment_result_plugin::MachinePage::new(
        vec![machine.clone()],
        None,
        1024,
        Digest::from_text("machine-list"),
        truncated,
    )
    .expect("machine list");
    let machine_detail = hartevo_flyio_deployment_result_plugin::MachinePage::new(
        vec![machine],
        None,
        2048,
        Digest::from_text("machine-detail"),
        truncated,
    )
    .expect("machine detail");
    (app_list, app_detail, machine_list, machine_detail)
}

fn service_with(
    responses: impl IntoIterator<Item = FixtureResponse>,
) -> FlyioDeploymentResultService<RecordingTransport> {
    let scope = scope();
    let provider =
        FlyioMachinesProvider::new(scope.clone(), RecordingTransport::fixture(responses))
            .expect("provider");
    let secret = SecretReference::new("keychain/flyio/api-token", 1, &scope).expect("secret");
    let registration = FlyioDeploymentResultRegistration::new(
        "flyio-registration-1",
        scope.clone(),
        secret,
        PermissionSnapshot::baseline(),
        ConsentScope::for_scope(&scope),
        provider.definition(),
        1,
    )
    .expect("registration");
    FlyioDeploymentResultService::new(provider, registration).expect("service")
}

#[test]
fn contract_registration_and_capability_binding_are_exact() {
    let contract = FlyioDeploymentResultContract::baseline().expect("contract");
    assert_eq!(
        contract.digest().as_str(),
        hartevo_flyio_deployment_result_plugin::CONTRACT_DIGEST
    );
    assert_eq!(
        contract.value()["provider"]["allowedMethods"],
        serde_json::json!(["GET"])
    );
    assert_eq!(contract.value()["provider"]["connected"], false);
    assert_eq!(contract.value()["provider"]["native"], false);
    assert_eq!(contract.value()["provider"]["firstParty"], false);
    assert!(
        contract.value()["forbiddenEffects"]
            .as_array()
            .expect("forbidden effects")
            .iter()
            .any(|value| value == "StartMachine")
    );

    let scope = scope();
    let provider =
        FlyioMachinesProvider::new(scope.clone(), BlockedEnvTransport).expect("provider");
    let secret = SecretReference::new("keychain/flyio/api-token", 1, &scope).expect("secret");
    let registration = FlyioDeploymentResultRegistration::new(
        "registration-1",
        scope.clone(),
        secret,
        PermissionSnapshot::baseline(),
        ConsentScope::for_scope(&scope),
        provider.definition(),
        1,
    )
    .expect("registration");
    let service = FlyioDeploymentResultService::new(provider, registration).expect("service");
    let capabilities = service.describe_capabilities();
    assert_eq!(
        capabilities.service_id,
        hartevo_flyio_deployment_result_plugin::SERVICE_ID
    );
    assert_eq!(
        capabilities.provider_id,
        hartevo_flyio_deployment_result_plugin::PROVIDER_ID
    );
    assert_eq!(capabilities.scope_digest, scope.digest());
    assert!(capabilities.reversible_registration);
    assert!(capabilities.revocable_registration);
    assert!(!capabilities.connected && !capabilities.native && !capabilities.first_party);
}

#[test]
fn bounded_get_evidence_consumes_and_records_without_authority() {
    let scope = scope();
    let (app_list, app_detail, machine_list, machine_detail) =
        pages(&scope, MachineState::Started, 3, false);
    let mut service = service_with([
        FixtureResponse::Apps(Ok(app_list)),
        FixtureResponse::App(Ok(app_detail)),
        FixtureResponse::Machines(Ok(machine_list)),
        FixtureResponse::Machine(Ok(machine_detail)),
    ]);
    let proposal = service.propose_current().expect("proposal");
    proposal.validate_integrity().expect("proposal integrity");
    assert_eq!(proposal.state, EvidenceState::Started);
    assert_eq!(proposal.request_receipts.len(), 4);
    assert!(
        proposal
            .request_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(
        !proposal.provider_receipt && !proposal.outcome_adopted && !proposal.work_product_adopted
    );
    assert!(
        proposal
            .machine
            .as_ref()
            .expect("machine")
            .service_ports
            .len()
            <= 16
    );
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    assert!(!serialized.contains("keychain/flyio/api-token"));
    assert!(!serialized.contains("private_ip"));
    assert!(!serialized.contains("environment"));

    let registration = service.registration().clone();
    let mut consumer = MissionFlyioDeploymentConsumer::new(scope, registration).expect("consumer");
    let consumed = consumer.consume(&proposal).expect("consume");
    assert_eq!(
        consumed.disposition,
        hartevo_flyio_deployment_result_plugin::ProposalDisposition::Started
    );
    let first = consumer
        .record(&proposal, "mission-turn-1")
        .expect("record");
    let replay = consumer
        .record(&proposal, "mission-turn-1")
        .expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(!first.connected && !first.native && !first.first_party);
}

#[test]
fn replacement_drift_and_monotonicity_fail_closed() {
    let scope = scope();
    let (app_list, app_detail, machine_list, machine_detail) =
        pages(&scope, MachineState::Started, 3, false);
    let mut service = service_with([
        FixtureResponse::Apps(Ok(app_list)),
        FixtureResponse::App(Ok(app_detail)),
        FixtureResponse::Machines(Ok(machine_list)),
        FixtureResponse::Machine(Ok(machine_detail)),
    ]);
    let first = service.propose_current().expect("first proposal");

    let (app_list, app_detail, machine_list, machine_detail) =
        pages(&scope, MachineState::Started, 2, false);
    *service.provider_mut().transport_mut() = RecordingTransport::fixture([
        FixtureResponse::Apps(Ok(app_list)),
        FixtureResponse::App(Ok(app_detail)),
        FixtureResponse::Machines(Ok(machine_list)),
        FixtureResponse::Machine(Ok(machine_detail)),
    ]);
    let regression = service
        .propose(
            &hartevo_flyio_deployment_result_plugin::FlyioEvidenceRequest::for_scope(
                service.provider().scope(),
            ),
            Some(&first),
        )
        .expect("regression proposal");
    assert_eq!(regression.state, EvidenceState::Tampered);
    assert!(
        !service
            .verify(
                &regression,
                &hartevo_flyio_deployment_result_plugin::FlyioEvidenceRequest::for_scope(
                    service.provider().scope()
                ),
            )
            .expect("verification")
            .verified
    );
}

#[test]
fn stale_mission_and_registration_revocation_fail_closed() {
    let scope = scope();
    let (app_list, app_detail, machine_list, machine_detail) =
        pages(&scope, MachineState::Started, 4, false);
    let mut service = service_with([
        FixtureResponse::Apps(Ok(app_list)),
        FixtureResponse::App(Ok(app_detail)),
        FixtureResponse::Machines(Ok(machine_list)),
        FixtureResponse::Machine(Ok(machine_detail)),
    ]);
    let stale_request = hartevo_flyio_deployment_result_plugin::FlyioEvidenceRequest::new(
        &scope,
        scope.mission_revision() + 1,
        scope.project_revision(),
        scope.work_product_revision(),
        50,
    )
    .expect("stale request remains structurally bounded");
    let stale = service
        .propose(&stale_request, None)
        .expect("stale proposal");
    assert_eq!(stale.state, EvidenceState::StaleMission);
    assert!(
        !service
            .verify(&stale, &stale_request)
            .expect("verify")
            .verified
    );

    let mut revoked_service = service_with([]);
    revoked_service
        .registration_mut()
        .revoke()
        .expect("revoke registration");
    let revoked = revoked_service.propose_current().expect("revoked proposal");
    assert_eq!(revoked.state, EvidenceState::Revoked);
    assert!(!revoked.can_be_adopted());
}

#[test]
fn pagination_truncation_and_provider_statuses_are_non_adoptable() {
    let scope = scope();
    let (app_list, app_detail, machine_list, machine_detail) =
        pages(&scope, MachineState::Starting, 1, true);
    let mut service = service_with([
        FixtureResponse::Apps(Ok(app_list)),
        FixtureResponse::App(Ok(app_detail)),
        FixtureResponse::Machines(Ok(machine_list)),
        FixtureResponse::Machine(Ok(machine_detail)),
    ]);
    let partial = service.propose_current().expect("partial proposal");
    assert_eq!(partial.state, EvidenceState::Partial);
    assert!(
        !service
            .verify(
                &partial,
                &hartevo_flyio_deployment_result_plugin::FlyioEvidenceRequest::for_scope(
                    service.provider().scope()
                )
            )
            .expect("verify")
            .verified
    );

    for (error, state) in [
        (FlyioTransportError::BadRequest, EvidenceState::BadRequest),
        (
            FlyioTransportError::Unauthorized,
            EvidenceState::Unauthorized,
        ),
        (FlyioTransportError::Forbidden, EvidenceState::Forbidden),
        (FlyioTransportError::NotFound, EvidenceState::NotFound),
        (FlyioTransportError::Conflict, EvidenceState::Conflict),
        (
            FlyioTransportError::RateLimited {
                retry_after_seconds: Some(2),
            },
            EvidenceState::Throttled,
        ),
        (
            FlyioTransportError::ServerError { status: 503 },
            EvidenceState::ServerError,
        ),
        (FlyioTransportError::Timeout, EvidenceState::TimedOut),
        (FlyioTransportError::AccessLost, EvidenceState::AccessLost),
        (FlyioTransportError::Unknown, EvidenceState::ProviderUnknown),
    ] {
        let mut status_service = service_with([FixtureResponse::Apps(Err(error))]);
        let proposal = status_service.propose_current().expect("status proposal");
        assert_eq!(proposal.state, state);
        assert!(!proposal.can_be_adopted());
    }
}

#[test]
fn fixture_recording_loopback_and_blocked_env_never_claim_native() {
    assert!(!TransportProvenance::Fixture.connected());
    assert!(!TransportProvenance::Fixture.native());
    assert!(!TransportProvenance::Fixture.first_party());
    assert!(!TransportProvenance::Recording.connected());
    assert!(!TransportProvenance::Loopback.native());
    assert!(!TransportProvenance::BlockedEnv.first_party());

    let scope = scope();
    let secret = SecretReference::new("opaque/token", 1, &scope).expect("secret");
    assert!(serde_json::to_string(&secret).is_err());
    assert!(!format!("{secret:?}").contains("opaque/token"));

    let provider =
        FlyioMachinesProvider::new(scope.clone(), BlockedEnvTransport).expect("provider");
    let consent = ConsentScope::for_scope(&scope);
    let registration = FlyioDeploymentResultRegistration::new(
        "blocked-registration",
        scope,
        secret,
        PermissionSnapshot::baseline(),
        consent,
        provider.definition(),
        1,
    );
    assert!(registration.is_ok());
}
