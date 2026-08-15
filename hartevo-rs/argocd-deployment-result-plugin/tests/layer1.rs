use argocd::{
    ArgoCdDeploymentError, ArgoCdDeploymentResultService, ArgoCdDeploymentScope, ArgoCdResponse,
    ArgoCdTransport, ArgoCdTransportError, ArgoFixtureSet, BlockedEnvTransport, ConsentScope,
    Digest, FakeTransport, FixtureTransport, Layer1Authority, LoopbackTransport,
    MissionArgoCdDeploymentConsumer, PermissionSnapshot, ProviderProvenance, RecordingTransport,
    SecretReference, WorkProduct,
};
use hartevo_argocd_deployment_result_plugin as argocd;

const RAW_INSTANCE: &str = "argocd-prod.example.invalid";
const RAW_PROJECT: &str = "payments";
const RAW_APPLICATION: &str = "payments-api";
const RAW_CLUSTER: &str = "https://cluster.example.invalid";
const RAW_NAMESPACE: &str = "payments-prod";
const RAW_TARGET_REVISION: &str = "refs/heads/release-2026-08";
const RAW_OPERATION: &str = "sync-operation-745";
const RAW_TOKEN: &str = "do-not-leak-this-bearer-token";
const RAW_MANIFEST: &str = "apiVersion: apps/v1\nkind: Deployment";

fn scope() -> ArgoCdDeploymentScope {
    ArgoCdDeploymentScope::new(
        RAW_INSTANCE,
        RAW_PROJECT,
        RAW_APPLICATION,
        RAW_CLUSTER,
        RAW_NAMESPACE,
        RAW_TARGET_REVISION,
        RAW_OPERATION,
        argocd::Project::new("project-745", 2).expect("Project"),
        argocd::Mission::new("mission-745", 3).expect("Mission"),
        WorkProduct::new("work-product-745", 4).expect("Work Product"),
    )
    .expect("scope")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-745", 1, 100).expect("consent")
}

fn secret(scope: &ArgoCdDeploymentScope) -> SecretReference {
    SecretReference::bearer_token(RAW_TOKEN, scope, 7).expect("opaque bearer token")
}

fn registered<T: ArgoCdTransport>(
    scope: &ArgoCdDeploymentScope,
    transport: T,
) -> ArgoCdDeploymentResultService<T> {
    let provider =
        argocd::ArgoCdProvider::new(transport, scope.clone(), secret(scope)).expect("provider");
    ArgoCdDeploymentResultService::register(
        provider,
        "registration-745",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        consent(),
        1,
    )
    .expect("registration")
}

fn fixture_service() -> ArgoCdDeploymentResultService<FixtureTransport> {
    let scope = scope();
    registered(
        &scope,
        FixtureTransport::for_scope(&scope).expect("fixture transport"),
    )
}

fn recording_responses(scope: &ArgoCdDeploymentScope) -> Vec<ArgoCdResponse> {
    let fixtures = ArgoFixtureSet::for_scope(scope);
    vec![
        ArgoCdResponse::json(200, &fixtures.application).expect("application response"),
        ArgoCdResponse::json(200, &fixtures.resource_tree).expect("resource tree response"),
        ArgoCdResponse::json(200, &fixtures.sync_status).expect("sync response"),
        ArgoCdResponse::json(200, &fixtures.operation).expect("operation response"),
    ]
}

#[test]
fn contract_is_pinned_to_the_official_read_only_surface() {
    let contract = argocd::ArgoCdDeploymentContract::baseline().expect("contract");
    assert_eq!(contract.value()["schemaVersion"], argocd::CONTRACT_SCHEMA);
    assert_eq!(
        contract.value()["contractVersion"],
        argocd::CONTRACT_VERSION
    );
    assert_eq!(contract.value()["contractDigest"], argocd::CONTRACT_DIGEST);
    assert_eq!(argocd::contract_digest(), argocd::CONTRACT_DIGEST);
    assert_eq!(
        contract.value()["service"]["type"],
        "ArgoCdDeploymentResultService"
    );
    assert_eq!(contract.value()["provider"]["type"], "ArgoCdProvider");
    assert_eq!(
        contract.value()["consumer"]["type"],
        "MissionArgoCdDeploymentConsumer"
    );
    assert!(
        contract.value()["allowlist"]["writes"]
            .as_array()
            .expect("writes")
            .is_empty()
    );
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::first_party_provider());
    assert!(!Layer1Authority::external_writes());
    assert_eq!(
        argocd::ARGOCD_API_DOCS,
        "https://argo-cd.readthedocs.io/en/stable/developer-guide/api-docs/"
    );
}

#[test]
fn ready_fixture_is_digest_bound_redacted_and_mission_scoped() {
    let scope = scope();
    let mut service = registered(
        &scope,
        FixtureTransport::for_scope(&scope).expect("fixture transport"),
    );
    let evidence = service.read(10).expect("evidence");
    assert_eq!(evidence.state, argocd::ArgoCdDeploymentState::Ready);
    assert!(!evidence.partial);
    assert_eq!(evidence.request_receipts.len(), 4);
    assert!(
        evidence
            .request_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    evidence.validate_integrity().expect("evidence integrity");

    let proposal = service
        .compile_proposal_from_evidence(evidence)
        .expect("proposal");
    let report = service.verify_proposal(&proposal).expect("verification");
    assert!(report.verified());
    assert!(report.review_eligible);
    assert!(!report.can_be_adopted);
    let receipt = service
        .record_observation(&proposal, 10)
        .expect("observation receipt");
    receipt.validate_integrity().expect("receipt integrity");
    assert!(!receipt.durable_provider_receipt);

    let registration_json = serde_json::to_string(service.registration()).expect("registration");
    let proposal_json = serde_json::to_string(&proposal).expect("proposal");
    let debug = format!("{service:?}");
    for raw in [
        RAW_INSTANCE,
        RAW_PROJECT,
        RAW_APPLICATION,
        RAW_CLUSTER,
        RAW_NAMESPACE,
        RAW_TARGET_REVISION,
        RAW_OPERATION,
        RAW_TOKEN,
        RAW_MANIFEST,
    ] {
        assert!(
            !registration_json.contains(raw),
            "registration leaked {raw}"
        );
        assert!(!proposal_json.contains(raw), "proposal leaked {raw}");
        assert!(!debug.contains(raw), "debug leaked {raw}");
    }
    assert!(registration_json.contains("secretReferenceDigest"));

    let mut consumer =
        MissionArgoCdDeploymentConsumer::new(scope.clone(), service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    result.validate_integrity().expect("Mission integrity");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    let first = consumer
        .record(&proposal, "idempotency-745")
        .expect("record");
    assert!(!first.replayed);
    let replay = consumer
        .record(&proposal, "idempotency-745")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn opaque_secret_reference_is_bearer_only_and_revocation_is_visible_without_raw_material() {
    let scope = scope();
    let mut reference = secret(&scope);
    assert_eq!(reference.kind(), argocd::SecretKind::BearerToken);
    assert_eq!(reference.scope_digest(), &scope.digest());
    assert!(!format!("{reference:?}").contains(RAW_TOKEN));
    assert!(
        !serde_json::to_string(&reference)
            .expect("secret JSON")
            .contains(RAW_TOKEN)
    );
    reference.revoke();
    assert!(reference.is_revoked());
    assert_eq!(
        argocd::ArgoCdProvider::new(
            FixtureTransport::for_scope(&scope).expect("transport"),
            scope,
            reference,
        )
        .expect_err("revoked secret must not register")
        .to_string(),
        "secret reference is revoked"
    );
}

#[test]
fn all_deterministic_provenances_are_honest_and_blocked_env_is_unknown() {
    let scope = scope();
    let transports: Vec<Box<dyn ArgoCdTransport>> = vec![
        Box::new(FixtureTransport::for_scope(&scope).expect("fixture")),
        Box::new(RecordingTransport::default()),
        Box::new(FakeTransport::for_scope(&scope).expect("fake")),
        Box::new(LoopbackTransport::for_scope(&scope).expect("loopback")),
        Box::new(BlockedEnvTransport),
    ];
    for transport in transports {
        let provenance = transport.provenance();
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        assert!(!provenance.provider_receipt());
    }

    let mut service = registered(&scope, BlockedEnvTransport);
    let evidence = service.read(10).expect("blocked evidence");
    assert_eq!(
        evidence.state,
        argocd::ArgoCdDeploymentState::ProviderUnknown
    );
    assert_eq!(evidence.provenance, ProviderProvenance::BlockedEnv);
    assert!(!evidence.connected && !evidence.native && !evidence.first_party);
}

#[test]
fn rate_limit_retries_are_bounded_and_receipts_are_redacted() {
    let scope = scope();
    let mut transport = RecordingTransport::default();
    transport.push_error(ArgoCdTransportError::RateLimited {
        retry_after_seconds: Some(5),
    });
    for response in recording_responses(&scope) {
        transport.push_response(response);
    }
    let mut service = registered(&scope, transport);
    let evidence = service.read(10).expect("rate-limited read");
    assert_eq!(evidence.state, argocd::ArgoCdDeploymentState::Ready);
    assert_eq!(
        evidence
            .backoff
            .as_ref()
            .expect("backoff")
            .retry_after_seconds,
        5
    );
    assert_eq!(evidence.request_receipts.len(), 5);
    assert!(
        evidence
            .request_receipts
            .iter()
            .all(|receipt| receipt.redacted)
    );
    assert!(
        service
            .provider()
            .transport()
            .requests()
            .iter()
            .all(|request| request.is_get() && request.is_allowlisted())
    );
    let requests =
        serde_json::to_string(service.provider().transport().requests()).expect("requests");
    assert!(!requests.contains(RAW_APPLICATION));
    assert!(!requests.contains(RAW_TOKEN));
}

#[test]
fn partial_resource_tree_is_non_adoptable_and_tampered_response_fails_closed() {
    let scope = scope();
    let mut fixtures = ArgoFixtureSet::for_scope(&scope);
    fixtures.resource_tree.partial = true;
    let mut service = registered(
        &scope,
        RecordingTransport::from_responses(vec![
            ArgoCdResponse::json(200, &fixtures.application).expect("application"),
            ArgoCdResponse::json(200, &fixtures.resource_tree).expect("tree"),
            ArgoCdResponse::json(200, &fixtures.sync_status).expect("sync"),
            ArgoCdResponse::json(200, &fixtures.operation).expect("operation"),
        ]),
    );
    let partial = service.read(10).expect("partial evidence");
    assert_eq!(partial.state, argocd::ArgoCdDeploymentState::Partial);
    assert!(
        !service
            .verify_proposal(
                &service
                    .compile_proposal_from_evidence(partial)
                    .expect("partial proposal")
            )
            .expect("report")
            .verified()
    );

    let tampered_response =
        ArgoCdResponse::json(200, &ArgoFixtureSet::for_scope(&scope).application)
            .expect("application")
            .with_declared_digest(Digest::from_text("tampered-declared-digest"));
    let mut tampered = registered(
        &scope,
        RecordingTransport::from_responses(vec![tampered_response]),
    );
    let evidence = tampered.read(10).expect("tampered evidence");
    assert_eq!(evidence.state, argocd::ArgoCdDeploymentState::Tampered);
    assert_eq!(
        evidence.failure.as_ref().expect("failure").category,
        "tampered"
    );
}

#[test]
fn scope_and_target_revision_mismatches_are_not_silent() {
    let scope = scope();
    let mut stale = ArgoFixtureSet::for_scope(&scope);
    stale.application.target_revision = "refs/heads/other".to_owned();
    let mut stale_service = registered(
        &scope,
        RecordingTransport::from_responses(vec![
            ArgoCdResponse::json(200, &stale.application).expect("stale application"),
        ]),
    );
    let stale_evidence = stale_service.read(10).expect("stale evidence");
    assert_eq!(
        stale_evidence.state,
        argocd::ArgoCdDeploymentState::StaleRevision
    );

    let mut wrong_scope = ArgoFixtureSet::for_scope(&scope);
    wrong_scope.application.application = "other-application".to_owned();
    let mut wrong_service = registered(
        &scope,
        RecordingTransport::from_responses(vec![
            ArgoCdResponse::json(200, &wrong_scope.application).expect("wrong application"),
        ]),
    );
    let wrong_evidence = wrong_service.read(10).expect("wrong-scope evidence");
    assert_eq!(
        wrong_evidence.state,
        argocd::ArgoCdDeploymentState::Tampered
    );
}

#[test]
fn registration_revoke_restore_reverse_and_forbidden_writes_are_bound() {
    let mut service = fixture_service();
    let before = service.registration().registration_digest().clone();
    let revoked = service.revoke().expect("revoke");
    assert_eq!(revoked.previous_status, argocd::RegistrationStatus::Active);
    assert_eq!(revoked.new_status, argocd::RegistrationStatus::Revoked);
    assert_ne!(before, *service.registration().registration_digest());
    assert_eq!(
        service.read(10),
        Err(ArgoCdDeploymentError::RegistrationInactive)
    );
    service.restore_registration().expect("restore");
    service.reverse_registration().expect("reverse");
    assert_eq!(
        service.read(10),
        Err(ArgoCdDeploymentError::RegistrationInactive)
    );

    for operation in [
        "application sync",
        "application rollback",
        "application terminate",
        "Kubernetes apply",
        "Kubernetes patch",
        "Kubernetes delete",
        "raw manifest read",
        "raw secret read",
        "raw log read",
        "generic deployment registry",
    ] {
        assert_eq!(
            service.provider().reject_write(operation),
            Err(ArgoCdDeploymentError::MutationForbidden { operation })
        );
    }
}

#[test]
fn read_fence_detects_project_mission_work_product_or_target_revision_drift() {
    let scope = scope();
    let mut service = fixture_service();
    let mut request = argocd::ArgoCdReadRequest::new(
        &scope,
        service.registration().permission_digest(),
        service.registration().consent_digest().clone(),
    );
    request.mission_revision = argocd::Revision::new(99).expect("revision");
    assert_eq!(
        service.read_with_fence(&request, 10),
        Err(ArgoCdDeploymentError::StaleRevision)
    );
}

#[test]
fn operation_and_sync_status_are_typed_without_raw_details() {
    let scope = scope();
    let mut fixtures = ArgoFixtureSet::for_scope(&scope);
    fixtures.operation.phase = "Running".to_owned();
    fixtures.operation.detail = Some(RAW_MANIFEST.to_owned());
    fixtures.sync_status.sync_status = "OutOfSync".to_owned();
    let mut service = registered(
        &scope,
        RecordingTransport::from_responses(vec![
            ArgoCdResponse::json(200, &fixtures.application).expect("application"),
            ArgoCdResponse::json(200, &fixtures.resource_tree).expect("tree"),
            ArgoCdResponse::json(200, &fixtures.sync_status).expect("sync"),
            ArgoCdResponse::json(200, &fixtures.operation).expect("operation"),
        ]),
    );
    let proposal = service.compile_proposal(10).expect("proposal");
    assert_eq!(proposal.state, argocd::ArgoCdDeploymentState::Syncing);
    let encoded = serde_json::to_string(&proposal).expect("proposal");
    assert!(!encoded.contains(RAW_MANIFEST));
    assert!(proposal.operation.is_some());
}
