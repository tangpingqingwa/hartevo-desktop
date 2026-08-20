use hartevo_nomad_deployment_result_plugin as nomad;

use nomad::{
    ConsentScope, FixtureNomadTransport, Mission, MissionNomadDeploymentConsumer, NomadApiResponse,
    NomadDeploymentResultError, NomadDeploymentResultService, NomadDeploymentScope,
    NomadDeploymentState, NomadProvider, NomadProviderScope, NomadTransportError,
    NomadWireAllocation, NomadWireDeployment, NomadWireJob, PermissionSnapshot, Project,
    ProviderProvenance, SecretReference, WorkProduct,
};

fn scope() -> NomadDeploymentScope {
    let project = Project::new("project-1", 1).expect("Project");
    let mission = Mission::new("mission-1", 1).expect("Mission");
    let work_product = WorkProduct::new("work-product-1", 1).expect("Work Product");
    let provider = NomadProviderScope::new(
        "https://nomad.example:4646",
        "default",
        "global",
        Some("dc1"),
        "job-1",
        Some("deployment-1"),
        Some("allocation-1"),
    )
    .expect("provider scope");
    NomadDeploymentScope::new(project, mission, work_product, provider).expect("scope")
}

fn responses(scope: &NomadDeploymentScope) -> Vec<NomadApiResponse> {
    vec![
        NomadApiResponse::json(
            200,
            &NomadWireJob {
                id: scope.provider.job_id.as_str().to_owned(),
                namespace: scope.provider.namespace.as_str().to_owned(),
                region: scope.provider.region.as_str().to_owned(),
                status: "running".to_owned(),
                version: 7,
                create_index: 10,
                modify_index: 20,
                datacenters: vec!["dc1".to_owned()],
                task_groups: vec![nomad::NomadWireTaskGroup::default()],
            },
        )
        .expect("job response"),
        NomadApiResponse::json(
            200,
            &NomadWireDeployment {
                id: scope
                    .provider
                    .deployment_id
                    .as_ref()
                    .expect("deployment")
                    .as_str()
                    .to_owned(),
                job_id: scope.provider.job_id.as_str().to_owned(),
                job_version: 7,
                status: "successful".to_owned(),
                desired_total: 1,
                placed_allocations: 1,
                healthy_allocations: 1,
                unhealthy_allocations: 0,
                create_index: 21,
                modify_index: 22,
                namespace: scope.provider.namespace.as_str().to_owned(),
                region: scope.provider.region.as_str().to_owned(),
            },
        )
        .expect("deployment response"),
        NomadApiResponse::json(
            200,
            &NomadWireAllocation {
                id: scope
                    .provider
                    .allocation_id
                    .as_ref()
                    .expect("allocation")
                    .as_str()
                    .to_owned(),
                job_id: scope.provider.job_id.as_str().to_owned(),
                deployment_id: scope
                    .provider
                    .deployment_id
                    .as_ref()
                    .map(|value| value.as_str().to_owned()),
                node_id: Some("node-1".to_owned()),
                task_group: "web".to_owned(),
                desired_status: "run".to_owned(),
                client_status: "running".to_owned(),
                create_index: 23,
                modify_index: 24,
                namespace: scope.provider.namespace.as_str().to_owned(),
                region: scope.provider.region.as_str().to_owned(),
            },
        )
        .expect("allocation response"),
    ]
}

fn service_with(
    transport: FixtureNomadTransport,
) -> NomadDeploymentResultService<FixtureNomadTransport> {
    let scope = scope();
    let secret = SecretReference::acl_token("opaque-acl-token", &scope, 1).expect("secret");
    let provider = NomadProvider::new(transport, scope.clone(), secret).expect("provider");
    NomadDeploymentResultService::register(
        provider,
        "registration-1",
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::new("consent-1", &scope, 1, 100).expect("consent"),
        1,
    )
    .expect("service")
}

#[test]
fn contract_and_layer_one_authority_are_machine_checked() {
    let contract: serde_json::Value =
        serde_json::from_str(nomad::CONTRACT_JSON).expect("contract JSON");
    assert_eq!(
        contract["contractDigest"],
        nomad::contract_digest().as_str()
    );
    assert_eq!(contract["service"]["type"], "NomadDeploymentResultService");
    assert_eq!(contract["provider"]["type"], "NomadProvider");
    assert_eq!(
        contract["consumer"]["type"],
        "MissionNomadDeploymentConsumer"
    );
    assert_eq!(
        contract["provider"]["operations"].as_array().map(Vec::len),
        Some(3)
    );
    assert_eq!(
        contract["allowlist"]["writes"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(!nomad::AuthorityBoundary::connected());
    assert!(!nomad::AuthorityBoundary::native_provider());
    assert!(!nomad::AuthorityBoundary::first_party_provider());
    assert!(!nomad::AuthorityBoundary::truth());
    assert!(!nomad::AuthorityBoundary::consent());
    assert!(!nomad::AuthorityBoundary::effect());
    assert!(!nomad::AuthorityBoundary::receipt());
    assert!(!nomad::AuthorityBoundary::verification());
    assert!(!nomad::AuthorityBoundary::outcome());
    assert!(!nomad::AuthorityBoundary::external_writes());
    assert!(!nomad::AuthorityBoundary::work_product_adoption());
}

#[test]
fn happy_path_is_exactly_scoped_redacted_and_review_only() {
    let expected_scope = scope();
    let mut service = service_with(FixtureNomadTransport::new(responses(&expected_scope)));
    let evidence = service.read(10).expect("evidence");
    assert_eq!(evidence.state, NomadDeploymentState::Successful);
    assert!(evidence.complete);
    assert_eq!(evidence.item_count, 3);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.first_party);
    assert!(!evidence.provider_receipt);
    assert!(!evidence.redaction.raw_job_payload_retained);
    evidence.validate_integrity().expect("evidence integrity");

    let serialized = serde_json::to_string(&evidence).expect("evidence JSON");
    assert!(!serialized.contains("opaque-acl-token"));
    assert!(!serialized.contains("TaskGroups"));

    let proposal = service
        .compile_proposal_from_evidence(evidence)
        .expect("proposal");
    assert!(!proposal.is_adoptable());
    let verification = service.verify_proposal(&proposal).expect("verification");
    assert!(verification.valid);
    assert!(!verification.business_verified);

    let receipt = service
        .record_observation(&proposal, "observation-1", 10)
        .expect("local record");
    assert!(!receipt.replayed);
    assert!(!receipt.durable_provider_receipt);
    let replay = service
        .record_observation(&proposal, "observation-1", 11)
        .expect("idempotent replay");
    assert!(replay.replayed);

    let consumer =
        MissionNomadDeploymentConsumer::new(expected_scope, service.registration().clone())
            .expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(result.review_only);
    assert!(!result.connected);
    assert!(!result.native);
    assert!(!result.first_party);
    assert!(!result.outcome_adopted);
    assert!(!result.work_product_adopted);
    assert!(!result.can_be_adopted());
}

#[test]
fn all_non_native_provenances_stay_below_provider_authority() {
    let scope = scope();
    let responses = responses(&scope);
    let transports = [
        FixtureNomadTransport::new(responses.clone()).provenance(),
        nomad::NomadRecordingTransport::new(responses.clone()).provenance(),
        nomad::FakeNomadTransport::new(responses.clone()).provenance(),
        nomad::LoopbackNomadTransport::new(responses).provenance(),
        nomad::BlockedEnvNomadTransport::new().provenance(),
    ];
    assert_eq!(
        transports,
        [
            ProviderProvenance::Fixture,
            ProviderProvenance::Recording,
            ProviderProvenance::Fake,
            ProviderProvenance::Loopback,
            ProviderProvenance::BlockedEnv,
        ]
    );
    for provenance in transports {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
        assert!(!provenance.provider_receipt());
    }
}

#[test]
fn absent_partial_access_loss_provider_unknown_and_blocked_env_are_explicit() {
    let statuses = [
        (404, NomadDeploymentState::Absent),
        (206, NomadDeploymentState::Partial),
        (403, NomadDeploymentState::AccessLoss),
        (500, NomadDeploymentState::ProviderUnknown),
    ];
    for (status, expected) in statuses {
        let mut service = service_with(FixtureNomadTransport::new(vec![NomadApiResponse::new(
            status,
            b"{}".to_vec(),
        )]));
        let evidence = service.read(10).expect("typed failure evidence");
        assert_eq!(evidence.state, expected);
        assert!(evidence.failure.is_some());
        assert!(!evidence.connected);
        assert!(!evidence.native);
        assert!(!evidence.first_party);
    }

    let mut blocked = service_with(FixtureNomadTransport::from_results([Err(
        NomadTransportError::BlockedEnv,
    )]));
    assert_eq!(
        blocked.read(10).expect("blocked evidence").state,
        NomadDeploymentState::BlockedEnv
    );
}

#[test]
fn response_tamper_scope_drift_and_replay_are_fail_closed() {
    let scope = scope();
    let body = serde_json::to_vec(&NomadWireJob {
        id: scope.provider.job_id.as_str().to_owned(),
        namespace: "default".to_owned(),
        region: "global".to_owned(),
        status: "running".to_owned(),
        version: 1,
        create_index: 1,
        modify_index: 2,
        datacenters: vec!["dc1".to_owned()],
        task_groups: vec![],
    })
    .expect("wire body");
    let tampered =
        NomadApiResponse::with_digest(200, body, nomad::Digest::from_text("wrong-response-digest"));
    let mut service = service_with(FixtureNomadTransport::new(vec![tampered]));
    let evidence = service.read(10).expect("tamper evidence");
    assert_eq!(evidence.state, NomadDeploymentState::Tampered);
    assert!(
        service
            .compile_proposal_from_evidence(evidence)
            .expect_err("tampered evidence must not become a proposal")
            == NomadDeploymentResultError::TamperedEvidence
    );

    let mut wrong = responses(&scope);
    wrong[0] = NomadApiResponse::json(
        200,
        &NomadWireJob {
            id: "other-job".to_owned(),
            namespace: "default".to_owned(),
            region: "global".to_owned(),
            status: "running".to_owned(),
            version: 1,
            create_index: 1,
            modify_index: 2,
            datacenters: vec!["dc1".to_owned()],
            task_groups: vec![],
        },
    )
    .expect("wrong job");
    let mut scope_drift = service_with(FixtureNomadTransport::new(wrong));
    assert_eq!(
        scope_drift.read(10).expect("scope tamper evidence").state,
        NomadDeploymentState::Tampered
    );

    let mut healthy = service_with(FixtureNomadTransport::new(responses(&scope)));
    let proposal = healthy.compile_proposal(10).expect("proposal");
    let conflict = healthy
        .record_observation(&proposal, "same-key", 10)
        .expect("first record");
    assert!(!conflict.replayed);
    let replay = healthy
        .record_observation(&proposal, "same-key", 11)
        .expect("same proposal replay");
    assert!(replay.replayed);
    assert_eq!(NomadDeploymentState::Replay, NomadDeploymentState::Replay);
}

#[test]
fn registration_is_reversible_revocable_and_bound_to_secret_scope() {
    let scope = scope();
    let secret = SecretReference::acl_token("super-secret-acl", &scope, 1).expect("secret");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("super-secret-acl"));
    let registration = nomad::NomadDeploymentRegistration::new(
        "registration-1",
        scope.clone(),
        secret,
        PermissionSnapshot::for_layer_one(1).expect("permissions"),
        ConsentScope::new("consent-1", &scope, 1, 100).expect("consent"),
        1,
    )
    .expect("registration");
    let serialized = serde_json::to_string(&registration).expect("registration JSON");
    assert!(!serialized.contains("super-secret-acl"));
    assert!(serialized.contains("secretReferenceDigest"));

    let provider = NomadProvider::new(
        FixtureNomadTransport::new(responses(&scope)),
        scope.clone(),
        SecretReference::acl_token("super-secret-acl", &scope, 1).expect("secret"),
    )
    .expect("provider");
    let mut service = NomadDeploymentResultService::new(provider, registration).expect("service");
    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(revoked.to, nomad::RegistrationStatus::Revoked);
    assert_eq!(
        service.read(10).expect_err("revoked registration"),
        NomadDeploymentResultError::RegistrationInactive
    );
    service.restore_registration().expect("restore");
    let reversed = service.reverse_registration().expect("reverse");
    assert_eq!(reversed.to, nomad::RegistrationStatus::Reversed);
    assert_eq!(
        service
            .restore_registration()
            .expect_err("terminal reversal"),
        NomadDeploymentResultError::RegistrationReversed
    );
}

#[test]
fn writes_are_explicitly_forbidden() {
    let scope = scope();
    let service = service_with(FixtureNomadTransport::new(responses(&scope)));
    assert_eq!(
        service.reject_write("job_submit").expect_err("write"),
        NomadDeploymentResultError::MutationForbidden {
            operation: "job_submit"
        }
    );
}
