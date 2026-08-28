use hartevo_octopus_release_result_plugin::{
    BlockedEnvOctopusTransport, ChannelPayload, ChannelScope, ConsentScope, DeploymentPayload,
    DeploymentProcessPayload, DeploymentProcessTemplatePayload, DeploymentScope, Digest,
    EnvironmentPayload, EnvironmentScope, FixtureOctopusTransport, LoopbackOctopusTransport,
    MissionOctopusReleaseConsumer, OctopusEndpoint, OctopusHttpRequest, OctopusProvider,
    OctopusRegistrationRequest, OctopusReleaseResultRecordingLog, OctopusReleaseResultService,
    OctopusResponseBody, OctopusScope, PermissionSnapshot, ProjectPayload, ProjectScope,
    ProjectionStatus, RecordingOctopusTransport, ReleasePayload, ReleaseScope, SecretReference,
    ServerScope, SpacePayload, SpaceScope, TargetScope, TaskPayload, TenantPayload, TenantScope,
    TransportProvenance, validate_contract_document,
};

const SERVER: &str = "https://octopus.example.test";

fn scope() -> OctopusScope {
    OctopusScope::new(
        ServerScope::new(SERVER, 1).expect("server"),
        SpaceScope::new("Spaces-1", 2).expect("space"),
        hartevo_octopus_release_result_plugin::OctopusProjectScope::new(
            "Projects-1",
            3,
            "deploymentprocess-Projects-1",
        )
        .expect("project"),
        ChannelScope::new("Channels-1", 4).expect("channel"),
        ReleaseScope::new("Releases-1", "2026.08.14.1", 5).expect("release"),
        EnvironmentScope::new("Environments-1", 6).expect("environment"),
        TenantScope::new("Tenants-1", 7).expect("tenant"),
        DeploymentScope::new("Deployments-1", "ServerTasks-1", 8).expect("deployment"),
        TargetScope::new("Machines-1", 9).expect("target"),
        hartevo_octopus_release_result_plugin::MissionScope::new("mission-1", 10).expect("mission"),
        ProjectScope::new("hartevo-project-1", 11).expect("Hartevo project"),
        ConsentScope::new(
            "consent-1",
            12,
            Digest::from_text("approved").expect("digest"),
        )
        .expect("consent"),
    )
    .expect("scope")
}

fn entries(scope: &OctopusScope, state: &str) -> Vec<(OctopusEndpoint, OctopusResponseBody)> {
    let server = scope.server.origin.clone();
    let space_id = scope.space.id.as_str().to_owned();
    let project_id = scope.project.id.as_str().to_owned();
    let process_id = scope.project.deployment_process_id.as_str().to_owned();
    let channel_id = scope.channel.id.as_str().to_owned();
    let target_id = scope.target.id.as_str().to_owned();
    vec![
        (
            OctopusEndpoint::Spaces {
                server: server.clone(),
            },
            OctopusResponseBody::Spaces(vec![SpacePayload {
                id: space_id.clone(),
                name: "Default".to_owned(),
                revision: scope.space.revision,
            }]),
        ),
        (
            OctopusEndpoint::Projects {
                server: server.clone(),
                space_id: space_id.clone(),
            },
            OctopusResponseBody::Projects(vec![ProjectPayload {
                id: project_id.clone(),
                name: "Deploy Project".to_owned(),
                deployment_process_id: process_id.clone(),
                revision: scope.project.revision,
            }]),
        ),
        (
            OctopusEndpoint::Channels {
                server: server.clone(),
                space_id: space_id.clone(),
                project_id: project_id.clone(),
            },
            OctopusResponseBody::Channels(vec![ChannelPayload {
                id: channel_id.clone(),
                project_id: project_id.clone(),
                name: "Default".to_owned(),
                revision: scope.channel.revision,
            }]),
        ),
        (
            OctopusEndpoint::Environments {
                server: server.clone(),
                space_id: space_id.clone(),
            },
            OctopusResponseBody::Environments(vec![EnvironmentPayload {
                id: scope.environment.id.as_str().to_owned(),
                name: "Production".to_owned(),
                revision: scope.environment.revision,
            }]),
        ),
        (
            OctopusEndpoint::Tenants {
                server: server.clone(),
                space_id: space_id.clone(),
            },
            OctopusResponseBody::Tenants(vec![TenantPayload {
                id: scope
                    .tenant
                    .id
                    .as_ref()
                    .expect("tenant")
                    .as_str()
                    .to_owned(),
                name: "Tenant One".to_owned(),
                revision: scope.tenant.revision,
            }]),
        ),
        (
            OctopusEndpoint::Release {
                server: server.clone(),
                space_id: space_id.clone(),
                release_id: scope.release.id.as_str().to_owned(),
            },
            OctopusResponseBody::Release(ReleasePayload {
                id: scope.release.id.as_str().to_owned(),
                project_id: project_id.clone(),
                channel_id: channel_id.clone(),
                version: scope.release.version.as_str().to_owned(),
                selected_package_count: 2,
                revision: scope.release.revision,
            }),
        ),
        (
            OctopusEndpoint::DeploymentProcess {
                server: server.clone(),
                space_id: space_id.clone(),
                deployment_process_id: process_id.clone(),
            },
            OctopusResponseBody::DeploymentProcess(DeploymentProcessPayload {
                id: process_id.clone(),
                project_id: project_id.clone(),
                step_count: 2,
                action_count: 3,
                revision: 20,
            }),
        ),
        (
            OctopusEndpoint::DeploymentProcessTemplate {
                server: server.clone(),
                space_id: space_id.clone(),
                deployment_process_id: process_id.clone(),
                channel_id: channel_id.clone(),
            },
            OctopusResponseBody::DeploymentProcessTemplate(DeploymentProcessTemplatePayload {
                process_id,
                project_id: project_id.clone(),
                channel_id,
                package_count: 2,
                revision: 21,
            }),
        ),
        (
            OctopusEndpoint::Deployment {
                server: server.clone(),
                space_id,
                deployment_id: scope.deployment.id.as_str().to_owned(),
            },
            OctopusResponseBody::Deployment(DeploymentPayload {
                id: scope.deployment.id.as_str().to_owned(),
                release_id: scope.release.id.as_str().to_owned(),
                project_id,
                environment_id: scope.environment.id.as_str().to_owned(),
                tenant_id: scope.tenant.id.as_ref().map(ToString::to_string),
                task_id: scope.deployment.task_id.as_str().to_owned(),
                state: state.to_owned(),
                target_ids: vec![target_id.clone()],
                revision: scope.deployment.revision,
            }),
        ),
        (
            OctopusEndpoint::Task {
                server,
                task_id: scope.deployment.task_id.as_str().to_owned(),
            },
            OctopusResponseBody::Task(TaskPayload {
                id: scope.deployment.task_id.as_str().to_owned(),
                deployment_id: scope.deployment.id.as_str().to_owned(),
                state: state.to_owned(),
                finished_successfully: None,
                target_ids: vec![target_id],
                revision: 22,
            }),
        ),
    ]
}

fn registration() -> hartevo_octopus_release_result_plugin::OctopusRegistration {
    let mut service = OctopusReleaseResultService::new();
    let receipt = service.register(
        OctopusRegistrationRequest::new(
            registration_scope(),
            registration_secret(),
            PermissionSnapshot::read_only(),
            1,
        )
        .expect("request"),
    );
    let digest = receipt.expect("receipt").registration_digest;
    service.get(&digest).expect("registration").clone()
}

fn registration_scope() -> OctopusScope {
    scope()
}

fn registration_secret() -> SecretReference {
    let current_scope = scope();
    let permissions = PermissionSnapshot::read_only();
    SecretReference::new("opaque://octopus/layer1")
        .expect("secret")
        .bind_to(&current_scope, &permissions)
        .expect("bound secret")
}

#[test]
fn contract_and_capability_boundary_are_exact() {
    validate_contract_document().expect("contract");
    let service = OctopusReleaseResultService::new();
    let capabilities = service.describe_capabilities();
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(!capabilities.external_writes);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.kernel_authority);
    assert!(!capabilities.raw_task_logs);
    assert!(!capabilities.raw_scripts);
    assert!(!capabilities.package_bytes);
    assert!(!capabilities.generic_deployment_registry);
    assert_eq!(
        capabilities.transport_provenance,
        ["recording", "fixture", "loopback", "blocked_env"]
    );
}

#[test]
fn registration_is_digest_bound_reversible_and_revocable() {
    let current_scope = scope();
    let permissions = PermissionSnapshot::read_only();
    let secret = SecretReference::new("opaque://octopus/registration")
        .expect("secret")
        .bind_to(&current_scope, &permissions)
        .expect("bound secret");
    let mut service = OctopusReleaseResultService::new();
    let request =
        OctopusRegistrationRequest::new(current_scope, secret, permissions, 7).expect("request");
    let registered = service.register(request).expect("registered");
    assert!(registered.reversible);
    assert!(registered.revocable);
    assert!(!registered.connected);
    assert!(!registered.native);

    let reversed = service
        .reverse_registration(&registered.registration_digest)
        .expect("reversed");
    assert_eq!(
        reversed.status,
        hartevo_octopus_release_result_plugin::OctopusRegistrationStatus::Reversed
    );
    assert!(
        service
            .reverse_registration(&registered.registration_digest)
            .is_err()
    );

    let current_scope = scope();
    let permissions = PermissionSnapshot::read_only();
    let secret = SecretReference::new("opaque://octopus/revocable")
        .expect("secret")
        .bind_to(&current_scope, &permissions)
        .expect("bound secret");
    let registered = service
        .register(
            OctopusRegistrationRequest::new(current_scope, secret, permissions, 8)
                .expect("request"),
        )
        .expect("registered");
    let revoked = service
        .revoke_registration(&registered.registration_digest)
        .expect("revoked");
    assert_eq!(
        revoked.status,
        hartevo_octopus_release_result_plugin::OctopusRegistrationStatus::Revoked
    );
}

#[test]
fn fixture_read_projects_success_and_records_only_redacted_gets() {
    let registration = registration();
    let scope = registration.scope.clone();
    let fixture = RecordingOctopusTransport::new(entries(&scope, "Succeeded")).expect("fixture");
    let mut provider = OctopusProvider::new(registration.clone(), fixture).expect("provider");
    let projection = provider.read_result().expect("projection");
    assert_eq!(projection.status, ProjectionStatus::Succeeded);
    assert_eq!(projection.provenance, TransportProvenance::Recording);
    assert_eq!(projection.receipts.len(), 10);
    assert!(projection.receipts.iter().all(|receipt| {
        receipt.method == "GET"
            && !receipt.raw_provider_payload
            && !receipt.credential_material
            && !receipt.connected
            && !receipt.native
    }));
    assert!(!projection.connected);
    assert!(!projection.native);
    projection
        .validate_integrity()
        .expect("projection integrity");
    assert_eq!(provider.transport().requests().len(), 10);
    assert!(
        provider
            .transport()
            .requests()
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );

    let consumer = MissionOctopusReleaseConsumer::new(&registration).expect("consumer");
    let proposal = consumer
        .compile_proposal(&projection, "release-result-1")
        .expect("proposal");
    assert!(proposal.is_review_only());
    assert!(!proposal.can_be_adopted());
    let mut log = OctopusReleaseResultRecordingLog::default();
    let recorded = consumer.record(&proposal, &mut log).expect("recording");
    assert!(!recorded.replayed);
    let replay = consumer.record(&proposal, &mut log).expect("replay");
    assert!(replay.replayed);
    assert_eq!(log.len(), 1);
}

#[test]
fn status_vocabulary_and_missing_access_are_projection_states() {
    for (provider_state, expected) in [
        ("Queued", ProjectionStatus::Queued),
        ("Running", ProjectionStatus::Running),
        ("Succeeded", ProjectionStatus::Succeeded),
        ("Failed", ProjectionStatus::Failed),
        ("Canceled", ProjectionStatus::Canceled),
        ("Paused", ProjectionStatus::Paused),
    ] {
        let registered = registration();
        let scope = registered.scope.clone();
        let transport =
            LoopbackOctopusTransport::new(entries(&scope, provider_state)).expect("loopback");
        let mut provider = OctopusProvider::new(registered, transport).expect("provider");
        assert_eq!(provider.read_result().expect("result").status, expected);
    }

    let access_registration = registration();
    let scope = access_registration.scope.clone();
    let mut fixture = FixtureOctopusTransport::empty();
    fixture
        .insert_status(
            OctopusEndpoint::Spaces {
                server: scope.server.origin.clone(),
            },
            403,
        )
        .expect("status");
    let mut provider = OctopusProvider::new(access_registration, fixture).expect("provider");
    assert_eq!(
        provider.read_result().expect("access projection").status,
        ProjectionStatus::AccessLost
    );

    let retention_registration = registration();
    let scope = retention_registration.scope.clone();
    let mut fixture = FixtureOctopusTransport::empty();
    fixture
        .insert_status(
            OctopusEndpoint::Spaces {
                server: scope.server.origin,
            },
            404,
        )
        .expect("status");
    let mut provider = OctopusProvider::new(retention_registration, fixture).expect("provider");
    assert_eq!(
        provider.read_result().expect("retention projection").status,
        ProjectionStatus::RetentionGap
    );
}

#[test]
fn blocked_env_and_secret_reference_are_honest() {
    let registration = registration();
    let secret_json = serde_json::to_string(&registration.secret_reference).expect("json");
    assert!(!secret_json.contains("opaque://octopus/layer1"));
    assert!(secret_json.contains("referenceDigest"));

    let mut provider =
        OctopusProvider::new(registration, BlockedEnvOctopusTransport).expect("provider");
    let projection = provider.read_result().expect("blocked projection");
    assert_eq!(projection.status, ProjectionStatus::ProviderUnknown);
    assert_eq!(projection.provenance, TransportProvenance::BlockedEnv);
    assert!(!projection.connected);
    assert!(!projection.native);
    assert_eq!(
        provider.state(),
        hartevo_octopus_release_result_plugin::OctopusProviderState::BlockedEnv
    );

    let endpoint = OctopusEndpoint::DeploymentProcessTemplate {
        server: SERVER.to_owned(),
        space_id: "Spaces-1".to_owned(),
        deployment_process_id: "deploymentprocess-Projects-1".to_owned(),
        channel_id: "Channels-1".to_owned(),
    };
    assert_eq!(
        OctopusHttpRequest::new(endpoint, 1_048_576)
            .expect("request")
            .path_and_query()
            .expect("path"),
        "https://octopus.example.test/api/Spaces-1/deploymentprocesses/deploymentprocess-Projects-1/template?channel=Channels-1"
    );
}
