use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use hartevo_vercel_delivery_plugin::{
    ArtifactFile, ArtifactManifest, BlockedEnvCredentialResolver, DeploymentEventApi,
    DeploymentListApi, DeploymentPaginationApi, DeploymentState,
    EnvironmentVercelCredentialResolver, MissionScope, MissionSelectedResultConsumer,
    PLUGIN_VERSION, PreviewDeploymentProposalInput, ProjectApi, ProviderProvenance, SourceCommit,
    TeamApi, VERCEL_TOKEN_ENVIRONMENT_VARIABLE, VercelApiTransport, VercelCredentialResolver,
    VercelDeliveryError, VercelDeploymentApi, VercelDeploymentProvider, VercelDeploymentSourceApi,
    VercelPluginRegistration, VercelProviderError, VercelProviderState, VercelSecretReference,
    VercelTarget, VercelTransportError,
};
use serde_json::json;
use zeroize::Zeroizing;

const TOKEN: &str = "controlled-token";
const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

#[derive(Clone, Debug, Default)]
struct ControlledTransport {
    calls: Arc<Mutex<Vec<String>>>,
}

impl ControlledTransport {
    fn record(&self, operation: &str, bearer_token: &str) -> Result<(), VercelTransportError> {
        if bearer_token != TOKEN {
            return Err(VercelTransportError::Unauthorized { status: 401 });
        }
        self.calls
            .lock()
            .map_err(|_| VercelTransportError::Transport {
                detail: "controlled call log poisoned".to_owned(),
            })?
            .push(operation.to_owned());
        Ok(())
    }
}

impl VercelApiTransport for ControlledTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::ControlledProvider
    }

    fn get_team(
        &self,
        bearer_token: &str,
        _team_id: &str,
    ) -> Result<TeamApi, VercelTransportError> {
        self.record("team", bearer_token)?;
        Ok(TeamApi {
            id: "team_1".to_owned(),
            slug: "controlled-team".to_owned(),
            name: "Controlled Team".to_owned(),
        })
    }

    fn get_project(
        &self,
        bearer_token: &str,
        _team_id: &str,
        _project_id: &str,
    ) -> Result<ProjectApi, VercelTransportError> {
        self.record("project", bearer_token)?;
        Ok(ProjectApi {
            id: "prj_1".to_owned(),
            name: "controlled-project".to_owned(),
            account_id: Some("team_1".to_owned()),
            team_id: None,
            framework: Some("nextjs".to_owned()),
        })
    }

    fn list_deployments(
        &self,
        bearer_token: &str,
        _team_id: &str,
        _project_id: &str,
    ) -> Result<DeploymentListApi, VercelTransportError> {
        self.record("deployments", bearer_token)?;
        let states = ["QUEUED", "BUILDING", "READY", "ERROR", "CANCELED"];
        Ok(DeploymentListApi {
            deployments: states
                .iter()
                .enumerate()
                .map(|(index, state)| VercelDeploymentApi {
                    id: format!("dpl_{index}"),
                    uid: None,
                    url: format!("preview-{index}.vercel.app"),
                    name: "controlled-project".to_owned(),
                    state: Some((*state).to_owned()),
                    ready_state: None,
                    target: Some("preview".to_owned()),
                    project_id: Some("prj_1".to_owned()),
                    team_id: Some("team_1".to_owned()),
                    account_id: None,
                    created_at: Some(100 + index as u64),
                    ready_at: None,
                    meta: BTreeMap::new(),
                    git_source: None,
                })
                .collect(),
            pagination: Some(DeploymentPaginationApi {
                count: 5,
                next: Some(9),
                prev: None,
            }),
        })
    }

    fn get_deployment(
        &self,
        bearer_token: &str,
        _team_id: &str,
        _deployment_id_or_url: &str,
    ) -> Result<VercelDeploymentApi, VercelTransportError> {
        self.record("deployment", bearer_token)?;
        Ok(VercelDeploymentApi {
            id: "dpl_ready".to_owned(),
            uid: None,
            url: "ready-preview.vercel.app".to_owned(),
            name: "controlled-project".to_owned(),
            state: None,
            ready_state: Some("READY".to_owned()),
            target: Some("preview".to_owned()),
            project_id: Some("prj_1".to_owned()),
            team_id: Some("team_1".to_owned()),
            account_id: None,
            created_at: Some(100),
            ready_at: Some(200),
            meta: BTreeMap::from([
                ("githubCommitSha".to_owned(), COMMIT.to_owned()),
                ("githubCommitRef".to_owned(), "main".to_owned()),
            ]),
            git_source: Some(VercelDeploymentSourceApi {
                source_type: Some("github".to_owned()),
                sha: Some(COMMIT.to_owned()),
                ref_name: Some("main".to_owned()),
                repo_id: Some("repo-1".to_owned()),
                repo: Some("org/site".to_owned()),
            }),
        })
    }

    fn get_deployment_events(
        &self,
        bearer_token: &str,
        _team_id: &str,
        _deployment_id_or_url: &str,
    ) -> Result<Vec<DeploymentEventApi>, VercelTransportError> {
        self.record("events", bearer_token)?;
        Ok(vec![
            DeploymentEventApi {
                event_type: "deployment-state".to_owned(),
                created: 101,
                payload: json!({"info": {"readyState": "BUILDING"}}),
            },
            DeploymentEventApi {
                event_type: "stdout".to_owned(),
                created: 102,
                payload: json!({"text": "build complete"}),
            },
            DeploymentEventApi {
                event_type: "deployment-state".to_owned(),
                created: 103,
                payload: json!({"info": {"readyState": "READY"}}),
            },
        ])
    }
}

#[derive(Clone, Debug, Default)]
struct ControlledCredentials;

impl VercelCredentialResolver for ControlledCredentials {
    fn resolve(
        &self,
        _reference: &VercelSecretReference,
    ) -> Result<Zeroizing<String>, VercelProviderError> {
        Ok(Zeroizing::new(TOKEN.to_owned()))
    }
}

fn registration() -> VercelPluginRegistration {
    let scope = MissionScope::new("tenant-1", "project-1", "mission-1").expect("scope");
    let target = VercelTarget::preview("team_1", "prj_1").expect("target");
    let secret = VercelSecretReference::for_target("secret-ref-controlled", &scope, &target, 1)
        .expect("secret");
    VercelPluginRegistration::new(scope, target, secret, PLUGIN_VERSION).expect("registration")
}

fn proposal_input() -> PreviewDeploymentProposalInput {
    let scope = MissionScope::new("tenant-1", "project-1", "mission-1").expect("scope");
    let source = SourceCommit::new("org/site", "main", COMMIT).expect("source");
    let artifact = ArtifactManifest::new([
        ArtifactFile::new("index.html", SHA_A, 10).expect("index"),
        ArtifactFile::new("assets/app.js", SHA_B, 20).expect("app"),
    ])
    .expect("artifact");
    PreviewDeploymentProposalInput::new(scope, source, artifact, 1_000).expect("input")
}

#[test]
fn controlled_provider_projects_reads_and_builds_prepare_only_adoption() {
    let transport = ControlledTransport::default();
    let calls = Arc::clone(&transport.calls);
    let provider = VercelDeploymentProvider::new(registration(), transport, ControlledCredentials)
        .expect("provider");
    let mut service = hartevo_vercel_delivery_plugin::DeploymentService::new(provider);

    let target = service.probe_team_project().expect("probe");
    assert_eq!(target.team_id, "team_1");
    assert_eq!(target.project_id, "prj_1");
    assert!(!target.native);
    assert_eq!(
        service.provider().state(),
        VercelProviderState::ReachableNonNative
    );

    let list = service.read_deployments().expect("list");
    assert_eq!(list.deployments.len(), 5);
    assert_eq!(list.next_cursor, Some(9));
    assert_eq!(
        list.deployments
            .iter()
            .map(|deployment| deployment.state)
            .collect::<Vec<_>>(),
        vec![
            DeploymentState::Queued,
            DeploymentState::Building,
            DeploymentState::Ready,
            DeploymentState::Error,
            DeploymentState::Cancelled,
        ]
    );

    let deployment = service.read_deployment("dpl_ready").expect("deployment");
    assert_eq!(deployment.state, DeploymentState::Ready);
    assert_eq!(
        deployment
            .source
            .as_ref()
            .and_then(|source| source.commit_sha.as_deref()),
        Some(COMMIT)
    );
    let events = service.read_deployment_events("dpl_ready").expect("events");
    assert_eq!(events.events[0].state, DeploymentState::Building);
    assert_eq!(events.events[2].state, DeploymentState::Ready);

    let proposal = service.propose_preview(proposal_input()).expect("proposal");
    proposal.validate().expect("valid proposal");
    assert!(proposal.non_mutating);
    assert!(!proposal.external_effect_created);
    assert_eq!(
        proposal.target.environment,
        hartevo_vercel_delivery_plugin::DeploymentEnvironment::Preview
    );

    let result = MissionSelectedResultConsumer
        .adopt(proposal)
        .expect("selected result");
    assert_eq!(
        result.status,
        hartevo_vercel_delivery_plugin::SelectedResultStatus::Proposed
    );
    assert_eq!(result.verification_status, "not_performed_layer_1");
    assert!(!result.native);
    assert!(!result.external_effect_created);

    let calls = calls.lock().expect("calls");
    assert!(calls.iter().all(|operation| operation != "create"));
    assert!(calls.contains(&"team".to_owned()));
    assert!(calls.contains(&"project".to_owned()));
    assert!(calls.contains(&"deployments".to_owned()));
    assert!(calls.contains(&"deployment".to_owned()));
    assert!(calls.contains(&"events".to_owned()));
}

#[test]
fn blocked_environment_never_becomes_connected_or_native() {
    let provider = VercelDeploymentProvider::new(
        registration(),
        ControlledTransport::default(),
        BlockedEnvCredentialResolver,
    )
    .expect("provider");
    let mut service = hartevo_vercel_delivery_plugin::DeploymentService::new(provider);
    assert!(matches!(
        service.probe_team_project(),
        Err(VercelProviderError::BlockedEnv)
    ));
    assert_eq!(service.provider().state(), VercelProviderState::BlockedEnv);
    assert_eq!(
        service.provider().provenance(),
        ProviderProvenance::BlockedEnv
    );
    assert!(!service.provider().is_native());
}

#[test]
fn revocation_fences_all_subsequent_reads() {
    let provider = VercelDeploymentProvider::new(
        registration(),
        ControlledTransport::default(),
        ControlledCredentials,
    )
    .expect("provider");
    let mut service = hartevo_vercel_delivery_plugin::DeploymentService::new(provider);
    service.provider_mut().revoke(2_000).expect("revoke");
    assert!(matches!(
        service.read_deployments(),
        Err(VercelProviderError::Revoked)
    ));
    assert_eq!(service.provider().state(), VercelProviderState::Revoked);
}

#[test]
fn environment_resolver_is_explicit_and_missing_tokens_are_blocked() {
    let scope = MissionScope::new("tenant-1", "project-1", "mission-1").expect("scope");
    let target = VercelTarget::preview("team_1", "prj_1").expect("target");
    let secret =
        VercelSecretReference::for_target("secret-ref-env", &scope, &target, 1).expect("secret");
    if std::env::var(VERCEL_TOKEN_ENVIRONMENT_VARIABLE).is_err() {
        let result = EnvironmentVercelCredentialResolver.resolve(&secret);
        assert!(matches!(result, Err(VercelProviderError::BlockedEnv)));
    }
}

#[test]
fn production_and_malformed_artifact_targets_are_rejected() {
    assert!(matches!(
        VercelTarget::new(
            "team_1",
            "prj_1",
            hartevo_vercel_delivery_plugin::DeploymentEnvironment::Production
        ),
        Err(VercelDeliveryError::UnsupportedTargetEnvironment { .. })
    ));
    assert!(matches!(
        ArtifactFile::new("index.html", "not-a-digest", 1),
        Err(VercelDeliveryError::InvalidInput { .. })
    ));
}
