use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_plugin_runtime::{
    MissionId as RuntimeMissionId, PluginRuntime, PluginScope, ProjectId as RuntimeProjectId,
};

use hartevo_azure_devops_work_plugin::{
    ArtifactPayload, AzureDevOpsEndpoint, AzureDevOpsHttpRequest, AzureDevOpsHttpResponse,
    AzureDevOpsReadRequest, AzureDevOpsResponseBody, AzureDevOpsScope, AzureDevOpsScopeInput,
    AzureDevOpsServicesProvider, AzureDevOpsTransportError, AzureDevOpsWorkContract,
    AzureDevOpsWorkEvidence, AzureDevOpsWorkTransport, BlockedEnvCredentialResolver, BuildPayload,
    EntraAccessToken, EntraCredentialError, EntraCredentialResolver, EntraSecretReference,
    FakeAzureDevOpsTransport, MissionAzureDevOpsWorkConsumer, NativeProbeStatus,
    PullRequestPayload, RecordingAzureDevOpsTransport, TimelineRecordPayload, TransportProvenance,
    WorkItemPayload, WorkItemRelationPayload, contract_digest, native_probe_from_environment,
    plugin_definition,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const HEAD_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid test timestamp")
}

fn scope() -> AzureDevOpsScope {
    AzureDevOpsScope::new(AzureDevOpsScopeInput {
        organization: "contoso".to_owned(),
        project: "Hartevo Project".to_owned(),
        repository_id: "repo-1".to_owned(),
        work_item_id: 7,
        mission_id: "mission-1".to_owned(),
        mission_revision: 3,
        hartevo_project_id: "project-1".to_owned(),
        project_revision: 4,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 5,
    })
    .expect("scope")
}

fn secret() -> EntraSecretReference {
    EntraSecretReference::new("vault/entra/azure-devops", "tenant-1", "client-1", 1)
        .expect("secret reference")
}

#[derive(Clone, Debug)]
struct FixtureResolver;

impl EntraCredentialResolver for FixtureResolver {
    fn resolve(
        &mut self,
        _reference: &EntraSecretReference,
        at: DateTime<Utc>,
    ) -> Result<EntraAccessToken, EntraCredentialError> {
        EntraAccessToken::new(
            "fixture-token",
            at - Duration::seconds(1),
            at + Duration::seconds(120),
        )
    }
}

fn request(endpoint: AzureDevOpsEndpoint, at: DateTime<Utc>) -> AzureDevOpsHttpRequest {
    AzureDevOpsHttpRequest::new(
        endpoint,
        at,
        hartevo_azure_devops_work_plugin::AZURE_DEVOPS_MAX_RESPONSE_BYTES,
    )
    .expect("request")
}

fn response(
    endpoint: AzureDevOpsEndpoint,
    body: AzureDevOpsResponseBody,
    at: DateTime<Utc>,
) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
    let request = request(endpoint, at);
    AzureDevOpsHttpResponse::from_body(&request, body)
}

fn work_item_response(
    at: DateTime<Utc>,
) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
    response(
        AzureDevOpsEndpoint::WorkItem {
            organization: "contoso".to_owned(),
            project: "Hartevo Project".to_owned(),
            work_item_id: 7,
        },
        AzureDevOpsResponseBody::WorkItem(WorkItemPayload {
            id: 7,
            rev: 9,
            title: Some("Implement Azure DevOps evidence".to_owned()),
            state: Some("Active".to_owned()),
            work_item_type: Some("Task".to_owned()),
            relations: vec![WorkItemRelationPayload {
                relation_type: "ArtifactLink".to_owned(),
                url: "https://dev.azure.com/contoso/Hartevo%20Project/_apis/git/repositories/repo-1/pullRequests/42".to_owned(),
            }],
        }),
        at,
    )
}

fn pull_request_response(
    at: DateTime<Utc>,
) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
    response(
        AzureDevOpsEndpoint::PullRequest {
            organization: "contoso".to_owned(),
            project: "Hartevo Project".to_owned(),
            repository_id: "repo-1".to_owned(),
            pull_request_id: 42,
        },
        AzureDevOpsResponseBody::PullRequest(PullRequestPayload {
            pull_request_id: 42,
            repository_id: "repo-1".to_owned(),
            status: "active".to_owned(),
            title: Some("Azure DevOps Work Layer 1".to_owned()),
            source_ref_name: "refs/heads/feature/azdo".to_owned(),
            target_ref_name: "refs/heads/main".to_owned(),
            source_commit: Some(HEAD_SHA.to_owned()),
            target_commit: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()),
            last_merge_source_commit: Some(HEAD_SHA.to_owned()),
            last_merge_target_commit: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()),
        }),
        at,
    )
}

fn build_response(at: DateTime<Utc>) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
    response(
        AzureDevOpsEndpoint::Builds {
            organization: "contoso".to_owned(),
            project: "Hartevo Project".to_owned(),
            repository_id: "repo-1".to_owned(),
            pull_request_id: 42,
            page: 1,
            top: hartevo_azure_devops_work_plugin::AZURE_DEVOPS_PAGE_SIZE,
            continuation_token: None,
        },
        AzureDevOpsResponseBody::Builds(vec![BuildPayload {
            id: 100,
            build_number: Some("2026.08.14.1".to_owned()),
            status: Some("completed".to_owned()),
            result: Some("succeeded".to_owned()),
            source_version: HEAD_SHA.to_owned(),
            source_branch: "refs/pull/42/merge".to_owned(),
            repository_id: Some("repo-1".to_owned()),
            queue_time: None,
            start_time: None,
            finish_time: None,
            definition_name: Some("CI".to_owned()),
        }]),
        at,
    )
}

fn timeline_response(
    at: DateTime<Utc>,
) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
    response(
        AzureDevOpsEndpoint::Timeline {
            organization: "contoso".to_owned(),
            project: "Hartevo Project".to_owned(),
            build_id: 100,
            page: 1,
            top: hartevo_azure_devops_work_plugin::AZURE_DEVOPS_PAGE_SIZE,
            continuation_token: None,
        },
        AzureDevOpsResponseBody::Timeline(vec![TimelineRecordPayload {
            id: "timeline-1".to_owned(),
            record_type: Some("Task".to_owned()),
            name: Some("cargo test".to_owned()),
            state: Some("completed".to_owned()),
            result: Some("succeeded".to_owned()),
            order: Some(1),
            start_time: None,
            finish_time: None,
            error_count: Some(0),
            warning_count: Some(0),
            log_reference_present: false,
        }]),
        at,
    )
}

fn artifacts_response(
    at: DateTime<Utc>,
) -> Result<AzureDevOpsHttpResponse, AzureDevOpsTransportError> {
    response(
        AzureDevOpsEndpoint::Artifacts {
            organization: "contoso".to_owned(),
            project: "Hartevo Project".to_owned(),
            build_id: 100,
            page: 1,
            top: hartevo_azure_devops_work_plugin::AZURE_DEVOPS_PAGE_SIZE,
            continuation_token: None,
        },
        AzureDevOpsResponseBody::Artifacts(vec![ArtifactPayload {
            id: "artifact-1".to_owned(),
            name: "test-results".to_owned(),
            artifact_type: Some("Container".to_owned()),
        }]),
        at,
    )
}

fn provider(
    at: DateTime<Utc>,
) -> AzureDevOpsServicesProvider<RecordingAzureDevOpsTransport, FixtureResolver> {
    let responses = [
        work_item_response(at),
        pull_request_response(at),
        build_response(at),
        timeline_response(at),
        artifacts_response(at),
    ];
    AzureDevOpsServicesProvider::new(
        scope(),
        secret(),
        RecordingAzureDevOpsTransport::fixture(responses),
        FixtureResolver,
        at,
    )
    .expect("provider")
}

#[test]
fn contract_plugin_definition_and_native_gap_are_exact() {
    let contract = AzureDevOpsWorkContract::baseline().expect("contract");
    assert_eq!(contract.digest(), contract_digest());
    assert_eq!(contract.api_version, "7.1");
    assert!(contract.read_only);
    assert!(contract.mutating_provider_operations.is_empty());
    assert!(!contract.authority.connected);
    assert!(!contract.authority.raw_logs);
    assert!(!contract.authority.raw_artifacts);

    let runtime_scope = PluginScope::new(
        RuntimeProjectId::new("project-1").expect("runtime project"),
        RuntimeMissionId::new("mission-1").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    let definition = plugin_definition(runtime_scope.clone()).expect("definition");
    assert_eq!(definition.scope(), &runtime_scope);
    assert_eq!(
        definition.version(),
        hartevo_azure_devops_work_plugin::plugin_version()
    );
    assert_eq!(
        native_probe_from_environment().status,
        NativeProbeStatus::BlockedEnv
    );
    assert!(!native_probe_from_environment().native_connected_claim);

    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition).expect("define");
    let receipt = runtime.mount(&handle).expect("mount");
    assert_eq!(receipt.generation(), 1);
    runtime.revoke(&handle).expect("revoke");
}

#[test]
fn work_item_revision_to_pr_build_timeline_and_artifact_evidence_is_bounded() {
    let at = now();
    let mut provider = provider(at);
    let request = AzureDevOpsReadRequest::new()
        .with_expected_work_item_rev(9)
        .expect("revision")
        .with_expected_pull_request_id(42)
        .expect("pull request");
    let consumer = MissionAzureDevOpsWorkConsumer::new(scope());
    let result = consumer.read(&mut provider, &request, at).expect("read");
    result.validate(&scope()).expect("result validation");
    let evidence: &AzureDevOpsWorkEvidence = &result.evidence;
    assert_eq!(evidence.work_item.rev, 9);
    assert_eq!(evidence.pull_request.id.get(), 42);
    assert_eq!(evidence.builds.len(), 1);
    assert_eq!(evidence.builds[0].timeline.len(), 1);
    assert_eq!(evidence.builds[0].artifacts.len(), 1);
    assert!(!evidence.native_evidence);
    assert!(!evidence.external_write_performed);
    assert!(!evidence.outcome_authority);
    assert!(evidence.receipts.iter().all(|receipt| {
        receipt.api_version == "7.1"
            && !receipt.raw_payload_retained
            && !receipt.raw_logs_retained
            && !receipt.raw_artifacts_retained
            && !receipt.credential_material_retained
    }));
    let serialized = serde_json::to_string(&result).expect("result JSON");
    assert!(!serialized.contains("fixture-token"));
    assert!(!serialized.contains("downloadUrl"));
    assert!(!serialized.contains("raw log contents"));
    assert_eq!(provider.transport().requests().len(), 5);
    assert!(provider.transport().requests().iter().all(|request| {
        request.api_version == "7.1"
            && request
                .path_and_query()
                .expect("request URL")
                .contains("api-version=7.1")
    }));
}

#[test]
fn recording_and_fixture_provenance_never_become_native_connected() {
    let at = now();
    let fixture = provider(at);
    assert_eq!(
        fixture.transport().provenance(),
        TransportProvenance::Fixture
    );
    assert!(!fixture.transport().provenance().is_native());
    assert!(!fixture.transport().provenance().is_connected());
    assert!(!fixture.is_connected());

    let fake: FakeAzureDevOpsTransport = RecordingAzureDevOpsTransport::fixture([]);
    assert_eq!(fake.provenance(), TransportProvenance::Fixture);
    assert!(!fake.provenance().is_native());

    let blocked = BlockedEnvCredentialResolver;
    assert_eq!(format!("{blocked:?}"), "BlockedEnvCredentialResolver");
}

#[test]
fn blocked_env_revocation_scope_and_revision_fences_fail_closed() {
    let at = now();
    let mut blocked = AzureDevOpsServicesProvider::new(
        scope(),
        secret(),
        RecordingAzureDevOpsTransport::fixture([]),
        BlockedEnvCredentialResolver,
        at,
    )
    .expect("blocked provider");
    let error = blocked
        .read(&AzureDevOpsReadRequest::new(), at)
        .expect_err("native credential resolution must be blocked");
    assert_eq!(
        error,
        hartevo_azure_devops_work_plugin::AzureDevOpsWorkError::BlockedEnv
    );
    assert!(blocked.transport().requests().is_empty());

    let mut revoked = provider(at);
    revoked.revoke(at + Duration::seconds(1)).expect("revoke");
    assert_eq!(
        revoked
            .read(&AzureDevOpsReadRequest::new(), at + Duration::seconds(2))
            .expect_err("revoked registration"),
        hartevo_azure_devops_work_plugin::AzureDevOpsWorkError::RegistrationRevoked
    );

    let wrong_scope = AzureDevOpsScope::new(AzureDevOpsScopeInput {
        organization: "other-org".to_owned(),
        project: "Hartevo Project".to_owned(),
        repository_id: "repo-1".to_owned(),
        work_item_id: 7,
        mission_id: "mission-1".to_owned(),
        mission_revision: 3,
        hartevo_project_id: "project-1".to_owned(),
        project_revision: 4,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 5,
    })
    .expect("wrong scope");
    let mut scoped = provider(at);
    let error = MissionAzureDevOpsWorkConsumer::new(wrong_scope)
        .read(&mut scoped, &AzureDevOpsReadRequest::new(), at)
        .expect_err("consumer scope fence");
    assert!(matches!(
        error,
        hartevo_azure_devops_work_plugin::AzureDevOpsWorkError::ScopeMismatch(_)
    ));

    let mut stale = provider(at);
    let request = AzureDevOpsReadRequest::new()
        .with_expected_work_item_rev(10)
        .expect("revision");
    assert!(matches!(
        stale.read(&request, at),
        Err(
            hartevo_azure_devops_work_plugin::AzureDevOpsWorkError::WorkItemRevisionMismatch {
                expected: 10,
                observed: 9
            }
        )
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn contract_digest_api_version_and_raw_timeline_fences_are_adversarial() {
    let at = now();
    let mut registration_request =
        hartevo_azure_devops_work_plugin::AzureDevOpsRegistrationRequest::baseline(
            scope(),
            secret(),
            at,
        )
        .expect("registration request");
    registration_request.contract_digest = hartevo_azure_devops_work_plugin::Digest::parse(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
    .expect("bad digest");
    assert!(matches!(
        hartevo_azure_devops_work_plugin::AzureDevOpsRegistration::new(registration_request),
        Err(hartevo_azure_devops_work_plugin::AzureDevOpsWorkError::ContractDigestMismatch)
    ));

    let work_request = request(
        AzureDevOpsEndpoint::WorkItem {
            organization: "contoso".to_owned(),
            project: "Hartevo Project".to_owned(),
            work_item_id: 7,
        },
        at,
    );
    let api_drift = AzureDevOpsHttpResponse::new(
        &work_request,
        200,
        "7.0".to_owned(),
        AzureDevOpsResponseBody::WorkItem(WorkItemPayload {
            id: 7,
            rev: 9,
            title: None,
            state: None,
            work_item_type: None,
            relations: Vec::new(),
        }),
        1,
        hartevo_azure_devops_work_plugin::sha256_digest(b"api-drift"),
        hartevo_azure_devops_work_plugin::ProviderRevision::parse(
            hartevo_azure_devops_work_plugin::AZURE_DEVOPS_WORK_PROVIDER_REVISION,
        )
        .expect("provider revision"),
        None,
        None,
    )
    .expect("api drift response");
    let mut drift = AzureDevOpsServicesProvider::new(
        scope(),
        secret(),
        RecordingAzureDevOpsTransport::fixture([Ok(api_drift)]),
        FixtureResolver,
        at,
    )
    .expect("drift provider");
    assert!(matches!(
        drift.read(&AzureDevOpsReadRequest::new(), at),
        Err(hartevo_azure_devops_work_plugin::AzureDevOpsWorkError::ApiVersionDrift { .. })
    ));

    let mut responses = [
        work_item_response(at),
        pull_request_response(at),
        build_response(at),
    ]
    .into_iter()
    .collect::<Vec<_>>();
    responses.push(response(
        AzureDevOpsEndpoint::Timeline {
            organization: "contoso".to_owned(),
            project: "Hartevo Project".to_owned(),
            build_id: 100,
            page: 1,
            top: hartevo_azure_devops_work_plugin::AZURE_DEVOPS_PAGE_SIZE,
            continuation_token: None,
        },
        AzureDevOpsResponseBody::Timeline(vec![TimelineRecordPayload {
            id: "timeline-with-log".to_owned(),
            record_type: Some("Task".to_owned()),
            name: Some("secret log".to_owned()),
            state: Some("completed".to_owned()),
            result: Some("failed".to_owned()),
            order: Some(1),
            start_time: None,
            finish_time: None,
            error_count: Some(1),
            warning_count: Some(0),
            log_reference_present: true,
        }]),
        at,
    ));
    let mut raw_log = AzureDevOpsServicesProvider::new(
        scope(),
        secret(),
        RecordingAzureDevOpsTransport::fixture(responses),
        FixtureResolver,
        at,
    )
    .expect("raw log provider");
    assert_eq!(
        raw_log
            .read(&AzureDevOpsReadRequest::new(), at)
            .expect_err("raw timeline log must be rejected"),
        hartevo_azure_devops_work_plugin::AzureDevOpsWorkError::ForbiddenPayloadRetention
    );
}

#[test]
fn entra_reference_debug_and_recordings_do_not_expose_credential_material() {
    let reference = secret();
    let debug = format!("{reference:?}");
    assert!(!debug.contains("vault/entra/azure-devops"));
    assert!(!debug.contains("client-1"));
    assert!(!debug.contains("fixture-token"));
    let json = serde_json::to_string(&reference).expect("reference JSON");
    assert!(json.contains("vault/entra/azure-devops"));
    assert!(!json.contains("fixture-token"));

    let transport = RecordingAzureDevOpsTransport::fixture([]);
    assert!(!format!("{transport:?}").contains("fixture-token"));
    assert_eq!(transport.provenance(), TransportProvenance::Fixture);
    assert!(!transport.provenance().is_native());
}
