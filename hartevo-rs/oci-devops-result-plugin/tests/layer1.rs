use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_oci_devops_result_plugin::{
    BlockedEnvOciDevopsTransport, BlockedEnvSigningKeyResolver, Digest, FakeOciDevopsTransport,
    MissionOciDevopsConsumer, OciAccessCredential, OciBuildRunPayload, OciDeploymentPayload,
    OciDevopsEndpoint, OciDevopsError, OciDevopsHttpRequest, OciDevopsHttpResponse,
    OciDevopsProvider, OciDevopsReadRequest, OciDevopsResultContract, OciDevopsResultService,
    OciDevopsScope, OciDevopsScopeInput, OciDevopsTransport, OciResponseBody, OciStagePayload,
    OciTransportError, OciWorkRequestPayload, SecretReference, TransportProvenance,
    contract_digest, evidence_policy_digest, native_probe_from_environment, plugin_definition,
};
use hartevo_plugin_runtime::{
    MissionId as RuntimeMissionId, PluginRuntime, PluginScope, ProjectId as RuntimeProjectId,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const TENANCY: &str = "ocid1.tenancy.oc1..tenancy";
const COMPARTMENT: &str = "ocid1.compartment.oc1..compartment";
const PROJECT: &str = "ocid1.devopsproject.oc1..project";
const PIPELINE: &str = "ocid1.pipeline.oc1..pipeline";
const BUILD: &str = "ocid1.buildrun.oc1..build";
const DEPLOYMENT: &str = "ocid1.deployment.oc1..deployment";
const WORK_REQUEST: &str = "ocid1.workrequest.oc1..work";
const STAGE: &str = "ocid1.deploystage.oc1..stage";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid test timestamp")
}

fn scope() -> OciDevopsScope {
    OciDevopsScope::new(OciDevopsScopeInput {
        region: "us-phoenix-1".to_owned(),
        tenancy_id: TENANCY.to_owned(),
        compartment_id: COMPARTMENT.to_owned(),
        oci_project_id: PROJECT.to_owned(),
        pipeline_id: PIPELINE.to_owned(),
        build_id: BUILD.to_owned(),
        deployment_id: DEPLOYMENT.to_owned(),
        work_request_id: WORK_REQUEST.to_owned(),
        permission_digest: Digest::from_bytes(b"devops-read-only-permission"),
        mission_id: "mission-oci-1".to_owned(),
        mission_revision: 3,
        hartevo_project_id: "project-oci-1".to_owned(),
        project_revision: 4,
        work_product_id: "work-product-oci-1".to_owned(),
        work_product_revision: 5,
    })
    .expect("scope")
}

fn secret() -> SecretReference {
    SecretReference::new("vault/oci/signing-key", &scope(), 1).expect("secret reference")
}

#[derive(Clone, Debug)]
struct FixtureResolver;

impl hartevo_oci_devops_result_plugin::OciSigningKeyResolver for FixtureResolver {
    fn resolve(
        &mut self,
        _reference: &SecretReference,
        at: DateTime<Utc>,
    ) -> Result<OciAccessCredential, hartevo_oci_devops_result_plugin::OciCredentialError> {
        OciAccessCredential::new(
            "fixture-signing-key",
            at - Duration::seconds(1),
            at + Duration::seconds(120),
        )
    }
}

fn request(endpoint: OciDevopsEndpoint, at: DateTime<Utc>) -> OciDevopsHttpRequest {
    OciDevopsHttpRequest::new(
        endpoint,
        at,
        hartevo_oci_devops_result_plugin::OCI_DEVOPS_MAX_RESPONSE_BYTES,
    )
    .expect("request")
}

fn response(
    endpoint: OciDevopsEndpoint,
    body: OciResponseBody,
    at: DateTime<Utc>,
) -> Result<OciDevopsHttpResponse, OciTransportError> {
    OciDevopsHttpResponse::from_body(&request(endpoint, at), body)
}

fn response_with_page(
    endpoint: OciDevopsEndpoint,
    body: OciResponseBody,
    next_page: Option<&str>,
    at: DateTime<Utc>,
) -> Result<OciDevopsHttpResponse, OciTransportError> {
    OciDevopsHttpResponse::from_body_with_next_page(
        &request(endpoint, at),
        body,
        next_page.map(str::to_owned),
    )
}

fn stage(revision: u64, state: &str) -> OciStagePayload {
    OciStagePayload {
        id: STAGE.to_owned(),
        state: state.to_owned(),
        revision,
    }
}

fn deployment(revision: u64, compartment_id: &str) -> OciDeploymentPayload {
    OciDeploymentPayload {
        id: DEPLOYMENT.to_owned(),
        compartment_id: compartment_id.to_owned(),
        project_id: PROJECT.to_owned(),
        pipeline_id: PIPELINE.to_owned(),
        build_run_id: Some(BUILD.to_owned()),
        lifecycle_state: "SUCCEEDED".to_owned(),
        revision,
        time_created: Some(now() - Duration::minutes(5)),
        time_started: Some(now() - Duration::minutes(4)),
        time_finished: Some(now() - Duration::minutes(1)),
        stages: vec![stage(2, "SUCCEEDED")],
        artifact_count: 2,
        artifact_metadata_fingerprint: Some(Digest::from_bytes(b"artifact-metadata")),
        log_metadata_fingerprint: Some(Digest::from_bytes(b"log-metadata")),
    }
}

fn build(revision: u64) -> OciBuildRunPayload {
    OciBuildRunPayload {
        id: BUILD.to_owned(),
        compartment_id: COMPARTMENT.to_owned(),
        project_id: PROJECT.to_owned(),
        pipeline_id: PIPELINE.to_owned(),
        lifecycle_state: "SUCCEEDED".to_owned(),
        revision,
        time_created: Some(now() - Duration::minutes(8)),
        time_started: Some(now() - Duration::minutes(7)),
        time_finished: Some(now() - Duration::minutes(6)),
        stages: vec![stage(2, "SUCCEEDED")],
        artifact_count: 1,
        artifact_metadata_fingerprint: Some(Digest::from_bytes(b"build-artifact-metadata")),
        log_metadata_fingerprint: Some(Digest::from_bytes(b"build-log-metadata")),
    }
}

fn work_request(revision: u64) -> OciWorkRequestPayload {
    OciWorkRequestPayload {
        id: WORK_REQUEST.to_owned(),
        compartment_id: COMPARTMENT.to_owned(),
        project_id: PROJECT.to_owned(),
        resource_id: Some(DEPLOYMENT.to_owned()),
        operation_type: Some("GetDeployment".to_owned()),
        status: "SUCCEEDED".to_owned(),
        percent_complete: Some(100),
        revision,
        time_accepted: Some(now() - Duration::minutes(3)),
        time_started: Some(now() - Duration::minutes(3)),
        time_finished: Some(now() - Duration::minutes(2)),
    }
}

fn fixture_provider(
    at: DateTime<Utc>,
) -> OciDevopsProvider<FakeOciDevopsTransport, FixtureResolver> {
    let responses = [
        response(
            OciDevopsEndpoint::ListDeployments {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                pipeline_id: PIPELINE.to_owned(),
                limit: 50,
                page_token: None,
            },
            OciResponseBody::Deployments(vec![deployment(9, COMPARTMENT)]),
            at,
        ),
        response(
            OciDevopsEndpoint::GetDeployment {
                deployment_id: DEPLOYMENT.to_owned(),
            },
            OciResponseBody::Deployment(deployment(9, COMPARTMENT)),
            at,
        ),
        response(
            OciDevopsEndpoint::ListBuildRuns {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                pipeline_id: PIPELINE.to_owned(),
                limit: 50,
                page_token: None,
            },
            OciResponseBody::BuildRuns(vec![build(7)]),
            at,
        ),
        response(
            OciDevopsEndpoint::GetBuildRun {
                build_run_id: BUILD.to_owned(),
            },
            OciResponseBody::BuildRun(build(7)),
            at,
        ),
        response(
            OciDevopsEndpoint::ListWorkRequests {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                limit: 50,
                page_token: None,
            },
            OciResponseBody::WorkRequests(vec![work_request(4)]),
            at,
        ),
        response(
            OciDevopsEndpoint::GetWorkRequest {
                work_request_id: WORK_REQUEST.to_owned(),
            },
            OciResponseBody::WorkRequest(work_request(4)),
            at,
        ),
    ];
    OciDevopsProvider::new(
        scope(),
        secret(),
        FakeOciDevopsTransport::fixture(responses),
        FixtureResolver,
        at,
    )
    .expect("provider")
}

#[test]
fn contract_definition_and_native_gap_are_exact() {
    let contract = OciDevopsResultContract::baseline().expect("contract");
    assert_eq!(contract.digest(), contract_digest());
    assert_eq!(contract.api_version, "20210630");
    assert!(contract.read_only);
    assert!(contract.mutating_provider_operations.is_empty());
    assert!(!contract.authority.run);
    assert!(!contract.authority.cancel);
    assert!(!contract.authority.approve);
    assert!(!contract.authority.redeploy);
    assert!(!contract.authority.raw_logs);
    assert!(!contract.authority.raw_artifacts);
    let service = OciDevopsResultService::new();
    service.validate().expect("service descriptor");
    assert_eq!(
        service.capabilities().len(),
        hartevo_oci_devops_result_plugin::OciDevopsOperation::ALL.len()
    );

    let runtime_scope = PluginScope::new(
        RuntimeProjectId::new("project-oci-1").expect("runtime project"),
        RuntimeMissionId::new("mission-oci-1").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    let definition = plugin_definition(runtime_scope.clone()).expect("definition");
    assert_eq!(definition.scope(), &runtime_scope);
    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition).expect("define");
    let receipt = runtime.mount(&handle).expect("mount");
    assert_eq!(receipt.generation(), 1);
    runtime.revoke(&handle).expect("revoke");
    assert!(!native_probe_from_environment().native_connected_claim);
}

#[test]
fn bounded_delivery_result_is_redacted_and_locally_verifiable() {
    let at = now();
    let mut provider = fixture_provider(at);
    let consumer = MissionOciDevopsConsumer::new(scope());
    let request = OciDevopsReadRequest::new()
        .with_expected_deployment_revision(9)
        .expect("deployment revision")
        .with_expected_build_revision(7)
        .expect("build revision")
        .with_expected_work_request_revision(4)
        .expect("work request revision")
        .with_stage_fence(STAGE, "SUCCEEDED", 2)
        .expect("stage fence");
    let result = consumer.read(&mut provider, &request, at).expect("read");
    result.validate(&scope()).expect("result validation");
    assert_eq!(result.evidence.deployment.revision, 9);
    assert_eq!(result.evidence.build_run.revision, 7);
    assert_eq!(result.evidence.work_request.revision, 4);
    assert!(result.readback.verified);
    assert!(!result.evidence.native_evidence);
    assert!(!result.evidence.external_write_performed);
    assert!(!result.evidence.outcome_authority);
    assert_eq!(
        provider.registration().evidence_digest(),
        &evidence_policy_digest()
    );
    assert!(!result.record.external_effect_performed);
    assert!(result.evidence.receipts.iter().all(|receipt| {
        receipt.api_version == "20210630"
            && !receipt.raw_provider_payload_retained
            && !receipt.raw_logs_retained
            && !receipt.raw_artifacts_retained
            && !receipt.credential_material_retained
    }));
    let serialized = serde_json::to_string(&result).expect("result JSON");
    assert!(!serialized.contains("fixture-signing-key"));
    assert!(!serialized.contains("downloadUrl"));
    assert!(!serialized.contains("raw log contents"));
    assert_eq!(provider.transport().requests().len(), 6);
    assert!(
        provider
            .transport()
            .requests()
            .iter()
            .all(|request| !request.endpoint.contains("fixture-signing-key"))
    );
}

#[test]
fn fixture_recording_loopback_and_blocked_env_are_non_native() {
    let at = now();
    let provider = fixture_provider(at);
    assert_eq!(
        provider.transport().provenance(),
        TransportProvenance::Fixture
    );
    assert!(!provider.transport().provenance().is_native());
    assert!(!provider.transport().provenance().is_connected());
    assert!(!provider.is_connected());
    let loopback = FakeOciDevopsTransport::loopback([]);
    assert_eq!(loopback.provenance(), TransportProvenance::Loopback);
    assert!(!loopback.provenance().is_native());
    let blocked = BlockedEnvOciDevopsTransport;
    assert_eq!(blocked.provenance(), TransportProvenance::BlockedEnv);
    assert_eq!(
        format!("{BlockedEnvSigningKeyResolver:?}"),
        "BlockedEnvSigningKeyResolver"
    );
}

#[test]
fn revocation_scope_revision_and_stage_fences_fail_closed() {
    let at = now();
    let mut revoked = fixture_provider(at);
    revoked.revoke(at + Duration::seconds(1)).expect("revoke");
    assert_eq!(
        revoked
            .read(&OciDevopsReadRequest::new(), at + Duration::seconds(2))
            .expect_err("revoked registration"),
        OciDevopsError::RegistrationRevoked
    );

    let mut stale = fixture_provider(at);
    let stale_request = OciDevopsReadRequest::new()
        .with_expected_deployment_revision(10)
        .expect("revision");
    assert!(matches!(
        stale.read(&stale_request, at),
        Err(OciDevopsError::RevisionMismatch { .. })
    ));

    let mut stage_provider = fixture_provider(at);
    let stage_fence_request = OciDevopsReadRequest::new()
        .with_stage_fence(STAGE, "IN_PROGRESS", 2)
        .expect("stage fence");
    assert_eq!(
        stage_provider
            .read(&stage_fence_request, at)
            .expect_err("stage drift"),
        OciDevopsError::StageStateMismatch
    );

    let mut wrong_input = OciDevopsScopeInput {
        region: "us-phoenix-1".to_owned(),
        tenancy_id: TENANCY.to_owned(),
        compartment_id: COMPARTMENT.to_owned(),
        oci_project_id: PROJECT.to_owned(),
        pipeline_id: PIPELINE.to_owned(),
        build_id: BUILD.to_owned(),
        deployment_id: DEPLOYMENT.to_owned(),
        work_request_id: WORK_REQUEST.to_owned(),
        permission_digest: Digest::from_bytes(b"devops-read-only-permission"),
        mission_id: "mission-oci-1".to_owned(),
        mission_revision: 3,
        hartevo_project_id: "project-oci-1".to_owned(),
        project_revision: 4,
        work_product_id: "work-product-oci-1".to_owned(),
        work_product_revision: 5,
    };
    wrong_input.compartment_id = "ocid1.compartment.oc1..other".to_owned();
    let wrong_scope = OciDevopsScope::new(wrong_input).expect("wrong scope");
    let mut scoped = fixture_provider(at);
    assert!(matches!(
        MissionOciDevopsConsumer::new(wrong_scope).read(
            &mut scoped,
            &OciDevopsReadRequest::new(),
            at,
        ),
        Err(OciDevopsError::ScopeMismatch(_))
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn pagination_status_and_tamper_are_rejected_or_bounded() {
    let at = now();
    let list_deployments = response_with_page(
        OciDevopsEndpoint::ListDeployments {
            compartment_id: COMPARTMENT.to_owned(),
            project_id: PROJECT.to_owned(),
            pipeline_id: PIPELINE.to_owned(),
            limit: 1,
            page_token: None,
        },
        OciResponseBody::Deployments(Vec::new()),
        Some("page-2"),
        at,
    );
    let list_deployments_page_2 = response(
        OciDevopsEndpoint::ListDeployments {
            compartment_id: COMPARTMENT.to_owned(),
            project_id: PROJECT.to_owned(),
            pipeline_id: PIPELINE.to_owned(),
            limit: 1,
            page_token: Some("page-2".to_owned()),
        },
        OciResponseBody::Deployments(vec![deployment(9, COMPARTMENT)]),
        at,
    );
    let responses = [
        list_deployments,
        list_deployments_page_2,
        response(
            OciDevopsEndpoint::GetDeployment {
                deployment_id: DEPLOYMENT.to_owned(),
            },
            OciResponseBody::Deployment(deployment(9, COMPARTMENT)),
            at,
        ),
        response(
            OciDevopsEndpoint::ListBuildRuns {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                pipeline_id: PIPELINE.to_owned(),
                limit: 1,
                page_token: None,
            },
            OciResponseBody::BuildRuns(vec![build(7)]),
            at,
        ),
        response(
            OciDevopsEndpoint::GetBuildRun {
                build_run_id: BUILD.to_owned(),
            },
            OciResponseBody::BuildRun(build(7)),
            at,
        ),
        response(
            OciDevopsEndpoint::ListWorkRequests {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                limit: 1,
                page_token: None,
            },
            OciResponseBody::WorkRequests(vec![work_request(4)]),
            at,
        ),
        response(
            OciDevopsEndpoint::GetWorkRequest {
                work_request_id: WORK_REQUEST.to_owned(),
            },
            OciResponseBody::WorkRequest(work_request(4)),
            at,
        ),
    ];
    let mut provider = OciDevopsProvider::new(
        scope(),
        secret(),
        FakeOciDevopsTransport::fixture(responses),
        FixtureResolver,
        at,
    )
    .expect("provider");
    let request = OciDevopsReadRequest::new()
        .with_max_results(1)
        .expect("limit")
        .with_max_pages(2)
        .expect("pages");
    let evidence = provider.read(&request, at).expect("paginated read");
    assert!(evidence.next_page_tokens.contains_key("deployments"));

    let mut status_provider = OciDevopsProvider::new(
        scope(),
        secret(),
        FakeOciDevopsTransport::fixture([Err(OciTransportError::Status(429))]),
        FixtureResolver,
        at,
    )
    .expect("status provider");
    assert_eq!(
        status_provider
            .read(&OciDevopsReadRequest::new(), at)
            .expect_err("429"),
        OciDevopsError::UnexpectedStatus { status: 429 }
    );

    let consumer = MissionOciDevopsConsumer::new(scope());
    let mut tampered_provider = fixture_provider(at);
    let mut evidence = tampered_provider
        .read(&OciDevopsReadRequest::new(), at)
        .expect("evidence");
    evidence.deployment.revision = 99;
    assert_eq!(
        consumer.consume_evidence(evidence).expect_err("tamper"),
        OciDevopsError::EvidenceDigestMismatch
    );
}

#[test]
fn opaque_secret_and_credential_debug_do_not_disclose_material() {
    let reference = secret();
    let debug = format!("{reference:?}");
    assert!(!debug.contains("vault/oci/signing-key"));
    assert!(!debug.contains("fixture-signing-key"));
    let credential = OciAccessCredential::new(
        "fixture-signing-key",
        now() - Duration::seconds(1),
        now() + Duration::seconds(60),
    )
    .expect("credential");
    assert!(!format!("{credential:?}").contains("fixture-signing-key"));
}

#[test]
fn required_http_failures_are_fail_closed() {
    let at = now();
    for status in [401, 403, 404, 409, 429, 500, 503] {
        let mut provider = OciDevopsProvider::new(
            scope(),
            secret(),
            FakeOciDevopsTransport::fixture([Err(OciTransportError::Status(status))]),
            FixtureResolver,
            at,
        )
        .expect("status provider");
        assert_eq!(
            provider
                .read(&OciDevopsReadRequest::new(), at)
                .expect_err("status must fail closed"),
            OciDevopsError::UnexpectedStatus { status }
        );
    }

    let mut timeout_provider = OciDevopsProvider::new(
        scope(),
        secret(),
        FakeOciDevopsTransport::fixture([Err(OciTransportError::Timeout)]),
        FixtureResolver,
        at,
    )
    .expect("timeout provider");
    assert_eq!(
        timeout_provider
            .read(&OciDevopsReadRequest::new(), at)
            .expect_err("timeout must fail closed"),
        OciDevopsError::Transport("timeout".to_owned())
    );
}

#[test]
fn compartment_drift_and_ambiguous_work_requests_are_rejected() {
    let at = now();
    let drift_responses = [
        response(
            OciDevopsEndpoint::ListDeployments {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                pipeline_id: PIPELINE.to_owned(),
                limit: 50,
                page_token: None,
            },
            OciResponseBody::Deployments(vec![deployment(9, COMPARTMENT)]),
            at,
        ),
        response(
            OciDevopsEndpoint::GetDeployment {
                deployment_id: DEPLOYMENT.to_owned(),
            },
            OciResponseBody::Deployment(deployment(9, "ocid1.compartment.oc1..drift")),
            at,
        ),
    ];
    let mut drift_provider = OciDevopsProvider::new(
        scope(),
        secret(),
        FakeOciDevopsTransport::fixture(drift_responses),
        FixtureResolver,
        at,
    )
    .expect("drift provider");
    assert_eq!(
        drift_provider
            .read(&OciDevopsReadRequest::new(), at)
            .expect_err("compartment drift"),
        OciDevopsError::CompartmentProjectMismatch
    );

    let ambiguous_responses = [
        response(
            OciDevopsEndpoint::ListDeployments {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                pipeline_id: PIPELINE.to_owned(),
                limit: 50,
                page_token: None,
            },
            OciResponseBody::Deployments(vec![deployment(9, COMPARTMENT)]),
            at,
        ),
        response(
            OciDevopsEndpoint::GetDeployment {
                deployment_id: DEPLOYMENT.to_owned(),
            },
            OciResponseBody::Deployment(deployment(9, COMPARTMENT)),
            at,
        ),
        response(
            OciDevopsEndpoint::ListBuildRuns {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                pipeline_id: PIPELINE.to_owned(),
                limit: 50,
                page_token: None,
            },
            OciResponseBody::BuildRuns(vec![build(7)]),
            at,
        ),
        response(
            OciDevopsEndpoint::GetBuildRun {
                build_run_id: BUILD.to_owned(),
            },
            OciResponseBody::BuildRun(build(7)),
            at,
        ),
        response(
            OciDevopsEndpoint::ListWorkRequests {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                limit: 50,
                page_token: None,
            },
            OciResponseBody::WorkRequests(vec![work_request(4), work_request(4)]),
            at,
        ),
    ];
    let mut ambiguous_provider = OciDevopsProvider::new(
        scope(),
        secret(),
        FakeOciDevopsTransport::fixture(ambiguous_responses),
        FixtureResolver,
        at,
    )
    .expect("ambiguous provider");
    assert_eq!(
        ambiguous_provider
            .read(&OciDevopsReadRequest::new(), at)
            .expect_err("ambiguous work request"),
        OciDevopsError::WorkRequestAmbiguous
    );
}

#[test]
fn repeated_page_tokens_and_mission_revision_drift_are_rejected() {
    let at = now();
    let repeated_responses = [
        response_with_page(
            OciDevopsEndpoint::ListDeployments {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                pipeline_id: PIPELINE.to_owned(),
                limit: 1,
                page_token: None,
            },
            OciResponseBody::Deployments(Vec::new()),
            Some("same-page"),
            at,
        ),
        response_with_page(
            OciDevopsEndpoint::ListDeployments {
                compartment_id: COMPARTMENT.to_owned(),
                project_id: PROJECT.to_owned(),
                pipeline_id: PIPELINE.to_owned(),
                limit: 1,
                page_token: Some("same-page".to_owned()),
            },
            OciResponseBody::Deployments(Vec::new()),
            Some("same-page"),
            at,
        ),
    ];
    let mut repeated_provider = OciDevopsProvider::new(
        scope(),
        secret(),
        FakeOciDevopsTransport::fixture(repeated_responses),
        FixtureResolver,
        at,
    )
    .expect("repeated page provider");
    let request = OciDevopsReadRequest::new()
        .with_max_results(1)
        .expect("limit")
        .with_max_pages(2)
        .expect("pages");
    assert!(matches!(
        repeated_provider.read(&request, at),
        Err(OciDevopsError::Pagination(message)) if message.contains("repeated deployment page token")
    ));

    let mission_revision_input = OciDevopsScopeInput {
        region: "us-phoenix-1".to_owned(),
        tenancy_id: TENANCY.to_owned(),
        compartment_id: COMPARTMENT.to_owned(),
        oci_project_id: PROJECT.to_owned(),
        pipeline_id: PIPELINE.to_owned(),
        build_id: BUILD.to_owned(),
        deployment_id: DEPLOYMENT.to_owned(),
        work_request_id: WORK_REQUEST.to_owned(),
        permission_digest: Digest::from_bytes(b"devops-read-only-permission"),
        mission_id: "mission-oci-1".to_owned(),
        mission_revision: 4,
        hartevo_project_id: "project-oci-1".to_owned(),
        project_revision: 4,
        work_product_id: "work-product-oci-1".to_owned(),
        work_product_revision: 5,
    };
    let stale_mission_scope = OciDevopsScope::new(mission_revision_input).expect("scope");
    let mut provider = fixture_provider(at);
    assert!(matches!(
        MissionOciDevopsConsumer::new(stale_mission_scope).read(
            &mut provider,
            &OciDevopsReadRequest::new(),
            at,
        ),
        Err(OciDevopsError::ScopeMismatch(_))
    ));
}

#[test]
fn evidence_replay_is_rejected_after_first_consume() {
    let at = now();
    let mut provider = fixture_provider(at);
    let evidence = provider
        .read(&OciDevopsReadRequest::new(), at)
        .expect("evidence");
    let replay = evidence.clone();
    let consumer = MissionOciDevopsConsumer::new(scope());
    consumer.consume_evidence(evidence).expect("first consume");
    assert_eq!(
        consumer
            .consume_evidence(replay)
            .expect_err("replay must fail"),
        OciDevopsError::StaleEvidence
    );
}
