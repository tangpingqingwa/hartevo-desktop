use hartevo_jenkins_build_result_plugin as jenkins;
use hartevo_plugin_runtime::{MissionId, PluginScope, ProjectId};
use serde_json::json;

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn scope() -> jenkins::JenkinsBuildResultScope {
    jenkins::JenkinsBuildResultScope::new(jenkins::JenkinsBuildResultScopeInput {
        controller_url: "https://ci.example.com/".to_owned(),
        folder_path: vec!["Hartevo Folder".to_owned()],
        job_name: "build-result".to_owned(),
        build_number: 42,
        branch_name: Some("feature/jenkins".to_owned()),
        commit_sha: Some(COMMIT.to_owned()),
        project_id: "project-824".to_owned(),
        project_revision: 3,
        mission_id: "mission-824".to_owned(),
        mission_revision: 4,
        work_product_id: "work-product-824".to_owned(),
        work_product_revision: 5,
    })
    .expect("scope")
}

fn fixture_service() -> jenkins::JenkinsBuildResultService<jenkins::FixtureJenkinsTransport> {
    let scope = scope();
    let transport = jenkins::FixtureJenkinsTransport::for_scope(&scope).expect("fixture");
    let secret = jenkins::SecretReference::for_scope("jenkins-api-token", &scope, 1)
        .expect("opaque secret reference");
    let provider = jenkins::JenkinsProvider::new(scope, secret, transport).expect("provider");
    jenkins::JenkinsBuildResultService::new(provider).expect("service")
}

#[test]
fn contract_metadata_and_runtime_definition_are_frozen() {
    jenkins::validate_contract().expect("contract validates");
    let metadata = jenkins::contract_metadata().expect("metadata");
    assert_eq!(
        metadata.schema_version,
        jenkins::JENKINS_BUILD_RESULT_SCHEMA_VERSION
    );
    assert_eq!(
        metadata.contract_version,
        jenkins::JENKINS_BUILD_RESULT_CONTRACT_VERSION
    );
    assert_eq!(
        metadata.plugin_version,
        jenkins::JENKINS_BUILD_RESULT_PLUGIN_VERSION
    );
    assert_eq!(metadata.plugin_id, jenkins::JENKINS_BUILD_RESULT_PLUGIN_ID);
    assert_eq!(metadata.layer, "Layer-1");

    let runtime_scope = PluginScope::new(
        ProjectId::new("project-824").expect("project"),
        MissionId::new("mission-824").expect("mission"),
        1,
    )
    .expect("runtime scope");
    let definition = jenkins::plugin_definition(runtime_scope.clone()).expect("definition");
    assert_eq!(definition.scope(), &runtime_scope);
    assert_eq!(definition.version(), jenkins::plugin_version());
    assert_eq!(
        definition.contributions().services[0]
            .contract_digest()
            .as_str(),
        jenkins::contract_digest().as_str()
    );
    assert!(!jenkins::Layer1Authority::native());
    assert!(!jenkins::Layer1Authority::connected());
    assert!(!jenkins::Layer1Authority::external_writes());
    assert!(!jenkins::Layer1Authority::kernel_authority());
}

#[test]
#[allow(clippy::too_many_lines)]
fn fixture_reads_are_get_only_normalized_and_deterministic() {
    let mut service = fixture_service();
    let proposal = service.compile_proposal().expect("proposal");
    assert_eq!(
        proposal.status(),
        jenkins::JenkinsBuildResultStatus::Success
    );
    assert!(proposal.evidence.controller.is_some());
    assert!(proposal.evidence.folder.is_some());
    assert!(proposal.evidence.job.is_some());
    assert!(proposal.evidence.branch.is_some());
    assert!(proposal.evidence.build.is_some());
    assert!(proposal.evidence.commit.is_some());
    assert_eq!(
        proposal
            .evidence
            .test_summary
            .as_ref()
            .expect("tests")
            .total,
        11
    );
    assert_eq!(
        proposal
            .evidence
            .artifact_metadata
            .as_ref()
            .expect("artifact metadata")
            .artifact_count,
        1
    );
    assert!(proposal.evidence.receipts.iter().all(|receipt| {
        receipt.method == "GET" && receipt.redacted && !receipt.path_digest.as_str().is_empty()
    }));
    assert!(proposal.validate_integrity().is_ok());
    assert!(service.verify(&proposal).valid);
    assert!(
        !service.verify(&proposal).review_eligible
            || proposal.status() == jenkins::JenkinsBuildResultStatus::Success
    );
    assert!(!proposal.native && !proposal.connected);
    assert!(proposal.proposal_only);
    assert!(!proposal.adopts_outcome && !proposal.adopts_work_product);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for forbidden in [
        "jenkins-api-token",
        "feature/jenkins",
        COMMIT,
        "result.json",
        "relativePath",
        "consoleText",
        "script-output",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "raw value leaked: {forbidden}"
        );
    }
    let debug = format!("{service:?}");
    assert!(!debug.contains("jenkins-api-token"));

    let scope = scope();
    let build_one = jenkins::JenkinsHttpResponse::new(
        200,
        json!({
            "number": 42,
            "result": "SUCCESS",
            "building": false,
            "changeSet": {"items": [{"commitId": COMMIT}, {"commitId": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]},
            "artifacts": [
                {"fileName": "b.bin", "relativePath": "b.bin", "size": 2},
                {"fileName": "a.bin", "relativePath": "a.bin", "size": 1}
            ]
        }),
        jenkins::TransportProvenance::Fixture,
    )
    .expect("build response");
    let build_two = jenkins::JenkinsHttpResponse::new(
        200,
        json!({
            "artifacts": [
                {"size": 1, "relativePath": "a.bin", "fileName": "a.bin"},
                {"size": 2, "relativePath": "b.bin", "fileName": "b.bin"}
            ],
            "changeSet": {"items": [{"commitId": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, {"commitId": COMMIT}]},
            "building": false,
            "result": "SUCCESS",
            "number": 42
        }),
        jenkins::TransportProvenance::Fixture,
    )
    .expect("reordered build response");
    let provider_one = jenkins::JenkinsProvider::new(
        scope.clone(),
        jenkins::SecretReference::for_scope("secret-one", &scope, 1).expect("secret"),
        jenkins::FixtureJenkinsTransport::new(build_one),
    )
    .expect("provider one");
    let provider_two = jenkins::JenkinsProvider::new(
        scope.clone(),
        jenkins::SecretReference::for_scope("secret-one", &scope, 1).expect("secret"),
        jenkins::FixtureJenkinsTransport::new(build_two),
    )
    .expect("provider two");
    let mut service_one =
        jenkins::JenkinsBuildResultService::new(provider_one).expect("service one");
    let mut service_two =
        jenkins::JenkinsBuildResultService::new(provider_two).expect("service two");
    let request = jenkins::JenkinsBuildResultRequest::new(
        &scope,
        vec![jenkins::JenkinsReadOperation::ReadBuild],
        None,
    )
    .expect("request");
    let proposal_one = service_one
        .compile_proposal_for(&request)
        .expect("proposal one");
    let proposal_two = service_two
        .compile_proposal_for(&request)
        .expect("proposal two");
    assert_eq!(
        proposal_one.evidence.source_digest,
        proposal_two.evidence.source_digest
    );
    assert_eq!(
        proposal_one.evidence.evidence_digest,
        proposal_two.evidence.evidence_digest
    );
}

#[test]
fn paths_are_allowlisted_get_only_and_cursor_is_opaque() {
    let scope = scope();
    for operation in jenkins::JenkinsReadOperation::ALL {
        let request =
            jenkins::JenkinsReadRequest::for_operation(&scope, operation).expect("request");
        let http = request.http_request().expect("HTTP request");
        assert_eq!(http.method, jenkins::JenkinsHttpMethod::Get);
        assert!(http.redacted);
        assert!(http.path_and_query.contains("/api/json"));
        assert!(!http.path_and_query.contains("consoleText"));
        assert!(
            !http.path_and_query.contains("artifact/")
                || operation == jenkins::JenkinsReadOperation::ReadArtifactMetadata
        );
        assert!(!http.path_and_query.contains("buildWithParameters"));
        assert!(!http.path_and_query.contains("config.xml"));
    }
    let cursor = jenkins::JenkinsCursor::new("opaque-queue-token", &scope, 2).expect("cursor");
    let request = jenkins::JenkinsReadRequest::new(
        &scope,
        jenkins::JenkinsEndpoint::Build,
        Some(cursor.clone()),
    )
    .expect("cursor request");
    let serialized = serde_json::to_string(&cursor).expect("cursor JSON");
    assert!(!serialized.contains("opaque-queue-token"));
    assert!(serialized.contains(cursor.cursor_digest().as_str()));
    assert_eq!(
        request.cursor().expect("request cursor").scope_digest(),
        scope.digest()
    );
}

#[test]
fn provider_request_budget_is_bounded() {
    let scope = scope();
    let response = jenkins::JenkinsHttpResponse::new(
        200,
        json!({"number": 42, "result": "SUCCESS", "building": false}),
        jenkins::TransportProvenance::Fixture,
    )
    .expect("response");
    let secret = jenkins::SecretReference::for_scope("budget-secret", &scope, 1).expect("secret");
    let mut provider = jenkins::JenkinsProvider::new(
        scope,
        secret,
        jenkins::FixtureJenkinsTransport::new(response),
    )
    .expect("provider");
    for _ in 0..jenkins::MAX_REQUESTS_PER_MINUTE {
        provider.read_build().expect("bounded request");
    }
    assert!(matches!(
        provider.read_build(),
        Err(jenkins::JenkinsProviderError::RateLimited { .. })
    ));
}

#[test]
fn status_matrix_and_blocked_environment_are_honest() {
    assert_eq!(
        jenkins::JenkinsBuildResultStatus::from_wire(None, false, true),
        jenkins::JenkinsBuildResultStatus::Queued
    );
    assert_eq!(
        jenkins::JenkinsBuildResultStatus::from_wire(None, true, false),
        jenkins::JenkinsBuildResultStatus::Running
    );
    assert_eq!(
        jenkins::JenkinsBuildResultStatus::from_wire(Some("SUCCESS"), false, false),
        jenkins::JenkinsBuildResultStatus::Success
    );
    assert_eq!(
        jenkins::JenkinsBuildResultStatus::from_wire(Some("UNSTABLE"), false, false),
        jenkins::JenkinsBuildResultStatus::Unstable
    );
    assert_eq!(
        jenkins::JenkinsBuildResultStatus::from_wire(Some("FAILURE"), false, false),
        jenkins::JenkinsBuildResultStatus::Failure
    );
    assert_eq!(
        jenkins::JenkinsBuildResultStatus::from_wire(Some("ABORTED"), false, false),
        jenkins::JenkinsBuildResultStatus::Aborted
    );
    assert_eq!(
        jenkins::JenkinsBuildResultStatus::from_wire(Some("NOT_BUILT"), false, false),
        jenkins::JenkinsBuildResultStatus::NotBuilt
    );
    assert_eq!(
        jenkins::JenkinsBuildResultStatus::from_wire(None, false, false),
        jenkins::JenkinsBuildResultStatus::ProviderUnknown
    );

    let scope = scope();
    let secret = jenkins::SecretReference::for_scope("blocked-secret", &scope, 1).expect("secret");
    let provider =
        jenkins::JenkinsProvider::new(scope, secret, jenkins::BlockedEnvJenkinsTransport)
            .expect("provider");
    let mut service = jenkins::JenkinsBuildResultService::new(provider).expect("service");
    let proposal = service.compile_proposal().expect("blocked proposal");
    assert_eq!(
        proposal.status(),
        jenkins::JenkinsBuildResultStatus::ProviderUnknown
    );
    assert_eq!(
        proposal.evidence.provenance,
        jenkins::TransportProvenance::BlockedEnv
    );
    assert!(!proposal.native && !proposal.connected);
    assert!(proposal.evidence.receipts.is_empty());
    assert!(
        proposal
            .evidence
            .failures
            .iter()
            .all(|failure| { failure.code == jenkins::JenkinsFailureCode::BlockedEnv })
    );
}

#[test]
fn registration_is_reversible_and_digest_fenced() {
    let mut service = fixture_service();
    let original = service.registration().registration_digest().clone();
    let proposal = service.compile_proposal().expect("proposal");
    let transition = service.revoke_registration().expect("revoke");
    assert_eq!(transition.previous_registration_digest, original);
    assert_ne!(transition.registration_digest, original);
    assert!(matches!(
        service.compile_proposal(),
        Err(jenkins::JenkinsBuildResultServiceError::RegistrationRevoked)
    ));
    service.restore_registration().expect("restore");
    assert_ne!(service.registration().registration_digest(), &original);
    assert!(!service.verify(&proposal).valid);
    let restored = service.compile_proposal().expect("restored proposal");
    assert_ne!(restored.registration_digest, original);
    let registration_json =
        serde_json::to_string(service.registration()).expect("registration JSON");
    assert!(registration_json.contains("secretReferenceDigest"));
    assert!(!registration_json.contains("jenkins-api-token"));
}

#[test]
fn mission_consumer_rejects_replay_and_keeps_authority_false() {
    let scope = scope();
    let transport = jenkins::FixtureJenkinsTransport::for_scope(&scope).expect("fixture");
    let secret = jenkins::SecretReference::for_scope("consumer-secret", &scope, 1).expect("secret");
    let provider = jenkins::JenkinsProvider::new(scope, secret, transport).expect("provider");
    let mut consumer = jenkins::MissionJenkinsBuildConsumer::new(provider).expect("consumer");
    let proposal = consumer.compile_proposal().expect("proposal");
    let result = consumer.consume(&proposal).expect("consume");
    assert_eq!(result.status, jenkins::JenkinsBuildResultStatus::Success);
    assert!(result.proposal_only);
    assert!(!result.native && !result.connected);
    assert!(!result.adopts_outcome && !result.adopts_work_product);
    assert!(matches!(
        consumer.consume(&proposal),
        Err(jenkins::MissionJenkinsBuildConsumerError::ReplayDetected)
    ));
}

#[test]
fn tampered_response_fails_closed_without_raw_payload() {
    let scope = scope();
    let mut response = jenkins::JenkinsHttpResponse::new(
        200,
        json!({"number":42,"result":"SUCCESS","building":false}),
        jenkins::TransportProvenance::Recording,
    )
    .expect("response");
    response.response_digest = jenkins::Digest::from_text("tampered-receipt");
    let mut transport = jenkins::RecordingJenkinsTransport::new();
    transport.push_response(jenkins::JenkinsReadOperation::ReadBuild, Ok(response));
    let secret = jenkins::SecretReference::for_scope("tamper-secret", &scope, 1).expect("secret");
    let provider =
        jenkins::JenkinsProvider::new(scope.clone(), secret, transport).expect("provider");
    let mut service = jenkins::JenkinsBuildResultService::new(provider).expect("service");
    let request = jenkins::JenkinsBuildResultRequest::new(
        &scope,
        vec![jenkins::JenkinsReadOperation::ReadBuild],
        None,
    )
    .expect("request");
    let proposal = service
        .compile_proposal_for(&request)
        .expect("tampered proposal");
    assert_eq!(
        proposal.status(),
        jenkins::JenkinsBuildResultStatus::Tampered
    );
    assert!(proposal.evidence.build.is_none());
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal JSON")
            .contains("tampered-receipt")
    );
}
