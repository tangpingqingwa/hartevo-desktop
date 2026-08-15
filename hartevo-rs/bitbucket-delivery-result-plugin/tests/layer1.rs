use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_plugin_runtime::{
    MissionId as RuntimeMissionId, PluginScope, ProjectId as RuntimeProjectId,
};
use serde_json::json;

use hartevo_bitbucket_delivery_result_plugin as bitbucket;

const NOW_SECONDS: i64 = 1_787_000_000;
const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DESTINATION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid test timestamp")
}

fn scope() -> bitbucket::BitbucketDeliveryScope {
    bitbucket::BitbucketDeliveryScope::new(bitbucket::BitbucketDeliveryScopeInput {
        workspace: "acme".to_owned(),
        repository: "delivery".to_owned(),
        repository_uuid: Some("{repo-1}".to_owned()),
        pull_request_id: 42,
        commit: COMMIT.to_owned(),
        build_number: 7,
        pipeline_uuid: "{pipe-1}".to_owned(),
        deployment_uuid: Some("{deployment-1}".to_owned()),
        project_id: "project-1".to_owned(),
        project_revision: 4,
        mission_id: "mission-1".to_owned(),
        mission_revision: 5,
        work_product_id: "work-product-1".to_owned(),
        work_product_revision: 6,
    })
    .expect("scope")
}

fn secret() -> bitbucket::SecretReference {
    bitbucket::SecretReference::oauth("host/keyring/bitbucket", 9).expect("secret reference")
}

#[derive(Clone, Debug)]
struct FixtureResolver;

impl bitbucket::BitbucketCredentialResolver for FixtureResolver {
    fn resolve(
        &mut self,
        _reference: &bitbucket::SecretReference,
        at: DateTime<Utc>,
    ) -> Result<bitbucket::BitbucketAccessToken, bitbucket::CredentialError> {
        bitbucket::BitbucketAccessToken::new(
            "fixture-access-token",
            at - Duration::seconds(1),
            at + Duration::seconds(300),
        )
        .map_err(|error| bitbucket::CredentialError::Failed(error.to_string()))
    }
}

fn request(endpoint: bitbucket::BitbucketEndpoint) -> bitbucket::BitbucketHttpRequest {
    bitbucket::BitbucketHttpRequest::new(endpoint, now(), bitbucket::MAX_RESPONSE_BYTES)
        .expect("request")
}

fn response(
    endpoint: bitbucket::BitbucketEndpoint,
    status: u16,
    body: bitbucket::BitbucketResponseBody,
    retry_after_seconds: Option<u32>,
    next_page_token: Option<&str>,
) -> Result<bitbucket::BitbucketHttpResponse, bitbucket::BitbucketTransportError> {
    let request = request(endpoint);
    bitbucket::BitbucketHttpResponse::from_body(
        &request,
        status,
        body,
        256,
        bitbucket::BITBUCKET_PROVIDER_REVISION,
        retry_after_seconds,
        next_page_token.map(str::to_owned),
    )
}

fn repository_response()
-> Result<bitbucket::BitbucketHttpResponse, bitbucket::BitbucketTransportError> {
    response(
        bitbucket::BitbucketEndpoint::Repository {
            workspace: "acme".to_owned(),
            repository: "delivery".to_owned(),
        },
        200,
        bitbucket::BitbucketResponseBody::Repository(bitbucket::RepositoryPayload {
            uuid: "{repo-1}".to_owned(),
            workspace: "acme".to_owned(),
            slug: "delivery".to_owned(),
            name: Some("Delivery repository".to_owned()),
            is_private: true,
            revision: "repo-r1".to_owned(),
        }),
        None,
        None,
    )
}

fn pull_request_response(
    state: &str,
) -> Result<bitbucket::BitbucketHttpResponse, bitbucket::BitbucketTransportError> {
    response(
        bitbucket::BitbucketEndpoint::PullRequest {
            workspace: "acme".to_owned(),
            repository: "delivery".to_owned(),
            pull_request_id: 42,
        },
        200,
        bitbucket::BitbucketResponseBody::PullRequest(bitbucket::PullRequestPayload {
            id: 42,
            repository_uuid: "{repo-1}".to_owned(),
            state: state.to_owned(),
            title: Some("Bounded delivery result".to_owned()),
            source_commit: COMMIT.to_owned(),
            destination_commit: DESTINATION.to_owned(),
            revision: "pr-r1".to_owned(),
        }),
        None,
        None,
    )
}

fn statuses_response(
    status: u16,
    statuses: Vec<bitbucket::CommitStatusPayload>,
    retry_after_seconds: Option<u32>,
    next_page_token: Option<&str>,
) -> Result<bitbucket::BitbucketHttpResponse, bitbucket::BitbucketTransportError> {
    statuses_response_for_page(status, statuses, retry_after_seconds, next_page_token, None)
}

fn statuses_response_for_page(
    status: u16,
    statuses: Vec<bitbucket::CommitStatusPayload>,
    retry_after_seconds: Option<u32>,
    next_page_token: Option<&str>,
    page_token: Option<&str>,
) -> Result<bitbucket::BitbucketHttpResponse, bitbucket::BitbucketTransportError> {
    response(
        bitbucket::BitbucketEndpoint::CommitStatuses {
            workspace: "acme".to_owned(),
            repository: "delivery".to_owned(),
            commit: COMMIT.to_owned(),
            page_token: page_token
                .map(|value| bitbucket::OpaquePageToken::new(value).expect("page token")),
            page_size: bitbucket::PAGE_SIZE,
        },
        status,
        if status == 200 {
            bitbucket::BitbucketResponseBody::CommitStatuses(statuses)
        } else {
            bitbucket::BitbucketResponseBody::Empty
        },
        retry_after_seconds,
        next_page_token,
    )
}

fn pipeline_response(
    state: &str,
    result: Option<&str>,
) -> Result<bitbucket::BitbucketHttpResponse, bitbucket::BitbucketTransportError> {
    response(
        bitbucket::BitbucketEndpoint::Pipeline {
            workspace: "acme".to_owned(),
            repository: "delivery".to_owned(),
            pipeline_uuid: "{pipe-1}".to_owned(),
        },
        200,
        bitbucket::BitbucketResponseBody::Pipeline(bitbucket::PipelinePayload {
            uuid: "{pipe-1}".to_owned(),
            build_number: 7,
            state: state.to_owned(),
            result: result.map(str::to_owned),
            commit: COMMIT.to_owned(),
            target_ref: Some("main".to_owned()),
            revision: "pipeline-r1".to_owned(),
        }),
        None,
        None,
    )
}

fn deployment_response(
    status: u16,
) -> Result<bitbucket::BitbucketHttpResponse, bitbucket::BitbucketTransportError> {
    response(
        bitbucket::BitbucketEndpoint::Deployment {
            workspace: "acme".to_owned(),
            repository: "delivery".to_owned(),
            deployment_uuid: "{deployment-1}".to_owned(),
        },
        status,
        if status == 200 {
            bitbucket::BitbucketResponseBody::Deployment(bitbucket::DeploymentPayload {
                uuid: "{deployment-1}".to_owned(),
                pipeline_uuid: "{pipe-1}".to_owned(),
                commit: COMMIT.to_owned(),
                state: "SUCCESSFUL".to_owned(),
                environment: Some("production".to_owned()),
                revision: "deployment-r1".to_owned(),
            })
        } else {
            bitbucket::BitbucketResponseBody::Empty
        },
        None,
        None,
    )
}

fn success_statuses() -> Vec<bitbucket::CommitStatusPayload> {
    vec![bitbucket::CommitStatusPayload {
        key: "unit".to_owned(),
        name: Some("Unit tests".to_owned()),
        state: "SUCCESSFUL".to_owned(),
        revision: "status-r1".to_owned(),
        target_url_digest: Some(bitbucket::sha256_digest(
            b"https://ci.example.test/build/7?private=token",
        )),
    }]
}

fn provider_with_responses(
    responses: impl IntoIterator<
        Item = Result<bitbucket::BitbucketHttpResponse, bitbucket::BitbucketTransportError>,
    >,
) -> bitbucket::BitbucketProvider<bitbucket::FixtureBitbucketTransport, FixtureResolver> {
    bitbucket::BitbucketProvider::new(
        scope(),
        secret(),
        bitbucket::FixtureBitbucketTransport::new(responses),
        FixtureResolver,
    )
    .expect("provider")
}

fn complete_provider()
-> bitbucket::BitbucketProvider<bitbucket::FixtureBitbucketTransport, FixtureResolver> {
    provider_with_responses([
        repository_response(),
        pull_request_response("OPEN"),
        statuses_response(200, success_statuses(), None, None),
        pipeline_response("COMPLETED", Some("SUCCESSFUL")),
        deployment_response(200),
    ])
}

#[test]
fn contract_runtime_definition_and_native_gap_are_exact() {
    bitbucket::validate_contract().expect("contract validates");
    assert_eq!(bitbucket::contract_digest().as_str().len(), 64);
    let runtime_scope = PluginScope::new(
        RuntimeProjectId::new("project-1").expect("runtime project"),
        RuntimeMissionId::new("mission-1").expect("runtime mission"),
        1,
    )
    .expect("runtime scope");
    let definition = bitbucket::plugin_definition(runtime_scope.clone()).expect("definition");
    assert_eq!(definition.scope(), &runtime_scope);
    assert_eq!(definition.version(), bitbucket::plugin_version());
    assert_eq!(
        bitbucket::native_probe_from_environment().status,
        bitbucket::NativeProbeStatus::BlockedEnv
    );
    assert!(!bitbucket::native_probe_from_environment().native_connected_claim);
    assert!(!bitbucket::Layer1Authority::connected());
    assert!(!bitbucket::Layer1Authority::native());
    assert!(!bitbucket::Layer1Authority::first_party());
}

#[test]
fn complete_read_is_deterministic_bounded_and_redacted() {
    let mut service =
        bitbucket::BitbucketDeliveryResultService::new(complete_provider()).expect("service");
    let evidence = service
        .read(&bitbucket::BitbucketReadRequest::new(), now())
        .expect("read");
    assert_eq!(evidence.state, bitbucket::DeliveryResultState::Open);
    assert_eq!(evidence.provenance, bitbucket::TransportProvenance::Fixture);
    assert!(!evidence.connected && !evidence.native && !evidence.first_party);
    assert_eq!(evidence.receipts.len(), 5);
    assert!(evidence.receipts.iter().all(|receipt| {
        !receipt.raw_provider_payload_retained
            && !receipt.raw_credential_material_retained
            && !receipt.raw_pagination_token_retained
    }));
    let serialized = serde_json::to_string(&evidence).expect("evidence serializes");
    assert!(!serialized.contains("fixture-access-token"));
    assert!(!serialized.contains("host/keyring/bitbucket"));
    assert!(!serialized.contains("private=token"));
    assert!(!serialized.contains("https://ci.example.test"));
    assert_eq!(
        evidence.repository.as_ref().expect("repository").digest(),
        {
            let repository = evidence.repository.as_ref().expect("repository");
            repository.digest()
        }
    );

    let mut second_service = bitbucket::BitbucketDeliveryResultService::new(complete_provider())
        .expect("second service");
    let second = second_service
        .read(&bitbucket::BitbucketReadRequest::new(), now())
        .expect("second read");
    assert_eq!(evidence.digest(), second.digest());
    assert_eq!(evidence.scope_digest, scope().digest());
}

#[test]
fn mission_consumer_binds_scope_and_rejects_tamper_and_replay() {
    let mut provider = complete_provider();
    let mut consumer = bitbucket::MissionBitbucketDeliveryConsumer::new(scope());
    let evidence = provider
        .read(&bitbucket::BitbucketReadRequest::new(), now())
        .expect("evidence");
    let result = consumer
        .consume_once(evidence.clone())
        .expect("first consume");
    assert_eq!(result.state(), &bitbucket::DeliveryResultState::Open);
    assert_eq!(
        consumer.consume_once(evidence.clone()),
        Err(bitbucket::BitbucketDeliveryError::ReplayDetected)
    );

    let mut tampered = evidence;
    tampered.state = bitbucket::DeliveryResultState::Merged;
    assert_eq!(
        bitbucket::MissionBitbucketDeliveryConsumer::new(scope()).consume_evidence(tampered),
        Err(bitbucket::BitbucketDeliveryError::StaleEvidence)
    );

    let other_scope =
        bitbucket::BitbucketDeliveryScope::new(bitbucket::BitbucketDeliveryScopeInput {
            mission_revision: 6,
            ..bitbucket::BitbucketDeliveryScopeInput {
                workspace: "acme".to_owned(),
                repository: "delivery".to_owned(),
                repository_uuid: Some("{repo-1}".to_owned()),
                pull_request_id: 42,
                commit: COMMIT.to_owned(),
                build_number: 7,
                pipeline_uuid: "{pipe-1}".to_owned(),
                deployment_uuid: Some("{deployment-1}".to_owned()),
                project_id: "project-1".to_owned(),
                project_revision: 4,
                mission_id: "mission-1".to_owned(),
                mission_revision: 5,
                work_product_id: "work-product-1".to_owned(),
                work_product_revision: 6,
            }
        })
        .expect("other scope");
    assert_eq!(
        bitbucket::MissionBitbucketDeliveryConsumer::new(other_scope)
            .consume_evidence(result.evidence),
        Err(bitbucket::BitbucketDeliveryError::StaleEvidence)
    );
}

#[test]
fn typed_states_cover_denied_rate_limit_unknown_failed_and_partial() {
    let mut denied = provider_with_responses([response(
        bitbucket::BitbucketEndpoint::Repository {
            workspace: "acme".to_owned(),
            repository: "delivery".to_owned(),
        },
        403,
        bitbucket::BitbucketResponseBody::Empty,
        None,
        None,
    )]);
    assert_eq!(
        denied
            .read(&bitbucket::BitbucketReadRequest::new(), now())
            .expect("denied evidence")
            .state,
        bitbucket::DeliveryResultState::Denied
    );

    let mut rate_limited = provider_with_responses([response(
        bitbucket::BitbucketEndpoint::Repository {
            workspace: "acme".to_owned(),
            repository: "delivery".to_owned(),
        },
        429,
        bitbucket::BitbucketResponseBody::Empty,
        Some(120),
        None,
    )]);
    let rate_limited_evidence = rate_limited
        .read(&bitbucket::BitbucketReadRequest::new(), now())
        .expect("rate-limit evidence");
    assert_eq!(
        rate_limited_evidence.state,
        bitbucket::DeliveryResultState::RateLimit
    );
    assert_eq!(
        rate_limited_evidence.receipts[0].retry_after_seconds,
        Some(120)
    );

    let mut unknown = provider_with_responses([response(
        bitbucket::BitbucketEndpoint::Repository {
            workspace: "acme".to_owned(),
            repository: "delivery".to_owned(),
        },
        404,
        bitbucket::BitbucketResponseBody::Empty,
        None,
        None,
    )]);
    assert_eq!(
        unknown
            .read(&bitbucket::BitbucketReadRequest::new(), now())
            .expect("unknown evidence")
            .state,
        bitbucket::DeliveryResultState::ProviderUnknown
    );

    let mut failed = provider_with_responses([
        repository_response(),
        pull_request_response("OPEN"),
        statuses_response(
            200,
            vec![bitbucket::CommitStatusPayload {
                state: "FAILED".to_owned(),
                ..success_statuses().remove(0)
            }],
            None,
            None,
        ),
        pipeline_response("COMPLETED", Some("FAILED")),
        deployment_response(200),
    ]);
    assert_eq!(
        failed
            .read(&bitbucket::BitbucketReadRequest::new(), now())
            .expect("failed evidence")
            .state,
        bitbucket::DeliveryResultState::Failed
    );

    let mut partial = provider_with_responses([
        repository_response(),
        pull_request_response("OPEN"),
        statuses_response(403, Vec::new(), None, None),
        pipeline_response("COMPLETED", Some("SUCCESSFUL")),
        deployment_response(200),
    ]);
    let partial_evidence = partial
        .read(&bitbucket::BitbucketReadRequest::new(), now())
        .expect("partial evidence");
    assert_eq!(
        partial_evidence.state,
        bitbucket::DeliveryResultState::Partial
    );
    assert!(
        partial_evidence
            .partial_reasons
            .contains(&bitbucket::PartialReason::CommitStatusReadDenied)
    );
}

#[test]
fn pagination_is_bounded_and_page_tokens_are_opaque() {
    let first = statuses_response(200, success_statuses(), None, Some("opaque-page-cursor"));
    let second = statuses_response_for_page(
        200,
        success_statuses(),
        None,
        None,
        Some("opaque-page-cursor"),
    );
    let mut provider = provider_with_responses([
        repository_response(),
        pull_request_response("OPEN"),
        first,
        second,
        pipeline_response("COMPLETED", Some("SUCCESSFUL")),
        deployment_response(200),
    ]);
    let evidence = provider
        .read(&bitbucket::BitbucketReadRequest::new(), now())
        .expect("paginated evidence");
    assert_eq!(evidence.page_count, 2);
    assert_eq!(evidence.commit_statuses.len(), 2);
    let request_debug = format!("{:?}", provider.transport().requests()[3]);
    assert!(!request_debug.contains("opaque-page-cursor"));
    assert!(
        provider.transport().requests()[3]
            .safe_path_and_query()
            .expect("safe path")
            .contains("page_digest=")
    );
    assert!(evidence.receipts[3].path_and_query.contains("page_digest="));
    assert!(
        !evidence.receipts[3]
            .path_and_query
            .contains("opaque-page-cursor")
    );

    let mut bounded = provider_with_responses([
        repository_response(),
        pull_request_response("OPEN"),
        statuses_response(200, success_statuses(), None, Some("opaque-page-cursor")),
        pipeline_response("COMPLETED", Some("SUCCESSFUL")),
        deployment_response(200),
    ]);
    let request = bitbucket::BitbucketReadRequest::new()
        .with_page_bounds(bitbucket::PAGE_SIZE, 1)
        .expect("one page bound");
    let bounded_evidence = bounded.read(&request, now()).expect("bounded evidence");
    assert_eq!(
        bounded_evidence.state,
        bitbucket::DeliveryResultState::Partial
    );
    assert!(
        bounded_evidence
            .partial_reasons
            .contains(&bitbucket::PartialReason::PaginationBoundExceeded)
    );
}

#[test]
fn revision_scope_redaction_revocation_and_blocked_env_fail_closed() {
    let mut provider = provider_with_responses([
        repository_response(),
        pull_request_response("OPEN"),
        statuses_response(200, success_statuses(), None, None),
        pipeline_response("COMPLETED", Some("SUCCESSFUL")),
        deployment_response(200),
    ]);
    let request = bitbucket::BitbucketReadRequest::new()
        .with_expected_pipeline_revision("wrong-revision")
        .expect("revision request");
    assert!(matches!(
        provider.read(&request, now()),
        Err(bitbucket::BitbucketDeliveryError::PipelineRevisionMismatch { .. })
    ));

    let secret_ref = secret();
    assert!(!format!("{secret_ref:?}").contains("host/keyring/bitbucket"));
    assert!(
        !format!(
            "{:?}",
            bitbucket::BitbucketAccessToken::new(
                "secret-token",
                now() - Duration::seconds(1),
                now() + Duration::seconds(1),
            )
            .expect("token")
        )
        .contains("secret-token")
    );

    let mut revoked = complete_provider();
    let registration_digest = revoked.registration().registration_digest().clone();
    revoked
        .revoke(now() + Duration::seconds(1))
        .expect("revoke");
    assert_eq!(
        revoked.read(&bitbucket::BitbucketReadRequest::new(), now()),
        Err(bitbucket::BitbucketDeliveryError::RegistrationRevoked)
    );
    assert_eq!(
        revoked.registration().registration_digest(),
        &registration_digest
    );

    let mut blocked = bitbucket::BitbucketProvider::new(
        scope(),
        secret(),
        bitbucket::BlockedEnvBitbucketTransport,
        bitbucket::BlockedEnvCredentialResolver,
    )
    .expect("blocked provider");
    assert_eq!(
        blocked.read(&bitbucket::BitbucketReadRequest::new(), now()),
        Err(bitbucket::BitbucketDeliveryError::BlockedEnv)
    );
}

#[test]
fn raw_json_is_normalized_without_urls_or_unbounded_provider_payload() {
    let endpoint = bitbucket::BitbucketEndpoint::CommitStatuses {
        workspace: "acme".to_owned(),
        repository: "delivery".to_owned(),
        commit: COMMIT.to_owned(),
        page_token: None,
        page_size: bitbucket::PAGE_SIZE,
    };
    let request =
        bitbucket::BitbucketHttpRequest::new(endpoint, now(), bitbucket::MAX_RESPONSE_BYTES)
            .expect("request");
    let raw = serde_json::to_vec(&json!({
        "values": [{
            "key": "unit",
            "name": "Unit",
            "state": "SUCCESSFUL",
            "updated_on": "status-r1",
            "url": "https://ci.example.test/private/raw-token"
        }],
        "next": "https://api.bitbucket.org/2.0/statuses?page=opaque-json-token"
    }))
    .expect("raw json");
    let response = bitbucket::BitbucketHttpResponse::from_json(&request, 200, &raw, None, None)
        .expect("normalized response");
    let serialized = serde_json::to_string(response.body()).expect("normalized body");
    assert!(!serialized.contains("https://ci.example.test"));
    assert!(!serialized.contains("private-token"));
    assert_eq!(
        response
            .next_page_token()
            .expect("opaque next token")
            .digest(),
        bitbucket::sha256_digest(b"opaque-json-token")
    );
    assert!(!format!("{:?}", response.next_page_token()).contains("opaque-json-token"));
    assert_eq!(
        response.receipt().response_digest,
        bitbucket::sha256_digest(&raw)
    );
}
