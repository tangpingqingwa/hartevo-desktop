use std::collections::BTreeMap;

use hartevo_pinecone_retrieval_result_plugin::{
    MAX_METADATA_FIELDS, MAX_VECTOR_DIMENSIONS, MissionPineconeRetrievalConsumer,
    MissionPineconeRetrievalRequest, NativeStatus, PineconeCloud, PineconeConsistency,
    PineconeEvidenceError, PineconeFetchRequest, PineconeFilter, PineconeIndexDescription,
    PineconeIndexId, PineconeMatch, PineconeMetadata, PineconeMetadataValue, PineconeMetric,
    PineconeNamespace, PineconePaginationEvidence, PineconeProvider, PineconeProviderError,
    PineconeProviderManifest, PineconeQuery, PineconeQueryPolicy, PineconeQueryRequest,
    PineconeQueryResponse, PineconeReadiness, PineconeResultStatus, PineconeRetrievalProvider,
    PineconeRetrievalResultService, PineconeScope, PineconeVector, ResultId, SecretKind,
    SecretReference, VectorId, WorkProductId, contract_digest,
};
use serde_json::Value;

fn scope(mission_id: &str) -> PineconeScope {
    PineconeScope::fixture(mission_id).expect("fixture scope")
}

fn policy() -> PineconeQueryPolicy {
    PineconeQueryPolicy::fixture().expect("fixture policy")
}

fn query() -> PineconeQuery {
    PineconeQuery::new(
        policy().model,
        PineconeVector::new(vec![0.1, 0.2, 0.3]).expect("vector"),
        3,
        Some(
            PineconeFilter::eq(
                "topic",
                PineconeMetadataValue::Text(String::from("retrieval")),
            )
            .expect("filter"),
        ),
    )
    .expect("query")
}

fn service() -> (
    PineconeRetrievalResultService<PineconeProvider>,
    PineconeScope,
    PineconeQueryPolicy,
) {
    let scope = scope("mission-pinecone");
    let policy = policy();
    let provider = PineconeProvider::recording(scope.clone(), policy.clone()).expect("provider");
    (
        PineconeRetrievalResultService::new(provider).expect("service"),
        scope,
        policy,
    )
}

fn query_request(
    service: &PineconeRetrievalResultService<PineconeProvider>,
    scope: &PineconeScope,
    policy: &PineconeQueryPolicy,
    nonce: &str,
) -> PineconeQueryRequest {
    let proposal = service.compile_query_proposal(query()).expect("proposal");
    PineconeQueryRequest::for_policy(scope.clone(), proposal, policy, 1, nonce)
        .expect("query request")
}

#[test]
fn contract_is_layer_one_and_authority_is_honest() {
    let contract: Value = serde_json::from_str(
        hartevo_pinecone_retrieval_result_plugin::PINECONE_RETRIEVAL_RESULT_CONTRACT_JSON,
    )
    .expect("contract JSON");
    assert_eq!(contract["contractVersion"], "EXT-PINECONE-01-L1/v1");
    assert_eq!(contract["layer"], 1);
    assert_eq!(contract["queryPolicy"]["filter"]["arbitraryDsl"], false);
    assert_eq!(contract["provider"]["namespaceMutation"], false);
    assert_eq!(contract["authority"]["genericCatalog"], false);
    assert_eq!(contract["authority"]["durableMemory"], false);
    assert_eq!(contract["native"]["status"], "BLOCKED_ENV");
    assert_eq!(contract["contractDigest"], contract_digest().as_str());
}

#[test]
fn scope_query_model_vector_filter_consent_and_mission_are_bound() {
    let (service, scope, policy) = service();
    let capabilities = service.describe_capabilities().expect("capabilities");
    assert_eq!(capabilities.native_status, NativeStatus::BlockedEnv);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.external_write);
    assert_eq!(scope.cloud, PineconeCloud::Aws);
    assert_eq!(scope.namespace.as_str(), "fixture");
    assert_eq!(scope.mission_scope.mission_id.as_str(), "mission-pinecone");
    assert_eq!(scope.consent.consent_id.as_str(), "consent.fixture");

    let request = query_request(&service, &scope, &policy, "query-1");
    let response = service.query(&request).expect("query response");
    assert_eq!(response.status, PineconeResultStatus::Present);
    assert_eq!(response.revision, scope.index_revision);
    assert_eq!(response.read_units, 1);
    assert_eq!(response.matches[0].id.as_str(), "fixture-vector-1");

    let mission =
        MissionPineconeRetrievalRequest::new(scope, ResultId::new("result-1").expect("result id"))
            .expect("mission request");
    let consumer = MissionPineconeRetrievalConsumer::new(service);
    let evidence = consumer
        .consume_query(&mission, &response)
        .expect("mission evidence");
    assert!(!evidence.proposal.adopted);
    assert!(!evidence.proposal.kernel_verified);
    assert!(!evidence.receipt_candidate.durable);
    assert!(evidence.verification.tamper_checked);
    assert!(evidence.verification.replay_checked);
    assert!(evidence.verification.revision_checked);
}

#[test]
fn api_key_and_service_account_references_are_opaque_and_plans_are_blocked() {
    let scope = scope("mission-auth");
    let policy = policy();
    let api_manifest = hartevo_pinecone_retrieval_result_plugin::PineconeProviderManifest::api_key_secret_reference(
        scope.clone(),
        policy.clone(),
    )
    .expect("api manifest");
    let provider = PineconeProvider::new(api_manifest).expect("provider");
    let reference = SecretReference::with_kind(
        SecretKind::ApiKey,
        "raw-api-key-must-not-escape",
        scope.digest(),
        1,
    )
    .expect("opaque api key reference");
    assert!(!format!("{reference:?}").contains("raw-api-key-must-not-escape"));
    let plan_request = {
        let service = PineconeRetrievalResultService::new(
            provider.clone().with_secret_reference(reference.clone()),
        )
        .expect("service");
        query_request(&service, &scope, &policy, "auth-query")
    };
    let plan = provider
        .request_plan_for_query(&plan_request)
        .expect("query plan");
    assert!(plan.secret_reference_required);
    assert!(!plan.connected);
    assert!(!plan.native);
    assert!(!format!("{plan:?}").contains("raw-api-key"));
    let blocked_service = PineconeRetrievalResultService::new(
        provider.clone().with_secret_reference(reference.clone()),
    )
    .expect("blocked service");
    let blocked_request = query_request(&blocked_service, &scope, &policy, "auth-blocked");
    assert_eq!(
        blocked_service
            .query(&blocked_request)
            .expect_err("native gap"),
        PineconeEvidenceError::Provider(PineconeProviderError::BlockedEnv)
    );
    let mut revoked_reference = reference;
    revoked_reference.revoke();
    let revoked_service =
        PineconeRetrievalResultService::new(provider.with_secret_reference(revoked_reference))
            .expect("revoked service");
    let revoked_request = query_request(&revoked_service, &scope, &policy, "auth-revoked");
    assert_eq!(
        revoked_service
            .query(&revoked_request)
            .expect_err("revoked secret"),
        PineconeEvidenceError::Provider(PineconeProviderError::Unauthorized401 {
            access: hartevo_pinecone_retrieval_result_plugin::PineconeAccessLoss::CredentialRevoked,
        })
    );

    let service_manifest = hartevo_pinecone_retrieval_result_plugin::PineconeProviderManifest::service_account_secret_reference(
        scope.clone(),
        policy,
    )
    .expect("service account manifest");
    assert_eq!(
        service_manifest.auth_mode.required_kind(),
        Some(SecretKind::ServiceAccount)
    );
}

#[test]
fn query_and_fetch_carry_read_units_revision_tamper_and_replay_fences() {
    let (service, scope, policy) = service();
    let request = query_request(&service, &scope, &policy, "fence-query");
    let mut tampered_request = request.clone();
    tampered_request.request_digest = contract_digest();
    assert_eq!(
        service
            .query(&tampered_request)
            .expect_err("tampered request"),
        PineconeEvidenceError::TamperedResponse
    );
    let response = service.query(&request).expect("query");
    assert_eq!(response.request_digest, request.request_digest);
    assert_eq!(response.replay_fence, request.replay_fence);
    assert_eq!(response.revision, 1);
    assert_eq!(response.read_units, 1);

    service.provider().set_query_response(Ok(response.clone()));
    assert_eq!(
        service.query(&request).expect_err("replay"),
        PineconeEvidenceError::ReplayDetected
    );

    let mut tampered = response.clone();
    tampered.matches[0].score = 0.01;
    service.provider().set_query_response(Ok(tampered));
    let fresh_request = query_request(&service, &scope, &policy, "fence-tamper");
    assert_eq!(
        service.query(&fresh_request).expect_err("tamper"),
        PineconeEvidenceError::TamperedResponse
    );

    let fetch_request = PineconeFetchRequest::new(
        scope.clone(),
        vec![VectorId::new("fixture-vector-1").expect("vector id")],
        1,
        "fence-fetch",
    )
    .expect("fetch request");
    service.provider().clear_fault();
    let fetch = service.fetch(&fetch_request).expect("fetch");
    assert_eq!(fetch.revision, 1);
    assert_eq!(fetch.read_units, 1);
    assert_eq!(fetch.request_digest, fetch_request.request_digest);
}

#[test]
fn bounded_vectors_metadata_ids_and_typed_filters_fail_closed() {
    assert!(PineconeVector::new(vec![0.0; MAX_VECTOR_DIMENSIONS + 1]).is_err());
    assert!(PineconeVector::new(vec![f32::NAN]).is_err());
    let oversized_metadata = PineconeMetadata::new(
        (0..=MAX_METADATA_FIELDS)
            .map(|index| {
                (
                    format!("field-{index}"),
                    PineconeMetadataValue::Text(String::from("bounded")),
                )
            })
            .collect::<BTreeMap<_, _>>(),
    );
    assert!(oversized_metadata.is_err());
    assert!(VectorId::new(" ").is_err());

    let disallowed = PineconeFilter::eq(
        "not-registered",
        PineconeMetadataValue::Text(String::from("x")),
    )
    .expect("typed filter");
    let (service, _, _) = service();
    let rejected_query = PineconeQuery::new(
        policy().model,
        PineconeVector::new(vec![0.1, 0.2, 0.3]).expect("vector"),
        3,
        Some(disallowed),
    )
    .expect("typed query");
    assert!(matches!(
        service.compile_query_proposal(rejected_query),
        Err(PineconeEvidenceError::FilterFieldNotAllowlisted { .. })
    ));
    assert!(PineconeFilter::in_values("topic", Vec::new()).is_err());
}

#[test]
fn registration_is_versioned_scope_bound_reversible_and_revocable() {
    let scope = scope("mission-registration");
    let manifest =
        hartevo_pinecone_retrieval_result_plugin::PineconeProviderManifest::fixture(scope.clone())
            .expect("manifest");
    manifest.validate().expect("manifest valid");
    assert!(manifest.registration.reversible);
    assert!(manifest.registration.enabled);
    let revoked = manifest.revoked().expect("revoked");
    assert!(!revoked.registration.enabled);
    assert_ne!(revoked.manifest_digest, manifest.manifest_digest);
    assert!(revoked.validate().is_ok());
    let provider = PineconeProvider::fixture(scope).expect("provider");
    let service = PineconeRetrievalResultService::new(provider.clone()).expect("service");
    provider.revoke().expect("revoke");
    assert_eq!(
        service.describe_capabilities().expect_err("revoked"),
        PineconeEvidenceError::RegistrationRevoked
    );
    provider.reactivate().expect("reactivate");
    assert!(service.describe_capabilities().is_ok());
}

#[test]
fn readiness_not_ready_and_metric_mismatch_fail_closed() {
    let scope = scope("mission-readiness");
    let policy = policy();
    let not_ready_manifest = PineconeProviderManifest::recording(scope.clone(), policy.clone())
        .expect("manifest")
        .with_index_description(
            PineconeIndexDescription::new(
                3,
                PineconeMetric::Cosine,
                PineconeReadiness::NotReady,
                1,
            )
            .expect("index description"),
        )
        .expect("not-ready manifest");
    let not_ready = PineconeProvider::new(not_ready_manifest).expect("provider");
    let not_ready_service = PineconeRetrievalResultService::new(not_ready).expect("service");
    assert_eq!(
        not_ready_service.describe_index().expect("index").readiness,
        PineconeReadiness::NotReady
    );
    let not_ready_request = query_request(&not_ready_service, &scope, &policy, "not-ready");
    assert_eq!(
        not_ready_service
            .query(&not_ready_request)
            .expect_err("not ready"),
        PineconeEvidenceError::Provider(PineconeProviderError::IndexNotReady)
    );

    let metric_mismatch = PineconeProviderManifest::recording(scope.clone(), policy.clone())
        .expect("manifest")
        .with_index_description(
            PineconeIndexDescription::new(
                3,
                PineconeMetric::DotProduct,
                PineconeReadiness::Ready,
                1,
            )
            .expect("index description"),
        )
        .expect("metric manifest");
    assert_eq!(
        PineconeProvider::new(metric_mismatch).expect_err("metric mismatch"),
        PineconeEvidenceError::MetricMismatch
    );
}

#[test]
fn partial_empty_ranked_and_work_product_fences_are_typed() {
    let (partial_service, scope, policy) = service();
    let request = query_request(&partial_service, &scope, &policy, "partial");
    let manifest = partial_service.provider_manifest().expect("manifest");
    let ranked_matches = vec![
        PineconeMatch::new(
            VectorId::new("rank-1").expect("id"),
            0.91,
            PineconeMetadata::fixture().expect("metadata"),
            None,
        )
        .expect("match"),
        PineconeMatch::new(
            VectorId::new("rank-2").expect("id"),
            0.72,
            PineconeMetadata::default(),
            None,
        )
        .expect("match"),
    ];
    let partial = PineconeQueryResponse::recorded_partial(
        &request,
        &manifest,
        ranked_matches,
        2,
        PineconeConsistency::Eventual,
        PineconePaginationEvidence::new(1, 2, true).expect("pagination"),
        true,
    )
    .expect("partial response");
    partial_service.provider().set_query_response(Ok(partial));
    let response = partial_service.query(&request).expect("partial query");
    assert_eq!(response.status, PineconeResultStatus::Partial);
    assert!(response.truncated);
    assert!(response.pagination.has_more);
    assert!(response.matches[0].score > response.matches[1].score);

    let mission = MissionPineconeRetrievalRequest::for_work_product(
        scope.clone(),
        ResultId::new("result-partial").expect("result"),
        WorkProductId::new("work-product-1").expect("work product"),
    )
    .expect("mission");
    let consumer = MissionPineconeRetrievalConsumer::new(partial_service);
    let evidence = consumer
        .consume_query(&mission, &response)
        .expect("evidence");
    assert!(evidence.proposal.truncated);
    assert_eq!(
        evidence.proposal.work_product_id,
        Some(WorkProductId::new("work-product-1").expect("work product"))
    );
    assert!(evidence.proposal.work_product_digest.is_some());

    let (empty_service, empty_scope, empty_policy) = service();
    let empty_request = query_request(&empty_service, &empty_scope, &empty_policy, "empty");
    let empty_manifest = empty_service.provider_manifest().expect("manifest");
    let empty_response =
        PineconeQueryResponse::recorded(&empty_request, &empty_manifest, Vec::new(), 1)
            .expect("empty response");
    empty_service
        .provider()
        .set_query_response(Ok(empty_response));
    assert_eq!(
        empty_service
            .query(&empty_request)
            .expect("empty query")
            .status,
        PineconeResultStatus::Empty
    );
}

#[test]
fn stale_mission_revision_and_work_product_binding_fail_closed() {
    let (service, scope, policy) = service();
    let request = query_request(&service, &scope, &policy, "mission-revision");
    let response = service.query(&request).expect("query");
    let mission =
        MissionPineconeRetrievalRequest::new(scope, ResultId::new("result-stale").expect("result"))
            .expect("mission");
    let mut stale = mission.clone();
    stale.mission_scope.mission_revision = 2;
    let consumer = MissionPineconeRetrievalConsumer::new(service);
    assert_eq!(
        consumer
            .consume_query(&stale, &response)
            .expect_err("stale Mission revision"),
        PineconeEvidenceError::MissionRevisionMismatch {
            expected: 1,
            actual: 2,
        }
    );
}

#[test]
fn index_and_namespace_drift_fail_closed() {
    let (service, scope, policy) = service();
    let request = query_request(&service, &scope, &policy, "scope-drift");
    let mut index_drift = request.clone();
    index_drift.scope.index = PineconeIndexId::new("drifted-index").expect("index");
    assert_eq!(
        service.query(&index_drift).expect_err("index drift"),
        PineconeEvidenceError::ProposalBindingMismatch
    );
    let mut namespace_drift = request;
    namespace_drift.scope.namespace =
        PineconeNamespace::new("drifted-namespace").expect("namespace");
    assert_eq!(
        service
            .query(&namespace_drift)
            .expect_err("namespace drift"),
        PineconeEvidenceError::ProposalBindingMismatch
    );
}

#[test]
fn fixture_recording_fake_loopback_and_blocked_env_never_claim_connected_or_native() {
    let mission_seams_scope = scope("mission-seams");
    let seam_policy = policy();
    let providers = [
        PineconeProvider::fixture(mission_seams_scope.clone()).expect("fixture"),
        PineconeProvider::recording(mission_seams_scope.clone(), seam_policy.clone())
            .expect("recording"),
        PineconeProvider::fake(mission_seams_scope.clone(), seam_policy.clone()).expect("fake"),
        PineconeProvider::loopback(mission_seams_scope.clone(), seam_policy.clone())
            .expect("loopback"),
    ];
    for provider in providers {
        let manifest = provider.current_manifest();
        assert_eq!(manifest.native_status, NativeStatus::BlockedEnv);
        assert!(!manifest.connected);
        assert!(!manifest.native);
        assert!(!provider.external_write_available());
    }
    let blocked_scope = scope("mission-blocked");
    let blocked =
        PineconeProvider::blocked_env(blocked_scope.clone(), seam_policy).expect("blocked env");
    let service = PineconeRetrievalResultService::new(blocked).expect("service");
    let request = query_request(&service, &blocked_scope, &policy(), "blocked");
    assert_eq!(
        service.query(&request).expect_err("blocked"),
        PineconeEvidenceError::Provider(PineconeProviderError::BlockedEnv)
    );
}

#[test]
fn typed_provider_failures_have_no_raw_bodies_or_secrets() {
    for status in [401, 403, 404, 409, 429, 500] {
        assert!(
            PineconeProviderError::from_status(status)
                .status_code()
                .is_some()
        );
    }
    let error = PineconeProviderError::Unauthorized401 {
        access: hartevo_pinecone_retrieval_result_plugin::PineconeAccessLoss::CredentialRevoked,
    };
    assert!(!format!("{error:?}").contains("raw"));
    assert_eq!(
        error.projection_status(),
        hartevo_pinecone_retrieval_result_plugin::PineconeResultStatus::AccessLoss
    );
}
