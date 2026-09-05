use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_personalize_recommendation_result_plugin::{
    AwsAccountId, AwsPersonalizeProvider, AwsPersonalizeRecommendationScope,
    AwsPersonalizeRecommendationService, AwsPersonalizeTransportError, AwsRegion,
    BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA, CampaignIdentity,
    CampaignMetadata, CampaignMetadataInput, CampaignStatus, ConsentScope, Digest, FilterIdentity,
    FixtureTransport, GetRecommendationsRequest, ItemFingerprint, LoopbackTransport,
    MissionIdentity, ModelRevision, PROVIDER_API_REVISION, PersonalizeDomain, ProjectIdentity,
    RecommendationEvidenceState, RecommendationItem, RecommendationItemKind,
    RecommendationOperation, RecommendationResult, RecommenderIdentity, RecommenderMetadata,
    RecommenderMetadataInput, RecommenderStatus, ScoreBucket, SecretReference, ServingTarget,
    SolutionVersionIdentity, TransportProvenance, UserFingerprint, WorkProductIdentity,
};

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_SECRET: &str = "fixture-sigv4-secret-handle";
const RAW_CAMPAIGN: &str = "arn:aws:personalize:us-east-1:123456789012:campaign/fixture-campaign";
const RAW_RECOMMENDER: &str =
    "arn:aws:personalize:us-east-1:123456789012:recommender/fixture-recommender";
const RAW_FILTER: &str = "arn:aws:personalize:us-east-1:123456789012:filter/fixture-filter";
const RAW_USER: &str = "user-profile-never-exported";
const RAW_ITEM_LIST: &str = "item-001,item-002,item-003";
const RAW_PROVIDER_FAILURE: &str = "provider-private failure reason never exported";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("fixture timestamp")
}

fn scope() -> AwsPersonalizeRecommendationScope {
    AwsPersonalizeRecommendationScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        PersonalizeDomain::new("ECOMMERCE").expect("domain"),
        Some(CampaignIdentity::new(RAW_CAMPAIGN).expect("campaign")),
        Some(RecommenderIdentity::new(RAW_RECOMMENDER).expect("recommender")),
        Some(
            hartevo_aws_personalize_recommendation_result_plugin::SolutionVersionIdentity::new(
                "arn:aws:personalize:us-east-1:123456789012:solution/fixture/versions/1",
            )
            .expect("solution version"),
        ),
        Some(FilterIdentity::new(RAW_FILTER).expect("filter")),
        Some(UserFingerprint::new(RAW_USER).expect("user fingerprint")),
        Some(ItemFingerprint::new(RAW_ITEM_LIST).expect("item fingerprint")),
        ProjectIdentity::new("project-807", 4).expect("project"),
        MissionIdentity::new("mission-807", 7).expect("mission"),
        WorkProductIdentity::new("work-product-807", 9).expect("work product"),
    )
    .expect("scope")
}

fn secret(scope: &AwsPersonalizeRecommendationScope) -> SecretReference {
    SecretReference::sigv4(RAW_SECRET, scope, 1).expect("secret")
}

fn consent() -> ConsentScope {
    ConsentScope::for_layer_one("consent-807", 2, now() + Duration::days(7)).expect("consent")
}

fn fixture_service() -> AwsPersonalizeRecommendationService<FixtureTransport> {
    let scope = scope();
    let provider = AwsPersonalizeProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    AwsPersonalizeRecommendationService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("fixture service")
}

#[test]
fn contract_scope_registration_and_service_definition_are_fenced() {
    assert_eq!(
        CONTRACT_SCHEMA,
        "hartevo.aws-personalize-recommendation-result/v1"
    );
    assert_eq!(CONTRACT_DIGEST.len(), 64);
    assert!(CONTRACT_JSON.contains(PROVIDER_API_REVISION));

    let service = fixture_service();
    let definition = service.service_definition();
    definition.validate().expect("service definition");
    let capabilities = service.describe_capabilities();
    assert_eq!(capabilities.operations.len(), 4);
    assert!(capabilities.read_only);
    assert!(capabilities.proposal_only);
    assert!(!capabilities.connected);
    assert!(!capabilities.native);
    assert!(!capabilities.first_party);
    assert!(!capabilities.external_writes);
    assert!(service.registration().validate().is_ok());
    assert!(
        service
            .registration()
            .evidence_policy_digest()
            .as_str()
            .len()
            == 64
    );

    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
    assert!(!format!("{:?}", service.scope()).contains(RAW_CAMPAIGN));
    assert!(!format!("{:?}", service.scope()).contains(RAW_USER));
}

#[test]
fn fixture_recommendations_preserve_rank_score_buckets_and_model_revision_digest() {
    let mut service = fixture_service();
    let request = service.recommendations_request(3).expect("request");
    assert!(request.request_digest().as_str().len() == 64);
    assert!(!request.path_and_query().contains(RAW_USER));
    assert!(!request.path_and_query().contains(RAW_ITEM_LIST));

    let proposal = service.propose(request).expect("proposal");
    assert_eq!(proposal.state, RecommendationEvidenceState::Active);
    assert_eq!(proposal.provenance, TransportProvenance::Fixture);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.outcome_adopted);
    assert!(!proposal.work_product_adopted);
    let metadata = proposal
        .campaign_metadata
        .as_ref()
        .expect("campaign metadata");
    assert_eq!(metadata.status, CampaignStatus::Active);
    assert_eq!(metadata.model_revision.revision_digest.as_str().len(), 64);
    let result = proposal
        .recommendation_result
        .as_ref()
        .expect("recommendation result");
    assert_eq!(
        result.operation,
        RecommendationOperation::GetRecommendations
    );
    assert_eq!(result.items.len(), 3);
    assert_eq!(result.items[0].rank, 1);
    assert_eq!(result.items[1].rank, 2);
    assert_eq!(result.items[2].rank, 3);
    assert_eq!(result.items[0].score_bucket, ScoreBucket::VeryHigh);
    assert_eq!(result.items[1].score_bucket, ScoreBucket::High);
    assert_eq!(result.items[2].score_bucket, ScoreBucket::Low);
    assert!(!format!("{result:?}").contains("fixture-item-001"));
    assert!(
        !serde_json::to_string(&proposal)
            .expect("proposal JSON")
            .contains("fixture-item-001")
    );
    assert!(proposal.validate_integrity().is_ok());
    let report = service.verify(&proposal);
    assert!(report.valid);
    assert!(report.review_eligible);

    let mut consumer = service.consumer().expect("consumer");
    let mission_result = consumer.consume(&proposal).expect("mission result");
    assert!(mission_result.is_review_only());
    assert!(!mission_result.can_be_adopted());
    let first = consumer.record(&proposal, "recording-key").expect("record");
    let replay = consumer.record(&proposal, "recording-key").expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
    assert!(first.validate_integrity().is_ok());
}

#[test]
fn direct_campaign_recommender_and_ranking_seams_are_allowlisted() {
    let mut service = fixture_service();
    let campaign = service
        .propose(
            service
                .describe_campaign_request()
                .expect("campaign request"),
        )
        .expect("campaign proposal");
    assert_eq!(campaign.state, RecommendationEvidenceState::Active);
    assert!(campaign.campaign_metadata.is_some());
    assert!(campaign.recommendation_result.is_none());

    let recommender = service
        .propose(
            service
                .describe_recommender_request()
                .expect("recommender request"),
        )
        .expect("recommender proposal");
    assert_eq!(recommender.state, RecommendationEvidenceState::Active);
    assert!(recommender.recommender_metadata.is_some());

    let ranking = service
        .propose(
            service
                .personalized_ranking_request(3)
                .expect("ranking request"),
        )
        .expect("ranking proposal");
    assert_eq!(ranking.state, RecommendationEvidenceState::Active);
    assert_eq!(
        ranking
            .recommendation_result
            .as_ref()
            .expect("ranking result")
            .operation,
        RecommendationOperation::GetPersonalizedRanking
    );
}

#[test]
fn filter_fingerprint_and_ranking_bounds_fail_closed() {
    let scope = scope();
    let other_filter =
        FilterIdentity::new("arn:aws:personalize:us-east-1:123456789012:filter/other")
            .expect("other filter");
    let target_digest = scope.campaign().expect("campaign").digest();
    let result = GetRecommendationsRequest::new(
        &scope,
        ServingTarget::Campaign,
        target_digest,
        scope.user_fingerprint().cloned(),
        scope.item_fingerprint().cloned(),
        Some(other_filter),
        3,
    );
    assert!(result.is_err());

    assert!(GetRecommendationsRequest::for_scope(&scope, 0).is_err());
    assert!(GetRecommendationsRequest::for_scope(&scope, 51).is_err());
    let gap = RecommendationItem::new(RecommendationItemKind::Item, "item", 2, Some(0.5))
        .expect("bounded item");
    assert_eq!(
        RecommendationResult::new(RecommendationOperation::GetRecommendations, vec![gap])
            .expect_err("rank gap")
            .to_string(),
        "AWS Personalize recommendation ranking is not contiguous"
    );
    assert_eq!(
        ScoreBucket::from_score(Some(0.0)).expect("zero"),
        ScoreBucket::Zero
    );
    assert!(ScoreBucket::from_score(Some(1.1)).is_err());
}

#[test]
fn loopback_and_blocked_env_never_claim_native_or_connected() {
    let scope = scope();
    let loopback_provider =
        AwsPersonalizeProvider::new(LoopbackTransport::for_scope(&scope, now()))
            .expect("loopback provider");
    let mut loopback = AwsPersonalizeRecommendationService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        loopback_provider,
        now(),
    )
    .expect("loopback service");
    let loopback_proposal = loopback
        .propose(loopback.default_request().expect("request"))
        .expect("loopback proposal");
    assert_eq!(loopback_proposal.provenance, TransportProvenance::Loopback);
    assert!(!loopback_proposal.connected);
    assert!(!loopback_proposal.native);
    assert!(!loopback_proposal.first_party);

    let blocked_provider = AwsPersonalizeProvider::<BlockedEnvTransport>::default();
    let mut blocked = AwsPersonalizeRecommendationService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        blocked_provider,
        now(),
    )
    .expect("blocked service");
    let blocked_proposal = blocked
        .propose(blocked.default_request().expect("request"))
        .expect("blocked proposal");
    assert_eq!(
        blocked_proposal.state,
        RecommendationEvidenceState::ProviderUnknown
    );
    assert_eq!(blocked_proposal.provenance, TransportProvenance::BlockedEnv);
    assert_eq!(
        blocked_proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!blocked_proposal.connected);
    assert!(!blocked_proposal.native);
    assert!(!blocked_proposal.first_party);
    assert!(blocked.verify(&blocked_proposal).valid);
}

#[test]
fn recording_transport_preserves_response_digests_and_rejects_tamper() {
    let scope = scope();
    let campaign_request =
        hartevo_aws_personalize_recommendation_result_plugin::DescribeCampaignRequest::for_scope(
            &scope,
        )
        .expect("campaign request");
    let campaign_metadata = CampaignMetadata::new(
        &scope,
        CampaignMetadataInput {
            status: CampaignStatus::Active,
            model_revision: ModelRevision::from_digest(
                Digest::from_text("recorded-model-r1"),
                scope
                    .solution_version()
                    .map(SolutionVersionIdentity::digest),
            )
            .expect("model"),
            failure_reason: None,
            observed_at: now(),
        },
    )
    .expect("metadata");
    let campaign_response =
        hartevo_aws_personalize_recommendation_result_plugin::DescribeCampaignResponse::new(
            &campaign_request,
            campaign_metadata,
            256,
            TransportProvenance::Recording,
        )
        .expect("campaign response");
    let recommendation_request =
        GetRecommendationsRequest::for_scope(&scope, 2).expect("recommendation request");
    let recommendation_result = RecommendationResult::new(
        RecommendationOperation::GetRecommendations,
        vec![
            RecommendationItem::new(
                RecommendationItemKind::Item,
                "recorded-item-1",
                1,
                Some(0.8),
            )
            .expect("item 1"),
            RecommendationItem::new(
                RecommendationItemKind::Item,
                "recorded-item-2",
                2,
                Some(0.3),
            )
            .expect("item 2"),
        ],
    )
    .expect("result");
    let recommendation_response =
        hartevo_aws_personalize_recommendation_result_plugin::GetRecommendationsResponse::new(
            &recommendation_request,
            recommendation_result,
            256,
            TransportProvenance::Recording,
        )
        .expect("recommendation response");
    let mut transport =
        hartevo_aws_personalize_recommendation_result_plugin::RecordingTransport::default();
    transport.push_describe_campaign_response(Ok(campaign_response));
    transport.push_get_recommendations_response(Ok(recommendation_response));
    let provider = AwsPersonalizeProvider::new(transport).expect("recording provider");
    let mut service = AwsPersonalizeRecommendationService::new(
        scope.clone(),
        secret(&scope),
        consent(),
        provider,
        now(),
    )
    .expect("recording service");
    let proposal = service
        .propose(
            AwsPersonalizeRecommendationService::recommendations_request(&service, 2)
                .expect("request"),
        )
        .expect("recorded proposal");
    assert_eq!(proposal.provenance, TransportProvenance::Recording);
    assert_eq!(
        proposal
            .recommendation_result
            .as_ref()
            .expect("result")
            .items
            .len(),
        2
    );
    assert_eq!(service.provider().transport().requests().len(), 2);
    assert!(service.verify(&proposal).valid);

    let mut tampered = proposal.clone();
    tampered.proposal_digest = Digest::from_text("tampered-proposal");
    assert!(tampered.validate_integrity().is_err());
}

#[test]
fn registration_revoke_restore_and_failure_reason_are_digest_fenced() {
    let mut service = fixture_service();
    let revoked = service.revoke_registration().expect("revoke");
    assert_eq!(
        revoked.new_status,
        hartevo_aws_personalize_recommendation_result_plugin::RegistrationStatus::Revoked
    );
    assert!(service.default_request().is_ok());
    assert_eq!(
        service
            .propose(service.default_request().expect("request"))
            .expect_err("revoked registration")
            .to_string(),
        "AWS Personalize registration is not active"
    );
    service.restore_registration().expect("restore");
    assert!(
        service
            .propose(service.default_request().expect("request"))
            .is_ok()
    );

    let scope = scope();
    let model = ModelRevision::new("model", Some("solution")).expect("model");
    let metadata = RecommenderMetadata::new(
        &scope,
        RecommenderMetadataInput {
            status: RecommenderStatus::CreateFailed,
            model_revision: model,
            failure_reason: Some(RAW_PROVIDER_FAILURE.to_owned()),
            observed_at: now(),
        },
    )
    .expect("metadata");
    assert_eq!(metadata.status, RecommenderStatus::CreateFailed);
    assert!(metadata.failure_reason_digest.is_some());
    let serialized = serde_json::to_string(&metadata).expect("metadata JSON");
    assert!(!serialized.contains(RAW_PROVIDER_FAILURE));
}

#[test]
fn transport_error_mapping_keeps_access_loss_distinct() {
    assert!(AwsPersonalizeTransportError::Forbidden.is_access_loss());
    assert_eq!(
        AwsPersonalizeTransportError::RateLimited {
            retry_after_seconds: Some(2)
        }
        .status_code(),
        Some(429)
    );
}
