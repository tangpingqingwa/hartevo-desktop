use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_aws_datazone_subscription_result_plugin::{
    AwsAccountId, AwsDataZoneProvider, AwsDataZoneSubscriptionResultContract,
    AwsDataZoneSubscriptionResultService, AwsDataZoneSubscriptionScope, AwsDataZoneTransportError,
    AwsRegion, BlockedEnvTransport, CONTRACT_DIGEST, CONTRACT_JSON, CONTRACT_SCHEMA,
    CONTRACT_VERSION, DataZoneAssetId, DataZoneAssetIdentity, DataZoneDomainId,
    DataZoneEvidenceState, DataZoneListingId, DataZoneProjectId, DataZoneRevision,
    DataZoneSubscriptionGrantId, DataZoneSubscriptionId, DataZoneSubscriptionIdentity,
    DataZoneSubscriptionRequestId, DataZoneSubscriptionRequestIdentity, Digest, FixtureTransport,
    GetAssetRequest, GetAssetResponse, GetSubscriptionRequest,
    GetSubscriptionRequestDetailsRequest, GetSubscriptionRequestDetailsResponse,
    GetSubscriptionResponse, ListSubscriptionRequestsRequest, ListSubscriptionRequestsResponse,
    LoopbackTransport, MissionIdentity, ProjectIdentity, RecordingTransport, SecretReference,
    SubscriptionMetadata, SubscriptionRequestFilter, SubscriptionRequestMetadata,
    SubscriptionRequestStatus, SubscriptionStatus, TransportProvenance, WorkProductIdentity,
    contract_digest,
};
use serde_json::Value;

const NOW_SECONDS: i64 = 1_787_000_000;
const RAW_SECRET: &str = "opaque-datazone-fixture-secret";
const RAW_SCHEMA: &str = "raw-schema-must-not-escape";
const RAW_FORM: &str = "raw-metadata-form-must-not-escape";
const RAW_PRINCIPAL: &str = "arn:aws:iam::123456789012:role/raw-principal";

fn now() -> DateTime<Utc> {
    Utc.timestamp_opt(NOW_SECONDS, 0)
        .single()
        .expect("valid fixture timestamp")
}

fn scope() -> AwsDataZoneSubscriptionScope {
    AwsDataZoneSubscriptionScope::new(
        AwsAccountId::new("123456789012").expect("account"),
        AwsRegion::new("us-east-1").expect("region"),
        DataZoneDomainId::new("dzd-fixture-domain").expect("domain"),
        DataZoneProjectId::new("dz-project-fixture").expect("DataZone project"),
        DataZoneAssetIdentity::new(
            DataZoneAssetId::new("asset-fixture").expect("asset"),
            "asset-revision-1",
        )
        .expect("asset identity"),
        DataZoneListingId::new("listing-fixture").expect("listing"),
        DataZoneSubscriptionRequestIdentity::new(
            DataZoneSubscriptionRequestId::new("request-fixture").expect("request"),
        ),
        DataZoneSubscriptionIdentity::new(
            DataZoneSubscriptionId::new("subscription-fixture").expect("subscription"),
        ),
        DataZoneSubscriptionGrantId::new("grant-fixture").expect("grant"),
        DataZoneRevision::new("asset-revision-1").expect("revision"),
        MissionIdentity::new("mission-808", 7).expect("mission"),
        ProjectIdentity::new("project-808", 11).expect("project"),
        WorkProductIdentity::new("work-product-808", 13).expect("work product"),
    )
    .expect("scope")
}

fn fixture_service() -> AwsDataZoneSubscriptionResultService<FixtureTransport> {
    let scope = scope();
    let provider = AwsDataZoneProvider::new(FixtureTransport::for_scope(&scope, now()))
        .expect("fixture provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_datazone_subscription_result_plugin::ConsentScope::for_layer_one(
        "consent-808",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    AwsDataZoneSubscriptionResultService::new(scope, secret, consent, provider, now())
        .expect("service")
}

#[test]
fn contract_registration_and_secret_are_digest_bound() {
    let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
    assert_eq!(document["contractVersion"], CONTRACT_VERSION);
    assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
    assert_eq!(contract_digest(), CONTRACT_DIGEST);
    assert!(!document["provider"]["connected"].as_bool().unwrap());
    assert!(!document["provider"]["native"].as_bool().unwrap());
    assert!(!document["provider"]["firstParty"].as_bool().unwrap());
    assert!(!document["projection"]["rawSchemas"].as_bool().unwrap());
    assert!(
        !document["projection"]["rawMetadataForms"]
            .as_bool()
            .unwrap()
    );
    assert!(!document["projection"]["principals"].as_bool().unwrap());
    assert!(!document["projection"]["dataAccess"].as_bool().unwrap());
    assert!(
        !document["projection"]["subscriptionGrantEffects"]
            .as_bool()
            .unwrap()
    );
    AwsDataZoneSubscriptionResultContract::baseline().expect("checked contract");

    let service = fixture_service();
    let serialized = serde_json::to_string(service.registration()).expect("registration JSON");
    let debug = format!("{:?}", service.registration());
    assert!(serialized.contains("secretReferenceDigest"));
    assert!(!serialized.contains(RAW_SECRET));
    assert!(!debug.contains(RAW_SECRET));
    assert!(service.registration().validate().is_ok());
    assert_eq!(service.describe_capabilities().operations.len(), 4);
    assert_eq!(
        service.describe_capabilities().provider_id,
        "aws.datazone.subscription-result.recording"
    );
}

#[test]
fn fixture_evidence_preserves_digests_and_is_review_only() {
    let mut service = fixture_service();
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("proposal");
    assert_eq!(proposal.state, DataZoneEvidenceState::Accepted);
    assert!(proposal.list_complete);
    assert_eq!(proposal.list_pages, 1);
    assert!(proposal.asset.is_some());
    assert!(proposal.subscription_request.is_some());
    assert!(proposal.subscription.is_some());
    let request = proposal
        .subscription_request
        .as_ref()
        .expect("request projection");
    assert!(request.status_digest.as_str().len() == 64);
    assert!(request.revision_digest.as_str().len() == 64);
    assert!(request.request_reason_digest.as_str().len() == 64);
    assert!(request.reviewer_role_digest.as_str().len() == 64);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.first_party);
    assert!(!proposal.provider_receipt);
    assert!(!proposal.subscription_effect_claim);
    assert!(!proposal.data_access_claim);
    assert!(!proposal.can_be_adopted());
    assert!(proposal.validate_integrity().is_ok());
    assert!(service.verify(&proposal).valid);
    assert!(service.verify(&proposal).review_eligible);

    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for raw in [RAW_SECRET, RAW_SCHEMA, RAW_FORM, RAW_PRINCIPAL, "PUBLISHED"] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
    assert!(!serialized.contains("metadataForms"));
    assert!(!serialized.contains("subscribedPrincipals"));
    assert!(!serialized.contains("assetPermissions"));
    assert!(!serialized.contains("retainPermissions"));

    let mut consumer = service.consumer().expect("consumer");
    let result = consumer.consume(&proposal).expect("Mission result");
    assert!(result.review_only);
    assert!(!result.can_be_adopted());
    let recorded = consumer
        .record(&proposal, "idempotency-808")
        .expect("record");
    assert!(recorded.validate_integrity().is_ok());
    let replay = consumer
        .record(&proposal, "idempotency-808")
        .expect("replay");
    assert!(replay.replayed);
    assert_eq!(consumer.record_count(), 1);
}

#[test]
fn loopback_and_blocked_env_never_claim_native_evidence() {
    let scope = scope();
    let provider = AwsDataZoneProvider::new(LoopbackTransport::for_scope(&scope, now()))
        .expect("loopback provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_datazone_subscription_result_plugin::ConsentScope::for_layer_one(
        "consent-808",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsDataZoneSubscriptionResultService::new(scope.clone(), secret, consent, provider, now())
            .expect("loopback service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("loopback proposal");
    assert_eq!(proposal.provenance, TransportProvenance::Loopback);
    assert!(!proposal.connected && !proposal.native && !proposal.first_party);
    assert!(!service.verify(&proposal).valid || service.verify(&proposal).review_eligible);

    let provider = AwsDataZoneProvider::new(BlockedEnvTransport).expect("blocked provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_datazone_subscription_result_plugin::ConsentScope::for_layer_one(
        "consent-808",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut blocked =
        AwsDataZoneSubscriptionResultService::new(scope, secret, consent, provider, now())
            .expect("blocked service");
    let proposal = blocked
        .propose(blocked.default_request(now()).expect("request"))
        .expect("blocked proposal");
    assert_eq!(proposal.state, DataZoneEvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").category,
        "blocked_env"
    );
    assert!(!blocked.verify(&proposal).review_eligible);
}

#[test]
fn registration_revoke_restore_and_reverse_are_fenced() {
    let mut service = fixture_service();
    let request = service.default_request(now()).expect("request");
    service.revoke().expect("revoke");
    assert!(!service.registration().is_active());
    assert!(service.propose(request).is_err());
    service.restore_registration().expect("restore");
    assert!(service.registration().is_active());
    service.reverse().expect("reverse");
    assert!(
        service
            .propose(service.default_request(now()).expect("request"))
            .is_err()
    );
    assert!(service.restore_registration().is_err());
}

#[test]
fn recording_tamper_and_provider_failures_close_evidence() {
    let scope = scope();
    let filter = SubscriptionRequestFilter::for_scope(&scope, 50, None).expect("filter");
    let list_request = ListSubscriptionRequestsRequest::new(&scope, filter, None).expect("list");
    let item = SubscriptionRequestMetadata::for_scope(
        &scope,
        SubscriptionRequestStatus::Accepted,
        "request-revision-1",
        "catalog-approver",
    )
    .expect("request item");
    let list_response = ListSubscriptionRequestsResponse::new(
        &list_request,
        vec![item.clone()],
        None,
        512,
        TransportProvenance::Recording,
    )
    .expect("list response")
    .with_declared_digest(Digest::from_text("tampered-list"));
    let mut transport = RecordingTransport::default();
    transport.push_list_subscription_requests_response(Ok(list_response));
    let provider = AwsDataZoneProvider::new(transport).expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_datazone_subscription_result_plugin::ConsentScope::for_layer_one(
        "consent-808",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsDataZoneSubscriptionResultService::new(scope.clone(), secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("tampered proposal");
    assert_eq!(proposal.state, DataZoneEvidenceState::Tampered);
    assert!(!service.verify(&proposal).review_eligible);

    let provider = AwsDataZoneProvider::new({
        let mut transport = RecordingTransport::default();
        transport.push_list_subscription_requests_response(Err(
            AwsDataZoneTransportError::RateLimited {
                retry_after_seconds: Some(3),
            },
        ));
        transport
    })
    .expect("provider");
    let secret = SecretReference::sigv4(RAW_SECRET, &scope, 1).expect("secret");
    let consent = hartevo_aws_datazone_subscription_result_plugin::ConsentScope::for_layer_one(
        "consent-808",
        1,
        now() + Duration::days(7),
    )
    .expect("consent");
    let mut service =
        AwsDataZoneSubscriptionResultService::new(scope, secret, consent, provider, now())
            .expect("service");
    let proposal = service
        .propose(service.default_request(now()).expect("request"))
        .expect("throttled proposal");
    assert_eq!(proposal.state, DataZoneEvidenceState::Throttled);
    assert_eq!(
        proposal.failure.as_ref().expect("failure").status_code,
        Some(429)
    );
}

#[test]
fn response_shapes_keep_only_digest_projection() {
    let scope = scope();
    let asset_request = GetAssetRequest::for_scope(&scope).expect("asset request");
    let asset = hartevo_aws_datazone_subscription_result_plugin::AssetMetadata::new(
        &scope,
        hartevo_aws_datazone_subscription_result_plugin::AssetMetadataInput {
            status: "PUBLISHED".to_owned(),
            revision: "asset-revision-1".to_owned(),
            type_identifier: "raw-type".to_owned(),
            type_revision: "raw-type-revision".to_owned(),
            listing_id: "listing-fixture".to_owned(),
            owning_project_id: "dz-project-fixture".to_owned(),
            created_at: now() - Duration::hours(2),
            updated_at: now() - Duration::hours(1),
        },
    )
    .expect("asset");
    let response =
        GetAssetResponse::new(&asset_request, asset, 128, TransportProvenance::Recording)
            .expect("asset response");
    let serialized = serde_json::to_string(&response).expect("response JSON");
    for raw in ["PUBLISHED", "raw-type", "raw-type-revision"] {
        assert!(!serialized.contains(raw), "raw asset value leaked: {raw}");
    }

    let details_request =
        GetSubscriptionRequestDetailsRequest::for_scope(&scope).expect("details request");
    let details = SubscriptionRequestMetadata::for_scope(
        &scope,
        SubscriptionRequestStatus::Accepted,
        "request-revision-1",
        "reviewer-role",
    )
    .expect("details");
    let details_response = GetSubscriptionRequestDetailsResponse::new(
        &details_request,
        details,
        128,
        TransportProvenance::Recording,
    )
    .expect("details response");
    let subscription_request =
        GetSubscriptionRequest::for_scope(&scope).expect("subscription request");
    let subscription = SubscriptionMetadata::for_scope(
        &scope,
        SubscriptionStatus::Approved,
        "subscription-revision-1",
    )
    .expect("subscription");
    let subscription_response = GetSubscriptionResponse::new(
        &subscription_request,
        subscription,
        128,
        TransportProvenance::Recording,
    )
    .expect("subscription response");
    let combined =
        serde_json::to_string(&(details_response, subscription_response)).expect("combined JSON");
    for raw in [
        RAW_SCHEMA,
        RAW_FORM,
        RAW_PRINCIPAL,
        "reviewer-role",
        "request-revision-1",
    ] {
        assert!(
            !combined.contains(raw),
            "raw subscription value leaked: {raw}"
        );
    }
}
