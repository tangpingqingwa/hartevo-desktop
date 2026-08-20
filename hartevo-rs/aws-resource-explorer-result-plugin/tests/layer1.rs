use hartevo_aws_resource_explorer_result_plugin::{
    AccountId, AwsRegion, AwsResourceExplorerContract, AwsResourceExplorerOperation,
    AwsResourceExplorerProvider, AwsResourceExplorerScope, AwsResourceExplorerScopeSpec,
    AwsResourceExplorerService, BlockedEnvAwsResourceExplorerTransport, Digest,
    FakeAwsResourceExplorerTransport, IndexInventoryItem, InventoryState, ListIndexesPage,
    ListIndexesRequest, MissionAwsResourceExplorerConsumer, MissionAwsResourceExplorerState,
    MissionBinding, OpaquePageToken, PermissionFence, PropertyDigest,
    RecordingAwsResourceExplorerTransport, ResourceExplorerIndex, ResourceExplorerQuery,
    ResourceExplorerResource, ResourceExplorerView, ResourceInventoryItem, Revision, SearchPage,
    SearchRequest, SecretReference, TransportError, TransportProvenance,
};

fn scope() -> AwsResourceExplorerScope {
    let account = AccountId::new("123456789012").expect("account");
    let region = AwsRegion::new("us-east-1").expect("region");
    let index = ResourceExplorerIndex::new(
        account.clone(),
        region.clone(),
        "arn:aws:resource-explorer-2:us-east-1:123456789012:index/idx-1",
        Revision::new(2).expect("index revision"),
    )
    .expect("index");
    let view = ResourceExplorerView::new(
        "arn:aws:resource-explorer-2:us-east-1:123456789012:view/view-1",
        Revision::new(3).expect("view revision"),
    )
    .expect("view");
    let resource = ResourceExplorerResource::new(
        "AWS::S3::Bucket",
        "arn:aws:s3:::bucket-a",
        region.clone(),
        Revision::new(4).expect("resource revision"),
    )
    .expect("resource");
    AwsResourceExplorerScope::new(AwsResourceExplorerScopeSpec {
        account_id: account,
        region,
        index,
        view,
        query: ResourceExplorerQuery::new("service:s3", Revision::new(5).expect("query revision"))
            .expect("query"),
        resources: vec![resource],
        mission: MissionBinding::from_parts("mission-1", 6).expect("Mission"),
        permission: PermissionFence::for_layer_one(7).expect("permissions"),
    })
    .expect("scope")
}

fn resource(scope: &AwsResourceExplorerScope) -> ResourceInventoryItem {
    ResourceInventoryItem::from_raw(
        "arn:aws:s3:::bucket-a",
        "AWS::S3::Bucket",
        scope.region().clone(),
        "s3",
        [(
            "LastReportedAt".to_owned(),
            "2026-08-15T00:00:00Z".to_owned(),
        )],
        Revision::new(4).expect("resource revision"),
    )
    .expect("resource evidence")
}

fn service_with_recording(
    transport: RecordingAwsResourceExplorerTransport,
) -> (
    AwsResourceExplorerScope,
    AwsResourceExplorerService<RecordingAwsResourceExplorerTransport>,
) {
    let scope = scope();
    let secret = SecretReference::for_scope("keyring-ref", &scope, 1).expect("secret");
    let provider = AwsResourceExplorerProvider::new(transport).expect("provider");
    let service = AwsResourceExplorerService::new(
        scope.clone(),
        secret,
        scope.permission().clone(),
        provider,
    )
    .expect("service");
    (scope, service)
}

#[test]
fn contract_and_layer_one_authority_are_explicit() {
    AwsResourceExplorerContract::baseline().expect("contract");
    assert!(
        !serde_json::to_string(&AwsResourceExplorerContract::baseline().unwrap().value())
            .unwrap()
            .is_empty()
    );
    assert!(!hartevo_aws_resource_explorer_result_plugin::Layer1Authority::connected());
    assert!(!hartevo_aws_resource_explorer_result_plugin::Layer1Authority::native());
    assert!(!hartevo_aws_resource_explorer_result_plugin::Layer1Authority::external_writes());
}

#[test]
fn secret_and_pagination_are_opaque_and_non_leaking() {
    let scope = scope();
    let secret = SecretReference::for_scope("raw-keyring-material", &scope, 1).expect("secret");
    assert!(serde_json::to_string(&secret).is_err());
    assert!(!format!("{secret:?}").contains("raw-keyring-material"));

    let request = SearchRequest::new(&scope, 50, 4, None).expect("request");
    let token = OpaquePageToken::new("provider-next-token", request.pagination_binding_digest())
        .expect("token");
    let encoded = serde_json::to_string(&token).expect("opaque token JSON");
    assert_eq!(encoded, r#"{"opaque":true}"#);
    assert!(!encoded.contains("provider-next-token"));
    let next = request.with_page_token(token).expect("bound request");
    assert!(
        !serde_json::to_string(&next)
            .expect("request JSON")
            .contains("provider-next-token")
    );
}

#[test]
fn search_proposal_record_verify_and_mission_consume_are_read_only() {
    let scope = scope();
    let request = SearchRequest::new(&scope, 50, 4, None).expect("request");
    let mut transport = RecordingAwsResourceExplorerTransport::default();
    transport.push_search_response(Ok(SearchPage::new(
        &request,
        1,
        vec![resource(&scope)],
        None,
        512,
        "aws-resource-explorer-2-read-r1",
    )
    .expect("page")));
    let (scope, mut service) = service_with_recording(transport);
    let proposal = service.propose_search(request).expect("proposal");
    assert_eq!(proposal.operation, AwsResourceExplorerOperation::Search);
    assert_eq!(proposal.evidence.state, InventoryState::Complete);
    assert!(proposal.evidence.property_digests_only);
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.raw_properties_retained);
    assert!(!proposal.evidence.raw_tags_retained);
    assert!(!proposal.evidence.raw_pii_retained);

    let mut consumer =
        MissionAwsResourceExplorerConsumer::new(scope.clone(), service.registration())
            .expect("consumer");
    let mission_result = consumer.consume(proposal.clone()).expect("Mission result");
    assert_eq!(
        mission_result.state,
        MissionAwsResourceExplorerState::DecisionReady
    );
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    assert!(!mission_result.deployability_claim);
    assert!(!mission_result.compliance_claim);
    assert!(!mission_result.adopted_outcome);

    let record = service.record(&proposal).expect("record");
    assert!(record.recorded);
    assert!(!record.durable_receipt);
    assert!(!record.connected);
    let verification = service.verify(&record).expect("verification");
    assert!(verification.verified);
    assert!(verification.property_digests_only);
    assert!(!verification.adopted_outcome);
    assert!(consumer.consume(proposal).is_err());
}

#[test]
fn list_indexes_is_bounded_and_registration_is_reversible() {
    let scope = scope();
    let request = ListIndexesRequest::new(&scope, 50, 4, None).expect("request");
    let index = IndexInventoryItem::from_raw(
        "arn:aws:resource-explorer-2:us-east-1:123456789012:index/idx-2",
        scope.region().clone(),
        "ACTIVE",
        "LOCAL",
        Revision::new(1).expect("index revision"),
    )
    .expect("index evidence");
    let mut transport = RecordingAwsResourceExplorerTransport::default();
    transport.push_list_indexes_response(Ok(ListIndexesPage::new(
        &request,
        1,
        vec![index],
        None,
        128,
        "aws-resource-explorer-2-read-r1",
    )
    .expect("page")));
    let (_, mut service) = service_with_recording(transport);
    let evidence = service.read_list_indexes(request).expect("evidence");
    assert_eq!(evidence.state, InventoryState::Complete);
    assert_eq!(evidence.indexes.len(), 1);
    service.revoke_registration().expect("revoke");
    assert!(service.register().is_err());
    service.restore_registration().expect("restore");
    assert!(service.is_active());
}

#[test]
fn cursor_replay_and_provider_failures_fail_closed() {
    let scope = scope();
    let request = SearchRequest::new(&scope, 50, 2, None).expect("request");
    let token =
        OpaquePageToken::new("replayed", request.pagination_binding_digest()).expect("token");
    let first = SearchPage::new(
        &request,
        1,
        vec![resource(&scope)],
        Some(token.clone()),
        128,
        "aws-resource-explorer-2-read-r1",
    )
    .expect("first page");
    let second_request = request
        .with_page_token(token.clone())
        .expect("second request");
    let second = SearchPage::new(
        &second_request,
        2,
        vec![resource(&scope)],
        Some(token),
        128,
        "aws-resource-explorer-2-read-r1",
    )
    .expect("second page");
    let mut transport = RecordingAwsResourceExplorerTransport::default();
    transport.push_search_response(Ok(first));
    transport.push_search_response(Ok(second));
    let (_, mut service) = service_with_recording(transport);
    let evidence = service.read_search(request).expect("read");
    assert_eq!(evidence.state, InventoryState::Partial);
    assert_eq!(
        evidence.partial_reason,
        Some(hartevo_aws_resource_explorer_result_plugin::PartialReason::CursorReplay)
    );

    let mut blocked = AwsResourceExplorerService::new(
        scope.clone(),
        SecretReference::for_scope("blocked-ref", &scope, 1).expect("secret"),
        scope.permission().clone(),
        AwsResourceExplorerProvider::new(BlockedEnvAwsResourceExplorerTransport).expect("provider"),
    )
    .expect("blocked service");
    let evidence = blocked
        .read_search(SearchRequest::new(&scope, 50, 1, None).expect("request"))
        .expect("blocked read");
    assert_eq!(evidence.state, InventoryState::ProviderUnknown);
    assert!(!evidence.provenance.native());
    assert!(!evidence.provenance.connected());

    let mut denied_transport = RecordingAwsResourceExplorerTransport::default();
    denied_transport.push_search_response(Err(TransportError::Forbidden));
    let (_, mut denied) = service_with_recording(denied_transport);
    let evidence = denied
        .read_search(SearchRequest::new(&scope, 50, 1, None).expect("request"))
        .expect("denied read");
    assert_eq!(evidence.state, InventoryState::AccessLost);
}

#[test]
fn parser_discards_raw_properties_tags_and_next_token() {
    let scope = scope();
    let request = SearchRequest::new(&scope, 50, 1, None).expect("request");
    let body = br#"{
      "Resources": [{
        "Arn": "arn:aws:s3:::bucket-a",
        "ResourceType": "AWS::S3::Bucket",
        "Region": "us-east-1",
        "Service": "s3",
        "Properties": [{"Name":"SecretProperty","Data":"do-not-retain"}],
        "Tags": [{"Key":"PII","Value":"do-not-retain"}]
      }],
      "NextToken": "raw-provider-token"
    }"#;
    let page =
        AwsResourceExplorerProvider::<RecordingAwsResourceExplorerTransport>::parse_search_page(
            &request, 1, body,
        )
        .expect("parsed page");
    let encoded = serde_json::to_string(&page).expect("page JSON");
    for forbidden in [
        "do-not-retain",
        "raw-provider-token",
        "SecretProperty",
        "PII",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "raw value survived: {forbidden}"
        );
    }
    assert!(encoded.contains("propertyDigests"));
}

#[test]
fn all_layer_one_provenances_are_not_connected_or_native() {
    let recording_providers = [
        AwsResourceExplorerProvider::new(RecordingAwsResourceExplorerTransport::fixture())
            .expect("fixture"),
        AwsResourceExplorerProvider::new(RecordingAwsResourceExplorerTransport::new(
            TransportProvenance::Recording,
        ))
        .expect("recording"),
    ];
    for provider in recording_providers {
        assert!(!provider.connected());
        assert!(!provider.native());
        assert!(!provider.definition().connected);
        assert!(!provider.definition().native);
    }
    let loopback = AwsResourceExplorerProvider::new(
        FakeAwsResourceExplorerTransport::new(Vec::new(), Vec::new())
            .with_provenance(TransportProvenance::Loopback),
    )
    .expect("loopback");
    assert!(!loopback.connected());
    assert!(!loopback.native());
    let blocked =
        AwsResourceExplorerProvider::new(BlockedEnvAwsResourceExplorerTransport).expect("blocked");
    assert!(!blocked.connected());
    assert!(!blocked.native());
}

#[test]
fn property_digest_values_are_stable_without_raw_value_retention() {
    let property = PropertyDigest::new("Name", "value").expect("property");
    assert_eq!(property.name_digest(), &Digest::from_text("Name"));
    assert_ne!(property.value_digest(), &Digest::zero());
    assert!(
        !serde_json::to_string(&property)
            .expect("property JSON")
            .contains("\"value\""),
    );
}
