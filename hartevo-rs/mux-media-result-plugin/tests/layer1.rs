use hartevo_mux_media_result_plugin::{
    AssetScope, BlockedEnvMuxTransport, ConsentOperation, ConsentScope, EncodingScope,
    FixtureMuxTransport, Layer1Authority, LoopbackMuxTransport, MissionMuxMediaConsumer,
    MissionScope, MuxAssetPayload, MuxAssetState, MuxCursor, MuxEndpoint, MuxEnvironment, MuxError,
    MuxHttpRequest, MuxHttpResponse, MuxJsonResponse, MuxMediaResultContract,
    MuxMediaResultRequest, MuxMediaResultService, MuxPlaybackAssociationPayload,
    MuxPlaybackPayload, MuxPlaybackPolicy, MuxProgressPayload, MuxProvider, MuxReadBounds,
    MuxRegistration, MuxResponseBody, MuxRetryPolicy, MuxScope, MuxScopeInput, MuxSecretKind,
    MuxTrackId, MuxTrackPayload, MuxTransportMode, ProjectScope, RecordingMuxTransport,
    SecretReference, StaticRenditionScope, WorkProductScope, contract_digest, provider_digest,
};

const NOW: i64 = 1_787_000_000;

fn secret() -> SecretReference {
    SecretReference::new(
        "host/keychain/mux-api-credential",
        MuxSecretKind::ApiCredential,
        7,
    )
    .expect("opaque secret")
}

fn scope() -> MuxScope {
    MuxScope::new(MuxScopeInput {
        environment: MuxEnvironment::new("mux-env-1", 2).expect("environment"),
        asset: AssetScope::new("asset-1", 3).expect("asset"),
        playback: Some(
            hartevo_mux_media_result_plugin::MuxPlaybackScope::new(
                "playback-1",
                4,
                MuxPlaybackPolicy::Public,
                5,
            )
            .expect("playback"),
        ),
        track: Some(
            hartevo_mux_media_result_plugin::MuxTrackScope::new("track-video-1", 6).expect("track"),
        ),
        static_rendition: Some(
            StaticRenditionScope::new("static-rendition-1", 7).expect("static rendition"),
        ),
        encoding: EncodingScope::new("baseline", 8).expect("encoding"),
        project: ProjectScope::new("project-1", 9).expect("project"),
        mission: MissionScope::new("mission-1", 10).expect("mission"),
        work_product: WorkProductScope::new("work-product-1", 11).expect("work product"),
        consent: ConsentScope::new("consent-1", 12, ConsentOperation::MetadataRead)
            .expect("consent"),
        secret: secret(),
    })
    .expect("scope")
}

fn request(scope: &MuxScope) -> MuxMediaResultRequest {
    MuxMediaResultRequest::new(scope)
}

fn asset_payload(scope: &MuxScope, status: &str) -> MuxAssetPayload {
    MuxAssetPayload {
        id: scope.asset().id.clone(),
        status: status.to_owned(),
        tracks: vec![
            MuxTrackPayload {
                id: scope.track().expect("track scope").id.clone(),
                kind: "video".to_owned(),
                status: Some("ready".to_owned()),
                max_width: Some(1920),
                max_height: Some(1080),
                max_frame_rate_milli: Some(29_970),
                max_channels: None,
                duration_ms: Some(2_500),
                language_code: None,
                text_type: None,
            },
            MuxTrackPayload {
                id: MuxTrackId::new("track-audio-1").expect("audio track"),
                kind: "audio".to_owned(),
                status: Some("ready".to_owned()),
                max_width: None,
                max_height: None,
                max_frame_rate_milli: None,
                max_channels: Some(2),
                duration_ms: Some(2_500),
                language_code: Some("en".to_owned()),
                text_type: None,
            },
        ],
        playback_ids: vec![MuxPlaybackPayload {
            id: scope.playback().expect("playback scope").id.clone(),
            policy: Some("public".to_owned()),
        }],
        duration_ms: Some(2_500),
        created_at_epoch_seconds: Some(NOW),
        max_stored_resolution: Some("HD".to_owned()),
        resolution_tier: Some("1080p".to_owned()),
        encoding_tier: Some("baseline".to_owned()),
        video_quality: Some("basic".to_owned()),
        progress: Some(MuxProgressPayload {
            state: Some("completed".to_owned()),
            progress: Some(if status == "partial" { 50 } else { 100 }),
        }),
    }
}

fn playback_payload(scope: &MuxScope) -> MuxPlaybackAssociationPayload {
    MuxPlaybackAssociationPayload {
        id: scope.playback().expect("playback scope").id.clone(),
        policy: Some("public".to_owned()),
        object_type: "asset".to_owned(),
        object_id: scope.asset().id.clone(),
    }
}

fn typed_responses(scope: &MuxScope, status: &str) -> [MuxHttpResponse; 2] {
    [
        MuxHttpResponse::from_body(
            200,
            MuxResponseBody::Asset(asset_payload(scope, status)),
            None,
        ),
        MuxHttpResponse::from_body(
            200,
            MuxResponseBody::PlaybackAssociation(playback_payload(scope)),
            None,
        ),
    ]
}

#[test]
fn contract_and_definition_are_exact_and_layer_one_closed() {
    let contract = MuxMediaResultContract::baseline().expect("typed contract");
    assert_eq!(
        contract.schema_version,
        "hartevo.mux-media-result.contract/v1"
    );
    assert_eq!(contract.contract_version, "mux-media-result/v1");
    assert_eq!(contract.service_id, "mux.media.result");
    assert_eq!(contract.provider_id, "mux.video.metadata");
    assert_eq!(contract_digest(), contract.digest());
    assert_eq!(provider_digest().as_str().len(), 64);
    assert!(!contract.authority.connected);
    assert!(!contract.authority.native);
    assert!(!contract.authority.external_writes);
    assert!(!contract.authority.media_download);
    assert!(!contract.authority.signed_token_generation);
    assert_eq!(contract.native_gap.status, "BLOCKED_ENV");
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::external_writes());
    assert!(!Layer1Authority::signed_token_generation());
    assert!(!Layer1Authority::media_download());
    assert!(!Layer1Authority::viewer_analytics());
    assert!(!Layer1Authority::adopted_outcome());

    let service = MuxMediaResultService::new(scope()).expect("service");
    let definition = service.plugin_definition().expect("definition");
    definition.validate().expect("definition is bound");
    assert_eq!(definition.scope_digest, service.scope().digest());
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
}

#[test]
fn opaque_secret_never_serializes_or_debug_prints_the_host_handle() {
    let handle = "mux-token-id=do-not-retain;secret=do-not-retain;signing-key=do-not-retain";
    let reference = SecretReference::new(handle, MuxSecretKind::HostManaged, 3).expect("reference");
    let serialized = serde_json::to_string(&reference).expect("secret JSON");
    let debug = format!("{reference:?}");
    assert!(!serialized.contains(handle));
    assert!(!debug.contains(handle));
    assert!(!serialized.contains("token-id"));
    assert!(!serialized.contains("signing-key"));
    assert!(serialized.contains("referenceDigest"));
    assert_eq!(reference.reference_digest().as_str().len(), 64);
}

#[test]
fn loopback_produces_bounded_ready_evidence_without_native_claims() {
    let scoped = scope();
    let transport = LoopbackMuxTransport::for_scope(&scoped);
    let mut provider = MuxProvider::new(scoped.clone(), transport).expect("provider");
    let mut consumer = MissionMuxMediaConsumer::new(scoped.clone()).expect("consumer");
    let result = consumer
        .read(&mut provider, &request(&scoped), NOW)
        .expect("loopback read");

    assert_eq!(result.evidence.provenance, MuxTransportMode::Loopback);
    assert_eq!(result.evidence.asset.state, MuxAssetState::Ready);
    assert_eq!(result.evidence.delivery.state, MuxAssetState::Ready);
    assert!(result.evidence.delivery.metadata_ready);
    assert!(result.evidence.delivery.encoding_ready);
    assert!(!result.evidence.delivery.authorization_proven);
    assert!(!result.evidence.delivery.playback_success_proven);
    assert!(!result.evidence.playback_success_proven);
    assert!(!result.evidence.content_correctness_proven);
    assert!(!result.evidence.publication_authority);
    assert!(!result.evidence.native_connected);
    assert_eq!(result.evidence.asset.tracks.len(), 2);
    assert!(result.evidence.receipts.iter().all(|receipt| {
        receipt.method == "GET"
            && !receipt.raw_provider_payload_retained
            && !receipt.credential_material_retained
            && !receipt.media_bytes_retained
            && !receipt.viewer_identifiers_retained
    }));
    let serialized = serde_json::to_string(&result).expect("result JSON");
    assert!(!serialized.contains("stream.mux.com"));
    assert!(!serialized.contains("token="));
    assert!(!serialized.contains("viewer-"));
    assert!(result.observation.digest().is_sha256());
}

#[test]
fn recording_json_drops_urls_tokens_bytes_and_viewer_identifiers() {
    let scoped = scope();
    let request = request(&scoped);
    let asset_endpoint = MuxEndpoint::AssetMetadata {
        asset_id: scoped.asset().id.clone(),
    };
    let playback_endpoint = MuxEndpoint::PlaybackAssociation {
        playback_id: scoped.playback().expect("playback").id.clone(),
    };
    let asset_request = MuxHttpRequest::get(
        asset_endpoint,
        request.digest(),
        scoped.digest(),
        hartevo_mux_media_result_plugin::MUX_MAX_RESPONSE_BYTES,
    )
    .expect("asset request");
    let playback_request = MuxHttpRequest::get(
        playback_endpoint,
        request.digest(),
        scoped.digest(),
        hartevo_mux_media_result_plugin::MUX_MAX_RESPONSE_BYTES,
    )
    .expect("playback request");
    let asset_json = br#"{
      "data": {
        "id": "asset-1",
        "status": "ready",
        "tracks": [{"id":"track-video-1","type":"video","status":"ready","max_width":1280,"max_height":720,"max_frame_rate":29.97,"duration":2.5,"source_url":"https://origin.example/raw.mp4","viewer_id":"viewer-77"}],
        "playback_ids": [{"id":"playback-1","policy":"public","token":"MUX_TOKEN_SECRET"}],
        "duration": 2.5,
        "created_at": "1787000000",
        "resolution_tier":"720p",
        "source_url":"https://storage.example/source.mp4",
        "thumbnail_url":"https://image.mux.com/secret/thumbnail.jpg",
        "raw_bytes":"AAECAwQ=",
        "viewer":{"email":"person@example.com"},
        "progress":{"state":"completed","progress":100}
      }
    }"#;
    let playback_json = br#"{
      "data": {
        "id":"playback-1",
        "policy":"public",
        "token":"MUX_PLAYBACK_TOKEN",
        "signed_url":"https://stream.mux.com/secret.m3u8?token=secret",
        "object":{"type":"asset","id":"asset-1"},
        "viewer_id":"viewer-77"
      }
    }"#;
    let asset_response = MuxJsonResponse::from_bytes(&asset_request, 200, asset_json, None)
        .expect("asset JSON projection");
    let playback_response =
        MuxJsonResponse::from_bytes(&playback_request, 200, playback_json, None)
            .expect("playback JSON projection");
    let recording = RecordingMuxTransport::fixture([asset_response, playback_response]);
    let mut provider = MuxProvider::new(scoped.clone(), recording).expect("provider");
    let mut consumer = MissionMuxMediaConsumer::new(scoped.clone()).expect("consumer");
    let result = consumer
        .read(&mut provider, &request, NOW)
        .expect("recorded read");
    let serialized = serde_json::to_string(&result).expect("result JSON");
    for forbidden in [
        "MUX_TOKEN_SECRET",
        "MUX_PLAYBACK_TOKEN",
        "https://stream.mux.com",
        "https://origin.example",
        "https://storage.example",
        "https://image.mux.com",
        "AAECAwQ=",
        "person@example.com",
        "viewer-77",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "retained forbidden value: {forbidden}"
        );
    }
    assert_eq!(result.evidence.asset.duration_ms, Some(2_500));
    assert_eq!(
        result.evidence.asset.dimensions.expect("dimensions").width,
        1280
    );
    assert_eq!(result.evidence.receipts.len(), 2);
    assert!(provider.transport().requests().iter().all(|request| {
        request.method == "GET"
            && request.max_response_bytes <= hartevo_mux_media_result_plugin::MUX_MAX_RESPONSE_BYTES
    }));
}

#[test]
fn bounded_asset_list_uses_opaque_cursor_digest_and_exact_asset_filter() {
    let scoped = scope();
    let cursor = MuxCursor::new("provider-cursor-value").expect("cursor");
    let read_request = request(&scoped).with_page(2).with_cursor(cursor);
    let list_response = MuxHttpResponse::from_body(
        200,
        MuxResponseBody::AssetList {
            assets: vec![asset_payload(&scoped, "ready")],
            next_cursor_digest: None,
        },
        None,
    );
    let recording = RecordingMuxTransport::fixture([
        list_response,
        typed_responses(&scoped, "ready")[1].clone(),
    ]);
    let mut provider = MuxProvider::new(scoped.clone(), recording).expect("provider");
    let mut consumer = MissionMuxMediaConsumer::new(scoped.clone()).expect("consumer");
    let result = consumer
        .read(&mut provider, &read_request, NOW)
        .expect("bounded list read");
    assert_eq!(result.evidence.asset.state, MuxAssetState::Ready);
    let requests = provider.transport().requests();
    assert!(matches!(
        requests.first().expect("list request").endpoint,
        MuxEndpoint::AssetListMetadata {
            page: 2,
            limit: 25,
            ..
        }
    ));
    let path = requests
        .first()
        .expect("list request")
        .endpoint
        .path_and_query();
    assert!(!path.contains("provider-cursor-value"));
    assert!(path.contains("cursor_digest="));
}

#[test]
fn status_normalization_covers_provider_states_and_unknowns() {
    for (status, expected) in [
        ("preparing", MuxAssetState::Preparing),
        ("ready", MuxAssetState::Ready),
        ("errored", MuxAssetState::Errored),
        ("archived", MuxAssetState::Archived),
        ("partial", MuxAssetState::Partial),
        ("provider-new-state", MuxAssetState::ProviderUnknown),
    ] {
        let scoped = scope();
        let mut provider = MuxProvider::new(
            scoped.clone(),
            FixtureMuxTransport::new(typed_responses(&scoped, status)),
        )
        .expect("provider");
        let mut consumer = MissionMuxMediaConsumer::new(scoped.clone()).expect("consumer");
        let result = consumer
            .read(&mut provider, &request(&scoped), NOW)
            .expect("state read");
        assert_eq!(result.evidence.asset.state, expected, "status {status}");
    }
}

#[test]
fn blocked_env_is_explicitly_non_connected_and_does_not_fabricate_evidence() {
    let scoped = scope();
    let mut provider =
        MuxProvider::new(scoped.clone(), BlockedEnvMuxTransport::new()).expect("provider");
    let error = provider
        .read(&request(&scoped), NOW)
        .expect_err("native gap");
    assert_eq!(error, MuxError::BlockedEnv);
    assert_eq!(
        provider.provenance(),
        hartevo_mux_media_result_plugin::ProviderProvenance::BlockedEnv
    );
    let service = MuxMediaResultService::new(scoped).expect("service");
    assert!(!service.describe_capabilities().connected);
    assert!(!service.describe_capabilities().native);
}

#[test]
fn access_lost_is_normalized_without_claiming_playback_or_authorization() {
    let scoped = scope();
    let mut provider = MuxProvider::new(
        scoped.clone(),
        FixtureMuxTransport::new([MuxHttpResponse::empty(403, None)]),
    )
    .expect("provider");
    let mut consumer = MissionMuxMediaConsumer::new(scoped.clone()).expect("consumer");
    let result = consumer
        .read(&mut provider, &request(&scoped), NOW)
        .expect("access-lost projection");
    assert_eq!(result.evidence.asset.state, MuxAssetState::AccessLost);
    assert_eq!(result.evidence.delivery.state, MuxAssetState::AccessLost);
    assert!(!result.evidence.delivery.authorization_proven);
    assert!(!result.evidence.delivery.playback_success_proven);
}

#[test]
fn retries_are_bounded_and_receipt_attempts_are_deterministic() {
    let scoped = scope();
    let responses = [
        MuxHttpResponse::empty(429, Some(1)),
        typed_responses(&scoped, "ready")[0].clone(),
        typed_responses(&scoped, "ready")[1].clone(),
    ];
    let recording = RecordingMuxTransport::fixture(responses);
    let mut provider = MuxProvider::with_options(
        scoped.clone(),
        recording,
        MuxReadBounds::default(),
        MuxRetryPolicy::new(3, 5).expect("retry policy"),
    )
    .expect("provider");
    let mut consumer = MissionMuxMediaConsumer::new(scoped.clone()).expect("consumer");
    let result = consumer
        .read(&mut provider, &request(&scoped), NOW)
        .expect("retry read");
    assert_eq!(result.evidence.receipts[0].attempts, 2);
    assert_eq!(result.evidence.receipts[0].response_status, 200);
}

#[test]
fn scope_registration_revision_drift_revoke_and_duplicate_fences_fail_closed() {
    let scoped = scope();
    let registration = MuxRegistration::new(&scoped);
    registration
        .validate_against(&scoped)
        .expect("registration");
    assert!(registration.registration_digest().is_sha256());

    let mut service = MuxMediaResultService::new(scoped.clone()).expect("service");
    let proposal = service
        .compile_media_result_proposal(&request(&scoped))
        .expect("proposal");
    proposal.verify_integrity().expect("proposal integrity");
    service.revoke_registration().expect("revoke");
    assert_eq!(
        service
            .compile_media_result_proposal(&request(&scoped))
            .expect_err("revoked service"),
        MuxError::RegistrationRevoked
    );

    let changed = MuxScope::new(MuxScopeInput {
        environment: MuxEnvironment::new("mux-env-1", 3).expect("environment"),
        asset: AssetScope::new("asset-1", 3).expect("asset"),
        playback: scoped.playback().cloned(),
        track: scoped.track().cloned(),
        static_rendition: scoped.static_rendition().cloned(),
        encoding: scoped.encoding().clone(),
        project: scoped.project().clone(),
        mission: scoped.mission().clone(),
        work_product: scoped.work_product().clone(),
        consent: scoped.consent().clone(),
        secret: scoped.secret().clone(),
    })
    .expect("changed scope");
    let mut changed_consumer = MissionMuxMediaConsumer::new(changed).expect("changed consumer");
    let mut provider = MuxProvider::new(
        scoped.clone(),
        FixtureMuxTransport::new(typed_responses(&scoped, "ready")),
    )
    .expect("provider");
    let error = changed_consumer
        .read(&mut provider, &request(&scoped), NOW)
        .expect_err("scope drift");
    assert!(matches!(error, MuxError::ScopeMismatch(_)));

    let mut consumer = MissionMuxMediaConsumer::new(scoped.clone()).expect("consumer");
    let result = consumer
        .read(&mut provider, &request(&scoped), NOW)
        .expect("result");
    let mut tampered = result.evidence.clone();
    tampered.delivery.readiness_label = "tampered".to_owned();
    assert_eq!(
        tampered.verify_integrity().expect_err("tampered evidence"),
        MuxError::EvidenceTampered
    );
    let mut drifted_provider = MuxProvider::new(
        scoped.clone(),
        FixtureMuxTransport::new(typed_responses(&scoped, "preparing")),
    )
    .expect("drifted provider");
    let mut drifted_consumer = MissionMuxMediaConsumer::new(scoped.clone()).expect("consumer");
    let drift_request = request(&scoped)
        .with_expected_asset_digest(result.evidence.asset.asset_snapshot_digest.clone());
    assert_eq!(
        drifted_consumer
            .read(&mut drifted_provider, &drift_request, NOW)
            .expect_err("asset snapshot drift"),
        MuxError::AssetRevisionDrift
    );
    let duplicate = consumer
        .consume(result.proposal.clone(), result.evidence.clone())
        .expect_err("duplicate evidence");
    assert_eq!(duplicate, MuxError::DuplicateEvidence);
    result
        .evidence
        .verify_integrity()
        .expect("original evidence");
}

#[test]
fn bounds_reject_oversized_cursor_response_and_custom_limits() {
    let oversized = "x".repeat(hartevo_mux_media_result_plugin::MUX_MAX_CURSOR_BYTES + 1);
    assert_eq!(
        MuxCursor::new(oversized).expect_err("cursor bound"),
        MuxError::InvalidField {
            field: "mux_cursor",
            reason: "must be bounded, non-empty, and free of control characters",
        }
    );
    assert!(
        MuxReadBounds::new(
            hartevo_mux_media_result_plugin::MUX_MAX_RESPONSE_BYTES + 1,
            1,
            1,
            1,
            1,
        )
        .is_err()
    );
    let scoped = scope();
    let invalid = request(&scoped).with_max_response_bytes(0);
    let service = MuxMediaResultService::new(scoped).expect("service");
    assert_eq!(
        service
            .compile_media_result_proposal(&invalid)
            .expect_err("response bound"),
        MuxError::ResponseLimitExceeded
    );
}

#[test]
fn no_mutating_api_or_raw_media_operation_is_exposed_in_contract() {
    let json = serde_json::from_str::<serde_json::Value>(
        hartevo_mux_media_result_plugin::MUX_MEDIA_RESULT_CONTRACT_JSON,
    )
    .expect("contract JSON");
    let operations = json
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .expect("operations");
    let operations = operations
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    assert!(operations.iter().all(|operation| {
        !operation.contains("upload")
            && !operation.contains("delete")
            && !operation.contains("update")
            && !operation.contains("download")
            && !operation.contains("token")
            && !operation.contains("webhook")
    }));
    let forbidden = json
        .get("forbidden")
        .and_then(serde_json::Value::as_array)
        .expect("forbidden");
    assert!(forbidden.iter().any(|value| value == "jwt_generation"));
    assert!(
        forbidden
            .iter()
            .any(|value| value == "media_or_rendition_download")
    );
}
