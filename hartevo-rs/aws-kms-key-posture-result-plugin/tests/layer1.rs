use hartevo_aws_kms_key_posture_result_plugin::{
    AwsAccountId, AwsKmsKeyPostureService, AwsKmsScope, AwsRegion, ConsistencyState,
    DeploymentBinding, DeploymentId, DescribeKeyResponse, Digest, KmsAliasSummary, KmsGrantSummary,
    KmsKeyMetadata, KmsKeyMetadataInput, KmsKeyOrigin, KmsKeyReference, KmsKeySpec, KmsKeyState,
    KmsKeySummary, KmsKeyUsage, KmsReadBounds, ListAliasesPage, ListGrantsPage, ListKeysPage,
    ListKeysRequest, MissionAwsKmsConsumer, MissionBinding, MissionId, PermissionFence,
    ProjectBinding, ProjectId, ProviderProvenance, RecordingAwsKmsTransport, Revision,
    RotationStatus, RotationStatusResponse, SecretReference, ServiceError, TransportError,
    TransportFailure, WorkProductBinding, WorkProductId,
};

type Service = AwsKmsKeyPostureService<RecordingAwsKmsTransport>;

struct Fixture {
    service: Service,
    scope: AwsKmsScope,
    key: KmsKeyReference,
    permission: PermissionFence,
}

fn fixture_transport() -> RecordingAwsKmsTransport {
    RecordingAwsKmsTransport::new()
}

fn fixture() -> Fixture {
    let account = AwsAccountId::new("123456789012").expect("account");
    let region = AwsRegion::new("us-east-1").expect("region");
    let key = KmsKeyReference::new(
        hartevo_aws_kms_key_posture_result_plugin::KmsKeyId::new(
            "11111111-1111-1111-1111-111111111111",
        )
        .expect("key id"),
        Some(
            hartevo_aws_kms_key_posture_result_plugin::KmsKeyArn::new(
                "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111",
            )
            .expect("key ARN"),
        ),
    )
    .expect("key reference");
    let permission =
        PermissionFence::readonly("kms-key-posture-read", Revision::new(3).expect("revision"))
            .expect("permission");
    let scope = AwsKmsScope::new(
        account,
        region.clone(),
        Some(vec![key.clone()]),
        DeploymentBinding::new(
            DeploymentId::new("deployment-1").expect("deployment"),
            Revision::new(4).expect("revision"),
        ),
        MissionBinding::new(
            MissionId::new("mission-1").expect("mission"),
            Revision::new(5).expect("revision"),
        ),
        ProjectBinding::new(
            ProjectId::new("project-1").expect("project"),
            Revision::new(6).expect("revision"),
        ),
        WorkProductBinding::new(
            WorkProductId::new("work-product-1").expect("work product"),
            Revision::new(7).expect("revision"),
        ),
        permission.permission_digest.clone(),
    )
    .expect("scope");
    let secret = SecretReference::new(
        "sigv4-keyring-reference",
        region,
        scope.scope_digest.clone(),
        Revision::new(1).expect("secret revision"),
    )
    .expect("secret reference");
    let service = Service::new(
        scope.clone(),
        secret,
        permission.clone(),
        AwsKmsProvider::new(fixture_transport()),
    )
    .expect("service");
    Fixture {
        service,
        scope,
        key,
        permission,
    }
}

fn push_complete_posture(fixture: &mut Fixture, state: KmsKeyState) {
    let scope_digest = fixture.scope.scope_digest.clone();
    let permission_digest = fixture.permission.permission_digest.clone();
    let key = fixture.key.clone();
    let key_digest = key.digest();
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_list_keys(Ok(ListKeysPage::new(
            scope_digest.clone(),
            permission_digest.clone(),
            vec![KmsKeySummary::from_key(&key)],
            None,
            256,
        )));
    let metadata = KmsKeyMetadata::from_input(KmsKeyMetadataInput {
        key: key.clone(),
        state,
        spec: KmsKeySpec::SymmetricDefault,
        usage: KmsKeyUsage::EncryptDecrypt,
        origin: KmsKeyOrigin::AwsKms,
        multi_region: false,
        creation_date: None,
        deletion_date: None,
        consistency: ConsistencyState::Stable,
    });
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_describe_key(Ok(DescribeKeyResponse::new(
            scope_digest.clone(),
            permission_digest.clone(),
            key_digest.clone(),
            metadata,
            512,
        )));
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_rotation_status(Ok(RotationStatusResponse::new(
            scope_digest.clone(),
            permission_digest.clone(),
            key_digest.clone(),
            RotationStatus {
                enabled: true,
                period_days: Some(365),
                next_rotation_date: None,
                consistency: ConsistencyState::Stable,
            },
            256,
        )));
    let alias =
        KmsAliasSummary::from_provider_fields("alias/hartevo-test", key.key_id()).expect("alias");
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_list_aliases(Ok(ListAliasesPage::new(
            scope_digest.clone(),
            permission_digest.clone(),
            key_digest.clone(),
            vec![alias],
            None,
            256,
        )));
    let grant = KmsGrantSummary::from_provider_fields(
        "grant-1",
        "arn:aws:iam::123456789012:role/example",
        Some("arn:aws:iam::123456789012:role/retirer"),
        ["Encrypt", "Decrypt"],
        Some("encryptionContextEquals"),
    )
    .expect("grant");
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_list_grants(Ok(ListGrantsPage::new(
            scope_digest,
            permission_digest,
            key_digest,
            vec![grant],
            None,
            384,
        )));
}

use hartevo_aws_kms_key_posture_result_plugin::AwsKmsProvider;

#[test]
fn complete_posture_is_redacted_and_mission_consumable_but_not_authoritative() {
    let mut fixture = fixture();
    push_complete_posture(&mut fixture, KmsKeyState::Enabled);
    let result = fixture
        .service
        .read_key_posture(fixture.key.clone())
        .expect("posture result");
    assert_eq!(
        result.evidence.status,
        hartevo_aws_kms_key_posture_result_plugin::EvidenceStatus::Complete
    );
    assert_eq!(result.evidence.key.state, KmsKeyState::Enabled);
    assert_eq!(result.evidence.key.alias_count, 1);
    assert_eq!(result.evidence.key.grant_count, 1);
    assert_eq!(result.evidence.key.rotation_period_days, Some(365));
    assert_ne!(result.evidence.key.key_id_digest, Digest::zero());
    assert_ne!(result.evidence.key.key_arn_digest, None);
    assert!(
        result
            .evidence
            .receipts
            .iter()
            .all(|receipt| receipt.attempts == 1)
    );
    assert!(!result.evidence.redaction.key_material_retained);
    assert!(!result.evidence.redaction.raw_key_policy_json_retained);
    assert!(!result.evidence.redaction.grant_principals_retained);
    assert!(!result.evidence.redaction.raw_tokens_retained);
    assert!(!result.evidence.authority.connected);
    assert!(!result.evidence.authority.native);
    assert!(!result.evidence.authority.first_party);
    assert!(
        !result
            .evidence
            .authority
            .cryptographic_verification_authority
    );
    assert!(!result.evidence.authority.outcome_authority);
    assert_eq!(
        fixture.service.provider().provenance(),
        ProviderProvenance::Recording
    );

    let encoded = serde_json::to_string(&result.evidence).expect("evidence JSON");
    assert!(!encoded.contains("arn:aws:iam"));
    assert!(!encoded.contains("alias/hartevo-test"));
    assert!(!encoded.contains("sigv4-keyring-reference"));
    assert!(
        !format!("{:?}", fixture.service.secret_reference()).contains("sigv4-keyring-reference")
    );

    let consumer = MissionAwsKmsConsumer::new(
        fixture.scope.clone(),
        fixture.service.registration().clone(),
    )
    .expect("consumer");
    let mission_result = consumer.consume(&result.evidence).expect("Mission result");
    assert!(mission_result.requires_human_review);
    assert!(!mission_result.safe_to_promote);
    assert!(!mission_result.connected);
    assert!(!mission_result.native);
    assert!(!mission_result.first_party);
    assert!(!mission_result.certification_claim);
    assert!(!mission_result.adopted_outcome);
    assert!(!mission_result.cryptographic_verification_authority);
}

#[test]
fn registration_and_scope_bind_all_digests_and_lifecycles_are_reversible() {
    let mut fixture = fixture();
    assert!(fixture.scope.verify().is_ok());
    assert_ne!(
        fixture.service.registration().provider_digest,
        Digest::zero()
    );
    assert_ne!(fixture.service.registration().api_digest, Digest::zero());
    assert_ne!(
        fixture.service.registration().permission_digest,
        Digest::zero()
    );
    assert_ne!(fixture.service.registration().scope_digest, Digest::zero());
    assert_ne!(
        fixture.service.registration().key_scope_digest,
        Digest::zero()
    );
    assert_ne!(
        fixture.service.registration().evidence_digest,
        Digest::zero()
    );
    assert!(fixture.service.registration().reversible);
    assert!(fixture.service.registration().revocable);
    fixture
        .service
        .reverse_registration()
        .expect("reverse registration");
    assert_eq!(
        fixture.service.registration().state,
        hartevo_aws_kms_key_posture_result_plugin::RegistrationState::Reversed
    );
    assert!(matches!(
        fixture.service.propose_list_keys(),
        Err(ServiceError::RegistrationRevoked)
    ));
}

#[test]
fn secret_and_marker_debug_never_expose_raw_material() {
    let fixture = fixture();
    let marker =
        hartevo_aws_kms_key_posture_result_plugin::OpaqueMarker::new("provider-marker-secret")
            .expect("marker");
    assert!(!format!("{marker:?}").contains("provider-marker-secret"));
    assert!(!format!("{:?}", fixture.key).contains("11111111-1111-1111-1111-111111111111"));
    let scope_json = serde_json::to_string(&fixture.scope).expect("scope JSON");
    assert!(!scope_json.contains("11111111-1111-1111-1111-111111111111"));
}

#[test]
fn provider_rejects_marker_loops_scope_drift_and_incomplete_pages() {
    let fixture = fixture();
    let mut provider = AwsKmsProvider::new(RecordingAwsKmsTransport::new());
    let request = ListKeysRequest::new(&fixture.scope, &KmsReadBounds::default()).expect("request");
    let marker = hartevo_aws_kms_key_posture_result_plugin::OpaqueMarker::new("loop-marker")
        .expect("marker");
    provider
        .transport_mut()
        .push_list_keys(Ok(ListKeysPage::new(
            fixture.scope.scope_digest.clone(),
            fixture.permission.permission_digest.clone(),
            Vec::new(),
            Some(marker.clone()),
            128,
        )));
    provider
        .transport_mut()
        .push_list_keys(Ok(ListKeysPage::new(
            fixture.scope.scope_digest.clone(),
            fixture.permission.permission_digest.clone(),
            Vec::new(),
            Some(marker),
            128,
        )));
    assert!(matches!(
        provider.list_keys(request.clone()),
        Err(hartevo_aws_kms_key_posture_result_plugin::AwsKmsProviderError::MarkerLoop)
    ));

    let mut drifted = AwsKmsProvider::new(RecordingAwsKmsTransport::new());
    drifted.transport_mut().push_list_keys(Ok(ListKeysPage::new(
        Digest::from_text("scope-drift"),
        fixture.permission.permission_digest.clone(),
        Vec::new(),
        None,
        128,
    )));
    assert!(matches!(
        drifted.list_keys(request),
        Err(hartevo_aws_kms_key_posture_result_plugin::AwsKmsProviderError::ScopeDrift)
    ));
}

#[test]
fn unsafe_states_eventual_consistency_and_access_fail_closed() {
    let mut disabled = fixture();
    push_complete_posture(&mut disabled, KmsKeyState::Disabled);
    assert!(matches!(
        disabled.service.read_key_posture(disabled.key),
        Err(ServiceError::UnsafeKeyState)
    ));

    let mut eventual = fixture();
    push_complete_posture(&mut eventual, KmsKeyState::Enabled);
    eventual
        .service
        .provider_mut()
        .transport_mut()
        .push_list_keys(Err(TransportError::eventual_consistency()));
    let mut blocked = fixture();
    blocked
        .service
        .provider_mut()
        .transport_mut()
        .push_list_keys(Err(TransportError::from_status(403)));
    assert!(matches!(
        blocked.service.read_key_posture(blocked.key),
        Err(ServiceError::PermissionLoss)
    ));

    let mut provider = AwsKmsProvider::new(RecordingAwsKmsTransport::new());
    let request =
        ListKeysRequest::new(&eventual.scope, &KmsReadBounds::default()).expect("request");
    provider
        .transport_mut()
        .push_list_keys(Err(TransportError::eventual_consistency()));
    assert!(matches!(
        provider.list_keys(request),
        Err(
            hartevo_aws_kms_key_posture_result_plugin::AwsKmsProviderError::Transport(
                TransportError {
                    failure: TransportFailure::EventualConsistency,
                    ..
                }
            )
        )
    ));
}

#[test]
fn specified_http_and_timeout_failures_are_never_retried_or_promoted() {
    let fixture = fixture();
    let failures = [
        TransportFailure::BadRequest,
        TransportFailure::Unauthorized,
        TransportFailure::AccessDenied,
        TransportFailure::NotFound,
        TransportFailure::Throttled,
        TransportFailure::Server,
        TransportFailure::Timeout,
    ];
    for failure in failures {
        let mut provider = AwsKmsProvider::new(RecordingAwsKmsTransport::new());
        provider
            .transport_mut()
            .push_list_keys(Err(TransportError::new(failure)));
        let request =
            ListKeysRequest::new(&fixture.scope, &KmsReadBounds::default()).expect("request");
        let error = provider.list_keys(request).expect_err("failure must close");
        assert!(matches!(
            error,
            hartevo_aws_kms_key_posture_result_plugin::AwsKmsProviderError::Transport(
                TransportError { failure: observed, .. }
            ) if observed == failure
        ));
        assert_eq!(provider.transport().calls().len(), 1);
    }
}

#[test]
fn tamper_and_replay_are_rejected() {
    let mut fixture = fixture();
    push_complete_posture(&mut fixture, KmsKeyState::Enabled);
    let proposal = fixture
        .service
        .propose_key_posture(fixture.key.clone())
        .expect("proposal");
    let envelope = fixture.service.record(&proposal).expect("record");
    let mut tampered = match envelope {
        hartevo_aws_kms_key_posture_result_plugin::AwsKmsReadRecordEnvelope::KeyPosture(record) => {
            *record
        }
        hartevo_aws_kms_key_posture_result_plugin::AwsKmsReadRecordEnvelope::Single(_) => {
            panic!("posture record")
        }
    };
    tampered.key_digest = Digest::from_text("tamper");
    assert!(matches!(
        fixture.service.verify_key_posture(
            &proposal,
            &hartevo_aws_kms_key_posture_result_plugin::AwsKmsReadRecordEnvelope::KeyPosture(
                Box::new(tampered),
            )
        ),
        Err(ServiceError::RequestDrift | ServiceError::TamperedEvidence)
    ));
    assert!(matches!(
        fixture.service.record(&proposal),
        Err(ServiceError::Replay)
    ));
}

#[test]
fn all_transport_provenances_are_explicitly_disconnected_non_native_and_non_first_party() {
    assert!(!ProviderProvenance::Fixture.connected());
    assert!(!ProviderProvenance::Fixture.native());
    assert!(!ProviderProvenance::Fixture.first_party());
    assert!(!ProviderProvenance::Recording.connected());
    assert!(!ProviderProvenance::Loopback.native());
    assert!(!ProviderProvenance::BlockedEnv.first_party());
}
