use hartevo_figma_design_plugin::{
    AdapterId, AdoptionReason, AdoptionRequest, BlockedEnvTransport, ExportFormat, ExportRequest,
    ExportScale, FIGMA_ADAPTER_ID, FIGMA_PROVIDER_ID, FIGMA_PROVIDER_VERSION, FigmaAuthMethod,
    FigmaDesignProvider, FigmaDesignRegistration, FigmaDesignService, FigmaEvidenceClass,
    FigmaFileMetadata, FigmaHttpsEndpoint, FigmaHttpsTransport, FigmaNodeKind, FigmaNodeMetadata,
    FigmaProjectId, FigmaProviderAvailability, FigmaProviderError, FigmaProviderMode,
    FigmaRegistrationBinding, FigmaScope, FigmaServiceError, FigmaTimestamp, FigmaTransportCall,
    FigmaTransportError, FigmaTransportErrorKind, FigmaVersion, FileKey,
    MissionDesignResultConsumer, MissionDesignSource, MissionId, NodeId, ProjectId,
    ProviderVersion, RecordingFigmaTransport, SecretReference, Sha256Digest, TeamId, TenantId,
    VersionId,
};

fn fixture_scope() -> FigmaScope {
    FigmaScope::new(
        TenantId::new("tenant-308").expect("tenant"),
        ProjectId::new("project-308").expect("project"),
        MissionId::new("mission-308").expect("mission"),
        TeamId::new("team-308").expect("team"),
        FigmaProjectId::new("figma-project-308").expect("Figma project"),
        FileKey::new("file-308").expect("file"),
        [
            NodeId::new("1:1").expect("node"),
            NodeId::new("1:2").expect("node"),
        ],
        VersionId::new("version-308").expect("version"),
    )
    .expect("scope")
}

fn fixture_parts(
    mode: FigmaProviderMode,
) -> (
    FigmaScope,
    hartevo_figma_design_plugin::FigmaDesignRegistration,
    RecordingFigmaTransport,
    Vec<ExportRequest>,
) {
    let scope = fixture_scope();
    let file = hartevo_figma_design_plugin::fixture_file_metadata(&scope);
    let versions = vec![
        FigmaVersion::new(
            VersionId::new("version-1").expect("version"),
            FigmaTimestamp::new("2026-08-12T00:00:00Z").expect("time"),
            hartevo_figma_design_plugin::RedactedText::new("first").expect("label"),
            hartevo_figma_design_plugin::RedactedText::new("designer-a").expect("user"),
        ),
        FigmaVersion::new(
            VersionId::new("version-2").expect("version"),
            FigmaTimestamp::new("2026-08-13T00:00:00Z").expect("time"),
            hartevo_figma_design_plugin::RedactedText::new("second").expect("label"),
            hartevo_figma_design_plugin::RedactedText::new("designer-b").expect("user"),
        ),
        FigmaVersion::new(
            VersionId::new("version-3").expect("version"),
            FigmaTimestamp::new("2026-08-14T00:00:00Z").expect("time"),
            hartevo_figma_design_plugin::RedactedText::new("third").expect("label"),
            hartevo_figma_design_plugin::RedactedText::new("designer-c").expect("user"),
        ),
    ];
    let nodes = scope
        .node_ids()
        .iter()
        .map(|node_id| {
            FigmaNodeMetadata::new(
                node_id.clone(),
                scope.version_id().clone(),
                FigmaNodeKind::Frame,
                hartevo_figma_design_plugin::RedactedText::new(format!(
                    "node {}",
                    node_id.as_str()
                ))
                .expect("node name"),
            )
        })
        .collect::<Vec<_>>();
    let requests = vec![
        ExportRequest::new(
            scope.file_key().clone(),
            scope.version_id().clone(),
            NodeId::new("1:1").expect("node"),
            ExportFormat::Png,
            ExportScale::new(100).expect("scale"),
            1_024,
        )
        .expect("export request"),
        ExportRequest::new(
            scope.file_key().clone(),
            scope.version_id().clone(),
            NodeId::new("1:2").expect("node"),
            ExportFormat::Svg,
            ExportScale::new(200).expect("scale"),
            1_024,
        )
        .expect("export request"),
    ];
    let exports = vec![
        hartevo_figma_design_plugin::FigmaExportPayload::from_bytes(
            &requests[0],
            b"fixture-png-bytes".to_vec(),
        )
        .expect("PNG payload"),
        hartevo_figma_design_plugin::FigmaExportPayload::from_bytes(
            &requests[1],
            b"<svg>fixture</svg>".to_vec(),
        )
        .expect("SVG payload"),
    ];
    let transport =
        RecordingFigmaTransport::new(mode, file, versions, nodes, exports).expect("transport");
    let registration = hartevo_figma_design_plugin::figma_registration(
        scope.clone(),
        "registration-308",
        Sha256Digest::from_text("implementation-308"),
    )
    .expect("registration");
    (scope, registration, transport, requests)
}

fn service(
    mode: FigmaProviderMode,
) -> (
    FigmaScope,
    hartevo_figma_design_plugin::FigmaDesignRegistration,
    FigmaDesignService<RecordingFigmaTransport>,
    Vec<ExportRequest>,
) {
    let (scope, registration, transport, requests) = fixture_parts(mode);
    let secret = SecretReference::new("secret-ref-308", &scope, 1).expect("secret");
    let provider = FigmaDesignProvider::new(
        transport,
        registration.clone(),
        secret,
        FigmaAuthMethod::OAuth,
    )
    .expect("provider");
    (
        scope,
        registration,
        FigmaDesignService::new(provider),
        requests,
    )
}

#[test]
fn fixture_service_binds_file_version_nodes_exports_and_revision_proposal() {
    let (scope, registration, mut service, requests) = service(FigmaProviderMode::Fixture);
    let file = service.inspect_file().expect("file metadata");
    assert_eq!(file.value.file_key(), scope.file_key());
    assert_eq!(file.value.version_id(), scope.version_id());
    assert_eq!(
        file.value.version_timestamp().as_str(),
        "2026-08-14T00:00:00Z"
    );

    let versions = service
        .list_versions(hartevo_figma_design_plugin::VersionListPlan::new(2, 2).expect("plan"))
        .expect("version history");
    assert_eq!(versions.value.len(), 3);
    assert_eq!(
        versions.value[2].created_at().as_str(),
        "2026-08-14T00:00:00Z"
    );

    let nodes = service.inspect_nodes().expect("nodes");
    assert_eq!(nodes.value.len(), 2);
    assert_eq!(nodes.value[0].version_id(), scope.version_id());

    let source = MissionDesignSource::new(
        scope.mission_id().clone(),
        7,
        Sha256Digest::from_text("mission-result-revision-7"),
    )
    .expect("source");
    let result = service
        .collect_design_result(source, &requests)
        .expect("design result");
    assert_eq!(result.value.node_ids(), scope.node_ids());
    assert_eq!(result.value.exports().len(), 2);
    assert_eq!(
        result.value.provider_version().as_str(),
        FIGMA_PROVIDER_VERSION
    );
    assert_eq!(
        result.value.registration_digest(),
        registration.record_digest()
    );
    assert!(!result.value.connected());
    assert!(!result.value.native());

    let consumer = MissionDesignResultConsumer::new(registration).expect("consumer");
    let request = AdoptionRequest::for_result(
        hartevo_figma_design_plugin::ProposalId::new("proposal-308").expect("proposal"),
        result.value.clone(),
        FigmaTimestamp::new("2026-08-14T00:01:00Z").expect("time"),
        AdoptionReason::UiChange,
    )
    .expect("adoption request");
    let proposal = service
        .propose_adoption(&consumer, &request)
        .expect("adoption proposal");
    assert_eq!(proposal.value.version_id(), scope.version_id());
    assert_eq!(proposal.value.source_result_revision(), 7);
    assert_eq!(
        proposal.value.source_result_revision_digest(),
        result.value.source().result_revision_digest()
    );
    assert_eq!(
        proposal.value.status(),
        hartevo_figma_design_plugin::ProposalStatus::Proposed
    );
    assert!(!proposal.value.connected());
    assert!(!proposal.value.native());
    assert!(!proposal.value.is_adopted());

    let receipt_json = serde_json::to_string(&result.receipt).expect("receipt JSON");
    assert!(!receipt_json.contains("fixture-png-bytes"));
    assert!(!receipt_json.contains("node 1:1"));
    assert!(receipt_json.contains("receipt-"));
    assert_eq!(
        service
            .provider()
            .transport()
            .calls()
            .iter()
            .filter(|call| matches!(call, FigmaTransportCall::BoundedExport { .. }))
            .count(),
        2
    );
}

#[test]
fn adoption_proposal_refuses_a_stale_mission_result_revision() {
    let (scope, registration, mut service, requests) = service(FigmaProviderMode::Fixture);
    let source = MissionDesignSource::new(
        scope.mission_id().clone(),
        11,
        Sha256Digest::from_text("mission-result-revision-11"),
    )
    .expect("source");
    let result = service
        .collect_design_result(source, &requests)
        .expect("design result")
        .value;
    let consumer = MissionDesignResultConsumer::new(registration).expect("result consumer");
    let stale_fence = MissionDesignSource::new(
        scope.mission_id().clone(),
        12,
        Sha256Digest::from_text("mission-result-revision-12"),
    )
    .expect("stale fence");
    let request = AdoptionRequest::new(
        hartevo_figma_design_plugin::ProposalId::new("proposal-stale").expect("proposal"),
        result.clone(),
        stale_fence,
        result.node_ids().clone(),
        result.export_digests().clone(),
        FigmaTimestamp::new("2026-08-14T00:02:00Z").expect("time"),
        AdoptionReason::DesignBrief,
    )
    .expect("request");
    assert!(matches!(
        service.propose_adoption(&consumer, &request),
        Err(FigmaServiceError::Adoption(
            hartevo_figma_design_plugin::AdoptionError::StaleRevision
        ))
    ));
}

#[test]
fn exact_bytes_digest_fence_rejects_tampered_export_payload() {
    let (scope, registration, _transport, requests) = fixture_parts(FigmaProviderMode::Fixture);
    let valid = hartevo_figma_design_plugin::FigmaExportPayload::from_bytes(
        &requests[0],
        b"provider-bytes".to_vec(),
    )
    .expect("valid payload");
    let tampered = hartevo_figma_design_plugin::FigmaExportPayload::from_parts(
        valid.metadata().clone(),
        b"tampered-bytes".to_vec(),
    );
    let transport = RecordingFigmaTransport::new(
        FigmaProviderMode::Fixture,
        FigmaFileMetadata::new(
            scope.file_key().clone(),
            scope.version_id().clone(),
            FigmaTimestamp::new("2026-08-14T00:00:00Z").expect("time"),
            FigmaTimestamp::new("2026-08-14T00:00:00Z").expect("time"),
            hartevo_figma_design_plugin::RedactedText::new("fixture").expect("name"),
            &scope,
        ),
        Vec::new(),
        Vec::new(),
        vec![tampered],
    )
    .expect("tampered transport");
    let secret = SecretReference::new("secret-ref-tamper", &scope, 1).expect("secret");
    let provider = FigmaDesignProvider::new(
        transport,
        registration,
        secret,
        FigmaAuthMethod::PersonalAccessToken,
    )
    .expect("provider");
    let mut service = FigmaDesignService::new(provider);
    assert!(matches!(
        service.record_bounded_export(&requests[0]),
        Err(FigmaServiceError::Provider(FigmaProviderError::ExportFence))
    ));
}

#[test]
fn stale_version_and_scope_loss_are_explicit_fail_closed_errors() {
    let (scope, registration, _transport, _requests) = fixture_parts(FigmaProviderMode::Fixture);
    let stale_file = FigmaFileMetadata::new(
        scope.file_key().clone(),
        VersionId::new("version-stale").expect("version"),
        FigmaTimestamp::new("2026-08-14T00:00:00Z").expect("time"),
        FigmaTimestamp::new("2026-08-14T00:00:00Z").expect("time"),
        hartevo_figma_design_plugin::RedactedText::new("stale").expect("name"),
        &scope,
    );
    let transport = RecordingFigmaTransport::new(
        FigmaProviderMode::Fixture,
        stale_file,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("transport");
    let secret = SecretReference::new("secret-ref-stale", &scope, 1).expect("secret");
    let provider =
        FigmaDesignProvider::new(transport, registration, secret, FigmaAuthMethod::OAuth)
            .expect("provider");
    let mut service = FigmaDesignService::new(provider);
    assert!(matches!(
        service.inspect_file(),
        Err(FigmaServiceError::Provider(
            FigmaProviderError::StaleVersion
        ))
    ));

    let (scope, registration, mut transport, _requests) = fixture_parts(FigmaProviderMode::Fixture);
    transport.fail_next(FigmaTransportError::new(FigmaTransportErrorKind::Forbidden));
    let secret = SecretReference::new("secret-ref-forbidden", &scope, 1).expect("secret");
    let mut provider =
        FigmaDesignProvider::new(transport, registration, secret, FigmaAuthMethod::OAuth)
            .expect("provider");
    let error = provider.read_file_metadata().expect_err("forbidden");
    assert!(matches!(
        error,
        FigmaProviderError::Transport {
            kind: FigmaTransportErrorKind::Forbidden,
            attempts: 1
        }
    ));
    assert_eq!(
        error.availability(),
        FigmaProviderAvailability::ProviderUnknown
    );
}

#[test]
fn retry_is_bounded_and_transient_failures_do_not_change_evidence_class() {
    let (scope, registration, mut transport, _requests) =
        fixture_parts(FigmaProviderMode::Loopback);
    transport.fail_next(FigmaTransportError::new(FigmaTransportErrorKind::Timeout));
    transport.fail_next(FigmaTransportError::new(
        FigmaTransportErrorKind::RateLimited,
    ));
    let secret = SecretReference::new("secret-ref-retry", &scope, 1).expect("secret");
    let mut provider =
        FigmaDesignProvider::new(transport, registration, secret, FigmaAuthMethod::OAuth)
            .expect("provider");
    let observation = provider.read_file_metadata().expect("retry succeeds");
    assert_eq!(
        observation.evidence.evidence_class(),
        FigmaEvidenceClass::Loopback
    );
    assert!(!observation.evidence.connected());
    assert!(!observation.evidence.native());
    assert_eq!(provider.transport().calls().len(), 3);

    let (scope, registration, mut transport, _requests) = fixture_parts(FigmaProviderMode::Fixture);
    transport.fail_next(FigmaTransportError::new(FigmaTransportErrorKind::Timeout));
    transport.fail_next(FigmaTransportError::new(FigmaTransportErrorKind::Timeout));
    transport.fail_next(FigmaTransportError::new(FigmaTransportErrorKind::Timeout));
    let secret = SecretReference::new("secret-ref-retry-limit", &scope, 1).expect("secret");
    let mut provider =
        FigmaDesignProvider::new(transport, registration, secret, FigmaAuthMethod::OAuth)
            .expect("provider");
    assert!(matches!(
        provider.read_file_metadata(),
        Err(FigmaProviderError::Transport {
            kind: FigmaTransportErrorKind::Timeout,
            attempts: 3
        })
    ));
}

#[test]
fn fixture_loopback_blocked_env_and_https_seam_never_claim_connected_or_native() {
    for mode in [FigmaProviderMode::Fixture, FigmaProviderMode::Loopback] {
        let (scope, registration, transport, _requests) = fixture_parts(mode);
        let secret = SecretReference::new("secret-ref-mode", &scope, 1).expect("secret");
        let provider =
            FigmaDesignProvider::new(transport, registration, secret, FigmaAuthMethod::OAuth)
                .expect("provider");
        let evidence = provider.evidence();
        assert_eq!(evidence.mode(), mode);
        assert!(!evidence.connected());
        assert!(!evidence.native());
    }

    let (scope, registration, _transport, _requests) = fixture_parts(FigmaProviderMode::Fixture);
    let secret = SecretReference::new("secret-ref-blocked", &scope, 1).expect("secret");
    let mut provider = FigmaDesignProvider::new(
        BlockedEnvTransport,
        registration,
        secret,
        FigmaAuthMethod::PlanAccessToken,
    )
    .expect("blocked provider");
    let error = provider.read_file_metadata().expect_err("BLOCKED_ENV");
    assert!(matches!(
        error,
        FigmaProviderError::Transport {
            kind: FigmaTransportErrorKind::BlockedEnv,
            attempts: 1
        }
    ));
    assert_eq!(error.availability(), FigmaProviderAvailability::BlockedEnv);
    assert!(!provider.evidence().connected());
    assert!(!provider.evidence().native());

    let endpoint = FigmaHttpsEndpoint::new("https://api.figma.com/v1").expect("HTTPS endpoint");
    let transport = FigmaHttpsTransport::new(endpoint, FigmaAuthMethod::PersonalAccessToken)
        .expect("HTTPS seam");
    assert_eq!(transport.endpoint().as_str(), "https://api.figma.com/v1");
    let secret = SecretReference::new("secret-ref-https", &scope, 1).expect("secret");
    let provider = FigmaDesignProvider::new(
        transport,
        fixture_parts(FigmaProviderMode::Fixture).1,
        secret,
        FigmaAuthMethod::PersonalAccessToken,
    );
    assert!(provider.is_ok());
    assert_eq!(
        provider.expect("provider").mode(),
        FigmaProviderMode::BlockedEnv
    );
}

#[test]
fn registration_is_digest_version_scope_bound_and_reversible() {
    let scope = fixture_scope();
    let binding = FigmaRegistrationBinding::new(
        FIGMA_PROVIDER_ID,
        AdapterId::new(FIGMA_ADAPTER_ID).expect("adapter"),
        1,
        ProviderVersion::new(FIGMA_PROVIDER_VERSION).expect("version"),
        Sha256Digest::from_text("implementation"),
        hartevo_figma_design_plugin::FigmaDesignContract::baseline()
            .expect("contract")
            .digest(),
    )
    .expect("binding");
    let mut registration = FigmaDesignRegistration::register(
        hartevo_figma_design_plugin::RegistrationId::new("registration-reversible")
            .expect("registration"),
        binding,
        scope,
    )
    .expect("registration");
    let active_digest = registration.record_digest().clone();
    registration.revoke().expect("revoke");
    assert!(!registration.is_active());
    assert_ne!(registration.record_digest(), &active_digest);
    registration.restore().expect("restore");
    assert!(registration.is_active());
    assert_ne!(registration.record_digest(), &active_digest);
    assert!(registration.validate().is_ok());
}
