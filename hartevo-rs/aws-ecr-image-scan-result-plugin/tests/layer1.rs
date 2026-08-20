use hartevo_aws_ecr_image_scan_result_plugin as ecr;
use serde_json::json;

fn scope() -> ecr::EcrImageScanScope {
    ecr::EcrImageScanScope::new(ecr::EcrImageScanScopeSpec {
        registry: ecr::RegistryId::new("123456789012").expect("registry"),
        account_id: ecr::AccountId::new("123456789012").expect("account"),
        region: ecr::AwsRegion::new("us-east-1").expect("region"),
        repository: ecr::RepositoryName::new("platform/api").expect("repository"),
        image_digest: ecr::ImageDigest::new(format!("sha256:{}", "a".repeat(64)))
            .expect("image digest"),
        scan_type: ecr::ScanType::Basic,
        scan_revision: ecr::Revision::new(7).expect("scan revision"),
        inspector_finding_revision: ecr::Revision::new(11).expect("finding revision"),
        project: ecr::ProjectBinding::new("project-1", 2).expect("project"),
        mission: ecr::MissionBinding::new("mission-1", 3).expect("mission"),
        work_product: ecr::WorkProductBinding::new("work-product-1", 4).expect("work product"),
        permission: ecr::PermissionFence::for_layer_one(5).expect("permission"),
    })
    .expect("scope")
}

fn finding() -> ecr::RedactedFinding {
    ecr::RedactedFinding::from_raw(
        ecr::Severity::High,
        Some("CVE-2026-12345"),
        Some("openssl"),
        Some("3.0.1"),
        Some("3.0.2"),
    )
    .expect("finding")
}

fn service_with(
    lifecycle: ecr::ScanLifecycle,
    scan_revision: ecr::Revision,
    finding_revision: ecr::Revision,
    error: Option<ecr::TransportError>,
) -> ecr::EcrImageScanResultService<ecr::RecordingEcrTransport> {
    let scope = scope();
    let image_request =
        ecr::DescribeImagesRequest::new(&scope, ecr::PAGE_SIZE, ecr::MAX_PAGES, None)
            .expect("image request");
    let findings_request =
        ecr::DescribeImageScanFindingsRequest::new(&scope, ecr::PAGE_SIZE, ecr::MAX_PAGES, None)
            .expect("findings request");
    let mut transport = ecr::RecordingEcrTransport::fixture();
    transport.push_describe_images_response(Ok(ecr::DescribeImagesPage::new(
        &image_request,
        1,
        vec![ecr::EcrImageDescriptor::new(scope.image_digest().clone())],
        None,
        128,
        ecr::AWS_ECR_API_REVISION,
    )
    .expect("image page")));
    if let Some(error) = error {
        transport.push_findings_response(Err(error));
    } else {
        transport.push_findings_response(Ok(ecr::DescribeImageScanFindingsPage::new(
            &findings_request,
            1,
            lifecycle,
            scan_revision,
            finding_revision,
            vec![ecr::SeverityCount::new(ecr::Severity::High, 1)],
            vec![finding()],
            None,
            256,
            ecr::AWS_ECR_API_REVISION,
        )
        .expect("findings page")));
    }
    let secret =
        ecr::SecretReference::for_scope("opaque-sigv4-ref", &scope, 9).expect("secret reference");
    let provider = ecr::EcrProvider::new(transport).expect("provider");
    ecr::EcrImageScanResultService::new(scope.clone(), secret, scope.permission().clone(), provider)
        .expect("service")
}

#[test]
fn contract_and_authority_are_explicit() {
    ecr::EcrImageScanContract::baseline().expect("contract");
    assert!(!ecr::Layer1Authority::connected());
    assert!(!ecr::Layer1Authority::native());
    assert!(!ecr::Layer1Authority::external_writes());
    assert!(!ecr::Layer1Authority::durable_receipt());
    assert!(!ecr::Layer1Authority::independent_readback());
    assert!(!ecr::Layer1Authority::adopted_outcome());
    assert!(!ecr::Layer1Authority::raw_layers());
    assert!(!ecr::Layer1Authority::raw_image_bytes());
    assert!(!ecr::Layer1Authority::remediation());
}

#[test]
fn secret_and_pagination_are_opaque() {
    let scope = scope();
    let secret =
        ecr::SecretReference::for_scope("raw-secret-handle", &scope, 1).expect("secret reference");
    assert!(serde_json::to_string(&secret).is_err());
    assert!(!format!("{secret:?}").contains("raw-secret-handle"));

    let request = ecr::DescribeImagesRequest::new(&scope, ecr::PAGE_SIZE, ecr::MAX_PAGES, None)
        .expect("request");
    let token = ecr::OpaquePageToken::new(
        "raw-provider-next-token",
        request.pagination_binding_digest(),
    )
    .expect("opaque token");
    assert_eq!(
        serde_json::to_string(&token).expect("token JSON"),
        r#"{"opaque":true}"#
    );
    assert!(!format!("{token:?}").contains("raw-provider-next-token"));
    let next = request.with_page_token(token).expect("bound token");
    assert!(
        !serde_json::to_string(&next)
            .expect("request JSON")
            .contains("raw-provider-next-token")
    );
}

#[test]
fn parser_discards_provider_body_tags_paths_urls_layers_and_tokens() {
    let scope = scope();
    let image_request =
        ecr::DescribeImagesRequest::new(&scope, ecr::PAGE_SIZE, ecr::MAX_PAGES, None)
            .expect("image request");
    let image_body = json!({
        "imageDetails": [{
            "registryId": "123456789012",
            "repositoryName": "platform/api",
            "imageDigest": scope.image_digest().as_str(),
            "imageTags": ["production-secret-tag"],
            "imageSizeInBytes": 123_456,
            "rootfs": "raw-layer-bytes"
        }],
        "nextToken": "provider-page-token"
    });
    let page = ecr::EcrProvider::<ecr::RecordingEcrTransport>::parse_describe_images_page(
        &image_request,
        1,
        serde_json::to_vec(&image_body)
            .expect("image body")
            .as_slice(),
    )
    .expect("parsed images");
    let page_json = serde_json::to_string(&page).expect("page JSON");
    for forbidden in [
        "production-secret-tag",
        "raw-layer-bytes",
        "provider-page-token",
    ] {
        assert!(
            !page_json.contains(forbidden),
            "raw value survived: {forbidden}"
        );
    }

    let findings_request =
        ecr::DescribeImageScanFindingsRequest::new(&scope, ecr::PAGE_SIZE, ecr::MAX_PAGES, None)
            .expect("findings request");
    let findings_body = json!({
        "imageScanStatus": {"status": "COMPLETE"},
        "imageScanFindings": {
            "findingSeverityCounts": {"HIGH": 1},
            "findings": [{
                "findingArn": "arn:aws:inspector:secret",
                "severity": "HIGH",
                "uri": "https://private.example/vulnerability",
                "packageVulnerabilityDetails": {
                    "vulnerabilityId": "CVE-2026-12345",
                    "referenceUrls": ["https://private.example/reference"],
                    "vulnerablePackages": [{
                        "name": "openssl",
                        "version": "3.0.1",
                        "fixedInVersion": "3.0.2",
                        "filePath": "/private/path",
                        "sourceLayerHash": "sha256:raw-layer"
                    }]
                },
                "attributes": [{"key": "private", "value": "PII"}]
            }]
        },
        "nextToken": "findings-provider-token"
    });
    let findings_page =
        ecr::EcrProvider::<ecr::RecordingEcrTransport>::parse_describe_image_scan_findings_page(
            &findings_request,
            1,
            serde_json::to_vec(&findings_body)
                .expect("findings body")
                .as_slice(),
        )
        .expect("parsed findings");
    let findings_json = serde_json::to_string(&findings_page).expect("findings JSON");
    for forbidden in [
        "arn:aws:inspector:secret",
        "private.example",
        "CVE-2026-12345",
        "openssl",
        "3.0.1",
        "3.0.2",
        "/private/path",
        "sha256:raw-layer",
        "PII",
        "findings-provider-token",
    ] {
        assert!(
            !findings_json.contains(forbidden),
            "raw value survived: {forbidden}"
        );
    }
    assert!(findings_json.contains("cveDigest"));
}

#[test]
fn parser_handles_enhanced_findings_with_bounded_fix_projection() {
    let scope = scope();
    let request =
        ecr::DescribeImageScanFindingsRequest::new(&scope, ecr::PAGE_SIZE, ecr::MAX_PAGES, None)
            .expect("findings request");
    let body = json!({
        "registryId": "123456789012",
        "repositoryName": "platform/api",
        "imageId": {"imageDigest": scope.image_digest().as_str()},
        "imageScanStatus": {"status": "ACTIVE"},
        "imageScanFindings": {
            "findingSeverityCounts": {"HIGH": 1},
            "enhancedFindings": [{
                "findingArn": "arn:aws:inspector2:private",
                "severity": "HIGH",
                "packageVulnerabilityDetails": {
                    "vulnerabilityId": "CVE-2026-54321",
                    "vulnerablePackages": [{
                        "name": "libxml2",
                        "version": "2.9.14",
                        "fixedInVersion": "NotAvailable",
                        "sourceLayerHash": "sha256:private-layer"
                    }]
                },
                "remediation": {"recommendation": {"url": "https://private.example"}}
            }]
        }
    });
    let page =
        ecr::EcrProvider::<ecr::RecordingEcrTransport>::parse_describe_image_scan_findings_page(
            &request,
            1,
            serde_json::to_vec(&body).expect("enhanced body").as_slice(),
        )
        .expect("parsed enhanced findings");
    assert_eq!(page.findings.len(), 1);
    assert_eq!(page.findings[0].severity, ecr::Severity::High);
    assert_eq!(page.findings[0].fix_status, ecr::FixStatus::NotAvailable);
    assert_ne!(page.findings[0].cve_digest, ecr::Digest::zero());
    let serialized = serde_json::to_string(&page).expect("page JSON");
    for forbidden in [
        "arn:aws:inspector2:private",
        "CVE-2026-54321",
        "libxml2",
        "2.9.14",
        "sha256:private-layer",
        "private.example",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "raw enhanced finding survived: {forbidden}"
        );
    }
}

#[test]
fn complete_proposal_is_digest_fenced_and_mission_consumption_is_non_adopting() {
    let mut service = service_with(
        ecr::ScanLifecycle::Complete,
        ecr::Revision::new(7).expect("revision"),
        ecr::Revision::new(11).expect("revision"),
        None,
    );
    let proposal = service.propose().expect("proposal");
    assert_eq!(proposal.evidence.state, ecr::ScanProjection::Complete);
    assert!(proposal.evidence.findings.len() == 1);
    assert!(!proposal.native && !proposal.connected && !proposal.adopted_outcome);
    let serialized = serde_json::to_string(&proposal).expect("proposal JSON");
    for forbidden in ["CVE-2026-12345", "openssl", "3.0.1", "3.0.2"] {
        assert!(
            !serialized.contains(forbidden),
            "raw finding survived: {forbidden}"
        );
    }
    let second = service.propose().expect("second proposal");
    assert_eq!(
        proposal.evidence.evidence_digest,
        second.evidence.evidence_digest
    );
    assert_eq!(proposal.proposal_digest, second.proposal_digest);

    let mut consumer =
        ecr::MissionEcrImageConsumer::new(scope(), service.registration()).expect("consumer");
    let result = consumer.consume(proposal.clone()).expect("Mission result");
    assert_eq!(result.state, ecr::MissionEcrImageScanState::DecisionReady);
    assert!(result.proposal_only);
    assert!(!result.native && !result.connected && !result.adopted_outcome);
    assert!(matches!(
        consumer.consume(proposal),
        Err(ecr::MissionEcrImageConsumerError::ReplayDetected)
    ));
}

#[test]
fn lifecycle_access_stale_and_provider_unknown_projections_are_typed() {
    let cases = [
        (ecr::ScanLifecycle::Pending, ecr::ScanProjection::Pending),
        (ecr::ScanLifecycle::Failed, ecr::ScanProjection::Failed),
        (ecr::ScanLifecycle::Inactive, ecr::ScanProjection::Inactive),
        (ecr::ScanLifecycle::Expired, ecr::ScanProjection::Expired),
    ];
    for (lifecycle, expected) in cases {
        let mut service = service_with(
            lifecycle,
            ecr::Revision::new(7).expect("revision"),
            ecr::Revision::new(11).expect("revision"),
            None,
        );
        assert_eq!(service.read().expect("evidence").state, expected);
    }
    let mut denied = service_with(
        ecr::ScanLifecycle::Complete,
        ecr::Revision::new(7).expect("revision"),
        ecr::Revision::new(11).expect("revision"),
        Some(ecr::TransportError::Forbidden),
    );
    assert_eq!(
        denied.read().expect("access evidence").state,
        ecr::ScanProjection::AccessLost
    );

    let scope = scope();
    let secret = ecr::SecretReference::for_scope("blocked-ref", &scope, 1).expect("secret");
    let provider = ecr::EcrProvider::new(ecr::BlockedEnvEcrTransport).expect("provider");
    let mut blocked = ecr::EcrImageScanResultService::new(
        scope.clone(),
        secret,
        scope.permission().clone(),
        provider,
    )
    .expect("blocked service");
    assert_eq!(
        blocked.read().expect("blocked evidence").state,
        ecr::ScanProjection::ProviderUnknown
    );
    assert!(!blocked.provider().native());
    assert!(!blocked.provider().connected());
}

#[test]
fn stale_and_tampered_pages_fail_closed() {
    let mut stale = service_with(
        ecr::ScanLifecycle::Complete,
        ecr::Revision::new(8).expect("revision"),
        ecr::Revision::new(11).expect("revision"),
        None,
    );
    assert_eq!(
        stale.read().expect("stale evidence").state,
        ecr::ScanProjection::Stale
    );

    let scope = scope();
    let image_request =
        ecr::DescribeImagesRequest::new(&scope, ecr::PAGE_SIZE, ecr::MAX_PAGES, None)
            .expect("image request");
    let findings_request =
        ecr::DescribeImageScanFindingsRequest::new(&scope, ecr::PAGE_SIZE, ecr::MAX_PAGES, None)
            .expect("findings request");
    let mut image_page = ecr::DescribeImagesPage::new(
        &image_request,
        1,
        vec![ecr::EcrImageDescriptor::new(scope.image_digest().clone())],
        None,
        128,
        ecr::AWS_ECR_API_REVISION,
    )
    .expect("image page");
    image_page.page_digest = ecr::Digest::zero();
    let findings_page = ecr::DescribeImageScanFindingsPage::new(
        &findings_request,
        1,
        ecr::ScanLifecycle::Complete,
        ecr::Revision::new(7).expect("revision"),
        ecr::Revision::new(11).expect("revision"),
        Vec::new(),
        Vec::new(),
        None,
        128,
        ecr::AWS_ECR_API_REVISION,
    )
    .expect("findings page");
    let mut transport = ecr::RecordingEcrTransport::fixture();
    transport.push_describe_images_response(Ok(image_page));
    transport.push_findings_response(Ok(findings_page));
    let secret = ecr::SecretReference::for_scope("tampered-ref", &scope, 1).expect("secret");
    let provider = ecr::EcrProvider::new(transport).expect("provider");
    let mut service = ecr::EcrImageScanResultService::new(
        scope.clone(),
        secret,
        scope.permission().clone(),
        provider,
    )
    .expect("service");
    assert_eq!(
        service.read().expect("tamper evidence").state,
        ecr::ScanProjection::Tampered
    );
}

#[test]
fn pagination_replay_is_partial_and_registration_is_reversible() {
    let scope = scope();
    let image_request =
        ecr::DescribeImagesRequest::new(&scope, ecr::PAGE_SIZE, ecr::MAX_PAGES, None)
            .expect("image request");
    let token =
        ecr::OpaquePageToken::new("replayed-cursor", image_request.pagination_binding_digest())
            .expect("token");
    let first = ecr::DescribeImagesPage::new(
        &image_request,
        1,
        vec![ecr::EcrImageDescriptor::new(scope.image_digest().clone())],
        Some(token.clone()),
        128,
        ecr::AWS_ECR_API_REVISION,
    )
    .expect("first page");
    let second_request = image_request
        .with_page_token(token.clone())
        .expect("second request");
    let second = ecr::DescribeImagesPage::new(
        &second_request,
        2,
        vec![ecr::EcrImageDescriptor::new(scope.image_digest().clone())],
        Some(token),
        128,
        ecr::AWS_ECR_API_REVISION,
    )
    .expect("second page");
    let mut transport = ecr::RecordingEcrTransport::fixture();
    transport.push_describe_images_response(Ok(first));
    transport.push_describe_images_response(Ok(second));
    let secret = ecr::SecretReference::for_scope("registration-ref", &scope, 1).expect("secret");
    let provider = ecr::EcrProvider::new(transport).expect("provider");
    let mut service = ecr::EcrImageScanResultService::new(
        scope,
        secret,
        ecr::PermissionFence::for_layer_one(5).expect("permission"),
        provider,
    )
    .expect("service");
    let original = service.registration().registration_digest.clone();
    let evidence = service.read().expect("partial evidence");
    assert_eq!(evidence.state, ecr::ScanProjection::Partial);
    assert_eq!(
        evidence.partial_reason,
        Some(ecr::PartialReason::CursorReplay)
    );

    service.revoke_registration().expect("revoke");
    assert!(service.read().is_err());
    service.restore_registration().expect("restore");
    assert_ne!(original, service.registration().registration_digest);
    assert!(service.registration().is_active());
}

#[test]
fn all_layer_one_transports_are_not_native_or_connected() {
    let fixture = ecr::EcrProvider::new(ecr::RecordingEcrTransport::fixture()).expect("fixture");
    assert!(!fixture.native() && !fixture.connected());
    let loopback = ecr::EcrProvider::new(ecr::FakeEcrTransport::default()).expect("loopback");
    assert!(!loopback.native() && !loopback.connected());
    let blocked = ecr::EcrProvider::new(ecr::BlockedEnvEcrTransport).expect("blocked");
    assert!(!blocked.native() && !blocked.connected());
}
