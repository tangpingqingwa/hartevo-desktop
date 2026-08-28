use hartevo_cloud_run_deployment_result_plugin::*;

const TOKEN: &str = "oauth-or-service-account-material-must-not-escape";

fn digest(seed: u8) -> Digest {
    Digest::from_bytes(&[seed; 16])
}

fn scope() -> CloudRunScope {
    let revision = CloudRunRevisionName::new("orders-rev-00001").expect("revision");
    CloudRunScope::new(
        GoogleProjectId::new("google-project-1").expect("project"),
        CloudRunLocation::new("us-central1").expect("location"),
        CloudRunServiceName::new("orders").expect("service"),
        revision.clone(),
        CloudRunSource::new("gcr.io/example/orders", digest(1)).expect("source"),
        CloudRunTrafficPlan::single(revision).expect("traffic"),
        7,
        HartevoProjectId::new("hartevo-project-1").expect("Hartevo project"),
        MissionId::new("mission-1").expect("Mission"),
        WorkProductId::new("work-product-1").expect("Work Product"),
        11,
        13,
        CloudRunPermissionSnapshot::read_only_default("permissions-r1").expect("permissions"),
    )
    .expect("scope")
}

fn service_record(scope: &CloudRunScope, readiness: CloudRunReadiness) -> CloudRunServiceRecord {
    CloudRunServiceRecord {
        google_project_id: scope.google_project_id.clone(),
        location: scope.location.clone(),
        service_name: scope.service_name.clone(),
        service_uid: ServiceUid::new("service-uid-1").expect("service uid"),
        generation: scope.generation,
        observed_generation: scope.generation,
        revision_name: scope.revision_name.clone(),
        source: scope.source.clone(),
        traffic: scope.traffic.clone(),
        readiness,
        iam: CloudRunIamRecord::new(digest(2), 2, true).expect("IAM"),
        uri_metadata: Some(
            CloudRunUriMetadata::from_uri("https://orders-abc-uc.a.run.app").expect("URI"),
        ),
        request_id: Some("request-1".to_owned()),
        deleted: false,
        access_lost: false,
    }
}

fn revision_record(scope: &CloudRunScope, readiness: CloudRunReadiness) -> CloudRunRevisionRecord {
    CloudRunRevisionRecord {
        revision_name: scope.revision_name.clone(),
        revision_uid: RevisionUid::new("revision-uid-1").expect("revision uid"),
        generation: scope.generation,
        observed_generation: scope.generation,
        source: scope.source.clone(),
        readiness,
        condition_digest: digest(3),
    }
}

fn registration(scope: &CloudRunScope) -> CloudRunRegistration {
    let secret = SecretReference::new(
        "opaque-google-credential-reference",
        scope,
        2,
        CloudRunAuthMethod::GoogleOAuth,
    )
    .expect("opaque secret reference");
    CloudRunRegistration::new(scope.clone(), secret, 4).expect("registration")
}

fn make_provider(
    scope: &CloudRunScope,
    transport: RecordingCloudRunTransport,
) -> CloudRunProvider<RecordingCloudRunTransport, StaticCloudRunCredentialResolver> {
    CloudRunProvider::new(
        registration(scope),
        transport,
        StaticCloudRunCredentialResolver::new(TOKEN),
    )
    .expect("provider")
}

fn ready_service(
    scope: &CloudRunScope,
) -> CloudRunDeploymentResultService<RecordingCloudRunTransport, StaticCloudRunCredentialResolver> {
    let transport = RecordingCloudRunTransport::recording(
        service_record(scope, CloudRunReadiness::Ready),
        vec![revision_record(scope, CloudRunReadiness::Ready)],
    );
    CloudRunDeploymentResultService::new(make_provider(scope, transport)).expect("service")
}

#[test]
fn ready_recording_flow_seals_exact_scope_and_mission_proposal() {
    let scope = scope();
    let registration = registration(&scope);
    let mut service = ready_service(&scope);
    let description = service.describe_service().expect("description");
    assert_eq!(description.service_uid.as_str(), "service-uid-1");
    assert!(!description.native_connected);
    assert!(!description.provenance.is_connected());

    let evidence = service.read_evidence().expect("evidence");
    assert_eq!(evidence.state, CloudRunResultState::Ready);
    assert_eq!(evidence.observed_generation, scope.generation);
    assert_eq!(evidence.revision_count, 1);
    assert_eq!(evidence.page_count, 1);
    assert!(!evidence.native_connected);
    assert!(!evidence.provenance.is_native());

    let receipt = service
        .record_deployment_receipt(&evidence)
        .expect("receipt");
    let proposal = service
        .compile_deployment_result_proposal(&evidence)
        .expect("proposal");
    let verified = service
        .verify_deployment_result(&proposal, &evidence, &receipt)
        .expect("verified proposal");
    let consumer =
        MissionCloudRunDeploymentConsumer::from_registration(&registration).expect("consumer");
    let mission_result = consumer.consume_result(&verified).expect("Mission result");
    mission_result.validate().expect("Mission result validates");
    assert!(!mission_result.durable_adoption);
    assert!(!mission_result.kernel_authority);
}

#[test]
fn fake_fixture_and_loopback_never_upgrade_to_native_or_connected() {
    let scope = scope();
    for transport in [
        RecordingCloudRunTransport::fake(
            service_record(&scope, CloudRunReadiness::Ready),
            vec![revision_record(&scope, CloudRunReadiness::Ready)],
        ),
        RecordingCloudRunTransport::fixture(
            service_record(&scope, CloudRunReadiness::Ready),
            vec![revision_record(&scope, CloudRunReadiness::Ready)],
        ),
        RecordingCloudRunTransport::loopback(
            service_record(&scope, CloudRunReadiness::Ready),
            vec![revision_record(&scope, CloudRunReadiness::Ready)],
        ),
    ] {
        let mut provider = make_provider(&scope, transport);
        let evidence = provider.read_evidence().expect("evidence");
        assert!(!evidence.native_connected);
        assert!(!evidence.provenance.is_connected());
        assert!(!evidence.provenance.is_native());
    }
}

#[test]
fn blocked_env_revocation_and_all_external_mutations_fail_closed() {
    let scope = scope();
    let transport = RecordingCloudRunTransport::blocked_env(
        service_record(&scope, CloudRunReadiness::Ready),
        vec![revision_record(&scope, CloudRunReadiness::Ready)],
    );
    let registration = registration(&scope);
    let mut blocked = CloudRunProvider::new(registration, transport, BlockedEnvCredentialResolver)
        .expect("blocked provider");
    assert_eq!(
        blocked.read_evidence().expect_err("BLOCKED_ENV"),
        CloudRunDeploymentResultError::BlockedEnv
    );
    assert_eq!(blocked.state(), CloudRunProviderState::BlockedEnv);

    let transport = RecordingCloudRunTransport::recording(
        service_record(&scope, CloudRunReadiness::Ready),
        vec![revision_record(&scope, CloudRunReadiness::Ready)],
    );
    let mut provider = make_provider(&scope, transport);
    let revocation = provider.revoke().expect("revocation");
    assert!(revocation.reversible);
    assert_eq!(provider.state(), CloudRunProviderState::Revoked);
    assert_eq!(
        provider.read_evidence().expect_err("revoked read"),
        CloudRunDeploymentResultError::RegistrationRevoked
    );

    for operation in [
        "service create",
        "service patch",
        "service delete",
        "traffic mutation",
        "IAM mutation",
        "secret export",
        "raw logs",
        "unbounded revision listing",
    ] {
        assert_eq!(
            provider.reject_write(operation),
            Err(CloudRunDeploymentResultError::MutationForbidden { operation })
        );
    }
}

#[test]
fn readiness_generation_traffic_and_revision_states_are_typed() {
    let scope = scope();
    for (readiness, expected) in [
        (
            CloudRunReadiness::Reconciling,
            CloudRunResultState::Reconciling,
        ),
        (CloudRunReadiness::Failed, CloudRunResultState::Failed),
        (CloudRunReadiness::Partial, CloudRunResultState::Partial),
        (
            CloudRunReadiness::Unknown,
            CloudRunResultState::ProviderUnknown,
        ),
    ] {
        let transport = RecordingCloudRunTransport::recording(
            service_record(&scope, readiness),
            vec![revision_record(&scope, readiness)],
        );
        let mut provider = make_provider(&scope, transport);
        let evidence = provider.read_evidence().expect("typed evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.is_adoptable());
    }

    let transport = RecordingCloudRunTransport::recording(
        service_record(&scope, CloudRunReadiness::Ready),
        vec![revision_record(&scope, CloudRunReadiness::Ready)],
    );
    transport.set_service(CloudRunServiceRecord {
        traffic: CloudRunTrafficPlan::new(vec![
            CloudRunTrafficTarget::new(
                CloudRunRevisionName::new("orders-rev-00002").expect("drift revision"),
                100,
                None,
            )
            .expect("drift traffic"),
        ])
        .expect("drift plan"),
        ..service_record(&scope, CloudRunReadiness::Ready)
    });
    let mut provider = make_provider(&scope, transport);
    let evidence = provider.read_evidence().expect("traffic drift evidence");
    assert_eq!(evidence.state, CloudRunResultState::TrafficDrift);
    assert!(!evidence.is_adoptable());

    let transport = RecordingCloudRunTransport::recording(
        service_record(&scope, CloudRunReadiness::Ready),
        vec![revision_record(&scope, CloudRunReadiness::Ready)],
    );
    transport.set_service(CloudRunServiceRecord {
        generation: scope.generation + 1,
        observed_generation: scope.generation + 1,
        ..service_record(&scope, CloudRunReadiness::Ready)
    });
    let mut provider = make_provider(&scope, transport);
    assert_eq!(
        provider.read_evidence().expect_err("generation drift"),
        CloudRunDeploymentResultError::StaleGeneration
    );

    let transport = RecordingCloudRunTransport::recording(
        CloudRunServiceRecord {
            observed_generation: scope.generation + 1,
            ..service_record(&scope, CloudRunReadiness::Ready)
        },
        vec![CloudRunRevisionRecord {
            observed_generation: scope.generation + 1,
            ..revision_record(&scope, CloudRunReadiness::Ready)
        }],
    );
    let mut provider = make_provider(&scope, transport);
    let evidence = provider
        .read_evidence()
        .expect("future observed generation is typed evidence");
    assert_eq!(evidence.state, CloudRunResultState::ProviderUnknown);
    assert!(!evidence.is_adoptable());
}

#[test]
fn deleted_and_access_loss_states_are_explicit_and_not_adoptable() {
    let scope = scope();
    for (deleted, access_lost, expected) in [
        (true, false, CloudRunResultState::Deleted),
        (false, true, CloudRunResultState::AccessLost),
    ] {
        let transport = RecordingCloudRunTransport::recording(
            CloudRunServiceRecord {
                deleted,
                access_lost,
                ..service_record(&scope, CloudRunReadiness::Ready)
            },
            vec![revision_record(&scope, CloudRunReadiness::Ready)],
        );
        let mut provider = make_provider(&scope, transport);
        let evidence = provider.read_evidence().expect("availability evidence");
        assert_eq!(evidence.state, expected);
        assert!(!evidence.is_adoptable());
        assert!(
            provider
                .compile_deployment_result_proposal(&evidence)
                .is_err()
        );
    }
}

#[test]
fn same_name_replacement_source_tamper_and_revision_drift_fail_closed() {
    let scope = scope();
    let transport = RecordingCloudRunTransport::recording(
        service_record(&scope, CloudRunReadiness::Ready),
        vec![revision_record(&scope, CloudRunReadiness::Ready)],
    );
    let mut provider = make_provider(&scope, transport.clone());
    provider.read_evidence().expect("baseline");
    transport.set_service(CloudRunServiceRecord {
        service_uid: ServiceUid::new("service-uid-replaced").expect("replacement"),
        ..service_record(&scope, CloudRunReadiness::Ready)
    });
    assert_eq!(
        provider.read_evidence().expect_err("same-name replacement"),
        CloudRunDeploymentResultError::SameNameReplacement
    );

    let transport = RecordingCloudRunTransport::recording(
        CloudRunServiceRecord {
            source: CloudRunSource::new("gcr.io/example/orders", digest(99)).expect("tamper"),
            ..service_record(&scope, CloudRunReadiness::Ready)
        },
        vec![revision_record(&scope, CloudRunReadiness::Ready)],
    );
    let mut provider = make_provider(&scope, transport);
    assert_eq!(
        provider.read_evidence().expect_err("source tamper"),
        CloudRunDeploymentResultError::SourceDigestMismatch
    );

    let transport = RecordingCloudRunTransport::recording(
        service_record(&scope, CloudRunReadiness::Ready),
        vec![CloudRunRevisionRecord {
            revision_uid: RevisionUid::new("revision-replaced").expect("revision replacement"),
            ..revision_record(&scope, CloudRunReadiness::Ready)
        }],
    );
    let mut provider = make_provider(&scope, transport);
    provider.read_evidence().expect("first revision");
    provider
        .transport_mut()
        .set_pages(vec![CloudRunRevisionPage {
            revisions: vec![CloudRunRevisionRecord {
                revision_uid: RevisionUid::new("revision-replaced-again").expect("drift"),
                ..revision_record(&scope, CloudRunReadiness::Ready)
            }],
            next_page_token: None,
        }]);
    assert_eq!(
        provider.read_evidence().expect_err("revision drift"),
        CloudRunDeploymentResultError::StaleRevision
    );
}

#[test]
fn bounded_pagination_http_faults_and_stale_mission_are_preserved() {
    let scope = scope();
    let transport = RecordingCloudRunTransport::recording(
        service_record(&scope, CloudRunReadiness::Ready),
        vec![revision_record(&scope, CloudRunReadiness::Ready)],
    );
    transport.set_pages(vec![CloudRunRevisionPage {
        revisions: vec![revision_record(&scope, CloudRunReadiness::Ready)],
        next_page_token: Some("page:1".to_owned()),
    }]);
    let mut provider = make_provider(&scope, transport);
    let request = CloudRunReadRequest::new(
        scope.clone(),
        scope.mission_revision,
        scope.work_product_revision,
    )
    .expect("request")
    .with_bounds(1, 4)
    .expect("bounds");
    assert_eq!(
        provider
            .read_deployment_evidence(&request)
            .expect_err("pagination bound"),
        CloudRunDeploymentResultError::PaginationBoundExceeded
    );
    assert_eq!(
        CloudRunReadRequest::new(
            scope.clone(),
            scope.mission_revision + 1,
            scope.work_product_revision,
        )
        .expect_err("stale Mission"),
        CloudRunDeploymentResultError::StaleMissionRevision
    );

    for (fault, expected) in [
        (
            CloudRunTransportError::NotFoundOrUnauthorized,
            CloudRunDeploymentResultError::NotFoundOrUnauthorized,
        ),
        (
            CloudRunTransportError::Unauthorized,
            CloudRunDeploymentResultError::Unauthorized,
        ),
        (
            CloudRunTransportError::Forbidden,
            CloudRunDeploymentResultError::Forbidden,
        ),
        (
            CloudRunTransportError::NotFound,
            CloudRunDeploymentResultError::NotFound,
        ),
        (
            CloudRunTransportError::Conflict,
            CloudRunDeploymentResultError::Conflict,
        ),
        (
            CloudRunTransportError::RateLimited {
                retry_after_seconds: Some(9),
            },
            CloudRunDeploymentResultError::RateLimited {
                retry_after_seconds: Some(9),
            },
        ),
        (
            CloudRunTransportError::Timeout,
            CloudRunDeploymentResultError::Timeout,
        ),
        (
            CloudRunTransportError::ResponseTooLarge,
            CloudRunDeploymentResultError::ResponseTooLarge,
        ),
        (
            CloudRunTransportError::ServerUnavailable,
            CloudRunDeploymentResultError::RetryExhausted,
        ),
    ] {
        let transport = RecordingCloudRunTransport::recording(
            service_record(&scope, CloudRunReadiness::Ready),
            vec![revision_record(&scope, CloudRunReadiness::Ready)],
        );
        transport.set_fault(fault);
        let mut provider = make_provider(&scope, transport);
        assert_eq!(provider.read_evidence().expect_err("fault"), expected);
    }
}

#[test]
fn tamper_truncation_redaction_and_secret_registration_fences_hold() {
    let scope = scope();
    let secret = SecretReference::new(
        "private-service-account-json-and-refresh-token",
        &scope,
        5,
        CloudRunAuthMethod::GoogleServiceAccount,
    )
    .expect("secret reference");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("private-service-account-json"));
    assert!(
        !serde_json::to_string(&secret)
            .expect("secret reference JSON")
            .contains("refresh-token")
    );

    let mut service = ready_service(&scope);
    let evidence = service.read_evidence().expect("evidence");
    let mut tampered = evidence.clone();
    tampered.observed_generation += 1;
    assert_eq!(
        tampered.validate().expect_err("tampered evidence"),
        CloudRunDeploymentResultError::InvalidEvidence
    );
    let mut truncated = evidence.clone();
    truncated.truncated = true;
    truncated.evidence_digest = truncated.computed_digest();
    assert_eq!(
        truncated.validate().expect_err("truncated evidence"),
        CloudRunDeploymentResultError::TruncatedEvidence
    );
    let receipt = service
        .record_deployment_receipt(&evidence)
        .expect("receipt");
    let mut receipt_tampered = receipt.clone();
    receipt_tampered.observed_generation += 1;
    assert_eq!(
        receipt_tampered
            .validate_against(&evidence, &receipt.registration_digest)
            .expect_err("tampered receipt"),
        CloudRunDeploymentResultError::ReceiptMismatch
    );
    let provider_debug = format!("{:?}", service.provider());
    assert!(!provider_debug.contains(TOKEN));
}

#[test]
fn official_and_loopback_http_endpoints_are_explicitly_separate() {
    let official = UreqCloudRunTransport::new(CLOUD_RUN_API_BASE_URL).expect("HTTPS transport");
    assert_eq!(official.provenance(), ProviderProvenance::OfficialHttps);
    assert!(official.provenance().is_native());
    assert!(!official.provenance().is_connected());
    assert!(UreqCloudRunTransport::new("http://example.invalid").is_err());
    let loopback =
        UreqCloudRunTransport::new_loopback("http://127.0.0.1:1").expect("loopback transport");
    assert_eq!(loopback.provenance(), ProviderProvenance::Loopback);
    assert!(!loopback.provenance().is_native());
    assert!(!loopback.provenance().is_connected());
}
