use hartevo_kubernetes_rollout_plugin::*;
use serde_json::Value;
use std::collections::BTreeMap;

fn digest(seed: u8) -> String {
    let digit = char::from(b'0' + (seed % 10));
    format!("sha256:{}", digit.to_string().repeat(64))
}

fn scope() -> KubernetesRolloutScope {
    let rbac = RbacCapabilitySnapshot::read_only_default("rbac-revision-1")
        .expect("read-only RBAC snapshot should be valid");
    let api_server = ApiServerEndpoint::new("https://kube.example.test")
        .expect("HTTPS API server should be valid");
    let cluster = ClusterIdentity::new("cluster-1", "kube.example.test")
        .expect("cluster identity should be valid");
    let images = BTreeMap::from([(
        "web".into(),
        ImageReference::new("ghcr.io/example/web", digest(1)).expect("image should be valid"),
    )]);
    KubernetesRolloutScope::new(
        api_server,
        digest(2),
        cluster,
        "production",
        "web",
        "deployment-uid-1",
        "hartevo-rollout",
        images,
        "mission-1",
        "project-1",
        "work-product-1",
        7,
        11,
        rbac,
    )
    .expect("scope should be valid")
}

fn make_service(
    scope: KubernetesRolloutScope,
    transport: RecordingTransport,
) -> KubernetesRolloutService<KubernetesApiRolloutProvider<RecordingTransport>> {
    let auth = SecretReference::for_scope("kube-secret-ref", 3, scope.digest())
        .expect("opaque reference should be valid");
    let registration = KubernetesRolloutRegistration::new(&scope, PLUGIN_VERSION, "adapter-r1", 1)
        .expect("registration should be valid");
    KubernetesRolloutService::new(
        KubernetesApiRolloutProvider::new(transport),
        scope,
        auth,
        registration,
    )
    .expect("service should be valid")
}

fn snapshot(
    scope: &KubernetesRolloutScope,
    resource_version: &str,
    generation: u64,
    observed_generation: u64,
    image_digests: BTreeMap<String, String>,
) -> DeploymentSnapshot {
    DeploymentSnapshot {
        identity: scope.deployment.clone(),
        resource_version: resource_version.into(),
        generation,
        observed_generation,
        spec_fingerprint: digest(3),
        template_fingerprint: digest(4),
        image_digests: image_digests.clone(),
        desired_replicas: 3,
        updated_replicas: 3,
        ready_replicas: 3,
        available_replicas: 3,
        unavailable_replicas: 0,
        paused: false,
        progress_deadline_seconds: Some(600),
        conditions: vec![
            RolloutCondition {
                condition_type: "Available".into(),
                status: "True".into(),
                reason: Some("MinimumReplicasAvailable".into()),
                observed_generation: Some(observed_generation),
            },
            RolloutCondition {
                condition_type: "Progressing".into(),
                status: "True".into(),
                reason: Some("NewReplicaSetAvailable".into()),
                observed_generation: Some(observed_generation),
            },
        ],
        replica_sets: vec![ReplicaSetSnapshot {
            name: "web-rs".into(),
            uid: "replicaset-uid-1".into(),
            revision: "2".into(),
            resource_version: resource_version.into(),
            desired_replicas: 3,
            updated_replicas: 3,
            ready_replicas: 3,
            available_replicas: 3,
        }],
        pods: vec![PodRolloutEvidence {
            uid: "pod-uid-1".into(),
            phase: "Running".into(),
            ready: true,
            container_image_digests: image_digests,
            resource_version: resource_version.into(),
        }],
        request_id: Some(format!("audit-{resource_version}")),
    }
}

fn expected_images(scope: &KubernetesRolloutScope) -> BTreeMap<String, String> {
    scope.expected_image_digests()
}

fn read_once(
    scope: &KubernetesRolloutScope,
    snapshot: DeploymentSnapshot,
    expected_generation: u64,
    expected_image_digests: BTreeMap<String, String>,
) -> Result<RolloutEvidence, KubernetesRolloutError> {
    let mut service = make_service(scope.clone(), RecordingTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .push_read(Ok(snapshot));
    let request = RolloutReadRequest::new(scope, expected_generation, expected_image_digests)?;
    service.read_rollout_evidence(&request)
}

#[test]
fn contract_and_public_definitions_are_read_only_and_version_bound() {
    let service_definition = KubernetesRolloutService::<KubernetesApiRolloutProvider>::definition();
    service_definition
        .validate()
        .expect("service definition should match the contract");
    assert!(!service_definition.writes_allowed);
    assert_eq!(service_definition.layer, 1);
    assert_eq!(service_definition.contract_digest, contract_digest());

    let provider_definition = KubernetesApiRolloutProvider::<BlockedEnvTransport>::blocked_env();
    assert_eq!(
        provider_definition.provenance(),
        EvidenceProvenance::BlockedEnv
    );
    assert!(!provider_definition.provenance().is_connected());
    assert!(!provider_definition.provenance().is_native());

    let consumer_definition = MissionKubernetesRolloutConsumer::definition();
    assert_eq!(consumer_definition.consumer_id, MISSION_CONSUMER_ID);
    assert!(!consumer_definition.outcome_adoption);

    let contract: Value = serde_json::from_str(include_str!(
        "../../../contracts/plugins/kubernetes-rollout/kubernetes-rollout.v1.schema.json"
    ))
    .expect("contract must be valid JSON");
    assert_eq!(contract["properties"]["layer"]["const"], 1);
    assert_eq!(
        contract["properties"]["service"]["properties"]["writesAllowed"]["const"],
        false
    );
    assert_eq!(
        contract["properties"]["nativeGap"]["properties"]["status"]["const"],
        "BLOCKED_ENV"
    );
}

#[test]
fn schema_constants_and_serde_definitions_round_trip_without_drift() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../contracts/plugins/kubernetes-rollout/kubernetes-rollout.v1.schema.json"
    ))
    .expect("contract must be valid JSON");

    let service = KubernetesRolloutService::<KubernetesApiRolloutProvider>::definition();
    let service_json = serde_json::to_value(&service).expect("service must serialize");
    assert_eq!(
        serde_json::from_value::<KubernetesRolloutServiceDefinition>(service_json.clone())
            .expect("service must deserialize"),
        service
    );
    assert_eq!(
        service_json["contractVersion"],
        contract["properties"]["contractVersion"]["const"]
    );
    assert_eq!(
        service_json["serviceId"],
        contract["properties"]["service"]["properties"]["id"]["const"]
    );
    assert_eq!(
        service_json["access"],
        contract["properties"]["service"]["properties"]["access"]["const"]
    );
    assert_eq!(
        service_json["operations"],
        contract["properties"]["service"]["properties"]["operations"]["items"]["enum"]
    );
    assert_eq!(
        service_json["writesAllowed"],
        contract["properties"]["service"]["properties"]["writesAllowed"]["const"]
    );
    assert_eq!(
        service_json["layer"],
        contract["properties"]["layer"]["const"]
    );

    let provider = KubernetesApiRolloutProvider::<BlockedEnvTransport>::definition();
    let provider_json = serde_json::to_value(&provider).expect("provider must serialize");
    assert_eq!(
        serde_json::from_value::<KubernetesRolloutProviderDefinition>(provider_json.clone())
            .expect("provider must deserialize"),
        provider
    );
    assert_eq!(
        provider_json["providerId"],
        contract["properties"]["provider"]["properties"]["id"]["const"]
    );
    assert_eq!(
        provider_json["kubernetesApiRevision"],
        contract["properties"]["provider"]["properties"]["apiRevision"]["const"]
    );
    assert_eq!(
        provider_json["transport"],
        contract["properties"]["provider"]["properties"]["transport"]["const"]
    );
    assert_eq!(
        provider_json["nativeConnectedClaim"],
        contract["properties"]["provider"]["properties"]["nativeConnectedClaim"]["const"]
    );

    let consumer = MissionKubernetesRolloutConsumer::definition();
    let consumer_json = serde_json::to_value(&consumer).expect("consumer must serialize");
    assert_eq!(
        serde_json::from_value::<MissionKubernetesRolloutConsumerDefinition>(consumer_json.clone())
            .expect("consumer must deserialize"),
        consumer
    );
    assert_eq!(
        consumer_json["consumerId"],
        contract["properties"]["missionConsumer"]["properties"]["id"]["const"]
    );
    assert_eq!(
        consumer_json["authority"],
        contract["properties"]["missionConsumer"]["properties"]["authority"]["const"]
    );
    assert_eq!(
        consumer_json["outcomeAdoption"],
        contract["properties"]["missionConsumer"]["properties"]["outcomeAdoption"]["const"]
    );
}

#[test]
fn complete_read_to_mission_result_preserves_all_identity_fences() {
    let scope = scope();
    let images = expected_images(&scope);
    let snapshot = snapshot(&scope, "100", 2, 2, images.clone());
    let description = ClusterDescription {
        api_server: scope.api_server.clone(),
        cluster_ca_spki_sha256: scope.cluster_ca_spki_sha256.clone(),
        cluster_identity: scope.cluster_identity.clone(),
        namespace: scope.namespace.clone(),
        rbac: scope.rbac.clone(),
        provenance: EvidenceProvenance::Recording,
        request_id: Some("audit-describe".into()),
        connected: false,
        native: false,
    };
    let mut service = make_service(scope.clone(), RecordingTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .set_description(Ok(description));
    service
        .provider_mut()
        .transport_mut()
        .push_read(Ok(snapshot));

    let described = service
        .describe_rollout()
        .expect("recorded description should read");
    assert_eq!(described.cluster_identity, scope.cluster_identity);
    let request = RolloutReadRequest::new(&scope, 2, images).expect("read request should bind");
    let evidence = service
        .read_rollout_evidence(&request)
        .expect("recorded rollout should read");
    assert_eq!(evidence.snapshot.identity.uid, "deployment-uid-1");
    assert_eq!(evidence.snapshot.generation, 2);
    assert_eq!(evidence.snapshot.observed_generation, 2);
    assert_eq!(evidence.observation.phase, RolloutPhase::Complete);
    assert!(evidence.observation.complete);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert!(!evidence.provenance.is_connected());
    assert!(!evidence.provenance.is_native());

    let receipt = service
        .record_rollout_receipt(&evidence)
        .expect("read receipt should be recordable");
    assert!(receipt.dry_run_is_not_write_receipt);
    assert!(!receipt.write_receipt);
    let verification = service
        .verify_rollout_result(&receipt, &evidence)
        .expect("receipt and readback should verify");
    assert!(verification.verified);
    assert!(verification.complete);
    assert!(verification.below_kernel_authority);

    let consumer = MissionKubernetesRolloutConsumer::new(&scope, service.registration())
        .expect("consumer should bind to the exact scope");
    let proposal = consumer
        .consume(&receipt, &evidence, &verification)
        .expect("consumer should create a Mission proposal");
    proposal
        .validate()
        .expect("proposal should be self-consistent");
    assert_eq!(proposal.phase, RolloutPhase::Complete);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.outcome_adopted);
    assert_eq!(proposal.authority, "mission_result_proposal");

    let debug = format!("{service:?}");
    assert!(!debug.contains("kube-secret-ref"));
    assert!(!debug.contains("super-secret"));
}

#[test]
fn apply_and_dry_run_are_proposals_only_and_never_write_receipts() {
    let scope = scope();
    let current_images = BTreeMap::from([("web".into(), digest(9))]);
    let desired_images = scope.allowed_images.clone();
    let current_snapshot = snapshot(&scope, "200", 4, 4, current_images);
    let mut service = make_service(scope.clone(), RecordingTransport::recording());
    let proposal = service
        .compile_apply_proposal(&current_snapshot, &desired_images)
        .expect("exact image update should compile");
    proposal
        .validate()
        .expect("apply proposal should be bounded");
    assert_eq!(proposal.execution, ProposalExecution::NotExecuted);
    assert!(!proposal.dry_run);
    assert!(!proposal.connected);
    assert!(!proposal.native);

    let proposal_receipt = service
        .record_proposal_receipt(&proposal)
        .expect("proposal recording should succeed");
    proposal_receipt
        .validate()
        .expect("proposal receipt should be bounded");
    assert_eq!(proposal_receipt.kind, ReceiptKind::ProposalRecording);
    assert!(!proposal_receipt.write_receipt);

    let dry_run_proposal = service
        .compile_dry_run_proposal(&proposal)
        .expect("dry-run proposal should compile");
    assert_eq!(dry_run_proposal.dry_run_parameter, "All");
    assert!(!dry_run_proposal.connected);
    assert!(!dry_run_proposal.native);
    service
        .provider_mut()
        .transport_mut()
        .push_dry_run(Ok(DryRunTransportEvidence::accepted(
            digest(7),
            Some(digest(8)),
            Some("audit-dry-run".into()),
        )
        .expect("recorded dry-run evidence should be valid")));
    let dry_run = service
        .dry_run(&dry_run_proposal)
        .expect("recorded dry-run evidence should be returned");
    assert_eq!(dry_run.status, DryRunStatus::Accepted);
    assert!(dry_run.dry_run_is_not_write_receipt);
    assert!(!dry_run.write_receipt);
    assert!(!dry_run.connected);
    assert!(!dry_run.native);
    let dry_run_receipt = service
        .record_dry_run_receipt(&dry_run)
        .expect("dry-run recording should succeed");
    assert_eq!(dry_run_receipt.kind, ReceiptKind::DryRunAdmission);
    assert!(dry_run_receipt.dry_run_is_not_write_receipt);
    assert!(!dry_run_receipt.write_receipt);

    let mut blocked = KubernetesRolloutService::new(
        KubernetesApiRolloutProvider::blocked_env(),
        scope.clone(),
        SecretReference::for_scope("kube-secret-ref", 3, scope.digest()).expect("auth"),
        KubernetesRolloutRegistration::new(&scope, PLUGIN_VERSION, "adapter-r1", 1)
            .expect("registration"),
    )
    .expect("blocked service should still be constructible");
    let blocked_dry_run = blocked
        .dry_run(&dry_run_proposal)
        .expect("blocked environment should be typed evidence");
    assert_eq!(blocked_dry_run.status, DryRunStatus::BlockedEnv);
    assert_eq!(blocked_dry_run.provenance, EvidenceProvenance::BlockedEnv);
    assert!(!blocked_dry_run.write_receipt);
    assert!(!blocked_dry_run.connected);
    assert!(!blocked_dry_run.native);
}

#[test]
fn registration_is_scope_digest_bound_reversible_and_revocable() {
    let scope = scope();
    let mut registration =
        KubernetesRolloutRegistration::new(&scope, PLUGIN_VERSION, "adapter-r1", 1)
            .expect("registration should be valid");
    let original_digest = registration.registration_digest.clone();
    let revocation = registration
        .revoke("operator-requested-revocation")
        .expect("revoke");
    assert!(revocation.reversible);
    assert_ne!(
        revocation.registration_digest_before,
        revocation.registration_digest_after
    );
    assert!(!registration.is_active());

    let reissued = registration
        .reissue(&scope, 2)
        .expect("reissue should create a new digest");
    assert!(reissued.is_active());
    assert_ne!(reissued.registration_digest, original_digest);
    assert_eq!(reissued.scope_digest, scope.digest());
    assert_eq!(
        reissued.rbac_capability_snapshot_digest,
        scope.rbac.digest()
    );

    let mut changed_scope = scope.clone();
    changed_scope.policy_revision += 1;
    assert!(matches!(
        reissued.validate(&changed_scope),
        Err(KubernetesRolloutError::RegistrationDrift)
    ));
}

#[test]
fn trust_image_and_auth_boundaries_fail_closed() {
    assert!(matches!(
        ApiServerEndpoint::new("http://kube.example.test"),
        Err(ModelError::ApiServerMustBeHttps)
    ));
    assert!(matches!(
        ImageReference::new("ghcr.io/example/web:latest", digest(1)),
        Err(ModelError::ImageMustUseExactDigest)
    ));
    assert!(matches!(
        ImageReference::new("ghcr.io/example/web", "sha256:tag"),
        Err(ModelError::ImageMustUseExactDigest)
    ));

    let scope = scope();
    let unbound = SecretReference::new("kube-secret-ref", 3).expect("opaque ref itself is valid");
    let registration = KubernetesRolloutRegistration::new(&scope, PLUGIN_VERSION, "adapter-r1", 1)
        .expect("registration");
    assert!(matches!(
        KubernetesRolloutService::new(
            KubernetesApiRolloutProvider::blocked_env(),
            scope.clone(),
            unbound,
            registration,
        ),
        Err(KubernetesRolloutError::Model(ModelError::AuthScopeMismatch))
    ));

    let secret = SecretReference::for_scope("super-secret-token-value", 3, scope.digest())
        .expect("opaque ref");
    let debug = format!("{secret:?}");
    assert!(!debug.contains("super-secret-token-value"));
}

#[test]
fn generation_readiness_conditions_and_exact_uid_are_adversarially_fenced() {
    let scope = scope();
    let images = expected_images(&scope);

    let stale = snapshot(&scope, "10", 1, 1, images.clone());
    assert!(matches!(
        read_once(&scope, stale, 2, images.clone()),
        Err(KubernetesRolloutError::Model(ModelError::StaleGeneration))
    ));

    let newer = snapshot(&scope, "10-newer", 3, 3, images.clone());
    let evidence =
        read_once(&scope, newer, 2, images.clone()).expect("newer generation is evidence");
    assert_eq!(evidence.observation.phase, RolloutPhase::ProviderUnknown);
    assert!(!evidence.observation.complete);
    assert!(
        evidence
            .observation
            .reasons
            .contains(&"newer_generation".into())
    );

    let lagging = snapshot(&scope, "11", 2, 1, images.clone());
    let evidence = read_once(&scope, lagging, 2, images.clone()).expect("lag is evidence");
    assert_eq!(evidence.observation.phase, RolloutPhase::Progressing);
    assert!(!evidence.observation.complete);
    assert!(
        evidence
            .observation
            .reasons
            .contains(&"observed_generation_lag".into())
    );

    let mut partial = snapshot(&scope, "12", 2, 2, images.clone());
    partial.updated_replicas = 2;
    partial.ready_replicas = 1;
    partial.available_replicas = 1;
    partial.unavailable_replicas = 2;
    partial.conditions[0].status = "False".into();
    let evidence = read_once(&scope, partial, 2, images.clone()).expect("partial is evidence");
    assert_eq!(evidence.observation.phase, RolloutPhase::Degraded);
    assert!(!evidence.observation.complete);

    let mut stalled = snapshot(&scope, "13", 2, 2, images.clone());
    stalled.conditions = vec![RolloutCondition {
        condition_type: "Progressing".into(),
        status: "False".into(),
        reason: Some("ProgressDeadlineExceeded".into()),
        observed_generation: Some(2),
    }];
    let evidence = read_once(&scope, stalled, 2, images.clone()).expect("stalled is evidence");
    assert_eq!(evidence.observation.phase, RolloutPhase::Stalled);

    let mut paused = snapshot(&scope, "14", 2, 2, images.clone());
    paused.paused = true;
    let evidence = read_once(&scope, paused, 2, images.clone()).expect("paused is evidence");
    assert_eq!(evidence.observation.phase, RolloutPhase::Paused);

    let mut unknown = snapshot(&scope, "15", 2, 2, images.clone());
    unknown.conditions[0].condition_type = "FutureControllerCondition".into();
    let evidence = read_once(&scope, unknown, 2, images.clone()).expect("unknown is evidence");
    assert_eq!(evidence.observation.phase, RolloutPhase::ProviderUnknown);
    assert!(!evidence.observation.complete);

    let wrong_images = BTreeMap::from([("web".into(), digest(8))]);
    let wrong_image_snapshot = snapshot(&scope, "16", 2, 2, wrong_images);
    assert!(matches!(
        read_once(&scope, wrong_image_snapshot, 2, images.clone()),
        Err(KubernetesRolloutError::Model(
            ModelError::ImageDigestMismatch
        ))
    ));

    let mut recreated = snapshot(&scope, "17", 2, 2, images.clone());
    recreated.identity.uid = "deployment-uid-recreated".into();
    assert!(matches!(
        read_once(&scope, recreated, 2, images),
        Err(KubernetesRolloutError::Model(
            ModelError::ObjectIdentityMismatch
        ))
    ));
}

#[test]
fn resource_version_and_bounded_retry_fences_cover_conflicts_compaction_rate_limit_and_timeout() {
    let scope = scope();
    let images = expected_images(&scope);
    let initial_snapshot = snapshot(&scope, "20", 2, 2, images.clone());
    let mut service = make_service(scope.clone(), RecordingTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .push_read(Ok(initial_snapshot));
    let repeated_request = RolloutReadRequest::new(&scope, 2, images.clone())
        .expect("request")
        .with_previous_resource_version("20");
    assert!(matches!(
        service.read_rollout_evidence(&repeated_request),
        Err(KubernetesRolloutError::RepeatedWatchEvent)
    ));

    let regressed = snapshot(&scope, "19", 2, 2, images.clone());
    let mut service = make_service(scope.clone(), RecordingTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .push_read(Ok(regressed));
    let regressed_request = RolloutReadRequest::new(&scope, 2, images.clone())
        .expect("request")
        .with_previous_resource_version("20");
    assert!(matches!(
        service.read_rollout_evidence(&regressed_request),
        Err(KubernetesRolloutError::ResourceVersionRegression)
    ));

    for error in [
        KubernetesApiError::HttpStatus {
            status: 409,
            request_id: Some("conflict".into()),
        },
        KubernetesApiError::WatchCompacted {
            request_id: Some("compacted".into()),
        },
        KubernetesApiError::HttpStatus {
            status: 429,
            request_id: Some("rate-limit".into()),
        },
        KubernetesApiError::HttpStatus {
            status: 503,
            request_id: Some("server-error".into()),
        },
        KubernetesApiError::Timeout,
    ] {
        assert!(error.retryable());
        let mut service = make_service(scope.clone(), RecordingTransport::recording());
        service
            .provider_mut()
            .transport_mut()
            .push_read(Err(error.clone()));
        service
            .provider_mut()
            .transport_mut()
            .push_read(Err(error.clone()));
        service
            .provider_mut()
            .transport_mut()
            .push_read(Err(error.clone()));
        let request = RolloutReadRequest::new(&scope, 2, images.clone())
            .expect("request")
            .with_max_attempts(3)
            .expect("retry budget");
        assert!(matches!(
            service.read_rollout_evidence(&request),
            Err(KubernetesRolloutError::RetryExhausted(_))
        ));
    }

    for status in [403, 404] {
        let mut service = make_service(scope.clone(), RecordingTransport::recording());
        service
            .provider_mut()
            .transport_mut()
            .push_read(Err(KubernetesApiError::HttpStatus {
                status,
                request_id: Some(format!("audit-{status}")),
            }));
        let request = RolloutReadRequest::new(&scope, 2, images.clone()).expect("request");
        assert!(matches!(
            service.read_rollout_evidence(&request),
            Err(KubernetesRolloutError::Provider(KubernetesProviderError::Api(
                KubernetesApiError::HttpStatus { status: actual, .. }
            ))) if actual == status
        ));
    }
}

#[test]
fn trust_rbac_provenance_and_tamper_cases_never_upgrade_evidence() {
    let scope = scope();
    let images = expected_images(&scope);
    for transport in [
        RecordingTransport::fixture(),
        RecordingTransport::loopback(),
    ] {
        let mut service = make_service(scope.clone(), transport);
        service
            .provider_mut()
            .transport_mut()
            .push_read(Ok(snapshot(&scope, "30", 2, 2, images.clone())));
        let request = RolloutReadRequest::new(&scope, 2, images.clone()).expect("request");
        let evidence = service.read_rollout_evidence(&request).expect("evidence");
        assert!(!evidence.connected);
        assert!(!evidence.native);
        assert!(!evidence.provenance.is_connected());
        assert!(!evidence.provenance.is_native());
    }

    let mut drifted_description = ClusterDescription {
        api_server: scope.api_server.clone(),
        cluster_ca_spki_sha256: digest(99),
        cluster_identity: scope.cluster_identity.clone(),
        namespace: scope.namespace.clone(),
        rbac: scope.rbac.clone(),
        provenance: EvidenceProvenance::Recording,
        request_id: Some("audit-drift".into()),
        connected: false,
        native: false,
    };
    let mut service = make_service(scope.clone(), RecordingTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .set_description(Ok(drifted_description.clone()));
    assert!(matches!(
        service.describe_rollout(),
        Err(KubernetesRolloutError::Model(
            ModelError::TrustOrProvenanceMismatch
        ))
    ));

    drifted_description.cluster_ca_spki_sha256 = scope.cluster_ca_spki_sha256.clone();
    let mut changed_rbac = scope.rbac.clone();
    changed_rbac.revision = "rbac-drift".into();
    drifted_description.rbac =
        RbacCapabilitySnapshot::new("rbac-drift", changed_rbac.capabilities.clone())
            .expect("changed RBAC snapshot");
    let mut service = make_service(scope.clone(), RecordingTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .set_description(Ok(drifted_description));
    assert!(matches!(
        service.describe_rollout(),
        Err(KubernetesRolloutError::Model(
            ModelError::TrustOrProvenanceMismatch
        ))
    ));

    let mut service = make_service(scope.clone(), RecordingTransport::recording());
    service
        .provider_mut()
        .transport_mut()
        .push_read(Ok(snapshot(&scope, "31", 2, 2, images.clone())));
    let request = RolloutReadRequest::new(&scope, 2, images).expect("request");
    let evidence = service.read_rollout_evidence(&request).expect("evidence");
    let mut tampered_evidence = evidence.clone();
    tampered_evidence.snapshot.resource_version = "999".into();
    assert!(matches!(
        tampered_evidence.validate(),
        Err(ModelError::TamperedEvidence)
    ));
    let receipt = service.record_rollout_receipt(&evidence).expect("receipt");
    let mut tampered_receipt = receipt.clone();
    tampered_receipt.write_receipt = true;
    assert!(matches!(
        tampered_receipt.validate(),
        Err(KubernetesRolloutError::TamperedReceipt)
    ));
}
