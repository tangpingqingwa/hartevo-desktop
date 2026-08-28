use hartevo_tailscale_network_posture_result_plugin as plugin;
use plugin::{
    AccessDecision, ConsentScope, DeviceId, DeviceScope, EvidenceState, FixtureTransport, GrantId,
    GrantScope, IdempotencyKey, ModelError, PermissionSnapshot, PostureId, PostureScope, ProjectId,
    ProjectScope, Revision, SecretReference, TagId, TagScope, TailnetId, TailnetScope,
    TailscaleNetworkPostureResultService, TailscaleNetworkPostureScope, TailscaleOperation,
    TailscaleProvider, TailscaleReadRequest, TailscaleResponse, TailscaleTransport, TransportError,
    TransportProvenance, WorkProductId, WorkProductScope,
};

fn scope() -> TailscaleNetworkPostureScope {
    TailscaleNetworkPostureScope::new(
        TailnetScope::new(
            TailnetId::new("tailnet-763").unwrap(),
            Revision::new(2).unwrap(),
        )
        .unwrap(),
        DeviceScope::new(
            DeviceId::new("device-763").unwrap(),
            Revision::new(3).unwrap(),
        )
        .unwrap(),
        TagScope::new(
            TagId::new("tag:production").unwrap(),
            Revision::new(4).unwrap(),
        )
        .unwrap(),
        PostureScope::new(
            PostureId::new("posture-763").unwrap(),
            Revision::new(5).unwrap(),
        )
        .unwrap(),
        plugin::AclScope::new(
            plugin::AclPolicyId::new("acl-763").unwrap(),
            Revision::new(6).unwrap(),
        )
        .unwrap(),
        GrantScope::new(
            GrantId::new("grant-763").unwrap(),
            Revision::new(7).unwrap(),
        )
        .unwrap(),
        ProjectScope::new(
            ProjectId::new("project-763").unwrap(),
            Revision::new(8).unwrap(),
        )
        .unwrap(),
        plugin::MissionScope::new(
            plugin::MissionId::new("mission-763").unwrap(),
            Revision::new(9).unwrap(),
        )
        .unwrap(),
        WorkProductScope::new(
            WorkProductId::new("work-product-763").unwrap(),
            Revision::new(10).unwrap(),
        )
        .unwrap(),
        PermissionSnapshot::layer_one(Revision::new(11).unwrap()).unwrap(),
        ConsentScope::new("consent-763", Revision::new(12).unwrap()).unwrap(),
        Revision::new(13).unwrap(),
    )
    .unwrap()
}

fn device_response(revision: u64) -> TailscaleResponse {
    TailscaleResponse::json(
        200,
        &serde_json::json!({
            "id": "device-763",
            "hostname": "private-hostname-never-retained",
            "addresses": ["100.64.0.10", "fd7a:115c:a1e0::10"],
            "tags": ["tag:production", "tag:private"],
            "posture": "compliant",
            "revision": revision
        }),
    )
}

fn service_with<T: TailscaleTransport>(
    scope: TailscaleNetworkPostureScope,
    transport: T,
) -> TailscaleNetworkPostureResultService<T> {
    let secret = SecretReference::for_scope("oauth-api-token-never-retained", &scope).unwrap();
    let provider = TailscaleProvider::new(transport).unwrap();
    TailscaleNetworkPostureResultService::new(scope, secret, provider).unwrap()
}

#[test]
fn contract_scope_and_authority_are_explicitly_layer_one() {
    let contract: serde_json::Value = serde_json::from_str(plugin::CONTRACT_JSON).unwrap();
    assert_eq!(contract["contractVersion"], plugin::CONTRACT_VERSION);
    assert_eq!(contract["pluginId"], plugin::PLUGIN_ID);
    assert_eq!(contract["layer"], 1);
    assert_eq!(
        contract["service"]["type"],
        "TailscaleNetworkPostureResultService"
    );
    assert_eq!(contract["provider"]["type"], "TailscaleProvider");
    assert_eq!(
        contract["consumer"]["type"],
        "MissionTailscaleNetworkConsumer"
    );
    assert_eq!(contract["nativeGap"]["status"], plugin::BLOCKED_ENV);
    assert_eq!(contract["nativeGap"]["connected"], false);
    assert_eq!(plugin::LAYER1_PERMISSIONS.len(), 8);
    assert!(!plugin::Layer1Authority::connected());
    assert!(!plugin::Layer1Authority::native());
    assert!(!plugin::Layer1Authority::network_reachability());
    assert!(!plugin::Layer1Authority::effective_authorization());
    assert!(!plugin::Layer1Authority::access_certification());
    assert!(!plugin::Layer1Authority::device_mutation());
    assert!(!plugin::Layer1Authority::acl_mutation());
    assert!(!plugin::Layer1Authority::grant_mutation());
    assert!(!plugin::Layer1Authority::key_mutation());

    let scope = scope();
    let encoded_scope = serde_json::to_string(&scope).unwrap();
    for forbidden in [
        "tailnet-763",
        "device-763",
        "tag:production",
        "mission-763",
        "work-product-763",
    ] {
        assert!(!encoded_scope.contains(forbidden), "leaked {forbidden}");
    }
    let secret = SecretReference::for_scope("oauth-api-token-never-retained", &scope).unwrap();
    assert!(!format!("{secret:?}").contains("oauth-api-token-never-retained"));
    assert!(format!("{secret:?}").contains("reference_digest"));
}

#[test]
fn fixture_read_is_bounded_redacted_digest_fenced_and_idempotent() {
    let scope = scope();
    let mut service = service_with(scope.clone(), FixtureTransport::new(device_response(3)));
    let key = IdempotencyKey::new("device-posture-763").unwrap();
    let request = TailscaleReadRequest::device_posture(&scope, &key).unwrap();
    let proposal = service.propose(request.clone()).unwrap();

    assert_eq!(proposal.state, EvidenceState::Allowed);
    assert!(proposal.evidence.redactions.is_complete());
    assert!(proposal.evidence.validate_integrity().is_ok());
    assert!(proposal.validate_integrity().is_ok());
    assert!(!proposal.evidence.connected);
    assert!(!proposal.evidence.native);
    assert!(!proposal.evidence.first_party);
    assert!(!proposal.evidence.network_reachability_claim);
    assert!(!proposal.evidence.effective_authorization_claim);
    assert!(!proposal.evidence.access_certification_claim);
    assert!(!proposal.evidence.can_be_adopted());
    assert_eq!(proposal.evidence.device.as_ref().unwrap().tag_count, 2);

    let encoded = serde_json::to_string(&proposal).unwrap();
    for forbidden in [
        "private-hostname-never-retained",
        "100.64.0.10",
        "fd7a:115c:a1e0::10",
        "tag:private",
        "oauth-api-token-never-retained",
    ] {
        assert!(!encoded.contains(forbidden), "leaked {forbidden}");
    }
    assert!(!encoded.contains(r#""rawNodeAddressesRetained":true"#));

    let replay = service.propose(request).unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.proposal_digest, proposal.proposal_digest);
    assert_eq!(service.provider().calls().len(), 1);
}

#[test]
fn allowlisted_operations_are_recorded_without_raw_targets() {
    let scope = scope();
    let response = TailscaleResponse::json(
        200,
        &serde_json::json!({
            "id": "acl-763",
            "revision": 6,
            "acls": [{"action": "accept", "src": ["private-user"]}],
            "grants": [{"action": "accept", "srcPosture": ["posture-763"]}],
            "decision": "allow"
        }),
    );
    let provider = TailscaleProvider::new(plugin::RecordingTransport::new(response)).unwrap();
    let mut service = TailscaleNetworkPostureResultService::new(
        scope.clone(),
        SecretReference::for_scope("recording-secret", &scope).unwrap(),
        provider,
    )
    .unwrap();
    let key = IdempotencyKey::new("acl-read-763").unwrap();
    let request = TailscaleReadRequest::acl_policy(&scope, &key).unwrap();
    let proposal = service.propose(request).unwrap();
    assert_eq!(proposal.state, EvidenceState::Allowed);
    assert_eq!(proposal.evidence.access_decision, AccessDecision::Allowed);
    assert_eq!(proposal.evidence.policy.as_ref().unwrap().acl_rule_count, 1);
    assert_eq!(proposal.evidence.policy.as_ref().unwrap().grant_count, 1);
    assert_eq!(
        service.provider().calls()[0].path,
        "/api/v2/tailnet/{tailnet}/acl"
    );
    assert!(
        !serde_json::to_string(&service.provider().calls()[0])
            .unwrap()
            .contains("private-user")
    );
}

#[test]
fn typed_failure_states_and_blocked_env_never_claim_connection() {
    let cases = [
        (TransportError::Denied, EvidenceState::Denied),
        (TransportError::Expired, EvidenceState::Expired),
        (TransportError::Partial, EvidenceState::Partial),
        (
            TransportError::RateLimited {
                retry_after_seconds: 7,
            },
            EvidenceState::RateLimited,
        ),
        (
            TransportError::ProviderUnknown,
            EvidenceState::ProviderUnknown,
        ),
    ];
    for (index, (error, expected)) in cases.into_iter().enumerate() {
        let scope = scope();
        let mut transport = plugin::FakeTransport::default();
        transport.push_error(error);
        let mut service = service_with(scope.clone(), transport);
        let key = IdempotencyKey::new(format!("failure-{index}")).unwrap();
        let proposal = service
            .propose(TailscaleReadRequest::device_posture(&scope, &key).unwrap())
            .unwrap();
        assert_eq!(proposal.state, expected);
        assert!(proposal.evidence.failure.is_some());
        assert!(!proposal.evidence.connected);
        assert!(!proposal.evidence.native);
        assert!(!proposal.evidence.first_party);
    }

    let scope = scope();
    let mut blocked = TailscaleNetworkPostureResultService::new(
        scope.clone(),
        SecretReference::for_scope("blocked-secret", &scope).unwrap(),
        TailscaleProvider::default(),
    )
    .unwrap();
    let proposal = blocked.propose(blocked.default_request().unwrap()).unwrap();
    assert_eq!(proposal.state, EvidenceState::ProviderUnknown);
    assert_eq!(
        proposal.evidence.provenance,
        TransportProvenance::BlockedEnv
    );
    assert!(!proposal.evidence.connected);
    assert_eq!(plugin::BLOCKED_ENV, "BLOCKED_ENV");
}

#[test]
fn registration_reversal_restore_revoke_and_secret_revoke_are_local_and_digest_bound() {
    let first_scope = scope();
    let mut service = service_with(
        first_scope.clone(),
        FixtureTransport::new(device_response(3)),
    );
    let original = service.registration().registration_digest.clone();
    let reversed = service.reverse_registration("review pause").unwrap();
    assert_eq!(reversed.to, plugin::RegistrationState::Reversed);
    assert_ne!(reversed.registration_digest, original);
    assert!(matches!(
        service.propose(service.default_request().unwrap()),
        Err(plugin::ServiceError::RegistrationReversed)
    ));
    service.restore_registration("review resume").unwrap();
    service.revoke_registration("operator revoke").unwrap();
    assert!(matches!(
        service.propose(service.default_request().unwrap()),
        Err(plugin::ServiceError::RegistrationRevoked)
    ));

    let second_scope = scope();
    let mut revoked_secret = service_with(
        second_scope.clone(),
        FixtureTransport::new(device_response(3)),
    );
    revoked_secret.revoke_secret_reference().unwrap();
    assert!(matches!(
        revoked_secret.propose(revoked_secret.default_request().unwrap()),
        Err(plugin::ServiceError::SecretRevoked)
    ));
}

#[test]
fn tamper_scope_revision_and_mission_consumption_fail_closed() {
    let scope = scope();
    let mut service = service_with(scope.clone(), FixtureTransport::new(device_response(3)));
    let proposal = service.propose(service.default_request().unwrap()).unwrap();
    let mut tampered = proposal.clone();
    tampered.evidence.access_certification_claim = true;
    assert!(!service.verify(&tampered).valid);
    assert!(matches!(
        service.consumer().unwrap().verify_proposal(&tampered),
        Err(plugin::ConsumerError::ProposalTampered)
    ));

    let mut consumer = service.consumer().unwrap();
    let result = consumer.consume(proposal.clone()).unwrap();
    assert!(result.review_only);
    assert!(result.requires_human_review);
    assert!(!result.network_reachability_claim);
    assert!(!result.effective_authorization_claim);
    assert!(!result.access_certification_claim);
    assert!(!result.truth_authority);
    assert!(!result.outcome_adopted);
    assert!(!result.work_product_adopted);
    assert!(!result.can_be_adopted());
    assert!(matches!(
        consumer.consume(proposal),
        Err(plugin::ConsumerError::ReplayDetected)
    ));

    let record = service.record(&tampered, "record-key");
    assert!(record.is_err());
}

#[test]
fn response_revision_drift_is_typed_tamper_without_raw_body() {
    let scope = scope();
    let response = device_response(99);
    let mut service = service_with(scope.clone(), FixtureTransport::new(response));
    let key = IdempotencyKey::new("revision-drift").unwrap();
    let request = TailscaleReadRequest::device_posture(&scope, &key).unwrap();
    let proposal = service.propose(request).unwrap();
    assert_eq!(proposal.state, EvidenceState::Tamper);
    assert!(proposal.evidence.failure.is_some());
    assert!(
        !serde_json::to_string(&proposal)
            .unwrap()
            .contains("100.64.0.10")
    );
}

#[test]
fn all_local_transport_modes_are_disconnected_and_non_native() {
    for provenance in [
        TransportProvenance::Fixture,
        TransportProvenance::Recording,
        TransportProvenance::Fake,
        TransportProvenance::Loopback,
        TransportProvenance::BlockedEnv,
    ] {
        assert!(!provenance.connected());
        assert!(!provenance.native());
        assert!(!provenance.first_party());
    }
    assert_eq!(
        TailscaleOperation::Devices.path(),
        "/api/v2/tailnet/{tailnet}/devices"
    );
    assert!(TailscaleOperation::AclPolicy.is_allowlisted());
    assert!(TailscaleOperation::Grants.is_allowlisted());
}

#[test]
fn bounded_projection_rejects_counts_and_keeps_policy_digest_deterministic() {
    let scope = scope();
    let tag_digest = plugin::canonical_digest(&["tag-a", "tag-b"]);
    let first = plugin::PolicyProjection::new(&scope, 1, 1, 1, AccessDecision::Allowed).unwrap();
    let second = plugin::PolicyProjection::new(&scope, 1, 1, 1, AccessDecision::Allowed).unwrap();
    assert_eq!(first.digest(), second.digest());
    assert_eq!(scope.policy_digest(), scope.policy_digest());
    assert_eq!(tag_digest.len(), 64);
    assert!(matches!(
        plugin::DevicePostureProjection::new(
            &scope,
            plugin::PostureState::Compliant,
            plugin::MAX_DEVICES + 1,
            0,
            tag_digest,
        ),
        Err(ModelError::CountExceeded)
    ));
}
