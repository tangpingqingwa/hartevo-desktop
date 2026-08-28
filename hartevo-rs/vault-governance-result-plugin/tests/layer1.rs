use hartevo_vault_governance_result_plugin::*;

const PROVIDER_REVISION: &str = VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION;

fn base_scope() -> VaultScope {
    VaultScope::new(
        "team/production",
        "kv",
        [
            VaultPath::new("apps/hartevo/config").expect("path"),
            VaultPath::new("apps/hartevo/metadata").expect("path"),
        ],
        "mission-1",
        7,
        "project-1",
        3,
    )
    .expect("scope")
}

fn bind_scope(scope: VaultScope) -> VaultScope {
    let reference =
        SecretReference::new("s.super-secret-token-material", &scope, 4).expect("secret reference");
    scope
        .bind_secret_reference(&reference)
        .expect("secret binding")
}

fn scope() -> VaultScope {
    bind_scope(base_scope())
}

fn revocation_scope() -> VaultScope {
    bind_scope(
        VaultScope::new(
            "team/production",
            "kv",
            [VaultPath::new("apps/hartevo/config").expect("path")],
            "mission-revocation",
            99,
            "project-revocation",
            99,
        )
        .expect("revocation scope"),
    )
}

fn reversible_scope() -> VaultScope {
    bind_scope(
        VaultScope::new(
            "team/production",
            "kv",
            [VaultPath::new("apps/hartevo/config").expect("path")],
            "mission-reversible",
            98,
            "project-reversible",
            98,
        )
        .expect("reversible scope"),
    )
}

fn scope_with_lease() -> (VaultScope, LeaseReference) {
    let lease = LeaseReference::new("database/creds/hartevo/opaque-lease").expect("lease");
    (bind_scope(base_scope().bind_lease(&lease)), lease)
}

fn secret(scope: &VaultScope) -> SecretReference {
    SecretReference::new("s.super-secret-token-material", scope, 4).expect("secret reference")
}

fn service() -> VaultGovernanceResultService {
    VaultGovernanceResultService::new()
}

fn response(
    scope: &VaultScope,
    endpoint: VaultEndpoint,
    status: u16,
    response_size: usize,
    payload: VaultResponsePayload,
) -> VaultHttpResponse {
    let request = VaultRequest::new(scope, endpoint);
    VaultHttpResponse::for_request(&request, status, response_size, PROVIDER_REVISION, payload)
        .expect("response")
}

#[test]
fn fixture_read_record_verify_and_mission_consume_are_bounded() {
    let (scope, lease) = scope_with_lease();
    let service = service();
    let mut provider = service
        .register(
            scope.clone(),
            secret(&scope),
            FixtureVaultTransport::default(),
        )
        .expect("provider");
    let request = VaultReadRequest::new(1_700_000_000)
        .check_path(
            VaultPath::new("apps/hartevo/config").expect("path"),
            [CapabilityClass::Read, CapabilityClass::List],
        )
        .expect("capability request")
        .lookup_lease(lease);
    let proposal = service.propose(&mut provider, &request).expect("proposal");
    assert_eq!(proposal.evidence().provenance, ProviderProvenance::Fixture);
    assert_eq!(
        proposal.evidence().health.as_ref().unwrap().status,
        HealthStatus::Active
    );
    assert_eq!(
        proposal.evidence().token.as_ref().unwrap().status,
        TokenStatus::Active
    );
    assert_eq!(
        proposal.evidence().lease.as_ref().unwrap().status,
        LeaseStatus::Active
    );
    assert!(!proposal.evidence().native_evidence);
    assert!(!proposal.evidence().secret_values_retained);
    assert!(!proposal.evidence().token_material_retained);
    assert_eq!(
        proposal.evidence().lifecycle_generation,
        proposal.lifecycle_generation()
    );
    assert!(!provider.is_connected());

    let record = service.record(proposal).expect("record");
    let verification = service.verify(&record, &scope).expect("verification");
    assert!(verification.verified);
    assert_eq!(
        verification.lifecycle_generation,
        record.lifecycle_generation()
    );
    assert!(!verification.native_authority);
    assert!(!verification.truth_authority);

    let consumer = MissionVaultGovernanceConsumer::new(
        scope.clone(),
        record.evidence().registration_digest.clone(),
    );
    let result = consumer.consume(&record).expect("mission result");
    assert_eq!(result.observation.mission_id.as_str(), "mission-1");
    assert_eq!(result.observation.project_id.as_str(), "project-1");
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer2);
    assert_eq!(
        result.observation.lifecycle_generation,
        record.lifecycle_generation()
    );
    assert!(!result.observation.adopted_outcome);
    result.validate(&scope).expect("result validation");
}

#[test]
fn opaque_secret_and_lease_references_never_debug_raw_material() {
    let (scope, lease) = scope_with_lease();
    let secret = secret(&scope);
    let secret_debug = format!("{secret:?}");
    let lease_debug = format!("{lease:?}");
    assert!(!secret_debug.contains("super-secret-token-material"));
    assert!(!lease_debug.contains("database/creds/hartevo/opaque-lease"));
    assert!(!secret_debug.contains("s.super-secret-token-material"));

    let mut provider = service()
        .register(scope.clone(), secret, RecordingVaultTransport::default())
        .expect("provider");
    let _ = provider
        .read(&VaultReadRequest::health_only(1_700_000_001))
        .expect("health");
    let recorded = format!("{:?}", provider.transport().requests());
    assert!(!recorded.contains("s.super-secret-token-material"));
    assert!(!recorded.contains("opaque-lease"));
    assert_eq!(
        provider.transport().requests()[0].api_path(),
        "/v1/sys/health"
    );
}

#[test]
fn namespace_mount_and_path_traversal_fail_closed() {
    assert!(VaultNamespace::new("team/../production").is_err());
    assert!(VaultNamespace::new("root").is_err());
    assert!(VaultMount::new("sys").is_err());
    assert!(VaultPath::new("apps/../secret").is_err());
    assert!(VaultPath::new("/secret/data").is_err());
    assert!(VaultPath::new("sys/health").is_err());
    assert!(VaultPath::new("auth/token/lookup-self").is_err());

    let paths = (0..=16)
        .map(|index| VaultPath::new(format!("apps/path-{index}")).expect("path"))
        .collect::<Vec<_>>();
    assert!(VaultScope::new("team", "kv", paths, "mission-1", 1, "project-1", 1).is_err());
}

#[test]
fn sealed_and_standby_health_statuses_are_normalized_without_native_claims() {
    for (status, expected, mut metadata) in [
        (503, HealthStatus::Sealed, VaultHealthMetadata::default()),
        (429, HealthStatus::Standby, VaultHealthMetadata::default()),
    ] {
        metadata.sealed = expected == HealthStatus::Sealed;
        metadata.standby = expected == HealthStatus::Standby;
        let scope = scope();
        let response = response(
            &scope,
            VaultEndpoint::SysHealth,
            status,
            512,
            VaultResponsePayload::Health(metadata),
        );
        let mut transport = RecordingVaultTransport::default();
        transport.push_response(response);
        let mut provider = service()
            .register(scope.clone(), secret(&scope), transport)
            .expect("provider");
        let evidence = provider
            .read(&VaultReadRequest::health_only(10))
            .expect("health");
        assert_eq!(evidence.health.as_ref().unwrap().status, expected);
        assert!(!evidence.native_evidence);
    }
}

#[test]
fn permission_conflict_rate_limit_and_server_statuses_are_distinct() {
    for status in [401, 403, 404, 409, 429, 500, 503] {
        let scope = scope();
        let response = response(
            &scope,
            VaultEndpoint::AuthTokenLookupSelf,
            status,
            128,
            VaultResponsePayload::TokenSelf(
                VaultTokenSelfMetadata::new(
                    Digest::from_text("token"),
                    Digest::from_text("accessor"),
                    None,
                    60,
                    false,
                    vec![PolicyClass::ReadOnly],
                )
                .expect("token metadata"),
            ),
        );
        let mut transport = RecordingVaultTransport::default();
        transport.push_response(response);
        let mut provider = service()
            .register(scope.clone(), secret(&scope), transport)
            .expect("provider");
        let error = provider
            .read(&VaultReadRequest::new(11).include_health(false))
            .expect_err("status should fail closed");
        assert!(matches!(
            error,
            VaultProviderError::UnexpectedStatus {
                status: observed,
                ..
            } if observed == status
        ));
        assert_eq!(
            classify_status(status),
            match status {
                401 => VaultStatusClass::Unauthorized,
                403 => VaultStatusClass::Forbidden,
                404 => VaultStatusClass::NotFound,
                409 => VaultStatusClass::Conflict,
                429 => VaultStatusClass::RateLimitedOrStandby,
                500 | 503 => VaultStatusClass::ServerError,
                _ => VaultStatusClass::Unknown,
            }
        );
    }
}

#[test]
fn capability_mismatch_and_expired_lease_are_fail_closed_and_bounded() {
    let (scope, lease) = scope_with_lease();
    let path = VaultPath::new("apps/hartevo/config").expect("path");
    let mismatched = response(
        &scope,
        VaultEndpoint::SysCapabilitiesSelf {
            path_digests: vec![path.path_digest()],
        },
        200,
        256,
        VaultResponsePayload::CapabilitiesSelf(vec![
            VaultCapabilityMetadata::new(path.path_digest(), vec![CapabilityClass::Read])
                .expect("capability"),
        ]),
    );
    let mut transport = RecordingVaultTransport::default();
    transport.push_response(mismatched);
    let mut provider = service()
        .register(scope.clone(), secret(&scope), transport)
        .expect("provider");
    let request = VaultReadRequest::new(12)
        .include_health(false)
        .include_token_self(false)
        .check_path(path, [CapabilityClass::Read, CapabilityClass::List])
        .expect("request");
    assert!(matches!(
        provider.read(&request),
        Err(VaultProviderError::CapabilityMismatch { .. })
    ));

    let expired = response(
        &scope,
        VaultEndpoint::SysLeasesLookup {
            lease_digest: lease.reference_digest().clone(),
        },
        200,
        256,
        VaultResponsePayload::LeaseLookup(VaultLeaseMetadata::new(
            lease.reference_digest().clone(),
            scope.mount().mount_digest(),
            Digest::from_text("lease-path"),
            0,
            true,
        )),
    );
    let mut transport = RecordingVaultTransport::default();
    transport.push_response(expired);
    let mut provider = service()
        .register(scope.clone(), secret(&scope), transport)
        .expect("provider");
    let request = VaultReadRequest::new(13)
        .include_health(false)
        .include_token_self(false)
        .lookup_lease(lease);
    let evidence = provider
        .read(&request)
        .expect("expired metadata is readable");
    assert_eq!(
        evidence.lease.as_ref().unwrap().status,
        LeaseStatus::Expired
    );
    assert_eq!(evidence.lease.as_ref().unwrap().ttl_seconds, 0);
}

#[test]
fn tamper_partial_provider_unknown_timeout_and_blocked_env_fail_closed() {
    let scope = scope();
    let mut provider = service()
        .register(
            scope.clone(),
            secret(&scope),
            FixtureVaultTransport::default(),
        )
        .expect("provider");
    let proposal = service()
        .propose(&mut provider, &VaultReadRequest::health_only(14))
        .expect("proposal");
    let mut tampered = proposal.evidence().clone();
    tampered.provider_version = "9.9.9".to_owned();
    assert!(service().verify_evidence(&tampered, &scope).is_err());

    let mut partial_transport = RecordingVaultTransport::default();
    partial_transport.push_response(response(
        &scope,
        VaultEndpoint::SysHealth,
        200,
        128,
        VaultResponsePayload::Health(VaultHealthMetadata::default()),
    ));
    partial_transport.push_error(VaultTransportError::Timeout);
    let mut partial_provider = service()
        .register(scope.clone(), secret(&scope), partial_transport)
        .expect("provider");
    assert!(matches!(
        partial_provider.read(&VaultReadRequest::new(15)),
        Err(VaultProviderError::Partial { completed: 1, .. })
    ));

    let mut unknown_transport = RecordingVaultTransport::default();
    unknown_transport.push_error(VaultTransportError::ProviderUnknown);
    let mut unknown_provider = service()
        .register(scope.clone(), secret(&scope), unknown_transport)
        .expect("provider");
    assert!(matches!(
        unknown_provider.read(&VaultReadRequest::health_only(16)),
        Err(VaultProviderError::ProviderUnknown)
    ));

    let mut blocked_provider = service()
        .register(scope.clone(), secret(&scope), BlockedEnvVaultTransport)
        .expect("provider");
    assert!(matches!(
        blocked_provider.read(&VaultReadRequest::health_only(17)),
        Err(VaultProviderError::BlockedEnv)
    ));
}

#[test]
fn loopback_recording_and_fixture_provenance_are_explicitly_non_native() {
    let scope = scope();
    let mut loopback = service()
        .register(
            scope.clone(),
            secret(&scope),
            LoopbackVaultTransport::default(),
        )
        .expect("provider");
    let evidence = loopback
        .read(&VaultReadRequest::health_only(18))
        .expect("loopback");
    assert_eq!(evidence.provenance, ProviderProvenance::Loopback);
    assert!(!evidence.native_evidence);

    let mut fixture = service()
        .register(scope.clone(), secret(&scope), FakeVaultTransport::default())
        .expect("provider");
    assert_eq!(
        fixture
            .read(&VaultReadRequest::health_only(19))
            .expect("fixture")
            .provenance,
        ProviderProvenance::Fixture
    );
}

#[test]
fn registration_is_reversible_and_revocation_fails_closed() {
    let scope = reversible_scope();
    let mut provider = service()
        .register(
            scope.clone(),
            secret(&scope),
            FixtureVaultTransport::default(),
        )
        .expect("provider");
    service()
        .revoke_registration(&mut provider, 20)
        .expect("revoke registration");
    assert_eq!(provider.registration().state(), RegistrationState::Revoked);
    assert!(matches!(
        provider.read(&VaultReadRequest::health_only(21)),
        Err(VaultProviderError::RegistrationRevoked)
    ));
    assert!(matches!(
        service().revoke_registration(&mut provider, 22),
        Err(VaultGovernanceError::Provider(
            VaultProviderError::RegistrationRevoked
        ))
    ));
}

#[test]
fn serde_rechecks_constructor_invariants_and_nested_unknown_fields() {
    assert!(serde_json::from_str::<Digest>("\"not-a-digest\"").is_err());
    assert!(serde_json::from_str::<Revision>("0").is_err());
    assert!(serde_json::from_str::<ProjectId>("\"mission id\"").is_err());
    assert!(serde_json::from_str::<VaultPath>("\"apps/../secret\"").is_err());

    let scope = scope();
    let mut serialized = serde_json::to_value(&scope).expect("scope json");
    serialized["allowlistedPaths"][0] = serde_json::json!("apps/../secret");
    assert!(serde_json::from_value::<VaultScope>(serialized).is_err());

    let mut serialized = serde_json::to_value(&scope).expect("scope json");
    serialized["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<VaultScope>(serialized).is_err());

    let token = VaultTokenSelfMetadata::new(
        Digest::from_text("token-serde"),
        Digest::from_text("accessor-serde"),
        None,
        60,
        false,
        vec![PolicyClass::ReadOnly],
    )
    .expect("token");
    let mut token_json = serde_json::to_value(token).expect("token json");
    token_json["policyDigest"] = serde_json::json!(Digest::from_text("wrong").as_str());
    assert!(serde_json::from_value::<VaultTokenSelfMetadata>(token_json).is_err());

    let mut provider = service()
        .register(
            scope.clone(),
            secret(&scope),
            FixtureVaultTransport::default(),
        )
        .expect("provider");
    let evidence = provider
        .read(&VaultReadRequest::health_only(30))
        .expect("evidence");
    let mut evidence_json = serde_json::to_value(evidence).expect("evidence json");
    evidence_json["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<VaultGovernanceEvidence>(evidence_json).is_err());
}

#[test]
fn request_and_response_digests_are_nonzero_exact_and_recomputed() {
    let scope = scope();
    let request = VaultRequest::new(&scope, VaultEndpoint::SysHealth);
    let request_json = serde_json::to_value(&request).expect("request json");
    assert_ne!(
        request_json["requestDigest"],
        serde_json::json!("0000000000000000000000000000000000000000000000000000000000000000")
    );

    let unbound = VaultHttpResponse::new(
        VaultOperation::SysHealth,
        200,
        128,
        PROVIDER_REVISION,
        VaultResponsePayload::Health(VaultHealthMetadata::default()),
    )
    .expect("unbound response");
    let mut transport = RecordingVaultTransport::default();
    transport.push_response(unbound);
    let mut provider = service()
        .register(scope.clone(), secret(&scope), transport)
        .expect("provider");
    assert!(matches!(
        provider.read(&VaultReadRequest::health_only(31)),
        Err(VaultProviderError::RequestDigestMismatch)
    ));

    let valid = response(
        &scope,
        VaultEndpoint::SysHealth,
        200,
        128,
        VaultResponsePayload::Health(VaultHealthMetadata::default()),
    );
    let mut response_json = serde_json::to_value(valid).expect("response json");
    response_json["responseSize"] = serde_json::json!(129);
    assert!(serde_json::from_value::<VaultHttpResponse>(response_json).is_err());
}

#[test]
fn shared_revocation_fence_rejects_snapshots_and_replay() {
    let scope = revocation_scope();
    let mut provider = service()
        .register(
            scope.clone(),
            secret(&scope),
            FixtureVaultTransport::default(),
        )
        .expect("provider");
    let snapshot = provider.registration().clone();
    provider.revoke_registration(40).expect("revoke");
    assert!(matches!(
        VaultProvider::from_registration(snapshot, FixtureVaultTransport::default()),
        Err(VaultProviderError::RegistrationRevoked | VaultProviderError::RegistrationReplay)
    ));
    assert!(matches!(
        service().register(
            scope.clone(),
            secret(&scope),
            FixtureVaultTransport::default()
        ),
        Err(VaultGovernanceError::Provider(
            VaultProviderError::RegistrationReplay
        ))
    ));
}

#[test]
fn current_generation_fences_pre_revocation_artifacts_and_stale_clones() {
    let scope = bind_scope(
        VaultScope::new(
            "team/generation",
            "kv",
            [VaultPath::new("apps/generation/config").expect("path")],
            "mission-generation",
            101,
            "project-generation",
            101,
        )
        .expect("scope"),
    );
    let service = service();
    let mut provider = service
        .register(
            scope.clone(),
            secret(&scope),
            FixtureVaultTransport::default(),
        )
        .expect("provider");
    let mut stale_clone = VaultProvider::from_registration(
        provider.registration().clone(),
        FixtureVaultTransport::default(),
    )
    .expect("stale clone");
    let proposal = service
        .propose(&mut provider, &VaultReadRequest::health_only(50))
        .expect("proposal");
    let record = service.record(proposal.clone()).expect("record");
    let consumer = MissionVaultGovernanceConsumer::new(
        scope.clone(),
        record.evidence().registration_digest.clone(),
    );
    assert_eq!(
        proposal.evidence().lifecycle_generation,
        record.evidence().lifecycle_generation
    );

    service
        .revoke_registration(&mut provider, 51)
        .expect("revoke");

    assert!(
        stale_clone
            .read(&VaultReadRequest::health_only(52))
            .is_err()
    );
    assert!(proposal.validate().is_err());
    assert!(service.record(proposal.clone()).is_err());
    assert!(record.validate().is_err());
    assert!(service.verify(&record, &scope).is_err());
    assert!(service.verify_evidence(record.evidence(), &scope).is_err());
    assert!(consumer.consume(&record).is_err());
    assert!(
        consumer
            .consume_evidence(record.evidence().clone())
            .is_err()
    );
}

#[test]
fn provider_origin_seal_rejects_mutation_resealing_and_mission_tampering() {
    let scope = scope();
    let service = service();
    let mut provider = service
        .register(
            scope.clone(),
            secret(&scope),
            FixtureVaultTransport::default(),
        )
        .expect("provider");
    let proposal = service
        .propose(&mut provider, &VaultReadRequest::health_only(53))
        .expect("proposal");
    let record = service.record(proposal.clone()).expect("record");
    let mut tampered = proposal.evidence().clone();
    tampered.provider_version = "caller-resealed-provider".to_owned();
    tampered.evidence_digest = Digest::from_text("caller-resealed-digest");
    assert!(tampered.validate().is_err());
    assert!(service.verify_evidence(&tampered, &scope).is_err());
    let serialized = serde_json::to_value(proposal.evidence()).expect("evidence json");
    assert!(serde_json::from_value::<VaultGovernanceEvidence>(serialized).is_err());

    let consumer = MissionVaultGovernanceConsumer::new(
        scope.clone(),
        record.evidence().registration_digest.clone(),
    );
    let result = consumer.consume(&record).expect("mission result");
    let mut observation_tampered = result.clone();
    observation_tampered.observation.evidence_digest = Digest::from_text("observation-tamper");
    assert!(observation_tampered.validate(&scope).is_err());
    let mut evidence_tampered = result;
    evidence_tampered.evidence.provider_digest = Digest::from_text("origin-tamper");
    assert!(evidence_tampered.validate(&scope).is_err());
}

#[test]
fn exact_provider_registration_and_mission_bindings_are_verified() {
    let mut definition = VaultProviderDefinition::new(
        VAULT_GOVERNANCE_RESULT_SERVICE_VERSION,
        ProviderProvenance::Fixture,
    )
    .expect("definition");
    definition.provider_digest = Digest::from_text("tampered-provider");
    assert!(definition.validate().is_err());

    let scope = scope();
    let mut provider = service()
        .register(
            scope.clone(),
            secret(&scope),
            FixtureVaultTransport::default(),
        )
        .expect("provider");
    let evidence = provider
        .read(&VaultReadRequest::health_only(41))
        .expect("evidence");
    let mut tampered = evidence;
    tampered.provider_digest = Digest::from_text("tampered-provider");
    assert!(service().verify_evidence(&tampered, &scope).is_err());

    let consumer = MissionVaultGovernanceConsumer::new(scope, Digest::from_text("wrong"));
    let record = service()
        .record(
            service()
                .propose(&mut provider, &VaultReadRequest::health_only(42))
                .expect("proposal"),
        )
        .expect("record");
    assert!(matches!(
        consumer.consume(&record),
        Err(VaultGovernanceError::StaleEvidence | VaultGovernanceError::EvidenceDigestMismatch)
    ));
}

#[test]
fn secret_revision_role_and_time_window_are_scope_fences() {
    let base = VaultScope::new(
        "team/window",
        "kv",
        [VaultPath::new("apps/window/config").expect("path")],
        "mission-window",
        1,
        "project-window",
        1,
    )
    .expect("base scope");
    let reference = SecretReference::new_with_window(
        "s.window-secret",
        &base,
        8,
        VaultSecretRole::ObservationOnly,
        100,
        200,
    )
    .expect("reference");
    let scope = base.bind_secret_reference(&reference).expect("bound scope");
    let mut provider = service()
        .register(scope.clone(), reference, FixtureVaultTransport::default())
        .expect("provider");
    assert!(provider.read(&VaultReadRequest::health_only(99)).is_err());
    assert!(provider.read(&VaultReadRequest::health_only(100)).is_ok());
    assert!(provider.read(&VaultReadRequest::health_only(200)).is_err());
}
