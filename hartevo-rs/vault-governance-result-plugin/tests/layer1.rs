use hartevo_vault_governance_result_plugin::*;

const PROVIDER_REVISION: &str = VAULT_GOVERNANCE_RESULT_PROVIDER_REVISION;

fn scope() -> VaultScope {
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

fn scope_with_lease() -> (VaultScope, LeaseReference) {
    let lease = LeaseReference::new("database/creds/hartevo/opaque-lease").expect("lease");
    (scope().bind_lease(&lease), lease)
}

fn secret(scope: &VaultScope) -> SecretReference {
    SecretReference::new("s.super-secret-token-material", scope, 4).expect("secret reference")
}

fn service() -> VaultGovernanceResultService {
    VaultGovernanceResultService::new()
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
    assert_eq!(proposal.evidence.provenance, ProviderProvenance::Fixture);
    assert_eq!(
        proposal.evidence.health.as_ref().unwrap().status,
        HealthStatus::Active
    );
    assert_eq!(
        proposal.evidence.token.as_ref().unwrap().status,
        TokenStatus::Active
    );
    assert_eq!(
        proposal.evidence.lease.as_ref().unwrap().status,
        LeaseStatus::Active
    );
    assert!(!proposal.evidence.native_evidence);
    assert!(!proposal.evidence.secret_values_retained);
    assert!(!proposal.evidence.token_material_retained);
    assert!(!provider.is_connected());

    let record = service.record(proposal).expect("record");
    let verification = service.verify(&record, &scope).expect("verification");
    assert!(verification.verified);
    assert!(!verification.native_authority);
    assert!(!verification.truth_authority);

    let consumer = MissionVaultGovernanceConsumer::new(scope.clone())
        .with_registration_digest(record.evidence.registration_digest.clone());
    let result = consumer.consume(&record).expect("mission result");
    assert_eq!(result.observation.mission_id.as_str(), "mission-1");
    assert_eq!(result.observation.project_id.as_str(), "project-1");
    assert_eq!(result.adoption, AdoptionAvailability::NotAdoptedLayer2);
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
        let response = VaultHttpResponse::new(
            VaultOperation::SysHealth,
            status,
            512,
            PROVIDER_REVISION,
            VaultResponsePayload::Health(metadata),
        )
        .expect("response");
        let mut transport = RecordingVaultTransport::default();
        transport.push_response(response);
        let scope = scope();
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
        let response = VaultHttpResponse::new(
            VaultOperation::AuthTokenLookupSelf,
            status,
            128,
            PROVIDER_REVISION,
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
        )
        .expect("response");
        let mut transport = RecordingVaultTransport::default();
        transport.push_response(response);
        let scope = scope();
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
    let mismatched = VaultHttpResponse::new(
        VaultOperation::SysCapabilitiesSelfAllowlisted,
        200,
        256,
        PROVIDER_REVISION,
        VaultResponsePayload::CapabilitiesSelf(vec![
            VaultCapabilityMetadata::new(path.path_digest(), vec![CapabilityClass::Read])
                .expect("capability"),
        ]),
    )
    .expect("response");
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

    let expired = VaultHttpResponse::new(
        VaultOperation::SysLeasesLookupMetadata,
        200,
        256,
        PROVIDER_REVISION,
        VaultResponsePayload::LeaseLookup(VaultLeaseMetadata::new(
            lease.reference_digest().clone(),
            scope.mount().mount_digest(),
            Digest::from_text("lease-path"),
            0,
            true,
        )),
    )
    .expect("response");
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
    let mut tampered = proposal.evidence.clone();
    tampered.provider_version = "9.9.9".to_owned();
    assert!(matches!(
        service().verify_evidence(&tampered, &scope),
        Err(VaultGovernanceError::Model(ModelError::DigestMismatch)
            | VaultGovernanceError::Provider(VaultProviderError::InvalidPayload)
            | VaultGovernanceError::EvidenceDigestMismatch,)
    ));

    let mut partial_transport = RecordingVaultTransport::default();
    partial_transport.push_response(
        VaultHttpResponse::new(
            VaultOperation::SysHealth,
            200,
            128,
            PROVIDER_REVISION,
            VaultResponsePayload::Health(VaultHealthMetadata::default()),
        )
        .expect("response"),
    );
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
    let scope = scope();
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
