use std::collections::BTreeMap;

use chrono::{Duration, TimeZone, Utc};
use hartevo_supabase_identity_plugin::{
    AuthIdentityObservation, CONTRACT_JSON, ClaimValue, CredentialAuthority, DatabaseGrant,
    DatabasePrivilege, EvidenceProvenance, EvidenceStatus, IdentityProjection, IdentityState,
    JwtClaimsEvidence, MissionScope, MissionSupabaseIdentityConsumer, PROVIDER_API_REVISION,
    PolicyDecision, PolicyProjection, ProjectionReason, RecordingSupabaseTransport,
    RegistrationState, RlsPolicyEvidence, SecretReference, SupabaseHttpsTransport,
    SupabaseIdentityError, SupabaseIdentityProvider, SupabaseIdentityService, SupabaseOperation,
    SupabasePermissionSet, SupabaseProviderError, SupabaseScope, TransportMode, connected,
    contract_digest, identity_authority, native, truth_authority,
};
use serde_json::Value;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
        .single()
        .expect("fixed test time")
}

fn scope() -> SupabaseScope {
    SupabaseScope::fixture()
}

fn service_with(
    transport: &RecordingSupabaseTransport,
) -> (SupabaseIdentityService, SupabaseScope, SecretReference) {
    let scope = scope();
    let permissions = SupabasePermissionSet::layer1(&scope).expect("permissions");
    let provider =
        SupabaseIdentityProvider::new(&scope, &permissions, transport.clone()).expect("provider");
    let secret = SecretReference::oauth("opaque-ref-1", &scope, 1).expect("secret reference");
    let service = SupabaseIdentityService::register(
        provider,
        "registration-1",
        scope.clone(),
        permissions,
        secret.clone(),
    )
    .expect("service");
    (service, scope, secret)
}

fn recompute_identity_digest(observation: &mut AuthIdentityObservation) {
    observation.response_digest = observation
        .expected_response_digest()
        .expect("identity digest");
}

fn recompute_policy_digest(
    observation: &mut hartevo_supabase_identity_plugin::PostgrestMetadataObservation,
) {
    observation.response_digest = observation
        .expected_response_digest()
        .expect("policy digest");
}

fn identity_observation(
    scope: &SupabaseScope,
    identity: Option<hartevo_supabase_identity_plugin::SupabaseIdentityRecord>,
    claims: Option<JwtClaimsEvidence>,
) -> AuthIdentityObservation {
    AuthIdentityObservation::new(scope, identity, claims, PROVIDER_API_REVISION, now(), 1024)
        .expect("identity observation")
}

#[test]
fn contract_is_read_only_external_evidence_and_digest_bound() {
    assert!(!connected());
    assert!(!native());
    assert!(!identity_authority());
    assert!(!truth_authority());
    assert!(contract_digest().len() == 64);
    let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
    assert_eq!(contract["connected"], false);
    assert_eq!(contract["native"], false);
    assert_eq!(contract["identityAuthority"], false);
    assert_eq!(contract["truthAuthority"], false);
    assert_eq!(contract["effectAuthority"], false);
    assert_eq!(contract["authentication"]["rawJwt"], false);
    assert_eq!(contract["authentication"]["rawServiceRoleKey"], false);
    assert!(
        contract["forbiddenLayer1Actions"]
            .as_array()
            .expect("forbidden actions")
            .iter()
            .any(|item| item == "write_table")
    );
    assert!(
        contract["layer2Gaps"]
            .as_array()
            .expect("Layer 2 gaps")
            .iter()
            .any(|item| item == "adoption")
    );
}

#[test]
fn secret_reference_is_opaque_and_service_role_is_not_serialized() {
    let scope = scope();
    let service_role = SecretReference::service_role("opaque-ref-service", &scope, 2)
        .expect("service role reference");
    let encoded = serde_json::to_string(&service_role).expect("secret reference JSON");
    assert!(!encoded.contains("service-role"));
    assert!(!encoded.contains("jwt"));
    assert!(!encoded.contains("key"));
    assert!(!encoded.contains("token"));
    let decoded: SecretReference = serde_json::from_str(&encoded).expect("opaque roundtrip");
    assert_eq!(decoded.reference_id(), "opaque-ref-service");
    assert_eq!(decoded.authority(), CredentialAuthority::Unknown);
}

#[test]
fn fixture_identity_claims_are_present_but_never_connected_or_native() {
    let transport = RecordingSupabaseTransport::fixture();
    let (service, scope, _) = service_with(&transport);
    let projection = service.read_identity(now()).expect("identity read");
    let IdentityProjection::Present(evidence) = projection else {
        panic!("fixture identity should be present");
    };
    assert_eq!(evidence.identity.state, IdentityState::Active);
    assert_eq!(evidence.identity.tenant_id, scope.tenant_id);
    assert_eq!(evidence.jwt_claims.audience, scope.auth_audience);
    assert_eq!(evidence.jwt_claims.issuer, scope.auth_issuer);
    assert!(!evidence.connected);
    assert!(!evidence.native);
    assert_eq!(
        evidence.native_status,
        hartevo_supabase_identity_plugin::NativeStatus::BlockedEnv
    );
    assert_eq!(service.provider().provenance(), EvidenceProvenance::Fixture);
}

#[test]
fn jwt_audience_issuer_and_expiry_are_project_scoped_projections() {
    let transport = RecordingSupabaseTransport::recording();
    let (service, scope, _) = service_with(&transport);
    let identity = hartevo_supabase_identity_plugin::SupabaseIdentityRecord::new(
        "user-fixture",
        scope.tenant_id.clone(),
        "authenticated",
        IdentityState::Active,
        PROVIDER_API_REVISION,
    )
    .expect("identity");
    let mut audience_claims = JwtClaimsEvidence::fixture(&scope, now(), "user-fixture");
    audience_claims.audience = "wrong-audience".into();
    let mut audience = identity_observation(&scope, Some(identity.clone()), Some(audience_claims));
    recompute_identity_digest(&mut audience);
    transport.set_identity_observation(audience);
    assert!(matches!(
        service.read_identity(now()).expect("audience projection"),
        IdentityProjection::ScopeMismatch {
            reason: ProjectionReason::WrongAudience,
            ..
        }
    ));

    let mut issuer_claims = JwtClaimsEvidence::fixture(&scope, now(), "user-fixture");
    issuer_claims.issuer = "https://other-project.supabase.co/auth/v1".into();
    let mut issuer = identity_observation(&scope, Some(identity.clone()), Some(issuer_claims));
    recompute_identity_digest(&mut issuer);
    transport.set_identity_observation(issuer);
    assert!(matches!(
        service.read_identity(now()).expect("issuer projection"),
        IdentityProjection::ScopeMismatch {
            reason: ProjectionReason::WrongIssuer,
            ..
        }
    ));

    let expired = JwtClaimsEvidence::new(
        scope.auth_issuer.clone(),
        scope.auth_audience.clone(),
        "user-fixture",
        now() - Duration::hours(2),
        now() - Duration::hours(1),
        None,
        BTreeMap::from([("sub".into(), ClaimValue::String("user-fixture".into()))]),
        "a".repeat(64),
        true,
    )
    .expect("expired claims shape");
    let mut expired_observation = identity_observation(&scope, Some(identity), Some(expired));
    recompute_identity_digest(&mut expired_observation);
    transport.set_identity_observation(expired_observation);
    assert!(matches!(
        service.read_identity(now()).expect("expired projection"),
        IdentityProjection::Expired {
            reason: ProjectionReason::JwtExpired,
            ..
        }
    ));
}

#[test]
fn anon_and_service_role_authority_are_rejected_at_the_mission_boundary() {
    let transport = RecordingSupabaseTransport::fixture();
    let scope = scope();
    let permissions = SupabasePermissionSet::layer1(&scope).expect("permissions");
    let provider =
        SupabaseIdentityProvider::new(&scope, &permissions, transport).expect("provider");
    let anon = SecretReference::anon_key("anon-ref", &scope, 1).expect("anon reference");
    let anon_service = SupabaseIdentityService::register(
        provider.clone(),
        "registration-anon",
        scope.clone(),
        permissions.clone(),
        anon,
    )
    .expect("anon service");
    assert!(matches!(
        anon_service.read_identity(now()).expect("anon projection"),
        IdentityProjection::Denied {
            reason: ProjectionReason::AnonymousCredential,
            ..
        }
    ));

    let service_role = SecretReference::service_role("service-role-ref", &scope, 1)
        .expect("service role reference");
    let rejected = SupabaseIdentityService::register(
        provider,
        "registration-service-role",
        scope,
        permissions,
        service_role,
    );
    assert!(matches!(
        rejected,
        Err(SupabaseIdentityError::ServiceRoleAuthorityRejected)
    ));
}

#[test]
fn tenant_role_project_and_user_crossing_fail_closed() {
    let transport = RecordingSupabaseTransport::recording();
    let (service, scope, _) = service_with(&transport);
    let wrong_tenant = hartevo_supabase_identity_plugin::SupabaseIdentityRecord::new(
        "user-fixture",
        "other-tenant",
        "authenticated",
        IdentityState::Active,
        PROVIDER_API_REVISION,
    )
    .expect("identity");
    let claims = JwtClaimsEvidence::fixture(&scope, now(), "user-fixture");
    let mut observation = identity_observation(&scope, Some(wrong_tenant), Some(claims));
    recompute_identity_digest(&mut observation);
    transport.set_identity_observation(observation);
    assert!(matches!(
        service.read_identity(now()).expect("tenant projection"),
        IdentityProjection::ScopeMismatch {
            reason: ProjectionReason::TenantCrossing,
            ..
        }
    ));

    let wrong_role = hartevo_supabase_identity_plugin::SupabaseIdentityRecord::new(
        "user-fixture",
        scope.tenant_id.clone(),
        "admin",
        IdentityState::Active,
        PROVIDER_API_REVISION,
    )
    .expect("identity");
    let mut observation = identity_observation(
        &scope,
        Some(wrong_role),
        Some(JwtClaimsEvidence::fixture(&scope, now(), "user-fixture")),
    );
    recompute_identity_digest(&mut observation);
    transport.set_identity_observation(observation);
    assert!(matches!(
        service.read_identity(now()).expect("role projection"),
        IdentityProjection::Denied {
            reason: ProjectionReason::RoleNotAllowed,
            ..
        }
    ));

    let wrong_user = hartevo_supabase_identity_plugin::SupabaseIdentityRecord::new(
        "other-user",
        scope.tenant_id.clone(),
        "authenticated",
        IdentityState::Active,
        PROVIDER_API_REVISION,
    )
    .expect("identity");
    let mut observation = identity_observation(
        &scope,
        Some(wrong_user),
        Some(JwtClaimsEvidence::fixture(&scope, now(), "other-user")),
    );
    recompute_identity_digest(&mut observation);
    transport.set_identity_observation(observation);
    assert!(matches!(
        service.read_identity(now()).expect("user projection"),
        IdentityProjection::ScopeMismatch {
            reason: ProjectionReason::ProjectDrift,
            ..
        }
    ));
}

#[test]
fn rls_grants_are_present_and_grant_policy_drift_is_explicit() {
    let transport = RecordingSupabaseTransport::recording();
    let (service, scope, _) = service_with(&transport);
    let policy = service.read_policy(now()).expect("policy read");
    let PolicyProjection::Present(evidence) = policy else {
        panic!("fixture policy should be present");
    };
    assert_eq!(evidence.grant_revision, scope.grant_revision);
    assert_eq!(evidence.policy_revision, scope.policy_revision);
    assert!(!evidence.connected);
    assert!(!evidence.native);

    let table = scope.tables.iter().next().expect("fixture table").clone();
    let grant = DatabaseGrant::select("authenticated", table.clone(), scope.tenant_id.clone())
        .expect("grant");
    let mut mismatch = hartevo_supabase_identity_plugin::PostgrestMetadataObservation::new(
        &scope,
        vec![grant],
        Vec::new(),
        PROVIDER_API_REVISION,
        now(),
        100,
    )
    .expect("mismatch observation");
    recompute_policy_digest(&mut mismatch);
    transport.set_policy_observation(mismatch);
    assert!(matches!(
        service.read_policy(now()).expect("mismatch projection"),
        PolicyProjection::Mismatch {
            reason: ProjectionReason::GrantPolicyMismatch,
            ..
        }
    ));
}

#[test]
fn policy_revision_tenant_crossing_and_tamper_are_distinct() {
    let transport = RecordingSupabaseTransport::recording();
    let (service, scope, _) = service_with(&transport);
    let table = scope.tables.iter().next().expect("fixture table").clone();
    let grant = DatabaseGrant::select("authenticated", table.clone(), scope.tenant_id.clone())
        .expect("grant");
    let policy = RlsPolicyEvidence::allow_read(
        "policy-1",
        table,
        "authenticated",
        scope.tenant_id.clone(),
        scope.policy_revision.clone(),
    )
    .expect("policy");
    let mut drift = hartevo_supabase_identity_plugin::PostgrestMetadataObservation::new(
        &scope,
        vec![grant.clone()],
        vec![policy.clone()],
        PROVIDER_API_REVISION,
        now(),
        100,
    )
    .expect("drift observation");
    drift.policy_revision = "policy-revision-2".into();
    recompute_policy_digest(&mut drift);
    transport.set_policy_observation(drift);
    assert!(matches!(
        service.read_policy(now()).expect("revision projection"),
        PolicyProjection::Mismatch {
            reason: ProjectionReason::PolicyRevisionDrift,
            ..
        }
    ));

    let mut tenant = hartevo_supabase_identity_plugin::PostgrestMetadataObservation::new(
        &scope,
        vec![grant],
        vec![policy],
        PROVIDER_API_REVISION,
        now(),
        100,
    )
    .expect("tenant observation");
    tenant.tenant_id = "other-tenant".into();
    recompute_policy_digest(&mut tenant);
    transport.set_policy_observation(tenant);
    assert!(matches!(
        service.read_policy(now()).expect("tenant projection"),
        PolicyProjection::ScopeMismatch {
            reason: ProjectionReason::ProjectDrift,
            ..
        }
    ));

    let mut tampered = hartevo_supabase_identity_plugin::PostgrestMetadataObservation::new(
        &scope,
        Vec::new(),
        Vec::new(),
        PROVIDER_API_REVISION,
        now(),
        100,
    )
    .expect("tampered observation");
    tampered.grant_revision = "tampered".into();
    transport.set_policy_observation(tampered);
    assert!(matches!(
        service.read_policy(now()).expect("tamper projection"),
        PolicyProjection::Tampered {
            reason: ProjectionReason::IntegrityFailure,
            ..
        }
    ));
}

#[test]
fn provider_http_faults_timeout_server_and_blocked_env_are_projected_without_native_claims() {
    let transport = RecordingSupabaseTransport::recording();
    let (service, _, _) = service_with(&transport);
    for status in [401_u16, 403, 404, 409, 429, 503] {
        transport.set_fault(SupabaseProviderError::from_http_status(status));
        let projection = service.read_identity(now()).expect("fault projection");
        match status {
            401 | 403 => assert_eq!(projection.status(), EvidenceStatus::Denied),
            404 => assert_eq!(projection.status(), EvidenceStatus::Absent),
            409 => assert_eq!(projection.status(), EvidenceStatus::ScopeMismatch),
            429 | 503 => assert_eq!(projection.status(), EvidenceStatus::ProviderUnknown),
            _ => unreachable!(),
        }
        transport.clear_fault();
    }
    transport.set_fault(SupabaseProviderError::Timeout);
    assert_eq!(
        service
            .read_identity(now())
            .expect("timeout projection")
            .status(),
        EvidenceStatus::ProviderUnknown
    );
    transport.clear_fault();

    let blocked = RecordingSupabaseTransport::blocked_env();
    let (service, _, _) = service_with(&blocked);
    assert_eq!(
        service
            .read_identity(now())
            .expect("blocked projection")
            .status(),
        EvidenceStatus::ProviderUnknown
    );
    assert!(!blocked.mode().is_connected());
    assert!(!blocked.mode().is_native());
    assert_eq!(blocked.mode(), TransportMode::BlockedEnv);
}

#[test]
fn registration_is_reversible_and_revocable() {
    let transport = RecordingSupabaseTransport::fixture();
    let (mut service, scope, _) = service_with(&transport);
    assert_eq!(service.registration().state, RegistrationState::Active);
    service.reverse_registration().expect("reverse");
    assert!(matches!(
        service.read_identity(now()),
        Err(SupabaseIdentityError::RegistrationInactive)
    ));
    service.restore_registration().expect("restore");
    assert_eq!(
        service.read_identity(now()).expect("restored").status(),
        EvidenceStatus::Present
    );
    service.revoke_registration().expect("revoke");
    assert_eq!(service.registration().scope_digest, scope.digest());
    assert!(matches!(
        service.read_policy(now()),
        Err(SupabaseIdentityError::RegistrationRevoked)
    ));
}

#[test]
fn mission_consumer_binds_proposal_and_keeps_layer2_gaps_explicit() {
    let transport = RecordingSupabaseTransport::fixture();
    let (service, scope, _) = service_with(&transport);
    let mission = scope.mission.clone();
    let table = scope.tables.iter().next().expect("table").clone();
    let consumer = MissionSupabaseIdentityConsumer::new(service);
    let result = consumer
        .inspect_and_propose(
            &mission,
            now(),
            PolicyDecision::AllowRead,
            table,
            "authenticated",
            DatabasePrivilege::Select,
            "read-policy-review",
        )
        .expect("mission result");
    assert!(result.evidence.is_positive());
    let proposal = result.proposal.expect("proposal");
    assert_eq!(proposal.effective_decision, PolicyDecision::AllowRead);
    assert!(!proposal.connected);
    assert!(!proposal.native);
    assert!(!proposal.durable_receipt);
    assert!(!proposal.adopted);
    assert_eq!(
        proposal.provider_authority,
        "external_provider_policy_evidence_only"
    );
    proposal.verify_integrity().expect("proposal integrity");
    assert!(consumer.service().registration().is_active());

    let foreign_mission = MissionScope::new(
        "mission-foreign",
        1,
        mission.project_id.clone(),
        mission.work_product_id.clone(),
        mission.consent_reference.clone(),
        mission.consent_revision,
        mission.tenant_id.clone(),
    )
    .expect("foreign mission");
    assert!(matches!(
        consumer.inspect(&foreign_mission, now()),
        Err(SupabaseIdentityError::MissionScopeMismatch)
    ));
}

#[test]
fn policy_mismatch_downgrades_allow_proposal_to_review() {
    let transport = RecordingSupabaseTransport::recording();
    let (service, scope, _) = service_with(&transport);
    let table = scope.tables.iter().next().expect("table").clone();
    let grant = DatabaseGrant::select("authenticated", table.clone(), scope.tenant_id.clone())
        .expect("grant");
    let mut observation = hartevo_supabase_identity_plugin::PostgrestMetadataObservation::new(
        &scope,
        vec![grant],
        Vec::new(),
        PROVIDER_API_REVISION,
        now(),
        100,
    )
    .expect("mismatch observation");
    recompute_policy_digest(&mut observation);
    transport.set_policy_observation(observation);
    let service = service;
    let evidence = service.read_evidence(now()).expect("evidence");
    let proposal = service
        .compile_policy_decision_proposal(
            &scope.mission,
            &evidence,
            PolicyDecision::AllowRead,
            table,
            "authenticated",
            DatabasePrivilege::Select,
            "grant-policy-mismatch",
        )
        .expect("review proposal");
    assert_eq!(proposal.effective_decision, PolicyDecision::ReviewRequired);
}

#[test]
fn provider_calls_contain_digests_and_opaque_reference_ids_only() {
    let transport = RecordingSupabaseTransport::recording();
    let (service, _, secret) = service_with(&transport);
    let _ = service.read_identity(now()).expect("identity");
    let _ = service.read_policy(now()).expect("policy");
    let calls = transport.calls();
    assert_eq!(calls.len(), 2);
    let serialized = serde_json::to_string(&calls).expect("calls JSON");
    assert!(serialized.contains(secret.reference_id()));
    assert!(!serialized.contains("access_token"));
    assert!(!serialized.contains("service_role_key"));
    assert!(!serialized.contains("password"));
}

#[test]
fn operation_set_has_no_write_or_kernel_authority_operation() {
    let scope = scope();
    let permissions = SupabasePermissionSet::layer1(&scope).expect("permissions");
    assert!(
        permissions
            .operations
            .contains(&SupabaseOperation::CompilePolicyDecisionProposal)
    );
    assert!(!permissions.service_role_allowed);
    assert!(!permissions.mutation_allowed);
    assert!(permissions.operations.iter().all(|operation| matches!(
        operation,
        SupabaseOperation::DescribeCapabilities
            | SupabaseOperation::ProbeRegistration
            | SupabaseOperation::ReadProjectMetadata
            | SupabaseOperation::ReadAuthIdentity
            | SupabaseOperation::ReadJwtClaimEvidence
            | SupabaseOperation::ReadDatabaseGrants
            | SupabaseOperation::ReadRlsPolicyMetadata
            | SupabaseOperation::CompilePolicyDecisionProposal
    )));
}
