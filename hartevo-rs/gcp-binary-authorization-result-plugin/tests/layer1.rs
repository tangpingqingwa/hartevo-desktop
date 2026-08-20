use std::collections::BTreeSet;

use hartevo_gcp_binary_authorization_result_plugin::*;

type TestService = GcpBinaryAuthorizationService<
    GcpBinaryAuthorizationProvider<RecordingGcpBinaryAuthorizationTransport>,
>;

struct Fixture {
    scope: GcpBinaryAuthorizationScope,
    secret: SecretReference,
    policy: PolicySummary,
    attestor: AttestorSummary,
    service: TestService,
}

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn fixture() -> Fixture {
    let scope = GcpBinaryAuthorizationScope::new(
        ProjectId::new("project-1").expect("project"),
        PolicyId::new("policy-1").expect("policy"),
        [AttestorId::new("attestor-1").expect("attestor")],
        ImageDigest::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("image"),
        Platform::gke(),
        MissionId::new("mission-1").expect("mission"),
        WorkProductId::new("work-product-1").expect("work product"),
        Revision::new(7).expect("revision"),
        digest("permission-revision-1"),
        digest("consent-revision-1"),
    )
    .expect("scope");
    let secret = SecretReference::new(
        "opaque-gcp-secret-reference",
        &scope,
        Revision::new(3).expect("credential revision"),
        GcpAuthKind::OAuth,
    )
    .expect("secret reference");
    let policy = PolicySummary::new(
        &scope,
        Revision::new(2).expect("policy revision"),
        [AttestorId::new("attestor-1").expect("attestor")],
        PolicyDefaultAction::Deny,
    )
    .expect("policy");
    let attestor = AttestorSummary::new(
        &scope,
        AttestorId::new("attestor-1").expect("attestor"),
        Revision::new(4).expect("attestor revision"),
        false,
        Some(digest("public-key-digest-only")),
    )
    .expect("attestor");
    let provider = GcpBinaryAuthorizationProvider::new(
        RecordingGcpBinaryAuthorizationTransport::default(),
        "1.0.0",
        ProviderProvenance::Recording,
    )
    .expect("provider");
    let service = GcpBinaryAuthorizationService::new(scope.clone(), secret.clone(), provider)
        .expect("service");
    Fixture {
        scope,
        secret,
        policy,
        attestor,
        service,
    }
}

fn occurrence() -> Digest {
    digest("attestation-occurrence-1")
}

fn queue_policy_and_attestor(fixture: &mut Fixture) {
    let fence = fixture
        .scope
        .provider_fence(&fixture.secret)
        .expect("provider fence");
    let policy_request = PolicyGetRequest::new(&fixture.scope, &fence).expect("policy request");
    let attestor_request = AttestorGetRequest::new(
        &fixture.scope,
        &fence,
        fixture.attestor.attestor_id().clone(),
    )
    .expect("attestor request");
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_policy_response(Ok(PolicyGetResponse::new(
            &policy_request,
            fixture.policy.clone(),
        )));
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_attestor_response(Ok(AttestorGetResponse::new(
            &attestor_request,
            fixture.attestor.clone(),
        )));
}

fn proposal(fixture: &Fixture) -> GcpBinaryAuthorizationProposal {
    fixture
        .service
        .propose_validate_attestation_occurrence(
            fixture.policy.clone(),
            fixture.attestor.clone(),
            occurrence(),
        )
        .expect("proposal")
}

#[test]
fn contract_and_authority_are_explicitly_layer_one() {
    GcpBinaryAuthorizationContract::baseline().expect("contract");
    assert_eq!(GCP_BINARY_AUTHORIZATION_RESULT_EVIDENCE_LEVEL, "E1");
    assert_eq!(GCP_BINARY_AUTHORIZATION_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
    assert!(!Layer1Authority::connected());
    assert!(!Layer1Authority::native_provider());
    assert!(!Layer1Authority::consent());
    assert!(!Layer1Authority::effect());
    assert!(!Layer1Authority::durable_receipt());
    assert!(!Layer1Authority::adopted_outcome());
    assert!(!Layer1Authority::raw_keys());
    assert!(!Layer1Authority::raw_attestation_payload());
}

#[test]
fn secret_reference_is_opaque_and_auth_kind_is_typed() {
    let fixture = fixture();
    let debug = format!("{:?}", fixture.secret);
    assert!(!debug.contains("opaque-gcp-secret-reference"));
    assert_eq!(fixture.secret.auth_kind(), GcpAuthKind::OAuth);
    assert_eq!(fixture.secret.scope_digest(), fixture.scope.scope_digest());
    assert!(!fixture.secret.is_revoked());
}

#[test]
fn policy_and_attestor_get_are_bound_to_project_policy_and_scope() {
    let mut fixture = fixture();
    queue_policy_and_attestor(&mut fixture);
    let policy_evidence = fixture.service.get_policy().expect("policy evidence");
    let attestor_response = fixture
        .service
        .get_attestor(fixture.attestor.attestor_id().clone())
        .expect("attestor evidence");
    assert_eq!(
        policy_evidence.policy.policy_id(),
        fixture.scope.policy_id()
    );
    assert_eq!(policy_evidence.scope_digest, *fixture.scope.scope_digest());
    assert_eq!(
        attestor_response.attestor.attestor_id(),
        fixture.attestor.attestor_id()
    );
    assert_eq!(
        attestor_response.observed_fence.scope_digest(),
        fixture.scope.scope_digest()
    );
    assert_eq!(fixture.service.provider().transport().policy_calls(), 1);
    assert_eq!(fixture.service.provider().transport().attestor_calls(), 1);
}

#[test]
fn allow_proposal_record_verify_and_mission_consume_are_non_native() {
    let mut fixture = fixture();
    queue_policy_and_attestor(&mut fixture);
    fixture.service.get_policy().expect("policy evidence");
    fixture
        .service
        .get_attestor(fixture.attestor.attestor_id().clone())
        .expect("attestor evidence");
    let proposal = proposal(&fixture);
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_validation_response(Ok(ValidationResponse::allow(
            &proposal.request,
            &fixture.policy,
            &fixture.attestor,
        )));
    let record = fixture
        .service
        .record_validate_attestation_occurrence(proposal)
        .expect("record");
    let verification = fixture
        .service
        .verify_validate_attestation_occurrence(&record)
        .expect("verification seam");
    assert_eq!(verification.decision(), ValidationDecision::Allow);
    assert!(verification.structurally_valid);
    assert!(!verification.evidence.is_adopted());
    assert_eq!(
        verification.evidence.completeness,
        EvidenceCompleteness::Complete
    );
    assert_eq!(
        verification.evidence.provenance,
        ProviderProvenance::Recording
    );
    assert_eq!(
        verification.evidence.digests.scope_digest,
        *fixture.scope.scope_digest()
    );
    assert!(!Layer1EvidenceAuthority::connected());
    assert!(!Layer1EvidenceAuthority::native_provider());
    assert!(!Layer1EvidenceAuthority::effect());

    let mut consumer = MissionGcpBinaryAuthorizationConsumer::new(
        fixture.scope.clone(),
        fixture.service.registration(),
    )
    .expect("consumer");
    let result = consumer.consume(verification).expect("Mission result");
    assert_eq!(result.project_id, *fixture.scope.project_id());
    assert_eq!(result.mission_id, *fixture.scope.mission_id());
    assert_eq!(result.work_product_id, *fixture.scope.work_product_id());
    assert_eq!(result.decision, ValidationDecision::Allow);
    assert_eq!(
        result.state,
        MissionGcpBinaryAuthorizationState::PendingDecision
    );
    assert!(!result.adopted_outcome);
    assert!(!result.durable_adoption);
}

#[test]
fn all_four_validation_decisions_are_explicit() {
    let mut fixture = fixture();
    let policy = fixture.policy.clone();
    let attestor = fixture.attestor.clone();
    let deny_proposal = proposal(&fixture);
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_validation_response(Ok(ValidationResponse::deny(
            &deny_proposal.request,
            &policy,
            &attestor,
            ValidationReason::PolicyDeny,
            BTreeSet::new(),
        )));
    let deny_record = fixture
        .service
        .record_validate_attestation_occurrence(deny_proposal)
        .expect("deny record");
    assert_eq!(
        fixture
            .service
            .verify_validate_attestation_occurrence(&deny_record)
            .expect("deny verification")
            .decision(),
        ValidationDecision::Deny
    );

    let error_proposal = fixture
        .service
        .propose_validate_attestation_occurrence(policy.clone(), attestor.clone(), digest("error"))
        .expect("error proposal");
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_validation_response(Ok(ValidationResponse::error(
            &error_proposal.request,
            ProviderErrorEvidence::new(
                ProviderErrorKind::PermissionDenied,
                Some(403),
                false,
                "permission-denied",
            ),
        )));
    let error_record = fixture
        .service
        .record_validate_attestation_occurrence(error_proposal)
        .expect("error record");
    assert_eq!(
        fixture
            .service
            .verify_validate_attestation_occurrence(&error_record)
            .expect("error verification")
            .decision(),
        ValidationDecision::Error
    );

    let unknown_proposal = fixture
        .service
        .propose_validate_attestation_occurrence(policy, attestor, digest("unknown"))
        .expect("unknown proposal");
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_validation_response(Ok(ValidationResponse::unknown(
            &unknown_proposal.request,
            ProviderErrorEvidence::new(ProviderErrorKind::Unknown, None, false, "provider-unknown"),
        )));
    let unknown_record = fixture
        .service
        .record_validate_attestation_occurrence(unknown_proposal)
        .expect("unknown record");
    assert_eq!(
        fixture
            .service
            .verify_validate_attestation_occurrence(&unknown_record)
            .expect("unknown verification")
            .decision(),
        ValidationDecision::Unknown
    );
}

#[test]
fn image_binding_replay_and_tamper_fail_closed() {
    let fixture = fixture();
    let first = proposal(&fixture);
    let second = fixture
        .service
        .propose_validate_attestation_occurrence(
            fixture.policy.clone(),
            fixture.attestor.clone(),
            digest("second-occurrence"),
        )
        .expect("second proposal");
    let response = ValidationResponse::allow(&first.request, &fixture.policy, &fixture.attestor);
    assert!(matches!(
        fixture
            .service
            .record_validate_attestation_occurrence_response(second, response.clone()),
        Err(GcpBinaryAuthorizationServiceError::ReplayDetected)
    ));

    let mut tampered = response;
    tampered.decision = ValidationDecision::Deny;
    assert!(matches!(
        fixture
            .service
            .record_validate_attestation_occurrence_response(first.clone(), tampered),
        Err(GcpBinaryAuthorizationServiceError::TamperDetected)
    ));

    let wrong_image = AttestationOccurrenceReference::new(
        digest("wrong-image-occurrence"),
        ImageDigest::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("wrong image"),
        fixture.attestor.attestor_id().clone(),
    )
    .expect("occurrence reference");
    assert!(matches!(
        fixture
            .service
            .propose_validate_attestation_occurrence_reference(
                fixture.policy.clone(),
                fixture.attestor.clone(),
                wrong_image,
            ),
        Err(GcpBinaryAuthorizationServiceError::ImageDigestMismatch)
    ));
}

#[test]
fn revocation_partial_and_access_loss_are_retained_as_adversarial_evidence() {
    let mut fixture = fixture();
    let revoked_attestor = AttestorSummary::new(
        &fixture.scope,
        fixture.attestor.attestor_id().clone(),
        Revision::new(5).expect("attestor revision"),
        true,
        Some(digest("revoked-public-key-digest")),
    )
    .expect("revoked attestor");
    let revoked_proposal = fixture
        .service
        .propose_validate_attestation_occurrence(
            fixture.policy.clone(),
            revoked_attestor.clone(),
            digest("revoked-occurrence"),
        )
        .expect("revoked proposal");
    let mut revocation = BTreeSet::new();
    revocation.insert(AdversarialFinding::Revocation);
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_validation_response(Ok(ValidationResponse::deny(
            &revoked_proposal.request,
            &fixture.policy,
            &revoked_attestor,
            ValidationReason::AttestorRevoked,
            revocation,
        )));
    let revoked_record = fixture
        .service
        .record_validate_attestation_occurrence(revoked_proposal)
        .expect("revoked record");
    let revoked_evidence = fixture
        .service
        .verify_validate_attestation_occurrence(&revoked_record)
        .expect("revoked verification")
        .evidence;
    assert_eq!(revoked_evidence.decision, ValidationDecision::Deny);
    assert!(
        revoked_evidence
            .findings
            .contains(&AdversarialFinding::Revocation)
    );

    let partial_proposal = proposal(&fixture);
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_validation_response(Err(TransportError::partial()));
    let partial_record = fixture
        .service
        .record_validate_attestation_occurrence(partial_proposal)
        .expect("partial record");
    let partial_evidence = fixture
        .service
        .verify_validate_attestation_occurrence(&partial_record)
        .expect("partial verification")
        .evidence;
    assert_eq!(partial_evidence.decision, ValidationDecision::Unknown);
    assert_eq!(partial_evidence.completeness, EvidenceCompleteness::Partial);
    assert!(
        partial_evidence
            .findings
            .contains(&AdversarialFinding::Partial)
    );

    let access_lost_proposal = fixture
        .service
        .propose_validate_attestation_occurrence(
            fixture.policy.clone(),
            fixture.attestor.clone(),
            digest("access-lost-occurrence"),
        )
        .expect("access-lost proposal");
    fixture
        .service
        .provider_mut()
        .transport_mut()
        .push_validation_response(Err(TransportError::access_lost()));
    let access_lost_record = fixture
        .service
        .record_validate_attestation_occurrence(access_lost_proposal)
        .expect("access-lost record");
    let access_lost_evidence = fixture
        .service
        .verify_validate_attestation_occurrence(&access_lost_record)
        .expect("access-lost verification")
        .evidence;
    assert_eq!(access_lost_evidence.decision, ValidationDecision::Unknown);
    assert_eq!(
        access_lost_evidence.completeness,
        EvidenceCompleteness::AccessLost
    );
    assert!(
        access_lost_evidence
            .findings
            .contains(&AdversarialFinding::AccessLoss)
    );
}

#[test]
fn registration_and_provider_fences_are_reversible_and_fail_closed() {
    let mut fixture = fixture();
    let original_registration = fixture.service.registration().registration_digest.clone();
    fixture
        .service
        .revoke_registration()
        .expect("revoke registration");
    assert!(!fixture.service.is_active());
    assert!(matches!(
        fixture.service.get_policy(),
        Err(GcpBinaryAuthorizationServiceError::Revoked)
    ));
    assert_ne!(
        fixture.service.registration().registration_digest,
        original_registration
    );

    let mut secret = fixture.secret;
    secret.revoke().expect("secret revoke");
    assert!(secret.is_revoked());
    assert!(matches!(
        fixture.scope.provider_fence(&secret),
        Err(ModelError::Revoked)
    ));

    let authority = ConsentEffectFence::read_only(&fixture.scope);
    assert!(!authority.effect_requested());
    assert!(authority.effect_receipt_digest().is_none());
    authority
        .validate_for(&fixture.scope)
        .expect("read-only Consent/Effect fence");
}
