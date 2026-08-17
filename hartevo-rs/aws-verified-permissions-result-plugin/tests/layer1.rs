use hartevo_aws_verified_permissions_result_plugin::{
    AccountId, ActionReference, AuthorizationDecision, AwsRegion, AwsVerifiedPermissionsProvider,
    AwsVerifiedPermissionsScope, ConsentReference, ContextReference, Digest, EffectGate,
    EffectState, EvidenceState, FakeAwsVerifiedPermissionsTransport,
    FixtureAwsVerifiedPermissionsTransport, KernelAuthorizationFence, KernelEffectReference,
    LoopbackAwsVerifiedPermissionsTransport, MissionAwsVerifiedPermissionsConsumer, ModelError,
    PolicyStoreId, PrincipalReference, ProjectId, ProviderError, ProviderErrorKind,
    ProviderProvenance, RecordingTransport, RegistrationState, ResourceReference, Revision,
    SecretReference, TransportError, VerificationState, WorkProductId,
};

const PROVIDER_VERSION: &str = "1.0.0";

fn digest(label: &str) -> Digest {
    Digest::from_text(label)
}

fn scope_and_secret() -> (AwsVerifiedPermissionsScope, SecretReference) {
    let consent =
        ConsentReference::granted(digest("kernel-consent"), Revision::new(1).unwrap()).unwrap();
    let scope = AwsVerifiedPermissionsScope::new(
        AccountId::new("123456789012").unwrap(),
        AwsRegion::new("us-east-1").unwrap(),
        PolicyStoreId::new("store-layer1").unwrap(),
        PrincipalReference::from_text("person@example.invalid").unwrap(),
        ActionReference::from_text("read-report").unwrap(),
        ResourceReference::from_text("arn:example:private-report").unwrap(),
        ContextReference::from_text("tenant=production;classification=private"),
        ProjectId::new("project-layer1").unwrap(),
        hartevo_aws_verified_permissions_result_plugin::MissionId::new("mission-layer1").unwrap(),
        WorkProductId::new("work-product-layer1").unwrap(),
        Revision::new(7).unwrap(),
        consent,
        digest("permission-snapshot"),
        digest("policy-snapshot"),
    )
    .unwrap();
    let secret = SecretReference::new(
        "keyring/sigv4/private-reference",
        &scope,
        Revision::new(3).unwrap(),
    )
    .unwrap();
    (scope, secret)
}

fn fence(
    scope: &AwsVerifiedPermissionsScope,
    effect_state: EffectState,
) -> KernelAuthorizationFence {
    KernelAuthorizationFence::new(
        scope.consent().clone(),
        KernelEffectReference::new(
            digest("kernel-effect"),
            Revision::new(9).unwrap(),
            effect_state,
        )
        .unwrap(),
    )
}

fn allow_provider() -> AwsVerifiedPermissionsProvider<FakeAwsVerifiedPermissionsTransport> {
    AwsVerifiedPermissionsProvider::new(
        FakeAwsVerifiedPermissionsTransport::new(AuthorizationDecision::Allow),
        PROVIDER_VERSION,
        ProviderProvenance::Fake,
    )
    .unwrap()
}

#[test]
fn service_and_contract_are_layer_one_only() {
    let service =
        hartevo_aws_verified_permissions_result_plugin::AwsVerifiedPermissionsService::new();
    service.validate().unwrap();
    assert_eq!(service.capabilities().len(), 8);
    assert!(service.read_only());
    assert!(!service.live_execution());
    assert!(!service.policy_mutation());
    assert!(!service.external_action_execution());
    assert!(
        service
            .capabilities()
            .iter()
            .all(|capability| !capability.mutates_policy
                && !capability.executes_external_action
                && !capability.native_evidence)
    );
    assert_eq!(
        hartevo_aws_verified_permissions_result_plugin::contract_digest(),
        digest(
            hartevo_aws_verified_permissions_result_plugin::AWS_VERIFIED_PERMISSIONS_CONTRACT_JSON
        )
    );
}

#[test]
fn sigv4_secret_is_opaque_and_non_serializing() {
    let (scope, secret) = scope_and_secret();
    let debug = format!("{secret:?}");
    assert!(!debug.contains("keyring/sigv4/private-reference"));
    assert!(debug.contains(secret.reference_digest().as_str()));
    assert!(secret.validate_for_scope(&scope).is_ok());
    assert_eq!(
        secret.signing_service(),
        hartevo_aws_verified_permissions_result_plugin::SigV4SigningService::VerifiedPermissions
    );
}

#[test]
fn allow_requires_kernel_fences_and_never_becomes_effect_authority() {
    let (scope, secret) = scope_and_secret();
    let mut provider = allow_provider();
    let registration = provider.register(&scope).unwrap();
    let proposal = provider.propose(&scope, &secret).unwrap();
    assert_eq!(proposal.decision, AuthorizationDecision::Allow);
    assert_eq!(
        proposal.effect_gate,
        EffectGate::KernelConsentAndEffectRequired
    );
    let mut consumer =
        MissionAwsVerifiedPermissionsConsumer::new(scope.clone(), &registration).unwrap();
    let record = consumer
        .record(proposal, &fence(&scope, EffectState::Pending))
        .unwrap();
    let verification = consumer
        .verify(record, &fence(&scope, EffectState::Pending))
        .unwrap();
    assert_eq!(verification.verification_state, VerificationState::Verified);
    assert_eq!(
        verification.effect_gate,
        EffectGate::KernelConsentAndEffectRequired
    );
    assert!(!verification.execution_permitted);
    let result = consumer.consume(&verification).unwrap();
    assert!(!result.authority.connected());
    assert!(!result.authority.native());
    assert!(!result.authority.truth());
    assert!(!result.authority.adopted());
}

#[test]
fn provider_allow_cannot_use_denied_effect_or_withdrawn_consent_fence() {
    let (scope, secret) = scope_and_secret();
    let mut provider = allow_provider();
    let registration = provider.register(&scope).unwrap();
    let proposal = provider.propose(&scope, &secret).unwrap();
    let mut consumer =
        MissionAwsVerifiedPermissionsConsumer::new(scope.clone(), &registration).unwrap();
    let denied_effect = fence(&scope, EffectState::Denied);
    assert!(matches!(
        consumer.record(proposal.clone(), &denied_effect),
        Err(hartevo_aws_verified_permissions_result_plugin::ConsumerError::EffectFenceMismatch)
    ));
    let withdrawn_consent = ConsentReference::withdrawn(
        scope.consent().consent_digest.clone(),
        scope.consent().revision,
    )
    .unwrap();
    let withdrawn_fence = KernelAuthorizationFence::new(
        withdrawn_consent,
        KernelEffectReference::pending(digest("kernel-effect"), Revision::new(9).unwrap()).unwrap(),
    );
    assert!(matches!(
        consumer.record(proposal, &withdrawn_fence),
        Err(hartevo_aws_verified_permissions_result_plugin::ConsumerError::ConsentMismatch)
    ));
}

#[test]
fn deny_and_indeterminate_are_explicit_and_bounded() {
    let (scope, secret) = scope_and_secret();
    let mut deny_provider = AwsVerifiedPermissionsProvider::new(
        FakeAwsVerifiedPermissionsTransport::new(AuthorizationDecision::Deny),
        PROVIDER_VERSION,
        ProviderProvenance::Fake,
    )
    .unwrap();
    let registration = deny_provider.register(&scope).unwrap();
    let deny_proposal = deny_provider.propose(&scope, &secret).unwrap();
    assert_eq!(deny_proposal.decision, AuthorizationDecision::Deny);
    let mut consumer =
        MissionAwsVerifiedPermissionsConsumer::new(scope.clone(), &registration).unwrap();
    let deny_record = consumer
        .record(deny_proposal, &fence(&scope, EffectState::NotRequested))
        .unwrap();
    let deny_verification = consumer
        .verify(deny_record, &fence(&scope, EffectState::NotRequested))
        .unwrap();
    assert_eq!(deny_verification.decision, AuthorizationDecision::Deny);
    assert_eq!(deny_verification.effect_gate, EffectGate::NotApplicable);

    let mut unknown_provider = AwsVerifiedPermissionsProvider::new(
        FakeAwsVerifiedPermissionsTransport::with_evidence_state(
            AuthorizationDecision::Indeterminate,
            EvidenceState::Partial,
        ),
        PROVIDER_VERSION,
        ProviderProvenance::Fake,
    )
    .unwrap();
    let unknown_registration = unknown_provider.register(&scope).unwrap();
    let unknown_proposal = unknown_provider.propose(&scope, &secret).unwrap();
    assert_eq!(
        unknown_proposal.decision,
        AuthorizationDecision::Indeterminate
    );
    let mut unknown_consumer =
        MissionAwsVerifiedPermissionsConsumer::new(scope.clone(), &unknown_registration).unwrap();
    let unknown_record = unknown_consumer
        .record(unknown_proposal, &fence(&scope, EffectState::NotRequested))
        .unwrap();
    let unknown_verification = unknown_consumer
        .verify(unknown_record, &fence(&scope, EffectState::NotRequested))
        .unwrap();
    assert_eq!(
        unknown_verification.verification_state,
        VerificationState::Partial
    );
}

#[test]
fn partial_or_access_lost_allow_is_rejected_before_proposal() {
    let (scope, secret) = scope_and_secret();
    for evidence_state in [EvidenceState::Partial, EvidenceState::AccessLost] {
        let mut provider = AwsVerifiedPermissionsProvider::new(
            FakeAwsVerifiedPermissionsTransport::with_evidence_state(
                AuthorizationDecision::Allow,
                evidence_state,
            ),
            PROVIDER_VERSION,
            ProviderProvenance::Fake,
        )
        .unwrap();
        assert!(matches!(
            provider.propose(&scope, &secret),
            Err(ProviderError::UnsafeAllowEvidence)
        ));
    }
}

#[test]
fn context_mismatch_is_rejected_at_verify() {
    let (scope, secret) = scope_and_secret();
    let mut provider = allow_provider();
    let registration = provider.register(&scope).unwrap();
    let proposal = provider.propose(&scope, &secret).unwrap();
    let mut consumer =
        MissionAwsVerifiedPermissionsConsumer::new(scope.clone(), &registration).unwrap();
    let record = consumer
        .record(proposal, &fence(&scope, EffectState::Pending))
        .unwrap();
    let changed_context = ContextReference::from_text("tenant=other");
    assert!(matches!(
        consumer.verify_against_context(
            record,
            &changed_context,
            &fence(&scope, EffectState::Pending)
        ),
        Err(hartevo_aws_verified_permissions_result_plugin::ConsumerError::ContextMismatch)
    ));
}

#[test]
fn tamper_and_replay_are_rejected() {
    let (scope, secret) = scope_and_secret();
    let mut provider = allow_provider();
    let registration = provider.register(&scope).unwrap();
    let proposal = provider.propose(&scope, &secret).unwrap();
    let mut tampered = proposal.clone();
    tampered.evidence_digest = digest("tampered-evidence");
    let mut tamper_consumer =
        MissionAwsVerifiedPermissionsConsumer::new(scope.clone(), &registration).unwrap();
    assert!(matches!(
        tamper_consumer.record(tampered, &fence(&scope, EffectState::Pending)),
        Err(hartevo_aws_verified_permissions_result_plugin::ConsumerError::Tampered)
    ));

    let mut replay_consumer =
        MissionAwsVerifiedPermissionsConsumer::new(scope.clone(), &registration).unwrap();
    let record = replay_consumer
        .record(proposal.clone(), &fence(&scope, EffectState::Pending))
        .unwrap();
    assert!(matches!(
        replay_consumer.record(proposal, &fence(&scope, EffectState::Pending)),
        Err(hartevo_aws_verified_permissions_result_plugin::ConsumerError::ReplayRejected)
    ));
    let mut record_consumer =
        MissionAwsVerifiedPermissionsConsumer::new(scope.clone(), &registration).unwrap();
    let mut tampered_record = record.clone();
    tampered_record.record_digest = digest("tampered-record");
    assert!(matches!(
        record_consumer.verify(tampered_record, &fence(&scope, EffectState::Pending)),
        Err(hartevo_aws_verified_permissions_result_plugin::ConsumerError::Tampered)
    ));
    let first_verification = record_consumer
        .verify(record.clone(), &fence(&scope, EffectState::Pending))
        .unwrap();
    assert_eq!(
        first_verification.verification_state,
        VerificationState::Verified
    );
    assert!(matches!(
        record_consumer.verify(record, &fence(&scope, EffectState::Pending)),
        Err(hartevo_aws_verified_permissions_result_plugin::ConsumerError::ReplayRejected)
    ));
}

#[test]
fn registration_is_digest_bound_revocable_and_explicitly_reissued() {
    let (scope, secret) = scope_and_secret();
    let mut provider = allow_provider();
    let mut registration = provider.register(&scope).unwrap();
    registration.validate_for_scope(&scope).unwrap();
    let original_digest = registration.registration_digest.clone();
    let revocation = registration.revoke().unwrap();
    assert_eq!(revocation.registration_digest, original_digest);
    assert_eq!(registration.state, RegistrationState::Revoked);
    assert!(registration.ensure_active().is_err());
    let reissued = registration.reissue().unwrap();
    assert_eq!(reissued.state, RegistrationState::Active);
    assert_ne!(reissued.registration_digest, original_digest);
    reissued.validate_for_scope(&scope).unwrap();
    let mut revoked_secret = secret.clone();
    revoked_secret.revoke().unwrap();
    assert!(matches!(
        provider.propose(&scope, &revoked_secret),
        Err(ProviderError::Model(ModelError::AlreadyRevoked))
    ));
}

#[test]
fn blocked_env_and_fixture_modes_are_non_native() {
    let (scope, secret) = scope_and_secret();
    for provenance in [
        ProviderProvenance::Fixture,
        ProviderProvenance::Recording,
        ProviderProvenance::Fake,
        ProviderProvenance::Loopback,
        ProviderProvenance::BlockedEnv,
    ] {
        assert!(!provenance.is_native());
    }
    let mut provider = AwsVerifiedPermissionsProvider::new(
        hartevo_aws_verified_permissions_result_plugin::BlockedEnvAwsVerifiedPermissionsTransport,
        PROVIDER_VERSION,
        ProviderProvenance::BlockedEnv,
    )
    .unwrap();
    assert!(matches!(
        provider.propose(&scope, &secret),
        Err(ProviderError::Transport(TransportError {
            kind: ProviderErrorKind::BlockedEnv,
            blocked_env: true,
            ..
        }))
    ));
}

#[test]
fn fixture_recording_and_loopback_transports_are_non_native() {
    let (scope, secret) = scope_and_secret();
    let mut fixture_provider = AwsVerifiedPermissionsProvider::new(
        FixtureAwsVerifiedPermissionsTransport::new(AuthorizationDecision::Deny),
        PROVIDER_VERSION,
        ProviderProvenance::Fixture,
    )
    .unwrap();
    assert_eq!(
        fixture_provider.propose(&scope, &secret).unwrap().decision,
        AuthorizationDecision::Deny
    );

    let mut loopback_provider = AwsVerifiedPermissionsProvider::new(
        LoopbackAwsVerifiedPermissionsTransport::new(AuthorizationDecision::Indeterminate),
        PROVIDER_VERSION,
        ProviderProvenance::Loopback,
    )
    .unwrap();
    assert_eq!(
        loopback_provider.propose(&scope, &secret).unwrap().decision,
        AuthorizationDecision::Indeterminate
    );

    let mut source_provider = allow_provider();
    let source_read = source_provider.is_authorized_read(&scope, &secret).unwrap();
    let mut recording_transport = RecordingTransport::new();
    recording_transport.push_response(source_read.response);
    let mut recording_provider = AwsVerifiedPermissionsProvider::new(
        recording_transport,
        PROVIDER_VERSION,
        ProviderProvenance::Recording,
    )
    .unwrap();
    assert_eq!(
        recording_provider
            .propose(&scope, &secret)
            .unwrap()
            .decision,
        AuthorizationDecision::Allow
    );
    assert_eq!(
        recording_provider.provenance(),
        ProviderProvenance::Recording
    );
    assert!(!recording_provider.provenance().is_native());
}

#[test]
fn evidence_does_not_retain_raw_principal_resource_context_or_secret() {
    let (scope, secret) = scope_and_secret();
    let mut provider = allow_provider();
    let proposal = provider.propose(&scope, &secret).unwrap();
    let serialized = serde_json::to_string(&proposal).unwrap();
    for raw in [
        "person@example.invalid",
        "arn:example:private-report",
        "tenant=production;classification=private",
        "keyring/sigv4/private-reference",
    ] {
        assert!(!serialized.contains(raw), "raw value leaked: {raw}");
    }
}

#[test]
fn response_metadata_is_digest_only_and_request_bound() {
    let (scope, secret) = scope_and_secret();
    let mut provider = allow_provider();
    let read = provider.is_authorized_read(&scope, &secret).unwrap();
    read.validate().unwrap();
    assert_eq!(read.response.principal_digest, *scope.principal().digest());
    assert_eq!(read.response.resource_digest, *scope.resource().digest());
    assert_eq!(read.response.context_digest, *scope.context_digest());
    assert!(read.response.determining_policy.is_some());
    assert_eq!(
        read.response
            .determining_policy
            .as_ref()
            .unwrap()
            .policy_store_digest,
        *scope.policy_store_digest()
    );
}

#[test]
fn transport_errors_are_digest_only() {
    let error = TransportError::access_lost();
    assert_eq!(error.kind, ProviderErrorKind::AccessLost);
    assert_eq!(error.status_code, Some(403));
    assert_eq!(error.diagnostic_digest, digest("access-lost"));
    assert!(!format!("{error:?}").contains("access-lost"));
}
