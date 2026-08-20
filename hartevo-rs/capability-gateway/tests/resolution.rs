use std::collections::BTreeSet;

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_capability_gateway::{
    AdapterBinding, AdapterId, AdapterRegistry, ApprovalRequirement, BudgetAuthority, BudgetUse,
    CAPABILITY_MANIFEST_SCHEMA, CAPABILITY_REQUEST_SCHEMA, CAPABILITY_RESULT_SCHEMA,
    CapabilityClass, CapabilityCompositionLifecycle, CapabilityCompositionScope,
    CapabilityCompositionSnapshot, CapabilityConsumerDefinition, CapabilityGateway, CapabilityId,
    CapabilityInvocationCloseReason, CapabilityInvocationContext,
    CapabilityInvocationEffectReceipt, CapabilityInvocationError, CapabilityInvocationEventKind,
    CapabilityInvocationVisibility, CapabilityManifest, CapabilityProviderDefinition,
    CapabilityRequest, CapabilityResolutionAuditEventKind, CapabilityResolutionError,
    CapabilityResolutionLease, CapabilityResolutionSelector, CapabilityResult,
    CapabilityServiceDefinition, CapabilityVersion, ContributionLifecycle, CostLimit,
    DataAuthority, DataClass, Digest, EffectAuthority, EffectDisposition, EffectId, EffectKind,
    ExternalEffectRequest, ExternalEffectResult, IdempotencyKey, InvocationScope,
    MAX_INVOCATION_ATTEMPTS, ManifestIssuer, ManifestProvenance, MemoryCapabilityInvocationLog,
    MemoryCapabilityResolutionLedger, MissionId, MissionScope, NetworkAuthority, Origin, ProjectId,
    ProjectScope, Provenance, ProvenanceSource, ReadCompleteness, ReadOperation, ReadRequest,
    ReadResult, RequestId, RequestPayload, ResultPayload, RevocationBinding, RevocationStatus,
    SecretAuthority, SignedCapabilityManifest, TenantId,
};
use proptest::prelude::*;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

const NOW: (i32, u32, u32, u32, u32, u32) = (2030, 1, 1, 12, 0, 0);

struct Fixture {
    signed: SignedCapabilityManifest,
    gateway: CapabilityGateway,
    request: CapabilityRequest,
    selector: CapabilityResolutionSelector,
    composition: CapabilityCompositionSnapshot,
    now: DateTime<Utc>,
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(NOW.0, NOW.1, NOW.2, NOW.3, NOW.4, NOW.5)
        .single()
        .expect("fixed timestamp")
}

fn digest(value: &str) -> Digest {
    Digest::from_text(value)
}

fn adapter_binding() -> AdapterBinding {
    AdapterBinding {
        adapter_id: AdapterId::from_stable("resolution.read.adapter"),
        implementation_id: "private-provider-implementation-marker".into(),
        implementation_digest: digest("resolution-provider-v1"),
        binary_digest: digest("resolution-binary-v1"),
        schema_digest: digest("resolution-schema-v1"),
        version: "1.2.3".into(),
        revocation_epoch: 1,
    }
}

fn project_scope() -> ProjectScope {
    ProjectScope {
        tenant_id: TenantId::from_stable("resolution-tenant"),
        project_id: ProjectId::from_stable("resolution-project"),
        workspace_digest: digest("resolution-workspace"),
        resource_scope_digest: digest("resolution-resource-scope"),
    }
}

fn mission_scope(project: &ProjectScope, generation: u64) -> MissionScope {
    MissionScope {
        tenant_id: project.tenant_id.clone(),
        project_id: project.project_id.clone(),
        mission_id: MissionId::from_stable("resolution-mission"),
        task_id: None,
        worker_id: None,
        worker_lease_id: None,
        context_workspace_id: None,
        context_capsule_id: None,
        context_branch_id: None,
        generation,
        contract_revision: 1,
        scope_digest: digest(&format!("resolution-mission-scope-{generation}")),
    }
}

fn request(manifest: &CapabilityManifest, now: DateTime<Utc>) -> CapabilityRequest {
    let manifest_digest = manifest.digest().expect("manifest digest");
    let authority_digest = manifest.authority_digest().expect("authority digest");
    CapabilityRequest {
        schema: CAPABILITY_REQUEST_SCHEMA.into(),
        request_id: RequestId::from_stable("resolution-request"),
        capability_id: manifest.capability_id.clone(),
        class: manifest.class,
        scope: InvocationScope::from_manifest(manifest),
        generation: manifest.mission.generation,
        idempotency_key: IdempotencyKey::from_stable("resolution-idempotency"),
        manifest_digest: manifest_digest.clone(),
        provenance: Provenance {
            source: ProvenanceSource::Runtime,
            manifest_digest,
            authority_digest,
            parent_digest: None,
            input_digest: digest("resolution-input"),
            generation: manifest.mission.generation,
            observed_at: now - Duration::seconds(1),
            links: Vec::new(),
        },
        budget_use: BudgetUse {
            request_bytes: 0,
            result_bytes: 0,
            estimated_tokens: 1,
            estimated_cost: CostLimit {
                amount_minor: 0,
                currency: "USD".into(),
            },
            external_effect_count: 0,
        },
        payload: RequestPayload::Read(ReadRequest {
            operation: ReadOperation::ProjectSnapshot { revision: 1 },
            requested_class: DataClass::Business,
            secret_references: BTreeSet::new(),
        }),
    }
}

fn read_result(fixture: &Fixture) -> CapabilityResult {
    CapabilityResult {
        schema: CAPABILITY_RESULT_SCHEMA.into(),
        request_id: fixture.request.request_id.clone(),
        capability_id: fixture.request.capability_id.clone(),
        class: CapabilityClass::Read,
        scope: fixture.request.scope.clone(),
        generation: fixture.request.generation,
        manifest_digest: fixture.request.manifest_digest.clone(),
        provenance: fixture.request.provenance.clone(),
        budget_use: BudgetUse {
            request_bytes: 0,
            result_bytes: 0,
            estimated_tokens: 1,
            estimated_cost: CostLimit {
                amount_minor: 0,
                currency: "USD".into(),
            },
            external_effect_count: 0,
        },
        payload: ResultPayload::Read(ReadResult {
            payload: None,
            completeness: ReadCompleteness::Complete,
            continuation_digest: None,
        }),
    }
}

fn invocation_context(
    resolution: &CapabilityResolutionLease,
    visibility: CapabilityInvocationVisibility,
) -> CapabilityInvocationContext {
    CapabilityInvocationContext::from_binding(resolution.binding(), visibility)
        .expect("invocation context")
}

#[allow(clippy::too_many_lines)]
fn fixture(generation: u64) -> Fixture {
    let now = now();
    let binding = adapter_binding();
    let capability_id = CapabilityId::from_stable("resolution.read");
    let mut registry = AdapterRegistry::new();
    let record_digest = registry
        .register(binding.clone(), BTreeSet::from([capability_id.clone()]))
        .expect("adapter registration");
    let project = project_scope();
    let mission = mission_scope(&project, generation);
    let manifest = CapabilityManifest {
        schema: CAPABILITY_MANIFEST_SCHEMA.into(),
        manifest_version: 1,
        schema_digest: binding.schema_digest.clone(),
        capability_id,
        class: CapabilityClass::Read,
        project,
        mission: mission.clone(),
        data: DataAuthority {
            maximum_class: DataClass::Business,
            allowed_resource_digests: BTreeSet::new(),
        },
        network: NetworkAuthority::None,
        secrets: SecretAuthority::none(),
        budget: BudgetAuthority {
            max_tokens: 1_000,
            max_cost: CostLimit {
                amount_minor: 100,
                currency: "USD".into(),
            },
            max_request_bytes: 4_096,
            max_result_bytes: 4_096,
            max_external_effects: 0,
            deadline_at: now + Duration::hours(1),
        },
        effect: EffectAuthority {
            allowed_kinds: BTreeSet::new(),
            allowed_providers: BTreeSet::new(),
            approval: ApprovalRequirement::Required,
            uncertain_policy: hartevo_capability_gateway::UncertainEffectPolicy::ReconcileOnly,
            max_cost: None,
            broker_policy_digest: digest("resolution-broker-policy"),
        },
        adapter: binding,
        revocation: RevocationBinding {
            registry_revision: registry.revision,
            revocation_epoch: 1,
            status: RevocationStatus::Active,
            record_digest,
        },
        provenance: ManifestProvenance {
            issuer: ManifestIssuer::Application,
            source_digest: digest("resolution-manifest-source"),
            parent_manifest_digest: None,
            issued_for_generation: generation,
        },
        issued_at: now - Duration::seconds(1),
        expires_at: now + Duration::hours(1),
    };
    let key_pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("signing key");
    let signed = SignedCapabilityManifest::sign(
        manifest.clone(),
        "resolution-manifest-key",
        key_pair.as_ref(),
    )
    .expect("signed manifest");
    let request = request(&manifest, now);
    let version = CapabilityVersion::new(1, 2, 3);
    let service_id_digest = digest("resolution-service");
    let provider_id_digest = digest("resolution-provider");
    let consumer_id_digest = digest("resolution-consumer");
    let owner_plugin_digest = digest("resolution-plugin");
    let scope = CapabilityCompositionScope::new(
        manifest.mission.project_id.clone(),
        manifest.mission.mission_id.clone(),
        generation,
        manifest.mission.scope_digest.clone(),
    )
    .expect("composition scope");
    let manifest_digest = manifest.digest().expect("manifest digest");
    let authority_digest = manifest.authority_digest().expect("authority digest");
    let service = CapabilityServiceDefinition::new(
        service_id_digest.clone(),
        owner_plugin_digest.clone(),
        digest(manifest.capability_id.as_str()),
        CapabilityClass::Read,
        version,
        manifest_digest,
        authority_digest.clone(),
        1,
        ContributionLifecycle::Active,
    )
    .expect("service definition");
    let provider = CapabilityProviderDefinition::new(
        provider_id_digest,
        service_id_digest.clone(),
        owner_plugin_digest.clone(),
        manifest.adapter.implementation_digest.clone(),
        version,
        ContributionLifecycle::Active,
    )
    .expect("provider definition");
    let consumer = CapabilityConsumerDefinition::new(
        consumer_id_digest.clone(),
        service_id_digest.clone(),
        owner_plugin_digest,
        digest(manifest.capability_id.as_str()),
        CapabilityClass::Read,
        version,
        authority_digest,
        digest(CAPABILITY_REQUEST_SCHEMA),
        scope.clone(),
        ContributionLifecycle::Active,
    )
    .expect("consumer definition");
    let composition = CapabilityCompositionSnapshot::new(
        scope,
        4,
        CapabilityCompositionLifecycle::Mounted,
        vec![service],
        vec![provider],
        vec![consumer],
    )
    .expect("composition snapshot");
    let selector =
        CapabilityResolutionSelector::new(consumer_id_digest, service_id_digest, version)
            .expect("resolution selector");
    Fixture {
        signed,
        gateway: CapabilityGateway::new(registry).expect("gateway"),
        request,
        selector,
        composition,
        now,
    }
}

#[allow(clippy::too_many_lines)]
fn external_fixture(generation: u64) -> Fixture {
    let base = fixture(generation);
    let now = base.now;
    let mut manifest = base.signed.manifest.clone();
    manifest.capability_id = CapabilityId::from_stable("message.send");
    manifest.class = CapabilityClass::ExternalEffect;
    manifest.network = NetworkAuthority::EffectBroker {
        providers: BTreeSet::from([String::from("mail")]),
    };
    manifest.effect = EffectAuthority {
        allowed_kinds: BTreeSet::from([EffectKind::Outreach]),
        allowed_providers: BTreeSet::from([String::from("mail")]),
        approval: ApprovalRequirement::Required,
        uncertain_policy: hartevo_capability_gateway::UncertainEffectPolicy::ReconcileOnly,
        max_cost: None,
        broker_policy_digest: digest("external-broker-policy"),
    };
    manifest.budget.max_external_effects = 1;
    manifest.secrets = SecretAuthority::none();
    let mut registry = AdapterRegistry::new();
    let record_digest = registry
        .register(
            manifest.adapter.clone(),
            BTreeSet::from([manifest.capability_id.clone()]),
        )
        .expect("external adapter registration");
    manifest.revocation.registry_revision = registry.revision;
    manifest.revocation.record_digest = record_digest;
    let key_pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("signing key");
    let signed = SignedCapabilityManifest::sign(
        manifest.clone(),
        "external-manifest-key",
        key_pair.as_ref(),
    )
    .expect("signed external manifest");
    let request = external_request(&manifest, now);
    let version = CapabilityVersion::new(1, 2, 3);
    let service_id_digest = digest("external-service");
    let provider_id_digest = digest("external-provider");
    let consumer_id_digest = digest("external-consumer");
    let owner_plugin_digest = digest("external-plugin");
    let scope = CapabilityCompositionScope::new(
        manifest.mission.project_id.clone(),
        manifest.mission.mission_id.clone(),
        generation,
        manifest.mission.scope_digest.clone(),
    )
    .expect("external composition scope");
    let service = CapabilityServiceDefinition::new(
        service_id_digest.clone(),
        owner_plugin_digest.clone(),
        digest(manifest.capability_id.as_str()),
        CapabilityClass::ExternalEffect,
        version,
        manifest.digest().expect("external manifest digest"),
        manifest
            .authority_digest()
            .expect("external authority digest"),
        1,
        ContributionLifecycle::Active,
    )
    .expect("external service");
    let provider = CapabilityProviderDefinition::new(
        provider_id_digest,
        service_id_digest.clone(),
        owner_plugin_digest.clone(),
        manifest.adapter.implementation_digest.clone(),
        version,
        ContributionLifecycle::Active,
    )
    .expect("external provider");
    let consumer = CapabilityConsumerDefinition::new(
        consumer_id_digest.clone(),
        service_id_digest.clone(),
        owner_plugin_digest,
        digest(manifest.capability_id.as_str()),
        CapabilityClass::ExternalEffect,
        version,
        manifest.authority_digest().expect("external policy digest"),
        digest(CAPABILITY_REQUEST_SCHEMA),
        scope.clone(),
        ContributionLifecycle::Active,
    )
    .expect("external consumer");
    let composition = CapabilityCompositionSnapshot::new(
        scope,
        5,
        CapabilityCompositionLifecycle::Mounted,
        vec![service],
        vec![provider],
        vec![consumer],
    )
    .expect("external composition");
    let selector =
        CapabilityResolutionSelector::new(consumer_id_digest, service_id_digest, version)
            .expect("external selector");
    Fixture {
        signed,
        gateway: CapabilityGateway::new(registry).expect("external gateway"),
        request,
        selector,
        composition,
        now,
    }
}

fn external_request(manifest: &CapabilityManifest, now: DateTime<Utc>) -> CapabilityRequest {
    let manifest_digest = manifest.digest().expect("external manifest digest");
    let authority_digest = manifest
        .authority_digest()
        .expect("external authority digest");
    CapabilityRequest {
        schema: CAPABILITY_REQUEST_SCHEMA.into(),
        request_id: RequestId::from_stable("external-request"),
        capability_id: manifest.capability_id.clone(),
        class: CapabilityClass::ExternalEffect,
        scope: InvocationScope::from_manifest(manifest),
        generation: manifest.mission.generation,
        idempotency_key: IdempotencyKey::from_stable("external-idempotency"),
        manifest_digest: manifest_digest.clone(),
        provenance: Provenance {
            source: ProvenanceSource::Runtime,
            manifest_digest,
            authority_digest,
            parent_digest: None,
            input_digest: digest("external-input"),
            generation: manifest.mission.generation,
            observed_at: now - Duration::seconds(1),
            links: Vec::new(),
        },
        budget_use: BudgetUse {
            request_bytes: 64,
            result_bytes: 0,
            estimated_tokens: 1,
            estimated_cost: CostLimit {
                amount_minor: 0,
                currency: "USD".into(),
            },
            external_effect_count: 1,
        },
        payload: RequestPayload::ExternalEffect(ExternalEffectRequest {
            effect_id: EffectId::from_stable("external-effect"),
            kind: EffectKind::Outreach,
            provider: "mail".into(),
            target_origin: Origin::parse("https://mail.example").expect("origin"),
            target_digest: digest("external-target"),
            payload: hartevo_capability_gateway::BoundedPayload::try_new(
                "hartevo.external-message/v1",
                DataClass::Business,
                b"opaque-effect-material".to_vec(),
                manifest.budget.max_request_bytes,
            )
            .expect("effect payload"),
            audience_digest: Some(digest("external-audience")),
            amount: None,
            approval_required: ApprovalRequirement::Required,
            secret_references: BTreeSet::new(),
        }),
    }
}

fn external_effect_digest(request: &CapabilityRequest) -> Digest {
    let RequestPayload::ExternalEffect(effect) = &request.payload else {
        panic!("expected external effect request");
    };
    Digest::from_bytes(&serde_json::to_vec(effect).expect("effect canonical bytes"))
}

fn external_result(
    fixture: &Fixture,
    disposition: EffectDisposition,
    receipt_digest: Option<Digest>,
    verification_digest: Option<Digest>,
    reconciliation_digest: Option<Digest>,
) -> CapabilityResult {
    let effect_id = match &fixture.request.payload {
        RequestPayload::ExternalEffect(effect) => effect.effect_id.clone(),
        _ => panic!("expected external effect request"),
    };
    CapabilityResult {
        schema: CAPABILITY_RESULT_SCHEMA.into(),
        request_id: fixture.request.request_id.clone(),
        capability_id: fixture.request.capability_id.clone(),
        class: CapabilityClass::ExternalEffect,
        scope: fixture.request.scope.clone(),
        generation: fixture.request.generation,
        manifest_digest: fixture.request.manifest_digest.clone(),
        provenance: fixture.request.provenance.clone(),
        budget_use: BudgetUse {
            request_bytes: 0,
            result_bytes: 0,
            estimated_tokens: 1,
            estimated_cost: CostLimit {
                amount_minor: 0,
                currency: "USD".into(),
            },
            external_effect_count: 1,
        },
        payload: ResultPayload::ExternalEffect(ExternalEffectResult {
            effect_id,
            effect_digest: external_effect_digest(&fixture.request),
            disposition,
            receipt_digest,
            verification_digest,
            reconciliation_digest,
        }),
    }
}

#[test]
fn resolves_closed_service_provider_consumer_loop_and_reopens_deterministically() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let mut audit = MemoryCapabilityResolutionLedger::default();
    let mut lease = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        )
        .expect("resolve closed composition");
    let original_receipt = lease.receipt().clone();
    let original_binding = lease.binding().clone();
    assert!(!lease.is_released());
    assert_eq!(
        audit.events()[0].kind(),
        CapabilityResolutionAuditEventKind::Resolved
    );
    assert_eq!(audit.len(), 1);

    let release = lease
        .release(fixture.now + Duration::seconds(1), &mut audit)
        .expect("release invocation lease");
    assert!(lease.is_released());
    assert!(matches!(
        lease.release(fixture.now + Duration::seconds(2), &mut audit),
        Err(CapabilityResolutionError::AlreadyReleased)
    ));
    assert_eq!(
        audit.events()[1].kind(),
        CapabilityResolutionAuditEventKind::Released
    );

    let reopened = resolver
        .reopen(
            &release,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now + Duration::seconds(3),
            &mut audit,
        )
        .expect("reopen same composition");
    assert_eq!(reopened.receipt(), &original_receipt);
    assert_eq!(reopened.binding(), &original_binding);
    assert_eq!(
        audit.events()[2].kind(),
        CapabilityResolutionAuditEventKind::Reopened
    );
    assert_eq!(audit.len(), 3);
}

#[test]
fn catalog_provider_alone_and_missing_consumer_are_not_resolvable() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let mut audit = MemoryCapabilityResolutionLedger::default();
    let no_service = CapabilityCompositionSnapshot::new(
        fixture.composition.scope.clone(),
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        Vec::new(),
        fixture.composition.providers.clone(),
        fixture.composition.consumers.clone(),
    )
    .expect("provider-alone snapshot");
    assert!(matches!(
        resolver.resolve(
            &no_service,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::MissingService)
    ));

    let no_provider = CapabilityCompositionSnapshot::new(
        fixture.composition.scope.clone(),
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture
            .composition
            .services
            .iter()
            .cloned()
            .map(|mut service| {
                service.provider_count = 0;
                service
            })
            .collect(),
        Vec::new(),
        fixture.composition.consumers.clone(),
    )
    .expect("catalog-only snapshot");
    assert!(matches!(
        resolver.resolve(
            &no_provider,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::MissingProvider)
    ));

    let no_consumer = CapabilityCompositionSnapshot::new(
        fixture.composition.scope.clone(),
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture.composition.services.clone(),
        fixture.composition.providers.clone(),
        Vec::new(),
    )
    .expect("provider-only snapshot");
    assert!(matches!(
        resolver.resolve(
            &no_consumer,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::MissingConsumer)
    ));
    assert!(audit.is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
fn ambiguity_revocation_unmount_and_stale_scope_fail_closed() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let mut audit = MemoryCapabilityResolutionLedger::default();

    let mut duplicate_providers = fixture.composition.providers.clone();
    duplicate_providers.push(duplicate_providers[0].clone());
    let ambiguous = CapabilityCompositionSnapshot::new(
        fixture.composition.scope.clone(),
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture.composition.services.clone(),
        duplicate_providers,
        fixture.composition.consumers.clone(),
    )
    .expect("ambiguous provider snapshot");
    assert!(matches!(
        resolver.resolve(
            &ambiguous,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::AmbiguousComposition)
    ));

    let revoked = CapabilityCompositionSnapshot::new(
        fixture.composition.scope.clone(),
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture.composition.services.clone(),
        fixture
            .composition
            .providers
            .iter()
            .cloned()
            .map(|mut provider| {
                provider.lifecycle = ContributionLifecycle::Revoked;
                provider
            })
            .collect(),
        fixture.composition.consumers.clone(),
    )
    .expect("revoked provider snapshot");
    assert!(matches!(
        resolver.resolve(
            &revoked,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::ProviderRevoked)
    ));

    for lifecycle in [
        CapabilityCompositionLifecycle::Unmounted,
        CapabilityCompositionLifecycle::Revoked,
        CapabilityCompositionLifecycle::Stale,
    ] {
        let unavailable = CapabilityCompositionSnapshot::new(
            fixture.composition.scope.clone(),
            fixture.composition.revision,
            lifecycle,
            fixture.composition.services.clone(),
            fixture.composition.providers.clone(),
            fixture.composition.consumers.clone(),
        )
        .expect("lifecycle snapshot");
        let result = resolver.resolve(
            &unavailable,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        );
        assert!(matches!(
            (lifecycle, result),
            (
                CapabilityCompositionLifecycle::Unmounted,
                Err(CapabilityResolutionError::CompositionUnavailable)
            ) | (
                CapabilityCompositionLifecycle::Revoked,
                Err(CapabilityResolutionError::PluginRevoked)
            ) | (
                CapabilityCompositionLifecycle::Stale,
                Err(CapabilityResolutionError::StaleGeneration)
            )
        ));
    }

    let stale_scope = CapabilityCompositionScope::new(
        fixture.composition.scope.project_id.clone(),
        fixture.composition.scope.mission_id.clone(),
        8,
        digest("stale-resolution-scope"),
    )
    .expect("stale scope");
    let stale = CapabilityCompositionSnapshot::new(
        stale_scope,
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture.composition.services.clone(),
        fixture.composition.providers.clone(),
        fixture.composition.consumers.clone(),
    )
    .expect("stale generation snapshot");
    assert!(matches!(
        resolver.resolve(
            &stale,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::StaleGeneration)
    ));
}

#[test]
fn contribution_and_adapter_revocation_fail_closed() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let mut audit = MemoryCapabilityResolutionLedger::default();

    for (lifecycle, expected) in [
        (
            ContributionLifecycle::Unmounted,
            CapabilityResolutionError::CompositionUnavailable,
        ),
        (
            ContributionLifecycle::Stale,
            CapabilityResolutionError::StaleGeneration,
        ),
    ] {
        let snapshot = CapabilityCompositionSnapshot::new(
            fixture.composition.scope.clone(),
            fixture.composition.revision,
            CapabilityCompositionLifecycle::Mounted,
            fixture.composition.services.clone(),
            fixture
                .composition
                .providers
                .iter()
                .cloned()
                .map(|mut provider| {
                    provider.lifecycle = lifecycle;
                    provider
                })
                .collect(),
            fixture.composition.consumers.clone(),
        )
        .expect("provider lifecycle snapshot");
        assert_eq!(
            resolver.resolve(
                &snapshot,
                &fixture.signed,
                &fixture.request,
                &fixture.selector,
                fixture.now,
                &mut audit,
            ),
            Err(expected)
        );
    }

    let revoked_consumer = CapabilityCompositionSnapshot::new(
        fixture.composition.scope.clone(),
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture.composition.services.clone(),
        fixture.composition.providers.clone(),
        fixture
            .composition
            .consumers
            .iter()
            .cloned()
            .map(|mut consumer| {
                consumer.lifecycle = ContributionLifecycle::Revoked;
                consumer
            })
            .collect(),
    )
    .expect("revoked consumer snapshot");
    assert_eq!(
        resolver.resolve(
            &revoked_consumer,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::ConsumerRevoked)
    );

    let mut revoked_registry = fixture.gateway.registry().clone();
    revoked_registry
        .revoke(&fixture.signed.manifest.adapter.adapter_id)
        .expect("revoke adapter");
    let revoked_gateway = CapabilityGateway::new(revoked_registry).expect("revoked gateway");
    assert_eq!(
        revoked_gateway.resolver().resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::ProviderRevoked)
    );
    assert!(audit.is_empty());
}

#[test]
fn policy_version_scope_and_tamper_drift_fail_closed_without_audit() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let mut audit = MemoryCapabilityResolutionLedger::default();

    let wrong_policy = CapabilityCompositionSnapshot::new(
        fixture.composition.scope.clone(),
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture
            .composition
            .services
            .iter()
            .cloned()
            .map(|mut service| {
                service.policy_digest = digest("wrong-policy");
                service
            })
            .collect(),
        fixture.composition.providers.clone(),
        fixture.composition.consumers.clone(),
    )
    .expect("wrong policy snapshot");
    assert!(matches!(
        resolver.resolve(
            &wrong_policy,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::PolicyMismatch)
    ));

    let wrong_provider_version = CapabilityCompositionSnapshot::new(
        fixture.composition.scope.clone(),
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture.composition.services.clone(),
        fixture
            .composition
            .providers
            .iter()
            .cloned()
            .map(|mut provider| {
                provider.version = CapabilityVersion::new(9, 9, 9);
                provider
            })
            .collect(),
        fixture.composition.consumers.clone(),
    )
    .expect("wrong version snapshot");
    assert!(matches!(
        resolver.resolve(
            &wrong_provider_version,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::VersionMismatch)
    ));

    let mut tampered = fixture.composition.clone();
    tampered.revision += 1;
    assert!(matches!(
        resolver.resolve(
            &tampered,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::InvalidComposition)
    ));
    assert!(audit.is_empty());

    let mut wrong_project_scope = fixture.composition.scope.clone();
    wrong_project_scope.project_id = ProjectId::from_stable("other-project");
    let wrong_project = CapabilityCompositionSnapshot::new(
        wrong_project_scope,
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture.composition.services.clone(),
        fixture.composition.providers.clone(),
        fixture.composition.consumers.clone(),
    )
    .expect("wrong project snapshot");
    assert!(matches!(
        resolver.resolve(
            &wrong_project,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut audit,
        ),
        Err(CapabilityResolutionError::ScopeMismatch)
    ));
}

#[test]
fn resolution_outputs_are_content_free_and_audit_is_deterministic() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let mut first_audit = MemoryCapabilityResolutionLedger::default();
    let first = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut first_audit,
        )
        .expect("first resolution");
    let mut second_audit = MemoryCapabilityResolutionLedger::default();
    let second = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut second_audit,
        )
        .expect("second resolution");
    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(first.binding(), second.binding());
    assert_eq!(first_audit.events(), second_audit.events());

    let debug = format!("{first:?}{:?}{:?}", first.binding(), first.receipt());
    assert!(!debug.contains("private-provider-implementation-marker"));
    let json = serde_json::to_string(first.binding()).expect("binding JSON");
    assert!(!json.contains("private-provider-implementation-marker"));
    assert!(
        !serde_json::to_string(&first_audit.events()[0])
            .expect("audit JSON")
            .contains("resolution-service")
    );
}

proptest! {
    #[test]
fn same_composition_reopens_to_same_binding(generation in 1_u64..1_000_u64) {
        let first = fixture(generation);
        let second = fixture(generation);
        let first_resolver = first.gateway.resolver();
        let second_resolver = second.gateway.resolver();
        let mut first_audit = MemoryCapabilityResolutionLedger::default();
        let mut second_audit = MemoryCapabilityResolutionLedger::default();
        let first_lease = first_resolver.resolve(
            &first.composition,
            &first.signed,
            &first.request,
            &first.selector,
            first.now,
            &mut first_audit,
        ).expect("first resolution");
        let mut second_lease = second_resolver.resolve(
            &second.composition,
            &second.signed,
            &second.request,
            &second.selector,
            second.now,
            &mut second_audit,
        ).expect("second resolution");
        prop_assert_eq!(first_lease.receipt(), second_lease.receipt());
        prop_assert_eq!(first_lease.binding(), second_lease.binding());
        let release = second_lease.release(second.now, &mut second_audit)
            .expect("release");
        let reopened = second_resolver.reopen(
            &release,
            &second.composition,
            &second.signed,
            &second.request,
            &second.selector,
            second.now,
            &mut second_audit,
        ).expect("reopen");
        prop_assert_eq!(reopened.receipt(), first_lease.receipt());
        prop_assert_eq!(reopened.binding(), first_lease.binding());
    }
}

#[test]
fn begin_complete_release_is_single_use_and_model_visible_has_log_reference() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let mut resolution_audit = MemoryCapabilityResolutionLedger::default();
    let resolution = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut resolution_audit,
        )
        .expect("resolution");
    let context = invocation_context(&resolution, CapabilityInvocationVisibility::ModelVisible);
    let mut log = MemoryCapabilityInvocationLog::default();
    let mut lease = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut log,
        )
        .expect("begin invocation");
    assert_eq!(lease.attempt(), 1);
    assert_eq!(
        lease.visibility(),
        CapabilityInvocationVisibility::ModelVisible
    );
    assert_eq!(log.len(), 1);
    assert_eq!(log.events()[0].kind(), CapabilityInvocationEventKind::Began);
    assert_eq!(
        lease.log_reference().digest(),
        log.events()[0].event_digest()
    );

    let result = read_result(&fixture);
    let release = resolver
        .complete_invocation(
            &mut lease,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &result,
            None,
            fixture.now + Duration::seconds(1),
            &mut log,
        )
        .expect("complete invocation");
    assert!(lease.is_released());
    assert_eq!(release.kind(), CapabilityInvocationEventKind::Completed);
    assert_eq!(release.result_digest(), Some(&result.digest()));
    assert!(release.effect_receipt_digest().is_none());
    assert_eq!(log.len(), 2);
    lease
        .release_resolution(fixture.now + Duration::seconds(1), &mut resolution_audit)
        .expect("release resolved binding");
    assert_eq!(resolution_audit.len(), 2);
    let context = invocation_context(&resolution, CapabilityInvocationVisibility::ModelVisible);
    assert!(matches!(
        resolver.reopen_invocation(
            &release,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now + Duration::seconds(2),
            &mut log,
        ),
        Err(CapabilityInvocationError::ReopenNotAllowed)
    ));
    assert_eq!(
        log.events()[1].kind(),
        CapabilityInvocationEventKind::Completed
    );
    assert!(matches!(
        resolver.complete_invocation(
            &mut lease,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &result,
            None,
            fixture.now + Duration::seconds(2),
            &mut log,
        ),
        Err(CapabilityInvocationError::AlreadyReleased)
    ));
    assert_eq!(log.len(), 2);
}

#[test]
fn timeout_cancel_crash_and_reopen_are_exact_once_and_bounded() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let resolution = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut MemoryCapabilityResolutionLedger::default(),
        )
        .expect("resolution");
    let context = invocation_context(&resolution, CapabilityInvocationVisibility::Internal);

    for (close, expected_kind, expected_reason) in [
        (
            "timeout",
            CapabilityInvocationEventKind::TimedOut,
            CapabilityInvocationCloseReason::Timeout,
        ),
        (
            "cancel",
            CapabilityInvocationEventKind::Cancelled,
            CapabilityInvocationCloseReason::Cancelled,
        ),
        (
            "crash",
            CapabilityInvocationEventKind::Crashed,
            CapabilityInvocationCloseReason::Crashed,
        ),
    ] {
        let mut log = MemoryCapabilityInvocationLog::default();
        let mut lease = resolver
            .begin_invocation(
                &resolution,
                &fixture.composition,
                &fixture.signed,
                &fixture.request,
                &context,
                fixture.now,
                &mut log,
            )
            .expect("begin");
        let release = match close {
            "timeout" => lease.timeout(fixture.now, &mut log),
            "cancel" => lease.cancel(fixture.now, &mut log),
            "crash" => lease.crash(fixture.now, &mut log),
            _ => unreachable!(),
        }
        .expect("close");
        assert_eq!(release.kind(), expected_kind);
        assert_eq!(release.reason(), Some(expected_reason));
        assert!(matches!(
            lease.timeout(fixture.now, &mut log),
            Err(CapabilityInvocationError::AlreadyReleased)
        ));
        assert_eq!(log.len(), 2);

        let reopened = resolver
            .reopen_invocation(
                &release,
                &fixture.composition,
                &fixture.signed,
                &fixture.request,
                &context,
                fixture.now + Duration::seconds(1),
                &mut log,
            )
            .expect("reopen");
        assert_eq!(reopened.attempt(), 2);
        assert_eq!(reopened.invocation_digest(), lease.invocation_digest());
        assert_eq!(log.len(), 3);
        assert_eq!(
            log.events()[2].kind(),
            CapabilityInvocationEventKind::Reopened
        );
    }
}

#[test]
fn reopen_attempt_limit_is_enforced_without_reusing_a_terminal_lease() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let resolution = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut MemoryCapabilityResolutionLedger::default(),
        )
        .expect("resolution");
    let context = invocation_context(&resolution, CapabilityInvocationVisibility::Internal);
    let mut log = MemoryCapabilityInvocationLog::default();
    let mut lease = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut log,
        )
        .expect("begin");
    for attempt in 1..=MAX_INVOCATION_ATTEMPTS {
        let release = lease
            .timeout(fixture.now, &mut log)
            .expect("timeout attempt");
        assert_eq!(release.attempt(), attempt);
        if attempt < MAX_INVOCATION_ATTEMPTS {
            lease = resolver
                .reopen_invocation(
                    &release,
                    &fixture.composition,
                    &fixture.signed,
                    &fixture.request,
                    &context,
                    fixture.now,
                    &mut log,
                )
                .expect("bounded reopen");
        } else {
            assert!(matches!(
                resolver.reopen_invocation(
                    &release,
                    &fixture.composition,
                    &fixture.signed,
                    &fixture.request,
                    &context,
                    fixture.now,
                    &mut log,
                ),
                Err(CapabilityInvocationError::AttemptLimit)
            ));
        }
    }
    assert_eq!(log.len(), (MAX_INVOCATION_ATTEMPTS * 2) as usize);
}

#[test]
#[allow(clippy::too_many_lines)]
fn scope_revision_generation_policy_and_lifecycle_drift_invalidate_immediately() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let resolution = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut MemoryCapabilityResolutionLedger::default(),
        )
        .expect("resolution");

    let mut context = invocation_context(&resolution, CapabilityInvocationVisibility::Internal);
    context = CapabilityInvocationContext::new(
        context.project_id().clone(),
        context.mission_id().clone(),
        context.generation(),
        context.composition_revision() + 1,
        context.provider_generation(),
        context.policy_digest().clone(),
        context.visibility(),
    )
    .expect("revision drift context");
    let mut log = MemoryCapabilityInvocationLog::default();
    assert!(matches!(
        resolver.begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut log,
        ),
        Err(CapabilityInvocationError::RevisionMismatch)
    ));
    assert!(log.is_empty());

    let valid_context = invocation_context(&resolution, CapabilityInvocationVisibility::Internal);
    let mismatches = [
        (
            CapabilityInvocationContext::new(
                ProjectId::from_stable("other-project"),
                valid_context.mission_id().clone(),
                valid_context.generation(),
                valid_context.composition_revision(),
                valid_context.provider_generation(),
                valid_context.policy_digest().clone(),
                valid_context.visibility(),
            )
            .expect("project mismatch context"),
            CapabilityInvocationError::MissionMismatch,
        ),
        (
            CapabilityInvocationContext::new(
                valid_context.project_id().clone(),
                valid_context.mission_id().clone(),
                valid_context.generation() + 1,
                valid_context.composition_revision(),
                valid_context.provider_generation() + 1,
                valid_context.policy_digest().clone(),
                valid_context.visibility(),
            )
            .expect("generation mismatch context"),
            CapabilityInvocationError::GenerationMismatch,
        ),
        (
            CapabilityInvocationContext::new(
                valid_context.project_id().clone(),
                valid_context.mission_id().clone(),
                valid_context.generation(),
                valid_context.composition_revision(),
                valid_context.provider_generation() + 1,
                valid_context.policy_digest().clone(),
                valid_context.visibility(),
            )
            .expect("provider generation mismatch context"),
            CapabilityInvocationError::ProviderGenerationMismatch,
        ),
        (
            CapabilityInvocationContext::new(
                valid_context.project_id().clone(),
                valid_context.mission_id().clone(),
                valid_context.generation(),
                valid_context.composition_revision(),
                valid_context.provider_generation(),
                digest("drifted-policy"),
                valid_context.visibility(),
            )
            .expect("policy mismatch context"),
            CapabilityInvocationError::PolicyDrift,
        ),
    ];
    for (mismatched, expected) in mismatches {
        assert!(matches!(
            resolver.begin_invocation(
                &resolution,
                &fixture.composition,
                &fixture.signed,
                &fixture.request,
                &mismatched,
                fixture.now,
                &mut log,
            ),
            Err(error) if error == expected
        ));
        assert!(log.is_empty());
    }

    let context = invocation_context(&resolution, CapabilityInvocationVisibility::Internal);
    let mut lease = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut log,
        )
        .expect("begin");

    let mut tampered = fixture.composition.clone();
    tampered.revision += 1;
    assert!(matches!(
        resolver.revalidate_invocation(
            &mut lease,
            &tampered,
            &fixture.signed,
            &fixture.request,
            fixture.now,
            &mut log,
        ),
        Err(CapabilityInvocationError::Invalidated(
            CapabilityInvocationCloseReason::BindingDrift
        ))
    ));
    assert!(lease.is_released());
    assert_eq!(log.len(), 2);
    assert_eq!(
        log.events()[1].reason(),
        Some(CapabilityInvocationCloseReason::BindingDrift)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn revoked_unmounted_stale_and_policy_drift_never_complete_or_reopen() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let resolution = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut MemoryCapabilityResolutionLedger::default(),
        )
        .expect("resolution");
    let context = invocation_context(&resolution, CapabilityInvocationVisibility::Internal);
    for lifecycle in [
        CapabilityCompositionLifecycle::Unmounted,
        CapabilityCompositionLifecycle::Revoked,
        CapabilityCompositionLifecycle::Stale,
    ] {
        let mut log = MemoryCapabilityInvocationLog::default();
        let mut lease = resolver
            .begin_invocation(
                &resolution,
                &fixture.composition,
                &fixture.signed,
                &fixture.request,
                &context,
                fixture.now,
                &mut log,
            )
            .expect("begin");
        let unavailable = CapabilityCompositionSnapshot::new(
            fixture.composition.scope.clone(),
            fixture.composition.revision,
            lifecycle,
            fixture.composition.services.clone(),
            fixture.composition.providers.clone(),
            fixture.composition.consumers.clone(),
        )
        .expect("lifecycle composition");
        let result = read_result(&fixture);
        let expected = match lifecycle {
            CapabilityCompositionLifecycle::Unmounted => {
                CapabilityInvocationCloseReason::CompositionUnavailable
            }
            CapabilityCompositionLifecycle::Revoked => {
                CapabilityInvocationCloseReason::PluginRevoked
            }
            CapabilityCompositionLifecycle::Stale => {
                CapabilityInvocationCloseReason::GenerationStale
            }
            CapabilityCompositionLifecycle::Mounted => unreachable!(),
        };
        assert!(matches!(
            resolver.complete_invocation(
                &mut lease,
                &unavailable,
                &fixture.signed,
                &fixture.request,
                &result,
                None,
                fixture.now,
                &mut log,
            ),
            Err(CapabilityInvocationError::Invalidated(reason)) if reason == expected
        ));
        assert!(lease.is_released());
        assert_eq!(log.len(), 2);
    }

    let revoked_provider = CapabilityCompositionSnapshot::new(
        fixture.composition.scope.clone(),
        fixture.composition.revision,
        CapabilityCompositionLifecycle::Mounted,
        fixture.composition.services.clone(),
        fixture
            .composition
            .providers
            .iter()
            .cloned()
            .map(|mut provider| {
                provider.lifecycle = ContributionLifecycle::Revoked;
                provider
            })
            .collect(),
        fixture.composition.consumers.clone(),
    )
    .expect("revoked provider composition");
    let mut provider_log = MemoryCapabilityInvocationLog::default();
    let mut provider_lease = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut provider_log,
        )
        .expect("begin revoked provider invocation");
    assert!(matches!(
        resolver.complete_invocation(
            &mut provider_lease,
            &revoked_provider,
            &fixture.signed,
            &fixture.request,
            &read_result(&fixture),
            None,
            fixture.now,
            &mut provider_log,
        ),
        Err(CapabilityInvocationError::Invalidated(
            CapabilityInvocationCloseReason::ProviderRevoked
        ))
    ));
}

#[test]
fn result_and_effect_receipts_are_typed_and_uncertain_effect_never_reopens() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let resolution = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut MemoryCapabilityResolutionLedger::default(),
        )
        .expect("resolution");
    let context = invocation_context(&resolution, CapabilityInvocationVisibility::ModelVisible);
    let mut log = MemoryCapabilityInvocationLog::default();
    let mut lease = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut log,
        )
        .expect("begin");
    let result = read_result(&fixture);
    let effect_receipt = hartevo_capability_gateway::CapabilityInvocationEffectReceipt::verified(
        digest("effect"),
        digest("receipt"),
        digest("verification"),
    )
    .expect("effect receipt");
    assert!(matches!(
        resolver.complete_invocation(
            &mut lease,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &result,
            Some(&effect_receipt),
            fixture.now,
            &mut log,
        ),
        Err(CapabilityInvocationError::Invalidated(
            CapabilityInvocationCloseReason::ResultRejected
        ))
    ));
    assert!(lease.is_released());
    assert_eq!(log.len(), 2);
}

#[test]
#[allow(clippy::too_many_lines)]
fn verified_external_effect_binds_effect_receipt_and_uncertain_effect_is_not_retried() {
    let fixture = external_fixture(7);
    let resolver = fixture.gateway.resolver();
    let resolution = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut MemoryCapabilityResolutionLedger::default(),
        )
        .expect("external resolution");
    let context = invocation_context(&resolution, CapabilityInvocationVisibility::ModelVisible);
    let effect_digest = external_effect_digest(&fixture.request);
    let receipt_digest = digest("verified-effect-receipt");
    let verification_digest = digest("verified-effect-proof");
    let effect_receipt = CapabilityInvocationEffectReceipt::verified(
        effect_digest.clone(),
        receipt_digest.clone(),
        verification_digest.clone(),
    )
    .expect("typed effect receipt");
    let mut log = MemoryCapabilityInvocationLog::default();
    let mut lease = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut log,
        )
        .expect("begin external invocation");
    let result = external_result(
        &fixture,
        EffectDisposition::Verified,
        Some(receipt_digest),
        Some(verification_digest),
        None,
    );
    let release = resolver
        .complete_invocation(
            &mut lease,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &result,
            Some(&effect_receipt),
            fixture.now,
            &mut log,
        )
        .expect("complete verified effect");
    assert_eq!(release.kind(), CapabilityInvocationEventKind::Completed);
    assert_eq!(
        release.effect_receipt_digest(),
        Some(effect_receipt.receipt_digest())
    );
    assert_eq!(
        log.events()[1].effect_receipt_digest(),
        Some(effect_receipt.receipt_digest())
    );

    let mut uncertain_log = MemoryCapabilityInvocationLog::default();
    let mut uncertain_lease = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut uncertain_log,
        )
        .expect("begin uncertain effect");
    let uncertain = external_result(
        &fixture,
        EffectDisposition::Uncertain,
        None,
        None,
        Some(digest("reconcile-external-effect")),
    );
    assert!(matches!(
        resolver.complete_invocation(
            &mut uncertain_lease,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &uncertain,
            None,
            fixture.now,
            &mut uncertain_log,
        ),
        Err(CapabilityInvocationError::Invalidated(
            CapabilityInvocationCloseReason::UncertainExternalEffect
        ))
    ));
    assert!(uncertain_lease.is_released());

    let mut timed_out_log = MemoryCapabilityInvocationLog::default();
    let mut timed_out_lease = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut timed_out_log,
        )
        .expect("begin timeout effect");
    let timeout_release = timed_out_lease
        .timeout(fixture.now, &mut timed_out_log)
        .expect("timeout external effect");
    assert!(matches!(
        resolver.reopen_invocation(
            &timeout_release,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut uncertain_log,
        ),
        Err(CapabilityInvocationError::UncertainExternalEffect)
    ));
}

#[test]
fn invocation_events_and_receipts_are_content_free_and_deterministic() {
    let fixture = fixture(7);
    let resolver = fixture.gateway.resolver();
    let resolution = resolver
        .resolve(
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &fixture.selector,
            fixture.now,
            &mut MemoryCapabilityResolutionLedger::default(),
        )
        .expect("resolution");
    let context = invocation_context(&resolution, CapabilityInvocationVisibility::ModelVisible);
    let mut first_log = MemoryCapabilityInvocationLog::default();
    let mut second_log = MemoryCapabilityInvocationLog::default();
    let mut first = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut first_log,
        )
        .expect("first begin");
    let mut second = resolver
        .begin_invocation(
            &resolution,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &context,
            fixture.now,
            &mut second_log,
        )
        .expect("second begin");
    assert_eq!(first.invocation_digest(), second.invocation_digest());
    assert_eq!(first.receipt(), second.receipt());
    assert_eq!(first_log.events(), second_log.events());
    let first_release = resolver
        .complete_invocation(
            &mut first,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &read_result(&fixture),
            None,
            fixture.now + Duration::seconds(1),
            &mut first_log,
        )
        .expect("first complete");
    let second_release = resolver
        .complete_invocation(
            &mut second,
            &fixture.composition,
            &fixture.signed,
            &fixture.request,
            &read_result(&fixture),
            None,
            fixture.now + Duration::seconds(1),
            &mut second_log,
        )
        .expect("second complete");
    assert_eq!(first_release, second_release);
    let debug = format!("{first:?}{first_release:?}{:?}", first_log.events());
    assert!(!debug.contains("private-provider-implementation-marker"));
    let json = serde_json::to_string(&first_release).expect("release JSON");
    assert!(!json.contains("private-provider-implementation-marker"));
}
