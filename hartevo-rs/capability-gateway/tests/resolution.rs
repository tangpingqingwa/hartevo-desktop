use std::collections::BTreeSet;

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_capability_gateway::{
    AdapterBinding, AdapterId, AdapterRegistry, ApprovalRequirement, BudgetAuthority, BudgetUse,
    CAPABILITY_MANIFEST_SCHEMA, CAPABILITY_REQUEST_SCHEMA, CapabilityClass,
    CapabilityCompositionLifecycle, CapabilityCompositionScope, CapabilityCompositionSnapshot,
    CapabilityConsumerDefinition, CapabilityGateway, CapabilityId, CapabilityManifest,
    CapabilityProviderDefinition, CapabilityRequest, CapabilityResolutionAuditEventKind,
    CapabilityResolutionError, CapabilityResolutionSelector, CapabilityServiceDefinition,
    CapabilityVersion, ContributionLifecycle, CostLimit, DataAuthority, DataClass, Digest,
    EffectAuthority, IdempotencyKey, InvocationScope, ManifestIssuer, ManifestProvenance,
    MemoryCapabilityResolutionLedger, MissionId, MissionScope, NetworkAuthority, ProjectId,
    ProjectScope, Provenance, ProvenanceSource, ReadOperation, ReadRequest, RequestId,
    RequestPayload, RevocationBinding, RevocationStatus, SecretAuthority, SignedCapabilityManifest,
    TenantId,
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
