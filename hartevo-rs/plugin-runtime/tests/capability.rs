use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_capability_gateway::{
    AdapterBinding, AdapterFailure, AdapterId, AdapterRegistry, ApprovalRequirement,
    BudgetAuthority, BudgetUse, CAPABILITY_MANIFEST_SCHEMA, CAPABILITY_REQUEST_SCHEMA,
    CAPABILITY_RESULT_SCHEMA, CapabilityAdapter, CapabilityClass, CapabilityGateway, CapabilityId,
    CapabilityManifest, CapabilityRequest, CapabilityResult, CostLimit, DataAuthority, DataClass,
    EffectAuthority, GatewayError, IdempotencyKey, InvocationScope, ManifestIssuer,
    ManifestProvenance, MemoryInvocationLedger, MissionId, MissionScope, NetworkAuthority,
    ProjectId, ProjectScope, Provenance, ProvenanceSource, ReadCompleteness, ReadOperation,
    ReadRequest, RequestId, RequestPayload, RevocationBinding, RevocationStatus, SecretAuthority,
    SignedCapabilityManifest, TenantId,
};
use hartevo_plugin_runtime::{
    CapabilityPluginError, MissionId as PluginMissionId, MountedReadOnlyCapability, PluginRuntime,
    PluginScope, PluginVersion, ProjectId as PluginProjectId,
};
use proptest::prelude::*;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

const NOW: (i32, u32, u32, u32, u32, u32) = (2030, 1, 1, 12, 0, 0);

#[derive(Clone)]
struct ReadOnlyAdapter {
    binding: AdapterBinding,
    calls: Arc<AtomicUsize>,
}

impl CapabilityAdapter for ReadOnlyAdapter {
    fn binding(&self) -> &AdapterBinding {
        &self.binding
    }

    fn invoke(&self, request: &CapabilityRequest) -> Result<CapabilityResult, AdapterFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(read_result(request))
    }
}

struct Fixture {
    manifest: CapabilityManifest,
    signed_manifest: SignedCapabilityManifest,
    gateway: CapabilityGateway,
    adapter: ReadOnlyAdapter,
    scope: PluginScope,
    now: DateTime<Utc>,
}

struct MountedFixture {
    manifest: CapabilityManifest,
    adapter: ReadOnlyAdapter,
    now: DateTime<Utc>,
    mounted: MountedReadOnlyCapability<ReadOnlyAdapter>,
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(NOW.0, NOW.1, NOW.2, NOW.3, NOW.4, NOW.5)
        .single()
        .expect("fixed test timestamp")
}

fn digest(value: &str) -> hartevo_capability_gateway::Digest {
    hartevo_capability_gateway::Digest::from_text(value)
}

fn binding() -> AdapterBinding {
    AdapterBinding {
        adapter_id: AdapterId::from_stable("runtime.read-only.adapter"),
        implementation_id: "implementation-marker-must-not-leak".into(),
        implementation_digest: digest("read-only-implementation-v1"),
        binary_digest: digest("read-only-binary-v1"),
        schema_digest: digest("read-only-schema-v1"),
        version: "1.0.0".into(),
        revocation_epoch: 1,
    }
}

fn project_scope() -> ProjectScope {
    ProjectScope {
        tenant_id: TenantId::from_stable("tenant-plugin-cap"),
        project_id: ProjectId::from_stable("project-plugin-cap"),
        workspace_digest: digest("plugin-cap-workspace"),
        resource_scope_digest: digest("plugin-cap-resource-scope"),
    }
}

fn mission_scope(project: &ProjectScope, generation: u64) -> MissionScope {
    MissionScope {
        tenant_id: project.tenant_id.clone(),
        project_id: project.project_id.clone(),
        mission_id: MissionId::from_stable("mission-plugin-cap"),
        task_id: None,
        worker_id: None,
        worker_lease_id: None,
        context_workspace_id: None,
        context_capsule_id: None,
        context_branch_id: None,
        generation,
        contract_revision: 1,
        scope_digest: digest(&format!("plugin-cap-scope-{generation}")),
    }
}

fn plugin_scope(generation: u64) -> PluginScope {
    PluginScope::new(
        PluginProjectId::new("project-plugin-cap").expect("plugin project"),
        PluginMissionId::new("mission-plugin-cap").expect("plugin mission"),
        generation,
    )
    .expect("plugin scope")
}

fn fixture(generation: u64) -> Fixture {
    let now = now();
    let binding = binding();
    let capability_id = CapabilityId::from_stable("runtime.read-only");
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
            max_tokens: 10_000,
            max_cost: CostLimit {
                amount_minor: 1_000,
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
            broker_policy_digest: digest("read-only-broker-policy"),
        },
        adapter: binding.clone(),
        revocation: RevocationBinding {
            registry_revision: registry.revision,
            revocation_epoch: binding.revocation_epoch,
            status: RevocationStatus::Active,
            record_digest,
        },
        provenance: ManifestProvenance {
            issuer: ManifestIssuer::Application,
            source_digest: digest("plugin-cap-manifest-source"),
            parent_manifest_digest: None,
            issued_for_generation: mission.generation,
        },
        issued_at: now - Duration::seconds(1),
        expires_at: now + Duration::hours(1),
    };
    let key_pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("manifest key");
    let signed_manifest =
        SignedCapabilityManifest::sign(manifest.clone(), "plugin-cap-test-key", key_pair.as_ref())
            .expect("signed manifest");
    let gateway = CapabilityGateway::new(registry).expect("gateway");
    let adapter = ReadOnlyAdapter {
        binding,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    Fixture {
        manifest,
        signed_manifest,
        gateway,
        adapter,
        scope: plugin_scope(generation),
        now,
    }
}

fn mount_fixture(generation: u64) -> MountedFixture {
    let fixture = fixture(generation);
    let mounted = MountedReadOnlyCapability::mount(
        PluginRuntime::new(),
        fixture.gateway,
        fixture.signed_manifest.clone(),
        fixture.adapter.clone(),
        PluginVersion::new(1, 0, 0),
        fixture.scope.clone(),
        fixture.now,
    )
    .expect("read-only capability mount");
    MountedFixture {
        manifest: fixture.manifest,
        adapter: fixture.adapter,
        now: fixture.now,
        mounted,
    }
}

fn read_request(manifest: &CapabilityManifest, request_id: &str) -> CapabilityRequest {
    let manifest_digest = manifest.digest().expect("manifest digest");
    let authority_digest = manifest.authority_digest().expect("authority digest");
    CapabilityRequest {
        schema: CAPABILITY_REQUEST_SCHEMA.into(),
        request_id: RequestId::from_stable(request_id),
        capability_id: manifest.capability_id.clone(),
        class: CapabilityClass::Read,
        scope: InvocationScope::from_manifest(manifest),
        generation: manifest.mission.generation,
        idempotency_key: IdempotencyKey::from_stable(format!("idempotency-{request_id}")),
        manifest_digest: manifest_digest.clone(),
        provenance: Provenance {
            source: ProvenanceSource::Runtime,
            manifest_digest,
            authority_digest,
            parent_digest: None,
            input_digest: digest("plugin-cap-input"),
            generation: manifest.mission.generation,
            observed_at: now() - Duration::seconds(1),
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

fn read_result(request: &CapabilityRequest) -> CapabilityResult {
    CapabilityResult {
        schema: CAPABILITY_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        capability_id: request.capability_id.clone(),
        class: CapabilityClass::Read,
        scope: request.scope.clone(),
        generation: request.generation,
        manifest_digest: request.manifest_digest.clone(),
        provenance: Provenance {
            source: ProvenanceSource::Runtime,
            manifest_digest: request.manifest_digest.clone(),
            authority_digest: request.provenance.authority_digest.clone(),
            parent_digest: None,
            input_digest: digest("plugin-cap-input"),
            generation: request.generation,
            observed_at: now() - Duration::seconds(1),
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
        payload: hartevo_capability_gateway::ResultPayload::Read(
            hartevo_capability_gateway::ReadResult {
                payload: None,
                completeness: ReadCompleteness::Complete,
                continuation_digest: None,
            },
        ),
    }
}

#[test]
fn mount_exposes_one_provider_and_consumer_only_in_bound_mission() {
    let fixture = mount_fixture(7);
    let inspection = fixture.mounted.inspection();
    assert!(inspection.mounted);
    assert_eq!(inspection.provider_count, 1);
    assert_eq!(inspection.consumer_count, 1);
    assert_eq!(fixture.mounted.composition_inspection().services.len(), 1);
    assert_eq!(fixture.mounted.composition_inspection().providers.len(), 1);
    assert_eq!(fixture.mounted.composition_inspection().consumers.len(), 1);

    let other_mission = PluginScope::new(
        PluginProjectId::new("project-plugin-cap").expect("plugin project"),
        PluginMissionId::new("mission-other").expect("other mission"),
        7,
    )
    .expect("other mission scope");
    let other_project = PluginScope::new(
        PluginProjectId::new("project-other").expect("other project"),
        PluginMissionId::new("mission-plugin-cap").expect("plugin mission"),
        7,
    )
    .expect("other project scope");
    assert!(fixture.mounted.inspect_scope(&other_mission).is_empty());
    assert!(fixture.mounted.inspect_scope(&other_project).is_empty());

    let debug = format!("{:?}{:?}", fixture.mounted, fixture.mounted.mount_receipt());
    assert!(!debug.contains("implementation-marker-must-not-leak"));
    let json = serde_json::to_string(&inspection).expect("inspection JSON");
    assert!(!json.contains("implementation-marker-must-not-leak"));
    assert_eq!(fixture.manifest.mission.generation, 7);
}

#[test]
fn resolved_receipt_survives_unmount_but_new_resolution_fails() {
    let fixture = mount_fixture(7);
    let mut mounted = fixture.mounted;
    let request = read_request(&fixture.manifest, "unmount-request");
    let receipt = mounted.resolve(&request, fixture.now).expect("resolve");

    let unmount = mounted.unmount().expect("unmount");
    assert_eq!(unmount.contribution_count, 3);
    assert!(!mounted.inspection().mounted);
    assert!(mounted.composition_inspection().is_empty());
    assert!(matches!(
        mounted.resolve(&request, fixture.now),
        Err(CapabilityPluginError::CompositionUnavailable)
    ));

    let mut ledger = MemoryInvocationLedger::default();
    mounted
        .invoke_resolved(&receipt, &request, &mut ledger, fixture.now)
        .expect("immutable resolved invocation");
    assert_eq!(fixture.adapter.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn revoke_removes_rows_and_keeps_only_existing_receipts_usable() {
    let fixture = mount_fixture(7);
    let mut mounted = fixture.mounted;
    let request = read_request(&fixture.manifest, "revoke-request");
    let receipt = mounted.resolve(&request, fixture.now).expect("resolve");

    let revocation = mounted.revoke().expect("revoke");
    assert_eq!(revocation.revocation_revision, 2);
    assert!(!mounted.inspection().mounted);
    assert!(mounted.composition_inspection().is_empty());
    assert!(matches!(
        mounted.resolve(&request, fixture.now),
        Err(CapabilityPluginError::CompositionUnavailable)
    ));

    let mut ledger = MemoryInvocationLedger::default();
    mounted
        .invoke_resolved(&receipt, &request, &mut ledger, fixture.now)
        .expect("existing receipt remains typed");
}

#[test]
fn scope_generation_and_binding_drift_fail_closed() {
    let first = fixture(7);
    let wrong_scope = plugin_scope(8);
    assert!(matches!(
        MountedReadOnlyCapability::mount(
            PluginRuntime::new(),
            first.gateway,
            first.signed_manifest,
            first.adapter,
            PluginVersion::new(1, 0, 0),
            wrong_scope,
            first.now,
        ),
        Err(CapabilityPluginError::ScopeMismatch)
    ));

    let stale = fixture(7);
    let mut stale_runtime = PluginRuntime::new();
    stale_runtime
        .advance_generation(
            PluginProjectId::new("project-plugin-cap").expect("project"),
            PluginMissionId::new("mission-plugin-cap").expect("mission"),
            8,
        )
        .expect("advance generation");
    assert!(matches!(
        MountedReadOnlyCapability::mount(
            stale_runtime,
            stale.gateway,
            stale.signed_manifest,
            stale.adapter,
            PluginVersion::new(1, 0, 0),
            stale.scope,
            stale.now,
        ),
        Err(CapabilityPluginError::Plugin(
            hartevo_plugin_runtime::PluginError::StaleGeneration
        ))
    ));

    let drift = fixture(7);
    let mut drift_manifest = drift.manifest.clone();
    drift_manifest.revocation.registry_revision += 1;
    let key_pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("manifest key");
    let drift_signed =
        SignedCapabilityManifest::sign(drift_manifest, "plugin-cap-drift-key", key_pair.as_ref())
            .expect("drift manifest");
    assert!(matches!(
        MountedReadOnlyCapability::mount(
            PluginRuntime::new(),
            drift.gateway,
            drift_signed,
            drift.adapter,
            PluginVersion::new(1, 0, 0),
            drift.scope,
            drift.now,
        ),
        Err(CapabilityPluginError::BindingDrift)
    ));

    let revoked = fixture(7);
    let mut registry = revoked.gateway.registry().clone();
    registry
        .revoke(&revoked.adapter.binding.adapter_id)
        .expect("revoke adapter");
    let registration = registry
        .registration(&revoked.adapter.binding.adapter_id)
        .expect("revoked registration");
    let mut revoked_manifest = revoked.manifest.clone();
    revoked_manifest.adapter = registration.binding.clone();
    revoked_manifest.revocation.registry_revision = registration.registry_revision;
    revoked_manifest.revocation.revocation_epoch = registration.binding.revocation_epoch;
    revoked_manifest.revocation.record_digest = registration.record_digest.clone();
    let key_pair = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("manifest key");
    let revoked_signed = SignedCapabilityManifest::sign(
        revoked_manifest.clone(),
        "plugin-cap-revoked-key",
        key_pair.as_ref(),
    )
    .expect("revoked manifest");
    let revoked_adapter = ReadOnlyAdapter {
        binding: revoked_manifest.adapter,
        calls: Arc::new(AtomicUsize::new(0)),
    };
    assert!(matches!(
        MountedReadOnlyCapability::mount(
            PluginRuntime::new(),
            CapabilityGateway::new(registry).expect("revoked gateway"),
            revoked_signed,
            revoked_adapter,
            PluginVersion::new(1, 0, 0),
            revoked.scope,
            revoked.now,
        ),
        Err(CapabilityPluginError::Gateway(GatewayError::AdapterRevoked))
    ));
}

proptest! {
    #[test]
    fn identical_scope_and_manifest_have_stable_mount_identity(generation in 1_u64..1_000_u64) {
        let first_fixture = mount_fixture(generation);
        let second_fixture = mount_fixture(generation);
        let first = &first_fixture.mounted;
        let second = &second_fixture.mounted;
        prop_assert_eq!(first.mount_receipt().digest(), second.mount_receipt().digest());
        prop_assert_eq!(first.inspection(), second.inspection());
        prop_assert!(!serde_json::to_string(first.mount_receipt())
            .expect("receipt JSON")
            .contains("implementation-marker-must-not-leak"));
        prop_assert_eq!(
            first_fixture.manifest.digest().expect("first manifest digest"),
            second_fixture.manifest.digest().expect("second manifest digest"),
        );

        let different_generation = mount_fixture(generation + 1);
        prop_assert_ne!(
            first.mount_receipt().digest(),
            different_generation.mounted.mount_receipt().digest(),
        );
        prop_assert_eq!(
            first.composition_inspection().providers.len(),
            1,
        );
    }
}
