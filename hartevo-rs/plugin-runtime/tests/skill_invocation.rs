use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use chrono::{DateTime, Duration, TimeZone, Utc};
use hartevo_capability_gateway::{
    AdapterBinding, AdapterId, AdapterRegistry, ApprovalRequirement, BudgetAuthority, BudgetUse,
    CAPABILITY_MANIFEST_SCHEMA, CAPABILITY_REQUEST_SCHEMA, CAPABILITY_RESULT_SCHEMA,
    CapabilityClass, CapabilityCompositionLifecycle, CapabilityCompositionScope,
    CapabilityCompositionSnapshot, CapabilityConsumerDefinition, CapabilityGateway,
    CapabilityInvocationCloseReason, CapabilityInvocationContext,
    CapabilityInvocationEffectReceipt, CapabilityInvocationVisibility, CapabilityManifest,
    CapabilityProviderDefinition, CapabilityRequest, CapabilityResolutionSelector,
    CapabilityResult, CapabilityServiceDefinition, CapabilityVersion, CostLimit, DataAuthority,
    DataClass, Digest as GatewayDigest, EffectAuthority, EffectDisposition, EffectId, EffectKind,
    ExternalEffectRequest, IdempotencyKey, InvocationScope, ManifestIssuer, ManifestProvenance,
    MemoryCapabilityInvocationLog, MemoryCapabilityResolutionLedger, MissionId as GatewayMissionId,
    MissionScope, NetworkAuthority, Origin, ProjectId as GatewayProjectId, ProjectScope,
    Provenance, ProvenanceSource, ReadCompleteness, ReadOperation, ReadRequest, ReadResult,
    RequestId, RequestPayload, ResultPayload, RevocationBinding, RevocationStatus, SecretAuthority,
    SignedCapabilityManifest, TenantId,
};
use hartevo_plugin_runtime::skill::{
    MemorySkillPackAuditLog, SkillEffectClass, SkillItemId, SkillPackCapabilityResolution,
    SkillPackCapabilityResolver, SkillPackFile, SkillPackHostAdapter, SkillPackHostError,
    SkillPackLoadRequest, SkillPackManifest, SkillPackMigrationReceipt, SkillPackMissionContext,
    SkillPackPath, SkillPackPolicy, SkillPackPolicySpec, SkillPackProvider, SkillPackSource,
    SkillPackUpgradePlan, SkillPackVerificationAttestation, SkillPackVerificationReceipt,
    SkillPackVerificationStatus, SkillPackVerifiedPackage, SkillServiceRequirement,
    SkillToolRequirement,
};
use hartevo_plugin_runtime::skill_invocation::{
    MemorySkillPackInvocationLog, SkillPackInvocationConsumer, SkillPackInvocationError,
    SkillPackInvocationEventKind, SkillPackInvocationItemKind, SkillPackInvocationSelector,
};
use hartevo_plugin_runtime::{
    ConsumerId, Digest, MissionId, PluginId, PluginRuntime, PluginScope, PluginVersion, ProjectId,
    ServiceId,
};
use proptest::prelude::*;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

const HOST_API: PluginVersion = PluginVersion::new(1, 0, 0);
const NOW: (i32, u32, u32, u32, u32, u32) = (2030, 1, 1, 12, 0, 0);

struct SkillFixture {
    package: SkillPackVerifiedPackage,
    policy: SkillPackPolicy,
    request: SkillPackLoadRequest,
    context: SkillPackMissionContext,
    tool: SkillToolRequirement,
    item_id: SkillItemId,
    item_content_digest: Digest,
    visible_text: String,
}

#[derive(Debug)]
struct FixtureHost {
    package: SkillPackVerifiedPackage,
    releases: Arc<Mutex<Vec<Digest>>>,
    upgrade_plan: Option<hartevo_plugin_runtime::skill::SkillPackUpgradePlan>,
}

impl FixtureHost {
    fn new(package: SkillPackVerifiedPackage) -> (Self, Arc<Mutex<Vec<Digest>>>) {
        let releases = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                package,
                releases: releases.clone(),
                upgrade_plan: None,
            },
            releases,
        )
    }
}

impl SkillPackHostAdapter for FixtureHost {
    fn verify_and_load(
        &mut self,
        _request: &SkillPackLoadRequest,
    ) -> Result<SkillPackVerifiedPackage, SkillPackHostError> {
        Ok(self.package.clone())
    }

    fn prepare_upgrade(
        &mut self,
        _current: &SkillPackVerifiedPackage,
        _request: &SkillPackLoadRequest,
    ) -> Result<hartevo_plugin_runtime::skill::SkillPackUpgradePlan, SkillPackHostError> {
        self.upgrade_plan
            .clone()
            .ok_or(SkillPackHostError::MigrationUnavailable)
    }

    fn release(&mut self, package_digest: &Digest) -> Result<(), SkillPackHostError> {
        self.releases
            .lock()
            .expect("release ledger")
            .push(package_digest.clone());
        Ok(())
    }
}

struct ExactSkillResolver;

impl SkillPackCapabilityResolver for ExactSkillResolver {
    fn resolve(
        &mut self,
        scope: &PluginScope,
        policy: &SkillPackPolicy,
        required_services: &[SkillServiceRequirement],
        required_tools: &[SkillToolRequirement],
    ) -> Result<SkillPackCapabilityResolution, hartevo_plugin_runtime::skill::SkillPackError> {
        SkillPackCapabilityResolution::from_requirements(
            scope,
            policy,
            required_services.to_vec(),
            required_tools.to_vec(),
        )
    }
}

struct GatewayFixture {
    gateway: CapabilityGateway,
    signed: SignedCapabilityManifest,
    request: CapabilityRequest,
    composition: CapabilityCompositionSnapshot,
    selector: CapabilityResolutionSelector,
    now: DateTime<Utc>,
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(NOW.0, NOW.1, NOW.2, NOW.3, NOW.4, NOW.5)
        .single()
        .expect("fixed test time")
}

fn gateway_digest(value: &str) -> GatewayDigest {
    GatewayDigest::from_text(value)
}

fn plugin_scope(generation: u64) -> PluginScope {
    PluginScope::new(
        ProjectId::new("project.skill-invocation").expect("project"),
        MissionId::new("mission.skill-invocation").expect("mission"),
        generation,
    )
    .expect("scope")
}

fn plugin_digest(scope: &PluginScope) -> GatewayDigest {
    GatewayDigest::parse(scope.digest().as_str().to_owned()).expect("scope digest")
}

fn skill_fixture(effect_class: SkillEffectClass, generation: u64) -> SkillFixture {
    skill_fixture_with_version(effect_class, generation, PluginVersion::new(1, 0, 0))
}

fn skill_fixture_with_version(
    effect_class: SkillEffectClass,
    generation: u64,
    skill_version: PluginVersion,
) -> SkillFixture {
    let package_id =
        hartevo_plugin_runtime::skill::SkillPackId::new("pack.invocation").expect("package id");
    let plugin_id = PluginId::new("plugin.skill.invocation").expect("plugin id");
    let skill_id =
        hartevo_plugin_runtime::skill::SkillId::new("skill.invocation").expect("skill id");
    let item_id = SkillItemId::new("recipe.lookup").expect("item id");
    let service = SkillServiceRequirement::new(
        ServiceId::new("data.read").expect("service id"),
        PluginVersion::new(1, 0, 0),
        Digest::from_text("data.read.contract"),
    )
    .expect("service requirement");
    let tool = SkillToolRequirement::new(
        ServiceId::new("data.read").expect("tool service"),
        ConsumerId::new("data.lookup").expect("tool id"),
        PluginVersion::new(1, 0, 0),
        Digest::from_text("data.lookup.descriptor"),
        effect_class,
    )
    .expect("tool requirement");
    let path = SkillPackPath::new("recipes/lookup.md").expect("path");
    let visible_text = "read the exact typed result through the approved gateway".to_owned();
    let bytes = visible_text.as_bytes().to_vec();
    let item_content_digest = Digest::from_bytes(&bytes);
    let files = vec![SkillPackFile::regular(path.clone(), bytes).expect("file")];
    let manifest = SkillPackManifest::new(
        package_id.clone(),
        plugin_id,
        skill_id.clone(),
        skill_version,
        HOST_API,
        BTreeMap::from([(path.clone(), item_content_digest.clone())]),
        BTreeMap::new(),
        BTreeMap::from([(item_id.clone(), path)]),
        vec![service.clone()],
        vec![tool.clone()],
    )
    .expect("manifest");
    let source = SkillPackSource::new(
        Digest::from_text("fixture.skill.locator"),
        Digest::from_text("fixture.skill.source"),
    )
    .expect("source");
    let content_digest = SkillPackVerifiedPackage::content_digest_for_files(&files);
    let verification =
        SkillPackVerificationReceipt::from_attestation(SkillPackVerificationAttestation {
            status: SkillPackVerificationStatus::Verified,
            verifier_digest: Digest::from_text("fixture.verifier"),
            signature_digest: Digest::from_text("fixture.signature"),
            source_digest: source.source_digest().clone(),
            manifest_digest: manifest.digest().clone(),
            content_digest: content_digest.clone(),
            host_api: HOST_API,
            verified_at: 1,
        })
        .expect("verification receipt");
    let package = SkillPackVerifiedPackage::new(manifest, source.clone(), &files, verification)
        .expect("verified package");
    let policy = SkillPackPolicy::new(SkillPackPolicySpec {
        allowed_package_ids: BTreeSet::from([package.manifest().package_id().clone()]),
        allowed_skill_ids: BTreeSet::from([package.manifest().skill_id().clone()]),
        allowed_source_digests: BTreeSet::from([source.source_digest().clone()]),
        allowed_instruction_ids: BTreeSet::new(),
        allowed_recipe_ids: BTreeSet::from([item_id.clone()]),
        allowed_capability_digests: BTreeSet::from([service.digest(), tool.digest()]),
        host_api: HOST_API,
    })
    .expect("policy");
    let scope = plugin_scope(generation);
    let request = SkillPackLoadRequest::new(
        scope.clone(),
        policy.digest().clone(),
        source,
        Some(package.package_digest().clone()),
        Some(package.manifest().digest().clone()),
        Some(package.content_digest().clone()),
    )
    .expect("load request");
    let context =
        SkillPackMissionContext::new(scope, policy.digest().clone()).expect("Mission context");
    SkillFixture {
        package,
        policy,
        request,
        context,
        tool,
        item_id,
        item_content_digest,
        visible_text,
    }
}

#[allow(clippy::match_same_arms, clippy::too_many_lines)]
fn gateway_fixture(skill: &SkillFixture, effect_class: SkillEffectClass) -> GatewayFixture {
    let now = now();
    let class = match effect_class {
        SkillEffectClass::ReadOnly => CapabilityClass::Read,
        SkillEffectClass::EffectProposal => CapabilityClass::ExternalEffect,
    };
    let capability_id = hartevo_capability_gateway::CapabilityId::from_stable("data.lookup");
    let binding = AdapterBinding {
        adapter_id: AdapterId::from_stable("skill-tool.adapter"),
        implementation_id: "typed-skill-tool-provider".into(),
        implementation_digest: gateway_digest("skill-tool-provider-v1"),
        binary_digest: gateway_digest("skill-tool-binary-v1"),
        schema_digest: gateway_digest("skill-tool-schema-v1"),
        version: "1.0.0".into(),
        revocation_epoch: 1,
    };
    let mut registry = AdapterRegistry::new();
    let record_digest = registry
        .register(binding.clone(), BTreeSet::from([capability_id.clone()]))
        .expect("adapter registration");
    let plugin_scope_digest = plugin_digest(skill.context.scope());
    let project = ProjectScope {
        tenant_id: TenantId::from_stable("tenant.skill-invocation"),
        project_id: GatewayProjectId::from_stable(skill.context.scope().project_id().as_str()),
        workspace_digest: gateway_digest("workspace"),
        resource_scope_digest: gateway_digest("resource-scope"),
    };
    let mission = MissionScope {
        tenant_id: project.tenant_id.clone(),
        project_id: project.project_id.clone(),
        mission_id: GatewayMissionId::from_stable(skill.context.scope().mission_id().as_str()),
        task_id: None,
        worker_id: None,
        worker_lease_id: None,
        context_workspace_id: None,
        context_capsule_id: None,
        context_branch_id: None,
        generation: skill.context.scope().generation(),
        contract_revision: 1,
        scope_digest: plugin_scope_digest,
    };
    let network = match class {
        CapabilityClass::Read => NetworkAuthority::None,
        CapabilityClass::ExternalEffect => NetworkAuthority::EffectBroker {
            providers: BTreeSet::from([String::from("mail")]),
        },
        CapabilityClass::LocalMutation => NetworkAuthority::None,
    };
    let effect = match class {
        CapabilityClass::ExternalEffect => EffectAuthority {
            allowed_kinds: BTreeSet::from([EffectKind::Outreach]),
            allowed_providers: BTreeSet::from([String::from("mail")]),
            approval: ApprovalRequirement::Required,
            uncertain_policy: hartevo_capability_gateway::UncertainEffectPolicy::ReconcileOnly,
            max_cost: None,
            broker_policy_digest: gateway_digest("broker-policy"),
        },
        _ => EffectAuthority {
            allowed_kinds: BTreeSet::new(),
            allowed_providers: BTreeSet::new(),
            approval: ApprovalRequirement::Required,
            uncertain_policy: hartevo_capability_gateway::UncertainEffectPolicy::ReconcileOnly,
            max_cost: None,
            broker_policy_digest: gateway_digest("broker-policy"),
        },
    };
    let manifest = CapabilityManifest {
        schema: CAPABILITY_MANIFEST_SCHEMA.into(),
        manifest_version: 1,
        schema_digest: binding.schema_digest.clone(),
        capability_id: capability_id.clone(),
        class,
        project,
        mission,
        data: DataAuthority {
            maximum_class: DataClass::Business,
            allowed_resource_digests: BTreeSet::new(),
        },
        network,
        secrets: SecretAuthority::none(),
        budget: BudgetAuthority {
            max_tokens: 100,
            max_cost: CostLimit {
                amount_minor: 100,
                currency: "USD".into(),
            },
            max_request_bytes: 4_096,
            max_result_bytes: 4_096,
            max_external_effects: u32::from(class == CapabilityClass::ExternalEffect),
            deadline_at: now + Duration::hours(1),
        },
        effect,
        adapter: binding.clone(),
        revocation: RevocationBinding {
            registry_revision: registry.revision,
            revocation_epoch: 1,
            status: RevocationStatus::Active,
            record_digest,
        },
        provenance: ManifestProvenance {
            issuer: ManifestIssuer::Application,
            source_digest: gateway_digest("skill-manifest-source"),
            parent_manifest_digest: None,
            issued_for_generation: skill.context.scope().generation(),
        },
        issued_at: now - Duration::seconds(1),
        expires_at: now + Duration::hours(1),
    };
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("signing key");
    let signed = SignedCapabilityManifest::sign(manifest.clone(), "skill-test-key", key.as_ref())
        .expect("signed manifest");
    let manifest_digest = manifest.digest().expect("manifest digest");
    let authority_digest = manifest.authority_digest().expect("authority digest");
    let request = match class {
        CapabilityClass::Read => CapabilityRequest {
            schema: CAPABILITY_REQUEST_SCHEMA.into(),
            request_id: RequestId::from_stable("skill-read-request"),
            capability_id,
            class,
            scope: InvocationScope::from_manifest(&manifest),
            generation: manifest.mission.generation,
            idempotency_key: IdempotencyKey::from_stable("skill-read-idempotency"),
            manifest_digest: manifest_digest.clone(),
            provenance: Provenance {
                source: ProvenanceSource::Runtime,
                manifest_digest: manifest_digest.clone(),
                authority_digest: authority_digest.clone(),
                parent_digest: None,
                input_digest: gateway_digest("skill-read-input"),
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
        },
        CapabilityClass::ExternalEffect => {
            let payload = hartevo_capability_gateway::BoundedPayload::try_new(
                "skill.effect-proposal/v1",
                DataClass::Business,
                b"typed-effect-proposal".to_vec(),
                manifest.budget.max_request_bytes,
            )
            .expect("effect payload");
            CapabilityRequest {
                schema: CAPABILITY_REQUEST_SCHEMA.into(),
                request_id: RequestId::from_stable("skill-effect-request"),
                capability_id,
                class,
                scope: InvocationScope::from_manifest(&manifest),
                generation: manifest.mission.generation,
                idempotency_key: IdempotencyKey::from_stable("skill-effect-idempotency"),
                manifest_digest: manifest_digest.clone(),
                provenance: Provenance {
                    source: ProvenanceSource::Runtime,
                    manifest_digest: manifest_digest.clone(),
                    authority_digest: authority_digest.clone(),
                    parent_digest: None,
                    input_digest: gateway_digest("skill-effect-input"),
                    generation: manifest.mission.generation,
                    observed_at: now - Duration::seconds(1),
                    links: Vec::new(),
                },
                budget_use: BudgetUse {
                    request_bytes: payload.byte_len,
                    result_bytes: 0,
                    estimated_tokens: 1,
                    estimated_cost: CostLimit {
                        amount_minor: 0,
                        currency: "USD".into(),
                    },
                    external_effect_count: 1,
                },
                payload: RequestPayload::ExternalEffect(ExternalEffectRequest {
                    effect_id: EffectId::from_stable("skill-effect"),
                    kind: EffectKind::Outreach,
                    provider: "mail".into(),
                    target_origin: Origin::parse("https://mail.example").expect("origin"),
                    target_digest: gateway_digest("skill-target"),
                    payload,
                    audience_digest: Some(gateway_digest("skill-audience")),
                    amount: None,
                    approval_required: ApprovalRequirement::Required,
                    secret_references: BTreeSet::new(),
                }),
            }
        }
        CapabilityClass::LocalMutation => unreachable!("fixture has no local mutation"),
    };
    let version = CapabilityVersion::new(1, 0, 0);
    let service_digest = gateway_digest("data.read");
    let provider_digest = gateway_digest("provider.data.lookup");
    let owner_plugin_digest = gateway_digest("plugin.data.provider");
    let consumer_digest = gateway_digest("data.lookup");
    let composition_scope = CapabilityCompositionScope::new(
        manifest.mission.project_id.clone(),
        manifest.mission.mission_id.clone(),
        manifest.mission.generation,
        manifest.mission.scope_digest.clone(),
    )
    .expect("composition scope");
    let service = CapabilityServiceDefinition::new(
        service_digest.clone(),
        owner_plugin_digest.clone(),
        gateway_digest(manifest.capability_id.as_str()),
        class,
        version,
        manifest_digest,
        authority_digest.clone(),
        1,
        hartevo_capability_gateway::ContributionLifecycle::Active,
    )
    .expect("service");
    let provider = CapabilityProviderDefinition::new(
        provider_digest,
        service_digest.clone(),
        owner_plugin_digest.clone(),
        binding.implementation_digest.clone(),
        version,
        hartevo_capability_gateway::ContributionLifecycle::Active,
    )
    .expect("provider");
    let consumer = CapabilityConsumerDefinition::new(
        consumer_digest.clone(),
        service_digest.clone(),
        owner_plugin_digest,
        gateway_digest(manifest.capability_id.as_str()),
        class,
        version,
        authority_digest,
        gateway_digest(CAPABILITY_REQUEST_SCHEMA),
        composition_scope.clone(),
        hartevo_capability_gateway::ContributionLifecycle::Active,
    )
    .expect("consumer");
    let composition = CapabilityCompositionSnapshot::new(
        composition_scope,
        1,
        CapabilityCompositionLifecycle::Mounted,
        vec![service],
        vec![provider],
        vec![consumer],
    )
    .expect("composition");
    let selector = CapabilityResolutionSelector::new(consumer_digest, service_digest, version)
        .expect("selector");
    GatewayFixture {
        gateway: CapabilityGateway::new(registry).expect("gateway"),
        signed,
        request,
        composition,
        selector,
        now,
    }
}

fn mount_and_compose(
    skill: &SkillFixture,
) -> (
    SkillPackProvider<FixtureHost>,
    PluginRuntime,
    hartevo_plugin_runtime::skill::SkillPackModelContext,
    MemorySkillPackAuditLog,
) {
    let (host, _releases) = FixtureHost::new(skill.package.clone());
    let mut runtime = PluginRuntime::new();
    let mut provider =
        SkillPackProvider::load_and_mount(host, &skill.request, skill.policy.clone(), &mut runtime)
            .expect("mount");
    let mut resolver = ExactSkillResolver;
    let mut audit = MemorySkillPackAuditLog::default();
    let model = provider
        .compose(&skill.context, &mut resolver, &mut runtime, &mut audit, 10)
        .expect("compose");
    (provider, runtime, model, audit)
}

fn resolve(
    gateway: &GatewayFixture,
) -> (
    hartevo_capability_gateway::CapabilityResolutionLease,
    MemoryCapabilityResolutionLedger,
    CapabilityInvocationContext,
) {
    let mut audit = MemoryCapabilityResolutionLedger::default();
    let lease = gateway
        .gateway
        .resolver()
        .resolve(
            &gateway.composition,
            &gateway.signed,
            &gateway.request,
            &gateway.selector,
            gateway.now,
            &mut audit,
        )
        .expect("resolve exact binding");
    let context = CapabilityInvocationContext::from_binding(
        lease.binding(),
        CapabilityInvocationVisibility::ModelVisible,
    )
    .expect("invocation context");
    (lease, audit, context)
}

#[allow(clippy::too_many_arguments)]
fn propose(
    skill: &SkillFixture,
    provider: &mut SkillPackProvider<FixtureHost>,
    runtime: &PluginRuntime,
    model: &hartevo_plugin_runtime::skill::SkillPackModelContext,
    gateway: &GatewayFixture,
    resolution: hartevo_capability_gateway::CapabilityResolutionLease,
    mut resolution_audit: MemoryCapabilityResolutionLedger,
    invocation_log: &mut MemorySkillPackInvocationLog,
    context: CapabilityInvocationContext,
) -> (
    hartevo_plugin_runtime::skill_invocation::SkillPackInvocationProposal,
    MemoryCapabilityResolutionLedger,
) {
    let selector = SkillPackInvocationSelector::new(
        skill.item_id.clone(),
        SkillPackInvocationItemKind::Recipe,
        skill.item_content_digest.clone(),
    )
    .expect("selector");
    let consumer = SkillPackInvocationConsumer::new();
    let proposal = consumer
        .propose(
            provider,
            &skill.context,
            model,
            selector,
            skill.tool.clone(),
            resolution,
            gateway.composition.clone(),
            gateway.signed.clone(),
            gateway.request.clone(),
            context,
            runtime,
            &mut resolution_audit,
            invocation_log,
            gateway.now + Duration::seconds(1),
        )
        .expect("typed proposal");
    (proposal, resolution_audit)
}

fn read_result(request: &CapabilityRequest) -> CapabilityResult {
    CapabilityResult {
        schema: CAPABILITY_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        capability_id: request.capability_id.clone(),
        class: request.class,
        scope: request.scope.clone(),
        generation: request.generation,
        manifest_digest: request.manifest_digest.clone(),
        provenance: request.provenance.clone(),
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

fn external_effect_digest(request: &CapabilityRequest) -> GatewayDigest {
    let RequestPayload::ExternalEffect(effect) = &request.payload else {
        panic!("external request expected");
    };
    GatewayDigest::from_bytes(&serde_json::to_vec(effect).expect("effect serialization"))
}

fn external_result(
    request: &CapabilityRequest,
    disposition: EffectDisposition,
    receipt_digest: Option<GatewayDigest>,
    verification_digest: Option<GatewayDigest>,
    reconciliation_digest: Option<GatewayDigest>,
) -> CapabilityResult {
    let RequestPayload::ExternalEffect(effect) = &request.payload else {
        panic!("external request expected");
    };
    CapabilityResult {
        schema: CAPABILITY_RESULT_SCHEMA.into(),
        request_id: request.request_id.clone(),
        capability_id: request.capability_id.clone(),
        class: CapabilityClass::ExternalEffect,
        scope: request.scope.clone(),
        generation: request.generation,
        manifest_digest: request.manifest_digest.clone(),
        provenance: request.provenance.clone(),
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
        payload: ResultPayload::ExternalEffect(hartevo_capability_gateway::ExternalEffectResult {
            effect_id: effect.effect_id.clone(),
            effect_digest: external_effect_digest(request),
            disposition,
            receipt_digest,
            verification_digest,
            reconciliation_digest,
        }),
    }
}

#[test]
fn read_invocation_is_typed_durable_model_visible_and_content_free() {
    let skill = skill_fixture(SkillEffectClass::ReadOnly, 1);
    let (mut provider, runtime, model, _skill_audit) = mount_and_compose(&skill);
    let gateway = gateway_fixture(&skill, SkillEffectClass::ReadOnly);
    let (resolution, resolution_audit, invocation_context) = resolve(&gateway);
    let mut skill_log = MemorySkillPackInvocationLog::default();
    let (proposal, mut resolution_audit) = propose(
        &skill,
        &mut provider,
        &runtime,
        &model,
        &gateway,
        resolution,
        resolution_audit,
        &mut skill_log,
        invocation_context,
    );
    let proposal_json = serde_json::to_string(&proposal).expect("proposal json");
    assert!(!proposal_json.contains(&skill.visible_text));
    assert!(!format!("{proposal:?}").contains(&skill.visible_text));
    let mut gateway_log = MemoryCapabilityInvocationLog::default();
    let mut lease = proposal
        .begin(
            &mut provider,
            &skill.context,
            &runtime,
            &gateway.gateway,
            &mut gateway_log,
            &mut skill_log,
            &mut resolution_audit,
            gateway.now + Duration::seconds(2),
        )
        .expect("begin invocation");
    let result = lease
        .complete(
            &mut provider,
            &skill.context,
            &runtime,
            &gateway.gateway,
            read_result(&gateway.request),
            None,
            &mut gateway_log,
            &mut resolution_audit,
            &mut skill_log,
            gateway.now + Duration::seconds(3),
        )
        .expect("complete invocation");
    assert_eq!(result.result().class, CapabilityClass::Read);
    assert!(lease.is_released());
    assert_eq!(gateway_log.len(), 2);
    assert_eq!(resolution_audit.len(), 2);
    assert_eq!(skill_log.len(), 2);
    assert_eq!(
        skill_log.events()[0].kind(),
        SkillPackInvocationEventKind::Proposed
    );
    assert_eq!(
        skill_log.events()[1].kind(),
        SkillPackInvocationEventKind::Completed
    );
    assert_eq!(
        skill_log.events()[1].result_digest(),
        Some(result.result_digest())
    );
    assert_eq!(
        skill_log.events()[1].binding().generation(),
        skill_log.events()[1]
            .binding()
            .gateway_provider_generation()
    );
    let result_json = serde_json::to_string(&result).expect("result json");
    let log_json = serde_json::to_string(skill_log.events()).expect("log json");
    assert!(result_json.contains(CAPABILITY_RESULT_SCHEMA));
    assert!(!result_json.contains(&skill.visible_text));
    assert!(!log_json.contains(&skill.visible_text));
}

#[test]
fn failed_begin_terminalizes_proposal_and_releases_resolution() {
    let skill = skill_fixture(SkillEffectClass::ReadOnly, 1);
    let (mut provider, mut runtime, model, _skill_audit) = mount_and_compose(&skill);
    let gateway = gateway_fixture(&skill, SkillEffectClass::ReadOnly);
    let (resolution, resolution_audit, invocation_context) = resolve(&gateway);
    let mut skill_log = MemorySkillPackInvocationLog::default();
    let (proposal, mut resolution_audit) = propose(
        &skill,
        &mut provider,
        &runtime,
        &model,
        &gateway,
        resolution,
        resolution_audit,
        &mut skill_log,
        invocation_context,
    );
    provider.crash(&mut runtime).expect("crash provider");
    let mut gateway_log = MemoryCapabilityInvocationLog::default();
    assert!(matches!(
        proposal.begin(
            &mut provider,
            &skill.context,
            &runtime,
            &gateway.gateway,
            &mut gateway_log,
            &mut skill_log,
            &mut resolution_audit,
            gateway.now + Duration::seconds(2),
        ),
        Err(SkillPackInvocationError::Provider(_))
    ));
    assert!(gateway_log.is_empty());
    assert_eq!(resolution_audit.len(), 2);
    assert_eq!(skill_log.len(), 2);
    assert_eq!(
        skill_log.events()[1].kind(),
        SkillPackInvocationEventKind::Invalidated
    );
    assert!(runtime.inspect(skill.context.scope()).is_empty());
}

#[test]
fn upgrade_invalidates_old_invocation_without_dispatch_or_residue() {
    let old =
        skill_fixture_with_version(SkillEffectClass::ReadOnly, 1, PluginVersion::new(1, 0, 0));
    let upgraded =
        skill_fixture_with_version(SkillEffectClass::ReadOnly, 1, PluginVersion::new(1, 1, 0));
    assert_eq!(old.policy.digest(), upgraded.policy.digest());
    let migration = SkillPackMigrationReceipt::new(
        &old.context.scope().clone(),
        &old.policy,
        &old.package,
        &upgraded.package,
        Digest::from_text("fixture.skill.migration"),
    )
    .expect("migration receipt");
    let (mut host, _releases) = FixtureHost::new(old.package.clone());
    host.upgrade_plan = Some(SkillPackUpgradePlan::new(
        upgraded.package.clone(),
        migration,
    ));
    let mut runtime = PluginRuntime::new();
    let mut provider =
        SkillPackProvider::load_and_mount(host, &old.request, old.policy.clone(), &mut runtime)
            .expect("mount old package");
    let mut resolver = ExactSkillResolver;
    let mut lifecycle_log = MemorySkillPackAuditLog::default();
    let model = provider
        .compose(
            &old.context,
            &mut resolver,
            &mut runtime,
            &mut lifecycle_log,
            1,
        )
        .expect("compose old package");
    let gateway = gateway_fixture(&old, SkillEffectClass::ReadOnly);
    let (resolution, resolution_audit, invocation_context) = resolve(&gateway);
    let mut skill_log = MemorySkillPackInvocationLog::default();
    let (proposal, mut resolution_audit) = propose(
        &old,
        &mut provider,
        &runtime,
        &model,
        &gateway,
        resolution,
        resolution_audit,
        &mut skill_log,
        invocation_context,
    );
    let mut gateway_log = MemoryCapabilityInvocationLog::default();
    let mut lease = proposal
        .begin(
            &mut provider,
            &old.context,
            &runtime,
            &gateway.gateway,
            &mut gateway_log,
            &mut skill_log,
            &mut resolution_audit,
            gateway.now + Duration::seconds(2),
        )
        .expect("begin old invocation");
    provider
        .upgrade(
            &old.context,
            &upgraded.request,
            &mut runtime,
            &mut lifecycle_log,
            3,
        )
        .expect("upgrade package");
    assert!(matches!(
        lease.complete(
            &mut provider,
            &old.context,
            &runtime,
            &gateway.gateway,
            read_result(&gateway.request),
            None,
            &mut gateway_log,
            &mut resolution_audit,
            &mut skill_log,
            gateway.now + Duration::seconds(4),
        ),
        Err(SkillPackInvocationError::Provider(_))
    ));
    assert!(lease.is_released());
    assert_eq!(gateway_log.len(), 2);
    assert_eq!(resolution_audit.len(), 2);
    assert_eq!(skill_log.len(), 2);
    assert_eq!(
        skill_log.events()[1].kind(),
        SkillPackInvocationEventKind::Invalidated
    );
    provider
        .crash(&mut runtime)
        .expect("cleanup upgraded package");
    assert!(runtime.inspect(old.context.scope()).is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
fn effect_proposal_requires_verified_effect_receipt_and_never_retries_uncertain() {
    let skill = skill_fixture(SkillEffectClass::EffectProposal, 1);
    let (mut provider, runtime, model, _skill_audit) = mount_and_compose(&skill);
    let gateway = gateway_fixture(&skill, SkillEffectClass::EffectProposal);
    let (resolution, resolution_audit, invocation_context) = resolve(&gateway);
    let mut skill_log = MemorySkillPackInvocationLog::default();
    let (proposal, mut resolution_audit) = propose(
        &skill,
        &mut provider,
        &runtime,
        &model,
        &gateway,
        resolution,
        resolution_audit,
        &mut skill_log,
        invocation_context,
    );
    assert_eq!(
        proposal.binding().capability_class(),
        CapabilityClass::ExternalEffect
    );
    let mut gateway_log = MemoryCapabilityInvocationLog::default();
    let mut lease = proposal
        .begin(
            &mut provider,
            &skill.context,
            &runtime,
            &gateway.gateway,
            &mut gateway_log,
            &mut skill_log,
            &mut resolution_audit,
            gateway.now + Duration::seconds(2),
        )
        .expect("begin effect proposal");
    let uncertain = external_result(
        &gateway.request,
        EffectDisposition::Uncertain,
        None,
        None,
        Some(gateway_digest("reconcile")),
    );
    assert!(matches!(
        lease.complete(
            &mut provider,
            &skill.context,
            &runtime,
            &gateway.gateway,
            uncertain,
            None,
            &mut gateway_log,
            &mut resolution_audit,
            &mut skill_log,
            gateway.now + Duration::seconds(3),
        ),
        Err(SkillPackInvocationError::Invocation(_))
    ));
    assert!(lease.is_released());
    assert_eq!(gateway_log.len(), 2);
    assert_eq!(resolution_audit.len(), 2);
    assert_eq!(
        skill_log.events()[1].kind(),
        SkillPackInvocationEventKind::Invalidated
    );
    assert_eq!(
        skill_log.events()[1].reason(),
        Some(CapabilityInvocationCloseReason::UncertainExternalEffect)
    );
    assert!(matches!(
        lease.complete(
            &mut provider,
            &skill.context,
            &runtime,
            &gateway.gateway,
            external_result(
                &gateway.request,
                EffectDisposition::Verified,
                Some(gateway_digest("receipt")),
                Some(gateway_digest("verification")),
                None,
            ),
            None,
            &mut gateway_log,
            &mut resolution_audit,
            &mut skill_log,
            gateway.now + Duration::seconds(4),
        ),
        Err(SkillPackInvocationError::Invocation(_))
    ));

    let skill = skill_fixture(SkillEffectClass::EffectProposal, 1);
    let (mut provider, runtime, model, _skill_audit) = mount_and_compose(&skill);
    let gateway = gateway_fixture(&skill, SkillEffectClass::EffectProposal);
    let (resolution, resolution_audit, invocation_context) = resolve(&gateway);
    let mut skill_log = MemorySkillPackInvocationLog::default();
    let (proposal, mut resolution_audit) = propose(
        &skill,
        &mut provider,
        &runtime,
        &model,
        &gateway,
        resolution,
        resolution_audit,
        &mut skill_log,
        invocation_context,
    );
    let mut gateway_log = MemoryCapabilityInvocationLog::default();
    let mut lease = proposal
        .begin(
            &mut provider,
            &skill.context,
            &runtime,
            &gateway.gateway,
            &mut gateway_log,
            &mut skill_log,
            &mut resolution_audit,
            gateway.now + Duration::seconds(2),
        )
        .expect("begin verified effect");
    let effect_digest = external_effect_digest(&gateway.request);
    let receipt = CapabilityInvocationEffectReceipt::verified(
        effect_digest.clone(),
        gateway_digest("receipt"),
        gateway_digest("verification"),
    )
    .expect("effect receipt");
    let result = lease
        .complete(
            &mut provider,
            &skill.context,
            &runtime,
            &gateway.gateway,
            external_result(
                &gateway.request,
                EffectDisposition::Verified,
                Some(gateway_digest("receipt")),
                Some(gateway_digest("verification")),
                None,
            ),
            Some(&receipt),
            &mut gateway_log,
            &mut resolution_audit,
            &mut skill_log,
            gateway.now + Duration::seconds(3),
        )
        .expect("verified effect result");
    assert_eq!(
        result.result_digest(),
        result
            .gateway_release()
            .result_digest()
            .expect("result digest")
    );
    assert_eq!(
        result.gateway_release().effect_receipt_digest(),
        Some(receipt.receipt_digest())
    );
}

#[test]
fn unmount_revoke_and_crash_close_old_invocations_without_residue() {
    for mode in 0..3 {
        let skill = skill_fixture(SkillEffectClass::ReadOnly, 1);
        let (mut provider, mut runtime, model, mut lifecycle_log) = mount_and_compose(&skill);
        let gateway = gateway_fixture(&skill, SkillEffectClass::ReadOnly);
        let (resolution, resolution_audit, invocation_context) = resolve(&gateway);
        let mut skill_log = MemorySkillPackInvocationLog::default();
        let (proposal, mut resolution_audit) = propose(
            &skill,
            &mut provider,
            &runtime,
            &model,
            &gateway,
            resolution,
            resolution_audit,
            &mut skill_log,
            invocation_context,
        );
        let mut gateway_log = MemoryCapabilityInvocationLog::default();
        let mut lease = proposal
            .begin(
                &mut provider,
                &skill.context,
                &runtime,
                &gateway.gateway,
                &mut gateway_log,
                &mut skill_log,
                &mut resolution_audit,
                gateway.now + Duration::seconds(2),
            )
            .expect("begin");
        match mode {
            0 => {
                provider
                    .unmount(&skill.context, &mut runtime, &mut lifecycle_log, 3)
                    .expect("unmount");
            }
            1 => {
                provider
                    .revoke(&skill.context, &mut runtime, &mut lifecycle_log, 3)
                    .expect("revoke");
            }
            _ => provider.crash(&mut runtime).expect("crash"),
        }
        assert!(
            lease
                .complete(
                    &mut provider,
                    &skill.context,
                    &runtime,
                    &gateway.gateway,
                    read_result(&gateway.request),
                    None,
                    &mut gateway_log,
                    &mut resolution_audit,
                    &mut skill_log,
                    gateway.now + Duration::seconds(4),
                )
                .is_err()
        );
        assert!(lease.is_released());
        assert!(runtime.inspect(skill.context.scope()).is_empty());
        assert_eq!(gateway_log.len(), 2);
        assert_eq!(resolution_audit.len(), 2);
        assert_eq!(skill_log.len(), 2);
        assert_eq!(
            skill_log.events()[1].kind(),
            SkillPackInvocationEventKind::Invalidated
        );
    }
}

#[test]
fn scope_policy_visibility_and_replay_tamper_fail_closed_before_dispatch() {
    let skill = skill_fixture(SkillEffectClass::ReadOnly, 1);
    let (mut provider, runtime, model, _skill_audit) = mount_and_compose(&skill);
    let gateway = gateway_fixture(&skill, SkillEffectClass::ReadOnly);
    let (resolution, mut resolution_audit, _) = resolve(&gateway);
    let mut invocation_log = MemorySkillPackInvocationLog::default();
    let selector = SkillPackInvocationSelector::new(
        skill.item_id.clone(),
        SkillPackInvocationItemKind::Recipe,
        Digest::from_text("wrong-content"),
    )
    .expect("selector");
    let consumer = SkillPackInvocationConsumer::new();
    assert!(matches!(
        consumer.propose(
            &mut provider,
            &skill.context,
            &model,
            selector,
            skill.tool.clone(),
            resolution,
            gateway.composition.clone(),
            gateway.signed.clone(),
            gateway.request.clone(),
            CapabilityInvocationContext::from_binding(
                &gateway
                    .gateway
                    .resolver()
                    .resolve(
                        &gateway.composition,
                        &gateway.signed,
                        &gateway.request,
                        &gateway.selector,
                        gateway.now,
                        &mut MemoryCapabilityResolutionLedger::default(),
                    )
                    .expect("second resolution")
                    .binding()
                    .clone(),
                CapabilityInvocationVisibility::Internal,
            )
            .expect("internal context"),
            &runtime,
            &mut resolution_audit,
            &mut invocation_log,
            gateway.now + Duration::seconds(1),
        ),
        Err(
            SkillPackInvocationError::ItemNotVisible | SkillPackInvocationError::VisibilityRequired,
        )
    ));
    assert!(invocation_log.is_empty());
}

#[test]
fn repeated_identical_proposals_have_stable_digests_and_audit_json() {
    let make = || {
        let skill = skill_fixture(SkillEffectClass::ReadOnly, 1);
        let (mut provider, runtime, model, _skill_audit) = mount_and_compose(&skill);
        let gateway = gateway_fixture(&skill, SkillEffectClass::ReadOnly);
        let (resolution, resolution_audit, invocation_context) = resolve(&gateway);
        let mut log = MemorySkillPackInvocationLog::default();
        let (proposal, _resolution_audit) = propose(
            &skill,
            &mut provider,
            &runtime,
            &model,
            &gateway,
            resolution,
            resolution_audit,
            &mut log,
            invocation_context,
        );
        (proposal, log)
    };
    let (first, first_log) = make();
    let (second, second_log) = make();
    assert_eq!(first.proposal_digest(), second.proposal_digest());
    assert_eq!(
        serde_json::to_string(first_log.events()).expect("first json"),
        serde_json::to_string(second_log.events()).expect("second json")
    );
}

proptest! {
    #[test]
    fn generation_is_always_bound_in_the_proposal(generation in 1_u64..8) {
        let skill = skill_fixture(SkillEffectClass::ReadOnly, generation);
        let (mut provider, runtime, model, _skill_audit) = mount_and_compose(&skill);
        let gateway = gateway_fixture(&skill, SkillEffectClass::ReadOnly);
        let (resolution, resolution_audit, invocation_context) = resolve(&gateway);
        let mut log = MemorySkillPackInvocationLog::default();
        let (proposal, _resolution_audit) = propose(
            &skill,
            &mut provider,
            &runtime,
            &model,
            &gateway,
            resolution,
            resolution_audit,
            &mut log,
            invocation_context,
        );
        prop_assert_eq!(proposal.binding().generation(), generation);
        prop_assert_eq!(proposal.binding().gateway_provider_generation(), generation);
    }
}
