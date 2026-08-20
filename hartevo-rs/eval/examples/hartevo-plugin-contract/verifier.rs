use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use serde::Serialize;

use crate::digest::{bool_text, domain_digest, is_lower_hex, sha256_hex};
use crate::model::{
    AuthorityBoundary, Composition, ConsumerDefinition, DurableEvent, DurableLogFence, EventKind,
    FixtureObservation, LifecyclePolicy, LifecycleState, PluginFixture, PluginIdentity,
    PluginManifest, PluginRegistry, ProjectMissionScope, ProviderDefinition, ReadinessPolicy,
    RegistryPolicy, ScopeKind, ServiceDefinition, SurfaceDefinition, parse_strict_json,
};

pub const MANIFEST_PATH: &str = "contracts/plugins/manifest.v1.json";
pub const REGISTRY_PATH: &str = "contracts/plugins/registry.v1.json";
pub const FIXTURE_PATH: &str = "contracts/plugins/fixture.v1.json";
pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-plugin-validation/v1";
pub const AUTHORITY: &str = "plugin_contract_validation_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const NOT_EVALUATED: &str = "NOT_EVALUATED";
pub const REAL_PROVIDER_REASON: &str = "REAL_PROVIDER_REGISTRATION_EMPTY";

// These are deliberately checked-in after the contract bytes are frozen. The
// evaluator therefore cannot silently validate a different manifest, registry,
// or fixture while retaining the same Rust type shape.
pub const MANIFEST_RAW_SHA256: &str =
    "f0e785c6bc0eed7c9e0d1670917fc4ce64702310d7f91d52b2e6c802bc766327";
pub const REGISTRY_RAW_SHA256: &str =
    "af606202bcbd6a06335959a1538ac8ba317520859259a78d06a91a3dc472c4bd";
pub const FIXTURE_RAW_SHA256: &str =
    "1e1d5f63278b66476c0486dcb49766f1e4c3271c619e4f9df8bcde5f4cd85053";

const PLUGIN_ID: &str = "hartevo.readonly.market-evidence";
const PLUGIN_VERSION: &str = "1.0.0";
const SOURCE_DIGEST_DOMAIN: &str = "hartevo-plugin-source/v1";
const PLUGIN_IDENTITY_DOMAIN: &str = "hartevo-plugin-identity/v1";
const SERVICE_DEFINITION_DOMAIN: &str = "hartevo-plugin-service-definition/v1";
const PROVIDER_DEFINITION_DOMAIN: &str = "hartevo-plugin-provider-definition/v1";
const CONSUMER_DEFINITION_DOMAIN: &str = "hartevo-plugin-consumer-definition/v1";
const SURFACE_DEFINITION_DOMAIN: &str = "hartevo-plugin-surface-definition/v1";
const SCHEMA_DIGEST_DOMAIN: &str = "hartevo-plugin-schema/v1";
const IMPLEMENTATION_DIGEST_DOMAIN: &str = "hartevo-plugin-implementation/v1";
const COMMAND_DIGEST_DOMAIN: &str = "hartevo-plugin-command/v1";
const REGISTRY_DIGEST_DOMAIN: &str = "hartevo-plugin-registry/v1";
const SCOPE_DIGEST_DOMAIN: &str = "hartevo-plugin-scope/v1";
const MOUNT_RECEIPT_DOMAIN: &str = "hartevo-plugin-mount-receipt/v1";
const UNMOUNT_RECEIPT_DOMAIN: &str = "hartevo-plugin-unmount-receipt/v1";
const EVENT_DIGEST_DOMAIN: &str = "hartevo-plugin-durable-event/v1";

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct ValidationReport {
    pub schema_version: &'static str,
    pub authority: &'static str,
    pub validator_status: &'static str,
    pub readiness_status: &'static str,
    pub reason_code: &'static str,
    pub catalog_plugin_count: usize,
    pub active_registration_count: usize,
    pub fixture_registration_count: usize,
    pub real_provider_count: usize,
    pub native_calls: usize,
    pub provider_execution: bool,
    pub contract_validated: bool,
    pub capability_evaluated: bool,
    pub release_decision: &'static str,
    pub writes_performed: bool,
    pub manifest_digest: String,
    pub registry_digest: String,
    pub fixture_digest: String,
    pub lifecycle_reversible: bool,
    pub durable_log_replayable: bool,
    pub direct_authority_granted: bool,
}

pub fn validate_contracts(
    manifest_bytes: &[u8],
    registry_bytes: &[u8],
    fixture_bytes: &[u8],
) -> Result<ValidationReport> {
    validate_raw_digest(manifest_bytes, MANIFEST_RAW_SHA256, "manifest")?;
    validate_raw_digest(registry_bytes, REGISTRY_RAW_SHA256, "registry")?;
    validate_raw_digest(fixture_bytes, FIXTURE_RAW_SHA256, "fixture")?;

    let manifest = parse_strict_json::<PluginManifest>(manifest_bytes)
        .context("plugin manifest is not strict typed JSON")?;
    let registry = parse_strict_json::<PluginRegistry>(registry_bytes)
        .context("plugin registry is not strict typed JSON")?;
    let fixture = parse_strict_json::<PluginFixture>(fixture_bytes)
        .context("plugin fixture is not strict typed JSON")?;

    validate_manifest(&manifest)?;
    validate_registry(&registry, &manifest)?;
    validate_fixture(&fixture, &manifest)?;

    let fixture_registration_count = fixture
        .host_composition
        .registrations
        .len()
        .checked_add(
            fixture
                .project_mission_compositions
                .iter()
                .map(|composition| composition.registrations.len())
                .sum::<usize>(),
        )
        .context("fixture registration count overflow")?;

    ensure!(
        registry.active_registrations.is_empty(),
        "active registry must remain empty"
    );
    ensure!(
        registry.trusted_providers.is_empty(),
        "trusted provider registry must remain empty"
    );
    ensure!(fixture.observation.real_provider_count == 0);
    ensure!(fixture.observation.registration_count == 0);
    ensure!(!fixture.observation.provider_execution);
    ensure!(fixture.observation.native_calls == 0);

    Ok(ValidationReport {
        schema_version: VALIDATION_SCHEMA_VERSION,
        authority: AUTHORITY,
        validator_status: "CONTRACT_VALIDATED",
        readiness_status: NOT_EVALUATED,
        reason_code: REAL_PROVIDER_REASON,
        catalog_plugin_count: registry.catalog_plugin_ids.len(),
        active_registration_count: registry.active_registrations.len(),
        fixture_registration_count,
        real_provider_count: fixture.observation.real_provider_count,
        native_calls: fixture.observation.native_calls,
        provider_execution: fixture.observation.provider_execution,
        contract_validated: true,
        capability_evaluated: false,
        release_decision: RELEASE_DECISION,
        writes_performed: false,
        manifest_digest: sha256_hex(manifest_bytes),
        registry_digest: sha256_hex(registry_bytes),
        fixture_digest: sha256_hex(fixture_bytes),
        lifecycle_reversible: manifest.plugin.lifecycle.reversible_mount
            && manifest.plugin.lifecycle.atomic_mount_receipt
            && manifest.plugin.lifecycle.reverse_order_unmount,
        durable_log_replayable: manifest.durable_log_fence.replay_deterministic,
        direct_authority_granted: false,
    })
}

fn validate_raw_digest(bytes: &[u8], expected: &str, label: &str) -> Result<()> {
    ensure!(
        is_lower_hex(expected, 32),
        "compiled {label} digest is not lowercase SHA-256"
    );
    let actual = sha256_hex(bytes);
    ensure!(
        actual == expected,
        "{label} raw digest drift: expected {expected}, got {actual}"
    );
    Ok(())
}

fn validate_manifest(manifest: &PluginManifest) -> Result<()> {
    ensure!(manifest.schema_version == "hartevo-plugin-manifest/v1");
    ensure!(manifest.contract_version == "plugin-contract-closure-01/v1");
    ensure!(manifest.catalog_version == "desktop-2026-08-14-plugin-catalog/v1");
    ensure!(manifest.authority == "contract_validation_only");
    ensure!(manifest.release_decision == RELEASE_DECISION);
    validate_plugin_identity(&manifest.plugin)?;
    ensure!(manifest.service_definitions.len() == 1);
    ensure!(manifest.providers.len() == 1);
    ensure!(manifest.consumers.len() == 1);
    ensure!(manifest.surfaces.len() == 2);
    validate_service(&manifest.service_definitions[0])?;
    validate_provider(&manifest.providers[0], &manifest.service_definitions[0])?;
    validate_consumer(&manifest.consumers[0], &manifest.service_definitions[0])?;
    for surface in &manifest.surfaces {
        validate_surface(surface, &manifest.consumers[0])?;
    }
    validate_composition_rules(&manifest.composition_rules)?;
    validate_log_fence(&manifest.durable_log_fence)?;
    validate_authority_boundary(&manifest.authority_boundary)?;
    validate_readiness_policy(&manifest.readiness_policy)?;
    Ok(())
}

fn validate_plugin_identity(plugin: &PluginIdentity) -> Result<()> {
    ensure!(plugin.plugin_id == PLUGIN_ID && plugin.version == PLUGIN_VERSION);
    ensure!(plugin.manifest_revision == 1);
    ensure!(plugin.provenance == "synthetic_contract_fixture");
    let expected_source = domain_digest(SOURCE_DIGEST_DOMAIN, &[PLUGIN_ID, PLUGIN_VERSION]);
    ensure!(plugin.source_digest == expected_source);
    let expected_definition = domain_digest(
        PLUGIN_IDENTITY_DOMAIN,
        &[
            plugin.plugin_id.as_str(),
            plugin.version.as_str(),
            &plugin.manifest_revision.to_string(),
            plugin.source_digest.as_str(),
        ],
    );
    ensure!(plugin.definition_digest == expected_definition);
    ensure!(plugin.scope_kinds == [ScopeKind::Host, ScopeKind::ProjectMission]);
    validate_lifecycle(&plugin.lifecycle)
}

fn validate_lifecycle(lifecycle: &LifecyclePolicy) -> Result<()> {
    ensure!(lifecycle.initial_state == LifecycleState::Defined);
    ensure!(
        lifecycle.states
            == [
                LifecycleState::Defined,
                LifecycleState::Mounted,
                LifecycleState::Stopping,
                LifecycleState::Stopped,
                LifecycleState::Revoked,
                LifecycleState::Failed,
            ]
    );
    ensure!(
        lifecycle.terminal_states
            == [
                LifecycleState::Stopped,
                LifecycleState::Revoked,
                LifecycleState::Failed
            ]
    );
    ensure!(lifecycle.reversible_mount);
    ensure!(lifecycle.atomic_mount_receipt);
    ensure!(lifecycle.reverse_order_unmount);
    ensure!(lifecycle.crash_policy == "revoke_and_unmount");
    Ok(())
}

fn validate_service(service: &ServiceDefinition) -> Result<()> {
    ensure!(service.service_id == "market.evidence.read");
    ensure!(service.version == 1);
    ensure!(service.mode == "read_only");
    ensure!(service.scope_kind == ScopeKind::ProjectMission);
    ensure!(service.provider_cardinality == "exactly_one");
    ensure!(service.reversible);
    let input_digest = domain_digest(
        SCHEMA_DIGEST_DOMAIN,
        &[service.service_id.as_str(), "input", "1"],
    );
    let output_digest = domain_digest(
        SCHEMA_DIGEST_DOMAIN,
        &[service.service_id.as_str(), "output", "1"],
    );
    ensure!(service.input_schema_digest == input_digest);
    ensure!(service.output_schema_digest == output_digest);
    let expected = domain_digest(
        SERVICE_DEFINITION_DOMAIN,
        &[
            service.service_id.as_str(),
            &service.version.to_string(),
            service.input_schema_digest.as_str(),
            service.output_schema_digest.as_str(),
            service.mode.as_str(),
            "project_mission",
            service.provider_cardinality.as_str(),
            bool_text(service.reversible),
        ],
    );
    ensure!(service.definition_digest == expected);
    Ok(())
}

fn validate_provider(provider: &ProviderDefinition, service: &ServiceDefinition) -> Result<()> {
    ensure!(provider.provider_id == "market.evidence.real-provider");
    ensure!(provider.service_id == service.service_id && provider.version == service.version);
    ensure!(provider.provider_kind == "real_provider_adapter");
    ensure!(provider.availability == NOT_EVALUATED);
    ensure!(provider.registration_state == "catalog_only");
    ensure!(provider.read_only && provider.real_provider_required);
    ensure!(provider.authority == "provider_adapter_only");
    ensure!(
        provider.direct_authorities
            == (crate::model::DirectAuthorities {
                store: false,
                keyring: false,
                browser_profile: false,
                effect: false,
            })
    );
    let expected_implementation = domain_digest(
        IMPLEMENTATION_DIGEST_DOMAIN,
        &[
            provider.provider_id.as_str(),
            provider.service_id.as_str(),
            "1",
            "unavailable",
        ],
    );
    ensure!(provider.implementation_digest == expected_implementation);
    let expected = domain_digest(
        PROVIDER_DEFINITION_DOMAIN,
        &[
            provider.provider_id.as_str(),
            provider.service_id.as_str(),
            &provider.version.to_string(),
            provider.implementation_digest.as_str(),
            provider.provider_kind.as_str(),
            provider.availability.as_str(),
            provider.registration_state.as_str(),
            provider.authority.as_str(),
        ],
    );
    ensure!(provider.definition_digest == expected);
    Ok(())
}

fn validate_consumer(consumer: &ConsumerDefinition, service: &ServiceDefinition) -> Result<()> {
    ensure!(consumer.consumer_id == "market.evidence.inspect");
    ensure!(consumer.service_id == service.service_id && consumer.version == service.version);
    ensure!(consumer.kind == "tool");
    ensure!(consumer.model_visible && consumer.read_only);
    ensure!(consumer.scope_kind == ScopeKind::ProjectMission);
    let expected_command = domain_digest(
        COMMAND_DIGEST_DOMAIN,
        &[
            consumer.consumer_id.as_str(),
            consumer.service_id.as_str(),
            "1",
        ],
    );
    ensure!(consumer.command_digest == expected_command);
    let expected = domain_digest(
        CONSUMER_DEFINITION_DOMAIN,
        &[
            consumer.consumer_id.as_str(),
            consumer.service_id.as_str(),
            &consumer.version.to_string(),
            consumer.kind.as_str(),
            bool_text(consumer.model_visible),
            bool_text(consumer.read_only),
            "project_mission",
            consumer.command_digest.as_str(),
        ],
    );
    ensure!(consumer.definition_digest == expected);
    Ok(())
}

fn validate_surface(surface: &SurfaceDefinition, consumer: &ConsumerDefinition) -> Result<()> {
    ensure!(surface.consumer_id == consumer.consumer_id);
    ensure!(surface.version == 1 && surface.model_visible);
    ensure!(surface.scope_kind == ScopeKind::ProjectMission);
    ensure!(matches!(
        surface.surface_kind.as_str(),
        "conversation_node" | "result_view"
    ));
    let expected = domain_digest(
        SURFACE_DEFINITION_DOMAIN,
        &[
            surface.surface_id.as_str(),
            surface.surface_kind.as_str(),
            surface.consumer_id.as_str(),
            &surface.version.to_string(),
            bool_text(surface.model_visible),
            "project_mission",
        ],
    );
    ensure!(surface.definition_digest == expected);
    Ok(())
}

fn validate_composition_rules(rules: &crate::model::CompositionRules) -> Result<()> {
    ensure!(rules.host_scope_kind == ScopeKind::Host);
    ensure!(rules.project_mission_scope_kind == ScopeKind::ProjectMission);
    ensure!(rules.host_contribution_kinds == ["service_definition", "provider"]);
    ensure!(rules.project_mission_contribution_kinds == ["consumer", "surface", "provider"]);
    ensure!(rules.cross_scope_mount_forbidden);
    ensure!(rules.provider_selection_per_project_mission);
    ensure!(rules.duplicate_provider_policy == "deny");
    ensure!(rules.stale_generation_policy == "deny");
    ensure!(rules.scope_drift_policy == "deny");
    Ok(())
}

fn validate_log_fence(fence: &DurableLogFence) -> Result<()> {
    ensure!(fence.schema_version == "hartevo-plugin-durable-log/v1");
    ensure!(fence.event_kinds == [EventKind::Input, EventKind::Output, EventKind::Lifecycle]);
    ensure!(fence.model_visible_input_required && fence.model_visible_output_required);
    ensure!(
        fence.sequence_monotonic
            && fence.scope_digest_required
            && fence.definition_digest_required
            && fence.replay_deterministic
            && fence.debug_content_free
            && !fence.raw_secret_or_private_content_allowed
    );
    Ok(())
}

fn validate_authority_boundary(boundary: &AuthorityBoundary) -> Result<()> {
    ensure!(boundary.direct_store_access == "forbidden");
    ensure!(boundary.direct_keyring_access == "forbidden");
    ensure!(boundary.direct_browser_profile_access == "forbidden");
    ensure!(boundary.direct_effect_authority == "forbidden");
    ensure!(boundary.effect_broker_only);
    ensure!(boundary.secret_material == "reference_only");
    ensure!(boundary.model_visible_raw_secrets == "forbidden");
    ensure!(boundary.manifest_private_content == "forbidden");
    Ok(())
}

fn validate_readiness_policy(policy: &ReadinessPolicy) -> Result<()> {
    ensure!(policy.registration_mode == "empty_by_default");
    ensure!(policy.real_provider_required);
    ensure!(policy.catalog_does_not_count && policy.fixture_does_not_count);
    ensure!(policy.empty_registry_status == NOT_EVALUATED);
    ensure!(policy.status_on_missing_real_provider == NOT_EVALUATED);
    ensure!(policy.release_decision == RELEASE_DECISION);
    Ok(())
}

fn validate_registry(registry: &PluginRegistry, manifest: &PluginManifest) -> Result<()> {
    ensure!(registry.schema_version == "hartevo-plugin-registry/v1");
    ensure!(registry.registry_version == "desktop-2026-08-14-plugin-registry/v1");
    ensure!(registry.registry_epoch == 0);
    ensure!(registry.catalog_plugin_ids == [manifest.plugin.plugin_id.as_str()]);
    ensure!(registry.active_registrations.is_empty());
    ensure!(registry.trusted_providers.is_empty());
    let expected_digest = domain_digest(
        REGISTRY_DIGEST_DOMAIN,
        &[
            registry.registry_version.as_str(),
            &registry.registry_epoch.to_string(),
            manifest.plugin.plugin_id.as_str(),
            "active:0",
            "trusted:0",
        ],
    );
    ensure!(registry.registry_digest == expected_digest);
    validate_registry_policy(&registry.policy)
}

fn validate_registry_policy(policy: &RegistryPolicy) -> Result<()> {
    ensure!(policy.registration_mode == "empty_by_default");
    ensure!(policy.empty_registry_admission == "deny");
    ensure!(!policy.native_loading_allowed && !policy.real_provider_execution_allowed);
    ensure!(!policy.fixture_registrations_count_as_capability);
    ensure!(!policy.catalog_entries_count_as_capability);
    ensure!(policy.release_decision == RELEASE_DECISION);
    Ok(())
}

fn validate_fixture(fixture: &PluginFixture, manifest: &PluginManifest) -> Result<()> {
    ensure!(fixture.schema_version == "hartevo-plugin-fixture/v1");
    ensure!(fixture.fixture_id == "readonly-market-plugin-mount/v1");
    ensure!(fixture.fixture_class == "contract_fixture");
    ensure!(fixture.plugin_id == manifest.plugin.plugin_id);
    ensure!(fixture.plugin_version == manifest.plugin.version);
    ensure!(fixture.plugin_definition_digest == manifest.plugin.definition_digest);
    validate_composition(
        &fixture.host_composition,
        ScopeKind::Host,
        &manifest.service_definitions,
        &manifest.providers,
        &manifest.consumers,
        &manifest.surfaces,
    )?;
    ensure!(fixture.project_mission_compositions.len() == 1);
    ensure!(
        fixture.host_composition.composition_id
            != fixture.project_mission_compositions[0].composition_id
    );
    ensure!(
        fixture.host_composition.scope_digest
            != fixture.project_mission_compositions[0].scope_digest
    );
    validate_composition(
        &fixture.project_mission_compositions[0],
        ScopeKind::ProjectMission,
        &manifest.service_definitions,
        &manifest.providers,
        &manifest.consumers,
        &manifest.surfaces,
    )?;
    validate_lifecycle_trace(&fixture.lifecycle_trace)?;
    validate_durable_events(&fixture.durable_events, manifest)?;
    validate_observation(&fixture.observation)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_composition(
    composition: &Composition,
    expected_scope: ScopeKind,
    services: &[ServiceDefinition],
    providers: &[ProviderDefinition],
    consumers: &[ConsumerDefinition],
    surfaces: &[SurfaceDefinition],
) -> Result<()> {
    ensure!(composition.scope_kind == expected_scope);
    ensure!(composition.generation > 0);
    ensure!(composition.registration_state == "mounted");
    ensure!(is_lower_hex(&composition.scope_digest, 32));
    match expected_scope {
        ScopeKind::Host => {
            ensure!(composition.scope.is_none());
            let expected_scope_digest = domain_digest(
                SCOPE_DIGEST_DOMAIN,
                &[
                    composition.composition_id.as_str(),
                    "host",
                    &composition.generation.to_string(),
                ],
            );
            ensure!(composition.scope_digest == expected_scope_digest);
            ensure!(composition.registrations.len() == 2);
            ensure!(composition.registrations[0].contribution_kind == "service_definition");
            ensure!(composition.registrations[0].contribution_id == services[0].service_id);
            ensure!(composition.registrations[1].contribution_kind == "provider");
            ensure!(composition.registrations[1].contribution_id == providers[0].provider_id);
        }
        ScopeKind::ProjectMission => {
            let scope = composition
                .scope
                .as_ref()
                .context("project/misson scope missing")?;
            validate_project_scope(scope, &composition.scope_digest)?;
            ensure!(composition.registrations.len() == 3);
            ensure!(composition.registrations[0].contribution_kind == "consumer");
            ensure!(composition.registrations[0].contribution_id == consumers[0].consumer_id);
            ensure!(composition.registrations[1].contribution_kind == "surface");
            ensure!(composition.registrations[1].contribution_id == surfaces[0].surface_id);
            ensure!(composition.registrations[2].contribution_kind == "surface");
            ensure!(composition.registrations[2].contribution_id == surfaces[1].surface_id);
        }
    }
    validate_registration_list(&composition.registrations)?;
    let contribution_ids = composition
        .registrations
        .iter()
        .map(|registration| registration.contribution_id.clone())
        .collect::<Vec<_>>();
    validate_mount_receipt(&composition.mount_receipt, composition, &contribution_ids)?;
    validate_unmount_receipt(&composition.unmount_receipt, composition, &contribution_ids)?;
    Ok(())
}

fn validate_project_scope(scope: &ProjectMissionScope, scope_digest: &str) -> Result<()> {
    for digest in [
        &scope.tenant_id_digest,
        &scope.project_id_digest,
        &scope.mission_id_digest,
    ] {
        ensure!(is_lower_hex(digest, 32));
    }
    let expected = domain_digest(
        SCOPE_DIGEST_DOMAIN,
        &[
            scope.tenant_id_digest.as_str(),
            scope.project_id_digest.as_str(),
            scope.mission_id_digest.as_str(),
        ],
    );
    ensure!(scope_digest == expected);
    Ok(())
}

fn validate_registration_list(
    registrations: &[crate::model::ContributionRegistration],
) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut contribution_ids = BTreeSet::new();
    for (index, registration) in registrations.iter().enumerate() {
        ensure!(registration.sequence == index as u64 + 1);
        ensure!(ids.insert(registration.registration_id.clone()));
        ensure!(contribution_ids.insert(registration.contribution_id.clone()));
    }
    Ok(())
}

fn validate_mount_receipt(
    receipt: &crate::model::MountReceipt,
    composition: &Composition,
    contribution_ids: &[String],
) -> Result<()> {
    ensure!(receipt.generation == composition.generation);
    ensure!(receipt.atomic && receipt.reverse_order_unmount);
    ensure!(receipt.contribution_ids == contribution_ids);
    let expected = domain_digest(
        MOUNT_RECEIPT_DOMAIN,
        &[
            receipt.receipt_id.as_str(),
            &receipt.generation.to_string(),
            composition.composition_id.as_str(),
            composition.scope_digest.as_str(),
            &contribution_ids.join(","),
        ],
    );
    ensure!(receipt.receipt_digest == expected);
    Ok(())
}

fn validate_unmount_receipt(
    receipt: &crate::model::UnmountReceipt,
    composition: &Composition,
    contribution_ids: &[String],
) -> Result<()> {
    ensure!(receipt.generation == composition.generation);
    ensure!(receipt.atomic && receipt.remaining_registration_count == 0);
    let mut expected_reverse = contribution_ids.to_vec();
    expected_reverse.reverse();
    ensure!(receipt.reverse_order == expected_reverse);
    let expected = domain_digest(
        UNMOUNT_RECEIPT_DOMAIN,
        &[
            receipt.receipt_id.as_str(),
            &receipt.generation.to_string(),
            composition.composition_id.as_str(),
            composition.scope_digest.as_str(),
            &receipt.reverse_order.join(","),
            "remaining:0",
        ],
    );
    ensure!(receipt.receipt_digest == expected);
    Ok(())
}

fn validate_lifecycle_trace(trace: &[crate::model::LifecycleTraceEntry]) -> Result<()> {
    ensure!(trace.len() == 4);
    let expected = [
        (1, LifecycleState::Defined),
        (2, LifecycleState::Mounted),
        (3, LifecycleState::Stopping),
        (4, LifecycleState::Stopped),
    ];
    for (entry, (sequence, state)) in trace.iter().zip(expected) {
        ensure!(entry.sequence == sequence);
        ensure!(entry.state == state);
        ensure!(entry.generation == 7);
        ensure!(entry.scope_kind == ScopeKind::Host);
    }
    Ok(())
}

fn validate_durable_events(events: &[DurableEvent], manifest: &PluginManifest) -> Result<()> {
    ensure!(events.len() == 3);
    let mut ids = BTreeSet::new();
    let mut sequences = BTreeSet::new();
    for event in events {
        ensure!(ids.insert(event.event_id.clone()));
        ensure!(sequences.insert(event.sequence));
        ensure!(event.sequence > 0);
        ensure!(is_lower_hex(&event.scope_digest, 32));
        ensure!(is_lower_hex(&event.definition_digest, 32));
        ensure!(is_lower_hex(&event.payload_digest, 32));
        ensure!(is_lower_hex(&event.event_digest, 32));
        match event.event_kind {
            EventKind::Input | EventKind::Output => {
                ensure!(event.model_visible);
                ensure!(event.scope_kind == ScopeKind::ProjectMission);
                ensure!(event.definition_digest == manifest.consumers[0].definition_digest);
            }
            EventKind::Lifecycle => {
                ensure!(!event.model_visible);
                ensure!(event.scope_kind == ScopeKind::Host);
                ensure!(event.definition_digest == manifest.plugin.definition_digest);
            }
        }
        let expected = domain_digest(
            EVENT_DIGEST_DOMAIN,
            &[
                &event.sequence.to_string(),
                event.event_id.as_str(),
                event_kind_text(event.event_kind),
                scope_kind_text(event.scope_kind),
                event.scope_digest.as_str(),
                event.definition_digest.as_str(),
                bool_text(event.model_visible),
                event.payload_digest.as_str(),
            ],
        );
        ensure!(event.event_digest == expected);
    }
    ensure!(sequences.into_iter().eq(1..=events.len() as u64));
    Ok(())
}

fn event_kind_text(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Input => "input",
        EventKind::Output => "output",
        EventKind::Lifecycle => "lifecycle",
    }
}

fn scope_kind_text(scope: ScopeKind) -> &'static str {
    match scope {
        ScopeKind::Host => "host",
        ScopeKind::ProjectMission => "project_mission",
    }
}

fn validate_observation(observation: &FixtureObservation) -> Result<()> {
    ensure!(observation.registration_count == 0);
    ensure!(observation.real_provider_count == 0);
    ensure!(observation.native_calls == 0);
    ensure!(!observation.provider_execution);
    ensure!(observation.status == NOT_EVALUATED);
    ensure!(observation.release_decision == RELEASE_DECISION);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FIXTURE_RAW_SHA256, MANIFEST_RAW_SHA256, REGISTRY_RAW_SHA256, validate_contracts};
    use crate::model::{PluginFixture, PluginManifest, PluginRegistry, parse_strict_json};

    const MANIFEST: &[u8] = include_bytes!("../../../../contracts/plugins/manifest.v1.json");
    const REGISTRY: &[u8] = include_bytes!("../../../../contracts/plugins/registry.v1.json");
    const FIXTURE: &[u8] = include_bytes!("../../../../contracts/plugins/fixture.v1.json");

    fn validated() -> super::ValidationReport {
        validate_contracts(MANIFEST, REGISTRY, FIXTURE).expect("plugin contract validates")
    }

    #[test]
    fn raw_contract_digests_are_compiled_and_contract_only() {
        let report = validated();
        assert_eq!(report.validator_status, "CONTRACT_VALIDATED");
        assert_eq!(report.readiness_status, "NOT_EVALUATED");
        assert_eq!(report.reason_code, super::REAL_PROVIDER_REASON);
        assert_eq!(report.native_calls, 0);
        assert!(!report.capability_evaluated);
        assert!(!report.provider_execution);
        assert!(!report.direct_authority_granted);
        assert_eq!(report.manifest_digest, MANIFEST_RAW_SHA256);
        assert_eq!(report.registry_digest, REGISTRY_RAW_SHA256);
        assert_eq!(report.fixture_digest, FIXTURE_RAW_SHA256);
    }

    #[test]
    fn provider_catalog_and_fixture_do_not_count_as_registration() {
        let report = validated();
        assert_eq!(report.catalog_plugin_count, 1);
        assert_eq!(report.active_registration_count, 0);
        assert_eq!(report.real_provider_count, 0);
        assert_eq!(report.fixture_registration_count, 5);
    }

    #[test]
    fn manifest_mutations_fail_closed() {
        let mut manifest = parse_strict_json::<PluginManifest>(MANIFEST).expect("manifest");
        manifest.providers[0].direct_authorities.store = true;
        let bytes = serde_json::to_vec(&manifest).expect("serialize");
        assert!(validate_contracts(&bytes, REGISTRY, FIXTURE).is_err());

        let mut manifest = parse_strict_json::<PluginManifest>(MANIFEST).expect("manifest");
        manifest.consumers[0].definition_digest = "a".repeat(64);
        let bytes = serde_json::to_vec(&manifest).expect("serialize");
        assert!(validate_contracts(&bytes, REGISTRY, FIXTURE).is_err());
    }

    #[test]
    fn registry_and_scope_mutations_fail_closed() {
        let mut registry = parse_strict_json::<PluginRegistry>(REGISTRY).expect("registry");
        registry.policy.native_loading_allowed = true;
        let bytes = serde_json::to_vec(&registry).expect("serialize");
        assert!(validate_contracts(MANIFEST, &bytes, FIXTURE).is_err());

        let mut fixture = parse_strict_json::<PluginFixture>(FIXTURE).expect("fixture");
        fixture.project_mission_compositions[0]
            .scope
            .as_mut()
            .unwrap()
            .mission_id_digest = "e".repeat(64);
        let bytes = serde_json::to_vec(&fixture).expect("serialize");
        assert!(validate_contracts(MANIFEST, REGISTRY, &bytes).is_err());
    }

    #[test]
    fn lifecycle_and_durable_log_mutations_fail_closed() {
        let mut fixture = parse_strict_json::<PluginFixture>(FIXTURE).expect("fixture");
        fixture
            .host_composition
            .unmount_receipt
            .remaining_registration_count = 1;
        let bytes = serde_json::to_vec(&fixture).expect("serialize");
        assert!(validate_contracts(MANIFEST, REGISTRY, &bytes).is_err());

        let mut fixture = parse_strict_json::<PluginFixture>(FIXTURE).expect("fixture");
        fixture.durable_events[0].model_visible = false;
        let bytes = serde_json::to_vec(&fixture).expect("serialize");
        assert!(validate_contracts(MANIFEST, REGISTRY, &bytes).is_err());
    }

    #[test]
    fn stale_generation_and_cross_scope_mount_fail_closed() {
        let mut fixture = parse_strict_json::<PluginFixture>(FIXTURE).expect("fixture");
        fixture.host_composition.mount_receipt.generation = 6;
        let bytes = serde_json::to_vec(&fixture).expect("serialize");
        assert!(validate_contracts(MANIFEST, REGISTRY, &bytes).is_err());

        let mut fixture = parse_strict_json::<PluginFixture>(FIXTURE).expect("fixture");
        fixture.host_composition.scope_kind = crate::model::ScopeKind::ProjectMission;
        let bytes = serde_json::to_vec(&fixture).expect("serialize");
        assert!(validate_contracts(MANIFEST, REGISTRY, &bytes).is_err());
    }

    #[test]
    fn raw_byte_drift_is_rejected_before_typed_validation() {
        let mut bytes = MANIFEST.to_vec();
        bytes.push(b'\n');
        assert!(validate_contracts(&bytes, REGISTRY, FIXTURE).is_err());
    }
}
