use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginManifest {
    pub schema_version: String,
    pub contract_version: String,
    pub catalog_version: String,
    pub authority: String,
    pub release_decision: String,
    pub plugin: PluginIdentity,
    pub service_definitions: Vec<ServiceDefinition>,
    pub providers: Vec<ProviderDefinition>,
    pub consumers: Vec<ConsumerDefinition>,
    pub surfaces: Vec<SurfaceDefinition>,
    pub composition_rules: CompositionRules,
    pub durable_log_fence: DurableLogFence,
    pub authority_boundary: AuthorityBoundary,
    pub readiness_policy: ReadinessPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginIdentity {
    pub plugin_id: String,
    pub version: String,
    pub manifest_revision: u64,
    pub source_digest: String,
    pub definition_digest: String,
    pub provenance: String,
    pub lifecycle: LifecyclePolicy,
    pub scope_kinds: Vec<ScopeKind>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecyclePolicy {
    pub initial_state: LifecycleState,
    pub states: Vec<LifecycleState>,
    pub terminal_states: Vec<LifecycleState>,
    pub reversible_mount: bool,
    pub atomic_mount_receipt: bool,
    pub reverse_order_unmount: bool,
    pub crash_policy: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Defined,
    Mounted,
    Stopping,
    Stopped,
    Revoked,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Host,
    ProjectMission,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceDefinition {
    pub service_id: String,
    pub version: u64,
    pub input_schema_digest: String,
    pub output_schema_digest: String,
    pub definition_digest: String,
    pub mode: String,
    pub scope_kind: ScopeKind,
    pub provider_cardinality: String,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDefinition {
    pub provider_id: String,
    pub service_id: String,
    pub version: u64,
    pub implementation_digest: String,
    pub definition_digest: String,
    pub provider_kind: String,
    pub availability: String,
    pub registration_state: String,
    pub read_only: bool,
    pub real_provider_required: bool,
    pub authority: String,
    pub direct_authorities: DirectAuthorities,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct DirectAuthorities {
    pub store: bool,
    pub keyring: bool,
    pub browser_profile: bool,
    pub effect: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsumerDefinition {
    pub consumer_id: String,
    pub service_id: String,
    pub version: u64,
    pub definition_digest: String,
    pub kind: String,
    pub model_visible: bool,
    pub read_only: bool,
    pub scope_kind: ScopeKind,
    pub command_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SurfaceDefinition {
    pub surface_id: String,
    pub surface_kind: String,
    pub consumer_id: String,
    pub version: u64,
    pub definition_digest: String,
    pub model_visible: bool,
    pub scope_kind: ScopeKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompositionRules {
    pub host_scope_kind: ScopeKind,
    pub project_mission_scope_kind: ScopeKind,
    pub host_contribution_kinds: Vec<String>,
    pub project_mission_contribution_kinds: Vec<String>,
    pub cross_scope_mount_forbidden: bool,
    pub provider_selection_per_project_mission: bool,
    pub duplicate_provider_policy: String,
    pub stale_generation_policy: String,
    pub scope_drift_policy: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct DurableLogFence {
    pub schema_version: String,
    pub event_kinds: Vec<EventKind>,
    pub model_visible_input_required: bool,
    pub model_visible_output_required: bool,
    pub sequence_monotonic: bool,
    pub scope_digest_required: bool,
    pub definition_digest_required: bool,
    pub replay_deterministic: bool,
    pub debug_content_free: bool,
    pub raw_secret_or_private_content_allowed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Input,
    Output,
    Lifecycle,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityBoundary {
    pub direct_store_access: String,
    pub direct_keyring_access: String,
    pub direct_browser_profile_access: String,
    pub direct_effect_authority: String,
    pub effect_broker_only: bool,
    pub secret_material: String,
    pub model_visible_raw_secrets: String,
    pub manifest_private_content: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadinessPolicy {
    pub registration_mode: String,
    pub real_provider_required: bool,
    pub catalog_does_not_count: bool,
    pub fixture_does_not_count: bool,
    pub empty_registry_status: String,
    pub status_on_missing_real_provider: String,
    pub release_decision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginRegistry {
    pub schema_version: String,
    pub registry_version: String,
    pub registry_epoch: u64,
    pub registry_digest: String,
    pub catalog_plugin_ids: Vec<String>,
    pub active_registrations: Vec<ActiveRegistration>,
    pub trusted_providers: Vec<TrustedProvider>,
    pub policy: RegistryPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveRegistration {
    pub registration_id: String,
    pub plugin_id: String,
    pub scope_kind: ScopeKind,
    pub scope_digest: String,
    pub generation: u64,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedProvider {
    pub provider_id: String,
    pub implementation_digest: String,
    pub registry_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RegistryPolicy {
    pub registration_mode: String,
    pub empty_registry_admission: String,
    pub native_loading_allowed: bool,
    pub real_provider_execution_allowed: bool,
    pub fixture_registrations_count_as_capability: bool,
    pub catalog_entries_count_as_capability: bool,
    pub release_decision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginFixture {
    pub schema_version: String,
    pub fixture_id: String,
    pub fixture_class: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_definition_digest: String,
    pub host_composition: Composition,
    pub project_mission_compositions: Vec<Composition>,
    pub lifecycle_trace: Vec<LifecycleTraceEntry>,
    pub durable_events: Vec<DurableEvent>,
    pub observation: FixtureObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct Composition {
    pub composition_id: String,
    pub scope_kind: ScopeKind,
    pub scope_digest: String,
    #[serde(default)]
    pub scope: Option<ProjectMissionScope>,
    pub generation: u64,
    pub registration_state: String,
    pub registrations: Vec<ContributionRegistration>,
    pub mount_receipt: MountReceipt,
    pub unmount_receipt: UnmountReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct ProjectMissionScope {
    pub tenant_id_digest: String,
    pub project_id_digest: String,
    pub mission_id_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContributionRegistration {
    pub registration_id: String,
    pub contribution_kind: String,
    pub contribution_id: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MountReceipt {
    pub receipt_id: String,
    pub generation: u64,
    pub atomic: bool,
    pub reverse_order_unmount: bool,
    pub contribution_ids: Vec<String>,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnmountReceipt {
    pub receipt_id: String,
    pub generation: u64,
    pub atomic: bool,
    pub reverse_order: Vec<String>,
    pub remaining_registration_count: usize,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleTraceEntry {
    pub sequence: u64,
    pub state: LifecycleState,
    pub generation: u64,
    pub scope_kind: ScopeKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableEvent {
    pub sequence: u64,
    pub event_id: String,
    pub event_kind: EventKind,
    pub scope_kind: ScopeKind,
    pub scope_digest: String,
    pub definition_digest: String,
    pub model_visible: bool,
    pub payload_digest: String,
    pub event_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureObservation {
    pub registration_count: usize,
    pub real_provider_count: usize,
    pub native_calls: usize,
    pub provider_execution: bool,
    pub status: String,
    pub release_decision: String,
}

pub fn parse_strict_json<T: DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}
