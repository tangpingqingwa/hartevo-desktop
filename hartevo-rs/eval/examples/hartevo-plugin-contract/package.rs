use serde::{Deserialize, Serialize};

use crate::model::{LifecycleState, ScopeKind};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtensionPackageManifest {
    pub schema_version: String,
    pub contract_version: String,
    pub package_id: String,
    pub package_version: String,
    pub manifest_revision: u64,
    pub definition_digest: String,
    pub base_manifest_digest: String,
    pub service_definition_digest: String,
    pub provider_definition_digest: String,
    pub consumer_definition_digest: String,
    pub binary: BinaryBinding,
    pub host_api: HostApiBinding,
    pub requested_scopes: Vec<RequestedScope>,
    pub requested_authorities: RequestedAuthorities,
    pub entrypoint: EntrypointBinding,
    pub lifecycle: PackageLifecycle,
    pub signature_policy: SignaturePolicy,
    pub runner_policy: RunnerPolicy,
    pub readiness_policy: PackageReadinessPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BinaryBinding {
    pub entrypoint: String,
    pub binary_format: String,
    pub binary_digest: String,
    pub assets: Vec<AssetBinding>,
    pub bundle_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssetBinding {
    pub asset_id: String,
    pub path_digest: String,
    pub content_digest: String,
    pub byte_count: u64,
    pub asset_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostApiBinding {
    pub api_id: String,
    pub major: u64,
    pub minor: u64,
    pub api_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestedScope {
    pub scope_kind: ScopeKind,
    pub scope_digest: String,
    pub capabilities: Vec<String>,
    pub scope_binding_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestedAuthorities {
    pub store: String,
    pub keyring: String,
    pub browser_profile: String,
    pub effect: String,
    pub allowed: Vec<String>,
    pub unknown_authority_policy: String,
    pub authority_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntrypointBinding {
    pub kind: String,
    pub symbol: String,
    pub symbol_digest: String,
    pub invocation: String,
    pub return_contract_digest: String,
    pub entrypoint_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageLifecycle {
    pub mount: String,
    pub unmount: String,
    pub upgrade: String,
    pub downgrade: String,
    pub revoke: String,
    pub crash_recovery: String,
    pub migration_policy: String,
    pub migration_reversible: bool,
    pub rollback_required: bool,
    pub receipt_required: bool,
    pub unknown_transition: String,
    pub lifecycle_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignaturePolicy {
    pub algorithm: String,
    pub required: bool,
    pub key_id_digest: String,
    pub key_registry_epoch: u64,
    pub signature_status: String,
    pub signed_payload_digest: String,
    pub signature_digest: String,
    pub signature_hex: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunnerPolicy {
    pub required: bool,
    pub registry_status: String,
    pub runner_id_digest: Option<String>,
    pub runner_binary_digest: Option<String>,
    pub runner_signature_status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageReadinessPolicy {
    pub real_signature_key_required: bool,
    pub real_runner_required: bool,
    pub empty_registry_status: String,
    pub fixture_does_not_count: bool,
    pub release_decision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageReceiptFixture {
    pub schema_version: String,
    pub fixture_id: String,
    pub package_id: String,
    pub package_version: String,
    pub package_definition_digest: String,
    pub scope: RequestedScope,
    pub receipts: Vec<PackageReceipt>,
    pub observation: PackageObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageReceipt {
    pub receipt_id: String,
    pub sequence: u64,
    pub operation: String,
    pub status: String,
    pub package_definition_digest: String,
    pub scope_digest: String,
    pub generation: u64,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub signature_verification: String,
    pub runner_verification: String,
    pub lifecycle_before: LifecycleState,
    pub lifecycle_after: LifecycleState,
    pub migration: MigrationRecord,
    pub rollback: RollbackRecord,
    pub failure: ReceiptFailure,
    pub receipt_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationRecord {
    pub kind: String,
    pub reversible: bool,
    pub migration_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RollbackRecord {
    pub required: bool,
    pub attempted: bool,
    pub succeeded: bool,
    pub remaining_registration_count: usize,
    pub rollback_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptFailure {
    pub code: String,
    pub observation_digest: String,
    pub exit_condition_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageObservation {
    pub signature_key_available: bool,
    pub runner_available: bool,
    pub native_calls: usize,
    pub status: String,
    pub release_decision: String,
}
