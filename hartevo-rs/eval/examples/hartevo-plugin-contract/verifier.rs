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
use crate::package::{
    AssetBinding, BinaryBinding, EntrypointBinding, ExtensionPackageManifest, HostApiBinding,
    PackageLifecycle, PackageObservation, PackageReadinessPolicy, PackageReceipt,
    PackageReceiptFixture, ReceiptFailure, RequestedAuthorities, RequestedScope, RollbackRecord,
    RunnerPolicy, SignaturePolicy,
};

pub const MANIFEST_PATH: &str = "contracts/plugins/manifest.v1.json";
pub const REGISTRY_PATH: &str = "contracts/plugins/registry.v1.json";
pub const FIXTURE_PATH: &str = "contracts/plugins/fixture.v1.json";
pub const VALIDATION_SCHEMA_VERSION: &str = "hartevo-plugin-validation/v1";
pub const AUTHORITY: &str = "plugin_contract_validation_only";
pub const RELEASE_DECISION: &str = "NOT_EVALUATED";
pub const NOT_EVALUATED: &str = "NOT_EVALUATED";
pub const REAL_PROVIDER_REASON: &str = "REAL_PROVIDER_REGISTRATION_EMPTY";
pub const PACKAGE_PATH: &str = "contracts/plugins/package.v1.json";
pub const PACKAGE_FIXTURE_PATH: &str = "contracts/plugins/package-fixture.v1.json";
pub const PACKAGE_NOT_EVALUATED_REASON: &str = "REAL_SIGNATURE_KEY_OR_RUNNER_UNAVAILABLE";

// These are deliberately checked-in after the contract bytes are frozen. The
// evaluator therefore cannot silently validate a different manifest, registry,
// or fixture while retaining the same Rust type shape.
pub const MANIFEST_RAW_SHA256: &str =
    "f0e785c6bc0eed7c9e0d1670917fc4ce64702310d7f91d52b2e6c802bc766327";
pub const REGISTRY_RAW_SHA256: &str =
    "af606202bcbd6a06335959a1538ac8ba317520859259a78d06a91a3dc472c4bd";
pub const FIXTURE_RAW_SHA256: &str =
    "1e1d5f63278b66476c0486dcb49766f1e4c3271c619e4f9df8bcde5f4cd85053";
pub const PACKAGE_RAW_SHA256: &str =
    "6d66eef85c2c87abce9fa98fe5a414aebd6d9a1609f4a70e873172556c8c558e";
pub const PACKAGE_FIXTURE_RAW_SHA256: &str =
    "2bf98558546572663a452778d78f6b6ff52e208ea5b2a335d0bedcc7eba131ca";

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
const PACKAGE_DEFINITION_DOMAIN: &str = "hartevo-plugin-package-definition/v1";
const PACKAGE_BINARY_DOMAIN: &str = "hartevo-plugin-binary/v1";
const PACKAGE_ASSET_PATH_DOMAIN: &str = "hartevo-plugin-asset-path/v1";
const PACKAGE_ASSET_CONTENT_DOMAIN: &str = "hartevo-plugin-asset-content/v1";
const PACKAGE_ASSET_DOMAIN: &str = "hartevo-plugin-asset/v1";
const PACKAGE_BUNDLE_DOMAIN: &str = "hartevo-plugin-bundle/v1";
const PACKAGE_HOST_API_DOMAIN: &str = "hartevo-plugin-host-api/v1";
const PACKAGE_SCOPE_DOMAIN: &str = "hartevo-plugin-package-scope/v1";
const PACKAGE_AUTHORITY_DOMAIN: &str = "hartevo-plugin-authority/v1";
const PACKAGE_SYMBOL_DOMAIN: &str = "hartevo-plugin-entrypoint-symbol/v1";
const PACKAGE_ENTRYPOINT_DOMAIN: &str = "hartevo-plugin-entrypoint/v1";
const PACKAGE_LIFECYCLE_DOMAIN: &str = "hartevo-plugin-lifecycle/v1";
const PACKAGE_KEY_DOMAIN: &str = "hartevo-plugin-signing-key/v1";
const PACKAGE_SIGNATURE_DOMAIN: &str = "hartevo-plugin-signature-evidence/v1";
const PACKAGE_PAYLOAD_DOMAIN: &str = "hartevo-plugin-signed-payload/v1";
const PACKAGE_MIGRATION_DOMAIN: &str = "hartevo-plugin-migration/v1";
const PACKAGE_ROLLBACK_DOMAIN: &str = "hartevo-plugin-rollback/v1";
const PACKAGE_FAILURE_DOMAIN: &str = "hartevo-plugin-receipt-failure/v1";
const PACKAGE_RECEIPT_DOMAIN: &str = "hartevo-plugin-receipt/v1";

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

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageValidationReport {
    pub schema_version: &'static str,
    pub authority: &'static str,
    pub validator_status: &'static str,
    pub readiness_status: &'static str,
    pub reason_code: &'static str,
    pub package_id: String,
    pub package_version: String,
    pub operation_count: usize,
    pub receipt_count: usize,
    pub signature_key_available: bool,
    pub runner_available: bool,
    pub native_calls: usize,
    pub signatures_verified: bool,
    pub lifecycle_receipts_validated: bool,
    pub capability_evaluated: bool,
    pub release_decision: &'static str,
    pub package_digest: String,
    pub fixture_digest: String,
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

pub fn validate_package_contracts(
    base_manifest_bytes: &[u8],
    package_bytes: &[u8],
    package_fixture_bytes: &[u8],
) -> Result<PackageValidationReport> {
    validate_raw_digest(
        base_manifest_bytes,
        MANIFEST_RAW_SHA256,
        "base plugin manifest",
    )?;
    validate_raw_digest(package_bytes, PACKAGE_RAW_SHA256, "extension package")?;
    validate_raw_digest(
        package_fixture_bytes,
        PACKAGE_FIXTURE_RAW_SHA256,
        "extension package fixture",
    )?;
    let manifest = parse_strict_json::<PluginManifest>(base_manifest_bytes)
        .context("base plugin manifest is not strict typed JSON")?;
    let package = parse_strict_json::<ExtensionPackageManifest>(package_bytes)
        .context("extension package manifest is not strict typed JSON")?;
    let fixture = parse_strict_json::<PackageReceiptFixture>(package_fixture_bytes)
        .context("extension package fixture is not strict typed JSON")?;
    validate_manifest(&manifest)?;
    validate_package_manifest(&package, &manifest)?;
    validate_package_fixture(&fixture, &package)?;
    Ok(PackageValidationReport {
        schema_version: VALIDATION_SCHEMA_VERSION,
        authority: AUTHORITY,
        validator_status: "PACKAGE_CONTRACT_VALIDATED",
        readiness_status: NOT_EVALUATED,
        reason_code: PACKAGE_NOT_EVALUATED_REASON,
        package_id: package.package_id,
        package_version: package.package_version,
        operation_count: 5,
        receipt_count: fixture.receipts.len(),
        signature_key_available: fixture.observation.signature_key_available,
        runner_available: fixture.observation.runner_available,
        native_calls: fixture.observation.native_calls,
        signatures_verified: false,
        lifecycle_receipts_validated: true,
        capability_evaluated: false,
        release_decision: RELEASE_DECISION,
        package_digest: sha256_hex(package_bytes),
        fixture_digest: sha256_hex(package_fixture_bytes),
    })
}

fn validate_package_manifest(
    package: &ExtensionPackageManifest,
    manifest: &PluginManifest,
) -> Result<()> {
    ensure!(package.schema_version == "hartevo-plugin-package/v1");
    ensure!(package.contract_version == "plugin-contract-closure-01/package/v1");
    ensure!(package.package_id == manifest.plugin.plugin_id && package.package_id == PLUGIN_ID);
    ensure!(
        package.package_version == manifest.plugin.version
            && package.package_version == PLUGIN_VERSION
    );
    ensure!(package.manifest_revision == 1);
    ensure!(package.base_manifest_digest == MANIFEST_RAW_SHA256);
    ensure!(package.service_definition_digest == manifest.service_definitions[0].definition_digest);
    ensure!(package.provider_definition_digest == manifest.providers[0].definition_digest);
    ensure!(package.consumer_definition_digest == manifest.consumers[0].definition_digest);
    validate_package_binary(&package.binary, package)?;
    validate_host_api(&package.host_api)?;
    ensure!(package.requested_scopes.len() == 1);
    validate_package_scope(&package.requested_scopes[0])?;
    validate_requested_authorities(&package.requested_authorities)?;
    validate_entrypoint(&package.entrypoint, package, manifest)?;
    validate_package_lifecycle(&package.lifecycle)?;
    let expected_definition = package_definition_digest(package);
    ensure!(package.definition_digest == expected_definition);
    validate_signature_policy(&package.signature_policy, package)?;
    validate_runner_policy(&package.runner_policy)?;
    validate_package_readiness(&package.readiness_policy)?;
    Ok(())
}

fn validate_package_binary(
    binary: &BinaryBinding,
    package: &ExtensionPackageManifest,
) -> Result<()> {
    ensure!(binary.entrypoint == "hartevo_plugin_service_provider_v1");
    ensure!(binary.binary_format == "native");
    ensure!(binary.assets.len() == 1);
    let expected_binary = domain_digest(
        PACKAGE_BINARY_DOMAIN,
        &[
            package.package_id.as_str(),
            package.package_version.as_str(),
            "unavailable",
        ],
    );
    ensure!(binary.binary_digest == expected_binary);
    let asset = &binary.assets[0];
    validate_asset(asset)?;
    let expected_bundle = domain_digest(
        PACKAGE_BUNDLE_DOMAIN,
        &[
            binary.binary_format.as_str(),
            binary.binary_digest.as_str(),
            binary.entrypoint.as_str(),
            &asset.asset_digest,
        ],
    );
    ensure!(binary.bundle_digest == expected_bundle);
    Ok(())
}

fn validate_asset(asset: &AssetBinding) -> Result<()> {
    ensure!(asset.asset_id == "market-evidence-schema");
    ensure!(asset.byte_count == 4096);
    let expected_path = domain_digest(PACKAGE_ASSET_PATH_DOMAIN, &[asset.asset_id.as_str()]);
    let expected_content = domain_digest(
        PACKAGE_ASSET_CONTENT_DOMAIN,
        &[asset.asset_id.as_str(), "unavailable"],
    );
    ensure!(asset.path_digest == expected_path && asset.content_digest == expected_content);
    let expected_asset = domain_digest(
        PACKAGE_ASSET_DOMAIN,
        &[
            asset.asset_id.as_str(),
            asset.path_digest.as_str(),
            asset.content_digest.as_str(),
            &asset.byte_count.to_string(),
        ],
    );
    ensure!(asset.asset_digest == expected_asset);
    Ok(())
}

fn validate_host_api(api: &HostApiBinding) -> Result<()> {
    ensure!(api.api_id == "hartevo.plugin.host");
    ensure!(api.major == 1 && api.minor == 0);
    let expected = domain_digest(
        PACKAGE_HOST_API_DOMAIN,
        &[
            api.api_id.as_str(),
            &api.major.to_string(),
            &api.minor.to_string(),
        ],
    );
    ensure!(api.api_digest == expected);
    Ok(())
}

fn validate_package_scope(scope: &RequestedScope) -> Result<()> {
    ensure!(scope.scope_kind == ScopeKind::ProjectMission);
    ensure!(
        scope.scope_digest == "15b4d31832f6165508833f47e9e52a459bd93af17280d64705f2d0207aae744c"
    );
    ensure!(scope.capabilities == ["consumer.model_visible", "service.read_only"]);
    let expected = domain_digest(
        PACKAGE_SCOPE_DOMAIN,
        &[
            scope_kind_text(scope.scope_kind),
            scope.scope_digest.as_str(),
            &scope.capabilities.join(","),
        ],
    );
    ensure!(scope.scope_binding_digest == expected);
    Ok(())
}

fn validate_requested_authorities(authorities: &RequestedAuthorities) -> Result<()> {
    ensure!(authorities.store == "forbidden");
    ensure!(authorities.keyring == "forbidden");
    ensure!(authorities.browser_profile == "forbidden");
    ensure!(authorities.effect == "forbidden");
    ensure!(
        authorities.allowed
            == [
                "durable_log_append",
                "model_input_output",
                "provider_read_only"
            ]
    );
    ensure!(authorities.unknown_authority_policy == "deny");
    let expected = domain_digest(
        PACKAGE_AUTHORITY_DOMAIN,
        &[
            authorities.store.as_str(),
            authorities.keyring.as_str(),
            authorities.browser_profile.as_str(),
            authorities.effect.as_str(),
            &authorities.allowed.join(","),
            authorities.unknown_authority_policy.as_str(),
        ],
    );
    ensure!(authorities.authority_digest == expected);
    Ok(())
}

fn validate_entrypoint(
    entrypoint: &EntrypointBinding,
    package: &ExtensionPackageManifest,
    manifest: &PluginManifest,
) -> Result<()> {
    ensure!(entrypoint.kind == "service_provider");
    ensure!(entrypoint.symbol == package.binary.entrypoint);
    ensure!(entrypoint.invocation == "host_dispatch");
    ensure!(
        entrypoint.return_contract_digest == manifest.service_definitions[0].output_schema_digest
    );
    let expected_symbol = domain_digest(PACKAGE_SYMBOL_DOMAIN, &[entrypoint.symbol.as_str()]);
    ensure!(entrypoint.symbol_digest == expected_symbol);
    let expected_entrypoint = domain_digest(
        PACKAGE_ENTRYPOINT_DOMAIN,
        &[
            entrypoint.kind.as_str(),
            entrypoint.symbol_digest.as_str(),
            entrypoint.invocation.as_str(),
            entrypoint.return_contract_digest.as_str(),
        ],
    );
    ensure!(entrypoint.entrypoint_digest == expected_entrypoint);
    Ok(())
}

fn validate_package_lifecycle(lifecycle: &PackageLifecycle) -> Result<()> {
    ensure!(lifecycle.mount == "atomic_registration_receipt");
    ensure!(lifecycle.unmount == "reverse_order_atomic");
    ensure!(lifecycle.upgrade == "install_then_cutover");
    ensure!(lifecycle.downgrade == "install_then_cutover");
    ensure!(lifecycle.revoke == "stop_revoke_unmount");
    ensure!(lifecycle.crash_recovery == "rollback_to_previous_or_stopped");
    ensure!(lifecycle.migration_policy == "none");
    ensure!(lifecycle.migration_reversible);
    ensure!(lifecycle.rollback_required && lifecycle.receipt_required);
    ensure!(lifecycle.unknown_transition == "deny");
    let expected = domain_digest(
        PACKAGE_LIFECYCLE_DOMAIN,
        &[
            lifecycle.mount.as_str(),
            lifecycle.unmount.as_str(),
            lifecycle.upgrade.as_str(),
            lifecycle.downgrade.as_str(),
            lifecycle.revoke.as_str(),
            lifecycle.crash_recovery.as_str(),
            lifecycle.migration_policy.as_str(),
            bool_text(lifecycle.migration_reversible),
            bool_text(lifecycle.rollback_required),
            bool_text(lifecycle.receipt_required),
            lifecycle.unknown_transition.as_str(),
        ],
    );
    ensure!(lifecycle.lifecycle_digest == expected);
    Ok(())
}

fn validate_signature_policy(
    signature: &SignaturePolicy,
    package: &ExtensionPackageManifest,
) -> Result<()> {
    ensure!(signature.algorithm == "ed25519" && signature.required);
    ensure!(signature.key_registry_epoch == 0);
    ensure!(signature.signature_status == NOT_EVALUATED);
    ensure!(signature.signature_hex.is_none());
    let expected_key = domain_digest(
        PACKAGE_KEY_DOMAIN,
        &[package.package_id.as_str(), "unprovisioned"],
    );
    ensure!(signature.key_id_digest == expected_key);
    let expected_payload = package_signed_payload_digest(package);
    ensure!(signature.signed_payload_digest == expected_payload);
    let expected_signature = domain_digest(
        PACKAGE_SIGNATURE_DOMAIN,
        &[
            signature.key_id_digest.as_str(),
            signature.signed_payload_digest.as_str(),
            signature.signature_status.as_str(),
        ],
    );
    ensure!(signature.signature_digest == expected_signature);
    Ok(())
}

fn validate_runner_policy(runner: &RunnerPolicy) -> Result<()> {
    ensure!(runner.required);
    ensure!(runner.registry_status == "EMPTY");
    ensure!(runner.runner_id_digest.is_none() && runner.runner_binary_digest.is_none());
    ensure!(runner.runner_signature_status == NOT_EVALUATED);
    Ok(())
}

fn validate_package_readiness(policy: &PackageReadinessPolicy) -> Result<()> {
    ensure!(policy.real_signature_key_required && policy.real_runner_required);
    ensure!(policy.empty_registry_status == NOT_EVALUATED);
    ensure!(policy.fixture_does_not_count);
    ensure!(policy.release_decision == RELEASE_DECISION);
    Ok(())
}

fn package_definition_digest(package: &ExtensionPackageManifest) -> String {
    domain_digest(
        PACKAGE_DEFINITION_DOMAIN,
        &[
            package.package_id.as_str(),
            package.package_version.as_str(),
            &package.manifest_revision.to_string(),
            package.base_manifest_digest.as_str(),
            package.service_definition_digest.as_str(),
            package.provider_definition_digest.as_str(),
            package.consumer_definition_digest.as_str(),
            package.binary.bundle_digest.as_str(),
            package.host_api.api_digest.as_str(),
            package.requested_scopes[0].scope_binding_digest.as_str(),
            package.requested_authorities.authority_digest.as_str(),
            package.entrypoint.entrypoint_digest.as_str(),
            package.lifecycle.lifecycle_digest.as_str(),
        ],
    )
}

fn package_signed_payload_digest(package: &ExtensionPackageManifest) -> String {
    domain_digest(
        PACKAGE_PAYLOAD_DOMAIN,
        &[
            package.definition_digest.as_str(),
            package.host_api.api_digest.as_str(),
            package.requested_scopes[0].scope_binding_digest.as_str(),
            package.requested_authorities.authority_digest.as_str(),
            package.entrypoint.entrypoint_digest.as_str(),
            package.lifecycle.lifecycle_digest.as_str(),
        ],
    )
}

fn validate_package_fixture(
    fixture: &PackageReceiptFixture,
    package: &ExtensionPackageManifest,
) -> Result<()> {
    ensure!(fixture.schema_version == "hartevo-plugin-package-fixture/v1");
    ensure!(fixture.fixture_id == "readonly-market-package-lifecycle/v1");
    ensure!(fixture.package_id == package.package_id);
    ensure!(fixture.package_version == package.package_version);
    ensure!(fixture.package_definition_digest == package.definition_digest);
    validate_package_scope(&fixture.scope)?;
    ensure!(fixture.scope == package.requested_scopes[0]);
    ensure!(fixture.receipts.len() == 5);
    let expected_operations = [
        "install",
        "upgrade",
        "downgrade",
        "revoke",
        "crash_recovery",
    ];
    let mut receipt_ids = BTreeSet::new();
    for (index, receipt) in fixture.receipts.iter().enumerate() {
        ensure!(receipt_ids.insert(receipt.receipt_id.clone()));
        validate_package_receipt(
            receipt,
            package,
            index as u64 + 1,
            expected_operations[index],
        )?;
    }
    validate_package_observation(&fixture.observation)
}

fn validate_package_receipt(
    receipt: &PackageReceipt,
    package: &ExtensionPackageManifest,
    expected_sequence: u64,
    expected_operation: &str,
) -> Result<()> {
    ensure!(receipt.sequence == expected_sequence);
    ensure!(receipt.operation == expected_operation);
    ensure!(receipt.status == NOT_EVALUATED);
    ensure!(receipt.package_definition_digest == package.definition_digest);
    ensure!(receipt.scope_digest == package.requested_scopes[0].scope_digest);
    ensure!(receipt.generation == expected_sequence);
    ensure!(receipt.signature_verification == NOT_EVALUATED);
    ensure!(receipt.runner_verification == NOT_EVALUATED);
    let (from, to, before, after, failure_code) = match expected_operation {
        "install" => (
            None,
            Some("1.0.0"),
            LifecycleState::Defined,
            LifecycleState::Stopped,
            "REAL_SIGNATURE_KEY_UNAVAILABLE",
        ),
        "upgrade" => (
            Some("1.0.0"),
            Some("1.1.0"),
            LifecycleState::Mounted,
            LifecycleState::Stopped,
            "REAL_SIGNATURE_KEY_UNAVAILABLE",
        ),
        "downgrade" => (
            Some("1.1.0"),
            Some("1.0.0"),
            LifecycleState::Mounted,
            LifecycleState::Stopped,
            "REAL_SIGNATURE_KEY_UNAVAILABLE",
        ),
        "revoke" => (
            Some("1.0.0"),
            None,
            LifecycleState::Mounted,
            LifecycleState::Revoked,
            "REAL_SIGNATURE_KEY_UNAVAILABLE",
        ),
        "crash_recovery" => (
            Some("1.0.0"),
            Some("1.0.0"),
            LifecycleState::Mounted,
            LifecycleState::Stopped,
            "REAL_RUNNER_UNAVAILABLE",
        ),
        _ => return Err(anyhow::anyhow!("unknown package operation")),
    };
    ensure!(receipt.from_version.as_deref() == from);
    ensure!(receipt.to_version.as_deref() == to);
    ensure!(receipt.lifecycle_before == before && receipt.lifecycle_after == after);
    validate_migration(&receipt.migration, package, expected_operation)?;
    validate_rollback(&receipt.rollback, receipt, package)?;
    validate_receipt_failure(&receipt.failure, expected_operation, failure_code)?;
    let expected_digest = package_receipt_digest(receipt);
    ensure!(receipt.receipt_digest == expected_digest);
    Ok(())
}

fn validate_migration(
    migration: &crate::package::MigrationRecord,
    package: &ExtensionPackageManifest,
    operation: &str,
) -> Result<()> {
    ensure!(migration.kind == "none" && migration.reversible);
    let expected = domain_digest(
        PACKAGE_MIGRATION_DOMAIN,
        &[package.package_id.as_str(), operation, "none"],
    );
    ensure!(migration.migration_digest == expected);
    Ok(())
}

fn validate_rollback(
    rollback: &RollbackRecord,
    receipt: &PackageReceipt,
    package: &ExtensionPackageManifest,
) -> Result<()> {
    ensure!(rollback.required && rollback.attempted && rollback.succeeded);
    ensure!(rollback.remaining_registration_count == 0);
    let expected = domain_digest(
        PACKAGE_ROLLBACK_DOMAIN,
        &[
            receipt.receipt_id.as_str(),
            &receipt.sequence.to_string(),
            package.definition_digest.as_str(),
            receipt.scope_digest.as_str(),
            "remaining:0",
            "succeeded:true",
        ],
    );
    ensure!(rollback.rollback_digest == expected);
    Ok(())
}

fn validate_receipt_failure(
    failure: &ReceiptFailure,
    operation: &str,
    expected_code: &str,
) -> Result<()> {
    ensure!(failure.code == expected_code);
    let expected_observation = domain_digest(
        PACKAGE_FAILURE_DOMAIN,
        &[operation, expected_code, "observation"],
    );
    let expected_exit = domain_digest(PACKAGE_FAILURE_DOMAIN, &[operation, expected_code, "exit"]);
    ensure!(failure.observation_digest == expected_observation);
    ensure!(failure.exit_condition_digest == expected_exit);
    Ok(())
}

fn package_receipt_digest(receipt: &PackageReceipt) -> String {
    domain_digest(
        PACKAGE_RECEIPT_DOMAIN,
        &[
            receipt.receipt_id.as_str(),
            &receipt.sequence.to_string(),
            receipt.operation.as_str(),
            receipt.status.as_str(),
            receipt.package_definition_digest.as_str(),
            receipt.scope_digest.as_str(),
            &receipt.generation.to_string(),
            receipt.from_version.as_deref().unwrap_or("none"),
            receipt.to_version.as_deref().unwrap_or("none"),
            receipt.signature_verification.as_str(),
            receipt.runner_verification.as_str(),
            lifecycle_state_text(receipt.lifecycle_before),
            lifecycle_state_text(receipt.lifecycle_after),
            receipt.migration.migration_digest.as_str(),
            receipt.rollback.rollback_digest.as_str(),
            receipt.failure.code.as_str(),
            receipt.failure.observation_digest.as_str(),
            receipt.failure.exit_condition_digest.as_str(),
        ],
    )
}

fn validate_package_observation(observation: &PackageObservation) -> Result<()> {
    ensure!(!observation.signature_key_available && !observation.runner_available);
    ensure!(observation.native_calls == 0);
    ensure!(observation.status == NOT_EVALUATED);
    ensure!(observation.release_decision == RELEASE_DECISION);
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

fn lifecycle_state_text(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::Defined => "defined",
        LifecycleState::Mounted => "mounted",
        LifecycleState::Stopping => "stopping",
        LifecycleState::Stopped => "stopped",
        LifecycleState::Revoked => "revoked",
        LifecycleState::Failed => "failed",
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
    use super::{
        FIXTURE_RAW_SHA256, MANIFEST_RAW_SHA256, PACKAGE_FIXTURE_RAW_SHA256, PACKAGE_RAW_SHA256,
        REGISTRY_RAW_SHA256, validate_contracts, validate_package_contracts,
        validate_package_fixture, validate_package_manifest,
    };
    use crate::model::{PluginFixture, PluginManifest, PluginRegistry, parse_strict_json};
    use crate::package::{ExtensionPackageManifest, PackageReceiptFixture};

    const MANIFEST: &[u8] = include_bytes!("../../../../contracts/plugins/manifest.v1.json");
    const REGISTRY: &[u8] = include_bytes!("../../../../contracts/plugins/registry.v1.json");
    const FIXTURE: &[u8] = include_bytes!("../../../../contracts/plugins/fixture.v1.json");
    const PACKAGE: &[u8] = include_bytes!("../../../../contracts/plugins/package.v1.json");
    const PACKAGE_FIXTURE: &[u8] =
        include_bytes!("../../../../contracts/plugins/package-fixture.v1.json");

    fn validated() -> super::ValidationReport {
        validate_contracts(MANIFEST, REGISTRY, FIXTURE).expect("plugin contract validates")
    }

    fn package_validated() -> super::PackageValidationReport {
        validate_package_contracts(MANIFEST, PACKAGE, PACKAGE_FIXTURE)
            .expect("extension package contract validates")
    }

    #[test]
    fn package_contract_is_typed_but_not_native_capability() {
        let report = package_validated();
        assert_eq!(report.validator_status, "PACKAGE_CONTRACT_VALIDATED");
        assert_eq!(report.readiness_status, super::NOT_EVALUATED);
        assert_eq!(report.reason_code, super::PACKAGE_NOT_EVALUATED_REASON);
        assert_eq!(report.package_id, "hartevo.readonly.market-evidence");
        assert_eq!(report.package_version, "1.0.0");
        assert_eq!(report.operation_count, 5);
        assert_eq!(report.receipt_count, 5);
        assert!(!report.signature_key_available);
        assert!(!report.runner_available);
        assert_eq!(report.native_calls, 0);
        assert!(!report.signatures_verified);
        assert!(report.lifecycle_receipts_validated);
        assert!(!report.capability_evaluated);
        assert_eq!(report.release_decision, super::RELEASE_DECISION);
        assert_eq!(report.package_digest, PACKAGE_RAW_SHA256);
        assert_eq!(report.fixture_digest, PACKAGE_FIXTURE_RAW_SHA256);
    }

    #[test]
    fn package_raw_byte_drift_is_rejected_before_typed_validation() {
        let mut package = PACKAGE.to_vec();
        package.push(b'\n');
        assert!(validate_package_contracts(MANIFEST, &package, PACKAGE_FIXTURE).is_err());
    }

    #[test]
    fn unknown_requested_authority_fails_closed() {
        let manifest = parse_strict_json::<PluginManifest>(MANIFEST).expect("manifest");
        let mut package = parse_strict_json::<ExtensionPackageManifest>(PACKAGE).expect("package");
        package.requested_authorities.allowed = vec!["host.secret_store".to_owned()];
        assert!(validate_package_manifest(&package, &manifest).is_err());
    }

    #[test]
    fn irreversible_migration_fails_closed() {
        let manifest = parse_strict_json::<PluginManifest>(MANIFEST).expect("manifest");
        let mut package = parse_strict_json::<ExtensionPackageManifest>(PACKAGE).expect("package");
        package.lifecycle.migration_policy = "custom".to_owned();
        package.lifecycle.migration_reversible = false;
        assert!(validate_package_manifest(&package, &manifest).is_err());
    }

    #[test]
    fn fixture_status_cannot_be_promoted_to_pass() {
        let package = parse_strict_json::<ExtensionPackageManifest>(PACKAGE).expect("package");
        let mut fixture =
            parse_strict_json::<PackageReceiptFixture>(PACKAGE_FIXTURE).expect("fixture");
        fixture.receipts[0].status = "PASS".to_owned();
        assert!(validate_package_fixture(&fixture, &package).is_err());
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
