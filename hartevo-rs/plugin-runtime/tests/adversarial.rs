use hartevo_plugin_runtime::{
    CompatibilityPolicy, Digest, EventKind, PluginContributions, PluginDefinition, PluginErrorCode,
    PluginLifecycle, PluginRuntime, PluginScope, PluginVersion, ProjectId, ProviderCardinality,
    ProviderDefinition, ServiceDefinition, ServiceId, sample::SampleReadOnlyPlugin,
};
use proptest::prelude::*;

fn scope(project: &str, mission: &str, generation: u64) -> PluginScope {
    PluginScope::new(
        ProjectId::new(project).expect("project"),
        hartevo_plugin_runtime::MissionId::new(mission).expect("mission"),
        generation,
    )
    .expect("scope")
}

fn sample_definition(scope: PluginScope, version: PluginVersion) -> PluginDefinition {
    SampleReadOnlyPlugin::definition(scope, version).expect("sample definition")
}

fn provider_only_definition(
    plugin_id: &str,
    scope: PluginScope,
    service_id: &str,
    provider_id: &str,
    provider_version: PluginVersion,
) -> PluginDefinition {
    PluginDefinition::new(
        hartevo_plugin_runtime::PluginId::new(plugin_id).expect("plugin id"),
        PluginVersion::new(1, 0, 0),
        scope,
        PluginContributions {
            providers: vec![
                ProviderDefinition::new(
                    hartevo_plugin_runtime::ProviderId::new(provider_id).expect("provider id"),
                    ServiceId::new(service_id).expect("service id"),
                    provider_version,
                    Digest::from_text("provider-implementation"),
                )
                .expect("provider"),
            ],
            ..PluginContributions::default()
        },
    )
    .expect("provider-only definition")
}

fn many_service_definition(
    plugin_id: &str,
    scope: PluginScope,
    service_id: &str,
    provider_id: &str,
) -> PluginDefinition {
    let service_id = ServiceId::new(service_id).expect("service id");
    let service = ServiceDefinition::read_only(
        service_id.clone(),
        PluginVersion::new(1, 0, 0),
        Digest::from_text("many-service-contract"),
        ProviderCardinality::Many,
        CompatibilityPolicy::SameMajor,
    )
    .expect("service");
    let provider = ProviderDefinition::new(
        hartevo_plugin_runtime::ProviderId::new(provider_id).expect("provider id"),
        service_id,
        PluginVersion::new(1, 0, 0),
        Digest::from_text("many-provider-implementation"),
    )
    .expect("provider");
    PluginDefinition::new(
        hartevo_plugin_runtime::PluginId::new(plugin_id).expect("plugin id"),
        PluginVersion::new(1, 0, 0),
        scope,
        PluginContributions {
            services: vec![service],
            providers: vec![provider],
            ..PluginContributions::default()
        },
    )
    .expect("many service definition")
}

#[test]
fn sample_plugin_mounts_all_typed_contributions_and_unmounts_in_reverse() {
    let sample_scope = scope("project.alpha", "mission.alpha", 1);
    let other_mission = scope("project.alpha", "mission.other", 1);
    let definition = sample_definition(sample_scope.clone(), PluginVersion::new(1, 0, 0));
    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition.clone()).expect("define");
    assert_eq!(
        runtime.lifecycle(&handle).expect("lifecycle").lifecycle,
        PluginLifecycle::Defined
    );
    assert!(runtime.inspect(&other_mission).is_empty());

    let receipt = runtime.mount(&handle).expect("mount");
    assert_eq!(receipt.contribution_count(), 6);
    let mounted = runtime.inspect(&sample_scope);
    assert_eq!(mounted.plugins.len(), 1);
    assert_eq!(mounted.services.len(), 1);
    assert_eq!(mounted.providers.len(), 1);
    assert_eq!(mounted.consumers.len(), 1);
    assert_eq!(mounted.events.len(), 1);
    assert_eq!(mounted.events[0].kind, EventKind::Conversation);
    assert_eq!(mounted.ui_surfaces.len(), 2);
    assert!(runtime.inspect(&other_mission).is_empty());
    assert_eq!(mounted.scope_digest, sample_scope.digest());
    assert_eq!(mounted.generation, 1);

    let debug = format!("{definition:?} {handle:?} {receipt:?} {mounted:?} {runtime:?}");
    let encoded = serde_json::to_string(&mounted).expect("inspection JSON");
    assert!(!debug.contains("private-plugin-payload"));
    assert!(!encoded.contains("private-plugin-payload"));
    assert!(!encoded.contains("sample.read.tool.descriptor.v1"));

    let stale_receipt = receipt.clone();
    let unmounted = runtime.unmount(&receipt).expect("unmount");
    assert_eq!(unmounted.contribution_count, 6);
    assert!(runtime.inspect(&sample_scope).is_empty());
    assert_eq!(
        runtime.lifecycle(&handle).expect("lifecycle").lifecycle,
        PluginLifecycle::Stopped
    );
    assert_eq!(
        runtime
            .unmount(&stale_receipt)
            .expect_err("stale receipt")
            .code(),
        PluginErrorCode::StaleReceipt
    );
}

#[test]
fn compatible_version_remounts_after_atomic_unmount() {
    let sample_scope = scope("project.versioned", "mission.versioned", 1);
    let mut runtime = PluginRuntime::new();
    let first = runtime
        .define(sample_definition(
            sample_scope.clone(),
            PluginVersion::new(1, 0, 0),
        ))
        .expect("define first");
    let receipt = runtime.mount(&first).expect("mount first");
    runtime.unmount(&receipt).expect("unmount first");

    let second = runtime
        .define(sample_definition(
            sample_scope.clone(),
            PluginVersion::new(2, 0, 0),
        ))
        .expect("define compatible replacement");
    let receipt = runtime.mount(&second).expect("mount replacement");
    assert_eq!(
        runtime.inspect(&sample_scope).plugins[0].version,
        PluginVersion::new(2, 0, 0)
    );
    assert_ne!(first.digest(), second.digest());
    runtime.unmount(&receipt).expect("unmount replacement");
}

#[test]
fn provider_cardinality_and_compatibility_fail_closed_without_leaks() {
    let plugin_scope = scope("project.providers", "mission.providers", 1);
    let mut runtime = PluginRuntime::new();
    let base = runtime
        .define(sample_definition(
            plugin_scope.clone(),
            PluginVersion::new(1, 0, 0),
        ))
        .expect("define base");
    let _base_receipt = runtime.mount(&base).expect("mount base");

    let duplicate = runtime
        .define(provider_only_definition(
            "provider.duplicate",
            plugin_scope.clone(),
            "sample.read",
            "provider.second",
            PluginVersion::new(1, 2, 0),
        ))
        .expect("define duplicate");
    assert_eq!(
        runtime
            .mount(&duplicate)
            .expect_err("singleton violation")
            .code(),
        PluginErrorCode::ProviderCardinalityExceeded
    );
    assert_eq!(runtime.inspect(&plugin_scope).providers.len(), 1);

    let incompatible = runtime
        .define(provider_only_definition(
            "provider.incompatible",
            plugin_scope.clone(),
            "sample.read",
            "provider.third",
            PluginVersion::new(2, 0, 0),
        ))
        .expect("define incompatible");
    assert_eq!(
        runtime
            .mount(&incompatible)
            .expect_err("incompatible provider")
            .code(),
        PluginErrorCode::ProviderIncompatible
    );
    assert_eq!(runtime.inspect(&plugin_scope).providers.len(), 1);

    let many_scope = scope("project.providers", "mission.many", 1);
    let many_first = runtime
        .define(many_service_definition(
            "provider.many.first",
            many_scope.clone(),
            "many.read",
            "many.provider.first",
        ))
        .expect("define many first");
    let first_receipt = runtime.mount(&many_first).expect("mount many first");
    let many_second = runtime
        .define(provider_only_definition(
            "provider.many.second",
            many_scope.clone(),
            "many.read",
            "many.provider.second",
            PluginVersion::new(1, 0, 0),
        ))
        .expect("define many second");
    runtime
        .mount(&many_second)
        .expect("many cardinality allows second");
    assert_eq!(runtime.inspect(&many_scope).providers.len(), 2);
    runtime
        .unmount(&first_receipt)
        .expect_err("dependent provider remains");
}

#[test]
fn digest_scope_generation_and_revocation_boundaries_are_fail_closed() {
    let original_scope = scope("project.boundary", "mission.boundary", 1);
    let mut definition_value = serde_json::to_value(sample_definition(
        original_scope.clone(),
        PluginVersion::new(1, 0, 0),
    ))
    .expect("definition JSON");
    definition_value["identity"]["digest"] = serde_json::json!(Digest::from_text("drift"));
    let drifted: PluginDefinition = serde_json::from_value(definition_value).expect("drifted");
    assert_eq!(
        PluginRuntime::new()
            .define(drifted)
            .expect_err("digest drift")
            .code(),
        PluginErrorCode::DigestMismatch
    );

    let mut runtime = PluginRuntime::new();
    let handle = runtime
        .define(sample_definition(
            original_scope.clone(),
            PluginVersion::new(1, 0, 0),
        ))
        .expect("define");
    let wrong_scope = scope("project.boundary", "mission.other", 1);
    assert_eq!(
        runtime
            .mount_in_scope(&handle, &wrong_scope)
            .expect_err("scope drift")
            .code(),
        PluginErrorCode::ScopeMismatch
    );
    let receipt = runtime.mount(&handle).expect("mount");
    let stale = receipt.clone();
    let revocation = runtime.revoke(&handle).expect("revoke");
    assert_eq!(revocation.revocation_revision, 2);
    assert!(runtime.inspect(&original_scope).is_empty());
    assert_eq!(
        runtime.lifecycle(&handle).expect("lifecycle").lifecycle,
        PluginLifecycle::Revoked
    );
    assert_eq!(
        runtime.mount(&handle).expect_err("revoked remount").code(),
        PluginErrorCode::PluginRevoked
    );
    assert_eq!(
        runtime.unmount(&stale).expect_err("revoked receipt").code(),
        PluginErrorCode::PluginRevoked
    );

    let stale_scope = scope("project.stale", "mission.stale", 1);
    let stale_handle = runtime
        .define(sample_definition(
            stale_scope.clone(),
            PluginVersion::new(1, 0, 0),
        ))
        .expect("define stale");
    runtime
        .advance_generation(
            stale_scope.project_id().clone(),
            stale_scope.mission_id().clone(),
            2,
        )
        .expect("advance generation");
    assert_eq!(
        runtime
            .mount(&stale_handle)
            .expect_err("stale generation")
            .code(),
        PluginErrorCode::StaleGeneration
    );
}

proptest! {
    #[test]
    fn scope_digest_is_stable_and_generation_bound(generation in 1_u64..10_000) {
        let left = scope("project.property", "mission.property", generation);
        let right = scope("project.property", "mission.property", generation);
        prop_assert_eq!(left.digest(), right.digest());

        let next = scope("project.property", "mission.property", generation + 1);
        prop_assert_ne!(left.digest(), next.digest());
    }
}
