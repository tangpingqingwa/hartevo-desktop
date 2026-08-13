use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    sync::{Arc, Mutex},
};

use hartevo_plugin_runtime::skill::{
    MemorySkillPackAuditLog, SkillEffectClass, SkillItemId, SkillPackAuditEntry,
    SkillPackAuditEventKind, SkillPackAuditLog, SkillPackCapabilityResolution,
    SkillPackCapabilityResolver, SkillPackContextReceipt, SkillPackError, SkillPackFile,
    SkillPackHostAdapter, SkillPackHostError, SkillPackLoadRequest, SkillPackManifest,
    SkillPackMigrationReceipt, SkillPackMissionContext, SkillPackPath, SkillPackPolicy,
    SkillPackPolicySpec, SkillPackProvider, SkillPackService, SkillPackSource, SkillPackStatus,
    SkillPackUpgradePlan, SkillPackVerificationAttestation, SkillPackVerificationReceipt,
    SkillPackVerificationStatus, SkillPackVerifiedPackage, SkillServiceRequirement,
    SkillToolRequirement,
};
use hartevo_plugin_runtime::{
    ConsumerId, Digest, MissionId, PluginId, PluginRuntime, PluginScope, PluginVersion, ProjectId,
    ServiceAccess, ServiceId,
};
use proptest::prelude::*;

const HOST_API: PluginVersion = PluginVersion::new(1, 0, 0);

struct Fixture {
    manifest: SkillPackManifest,
    source: SkillPackSource,
    files: Vec<SkillPackFile>,
    package: SkillPackVerifiedPackage,
    policy: SkillPackPolicy,
    request: SkillPackLoadRequest,
    context: SkillPackMissionContext,
    service: SkillServiceRequirement,
    tool: SkillToolRequirement,
    public_text: String,
    secret_text: String,
}

fn scope(generation: u64) -> PluginScope {
    PluginScope::new(
        ProjectId::new("project.skill-pack").expect("project"),
        MissionId::new("mission.skill-pack").expect("mission"),
        generation,
    )
    .expect("scope")
}

fn verification_receipt(
    manifest: &SkillPackManifest,
    source: &SkillPackSource,
    content_digest: &Digest,
    status: SkillPackVerificationStatus,
) -> SkillPackVerificationReceipt {
    SkillPackVerificationReceipt::from_attestation(SkillPackVerificationAttestation {
        status,
        verifier_digest: Digest::from_text("fixture.verifier"),
        signature_digest: Digest::from_text("fixture.signature"),
        source_digest: source.source_digest().clone(),
        manifest_digest: manifest.digest().clone(),
        content_digest: content_digest.clone(),
        host_api: HOST_API,
        verified_at: 1,
    })
    .expect("verification receipt")
}

fn package_from_files(
    manifest: SkillPackManifest,
    source: SkillPackSource,
    files: &[SkillPackFile],
    status: SkillPackVerificationStatus,
) -> Result<SkillPackVerifiedPackage, SkillPackError> {
    let content_digest = SkillPackVerifiedPackage::content_digest_for_files(files);
    let receipt = verification_receipt(&manifest, &source, &content_digest, status);
    SkillPackVerifiedPackage::new(manifest, source, files, receipt)
}

#[allow(clippy::too_many_lines)]
fn fixture(version: PluginVersion, generation: u64) -> Fixture {
    let package_id =
        hartevo_plugin_runtime::skill::SkillPackId::new("pack.alpha").expect("package id");
    let plugin_id = PluginId::new("plugin.skill.alpha").expect("plugin id");
    let skill_id = hartevo_plugin_runtime::skill::SkillId::new("skill.alpha").expect("skill id");
    let instruction_id = SkillItemId::new("instruction.main").expect("instruction id");
    let denied_instruction_id = SkillItemId::new("instruction.secret").expect("denied id");
    let recipe_id = SkillItemId::new("recipe.safe").expect("recipe id");

    let service = SkillServiceRequirement::new(
        ServiceId::new("data.read").expect("service id"),
        PluginVersion::new(1, 0, 0),
        Digest::from_text("data.read.contract"),
    )
    .expect("service requirement");
    let tool = SkillToolRequirement::new(
        ServiceId::new("data.read").expect("tool service id"),
        ConsumerId::new("data.lookup").expect("tool id"),
        PluginVersion::new(1, 0, 0),
        Digest::from_text("data.lookup.descriptor"),
        SkillEffectClass::EffectProposal,
    )
    .expect("tool requirement");

    let instruction_path = SkillPackPath::new("instructions/main.md").expect("instruction path");
    let denied_instruction_path =
        SkillPackPath::new("instructions/secret.md").expect("denied path");
    let recipe_path = SkillPackPath::new("recipes/safe.md").expect("recipe path");
    let public_text = format!("Use the typed gateway for skill version {version:?}.");
    let secret_text = "do-not-surface-secret-in-model-context".to_owned();
    let recipe_text = "Read the approved report through the declared capability.".to_owned();
    let public_bytes = public_text.as_bytes().to_vec();
    let secret_bytes = secret_text.as_bytes().to_vec();
    let recipe_bytes = recipe_text.as_bytes().to_vec();
    let files = vec![
        SkillPackFile::regular(instruction_path.clone(), public_bytes.clone())
            .expect("public file"),
        SkillPackFile::regular(denied_instruction_path.clone(), secret_bytes.clone())
            .expect("secret file"),
        SkillPackFile::regular(recipe_path.clone(), recipe_bytes.clone()).expect("recipe file"),
    ];
    let manifest = SkillPackManifest::new(
        package_id.clone(),
        plugin_id,
        skill_id.clone(),
        version,
        HOST_API,
        BTreeMap::from([
            (instruction_path.clone(), Digest::from_bytes(&public_bytes)),
            (
                denied_instruction_path.clone(),
                Digest::from_bytes(&secret_bytes),
            ),
            (recipe_path.clone(), Digest::from_bytes(&recipe_bytes)),
        ]),
        BTreeMap::from([
            (instruction_id.clone(), instruction_path),
            (denied_instruction_id, denied_instruction_path),
        ]),
        BTreeMap::from([(recipe_id.clone(), recipe_path)]),
        vec![service.clone()],
        vec![tool.clone()],
    )
    .expect("manifest");
    let source = SkillPackSource::new(
        Digest::from_text("fixture.skill.locator"),
        Digest::from_text("fixture.skill.source"),
    )
    .expect("source");
    let package = package_from_files(
        manifest.clone(),
        source.clone(),
        &files,
        SkillPackVerificationStatus::Verified,
    )
    .expect("verified package");
    let policy = SkillPackPolicy::new(SkillPackPolicySpec {
        allowed_package_ids: BTreeSet::from([package_id]),
        allowed_skill_ids: BTreeSet::from([skill_id]),
        allowed_source_digests: BTreeSet::from([source.source_digest().clone()]),
        allowed_instruction_ids: BTreeSet::from([instruction_id]),
        allowed_recipe_ids: BTreeSet::from([recipe_id]),
        allowed_capability_digests: BTreeSet::from([service.digest(), tool.digest()]),
        host_api: HOST_API,
    })
    .expect("policy");
    let request = SkillPackLoadRequest::new(
        scope(generation),
        policy.digest().clone(),
        source.clone(),
        Some(package.package_digest().clone()),
        Some(package.manifest().digest().clone()),
        Some(package.content_digest().clone()),
    )
    .expect("load request");
    let context = SkillPackMissionContext::new(scope(generation), policy.digest().clone())
        .expect("mission context");
    Fixture {
        manifest,
        source,
        files,
        package,
        policy,
        request,
        context,
        service,
        tool,
        public_text,
        secret_text,
    }
}

#[derive(Debug)]
struct FixtureHost {
    package: SkillPackVerifiedPackage,
    verify_error: Option<SkillPackHostError>,
    upgrade_plan: Option<SkillPackUpgradePlan>,
    releases: Arc<Mutex<Vec<Digest>>>,
}

impl FixtureHost {
    fn for_package(package: SkillPackVerifiedPackage) -> (Self, Arc<Mutex<Vec<Digest>>>) {
        let releases = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                package,
                verify_error: None,
                upgrade_plan: None,
                releases: releases.clone(),
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
        if let Some(error) = self.verify_error {
            return Err(error);
        }
        Ok(self.package.clone())
    }

    fn prepare_upgrade(
        &mut self,
        _current: &SkillPackVerifiedPackage,
        _request: &SkillPackLoadRequest,
    ) -> Result<SkillPackUpgradePlan, SkillPackHostError> {
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

struct ExactResolver;

impl SkillPackCapabilityResolver for ExactResolver {
    fn resolve(
        &mut self,
        scope: &PluginScope,
        policy: &SkillPackPolicy,
        required_services: &[SkillServiceRequirement],
        required_tools: &[SkillToolRequirement],
    ) -> Result<SkillPackCapabilityResolution, SkillPackError> {
        SkillPackCapabilityResolution::from_requirements(
            scope,
            policy,
            required_services.to_vec(),
            required_tools.to_vec(),
        )
    }
}

struct EmptyResolver;

impl SkillPackCapabilityResolver for EmptyResolver {
    fn resolve(
        &mut self,
        scope: &PluginScope,
        policy: &SkillPackPolicy,
        _required_services: &[SkillServiceRequirement],
        _required_tools: &[SkillToolRequirement],
    ) -> Result<SkillPackCapabilityResolution, SkillPackError> {
        SkillPackCapabilityResolution::from_requirements(scope, policy, Vec::new(), Vec::new())
    }
}

struct RejectingAuditLog;

impl SkillPackAuditLog for RejectingAuditLog {
    fn append(
        &mut self,
        _entry: SkillPackAuditEntry,
    ) -> Result<(), hartevo_plugin_runtime::skill::SkillPackAuditLogError> {
        Err(hartevo_plugin_runtime::skill::SkillPackAuditLogError::Unavailable)
    }
}

#[test]
fn verified_skill_pack_mounts_and_composes_policy_filtered_context() {
    let fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    let (host, releases) = FixtureHost::for_package(fixture.package.clone());
    let mut runtime = PluginRuntime::new();
    let mut provider = SkillPackProvider::load_and_mount(
        host,
        &fixture.request,
        fixture.policy.clone(),
        &mut runtime,
    )
    .expect("mount");
    let service = SkillPackService::definition().expect("service definition");
    assert_eq!(service.id().as_str(), SkillPackService::ID);
    assert_eq!(service.access(), ServiceAccess::ReadOnly);
    assert_eq!(fixture.service.service_id().as_str(), "data.read");
    assert_eq!(provider.status(), SkillPackStatus::Mounted);
    assert_eq!(provider.metadata().version(), PluginVersion::new(1, 0, 0));
    assert_eq!(
        provider.metadata().source_digest(),
        fixture.source.source_digest()
    );

    let mut resolver = ExactResolver;
    let mut log = MemorySkillPackAuditLog::default();
    let model = provider
        .compose(&fixture.context, &mut resolver, &mut runtime, &mut log, 7)
        .expect("compose");
    assert_eq!(model.instructions().len(), 1);
    assert_eq!(model.recipes().len(), 1);
    assert_eq!(
        model.instructions()[0].content().as_str(),
        fixture.public_text
    );
    assert_eq!(
        fixture.tool.effect_class(),
        SkillEffectClass::EffectProposal
    );
    assert!(log.entries().iter().any(|entry| {
        entry.kind == SkillPackAuditEventKind::InstructionVisible
            && entry.model_visible
            && entry.version == PluginVersion::new(1, 0, 0)
            && entry.source_digest == *fixture.source.source_digest()
    }));
    assert!(
        log.entries()
            .iter()
            .all(|entry| entry.item_content_digest.is_some() || !entry.model_visible)
    );

    let debug = format!("{model:?} {:?} {:?}", fixture.package, model.receipt());
    assert!(!debug.contains(&fixture.public_text));
    assert!(!debug.contains(&fixture.secret_text));
    let receipt_json = serde_json::to_string(model.receipt()).expect("receipt json");
    assert!(!receipt_json.contains(&fixture.public_text));
    assert!(!receipt_json.contains(&fixture.secret_text));
    let audit_json = serde_json::to_string(log.entries()).expect("audit json");
    assert!(!audit_json.contains(&fixture.public_text));
    assert!(!audit_json.contains(&fixture.secret_text));
    provider
        .validate_context(&fixture.context, &model, &runtime)
        .expect("live context");
    assert!(!runtime.inspect(fixture.context.scope()).is_empty());
    assert!(releases.lock().expect("release ledger").is_empty());
}

#[test]
fn verification_and_package_integrity_fail_closed_before_mount() {
    let fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    for host_error in [
        SkillPackHostError::SignatureUnavailable,
        SkillPackHostError::Disconnected,
    ] {
        let (mut host, _releases) = FixtureHost::for_package(fixture.package.clone());
        host.verify_error = Some(host_error);
        let mut runtime = PluginRuntime::new();
        let error = SkillPackProvider::load_and_mount(
            host,
            &fixture.request,
            fixture.policy.clone(),
            &mut runtime,
        )
        .expect_err("unverified host must not mount");
        assert_eq!(error, SkillPackError::from(host_error));
        assert!(runtime.inspect(fixture.context.scope()).is_empty());
    }

    assert_eq!(
        SkillPackPath::new("../escape").expect_err("parent path"),
        SkillPackError::InvalidPath
    );
    let symlink = SkillPackFile::symlink(
        fixture.files[0].path().clone(),
        SkillPackPath::new("outside.md").expect("symlink target"),
    )
    .expect("symlink fixture");
    let mut symlink_files = fixture.files.clone();
    symlink_files[0] = symlink;
    assert_eq!(
        package_from_files(
            fixture.manifest.clone(),
            fixture.source.clone(),
            &symlink_files,
            SkillPackVerificationStatus::Verified,
        )
        .expect_err("symlink must be rejected"),
        SkillPackError::SymlinkEscape
    );

    let extra_path = SkillPackPath::new("unknown.txt").expect("extra path");
    let mut extra_files = fixture.files.clone();
    extra_files.push(SkillPackFile::regular(extra_path, b"unknown".to_vec()).expect("extra"));
    assert_eq!(
        package_from_files(
            fixture.manifest.clone(),
            fixture.source.clone(),
            &extra_files,
            SkillPackVerificationStatus::Verified,
        )
        .expect_err("unknown file must be rejected"),
        SkillPackError::UnknownFile
    );

    let wrong_source = SkillPackSource::new(
        Digest::from_text("fixture.other.locator"),
        fixture.source.source_digest().clone(),
    )
    .expect("wrong source");
    let request = SkillPackLoadRequest::new(
        fixture.context.scope().clone(),
        fixture.policy.digest().clone(),
        wrong_source,
        None,
        None,
        None,
    )
    .expect("drift request");
    let (host, releases) = FixtureHost::for_package(fixture.package);
    let mut runtime = PluginRuntime::new();
    assert_eq!(
        SkillPackProvider::load_and_mount(host, &request, fixture.policy, &mut runtime)
            .expect_err("source drift"),
        SkillPackError::PathDrift
    );
    assert!(runtime.inspect(&scope(1)).is_empty());
    assert_eq!(releases.lock().expect("release ledger").len(), 1);
}

#[test]
fn missing_capability_or_audit_commit_failure_removes_runtime_state() {
    let missing_fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    let (host, releases) = FixtureHost::for_package(missing_fixture.package.clone());
    let mut runtime = PluginRuntime::new();
    let mut provider = SkillPackProvider::load_and_mount(
        host,
        &missing_fixture.request,
        missing_fixture.policy.clone(),
        &mut runtime,
    )
    .expect("mount");
    let mut resolver = EmptyResolver;
    let mut log = MemorySkillPackAuditLog::default();
    assert_eq!(
        provider
            .compose(
                &missing_fixture.context,
                &mut resolver,
                &mut runtime,
                &mut log,
                1,
            )
            .expect_err("missing capability"),
        SkillPackError::CapabilityMismatch
    );
    assert_eq!(provider.status(), SkillPackStatus::Failed);
    assert!(runtime.inspect(missing_fixture.context.scope()).is_empty());
    assert_eq!(
        releases.lock().expect("release ledger").as_slice(),
        &[missing_fixture.package.package_digest().clone()]
    );

    let audit_fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    let (host, releases) = FixtureHost::for_package(audit_fixture.package.clone());
    let mut runtime = PluginRuntime::new();
    let mut provider = SkillPackProvider::load_and_mount(
        host,
        &audit_fixture.request,
        audit_fixture.policy,
        &mut runtime,
    )
    .expect("mount");
    let mut resolver = ExactResolver;
    let mut rejecting_log = RejectingAuditLog;
    assert_eq!(
        provider
            .compose(
                &audit_fixture.context,
                &mut resolver,
                &mut runtime,
                &mut rejecting_log,
                2,
            )
            .expect_err("audit commit failure"),
        SkillPackError::AuditCommitFailed
    );
    assert_eq!(provider.status(), SkillPackStatus::Failed);
    assert!(runtime.inspect(audit_fixture.context.scope()).is_empty());
    assert_eq!(
        releases.lock().expect("release ledger").as_slice(),
        &[audit_fixture.package.package_digest().clone()]
    );
}

#[test]
fn unmount_and_revoke_make_old_context_unusable() {
    let unmount_fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    let (host, releases) = FixtureHost::for_package(unmount_fixture.package.clone());
    let mut runtime = PluginRuntime::new();
    let mut provider = SkillPackProvider::load_and_mount(
        host,
        &unmount_fixture.request,
        unmount_fixture.policy.clone(),
        &mut runtime,
    )
    .expect("mount");
    let mut resolver = ExactResolver;
    let mut log = MemorySkillPackAuditLog::default();
    let model = provider
        .compose(
            &unmount_fixture.context,
            &mut resolver,
            &mut runtime,
            &mut log,
            1,
        )
        .expect("compose");
    provider
        .unmount(&unmount_fixture.context, &mut runtime, &mut log, 2)
        .expect("unmount");
    assert_eq!(provider.status(), SkillPackStatus::Unmounted);
    assert!(runtime.inspect(unmount_fixture.context.scope()).is_empty());
    assert_eq!(
        provider
            .validate_context(&unmount_fixture.context, &model, &runtime)
            .expect_err("late unmounted context"),
        SkillPackError::PluginUnmounted
    );
    assert_eq!(
        provider
            .unmount(&unmount_fixture.context, &mut runtime, &mut log, 3)
            .expect_err("duplicate unmount"),
        SkillPackError::PluginUnmounted
    );
    assert_eq!(releases.lock().expect("release ledger").len(), 1);

    let revoke_fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    let (host, _releases) = FixtureHost::for_package(revoke_fixture.package.clone());
    let mut runtime = PluginRuntime::new();
    let mut provider = SkillPackProvider::load_and_mount(
        host,
        &revoke_fixture.request,
        revoke_fixture.policy,
        &mut runtime,
    )
    .expect("mount");
    let mut log = MemorySkillPackAuditLog::default();
    provider
        .revoke(&revoke_fixture.context, &mut runtime, &mut log, 4)
        .expect("revoke");
    assert_eq!(provider.status(), SkillPackStatus::Revoked);
    assert!(runtime.inspect(revoke_fixture.context.scope()).is_empty());
}

#[test]
fn missing_upgrade_migration_preserves_old_mount_but_crash_releases_it() {
    let fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    let (host, releases) = FixtureHost::for_package(fixture.package.clone());
    let mut runtime = PluginRuntime::new();
    let mut provider =
        SkillPackProvider::load_and_mount(host, &fixture.request, fixture.policy, &mut runtime)
            .expect("mount");
    let mut log = MemorySkillPackAuditLog::default();
    assert_eq!(
        provider
            .upgrade(
                &fixture.context,
                &fixture.request,
                &mut runtime,
                &mut log,
                1,
            )
            .expect_err("missing migration"),
        SkillPackError::UpgradeMigrationRequired
    );
    assert_eq!(provider.status(), SkillPackStatus::Mounted);
    assert!(!runtime.inspect(fixture.context.scope()).is_empty());
    provider.crash(&mut runtime).expect("crash cleanup");
    assert_eq!(provider.status(), SkillPackStatus::Failed);
    assert!(runtime.inspect(fixture.context.scope()).is_empty());
    assert_eq!(releases.lock().expect("release ledger").len(), 1);
}

#[test]
fn upgrade_requires_verified_migration_and_invalidates_old_generation_binding() {
    let old = fixture(PluginVersion::new(1, 0, 0), 1);
    let new = fixture(PluginVersion::new(1, 1, 0), 1);
    assert_eq!(old.policy.digest(), new.policy.digest());
    let migration = SkillPackMigrationReceipt::new(
        &old.context.scope().clone(),
        &old.policy,
        &old.package,
        &new.package,
        Digest::from_text("fixture.skill.migration"),
    )
    .expect("migration receipt");
    let (mut host, releases) = FixtureHost::for_package(old.package.clone());
    host.upgrade_plan = Some(SkillPackUpgradePlan::new(new.package.clone(), migration));
    let mut runtime = PluginRuntime::new();
    let mut provider =
        SkillPackProvider::load_and_mount(host, &old.request, old.policy.clone(), &mut runtime)
            .expect("mount old");
    let mut resolver = ExactResolver;
    let mut log = MemorySkillPackAuditLog::default();
    let old_model = provider
        .compose(&old.context, &mut resolver, &mut runtime, &mut log, 1)
        .expect("old compose");
    provider
        .upgrade(&old.context, &new.request, &mut runtime, &mut log, 2)
        .expect("upgrade");
    assert_eq!(provider.status(), SkillPackStatus::Mounted);
    assert_eq!(provider.metadata().version(), PluginVersion::new(1, 1, 0));
    assert_eq!(
        provider.metadata().manifest_digest(),
        new.package.manifest().digest()
    );
    assert_eq!(
        provider
            .validate_context(&old.context, &old_model, &runtime)
            .expect_err("old context must be stale"),
        SkillPackError::LateConsumer
    );
    let new_model = provider
        .compose(&old.context, &mut resolver, &mut runtime, &mut log, 3)
        .expect("new compose");
    assert_eq!(new_model.receipt().version(), PluginVersion::new(1, 1, 0));
    assert_eq!(
        releases.lock().expect("release ledger").as_slice(),
        &[old.package.package_digest().clone()]
    );
    assert!(!runtime.inspect(old.context.scope()).is_empty());
}

#[test]
fn tampered_verification_receipt_is_not_a_verified_package() {
    let fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    let content_digest = SkillPackVerifiedPackage::content_digest_for_files(&fixture.files);
    let receipt = verification_receipt(
        &fixture.manifest,
        &fixture.source,
        &content_digest,
        SkillPackVerificationStatus::Verified,
    );
    let mut value = serde_json::to_value(&receipt).expect("receipt value");
    value["receiptDigest"] = serde_json::json!(Digest::from_text("tampered.receipt"));
    let tampered: SkillPackVerificationReceipt =
        serde_json::from_value(value).expect("tampered receipt shape");
    assert_eq!(
        SkillPackVerifiedPackage::new(fixture.manifest, fixture.source, &fixture.files, tampered,)
            .expect_err("tamper must fail"),
        SkillPackError::VerificationFailed
    );
}

#[test]
fn real_verified_package_smoke_is_explicitly_blocked_without_native_host() {
    let required = [
        "HARTEVO_SKILL_VERIFIED_PACKAGE_SOURCE",
        "HARTEVO_SKILL_VERIFIER",
        "HARTEVO_SKILL_RUNNER",
    ];
    let missing: Vec<_> = required
        .iter()
        .copied()
        .filter(|name| env::var_os(name).is_none())
        .collect();
    if !missing.is_empty() {
        eprintln!("BLOCKED_ENV: missing verified Skill Pack smoke inputs");
        return;
    }
    eprintln!("Disconnected: native verifier/runner adapter is not provided by plugin-runtime");
    let fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    let (mut host, _releases) = FixtureHost::for_package(fixture.package);
    host.verify_error = Some(SkillPackHostError::Disconnected);
    let mut runtime = PluginRuntime::new();
    assert_eq!(
        SkillPackProvider::load_and_mount(host, &fixture.request, fixture.policy, &mut runtime)
            .expect_err("native smoke is disconnected"),
        SkillPackError::Disconnected
    );
}

#[test]
fn context_receipt_is_digest_only_and_round_trips() {
    let fixture = fixture(PluginVersion::new(1, 0, 0), 1);
    let (host, _releases) = FixtureHost::for_package(fixture.package);
    let mut runtime = PluginRuntime::new();
    let mut provider =
        SkillPackProvider::load_and_mount(host, &fixture.request, fixture.policy, &mut runtime)
            .expect("mount");
    let mut resolver = ExactResolver;
    let mut log = MemorySkillPackAuditLog::default();
    let model = provider
        .compose(&fixture.context, &mut resolver, &mut runtime, &mut log, 10)
        .expect("compose");
    let round_trip: SkillPackContextReceipt =
        serde_json::from_str(&serde_json::to_string(model.receipt()).expect("receipt json"))
            .expect("receipt round trip");
    assert_eq!(round_trip.digest(), model.receipt().digest());
    assert_eq!(
        round_trip.package_digest(),
        model.receipt().package_digest()
    );
    assert!(!format!("{round_trip:?}").contains(&fixture.public_text));
}

proptest! {
    #[test]
    fn parent_components_are_never_accepted_as_skill_paths(prefix in "[a-z]{0,16}") {
        let path = format!("{prefix}/../skill.md");
        prop_assert_eq!(SkillPackPath::new(path), Err(SkillPackError::InvalidPath));
    }
}
