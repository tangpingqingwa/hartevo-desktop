use std::collections::{BTreeMap, BTreeSet};

use hartevo_plugin_runtime::skill::{
    MemorySkillPackAuditLog, SkillPackCapabilityResolution, SkillPackCapabilityResolver,
    SkillPackFile, SkillPackHostAdapter, SkillPackHostError, SkillPackLoadRequest,
    SkillPackManifest, SkillPackMissionContext, SkillPackPolicy, SkillPackPolicySpec,
    SkillPackProvider, SkillPackService, SkillPackSource, SkillPackVerificationAttestation,
    SkillPackVerificationReceipt, SkillPackVerificationStatus, SkillPackVerifiedPackage,
};
use hartevo_plugin_runtime::{
    Digest, MissionId, PluginId, PluginRuntime, PluginScope, PluginVersion, ProjectId,
};

struct SampleHost {
    package: SkillPackVerifiedPackage,
}

impl SkillPackHostAdapter for SampleHost {
    fn verify_and_load(
        &mut self,
        _request: &SkillPackLoadRequest,
    ) -> Result<SkillPackVerifiedPackage, SkillPackHostError> {
        Ok(self.package.clone())
    }

    fn release(&mut self, _package_digest: &Digest) -> Result<(), SkillPackHostError> {
        Ok(())
    }
}

struct NoCapabilities;

impl SkillPackCapabilityResolver for NoCapabilities {
    fn resolve(
        &mut self,
        scope: &PluginScope,
        policy: &SkillPackPolicy,
        _required_services: &[hartevo_plugin_runtime::skill::SkillServiceRequirement],
        _required_tools: &[hartevo_plugin_runtime::skill::SkillToolRequirement],
    ) -> Result<SkillPackCapabilityResolution, hartevo_plugin_runtime::skill::SkillPackError> {
        SkillPackCapabilityResolution::from_requirements(scope, policy, Vec::new(), Vec::new())
    }
}

fn main() {
    let service = SkillPackService::definition().expect("SkillPackService definition");
    let scope = PluginScope::new(
        ProjectId::new("project.example").expect("project"),
        MissionId::new("mission.example").expect("mission"),
        1,
    )
    .expect("scope");
    let package_id =
        hartevo_plugin_runtime::skill::SkillPackId::new("pack.example").expect("package id");
    let skill_id = hartevo_plugin_runtime::skill::SkillId::new("skill.example").expect("skill id");
    let path =
        hartevo_plugin_runtime::skill::SkillPackPath::new("instructions/hello.md").expect("path");
    let bytes = b"Use only the typed capability gateway.".to_vec();
    let files = vec![SkillPackFile::regular(path.clone(), bytes.clone()).expect("file")];
    let manifest = SkillPackManifest::new(
        package_id.clone(),
        PluginId::new("plugin.example").expect("plugin id"),
        skill_id.clone(),
        PluginVersion::new(1, 0, 0),
        PluginVersion::new(1, 0, 0),
        BTreeMap::from([(path.clone(), Digest::from_bytes(&bytes))]),
        BTreeMap::from([(
            hartevo_plugin_runtime::skill::SkillItemId::new("instruction.hello").expect("item id"),
            path,
        )]),
        BTreeMap::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect("manifest");
    let source = SkillPackSource::new(
        Digest::from_text("example.locator"),
        Digest::from_text("example.source"),
    )
    .expect("source");
    let content_digest = SkillPackVerifiedPackage::content_digest_for_files(&files);
    let verification =
        SkillPackVerificationReceipt::from_attestation(SkillPackVerificationAttestation {
            status: SkillPackVerificationStatus::Verified,
            verifier_digest: Digest::from_text("example.verifier"),
            signature_digest: Digest::from_text("example.signature"),
            source_digest: source.source_digest().clone(),
            manifest_digest: manifest.digest().clone(),
            content_digest,
            host_api: PluginVersion::new(1, 0, 0),
            verified_at: 1,
        })
        .expect("verification");
    let package = SkillPackVerifiedPackage::new(manifest, source.clone(), &files, verification)
        .expect("verified package");
    let policy = SkillPackPolicy::new(SkillPackPolicySpec {
        allowed_package_ids: BTreeSet::from([package_id]),
        allowed_skill_ids: BTreeSet::from([skill_id]),
        allowed_source_digests: BTreeSet::from([source.source_digest().clone()]),
        allowed_instruction_ids: BTreeSet::from([hartevo_plugin_runtime::skill::SkillItemId::new(
            "instruction.hello",
        )
        .expect("item id")]),
        allowed_recipe_ids: BTreeSet::new(),
        allowed_capability_digests: BTreeSet::new(),
        host_api: PluginVersion::new(1, 0, 0),
    })
    .expect("policy");
    let request = SkillPackLoadRequest::new(
        scope.clone(),
        policy.digest().clone(),
        source,
        Some(package.package_digest().clone()),
        Some(package.manifest().digest().clone()),
        Some(package.content_digest().clone()),
    )
    .expect("request");
    let context =
        SkillPackMissionContext::new(scope, policy.digest().clone()).expect("mission context");
    let mut runtime = PluginRuntime::new();
    let mut provider =
        SkillPackProvider::load_and_mount(SampleHost { package }, &request, policy, &mut runtime)
            .expect("mount");
    let mut resolver = NoCapabilities;
    let mut audit = MemorySkillPackAuditLog::default();
    let model = provider
        .compose(&context, &mut resolver, &mut runtime, &mut audit, 1)
        .expect("compose");
    println!("Mounted {service:?}; context receipt={:?}", model.receipt());
    println!(
        "Model-visible instruction: {}",
        model.instructions()[0].content().as_str()
    );
}
