use hartevo_plugin_runtime::{
    ConsumerId, Digest, PluginRuntime, PluginVersion, ProviderId, ServiceId,
    provenance::{
        BuildProvenance, PluginEvidenceBinding, PluginEvidenceConsumer, PluginEvidenceProvider,
        PluginEvidenceService,
    },
    sample::SampleReadOnlyPlugin,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scope = SampleReadOnlyPlugin::default_scope()?;
    let definition = SampleReadOnlyPlugin::definition(scope, PluginVersion::new(1, 0, 0))?;
    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition)?;
    let mount_receipt = runtime.mount(&handle)?;

    let service = PluginEvidenceService::definition()?;
    let provider = PluginEvidenceProvider::default();
    let consumer = PluginEvidenceConsumer::default();
    assert_eq!(provider.definition()?.service_id(), service.id());
    assert_eq!(consumer.definition()?.service_id(), service.id());

    let binding = PluginEvidenceBinding::from_mounted_plugin(
        &handle,
        &mount_receipt,
        &ServiceId::new("sample.read")?,
        &ProviderId::new("sample.read.provider")?,
        &ConsumerId::new("sample.read.tool")?,
    )?;
    let provenance = BuildProvenance::new(
        "114abe2bc04d77d1eca4efea64092b37a0b0fb06",
        "aarch64-apple-darwin",
        handle.version(),
        Digest::from_text("fixture-plugin-artifact"),
        "rustc 1.95.0 (fixture-contract)",
    )?;
    let evidence = provider.generate(&binding, &provenance)?;
    let verification = consumer.verify(&evidence, &provenance, None)?;
    assert!(!evidence.release_ready());
    assert!(!verification.release_ready());

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "execution": "FIXTURE_CONTRACT_ONLY",
            "evidence": evidence,
            "verification": verification,
            "release": false,
            "nativeEvidence": "NOT_PROVEN"
        }))?
    );

    runtime.unmount(&mount_receipt)?;
    Ok(())
}
