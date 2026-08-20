use hartevo_plugin_runtime::{
    PluginId, PluginRuntime, PluginVersion, sample::SampleReadOnlyPlugin,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scope = SampleReadOnlyPlugin::default_scope()?;
    let definition = SampleReadOnlyPlugin::definition(scope.clone(), PluginVersion::new(1, 0, 0))?;
    let mut runtime = PluginRuntime::new();
    let handle = runtime.define(definition)?;
    let receipt = runtime.mount(&handle)?;

    let mounted = runtime.inspect(&scope);
    assert_eq!(mounted.plugins.len(), 1);
    assert_eq!(mounted.services.len(), 1);
    assert_eq!(mounted.providers.len(), 1);
    assert_eq!(mounted.consumers.len(), 1);
    assert_eq!(mounted.events.len(), 1);
    assert_eq!(mounted.ui_surfaces.len(), 2);
    println!("{}", serde_json::to_string_pretty(&mounted)?);

    runtime.unmount(&receipt)?;
    assert!(runtime.inspect(&scope).is_empty());
    let _ = PluginId::new("sample.readonly")?;
    Ok(())
}
