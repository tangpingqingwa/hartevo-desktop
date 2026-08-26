use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    ConfigValue, Context, CordisError, EnvironmentOverlay, Loader, LoaderContext, OverlayLayer,
    PluginEntry, PluginId, PluginSpec, Service, keys, load_plugins,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Marker(&'static str);

struct ProvideTools;

impl Service for ProvideTools {
    fn apply(self, ctx: &mut Context) {
        ctx.provide(keys::TOOLS, Marker("tools"));
        ctx.set_var(
            "tools",
            ConfigValue::object([("endpoint", "ctx://tools".into())]),
        );
    }
}

#[test]
fn overlay_selects_plugins_instead_of_a_crate_boot_list() {
    let catalog = vec![
        PluginEntry::new("domain"),
        PluginEntry::new("tools"),
        PluginEntry::new("openinterpreter").with_disabled(true),
        PluginEntry::new("desktop"),
    ];
    let overlay = EnvironmentOverlay::new("macos-dev")
        .with_layer(OverlayLayer::new("base").enable("domain").enable("tools"))
        .with_layer(
            OverlayLayer::new("env")
                .disable("openinterpreter")
                .enable("desktop")
                .only(["domain", "desktop"]),
        );

    let selected: Vec<_> = overlay
        .select(&catalog)
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    assert_eq!(
        selected,
        [PluginId::new("domain"), PluginId::new("desktop")]
    );
    assert!(!selected.iter().any(|id| id.as_str() == "tools"));
    assert!(!selected.iter().any(|id| id.as_str() == "openinterpreter"));

    let base_only = EnvironmentOverlay::new("macos-dev")
        .with_layer(OverlayLayer::new("base").enable("domain").enable("tools"));
    assert_eq!(
        base_only
            .select(&catalog)
            .into_iter()
            .map(|entry| entry.id)
            .collect::<Vec<_>>(),
        [PluginId::new("domain"), PluginId::new("tools")]
    );
}

#[test]
fn disabled_interpolates_from_loader_context_not_plugin_context() {
    let catalog = vec![
        PluginEntry::new("trace").with_disabled("{env.debug}"),
        PluginEntry::new("llm").with_disabled("{flags.disableLlm}"),
    ];
    let overlay = EnvironmentOverlay::new("test");
    let loader = Loader::new(
        overlay,
        LoaderContext::new()
            .with("env", ConfigValue::object([("debug", false.into())]))
            .with("flags", ConfigValue::object([("disableLlm", true.into())])),
    )
    .with_catalog(catalog);

    let resolved = loader.resolve().unwrap();
    let by_id: std::collections::BTreeMap<_, _> = resolved
        .into_iter()
        .map(|plugin| (plugin.id.as_str().to_string(), plugin.disabled))
        .collect();
    assert_eq!(by_id.get("trace"), Some(&false));
    assert_eq!(by_id.get("llm"), Some(&true));
    assert_eq!(
        loader
            .enabled()
            .unwrap()
            .into_iter()
            .map(|plugin| plugin.id)
            .collect::<Vec<_>>(),
        [PluginId::new("trace")]
    );
}

#[test]
fn plugin_config_interpolates_after_inject_on_the_plugin_context() {
    let mut ctx = Context::new();
    let started = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Mutex::new(None));

    let loader = LoaderContext::new().with("env", ConfigValue::object([("name", "prod".into())]));
    // Loader context has a colliding key; plugin config must not read it.
    let overlay = EnvironmentOverlay::new("test");

    let provider = PluginSpec::new("tools", |_config, ctx| {
        ProvideTools.apply(ctx);
    });
    let consumer_started = Arc::clone(&started);
    let consumer_seen = Arc::clone(&seen);
    let consumer = PluginSpec::new("agent", move |config, _ctx| {
        consumer_started.store(true, Ordering::SeqCst);
        *consumer_seen.lock().expect("seen") = Some(config);
    })
    .with_inject([keys::TOOLS])
    .with_config(ConfigValue::object([
        ("endpoint", ConfigValue::string("{tools.endpoint}")),
        ("env", ConfigValue::string("{env.name}")),
    ]));

    ctx.set_var("env", ConfigValue::object([("name", "plugin-ctx".into())]));
    let report = load_plugins(&mut ctx, &loader, &overlay, &[provider, consumer]).unwrap();
    assert_eq!(
        report.started,
        [PluginId::new("tools"), PluginId::new("agent")]
    );
    assert!(started.load(Ordering::SeqCst));
    assert_eq!(
        seen.lock().expect("seen").clone(),
        Some(ConfigValue::object([
            ("endpoint", "ctx://tools".into()),
            ("env", "plugin-ctx".into()),
        ]))
    );
}

#[test]
fn missing_inject_blocks_config_interpolation_and_start() {
    let mut ctx = Context::new();
    let started = Arc::new(AtomicBool::new(false));
    let interpolations = Arc::new(AtomicUsize::new(0));
    let overlay = EnvironmentOverlay::new("test");
    let loader = LoaderContext::new();

    let interpolations_for_plugin = Arc::clone(&interpolations);
    let started_for_plugin = Arc::clone(&started);
    let plugin = PluginSpec::new("agent", move |config, _ctx| {
        interpolations_for_plugin.fetch_add(1, Ordering::SeqCst);
        let _ = config;
        started_for_plugin.store(true, Ordering::SeqCst);
    })
    .with_inject([keys::TOOLS])
    .with_config(ConfigValue::string("{tools.endpoint}"));

    let err = load_plugins(&mut ctx, &loader, &overlay, &[plugin]).unwrap_err();
    assert_eq!(
        err,
        CordisError::MissingDependencies(vec![keys::TOOLS.to_string()])
    );
    assert!(!started.load(Ordering::SeqCst));
    assert_eq!(interpolations.load(Ordering::SeqCst), 0);
}

#[test]
fn load_order_follows_inject_not_catalog_order() {
    let mut ctx = Context::new();
    let order = Arc::new(Mutex::new(Vec::new()));
    let overlay = EnvironmentOverlay::new("test");
    let loader = LoaderContext::new();

    let order_agent = Arc::clone(&order);
    let agent = PluginSpec::new("agent", move |_config, _ctx| {
        order_agent.lock().expect("order").push("agent");
    })
    .with_inject([keys::TOOLS]);

    let order_tools = Arc::clone(&order);
    let tools = PluginSpec::new("tools", move |_config, ctx| {
        order_tools.lock().expect("order").push("tools");
        ProvideTools.apply(ctx);
    });

    // Catalog lists the dependent plugin first. Overlay does not sort by crate.
    let report = load_plugins(&mut ctx, &loader, &overlay, &[agent, tools]).unwrap();
    assert_eq!(*order.lock().expect("order"), ["tools", "agent"]);
    assert_eq!(
        report.started,
        [PluginId::new("tools"), PluginId::new("agent")]
    );
}

#[test]
fn overlay_disabled_plugin_never_starts_even_when_inject_is_ready() {
    let mut ctx = Context::new();
    ctx.provide(keys::TOOLS, Marker("tools"));
    let started = Arc::new(AtomicBool::new(false));
    let overlay =
        EnvironmentOverlay::new("test").with_layer(OverlayLayer::new("env").disable("agent"));
    let loader = LoaderContext::new();
    let started_for_plugin = Arc::clone(&started);
    let plugin = PluginSpec::new("agent", move |_config, _ctx| {
        started_for_plugin.store(true, Ordering::SeqCst);
    })
    .with_inject([keys::TOOLS]);

    let report = load_plugins(&mut ctx, &loader, &overlay, &[plugin]).unwrap();
    assert!(report.started.is_empty());
    assert!(report.disabled.is_empty());
    assert_eq!(report.omitted, [PluginId::new("agent")]);
    assert!(!started.load(Ordering::SeqCst));
}

#[test]
fn loader_disabled_flag_skips_start_without_reading_plugin_vars() {
    let mut ctx = Context::new();
    ctx.set_var("flags", ConfigValue::object([("off", false.into())]));
    let started = Arc::new(AtomicBool::new(false));
    let overlay = EnvironmentOverlay::new("test");
    let loader = LoaderContext::new().with("flags", ConfigValue::object([("off", true.into())]));
    let started_for_plugin = Arc::clone(&started);
    let plugin = PluginSpec::new("trace", move |_config, _ctx| {
        started_for_plugin.store(true, Ordering::SeqCst);
    })
    .with_disabled("{flags.off}");

    let report = load_plugins(&mut ctx, &loader, &overlay, &[plugin]).unwrap();
    assert_eq!(report.disabled, [PluginId::new("trace")]);
    assert!(!started.load(Ordering::SeqCst));
}

#[test]
fn plugin_var_is_reversed_on_teardown() {
    let mut ctx = Context::new();
    ctx.set_var("env", ConfigValue::string("one"));
    assert_eq!(ctx.var("env"), Some(&ConfigValue::string("one")));
    ctx.teardown();
    assert!(ctx.var("env").is_none());
}

#[test]
fn plugin_config_does_not_fall_back_to_loader_context() {
    let mut ctx = Context::new();
    ctx.provide(keys::TOOLS, Marker("tools"));
    let overlay = EnvironmentOverlay::new("test");
    let loader = LoaderContext::new().with(
        "tools",
        ConfigValue::object([("endpoint", "loader://tools".into())]),
    );
    let plugin = PluginSpec::new("agent", |_config, _ctx| {})
        .with_inject([keys::TOOLS])
        .with_config(ConfigValue::string("{tools.endpoint}"));

    let err = load_plugins(&mut ctx, &loader, &overlay, &[plugin]).unwrap_err();
    match err {
        CordisError::Interpolate(hartevo_cordis::InterpolateError::MissingPath {
            path, ..
        }) => {
            assert_eq!(path, "tools.endpoint");
        }
        other => panic!("expected missing plugin-context path, got {other:?}"),
    }
}

#[test]
fn overlay_replace_overrides_catalog_disabled_and_config() {
    let overlay = EnvironmentOverlay::new("prod").with_layer(
        OverlayLayer::new("env").replace(
            PluginEntry::new("trace")
                .with_disabled(true)
                .with_config(ConfigValue::string("prod")),
        ),
    );
    let loader = Loader::new(overlay, LoaderContext::new()).with_catalog(vec![
        PluginEntry::new("trace")
            .with_disabled(false)
            .with_config(ConfigValue::string("dev")),
    ]);
    let resolved = loader.resolve().unwrap();
    assert_eq!(resolved.len(), 1);
    assert!(resolved[0].disabled);
    assert_eq!(resolved[0].config, ConfigValue::string("prod"));
}
