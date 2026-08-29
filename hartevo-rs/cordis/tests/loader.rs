use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    ConfigValue, Context, CordisError, EnvironmentOverlay, Loader, LoaderContext, OverlayLayer,
    PluginEntry, PluginFactory, PluginId, PluginSpec, Service, keys, load_plugins,
    load_plugins_pending,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Marker(&'static str);

struct ProvideTools;

impl Service for ProvideTools {
    fn apply(self, ctx: &mut Context) -> Result<(), CordisError> {
        ctx.provide(keys::TOOLS, Marker("tools"))?;
        ctx.set_var(
            "tools",
            ConfigValue::object([("endpoint", "ctx://tools".into())]),
        );
        Ok(())
    }
}

struct ChildOwnedService;

impl Service for ChildOwnedService {
    fn apply(self, ctx: &mut Context) -> Result<(), CordisError> {
        ctx.provide("child-owned-service", true).map(|_| ())
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

    let provider = PluginSpec::new("tools", |_config, ctx| ProvideTools.apply(ctx));
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
        ProvideTools.apply(ctx)
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
    ctx.provide(keys::TOOLS, Marker("tools")).unwrap();
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
    ctx.provide(keys::TOOLS, Marker("tools")).unwrap();
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

#[test]
fn pending_factory_is_retained_and_activates_once_after_provider_arrives() {
    let mut ctx = Context::new();
    let starts = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let factory = PluginFactory::new("identity", |_config, _ctx| Ok::<(), CordisError>(()));
    let cloned = factory.clone();
    assert_eq!(factory.id(), cloned.id());

    ctx.set_var(
        "dependency",
        ConfigValue::object([("value", "ready".into())]),
    );
    let starts_for_plugin = Arc::clone(&starts);
    let seen_for_plugin = Arc::clone(&seen);
    let plugin = PluginSpec::new("consumer", move |config, ctx| {
        starts_for_plugin.fetch_add(1, Ordering::SeqCst);
        seen_for_plugin.lock().expect("seen").push(config);
        ctx.provide("consumer-output", Marker("active")).map(|_| ())
    })
    .with_inject(["dependency"])
    .with_config(ConfigValue::string("{dependency.value}"));
    let report = load_plugins_pending(
        &mut ctx,
        &LoaderContext::new(),
        &EnvironmentOverlay::new("test"),
        &[plugin],
    )
    .unwrap();
    assert_eq!(report.pending, [PluginId::new("consumer")]);
    assert_eq!(ctx.pending_count(), 1);
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    ctx.provide(
        "dependency",
        ConfigValue::object([("value", "ready".into())]),
    )
    .unwrap();
    assert_eq!(ctx.pending_count(), 0);

    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(seen.lock().expect("seen").len(), 1);
    assert_eq!(ctx.pending_count(), 0);
    assert!(ctx.has("consumer-output"));
}

#[test]
fn disposed_pending_factory_never_receives_late_activation() {
    let mut ctx = Context::new();
    let starts = Arc::new(AtomicUsize::new(0));
    let starts_for_factory = Arc::clone(&starts);
    let factory = PluginFactory::new("late", move |_config, _ctx| {
        starts_for_factory.fetch_add(1, Ordering::SeqCst);
        Ok::<(), CordisError>(())
    })
    .with_inject(["dependency"]);
    let handle = ctx.mount_pending(factory).unwrap();
    assert!(handle.is_pending());
    assert!(ctx.dispose_pending(&handle).unwrap());
    assert!(handle.is_disposed());
    assert_eq!(ctx.pending_count(), 0);
    ctx.provide("dependency", Marker("ready")).unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    assert_eq!(handle.state(), hartevo_cordis::FiberState::Pending);
}

#[test]
fn failed_pending_activation_propagates_and_cleans_partial_records() {
    let mut ctx = Context::new();
    let disposed = Arc::new(AtomicUsize::new(0));
    let disposed_for_factory = Arc::clone(&disposed);
    let factory = PluginFactory::new("failing", move |_config, ctx| {
        ctx.provide("partial", true)?;
        let disposed_for_disposer = Arc::clone(&disposed_for_factory);
        ctx.effect(move || {
            disposed_for_disposer.fetch_add(1, Ordering::SeqCst);
        });
        Err(CordisError::MissingDependencies(vec!["late".to_string()]))
    });

    let error = ctx.mount_pending(factory).unwrap_err();
    match error {
        CordisError::PluginActivation { source, .. } => assert_eq!(
            *source,
            CordisError::MissingDependencies(vec!["late".to_string()])
        ),
        other => panic!("expected activation error, got {other:?}"),
    }
    assert!(!ctx.has("partial"));
    assert_eq!(ctx.registration_count(), 0);
    assert_eq!(disposed.load(Ordering::SeqCst), 1);
}

#[test]
fn mount_preserves_factory_fiber_owner_until_disposal() {
    let mut ctx = Context::new();
    let factory = PluginFactory::new("owner-preserving", |_config, ctx| {
        ctx.mount(ChildOwnedService)
    })
    .with_inject(["dependency"]);
    let pending = ctx.mount_pending(factory).unwrap();

    ctx.provide("dependency", Marker("ready")).unwrap();
    assert!(pending.is_active());
    assert!(ctx.has("child-owned-service"));

    ctx.dispose_pending(&pending).unwrap();
    assert!(pending.is_disposed());
    assert!(!ctx.has("child-owned-service"));
    assert!(ctx.has("dependency"));
}

#[test]
fn downstream_notification_error_returns_committed_factory_handle() {
    let mut ctx = Context::new();
    let downstream = PluginFactory::new("downstream-fails-after-starter", |_config, _ctx| {
        Err::<(), _>(CordisError::MissingDependencies(vec![
            "downstream".to_string(),
        ]))
    })
    .with_inject(["dependency"]);
    let downstream = ctx.mount_pending(downstream).unwrap();
    let starter = PluginFactory::new("starter-provides-dependency", |_config, ctx| {
        ctx.provide("dependency", Marker("ready")).map(|_| ())
    });

    let committed = match ctx.mount_pending(starter).unwrap_err() {
        CordisError::PendingNotification { handle, .. } => handle,
        other => panic!("expected committed factory handle, got {other:?}"),
    };
    assert!(committed.is_active());
    assert!(downstream.is_disposed());
    assert!(ctx.has("dependency"));

    assert!(ctx.dispose_pending(&committed).unwrap());
    assert!(committed.is_disposed());
    assert!(!ctx.has("dependency"));
    assert_eq!(ctx.pending_count(), 0);
}

#[test]
fn failed_ready_factory_requeues_later_ready_factories() {
    let mut ctx = Context::new();
    let first = PluginFactory::new("ready-first-fails", |_config, _ctx| {
        Err::<(), _>(CordisError::MissingDependencies(vec!["later".to_string()]))
    })
    .with_inject(["dependency"]);
    let starts = Arc::new(AtomicUsize::new(0));
    let starts_for_second = Arc::clone(&starts);
    let second = PluginFactory::new("ready-second-succeeds", move |_config, _ctx| {
        starts_for_second.fetch_add(1, Ordering::SeqCst);
        Ok::<(), CordisError>(())
    })
    .with_inject(["dependency"]);
    let _first = ctx.mount_pending(first).unwrap();
    let second = ctx.mount_pending(second).unwrap();

    let error = ctx.provide("dependency", Marker("ready")).unwrap_err();
    assert!(matches!(error, CordisError::ProviderNotification { .. }));
    assert!(second.is_pending());
    assert_eq!(ctx.pending_count(), 1);
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    ctx.provide("retry-notification", true).unwrap();
    assert!(second.is_active());
    assert_eq!(ctx.pending_count(), 0);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
}

#[test]
fn provider_notification_errors_return_a_recoverable_current_handle() {
    let mut ctx = Context::new();
    let first = PluginFactory::new("notification-first-fails", |_config, _ctx| {
        Err::<(), _>(CordisError::MissingDependencies(vec!["late".to_string()]))
    })
    .with_inject(["dependency"]);
    let second = PluginFactory::new("notification-second-fails", |_config, _ctx| {
        Err::<(), _>(CordisError::MissingDependencies(vec!["late".to_string()]))
    })
    .with_inject(["dependency"]);
    let _first = ctx.mount_pending(first).unwrap();
    let _second = ctx.mount_pending(second).unwrap();

    let initial = match ctx.provide("dependency", true).unwrap_err() {
        CordisError::ProviderNotification { handle, .. } => handle,
        other => panic!("expected committed initial handle, got {other:?}"),
    };
    assert_eq!(initial.generation(), 0);
    assert_eq!(ctx.get::<bool>("dependency").as_deref(), Some(&true));

    let replacement = match initial.replace(&mut ctx, false).unwrap_err() {
        CordisError::ProviderNotification { handle, .. } => handle,
        other => panic!("expected committed replacement handle, got {other:?}"),
    };
    assert_eq!(replacement.provider_id(), initial.provider_id());
    assert_eq!(replacement.generation(), 1);
    assert_eq!(ctx.get::<bool>("dependency").as_deref(), Some(&false));

    let current = replacement.replace(&mut ctx, true).unwrap();
    assert_eq!(current.generation(), 2);
    assert_eq!(ctx.get::<bool>("dependency").as_deref(), Some(&true));
}

#[test]
fn immediate_activation_does_not_notify_dependents_before_success() {
    let mut ctx = Context::new();
    let dependent_starts = Arc::new(AtomicUsize::new(0));
    let dependent_starts_for_factory = Arc::clone(&dependent_starts);
    let dependent = PluginFactory::new("dependent-waits-for-partial", move |_config, _ctx| {
        dependent_starts_for_factory.fetch_add(1, Ordering::SeqCst);
        Ok::<(), CordisError>(())
    })
    .with_inject(["partial"]);
    let dependent = ctx.mount_pending(dependent).unwrap();

    let activating = PluginFactory::new("partial-then-fails", |_config, ctx| {
        ctx.provide("partial", true)?;
        Err::<(), _>(CordisError::MissingDependencies(vec![
            "failure".to_string(),
        ]))
    });
    let error = ctx.mount_pending(activating).unwrap_err();
    assert!(matches!(error, CordisError::PluginActivation { .. }));
    assert_eq!(dependent_starts.load(Ordering::SeqCst), 0);
    assert!(dependent.is_pending());
    assert!(!ctx.has("partial"));
    assert_eq!(ctx.pending_count(), 1);

    ctx.provide("partial", true).unwrap();
    assert!(dependent.is_active());
    assert_eq!(dependent_starts.load(Ordering::SeqCst), 1);
}

#[test]
fn pending_config_interpolates_against_the_owning_fiber_metadata() {
    let mut ctx = Context::new();
    ctx.set_var("scope", "parent");
    let child = ctx.new_fiber().unwrap();
    let seen = Arc::new(Mutex::new(None));
    let seen_for_factory = Arc::clone(&seen);
    let factory = PluginFactory::new("scoped-config", move |config, _ctx| {
        *seen_for_factory.lock().expect("seen") = Some(config);
        Ok::<(), CordisError>(())
    })
    .with_inject(["dependency"])
    .with_config(ConfigValue::string("{scope}"));

    {
        let mut view = ctx
            .with_fiber(&child)
            .isolate("tenant")
            .extend(ConfigValue::object([("scope", "child".into())]));
        let pending = view.mount_pending(factory).unwrap();
        assert!(pending.is_pending());
        view.provide("dependency", true).unwrap();
        assert!(pending.is_active());
        assert_eq!(view.var("scope"), Some(&ConfigValue::string("child")));
    }

    assert_eq!(ctx.var("scope"), Some(&ConfigValue::string("parent")));
    assert_eq!(
        *seen.lock().expect("seen"),
        Some(ConfigValue::string("child"))
    );
}

#[test]
fn isolated_factory_context_lookups_use_its_local_namespace() {
    let mut ctx = Context::new();
    ctx.provide("root-only", Marker("root")).unwrap();
    let child = ctx.new_fiber().unwrap();
    let seen = Arc::new(AtomicBool::new(false));
    let seen_for_factory = Arc::clone(&seen);
    let factory = PluginFactory::new("isolated-lookups", move |_config, ctx| {
        assert!(ctx.has("local-dependency"));
        assert!(!ctx.has("root-only"));
        assert_eq!(
            ctx.get::<Marker>("local-dependency").as_deref(),
            Some(&Marker("local"))
        );
        assert!(ctx.get::<Marker>("root-only").is_none());
        seen_for_factory.store(true, Ordering::SeqCst);
        Ok::<(), CordisError>(())
    })
    .with_inject(["local-dependency"]);

    {
        let mut view = ctx.with_fiber(&child).isolate("tenant");
        let pending = view.mount_pending(factory).unwrap();
        assert!(pending.is_pending());
        view.provide("local-dependency", Marker("local")).unwrap();
        assert!(pending.is_active());
    }

    assert!(seen.load(Ordering::SeqCst));
    assert!(ctx.has("root-only"));
    assert!(!ctx.has("local-dependency"));
}

#[test]
fn panicking_notification_returns_committed_provider_handle_and_requeues_ready_work() {
    let mut ctx = Context::new();
    let panicking = PluginFactory::new("panic-first", |_config, _ctx| -> () {
        panic!("intentional factory panic");
    })
    .with_inject(["dependency"]);
    let starts = Arc::new(AtomicUsize::new(0));
    let starts_for_factory = Arc::clone(&starts);
    let later = PluginFactory::new("ready-after-panic", move |_config, _ctx| {
        starts_for_factory.fetch_add(1, Ordering::SeqCst);
        Ok::<(), CordisError>(())
    })
    .with_inject(["dependency"]);
    let panicking = ctx.mount_pending(panicking).unwrap();
    let later = ctx.mount_pending(later).unwrap();

    let committed = match ctx.provide("dependency", true).unwrap_err() {
        CordisError::ProviderNotification { handle, source } => {
            assert!(matches!(*source, CordisError::PluginActivation { .. }));
            handle
        }
        other => panic!("expected committed provider handle, got {other:?}"),
    };
    assert_eq!(committed.generation(), 0);
    assert!(panicking.is_disposed());
    assert!(later.is_pending());
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    let current = committed.replace(&mut ctx, false).unwrap();
    assert_eq!(current.generation(), 1);
    assert!(later.is_active());
    assert_eq!(starts.load(Ordering::SeqCst), 1);
}

#[test]
fn self_disposal_and_teardown_attempts_leave_activation_reusable() {
    let mut ctx = Context::new();
    let fiber_slot = Arc::new(Mutex::new(None));
    let fiber_for_factory = Arc::clone(&fiber_slot);
    let disposed_effect = Arc::new(AtomicUsize::new(0));
    let disposed_effect_for_factory = Arc::clone(&disposed_effect);
    let factory = PluginFactory::new("self-dispose", move |_config, ctx| {
        let fiber = fiber_for_factory
            .lock()
            .expect("fiber")
            .clone()
            .expect("pending fiber");
        assert!(ctx.dispose_fiber(&fiber)?);
        assert!(matches!(
            ctx.provide("post-dispose-provider", true),
            Err(CordisError::FiberDisposed { .. } | CordisError::FiberContextMismatch { .. })
        ));
        let disposed_effect = Arc::clone(&disposed_effect_for_factory);
        let handle = ctx.effect(move || {
            disposed_effect.fetch_add(1, Ordering::SeqCst);
        });
        assert!(handle.is_disposed());
        ctx.set_var("post-dispose-var", "forbidden");
        assert!(ctx.on("post-dispose-event", || {}).is_err());
        assert!(
            ctx.lock_event("post-dispose-lock", hartevo_cordis::DispatchMode::Emit)
                .is_err()
        );
        ctx.teardown();
        Ok::<(), CordisError>(())
    })
    .with_inject(["dependency"]);
    let pending = ctx.mount_pending(factory).unwrap();
    *fiber_slot.lock().expect("fiber") = Some(pending.fiber());

    let error = ctx.provide("dependency", true).unwrap_err();
    assert!(matches!(error, CordisError::ProviderNotification { .. }));
    assert!(pending.is_disposed());
    assert!(!ctx.has("post-dispose-provider"));
    assert_eq!(ctx.var("post-dispose-var"), None);
    assert_eq!(ctx.listener_count("post-dispose-event"), 0);
    assert_eq!(ctx.event_mode("post-dispose-lock"), None);
    assert_eq!(disposed_effect.load(Ordering::SeqCst), 0);
    assert!(ctx.has("dependency"));

    let starts = Arc::new(AtomicUsize::new(0));
    let starts_for_factory = Arc::clone(&starts);
    let clean = ctx
        .mount_pending(PluginFactory::new(
            "clean-after-dispose",
            move |_config, _ctx| {
                starts_for_factory.fetch_add(1, Ordering::SeqCst);
                Ok::<(), CordisError>(())
            },
        ))
        .unwrap();
    assert!(clean.is_active());
    assert_eq!(starts.load(Ordering::SeqCst), 1);
}

#[test]
fn nested_factories_inherit_parent_and_root_switch_is_rejected() {
    let mut ctx = Context::new();
    ctx.provide("root-only", true).unwrap();
    let nested_slot = Arc::new(Mutex::new(None));
    let nested_for_factory = Arc::clone(&nested_slot);
    let parent = PluginFactory::new("parent", move |_config, ctx| {
        let root = ctx.root_fiber();
        let mut root_view = ctx.with_fiber(&root);
        assert!(!root_view.is_valid());
        assert!(!root_view.has("root-only"));
        assert!(matches!(
            root_view.provide("escaped-root-provider", true),
            Err(CordisError::FiberScopeViolation { .. })
        ));
        drop(root_view);

        let nested = ctx.mount_pending(
            PluginFactory::new("nested", |_config, _ctx| Ok::<(), CordisError>(()))
                .with_inject(["nested-dependency"]),
        )?;
        *nested_for_factory.lock().expect("nested") = Some(nested);
        Ok::<(), CordisError>(())
    })
    .with_inject(["parent-dependency"]);
    let parent = ctx.mount_pending(parent).unwrap();
    ctx.provide("parent-dependency", true).unwrap();
    assert!(parent.is_active());
    let nested = nested_slot
        .lock()
        .expect("nested")
        .clone()
        .expect("nested handle");
    assert!(nested.is_pending());
    assert_eq!(nested.fiber().parent_uid(), Some(parent.fiber().uid()));
    assert_eq!(ctx.pending_count(), 1);
    assert!(!ctx.has("escaped-root-provider"));

    assert!(ctx.dispose_pending(&parent).unwrap());
    assert!(parent.is_disposed());
    assert!(nested.is_disposed());
    assert_eq!(ctx.pending_count(), 0);
    assert!(!ctx.has("escaped-root-provider"));
}

#[test]
fn panicking_disposer_cannot_orphan_partial_state_or_drop_ready_queue() {
    let mut ctx = Context::new();
    let failing = PluginFactory::new("cleanup-panics", |_config, ctx| {
        ctx.provide("partial-provider", true)?;
        ctx.on("partial-listener", || {})?;
        ctx.effect(|| panic!("intentional disposer panic"));
        Err::<(), _>(CordisError::MissingDependencies(vec![
            "factory-failure".to_string(),
        ]))
    })
    .with_inject(["dependency"]);
    let starts = Arc::new(AtomicUsize::new(0));
    let starts_for_later = Arc::clone(&starts);
    let later = PluginFactory::new("later-ready", move |_config, _ctx| {
        starts_for_later.fetch_add(1, Ordering::SeqCst);
        Ok::<(), CordisError>(())
    })
    .with_inject(["dependency"]);
    let failing = ctx.mount_pending(failing).unwrap();
    let later = ctx.mount_pending(later).unwrap();

    let error = ctx.provide("dependency", true).unwrap_err();
    assert!(matches!(error, CordisError::ProviderNotification { .. }));
    assert!(failing.is_disposed());
    assert!(later.is_pending());
    assert!(!ctx.has("partial-provider"));
    assert_eq!(ctx.listener_count("partial-listener"), 0);
    assert_eq!(ctx.event_mode("partial-listener"), None);
    assert_eq!(ctx.pending_count(), 1);
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    ctx.provide("retry-cleanup-notification", true).unwrap();
    assert!(later.is_active());
    assert_eq!(ctx.pending_count(), 0);
    assert_eq!(starts.load(Ordering::SeqCst), 1);
}
