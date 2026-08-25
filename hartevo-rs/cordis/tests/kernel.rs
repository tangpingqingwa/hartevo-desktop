use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hartevo_cordis::{Context, CordisError, Service, keys};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Marker(&'static str);

struct ProvideTools;

impl Service for ProvideTools {
    fn apply(self, ctx: &mut Context) {
        ctx.provide(keys::TOOLS, Marker("tools"));
    }
}

struct NeedsTools {
    started: Arc<AtomicBool>,
}

impl Service for NeedsTools {
    fn inject() -> &'static [&'static str] {
        &[keys::TOOLS]
    }

    fn apply(self, ctx: &mut Context) {
        assert!(ctx.get::<Marker>(keys::TOOLS).is_some());
        self.started.store(true, Ordering::SeqCst);
    }
}

struct NeedsToolsAndLlm {
    started: Arc<AtomicBool>,
}

impl Service for NeedsToolsAndLlm {
    fn inject() -> &'static [&'static str] {
        &[keys::TOOLS, keys::LLM]
    }

    fn apply(self, _ctx: &mut Context) {
        self.started.store(true, Ordering::SeqCst);
    }
}

struct RecordEffect {
    order: Arc<Mutex<Vec<&'static str>>>,
    tag: &'static str,
}

impl Service for RecordEffect {
    fn apply(self, ctx: &mut Context) {
        let order = Arc::clone(&self.order);
        let tag = self.tag;
        ctx.effect(move || order.lock().expect("order").push(tag));
        ctx.on(tag, || {}).unwrap();
    }
}

#[test]
fn typed_slots_round_trip_well_known_keys() {
    let mut ctx = Context::new();
    ctx.provide(keys::TOOLS, Marker("tools"));
    ctx.provide(keys::LLM, Marker("llm"));
    ctx.provide(keys::SESSIONS, Marker("sessions"));
    ctx.provide(keys::DOMAIN, Marker("domain"));
    ctx.provide(keys::EFFECT_BROKER, Marker("effect_broker"));
    ctx.provide(keys::RUNTIME, Marker("runtime"));
    ctx.provide(keys::DESKTOP, Marker("desktop"));

    assert_eq!(
        ctx.get::<Marker>(keys::TOOLS).as_deref(),
        Some(&Marker("tools"))
    );
    assert_eq!(ctx.tools::<Marker>().as_deref(), Some(&Marker("tools")));
    assert_eq!(ctx.llm::<Marker>().as_deref(), Some(&Marker("llm")));
    assert_eq!(
        ctx.sessions::<Marker>().as_deref(),
        Some(&Marker("sessions"))
    );
    assert_eq!(ctx.domain::<Marker>().as_deref(), Some(&Marker("domain")));
    assert_eq!(
        ctx.effect_broker::<Marker>().as_deref(),
        Some(&Marker("effect_broker"))
    );
    assert_eq!(ctx.runtime::<Marker>().as_deref(), Some(&Marker("runtime")));
    assert_eq!(ctx.desktop::<Marker>().as_deref(), Some(&Marker("desktop")));
    assert!(ctx.get::<u32>(keys::TOOLS).is_none());
}

#[test]
fn inject_waits_missing_dependency_errors_and_does_not_start() {
    let mut ctx = Context::new();
    let started = Arc::new(AtomicBool::new(false));
    let err = ctx
        .mount(NeedsTools {
            started: Arc::clone(&started),
        })
        .expect_err("tools is not provided");
    assert_eq!(
        err,
        CordisError::MissingDependencies(vec![keys::TOOLS.to_string()])
    );
    assert!(
        !started.load(Ordering::SeqCst),
        "plugin must not start while inject deps are missing"
    );
}

#[test]
fn inject_reports_every_missing_dependency() {
    let mut ctx = Context::new();
    let started = Arc::new(AtomicBool::new(false));
    let err = ctx
        .mount(NeedsToolsAndLlm {
            started: Arc::clone(&started),
        })
        .expect_err("tools and llm are not provided");
    assert_eq!(
        err,
        CordisError::MissingDependencies(vec![keys::TOOLS.to_string(), keys::LLM.to_string()])
    );
    assert!(!started.load(Ordering::SeqCst));

    ctx.provide(keys::TOOLS, Marker("tools"));
    let err = ctx
        .mount(NeedsToolsAndLlm {
            started: Arc::clone(&started),
        })
        .expect_err("llm is still missing");
    assert_eq!(
        err,
        CordisError::MissingDependencies(vec![keys::LLM.to_string()])
    );
    assert!(!started.load(Ordering::SeqCst));
}

#[test]
fn inject_starts_only_after_dependency_is_present() {
    let mut ctx = Context::new();
    let started = Arc::new(AtomicBool::new(false));

    ctx.mount(NeedsTools {
        started: Arc::clone(&started),
    })
    .expect_err("still waiting on tools");
    assert!(!started.load(Ordering::SeqCst));

    ctx.mount(ProvideTools)
        .expect("provider has no inject deps");
    ctx.mount(NeedsTools {
        started: Arc::clone(&started),
    })
    .expect("tools is ready");
    assert!(started.load(Ordering::SeqCst));
}

#[test]
fn effect_disposers_run_newest_first_on_teardown() {
    let mut ctx = Context::new();
    let order = Arc::new(Mutex::new(Vec::new()));
    for tag in ["a", "b", "c"] {
        let order = Arc::clone(&order);
        ctx.effect(move || order.lock().expect("order").push(tag));
    }
    ctx.teardown();
    assert_eq!(*order.lock().expect("order"), ["c", "b", "a"]);
}

#[test]
fn on_stores_listeners_and_unregisters_on_teardown() {
    let mut ctx = Context::new();
    ctx.on("ready", || {}).unwrap();
    ctx.on("ready", || {}).unwrap();
    ctx.on("stop", || {}).unwrap();
    assert_eq!(ctx.listener_count("ready"), 2);
    assert_eq!(ctx.listener_count("stop"), 1);
    ctx.teardown();
    assert_eq!(ctx.listener_count("ready"), 0);
    assert_eq!(ctx.listener_count("stop"), 0);
}

#[test]
fn on_and_effect_share_one_reverse_disposer_stack() {
    let mut ctx = Context::new();
    let order = Arc::new(Mutex::new(Vec::new()));

    {
        let order = Arc::clone(&order);
        ctx.effect(move || order.lock().expect("order").push("effect-1"));
    }
    ctx.on("tick", || {}).unwrap();
    assert_eq!(ctx.listener_count("tick"), 1);
    {
        let order = Arc::clone(&order);
        ctx.effect(move || {
            order.lock().expect("order").push("effect-2");
        });
    }

    ctx.teardown();
    assert_eq!(ctx.listener_count("tick"), 0);
    assert_eq!(*order.lock().expect("order"), ["effect-2", "effect-1"]);
}

#[test]
fn drop_runs_disposers_in_reverse() {
    let order = Arc::new(Mutex::new(Vec::new()));
    {
        let mut ctx = Context::new();
        for tag in [1, 2, 3] {
            let order = Arc::clone(&order);
            ctx.effect(move || order.lock().expect("order").push(tag));
        }
    }
    assert_eq!(*order.lock().expect("order"), [3, 2, 1]);
}

#[test]
fn teardown_then_second_mount_can_reregister() {
    let mut ctx = Context::new();
    let order = Arc::new(Mutex::new(Vec::new()));
    let generations = Arc::new(AtomicUsize::new(0));

    ctx.mount(RecordEffect {
        order: Arc::clone(&order),
        tag: "first",
    })
    .unwrap();
    ctx.provide(keys::TOOLS, Marker("v1"));
    assert!(ctx.has(keys::TOOLS));
    assert_eq!(ctx.listener_count("first"), 1);
    ctx.teardown();
    assert!(!ctx.has(keys::TOOLS));
    assert_eq!(ctx.listener_count("first"), 0);
    assert_eq!(*order.lock().expect("order"), ["first"]);

    generations.fetch_add(1, Ordering::SeqCst);
    ctx.mount(RecordEffect {
        order: Arc::clone(&order),
        tag: "second",
    })
    .unwrap();
    ctx.provide(keys::TOOLS, Marker("v2"));
    ctx.on("second", || {}).unwrap();
    assert_eq!(ctx.tools::<Marker>().as_deref(), Some(&Marker("v2")));
    assert_eq!(ctx.listener_count("second"), 2);
    ctx.teardown();
    assert!(!ctx.has(keys::TOOLS));
    assert_eq!(ctx.listener_count("second"), 0);
    assert_eq!(*order.lock().expect("order"), ["first", "second"]);
    assert_eq!(generations.load(Ordering::SeqCst), 1);
}
