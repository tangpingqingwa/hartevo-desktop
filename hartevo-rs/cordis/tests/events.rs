use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use hartevo_cordis::{Context, CordisError, DispatchMode, Service, keys};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Marker(&'static str);

struct ProvideTools;

impl Service for ProvideTools {
    fn apply(self, ctx: &mut Context) {
        ctx.provide(keys::TOOLS, Marker("tools"));
    }
}

fn mode_conflict(err: &CordisError, name: &str, locked: DispatchMode, requested: DispatchMode) {
    assert_eq!(
        err,
        &CordisError::ModeConflict {
            name: name.to_string(),
            locked,
            requested,
        }
    );
}

#[test]
fn on_locks_emit_mode() {
    let mut ctx = Context::new();
    ctx.on("ready", || {}).unwrap();
    assert_eq!(ctx.event_mode("ready"), Some(DispatchMode::Emit));
    assert_eq!(ctx.listener_count("ready"), 1);
}

#[test]
fn mixing_registration_modes_on_the_same_name_errors() {
    let mut ctx = Context::new();
    ctx.on_emit("policy", |(): &()| {}).unwrap();
    mode_conflict(
        &ctx.on_waterfall("policy", |value: i32, next| next(value))
            .unwrap_err(),
        "policy",
        DispatchMode::Emit,
        DispatchMode::Waterfall,
    );
    mode_conflict(
        &ctx.on_parallel("policy", |(): ()| async move { Ok::<(), String>(()) })
            .unwrap_err(),
        "policy",
        DispatchMode::Emit,
        DispatchMode::Parallel,
    );
    mode_conflict(
        &ctx.on_serial("policy", |(): ()| async move { Ok::<(), String>(()) })
            .unwrap_err(),
        "policy",
        DispatchMode::Emit,
        DispatchMode::Serial,
    );
    assert_eq!(ctx.event_mode("policy"), Some(DispatchMode::Emit));
}

#[test]
fn mixing_dispatch_modes_on_the_same_name_errors() {
    let mut ctx = Context::new();
    ctx.emit("tick", &()).unwrap();
    assert_eq!(ctx.event_mode("tick"), Some(DispatchMode::Emit));
    mode_conflict(
        &ctx.waterfall("tick", ()).unwrap_err(),
        "tick",
        DispatchMode::Emit,
        DispatchMode::Waterfall,
    );
}

#[tokio::test]
async fn mixing_awaited_dispatch_modes_errors() {
    let mut ctx = Context::new();
    ctx.parallel("load", ()).await.unwrap();
    mode_conflict(
        &ctx.serial("load", ()).await.unwrap_err(),
        "load",
        DispatchMode::Parallel,
        DispatchMode::Serial,
    );
}

#[test]
fn emit_invokes_listeners_in_registration_order() {
    let mut ctx = Context::new();
    let order = Arc::new(Mutex::new(Vec::new()));
    for tag in ["a", "b", "c"] {
        let order = Arc::clone(&order);
        ctx.on_emit("tick", move |payload: &String| {
            order
                .lock()
                .expect("order")
                .push(format!("{payload}:{tag}"));
        })
        .unwrap();
    }
    ctx.emit("tick", &"go".to_string()).unwrap();
    assert_eq!(*order.lock().expect("order"), ["go:a", "go:b", "go:c"]);
}

#[test]
fn waterfall_threads_return_and_short_circuits_without_next() {
    let mut ctx = Context::new();
    let seen = Arc::new(Mutex::new(Vec::new()));

    {
        let seen = Arc::clone(&seen);
        ctx.on_waterfall("policy", move |value: i32, next| {
            seen.lock().expect("seen").push(("first", value));
            if value < 0 {
                return value;
            }
            next(value + 1)
        })
        .unwrap();
    }
    {
        let seen = Arc::clone(&seen);
        ctx.on_waterfall("policy", move |value: i32, next| {
            seen.lock().expect("seen").push(("second", value));
            next(value * 10)
        })
        .unwrap();
    }

    assert_eq!(ctx.waterfall("policy", 1).unwrap(), 20);
    assert_eq!(*seen.lock().expect("seen"), [("first", 1), ("second", 2)]);

    seen.lock().expect("seen").clear();
    assert_eq!(ctx.waterfall("policy", -3).unwrap(), -3);
    assert_eq!(*seen.lock().expect("seen"), [("first", -3)]);
}

#[tokio::test]
async fn parallel_joins_errors_without_dropping_others() {
    let mut ctx = Context::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));

    for (tag, fail) in [("a", true), ("b", false), ("c", true)] {
        let seen = Arc::clone(&seen);
        let started = Arc::clone(&started);
        let released = Arc::clone(&released);
        ctx.on_parallel("load", move |payload: String| {
            let seen = Arc::clone(&seen);
            let started = Arc::clone(&started);
            let released = Arc::clone(&released);
            async move {
                started.fetch_add(1, Ordering::SeqCst);
                while started.load(Ordering::SeqCst) < 3 {
                    tokio::task::yield_now().await;
                }
                seen.lock().expect("seen").push(format!("{payload}:{tag}"));
                released.fetch_add(1, Ordering::SeqCst);
                if fail {
                    Err(format!("{tag}-failed"))
                } else {
                    Ok(())
                }
            }
        })
        .unwrap();
    }

    let err = ctx
        .parallel("load", "job".to_string())
        .await
        .expect_err("joined listener errors");
    match err {
        CordisError::ParallelJoin { name, mut errors } => {
            assert_eq!(name, "load");
            errors.sort();
            assert_eq!(errors, ["a-failed", "c-failed"]);
        }
        other => panic!("expected ParallelJoin, got {other:?}"),
    }
    assert_eq!(released.load(Ordering::SeqCst), 3);
    let mut got = seen.lock().expect("seen").clone();
    got.sort();
    assert_eq!(got, ["job:a", "job:b", "job:c"]);
}

#[tokio::test]
async fn serial_awaits_in_registration_order_and_threads_return() {
    let mut ctx = Context::new();
    let order = Arc::new(Mutex::new(Vec::new()));
    for tag in ["a", "b", "c"] {
        let order = Arc::clone(&order);
        ctx.on_serial("pipe", move |value: String| {
            let order = Arc::clone(&order);
            async move {
                order.lock().expect("order").push(format!("{value}+{tag}"));
                Ok::<String, String>(format!("{value}{tag}"))
            }
        })
        .unwrap();
    }
    let out = ctx.serial("pipe", "x".to_string()).await.unwrap();
    assert_eq!(out, "xabc");
    assert_eq!(*order.lock().expect("order"), ["x+a", "xa+b", "xab+c"]);
}

#[test]
fn teardown_unregisters_listeners_and_unlocks_mode() {
    let mut ctx = Context::new();
    let called = Arc::new(AtomicUsize::new(0));
    {
        let called = Arc::clone(&called);
        ctx.on_emit("tick", move |(): &()| {
            called.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    }
    ctx.emit("tick", &()).unwrap();
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert_eq!(ctx.listener_count("tick"), 1);
    assert_eq!(ctx.event_mode("tick"), Some(DispatchMode::Emit));

    ctx.teardown();
    assert_eq!(ctx.listener_count("tick"), 0);
    assert_eq!(ctx.event_mode("tick"), None);

    ctx.emit("tick", &()).unwrap();
    assert_eq!(called.load(Ordering::SeqCst), 1);
}

#[test]
fn dispatch_after_teardown_is_noop_then_context_is_reusable() {
    let mut ctx = Context::new();
    let first = Arc::new(AtomicUsize::new(0));
    let second = Arc::new(AtomicUsize::new(0));
    {
        let first = Arc::clone(&first);
        ctx.on_emit("tick", move |(): &()| {
            first.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    }
    ctx.teardown();
    ctx.emit("tick", &()).unwrap();
    assert_eq!(first.load(Ordering::SeqCst), 0);

    {
        let second = Arc::clone(&second);
        ctx.on_emit("tick", move |(): &()| {
            second.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
    }
    ctx.emit("tick", &()).unwrap();
    assert_eq!(second.load(Ordering::SeqCst), 1);
    assert_eq!(first.load(Ordering::SeqCst), 0);
}

#[test]
fn capability_lookups_stay_get_provide_under_events() {
    let mut ctx = Context::new();
    ctx.mount(ProvideTools).unwrap();
    ctx.on("ready", || {}).unwrap();
    ctx.emit("ready", &()).unwrap();
    assert_eq!(
        ctx.get::<Marker>(keys::TOOLS).as_deref(),
        Some(&Marker("tools"))
    );
    assert_eq!(ctx.tools::<Marker>().as_deref(), Some(&Marker("tools")));
    assert!(ctx.get::<u32>(keys::TOOLS).is_none());
}
