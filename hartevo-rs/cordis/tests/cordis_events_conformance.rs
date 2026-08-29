use std::collections::BTreeMap;
use std::error::Error;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc as std_mpsc};
use std::time::{Duration, Instant};

use chrono::{TimeZone, Utc};
use futures_util::FutureExt;
use hartevo_cordis::{
    Accumulate, AgentsSurface, AuthorityScope, Bail, BailOutcome, Context, CordisError, CordisHost,
    DispatchMode, Emit, EventKey, EventOptions, EventReentry, EventSchemaId, KernelConsentState,
    ListenerHandle, NonBail, Parallel, RuntimeBinding, Serial, Waterfall, WaterfallFailure,
};
use tokio::sync::{mpsc, oneshot};

const EMIT_I32: EventKey<Emit, i32, ()> =
    EventKey::new(EventSchemaId::new("conformance.emit-i32.v1"), "same-name");
const ORDER: EventKey<Emit, (), ()> =
    EventKey::new(EventSchemaId::new("conformance.order.v1"), "order");
const DIRECT_REENTRY: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("conformance.direct-reentry.v1"),
    "direct-reentry",
);
const VIEW_REENTRY: EventKey<Emit, u8, ()> = EventKey::new(
    EventSchemaId::new("conformance.view-reentry.v1"),
    "view-reentry",
);
const FENCE_BLOCK: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("conformance.fence-block.v1"),
    "fence-block",
);
const FENCE_PROBE: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("conformance.fence-probe.v1"),
    "fence-probe",
);
const FENCE_CANDIDATE: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("conformance.fence-candidate.v1"),
    "fence-candidate",
);
const DROP_SOURCE: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("conformance.drop-source.v1"),
    "drop-source",
);
const DROP_TARGET: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("conformance.drop-target.v1"),
    "drop-target",
);
const SELF_TEARDOWN: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("conformance.self-teardown.v1"),
    "self-teardown",
);
const SELF_DROP: EventKey<Emit, u8, ()> =
    EventKey::new(EventSchemaId::new("conformance.self-drop.v1"), "self-drop");
const PANIC_CLEANUP: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("conformance.panic-cleanup.v1"),
    "panic-cleanup",
);
const SCOPED: EventKey<Emit, (), ()> =
    EventKey::new(EventSchemaId::new("conformance.scope.v1"), "scope");
const FALLIBLE_EMIT: EventKey<Emit, (), ()> = EventKey::new(
    EventSchemaId::new("conformance.fallible-emit.v1"),
    "fallible-emit",
);
const PARALLEL_KEY: EventKey<Parallel, (), ()> =
    EventKey::new(EventSchemaId::new("conformance.parallel.v1"), "parallel");
const SERIAL_EDGE: EventKey<Serial, (), BailOutcome<JsValue>> = EventKey::new(
    EventSchemaId::new("conformance.serial-edge.v1"),
    "serial-edge",
);
const BAIL_EDGE: EventKey<Bail, (), BailOutcome<JsValue>> =
    EventKey::new(EventSchemaId::new("conformance.bail-edge.v1"), "bail-edge");
const TRY_WATERFALL: EventKey<Waterfall, i32, Result<i32, WaterfallFailure>> = EventKey::new(
    EventSchemaId::new("conformance.try-waterfall.v1"),
    "try-waterfall",
);
const VIEW_WATERFALL: EventKey<Waterfall, i32, i32> = EventKey::new(
    EventSchemaId::new("conformance.view-waterfall.v1"),
    "view-waterfall",
);
const ACCUMULATE_FAIL: EventKey<Accumulate, i32, i32> = EventKey::new(
    EventSchemaId::new("conformance.accumulate-fail.v1"),
    "accumulate-fail",
);

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestEventError(&'static str);

impl std::fmt::Display for TestEventError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for TestEventError {}

struct RegisterOnDrop {
    events: EventReentry,
    calls: Arc<AtomicUsize>,
    completed: Option<std_mpsc::SyncSender<Result<u64, CordisError>>>,
}

impl Drop for RegisterOnDrop {
    fn drop(&mut self) {
        let calls = Arc::clone(&self.calls);
        let result = self
            .events
            .on_emit(DROP_TARGET, move |()| {
                calls.fetch_add(1, Ordering::SeqCst);
            })
            .map(|handle| handle.id());
        if let Some(completed) = self.completed.take() {
            let _ = completed.send(result);
        }
    }
}

struct InspectHandleOnDrop {
    handle: ListenerHandle,
    completed: Option<std_mpsc::SyncSender<bool>>,
}

struct PanicOnDrop {
    label: &'static str,
    dropped: Arc<Mutex<Vec<&'static str>>>,
}

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        self.dropped.lock().unwrap().push(self.label);
        std::panic::panic_any(self.label.to_string());
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else {
        "non-string panic payload".to_string()
    }
}

impl Drop for InspectHandleOnDrop {
    fn drop(&mut self) {
        let disposed = self.handle.is_disposed();
        if let Some(completed) = self.completed.take() {
            let _ = completed.send(disposed);
        }
    }
}

fn wait_for_event_gate_to_close(events: &EventReentry) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match events.emit(FENCE_PROBE, &()) {
            Err(CordisError::FiberContextMismatch { .. }) => return,
            Ok(()) if Instant::now() < deadline => std::thread::yield_now(),
            Ok(()) => panic!("event generation did not close before the bounded deadline"),
            Err(error) => panic!("unexpected event-gate error while closing: {error}"),
        }
    }
}

fn runtime_scope() -> AuthorityScope {
    AuthorityScope::new("tenant-a", "project-a", "mission-a", 1)
        .unwrap()
        .with_runtime(RuntimeBinding::new(1, None, None, "a".repeat(64)).unwrap())
}

#[derive(Debug, Clone)]
enum JsValue {
    Number(f64),
    Text(String),
    Bool(bool),
    Array(Vec<()>),
    Object(BTreeMap<String, bool>),
    Opaque,
}

fn assert_same_js_value(actual: &JsValue, expected: &JsValue) {
    match (actual, expected) {
        (JsValue::Number(actual), JsValue::Number(expected)) if expected.is_nan() => {
            assert!(actual.is_nan());
        }
        (JsValue::Number(actual), JsValue::Number(expected)) => {
            assert_eq!(actual.to_bits(), expected.to_bits());
        }
        (JsValue::Text(actual), JsValue::Text(expected)) => assert_eq!(actual, expected),
        (JsValue::Bool(actual), JsValue::Bool(expected)) => assert_eq!(actual, expected),
        (JsValue::Array(actual), JsValue::Array(expected)) => assert_eq!(actual, expected),
        (JsValue::Object(actual), JsValue::Object(expected)) => assert_eq!(actual, expected),
        (JsValue::Opaque, JsValue::Opaque) => {}
        _ => panic!("different explicit JS stand-ins: {actual:?} != {expected:?}"),
    }
}

fn assert_bailed(actual: BailOutcome<JsValue>, expected: &JsValue) {
    let BailOutcome::Bail(actual) = actual else {
        panic!("expected an explicit bail");
    };
    assert_same_js_value(&actual, expected);
}

#[test]
fn complete_descriptor_conflicts_are_zero_mutation_and_exact_rebuild_is_compatible() {
    let mut context = Context::new();
    let first = context.on_emit(EMIT_I32, |_: &i32| {}).unwrap();
    let descriptor = context.event_descriptor(EMIT_I32).unwrap();

    let wrong_mode = EventKey::<Waterfall, i32, i32>::new(EMIT_I32.schema_id(), EMIT_I32.name());
    let wrong_payload = EventKey::<Emit, String, ()>::new(EMIT_I32.schema_id(), EMIT_I32.name());
    let wrong_result = EventKey::<Emit, i32, String>::new(EMIT_I32.schema_id(), EMIT_I32.name());
    let wrong_schema = EventKey::<Emit, i32, ()>::new(
        EventSchemaId::new("conformance.emit-i32.v2"),
        EMIT_I32.name(),
    );

    assert!(matches!(
        context.on_waterfall(wrong_mode, |value, next| next(value)),
        Err(CordisError::SchemaConflict { .. })
    ));
    assert!(matches!(
        context.on_emit(wrong_payload, |_: &String| {}),
        Err(CordisError::SchemaConflict { .. })
    ));
    assert!(matches!(
        context.lock_event_key(wrong_result),
        Err(CordisError::SchemaConflict { .. })
    ));
    assert!(matches!(
        context.on_emit(wrong_schema, |_: &i32| {}),
        Err(CordisError::SchemaConflict { .. })
    ));

    assert_eq!(context.event_descriptor(EMIT_I32), Some(descriptor));
    assert_eq!(context.listener_count(EMIT_I32), 1);
    assert_eq!(context.event_mode(EMIT_I32), Some(DispatchMode::Emit));
    let rebuilt = EventKey::<Emit, i32, ()>::new(EMIT_I32.schema_id(), EMIT_I32.name());
    let second = context.on_emit(rebuilt, |_: &i32| {}).unwrap();
    assert_eq!(
        second.id(),
        first.id() + 1,
        "rejections must not consume ids"
    );
}

#[test]
fn mode_only_lock_is_an_active_zero_mutation_tombstone() {
    let mut context = Context::new();
    let first = context.on_emit(EMIT_I32, |_: &i32| {}).unwrap();
    let descriptor = context.event_descriptor(EMIT_I32);
    assert_eq!(
        context
            .lock_event(EMIT_I32.name(), DispatchMode::Emit)
            .unwrap_err(),
        CordisError::EventDescriptorRequired {
            name: EMIT_I32.name().to_string(),
        }
    );
    assert_eq!(context.event_descriptor(EMIT_I32), descriptor);
    assert_eq!(context.listener_count(EMIT_I32), 1);
    let second = context.on_emit(EMIT_I32, |_: &i32| {}).unwrap();
    assert_eq!(second.id(), first.id() + 1);
}

#[test]
fn prepend_is_lifo_front_ahead_of_append_and_handle_drop_does_not_unregister() {
    let mut context = Context::new();
    let order = Arc::new(Mutex::new(Vec::new()));
    for tag in ["append-a", "append-b"] {
        let order = Arc::clone(&order);
        let handle = context
            .on_emit(ORDER, move |()| order.lock().unwrap().push(tag))
            .unwrap();
        drop(handle);
    }
    for tag in ["prepend-a", "prepend-b"] {
        let order = Arc::clone(&order);
        context
            .on_emit_with_options(
                ORDER,
                EventOptions {
                    prepend: true,
                    global: false,
                },
                move |()| order.lock().unwrap().push(tag),
            )
            .unwrap();
    }
    context.emit(ORDER, &()).unwrap();
    assert_eq!(
        *order.lock().unwrap(),
        ["prepend-b", "prepend-a", "append-a", "append-b"]
    );
}

#[test]
fn targeted_dispatch_filters_isolates_but_shared_and_global_bypass() {
    let mut context = Context::new();
    let first = context.new_fiber().unwrap();
    let second = context.new_fiber().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));

    {
        let mut view = context.with_fiber(&first).isolate("first");
        let seen = Arc::clone(&seen);
        view.on_emit(SCOPED, move |()| seen.lock().unwrap().push("local"))
            .unwrap();
    }
    {
        let mut view = context
            .with_fiber(&first)
            .isolate("first")
            .share_label("team");
        let seen = Arc::clone(&seen);
        view.on_emit(SCOPED, move |()| seen.lock().unwrap().push("shared"))
            .unwrap();
    }
    {
        let mut view = context.with_fiber(&first).isolate("first");
        let seen = Arc::clone(&seen);
        view.on_emit_with_options(
            SCOPED,
            EventOptions {
                prepend: false,
                global: true,
            },
            move |()| seen.lock().unwrap().push("global"),
        )
        .unwrap();
    }
    {
        let mut target = context
            .with_fiber(&second)
            .isolate("second")
            .share_label("team");
        target.emit(SCOPED, &()).unwrap();
    }
    assert_eq!(*seen.lock().unwrap(), ["shared", "global"]);

    seen.lock().unwrap().clear();
    context.emit(SCOPED, &()).unwrap();
    assert_eq!(*seen.lock().unwrap(), ["local", "shared", "global"]);
}

#[test]
fn borrowed_context_view_applies_non_emit_options_and_once_before_reentry() {
    let mut context = Context::new();
    let fiber = context.new_fiber().unwrap();
    let mut view = context.with_fiber(&fiber).isolate("view");
    view.on_waterfall(VIEW_WATERFALL, |value, next| next(value * 10))
        .unwrap();
    view.once_waterfall_with_options(
        VIEW_WATERFALL,
        EventOptions {
            prepend: true,
            global: false,
        },
        |value, next| next(value + 1),
    )
    .unwrap();

    assert_eq!(view.waterfall(VIEW_WATERFALL, 1).unwrap(), 20);
    assert_eq!(view.waterfall(VIEW_WATERFALL, 1).unwrap(), 10);
}

#[test]
fn public_context_reentry_claims_once_before_recursive_dispatch() {
    let context = Context::new();
    let events = context.event_reentry().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_listener = Arc::clone(&calls);
    let nested = events.clone();
    let once = events
        .once_emit(DIRECT_REENTRY, move |()| {
            calls_for_listener.fetch_add(1, Ordering::SeqCst);
            nested.emit(DIRECT_REENTRY, &()).unwrap();
        })
        .unwrap();

    events.emit(DIRECT_REENTRY, &()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(once.is_disposed());
}

#[test]
fn public_context_reentry_fails_closed_after_its_context_drops() {
    let events = {
        let context = Context::new();
        context.event_reentry().unwrap()
    };
    assert!(matches!(
        events.on_emit(DIRECT_REENTRY, |()| {}),
        Err(CordisError::FiberContextMismatch { .. })
    ));
    assert!(matches!(
        events.emit(DIRECT_REENTRY, &()),
        Err(CordisError::FiberContextMismatch { .. })
    ));
}

#[test]
fn explicit_teardown_closes_then_drains_and_reopens_only_a_fresh_generation() {
    let mut context = Context::new();
    let events = context.event_reentry().unwrap();
    let entered = std_mpsc::sync_channel(1);
    let release = Arc::new(Barrier::new(2));
    let release_for_listener = Arc::clone(&release);
    events
        .on_emit(FENCE_BLOCK, move |()| {
            entered.0.send(()).unwrap();
            release_for_listener.wait();
        })
        .unwrap();

    let dispatched = std_mpsc::sync_channel(1);
    let dispatch_events = events.clone();
    std::thread::spawn(move || {
        let _ = dispatched.0.send(dispatch_events.emit(FENCE_BLOCK, &()));
    });
    entered
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("the winning event operation must enter its callback");

    let torn_down = std_mpsc::sync_channel(1);
    std::thread::spawn(move || {
        context.teardown();
        let _ = torn_down.0.send(context);
    });
    wait_for_event_gate_to_close(&events);

    let rejected_calls = Arc::new(AtomicUsize::new(0));
    let rejected_calls_for_listener = Arc::clone(&rejected_calls);
    assert!(matches!(
        events.on_emit(FENCE_CANDIDATE, move |()| {
            rejected_calls_for_listener.fetch_add(1, Ordering::SeqCst);
        }),
        Err(CordisError::FiberContextMismatch { .. })
    ));
    assert!(matches!(
        events.emit(FENCE_CANDIDATE, &()),
        Err(CordisError::FiberContextMismatch { .. })
    ));
    assert_eq!(rejected_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        torn_down.1.try_recv(),
        Err(std_mpsc::TryRecvError::Empty)
    ));

    release.wait();
    dispatched
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("the winning dispatch must settle")
        .unwrap();
    let context = torn_down
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("teardown must finish after the winning operation drains");
    assert_eq!(context.listener_count(FENCE_CANDIDATE), 0);
    assert!(matches!(
        events.emit(FENCE_CANDIDATE, &()),
        Err(CordisError::FiberContextMismatch { .. })
    ));
    let fresh = context.event_reentry().unwrap();
    let fresh_handle = fresh.on_emit(FENCE_CANDIDATE, |()| {}).unwrap();
    assert_eq!(fresh_handle.owner_uid(), context.root().uid());
}

#[test]
fn context_drop_waits_for_an_operation_that_linearized_first() {
    let context = Context::new();
    let events = context.event_reentry().unwrap();
    let entered = std_mpsc::sync_channel(1);
    let release = Arc::new(Barrier::new(2));
    let release_for_listener = Arc::clone(&release);
    events
        .on_emit(FENCE_BLOCK, move |()| {
            entered.0.send(()).unwrap();
            release_for_listener.wait();
        })
        .unwrap();

    let dispatched = std_mpsc::sync_channel(1);
    let dispatch_events = events.clone();
    std::thread::spawn(move || {
        let _ = dispatched.0.send(dispatch_events.emit(FENCE_BLOCK, &()));
    });
    entered
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("the winning event operation must enter its callback");

    let dropped = std_mpsc::sync_channel(1);
    std::thread::spawn(move || {
        drop(context);
        let _ = dropped.0.send(());
    });
    wait_for_event_gate_to_close(&events);
    assert!(matches!(
        dropped.1.try_recv(),
        Err(std_mpsc::TryRecvError::Empty)
    ));

    release.wait();
    dispatched
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("the winning dispatch must settle")
        .unwrap();
    dropped
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("Context Drop must finish after draining the winning operation");
    assert!(matches!(
        events.emit(FENCE_BLOCK, &()),
        Err(CordisError::FiberContextMismatch { .. })
    ));
}

#[test]
fn callback_reusable_teardown_is_a_preclose_noop_and_keeps_context_open() {
    let context = Arc::new(Mutex::new(Context::new()));
    let events = context.lock().unwrap().event_reentry().unwrap();
    let callback_context = Arc::clone(&context);
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = Arc::clone(&calls);
    let teardown_listener = events
        .on_emit(SELF_TEARDOWN, move |()| {
            callback_context.lock().unwrap().teardown();
            callback_calls.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();

    let dispatched = std_mpsc::sync_channel(1);
    let dispatch_events = events.clone();
    std::thread::spawn(move || {
        let _ = dispatched.0.send(dispatch_events.emit(SELF_TEARDOWN, &()));
    });
    dispatched
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("callback teardown must not wait for its own event permit")
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(context.lock().unwrap().listener_count(SELF_TEARDOWN), 1);

    let candidate_calls = Arc::new(AtomicUsize::new(0));
    let candidate_calls_for_listener = Arc::clone(&candidate_calls);
    let candidate = events
        .on_emit(FENCE_CANDIDATE, move |()| {
            candidate_calls_for_listener.fetch_add(1, Ordering::SeqCst);
        })
        .expect("the same generation must remain open after a callback teardown no-op");
    events.emit(FENCE_CANDIDATE, &()).unwrap();
    assert_eq!(candidate_calls.load(Ordering::SeqCst), 1);

    assert!(teardown_listener.dispose());
    assert!(candidate.dispose());
}

#[test]
fn callback_root_dispose_reports_busy_and_preserves_exact_context_state() {
    let mut context = Context::new();
    let root = context.root();
    let provider = context
        .provide("busy-provider", "original".to_string())
        .unwrap();
    let value_before = context.get::<String>("busy-provider").unwrap();
    let registrations_before = context.registration_count();
    let pending_before = context.pending_count();
    let context = Arc::new(Mutex::new(context));
    let events = context.lock().unwrap().event_reentry().unwrap();
    let callback_context = Arc::clone(&context);
    let callback_root = root.clone();
    let dispose_result = std_mpsc::sync_channel(1);
    let listener = events
        .on_emit(SELF_TEARDOWN, move |()| {
            let result = callback_context
                .lock()
                .unwrap()
                .dispose_fiber(&callback_root);
            dispose_result.0.send(result).unwrap();
        })
        .unwrap();
    let listener_count_before = context.lock().unwrap().listener_count(SELF_TEARDOWN);

    let dispatched = std_mpsc::sync_channel(1);
    let dispatch_events = events.clone();
    std::thread::spawn(move || {
        let _ = dispatched.0.send(dispatch_events.emit(SELF_TEARDOWN, &()));
    });
    assert!(
        !dispose_result
            .1
            .recv_timeout(Duration::from_secs(5))
            .expect("root disposal must return instead of waiting for its callback permit")
            .unwrap(),
        "Busy root disposal must report that no teardown completed"
    );
    dispatched
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("the root-dispose callback dispatch must settle")
        .unwrap();

    {
        let context = context.lock().unwrap();
        assert!(!root.is_disposed());
        assert_eq!(context.registration_count(), registrations_before);
        assert_eq!(context.pending_count(), pending_before);
        assert_eq!(context.listener_count(SELF_TEARDOWN), listener_count_before);
        let value_after = context.get::<String>("busy-provider").unwrap();
        assert!(Arc::ptr_eq(&value_before, &value_after));
    }
    assert_eq!(provider.generation(), 0);

    let candidate = events
        .on_emit(FENCE_CANDIDATE, |()| {})
        .expect("Busy root disposal must leave the exact event generation open");
    events.emit(FENCE_CANDIDATE, &()).unwrap();
    assert!(listener.dispose());
    assert!(candidate.dispose());

    let mut context = context.lock().unwrap();
    assert!(context.dispose_fiber(&root).unwrap());
    assert!(!context.has("busy-provider"));
    assert_eq!(context.registration_count(), 0);
    assert_eq!(context.listener_count(SELF_TEARDOWN), 0);
}

#[test]
fn callback_host_teardown_is_atomic_busy_across_host_and_context() {
    let mut host = CordisHost::boot(false).unwrap();
    let scope = runtime_scope();
    host.bind_domain_kernel_scope(
        scope.clone(),
        KernelConsentState::NotRequired,
        None,
        None,
        Utc.with_ymd_and_hms(2026, 8, 30, 0, 0, 0).unwrap(),
    )
    .unwrap();
    let permit = host.authorize_runtime(&scope).unwrap();
    let agents_before = host.context().agents::<AgentsSurface>().unwrap();
    let live_agents_before = agents_before.list();
    let registrations_before = host.context().registration_count();
    let pending_before = host.context().pending_count();
    let mounted_keys = host.mounted_keys();
    let host = Arc::new(Mutex::new(host));
    let events = host.lock().unwrap().context().event_reentry().unwrap();
    let callback_host = Arc::clone(&host);
    let callback_done = std_mpsc::sync_channel(1);
    let listener = events
        .on_emit(SELF_TEARDOWN, move |()| {
            callback_host.lock().unwrap().teardown();
            callback_done.0.send(()).unwrap();
        })
        .unwrap();
    let listener_count_before = host.lock().unwrap().context().listener_count(SELF_TEARDOWN);

    let dispatched = std_mpsc::sync_channel(1);
    let dispatch_events = events.clone();
    std::thread::spawn(move || {
        let _ = dispatched.0.send(dispatch_events.emit(SELF_TEARDOWN, &()));
    });
    callback_done
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("Host teardown must return Busy without waiting for its callback permit");
    dispatched
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("the Host teardown callback dispatch must settle")
        .unwrap();

    {
        let host = host.lock().unwrap();
        assert_eq!(host.bound_scope(), Some(&scope));
        assert_eq!(host.active_runtime_scope(), Some(&scope));
        assert_eq!(host.context().registration_count(), registrations_before);
        assert_eq!(host.context().pending_count(), pending_before);
        assert_eq!(
            host.context().listener_count(SELF_TEARDOWN),
            listener_count_before
        );
        assert!(mounted_keys.iter().all(|key| host.context().has(key)));
        let agents_after = host.context().agents::<AgentsSurface>().unwrap();
        assert!(Arc::ptr_eq(&agents_before, &agents_after));
        assert_eq!(agents_after.list(), live_agents_before);
    }

    let candidate = events
        .on_emit(FENCE_CANDIDATE, |()| {})
        .expect("Busy Host teardown must leave the exact Context generation open");
    events.emit(FENCE_CANDIDATE, &()).unwrap();
    assert!(listener.dispose());
    assert!(candidate.dispose());

    let completion = host.lock().unwrap().finish_runtime(permit).unwrap();
    completion.announce().unwrap();
    {
        let mut host = host.lock().unwrap();
        host.teardown();
        assert_eq!(host.bound_scope(), None);
        assert_eq!(host.active_runtime_scope(), None);
        assert!(mounted_keys.iter().all(|key| !host.context().has(key)));
        assert_eq!(host.context().registration_count(), 0);
    }
}

#[test]
fn nested_callback_can_take_and_drop_the_final_context_without_self_wait() {
    let context = Arc::new(Mutex::new(Some(Context::new())));
    let events = context
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .event_reentry()
        .unwrap();
    let blocking_entered = std_mpsc::sync_channel(1);
    let blocking_release = Arc::new(Barrier::new(2));
    let blocking_release_for_listener = Arc::clone(&blocking_release);
    let blocking = events
        .on_emit(FENCE_BLOCK, move |()| {
            blocking_entered.0.send(()).unwrap();
            blocking_release_for_listener.wait();
        })
        .unwrap();
    let nested = events.clone();
    let callback_context = Arc::clone(&context);
    let handle = events
        .on_emit(SELF_DROP, move |depth| {
            if *depth == 0 {
                nested.emit(SELF_DROP, &1).unwrap();
                return;
            }
            let context = callback_context
                .lock()
                .unwrap()
                .take()
                .expect("the nested callback owns the final Context");
            drop(context);
        })
        .unwrap();

    let blocking_dispatched = std_mpsc::sync_channel(1);
    let blocking_events = events.clone();
    std::thread::spawn(move || {
        let _ = blocking_dispatched
            .0
            .send(blocking_events.emit(FENCE_BLOCK, &()));
    });
    blocking_entered
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("the other-thread permit must enter before self-owning Context Drop");

    let dispatched = std_mpsc::sync_channel(1);
    let dispatch_events = events.clone();
    std::thread::spawn(move || {
        let _ = dispatched.0.send(dispatch_events.emit(SELF_DROP, &0));
    });
    wait_for_event_gate_to_close(&events);
    assert!(matches!(
        dispatched.1.try_recv(),
        Err(std_mpsc::TryRecvError::Empty)
    ));

    blocking_release.wait();
    blocking_dispatched
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("the other-thread operation must settle")
        .unwrap();
    dispatched
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("Context Drop must exclude both nested own permits and drain the other thread")
        .unwrap();

    assert!(context.lock().unwrap().is_none());
    assert!(blocking.is_disposed());
    assert!(handle.is_disposed());
    assert!(matches!(
        events.emit(SELF_DROP, &0),
        Err(CordisError::FiberContextMismatch { .. })
    ));
}

#[test]
fn root_teardown_drops_all_panicking_callbacks_then_reopens_a_fresh_generation() {
    let mut context = Context::new();
    let child = context.new_fiber().unwrap();
    let child_events = context.with_fiber(&child).event_reentry().unwrap();
    let normal = context
        .with_fiber(&child)
        .on_emit(DROP_TARGET, |()| {})
        .unwrap();
    let dropped = Arc::new(Mutex::new(Vec::new()));
    for label in ["root-first", "root-second"] {
        let probe = PanicOnDrop {
            label,
            dropped: Arc::clone(&dropped),
        };
        child_events
            .on_emit(PANIC_CLEANUP, move |()| {
                let _ = &probe;
            })
            .unwrap();
    }

    let torn_down = std_mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| context.teardown()))
            .expect_err("callback-capture destruction must preserve its first panic");
        let _ = torn_down.0.send((panic_message(panic.as_ref()), context));
    });
    let (message, mut context) = torn_down
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("root teardown must finish structural cleanup before propagating panic");

    assert_eq!(message, "root-first");
    assert_eq!(*dropped.lock().unwrap(), ["root-first", "root-second"]);
    assert!(child.is_disposed());
    assert!(normal.is_disposed());
    assert_eq!(context.registration_count(), 0);
    assert_eq!(context.listener_count(DROP_TARGET), 0);
    assert_eq!(context.listener_count(PANIC_CLEANUP), 0);
    assert!(matches!(
        child_events.on_emit(PANIC_CLEANUP, |()| {}),
        Err(CordisError::FiberContextMismatch { .. } | CordisError::FiberDisposed { .. })
    ));
    assert!(matches!(
        context.with_fiber(&child).event_reentry(),
        Err(CordisError::FiberContextMismatch { .. } | CordisError::FiberDisposed { .. })
    ));

    let fresh = context.event_reentry().unwrap();
    let fresh_listener = fresh.on_emit(PANIC_CLEANUP, |()| {}).unwrap();
    assert!(fresh_listener.dispose());
}

#[test]
fn child_cleanup_converts_first_destructor_panic_after_removing_every_record() {
    let mut context = Context::new();
    let child = context.new_fiber().unwrap();
    let child_events = context.with_fiber(&child).event_reentry().unwrap();
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let mut panicking_handles = Vec::new();
    for label in ["child-first", "child-second"] {
        let probe = PanicOnDrop {
            label,
            dropped: Arc::clone(&dropped),
        };
        panicking_handles.push(
            child_events
                .on_emit(PANIC_CLEANUP, move |()| {
                    let _ = &probe;
                })
                .unwrap(),
        );
    }
    let recorded = context
        .with_fiber(&child)
        .on_emit(PANIC_CLEANUP, |()| {})
        .unwrap();

    let cleaned = std_mpsc::sync_channel(1);
    let child_for_cleanup = child.clone();
    std::thread::spawn(move || {
        let result = context.dispose_fiber(&child_for_cleanup);
        let _ = cleaned.0.send((result, context));
    });
    let (result, mut context) = cleaned
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("child cleanup must convert callback destructor panic without stopping cleanup");

    assert!(matches!(
        result,
        Err(CordisError::CleanupPanicked { ref message }) if message == "child-first"
    ));
    assert_eq!(*dropped.lock().unwrap(), ["child-first", "child-second"]);
    assert!(child.is_disposed());
    assert!(recorded.is_disposed());
    assert!(panicking_handles.iter().all(ListenerHandle::is_disposed));
    assert_eq!(context.registration_count(), 0);
    assert_eq!(context.listener_count(PANIC_CLEANUP), 0);
    assert!(matches!(
        context.with_fiber(&child).event_reentry(),
        Err(CordisError::FiberContextMismatch { .. } | CordisError::FiberDisposed { .. })
    ));
    assert!(matches!(
        child_events.emit(PANIC_CLEANUP, &()),
        Err(CordisError::FiberDisposed { .. } | CordisError::FiberContextMismatch { .. })
    ));
}

#[test]
fn explicit_handle_disposal_drops_callback_capture_after_unlocking() {
    let context = Context::new();
    let events = context.event_reentry().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let completed = std_mpsc::sync_channel(1);
    let probe = RegisterOnDrop {
        events: events.clone(),
        calls: Arc::clone(&calls),
        completed: Some(completed.0),
    };
    let handle = events
        .on_emit(DROP_SOURCE, move |()| {
            let _ = &probe;
        })
        .unwrap();

    let disposed = std_mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = disposed.0.send(handle.dispose());
    });
    assert!(
        completed
            .1
            .recv_timeout(Duration::from_secs(5))
            .expect("callback destructor must re-enter registration without deadlock")
            .is_ok()
    );
    assert!(
        disposed
            .1
            .recv_timeout(Duration::from_secs(5))
            .expect("explicit listener disposal must finish")
    );
    assert_eq!(context.listener_count(DROP_SOURCE), 0);
    assert_eq!(context.listener_count(DROP_TARGET), 1);
    events.emit(DROP_TARGET, &()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn explicit_handle_disposal_commits_removal_before_destructor_panic() {
    let context = Context::new();
    let events = context.event_reentry().unwrap();
    let dropped = Arc::new(Mutex::new(Vec::new()));
    let probe = PanicOnDrop {
        label: "explicit-handle",
        dropped: Arc::clone(&dropped),
    };
    let handle = events
        .on_emit(PANIC_CLEANUP, move |()| {
            let _ = &probe;
        })
        .unwrap();
    let observed = handle.clone();

    let disposed = std_mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let panic = std::panic::catch_unwind(AssertUnwindSafe(|| handle.dispose()))
            .expect_err("the callback capture destructor must retain its panic");
        let _ = disposed.0.send(panic_message(panic.as_ref()));
    });
    assert_eq!(
        disposed
            .1
            .recv_timeout(Duration::from_secs(5))
            .expect("explicit disposal must not hold the event table while dropping callbacks"),
        "explicit-handle"
    );
    assert_eq!(*dropped.lock().unwrap(), ["explicit-handle"]);
    assert!(observed.is_disposed());
    assert_eq!(context.listener_count(PANIC_CLEANUP), 0);
}

#[test]
fn owner_cleanup_drops_callback_capture_after_unlocking() {
    let mut context = Context::new();
    let root_events = context.event_reentry().unwrap();
    let child = context.new_fiber().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let completed = std_mpsc::sync_channel(1);
    let probe = RegisterOnDrop {
        events: root_events.clone(),
        calls: Arc::clone(&calls),
        completed: Some(completed.0),
    };
    context
        .with_fiber(&child)
        .on_emit(DROP_SOURCE, move |()| {
            let _ = &probe;
        })
        .unwrap();

    let cleaned = std_mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = context.dispose_fiber(&child);
        let _ = cleaned.0.send((result, context));
    });
    assert!(
        completed
            .1
            .recv_timeout(Duration::from_secs(5))
            .expect("owner cleanup destructor must re-enter registration without deadlock")
            .is_ok()
    );
    let (result, context) = cleaned
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("owner cleanup must finish");
    assert!(result.unwrap());
    assert_eq!(context.listener_count(DROP_SOURCE), 0);
    assert_eq!(context.listener_count(DROP_TARGET), 1);
    root_events.emit(DROP_TARGET, &()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn context_teardown_drops_callback_capture_after_clearing_under_unlock() {
    let mut context = Context::new();
    let events = context.event_reentry().unwrap();
    let inspected = events.on_emit(DROP_TARGET, |()| {}).unwrap();
    let completed = std_mpsc::sync_channel(1);
    let probe = InspectHandleOnDrop {
        handle: inspected.clone(),
        completed: Some(completed.0),
    };
    events
        .on_emit(DROP_SOURCE, move |()| {
            let _ = &probe;
        })
        .unwrap();

    let torn_down = std_mpsc::sync_channel(1);
    std::thread::spawn(move || {
        context.teardown();
        let _ = torn_down.0.send(context);
    });
    assert!(
        completed
            .1
            .recv_timeout(Duration::from_secs(5))
            .expect("teardown destructor must re-enter the event table without deadlock")
    );
    let context = torn_down
        .1
        .recv_timeout(Duration::from_secs(5))
        .expect("Context teardown must finish");
    assert!(inspected.is_disposed());
    assert_eq!(context.listener_count(DROP_SOURCE), 0);
    assert_eq!(context.listener_count(DROP_TARGET), 0);
}

#[test]
fn borrowed_view_reentry_registers_into_next_snapshot_and_stays_owner_bound() {
    let mut context = Context::new();
    let fiber = context.new_fiber().unwrap();
    let events = {
        let view = context.with_fiber(&fiber).isolate("callback");
        view.event_reentry().unwrap()
    };
    let order = Arc::new(Mutex::new(Vec::new()));
    let nested_handle = Arc::new(Mutex::new(None));
    let order_for_outer = Arc::clone(&order);
    let nested_handle_for_outer = Arc::clone(&nested_handle);
    let nested_events = events.clone();
    let once = events
        .once_emit(VIEW_REENTRY, move |depth| {
            order_for_outer.lock().unwrap().push(("outer", *depth));
            let order_for_nested = Arc::clone(&order_for_outer);
            let handle = nested_events
                .on_emit(VIEW_REENTRY, move |nested_depth| {
                    order_for_nested
                        .lock()
                        .unwrap()
                        .push(("nested", *nested_depth));
                })
                .unwrap();
            *nested_handle_for_outer.lock().unwrap() = Some(handle);
            nested_events.emit(VIEW_REENTRY, &1).unwrap();
        })
        .unwrap();

    events.emit(VIEW_REENTRY, &0).unwrap();
    assert_eq!(*order.lock().unwrap(), [("outer", 0), ("nested", 1)]);
    assert!(once.is_disposed());
    let handle = nested_handle.lock().unwrap().clone().unwrap();
    assert_eq!(handle.owner_uid(), fiber.uid());
    assert_eq!(context.listener_count(VIEW_REENTRY), 1);

    events.emit(VIEW_REENTRY, &2).unwrap();
    assert_eq!(
        *order.lock().unwrap(),
        [("outer", 0), ("nested", 1), ("nested", 2)]
    );

    let mut foreign = Context::new();
    let foreign_error = foreign
        .with_fiber(&fiber)
        .event_reentry()
        .expect_err("a foreign Context must not mint an event capability");
    assert_eq!(
        foreign_error,
        CordisError::FiberContextMismatch { uid: fiber.uid() }
    );

    assert!(context.dispose_fiber(&fiber).unwrap());
    assert!(handle.is_disposed());
    assert_eq!(context.listener_count(VIEW_REENTRY), 0);
    assert_eq!(
        events.on_emit(VIEW_REENTRY, |_| {}).unwrap_err(),
        CordisError::FiberDisposed { uid: fiber.uid() }
    );
    assert_eq!(
        events.emit(VIEW_REENTRY, &3).unwrap_err(),
        CordisError::FiberDisposed { uid: fiber.uid() }
    );
    assert_eq!(
        *order.lock().unwrap(),
        [("outer", 0), ("nested", 1), ("nested", 2)]
    );
    assert_eq!(context.listener_count(VIEW_REENTRY), 0);
}

#[test]
fn self_removal_is_lock_free_and_affects_only_the_next_snapshot() {
    let mut context = Context::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let handle_slot = Arc::new(Mutex::new(None));
    let calls_for_listener = Arc::clone(&calls);
    let slot_for_listener = Arc::clone(&handle_slot);
    let handle = context
        .on_emit(ORDER, move |()| {
            calls_for_listener.fetch_add(1, Ordering::SeqCst);
            assert!(
                slot_for_listener
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(hartevo_cordis::ListenerHandle::dispose)
            );
        })
        .unwrap();
    *handle_slot.lock().unwrap() = Some(handle);
    context.emit(ORDER, &()).unwrap();
    context.emit(ORDER, &()).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn disposed_fiber_cannot_register_a_listener() {
    let mut context = Context::new();
    let fiber = context.new_fiber().unwrap();
    assert!(context.dispose_fiber(&fiber).unwrap());
    let mut view = context.with_fiber(&fiber);
    assert!(matches!(
        view.on_emit(ORDER, |()| {}),
        Err(CordisError::FiberDisposed { .. } | CordisError::FiberContextMismatch { .. })
    ));
}

#[test]
fn fallible_emit_stops_first_error_preserves_source_and_panics_stay_panics() {
    let mut context = Context::new();
    let later = Arc::new(AtomicUsize::new(0));
    context
        .try_on_emit(FALLIBLE_EMIT, |()| Err(TestEventError("emit-source")))
        .unwrap();
    {
        let later = Arc::clone(&later);
        context
            .on_emit(FALLIBLE_EMIT, move |()| {
                later.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();
    }
    let error = context.emit(FALLIBLE_EMIT, &()).unwrap_err();
    let cloned = error.clone();
    assert_eq!(
        cloned
            .source()
            .unwrap()
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<TestEventError>(),
        Some(&TestEventError("emit-source"))
    );
    let CordisError::Emit { error, .. } = cloned else {
        panic!("expected typed Emit error");
    };
    assert_eq!(
        error
            .event_source()
            .as_error()
            .downcast_ref::<TestEventError>(),
        Some(&TestEventError("emit-source"))
    );
    assert_eq!(later.load(Ordering::SeqCst), 0);

    let panic_key = EventKey::<Emit, (), ()>::new(
        EventSchemaId::new("conformance.emit-panic.v1"),
        "emit-panic",
    );
    context
        .on_emit(panic_key, |()| panic!("event panic"))
        .unwrap();
    assert!(std::panic::catch_unwind(AssertUnwindSafe(|| context.emit(panic_key, &()))).is_err());
}

#[tokio::test]
async fn parallel_starts_all_drains_all_and_aggregates_snapshot_order() {
    let mut context = Context::new();
    let (started_tx, mut started_rx) = mpsc::unbounded_channel();
    let mut releases = Vec::new();
    for (index, label) in [(0, "first"), (1, "second"), (2, "third")] {
        let (release_tx, release_rx) = oneshot::channel();
        releases.push(Some(release_tx));
        let release_rx = Arc::new(Mutex::new(Some(release_rx)));
        let started_tx = started_tx.clone();
        context
            .on_parallel(PARALLEL_KEY, move |()| {
                let release_rx = Arc::clone(&release_rx);
                let started_tx = started_tx.clone();
                let release_rx = release_rx.lock().unwrap().take().unwrap();
                async move {
                    started_tx.send(index).unwrap();
                    release_rx.await.unwrap();
                    Err::<(), _>(TestEventError(label))
                }
            })
            .unwrap();
    }
    drop(started_tx);
    let controller = async move {
        let mut started = Vec::new();
        while let Some(index) = started_rx.recv().await {
            started.push(index);
            if started.len() == 3 {
                break;
            }
        }
        assert_eq!(started.len(), 3, "all listeners must start before release");
        for index in [2, 1, 0] {
            releases[index].take().unwrap().send(()).unwrap();
        }
    };
    let (result, ()) = tokio::join!(context.parallel(PARALLEL_KEY, ()), controller);
    let error = result.unwrap_err();
    let cloned_error = error.clone();
    assert_eq!(
        cloned_error
            .source()
            .unwrap()
            .source()
            .unwrap()
            .source()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<TestEventError>(),
        Some(&TestEventError("first"))
    );
    let CordisError::ParallelJoin { errors, .. } = error else {
        panic!("expected aggregate");
    };
    let labels: Vec<_> = errors
        .iter()
        .map(|error| error.event_source().as_error().to_string())
        .collect();
    assert_eq!(labels, ["first", "second", "third"]);
    let cloned = errors.clone();
    assert!(cloned.iter().all(|error| {
        error
            .event_source()
            .as_error()
            .downcast_ref::<TestEventError>()
            .is_some()
    }));
}

#[tokio::test]
async fn parallel_drains_remaining_listener_before_resuming_panic() {
    let mut context = Context::new();
    let drained = Arc::new(AtomicBool::new(false));
    context
        .on_parallel(PARALLEL_KEY, |()| async move {
            panic!("parallel panic");
            #[allow(unreachable_code)]
            Ok::<(), TestEventError>(())
        })
        .unwrap();
    {
        let drained = Arc::clone(&drained);
        context
            .on_parallel(PARALLEL_KEY, move |()| {
                let drained = Arc::clone(&drained);
                async move {
                    drained.store(true, Ordering::SeqCst);
                    Ok::<(), TestEventError>(())
                }
            })
            .unwrap();
    }
    let outcome = AssertUnwindSafe(context.parallel(PARALLEL_KEY, ()))
        .catch_unwind()
        .await;
    assert!(outcome.is_err());
    assert!(drained.load(Ordering::SeqCst));
}

#[tokio::test]
async fn serial_and_bail_use_explicit_non_bails_for_every_js_edge() {
    let edges = [
        JsValue::Number(0.0),
        JsValue::Number(-0.0),
        JsValue::Number(f64::NAN),
        JsValue::Text(String::new()),
        JsValue::Bool(true),
        JsValue::Array(Vec::new()),
        JsValue::Object(BTreeMap::new()),
        JsValue::Opaque,
    ];
    for edge in edges {
        let mut serial = Context::new();
        for non_bail in [NonBail::Undefined, NonBail::Null, NonBail::False] {
            serial
                .on_serial(SERIAL_EDGE, move |_| async move {
                    Ok::<_, TestEventError>(BailOutcome::Continue(non_bail))
                })
                .unwrap();
        }
        let edge_for_serial = edge.clone();
        serial
            .on_serial(SERIAL_EDGE, move |_| {
                let edge = edge_for_serial.clone();
                async move { Ok::<_, TestEventError>(BailOutcome::Bail(edge)) }
            })
            .unwrap();
        let serial_later = Arc::new(AtomicUsize::new(0));
        {
            let serial_later = Arc::clone(&serial_later);
            serial
                .on_serial(SERIAL_EDGE, move |_| {
                    let serial_later = Arc::clone(&serial_later);
                    async move {
                        serial_later.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, TestEventError>(BailOutcome::Continue(NonBail::Undefined))
                    }
                })
                .unwrap();
        }
        assert_bailed(serial.serial(SERIAL_EDGE, ()).await.unwrap(), &edge);
        assert_eq!(serial_later.load(Ordering::SeqCst), 0);

        let mut bail = Context::new();
        for non_bail in [NonBail::Undefined, NonBail::Null, NonBail::False] {
            bail.on_bail(BAIL_EDGE, move |()| BailOutcome::Continue(non_bail))
                .unwrap();
        }
        let edge_for_bail = edge.clone();
        bail.on_bail(BAIL_EDGE, move |()| {
            BailOutcome::Bail(edge_for_bail.clone())
        })
        .unwrap();
        let bail_later = Arc::new(AtomicUsize::new(0));
        {
            let bail_later = Arc::clone(&bail_later);
            bail.on_bail(BAIL_EDGE, move |()| {
                bail_later.fetch_add(1, Ordering::SeqCst);
                BailOutcome::Continue(NonBail::Undefined)
            })
            .unwrap();
        }
        assert_bailed(bail.bail(BAIL_EDGE, &()).unwrap(), &edge);
        assert_eq!(bail_later.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn empty_listener_sets_keep_each_modes_identity_result() {
    let mut context = Context::new();
    context.emit(ORDER, &()).unwrap();
    context.parallel(PARALLEL_KEY, ()).await.unwrap();
    assert!(matches!(
        context.serial(SERIAL_EDGE, ()).await.unwrap(),
        BailOutcome::Continue(NonBail::Undefined)
    ));
    assert!(matches!(
        context.bail(BAIL_EDGE, &()).unwrap(),
        BailOutcome::Continue(NonBail::Undefined)
    ));
    assert_eq!(context.waterfall(VIEW_WATERFALL, 7).unwrap(), 7);
    assert_eq!(context.accumulate(ACCUMULATE_FAIL, 9).await.unwrap(), 9);
}

#[tokio::test]
async fn serial_awaits_in_order_then_stops_on_first_source_error() {
    let mut context = Context::new();
    let (started_tx, started_rx) = oneshot::channel();
    let started_tx = Arc::new(Mutex::new(Some(started_tx)));
    let (release_tx, release_rx) = oneshot::channel();
    let release_rx = Arc::new(Mutex::new(Some(release_rx)));
    context
        .on_serial(SERIAL_EDGE, move |_| {
            let started_tx = started_tx.lock().unwrap().take().unwrap();
            let release_rx = release_rx.lock().unwrap().take().unwrap();
            async move {
                started_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok::<_, TestEventError>(BailOutcome::Continue(NonBail::Undefined))
            }
        })
        .unwrap();
    context
        .on_serial(SERIAL_EDGE, |_| async move {
            Err::<BailOutcome<JsValue>, _>(TestEventError("serial-source"))
        })
        .unwrap();
    let later = Arc::new(AtomicUsize::new(0));
    {
        let later = Arc::clone(&later);
        context
            .on_serial(SERIAL_EDGE, move |_| {
                let later = Arc::clone(&later);
                async move {
                    later.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TestEventError>(BailOutcome::Continue(NonBail::Undefined))
                }
            })
            .unwrap();
    }
    let later_during_gate = Arc::clone(&later);
    let controller = async move {
        started_rx.await.unwrap();
        assert_eq!(later_during_gate.load(Ordering::SeqCst), 0);
        release_tx.send(()).unwrap();
    };

    let (result, ()) = tokio::join!(context.serial(SERIAL_EDGE, ()), controller);

    let CordisError::Serial { error, .. } = result.unwrap_err() else {
        panic!("expected typed Serial error");
    };
    assert_eq!(
        error
            .event_source()
            .as_error()
            .downcast_ref::<TestEventError>(),
        Some(&TestEventError("serial-source"))
    );
    assert_eq!(later.load(Ordering::SeqCst), 0);
}

#[test]
fn fallible_bail_stops_later_listener_and_preserves_source() {
    let mut context = Context::new();
    context
        .try_on_bail(BAIL_EDGE, |()| Err(TestEventError("bail-source")))
        .unwrap();
    let later = Arc::new(AtomicUsize::new(0));
    {
        let later = Arc::clone(&later);
        context
            .on_bail(BAIL_EDGE, move |()| {
                later.fetch_add(1, Ordering::SeqCst);
                BailOutcome::Continue(NonBail::Undefined)
            })
            .unwrap();
    }

    let CordisError::Bail { error, .. } = context.bail(BAIL_EDGE, &()).unwrap_err() else {
        panic!("expected typed Bail error");
    };
    assert_eq!(
        error
            .event_source()
            .as_error()
            .downcast_ref::<TestEventError>(),
        Some(&TestEventError("bail-source"))
    );
    assert_eq!(later.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn accumulate_threads_until_first_source_error_and_stops() {
    let mut context = Context::new();
    context
        .on_accumulate(ACCUMULATE_FAIL, |value| async move {
            Ok::<_, TestEventError>(value + 1)
        })
        .unwrap();
    context
        .on_accumulate(ACCUMULATE_FAIL, |_| async move {
            Err::<i32, _>(TestEventError("accumulate-source"))
        })
        .unwrap();
    let later = Arc::new(AtomicUsize::new(0));
    {
        let later = Arc::clone(&later);
        context
            .on_accumulate(ACCUMULATE_FAIL, move |value| {
                let later = Arc::clone(&later);
                async move {
                    later.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TestEventError>(value)
                }
            })
            .unwrap();
    }

    let CordisError::Accumulate { error, .. } =
        context.accumulate(ACCUMULATE_FAIL, 1).await.unwrap_err()
    else {
        panic!("expected typed Accumulate error");
    };
    assert_eq!(
        error
            .event_source()
            .as_error()
            .downcast_ref::<TestEventError>(),
        Some(&TestEventError("accumulate-source"))
    );
    assert_eq!(later.load(Ordering::SeqCst), 0);
}

#[test]
fn fallible_waterfall_preserves_inner_attribution_through_outer_question_marks() {
    let mut context = Context::new();
    context
        .try_on_waterfall(TRY_WATERFALL, |value, next| Ok(next(value + 1)? + 1))
        .unwrap();
    context
        .try_on_waterfall(TRY_WATERFALL, |value, next| Ok(next(value + 1)? + 1))
        .unwrap();
    let inner = context
        .try_on_waterfall(TRY_WATERFALL, |_, _| {
            Err(WaterfallFailure::source(TestEventError("inner")))
        })
        .unwrap();
    let error = context.try_waterfall(TRY_WATERFALL, 1).unwrap_err();
    let cloned = error.clone();
    let CordisError::Waterfall { error, .. } = cloned else {
        panic!("expected attributed Waterfall error");
    };
    assert_eq!(error.listener_id(), inner.id());
    assert_eq!(
        error
            .event_source()
            .as_error()
            .downcast_ref::<TestEventError>(),
        Some(&TestEventError("inner"))
    );

    let empty = EventKey::<Waterfall, i32, Result<i32, WaterfallFailure>>::new(
        EventSchemaId::new("conformance.empty-waterfall.v1"),
        "empty-waterfall",
    );
    assert_eq!(Context::new().try_waterfall(empty, 7).unwrap(), 7);
}
