use std::error::Error;
use std::sync::{Arc, Mutex};

use hartevo_cordis::{
    Accumulate, BailOutcome, Context, CordisError, DispatchMode, Emit, EventKey, EventSchemaId,
    NonBail, Parallel, Serial, Service, Waterfall, keys,
};

const READY: EventKey<Emit, (), ()> = EventKey::new(EventSchemaId::new("test.ready.v1"), "ready");
const TICK: EventKey<Emit, String, ()> = EventKey::new(EventSchemaId::new("test.tick.v1"), "tick");
const POLICY: EventKey<Waterfall, i32, i32> =
    EventKey::new(EventSchemaId::new("test.policy.v1"), "policy");
const LOAD: EventKey<Parallel, String, ()> =
    EventKey::new(EventSchemaId::new("test.load.v1"), "load");
const SERIAL: EventKey<Serial, String, BailOutcome<String>> =
    EventKey::new(EventSchemaId::new("test.serial.v1"), "serial");
const ACCUMULATE: EventKey<Accumulate, String, String> =
    EventKey::new(EventSchemaId::new("test.accumulate.v1"), "accumulate");

#[derive(Debug, Clone, PartialEq, Eq)]
struct TestError(&'static str);

impl std::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for TestError {}

#[test]
fn event_names_lock_complete_typed_descriptors() {
    let mut ctx = Context::new();
    ctx.on(READY, || {}).unwrap();
    assert_eq!(ctx.listener_count(READY), 1);
    assert_eq!(ctx.event_mode(READY), Some(DispatchMode::Emit));
    assert_eq!(ctx.event_descriptor(READY), Some(READY.descriptor()));

    let conflicting =
        EventKey::<Waterfall, (), ()>::new(EventSchemaId::new("test.ready.v1"), "ready");
    assert!(matches!(
        ctx.on_waterfall(conflicting, |(), next| next(())),
        Err(CordisError::SchemaConflict { .. })
    ));
    assert_eq!(ctx.listener_count(READY), 1);
}

#[test]
fn emit_invokes_in_registration_order() {
    let mut ctx = Context::new();
    let order = Arc::new(Mutex::new(Vec::new()));
    for tag in ["a", "b", "c"] {
        let order = Arc::clone(&order);
        ctx.on_emit(TICK, move |payload| {
            order.lock().unwrap().push(format!("{payload}:{tag}"));
        })
        .unwrap();
    }
    ctx.emit(TICK, &"go".to_string()).unwrap();
    assert_eq!(*order.lock().unwrap(), ["go:a", "go:b", "go:c"]);
}

#[test]
fn waterfall_threads_and_short_circuits() {
    let mut ctx = Context::new();
    ctx.on_waterfall(
        POLICY,
        |value, next| {
            if value < 0 { value } else { next(value + 1) }
        },
    )
    .unwrap();
    ctx.on_waterfall(POLICY, |value, next| next(value * 10))
        .unwrap();
    assert_eq!(ctx.waterfall(POLICY, 1).unwrap(), 20);
    assert_eq!(ctx.waterfall(POLICY, -3).unwrap(), -3);
}

#[tokio::test]
async fn parallel_preserves_error_order_and_sources() {
    let mut ctx = Context::new();
    ctx.on_parallel(LOAD, |_| async { Err::<(), _>(TestError("first")) })
        .unwrap();
    ctx.on_parallel(LOAD, |_| async { Ok::<(), TestError>(()) })
        .unwrap();
    ctx.on_parallel(LOAD, |_| async { Err::<(), _>(TestError("third")) })
        .unwrap();

    let error = ctx.parallel(LOAD, "job".to_string()).await.unwrap_err();
    let CordisError::ParallelJoin { errors, .. } = error else {
        panic!("expected ordered parallel errors");
    };
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].event_source().as_error().to_string(), "first");
    assert_eq!(errors[1].event_source().as_error().to_string(), "third");
}

#[tokio::test]
async fn serial_receives_same_original_payload_and_bails_explicitly() {
    let mut ctx = Context::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    for tag in ["a", "b"] {
        let seen = Arc::clone(&seen);
        ctx.on_serial(SERIAL, move |value| {
            let seen = Arc::clone(&seen);
            async move {
                seen.lock()
                    .unwrap()
                    .push(format!("{}:{tag}", value.as_str()));
                Ok::<_, TestError>(BailOutcome::Continue(NonBail::False))
            }
        })
        .unwrap();
    }
    ctx.on_serial(SERIAL, |value| async move {
        Ok::<_, TestError>(BailOutcome::Bail(format!("{}:stop", value.as_str())))
    })
    .unwrap();

    assert_eq!(
        ctx.serial(SERIAL, "original".to_string()).await.unwrap(),
        BailOutcome::Bail("original:stop".to_string())
    );
    assert_eq!(*seen.lock().unwrap(), ["original:a", "original:b"]);
}

#[tokio::test]
async fn accumulate_preserves_old_hartevo_transform() {
    let mut ctx = Context::new();
    for tag in ["a", "b", "c"] {
        ctx.on_accumulate(ACCUMULATE, move |value| async move {
            Ok::<_, TestError>(format!("{value}{tag}"))
        })
        .unwrap();
    }
    assert_eq!(
        ctx.accumulate(ACCUMULATE, "x".to_string()).await.unwrap(),
        "xabc"
    );
}

#[test]
fn teardown_disposes_listener_handles_and_unlocks_registration_slots() {
    let mut ctx = Context::new();
    let handle = ctx.on(READY, || {}).unwrap();
    assert!(!handle.is_disposed());
    ctx.teardown();
    assert!(handle.is_disposed());
    assert_eq!(ctx.listener_count(READY), 0);
    assert_eq!(ctx.event_mode(READY), None);
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Marker(&'static str);

struct ProvideTools;

impl Service for ProvideTools {
    fn apply(self, ctx: &mut Context) -> Result<(), CordisError> {
        ctx.provide(keys::TOOLS, Marker("tools"))?;
        Ok(())
    }
}

#[test]
fn capability_lookups_remain_independent_of_typed_events() {
    let mut ctx = Context::new();
    ctx.mount(ProvideTools).unwrap();
    ctx.on(READY, || {}).unwrap();
    ctx.emit(READY, &()).unwrap();
    assert_eq!(ctx.tools::<Marker>().as_deref(), Some(&Marker("tools")));
}
