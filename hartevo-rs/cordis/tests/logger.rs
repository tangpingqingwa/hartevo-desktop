use std::sync::{Arc, Mutex, MutexGuard};

use hartevo_cordis::{
    CallableService, ConfigValue, Context, LoggerExportError, LoggerExporter, LoggerLevel,
    LoggerMessage, ServiceCall, ServiceOptions,
};
use serde_json::{Value, json};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn capture_all(context: &mut Context) -> Arc<Mutex<Vec<LoggerMessage>>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    context.logger_exporter(
        LoggerExporter::infallible(move |message| lock(&sink).push(message.clone()))
            .with_default_level(LoggerLevel::Debug),
    );
    captured
}

fn first_argument_text(message: &LoggerMessage) -> Option<&str> {
    message.arguments().first().and_then(Value::as_str)
}

#[test]
fn bounded_buffer_stays_in_place_and_chronological() {
    let context = Context::new();
    let service = context.logger_service();
    let buffer = service.buffer();
    buffer.set_capacity(2);

    context.logger().info("one");
    context.logger().info("two");
    context.logger().info("three");
    assert!(buffer.same_storage(&service.buffer()));
    assert_eq!(
        buffer
            .snapshot()
            .iter()
            .filter_map(first_argument_text)
            .collect::<Vec<_>>(),
        ["two", "three"]
    );

    buffer.set_capacity(1);
    context.logger().info("four");
    assert_eq!(
        buffer
            .snapshot()
            .iter()
            .filter_map(first_argument_text)
            .collect::<Vec<_>>(),
        ["four"]
    );

    buffer.set_capacity(0);
    context.logger().info("five");
    assert!(buffer.is_empty());
    assert!(buffer.same_storage(&service.buffer()));
}

#[test]
fn exporters_filter_and_dispose_independently() {
    let mut context = Context::new();
    let first = Arc::new(Mutex::new(Vec::new()));
    let first_sink = Arc::clone(&first);
    let first_handle = context.logger_exporter(
        LoggerExporter::infallible(move |message| lock(&first_sink).push(message.clone()))
            .with_default_level(LoggerLevel::Debug),
    );
    let second = Arc::new(Mutex::new(Vec::new()));
    let second_sink = Arc::clone(&second);
    let second_handle = context.logger_exporter(
        LoggerExporter::infallible(move |message| lock(&second_sink).push(message.clone()))
            .with_default_level(LoggerLevel::Warn)
            .with_level("chat", LoggerLevel::Debug),
    );

    assert!(first_handle.dispose());
    context.logger().debug("filtered");
    context.logger_named("chat").debug("included");
    assert!(lock(&first).is_empty());
    assert_eq!(lock(&second).len(), 1);
    assert_eq!(lock(&second)[0].name(), "chat");

    assert!(second_handle.dispose());
    assert!(!second_handle.dispose());
    context.logger_named("chat").error("after-dispose");
    assert_eq!(lock(&second).len(), 1);
}

#[derive(Debug)]
struct LoggingService {
    message: &'static str,
    nested: Option<&'static str>,
}

impl CallableService<()> for LoggingService {
    type Output = ();

    fn invoke(&self, call: ServiceCall<'_>, (): ()) -> Self::Output {
        if let Some(nested) = self.nested {
            call.service::<Self>(nested)
                .expect("nested logger fixture must exist")
                .call(());
        }
        call.logger().debug(self.message);
    }
}

#[test]
fn logger_names_follow_explicit_intercept_and_innermost_service_order() {
    let mut context = Context::new();
    let captured = capture_all(&mut context);

    context.logger().debug("root");
    context.logger_named("ExplicitName").debug("explicit");
    let root = context.root();
    context
        .with_fiber(&root)
        .intercept(
            "logger",
            ConfigValue::object([("name", "caller-override".into())]),
        )
        .logger_named("exact")
        .unwrap()
        .debug("explicit-over-intercept");

    context
        .provide_service(
            "innerService",
            LoggingService {
                message: "inner",
                nested: None,
            },
            ServiceOptions::shadowed(),
        )
        .unwrap();
    context
        .provide_service(
            "outerService",
            LoggingService {
                message: "outer",
                nested: Some("innerService"),
            },
            ServiceOptions::shadowed(),
        )
        .unwrap();
    context
        .service::<LoggingService>("outerService")
        .unwrap()
        .call(());

    let messages = lock(&captured);
    let observed = messages
        .iter()
        .map(|message| (message.name(), first_argument_text(message).unwrap()))
        .collect::<Vec<_>>();
    assert_eq!(
        observed,
        [
            ("root", "root"),
            ("ExplicitName", "explicit"),
            ("exact", "explicit-over-intercept"),
            ("inner-service", "inner"),
            ("outer-service", "outer"),
        ]
    );
    drop(messages);

    lock(&captured).clear();
    context
        .with_fiber(&root)
        .intercept(
            "logger",
            ConfigValue::object([("name", "caller-override".into())]),
        )
        .service::<LoggingService>("outerService")
        .unwrap()
        .call(());
    assert_eq!(
        lock(&captured)
            .iter()
            .map(LoggerMessage::name)
            .collect::<Vec<_>>(),
        ["caller-override", "caller-override"]
    );
}

#[test]
fn no_shadow_service_uses_its_service_caller_origin() {
    let mut context = Context::new();
    let captured = capture_all(&mut context);
    context
        .provide_service(
            "no-shadow-inner",
            LoggingService {
                message: "inner",
                nested: None,
            },
            ServiceOptions::no_shadow(),
        )
        .unwrap();
    context
        .provide_service(
            "shadowed-outer",
            LoggingService {
                message: "outer",
                nested: Some("no-shadow-inner"),
            },
            ServiceOptions::shadowed(),
        )
        .unwrap();

    context
        .service::<LoggingService>("shadowed-outer")
        .unwrap()
        .call(());
    assert_eq!(
        lock(&captured)
            .iter()
            .map(LoggerMessage::name)
            .collect::<Vec<_>>(),
        ["shadowed-outer", "shadowed-outer"]
    );
}

#[test]
fn exporter_failure_is_observable_without_stopping_other_exporters() {
    let mut context = Context::new();
    context.logger_exporter(
        LoggerExporter::new(|_| Err(LoggerExportError::new("sink unavailable")))
            .with_default_level(LoggerLevel::Debug),
    );
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let delivered_sink = Arc::clone(&delivered);
    context.logger_exporter(
        LoggerExporter::infallible(move |message| lock(&delivered_sink).push(message.clone()))
            .with_default_level(LoggerLevel::Debug),
    );

    let report = context
        .logger()
        .info_args([json!("hello"), json!({ "account": 7 })]);
    assert_eq!(report.exported(), 1);
    assert_eq!(report.failures().len(), 1);
    assert_eq!(report.failures()[0].detail(), "sink unavailable");
    assert_eq!(lock(&delivered).len(), 1);
    assert_eq!(context.logger_service().failures(), report.failures());

    let debug = format!("{:?}", &lock(&delivered)[0]);
    assert!(debug.contains("argument_count"));
    assert!(!debug.contains("account"));
}

#[test]
fn exporter_registration_is_removed_by_its_fiber_teardown_once() {
    let mut context = Context::new();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let root = context.root();
    let child = context.child_fiber(&root).unwrap();
    let handle = context.with_fiber(&child).logger_exporter(
        LoggerExporter::infallible(move |message| lock(&sink).push(message.clone()))
            .with_default_level(LoggerLevel::Debug),
    );

    context.logger().info("before");
    assert_eq!(lock(&captured).len(), 1);
    assert!(context.dispose_fiber(&child).unwrap());
    assert!(handle.is_disposed());
    context.logger().info("after");
    assert_eq!(lock(&captured).len(), 1);
    assert!(!handle.dispose());
}

#[test]
fn logger_level_intercept_enables_debug_buffering_with_trusted_metadata() {
    let mut context = Context::new();
    let buffer = context.logger_service().buffer();
    buffer.set_capacity(4);
    let root = context.root();

    let filtered = context.logger().debug("filtered");
    assert!(!filtered.buffered());
    let included = context
        .with_fiber(&root)
        .intercept(
            "logger",
            ConfigValue::object([("level", ConfigValue::Int(3))]),
        )
        .logger()
        .unwrap()
        .debug("included");
    assert!(included.buffered());

    let messages = buffer.snapshot();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].sequence(), included.sequence());
    assert!(messages[0].timestamp_millis() > 0);
    assert_eq!(messages[0].fiber_uid(), Some(root.uid()));
    assert_eq!(first_argument_text(&messages[0]), Some("included"));
}
