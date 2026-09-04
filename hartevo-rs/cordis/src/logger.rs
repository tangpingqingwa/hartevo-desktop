//! Rust-native Cordis logging.
//!
//! A logger carries only immutable attribution metadata and a shared sink. It
//! is deliberately not a Context authority. Exporters are installed through
//! [`crate::Context`] so their lifetime remains owned by the registering
//! Fiber.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde_json::Value;

use crate::config::ConfigValue;
use crate::fiber::FiberUid;

pub const DEFAULT_LOGGER_BUFFER_CAPACITY: usize = 1_000;
const MAX_RECORDED_EXPORT_FAILURES: usize = 256;

/// Ordered log severity used by logger and exporter thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum LoggerLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

impl LoggerLevel {
    fn from_config(value: &ConfigValue) -> Option<Self> {
        match value {
            ConfigValue::Int(0) => Some(Self::Error),
            ConfigValue::Int(1) => Some(Self::Warn),
            ConfigValue::Int(2) => Some(Self::Info),
            ConfigValue::Int(3) => Some(Self::Debug),
            _ => None,
        }
    }

    const fn allows(self, message: Self) -> bool {
        self as u8 >= message as u8
    }
}

/// Stable message kind corresponding to one [`LoggerLevel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoggerType {
    Error,
    Warn,
    Info,
    Debug,
}

impl LoggerType {
    #[must_use]
    pub const fn level(self) -> LoggerLevel {
        match self {
            Self::Error => LoggerLevel::Error,
            Self::Warn => LoggerLevel::Warn,
            Self::Info => LoggerLevel::Info,
            Self::Debug => LoggerLevel::Debug,
        }
    }
}

/// Immutable snapshot delivered to the buffer and every matching exporter.
#[derive(Clone, PartialEq)]
pub struct LoggerMessage {
    sequence: u64,
    timestamp_millis: i64,
    name: String,
    kind: LoggerType,
    level: LoggerLevel,
    arguments: Vec<Value>,
    fiber_uid: Option<FiberUid>,
}

impl LoggerMessage {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn timestamp_millis(&self) -> i64 {
        self.timestamp_millis
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn kind(&self) -> LoggerType {
        self.kind
    }

    #[must_use]
    pub const fn level(&self) -> LoggerLevel {
        self.level
    }

    #[must_use]
    pub fn arguments(&self) -> &[Value] {
        &self.arguments
    }

    #[must_use]
    pub const fn fiber_uid(&self) -> Option<FiberUid> {
        self.fiber_uid
    }
}

impl fmt::Debug for LoggerMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoggerMessage")
            .field("sequence", &self.sequence)
            .field("timestamp_millis", &self.timestamp_millis)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("level", &self.level)
            .field("argument_count", &self.arguments.len())
            .field("fiber_uid", &self.fiber_uid)
            .finish()
    }
}

#[derive(Default)]
struct LoggerBufferState {
    capacity: usize,
    messages: VecDeque<LoggerMessage>,
}

/// Stable, cloneable view of the bounded chronological in-memory log buffer.
#[derive(Clone)]
pub struct LoggerBuffer {
    inner: Arc<Mutex<LoggerBufferState>>,
}

impl LoggerBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LoggerBufferState {
                capacity,
                messages: VecDeque::with_capacity(capacity),
            })),
        }
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        lock(&self.inner).capacity
    }

    /// Resize this buffer without replacing its shared identity.
    pub fn set_capacity(&self, capacity: usize) {
        let mut state = lock(&self.inner);
        state.capacity = capacity;
        trim_buffer(&mut state);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.inner).messages.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<LoggerMessage> {
        lock(&self.inner).messages.iter().cloned().collect()
    }

    #[must_use]
    pub fn same_storage(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn push(&self, message: LoggerMessage) {
        let mut state = lock(&self.inner);
        if state.capacity == 0 {
            state.messages.clear();
            return;
        }
        state.messages.push_back(message);
        trim_buffer(&mut state);
    }

    fn reset(&self) {
        let mut state = lock(&self.inner);
        state.capacity = DEFAULT_LOGGER_BUFFER_CAPACITY;
        state.messages.clear();
    }
}

impl fmt::Debug for LoggerBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoggerBuffer")
            .field("capacity", &self.capacity())
            .field("len", &self.len())
            .finish()
    }
}

fn trim_buffer(state: &mut LoggerBufferState) {
    let overflow = state.messages.len().saturating_sub(state.capacity);
    state.messages.drain(..overflow);
}

/// Failure returned by one logger exporter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggerExportError {
    detail: String,
}

impl LoggerExportError {
    #[must_use]
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for LoggerExportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.detail.fmt(formatter)
    }
}

impl std::error::Error for LoggerExportError {}

impl From<String> for LoggerExportError {
    fn from(detail: String) -> Self {
        Self::new(detail)
    }
}

impl From<&str> for LoggerExportError {
    fn from(detail: &str) -> Self {
        Self::new(detail)
    }
}

type LoggerExportCallback =
    dyn Fn(&LoggerMessage) -> Result<(), LoggerExportError> + Send + Sync + 'static;

/// One independently filtered immutable-message exporter.
#[derive(Clone)]
pub struct LoggerExporter {
    levels: BTreeMap<String, LoggerLevel>,
    callback: Arc<LoggerExportCallback>,
}

impl LoggerExporter {
    #[must_use]
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(&LoggerMessage) -> Result<(), LoggerExportError> + Send + Sync + 'static,
    {
        Self {
            levels: BTreeMap::new(),
            callback: Arc::new(callback),
        }
    }

    #[must_use]
    pub fn infallible<F>(callback: F) -> Self
    where
        F: Fn(&LoggerMessage) + Send + Sync + 'static,
    {
        Self::new(move |message| {
            callback(message);
            Ok(())
        })
    }

    #[must_use]
    pub fn with_default_level(mut self, level: LoggerLevel) -> Self {
        self.levels.insert("default".to_string(), level);
        self
    }

    #[must_use]
    pub fn with_level(mut self, name: impl Into<String>, level: LoggerLevel) -> Self {
        self.levels.insert(name.into(), level);
        self
    }

    fn threshold(&self, name: &str, logger_level: Option<LoggerLevel>) -> LoggerLevel {
        self.levels
            .get(name)
            .or_else(|| self.levels.get("default"))
            .copied()
            .or(logger_level)
            .unwrap_or(LoggerLevel::Info)
    }
}

impl fmt::Debug for LoggerExporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoggerExporter")
            .field("levels", &self.levels)
            .finish_non_exhaustive()
    }
}

/// Stable identity of an exporter within one [`LoggerService`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoggerExporterId(u64);

impl LoggerExporterId {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Observable, contained failure from one exporter invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggerExportFailure {
    exporter_id: LoggerExporterId,
    message_sequence: u64,
    detail: String,
}

impl LoggerExportFailure {
    #[must_use]
    pub const fn exporter_id(&self) -> LoggerExporterId {
        self.exporter_id
    }

    #[must_use]
    pub const fn message_sequence(&self) -> u64 {
        self.message_sequence
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

/// Result of one log dispatch. Exporter failures never abort other exporters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggerDispatchReport {
    sequence: u64,
    buffered: bool,
    exported: usize,
    failures: Vec<LoggerExportFailure>,
}

impl LoggerDispatchReport {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn buffered(&self) -> bool {
        self.buffered
    }

    #[must_use]
    pub const fn exported(&self) -> usize {
        self.exported
    }

    #[must_use]
    pub fn failures(&self) -> &[LoggerExportFailure] {
        &self.failures
    }
}

struct LoggerServiceState {
    sequence: u64,
    next_exporter_id: u64,
    exporters: BTreeMap<LoggerExporterId, LoggerExporter>,
    failures: VecDeque<LoggerExportFailure>,
}

/// Shared Cordis logger state. Exporter mutation remains Context-owned.
#[derive(Clone)]
pub struct LoggerService {
    state: Arc<Mutex<LoggerServiceState>>,
    buffer: LoggerBuffer,
}

impl Default for LoggerService {
    fn default() -> Self {
        Self::new()
    }
}

impl LoggerService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(LoggerServiceState {
                sequence: 0,
                next_exporter_id: 1,
                exporters: BTreeMap::new(),
                failures: VecDeque::new(),
            })),
            buffer: LoggerBuffer::new(DEFAULT_LOGGER_BUFFER_CAPACITY),
        }
    }

    #[must_use]
    pub fn buffer(&self) -> LoggerBuffer {
        self.buffer.clone()
    }

    #[must_use]
    pub fn failures(&self) -> Vec<LoggerExportFailure> {
        lock(&self.state).failures.iter().cloned().collect()
    }

    pub fn clear_failures(&self) {
        lock(&self.state).failures.clear();
    }

    pub(crate) fn logger(
        &self,
        name: String,
        level: Option<LoggerLevel>,
        fiber_uid: Option<FiberUid>,
    ) -> Logger {
        Logger {
            service: self.clone(),
            name,
            level,
            fiber_uid,
        }
    }

    pub(crate) fn add_exporter(&self, exporter: LoggerExporter) -> LoggerExporterId {
        let mut state = lock(&self.state);
        let id = LoggerExporterId(state.next_exporter_id);
        state.next_exporter_id = state
            .next_exporter_id
            .checked_add(1)
            .expect("logger exporter identity exhausted");
        state.exporters.insert(id, exporter);
        id
    }

    pub(crate) fn remove_exporter(&self, id: LoggerExporterId) -> bool {
        lock(&self.state).exporters.remove(&id).is_some()
    }

    pub(crate) fn reset(&self) {
        let mut state = lock(&self.state);
        state.exporters.clear();
        state.failures.clear();
        drop(state);
        self.buffer.reset();
    }

    fn emit(
        &self,
        name: &str,
        logger_level: Option<LoggerLevel>,
        fiber_uid: Option<FiberUid>,
        kind: LoggerType,
        arguments: Vec<Value>,
    ) -> LoggerDispatchReport {
        let (sequence, exporters) = {
            let mut state = lock(&self.state);
            state.sequence = state
                .sequence
                .checked_add(1)
                .expect("logger message sequence exhausted");
            let exporters = state
                .exporters
                .iter()
                .map(|(id, exporter)| (*id, exporter.clone()))
                .collect::<Vec<_>>();
            (state.sequence, exporters)
        };
        let level = kind.level();
        let message = LoggerMessage {
            sequence,
            timestamp_millis: Utc::now().timestamp_millis(),
            name: name.to_string(),
            kind,
            level,
            arguments,
            fiber_uid,
        };

        let buffered = logger_level.unwrap_or(LoggerLevel::Info).allows(level);
        if buffered {
            self.buffer.push(message.clone());
        }

        let mut exported = 0;
        let mut failures = Vec::new();
        for (exporter_id, exporter) in exporters {
            if !exporter.threshold(name, logger_level).allows(level) {
                continue;
            }
            let outcome = catch_unwind(AssertUnwindSafe(|| (exporter.callback)(&message)));
            match outcome {
                Ok(Ok(())) => exported += 1,
                Ok(Err(error)) => failures.push(LoggerExportFailure {
                    exporter_id,
                    message_sequence: sequence,
                    detail: error.to_string(),
                }),
                Err(payload) => failures.push(LoggerExportFailure {
                    exporter_id,
                    message_sequence: sequence,
                    detail: format!(
                        "exporter panicked: {}",
                        panic_payload_message(payload.as_ref())
                    ),
                }),
            }
        }
        if !failures.is_empty() {
            let mut state = lock(&self.state);
            state.failures.extend(failures.iter().cloned());
            let overflow = state
                .failures
                .len()
                .saturating_sub(MAX_RECORDED_EXPORT_FAILURES);
            state.failures.drain(..overflow);
        }
        LoggerDispatchReport {
            sequence,
            buffered,
            exported,
            failures,
        }
    }
}

impl fmt::Debug for LoggerService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.state);
        formatter
            .debug_struct("LoggerService")
            .field("sequence", &state.sequence)
            .field("exporter_count", &state.exporters.len())
            .field("failure_count", &state.failures.len())
            .field("buffer", &self.buffer)
            .finish()
    }
}

/// Lightweight logger with resolved attribution and level fallback.
#[derive(Clone)]
pub struct Logger {
    service: LoggerService,
    name: String,
    level: Option<LoggerLevel>,
    fiber_uid: Option<FiberUid>,
}

impl Logger {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn level(&self) -> Option<LoggerLevel> {
        self.level
    }

    #[must_use]
    pub const fn fiber_uid(&self) -> Option<FiberUid> {
        self.fiber_uid
    }

    pub fn error(&self, argument: impl Into<Value>) -> LoggerDispatchReport {
        self.error_args([argument])
    }

    pub fn warn(&self, argument: impl Into<Value>) -> LoggerDispatchReport {
        self.warn_args([argument])
    }

    pub fn info(&self, argument: impl Into<Value>) -> LoggerDispatchReport {
        self.info_args([argument])
    }

    pub fn debug(&self, argument: impl Into<Value>) -> LoggerDispatchReport {
        self.debug_args([argument])
    }

    pub fn error_args<I, V>(&self, arguments: I) -> LoggerDispatchReport
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        self.emit(LoggerType::Error, arguments)
    }

    pub fn warn_args<I, V>(&self, arguments: I) -> LoggerDispatchReport
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        self.emit(LoggerType::Warn, arguments)
    }

    pub fn info_args<I, V>(&self, arguments: I) -> LoggerDispatchReport
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        self.emit(LoggerType::Info, arguments)
    }

    pub fn debug_args<I, V>(&self, arguments: I) -> LoggerDispatchReport
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        self.emit(LoggerType::Debug, arguments)
    }

    fn emit<I, V>(&self, kind: LoggerType, arguments: I) -> LoggerDispatchReport
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        self.service.emit(
            &self.name,
            self.level,
            self.fiber_uid,
            kind,
            arguments.into_iter().map(Into::into).collect(),
        )
    }
}

impl fmt::Debug for Logger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Logger")
            .field("name", &self.name)
            .field("level", &self.level)
            .field("fiber_uid", &self.fiber_uid)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LoggerConfig {
    pub(crate) name: Option<String>,
    pub(crate) level: Option<LoggerLevel>,
}

impl LoggerConfig {
    pub(crate) fn from_value(value: &ConfigValue) -> Self {
        Self {
            name: value
                .lookup("name")
                .and_then(ConfigValue::as_str)
                .map(str::to_string),
            level: value.lookup("level").and_then(LoggerLevel::from_config),
        }
    }
}

pub(crate) fn hyphenate_logger_name(name: &str) -> String {
    let mut output = String::with_capacity(name.len());
    let mut previous_was_lower_or_digit = false;
    for character in name.chars() {
        if character == '_' || character.is_whitespace() {
            if !output.ends_with('-') {
                output.push('-');
            }
            previous_was_lower_or_digit = false;
        } else if character.is_uppercase() {
            if previous_was_lower_or_digit && !output.ends_with('-') {
                output.push('-');
            }
            output.extend(character.to_lowercase());
            previous_was_lower_or_digit = false;
        } else {
            previous_was_lower_or_digit = character.is_lowercase() || character.is_ascii_digit();
            output.push(character);
        }
    }
    output
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload.downcast_ref::<String>().map_or_else(
        || {
            payload.downcast_ref::<&str>().map_or_else(
                || "non-string panic payload".to_string(),
                |message| (*message).to_string(),
            )
        },
        Clone::clone,
    )
}
