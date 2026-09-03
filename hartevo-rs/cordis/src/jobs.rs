//! Process-local background-job ownership and control.
//!
//! Producers retain their execution mechanics while this Cordis surface owns
//! admission, identity, Session isolation, lifecycle state, and teardown.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::{AgentRef, LifecycleCancellation, SessionId};

/// Default maximum number of live jobs owned by one Session.
pub const DEFAULT_MAX_CONCURRENT_JOBS_PER_SESSION: usize = 10;

const DEFAULT_SHUTDOWN_WAIT: Duration = Duration::from_secs(5);
const CANCELLATION_POLL: Duration = Duration::from_millis(25);

/// Registry-issued background-job identity (`<kind>-<serial>`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobId(String);

impl JobId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Public lifecycle of one registered job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Running,
    Stopping,
    Completed,
    Killed,
    Failed,
}

impl JobStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Completed => "completed",
            Self::Killed => "killed",
            Self::Failed => "failed",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Killed | Self::Failed)
    }
}

/// Terminal state a producer supplies when its resources have been released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobTerminalStatus {
    Completed,
    Killed,
    Failed,
}

impl JobTerminalStatus {
    const fn public(self) -> JobStatus {
        match self {
            Self::Completed => JobStatus::Completed,
            Self::Killed => JobStatus::Killed,
            Self::Failed => JobStatus::Failed,
        }
    }
}

/// Producer-authored terminal result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobOutcome {
    status: JobTerminalStatus,
    detail: Option<String>,
    output: Option<String>,
}

impl JobOutcome {
    #[must_use]
    pub const fn new(status: JobTerminalStatus) -> Self {
        Self {
            status,
            detail: None,
            output: None,
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn with_output(mut self, output: impl Into<String>) -> Self {
        self.output = Some(output.into());
        self
    }
}

/// Read-only job facts returned to controllers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSnapshot {
    id: JobId,
    kind: String,
    label: String,
    owner_session: String,
    status: JobStatus,
    detail: Option<String>,
    started_at_ms: u64,
    finished_at_ms: Option<u64>,
}

impl JobSnapshot {
    #[must_use]
    pub const fn id(&self) -> &JobId {
        &self.id
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn owner_session(&self) -> &str {
        &self.owner_session
    }

    #[must_use]
    pub const fn status(&self) -> JobStatus {
        self.status
    }

    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    #[must_use]
    pub const fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    #[must_use]
    pub const fn finished_at_ms(&self) -> Option<u64> {
        self.finished_at_ms
    }
}

/// Newly consumed output plus the state observed immediately afterward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRead {
    output: String,
    snapshot: JobSnapshot,
}

impl JobRead {
    #[must_use]
    pub fn output(&self) -> &str {
        &self.output
    }

    #[must_use]
    pub const fn snapshot(&self) -> &JobSnapshot {
        &self.snapshot
    }
}

/// Result of a controller-owned kill request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobKillOutcome {
    Requested,
    AlreadyFinished,
}

impl JobKillOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::AlreadyFinished => "already-finished",
        }
    }
}

/// Typed background-job registry failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JobError {
    #[error("job kind must be a non-empty lowercase identifier")]
    InvalidKind,
    #[error("job label must not be blank")]
    InvalidLabel,
    #[error("job wait timeout must be greater than zero")]
    InvalidWaitTimeout,
    #[error("background job limit reached for Session `{session}` (limit: {limit})")]
    LimitReached { session: String, limit: usize },
    #[error("background job id allocation overflowed for kind `{kind}`")]
    IdentityOverflow { kind: String },
    #[error("unknown background job `{id}`")]
    Unknown { id: String },
    #[error("background job `{id}` belongs to another Session")]
    AccessDenied { id: String },
    #[error("background job `{id}` has no cancellation controller")]
    MissingController { id: String },
    #[error("background job `{id}` cancellation panicked")]
    CancellationPanicked { id: String },
    #[error("background job `{id}` output reader panicked")]
    OutputReadPanicked { id: String },
    #[error("background job wait was cancelled")]
    WaitCancelled,
    #[error("background job registry is shutting down")]
    ShuttingDown,
    #[error("background job producer failed to start: {detail}")]
    StartFailed { detail: String },
    #[error("background job producer panicked while starting")]
    StartPanicked,
}

/// Producer-owned cancellation entry point retained by Cordis after start.
type JobCancelCallback = dyn Fn(Option<&str>) + Send + Sync;
type JobOutputCallback = dyn Fn() -> String + Send + Sync;
type JobTerminalObserver = dyn Fn(JobTerminalNotice) + Send + Sync;

/// Content-free signal that one exact Agent-owned job became terminal.
///
/// Consumers must still claim current job facts before acting. The signal
/// grants no Session, Runtime, Domain, Effect, or provider authority.
#[derive(Clone, Debug)]
pub struct JobTerminalNotice {
    owner_session: SessionId,
    owner_agent: AgentRef,
}

impl JobTerminalNotice {
    #[must_use]
    pub const fn owner_session(&self) -> &SessionId {
        &self.owner_session
    }

    #[must_use]
    pub const fn owner_agent(&self) -> &AgentRef {
        &self.owner_agent
    }
}

#[derive(Clone)]
pub struct JobControl {
    cancel: Arc<JobCancelCallback>,
    read_output: Option<Arc<JobOutputCallback>>,
}

impl JobControl {
    #[must_use]
    pub fn new<F>(cancel: F) -> Self
    where
        F: Fn(Option<&str>) + Send + Sync + 'static,
    {
        Self {
            cancel: Arc::new(cancel),
            read_output: None,
        }
    }

    /// Attach a consuming reader for output produced since the prior read.
    #[must_use]
    pub fn with_output_reader<F>(mut self, read_output: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.read_output = Some(Arc::new(read_output));
        self
    }

    fn cancel(&self, reason: Option<&str>) {
        (self.cancel)(reason);
    }
}

impl fmt::Debug for JobControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JobControl(..)")
    }
}

struct JobRecordState {
    published: bool,
    reported: bool,
    terminal_signalled: bool,
    waiters: usize,
    status: JobStatus,
    detail: Option<String>,
    output: Option<String>,
    finished_at_ms: Option<u64>,
    control: Option<JobControl>,
    read_output: Option<Arc<JobOutputCallback>>,
}

struct JobRecord {
    id: JobId,
    kind: String,
    label: String,
    owner_session: String,
    owner_agent: AgentRef,
    started_at_ms: u64,
    state: Mutex<JobRecordState>,
    changed: Condvar,
    terminal_observer: Arc<Mutex<Option<Arc<JobTerminalObserver>>>>,
}

impl JobRecord {
    fn snapshot_with(&self, state: &JobRecordState) -> JobSnapshot {
        JobSnapshot {
            id: self.id.clone(),
            kind: self.kind.clone(),
            label: self.label.clone(),
            owner_session: self.owner_session.clone(),
            status: state.status,
            detail: state.detail.clone(),
            started_at_ms: self.started_at_ms,
            finished_at_ms: state.finished_at_ms,
        }
    }

    fn snapshot(&self) -> JobSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.snapshot_with(&state)
    }
}

/// One-shot producer settlement capability.
pub struct JobCompletion {
    record: Option<Arc<JobRecord>>,
}

impl JobCompletion {
    /// Commit the first terminal result and release all waiters.
    pub fn complete(mut self, outcome: JobOutcome) -> bool {
        let Some(record) = self.record.take() else {
            return false;
        };
        settle_record(&record, outcome)
    }
}

impl fmt::Debug for JobCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobCompletion")
            .field("pending", &self.record.is_some())
            .finish()
    }
}

impl Drop for JobCompletion {
    fn drop(&mut self) {
        if let Some(record) = self.record.take() {
            let _ = settle_record(
                &record,
                JobOutcome::new(JobTerminalStatus::Failed)
                    .with_detail("producer stopped without a terminal outcome"),
            );
        }
    }
}

#[derive(Default)]
struct JobsState {
    shutting_down: bool,
    counters: HashMap<String, u64>,
    records: BTreeMap<JobId, Arc<JobRecord>>,
}

struct JobsInner {
    max_concurrent_jobs_per_session: usize,
    state: Mutex<JobsState>,
    terminal_observer: Arc<Mutex<Option<Arc<JobTerminalObserver>>>>,
}

impl Drop for JobsInner {
    fn drop(&mut self) {
        let records = {
            let state = self
                .state
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.shutting_down = true;
            state.records.values().cloned().collect::<Vec<_>>()
        };
        stop_records(&records, "Cordis jobs teardown");
        wait_for_records(&records, DEFAULT_SHUTDOWN_WAIT);
    }
}

/// Process-local Cordis job registry.
#[derive(Clone)]
pub struct JobsSurface {
    inner: Arc<JobsInner>,
}

impl fmt::Debug for JobsSurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        formatter
            .debug_struct("JobsSurface")
            .field(
                "max_concurrent_jobs_per_session",
                &self.inner.max_concurrent_jobs_per_session,
            )
            .field("job_count", &state.records.len())
            .field("shutting_down", &state.shutting_down)
            .finish()
    }
}

impl Default for JobsSurface {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONCURRENT_JOBS_PER_SESSION)
    }
}

impl JobsSurface {
    #[must_use]
    pub fn new(max_concurrent_jobs_per_session: usize) -> Self {
        assert!(
            max_concurrent_jobs_per_session > 0,
            "Cordis jobs limit must be positive"
        );
        Self {
            inner: Arc::new(JobsInner {
                max_concurrent_jobs_per_session,
                state: Mutex::new(JobsState::default()),
                terminal_observer: Arc::new(Mutex::new(None)),
            }),
        }
    }

    /// Install the process-local terminal signal sink used by the host wake
    /// driver. Replacing the sink is harmless and affects only future signals.
    pub fn on_terminal<F>(&self, observer: F)
    where
        F: Fn(JobTerminalNotice) + Send + Sync + 'static,
    {
        *self
            .inner
            .terminal_observer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(observer));
    }

    /// Preflight and register one producer. The callback starts work and gives
    /// Cordis the cancellation entry point; its completion capability must be
    /// moved to the worker that releases the producer's resources.
    pub fn start<F>(
        &self,
        owner: &SessionId,
        owner_agent: &AgentRef,
        kind: impl Into<String>,
        label: impl Into<String>,
        starter: F,
    ) -> Result<JobId, JobError>
    where
        F: FnOnce(JobCompletion) -> Result<JobControl, String>,
    {
        let record = self.reserve(owner, owner_agent, kind.into(), label.into())?;

        let completion = JobCompletion {
            record: Some(Arc::clone(&record)),
        };
        let start_result = catch_unwind(AssertUnwindSafe(|| starter(completion)));
        let control = match start_result {
            Ok(Ok(control)) => control,
            Ok(Err(detail)) => {
                self.remove_record(&record.id);
                return Err(JobError::StartFailed { detail });
            }
            Err(_) => {
                self.remove_record(&record.id);
                return Err(JobError::StartPanicked);
            }
        };

        let mut control = Some(control);
        let shutting_down = {
            let state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.shutting_down {
                true
            } else {
                let mut record_state = record
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                record_state.read_output = control
                    .as_ref()
                    .and_then(|control| control.read_output.clone());
                if !record_state.status.is_terminal() {
                    record_state.control = control.take();
                }
                record_state.published = true;
                false
            }
        };
        if shutting_down {
            let control = control.expect("shutdown keeps the uncommitted job controller");
            let _ = catch_unwind(AssertUnwindSafe(|| {
                control.cancel(Some("Cordis jobs teardown"));
            }));
            wait_for_records(std::slice::from_ref(&record), DEFAULT_SHUTDOWN_WAIT);
            self.remove_record(&record.id);
            return Err(JobError::ShuttingDown);
        }

        record.changed.notify_all();
        signal_terminal(&record);
        Ok(record.id.clone())
    }

    fn reserve(
        &self,
        owner: &SessionId,
        owner_agent: &AgentRef,
        kind: String,
        label: String,
    ) -> Result<Arc<JobRecord>, JobError> {
        if kind.is_empty()
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(JobError::InvalidKind);
        }
        if label.trim().is_empty() {
            return Err(JobError::InvalidLabel);
        }
        let owner_session = owner.as_str().to_string();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.shutting_down {
            return Err(JobError::ShuttingDown);
        }
        let active = state
            .records
            .values()
            .filter(|record| record.owner_session == owner_session)
            .filter(|record| !record.snapshot().status().is_terminal())
            .count();
        if active >= self.inner.max_concurrent_jobs_per_session {
            return Err(JobError::LimitReached {
                session: owner_session,
                limit: self.inner.max_concurrent_jobs_per_session,
            });
        }
        let next = state
            .counters
            .get(&kind)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| JobError::IdentityOverflow { kind: kind.clone() })?;
        state.counters.insert(kind.clone(), next);
        let id = JobId(format!("{kind}-{next}"));
        let record = Arc::new(JobRecord {
            id: id.clone(),
            kind,
            label,
            owner_session,
            owner_agent: owner_agent.clone(),
            started_at_ms: unix_time_ms(),
            state: Mutex::new(JobRecordState {
                published: false,
                reported: false,
                terminal_signalled: false,
                waiters: 0,
                status: JobStatus::Running,
                detail: None,
                output: None,
                finished_at_ms: None,
                control: None,
                read_output: None,
            }),
            changed: Condvar::new(),
            terminal_observer: Arc::clone(&self.inner.terminal_observer),
        });
        state.records.insert(id, Arc::clone(&record));
        Ok(record)
    }

    #[must_use]
    pub fn list(&self, owner: &SessionId) -> Vec<JobSnapshot> {
        let records = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .values()
            .filter(|record| record.owner_session == owner.as_str())
            .cloned()
            .collect::<Vec<_>>();
        records
            .into_iter()
            .filter_map(|record| {
                let state = record
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.published.then(|| record.snapshot_with(&state))
            })
            .collect()
    }

    pub fn get(&self, id: &str, owner: &SessionId) -> Result<JobSnapshot, JobError> {
        Ok(self.owned_record(id, owner)?.snapshot())
    }

    pub fn read(&self, id: &str, owner: &SessionId) -> Result<JobRead, JobError> {
        let record = self.owned_record(id, owner)?;
        let read_output = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .read_output
            .clone();
        let incremental = read_output
            .map(|read_output| {
                catch_unwind(AssertUnwindSafe(|| read_output())).map_err(|_| {
                    JobError::OutputReadPanicked {
                        id: record.id.to_string(),
                    }
                })
            })
            .transpose()?;
        let mut state = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let output = if let Some(mut incremental) = incremental {
            if state.status.is_terminal() {
                state.reported = true;
                if let Some(terminal) = state.output.take() {
                    append_output(&mut incremental, &terminal);
                }
            }
            incremental
        } else if state.status.is_terminal() {
            state.reported = true;
            state.output.clone().unwrap_or_default()
        } else {
            String::new()
        };
        Ok(JobRead {
            output,
            snapshot: record.snapshot_with(&state),
        })
    }

    /// Wait until terminal, the bounded timeout expires, or the exact caller
    /// cancellation fires. A timeout is not an error; the returned snapshot
    /// remains `running` or `stopping`.
    pub fn wait(
        &self,
        id: &str,
        owner: &SessionId,
        timeout: Duration,
        cancellation: &LifecycleCancellation,
    ) -> Result<JobSnapshot, JobError> {
        if timeout.is_zero() {
            return Err(JobError::InvalidWaitTimeout);
        }
        let record = self.owned_record(id, owner)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(JobError::InvalidWaitTimeout)?;
        let mut state = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status.is_terminal() {
            state.reported = true;
            return Ok(record.snapshot_with(&state));
        }
        state.waiters = state.waiters.saturating_add(1);
        while !state.status.is_terminal() {
            if cancellation.is_cancelled() {
                state.waiters = state.waiters.saturating_sub(1);
                return Err(JobError::WaitCancelled);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let slice = remaining.min(CANCELLATION_POLL);
            let waited = record.changed.wait_timeout(state, slice);
            let (next, _) = waited.unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
        state.waiters = state.waiters.saturating_sub(1);
        if state.status.is_terminal() {
            state.reported = true;
        }
        Ok(record.snapshot_with(&state))
    }

    pub fn kill(
        &self,
        id: &str,
        owner: &SessionId,
        reason: Option<&str>,
    ) -> Result<JobKillOutcome, JobError> {
        let record = self.owned_record(id, owner)?;
        mark_reported(&record);
        request_stop(&record, reason).map(|requested| {
            if requested {
                JobKillOutcome::Requested
            } else {
                JobKillOutcome::AlreadyFinished
            }
        })
    }

    /// Atomically claim terminal notices owned by one exact live Agent.
    #[must_use]
    pub fn claim_unreported_terminal(&self, owner_agent: &AgentRef) -> Vec<JobSnapshot> {
        self.records_for_agent(owner_agent)
            .into_iter()
            .filter_map(|record| {
                let mut state = record
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !state.published || !state.status.is_terminal() || state.reported {
                    return None;
                }
                state.reported = true;
                Some(record.snapshot_with(&state))
            })
            .collect()
    }

    /// Snapshot terminal work that has not yet been reported.
    ///
    /// Desktop uses this only while the exact Agent is idle and its coordinator
    /// is exclusively checked out, then commits the corresponding inbox
    /// message before marking these ids reported.
    #[must_use]
    pub fn unreported_terminal(&self, owner_agent: &AgentRef) -> Vec<JobSnapshot> {
        self.records_for_agent(owner_agent)
            .into_iter()
            .filter_map(|record| {
                let state = record
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (state.published && state.status.is_terminal() && !state.reported)
                    .then(|| record.snapshot_with(&state))
            })
            .collect()
    }

    /// Mark the exact terminal ids reported after their durable inbox message
    /// has committed. Unknown, non-terminal, or cross-Agent ids are ignored.
    pub fn mark_terminal_reported(&self, owner_agent: &AgentRef, ids: &[JobId]) -> usize {
        self.records_for_agent(owner_agent)
            .into_iter()
            .filter(|record| ids.iter().any(|id| id == &record.id))
            .filter(|record| {
                let mut state = record
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !state.published || !state.status.is_terminal() || state.reported {
                    return false;
                }
                state.reported = true;
                true
            })
            .count()
    }

    /// Cancel jobs attached to one exact disposed Agent lifecycle, boundedly
    /// await compliant producers, and discard every terminal record.
    pub fn dispose_agent_and_wait(&self, owner_agent: &AgentRef, timeout: Duration) -> bool {
        let records = self.records_for_agent(owner_agent);
        stop_records(&records, "owning Agent disposed");
        let settled = wait_for_records(&records, timeout);
        let terminal_ids = records
            .iter()
            .filter(|record| record.snapshot().status().is_terminal())
            .map(|record| record.id.clone())
            .collect::<Vec<_>>();
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for id in terminal_ids {
            state.records.remove(&id);
        }
        settled
    }

    /// Stop admission, cancel all registered work, and boundedly wait for it.
    /// Repeated calls are harmless.
    pub fn shutdown(&self) -> bool {
        let records = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.shutting_down = true;
            state.records.values().cloned().collect::<Vec<_>>()
        };
        stop_records(&records, "Cordis jobs teardown");
        wait_for_records(&records, DEFAULT_SHUTDOWN_WAIT)
    }

    fn owned_record(&self, id: &str, owner: &SessionId) -> Result<Arc<JobRecord>, JobError> {
        let record = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .get(&JobId(id.to_string()))
            .cloned()
            .ok_or_else(|| JobError::Unknown { id: id.to_string() })?;
        let published = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .published;
        if !published {
            return Err(JobError::Unknown { id: id.to_string() });
        }
        if record.owner_session != owner.as_str() {
            return Err(JobError::AccessDenied { id: id.to_string() });
        }
        Ok(record)
    }

    fn records_for_agent(&self, owner_agent: &AgentRef) -> Vec<Arc<JobRecord>> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .values()
            .filter(|record| record.owner_agent.is_same_lifecycle(owner_agent))
            .cloned()
            .collect()
    }

    fn remove_record(&self, id: &JobId) {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .records
            .remove(id);
    }
}

fn request_stop(record: &Arc<JobRecord>, reason: Option<&str>) -> Result<bool, JobError> {
    let control = {
        let state = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.status.is_terminal() {
            return Ok(false);
        }
        state
            .control
            .clone()
            .ok_or_else(|| JobError::MissingController {
                id: record.id.to_string(),
            })?
    };
    if catch_unwind(AssertUnwindSafe(|| control.cancel(reason))).is_err() {
        let _ = settle_record(
            record,
            JobOutcome::new(JobTerminalStatus::Failed)
                .with_detail("producer cancellation panicked"),
        );
        return Err(JobError::CancellationPanicked {
            id: record.id.to_string(),
        });
    }
    let mut state = record
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !state.status.is_terminal() {
        state.status = JobStatus::Stopping;
        record.changed.notify_all();
    }
    Ok(true)
}

fn stop_records(records: &[Arc<JobRecord>], reason: &str) {
    for record in records {
        mark_reported(record);
        let _ = request_stop(record, Some(reason));
    }
}

fn mark_reported(record: &Arc<JobRecord>) {
    record
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .reported = true;
}

fn wait_for_records(records: &[Arc<JobRecord>], timeout: Duration) -> bool {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    records.iter().all(|record| {
        let mut state = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !state.status.is_terminal() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let waited = record.changed.wait_timeout(state, remaining);
            let (next, timeout_result) = waited.unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout_result.timed_out() && !state.status.is_terminal() {
                return false;
            }
        }
        true
    })
}

fn settle_record(record: &Arc<JobRecord>, outcome: JobOutcome) -> bool {
    let mut state = record
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.status.is_terminal() {
        return false;
    }
    state.status = outcome.status.public();
    state.detail = outcome.detail;
    state.output = outcome.output;
    state.finished_at_ms = Some(unix_time_ms());
    if state.waiters > 0 {
        state.reported = true;
    }
    state.control = None;
    drop(state);
    record.changed.notify_all();
    signal_terminal(record);
    true
}

fn signal_terminal(record: &Arc<JobRecord>) {
    let observer = record
        .terminal_observer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(observer) = observer else {
        return;
    };
    let notice = {
        let mut state = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.published
            || !state.status.is_terminal()
            || state.reported
            || state.terminal_signalled
        {
            return;
        }
        state.terminal_signalled = true;
        JobTerminalNotice {
            owner_session: SessionId::new(record.owner_session.clone())
                .expect("a Job owner was validated before reservation"),
            owner_agent: record.owner_agent.clone(),
        }
    };
    let _ = catch_unwind(AssertUnwindSafe(|| observer(notice)));
}

fn append_output(output: &mut String, addition: &str) {
    if addition.is_empty() {
        return;
    }
    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }
    output.push_str(addition);
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
