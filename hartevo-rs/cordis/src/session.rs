//! Minimal Rust-native Session boundary log adapted from DeepSeek Harness.
//!
//! This slice records and validates turn/step lifecycle only. Message history,
//! durable persistence, surface replacement, and the wider Harness vocabulary
//! remain separate follow-up work.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use chrono::Utc;

/// The Rust Session format written by this bounded implementation.
pub const SESSION_FORMAT_VERSION: u32 = 0;

/// Stable identity for one Session log.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(id: impl Into<String>) -> Result<Self, SessionError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SessionError::EmptySessionId);
        }
        Ok(Self(id))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Immutable metadata kept outside the append-only event sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHeader {
    pub version: u32,
    pub id: SessionId,
    pub created_at_ms: i64,
    pub parent_session: Option<SessionId>,
    pub seed_length: Option<u64>,
}

impl SessionHeader {
    pub fn new(id: SessionId) -> Result<Self, SessionError> {
        Self::new_at(id, Utc::now().timestamp_millis())
    }

    pub fn new_at(id: SessionId, created_at_ms: i64) -> Result<Self, SessionError> {
        if created_at_ms < 0 {
            return Err(SessionError::InvalidCreatedAt { created_at_ms });
        }
        Ok(Self {
            version: SESSION_FORMAT_VERSION,
            id,
            created_at_ms,
            parent_session: None,
            seed_length: None,
        })
    }
}

/// Content-free cancellation identity for a terminal turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCancelCause {
    User,
    Parent,
    Hook,
    Disposed,
    Legacy,
}

/// Why a turn ended. This mirrors the stable Harness boundary without logging
/// error bodies or other private content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnEndReason {
    Completed,
    Aborted(SessionCancelCause),
    Blocked,
    Error,
    MaxTokens,
    Interrupted,
}

/// The N17 Session event vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEventKind {
    TurnStart { turn: u64 },
    TurnEnd { turn: u64, reason: TurnEndReason },
    StepStart { turn: u64, step: u64 },
    StepEnd { turn: u64, step: u64 },
}

impl SessionEventKind {
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::TurnStart { .. } => "turn/start",
            Self::TurnEnd { .. } => "turn/end",
            Self::StepStart { .. } => "step/start",
            Self::StepEnd { .. } => "step/end",
        }
    }
}

/// One immutable entry in the contiguous Session log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEvent {
    pub seq: u64,
    pub time_ms: i64,
    pub kind: SessionEventKind,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SessionState {
    last_turn: u64,
    open_turn: Option<u64>,
    last_step: u64,
    open_step: Option<u64>,
}

impl SessionState {
    fn apply(&mut self, kind: &SessionEventKind) -> Result<(), SessionError> {
        match *kind {
            SessionEventKind::TurnStart { turn } => {
                if let Some(open) = self.open_turn {
                    return Err(SessionError::TurnAlreadyOpen { turn: open });
                }
                let expected = self
                    .last_turn
                    .checked_add(1)
                    .ok_or(SessionError::TurnSequenceOverflow)?;
                if turn != expected {
                    return Err(SessionError::UnexpectedTurn {
                        expected,
                        actual: turn,
                    });
                }
                self.last_turn = turn;
                self.open_turn = Some(turn);
                self.last_step = 0;
            }
            SessionEventKind::TurnEnd { turn, .. } => {
                require_turn(self.open_turn, turn)?;
                if let Some(step) = self.open_step {
                    return Err(SessionError::StepStillOpen { turn, step });
                }
                self.open_turn = None;
            }
            SessionEventKind::StepStart { turn, step } => {
                require_turn(self.open_turn, turn)?;
                if let Some(open) = self.open_step {
                    return Err(SessionError::StepAlreadyOpen { turn, step: open });
                }
                let expected = self
                    .last_step
                    .checked_add(1)
                    .ok_or(SessionError::StepSequenceOverflow { turn })?;
                if step != expected {
                    return Err(SessionError::UnexpectedStep {
                        turn,
                        expected,
                        actual: step,
                    });
                }
                self.last_step = step;
                self.open_step = Some(step);
            }
            SessionEventKind::StepEnd { turn, step } => {
                require_turn(self.open_turn, turn)?;
                match self.open_step {
                    Some(open) if open == step => self.open_step = None,
                    Some(open) => {
                        return Err(SessionError::StepMismatch {
                            turn,
                            expected: open,
                            actual: step,
                        });
                    }
                    None => return Err(SessionError::NoOpenStep { turn }),
                }
            }
        }
        Ok(())
    }
}

fn require_turn(open_turn: Option<u64>, actual: u64) -> Result<(), SessionError> {
    match open_turn {
        Some(expected) if expected == actual => Ok(()),
        Some(expected) => Err(SessionError::TurnMismatch { expected, actual }),
        None => Err(SessionError::NoOpenTurn),
    }
}

/// Validated append-only lifecycle log for one Session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLog {
    header: SessionHeader,
    events: Vec<SessionEvent>,
    state: SessionState,
}

impl SessionLog {
    pub fn new(id: SessionId) -> Result<Self, SessionError> {
        Ok(Self {
            header: SessionHeader::new(id)?,
            events: Vec::new(),
            state: SessionState::default(),
        })
    }

    pub fn new_at(id: SessionId, created_at_ms: i64) -> Result<Self, SessionError> {
        Ok(Self {
            header: SessionHeader::new_at(id, created_at_ms)?,
            events: Vec::new(),
            state: SessionState::default(),
        })
    }

    pub fn restore(header: SessionHeader, events: Vec<SessionEvent>) -> Result<Self, SessionError> {
        validate_header(&header, events.len())?;
        let mut state = SessionState::default();
        for (index, event) in events.iter().enumerate() {
            let expected = u64::try_from(index).map_err(|_| SessionError::EventSequenceOverflow)?;
            if event.seq != expected {
                return Err(SessionError::UnexpectedEventSequence {
                    expected,
                    actual: event.seq,
                });
            }
            if event.time_ms < 0 {
                return Err(SessionError::InvalidEventTime {
                    seq: event.seq,
                    time_ms: event.time_ms,
                });
            }
            state.apply(&event.kind)?;
        }
        Ok(Self {
            header,
            events,
            state,
        })
    }

    #[must_use]
    pub fn header(&self) -> &SessionHeader {
        &self.header
    }

    #[must_use]
    pub fn events(&self) -> &[SessionEvent] {
        &self.events
    }

    #[must_use]
    pub const fn open_turn(&self) -> Option<u64> {
        self.state.open_turn
    }

    #[must_use]
    pub const fn open_step(&self) -> Option<u64> {
        self.state.open_step
    }

    pub fn start_turn(&mut self) -> Result<u64, SessionError> {
        let turn = self
            .state
            .last_turn
            .checked_add(1)
            .ok_or(SessionError::TurnSequenceOverflow)?;
        self.append(SessionEventKind::TurnStart { turn })?;
        Ok(turn)
    }

    pub fn finish_turn(&mut self, turn: u64, reason: TurnEndReason) -> Result<(), SessionError> {
        self.append(SessionEventKind::TurnEnd { turn, reason })?;
        Ok(())
    }

    pub fn start_step(&mut self, turn: u64) -> Result<u64, SessionError> {
        require_turn(self.state.open_turn, turn)?;
        let step = self
            .state
            .last_step
            .checked_add(1)
            .ok_or(SessionError::StepSequenceOverflow { turn })?;
        self.append(SessionEventKind::StepStart { turn, step })?;
        Ok(step)
    }

    pub fn finish_step(&mut self, turn: u64, step: u64) -> Result<(), SessionError> {
        self.append(SessionEventKind::StepEnd { turn, step })?;
        Ok(())
    }

    fn append(&mut self, kind: SessionEventKind) -> Result<&SessionEvent, SessionError> {
        let mut next_state = self.state;
        next_state.apply(&kind)?;
        let seq =
            u64::try_from(self.events.len()).map_err(|_| SessionError::EventSequenceOverflow)?;
        let time_ms = Utc::now().timestamp_millis();
        if time_ms < 0 {
            return Err(SessionError::InvalidEventTime { seq, time_ms });
        }
        self.events.push(SessionEvent { seq, time_ms, kind });
        self.state = next_state;
        self.events
            .last()
            .ok_or(SessionError::EventSequenceOverflow)
    }
}

fn validate_header(header: &SessionHeader, event_count: usize) -> Result<(), SessionError> {
    if header.version != SESSION_FORMAT_VERSION {
        return Err(SessionError::UnsupportedFormatVersion {
            expected: SESSION_FORMAT_VERSION,
            actual: header.version,
        });
    }
    if header.created_at_ms < 0 {
        return Err(SessionError::InvalidCreatedAt {
            created_at_ms: header.created_at_ms,
        });
    }
    if let Some(seed_length) = header.seed_length {
        let event_count =
            u64::try_from(event_count).map_err(|_| SessionError::EventSequenceOverflow)?;
        if seed_length > event_count {
            return Err(SessionError::SeedBeyondLog {
                seed_length,
                event_count,
            });
        }
    }
    Ok(())
}

/// Shared handle to one live Session log.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    inner: Arc<Mutex<SessionLog>>,
}

impl SessionHandle {
    fn new(log: SessionLog) -> Self {
        Self {
            inner: Arc::new(Mutex::new(log)),
        }
    }

    pub fn header(&self) -> Result<SessionHeader, SessionError> {
        Ok(self.lock()?.header().clone())
    }

    pub fn events(&self) -> Result<Vec<SessionEvent>, SessionError> {
        Ok(self.lock()?.events().to_vec())
    }

    pub fn start_turn(&self) -> Result<u64, SessionError> {
        self.lock()?.start_turn()
    }

    pub fn finish_turn(&self, turn: u64, reason: TurnEndReason) -> Result<(), SessionError> {
        self.lock()?.finish_turn(turn, reason)
    }

    pub fn start_step(&self, turn: u64) -> Result<u64, SessionError> {
        self.lock()?.start_step(turn)
    }

    pub fn finish_step(&self, turn: u64, step: u64) -> Result<(), SessionError> {
        self.lock()?.finish_step(turn, step)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SessionLog>, SessionError> {
        self.inner.lock().map_err(|_| SessionError::LogPoisoned)
    }
}

#[derive(Debug, Default)]
struct SessionStoreState {
    sessions: HashMap<SessionId, SessionHandle>,
}

/// In-memory Session store mounted at `ctx.sessions`.
#[derive(Debug, Clone, Default)]
pub struct SessionStore {
    inner: Arc<Mutex<SessionStoreState>>,
}

impl SessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn create(&self, id: SessionId) -> Result<SessionHandle, SessionError> {
        let mut state = self.lock()?;
        if state.sessions.contains_key(&id) {
            return Err(SessionError::SessionAlreadyExists { id });
        }
        let handle = SessionHandle::new(SessionLog::new(id.clone())?);
        state.sessions.insert(id, handle.clone());
        Ok(handle)
    }

    pub fn restore(
        &self,
        header: SessionHeader,
        events: Vec<SessionEvent>,
    ) -> Result<SessionHandle, SessionError> {
        let mut state = self.lock()?;
        if state.sessions.contains_key(&header.id) {
            return Err(SessionError::SessionAlreadyExists {
                id: header.id.clone(),
            });
        }
        let id = header.id.clone();
        let handle = SessionHandle::new(SessionLog::restore(header, events)?);
        state.sessions.insert(id, handle.clone());
        Ok(handle)
    }

    /// Create a live child from a detached prefix of a live source Session.
    ///
    /// `boundary` is the inclusive source event sequence. Omitting it selects
    /// the current last event, while omitting it on an empty source creates an
    /// empty child. The selected prefix must end outside an open turn.
    pub fn fork(
        &self,
        source_id: &SessionId,
        boundary: Option<u64>,
        child_id: SessionId,
    ) -> Result<SessionHandle, SessionError> {
        let mut state = self.lock()?;
        if state.sessions.contains_key(&child_id) {
            return Err(SessionError::SessionAlreadyExists { id: child_id });
        }
        let source = state.sessions.get(source_id).cloned().ok_or_else(|| {
            SessionError::SessionNotFound {
                id: source_id.clone(),
            }
        })?;
        let source_log = source.lock()?;
        let last_seq = source_log.events().last().map(|event| event.seq);
        let selected_boundary = boundary.or(last_seq);
        let seed = match selected_boundary {
            None => Vec::new(),
            Some(boundary) => {
                let index = usize::try_from(boundary).map_err(|_| {
                    SessionError::ForkBoundaryDoesNotExist {
                        id: source_id.clone(),
                        boundary,
                        last_seq,
                    }
                })?;
                let event = source_log.events().get(index).ok_or_else(|| {
                    SessionError::ForkBoundaryDoesNotExist {
                        id: source_id.clone(),
                        boundary,
                        last_seq,
                    }
                })?;
                if event.seq != boundary {
                    return Err(SessionError::ForkBoundaryNotContiguous {
                        id: source_id.clone(),
                        boundary,
                    });
                }
                source_log.events()[..=index].to_vec()
            }
        };
        drop(source_log);

        let seed_length =
            u64::try_from(seed.len()).map_err(|_| SessionError::EventSequenceOverflow)?;
        let header = SessionHeader {
            version: SESSION_FORMAT_VERSION,
            id: child_id.clone(),
            created_at_ms: Utc::now().timestamp_millis(),
            parent_session: Some(source_id.clone()),
            seed_length: Some(seed_length),
        };
        let child_log = SessionLog::restore(header, seed)?;
        if let Some(turn) = child_log.open_turn() {
            let boundary = selected_boundary.ok_or(SessionError::EventSequenceOverflow)?;
            return Err(SessionError::ForkInsideOpenTurn {
                id: source_id.clone(),
                boundary,
                turn,
            });
        }
        let child = SessionHandle::new(child_log);
        state.sessions.insert(child_id, child.clone());
        Ok(child)
    }

    pub fn get(&self, id: &SessionId) -> Result<Option<SessionHandle>, SessionError> {
        Ok(self.lock()?.sessions.get(id).cloned())
    }

    pub fn get_or_create(&self, id: SessionId) -> Result<SessionHandle, SessionError> {
        let mut state = self.lock()?;
        if let Some(session) = state.sessions.get(&id) {
            return Ok(session.clone());
        }
        let handle = SessionHandle::new(SessionLog::new(id.clone())?);
        state.sessions.insert(id, handle.clone());
        Ok(handle)
    }

    pub fn len(&self) -> Result<usize, SessionError> {
        Ok(self.lock()?.sessions.len())
    }

    pub fn is_empty(&self) -> Result<bool, SessionError> {
        Ok(self.lock()?.sessions.is_empty())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SessionStoreState>, SessionError> {
        self.inner.lock().map_err(|_| SessionError::StorePoisoned)
    }
}

/// Fail-closed Session construction, replay, and transition errors.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SessionError {
    #[error("session id must not be empty")]
    EmptySessionId,
    #[error("session format version must be {expected}, got {actual}")]
    UnsupportedFormatVersion { expected: u32, actual: u32 },
    #[error("session created_at_ms must be non-negative, got {created_at_ms}")]
    InvalidCreatedAt { created_at_ms: i64 },
    #[error("session event {seq} time must be non-negative, got {time_ms}")]
    InvalidEventTime { seq: u64, time_ms: i64 },
    #[error("session event sequence must be {expected}, got {actual}")]
    UnexpectedEventSequence { expected: u64, actual: u64 },
    #[error("session event sequence overflowed")]
    EventSequenceOverflow,
    #[error("session turn sequence overflowed")]
    TurnSequenceOverflow,
    #[error("session step sequence overflowed in turn {turn}")]
    StepSequenceOverflow { turn: u64 },
    #[error("session turn {turn} is already open")]
    TurnAlreadyOpen { turn: u64 },
    #[error("session requires turn {expected}, got {actual}")]
    UnexpectedTurn { expected: u64, actual: u64 },
    #[error("session has no open turn")]
    NoOpenTurn,
    #[error("session open turn is {expected}, got {actual}")]
    TurnMismatch { expected: u64, actual: u64 },
    #[error("session turn {turn} step {step} is already open")]
    StepAlreadyOpen { turn: u64, step: u64 },
    #[error("session turn {turn} requires step {expected}, got {actual}")]
    UnexpectedStep {
        turn: u64,
        expected: u64,
        actual: u64,
    },
    #[error("session turn {turn} has no open step")]
    NoOpenStep { turn: u64 },
    #[error("session turn {turn} open step is {expected}, got {actual}")]
    StepMismatch {
        turn: u64,
        expected: u64,
        actual: u64,
    },
    #[error("session turn {turn} cannot end while step {step} is open")]
    StepStillOpen { turn: u64, step: u64 },
    #[error("session seed length {seed_length} exceeds event count {event_count}")]
    SeedBeyondLog { seed_length: u64, event_count: u64 },
    #[error("session `{id}` already exists")]
    SessionAlreadyExists { id: SessionId },
    #[error("session `{id}` was not found")]
    SessionNotFound { id: SessionId },
    #[error("fork boundary {boundary} does not exist in session `{id}` (last seq: {last_seq:?})")]
    ForkBoundaryDoesNotExist {
        id: SessionId,
        boundary: u64,
        last_seq: Option<u64>,
    },
    #[error("fork boundary {boundary} is not contiguous in session `{id}`")]
    ForkBoundaryNotContiguous { id: SessionId, boundary: u64 },
    #[error("fork boundary {boundary} in session `{id}` ends inside open turn {turn}")]
    ForkInsideOpenTurn {
        id: SessionId,
        boundary: u64,
        turn: u64,
    },
    #[error("session store mutex is poisoned")]
    StorePoisoned,
    #[error("session log mutex is poisoned")]
    LogPoisoned,
}
