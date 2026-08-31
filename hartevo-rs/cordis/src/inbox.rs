//! Session-owned projection of durable DeepSeek Harness agent inbox events.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::session::{
    SessionError, SessionEvent, SessionEventKind, SessionHandle, SessionHeader, SessionMessage,
    validate_inbox_user_message,
};

/// One of the two ordered pending-message lists owned by a Harness agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInboxTarget {
    NextTurn,
    NextStep,
}

/// Why a durable inbox deletion does not count as turn-owned work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInboxOutcome {
    Canceled,
}

/// Shared live view over one Session's durable pending input.
#[derive(Debug, Clone)]
pub struct AgentInbox {
    session: SessionHandle,
    state: Arc<Mutex<AgentInboxState>>,
    mutating: Arc<AtomicBool>,
}

impl AgentInbox {
    pub(crate) fn new(
        session: SessionHandle,
        state: Arc<Mutex<AgentInboxState>>,
        mutating: Arc<AtomicBool>,
    ) -> Self {
        Self {
            session,
            state,
            mutating,
        }
    }

    /// Return a detached snapshot of messages awaiting individual turns.
    pub fn next_turn(&self) -> Result<Vec<SessionMessage>, SessionError> {
        Ok(self.lock()?.next_turn.clone())
    }

    /// Return a detached read-only snapshot of future next-step input.
    ///
    /// N37 does not expose next-step mutation; retaining the second projection
    /// makes persisted vocabulary strict without granting steer/inject behavior.
    pub fn next_step(&self) -> Result<Vec<SessionMessage>, SessionError> {
        Ok(self.lock()?.next_step.clone())
    }

    /// Whether either owned pending list contains input.
    pub fn has_pending(&self) -> Result<bool, SessionError> {
        let state = self.lock()?;
        Ok(!state.next_turn.is_empty() || !state.next_step.is_empty())
    }

    /// Durably append one message for a future turn, then update the live view.
    pub fn append_next_turn(&self, message: SessionMessage) -> Result<(), SessionError> {
        let _permit = AgentInboxMutationPermit::enter(&self.mutating, self.session.id())?;
        let inserted = vec![message];
        let start = {
            let state = self.lock()?;
            let start = u64::try_from(state.next_turn.len())
                .map_err(|_| SessionError::EventSequenceOverflow)?;
            state.validate(AgentInboxTarget::NextTurn, start, None, &inserted, None)?;
            start
        };
        let event = self.session.append_agent_inbox_splice(
            AgentInboxTarget::NextTurn,
            start,
            None,
            inserted,
            None,
        )?;
        if !self.apply_committed(&event)?.is_empty() {
            return Err(SessionError::InboxProjectionDrift);
        }
        Ok(())
    }

    /// Durably claim and return exactly the first queued turn message.
    ///
    /// The requested turn must be the exact currently open Session turn. An
    /// empty queue returns `None` without appending a no-op event.
    pub fn claim_next_turn(&self, turn: u64) -> Result<Option<SessionMessage>, SessionError> {
        let _permit = AgentInboxMutationPermit::enter(&self.mutating, self.session.id())?;
        {
            let state = self.lock()?;
            if state.next_turn.is_empty() {
                self.session.require_open_turn(turn)?;
                return Ok(None);
            }
            state.validate(AgentInboxTarget::NextTurn, 0, Some(1), &[], None)?;
        }
        let event = self.session.claim_agent_inbox_splice(
            turn,
            AgentInboxTarget::NextTurn,
            0,
            Some(1),
            Vec::new(),
            None,
        )?;
        let mut removed = self.apply_committed(&event)?;
        if removed.len() != 1 {
            return Err(SessionError::InboxProjectionDrift);
        }
        Ok(removed.pop())
    }

    fn apply_committed(&self, event: &SessionEvent) -> Result<Vec<SessionMessage>, SessionError> {
        let SessionEventKind::AgentInboxSpliced {
            target,
            start,
            removed_count,
            inserted,
            outcome,
        } = &event.kind
        else {
            return Err(SessionError::InboxProjectionDrift);
        };
        self.lock()?
            .apply(*target, *start, *removed_count, inserted, *outcome)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, AgentInboxState>, SessionError> {
        self.state
            .lock()
            .map_err(|_| SessionError::InboxProjectionPoisoned)
    }
}

#[derive(Debug, Default)]
pub(crate) struct AgentInboxState {
    next_turn: Vec<SessionMessage>,
    next_step: Vec<SessionMessage>,
}

impl AgentInboxState {
    pub(crate) fn restore(
        header: &SessionHeader,
        events: &[SessionEvent],
    ) -> Result<Self, SessionError> {
        let start = usize::try_from(header.seed_length.unwrap_or_default())
            .map_err(|_| SessionError::EventSequenceOverflow)?;
        let mut state = Self::default();
        for event in &events[start..] {
            let SessionEventKind::AgentInboxSpliced {
                target,
                start,
                removed_count,
                inserted,
                outcome,
            } = &event.kind
            else {
                continue;
            };
            if state
                .apply(*target, *start, *removed_count, inserted, *outcome)
                .is_err()
            {
                return Err(SessionError::InvalidPersistedInboxSplice { seq: event.seq });
            }
        }
        Ok(state)
    }

    fn apply(
        &mut self,
        target: AgentInboxTarget,
        start: u64,
        removed_count: Option<u64>,
        inserted: &[SessionMessage],
        outcome: Option<AgentInboxOutcome>,
    ) -> Result<Vec<SessionMessage>, SessionError> {
        self.validate(target, start, removed_count, inserted, outcome)?;
        let start = usize::try_from(start).map_err(|_| SessionError::InvalidInboxSplice {
            expected: "coordinates within the pending list",
        })?;
        let removed_count = usize::try_from(removed_count.unwrap_or_default()).map_err(|_| {
            SessionError::InvalidInboxSplice {
                expected: "coordinates within the pending list",
            }
        })?;
        let inbox = self.list_mut(target);
        Ok(inbox
            .splice(start..start + removed_count, inserted.iter().cloned())
            .collect())
    }

    fn validate(
        &self,
        target: AgentInboxTarget,
        start: u64,
        removed_count: Option<u64>,
        inserted: &[SessionMessage],
        outcome: Option<AgentInboxOutcome>,
    ) -> Result<(), SessionError> {
        validate_agent_inbox_event(removed_count, inserted, outcome)?;
        let start = usize::try_from(start).map_err(|_| SessionError::InvalidInboxSplice {
            expected: "coordinates within the pending list",
        })?;
        let removed_count = usize::try_from(removed_count.unwrap_or_default()).map_err(|_| {
            SessionError::InvalidInboxSplice {
                expected: "coordinates within the pending list",
            }
        })?;
        let inbox = self.list(target);
        let end = start
            .checked_add(removed_count)
            .ok_or(SessionError::InvalidInboxSplice {
                expected: "coordinates within the pending list",
            })?;
        if start > inbox.len() || end > inbox.len() {
            return Err(SessionError::InvalidInboxSplice {
                expected: "coordinates within the pending list",
            });
        }

        let mut candidate = inbox.to_vec();
        candidate.splice(start..end, inserted.iter().cloned());
        let other = self.list(match target {
            AgentInboxTarget::NextTurn => AgentInboxTarget::NextStep,
            AgentInboxTarget::NextStep => AgentInboxTarget::NextTurn,
        });
        let mut identities = HashSet::new();
        for message in candidate.iter().chain(other) {
            if !identities.insert(message.id.as_str()) {
                return Err(SessionError::DuplicatePendingMessage {
                    id: message.id.clone(),
                });
            }
        }
        Ok(())
    }

    fn list(&self, target: AgentInboxTarget) -> &[SessionMessage] {
        match target {
            AgentInboxTarget::NextTurn => &self.next_turn,
            AgentInboxTarget::NextStep => &self.next_step,
        }
    }

    fn list_mut(&mut self, target: AgentInboxTarget) -> &mut Vec<SessionMessage> {
        match target {
            AgentInboxTarget::NextTurn => &mut self.next_turn,
            AgentInboxTarget::NextStep => &mut self.next_step,
        }
    }
}

pub(crate) fn validate_agent_inbox_event(
    removed_count: Option<u64>,
    inserted: &[SessionMessage],
    outcome: Option<AgentInboxOutcome>,
) -> Result<(), SessionError> {
    if removed_count == Some(0) {
        return Err(SessionError::InvalidInboxSplice {
            expected: "an omitted zero removed count",
        });
    }
    if removed_count.is_none() && inserted.is_empty() {
        return Err(SessionError::InvalidInboxSplice {
            expected: "at least one insertion or removal",
        });
    }
    if outcome.is_some() && removed_count.is_none() {
        return Err(SessionError::InvalidInboxSplice {
            expected: "a cancellation outcome only with removals",
        });
    }
    for message in inserted {
        validate_inbox_user_message(message)?;
    }
    Ok(())
}

struct AgentInboxMutationPermit<'a>(&'a AtomicBool);

impl<'a> AgentInboxMutationPermit<'a> {
    fn enter(flag: &'a AtomicBool, id: &crate::session::SessionId) -> Result<Self, SessionError> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self(flag))
            .map_err(|_| SessionError::InboxMutationInProgress { id: id.clone() })
    }
}

impl Drop for AgentInboxMutationPermit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
