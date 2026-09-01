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

    /// Return a detached snapshot of input awaiting the next step boundary.
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
        self.insert(AgentInboxTarget::NextTurn, message, false)
    }

    /// Durably append one message for the next step, then update the live view.
    pub fn append_next_step(&self, message: SessionMessage) -> Result<(), SessionError> {
        self.insert(AgentInboxTarget::NextStep, message, false)
    }

    /// Durably prepend one message for a future turn.
    pub fn prepend_next_turn(&self, message: SessionMessage) -> Result<(), SessionError> {
        self.insert(AgentInboxTarget::NextTurn, message, true)
    }

    /// Durably prepend one message for the next step boundary.
    pub fn prepend_next_step(&self, message: SessionMessage) -> Result<(), SessionError> {
        self.insert(AgentInboxTarget::NextStep, message, true)
    }

    fn insert(
        &self,
        target: AgentInboxTarget,
        message: SessionMessage,
        prepend: bool,
    ) -> Result<(), SessionError> {
        let _permit = AgentInboxMutationPermit::enter(&self.mutating, self.session.id())?;
        let start = {
            let state = self.lock()?;
            if prepend {
                0
            } else {
                u64::try_from(state.list(target).len())
                    .map_err(|_| SessionError::EventSequenceOverflow)?
            }
        };
        if !self
            .mutate(target, start, None, vec![message], None)?
            .is_empty()
        {
            return Err(SessionError::InboxProjectionDrift);
        }
        Ok(())
    }

    /// Replace one still-pending message in place by exact identity.
    pub fn replace(
        &self,
        message_id: &str,
        replacement: SessionMessage,
    ) -> Result<bool, SessionError> {
        let _permit = AgentInboxMutationPermit::enter(&self.mutating, self.session.id())?;
        let Some((target, start)) = self.lock()?.locate(message_id)? else {
            return Ok(false);
        };
        let removed = self.mutate(
            target,
            start,
            Some(1),
            vec![replacement],
            Some(AgentInboxOutcome::Canceled),
        )?;
        if removed.len() != 1 {
            return Err(SessionError::InboxProjectionDrift);
        }
        Ok(true)
    }

    /// Remove one still-pending message by exact identity.
    pub fn remove(&self, message_id: &str) -> Result<bool, SessionError> {
        let _permit = AgentInboxMutationPermit::enter(&self.mutating, self.session.id())?;
        let Some((target, start)) = self.lock()?.locate(message_id)? else {
            return Ok(false);
        };
        let removed = self.mutate(
            target,
            start,
            Some(1),
            Vec::new(),
            Some(AgentInboxOutcome::Canceled),
        )?;
        if removed.len() != 1 {
            return Err(SessionError::InboxProjectionDrift);
        }
        Ok(true)
    }

    /// Durably cancel all pending input, clearing next-step before next-turn.
    pub fn clear(&self) -> Result<(), SessionError> {
        let _permit = AgentInboxMutationPermit::enter(&self.mutating, self.session.id())?;
        for target in [AgentInboxTarget::NextStep, AgentInboxTarget::NextTurn] {
            let removed_count = u64::try_from(self.lock()?.list(target).len())
                .map_err(|_| SessionError::EventSequenceOverflow)?;
            if removed_count == 0 {
                continue;
            }
            let removed = self.mutate(
                target,
                0,
                Some(removed_count),
                Vec::new(),
                Some(AgentInboxOutcome::Canceled),
            )?;
            if u64::try_from(removed.len()).map_err(|_| SessionError::EventSequenceOverflow)?
                != removed_count
            {
                return Err(SessionError::InboxProjectionDrift);
            }
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

    /// Durably claim all queued next-step input in FIFO order.
    ///
    /// The requested turn must be the exact currently open Session turn. An
    /// empty queue returns an empty batch without appending a no-op event.
    pub fn claim_next_step(&self, turn: u64) -> Result<Vec<SessionMessage>, SessionError> {
        let _permit = AgentInboxMutationPermit::enter(&self.mutating, self.session.id())?;
        let removed_count = {
            let state = self.lock()?;
            if state.next_step.is_empty() {
                self.session.require_open_turn(turn)?;
                return Ok(Vec::new());
            }
            let removed_count = u64::try_from(state.next_step.len())
                .map_err(|_| SessionError::EventSequenceOverflow)?;
            state.validate(
                AgentInboxTarget::NextStep,
                0,
                Some(removed_count),
                &[],
                None,
            )?;
            removed_count
        };
        let event = self.session.claim_agent_inbox_splice(
            turn,
            AgentInboxTarget::NextStep,
            0,
            Some(removed_count),
            Vec::new(),
            None,
        )?;
        let removed = self.apply_committed(&event)?;
        if u64::try_from(removed.len()).map_err(|_| SessionError::EventSequenceOverflow)?
            != removed_count
        {
            return Err(SessionError::InboxProjectionDrift);
        }
        Ok(removed)
    }

    fn mutate(
        &self,
        target: AgentInboxTarget,
        start: u64,
        removed_count: Option<u64>,
        inserted: Vec<SessionMessage>,
        outcome: Option<AgentInboxOutcome>,
    ) -> Result<Vec<SessionMessage>, SessionError> {
        self.lock()?
            .validate(target, start, removed_count, &inserted, outcome)?;
        let event = self.session.append_agent_inbox_splice(
            target,
            start,
            removed_count,
            inserted,
            outcome,
        )?;
        self.apply_committed(&event)
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

    fn locate(&self, message_id: &str) -> Result<Option<(AgentInboxTarget, u64)>, SessionError> {
        for target in [AgentInboxTarget::NextTurn, AgentInboxTarget::NextStep] {
            if let Some(index) = self
                .list(target)
                .iter()
                .position(|message| message.id == message_id)
            {
                return Ok(Some((
                    target,
                    u64::try_from(index).map_err(|_| SessionError::EventSequenceOverflow)?,
                )));
            }
        }
        Ok(None)
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
