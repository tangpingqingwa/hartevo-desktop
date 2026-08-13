//! Runtime-owned mid-turn steering service.
//!
//! This is the provider-side half of the durable steering boundary.  It deliberately carries
//! no Mission business authority: the caller supplies the exact scope/fence and a durable log.
//! The service only proves ordering, idempotency, and provider-session lifecycle.  A steering
//! request is queued in the supplied log before the OpenInterpreter `turn/steer` request is sent;
//! acknowledgements and stream observations are logged before they are exposed to the caller.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{MappedTurnEventKind, RuntimeMapping, RuntimePluginScope};

pub const RUNTIME_STEERING_SERVICE_SCHEMA: &str = "hartevo.runtime-steering-service/v1";
pub const RUNTIME_STEERING_EVENT_SCHEMA: &str = "hartevo.runtime-steering-event/v1";

const MAX_STEERING_CONTENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_STEERING_IDENTIFIER_BYTES: usize = 1_024;

fn digest(value: &[u8]) -> String {
    super::digest_hex(value)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STEERING_IDENTIFIER_BYTES
        && !value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSteeringPhase {
    Queued,
    Accepted,
    Applied,
    Terminal,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSteeringTerminalReason {
    TurnCompleted,
    Interrupted,
    Unmounted,
    Revoked,
    ProviderRejected,
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum RuntimeSteeringError {
    #[error("runtime steering scope or mapping is invalid")]
    InvalidScope,
    #[error("runtime steering fence is invalid")]
    InvalidFence,
    #[error("runtime steering has no active turn")]
    NoActiveTurn,
    #[error("runtime steering fence is stale")]
    StaleFence,
    #[error("runtime steering provider state is uncertain; explicit continue is required")]
    ProviderStateUncertain,
    #[error("runtime steering requires a durable Mission/session log")]
    DurableLogRequired,
    #[error("runtime steering content is empty or exceeds its bound")]
    InvalidContent,
    #[error("runtime steering idempotency key was already dispatched")]
    DuplicateSteering,
    #[error("runtime steering already has an in-flight request")]
    SteeringInFlight,
    #[error("runtime steering lifecycle transition is invalid")]
    InvalidTransition,
    #[error("runtime steering event sequence is exhausted")]
    SequenceExhausted,
}

/// The exact owner and provider identity carried by every steering event.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeSteeringFence {
    pub schema: String,
    pub project_id: String,
    pub mission_id: String,
    pub session_id: String,
    pub runtime_thread_id: String,
    pub runtime_turn_id: String,
    pub runtime_generation: u64,
    pub cursor: u64,
    pub revision: u64,
    pub mapping_digest: String,
}

impl fmt::Debug for RuntimeSteeringFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeSteeringFence")
            .field("schema", &self.schema)
            .field("project_digest", &digest(self.project_id.as_bytes()))
            .field("mission_digest", &digest(self.mission_id.as_bytes()))
            .field("session_digest", &digest(self.session_id.as_bytes()))
            .field(
                "runtime_thread_digest",
                &digest(self.runtime_thread_id.as_bytes()),
            )
            .field(
                "runtime_turn_digest",
                &digest(self.runtime_turn_id.as_bytes()),
            )
            .field("runtime_generation", &self.runtime_generation)
            .field("cursor", &self.cursor)
            .field("revision", &self.revision)
            .field("mapping_digest", &self.mapping_digest)
            .finish()
    }
}

impl RuntimeSteeringFence {
    fn from_mapping(
        scope: &RuntimePluginScope,
        mapping: &RuntimeMapping,
        cursor: u64,
        revision: u64,
    ) -> Result<Self, RuntimeSteeringError> {
        scope
            .validate()
            .map_err(|_| RuntimeSteeringError::InvalidScope)?;
        mapping
            .validate()
            .map_err(|_| RuntimeSteeringError::InvalidScope)?;
        if mapping.project_id != scope.project_id || mapping.mission_id != scope.mission_id {
            return Err(RuntimeSteeringError::InvalidScope);
        }
        let Some(runtime_turn_id) = mapping.runtime_turn_id.as_ref() else {
            return Err(RuntimeSteeringError::NoActiveTurn);
        };
        let mapping_digest = mapping
            .digest()
            .map_err(|_| RuntimeSteeringError::InvalidScope)?;
        let fence = Self {
            schema: RUNTIME_STEERING_SERVICE_SCHEMA.to_owned(),
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
            session_id: scope.session_id.clone(),
            runtime_thread_id: mapping.runtime_thread_id.clone(),
            runtime_turn_id: runtime_turn_id.clone(),
            runtime_generation: mapping.runtime_generation,
            cursor,
            revision,
            mapping_digest,
        };
        fence.validate()?;
        Ok(fence)
    }

    fn validate(&self) -> Result<(), RuntimeSteeringError> {
        if self.schema != RUNTIME_STEERING_SERVICE_SCHEMA
            || !valid_identifier(&self.project_id)
            || !valid_identifier(&self.mission_id)
            || !valid_identifier(&self.session_id)
            || !valid_identifier(&self.runtime_thread_id)
            || !valid_identifier(&self.runtime_turn_id)
            || self.runtime_generation == 0
            || self.revision == 0
            || !valid_digest(&self.mapping_digest)
        {
            return Err(RuntimeSteeringError::InvalidFence);
        }
        Ok(())
    }
}

/// A content-bearing durable steering event.  Debug output intentionally redacts the prompt;
/// the supplied Mission/session log remains the authority for private model-visible content.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeSteeringEvent {
    pub schema: String,
    pub sequence: u64,
    pub phase: RuntimeSteeringPhase,
    pub fence: RuntimeSteeringFence,
    pub client_steering_id_digest: String,
    pub prompt_digest: String,
    pub prompt: String,
    pub request_digest: Option<String>,
    pub response_digest: Option<String>,
    pub observed_event_digest: Option<String>,
    pub terminal_reason: Option<RuntimeSteeringTerminalReason>,
    pub error_digest: Option<String>,
    pub event_digest: String,
}

impl fmt::Debug for RuntimeSteeringEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeSteeringEvent")
            .field("schema", &self.schema)
            .field("sequence", &self.sequence)
            .field("phase", &self.phase)
            .field("fence", &self.fence)
            .field("client_steering_id_digest", &self.client_steering_id_digest)
            .field("prompt_digest", &self.prompt_digest)
            .field("prompt", &"<redacted>")
            .field("request_digest", &self.request_digest)
            .field("response_digest", &self.response_digest)
            .field("observed_event_digest", &self.observed_event_digest)
            .field("terminal_reason", &self.terminal_reason)
            .field("error_digest", &self.error_digest)
            .field("event_digest", &self.event_digest)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeSteeringEventDigestMaterial<'a> {
    schema: &'a str,
    sequence: u64,
    phase: RuntimeSteeringPhase,
    fence: &'a RuntimeSteeringFence,
    client_steering_id_digest: &'a str,
    prompt_digest: &'a str,
    request_digest: &'a Option<String>,
    response_digest: &'a Option<String>,
    observed_event_digest: &'a Option<String>,
    terminal_reason: &'a Option<RuntimeSteeringTerminalReason>,
    error_digest: &'a Option<String>,
}

impl RuntimeSteeringEvent {
    #[allow(
        clippy::too_many_arguments,
        reason = "each durable transition binds its exact fence and provider acknowledgement fields"
    )]
    fn new(
        sequence: u64,
        phase: RuntimeSteeringPhase,
        fence: RuntimeSteeringFence,
        client_steering_id_digest: String,
        prompt: String,
        request_digest: Option<String>,
        response_digest: Option<String>,
        observed_event_digest: Option<String>,
        terminal_reason: Option<RuntimeSteeringTerminalReason>,
        error_digest: Option<String>,
    ) -> Result<Self, RuntimeSteeringError> {
        let mut event = Self {
            schema: RUNTIME_STEERING_EVENT_SCHEMA.to_owned(),
            sequence,
            phase,
            fence,
            client_steering_id_digest,
            prompt_digest: digest(prompt.as_bytes()),
            prompt,
            request_digest,
            response_digest,
            observed_event_digest,
            terminal_reason,
            error_digest,
            event_digest: String::new(),
        };
        event.event_digest = event.computed_digest()?;
        event.validate()?;
        Ok(event)
    }

    fn computed_digest(&self) -> Result<String, RuntimeSteeringError> {
        let material = RuntimeSteeringEventDigestMaterial {
            schema: &self.schema,
            sequence: self.sequence,
            phase: self.phase,
            fence: &self.fence,
            client_steering_id_digest: &self.client_steering_id_digest,
            prompt_digest: &self.prompt_digest,
            request_digest: &self.request_digest,
            response_digest: &self.response_digest,
            observed_event_digest: &self.observed_event_digest,
            terminal_reason: &self.terminal_reason,
            error_digest: &self.error_digest,
        };
        serde_json::to_vec(&material)
            .map(|bytes| digest(&bytes))
            .map_err(|_| RuntimeSteeringError::InvalidFence)
    }

    pub fn validate(&self) -> Result<(), RuntimeSteeringError> {
        if self.schema != RUNTIME_STEERING_EVENT_SCHEMA
            || self.sequence == 0
            || self.fence.validate().is_err()
            || !valid_digest(&self.client_steering_id_digest)
            || !valid_digest(&self.prompt_digest)
            || self.prompt.trim().is_empty()
            || self.prompt.len() > MAX_STEERING_CONTENT_BYTES
            || self.prompt_digest != digest(self.prompt.as_bytes())
            || self.event_digest != self.computed_digest()?
            || self
                .request_digest
                .as_deref()
                .is_some_and(|value| !valid_digest(value))
            || self
                .response_digest
                .as_deref()
                .is_some_and(|value| !valid_digest(value))
            || self
                .observed_event_digest
                .as_deref()
                .is_some_and(|value| !valid_digest(value))
            || self
                .error_digest
                .as_deref()
                .is_some_and(|value| !valid_digest(value))
        {
            return Err(RuntimeSteeringError::InvalidFence);
        }
        let valid_phase_shape = match self.phase {
            RuntimeSteeringPhase::Queued => {
                self.request_digest.is_none()
                    && self.response_digest.is_none()
                    && self.observed_event_digest.is_none()
                    && self.terminal_reason.is_none()
                    && self.error_digest.is_none()
            }
            RuntimeSteeringPhase::Accepted => {
                self.request_digest.is_some()
                    && self.response_digest.is_some()
                    && self.observed_event_digest.is_none()
                    && self.terminal_reason.is_none()
                    && self.error_digest.is_none()
            }
            RuntimeSteeringPhase::Applied => {
                self.observed_event_digest.is_some()
                    && self.terminal_reason.is_none()
                    && self.error_digest.is_none()
            }
            RuntimeSteeringPhase::Terminal => {
                self.terminal_reason.is_some() && self.error_digest.is_none()
            }
            RuntimeSteeringPhase::Uncertain => {
                self.error_digest.is_some() && self.terminal_reason.is_none()
            }
        };
        if !valid_phase_shape {
            return Err(RuntimeSteeringError::InvalidTransition);
        }
        Ok(())
    }
}

/// Implementations must durably commit before returning `Ok`.
pub trait RuntimeSteeringLog {
    fn append_steering_event(&mut self, event: RuntimeSteeringEvent) -> Result<(), String>;
}

impl<F> RuntimeSteeringLog for F
where
    F: FnMut(RuntimeSteeringEvent) -> Result<(), String>,
{
    fn append_steering_event(&mut self, event: RuntimeSteeringEvent) -> Result<(), String> {
        self(event)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSteeringAck {
    pub phase: RuntimeSteeringPhase,
    pub fence: RuntimeSteeringFence,
    pub client_steering_id_digest: String,
    pub event_digest: String,
}

#[derive(Clone)]
struct PendingSteering {
    client_steering_id_digest: String,
    prompt: String,
    fence: RuntimeSteeringFence,
    phase: RuntimeSteeringPhase,
}

/// Typed provider-side state machine for one exact mounted session.
pub struct RuntimeSteeringService {
    scope: RuntimePluginScope,
    current_fence: Option<RuntimeSteeringFence>,
    next_event_sequence: u64,
    pending: Option<PendingSteering>,
    seen_client_ids: BTreeSet<String>,
    blocked: bool,
}

impl fmt::Debug for RuntimeSteeringService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeSteeringService")
            .field("scope", &self.scope)
            .field("current_fence", &self.current_fence)
            .field("next_event_sequence", &self.next_event_sequence)
            .field(
                "pending",
                &self.pending.as_ref().map(|pending| &pending.phase),
            )
            .field("seen_client_id_count", &self.seen_client_ids.len())
            .field("blocked", &self.blocked)
            .finish()
    }
}

impl RuntimeSteeringService {
    pub fn new(
        scope: RuntimePluginScope,
        mapping: &RuntimeMapping,
    ) -> Result<Self, RuntimeSteeringError> {
        scope
            .validate()
            .map_err(|_| RuntimeSteeringError::InvalidScope)?;
        let mut service = Self {
            scope,
            current_fence: None,
            next_event_sequence: 1,
            pending: None,
            seen_client_ids: BTreeSet::new(),
            blocked: false,
        };
        service.bind_mapping(mapping)?;
        Ok(service)
    }

    pub fn current_fence(&self) -> Result<RuntimeSteeringFence, RuntimeSteeringError> {
        if self.blocked {
            return Err(RuntimeSteeringError::ProviderStateUncertain);
        }
        self.current_fence
            .clone()
            .ok_or(RuntimeSteeringError::NoActiveTurn)
    }

    /// Returns the exact post-restart fence needed for an explicit Continue.  It is intentionally
    /// separate from `current_fence`, which remains fail-closed while provider state is uncertain.
    pub fn continuation_fence(&self) -> Result<RuntimeSteeringFence, RuntimeSteeringError> {
        self.current_fence
            .clone()
            .ok_or(RuntimeSteeringError::NoActiveTurn)
    }

    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    pub fn bind_mapping(&mut self, mapping: &RuntimeMapping) -> Result<(), RuntimeSteeringError> {
        mapping
            .validate()
            .map_err(|_| RuntimeSteeringError::InvalidScope)?;
        if mapping.project_id != self.scope.project_id
            || mapping.mission_id != self.scope.mission_id
        {
            return Err(RuntimeSteeringError::InvalidScope);
        }
        if self.pending.is_some() {
            return Err(RuntimeSteeringError::SteeringInFlight);
        }
        if mapping.runtime_turn_id.is_none() {
            self.current_fence = None;
            return Ok(());
        }
        let mapping_digest = mapping
            .digest()
            .map_err(|_| RuntimeSteeringError::InvalidScope)?;
        let is_same_mapping = self
            .current_fence
            .as_ref()
            .is_some_and(|fence| fence.mapping_digest == mapping_digest);
        if is_same_mapping {
            return Ok(());
        }
        let revision = if let Some(fence) = &self.current_fence {
            fence
                .revision
                .checked_add(1)
                .ok_or(RuntimeSteeringError::SequenceExhausted)?
        } else {
            1
        };
        self.current_fence = Some(RuntimeSteeringFence::from_mapping(
            &self.scope,
            mapping,
            0,
            revision,
        )?);
        Ok(())
    }

    pub fn advance_cursor(&mut self) -> Result<(), RuntimeSteeringError> {
        if let Some(fence) = &mut self.current_fence {
            fence.cursor = fence
                .cursor
                .checked_add(1)
                .ok_or(RuntimeSteeringError::SequenceExhausted)?;
        }
        Ok(())
    }

    pub fn queue(
        &mut self,
        fence: &RuntimeSteeringFence,
        client_steering_id: &str,
        prompt: &str,
    ) -> Result<RuntimeSteeringEvent, RuntimeSteeringError> {
        let client_digest = digest(client_steering_id.as_bytes());
        if self.seen_client_ids.contains(&client_digest) {
            return Err(RuntimeSteeringError::DuplicateSteering);
        }
        self.ensure_dispatchable(fence)?;
        if !valid_identifier(client_steering_id)
            || prompt.trim().is_empty()
            || prompt.len() > MAX_STEERING_CONTENT_BYTES
        {
            return Err(RuntimeSteeringError::InvalidContent);
        }
        if self.pending.is_some() {
            return Err(RuntimeSteeringError::SteeringInFlight);
        }
        let event = self.next_event(
            RuntimeSteeringPhase::Queued,
            fence.clone(),
            client_digest.clone(),
            prompt.to_owned(),
            None,
            None,
            None,
            None,
            None,
        )?;
        self.pending = Some(PendingSteering {
            client_steering_id_digest: client_digest.clone(),
            prompt: prompt.to_owned(),
            fence: fence.clone(),
            phase: RuntimeSteeringPhase::Queued,
        });
        self.seen_client_ids.insert(client_digest);
        Ok(event)
    }

    pub fn accepted(
        &mut self,
        request_digest: String,
        response_digest: String,
    ) -> Result<RuntimeSteeringEvent, RuntimeSteeringError> {
        let pending = self
            .pending
            .clone()
            .ok_or(RuntimeSteeringError::InvalidTransition)?;
        if pending.phase != RuntimeSteeringPhase::Queued
            || !valid_digest(&request_digest)
            || !valid_digest(&response_digest)
        {
            return Err(RuntimeSteeringError::InvalidTransition);
        }
        let event = self.next_event(
            RuntimeSteeringPhase::Accepted,
            pending.fence.clone(),
            pending.client_steering_id_digest.clone(),
            pending.prompt.clone(),
            Some(request_digest),
            Some(response_digest),
            None,
            None,
            None,
        )?;
        if let Some(pending) = self.pending.as_mut() {
            pending.phase = RuntimeSteeringPhase::Accepted;
        }
        Ok(event)
    }

    pub fn observe_stream(
        &mut self,
        kind: &MappedTurnEventKind,
        observed_event_digest: &str,
    ) -> Result<Option<RuntimeSteeringEvent>, RuntimeSteeringError> {
        if !valid_digest(observed_event_digest) {
            return Err(RuntimeSteeringError::InvalidFence);
        }
        let Some(pending) = self.pending.clone() else {
            return Ok(None);
        };
        if pending.phase == RuntimeSteeringPhase::Accepted
            && matches!(
                kind,
                MappedTurnEventKind::ItemStarted
                    | MappedTurnEventKind::AgentMessageDelta
                    | MappedTurnEventKind::ItemCompleted
            )
        {
            let event = self.next_event(
                RuntimeSteeringPhase::Applied,
                pending.fence.clone(),
                pending.client_steering_id_digest.clone(),
                pending.prompt.clone(),
                None,
                None,
                Some(observed_event_digest.to_owned()),
                None,
                None,
            )?;
            if let Some(pending) = self.pending.as_mut() {
                pending.phase = RuntimeSteeringPhase::Applied;
            }
            return Ok(Some(event));
        }
        if matches!(kind, MappedTurnEventKind::TurnCompleted(_))
            && matches!(
                pending.phase,
                RuntimeSteeringPhase::Accepted | RuntimeSteeringPhase::Applied
            )
        {
            let event = self.next_event(
                RuntimeSteeringPhase::Terminal,
                pending.fence.clone(),
                pending.client_steering_id_digest.clone(),
                pending.prompt.clone(),
                None,
                None,
                Some(observed_event_digest.to_owned()),
                Some(RuntimeSteeringTerminalReason::TurnCompleted),
                None,
            )?;
            self.pending = None;
            return Ok(Some(event));
        }
        Ok(None)
    }

    pub fn terminate(
        &mut self,
        reason: RuntimeSteeringTerminalReason,
        response_digest: Option<String>,
    ) -> Result<Option<RuntimeSteeringEvent>, RuntimeSteeringError> {
        let Some(pending) = self.pending.take() else {
            return Ok(None);
        };
        if response_digest
            .as_deref()
            .is_some_and(|value| !valid_digest(value))
        {
            self.pending = Some(pending);
            return Err(RuntimeSteeringError::InvalidFence);
        }
        self.next_event(
            RuntimeSteeringPhase::Terminal,
            pending.fence,
            pending.client_steering_id_digest,
            pending.prompt,
            None,
            response_digest,
            None,
            Some(reason),
            None,
        )
        .map(Some)
    }

    pub fn uncertain(
        &mut self,
        error_digest: String,
    ) -> Result<Option<RuntimeSteeringEvent>, RuntimeSteeringError> {
        self.blocked = true;
        let Some(pending) = self.pending.take() else {
            return Ok(None);
        };
        if !valid_digest(&error_digest) {
            return Err(RuntimeSteeringError::InvalidFence);
        }
        self.next_event(
            RuntimeSteeringPhase::Uncertain,
            pending.fence,
            pending.client_steering_id_digest,
            pending.prompt,
            None,
            None,
            None,
            None,
            Some(error_digest),
        )
        .map(Some)
    }

    /// Clear only the local steering block after the caller has performed its explicit recovery
    /// decision.  No request is replayed and the old idempotency key remains consumed.
    pub fn explicit_continue(
        &mut self,
        fence: &RuntimeSteeringFence,
    ) -> Result<RuntimeSteeringFence, RuntimeSteeringError> {
        if !self.blocked {
            return Err(RuntimeSteeringError::InvalidTransition);
        }
        let Some(current) = self.current_fence.as_ref() else {
            return Err(RuntimeSteeringError::NoActiveTurn);
        };
        if current != fence {
            return Err(RuntimeSteeringError::StaleFence);
        }
        let next_revision = current
            .revision
            .checked_add(1)
            .ok_or(RuntimeSteeringError::SequenceExhausted)?;
        let mut continued = current.clone();
        continued.revision = next_revision;
        self.current_fence = Some(continued.clone());
        self.blocked = false;
        Ok(continued)
    }

    pub fn block(&mut self) {
        self.blocked = true;
    }

    fn ensure_dispatchable(
        &self,
        fence: &RuntimeSteeringFence,
    ) -> Result<(), RuntimeSteeringError> {
        if self.blocked {
            return Err(RuntimeSteeringError::ProviderStateUncertain);
        }
        let Some(current) = &self.current_fence else {
            return Err(RuntimeSteeringError::NoActiveTurn);
        };
        fence.validate()?;
        if current != fence {
            return Err(RuntimeSteeringError::StaleFence);
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "every durable transition carries the same exact fence and provider evidence"
    )]
    fn next_event(
        &mut self,
        phase: RuntimeSteeringPhase,
        fence: RuntimeSteeringFence,
        client_steering_id_digest: String,
        prompt: String,
        request_digest: Option<String>,
        response_digest: Option<String>,
        observed_event_digest: Option<String>,
        terminal_reason: Option<RuntimeSteeringTerminalReason>,
        error_digest: Option<String>,
    ) -> Result<RuntimeSteeringEvent, RuntimeSteeringError> {
        let sequence = self.next_event_sequence;
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .ok_or(RuntimeSteeringError::SequenceExhausted)?;
        RuntimeSteeringEvent::new(
            sequence,
            phase,
            fence,
            client_steering_id_digest,
            prompt,
            request_digest,
            response_digest,
            observed_event_digest,
            terminal_reason,
            error_digest,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RuntimeMapping, RuntimePluginScope};

    fn mapping() -> (RuntimePluginScope, RuntimeMapping) {
        let scope = RuntimePluginScope::new("project-steer", "mission-steer", "session-steer")
            .expect("scope");
        let mut mapping = RuntimeMapping::new(
            scope.project_id.clone(),
            scope.mission_id.clone(),
            7,
            "a".repeat(64),
            "gpt-5.6",
            "openai",
            "thread-steer",
        )
        .expect("mapping");
        mapping.runtime_turn_id = Some("turn-steer".to_owned());
        (scope, mapping)
    }

    #[test]
    fn exact_fence_orders_transitions_and_explicit_continue_never_replays() {
        let (scope, mapping) = mapping();
        let mut service = RuntimeSteeringService::new(scope, &mapping).expect("service");
        let fence = service.current_fence().expect("fence");
        let queued = service
            .queue(&fence, "steer-1", "Keep the result bounded.")
            .expect("queued");
        assert_eq!(queued.phase, RuntimeSteeringPhase::Queued);
        let accepted = service
            .accepted("b".repeat(64), "c".repeat(64))
            .expect("accepted");
        assert_eq!(accepted.phase, RuntimeSteeringPhase::Accepted);
        let applied = service
            .observe_stream(&MappedTurnEventKind::AgentMessageDelta, &"d".repeat(64))
            .expect("observed")
            .expect("applied");
        assert_eq!(applied.phase, RuntimeSteeringPhase::Applied);
        let terminal = service
            .observe_stream(
                &MappedTurnEventKind::TurnCompleted(crate::RuntimeTurnCompletionStatus::Completed),
                &"e".repeat(64),
            )
            .expect("terminal")
            .expect("terminal event");
        assert_eq!(terminal.phase, RuntimeSteeringPhase::Terminal);
        assert!(matches!(
            service.queue(&fence, "steer-1", "Keep the result bounded."),
            Err(RuntimeSteeringError::DuplicateSteering)
        ));

        let queued = service
            .queue(
                &service.current_fence().expect("same turn fence"),
                "steer-2",
                "Stop before external effects.",
            )
            .expect("second queued");
        assert_eq!(queued.phase, RuntimeSteeringPhase::Queued);
        let uncertain = service
            .uncertain("f".repeat(64))
            .expect("uncertain")
            .expect("uncertain event");
        assert_eq!(uncertain.phase, RuntimeSteeringPhase::Uncertain);
        assert!(matches!(
            service.queue(
                &service.continuation_fence().expect("continuation fence"),
                "steer-3",
                "must be blocked",
            ),
            Err(RuntimeSteeringError::ProviderStateUncertain)
        ));
        let continued = service
            .explicit_continue(&service.continuation_fence().expect("continuation fence"))
            .expect("explicit continue");
        assert!(continued.revision > fence.revision);
        assert!(matches!(
            service.queue(&fence, "steer-replay", "stale"),
            Err(RuntimeSteeringError::StaleFence)
        ));
    }

    #[test]
    fn lifecycle_terminal_reasons_and_event_debug_do_not_leak_prompt() {
        let (scope, mapping) = mapping();
        let mut service = RuntimeSteeringService::new(scope, &mapping).expect("service");
        let fence = service.current_fence().expect("fence");
        let prompt = "private correction MUST NOT be in debug";
        service
            .queue(&fence, "steer-interrupt", prompt)
            .expect("queue");
        let terminal = service
            .terminate(
                RuntimeSteeringTerminalReason::Interrupted,
                Some("a".repeat(64)),
            )
            .expect("terminate")
            .expect("event");
        assert_eq!(
            terminal.terminal_reason,
            Some(RuntimeSteeringTerminalReason::Interrupted)
        );
        assert!(!format!("{terminal:?}").contains(prompt));
        service
            .queue(
                &service.current_fence().expect("same turn"),
                "steer-crash",
                "crash correction",
            )
            .expect("queue");
        let uncertain = service
            .uncertain("b".repeat(64))
            .expect("uncertain")
            .expect("event");
        assert_eq!(uncertain.phase, RuntimeSteeringPhase::Uncertain);
    }
}
