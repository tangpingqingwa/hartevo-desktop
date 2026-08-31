//! One-call-site Cordis mount and typed Domain/Effect/Runtime adapters for Desktop.
//!
//! Production Runtime enters through [`dispatch_live_runtime`]: Cordis issues
//! a short-lived scoped permit, Desktop releases the host lock, and the real
//! Application coordinator runs exactly once. OpenInterpreter may occupy the
//! optional plugin slot; it never owns Domain, Effect, or execution authority.

use std::collections::BTreeMap;
#[cfg(test)]
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use hartevo_cordis::{
    AgentInboxOutcome, AgentInboxTarget, AuthorityDispatchError, AuthorityScope, CordisError,
    CordisHost, DomainCommandAuthority, DomainCommandBinding, DomainCommandPermit,
    EffectExecutionAuthority, EffectExecutionBinding, EffectExecutionPermit,
    EffectReconciliationAuthority, EffectReconciliationBinding, EffectReconciliationPermit,
    EffectVerificationAuthority, EffectVerificationBinding, EffectVerificationPermit, Fiber,
    FiberState, FiberUid, KernelApproval, KernelApprovalDecision, KernelConsentRecord,
    KernelConsentState, KernelConsentStatus, RuntimeAuthority, RuntimeDispatchCompletion,
    RuntimeDispatchPermit, SessionCallConfig, SessionCancelCause, SessionCheckpoint,
    SessionContentBlock, SessionEpochHeader, SessionError, SessionEvent, SessionEventKind,
    SessionEventRecord, SessionFinishReason, SessionHandle, SessionHeader, SessionId, SessionLog,
    SessionMessage, SessionMessageRole, SessionMessageSource, SessionRequestContext,
    SessionRequestHeader, SessionRequestHeaderReason, SessionStore, SessionStreamBlockType,
    SessionStreamChunk, SessionSurfaceIntent, SessionToolError, TurnEndReason, host_is_cordis_loop,
    keys, session_events,
};
use hartevo_domain_kernel::{
    Approval, ApprovalDecision, ConsentRecord, ConsentState, ConsentStatus,
};
use hartevo_storage::{
    PersistedAgentInboxOutcome, PersistedAgentInboxTarget, PersistedSessionCancelCause,
    PersistedSessionCheckpoint, PersistedSessionEvent, PersistedSessionEventKind,
    PersistedSessionHeader, PersistedSessionToolError, PersistedTurnEndReason, ProjectStore,
    StorageError,
};
use thiserror::Error;

use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

/// Whether OpenInterpreter is configured as an optional runtime adapter.
#[must_use]
fn openinterpreter_runtime_plugin(runtime: &DesktopRuntimeProjection) -> bool {
    matches!(
        runtime.status,
        DesktopRuntimeAvailabilityStatus::ReadyDevelopment
            | DesktopRuntimeAvailabilityStatus::ReadyDistribution
    )
}

#[derive(Debug, Eq, PartialEq)]
struct DesktopCordisBindingState {
    root_fiber_uid: FiberUid,
    refresh_sequence: u64,
    scope: Option<AuthorityScope>,
}

/// Typed proof that one exact scoped live binding completed before Runtime
/// authorization. The underlying reserved Domain provider remains Cordis-owned.
#[derive(Debug)]
struct DesktopCordisBindingReceipt {
    coordinator_identity: Arc<()>,
    root_fiber_uid: FiberUid,
    refresh_sequence: u64,
    scope: AuthorityScope,
}

impl DesktopCordisBindingReceipt {
    #[cfg(test)]
    #[must_use]
    const fn scope(&self) -> &AuthorityScope {
        &self.scope
    }

    #[cfg(test)]
    #[must_use]
    const fn root_fiber_uid(&self) -> FiberUid {
        self.root_fiber_uid
    }

    #[cfg(test)]
    #[must_use]
    const fn refresh_sequence(&self) -> u64 {
        self.refresh_sequence
    }
}

/// Desktop-owned lifetime boundary around the generic Cordis host.
///
/// It retains the root Fiber handle and records only successful live bindings.
/// Cordis remains the sole owner of reserved provider identity/generation and
/// of Runtime permits.
#[derive(Debug)]
pub(crate) struct DesktopCordisCoordinator {
    host: CordisHost,
    session_persistence: DesktopSessionPersistence,
    identity: Arc<()>,
    root_fiber: Fiber,
    successful_bindings: u64,
    last_binding: Option<DesktopCordisBindingState>,
}

/// One already-observed Application Runtime turn projected into Cordis.
///
/// Bodies stay private to the encrypted Session store and are deliberately
/// omitted from `Debug` surfaces. Application remains the execution and
/// Mission-truth owner; this value grants no Runtime or Effect authority.
pub(crate) struct DesktopRuntimeSessionTranscript {
    session_id: String,
    runtime_turn_id: String,
    user_body: String,
    provider: String,
    model: String,
    assistant_chunks: Vec<String>,
    assistant_body: Option<String>,
    end_reason: TurnEndReason,
}

/// Exact model-request facts that must be durable before Application calls the
/// external Runtime. This does not carry or compose the private Context
/// envelope used by Application.
pub(crate) struct DesktopRuntimeSessionPreflight {
    session_id: String,
    runtime_turn_id: String,
    user_body: String,
    provider: String,
    model: String,
}

/// Cumulative text deltas already persisted by Application for one exact
/// Runtime attempt and ready for synchronous Session flush.
pub(crate) struct DesktopRuntimeSessionStreamFlush {
    session_id: String,
    runtime_turn_id: String,
    user_body: String,
    provider: String,
    model: String,
    assistant_chunks: Vec<String>,
}

impl DesktopRuntimeSessionPreflight {
    pub(crate) fn new(
        session_id: impl Into<String>,
        runtime_turn_id: impl Into<String>,
        user_body: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            runtime_turn_id: runtime_turn_id.into(),
            user_body: user_body.into(),
            provider: provider.into(),
            model: model.into(),
        }
    }
}

impl DesktopRuntimeSessionStreamFlush {
    pub(crate) fn new(
        session_id: impl Into<String>,
        runtime_turn_id: impl Into<String>,
        user_body: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        assistant_chunks: Vec<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            runtime_turn_id: runtime_turn_id.into(),
            user_body: user_body.into(),
            provider: provider.into(),
            model: model.into(),
            assistant_chunks,
        }
    }
}

impl DesktopRuntimeSessionTranscript {
    #[allow(
        clippy::too_many_arguments,
        reason = "the private boundary keeps exact Session, Runtime turn, route, chunks, final body, and terminal identity visible without another transport type"
    )]
    pub(crate) fn new(
        session_id: impl Into<String>,
        runtime_turn_id: impl Into<String>,
        user_body: impl Into<String>,
        provider: impl Into<String>,
        model: impl Into<String>,
        assistant_chunks: Vec<String>,
        assistant_body: Option<String>,
        end_reason: TurnEndReason,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            runtime_turn_id: runtime_turn_id.into(),
            user_body: user_body.into(),
            provider: provider.into(),
            model: model.into(),
            assistant_chunks,
            assistant_body,
            end_reason,
        }
    }
}

fn runtime_user_message(runtime_turn_id: &str, user_body: String) -> SessionMessage {
    SessionMessage {
        id: format!("runtime:{runtime_turn_id}:user"),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text { text: user_body }],
        source: SessionMessageSource::User,
    }
}

fn runtime_request_header(provider: &str, model: &str) -> SessionEpochHeader {
    SessionEpochHeader {
        config: SessionCallConfig {
            provider: provider.to_owned(),
            model: model.to_owned(),
            reasoning_effort: None,
            temperature: None,
            max_tokens: None,
            stop: None,
        },
        adapter_defaults: None,
        system: None,
        tools: None,
    }
}

fn runtime_request_context(provider: &str, model: &str) -> SessionRequestContext {
    SessionRequestContext {
        provider: provider.to_owned(),
        model: model.to_owned(),
        context_window: None,
    }
}

fn append_runtime_preflight(
    session: &SessionHandle,
    user: SessionMessage,
    header: SessionEpochHeader,
    context: SessionRequestContext,
) -> Result<(u64, u64), SessionError> {
    let turn = session.start_turn()?;
    session.append_request_header(header, SessionRequestHeaderReason::Initial, false)?;
    let step = session.start_step(turn)?;
    session.append_user_message(user)?;
    session.append_request_context(context)?;
    Ok((turn, step))
}

fn runtime_request_location(
    events: &[SessionEvent],
    user: &SessionMessage,
    header: &SessionEpochHeader,
    context: &SessionRequestContext,
) -> Option<(u64, u64, usize)> {
    let mut matches = events.iter().enumerate().filter_map(|(index, event)| {
        let SessionEventKind::UserMessage { message, surface } = &event.kind else {
            return None;
        };
        (message.id == user.id).then_some((index, message, surface))
    });
    let (user_index, recorded_user, surface) = matches.next()?;
    if matches.next().is_some()
        || recorded_user != user
        || surface != &SessionSurfaceIntent::append()
    {
        return None;
    }
    let prefix_start = user_index.checked_sub(3)?;
    let turn = match &events.get(prefix_start)?.kind {
        SessionEventKind::TurnStart { turn } => *turn,
        _ => return None,
    };
    let SessionEventKind::RequestHeader { request } = &events.get(prefix_start + 1)?.kind else {
        return None;
    };
    if request.header != *header
        || request.reason != SessionRequestHeaderReason::Initial
        || request.starts_series
    {
        return None;
    }
    let step = match &events.get(prefix_start + 2)?.kind {
        SessionEventKind::StepStart {
            turn: step_turn,
            step,
        } if *step_turn == turn => *step,
        _ => return None,
    };
    let context_index = user_index.checked_add(1)?;
    match &events.get(context_index)?.kind {
        SessionEventKind::RequestContext { context: recorded } if recorded == context => {
            Some((turn, step, context_index))
        }
        _ => None,
    }
}

fn runtime_preflight_location(
    events: &[SessionEvent],
    user: &SessionMessage,
    header: &SessionEpochHeader,
    context: &SessionRequestContext,
) -> Option<(u64, u64)> {
    let (turn, step, context_index) = runtime_request_location(events, user, header, context)?;
    events[context_index.checked_add(1)?..]
        .iter()
        .all(|event| {
            matches!(
                &event.kind,
                SessionEventKind::AssistantChunk {
                    turn: chunk_turn,
                    step: chunk_step,
                    ..
                } if *chunk_turn == turn && *chunk_step == step
            )
        })
        .then_some((turn, step))
}

fn runtime_live_chunks(chunks: Vec<String>) -> Vec<SessionStreamChunk> {
    let mut expected = Vec::with_capacity(chunks.len().saturating_add(1));
    if !chunks.is_empty() {
        expected.push(SessionStreamChunk::BlockStart {
            index: 0,
            block_type: SessionStreamBlockType::Text,
        });
        expected.extend(
            chunks
                .into_iter()
                .map(|text| SessionStreamChunk::TextDelta { index: 0, text }),
        );
    }
    expected
}

fn runtime_open_turn(events: &[SessionEvent]) -> Option<u64> {
    events.iter().fold(None, |open, event| match &event.kind {
        SessionEventKind::TurnStart { turn } => Some(*turn),
        SessionEventKind::TurnEnd { turn, .. } if open == Some(*turn) => None,
        _ => open,
    })
}

impl DesktopCordisCoordinator {
    fn new(
        host: CordisHost,
        session_persistence: DesktopSessionPersistence,
    ) -> Result<Self, CordisError> {
        let root_fiber = host.context().root_fiber();
        let coordinator = Self {
            host,
            session_persistence,
            identity: Arc::new(()),
            root_fiber,
            successful_bindings: 0,
            last_binding: None,
        };
        coordinator.ensure_root_fiber_active()?;
        Ok(coordinator)
    }

    fn ensure_root_fiber_active(&self) -> Result<(), CordisError> {
        if self.root_fiber.is_disposed() || self.root_fiber.state() != FiberState::Active {
            return Err(CordisError::FiberDisposed {
                uid: self.root_fiber.uid(),
            });
        }
        Ok(())
    }

    pub(crate) fn bind_session_persistence(
        &mut self,
        store: ProjectStore,
    ) -> Result<usize, DesktopSessionPersistenceError> {
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopSessionPersistenceError::MissingSessionStore)?;
        self.session_persistence.bind_and_restore(store, &sessions)
    }

    /// Persist the exact open Session prefix before Application dispatches the
    /// matching external Runtime turn.
    pub(crate) fn prepare_runtime_transcript(
        &mut self,
        preflight: DesktopRuntimeSessionPreflight,
    ) -> Result<(), DesktopSessionPersistenceError> {
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopSessionPersistenceError::MissingSessionStore)?;
        let session = sessions.get_or_create(SessionId::new(preflight.session_id.clone())?)?;
        let user = runtime_user_message(&preflight.runtime_turn_id, preflight.user_body);
        let assistant_id = format!("runtime:{}:assistant", preflight.runtime_turn_id);
        let header = runtime_request_header(&preflight.provider, &preflight.model);
        let context = runtime_request_context(&preflight.provider, &preflight.model);
        let events = session.events()?;
        let identity_exists = events.iter().any(|event| match &event.kind {
            SessionEventKind::UserMessage { message, .. }
            | SessionEventKind::AssistantMessage { message, .. } => {
                message.id == user.id || message.id == assistant_id
            }
            _ => false,
        });
        if identity_exists {
            let Some((turn, step)) = runtime_preflight_location(&events, &user, &header, &context)
            else {
                return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                    preflight.session_id,
                ));
            };
            if runtime_open_turn(&events) != Some(turn)
                || !session.assistant_chunks(turn, step)?.is_empty()
                || events.iter().any(|event| {
                    matches!(
                        &event.kind,
                        SessionEventKind::AssistantMessage { message, .. }
                            if message.id == assistant_id
                    )
                })
            {
                return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                    preflight.session_id,
                ));
            }
            return self.session_persistence.persist_live(&session);
        }

        append_runtime_preflight(&session, user, header, context)?;
        self.session_persistence.persist_live(&session)
    }

    /// Extend the exact open Runtime step with the cumulative text stream that
    /// Application has already persisted. Exact retries append nothing.
    pub(crate) fn flush_runtime_stream(
        &mut self,
        stream: DesktopRuntimeSessionStreamFlush,
    ) -> Result<(), DesktopSessionPersistenceError> {
        if stream.assistant_chunks.is_empty() {
            return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                stream.session_id,
            ));
        }
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopSessionPersistenceError::MissingSessionStore)?;
        let session = sessions.get_or_create(SessionId::new(stream.session_id.clone())?)?;
        let user = runtime_user_message(&stream.runtime_turn_id, stream.user_body);
        let header = runtime_request_header(&stream.provider, &stream.model);
        let context = runtime_request_context(&stream.provider, &stream.model);
        let events = session.events()?;
        let Some((turn, step)) = runtime_preflight_location(&events, &user, &header, &context)
        else {
            return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                stream.session_id,
            ));
        };
        let recorded_messages = session
            .derive_messages()?
            .into_iter()
            .filter(|message| message.id == user.id)
            .collect::<Vec<_>>();
        let recorded_chunks = session.assistant_chunks(turn, step)?;
        let recorded_values = recorded_chunks
            .iter()
            .map(|chunk| chunk.chunk.clone())
            .collect::<Vec<_>>();
        let expected_chunks = runtime_live_chunks(stream.assistant_chunks);
        if runtime_open_turn(&events) != Some(turn)
            || recorded_messages != vec![user]
            || recorded_values.len() > expected_chunks.len()
            || !expected_chunks.starts_with(&recorded_values)
        {
            return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                stream.session_id,
            ));
        }
        for chunk in expected_chunks.into_iter().skip(recorded_values.len()) {
            session.append_assistant_chunk(turn, step, chunk)?;
        }
        self.session_persistence.persist_live(&session)
    }

    /// Append one closed, idempotent projection of a real Application Runtime
    /// turn and commit it through the existing SQLCipher Session adapter.
    #[allow(
        clippy::too_many_lines,
        reason = "one transactional boundary keeps exact replay validation and first Session append together"
    )]
    pub(crate) fn record_runtime_transcript(
        &mut self,
        transcript: DesktopRuntimeSessionTranscript,
    ) -> Result<(), DesktopSessionPersistenceError> {
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopSessionPersistenceError::MissingSessionStore)?;
        let session = sessions.get_or_create(SessionId::new(transcript.session_id.clone())?)?;
        let user = runtime_user_message(&transcript.runtime_turn_id, transcript.user_body);
        let assistant_chunks = transcript.assistant_chunks;
        let partial_body = assistant_chunks.concat();
        let assistant_body = transcript.assistant_body.or_else(|| {
            (transcript.end_reason == TurnEndReason::Interrupted && !partial_body.trim().is_empty())
                .then(|| partial_body.clone())
        });
        let assistant = assistant_body.as_ref().map(|body| SessionMessage {
            id: format!("runtime:{}:assistant", transcript.runtime_turn_id),
            role: SessionMessageRole::Assistant,
            content: vec![SessionContentBlock::Text { text: body.clone() }],
            source: SessionMessageSource::Model {
                provider: transcript.provider.clone(),
                model: transcript.model.clone(),
            },
        });
        let expected_header = runtime_request_header(&transcript.provider, &transcript.model);
        let expected_context = runtime_request_context(&transcript.provider, &transcript.model);
        let legacy_chunks = assistant_chunks
            .into_iter()
            .map(|text| SessionStreamChunk::TextDelta { index: 0, text })
            .collect::<Vec<_>>();
        let mut expected_chunks = Vec::with_capacity(legacy_chunks.len().saturating_add(3));
        let stream_body = assistant_body
            .clone()
            .or_else(|| (!legacy_chunks.is_empty()).then_some(partial_body));
        if stream_body.is_some() {
            expected_chunks.push(SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            });
        }
        expected_chunks.extend(legacy_chunks.iter().cloned());
        if let Some(body) = stream_body {
            expected_chunks.push(SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::Text { text: body },
            });
            if transcript.end_reason == TurnEndReason::Completed {
                expected_chunks.push(SessionStreamChunk::Finish {
                    reason: SessionFinishReason::Stop,
                    replay_state: None,
                });
            }
        }
        let expected = std::iter::once(&user)
            .chain(assistant.iter())
            .cloned()
            .collect::<Vec<_>>();
        let expected_ids = expected
            .iter()
            .map(|message| message.id.as_str())
            .collect::<Vec<_>>();
        let recorded = session
            .derive_messages()?
            .into_iter()
            .filter(|message| expected_ids.contains(&message.id.as_str()))
            .collect::<Vec<_>>();
        let events = session.events()?;
        let partial_location = if let Some(open_turn) = runtime_open_turn(&events) {
            let Some((turn, step)) =
                runtime_preflight_location(&events, &user, &expected_header, &expected_context)
            else {
                return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                    transcript.session_id,
                ));
            };
            let recorded_chunks = session.assistant_chunks(turn, step)?;
            let recorded_values = recorded_chunks
                .iter()
                .map(|chunk| chunk.chunk.clone())
                .collect::<Vec<_>>();
            if turn != open_turn
                || recorded.len() != 1
                || recorded.first() != Some(&user)
                || recorded_values.len() > expected_chunks.len()
                || !expected_chunks.starts_with(&recorded_values)
            {
                return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                    transcript.session_id,
                ));
            }
            Some((
                turn,
                step,
                recorded_chunks
                    .iter()
                    .map(|chunk| chunk.seq)
                    .collect::<Vec<_>>(),
            ))
        } else {
            None
        };
        if !recorded.is_empty() && partial_location.is_none() {
            if recorded != expected
                || session
                    .request_header()?
                    .as_ref()
                    .is_some_and(|header| header != &expected_header)
            {
                return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                    transcript.session_id,
                ));
            }
            if let Some(assistant) = assistant.as_ref() {
                let location = events.iter().find_map(|event| {
                    let SessionEventKind::AssistantMessage {
                        turn,
                        step,
                        message,
                        surface,
                    } = &event.kind
                    else {
                        return None;
                    };
                    (message.id == assistant.id).then(|| (*turn, *step, surface.clone()))
                });
                let Some((turn, step, surface)) = location else {
                    return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                        transcript.session_id,
                    ));
                };
                let recorded_chunks = session.assistant_chunks(turn, step)?;
                let recorded_chunk_seqs = recorded_chunks
                    .iter()
                    .map(|chunk| chunk.seq)
                    .collect::<Vec<_>>();
                let recorded_chunks = recorded_chunks
                    .into_iter()
                    .map(|chunk| chunk.chunk)
                    .collect::<Vec<_>>();
                if !recorded_chunks.is_empty()
                    && recorded_chunks != legacy_chunks
                    && recorded_chunks != expected_chunks
                {
                    return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                        transcript.session_id,
                    ));
                }
                let exact_provenance = recorded_chunks == expected_chunks
                    && surface == SessionSurfaceIntent::append_from(recorded_chunk_seqs);
                if surface != SessionSurfaceIntent::append() && !exact_provenance {
                    return Err(DesktopSessionPersistenceError::RuntimeTranscriptDiverged(
                        transcript.session_id,
                    ));
                }
            }
            return self.session_persistence.persist_live(&session);
        }

        let (turn, step, mut source_seqs) = if let Some(location) = partial_location {
            location
        } else {
            let (turn, step) =
                append_runtime_preflight(&session, user, expected_header, expected_context)?;
            (turn, step, Vec::new())
        };
        for chunk in expected_chunks.into_iter().skip(source_seqs.len()) {
            source_seqs.push(session.append_assistant_chunk(turn, step, chunk)?);
        }
        if let Some(message) = assistant {
            session.append_assistant_message_with_surface(
                turn,
                step,
                message,
                SessionSurfaceIntent::append_from(source_seqs),
            )?;
        }
        session.finish_step(turn, step)?;
        session.finish_turn(turn, transcript.end_reason)?;
        self.session_persistence.persist_live(&session)
    }

    fn next_binding_sequence(&self) -> Result<u64, CordisError> {
        self.successful_bindings.checked_add(1).ok_or_else(|| {
            CordisError::ProviderGenerationOverflow {
                key: keys::DOMAIN.to_string(),
            }
        })
    }

    fn record_binding(&mut self, refresh_sequence: u64, scope: Option<AuthorityScope>) {
        self.successful_bindings = refresh_sequence;
        self.last_binding = Some(DesktopCordisBindingState {
            root_fiber_uid: self.root_fiber.uid(),
            refresh_sequence,
            scope,
        });
    }

    #[cfg(test)]
    fn bind_domain_kernel(
        &mut self,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Result<(), CordisError> {
        self.ensure_root_fiber_active()?;
        let refresh_sequence = self.next_binding_sequence()?;
        self.host
            .bind_domain_kernel(consent, record, approval, now)?;
        self.record_binding(refresh_sequence, None);
        Ok(())
    }

    fn bind_domain_kernel_scope(
        &mut self,
        scope: AuthorityScope,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Result<DesktopCordisBindingReceipt, CordisError> {
        self.ensure_root_fiber_active()?;
        let refresh_sequence = self.next_binding_sequence()?;
        self.host
            .bind_domain_kernel_scope(scope.clone(), consent, record, approval, now)?;
        self.record_binding(refresh_sequence, Some(scope.clone()));
        Ok(DesktopCordisBindingReceipt {
            coordinator_identity: Arc::clone(&self.identity),
            root_fiber_uid: self.root_fiber.uid(),
            refresh_sequence,
            scope,
        })
    }

    fn consume_binding(
        &mut self,
        binding: DesktopCordisBindingReceipt,
    ) -> Result<AuthorityScope, CordisError> {
        let DesktopCordisBindingReceipt {
            coordinator_identity,
            root_fiber_uid,
            refresh_sequence,
            scope,
        } = binding;
        self.ensure_root_fiber_active()?;
        if !Arc::ptr_eq(&self.identity, &coordinator_identity)
            || root_fiber_uid != self.root_fiber.uid()
        {
            return Err(CordisError::AuthorityScopeMismatch);
        }
        let Some(current) = self.last_binding.as_ref() else {
            return Err(CordisError::AuthorityScopeUnbound);
        };
        if current.root_fiber_uid != root_fiber_uid
            || current.refresh_sequence != refresh_sequence
            || current.refresh_sequence != self.successful_bindings
            || current.scope.as_ref() != Some(&scope)
        {
            return Err(CordisError::AuthorityScopeMismatch);
        }
        self.last_binding = None;
        Ok(scope)
    }

    fn authorize_bound_runtime(
        &mut self,
        binding: DesktopCordisBindingReceipt,
    ) -> Result<RuntimeDispatchPermit, CordisError> {
        let scope = self.consume_binding(binding)?;
        self.host.authorize_runtime(&scope)
    }

    fn authorize_bound_domain_command(
        &mut self,
        binding: DesktopCordisBindingReceipt,
        command: DomainCommandBinding,
    ) -> Result<DomainCommandPermit, CordisError> {
        let scope = self.consume_binding(binding)?;
        self.host.authorize_domain_command(&scope, command)
    }

    fn authorize_bound_effect_execution(
        &mut self,
        binding: DesktopCordisBindingReceipt,
        effect: EffectExecutionBinding,
    ) -> Result<EffectExecutionPermit, CordisError> {
        let scope = self.consume_binding(binding)?;
        self.host.authorize_effect_execution(&scope, effect)
    }

    fn authorize_bound_effect_reconciliation(
        &mut self,
        binding: DesktopCordisBindingReceipt,
        effect: EffectReconciliationBinding,
    ) -> Result<EffectReconciliationPermit, CordisError> {
        let scope = self.consume_binding(binding)?;
        self.host.authorize_effect_reconciliation(&scope, effect)
    }

    fn authorize_bound_effect_verification(
        &mut self,
        binding: DesktopCordisBindingReceipt,
        effect: EffectVerificationBinding,
    ) -> Result<EffectVerificationPermit, CordisError> {
        let scope = self.consume_binding(binding)?;
        self.host.authorize_effect_verification(&scope, effect)
    }

    fn bind_and_authorize_runtime(
        &mut self,
        scope: AuthorityScope,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        now: DateTime<Utc>,
    ) -> Result<RuntimeDispatchPermit, CordisError> {
        let binding = self.bind_domain_kernel_scope(scope, consent, record, approval, now)?;
        self.authorize_bound_runtime(binding)
    }

    fn bind_and_authorize_domain_command(
        &mut self,
        scope: AuthorityScope,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        command: DomainCommandBinding,
        now: DateTime<Utc>,
    ) -> Result<DomainCommandPermit, CordisError> {
        let binding = self.bind_domain_kernel_scope(scope, consent, record, approval, now)?;
        self.authorize_bound_domain_command(binding, command)
    }

    fn bind_and_authorize_effect_execution(
        &mut self,
        scope: AuthorityScope,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        effect: EffectExecutionBinding,
        now: DateTime<Utc>,
    ) -> Result<EffectExecutionPermit, CordisError> {
        let binding = self.bind_domain_kernel_scope(scope, consent, record, approval, now)?;
        self.authorize_bound_effect_execution(binding, effect)
    }

    fn bind_and_authorize_effect_reconciliation(
        &mut self,
        scope: AuthorityScope,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        effect: EffectReconciliationBinding,
        now: DateTime<Utc>,
    ) -> Result<EffectReconciliationPermit, CordisError> {
        let binding = self.bind_domain_kernel_scope(scope, consent, record, approval, now)?;
        self.authorize_bound_effect_reconciliation(binding, effect)
    }

    fn bind_and_authorize_effect_verification(
        &mut self,
        scope: AuthorityScope,
        consent: KernelConsentState,
        record: Option<KernelConsentRecord>,
        approval: Option<KernelApproval>,
        effect: EffectVerificationBinding,
        now: DateTime<Utc>,
    ) -> Result<EffectVerificationPermit, CordisError> {
        let binding = self.bind_domain_kernel_scope(scope, consent, record, approval, now)?;
        self.authorize_bound_effect_verification(binding, effect)
    }

    fn finish_runtime(
        &mut self,
        permit: RuntimeDispatchPermit,
    ) -> Result<RuntimeDispatchCompletion, CordisError> {
        self.host.finish_runtime(permit)
    }

    fn finish_domain_command(&mut self, permit: DomainCommandPermit) -> Result<(), CordisError> {
        self.host.finish_domain_command(permit)
    }

    fn finish_effect_execution(
        &mut self,
        permit: EffectExecutionPermit,
    ) -> Result<(), CordisError> {
        self.host.finish_effect_execution(permit)
    }

    fn finish_effect_reconciliation(
        &mut self,
        permit: EffectReconciliationPermit,
    ) -> Result<(), CordisError> {
        self.host.finish_effect_reconciliation(permit)
    }

    fn finish_effect_verification(
        &mut self,
        permit: EffectVerificationPermit,
    ) -> Result<(), CordisError> {
        self.host.finish_effect_verification(permit)
    }

    #[cfg(test)]
    pub(crate) fn host_mut(&mut self) -> &mut CordisHost {
        &mut self.host
    }

    #[cfg(test)]
    #[must_use]
    fn root_fiber(&self) -> &Fiber {
        &self.root_fiber
    }

    #[cfg(test)]
    #[must_use]
    fn last_binding(&self) -> Option<&DesktopCordisBindingState> {
        self.last_binding.as_ref()
    }

    #[cfg(test)]
    #[must_use]
    const fn successful_bindings(&self) -> u64 {
        self.successful_bindings
    }
}

#[cfg(test)]
impl Deref for DesktopCordisCoordinator {
    type Target = CordisHost;

    fn deref(&self) -> &Self::Target {
        &self.host
    }
}

#[cfg(test)]
impl DerefMut for DesktopCordisCoordinator {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.host
    }
}

/// Boot SurfaceMapping + AgentLoop + InvariantGate for this desktop process.
///
/// Production mount is fail-closed: consent/approval stay false until
/// the exact scoped runtime adapter reads live Domain Kernel facts.
pub(crate) fn mount_cordis_host(
    runtime: &DesktopRuntimeProjection,
) -> Result<DesktopCordisCoordinator, CordisError> {
    let mut host = CordisHost::boot(openinterpreter_runtime_plugin(runtime))?;
    host_is_cordis_loop(&host)?;
    let session_persistence = DesktopSessionPersistence::default();
    session_persistence.mount(&mut host)?;
    DesktopCordisCoordinator::new(host, session_persistence)
}

/// Desktop-owned SQLCipher adapter for Cordis' storage-agnostic Session seam.
///
/// `session/event` only marks the live prefix dirty. The awaited
/// `session/flush` callback is the single durability boundary and extends the
/// encrypted log transactionally. The already-open database connection is
/// retained; raw key bytes never enter Cordis or either listener.
#[derive(Clone, Debug, Default)]
struct DesktopSessionPersistence {
    store: Arc<Mutex<Option<ProjectStore>>>,
    observed: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl DesktopSessionPersistence {
    fn mount(&self, host: &mut CordisHost) -> Result<(), CordisError> {
        let observed = Arc::clone(&self.observed);
        host.context_mut().on_emit(
            session_events::SESSION_EVENT,
            move |record: &SessionEventRecord| {
                observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(record.header.id.as_str().to_owned(), record.event.seq);
            },
        )?;

        let persistence = self.clone();
        host.context_mut().on_parallel(
            session_events::SESSION_FLUSH,
            move |checkpoint: SessionCheckpoint| {
                let persistence = persistence.clone();
                async move { persistence.persist(&checkpoint) }
            },
        )?;
        Ok(())
    }

    fn bind_and_restore(
        &self,
        mut store: ProjectStore,
        sessions: &SessionStore,
    ) -> Result<usize, DesktopSessionPersistenceError> {
        let checkpoints = store
            .load_session_checkpoints()?
            .into_iter()
            .map(decode_checkpoint)
            .collect::<Result<Vec<_>, _>>()?;
        let mut prepared = Vec::with_capacity(checkpoints.len());
        for (header, events) in checkpoints {
            let mut log = SessionLog::restore(header.clone(), events)?;
            if let Some(live) = sessions.get(&header.id)? {
                let live_header = live.header()?;
                let live_events = live.events()?;
                if live_header != header || !live_events.starts_with(log.events()) {
                    return Err(DesktopSessionPersistenceError::LiveSessionDiverged(
                        header.id.to_string(),
                    ));
                }
                prepared.push((header, log.events().to_vec(), true, false));
            } else {
                let repaired = log.repair_interrupted_tail()?;
                prepared.push((header, log.events().to_vec(), false, repaired));
            }
        }

        for (header, events, live, repaired) in &prepared {
            if !live && *repaired {
                store.persist_session_checkpoint(&encode_checkpoint(&SessionCheckpoint {
                    header: header.clone(),
                    events: events.clone(),
                })?)?;
            }
        }

        let mut restored = 0;
        for (header, events, live, _) in prepared {
            if !live {
                sessions.restore(header, events)?;
                restored += 1;
            }
        }
        *self
            .store
            .lock()
            .map_err(|_| DesktopSessionPersistenceError::StatePoisoned)? = Some(store);
        Ok(restored)
    }

    fn persist(
        &self,
        checkpoint: &SessionCheckpoint,
    ) -> Result<(), DesktopSessionPersistenceError> {
        SessionLog::restore(checkpoint.header.clone(), checkpoint.events.clone())?;
        let persisted = encode_checkpoint(checkpoint)?;
        let mut state = self
            .store
            .lock()
            .map_err(|_| DesktopSessionPersistenceError::StatePoisoned)?;
        let store = state
            .as_mut()
            .ok_or(DesktopSessionPersistenceError::Unbound)?;
        store.persist_session_checkpoint(&persisted)?;
        drop(state);

        if let Some(through_seq) = checkpoint.through_seq() {
            let mut observed = self
                .observed
                .lock()
                .map_err(|_| DesktopSessionPersistenceError::StatePoisoned)?;
            if observed
                .get(checkpoint.header.id.as_str())
                .is_some_and(|seen| *seen <= through_seq)
            {
                observed.remove(checkpoint.header.id.as_str());
            }
        }
        Ok(())
    }

    fn persist_live(&self, session: &SessionHandle) -> Result<(), DesktopSessionPersistenceError> {
        self.persist(&SessionCheckpoint {
            header: session.header()?,
            events: session.events()?,
        })
    }
}

#[derive(Debug, Error)]
pub(crate) enum DesktopSessionPersistenceError {
    #[error("Desktop Session persistence is not bound to an unlocked database")]
    Unbound,
    #[error("Desktop Session persistence state is poisoned")]
    StatePoisoned,
    #[error("Cordis did not mount its Session store")]
    MissingSessionStore,
    #[error("live Cordis Session {0} diverges from its durable prefix")]
    LiveSessionDiverged(String),
    #[error("Cordis Runtime transcript for Session {0} diverges from its exact turn identity")]
    RuntimeTranscriptDiverged(String),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Session(#[from] SessionError),
}

fn encode_checkpoint(
    checkpoint: &SessionCheckpoint,
) -> Result<PersistedSessionCheckpoint, DesktopSessionPersistenceError> {
    Ok(PersistedSessionCheckpoint {
        header: PersistedSessionHeader {
            version: checkpoint.header.version,
            id: checkpoint.header.id.as_str().to_owned(),
            created_at_ms: checkpoint.header.created_at_ms,
            parent_session: checkpoint
                .header
                .parent_session
                .as_ref()
                .map(|id| id.as_str().to_owned()),
            seed_length: checkpoint.header.seed_length,
        },
        events: checkpoint
            .events
            .iter()
            .map(encode_event)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn encode_event(
    event: &SessionEvent,
) -> Result<PersistedSessionEvent, DesktopSessionPersistenceError> {
    Ok(PersistedSessionEvent {
        seq: event.seq,
        time_ms: event.time_ms,
        kind: match &event.kind {
            SessionEventKind::TurnStart { turn } => {
                PersistedSessionEventKind::TurnStart { turn: *turn }
            }
            SessionEventKind::TurnEnd { turn, reason } => PersistedSessionEventKind::TurnEnd {
                turn: *turn,
                reason: encode_turn_end_reason(*reason),
            },
            SessionEventKind::StepStart { turn, step } => PersistedSessionEventKind::StepStart {
                turn: *turn,
                step: *step,
            },
            SessionEventKind::StepEnd { turn, step } => PersistedSessionEventKind::StepEnd {
                turn: *turn,
                step: *step,
            },
            SessionEventKind::AgentInboxSpliced {
                target,
                start,
                removed_count,
                inserted,
                outcome,
            } => PersistedSessionEventKind::AgentInboxSpliced {
                target: encode_inbox_target(*target),
                start: *start,
                removed_count: *removed_count,
                inserted: inserted
                    .iter()
                    .map(SessionMessage::to_json_value)
                    .collect::<Result<Vec<_>, _>>()?,
                outcome: outcome.map(encode_inbox_outcome),
            },
            SessionEventKind::UserMessage { message, surface } => {
                PersistedSessionEventKind::UserMessage {
                    message: message.to_json_value()?,
                    surface: Some(surface.to_json_value()?),
                }
            }
            SessionEventKind::AssistantChunk { turn, step, chunk } => {
                PersistedSessionEventKind::AssistantChunk {
                    turn: *turn,
                    step: *step,
                    chunk: chunk.to_json_value()?,
                }
            }
            SessionEventKind::RequestHeader { request } => {
                PersistedSessionEventKind::RequestHeader {
                    request: request.to_json_value()?,
                }
            }
            SessionEventKind::RequestContext { context } => {
                PersistedSessionEventKind::RequestContext {
                    context: context.to_json_value()?,
                }
            }
            SessionEventKind::ToolCall {
                turn,
                step,
                call_id,
                name,
                arguments,
            } => PersistedSessionEventKind::ToolCall {
                turn: *turn,
                step: *step,
                call_id: call_id.clone(),
                name: name.clone(),
                arguments: arguments.clone(),
            },
            SessionEventKind::AssistantMessage {
                turn,
                step,
                message,
                surface,
            } => PersistedSessionEventKind::AssistantMessage {
                turn: *turn,
                step: *step,
                message: message.to_json_value()?,
                surface: Some(surface.to_json_value()?),
            },
            SessionEventKind::ToolResult {
                turn,
                step,
                message,
                error,
                surface,
            } => PersistedSessionEventKind::ToolResult {
                turn: *turn,
                step: *step,
                message: message.to_json_value()?,
                error: error.as_ref().map(|error| PersistedSessionToolError {
                    name: error.name.clone(),
                    code: error.code.clone(),
                }),
                surface: Some(surface.to_json_value()?),
            },
        },
    })
}

const fn encode_turn_end_reason(reason: TurnEndReason) -> PersistedTurnEndReason {
    match reason {
        TurnEndReason::Completed => PersistedTurnEndReason::Completed,
        TurnEndReason::Aborted(cause) => {
            PersistedTurnEndReason::Aborted(encode_cancel_cause(cause))
        }
        TurnEndReason::Blocked => PersistedTurnEndReason::Blocked,
        TurnEndReason::Error => PersistedTurnEndReason::Error,
        TurnEndReason::MaxTokens => PersistedTurnEndReason::MaxTokens,
        TurnEndReason::Interrupted => PersistedTurnEndReason::Interrupted,
    }
}

const fn encode_inbox_target(target: AgentInboxTarget) -> PersistedAgentInboxTarget {
    match target {
        AgentInboxTarget::NextTurn => PersistedAgentInboxTarget::NextTurn,
        AgentInboxTarget::NextStep => PersistedAgentInboxTarget::NextStep,
    }
}

const fn encode_inbox_outcome(outcome: AgentInboxOutcome) -> PersistedAgentInboxOutcome {
    match outcome {
        AgentInboxOutcome::Canceled => PersistedAgentInboxOutcome::Canceled,
    }
}

const fn encode_cancel_cause(cause: SessionCancelCause) -> PersistedSessionCancelCause {
    match cause {
        SessionCancelCause::User => PersistedSessionCancelCause::User,
        SessionCancelCause::Parent => PersistedSessionCancelCause::Parent,
        SessionCancelCause::Hook => PersistedSessionCancelCause::Hook,
        SessionCancelCause::Disposed => PersistedSessionCancelCause::Disposed,
        SessionCancelCause::Legacy => PersistedSessionCancelCause::Legacy,
    }
}

fn decode_checkpoint(
    checkpoint: PersistedSessionCheckpoint,
) -> Result<(SessionHeader, Vec<SessionEvent>), DesktopSessionPersistenceError> {
    let header = SessionHeader {
        version: checkpoint.header.version,
        id: SessionId::new(checkpoint.header.id)?,
        created_at_ms: checkpoint.header.created_at_ms,
        parent_session: checkpoint
            .header
            .parent_session
            .map(SessionId::new)
            .transpose()?,
        seed_length: checkpoint.header.seed_length,
    };
    let events = checkpoint
        .events
        .iter()
        .map(decode_event)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((header, events))
}

fn decode_event(
    event: &PersistedSessionEvent,
) -> Result<SessionEvent, DesktopSessionPersistenceError> {
    Ok(SessionEvent {
        seq: event.seq,
        time_ms: event.time_ms,
        kind: match &event.kind {
            PersistedSessionEventKind::TurnStart { turn } => {
                SessionEventKind::TurnStart { turn: *turn }
            }
            PersistedSessionEventKind::TurnEnd { turn, reason } => SessionEventKind::TurnEnd {
                turn: *turn,
                reason: decode_turn_end_reason(*reason),
            },
            PersistedSessionEventKind::StepStart { turn, step } => SessionEventKind::StepStart {
                turn: *turn,
                step: *step,
            },
            PersistedSessionEventKind::StepEnd { turn, step } => SessionEventKind::StepEnd {
                turn: *turn,
                step: *step,
            },
            PersistedSessionEventKind::AgentInboxSpliced {
                target,
                start,
                removed_count,
                inserted,
                outcome,
            } => decode_inbox_splice(*target, *start, *removed_count, inserted, *outcome)?,
            PersistedSessionEventKind::UserMessage { message, surface } => {
                decode_user_message(message, surface.as_ref())?
            }
            PersistedSessionEventKind::AssistantChunk { turn, step, chunk } => {
                SessionEventKind::AssistantChunk {
                    turn: *turn,
                    step: *step,
                    chunk: SessionStreamChunk::from_json_value(chunk)?,
                }
            }
            PersistedSessionEventKind::RequestHeader { request } => {
                SessionEventKind::RequestHeader {
                    request: SessionRequestHeader::from_json_value(request)?,
                }
            }
            PersistedSessionEventKind::RequestContext { context } => {
                SessionEventKind::RequestContext {
                    context: SessionRequestContext::from_json_value(context)?,
                }
            }
            PersistedSessionEventKind::ToolCall {
                turn,
                step,
                call_id,
                name,
                arguments,
            } => SessionEventKind::ToolCall {
                turn: *turn,
                step: *step,
                call_id: call_id.clone(),
                name: name.clone(),
                arguments: arguments.clone(),
            },
            PersistedSessionEventKind::AssistantMessage {
                turn,
                step,
                message,
                surface,
            } => SessionEventKind::AssistantMessage {
                turn: *turn,
                step: *step,
                message: SessionMessage::from_json_value(message.clone())?,
                surface: surface.as_ref().map_or_else(
                    || Ok(SessionSurfaceIntent::append()),
                    |value| {
                        SessionSurfaceIntent::from_json_value(value.clone())
                            .map_err(DesktopSessionPersistenceError::from)
                    },
                )?,
            },
            PersistedSessionEventKind::ToolResult {
                turn,
                step,
                message,
                error,
                surface,
            } => SessionEventKind::ToolResult {
                turn: *turn,
                step: *step,
                message: SessionMessage::from_json_value(message.clone())?,
                error: decode_tool_error(error.as_ref()),
                surface: surface.as_ref().map_or_else(
                    || Ok(SessionSurfaceIntent::append()),
                    |value| {
                        SessionSurfaceIntent::from_json_value(value.clone())
                            .map_err(DesktopSessionPersistenceError::from)
                    },
                )?,
            },
        },
    })
}

fn decode_inbox_splice(
    target: PersistedAgentInboxTarget,
    start: u64,
    removed_count: Option<u64>,
    inserted: &[serde_json::Value],
    outcome: Option<PersistedAgentInboxOutcome>,
) -> Result<SessionEventKind, DesktopSessionPersistenceError> {
    Ok(SessionEventKind::AgentInboxSpliced {
        target: decode_inbox_target(target),
        start,
        removed_count,
        inserted: inserted
            .iter()
            .cloned()
            .map(SessionMessage::from_json_value)
            .collect::<Result<Vec<_>, _>>()?,
        outcome: outcome.map(decode_inbox_outcome),
    })
}

fn decode_user_message(
    message: &serde_json::Value,
    surface: Option<&serde_json::Value>,
) -> Result<SessionEventKind, DesktopSessionPersistenceError> {
    Ok(SessionEventKind::UserMessage {
        message: SessionMessage::from_json_value(message.clone())?,
        // N22 rows predate surface metadata and were append-only.
        surface: surface.map_or_else(
            || Ok(SessionSurfaceIntent::append()),
            |value| {
                SessionSurfaceIntent::from_json_value(value.clone())
                    .map_err(DesktopSessionPersistenceError::from)
            },
        )?,
    })
}

fn decode_tool_error(error: Option<&PersistedSessionToolError>) -> Option<SessionToolError> {
    error.map(|error| SessionToolError {
        name: error.name.clone(),
        code: error.code.clone(),
    })
}

const fn decode_turn_end_reason(reason: PersistedTurnEndReason) -> TurnEndReason {
    match reason {
        PersistedTurnEndReason::Completed => TurnEndReason::Completed,
        PersistedTurnEndReason::Aborted(cause) => {
            TurnEndReason::Aborted(decode_cancel_cause(cause))
        }
        PersistedTurnEndReason::Blocked => TurnEndReason::Blocked,
        PersistedTurnEndReason::Error => TurnEndReason::Error,
        PersistedTurnEndReason::MaxTokens => TurnEndReason::MaxTokens,
        PersistedTurnEndReason::Interrupted => TurnEndReason::Interrupted,
    }
}

const fn decode_inbox_target(target: PersistedAgentInboxTarget) -> AgentInboxTarget {
    match target {
        PersistedAgentInboxTarget::NextTurn => AgentInboxTarget::NextTurn,
        PersistedAgentInboxTarget::NextStep => AgentInboxTarget::NextStep,
    }
}

const fn decode_inbox_outcome(outcome: PersistedAgentInboxOutcome) -> AgentInboxOutcome {
    match outcome {
        PersistedAgentInboxOutcome::Canceled => AgentInboxOutcome::Canceled,
    }
}

const fn decode_cancel_cause(cause: PersistedSessionCancelCause) -> SessionCancelCause {
    match cause {
        PersistedSessionCancelCause::User => SessionCancelCause::User,
        PersistedSessionCancelCause::Parent => SessionCancelCause::Parent,
        PersistedSessionCancelCause::Hook => SessionCancelCause::Hook,
        PersistedSessionCancelCause::Disposed => SessionCancelCause::Disposed,
        PersistedSessionCancelCause::Legacy => SessionCancelCause::Legacy,
    }
}

/// Map a Domain Kernel [`ConsentState`] onto the host-side DTO.
#[must_use]
fn kernel_consent_state(state: &ConsentState) -> KernelConsentState {
    match state {
        ConsentState::NotRequired => KernelConsentState::NotRequired,
        ConsentState::Confirmed => KernelConsentState::Confirmed,
        ConsentState::Missing => KernelConsentState::Missing,
        ConsentState::Withdrawn => KernelConsentState::Withdrawn,
    }
}

/// Map a live Domain Kernel [`ConsentRecord`] onto the host-side DTO.
#[must_use]
fn kernel_consent_record(record: &ConsentRecord) -> KernelConsentRecord {
    KernelConsentRecord {
        status: match record.status {
            ConsentStatus::Granted => KernelConsentStatus::Granted,
            ConsentStatus::Denied => KernelConsentStatus::Denied,
            ConsentStatus::Withdrawn => KernelConsentStatus::Withdrawn,
            ConsentStatus::Expired => KernelConsentStatus::Expired,
        },
        granted_at: record.granted_at,
        valid_until: record.valid_until,
        withdrawn_at: record.withdrawn_at,
    }
}

/// Map a live Domain Kernel [`Approval`] onto the host-side DTO.
#[must_use]
fn kernel_approval(approval: &Approval) -> KernelApproval {
    KernelApproval {
        decision: match approval.decision {
            ApprovalDecision::Approved => KernelApprovalDecision::Approved,
            ApprovalDecision::Rejected => KernelApprovalDecision::Rejected,
        },
        valid_until: approval.valid_until,
    }
}

/// Test-only unscoped Domain Kernel fact binding.
#[cfg(test)]
pub(crate) fn bind_live_domain_kernel(
    host: &mut DesktopCordisCoordinator,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
) -> Result<(), CordisError> {
    host.bind_domain_kernel(
        kernel_consent_state(consent),
        record.map(kernel_consent_record),
        approval.map(kernel_approval),
        now,
    )
}

/// Test-only exact Project/Mission binding receipt.
#[cfg(test)]
fn bind_live_domain_kernel_scope(
    host: &mut DesktopCordisCoordinator,
    scope: AuthorityScope,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
) -> Result<DesktopCordisBindingReceipt, CordisError> {
    host.bind_domain_kernel_scope(
        scope,
        kernel_consent_state(consent),
        record.map(kernel_consent_record),
        approval.map(kernel_approval),
        now,
    )
}

/// Test-only compatibility seam for DataPlane invariant fixtures.
#[cfg(test)]
pub(crate) fn bind_live_domain_kernel_scope_for_test(
    host: &mut DesktopCordisCoordinator,
    scope: AuthorityScope,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
) -> Result<(), CordisError> {
    bind_live_domain_kernel_scope(host, scope, consent, record, approval, now).map(drop)
}

/// Private Desktop adapter for the one Cordis-authorized Application call.
///
/// Keeping the closure inside this type makes the production composition seam
/// explicit without making generic Cordis depend on ApplicationService.
pub(crate) struct DesktopRuntimeAuthority<Execute> {
    execute: Execute,
}

impl<Execute> DesktopRuntimeAuthority<Execute> {
    pub(crate) fn new(execute: Execute) -> Self {
        Self { execute }
    }
}

impl<Execute, Output, AdapterError> RuntimeAuthority for DesktopRuntimeAuthority<Execute>
where
    Execute: FnOnce(&RuntimeDispatchPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn execute(self, permit: &RuntimeDispatchPermit) -> Result<Self::Output, Self::Error> {
        (self.execute)(permit)
    }
}

/// Private Desktop adapter for one Cordis-authorized Domain command.
struct DesktopDomainCommandAuthority<Execute> {
    execute: Execute,
}

impl<Execute> DesktopDomainCommandAuthority<Execute> {
    fn new(execute: Execute) -> Self {
        Self { execute }
    }
}

impl<Execute, Output, AdapterError> DomainCommandAuthority
    for DesktopDomainCommandAuthority<Execute>
where
    Execute: FnOnce(&DomainCommandPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn execute(self, permit: &DomainCommandPermit) -> Result<Self::Output, Self::Error> {
        (self.execute)(permit)
    }
}

/// Private Desktop adapter for one Cordis-authorized Effect Broker execution.
struct DesktopEffectExecutionAuthority<Execute> {
    execute: Execute,
}

impl<Execute> DesktopEffectExecutionAuthority<Execute> {
    fn new(execute: Execute) -> Self {
        Self { execute }
    }
}

impl<Execute, Output, AdapterError> EffectExecutionAuthority
    for DesktopEffectExecutionAuthority<Execute>
where
    Execute: FnOnce(&EffectExecutionPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn execute(self, permit: &EffectExecutionPermit) -> Result<Self::Output, Self::Error> {
        (self.execute)(permit)
    }
}

/// Private Desktop adapter for one Cordis-authorized read reconciliation.
struct DesktopEffectReconciliationAuthority<Observe> {
    observe: Observe,
}

impl<Observe> DesktopEffectReconciliationAuthority<Observe> {
    fn new(observe: Observe) -> Self {
        Self { observe }
    }
}

impl<Observe, Output, AdapterError> EffectReconciliationAuthority
    for DesktopEffectReconciliationAuthority<Observe>
where
    Observe: FnOnce(&EffectReconciliationPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn reconcile(self, permit: &EffectReconciliationPermit) -> Result<Self::Output, Self::Error> {
        (self.observe)(permit)
    }
}

/// Private Desktop adapter for one Cordis-authorized independent verification.
struct DesktopEffectVerificationAuthority<Verify> {
    verify: Verify,
}

impl<Verify> DesktopEffectVerificationAuthority<Verify> {
    fn new(verify: Verify) -> Self {
        Self { verify }
    }
}

impl<Verify, Output, AdapterError> EffectVerificationAuthority
    for DesktopEffectVerificationAuthority<Verify>
where
    Verify: FnOnce(&EffectVerificationPermit) -> Result<Output, AdapterError>,
{
    type Output = Output;
    type Error = AdapterError;

    fn verify(self, permit: &EffectVerificationPermit) -> Result<Self::Output, Self::Error> {
        (self.verify)(permit)
    }
}

/// Exact Cordis scope plus the single Domain command admitted in that scope.
pub(crate) struct DesktopDomainCommandAuthorization {
    scope: AuthorityScope,
    command: DomainCommandBinding,
}

impl DesktopDomainCommandAuthorization {
    pub(crate) fn new(scope: AuthorityScope, command: DomainCommandBinding) -> Self {
        Self { scope, command }
    }
}

/// Exact Cordis scope plus the immutable approved Effect fence admitted in it.
pub(crate) struct DesktopEffectExecutionAuthorization {
    scope: AuthorityScope,
    effect: EffectExecutionBinding,
}

impl DesktopEffectExecutionAuthorization {
    pub(crate) fn new(scope: AuthorityScope, effect: EffectExecutionBinding) -> Self {
        Self { scope, effect }
    }
}

/// Exact Cordis scope plus the immutable uncertain-Effect fence admitted for
/// read reconciliation. It grants no execution or provider-write capability.
pub(crate) struct DesktopEffectReconciliationAuthorization {
    scope: AuthorityScope,
    effect: EffectReconciliationBinding,
}

impl DesktopEffectReconciliationAuthorization {
    pub(crate) fn new(scope: AuthorityScope, effect: EffectReconciliationBinding) -> Self {
        Self { scope, effect }
    }
}

/// Exact Cordis scope plus the immutable independent-verification fence.
pub(crate) struct DesktopEffectVerificationAuthorization {
    scope: AuthorityScope,
    effect: EffectVerificationBinding,
}

impl DesktopEffectVerificationAuthorization {
    pub(crate) fn new(scope: AuthorityScope, effect: EffectVerificationBinding) -> Self {
        Self { scope, effect }
    }
}

/// Bind exact live facts, obtain an unforgeable Cordis permit, release the
/// host lock, execute the real Desktop/Application adapter exactly once, and
/// settle the lifecycle under a second short lock.
pub(crate) fn dispatch_live_runtime<Execute, Output, AdapterError>(
    cordis: &Arc<Mutex<DesktopCordisCoordinator>>,
    scope: AuthorityScope,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
    execute: Execute,
) -> Result<Output, AuthorityDispatchError<AdapterError>>
where
    Execute: FnOnce(&RuntimeDispatchPermit) -> Result<Output, AdapterError>,
{
    let mut permit = {
        let mut host = cordis
            .lock()
            .map_err(|_| CordisError::RuntimeCoordinatorPoisoned)?;
        host.bind_and_authorize_runtime(
            scope,
            kernel_consent_state(consent),
            record.map(kernel_consent_record),
            approval.map(kernel_approval),
            now,
        )?
    };
    let started = permit.announce_started().err();
    let (output, authority) = if started.is_none() {
        match DesktopRuntimeAuthority::new(execute).execute(&permit) {
            Ok(output) => (Some(output), None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };

    let completion = match cordis.lock() {
        Ok(mut host) => host.finish_runtime(permit),
        Err(_) => Err(CordisError::RuntimeCoordinatorPoisoned),
    };
    let (finish, disposed) = match completion {
        Ok(completion) => (None, completion.announce().err()),
        Err(error) => (Some(error), None),
    };
    if let Some(error) = AuthorityDispatchError::from_phases(started, authority, finish, disposed) {
        Err(error)
    } else {
        output.ok_or_else(|| {
            AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimePermitMismatch))
        })
    }
}

/// Bind exact live facts, issue a one-shot Domain-command permit, release the
/// coordinator lock for Application, then settle the permit under a second
/// short lock. This path grants no Effect execution capability.
pub(crate) fn dispatch_live_domain_command<Execute, Output, AdapterError>(
    cordis: &Arc<Mutex<DesktopCordisCoordinator>>,
    authorization: DesktopDomainCommandAuthorization,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
    execute: Execute,
) -> Result<Output, AuthorityDispatchError<AdapterError>>
where
    Execute: FnOnce(&DomainCommandPermit) -> Result<Output, AdapterError>,
{
    let DesktopDomainCommandAuthorization { scope, command } = authorization;
    let permit = {
        let mut host = cordis
            .lock()
            .map_err(|_| CordisError::DomainCommandCoordinatorPoisoned)?;
        host.bind_and_authorize_domain_command(
            scope,
            kernel_consent_state(consent),
            record.map(kernel_consent_record),
            approval.map(kernel_approval),
            command,
            now,
        )?
    };
    let (output, authority) = match DesktopDomainCommandAuthority::new(execute).execute(&permit) {
        Ok(output) => (Some(output), None),
        Err(error) => (None, Some(error)),
    };
    let finish = match cordis.lock() {
        Ok(mut host) => host.finish_domain_command(permit).err(),
        Err(_) => Some(CordisError::DomainCommandCoordinatorPoisoned),
    };
    if let Some(error) = AuthorityDispatchError::from_phases(None, authority, finish, None) {
        Err(error)
    } else {
        output.ok_or_else(|| {
            AuthorityDispatchError::Cordis(Box::new(CordisError::DomainCommandPermitMismatch))
        })
    }
}

/// Bind exact live facts, issue a one-shot Effect-execution permit, release the
/// coordinator lock for Application/Broker/provider work, then settle under a
/// second short lock. Cordis receives no external-write capability or result.
pub(crate) fn dispatch_live_effect_execution<Execute, Output, AdapterError>(
    cordis: &Arc<Mutex<DesktopCordisCoordinator>>,
    authorization: DesktopEffectExecutionAuthorization,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: &Approval,
    now: DateTime<Utc>,
    execute: Execute,
) -> Result<Output, AuthorityDispatchError<AdapterError>>
where
    Execute: FnOnce(&EffectExecutionPermit) -> Result<Output, AdapterError>,
{
    let DesktopEffectExecutionAuthorization { scope, effect } = authorization;
    let permit = {
        let mut host = cordis
            .lock()
            .map_err(|_| CordisError::EffectExecutionCoordinatorPoisoned)?;
        host.bind_and_authorize_effect_execution(
            scope,
            kernel_consent_state(consent),
            record.map(kernel_consent_record),
            Some(kernel_approval(approval)),
            effect,
            now,
        )?
    };
    let (output, authority) = match DesktopEffectExecutionAuthority::new(execute).execute(&permit) {
        Ok(output) => (Some(output), None),
        Err(error) => (None, Some(error)),
    };
    let finish = match cordis.lock() {
        Ok(mut host) => host.finish_effect_execution(permit).err(),
        Err(_) => Some(CordisError::EffectExecutionCoordinatorPoisoned),
    };
    if let Some(error) = AuthorityDispatchError::from_phases(None, authority, finish, None) {
        Err(error)
    } else {
        output.ok_or_else(|| {
            AuthorityDispatchError::Cordis(Box::new(CordisError::EffectExecutionPermitMismatch))
        })
    }
}

/// Bind exact live facts, issue a one-shot read-reconciliation permit, release
/// the coordinator lock for Application/Broker/observer/verifier work, then
/// settle under a second short lock. No executor exists in this signature.
pub(crate) fn dispatch_live_effect_reconciliation<Observe, Output, AdapterError>(
    cordis: &Arc<Mutex<DesktopCordisCoordinator>>,
    authorization: DesktopEffectReconciliationAuthorization,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
    observe: Observe,
) -> Result<Output, AuthorityDispatchError<AdapterError>>
where
    Observe: FnOnce(&EffectReconciliationPermit) -> Result<Output, AdapterError>,
{
    let DesktopEffectReconciliationAuthorization { scope, effect } = authorization;
    let permit = {
        let mut host = cordis
            .lock()
            .map_err(|_| CordisError::EffectReconciliationCoordinatorPoisoned)?;
        host.bind_and_authorize_effect_reconciliation(
            scope,
            kernel_consent_state(consent),
            record.map(kernel_consent_record),
            approval.map(kernel_approval),
            effect,
            now,
        )?
    };
    let (output, authority) =
        match DesktopEffectReconciliationAuthority::new(observe).reconcile(&permit) {
            Ok(output) => (Some(output), None),
            Err(error) => (None, Some(error)),
        };
    let finish = match cordis.lock() {
        Ok(mut host) => host.finish_effect_reconciliation(permit).err(),
        Err(_) => Some(CordisError::EffectReconciliationCoordinatorPoisoned),
    };
    if let Some(error) = AuthorityDispatchError::from_phases(None, authority, finish, None) {
        Err(error)
    } else {
        output.ok_or_else(|| {
            AuthorityDispatchError::Cordis(Box::new(
                CordisError::EffectReconciliationPermitMismatch,
            ))
        })
    }
}

/// Bind exact live facts, issue a one-shot independent-verification permit,
/// release the coordinator lock for Application/Broker/source work, then
/// settle under a second short lock. No executor, reconciler, or generic
/// EffectVerifier is present in this signature.
pub(crate) fn dispatch_live_effect_verification<Verify, Output, AdapterError>(
    cordis: &Arc<Mutex<DesktopCordisCoordinator>>,
    authorization: DesktopEffectVerificationAuthorization,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
    verify: Verify,
) -> Result<Output, AuthorityDispatchError<AdapterError>>
where
    Verify: FnOnce(&EffectVerificationPermit) -> Result<Output, AdapterError>,
{
    let DesktopEffectVerificationAuthorization { scope, effect } = authorization;
    let permit = {
        let mut host = cordis
            .lock()
            .map_err(|_| CordisError::EffectVerificationCoordinatorPoisoned)?;
        host.bind_and_authorize_effect_verification(
            scope,
            kernel_consent_state(consent),
            record.map(kernel_consent_record),
            approval.map(kernel_approval),
            effect,
            now,
        )?
    };
    let (output, authority) = match DesktopEffectVerificationAuthority::new(verify).verify(&permit)
    {
        Ok(output) => (Some(output), None),
        Err(error) => (None, Some(error)),
    };
    let finish = match cordis.lock() {
        Ok(mut host) => host.finish_effect_verification(permit).err(),
        Err(_) => Some(CordisError::EffectVerificationCoordinatorPoisoned),
    };
    if let Some(error) = AuthorityDispatchError::from_phases(None, authority, finish, None) {
        Err(error)
    } else {
        output.ok_or_else(|| {
            AuthorityDispatchError::Cordis(Box::new(CordisError::EffectVerificationPermitMismatch))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt::{self, Display};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::thread;
    use std::time::Duration as StdDuration;

    use chrono::{Duration, TimeZone, Utc};
    use hartevo_cordis::{
        AgentInboxTarget, AgentStep, AgentsSurface, AuthorityDispatchError, AuthorityScope,
        CordisError, CordisHost, DomainCommandBinding, DomainCommandKind, DomainSurface,
        EffectExecutionBinding, EffectReconciliationBinding, EffectVerificationBinding, FiberState,
        OPENINTERPRETER, RuntimeBinding, SessionContentBlock, SessionError, SessionEventKind,
        SessionId, SessionMessage, SessionMessageRole, SessionMessageSource, SessionStore,
        SessionSurfaceIntent, SessionSurfaceOp, SurfaceOwner, enforce_invariants, events,
        host_is_cordis_loop, invariant_missing, keys,
    };
    use hartevo_domain_kernel::{
        ActorId, Approval, ApprovalDecision, ApprovalId, ConsentPurpose, ConsentRecord,
        ConsentRecordId, ConsentState, ConsentStatus, ContactChannel, LegalBasis, PersonId,
        ProjectId, TenantId,
    };
    use hartevo_runtime_adapter::OPENINTERPRETER_RELEASE;
    use hartevo_storage::{
        PersistedAgentInboxTarget, PersistedSessionEvent, PersistedSessionEventKind, ProjectStore,
    };

    use super::{
        DesktopDomainCommandAuthorization, DesktopEffectExecutionAuthorization,
        DesktopEffectReconciliationAuthorization, DesktopEffectVerificationAuthorization,
        bind_live_domain_kernel, bind_live_domain_kernel_scope, decode_event,
        dispatch_live_domain_command, dispatch_live_effect_execution,
        dispatch_live_effect_reconciliation, dispatch_live_effect_verification,
        dispatch_live_runtime, encode_event, mount_cordis_host, openinterpreter_runtime_plugin,
    };
    use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

    fn projection(status: DesktopRuntimeAvailabilityStatus) -> DesktopRuntimeProjection {
        DesktopRuntimeProjection {
            status,
            target: Some("aarch64-apple-darwin".into()),
            release: OPENINTERPRETER_RELEASE.into(),
            program_sha256: None,
            provider: None,
            model: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        }
    }

    #[test]
    fn legacy_n22_message_without_surface_decodes_as_append() {
        let message = SessionMessage {
            id: "legacy-user".into(),
            role: SessionMessageRole::User,
            content: vec![SessionContentBlock::Text {
                text: "legacy".into(),
            }],
            source: SessionMessageSource::User,
        };
        let event = PersistedSessionEvent {
            seq: 0,
            time_ms: 1,
            kind: PersistedSessionEventKind::UserMessage {
                message: message.to_json_value().unwrap(),
                surface: None,
            },
        };

        assert!(matches!(
            decode_event(&event).unwrap().kind,
            SessionEventKind::UserMessage {
                surface: SessionSurfaceIntent {
                    surface_op: SessionSurfaceOp::Append,
                    source_event_seqs: None,
                },
                ..
            }
        ));
    }

    #[test]
    fn agent_inbox_splice_codec_round_trips_exactly() {
        let message = SessionMessage {
            id: "queued-user".into(),
            role: SessionMessageRole::User,
            content: vec![SessionContentBlock::Text {
                text: "queued".into(),
            }],
            source: SessionMessageSource::User,
        };
        let event = hartevo_cordis::SessionEvent {
            seq: 0,
            time_ms: 1,
            kind: SessionEventKind::AgentInboxSpliced {
                target: AgentInboxTarget::NextStep,
                start: 0,
                removed_count: None,
                inserted: vec![message.clone()],
                outcome: None,
            },
        };

        let persisted = encode_event(&event).unwrap();
        assert!(matches!(
            &persisted.kind,
            PersistedSessionEventKind::AgentInboxSpliced {
                target: PersistedAgentInboxTarget::NextStep,
                start: 0,
                removed_count: None,
                inserted,
                outcome: None,
            } if inserted == &[message.to_json_value().unwrap()]
        ));
        assert_eq!(decode_event(&persisted).unwrap(), event);
    }

    #[test]
    fn agent_inbox_survives_desktop_session_persistence_rebind() {
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        assert_eq!(
            live.bind_session_persistence(ProjectStore::in_memory().unwrap())
                .unwrap(),
            0
        );
        let sessions = live.context().sessions::<SessionStore>().unwrap();
        let session = sessions
            .create(SessionId::new("persisted-inbox").unwrap())
            .unwrap();
        let message = SessionMessage {
            id: "persisted-user".into(),
            role: SessionMessageRole::User,
            content: vec![SessionContentBlock::Text {
                text: "persist me".into(),
            }],
            source: SessionMessageSource::User,
        };
        let step_message = SessionMessage {
            id: "persisted-step".into(),
            role: SessionMessageRole::User,
            content: vec![SessionContentBlock::Text {
                text: "persist next step".into(),
            }],
            source: SessionMessageSource::Plugin {
                plugin: "watcher".into(),
            },
        };
        session.inbox().append_next_turn(message.clone()).unwrap();
        session
            .inbox()
            .append_next_step(step_message.clone())
            .unwrap();
        live.session_persistence.persist_live(&session).unwrap();
        let store = live
            .session_persistence
            .store
            .lock()
            .unwrap()
            .take()
            .unwrap();

        let mut cold =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        assert_eq!(cold.bind_session_persistence(store).unwrap(), 1);
        let restored = cold
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&SessionId::new("persisted-inbox").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            restored.inbox().next_turn().unwrap().as_slice(),
            std::slice::from_ref(&message)
        );
        assert_eq!(restored.inbox().next_step().unwrap(), [step_message]);
    }

    #[test]
    fn persisted_assistant_chunk_with_unknown_shape_fails_closed() {
        let event = PersistedSessionEvent {
            seq: 0,
            time_ms: 1,
            kind: PersistedSessionEventKind::AssistantChunk {
                turn: 1,
                step: 1,
                chunk: serde_json::json!({
                    "type": "text-delta",
                    "index": 0,
                    "text": "hello",
                    "unknown": true
                }),
            },
        };

        assert!(matches!(
            decode_event(&event),
            Err(super::DesktopSessionPersistenceError::Session(
                SessionError::InvalidAssistantChunkEncoding
            ))
        ));
    }

    #[test]
    fn persisted_request_header_with_unknown_shape_fails_closed() {
        let event = PersistedSessionEvent {
            seq: 0,
            time_ms: 1,
            kind: PersistedSessionEventKind::RequestHeader {
                request: serde_json::json!({
                    "header": {
                        "config": { "provider": "provider", "model": "model" },
                        "unknown": true
                    },
                    "reason": "initial"
                }),
            },
        };

        assert!(matches!(
            decode_event(&event),
            Err(super::DesktopSessionPersistenceError::Session(
                SessionError::InvalidRequestHeaderEncoding
            ))
        ));
    }

    #[derive(Debug, Eq, PartialEq)]
    struct PhaseError(&'static str);

    impl Display for PhaseError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for PhaseError {}

    fn runtime_scope() -> AuthorityScope {
        AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap())
    }

    fn domain_scope() -> AuthorityScope {
        AuthorityScope::new("tenant-a", "project-a", "mission-a", 4).unwrap()
    }

    fn approval_command() -> DomainCommandBinding {
        DomainCommandBinding::approve_proposed_effect("effect-a", "a".repeat(64)).unwrap()
    }

    fn effect_execution() -> EffectExecutionBinding {
        EffectExecutionBinding::new("effect-a", "a".repeat(64), "b".repeat(64)).unwrap()
    }

    fn effect_reconciliation() -> EffectReconciliationBinding {
        EffectReconciliationBinding::new("effect-a", "a".repeat(64), "b".repeat(64)).unwrap()
    }

    fn effect_verification() -> EffectVerificationBinding {
        EffectVerificationBinding::new(
            "effect-a",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
        )
        .unwrap()
    }

    fn assert_emit_source(error: &CordisError, expected: &'static str) {
        let CordisError::Emit { error, .. } = error else {
            panic!("expected typed Emit phase failure: {error:?}");
        };
        assert_eq!(
            error.event_source().as_error().downcast_ref::<PhaseError>(),
            Some(&PhaseError(expected))
        );
    }

    #[test]
    fn started_failure_is_cached_and_lifecycle_callbacks_run_after_unlock() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let started_calls = Arc::new(AtomicUsize::new(0));
        let later_started_calls = Arc::new(AtomicUsize::new(0));
        let disposed_calls = Arc::new(AtomicUsize::new(0));
        {
            let started_host = Arc::clone(&host);
            let started_calls = Arc::clone(&started_calls);
            let later_started_calls = Arc::clone(&later_started_calls);
            let disposed_host = Arc::clone(&host);
            let disposed_calls = Arc::clone(&disposed_calls);
            let mut locked = host.lock().unwrap();
            locked
                .context_mut()
                .try_on_emit(events::AGENT_CREATED, move |_| {
                    assert!(started_host.try_lock().is_ok());
                    started_calls.fetch_add(1, Ordering::SeqCst);
                    Err(PhaseError("started"))
                })
                .unwrap();
            locked
                .on_runtime_started(move |_| {
                    later_started_calls.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
            locked
                .on_runtime_finished(move |_| {
                    assert!(disposed_host.try_lock().is_ok());
                    disposed_calls.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
        }
        let scope = runtime_scope();
        let mut permit = {
            let mut locked = host.lock().unwrap();
            bind_live_domain_kernel_scope(
                &mut locked,
                scope.clone(),
                &ConsentState::NotRequired,
                None,
                None,
                now(),
            )
            .unwrap();
            locked.authorize_runtime(&scope).unwrap()
        };

        let first = permit.announce_started().unwrap_err();
        let second = permit.announce_started().unwrap_err();
        assert_eq!(first, second);
        assert_emit_source(&first, "started");
        assert_eq!(started_calls.load(Ordering::SeqCst), 1);
        assert_eq!(later_started_calls.load(Ordering::SeqCst), 0);
        let completion = host.lock().unwrap().finish_runtime(permit).unwrap();
        completion.announce().unwrap();
        assert_eq!(disposed_calls.load(Ordering::SeqCst), 1);
        assert!(host.lock().unwrap().active_runtime_scope().is_none());
    }

    #[test]
    fn started_and_disposed_failures_are_combined_and_authority_is_skipped() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        {
            let mut locked = host.lock().unwrap();
            locked
                .context_mut()
                .try_on_emit(events::AGENT_CREATED, |_| Err(PhaseError("started")))
                .unwrap();
            locked
                .context_mut()
                .try_on_emit(events::AGENT_DISPOSED, |_| Err(PhaseError("disposed")))
                .unwrap();
        }
        let authority_calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&authority_calls);
        let error = dispatch_live_runtime(
            &host,
            runtime_scope(),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |_| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, PhaseError>(())
            },
        )
        .unwrap_err();
        let AuthorityDispatchError::Combined(failures) = &error else {
            panic!("expected started+disposed combined failure: {error:?}");
        };
        assert_emit_source(failures.started().unwrap(), "started");
        assert!(failures.authority().is_none());
        assert!(failures.finish().is_none());
        assert_emit_source(failures.disposed().unwrap(), "disposed");
        assert_eq!(authority_calls.load(Ordering::SeqCst), 0);
        assert!(host.lock().unwrap().active_runtime_scope().is_none());
    }

    #[test]
    fn authority_and_disposed_failures_are_combined_without_source_loss() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        host.lock()
            .unwrap()
            .context_mut()
            .try_on_emit(events::AGENT_DISPOSED, |_| Err(PhaseError("disposed")))
            .unwrap();
        let error = dispatch_live_runtime(
            &host,
            runtime_scope(),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            |_| Err::<(), _>(PhaseError("authority")),
        )
        .unwrap_err();
        let AuthorityDispatchError::Combined(failures) = &error else {
            panic!("expected authority+disposed combined failure: {error:?}");
        };
        assert!(failures.started().is_none());
        assert_eq!(failures.authority(), Some(&PhaseError("authority")));
        assert!(failures.finish().is_none());
        assert_emit_source(failures.disposed().unwrap(), "disposed");
        assert_eq!(
            error.source().unwrap().downcast_ref::<PhaseError>(),
            Some(&PhaseError("authority"))
        );
    }

    #[test]
    fn desktop_runtime_adapter_releases_host_lock_and_calls_authority_once() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let probe = Arc::clone(&host);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let expected_scope = scope.clone();
        let nested_calls = Arc::new(AtomicUsize::new(0));
        let observed_nested_calls = Arc::clone(&nested_calls);

        let output = dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                assert_eq!(permit.scope(), &expected_scope);
                assert!(
                    probe.try_lock().is_ok(),
                    "Application adapter must run without the Cordis host lock"
                );
                let nested_scope = permit.scope().clone();
                let nested = dispatch_live_runtime(
                    &probe,
                    nested_scope,
                    &ConsentState::NotRequired,
                    None,
                    None,
                    now(),
                    move |_| {
                        observed_nested_calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, &'static str>(())
                    },
                );
                assert_eq!(
                    nested.unwrap_err(),
                    AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimeDispatchBusy))
                );
                observed_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>("application-runtime")
            },
        )
        .unwrap();

        assert_eq!(output, "application-runtime");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(nested_calls.load(Ordering::SeqCst), 0);
        let host = host.lock().unwrap();
        assert!(host.active_runtime_scope().is_none());
        assert!(
            host.context()
                .agents::<AgentsSurface>()
                .unwrap()
                .list()
                .is_empty()
        );
    }

    #[test]
    fn desktop_domain_command_releases_lock_and_calls_application_once() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let probe = Arc::clone(&host);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let expected_scope = domain_scope();
        let expected_command = approval_command();

        let output = dispatch_live_domain_command(
            &host,
            DesktopDomainCommandAuthorization::new(
                expected_scope.clone(),
                expected_command.clone(),
            ),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                assert_eq!(permit.scope(), &expected_scope);
                assert_eq!(permit.command(), &expected_command);
                assert_eq!(
                    permit.command().kind(),
                    DomainCommandKind::ApproveProposedEffect
                );
                assert!(
                    probe.try_lock().is_ok(),
                    "Application must run without the Cordis coordinator lock"
                );
                let nested = dispatch_live_domain_command(
                    &probe,
                    DesktopDomainCommandAuthorization::new(
                        permit.scope().clone(),
                        permit.command().clone(),
                    ),
                    &ConsentState::NotRequired,
                    None,
                    None,
                    now(),
                    |_| Ok::<_, &'static str>(()),
                );
                assert_eq!(
                    nested.unwrap_err(),
                    AuthorityDispatchError::Cordis(Box::new(
                        CordisError::DomainCommandDispatchBusy
                    ))
                );
                observed_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>("application-domain-command")
            },
        )
        .unwrap();

        assert_eq!(output, "application-domain-command");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(host.lock().unwrap().active_domain_command_scope().is_none());
    }

    #[test]
    fn desktop_effect_execution_releases_lock_and_calls_application_once() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let probe = Arc::clone(&host);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let nested_calls = Arc::new(AtomicUsize::new(0));
        let observed_nested_calls = Arc::clone(&nested_calls);
        let expected_scope = domain_scope();
        let expected_binding = effect_execution();
        let approval = approved(now() + Duration::minutes(5));
        let nested_approval = approval.clone();

        let output = dispatch_live_effect_execution(
            &host,
            DesktopEffectExecutionAuthorization::new(
                expected_scope.clone(),
                expected_binding.clone(),
            ),
            &ConsentState::Confirmed,
            None,
            &approval,
            now(),
            move |permit| {
                assert_eq!(permit.scope(), &expected_scope);
                assert_eq!(permit.binding(), &expected_binding);
                assert!(
                    probe.try_lock().is_ok(),
                    "Application/Broker must run without the Cordis coordinator lock"
                );
                let nested = dispatch_live_effect_execution(
                    &probe,
                    DesktopEffectExecutionAuthorization::new(
                        permit.scope().clone(),
                        permit.binding().clone(),
                    ),
                    &ConsentState::Confirmed,
                    None,
                    &nested_approval,
                    now(),
                    move |_| {
                        observed_nested_calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, &'static str>(())
                    },
                );
                assert_eq!(
                    nested.unwrap_err(),
                    AuthorityDispatchError::Cordis(Box::new(
                        CordisError::EffectExecutionDispatchBusy
                    ))
                );
                observed_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>("application-effect-broker")
            },
        )
        .unwrap();

        assert_eq!(output, "application-effect-broker");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(nested_calls.load(Ordering::SeqCst), 0);
        let host = host.lock().unwrap();
        assert!(host.active_effect_execution_scope().is_none());
        assert!(host.active_domain_command_scope().is_none());
        assert!(host.active_runtime_scope().is_none());
    }

    #[test]
    fn desktop_effect_reconciliation_releases_lock_and_has_no_execution_authority() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let probe = Arc::clone(&host);
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let nested_calls = Arc::new(AtomicUsize::new(0));
        let observed_nested_calls = Arc::clone(&nested_calls);
        let expected_scope = domain_scope();
        let expected_binding = effect_reconciliation();
        let expired_approval = approved(now() - Duration::minutes(1));
        let nested_approval = expired_approval.clone();

        let output = dispatch_live_effect_reconciliation(
            &host,
            DesktopEffectReconciliationAuthorization::new(
                expected_scope.clone(),
                expected_binding.clone(),
            ),
            &ConsentState::Missing,
            None,
            Some(&expired_approval),
            now(),
            move |permit| {
                assert_eq!(permit.scope(), &expected_scope);
                assert_eq!(permit.binding(), &expected_binding);
                assert!(
                    probe.try_lock().is_ok(),
                    "Application/Broker observer must run without the Cordis lock"
                );
                let nested = dispatch_live_effect_reconciliation(
                    &probe,
                    DesktopEffectReconciliationAuthorization::new(
                        permit.scope().clone(),
                        permit.binding().clone(),
                    ),
                    &ConsentState::Missing,
                    None,
                    Some(&nested_approval),
                    now(),
                    move |_| {
                        observed_nested_calls.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, &'static str>(())
                    },
                );
                assert_eq!(
                    nested.unwrap_err(),
                    AuthorityDispatchError::Cordis(Box::new(
                        CordisError::EffectReconciliationDispatchBusy
                    ))
                );
                observed_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>("application-effect-reconciliation")
            },
        )
        .unwrap();

        assert_eq!(output, "application-effect-reconciliation");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(nested_calls.load(Ordering::SeqCst), 0);
        let host = host.lock().unwrap();
        assert!(host.active_effect_reconciliation_scope().is_none());
        assert!(host.active_effect_execution_scope().is_none());
        assert!(host.active_domain_command_scope().is_none());
        assert!(host.active_runtime_scope().is_none());
    }

    #[test]
    fn desktop_effect_verification_is_one_shot_exclusive_redacted_and_drop_safe() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let probe = Arc::clone(&host);
        let expected_scope = domain_scope();
        let expected_binding = effect_verification();
        let approval = approved(now() + Duration::minutes(5));
        let nested_approval = approval.clone();
        let output = dispatch_live_effect_verification(
            &host,
            DesktopEffectVerificationAuthorization::new(
                expected_scope.clone(),
                expected_binding.clone(),
            ),
            &ConsentState::Confirmed,
            None,
            Some(&approval),
            now(),
            move |permit| {
                assert_eq!(permit.scope(), &expected_scope);
                assert_eq!(permit.binding(), &expected_binding);
                let debug = format!("{permit:?}");
                for digest in ["a", "b", "c", "d", "e"] {
                    assert!(!debug.contains(&digest.repeat(64)));
                }
                assert!(probe.try_lock().is_ok());
                let nested = dispatch_live_effect_verification(
                    &probe,
                    DesktopEffectVerificationAuthorization::new(
                        permit.scope().clone(),
                        permit.binding().clone(),
                    ),
                    &ConsentState::Confirmed,
                    None,
                    Some(&nested_approval),
                    now(),
                    |_| Ok::<_, &'static str>(()),
                );
                assert_eq!(
                    nested.unwrap_err(),
                    AuthorityDispatchError::Cordis(Box::new(
                        CordisError::EffectVerificationDispatchBusy
                    ))
                );
                Ok::<_, &'static str>("application-independent-verification")
            },
        )
        .unwrap();
        assert_eq!(output, "application-independent-verification");
        assert!(
            host.lock()
                .unwrap()
                .active_effect_verification_scope()
                .is_none()
        );

        let panic_host = Arc::clone(&host);
        let panic_approval = approval.clone();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _ = dispatch_live_effect_verification(
                &panic_host,
                DesktopEffectVerificationAuthorization::new(domain_scope(), effect_verification()),
                &ConsentState::Confirmed,
                None,
                Some(&panic_approval),
                now(),
                |_| -> Result<(), &'static str> { panic!("verification source panic") },
            );
        }));
        assert!(panicked.is_err());
        assert!(
            host.lock()
                .unwrap()
                .active_effect_verification_scope()
                .is_none()
        );
    }

    #[test]
    fn abandoned_desktop_effect_reconciliation_recovers_on_next_dispatch() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let panic_host = Arc::clone(&host);
        let approval = approved(now() - Duration::minutes(1));
        let panic_approval = approval.clone();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _ = dispatch_live_effect_reconciliation(
                &panic_host,
                DesktopEffectReconciliationAuthorization::new(
                    domain_scope(),
                    effect_reconciliation(),
                ),
                &ConsentState::Missing,
                None,
                Some(&panic_approval),
                now(),
                |_| -> Result<(), &'static str> { panic!("reconciliation observer panic") },
            );
        }));
        assert!(panicked.is_err());
        assert!(
            host.lock()
                .unwrap()
                .active_effect_reconciliation_scope()
                .is_none()
        );

        dispatch_live_effect_reconciliation(
            &host,
            DesktopEffectReconciliationAuthorization::new(domain_scope(), effect_reconciliation()),
            &ConsentState::Missing,
            None,
            Some(&approval),
            now(),
            |_| Ok::<_, &'static str>(()),
        )
        .unwrap();
    }

    #[test]
    fn abandoned_desktop_domain_command_recovers_on_next_dispatch() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let panic_host = Arc::clone(&host);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _ = dispatch_live_domain_command(
                &panic_host,
                DesktopDomainCommandAuthorization::new(domain_scope(), approval_command()),
                &ConsentState::NotRequired,
                None,
                None,
                now(),
                |_| -> Result<(), &'static str> { panic!("Domain command adapter panic") },
            );
        }));
        assert!(panicked.is_err());
        assert!(host.lock().unwrap().active_domain_command_scope().is_none());

        dispatch_live_domain_command(
            &host,
            DesktopDomainCommandAuthorization::new(domain_scope(), approval_command()),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            |_| Ok::<_, &'static str>(()),
        )
        .unwrap();
    }

    #[test]
    fn concurrent_same_scope_dispatch_runs_exactly_one_authority() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_host = Arc::clone(&host);
        let first_scope = scope.clone();
        let first_calls = Arc::clone(&calls);
        let first = thread::spawn(move || {
            dispatch_live_runtime(
                &first_host,
                first_scope,
                &ConsentState::NotRequired,
                None,
                None,
                now(),
                move |_| {
                    first_calls.fetch_add(1, Ordering::SeqCst);
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok::<_, &'static str>("first")
                },
            )
        });
        entered_rx
            .recv_timeout(StdDuration::from_secs(2))
            .expect("first authority entered");

        let second_calls = Arc::clone(&calls);
        let second = dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |_| {
                second_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>("second")
            },
        );
        assert_eq!(
            second.unwrap_err(),
            AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimeDispatchBusy))
        );
        let locked = host.lock().unwrap();
        assert_eq!(locked.successful_bindings(), 1);
        assert!(
            locked.last_binding().is_none(),
            "authorization consumes the only successful binding receipt"
        );
        drop(locked);
        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap().unwrap(), "first");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn lifecycle_observers_reenter_only_after_host_unlock() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let started = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        {
            let started_host = Arc::clone(&host);
            let started_scope = scope.clone();
            let started_count = Arc::clone(&started);
            let finished_host = Arc::clone(&host);
            let finished_count = Arc::clone(&finished);
            let mut locked = host.lock().unwrap();
            locked
                .on_runtime_started(move |_| {
                    let nested = dispatch_live_runtime(
                        &started_host,
                        started_scope.clone(),
                        &ConsentState::NotRequired,
                        None,
                        None,
                        now(),
                        |_| Ok::<_, &'static str>(()),
                    );
                    assert_eq!(
                        nested.unwrap_err(),
                        AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimeDispatchBusy))
                    );
                    started_count.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
            locked
                .on_runtime_finished(move |_| {
                    assert!(
                        finished_host.try_lock().is_ok(),
                        "finished observer must run after host unlock"
                    );
                    finished_count.fetch_add(1, Ordering::SeqCst);
                })
                .unwrap();
        }

        dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            |_| Ok::<_, &'static str>(()),
        )
        .unwrap();
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert_eq!(finished.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poisoned_host_fails_closed_without_calling_authority() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let poison = Arc::clone(&host);
        let _ = thread::spawn(move || {
            let _locked = poison.lock().unwrap();
            panic!("poison Cordis coordinator for fail-closed test");
        })
        .join();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_calls = Arc::clone(&calls);
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let result = dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |_| {
                observed_calls.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &'static str>(())
            },
        );
        assert_eq!(
            result.unwrap_err(),
            AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimeCoordinatorPoisoned))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn authority_panic_drops_permit_and_next_dispatch_can_recover() {
        let host = Arc::new(Mutex::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let scope = AuthorityScope::new("tenant-a", "project-a", "mission-a", 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());
        let panic_host = Arc::clone(&host);
        let panic_scope = scope.clone();
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _ = dispatch_live_runtime(
                &panic_host,
                panic_scope,
                &ConsentState::NotRequired,
                None,
                None,
                now(),
                |_| -> Result<(), &'static str> { panic!("authority panic") },
            );
        }));
        assert!(panicked.is_err());
        assert!(
            host.lock()
                .unwrap()
                .context()
                .agents::<AgentsSurface>()
                .unwrap()
                .list()
                .is_empty()
        );
        dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            |_| Ok::<_, &'static str>(()),
        )
        .unwrap();
    }

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 25, 13, 34, 33).unwrap()
    }

    fn granted_record(valid_until: chrono::DateTime<Utc>) -> ConsentRecord {
        ConsentRecord::grant(
            ConsentRecordId::from("consent-desktop"),
            TenantId::from("tenant-desktop"),
            ProjectId::from("project-desktop"),
            PersonId::from("person-desktop"),
            ConsentPurpose::DirectOutreach,
            ContactChannel::Email,
            "US",
            LegalBasis::ExplicitConsent,
            "signed desktop consent",
            "e".repeat(64),
            now(),
            Some(valid_until),
        )
        .expect("granted consent")
    }

    fn approved(valid_until: chrono::DateTime<Utc>) -> Approval {
        Approval {
            id: ApprovalId::from("approval-desktop"),
            decision: ApprovalDecision::Approved,
            decided_by: ActorId::from("user-desktop"),
            decided_at: now(),
            valid_until,
            scope_digest: "a".repeat(64),
            permission_digest: "b".repeat(64),
        }
    }

    #[test]
    fn production_desktop_surfaces_do_not_pre_grant_consent_or_approval() {
        for openinterpreter in [false, true] {
            let host = CordisHost::boot(openinterpreter).unwrap();
            let domain = host.context().domain::<DomainSurface>().unwrap();
            assert!(!domain.consent());
            assert!(!domain.approved());
            assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
            assert!(domain.local_first());
            assert!(domain.sqlcipher());
            assert!(domain.eval_gate());
            assert!(
                !host
                    .context()
                    .effect_broker::<hartevo_cordis::EffectBrokerSurface>()
                    .unwrap()
                    .receipt_is_verification()
            );
        }
    }

    #[test]
    fn not_configured_runtime_does_not_name_openinterpreter_plugin() {
        assert!(!openinterpreter_runtime_plugin(&projection(
            DesktopRuntimeAvailabilityStatus::NotConfigured
        )));
        let host = mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
            .unwrap();
        assert_eq!(host.root_fiber().state(), FiberState::Active);
        assert!(!host.root_fiber().is_disposed());
        assert!(host.last_binding().is_none());
        host_is_cordis_loop(&host).unwrap();
        assert_eq!(host.runtime_plugin(), None);
        let domain = host.context().domain::<DomainSurface>().unwrap();
        assert_eq!(domain.owner(), SurfaceOwner::Hartevo);
        assert!(!domain.consent());
        assert!(!domain.approved());
        assert!(host.context().get::<String>(OPENINTERPRETER).is_none());
    }

    #[test]
    fn scoped_live_bindings_return_monotonic_root_fiber_receipts() {
        let mut host =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let scope = runtime_scope();
        let first = bind_live_domain_kernel_scope(
            &mut host,
            scope.clone(),
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();

        assert_eq!(first.scope(), &scope);
        assert_eq!(first.root_fiber_uid(), host.root_fiber().uid());
        assert_eq!(first.refresh_sequence(), 1);
        assert_eq!(host.last_binding().unwrap().scope.as_ref(), Some(&scope));

        let second = bind_live_domain_kernel_scope(
            &mut host,
            scope.clone(),
            &ConsentState::Missing,
            None,
            None,
            now(),
        )
        .unwrap();
        assert_eq!(second.root_fiber_uid(), first.root_fiber_uid());
        assert_eq!(second.refresh_sequence(), 2);
        let domain = host.context().domain::<DomainSurface>().unwrap();
        assert!(!domain.consent());
        assert!(!domain.approved());
        assert_eq!(
            host.authorize_bound_runtime(first).unwrap_err(),
            CordisError::AuthorityScopeMismatch,
            "an older receipt cannot authorize after a newer live binding"
        );
        assert_eq!(host.last_binding().unwrap().refresh_sequence, 2);
        let permit = host.authorize_bound_runtime(second).unwrap();
        assert!(host.last_binding().is_none());
        host.finish_runtime(permit).unwrap().announce().unwrap();
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
    }

    #[test]
    fn scoped_binding_receipt_cannot_cross_coordinators() {
        let mut first =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let receipt = bind_live_domain_kernel_scope(
            &mut first,
            runtime_scope(),
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        let mut second =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();

        assert_eq!(
            second.authorize_bound_runtime(receipt).unwrap_err(),
            CordisError::AuthorityScopeMismatch
        );
        assert_eq!(second.successful_bindings(), 0);
        assert!(second.last_binding().is_none());
    }

    #[test]
    fn ready_runtime_keeps_openinterpreter_as_optional_plugin_without_pre_grant() {
        let mut host = mount_cordis_host(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment,
        ))
        .unwrap();
        assert!(openinterpreter_runtime_plugin(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment
        )));
        host_is_cordis_loop(&host).unwrap();
        assert_eq!(host.runtime_plugin(), Some(OPENINTERPRETER));
        assert_eq!(
            host.context()
                .runtime::<hartevo_cordis::RuntimeSurface>()
                .unwrap()
                .owner(),
            SurfaceOwner::Hartevo
        );
        assert_eq!(
            enforce_invariants(host.context()).unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        enforce_invariants(host.context()).unwrap();
        host.apply_effect().unwrap();
    }

    #[test]
    fn desktop_step_fails_closed_until_kernel_facts_are_bound() {
        let mut host = mount_cordis_host(&projection(
            DesktopRuntimeAvailabilityStatus::ReadyDistribution,
        ))
        .unwrap();
        host_is_cordis_loop(&host).unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-desktop", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
        bind_live_domain_kernel(&mut host, &ConsentState::Confirmed, None, None, now()).unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-desktop", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
        );
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        let out = host
            .step(AgentStep::new("mission-desktop", "plan"))
            .unwrap();
        assert_eq!(out.id, "mission-desktop");
        for key in [
            keys::TOOLS,
            keys::LLM,
            keys::AGENTS,
            keys::DOMAIN,
            keys::EFFECT_BROKER,
        ] {
            assert!(host.context().has(key), "{key} must stay mounted");
        }
    }

    fn denied_record() -> ConsentRecord {
        let denied = ConsentRecord {
            id: ConsentRecordId::from("consent-denied"),
            tenant_id: TenantId::from("tenant-desktop"),
            project_id: ProjectId::from("project-desktop"),
            person_id: PersonId::from("person-desktop"),
            purpose: ConsentPurpose::DirectOutreach,
            channel: ContactChannel::Email,
            market: "US".into(),
            legal_basis: LegalBasis::ExplicitConsent,
            status: ConsentStatus::Denied,
            source: "signed desktop consent".into(),
            evidence_digest: "e".repeat(64),
            granted_at: None,
            valid_until: None,
            withdrawn_at: None,
            revision: 1,
        };
        denied.validate().expect("denied record");
        denied
    }

    #[test]
    fn withdrawn_missing_denied_and_expired_consent_fail_closed() {
        let mut host =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let mut withdrawn = granted_record(now() + Duration::days(30));
        withdrawn.withdraw(now() + Duration::hours(1)).unwrap();
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Withdrawn,
            Some(&withdrawn),
            Some(&approved(now() + Duration::minutes(5))),
            now() + Duration::hours(2),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-withdrawn", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );

        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Missing,
            None,
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );

        let mut expired_record = granted_record(now() + Duration::seconds(1));
        expired_record
            .expire(now() + Duration::seconds(2))
            .expect("expire");
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::NotRequired,
            Some(&expired_record),
            Some(&approved(now() + Duration::minutes(5))),
            now() + Duration::seconds(3),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-expired-record", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );

        let denied = denied_record();
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::NotRequired,
            Some(&denied),
            Some(&approved(now() + Duration::minutes(5))),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.apply_effect().unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::CONSENT.to_string()])
        );
    }

    #[test]
    fn expired_or_rejected_approval_fails_closed_and_granted_record_allows_step() {
        let mut host =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&approved(now() - Duration::seconds(1))),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-expired", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
        );

        bind_live_domain_kernel(
            &mut host,
            &ConsentState::Confirmed,
            None,
            Some(&Approval {
                id: ApprovalId::from("approval-rejected"),
                decision: ApprovalDecision::Rejected,
                decided_by: ActorId::from("user-desktop"),
                decided_at: now(),
                valid_until: now() + Duration::minutes(5),
                scope_digest: "a".repeat(64),
                permission_digest: "b".repeat(64),
            }),
            now(),
        )
        .unwrap();
        assert_eq!(
            host.step(AgentStep::new("mission-rejected", "plan"))
                .unwrap_err(),
            CordisError::MissingDependencies(vec![invariant_missing::APPROVAL.to_string()])
        );

        let live = granted_record(now() + Duration::days(30));
        assert_eq!(live.status, ConsentStatus::Granted);
        bind_live_domain_kernel(
            &mut host,
            &ConsentState::NotRequired,
            Some(&live),
            Some(&approved(now() + Duration::minutes(5))),
            now() + Duration::minutes(1),
        )
        .unwrap();
        host.step(AgentStep::new("mission-granted-record", "plan"))
            .unwrap();
    }
}
