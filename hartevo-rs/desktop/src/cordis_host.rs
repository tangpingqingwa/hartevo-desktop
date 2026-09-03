//! One-call-site Cordis mount and typed Domain/Effect/Runtime adapters for Desktop.
//!
//! Production Runtime enters through [`dispatch_live_runtime`]: Cordis issues
//! a short-lived scoped permit, Desktop releases the host lock, and the real
//! Application coordinator runs exactly once. OpenInterpreter may occupy the
//! optional plugin slot; it never owns Domain, Effect, or execution authority.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::TryLockError;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use futures_util::{StreamExt, stream};
use hartevo_cordis::{
    AgentInboxOutcome, AgentInboxTarget, AgentTurnOutcome, ApprovalOutcome, ApprovalPrompt,
    ApprovalRequestId, AuthorityDispatchError, AuthorityScope, BailOutcome, CompactionResult,
    CordisError, CordisHost, DomainCommandAuthority, DomainCommandBinding, DomainCommandPermit,
    EffectExecutionAuthority, EffectExecutionBinding, EffectExecutionPermit,
    EffectReconciliationAuthority, EffectReconciliationBinding, EffectReconciliationPermit,
    EffectVerificationAuthority, EffectVerificationBinding, EffectVerificationPermit, EventOptions,
    Fiber, FiberState, FiberUid, JobId, JobTerminalNotice, JobsSurface, KernelApproval,
    KernelApprovalDecision, KernelConsentRecord, KernelConsentState, KernelConsentStatus,
    LifecycleCancellation, ListenerHandle, LlmAdapter, LlmAdapterStream, LlmError,
    LlmGenerateRequest, LlmResolvedModel, ManualCompactionError, ManualCompactionErrorCode,
    NonBail, OneShotSubagentDescriptor, PromptSection, RegistrationHandle, RuntimeAgentIdentity,
    RuntimeAuthority, RuntimeDispatchCompletion, RuntimeDispatchPermit, RuntimeStatusCompletion,
    SandboxError, SessionApprovalAsked, SessionApprovalDecided, SessionApprovalPolicy,
    SessionCallConfig, SessionCancelCause, SessionCheckpoint, SessionCompactionEnd,
    SessionCompactionStart, SessionCompactionSummary, SessionContentBlock, SessionEpochHeader,
    SessionError, SessionEvent, SessionEventKind, SessionEventRecord, SessionFinishReason,
    SessionHandle, SessionHeader, SessionId, SessionLlmFailure, SessionLlmRetry,
    SessionLlmRetryStarted, SessionLog, SessionMessage, SessionMessageRole, SessionMessageSource,
    SessionRequestContext, SessionRequestHeader, SessionRequestHeaderReason, SessionSandboxMode,
    SessionStore, SessionStreamBlockType, SessionStreamChunk, SessionSurfaceIntent,
    SessionToolError, TurnEndReason, approval_events, bind_sandbox_workspace, compact_now,
    host_is_cordis_loop, keys, register_llm_adapter, register_prompt_section,
    run_agent_turn as run_cordis_agent_turn, session_events,
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

const IDLE_JOB_COMPLETION_WAKE_BUDGET: u8 = 3;

/// Whether OpenInterpreter is configured as an optional runtime adapter.
#[must_use]
fn openinterpreter_runtime_plugin(runtime: &DesktopRuntimeProjection) -> bool {
    runtime.program_sha256.is_some()
        && matches!(
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
    idle_job_wake_budgets: Vec<DesktopIdleJobWakeBudget>,
}

#[derive(Debug)]
struct DesktopIdleJobWakeBudget {
    agent: hartevo_cordis::AgentRef,
    remaining: u8,
}

/// Content-minimized Desktop projection of one exact Cordis approval.
///
/// Tool arguments are deliberately absent: the window receives only the
/// durable request identity and human-readable routing metadata needed to
/// answer that one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DesktopHeldCordisApproval {
    id: ApprovalRequestId,
    agent_id: String,
    session_id: SessionId,
    tool_name: String,
    call_id: Option<String>,
    reason: Option<String>,
}

impl DesktopHeldCordisApproval {
    #[must_use]
    pub(crate) const fn id(&self) -> &ApprovalRequestId {
        &self.id
    }

    #[must_use]
    pub(crate) fn tool_name(&self) -> &str {
        &self.tool_name
    }

    #[must_use]
    pub(crate) fn call_id(&self) -> Option<&str> {
        self.call_id.as_deref()
    }

    #[must_use]
    pub(crate) fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum DesktopCordisApprovalDecisionError {
    #[error("no live Cordis tool approval is held for this Desktop turn")]
    Unavailable,
    #[error("Cordis tool approval must match the exact held request id")]
    Mismatch,
}

struct DesktopPendingCordisApproval {
    request: DesktopHeldCordisApproval,
    answer: Option<tokio::sync::oneshot::Sender<ApprovalOutcome>>,
}

#[derive(Default)]
struct DesktopCordisApprovalState {
    pending: Option<DesktopPendingCordisApproval>,
}

/// Request-scoped bridge between Cordis' serial approval event and Desktop.
///
/// Every state transition invokes `on_change`, allowing the existing Runtime
/// progress monitor to repaint without a second protocol or polling channel.
#[derive(Clone)]
pub(crate) struct DesktopCordisApprovalBridge {
    state: Arc<Mutex<DesktopCordisApprovalState>>,
    on_change: Arc<dyn Fn(bool) + Send + Sync>,
}

impl std::fmt::Debug for DesktopCordisApprovalBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DesktopCordisApprovalBridge")
            .field("pending", &self.pending())
            .finish_non_exhaustive()
    }
}

impl Default for DesktopCordisApprovalBridge {
    fn default() -> Self {
        Self::new(|_| {})
    }
}

impl DesktopCordisApprovalBridge {
    pub(crate) fn new(on_change: impl Fn(bool) + Send + Sync + 'static) -> Self {
        Self {
            state: Arc::new(Mutex::new(DesktopCordisApprovalState::default())),
            on_change: Arc::new(on_change),
        }
    }

    #[must_use]
    pub(crate) fn pending(&self) -> Option<DesktopHeldCordisApproval> {
        self.state.lock().ok().and_then(|state| {
            state
                .pending
                .as_ref()
                .map(|pending| pending.request.clone())
        })
    }

    pub(crate) fn allow_once(
        &self,
        id: &ApprovalRequestId,
    ) -> Result<(), DesktopCordisApprovalDecisionError> {
        self.decide(id, ApprovalOutcome::AllowedOnce)
    }

    pub(crate) fn reject(
        &self,
        id: &ApprovalRequestId,
    ) -> Result<(), DesktopCordisApprovalDecisionError> {
        self.decide(id, ApprovalOutcome::Rejected)
    }

    fn decide(
        &self,
        id: &ApprovalRequestId,
        outcome: ApprovalOutcome,
    ) -> Result<(), DesktopCordisApprovalDecisionError> {
        let mut pending = self
            .state
            .lock()
            .map_err(|_| DesktopCordisApprovalDecisionError::Unavailable)?
            .pending
            .take()
            .ok_or(DesktopCordisApprovalDecisionError::Unavailable)?;
        let matches = pending.request.id == *id;
        let answer = if matches {
            outcome
        } else {
            ApprovalOutcome::Unavailable
        };
        let delivered = pending
            .answer
            .take()
            .is_some_and(|sender| sender.send(answer).is_ok());
        (self.on_change)(false);
        if !matches {
            return Err(DesktopCordisApprovalDecisionError::Mismatch);
        }
        if !delivered {
            return Err(DesktopCordisApprovalDecisionError::Unavailable);
        }
        Ok(())
    }

    async fn answer(&self, prompt: &ApprovalPrompt) -> ApprovalOutcome {
        let request = DesktopHeldCordisApproval {
            id: prompt.id().clone(),
            agent_id: prompt.agent().id.clone(),
            session_id: prompt.session_id().clone(),
            tool_name: prompt.tool_name().to_owned(),
            call_id: prompt.call_id().map(str::to_owned),
            reason: prompt.reason().map(str::to_owned),
        };
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let stored = self.state.lock().is_ok_and(|mut state| {
            if state.pending.is_some() {
                return false;
            }
            state.pending = Some(DesktopPendingCordisApproval {
                request: request.clone(),
                answer: Some(sender),
            });
            true
        });
        if !stored {
            return ApprovalOutcome::Unavailable;
        }
        (self.on_change)(true);
        let guard = DesktopCordisPendingGuard {
            bridge: self.clone(),
            id: request.id,
        };
        let outcome = receiver.await.unwrap_or(ApprovalOutcome::Unavailable);
        drop(guard);
        outcome
    }

    fn clear_matching(&self, id: &ApprovalRequestId) {
        let pending = self.state.lock().ok().and_then(|mut state| {
            if state
                .pending
                .as_ref()
                .is_some_and(|pending| pending.request.id == *id)
            {
                state.pending.take()
            } else {
                None
            }
        });
        if let Some(mut pending) = pending {
            if let Some(answer) = pending.answer.take() {
                let _ = answer.send(ApprovalOutcome::Unavailable);
            }
            (self.on_change)(false);
        }
    }

    pub(crate) fn clear(&self) {
        let pending = self
            .state
            .lock()
            .ok()
            .and_then(|mut state| state.pending.take());
        if let Some(mut pending) = pending {
            if let Some(answer) = pending.answer.take() {
                let _ = answer.send(ApprovalOutcome::Unavailable);
            }
            (self.on_change)(false);
        }
    }
}

struct DesktopCordisPendingGuard {
    bridge: DesktopCordisApprovalBridge,
    id: ApprovalRequestId,
}

impl Drop for DesktopCordisPendingGuard {
    fn drop(&mut self) {
        self.bridge.clear_matching(&self.id);
    }
}

/// Short-lock storage for the process-wide Cordis coordinator.
///
/// A live Runtime turn checks the coordinator out so its canonical driver can
/// invoke Application without holding this mutex. Concurrent admissions fail
/// fast while the same coordinator is checked out; dropping the checkout
/// restores it even while unwinding.
#[derive(Debug)]
pub(crate) struct DesktopCordisSlot {
    coordinator: Mutex<Option<DesktopCordisCoordinator>>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum DesktopCordisSlotError {
    #[error("Desktop Cordis coordinator is checked out by the active Runtime turn")]
    CheckedOut,
    #[error("Desktop Cordis coordinator mutex is poisoned")]
    Poisoned,
}

pub(crate) struct DesktopCordisGuard<'a> {
    guard: Option<MutexGuard<'a, Option<DesktopCordisCoordinator>>>,
}

pub(crate) struct DesktopCordisCheckout {
    slot: Arc<DesktopCordisSlot>,
    coordinator: Option<DesktopCordisCoordinator>,
}

impl DesktopCordisSlot {
    pub(crate) fn new(coordinator: DesktopCordisCoordinator) -> Self {
        Self {
            coordinator: Mutex::new(Some(coordinator)),
        }
    }

    pub(crate) fn lock(&self) -> Result<DesktopCordisGuard<'_>, DesktopCordisSlotError> {
        loop {
            let mut guard = self
                .coordinator
                .lock()
                .map_err(|_| DesktopCordisSlotError::Poisoned)?;
            let Some(coordinator) = guard.as_mut() else {
                return Err(DesktopCordisSlotError::CheckedOut);
            };
            let statuses = coordinator.take_deferred_runtime_status();
            if statuses.is_empty() {
                return Ok(DesktopCordisGuard { guard: Some(guard) });
            }
            drop(guard);
            for status in statuses {
                status.announce();
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn try_lock(&self) -> Result<DesktopCordisGuard<'_>, DesktopCordisSlotError> {
        let guard = match self.coordinator.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(_)) => return Err(DesktopCordisSlotError::Poisoned),
            Err(TryLockError::WouldBlock) => return Err(DesktopCordisSlotError::CheckedOut),
        };
        if guard.is_none() {
            return Err(DesktopCordisSlotError::CheckedOut);
        }
        Ok(DesktopCordisGuard { guard: Some(guard) })
    }

    #[cfg(test)]
    pub(crate) fn is_checked_out(&self) -> bool {
        matches!(self.coordinator.try_lock(), Ok(guard) if guard.is_none())
    }

    pub(crate) fn checkout(
        self: &Arc<Self>,
    ) -> Result<DesktopCordisCheckout, DesktopCordisSlotError> {
        loop {
            let mut slot = self
                .coordinator
                .lock()
                .map_err(|_| DesktopCordisSlotError::Poisoned)?;
            let Some(coordinator) = slot.as_mut() else {
                return Err(DesktopCordisSlotError::CheckedOut);
            };
            let statuses = coordinator.take_deferred_runtime_status();
            if statuses.is_empty() {
                let coordinator = slot.take().expect("the coordinator was just observed");
                return Ok(DesktopCordisCheckout {
                    slot: Arc::clone(self),
                    coordinator: Some(coordinator),
                });
            }
            drop(slot);
            for status in statuses {
                status.announce();
            }
        }
    }
}

impl Deref for DesktopCordisGuard<'_> {
    type Target = DesktopCordisCoordinator;

    fn deref(&self) -> &Self::Target {
        self.guard
            .as_ref()
            .and_then(|guard| guard.as_ref())
            .expect("an active Cordis guard always contains its coordinator")
    }
}

impl DerefMut for DesktopCordisGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.guard
            .as_mut()
            .and_then(|guard| guard.as_mut())
            .expect("an active Cordis guard always contains its coordinator")
    }
}

impl Drop for DesktopCordisGuard<'_> {
    fn drop(&mut self) {
        let statuses = self
            .guard
            .as_mut()
            .and_then(|guard| guard.as_mut())
            .map_or_else(Vec::new, |coordinator| {
                coordinator.take_deferred_runtime_status()
            });
        drop(self.guard.take());
        for status in statuses {
            status.announce();
        }
    }
}

impl Deref for DesktopCordisCheckout {
    type Target = DesktopCordisCoordinator;

    fn deref(&self) -> &Self::Target {
        self.coordinator
            .as_ref()
            .expect("a live Cordis checkout always contains its coordinator")
    }
}

impl DerefMut for DesktopCordisCheckout {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.coordinator
            .as_mut()
            .expect("a live Cordis checkout always contains its coordinator")
    }
}

impl Drop for DesktopCordisCheckout {
    fn drop(&mut self) {
        let Some(mut coordinator) = self.coordinator.take() else {
            return;
        };
        let statuses = coordinator.take_deferred_runtime_status();
        let mut slot = self
            .slot
            .coordinator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(
            slot.is_none(),
            "Cordis checkout restored into an occupied slot"
        );
        if slot.is_none() {
            *slot = Some(coordinator);
        }
        drop(slot);
        for status in statuses {
            status.announce();
        }
    }
}

impl DesktopCordisSlotError {
    const fn runtime(self) -> CordisError {
        match self {
            Self::CheckedOut => CordisError::RuntimeDispatchBusy,
            Self::Poisoned => CordisError::RuntimeCoordinatorPoisoned,
        }
    }

    const fn domain_command(self) -> CordisError {
        match self {
            Self::CheckedOut => CordisError::DomainCommandDispatchBusy,
            Self::Poisoned => CordisError::DomainCommandCoordinatorPoisoned,
        }
    }

    const fn effect_execution(self) -> CordisError {
        match self {
            Self::CheckedOut => CordisError::EffectExecutionDispatchBusy,
            Self::Poisoned => CordisError::EffectExecutionCoordinatorPoisoned,
        }
    }

    const fn effect_reconciliation(self) -> CordisError {
        match self {
            Self::CheckedOut => CordisError::EffectReconciliationDispatchBusy,
            Self::Poisoned => CordisError::EffectReconciliationCoordinatorPoisoned,
        }
    }

    const fn effect_verification(self) -> CordisError {
        match self {
            Self::CheckedOut => CordisError::EffectVerificationDispatchBusy,
            Self::Poisoned => CordisError::EffectVerificationCoordinatorPoisoned,
        }
    }
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

const DESKTOP_COMPACT_COMMAND_USAGE: &str = "Usage: /compact (no arguments)";

/// One Desktop-owned human command result. Command text is presentation-only;
/// a successful compaction separately names its durable summary event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DesktopHumanCommandResult {
    Success {
        text: String,
        source_event_seq: Option<u64>,
    },
    Error {
        text: String,
    },
}

/// Whether an input belonged to the Desktop human-command surface. Unknown
/// slash forms and ordinary messages remain available to the normal composer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DesktopHumanCommandDispatch {
    NotCommand,
    Handled(DesktopHumanCommandResult),
}

fn compact_command_raw_input(line: &str) -> Option<&str> {
    let raw_input = line.strip_prefix("/compact")?;
    (raw_input.is_empty()
        || raw_input
            .as_bytes()
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r')))
    .then_some(raw_input)
}

/// Whether the composer must offer this input to the human-command handler.
/// The handler remains the sole owner of usage validation and execution.
pub(crate) fn is_desktop_human_command(line: &str) -> bool {
    compact_command_raw_input(line).is_some()
}

fn manual_compaction_failure_result(code: ManualCompactionErrorCode) -> DesktopHumanCommandResult {
    let text = match code {
        ManualCompactionErrorCode::Busy => {
            "Compaction is unavailable because this process has an active compaction, or the agent is not idle."
        }
        ManualCompactionErrorCode::Cancelled => "Compaction cancelled.",
        ManualCompactionErrorCode::Changed => {
            "The history selected for compaction changed before it could be replaced. The conversation is unchanged; the attempt is recorded in the session log."
        }
        ManualCompactionErrorCode::Summary => {
            "Compaction could not produce a useful summary. The conversation is unchanged; the attempt is recorded in the session log."
        }
        ManualCompactionErrorCode::Commit => {
            "Compaction did not finish cleanly; some session history may have changed. Inspect the current session state before retrying."
        }
        ManualCompactionErrorCode::Persistence => {
            "Compaction finished, but the session could not be saved."
        }
    };
    DesktopHumanCommandResult::Error { text: text.into() }
}

/// One exact Desktop input admitted to the complete Cordis turn driver.
///
/// The private user body is intentionally redacted from `Debug`; provider and
/// model names are routing metadata, not credentials or business authority.
#[allow(
    dead_code,
    reason = "N64 freezes the Desktop complete-turn input consumed by the next live Runtime adapter slice"
)]
pub(crate) struct DesktopAgentTurnRequest {
    session_id: SessionId,
    input: SessionMessage,
    workspace_root: PathBuf,
    config: SessionCallConfig,
    resolved_model: LlmResolvedModel,
    system_prompt: Option<String>,
}

impl DesktopAgentTurnRequest {
    #[allow(
        dead_code,
        reason = "N64 freezes the Desktop complete-turn constructor consumed by the next live Runtime adapter slice"
    )]
    pub(crate) fn new(
        session_id: impl Into<String>,
        message_id: impl Into<String>,
        user_body: impl Into<String>,
        workspace_root: impl Into<PathBuf>,
        config: SessionCallConfig,
    ) -> Result<Self, SessionError> {
        let resolved_model = LlmResolvedModel::new(config.provider.clone(), config.model.clone());
        Ok(Self {
            session_id: SessionId::new(session_id.into())?,
            input: SessionMessage {
                id: message_id.into(),
                role: SessionMessageRole::User,
                content: vec![SessionContentBlock::Text {
                    text: user_body.into(),
                }],
                source: SessionMessageSource::User,
            },
            workspace_root: workspace_root.into(),
            config,
            resolved_model,
            system_prompt: None,
        })
    }

    pub(crate) fn job_completion(
        session_id: impl Into<String>,
        message_id: impl Into<String>,
        body: impl Into<String>,
        workspace_root: impl Into<PathBuf>,
        config: SessionCallConfig,
    ) -> Result<Self, SessionError> {
        let resolved_model = LlmResolvedModel::new(config.provider.clone(), config.model.clone());
        Ok(Self {
            session_id: SessionId::new(session_id.into())?,
            input: SessionMessage {
                id: message_id.into(),
                role: SessionMessageRole::User,
                content: vec![SessionContentBlock::Text { text: body.into() }],
                source: SessionMessageSource::Plugin {
                    plugin: "tool-jobs".into(),
                    compaction_id: None,
                    source_command_id: None,
                },
            },
            workspace_root: workspace_root.into(),
            config,
            resolved_model,
            system_prompt: None,
        })
    }

    #[must_use]
    pub(crate) fn with_system_prompt(mut self, system_prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(system_prompt.into());
        self
    }

    pub(crate) fn resolve_with(mut self, adapter: &impl LlmAdapter) -> Result<Self, LlmError> {
        self.resolved_model = adapter.prepare_model(&self.config.provider, &self.config.model)?;
        Ok(self)
    }

    fn is_human_input(&self) -> bool {
        self.input.source == SessionMessageSource::User
    }
}

impl std::fmt::Debug for DesktopAgentTurnRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DesktopAgentTurnRequest")
            .field("session_id", &self.session_id)
            .field("message_id", &self.input.id)
            .field("workspace_root", &"[REDACTED]")
            .field("config", &self.config)
            .field("resolved_model", &self.resolved_model)
            .field(
                "system_prompt",
                &self.system_prompt.as_ref().map(|_| "[REDACTED]"),
            )
            .field("user_body", &"[REDACTED]")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "N64 freezes pre-dispatch Session durability for the next live Runtime adapter slice"
)]
struct DesktopPersistedLlmAdapter<A> {
    adapter: Arc<A>,
    sessions: Arc<SessionStore>,
    resolved_model: LlmResolvedModel,
}

impl<A> DesktopPersistedLlmAdapter<A> {
    #[allow(
        dead_code,
        reason = "N64 freezes pre-dispatch Session durability for the next live Runtime adapter slice"
    )]
    fn new(adapter: A, sessions: Arc<SessionStore>, resolved_model: LlmResolvedModel) -> Self {
        Self {
            adapter: Arc::new(adapter),
            sessions,
            resolved_model,
        }
    }
}

impl<A> LlmAdapter for DesktopPersistedLlmAdapter<A>
where
    A: LlmAdapter,
{
    fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
        if self.resolved_model.provider() != provider || self.resolved_model.model() != model {
            return Err(LlmError::InvalidModelInfo {
                provider: provider.to_owned(),
                model: model.to_owned(),
                expected: "the Desktop-pinned provider/model identity",
            });
        }
        Ok(self.resolved_model.clone())
    }

    fn stream(&self, request: LlmGenerateRequest) -> Result<LlmAdapterStream, SessionLlmFailure> {
        let session_id = request.session_id().cloned().ok_or_else(|| {
            desktop_agent_failure(
                "SESSION_ID_MISSING",
                "Desktop Cordis model request is missing its Session identity",
            )
        })?;
        let session = self
            .sessions
            .get(&session_id)
            .map_err(|_| {
                desktop_agent_failure(
                    "SESSION_LOOKUP_FAILED",
                    "Desktop Cordis Session lookup failed before provider dispatch",
                )
            })?
            .ok_or_else(|| {
                desktop_agent_failure(
                    "SESSION_NOT_LIVE",
                    "Desktop Cordis Session is not live before provider dispatch",
                )
            })?;
        let sessions = self.sessions.clone();
        let adapter = Arc::clone(&self.adapter);
        let resolved_model = self.resolved_model.clone();
        Ok(Box::pin(
            stream::once(async move {
                match sessions.flush(&session).await {
                    Ok(true) => {
                        let config = request.config();
                        match adapter.prepare_model(&config.provider, &config.model) {
                            Ok(observed) if observed == resolved_model => adapter
                                .stream(request)
                                .unwrap_or_else(desktop_agent_failure_stream),
                            Ok(_) => desktop_agent_failure_stream(desktop_agent_failure(
                                "MODEL_PREPARATION_DIVERGED",
                                "Desktop Cordis adapter preparation diverged from the durable request",
                            )),
                            Err(_) => desktop_agent_failure_stream(desktop_agent_failure(
                                "MODEL_PREPARATION_FAILED",
                                "Desktop Cordis adapter preparation failed after request persistence",
                            )),
                        }
                    }
                    Ok(false) => desktop_agent_failure_stream(desktop_agent_failure(
                        "SESSION_PERSISTENCE_UNBOUND",
                        "Desktop Cordis request prefix has no persistence listener",
                    )),
                    Err(_) => desktop_agent_failure_stream(desktop_agent_failure(
                        "SESSION_FLUSH_FAILED",
                        "Desktop Cordis request prefix could not be persisted",
                    )),
                }
            })
            .flatten(),
        ))
    }
}

#[allow(
    dead_code,
    reason = "N64 freezes redacted adapter failures for the next live Runtime adapter slice"
)]
fn desktop_agent_failure(code: &str, message: &str) -> SessionLlmFailure {
    SessionLlmFailure {
        message: message.to_owned(),
        code: code.to_owned(),
        status: None,
        provider_retry_after_ms: None,
        request_id: None,
    }
}

#[allow(
    dead_code,
    reason = "N64 freezes redacted adapter failures for the next live Runtime adapter slice"
)]
fn desktop_agent_failure_stream(failure: SessionLlmFailure) -> LlmAdapterStream {
    Box::pin(stream::once(async move { Err(failure) }))
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

fn runtime_open_turn(events: &[SessionEvent]) -> Option<u64> {
    events.iter().fold(None, |open, event| match &event.kind {
        SessionEventKind::TurnStart { turn } => Some(*turn),
        SessionEventKind::TurnEnd { turn, .. } if open == Some(*turn) => None,
        _ => open,
    })
}

fn session_history_contains_message_id(events: &[SessionEvent], message_id: &str) -> bool {
    events.iter().any(|event| {
        matches!(
            &event.kind,
            SessionEventKind::UserMessage { message, .. }
                | SessionEventKind::AssistantMessage { message, .. }
                | SessionEventKind::ToolResult { message, .. }
                if message.id == message_id
        )
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
            idle_job_wake_budgets: Vec::new(),
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

    #[must_use]
    pub(crate) fn retained_runtime_agent_identity(
        &self,
        agent: &hartevo_cordis::AgentRef,
    ) -> Option<RuntimeAgentIdentity> {
        self.host.retained_runtime_agent_identity(agent)
    }

    pub(crate) fn jobs(&self) -> Result<Arc<JobsSurface>, CordisError> {
        self.host
            .context()
            .jobs::<JobsSurface>()
            .ok_or_else(|| CordisError::MissingDependencies(vec![keys::JOBS.to_string()]))
    }

    /// Read one exact durable input identity without deriving the visible
    /// transcript. This keeps pre-N65 bridge recovery idempotent while also
    /// recognizing messages that a later Session surface has shadowed.
    pub(crate) fn has_committed_message_id(
        &self,
        session_id: &str,
        message_id: &str,
    ) -> Result<bool, DesktopAgentTurnError> {
        self.ensure_root_fiber_active()?;
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopAgentTurnError::MissingSessionStore)?;
        let session_id = SessionId::new(session_id.to_owned())?;
        let Some(session) = sessions.get(&session_id)? else {
            return Ok(false);
        };
        Ok(session_history_contains_message_id(
            &session.events()?,
            message_id,
        ))
    }

    /// Snapshot one already validated live Session. Callers use this only
    /// after the awaited flush boundary, or after SQLCipher restore, so the
    /// detached prefix is safe input to Application's draft-proof parser.
    pub(crate) fn session_checkpoint(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionCheckpoint>, DesktopAgentTurnError> {
        self.ensure_root_fiber_active()?;
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopAgentTurnError::MissingSessionStore)?;
        let session_id = SessionId::new(session_id.to_owned())?;
        let Some(session) = sessions.get(&session_id)? else {
            return Ok(None);
        };
        Ok(Some(SessionCheckpoint {
            header: session.header()?,
            events: session.events()?,
        }))
    }

    /// Run one idle-session manual compaction through the Desktop persistence
    /// and request-scoped provider boundary.
    ///
    /// The persisted adapter flushes the standalone start marker before the
    /// provider stream is consumed. `compact_now` owns the terminal flush and
    /// the complete manual failure taxonomy. The temporary provider route is
    /// removed before this method returns on every result path.
    pub(crate) async fn compact_session<A>(
        &mut self,
        session_id: &str,
        source_command_id: Option<String>,
        adapter: A,
        cancellation: &LifecycleCancellation,
    ) -> Result<Option<CompactionResult>, DesktopManualCompactionError>
    where
        A: LlmAdapter,
    {
        self.ensure_root_fiber_active()?;
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopManualCompactionError::MissingSessionStore)?;
        let session_id = SessionId::new(session_id.to_owned())?;
        let session = sessions
            .get(&session_id)?
            .ok_or_else(|| DesktopManualCompactionError::SessionNotFound(session_id.to_string()))?;

        if cancellation.is_cancelled() {
            return compact_now(
                self.host.context_mut(),
                &session,
                source_command_id,
                cancellation,
            )
            .await
            .map_err(Into::into);
        }
        // With fewer than two visible nodes the backend necessarily retains
        // the newest node. Preserve its true no-op contract without requiring
        // a request header or mounting a provider route.
        if session.surface()?.nodes.len() < 2 {
            return Ok(None);
        }
        let header = session.request_header()?.ok_or_else(|| {
            DesktopManualCompactionError::MissingRequestHeader(session_id.to_string())
        })?;
        let provider = header.config.provider.clone();
        // Resolve before opening the durable bracket; the persisted wrapper
        // revalidates the same descriptor after flushing compaction/start.
        let resolved_model = adapter
            .prepare_model(&provider, &header.config.model)
            .map_err(CordisError::from)?;
        let registration = register_llm_adapter(
            self.host.context_mut(),
            [provider],
            DesktopPersistedLlmAdapter::new(adapter, Arc::clone(&sessions), resolved_model),
        )?;
        let outcome = compact_now(
            self.host.context_mut(),
            &session,
            source_command_id,
            cancellation,
        )
        .await;
        registration.dispose();
        outcome.map_err(Into::into)
    }

    /// Parse and execute the argument-free Desktop `/compact` command.
    ///
    /// Inputs outside this exact lowercase command fall through untouched.
    /// Expected manual-compaction failures are stable human results; mounting,
    /// routing, and Session failures remain typed coordinator errors.
    pub(crate) async fn dispatch_human_command<A>(
        &mut self,
        session_id: &str,
        command_id: String,
        line: &str,
        adapter: A,
        cancellation: &LifecycleCancellation,
    ) -> Result<DesktopHumanCommandDispatch, DesktopManualCompactionError>
    where
        A: LlmAdapter,
    {
        let Some(raw_input) = compact_command_raw_input(line) else {
            return Ok(DesktopHumanCommandDispatch::NotCommand);
        };
        if !raw_input.trim().is_empty() {
            return Ok(DesktopHumanCommandDispatch::Handled(
                DesktopHumanCommandResult::Error {
                    text: DESKTOP_COMPACT_COMMAND_USAGE.into(),
                },
            ));
        }

        match self
            .compact_session(session_id, Some(command_id), adapter, cancellation)
            .await
        {
            Ok(None) => Ok(DesktopHumanCommandDispatch::Handled(
                DesktopHumanCommandResult::Success {
                    text: "No compactable history yet.".into(),
                    source_event_seq: None,
                },
            )),
            Ok(Some(result)) => Ok(DesktopHumanCommandDispatch::Handled(
                DesktopHumanCommandResult::Success {
                    text: format!(
                        "Compacted {} history items (~{} tokens).",
                        result.shadowed_seqs.len(),
                        result.shadowed_token_count
                    ),
                    source_event_seq: Some(result.summary_seq),
                },
            )),
            Err(_) if cancellation.is_cancelled() => Ok(DesktopHumanCommandDispatch::Handled(
                manual_compaction_failure_result(ManualCompactionErrorCode::Cancelled),
            )),
            Err(DesktopManualCompactionError::Manual(error)) => {
                Ok(DesktopHumanCommandDispatch::Handled(
                    manual_compaction_failure_result(error.code()),
                ))
            }
            Err(error) => Err(error),
        }
    }

    /// Run one complete Cordis turn through a request-scoped Desktop adapter.
    ///
    /// The queued input is durable before admission, the canonical request
    /// prefix is durable before adapter dispatch, and the terminal turn is
    /// durable before this method returns. The provider route exists only for
    /// this call and is removed on both success and failure.
    #[allow(
        dead_code,
        reason = "the full-invariant driver remains the focused contract test seam; production Runtime uses the permit-bound entry below"
    )]
    pub(crate) async fn run_agent_turn<A>(
        &mut self,
        request: DesktopAgentTurnRequest,
        adapter: A,
        cancellation: &LifecycleCancellation,
    ) -> Result<AgentTurnOutcome, DesktopAgentTurnError>
    where
        A: LlmAdapter,
    {
        self.run_agent_turn_with_permit(request, adapter, cancellation, None, None)
            .await
    }

    /// Run the Desktop turn under the same active Runtime permit that encloses
    /// the real Application operation. This selects Cordis' read/plan gate;
    /// ordinary agent and Effect paths retain full consent and approval gates.
    pub(crate) async fn run_authorized_runtime_agent_turn<A>(
        &mut self,
        request: DesktopAgentTurnRequest,
        adapter: A,
        cancellation: &LifecycleCancellation,
        permit: &RuntimeDispatchPermit,
        approval_bridge: Option<&DesktopCordisApprovalBridge>,
    ) -> Result<AgentTurnOutcome, DesktopAgentTurnError>
    where
        A: LlmAdapter,
    {
        self.run_agent_turn_with_permit(
            request,
            adapter,
            cancellation,
            Some(permit),
            approval_bridge,
        )
        .await
    }

    /// Durably queue one grouped idle-job completion follow-up for the exact
    /// retained Agent. Returning `None` is the normal suppressed/budgeted path.
    pub(crate) async fn prepare_idle_job_completion_followup(
        &mut self,
        permit: &RuntimeDispatchPermit,
        session_id: &SessionId,
        message_id: String,
        workspace_root: PathBuf,
        config: SessionCallConfig,
    ) -> Result<Option<(DesktopAgentTurnRequest, String)>, DesktopAgentTurnError> {
        self.ensure_root_fiber_active()?;
        let agent = permit.agent();
        if agent.status() != hartevo_cordis::AgentStatus::Running {
            return Ok(None);
        }
        let Some(identity) = self.host.retained_runtime_agent_identity(agent) else {
            return Ok(None);
        };
        if identity.mission() != session_id.as_str()
            || !self
                .idle_job_wake_budgets
                .iter()
                .any(|budget| budget.agent.is_same_lifecycle(agent) && budget.remaining > 0)
        {
            return Ok(None);
        }
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopAgentTurnError::MissingSessionStore)?;
        let session = sessions
            .get(session_id)?
            .ok_or_else(|| DesktopAgentTurnError::SessionBusy(session_id.to_string()))?;
        if runtime_open_turn(&session.events()?).is_some() || session.inbox().has_pending()? {
            return Ok(None);
        }
        let jobs = self
            .host
            .context()
            .jobs::<JobsSurface>()
            .ok_or_else(|| CordisError::MissingDependencies(vec![keys::JOBS.into()]))?;
        let notices = jobs.unreported_terminal(agent);
        if notices.is_empty()
            || notices
                .iter()
                .any(|notice| notice.owner_session() != session_id.as_str())
        {
            return Ok(None);
        }
        let body = notices
            .iter()
            .map(crate::sandbox_provider::background_job_completion_notice)
            .collect::<Vec<_>>()
            .join("\n");
        let request = DesktopAgentTurnRequest::job_completion(
            session_id.as_str(),
            message_id,
            body.clone(),
            workspace_root,
            config,
        )?;
        session.inbox().append_next_turn(request.input.clone())?;
        if !sessions.flush(&session).await? {
            return Err(DesktopAgentTurnError::PersistenceUnavailable);
        }
        let ids = notices
            .iter()
            .map(|notice| notice.id().clone())
            .collect::<Vec<JobId>>();
        let _ = jobs.mark_terminal_reported(agent, &ids);
        let consumed = self.consume_idle_job_completion_wake_budget(agent);
        debug_assert!(consumed, "eligibility reserved one wake budget");
        Ok(Some((request, body)))
    }

    fn idle_job_completion_is_eligible(
        &self,
        agent: &hartevo_cordis::AgentRef,
        session_id: &SessionId,
    ) -> Result<bool, DesktopAgentTurnError> {
        if agent.status() != hartevo_cordis::AgentStatus::Idle
            || !self
                .idle_job_wake_budgets
                .iter()
                .any(|budget| budget.agent.is_same_lifecycle(agent) && budget.remaining > 0)
        {
            return Ok(false);
        }
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopAgentTurnError::MissingSessionStore)?;
        let Some(session) = sessions.get(session_id)? else {
            return Ok(false);
        };
        if runtime_open_turn(&session.events()?).is_some() || session.inbox().has_pending()? {
            return Ok(false);
        }
        let jobs = self
            .host
            .context()
            .jobs::<JobsSurface>()
            .ok_or_else(|| CordisError::MissingDependencies(vec![keys::JOBS.to_string()]))?;
        let notices = jobs.unreported_terminal(agent);
        Ok(!notices.is_empty()
            && notices
                .iter()
                .all(|notice| notice.owner_session() == session_id.as_str()))
    }

    fn reset_idle_job_completion_wake_budget(&mut self, agent: &hartevo_cordis::AgentRef) {
        self.idle_job_wake_budgets
            .retain(|budget| !budget.agent.is_same_lifecycle(agent));
        self.idle_job_wake_budgets.push(DesktopIdleJobWakeBudget {
            agent: agent.clone(),
            remaining: IDLE_JOB_COMPLETION_WAKE_BUDGET,
        });
    }

    fn consume_idle_job_completion_wake_budget(
        &mut self,
        agent: &hartevo_cordis::AgentRef,
    ) -> bool {
        let Some(budget) = self
            .idle_job_wake_budgets
            .iter_mut()
            .find(|budget| budget.agent.is_same_lifecycle(agent) && budget.remaining > 0)
        else {
            return false;
        };
        budget.remaining -= 1;
        true
    }

    fn reset_idle_job_wake_budget_for_request(
        &mut self,
        request: &DesktopAgentTurnRequest,
        runtime_permit: Option<&RuntimeDispatchPermit>,
    ) {
        if request.is_human_input()
            && let Some(permit) = runtime_permit
        {
            self.reset_idle_job_completion_wake_budget(permit.agent());
        }
    }

    fn register_tool_approval_answerer(
        &mut self,
        session_id: &SessionId,
        runtime_permit: Option<&RuntimeDispatchPermit>,
        approval_bridge: Option<&DesktopCordisApprovalBridge>,
    ) -> Result<Option<ListenerHandle>, CordisError> {
        let (Some(permit), Some(bridge)) = (runtime_permit, approval_bridge) else {
            return Ok(None);
        };
        let expected_agent = permit.agent().clone();
        let expected_session = session_id.clone();
        let bridge = bridge.clone();
        self.host
            .context_mut()
            .on_serial_with_options(
                approval_events::APPROVAL_REQUEST,
                EventOptions {
                    prepend: true,
                    global: false,
                },
                move |prompt| {
                    let expected_agent = expected_agent.clone();
                    let expected_session = expected_session.clone();
                    let bridge = bridge.clone();
                    async move {
                        if !prompt.agent().is_same_lifecycle(&expected_agent)
                            || prompt.session_id() != &expected_session
                        {
                            return Ok::<_, std::convert::Infallible>(BailOutcome::Continue(
                                NonBail::Undefined,
                            ));
                        }
                        Ok(BailOutcome::Bail(bridge.answer(&prompt).await))
                    }
                },
            )
            .map(Some)
    }

    fn register_request_prompt(
        &mut self,
        request: &DesktopAgentTurnRequest,
    ) -> Result<Option<RegistrationHandle>, CordisError> {
        request
            .system_prompt
            .as_ref()
            .map(|system_prompt| {
                register_prompt_section(
                    self.host.context_mut(),
                    PromptSection::new(
                        format!("desktop-request:{}", request.input.id),
                        1_000,
                        system_prompt.clone(),
                    ),
                )
            })
            .transpose()
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one request lifetime owns durable input, scoped prompt/provider/approval registrations, terminal flush, and exact teardown"
    )]
    async fn run_agent_turn_with_permit<A>(
        &mut self,
        request: DesktopAgentTurnRequest,
        adapter: A,
        cancellation: &LifecycleCancellation,
        runtime_permit: Option<&RuntimeDispatchPermit>,
        approval_bridge: Option<&DesktopCordisApprovalBridge>,
    ) -> Result<AgentTurnOutcome, DesktopAgentTurnError>
    where
        A: LlmAdapter,
    {
        if let Some(bridge) = approval_bridge {
            bridge.clear();
        }
        self.ensure_root_fiber_active()?;
        let sessions = self
            .host
            .context()
            .sessions::<SessionStore>()
            .ok_or(DesktopAgentTurnError::MissingSessionStore)?;
        let session = sessions.get_or_create(request.session_id.clone())?;
        let events = session.events()?;
        if runtime_open_turn(&events).is_some() || !session.inbox().next_step()?.is_empty() {
            return Err(DesktopAgentTurnError::SessionBusy(
                request.session_id.to_string(),
            ));
        }
        if session_history_contains_message_id(&events, &request.input.id) {
            return Err(DesktopAgentTurnError::MessageAlreadyCommitted {
                session_id: request.session_id.to_string(),
                message_id: request.input.id,
            });
        }
        let _workspace_binding =
            bind_sandbox_workspace(self.host.context(), &session, &request.workspace_root)?;

        let pending = session.inbox().next_turn()?;
        if pending.is_empty() {
            session.inbox().append_next_turn(request.input.clone())?;
        } else if pending != [request.input.clone()] {
            return Err(DesktopAgentTurnError::SessionBusy(
                request.session_id.to_string(),
            ));
        }
        if !sessions.flush(&session).await? {
            return Err(DesktopAgentTurnError::PersistenceUnavailable);
        }
        self.reset_idle_job_wake_budget_for_request(&request, runtime_permit);

        let prompt_registration = self.register_request_prompt(&request)?;
        let approval_registration = match self.register_tool_approval_answerer(
            &request.session_id,
            runtime_permit,
            approval_bridge,
        ) {
            Ok(registration) => registration,
            Err(error) => {
                if let Some(registration) = prompt_registration.as_ref() {
                    registration.dispose();
                }
                return Err(error.into());
            }
        };
        let provider = request.config.provider.clone();
        let registration = match register_llm_adapter(
            self.host.context_mut(),
            [provider],
            DesktopPersistedLlmAdapter::new(adapter, sessions.clone(), request.resolved_model),
        ) {
            Ok(registration) => registration,
            Err(error) => {
                if let Some(registration) = prompt_registration.as_ref() {
                    registration.dispose();
                }
                if let Some(registration) = approval_registration.as_ref() {
                    registration.dispose();
                }
                if let Some(bridge) = approval_bridge {
                    bridge.clear();
                }
                return Err(error.into());
            }
        };
        let outcome = match runtime_permit {
            Some(permit) => {
                self.host
                    .run_authorized_runtime_agent_turn(
                        permit,
                        &request.session_id,
                        request.config,
                        cancellation,
                    )
                    .await
            }
            None => {
                run_cordis_agent_turn(
                    self.host.context_mut(),
                    &request.session_id,
                    request.config,
                    cancellation,
                )
                .await
            }
        };
        registration.dispose();
        if let Some(registration) = prompt_registration.as_ref() {
            registration.dispose();
        }
        if let Some(registration) = approval_registration.as_ref() {
            registration.dispose();
        }
        if let Some(bridge) = approval_bridge {
            bridge.clear();
        }
        let flushed = sessions.flush(&session).await;

        match (outcome, flushed) {
            (Ok(outcome), Ok(true)) => Ok(outcome),
            (Ok(_) | Err(_), Ok(false)) => Err(DesktopAgentTurnError::PersistenceUnavailable),
            (Ok(_), Err(flush)) => Err(flush.into()),
            (Err(run), Ok(true)) => Err(run.into()),
            (Err(run), Err(flush)) => Err(DesktopAgentTurnError::RunAndFlush {
                run: Box::new(run),
                flush,
            }),
        }
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

    fn take_deferred_runtime_status(&mut self) -> Vec<RuntimeStatusCompletion> {
        self.host.take_deferred_runtime_status()
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
    #[cfg(target_os = "macos")]
    {
        crate::sandbox_provider::mount_macos_sandbox_provider(&mut host)?;
        crate::sandbox_provider::mount_macos_sandboxed_bash_tool(&mut host)?;
    }
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

#[allow(
    dead_code,
    reason = "N64 freezes typed complete-turn failures for the next live Runtime adapter slice"
)]
#[derive(Debug, Error)]
pub(crate) enum DesktopAgentTurnError {
    #[error("Cordis did not mount its Session store")]
    MissingSessionStore,
    #[error("Desktop Cordis Session {0} already owns pending or open turn work")]
    SessionBusy(String),
    #[error("Desktop Cordis Session {session_id} already committed message identity {message_id}")]
    MessageAlreadyCommitted {
        session_id: String,
        message_id: String,
    },
    #[error("Desktop Cordis Session persistence is unavailable")]
    PersistenceUnavailable,
    #[error("Cordis turn failed ({run}) and its terminal flush also failed ({flush})")]
    RunAndFlush {
        run: Box<CordisError>,
        flush: SessionError,
    },
    #[error(transparent)]
    Cordis(#[from] CordisError),
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    #[error(transparent)]
    Session(#[from] SessionError),
}

#[derive(Debug, Error)]
pub(crate) enum DesktopManualCompactionError {
    #[error("Cordis did not mount its Session store")]
    MissingSessionStore,
    #[error("Desktop Cordis Session {0} does not exist")]
    SessionNotFound(String),
    #[error("Desktop Cordis Session {0} has no request route for summarization")]
    MissingRequestHeader(String),
    #[error(transparent)]
    Manual(#[from] ManualCompactionError),
    #[error(transparent)]
    Cordis(#[from] CordisError),
    #[error(transparent)]
    Session(#[from] SessionError),
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
            delegation_depth: checkpoint.header.delegation_depth,
            seed_length: checkpoint.header.seed_length,
        },
        events: checkpoint
            .events
            .iter()
            .map(encode_event)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the Desktop persistence boundary keeps every Cordis Session event conversion exhaustive"
)]
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
            SessionEventKind::SubagentDescriptor { descriptor } => {
                PersistedSessionEventKind::SubagentDescriptor {
                    descriptor: serde_json::to_value(descriptor).map_err(|_| {
                        SessionError::InvalidSubagentDescriptor {
                            expected: "valid JSON",
                        }
                    })?,
                }
            }
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
            SessionEventKind::ApprovalAsked { approval } => {
                PersistedSessionEventKind::ApprovalAsked {
                    approval: approval.to_json_value()?,
                }
            }
            SessionEventKind::ApprovalDecided { approval } => {
                PersistedSessionEventKind::ApprovalDecided {
                    approval: approval.to_json_value()?,
                }
            }
            SessionEventKind::ApprovalPolicy { approval } => {
                PersistedSessionEventKind::ApprovalPolicy {
                    approval: approval.to_json_value()?,
                }
            }
            SessionEventKind::SandboxMode { sandbox } => PersistedSessionEventKind::SandboxMode {
                sandbox: sandbox.to_json_value()?,
            },
            SessionEventKind::LlmRetry { retry } => PersistedSessionEventKind::LlmRetry {
                retry: retry.to_json_value()?,
            },
            SessionEventKind::LlmRetryStarted { started } => {
                PersistedSessionEventKind::LlmRetryStarted {
                    started: started.to_json_value()?,
                }
            }
            SessionEventKind::CompactionStart { compaction } => {
                PersistedSessionEventKind::CompactionStart {
                    compaction: compaction.to_json_value()?,
                }
            }
            SessionEventKind::CompactionSummary { compaction } => {
                PersistedSessionEventKind::CompactionSummary {
                    compaction: compaction.to_json_value()?,
                }
            }
            SessionEventKind::CompactionEnd { compaction } => {
                PersistedSessionEventKind::CompactionEnd {
                    compaction: compaction.to_json_value()?,
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
        delegation_depth: checkpoint.header.delegation_depth,
        seed_length: checkpoint.header.seed_length,
    };
    let events = checkpoint
        .events
        .iter()
        .map(decode_event)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((header, events))
}

#[allow(
    clippy::too_many_lines,
    reason = "the Desktop persistence boundary keeps every neutral Session event conversion exhaustive"
)]
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
            PersistedSessionEventKind::SubagentDescriptor { descriptor } => {
                SessionEventKind::SubagentDescriptor {
                    descriptor: serde_json::from_value::<OneShotSubagentDescriptor>(
                        descriptor.clone(),
                    )
                    .map_err(|_| SessionError::InvalidSubagentDescriptor {
                        expected: "the versioned one-shot schema",
                    })?,
                }
            }
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
            PersistedSessionEventKind::ApprovalAsked { approval } => {
                SessionEventKind::ApprovalAsked {
                    approval: SessionApprovalAsked::from_json_value(approval)?,
                }
            }
            PersistedSessionEventKind::ApprovalDecided { approval } => {
                SessionEventKind::ApprovalDecided {
                    approval: SessionApprovalDecided::from_json_value(approval)?,
                }
            }
            PersistedSessionEventKind::ApprovalPolicy { approval } => {
                SessionEventKind::ApprovalPolicy {
                    approval: SessionApprovalPolicy::from_json_value(approval)?,
                }
            }
            PersistedSessionEventKind::SandboxMode { sandbox } => SessionEventKind::SandboxMode {
                sandbox: SessionSandboxMode::from_json_value(sandbox)?,
            },
            PersistedSessionEventKind::LlmRetry { retry } => SessionEventKind::LlmRetry {
                retry: SessionLlmRetry::from_json_value(retry)?,
            },
            PersistedSessionEventKind::LlmRetryStarted { started } => {
                SessionEventKind::LlmRetryStarted {
                    started: SessionLlmRetryStarted::from_json_value(started)?,
                }
            }
            PersistedSessionEventKind::CompactionStart { compaction } => {
                SessionEventKind::CompactionStart {
                    compaction: SessionCompactionStart::from_json_value(compaction)?,
                }
            }
            PersistedSessionEventKind::CompactionSummary { compaction } => {
                SessionEventKind::CompactionSummary {
                    compaction: SessionCompactionSummary::from_json_value(compaction)?,
                }
            }
            PersistedSessionEventKind::CompactionEnd { compaction } => {
                SessionEventKind::CompactionEnd {
                    compaction: SessionCompactionEnd::from_json_value(compaction)?,
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
                message: SessionMessage::from_json_value(message)?,
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
                message: SessionMessage::from_json_value(message)?,
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
        message: SessionMessage::from_json_value(message)?,
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
    cordis: &Arc<DesktopCordisSlot>,
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
        let mut host = cordis.lock().map_err(DesktopCordisSlotError::runtime)?;
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
        Err(error) => Err(error.runtime()),
    };
    let finish = match completion {
        Ok(completion) => completion.announce().err(),
        Err(error) => Some(error),
    };
    if let Some(error) = AuthorityDispatchError::from_phases(started, authority, finish, None) {
        Err(error)
    } else {
        output.ok_or_else(|| {
            AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimePermitMismatch))
        })
    }
}

/// Wake one exact retained Idle Agent after a background job becomes terminal.
///
/// Authorization and the Running transition happen before the durable plugin
/// input is queued. Busy, stale, disposed, or exhausted-budget observations
/// are ordinary suppression and never invoke the adapter.
#[allow(
    clippy::too_many_arguments,
    reason = "one narrow wake boundary binds exact job ownership, fresh Domain facts, Session input, Runtime route, and lifecycle settlement"
)]
pub(crate) fn dispatch_idle_job_completion_runtime<Execute, Output, AdapterError>(
    cordis: &Arc<DesktopCordisSlot>,
    notice: &JobTerminalNotice,
    scope: AuthorityScope,
    consent: &ConsentState,
    record: Option<&ConsentRecord>,
    approval: Option<&Approval>,
    now: DateTime<Utc>,
    execute: Execute,
) -> Result<Option<Output>, AuthorityDispatchError<AdapterError>>
where
    Execute: FnOnce(&RuntimeDispatchPermit) -> Result<Output, AdapterError>,
{
    let mut permit = {
        let mut host = match cordis.lock() {
            Ok(host) => host,
            Err(DesktopCordisSlotError::CheckedOut) => return Ok(None),
            Err(error) => return Err(error.runtime().into()),
        };
        if notice.owner_agent().status() != hartevo_cordis::AgentStatus::Idle {
            return Ok(None);
        }
        let Some(identity) = host
            .host
            .retained_runtime_agent_identity(notice.owner_agent())
        else {
            return Ok(None);
        };
        if identity.tenant() != scope.tenant_id()
            || identity.project() != scope.project_id()
            || identity.mission() != scope.mission_id()
            || identity.mission() != notice.owner_session().as_str()
            || !host
                .idle_job_completion_is_eligible(notice.owner_agent(), notice.owner_session())
                .unwrap_or(false)
        {
            return Ok(None);
        }
        match host.bind_and_authorize_runtime(
            scope,
            kernel_consent_state(consent),
            record.map(kernel_consent_record),
            approval.map(kernel_approval),
            now,
        ) {
            Ok(permit) => permit,
            Err(CordisError::RuntimeDispatchBusy) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
    };

    let started = permit.announce_started().err();
    let (output, authority) = if started.is_none() {
        match execute(&permit) {
            Ok(output) => (Some(output), None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };

    let completion = match cordis.lock() {
        Ok(mut host) => host.finish_runtime(permit),
        Err(error) => Err(error.runtime()),
    };
    let finish = match completion {
        Ok(completion) => completion.announce().err(),
        Err(error) => Some(error),
    };
    if let Some(error) = AuthorityDispatchError::from_phases(started, authority, finish, None) {
        Err(error)
    } else {
        output.map(Some).ok_or_else(|| {
            AuthorityDispatchError::Cordis(Box::new(CordisError::RuntimePermitMismatch))
        })
    }
}

/// Bind exact live facts, issue a one-shot Domain-command permit, release the
/// coordinator lock for Application, then settle the permit under a second
/// short lock. This path grants no Effect execution capability.
pub(crate) fn dispatch_live_domain_command<Execute, Output, AdapterError>(
    cordis: &Arc<DesktopCordisSlot>,
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
            .map_err(DesktopCordisSlotError::domain_command)?;
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
        Err(error) => Some(error.domain_command()),
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
    cordis: &Arc<DesktopCordisSlot>,
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
            .map_err(DesktopCordisSlotError::effect_execution)?;
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
        Err(error) => Some(error.effect_execution()),
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
    cordis: &Arc<DesktopCordisSlot>,
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
            .map_err(DesktopCordisSlotError::effect_reconciliation)?;
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
        Err(error) => Some(error.effect_reconciliation()),
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
    cordis: &Arc<DesktopCordisSlot>,
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
            .map_err(DesktopCordisSlotError::effect_verification)?;
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
        Err(error) => Some(error.effect_verification()),
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
    #[cfg(target_os = "macos")]
    use std::collections::HashMap;
    use std::collections::VecDeque;
    use std::error::Error;
    use std::fmt::{self, Display};
    #[cfg(target_os = "macos")]
    use std::sync::Condvar;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::thread;
    use std::time::Duration as StdDuration;

    use chrono::{Duration, TimeZone, Utc};
    use futures_util::stream;
    #[cfg(target_os = "macos")]
    use hartevo_application::llm_deepseek::{
        DEEPSEEK_PROVIDER_ID, DeepSeekAdapter, DeepSeekConnection, DeepSeekTransport,
        DeepSeekWireResponse,
    };
    use hartevo_cordis::{
        AgentInboxOutcome, AgentInboxTarget, AgentRef, AgentStatus, AgentStatusChange, AgentStep,
        AgentsSurface, ApprovalOutcome, ApprovalPolicy, ApprovalPolicySource, ApprovalRequestId,
        AuthorityDispatchError, AuthorityScope, CompactionCheckpoint, CompactionId,
        CompactionSummaryDraft, CordisError, CordisHost, DomainCommandBinding, DomainCommandKind,
        DomainSurface, EffectExecutionBinding, EffectReconciliationBinding,
        EffectVerificationBinding, FiberState, KernelApproval, KernelApprovalDecision,
        KernelConsentState, LifecycleCancellation, LlmAdapter, LlmAdapterStream, LlmError,
        LlmGenerateRequest, LlmResolvedModel, LlmSurface, ManualCompactionErrorCode,
        OPENINTERPRETER, OneShotSubagentDescriptor, RuntimeBinding, SUBAGENT_TOOL_NAME,
        SandboxError, SandboxMode, SandboxModeSource, SessionApprovalAsked, SessionApprovalDecided,
        SessionApprovalPolicy, SessionCallConfig, SessionCancelCause, SessionCheckpoint,
        SessionCompactionEnd, SessionCompactionStart, SessionCompactionSummary,
        SessionContentBlock, SessionError, SessionEvent, SessionEventKind, SessionFinishReason,
        SessionHandle, SessionHeader, SessionId, SessionLlmFailure, SessionLlmRetry,
        SessionLlmRetryMode, SessionLlmRetryStarted, SessionMessage, SessionMessageRole,
        SessionMessageSource, SessionSandboxMode, SessionStore, SessionStreamBlockType,
        SessionStreamChunk, SessionSurfaceIntent, SessionSurfaceOp, SessionToolSchema,
        SurfaceOwner, ToolCall, ToolDefinition, TurnEndReason, enforce_invariants, events,
        host_is_cordis_loop, invariant_missing, is_compact_checkpoint_source, keys,
        register_tool_definition, session_events, set_sandbox_mode,
    };
    #[cfg(target_os = "macos")]
    use hartevo_cordis::{JobControl, JobOutcome, JobStatus, JobTerminalStatus, JobsSurface};
    use hartevo_domain_kernel::{
        ActorId, Approval, ApprovalDecision, ApprovalId, ConsentPurpose, ConsentRecord,
        ConsentRecordId, ConsentState, ConsentStatus, ContactChannel, LegalBasis, PersonId,
        ProjectId, TenantId,
    };
    use hartevo_runtime_adapter::OPENINTERPRETER_RELEASE;
    use hartevo_storage::{
        PersistedAgentInboxOutcome, PersistedAgentInboxTarget, PersistedSessionEvent,
        PersistedSessionEventKind, ProjectStore,
    };
    #[cfg(target_os = "macos")]
    use zeroize::Zeroizing;

    use super::{
        DesktopAgentTurnError, DesktopAgentTurnRequest, DesktopCordisApprovalBridge,
        DesktopCordisSlot, DesktopDomainCommandAuthorization, DesktopEffectExecutionAuthorization,
        DesktopEffectReconciliationAuthorization, DesktopEffectVerificationAuthorization,
        DesktopHumanCommandDispatch, DesktopHumanCommandResult, DesktopSessionPersistenceError,
        bind_live_domain_kernel, bind_live_domain_kernel_scope, decode_checkpoint, decode_event,
        dispatch_live_domain_command, dispatch_live_effect_execution,
        dispatch_live_effect_reconciliation, dispatch_live_effect_verification,
        dispatch_live_runtime, encode_checkpoint, encode_event, is_desktop_human_command,
        manual_compaction_failure_result, mount_cordis_host, openinterpreter_runtime_plugin,
        runtime_open_turn,
    };
    use crate::runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

    fn projection(status: DesktopRuntimeAvailabilityStatus) -> DesktopRuntimeProjection {
        let program_sha256 = matches!(
            status,
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment
                | DesktopRuntimeAvailabilityStatus::ReadyDistribution
        )
        .then(|| "a".repeat(64));
        DesktopRuntimeProjection {
            status,
            target: Some("aarch64-apple-darwin".into()),
            release: OPENINTERPRETER_RELEASE.into(),
            program_sha256,
            provider: None,
            model: None,
            native_credential_source: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        }
    }

    #[test]
    fn idle_job_completion_budget_is_three_and_exact_lifecycle_scoped() {
        let mut coordinator =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let agent = AgentRef::new("budget-agent");
        let same_id_replacement = AgentRef::new(agent.id.clone());

        coordinator.reset_idle_job_completion_wake_budget(&agent);
        assert!(!coordinator.consume_idle_job_completion_wake_budget(&same_id_replacement));
        for _ in 0..3 {
            assert!(coordinator.consume_idle_job_completion_wake_budget(&agent));
        }
        assert!(!coordinator.consume_idle_job_completion_wake_budget(&agent));

        coordinator.reset_idle_job_completion_wake_budget(&agent);
        assert!(coordinator.consume_idle_job_completion_wake_budget(&agent));
    }

    #[derive(Default)]
    struct DesktopTurnTestProbe {
        prepare_calls: Arc<AtomicUsize>,
        stream_calls: Arc<AtomicUsize>,
        observed_prepare_flushes: Arc<AtomicUsize>,
        observed_flushes: Arc<AtomicUsize>,
        seen: Arc<Mutex<Vec<LlmGenerateRequest>>>,
    }

    #[derive(Clone)]
    struct DesktopTurnTestAdapter {
        probe: Arc<DesktopTurnTestProbe>,
        flushes: Arc<AtomicUsize>,
    }

    impl LlmAdapter for DesktopTurnTestAdapter {
        fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
            self.probe.prepare_calls.fetch_add(1, Ordering::SeqCst);
            self.probe
                .observed_prepare_flushes
                .store(self.flushes.load(Ordering::SeqCst), Ordering::SeqCst);
            Ok(LlmResolvedModel::new(provider, model))
        }

        fn stream(
            &self,
            request: LlmGenerateRequest,
        ) -> Result<LlmAdapterStream, SessionLlmFailure> {
            self.probe.stream_calls.fetch_add(1, Ordering::SeqCst);
            self.probe
                .observed_flushes
                .store(self.flushes.load(Ordering::SeqCst), Ordering::SeqCst);
            self.probe.seen.lock().unwrap().push(request);
            Ok(Box::pin(stream::iter([
                Ok(SessionStreamChunk::BlockStart {
                    index: 0,
                    block_type: SessionStreamBlockType::Text,
                }),
                Ok(SessionStreamChunk::TextDelta {
                    index: 0,
                    text: "desktop response".into(),
                }),
                Ok(SessionStreamChunk::BlockEnd {
                    index: 0,
                    block: SessionContentBlock::Text {
                        text: "desktop response".into(),
                    },
                }),
                Ok(SessionStreamChunk::Finish {
                    reason: SessionFinishReason::Stop,
                    replay_state: None,
                }),
            ])))
        }
    }

    fn desktop_turn_adapter(
        flushes: Arc<AtomicUsize>,
    ) -> (DesktopTurnTestAdapter, Arc<DesktopTurnTestProbe>) {
        let probe = Arc::new(DesktopTurnTestProbe::default());
        (
            DesktopTurnTestAdapter {
                probe: Arc::clone(&probe),
                flushes,
            },
            probe,
        )
    }

    #[derive(Clone)]
    struct DesktopSequencedTurnAdapter {
        turns: Arc<Mutex<VecDeque<Vec<SessionStreamChunk>>>>,
    }

    impl LlmAdapter for DesktopSequencedTurnAdapter {
        fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
            Ok(LlmResolvedModel::new(provider, model))
        }

        fn stream(
            &self,
            _request: LlmGenerateRequest,
        ) -> Result<LlmAdapterStream, SessionLlmFailure> {
            let chunks = self
                .turns
                .lock()
                .unwrap()
                .pop_front()
                .expect("one scripted Desktop response per Cordis step");
            Ok(Box::pin(stream::iter(chunks.into_iter().map(Ok))))
        }
    }

    #[cfg(target_os = "macos")]
    #[derive(Clone)]
    struct DesktopObservedDeepSeekAdapter {
        adapter: Arc<DeepSeekAdapter>,
        seen: Arc<Mutex<Vec<LlmGenerateRequest>>>,
    }

    #[cfg(target_os = "macos")]
    impl LlmAdapter for DesktopObservedDeepSeekAdapter {
        fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
            self.adapter.prepare_model(provider, model)
        }

        fn stream(
            &self,
            request: LlmGenerateRequest,
        ) -> Result<LlmAdapterStream, SessionLlmFailure> {
            self.seen.lock().unwrap().push(request.clone());
            self.adapter.stream(request)
        }
    }

    #[cfg(target_os = "macos")]
    #[derive(Clone)]
    struct DesktopDeepSeekFixtureTransport {
        responses: Arc<Mutex<VecDeque<DeepSeekWireResponse>>>,
        seen: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    #[cfg(target_os = "macos")]
    impl DeepSeekTransport for DesktopDeepSeekFixtureTransport {
        fn execute(
            &self,
            connection: &DeepSeekConnection,
            api_key: &str,
            request: &serde_json::Value,
            cancellation: &LifecycleCancellation,
        ) -> Result<DeepSeekWireResponse, SessionLlmFailure> {
            assert!(!cancellation.is_cancelled());
            assert_eq!(connection.base_url().as_str(), "https://api.deepseek.com/");
            assert_eq!(api_key, "desktop-fixture-secret");
            self.seen.lock().unwrap().push(request.clone());
            Ok(self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("one DeepSeek fixture response per Cordis parent/child step"))
        }
    }

    #[cfg(target_os = "macos")]
    #[derive(Clone)]
    struct DesktopCompletionNoticeAdapter {
        turns: Arc<Mutex<VecDeque<Vec<SessionStreamChunk>>>>,
        seen: Arc<Mutex<Vec<LlmGenerateRequest>>>,
    }

    #[cfg(target_os = "macos")]
    impl LlmAdapter for DesktopCompletionNoticeAdapter {
        fn prepare_model(&self, provider: &str, model: &str) -> Result<LlmResolvedModel, LlmError> {
            Ok(LlmResolvedModel::new(provider, model))
        }

        fn stream(
            &self,
            request: LlmGenerateRequest,
        ) -> Result<LlmAdapterStream, SessionLlmFailure> {
            let request_index = {
                let mut seen = self.seen.lock().unwrap();
                let index = seen.len();
                seen.push(request);
                index
            };
            if request_index == 1 {
                std::thread::sleep(StdDuration::from_millis(200));
            }
            let chunks = self
                .turns
                .lock()
                .unwrap()
                .pop_front()
                .expect("one scripted Desktop completion-notice response per Cordis step");
            Ok(Box::pin(stream::iter(chunks.into_iter().map(Ok))))
        }
    }

    #[cfg(target_os = "macos")]
    fn desktop_tool_text_results(events: &[SessionEvent]) -> HashMap<String, String> {
        events
            .iter()
            .filter_map(|event| {
                let SessionEventKind::ToolResult { message, error, .. } = &event.kind else {
                    return None;
                };
                assert!(error.is_none());
                let SessionMessageSource::Tool { call_id } = &message.source else {
                    return None;
                };
                let [
                    SessionContentBlock::ToolResult {
                        content,
                        is_error: false,
                        ..
                    },
                ] = message.content.as_slice()
                else {
                    return None;
                };
                let [SessionContentBlock::Text { text }] = content.as_slice() else {
                    return None;
                };
                Some((call_id.clone(), text.clone()))
            })
            .collect()
    }

    fn desktop_tool_schema(name: &str) -> SessionToolSchema {
        SessionToolSchema {
            name: name.into(),
            description: format!("{name} tool"),
            parameters: serde_json::Map::from_iter([(
                "type".into(),
                serde_json::Value::String("object".into()),
            )]),
        }
    }

    fn desktop_tool_turn_adapter() -> DesktopSequencedTurnAdapter {
        let first = vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::ToolCall,
            },
            SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::ToolCall {
                    id: "desktop-call-1".into(),
                    name: "desktop-ask-tool".into(),
                    arguments: r#"{"secret":"must-not-reach-window"}"#.into(),
                },
            },
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::ToolCalls,
                replay_state: None,
            },
        ];
        let second = vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
            SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::Text {
                    text: "approved tool completed".into(),
                },
            },
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::Stop,
                replay_state: None,
            },
        ];
        DesktopSequencedTurnAdapter {
            turns: Arc::new(Mutex::new(VecDeque::from([first, second]))),
        }
    }

    #[cfg(target_os = "macos")]
    fn desktop_bash_turn_adapter() -> DesktopSequencedTurnAdapter {
        let first = vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::ToolCall,
            },
            SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::ToolCall {
                    id: "desktop-bash-call-1".into(),
                    name: "bash".into(),
                    arguments: r#"{"command":"pwd; printf 'n96-env=%s\\n' \"$DSH_SHELL|$DSH_SESSION_ID\"; printf n90-cordis; printf n90-stderr >&2; exit 7","description":"Exercise the foreground result and managed Session environment contracts"}"#.into(),
                },
            },
            SessionStreamChunk::BlockStart {
                index: 1,
                block_type: SessionStreamBlockType::ToolCall,
            },
            SessionStreamChunk::BlockEnd {
                index: 1,
                block: SessionContentBlock::ToolCall {
                    id: "desktop-bash-workdir-call".into(),
                    name: "bash".into(),
                    arguments: r#"{"command":"pwd","description":"Show the explicit working directory","workdir":"nested"}"#.into(),
                },
            },
            SessionStreamChunk::BlockStart {
                index: 2,
                block_type: SessionStreamBlockType::ToolCall,
            },
            SessionStreamChunk::BlockEnd {
                index: 2,
                block: SessionContentBlock::ToolCall {
                    id: "desktop-bash-timeout-call".into(),
                    name: "bash".into(),
                    arguments: r#"{"command":"sleep 30","description":"Exercise the foreground timeout contract","timeoutMs":50}"#.into(),
                },
            },
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::ToolCalls,
                replay_state: None,
            },
        ];
        let second = vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
            SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::Text {
                    text: "sandboxed bash completed".into(),
                },
            },
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::Stop,
                replay_state: None,
            },
        ];
        DesktopSequencedTurnAdapter {
            turns: Arc::new(Mutex::new(VecDeque::from([first, second]))),
        }
    }

    #[cfg(target_os = "macos")]
    fn desktop_single_tool_turn(id: &str, name: &str, arguments: &str) -> Vec<SessionStreamChunk> {
        vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::ToolCall,
            },
            SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::ToolCall {
                    id: id.into(),
                    name: name.into(),
                    arguments: arguments.into(),
                },
            },
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::ToolCalls,
                replay_state: None,
            },
        ]
    }

    #[cfg(target_os = "macos")]
    fn desktop_deepseek_response(
        request_id: &str,
        payload: &serde_json::Value,
    ) -> DeepSeekWireResponse {
        DeepSeekWireResponse::new(
            vec![payload.to_string(), "[DONE]".into()],
            Some(request_id.into()),
        )
    }

    #[cfg(target_os = "macos")]
    #[allow(
        clippy::type_complexity,
        reason = "the tuple exposes the adapter and three independent observations to one focused Desktop journey"
    )]
    fn desktop_foreground_subagent_turn_adapter() -> (
        DesktopObservedDeepSeekAdapter,
        Arc<Mutex<Vec<LlmGenerateRequest>>>,
        Arc<Mutex<Vec<serde_json::Value>>>,
        Arc<AtomicUsize>,
    ) {
        let turns = [
            desktop_deepseek_response(
                "desktop-deepseek-parent-1",
                &serde_json::json!({
                    "choices": [{
                        "delta": {
                            "reasoning_content": "delegate the bounded inspection",
                            "tool_calls": [{
                                "index": 0,
                                "id": "desktop-subagent-call-1",
                                "function": {
                                    "name": SUBAGENT_TOOL_NAME,
                                    "arguments": r#"{"prompt":"inspect the exact Desktop workspace boundary"}"#,
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                }),
            ),
            desktop_deepseek_response(
                "desktop-deepseek-child-1",
                &serde_json::json!({
                    "choices": [{
                        "delta": {
                            "tool_calls": [{
                                "index": 0,
                                "id": "desktop-subagent-bash-call-1",
                                "function": {
                                    "name": "bash",
                                    "arguments": r#"{"command":"pwd; printf n113-child","description":"Verify the delegated Desktop workspace binding"}"#,
                                },
                            }],
                        },
                        "finish_reason": "tool_calls",
                    }],
                }),
            ),
            desktop_deepseek_response(
                "desktop-deepseek-child-2",
                &serde_json::json!({
                    "choices": [{
                        "delta": {"content": "child inspected desktop"},
                        "finish_reason": "stop",
                    }],
                }),
            ),
            desktop_deepseek_response(
                "desktop-deepseek-parent-2",
                &serde_json::json!({
                    "choices": [{
                        "delta": {"content": "parent received child"},
                        "finish_reason": "stop",
                    }],
                }),
            ),
        ];
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_wire = Arc::new(Mutex::new(Vec::new()));
        let credential_resolutions = Arc::new(AtomicUsize::new(0));
        let transport = DesktopDeepSeekFixtureTransport {
            responses: Arc::new(Mutex::new(VecDeque::from(turns))),
            seen: Arc::clone(&seen_wire),
        };
        let credential_counter = Arc::clone(&credential_resolutions);
        let adapter = DeepSeekAdapter::new(
            DeepSeekConnection::new(
                "https://api.deepseek.com",
                "DEEPSEEK_API_KEY",
                128_000,
                8_192,
                StdDuration::from_secs(5),
            )
            .unwrap(),
            move |name: &str| {
                assert_eq!(name, "DEEPSEEK_API_KEY");
                credential_counter.fetch_add(1, Ordering::SeqCst);
                Ok(Zeroizing::new("desktop-fixture-secret".into()))
            },
            transport,
        );
        (
            DesktopObservedDeepSeekAdapter {
                adapter: Arc::new(adapter),
                seen: Arc::clone(&seen),
            },
            seen,
            seen_wire,
            credential_resolutions,
        )
    }

    #[cfg(target_os = "macos")]
    fn desktop_background_bash_turn_adapter() -> DesktopSequencedTurnAdapter {
        let turns = [
            desktop_single_tool_turn(
                "desktop-background-start-short",
                "bash",
                r#"{"command":"printf n102-first; sleep 1; printf n102-second","description":"Start the incremental background output proof","run_in_background":true}"#,
            ),
            desktop_single_tool_turn(
                "desktop-background-read-first",
                "job_output",
                r#"{"job_id":"bash-1","wait":true,"timeout_ms":500}"#,
            ),
            desktop_single_tool_turn(
                "desktop-background-read-empty",
                "job_output",
                r#"{"job_id":"bash-1"}"#,
            ),
            desktop_single_tool_turn(
                "desktop-background-read-terminal",
                "job_output",
                r#"{"job_id":"bash-1","wait":true,"timeout_ms":5000}"#,
            ),
            desktop_single_tool_turn(
                "desktop-background-start-long",
                "bash",
                r#"{"command":"sleep 30 & child=$!; printf '%s\\n' \"$child\"; wait \"$child\"","description":"Start the cancellable background process group","run_in_background":true}"#,
            ),
            desktop_single_tool_turn(
                "desktop-background-probe-long",
                "job_output",
                r#"{"job_id":"bash-2","wait":true,"timeout_ms":150}"#,
            ),
            desktop_single_tool_turn("desktop-background-list", "job_list", r"{}"),
            desktop_single_tool_turn(
                "desktop-background-kill-long",
                "job_kill",
                r#"{"job_id":"bash-2","reason":"production lifecycle proof complete"}"#,
            ),
            desktop_single_tool_turn(
                "desktop-background-read-long",
                "job_output",
                r#"{"job_id":"bash-2","wait":true,"timeout_ms":5000}"#,
            ),
            vec![
                SessionStreamChunk::BlockStart {
                    index: 0,
                    block_type: SessionStreamBlockType::Text,
                },
                SessionStreamChunk::BlockEnd {
                    index: 0,
                    block: SessionContentBlock::Text {
                        text: "background jobs verified".into(),
                    },
                },
                SessionStreamChunk::Finish {
                    reason: SessionFinishReason::Stop,
                    replay_state: None,
                },
            ],
        ];
        DesktopSequencedTurnAdapter {
            turns: Arc::new(Mutex::new(VecDeque::from(turns))),
        }
    }

    #[cfg(target_os = "macos")]
    fn desktop_completion_notice_turn_adapter() -> (
        DesktopCompletionNoticeAdapter,
        Arc<Mutex<Vec<LlmGenerateRequest>>>,
    ) {
        let turns = [
            desktop_single_tool_turn(
                "desktop-background-notice-start",
                "bash",
                r#"{"command":"printf n102-notice-ready","description":"Finish while the owning Agent remains active","run_in_background":true}"#,
            ),
            vec![
                SessionStreamChunk::BlockStart {
                    index: 0,
                    block_type: SessionStreamBlockType::Text,
                },
                SessionStreamChunk::BlockEnd {
                    index: 0,
                    block: SessionContentBlock::Text {
                        text: "background job still settling".into(),
                    },
                },
                SessionStreamChunk::Finish {
                    reason: SessionFinishReason::Stop,
                    replay_state: None,
                },
            ],
            vec![
                SessionStreamChunk::BlockStart {
                    index: 0,
                    block_type: SessionStreamBlockType::Text,
                },
                SessionStreamChunk::BlockEnd {
                    index: 0,
                    block: SessionContentBlock::Text {
                        text: "background completion notice observed".into(),
                    },
                },
                SessionStreamChunk::Finish {
                    reason: SessionFinishReason::Stop,
                    replay_state: None,
                },
            ],
        ];
        let seen = Arc::new(Mutex::new(Vec::new()));
        (
            DesktopCompletionNoticeAdapter {
                turns: Arc::new(Mutex::new(VecDeque::from(turns))),
                seen: Arc::clone(&seen),
            },
            seen,
        )
    }

    #[cfg(target_os = "macos")]
    fn desktop_bash_escalation_turn_adapter(
        call_id: &str,
        command: &str,
        workdir: Option<&str>,
        justification: &str,
    ) -> DesktopSequencedTurnAdapter {
        let mut arguments = serde_json::json!({
            "command": command,
            "description": "Exercise one exact N91 sandbox escalation",
            "sandbox_permissions": "workspace-write",
            "justification": justification,
        });
        if let Some(workdir) = workdir {
            arguments["workdir"] = serde_json::json!(workdir);
        }
        let first = vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::ToolCall,
            },
            SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::ToolCall {
                    id: call_id.into(),
                    name: "bash".into(),
                    arguments: arguments.to_string(),
                },
            },
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::ToolCalls,
                replay_state: None,
            },
        ];
        let second = vec![
            SessionStreamChunk::BlockStart {
                index: 0,
                block_type: SessionStreamBlockType::Text,
            },
            SessionStreamChunk::BlockEnd {
                index: 0,
                block: SessionContentBlock::Text {
                    text: "sandbox escalation settled".into(),
                },
            },
            SessionStreamChunk::Finish {
                reason: SessionFinishReason::Stop,
                replay_state: None,
            },
        ];
        DesktopSequencedTurnAdapter {
            turns: Arc::new(Mutex::new(VecDeque::from([first, second]))),
        }
    }

    fn desktop_turn_request() -> DesktopAgentTurnRequest {
        desktop_turn_request_in(&std::env::current_dir().unwrap())
    }

    fn desktop_turn_request_in(workspace_root: &std::path::Path) -> DesktopAgentTurnRequest {
        DesktopAgentTurnRequest::new(
            "desktop-agent-session",
            "desktop-agent-input-1",
            "private desktop prompt",
            workspace_root,
            SessionCallConfig {
                provider: "desktop-runtime".into(),
                model: "desktop-model".into(),
                reasoning_effort: None,
                temperature: None,
                max_tokens: None,
                stop: None,
            },
        )
        .unwrap()
    }

    #[cfg(target_os = "macos")]
    fn desktop_deepseek_turn_request_in<A: LlmAdapter>(
        workspace_root: &std::path::Path,
        adapter: &A,
    ) -> DesktopAgentTurnRequest {
        let mut request = DesktopAgentTurnRequest::new(
            "desktop-agent-session",
            "desktop-agent-input-1",
            "private desktop prompt",
            workspace_root,
            SessionCallConfig {
                provider: DEEPSEEK_PROVIDER_ID.into(),
                model: "deepseek-chat".into(),
                reasoning_effort: Some("high".into()),
                temperature: None,
                max_tokens: None,
                stop: None,
            },
        )
        .unwrap();
        request.resolved_model = adapter
            .prepare_model(DEEPSEEK_PROVIDER_ID, "deepseek-chat")
            .unwrap();
        request
    }

    fn approve_agent_turn(host: &mut super::DesktopCordisCoordinator) {
        host.bind_domain_kernel(
            KernelConsentState::Confirmed,
            None,
            Some(KernelApproval {
                decision: KernelApprovalDecision::Approved,
                valid_until: now() + Duration::minutes(5),
            }),
            now(),
        )
        .unwrap();
    }

    fn seed_desktop_compaction(
        host: &mut super::DesktopCordisCoordinator,
        id: &str,
    ) -> SessionHandle {
        let session = host
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .create(SessionId::new(id).unwrap())
            .unwrap();
        let turn = session.start_turn().unwrap();
        session
            .append_request_header(
                hartevo_cordis::SessionEpochHeader {
                    config: SessionCallConfig {
                        provider: "desktop-runtime".into(),
                        model: "desktop-model".into(),
                        reasoning_effort: None,
                        temperature: None,
                        max_tokens: None,
                        stop: None,
                    },
                    adapter_defaults: None,
                    system: Some("Keep durable facts.".into()),
                    tools: None,
                },
                hartevo_cordis::SessionRequestHeaderReason::Initial,
                false,
            )
            .unwrap();
        let step = session.start_step(turn).unwrap();
        session
            .append_user_message(SessionMessage {
                id: "desktop-compact-old".into(),
                role: SessionMessageRole::User,
                content: vec![SessionContentBlock::Text {
                    text: "older desktop history ".repeat(400),
                }],
                source: SessionMessageSource::User,
            })
            .unwrap();
        session
            .append_assistant_message(
                turn,
                step,
                SessionMessage {
                    id: "desktop-compact-recent".into(),
                    role: SessionMessageRole::Assistant,
                    content: vec![SessionContentBlock::Text {
                        text: "recent desktop answer".into(),
                    }],
                    source: SessionMessageSource::Model {
                        provider: "desktop-runtime".into(),
                        model: "desktop-model".into(),
                    },
                },
            )
            .unwrap();
        session.finish_step(turn, step).unwrap();
        session.finish_turn(turn, TurnEndReason::Completed).unwrap();
        session
    }

    #[tokio::test]
    async fn desktop_complete_agent_turn_flushes_before_adapter_and_restores() {
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        approve_agent_turn(&mut live);
        assert_eq!(
            live.bind_session_persistence(ProjectStore::in_memory().unwrap())
                .unwrap(),
            0
        );
        let flushes = Arc::new(AtomicUsize::new(0));
        let observed_flushes = Arc::clone(&flushes);
        live.context_mut()
            .on_parallel(session_events::SESSION_FLUSH, move |_| {
                let observed_flushes = Arc::clone(&observed_flushes);
                async move {
                    observed_flushes.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), std::convert::Infallible>(())
                }
            })
            .unwrap();
        let (adapter, probe) = desktop_turn_adapter(Arc::clone(&flushes));
        let request = desktop_turn_request();
        let request_debug = format!("{request:?}");
        assert!(request_debug.contains("[REDACTED]"));
        assert!(!request_debug.contains("private desktop prompt"));

        let outcome = live
            .run_agent_turn(request, adapter, &LifecycleCancellation::default())
            .await
            .unwrap();

        assert_eq!(outcome.steps(), 1);
        assert_eq!(outcome.reason(), TurnEndReason::Completed);
        assert_eq!(probe.prepare_calls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.stream_calls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.observed_prepare_flushes.load(Ordering::SeqCst), 2);
        assert_eq!(probe.observed_flushes.load(Ordering::SeqCst), 2);
        assert_eq!(flushes.load(Ordering::SeqCst), 3);
        assert_eq!(probe.seen.lock().unwrap().len(), 1);
        assert!(
            live.context()
                .llm::<LlmSurface>()
                .unwrap()
                .providers()
                .unwrap()
                .is_empty()
        );

        let session_id = SessionId::new("desktop-agent-session").unwrap();
        let session = live
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .unwrap();
        let messages = session.derive_messages().unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].id, "desktop-agent-input-1");
        assert_eq!(
            messages[1].content,
            [SessionContentBlock::Text {
                text: "desktop response".into()
            }]
        );
        assert!(runtime_open_turn(&session.events().unwrap()).is_none());

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
            .get(&session_id)
            .unwrap()
            .unwrap();
        assert_eq!(restored.events().unwrap(), session.events().unwrap());
        assert_eq!(restored.derive_messages().unwrap(), messages);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one focused journey proves DeepSeek wire translation plus the Desktop parent/child/parent sandbox, disposal, and cold-restore closure"
    )]
    async fn desktop_deepseek_adapter_runs_child_bash_and_cold_restores_both_sessions() {
        let scratch = tempfile::Builder::new()
            .prefix("n113-deepseek-subagent-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let workspace_root = scratch.path().canonicalize().unwrap();
        let parent_id = SessionId::new("desktop-agent-session").unwrap();
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        assert_eq!(
            live.bind_session_persistence(ProjectStore::in_memory().unwrap())
                .unwrap(),
            0
        );
        let sessions = live.context().sessions::<SessionStore>().unwrap();
        let parent = sessions.create(parent_id.clone()).unwrap();
        set_sandbox_mode(live.context(), &parent, SandboxMode::ReadOnly, None)
            .await
            .unwrap();
        let (adapter, seen, seen_wire, credential_resolutions) =
            desktop_foreground_subagent_turn_adapter();
        let request = desktop_deepseek_turn_request_in(&workspace_root, &adapter);
        let slot = Arc::new(DesktopCordisSlot::new(live));
        let execution_slot = Arc::clone(&slot);
        let scope = AuthorityScope::new("tenant-a", "project-a", parent_id.as_str(), 4)
            .unwrap()
            .with_runtime(RuntimeBinding::new(2, None, None, "a".repeat(64)).unwrap());

        let outcome = dispatch_live_runtime(
            &slot,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                let mut coordinator = execution_slot.lock().unwrap();
                futures_executor::block_on(coordinator.run_authorized_runtime_agent_turn(
                    request,
                    adapter,
                    &LifecycleCancellation::default(),
                    permit,
                    None,
                ))
                .map_err(|error| error.to_string())
            },
        )
        .unwrap();

        assert_eq!(outcome.steps(), 2);
        assert_eq!(outcome.reason(), TurnEndReason::Completed);
        let observed = seen.lock().unwrap();
        assert_eq!(observed.len(), 4);
        assert_eq!(observed[0].session_id(), Some(&parent_id));
        let child_id = observed[1]
            .session_id()
            .cloned()
            .expect("child request must carry its Session identity");
        assert_eq!(observed[2].session_id(), Some(&child_id));
        assert_eq!(observed[3].session_id(), Some(&parent_id));
        assert!(
            observed[0]
                .tools()
                .unwrap_or_default()
                .iter()
                .any(|schema| schema.name == SUBAGENT_TOOL_NAME)
        );
        assert_eq!(observed[1].messages().len(), 1);
        assert_eq!(
            observed[1].messages()[0].content,
            [SessionContentBlock::Text {
                text: "inspect the exact Desktop workspace boundary".into(),
            }]
        );
        assert_eq!(observed[1].config(), observed[0].config());
        assert!(
            observed[2].messages().iter().any(|message| {
                matches!(
                    message.content.as_slice(),
                    [SessionContentBlock::ToolResult {
                        tool_call_id,
                        content,
                        is_error: false,
                    }] if tool_call_id == "desktop-subagent-bash-call-1"
                        && content.iter().any(|block| matches!(
                            block,
                            SessionContentBlock::Text { text }
                                if text.contains("n113-child")
                                    && text.contains("[sandbox: read-only, full enforcement]")
                        ))
                )
            }),
            "the child must observe its real sandboxed Desktop bash result"
        );
        assert!(observed[3].messages().iter().any(|message| {
            matches!(
                message.content.as_slice(),
                [SessionContentBlock::ToolResult {
                    tool_call_id,
                    content,
                    is_error: false,
                }] if tool_call_id == "desktop-subagent-call-1"
                    && content == &[SessionContentBlock::Text {
                        text: "child inspected desktop".into(),
                    }]
            )
        }));
        drop(observed);

        assert_eq!(credential_resolutions.load(Ordering::SeqCst), 4);
        let wire = seen_wire.lock().unwrap();
        assert_eq!(wire.len(), 4);
        assert!(
            wire.iter()
                .all(|request| request["model"] == "deepseek-chat")
        );
        assert_eq!(wire[0]["thinking"], serde_json::json!({"type": "enabled"}));
        assert_eq!(wire[0]["reasoning_effort"], "high");
        assert_eq!(wire[0]["max_tokens"], 8_192);
        assert!(
            wire[0]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .any(|tool| tool["function"]["name"] == SUBAGENT_TOOL_NAME)
        );
        assert!(
            wire[1]["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| {
                    message["role"] == "user"
                        && message["content"] == "inspect the exact Desktop workspace boundary"
                })
        );
        assert!(
            wire[2]["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| {
                    message["role"] == "tool"
                        && message["tool_call_id"] == "desktop-subagent-bash-call-1"
                        && message["content"].as_str().is_some_and(|text| {
                            text.contains("n113-child")
                                && text.contains("[sandbox: read-only, full enforcement]")
                        })
                })
        );
        assert!(
            wire[3]["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|message| {
                    message["role"] == "tool"
                        && message["tool_call_id"] == "desktop-subagent-call-1"
                        && message["content"] == "child inspected desktop"
                })
        );
        drop(wire);

        let (parent_events, parent_messages, child_events, child_messages, store) = {
            let live = slot.lock().unwrap();
            let sessions = live.context().sessions::<SessionStore>().unwrap();
            assert_eq!(sessions.len().unwrap(), 2);
            let parent = sessions.get(&parent_id).unwrap().unwrap();
            let child = sessions.get(&child_id).unwrap().unwrap();
            let child_header = child.header().unwrap();
            assert_eq!(child_header.parent_session, Some(parent_id.clone()));
            assert_eq!(child_header.delegation_depth, 1);
            assert_eq!(parent.sandbox_mode().unwrap(), Some(SandboxMode::ReadOnly));
            assert_eq!(parent.approval_policy().unwrap(), ApprovalPolicy::Ask);
            assert_eq!(child.sandbox_mode().unwrap(), Some(SandboxMode::ReadOnly));
            assert_eq!(child.approval_policy().unwrap(), ApprovalPolicy::Never);
            let child_events = child.events().unwrap();
            let delegated_sandbox = child_events
                .iter()
                .position(|event| {
                    matches!(
                        event.kind,
                        SessionEventKind::SandboxMode { sandbox }
                            if sandbox.mode() == SandboxMode::ReadOnly
                                && sandbox.source() == Some(SandboxModeSource::Delegation)
                    )
                })
                .unwrap();
            let delegated_approval = child_events
                .iter()
                .position(|event| {
                    matches!(
                        event.kind,
                        SessionEventKind::ApprovalPolicy { approval }
                            if approval.policy() == ApprovalPolicy::Never
                                && approval.source() == Some(ApprovalPolicySource::Delegation)
                    )
                })
                .unwrap();
            let child_turn_start = child_events
                .iter()
                .position(|event| matches!(event.kind, SessionEventKind::TurnStart { .. }))
                .unwrap();
            assert!(delegated_sandbox < child_turn_start);
            assert!(delegated_approval < child_turn_start);
            assert!(runtime_open_turn(&child_events).is_none());
            let parent_events = parent.events().unwrap();
            assert!(runtime_open_turn(&parent_events).is_none());
            assert!(
                live.context()
                    .agents::<AgentsSurface>()
                    .unwrap()
                    .list()
                    .iter()
                    .all(|agent| agent.id != child_id.as_str()),
                "the foreground child Agent must be disposed"
            );
            let store = live
                .session_persistence
                .store
                .lock()
                .unwrap()
                .take()
                .unwrap();
            (
                parent_events,
                parent.derive_messages().unwrap(),
                child_events,
                child.derive_messages().unwrap(),
                store,
            )
        };

        let mut cold =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        assert_eq!(cold.bind_session_persistence(store).unwrap(), 2);
        let restored_sessions = cold.context().sessions::<SessionStore>().unwrap();
        let restored_parent = restored_sessions.get(&parent_id).unwrap().unwrap();
        let restored_child = restored_sessions.get(&child_id).unwrap().unwrap();
        assert_eq!(restored_parent.events().unwrap(), parent_events);
        assert_eq!(restored_parent.derive_messages().unwrap(), parent_messages);
        assert_eq!(restored_child.events().unwrap(), child_events);
        assert_eq!(restored_child.derive_messages().unwrap(), child_messages);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the focused production proof keeps default cwd, explicit cwd, timeout, and durable settlement together"
    )]
    async fn desktop_production_bash_tool_runs_in_cordis_sandbox_and_commits_result() {
        let scratch = tempfile::Builder::new()
            .prefix("n92-read-only-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let workspace_root = scratch.path().canonicalize().unwrap();
        let nested = scratch.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let nested = nested.canonicalize().unwrap();
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        approve_agent_turn(&mut live);
        live.bind_session_persistence(ProjectStore::in_memory().unwrap())
            .unwrap();

        let outcome = live
            .run_agent_turn(
                desktop_turn_request_in(scratch.path()),
                desktop_bash_turn_adapter(),
                &LifecycleCancellation::default(),
            )
            .await
            .unwrap();

        assert_eq!(outcome.steps(), 2);
        assert_eq!(outcome.reason(), TurnEndReason::Completed);
        let session = live
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&SessionId::new("desktop-agent-session").unwrap())
            .unwrap()
            .unwrap();
        let events = session.events().unwrap();
        let (message, error) = events
            .iter()
            .find_map(|event| match &event.kind {
                SessionEventKind::ToolResult { message, error, .. }
                    if matches!(
                        &message.source,
                        SessionMessageSource::Tool { call_id }
                            if call_id == "desktop-bash-call-1"
                    ) =>
                {
                    Some((message, error))
                }
                _ => None,
            })
            .expect("production Cordis bash result must be durable");
        assert!(error.is_none());
        let [
            SessionContentBlock::ToolResult {
                tool_call_id,
                content,
                is_error,
            },
        ] = message.content.as_slice()
        else {
            panic!("production Cordis bash result must use the canonical tool wrapper");
        };
        assert_eq!(tool_call_id, "desktop-bash-call-1");
        assert!(!is_error);
        let [SessionContentBlock::Text { text }] = content.as_slice() else {
            panic!("production Cordis bash payload must be one text block");
        };
        assert!(text.contains(&workspace_root.display().to_string()));
        assert!(text.contains("n96-env=1|desktop-agent-session"));
        assert!(text.contains("n90-cordis"));
        assert!(text.contains("[stderr]\nn90-stderr"));
        assert!(text.contains("[sandbox: read-only, full enforcement]"));
        assert!(text.contains("[exit code: 7]"));
        let workdir_message = events
            .iter()
            .find_map(|event| match &event.kind {
                SessionEventKind::ToolResult { message, error, .. }
                    if error.is_none()
                        && matches!(
                            &message.source,
                            SessionMessageSource::Tool { call_id }
                                if call_id == "desktop-bash-workdir-call"
                        ) =>
                {
                    Some(message)
                }
                _ => None,
            })
            .expect("explicit workdir result must be durable");
        let [
            SessionContentBlock::ToolResult {
                content,
                is_error: false,
                ..
            },
        ] = workdir_message.content.as_slice()
        else {
            panic!("explicit workdir must use the canonical successful tool wrapper");
        };
        let [SessionContentBlock::Text { text }] = content.as_slice() else {
            panic!("explicit workdir result must contain one text block");
        };
        assert!(text.contains(&nested.display().to_string()));
        assert!(text.contains("[sandbox: read-only, full enforcement]"));
        let timeout_message = events
            .iter()
            .find_map(|event| match &event.kind {
                SessionEventKind::ToolResult { message, error, .. }
                    if error.is_none()
                        && matches!(
                            &message.source,
                            SessionMessageSource::Tool { call_id }
                                if call_id == "desktop-bash-timeout-call"
                        ) =>
                {
                    Some(message)
                }
                _ => None,
            })
            .expect("foreground timeout result must be durable");
        let [
            SessionContentBlock::ToolResult {
                content,
                is_error: false,
                ..
            },
        ] = timeout_message.content.as_slice()
        else {
            panic!("foreground timeout must use the canonical successful tool wrapper");
        };
        let [SessionContentBlock::Text { text }] = content.as_slice() else {
            panic!("foreground timeout result must contain one text block");
        };
        assert!(text.contains("[timed out after 50ms]"));
        assert!(text.contains("[sandbox: read-only, full enforcement]"));
        assert!(runtime_open_turn(&events).is_none());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn desktop_background_bash_jobs_start_collect_list_kill_and_reap() {
        use std::process::{Command, Stdio};

        let scratch = tempfile::Builder::new()
            .prefix("n101-background-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        approve_agent_turn(&mut live);
        live.bind_session_persistence(ProjectStore::in_memory().unwrap())
            .unwrap();

        let outcome = live
            .run_agent_turn(
                desktop_turn_request_in(scratch.path()),
                desktop_background_bash_turn_adapter(),
                &LifecycleCancellation::default(),
            )
            .await
            .unwrap();

        assert_eq!(outcome.steps(), 10);
        assert_eq!(outcome.reason(), TurnEndReason::Completed);
        let session_id = SessionId::new("desktop-agent-session").unwrap();
        let session = live
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&session_id)
            .unwrap()
            .unwrap();
        let events = session.events().unwrap();
        let results = desktop_tool_text_results(&events);

        assert_eq!(
            results["desktop-background-start-short"],
            "started background job bash-1"
        );
        let first = &results["desktop-background-read-first"];
        assert!(first.contains("n102-first"));
        assert!(!first.contains("n102-second"));
        assert!(first.contains("[status: running]"));
        let empty = &results["desktop-background-read-empty"];
        assert!(empty.contains("(no new output)"));
        assert!(!empty.contains("n102-first"));
        assert!(!empty.contains("n102-second"));
        let terminal = &results["desktop-background-read-terminal"];
        assert!(!terminal.contains("n102-first"));
        assert!(terminal.contains("n102-second"));
        assert!(terminal.contains("[sandbox: read-only, full enforcement]"));
        assert!(terminal.contains("[status: completed, exit code: 0]"));
        assert_eq!(
            results["desktop-background-start-long"],
            "started background job bash-2"
        );
        let probe = &results["desktop-background-probe-long"];
        assert!(probe.contains("[status: running]"));
        let list = &results["desktop-background-list"];
        assert!(list.contains("bash-1 [bash] completed"));
        assert!(list.contains("bash-2 [bash] running"));
        assert!(
            results["desktop-background-kill-long"]
                .contains("requested cancellation for background job bash-2")
        );
        let killed = &results["desktop-background-read-long"];
        assert!(killed.contains("[killed by signal: SIGTERM]"));
        assert!(killed.contains("[status: killed, signal: SIGTERM]"));
        let child_pid = probe
            .lines()
            .find_map(|line| line.parse::<u32>().ok())
            .expect("the live incremental read must report the child pid before cancellation");
        assert!(
            !Command::new("/bin/kill")
                .args(["-0", &child_pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );

        let jobs = live.context().jobs::<JobsSurface>().unwrap();
        let snapshots = jobs.list(&session_id);
        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].status(), JobStatus::Completed);
        assert_eq!(snapshots[1].status(), JobStatus::Killed);
        assert!(runtime_open_turn(&events).is_none());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn desktop_background_completion_notifies_the_exact_active_agent_once() {
        let scratch = tempfile::Builder::new()
            .prefix("n102-completion-notice-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        approve_agent_turn(&mut live);
        live.bind_session_persistence(ProjectStore::in_memory().unwrap())
            .unwrap();
        let (adapter, seen) = desktop_completion_notice_turn_adapter();

        let outcome = live
            .run_agent_turn(
                desktop_turn_request_in(scratch.path()),
                adapter,
                &LifecycleCancellation::default(),
            )
            .await
            .unwrap();

        assert_eq!(outcome.steps(), 3);
        assert_eq!(outcome.reason(), TurnEndReason::Completed);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        let notices = seen[2]
            .messages()
            .iter()
            .filter(|message| {
                matches!(
                    &message.source,
                    SessionMessageSource::Plugin { plugin, .. } if plugin == "tool-jobs"
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(notices.len(), 1);
        assert!(matches!(
            notices[0].content.as_slice(),
            [SessionContentBlock::Text { text }]
                if text.contains("Background job bash-1 (bash) finished [status: completed, exit code: 0]")
                    && text.contains("job_output")
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the focused production proof keeps exact prompt identity, one-shot approval, execution, and durable settlement together"
    )]
    fn desktop_production_bash_escalation_asks_once_then_runs_the_exact_call() {
        let scratch = tempfile::Builder::new()
            .prefix("n91-approved-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let nested = scratch.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let marker = nested.join("allowed-marker");
        let nested = nested.canonicalize().unwrap();
        let request_workspace_root = scratch.path().to_path_buf();
        let command = "printf n91-approved > allowed-marker; cat allowed-marker; pwd";
        let justification = "create the N91 marker inside the current workspace";
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        live.bind_session_persistence(ProjectStore::in_memory().unwrap())
            .unwrap();
        let slot = Arc::new(DesktopCordisSlot::new(live));
        let bridge_changes = Arc::new(Mutex::new(Vec::new()));
        let bridge = {
            let bridge_changes = Arc::clone(&bridge_changes);
            DesktopCordisApprovalBridge::new(move |pending| {
                bridge_changes.lock().unwrap().push(pending);
            })
        };
        let expected_agent_id = Arc::new(Mutex::new(None::<String>));
        let answer_bridge = bridge.clone();
        let answer_expected_agent_id = Arc::clone(&expected_agent_id);
        let answerer = thread::spawn(move || {
            for _ in 0..200 {
                if let Some(held) = answer_bridge.pending() {
                    let expected = answer_expected_agent_id.lock().unwrap().clone().unwrap();
                    assert_eq!(held.agent_id, expected);
                    assert_eq!(held.session_id.as_str(), "desktop-agent-session");
                    assert_eq!(held.tool_name(), "bash");
                    assert_eq!(held.call_id(), Some("desktop-bash-escalation-allow"));
                    assert_eq!(
                        held.reason(),
                        Some(
                            "escalate sandbox to workspace-write: create the N91 marker inside the current workspace"
                        )
                    );
                    let id = held.id().clone();
                    answer_bridge.allow_once(&id).unwrap();
                    return held;
                }
                thread::sleep(StdDuration::from_millis(5));
            }
            panic!("Desktop never received the sandbox escalation request");
        });

        let execution_slot = Arc::clone(&slot);
        let execution_bridge = bridge.clone();
        let execution_agent_id = Arc::clone(&expected_agent_id);
        let outcome = dispatch_live_runtime(
            &slot,
            runtime_scope(),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                *execution_agent_id.lock().unwrap() = Some(permit.agent().id.clone());
                let mut coordinator = execution_slot.lock().unwrap();
                futures_executor::block_on(coordinator.run_authorized_runtime_agent_turn(
                    desktop_turn_request_in(&request_workspace_root),
                    desktop_bash_escalation_turn_adapter(
                        "desktop-bash-escalation-allow",
                        command,
                        Some("nested"),
                        justification,
                    ),
                    &LifecycleCancellation::default(),
                    permit,
                    Some(&execution_bridge),
                ))
                .map_err(|error| error.to_string())
            },
        )
        .unwrap();
        let held = answerer.join().unwrap();

        assert_eq!(outcome.steps(), 2);
        assert_eq!(outcome.reason(), TurnEndReason::Completed);
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "n91-approved");
        assert_eq!(*bridge_changes.lock().unwrap(), [true, false]);
        assert!(bridge.pending().is_none());
        let session = slot
            .lock()
            .unwrap()
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&held.session_id)
            .unwrap()
            .unwrap();
        let events = session.events().unwrap();
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                SessionEventKind::ApprovalAsked { approval: asked }
                    if asked.id() == held.id()
                        && asked.tool_name() == "bash"
                        && asked.call_id() == Some("desktop-bash-escalation-allow")
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                SessionEventKind::ApprovalDecided { approval: decided }
                    if decided.id() == held.id()
                        && decided.outcome() == ApprovalOutcome::AllowedOnce
            )
        }));
        let result_text = events
            .iter()
            .find_map(|event| match &event.kind {
                SessionEventKind::ToolResult { message, error, .. }
                    if error.is_none()
                        && matches!(
                            &message.source,
                            SessionMessageSource::Tool { call_id }
                                if call_id == "desktop-bash-escalation-allow"
                        ) =>
                {
                    message.content.iter().find_map(|content| match content {
                        SessionContentBlock::ToolResult {
                            content,
                            is_error: false,
                            ..
                        } => content.iter().find_map(|block| match block {
                            SessionContentBlock::Text { text } => Some(text.as_str()),
                            _ => None,
                        }),
                        _ => None,
                    })
                }
                _ => None,
            })
            .expect("approved escalation must commit one successful ToolResult");
        assert!(result_text.contains("n91-approved"));
        assert!(result_text.contains(&nested.display().to_string()));
        assert!(result_text.contains("[sandbox: workspace-write, full enforcement]"));
        assert!(runtime_open_turn(&events).is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the focused rejection proof keeps exact prompt identity, durable rejection, and no-spawn evidence together"
    )]
    fn desktop_rejected_bash_escalation_never_spawns_the_command() {
        let scratch = tempfile::Builder::new()
            .prefix("n91-rejected-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let marker = scratch.path().join("must-not-exist");
        let request_workspace_root = scratch.path().to_path_buf();
        let command = "printf forbidden > must-not-exist";
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        live.bind_session_persistence(ProjectStore::in_memory().unwrap())
            .unwrap();
        let slot = Arc::new(DesktopCordisSlot::new(live));
        let bridge_changes = Arc::new(Mutex::new(Vec::new()));
        let bridge = {
            let bridge_changes = Arc::clone(&bridge_changes);
            DesktopCordisApprovalBridge::new(move |pending| {
                bridge_changes.lock().unwrap().push(pending);
            })
        };
        let expected_agent_id = Arc::new(Mutex::new(None::<String>));
        let answer_bridge = bridge.clone();
        let answer_expected_agent_id = Arc::clone(&expected_agent_id);
        let answerer = thread::spawn(move || {
            for _ in 0..200 {
                if let Some(held) = answer_bridge.pending() {
                    let expected = answer_expected_agent_id.lock().unwrap().clone().unwrap();
                    assert_eq!(held.agent_id, expected);
                    assert_eq!(held.session_id.as_str(), "desktop-agent-session");
                    assert_eq!(held.tool_name(), "bash");
                    assert_eq!(held.call_id(), Some("desktop-bash-escalation-reject"));
                    assert_eq!(
                        held.reason(),
                        Some(
                            "escalate sandbox to workspace-write: write a marker that rejection must prevent"
                        )
                    );
                    let id = held.id().clone();
                    answer_bridge.reject(&id).unwrap();
                    return held;
                }
                thread::sleep(StdDuration::from_millis(5));
            }
            panic!("Desktop never received the sandbox escalation request");
        });

        let execution_slot = Arc::clone(&slot);
        let execution_bridge = bridge.clone();
        let execution_agent_id = Arc::clone(&expected_agent_id);
        let outcome = dispatch_live_runtime(
            &slot,
            runtime_scope(),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                *execution_agent_id.lock().unwrap() = Some(permit.agent().id.clone());
                let mut coordinator = execution_slot.lock().unwrap();
                futures_executor::block_on(coordinator.run_authorized_runtime_agent_turn(
                    desktop_turn_request_in(&request_workspace_root),
                    desktop_bash_escalation_turn_adapter(
                        "desktop-bash-escalation-reject",
                        command,
                        None,
                        "write a marker that rejection must prevent",
                    ),
                    &LifecycleCancellation::default(),
                    permit,
                    Some(&execution_bridge),
                ))
                .map_err(|error| error.to_string())
            },
        )
        .unwrap();
        let held = answerer.join().unwrap();

        assert_eq!(outcome.steps(), 2);
        assert!(!marker.exists());
        assert_eq!(*bridge_changes.lock().unwrap(), [true, false]);
        assert!(bridge.pending().is_none());
        let session = slot
            .lock()
            .unwrap()
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&held.session_id)
            .unwrap()
            .unwrap();
        let events = session.events().unwrap();
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                SessionEventKind::ApprovalAsked { approval: asked }
                    if asked.id() == held.id()
                        && asked.tool_name() == "bash"
                        && asked.call_id() == Some("desktop-bash-escalation-reject")
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                SessionEventKind::ApprovalDecided { approval: decided }
                    if decided.id() == held.id()
                        && decided.outcome() == ApprovalOutcome::Rejected
            )
        }));
        let message = events
            .iter()
            .find_map(|event| match &event.kind {
                SessionEventKind::ToolResult { message, .. }
                    if matches!(
                        &message.source,
                        SessionMessageSource::Tool { call_id }
                            if call_id == "desktop-bash-escalation-reject"
                    ) =>
                {
                    Some(message)
                }
                _ => None,
            })
            .expect("rejected escalation must commit one error ToolResult");
        let result_text = message.content.iter().find_map(|content| match content {
            SessionContentBlock::ToolResult {
                content,
                is_error: true,
                ..
            } => content.iter().find_map(|block| match block {
                SessionContentBlock::Text { text } => Some(text.as_str()),
                _ => None,
            }),
            _ => None,
        });
        assert!(
            result_text.is_some_and(|text| { text.contains("the user rejected tool \"bash\"") })
        );
        assert!(runtime_open_turn(&events).is_none());
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the focused Desktop contract keeps exact Agent/Session binding, minimized prompt, dispatch, and durable decision evidence together"
    )]
    fn desktop_runtime_answers_exact_cordis_tool_ask_once_without_exposing_arguments() {
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        live.bind_session_persistence(ProjectStore::in_memory().unwrap())
            .unwrap();
        let tool_runs = Arc::new(AtomicUsize::new(0));
        {
            let tool_runs = Arc::clone(&tool_runs);
            register_tool_definition(
                live.context_mut(),
                ToolDefinition::new(desktop_tool_schema("desktop-ask-tool"), move |_| {
                    tool_runs.fetch_add(1, Ordering::SeqCst);
                    Ok(serde_json::json!({ "completed": true }))
                }),
            )
            .unwrap();
        }
        live.context_mut()
            .on_waterfall(events::TOOLS_PRE_EXECUTE, |mut call: ToolCall, _next| {
                call.decision = "ask".into();
                call.result = "approve the exact Desktop tool call".into();
                call
            })
            .unwrap();

        let slot = Arc::new(DesktopCordisSlot::new(live));
        let bridge_changes = Arc::new(Mutex::new(Vec::new()));
        let bridge = {
            let bridge_changes = Arc::clone(&bridge_changes);
            DesktopCordisApprovalBridge::new(move |pending| {
                bridge_changes.lock().unwrap().push(pending);
            })
        };
        let expected_agent_id = Arc::new(Mutex::new(None::<String>));
        let answer_bridge = bridge.clone();
        let answer_expected_agent_id = Arc::clone(&expected_agent_id);
        let answerer = thread::spawn(move || {
            for _ in 0..200 {
                if let Some(held) = answer_bridge.pending() {
                    let expected = answer_expected_agent_id.lock().unwrap().clone().unwrap();
                    assert_eq!(held.agent_id, expected);
                    assert_eq!(held.session_id.as_str(), "desktop-agent-session");
                    assert_ne!(held.agent_id, held.session_id.as_str());
                    assert_eq!(held.tool_name(), "desktop-ask-tool");
                    assert_eq!(held.call_id(), Some("desktop-call-1"));
                    assert_eq!(held.reason(), Some("approve the exact Desktop tool call"));
                    assert!(!format!("{held:?}").contains("must-not-reach-window"));
                    let id = held.id().clone();
                    answer_bridge.allow_once(&id).unwrap();
                    return held;
                }
                thread::sleep(StdDuration::from_millis(5));
            }
            panic!("Desktop never received the Cordis approval request");
        });

        let execution_slot = Arc::clone(&slot);
        let execution_bridge = bridge.clone();
        let execution_agent_id = Arc::clone(&expected_agent_id);
        let outcome = dispatch_live_runtime(
            &slot,
            runtime_scope(),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                *execution_agent_id.lock().unwrap() = Some(permit.agent().id.clone());
                let mut coordinator = execution_slot.lock().unwrap();
                futures_executor::block_on(coordinator.run_authorized_runtime_agent_turn(
                    desktop_turn_request(),
                    desktop_tool_turn_adapter(),
                    &LifecycleCancellation::default(),
                    permit,
                    Some(&execution_bridge),
                ))
                .map_err(|error| error.to_string())
            },
        )
        .unwrap();
        let held = answerer.join().unwrap();

        assert_eq!(outcome.steps(), 2);
        assert_eq!(outcome.reason(), TurnEndReason::Completed);
        assert_eq!(tool_runs.load(Ordering::SeqCst), 1);
        assert_eq!(*bridge_changes.lock().unwrap(), [true, false]);
        assert!(bridge.pending().is_none());
        let session = slot
            .lock()
            .unwrap()
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&held.session_id)
            .unwrap()
            .unwrap();
        let events = session.events().unwrap();
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                SessionEventKind::ApprovalAsked { approval: asked }
                    if asked.id() == held.id()
                        && asked.tool_name() == "desktop-ask-tool"
                        && asked.call_id() == Some("desktop-call-1")
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                &event.kind,
                SessionEventKind::ApprovalDecided { approval: decided }
                    if decided.id() == held.id()
                        && decided.outcome() == ApprovalOutcome::AllowedOnce
            )
        }));
    }

    #[test]
    fn desktop_cordis_approval_id_mismatch_closes_the_held_request() {
        let bridge_changes = Arc::new(Mutex::new(Vec::new()));
        let bridge = {
            let bridge_changes = Arc::clone(&bridge_changes);
            DesktopCordisApprovalBridge::new(move |pending| {
                bridge_changes.lock().unwrap().push(pending);
            })
        };
        let held_id = ApprovalRequestId::new("held-approval").unwrap();
        let (answer, answered) = tokio::sync::oneshot::channel();
        bridge.state.lock().unwrap().pending = Some(super::DesktopPendingCordisApproval {
            request: super::DesktopHeldCordisApproval {
                id: held_id,
                agent_id: "runtime-agent".into(),
                session_id: SessionId::new("mission-session").unwrap(),
                tool_name: "desktop-ask-tool".into(),
                call_id: Some("desktop-call-stale".into()),
                reason: None,
            },
            answer: Some(answer),
        });

        assert_eq!(
            bridge.allow_once(&ApprovalRequestId::new("stale-approval").unwrap()),
            Err(super::DesktopCordisApprovalDecisionError::Mismatch)
        );
        assert_eq!(
            futures_executor::block_on(answered).unwrap(),
            ApprovalOutcome::Unavailable
        );
        assert!(bridge.pending().is_none());
        assert_eq!(*bridge_changes.lock().unwrap(), [false]);
    }

    #[tokio::test]
    async fn desktop_manual_compaction_flushes_before_provider_and_restores() {
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        assert_eq!(
            live.bind_session_persistence(ProjectStore::in_memory().unwrap())
                .unwrap(),
            0
        );
        let flushes = Arc::new(AtomicUsize::new(0));
        let observed_flushes = Arc::clone(&flushes);
        live.context_mut()
            .on_parallel(session_events::SESSION_FLUSH, move |_| {
                let observed_flushes = Arc::clone(&observed_flushes);
                async move {
                    observed_flushes.fetch_add(1, Ordering::SeqCst);
                    Ok::<(), std::convert::Infallible>(())
                }
            })
            .unwrap();
        let session = seed_desktop_compaction(&mut live, "desktop-manual-compaction");
        let (adapter, probe) = desktop_turn_adapter(Arc::clone(&flushes));

        let result = live
            .dispatch_human_command(
                "desktop-manual-compaction",
                "desktop-command-1".into(),
                "/compact",
                adapter,
                &LifecycleCancellation::default(),
            )
            .await
            .unwrap();
        assert_eq!(probe.prepare_calls.load(Ordering::SeqCst), 2);
        assert_eq!(probe.stream_calls.load(Ordering::SeqCst), 1);
        assert_eq!(probe.observed_prepare_flushes.load(Ordering::SeqCst), 1);
        assert_eq!(probe.observed_flushes.load(Ordering::SeqCst), 1);
        assert_eq!(flushes.load(Ordering::SeqCst), 2);
        assert!(
            live.context()
                .llm::<LlmSurface>()
                .unwrap()
                .providers()
                .unwrap()
                .is_empty()
        );
        let expected_events = session.events().unwrap();
        let expected_surface = session.surface().unwrap();
        let expected_messages = session.derive_messages().unwrap();
        let (summary_seq, summary) = expected_events
            .iter()
            .find_map(|event| match &event.kind {
                SessionEventKind::CompactionSummary { compaction } => Some((event.seq, compaction)),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            result,
            DesktopHumanCommandDispatch::Handled(DesktopHumanCommandResult::Success {
                text: format!(
                    "Compacted {} history items (~{} tokens).",
                    summary.shadowed_seqs.len(),
                    summary.shadowed_token_count
                ),
                source_event_seq: Some(summary_seq),
            })
        );
        assert_eq!(
            summary.source_command_id.as_deref(),
            Some("desktop-command-1")
        );
        assert!(is_compact_checkpoint_source(&expected_messages[0].source));

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
            .get(&SessionId::new("desktop-manual-compaction").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(restored.events().unwrap(), expected_events);
        assert_eq!(restored.surface().unwrap(), expected_surface);
        assert_eq!(restored.derive_messages().unwrap(), expected_messages);
    }

    #[tokio::test]
    async fn desktop_manual_compaction_noop_mounts_no_provider_and_writes_nothing() {
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        live.context()
            .sessions::<SessionStore>()
            .unwrap()
            .create(SessionId::new("desktop-manual-empty").unwrap())
            .unwrap();
        let flushes = Arc::new(AtomicUsize::new(0));
        let (adapter, probe) = desktop_turn_adapter(flushes);

        let result = live
            .dispatch_human_command(
                "desktop-manual-empty",
                "desktop-command-empty".into(),
                "/compact\t ",
                adapter,
                &LifecycleCancellation::default(),
            )
            .await
            .unwrap();

        assert_eq!(
            result,
            DesktopHumanCommandDispatch::Handled(DesktopHumanCommandResult::Success {
                text: "No compactable history yet.".into(),
                source_event_seq: None,
            })
        );
        assert_eq!(probe.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.stream_calls.load(Ordering::SeqCst), 0);
        let session = live
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&SessionId::new("desktop-manual-empty").unwrap())
            .unwrap()
            .unwrap();
        assert!(session.events().unwrap().is_empty());
        assert!(
            live.context()
                .llm::<LlmSurface>()
                .unwrap()
                .providers()
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn desktop_compact_command_rejects_arguments_and_preserves_fallthrough() {
        for line in ["/compact", "/compact ", "/compact now"] {
            assert!(is_desktop_human_command(line));
        }
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let flushes = Arc::new(AtomicUsize::new(0));
        let (adapter, probe) = desktop_turn_adapter(Arc::clone(&flushes));

        let usage = live
            .dispatch_human_command(
                "missing-session-is-not-read",
                "desktop-command-usage".into(),
                "/compact now",
                adapter,
                &LifecycleCancellation::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            usage,
            DesktopHumanCommandDispatch::Handled(DesktopHumanCommandResult::Error {
                text: "Usage: /compact (no arguments)".into(),
            })
        );
        assert_eq!(probe.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.stream_calls.load(Ordering::SeqCst), 0);

        for line in ["ordinary message", "/compactly", "/Compact", "/compact/"] {
            assert!(!is_desktop_human_command(line));
            let (adapter, probe) = desktop_turn_adapter(Arc::clone(&flushes));
            let result = live
                .dispatch_human_command(
                    "missing-session-is-not-read",
                    "desktop-command-fallthrough".into(),
                    line,
                    adapter,
                    &LifecycleCancellation::default(),
                )
                .await
                .unwrap();
            assert_eq!(result, DesktopHumanCommandDispatch::NotCommand);
            assert_eq!(probe.prepare_calls.load(Ordering::SeqCst), 0);
            assert_eq!(probe.stream_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn desktop_compact_command_maps_every_manual_failure_code() {
        let expected = [
            (
                ManualCompactionErrorCode::Busy,
                "Compaction is unavailable because this process has an active compaction, or the agent is not idle.",
            ),
            (
                ManualCompactionErrorCode::Cancelled,
                "Compaction cancelled.",
            ),
            (
                ManualCompactionErrorCode::Changed,
                "The history selected for compaction changed before it could be replaced. The conversation is unchanged; the attempt is recorded in the session log.",
            ),
            (
                ManualCompactionErrorCode::Summary,
                "Compaction could not produce a useful summary. The conversation is unchanged; the attempt is recorded in the session log.",
            ),
            (
                ManualCompactionErrorCode::Commit,
                "Compaction did not finish cleanly; some session history may have changed. Inspect the current session state before retrying.",
            ),
            (
                ManualCompactionErrorCode::Persistence,
                "Compaction finished, but the session could not be saved.",
            ),
        ];
        for (code, text) in expected {
            assert_eq!(
                manual_compaction_failure_result(code),
                DesktopHumanCommandResult::Error { text: text.into() }
            );
        }
    }

    #[tokio::test]
    async fn desktop_compact_command_prioritizes_cancellation_without_provider_work() {
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        live.context()
            .sessions::<SessionStore>()
            .unwrap()
            .create(SessionId::new("desktop-manual-cancelled").unwrap())
            .unwrap();
        let cancellation = LifecycleCancellation::default();
        cancellation.cancel_with(SessionCancelCause::User);
        let (adapter, probe) = desktop_turn_adapter(Arc::new(AtomicUsize::new(0)));

        let result = live
            .dispatch_human_command(
                "desktop-manual-cancelled",
                "desktop-command-cancelled".into(),
                "/compact",
                adapter,
                &cancellation,
            )
            .await
            .unwrap();

        assert_eq!(
            result,
            DesktopHumanCommandDispatch::Handled(DesktopHumanCommandResult::Error {
                text: "Compaction cancelled.".into(),
            })
        );
        assert_eq!(probe.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.stream_calls.load(Ordering::SeqCst), 0);
        let session = live
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&SessionId::new("desktop-manual-cancelled").unwrap())
            .unwrap()
            .unwrap();
        assert!(session.events().unwrap().is_empty());
    }

    #[tokio::test]
    async fn desktop_agent_turn_stops_before_adapter_when_persistence_is_unbound() {
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        approve_agent_turn(&mut live);
        let flushes = Arc::new(AtomicUsize::new(0));
        let (adapter, probe) = desktop_turn_adapter(Arc::clone(&flushes));

        let error = live
            .run_agent_turn(
                desktop_turn_request(),
                adapter,
                &LifecycleCancellation::default(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            DesktopAgentTurnError::Session(SessionError::FlushFailed { .. })
        ));
        assert_eq!(probe.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.stream_calls.load(Ordering::SeqCst), 0);
        let session = live
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&SessionId::new("desktop-agent-session").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(session.inbox().next_turn().unwrap().len(), 1);
        assert!(runtime_open_turn(&session.events().unwrap()).is_none());
    }

    #[tokio::test]
    async fn desktop_agent_turn_rejects_an_unusable_workspace_before_inbox_or_adapter() {
        let scratch = tempfile::Builder::new()
            .prefix("n92-missing-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        let missing = scratch.path().join("missing-workspace");
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let (adapter, probe) = desktop_turn_adapter(Arc::new(AtomicUsize::new(0)));

        let error = live
            .run_agent_turn(
                desktop_turn_request_in(&missing),
                adapter,
                &LifecycleCancellation::default(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            DesktopAgentTurnError::Sandbox(SandboxError::WorkspaceBindingUnavailable { .. })
        ));
        assert_eq!(probe.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.stream_calls.load(Ordering::SeqCst), 0);
        let session = live
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get(&SessionId::new("desktop-agent-session").unwrap())
            .unwrap()
            .unwrap();
        assert!(session.inbox().next_turn().unwrap().is_empty());
        assert!(session.events().unwrap().is_empty());
    }

    #[tokio::test]
    async fn desktop_agent_turn_rejects_shadowed_committed_message_identity() {
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        let request = desktop_turn_request();
        let session = live
            .context()
            .sessions::<SessionStore>()
            .unwrap()
            .get_or_create(request.session_id.clone())
            .unwrap();
        session.append_user_message(request.input.clone()).unwrap();
        let original_node = session.surface().unwrap().nodes[0];
        session
            .append_user_message_with_surface(
                SessionMessage {
                    id: "replacement-input".into(),
                    role: SessionMessageRole::User,
                    content: vec![SessionContentBlock::Text {
                        text: "replacement".into(),
                    }],
                    source: SessionMessageSource::User,
                },
                SessionSurfaceIntent::replace(original_node, original_node, vec![original_node]),
            )
            .unwrap();
        assert!(
            session
                .derive_messages()
                .unwrap()
                .iter()
                .all(|message| message.id != request.input.id)
        );
        let flushes = Arc::new(AtomicUsize::new(0));
        let (adapter, probe) = desktop_turn_adapter(flushes);

        let error = live
            .run_agent_turn(request, adapter, &LifecycleCancellation::default())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            DesktopAgentTurnError::MessageAlreadyCommitted { .. }
        ));
        assert_eq!(probe.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(probe.stream_calls.load(Ordering::SeqCst), 0);
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
        let event = hartevo_cordis::SessionEvent {
            seq: 0,
            time_ms: 1,
            kind: SessionEventKind::AgentInboxSpliced {
                target: AgentInboxTarget::NextStep,
                start: 0,
                removed_count: Some(1),
                inserted: vec![],
                outcome: Some(AgentInboxOutcome::Canceled),
            },
        };

        let persisted = encode_event(&event).unwrap();
        assert!(matches!(
            &persisted.kind,
            PersistedSessionEventKind::AgentInboxSpliced {
                target: PersistedAgentInboxTarget::NextStep,
                start: 0,
                removed_count: Some(1),
                inserted,
                outcome: Some(PersistedAgentInboxOutcome::Canceled),
            } if inserted.is_empty()
        ));
        assert_eq!(decode_event(&persisted).unwrap(), event);
    }

    #[test]
    fn subagent_descriptor_codec_round_trips_exactly() {
        let event = SessionEvent {
            seq: 1,
            time_ms: 2,
            kind: SessionEventKind::SubagentDescriptor {
                descriptor: OneShotSubagentDescriptor::new("spawn", Some("research".into())),
            },
        };

        let persisted = encode_event(&event).unwrap();
        assert!(matches!(
            &persisted.kind,
            PersistedSessionEventKind::SubagentDescriptor { descriptor }
                if descriptor == &serde_json::json!({
                    "version": 3,
                    "mode": "one-shot",
                    "provider": "spawn",
                    "label": "research",
                })
        ));
        assert_eq!(decode_event(&persisted).unwrap(), event);

        let invalid = PersistedSessionEvent {
            seq: 1,
            time_ms: 2,
            kind: PersistedSessionEventKind::SubagentDescriptor {
                descriptor: serde_json::json!({
                    "version": 3,
                    "mode": "continuable",
                    "provider": "spawn",
                }),
            },
        };
        assert!(matches!(
            decode_event(&invalid),
            Err(DesktopSessionPersistenceError::Session(
                SessionError::InvalidSubagentDescriptor {
                    expected: "the versioned one-shot schema",
                }
            ))
        ));
    }

    #[test]
    fn approval_codec_round_trips_the_closed_audit_vocabulary() {
        let id = ApprovalRequestId::new("desktop-approval-1").unwrap();
        let events = [
            SessionEvent {
                seq: 0,
                time_ms: 1,
                kind: SessionEventKind::ApprovalPolicy {
                    approval: SessionApprovalPolicy::new(
                        ApprovalPolicy::Never,
                        Some(ApprovalPolicySource::Delegation),
                    ),
                },
            },
            SessionEvent {
                seq: 1,
                time_ms: 2,
                kind: SessionEventKind::ApprovalAsked {
                    approval: SessionApprovalAsked::new(
                        id.clone(),
                        "filesystem.write".into(),
                        Some("call-1".into()),
                        Some("requires approval".into()),
                    )
                    .unwrap(),
                },
            },
            SessionEvent {
                seq: 2,
                time_ms: 3,
                kind: SessionEventKind::ApprovalDecided {
                    approval: SessionApprovalDecided::new(id, ApprovalOutcome::AllowedOnce),
                },
            },
        ];

        for event in events {
            let persisted = encode_event(&event).unwrap();
            assert_eq!(decode_event(&persisted).unwrap(), event);
        }
    }

    #[test]
    fn sandbox_mode_codec_round_trips_the_closed_policy_vocabulary() {
        let event = SessionEvent {
            seq: 0,
            time_ms: 1,
            kind: SessionEventKind::SandboxMode {
                sandbox: SessionSandboxMode::new(
                    SandboxMode::WorkspaceWrite,
                    Some(SandboxModeSource::Delegation),
                ),
            },
        };

        let persisted = encode_event(&event).unwrap();
        assert_eq!(decode_event(&persisted).unwrap(), event);
        let PersistedSessionEventKind::SandboxMode { sandbox } = persisted.kind else {
            unreachable!();
        };
        assert_eq!(
            sandbox,
            serde_json::json!({
                "mode": "workspace-write",
                "source": "delegation",
            })
        );
    }

    #[test]
    fn session_header_codec_preserves_monotone_delegation_depth() {
        let mut header = SessionHeader::new_at(SessionId::new("depth-child").unwrap(), 1).unwrap();
        header.parent_session = Some(SessionId::new("depth-parent").unwrap());
        header.delegation_depth = 3;
        header.seed_length = Some(0);
        let checkpoint = SessionCheckpoint {
            header: header.clone(),
            events: Vec::new(),
        };

        let persisted = encode_checkpoint(&checkpoint).unwrap();
        assert_eq!(persisted.header.delegation_depth, 3);
        let (decoded, events) = decode_checkpoint(persisted).unwrap();
        assert_eq!(decoded, header);
        assert!(events.is_empty());
    }

    #[test]
    fn llm_retry_codec_round_trips_schedule_and_started_transition() {
        let retry = SessionLlmRetry {
            retry_id: "desktop-retry".into(),
            turn: 1,
            step: 1,
            provider: "mock".into(),
            mode: SessionLlmRetryMode::Normal,
            policy_key: "normal-policy".into(),
            retry: 1,
            max_retries: Some(2),
            delay_ms: 25,
            failure: SessionLlmFailure {
                message: "busy".into(),
                code: "RATE_LIMIT".into(),
                status: Some(429),
                provider_retry_after_ms: Some(25),
                request_id: Some("request-1".into()),
            },
        };
        let events = [
            SessionEvent {
                seq: 0,
                time_ms: 1,
                kind: SessionEventKind::LlmRetry { retry },
            },
            SessionEvent {
                seq: 1,
                time_ms: 2,
                kind: SessionEventKind::LlmRetryStarted {
                    started: SessionLlmRetryStarted {
                        retry_id: "desktop-retry".into(),
                        turn: 1,
                        step: 1,
                        retry: 1,
                    },
                },
            },
        ];

        for event in events {
            let persisted = encode_event(&event).unwrap();
            assert_eq!(decode_event(&persisted).unwrap(), event);
        }
    }

    #[test]
    fn compaction_codec_round_trips_transaction_events() {
        let id = hartevo_cordis::CompactionId::new("desktop-compact").unwrap();
        let events = [
            SessionEvent {
                seq: 0,
                time_ms: 1,
                kind: SessionEventKind::CompactionStart {
                    compaction: SessionCompactionStart {
                        compaction_id: id.clone(),
                        source_command_id: Some("command-1".into()),
                        turn: None,
                    },
                },
            },
            SessionEvent {
                seq: 1,
                time_ms: 2,
                kind: SessionEventKind::CompactionSummary {
                    compaction: SessionCompactionSummary {
                        compaction_id: id.clone(),
                        source_command_id: Some("command-1".into()),
                        summary: vec![SessionContentBlock::Text {
                            text: "summary".into(),
                        }],
                        shadowed_range: hartevo_cordis::CompactionRange { start: 4, end: 2 },
                        shadowed_seqs: vec![4, 2],
                        shadowed_token_count: 12,
                        provider: "mock".into(),
                        model: "summary".into(),
                        max_tokens: Some(256),
                        usage: None,
                        raw_output: None,
                        llm_stream_call: false,
                    },
                },
            },
            SessionEvent {
                seq: 2,
                time_ms: 3,
                kind: SessionEventKind::CompactionEnd {
                    compaction: SessionCompactionEnd {
                        compaction_id: id,
                        source_command_id: Some("command-1".into()),
                        turn: None,
                        error: None,
                    },
                },
            },
        ];

        for event in events {
            let persisted = encode_event(&event).unwrap();
            assert_eq!(decode_event(&persisted).unwrap(), event);
        }
    }

    #[test]
    fn compaction_survives_desktop_session_persistence_rebind() {
        let mut live =
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap();
        assert_eq!(
            live.bind_session_persistence(ProjectStore::in_memory().unwrap())
                .unwrap(),
            0
        );
        let sessions = live.context().sessions::<SessionStore>().unwrap();
        let id = SessionId::new("persisted-compaction").unwrap();
        let session = sessions.create(id.clone()).unwrap();
        for (message_id, text) in [("user-1", "first"), ("user-2", "second")] {
            session
                .append_user_message(SessionMessage {
                    id: message_id.into(),
                    role: SessionMessageRole::User,
                    content: vec![SessionContentBlock::Text { text: text.into() }],
                    source: SessionMessageSource::User,
                })
                .unwrap();
        }
        let nodes = session.surface().unwrap().nodes;
        let lease = session
            .begin_compaction(
                CompactionId::new("desktop-persisted").unwrap(),
                None,
                None,
                nodes[0],
                nodes[1],
            )
            .unwrap();
        session
            .complete_compaction(
                &lease,
                CompactionSummaryDraft {
                    summary: vec![SessionContentBlock::Text {
                        text: "raw summary".into(),
                    }],
                    shadowed_token_count: 10,
                    provider: "mock".into(),
                    model: "summary".into(),
                    max_tokens: None,
                    usage: None,
                    raw_output: None,
                    llm_stream_call: false,
                },
                CompactionCheckpoint {
                    message_id: "checkpoint".into(),
                    content: vec![SessionContentBlock::Text {
                        text: "persisted summary".into(),
                    }],
                },
            )
            .unwrap();
        let expected_surface = session.surface().unwrap();
        let expected_messages = session.derive_messages().unwrap();
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
            .get(&id)
            .unwrap()
            .unwrap();
        assert_eq!(restored.surface().unwrap(), expected_surface);
        assert_eq!(restored.derive_messages().unwrap(), expected_messages);
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
                compaction_id: None,
                source_command_id: None,
            },
        };
        session.inbox().append_next_turn(message.clone()).unwrap();
        session
            .inbox()
            .append_next_step(step_message.clone())
            .unwrap();
        let replacement = SessionMessage {
            id: "persisted-step-replacement".into(),
            role: SessionMessageRole::User,
            content: vec![SessionContentBlock::Text {
                text: "replacement context".into(),
            }],
            source: SessionMessageSource::Plugin {
                plugin: "watcher".into(),
                compaction_id: None,
                source_command_id: None,
            },
        };
        assert!(
            session
                .inbox()
                .replace(&step_message.id, replacement.clone())
                .unwrap()
        );
        assert!(session.inbox().remove(&message.id).unwrap());
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
        assert!(restored.inbox().next_turn().unwrap().is_empty());
        assert_eq!(restored.inbox().next_step().unwrap(), [replacement]);
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

    fn record_runtime_status(host: &Arc<DesktopCordisSlot>) -> Arc<Mutex<Vec<AgentStatus>>> {
        let status_order = Arc::new(Mutex::new(Vec::new()));
        let status_probe = Arc::clone(host);
        let observed_status_order = Arc::clone(&status_order);
        host.lock()
            .unwrap()
            .context_mut()
            .on_emit(events::AGENT_STATUS, move |change: &AgentStatusChange| {
                let unlocked = status_probe
                    .try_lock()
                    .expect("agent/status must run without the Cordis host lock");
                assert_eq!(change.agent().status(), change.status());
                assert_eq!(
                    unlocked
                        .context()
                        .agents::<AgentsSurface>()
                        .unwrap()
                        .list()
                        .as_slice(),
                    std::slice::from_ref(change.agent())
                );
                observed_status_order.lock().unwrap().push(change.status());
            })
            .unwrap();
        status_order
    }

    #[test]
    fn started_failure_is_cached_without_fabricating_agent_disposal() {
        let host = Arc::new(DesktopCordisSlot::new(
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
                    let started_host = started_host.try_lock().unwrap();
                    assert_eq!(
                        started_host
                            .context()
                            .agents::<AgentsSurface>()
                            .unwrap()
                            .list()
                            .len(),
                        1,
                        "agent/created observes the committed publication"
                    );
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
        assert!(
            host.lock()
                .unwrap()
                .context()
                .agents::<AgentsSurface>()
                .unwrap()
                .list()
                .is_empty(),
            "failed publication rolls the registry entry back before returning"
        );
        let completion = host.lock().unwrap().finish_runtime(permit).unwrap();
        completion.announce().unwrap();
        assert_eq!(disposed_calls.load(Ordering::SeqCst), 0);
        assert!(host.lock().unwrap().active_runtime_scope().is_none());
    }

    #[test]
    fn started_failure_skips_authority_without_running_disposal_callbacks() {
        let host = Arc::new(DesktopCordisSlot::new(
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
        let AuthorityDispatchError::Cordis(error) = &error else {
            panic!("expected the started failure: {error:?}");
        };
        assert_emit_source(error, "started");
        assert_eq!(authority_calls.load(Ordering::SeqCst), 0);
        assert!(host.lock().unwrap().active_runtime_scope().is_none());
    }

    #[test]
    fn authority_failure_is_returned_while_the_agent_remains_idle() {
        let host = Arc::new(DesktopCordisSlot::new(
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
        assert_eq!(
            error,
            AuthorityDispatchError::Authority(PhaseError("authority"))
        );
        assert_eq!(
            error.source().unwrap().downcast_ref::<PhaseError>(),
            Some(&PhaseError("authority"))
        );
        let mut locked = host.lock().unwrap();
        let agents = locked.context().agents::<AgentsSurface>().unwrap();
        let agent = agents.list().into_iter().next().unwrap();
        assert_eq!(agent.status(), AgentStatus::Idle);
        let teardown = locked.host_mut().teardown();
        drop(locked);
        teardown.announce();
        assert!(agents.list().is_empty());
    }

    #[test]
    fn desktop_runtime_adapter_releases_host_lock_and_calls_authority_once() {
        let host = Arc::new(DesktopCordisSlot::new(
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
        let live_agent = Arc::new(Mutex::new(None::<AgentRef>));
        let observed_agent = Arc::clone(&live_agent);
        let status_order = record_runtime_status(&host);

        let output = dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                assert_eq!(permit.scope(), &expected_scope);
                let agent = {
                    let unlocked = probe
                        .try_lock()
                        .expect("Application adapter must run without the Cordis host lock");
                    let agents = unlocked.context().agents::<AgentsSurface>().unwrap().list();
                    assert_eq!(agents.len(), 1);
                    agents.into_iter().next().unwrap()
                };
                assert_eq!(agent.status(), AgentStatus::Running);
                *observed_agent.lock().unwrap() = Some(agent);
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
        assert_eq!(
            *status_order.lock().unwrap(),
            [AgentStatus::Running, AgentStatus::Idle]
        );
        assert_eq!(
            live_agent.lock().unwrap().as_ref().unwrap().status(),
            AgentStatus::Idle
        );
        let agent = live_agent.lock().unwrap().as_ref().unwrap().clone();
        let mut locked = host.lock().unwrap();
        assert!(locked.active_runtime_scope().is_none());
        let agents = locked.context().agents::<AgentsSurface>().unwrap();
        assert_eq!(agents.list().as_slice(), std::slice::from_ref(&agent));
        let teardown = locked.host_mut().teardown();
        drop(locked);
        teardown.announce();
        assert!(agents.list().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one journey proves background ownership across two turns and exact Host teardown"
    )]
    fn desktop_background_job_survives_turn_finish_and_stops_on_host_teardown() {
        let host = Arc::new(DesktopCordisSlot::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let jobs = host
            .lock()
            .unwrap()
            .context()
            .jobs::<JobsSurface>()
            .unwrap();
        let owner = SessionId::new("persistent-agent-job").unwrap();
        let stopped = Arc::new((Mutex::new(false), Condvar::new()));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let worker_stop = Arc::clone(&stopped);
        let control_stop = Arc::clone(&stopped);
        let control_cancelled = Arc::clone(&cancelled);
        let start_jobs = Arc::clone(&jobs);
        let start_owner = owner.clone();
        let scope = runtime_scope();

        let (job_id, agent) = dispatch_live_runtime(
            &host,
            scope.clone(),
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                let job_id = start_jobs.start(
                    &start_owner,
                    permit.agent(),
                    "bash",
                    "persistent background work",
                    move |completion| {
                        thread::spawn(move || {
                            let (lock, changed) = &*worker_stop;
                            let mut stopped = lock.lock().unwrap();
                            while !*stopped {
                                stopped = changed.wait(stopped).unwrap();
                            }
                            let _ = completion.complete(JobOutcome::new(JobTerminalStatus::Killed));
                        });
                        Ok(JobControl::new(move |_| {
                            control_cancelled.fetch_add(1, Ordering::SeqCst);
                            let (lock, changed) = &*control_stop;
                            *lock.lock().unwrap() = true;
                            changed.notify_all();
                        }))
                    },
                )?;
                Ok::<_, hartevo_cordis::JobError>((job_id, permit.agent().clone()))
            },
        )
        .unwrap();

        assert_eq!(agent.status(), AgentStatus::Idle);
        assert_eq!(
            jobs.get(job_id.as_str(), &owner).unwrap().status(),
            JobStatus::Running
        );
        assert_eq!(cancelled.load(Ordering::SeqCst), 0);

        let expected_agent = agent.clone();
        let observed_jobs = Arc::clone(&jobs);
        let observed_owner = owner.clone();
        let observed_job_id = job_id.clone();
        dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                assert!(permit.agent().is_same_lifecycle(&expected_agent));
                assert_eq!(
                    observed_jobs
                        .get(observed_job_id.as_str(), &observed_owner)
                        .unwrap()
                        .status(),
                    JobStatus::Running
                );
                Ok::<_, &'static str>(())
            },
        )
        .unwrap();
        assert_eq!(agent.status(), AgentStatus::Idle);
        assert_eq!(
            jobs.get(job_id.as_str(), &owner).unwrap().status(),
            JobStatus::Running
        );
        assert_eq!(cancelled.load(Ordering::SeqCst), 0);

        let agents = host
            .lock()
            .unwrap()
            .context()
            .agents::<AgentsSurface>()
            .unwrap();
        let teardown = {
            let mut locked = host.lock().unwrap();
            locked.host_mut().teardown()
        };
        teardown.announce();
        assert_eq!(cancelled.load(Ordering::SeqCst), 1);
        assert!(jobs.list(&owner).is_empty());
        assert!(agents.list().is_empty());
    }

    #[test]
    fn abandoned_runtime_status_is_drained_only_after_desktop_unlock() {
        let host = Arc::new(DesktopCordisSlot::new(
            mount_cordis_host(&projection(DesktopRuntimeAvailabilityStatus::NotConfigured))
                .unwrap(),
        ));
        let status_order = record_runtime_status(&host);
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
        permit.announce_started().unwrap();
        let agent = host
            .lock()
            .unwrap()
            .context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .into_iter()
            .next()
            .unwrap();

        let locked = host.lock().unwrap();
        drop(permit);
        assert_eq!(agent.status(), AgentStatus::Idle);
        assert!(locked.active_runtime_scope().is_none());
        assert_eq!(*status_order.lock().unwrap(), [AgentStatus::Running]);
        assert_eq!(
            locked
                .context()
                .agents::<AgentsSurface>()
                .unwrap()
                .list()
                .as_slice(),
            std::slice::from_ref(&agent)
        );
        drop(locked);

        assert_eq!(
            *status_order.lock().unwrap(),
            [AgentStatus::Running, AgentStatus::Idle]
        );
        assert_eq!(
            host.lock()
                .unwrap()
                .context()
                .agents::<AgentsSurface>()
                .unwrap()
                .list()
                .as_slice(),
            std::slice::from_ref(&agent)
        );
    }

    #[test]
    fn desktop_domain_command_releases_lock_and_calls_application_once() {
        let host = Arc::new(DesktopCordisSlot::new(
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
        let host = Arc::new(DesktopCordisSlot::new(
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
        let host = Arc::new(DesktopCordisSlot::new(
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
        let host = Arc::new(DesktopCordisSlot::new(
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
        let host = Arc::new(DesktopCordisSlot::new(
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
        let host = Arc::new(DesktopCordisSlot::new(
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
        let host = Arc::new(DesktopCordisSlot::new(
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
    fn lifecycle_observers_reenter_after_unlock_and_disposal_waits_for_host_teardown() {
        let host = Arc::new(DesktopCordisSlot::new(
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
                        "disposed observer must run after host unlock"
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
        assert_eq!(finished.load(Ordering::SeqCst), 0);
        let teardown = {
            let mut locked = host.lock().unwrap();
            locked.host_mut().teardown()
        };
        teardown.announce();
        assert_eq!(finished.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poisoned_host_fails_closed_without_calling_authority() {
        let host = Arc::new(DesktopCordisSlot::new(
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
        let host = Arc::new(DesktopCordisSlot::new(
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
        let agent = host
            .lock()
            .unwrap()
            .context()
            .agents::<AgentsSurface>()
            .unwrap()
            .list()
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(agent.status(), AgentStatus::Idle);
        let expected_agent = agent.clone();
        dispatch_live_runtime(
            &host,
            scope,
            &ConsentState::NotRequired,
            None,
            None,
            now(),
            move |permit| {
                assert!(permit.agent().is_same_lifecycle(&expected_agent));
                Ok::<_, &'static str>(())
            },
        )
        .unwrap();
        assert_eq!(agent.status(), AgentStatus::Idle);
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
