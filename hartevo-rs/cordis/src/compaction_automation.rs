//! DeepSeek Harness-compatible automatic and manual Cordis compaction.

use std::fmt;

use crate::compaction::{CompactionId, CompactionLease, CompactionResult};
use crate::compaction_policy::{
    CompactionPlan, CompactionPolicyConfig, CompactionPolicyError, CompactionRetention,
    CompactionTrigger, DEFAULT_COMPACTION_RETRIES, DEFAULT_COMPACTION_THRESHOLD_RATIO,
    DEFAULT_MAX_OVERFLOW_RETRIES, DEFAULT_RETAIN_RATIO, DEFAULT_SUMMARY_MAX_TOKENS,
    ResolvedCompactionConfig, execute_compaction_plan, measure_compaction_session, plan_compaction,
    resolve_compaction_config, select_compactable_range, summarize_compaction,
};
use crate::context::{Context, CordisError, keys};
use crate::fiber::LifecycleCancellation;
use crate::service::Service;
use crate::session::{
    SessionError, SessionHandle, SessionLlmFailure, SessionStore, SessionSurface,
};
use crate::surface::CONTEXT_WINDOW_EXCEEDED_CODE;

/// Dependencies required by the optional automatic compaction service.
pub const COMPACTION_AUTOMATION_KEYS: &[&str] = &[keys::LLM, keys::SESSIONS];

/// Configured compaction capability mounted by the Desktop Cordis host.
#[derive(Debug, Clone, PartialEq)]
pub struct CompactionAutomation {
    config: ResolvedCompactionConfig,
}

impl CompactionAutomation {
    pub fn new(config: CompactionPolicyConfig) -> Result<Self, CompactionPolicyError> {
        Ok(Self {
            config: resolve_compaction_config(config)?,
        })
    }

    #[must_use]
    pub const fn config(&self) -> &ResolvedCompactionConfig {
        &self.config
    }
}

impl Default for CompactionAutomation {
    fn default() -> Self {
        Self {
            config: ResolvedCompactionConfig {
                threshold_ratio: DEFAULT_COMPACTION_THRESHOLD_RATIO,
                retention: CompactionRetention::Ratio(DEFAULT_RETAIN_RATIO),
                summarization_provider: String::new(),
                summarization_model: String::new(),
                max_tokens: DEFAULT_SUMMARY_MAX_TOKENS,
                compaction_retries: DEFAULT_COMPACTION_RETRIES,
                max_overflow_retries: DEFAULT_MAX_OVERFLOW_RETRIES,
                model_policies: Vec::new(),
                auto: true,
            },
        }
    }
}

impl Service for CompactionAutomation {
    fn inject() -> &'static [&'static str] {
        COMPACTION_AUTOMATION_KEYS
    }

    fn apply(self, ctx: &mut Context) -> Result<(), CordisError> {
        ctx.provide(keys::COMPACTION, self).map(|_| ())
    }
}

/// Whether a failed agent request must retain its provider error or retry from
/// a newly replaced surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextOverflowRecovery {
    PreserveFailure,
    Retry { result: Option<CompactionResult> },
}

impl ContextOverflowRecovery {
    #[must_use]
    pub const fn should_retry(&self) -> bool {
        matches!(self, Self::Retry { .. })
    }

    #[must_use]
    pub const fn result(&self) -> Option<&CompactionResult> {
        match self {
            Self::PreserveFailure | Self::Retry { result: None } => None,
            Self::Retry {
                result: Some(result),
            } => Some(result),
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CompactionAutomationError {
    #[error(transparent)]
    Policy(#[from] CompactionPolicyError),
    #[error(
        "compaction remains above pressure after {attempts} attempts ({estimated_tokens} estimated tokens >= threshold {threshold_tokens})"
    )]
    PressureRemaining {
        attempts: u64,
        estimated_tokens: u64,
        threshold_tokens: u64,
    },
    #[error("successful compaction did not advance the Session replacement generation")]
    ReplacementDidNotAdvance,
}

/// Stable failure classes returned by an explicit idle-session compaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualCompactionErrorCode {
    Busy,
    Cancelled,
    Changed,
    Summary,
    Commit,
    Persistence,
}

impl ManualCompactionErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Cancelled => "cancelled",
            Self::Changed => "changed",
            Self::Summary => "summary",
            Self::Commit => "commit",
            Self::Persistence => "persistence",
        }
    }
}

impl fmt::Display for ManualCompactionErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Classified manual-compaction failure suitable for a direct command result.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[error("manual compaction failed ({code}): {message}")]
pub struct ManualCompactionError {
    code: ManualCompactionErrorCode,
    message: String,
}

impl ManualCompactionError {
    fn new(code: ManualCompactionErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn code(&self) -> ManualCompactionErrorCode {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

enum ManualAttemptOutcome {
    Success(CompactionResult),
    ClosedFailure(ManualCompactionError),
    UnclosedFailure(ManualCompactionError),
    Rejected(ManualCompactionError),
}

/// Run automatic pressure compaction before one real agent step is derived.
///
/// The caller deliberately treats an error as non-blocking, matching Harness:
/// pressure maintenance must not prevent the user turn from continuing.
pub async fn compact_before_agent_step(
    ctx: &mut Context,
    session: &SessionHandle,
    turn: u64,
    cancellation: &LifecycleCancellation,
) -> Result<Option<CompactionResult>, CompactionAutomationError> {
    let Some(config) = automatic_config(ctx) else {
        return Ok(None);
    };
    if cancellation.is_cancelled() {
        return Ok(None);
    }

    let mut attempts = 0_u64;
    let mut latest = None;
    loop {
        let Some(plan) = plan_compaction(session, &config, CompactionTrigger::Pressure)? else {
            return Ok(latest);
        };
        let allowed_attempts = plan.compaction_retries.saturating_add(1);
        if attempts >= allowed_attempts {
            return Err(CompactionAutomationError::PressureRemaining {
                attempts,
                estimated_tokens: plan.measurement.total_tokens,
                threshold_tokens: plan.threshold_tokens.unwrap_or_default(),
            });
        }
        let compaction_id = automatic_compaction_id(session, turn, "pressure")?;
        latest = Some(
            execute_compaction_plan(
                ctx,
                session,
                &plan,
                compaction_id,
                None,
                Some(turn),
                cancellation.clone(),
            )
            .await?,
        );
        attempts = attempts.saturating_add(1);
    }
}

/// Force one useful standalone compaction and checkpoint every closed attempt.
///
/// This is the backend seam consumed by a later `/compact` adapter. It writes
/// no marker for a no-op or pre-start rejection, and the Session reducer keeps
/// a turn boundary from crossing the standalone durable lock.
pub async fn compact_now(
    ctx: &mut Context,
    session: &SessionHandle,
    source_command_id: Option<String>,
    cancellation: &LifecycleCancellation,
) -> Result<Option<CompactionResult>, ManualCompactionError> {
    if cancellation.is_cancelled() {
        return Err(manual_cancelled(cancellation));
    }
    let config = compaction_config(ctx).ok_or_else(|| {
        ManualCompactionError::new(
            ManualCompactionErrorCode::Summary,
            "the Cordis compaction service is not mounted",
        )
    })?;

    // Harness selects before opening the bracket so an empty session is a
    // true no-op: no durable marker and no persistence checkpoint.
    let measurement =
        measure_compaction_session(session).map_err(|error| classify_policy_failure(&error))?;
    if select_compactable_range(session, &measurement, 0)
        .map_err(|error| classify_policy_failure(&error))?
        .is_none()
    {
        return Ok(None);
    }
    let Some(plan) = plan_compaction(session, &config, CompactionTrigger::Manual)
        .map_err(|error| classify_policy_failure(&error))?
    else {
        return Ok(None);
    };
    let compaction_id =
        standalone_compaction_id(session).map_err(|error| classify_policy_failure(&error))?;
    let sessions = ctx.sessions::<SessionStore>().ok_or_else(|| {
        ManualCompactionError::new(
            ManualCompactionErrorCode::Persistence,
            "the Cordis Session store is not mounted",
        )
    })?;

    let outcome = run_manual_attempt(
        ctx,
        session,
        &plan,
        compaction_id,
        source_command_id,
        cancellation.clone(),
    )
    .await;
    let flush = match &outcome {
        ManualAttemptOutcome::Success(_) | ManualAttemptOutcome::ClosedFailure(_) => {
            Some(sessions.flush(session).await)
        }
        ManualAttemptOutcome::UnclosedFailure(_) | ManualAttemptOutcome::Rejected(_) => None,
    };

    if cancellation.is_cancelled() {
        return Err(manual_cancelled(cancellation));
    }
    match outcome {
        ManualAttemptOutcome::Success(result) => match flush {
            Some(Ok(_)) => Ok(Some(result)),
            Some(Err(error)) => Err(ManualCompactionError::new(
                ManualCompactionErrorCode::Persistence,
                error.to_string(),
            )),
            None => unreachable!("a successful manual compaction is closed"),
        },
        ManualAttemptOutcome::ClosedFailure(error)
        | ManualAttemptOutcome::UnclosedFailure(error)
        | ManualAttemptOutcome::Rejected(error) => Err(error),
    }
}

/// Attempt one bounded recovery for a provider-confirmed context overflow.
///
/// Retry authorization requires durable replacement-generation progress. A
/// failure after such progress may still retry; otherwise the original model
/// failure remains authoritative.
pub async fn recover_context_overflow(
    ctx: &mut Context,
    session: &SessionHandle,
    turn: u64,
    prior_retries: u64,
    failure: &SessionLlmFailure,
    cancellation: &LifecycleCancellation,
) -> Result<ContextOverflowRecovery, CompactionAutomationError> {
    if failure.code != CONTEXT_WINDOW_EXCEEDED_CODE || cancellation.is_cancelled() {
        return Ok(ContextOverflowRecovery::PreserveFailure);
    }
    let Some(config) = automatic_config(ctx) else {
        return Ok(ContextOverflowRecovery::PreserveFailure);
    };
    let Some(plan) = plan_compaction(session, &config, CompactionTrigger::Overflow)? else {
        return Ok(ContextOverflowRecovery::PreserveFailure);
    };
    if prior_retries >= plan.max_overflow_retries {
        return Ok(ContextOverflowRecovery::PreserveFailure);
    }

    let generation = session
        .surface()
        .map_err(CompactionPolicyError::from)?
        .replace_generation;
    let compaction_id = automatic_compaction_id(session, turn, "overflow")?;
    let result = execute_compaction_plan(
        ctx,
        session,
        &plan,
        compaction_id,
        None,
        Some(turn),
        cancellation.clone(),
    )
    .await;
    let advanced = session
        .surface()
        .map_err(CompactionPolicyError::from)?
        .replace_generation
        > generation;
    if cancellation.is_cancelled() {
        return result
            .map(|_| ContextOverflowRecovery::PreserveFailure)
            .map_err(Into::into);
    }
    match (result, advanced) {
        (Ok(result), true) => Ok(ContextOverflowRecovery::Retry {
            result: Some(result),
        }),
        (Err(_), true) => Ok(ContextOverflowRecovery::Retry { result: None }),
        (Err(error), false) => Err(error.into()),
        (Ok(_), false) => Err(CompactionAutomationError::ReplacementDidNotAdvance),
    }
}

fn automatic_config(ctx: &Context) -> Option<ResolvedCompactionConfig> {
    compaction_config(ctx).filter(|config| config.auto)
}

fn compaction_config(ctx: &Context) -> Option<ResolvedCompactionConfig> {
    ctx.get::<CompactionAutomation>(keys::COMPACTION)
        .map(|service| service.config.clone())
}

fn automatic_compaction_id(
    session: &SessionHandle,
    turn: u64,
    trigger: &str,
) -> Result<CompactionId, CompactionPolicyError> {
    let next_seq = session
        .events()?
        .last()
        .map_or(Some(0), |event| event.seq.checked_add(1))
        .ok_or(SessionError::EventSequenceOverflow)?;
    CompactionId::new(format!("auto-{}-{turn}-{trigger}-{next_seq}", session.id()))
        .map_err(Into::into)
}

fn standalone_compaction_id(
    session: &SessionHandle,
) -> Result<CompactionId, CompactionPolicyError> {
    let next_seq = session
        .events()?
        .last()
        .map_or(Some(0), |event| event.seq.checked_add(1))
        .ok_or(SessionError::EventSequenceOverflow)?;
    CompactionId::new(format!("manual-{}-{next_seq}", session.id())).map_err(Into::into)
}

async fn run_manual_attempt(
    ctx: &mut Context,
    session: &SessionHandle,
    plan: &CompactionPlan,
    compaction_id: CompactionId,
    source_command_id: Option<String>,
    cancellation: LifecycleCancellation,
) -> ManualAttemptOutcome {
    if cancellation.is_cancelled() {
        return ManualAttemptOutcome::Rejected(manual_cancelled(&cancellation));
    }
    if let Err(error) = require_append_only_surface(session, &plan.surface) {
        return ManualAttemptOutcome::Rejected(classify_policy_failure(&error));
    }
    let lease = match session.begin_compaction(
        compaction_id.clone(),
        source_command_id,
        None,
        plan.region.start,
        plan.region.end,
    ) {
        Ok(lease) => lease,
        Err(error) => return ManualAttemptOutcome::Rejected(classify_entry_failure(&error)),
    };
    let prepared = match summarize_compaction(ctx, plan, &compaction_id, cancellation.clone()).await
    {
        Ok(prepared) => prepared,
        Err(error) => {
            let failure = classify_policy_failure(&error);
            return close_manual_failure(session, &lease, failure);
        }
    };
    if cancellation.is_cancelled() {
        return close_manual_failure(session, &lease, manual_cancelled(&cancellation));
    }
    if let Err(error) = require_append_only_surface(session, &plan.surface) {
        return close_manual_failure(session, &lease, classify_policy_failure(&error));
    }
    match session.complete_compaction(&lease, prepared.draft, prepared.checkpoint) {
        Ok(result) => ManualAttemptOutcome::Success(result),
        Err(error) => {
            let failure = classify_commit_failure(&error);
            close_manual_failure(session, &lease, failure)
        }
    }
}

fn require_append_only_surface(
    session: &SessionHandle,
    expected: &SessionSurface,
) -> Result<(), CompactionPolicyError> {
    let current = session.surface()?;
    if current.replace_generation == expected.replace_generation
        && current.nodes.starts_with(&expected.nodes)
    {
        Ok(())
    } else {
        Err(CompactionPolicyError::SurfaceChanged)
    }
}

fn close_manual_failure(
    session: &SessionHandle,
    lease: &CompactionLease,
    failure: ManualCompactionError,
) -> ManualAttemptOutcome {
    match session.fail_compaction(lease, failure.to_string()) {
        Ok(_) => ManualAttemptOutcome::ClosedFailure(failure),
        Err(close) => ManualAttemptOutcome::UnclosedFailure(ManualCompactionError::new(
            ManualCompactionErrorCode::Commit,
            format!("{failure}; closing the durable compaction lock failed: {close}"),
        )),
    }
}

fn classify_policy_failure(error: &CompactionPolicyError) -> ManualCompactionError {
    let code = match error {
        CompactionPolicyError::Cancelled { .. } => ManualCompactionErrorCode::Cancelled,
        CompactionPolicyError::SurfaceChanged
        | CompactionPolicyError::MeasurementSurfaceChanged
        | CompactionPolicyError::Session(
            SessionError::CompactionRegionChanged
            | SessionError::CompactionSurfaceNodeNotFound { .. },
        ) => ManualCompactionErrorCode::Changed,
        CompactionPolicyError::CloseAfterFailure { .. } => ManualCompactionErrorCode::Commit,
        CompactionPolicyError::Session(
            SessionError::CompactionAlreadyOpen { .. }
            | SessionError::CompactionOwnerMismatch { .. }
            | SessionError::CompactionCrossesTurnBoundary,
        ) => ManualCompactionErrorCode::Busy,
        _ => ManualCompactionErrorCode::Summary,
    };
    ManualCompactionError::new(code, error.to_string())
}

fn classify_entry_failure(error: &SessionError) -> ManualCompactionError {
    let code = match error {
        SessionError::CompactionAlreadyOpen { .. }
        | SessionError::CompactionOwnerMismatch { .. }
        | SessionError::CompactionCrossesTurnBoundary => ManualCompactionErrorCode::Busy,
        SessionError::CompactionRegionChanged
        | SessionError::CompactionSurfaceNodeNotFound { .. } => ManualCompactionErrorCode::Changed,
        _ => ManualCompactionErrorCode::Commit,
    };
    ManualCompactionError::new(code, error.to_string())
}

fn classify_commit_failure(error: &SessionError) -> ManualCompactionError {
    let code = match error {
        SessionError::CompactionRegionChanged
        | SessionError::CompactionSurfaceNodeNotFound { .. } => ManualCompactionErrorCode::Changed,
        _ => ManualCompactionErrorCode::Commit,
    };
    ManualCompactionError::new(code, error.to_string())
}

fn manual_cancelled(cancellation: &LifecycleCancellation) -> ManualCompactionError {
    ManualCompactionError::new(
        ManualCompactionErrorCode::Cancelled,
        format!(
            "manual compaction was cancelled ({:?})",
            cancellation.cause()
        ),
    )
}
