//! Automatic DeepSeek Harness-compatible compaction for the Cordis agent loop.

use crate::compaction::{CompactionId, CompactionResult};
use crate::compaction_policy::{
    CompactionPolicyConfig, CompactionPolicyError, CompactionRetention, CompactionTrigger,
    DEFAULT_COMPACTION_RETRIES, DEFAULT_COMPACTION_THRESHOLD_RATIO, DEFAULT_MAX_OVERFLOW_RETRIES,
    DEFAULT_RETAIN_RATIO, DEFAULT_SUMMARY_MAX_TOKENS, ResolvedCompactionConfig,
    execute_compaction_plan, plan_compaction, resolve_compaction_config,
};
use crate::context::{Context, CordisError, keys};
use crate::fiber::LifecycleCancellation;
use crate::service::Service;
use crate::session::{SessionError, SessionHandle, SessionLlmFailure};
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
    ctx.get::<CompactionAutomation>(keys::COMPACTION)
        .map(|service| service.config.clone())
        .filter(|config| config.auto)
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
