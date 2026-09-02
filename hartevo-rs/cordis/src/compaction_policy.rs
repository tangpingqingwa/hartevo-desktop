//! DeepSeek Harness-aligned compaction policy, token measurement, and summary execution.
//!
//! The automatic Agent listeners and user-facing command remain outside this
//! module. This layer turns one exact current Session surface into a durable
//! N76 compaction transaction.

use std::collections::{HashMap, HashSet};

use futures_util::StreamExt;

use crate::compaction::{
    COMPACTION_CHECKPOINT_PLUGIN, CompactionCheckpoint, CompactionId, CompactionRegion,
    CompactionResult, CompactionSummaryDraft, tool_pairing_balanced_before,
};
use crate::context::{Context, CordisError};
use crate::fiber::LifecycleCancellation;
use crate::session::{
    SessionCallConfig, SessionCancelCause, SessionContentBlock, SessionEpochHeader, SessionError,
    SessionEvent, SessionEventKind, SessionFinishReason, SessionHandle, SessionId, SessionMessage,
    SessionMessageRole, SessionMessageSource, SessionStreamBlockType, SessionStreamChunk,
    SessionSurface, SessionTokenUsage,
};
use crate::surface::{LlmGenerateRequest, LlmRequestPurpose, stream_llm_request};

pub const DEFAULT_COMPACTION_THRESHOLD_RATIO: f64 = 0.8;
pub const DEFAULT_RETAIN_RATIO: f64 = 0.16;
pub const DEFAULT_SUMMARY_MAX_TOKENS: u64 = 8_192;
pub const DEFAULT_COMPACTION_RETRIES: u64 = 1;
pub const DEFAULT_MAX_OVERFLOW_RETRIES: u64 = 1;

pub const SUMMARY_OPEN_TAG: &str = "<compacted-summary>";
pub const SUMMARY_CLOSE_TAG: &str = "</compacted-summary>";

pub const CHECKPOINT_PREAMBLE: &str = "This is an automatically generated checkpoint condensing an earlier span of the conversation to free up context. Treat the captured context as established background and build on it without restating it. Continue the task directly from the messages that follow, without acknowledging this checkpoint.";

pub const COMPACTION_INSTRUCTION: &str = concat!(
    "You are now acting as a compaction engine for this AI coding assistant. Condense the conversation ABOVE into a structured checkpoint that lets another model resume the work with no loss of essential context.\n",
    "\n",
    "Output EXACTLY the Markdown structure below: keep every section, in order. Use terse bullets, not prose paragraphs. Write \"(none)\" for an empty section — never drop a section.\n",
    "\n",
    "## Primary Request and Intent\n",
    "- [the user's original and evolving goals; quote verbatim where the exact wording matters]\n",
    "\n",
    "## Key Technical Concepts\n",
    "- [technologies, frameworks, patterns, and conventions in play]\n",
    "\n",
    "## Files and Code\n",
    "- [exact path: why it matters, key changes or snippets]\n",
    "\n",
    "## Errors and Fixes\n",
    "- [error: how it was resolved, plus any related user feedback]\n",
    "\n",
    "## Pending Jobs\n",
    "- [explicitly requested work not yet completed]\n",
    "\n",
    "## Current Work\n",
    "- [precisely what was in progress at this checkpoint]\n",
    "\n",
    "## Next Step\n",
    "- [the single next action, directly in line with the most recent request, or \"(none)\"]\n",
    "\n",
    "## Critical Context\n",
    "- [decisions and their rationale, constraints, user preferences, open questions, data needed to continue]\n",
    "\n",
    "Rules:\n",
    "- Write concise English engineering prose. Preserve exact file paths, commands, error strings, identifiers, numeric values, function signatures, and syntax fragments.\n",
    "- Capture user feedback and explicit instructions faithfully, especially corrections.\n",
    "- Do NOT mention this summarization request or that the context was compacted.\n",
    "- Output only the checkpoint text: do not call any tool or take any other action.\n",
    "- If the conversation already contains a <compacted-summary> block, it is a PRIOR checkpoint. Do not copy it forward verbatim: preserve still-true facts, drop stale ones, and merge newer information into a single consolidated summary under the same structure.",
);

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactionPolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summarization_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summarization_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction_retries: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_overflow_retries: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_policies: Vec<ModelCompactionPolicyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelCompactionPolicyConfig {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summarization_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summarization_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction_retries: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_overflow_retries: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompactionRetention {
    Ratio(f64),
    Tokens(u64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedCompactionConfig {
    pub threshold_ratio: f64,
    pub retention: CompactionRetention,
    pub summarization_provider: String,
    pub summarization_model: String,
    pub max_tokens: u64,
    pub compaction_retries: u64,
    pub max_overflow_retries: u64,
    pub model_policies: Vec<ModelCompactionPolicyConfig>,
    pub auto: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionTarget {
    pub provider: String,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedCompactionPolicy {
    pub target: CompactionTarget,
    pub threshold_ratio: f64,
    pub retention: CompactionRetention,
    pub summarization_provider: String,
    pub summarization_model: String,
    pub max_tokens: u64,
    pub compaction_retries: u64,
    pub max_overflow_retries: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedCompactionSpec {
    pub policy: ResolvedCompactionPolicy,
    pub context_window: u64,
    pub threshold_tokens: u64,
    pub retain_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionNodeMeasurement {
    pub seq: u64,
    pub tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionMeasurement {
    pub header_tokens: u64,
    pub surface_tokens: u64,
    pub total_tokens: u64,
    pub nodes: Vec<CompactionNodeMeasurement>,
    pub surface: SessionSurface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionTrigger {
    Pressure,
    Overflow,
    Manual,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompactionPlan {
    pub trigger: CompactionTrigger,
    pub session_id: SessionId,
    pub surface: SessionSurface,
    pub measurement: CompactionMeasurement,
    pub region: CompactionRegion,
    pub selected_messages: Vec<SessionMessage>,
    pub shadowed_token_count: u64,
    pub retained_tokens: u64,
    pub threshold_tokens: Option<u64>,
    pub conversation_target: CompactionTarget,
    pub summarization_target: CompactionTarget,
    pub system: Option<String>,
    pub tools: Vec<crate::session::SessionToolSchema>,
    pub max_tokens: u64,
    pub compaction_retries: u64,
    pub max_overflow_retries: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCompactionSummary {
    pub draft: CompactionSummaryDraft,
    pub checkpoint: CompactionCheckpoint,
    pub replacement_tokens: u64,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum CompactionPolicyError {
    #[error("compaction policy {scope} must have {expected}")]
    InvalidConfig {
        scope: String,
        expected: &'static str,
    },
    #[error("compaction policy has a duplicate exact target {provider}/{model}")]
    DuplicateTarget { provider: String, model: String },
    #[error("compaction requires a latest request header")]
    MissingRequestHeader,
    #[error("compaction request route changed from {header} to {context}")]
    RequestRouteMismatch { header: String, context: String },
    #[error("compaction pressure policy requires a positive context window for {target}")]
    MissingContextWindow { target: String },
    #[error(
        "compaction retention ({retain_tokens}) must be below pressure threshold ({threshold_tokens}) for {target}"
    )]
    RetentionAtOrAboveThreshold {
        target: String,
        retain_tokens: u64,
        threshold_tokens: u64,
    },
    #[error("compaction token measurement does not match the current Session surface")]
    MeasurementSurfaceChanged,
    #[error("compaction planned Session {expected} does not match {actual}")]
    SessionMismatch {
        expected: SessionId,
        actual: SessionId,
    },
    #[error("compaction surface changed after it was planned")]
    SurfaceChanged,
    #[error("compaction was cancelled ({cause:?})")]
    Cancelled { cause: Option<SessionCancelCause> },
    #[error("compaction summary stream must have {expected}")]
    InvalidSummaryStream { expected: &'static str },
    #[error("compaction summary request failed ({code}): {message}")]
    SummaryRequestFailed { code: String, message: String },
    #[error("compaction summary was truncated at the token cap")]
    SummaryTruncated,
    #[error("compaction summary contains unsupported non-text output")]
    UnsupportedSummaryOutput,
    #[error("compaction summary produced no non-empty text")]
    EmptySummary,
    #[error(
        "compaction replacement ({replacement_tokens} tokens) is not smaller than its selected span ({shadowed_tokens} tokens)"
    )]
    SummaryNotSmaller {
        replacement_tokens: u64,
        shadowed_tokens: u64,
    },
    #[error("compaction failure {failure} could not close its durable lease: {close}")]
    CloseAfterFailure { failure: String, close: String },
    #[error(transparent)]
    Cordis(#[from] CordisError),
    #[error(transparent)]
    Session(#[from] SessionError),
}

pub fn resolve_compaction_config(
    config: CompactionPolicyConfig,
) -> Result<ResolvedCompactionConfig, CompactionPolicyError> {
    validate_policy_fields(
        "defaults",
        config.threshold_ratio,
        config.retain_ratio,
        config.retain_tokens,
        config.summarization_provider.as_deref(),
        config.summarization_model.as_deref(),
        config.max_tokens,
    )?;
    let threshold_ratio = config
        .threshold_ratio
        .unwrap_or(DEFAULT_COMPACTION_THRESHOLD_RATIO);
    let retention = resolve_retention(
        config.retain_ratio,
        config.retain_tokens,
        CompactionRetention::Ratio(DEFAULT_RETAIN_RATIO),
    );
    validate_ratio_retention("defaults", threshold_ratio, retention)?;

    let mut targets = HashSet::with_capacity(config.model_policies.len());
    for (index, policy) in config.model_policies.iter().enumerate() {
        let scope = format!("modelPolicies[{index}]");
        if policy.provider.is_empty() || policy.model.is_empty() {
            return Err(invalid_config(scope, "a non-empty provider and model"));
        }
        validate_policy_fields(
            &scope,
            policy.threshold_ratio,
            policy.retain_ratio,
            policy.retain_tokens,
            policy.summarization_provider.as_deref(),
            policy.summarization_model.as_deref(),
            policy.max_tokens,
        )?;
        let key = (policy.provider.clone(), policy.model.clone());
        if !targets.insert(key) {
            return Err(CompactionPolicyError::DuplicateTarget {
                provider: policy.provider.clone(),
                model: policy.model.clone(),
            });
        }
        let effective_threshold = policy.threshold_ratio.unwrap_or(threshold_ratio);
        let effective_retention =
            resolve_retention(policy.retain_ratio, policy.retain_tokens, retention);
        validate_ratio_retention(&scope, effective_threshold, effective_retention)?;
    }

    Ok(ResolvedCompactionConfig {
        threshold_ratio,
        retention,
        summarization_provider: config.summarization_provider.unwrap_or_default(),
        summarization_model: config.summarization_model.unwrap_or_default(),
        max_tokens: config.max_tokens.unwrap_or(DEFAULT_SUMMARY_MAX_TOKENS),
        compaction_retries: config
            .compaction_retries
            .unwrap_or(DEFAULT_COMPACTION_RETRIES),
        max_overflow_retries: config
            .max_overflow_retries
            .unwrap_or(DEFAULT_MAX_OVERFLOW_RETRIES),
        model_policies: config.model_policies,
        auto: config.auto.unwrap_or(true),
    })
}

#[must_use]
pub fn resolve_compaction_policy(
    config: &ResolvedCompactionConfig,
    target: CompactionTarget,
) -> ResolvedCompactionPolicy {
    let policy = config
        .model_policies
        .iter()
        .find(|policy| policy.provider == target.provider && policy.model == target.model);
    let summarization_pair = policy.and_then(|policy| {
        policy
            .summarization_provider
            .as_ref()
            .zip(policy.summarization_model.as_ref())
    });
    ResolvedCompactionPolicy {
        target,
        threshold_ratio: policy
            .and_then(|policy| policy.threshold_ratio)
            .unwrap_or(config.threshold_ratio),
        retention: policy.map_or(config.retention, |policy| {
            resolve_retention(policy.retain_ratio, policy.retain_tokens, config.retention)
        }),
        summarization_provider: summarization_pair.map_or_else(
            || config.summarization_provider.clone(),
            |(provider, _)| provider.clone(),
        ),
        summarization_model: summarization_pair.map_or_else(
            || config.summarization_model.clone(),
            |(_, model)| model.clone(),
        ),
        max_tokens: policy
            .and_then(|policy| policy.max_tokens)
            .unwrap_or(config.max_tokens),
        compaction_retries: policy
            .and_then(|policy| policy.compaction_retries)
            .unwrap_or(config.compaction_retries),
        max_overflow_retries: policy
            .and_then(|policy| policy.max_overflow_retries)
            .unwrap_or(config.max_overflow_retries),
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
pub fn resolve_compaction_spec(
    policy: ResolvedCompactionPolicy,
    context_window: u64,
) -> Result<ResolvedCompactionSpec, CompactionPolicyError> {
    let target = target_key(&policy.target);
    if context_window == 0 {
        return Err(CompactionPolicyError::MissingContextWindow { target });
    }
    let threshold_tokens = ((context_window as f64) * policy.threshold_ratio).floor() as u64;
    let retain_tokens = match policy.retention {
        CompactionRetention::Ratio(ratio) => ((context_window as f64) * ratio).floor() as u64,
        CompactionRetention::Tokens(tokens) => tokens,
    };
    if retain_tokens >= threshold_tokens {
        return Err(CompactionPolicyError::RetentionAtOrAboveThreshold {
            target,
            retain_tokens,
            threshold_tokens,
        });
    }
    Ok(ResolvedCompactionSpec {
        policy,
        context_window,
        threshold_tokens,
        retain_tokens,
    })
}

#[must_use]
pub fn estimate_content_tokens(blocks: &[SessionContentBlock]) -> u64 {
    blocks.iter().fold(0_u64, |tokens, block| {
        let block_tokens = match block {
            SessionContentBlock::Text { text } | SessionContentBlock::Reasoning { text } => {
                estimate_text(text).saturating_add(4)
            }
            SessionContentBlock::ToolCall {
                name, arguments, ..
            } => estimate_text(name)
                .saturating_add(estimate_text(arguments))
                .saturating_add(4),
            SessionContentBlock::ToolResult { content, .. } => {
                estimate_content_tokens(content).saturating_add(4)
            }
        };
        tokens.saturating_add(block_tokens)
    })
}

#[must_use]
pub fn estimate_message_tokens(message: &SessionMessage) -> u64 {
    estimate_content_tokens(&message.content).saturating_add(4)
}

pub fn measure_compaction_session(
    session: &SessionHandle,
) -> Result<CompactionMeasurement, CompactionPolicyError> {
    let surface = session.surface()?;
    let events = session.events()?;
    let header = session.request_header()?;
    let header_tokens = estimate_header_tokens(header.as_ref());
    let mut nodes = Vec::with_capacity(surface.nodes.len());
    let mut surface_tokens = 0_u64;
    for seq in &surface.nodes {
        let event = event_at(&events, *seq)?;
        let message =
            surface_message(event).ok_or(SessionError::CompactionSurfaceCorrupt { seq: *seq })?;
        let tokens = estimate_message_tokens(message);
        surface_tokens = surface_tokens.saturating_add(tokens);
        nodes.push(CompactionNodeMeasurement { seq: *seq, tokens });
    }
    Ok(CompactionMeasurement {
        header_tokens,
        surface_tokens,
        total_tokens: header_tokens.saturating_add(surface_tokens),
        nodes,
        surface,
    })
}

pub fn select_compactable_range(
    session: &SessionHandle,
    measurement: &CompactionMeasurement,
    retain_tokens: u64,
) -> Result<Option<CompactionRegion>, CompactionPolicyError> {
    let current = session.surface()?;
    if current != measurement.surface
        || current.nodes.len() != measurement.nodes.len()
        || current
            .nodes
            .iter()
            .zip(&measurement.nodes)
            .any(|(seq, measured)| *seq != measured.seq)
    {
        return Err(CompactionPolicyError::MeasurementSurfaceChanged);
    }
    if measurement.nodes.is_empty() {
        return Ok(None);
    }

    let mut accumulated = 0_u64;
    let mut keep_from = measurement.nodes.len();
    for index in (0..measurement.nodes.len()).rev() {
        accumulated = accumulated.saturating_add(measurement.nodes[index].tokens);
        keep_from = index;
        if accumulated >= retain_tokens {
            break;
        }
    }
    if keep_from == 0 {
        return Ok(None);
    }
    while keep_from > 0 && !tool_pairing_balanced_before(session, current.nodes[keep_from])? {
        keep_from -= 1;
    }
    if keep_from == 0 {
        return Ok(None);
    }
    Ok(Some(CompactionRegion {
        start: current.nodes[0],
        end: current.nodes[keep_from - 1],
        shadowed_seqs: current.nodes[..keep_from].to_vec(),
        surface_generation: current.replace_generation,
    }))
}

pub fn plan_compaction(
    session: &SessionHandle,
    config: &ResolvedCompactionConfig,
    trigger: CompactionTrigger,
) -> Result<Option<CompactionPlan>, CompactionPolicyError> {
    if trigger != CompactionTrigger::Manual && !config.auto {
        return Ok(None);
    }
    let header = session
        .request_header()?
        .ok_or(CompactionPolicyError::MissingRequestHeader)?;
    let conversation_target = CompactionTarget {
        provider: header.config.provider.clone(),
        model: header.config.model.clone(),
    };
    let context = session.request_context()?;
    if let Some(context) = &context {
        let context_target = CompactionTarget {
            provider: context.provider.clone(),
            model: context.model.clone(),
        };
        if context_target != conversation_target {
            return Err(CompactionPolicyError::RequestRouteMismatch {
                header: target_key(&conversation_target),
                context: target_key(&context_target),
            });
        }
    }
    let policy = resolve_compaction_policy(config, conversation_target.clone());
    let (threshold_tokens, retain_tokens) = if trigger == CompactionTrigger::Pressure {
        let context_window = context
            .and_then(|context| context.context_window)
            .filter(|window| *window > 0)
            .ok_or_else(|| CompactionPolicyError::MissingContextWindow {
                target: target_key(&conversation_target),
            })?;
        let spec = resolve_compaction_spec(policy.clone(), context_window)?;
        (Some(spec.threshold_tokens), spec.retain_tokens)
    } else {
        (None, 0)
    };

    let measurement = measure_compaction_session(session)?;
    if threshold_tokens.is_some_and(|threshold| measurement.total_tokens < threshold) {
        return Ok(None);
    }
    let Some(region) = select_compactable_range(session, &measurement, retain_tokens)? else {
        return Ok(None);
    };
    let events = session.events()?;
    let selected_messages = selected_messages(&events, &region.shadowed_seqs)?;
    let shadowed_token_count = measurement
        .nodes
        .iter()
        .take(region.shadowed_seqs.len())
        .fold(0_u64, |total, node| total.saturating_add(node.tokens));
    let summarization_target = if policy.summarization_provider.is_empty() {
        conversation_target.clone()
    } else {
        CompactionTarget {
            provider: policy.summarization_provider.clone(),
            model: policy.summarization_model.clone(),
        }
    };

    Ok(Some(CompactionPlan {
        trigger,
        session_id: session.id().clone(),
        surface: measurement.surface.clone(),
        measurement,
        region,
        selected_messages,
        shadowed_token_count,
        retained_tokens: retain_tokens,
        threshold_tokens,
        conversation_target,
        summarization_target,
        system: header.system,
        tools: header.tools.unwrap_or_default(),
        max_tokens: policy.max_tokens,
        compaction_retries: policy.compaction_retries,
        max_overflow_retries: policy.max_overflow_retries,
    }))
}

#[must_use]
pub fn frame_compaction_summary(summary: &[SessionContentBlock]) -> Vec<SessionContentBlock> {
    let mut framed = Vec::with_capacity(summary.len() + 2);
    framed.push(SessionContentBlock::Text {
        text: format!("{CHECKPOINT_PREAMBLE}\n\n{SUMMARY_OPEN_TAG}"),
    });
    framed.extend_from_slice(summary);
    framed.push(SessionContentBlock::Text {
        text: SUMMARY_CLOSE_TAG.into(),
    });
    framed
}

pub async fn summarize_compaction(
    ctx: &mut Context,
    plan: &CompactionPlan,
    compaction_id: &CompactionId,
    cancellation: LifecycleCancellation,
) -> Result<PreparedCompactionSummary, CompactionPolicyError> {
    require_not_cancelled(&cancellation)?;
    let request = build_summary_request(plan, compaction_id, cancellation.clone());
    let (raw_output, usage, finish) = collect_summary_stream(ctx, request, &cancellation).await?;
    prepare_summary_output(plan, compaction_id, raw_output, usage, finish)
}

fn build_summary_request(
    plan: &CompactionPlan,
    compaction_id: &CompactionId,
    cancellation: LifecycleCancellation,
) -> LlmGenerateRequest {
    let instruction = SessionMessage {
        id: format!("compaction-instruction-{compaction_id}"),
        role: SessionMessageRole::User,
        content: vec![SessionContentBlock::Text {
            text: COMPACTION_INSTRUCTION.into(),
        }],
        source: SessionMessageSource::Plugin {
            plugin: "dsh-compaction-basic".into(),
            compaction_id: None,
            source_command_id: None,
        },
    };
    let mut messages = plan.selected_messages.clone();
    messages.push(instruction);
    LlmGenerateRequest::new(
        SessionCallConfig {
            provider: plan.summarization_target.provider.clone(),
            model: plan.summarization_target.model.clone(),
            reasoning_effort: None,
            temperature: None,
            max_tokens: Some(plan.max_tokens),
            stop: None,
        },
        messages,
    )
    .with_system(plan.system.clone())
    .with_tools(plan.tools.clone())
    .with_session_id(plan.session_id.clone())
    .with_purpose(LlmRequestPurpose::Compaction)
    .with_cancellation(cancellation)
}

async fn collect_summary_stream(
    ctx: &mut Context,
    request: LlmGenerateRequest,
    cancellation: &LifecycleCancellation,
) -> Result<
    (
        Vec<SessionContentBlock>,
        Option<SessionTokenUsage>,
        SessionFinishReason,
    ),
    CompactionPolicyError,
> {
    let mut stream = stream_llm_request(ctx, request)?;
    let mut assembler = SummaryAssembler::default();
    loop {
        let next_chunk = stream.next();
        let cancelled = cancellation.cancelled();
        futures_util::pin_mut!(next_chunk, cancelled);
        match futures_util::future::select(cancelled, next_chunk).await {
            futures_util::future::Either::Left(_) => {
                return Err(CompactionPolicyError::Cancelled {
                    cause: cancellation.cause(),
                });
            }
            futures_util::future::Either::Right((Some(chunk), _)) => assembler.push(chunk)?,
            futures_util::future::Either::Right((None, _)) => break,
        }
    }
    require_not_cancelled(cancellation)?;
    assembler.finish()
}

fn prepare_summary_output(
    plan: &CompactionPlan,
    compaction_id: &CompactionId,
    raw_output: Vec<SessionContentBlock>,
    usage: Option<SessionTokenUsage>,
    finish: SessionFinishReason,
) -> Result<PreparedCompactionSummary, CompactionPolicyError> {
    match finish {
        SessionFinishReason::Error { failure } | SessionFinishReason::Aborted { failure } => {
            return Err(CompactionPolicyError::SummaryRequestFailed {
                code: failure.code,
                message: failure.message,
            });
        }
        SessionFinishReason::MaxTokens => {
            return Err(CompactionPolicyError::SummaryTruncated);
        }
        SessionFinishReason::Stop | SessionFinishReason::ToolCalls => {}
    }

    let mut summary = Vec::new();
    for block in &raw_output {
        match block {
            SessionContentBlock::Text { .. } => summary.push(block.clone()),
            SessionContentBlock::Reasoning { .. } => {}
            SessionContentBlock::ToolCall { .. } | SessionContentBlock::ToolResult { .. } => {
                return Err(CompactionPolicyError::UnsupportedSummaryOutput);
            }
        }
    }
    if !summary
        .iter()
        .any(|block| matches!(block, SessionContentBlock::Text { text } if !text.trim().is_empty()))
    {
        return Err(CompactionPolicyError::EmptySummary);
    }
    let checkpoint = CompactionCheckpoint {
        message_id: format!("compaction-checkpoint-{compaction_id}"),
        content: frame_compaction_summary(&summary),
    };
    let replacement_tokens = estimate_message_tokens(&SessionMessage {
        id: checkpoint.message_id.clone(),
        role: SessionMessageRole::User,
        content: checkpoint.content.clone(),
        source: SessionMessageSource::Plugin {
            plugin: COMPACTION_CHECKPOINT_PLUGIN.into(),
            compaction_id: Some(compaction_id.clone()),
            source_command_id: None,
        },
    });
    if replacement_tokens >= plan.shadowed_token_count {
        return Err(CompactionPolicyError::SummaryNotSmaller {
            replacement_tokens,
            shadowed_tokens: plan.shadowed_token_count,
        });
    }
    Ok(PreparedCompactionSummary {
        draft: CompactionSummaryDraft {
            summary,
            shadowed_token_count: plan.shadowed_token_count,
            provider: plan.summarization_target.provider.clone(),
            model: plan.summarization_target.model.clone(),
            max_tokens: Some(plan.max_tokens),
            usage,
            raw_output: Some(raw_output),
            llm_stream_call: true,
        },
        checkpoint,
        replacement_tokens,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_compaction_plan(
    ctx: &mut Context,
    session: &SessionHandle,
    plan: &CompactionPlan,
    compaction_id: CompactionId,
    source_command_id: Option<String>,
    turn: Option<u64>,
    cancellation: LifecycleCancellation,
) -> Result<CompactionResult, CompactionPolicyError> {
    if session.id() != &plan.session_id {
        return Err(CompactionPolicyError::SessionMismatch {
            expected: plan.session_id.clone(),
            actual: session.id().clone(),
        });
    }
    require_not_cancelled(&cancellation)?;
    require_surface(session, &plan.surface)?;
    let lease = session.begin_compaction(
        compaction_id.clone(),
        source_command_id,
        turn,
        plan.region.start,
        plan.region.end,
    )?;
    let prepared = match summarize_compaction(ctx, plan, &compaction_id, cancellation.clone()).await
    {
        Ok(prepared) => prepared,
        Err(error) => return close_failed_compaction(session, &lease, error),
    };
    if let Err(error) =
        require_not_cancelled(&cancellation).and_then(|()| require_surface(session, &plan.surface))
    {
        return close_failed_compaction(session, &lease, error);
    }
    match session.complete_compaction(&lease, prepared.draft, prepared.checkpoint) {
        Ok(result) => Ok(result),
        Err(error) => close_failed_compaction(session, &lease, error.into()),
    }
}

fn validate_policy_fields(
    scope: &str,
    threshold_ratio: Option<f64>,
    retain_ratio: Option<f64>,
    retain_tokens: Option<u64>,
    summarization_provider: Option<&str>,
    summarization_model: Option<&str>,
    max_tokens: Option<u64>,
) -> Result<(), CompactionPolicyError> {
    if threshold_ratio.is_some_and(|ratio| !valid_ratio(ratio)) {
        return Err(invalid_config(
            scope,
            "a threshold ratio in the interval (0, 1]",
        ));
    }
    if retain_ratio.is_some_and(|ratio| !valid_ratio(ratio)) {
        return Err(invalid_config(
            scope,
            "a retain ratio in the interval (0, 1]",
        ));
    }
    if retain_ratio.is_some() && retain_tokens.is_some() {
        return Err(invalid_config(
            scope,
            "only one of retain ratio and retain tokens",
        ));
    }
    if max_tokens == Some(0) {
        return Err(invalid_config(scope, "a positive summary token cap"));
    }
    match (summarization_provider, summarization_model) {
        (None, None) => {}
        (Some(provider), Some(model)) if provider.is_empty() == model.is_empty() => {}
        _ => {
            return Err(invalid_config(
                scope,
                "a jointly empty or jointly non-empty summary provider/model pair",
            ));
        }
    }
    Ok(())
}

fn validate_ratio_retention(
    scope: &str,
    threshold_ratio: f64,
    retention: CompactionRetention,
) -> Result<(), CompactionPolicyError> {
    if matches!(retention, CompactionRetention::Ratio(ratio) if ratio >= threshold_ratio) {
        return Err(invalid_config(
            scope,
            "a retain ratio below the resolved threshold ratio",
        ));
    }
    Ok(())
}

const fn valid_ratio(ratio: f64) -> bool {
    ratio.is_finite() && ratio > 0.0 && ratio <= 1.0
}

const fn resolve_retention(
    retain_ratio: Option<f64>,
    retain_tokens: Option<u64>,
    fallback: CompactionRetention,
) -> CompactionRetention {
    if let Some(tokens) = retain_tokens {
        CompactionRetention::Tokens(tokens)
    } else if let Some(ratio) = retain_ratio {
        CompactionRetention::Ratio(ratio)
    } else {
        fallback
    }
}

fn invalid_config(scope: impl Into<String>, expected: &'static str) -> CompactionPolicyError {
    CompactionPolicyError::InvalidConfig {
        scope: scope.into(),
        expected,
    }
}

fn estimate_text(text: &str) -> u64 {
    u64::try_from(text.encode_utf16().count())
        .unwrap_or(u64::MAX)
        .div_ceil(4)
}

fn estimate_header_tokens(header: Option<&SessionEpochHeader>) -> u64 {
    let Some(header) = header else {
        return 0;
    };
    let system = header
        .system
        .as_deref()
        .map_or(0, |system| estimate_text(system).saturating_add(4));
    let tools = header.tools.as_ref().map_or(0, |tools| {
        serde_json::to_string(tools).map_or(u64::MAX, |encoded| {
            estimate_text(&encoded).saturating_add(4)
        })
    });
    system.saturating_add(tools)
}

fn event_at(events: &[SessionEvent], seq: u64) -> Result<&SessionEvent, SessionError> {
    usize::try_from(seq)
        .ok()
        .and_then(|index| events.get(index))
        .filter(|event| event.seq == seq)
        .ok_or(SessionError::CompactionSurfaceCorrupt { seq })
}

const fn surface_message(event: &SessionEvent) -> Option<&SessionMessage> {
    match &event.kind {
        SessionEventKind::UserMessage { message, .. }
        | SessionEventKind::AssistantMessage { message, .. }
        | SessionEventKind::ToolResult { message, .. } => Some(message),
        SessionEventKind::TurnStart { .. }
        | SessionEventKind::TurnEnd { .. }
        | SessionEventKind::StepStart { .. }
        | SessionEventKind::StepEnd { .. }
        | SessionEventKind::AgentInboxSpliced { .. }
        | SessionEventKind::AssistantChunk { .. }
        | SessionEventKind::RequestHeader { .. }
        | SessionEventKind::RequestContext { .. }
        | SessionEventKind::ApprovalAsked { .. }
        | SessionEventKind::ApprovalDecided { .. }
        | SessionEventKind::ApprovalPolicy { .. }
        | SessionEventKind::LlmRetry { .. }
        | SessionEventKind::LlmRetryStarted { .. }
        | SessionEventKind::CompactionStart { .. }
        | SessionEventKind::CompactionSummary { .. }
        | SessionEventKind::CompactionEnd { .. }
        | SessionEventKind::ToolCall { .. } => None,
    }
}

fn selected_messages(
    events: &[SessionEvent],
    selected: &[u64],
) -> Result<Vec<SessionMessage>, CompactionPolicyError> {
    let mut messages = Vec::with_capacity(selected.len());
    for seq in selected {
        let event = event_at(events, *seq)?;
        let message =
            surface_message(event).ok_or(SessionError::CompactionSurfaceCorrupt { seq: *seq })?;
        if message.role != SessionMessageRole::Assistant || !message.content.is_empty() {
            messages.push(message.clone());
        }
    }
    Ok(messages)
}

fn target_key(target: &CompactionTarget) -> String {
    format!("{}/{}", target.provider, target.model)
}

fn require_not_cancelled(
    cancellation: &LifecycleCancellation,
) -> Result<(), CompactionPolicyError> {
    if cancellation.is_cancelled() {
        Err(CompactionPolicyError::Cancelled {
            cause: cancellation.cause(),
        })
    } else {
        Ok(())
    }
}

fn require_surface(
    session: &SessionHandle,
    expected: &SessionSurface,
) -> Result<(), CompactionPolicyError> {
    if &session.surface()? == expected {
        Ok(())
    } else {
        Err(CompactionPolicyError::SurfaceChanged)
    }
}

fn close_failed_compaction(
    session: &SessionHandle,
    lease: &crate::compaction::CompactionLease,
    error: CompactionPolicyError,
) -> Result<CompactionResult, CompactionPolicyError> {
    match session.fail_compaction(lease, error.to_string()) {
        Ok(_) => Err(error),
        Err(close) => Err(CompactionPolicyError::CloseAfterFailure {
            failure: error.to_string(),
            close: close.to_string(),
        }),
    }
}

#[derive(Default)]
struct SummaryAssembler {
    order: Vec<u64>,
    blocks: HashMap<u64, (SessionStreamBlockType, Option<SessionContentBlock>)>,
    usage: Option<SessionTokenUsage>,
    finish: Option<SessionFinishReason>,
}

impl SummaryAssembler {
    fn push(&mut self, chunk: SessionStreamChunk) -> Result<(), CompactionPolicyError> {
        if self.finish.is_some() {
            return Err(invalid_summary_stream(
                "no chunks after the terminal finish",
            ));
        }
        match chunk {
            SessionStreamChunk::BlockStart { index, block_type } => {
                validate_summary_index(index)?;
                if self.blocks.contains_key(&index) {
                    return Err(invalid_summary_stream("one block start per index"));
                }
                self.order.push(index);
                self.blocks.insert(index, (block_type, None));
            }
            SessionStreamChunk::TextDelta { index, .. } => {
                self.require_open(index, SessionStreamBlockType::Text)?;
            }
            SessionStreamChunk::ReasoningDelta { index, .. } => {
                self.require_open(index, SessionStreamBlockType::Reasoning)?;
            }
            SessionStreamChunk::ToolCallDelta { index, .. } => {
                self.require_open(index, SessionStreamBlockType::ToolCall)?;
            }
            SessionStreamChunk::BlockEnd { index, block } => {
                validate_summary_index(index)?;
                let actual = summary_block_type(&block)
                    .ok_or_else(|| invalid_summary_stream("a model-output block type"))?;
                let Some((expected, completed)) = self.blocks.get_mut(&index) else {
                    return Err(invalid_summary_stream("block-end to target an open block"));
                };
                if *expected != actual || completed.is_some() {
                    return Err(invalid_summary_stream(
                        "one matching block-end for each open block",
                    ));
                }
                *completed = Some(block);
            }
            SessionStreamChunk::Usage { usage } => {
                if self.usage.replace(usage).is_some() {
                    return Err(invalid_summary_stream("at most one usage chunk"));
                }
            }
            SessionStreamChunk::Finish { reason, .. } => {
                if !matches!(
                    reason,
                    SessionFinishReason::Error { .. } | SessionFinishReason::Aborted { .. }
                ) && self.blocks.values().any(|(_, block)| block.is_none())
                {
                    return Err(invalid_summary_stream(
                        "successful finish after every block closes",
                    ));
                }
                self.finish = Some(reason);
            }
        }
        Ok(())
    }

    fn require_open(
        &self,
        index: u64,
        expected: SessionStreamBlockType,
    ) -> Result<(), CompactionPolicyError> {
        validate_summary_index(index)?;
        if self
            .blocks
            .get(&index)
            .is_some_and(|(actual, completed)| *actual == expected && completed.is_none())
        {
            Ok(())
        } else {
            Err(invalid_summary_stream(
                "each delta to target its matching open block",
            ))
        }
    }

    fn finish(
        self,
    ) -> Result<
        (
            Vec<SessionContentBlock>,
            Option<SessionTokenUsage>,
            SessionFinishReason,
        ),
        CompactionPolicyError,
    > {
        let finish = self
            .finish
            .ok_or_else(|| invalid_summary_stream("exactly one terminal finish"))?;
        if matches!(
            finish,
            SessionFinishReason::Error { .. } | SessionFinishReason::Aborted { .. }
        ) {
            return Ok((Vec::new(), self.usage, finish));
        }
        let mut blocks = Vec::with_capacity(self.order.len());
        for index in self.order {
            let block = self
                .blocks
                .get(&index)
                .and_then(|(_, block)| block.clone())
                .ok_or_else(|| {
                    invalid_summary_stream("every successful block to close exactly once")
                })?;
            blocks.push(block);
        }
        Ok((blocks, self.usage, finish))
    }
}

fn validate_summary_index(index: u64) -> Result<(), CompactionPolicyError> {
    if index <= 9_007_199_254_740_991 {
        Ok(())
    } else {
        Err(invalid_summary_stream(
            "block indexes within the JavaScript safe-integer range",
        ))
    }
}

const fn summary_block_type(block: &SessionContentBlock) -> Option<SessionStreamBlockType> {
    match block {
        SessionContentBlock::Text { .. } => Some(SessionStreamBlockType::Text),
        SessionContentBlock::Reasoning { .. } => Some(SessionStreamBlockType::Reasoning),
        SessionContentBlock::ToolCall { .. } => Some(SessionStreamBlockType::ToolCall),
        SessionContentBlock::ToolResult { .. } => None,
    }
}

const fn invalid_summary_stream(expected: &'static str) -> CompactionPolicyError {
    CompactionPolicyError::InvalidSummaryStream { expected }
}
