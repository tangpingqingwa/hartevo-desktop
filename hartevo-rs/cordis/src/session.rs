//! Minimal Rust-native Session boundary log adapted from DeepSeek Harness.
//!
//! This slice records and validates turn/step lifecycle, request state, raw
//! assistant stream chunks, tool-call identities, and the three durable message
//! events that form model history. Its ordered surface can append or replace
//! model-visible nodes without deleting the source log, and it exposes the
//! typed event/flush seam consumed by persistence plugins. The wider Harness
//! vocabulary remains separate follow-up work.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;

use crate::context::EventReentry;
use crate::event::{Emit, EventKey, EventSchemaId, Parallel};
use crate::inbox::{
    AgentInbox, AgentInboxOutcome, AgentInboxState, AgentInboxTarget, validate_agent_inbox_event,
};

/// The Rust Session format written by this bounded implementation.
pub const SESSION_FORMAT_VERSION: u32 = 0;

/// Recovery code for an assistant tool request that never reached a durable call start.
pub const TOOL_NOT_STARTED: &str = "TOOL_NOT_STARTED";

/// Recovery code for a durable tool call whose outcome was not durably recorded.
pub const TOOL_OUTCOME_UNKNOWN: &str = "TOOL_OUTCOME_UNKNOWN";

const TOOL_NOT_STARTED_MESSAGE: &str = "The tool call was interrupted before the Harness recorded it as started. Retry it if it is still needed.";
const TOOL_OUTCOME_UNKNOWN_MESSAGE: &str = "The tool call was interrupted after it was recorded, but no result was durably recorded. Its outcome is unknown. Decide whether to retry from the tool semantics: retry only if the operation is read-only or idempotent; if it may have side effects, first verify external state or ask the user. Do not retry blindly.";

/// Typed Cordis events forming the storage-agnostic Session persistence seam.
pub mod events {
    use super::{Emit, EventKey, EventSchemaId, Parallel, SessionCheckpoint, SessionEventRecord};

    /// One committed append, published only after it entered the live log.
    pub const SESSION_EVENT: EventKey<Emit, SessionEventRecord, ()> = EventKey::new(
        EventSchemaId::new("hartevo.session.event.v1"),
        "session/event",
    );
    /// Awaited durability checkpoint over one immutable Session prefix.
    pub const SESSION_FLUSH: EventKey<Parallel, SessionCheckpoint, ()> = EventKey::new(
        EventSchemaId::new("hartevo.session.flush.v1"),
        "session/flush",
    );
}

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

/// Provider-neutral call configuration retained in a request-header snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionCallConfig {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<serde_json::Number>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
}

/// Call-config fields supplied by exact adapter resolution.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionCallConfigAdapterDefaults {
    #[serde(default, skip_serializing_if = "is_false")]
    pub reasoning_effort: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub max_tokens: bool,
}

/// Lossless JSON Schema sent for one assembled tool.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionToolSchema {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Map<String, serde_json::Value>,
}

/// Full request state reconstructed from the latest header snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionEpochHeader {
    pub config: SessionCallConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_defaults: Option<SessionCallConfigAdapterDefaults>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<SessionToolSchema>>,
}

impl SessionEpochHeader {
    fn canonicalized(mut self) -> Self {
        if self
            .adapter_defaults
            .as_ref()
            .is_some_and(|defaults| !defaults.reasoning_effort && !defaults.max_tokens)
        {
            self.adapter_defaults = None;
        }
        if self.system.as_ref().is_some_and(String::is_empty) {
            self.system = None;
        }
        if self.tools.as_ref().is_some_and(Vec::is_empty) {
            self.tools = None;
        }
        self
    }
}

/// Why a complete request-header snapshot was appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionRequestHeaderReason {
    Initial,
    Resume,
    Change,
    Series,
}

/// One canonical, complete request-header event payload.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionRequestHeader {
    pub header: SessionEpochHeader,
    pub reason: SessionRequestHeaderReason,
    #[serde(default, skip_serializing_if = "is_false")]
    pub starts_series: bool,
}

impl SessionRequestHeader {
    fn canonicalized(mut self) -> Self {
        self.header = self.header.canonicalized();
        self
    }

    /// Encode one canonical snapshot for a neutral persistence adapter.
    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        serde_json::to_value(self.clone().canonicalized())
            .map_err(|_| SessionError::InvalidRequestHeaderEncoding)
    }

    /// Decode an exact current snapshot, rejecting lossy and legacy shapes.
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let request: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidRequestHeaderEncoding)?;
        let request = request.canonicalized();
        if request.to_json_value()?.ne(value) {
            return Err(SessionError::InvalidRequestHeaderEncoding);
        }
        validate_request_header(&request)?;
        Ok(request)
    }
}

/// Registered provider route metadata reconstructed from its latest event.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionRequestContext {
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window: Option<u64>,
}

impl SessionRequestContext {
    /// Encode exact route metadata for a neutral persistence adapter.
    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        serde_json::to_value(self).map_err(|_| SessionError::InvalidRequestContextEncoding)
    }

    /// Decode exact route metadata, rejecting unknown or non-canonical fields.
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let context: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidRequestContextEncoding)?;
        if context.to_json_value()?.ne(value) {
            return Err(SessionError::InvalidRequestContextEncoding);
        }
        validate_request_context(&context)?;
        Ok(context)
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde skip predicates receive references.
const fn is_false(value: &bool) -> bool {
    !*value
}

/// Provider-neutral role carried by one durable Session message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMessageRole {
    User,
    Assistant,
}

/// Provenance required to replay one model-visible message.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionMessageSource {
    User,
    Plugin { plugin: String },
    Model { provider: String, model: String },
    Tool { call_id: String },
}

/// The bounded N22 content vocabulary needed for text and tool-history replay.
#[derive(Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionContentBlock {
    Text {
        text: String,
    },
    Reasoning {
        text: String,
    },
    ToolCall {
        id: String,
        name: String,
        arguments: String,
    },
    ToolResult {
        tool_call_id: String,
        content: Vec<Self>,
        is_error: bool,
    },
}

impl fmt::Debug for SessionContentBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text { text } => formatter
                .debug_struct("Text")
                .field("bytes", &text.len())
                .finish(),
            Self::Reasoning { text } => formatter
                .debug_struct("Reasoning")
                .field("bytes", &text.len())
                .finish(),
            Self::ToolCall {
                id,
                name,
                arguments,
            } => formatter
                .debug_struct("ToolCall")
                .field("id", id)
                .field("name", name)
                .field("argument_bytes", &arguments.len())
                .finish(),
            Self::ToolResult {
                tool_call_id,
                content,
                is_error,
            } => formatter
                .debug_struct("ToolResult")
                .field("tool_call_id", tool_call_id)
                .field("content_blocks", &content.len())
                .field("is_error", is_error)
                .finish(),
        }
    }
}

/// Provider-neutral block kind opened by one assistant stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionStreamBlockType {
    Text,
    Reasoning,
    ToolCall,
}

/// Serializable provider or transport failure facts carried by a finish chunk.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionLlmFailure {
    pub message: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Why one provider stream stopped.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SessionFinishReason {
    Stop,
    ToolCalls,
    MaxTokens,
    Aborted { failure: SessionLlmFailure },
    Error { failure: SessionLlmFailure },
}

/// Disjoint token accounting for one provider call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionTokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
}

/// Adapter-private lossless JSON retained on a successful terminal chunk.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionReplayEnvelope {
    pub response: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<serde_json::Value>>,
}

/// Raw provider-neutral streaming vocabulary retained for token-level replay.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SessionStreamChunk {
    BlockStart {
        index: u64,
        #[serde(rename = "blockType")]
        block_type: SessionStreamBlockType,
    },
    TextDelta {
        index: u64,
        text: String,
    },
    ReasoningDelta {
        index: u64,
        text: String,
    },
    ToolCallDelta {
        index: u64,
        id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(rename = "argumentsDelta")]
        arguments_delta: String,
    },
    BlockEnd {
        index: u64,
        block: SessionContentBlock,
    },
    Usage {
        usage: SessionTokenUsage,
    },
    Finish {
        reason: SessionFinishReason,
        #[serde(
            rename = "replayState",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        replay_state: Option<SessionReplayEnvelope>,
    },
}

impl SessionStreamChunk {
    /// Encode one typed raw chunk for a neutral persistence adapter.
    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        serde_json::to_value(self).map_err(|_| SessionError::InvalidAssistantChunkEncoding)
    }

    /// Decode one exact neutral chunk shape before Session replay validates it.
    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let chunk: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidAssistantChunkEncoding)?;
        let canonical = chunk.to_json_value()?;
        if &canonical != value {
            return Err(SessionError::InvalidAssistantChunkEncoding);
        }
        Ok(chunk)
    }
}

/// Detached raw chunk record returned in authoritative Session order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAssistantChunk {
    pub seq: u64,
    pub time_ms: i64,
    pub turn: u64,
    pub step: u64,
    pub chunk: SessionStreamChunk,
}

/// Detached log-only tool invocation returned in authoritative Session order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToolCall {
    pub seq: u64,
    pub time_ms: i64,
    pub turn: u64,
    pub step: u64,
    pub call_id: String,
    pub name: String,
    /// Raw JSON string exactly as the model produced it; never parsed here.
    pub arguments: String,
}

/// Provider-neutral failure identity attached to one durable tool result.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionToolError {
    pub name: String,
    pub code: String,
}

/// One identified immutable message shared by durable history and replay.
#[derive(Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionMessage {
    pub id: String,
    pub role: SessionMessageRole,
    pub content: Vec<SessionContentBlock>,
    pub source: SessionMessageSource,
}

impl fmt::Debug for SessionMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMessage")
            .field("id", &self.id)
            .field("role", &self.role)
            .field("content_blocks", &self.content.len())
            .field("source", &self.source)
            .finish()
    }
}

impl SessionMessage {
    /// Encode one validated typed message for a neutral persistence adapter.
    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        serde_json::to_value(self).map_err(|_| SessionError::InvalidMessageEncoding)
    }

    /// Decode one neutral persistence value before Session replay validates it.
    pub fn from_json_value(value: serde_json::Value) -> Result<Self, SessionError> {
        serde_json::from_value(value).map_err(|_| SessionError::InvalidMessageEncoding)
    }
}

/// How one message-producing event enters the ordered model-visible surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionSurfaceOp {
    Append,
    Replace { start: u64, end: u64 },
}

/// Surface placement plus the complete known provenance for one message event.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionSurfaceIntent {
    pub surface_op: SessionSurfaceOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_event_seqs: Option<Vec<u64>>,
}

impl SessionSurfaceIntent {
    #[must_use]
    pub const fn append() -> Self {
        Self {
            surface_op: SessionSurfaceOp::Append,
            source_event_seqs: None,
        }
    }

    #[must_use]
    pub fn append_from(source_event_seqs: Vec<u64>) -> Self {
        Self {
            surface_op: SessionSurfaceOp::Append,
            source_event_seqs: Some(source_event_seqs),
        }
    }

    #[must_use]
    pub fn replace(start: u64, end: u64, source_event_seqs: Vec<u64>) -> Self {
        Self {
            surface_op: SessionSurfaceOp::Replace { start, end },
            source_event_seqs: Some(source_event_seqs),
        }
    }

    /// Encode validated typed surface metadata for a neutral persistence adapter.
    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        serde_json::to_value(self).map_err(|_| SessionError::InvalidSurfaceEncoding)
    }

    /// Decode neutral persistence metadata before Session replay validates it.
    pub fn from_json_value(value: serde_json::Value) -> Result<Self, SessionError> {
        if !surface_json_shape_is_exact(&value) {
            return Err(SessionError::InvalidSurfaceEncoding);
        }
        serde_json::from_value(value).map_err(|_| SessionError::InvalidSurfaceEncoding)
    }
}

fn surface_json_shape_is_exact(value: &serde_json::Value) -> bool {
    let Some(intent) = value.as_object() else {
        return false;
    };
    if !intent
        .keys()
        .all(|key| matches!(key.as_str(), "surfaceOp" | "sourceEventSeqs"))
        || !intent.contains_key("surfaceOp")
        || intent
            .get("sourceEventSeqs")
            .is_some_and(|sources| !sources.is_array())
    {
        return false;
    }
    let Some(operation) = intent
        .get("surfaceOp")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    match operation.get("op").and_then(serde_json::Value::as_str) {
        Some("append") => operation.len() == 1,
        Some("replace") => {
            operation.len() == 3 && operation.contains_key("start") && operation.contains_key("end")
        }
        _ => false,
    }
}

/// Detached ordered-surface state for inspection and exact replay assertions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSurface {
    pub nodes: Vec<u64>,
    pub replace_generation: u64,
}

/// The bounded Session event vocabulary through N37.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEventKind {
    TurnStart {
        turn: u64,
    },
    TurnEnd {
        turn: u64,
        reason: TurnEndReason,
    },
    StepStart {
        turn: u64,
        step: u64,
    },
    StepEnd {
        turn: u64,
        step: u64,
    },
    AgentInboxSpliced {
        target: AgentInboxTarget,
        start: u64,
        removed_count: Option<u64>,
        inserted: Vec<SessionMessage>,
        outcome: Option<AgentInboxOutcome>,
    },
    AssistantChunk {
        turn: u64,
        step: u64,
        chunk: SessionStreamChunk,
    },
    RequestHeader {
        request: SessionRequestHeader,
    },
    RequestContext {
        context: SessionRequestContext,
    },
    ToolCall {
        turn: u64,
        step: u64,
        call_id: String,
        name: String,
        arguments: String,
    },
    UserMessage {
        message: SessionMessage,
        surface: SessionSurfaceIntent,
    },
    AssistantMessage {
        turn: u64,
        step: u64,
        message: SessionMessage,
        surface: SessionSurfaceIntent,
    },
    ToolResult {
        turn: u64,
        step: u64,
        message: SessionMessage,
        error: Option<SessionToolError>,
        surface: SessionSurfaceIntent,
    },
}

impl SessionEventKind {
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::TurnStart { .. } => "turn/start",
            Self::TurnEnd { .. } => "turn/end",
            Self::StepStart { .. } => "step/start",
            Self::StepEnd { .. } => "step/end",
            Self::AgentInboxSpliced { .. } => "agent/inbox/spliced",
            Self::AssistantChunk { .. } => "assistant/chunk",
            Self::RequestHeader { .. } => "request/header",
            Self::RequestContext { .. } => "request/context",
            Self::ToolCall { .. } => "tool/call",
            Self::UserMessage { .. } => "user/message",
            Self::AssistantMessage { .. } => "assistant/message",
            Self::ToolResult { .. } => "tool/result",
        }
    }

    fn derived_message(&self) -> Option<&SessionMessage> {
        match self {
            Self::UserMessage { message, .. } | Self::ToolResult { message, .. } => Some(message),
            Self::AssistantMessage { message, .. } if !message.content.is_empty() => Some(message),
            Self::AssistantMessage { .. }
            | Self::TurnStart { .. }
            | Self::TurnEnd { .. }
            | Self::StepStart { .. }
            | Self::StepEnd { .. }
            | Self::AgentInboxSpliced { .. }
            | Self::AssistantChunk { .. }
            | Self::RequestHeader { .. }
            | Self::RequestContext { .. }
            | Self::ToolCall { .. } => None,
        }
    }

    fn surface_intent(&self) -> Option<&SessionSurfaceIntent> {
        match self {
            Self::UserMessage { surface, .. }
            | Self::AssistantMessage { surface, .. }
            | Self::ToolResult { surface, .. } => Some(surface),
            Self::TurnStart { .. }
            | Self::TurnEnd { .. }
            | Self::StepStart { .. }
            | Self::StepEnd { .. }
            | Self::AgentInboxSpliced { .. }
            | Self::AssistantChunk { .. }
            | Self::RequestHeader { .. }
            | Self::RequestContext { .. }
            | Self::ToolCall { .. } => None,
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

/// Detached notification for one event that is already committed in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEventRecord {
    pub header: SessionHeader,
    pub event: SessionEvent,
}

/// Immutable Session prefix presented to every durability listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCheckpoint {
    pub header: SessionHeader,
    pub events: Vec<SessionEvent>,
}

impl SessionCheckpoint {
    #[must_use]
    pub fn through_seq(&self) -> Option<u64> {
        self.events.last().map(|event| event.seq)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SessionState {
    last_turn: u64,
    open_turn: Option<u64>,
    last_step: u64,
    open_step: Option<u64>,
    pending_tool_calls: HashSet<String>,
}

impl SessionState {
    fn apply(&mut self, kind: &SessionEventKind) -> Result<(), SessionError> {
        match kind {
            SessionEventKind::TurnStart { turn } => {
                let turn = *turn;
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
                let turn = *turn;
                require_turn(self.open_turn, turn)?;
                if let Some(step) = self.open_step {
                    return Err(SessionError::StepStillOpen { turn, step });
                }
                self.open_turn = None;
            }
            SessionEventKind::StepStart { turn, step } => {
                let (turn, step) = (*turn, *step);
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
                let (turn, step) = (*turn, *step);
                require_turn(self.open_turn, turn)?;
                require_step(self.open_step, turn, step)?;
                self.pending_tool_calls.clear();
                self.open_step = None;
            }
            SessionEventKind::AgentInboxSpliced {
                removed_count,
                inserted,
                outcome,
                ..
            } => self.validate_inbox_splice(*removed_count, inserted, *outcome)?,
            SessionEventKind::AssistantChunk { turn, step, chunk } => {
                require_turn(self.open_turn, *turn)?;
                require_step(self.open_step, *turn, *step)?;
                validate_assistant_chunk(chunk)?;
            }
            SessionEventKind::RequestHeader { request } => {
                require_open_turn(self.open_turn)?;
                validate_request_header(request)?;
            }
            SessionEventKind::RequestContext { context } => {
                require_open_turn(self.open_turn)?;
                validate_request_context(context)?;
            }
            SessionEventKind::ToolCall {
                turn,
                step,
                call_id,
                name,
                ..
            } => self.apply_tool_call(*turn, *step, call_id, name)?,
            SessionEventKind::ToolResult {
                message,
                error,
                surface,
                ..
            } => self.apply_tool_result(kind, message, error.as_ref(), surface)?,
            SessionEventKind::UserMessage { .. } | SessionEventKind::AssistantMessage { .. } => {
                self.validate_message_event(kind)?;
            }
        }
        Ok(())
    }

    fn apply_tool_call(
        &mut self,
        turn: u64,
        step: u64,
        call_id: &str,
        name: &str,
    ) -> Result<(), SessionError> {
        require_turn(self.open_turn, turn)?;
        require_step(self.open_step, turn, step)?;
        if call_id.is_empty() || name.is_empty() {
            return Err(SessionError::InvalidToolCall {
                expected: "non-empty call id and name",
            });
        }
        self.pending_tool_calls.insert(call_id.to_owned());
        Ok(())
    }

    fn validate_inbox_splice(
        &self,
        removed_count: Option<u64>,
        inserted: &[SessionMessage],
        outcome: Option<AgentInboxOutcome>,
    ) -> Result<(), SessionError> {
        validate_agent_inbox_event(removed_count, inserted, outcome)?;
        if removed_count.is_some() && outcome.is_none() {
            require_open_turn(self.open_turn)?;
        }
        Ok(())
    }

    fn apply_tool_result(
        &mut self,
        kind: &SessionEventKind,
        message: &SessionMessage,
        error: Option<&SessionToolError>,
        surface: &SessionSurfaceIntent,
    ) -> Result<(), SessionError> {
        self.validate_message_event(kind)?;
        if !matches!(surface.surface_op, SessionSurfaceOp::Append) {
            return Ok(());
        }
        let SessionMessageSource::Tool { call_id } = &message.source else {
            return Err(SessionError::InvalidMessageSource {
                event_type: "tool/result",
                expected: "non-empty tool call id",
            });
        };
        if !self.pending_tool_calls.contains(call_id) && !synthetic_tool_not_started(message, error)
        {
            return Err(SessionError::ToolResultWithoutCall {
                call_id: call_id.clone(),
            });
        }
        self.pending_tool_calls.remove(call_id);
        Ok(())
    }

    fn validate_message_event(&self, kind: &SessionEventKind) -> Result<(), SessionError> {
        match kind {
            SessionEventKind::UserMessage { message, .. } => validate_message(
                message,
                SessionMessageRole::User,
                "user/message",
                valid_user_source,
                "user or non-empty plugin",
            ),
            SessionEventKind::AssistantMessage {
                turn,
                step,
                message,
                ..
            } => {
                require_turn(self.open_turn, *turn)?;
                require_step(self.open_step, *turn, *step)?;
                validate_message(
                    message,
                    SessionMessageRole::Assistant,
                    "assistant/message",
                    |source| {
                        matches!(
                            source,
                            SessionMessageSource::Model { provider, model }
                                if !provider.is_empty() && !model.is_empty()
                        )
                    },
                    "non-empty model provider and model",
                )
            }
            SessionEventKind::ToolResult {
                turn,
                step,
                message,
                error,
                ..
            } => {
                require_turn(self.open_turn, *turn)?;
                require_step(self.open_step, *turn, *step)?;
                validate_message(
                    message,
                    SessionMessageRole::User,
                    "tool/result",
                    |source| {
                        matches!(
                            source,
                            SessionMessageSource::Tool { call_id } if !call_id.is_empty()
                        )
                    },
                    "non-empty tool call id",
                )?;
                validate_tool_result_message(message)?;
                validate_tool_result_error(message, error.as_ref())
            }
            SessionEventKind::TurnStart { .. }
            | SessionEventKind::TurnEnd { .. }
            | SessionEventKind::StepStart { .. }
            | SessionEventKind::StepEnd { .. }
            | SessionEventKind::AgentInboxSpliced { .. }
            | SessionEventKind::AssistantChunk { .. }
            | SessionEventKind::RequestHeader { .. }
            | SessionEventKind::RequestContext { .. }
            | SessionEventKind::ToolCall { .. } => Ok(()),
        }
    }
}

pub(crate) fn validate_inbox_user_message(message: &SessionMessage) -> Result<(), SessionError> {
    validate_agent_user_message(message, "agent/inbox/spliced")
}

pub(crate) fn validate_agent_user_message(
    message: &SessionMessage,
    event_type: &'static str,
) -> Result<(), SessionError> {
    validate_message(
        message,
        SessionMessageRole::User,
        event_type,
        valid_user_source,
        "user or non-empty plugin",
    )
}

fn valid_user_source(source: &SessionMessageSource) -> bool {
    matches!(source, SessionMessageSource::User)
        || matches!(
            source,
            SessionMessageSource::Plugin { plugin } if !plugin.is_empty()
        )
}

fn validate_request_header(request: &SessionRequestHeader) -> Result<(), SessionError> {
    if request.clone().canonicalized() != *request {
        return Err(SessionError::InvalidRequestHeader {
            expected: "canonical absent empty system, tools, and adapter defaults",
        });
    }
    validate_call_config(&request.header.config)
        .map_err(|expected| SessionError::InvalidRequestHeader { expected })?;
    let config = &request.header.config;
    if let Some(defaults) = &request.header.adapter_defaults
        && ((!defaults.reasoning_effort && !defaults.max_tokens)
            || (defaults.reasoning_effort && config.reasoning_effort.is_none())
            || (defaults.max_tokens && config.max_tokens.is_none()))
    {
        return Err(SessionError::InvalidRequestHeader {
            expected: "adapter-default markers for present config fields",
        });
    }
    Ok(())
}

fn validate_call_config(config: &SessionCallConfig) -> Result<(), &'static str> {
    if config.provider.is_empty() || config.model.is_empty() {
        return Err("non-empty provider and model");
    }
    if config
        .reasoning_effort
        .as_ref()
        .is_some_and(String::is_empty)
    {
        return Err("a non-empty optional reasoning effort");
    }
    Ok(())
}

pub(crate) fn validate_agent_request_config(
    config: &SessionCallConfig,
) -> Result<(), SessionError> {
    validate_call_config(config)
        .map_err(|expected| SessionError::InvalidAgentRequestConfig { expected })
}

fn validate_request_context(context: &SessionRequestContext) -> Result<(), SessionError> {
    if context.provider.is_empty() || context.model.is_empty() {
        return Err(SessionError::InvalidRequestContext {
            expected: "non-empty provider and model",
        });
    }
    Ok(())
}

fn validate_assistant_chunk(chunk: &SessionStreamChunk) -> Result<(), SessionError> {
    match chunk {
        SessionStreamChunk::BlockStart { .. }
        | SessionStreamChunk::TextDelta { .. }
        | SessionStreamChunk::ReasoningDelta { .. } => Ok(()),
        SessionStreamChunk::ToolCallDelta { id, name, .. } => {
            if id.is_empty() || name.as_ref().is_some_and(String::is_empty) {
                return Err(SessionError::InvalidAssistantChunk {
                    expected: "non-empty tool call id and optional name",
                });
            }
            Ok(())
        }
        SessionStreamChunk::BlockEnd { block, .. } => {
            if matches!(block, SessionContentBlock::ToolResult { .. }) {
                return Err(SessionError::InvalidAssistantChunk {
                    expected: "assistant block-end content",
                });
            }
            validate_content_blocks(std::slice::from_ref(block), "assistant/chunk")
        }
        SessionStreamChunk::Usage { usage } => validate_token_usage(usage),
        SessionStreamChunk::Finish {
            reason,
            replay_state,
        } => {
            let failed = matches!(
                reason,
                SessionFinishReason::Aborted { .. } | SessionFinishReason::Error { .. }
            );
            if failed && replay_state.is_some() {
                return Err(SessionError::InvalidAssistantChunk {
                    expected: "replay state only on a successful finish",
                });
            }
            if let SessionFinishReason::Aborted { failure }
            | SessionFinishReason::Error { failure } = reason
            {
                validate_llm_failure(failure)?;
            }
            Ok(())
        }
    }
}

fn validate_token_usage(usage: &SessionTokenUsage) -> Result<(), SessionError> {
    if usage
        .reasoning_tokens
        .is_some_and(|reasoning| reasoning > usage.output_tokens)
    {
        return Err(SessionError::InvalidAssistantChunk {
            expected: "reasoning tokens within output tokens",
        });
    }
    let exact_total = usage
        .input_tokens
        .checked_add(usage.output_tokens)
        .and_then(|total| total.checked_add(usage.cache_read_tokens.unwrap_or_default()))
        .and_then(|total| total.checked_add(usage.cache_write_tokens.unwrap_or_default()))
        .ok_or(SessionError::InvalidAssistantChunk {
            expected: "token counts without overflow",
        })?;
    if usage.total_tokens.is_some_and(|total| total != exact_total) {
        return Err(SessionError::InvalidAssistantChunk {
            expected: "an exact total matching disjoint token counts",
        });
    }
    Ok(())
}

fn validate_llm_failure(failure: &SessionLlmFailure) -> Result<(), SessionError> {
    if failure.message.is_empty()
        || failure.code.is_empty()
        || failure.status == Some(0)
        || failure.request_id.as_ref().is_some_and(String::is_empty)
    {
        return Err(SessionError::InvalidAssistantChunk {
            expected: "non-empty failure message/code/request id and positive status",
        });
    }
    Ok(())
}

fn validate_tool_result_message(message: &SessionMessage) -> Result<(), SessionError> {
    let SessionMessageSource::Tool { call_id } = &message.source else {
        return Err(SessionError::InvalidMessageSource {
            event_type: "tool/result",
            expected: "non-empty tool call id",
        });
    };
    let [SessionContentBlock::ToolResult { tool_call_id, .. }] = message.content.as_slice() else {
        return Err(SessionError::InvalidToolResultShape);
    };
    if call_id != tool_call_id {
        return Err(SessionError::MismatchedToolCallIds);
    }
    Ok(())
}

fn validate_tool_result_error(
    message: &SessionMessage,
    error: Option<&SessionToolError>,
) -> Result<(), SessionError> {
    let Some(error) = error else {
        return Ok(());
    };
    let [SessionContentBlock::ToolResult { is_error, .. }] = message.content.as_slice() else {
        return Err(SessionError::InvalidToolResultShape);
    };
    if error.name.is_empty() || error.code.is_empty() || !is_error {
        return Err(SessionError::InvalidToolResultError {
            expected: "non-empty name/code on an error result",
        });
    }
    Ok(())
}

fn synthetic_tool_not_started(message: &SessionMessage, error: Option<&SessionToolError>) -> bool {
    matches!(
        (message.content.as_slice(), error),
        (
            [SessionContentBlock::ToolResult { is_error: true, .. }],
            Some(SessionToolError { code, .. })
        ) if code == TOOL_NOT_STARTED
    )
}

fn pending_interrupted_tool_calls(events: &[SessionEvent]) -> Vec<(String, u64, Option<u64>)> {
    let mut pending = Vec::<(String, u64, Option<u64>)>::new();
    for event in events {
        match &event.kind {
            SessionEventKind::TurnStart { .. }
            | SessionEventKind::TurnEnd { .. }
            | SessionEventKind::StepEnd { .. } => pending.clear(),
            SessionEventKind::AssistantMessage { step, message, .. } => {
                for block in &message.content {
                    let SessionContentBlock::ToolCall { id, .. } = block else {
                        continue;
                    };
                    if let Some((_, pending_step, call_seq)) =
                        pending.iter_mut().find(|(call_id, _, _)| call_id == id)
                    {
                        *pending_step = *step;
                        *call_seq = None;
                    } else {
                        pending.push((id.clone(), *step, None));
                    }
                }
            }
            SessionEventKind::ToolCall { call_id, .. } => {
                if let Some((_, _, call_seq)) = pending
                    .iter_mut()
                    .find(|(pending_id, _, _)| pending_id == call_id)
                {
                    *call_seq = Some(event.seq);
                }
            }
            SessionEventKind::ToolResult { message, .. } => {
                if let SessionMessageSource::Tool { call_id } = &message.source {
                    pending.retain(|(pending_id, _, _)| pending_id != call_id);
                }
            }
            SessionEventKind::StepStart { .. }
            | SessionEventKind::AgentInboxSpliced { .. }
            | SessionEventKind::AssistantChunk { .. }
            | SessionEventKind::RequestHeader { .. }
            | SessionEventKind::RequestContext { .. }
            | SessionEventKind::UserMessage { .. } => {}
        }
    }
    pending
}

fn require_turn(open_turn: Option<u64>, actual: u64) -> Result<(), SessionError> {
    match open_turn {
        Some(expected) if expected == actual => Ok(()),
        Some(expected) => Err(SessionError::TurnMismatch { expected, actual }),
        None => Err(SessionError::NoOpenTurn),
    }
}

fn require_open_turn(open_turn: Option<u64>) -> Result<(), SessionError> {
    open_turn.map_or(Err(SessionError::NoOpenTurn), |_| Ok(()))
}

fn require_step(open_step: Option<u64>, turn: u64, actual: u64) -> Result<(), SessionError> {
    match open_step {
        Some(expected) if expected == actual => Ok(()),
        Some(expected) => Err(SessionError::StepMismatch {
            turn,
            expected,
            actual,
        }),
        None => Err(SessionError::NoOpenStep { turn }),
    }
}

fn validate_message(
    message: &SessionMessage,
    expected_role: SessionMessageRole,
    event_type: &'static str,
    valid_source: impl FnOnce(&SessionMessageSource) -> bool,
    expected_source: &'static str,
) -> Result<(), SessionError> {
    if message.id.is_empty() {
        return Err(SessionError::EmptyMessageId { event_type });
    }
    if message.role != expected_role {
        return Err(SessionError::UnexpectedMessageRole {
            event_type,
            expected: expected_role,
            actual: message.role,
        });
    }
    if !valid_source(&message.source) {
        return Err(SessionError::InvalidMessageSource {
            event_type,
            expected: expected_source,
        });
    }
    validate_content_blocks(&message.content, event_type)
}

fn validate_content_blocks(
    blocks: &[SessionContentBlock],
    event_type: &'static str,
) -> Result<(), SessionError> {
    let mut pending = blocks.iter().collect::<Vec<_>>();
    while let Some(block) = pending.pop() {
        match block {
            SessionContentBlock::Text { .. } | SessionContentBlock::Reasoning { .. } => {}
            SessionContentBlock::ToolCall { id, name, .. } => {
                if id.is_empty() || name.is_empty() {
                    return Err(SessionError::InvalidContentBlock {
                        event_type,
                        expected: "non-empty tool call id and name",
                    });
                }
            }
            SessionContentBlock::ToolResult {
                tool_call_id,
                content,
                ..
            } => {
                if tool_call_id.is_empty() {
                    return Err(SessionError::InvalidContentBlock {
                        event_type,
                        expected: "non-empty tool result call id",
                    });
                }
                pending.extend(content);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SessionSurfaceState {
    nodes: Vec<u64>,
    replace_generation: u64,
}

#[derive(Clone, Copy)]
enum SessionSurfacePlan {
    None,
    Append {
        seq: u64,
    },
    Replace {
        seq: u64,
        start_index: usize,
        end_index: usize,
        generation: u64,
    },
}

impl SessionSurfaceState {
    fn snapshot(&self) -> SessionSurface {
        SessionSurface {
            nodes: self.nodes.clone(),
            replace_generation: self.replace_generation,
        }
    }

    fn plan(
        &self,
        seq: u64,
        kind: &SessionEventKind,
        prior_events: &[SessionEvent],
    ) -> Result<SessionSurfacePlan, SessionError> {
        let Some(intent) = kind.surface_intent() else {
            return Ok(SessionSurfacePlan::None);
        };
        match intent.surface_op {
            SessionSurfaceOp::Append => {
                validate_surface_provenance(seq, kind, intent, &[], prior_events)?;
                Ok(SessionSurfacePlan::Append { seq })
            }
            SessionSurfaceOp::Replace { start, end } => {
                let start_index = self
                    .nodes
                    .iter()
                    .position(|node| *node == start)
                    .ok_or(SessionError::SurfaceReplaceStartNotFound { start })?;
                let end_index = self
                    .nodes
                    .iter()
                    .position(|node| *node == end)
                    .ok_or(SessionError::SurfaceReplaceEndNotFound { end })?;
                if start_index > end_index {
                    return Err(SessionError::SurfaceReplaceRangeReversed { start, end });
                }
                let shadowed = self.nodes[start_index..=end_index].to_vec();
                validate_surface_provenance(seq, kind, intent, &shadowed, prior_events)?;
                validate_tool_result_replacement(kind, &shadowed, prior_events)?;
                let generation = self
                    .replace_generation
                    .checked_add(1)
                    .ok_or(SessionError::SurfaceGenerationOverflow)?;
                Ok(SessionSurfacePlan::Replace {
                    seq,
                    start_index,
                    end_index,
                    generation,
                })
            }
        }
    }

    fn apply(&mut self, plan: SessionSurfacePlan) {
        match plan {
            SessionSurfacePlan::None => {}
            SessionSurfacePlan::Append { seq } => self.nodes.push(seq),
            SessionSurfacePlan::Replace {
                seq,
                start_index,
                end_index,
                generation,
            } => {
                self.nodes.splice(start_index..=end_index, [seq]);
                self.replace_generation = generation;
            }
        }
    }
}

fn validate_surface_provenance(
    seq: u64,
    kind: &SessionEventKind,
    intent: &SessionSurfaceIntent,
    shadowed: &[u64],
    prior_events: &[SessionEvent],
) -> Result<(), SessionError> {
    let mut sources = HashSet::new();
    if let Some(source_event_seqs) = &intent.source_event_seqs {
        if source_event_seqs.is_empty()
            && !matches!(kind, SessionEventKind::AssistantMessage { .. })
        {
            return Err(SessionError::EmptySurfaceProvenance {
                event_type: kind.event_type(),
            });
        }
        for source in source_event_seqs {
            if !sources.insert(*source) {
                return Err(SessionError::DuplicateSurfaceProvenance {
                    source_seq: *source,
                });
            }
            if *source >= seq {
                return Err(SessionError::SurfaceProvenanceNotEarlier {
                    source_seq: *source,
                    current: seq,
                });
            }
        }
    }
    if let (SessionEventKind::AssistantMessage { turn, step, .. }, Some(source_event_seqs)) =
        (kind, &intent.source_event_seqs)
    {
        for source in source_event_seqs {
            if shadowed.contains(source) {
                continue;
            }
            let event = usize::try_from(*source)
                .ok()
                .and_then(|index| prior_events.get(index));
            match event.map(|event| &event.kind) {
                Some(SessionEventKind::AssistantChunk {
                    turn: source_turn,
                    step: source_step,
                    ..
                }) if source_turn == turn && source_step == step => {}
                Some(SessionEventKind::AssistantChunk {
                    turn: source_turn,
                    step: source_step,
                    ..
                }) => {
                    return Err(SessionError::AssistantChunkProvenanceScope {
                        source_seq: *source,
                        expected_turn: *turn,
                        expected_step: *step,
                        actual_turn: *source_turn,
                        actual_step: *source_step,
                    });
                }
                _ => {
                    return Err(SessionError::AssistantChunkProvenanceTarget {
                        source_seq: *source,
                    });
                }
            }
        }
    }
    let missing = shadowed
        .iter()
        .copied()
        .filter(|node| !sources.contains(node))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(SessionError::IncompleteSurfaceProvenance { missing });
    }
    Ok(())
}

fn validate_tool_result_replacement(
    replacement: &SessionEventKind,
    shadowed: &[u64],
    prior_events: &[SessionEvent],
) -> Result<(), SessionError> {
    let SessionEventKind::ToolResult {
        turn,
        step,
        message,
        error,
        ..
    } = replacement
    else {
        return Ok(());
    };
    let [original_seq] = shadowed else {
        return Err(SessionError::ToolResultSurfaceReplaceRange);
    };
    let original = usize::try_from(*original_seq)
        .ok()
        .and_then(|index| prior_events.get(index));
    let Some(SessionEvent {
        kind:
            SessionEventKind::ToolResult {
                turn: original_turn,
                step: original_step,
                message: original_message,
                error: original_error,
                ..
            },
        ..
    }) = original
    else {
        return Err(SessionError::ToolResultSurfaceReplaceTarget);
    };
    if turn != original_turn
        || step != original_step
        || error != original_error
        || !tool_result_same_except_content(original_message, message)
    {
        return Err(SessionError::ToolResultSurfaceReplaceDrift);
    }
    Ok(())
}

fn tool_result_same_except_content(
    original: &SessionMessage,
    replacement: &SessionMessage,
) -> bool {
    if original.id != replacement.id
        || original.role != replacement.role
        || original.source != replacement.source
    {
        return false;
    }
    matches!(
        (original.content.as_slice(), replacement.content.as_slice()),
        (
            [SessionContentBlock::ToolResult {
                tool_call_id: original_call,
                is_error: original_error,
                ..
            }],
            [SessionContentBlock::ToolResult {
                tool_call_id: replacement_call,
                is_error: replacement_error,
                ..
            }]
        ) if original_call == replacement_call && original_error == replacement_error
    )
}

/// Validated append-only lifecycle log for one Session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLog {
    header: SessionHeader,
    events: Vec<SessionEvent>,
    state: SessionState,
    surface: SessionSurfaceState,
}

impl SessionLog {
    pub fn new(id: SessionId) -> Result<Self, SessionError> {
        Ok(Self {
            header: SessionHeader::new(id)?,
            events: Vec::new(),
            state: SessionState::default(),
            surface: SessionSurfaceState::default(),
        })
    }

    pub fn new_at(id: SessionId, created_at_ms: i64) -> Result<Self, SessionError> {
        Ok(Self {
            header: SessionHeader::new_at(id, created_at_ms)?,
            events: Vec::new(),
            state: SessionState::default(),
            surface: SessionSurfaceState::default(),
        })
    }

    pub fn restore(header: SessionHeader, events: Vec<SessionEvent>) -> Result<Self, SessionError> {
        validate_header(&header, events.len())?;
        let mut state = SessionState::default();
        let mut surface = SessionSurfaceState::default();
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
            let plan = surface.plan(event.seq, &event.kind, &events[..index])?;
            surface.apply(plan);
        }
        Ok(Self {
            header,
            events,
            state,
            surface,
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
    pub fn surface(&self) -> SessionSurface {
        self.surface.snapshot()
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

    fn append_agent_inbox_splice(
        &mut self,
        target: AgentInboxTarget,
        start: u64,
        removed_count: Option<u64>,
        inserted: Vec<SessionMessage>,
        outcome: Option<AgentInboxOutcome>,
    ) -> Result<SessionEvent, SessionError> {
        Ok(self
            .append(SessionEventKind::AgentInboxSpliced {
                target,
                start,
                removed_count,
                inserted,
                outcome,
            })?
            .clone())
    }

    pub fn append_user_message(&mut self, message: SessionMessage) -> Result<(), SessionError> {
        self.append_user_message_with_surface(message, SessionSurfaceIntent::append())
    }

    pub fn append_user_message_with_surface(
        &mut self,
        message: SessionMessage,
        surface: SessionSurfaceIntent,
    ) -> Result<(), SessionError> {
        self.append(SessionEventKind::UserMessage { message, surface })?;
        Ok(())
    }

    /// Append one raw assistant stream chunk and return its durable source seq.
    pub fn append_assistant_chunk(
        &mut self,
        turn: u64,
        step: u64,
        chunk: SessionStreamChunk,
    ) -> Result<u64, SessionError> {
        Ok(self
            .append(SessionEventKind::AssistantChunk { turn, step, chunk })?
            .seq)
    }

    /// Append one complete canonical header snapshot inside the open turn.
    pub fn append_request_header(
        &mut self,
        header: SessionEpochHeader,
        reason: SessionRequestHeaderReason,
        starts_series: bool,
    ) -> Result<(), SessionError> {
        self.append(SessionEventKind::RequestHeader {
            request: SessionRequestHeader {
                header,
                reason,
                starts_series,
            }
            .canonicalized(),
        })?;
        Ok(())
    }

    /// Append resolved route metadata inside the open turn.
    pub fn append_request_context(
        &mut self,
        context: SessionRequestContext,
    ) -> Result<(), SessionError> {
        self.append(SessionEventKind::RequestContext { context })?;
        Ok(())
    }

    /// Append one model-requested invocation without parsing its raw arguments.
    pub fn append_tool_call(
        &mut self,
        turn: u64,
        step: u64,
        call_id: impl Into<String>,
        name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Result<u64, SessionError> {
        Ok(self
            .append(SessionEventKind::ToolCall {
                turn,
                step,
                call_id: call_id.into(),
                name: name.into(),
                arguments: arguments.into(),
            })?
            .seq)
    }

    pub fn append_assistant_message(
        &mut self,
        turn: u64,
        step: u64,
        message: SessionMessage,
    ) -> Result<(), SessionError> {
        self.append_assistant_message_with_surface(
            turn,
            step,
            message,
            SessionSurfaceIntent::append(),
        )
    }

    pub fn append_assistant_message_with_surface(
        &mut self,
        turn: u64,
        step: u64,
        message: SessionMessage,
        surface: SessionSurfaceIntent,
    ) -> Result<(), SessionError> {
        self.append(SessionEventKind::AssistantMessage {
            turn,
            step,
            message,
            surface,
        })?;
        Ok(())
    }

    pub fn append_tool_result(
        &mut self,
        turn: u64,
        step: u64,
        message: SessionMessage,
    ) -> Result<(), SessionError> {
        self.append_tool_result_with_surface(turn, step, message, SessionSurfaceIntent::append())
    }

    pub fn append_tool_result_with_surface(
        &mut self,
        turn: u64,
        step: u64,
        message: SessionMessage,
        surface: SessionSurfaceIntent,
    ) -> Result<(), SessionError> {
        self.append(SessionEventKind::ToolResult {
            turn,
            step,
            message,
            error: None,
            surface,
        })?;
        Ok(())
    }

    /// Derive a detached model-history snapshot from the ordered surface.
    ///
    /// Replaced nodes remain durable but are shadowed from future requests.
    /// Lifecycle events never enter history, and an empty assistant message is
    /// retained on the surface for accounting while omitted from the transcript.
    #[must_use]
    pub fn derive_messages(&self) -> Vec<SessionMessage> {
        self.surface
            .nodes
            .iter()
            .filter_map(|seq| usize::try_from(*seq).ok())
            .filter_map(|index| self.events.get(index))
            .filter_map(|event| event.kind.derived_message().cloned())
            .collect()
    }

    /// Replay detached raw chunks for one step in authoritative event order.
    #[must_use]
    pub fn assistant_chunks(&self, turn: u64, step: u64) -> Vec<SessionAssistantChunk> {
        self.events
            .iter()
            .filter_map(|event| {
                let SessionEventKind::AssistantChunk {
                    turn: chunk_turn,
                    step: chunk_step,
                    chunk,
                } = &event.kind
                else {
                    return None;
                };
                (*chunk_turn == turn && *chunk_step == step).then(|| SessionAssistantChunk {
                    seq: event.seq,
                    time_ms: event.time_ms,
                    turn: *chunk_turn,
                    step: *chunk_step,
                    chunk: chunk.clone(),
                })
            })
            .collect()
    }

    /// Replay detached tool invocations for one step in authoritative order.
    #[must_use]
    pub fn tool_calls(&self, turn: u64, step: u64) -> Vec<SessionToolCall> {
        self.events
            .iter()
            .filter_map(|event| {
                let SessionEventKind::ToolCall {
                    turn: call_turn,
                    step: call_step,
                    call_id,
                    name,
                    arguments,
                } = &event.kind
                else {
                    return None;
                };
                (*call_turn == turn && *call_step == step).then(|| SessionToolCall {
                    seq: event.seq,
                    time_ms: event.time_ms,
                    turn: *call_turn,
                    step: *call_step,
                    call_id: call_id.clone(),
                    name: name.clone(),
                    arguments: arguments.clone(),
                })
            })
            .collect()
    }

    /// Reconstruct the latest complete request header independently of history.
    #[must_use]
    pub fn request_header(&self) -> Option<SessionEpochHeader> {
        self.events.iter().rev().find_map(|event| {
            let SessionEventKind::RequestHeader { request } = &event.kind else {
                return None;
            };
            Some(request.header.clone())
        })
    }

    /// Reconstruct the latest resolved route metadata independently of history.
    #[must_use]
    pub fn request_context(&self) -> Option<SessionRequestContext> {
        self.events.iter().rev().find_map(|event| {
            let SessionEventKind::RequestContext { context } = &event.kind else {
                return None;
            };
            Some(context.clone())
        })
    }

    /// Close a durable turn left open by a crashed process.
    ///
    /// Synthetic tool outcomes precede the lifecycle closers, making the
    /// repaired transcript provider-valid. All synthetic events reuse the
    /// final real timestamp, and a balanced log is unchanged.
    pub fn repair_interrupted_tail(&mut self) -> Result<bool, SessionError> {
        let Some(turn) = self.state.open_turn else {
            return Ok(false);
        };
        let time_ms = self
            .events
            .last()
            .ok_or(SessionError::EventSequenceOverflow)?
            .time_ms;

        let mut repaired = self.clone();
        for (call_id, step, call_seq) in pending_interrupted_tool_calls(&self.events) {
            let seq = u64::try_from(repaired.events.len())
                .map_err(|_| SessionError::EventSequenceOverflow)?;
            let (name, code, text) = if call_seq.is_some() {
                (
                    "ToolOutcomeUnknownError",
                    TOOL_OUTCOME_UNKNOWN,
                    TOOL_OUTCOME_UNKNOWN_MESSAGE,
                )
            } else {
                (
                    "ToolNotStartedError",
                    TOOL_NOT_STARTED,
                    TOOL_NOT_STARTED_MESSAGE,
                )
            };
            let surface = call_seq.map_or_else(SessionSurfaceIntent::append, |source_seq| {
                SessionSurfaceIntent::append_from(vec![source_seq])
            });
            repaired.append_at(
                SessionEventKind::ToolResult {
                    turn,
                    step,
                    message: SessionMessage {
                        id: format!("interrupted-tool-result-{call_id}-{seq}"),
                        role: SessionMessageRole::User,
                        content: vec![SessionContentBlock::ToolResult {
                            tool_call_id: call_id.clone(),
                            content: vec![SessionContentBlock::Text { text: text.into() }],
                            is_error: true,
                        }],
                        source: SessionMessageSource::Tool { call_id },
                    },
                    error: Some(SessionToolError {
                        name: name.into(),
                        code: code.into(),
                    }),
                    surface,
                },
                time_ms,
            )?;
        }
        if let Some(step) = repaired.state.open_step {
            repaired.append_at(SessionEventKind::StepEnd { turn, step }, time_ms)?;
        }
        repaired.append_at(
            SessionEventKind::TurnEnd {
                turn,
                reason: TurnEndReason::Interrupted,
            },
            time_ms,
        )?;
        *self = repaired;
        Ok(true)
    }

    fn append(&mut self, kind: SessionEventKind) -> Result<&SessionEvent, SessionError> {
        self.append_at(kind, Utc::now().timestamp_millis())
    }

    fn append_at(
        &mut self,
        kind: SessionEventKind,
        time_ms: i64,
    ) -> Result<&SessionEvent, SessionError> {
        let seq =
            u64::try_from(self.events.len()).map_err(|_| SessionError::EventSequenceOverflow)?;
        if time_ms < 0 {
            return Err(SessionError::InvalidEventTime { seq, time_ms });
        }
        let mut next_state = self.state.clone();
        next_state.apply(&kind)?;
        let surface_plan = self.surface.plan(seq, &kind, &self.events)?;
        self.events.push(SessionEvent { seq, time_ms, kind });
        self.state = next_state;
        self.surface.apply(surface_plan);
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
    id: SessionId,
    inner: Arc<Mutex<SessionLog>>,
    event_dispatcher: Option<EventReentry>,
    appending: Arc<AtomicBool>,
    inbox_state: Arc<Mutex<AgentInboxState>>,
    inbox_mutating: Arc<AtomicBool>,
}

impl SessionHandle {
    fn new(log: SessionLog, event_dispatcher: Option<EventReentry>) -> Result<Self, SessionError> {
        let inbox_state = AgentInboxState::restore(log.header(), log.events())?;
        Ok(Self {
            id: log.header().id.clone(),
            inner: Arc::new(Mutex::new(log)),
            event_dispatcher,
            appending: Arc::new(AtomicBool::new(false)),
            inbox_state: Arc::new(Mutex::new(inbox_state)),
            inbox_mutating: Arc::new(AtomicBool::new(false)),
        })
    }

    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn header(&self) -> Result<SessionHeader, SessionError> {
        Ok(self.lock()?.header().clone())
    }

    pub fn events(&self) -> Result<Vec<SessionEvent>, SessionError> {
        Ok(self.lock()?.events().to_vec())
    }

    pub fn surface(&self) -> Result<SessionSurface, SessionError> {
        Ok(self.lock()?.surface())
    }

    /// Return the single shared pending-input projection owned by this Session.
    #[must_use]
    pub fn inbox(&self) -> AgentInbox {
        AgentInbox::new(
            self.clone(),
            Arc::clone(&self.inbox_state),
            Arc::clone(&self.inbox_mutating),
        )
    }

    pub fn start_turn(&self) -> Result<u64, SessionError> {
        self.commit(SessionLog::start_turn)
    }

    pub fn finish_turn(&self, turn: u64, reason: TurnEndReason) -> Result<(), SessionError> {
        self.commit(|log| log.finish_turn(turn, reason))
    }

    pub fn start_step(&self, turn: u64) -> Result<u64, SessionError> {
        self.commit(|log| log.start_step(turn))
    }

    pub fn finish_step(&self, turn: u64, step: u64) -> Result<(), SessionError> {
        self.commit(|log| log.finish_step(turn, step))
    }

    pub(crate) fn require_open_turn(&self, turn: u64) -> Result<(), SessionError> {
        require_turn(self.lock()?.open_turn(), turn)
    }

    pub(crate) fn require_open_step(&self, turn: u64, step: u64) -> Result<(), SessionError> {
        let log = self.lock()?;
        require_turn(log.open_turn(), turn)?;
        require_step(log.open_step(), turn, step)
    }

    pub(crate) fn append_agent_inbox_splice(
        &self,
        target: AgentInboxTarget,
        start: u64,
        removed_count: Option<u64>,
        inserted: Vec<SessionMessage>,
        outcome: Option<AgentInboxOutcome>,
    ) -> Result<SessionEvent, SessionError> {
        self.commit(|log| {
            log.append_agent_inbox_splice(target, start, removed_count, inserted, outcome)
        })
    }

    pub(crate) fn claim_agent_inbox_splice(
        &self,
        turn: u64,
        target: AgentInboxTarget,
        start: u64,
        removed_count: Option<u64>,
        inserted: Vec<SessionMessage>,
        outcome: Option<AgentInboxOutcome>,
    ) -> Result<SessionEvent, SessionError> {
        self.commit(|log| {
            require_turn(log.open_turn(), turn)?;
            log.append_agent_inbox_splice(target, start, removed_count, inserted, outcome)
        })
    }

    pub(crate) fn claim_agent_inbox_batch(
        &self,
        turn: u64,
        next_step_removed_count: u64,
        claim_next_turn: bool,
    ) -> Result<Vec<SessionEvent>, SessionError> {
        let _permit = SessionAppendPermit::enter(&self.appending, &self.id)?;
        let records = {
            let mut log = self.lock()?;
            require_turn(log.open_turn(), turn)?;

            let mut candidate = log.clone();
            let mut events = Vec::with_capacity(2);
            if next_step_removed_count > 0 {
                events.push(candidate.append_agent_inbox_splice(
                    AgentInboxTarget::NextStep,
                    0,
                    Some(next_step_removed_count),
                    Vec::new(),
                    None,
                )?);
            }
            if claim_next_turn {
                events.push(candidate.append_agent_inbox_splice(
                    AgentInboxTarget::NextTurn,
                    0,
                    Some(1),
                    Vec::new(),
                    None,
                )?);
            }
            let header = candidate.header().clone();
            *log = candidate;
            events
                .into_iter()
                .map(|event| SessionEventRecord {
                    header: header.clone(),
                    event,
                })
                .collect::<Vec<_>>()
        };

        if let Some(dispatcher) = &self.event_dispatcher {
            for record in &records {
                let _ = dispatcher.emit_contained(events::SESSION_EVENT, record);
            }
        }
        Ok(records.into_iter().map(|record| record.event).collect())
    }

    pub(crate) fn enter_agent_step(
        &self,
        turn: u64,
        step: u64,
        messages: &[SessionMessage],
    ) -> Result<(), SessionError> {
        if messages.is_empty() {
            return Ok(());
        }
        let _permit = SessionAppendPermit::enter(&self.appending, &self.id)?;
        let records = {
            let mut log = self.lock()?;
            let previous_len = log.events().len();
            let mut candidate = log.clone();
            let expected = candidate.start_step(turn)?;
            if step != expected {
                return Err(SessionError::UnexpectedStep {
                    turn,
                    expected,
                    actual: step,
                });
            }
            for message in messages {
                candidate.append_user_message(message.clone())?;
            }
            let header = candidate.header().clone();
            let records = candidate.events()[previous_len..]
                .iter()
                .cloned()
                .map(|event| SessionEventRecord {
                    header: header.clone(),
                    event,
                })
                .collect::<Vec<_>>();
            *log = candidate;
            records
        };

        if let Some(dispatcher) = &self.event_dispatcher {
            for record in &records {
                let _ = dispatcher.emit_contained(events::SESSION_EVENT, record);
            }
        }
        Ok(())
    }

    pub fn append_user_message(&self, message: SessionMessage) -> Result<(), SessionError> {
        self.commit(|log| log.append_user_message(message))
    }

    pub fn append_user_message_with_surface(
        &self,
        message: SessionMessage,
        surface: SessionSurfaceIntent,
    ) -> Result<(), SessionError> {
        self.commit(|log| log.append_user_message_with_surface(message, surface))
    }

    pub fn append_assistant_chunk(
        &self,
        turn: u64,
        step: u64,
        chunk: SessionStreamChunk,
    ) -> Result<u64, SessionError> {
        self.commit(|log| log.append_assistant_chunk(turn, step, chunk))
    }

    pub fn append_request_header(
        &self,
        header: SessionEpochHeader,
        reason: SessionRequestHeaderReason,
        starts_series: bool,
    ) -> Result<(), SessionError> {
        self.commit(|log| log.append_request_header(header, reason, starts_series))
    }

    pub fn append_request_context(
        &self,
        context: SessionRequestContext,
    ) -> Result<(), SessionError> {
        self.commit(|log| log.append_request_context(context))
    }

    pub fn append_tool_call(
        &self,
        turn: u64,
        step: u64,
        call_id: impl Into<String>,
        name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Result<u64, SessionError> {
        self.commit(|log| log.append_tool_call(turn, step, call_id, name, arguments))
    }

    pub fn append_assistant_message(
        &self,
        turn: u64,
        step: u64,
        message: SessionMessage,
    ) -> Result<(), SessionError> {
        self.commit(|log| log.append_assistant_message(turn, step, message))
    }

    pub fn append_assistant_message_with_surface(
        &self,
        turn: u64,
        step: u64,
        message: SessionMessage,
        surface: SessionSurfaceIntent,
    ) -> Result<(), SessionError> {
        self.commit(|log| log.append_assistant_message_with_surface(turn, step, message, surface))
    }

    pub fn append_tool_result(
        &self,
        turn: u64,
        step: u64,
        message: SessionMessage,
    ) -> Result<(), SessionError> {
        self.commit(|log| log.append_tool_result(turn, step, message))
    }

    pub fn append_tool_result_with_surface(
        &self,
        turn: u64,
        step: u64,
        message: SessionMessage,
        surface: SessionSurfaceIntent,
    ) -> Result<(), SessionError> {
        self.commit(|log| log.append_tool_result_with_surface(turn, step, message, surface))
    }

    pub fn derive_messages(&self) -> Result<Vec<SessionMessage>, SessionError> {
        Ok(self.lock()?.derive_messages())
    }

    pub fn assistant_chunks(
        &self,
        turn: u64,
        step: u64,
    ) -> Result<Vec<SessionAssistantChunk>, SessionError> {
        Ok(self.lock()?.assistant_chunks(turn, step))
    }

    pub fn tool_calls(&self, turn: u64, step: u64) -> Result<Vec<SessionToolCall>, SessionError> {
        Ok(self.lock()?.tool_calls(turn, step))
    }

    pub fn request_header(&self) -> Result<Option<SessionEpochHeader>, SessionError> {
        Ok(self.lock()?.request_header())
    }

    pub fn request_context(&self) -> Result<Option<SessionRequestContext>, SessionError> {
        Ok(self.lock()?.request_context())
    }

    fn commit<R>(
        &self,
        append: impl FnOnce(&mut SessionLog) -> Result<R, SessionError>,
    ) -> Result<R, SessionError> {
        let _permit = SessionAppendPermit::enter(&self.appending, &self.id)?;
        let (result, record) = {
            let mut log = self.lock()?;
            let previous_len = log.events().len();
            let result = append(&mut log)?;
            let expected_seq =
                u64::try_from(previous_len).map_err(|_| SessionError::EventSequenceOverflow)?;
            let event = log
                .events()
                .get(previous_len)
                .filter(|event| event.seq == expected_seq)
                .cloned()
                .ok_or(SessionError::EventSequenceOverflow)?;
            if log.events().len() != previous_len + 1 {
                return Err(SessionError::EventSequenceOverflow);
            }
            let record = SessionEventRecord {
                header: log.header().clone(),
                event,
            };
            (result, record)
        };

        if let Some(dispatcher) = &self.event_dispatcher {
            // The append is authoritative. Observation failures are contained
            // here; persistence adapters report durability at the flush edge.
            let _ = dispatcher.emit_contained(events::SESSION_EVENT, &record);
        }
        Ok(result)
    }

    fn checkpoint(&self) -> Result<SessionCheckpoint, SessionError> {
        let log = self.lock()?;
        Ok(SessionCheckpoint {
            header: log.header().clone(),
            events: log.events().to_vec(),
        })
    }

    async fn flush(&self) -> Result<bool, SessionError> {
        let Some(dispatcher) = &self.event_dispatcher else {
            return Ok(false);
        };
        let listener_count = dispatcher
            .parallel(events::SESSION_FLUSH, self.checkpoint()?)
            .await
            .map_err(|error| SessionError::FlushFailed {
                message: error.to_string(),
            })?;
        Ok(listener_count != 0)
    }

    fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, SessionLog>, SessionError> {
        self.inner.lock().map_err(|_| SessionError::LogPoisoned)
    }
}

struct SessionAppendPermit<'a>(&'a AtomicBool);

impl<'a> SessionAppendPermit<'a> {
    fn enter(flag: &'a AtomicBool, id: &SessionId) -> Result<Self, SessionError> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self(flag))
            .map_err(|_| SessionError::AppendInProgress { id: id.clone() })
    }
}

impl Drop for SessionAppendPermit<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Debug, Default)]
struct SessionStoreState {
    sessions: HashMap<SessionId, SessionHandle>,
}

/// In-memory Session store mounted at `ctx.sessions`.
#[derive(Debug, Clone)]
pub struct SessionStore {
    inner: Arc<Mutex<SessionStoreState>>,
    event_dispatcher: Option<EventReentry>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionStoreState::default())),
            event_dispatcher: None,
        }
    }

    pub(crate) fn with_event_dispatcher(event_dispatcher: EventReentry) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SessionStoreState::default())),
            event_dispatcher: Some(event_dispatcher),
        }
    }

    pub fn create(&self, id: SessionId) -> Result<SessionHandle, SessionError> {
        let mut state = self.lock()?;
        if state.sessions.contains_key(&id) {
            return Err(SessionError::SessionAlreadyExists { id });
        }
        let handle =
            SessionHandle::new(SessionLog::new(id.clone())?, self.event_dispatcher.clone())?;
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
        let handle = SessionHandle::new(
            SessionLog::restore(header, events)?,
            self.event_dispatcher.clone(),
        )?;
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
        let child = SessionHandle::new(child_log, self.event_dispatcher.clone())?;
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
        let handle =
            SessionHandle::new(SessionLog::new(id.clone())?, self.event_dispatcher.clone())?;
        state.sessions.insert(id, handle.clone());
        Ok(handle)
    }

    /// Wait until every persistence listener has handled one immutable prefix.
    ///
    /// Returns `false` when no persistence listener is mounted. Listener
    /// failures are reported after the complete callback snapshot settles.
    pub async fn flush(&self, session: &SessionHandle) -> Result<bool, SessionError> {
        {
            let state = self.lock()?;
            let Some(live) = state.sessions.get(session.id()) else {
                return Err(SessionError::SessionNotLive {
                    id: session.id().clone(),
                });
            };
            if !session.same_instance(live) {
                return Err(SessionError::SessionNotLive {
                    id: session.id().clone(),
                });
            }
        }
        session.flush().await
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
    #[error("session {event_type} message id must not be empty")]
    EmptyMessageId { event_type: &'static str },
    #[error("session {event_type} message role must be {expected:?}, got {actual:?}")]
    UnexpectedMessageRole {
        event_type: &'static str,
        expected: SessionMessageRole,
        actual: SessionMessageRole,
    },
    #[error("session {event_type} message source must be {expected}")]
    InvalidMessageSource {
        event_type: &'static str,
        expected: &'static str,
    },
    #[error("session {event_type} content block must have {expected}")]
    InvalidContentBlock {
        event_type: &'static str,
        expected: &'static str,
    },
    #[error("session tool/result message must contain exactly one tool-result block")]
    InvalidToolResultShape,
    #[error("session tool/result source and content call ids must match")]
    MismatchedToolCallIds,
    #[error("session tool/result for `{call_id}` has no prior tool/call in this step")]
    ToolResultWithoutCall { call_id: String },
    #[error("session tool/result error must have {expected}")]
    InvalidToolResultError { expected: &'static str },
    #[error("session tool/call must have {expected}")]
    InvalidToolCall { expected: &'static str },
    #[error("session message persistence encoding is invalid")]
    InvalidMessageEncoding,
    #[error("session assistant chunk persistence encoding is invalid")]
    InvalidAssistantChunkEncoding,
    #[error("session assistant chunk must have {expected}")]
    InvalidAssistantChunk { expected: &'static str },
    #[error("session request/header persistence encoding is invalid")]
    InvalidRequestHeaderEncoding,
    #[error("session request/header must have {expected}")]
    InvalidRequestHeader { expected: &'static str },
    #[error("session agent/request config must have {expected}")]
    InvalidAgentRequestConfig { expected: &'static str },
    #[error("session request/context persistence encoding is invalid")]
    InvalidRequestContextEncoding,
    #[error("session request/context must have {expected}")]
    InvalidRequestContext { expected: &'static str },
    #[error("session surface persistence encoding is invalid")]
    InvalidSurfaceEncoding,
    #[error("session {event_type} source event sequences must not be empty")]
    EmptySurfaceProvenance { event_type: &'static str },
    #[error("session surface source event sequence {source_seq} is duplicated")]
    DuplicateSurfaceProvenance { source_seq: u64 },
    #[error("session assistant message source event {source_seq} is not an assistant/chunk")]
    AssistantChunkProvenanceTarget { source_seq: u64 },
    #[error(
        "session assistant message source chunk {source_seq} belongs to turn {actual_turn}/step {actual_step}, expected turn {expected_turn}/step {expected_step}"
    )]
    AssistantChunkProvenanceScope {
        source_seq: u64,
        expected_turn: u64,
        expected_step: u64,
        actual_turn: u64,
        actual_step: u64,
    },
    #[error(
        "session surface source event sequence {source_seq} must be earlier than current event {current}"
    )]
    SurfaceProvenanceNotEarlier { source_seq: u64, current: u64 },
    #[error("session surface replace start {start} is not a current surface node")]
    SurfaceReplaceStartNotFound { start: u64 },
    #[error("session surface replace end {end} is not a current surface node")]
    SurfaceReplaceEndNotFound { end: u64 },
    #[error("session surface replace start {start} appears after end {end}")]
    SurfaceReplaceRangeReversed { start: u64, end: u64 },
    #[error("session surface replacement provenance is missing nodes {missing:?}")]
    IncompleteSurfaceProvenance { missing: Vec<u64> },
    #[error("session tool/result surface replacement must rewrite exactly one current node")]
    ToolResultSurfaceReplaceRange,
    #[error("session tool/result surface replacement must target a current tool/result")]
    ToolResultSurfaceReplaceTarget,
    #[error("session tool/result surface replacement may change only result content")]
    ToolResultSurfaceReplaceDrift,
    #[error("session surface replacement generation overflowed")]
    SurfaceGenerationOverflow,
    #[error("session agent inbox splice must have {expected}")]
    InvalidInboxSplice { expected: &'static str },
    #[error("session agent inbox message `{id}` is already pending")]
    DuplicatePendingMessage { id: String },
    #[error("session agent inbox persisted splice at seq {seq} is invalid")]
    InvalidPersistedInboxSplice { seq: u64 },
    #[error("session `{id}` agent inbox mutation is already being published")]
    InboxMutationInProgress { id: SessionId },
    #[error("session agent inbox live projection drifted from its committed event")]
    InboxProjectionDrift,
    #[error("session agent inbox projection mutex is poisoned")]
    InboxProjectionPoisoned,
    #[error("session seed length {seed_length} exceeds event count {event_count}")]
    SeedBeyondLog { seed_length: u64, event_count: u64 },
    #[error("session `{id}` already exists")]
    SessionAlreadyExists { id: SessionId },
    #[error("session `{id}` was not found")]
    SessionNotFound { id: SessionId },
    #[error("session `{id}` is not live in this store")]
    SessionNotLive { id: SessionId },
    #[error("session `{id}` append is already being published")]
    AppendInProgress { id: SessionId },
    #[error("session flush failed: {message}")]
    FlushFailed { message: String },
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
