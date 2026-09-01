//! Rust-native Cordis Session compaction contracts adapted from DeepSeek Harness.
//!
//! This module owns the durable transaction vocabulary and safe-region seam.
//! Policy, token estimation, summarization, and user-facing commands remain
//! separate layers.

use std::fmt;

use crate::session::{
    SessionContentBlock, SessionError, SessionHandle, SessionId, SessionMessageSource,
    SessionTokenUsage, validate_content_blocks, validate_token_usage,
};

/// Plugin marker carried by every compaction replacement checkpoint.
pub const COMPACTION_CHECKPOINT_PLUGIN: &str = "compact";

/// Stable identity shared by one complete compaction transaction.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Deserialize, serde::Serialize,
)]
#[serde(transparent)]
pub struct CompactionId(String);

impl CompactionId {
    pub fn new(id: impl Into<String>) -> Result<Self, SessionError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SessionError::EmptyCompactionId);
        }
        Ok(Self(id))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), SessionError> {
        if self.0.is_empty() {
            return Err(SessionError::EmptyCompactionId);
        }
        Ok(())
    }
}

impl fmt::Display for CompactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// First and last nodes of an inclusive current-surface span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompactionRange {
    pub start: u64,
    pub end: u64,
}

/// Durable lock marker for one compaction attempt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionCompactionStart {
    pub compaction_id: CompactionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_command_id: Option<String>,
    /// Some(turn) is strictly inside that turn; None is between turns.
    pub turn: Option<u64>,
}

impl SessionCompactionStart {
    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        validate_identity(
            &self.compaction_id,
            self.source_command_id.as_deref(),
            self.turn,
        )?;
        serde_json::to_value(self).map_err(|_| SessionError::InvalidCompactionEncoding)
    }

    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidCompactionEncoding)?;
        if payload.to_json_value()?.ne(value) {
            return Err(SessionError::InvalidCompactionEncoding);
        }
        Ok(payload)
    }
}

/// Durable facts for one completed summary call and its exact shadow price.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionCompactionSummary {
    pub compaction_id: CompactionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_command_id: Option<String>,
    pub summary: Vec<SessionContentBlock>,
    pub shadowed_range: CompactionRange,
    pub shadowed_seqs: Vec<u64>,
    pub shadowed_token_count: u64,
    pub provider: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<SessionTokenUsage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_output: Option<Vec<SessionContentBlock>>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub llm_stream_call: bool,
}

impl SessionCompactionSummary {
    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        self.validate()?;
        serde_json::to_value(self).map_err(|_| SessionError::InvalidCompactionEncoding)
    }

    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidCompactionEncoding)?;
        if payload.to_json_value()?.ne(value) {
            return Err(SessionError::InvalidCompactionEncoding);
        }
        Ok(payload)
    }

    pub(crate) fn validate(&self) -> Result<(), SessionError> {
        validate_identity(&self.compaction_id, self.source_command_id.as_deref(), None)?;
        validate_content_blocks(&self.summary, "compaction/summary")?;
        if self.shadowed_seqs.is_empty() {
            return Err(SessionError::InvalidCompaction {
                expected: "non-empty shadowed sequences",
            });
        }
        if self.shadowed_seqs.first() != Some(&self.shadowed_range.start)
            || self.shadowed_seqs.last() != Some(&self.shadowed_range.end)
        {
            return Err(SessionError::InvalidCompaction {
                expected: "range endpoints matching the first and last shadowed sequences",
            });
        }
        if self.provider.is_empty() || self.model.is_empty() {
            return Err(SessionError::InvalidCompaction {
                expected: "non-empty summary provider and model",
            });
        }
        if self.max_tokens == Some(0) {
            return Err(SessionError::InvalidCompaction {
                expected: "a positive max token cap when present",
            });
        }
        if let Some(usage) = &self.usage {
            validate_token_usage(usage)?;
        }
        if let Some(raw_output) = &self.raw_output {
            validate_content_blocks(raw_output, "compaction/summary raw output")?;
        }
        if self.llm_stream_call && self.raw_output.is_none() {
            return Err(SessionError::InvalidCompaction {
                expected: "raw output for a marked LLM stream call",
            });
        }
        Ok(())
    }
}

/// Durable unlock marker for one successful or failed compaction attempt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionCompactionEnd {
    pub compaction_id: CompactionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_command_id: Option<String>,
    pub turn: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SessionCompactionEnd {
    pub fn to_json_value(&self) -> Result<serde_json::Value, SessionError> {
        validate_identity(
            &self.compaction_id,
            self.source_command_id.as_deref(),
            self.turn,
        )?;
        if self.error.as_ref().is_some_and(String::is_empty) {
            return Err(SessionError::InvalidCompaction {
                expected: "a non-empty failure message when present",
            });
        }
        serde_json::to_value(self).map_err(|_| SessionError::InvalidCompactionEncoding)
    }

    pub fn from_json_value(value: &serde_json::Value) -> Result<Self, SessionError> {
        let payload: Self = serde_json::from_value(value.clone())
            .map_err(|_| SessionError::InvalidCompactionEncoding)?;
        if payload.to_json_value()?.ne(value) {
            return Err(SessionError::InvalidCompactionEncoding);
        }
        Ok(payload)
    }
}

/// Summary-call facts supplied by a future policy/backend implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionSummaryDraft {
    pub summary: Vec<SessionContentBlock>,
    pub shadowed_token_count: u64,
    pub provider: String,
    pub model: String,
    pub max_tokens: Option<u64>,
    pub usage: Option<SessionTokenUsage>,
    pub raw_output: Option<Vec<SessionContentBlock>>,
    pub llm_stream_call: bool,
}

/// Model-visible replacement payload; the Session builds its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionCheckpoint {
    pub message_id: String,
    pub content: Vec<SessionContentBlock>,
}

/// Exact current-surface selection captured when the durable lock is acquired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionRegion {
    pub start: u64,
    pub end: u64,
    pub shadowed_seqs: Vec<u64>,
    pub surface_generation: u64,
}

/// Opaque live transaction proof returned after compaction/start commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionLease {
    pub(crate) session_id: SessionId,
    pub(crate) compaction_id: CompactionId,
    pub(crate) source_command_id: Option<String>,
    pub(crate) turn: Option<u64>,
    pub(crate) start_seq: u64,
    pub(crate) region: CompactionRegion,
}

impl CompactionLease {
    #[must_use]
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub fn compaction_id(&self) -> &CompactionId {
        &self.compaction_id
    }

    #[must_use]
    pub fn source_command_id(&self) -> Option<&str> {
        self.source_command_id.as_deref()
    }

    #[must_use]
    pub const fn turn(&self) -> Option<u64> {
        self.turn
    }

    #[must_use]
    pub const fn start_seq(&self) -> u64 {
        self.start_seq
    }

    #[must_use]
    pub const fn region(&self) -> &CompactionRegion {
        &self.region
    }
}

/// Result of one successfully committed compaction replacement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionResult {
    pub compaction_id: CompactionId,
    pub source_command_id: Option<String>,
    pub start_seq: u64,
    pub summary_seq: u64,
    pub end_seq: u64,
    pub summary: Vec<SessionContentBlock>,
    pub shadowed_range: CompactionRange,
    pub shadowed_seqs: Vec<u64>,
    pub shadowed_token_count: u64,
}

/// Construct the correlated source for one replacement user message.
#[must_use]
pub fn compact_checkpoint_source(
    compaction_id: CompactionId,
    source_command_id: Option<String>,
) -> SessionMessageSource {
    SessionMessageSource::Plugin {
        plugin: COMPACTION_CHECKPOINT_PLUGIN.into(),
        compaction_id: Some(compaction_id),
        source_command_id,
    }
}

/// Recognize persisted replacement checkpoint provenance.
#[must_use]
pub fn is_compact_checkpoint_source(source: &SessionMessageSource) -> bool {
    matches!(
        source,
        SessionMessageSource::Plugin { plugin, .. }
            if plugin == COMPACTION_CHECKPOINT_PLUGIN
    )
}

/// Whether the cut immediately before a current surface node is tool-balanced.
pub fn tool_pairing_balanced_before(
    session: &SessionHandle,
    seq: u64,
) -> Result<bool, SessionError> {
    session.tool_pairing_balanced_at(seq, false)
}

/// Whether the cut immediately after a current surface node is tool-balanced.
pub fn tool_pairing_balanced_after(
    session: &SessionHandle,
    seq: u64,
) -> Result<bool, SessionError> {
    session.tool_pairing_balanced_at(seq, true)
}

pub(crate) fn validate_source_command_id(value: Option<&str>) -> Result<(), SessionError> {
    if value.is_some_and(str::is_empty) {
        return Err(SessionError::InvalidCompaction {
            expected: "a non-empty source command id when present",
        });
    }
    Ok(())
}

fn validate_identity(
    compaction_id: &CompactionId,
    source_command_id: Option<&str>,
    turn: Option<u64>,
) -> Result<(), SessionError> {
    compaction_id.validate()?;
    validate_source_command_id(source_command_id)?;
    if turn == Some(0) {
        return Err(SessionError::InvalidCompaction {
            expected: "a positive owner turn when present",
        });
    }
    Ok(())
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}
