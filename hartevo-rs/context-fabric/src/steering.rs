//! Mission-scoped durable steering input for an active Context turn.
//!
//! The journal is deliberately local to Context Fabric.  It gives a plugin a
//! small, serializable write-ahead boundary without making Runtime, Storage,
//! or Application responsible for the mid-turn protocol.  Input content is
//! appended to the durable content log before an event can expose a reference
//! to it; consumers can therefore only make model-visible content available by
//! reading an already logged record.

use std::collections::BTreeSet;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::MissionId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const STEERING_SCHEMA_VERSION: u32 = 1;

fn sha256_hex(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("{:x}", hasher.finalize())
}

fn text_digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum SteeringError {
    #[error("steering scope or turn fence is invalid")]
    InvalidScope,
    #[error("steering turn fence is stale")]
    StaleFence,
    #[error("steering revision or lease has expired")]
    ExpiredRevision,
    #[error("steering lifecycle is unavailable")]
    LifecycleUnavailable,
    #[error("steering idempotency key conflicts with durable input")]
    IdempotencyConflict,
    #[error("steering content must be durably logged")]
    InvalidContent,
    #[error("steering digest is invalid")]
    InvalidDigest,
    #[error("steering checkpoint is invalid")]
    InvalidCheckpoint,
    #[error("steering compaction conflicts with the durable checkpoint")]
    CompactionConflict,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SteeringSafePoint {
    BeforeFirstDelta,
    DuringStreaming,
    BeforeHumanDecision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SteeringLifecycle {
    Mounted,
    Revoked,
    Unmounted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SteeringEventStatus {
    Pending,
    Consumed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SteeringCancellationReason {
    Unmounted,
    Revoked,
    CrashRecovery,
}

/// The owner/revision/epoch fence attached to every steering operation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteeringTurnFence {
    turn_id_digest: String,
    revision: u64,
    generation: u64,
    attachment_epoch: u64,
    lease_expires_at: DateTime<Utc>,
}

impl fmt::Debug for SteeringTurnFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SteeringTurnFence")
            .field("revision", &self.revision)
            .field("generation", &self.generation)
            .field("attachment_epoch", &self.attachment_epoch)
            .field("lease_present", &true)
            .finish_non_exhaustive()
    }
}

impl SteeringTurnFence {
    pub fn new(
        turn_id: impl AsRef<str>,
        revision: u64,
        generation: u64,
        attachment_epoch: u64,
        lease_expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            turn_id_digest: text_digest(turn_id.as_ref()),
            revision,
            generation,
            attachment_epoch,
            lease_expires_at,
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn attachment_epoch(&self) -> u64 {
        self.attachment_epoch
    }

    pub fn lease_expires_at(&self) -> DateTime<Utc> {
        self.lease_expires_at
    }

    pub fn turn_id_digest(&self) -> &str {
        &self.turn_id_digest
    }

    fn validate_structural(&self) -> Result<(), SteeringError> {
        if !valid_digest(&self.turn_id_digest)
            || self.turn_id_digest == text_digest("")
            || self.generation == 0
            || self.attachment_epoch == 0
        {
            return Err(SteeringError::InvalidScope);
        }
        Ok(())
    }

    fn validate_at(&self, at: DateTime<Utc>) -> Result<(), SteeringError> {
        self.validate_structural()?;
        if self.lease_expires_at <= at {
            return Err(SteeringError::ExpiredRevision);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteeringInput {
    idempotency_key: String,
    content: String,
    safe_point: SteeringSafePoint,
}

impl fmt::Debug for SteeringInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SteeringInput")
            .field("safe_point", &self.safe_point)
            .field("content_present", &true)
            .field("idempotency_present", &true)
            .finish_non_exhaustive()
    }
}

impl SteeringInput {
    pub fn new(
        idempotency_key: impl Into<String>,
        content: impl Into<String>,
        safe_point: SteeringSafePoint,
    ) -> Self {
        Self {
            idempotency_key: idempotency_key.into(),
            content: content.into(),
            safe_point,
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteeringCompactionInput {
    objective_digest: String,
    authority_digest: String,
    tool_result_digests: Vec<String>,
    source_event_sequences: Vec<u64>,
    summary: String,
}

impl fmt::Debug for SteeringCompactionInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SteeringCompactionInput")
            .field("tool_result_count", &self.tool_result_digests.len())
            .field("source_event_count", &self.source_event_sequences.len())
            .field("summary_present", &true)
            .finish_non_exhaustive()
    }
}

impl SteeringCompactionInput {
    pub fn new(
        objective_digest: impl Into<String>,
        authority_digest: impl Into<String>,
        tool_result_digests: Vec<String>,
        source_event_sequences: Vec<u64>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            objective_digest: objective_digest.into(),
            authority_digest: authority_digest.into(),
            tool_result_digests,
            source_event_sequences,
            summary: summary.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteeringMicroCompaction {
    objective_digest: String,
    authority_digest: String,
    tool_result_digests: Vec<String>,
    summary_digest: String,
    summary_log_sequence: u64,
    source_event_sequences: Vec<u64>,
    created_at: DateTime<Utc>,
}

impl SteeringMicroCompaction {
    pub fn objective_digest(&self) -> &str {
        &self.objective_digest
    }

    pub fn authority_digest(&self) -> &str {
        &self.authority_digest
    }

    pub fn tool_result_digests(&self) -> &[String] {
        &self.tool_result_digests
    }

    pub fn summary_digest(&self) -> &str {
        &self.summary_digest
    }

    pub fn summary_log_sequence(&self) -> u64 {
        self.summary_log_sequence
    }

    pub fn source_event_sequences(&self) -> &[u64] {
        &self.source_event_sequences
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteeringDurableEvent {
    sequence: u64,
    event_id_digest: String,
    mission_id: MissionId,
    turn_id_digest: String,
    revision: u64,
    generation: u64,
    attachment_epoch: u64,
    idempotency_digest: String,
    content_digest: String,
    content_log_sequence: u64,
    safe_point: SteeringSafePoint,
    status: SteeringEventStatus,
    accepted_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    cancelled_at: Option<DateTime<Utc>>,
    cancellation_reason: Option<SteeringCancellationReason>,
}

impl fmt::Debug for SteeringDurableEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SteeringDurableEvent")
            .field("sequence", &self.sequence)
            .field("safe_point", &self.safe_point)
            .field("status", &self.status)
            .field("content_present", &true)
            .field("consumed", &self.consumed_at.is_some())
            .field("cancelled", &self.cancelled_at.is_some())
            .finish_non_exhaustive()
    }
}

impl SteeringDurableEvent {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn safe_point(&self) -> SteeringSafePoint {
        self.safe_point
    }

    pub fn status(&self) -> SteeringEventStatus {
        self.status
    }

    pub fn content_log_sequence(&self) -> u64 {
        self.content_log_sequence
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub fn accepted_at(&self) -> DateTime<Utc> {
        self.accepted_at
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteeringConsumedInput {
    event_sequence: u64,
    safe_point: SteeringSafePoint,
    content: String,
    content_digest: String,
    revision: u64,
    generation: u64,
    attachment_epoch: u64,
}

impl fmt::Debug for SteeringConsumedInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SteeringConsumedInput")
            .field("event_sequence", &self.event_sequence)
            .field("safe_point", &self.safe_point)
            .field("content_present", &true)
            .field("content_digest_present", &true)
            .finish_non_exhaustive()
    }
}

impl SteeringConsumedInput {
    pub fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    pub fn safe_point(&self) -> SteeringSafePoint {
        self.safe_point
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SteeringSubmitOutcome {
    Accepted {
        event_sequence: u64,
        content_log_sequence: u64,
    },
    Replay {
        event_sequence: u64,
        status: SteeringEventStatus,
    },
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteeringJournal {
    schema_version: u32,
    mission_id: MissionId,
    fence: SteeringTurnFence,
    lifecycle: SteeringLifecycle,
    next_event_sequence: u64,
    next_content_sequence: u64,
    content_log: Vec<SteeringContentRecord>,
    events: Vec<SteeringDurableEvent>,
    micro_compaction: Option<SteeringMicroCompaction>,
    crash_recoveries: u64,
}

impl fmt::Debug for SteeringJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SteeringJournal")
            .field("schema_version", &self.schema_version)
            .field("lifecycle", &self.lifecycle)
            .field("event_count", &self.events.len())
            .field("content_log_count", &self.content_log.len())
            .field("micro_compaction_present", &self.micro_compaction.is_some())
            .field("crash_recoveries", &self.crash_recoveries)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
struct SteeringContentRecord {
    log_sequence: u64,
    content_digest: String,
    content: String,
    logged_at: DateTime<Utc>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SteeringCheckpoint {
    schema_version: u32,
    journal: SteeringJournal,
    journal_digest: String,
}

impl fmt::Debug for SteeringCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SteeringCheckpoint")
            .field("schema_version", &self.schema_version)
            .field("journal", &self.journal)
            .field("digest_present", &true)
            .finish_non_exhaustive()
    }
}

impl SteeringCheckpoint {
    pub fn journal(&self) -> &SteeringJournal {
        &self.journal
    }

    fn validate(&self) -> Result<(), SteeringError> {
        if self.schema_version != STEERING_SCHEMA_VERSION {
            return Err(SteeringError::InvalidCheckpoint);
        }
        self.journal.validate_structural()?;
        let bytes =
            serde_json::to_vec(&self.journal).map_err(|_| SteeringError::InvalidCheckpoint)?;
        if sha256_hex(&bytes) != self.journal_digest {
            return Err(SteeringError::InvalidCheckpoint);
        }
        Ok(())
    }
}

impl SteeringJournal {
    fn new(mission_id: MissionId, fence: SteeringTurnFence) -> Result<Self, SteeringError> {
        fence.validate_structural()?;
        if mission_id.as_str().trim().is_empty() {
            return Err(SteeringError::InvalidScope);
        }
        Ok(Self {
            schema_version: STEERING_SCHEMA_VERSION,
            mission_id,
            fence,
            lifecycle: SteeringLifecycle::Mounted,
            next_event_sequence: 1,
            next_content_sequence: 1,
            content_log: Vec::new(),
            events: Vec::new(),
            micro_compaction: None,
            crash_recoveries: 0,
        })
    }

    fn validate_content_log(&self) -> Result<BTreeSet<u64>, SteeringError> {
        let mut sequences = BTreeSet::new();
        for content in &self.content_log {
            if content.log_sequence == 0
                || content.log_sequence >= self.next_content_sequence
                || !valid_digest(&content.content_digest)
                || text_digest(&content.content) != content.content_digest
                || !sequences.insert(content.log_sequence)
            {
                return Err(SteeringError::InvalidCheckpoint);
            }
        }
        Ok(sequences)
    }

    fn validate_events(
        &self,
        content_sequences: &BTreeSet<u64>,
    ) -> Result<BTreeSet<u64>, SteeringError> {
        let mut event_sequences = BTreeSet::new();
        let mut idempotency_digests = BTreeSet::new();
        for event in &self.events {
            if event.sequence == 0
                || event.sequence >= self.next_event_sequence
                || event.mission_id != self.mission_id
                || !valid_digest(&event.turn_id_digest)
                || event.generation == 0
                || event.attachment_epoch == 0
                || !valid_digest(&event.event_id_digest)
                || !valid_digest(&event.idempotency_digest)
                || !valid_digest(&event.content_digest)
                || !event_sequences.insert(event.sequence)
                || !idempotency_digests.insert(event.idempotency_digest.clone())
                || !content_sequences.contains(&event.content_log_sequence)
            {
                return Err(SteeringError::InvalidCheckpoint);
            }
            let expected_event_id = text_digest(&format!(
                "{}:{}:{}:{}",
                self.mission_id, event.idempotency_digest, event.revision, event.sequence
            ));
            if event.event_id_digest != expected_event_id {
                return Err(SteeringError::InvalidCheckpoint);
            }
            let content = self
                .content_log
                .iter()
                .find(|record| record.log_sequence == event.content_log_sequence)
                .ok_or(SteeringError::InvalidCheckpoint)?;
            if content.content_digest != event.content_digest {
                return Err(SteeringError::InvalidCheckpoint);
            }
            let valid_status = match event.status {
                SteeringEventStatus::Pending => {
                    event.consumed_at.is_none()
                        && event.cancelled_at.is_none()
                        && event.cancellation_reason.is_none()
                }
                SteeringEventStatus::Consumed => {
                    event.consumed_at.is_some()
                        && event.cancelled_at.is_none()
                        && event.cancellation_reason.is_none()
                }
                SteeringEventStatus::Cancelled => {
                    event.cancelled_at.is_some()
                        && event.consumed_at.is_none()
                        && event.cancellation_reason.is_some()
                }
            };
            let valid_timing = event
                .consumed_at
                .or(event.cancelled_at)
                .is_none_or(|completed_at| completed_at >= event.accepted_at);
            if !valid_status || !valid_timing {
                return Err(SteeringError::InvalidCheckpoint);
            }
        }
        Ok(event_sequences)
    }

    fn validate_compaction(
        &self,
        content_sequences: &BTreeSet<u64>,
        event_sequences: &BTreeSet<u64>,
    ) -> Result<(), SteeringError> {
        let Some(compaction) = &self.micro_compaction else {
            return Ok(());
        };
        if !valid_digest(&compaction.objective_digest)
            || !valid_digest(&compaction.authority_digest)
            || !valid_digest(&compaction.summary_digest)
            || compaction.summary_log_sequence == 0
            || !content_sequences.contains(&compaction.summary_log_sequence)
            || compaction.source_event_sequences.is_empty()
            || compaction
                .tool_result_digests
                .iter()
                .any(|digest| !valid_digest(digest))
        {
            return Err(SteeringError::InvalidCheckpoint);
        }
        let mut sources = BTreeSet::new();
        for sequence in &compaction.source_event_sequences {
            if !event_sequences.contains(sequence) || !sources.insert(*sequence) {
                return Err(SteeringError::InvalidCheckpoint);
            }
        }
        let summary = self
            .content_log
            .iter()
            .find(|record| record.log_sequence == compaction.summary_log_sequence)
            .ok_or(SteeringError::InvalidCheckpoint)?;
        if summary.content_digest != compaction.summary_digest {
            return Err(SteeringError::InvalidCheckpoint);
        }
        Ok(())
    }

    fn validate_structural(&self) -> Result<(), SteeringError> {
        if self.schema_version != STEERING_SCHEMA_VERSION
            || self.mission_id.as_str().trim().is_empty()
        {
            return Err(SteeringError::InvalidCheckpoint);
        }
        self.fence
            .validate_structural()
            .map_err(|_| SteeringError::InvalidCheckpoint)?;
        let content_sequences = self.validate_content_log()?;
        let event_sequences = self.validate_events(&content_sequences)?;
        self.validate_compaction(&content_sequences, &event_sequences)
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn fence(&self) -> &SteeringTurnFence {
        &self.fence
    }

    pub fn lifecycle(&self) -> SteeringLifecycle {
        self.lifecycle
    }

    pub fn events(&self) -> &[SteeringDurableEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn content_log_len(&self) -> usize {
        self.content_log.len()
    }

    pub fn pending_event_count(&self) -> usize {
        self.events
            .iter()
            .filter(|event| event.status == SteeringEventStatus::Pending)
            .count()
    }

    pub fn micro_compaction(&self) -> Option<&SteeringMicroCompaction> {
        self.micro_compaction.as_ref()
    }

    pub fn crash_recoveries(&self) -> u64 {
        self.crash_recoveries
    }

    pub fn model_visible_content(&self, log_sequence: u64) -> Result<&str, SteeringError> {
        self.content_log
            .iter()
            .find(|record| record.log_sequence == log_sequence)
            .map(|record| record.content.as_str())
            .ok_or(SteeringError::InvalidCheckpoint)
    }

    fn ensure_active(
        &self,
        expected: &SteeringTurnFence,
        at: DateTime<Utc>,
    ) -> Result<(), SteeringError> {
        self.validate_structural()?;
        expected.validate_structural()?;
        if expected != &self.fence {
            return Err(SteeringError::StaleFence);
        }
        if self.lifecycle != SteeringLifecycle::Mounted {
            return Err(SteeringError::LifecycleUnavailable);
        }
        self.fence.validate_at(at)
    }

    fn ensure_owner(
        &self,
        expected: &SteeringTurnFence,
        at: DateTime<Utc>,
    ) -> Result<(), SteeringError> {
        self.ensure_active(expected, at)
    }

    fn append_content(&mut self, content: String, at: DateTime<Utc>) -> (u64, String) {
        let sequence = self.next_content_sequence;
        self.next_content_sequence += 1;
        let digest = text_digest(&content);
        self.content_log.push(SteeringContentRecord {
            log_sequence: sequence,
            content_digest: digest.clone(),
            content,
            logged_at: at,
        });
        (sequence, digest)
    }

    fn cancel_pending(&mut self, reason: SteeringCancellationReason, at: DateTime<Utc>) {
        for event in &mut self.events {
            if event.status == SteeringEventStatus::Pending {
                event.status = SteeringEventStatus::Cancelled;
                event.cancelled_at = Some(at);
                event.cancellation_reason = Some(reason);
            }
        }
    }

    fn submit(
        &mut self,
        expected: &SteeringTurnFence,
        input: SteeringInput,
        at: DateTime<Utc>,
    ) -> Result<SteeringSubmitOutcome, SteeringError> {
        self.ensure_active(expected, at)?;
        if input.idempotency_key.trim().is_empty() || input.content.trim().is_empty() {
            return Err(SteeringError::InvalidContent);
        }
        let idempotency_digest = text_digest(&input.idempotency_key);
        let content_digest = text_digest(&input.content);
        if let Some(existing) = self
            .events
            .iter()
            .find(|event| event.idempotency_digest == idempotency_digest)
        {
            if existing.content_digest != content_digest {
                return Err(SteeringError::IdempotencyConflict);
            }
            return Ok(SteeringSubmitOutcome::Replay {
                event_sequence: existing.sequence,
                status: existing.status,
            });
        }

        let (content_log_sequence, content_digest) = self.append_content(input.content, at);
        let event_sequence = self.next_event_sequence;
        self.next_event_sequence += 1;
        let event_id_digest = text_digest(&format!(
            "{}:{}:{}:{}",
            self.mission_id, idempotency_digest, self.fence.revision, event_sequence
        ));
        self.events.push(SteeringDurableEvent {
            sequence: event_sequence,
            event_id_digest,
            mission_id: self.mission_id.clone(),
            turn_id_digest: self.fence.turn_id_digest.clone(),
            revision: self.fence.revision,
            generation: self.fence.generation,
            attachment_epoch: self.fence.attachment_epoch,
            idempotency_digest,
            content_digest,
            content_log_sequence,
            safe_point: input.safe_point,
            status: SteeringEventStatus::Pending,
            accepted_at: at,
            consumed_at: None,
            cancelled_at: None,
            cancellation_reason: None,
        });
        self.validate_structural()?;
        Ok(SteeringSubmitOutcome::Accepted {
            event_sequence,
            content_log_sequence,
        })
    }

    fn consume(
        &mut self,
        expected: &SteeringTurnFence,
        safe_point: SteeringSafePoint,
        at: DateTime<Utc>,
    ) -> Result<Option<SteeringConsumedInput>, SteeringError> {
        self.ensure_active(expected, at)?;
        let Some(index) = self.events.iter().position(|event| {
            event.status == SteeringEventStatus::Pending && event.safe_point == safe_point
        }) else {
            return Ok(None);
        };
        let event = self.events[index].clone();
        let content = self
            .content_log
            .iter()
            .find(|record| record.log_sequence == event.content_log_sequence)
            .ok_or(SteeringError::InvalidCheckpoint)?;
        if content.content_digest != event.content_digest {
            return Err(SteeringError::InvalidCheckpoint);
        }
        self.events[index].status = SteeringEventStatus::Consumed;
        self.events[index].consumed_at = Some(at);
        self.validate_structural()?;
        Ok(Some(SteeringConsumedInput {
            event_sequence: event.sequence,
            safe_point: event.safe_point,
            content: content.content.clone(),
            content_digest: content.content_digest.clone(),
            revision: event.revision,
            generation: event.generation,
            attachment_epoch: event.attachment_epoch,
        }))
    }

    fn compact(
        &mut self,
        expected: &SteeringTurnFence,
        input: SteeringCompactionInput,
        at: DateTime<Utc>,
    ) -> Result<SteeringMicroCompaction, SteeringError> {
        self.ensure_active(expected, at)?;
        if !valid_digest(&input.objective_digest)
            || !valid_digest(&input.authority_digest)
            || input.source_event_sequences.is_empty()
            || input.summary.trim().is_empty()
            || input
                .tool_result_digests
                .iter()
                .any(|digest| !valid_digest(digest))
        {
            return Err(SteeringError::InvalidDigest);
        }
        let mut sources = BTreeSet::new();
        for sequence in &input.source_event_sequences {
            if !self.events.iter().any(|event| event.sequence == *sequence)
                || !sources.insert(*sequence)
            {
                return Err(SteeringError::InvalidCheckpoint);
            }
        }
        let summary_digest = text_digest(&input.summary);
        if let Some(existing) = &self.micro_compaction {
            if existing.objective_digest == input.objective_digest
                && existing.authority_digest == input.authority_digest
                && existing.tool_result_digests == input.tool_result_digests
                && existing.summary_digest == summary_digest
                && existing.source_event_sequences == input.source_event_sequences
            {
                return Ok(existing.clone());
            }
            return Err(SteeringError::CompactionConflict);
        }
        let (summary_log_sequence, _) = self.append_content(input.summary, at);
        let compaction = SteeringMicroCompaction {
            objective_digest: input.objective_digest,
            authority_digest: input.authority_digest,
            tool_result_digests: input.tool_result_digests,
            summary_digest,
            summary_log_sequence,
            source_event_sequences: input.source_event_sequences,
            created_at: at,
        };
        self.micro_compaction = Some(compaction.clone());
        self.validate_structural()?;
        Ok(compaction)
    }
}

pub trait SteeringProvider {
    fn submit_mid_turn_input(
        &mut self,
        expected: &SteeringTurnFence,
        input: SteeringInput,
        at: DateTime<Utc>,
    ) -> Result<SteeringSubmitOutcome, SteeringError>;

    fn micro_compact(
        &mut self,
        expected: &SteeringTurnFence,
        input: SteeringCompactionInput,
        at: DateTime<Utc>,
    ) -> Result<SteeringMicroCompaction, SteeringError>;
}

pub trait SteeringConsumer {
    fn consume_at_safe_point(
        &mut self,
        expected: &SteeringTurnFence,
        safe_point: SteeringSafePoint,
        at: DateTime<Utc>,
    ) -> Result<Option<SteeringConsumedInput>, SteeringError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct SteeringPluginService {
    journal: SteeringJournal,
}

impl fmt::Debug for SteeringPluginService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SteeringPluginService")
            .field("journal", &self.journal)
            .finish_non_exhaustive()
    }
}

impl SteeringPluginService {
    pub fn new(
        mission_id: MissionId,
        fence: SteeringTurnFence,
        at: DateTime<Utc>,
    ) -> Result<Self, SteeringError> {
        fence.validate_at(at)?;
        Ok(Self {
            journal: SteeringJournal::new(mission_id, fence)?,
        })
    }

    pub fn journal(&self) -> &SteeringJournal {
        &self.journal
    }

    pub fn checkpoint(&self) -> Result<SteeringCheckpoint, SteeringError> {
        self.journal.validate_structural()?;
        let bytes =
            serde_json::to_vec(&self.journal).map_err(|_| SteeringError::InvalidCheckpoint)?;
        Ok(SteeringCheckpoint {
            schema_version: STEERING_SCHEMA_VERSION,
            journal: self.journal.clone(),
            journal_digest: sha256_hex(&bytes),
        })
    }

    pub fn reopen(
        checkpoint: &SteeringCheckpoint,
        at: DateTime<Utc>,
    ) -> Result<Self, SteeringError> {
        checkpoint.validate()?;
        checkpoint.journal.fence.validate_at(at)?;
        Ok(Self {
            journal: checkpoint.journal.clone(),
        })
    }

    pub fn recover_after_crash(
        checkpoint: &SteeringCheckpoint,
        replacement_fence: SteeringTurnFence,
        at: DateTime<Utc>,
    ) -> Result<Self, SteeringError> {
        checkpoint.validate()?;
        replacement_fence.validate_at(at)?;
        if replacement_fence.generation <= checkpoint.journal.fence.generation
            || replacement_fence.revision < checkpoint.journal.fence.revision
        {
            return Err(SteeringError::StaleFence);
        }
        let mut journal = checkpoint.journal.clone();
        journal.fence = replacement_fence;
        journal.lifecycle = SteeringLifecycle::Mounted;
        journal.cancel_pending(SteeringCancellationReason::CrashRecovery, at);
        journal.crash_recoveries += 1;
        journal.validate_structural()?;
        Ok(Self { journal })
    }

    pub fn unmount(
        &mut self,
        expected: &SteeringTurnFence,
        at: DateTime<Utc>,
    ) -> Result<(), SteeringError> {
        self.journal.ensure_owner(expected, at)?;
        self.journal
            .cancel_pending(SteeringCancellationReason::Unmounted, at);
        self.journal.lifecycle = SteeringLifecycle::Unmounted;
        Ok(())
    }

    pub fn revoke(
        &mut self,
        expected: &SteeringTurnFence,
        at: DateTime<Utc>,
    ) -> Result<(), SteeringError> {
        self.journal.ensure_owner(expected, at)?;
        self.journal
            .cancel_pending(SteeringCancellationReason::Revoked, at);
        self.journal.lifecycle = SteeringLifecycle::Revoked;
        Ok(())
    }
}

impl SteeringProvider for SteeringPluginService {
    fn submit_mid_turn_input(
        &mut self,
        expected: &SteeringTurnFence,
        input: SteeringInput,
        at: DateTime<Utc>,
    ) -> Result<SteeringSubmitOutcome, SteeringError> {
        self.journal.submit(expected, input, at)
    }

    fn micro_compact(
        &mut self,
        expected: &SteeringTurnFence,
        input: SteeringCompactionInput,
        at: DateTime<Utc>,
    ) -> Result<SteeringMicroCompaction, SteeringError> {
        self.journal.compact(expected, input, at)
    }
}

impl SteeringConsumer for SteeringPluginService {
    fn consume_at_safe_point(
        &mut self,
        expected: &SteeringTurnFence,
        safe_point: SteeringSafePoint,
        at: DateTime<Utc>,
    ) -> Result<Option<SteeringConsumedInput>, SteeringError> {
        self.journal.consume(expected, safe_point, at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000 + second, 0)
            .single()
            .expect("valid test time")
    }

    fn make_fence(revision: u64, generation: u64, epoch: u64) -> SteeringTurnFence {
        SteeringTurnFence::new("turn-steer-01", revision, generation, epoch, at(600))
    }

    fn new_service() -> (SteeringPluginService, SteeringTurnFence) {
        let fence = make_fence(7, 2, 3);
        (
            SteeringPluginService::new(MissionId::from("mission-steer-01"), fence.clone(), at(0))
                .expect("service"),
            fence,
        )
    }

    #[test]
    fn mid_turn_input_is_revision_bound_durable_and_consumed_once_at_safe_point() {
        let (mut service, active_fence) = new_service();
        let accepted = service
            .submit_mid_turn_input(
                &active_fence,
                SteeringInput::new(
                    "input-1",
                    "change the evidence question",
                    SteeringSafePoint::DuringStreaming,
                ),
                at(1),
            )
            .expect("accepted");
        let SteeringSubmitOutcome::Accepted {
            event_sequence,
            content_log_sequence,
        } = accepted
        else {
            panic!("first input cannot replay")
        };
        assert_eq!(event_sequence, 1);
        assert_eq!(content_log_sequence, 1);
        assert_eq!(service.journal().content_log_len(), 1);
        assert_eq!(service.journal().pending_event_count(), 1);
        assert!(
            service
                .consume_at_safe_point(&active_fence, SteeringSafePoint::BeforeFirstDelta, at(2))
                .expect("safe point")
                .is_none()
        );
        let consumed = service
            .consume_at_safe_point(&active_fence, SteeringSafePoint::DuringStreaming, at(3))
            .expect("consume")
            .expect("pending input");
        assert_eq!(consumed.content(), "change the evidence question");
        assert_eq!(service.journal().pending_event_count(), 0);
        assert!(
            service
                .consume_at_safe_point(&active_fence, SteeringSafePoint::DuringStreaming, at(4))
                .expect("no replay")
                .is_none()
        );
        assert_eq!(
            service.submit_mid_turn_input(
                &active_fence,
                SteeringInput::new(
                    "input-1",
                    "change the evidence question",
                    SteeringSafePoint::DuringStreaming,
                ),
                at(5),
            ),
            Ok(SteeringSubmitOutcome::Replay {
                event_sequence: 1,
                status: SteeringEventStatus::Consumed,
            })
        );
        assert_eq!(
            service.submit_mid_turn_input(
                &active_fence,
                SteeringInput::new("input-1", "different", SteeringSafePoint::DuringStreaming),
                at(6),
            ),
            Err(SteeringError::IdempotencyConflict)
        );
        let debug = format!("{service:?}");
        assert!(!debug.contains("change the evidence question"));
        let checkpoint = service.checkpoint().expect("checkpoint");
        let reopened = SteeringPluginService::reopen(&checkpoint, at(7)).expect("reopen");
        assert_eq!(reopened.journal().events(), service.journal().events());
    }

    #[test]
    fn stale_or_expired_revision_is_rejected_without_mutation() {
        let (mut service, _active_fence) = new_service();
        let before = service.journal().clone();
        let stale = make_fence(6, 2, 3);
        assert_eq!(
            service.submit_mid_turn_input(
                &stale,
                SteeringInput::new(
                    "stale",
                    "must not enter",
                    SteeringSafePoint::BeforeFirstDelta
                ),
                at(1),
            ),
            Err(SteeringError::StaleFence)
        );
        assert_eq!(service.journal(), &before);
        let expired = make_fence(7, 2, 3);
        assert_eq!(
            service.consume_at_safe_point(&expired, SteeringSafePoint::BeforeFirstDelta, at(601)),
            Err(SteeringError::ExpiredRevision)
        );
        assert_eq!(service.journal(), &before);
    }

    #[test]
    fn micro_compaction_logs_model_visible_summary_and_retains_references() {
        let (mut service, active_fence) = new_service();
        let digest = |value: &str| text_digest(value);
        service
            .submit_mid_turn_input(
                &active_fence,
                SteeringInput::new(
                    "input-1",
                    "first delta",
                    SteeringSafePoint::BeforeFirstDelta,
                ),
                at(1),
            )
            .expect("input");
        let compaction = service
            .micro_compact(
                &active_fence,
                SteeringCompactionInput::new(
                    digest("objective"),
                    digest("authority"),
                    vec![digest("tool-result")],
                    vec![1],
                    "durable summary",
                ),
                at(2),
            )
            .expect("compaction");
        assert_eq!(compaction.source_event_sequences(), &[1]);
        assert_eq!(compaction.summary_log_sequence(), 2);
        assert_eq!(
            service
                .journal()
                .model_visible_content(compaction.summary_log_sequence())
                .expect("logged summary"),
            "durable summary"
        );
        assert!(!format!("{service:?}").contains("durable summary"));
        assert_eq!(
            service
                .micro_compact(
                    &active_fence,
                    SteeringCompactionInput::new(
                        digest("objective"),
                        digest("authority"),
                        vec![digest("tool-result")],
                        vec![1],
                        "durable summary",
                    ),
                    at(3),
                )
                .expect("idempotent compaction"),
            compaction
        );
    }

    #[test]
    fn unmount_revoke_and_crash_cancel_pending_and_recover_without_replay() {
        let (mut service, active_fence) = new_service();
        service
            .submit_mid_turn_input(
                &active_fence,
                SteeringInput::new(
                    "input-1",
                    "cancel me",
                    SteeringSafePoint::BeforeHumanDecision,
                ),
                at(1),
            )
            .expect("input");
        let checkpoint = service.checkpoint().expect("checkpoint");
        let replacement = make_fence(8, 3, 4);
        let mut recovered =
            SteeringPluginService::recover_after_crash(&checkpoint, replacement.clone(), at(4))
                .expect("recovery");
        assert_eq!(recovered.journal().pending_event_count(), 0);
        assert_eq!(recovered.journal().event_count(), 1);
        assert_eq!(
            recovered.consume_at_safe_point(
                &replacement,
                SteeringSafePoint::BeforeHumanDecision,
                at(5),
            ),
            Ok(None)
        );
        recovered
            .submit_mid_turn_input(
                &replacement,
                SteeringInput::new(
                    "input-2",
                    "new turn input",
                    SteeringSafePoint::BeforeHumanDecision,
                ),
                at(6),
            )
            .expect("new input");
        recovered.revoke(&replacement, at(7)).expect("revoke");
        assert_eq!(recovered.journal().pending_event_count(), 0);
        assert_eq!(
            recovered.submit_mid_turn_input(
                &replacement,
                SteeringInput::new("input-3", "blocked", SteeringSafePoint::BeforeHumanDecision),
                at(8),
            ),
            Err(SteeringError::LifecycleUnavailable)
        );

        let (mut unmounted, unmount_fence) = new_service();
        unmounted
            .submit_mid_turn_input(
                &unmount_fence,
                SteeringInput::new("input-4", "unmounted", SteeringSafePoint::DuringStreaming),
                at(1),
            )
            .expect("input");
        unmounted.unmount(&unmount_fence, at(2)).expect("unmount");
        assert_eq!(unmounted.journal().pending_event_count(), 0);
    }

    #[test]
    fn checkpoint_digest_rejects_tampered_model_visible_content() {
        let (mut service, active_fence) = new_service();
        service
            .submit_mid_turn_input(
                &active_fence,
                SteeringInput::new(
                    "input-1",
                    "durable input",
                    SteeringSafePoint::DuringStreaming,
                ),
                at(1),
            )
            .expect("input");
        let mut checkpoint = service.checkpoint().expect("checkpoint");
        checkpoint.journal.content_log[0].content = "tampered".to_owned();
        assert_eq!(
            SteeringPluginService::reopen(&checkpoint, at(2)),
            Err(SteeringError::InvalidCheckpoint)
        );
    }
}
