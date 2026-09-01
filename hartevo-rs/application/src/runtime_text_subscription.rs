//! Restart-safe, read-only projection of SQLCipher-private Runtime text.
//!
//! This boundary returns a stable Mission execution handle immediately after
//! the existing atomic Catalog Mission start commits. Subsequent reads pull
//! integrity-checked private deltas from the durable Application API. It does
//! not start a Runtime, execute an Effect, append an Event, or mutate an
//! Outbox.

// The host mount for this support-only Operations slice is intentionally
// outside this change. Keep the typed provider/consumer available to the
// module's dedicated contract tests without wiring a new production path.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Mission, MissionConversation, MissionConversationId, MissionId, ProjectId, RuntimeTurnAttempt,
    RuntimeTurnPrivateTextDelta, RuntimeTurnStatus, TenantId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use hartevo_storage::DomainEventRecord;

use crate::{ApplicationError, ApplicationService, StartCatalogMission};

pub const RUNTIME_TEXT_SUBSCRIPTION_MAX_PAGE_SIZE: usize = 64;
const SHA256_HEX_LENGTH: usize = 64;
const DIGEST_LABEL_LENGTH: usize = 8;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CatalogMissionExecutionHandle {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    manifest_id: String,
    manifest_version: u32,
    catalog_digest: String,
    conversation_id: MissionConversationId,
    mission_created_at: DateTime<Utc>,
    contract_digest: String,
    handle_digest: String,
}

impl CatalogMissionExecutionHandle {
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }

    pub const fn manifest_version(&self) -> u32 {
        self.manifest_version
    }

    pub fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }

    pub fn conversation_id(&self) -> &MissionConversationId {
        &self.conversation_id
    }

    pub const fn mission_created_at(&self) -> DateTime<Utc> {
        self.mission_created_at
    }

    pub fn contract_digest(&self) -> &str {
        &self.contract_digest
    }

    pub fn handle_digest(&self) -> &str {
        &self.handle_digest
    }

    fn from_durable(
        mission: &Mission,
        conversation: &MissionConversation,
    ) -> Result<Self, RuntimeTextSubscriptionError> {
        let definition = mission
            .definition
            .as_ref()
            .ok_or(RuntimeTextSubscriptionError::InvalidMissionHandleSource)?;
        let stable_conversation_id = MissionConversationId::from_stable(format!(
            "mission-conversation:{}",
            mission.id.as_str()
        ));
        if conversation.tenant_id != mission.tenant_id
            || conversation.project_id != mission.project_id
            || conversation.mission_id != mission.id
            || conversation.id != stable_conversation_id
        {
            return Err(RuntimeTextSubscriptionError::InvalidMissionHandleSource);
        }
        let contract_digest = digest_json(&mission.contract)?;
        let mut handle = Self {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            manifest_id: definition.manifest_id.clone(),
            manifest_version: definition.manifest_version,
            catalog_digest: definition.catalog_digest.clone(),
            conversation_id: conversation.id.clone(),
            mission_created_at: mission.created_at,
            contract_digest,
            handle_digest: String::new(),
        };
        handle.handle_digest = handle.computed_digest()?;
        handle.validate_shape()?;
        Ok(handle)
    }

    fn validate_shape(&self) -> Result<(), RuntimeTextSubscriptionError> {
        let stable_conversation_id = MissionConversationId::from_stable(format!(
            "mission-conversation:{}",
            self.mission_id.as_str()
        ));
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.manifest_id.trim().is_empty()
            || self.manifest_version == 0
            || self.conversation_id != stable_conversation_id
            || !is_digest(&self.catalog_digest)
            || !is_digest(&self.contract_digest)
            || !is_digest(&self.handle_digest)
            || self.computed_digest()? != self.handle_digest
        {
            return Err(RuntimeTextSubscriptionError::MissionHandleMismatch);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Result<String, RuntimeTextSubscriptionError> {
        digest_json(&CatalogMissionExecutionHandleDigestMaterial {
            tenant_id: self.tenant_id.as_str(),
            project_id: self.project_id.as_str(),
            mission_id: self.mission_id.as_str(),
            manifest_id: &self.manifest_id,
            manifest_version: self.manifest_version,
            catalog_digest: &self.catalog_digest,
            conversation_id: self.conversation_id.as_str(),
            mission_created_at: self.mission_created_at,
            contract_digest: &self.contract_digest,
        })
    }
}

impl fmt::Debug for CatalogMissionExecutionHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogMissionExecutionHandle")
            .field("handle", &ShortDigest(&self.handle_digest))
            .field("catalog", &ShortDigest(&self.catalog_digest))
            .field("contract", &ShortDigest(&self.contract_digest))
            .field("manifest_version", &self.manifest_version)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogMissionExecutionHandleDigestMaterial<'a> {
    tenant_id: &'a str,
    project_id: &'a str,
    mission_id: &'a str,
    manifest_id: &'a str,
    manifest_version: u32,
    catalog_digest: &'a str,
    conversation_id: &'a str,
    mission_created_at: DateTime<Utc>,
    contract_digest: &'a str,
}

#[derive(Clone, PartialEq)]
pub struct CatalogMissionExecutionStart {
    mission: Mission,
    handle: CatalogMissionExecutionHandle,
}

impl CatalogMissionExecutionStart {
    pub fn mission(&self) -> &Mission {
        &self.mission
    }

    pub fn handle(&self) -> &CatalogMissionExecutionHandle {
        &self.handle
    }

    pub fn into_parts(self) -> (Mission, CatalogMissionExecutionHandle) {
        (self.mission, self.handle)
    }
}

impl fmt::Debug for CatalogMissionExecutionStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogMissionExecutionStart")
            .field("handle", &self.handle)
            .field("mission_stage", &self.mission.stage)
            .field("mission_revision", &self.mission.revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeTextSubscriptionCursor {
    handle_digest: String,
    turn_identity_digest: String,
    worker_generation: u64,
    after_evidence_sequence: Option<u64>,
    observed_turn_revision: u64,
    observed_turn_status: RuntimeTurnStatus,
    cursor_digest: String,
}

impl RuntimeTextSubscriptionCursor {
    pub fn handle_digest(&self) -> &str {
        &self.handle_digest
    }

    pub fn turn_identity_digest(&self) -> &str {
        &self.turn_identity_digest
    }

    pub const fn worker_generation(&self) -> u64 {
        self.worker_generation
    }

    pub const fn after_evidence_sequence(&self) -> Option<u64> {
        self.after_evidence_sequence
    }

    pub const fn observed_turn_revision(&self) -> u64 {
        self.observed_turn_revision
    }

    pub const fn observed_turn_status(&self) -> RuntimeTurnStatus {
        self.observed_turn_status
    }

    pub fn cursor_digest(&self) -> &str {
        &self.cursor_digest
    }

    fn for_turn(
        handle: &CatalogMissionExecutionHandle,
        turn: &RuntimeTextSubscriptionTurn,
        after_evidence_sequence: Option<u64>,
    ) -> Result<Self, RuntimeTextSubscriptionError> {
        let mut cursor = Self {
            handle_digest: handle.handle_digest.clone(),
            turn_identity_digest: turn.turn_identity_digest.clone(),
            worker_generation: turn.worker_generation,
            after_evidence_sequence,
            observed_turn_revision: turn.turn_revision,
            observed_turn_status: turn.turn_status,
            cursor_digest: String::new(),
        };
        cursor.cursor_digest = cursor.computed_digest()?;
        Ok(cursor)
    }

    fn validate_for(
        &self,
        handle: &CatalogMissionExecutionHandle,
    ) -> Result<(), RuntimeTextSubscriptionError> {
        if !is_digest(&self.handle_digest)
            || !is_digest(&self.turn_identity_digest)
            || !is_digest(&self.cursor_digest)
            || self.handle_digest != handle.handle_digest
            || self.worker_generation == 0
            || self.observed_turn_revision == 0
            || self.after_evidence_sequence == Some(0)
            || self.computed_digest()? != self.cursor_digest
        {
            return Err(RuntimeTextSubscriptionError::CursorMismatch);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Result<String, RuntimeTextSubscriptionError> {
        digest_json(&RuntimeTextSubscriptionCursorDigestMaterial {
            handle_digest: &self.handle_digest,
            turn_identity_digest: &self.turn_identity_digest,
            worker_generation: self.worker_generation,
            after_evidence_sequence: self.after_evidence_sequence,
            observed_turn_revision: self.observed_turn_revision,
            observed_turn_status: self.observed_turn_status,
        })
    }
}

impl fmt::Debug for RuntimeTextSubscriptionCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTextSubscriptionCursor")
            .field("handle", &ShortDigest(&self.handle_digest))
            .field("turn", &ShortDigest(&self.turn_identity_digest))
            .field("worker_generation", &self.worker_generation)
            .field("after_evidence_sequence", &self.after_evidence_sequence)
            .field("observed_turn_revision", &self.observed_turn_revision)
            .field("observed_turn_status", &self.observed_turn_status)
            .field("cursor", &ShortDigest(&self.cursor_digest))
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeTextSubscriptionCursorDigestMaterial<'a> {
    handle_digest: &'a str,
    turn_identity_digest: &'a str,
    worker_generation: u64,
    after_evidence_sequence: Option<u64>,
    observed_turn_revision: u64,
    observed_turn_status: RuntimeTurnStatus,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeTextSubscriptionTurn {
    turn_identity_digest: String,
    worker_generation: u64,
    turn_revision: u64,
    turn_status: RuntimeTurnStatus,
    last_text_evidence_sequence: Option<u64>,
}

impl RuntimeTextSubscriptionTurn {
    pub fn turn_identity_digest(&self) -> &str {
        &self.turn_identity_digest
    }

    pub const fn worker_generation(&self) -> u64 {
        self.worker_generation
    }

    pub const fn turn_revision(&self) -> u64 {
        self.turn_revision
    }

    pub const fn turn_status(&self) -> RuntimeTurnStatus {
        self.turn_status
    }

    pub const fn last_text_evidence_sequence(&self) -> Option<u64> {
        self.last_text_evidence_sequence
    }
}

impl fmt::Debug for RuntimeTextSubscriptionTurn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTextSubscriptionTurn")
            .field("turn", &ShortDigest(&self.turn_identity_digest))
            .field("worker_generation", &self.worker_generation)
            .field("turn_revision", &self.turn_revision)
            .field("turn_status", &self.turn_status)
            .field(
                "last_text_evidence_sequence",
                &self.last_text_evidence_sequence,
            )
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeTextSubscriptionDelta {
    evidence_sequence: u64,
    stream_sequence: u64,
    item_identity_digest: String,
    text: String,
    text_digest: String,
    cumulative_byte_count: u64,
    chain_digest: String,
    evidence_digest: String,
    observed_at: DateTime<Utc>,
}

impl RuntimeTextSubscriptionDelta {
    pub const fn evidence_sequence(&self) -> u64 {
        self.evidence_sequence
    }

    pub const fn stream_sequence(&self) -> u64 {
        self.stream_sequence
    }

    pub fn item_identity_digest(&self) -> &str {
        &self.item_identity_digest
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn text_digest(&self) -> &str {
        &self.text_digest
    }

    pub const fn cumulative_byte_count(&self) -> u64 {
        self.cumulative_byte_count
    }

    pub fn chain_digest(&self) -> &str {
        &self.chain_digest
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
}

impl From<&RuntimeTurnPrivateTextDelta> for RuntimeTextSubscriptionDelta {
    fn from(delta: &RuntimeTurnPrivateTextDelta) -> Self {
        Self {
            evidence_sequence: delta.evidence_sequence,
            stream_sequence: delta.stream_sequence,
            item_identity_digest: delta.item_id_digest.clone(),
            text: delta.delta.clone(),
            text_digest: delta.delta_digest.clone(),
            cumulative_byte_count: delta.cumulative_byte_count,
            chain_digest: delta.chain_digest.clone(),
            evidence_digest: delta.event_digest.clone(),
            observed_at: delta.observed_at,
        }
    }
}

impl fmt::Debug for RuntimeTextSubscriptionDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTextSubscriptionDelta")
            .field("evidence_sequence", &self.evidence_sequence)
            .field("stream_sequence", &self.stream_sequence)
            .field("item", &ShortDigest(&self.item_identity_digest))
            .field("text", &"[REDACTED]")
            .field("text_digest", &ShortDigest(&self.text_digest))
            .field("cumulative_byte_count", &self.cumulative_byte_count)
            .field("chain", &ShortDigest(&self.chain_digest))
            .field("evidence", &ShortDigest(&self.evidence_digest))
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeTextSubscriptionPage {
    turn: RuntimeTextSubscriptionTurn,
    deltas: Vec<RuntimeTextSubscriptionDelta>,
    next_cursor: RuntimeTextSubscriptionCursor,
    has_more: bool,
}

impl RuntimeTextSubscriptionPage {
    pub fn turn(&self) -> &RuntimeTextSubscriptionTurn {
        &self.turn
    }

    pub fn deltas(&self) -> &[RuntimeTextSubscriptionDelta] {
        &self.deltas
    }

    pub fn next_cursor(&self) -> &RuntimeTextSubscriptionCursor {
        &self.next_cursor
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

impl fmt::Debug for RuntimeTextSubscriptionPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeTextSubscriptionPage")
            .field("turn", &self.turn)
            .field("delta_count", &self.deltas.len())
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "kind")]
pub enum RuntimeTextSubscriptionBatch {
    AwaitingTurn {
        handle_digest: String,
    },
    Reset {
        page: Box<RuntimeTextSubscriptionPage>,
    },
    Append {
        page: Box<RuntimeTextSubscriptionPage>,
    },
    CaughtUp {
        turn: RuntimeTextSubscriptionTurn,
        cursor: RuntimeTextSubscriptionCursor,
    },
}

impl fmt::Debug for RuntimeTextSubscriptionBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitingTurn { handle_digest } => formatter
                .debug_struct("RuntimeTextSubscriptionBatch::AwaitingTurn")
                .field("handle", &ShortDigest(handle_digest))
                .finish(),
            Self::Reset { page } => formatter
                .debug_struct("RuntimeTextSubscriptionBatch::Reset")
                .field("page", page)
                .finish(),
            Self::Append { page } => formatter
                .debug_struct("RuntimeTextSubscriptionBatch::Append")
                .field("page", page)
                .finish(),
            Self::CaughtUp { turn, cursor } => formatter
                .debug_struct("RuntimeTextSubscriptionBatch::CaughtUp")
                .field("turn", turn)
                .field("cursor", cursor)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RuntimeTextSubscriptionError {
    #[error("Runtime text page size must be between 1 and 64")]
    InvalidPageSize,
    #[error("Catalog Mission execution handle is not canonical or no longer matches durable state")]
    MissionHandleMismatch,
    #[error("Catalog Mission cannot produce a stable execution handle")]
    InvalidMissionHandleSource,
    #[error("Runtime text subscription cursor does not match the exact Mission handle")]
    CursorMismatch,
    #[error("Runtime text subscription cursor is ahead of durable evidence")]
    CursorAhead,
    #[error("Runtime text subscription cursor history is missing")]
    CursorHistoryMissing,
    #[error("Runtime text subscription source regressed behind its durable cursor")]
    SourceRegressed,
    #[error("Runtime text subscription source is unavailable")]
    SourceUnavailable,
    #[error("Runtime text subscription source failed integrity validation")]
    InvalidSource,
}

impl ApplicationService {
    pub fn start_catalog_mission_execution(
        &mut self,
        command: StartCatalogMission,
        now: DateTime<Utc>,
    ) -> Result<CatalogMissionExecutionStart, ApplicationError> {
        let mission = self.start_catalog_mission(command, now)?;
        let handle = self.mission_execution_handle(&mission.project_id, &mission.id)?;
        Ok(CatalogMissionExecutionStart { mission, handle })
    }

    pub fn mission_execution_handle(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<CatalogMissionExecutionHandle, ApplicationError> {
        let mission = self
            .load_mission(project_id, mission_id)
            .map_err(|_| RuntimeTextSubscriptionError::SourceUnavailable)?;
        let conversation = self
            .mission_conversation(project_id, mission_id)
            .map_err(|_| RuntimeTextSubscriptionError::SourceUnavailable)?;
        CatalogMissionExecutionHandle::from_durable(&mission, &conversation)
            .map_err(ApplicationError::from)
    }

    pub fn read_runtime_text_subscription(
        &self,
        handle: &CatalogMissionExecutionHandle,
        cursor: Option<&RuntimeTextSubscriptionCursor>,
        page_size: usize,
    ) -> Result<RuntimeTextSubscriptionBatch, ApplicationError> {
        validate_page_size(page_size)?;
        handle.validate_shape()?;
        let durable_handle = self
            .mission_execution_handle(handle.project_id(), handle.mission_id())
            .map_err(|_| RuntimeTextSubscriptionError::MissionHandleMismatch)?;
        if durable_handle != *handle {
            return Err(RuntimeTextSubscriptionError::MissionHandleMismatch.into());
        }
        let attempt = self
            .latest_runtime_turn_for_mission(handle.project_id(), handle.mission_id())
            .map_err(|_| RuntimeTextSubscriptionError::SourceUnavailable)?;
        let deltas = attempt
            .as_ref()
            .map(|attempt| {
                self.runtime_turn_private_text_deltas(handle.project_id(), &attempt.id)
                    .map_err(|_| RuntimeTextSubscriptionError::SourceUnavailable)
            })
            .transpose()?;
        project_runtime_text_subscription(
            handle,
            cursor,
            attempt.as_ref(),
            deltas.as_deref().unwrap_or_default(),
            page_size,
        )
        .map_err(ApplicationError::from)
    }
}

fn project_runtime_text_subscription(
    handle: &CatalogMissionExecutionHandle,
    cursor: Option<&RuntimeTextSubscriptionCursor>,
    attempt: Option<&RuntimeTurnAttempt>,
    deltas: &[RuntimeTurnPrivateTextDelta],
    page_size: usize,
) -> Result<RuntimeTextSubscriptionBatch, RuntimeTextSubscriptionError> {
    validate_page_size(page_size)?;
    handle.validate_shape()?;
    let Some(attempt) = attempt else {
        if cursor.is_some() || !deltas.is_empty() {
            return Err(RuntimeTextSubscriptionError::CursorHistoryMissing);
        }
        return Ok(RuntimeTextSubscriptionBatch::AwaitingTurn {
            handle_digest: handle.handle_digest.clone(),
        });
    };
    validate_runtime_source(handle, attempt, deltas)?;
    let turn = project_turn(handle, attempt, deltas)?;
    let Some(cursor) = cursor else {
        return reset_batch(handle, turn, deltas, page_size);
    };
    cursor.validate_for(handle)?;
    if cursor.turn_identity_digest != turn.turn_identity_digest
        || cursor.worker_generation != turn.worker_generation
    {
        return reset_batch(handle, turn, deltas, page_size);
    }
    project_same_turn_batch(handle, cursor, turn, deltas, page_size)
}

fn project_same_turn_batch(
    handle: &CatalogMissionExecutionHandle,
    cursor: &RuntimeTextSubscriptionCursor,
    turn: RuntimeTextSubscriptionTurn,
    deltas: &[RuntimeTurnPrivateTextDelta],
    page_size: usize,
) -> Result<RuntimeTextSubscriptionBatch, RuntimeTextSubscriptionError> {
    if cursor.observed_turn_revision > turn.turn_revision
        || (cursor.observed_turn_status.is_terminal()
            && cursor.observed_turn_status != turn.turn_status)
    {
        return Err(RuntimeTextSubscriptionError::SourceRegressed);
    }
    if cursor.observed_turn_revision == turn.turn_revision
        && cursor.observed_turn_status != turn.turn_status
    {
        return Err(RuntimeTextSubscriptionError::CursorMismatch);
    }
    let unseen_start = unseen_start_index(cursor.after_evidence_sequence, deltas)?;
    if unseen_start < deltas.len() {
        return page_batch(handle, turn, deltas, unseen_start, page_size, false);
    }
    if cursor.observed_turn_revision != turn.turn_revision
        || cursor.observed_turn_status != turn.turn_status
    {
        return reset_batch(handle, turn, deltas, page_size);
    }
    let caught_up_cursor =
        RuntimeTextSubscriptionCursor::for_turn(handle, &turn, cursor.after_evidence_sequence)?;
    Ok(RuntimeTextSubscriptionBatch::CaughtUp {
        turn,
        cursor: caught_up_cursor,
    })
}

fn unseen_start_index(
    after_evidence_sequence: Option<u64>,
    deltas: &[RuntimeTurnPrivateTextDelta],
) -> Result<usize, RuntimeTextSubscriptionError> {
    let Some(after) = after_evidence_sequence else {
        return Ok(0);
    };
    let Some(last) = deltas.last() else {
        return Err(RuntimeTextSubscriptionError::CursorAhead);
    };
    if after > last.evidence_sequence {
        return Err(RuntimeTextSubscriptionError::CursorAhead);
    }
    deltas
        .iter()
        .position(|delta| delta.evidence_sequence == after)
        .and_then(|index| index.checked_add(1))
        .ok_or(RuntimeTextSubscriptionError::CursorHistoryMissing)
}

fn reset_batch(
    handle: &CatalogMissionExecutionHandle,
    turn: RuntimeTextSubscriptionTurn,
    deltas: &[RuntimeTurnPrivateTextDelta],
    page_size: usize,
) -> Result<RuntimeTextSubscriptionBatch, RuntimeTextSubscriptionError> {
    page_batch(handle, turn, deltas, 0, page_size, true)
}

fn page_batch(
    handle: &CatalogMissionExecutionHandle,
    turn: RuntimeTextSubscriptionTurn,
    deltas: &[RuntimeTurnPrivateTextDelta],
    start: usize,
    page_size: usize,
    reset: bool,
) -> Result<RuntimeTextSubscriptionBatch, RuntimeTextSubscriptionError> {
    let end = start.saturating_add(page_size).min(deltas.len());
    let page_deltas = deltas[start..end]
        .iter()
        .map(RuntimeTextSubscriptionDelta::from)
        .collect::<Vec<_>>();
    let after = page_deltas
        .last()
        .map(RuntimeTextSubscriptionDelta::evidence_sequence);
    let page = RuntimeTextSubscriptionPage {
        next_cursor: RuntimeTextSubscriptionCursor::for_turn(handle, &turn, after)?,
        turn,
        deltas: page_deltas,
        has_more: end < deltas.len(),
    };
    if reset {
        Ok(RuntimeTextSubscriptionBatch::Reset {
            page: Box::new(page),
        })
    } else {
        Ok(RuntimeTextSubscriptionBatch::Append {
            page: Box::new(page),
        })
    }
}

fn validate_runtime_source(
    handle: &CatalogMissionExecutionHandle,
    attempt: &RuntimeTurnAttempt,
    deltas: &[RuntimeTurnPrivateTextDelta],
) -> Result<(), RuntimeTextSubscriptionError> {
    attempt
        .validate()
        .map_err(|_| RuntimeTextSubscriptionError::InvalidSource)?;
    if attempt.scope.tenant_id != handle.tenant_id
        || attempt.scope.project_id != handle.project_id
        || attempt.scope.mission_id != handle.mission_id
        || attempt.scope.worker_generation == 0
        || attempt.revision == 0
    {
        return Err(RuntimeTextSubscriptionError::InvalidSource);
    }
    let mut previous_by_item = BTreeMap::<&str, &RuntimeTurnPrivateTextDelta>::new();
    let mut previous_sequence = None::<u64>;
    for delta in deltas {
        if previous_sequence.is_some_and(|previous| delta.evidence_sequence <= previous) {
            return Err(RuntimeTextSubscriptionError::InvalidSource);
        }
        let previous = previous_by_item.get(delta.item_id_digest.as_str()).copied();
        delta
            .validate_for(attempt, previous)
            .map_err(|_| RuntimeTextSubscriptionError::InvalidSource)?;
        previous_sequence = Some(delta.evidence_sequence);
        previous_by_item.insert(delta.item_id_digest.as_str(), delta);
    }
    Ok(())
}

fn project_turn(
    handle: &CatalogMissionExecutionHandle,
    attempt: &RuntimeTurnAttempt,
    deltas: &[RuntimeTurnPrivateTextDelta],
) -> Result<RuntimeTextSubscriptionTurn, RuntimeTextSubscriptionError> {
    let turn_identity_digest = digest_json(&RuntimeTextTurnIdentityDigestMaterial {
        handle_digest: handle.handle_digest(),
        attempt_id: attempt.id.as_str(),
        runtime_thread_id_digest: &attempt.scope.runtime_thread_id_digest,
        worker_generation: attempt.scope.worker_generation,
        created_at: attempt.created_at,
    })?;
    Ok(RuntimeTextSubscriptionTurn {
        turn_identity_digest,
        worker_generation: attempt.scope.worker_generation,
        turn_revision: attempt.revision,
        turn_status: attempt.status,
        last_text_evidence_sequence: deltas.last().map(|delta| delta.evidence_sequence),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeTextTurnIdentityDigestMaterial<'a> {
    handle_digest: &'a str,
    attempt_id: &'a str,
    runtime_thread_id_digest: &'a str,
    worker_generation: u64,
    created_at: DateTime<Utc>,
}

fn validate_page_size(page_size: usize) -> Result<(), RuntimeTextSubscriptionError> {
    if !(1..=RUNTIME_TEXT_SUBSCRIPTION_MAX_PAGE_SIZE).contains(&page_size) {
        return Err(RuntimeTextSubscriptionError::InvalidPageSize);
    }
    Ok(())
}

fn digest_json(value: &impl Serialize) -> Result<String, RuntimeTextSubscriptionError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| RuntimeTextSubscriptionError::InvalidSource)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_digest(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

struct ShortDigest<'a>(&'a str);

impl fmt::Debug for ShortDigest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.get(..DIGEST_LABEL_LENGTH) {
            Some(label) if is_digest(self.0) => write!(formatter, "sha256:{label}…"),
            _ => formatter.write_str("sha256:[INVALID]"),
        }
    }
}

const OPERATIONS_PLUGIN_ID: &str = "operations.log-driven/v1";
const OPERATIONS_MAX_PAGE_SIZE: usize = 32;

/// Exact Project/Mission identity used by the Operations provider. The
/// provider never accepts a caller-supplied log or a caller-supplied tenant;
/// this value is constructed from the durable Mission before a service is
/// mounted.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
pub(crate) struct OperationsScope {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
}

impl OperationsScope {
    fn from_mission(mission: &Mission) -> Result<Self, OperationsPluginError> {
        let scope = Self {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
        };
        if scope.tenant_id.as_str().trim().is_empty()
            || scope.project_id.as_str().trim().is_empty()
            || scope.mission_id.as_str().trim().is_empty()
        {
            return Err(OperationsPluginError::InvalidScope);
        }
        Ok(scope)
    }

    fn digest(&self) -> Result<String, OperationsPluginError> {
        digest_json(self).map_err(|_| OperationsPluginError::InvalidSource)
    }
}

impl fmt::Debug for OperationsScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scope_digest = self.digest().unwrap_or_else(|_| "invalid".into());
        formatter
            .debug_struct("OperationsScope")
            .field("scope", &ShortDigest(&scope_digest))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum OperationsPluginError {
    #[error("Operations plugin page size must be between 1 and 32")]
    InvalidPageSize,
    #[error("Operations plugin scope is invalid")]
    InvalidScope,
    #[error("durable Mission execution log is unavailable")]
    SourceUnavailable,
    #[error("durable Mission execution log failed integrity validation")]
    InvalidSource,
    #[error("Operations plugin scope does not match the durable Mission log")]
    ScopeMismatch,
    #[error("Operations plugin Mission revision does not match the durable cursor")]
    RevisionMismatch,
    #[error("Operations plugin cursor is not canonical for its scope")]
    CursorMismatch,
    #[error("Operations plugin cursor is ahead of the durable Mission log")]
    CursorAhead,
    #[error("Operations plugin cursor history is missing from the durable Mission log")]
    CursorHistoryMissing,
    #[error("Operations plugin selection does not match the durable operation")]
    SelectionMismatch,
    #[error("Operations plugin is not mounted")]
    NotMounted,
    #[error("Operations plugin has been revoked")]
    Revoked,
    #[error("Operations plugin cannot advance its revision")]
    RevisionOverflow,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationsOperationKind {
    Mission,
    Checkpoint,
    Runtime,
    Conversation,
    Other,
}

impl OperationsOperationKind {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Mission => "MISSION",
            Self::Checkpoint => "CHECKPOINT",
            Self::Runtime => "RUNTIME",
            Self::Conversation => "CONVERSATION",
            Self::Other => "OTHER",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationsOperationStatus {
    Recorded,
    Running,
    Blocked,
    Completed,
    Failed,
    Uncertain,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationsBusinessStatus {
    Awaiting,
    Running,
    Blocked,
    Completed,
    ExpectedRefusal,
    Failed,
    Cancelled,
    Uncertain,
}

impl OperationsBusinessStatus {
    const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::ExpectedRefusal | Self::Failed | Self::Cancelled
        )
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct OperationsCursor {
    scope_digest: String,
    revision: u64,
    after_sequence: Option<u64>,
    log_prefix_digest: String,
    cursor_digest: String,
}

impl OperationsCursor {
    fn new(
        scope: &OperationsScope,
        revision: u64,
        after_sequence: Option<u64>,
        log_prefix_digest: String,
    ) -> Result<Self, OperationsPluginError> {
        let scope_digest = scope.digest()?;
        let mut cursor = Self {
            scope_digest,
            revision,
            after_sequence,
            log_prefix_digest,
            cursor_digest: String::new(),
        };
        cursor.cursor_digest = cursor.computed_digest()?;
        Ok(cursor)
    }

    fn validate_for(
        &self,
        scope: &OperationsScope,
        revision: u64,
    ) -> Result<(), OperationsPluginError> {
        let expected_scope = scope.digest()?;
        if !is_digest(&self.scope_digest)
            || !is_digest(&self.log_prefix_digest)
            || !is_digest(&self.cursor_digest)
            || self.scope_digest != expected_scope
            || self.revision == 0
            || self.revision != revision
            || self.after_sequence == Some(0)
            || self.computed_digest()? != self.cursor_digest
        {
            if self.scope_digest != expected_scope {
                return Err(OperationsPluginError::ScopeMismatch);
            }
            if self.revision != revision {
                return Err(OperationsPluginError::RevisionMismatch);
            }
            return Err(OperationsPluginError::CursorMismatch);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Result<String, OperationsPluginError> {
        digest_json(&OperationsCursorDigestMaterial {
            scope_digest: &self.scope_digest,
            revision: self.revision,
            after_sequence: self.after_sequence,
            log_prefix_digest: &self.log_prefix_digest,
        })
        .map_err(|_| OperationsPluginError::InvalidSource)
    }
}

impl fmt::Debug for OperationsCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationsCursor")
            .field("scope", &ShortDigest(&self.scope_digest))
            .field("revision", &self.revision)
            .field("after_sequence", &self.after_sequence)
            .field("log_prefix", &ShortDigest(&self.log_prefix_digest))
            .field("cursor", &ShortDigest(&self.cursor_digest))
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationsCursorDigestMaterial<'a> {
    scope_digest: &'a str,
    revision: u64,
    after_sequence: Option<u64>,
    log_prefix_digest: &'a str,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct OperationsSelection {
    scope_digest: String,
    revision: u64,
    sequence: u64,
    operation_digest: String,
    detail_digest: String,
    selection_digest: String,
}

impl OperationsSelection {
    fn new(
        scope: &OperationsScope,
        revision: u64,
        entry: &OperationsLogEntry,
    ) -> Result<Self, OperationsPluginError> {
        let mut selection = Self {
            scope_digest: scope.digest()?,
            revision,
            sequence: entry.sequence,
            operation_digest: entry.operation_digest.clone(),
            detail_digest: entry.detail_digest.clone(),
            selection_digest: String::new(),
        };
        selection.selection_digest = selection.computed_digest()?;
        Ok(selection)
    }

    fn validate_for(
        &self,
        scope: &OperationsScope,
        revision: u64,
    ) -> Result<(), OperationsPluginError> {
        let expected_scope = scope.digest()?;
        if !is_digest(&self.scope_digest)
            || !is_digest(&self.operation_digest)
            || !is_digest(&self.detail_digest)
            || !is_digest(&self.selection_digest)
            || self.scope_digest != expected_scope
            || self.revision == 0
            || self.sequence == 0
            || self.revision != revision
            || self.computed_digest()? != self.selection_digest
        {
            if self.scope_digest != expected_scope {
                return Err(OperationsPluginError::ScopeMismatch);
            }
            if self.revision != revision {
                return Err(OperationsPluginError::RevisionMismatch);
            }
            return Err(OperationsPluginError::SelectionMismatch);
        }
        Ok(())
    }

    fn computed_digest(&self) -> Result<String, OperationsPluginError> {
        digest_json(&OperationsSelectionDigestMaterial {
            scope_digest: &self.scope_digest,
            revision: self.revision,
            sequence: self.sequence,
            operation_digest: &self.operation_digest,
            detail_digest: &self.detail_digest,
        })
        .map_err(|_| OperationsPluginError::InvalidSource)
    }
}

impl fmt::Debug for OperationsSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationsSelection")
            .field("scope", &ShortDigest(&self.scope_digest))
            .field("revision", &self.revision)
            .field("sequence", &self.sequence)
            .field("operation", &ShortDigest(&self.operation_digest))
            .field("detail", &ShortDigest(&self.detail_digest))
            .field("selection", &ShortDigest(&self.selection_digest))
            .finish()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationsSelectionDigestMaterial<'a> {
    scope_digest: &'a str,
    revision: u64,
    sequence: u64,
    operation_digest: &'a str,
    detail_digest: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OperationsLogEntry {
    sequence: u64,
    kind: OperationsOperationKind,
    status: OperationsOperationStatus,
    operation_digest: String,
    detail_digest: String,
    checkpoint_digest: Option<String>,
    capability_digest: Option<String>,
    business_status: Option<OperationsBusinessStatus>,
}

#[derive(Clone, Debug)]
struct OperationsLogSnapshot {
    scope: OperationsScope,
    revision: u64,
    entries: Vec<OperationsLogEntry>,
    business_status: OperationsBusinessStatus,
}

#[derive(Clone, Debug)]
struct OperationsLogPage {
    scope: OperationsScope,
    revision: u64,
    entries: Vec<OperationsLogEntry>,
    selected_entry: Option<OperationsLogEntry>,
    next_cursor: OperationsCursor,
    has_more: bool,
    caught_up: bool,
    business_status: OperationsBusinessStatus,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct OperationsInlineNode {
    operation_digest: String,
    kind: OperationsOperationKind,
    status: OperationsOperationStatus,
    selection: OperationsSelection,
    selected: bool,
    detail_available: bool,
}

impl OperationsInlineNode {
    fn from_entry(
        scope: &OperationsScope,
        revision: u64,
        entry: &OperationsLogEntry,
        selection: Option<&OperationsSelection>,
    ) -> Result<Self, OperationsPluginError> {
        let node_selection = OperationsSelection::new(scope, revision, entry)?;
        Ok(Self {
            operation_digest: entry.operation_digest.clone(),
            kind: entry.kind,
            status: entry.status,
            selected: selection == Some(&node_selection),
            selection: node_selection,
            detail_available: true,
        })
    }
}

impl fmt::Debug for OperationsInlineNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationsInlineNode")
            .field("operation", &ShortDigest(&self.operation_digest))
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("selected", &self.selected)
            .field("detail_available", &self.detail_available)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct OperationsSelectedDetail {
    operation_digest: String,
    sequence: u64,
    kind: OperationsOperationKind,
    status: OperationsOperationStatus,
    detail_digest: String,
    checkpoint_digest: Option<String>,
    capability_digest: Option<String>,
    selection: OperationsSelection,
}

impl fmt::Debug for OperationsSelectedDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationsSelectedDetail")
            .field("operation", &ShortDigest(&self.operation_digest))
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("detail", &ShortDigest(&self.detail_digest))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct OperationsInlineProjection {
    plugin_id: String,
    scope_digest: String,
    revision: u64,
    business_status: OperationsBusinessStatus,
    caught_up: bool,
    nodes: Vec<OperationsInlineNode>,
    selected_detail: Option<OperationsSelectedDetail>,
    next_cursor: OperationsCursor,
    has_more: bool,
}

impl OperationsInlineProjection {
    pub(crate) fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub(crate) fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn business_status(&self) -> OperationsBusinessStatus {
        self.business_status
    }

    pub(crate) const fn caught_up(&self) -> bool {
        self.caught_up
    }

    pub(crate) const fn business_complete(&self) -> bool {
        self.business_status.is_terminal()
    }

    pub(crate) fn nodes(&self) -> &[OperationsInlineNode] {
        &self.nodes
    }

    pub(crate) fn selected_detail(&self) -> Option<&OperationsSelectedDetail> {
        self.selected_detail.as_ref()
    }

    pub(crate) fn next_cursor(&self) -> &OperationsCursor {
        &self.next_cursor
    }

    pub(crate) const fn has_more(&self) -> bool {
        self.has_more
    }
}

impl fmt::Debug for OperationsInlineProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationsInlineProjection")
            .field("plugin_id", &self.plugin_id)
            .field("scope", &ShortDigest(&self.scope_digest))
            .field("revision", &self.revision)
            .field("business_status", &self.business_status)
            .field("caught_up", &self.caught_up)
            .field("node_count", &self.nodes.len())
            .field("selected_detail", &self.selected_detail)
            .field("next_cursor", &self.next_cursor)
            .field("has_more", &self.has_more)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationsPluginLifecycle {
    Mounted,
    Unmounted,
    Revoked,
}

/// The provider is deliberately log-only. It has no Mission/Runtime state
/// cache and therefore cannot manufacture an operation from a current status,
/// a heartbeat, or a synthetic test payload.
struct OperationsLogProvider<'a> {
    application: &'a ApplicationService,
    scope: OperationsScope,
}

impl<'a> OperationsLogProvider<'a> {
    fn new(application: &'a ApplicationService, scope: OperationsScope) -> Self {
        Self { application, scope }
    }

    fn read_page(
        &self,
        cursor: Option<&OperationsCursor>,
        selection: Option<&OperationsSelection>,
        page_size: usize,
    ) -> Result<OperationsLogPage, OperationsPluginError> {
        if !(1..=OPERATIONS_MAX_PAGE_SIZE).contains(&page_size) {
            return Err(OperationsPluginError::InvalidPageSize);
        }
        let snapshot = self.read_snapshot()?;
        let (start, previous_sequence) = if let Some(cursor) = cursor {
            cursor.validate_for(&snapshot.scope, snapshot.revision)?;
            match cursor.after_sequence {
                None => {
                    if cursor.log_prefix_digest != empty_log_prefix_digest()? {
                        return Err(OperationsPluginError::CursorMismatch);
                    }
                    (0, None)
                }
                Some(after_sequence) => {
                    let Some(last) = snapshot.entries.last() else {
                        return Err(OperationsPluginError::CursorAhead);
                    };
                    if after_sequence > last.sequence {
                        return Err(OperationsPluginError::CursorAhead);
                    }
                    let Some(index) = snapshot
                        .entries
                        .iter()
                        .position(|entry| entry.sequence == after_sequence)
                    else {
                        return Err(OperationsPluginError::CursorHistoryMissing);
                    };
                    let prefix_digest = log_prefix_digest(&snapshot.entries, index + 1)?;
                    if cursor.log_prefix_digest != prefix_digest {
                        return Err(OperationsPluginError::CursorMismatch);
                    }
                    (
                        index
                            .checked_add(1)
                            .ok_or(OperationsPluginError::RevisionOverflow)?,
                        Some(after_sequence),
                    )
                }
            }
        } else {
            (0, None)
        };
        if let Some(selection) = selection {
            selection.validate_for(&snapshot.scope, snapshot.revision)?;
        }
        let end = start
            .checked_add(page_size)
            .ok_or(OperationsPluginError::RevisionOverflow)?
            .min(snapshot.entries.len());
        let entries = snapshot.entries[start..end].to_vec();
        let after_sequence = entries
            .last()
            .map(|entry| entry.sequence)
            .or(previous_sequence);
        let prefix_digest = log_prefix_digest(&snapshot.entries, end)?;
        let next_cursor = OperationsCursor::new(
            &snapshot.scope,
            snapshot.revision,
            after_sequence,
            prefix_digest,
        )?;
        let selected_entry = selection
            .map(|selection| {
                snapshot
                    .entries
                    .iter()
                    .find(|entry| entry.sequence == selection.sequence)
                    .ok_or(OperationsPluginError::SelectionMismatch)
                    .and_then(|entry| {
                        if entry.operation_digest != selection.operation_digest
                            || entry.detail_digest != selection.detail_digest
                        {
                            return Err(OperationsPluginError::SelectionMismatch);
                        }
                        Ok(entry.clone())
                    })
            })
            .transpose()?;
        Ok(OperationsLogPage {
            scope: snapshot.scope,
            revision: snapshot.revision,
            entries,
            selected_entry,
            next_cursor,
            has_more: end < snapshot.entries.len(),
            caught_up: end == snapshot.entries.len(),
            business_status: snapshot.business_status,
        })
    }

    fn read_snapshot(&self) -> Result<OperationsLogSnapshot, OperationsPluginError> {
        let mission = self
            .application
            .load_mission(&self.scope.project_id, &self.scope.mission_id)
            .map_err(|_| OperationsPluginError::SourceUnavailable)?;
        let durable_scope = OperationsScope::from_mission(&mission)?;
        if durable_scope != self.scope {
            return Err(OperationsPluginError::ScopeMismatch);
        }
        if mission.revision == 0 {
            return Err(OperationsPluginError::InvalidSource);
        }
        let events = self
            .application
            .mission_events(&self.scope.project_id, &self.scope.mission_id)
            .map_err(|_| OperationsPluginError::SourceUnavailable)?;
        let entries = events
            .iter()
            .map(|event| operation_log_entry(&self.scope, event))
            .collect::<Result<Vec<_>, _>>()?;
        let mut previous_sequence = None;
        for entry in &entries {
            if previous_sequence.is_some_and(|previous| entry.sequence <= previous) {
                return Err(OperationsPluginError::InvalidSource);
            }
            previous_sequence = Some(entry.sequence);
        }
        let mut business_status = OperationsBusinessStatus::Awaiting;
        for entry in &entries {
            if let Some(status) = entry.business_status {
                business_status = status;
            }
        }
        Ok(OperationsLogSnapshot {
            scope: self.scope.clone(),
            revision: mission.revision,
            entries,
            business_status,
        })
    }
}

/// Consumer seam for the Conversation inline surface. It accepts only the
/// content-free provider page and never receives a durable event payload.
#[derive(Clone, Copy, Debug)]
struct OperationsConversationConsumer {
    plugin_id: &'static str,
}

impl OperationsConversationConsumer {
    fn project(
        self,
        page: OperationsLogPage,
        selection: Option<&OperationsSelection>,
    ) -> Result<OperationsInlineProjection, OperationsPluginError> {
        let nodes = page
            .entries
            .iter()
            .map(|entry| {
                OperationsInlineNode::from_entry(&page.scope, page.revision, entry, selection)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let selected_detail = page.selected_entry.map(|entry| {
            let selection = OperationsSelection::new(&page.scope, page.revision, &entry)?;
            Ok(OperationsSelectedDetail {
                operation_digest: entry.operation_digest,
                sequence: entry.sequence,
                kind: entry.kind,
                status: entry.status,
                detail_digest: entry.detail_digest,
                checkpoint_digest: entry.checkpoint_digest,
                capability_digest: entry.capability_digest,
                selection,
            })
        });
        let selected_detail = selected_detail.transpose()?;
        Ok(OperationsInlineProjection {
            plugin_id: self.plugin_id.into(),
            scope_digest: page.scope.digest()?,
            revision: page.revision,
            business_status: page.business_status,
            caught_up: page.caught_up,
            nodes,
            selected_detail,
            next_cursor: page.next_cursor,
            has_more: page.has_more,
        })
    }
}

/// On-demand Operations service. The only retained private state is the last
/// content-free projection needed by the inline consumer; unmount and revoke
/// explicitly drop it before the lifecycle becomes unusable.
pub(crate) struct OperationsDetailService<'a> {
    provider: OperationsLogProvider<'a>,
    consumer: OperationsConversationConsumer,
    lifecycle: OperationsPluginLifecycle,
    private_projection: Option<OperationsInlineProjection>,
}

impl<'a> OperationsDetailService<'a> {
    fn mount(provider: OperationsLogProvider<'a>) -> Result<Self, OperationsPluginError> {
        provider.read_snapshot()?;
        Ok(Self {
            provider,
            consumer: OperationsConversationConsumer {
                plugin_id: OPERATIONS_PLUGIN_ID,
            },
            lifecycle: OperationsPluginLifecycle::Mounted,
            private_projection: None,
        })
    }

    pub(crate) fn read(
        &mut self,
        cursor: Option<&OperationsCursor>,
        selection: Option<&OperationsSelection>,
        page_size: usize,
    ) -> Result<OperationsInlineProjection, OperationsPluginError> {
        if self.lifecycle != OperationsPluginLifecycle::Mounted {
            self.private_projection = None;
            return Err(match self.lifecycle {
                OperationsPluginLifecycle::Mounted | OperationsPluginLifecycle::Unmounted => {
                    OperationsPluginError::NotMounted
                }
                OperationsPluginLifecycle::Revoked => OperationsPluginError::Revoked,
            });
        }
        let result = self
            .provider
            .read_page(cursor, selection, page_size)
            .and_then(|page| self.consumer.project(page, selection));
        match result {
            Ok(projection) => {
                self.private_projection = Some(projection.clone());
                Ok(projection)
            }
            Err(error) => {
                self.private_projection = None;
                Err(error)
            }
        }
    }

    pub(crate) fn mount_again(&mut self) -> Result<(), OperationsPluginError> {
        self.private_projection = None;
        if self.lifecycle == OperationsPluginLifecycle::Revoked {
            return Err(OperationsPluginError::Revoked);
        }
        self.lifecycle = OperationsPluginLifecycle::Unmounted;
        self.provider.read_snapshot()?;
        self.lifecycle = OperationsPluginLifecycle::Mounted;
        Ok(())
    }

    pub(crate) fn unmount(&mut self) {
        self.private_projection = None;
        self.lifecycle = OperationsPluginLifecycle::Unmounted;
    }

    pub(crate) fn revoke(&mut self) {
        self.private_projection = None;
        self.lifecycle = OperationsPluginLifecycle::Revoked;
    }

    #[cfg(test)]
    fn has_private_projection(&self) -> bool {
        self.private_projection.is_some()
    }
}

impl fmt::Debug for OperationsDetailService<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationsDetailService")
            .field("lifecycle", &self.lifecycle)
            .field(
                "private_projection_present",
                &self.private_projection.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl ApplicationService {
    pub(crate) fn operations_detail_service(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<OperationsDetailService<'_>, OperationsPluginError> {
        let mission = self
            .load_mission(project_id, mission_id)
            .map_err(|_| OperationsPluginError::SourceUnavailable)?;
        let scope = OperationsScope::from_mission(&mission)?;
        OperationsDetailService::mount(OperationsLogProvider::new(self, scope))
    }
}

fn operation_log_entry(
    scope: &OperationsScope,
    event: &DomainEventRecord,
) -> Result<OperationsLogEntry, OperationsPluginError> {
    if event.sequence <= 0
        || event.project_id != scope.project_id
        || event.mission_id.as_ref() != Some(&scope.mission_id)
    {
        return Err(OperationsPluginError::ScopeMismatch);
    }
    let sequence =
        u64::try_from(event.sequence).map_err(|_| OperationsPluginError::InvalidSource)?;
    let (kind, status, business_status) = classify_operation_event(&event.event_type);
    let detail_digest = digest_json(&OperationsEventDigestMaterial {
        event_type: &event.event_type,
        payload: &event.payload,
    })
    .map_err(|_| OperationsPluginError::InvalidSource)?;
    let scope_digest = scope.digest()?;
    let operation_digest = digest_json(&OperationsOperationDigestMaterial {
        scope_digest: &scope_digest,
        sequence,
        operation_kind: kind.code(),
        event_type: &event.event_type,
        detail_digest: &detail_digest,
    })
    .map_err(|_| OperationsPluginError::InvalidSource)?;
    Ok(OperationsLogEntry {
        sequence,
        kind,
        status,
        operation_digest,
        detail_digest,
        checkpoint_digest: digest_payload_identifier(&event.payload, "checkpointId"),
        capability_digest: digest_payload_identifier(&event.payload, "capabilityId"),
        business_status,
    })
}

fn classify_operation_event(
    event_type: &str,
) -> (
    OperationsOperationKind,
    OperationsOperationStatus,
    Option<OperationsBusinessStatus>,
) {
    let kind = if event_type.starts_with("mission.checkpoint") {
        OperationsOperationKind::Checkpoint
    } else if event_type.starts_with("mission.") {
        OperationsOperationKind::Mission
    } else if event_type.starts_with("context.runtime_turn") {
        OperationsOperationKind::Runtime
    } else if event_type.starts_with("conversation.") {
        OperationsOperationKind::Conversation
    } else {
        OperationsOperationKind::Other
    };
    let (status, business_status) = match event_type {
        "mission.completed" => (
            OperationsOperationStatus::Completed,
            Some(OperationsBusinessStatus::Completed),
        ),
        "mission.expected_refusal" => (
            OperationsOperationStatus::Completed,
            Some(OperationsBusinessStatus::ExpectedRefusal),
        ),
        "mission.failed" => (
            OperationsOperationStatus::Failed,
            Some(OperationsBusinessStatus::Failed),
        ),
        "mission.cancelled" => (
            OperationsOperationStatus::Cancelled,
            Some(OperationsBusinessStatus::Cancelled),
        ),
        "mission.application_checkpoint_blocked" => (
            OperationsOperationStatus::Blocked,
            Some(OperationsBusinessStatus::Blocked),
        ),
        event_type if event_type.contains("uncertain") || event_type.contains("unverified") => (
            OperationsOperationStatus::Uncertain,
            Some(OperationsBusinessStatus::Uncertain),
        ),
        event_type
            if event_type == "mission.started"
                || event_type == "mission.created"
                || event_type == "mission.catalog_bound"
                || event_type == "mission.checkpoint_started"
                || event_type == "mission.checkpoint_verification_started"
                || event_type == "mission.partial"
                || event_type.starts_with("context.runtime_turn") =>
        {
            (
                OperationsOperationStatus::Running,
                Some(OperationsBusinessStatus::Running),
            )
        }
        "mission.checkpoint_completed" => (
            OperationsOperationStatus::Completed,
            Some(OperationsBusinessStatus::Running),
        ),
        event_type if event_type.ends_with("_failed") || event_type == "mission.reply_failed" => {
            (OperationsOperationStatus::Failed, None)
        }
        event_type if event_type.ends_with("_completed") || event_type.ends_with("_sent") => {
            (OperationsOperationStatus::Completed, None)
        }
        _ => (OperationsOperationStatus::Recorded, None),
    };
    (kind, status, business_status)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationsEventDigestMaterial<'a> {
    event_type: &'a str,
    payload: &'a Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationsOperationDigestMaterial<'a> {
    scope_digest: &'a str,
    sequence: u64,
    operation_kind: &'a str,
    event_type: &'a str,
    detail_digest: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationsLogPrefixMaterial<'a> {
    sequence: u64,
    operation_digest: &'a str,
    detail_digest: &'a str,
}

fn digest_payload_identifier(payload: &Value, field: &str) -> Option<String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("{:x}", Sha256::digest(value.as_bytes())))
}

fn empty_log_prefix_digest() -> Result<String, OperationsPluginError> {
    log_prefix_digest(&[], 0)
}

fn log_prefix_digest(
    entries: &[OperationsLogEntry],
    end: usize,
) -> Result<String, OperationsPluginError> {
    let material = entries
        .get(..end)
        .ok_or(OperationsPluginError::InvalidSource)?
        .iter()
        .map(|entry| OperationsLogPrefixMaterial {
            sequence: entry.sequence,
            operation_digest: &entry.operation_digest,
            detail_digest: &entry.detail_digest,
        })
        .collect::<Vec<_>>();
    digest_json(&material).map_err(|_| OperationsPluginError::InvalidSource)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ContextAssemblyId, ContextBranchId, ContextCapsuleId, ContextCheckpointId,
        ContextWorkspaceId, CurrencyCode, KpiContract, KpiDirection, Money, OperatingMode,
        RuntimeRecoveryAttemptId, RuntimeTurnAttemptId, RuntimeTurnObservedKind, RuntimeTurnScope,
        StorageMode, TaskId, WorkerId, WorkerLeaseId,
    };
    use hartevo_storage::{DatabaseKey, ProjectStore, StorageError};

    use super::*;
    use crate::CreateProject;

    const PRIVATE_GOAL: &str = "PRIVATE-GOAL::decide whether the bounded market test is justified";
    const PRIVATE_THREAD_ID: &str = "private-runtime-thread-ui-sub-01";
    const PRIVATE_TURN_ID: &str = "private-runtime-turn-ui-sub-01";
    const PRIVATE_DELTA_PREFIX: &str = "PRIVATE-DELTA-UI-SUB-01";

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 12, 10, 0, 0)
            .single()
            .expect("valid fixture time")
    }

    fn sha256(value: impl AsRef<[u8]>) -> String {
        format!("{:x}", Sha256::digest(value.as_ref()))
    }

    fn count_kpi() -> BTreeMap<String, KpiContract> {
        BTreeMap::from([(
            "qualified_decision_count".into(),
            KpiContract {
                baseline: None,
                target: rust_decimal::Decimal::ONE,
                unit: "count".into(),
                direction: KpiDirection::AtLeast,
            },
        )])
    }

    struct DurableMissionFixture {
        _database_directory: tempfile::TempDir,
        _workspace: tempfile::TempDir,
        database_path: PathBuf,
        database_key: DatabaseKey,
        service: ApplicationService,
        project_id: ProjectId,
        mission_id: MissionId,
    }

    impl DurableMissionFixture {
        fn new() -> Self {
            let database_directory = tempfile::tempdir().expect("database directory");
            let workspace = tempfile::tempdir().expect("project workspace");
            let database_path = database_directory.path().join("ui-sub-01.sqlite3");
            let database_key = DatabaseKey::new([71; 32]).expect("database key");
            let store = ProjectStore::open(&database_path, &database_key).expect("SQLCipher store");
            let mut service = ApplicationService::new(store);
            let project_id = ProjectId::from("ui-sub-01-project");
            let mission_id = MissionId::from("ui-sub-01-mission");
            service
                .create_project(
                    CreateProject {
                        tenant_id: TenantId::from("ui-sub-01-tenant"),
                        id: project_id.clone(),
                        name: "Runtime text subscription".into(),
                        description: String::new(),
                        workspace_root: workspace
                            .path()
                            .canonicalize()
                            .expect("canonical project workspace"),
                        storage_mode: StorageMode::LocalNew,
                    },
                    now(),
                )
                .expect("project");
            Self {
                _database_directory: database_directory,
                _workspace: workspace,
                database_path,
                database_key,
                service,
                project_id,
                mission_id,
            }
        }

        fn command(&self) -> StartCatalogMission {
            StartCatalogMission {
                id: self.mission_id.clone(),
                first_task_id: TaskId::from("ui-sub-01-first-task"),
                project_id: self.project_id.clone(),
                manifest_id: "VM-07".into(),
                mode: OperatingMode::OneOffDecision,
                parent_mission_id: None,
                title: Some("Bounded market decision".into()),
                goal: PRIVATE_GOAL.into(),
                market: "DE".into(),
                language: "de-DE".into(),
                audience: "owner".into(),
                timezone: "Europe/Berlin".into(),
                kpis: count_kpi(),
                budget: Money::zero(CurrencyCode::parse("EUR").expect("EUR")),
            }
        }
    }

    fn started_handle() -> CatalogMissionExecutionHandle {
        let mut fixture = DurableMissionFixture::new();
        fixture
            .service
            .start_catalog_mission_execution(fixture.command(), now() + Duration::seconds(1))
            .expect("Catalog Mission execution start")
            .handle
    }

    fn runtime_scope(
        handle: &CatalogMissionExecutionHandle,
        worker_generation: u64,
        thread_id: &str,
    ) -> RuntimeTurnScope {
        RuntimeTurnScope {
            purpose: hartevo_domain_kernel::RuntimeTurnPurpose::Agent,
            tenant_id: handle.tenant_id.clone(),
            project_id: handle.project_id.clone(),
            mission_id: handle.mission_id.clone(),
            workspace_id: ContextWorkspaceId::from("ui-sub-workspace"),
            capsule_id: ContextCapsuleId::from("ui-sub-capsule"),
            capsule_revision: 1,
            capsule_authority_digest: sha256("capsule-authority"),
            branch_id: ContextBranchId::from("ui-sub-branch"),
            branch_revision: 1,
            worker_id: WorkerId::from("ui-sub-worker"),
            worker_generation,
            worker_lease_id: WorkerLeaseId::from("ui-sub-worker-lease"),
            worker_lease_revision: 1,
            attachment_epoch: 1,
            assembly_id: ContextAssemblyId::from("ui-sub-assembly"),
            assembly_revision: 1,
            assembly_manifest_digest: sha256("assembly-manifest"),
            assembly_input_digest: sha256("assembly-input"),
            prompt_digest: sha256("private-prompt"),
            checkpoint_id: ContextCheckpointId::from("ui-sub-checkpoint"),
            checkpoint_digest: sha256("checkpoint"),
            recovery_id: RuntimeRecoveryAttemptId::from("ui-sub-recovery"),
            recovery_revision: 1,
            runtime_instance_digest: sha256("runtime-instance"),
            runtime_mapping_digest: sha256("runtime-mapping"),
            runtime_thread_id: thread_id.into(),
            runtime_thread_id_digest: sha256(thread_id),
        }
    }

    fn running_attempt(
        handle: &CatalogMissionExecutionHandle,
        attempt_id: &str,
        worker_generation: u64,
        thread_id: &str,
    ) -> RuntimeTurnAttempt {
        let mut attempt = RuntimeTurnAttempt::prepare(
            RuntimeTurnAttemptId::from(attempt_id),
            runtime_scope(handle, worker_generation, thread_id),
            now(),
        )
        .expect("prepared attempt");
        attempt
            .begin_dispatch(now() + Duration::seconds(1))
            .expect("dispatch started");
        attempt
            .accept_dispatch(
                PRIVATE_TURN_ID.into(),
                sha256("dispatch-request"),
                sha256("dispatch-response"),
                now() + Duration::seconds(2),
            )
            .expect("dispatch accepted");
        attempt
    }

    fn append_private_deltas(
        attempt: &mut RuntimeTurnAttempt,
        count: usize,
    ) -> Vec<RuntimeTurnPrivateTextDelta> {
        let mut deltas = Vec::with_capacity(count);
        let item_digest = sha256("agent-message-item");
        for index in 0..count {
            let observed_at =
                now() + Duration::seconds(i64::try_from(index).expect("bounded fixture index") + 3);
            attempt
                .observe(
                    RuntimeTurnObservedKind::AgentMessageDelta,
                    sha256(format!("delta-evidence-{index}")),
                    observed_at,
                )
                .expect("delta evidence");
            let delta = RuntimeTurnPrivateTextDelta::capture(
                attempt,
                item_digest.clone(),
                format!("{PRIVATE_DELTA_PREFIX}-{index}"),
                deltas.last(),
            )
            .expect("private delta");
            deltas.push(delta);
        }
        deltas
    }

    fn page_from(batch: RuntimeTextSubscriptionBatch) -> RuntimeTextSubscriptionPage {
        match batch {
            RuntimeTextSubscriptionBatch::Reset { page }
            | RuntimeTextSubscriptionBatch::Append { page } => *page,
            other => panic!("expected Runtime text page, got {other:?}"),
        }
    }

    fn persisted_outbox_count(service: &ApplicationService) -> usize {
        let mut sequence = 1_i64;
        loop {
            match service.store.outbox_message(sequence) {
                Ok(message) => assert_eq!(message.sequence, sequence),
                Err(StorageError::DomainDecode(message))
                    if message == format!("unknown outbox message {sequence}") =>
                {
                    return usize::try_from(sequence - 1).expect("bounded outbox fixture");
                }
                Err(error) => panic!("outbox inspection failed at {sequence}: {error}"),
            }
            sequence = sequence.checked_add(1).expect("bounded outbox fixture");
        }
    }

    fn resign_cursor(cursor: &mut RuntimeTextSubscriptionCursor) {
        cursor.cursor_digest = cursor.computed_digest().expect("canonical test cursor");
    }

    fn resign_handle(handle: &mut CatalogMissionExecutionHandle) {
        handle.handle_digest = handle.computed_digest().expect("canonical test handle");
    }

    fn started_operations_fixture() -> DurableMissionFixture {
        let mut fixture = DurableMissionFixture::new();
        fixture
            .service
            .start_catalog_mission_execution(fixture.command(), now() + Duration::seconds(1))
            .expect("Catalog Mission execution start");
        fixture
    }

    fn operations_service(fixture: &DurableMissionFixture) -> OperationsDetailService<'_> {
        fixture
            .service
            .operations_detail_service(&fixture.project_id, &fixture.mission_id)
            .expect("mounted Operations detail service")
    }

    fn append_durable_operation_event(
        fixture: &mut DurableMissionFixture,
        event_type: &str,
        payload: &Value,
        offset_seconds: i64,
    ) {
        fixture
            .service
            .store
            .append_event(
                &fixture.project_id,
                Some(&fixture.mission_id),
                event_type,
                payload,
                now() + Duration::seconds(offset_seconds),
            )
            .expect("durable Mission execution event");
    }

    fn resign_operations_cursor(cursor: &mut OperationsCursor) {
        cursor.cursor_digest = cursor
            .computed_digest()
            .expect("canonical Operations cursor");
    }

    fn resign_operations_selection(selection: &mut OperationsSelection) {
        selection.selection_digest = selection
            .computed_digest()
            .expect("canonical Operations selection");
    }

    #[test]
    fn atomic_start_returns_restart_stable_content_free_handle_and_awaiting_turn() {
        let mut fixture = DurableMissionFixture::new();
        let baseline_outbox_count = persisted_outbox_count(&fixture.service);
        let started = fixture
            .service
            .start_catalog_mission_execution(fixture.command(), now() + Duration::seconds(1))
            .expect("Catalog Mission execution start");
        assert_eq!(started.mission().id, fixture.mission_id);
        assert!(started.mission().effects.is_empty());
        assert_eq!(started.handle().manifest_id(), "VM-07");
        assert_eq!(
            fixture
                .service
                .mission_execution_handle(&fixture.project_id, &fixture.mission_id)
                .expect("rebuilt handle"),
            *started.handle()
        );
        assert!(
            fixture
                .service
                .latest_runtime_turn_for_mission(&fixture.project_id, &fixture.mission_id)
                .expect("turn query")
                .is_none()
        );
        let events = fixture
            .service
            .mission_events(&fixture.project_id, &fixture.mission_id)
            .expect("Mission events");
        assert_eq!(events.len(), 3);
        assert!(
            events
                .iter()
                .all(|event| !event.event_type.contains("runtime"))
        );
        let started_outbox_count = persisted_outbox_count(&fixture.service);
        assert_eq!(started_outbox_count, baseline_outbox_count + events.len());
        let handle = started.handle().clone();
        let debug = format!("{started:?} {handle:?}");
        assert!(!debug.contains(PRIVATE_GOAL));
        let DurableMissionFixture {
            _database_directory,
            _workspace,
            database_path,
            database_key,
            service,
            project_id,
            mission_id,
        } = fixture;
        drop(service);
        let restarted = ApplicationService::new(
            ProjectStore::open(&database_path, &database_key).expect("reopened SQLCipher store"),
        );
        assert_eq!(
            restarted
                .mission_execution_handle(&project_id, &mission_id)
                .expect("restart-rebuilt handle"),
            handle
        );
        assert!(matches!(
            restarted
                .read_runtime_text_subscription(&handle, None, 64)
                .expect("read-only awaiting projection"),
            RuntimeTextSubscriptionBatch::AwaitingTurn { .. }
        ));
        assert_eq!(
            restarted
                .mission_events(&project_id, &mission_id)
                .expect("unchanged events")
                .len(),
            3
        );
        assert_eq!(persisted_outbox_count(&restarted), started_outbox_count);
    }

    #[test]
    fn every_handle_field_is_exactly_revalidated_and_page_limit_is_hard_bounded() {
        let mut fixture = DurableMissionFixture::new();
        let handle = fixture
            .service
            .start_catalog_mission_execution(fixture.command(), now() + Duration::seconds(1))
            .expect("Catalog Mission execution start")
            .handle;
        let mut tampered = Vec::new();
        let mut candidate = handle.clone();
        candidate.tenant_id = TenantId::from("foreign-tenant");
        resign_handle(&mut candidate);
        tampered.push(candidate);
        let mut candidate = handle.clone();
        candidate.project_id = ProjectId::from("foreign-project");
        resign_handle(&mut candidate);
        tampered.push(candidate);
        let mut candidate = handle.clone();
        candidate.mission_id = MissionId::from("foreign-mission");
        candidate.conversation_id = MissionConversationId::from_stable(format!(
            "mission-conversation:{}",
            candidate.mission_id.as_str()
        ));
        resign_handle(&mut candidate);
        tampered.push(candidate);
        let mut candidate = handle.clone();
        candidate.manifest_id = "VM-08".into();
        resign_handle(&mut candidate);
        tampered.push(candidate);
        let mut candidate = handle.clone();
        candidate.manifest_version = candidate.manifest_version.saturating_add(1);
        resign_handle(&mut candidate);
        tampered.push(candidate);
        let mut candidate = handle.clone();
        candidate.catalog_digest = sha256("foreign-catalog");
        resign_handle(&mut candidate);
        tampered.push(candidate);
        let mut candidate = handle.clone();
        candidate.conversation_id = MissionConversationId::from("foreign-conversation");
        resign_handle(&mut candidate);
        tampered.push(candidate);
        let mut candidate = handle.clone();
        candidate.mission_created_at += Duration::seconds(1);
        resign_handle(&mut candidate);
        tampered.push(candidate);
        let mut candidate = handle.clone();
        candidate.contract_digest = sha256("foreign-contract");
        resign_handle(&mut candidate);
        tampered.push(candidate);
        let mut candidate = handle.clone();
        candidate.handle_digest = sha256("foreign-handle");
        tampered.push(candidate);
        for candidate in tampered {
            assert!(matches!(
                fixture
                    .service
                    .read_runtime_text_subscription(&candidate, None, 1),
                Err(ApplicationError::RuntimeTextSubscription(
                    RuntimeTextSubscriptionError::MissionHandleMismatch
                ))
            ));
        }
        for invalid in [0, 65, usize::MAX] {
            assert!(matches!(
                fixture
                    .service
                    .read_runtime_text_subscription(&handle, None, invalid),
                Err(ApplicationError::RuntimeTextSubscription(
                    RuntimeTextSubscriptionError::InvalidPageSize
                ))
            ));
        }
    }

    #[test]
    fn serialized_handle_and_cursor_reject_unknown_null_and_wrong_typed_fields() {
        let handle = started_handle();
        let mut attempt = running_attempt(&handle, "ui-sub-attempt-a", 1, PRIVATE_THREAD_ID);
        let deltas = append_private_deltas(&mut attempt, 1);
        let cursor = page_from(
            project_runtime_text_subscription(&handle, None, Some(&attempt), &deltas, 64)
                .expect("initial reset"),
        )
        .next_cursor()
        .clone();
        let mut unknown_handle = serde_json::to_value(&handle).expect("handle JSON");
        unknown_handle
            .as_object_mut()
            .expect("handle object")
            .insert("futureAuthority".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<CatalogMissionExecutionHandle>(unknown_handle).is_err());
        let mut null_handle = serde_json::to_value(&handle).expect("handle JSON");
        null_handle["contractDigest"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CatalogMissionExecutionHandle>(null_handle).is_err());
        let mut unknown_cursor = serde_json::to_value(&cursor).expect("cursor JSON");
        unknown_cursor
            .as_object_mut()
            .expect("cursor object")
            .insert("futureSequence".into(), serde_json::json!(7));
        assert!(serde_json::from_value::<RuntimeTextSubscriptionCursor>(unknown_cursor).is_err());
        let mut wrong_typed_cursor = serde_json::to_value(&cursor).expect("cursor JSON");
        wrong_typed_cursor["workerGeneration"] = serde_json::json!("one");
        assert!(
            serde_json::from_value::<RuntimeTextSubscriptionCursor>(wrong_typed_cursor).is_err()
        );
    }

    #[test]
    fn reset_append_and_caught_up_page_sixty_six_durable_deltas_without_duplicates() {
        let handle = started_handle();
        let mut attempt = running_attempt(&handle, "ui-sub-attempt-a", 1, PRIVATE_THREAD_ID);
        let deltas = append_private_deltas(&mut attempt, 66);
        let reset = project_runtime_text_subscription(&handle, None, Some(&attempt), &deltas, 64)
            .expect("initial reset");
        assert!(matches!(reset, RuntimeTextSubscriptionBatch::Reset { .. }));
        let first = page_from(reset);
        assert_eq!(first.deltas().len(), 64);
        assert!(first.has_more());
        let append = project_runtime_text_subscription(
            &handle,
            Some(first.next_cursor()),
            Some(&attempt),
            &deltas,
            64,
        )
        .expect("remaining append");
        assert!(matches!(
            append,
            RuntimeTextSubscriptionBatch::Append { .. }
        ));
        let second = page_from(append);
        assert_eq!(second.deltas().len(), 2);
        assert!(!second.has_more());
        let caught_up = project_runtime_text_subscription(
            &handle,
            Some(second.next_cursor()),
            Some(&attempt),
            &deltas,
            64,
        )
        .expect("caught up");
        assert!(matches!(
            caught_up,
            RuntimeTextSubscriptionBatch::CaughtUp { .. }
        ));
        assert_eq!(
            first.deltas()[0].text(),
            format!("{PRIVATE_DELTA_PREFIX}-0")
        );
        assert_eq!(
            second.deltas()[1].text(),
            format!("{PRIVATE_DELTA_PREFIX}-65")
        );
    }

    #[test]
    fn attempt_generation_status_or_revision_changes_require_an_explicit_reset() {
        let handle = started_handle();
        let mut attempt = running_attempt(&handle, "ui-sub-attempt-a", 1, PRIVATE_THREAD_ID);
        let deltas = append_private_deltas(&mut attempt, 2);
        let initial = page_from(
            project_runtime_text_subscription(&handle, None, Some(&attempt), &deltas, 64)
                .expect("initial reset"),
        );
        let cursor = initial.next_cursor().clone();
        let mut revision_changed = attempt.clone();
        revision_changed
            .observe(
                RuntimeTurnObservedKind::Diagnostic,
                sha256("diagnostic-revision-evidence"),
                now() + Duration::minutes(1),
            )
            .expect("diagnostic revision transition");
        assert_eq!(revision_changed.status, RuntimeTurnStatus::Running);
        assert!(matches!(
            project_runtime_text_subscription(
                &handle,
                Some(&cursor),
                Some(&revision_changed),
                &deltas,
                64,
            )
            .expect("revision reset"),
            RuntimeTextSubscriptionBatch::Reset { .. }
        ));
        let mut completed = attempt.clone();
        completed
            .observe(
                RuntimeTurnObservedKind::Completed,
                sha256("terminal-status-evidence"),
                now() + Duration::minutes(2),
            )
            .expect("terminal status transition");
        assert_eq!(completed.status, RuntimeTurnStatus::Completed);
        assert!(matches!(
            project_runtime_text_subscription(
                &handle,
                Some(&cursor),
                Some(&completed),
                &deltas,
                64,
            )
            .expect("terminal status reset"),
            RuntimeTextSubscriptionBatch::Reset { .. }
        ));
        let replacement = running_attempt(
            &handle,
            "ui-sub-attempt-b",
            2,
            "private-runtime-thread-ui-sub-01-b",
        );
        assert!(matches!(
            project_runtime_text_subscription(&handle, Some(&cursor), Some(&replacement), &[], 64,)
                .expect("replacement reset"),
            RuntimeTextSubscriptionBatch::Reset { .. }
        ));
    }

    #[test]
    fn tampered_private_text_source_fails_integrity_before_projection() {
        let handle = started_handle();
        let mut attempt = running_attempt(&handle, "ui-sub-attempt-a", 1, PRIVATE_THREAD_ID);
        let deltas = append_private_deltas(&mut attempt, 2);
        let mut tampered = deltas.clone();
        tampered[1].delta.push_str("::TAMPERED");
        assert_eq!(
            project_runtime_text_subscription(&handle, None, Some(&attempt), &tampered, 64),
            Err(RuntimeTextSubscriptionError::InvalidSource)
        );
    }

    #[test]
    fn every_cursor_field_is_integrity_bound_before_resume_semantics_run() {
        let handle = started_handle();
        let mut attempt = running_attempt(&handle, "ui-sub-attempt-a", 1, PRIVATE_THREAD_ID);
        let deltas = append_private_deltas(&mut attempt, 2);
        let cursor = page_from(
            project_runtime_text_subscription(&handle, None, Some(&attempt), &deltas, 64)
                .expect("initial reset"),
        )
        .next_cursor()
        .clone();
        let mut tampered = Vec::new();
        let mut candidate = cursor.clone();
        candidate.handle_digest = sha256("foreign-handle");
        tampered.push(candidate);
        let mut candidate = cursor.clone();
        candidate.turn_identity_digest = sha256("foreign-turn");
        tampered.push(candidate);
        let mut candidate = cursor.clone();
        candidate.worker_generation += 1;
        tampered.push(candidate);
        let mut candidate = cursor.clone();
        candidate.after_evidence_sequence = Some(deltas[0].evidence_sequence);
        tampered.push(candidate);
        let mut candidate = cursor.clone();
        candidate.observed_turn_revision += 1;
        tampered.push(candidate);
        let mut candidate = cursor.clone();
        candidate.observed_turn_status = RuntimeTurnStatus::Completed;
        tampered.push(candidate);
        let mut candidate = cursor;
        candidate.cursor_digest = sha256("foreign-cursor");
        tampered.push(candidate);
        for candidate in tampered {
            assert_eq!(
                project_runtime_text_subscription(
                    &handle,
                    Some(&candidate),
                    Some(&attempt),
                    &deltas,
                    64,
                ),
                Err(RuntimeTextSubscriptionError::CursorMismatch)
            );
        }
    }

    #[test]
    fn wrong_cursor_ahead_history_missing_and_source_regression_fail_closed() {
        let handle = started_handle();
        let mut attempt = running_attempt(&handle, "ui-sub-attempt-a", 1, PRIVATE_THREAD_ID);
        let deltas = append_private_deltas(&mut attempt, 3);
        let page = page_from(
            project_runtime_text_subscription(&handle, None, Some(&attempt), &deltas, 64)
                .expect("initial reset"),
        );
        let cursor = page.next_cursor().clone();
        let mut wrong_handle = cursor.clone();
        wrong_handle.handle_digest = sha256("wrong-handle");
        assert_eq!(
            project_runtime_text_subscription(
                &handle,
                Some(&wrong_handle),
                Some(&attempt),
                &deltas,
                64,
            ),
            Err(RuntimeTextSubscriptionError::CursorMismatch)
        );
        let mut ahead = cursor.clone();
        ahead.after_evidence_sequence = Some(10_000);
        resign_cursor(&mut ahead);
        assert_eq!(
            project_runtime_text_subscription(&handle, Some(&ahead), Some(&attempt), &deltas, 64,),
            Err(RuntimeTextSubscriptionError::CursorAhead)
        );
        let mut missing = cursor.clone();
        missing.after_evidence_sequence = Some(deltas[0].evidence_sequence - 1);
        resign_cursor(&mut missing);
        assert_eq!(
            project_runtime_text_subscription(&handle, Some(&missing), Some(&attempt), &deltas, 64,),
            Err(RuntimeTextSubscriptionError::CursorHistoryMissing)
        );
        let mut regressed = cursor;
        regressed.observed_turn_revision = attempt.revision + 1;
        resign_cursor(&mut regressed);
        assert_eq!(
            project_runtime_text_subscription(
                &handle,
                Some(&regressed),
                Some(&attempt),
                &deltas,
                64,
            ),
            Err(RuntimeTextSubscriptionError::SourceRegressed)
        );
    }

    #[test]
    fn terminal_repeats_are_caught_up_and_debug_redacts_text_and_raw_runtime_ids() {
        let handle = started_handle();
        let mut attempt = running_attempt(&handle, "ui-sub-attempt-a", 1, PRIVATE_THREAD_ID);
        let deltas = append_private_deltas(&mut attempt, 1);
        attempt
            .observe(
                RuntimeTurnObservedKind::Completed,
                sha256("terminal-evidence"),
                now() + Duration::minutes(3),
            )
            .expect("terminal attempt");
        let reset = project_runtime_text_subscription(&handle, None, Some(&attempt), &deltas, 64)
            .expect("terminal reset");
        let page = page_from(reset);
        let caught_up = project_runtime_text_subscription(
            &handle,
            Some(page.next_cursor()),
            Some(&attempt),
            &deltas,
            64,
        )
        .expect("terminal caught up");
        assert!(matches!(
            caught_up,
            RuntimeTextSubscriptionBatch::CaughtUp { .. }
        ));
        let debug = format!("{handle:?} {page:?} {caught_up:?}");
        let delta_debug = format!("{:?}", page.deltas()[0]);
        for private in [
            PRIVATE_GOAL,
            PRIVATE_THREAD_ID,
            PRIVATE_TURN_ID,
            PRIVATE_DELTA_PREFIX,
            "ui-sub-attempt-a",
        ] {
            assert!(!debug.contains(private));
            assert!(!delta_debug.contains(private));
        }
        assert!(delta_debug.contains("[REDACTED]"));
    }

    #[test]
    fn operations_log_projection_is_caught_up_without_claiming_business_completion() {
        let fixture = started_operations_fixture();
        let mut service = operations_service(&fixture);
        let projection = service
            .read(None, None, OPERATIONS_MAX_PAGE_SIZE)
            .expect("Operations log projection");

        assert_eq!(projection.plugin_id(), OPERATIONS_PLUGIN_ID);
        assert!(is_digest(projection.scope_digest()));
        assert!(projection.revision() > 0);
        assert!(projection.caught_up());
        assert!(!projection.business_complete());
        assert_eq!(
            projection.business_status(),
            OperationsBusinessStatus::Running
        );
        assert_eq!(projection.nodes().len(), 3);
        assert!(projection.nodes().iter().all(|node| node.detail_available));
        assert!(projection.selected_detail().is_none());
        assert!(!projection.has_more());
    }

    #[test]
    fn operations_provider_reselects_exact_detail_and_reads_new_events_from_durable_log() {
        let mut fixture = started_operations_fixture();
        let (cursor, selection) = {
            let mut service = operations_service(&fixture);
            let first = service.read(None, None, 1).expect("first Operations page");
            let selection = first.nodes()[0].selection.clone();
            let cursor = first.next_cursor().clone();
            let reselected = service
                .read(Some(&cursor), Some(&selection), 1)
                .expect("reselected detail");
            assert_eq!(
                reselected
                    .selected_detail()
                    .expect("selected detail")
                    .sequence,
                selection.sequence
            );
            (cursor, selection)
        };

        append_durable_operation_event(
            &mut fixture,
            "mission.checkpoint_completed",
            &serde_json::json!({
                "checkpointId": "durable-checkpoint",
                "capabilityId": "durable-capability",
                "privateBody": PRIVATE_GOAL,
            }),
            4,
        );
        let mut service = operations_service(&fixture);
        let next = service
            .read(Some(&cursor), Some(&selection), OPERATIONS_MAX_PAGE_SIZE)
            .expect("durable appended Operations page");
        assert!(next.caught_up());
        assert!(!next.business_complete());
        assert_eq!(next.nodes().len(), 3);
        assert_eq!(
            next.nodes().last().expect("new operation node").status,
            OperationsOperationStatus::Completed
        );
        assert_eq!(
            next.selected_detail()
                .expect("reselected durable detail")
                .selection,
            selection
        );
    }

    #[test]
    fn operations_cursor_and_selection_reject_cross_scope_and_revision_reselect() {
        let fixture = started_operations_fixture();
        let mut service = operations_service(&fixture);
        let projection = service
            .read(None, None, OPERATIONS_MAX_PAGE_SIZE)
            .expect("Operations projection");

        let mut cross_scope_cursor = projection.next_cursor().clone();
        let foreign_scope = OperationsScope {
            tenant_id: TenantId::from("foreign-tenant"),
            project_id: ProjectId::from("foreign-project"),
            mission_id: MissionId::from("foreign-mission"),
        };
        cross_scope_cursor.scope_digest = foreign_scope.digest().expect("foreign scope digest");
        resign_operations_cursor(&mut cross_scope_cursor);
        assert_eq!(
            service.read(Some(&cross_scope_cursor), None, OPERATIONS_MAX_PAGE_SIZE),
            Err(OperationsPluginError::ScopeMismatch)
        );

        let mut stale_revision_cursor = projection.next_cursor().clone();
        stale_revision_cursor.revision += 1;
        resign_operations_cursor(&mut stale_revision_cursor);
        assert_eq!(
            service.read(Some(&stale_revision_cursor), None, OPERATIONS_MAX_PAGE_SIZE),
            Err(OperationsPluginError::RevisionMismatch)
        );

        let selection = projection.nodes()[0].selection.clone();
        let mut stale_selection = selection;
        stale_selection.revision += 1;
        resign_operations_selection(&mut stale_selection);
        assert_eq!(
            service.read(
                Some(projection.next_cursor()),
                Some(&stale_selection),
                OPERATIONS_MAX_PAGE_SIZE,
            ),
            Err(OperationsPluginError::RevisionMismatch)
        );
    }

    #[test]
    fn operations_log_replay_is_stable_after_sqlcipher_reopen() {
        let fixture = started_operations_fixture();
        let first = {
            let mut service = operations_service(&fixture);
            service
                .read(None, None, OPERATIONS_MAX_PAGE_SIZE)
                .expect("first durable projection")
        };
        let DurableMissionFixture {
            _database_directory: database_directory,
            _workspace: workspace,
            database_path,
            database_key,
            service,
            project_id,
            mission_id,
        } = fixture;
        drop(service);
        let restarted = ApplicationService::new(
            ProjectStore::open(&database_path, &database_key).expect("reopened SQLCipher store"),
        );
        let mut replay = restarted
            .operations_detail_service(&project_id, &mission_id)
            .expect("replayed Operations service");
        let second = replay
            .read(None, None, OPERATIONS_MAX_PAGE_SIZE)
            .expect("replayed durable projection");
        assert_eq!(first, second);
        drop((database_directory, workspace));
    }

    #[test]
    fn operations_unmount_and_revoke_clear_private_projection_and_redact_log_payload() {
        let mut fixture = started_operations_fixture();
        append_durable_operation_event(
            &mut fixture,
            "mission.checkpoint_started",
            &serde_json::json!({
                "checkpointId": "private-checkpoint-id",
                "capabilityId": "private-capability-id",
                "privateGoal": PRIVATE_GOAL,
                "privateText": PRIVATE_DELTA_PREFIX,
            }),
            4,
        );
        let mut service = operations_service(&fixture);
        let projection = service
            .read(None, None, OPERATIONS_MAX_PAGE_SIZE)
            .expect("redacted Operations projection");
        let serialized = serde_json::to_string(&projection).expect("serialized inline projection");
        let debug = format!("{projection:?} {service:?}");
        for private in [PRIVATE_GOAL, PRIVATE_DELTA_PREFIX, "private-checkpoint-id"] {
            assert!(!serialized.contains(private));
            assert!(!debug.contains(private));
        }
        assert!(service.has_private_projection());

        service.unmount();
        assert!(!service.has_private_projection());
        assert_eq!(
            service.read(None, None, OPERATIONS_MAX_PAGE_SIZE),
            Err(OperationsPluginError::NotMounted)
        );

        service.mount_again().expect("remount Operations service");
        service
            .read(None, None, OPERATIONS_MAX_PAGE_SIZE)
            .expect("projection after remount");
        assert!(service.has_private_projection());
        service.revoke();
        assert!(!service.has_private_projection());
        assert_eq!(
            service.read(None, None, OPERATIONS_MAX_PAGE_SIZE),
            Err(OperationsPluginError::Revoked)
        );
        assert_eq!(service.mount_again(), Err(OperationsPluginError::Revoked));
    }
}
