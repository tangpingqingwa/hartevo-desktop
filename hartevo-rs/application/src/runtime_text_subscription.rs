//! Restart-safe, read-only projection of SQLCipher-private Runtime text.
//!
//! This boundary returns a stable Mission execution handle immediately after
//! the existing atomic Catalog Mission start commits. Subsequent reads pull
//! integrity-checked private deltas from the durable Application API. It does
//! not start a Runtime, execute an Effect, append an Event, or mutate an
//! Outbox.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    Mission, MissionConversation, MissionConversationId, MissionId, ProjectId, RuntimeTurnAttempt,
    RuntimeTurnPrivateTextDelta, RuntimeTurnStatus, TenantId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

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
}
