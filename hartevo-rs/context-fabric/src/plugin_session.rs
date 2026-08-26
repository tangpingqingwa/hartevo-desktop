//! Mission-scoped plugin invocation recovery over the durable event spine.
//!
//! This is intentionally a Context-owned protocol. Storage persists each
//! [`PluginSessionEvent`] in its existing append-only domain-event table; the
//! journal validates the complete scope before a consumer can resume an
//! invocation. No plugin content or side effect is inferred during recovery.

use std::collections::BTreeSet;
use std::fmt;

use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PLUGIN_SESSION_SCHEMA_VERSION: u32 = 1;

fn digest(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("{:x}", hasher.finalize())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
pub enum PluginSessionError {
    #[error("plugin session scope or fence is invalid")]
    InvalidScope,
    #[error("plugin session fence is stale")]
    StaleFence,
    #[error("plugin session has expired")]
    Expired,
    #[error("plugin session is no longer mounted")]
    LifecycleUnavailable,
    #[error("plugin session is terminal")]
    Terminal,
    #[error("plugin invocation conflicts with durable history")]
    InvocationConflict,
    #[error("plugin invocation has no durable preparation")]
    MissingPreparation,
    #[error("plugin session event history is malformed")]
    InvalidHistory,
    #[error("plugin session cursor cannot move backwards")]
    CursorRegression,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionLifecycle {
    Mounted,
    Revoked,
    Unmounted,
    Terminal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionEventKind {
    Prepared,
    Committed,
    Cancelled,
    Lifecycle,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionEventStatus {
    Prepared,
    Committed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionCancelReason {
    Revoked,
    Unmounted,
    CrashRecovery,
    Terminal,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PluginSessionScope {
    tenant: TenantId,
    project: ProjectId,
    mission: MissionId,
}

impl PluginSessionScope {
    pub fn new(tenant_id: TenantId, project_id: ProjectId, mission_id: MissionId) -> Self {
        Self {
            tenant: tenant_id,
            project: project_id,
            mission: mission_id,
        }
    }
}

impl fmt::Debug for PluginSessionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionScope")
            .field("tenant_present", &true)
            .field("project_present", &true)
            .field("mission_present", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PluginSessionDescriptor {
    id: String,
    version: String,
    digest: String,
}

impl PluginSessionDescriptor {
    pub fn new(
        plugin_id: impl Into<String>,
        plugin_version: impl Into<String>,
        plugin_digest: impl Into<String>,
    ) -> Self {
        Self {
            id: plugin_id.into(),
            version: plugin_version.into(),
            digest: plugin_digest.into(),
        }
    }
}

impl fmt::Debug for PluginSessionDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionDescriptor")
            .field("plugin_present", &true)
            .field("version_present", &true)
            .field("digest_present", &true)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PluginSessionPosition {
    invocation_id: String,
    cursor: u64,
    generation: u64,
    attachment_epoch: u64,
}

impl PluginSessionPosition {
    pub fn new(
        invocation_id: impl Into<String>,
        cursor: u64,
        generation: u64,
        attachment_epoch: u64,
    ) -> Self {
        Self {
            invocation_id: invocation_id.into(),
            cursor,
            generation,
            attachment_epoch,
        }
    }
}

impl fmt::Debug for PluginSessionPosition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionPosition")
            .field("invocation_present", &true)
            .field("cursor", &self.cursor)
            .field("generation", &self.generation)
            .field("attachment_epoch", &self.attachment_epoch)
            .finish_non_exhaustive()
    }
}

/// The complete immutable identity and mutable cursor fence for an invocation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PluginSessionFence {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    plugin_id: String,
    plugin_version: String,
    plugin_digest: String,
    invocation_id: String,
    cursor: u64,
    generation: u64,
    attachment_epoch: u64,
}

impl fmt::Debug for PluginSessionFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionFence")
            .field("scope_present", &true)
            .field("plugin_present", &true)
            .field("cursor", &self.cursor)
            .field("generation", &self.generation)
            .field("attachment_epoch", &self.attachment_epoch)
            .finish_non_exhaustive()
    }
}

impl PluginSessionFence {
    pub fn new(
        scope: PluginSessionScope,
        descriptor: PluginSessionDescriptor,
        position: PluginSessionPosition,
    ) -> Self {
        Self {
            tenant_id: scope.tenant,
            project_id: scope.project,
            mission_id: scope.mission,
            plugin_id: descriptor.id,
            plugin_version: descriptor.version,
            plugin_digest: descriptor.digest,
            invocation_id: position.invocation_id,
            cursor: position.cursor,
            generation: position.generation,
            attachment_epoch: position.attachment_epoch,
        }
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn plugin_digest(&self) -> &str {
        &self.plugin_digest
    }

    pub fn invocation_id(&self) -> &str {
        &self.invocation_id
    }

    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn attachment_epoch(&self) -> u64 {
        self.attachment_epoch
    }

    #[must_use]
    pub fn with_cursor(&self, cursor: u64) -> Self {
        let mut next = self.clone();
        next.cursor = cursor;
        next
    }

    #[must_use]
    pub fn with_invocation(&self, invocation_id: impl Into<String>) -> Self {
        let mut next = self.clone();
        next.invocation_id = invocation_id.into();
        next
    }

    #[must_use]
    pub fn with_generation(&self, generation: u64, attachment_epoch: u64) -> Self {
        let mut next = self.clone();
        next.generation = generation;
        next.attachment_epoch = attachment_epoch;
        next
    }

    fn validate(&self) -> Result<(), PluginSessionError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.plugin_id.trim().is_empty()
            || self.plugin_version.trim().is_empty()
            || !is_digest(&self.plugin_digest)
            || self.generation == 0
            || self.attachment_epoch == 0
        {
            return Err(PluginSessionError::InvalidScope);
        }
        Ok(())
    }

    fn immutable_matches(&self, other: &Self) -> bool {
        self.tenant_id == other.tenant_id
            && self.project_id == other.project_id
            && self.mission_id == other.mission_id
            && self.plugin_id == other.plugin_id
            && self.plugin_version == other.plugin_version
            && self.plugin_digest == other.plugin_digest
            && self.generation == other.generation
            && self.attachment_epoch == other.attachment_epoch
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PluginSessionEvent {
    sequence: u64,
    kind: PluginSessionEventKind,
    status: PluginSessionEventStatus,
    fence: PluginSessionFence,
    side_effect_digest: String,
    idempotency_digest: String,
    cursor_after: Option<u64>,
    lifecycle_after: Option<PluginSessionLifecycle>,
    cancel_reason: Option<PluginSessionCancelReason>,
    recorded_at: String,
}

impl fmt::Debug for PluginSessionEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionEvent")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("cursor", &self.fence.cursor)
            .field("side_effect_present", &true)
            .field("idempotency_present", &true)
            .field("lifecycle_after", &self.lifecycle_after)
            .finish_non_exhaustive()
    }
}

impl PluginSessionEvent {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn kind(&self) -> PluginSessionEventKind {
        self.kind
    }

    pub fn status(&self) -> PluginSessionEventStatus {
        self.status
    }

    pub fn fence(&self) -> &PluginSessionFence {
        &self.fence
    }

    pub fn side_effect_digest(&self) -> &str {
        &self.side_effect_digest
    }

    pub fn cursor_after(&self) -> Option<u64> {
        self.cursor_after
    }

    pub fn lifecycle_after(&self) -> Option<PluginSessionLifecycle> {
        self.lifecycle_after
    }

    pub fn cancel_reason(&self) -> Option<PluginSessionCancelReason> {
        self.cancel_reason
    }

    pub fn recorded_at(&self) -> &str {
        &self.recorded_at
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum PluginSessionReceipt {
    Prepared {
        event_sequence: u64,
        fence: PluginSessionFence,
        side_effect_digest: String,
    },
    ReplayRequired {
        event_sequence: u64,
        fence: PluginSessionFence,
        side_effect_digest: String,
    },
    AlreadyApplied {
        event_sequence: u64,
        fence: PluginSessionFence,
        cursor_after: u64,
    },
    Cancelled {
        event_sequence: u64,
        fence: PluginSessionFence,
        reason: PluginSessionCancelReason,
    },
}

impl fmt::Debug for PluginSessionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Prepared { .. } => "prepared",
            Self::ReplayRequired { .. } => "replay_required",
            Self::AlreadyApplied { .. } => "already_applied",
            Self::Cancelled { .. } => "cancelled",
        };
        formatter
            .debug_struct("PluginSessionReceipt")
            .field("kind", &kind)
            .field("event_present", &true)
            .finish_non_exhaustive()
    }
}

impl PluginSessionReceipt {
    pub fn event_sequence(&self) -> u64 {
        match self {
            Self::Prepared { event_sequence, .. }
            | Self::ReplayRequired { event_sequence, .. }
            | Self::AlreadyApplied { event_sequence, .. }
            | Self::Cancelled { event_sequence, .. } => *event_sequence,
        }
    }

    pub fn fence(&self) -> &PluginSessionFence {
        match self {
            Self::Prepared { fence, .. }
            | Self::ReplayRequired { fence, .. }
            | Self::AlreadyApplied { fence, .. }
            | Self::Cancelled { fence, .. } => fence,
        }
    }
}

struct PluginSessionEventDraft<'a> {
    kind: PluginSessionEventKind,
    status: PluginSessionEventStatus,
    fence: &'a PluginSessionFence,
    side_effect_digest: &'a str,
    recorded_at: &'a str,
    cursor_after: Option<u64>,
    lifecycle_after: Option<PluginSessionLifecycle>,
    cancel_reason: Option<PluginSessionCancelReason>,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PluginSessionJournal {
    schema_version: u32,
    current_fence: PluginSessionFence,
    lifecycle: PluginSessionLifecycle,
    next_sequence: u64,
    events: Vec<PluginSessionEvent>,
}

impl fmt::Debug for PluginSessionJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionJournal")
            .field("schema_version", &self.schema_version)
            .field("lifecycle", &self.lifecycle)
            .field("event_count", &self.events.len())
            .field("cursor", &self.current_fence.cursor)
            .finish_non_exhaustive()
    }
}

impl PluginSessionJournal {
    pub fn new(fence: PluginSessionFence) -> Result<Self, PluginSessionError> {
        fence.validate()?;
        Ok(Self {
            schema_version: PLUGIN_SESSION_SCHEMA_VERSION,
            current_fence: fence,
            lifecycle: PluginSessionLifecycle::Mounted,
            next_sequence: 1,
            events: Vec::new(),
        })
    }

    pub fn from_events(
        fence: PluginSessionFence,
        events: Vec<PluginSessionEvent>,
    ) -> Result<Self, PluginSessionError> {
        let mut journal = Self::new(fence)?;
        for event in &events {
            if event.fence.validate().is_err() {
                return Err(PluginSessionError::InvalidHistory);
            }
            if !event.fence.immutable_matches(&journal.current_fence) {
                return Err(PluginSessionError::StaleFence);
            }
        }
        journal.events = events;
        journal.next_sequence = journal
            .events
            .last()
            .map(|event| {
                event
                    .sequence
                    .checked_add(1)
                    .ok_or(PluginSessionError::InvalidHistory)
            })
            .transpose()?
            .unwrap_or(1);
        journal.validate()?;
        if let Some(event) = journal.events.last() {
            if let Some(cursor_after) = event.cursor_after {
                journal.current_fence.cursor = cursor_after;
            }
            if let Some(lifecycle) = event.lifecycle_after {
                journal.lifecycle = lifecycle;
            }
        }
        journal.validate()?;
        Ok(journal)
    }

    pub fn fence(&self) -> &PluginSessionFence {
        &self.current_fence
    }

    pub fn lifecycle(&self) -> PluginSessionLifecycle {
        self.lifecycle
    }

    pub fn events(&self) -> &[PluginSessionEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn validate(&self) -> Result<(), PluginSessionError> {
        if self.schema_version != PLUGIN_SESSION_SCHEMA_VERSION {
            return Err(PluginSessionError::InvalidHistory);
        }
        self.current_fence.validate()?;
        let mut sequences = BTreeSet::new();
        for (index, event) in self.events.iter().enumerate() {
            if event.sequence == 0
                || event.sequence != index as u64 + 1
                || !sequences.insert(event.sequence)
                || !event.fence.immutable_matches(&self.current_fence)
                || !is_digest(&event.side_effect_digest)
                || !is_digest(&event.idempotency_digest)
                || event.fence.invocation_id.trim().is_empty()
                || event.recorded_at.trim().is_empty()
            {
                return Err(PluginSessionError::InvalidHistory);
            }
            match (event.kind, event.status) {
                (PluginSessionEventKind::Prepared, PluginSessionEventStatus::Prepared) => {
                    if event.cursor_after.is_some()
                        || event.lifecycle_after.is_some()
                        || event.cancel_reason.is_some()
                    {
                        return Err(PluginSessionError::InvalidHistory);
                    }
                }
                (PluginSessionEventKind::Committed, PluginSessionEventStatus::Committed) => {
                    if event.cursor_after.is_none()
                        || event.cursor_after < Some(event.fence.cursor)
                        || event.lifecycle_after.is_some()
                        || event.cancel_reason.is_some()
                    {
                        return Err(PluginSessionError::InvalidHistory);
                    }
                }
                (PluginSessionEventKind::Cancelled, PluginSessionEventStatus::Cancelled) => {
                    if event.cancel_reason.is_none() || event.lifecycle_after.is_none() {
                        return Err(PluginSessionError::InvalidHistory);
                    }
                }
                (PluginSessionEventKind::Lifecycle, PluginSessionEventStatus::Cancelled) => {
                    if event.fence.invocation_id.is_empty()
                        || event.cancel_reason.is_none()
                        || event.lifecycle_after.is_none()
                    {
                        return Err(PluginSessionError::InvalidHistory);
                    }
                }
                _ => return Err(PluginSessionError::InvalidHistory),
            }
        }
        Ok(())
    }

    fn ensure_write_fence(&self, fence: &PluginSessionFence) -> Result<(), PluginSessionError> {
        fence.validate()?;
        if fence != &self.current_fence {
            return Err(PluginSessionError::StaleFence);
        }
        match self.lifecycle {
            PluginSessionLifecycle::Mounted => Ok(()),
            PluginSessionLifecycle::Terminal => Err(PluginSessionError::Terminal),
            PluginSessionLifecycle::Revoked | PluginSessionLifecycle::Unmounted => {
                Err(PluginSessionError::LifecycleUnavailable)
            }
        }
    }

    fn ensure_read_fence(&self, fence: &PluginSessionFence) -> Result<(), PluginSessionError> {
        fence.validate()?;
        if !fence.immutable_matches(&self.current_fence) {
            return Err(PluginSessionError::StaleFence);
        }
        Ok(())
    }

    fn next_sequence(&mut self) -> Result<u64, PluginSessionError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(PluginSessionError::InvalidHistory)?;
        Ok(sequence)
    }

    fn matching_events(&self, invocation_id: &str) -> Vec<&PluginSessionEvent> {
        self.events
            .iter()
            .filter(|event| event.fence.invocation_id == invocation_id)
            .collect()
    }

    fn receipt_for(event: &PluginSessionEvent) -> Result<PluginSessionReceipt, PluginSessionError> {
        match event.status {
            PluginSessionEventStatus::Prepared => Ok(PluginSessionReceipt::ReplayRequired {
                event_sequence: event.sequence,
                fence: event.fence.clone(),
                side_effect_digest: event.side_effect_digest.clone(),
            }),
            PluginSessionEventStatus::Committed => Ok(PluginSessionReceipt::AlreadyApplied {
                event_sequence: event.sequence,
                fence: event.fence.clone(),
                cursor_after: event
                    .cursor_after
                    .ok_or(PluginSessionError::InvalidHistory)?,
            }),
            PluginSessionEventStatus::Cancelled => Ok(PluginSessionReceipt::Cancelled {
                event_sequence: event.sequence,
                fence: event.fence.clone(),
                reason: event
                    .cancel_reason
                    .ok_or(PluginSessionError::InvalidHistory)?,
            }),
        }
    }

    fn append_invocation_event(
        &mut self,
        draft: &PluginSessionEventDraft<'_>,
    ) -> Result<PluginSessionEvent, PluginSessionError> {
        if !is_digest(draft.side_effect_digest) {
            return Err(PluginSessionError::InvalidScope);
        }
        if draft.recorded_at.trim().is_empty() {
            return Err(PluginSessionError::InvalidHistory);
        }
        let sequence = self.next_sequence()?;
        let event = PluginSessionEvent {
            sequence,
            kind: draft.kind,
            status: draft.status,
            fence: draft.fence.clone(),
            side_effect_digest: draft.side_effect_digest.to_owned(),
            idempotency_digest: digest(
                format!(
                    "{}:{}:{}",
                    draft.fence.invocation_id, draft.side_effect_digest, sequence
                )
                .as_bytes(),
            ),
            cursor_after: draft.cursor_after,
            lifecycle_after: draft.lifecycle_after,
            cancel_reason: draft.cancel_reason,
            recorded_at: draft.recorded_at.to_owned(),
        };
        self.events.push(event.clone());
        self.validate()?;
        Ok(event)
    }

    pub fn prepare(
        &mut self,
        fence: &PluginSessionFence,
        side_effect_digest: &str,
        now: &str,
    ) -> Result<PluginSessionReceipt, PluginSessionError> {
        self.ensure_write_fence(fence)?;
        if !is_digest(side_effect_digest) {
            return Err(PluginSessionError::InvalidScope);
        }
        if let Some(existing) = self.matching_events(&fence.invocation_id).last() {
            if existing.fence.cursor != fence.cursor
                || existing.side_effect_digest != side_effect_digest
            {
                return Err(PluginSessionError::InvocationConflict);
            }
            return Self::receipt_for(existing);
        }
        let event = self.append_invocation_event(&PluginSessionEventDraft {
            kind: PluginSessionEventKind::Prepared,
            status: PluginSessionEventStatus::Prepared,
            fence,
            side_effect_digest,
            recorded_at: now,
            cursor_after: None,
            lifecycle_after: None,
            cancel_reason: None,
        })?;
        Ok(PluginSessionReceipt::Prepared {
            event_sequence: event.sequence,
            fence: fence.clone(),
            side_effect_digest: side_effect_digest.to_owned(),
        })
    }

    pub fn commit(
        &mut self,
        fence: &PluginSessionFence,
        side_effect_digest: &str,
        next_cursor: u64,
        now: &str,
    ) -> Result<PluginSessionReceipt, PluginSessionError> {
        self.ensure_write_fence(fence)?;
        if next_cursor < fence.cursor {
            return Err(PluginSessionError::CursorRegression);
        }
        let matching = self.matching_events(&fence.invocation_id);
        let Some(existing) = matching.last() else {
            return Err(PluginSessionError::MissingPreparation);
        };
        if existing.fence.cursor != fence.cursor
            || existing.side_effect_digest != side_effect_digest
        {
            return Err(PluginSessionError::InvocationConflict);
        }
        if existing.status != PluginSessionEventStatus::Prepared {
            return Self::receipt_for(existing);
        }
        let event = self.append_invocation_event(&PluginSessionEventDraft {
            kind: PluginSessionEventKind::Committed,
            status: PluginSessionEventStatus::Committed,
            fence,
            side_effect_digest,
            recorded_at: now,
            cursor_after: Some(next_cursor),
            lifecycle_after: None,
            cancel_reason: None,
        })?;
        self.current_fence.cursor = next_cursor;
        Ok(PluginSessionReceipt::AlreadyApplied {
            event_sequence: event.sequence,
            fence: fence.clone(),
            cursor_after: next_cursor,
        })
    }

    pub fn resume(
        &self,
        fence: &PluginSessionFence,
    ) -> Result<Option<PluginSessionReceipt>, PluginSessionError> {
        self.ensure_read_fence(fence)?;
        let matching = self.matching_events(&fence.invocation_id);
        let Some(existing) = matching.last() else {
            if fence != &self.current_fence {
                return Err(PluginSessionError::StaleFence);
            }
            return Ok(None);
        };
        if existing.fence.cursor != fence.cursor {
            if existing.status == PluginSessionEventStatus::Committed
                || existing.status == PluginSessionEventStatus::Cancelled
            {
                return Self::receipt_for(existing).map(Some);
            }
            return Err(PluginSessionError::StaleFence);
        }
        Self::receipt_for(existing).map(Some)
    }

    pub fn bind_next_invocation(
        &mut self,
        next_fence: PluginSessionFence,
    ) -> Result<(), PluginSessionError> {
        self.current_fence.validate()?;
        next_fence.validate()?;
        if self.lifecycle != PluginSessionLifecycle::Mounted {
            return Err(PluginSessionError::LifecycleUnavailable);
        }
        if !next_fence.immutable_matches(&self.current_fence)
            || next_fence.cursor != self.current_fence.cursor
            || next_fence.invocation_id == self.current_fence.invocation_id
        {
            return Err(PluginSessionError::StaleFence);
        }
        self.current_fence = next_fence;
        Ok(())
    }

    fn cancel(
        &mut self,
        fence: &PluginSessionFence,
        lifecycle: PluginSessionLifecycle,
        reason: PluginSessionCancelReason,
        now: &str,
    ) -> Result<Vec<PluginSessionReceipt>, PluginSessionError> {
        self.ensure_write_fence(fence)?;
        let pending = self
            .events
            .iter()
            .filter(|event| event.status == PluginSessionEventStatus::Prepared)
            .cloned()
            .collect::<Vec<_>>();
        let mut receipts = Vec::new();
        if pending.is_empty() {
            let marker_fence = fence.clone();
            self.append_invocation_event(&PluginSessionEventDraft {
                kind: PluginSessionEventKind::Lifecycle,
                status: PluginSessionEventStatus::Cancelled,
                fence: &marker_fence,
                side_effect_digest: &digest(b"lifecycle"),
                recorded_at: now,
                cursor_after: None,
                lifecycle_after: Some(lifecycle),
                cancel_reason: Some(reason),
            })?;
        } else {
            for event in pending {
                let cancelled = self.append_invocation_event(&PluginSessionEventDraft {
                    kind: PluginSessionEventKind::Cancelled,
                    status: PluginSessionEventStatus::Cancelled,
                    fence: &event.fence,
                    side_effect_digest: &event.side_effect_digest,
                    recorded_at: now,
                    cursor_after: None,
                    lifecycle_after: Some(lifecycle),
                    cancel_reason: Some(reason),
                })?;
                receipts.push(Self::receipt_for(&cancelled)?);
            }
        }
        self.lifecycle = lifecycle;
        self.validate()?;
        Ok(receipts)
    }

    pub fn revoke(
        &mut self,
        fence: &PluginSessionFence,
        now: &str,
    ) -> Result<Vec<PluginSessionReceipt>, PluginSessionError> {
        self.cancel(
            fence,
            PluginSessionLifecycle::Revoked,
            PluginSessionCancelReason::Revoked,
            now,
        )
    }

    pub fn unmount(
        &mut self,
        fence: &PluginSessionFence,
        now: &str,
    ) -> Result<Vec<PluginSessionReceipt>, PluginSessionError> {
        self.cancel(
            fence,
            PluginSessionLifecycle::Unmounted,
            PluginSessionCancelReason::Unmounted,
            now,
        )
    }

    pub fn events_since(&self, sequence: usize) -> &[PluginSessionEvent] {
        &self.events[sequence.min(self.events.len())..]
    }
}

pub trait PluginSessionProvider {
    fn prepare_invocation(
        &mut self,
        fence: &PluginSessionFence,
        side_effect_digest: &str,
        now: &str,
    ) -> Result<PluginSessionReceipt, PluginSessionError>;

    fn commit_invocation(
        &mut self,
        fence: &PluginSessionFence,
        side_effect_digest: &str,
        next_cursor: u64,
        now: &str,
    ) -> Result<PluginSessionReceipt, PluginSessionError>;
}

pub trait PluginSessionConsumer {
    fn resume_invocation(
        &self,
        fence: &PluginSessionFence,
    ) -> Result<Option<PluginSessionReceipt>, PluginSessionError>;
}

#[derive(Clone, Eq, PartialEq)]
pub struct PluginSessionService {
    journal: PluginSessionJournal,
}

impl fmt::Debug for PluginSessionService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionService")
            .field("journal", &self.journal)
            .finish_non_exhaustive()
    }
}

impl PluginSessionService {
    pub fn new(fence: PluginSessionFence) -> Result<Self, PluginSessionError> {
        Ok(Self {
            journal: PluginSessionJournal::new(fence)?,
        })
    }

    pub fn from_events(
        fence: PluginSessionFence,
        events: Vec<PluginSessionEvent>,
    ) -> Result<Self, PluginSessionError> {
        Ok(Self {
            journal: PluginSessionJournal::from_events(fence, events)?,
        })
    }

    pub fn journal(&self) -> &PluginSessionJournal {
        &self.journal
    }

    pub fn bind_next_invocation(
        &mut self,
        next_fence: PluginSessionFence,
    ) -> Result<(), PluginSessionError> {
        self.journal.bind_next_invocation(next_fence)
    }

    pub fn revoke(
        &mut self,
        fence: &PluginSessionFence,
        now: &str,
    ) -> Result<Vec<PluginSessionReceipt>, PluginSessionError> {
        self.journal.revoke(fence, now)
    }

    pub fn unmount(
        &mut self,
        fence: &PluginSessionFence,
        now: &str,
    ) -> Result<Vec<PluginSessionReceipt>, PluginSessionError> {
        self.journal.unmount(fence, now)
    }

    pub fn into_events(self) -> Vec<PluginSessionEvent> {
        self.journal.events
    }
}

impl PluginSessionProvider for PluginSessionService {
    fn prepare_invocation(
        &mut self,
        fence: &PluginSessionFence,
        side_effect_digest: &str,
        now: &str,
    ) -> Result<PluginSessionReceipt, PluginSessionError> {
        self.journal.prepare(fence, side_effect_digest, now)
    }

    fn commit_invocation(
        &mut self,
        fence: &PluginSessionFence,
        side_effect_digest: &str,
        next_cursor: u64,
        now: &str,
    ) -> Result<PluginSessionReceipt, PluginSessionError> {
        self.journal
            .commit(fence, side_effect_digest, next_cursor, now)
    }
}

impl PluginSessionConsumer for PluginSessionService {
    fn resume_invocation(
        &self,
        fence: &PluginSessionFence,
    ) -> Result<Option<PluginSessionReceipt>, PluginSessionError> {
        self.journal.resume(fence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fence(invocation: &str, cursor: u64) -> PluginSessionFence {
        PluginSessionFence::new(
            PluginSessionScope::new(
                TenantId::from("tenant-session"),
                ProjectId::from("project-session"),
                MissionId::from("mission-session"),
            ),
            PluginSessionDescriptor::new("plugin.market", "1.2.3", digest(b"plugin-binary-v1")),
            PluginSessionPosition::new(invocation, cursor, 3, 4),
        )
    }

    fn effect(value: &str) -> String {
        digest(value.as_bytes())
    }

    #[test]
    fn prepared_invocation_reopens_as_replay_without_duplicate_events() {
        let initial = fence("invocation-1", 0);
        let mut service = PluginSessionService::new(initial.clone()).expect("service");
        let prepared = service
            .prepare_invocation(&initial, &effect("side-effect"), "2026-08-14T00:00:00Z")
            .expect("prepare");
        assert!(matches!(
            prepared,
            PluginSessionReceipt::Prepared {
                event_sequence: 1,
                ..
            }
        ));
        assert_eq!(service.journal().events().len(), 1);

        let events = service.journal().events().to_vec();
        let reopened = PluginSessionService::from_events(initial.clone(), events).expect("reopen");
        let resumed = reopened
            .resume_invocation(&initial)
            .expect("resume")
            .expect("receipt");
        assert!(matches!(
            resumed,
            PluginSessionReceipt::ReplayRequired {
                event_sequence: 1,
                ..
            }
        ));
        assert_eq!(reopened.journal().events().len(), 1);
        let mut reopened = reopened;
        let replay = reopened
            .prepare_invocation(&initial, &effect("side-effect"), "2026-08-14T00:00:01Z")
            .expect("idempotent prepare");
        assert!(matches!(
            replay,
            PluginSessionReceipt::ReplayRequired {
                event_sequence: 1,
                ..
            }
        ));
    }

    #[test]
    fn commit_advances_cursor_and_old_fence_cannot_write_again() {
        let initial = fence("invocation-1", 0);
        let mut service = PluginSessionService::new(initial.clone()).expect("service");
        let side_effect = effect("browser-or-provider-side-effect");
        service
            .prepare_invocation(&initial, &side_effect, "2026-08-14T00:00:00Z")
            .expect("prepare");
        let committed = service
            .commit_invocation(&initial, &side_effect, 1, "2026-08-14T00:00:02Z")
            .expect("commit");
        assert!(matches!(
            committed,
            PluginSessionReceipt::AlreadyApplied {
                event_sequence: 2,
                cursor_after: 1,
                ..
            }
        ));
        assert_eq!(service.journal().fence().cursor(), 1);
        assert_eq!(
            service.commit_invocation(&initial, &side_effect, 1, "2026-08-14T00:00:03Z"),
            Err(PluginSessionError::StaleFence)
        );
        let next = initial.with_cursor(1).with_invocation("invocation-2");
        service
            .bind_next_invocation(next.clone())
            .expect("bind next invocation");
        assert!(
            service
                .resume_invocation(&initial)
                .expect("old replay")
                .is_some()
        );
        assert_eq!(
            service.resume_invocation(&next).expect("new invocation"),
            None
        );
    }

    #[test]
    fn scope_plugin_version_digest_and_generation_drift_fail_closed() {
        let initial = fence("invocation-1", 0);
        let mut service = PluginSessionService::new(initial.clone()).expect("service");
        let before = service.journal().clone();
        let wrong_digest = PluginSessionFence::new(
            PluginSessionScope::new(
                initial.tenant_id.clone(),
                initial.project_id.clone(),
                initial.mission_id.clone(),
            ),
            PluginSessionDescriptor::new(
                initial.plugin_id.clone(),
                initial.plugin_version.clone(),
                effect("different-plugin"),
            ),
            PluginSessionPosition::new(initial.invocation_id.clone(), 0, 3, 4),
        );
        assert_eq!(
            service.prepare_invocation(&wrong_digest, &effect("x"), "2026-08-14T00:00:00Z"),
            Err(PluginSessionError::StaleFence)
        );
        let wrong_generation = initial.with_generation(4, 5);
        assert_eq!(
            service.resume_invocation(&wrong_generation),
            Err(PluginSessionError::StaleFence)
        );
        assert_eq!(service.journal(), &before);
    }

    #[test]
    fn revoke_and_unmount_cancel_pending_and_terminal_refuses_resume() {
        let initial = fence("invocation-1", 0);
        let mut service = PluginSessionService::new(initial.clone()).expect("service");
        service
            .prepare_invocation(&initial, &effect("side-effect"), "2026-08-14T00:00:00Z")
            .expect("prepare");
        let receipts = service
            .journal
            .revoke(&initial, "2026-08-14T00:00:01Z")
            .expect("revoke");
        assert!(matches!(
            receipts.as_slice(),
            [PluginSessionReceipt::Cancelled { .. }]
        ));
        let history = service.journal().events().to_vec();
        let reopened = PluginSessionService::from_events(initial.clone(), history).expect("reopen");
        assert!(matches!(
            reopened.resume_invocation(&initial).expect("resume"),
            Some(PluginSessionReceipt::Cancelled { .. })
        ));
        let mut unmounted = PluginSessionService::new(fence("invocation-2", 0)).expect("service");
        let unmount_fence = unmounted.journal().fence().clone();
        unmounted
            .journal
            .unmount(&unmount_fence, "2026-08-14T00:00:02Z")
            .expect("unmount");
        assert_eq!(
            unmounted.prepare_invocation(
                &unmount_fence,
                &effect("blocked"),
                "2026-08-14T00:00:03Z"
            ),
            Err(PluginSessionError::LifecycleUnavailable)
        );
    }

    #[test]
    fn malformed_history_and_cursor_regression_fail_closed() {
        let initial = fence("invocation-1", 2);
        let mut service = PluginSessionService::new(initial.clone()).expect("service");
        let side_effect = effect("side-effect");
        service
            .prepare_invocation(&initial, &side_effect, "2026-08-14T00:00:00Z")
            .expect("prepare");
        assert_eq!(
            service.commit_invocation(&initial, &side_effect, 1, "2026-08-14T00:00:01Z"),
            Err(PluginSessionError::CursorRegression)
        );
        let mut history = service.journal().events().to_vec();
        history[0].fence.plugin_digest = "bad".into();
        assert_eq!(
            PluginSessionService::from_events(initial, history),
            Err(PluginSessionError::InvalidHistory)
        );
    }
}
