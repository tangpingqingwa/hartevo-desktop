//! Mission-scoped, on-demand projection of durable plugin invocation events.
//!
//! The provider reads the existing Application event spine and never appends
//! an event, creates a receipt, or talks to a native process. The consumer is
//! deliberately a Mission-shell contract: it materializes content-free
//! inline nodes only for the lifetime of an explicit request. Unmounting or
//! revoking the consumer clears its active projection while the provider can
//! still serve the durable, content-free audit trail.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use hartevo_storage::DomainEventRecord;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ApplicationError, ApplicationService};

pub const PLUGIN_INVOCATION_TIMELINE_MAX_PAGE_SIZE: usize = 64;

const CURSOR_SCHEMA: &str = "hartevo.plugin-invocation-timeline.cursor/v1";
const SCOPE_SCHEMA: &str = "hartevo.plugin-invocation-timeline.scope/v1";
const PREFIX_SCHEMA: &str = "hartevo.plugin-invocation-timeline.prefix/v1";
const DIGEST_HEX_LENGTH: usize = 64;

/// The durable stages understood by the first plugin invocation timeline
/// slice. The event payload remains private; only this typed stage crosses
/// the Application/Desktop boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginInvocationTimelineStage {
    Started,
    ModelVisibleLogged,
    ToolProgress,
    Result,
    Adopted,
    Rejected,
    Revoked,
    Recovery,
}

impl PluginInvocationTimelineStage {
    const fn order(self) -> u8 {
        match self {
            Self::Started => 0,
            Self::ModelVisibleLogged => 1,
            Self::ToolProgress => 2,
            Self::Result => 3,
            Self::Adopted | Self::Rejected => 4,
            Self::Revoked => 5,
            Self::Recovery => 6,
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::Adopted | Self::Rejected | Self::Revoked)
    }
}

/// A content-free status for an inline Mission-shell node.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginInvocationTimelineNodeStatus {
    Observed,
    Adopted,
    Rejected,
    Revoked,
    Recovering,
}

impl PluginInvocationTimelineNodeStatus {
    const fn for_stage(stage: PluginInvocationTimelineStage) -> Self {
        match stage {
            PluginInvocationTimelineStage::Started
            | PluginInvocationTimelineStage::ModelVisibleLogged
            | PluginInvocationTimelineStage::ToolProgress
            | PluginInvocationTimelineStage::Result => Self::Observed,
            PluginInvocationTimelineStage::Adopted => Self::Adopted,
            PluginInvocationTimelineStage::Rejected => Self::Rejected,
            PluginInvocationTimelineStage::Revoked => Self::Revoked,
            PluginInvocationTimelineStage::Recovery => Self::Recovering,
        }
    }
}

/// Lifecycle of the on-demand Mission-shell consumer.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginInvocationTimelineLifecycle {
    Mounted,
    Unmounted,
    Revoked,
}

impl PluginInvocationTimelineLifecycle {
    const fn is_active(self) -> bool {
        matches!(self, Self::Mounted)
    }
}

/// Exact Project/Mission scope bound into the timeline handle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[allow(
    clippy::struct_field_names,
    reason = "scope fields intentionally carry the exact tenant, Project, and Mission identity"
)]
pub struct PluginInvocationTimelineScope {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
}

impl PluginInvocationTimelineScope {
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }
}

/// A tamper-evident cursor over one exact Mission timeline revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PluginInvocationTimelineCursor {
    scope_digest: String,
    revision: u64,
    after_sequence: Option<u64>,
    prefix_digest: String,
    cursor_digest: String,
}

impl PluginInvocationTimelineCursor {
    pub fn scope_digest(&self) -> &str {
        &self.scope_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn after_sequence(&self) -> Option<u64> {
        self.after_sequence
    }

    pub fn prefix_digest(&self) -> &str {
        &self.prefix_digest
    }

    pub fn cursor_digest(&self) -> &str {
        &self.cursor_digest
    }

    fn computed_digest(&self) -> Result<String, PluginInvocationTimelineError> {
        digest_json(&serde_json::json!({
            "schema": CURSOR_SCHEMA,
            "scopeDigest": &self.scope_digest,
            "revision": self.revision,
            "afterSequence": self.after_sequence,
            "prefixDigest": &self.prefix_digest,
        }))
    }
}

/// One durable, content-free timeline entry. The source payload and raw
/// plugin/invocation identifiers never cross this boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PluginInvocationTimelineEntry {
    sequence: u64,
    stage: PluginInvocationTimelineStage,
    plugin_digest: String,
    invocation_digest: String,
    detail_digest: String,
    event_digest: String,
}

impl PluginInvocationTimelineEntry {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn stage(&self) -> PluginInvocationTimelineStage {
        self.stage
    }

    pub fn plugin_digest(&self) -> &str {
        &self.plugin_digest
    }

    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    pub fn detail_digest(&self) -> &str {
        &self.detail_digest
    }

    pub fn event_digest(&self) -> &str {
        &self.event_digest
    }
}

/// The content-free DTO consumed by the Desktop Mission shell.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PluginInvocationTimelineInlineNode {
    sequence: u64,
    stage: PluginInvocationTimelineStage,
    status: PluginInvocationTimelineNodeStatus,
    plugin_digest: String,
    invocation_digest: String,
    detail_digest: String,
    event_digest: String,
    active: bool,
}

impl PluginInvocationTimelineInlineNode {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn stage(&self) -> PluginInvocationTimelineStage {
        self.stage
    }

    pub const fn status(&self) -> PluginInvocationTimelineNodeStatus {
        self.status
    }

    pub fn plugin_digest(&self) -> &str {
        &self.plugin_digest
    }

    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    pub fn detail_digest(&self) -> &str {
        &self.detail_digest
    }

    pub fn event_digest(&self) -> &str {
        &self.event_digest
    }

    pub const fn active(&self) -> bool {
        self.active
    }
}

/// A durable audit page. It is readable after unmount/revoke but is never an
/// active shell projection by itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PluginInvocationTimelineAuditPage {
    scope: PluginInvocationTimelineScope,
    revision: u64,
    entries: Vec<PluginInvocationTimelineEntry>,
    cursor: PluginInvocationTimelineCursor,
    next_cursor: Option<PluginInvocationTimelineCursor>,
    caught_up: bool,
    projection_digest: String,
}

impl PluginInvocationTimelineAuditPage {
    pub fn scope(&self) -> &PluginInvocationTimelineScope {
        &self.scope
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn entries(&self) -> &[PluginInvocationTimelineEntry] {
        &self.entries
    }

    pub fn cursor(&self) -> &PluginInvocationTimelineCursor {
        &self.cursor
    }

    pub fn next_cursor(&self) -> Option<&PluginInvocationTimelineCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn caught_up(&self) -> bool {
        self.caught_up
    }

    pub fn projection_digest(&self) -> &str {
        &self.projection_digest
    }
}

/// An on-demand Mission-shell page. It has no content-bearing result body and
/// does not imply that a Mission or business outcome is complete.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PluginInvocationTimelineInlinePage {
    scope: PluginInvocationTimelineScope,
    revision: u64,
    nodes: Vec<PluginInvocationTimelineInlineNode>,
    cursor: PluginInvocationTimelineCursor,
    next_cursor: Option<PluginInvocationTimelineCursor>,
    caught_up: bool,
    projection_digest: String,
}

impl PluginInvocationTimelineInlinePage {
    pub fn scope(&self) -> &PluginInvocationTimelineScope {
        &self.scope
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn nodes(&self) -> &[PluginInvocationTimelineInlineNode] {
        &self.nodes
    }

    pub fn cursor(&self) -> &PluginInvocationTimelineCursor {
        &self.cursor
    }

    pub fn next_cursor(&self) -> Option<&PluginInvocationTimelineCursor> {
        self.next_cursor.as_ref()
    }

    pub const fn caught_up(&self) -> bool {
        self.caught_up
    }

    pub fn projection_digest(&self) -> &str {
        &self.projection_digest
    }
}

#[derive(Debug, Error)]
pub enum PluginInvocationTimelineError {
    #[error("durable Application event read failed: {0}")]
    Application(#[from] ApplicationError),
    #[error("timeline canonical digest failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the Mission scope does not match the requested Project/Mission")]
    ScopeMismatch,
    #[error(
        "the Mission revision changed while the timeline handle was live: expected {expected}, actual {actual}"
    )]
    RevisionMismatch { expected: u64, actual: u64 },
    #[error("timeline page size must be between 1 and {PLUGIN_INVOCATION_TIMELINE_MAX_PAGE_SIZE}")]
    InvalidPageSize,
    #[error("the Mission has no durable plugin invocation event")]
    NoPluginInvocation,
    #[error("durable event sequence must be positive: {sequence}")]
    InvalidEventSequence { sequence: i64 },
    #[error("durable Mission event sequence regressed from {previous} to {current}")]
    EventSequenceRegression { previous: u64, current: u64 },
    #[error("durable plugin invocation event has an unsupported stage: {event_type}")]
    UnsupportedInvocationStage { event_type: String },
    #[error("durable plugin invocation event is missing a content-free identity")]
    InvalidInvocationEvent,
    #[error("duplicate durable plugin invocation event identity")]
    DuplicateInvocationEvent,
    #[error("durable plugin invocation stage regressed for one invocation")]
    InvocationStageRegression,
    #[error("cursor scope does not match this Mission timeline")]
    CursorScopeMismatch,
    #[error("cursor revision does not match this Mission timeline")]
    CursorRevisionMismatch,
    #[error("cursor digest is invalid")]
    CursorDigestMismatch,
    #[error("cursor prefix digest is invalid")]
    CursorPrefixMismatch,
    #[error("cursor refers to a missing durable timeline sequence: {sequence}")]
    CursorHistoryMissing { sequence: u64 },
    #[error("cursor is ahead of the durable timeline: {sequence}")]
    CursorAhead { sequence: u64 },
    #[error("consumer cursor regressed")]
    CursorRegression,
    #[error("consumer cursor skipped a durable timeline page")]
    CursorSkipped,
    #[error("the Mission-shell timeline is not active: {lifecycle:?}")]
    LifecycleInactive {
        lifecycle: PluginInvocationTimelineLifecycle,
    },
}

/// Durable projector/provider for one exact Mission timeline.
pub struct PluginInvocationTimelineProvider<'a> {
    application: &'a ApplicationService,
    scope: PluginInvocationTimelineScope,
    revision: u64,
}

impl fmt::Debug for PluginInvocationTimelineProvider<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginInvocationTimelineProvider")
            .field("scope", &self.scope)
            .field("revision", &self.revision)
            .finish()
    }
}

impl PluginInvocationTimelineProvider<'_> {
    pub fn scope(&self) -> &PluginInvocationTimelineScope {
        &self.scope
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn initial_cursor(
        &self,
    ) -> Result<PluginInvocationTimelineCursor, PluginInvocationTimelineError> {
        let snapshot = self.snapshot()?;
        Ok(snapshot.cursor_at(None))
    }

    /// Read the durable audit projection without creating or mutating any
    /// application state.
    pub fn read_audit(
        &self,
        cursor: Option<&PluginInvocationTimelineCursor>,
        page_size: usize,
    ) -> Result<PluginInvocationTimelineAuditPage, PluginInvocationTimelineError> {
        validate_page_size(page_size)?;
        let snapshot = self.snapshot()?;
        let (current_cursor, start) = self.validate_cursor(cursor, &snapshot)?;
        let end = start.saturating_add(page_size).min(snapshot.entries.len());
        let entries = snapshot.entries[start..end].to_vec();
        let page_cursor = if end > start {
            snapshot.cursor_at(Some(end - 1))
        } else {
            current_cursor
        };
        let next_cursor = (!snapshot.entries.is_empty() && end < snapshot.entries.len())
            .then(|| page_cursor.clone());
        Ok(PluginInvocationTimelineAuditPage {
            scope: self.scope.clone(),
            revision: self.revision,
            entries,
            cursor: page_cursor,
            next_cursor,
            caught_up: end == snapshot.entries.len(),
            projection_digest: snapshot.projection_digest,
        })
    }

    fn read_inline(
        &self,
        cursor: Option<&PluginInvocationTimelineCursor>,
        page_size: usize,
    ) -> Result<PluginInvocationTimelineInlinePage, PluginInvocationTimelineError> {
        validate_page_size(page_size)?;
        let snapshot = self.snapshot()?;
        let (current_cursor, start) = self.validate_cursor(cursor, &snapshot)?;
        let end = start.saturating_add(page_size).min(snapshot.entries.len());
        let entries = &snapshot.entries[start..end];
        let page_cursor = if end > start {
            snapshot.cursor_at(Some(end - 1))
        } else {
            current_cursor
        };
        let next_cursor = (!snapshot.entries.is_empty() && end < snapshot.entries.len())
            .then(|| page_cursor.clone());
        let latest_stages = latest_stages(&snapshot.entries);
        let nodes = entries
            .iter()
            .map(|entry| PluginInvocationTimelineInlineNode {
                sequence: entry.sequence,
                stage: entry.stage,
                status: PluginInvocationTimelineNodeStatus::for_stage(entry.stage),
                plugin_digest: entry.plugin_digest.clone(),
                invocation_digest: entry.invocation_digest.clone(),
                detail_digest: entry.detail_digest.clone(),
                event_digest: entry.event_digest.clone(),
                active: latest_stages
                    .get(&(entry.plugin_digest.clone(), entry.invocation_digest.clone()))
                    .is_none_or(|stage| !stage.is_terminal()),
            })
            .collect();
        Ok(PluginInvocationTimelineInlinePage {
            scope: self.scope.clone(),
            revision: self.revision,
            nodes,
            cursor: page_cursor,
            next_cursor,
            caught_up: end == snapshot.entries.len(),
            projection_digest: snapshot.projection_digest,
        })
    }

    fn snapshot(&self) -> Result<ProjectionSnapshot, PluginInvocationTimelineError> {
        let mission = self
            .application
            .load_mission(&self.scope.project_id, &self.scope.mission_id)?;
        if mission.tenant_id != self.scope.tenant_id
            || mission.project_id != self.scope.project_id
            || mission.id != self.scope.mission_id
        {
            return Err(PluginInvocationTimelineError::ScopeMismatch);
        }
        if mission.revision != self.revision {
            return Err(PluginInvocationTimelineError::RevisionMismatch {
                expected: self.revision,
                actual: mission.revision,
            });
        }
        let events = self
            .application
            .mission_events(&self.scope.project_id, &self.scope.mission_id)?;
        let snapshot = project_events(&self.scope, self.revision, &events)?;
        if snapshot.entries.is_empty() {
            return Err(PluginInvocationTimelineError::NoPluginInvocation);
        }
        Ok(snapshot)
    }

    fn validate_cursor(
        &self,
        cursor: Option<&PluginInvocationTimelineCursor>,
        snapshot: &ProjectionSnapshot,
    ) -> Result<(PluginInvocationTimelineCursor, usize), PluginInvocationTimelineError> {
        let cursor = cursor.cloned().unwrap_or_else(|| snapshot.cursor_at(None));
        let scope_digest = scope_digest(&self.scope)?;
        if cursor.scope_digest != scope_digest {
            return Err(PluginInvocationTimelineError::CursorScopeMismatch);
        }
        if cursor.revision != self.revision {
            return Err(PluginInvocationTimelineError::CursorRevisionMismatch);
        }
        if !is_digest(&cursor.prefix_digest)
            || !is_digest(&cursor.cursor_digest)
            || cursor.cursor_digest != cursor.computed_digest()?
        {
            return Err(PluginInvocationTimelineError::CursorDigestMismatch);
        }
        let start = match cursor.after_sequence {
            None => {
                if cursor.prefix_digest != snapshot.initial_prefix_digest {
                    return Err(PluginInvocationTimelineError::CursorPrefixMismatch);
                }
                0
            }
            Some(sequence) => {
                let Some(index) = snapshot
                    .entries
                    .iter()
                    .position(|entry| entry.sequence == sequence)
                else {
                    let latest = snapshot.entries.last().map_or(0, |entry| entry.sequence);
                    if sequence > latest {
                        return Err(PluginInvocationTimelineError::CursorAhead { sequence });
                    }
                    return Err(PluginInvocationTimelineError::CursorHistoryMissing { sequence });
                };
                if cursor.prefix_digest != snapshot.prefix_digests[index] {
                    return Err(PluginInvocationTimelineError::CursorPrefixMismatch);
                }
                index + 1
            }
        };
        Ok((cursor, start))
    }
}

/// Mission-scoped service handle. It contains no durable write authority and
/// owns no raw event payload. Call into_mission_shell_consumer to opt into the
/// on-demand Desktop surface contract.
pub struct PluginInvocationTimeline {
    scope: PluginInvocationTimelineScope,
    revision: u64,
    lifecycle: PluginInvocationTimelineLifecycle,
}

impl fmt::Debug for PluginInvocationTimeline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginInvocationTimeline")
            .field("scope", &self.scope)
            .field("revision", &self.revision)
            .field("lifecycle", &self.lifecycle)
            .finish()
    }
}

impl PluginInvocationTimeline {
    fn new(scope: PluginInvocationTimelineScope, revision: u64) -> Self {
        Self {
            scope,
            revision,
            lifecycle: PluginInvocationTimelineLifecycle::Mounted,
        }
    }

    pub fn scope(&self) -> &PluginInvocationTimelineScope {
        &self.scope
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn lifecycle(&self) -> PluginInvocationTimelineLifecycle {
        self.lifecycle
    }

    pub const fn is_active(&self) -> bool {
        self.lifecycle.is_active()
    }

    pub fn provider<'a>(
        &self,
        application: &'a ApplicationService,
    ) -> PluginInvocationTimelineProvider<'a> {
        PluginInvocationTimelineProvider {
            application,
            scope: self.scope.clone(),
            revision: self.revision,
        }
    }

    pub fn read_audit(
        &self,
        application: &ApplicationService,
        cursor: Option<&PluginInvocationTimelineCursor>,
        page_size: usize,
    ) -> Result<PluginInvocationTimelineAuditPage, PluginInvocationTimelineError> {
        self.provider(application).read_audit(cursor, page_size)
    }

    pub fn into_mission_shell_consumer(self) -> PluginInvocationTimelineMissionShellConsumer {
        PluginInvocationTimelineMissionShellConsumer {
            timeline: self,
            last_request: None,
            last_page_cursor: None,
            expected_next_cursor: None,
            active_projection: None,
        }
    }
}

/// On-demand consumer contract for the persistent Mission conversation shell.
/// It is intentionally not a dashboard, workbench, or global Operations
/// panel. Cursor progression is tracked only for this consumer instance.
pub struct PluginInvocationTimelineMissionShellConsumer {
    timeline: PluginInvocationTimeline,
    last_request: Option<PluginInvocationTimelineCursor>,
    last_page_cursor: Option<PluginInvocationTimelineCursor>,
    expected_next_cursor: Option<PluginInvocationTimelineCursor>,
    active_projection: Option<PluginInvocationTimelineInlinePage>,
}

impl fmt::Debug for PluginInvocationTimelineMissionShellConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginInvocationTimelineMissionShellConsumer")
            .field("timeline", &self.timeline)
            .field("last_request", &self.last_request)
            .field("last_page_cursor", &self.last_page_cursor)
            .field("expected_next_cursor", &self.expected_next_cursor)
            .field("has_active_projection", &self.active_projection.is_some())
            .finish()
    }
}

impl PluginInvocationTimelineMissionShellConsumer {
    pub fn scope(&self) -> &PluginInvocationTimelineScope {
        self.timeline.scope()
    }

    pub const fn revision(&self) -> u64 {
        self.timeline.revision()
    }

    pub const fn lifecycle(&self) -> PluginInvocationTimelineLifecycle {
        self.timeline.lifecycle()
    }

    pub const fn is_active(&self) -> bool {
        self.timeline.is_active()
    }

    pub const fn has_active_projection(&self) -> bool {
        self.active_projection.is_some()
    }

    /// Project one content-free inline page on demand from the durable spine.
    pub fn project_inline(
        &mut self,
        application: &ApplicationService,
        cursor: Option<&PluginInvocationTimelineCursor>,
        page_size: usize,
    ) -> Result<PluginInvocationTimelineInlinePage, PluginInvocationTimelineError> {
        if !self.timeline.is_active() {
            return Err(PluginInvocationTimelineError::LifecycleInactive {
                lifecycle: self.timeline.lifecycle,
            });
        }
        let provider = self.timeline.provider(application);
        let normalized_cursor = match cursor {
            Some(cursor) => cursor.clone(),
            None => provider.initial_cursor()?,
        };
        let page = provider.read_inline(Some(&normalized_cursor), page_size)?;
        self.validate_progression(&normalized_cursor)?;
        self.last_request = Some(normalized_cursor);
        self.last_page_cursor = Some(page.cursor.clone());
        self.expected_next_cursor.clone_from(&page.next_cursor);
        self.active_projection = Some(page.clone());
        Ok(page)
    }

    /// Durable audit remains available after lifecycle teardown. This method
    /// does not repopulate the active inline projection.
    pub fn read_audit(
        &self,
        application: &ApplicationService,
        cursor: Option<&PluginInvocationTimelineCursor>,
        page_size: usize,
    ) -> Result<PluginInvocationTimelineAuditPage, PluginInvocationTimelineError> {
        self.timeline.read_audit(application, cursor, page_size)
    }

    pub fn unmount(&mut self) {
        self.timeline.lifecycle = PluginInvocationTimelineLifecycle::Unmounted;
        self.active_projection = None;
    }

    pub fn revoke(&mut self) {
        self.timeline.lifecycle = PluginInvocationTimelineLifecycle::Revoked;
        self.active_projection = None;
    }

    /// Clear only consumer cursor/projection state so a reselected Mission
    /// shell starts from the exact durable genesis cursor.
    pub fn reselect(&mut self) {
        if self.timeline.is_active() {
            self.last_request = None;
            self.last_page_cursor = None;
            self.expected_next_cursor = None;
            self.active_projection = None;
        }
    }

    fn validate_progression(
        &self,
        cursor: &PluginInvocationTimelineCursor,
    ) -> Result<(), PluginInvocationTimelineError> {
        let Some(last_request) = self.last_request.as_ref() else {
            return Ok(());
        };
        if cursor == last_request {
            return Ok(());
        }
        if self.last_page_cursor.as_ref() == Some(cursor) {
            return Ok(());
        }
        if self.expected_next_cursor.as_ref() == Some(cursor) {
            return Ok(());
        }
        let last_sequence = self
            .last_page_cursor
            .as_ref()
            .and_then(PluginInvocationTimelineCursor::after_sequence)
            .unwrap_or(0);
        let requested_sequence = cursor.after_sequence.unwrap_or(0);
        if requested_sequence < last_sequence {
            return Err(PluginInvocationTimelineError::CursorRegression);
        }
        if requested_sequence > last_sequence {
            return Err(PluginInvocationTimelineError::CursorSkipped);
        }
        Err(PluginInvocationTimelineError::CursorRegression)
    }
}

impl ApplicationService {
    /// Return an owned Mission-scoped timeline handle only when the durable
    /// Mission event spine contains a recognized plugin invocation.
    pub fn plugin_invocation_timeline(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Result<Option<PluginInvocationTimeline>, PluginInvocationTimelineError> {
        let mission = self.load_mission(project_id, mission_id)?;
        if mission.project_id != *project_id || mission.id != *mission_id {
            return Err(PluginInvocationTimelineError::ScopeMismatch);
        }
        let scope = PluginInvocationTimelineScope {
            tenant_id: mission.tenant_id,
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
        };
        let events = self.mission_events(project_id, mission_id)?;
        let snapshot = project_events(&scope, mission.revision, &events)?;
        if snapshot.entries.is_empty() {
            return Ok(None);
        }
        Ok(Some(PluginInvocationTimeline::new(scope, mission.revision)))
    }
}

#[derive(Clone)]
struct ProjectionSnapshot {
    scope_digest: String,
    revision: u64,
    entries: Vec<PluginInvocationTimelineEntry>,
    initial_prefix_digest: String,
    prefix_digests: Vec<String>,
    projection_digest: String,
}

impl ProjectionSnapshot {
    fn cursor_at(&self, index: Option<usize>) -> PluginInvocationTimelineCursor {
        let (after_sequence, prefix_digest) = match index {
            Some(index) => (
                Some(self.entries[index].sequence),
                self.prefix_digests[index].clone(),
            ),
            None => (None, self.initial_prefix_digest.clone()),
        };
        let mut cursor = PluginInvocationTimelineCursor {
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            after_sequence,
            prefix_digest,
            cursor_digest: String::new(),
        };
        cursor.cursor_digest = cursor
            .computed_digest()
            .expect("cursor digest serialization is infallible");
        cursor
    }
}

#[derive(Clone)]
struct CandidateEntry {
    stage: PluginInvocationTimelineStage,
    plugin_digest: String,
    invocation_digest: String,
    detail_digest: String,
    event_digest: String,
    identity_digest: String,
}

fn project_events(
    scope: &PluginInvocationTimelineScope,
    revision: u64,
    events: &[DomainEventRecord],
) -> Result<ProjectionSnapshot, PluginInvocationTimelineError> {
    let scope_digest = scope_digest(scope)?;
    let initial_prefix_digest = initial_prefix_digest(&scope_digest, revision)?;
    let mut entries = Vec::new();
    let mut prefix_digests = Vec::new();
    let mut previous_prefix_digest = initial_prefix_digest.clone();
    let mut last_sequence = None;
    let mut identities = BTreeSet::new();
    let mut latest_stages: BTreeMap<(String, String), PluginInvocationTimelineStage> =
        BTreeMap::new();

    for event in events {
        let sequence = u64::try_from(event.sequence).map_err(|_| {
            PluginInvocationTimelineError::InvalidEventSequence {
                sequence: event.sequence,
            }
        })?;
        if let Some(previous) = last_sequence
            && sequence <= previous
        {
            return Err(PluginInvocationTimelineError::EventSequenceRegression {
                previous,
                current: sequence,
            });
        }
        last_sequence = Some(sequence);
        if event.project_id != scope.project_id.clone()
            || event.mission_id.as_ref() != Some(&scope.mission_id)
        {
            return Err(PluginInvocationTimelineError::ScopeMismatch);
        }
        let Some(candidate) = classify_event(event)? else {
            continue;
        };
        if !identities.insert(candidate.identity_digest.clone()) {
            return Err(PluginInvocationTimelineError::DuplicateInvocationEvent);
        }
        let key = (
            candidate.plugin_digest.clone(),
            candidate.invocation_digest.clone(),
        );
        if let Some(previous) = latest_stages.get(&key)
            && candidate.stage.order() < previous.order()
        {
            return Err(PluginInvocationTimelineError::InvocationStageRegression);
        }
        if !latest_stages.contains_key(&key)
            && candidate.stage != PluginInvocationTimelineStage::Started
        {
            return Err(PluginInvocationTimelineError::InvocationStageRegression);
        }
        latest_stages.insert(key, candidate.stage);
        entries.push(PluginInvocationTimelineEntry {
            sequence,
            stage: candidate.stage,
            plugin_digest: candidate.plugin_digest,
            invocation_digest: candidate.invocation_digest,
            detail_digest: candidate.detail_digest,
            event_digest: candidate.event_digest,
        });
        let entry = entries.last().expect("entry was just pushed");
        let prefix = prefix_digest(&scope_digest, revision, &previous_prefix_digest, entry)?;
        prefix_digests.push(prefix.clone());
        previous_prefix_digest = prefix;
    }

    let projection_digest = prefix_digests
        .last()
        .cloned()
        .unwrap_or_else(|| initial_prefix_digest.clone());
    Ok(ProjectionSnapshot {
        scope_digest,
        revision,
        entries,
        initial_prefix_digest,
        prefix_digests,
        projection_digest,
    })
}

fn classify_event(
    event: &DomainEventRecord,
) -> Result<Option<CandidateEntry>, PluginInvocationTimelineError> {
    let normalized = normalize_event_type(&event.event_type);
    let invocation_namespace = normalized.starts_with("plugin_invocation_")
        || normalized.starts_with("plugin_tool_")
        || normalized.contains("_plugin_invocation_");
    if !invocation_namespace {
        return Ok(None);
    }
    let stage = stage_for_event_type(&normalized).ok_or_else(|| {
        PluginInvocationTimelineError::UnsupportedInvocationStage {
            event_type: event.event_type.clone(),
        }
    })?;
    let plugin_id = required_payload_string(&event.payload, &["pluginId", "plugin_id", "plugin"])?;
    let invocation_id = required_payload_string(
        &event.payload,
        &["invocationId", "invocation_id", "invocation"],
    )?;
    let content_free_payload = without_clock_fields(&event.payload);
    let detail_digest = digest_json(&content_free_payload)?;
    let plugin_digest = digest_text(&plugin_id);
    let invocation_digest = digest_text(&invocation_id);
    let identity_digest = digest_json(&serde_json::json!({
        "stage": stage,
        "pluginDigest": &plugin_digest,
        "invocationDigest": &invocation_digest,
        "detailDigest": &detail_digest,
    }))?;
    let event_digest = digest_json(&serde_json::json!({
        "sequence": event.sequence,
        "eventType": &normalized,
        "stage": stage,
        "pluginDigest": &plugin_digest,
        "invocationDigest": &invocation_digest,
        "detailDigest": &detail_digest,
    }))?;
    Ok(Some(CandidateEntry {
        stage,
        plugin_digest,
        invocation_digest,
        detail_digest,
        event_digest,
        identity_digest,
    }))
}

fn stage_for_event_type(normalized: &str) -> Option<PluginInvocationTimelineStage> {
    if normalized.ends_with("_started") || normalized.ends_with("_start") {
        Some(PluginInvocationTimelineStage::Started)
    } else if normalized.contains("model_visible")
        || normalized.contains("model_logged")
        || normalized.ends_with("_logged")
    {
        Some(PluginInvocationTimelineStage::ModelVisibleLogged)
    } else if normalized.contains("tool_progress") || normalized.ends_with("_progress") {
        Some(PluginInvocationTimelineStage::ToolProgress)
    } else if normalized.contains("result") {
        Some(PluginInvocationTimelineStage::Result)
    } else if normalized.contains("adopt") {
        Some(PluginInvocationTimelineStage::Adopted)
    } else if normalized.contains("reject") {
        Some(PluginInvocationTimelineStage::Rejected)
    } else if normalized.contains("revoke") {
        Some(PluginInvocationTimelineStage::Revoked)
    } else if normalized.contains("recover") {
        Some(PluginInvocationTimelineStage::Recovery)
    } else {
        None
    }
}

fn required_payload_string(
    payload: &Value,
    keys: &[&str],
) -> Result<String, PluginInvocationTimelineError> {
    for key in keys {
        if let Some(value) = payload.get(*key) {
            let Value::String(value) = value else {
                return Err(PluginInvocationTimelineError::InvalidInvocationEvent);
            };
            if value.trim().is_empty() {
                return Err(PluginInvocationTimelineError::InvalidInvocationEvent);
            }
            return Ok(value.clone());
        }
    }
    Err(PluginInvocationTimelineError::InvalidInvocationEvent)
}

fn latest_stages(
    entries: &[PluginInvocationTimelineEntry],
) -> BTreeMap<(String, String), PluginInvocationTimelineStage> {
    let mut latest = BTreeMap::new();
    for entry in entries {
        latest.insert(
            (entry.plugin_digest.clone(), entry.invocation_digest.clone()),
            entry.stage,
        );
    }
    latest
}

fn validate_page_size(page_size: usize) -> Result<(), PluginInvocationTimelineError> {
    if page_size == 0 || page_size > PLUGIN_INVOCATION_TIMELINE_MAX_PAGE_SIZE {
        return Err(PluginInvocationTimelineError::InvalidPageSize);
    }
    Ok(())
}

fn normalize_event_type(value: &str) -> String {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join("_")
}

fn without_clock_fields(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(without_clock_fields).collect()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| !is_clock_field(key))
                .map(|(key, value)| (key.clone(), without_clock_fields(value)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn is_clock_field(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "recordedat"
            | "timestamp"
            | "createdat"
            | "updatedat"
            | "observedat"
            | "occurredat"
            | "receivedat"
    )
}

fn scope_digest(
    scope: &PluginInvocationTimelineScope,
) -> Result<String, PluginInvocationTimelineError> {
    digest_json(&serde_json::json!({
        "schema": SCOPE_SCHEMA,
        "tenantId": &scope.tenant_id,
        "projectId": &scope.project_id,
        "missionId": &scope.mission_id,
    }))
}

fn initial_prefix_digest(
    scope_digest: &str,
    revision: u64,
) -> Result<String, PluginInvocationTimelineError> {
    digest_json(&serde_json::json!({
        "schema": PREFIX_SCHEMA,
        "scopeDigest": scope_digest,
        "revision": revision,
        "entryCount": 0,
    }))
}

fn prefix_digest(
    scope_digest: &str,
    revision: u64,
    previous_prefix_digest: &str,
    entry: &PluginInvocationTimelineEntry,
) -> Result<String, PluginInvocationTimelineError> {
    digest_json(&serde_json::json!({
        "schema": PREFIX_SCHEMA,
        "scopeDigest": scope_digest,
        "revision": revision,
        "previous": previous_prefix_digest,
        "sequence": entry.sequence,
        "eventDigest": &entry.event_digest,
    }))
}

fn digest_text(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn digest_json(value: &Value) -> Result<String, PluginInvocationTimelineError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn is_digest(value: &str) -> bool {
    value.len() == DIGEST_HEX_LENGTH && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, TimeZone, Utc};
    use hartevo_domain_kernel::{MissionId, ProjectId, StorageMode, TaskId, TenantId};
    use hartevo_storage::ProjectStore;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::{CreateProject, StartMission};

    struct Fixture {
        service: ApplicationService,
        _workspace: TempDir,
        project_id: ProjectId,
        mission_id: MissionId,
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("valid fixture time")
    }

    fn fixture() -> Fixture {
        let workspace = tempfile::tempdir().expect("workspace");
        let project_id = ProjectId::from("plugin-timeline-project");
        let mission_id = MissionId::from("plugin-timeline-mission");
        let mut service = ApplicationService::new(ProjectStore::in_memory().expect("store"));
        service
            .create_project(
                CreateProject {
                    tenant_id: TenantId::from("plugin-timeline-tenant"),
                    id: project_id.clone(),
                    name: "Plugin timeline fixture".into(),
                    description: String::new(),
                    workspace_root: workspace.path().to_path_buf(),
                    storage_mode: StorageMode::LocalNew,
                },
                now(),
            )
            .expect("project");
        service
            .start_mission(
                StartMission {
                    id: mission_id.clone(),
                    research_task_id: TaskId::from("plugin-timeline-task"),
                    project_id: project_id.clone(),
                    title: Some("Plugin timeline Mission".into()),
                    prompt: "fixture Mission prompt".into(),
                },
                now(),
            )
            .expect("Mission");
        Fixture {
            service,
            _workspace: workspace,
            project_id,
            mission_id,
        }
    }

    fn append_plugin_event(
        fixture: &mut Fixture,
        mission_id: &MissionId,
        event_type: &str,
        invocation_id: &str,
        private_body: &str,
    ) {
        fixture
            .service
            .store
            .append_event(
                &fixture.project_id,
                Some(mission_id),
                event_type,
                &json!({
                    "pluginId": "fixture-plugin-private-id",
                    "invocationId": invocation_id,
                    "privateBody": private_body,
                    "recordedAt": "must-not-enter-digest",
                }),
                now(),
            )
            .expect("durable fixture event");
    }

    fn append_primary_event(
        fixture: &mut Fixture,
        event_type: &str,
        invocation_id: &str,
        private_body: &str,
    ) {
        let mission_id = fixture.mission_id.clone();
        append_plugin_event(
            fixture,
            &mission_id,
            event_type,
            invocation_id,
            private_body,
        );
    }

    fn start_other_mission(fixture: &mut Fixture) -> MissionId {
        let mission_id = MissionId::from("plugin-timeline-other-mission");
        fixture
            .service
            .start_mission(
                StartMission {
                    id: mission_id.clone(),
                    research_task_id: TaskId::from("plugin-timeline-other-task"),
                    project_id: fixture.project_id.clone(),
                    title: Some("Other Mission".into()),
                    prompt: "other Mission prompt".into(),
                },
                now() + Duration::seconds(1),
            )
            .expect("other Mission");
        mission_id
    }

    #[test]
    fn no_plugin_invocation_is_none_and_cross_mission_is_hidden() {
        let mut fixture = fixture();
        assert!(
            fixture
                .service
                .plugin_invocation_timeline(&fixture.project_id, &fixture.mission_id)
                .expect("timeline lookup")
                .is_none()
        );

        let other_mission_id = start_other_mission(&mut fixture);
        append_plugin_event(
            &mut fixture,
            &other_mission_id,
            "plugin.invocation.started",
            "other-invocation",
            "other-private-body",
        );
        assert!(
            fixture
                .service
                .plugin_invocation_timeline(&fixture.project_id, &fixture.mission_id)
                .expect("first Mission remains plugin-free")
                .is_none()
        );

        append_primary_event(
            &mut fixture,
            "plugin.invocation.started",
            "first-invocation",
            "first-private-body",
        );
        let first = fixture
            .service
            .plugin_invocation_timeline(&fixture.project_id, &fixture.mission_id)
            .expect("first timeline")
            .expect("first plugin invocation");
        let other = fixture
            .service
            .plugin_invocation_timeline(&fixture.project_id, &other_mission_id)
            .expect("other timeline")
            .expect("other plugin invocation");
        let other_page = other
            .provider(&fixture.service)
            .read_audit(None, 8)
            .expect("other audit");
        let mut consumer = first.into_mission_shell_consumer();
        let first_page = consumer
            .project_inline(&fixture.service, None, 8)
            .expect("first inline page");
        assert_eq!(first_page.nodes().len(), 1);
        assert!(matches!(
            consumer.project_inline(&fixture.service, Some(other_page.cursor()), 8),
            Err(PluginInvocationTimelineError::CursorScopeMismatch)
        ));
        assert_eq!(first_page.scope().mission_id(), &fixture.mission_id);
    }

    #[test]
    fn projects_ordered_content_free_nodes_and_retains_audit_after_revoke() {
        let mut fixture = fixture();
        let events = [
            ("plugin.invocation.started", "started"),
            ("plugin.invocation.model_visible_logged", "model-visible"),
            ("plugin.invocation.tool_progress", "tool-progress"),
            ("plugin.invocation.result", "result"),
            ("plugin.invocation.adopted", "adopted"),
            ("plugin.invocation.revoked", "revoked"),
            ("plugin.invocation.recovery", "recovery"),
        ];
        for (event_type, body) in events {
            append_primary_event(&mut fixture, event_type, "ordered-invocation", body);
        }
        let timeline = fixture
            .service
            .plugin_invocation_timeline(&fixture.project_id, &fixture.mission_id)
            .expect("timeline")
            .expect("plugin invocation");
        let mut consumer = timeline.into_mission_shell_consumer();
        let mut cursor = None;
        let mut nodes = Vec::new();
        loop {
            let page = consumer
                .project_inline(&fixture.service, cursor.as_ref(), 3)
                .expect("inline page");
            nodes.extend(page.nodes().iter().cloned());
            if page.caught_up() {
                break;
            }
            cursor = page.next_cursor().cloned();
            assert!(cursor.is_some());
        }
        assert_eq!(nodes.len(), events.len());
        assert_eq!(nodes[0].stage(), PluginInvocationTimelineStage::Started);
        assert_eq!(
            nodes[1].stage(),
            PluginInvocationTimelineStage::ModelVisibleLogged
        );
        assert_eq!(
            nodes[2].stage(),
            PluginInvocationTimelineStage::ToolProgress
        );
        assert_eq!(nodes[3].stage(), PluginInvocationTimelineStage::Result);
        assert_eq!(
            nodes[4].status(),
            PluginInvocationTimelineNodeStatus::Adopted
        );
        assert_eq!(
            nodes[5].status(),
            PluginInvocationTimelineNodeStatus::Revoked
        );
        assert_eq!(
            nodes[6].status(),
            PluginInvocationTimelineNodeStatus::Recovering
        );
        let serialized = serde_json::to_string(&nodes).expect("content-free DTO JSON");
        assert!(!serialized.contains("fixture-plugin-private-id"));
        assert!(!serialized.contains("private-body"));
        assert!(!serialized.contains("must-not-enter-digest"));
        assert!(consumer.has_active_projection());

        consumer.revoke();
        assert!(!consumer.is_active());
        assert!(!consumer.has_active_projection());
        assert!(matches!(
            consumer.project_inline(&fixture.service, None, 3),
            Err(PluginInvocationTimelineError::LifecycleInactive { .. })
        ));
        let audit = consumer
            .read_audit(&fixture.service, None, 64)
            .expect("audit survives revoke");
        assert_eq!(audit.entries().len(), events.len());
        assert!(audit.caught_up());

        let second_timeline = fixture
            .service
            .plugin_invocation_timeline(&fixture.project_id, &fixture.mission_id)
            .expect("second timeline")
            .expect("second plugin invocation");
        let mut unmounted = second_timeline.into_mission_shell_consumer();
        unmounted
            .project_inline(&fixture.service, None, 2)
            .expect("second inline page");
        unmounted.unmount();
        assert!(!unmounted.is_active());
        assert!(!unmounted.has_active_projection());
        assert_eq!(
            unmounted
                .read_audit(&fixture.service, None, 64)
                .expect("audit survives unmount")
                .entries()
                .len(),
            events.len()
        );
    }

    #[test]
    fn replay_is_read_only_late_delta_is_exact_and_cursor_regression_is_rejected() {
        let mut fixture = fixture();
        append_primary_event(
            &mut fixture,
            "plugin.invocation.started",
            "continuation-invocation",
            "started-private",
        );
        let timeline = fixture
            .service
            .plugin_invocation_timeline(&fixture.project_id, &fixture.mission_id)
            .expect("timeline")
            .expect("plugin invocation");
        let mut consumer = timeline.into_mission_shell_consumer();
        let event_count_before = fixture
            .service
            .mission_events(&fixture.project_id, &fixture.mission_id)
            .expect("events")
            .len();
        let first = consumer
            .project_inline(&fixture.service, None, 1)
            .expect("first page");
        let replay = consumer
            .project_inline(&fixture.service, None, 1)
            .expect("same-cursor replay");
        assert_eq!(first, replay);
        assert_eq!(
            fixture
                .service
                .mission_events(&fixture.project_id, &fixture.mission_id)
                .expect("events after replay")
                .len(),
            event_count_before
        );

        let next = first.cursor().clone();
        append_primary_event(
            &mut fixture,
            "plugin.invocation.model_visible_logged",
            "continuation-invocation",
            "late-model-private",
        );
        let late = consumer
            .project_inline(&fixture.service, Some(&next), 1)
            .expect("late durable delta");
        assert_eq!(
            late.nodes()[0].stage(),
            PluginInvocationTimelineStage::ModelVisibleLogged
        );
        assert!(
            !serde_json::to_string(&late)
                .expect("inline json")
                .contains("late-model-private")
        );
        assert!(matches!(
            consumer.project_inline(&fixture.service, None, 1),
            Err(PluginInvocationTimelineError::CursorRegression)
        ));

        let mut mission = fixture
            .service
            .load_mission(&fixture.project_id, &fixture.mission_id)
            .expect("Mission");
        mission.revision = mission.revision.saturating_add(1);
        fixture
            .service
            .store
            .save_mission(&mission)
            .expect("fixture revision mutation");
        assert!(matches!(
            consumer.read_audit(&fixture.service, None, 8),
            Err(PluginInvocationTimelineError::RevisionMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_durable_invocation_identity_fails_closed() {
        let mut fixture = fixture();
        append_primary_event(
            &mut fixture,
            "plugin.invocation.started",
            "duplicate-invocation",
            "same-private-body",
        );
        append_primary_event(
            &mut fixture,
            "plugin.invocation.started",
            "duplicate-invocation",
            "same-private-body",
        );
        assert!(matches!(
            fixture
                .service
                .plugin_invocation_timeline(&fixture.project_id, &fixture.mission_id),
            Err(PluginInvocationTimelineError::DuplicateInvocationEvent)
        ));
    }

    #[test]
    fn cursor_scope_revision_prefix_and_history_fences_are_exact() {
        let mut fixture = fixture();
        append_primary_event(
            &mut fixture,
            "plugin.invocation.started",
            "cursor-invocation",
            "cursor-private-body",
        );
        let timeline = fixture
            .service
            .plugin_invocation_timeline(&fixture.project_id, &fixture.mission_id)
            .expect("timeline")
            .expect("plugin invocation");
        let provider = timeline.provider(&fixture.service);
        let first = provider.read_audit(None, 1).expect("first audit page");

        let mut ahead = first.cursor().clone();
        ahead.after_sequence = Some(u64::MAX);
        ahead.cursor_digest = ahead.computed_digest().expect("ahead cursor digest");
        assert!(matches!(
            provider.read_audit(Some(&ahead), 1),
            Err(PluginInvocationTimelineError::CursorAhead { .. })
        ));

        let mut missing = first.cursor().clone();
        missing.after_sequence = Some(1);
        missing.cursor_digest = missing.computed_digest().expect("missing cursor digest");
        assert!(matches!(
            provider.read_audit(Some(&missing), 1),
            Err(PluginInvocationTimelineError::CursorHistoryMissing { .. })
        ));

        let mut wrong_prefix = first.cursor().clone();
        wrong_prefix.prefix_digest = provider
            .initial_cursor()
            .expect("initial cursor")
            .prefix_digest
            .clone();
        wrong_prefix.cursor_digest = wrong_prefix
            .computed_digest()
            .expect("wrong prefix cursor digest");
        assert!(matches!(
            provider.read_audit(Some(&wrong_prefix), 1),
            Err(PluginInvocationTimelineError::CursorPrefixMismatch)
        ));
        assert!(matches!(
            provider.read_audit(None, 0),
            Err(PluginInvocationTimelineError::InvalidPageSize)
        ));
    }
}
