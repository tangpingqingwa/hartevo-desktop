#![allow(
    dead_code,
    reason = "UI-SUB-02A freezes the pure Desktop reducer contract before the UI-SUB-01 Application producer is wired"
)]

use std::collections::BTreeMap;
use std::fmt;

use hartevo_domain_kernel::{MissionId, ProjectId, RuntimeTurnStatus};
use thiserror::Error;

use crate::data_plane::DesktopRuntimeCancellation;

const SHA256_HEX_LENGTH: usize = 64;
const DIGEST_LABEL_LENGTH: usize = 8;

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DesktopOpaqueDigest(String);

impl DesktopOpaqueDigest {
    pub(crate) fn parse(value: impl Into<String>) -> Result<Self, RuntimeSubscriptionError> {
        let value = value.into();
        if value.len() != SHA256_HEX_LENGTH
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(RuntimeSubscriptionError::InvalidDigest);
        }
        Ok(Self(value))
    }

    fn short_label(&self) -> &str {
        &self.0[..DIGEST_LABEL_LENGTH]
    }
}

impl fmt::Debug for DesktopOpaqueDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}…", self.short_label())
    }
}

/// Exact UI scope for one persisted Mission stream. The digest binds the
/// future Application Mission handle, but is not execution or approval
/// authority by itself.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DesktopRuntimeSubscriptionScope {
    project_id: ProjectId,
    mission_id: MissionId,
    mission_handle_digest: DesktopOpaqueDigest,
}

impl DesktopRuntimeSubscriptionScope {
    pub(crate) fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        mission_handle_digest: impl Into<String>,
    ) -> Result<Self, RuntimeSubscriptionError> {
        Ok(Self {
            project_id,
            mission_id,
            mission_handle_digest: DesktopOpaqueDigest::parse(mission_handle_digest)?,
        })
    }

    pub(crate) fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub(crate) fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }
}

impl fmt::Debug for DesktopRuntimeSubscriptionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeSubscriptionScope")
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("mission_handle", &self.mission_handle_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DesktopRuntimeSubscriptionEpoch(u64);

impl DesktopRuntimeSubscriptionEpoch {
    pub(crate) const fn get(self) -> u64 {
        self.0
    }
}

/// Content-free metadata for one integrity-checked Runtime text turn. Raw
/// attempt/thread identifiers and private text stay outside this reducer.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeTurnDeliveryMeta {
    turn_identity_digest: DesktopOpaqueDigest,
    worker_generation: u64,
    turn_revision: u64,
    last_evidence_sequence: Option<u64>,
    turn_status: RuntimeTurnStatus,
}

impl DesktopRuntimeTurnDeliveryMeta {
    pub(crate) fn new(
        turn_identity_digest: impl Into<String>,
        worker_generation: u64,
        turn_revision: u64,
        last_evidence_sequence: Option<u64>,
        turn_status: RuntimeTurnStatus,
    ) -> Result<Self, RuntimeSubscriptionError> {
        if worker_generation == 0 {
            return Err(RuntimeSubscriptionError::InvalidWorkerGeneration);
        }
        if last_evidence_sequence == Some(0) {
            return Err(RuntimeSubscriptionError::InvalidEvidenceSequence);
        }
        Ok(Self {
            turn_identity_digest: DesktopOpaqueDigest::parse(turn_identity_digest)?,
            worker_generation,
            turn_revision,
            last_evidence_sequence,
            turn_status,
        })
    }

    fn same_turn_as(&self, other: &Self) -> bool {
        self.turn_identity_digest == other.turn_identity_digest
            && self.worker_generation == other.worker_generation
    }
}

impl fmt::Debug for DesktopRuntimeTurnDeliveryMeta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeTurnDeliveryMeta")
            .field("turn", &self.turn_identity_digest)
            .field("worker_generation", &self.worker_generation)
            .field("turn_revision", &self.turn_revision)
            .field("last_evidence_sequence", &self.last_evidence_sequence)
            .field("turn_status", &self.turn_status)
            .finish()
    }
}

/// Closed delivery vocabulary for the future Application pull subscription.
/// `Reset` is the only variant allowed to replace a turn or clear a cursor;
/// `CaughtUp` only confirms cursor position and cannot advance turn state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DesktopRuntimeDeliveryMeta {
    AwaitingTurn {
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
    },
    Reset {
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
        turn: DesktopRuntimeTurnDeliveryMeta,
    },
    Append {
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
        turn: DesktopRuntimeTurnDeliveryMeta,
    },
    CaughtUp {
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
        turn: DesktopRuntimeTurnDeliveryMeta,
    },
}

impl DesktopRuntimeDeliveryMeta {
    fn scope(&self) -> &DesktopRuntimeSubscriptionScope {
        match self {
            Self::AwaitingTurn { scope, .. }
            | Self::Reset { scope, .. }
            | Self::Append { scope, .. }
            | Self::CaughtUp { scope, .. } => scope,
        }
    }

    const fn epoch(&self) -> DesktopRuntimeSubscriptionEpoch {
        match self {
            Self::AwaitingTurn { epoch, .. }
            | Self::Reset { epoch, .. }
            | Self::Append { epoch, .. }
            | Self::CaughtUp { epoch, .. } => *epoch,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeViewportCursor {
    turn_identity_digest: DesktopOpaqueDigest,
    worker_generation: u64,
    after_evidence_sequence: Option<u64>,
}

impl fmt::Debug for DesktopRuntimeViewportCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeViewportCursor")
            .field("turn", &self.turn_identity_digest)
            .field("worker_generation", &self.worker_generation)
            .field("after_evidence_sequence", &self.after_evidence_sequence)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeSelection {
    pub(crate) scope: DesktopRuntimeSubscriptionScope,
    pub(crate) epoch: DesktopRuntimeSubscriptionEpoch,
    pub(crate) cursor: Option<DesktopRuntimeViewportCursor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeViewportState {
    scope: DesktopRuntimeSubscriptionScope,
    follow_latest: bool,
    has_unseen: bool,
    turn: Option<DesktopRuntimeTurnDeliveryMeta>,
    last_delivery: Option<DesktopRuntimeDeliveryMeta>,
}

impl DesktopRuntimeViewportState {
    fn new(scope: DesktopRuntimeSubscriptionScope) -> Self {
        Self {
            scope,
            follow_latest: true,
            has_unseen: false,
            turn: None,
            last_delivery: None,
        }
    }

    pub(crate) fn follow_latest(&self) -> bool {
        self.follow_latest
    }

    pub(crate) fn has_unseen(&self) -> bool {
        self.has_unseen
    }

    pub(crate) fn cursor(&self) -> Option<DesktopRuntimeViewportCursor> {
        self.turn.as_ref().map(|turn| DesktopRuntimeViewportCursor {
            turn_identity_digest: turn.turn_identity_digest.clone(),
            worker_generation: turn.worker_generation,
            after_evidence_sequence: turn.last_evidence_sequence,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DesktopRuntimeReducerEffect {
    IgnoredStale,
    Duplicate,
    AwaitingTurn,
    Reset {
        cleared_cursor: Option<DesktopRuntimeViewportCursor>,
        should_scroll: bool,
    },
    Appended {
        should_scroll: bool,
        has_unseen: bool,
    },
    CaughtUp,
}

#[derive(Debug, Default)]
pub(crate) struct DesktopRuntimeSubscriptionReducer {
    last_epoch: u64,
    selected: Option<(
        DesktopRuntimeSubscriptionScope,
        DesktopRuntimeSubscriptionEpoch,
    )>,
    viewports: BTreeMap<DesktopRuntimeSubscriptionScope, DesktopRuntimeViewportState>,
}

impl DesktopRuntimeSubscriptionReducer {
    /// Changes the selected scope and invalidates all outstanding deliveries
    /// with a checked epoch transition. Returning to a scope preserves its
    /// cursor and viewport preference, but receives a new epoch.
    pub(crate) fn select_scope(
        &mut self,
        scope: Option<DesktopRuntimeSubscriptionScope>,
    ) -> Result<Option<DesktopRuntimeSelection>, RuntimeSubscriptionError> {
        let next_epoch = self
            .last_epoch
            .checked_add(1)
            .ok_or(RuntimeSubscriptionError::EpochOverflow)?;
        let epoch = DesktopRuntimeSubscriptionEpoch(next_epoch);
        self.last_epoch = next_epoch;
        let Some(scope) = scope else {
            self.selected = None;
            return Ok(None);
        };
        let viewport = self
            .viewports
            .entry(scope.clone())
            .or_insert_with(|| DesktopRuntimeViewportState::new(scope.clone()));
        let selection = DesktopRuntimeSelection {
            scope: scope.clone(),
            epoch,
            cursor: viewport.cursor(),
        };
        self.selected = Some((scope, epoch));
        Ok(Some(selection))
    }

    pub(crate) fn viewport(
        &self,
        scope: &DesktopRuntimeSubscriptionScope,
    ) -> Option<&DesktopRuntimeViewportState> {
        self.viewports.get(scope)
    }

    pub(crate) fn set_follow_latest(
        &mut self,
        scope: &DesktopRuntimeSubscriptionScope,
        follow_latest: bool,
    ) -> Result<(), RuntimeSubscriptionError> {
        if self
            .selected
            .as_ref()
            .is_none_or(|(selected, _)| selected != scope)
        {
            return Err(RuntimeSubscriptionError::ScopeNotSelected);
        }
        let viewport = self
            .viewports
            .get_mut(scope)
            .ok_or(RuntimeSubscriptionError::ViewportMissing)?;
        viewport.follow_latest = follow_latest;
        if follow_latest {
            viewport.has_unseen = false;
        }
        Ok(())
    }

    pub(crate) fn apply_delivery(
        &mut self,
        delivery: DesktopRuntimeDeliveryMeta,
    ) -> Result<DesktopRuntimeReducerEffect, RuntimeSubscriptionError> {
        let selected_matches = self
            .selected
            .as_ref()
            .is_some_and(|(scope, epoch)| scope == delivery.scope() && *epoch == delivery.epoch());
        if !selected_matches {
            return Ok(DesktopRuntimeReducerEffect::IgnoredStale);
        }
        let viewport = self
            .viewports
            .get_mut(delivery.scope())
            .ok_or(RuntimeSubscriptionError::ViewportMissing)?;
        if viewport.last_delivery.as_ref() == Some(&delivery) {
            return Ok(DesktopRuntimeReducerEffect::Duplicate);
        }

        match &delivery {
            DesktopRuntimeDeliveryMeta::AwaitingTurn { .. } => {
                if viewport.turn.is_some() {
                    return Err(RuntimeSubscriptionError::TurnHistoryDisappeared);
                }
                viewport.last_delivery = Some(delivery);
                Ok(DesktopRuntimeReducerEffect::AwaitingTurn)
            }
            DesktopRuntimeDeliveryMeta::Reset { turn, .. } => {
                let cleared_cursor = viewport.cursor();
                // Clearing happens before the replacement is installed so a
                // caller can never accidentally append a new generation onto
                // the previous turn's paragraph chain.
                viewport.turn = None;
                viewport.last_delivery = None;
                viewport.has_unseen = false;
                viewport.turn = Some(turn.clone());
                let should_scroll = viewport.follow_latest;
                viewport.last_delivery = Some(delivery);
                Ok(DesktopRuntimeReducerEffect::Reset {
                    cleared_cursor,
                    should_scroll,
                })
            }
            DesktopRuntimeDeliveryMeta::Append { turn, .. } => {
                let current = viewport
                    .turn
                    .as_ref()
                    .ok_or(RuntimeSubscriptionError::AppendBeforeReset)?;
                if !current.same_turn_as(turn) {
                    return Err(RuntimeSubscriptionError::ReplacementRequiresReset);
                }
                let incoming_sequence = turn
                    .last_evidence_sequence
                    .ok_or(RuntimeSubscriptionError::AppendWithoutEvidence)?;
                if let Some(previous_sequence) = current.last_evidence_sequence {
                    let minimum_sequence = previous_sequence
                        .checked_add(1)
                        .ok_or(RuntimeSubscriptionError::SequenceOverflow)?;
                    if incoming_sequence == previous_sequence {
                        return Err(RuntimeSubscriptionError::ConflictingDuplicate);
                    }
                    if incoming_sequence < minimum_sequence {
                        return Err(RuntimeSubscriptionError::SequenceRegressed);
                    }
                }
                viewport.turn = Some(turn.clone());
                if !viewport.follow_latest {
                    viewport.has_unseen = true;
                }
                let effect = DesktopRuntimeReducerEffect::Appended {
                    should_scroll: viewport.follow_latest,
                    has_unseen: viewport.has_unseen,
                };
                viewport.last_delivery = Some(delivery);
                Ok(effect)
            }
            DesktopRuntimeDeliveryMeta::CaughtUp { turn, .. } => {
                let current = viewport
                    .turn
                    .as_ref()
                    .ok_or(RuntimeSubscriptionError::CaughtUpBeforeReset)?;
                if !current.same_turn_as(turn) {
                    return Err(RuntimeSubscriptionError::ReplacementRequiresReset);
                }
                if current.last_evidence_sequence != turn.last_evidence_sequence {
                    return Err(RuntimeSubscriptionError::CaughtUpCursorMismatch);
                }
                if current.turn_revision != turn.turn_revision
                    || current.turn_status != turn.turn_status
                {
                    return Err(RuntimeSubscriptionError::CaughtUpStateChange);
                }
                // CaughtUp is a cursor acknowledgement only. In particular,
                // it cannot turn Running into Completed or infer Mission state.
                viewport.last_delivery = Some(delivery);
                Ok(DesktopRuntimeReducerEffect::CaughtUp)
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeCommandIdentity {
    scope: DesktopRuntimeSubscriptionScope,
    command_digest: DesktopOpaqueDigest,
}

impl fmt::Debug for DesktopRuntimeCommandIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeCommandIdentity")
            .field("scope", &self.scope)
            .field("command", &self.command_digest)
            .finish()
    }
}

/// UI-owned stop capability. It is intentionally not `Clone`; the only
/// second endpoint created by `pair` is a scope-tagged coordinator control.
pub(crate) struct DesktopRuntimeCommandHandle {
    identity: DesktopRuntimeCommandIdentity,
    cancellation: DesktopRuntimeCancellation,
}

impl DesktopRuntimeCommandHandle {
    pub(crate) fn pair(
        scope: DesktopRuntimeSubscriptionScope,
        command_digest: impl Into<String>,
    ) -> Result<(Self, DesktopRuntimeCoordinatorControl), RuntimeSubscriptionError> {
        let identity = DesktopRuntimeCommandIdentity {
            scope,
            command_digest: DesktopOpaqueDigest::parse(command_digest)?,
        };
        let cancellation = DesktopRuntimeCancellation::default();
        let coordinator = DesktopRuntimeCoordinatorControl {
            identity: identity.clone(),
            cancellation: cancellation.clone(),
        };
        Ok((
            Self {
                identity,
                cancellation,
            },
            coordinator,
        ))
    }

    pub(crate) fn identity(&self) -> DesktopRuntimeCommandIdentity {
        self.identity.clone()
    }

    fn request_stop_for(
        &self,
        selected_scope: Option<&DesktopRuntimeSubscriptionScope>,
    ) -> DesktopRuntimeStopDisposition {
        if selected_scope != Some(&self.identity.scope) {
            return DesktopRuntimeStopDisposition::ScopeMismatch;
        }
        if self.cancellation.is_requested() {
            return DesktopRuntimeStopDisposition::AlreadyRequested;
        }
        self.cancellation.request();
        DesktopRuntimeStopDisposition::Requested
    }
}

impl fmt::Debug for DesktopRuntimeCommandHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeCommandHandle")
            .field("identity", &self.identity)
            .field("stop_requested", &self.cancellation.is_requested())
            .finish()
    }
}

/// Background endpoint paired with exactly one UI command handle. This type is
/// also deliberately not `Clone`; later data-plane wiring may borrow its
/// cancellation only while running the matching command.
pub(crate) struct DesktopRuntimeCoordinatorControl {
    identity: DesktopRuntimeCommandIdentity,
    cancellation: DesktopRuntimeCancellation,
}

impl DesktopRuntimeCoordinatorControl {
    pub(crate) fn identity(&self) -> &DesktopRuntimeCommandIdentity {
        &self.identity
    }

    pub(crate) fn is_stop_requested(&self) -> bool {
        self.cancellation.is_requested()
    }
}

impl fmt::Debug for DesktopRuntimeCoordinatorControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeCoordinatorControl")
            .field("identity", &self.identity)
            .field("stop_requested", &self.cancellation.is_requested())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesktopRuntimeStopDisposition {
    Requested,
    AlreadyRequested,
    ScopeMismatch,
    NoActiveCommand,
}

#[derive(Debug, Default)]
pub(crate) struct DesktopRuntimeCommandSlot {
    active: Option<DesktopRuntimeCommandHandle>,
}

impl DesktopRuntimeCommandSlot {
    pub(crate) fn install(
        &mut self,
        handle: DesktopRuntimeCommandHandle,
    ) -> Result<(), RuntimeSubscriptionError> {
        if self.active.is_some() {
            return Err(RuntimeSubscriptionError::CommandAlreadyActive);
        }
        self.active = Some(handle);
        Ok(())
    }

    pub(crate) fn stop_available_for(&self, scope: &DesktopRuntimeSubscriptionScope) -> bool {
        self.active
            .as_ref()
            .is_some_and(|handle| &handle.identity.scope == scope)
    }

    pub(crate) fn request_stop_for(
        &self,
        selected_scope: Option<&DesktopRuntimeSubscriptionScope>,
    ) -> DesktopRuntimeStopDisposition {
        self.active
            .as_ref()
            .map_or(DesktopRuntimeStopDisposition::NoActiveCommand, |handle| {
                handle.request_stop_for(selected_scope)
            })
    }

    /// Clears only the command whose exact identity completed. A stale async
    /// completion cannot remove a newer command for the same Mission.
    pub(crate) fn finish_exact(&mut self, identity: &DesktopRuntimeCommandIdentity) -> bool {
        if self
            .active
            .as_ref()
            .is_some_and(|handle| &handle.identity == identity)
        {
            self.active = None;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum RuntimeSubscriptionError {
    #[error("opaque digest is not canonical lowercase sha256")]
    InvalidDigest,
    #[error("worker generation must be positive")]
    InvalidWorkerGeneration,
    #[error("evidence sequence must be positive")]
    InvalidEvidenceSequence,
    #[error("subscription epoch overflow")]
    EpochOverflow,
    #[error("runtime evidence sequence overflow")]
    SequenceOverflow,
    #[error("selected viewport is missing")]
    ViewportMissing,
    #[error("viewport mutation does not match the selected scope")]
    ScopeNotSelected,
    #[error("runtime append arrived before an explicit reset")]
    AppendBeforeReset,
    #[error("runtime append has no evidence sequence")]
    AppendWithoutEvidence,
    #[error("runtime turn replacement requires an explicit reset")]
    ReplacementRequiresReset,
    #[error("same evidence sequence carried conflicting metadata")]
    ConflictingDuplicate,
    #[error("runtime evidence sequence regressed")]
    SequenceRegressed,
    #[error("caught-up delivery arrived before an explicit reset")]
    CaughtUpBeforeReset,
    #[error("caught-up delivery does not match the viewport cursor")]
    CaughtUpCursorMismatch,
    #[error("caught-up delivery attempted to change Runtime turn state")]
    CaughtUpStateChange,
    #[error("a previously observed Runtime turn disappeared")]
    TurnHistoryDisappeared,
    #[error("a Runtime command is already active")]
    CommandAlreadyActive,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(character: char) -> String {
        character.to_string().repeat(SHA256_HEX_LENGTH)
    }

    fn scope(
        project: &str,
        mission: &str,
        digest_character: char,
    ) -> DesktopRuntimeSubscriptionScope {
        DesktopRuntimeSubscriptionScope::new(
            ProjectId::from(project),
            MissionId::from(mission),
            digest(digest_character),
        )
        .expect("canonical scope")
    }

    fn turn(
        digest_character: char,
        generation: u64,
        revision: u64,
        sequence: Option<u64>,
        status: RuntimeTurnStatus,
    ) -> DesktopRuntimeTurnDeliveryMeta {
        DesktopRuntimeTurnDeliveryMeta::new(
            digest(digest_character),
            generation,
            revision,
            sequence,
            status,
        )
        .expect("canonical turn")
    }

    fn reset(
        selection: &DesktopRuntimeSelection,
        turn: DesktopRuntimeTurnDeliveryMeta,
    ) -> DesktopRuntimeDeliveryMeta {
        DesktopRuntimeDeliveryMeta::Reset {
            scope: selection.scope.clone(),
            epoch: selection.epoch,
            turn,
        }
    }

    fn append(
        selection: &DesktopRuntimeSelection,
        turn: DesktopRuntimeTurnDeliveryMeta,
    ) -> DesktopRuntimeDeliveryMeta {
        DesktopRuntimeDeliveryMeta::Append {
            scope: selection.scope.clone(),
            epoch: selection.epoch,
            turn,
        }
    }

    fn caught_up(
        selection: &DesktopRuntimeSelection,
        turn: DesktopRuntimeTurnDeliveryMeta,
    ) -> DesktopRuntimeDeliveryMeta {
        DesktopRuntimeDeliveryMeta::CaughtUp {
            scope: selection.scope.clone(),
            epoch: selection.epoch,
            turn,
        }
    }

    #[test]
    fn opaque_digests_fail_closed_and_debug_uses_only_short_labels() {
        for invalid in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
            assert_eq!(
                DesktopOpaqueDigest::parse(invalid),
                Err(RuntimeSubscriptionError::InvalidDigest)
            );
        }
        let full_digest = digest('a');
        let exact_scope = scope("project-a", "mission-a", 'a');
        let debug = format!("{exact_scope:?}");
        assert!(debug.contains("sha256:aaaaaaaa…"));
        assert!(!debug.contains(&full_digest));
        assert_eq!(exact_scope.project_id(), &ProjectId::from("project-a"));
        assert_eq!(exact_scope.mission_id(), &MissionId::from("mission-a"));
    }

    #[test]
    fn selection_epoch_is_checked_and_reselect_invalidates_old_deliveries() {
        let scope_a = scope("project", "mission-a", 'a');
        let scope_b = scope("project", "mission-b", 'b');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selected_a_v1 = reducer
            .select_scope(Some(scope_a.clone()))
            .expect("select A")
            .expect("A selection");
        assert_eq!(selected_a_v1.epoch.get(), 1);
        reducer
            .apply_delivery(reset(
                &selected_a_v1,
                turn('c', 1, 3, Some(4), RuntimeTurnStatus::Running),
            ))
            .expect("reset A");

        let selected_b = reducer
            .select_scope(Some(scope_b))
            .expect("select B")
            .expect("B selection");
        assert_eq!(selected_b.epoch.get(), 2);
        assert_eq!(
            reducer
                .apply_delivery(append(
                    &selected_a_v1,
                    turn('c', 1, 4, Some(5), RuntimeTurnStatus::Running),
                ))
                .expect("stale A delivery"),
            DesktopRuntimeReducerEffect::IgnoredStale
        );

        let selected_a_v2 = reducer
            .select_scope(Some(scope_a.clone()))
            .expect("reselect A")
            .expect("A reselection");
        assert_eq!(selected_a_v2.epoch.get(), 3);
        assert_eq!(
            selected_a_v2
                .cursor
                .as_ref()
                .and_then(|cursor| cursor.after_evidence_sequence),
            Some(4)
        );
        assert_eq!(
            reducer
                .apply_delivery(append(
                    &selected_a_v1,
                    turn('c', 1, 4, Some(5), RuntimeTurnStatus::Running),
                ))
                .expect("old epoch after reselect"),
            DesktopRuntimeReducerEffect::IgnoredStale
        );

        reducer.last_epoch = u64::MAX;
        assert_eq!(
            reducer.select_scope(Some(scope_a)),
            Err(RuntimeSubscriptionError::EpochOverflow)
        );
    }

    #[test]
    fn reset_append_and_exact_duplicates_obey_cursor_contract() {
        let scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(scope.clone()))
            .expect("select")
            .expect("selection");
        let awaiting = DesktopRuntimeDeliveryMeta::AwaitingTurn {
            scope: scope.clone(),
            epoch: selection.epoch,
        };
        assert_eq!(
            reducer
                .apply_delivery(awaiting.clone())
                .expect("awaiting turn"),
            DesktopRuntimeReducerEffect::AwaitingTurn
        );
        assert_eq!(
            reducer
                .apply_delivery(awaiting)
                .expect("duplicate awaiting"),
            DesktopRuntimeReducerEffect::Duplicate
        );

        let running_at_two = turn('b', 1, 4, Some(2), RuntimeTurnStatus::Running);
        let initial_reset = reset(&selection, running_at_two.clone());
        assert_eq!(
            reducer
                .apply_delivery(initial_reset.clone())
                .expect("initial reset"),
            DesktopRuntimeReducerEffect::Reset {
                cleared_cursor: None,
                should_scroll: true,
            }
        );
        assert_eq!(
            reducer
                .apply_delivery(initial_reset)
                .expect("duplicate reset"),
            DesktopRuntimeReducerEffect::Duplicate
        );

        let running_at_three = turn('b', 1, 5, Some(3), RuntimeTurnStatus::Running);
        let append_three = append(&selection, running_at_three.clone());
        assert_eq!(
            reducer
                .apply_delivery(append_three.clone())
                .expect("append"),
            DesktopRuntimeReducerEffect::Appended {
                should_scroll: true,
                has_unseen: false,
            }
        );
        assert_eq!(
            reducer
                .apply_delivery(append_three)
                .expect("exact duplicate append"),
            DesktopRuntimeReducerEffect::Duplicate
        );
    }

    #[test]
    fn conflicting_append_and_caught_up_metadata_fail_closed() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope))
            .expect("select")
            .expect("selection");
        let running_at_three = turn('b', 1, 5, Some(3), RuntimeTurnStatus::Running);
        reducer
            .apply_delivery(reset(&selection, running_at_three.clone()))
            .expect("current turn");

        assert_eq!(
            reducer.apply_delivery(append(
                &selection,
                turn('b', 1, 6, Some(3), RuntimeTurnStatus::InterruptRequested,),
            )),
            Err(RuntimeSubscriptionError::ConflictingDuplicate)
        );
        assert_eq!(
            reducer.apply_delivery(append(
                &selection,
                turn('c', 1, 6, Some(3), RuntimeTurnStatus::Running),
            )),
            Err(RuntimeSubscriptionError::ReplacementRequiresReset)
        );
        assert_eq!(
            reducer.apply_delivery(append(
                &selection,
                turn('b', 2, 6, Some(3), RuntimeTurnStatus::Running),
            )),
            Err(RuntimeSubscriptionError::ReplacementRequiresReset)
        );
        assert_eq!(
            reducer.apply_delivery(append(
                &selection,
                turn('b', 1, 6, Some(2), RuntimeTurnStatus::Running),
            )),
            Err(RuntimeSubscriptionError::SequenceRegressed)
        );
        assert_eq!(
            reducer
                .apply_delivery(caught_up(&selection, running_at_three.clone()))
                .expect("caught up"),
            DesktopRuntimeReducerEffect::CaughtUp
        );
        assert_eq!(
            reducer.apply_delivery(caught_up(
                &selection,
                turn('b', 1, 6, Some(3), RuntimeTurnStatus::Completed),
            )),
            Err(RuntimeSubscriptionError::CaughtUpStateChange)
        );
        assert_eq!(
            reducer.apply_delivery(caught_up(
                &selection,
                turn('b', 1, 6, Some(4), RuntimeTurnStatus::Running),
            )),
            Err(RuntimeSubscriptionError::CaughtUpCursorMismatch)
        );
    }

    #[test]
    fn replacement_requires_reset_and_reset_explicitly_clears_old_cursor() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope.clone()))
            .expect("select")
            .expect("selection");
        reducer
            .apply_delivery(reset(
                &selection,
                turn('b', 3, 7, Some(9), RuntimeTurnStatus::Failed),
            ))
            .expect("old generation");
        assert_eq!(
            reducer.apply_delivery(append(
                &selection,
                turn('c', 4, 1, Some(1), RuntimeTurnStatus::Running),
            )),
            Err(RuntimeSubscriptionError::ReplacementRequiresReset)
        );
        assert_eq!(
            reducer
                .viewport(&exact_scope)
                .expect("viewport")
                .cursor()
                .expect("old cursor")
                .after_evidence_sequence,
            Some(9)
        );

        let effect = reducer
            .apply_delivery(reset(
                &selection,
                turn('c', 4, 1, Some(1), RuntimeTurnStatus::Running),
            ))
            .expect("explicit replacement reset");
        let DesktopRuntimeReducerEffect::Reset {
            cleared_cursor: Some(cleared),
            ..
        } = effect
        else {
            panic!("replacement must report the cleared cursor");
        };
        assert_eq!(cleared.after_evidence_sequence, Some(9));
        assert_eq!(
            reducer
                .viewport(&exact_scope)
                .expect("viewport")
                .cursor()
                .expect("new cursor")
                .after_evidence_sequence,
            Some(1)
        );
    }

    #[test]
    fn sequence_overflow_and_invalid_turn_metadata_fail_closed() {
        assert_eq!(
            DesktopRuntimeTurnDeliveryMeta::new(
                digest('a'),
                0,
                0,
                None,
                RuntimeTurnStatus::Prepared,
            ),
            Err(RuntimeSubscriptionError::InvalidWorkerGeneration)
        );
        assert_eq!(
            DesktopRuntimeTurnDeliveryMeta::new(
                digest('a'),
                1,
                0,
                Some(0),
                RuntimeTurnStatus::Prepared,
            ),
            Err(RuntimeSubscriptionError::InvalidEvidenceSequence)
        );

        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope))
            .expect("select")
            .expect("selection");
        reducer
            .apply_delivery(reset(
                &selection,
                turn('b', 1, 8, Some(u64::MAX), RuntimeTurnStatus::Running),
            ))
            .expect("max sequence reset");
        assert_eq!(
            reducer.apply_delivery(append(
                &selection,
                turn('b', 1, 9, Some(u64::MAX), RuntimeTurnStatus::Running),
            )),
            Err(RuntimeSubscriptionError::SequenceOverflow)
        );
    }

    #[test]
    fn follow_latest_and_unseen_are_per_scope_and_reset_is_hydration() {
        let scope_a = scope("project", "mission-a", 'a');
        let scope_b = scope("project", "mission-b", 'b');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selected_a = reducer
            .select_scope(Some(scope_a.clone()))
            .expect("select A")
            .expect("A selection");
        reducer
            .set_follow_latest(&scope_a, false)
            .expect("pause follow A");
        let reset_effect = reducer
            .apply_delivery(reset(
                &selected_a,
                turn('c', 1, 2, Some(1), RuntimeTurnStatus::Running),
            ))
            .expect("restart hydration");
        assert!(matches!(
            reset_effect,
            DesktopRuntimeReducerEffect::Reset {
                should_scroll: false,
                ..
            }
        ));
        assert!(!reducer.viewport(&scope_a).expect("A viewport").has_unseen());
        assert_eq!(
            reducer
                .apply_delivery(append(
                    &selected_a,
                    turn('c', 1, 3, Some(2), RuntimeTurnStatus::Running),
                ))
                .expect("new text while not following"),
            DesktopRuntimeReducerEffect::Appended {
                should_scroll: false,
                has_unseen: true,
            }
        );

        reducer
            .select_scope(Some(scope_b))
            .expect("select B")
            .expect("B selection");
        let reselected_a = reducer
            .select_scope(Some(scope_a.clone()))
            .expect("reselect A")
            .expect("A reselection");
        assert_eq!(
            reselected_a
                .cursor
                .expect("persisted cursor")
                .after_evidence_sequence,
            Some(2)
        );
        let viewport = reducer.viewport(&scope_a).expect("A viewport");
        assert!(!viewport.follow_latest());
        assert!(viewport.has_unseen());
        reducer
            .set_follow_latest(&scope_a, true)
            .expect("return to latest");
        let viewport = reducer.viewport(&scope_a).expect("A viewport");
        assert!(viewport.follow_latest());
        assert!(!viewport.has_unseen());
    }

    #[test]
    fn command_slot_fences_stop_scope_and_stale_completion_without_clone_authority() {
        let scope_a = scope("project", "mission-a", 'a');
        let scope_b = scope("project", "mission-b", 'b');
        let (handle_one, coordinator_one) =
            DesktopRuntimeCommandHandle::pair(scope_a.clone(), digest('c'))
                .expect("command pair one");
        let identity_one = handle_one.identity();
        assert_eq!(coordinator_one.identity(), &identity_one);
        assert!(!coordinator_one.is_stop_requested());
        let mut slot = DesktopRuntimeCommandSlot::default();
        assert_eq!(
            slot.request_stop_for(Some(&scope_a)),
            DesktopRuntimeStopDisposition::NoActiveCommand
        );
        slot.install(handle_one).expect("install command one");
        assert!(slot.stop_available_for(&scope_a));
        assert!(!slot.stop_available_for(&scope_b));
        assert_eq!(
            slot.request_stop_for(Some(&scope_b)),
            DesktopRuntimeStopDisposition::ScopeMismatch
        );
        assert!(!coordinator_one.is_stop_requested());
        assert_eq!(
            slot.request_stop_for(Some(&scope_a)),
            DesktopRuntimeStopDisposition::Requested
        );
        assert!(coordinator_one.is_stop_requested());
        assert_eq!(
            slot.request_stop_for(Some(&scope_a)),
            DesktopRuntimeStopDisposition::AlreadyRequested
        );
        assert!(slot.finish_exact(&identity_one));

        let (handle_two, _coordinator_two) =
            DesktopRuntimeCommandHandle::pair(scope_a.clone(), digest('d'))
                .expect("command pair two");
        let identity_two = handle_two.identity();
        slot.install(handle_two).expect("install command two");
        assert!(!slot.finish_exact(&identity_one));
        assert!(slot.stop_available_for(&scope_a));
        assert!(slot.finish_exact(&identity_two));
        assert_eq!(
            slot.request_stop_for(Some(&scope_a)),
            DesktopRuntimeStopDisposition::NoActiveCommand
        );

        let debug = format!("{identity_two:?}");
        assert!(!debug.contains(&digest('d')));
    }

    #[test]
    fn restart_defaults_to_no_command_and_ledger_reset_does_not_claim_unseen_work() {
        let exact_scope = scope("project", "mission", 'a');
        let slot = DesktopRuntimeCommandSlot::default();
        assert_eq!(
            slot.request_stop_for(Some(&exact_scope)),
            DesktopRuntimeStopDisposition::NoActiveCommand
        );

        let mut restarted = DesktopRuntimeSubscriptionReducer::default();
        let selection = restarted
            .select_scope(Some(exact_scope.clone()))
            .expect("restart selection")
            .expect("selection");
        assert!(selection.cursor.is_none());
        restarted
            .apply_delivery(reset(
                &selection,
                turn('b', 7, 13, Some(21), RuntimeTurnStatus::Uncertain),
            ))
            .expect("durable ledger hydration");
        let viewport = restarted.viewport(&exact_scope).expect("viewport");
        assert!(!viewport.has_unseen());
        assert!(viewport.follow_latest());
    }
}
