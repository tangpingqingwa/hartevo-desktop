#![allow(
    dead_code,
    reason = "UI-SUB-02B1 wires the durable Desktop consumer before the Dioxus subscription owns these crate-private types"
)]

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_application::{
    CatalogMissionExecutionHandle, RuntimeTextSubscriptionBatch, RuntimeTextSubscriptionCursor,
    RuntimeTextSubscriptionDelta, RuntimeTextSubscriptionPage, RuntimeTextSubscriptionTurn,
};
use hartevo_domain_kernel::{MissionId, ProjectId, RuntimeTurnStatus};
use sha2::{Digest, Sha256};
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

    fn as_str(&self) -> &str {
        &self.0
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

    pub(crate) fn from_handle(
        handle: &CatalogMissionExecutionHandle,
    ) -> Result<Self, RuntimeSubscriptionError> {
        Self::new(
            handle.project_id().clone(),
            handle.mission_id().clone(),
            handle.handle_digest(),
        )
    }

    fn matches_handle_digest(&self, handle_digest: &str) -> bool {
        self.mission_handle_digest.as_str() == handle_digest
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
/// attempt/thread identifiers never cross the Application projection.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeTurnDeliveryMeta {
    turn_identity_digest: DesktopOpaqueDigest,
    worker_generation: u64,
    turn_revision: u64,
    consumed_evidence_sequence: Option<u64>,
    source_last_evidence_sequence: Option<u64>,
    turn_status: RuntimeTurnStatus,
}

impl DesktopRuntimeTurnDeliveryMeta {
    fn from_application(
        turn: &RuntimeTextSubscriptionTurn,
        cursor: &RuntimeTextSubscriptionCursor,
    ) -> Result<Self, RuntimeSubscriptionError> {
        if turn.worker_generation() == 0 || cursor.worker_generation() == 0 {
            return Err(RuntimeSubscriptionError::InvalidWorkerGeneration);
        }
        if turn.turn_revision() == 0 || cursor.observed_turn_revision() == 0 {
            return Err(RuntimeSubscriptionError::InvalidTurnRevision);
        }
        if turn.last_text_evidence_sequence() == Some(0)
            || cursor.after_evidence_sequence() == Some(0)
        {
            return Err(RuntimeSubscriptionError::InvalidEvidenceSequence);
        }
        if turn.turn_identity_digest() != cursor.turn_identity_digest()
            || turn.worker_generation() != cursor.worker_generation()
            || turn.turn_revision() != cursor.observed_turn_revision()
            || turn.turn_status() != cursor.observed_turn_status()
            || cursor.after_evidence_sequence().is_some_and(|consumed| {
                turn.last_text_evidence_sequence()
                    .is_none_or(|last| consumed > last)
            })
        {
            return Err(RuntimeSubscriptionError::CursorTurnMismatch);
        }
        Ok(Self {
            turn_identity_digest: DesktopOpaqueDigest::parse(turn.turn_identity_digest())?,
            worker_generation: turn.worker_generation(),
            turn_revision: turn.turn_revision(),
            consumed_evidence_sequence: cursor.after_evidence_sequence(),
            source_last_evidence_sequence: turn.last_text_evidence_sequence(),
            turn_status: turn.turn_status(),
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
            .field(
                "consumed_evidence_sequence",
                &self.consumed_evidence_sequence,
            )
            .field(
                "source_last_evidence_sequence",
                &self.source_last_evidence_sequence,
            )
            .field("turn_status", &self.turn_status)
            .finish()
    }
}

/// The exact signed Application cursor. Desktop never reconstructs or signs a
/// cursor from its smaller render metadata; restart and reselect pass this
/// value back to the durable Application read boundary unchanged.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeViewportCursor {
    producer: RuntimeTextSubscriptionCursor,
}

impl DesktopRuntimeViewportCursor {
    fn from_application(
        scope: &DesktopRuntimeSubscriptionScope,
        turn: &RuntimeTextSubscriptionTurn,
        cursor: RuntimeTextSubscriptionCursor,
    ) -> Result<Self, RuntimeSubscriptionError> {
        for digest in [
            cursor.handle_digest(),
            cursor.turn_identity_digest(),
            cursor.cursor_digest(),
        ] {
            DesktopOpaqueDigest::parse(digest)?;
        }
        if !scope.matches_handle_digest(cursor.handle_digest()) {
            return Err(RuntimeSubscriptionError::ScopeHandleMismatch);
        }
        DesktopRuntimeTurnDeliveryMeta::from_application(turn, &cursor)?;
        Ok(Self { producer: cursor })
    }

    pub(crate) fn producer(&self) -> &RuntimeTextSubscriptionCursor {
        &self.producer
    }

    pub(crate) const fn after_evidence_sequence(&self) -> Option<u64> {
        self.producer.after_evidence_sequence()
    }
}

impl fmt::Debug for DesktopRuntimeViewportCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DesktopRuntimeViewportCursor")
            .field(&self.producer)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeTextItemState {
    item_identity_digest: DesktopOpaqueDigest,
    text: String,
    delta_count: usize,
    last_stream_sequence: u64,
    cumulative_byte_count: u64,
    last_evidence_sequence: u64,
    observed_at: DateTime<Utc>,
}

impl DesktopRuntimeTextItemState {
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for DesktopRuntimeTextItemState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeTextItemState")
            .field("item", &self.item_identity_digest)
            .field("text", &"[REDACTED]")
            .field("text_byte_count", &self.text.len())
            .field("delta_count", &self.delta_count)
            .field("last_stream_sequence", &self.last_stream_sequence)
            .field("cumulative_byte_count", &self.cumulative_byte_count)
            .field("last_evidence_sequence", &self.last_evidence_sequence)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeTextProjectionState {
    turn: DesktopRuntimeTurnDeliveryMeta,
    delta_count: usize,
    items: Vec<DesktopRuntimeTextItemState>,
}

impl DesktopRuntimeTextProjectionState {
    fn empty(turn: DesktopRuntimeTurnDeliveryMeta) -> Self {
        Self {
            turn,
            delta_count: 0,
            items: Vec::new(),
        }
    }

    pub(crate) fn turn_status(&self) -> RuntimeTurnStatus {
        self.turn.turn_status
    }

    pub(crate) fn delta_count(&self) -> usize {
        self.delta_count
    }

    pub(crate) fn items(&self) -> &[DesktopRuntimeTextItemState] {
        &self.items
    }

    fn append_deltas(
        &mut self,
        deltas: &[RuntimeTextSubscriptionDelta],
    ) -> Result<(), RuntimeSubscriptionError> {
        let mut previous_evidence = self.turn.consumed_evidence_sequence;
        for delta in deltas {
            if delta.evidence_sequence() == 0
                || previous_evidence.is_some_and(|previous| delta.evidence_sequence() <= previous)
            {
                return Err(if previous_evidence == Some(delta.evidence_sequence()) {
                    RuntimeSubscriptionError::ConflictingDuplicate
                } else {
                    RuntimeSubscriptionError::SequenceRegressed
                });
            }
            let item_digest = DesktopOpaqueDigest::parse(delta.item_identity_digest())?;
            for digest in [
                delta.text_digest(),
                delta.chain_digest(),
                delta.evidence_digest(),
            ] {
                DesktopOpaqueDigest::parse(digest)?;
            }
            if delta.text().is_empty()
                || format!("{:x}", Sha256::digest(delta.text().as_bytes())) != delta.text_digest()
            {
                return Err(RuntimeSubscriptionError::DeltaIntegrityMismatch);
            }
            let text_byte_count = u64::try_from(delta.text().len())
                .map_err(|_| RuntimeSubscriptionError::TextSizeOverflow)?;
            if let Some(item) = self
                .items
                .iter_mut()
                .find(|item| item.item_identity_digest == item_digest)
            {
                let expected_stream_sequence = item
                    .last_stream_sequence
                    .checked_add(1)
                    .ok_or(RuntimeSubscriptionError::SequenceOverflow)?;
                let expected_byte_count = item
                    .cumulative_byte_count
                    .checked_add(text_byte_count)
                    .ok_or(RuntimeSubscriptionError::TextSizeOverflow)?;
                if delta.stream_sequence() != expected_stream_sequence
                    || delta.cumulative_byte_count() != expected_byte_count
                {
                    return Err(RuntimeSubscriptionError::DeltaIntegrityMismatch);
                }
                item.text.push_str(delta.text());
                item.delta_count = item
                    .delta_count
                    .checked_add(1)
                    .ok_or(RuntimeSubscriptionError::DeltaCountOverflow)?;
                item.last_stream_sequence = delta.stream_sequence();
                item.cumulative_byte_count = delta.cumulative_byte_count();
                item.last_evidence_sequence = delta.evidence_sequence();
                item.observed_at = delta.observed_at();
            } else {
                if delta.stream_sequence() != 1 || delta.cumulative_byte_count() != text_byte_count
                {
                    return Err(RuntimeSubscriptionError::DeltaIntegrityMismatch);
                }
                self.items.push(DesktopRuntimeTextItemState {
                    item_identity_digest: item_digest,
                    text: delta.text().into(),
                    delta_count: 1,
                    last_stream_sequence: delta.stream_sequence(),
                    cumulative_byte_count: delta.cumulative_byte_count(),
                    last_evidence_sequence: delta.evidence_sequence(),
                    observed_at: delta.observed_at(),
                });
            }
            self.delta_count = self
                .delta_count
                .checked_add(1)
                .ok_or(RuntimeSubscriptionError::DeltaCountOverflow)?;
            previous_evidence = Some(delta.evidence_sequence());
        }
        self.turn.consumed_evidence_sequence = previous_evidence;
        Ok(())
    }
}

impl fmt::Debug for DesktopRuntimeTextProjectionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeTextProjectionState")
            .field("turn", &self.turn)
            .field("delta_count", &self.delta_count)
            .field("item_count", &self.items.len())
            .finish()
    }
}

/// Closed delivery vocabulary produced only from an integrity-checked
/// Application batch. `Reset` owns replacement, while `CaughtUp` is only a
/// cursor acknowledgement and can never grant Mission completion authority.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum DesktopRuntimeDelivery {
    AwaitingTurn {
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
    },
    Reset {
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
        turn: DesktopRuntimeTurnDeliveryMeta,
        cursor: DesktopRuntimeViewportCursor,
        deltas: Vec<RuntimeTextSubscriptionDelta>,
        has_more: bool,
    },
    Append {
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
        turn: DesktopRuntimeTurnDeliveryMeta,
        cursor: DesktopRuntimeViewportCursor,
        deltas: Vec<RuntimeTextSubscriptionDelta>,
        has_more: bool,
    },
    CaughtUp {
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
        turn: DesktopRuntimeTurnDeliveryMeta,
        cursor: DesktopRuntimeViewportCursor,
    },
}

impl DesktopRuntimeDelivery {
    pub(crate) fn from_application(
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
        batch: RuntimeTextSubscriptionBatch,
    ) -> Result<Self, RuntimeSubscriptionError> {
        match batch {
            RuntimeTextSubscriptionBatch::AwaitingTurn { handle_digest } => {
                DesktopOpaqueDigest::parse(&handle_digest)?;
                if !scope.matches_handle_digest(&handle_digest) {
                    return Err(RuntimeSubscriptionError::ScopeHandleMismatch);
                }
                Ok(Self::AwaitingTurn { scope, epoch })
            }
            RuntimeTextSubscriptionBatch::Reset { page } => {
                Self::from_page(scope, epoch, &page, true)
            }
            RuntimeTextSubscriptionBatch::Append { page } => {
                Self::from_page(scope, epoch, &page, false)
            }
            RuntimeTextSubscriptionBatch::CaughtUp { turn, cursor } => {
                let viewport_cursor =
                    DesktopRuntimeViewportCursor::from_application(&scope, &turn, cursor)?;
                let turn = DesktopRuntimeTurnDeliveryMeta::from_application(
                    &turn,
                    viewport_cursor.producer(),
                )?;
                Ok(Self::CaughtUp {
                    scope,
                    epoch,
                    turn,
                    cursor: viewport_cursor,
                })
            }
        }
    }

    fn from_page(
        scope: DesktopRuntimeSubscriptionScope,
        epoch: DesktopRuntimeSubscriptionEpoch,
        page: &RuntimeTextSubscriptionPage,
        reset: bool,
    ) -> Result<Self, RuntimeSubscriptionError> {
        let cursor = DesktopRuntimeViewportCursor::from_application(
            &scope,
            page.turn(),
            page.next_cursor().clone(),
        )?;
        let turn =
            DesktopRuntimeTurnDeliveryMeta::from_application(page.turn(), cursor.producer())?;
        let deltas = page.deltas().to_vec();
        if !reset && deltas.is_empty() {
            return Err(RuntimeSubscriptionError::AppendWithoutEvidence);
        }
        if deltas
            .last()
            .map(RuntimeTextSubscriptionDelta::evidence_sequence)
            != cursor.after_evidence_sequence()
        {
            return Err(RuntimeSubscriptionError::CursorPageMismatch);
        }
        let source_last = page.turn().last_text_evidence_sequence();
        if page.has_more() {
            if cursor
                .after_evidence_sequence()
                .zip(source_last)
                .is_none_or(|(consumed, source)| consumed >= source)
            {
                return Err(RuntimeSubscriptionError::CursorPageMismatch);
            }
        } else if cursor.after_evidence_sequence() != source_last {
            return Err(RuntimeSubscriptionError::CursorPageMismatch);
        }
        if reset {
            Ok(Self::Reset {
                scope,
                epoch,
                turn,
                cursor,
                deltas,
                has_more: page.has_more(),
            })
        } else {
            Ok(Self::Append {
                scope,
                epoch,
                turn,
                cursor,
                deltas,
                has_more: page.has_more(),
            })
        }
    }

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

impl fmt::Debug for DesktopRuntimeDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwaitingTurn { scope, epoch } => formatter
                .debug_struct("DesktopRuntimeDelivery::AwaitingTurn")
                .field("scope", scope)
                .field("epoch", epoch)
                .finish(),
            Self::Reset {
                scope,
                epoch,
                turn,
                cursor,
                deltas,
                has_more,
            }
            | Self::Append {
                scope,
                epoch,
                turn,
                cursor,
                deltas,
                has_more,
            } => formatter
                .debug_struct(if matches!(self, Self::Reset { .. }) {
                    "DesktopRuntimeDelivery::Reset"
                } else {
                    "DesktopRuntimeDelivery::Append"
                })
                .field("scope", scope)
                .field("epoch", epoch)
                .field("turn", turn)
                .field("cursor", cursor)
                .field("delta_count", &deltas.len())
                .field("has_more", has_more)
                .finish(),
            Self::CaughtUp {
                scope,
                epoch,
                turn,
                cursor,
            } => formatter
                .debug_struct("DesktopRuntimeDelivery::CaughtUp")
                .field("scope", scope)
                .field("epoch", epoch)
                .field("turn", turn)
                .field("cursor", cursor)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopRuntimeDeliveryKind {
    AwaitingTurn,
    Reset,
    Append,
    CaughtUp,
}

/// Content-free identity for one consumed Application delivery. The reducer
/// retains this instead of retaining `DesktopRuntimeDelivery`, so the render
/// projection is the only long-lived owner of private text.
#[derive(Clone, Debug, Eq, PartialEq)]
struct DesktopRuntimeDeltaFingerprint {
    evidence_sequence: u64,
    stream_sequence: u64,
    item_identity_digest: DesktopOpaqueDigest,
    text_digest: DesktopOpaqueDigest,
    text_byte_count: usize,
    cumulative_byte_count: u64,
    chain_digest: DesktopOpaqueDigest,
    evidence_digest: DesktopOpaqueDigest,
    observed_at: DateTime<Utc>,
}

impl DesktopRuntimeDeltaFingerprint {
    fn from_delta(delta: &RuntimeTextSubscriptionDelta) -> Result<Self, RuntimeSubscriptionError> {
        if delta.text().is_empty()
            || format!("{:x}", Sha256::digest(delta.text().as_bytes())) != delta.text_digest()
        {
            return Err(RuntimeSubscriptionError::DeltaIntegrityMismatch);
        }
        Ok(Self {
            evidence_sequence: delta.evidence_sequence(),
            stream_sequence: delta.stream_sequence(),
            item_identity_digest: DesktopOpaqueDigest::parse(delta.item_identity_digest())?,
            text_digest: DesktopOpaqueDigest::parse(delta.text_digest())?,
            text_byte_count: delta.text().len(),
            cumulative_byte_count: delta.cumulative_byte_count(),
            chain_digest: DesktopOpaqueDigest::parse(delta.chain_digest())?,
            evidence_digest: DesktopOpaqueDigest::parse(delta.evidence_digest())?,
            observed_at: delta.observed_at(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DesktopRuntimeDeliveryFingerprint {
    kind: DesktopRuntimeDeliveryKind,
    scope: DesktopRuntimeSubscriptionScope,
    epoch: DesktopRuntimeSubscriptionEpoch,
    turn: Option<DesktopRuntimeTurnDeliveryMeta>,
    cursor: Option<RuntimeTextSubscriptionCursor>,
    has_more: bool,
    deltas: Vec<DesktopRuntimeDeltaFingerprint>,
}

impl DesktopRuntimeDeliveryFingerprint {
    fn from_delivery(delivery: &DesktopRuntimeDelivery) -> Result<Self, RuntimeSubscriptionError> {
        let (kind, turn, cursor, deltas, has_more) = match delivery {
            DesktopRuntimeDelivery::AwaitingTurn { .. } => (
                DesktopRuntimeDeliveryKind::AwaitingTurn,
                None,
                None,
                &[][..],
                false,
            ),
            DesktopRuntimeDelivery::Reset {
                turn,
                cursor,
                deltas,
                has_more,
                ..
            } => (
                DesktopRuntimeDeliveryKind::Reset,
                Some(turn.clone()),
                Some(cursor),
                deltas.as_slice(),
                *has_more,
            ),
            DesktopRuntimeDelivery::Append {
                turn,
                cursor,
                deltas,
                has_more,
                ..
            } => (
                DesktopRuntimeDeliveryKind::Append,
                Some(turn.clone()),
                Some(cursor),
                deltas.as_slice(),
                *has_more,
            ),
            DesktopRuntimeDelivery::CaughtUp { turn, cursor, .. } => (
                DesktopRuntimeDeliveryKind::CaughtUp,
                Some(turn.clone()),
                Some(cursor),
                &[][..],
                false,
            ),
        };
        Ok(Self {
            kind,
            scope: delivery.scope().clone(),
            epoch: delivery.epoch(),
            turn,
            cursor: cursor.map(|cursor| cursor.producer().clone()),
            has_more,
            deltas: deltas
                .iter()
                .map(DesktopRuntimeDeltaFingerprint::from_delta)
                .collect::<Result<_, _>>()?,
        })
    }

    fn shares_cursor_with(&self, other: &Self) -> bool {
        self.cursor.is_some() && self.cursor == other.cursor
    }

    /// Application legitimately answers the pull after a final Reset or
    /// Append with a content-free CaughtUp carrying the same signed cursor.
    /// These are the only same-cursor, different-kind transitions and remain
    /// transport-only.
    fn is_caught_up_acknowledgement_after(&self, previous: &Self) -> bool {
        matches!(
            previous.kind,
            DesktopRuntimeDeliveryKind::Reset | DesktopRuntimeDeliveryKind::Append
        ) && self.kind == DesktopRuntimeDeliveryKind::CaughtUp
            && !previous.has_more
            && !self.has_more
            && self.scope == previous.scope
            && self.epoch == previous.epoch
            && self.turn == previous.turn
            && self.cursor == previous.cursor
            && self.deltas.is_empty()
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
    follow_mode: DesktopRuntimeFollowMode,
    visibility: DesktopRuntimeVisibility,
    cursor: Option<DesktopRuntimeViewportCursor>,
    projection: Option<DesktopRuntimeTextProjectionState>,
    transport_state: DesktopRuntimeTransportState,
    last_delivery_fingerprint: Option<DesktopRuntimeDeliveryFingerprint>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopRuntimeFollowMode {
    FollowLatest,
    Paused,
}

impl DesktopRuntimeFollowMode {
    const fn is_following(self) -> bool {
        matches!(self, Self::FollowLatest)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopRuntimeVisibility {
    Seen,
    Unseen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopRuntimeTransportState {
    AwaitingTurn,
    MoreAvailable,
    FinalPage,
    CaughtUp,
}

impl DesktopRuntimeTransportState {
    const fn from_has_more(has_more: bool) -> Self {
        if has_more {
            Self::MoreAvailable
        } else {
            Self::FinalPage
        }
    }

    const fn after_reselect(self) -> Self {
        if matches!(self, Self::CaughtUp) {
            Self::FinalPage
        } else {
            self
        }
    }

    const fn has_more(self) -> bool {
        matches!(self, Self::MoreAvailable)
    }

    const fn is_caught_up(self) -> bool {
        matches!(self, Self::CaughtUp)
    }
}

impl DesktopRuntimeViewportState {
    fn new(scope: DesktopRuntimeSubscriptionScope) -> Result<Self, RuntimeSubscriptionError> {
        let viewport = Self {
            scope,
            follow_mode: DesktopRuntimeFollowMode::FollowLatest,
            visibility: DesktopRuntimeVisibility::Seen,
            cursor: None,
            projection: None,
            transport_state: DesktopRuntimeTransportState::AwaitingTurn,
            last_delivery_fingerprint: None,
        };
        viewport.validate()?;
        Ok(viewport)
    }

    fn validate(&self) -> Result<(), RuntimeSubscriptionError> {
        Self::validate_components(
            self.follow_mode,
            self.visibility,
            self.cursor.is_some(),
            self.projection.is_some(),
            self.transport_state,
        )
    }

    fn validate_components(
        follow_mode: DesktopRuntimeFollowMode,
        visibility: DesktopRuntimeVisibility,
        has_cursor: bool,
        has_projection: bool,
        transport_state: DesktopRuntimeTransportState,
    ) -> Result<(), RuntimeSubscriptionError> {
        let render_pair_is_valid = has_cursor == has_projection;
        let transport_is_valid = match transport_state {
            DesktopRuntimeTransportState::AwaitingTurn => !has_cursor && !has_projection,
            DesktopRuntimeTransportState::MoreAvailable
            | DesktopRuntimeTransportState::FinalPage
            | DesktopRuntimeTransportState::CaughtUp => has_cursor && has_projection,
        };
        let visibility_is_valid = !matches!(
            (follow_mode, visibility),
            (
                DesktopRuntimeFollowMode::FollowLatest,
                DesktopRuntimeVisibility::Unseen
            )
        );
        if render_pair_is_valid && transport_is_valid && visibility_is_valid {
            Ok(())
        } else {
            Err(RuntimeSubscriptionError::InvalidViewportState)
        }
    }

    pub(crate) fn follow_latest(&self) -> bool {
        self.follow_mode.is_following()
    }

    pub(crate) fn has_unseen(&self) -> bool {
        matches!(self.visibility, DesktopRuntimeVisibility::Unseen)
    }

    pub(crate) fn cursor(&self) -> Option<DesktopRuntimeViewportCursor> {
        self.cursor.clone()
    }

    pub(crate) fn projection(&self) -> Option<&DesktopRuntimeTextProjectionState> {
        self.projection.as_ref()
    }

    pub(crate) const fn has_more(&self) -> bool {
        self.transport_state.has_more()
    }

    pub(crate) const fn transport_caught_up(&self) -> bool {
        self.transport_state.is_caught_up()
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
        if let std::collections::btree_map::Entry::Vacant(entry) =
            self.viewports.entry(scope.clone())
        {
            entry.insert(DesktopRuntimeViewportState::new(scope.clone())?);
        }
        let viewport = self
            .viewports
            .get_mut(&scope)
            .ok_or(RuntimeSubscriptionError::ViewportMissing)?;
        let transport_state = viewport.transport_state.after_reselect();
        DesktopRuntimeViewportState::validate_components(
            viewport.follow_mode,
            viewport.visibility,
            viewport.cursor.is_some(),
            viewport.projection.is_some(),
            transport_state,
        )?;
        viewport.transport_state = transport_state;
        viewport.last_delivery_fingerprint = None;
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
        let follow_mode = if follow_latest {
            DesktopRuntimeFollowMode::FollowLatest
        } else {
            DesktopRuntimeFollowMode::Paused
        };
        let visibility = if follow_latest {
            DesktopRuntimeVisibility::Seen
        } else {
            viewport.visibility
        };
        DesktopRuntimeViewportState::validate_components(
            follow_mode,
            visibility,
            viewport.cursor.is_some(),
            viewport.projection.is_some(),
            viewport.transport_state,
        )?;
        viewport.follow_mode = follow_mode;
        viewport.visibility = visibility;
        Ok(())
    }

    pub(crate) fn apply_delivery(
        &mut self,
        delivery: &DesktopRuntimeDelivery,
    ) -> Result<DesktopRuntimeReducerEffect, RuntimeSubscriptionError> {
        let selected_matches = self
            .selected
            .as_ref()
            .is_some_and(|(scope, epoch)| scope == delivery.scope() && *epoch == delivery.epoch());
        if !selected_matches {
            return Ok(DesktopRuntimeReducerEffect::IgnoredStale);
        }
        let fingerprint = DesktopRuntimeDeliveryFingerprint::from_delivery(delivery)?;
        let viewport = self
            .viewports
            .get_mut(delivery.scope())
            .ok_or(RuntimeSubscriptionError::ViewportMissing)?;
        viewport.validate()?;
        if let Some(effect) = Self::replay_effect(viewport, &fingerprint)? {
            return Ok(effect);
        }

        match delivery {
            DesktopRuntimeDelivery::AwaitingTurn { .. } => {
                Self::apply_awaiting_turn(viewport, fingerprint)
            }
            DesktopRuntimeDelivery::Reset {
                turn,
                cursor,
                deltas,
                has_more,
                ..
            } => Self::apply_reset(viewport, turn, cursor, deltas, *has_more, fingerprint),
            DesktopRuntimeDelivery::Append {
                turn,
                cursor,
                deltas,
                has_more,
                ..
            } => Self::apply_append(viewport, turn, cursor, deltas, *has_more, fingerprint),
            DesktopRuntimeDelivery::CaughtUp { turn, cursor, .. } => {
                Self::apply_caught_up(viewport, turn, cursor, fingerprint)
            }
        }
    }

    fn replay_effect(
        viewport: &DesktopRuntimeViewportState,
        fingerprint: &DesktopRuntimeDeliveryFingerprint,
    ) -> Result<Option<DesktopRuntimeReducerEffect>, RuntimeSubscriptionError> {
        let Some(previous) = &viewport.last_delivery_fingerprint else {
            return Ok(None);
        };
        if previous == fingerprint {
            return Ok(Some(DesktopRuntimeReducerEffect::Duplicate));
        }
        if previous.shares_cursor_with(fingerprint)
            && !fingerprint.is_caught_up_acknowledgement_after(previous)
        {
            return Err(RuntimeSubscriptionError::ConflictingDuplicate);
        }
        Ok(None)
    }

    fn apply_awaiting_turn(
        viewport: &mut DesktopRuntimeViewportState,
        fingerprint: DesktopRuntimeDeliveryFingerprint,
    ) -> Result<DesktopRuntimeReducerEffect, RuntimeSubscriptionError> {
        if viewport.projection.is_some() || viewport.cursor.is_some() {
            return Err(RuntimeSubscriptionError::TurnHistoryDisappeared);
        }
        DesktopRuntimeViewportState::validate_components(
            viewport.follow_mode,
            viewport.visibility,
            false,
            false,
            DesktopRuntimeTransportState::AwaitingTurn,
        )?;
        viewport.transport_state = DesktopRuntimeTransportState::AwaitingTurn;
        viewport.last_delivery_fingerprint = Some(fingerprint);
        Ok(DesktopRuntimeReducerEffect::AwaitingTurn)
    }

    fn apply_reset(
        viewport: &mut DesktopRuntimeViewportState,
        turn: &DesktopRuntimeTurnDeliveryMeta,
        cursor: &DesktopRuntimeViewportCursor,
        deltas: &[RuntimeTextSubscriptionDelta],
        has_more: bool,
        fingerprint: DesktopRuntimeDeliveryFingerprint,
    ) -> Result<DesktopRuntimeReducerEffect, RuntimeSubscriptionError> {
        let cleared_cursor = viewport.cursor();
        let mut projection = DesktopRuntimeTextProjectionState::empty(turn.clone());
        projection.turn.consumed_evidence_sequence = None;
        projection.append_deltas(deltas)?;
        if projection.turn.consumed_evidence_sequence != cursor.after_evidence_sequence() {
            return Err(RuntimeSubscriptionError::CursorPageMismatch);
        }
        let transport_state = DesktopRuntimeTransportState::from_has_more(has_more);
        DesktopRuntimeViewportState::validate_components(
            viewport.follow_mode,
            DesktopRuntimeVisibility::Seen,
            true,
            true,
            transport_state,
        )?;

        // Every fallible validation is complete before the old generation is
        // cleared. No later operation can expose a partial replacement.
        viewport.projection = None;
        viewport.cursor = None;
        viewport.last_delivery_fingerprint = None;
        viewport.visibility = DesktopRuntimeVisibility::Seen;
        viewport.transport_state = DesktopRuntimeTransportState::AwaitingTurn;
        viewport.projection = Some(projection);
        viewport.cursor = Some(cursor.clone());
        viewport.transport_state = transport_state;
        let should_scroll = viewport.follow_mode.is_following();
        viewport.last_delivery_fingerprint = Some(fingerprint);
        Ok(DesktopRuntimeReducerEffect::Reset {
            cleared_cursor,
            should_scroll,
        })
    }

    fn apply_append(
        viewport: &mut DesktopRuntimeViewportState,
        turn: &DesktopRuntimeTurnDeliveryMeta,
        cursor: &DesktopRuntimeViewportCursor,
        deltas: &[RuntimeTextSubscriptionDelta],
        has_more: bool,
        fingerprint: DesktopRuntimeDeliveryFingerprint,
    ) -> Result<DesktopRuntimeReducerEffect, RuntimeSubscriptionError> {
        let current = viewport
            .projection
            .as_ref()
            .ok_or(RuntimeSubscriptionError::AppendBeforeReset)?;
        if !current.turn.same_turn_as(turn) {
            return Err(RuntimeSubscriptionError::ReplacementRequiresReset);
        }
        let previous_cursor = viewport
            .cursor
            .as_ref()
            .ok_or(RuntimeSubscriptionError::AppendBeforeReset)?;
        let first_sequence = deltas
            .first()
            .map(RuntimeTextSubscriptionDelta::evidence_sequence)
            .ok_or(RuntimeSubscriptionError::AppendWithoutEvidence)?;
        if previous_cursor
            .after_evidence_sequence()
            .is_some_and(|previous| first_sequence <= previous)
        {
            return Err(
                if previous_cursor.after_evidence_sequence() == Some(first_sequence) {
                    RuntimeSubscriptionError::ConflictingDuplicate
                } else {
                    RuntimeSubscriptionError::SequenceRegressed
                },
            );
        }
        let mut next_projection = current.clone();
        next_projection.turn = turn.clone();
        next_projection.turn.consumed_evidence_sequence = previous_cursor.after_evidence_sequence();
        next_projection.append_deltas(deltas)?;
        if next_projection.turn.consumed_evidence_sequence != cursor.after_evidence_sequence() {
            return Err(RuntimeSubscriptionError::CursorPageMismatch);
        }
        let visibility = if viewport.follow_mode.is_following() {
            viewport.visibility
        } else {
            DesktopRuntimeVisibility::Unseen
        };
        let transport_state = DesktopRuntimeTransportState::from_has_more(has_more);
        DesktopRuntimeViewportState::validate_components(
            viewport.follow_mode,
            visibility,
            true,
            true,
            transport_state,
        )?;

        viewport.projection = Some(next_projection);
        viewport.cursor = Some(cursor.clone());
        viewport.transport_state = transport_state;
        viewport.visibility = visibility;
        let effect = DesktopRuntimeReducerEffect::Appended {
            should_scroll: viewport.follow_mode.is_following(),
            has_unseen: matches!(viewport.visibility, DesktopRuntimeVisibility::Unseen),
        };
        viewport.last_delivery_fingerprint = Some(fingerprint);
        Ok(effect)
    }

    fn apply_caught_up(
        viewport: &mut DesktopRuntimeViewportState,
        turn: &DesktopRuntimeTurnDeliveryMeta,
        cursor: &DesktopRuntimeViewportCursor,
        fingerprint: DesktopRuntimeDeliveryFingerprint,
    ) -> Result<DesktopRuntimeReducerEffect, RuntimeSubscriptionError> {
        let current = viewport
            .projection
            .as_ref()
            .ok_or(RuntimeSubscriptionError::CaughtUpBeforeReset)?;
        if !current.turn.same_turn_as(turn) {
            return Err(RuntimeSubscriptionError::ReplacementRequiresReset);
        }
        if viewport.cursor.as_ref() != Some(cursor)
            || current.turn.consumed_evidence_sequence != turn.consumed_evidence_sequence
        {
            return Err(RuntimeSubscriptionError::CaughtUpCursorMismatch);
        }
        if current.turn.turn_revision != turn.turn_revision
            || current.turn.turn_status != turn.turn_status
            || current.turn.source_last_evidence_sequence != turn.source_last_evidence_sequence
        {
            return Err(RuntimeSubscriptionError::CaughtUpStateChange);
        }
        DesktopRuntimeViewportState::validate_components(
            viewport.follow_mode,
            viewport.visibility,
            true,
            true,
            DesktopRuntimeTransportState::CaughtUp,
        )?;

        // CaughtUp is transport-only and cannot infer Runtime or Mission
        // completion from the absence of another page.
        viewport.transport_state = DesktopRuntimeTransportState::CaughtUp;
        viewport.last_delivery_fingerprint = Some(fingerprint);
        Ok(DesktopRuntimeReducerEffect::CaughtUp)
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
    #[error("Runtime turn revision must be positive")]
    InvalidTurnRevision,
    #[error("evidence sequence must be positive")]
    InvalidEvidenceSequence,
    #[error("signed cursor does not describe the projected Runtime turn")]
    CursorTurnMismatch,
    #[error("Application batch does not match the selected Mission handle")]
    ScopeHandleMismatch,
    #[error("Runtime text delta failed integrity validation")]
    DeltaIntegrityMismatch,
    #[error("Runtime text size overflow")]
    TextSizeOverflow,
    #[error("Runtime text delta count overflow")]
    DeltaCountOverflow,
    #[error("signed cursor does not match its Runtime text page")]
    CursorPageMismatch,
    #[error("subscription epoch overflow")]
    EpochOverflow,
    #[error("runtime evidence sequence overflow")]
    SequenceOverflow,
    #[error("selected viewport is missing")]
    ViewportMissing,
    #[error("Runtime viewport transport, visibility, and render state are inconsistent")]
    InvalidViewportState,
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
    use serde_json::{Value, json};

    use super::*;

    fn digest(character: char) -> String {
        character.to_string().repeat(SHA256_HEX_LENGTH)
    }

    fn canonical_digests(value: &Value, output: &mut Vec<String>) {
        match value {
            Value::String(candidate)
                if candidate.len() == SHA256_HEX_LENGTH
                    && candidate
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
            {
                output.push(candidate.clone());
            }
            Value::Array(values) => {
                for value in values {
                    canonical_digests(value, output);
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    canonical_digests(value, output);
                }
            }
            _ => {}
        }
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

    fn turn_value(
        turn_character: char,
        generation: u64,
        revision: u64,
        source_last_sequence: Option<u64>,
        status: RuntimeTurnStatus,
    ) -> Value {
        json!({
            "turnIdentityDigest": digest(turn_character),
            "workerGeneration": generation,
            "turnRevision": revision,
            "turnStatus": status,
            "lastTextEvidenceSequence": source_last_sequence,
        })
    }

    fn cursor_value(
        handle_character: char,
        turn_character: char,
        generation: u64,
        after_sequence: Option<u64>,
        revision: u64,
        status: RuntimeTurnStatus,
        cursor_character: char,
    ) -> Value {
        json!({
            "handleDigest": digest(handle_character),
            "turnIdentityDigest": digest(turn_character),
            "workerGeneration": generation,
            "afterEvidenceSequence": after_sequence,
            "observedTurnRevision": revision,
            "observedTurnStatus": status,
            "cursorDigest": digest(cursor_character),
        })
    }

    fn delta_value(
        evidence_sequence: u64,
        stream_sequence: u64,
        item_character: char,
        text: &str,
        cumulative_byte_count: u64,
    ) -> Value {
        json!({
            "evidenceSequence": evidence_sequence,
            "streamSequence": stream_sequence,
            "itemIdentityDigest": digest(item_character),
            "text": text,
            "textDigest": format!("{:x}", Sha256::digest(text.as_bytes())),
            "cumulativeByteCount": cumulative_byte_count,
            "chainDigest": digest('e'),
            "evidenceDigest": digest('f'),
            "observedAt": "2026-08-13T09:00:00Z",
        })
    }

    #[derive(Clone, Copy)]
    struct RuntimeBatchFixture {
        handle_character: char,
        turn_character: char,
        generation: u64,
        revision: u64,
        status: RuntimeTurnStatus,
        source_last_sequence: Option<u64>,
        cursor_after_sequence: Option<u64>,
        cursor_character: char,
    }

    impl RuntimeBatchFixture {
        const fn running() -> Self {
            Self {
                handle_character: 'a',
                turn_character: 'b',
                generation: 1,
                revision: 4,
                status: RuntimeTurnStatus::Running,
                source_last_sequence: None,
                cursor_after_sequence: None,
                cursor_character: 'c',
            }
        }

        fn page(
            self,
            kind: &str,
            deltas: &[Value],
            has_more: bool,
        ) -> RuntimeTextSubscriptionBatch {
            serde_json::from_value(json!({
                "kind": kind,
                "page": {
                    "turn": turn_value(
                        self.turn_character,
                        self.generation,
                        self.revision,
                        self.source_last_sequence,
                        self.status,
                    ),
                    "deltas": deltas,
                    "nextCursor": cursor_value(
                        self.handle_character,
                        self.turn_character,
                        self.generation,
                        self.cursor_after_sequence,
                        self.revision,
                        self.status,
                        self.cursor_character,
                    ),
                    "hasMore": has_more,
                },
            }))
            .expect("producer batch fixture")
        }

        fn caught_up(self) -> RuntimeTextSubscriptionBatch {
            serde_json::from_value(json!({
                "kind": "caught_up",
                "turn": turn_value(
                    self.turn_character,
                    self.generation,
                    self.revision,
                    self.source_last_sequence,
                    self.status,
                ),
                "cursor": cursor_value(
                    self.handle_character,
                    self.turn_character,
                    self.generation,
                    self.cursor_after_sequence,
                    self.revision,
                    self.status,
                    self.cursor_character,
                ),
            }))
            .expect("caught-up fixture")
        }
    }

    fn delivery(
        selection: &DesktopRuntimeSelection,
        batch: RuntimeTextSubscriptionBatch,
    ) -> Result<DesktopRuntimeDelivery, RuntimeSubscriptionError> {
        DesktopRuntimeDelivery::from_application(selection.scope.clone(), selection.epoch, batch)
    }

    fn reset_page_one() -> RuntimeTextSubscriptionBatch {
        RuntimeBatchFixture {
            source_last_sequence: Some(2),
            cursor_after_sequence: Some(1),
            ..RuntimeBatchFixture::running()
        }
        .page("reset", &[delta_value(1, 1, 'd', "Hello ", 6)], true)
    }

    fn reset_final_one() -> RuntimeTextSubscriptionBatch {
        RuntimeBatchFixture {
            source_last_sequence: Some(1),
            cursor_after_sequence: Some(1),
            ..RuntimeBatchFixture::running()
        }
        .page(
            "reset",
            &[delta_value(1, 1, 'd', "complete page", 13)],
            false,
        )
    }

    fn append_page_two(cursor_character: char) -> RuntimeTextSubscriptionBatch {
        RuntimeBatchFixture {
            source_last_sequence: Some(2),
            cursor_after_sequence: Some(2),
            cursor_character,
            ..RuntimeBatchFixture::running()
        }
        .page("append", &[delta_value(2, 2, 'd', "world", 11)], false)
    }

    #[test]
    fn opaque_digests_and_application_scope_fail_closed_with_redacted_debug() {
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

        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope))
            .expect("select")
            .expect("selection");
        assert!(
            serde_json::from_value::<RuntimeTextSubscriptionBatch>(json!({
                "kind": "awaiting_turn",
                "handleDigest": digest('b'),
            }))
            .is_err()
        );
        let wrong_handle: RuntimeTextSubscriptionBatch = serde_json::from_value(json!({
            "kind": "awaiting_turn",
            "handle_digest": digest('b'),
        }))
        .expect("awaiting fixture");
        assert_eq!(
            delivery(&selection, wrong_handle),
            Err(RuntimeSubscriptionError::ScopeHandleMismatch)
        );
    }

    #[test]
    fn selection_epoch_is_checked_and_reselect_preserves_exact_signed_cursor() {
        let scope_a = scope("project", "mission-a", 'a');
        let scope_b = scope("project", "mission-b", 'b');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selected_a_v1 = reducer
            .select_scope(Some(scope_a.clone()))
            .expect("select A")
            .expect("A selection");
        assert_eq!(selected_a_v1.epoch.get(), 1);
        let reset = delivery(&selected_a_v1, reset_page_one()).expect("reset delivery");
        let exact_cursor = match &reset {
            DesktopRuntimeDelivery::Reset { cursor, .. } => cursor.clone(),
            other => panic!("expected reset, got {other:?}"),
        };
        reducer.apply_delivery(&reset).expect("reset A");
        let viewport_before_stale = reducer
            .viewport(&scope_a)
            .expect("A viewport before stale delivery")
            .clone();

        let selected_b = reducer
            .select_scope(Some(scope_b))
            .expect("select B")
            .expect("B selection");
        assert_eq!(selected_b.epoch.get(), 2);
        assert_eq!(
            reducer
                .apply_delivery(
                    &delivery(&selected_a_v1, append_page_two('d')).expect("stale append delivery"),
                )
                .expect("stale A delivery"),
            DesktopRuntimeReducerEffect::IgnoredStale
        );
        assert_eq!(reducer.viewport(&scope_a), Some(&viewport_before_stale));

        let selected_a_v2 = reducer
            .select_scope(Some(scope_a.clone()))
            .expect("reselect A")
            .expect("A reselection");
        assert_eq!(selected_a_v2.epoch.get(), 3);
        let restored_cursor = selected_a_v2.cursor.as_ref().expect("restored cursor");
        assert_eq!(restored_cursor, &exact_cursor);
        assert_eq!(
            serde_json::to_value(restored_cursor.producer()).expect("cursor JSON"),
            serde_json::to_value(exact_cursor.producer()).expect("exact cursor JSON")
        );
        assert_eq!(
            reducer
                .apply_delivery(
                    &delivery(&selected_a_v1, append_page_two('d'))
                        .expect("old-epoch append delivery"),
                )
                .expect("old epoch after reselect"),
            DesktopRuntimeReducerEffect::IgnoredStale
        );
        let viewport_after_reselect_stale = reducer
            .viewport(&scope_a)
            .expect("A viewport after reselect stale delivery");
        assert_eq!(viewport_after_reselect_stale.cursor(), Some(exact_cursor));
        assert_eq!(
            viewport_after_reselect_stale.projection(),
            viewport_before_stale.projection()
        );

        reducer.last_epoch = u64::MAX;
        assert_eq!(
            reducer.select_scope(Some(scope_a)),
            Err(RuntimeSubscriptionError::EpochOverflow)
        );
    }

    #[test]
    fn awaiting_and_reset_replays_obey_exact_delivery_contract() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope.clone()))
            .expect("select")
            .expect("selection");
        let awaiting_batch: RuntimeTextSubscriptionBatch = serde_json::from_value(json!({
            "kind": "awaiting_turn",
            "handle_digest": digest('a'),
        }))
        .expect("awaiting fixture");
        let awaiting = delivery(&selection, awaiting_batch).expect("awaiting delivery");
        assert_eq!(
            reducer.apply_delivery(&awaiting).expect("awaiting turn"),
            DesktopRuntimeReducerEffect::AwaitingTurn
        );
        assert_eq!(
            reducer
                .apply_delivery(&awaiting)
                .expect("duplicate awaiting"),
            DesktopRuntimeReducerEffect::Duplicate
        );

        let initial_reset = delivery(&selection, reset_page_one()).expect("reset delivery");
        assert_eq!(
            reducer
                .apply_delivery(&initial_reset)
                .expect("initial reset"),
            DesktopRuntimeReducerEffect::Reset {
                cleared_cursor: None,
                should_scroll: true,
            }
        );
        assert_eq!(
            reducer
                .apply_delivery(&initial_reset)
                .expect("duplicate reset"),
            DesktopRuntimeReducerEffect::Duplicate
        );
        let reset_viewport = reducer.viewport(&exact_scope).expect("reset viewport");
        assert!(reset_viewport.has_more());
        assert_eq!(
            reset_viewport.projection().expect("projection").items()[0].text(),
            "Hello "
        );
    }

    #[test]
    fn append_and_caught_up_replays_obey_exact_delivery_contract() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope.clone()))
            .expect("select")
            .expect("selection");
        reducer
            .apply_delivery(&delivery(&selection, reset_page_one()).expect("reset delivery"))
            .expect("initial reset");
        let append_two = delivery(&selection, append_page_two('d')).expect("append delivery");
        assert_eq!(
            reducer.apply_delivery(&append_two).expect("append"),
            DesktopRuntimeReducerEffect::Appended {
                should_scroll: true,
                has_unseen: false,
            }
        );
        assert_eq!(
            reducer
                .apply_delivery(&append_two)
                .expect("exact duplicate append"),
            DesktopRuntimeReducerEffect::Duplicate
        );
        let viewport = reducer.viewport(&exact_scope).expect("appended viewport");
        assert!(!viewport.has_more());
        let projection = viewport.projection().expect("projection");
        assert_eq!(projection.delta_count(), 2);
        assert_eq!(projection.items()[0].text(), "Hello world");

        let caught_up = delivery(
            &selection,
            RuntimeBatchFixture {
                source_last_sequence: Some(2),
                cursor_after_sequence: Some(2),
                cursor_character: 'd',
                ..RuntimeBatchFixture::running()
            }
            .caught_up(),
        )
        .expect("caught-up delivery");
        assert_eq!(
            reducer.apply_delivery(&caught_up).expect("caught up"),
            DesktopRuntimeReducerEffect::CaughtUp
        );
        assert!(
            reducer
                .viewport(&exact_scope)
                .expect("caught-up viewport")
                .transport_caught_up()
        );
        assert_eq!(
            reducer
                .apply_delivery(&caught_up)
                .expect("duplicate caught up"),
            DesktopRuntimeReducerEffect::Duplicate
        );
        assert_eq!(
            reducer.apply_delivery(
                &delivery(&selection, append_page_two('d')).expect("replayed final Append")
            ),
            Err(RuntimeSubscriptionError::ConflictingDuplicate)
        );
        assert_eq!(
            reducer
                .viewport(&exact_scope)
                .expect("viewport")
                .projection()
                .expect("projection")
                .turn_status(),
            RuntimeTurnStatus::Running
        );
    }

    #[test]
    fn final_reset_acknowledges_once_without_changing_projection() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope.clone()))
            .expect("select")
            .expect("selection");
        let final_reset = delivery(&selection, reset_final_one()).expect("final Reset");
        reducer
            .apply_delivery(&final_reset)
            .expect("apply final Reset");
        let projection_before = reducer
            .viewport(&exact_scope)
            .expect("viewport")
            .projection()
            .expect("projection")
            .clone();
        let cursor_before = reducer
            .viewport(&exact_scope)
            .expect("viewport")
            .cursor()
            .expect("cursor");
        let caught_up = delivery(
            &selection,
            RuntimeBatchFixture {
                source_last_sequence: Some(1),
                cursor_after_sequence: Some(1),
                ..RuntimeBatchFixture::running()
            }
            .caught_up(),
        )
        .expect("CaughtUp acknowledgement");
        assert_eq!(
            reducer
                .apply_delivery(&caught_up)
                .expect("final Reset acknowledgement"),
            DesktopRuntimeReducerEffect::CaughtUp
        );
        let acknowledged = reducer
            .viewport(&exact_scope)
            .expect("acknowledged viewport");
        assert!(acknowledged.transport_caught_up());
        assert_eq!(acknowledged.cursor(), Some(cursor_before.clone()));
        assert_eq!(acknowledged.projection(), Some(&projection_before));
        assert_eq!(
            reducer
                .apply_delivery(&caught_up)
                .expect("duplicate acknowledgement"),
            DesktopRuntimeReducerEffect::Duplicate
        );
        assert_eq!(
            reducer.apply_delivery(&final_reset),
            Err(RuntimeSubscriptionError::ConflictingDuplicate)
        );
    }

    #[test]
    fn nonfinal_reset_cannot_be_acknowledged_with_the_same_cursor() {
        let exact_scope = scope("project", "mission", 'a');
        let mut nonfinal = DesktopRuntimeSubscriptionReducer::default();
        let nonfinal_selection = nonfinal
            .select_scope(Some(exact_scope))
            .expect("select nonfinal")
            .expect("nonfinal selection");
        nonfinal
            .apply_delivery(
                &delivery(&nonfinal_selection, reset_page_one()).expect("nonfinal Reset"),
            )
            .expect("apply nonfinal Reset");
        let premature_caught_up = delivery(
            &nonfinal_selection,
            RuntimeBatchFixture {
                source_last_sequence: Some(2),
                cursor_after_sequence: Some(1),
                ..RuntimeBatchFixture::running()
            }
            .caught_up(),
        )
        .expect("premature CaughtUp envelope");
        assert_eq!(
            nonfinal.apply_delivery(&premature_caught_up),
            Err(RuntimeSubscriptionError::ConflictingDuplicate)
        );
    }

    #[test]
    fn caught_up_metadata_drift_fails_closed() {
        let exact_scope = scope("project", "mission", 'a');
        let mut drifted = DesktopRuntimeSubscriptionReducer::default();
        let drifted_selection = drifted
            .select_scope(Some(exact_scope))
            .expect("select drifted")
            .expect("drifted selection");
        drifted
            .apply_delivery(
                &delivery(&drifted_selection, reset_final_one()).expect("drift baseline"),
            )
            .expect("apply drift baseline");
        let source_last_drift = delivery(
            &drifted_selection,
            RuntimeBatchFixture {
                source_last_sequence: Some(2),
                cursor_after_sequence: Some(1),
                ..RuntimeBatchFixture::running()
            }
            .caught_up(),
        )
        .expect("drifted CaughtUp envelope");
        assert_eq!(
            drifted.apply_delivery(&source_last_drift),
            Err(RuntimeSubscriptionError::ConflictingDuplicate)
        );
    }

    #[test]
    fn nonfinal_append_cannot_be_acknowledged_with_the_same_cursor() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope.clone()))
            .expect("select")
            .expect("selection");
        reducer
            .apply_delivery(&delivery(&selection, reset_page_one()).expect("initial Reset"))
            .expect("apply initial Reset");
        let nonfinal_append = RuntimeBatchFixture {
            source_last_sequence: Some(3),
            cursor_after_sequence: Some(2),
            cursor_character: 'd',
            ..RuntimeBatchFixture::running()
        }
        .page("append", &[delta_value(2, 2, 'd', "world", 11)], true);
        reducer
            .apply_delivery(
                &delivery(&selection, nonfinal_append).expect("nonfinal Append delivery"),
            )
            .expect("apply nonfinal Append");
        let before_premature_ack = reducer
            .viewport(&exact_scope)
            .expect("viewport before premature acknowledgement")
            .clone();
        let premature_caught_up = RuntimeBatchFixture {
            source_last_sequence: Some(3),
            cursor_after_sequence: Some(2),
            cursor_character: 'd',
            ..RuntimeBatchFixture::running()
        }
        .caught_up();
        assert_eq!(
            reducer.apply_delivery(
                &delivery(&selection, premature_caught_up).expect("premature CaughtUp delivery")
            ),
            Err(RuntimeSubscriptionError::ConflictingDuplicate)
        );
        assert_eq!(reducer.viewport(&exact_scope), Some(&before_premature_ack));
    }

    #[test]
    fn same_sequence_with_different_payload_or_cursor_fails_closed() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope.clone()))
            .expect("select")
            .expect("selection");
        reducer
            .apply_delivery(&delivery(&selection, reset_page_one()).expect("reset delivery"))
            .expect("current turn");
        let before_conflict = reducer
            .viewport(&exact_scope)
            .expect("viewport before conflict")
            .clone();

        let duplicate_sequence = RuntimeBatchFixture {
            source_last_sequence: Some(2),
            cursor_after_sequence: Some(1),
            ..RuntimeBatchFixture::running()
        }
        .page(
            "append",
            &[delta_value(1, 1, 'd', "Different private payload", 25)],
            true,
        );
        assert_eq!(
            reducer.apply_delivery(
                &delivery(&selection, duplicate_sequence).expect("conflicting delivery")
            ),
            Err(RuntimeSubscriptionError::ConflictingDuplicate)
        );
        assert_eq!(reducer.viewport(&exact_scope), Some(&before_conflict));

        let exact_append = delivery(&selection, append_page_two('d')).expect("append delivery");
        reducer
            .apply_delivery(&exact_append)
            .expect("advance to second delta");
        let before_cursor_conflict = reducer
            .viewport(&exact_scope)
            .expect("viewport before cursor conflict")
            .clone();
        let same_payload_different_cursor =
            delivery(&selection, append_page_two('9')).expect("different cursor delivery");
        assert_eq!(
            reducer.apply_delivery(&same_payload_different_cursor),
            Err(RuntimeSubscriptionError::ConflictingDuplicate)
        );
        assert_eq!(
            reducer.viewport(&exact_scope),
            Some(&before_cursor_conflict)
        );
        assert_eq!(
            reducer
                .viewport(&exact_scope)
                .expect("viewport")
                .projection()
                .expect("projection")
                .items()[0]
                .text(),
            "Hello world"
        );
    }

    #[test]
    fn turn_or_generation_replacement_requires_atomic_reset() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope.clone()))
            .expect("select")
            .expect("selection");
        reducer
            .apply_delivery(&delivery(&selection, reset_page_one()).expect("reset delivery"))
            .expect("old generation");

        let replacement_append = RuntimeBatchFixture {
            turn_character: 'c',
            generation: 2,
            revision: 1,
            source_last_sequence: Some(1),
            cursor_after_sequence: Some(1),
            cursor_character: '7',
            ..RuntimeBatchFixture::running()
        }
        .page(
            "append",
            &[delta_value(1, 1, '8', "replacement", 11)],
            false,
        );
        assert_eq!(
            reducer.apply_delivery(
                &delivery(&selection, replacement_append).expect("replacement append delivery")
            ),
            Err(RuntimeSubscriptionError::ReplacementRequiresReset)
        );

        let old_cursor = reducer
            .viewport(&exact_scope)
            .expect("viewport")
            .cursor()
            .expect("old cursor");
        let viewport_before_malformed_reset = reducer
            .viewport(&exact_scope)
            .expect("viewport before malformed Reset")
            .clone();
        let malformed_reset = RuntimeBatchFixture {
            turn_character: 'c',
            generation: 2,
            revision: 1,
            source_last_sequence: Some(3),
            cursor_after_sequence: Some(3),
            cursor_character: '6',
            ..RuntimeBatchFixture::running()
        }
        .page("reset", &[delta_value(3, 2, '8', "malformed", 9)], false);
        assert_eq!(
            reducer.apply_delivery(
                &delivery(&selection, malformed_reset).expect("malformed reset envelope")
            ),
            Err(RuntimeSubscriptionError::DeltaIntegrityMismatch)
        );
        assert_eq!(
            reducer.viewport(&exact_scope),
            Some(&viewport_before_malformed_reset)
        );
        assert_eq!(
            reducer
                .viewport(&exact_scope)
                .expect("unchanged viewport")
                .cursor(),
            Some(old_cursor.clone())
        );

        let replacement_reset = RuntimeBatchFixture {
            turn_character: 'c',
            generation: 2,
            revision: 1,
            source_last_sequence: Some(1),
            cursor_after_sequence: Some(1),
            cursor_character: '5',
            ..RuntimeBatchFixture::running()
        }
        .page("reset", &[delta_value(1, 1, '8', "replacement", 11)], false);
        let effect = reducer
            .apply_delivery(
                &delivery(&selection, replacement_reset).expect("replacement reset delivery"),
            )
            .expect("replacement reset");
        assert!(matches!(
            effect,
            DesktopRuntimeReducerEffect::Reset {
                cleared_cursor: Some(ref cleared),
                ..
            } if cleared == &old_cursor
        ));
        let projection = reducer
            .viewport(&exact_scope)
            .expect("replacement viewport")
            .projection()
            .expect("replacement projection");
        assert_eq!(projection.items().len(), 1);
        assert_eq!(projection.items()[0].text(), "replacement");
    }

    #[test]
    fn caught_up_cannot_change_runtime_or_business_terminal_state() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope.clone()))
            .expect("select")
            .expect("selection");
        reducer
            .apply_delivery(&delivery(&selection, reset_page_one()).expect("reset delivery"))
            .expect("running reset");

        let completed_caught_up = RuntimeBatchFixture {
            revision: 5,
            status: RuntimeTurnStatus::Completed,
            source_last_sequence: Some(1),
            cursor_after_sequence: Some(1),
            cursor_character: '7',
            ..RuntimeBatchFixture::running()
        }
        .caught_up();
        assert_eq!(
            reducer.apply_delivery(
                &delivery(&selection, completed_caught_up).expect("completed cursor envelope")
            ),
            Err(RuntimeSubscriptionError::CaughtUpCursorMismatch)
        );
        assert_eq!(
            reducer
                .viewport(&exact_scope)
                .expect("viewport")
                .projection()
                .expect("projection")
                .turn_status(),
            RuntimeTurnStatus::Running
        );

        let changed_status_same_cursor = RuntimeBatchFixture {
            revision: 5,
            status: RuntimeTurnStatus::Completed,
            source_last_sequence: Some(1),
            cursor_after_sequence: Some(1),
            ..RuntimeBatchFixture::running()
        }
        .caught_up();
        assert_eq!(
            reducer.apply_delivery(
                &delivery(&selection, changed_status_same_cursor)
                    .expect("status-change cursor envelope")
            ),
            Err(RuntimeSubscriptionError::CaughtUpCursorMismatch)
        );

        // A durable status transition is represented by Reset, never by
        // CaughtUp. The projected Runtime status is still not Mission
        // completion authority.
        let completed_reset = RuntimeBatchFixture {
            revision: 5,
            status: RuntimeTurnStatus::Completed,
            source_last_sequence: Some(2),
            cursor_after_sequence: Some(2),
            cursor_character: '4',
            ..RuntimeBatchFixture::running()
        }
        .page(
            "reset",
            &[
                delta_value(1, 1, 'd', "Hello ", 6),
                delta_value(2, 2, 'd', "world", 11),
            ],
            false,
        );
        reducer
            .apply_delivery(&delivery(&selection, completed_reset).expect("completed reset"))
            .expect("durable status reset");
        assert_eq!(
            reducer
                .viewport(&exact_scope)
                .expect("viewport")
                .projection()
                .expect("projection")
                .turn_status(),
            RuntimeTurnStatus::Completed
        );
    }

    #[test]
    fn delivery_and_reducer_debug_never_expose_private_text_or_full_digests() {
        let exact_scope = scope("project", "mission", 'a');
        let mut reducer = DesktopRuntimeSubscriptionReducer::default();
        let selection = reducer
            .select_scope(Some(exact_scope.clone()))
            .expect("select")
            .expect("selection");
        let private = "private-attempt private-thread private-item private body";
        let batch = RuntimeBatchFixture {
            source_last_sequence: Some(1),
            cursor_after_sequence: Some(1),
            ..RuntimeBatchFixture::running()
        }
        .page(
            "reset",
            &[delta_value(
                1,
                1,
                'd',
                private,
                u64::try_from(private.len()).expect("private fixture length"),
            )],
            false,
        );
        let batch_json = serde_json::to_value(&batch).expect("subscription batch JSON");
        let mut full_digests = Vec::new();
        canonical_digests(&batch_json, &mut full_digests);
        assert!(!full_digests.is_empty());
        let debug_batch = format!("{batch:?}");
        let delivery = delivery(&selection, batch).expect("delivery");
        let debug_delivery = format!("{delivery:?}");
        reducer.apply_delivery(&delivery).expect("reset");
        let debug_reducer = format!("{reducer:?}");
        let debug_fingerprint = format!(
            "{:?}",
            reducer
                .viewport(&exact_scope)
                .expect("viewport")
                .last_delivery_fingerprint
        );
        for debug in [
            debug_batch,
            debug_delivery,
            debug_reducer,
            debug_fingerprint,
        ] {
            assert!(!debug.contains(private));
            assert!(!debug.contains(&digest('a')));
            assert!(!debug.contains(&digest('b')));
            assert!(!debug.contains(&digest('c')));
            assert!(!debug.contains(&digest('d')));
            for full_digest in &full_digests {
                assert!(!debug.contains(full_digest));
            }
            for raw_private_id in ["private-attempt", "private-thread", "private-item"] {
                assert!(!debug.contains(raw_private_id));
            }
        }
        for error in [
            RuntimeSubscriptionError::ConflictingDuplicate,
            RuntimeSubscriptionError::DeltaIntegrityMismatch,
            RuntimeSubscriptionError::CursorPageMismatch,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains(private));
            assert!(full_digests.iter().all(|digest| !rendered.contains(digest)));
        }
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
            .apply_delivery(&delivery(&selected_a, reset_page_one()).expect("reset delivery"))
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
                .apply_delivery(
                    &delivery(&selected_a, append_page_two('d')).expect("append delivery"),
                )
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
                .after_evidence_sequence(),
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
            .apply_delivery(
                &delivery(
                    &selection,
                    RuntimeBatchFixture {
                        generation: 7,
                        revision: 13,
                        status: RuntimeTurnStatus::Uncertain,
                        ..RuntimeBatchFixture::running()
                    }
                    .page("reset", &[], false),
                )
                .expect("restart reset delivery"),
            )
            .expect("durable ledger hydration");
        let viewport = restarted.viewport(&exact_scope).expect("viewport");
        assert!(!viewport.has_unseen());
        assert!(viewport.follow_latest());
    }
}
