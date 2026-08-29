#![allow(
    dead_code,
    reason = "UI-SUB-02B1 wires the durable Desktop consumer before the Dioxus subscription owns these crate-private types"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_application::{
    CatalogMissionExecutionHandle, RuntimeTextSubscriptionBatch, RuntimeTextSubscriptionCursor,
    RuntimeTextSubscriptionDelta, RuntimeTextSubscriptionPage, RuntimeTextSubscriptionTurn,
};
use hartevo_domain_kernel::{MissionId, ProjectId, RuntimeTurnStatus};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::data_plane::{
    DesktopRuntimeCancellation, DesktopRuntimeProgressEvent, DesktopRuntimeTextItemProjection,
    DesktopRuntimeTextStreamProjection,
};

const SHA256_HEX_LENGTH: usize = 64;
const DIGEST_LABEL_LENGTH: usize = 8;
pub(crate) const DESKTOP_RUNTIME_SUBSCRIPTION_PAGE_SIZE: usize = 64;

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

    pub(crate) fn handle_digest(&self) -> &str {
        self.mission_handle_digest.as_str()
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

    /// Borrows the exact cancellation authority while the matching background
    /// command is executing. The authority itself remains non-Clone at this
    /// Desktop orchestration boundary.
    pub(crate) fn cancellation(&self) -> &DesktopRuntimeCancellation {
        &self.cancellation
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
    const fn has_active_command(&self) -> bool {
        self.active.is_some()
    }

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

    fn cancellation_for(
        &self,
        selected_scope: Option<&DesktopRuntimeSubscriptionScope>,
    ) -> Option<DesktopRuntimeCancellation> {
        self.active.as_ref().and_then(|handle| {
            (selected_scope == Some(&handle.identity.scope)).then(|| handle.cancellation.clone())
        })
    }

    fn progress_since(
        &self,
        identity: &DesktopRuntimeCommandIdentity,
        sequence: u64,
    ) -> Option<Vec<DesktopRuntimeProgressEvent>> {
        self.active.as_ref().and_then(|handle| {
            (handle.identity == *identity).then(|| handle.cancellation.progress_since(sequence))
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

/// Result of reconciling the current Desktop selection with an exact retained
/// Application handle. `Untracked` falls back to the older read-only Mission
/// projection; it never fabricates a subscription handle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DesktopRuntimeSelectionChange {
    Untracked,
    Unchanged,
    Selected(DesktopRuntimeSelection),
}

/// Exact producer inputs for one durable pull. Both the Application handle and
/// cursor are retained byte-for-byte; Desktop only adds a checked selection
/// epoch and never reconstructs or signs either value.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DesktopRuntimePullRequest {
    scope: DesktopRuntimeSubscriptionScope,
    epoch: DesktopRuntimeSubscriptionEpoch,
    handle: CatalogMissionExecutionHandle,
    cursor: Option<DesktopRuntimeViewportCursor>,
}

impl DesktopRuntimePullRequest {
    pub(crate) fn handle(&self) -> &CatalogMissionExecutionHandle {
        &self.handle
    }

    pub(crate) fn producer_cursor(&self) -> Option<&RuntimeTextSubscriptionCursor> {
        self.cursor
            .as_ref()
            .map(DesktopRuntimeViewportCursor::producer)
    }

    pub(crate) fn into_delivery(
        self,
        batch: RuntimeTextSubscriptionBatch,
    ) -> Result<DesktopRuntimeDelivery, RuntimeSubscriptionError> {
        DesktopRuntimeDelivery::from_application(self.scope, self.epoch, batch)
    }
}

impl fmt::Debug for DesktopRuntimePullRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimePullRequest")
            .field("scope", &self.scope)
            .field("epoch", &self.epoch)
            .field("handle", &self.handle)
            .field("cursor", &self.cursor)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopRuntimePaintStreamTransport {
    Open,
    CaughtUp,
}

#[derive(Clone, Eq, PartialEq)]
enum DesktopRuntimePaintContent {
    Empty,
    AwaitingTurn,
    Stream {
        projection: DesktopRuntimeTextStreamProjection,
        transport: DesktopRuntimePaintStreamTransport,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DesktopRuntimePaintVisibility {
    Following,
    PausedSeen,
    PausedUnseen,
}

impl DesktopRuntimePaintVisibility {
    fn from_viewport(viewport: &DesktopRuntimeViewportState) -> Option<Self> {
        match (viewport.follow_mode, viewport.visibility) {
            (DesktopRuntimeFollowMode::FollowLatest, DesktopRuntimeVisibility::Seen) => {
                Some(Self::Following)
            }
            (DesktopRuntimeFollowMode::Paused, DesktopRuntimeVisibility::Seen) => {
                Some(Self::PausedSeen)
            }
            (DesktopRuntimeFollowMode::Paused, DesktopRuntimeVisibility::Unseen) => {
                Some(Self::PausedUnseen)
            }
            (DesktopRuntimeFollowMode::FollowLatest, DesktopRuntimeVisibility::Unseen) => None,
        }
    }

    const fn follow_latest(self) -> bool {
        matches!(self, Self::Following)
    }

    const fn has_unseen(self) -> bool {
        matches!(self, Self::PausedUnseen)
    }
}

/// Ephemeral render projection derived from the reducer. It may be cloned by
/// Dioxus while painting, but is never stored as a second application signal;
/// the reducer viewport remains the sole long-lived private-text owner. Typed
/// content and visibility states make contradictory boolean combinations
/// unrepresentable.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeExecutionPaintView {
    content: DesktopRuntimePaintContent,
    visibility: DesktopRuntimePaintVisibility,
}

impl DesktopRuntimeExecutionPaintView {
    pub(crate) fn stream(&self) -> Option<&DesktopRuntimeTextStreamProjection> {
        match &self.content {
            DesktopRuntimePaintContent::Stream { projection, .. } => Some(projection),
            DesktopRuntimePaintContent::Empty | DesktopRuntimePaintContent::AwaitingTurn => None,
        }
    }

    pub(crate) const fn awaiting_turn(&self) -> bool {
        matches!(&self.content, DesktopRuntimePaintContent::AwaitingTurn)
    }

    pub(crate) const fn follow_latest(&self) -> bool {
        self.visibility.follow_latest()
    }

    pub(crate) const fn has_unseen(&self) -> bool {
        self.visibility.has_unseen()
    }

    pub(crate) const fn transport_caught_up(&self) -> bool {
        matches!(
            &self.content,
            DesktopRuntimePaintContent::Stream {
                transport: DesktopRuntimePaintStreamTransport::CaughtUp,
                ..
            }
        )
    }
}

impl fmt::Debug for DesktopRuntimeExecutionPaintView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeExecutionPaintView")
            .field("has_stream", &self.stream().is_some())
            .field(
                "delta_count",
                &self.stream().map_or(0, |stream| stream.delta_count),
            )
            .field(
                "item_count",
                &self.stream().map_or(0, |stream| stream.items.len()),
            )
            .field("awaiting_turn", &self.awaiting_turn())
            .field("follow_latest", &self.follow_latest())
            .field("has_unseen", &self.has_unseen())
            .field("transport_caught_up", &self.transport_caught_up())
            .finish()
    }
}

/// Content-free receipt that phase one has entered the reducer. This is not a
/// render acknowledgement and deliberately carries no Runtime authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DesktopRuntimePaintCommit {
    selection: DesktopRuntimeSelection,
    identity: DesktopRuntimeCommandIdentity,
    prepared_sequence: u64,
}

impl DesktopRuntimePaintCommit {
    pub(crate) fn selection(&self) -> &DesktopRuntimeSelection {
        &self.selection
    }
}

/// Token produced only after a post-render Dioxus effect acknowledges the
/// exact phase-one paint receipt. Runtime execution owns the non-Clone
/// coordinator endpoint carried by this token.
pub(crate) struct DesktopRuntimeExecutionLaunch {
    selection: DesktopRuntimeSelection,
    handle: CatalogMissionExecutionHandle,
    identity: DesktopRuntimeCommandIdentity,
    coordinator: DesktopRuntimeCoordinatorControl,
    prepared_sequence: u64,
    render_ack_sequence: u64,
}

impl DesktopRuntimeExecutionLaunch {
    pub(crate) fn selection(&self) -> &DesktopRuntimeSelection {
        &self.selection
    }

    pub(crate) fn identity(&self) -> &DesktopRuntimeCommandIdentity {
        &self.identity
    }

    pub(crate) fn handle(&self) -> &CatalogMissionExecutionHandle {
        &self.handle
    }

    pub(crate) const fn prepared_sequence(&self) -> u64 {
        self.prepared_sequence
    }

    pub(crate) const fn render_ack_sequence(&self) -> u64 {
        self.render_ack_sequence
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        DesktopRuntimeSelection,
        CatalogMissionExecutionHandle,
        DesktopRuntimeCommandIdentity,
        DesktopRuntimeCoordinatorControl,
        u64,
        u64,
    ) {
        (
            self.selection,
            self.handle,
            self.identity,
            self.coordinator,
            self.prepared_sequence,
            self.render_ack_sequence,
        )
    }
}

impl fmt::Debug for DesktopRuntimeExecutionLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeExecutionLaunch")
            .field("selection", &self.selection)
            .field("handle", &self.handle)
            .field("identity", &self.identity)
            .field("prepared_sequence", &self.prepared_sequence)
            .field("render_ack_sequence", &self.render_ack_sequence)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DesktopRuntimeAcceptedCompletion {
    render_ack_sequence: u64,
    runtime_completion_sequence: u64,
}

impl DesktopRuntimeAcceptedCompletion {
    pub(crate) const fn render_ack_sequence(self) -> u64 {
        self.render_ack_sequence
    }

    pub(crate) const fn runtime_completion_sequence(self) -> u64 {
        self.runtime_completion_sequence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesktopRuntimeCompletionDisposition {
    Accepted(DesktopRuntimeAcceptedCompletion),
    IgnoredStale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesktopRuntimePollDisposition {
    Stale,
    PullNow,
    WaitForRuntime,
    WaitAfterRuntime,
    AwaitingWithoutRuntime,
    ReadyToFinalize,
    Complete,
}

#[derive(Debug)]
struct DesktopRuntimeActivePaint {
    identity: DesktopRuntimeCommandIdentity,
    selection: DesktopRuntimeSelection,
    prepared_sequence: u64,
    render_ack_sequence: Option<u64>,
    coordinator: Option<DesktopRuntimeCoordinatorControl>,
    runtime_returned: bool,
    post_return_delivery_observed: bool,
}

/// Single Desktop owner for exact Application handles, subscription viewports,
/// scoped stop authority, and execution/paint ordering. It owns no Mission or
/// Runtime completion authority; those remain in the durable snapshot/ledger.
#[derive(Default)]
pub(crate) struct DesktopRuntimeExecutionPaintState {
    reducer: DesktopRuntimeSubscriptionReducer,
    handles: BTreeMap<DesktopRuntimeSubscriptionScope, CatalogMissionExecutionHandle>,
    acknowledged_handles: BTreeSet<DesktopRuntimeSubscriptionScope>,
    command_slot: DesktopRuntimeCommandSlot,
    active_paint: Option<DesktopRuntimeActivePaint>,
    visible_scope: Option<DesktopRuntimeSubscriptionScope>,
    transition_sequence: u64,
}

impl DesktopRuntimeExecutionPaintState {
    pub(crate) fn commit_catalog_start(
        &mut self,
        handle: CatalogMissionExecutionHandle,
    ) -> Result<DesktopRuntimePaintCommit, RuntimeSubscriptionError> {
        if self.command_slot.has_active_command() {
            return Err(RuntimeSubscriptionError::CommandAlreadyActive);
        }
        let prepared_sequence = self
            .transition_sequence
            .checked_add(1)
            .ok_or(RuntimeSubscriptionError::SequenceOverflow)?;
        let scope = DesktopRuntimeSubscriptionScope::from_handle(&handle)?;
        let selection = self
            .reducer
            .select_scope(Some(scope.clone()))?
            .ok_or(RuntimeSubscriptionError::ScopeNotSelected)?;
        let awaiting = DesktopRuntimeDelivery::AwaitingTurn {
            scope: scope.clone(),
            epoch: selection.epoch,
        };
        if self.reducer.apply_delivery(&awaiting)? != DesktopRuntimeReducerEffect::AwaitingTurn {
            return Err(RuntimeSubscriptionError::InvalidViewportState);
        }
        let command_digest = execution_command_digest(&handle, selection.epoch);
        let (command, coordinator) =
            DesktopRuntimeCommandHandle::pair(scope.clone(), command_digest)?;
        let identity = command.identity();
        self.command_slot.install(command)?;
        self.acknowledged_handles.remove(&scope);
        self.handles.insert(scope.clone(), handle);
        self.visible_scope = Some(scope);
        self.active_paint = Some(DesktopRuntimeActivePaint {
            identity: identity.clone(),
            selection: selection.clone(),
            prepared_sequence,
            render_ack_sequence: None,
            coordinator: Some(coordinator),
            runtime_returned: false,
            post_return_delivery_observed: false,
        });
        self.transition_sequence = prepared_sequence;
        Ok(DesktopRuntimePaintCommit {
            selection,
            identity,
            prepared_sequence,
        })
    }

    pub(crate) fn pending_paint_commit(&self) -> Option<DesktopRuntimePaintCommit> {
        let active = self.active_paint.as_ref()?;
        (active.render_ack_sequence.is_none() && active.coordinator.is_some()).then(|| {
            DesktopRuntimePaintCommit {
                selection: active.selection.clone(),
                identity: active.identity.clone(),
                prepared_sequence: active.prepared_sequence,
            }
        })
    }

    /// Consumes the exact phase-one receipt from a post-render Dioxus effect.
    /// Calling this before that lifecycle point is a caller error: the state
    /// machine intentionally exposes no Runtime control through `commit`.
    pub(crate) fn acknowledge_rendered_paint(
        &mut self,
        commit: &DesktopRuntimePaintCommit,
    ) -> Result<DesktopRuntimeExecutionLaunch, RuntimeSubscriptionError> {
        let render_ack_sequence = self
            .transition_sequence
            .checked_add(1)
            .ok_or(RuntimeSubscriptionError::SequenceOverflow)?;
        let active = self
            .active_paint
            .as_ref()
            .ok_or(RuntimeSubscriptionError::PaintAcknowledgementMismatch)?;
        if active.identity != commit.identity
            || active.selection != commit.selection
            || active.prepared_sequence != commit.prepared_sequence
            || self.reducer.selected.as_ref()
                != Some(&(commit.selection.scope.clone(), commit.selection.epoch))
        {
            return Err(RuntimeSubscriptionError::PaintAcknowledgementMismatch);
        }
        if active.render_ack_sequence.is_some() || active.coordinator.is_none() {
            return Err(RuntimeSubscriptionError::PaintAlreadyAcknowledged);
        }
        let viewport = self
            .reducer
            .viewport(&commit.selection.scope)
            .ok_or(RuntimeSubscriptionError::ViewportMissing)?;
        if viewport.projection().is_some()
            || !matches!(
                viewport.transport_state,
                DesktopRuntimeTransportState::AwaitingTurn
            )
        {
            return Err(RuntimeSubscriptionError::PaintAcknowledgementMismatch);
        }
        if active
            .coordinator
            .as_ref()
            .is_some_and(DesktopRuntimeCoordinatorControl::is_stop_requested)
        {
            let identity = active.identity.clone();
            self.command_slot.finish_exact(&identity);
            self.active_paint = None;
            return Err(RuntimeSubscriptionError::PaintStoppedBeforeRuntime);
        }
        let handle = self
            .handles
            .get(&commit.selection.scope)
            .cloned()
            .ok_or(RuntimeSubscriptionError::ScopeHandleMismatch)?;
        if handle.handle_digest() != commit.selection.scope.handle_digest() {
            return Err(RuntimeSubscriptionError::ScopeHandleMismatch);
        }
        let active = self
            .active_paint
            .as_mut()
            .ok_or(RuntimeSubscriptionError::PaintAcknowledgementMismatch)?;
        let coordinator = active
            .coordinator
            .take()
            .ok_or(RuntimeSubscriptionError::PaintAlreadyAcknowledged)?;
        active.render_ack_sequence = Some(render_ack_sequence);
        self.acknowledged_handles
            .insert(commit.selection.scope.clone());
        self.transition_sequence = render_ack_sequence;
        Ok(DesktopRuntimeExecutionLaunch {
            selection: commit.selection.clone(),
            handle,
            identity: commit.identity.clone(),
            coordinator,
            prepared_sequence: commit.prepared_sequence,
            render_ack_sequence,
        })
    }

    pub(crate) fn reconcile_selection(
        &mut self,
        selected: Option<(&ProjectId, &MissionId)>,
    ) -> Result<DesktopRuntimeSelectionChange, RuntimeSubscriptionError> {
        self.abandon_unacknowledged_paint_if_scope_changed(selected);
        let Some((project_id, mission_id)) = selected else {
            self.visible_scope = None;
            if self.active_paint.is_none() && self.reducer.selected.is_some() {
                self.reducer.select_scope(None)?;
            }
            return Ok(DesktopRuntimeSelectionChange::Untracked);
        };
        let scope = self
            .handles
            .keys()
            .find(|scope| scope.project_id() == project_id && scope.mission_id() == mission_id)
            .cloned();
        let Some(scope) = scope else {
            self.visible_scope = None;
            if self.active_paint.is_none() && self.reducer.selected.is_some() {
                self.reducer.select_scope(None)?;
            }
            return Ok(DesktopRuntimeSelectionChange::Untracked);
        };
        let was_visible = self.visible_scope.as_ref() == Some(&scope);
        self.visible_scope = Some(scope.clone());

        if let Some(active_scope) = self
            .active_paint
            .as_ref()
            .map(|active| active.selection.scope.clone())
        {
            if active_scope != scope {
                return Ok(if was_visible {
                    DesktopRuntimeSelectionChange::Unchanged
                } else {
                    DesktopRuntimeSelectionChange::Untracked
                });
            }
            let transport_is_exact =
                self.reducer
                    .selected
                    .as_ref()
                    .is_some_and(|(selected_scope, selected_epoch)| {
                        selected_scope == &scope
                            && self
                                .active_paint
                                .as_ref()
                                .is_some_and(|active| active.selection.epoch == *selected_epoch)
                    });
            if was_visible && transport_is_exact {
                return Ok(DesktopRuntimeSelectionChange::Unchanged);
            }
            let selection = self
                .reducer
                .select_scope(Some(scope))?
                .ok_or(RuntimeSubscriptionError::ScopeNotSelected)?;
            let active = self
                .active_paint
                .as_mut()
                .ok_or(RuntimeSubscriptionError::CommandIdentityMismatch)?;
            active.selection = selection.clone();
            return Ok(DesktopRuntimeSelectionChange::Selected(selection));
        }

        if was_visible
            && self
                .reducer
                .selected
                .as_ref()
                .is_some_and(|(selected_scope, _)| selected_scope == &scope)
        {
            return Ok(DesktopRuntimeSelectionChange::Unchanged);
        }
        let selection = self
            .reducer
            .select_scope(Some(scope))?
            .ok_or(RuntimeSubscriptionError::ScopeNotSelected)?;
        Ok(DesktopRuntimeSelectionChange::Selected(selection))
    }

    fn abandon_unacknowledged_paint_if_scope_changed(
        &mut self,
        selected: Option<(&ProjectId, &MissionId)>,
    ) {
        let identity = self.active_paint.as_ref().and_then(|active| {
            let same_scope = selected.is_some_and(|(project_id, mission_id)| {
                active.selection.scope.project_id() == project_id
                    && active.selection.scope.mission_id() == mission_id
            });
            (active.render_ack_sequence.is_none() && !same_scope).then(|| active.identity.clone())
        });
        if let Some(identity) = identity {
            self.command_slot.finish_exact(&identity);
            self.active_paint = None;
        }
    }

    pub(crate) fn pull_request(
        &self,
        selection: &DesktopRuntimeSelection,
    ) -> Option<DesktopRuntimePullRequest> {
        if self.reducer.selected.as_ref() != Some(&(selection.scope.clone(), selection.epoch)) {
            return None;
        }
        let handle = self.handles.get(&selection.scope)?.clone();
        let cursor = self.reducer.viewport(&selection.scope)?.cursor();
        Some(DesktopRuntimePullRequest {
            scope: selection.scope.clone(),
            epoch: selection.epoch,
            handle,
            cursor,
        })
    }

    /// Return only a handle that crossed this process's post-render
    /// acknowledgement fence for the exact selected Catalog Mission.
    pub(crate) fn acknowledged_handle_for_selection(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Option<CatalogMissionExecutionHandle> {
        let scope = self.selected_scope_for(project_id, mission_id)?;
        if !self.acknowledged_handles.contains(scope) {
            return None;
        }
        let handle = self.handles.get(scope)?;
        (handle.handle_digest() == scope.handle_digest()).then(|| handle.clone())
    }

    pub(crate) fn apply_delivery(
        &mut self,
        delivery: &DesktopRuntimeDelivery,
    ) -> Result<DesktopRuntimeReducerEffect, RuntimeSubscriptionError> {
        let effect = self.reducer.apply_delivery(delivery)?;
        if effect != DesktopRuntimeReducerEffect::IgnoredStale
            && self.active_paint.as_ref().is_some_and(|active| {
                active.runtime_returned && active.selection.scope == *delivery.scope()
            })
            && let Some(active) = self.active_paint.as_mut()
        {
            active.post_return_delivery_observed = true;
        }
        Ok(effect)
    }

    pub(crate) fn set_follow_latest(
        &mut self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        follow_latest: bool,
    ) -> Result<bool, RuntimeSubscriptionError> {
        let Some(scope) = self.selected_scope_for(project_id, mission_id).cloned() else {
            return Ok(false);
        };
        self.reducer.set_follow_latest(&scope, follow_latest)?;
        Ok(true)
    }

    pub(crate) fn paint_view(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Option<DesktopRuntimeExecutionPaintView> {
        let scope = self.selected_scope_for(project_id, mission_id)?;
        let viewport = self.reducer.viewport(scope)?;
        let handle = self.handles.get(scope)?;
        let stream = viewport.projection().map(|projection| {
            let items = projection
                .items()
                .iter()
                .map(|item| DesktopRuntimeTextItemProjection {
                    item_id_digest: item.item_identity_digest.as_str().to_owned(),
                    text: item.text.clone(),
                    delta_count: item.delta_count,
                    last_stream_sequence: item.last_stream_sequence,
                    cumulative_byte_count: item.cumulative_byte_count,
                    observed_at: item.observed_at,
                })
                .collect::<Vec<_>>();
            let updated_at = items
                .iter()
                .map(|item| item.observed_at)
                .max()
                .unwrap_or_else(|| handle.mission_created_at());
            DesktopRuntimeTextStreamProjection {
                project_id: scope.project_id().clone(),
                mission_id: scope.mission_id().clone(),
                worker_generation: projection.turn.worker_generation,
                turn_revision: projection.turn.turn_revision,
                turn_status: projection.turn.turn_status,
                last_evidence_sequence: projection.turn.consumed_evidence_sequence,
                delta_count: projection.delta_count(),
                items,
                updated_at,
            }
        });
        let content = match stream {
            Some(projection) => DesktopRuntimePaintContent::Stream {
                projection,
                transport: if viewport.transport_caught_up() {
                    DesktopRuntimePaintStreamTransport::CaughtUp
                } else {
                    DesktopRuntimePaintStreamTransport::Open
                },
            },
            None if self.command_slot.stop_available_for(scope) => {
                DesktopRuntimePaintContent::AwaitingTurn
            }
            None => DesktopRuntimePaintContent::Empty,
        };
        Some(DesktopRuntimeExecutionPaintView {
            content,
            visibility: DesktopRuntimePaintVisibility::from_viewport(viewport)?,
        })
    }

    pub(crate) fn viewport_controls(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Option<(bool, bool)> {
        let scope = self.selected_scope_for(project_id, mission_id)?;
        let viewport = self.reducer.viewport(scope)?;
        Some((viewport.follow_latest(), viewport.has_unseen()))
    }

    pub(crate) fn mark_runtime_returned(
        &mut self,
        identity: &DesktopRuntimeCommandIdentity,
    ) -> Result<bool, RuntimeSubscriptionError> {
        let Some(active) = self.active_paint.as_mut() else {
            return Ok(false);
        };
        if active.identity != *identity {
            return Ok(false);
        }
        if active.render_ack_sequence.is_none() || active.coordinator.is_some() {
            return Err(RuntimeSubscriptionError::RuntimeStartedBeforePaint);
        }
        if active.runtime_returned {
            return Ok(false);
        }
        active.runtime_returned = true;
        active.post_return_delivery_observed = false;
        Ok(true)
    }

    pub(crate) fn poll_disposition(
        &self,
        selection: &DesktopRuntimeSelection,
    ) -> DesktopRuntimePollDisposition {
        if self.reducer.selected.as_ref() != Some(&(selection.scope.clone(), selection.epoch)) {
            return DesktopRuntimePollDisposition::Stale;
        }
        let Some(viewport) = self.reducer.viewport(&selection.scope) else {
            return DesktopRuntimePollDisposition::Stale;
        };
        let active = self
            .active_paint
            .as_ref()
            .filter(|active| active.selection.scope == selection.scope);
        if viewport.transport_caught_up() {
            match active {
                Some(active) if !active.runtime_returned => {
                    DesktopRuntimePollDisposition::WaitForRuntime
                }
                Some(active)
                    if active.post_return_delivery_observed
                        && viewport
                            .projection()
                            .is_some_and(|projection| projection.turn_status().is_terminal()) =>
                {
                    DesktopRuntimePollDisposition::ReadyToFinalize
                }
                Some(_) => DesktopRuntimePollDisposition::WaitAfterRuntime,
                None => DesktopRuntimePollDisposition::Complete,
            }
        } else if viewport.has_more() || viewport.projection().is_some() {
            DesktopRuntimePollDisposition::PullNow
        } else {
            match active {
                Some(active) if !active.runtime_returned => {
                    DesktopRuntimePollDisposition::WaitForRuntime
                }
                Some(active) if active.post_return_delivery_observed => {
                    DesktopRuntimePollDisposition::ReadyToFinalize
                }
                Some(_) => DesktopRuntimePollDisposition::WaitAfterRuntime,
                None => DesktopRuntimePollDisposition::AwaitingWithoutRuntime,
            }
        }
    }

    pub(crate) fn completion_ready(&self, identity: &DesktopRuntimeCommandIdentity) -> bool {
        let Some(active) = self
            .active_paint
            .as_ref()
            .filter(|active| active.identity == *identity)
        else {
            return false;
        };
        if !active.runtime_returned {
            return false;
        }
        self.poll_disposition(&active.selection) == DesktopRuntimePollDisposition::ReadyToFinalize
    }

    pub(crate) fn current_selection_for_command(
        &self,
        identity: &DesktopRuntimeCommandIdentity,
    ) -> Option<DesktopRuntimeSelection> {
        let active = self
            .active_paint
            .as_ref()
            .filter(|active| active.identity == *identity)?;
        (self.reducer.selected.as_ref()
            == Some(&(active.selection.scope.clone(), active.selection.epoch)))
        .then(|| active.selection.clone())
    }

    pub(crate) fn selection_is_visible(&self, selection: &DesktopRuntimeSelection) -> bool {
        self.visible_scope.as_ref() == Some(&selection.scope)
            && self.reducer.selected.as_ref() == Some(&(selection.scope.clone(), selection.epoch))
    }

    /// Releases a failed transport coordinator without treating it as Runtime
    /// or Mission completion. Durable text already in the reducer is retained.
    pub(crate) fn abort_runtime_transport(
        &mut self,
        identity: &DesktopRuntimeCommandIdentity,
    ) -> Result<bool, RuntimeSubscriptionError> {
        let Some(active) = self
            .active_paint
            .as_ref()
            .filter(|active| active.identity == *identity)
        else {
            return Ok(false);
        };
        if active.render_ack_sequence.is_none() {
            return Err(RuntimeSubscriptionError::RuntimeStartedBeforePaint);
        }
        let abort_sequence = self
            .transition_sequence
            .checked_add(1)
            .ok_or(RuntimeSubscriptionError::SequenceOverflow)?;
        if !self.command_slot.finish_exact(identity) {
            return Ok(false);
        }
        self.active_paint = None;
        self.transition_sequence = abort_sequence;
        Ok(true)
    }

    pub(crate) fn stop_available_for_selection(
        &self,
        selected: Option<(&ProjectId, &MissionId)>,
    ) -> bool {
        selected
            .and_then(|(project_id, mission_id)| self.selected_scope_for(project_id, mission_id))
            .is_some_and(|scope| self.command_slot.stop_available_for(scope))
    }

    pub(crate) fn request_stop_for_selection(
        &self,
        selected: Option<(&ProjectId, &MissionId)>,
    ) -> DesktopRuntimeStopDisposition {
        let scope = selected
            .and_then(|(project_id, mission_id)| self.selected_scope_for(project_id, mission_id));
        self.command_slot.request_stop_for(scope)
    }

    pub(crate) fn live_cancellation_for_selection(
        &self,
        selected: Option<(&ProjectId, &MissionId)>,
    ) -> Option<DesktopRuntimeCancellation> {
        let scope = selected
            .and_then(|(project_id, mission_id)| self.selected_scope_for(project_id, mission_id));
        self.command_slot.cancellation_for(scope)
    }

    pub(crate) fn progress_since(
        &self,
        identity: &DesktopRuntimeCommandIdentity,
        sequence: u64,
    ) -> Option<Vec<DesktopRuntimeProgressEvent>> {
        self.command_slot.progress_since(identity, sequence)
    }

    pub(crate) fn finish_runtime(
        &mut self,
        identity: &DesktopRuntimeCommandIdentity,
        selection: &DesktopRuntimeSelection,
    ) -> Result<DesktopRuntimeCompletionDisposition, RuntimeSubscriptionError> {
        let Some(active) = self.active_paint.as_ref() else {
            return Ok(DesktopRuntimeCompletionDisposition::IgnoredStale);
        };
        if active.identity != *identity || active.selection != *selection {
            return Ok(DesktopRuntimeCompletionDisposition::IgnoredStale);
        }
        if active.render_ack_sequence.is_none()
            || !active.runtime_returned
            || !self.completion_ready(identity)
        {
            return Err(RuntimeSubscriptionError::RuntimeCompletionBeforeTransportReady);
        }
        let completion_sequence = self
            .transition_sequence
            .checked_add(1)
            .ok_or(RuntimeSubscriptionError::SequenceOverflow)?;
        let render_ack_sequence = active
            .render_ack_sequence
            .ok_or(RuntimeSubscriptionError::RuntimeStartedBeforePaint)?;
        let selected_is_exact = self.visible_scope.as_ref() == Some(&selection.scope)
            && self.reducer.selected.as_ref() == Some(&(selection.scope.clone(), selection.epoch));
        if !self.command_slot.finish_exact(identity) {
            return Ok(DesktopRuntimeCompletionDisposition::IgnoredStale);
        }
        self.active_paint = None;
        self.transition_sequence = completion_sequence;
        if selected_is_exact {
            Ok(DesktopRuntimeCompletionDisposition::Accepted(
                DesktopRuntimeAcceptedCompletion {
                    render_ack_sequence,
                    runtime_completion_sequence: completion_sequence,
                },
            ))
        } else {
            Ok(DesktopRuntimeCompletionDisposition::IgnoredStale)
        }
    }

    fn selected_scope_for(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> Option<&DesktopRuntimeSubscriptionScope> {
        let visible = self
            .visible_scope
            .as_ref()
            .filter(|scope| scope.project_id() == project_id && scope.mission_id() == mission_id)?;
        self.reducer
            .selected
            .as_ref()
            .map(|(scope, _)| scope)
            .filter(|scope| *scope == visible)
    }
}

impl fmt::Debug for DesktopRuntimeExecutionPaintState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopRuntimeExecutionPaintState")
            .field("retained_handle_count", &self.handles.len())
            .field(
                "acknowledged_handle_count",
                &self.acknowledged_handles.len(),
            )
            .field("reducer", &self.reducer)
            .field("command_active", &self.command_slot.has_active_command())
            .field("has_visible_scope", &self.visible_scope.is_some())
            .field("active_paint", &self.active_paint)
            .field("transition_sequence", &self.transition_sequence)
            .finish()
    }
}

fn execution_command_digest(
    handle: &CatalogMissionExecutionHandle,
    epoch: DesktopRuntimeSubscriptionEpoch,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"hartevo.desktop.runtime-command/v1\0");
    hasher.update(handle.handle_digest().as_bytes());
    hasher.update(b"\0");
    hasher.update(epoch.get().to_be_bytes());
    format!("{:x}", hasher.finalize())
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
    #[error("the active Runtime command no longer matches its exact transport identity")]
    CommandIdentityMismatch,
    #[error("render acknowledgement does not match the prepared Mission paint")]
    PaintAcknowledgementMismatch,
    #[error("the prepared Mission paint was already acknowledged")]
    PaintAlreadyAcknowledged,
    #[error("the prepared Mission paint was stopped before Runtime launch")]
    PaintStoppedBeforeRuntime,
    #[error("Runtime execution cannot start before the exact render acknowledgement")]
    RuntimeStartedBeforePaint,
    #[error("the Runtime coordinator lost its exact command state")]
    RuntimeCoordinatorStateMismatch,
    #[error("Runtime completion arrived before final durable transport evidence")]
    RuntimeCompletionBeforeTransportReady,
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

    fn catalog_handle(
        project: &str,
        mission: &str,
        digest_character: char,
    ) -> CatalogMissionExecutionHandle {
        serde_json::from_value(json!({
            "tenantId": "tenant-desktop-runtime-paint",
            "projectId": project,
            "missionId": mission,
            "manifestId": "VM-07",
            "manifestVersion": 1,
            "catalogDigest": digest('9'),
            "conversationId": format!("mission-conversation:{mission}"),
            "missionCreatedAt": "2026-08-13T09:00:00Z",
            "contractDigest": digest('8'),
            "handleDigest": digest(digest_character),
        }))
        .expect("catalog execution handle fixture")
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

    fn reset_running_final_hello() -> RuntimeTextSubscriptionBatch {
        RuntimeBatchFixture {
            source_last_sequence: Some(1),
            cursor_after_sequence: Some(1),
            ..RuntimeBatchFixture::running()
        }
        .page("reset", &[delta_value(1, 1, 'd', "Hello ", 6)], false)
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

    fn acknowledged_execution_state(
        project_id: &ProjectId,
        mission_id: &MissionId,
    ) -> (
        DesktopRuntimeExecutionPaintState,
        CatalogMissionExecutionHandle,
        DesktopRuntimeSelection,
        DesktopRuntimeCommandIdentity,
    ) {
        let handle = catalog_handle(project_id.as_str(), mission_id.as_str(), 'a');
        let mut state = DesktopRuntimeExecutionPaintState::default();
        let commit = state
            .commit_catalog_start(handle.clone())
            .expect("prepare first paint");
        let launch = state
            .acknowledge_rendered_paint(&commit)
            .expect("ack rendered paint");
        let selection = launch.selection().clone();
        let identity = launch.identity().clone();
        (state, handle, selection, identity)
    }

    fn awaiting_turn_batch(handle: &CatalogMissionExecutionHandle) -> RuntimeTextSubscriptionBatch {
        serde_json::from_value(json!({
            "kind": "awaiting_turn",
            "handle_digest": handle.handle_digest(),
        }))
        .expect("awaiting batch")
    }

    fn apply_terminal_two_delta_turn(
        state: &mut DesktopRuntimeExecutionPaintState,
        selection: &DesktopRuntimeSelection,
        status: RuntimeTurnStatus,
        revision: u64,
        cursor_character: char,
    ) {
        let terminal_reset = RuntimeBatchFixture {
            revision,
            status,
            source_last_sequence: Some(2),
            cursor_after_sequence: Some(2),
            cursor_character,
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
        let terminal_reset = state
            .pull_request(selection)
            .expect("terminal reset pull")
            .into_delivery(terminal_reset)
            .expect("terminal Reset");
        state
            .apply_delivery(&terminal_reset)
            .expect("apply terminal Reset");
        assert_eq!(
            state.poll_disposition(selection),
            DesktopRuntimePollDisposition::PullNow
        );
        let terminal_ack = RuntimeBatchFixture {
            revision,
            status,
            source_last_sequence: Some(2),
            cursor_after_sequence: Some(2),
            cursor_character,
            ..RuntimeBatchFixture::running()
        }
        .caught_up();
        let terminal_ack = state
            .pull_request(selection)
            .expect("terminal ack pull")
            .into_delivery(terminal_ack)
            .expect("terminal CaughtUp");
        state
            .apply_delivery(&terminal_ack)
            .expect("apply terminal acknowledgement");
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
    fn execution_launch_requires_exact_post_render_ack_before_runtime_return() {
        let project_id = ProjectId::from("project-paint");
        let mission_id = MissionId::from("mission-paint");
        let handle = catalog_handle(project_id.as_str(), mission_id.as_str(), 'a');
        let exact_handle_digest = handle.handle_digest().to_owned();
        let mut state = DesktopRuntimeExecutionPaintState::default();

        let commit = state
            .commit_catalog_start(handle.clone())
            .expect("prepare durable first paint");
        assert_eq!(state.pending_paint_commit(), Some(commit.clone()));
        let view = state
            .paint_view(&project_id, &mission_id)
            .expect("selected paint view");
        assert!(view.awaiting_turn());
        assert!(view.stream().is_none());
        assert!(view.follow_latest());
        assert!(!view.has_unseen());
        assert!(!view.transport_caught_up());
        assert!(state.stop_available_for_selection(Some((&project_id, &mission_id))));
        let live = state
            .live_cancellation_for_selection(Some((&project_id, &mission_id)))
            .expect("catalog first-run observe-loop cancellation");
        assert!(!live.is_requested());
        let other_project = ProjectId::from("other-project");
        assert!(
            state
                .live_cancellation_for_selection(Some((&other_project, &mission_id)))
                .is_none()
        );
        assert_eq!(
            state.mark_runtime_returned(&commit.identity),
            Err(RuntimeSubscriptionError::RuntimeStartedBeforePaint)
        );

        let pull = state
            .pull_request(commit.selection())
            .expect("exact pull after paint");
        assert_eq!(pull.handle(), &handle);
        assert_eq!(pull.handle().handle_digest(), exact_handle_digest);
        assert!(pull.producer_cursor().is_none());
        assert_eq!(
            state.poll_disposition(commit.selection()),
            DesktopRuntimePollDisposition::WaitForRuntime
        );

        let launch = state
            .acknowledge_rendered_paint(&commit)
            .expect("post-render acknowledgement");
        assert!(launch.render_ack_sequence() > launch.prepared_sequence());
        assert!(matches!(
            state.acknowledge_rendered_paint(&commit),
            Err(RuntimeSubscriptionError::PaintAlreadyAcknowledged)
        ));
        let selection = launch.selection().clone();
        let identity = launch.identity().clone();
        let render_ack_sequence = launch.render_ack_sequence();
        assert!(
            state
                .mark_runtime_returned(&identity)
                .expect("record Runtime return")
        );
        let awaiting_batch: RuntimeTextSubscriptionBatch = serde_json::from_value(json!({
            "kind": "awaiting_turn",
            "handle_digest": exact_handle_digest,
        }))
        .expect("awaiting batch");
        let final_pull = state
            .pull_request(&selection)
            .expect("final read-only pull")
            .into_delivery(awaiting_batch)
            .expect("awaiting delivery");
        assert_eq!(
            state
                .apply_delivery(&final_pull)
                .expect("observe final pull"),
            DesktopRuntimeReducerEffect::Duplicate
        );
        assert_eq!(
            state.poll_disposition(&selection),
            DesktopRuntimePollDisposition::ReadyToFinalize
        );
        let completion = state
            .finish_runtime(&identity, &selection)
            .expect("fenced completion");
        let DesktopRuntimeCompletionDisposition::Accepted(completion) = completion else {
            panic!("exact selected completion must be accepted");
        };
        assert_eq!(completion.render_ack_sequence(), render_ack_sequence);
        assert!(completion.runtime_completion_sequence() > render_ack_sequence);
        assert!(
            !state
                .paint_view(&project_id, &mission_id)
                .expect("retained paint view")
                .awaiting_turn()
        );
        assert!(state.pull_request(&selection).is_some());
        assert!(!state.stop_available_for_selection(Some((&project_id, &mission_id))));
    }

    #[test]
    fn continuation_handle_exists_only_after_exact_render_ack() {
        let project_id = ProjectId::from("project-continuation-paint");
        let mission_id = MissionId::from("mission-continuation-paint");
        let handle = catalog_handle(project_id.as_str(), mission_id.as_str(), 'a');
        let mut state = DesktopRuntimeExecutionPaintState::default();
        let commit = state
            .commit_catalog_start(handle.clone())
            .expect("prepare first paint");
        assert!(
            state
                .acknowledged_handle_for_selection(&project_id, &mission_id)
                .is_none()
        );

        state
            .acknowledge_rendered_paint(&commit)
            .expect("exact post-render acknowledgement");
        assert_eq!(
            state.acknowledged_handle_for_selection(&project_id, &mission_id),
            Some(handle)
        );
        assert!(
            state
                .acknowledged_handle_for_selection(&ProjectId::from("other-project"), &mission_id,)
                .is_none()
        );
    }

    #[test]
    fn execution_paint_typed_states_map_getters_and_reject_invalid_visibility() {
        let empty_following = DesktopRuntimeExecutionPaintView {
            content: DesktopRuntimePaintContent::Empty,
            visibility: DesktopRuntimePaintVisibility::Following,
        };
        assert!(empty_following.stream().is_none());
        assert!(!empty_following.awaiting_turn());
        assert!(empty_following.follow_latest());
        assert!(!empty_following.has_unseen());
        assert!(!empty_following.transport_caught_up());

        let awaiting_paused = DesktopRuntimeExecutionPaintView {
            content: DesktopRuntimePaintContent::AwaitingTurn,
            visibility: DesktopRuntimePaintVisibility::PausedSeen,
        };
        assert!(awaiting_paused.awaiting_turn());
        assert!(!awaiting_paused.follow_latest());
        assert!(!awaiting_paused.has_unseen());

        let paused_unseen = DesktopRuntimeExecutionPaintView {
            content: DesktopRuntimePaintContent::Empty,
            visibility: DesktopRuntimePaintVisibility::PausedUnseen,
        };
        assert!(!paused_unseen.follow_latest());
        assert!(paused_unseen.has_unseen());

        let invalid_source = DesktopRuntimeViewportState {
            scope: scope(
                "project-invalid-visibility",
                "mission-invalid-visibility",
                'a',
            ),
            follow_mode: DesktopRuntimeFollowMode::FollowLatest,
            visibility: DesktopRuntimeVisibility::Unseen,
            cursor: None,
            projection: None,
            transport_state: DesktopRuntimeTransportState::AwaitingTurn,
            last_delivery_fingerprint: None,
        };
        assert_eq!(
            DesktopRuntimePaintVisibility::from_viewport(&invalid_source),
            None
        );
    }

    #[test]
    fn execution_paint_view_reselect_fences_stale_epoch_completion_and_stop() {
        let project_id = ProjectId::from("project-reselect");
        let mission_id = MissionId::from("mission-reselect");
        let (mut state, handle, stale_selection, stale_identity) =
            acknowledged_execution_state(&project_id, &mission_id);
        let stale_pull = state
            .pull_request(&stale_selection)
            .expect("initial command transport pull");

        assert_eq!(
            state
                .reconcile_selection(None)
                .expect("leave selected Mission"),
            DesktopRuntimeSelectionChange::Untracked
        );
        assert_eq!(
            state.current_selection_for_command(&stale_identity),
            Some(stale_selection.clone())
        );
        assert!(state.pull_request(&stale_selection).is_some());
        assert_eq!(
            state.request_stop_for_selection(None),
            DesktopRuntimeStopDisposition::ScopeMismatch
        );
        let reselected = state
            .reconcile_selection(Some((&project_id, &mission_id)))
            .expect("reselect retained handle");
        let DesktopRuntimeSelectionChange::Selected(reselected) = reselected else {
            panic!("retained exact handle must produce a new selection epoch");
        };
        assert!(reselected.epoch > stale_selection.epoch);
        assert_eq!(
            state.current_selection_for_command(&stale_identity),
            Some(reselected.clone())
        );
        let stale_delivery = stale_pull
            .into_delivery(awaiting_turn_batch(&handle))
            .expect("stale delivery");
        assert_eq!(
            state
                .apply_delivery(&stale_delivery)
                .expect("old epoch is ignored"),
            DesktopRuntimeReducerEffect::IgnoredStale
        );
        assert_eq!(
            state
                .finish_runtime(&stale_identity, &stale_selection)
                .expect("old epoch completion is ignored"),
            DesktopRuntimeCompletionDisposition::IgnoredStale
        );
        assert!(state.command_slot.has_active_command());
        assert!(state.active_paint.is_some());
        let reselected_pull = state
            .pull_request(&reselected)
            .expect("same-process reselected exact pull");
        assert_eq!(reselected_pull.handle(), &handle);
        assert!(
            state
                .mark_runtime_returned(&stale_identity)
                .expect("record stale Runtime return")
        );
        let delivery = reselected_pull
            .into_delivery(awaiting_turn_batch(&handle))
            .expect("reselected delivery");
        state
            .apply_delivery(&delivery)
            .expect("final reselected pull");
        assert!(state.completion_ready(&stale_identity));
        assert!(matches!(
            state
                .finish_runtime(&stale_identity, &reselected)
                .expect("real caller completes current transport selection"),
            DesktopRuntimeCompletionDisposition::Accepted(_)
        ));
        assert!(
            state
                .current_selection_for_command(&stale_identity)
                .is_none()
        );
        assert!(!state.command_slot.has_active_command());
        assert!(state.active_paint.is_none());
        assert_eq!(
            state
                .apply_delivery(&stale_delivery)
                .expect("old epoch remains stale after completion"),
            DesktopRuntimeReducerEffect::IgnoredStale
        );
        assert_eq!(
            state.poll_disposition(&reselected),
            DesktopRuntimePollDisposition::AwaitingWithoutRuntime
        );
    }

    #[test]
    fn offscreen_selection_keeps_exact_transport_until_final_pull_without_ui_acceptance() {
        let project_id = ProjectId::from("project-offscreen");
        let mission_id = MissionId::from("mission-offscreen");
        let (mut state, handle, command_selection, command_identity) =
            acknowledged_execution_state(&project_id, &mission_id);
        let other_project = ProjectId::from("project-other");
        let other_mission = MissionId::from("mission-other");

        assert_eq!(
            state
                .reconcile_selection(None)
                .expect("deselect active Mission"),
            DesktopRuntimeSelectionChange::Untracked
        );
        assert_eq!(
            state.current_selection_for_command(&command_identity),
            Some(command_selection.clone())
        );
        assert!(!state.selection_is_visible(&command_selection));
        assert_eq!(
            state
                .reconcile_selection(Some((&other_project, &other_mission)))
                .expect("select unrelated scope"),
            DesktopRuntimeSelectionChange::Untracked
        );
        assert!(state.paint_view(&project_id, &mission_id).is_none());
        assert_eq!(
            state.current_selection_for_command(&command_identity),
            Some(command_selection.clone())
        );
        assert!(
            state
                .mark_runtime_returned(&command_identity)
                .expect("record Runtime return")
        );
        assert!(!state.completion_ready(&command_identity));

        let final_pull = state
            .pull_request(&command_selection)
            .expect("offscreen exact command pull")
            .into_delivery(awaiting_turn_batch(&handle))
            .expect("offscreen delivery");
        assert_eq!(
            state
                .apply_delivery(&final_pull)
                .expect("observe offscreen final pull"),
            DesktopRuntimeReducerEffect::Duplicate
        );
        assert!(state.completion_ready(&command_identity));
        assert_eq!(
            state
                .finish_runtime(&command_identity, &command_selection)
                .expect("release offscreen command after durable evidence"),
            DesktopRuntimeCompletionDisposition::IgnoredStale
        );
        assert!(
            state
                .current_selection_for_command(&command_identity)
                .is_none()
        );
        assert!(!state.command_slot.has_active_command());
        assert!(state.active_paint.is_none());
        assert!(state.paint_view(&project_id, &mission_id).is_none());
    }

    #[test]
    fn execution_paint_stream_is_ephemeral_and_debug_redacts_private_text() {
        let project_id = ProjectId::from("project-stream");
        let mission_id = MissionId::from("mission-stream");
        let private = "private execution-time paint body";
        let handle = catalog_handle(project_id.as_str(), mission_id.as_str(), 'a');
        let mut state = DesktopRuntimeExecutionPaintState::default();
        let commit = state
            .commit_catalog_start(handle)
            .expect("prepare first paint");
        let launch = state
            .acknowledge_rendered_paint(&commit)
            .expect("ack rendered paint");
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
                u64::try_from(private.len()).expect("private length"),
            )],
            false,
        );
        let delivery = state
            .pull_request(launch.selection())
            .expect("pull request")
            .into_delivery(batch)
            .expect("integrity checked delivery");
        state.apply_delivery(&delivery).expect("apply Reset");

        let view = state
            .paint_view(&project_id, &mission_id)
            .expect("render view");
        let stream = view.stream().expect("stream projection");
        assert_eq!(stream.items[0].text, private);
        assert_eq!(stream.delta_count, 1);
        let debug = format!("{state:?} {view:?}");
        assert!(!debug.contains(private));
        assert!(!debug.contains(&digest('a')));
        assert!(!debug.contains(&digest('d')));
    }

    #[test]
    fn running_caught_up_waits_for_late_delta_and_terminal_ack() {
        let project_id = ProjectId::from("project-late-delta");
        let mission_id = MissionId::from("mission-late-delta");
        let (mut state, _handle, selection, identity) =
            acknowledged_execution_state(&project_id, &mission_id);

        let reset = state
            .pull_request(&selection)
            .expect("initial pull")
            .into_delivery(reset_running_final_hello())
            .expect("running Reset");
        state.apply_delivery(&reset).expect("apply running Reset");
        let running_caught_up = state
            .pull_request(&selection)
            .expect("running ack pull")
            .into_delivery(
                RuntimeBatchFixture {
                    source_last_sequence: Some(1),
                    cursor_after_sequence: Some(1),
                    ..RuntimeBatchFixture::running()
                }
                .caught_up(),
            )
            .expect("running CaughtUp");
        state
            .apply_delivery(&running_caught_up)
            .expect("apply running CaughtUp");
        let caught_up_view = state
            .paint_view(&project_id, &mission_id)
            .expect("caught-up stream paint view");
        assert!(caught_up_view.stream().is_some());
        assert!(caught_up_view.transport_caught_up());
        assert_eq!(
            state.poll_disposition(&selection),
            DesktopRuntimePollDisposition::WaitForRuntime
        );

        let late_append = state
            .pull_request(&selection)
            .expect("late delta pull")
            .into_delivery(append_page_two('d'))
            .expect("late Append");
        state
            .apply_delivery(&late_append)
            .expect("apply late delta");
        assert!(
            !state
                .paint_view(&project_id, &mission_id)
                .expect("reopened stream paint view")
                .transport_caught_up()
        );
        assert_eq!(
            state.poll_disposition(&selection),
            DesktopRuntimePollDisposition::PullNow
        );
        assert!(
            state
                .mark_runtime_returned(&identity)
                .expect("record Runtime completion")
        );
        apply_terminal_two_delta_turn(&mut state, &selection, RuntimeTurnStatus::Completed, 5, 'e');
        assert_eq!(
            state.poll_disposition(&selection),
            DesktopRuntimePollDisposition::ReadyToFinalize
        );
        assert!(state.completion_ready(&identity));
    }

    #[test]
    fn runtime_return_before_first_pull_requires_terminal_reset_and_caught_up() {
        let project_id = ProjectId::from("project-fast-runtime");
        let mission_id = MissionId::from("mission-fast-runtime");
        let (mut state, _handle, selection, identity) =
            acknowledged_execution_state(&project_id, &mission_id);
        assert!(
            state
                .mark_runtime_returned(&identity)
                .expect("record fast Runtime return")
        );
        assert_eq!(
            state.poll_disposition(&selection),
            DesktopRuntimePollDisposition::WaitAfterRuntime
        );

        let terminal_reset = RuntimeBatchFixture {
            revision: 2,
            status: RuntimeTurnStatus::Completed,
            source_last_sequence: Some(1),
            cursor_after_sequence: Some(1),
            ..RuntimeBatchFixture::running()
        }
        .page("reset", &[delta_value(1, 1, 'd', "done", 4)], false);
        let delivery = state
            .pull_request(&selection)
            .expect("first post-return pull")
            .into_delivery(terminal_reset)
            .expect("terminal Reset");
        state
            .apply_delivery(&delivery)
            .expect("apply terminal Reset");
        assert!(!state.completion_ready(&identity));
        let terminal_ack = state
            .pull_request(&selection)
            .expect("terminal acknowledgement pull")
            .into_delivery(
                RuntimeBatchFixture {
                    revision: 2,
                    status: RuntimeTurnStatus::Completed,
                    source_last_sequence: Some(1),
                    cursor_after_sequence: Some(1),
                    ..RuntimeBatchFixture::running()
                }
                .caught_up(),
            )
            .expect("terminal CaughtUp");
        state
            .apply_delivery(&terminal_ack)
            .expect("apply terminal acknowledgement");
        assert!(state.completion_ready(&identity));
    }

    #[test]
    fn stale_or_stopped_render_ack_never_produces_runtime_authority() {
        let project_id = ProjectId::from("project-ack-fence");
        let mission_id = MissionId::from("mission-ack-fence");
        let mut stale = DesktopRuntimeExecutionPaintState::default();
        let stale_commit = stale
            .commit_catalog_start(catalog_handle(
                project_id.as_str(),
                mission_id.as_str(),
                'a',
            ))
            .expect("prepare stale paint");
        stale
            .reconcile_selection(None)
            .expect("selection changed before render ack");
        assert!(matches!(
            stale.acknowledge_rendered_paint(&stale_commit),
            Err(RuntimeSubscriptionError::PaintAcknowledgementMismatch)
        ));
        assert!(stale.pending_paint_commit().is_none());

        let mut stopped = DesktopRuntimeExecutionPaintState::default();
        let stopped_commit = stopped
            .commit_catalog_start(catalog_handle(
                project_id.as_str(),
                mission_id.as_str(),
                'b',
            ))
            .expect("prepare stopped paint");
        assert_eq!(
            stopped.request_stop_for_selection(Some((&project_id, &mission_id))),
            DesktopRuntimeStopDisposition::Requested
        );
        assert!(matches!(
            stopped.acknowledge_rendered_paint(&stopped_commit),
            Err(RuntimeSubscriptionError::PaintStoppedBeforeRuntime)
        ));
        assert!(stopped.pending_paint_commit().is_none());
        assert!(!stopped.stop_available_for_selection(Some((&project_id, &mission_id))));
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
