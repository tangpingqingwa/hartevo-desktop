//! Second-layer restart handshake for a durable plugin session.
//!
//! The first-layer [`crate::PluginSessionService`] records the plugin
//! invocation and its cursor.  This module records the one consumer wake that
//! is allowed to resume it: a scoped runtime lease, a recovery revision, and a
//! typed completion receipt.  A prepared wake is replayable after a crash, but
//! it never authorizes a second wake or a different lease to commit the same
//! cursor.

use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{PluginSessionFence, PluginSessionLifecycle, PluginSessionService};

fn digest(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    format!("{:x}", hasher.finalize())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
pub enum PluginSessionResumeError {
    #[error("plugin resume scope or lease is invalid")]
    InvalidFence,
    #[error("plugin resume lease is expired or no longer current")]
    LeaseLost,
    #[error("plugin resume lease has expired")]
    Expired,
    #[error("plugin session is no longer mounted")]
    LifecycleUnavailable,
    #[error("plugin session invocation is already terminal")]
    AlreadyTerminal,
    #[error("plugin resume history is malformed")]
    InvalidHistory,
    #[error("plugin resume cursor or recovery revision is stale")]
    CursorDrift,
    #[error("plugin resume has no prepared wake")]
    MissingPreparation,
    #[error("plugin resume outcome conflicts with durable history")]
    OutcomeConflict,
    #[error(transparent)]
    Session(#[from] crate::PluginSessionError),
}

#[derive(Clone, Eq, PartialEq)]
pub struct PluginSessionRuntimeLeaseInput {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub lease_id: String,
    pub owner_digest: String,
    pub lease_token_digest: String,
    pub generation: u64,
    pub revision: u64,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl fmt::Debug for PluginSessionRuntimeLeaseInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionRuntimeLeaseInput")
            .field("scope_present", &true)
            .field("lease_present", &true)
            .field("owner_present", &true)
            .field("token_present", &true)
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PluginSessionRuntimeLease {
    tenant_id: TenantId,
    project_id: ProjectId,
    mission_id: MissionId,
    lease_id: String,
    owner_digest: String,
    lease_token_digest: String,
    generation: u64,
    revision: u64,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl fmt::Debug for PluginSessionRuntimeLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionRuntimeLease")
            .field("scope_present", &true)
            .field("lease_present", &true)
            .field("owner_present", &true)
            .field("token_present", &true)
            .field("generation", &self.generation)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

impl PluginSessionRuntimeLease {
    pub fn new(input: PluginSessionRuntimeLeaseInput) -> Result<Self, PluginSessionResumeError> {
        let lease = Self {
            tenant_id: input.tenant_id,
            project_id: input.project_id,
            mission_id: input.mission_id,
            lease_id: input.lease_id,
            owner_digest: input.owner_digest,
            lease_token_digest: input.lease_token_digest,
            generation: input.generation,
            revision: input.revision,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
        };
        lease.validate_shape()?;
        Ok(lease)
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

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn owner_digest(&self) -> &str {
        &self.owner_digest
    }

    pub fn lease_token_digest(&self) -> &str {
        &self.lease_token_digest
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    fn validate_shape(&self) -> Result<(), PluginSessionResumeError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.lease_id.trim().is_empty()
            || !valid_digest(&self.owner_digest)
            || !valid_digest(&self.lease_token_digest)
            || self.generation == 0
            || self.revision == 0
            || self.expires_at <= self.issued_at
        {
            return Err(PluginSessionResumeError::InvalidFence);
        }
        Ok(())
    }

    fn validate_for(
        &self,
        fence: &PluginSessionResumeFence,
        now: DateTime<Utc>,
    ) -> Result<(), PluginSessionResumeError> {
        self.validate_shape()?;
        if self.tenant_id != *fence.session_fence.tenant_id()
            || self.project_id != *fence.session_fence.project_id()
            || self.mission_id != *fence.session_fence.mission_id()
            || now < self.issued_at
        {
            return Err(PluginSessionResumeError::InvalidFence);
        }
        if now >= self.expires_at {
            return Err(PluginSessionResumeError::Expired);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PluginSessionResumeFence {
    session_fence: PluginSessionFence,
    session_event_sequence: u64,
    recovery_revision: u64,
    lease: PluginSessionRuntimeLease,
}

impl fmt::Debug for PluginSessionResumeFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionResumeFence")
            .field("session_present", &true)
            .field("session_event_sequence", &self.session_event_sequence)
            .field("recovery_revision", &self.recovery_revision)
            .field("lease", &self.lease)
            .finish_non_exhaustive()
    }
}

impl PluginSessionResumeFence {
    pub fn new(
        session_fence: PluginSessionFence,
        session_event_sequence: u64,
        recovery_revision: u64,
        lease: PluginSessionRuntimeLease,
    ) -> Result<Self, PluginSessionResumeError> {
        let fence = Self {
            session_fence,
            session_event_sequence,
            recovery_revision,
            lease,
        };
        fence.validate_shape()?;
        Ok(fence)
    }

    pub fn session_fence(&self) -> &PluginSessionFence {
        &self.session_fence
    }

    pub fn session_event_sequence(&self) -> u64 {
        self.session_event_sequence
    }

    pub fn recovery_revision(&self) -> u64 {
        self.recovery_revision
    }

    pub fn lease(&self) -> &PluginSessionRuntimeLease {
        &self.lease
    }

    fn validate_shape(&self) -> Result<(), PluginSessionResumeError> {
        PluginSessionService::new(self.session_fence.clone())?;
        if self.session_event_sequence == 0 || self.recovery_revision == 0 {
            return Err(PluginSessionResumeError::InvalidFence);
        }
        if self.lease.project_id() != self.session_fence.project_id()
            || self.lease.mission_id() != self.session_fence.mission_id()
            || self.lease.tenant_id() != self.session_fence.tenant_id()
        {
            return Err(PluginSessionResumeError::InvalidFence);
        }
        Ok(())
    }

    fn validate_for(&self, now: DateTime<Utc>) -> Result<(), PluginSessionResumeError> {
        self.validate_shape()?;
        self.lease.validate_for(self, now)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionResumeEventKind {
    LeaseAcquired,
    Completed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionResumeEventStatus {
    Leased,
    Completed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionResumeCancelReason {
    Revoked,
    Unmounted,
    Terminal,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct PluginSessionResumeEvent {
    sequence: u64,
    kind: PluginSessionResumeEventKind,
    status: PluginSessionResumeEventStatus,
    fence: PluginSessionResumeFence,
    cursor: u64,
    outcome_digest: Option<String>,
    cancel_reason: Option<PluginSessionResumeCancelReason>,
    recorded_at: String,
}

impl fmt::Debug for PluginSessionResumeEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionResumeEvent")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("cursor", &self.cursor)
            .field("outcome_present", &self.outcome_digest.is_some())
            .finish_non_exhaustive()
    }
}

impl PluginSessionResumeEvent {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn kind(&self) -> PluginSessionResumeEventKind {
        self.kind
    }

    pub fn status(&self) -> PluginSessionResumeEventStatus {
        self.status
    }

    pub fn fence(&self) -> &PluginSessionResumeFence {
        &self.fence
    }

    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn outcome_digest(&self) -> Option<&str> {
        self.outcome_digest.as_deref()
    }

    pub fn cancel_reason(&self) -> Option<PluginSessionResumeCancelReason> {
        self.cancel_reason
    }

    pub fn recorded_at(&self) -> &str {
        &self.recorded_at
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum PluginSessionResumeReceipt {
    LeaseAcquired {
        event_sequence: u64,
        fence: PluginSessionResumeFence,
        cursor: u64,
    },
    ReplayRequired {
        event_sequence: u64,
        fence: PluginSessionResumeFence,
        cursor: u64,
    },
    AlreadyCompleted {
        event_sequence: u64,
        fence: PluginSessionResumeFence,
        cursor: u64,
        outcome_digest: String,
    },
    Completed {
        event_sequence: u64,
        fence: PluginSessionResumeFence,
        cursor: u64,
        outcome_digest: String,
    },
    Cancelled {
        event_sequence: u64,
        fence: PluginSessionResumeFence,
        reason: PluginSessionResumeCancelReason,
    },
}

impl fmt::Debug for PluginSessionResumeReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::LeaseAcquired { .. } => "lease_acquired",
            Self::ReplayRequired { .. } => "replay_required",
            Self::AlreadyCompleted { .. } => "already_completed",
            Self::Completed { .. } => "completed",
            Self::Cancelled { .. } => "cancelled",
        };
        formatter
            .debug_struct("PluginSessionResumeReceipt")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

pub struct PluginSessionResumeService {
    fence: PluginSessionResumeFence,
    lifecycle: PluginSessionLifecycle,
    next_sequence: u64,
    events: Vec<PluginSessionResumeEvent>,
}

impl fmt::Debug for PluginSessionResumeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginSessionResumeService")
            .field("lifecycle", &self.lifecycle)
            .field("event_count", &self.events.len())
            .finish_non_exhaustive()
    }
}

impl PluginSessionResumeService {
    pub fn new(
        fence: PluginSessionResumeFence,
        lifecycle: PluginSessionLifecycle,
    ) -> Result<Self, PluginSessionResumeError> {
        fence.validate_shape()?;
        Ok(Self {
            fence,
            lifecycle,
            next_sequence: 1,
            events: Vec::new(),
        })
    }

    pub fn from_events(
        fence: PluginSessionResumeFence,
        lifecycle: PluginSessionLifecycle,
        events: Vec<PluginSessionResumeEvent>,
    ) -> Result<Self, PluginSessionResumeError> {
        let mut service = Self::new(fence, lifecycle)?;
        service.events = events;
        service.next_sequence = service
            .events
            .last()
            .and_then(|event| event.sequence.checked_add(1))
            .ok_or(PluginSessionResumeError::InvalidHistory)
            .or_else(|error| {
                if service.events.is_empty() {
                    Ok(1)
                } else {
                    Err(error)
                }
            })?;
        service.validate_history()?;
        Ok(service)
    }

    pub fn events(&self) -> &[PluginSessionResumeEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    fn validate_history(&self) -> Result<(), PluginSessionResumeError> {
        self.fence.validate_shape()?;
        let mut expected = 1u64;
        for event in &self.events {
            if event.sequence != expected
                || event.fence != self.fence
                || event.cursor != self.fence.session_fence.cursor()
                || event.recorded_at.trim().is_empty()
            {
                return Err(PluginSessionResumeError::InvalidHistory);
            }
            match (
                event.kind,
                event.status,
                &event.outcome_digest,
                event.cancel_reason,
            ) {
                (
                    PluginSessionResumeEventKind::LeaseAcquired,
                    PluginSessionResumeEventStatus::Leased,
                    None,
                    None,
                )
                | (
                    PluginSessionResumeEventKind::Cancelled,
                    PluginSessionResumeEventStatus::Cancelled,
                    None,
                    Some(_),
                ) => {}
                (
                    PluginSessionResumeEventKind::Completed,
                    PluginSessionResumeEventStatus::Completed,
                    Some(digest),
                    None,
                ) if valid_digest(digest) => {}
                _ => return Err(PluginSessionResumeError::InvalidHistory),
            }
            expected = expected
                .checked_add(1)
                .ok_or(PluginSessionResumeError::InvalidHistory)?;
        }
        Ok(())
    }

    fn latest(&self) -> Option<&PluginSessionResumeEvent> {
        self.events.last()
    }

    fn validate_at(&self, now: DateTime<Utc>) -> Result<(), PluginSessionResumeError> {
        self.validate_history()?;
        self.fence.validate_for(now)
    }

    fn append(
        &mut self,
        kind: PluginSessionResumeEventKind,
        status: PluginSessionResumeEventStatus,
        outcome_digest: Option<String>,
        cancel_reason: Option<PluginSessionResumeCancelReason>,
        recorded_at: DateTime<Utc>,
    ) -> Result<PluginSessionResumeEvent, PluginSessionResumeError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(PluginSessionResumeError::InvalidHistory)?;
        let event = PluginSessionResumeEvent {
            sequence,
            kind,
            status,
            fence: self.fence.clone(),
            cursor: self.fence.session_fence.cursor(),
            outcome_digest,
            cancel_reason,
            recorded_at: recorded_at.to_rfc3339(),
        };
        self.events.push(event.clone());
        self.validate_history()?;
        Ok(event)
    }

    pub fn resume(
        &mut self,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionResumeReceipt, PluginSessionResumeError> {
        self.validate_at(now)?;
        if self.lifecycle != PluginSessionLifecycle::Mounted {
            if let Some(event) = self.latest() {
                match event.status {
                    PluginSessionResumeEventStatus::Completed => {
                        let outcome_digest = event
                            .outcome_digest
                            .clone()
                            .ok_or(PluginSessionResumeError::InvalidHistory)?;
                        return Ok(PluginSessionResumeReceipt::AlreadyCompleted {
                            event_sequence: event.sequence,
                            fence: self.fence.clone(),
                            cursor: event.cursor,
                            outcome_digest,
                        });
                    }
                    PluginSessionResumeEventStatus::Cancelled => {
                        let reason = event
                            .cancel_reason
                            .ok_or(PluginSessionResumeError::InvalidHistory)?;
                        return Ok(PluginSessionResumeReceipt::Cancelled {
                            event_sequence: event.sequence,
                            fence: self.fence.clone(),
                            reason,
                        });
                    }
                    PluginSessionResumeEventStatus::Leased => {}
                }
            }
            let reason = cancellation_reason(self.lifecycle);
            let event = self.append(
                PluginSessionResumeEventKind::Cancelled,
                PluginSessionResumeEventStatus::Cancelled,
                None,
                Some(reason),
                now,
            )?;
            return Ok(PluginSessionResumeReceipt::Cancelled {
                event_sequence: event.sequence,
                fence: self.fence.clone(),
                reason,
            });
        }
        if let Some(event) = self.latest() {
            return match event.status {
                PluginSessionResumeEventStatus::Leased => {
                    Ok(PluginSessionResumeReceipt::ReplayRequired {
                        event_sequence: event.sequence,
                        fence: self.fence.clone(),
                        cursor: event.cursor,
                    })
                }
                PluginSessionResumeEventStatus::Completed => {
                    let outcome_digest = event
                        .outcome_digest
                        .clone()
                        .ok_or(PluginSessionResumeError::InvalidHistory)?;
                    Ok(PluginSessionResumeReceipt::AlreadyCompleted {
                        event_sequence: event.sequence,
                        fence: self.fence.clone(),
                        cursor: event.cursor,
                        outcome_digest,
                    })
                }
                PluginSessionResumeEventStatus::Cancelled => {
                    let reason = event
                        .cancel_reason
                        .ok_or(PluginSessionResumeError::InvalidHistory)?;
                    Ok(PluginSessionResumeReceipt::Cancelled {
                        event_sequence: event.sequence,
                        fence: self.fence.clone(),
                        reason,
                    })
                }
            };
        }
        let event = self.append(
            PluginSessionResumeEventKind::LeaseAcquired,
            PluginSessionResumeEventStatus::Leased,
            None,
            None,
            now,
        )?;
        Ok(PluginSessionResumeReceipt::LeaseAcquired {
            event_sequence: event.sequence,
            fence: self.fence.clone(),
            cursor: event.cursor,
        })
    }

    pub fn complete(
        &mut self,
        outcome_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionResumeReceipt, PluginSessionResumeError> {
        self.validate_at(now)?;
        if !valid_digest(outcome_digest) {
            return Err(PluginSessionResumeError::OutcomeConflict);
        }
        let Some(event) = self.latest() else {
            return Err(PluginSessionResumeError::MissingPreparation);
        };
        match event.status {
            PluginSessionResumeEventStatus::Completed => {
                let existing = event
                    .outcome_digest
                    .as_deref()
                    .ok_or(PluginSessionResumeError::InvalidHistory)?;
                if existing != outcome_digest {
                    return Err(PluginSessionResumeError::OutcomeConflict);
                }
                Ok(PluginSessionResumeReceipt::AlreadyCompleted {
                    event_sequence: event.sequence,
                    fence: self.fence.clone(),
                    cursor: event.cursor,
                    outcome_digest: existing.to_owned(),
                })
            }
            PluginSessionResumeEventStatus::Cancelled => {
                Err(PluginSessionResumeError::LifecycleUnavailable)
            }
            PluginSessionResumeEventStatus::Leased => {
                if self.lifecycle != PluginSessionLifecycle::Mounted {
                    return Err(PluginSessionResumeError::LifecycleUnavailable);
                }
                let event = self.append(
                    PluginSessionResumeEventKind::Completed,
                    PluginSessionResumeEventStatus::Completed,
                    Some(outcome_digest.to_owned()),
                    None,
                    now,
                )?;
                Ok(PluginSessionResumeReceipt::Completed {
                    event_sequence: event.sequence,
                    fence: self.fence.clone(),
                    cursor: event.cursor,
                    outcome_digest: outcome_digest.to_owned(),
                })
            }
        }
    }
}

fn cancellation_reason(lifecycle: PluginSessionLifecycle) -> PluginSessionResumeCancelReason {
    match lifecycle {
        PluginSessionLifecycle::Revoked => PluginSessionResumeCancelReason::Revoked,
        PluginSessionLifecycle::Unmounted => PluginSessionResumeCancelReason::Unmounted,
        PluginSessionLifecycle::Terminal | PluginSessionLifecycle::Mounted => {
            PluginSessionResumeCancelReason::Terminal
        }
    }
}

#[must_use]
pub fn plugin_resume_digest(value: &str) -> String {
    digest(value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PluginSessionDescriptor, PluginSessionPosition, PluginSessionScope};
    use chrono::TimeZone;

    fn session_fence(cursor: u64) -> PluginSessionFence {
        PluginSessionFence::new(
            PluginSessionScope::new(
                TenantId::from("tenant-resume"),
                ProjectId::from("project-resume"),
                MissionId::from("mission-resume"),
            ),
            PluginSessionDescriptor::new(
                "plugin.browser",
                "2.4.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            PluginSessionPosition::new("invocation-1", cursor, 4, 9),
        )
    }

    fn at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 14, 12, 0, 0)
            .single()
            .expect("time")
    }

    fn lease(fence: &PluginSessionFence, now: DateTime<Utc>) -> PluginSessionRuntimeLease {
        PluginSessionRuntimeLease::new(PluginSessionRuntimeLeaseInput {
            tenant_id: fence.tenant_id().clone(),
            project_id: fence.project_id().clone(),
            mission_id: fence.mission_id().clone(),
            lease_id: "lease-resume-1".into(),
            owner_digest: plugin_resume_digest("owner"),
            lease_token_digest: plugin_resume_digest("token"),
            generation: 8,
            revision: 3,
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        })
        .expect("lease")
    }

    #[test]
    fn crash_reopens_as_replay_and_completion_is_exactly_once() {
        let now = at();
        let base = session_fence(7);
        let resume_fence = PluginSessionResumeFence::new(base, 2, 1, lease(&session_fence(7), now))
            .expect("resume fence");
        let mut service =
            PluginSessionResumeService::new(resume_fence.clone(), PluginSessionLifecycle::Mounted)
                .expect("service");
        assert!(matches!(
            service.resume(now).expect("resume"),
            PluginSessionResumeReceipt::LeaseAcquired { .. }
        ));
        let history = service.events().to_vec();
        let mut reopened = PluginSessionResumeService::from_events(
            resume_fence.clone(),
            PluginSessionLifecycle::Mounted,
            history,
        )
        .expect("reopen");
        assert!(matches!(
            reopened.resume(now).expect("replay"),
            PluginSessionResumeReceipt::ReplayRequired { .. }
        ));
        let outcome = plugin_resume_digest("browser-result");
        assert!(matches!(
            reopened.complete(&outcome, now).expect("complete"),
            PluginSessionResumeReceipt::Completed { .. }
        ));
        assert!(matches!(
            reopened
                .complete(&outcome, now)
                .expect("idempotent complete"),
            PluginSessionResumeReceipt::AlreadyCompleted { .. }
        ));
        assert_eq!(reopened.events().len(), 2);
    }

    #[test]
    fn expired_or_drifted_lease_fails_before_a_resume_event() {
        let now = at();
        let base = session_fence(7);
        let expired = PluginSessionRuntimeLease::new(PluginSessionRuntimeLeaseInput {
            tenant_id: base.tenant_id().clone(),
            project_id: base.project_id().clone(),
            mission_id: base.mission_id().clone(),
            lease_id: "lease-expired".into(),
            owner_digest: plugin_resume_digest("owner"),
            lease_token_digest: plugin_resume_digest("token"),
            generation: 8,
            revision: 3,
            issued_at: now - chrono::Duration::minutes(5),
            expires_at: now - chrono::Duration::seconds(1),
        });
        let expired = expired.expect("expired lease shape");
        let expired_fence = PluginSessionResumeFence::new(base.clone(), 2, 1, expired)
            .expect("expired fence shape");
        let mut expired_service =
            PluginSessionResumeService::new(expired_fence, PluginSessionLifecycle::Mounted)
                .expect("expired service");
        assert!(matches!(
            expired_service.resume(now),
            Err(PluginSessionResumeError::Expired)
        ));
        assert!(expired_service.events().is_empty());
        let lease = lease(&base, now);
        let fence = PluginSessionResumeFence::new(base, 2, 1, lease).expect("fence");
        let mut service = PluginSessionResumeService::new(fence, PluginSessionLifecycle::Mounted)
            .expect("service");
        assert!(matches!(
            service.resume(now + chrono::Duration::minutes(6)),
            Err(PluginSessionResumeError::Expired)
        ));
        assert!(service.events().is_empty());
    }

    #[test]
    fn revoked_or_unmounted_lifecycle_cancels_without_replay() {
        let now = at();
        let base = session_fence(7);
        let fence =
            PluginSessionResumeFence::new(base.clone(), 2, 1, lease(&base, now)).expect("fence");
        let mut service = PluginSessionResumeService::new(fence, PluginSessionLifecycle::Unmounted)
            .expect("service");
        assert!(matches!(
            service.resume(now).expect("cancel"),
            PluginSessionResumeReceipt::Cancelled {
                reason: PluginSessionResumeCancelReason::Unmounted,
                ..
            }
        ));
        assert!(matches!(
            service.resume(now).expect("cancel replay"),
            PluginSessionResumeReceipt::Cancelled {
                reason: PluginSessionResumeCancelReason::Unmounted,
                ..
            }
        ));
        assert_eq!(service.events().len(), 1);

        let mounted_fence = PluginSessionResumeFence::new(base.clone(), 2, 1, lease(&base, now))
            .expect("mounted fence");
        let mut mounted =
            PluginSessionResumeService::new(mounted_fence.clone(), PluginSessionLifecycle::Mounted)
                .expect("mounted service");
        mounted.resume(now).expect("acquire before unmount");
        let mut reopened = PluginSessionResumeService::from_events(
            mounted_fence,
            PluginSessionLifecycle::Unmounted,
            mounted.events().to_vec(),
        )
        .expect("reopen after unmount");
        assert!(matches!(
            reopened.resume(now).expect("cancel leased wake"),
            PluginSessionResumeReceipt::Cancelled {
                reason: PluginSessionResumeCancelReason::Unmounted,
                ..
            }
        ));
        assert_eq!(reopened.events().len(), 2);
    }
}
