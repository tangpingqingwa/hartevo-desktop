use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::repair::{
    ConnectionRepairError, ConnectionRepairPlugin, ConnectionRepairReason,
    ConnectionRepairResultStatus, ConnectionRepairScope,
};
use crate::is_sha256;

/// Durable lifecycle events contain only typed scope metadata and digests.
/// They never contain objectives, callback data, SecretReferences, tokens, or
/// provider payloads.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionRepairEventKind {
    SessionOpened,
    ProbeSucceeded,
    ProbeFailed,
    SessionCompleted,
    SessionRevoked,
    SessionExpired,
    SessionCrashed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionRepairEvent {
    sequence: u64,
    kind: ConnectionRepairEventKind,
    scope: ConnectionRepairScope,
    connection_id: String,
    plugin: ConnectionRepairPlugin,
    request_digest: String,
    session_digest: String,
    invocation_digest: String,
    reason: ConnectionRepairReason,
    status: Option<ConnectionRepairResultStatus>,
    session_revision: u64,
    auth_revision: Option<u64>,
    probe_revision: Option<u64>,
    observed_at: DateTime<Utc>,
}

impl ConnectionRepairEvent {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sequence: u64,
        kind: ConnectionRepairEventKind,
        scope: ConnectionRepairScope,
        connection_id: String,
        plugin: ConnectionRepairPlugin,
        request_digest: String,
        session_digest: String,
        invocation_digest: String,
        reason: ConnectionRepairReason,
        status: Option<ConnectionRepairResultStatus>,
        session_revision: u64,
        auth_revision: Option<u64>,
        probe_revision: Option<u64>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, ConnectionRepairError> {
        let event = Self {
            sequence,
            kind,
            scope,
            connection_id,
            plugin,
            request_digest,
            session_digest,
            invocation_digest,
            reason,
            status,
            session_revision,
            auth_revision,
            probe_revision,
            observed_at,
        };
        event.validate()?;
        Ok(event)
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn kind(&self) -> &ConnectionRepairEventKind {
        &self.kind
    }

    pub const fn scope(&self) -> &ConnectionRepairScope {
        &self.scope
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub const fn plugin(&self) -> &ConnectionRepairPlugin {
        &self.plugin
    }

    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn session_digest(&self) -> &str {
        &self.session_digest
    }

    pub fn invocation_digest(&self) -> &str {
        &self.invocation_digest
    }

    pub const fn reason(&self) -> ConnectionRepairReason {
        self.reason
    }

    pub const fn status(&self) -> Option<ConnectionRepairResultStatus> {
        self.status
    }

    pub const fn session_revision(&self) -> u64 {
        self.session_revision
    }

    pub const fn auth_revision(&self) -> Option<u64> {
        self.auth_revision
    }

    pub const fn probe_revision(&self) -> Option<u64> {
        self.probe_revision
    }

    pub const fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub(crate) fn validate(&self) -> Result<(), ConnectionRepairError> {
        if self.sequence == 0
            || self.connection_id.trim().is_empty()
            || !is_sha256(&self.request_digest)
            || !is_sha256(&self.session_digest)
            || !is_sha256(&self.invocation_digest)
            || self.session_revision == 0
            || self.auth_revision.is_some_and(|revision| revision == 0)
            || self.probe_revision.is_some_and(|revision| revision == 0)
            || (matches!(self.kind, ConnectionRepairEventKind::ProbeSucceeded)
                && self.status != Some(ConnectionRepairResultStatus::Verified))
        {
            return Err(ConnectionRepairError::InvalidEvent);
        }
        Ok(())
    }
}

/// Storage boundary for append-only repair events. Implementations may be
/// SQLCipher-backed later; the service only sees this content-free contract.
pub trait ConnectionRepairEventSink {
    fn append(&mut self, event: ConnectionRepairEvent) -> Result<(), ConnectionRepairError>;
}

/// Deterministic append-only event sink used by the connection-center slice
/// and its scoped tests. The events are serializable and contain no secret
/// material, so a durable owner can persist the same contract without giving
/// the repair service Store or keyring authority.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectionRepairEventLog {
    events: Vec<ConnectionRepairEvent>,
}

impl ConnectionRepairEventLog {
    pub fn events(&self) -> &[ConnectionRepairEvent] {
        &self.events
    }

    pub fn validate_chain(&self) -> Result<(), ConnectionRepairError> {
        for (index, event) in self.events.iter().enumerate() {
            event.validate()?;
            if event.sequence != index as u64 + 1 {
                return Err(ConnectionRepairError::InvalidEvent);
            }
        }
        Ok(())
    }
}

impl ConnectionRepairEventSink for ConnectionRepairEventLog {
    fn append(&mut self, event: ConnectionRepairEvent) -> Result<(), ConnectionRepairError> {
        event.validate()?;
        let expected_sequence = self.events.len() as u64 + 1;
        if event.sequence != expected_sequence {
            return Err(ConnectionRepairError::EventSequenceConflict);
        }
        self.events.push(event);
        Ok(())
    }
}
