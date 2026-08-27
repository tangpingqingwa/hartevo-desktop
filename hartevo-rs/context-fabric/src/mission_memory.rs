//! A scoped Mission Memory plugin seam for the Agent Plane.
//!
//! This module deliberately stops at the Context Fabric boundary. A provider
//! receives already durable Mission facts and can only return bounded,
//! digest-bound references. The service owns lifecycle and generation fencing;
//! the durable log owns persistence. There is no Store, keyring, Browser, or
//! Effect authority here, and no model-visible projection can be returned
//! before its exact content-free result has been appended to the durable log.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{ContextDataClass, FactId, Mission, MissionId, ProjectId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const MISSION_MEMORY_SCHEMA_VERSION: &str = "hartevo.mission-memory/v1";

const MAX_CONSUMER_ID_BYTES: usize = 256;
const MAX_FACT_ID_BYTES: usize = 256;
const MAX_FACT_REVISION: u64 = u64::MAX - 1;
const MAX_HANDLE_ID_BYTES: usize = 256;
const MAX_MEMORY_ITEMS: usize = 512;
const MAX_PROVIDER_ID_BYTES: usize = 256;
const MAX_REFERENCE_BYTES: usize = 2_048;
const MAX_REQUEST_ID_BYTES: usize = 256;

#[derive(Debug, Error)]
pub enum MissionMemoryError {
    #[error("mission memory scope is invalid")]
    InvalidScope,
    #[error("mission memory fact is invalid")]
    InvalidFact,
    #[error("mission memory read request is invalid")]
    InvalidRequest,
    #[error("mission memory provider handle is invalid")]
    InvalidProviderHandle,
    #[error("mission memory provider output is invalid or outside the requested scope")]
    InvalidProviderOutput,
    #[error("mission memory continuation is invalid")]
    InvalidContinuation,
    #[error("mission memory session is not mounted")]
    NotMounted,
    #[error("mission memory session scope does not match the mounted Mission")]
    ScopeMismatch,
    #[error("mission memory session belongs to an obsolete generation")]
    StaleGeneration,
    #[error("mission memory provider does not match the mounted provider")]
    ProviderMismatch,
    #[error("mission memory provider is already mounted")]
    AlreadyMounted,
    #[error("mission memory fact revision is not the next durable revision")]
    RevisionMismatch,
    #[error("mission memory fact id is already bound to different content")]
    FactConflict,
    #[error("mission memory durable log is malformed or has drifted")]
    InvalidEventLog,
    #[error("mission memory durable event is invalid")]
    InvalidEvent,
    #[error("mission memory durable event sequence is not append-only")]
    EventSequence,
    #[error("mission memory durable log failed: {0}")]
    DurableLog(String),
    #[error("mission memory provider failed: {0}")]
    Provider(String),
    #[error("mission memory consumer rejected a durable result: {0}")]
    Consumer(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub mission_id: MissionId,
    pub mission_revision: u64,
}

impl MissionMemoryScope {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        project_revision: u64,
        mission_id: MissionId,
        mission_revision: u64,
    ) -> Result<Self, MissionMemoryError> {
        let scope = Self {
            tenant_id,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn from_mission(
        mission: &Mission,
        project_revision: u64,
    ) -> Result<Self, MissionMemoryError> {
        Self::new(
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            project_revision,
            mission.id.clone(),
            mission.revision,
        )
    }

    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.project_revision == 0
            || self.mission_revision == 0
        {
            return Err(MissionMemoryError::InvalidScope);
        }
        Ok(())
    }
}

/// A Mission fact already committed to the durable Mission event spine.
/// Memory stores only the typed reference and digest, never the fact body.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryFact {
    pub fact_id: FactId,
    pub scope: MissionMemoryScope,
    pub fact_revision: u64,
    pub source_event_id: String,
    pub payload_ref: String,
    pub payload_digest: String,
    pub classification: ContextDataClass,
    pub recorded_at: DateTime<Utc>,
}

impl MissionMemoryFact {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        self.scope.validate()?;
        if self.fact_id.as_str().trim().is_empty()
            || self.fact_id.as_str().len() > MAX_FACT_ID_BYTES
            || self.fact_revision == 0
            || self.fact_revision > MAX_FACT_REVISION
            || !bounded_text(&self.source_event_id, MAX_REFERENCE_BYTES)
            || !is_memory_reference(&self.payload_ref)
            || !is_lower_sha256(&self.payload_digest)
        {
            return Err(MissionMemoryError::InvalidFact);
        }
        Ok(())
    }

    fn item(&self) -> MissionMemoryItem {
        MissionMemoryItem {
            fact_id: self.fact_id.clone(),
            fact_revision: self.fact_revision,
            payload_ref: self.payload_ref.clone(),
            payload_digest: self.payload_digest.clone(),
            classification: self.classification,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryItem {
    pub fact_id: FactId,
    pub fact_revision: u64,
    pub payload_ref: String,
    pub payload_digest: String,
    pub classification: ContextDataClass,
}

impl MissionMemoryItem {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        if self.fact_id.as_str().trim().is_empty()
            || self.fact_id.as_str().len() > MAX_FACT_ID_BYTES
            || self.fact_revision == 0
            || self.fact_revision > MAX_FACT_REVISION
            || !is_memory_reference(&self.payload_ref)
            || !is_lower_sha256(&self.payload_digest)
        {
            return Err(MissionMemoryError::InvalidProviderOutput);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryWorkingSet {
    pub scope: MissionMemoryScope,
    pub generation: u64,
    pub revision: u64,
    pub items: Vec<MissionMemoryItem>,
}

impl MissionMemoryWorkingSet {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        self.scope.validate()?;
        if self.generation == 0 || self.revision == 0 || self.items.len() > MAX_MEMORY_ITEMS {
            return Err(MissionMemoryError::InvalidProviderOutput);
        }
        let mut previous: Option<(&FactId, u64)> = None;
        let mut ids = BTreeSet::new();
        for item in &self.items {
            item.validate()?;
            if !ids.insert(item.fact_id.clone()) {
                return Err(MissionMemoryError::InvalidProviderOutput);
            }
            if previous.is_some_and(|(fact_id, revision)| {
                (revision, fact_id) >= (item.fact_revision, &item.fact_id)
            }) {
                return Err(MissionMemoryError::InvalidProviderOutput);
            }
            previous = Some((&item.fact_id, item.fact_revision));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, MissionMemoryError> {
        self.validate()?;
        digest_json_with_domain("hartevo.mission-memory-working-set/v1", self)
    }
}

/// A content-free continuation cursor bound to the exact Project/Mission
/// revision and provider generation that produced the Working Set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryContinuation {
    pub scope: MissionMemoryScope,
    pub generation: u64,
    pub working_set_revision: u64,
    pub fact_revision_watermark: Option<u64>,
}

impl MissionMemoryContinuation {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        self.scope.validate()?;
        if self.generation == 0
            || self.working_set_revision == 0
            || self.fact_revision_watermark == Some(0)
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryProjection {
    pub working_set: MissionMemoryWorkingSet,
    pub continuation: MissionMemoryContinuation,
}

impl MissionMemoryProjection {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        self.working_set.validate()?;
        self.continuation.validate()?;
        if self.working_set.scope != self.continuation.scope
            || self.working_set.generation != self.continuation.generation
            || self.working_set.revision != self.continuation.working_set_revision
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, MissionMemoryError> {
        self.validate()?;
        digest_json_with_domain("hartevo.mission-memory-projection/v1", self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryVisibilityReceipt {
    pub event_sequence: u64,
    pub event_id: String,
    pub event_digest: String,
    pub request_digest: String,
    pub projection_digest: String,
}

impl MissionMemoryVisibilityReceipt {
    fn validate(&self) -> Result<(), MissionMemoryError> {
        if self.event_sequence == 0
            || !bounded_text(&self.event_id, MAX_REFERENCE_BYTES)
            || !is_lower_sha256(&self.event_digest)
            || !is_lower_sha256(&self.request_digest)
            || !is_lower_sha256(&self.projection_digest)
        {
            return Err(MissionMemoryError::InvalidEvent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryReadResult {
    pub projection: MissionMemoryProjection,
    pub visibility_receipt: MissionMemoryVisibilityReceipt,
}

impl MissionMemoryReadResult {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        self.projection.validate()?;
        self.visibility_receipt.validate()
    }

    pub fn working_set(&self) -> &MissionMemoryWorkingSet {
        &self.projection.working_set
    }

    pub fn continuation(&self) -> &MissionMemoryContinuation {
        &self.projection.continuation
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryReadRequest {
    pub request_id: String,
    pub max_items: u32,
    pub after_fact_revision: Option<u64>,
    pub requested_at: DateTime<Utc>,
}

impl MissionMemoryReadRequest {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        if !bounded_text(&self.request_id, MAX_REQUEST_ID_BYTES)
            || self.max_items == 0
            || usize::try_from(self.max_items).unwrap_or(usize::MAX) > MAX_MEMORY_ITEMS
            || self.after_fact_revision == Some(0)
        {
            return Err(MissionMemoryError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemorySession {
    pub scope: MissionMemoryScope,
    pub provider_id: String,
    pub handle_id: String,
    pub generation: u64,
}

impl MissionMemorySession {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        self.scope.validate()?;
        if !bounded_text(&self.provider_id, MAX_PROVIDER_ID_BYTES)
            || !bounded_text(&self.handle_id, MAX_HANDLE_ID_BYTES)
            || self.generation == 0
        {
            return Err(MissionMemoryError::InvalidProviderHandle);
        }
        Ok(())
    }

    pub fn scope(&self) -> &MissionMemoryScope {
        &self.scope
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionMemoryProviderHandle {
    provider_id: String,
    handle_id: String,
    scope: MissionMemoryScope,
    generation: u64,
}

impl MissionMemoryProviderHandle {
    pub fn new(
        provider_id: impl Into<String>,
        handle_id: impl Into<String>,
        scope: MissionMemoryScope,
        generation: u64,
    ) -> Result<Self, MissionMemoryError> {
        let handle = Self {
            provider_id: provider_id.into(),
            handle_id: handle_id.into(),
            scope,
            generation,
        };
        handle.validate()?;
        Ok(handle)
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn handle_id(&self) -> &str {
        &self.handle_id
    }

    pub fn scope(&self) -> &MissionMemoryScope {
        &self.scope
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn session(&self) -> MissionMemorySession {
        MissionMemorySession {
            scope: self.scope.clone(),
            provider_id: self.provider_id.clone(),
            handle_id: self.handle_id.clone(),
            generation: self.generation,
        }
    }

    fn validate(&self) -> Result<(), MissionMemoryError> {
        MissionMemorySession {
            scope: self.scope.clone(),
            provider_id: self.provider_id.clone(),
            handle_id: self.handle_id.clone(),
            generation: self.generation,
        }
        .validate()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionMemoryRecycleCause {
    MountFailed,
    Unmounted,
    Revoked,
    Crash,
    CrashRecovery,
}

/// Provider code can index or rank only the already durable typed facts. It
/// cannot persist independently or obtain any product authority through this
/// trait.
pub trait MissionMemoryProvider {
    fn provider_id(&self) -> &str;

    fn mount(
        &mut self,
        scope: &MissionMemoryScope,
        generation: u64,
    ) -> Result<MissionMemoryProviderHandle, MissionMemoryError>;

    fn build_working_set(
        &self,
        handle: &MissionMemoryProviderHandle,
        facts: &[MissionMemoryFact],
        request: &MissionMemoryReadRequest,
    ) -> Result<Vec<MissionMemoryItem>, MissionMemoryError>;

    /// Recycling is required to be idempotent so recovery can fence a handle
    /// that belonged to a process which stopped before its final lifecycle
    /// event was written.
    fn recycle(
        &mut self,
        handle: &MissionMemoryProviderHandle,
        cause: MissionMemoryRecycleCause,
    ) -> Result<(), MissionMemoryError>;
}

/// A consumer is deliberately narrower than a provider: it can request and
/// observe a model-visible result, but it receives no handle or authority.
pub trait MissionMemoryConsumer {
    fn consumer_id(&self) -> &str;

    fn request(&self, scope: &MissionMemoryScope, now: DateTime<Utc>) -> MissionMemoryReadRequest;

    fn observe(&mut self, result: &MissionMemoryReadResult) -> Result<(), MissionMemoryError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionMemoryAppendDisposition {
    Appended,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryFactReceipt {
    pub fact: MissionMemoryFact,
    pub disposition: MissionMemoryAppendDisposition,
    pub event_sequence: u64,
    pub event_id: String,
    pub event_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryLifecycleReceipt {
    pub session: MissionMemorySession,
    pub cause: MissionMemoryRecycleCause,
    pub event_sequence: u64,
    pub event_id: String,
    pub event_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MissionMemoryEvent {
    Mounted {
        session: MissionMemorySession,
    },
    FactAppended {
        fact: MissionMemoryFact,
    },
    ModelVisible {
        session: MissionMemorySession,
        consumer_id: String,
        request_digest: String,
        projection: Box<MissionMemoryProjection>,
    },
    ProviderRecycled {
        session: MissionMemorySession,
        cause: MissionMemoryRecycleCause,
    },
}

impl MissionMemoryEvent {
    fn validate(&self) -> Result<(), MissionMemoryError> {
        match self {
            Self::FactAppended { fact } => fact.validate(),
            Self::Mounted { session } | Self::ProviderRecycled { session, .. } => {
                session.validate()
            }
            Self::ModelVisible {
                session,
                consumer_id,
                request_digest,
                projection,
            } => {
                session.validate()?;
                if !bounded_text(consumer_id, MAX_CONSUMER_ID_BYTES)
                    || !is_lower_sha256(request_digest)
                {
                    return Err(MissionMemoryError::InvalidEvent);
                }
                projection.validate()
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryEventRecord {
    pub sequence: u64,
    pub event_id: String,
    pub event_digest: String,
    pub event: MissionMemoryEvent,
}

impl MissionMemoryEventRecord {
    pub fn from_event(
        sequence: u64,
        event: MissionMemoryEvent,
    ) -> Result<Self, MissionMemoryError> {
        event.validate()?;
        if sequence == 0 {
            return Err(MissionMemoryError::EventSequence);
        }
        Ok(Self {
            sequence,
            event_id: format!("mission-memory-event-{sequence}"),
            event_digest: event_digest(&event)?,
            event,
        })
    }

    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        let expected = Self::from_event(self.sequence, self.event.clone())?;
        if self.event_id != expected.event_id || self.event_digest != expected.event_digest {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        Ok(())
    }
}

/// The host supplies this with the durable Mission/event implementation. Its
/// append method must commit before returning; this is the persistence fence
/// that makes model-visible memory replayable and prevents a provider-local
/// cache from becoming product truth.
pub trait MissionMemoryDurableLog {
    fn append(
        &mut self,
        event: MissionMemoryEvent,
    ) -> Result<MissionMemoryEventRecord, MissionMemoryError>;

    fn replay(&self) -> Result<Vec<MissionMemoryEventRecord>, MissionMemoryError>;
}

#[derive(Debug)]
struct ActiveMissionMemory {
    session: MissionMemorySession,
    handle: MissionMemoryProviderHandle,
    next_working_set_revision: u64,
}

/// Lifecycle, scope, revision and durable-visibility authority for one
/// mounted Mission Memory provider.
#[derive(Debug)]
pub struct MissionMemoryService<L, P> {
    log: L,
    provider: P,
    active: Option<ActiveMissionMemory>,
    facts: BTreeMap<FactId, MissionMemoryFact>,
    fact_events: BTreeMap<FactId, MissionMemoryEventRecord>,
    seen_sessions: BTreeSet<MissionMemorySession>,
    seen_handle_ids: BTreeSet<String>,
    last_generation: u64,
    next_event_sequence: u64,
}

impl<L, P> MissionMemoryService<L, P>
where
    L: MissionMemoryDurableLog,
    P: MissionMemoryProvider,
{
    pub fn new(log: L, provider: P) -> Result<Self, MissionMemoryError> {
        let records = log.replay()?;
        let mut service = Self {
            log,
            provider,
            active: None,
            facts: BTreeMap::new(),
            fact_events: BTreeMap::new(),
            seen_sessions: BTreeSet::new(),
            seen_handle_ids: BTreeSet::new(),
            last_generation: 0,
            next_event_sequence: 1,
        };
        service.replay_records(&records)?;
        if service.active.is_some() {
            service.recycle_active(MissionMemoryRecycleCause::CrashRecovery)?;
        }
        Ok(service)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "mount takes ownership of the immutable scope snapshot that becomes the session boundary"
    )]
    pub fn mount(
        &mut self,
        scope: MissionMemoryScope,
    ) -> Result<MissionMemorySession, MissionMemoryError> {
        scope.validate()?;
        if self.active.is_some() {
            return Err(MissionMemoryError::AlreadyMounted);
        }
        let generation = self
            .last_generation
            .checked_add(1)
            .ok_or(MissionMemoryError::EventSequence)?;
        let handle = self.provider.mount(&scope, generation)?;
        if handle.provider_id() != self.provider.provider_id()
            || handle.scope() != &scope
            || handle.generation() != generation
            || self.seen_handle_ids.contains(handle.handle_id())
        {
            let _ = self
                .provider
                .recycle(&handle, MissionMemoryRecycleCause::MountFailed);
            return Err(MissionMemoryError::InvalidProviderHandle);
        }
        let session = handle.session();
        let event = MissionMemoryEvent::Mounted {
            session: session.clone(),
        };
        if let Err(error) = self.append_event(event) {
            let _ = self
                .provider
                .recycle(&handle, MissionMemoryRecycleCause::MountFailed);
            return Err(error);
        }
        self.last_generation = generation;
        self.seen_handle_ids.insert(handle.handle_id().to_owned());
        self.seen_sessions.insert(session.clone());
        self.active = Some(ActiveMissionMemory {
            session: session.clone(),
            handle,
            next_working_set_revision: 1,
        });
        Ok(session)
    }

    pub fn unmount(
        &mut self,
        session: &MissionMemorySession,
    ) -> Result<MissionMemoryLifecycleReceipt, MissionMemoryError> {
        self.recycle(session, MissionMemoryRecycleCause::Unmounted)
    }

    pub fn revoke(
        &mut self,
        session: &MissionMemorySession,
    ) -> Result<MissionMemoryLifecycleReceipt, MissionMemoryError> {
        self.recycle(session, MissionMemoryRecycleCause::Revoked)
    }

    pub fn crash(
        &mut self,
        session: &MissionMemorySession,
    ) -> Result<MissionMemoryLifecycleReceipt, MissionMemoryError> {
        self.recycle(session, MissionMemoryRecycleCause::Crash)
    }

    pub fn append_fact(
        &mut self,
        session: &MissionMemorySession,
        fact: MissionMemoryFact,
    ) -> Result<MissionMemoryFactReceipt, MissionMemoryError> {
        self.validate_session(session)?;
        fact.validate()?;
        if fact.scope != session.scope {
            return Err(MissionMemoryError::ScopeMismatch);
        }
        if let Some(existing) = self.facts.get(&fact.fact_id) {
            if existing == &fact {
                let record = self
                    .fact_events
                    .get(&fact.fact_id)
                    .ok_or(MissionMemoryError::InvalidEventLog)?;
                return Ok(fact_receipt(
                    fact,
                    MissionMemoryAppendDisposition::Replay,
                    record,
                ));
            }
            return Err(MissionMemoryError::FactConflict);
        }
        let expected_revision = self.next_fact_revision(&fact.scope)?;
        if fact.fact_revision != expected_revision {
            return Err(MissionMemoryError::RevisionMismatch);
        }
        let event = MissionMemoryEvent::FactAppended { fact: fact.clone() };
        let record = self.append_event(event)?;
        self.facts.insert(fact.fact_id.clone(), fact.clone());
        self.fact_events
            .insert(fact.fact_id.clone(), record.clone());
        Ok(fact_receipt(
            fact,
            MissionMemoryAppendDisposition::Appended,
            &record,
        ))
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "read owns the request snapshot so the durable visibility event cannot observe caller mutation"
    )]
    pub fn read(
        &mut self,
        session: &MissionMemorySession,
        consumer_id: impl Into<String>,
        request: MissionMemoryReadRequest,
    ) -> Result<MissionMemoryReadResult, MissionMemoryError> {
        let active = self.validate_session(session)?;
        request.validate()?;
        let consumer_id = consumer_id.into();
        if !bounded_text(&consumer_id, MAX_CONSUMER_ID_BYTES) {
            return Err(MissionMemoryError::InvalidRequest);
        }
        let facts = self.facts_for_scope(&session.scope);
        let items = self
            .provider
            .build_working_set(&active.handle, &facts, &request)?;
        validate_provider_items(&items, &facts, &request)?;
        let working_set = MissionMemoryWorkingSet {
            scope: session.scope.clone(),
            generation: session.generation,
            revision: active.next_working_set_revision,
            items,
        };
        let watermark = working_set
            .items
            .iter()
            .map(|item| item.fact_revision)
            .max();
        let projection = MissionMemoryProjection {
            working_set,
            continuation: MissionMemoryContinuation {
                scope: session.scope.clone(),
                generation: session.generation,
                working_set_revision: active.next_working_set_revision,
                fact_revision_watermark: watermark,
            },
        };
        projection.validate()?;
        let request_digest = read_request_digest(session, &consumer_id, &request)?;
        let record = self.append_event(MissionMemoryEvent::ModelVisible {
            session: session.clone(),
            consumer_id,
            request_digest: request_digest.clone(),
            projection: Box::new(projection.clone()),
        })?;
        let projection_digest = projection.digest()?;
        let result = MissionMemoryReadResult {
            projection,
            visibility_receipt: MissionMemoryVisibilityReceipt {
                event_sequence: record.sequence,
                event_id: record.event_id,
                event_digest: record.event_digest,
                request_digest,
                projection_digest,
            },
        };
        result.validate()?;
        if let Some(active) = self.active.as_mut() {
            active.next_working_set_revision = active
                .next_working_set_revision
                .checked_add(1)
                .ok_or(MissionMemoryError::EventSequence)?;
        }
        Ok(result)
    }

    pub fn read_for_consumer<C: MissionMemoryConsumer>(
        &mut self,
        session: &MissionMemorySession,
        consumer: &mut C,
        now: DateTime<Utc>,
    ) -> Result<MissionMemoryReadResult, MissionMemoryError> {
        let result = self.read(
            session,
            consumer.consumer_id().to_owned(),
            consumer.request(&session.scope, now),
        )?;
        consumer.observe(&result)?;
        Ok(result)
    }

    pub fn active_session(&self) -> Option<&MissionMemorySession> {
        self.active.as_ref().map(|active| &active.session)
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn durable_log(&self) -> &L {
        &self.log
    }

    pub fn last_generation(&self) -> u64 {
        self.last_generation
    }

    pub fn into_parts(self) -> (L, P) {
        (self.log, self.provider)
    }

    fn recycle(
        &mut self,
        session: &MissionMemorySession,
        cause: MissionMemoryRecycleCause,
    ) -> Result<MissionMemoryLifecycleReceipt, MissionMemoryError> {
        let active = self.validate_session(session)?.session.clone();
        let active_state = self.active.take().ok_or(MissionMemoryError::NotMounted)?;
        let provider_result = self.provider.recycle(&active_state.handle, cause);
        let event_result = self.append_event(MissionMemoryEvent::ProviderRecycled {
            session: active.clone(),
            cause,
        });
        let record = event_result?;
        provider_result?;
        Ok(MissionMemoryLifecycleReceipt {
            session: active,
            cause,
            event_sequence: record.sequence,
            event_id: record.event_id,
            event_digest: record.event_digest,
        })
    }

    fn validate_session(
        &self,
        session: &MissionMemorySession,
    ) -> Result<&ActiveMissionMemory, MissionMemoryError> {
        session.validate()?;
        let Some(active) = &self.active else {
            return if self.seen_sessions.contains(session) {
                Err(MissionMemoryError::StaleGeneration)
            } else {
                Err(MissionMemoryError::NotMounted)
            };
        };
        if active.session.scope != session.scope {
            return Err(MissionMemoryError::ScopeMismatch);
        }
        if active.session != *session {
            return Err(MissionMemoryError::StaleGeneration);
        }
        Ok(active)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the durable log consumes the event while the service retains an exact comparison copy"
    )]
    fn append_event(
        &mut self,
        event: MissionMemoryEvent,
    ) -> Result<MissionMemoryEventRecord, MissionMemoryError> {
        event.validate()?;
        let expected_sequence = self.next_event_sequence;
        let record = self.log.append(event.clone())?;
        record.validate()?;
        if record.sequence != expected_sequence || record.event != event {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        self.next_event_sequence = self
            .next_event_sequence
            .checked_add(1)
            .ok_or(MissionMemoryError::EventSequence)?;
        Ok(record)
    }

    fn replay_records(
        &mut self,
        records: &[MissionMemoryEventRecord],
    ) -> Result<(), MissionMemoryError> {
        for record in records {
            if record.sequence != self.next_event_sequence {
                return Err(MissionMemoryError::EventSequence);
            }
            record.validate()?;
            self.apply_event(&record.event, record)?;
            self.next_event_sequence = self
                .next_event_sequence
                .checked_add(1)
                .ok_or(MissionMemoryError::EventSequence)?;
        }
        Ok(())
    }

    fn apply_event(
        &mut self,
        event: &MissionMemoryEvent,
        record: &MissionMemoryEventRecord,
    ) -> Result<(), MissionMemoryError> {
        match event {
            MissionMemoryEvent::Mounted { session } => {
                session.validate()?;
                if session.provider_id != self.provider.provider_id()
                    || self.active.is_some()
                    || self.seen_handle_ids.contains(&session.handle_id)
                    || session.generation
                        != self
                            .last_generation
                            .checked_add(1)
                            .ok_or(MissionMemoryError::EventSequence)?
                {
                    return Err(MissionMemoryError::InvalidEventLog);
                }
                let handle = MissionMemoryProviderHandle::new(
                    session.provider_id.clone(),
                    session.handle_id.clone(),
                    session.scope.clone(),
                    session.generation,
                )?;
                self.last_generation = session.generation;
                self.seen_handle_ids.insert(session.handle_id.clone());
                self.seen_sessions.insert(session.clone());
                self.active = Some(ActiveMissionMemory {
                    session: session.clone(),
                    handle,
                    next_working_set_revision: 1,
                });
            }
            MissionMemoryEvent::FactAppended { fact } => {
                fact.validate()?;
                if self.facts.contains_key(&fact.fact_id)
                    || fact.fact_revision != self.next_fact_revision(&fact.scope)?
                {
                    return Err(MissionMemoryError::InvalidEventLog);
                }
                self.facts.insert(fact.fact_id.clone(), fact.clone());
                self.fact_events
                    .insert(fact.fact_id.clone(), record.clone());
            }
            MissionMemoryEvent::ModelVisible {
                session,
                projection,
                ..
            } => {
                let Some(active) = &self.active else {
                    return Err(MissionMemoryError::InvalidEventLog);
                };
                if active.session != *session
                    || projection.working_set.revision != active.next_working_set_revision
                {
                    return Err(MissionMemoryError::InvalidEventLog);
                }
                projection.validate()?;
                let facts = self.facts_for_scope(&session.scope);
                validate_projection_items(projection, &facts)?;
                let active = self
                    .active
                    .as_mut()
                    .ok_or(MissionMemoryError::InvalidEventLog)?;
                active.next_working_set_revision = active
                    .next_working_set_revision
                    .checked_add(1)
                    .ok_or(MissionMemoryError::EventSequence)?;
            }
            MissionMemoryEvent::ProviderRecycled { session, .. } => {
                let Some(active) = &self.active else {
                    return Err(MissionMemoryError::InvalidEventLog);
                };
                if active.session != *session {
                    return Err(MissionMemoryError::InvalidEventLog);
                }
                self.active = None;
            }
        }
        Ok(())
    }

    fn facts_for_scope(&self, scope: &MissionMemoryScope) -> Vec<MissionMemoryFact> {
        let mut facts = self
            .facts
            .values()
            .filter(|fact| &fact.scope == scope)
            .cloned()
            .collect::<Vec<_>>();
        facts.sort_by(|left, right| {
            left.fact_revision
                .cmp(&right.fact_revision)
                .then_with(|| left.fact_id.cmp(&right.fact_id))
        });
        facts
    }

    fn next_fact_revision(&self, scope: &MissionMemoryScope) -> Result<u64, MissionMemoryError> {
        self.facts
            .values()
            .filter(|fact| &fact.scope == scope)
            .map(|fact| fact.fact_revision)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(MissionMemoryError::RevisionMismatch)
    }

    fn recycle_active(
        &mut self,
        cause: MissionMemoryRecycleCause,
    ) -> Result<MissionMemoryLifecycleReceipt, MissionMemoryError> {
        let session = self
            .active
            .as_ref()
            .map(|active| active.session.clone())
            .ok_or(MissionMemoryError::NotMounted)?;
        self.recycle(&session, cause)
    }
}

#[derive(Debug)]
pub struct DeterministicMissionMemoryProvider {
    provider_id: String,
    active_handles: BTreeSet<String>,
    recycled_handles: BTreeSet<String>,
}

impl DeterministicMissionMemoryProvider {
    pub fn new(provider_id: impl Into<String>) -> Result<Self, MissionMemoryError> {
        let provider = Self {
            provider_id: provider_id.into(),
            active_handles: BTreeSet::new(),
            recycled_handles: BTreeSet::new(),
        };
        if !bounded_text(&provider.provider_id, MAX_PROVIDER_ID_BYTES) {
            return Err(MissionMemoryError::ProviderMismatch);
        }
        Ok(provider)
    }

    pub fn active_handle_count(&self) -> usize {
        self.active_handles.len()
    }

    pub fn recycled_handle_count(&self) -> usize {
        self.recycled_handles.len()
    }

    fn handle_is_active(
        &self,
        handle: &MissionMemoryProviderHandle,
    ) -> Result<(), MissionMemoryError> {
        if handle.provider_id() != self.provider_id
            || !self.active_handles.contains(handle.handle_id())
        {
            return Err(MissionMemoryError::StaleGeneration);
        }
        Ok(())
    }
}

impl Default for DeterministicMissionMemoryProvider {
    fn default() -> Self {
        Self::new("deterministic-mission-memory-provider")
            .expect("static provider identity is valid")
    }
}

impl MissionMemoryProvider for DeterministicMissionMemoryProvider {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn mount(
        &mut self,
        scope: &MissionMemoryScope,
        generation: u64,
    ) -> Result<MissionMemoryProviderHandle, MissionMemoryError> {
        scope.validate()?;
        if generation == 0 {
            return Err(MissionMemoryError::InvalidProviderHandle);
        }
        let handle_id = digest_json_with_domain(
            "hartevo.mission-memory-provider-handle/v1",
            &(self.provider_id.as_str(), scope, generation),
        )?;
        let handle = MissionMemoryProviderHandle::new(
            self.provider_id.clone(),
            handle_id,
            scope.clone(),
            generation,
        )?;
        self.active_handles.insert(handle.handle_id().to_owned());
        Ok(handle)
    }

    fn build_working_set(
        &self,
        handle: &MissionMemoryProviderHandle,
        facts: &[MissionMemoryFact],
        request: &MissionMemoryReadRequest,
    ) -> Result<Vec<MissionMemoryItem>, MissionMemoryError> {
        self.handle_is_active(handle)?;
        request.validate()?;
        let after = request.after_fact_revision.unwrap_or(0);
        let mut ordered = facts
            .iter()
            .filter(|fact| fact.scope == *handle.scope() && fact.fact_revision > after)
            .cloned()
            .collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            left.fact_revision
                .cmp(&right.fact_revision)
                .then_with(|| left.fact_id.cmp(&right.fact_id))
        });
        let keep = usize::try_from(request.max_items).unwrap_or(MAX_MEMORY_ITEMS);
        if ordered.len() > keep {
            ordered = ordered.split_off(ordered.len() - keep);
        }
        Ok(ordered.iter().map(MissionMemoryFact::item).collect())
    }

    fn recycle(
        &mut self,
        handle: &MissionMemoryProviderHandle,
        _cause: MissionMemoryRecycleCause,
    ) -> Result<(), MissionMemoryError> {
        if handle.provider_id() != self.provider_id {
            return Err(MissionMemoryError::ProviderMismatch);
        }
        self.active_handles.remove(handle.handle_id());
        self.recycled_handles.insert(handle.handle_id().to_owned());
        Ok(())
    }
}

fn fact_receipt(
    fact: MissionMemoryFact,
    disposition: MissionMemoryAppendDisposition,
    record: &MissionMemoryEventRecord,
) -> MissionMemoryFactReceipt {
    MissionMemoryFactReceipt {
        fact,
        disposition,
        event_sequence: record.sequence,
        event_id: record.event_id.clone(),
        event_digest: record.event_digest.clone(),
    }
}

fn validate_provider_items(
    items: &[MissionMemoryItem],
    facts: &[MissionMemoryFact],
    request: &MissionMemoryReadRequest,
) -> Result<(), MissionMemoryError> {
    if items.len() > usize::try_from(request.max_items).unwrap_or(MAX_MEMORY_ITEMS) {
        return Err(MissionMemoryError::InvalidProviderOutput);
    }
    let available = facts
        .iter()
        .filter(|fact| {
            request
                .after_fact_revision
                .is_none_or(|after| fact.fact_revision > after)
        })
        .map(|fact| &fact.fact_id)
        .collect::<BTreeSet<_>>();
    if items.iter().any(|item| !available.contains(&item.fact_id)) {
        return Err(MissionMemoryError::InvalidProviderOutput);
    }
    validate_items_against_facts(items, facts)
}

fn validate_projection_items(
    projection: &MissionMemoryProjection,
    facts: &[MissionMemoryFact],
) -> Result<(), MissionMemoryError> {
    validate_items_against_facts(&projection.working_set.items, facts)
}

fn validate_items_against_facts(
    items: &[MissionMemoryItem],
    facts: &[MissionMemoryFact],
) -> Result<(), MissionMemoryError> {
    let facts = facts
        .iter()
        .map(|fact| (&fact.fact_id, fact))
        .collect::<BTreeMap<_, _>>();
    let mut ids = BTreeSet::new();
    for item in items {
        let fact = facts
            .get(&item.fact_id)
            .ok_or(MissionMemoryError::InvalidProviderOutput)?;
        if !ids.insert(item.fact_id.clone()) || item != &fact.item() {
            return Err(MissionMemoryError::InvalidProviderOutput);
        }
    }
    Ok(())
}

fn read_request_digest(
    session: &MissionMemorySession,
    consumer_id: &str,
    request: &MissionMemoryReadRequest,
) -> Result<String, MissionMemoryError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ReadInput<'a> {
        schema_version: &'static str,
        session: &'a MissionMemorySession,
        consumer_id: &'a str,
        request: &'a MissionMemoryReadRequest,
    }
    digest_json_with_domain(
        "hartevo.mission-memory-read-request/v1",
        &ReadInput {
            schema_version: MISSION_MEMORY_SCHEMA_VERSION,
            session,
            consumer_id,
            request,
        },
    )
}

fn event_digest(event: &MissionMemoryEvent) -> Result<String, MissionMemoryError> {
    digest_json_with_domain("hartevo.mission-memory-event/v1", event)
}

fn digest_json_with_domain(
    domain: &str,
    value: &impl Serialize,
) -> Result<String, MissionMemoryError> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(serde_json::to_vec(value)?);
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

fn is_memory_reference(value: &str) -> bool {
    bounded_text(value, MAX_REFERENCE_BYTES)
        && (value.starts_with("cas://") || value.starts_with("event://"))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[derive(Clone, Debug, Default)]
    struct TestLog {
        records: Vec<MissionMemoryEventRecord>,
    }

    impl MissionMemoryDurableLog for TestLog {
        fn append(
            &mut self,
            event: MissionMemoryEvent,
        ) -> Result<MissionMemoryEventRecord, MissionMemoryError> {
            let sequence = u64::try_from(self.records.len())
                .map_err(|_| MissionMemoryError::EventSequence)?
                .checked_add(1)
                .ok_or(MissionMemoryError::EventSequence)?;
            let record = MissionMemoryEventRecord::from_event(sequence, event)?;
            self.records.push(record.clone());
            Ok(record)
        }

        fn replay(&self) -> Result<Vec<MissionMemoryEventRecord>, MissionMemoryError> {
            Ok(self.records.clone())
        }
    }

    #[derive(Debug, Default)]
    struct RecordingConsumer {
        id: String,
        seen: Vec<MissionMemoryReadResult>,
    }

    impl RecordingConsumer {
        fn new(id: impl Into<String>) -> Self {
            Self {
                id: id.into(),
                seen: Vec::new(),
            }
        }
    }

    impl MissionMemoryConsumer for RecordingConsumer {
        fn consumer_id(&self) -> &str {
            &self.id
        }

        fn request(
            &self,
            _scope: &MissionMemoryScope,
            now: DateTime<Utc>,
        ) -> MissionMemoryReadRequest {
            MissionMemoryReadRequest {
                request_id: format!("request-{}", self.seen.len() + 1),
                max_items: 32,
                after_fact_revision: None,
                requested_at: now,
            }
        }

        fn observe(&mut self, result: &MissionMemoryReadResult) -> Result<(), MissionMemoryError> {
            self.seen.push(result.clone());
            Ok(())
        }
    }

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_754_000_000 + second, 0)
            .single()
            .expect("fixture time")
    }

    fn scope(mission: &str) -> MissionMemoryScope {
        MissionMemoryScope::new(
            TenantId::from("tenant-memory"),
            ProjectId::from("project-memory"),
            4,
            MissionId::from(mission),
            7,
        )
        .expect("fixture scope")
    }

    fn fact(scope: &MissionMemoryScope, revision: u64, id: &str) -> MissionMemoryFact {
        MissionMemoryFact {
            fact_id: FactId::from(id),
            scope: scope.clone(),
            fact_revision: revision,
            source_event_id: format!("mission-event-{id}"),
            payload_ref: format!("cas://{id}"),
            payload_digest: format!("{revision:064x}"),
            classification: ContextDataClass::Business,
            recorded_at: at(i64::try_from(revision).expect("small revision")),
        }
    }

    fn new_service(
        log: TestLog,
    ) -> MissionMemoryService<TestLog, DeterministicMissionMemoryProvider> {
        MissionMemoryService::new(log, DeterministicMissionMemoryProvider::default())
            .expect("valid memory service")
    }

    fn read_request(id: &str) -> MissionMemoryReadRequest {
        MissionMemoryReadRequest {
            request_id: id.into(),
            max_items: 32,
            after_fact_revision: None,
            requested_at: at(20),
        }
    }

    #[test]
    fn provider_handle_is_recycled_on_unmount_revoke_and_crash() {
        let mut service = new_service(TestLog::default());
        let first_scope = scope("mission-a");
        let first = service.mount(first_scope.clone()).expect("mount");
        service.unmount(&first).expect("unmount recycles handle");
        assert!(matches!(
            service.append_fact(&first, fact(&first_scope, 1, "stale-write")),
            Err(MissionMemoryError::StaleGeneration)
        ));
        let second = service.mount(scope("mission-a")).expect("remount");
        service.revoke(&second).expect("revoke recycles handle");
        let third = service.mount(scope("mission-a")).expect("mount again");
        service.crash(&third).expect("crash recycles handle");
        assert_eq!(service.provider().active_handle_count(), 0);
        assert_eq!(service.provider().recycled_handle_count(), 3);
        assert_eq!(service.last_generation(), 3);
        assert_eq!(service.durable_log().replay().expect("replay").len(), 6);
    }

    #[test]
    fn reopen_recovers_unterminated_mount_and_replays_durable_facts() {
        let mut service = new_service(TestLog::default());
        let scope = scope("mission-reopen");
        let old_session = service.mount(scope.clone()).expect("mount");
        service
            .append_fact(&old_session, fact(&scope, 1, "fact-one"))
            .expect("durable fact");
        let first = service
            .read(&old_session, "model", read_request("read-one"))
            .expect("durable model result");
        let (log, _) = service.into_parts();

        let mut reopened = new_service(log);
        assert_eq!(reopened.provider().recycled_handle_count(), 1);
        assert_eq!(reopened.active_session(), None);
        assert!(matches!(
            reopened.read(&old_session, "model", read_request("stale")),
            Err(MissionMemoryError::StaleGeneration)
        ));
        let new_session = reopened.mount(scope).expect("new generation");
        assert_eq!(new_session.generation(), 2);
        let second = reopened
            .read(&new_session, "model", read_request("read-two"))
            .expect("replayed fact is visible");
        assert_eq!(first.working_set().items, second.working_set().items);
        assert!(
            reopened
                .durable_log()
                .replay()
                .expect("replay after recovery")
                .iter()
                .any(|record| {
                    matches!(
                        record.event,
                        MissionMemoryEvent::ProviderRecycled {
                            cause: MissionMemoryRecycleCause::CrashRecovery,
                            ..
                        }
                    )
                })
        );
    }

    #[test]
    fn revoke_and_scope_fences_reject_old_generation_and_new_mission_cross_read() {
        let mut service = new_service(TestLog::default());
        let scope_a = scope("mission-a");
        let scope_b = scope("mission-b");
        let old = service.mount(scope_a.clone()).expect("mount A");
        service
            .append_fact(&old, fact(&scope_a, 1, "fact-a"))
            .expect("fact A");
        assert!(matches!(
            service.append_fact(&old, fact(&scope_b, 1, "fact-b")),
            Err(MissionMemoryError::ScopeMismatch)
        ));
        service.revoke(&old).expect("revoke A");
        assert!(matches!(
            service.read(&old, "model", read_request("old-read")),
            Err(MissionMemoryError::StaleGeneration)
        ));
        assert!(matches!(
            service.append_fact(&old, fact(&scope_a, 2, "stale-write")),
            Err(MissionMemoryError::StaleGeneration)
        ));

        let fresh = service.mount(scope_b.clone()).expect("mount B");
        assert!(matches!(
            service.append_fact(&old, fact(&scope_a, 2, "fact-a-2")),
            Err(MissionMemoryError::ScopeMismatch)
        ));
        let result = service
            .read(&fresh, "model", read_request("new-mission-read"))
            .expect("new mission read");
        assert!(result.working_set().items.is_empty());
    }

    #[test]
    fn model_visible_result_is_durably_logged_before_consumer_observes_it() {
        let mut service = new_service(TestLog::default());
        let scope = scope("mission-consumer");
        let session = service.mount(scope.clone()).expect("mount");
        service
            .append_fact(&session, fact(&scope, 1, "fact-consumer"))
            .expect("fact");
        let mut consumer = RecordingConsumer::new("agent-plane-consumer");
        let result = service
            .read_for_consumer(&session, &mut consumer, at(30))
            .expect("consumer read");
        assert_eq!(consumer.seen, vec![result.clone()]);
        let records = service.durable_log().replay().expect("replay");
        let visible = records
            .iter()
            .find_map(|record| match &record.event {
                MissionMemoryEvent::ModelVisible { projection, .. } => Some(projection),
                _ => None,
            })
            .expect("visible event");
        assert_eq!(visible.as_ref(), &result.projection);
        assert_eq!(
            result.visibility_receipt.projection_digest,
            visible.digest().expect("projection digest")
        );
    }

    #[test]
    fn property_reopened_generation_preserves_only_exact_scope_and_durable_facts() {
        for fact_count in 1_u8..=16 {
            for mission_suffix in [1_u16, 7, 64, 4096] {
                let mut service = new_service(TestLog::default());
                let mission = format!("mission-{mission_suffix}");
                let scope = scope(&mission);
                let old = service.mount(scope.clone()).expect("mount");
                for revision in 1..=u64::from(fact_count) {
                    let id = format!("fact-{mission_suffix}-{revision}");
                    service
                        .append_fact(&old, fact(&scope, revision, &id))
                        .expect("durable fact");
                }
                let (log, _) = service.into_parts();
                let mut reopened = new_service(log);
                let fresh = reopened.mount(scope.clone()).expect("fresh generation");
                assert_eq!(fresh.generation(), 2);
                assert!(matches!(
                    reopened.read(&old, "model", read_request("old")),
                    Err(MissionMemoryError::StaleGeneration)
                ));
                let stale_revision = u64::from(fact_count) + 1;
                assert!(matches!(
                    reopened.append_fact(&old, fact(&scope, stale_revision, "stale-write")),
                    Err(MissionMemoryError::StaleGeneration)
                ));
                let result = reopened
                    .read(&fresh, "model", read_request("fresh"))
                    .expect("fresh read");
                assert_eq!(result.working_set().items.len(), usize::from(fact_count));
                assert!(
                    result
                        .working_set()
                        .items
                        .iter()
                        .all(|item| item.fact_id.as_str().contains(&mission_suffix.to_string()))
                );
            }
        }
    }
}
