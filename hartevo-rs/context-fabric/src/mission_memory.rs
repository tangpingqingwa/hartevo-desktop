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

    pub fn digest(&self) -> Result<String, MissionMemoryError> {
        self.validate()?;
        digest_json_with_domain("hartevo.mission-memory-fact/v1", self)
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

impl MissionMemoryRecycleCause {
    fn invalidates_compactions(self) -> bool {
        matches!(self, Self::Unmounted | Self::Revoked)
    }
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

    fn observe_continuation(
        &mut self,
        _result: &MissionMemoryContinuationResult,
    ) -> Result<(), MissionMemoryError> {
        Ok(())
    }
}

const MAX_COMPACTION_SOURCE_FACTS: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryCompactionRequest {
    pub request_id: String,
    pub max_retained_items: u32,
    pub counterevidence_fact_ids: BTreeSet<FactId>,
    pub requested_at: DateTime<Utc>,
}

impl MissionMemoryCompactionRequest {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        if !bounded_text(&self.request_id, MAX_REQUEST_ID_BYTES)
            || self.max_retained_items == 0
            || usize::try_from(self.max_retained_items).unwrap_or(usize::MAX) > MAX_MEMORY_ITEMS
            || self.counterevidence_fact_ids.len() > MAX_MEMORY_ITEMS
            || self
                .counterevidence_fact_ids
                .iter()
                .any(|fact_id| !bounded_text(fact_id.as_str(), MAX_FACT_ID_BYTES))
        {
            return Err(MissionMemoryError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryResumeRequest {
    pub request_id: String,
    pub requested_at: DateTime<Utc>,
}

impl MissionMemoryResumeRequest {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        if !bounded_text(&self.request_id, MAX_REQUEST_ID_BYTES) {
            return Err(MissionMemoryError::InvalidRequest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryContinuationToken {
    pub scope: MissionMemoryScope,
    pub source_generation: u64,
    pub continuation_version: u64,
    pub continuation_digest: String,
}

impl MissionMemoryContinuationToken {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        self.scope.validate()?;
        if self.source_generation == 0
            || self.continuation_version == 0
            || !is_lower_sha256(&self.continuation_digest)
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryContinuationArtifact {
    pub scope: MissionMemoryScope,
    pub source_generation: u64,
    pub continuation_version: u64,
    pub source_fact_digests: BTreeMap<FactId, String>,
    pub retained_items: Vec<MissionMemoryItem>,
    pub counterevidence_fact_ids: BTreeSet<FactId>,
    pub summary_ref: String,
    pub summary_digest: String,
}

impl MissionMemoryContinuationArtifact {
    pub fn validate(&self) -> Result<(), MissionMemoryError> {
        self.scope.validate()?;
        if self.source_generation == 0
            || self.continuation_version == 0
            || self.source_fact_digests.len() > MAX_COMPACTION_SOURCE_FACTS
            || self.retained_items.len() > MAX_MEMORY_ITEMS
            || self.counterevidence_fact_ids.len() > MAX_MEMORY_ITEMS
            || !is_memory_reference(&self.summary_ref)
            || !is_lower_sha256(&self.summary_digest)
            || self
                .source_fact_digests
                .iter()
                .any(|(fact_id, fact_digest)| {
                    !bounded_text(fact_id.as_str(), MAX_FACT_ID_BYTES)
                        || !is_lower_sha256(fact_digest)
                })
            || self
                .counterevidence_fact_ids
                .iter()
                .any(|fact_id| !self.source_fact_digests.contains_key(fact_id))
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        validate_item_list(&self.retained_items, MAX_MEMORY_ITEMS)?;
        let retained_ids = self
            .retained_items
            .iter()
            .map(|item| item.fact_id.clone())
            .collect::<BTreeSet<_>>();
        if self
            .counterevidence_fact_ids
            .iter()
            .any(|fact_id| !retained_ids.contains(fact_id))
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, MissionMemoryError> {
        self.validate()?;
        digest_json_with_domain("hartevo.mission-memory-continuation/v1", self)
    }

    pub fn token(&self) -> Result<MissionMemoryContinuationToken, MissionMemoryError> {
        Ok(MissionMemoryContinuationToken {
            scope: self.scope.clone(),
            source_generation: self.source_generation,
            continuation_version: self.continuation_version,
            continuation_digest: self.digest()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryContinuationProvenance {
    pub source_compaction_event_sequence: u64,
    pub source_compaction_event_digest: String,
    pub source_continuation_digest: String,
    pub source_generation: u64,
    pub resumed_generation: u64,
    pub source_fact_digests: BTreeMap<FactId, String>,
}

impl MissionMemoryContinuationProvenance {
    fn validate(&self) -> Result<(), MissionMemoryError> {
        if self.source_compaction_event_sequence == 0
            || !is_lower_sha256(&self.source_compaction_event_digest)
            || !is_lower_sha256(&self.source_continuation_digest)
            || self.source_generation == 0
            || self.resumed_generation == 0
            || self.source_generation == self.resumed_generation
            || self.source_fact_digests.len() > MAX_COMPACTION_SOURCE_FACTS
            || self
                .source_fact_digests
                .iter()
                .any(|(fact_id, fact_digest)| {
                    !bounded_text(fact_id.as_str(), MAX_FACT_ID_BYTES)
                        || !is_lower_sha256(fact_digest)
                })
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryCompactionResult {
    pub continuation: MissionMemoryContinuationArtifact,
    pub token: MissionMemoryContinuationToken,
    pub visibility_receipt: MissionMemoryVisibilityReceipt,
}

impl MissionMemoryCompactionResult {
    fn validate(&self) -> Result<(), MissionMemoryError> {
        self.continuation.validate()?;
        self.token.validate()?;
        self.visibility_receipt.validate()?;
        let digest = self.continuation.digest()?;
        if self.token.scope != self.continuation.scope
            || self.token.source_generation != self.continuation.source_generation
            || self.token.continuation_version != self.continuation.continuation_version
            || self.token.continuation_digest != digest
            || self.visibility_receipt.projection_digest != digest
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMemoryContinuationResult {
    pub token: MissionMemoryContinuationToken,
    pub working_set: MissionMemoryWorkingSet,
    pub provenance: MissionMemoryContinuationProvenance,
    pub visibility_receipt: MissionMemoryVisibilityReceipt,
}

impl MissionMemoryContinuationResult {
    fn validate(&self) -> Result<(), MissionMemoryError> {
        self.token.validate()?;
        self.working_set.validate()?;
        self.provenance.validate()?;
        self.visibility_receipt.validate()?;
        if self.token.scope != self.working_set.scope
            || self.token.source_generation != self.provenance.source_generation
            || self.working_set.generation != self.provenance.resumed_generation
            || self.token.continuation_digest != self.provenance.source_continuation_digest
            || self.token.source_generation == self.working_set.generation
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        let digest = self.digest_without_receipt()?;
        if self.visibility_receipt.projection_digest != digest {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        Ok(())
    }

    fn digest_without_receipt(&self) -> Result<String, MissionMemoryError> {
        digest_json_with_domain(
            "hartevo.mission-memory-continuation-result/v1",
            &(&self.token, &self.working_set, &self.provenance),
        )
    }
}

/// The continuation provider has no persistence or product authority. It
/// receives durable facts, produces a versioned digest-bound artifact, and
/// can restore only the artifact's retained references.
pub trait MissionMemoryContinuationProvider {
    fn compact(
        &self,
        handle: &MissionMemoryProviderHandle,
        facts: &[MissionMemoryFact],
        continuation_version: u64,
        request: &MissionMemoryCompactionRequest,
    ) -> Result<MissionMemoryContinuationArtifact, MissionMemoryError>;

    fn restore_working_set(
        &self,
        handle: &MissionMemoryProviderHandle,
        facts: &[MissionMemoryFact],
        continuation: &MissionMemoryContinuationArtifact,
    ) -> Result<Vec<MissionMemoryItem>, MissionMemoryError>;
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
    ContinuationCompacted {
        session: MissionMemorySession,
        consumer_id: String,
        request_digest: String,
        artifact: Box<MissionMemoryContinuationArtifact>,
    },
    ContinuationResumed {
        session: MissionMemorySession,
        consumer_id: String,
        request_digest: String,
        token: MissionMemoryContinuationToken,
        working_set: Box<MissionMemoryWorkingSet>,
        provenance: Box<MissionMemoryContinuationProvenance>,
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
            Self::ContinuationCompacted {
                session,
                consumer_id,
                request_digest,
                artifact,
            } => {
                session.validate()?;
                if !bounded_text(consumer_id, MAX_CONSUMER_ID_BYTES)
                    || !is_lower_sha256(request_digest)
                {
                    return Err(MissionMemoryError::InvalidEvent);
                }
                artifact.validate()
            }
            Self::ContinuationResumed {
                session,
                consumer_id,
                request_digest,
                token,
                working_set,
                provenance,
            } => {
                session.validate()?;
                if !bounded_text(consumer_id, MAX_CONSUMER_ID_BYTES)
                    || !is_lower_sha256(request_digest)
                {
                    return Err(MissionMemoryError::InvalidEvent);
                }
                token.validate()?;
                working_set.validate()?;
                provenance.validate()
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

#[derive(Clone, Debug)]
struct StoredMissionMemoryCompaction {
    artifact: MissionMemoryContinuationArtifact,
    record: MissionMemoryEventRecord,
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
    compactions: BTreeMap<String, StoredMissionMemoryCompaction>,
    compaction_versions: BTreeMap<MissionMemoryScope, u64>,
    invalidated_compactions: BTreeSet<String>,
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
            compactions: BTreeMap::new(),
            compaction_versions: BTreeMap::new(),
            invalidated_compactions: BTreeSet::new(),
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

    pub fn resume_for_consumer<C: MissionMemoryConsumer>(
        &mut self,
        session: &MissionMemorySession,
        consumer: &mut C,
        token: MissionMemoryContinuationToken,
        request: MissionMemoryResumeRequest,
    ) -> Result<MissionMemoryContinuationResult, MissionMemoryError>
    where
        P: MissionMemoryContinuationProvider,
    {
        let result = self.resume(session, consumer.consumer_id().to_owned(), token, request)?;
        consumer.observe_continuation(&result)?;
        Ok(result)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "compaction owns the immutable request snapshot that is durably bound to its event"
    )]
    pub fn compact(
        &mut self,
        session: &MissionMemorySession,
        consumer_id: impl Into<String>,
        request: MissionMemoryCompactionRequest,
    ) -> Result<MissionMemoryCompactionResult, MissionMemoryError>
    where
        P: MissionMemoryContinuationProvider,
    {
        let handle = self.validate_session(session)?.handle.clone();
        request.validate()?;
        let consumer_id = consumer_id.into();
        if !bounded_text(&consumer_id, MAX_CONSUMER_ID_BYTES) {
            return Err(MissionMemoryError::InvalidRequest);
        }
        let continuation_version = self.next_compaction_version(&session.scope)?;
        let facts = self.facts_for_scope(&session.scope);
        let artifact = self
            .provider
            .compact(&handle, &facts, continuation_version, &request)?;
        artifact.validate()?;
        if artifact.scope != session.scope
            || artifact.source_generation != session.generation
            || artifact.continuation_version != continuation_version
            || artifact.counterevidence_fact_ids != request.counterevidence_fact_ids
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        validate_compaction_against_facts(&artifact, &facts, &request.counterevidence_fact_ids)?;
        let request_digest =
            compaction_request_digest(session, &consumer_id, continuation_version, &request)?;
        let record = self.append_event(MissionMemoryEvent::ContinuationCompacted {
            session: session.clone(),
            consumer_id,
            request_digest: request_digest.clone(),
            artifact: Box::new(artifact.clone()),
        })?;
        let continuation_digest = artifact.digest()?;
        self.compactions.insert(
            continuation_digest.clone(),
            StoredMissionMemoryCompaction {
                artifact: artifact.clone(),
                record: record.clone(),
            },
        );
        self.compaction_versions
            .insert(session.scope.clone(), continuation_version);
        let result = MissionMemoryCompactionResult {
            token: artifact.token()?,
            continuation: artifact,
            visibility_receipt: MissionMemoryVisibilityReceipt {
                event_sequence: record.sequence,
                event_id: record.event_id,
                event_digest: record.event_digest,
                request_digest,
                projection_digest: continuation_digest,
            },
        };
        result.validate()?;
        Ok(result)
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "resume owns the immutable request and token snapshots that are durably bound to provenance"
    )]
    pub fn resume(
        &mut self,
        session: &MissionMemorySession,
        consumer_id: impl Into<String>,
        token: MissionMemoryContinuationToken,
        request: MissionMemoryResumeRequest,
    ) -> Result<MissionMemoryContinuationResult, MissionMemoryError>
    where
        P: MissionMemoryContinuationProvider,
    {
        let handle = self.validate_session(session)?.handle.clone();
        request.validate()?;
        token.validate()?;
        let consumer_id = consumer_id.into();
        if !bounded_text(&consumer_id, MAX_CONSUMER_ID_BYTES) {
            return Err(MissionMemoryError::InvalidRequest);
        }
        if token.scope != session.scope {
            return Err(MissionMemoryError::ScopeMismatch);
        }
        if token.source_generation >= session.generation
            || self
                .invalidated_compactions
                .contains(&token.continuation_digest)
        {
            return Err(MissionMemoryError::StaleGeneration);
        }
        let stored = self
            .compactions
            .get(&token.continuation_digest)
            .cloned()
            .ok_or(MissionMemoryError::InvalidContinuation)?;
        let artifact = stored.artifact;
        if artifact.digest()? != token.continuation_digest
            || artifact.source_generation != token.source_generation
            || artifact.continuation_version != token.continuation_version
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        let facts = self.facts_for_scope(&session.scope);
        validate_compaction_against_facts(&artifact, &facts, &artifact.counterevidence_fact_ids)?;
        let items = self
            .provider
            .restore_working_set(&handle, &facts, &artifact)?;
        if items != artifact.retained_items {
            return Err(MissionMemoryError::InvalidProviderOutput);
        }
        validate_item_list(&items, MAX_MEMORY_ITEMS)?;
        let working_set_revision = self
            .active
            .as_ref()
            .map(|active| active.next_working_set_revision)
            .ok_or(MissionMemoryError::NotMounted)?;
        let working_set = MissionMemoryWorkingSet {
            scope: session.scope.clone(),
            generation: session.generation,
            revision: working_set_revision,
            items,
        };
        let provenance = continuation_provenance(&artifact, &stored.record, session)?;
        let request_digest = resume_request_digest(session, &consumer_id, &token, &request)?;
        let result_digest = continuation_result_digest(&token, &working_set, &provenance)?;
        let record = self.append_event(MissionMemoryEvent::ContinuationResumed {
            session: session.clone(),
            consumer_id,
            request_digest: request_digest.clone(),
            token: token.clone(),
            working_set: Box::new(working_set.clone()),
            provenance: Box::new(provenance.clone()),
        })?;
        let result = MissionMemoryContinuationResult {
            token,
            working_set,
            provenance,
            visibility_receipt: MissionMemoryVisibilityReceipt {
                event_sequence: record.sequence,
                event_id: record.event_id,
                event_digest: record.event_digest,
                request_digest,
                projection_digest: result_digest,
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
        if cause.invalidates_compactions() {
            self.invalidate_compactions(&active.scope);
        }
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
            MissionMemoryEvent::ContinuationCompacted {
                session, artifact, ..
            } => self.apply_continuation_compacted(session, artifact, record)?,
            MissionMemoryEvent::ContinuationResumed {
                session,
                token,
                working_set,
                provenance,
                ..
            } => self.apply_continuation_resumed(session, token, working_set, provenance)?,
            MissionMemoryEvent::ProviderRecycled { session, cause } => {
                let Some(active) = &self.active else {
                    return Err(MissionMemoryError::InvalidEventLog);
                };
                if active.session != *session {
                    return Err(MissionMemoryError::InvalidEventLog);
                }
                self.active = None;
                if cause.invalidates_compactions() {
                    self.invalidate_compactions(&session.scope);
                }
            }
        }
        Ok(())
    }

    fn apply_continuation_compacted(
        &mut self,
        session: &MissionMemorySession,
        artifact: &MissionMemoryContinuationArtifact,
        record: &MissionMemoryEventRecord,
    ) -> Result<(), MissionMemoryError> {
        let Some(active) = &self.active else {
            return Err(MissionMemoryError::InvalidEventLog);
        };
        if active.session != *session
            || artifact.scope != session.scope
            || artifact.source_generation != session.generation
            || artifact.continuation_version != self.next_compaction_version(&session.scope)?
        {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        artifact.validate()?;
        let facts = self.facts_for_scope(&session.scope);
        validate_compaction_against_facts(artifact, &facts, &artifact.counterevidence_fact_ids)?;
        let digest = artifact.digest()?;
        if self.compactions.contains_key(&digest) {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        self.compaction_versions
            .insert(session.scope.clone(), artifact.continuation_version);
        self.compactions.insert(
            digest,
            StoredMissionMemoryCompaction {
                artifact: artifact.clone(),
                record: record.clone(),
            },
        );
        Ok(())
    }

    fn apply_continuation_resumed(
        &mut self,
        session: &MissionMemorySession,
        token: &MissionMemoryContinuationToken,
        working_set: &MissionMemoryWorkingSet,
        provenance: &MissionMemoryContinuationProvenance,
    ) -> Result<(), MissionMemoryError> {
        let Some(active) = &self.active else {
            return Err(MissionMemoryError::InvalidEventLog);
        };
        if active.session != *session || working_set.revision != active.next_working_set_revision {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        token.validate()?;
        if token.scope != session.scope || token.source_generation >= session.generation {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        let stored = self
            .compactions
            .get(&token.continuation_digest)
            .cloned()
            .ok_or(MissionMemoryError::InvalidEventLog)?;
        if self
            .invalidated_compactions
            .contains(&token.continuation_digest)
        {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        let artifact = stored.artifact;
        if artifact.digest()? != token.continuation_digest
            || artifact.source_generation != token.source_generation
            || artifact.continuation_version != token.continuation_version
        {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        let facts = self.facts_for_scope(&session.scope);
        validate_compaction_against_facts(&artifact, &facts, &artifact.counterevidence_fact_ids)?;
        working_set.validate()?;
        if working_set.scope != session.scope
            || working_set.generation != session.generation
            || working_set.items != artifact.retained_items
        {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        let expected = continuation_provenance(&artifact, &stored.record, session)?;
        if provenance != &expected {
            return Err(MissionMemoryError::InvalidEventLog);
        }
        let active = self
            .active
            .as_mut()
            .ok_or(MissionMemoryError::InvalidEventLog)?;
        active.next_working_set_revision = active
            .next_working_set_revision
            .checked_add(1)
            .ok_or(MissionMemoryError::EventSequence)?;
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

    fn next_compaction_version(
        &self,
        scope: &MissionMemoryScope,
    ) -> Result<u64, MissionMemoryError> {
        self.compaction_versions
            .get(scope)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(MissionMemoryError::InvalidContinuation)
    }

    fn invalidate_compactions(&mut self, scope: &MissionMemoryScope) {
        self.invalidated_compactions.extend(
            self.compactions
                .iter()
                .filter(|(_, stored)| stored.artifact.scope == *scope)
                .map(|(digest, _)| digest.clone()),
        );
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

impl MissionMemoryContinuationProvider for DeterministicMissionMemoryProvider {
    fn compact(
        &self,
        handle: &MissionMemoryProviderHandle,
        facts: &[MissionMemoryFact],
        continuation_version: u64,
        request: &MissionMemoryCompactionRequest,
    ) -> Result<MissionMemoryContinuationArtifact, MissionMemoryError> {
        self.handle_is_active(handle)?;
        request.validate()?;
        if continuation_version == 0 || facts.len() > MAX_COMPACTION_SOURCE_FACTS {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        for fact in facts {
            fact.validate()?;
            if fact.scope != *handle.scope() {
                return Err(MissionMemoryError::ScopeMismatch);
            }
        }
        let max_retained_items = usize::try_from(request.max_retained_items)
            .map_err(|_| MissionMemoryError::InvalidContinuation)?;
        if request.counterevidence_fact_ids.len() > max_retained_items {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        let mut ordered_facts = facts.to_vec();
        ordered_facts.sort_by(|left, right| {
            left.fact_revision
                .cmp(&right.fact_revision)
                .then_with(|| left.fact_id.cmp(&right.fact_id))
        });
        let source_fact_digests = ordered_facts
            .iter()
            .map(|fact| Ok((fact.fact_id.clone(), fact.digest()?)))
            .collect::<Result<BTreeMap<_, _>, MissionMemoryError>>()?;
        if request
            .counterevidence_fact_ids
            .iter()
            .any(|fact_id| !source_fact_digests.contains_key(fact_id))
        {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        let mut retained_ids = request.counterevidence_fact_ids.clone();
        for fact in ordered_facts.iter().rev() {
            if retained_ids.len() >= max_retained_items {
                break;
            }
            retained_ids.insert(fact.fact_id.clone());
        }
        let retained_items = ordered_facts
            .iter()
            .filter(|fact| retained_ids.contains(&fact.fact_id))
            .map(MissionMemoryFact::item)
            .collect::<Vec<_>>();
        let summary_digest = digest_json_with_domain(
            "hartevo.mission-memory-summary/v1",
            &(
                handle.scope(),
                continuation_version,
                &source_fact_digests,
                &retained_items,
                &request.counterevidence_fact_ids,
            ),
        )?;
        let artifact = MissionMemoryContinuationArtifact {
            scope: handle.scope().clone(),
            source_generation: handle.generation(),
            continuation_version,
            source_fact_digests,
            retained_items,
            counterevidence_fact_ids: request.counterevidence_fact_ids.clone(),
            summary_ref: format!("cas://mission-memory/continuation/{summary_digest}"),
            summary_digest,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    fn restore_working_set(
        &self,
        handle: &MissionMemoryProviderHandle,
        _facts: &[MissionMemoryFact],
        continuation: &MissionMemoryContinuationArtifact,
    ) -> Result<Vec<MissionMemoryItem>, MissionMemoryError> {
        self.handle_is_active(handle)?;
        continuation.validate()?;
        if continuation.scope != *handle.scope() {
            return Err(MissionMemoryError::ScopeMismatch);
        }
        Ok(continuation.retained_items.clone())
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

fn validate_item_list(
    items: &[MissionMemoryItem],
    maximum: usize,
) -> Result<(), MissionMemoryError> {
    if items.len() > maximum {
        return Err(MissionMemoryError::InvalidProviderOutput);
    }
    let mut ids = BTreeSet::new();
    let mut previous: Option<(u64, FactId)> = None;
    for item in items {
        item.validate()?;
        if !ids.insert(item.fact_id.clone()) {
            return Err(MissionMemoryError::InvalidProviderOutput);
        }
        let key = (item.fact_revision, item.fact_id.clone());
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return Err(MissionMemoryError::InvalidProviderOutput);
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_compaction_against_facts(
    artifact: &MissionMemoryContinuationArtifact,
    facts: &[MissionMemoryFact],
    expected_counterevidence: &BTreeSet<FactId>,
) -> Result<(), MissionMemoryError> {
    artifact.validate()?;
    if artifact.counterevidence_fact_ids != *expected_counterevidence {
        return Err(MissionMemoryError::InvalidContinuation);
    }
    let facts_by_id = facts
        .iter()
        .map(|fact| (fact.fact_id.clone(), fact))
        .collect::<BTreeMap<_, _>>();
    if facts_by_id.len() != facts.len() || artifact.source_fact_digests.len() != facts_by_id.len() {
        return Err(MissionMemoryError::InvalidContinuation);
    }
    for fact in facts {
        fact.validate()?;
        if fact.scope != artifact.scope {
            return Err(MissionMemoryError::InvalidContinuation);
        }
        let expected_digest = artifact
            .source_fact_digests
            .get(&fact.fact_id)
            .ok_or(MissionMemoryError::InvalidContinuation)?;
        if expected_digest != &fact.digest()? {
            return Err(MissionMemoryError::InvalidContinuation);
        }
    }
    if artifact
        .source_fact_digests
        .keys()
        .any(|fact_id| !facts_by_id.contains_key(fact_id))
    {
        return Err(MissionMemoryError::InvalidContinuation);
    }
    for item in &artifact.retained_items {
        let fact = facts_by_id
            .get(&item.fact_id)
            .ok_or(MissionMemoryError::InvalidContinuation)?;
        if item != &fact.item() {
            return Err(MissionMemoryError::InvalidContinuation);
        }
    }
    if artifact.counterevidence_fact_ids.iter().any(|fact_id| {
        !artifact
            .retained_items
            .iter()
            .any(|item| &item.fact_id == fact_id)
    }) {
        return Err(MissionMemoryError::InvalidContinuation);
    }
    Ok(())
}

fn continuation_provenance(
    artifact: &MissionMemoryContinuationArtifact,
    record: &MissionMemoryEventRecord,
    session: &MissionMemorySession,
) -> Result<MissionMemoryContinuationProvenance, MissionMemoryError> {
    let MissionMemoryEvent::ContinuationCompacted {
        artifact: recorded_artifact,
        ..
    } = &record.event
    else {
        return Err(MissionMemoryError::InvalidEventLog);
    };
    if recorded_artifact.as_ref() != artifact {
        return Err(MissionMemoryError::InvalidEventLog);
    }
    Ok(MissionMemoryContinuationProvenance {
        source_compaction_event_sequence: record.sequence,
        source_compaction_event_digest: record.event_digest.clone(),
        source_continuation_digest: artifact.digest()?,
        source_generation: artifact.source_generation,
        resumed_generation: session.generation,
        source_fact_digests: artifact.source_fact_digests.clone(),
    })
}

fn continuation_result_digest(
    token: &MissionMemoryContinuationToken,
    working_set: &MissionMemoryWorkingSet,
    provenance: &MissionMemoryContinuationProvenance,
) -> Result<String, MissionMemoryError> {
    digest_json_with_domain(
        "hartevo.mission-memory-continuation-result/v1",
        &(token, working_set, provenance),
    )
}

fn compaction_request_digest(
    session: &MissionMemorySession,
    consumer_id: &str,
    continuation_version: u64,
    request: &MissionMemoryCompactionRequest,
) -> Result<String, MissionMemoryError> {
    digest_json_with_domain(
        "hartevo.mission-memory-compaction-request/v1",
        &(session, consumer_id, continuation_version, request),
    )
}

fn resume_request_digest(
    session: &MissionMemorySession,
    consumer_id: &str,
    token: &MissionMemoryContinuationToken,
    request: &MissionMemoryResumeRequest,
) -> Result<String, MissionMemoryError> {
    digest_json_with_domain(
        "hartevo.mission-memory-resume-request/v1",
        &(session, consumer_id, token, request),
    )
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
        continuations: Vec<MissionMemoryContinuationResult>,
    }

    impl RecordingConsumer {
        fn new(id: impl Into<String>) -> Self {
            Self {
                id: id.into(),
                seen: Vec::new(),
                continuations: Vec::new(),
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

        fn observe_continuation(
            &mut self,
            result: &MissionMemoryContinuationResult,
        ) -> Result<(), MissionMemoryError> {
            self.continuations.push(result.clone());
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

    fn compaction_request(
        id: &str,
        max_retained_items: u32,
        counterevidence_fact_ids: &[&str],
    ) -> MissionMemoryCompactionRequest {
        MissionMemoryCompactionRequest {
            request_id: id.into(),
            max_retained_items,
            counterevidence_fact_ids: counterevidence_fact_ids
                .iter()
                .map(|fact_id| FactId::from(*fact_id))
                .collect(),
            requested_at: at(40),
        }
    }

    fn resume_request(id: &str) -> MissionMemoryResumeRequest {
        MissionMemoryResumeRequest {
            request_id: id.into(),
            requested_at: at(41),
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
    fn compaction_is_equivalent_to_the_exact_working_set_and_not_a_new_fact() {
        let mut service = new_service(TestLog::default());
        let scope = scope("mission-compaction-equivalence");
        let session = service.mount(scope.clone()).expect("mount");
        for revision in 1..=3 {
            let id = format!("fact-{revision}");
            service
                .append_fact(&session, fact(&scope, revision, &id))
                .expect("fact");
        }
        let direct = service
            .read(&session, "continuation-consumer", read_request("direct"))
            .expect("direct working set");
        let compacted = service
            .compact(
                &session,
                "continuation-consumer",
                compaction_request("compact", 32, &[]),
            )
            .expect("compact");
        assert_eq!(
            direct.working_set().items,
            compacted.continuation.retained_items
        );
        assert_eq!(
            compacted.token.continuation_digest,
            compacted
                .continuation
                .digest()
                .expect("continuation digest")
        );
        assert!(compacted.continuation.summary_ref.starts_with("cas://"));
        let records = service.durable_log().replay().expect("replay");
        assert_eq!(
            records
                .iter()
                .filter(|record| matches!(record.event, MissionMemoryEvent::FactAppended { .. }))
                .count(),
            3
        );
        assert!(!records.iter().any(|record| {
            matches!(
                &record.event,
                MissionMemoryEvent::FactAppended { fact }
                    if fact.payload_ref == compacted.continuation.summary_ref
            )
        }));
        assert!(matches!(
            service.resume(
                &session,
                "continuation-consumer",
                compacted.token,
                resume_request("same-generation"),
            ),
            Err(MissionMemoryError::StaleGeneration)
        ));
    }

    #[test]
    fn counterevidence_is_retained_when_compaction_window_is_narrow() {
        let mut service = new_service(TestLog::default());
        let scope = scope("mission-counterevidence");
        let session = service.mount(scope.clone()).expect("mount");
        for revision in 1..=3 {
            let id = format!("fact-{revision}");
            service
                .append_fact(&session, fact(&scope, revision, &id))
                .expect("fact");
        }
        let compacted = service
            .compact(
                &session,
                "counterevidence-consumer",
                compaction_request("protected", 1, &["fact-2"]),
            )
            .expect("compact with protected counterevidence");
        assert_eq!(
            compacted.continuation.counterevidence_fact_ids,
            BTreeSet::from([FactId::from("fact-2")])
        );
        assert_eq!(
            compacted
                .continuation
                .retained_items
                .iter()
                .map(|item| item.fact_id.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([FactId::from("fact-2")])
        );
    }

    #[test]
    fn restart_replay_restores_exact_items_and_durable_provenance() {
        let mut service = new_service(TestLog::default());
        let scope = scope("mission-continuation-restart");
        let old_session = service.mount(scope.clone()).expect("mount");
        for revision in 1..=3 {
            let id = format!("fact-{revision}");
            service
                .append_fact(&old_session, fact(&scope, revision, &id))
                .expect("fact");
        }
        let compacted = service
            .compact(
                &old_session,
                "restart-consumer",
                compaction_request("before-restart", 2, &["fact-1"]),
            )
            .expect("compact");
        let token = compacted.token.clone();
        let retained_items = compacted.continuation.retained_items.clone();
        let source_event_sequence = compacted.visibility_receipt.event_sequence;
        let source_event_digest = compacted.visibility_receipt.event_digest.clone();
        let source_continuation_digest = token.continuation_digest.clone();
        let (log, _) = service.into_parts();

        let mut reopened = new_service(log);
        let fresh_session = reopened.mount(scope).expect("new generation");
        assert_eq!(fresh_session.generation(), 2);
        let mut consumer = RecordingConsumer::new("restart-consumer");
        let resumed = reopened
            .resume_for_consumer(
                &fresh_session,
                &mut consumer,
                token.clone(),
                resume_request("after-restart"),
            )
            .expect("resume exact continuation");
        assert_eq!(consumer.continuations, vec![resumed.clone()]);
        assert_eq!(resumed.token, token);
        assert_eq!(resumed.working_set.items, retained_items);
        assert_eq!(
            resumed.provenance.source_compaction_event_sequence,
            source_event_sequence
        );
        assert_eq!(
            resumed.provenance.source_compaction_event_digest,
            source_event_digest
        );
        assert_eq!(
            resumed.provenance.source_continuation_digest,
            source_continuation_digest
        );
        assert_eq!(resumed.provenance.source_generation, 1);
        assert_eq!(resumed.provenance.resumed_generation, 2);
        let records = reopened.durable_log().replay().expect("replay");
        let resumed_event = records
            .iter()
            .find_map(|record| match &record.event {
                MissionMemoryEvent::ContinuationResumed {
                    token: event_token,
                    working_set,
                    provenance,
                    ..
                } => Some((event_token, working_set, provenance)),
                _ => None,
            })
            .expect("durable resume event");
        assert_eq!(resumed_event.0, &resumed.token);
        assert_eq!(resumed_event.1.as_ref(), &resumed.working_set);
        assert_eq!(resumed_event.2.as_ref(), &resumed.provenance);

        let (replayed_log, _) = reopened.into_parts();
        let replayed = new_service(replayed_log);
        assert_eq!(replayed.active_session(), None);
        assert_eq!(replayed.last_generation(), 2);
    }

    #[test]
    fn revoke_unmount_and_cross_mission_cannot_restore_a_continuation() {
        let mut service = new_service(TestLog::default());
        let scope_a = scope("mission-continuation-revoke");
        let source_session = service.mount(scope_a.clone()).expect("mount");
        service
            .append_fact(&source_session, fact(&scope_a, 1, "fact-a"))
            .expect("fact");
        let compacted = service
            .compact(
                &source_session,
                "revoke-consumer",
                compaction_request("before-revoke", 8, &[]),
            )
            .expect("compact");
        service.revoke(&source_session).expect("revoke");
        let fresh_same_mission = service.mount(scope_a).expect("fresh generation");
        assert!(matches!(
            service.resume(
                &fresh_same_mission,
                "revoke-consumer",
                compacted.token.clone(),
                resume_request("after-revoke"),
            ),
            Err(MissionMemoryError::StaleGeneration)
        ));
        service
            .unmount(&fresh_same_mission)
            .expect("unmount fresh generation");
        let other_mission = service
            .mount(scope("mission-continuation-other"))
            .expect("mount other mission");
        assert!(matches!(
            service.resume(
                &other_mission,
                "revoke-consumer",
                compacted.token,
                resume_request("cross-mission"),
            ),
            Err(MissionMemoryError::ScopeMismatch)
        ));
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
