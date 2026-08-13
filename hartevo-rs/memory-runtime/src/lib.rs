//! Mission-scoped, consent-gated memory candidates.
//!
//! This crate is a plugin boundary, not a replacement for the Context or
//! Storage facts.  A caller supplies already-durable, secret-free source
//! event metadata; the deterministic store keeps a content-controlled event
//! log and never reaches into a raw store, keyring, or effect authority.  Only
//! an explicit adoption can make a candidate queryable by a later Mission.

use std::{collections::BTreeMap, fmt};

use hartevo_plugin_runtime::{
    Digest, MissionId, PluginDefinitionHandle, PluginId, PluginScope, PluginVersion, ProjectId,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MEMORY_RUNTIME_SCHEMA: &str = "hartevo.memory-runtime/v1";
pub const MEMORY_POLICY_SCHEMA: &str = "hartevo.memory-policy/v1";
pub const MAX_MEMORY_BYTES: usize = 16 * 1024;

fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

fn canonical_digest<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("memory runtime values serialize");
    digest_bytes(&bytes)
}

fn valid_digest(value: &Digest) -> bool {
    value.as_str().len() == 64 && value.as_str().bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
pub enum MemoryRuntimeError {
    #[error("memory scope is invalid")]
    InvalidScope,
    #[error("memory source event is invalid or stale")]
    InvalidSource,
    #[error("memory source revision is stale")]
    SourceStale,
    #[error("memory candidate payload is invalid")]
    InvalidPayload,
    #[error("memory policy requires explicit adoption")]
    ConsentRequired,
    #[error("memory candidate was not found")]
    CandidateNotFound,
    #[error("memory candidate is already adopted")]
    AlreadyAdopted,
    #[error("memory candidate is already forgotten")]
    AlreadyForgotten,
    #[error("memory candidate is not adopted")]
    NotAdopted,
    #[error("memory candidate scope does not match the requested Mission")]
    ScopeMismatch,
    #[error("memory plugin is not mounted")]
    PluginInactive,
    #[error("memory plugin was revoked")]
    PluginRevoked,
    #[error("memory plugin upgrade requires an explicit migration")]
    PluginUpgradeRequiresMigration,
    #[error("memory candidate history is malformed")]
    InvalidHistory,
    #[error("memory candidate event is duplicated")]
    DuplicateEvent,
    #[error("memory candidate lifecycle transition is invalid")]
    LifecycleViolation,
    #[error("memory candidate policy does not match durable history")]
    PolicyMismatch,
    #[error("memory candidate plugin binding does not match durable history")]
    PluginMismatch,
    #[error("memory candidate consent is not explicit")]
    InvalidConsent,
    #[error("memory candidate digest is invalid")]
    InvalidDigest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCandidateClass {
    Preference,
    Fact,
    Procedure,
    SourceLink,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySourceKind {
    Conversation,
    ToolResult,
    Result,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryApplicability {
    Mission,
    Project,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryConsent {
    Explicit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryPluginLifecycle {
    Mounted,
    Revoked,
    Unmounted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRevocationReason {
    Revoked,
    Unmounted,
}

/// A controlled payload boundary.  Secret payloads can be represented by a
/// provider for negative tests, but proposal rejects them before any event is
/// written and no public Debug implementation prints their contents.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub enum MemoryPayload {
    Public(String),
    Secret(String),
}

impl fmt::Debug for MemoryPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryPayload")
            .field("class", &self.class_label())
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

impl MemoryPayload {
    pub fn public(value: impl Into<String>) -> Result<Self, MemoryRuntimeError> {
        let value = value.into();
        validate_payload(&value)?;
        Ok(Self::Public(value))
    }

    pub fn secret(value: impl Into<String>) -> Result<Self, MemoryRuntimeError> {
        let value = value.into();
        validate_payload(&value)?;
        Ok(Self::Secret(value))
    }

    pub fn is_secret(&self) -> bool {
        matches!(self, Self::Secret(_))
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Public(value) | Self::Secret(value) => value,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }

    fn class_label(&self) -> &'static str {
        if self.is_secret() { "secret" } else { "public" }
    }
}

fn validate_payload(value: &str) -> Result<(), MemoryRuntimeError> {
    if value.trim().is_empty() || value.len() > MAX_MEMORY_BYTES || value.contains('\0') {
        return Err(MemoryRuntimeError::InvalidPayload);
    }
    Ok(())
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryPolicy {
    version: u32,
    digest: Digest,
    explicit_adoption: bool,
}

impl fmt::Debug for MemoryPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryPolicy")
            .field("version", &self.version)
            .field("digest_present", &true)
            .field("explicit_adoption", &self.explicit_adoption)
            .finish_non_exhaustive()
    }
}

impl MemoryPolicy {
    pub fn explicit_only(version: u32, digest: Digest) -> Result<Self, MemoryRuntimeError> {
        let policy = Self {
            version,
            digest,
            explicit_adoption: true,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn from_parts(
        version: u32,
        digest: Digest,
        explicit_adoption: bool,
    ) -> Result<Self, MemoryRuntimeError> {
        let policy = Self {
            version,
            digest,
            explicit_adoption,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub const fn version(&self) -> u32 {
        self.version
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    fn validate(&self) -> Result<(), MemoryRuntimeError> {
        if self.version == 0 || !valid_digest(&self.digest) || !self.explicit_adoption {
            return Err(MemoryRuntimeError::ConsentRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryPluginBinding {
    plugin_id: PluginId,
    version: PluginVersion,
    plugin_digest: Digest,
    project_id: ProjectId,
    mission_id: MissionId,
    generation: u64,
}

impl fmt::Debug for MemoryPluginBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryPluginBinding")
            .field(
                "plugin_id_digest",
                &Digest::from_text(self.plugin_id.as_str()),
            )
            .field("version", &self.version)
            .field("plugin_digest", &self.plugin_digest)
            .field("scope_digest", &self.scope_digest())
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl MemoryPluginBinding {
    pub fn from_handle(handle: &PluginDefinitionHandle) -> Self {
        let scope = handle.scope();
        Self {
            plugin_id: handle.plugin_id().clone(),
            version: handle.version(),
            plugin_digest: handle.digest().clone(),
            project_id: scope.project_id().clone(),
            mission_id: scope.mission_id().clone(),
            generation: scope.generation(),
        }
    }

    pub fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    pub const fn version(&self) -> PluginVersion {
        self.version
    }

    pub fn plugin_digest(&self) -> &Digest {
        &self.plugin_digest
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn scope_digest(&self) -> Digest {
        canonical_digest(&(
            &self.project_id,
            &self.mission_id,
            self.generation,
            &self.plugin_id,
            self.version,
            &self.plugin_digest,
        ))
    }

    fn validate(&self) -> Result<(), MemoryRuntimeError> {
        if self.generation == 0 || !valid_digest(&self.plugin_digest) {
            return Err(MemoryRuntimeError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemorySourceEvent {
    project_id: ProjectId,
    mission_id: MissionId,
    revision: u64,
    kind: MemorySourceKind,
    event_digest: Digest,
    content_digest: Digest,
    secret_free: bool,
}

impl fmt::Debug for MemorySourceEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemorySourceEvent")
            .field("scope_digest", &self.scope_digest())
            .field("revision", &self.revision)
            .field("kind", &self.kind)
            .field("event_digest", &self.event_digest)
            .field("content_digest", &self.content_digest)
            .field("secret_free", &self.secret_free)
            .finish_non_exhaustive()
    }
}

impl MemorySourceEvent {
    pub fn new(
        project_id: ProjectId,
        mission_id: MissionId,
        event_digest: Digest,
        revision: u64,
        kind: MemorySourceKind,
        content_digest: Digest,
        secret_free: bool,
    ) -> Result<Self, MemoryRuntimeError> {
        if revision == 0 || !valid_digest(&event_digest) || !valid_digest(&content_digest) {
            return Err(MemoryRuntimeError::InvalidSource);
        }
        Ok(Self {
            project_id,
            mission_id,
            revision,
            kind,
            event_digest,
            content_digest,
            secret_free,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn kind(&self) -> MemorySourceKind {
        self.kind
    }

    pub fn event_digest(&self) -> &Digest {
        &self.event_digest
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub const fn secret_free(&self) -> bool {
        self.secret_free
    }

    fn scope_digest(&self) -> Digest {
        canonical_digest(&(&self.project_id, &self.mission_id))
    }

    fn validate(&self) -> Result<(), MemoryRuntimeError> {
        if self.revision == 0
            || !valid_digest(&self.event_digest)
            || !valid_digest(&self.content_digest)
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
        {
            return Err(MemoryRuntimeError::InvalidSource);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct MemoryCandidateDraft {
    classification: MemoryCandidateClass,
    payload: MemoryPayload,
    confidence: u8,
    applicability: MemoryApplicability,
}

impl fmt::Debug for MemoryCandidateDraft {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryCandidateDraft")
            .field("classification", &self.classification)
            .field("payload", &self.payload)
            .field("confidence", &self.confidence)
            .field("applicability", &self.applicability)
            .finish_non_exhaustive()
    }
}

impl MemoryCandidateDraft {
    pub fn new(
        classification: MemoryCandidateClass,
        payload: MemoryPayload,
        confidence: u8,
        applicability: MemoryApplicability,
    ) -> Result<Self, MemoryRuntimeError> {
        if confidence > 100 || payload.as_str().trim().is_empty() {
            return Err(MemoryRuntimeError::InvalidPayload);
        }
        Ok(Self {
            classification,
            payload,
            confidence,
            applicability,
        })
    }

    pub const fn classification(&self) -> MemoryCandidateClass {
        self.classification
    }

    pub fn payload(&self) -> &MemoryPayload {
        &self.payload
    }

    pub const fn confidence(&self) -> u8 {
        self.confidence
    }

    pub const fn applicability(&self) -> MemoryApplicability {
        self.applicability
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryCandidateStatus {
    Proposed,
    Adopted,
    Forgotten,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryEventKind {
    Proposed,
    Adopted,
    Recalled,
    Forgotten,
    Revoked,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryLifecycleEvent {
    sequence: u64,
    kind: MemoryEventKind,
    candidate_id: Digest,
    project_id: ProjectId,
    source_mission_id: MissionId,
    target_mission_id: Option<MissionId>,
    source_event_digest: Digest,
    source_content_digest: Digest,
    source_revision: u64,
    source_kind: MemorySourceKind,
    classification: MemoryCandidateClass,
    payload: Option<MemoryPayload>,
    content_digest: Digest,
    confidence: u8,
    applicability: MemoryApplicability,
    policy: MemoryPolicy,
    plugin: MemoryPluginBinding,
    consent: Option<MemoryConsent>,
    reason: Option<MemoryRevocationReason>,
}

impl fmt::Debug for MemoryLifecycleEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryLifecycleEvent")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("candidate_id", &self.candidate_id)
            .field("scope_digest", &self.scope_digest())
            .field("payload_present", &self.payload.is_some())
            .field("classification", &self.classification)
            .finish_non_exhaustive()
    }
}

impl MemoryLifecycleEvent {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn kind(&self) -> MemoryEventKind {
        self.kind
    }

    pub fn candidate_id(&self) -> &Digest {
        &self.candidate_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn source_mission_id(&self) -> &MissionId {
        &self.source_mission_id
    }

    pub fn source_event_digest(&self) -> &Digest {
        &self.source_event_digest
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub fn content_digest(&self) -> &Digest {
        &self.content_digest
    }

    pub const fn classification(&self) -> MemoryCandidateClass {
        self.classification
    }

    pub fn payload(&self) -> Option<&MemoryPayload> {
        self.payload.as_ref()
    }

    pub fn target_mission_id(&self) -> Option<&MissionId> {
        self.target_mission_id.as_ref()
    }

    fn scope_digest(&self) -> Digest {
        canonical_digest(&(
            &self.project_id,
            &self.source_mission_id,
            &self.target_mission_id,
        ))
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryCandidateReceipt {
    candidate_id: Digest,
    event_sequence: u64,
    status: MemoryCandidateStatus,
}

impl fmt::Debug for MemoryCandidateReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryCandidateReceipt")
            .field("status", &self.status)
            .field("event_sequence", &self.event_sequence)
            .finish_non_exhaustive()
    }
}

impl MemoryCandidateReceipt {
    pub fn candidate_id(&self) -> &Digest {
        &self.candidate_id
    }

    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    pub const fn status(&self) -> MemoryCandidateStatus {
        self.status
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryAdoptionReceipt {
    candidate_id: Digest,
    event_sequence: u64,
}

impl fmt::Debug for MemoryAdoptionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryAdoptionReceipt")
            .field("event_sequence", &self.event_sequence)
            .finish_non_exhaustive()
    }
}

impl MemoryAdoptionReceipt {
    pub fn candidate_id(&self) -> &Digest {
        &self.candidate_id
    }

    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryForgetReceipt {
    candidate_id: Digest,
    event_sequence: u64,
}

impl fmt::Debug for MemoryForgetReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryForgetReceipt")
            .field("event_sequence", &self.event_sequence)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryRevocationReceipt {
    reason: MemoryRevocationReason,
    first_event_sequence: Option<u64>,
    event_count: usize,
}

impl fmt::Debug for MemoryRevocationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryRevocationReceipt")
            .field("reason", &self.reason)
            .field("event_count", &self.event_count)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryQueryReceipt {
    target_mission_id: MissionId,
    first_event_sequence: Option<u64>,
    recalled_count: usize,
}

impl fmt::Debug for MemoryQueryReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryQueryReceipt")
            .field("target_scope_present", &true)
            .field("recalled_count", &self.recalled_count)
            .finish_non_exhaustive()
    }
}

impl MemoryQueryReceipt {
    pub const fn recalled_count(&self) -> usize {
        self.recalled_count
    }
}

#[derive(Clone, Eq, PartialEq)]
struct CandidateRecord {
    candidate_id: Digest,
    project_id: ProjectId,
    source_mission_id: MissionId,
    source_event_digest: Digest,
    source_content_digest: Digest,
    source_revision: u64,
    source_kind: MemorySourceKind,
    classification: MemoryCandidateClass,
    payload: MemoryPayload,
    content_digest: Digest,
    confidence: u8,
    applicability: MemoryApplicability,
    policy: MemoryPolicy,
    plugin: MemoryPluginBinding,
    status: MemoryCandidateStatus,
}

#[derive(Clone, Default)]
struct EventExtras {
    target_mission_id: Option<MissionId>,
    consent: Option<MemoryConsent>,
    reason: Option<MemoryRevocationReason>,
}

impl CandidateRecord {
    fn view(&self) -> MemoryRecall {
        MemoryRecall {
            candidate_id: self.candidate_id.clone(),
            source_mission_id: self.source_mission_id.clone(),
            source_event_digest: self.source_event_digest.clone(),
            source_revision: self.source_revision,
            classification: self.classification,
            payload: self.payload.clone(),
            confidence: self.confidence,
            applicability: self.applicability,
            policy: self.policy.clone(),
            plugin: self.plugin.clone(),
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryRecall {
    candidate_id: Digest,
    source_mission_id: MissionId,
    source_event_digest: Digest,
    source_revision: u64,
    classification: MemoryCandidateClass,
    payload: MemoryPayload,
    confidence: u8,
    applicability: MemoryApplicability,
    policy: MemoryPolicy,
    plugin: MemoryPluginBinding,
}

impl fmt::Debug for MemoryRecall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryRecall")
            .field("candidate_id", &self.candidate_id)
            .field(
                "source_mission_id_digest",
                &Digest::from_text(self.source_mission_id.as_str()),
            )
            .field("source_event_digest", &self.source_event_digest)
            .field("source_revision", &self.source_revision)
            .field("classification", &self.classification)
            .field("payload", &self.payload)
            .field("confidence", &self.confidence)
            .field("applicability", &self.applicability)
            .finish_non_exhaustive()
    }
}

impl MemoryRecall {
    pub fn candidate_id(&self) -> &Digest {
        &self.candidate_id
    }

    pub fn source_mission_id(&self) -> &MissionId {
        &self.source_mission_id
    }

    pub fn source_event_digest(&self) -> &Digest {
        &self.source_event_digest
    }

    pub const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub const fn classification(&self) -> MemoryCandidateClass {
        self.classification
    }

    pub fn payload(&self) -> &MemoryPayload {
        &self.payload
    }

    pub const fn confidence(&self) -> u8 {
        self.confidence
    }

    pub const fn applicability(&self) -> MemoryApplicability {
        self.applicability
    }

    pub fn policy(&self) -> &MemoryPolicy {
        &self.policy
    }

    pub fn plugin(&self) -> &MemoryPluginBinding {
        &self.plugin
    }
}

/// Deterministic local plugin seam.  The event vector is the durable test
/// boundary; production SQLCipher/keyring integration is deliberately outside
/// this crate and must supply the same typed events later.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MemoryStore {
    events: Vec<MemoryLifecycleEvent>,
    #[serde(skip)]
    sources: BTreeMap<Digest, MemorySourceEvent>,
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryStore")
            .field("event_count", &self.events.len())
            .field("source_count", &self.sources.len())
            .finish_non_exhaustive()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_events(events: Vec<MemoryLifecycleEvent>) -> Result<Self, MemoryRuntimeError> {
        let mut store = Self {
            events,
            sources: BTreeMap::new(),
        };
        store.rebuild_sources();
        store.validate()?;
        Ok(store)
    }

    pub fn events(&self) -> &[MemoryLifecycleEvent] {
        &self.events
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn register_source(&mut self, source: MemorySourceEvent) -> Result<(), MemoryRuntimeError> {
        source.validate()?;
        self.sources.insert(source.event_digest.clone(), source);
        Ok(())
    }

    fn rebuild_sources(&mut self) {
        self.sources.clear();
        for event in &self.events {
            if event.kind == MemoryEventKind::Proposed
                && let Ok(source) = MemorySourceEvent::from_event(event)
            {
                self.sources.insert(source.event_digest.clone(), source);
            }
        }
    }

    fn source(&self, digest: &Digest) -> Option<&MemorySourceEvent> {
        self.sources.get(digest)
    }

    fn records(&self) -> Result<BTreeMap<Digest, CandidateRecord>, MemoryRuntimeError> {
        let mut records = BTreeMap::new();
        for event in &self.events {
            match event.kind {
                MemoryEventKind::Proposed => {
                    if records.contains_key(&event.candidate_id) {
                        return Err(MemoryRuntimeError::DuplicateEvent);
                    }
                    let payload = event
                        .payload
                        .clone()
                        .ok_or(MemoryRuntimeError::InvalidHistory)?;
                    records.insert(
                        event.candidate_id.clone(),
                        CandidateRecord::from_event(event, payload)?,
                    );
                }
                MemoryEventKind::Adopted => {
                    let record = records
                        .get_mut(&event.candidate_id)
                        .ok_or(MemoryRuntimeError::InvalidHistory)?;
                    if !record.matches_event(event)
                        || record.status != MemoryCandidateStatus::Proposed
                        || event.consent != Some(MemoryConsent::Explicit)
                    {
                        return Err(MemoryRuntimeError::InvalidHistory);
                    }
                    record.status = MemoryCandidateStatus::Adopted;
                }
                MemoryEventKind::Recalled => {
                    let record = records
                        .get(&event.candidate_id)
                        .ok_or(MemoryRuntimeError::InvalidHistory)?;
                    if !record.matches_event(event)
                        || record.status != MemoryCandidateStatus::Adopted
                        || event.target_mission_id.is_none()
                    {
                        return Err(MemoryRuntimeError::InvalidHistory);
                    }
                }
                MemoryEventKind::Forgotten => {
                    let record = records
                        .get_mut(&event.candidate_id)
                        .ok_or(MemoryRuntimeError::InvalidHistory)?;
                    if !record.matches_event(event)
                        || record.status != MemoryCandidateStatus::Adopted
                    {
                        return Err(MemoryRuntimeError::InvalidHistory);
                    }
                    record.status = MemoryCandidateStatus::Forgotten;
                }
                MemoryEventKind::Revoked => {
                    let record = records
                        .get_mut(&event.candidate_id)
                        .ok_or(MemoryRuntimeError::InvalidHistory)?;
                    if !record.matches_event(event)
                        || event.reason.is_none()
                        || matches!(
                            record.status,
                            MemoryCandidateStatus::Forgotten | MemoryCandidateStatus::Revoked
                        )
                    {
                        return Err(MemoryRuntimeError::InvalidHistory);
                    }
                    record.status = MemoryCandidateStatus::Revoked;
                }
            }
        }
        Ok(records)
    }

    fn append_batch(
        &mut self,
        additions: &[MemoryLifecycleEvent],
    ) -> Result<(), MemoryRuntimeError> {
        let mut next = self.clone();
        let first_sequence = next
            .events
            .len()
            .checked_add(1)
            .ok_or(MemoryRuntimeError::InvalidHistory)? as u64;
        for (offset, addition) in additions.iter().cloned().enumerate() {
            let mut event = addition;
            event.sequence = first_sequence
                .checked_add(offset as u64)
                .ok_or(MemoryRuntimeError::InvalidHistory)?;
            next.events.push(event);
        }
        next.validate()?;
        *self = next;
        Ok(())
    }

    fn validate(&self) -> Result<(), MemoryRuntimeError> {
        let mut expected = 1u64;
        for event in &self.events {
            if event.sequence != expected {
                return Err(MemoryRuntimeError::InvalidHistory);
            }
            event.validate()?;
            expected = expected
                .checked_add(1)
                .ok_or(MemoryRuntimeError::InvalidHistory)?;
        }
        self.records().map(|_| ())
    }
}

impl MemoryLifecycleEvent {
    fn validate(&self) -> Result<(), MemoryRuntimeError> {
        if self.sequence == 0
            || !valid_digest(&self.candidate_id)
            || !valid_digest(&self.source_event_digest)
            || !valid_digest(&self.source_content_digest)
            || !valid_digest(&self.content_digest)
            || self.source_revision == 0
            || self.confidence > 100
            || self.project_id.as_str().trim().is_empty()
            || self.source_mission_id.as_str().trim().is_empty()
        {
            return Err(MemoryRuntimeError::InvalidHistory);
        }
        self.policy.validate()?;
        self.plugin.validate()?;
        match self.kind {
            MemoryEventKind::Proposed => {
                if self.payload.is_none() || self.consent.is_some() || self.reason.is_some() {
                    return Err(MemoryRuntimeError::InvalidHistory);
                }
            }
            MemoryEventKind::Adopted => {
                if self.payload.is_some()
                    || self.consent != Some(MemoryConsent::Explicit)
                    || self.reason.is_some()
                {
                    return Err(MemoryRuntimeError::InvalidHistory);
                }
            }
            MemoryEventKind::Recalled => {
                if self.payload.is_some()
                    || self.target_mission_id.is_none()
                    || self.consent.is_some()
                    || self.reason.is_some()
                {
                    return Err(MemoryRuntimeError::InvalidHistory);
                }
            }
            MemoryEventKind::Forgotten => {
                if self.payload.is_some() || self.consent.is_some() || self.reason.is_some() {
                    return Err(MemoryRuntimeError::InvalidHistory);
                }
            }
            MemoryEventKind::Revoked => {
                if self.payload.is_some() || self.consent.is_some() || self.reason.is_none() {
                    return Err(MemoryRuntimeError::InvalidHistory);
                }
            }
        }
        Ok(())
    }

    fn candidate_key(&self) -> Digest {
        canonical_digest(&(
            &self.project_id,
            &self.source_mission_id,
            self.plugin.generation(),
            &self.plugin,
            &self.policy,
            &self.source_event_digest,
            self.source_revision,
            &self.source_content_digest,
            self.source_kind,
            self.classification,
            &self.content_digest,
            self.confidence,
            self.applicability,
        ))
    }
}

impl MemorySourceEvent {
    fn from_event(event: &MemoryLifecycleEvent) -> Result<Self, MemoryRuntimeError> {
        let source = Self {
            project_id: event.project_id.clone(),
            mission_id: event.source_mission_id.clone(),
            revision: event.source_revision,
            kind: event.source_kind,
            event_digest: event.source_event_digest.clone(),
            content_digest: event.source_content_digest.clone(),
            secret_free: true,
        };
        source.validate()?;
        Ok(source)
    }
}

impl CandidateRecord {
    fn matches_event(&self, event: &MemoryLifecycleEvent) -> bool {
        self.candidate_id == event.candidate_id
            && self.project_id == event.project_id
            && self.source_mission_id == event.source_mission_id
            && self.source_event_digest == event.source_event_digest
            && self.source_content_digest == event.source_content_digest
            && self.source_revision == event.source_revision
            && self.source_kind == event.source_kind
            && self.classification == event.classification
            && self.content_digest == event.content_digest
            && self.confidence == event.confidence
            && self.applicability == event.applicability
            && self.policy == event.policy
            && self.plugin == event.plugin
    }

    fn from_event(
        event: &MemoryLifecycleEvent,
        payload: MemoryPayload,
    ) -> Result<Self, MemoryRuntimeError> {
        let record = Self {
            candidate_id: event.candidate_id.clone(),
            project_id: event.project_id.clone(),
            source_mission_id: event.source_mission_id.clone(),
            source_event_digest: event.source_event_digest.clone(),
            source_content_digest: event.source_content_digest.clone(),
            source_revision: event.source_revision,
            source_kind: event.source_kind,
            classification: event.classification,
            content_digest: event.content_digest.clone(),
            confidence: event.confidence,
            applicability: event.applicability,
            policy: event.policy.clone(),
            plugin: event.plugin.clone(),
            payload,
            status: MemoryCandidateStatus::Proposed,
        };
        if record.candidate_id != event.candidate_key() {
            return Err(MemoryRuntimeError::InvalidHistory);
        }
        if record.payload.digest() != record.content_digest || record.payload.is_secret() {
            return Err(MemoryRuntimeError::InvalidHistory);
        }
        Ok(record)
    }
}

pub struct MemoryCandidateService {
    scope: PluginScope,
    binding: MemoryPluginBinding,
    policy: MemoryPolicy,
    lifecycle: MemoryPluginLifecycle,
    store: MemoryStore,
}

impl fmt::Debug for MemoryCandidateService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryCandidateService")
            .field("scope_digest", &self.scope.digest())
            .field("plugin", &self.binding)
            .field("policy", &self.policy)
            .field("lifecycle", &self.lifecycle)
            .field("event_count", &self.store.event_count())
            .finish_non_exhaustive()
    }
}

impl MemoryCandidateService {
    pub fn new(
        scope: PluginScope,
        binding: MemoryPluginBinding,
        policy: MemoryPolicy,
    ) -> Result<Self, MemoryRuntimeError> {
        binding.validate()?;
        policy.validate()?;
        if binding.project_id() != scope.project_id()
            || binding.mission_id() != scope.mission_id()
            || binding.generation() != scope.generation()
        {
            return Err(MemoryRuntimeError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            binding,
            policy,
            lifecycle: MemoryPluginLifecycle::Mounted,
            store: MemoryStore::new(),
        })
    }

    pub fn from_events(
        scope: PluginScope,
        binding: MemoryPluginBinding,
        policy: MemoryPolicy,
        events: Vec<MemoryLifecycleEvent>,
    ) -> Result<Self, MemoryRuntimeError> {
        let mut service = Self::new(scope, binding, policy)?;
        service.store = MemoryStore::from_events(events)?;
        for event in service.store.events() {
            if event.plugin != service.binding {
                return Err(MemoryRuntimeError::PluginUpgradeRequiresMigration);
            }
            if event.policy != service.policy {
                return Err(MemoryRuntimeError::PolicyMismatch);
            }
            if event.project_id != *service.scope.project_id() {
                return Err(MemoryRuntimeError::ScopeMismatch);
            }
            if event.source_mission_id != *service.scope.mission_id() {
                return Err(MemoryRuntimeError::ScopeMismatch);
            }
            if event.kind == MemoryEventKind::Revoked {
                service.lifecycle = match event.reason {
                    Some(MemoryRevocationReason::Revoked) => MemoryPluginLifecycle::Revoked,
                    Some(MemoryRevocationReason::Unmounted) => MemoryPluginLifecycle::Unmounted,
                    None => return Err(MemoryRuntimeError::InvalidHistory),
                };
            }
        }
        Ok(service)
    }

    pub fn scope(&self) -> &PluginScope {
        &self.scope
    }

    pub fn binding(&self) -> &MemoryPluginBinding {
        &self.binding
    }

    pub fn policy(&self) -> &MemoryPolicy {
        &self.policy
    }

    pub const fn lifecycle(&self) -> MemoryPluginLifecycle {
        self.lifecycle
    }

    pub fn events(&self) -> &[MemoryLifecycleEvent] {
        self.store.events()
    }

    pub fn refresh_source(&mut self, source: MemorySourceEvent) -> Result<(), MemoryRuntimeError> {
        if source.project_id() != self.scope.project_id() {
            return Err(MemoryRuntimeError::ScopeMismatch);
        }
        self.store.register_source(source)
    }

    pub fn propose(
        &mut self,
        source: &MemorySourceEvent,
        draft: &MemoryCandidateDraft,
    ) -> Result<MemoryCandidateReceipt, MemoryRuntimeError> {
        self.ensure_mounted()?;
        source.validate()?;
        if !source.secret_free()
            || source.project_id() != self.scope.project_id()
            || source.mission_id() != self.scope.mission_id()
            || draft.payload().is_secret()
        {
            return Err(MemoryRuntimeError::InvalidSource);
        }
        let mut next = self.store.clone();
        next.register_source(source.clone())?;
        let candidate_id = candidate_id(&self.scope, &self.binding, &self.policy, source, draft);
        let records = next.records()?;
        if records.contains_key(&candidate_id) {
            return Err(MemoryRuntimeError::DuplicateEvent);
        }
        let event = self.event_for(
            0,
            MemoryEventKind::Proposed,
            &candidate_id,
            source,
            draft,
            EventExtras::default(),
        );
        next.append_batch(&[event])?;
        self.store = next;
        let sequence = self
            .store
            .events()
            .last()
            .map_or(0, MemoryLifecycleEvent::sequence);
        Ok(MemoryCandidateReceipt {
            candidate_id,
            event_sequence: sequence,
            status: MemoryCandidateStatus::Proposed,
        })
    }

    pub fn adopt(
        &mut self,
        candidate_id: &Digest,
        source_revision: u64,
        consent: MemoryConsent,
    ) -> Result<MemoryAdoptionReceipt, MemoryRuntimeError> {
        self.ensure_mounted()?;
        if consent != MemoryConsent::Explicit || !self.policy.explicit_adoption {
            return Err(MemoryRuntimeError::InvalidConsent);
        }
        let records = self.store.records()?;
        let record = records
            .get(candidate_id)
            .ok_or(MemoryRuntimeError::CandidateNotFound)?;
        if record.status == MemoryCandidateStatus::Adopted {
            return Err(MemoryRuntimeError::AlreadyAdopted);
        }
        if record.status != MemoryCandidateStatus::Proposed {
            return Err(MemoryRuntimeError::LifecycleViolation);
        }
        if source_revision != record.source_revision {
            return Err(MemoryRuntimeError::SourceStale);
        }
        let source = self
            .store
            .source(&record.source_event_digest)
            .ok_or(MemoryRuntimeError::SourceStale)?;
        if source.revision() != record.source_revision
            || source.content_digest() != &record.source_content_digest
            || !source.secret_free()
        {
            return Err(MemoryRuntimeError::SourceStale);
        }
        let event = self.event_for_record(
            0,
            MemoryEventKind::Adopted,
            record,
            EventExtras {
                consent: Some(MemoryConsent::Explicit),
                ..EventExtras::default()
            },
        );
        let mut next = self.store.clone();
        next.append_batch(&[event])?;
        self.store = next;
        let sequence = self
            .store
            .events()
            .last()
            .map_or(0, MemoryLifecycleEvent::sequence);
        Ok(MemoryAdoptionReceipt {
            candidate_id: candidate_id.clone(),
            event_sequence: sequence,
        })
    }

    pub fn forget(
        &mut self,
        candidate_id: &Digest,
    ) -> Result<MemoryForgetReceipt, MemoryRuntimeError> {
        self.ensure_mounted()?;
        let records = self.store.records()?;
        let record = records
            .get(candidate_id)
            .ok_or(MemoryRuntimeError::CandidateNotFound)?;
        match record.status {
            MemoryCandidateStatus::Adopted => {}
            MemoryCandidateStatus::Forgotten => return Err(MemoryRuntimeError::AlreadyForgotten),
            _ => return Err(MemoryRuntimeError::NotAdopted),
        }
        let event = self.event_for_record(
            0,
            MemoryEventKind::Forgotten,
            record,
            EventExtras::default(),
        );
        let mut next = self.store.clone();
        next.append_batch(&[event])?;
        self.store = next;
        let sequence = self
            .store
            .events()
            .last()
            .map_or(0, MemoryLifecycleEvent::sequence);
        Ok(MemoryForgetReceipt {
            candidate_id: candidate_id.clone(),
            event_sequence: sequence,
        })
    }

    pub fn revoke_plugin(&mut self) -> Result<MemoryRevocationReceipt, MemoryRuntimeError> {
        self.revoke_with_reason(MemoryRevocationReason::Revoked)
    }

    pub fn unmount_plugin(&mut self) -> Result<MemoryRevocationReceipt, MemoryRuntimeError> {
        self.revoke_with_reason(MemoryRevocationReason::Unmounted)
    }

    pub fn query(
        &mut self,
        project_id: ProjectId,
        mission_id: MissionId,
        generation: u64,
    ) -> Result<MemoryQueryService<'_>, MemoryRuntimeError> {
        if project_id != *self.scope.project_id() || generation != self.binding.generation() {
            return Err(MemoryRuntimeError::ScopeMismatch);
        }
        self.ensure_mounted()?;
        Ok(MemoryQueryService {
            service: self,
            project_id,
            mission_id,
            generation,
        })
    }

    fn event_for(
        &self,
        sequence: u64,
        kind: MemoryEventKind,
        candidate_id: &Digest,
        source: &MemorySourceEvent,
        draft: &MemoryCandidateDraft,
        extras: EventExtras,
    ) -> MemoryLifecycleEvent {
        MemoryLifecycleEvent {
            sequence,
            kind,
            candidate_id: candidate_id.clone(),
            project_id: source.project_id().clone(),
            source_mission_id: source.mission_id().clone(),
            target_mission_id: extras.target_mission_id,
            source_event_digest: source.event_digest().clone(),
            source_content_digest: source.content_digest().clone(),
            source_revision: source.revision(),
            source_kind: source.kind(),
            classification: draft.classification(),
            payload: (kind == MemoryEventKind::Proposed).then(|| draft.payload().clone()),
            content_digest: draft.payload().digest(),
            confidence: draft.confidence(),
            applicability: draft.applicability(),
            policy: self.policy.clone(),
            plugin: self.binding.clone(),
            consent: extras.consent,
            reason: extras.reason,
        }
    }

    fn event_for_record(
        &self,
        sequence: u64,
        kind: MemoryEventKind,
        record: &CandidateRecord,
        extras: EventExtras,
    ) -> MemoryLifecycleEvent {
        let source = MemorySourceEvent {
            project_id: record.project_id.clone(),
            mission_id: record.source_mission_id.clone(),
            revision: record.source_revision,
            kind: record.source_kind,
            event_digest: record.source_event_digest.clone(),
            content_digest: record.source_content_digest.clone(),
            secret_free: true,
        };
        let draft = MemoryCandidateDraft {
            classification: record.classification,
            payload: record.payload.clone(),
            confidence: record.confidence,
            applicability: record.applicability,
        };
        self.event_for(
            sequence,
            kind,
            &record.candidate_id,
            &source,
            &draft,
            extras,
        )
    }

    fn revoke_with_reason(
        &mut self,
        reason: MemoryRevocationReason,
    ) -> Result<MemoryRevocationReceipt, MemoryRuntimeError> {
        if self.lifecycle != MemoryPluginLifecycle::Mounted {
            return Err(match self.lifecycle {
                MemoryPluginLifecycle::Revoked => MemoryRuntimeError::PluginRevoked,
                MemoryPluginLifecycle::Unmounted => MemoryRuntimeError::PluginInactive,
                MemoryPluginLifecycle::Mounted => MemoryRuntimeError::LifecycleViolation,
            });
        }
        let records = self.store.records()?;
        let additions = records
            .values()
            .filter(|record| {
                matches!(
                    record.status,
                    MemoryCandidateStatus::Proposed | MemoryCandidateStatus::Adopted
                )
            })
            .map(|record| {
                self.event_for_record(
                    0,
                    MemoryEventKind::Revoked,
                    record,
                    EventExtras {
                        reason: Some(reason),
                        ..EventExtras::default()
                    },
                )
            })
            .collect::<Vec<_>>();
        let mut next = self.store.clone();
        next.append_batch(&additions)?;
        self.store = next;
        self.lifecycle = match reason {
            MemoryRevocationReason::Revoked => MemoryPluginLifecycle::Revoked,
            MemoryRevocationReason::Unmounted => MemoryPluginLifecycle::Unmounted,
        };
        let first = self
            .store
            .events()
            .iter()
            .rev()
            .take(additions.len())
            .next_back()
            .map(MemoryLifecycleEvent::sequence);
        Ok(MemoryRevocationReceipt {
            reason,
            first_event_sequence: first,
            event_count: additions.len(),
        })
    }

    fn ensure_mounted(&self) -> Result<(), MemoryRuntimeError> {
        match self.lifecycle {
            MemoryPluginLifecycle::Mounted => Ok(()),
            MemoryPluginLifecycle::Revoked => Err(MemoryRuntimeError::PluginRevoked),
            MemoryPluginLifecycle::Unmounted => Err(MemoryRuntimeError::PluginInactive),
        }
    }
}

pub struct MemoryQueryService<'a> {
    service: &'a mut MemoryCandidateService,
    project_id: ProjectId,
    mission_id: MissionId,
    generation: u64,
}

impl fmt::Debug for MemoryQueryService<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryQueryService")
            .field("target_scope_present", &true)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl MemoryQueryService<'_> {
    pub fn recall(self) -> Result<(MemoryQueryReceipt, Vec<MemoryRecall>), MemoryRuntimeError> {
        let Self {
            service,
            project_id,
            mission_id,
            generation,
        } = self;
        service.ensure_mounted()?;
        let records = service.store.records()?;
        let eligible = records
            .values()
            .filter(|record| {
                record.status == MemoryCandidateStatus::Adopted
                    && record.project_id == project_id
                    && record.plugin.generation() == generation
                    && (record.applicability == MemoryApplicability::Project
                        || record.source_mission_id == mission_id)
            })
            .cloned()
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            return Ok((
                MemoryQueryReceipt {
                    target_mission_id: mission_id,
                    first_event_sequence: None,
                    recalled_count: 0,
                },
                Vec::new(),
            ));
        }
        let mut additions = Vec::with_capacity(eligible.len());
        for record in &eligible {
            additions.push(service.event_for_record(
                0,
                MemoryEventKind::Recalled,
                record,
                EventExtras {
                    target_mission_id: Some(mission_id.clone()),
                    ..EventExtras::default()
                },
            ));
        }
        let mut next = service.store.clone();
        next.append_batch(&additions)?;
        service.store = next;
        let first = service
            .store
            .events()
            .iter()
            .rev()
            .take(additions.len())
            .next_back()
            .map(MemoryLifecycleEvent::sequence);
        let recalls = eligible.into_iter().map(|record| record.view()).collect();
        Ok((
            MemoryQueryReceipt {
                target_mission_id: mission_id,
                first_event_sequence: first,
                recalled_count: additions.len(),
            },
            recalls,
        ))
    }
}

fn candidate_id(
    scope: &PluginScope,
    binding: &MemoryPluginBinding,
    policy: &MemoryPolicy,
    source: &MemorySourceEvent,
    draft: &MemoryCandidateDraft,
) -> Digest {
    canonical_digest(&(
        scope.project_id(),
        scope.mission_id(),
        scope.generation(),
        binding,
        policy,
        source.event_digest(),
        source.revision(),
        source.content_digest(),
        source.kind(),
        draft.classification(),
        draft.payload().digest(),
        draft.confidence(),
        draft.applicability(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hartevo_plugin_runtime::{PluginRuntime, sample::SampleReadOnlyPlugin};

    fn scope(project: &str, mission: &str, generation: u64) -> PluginScope {
        PluginScope::new(
            ProjectId::new(project).expect("project"),
            MissionId::new(mission).expect("mission"),
            generation,
        )
        .expect("scope")
    }

    fn binding(scope: &PluginScope, version: PluginVersion) -> MemoryPluginBinding {
        let definition =
            SampleReadOnlyPlugin::definition(scope.clone(), version).expect("definition");
        let mut runtime = PluginRuntime::new();
        let handle = runtime.define(definition).expect("handle");
        MemoryPluginBinding::from_handle(&handle)
    }

    fn service() -> MemoryCandidateService {
        let service_scope = scope("project.memory", "mission.source", 1);
        MemoryCandidateService::new(
            service_scope,
            binding(
                &scope("project.memory", "mission.source", 1),
                PluginVersion::new(1, 0, 0),
            ),
            MemoryPolicy::explicit_only(1, Digest::from_text("memory-policy-v1")).expect("policy"),
        )
        .expect("service")
    }

    fn source(revision: u64) -> MemorySourceEvent {
        MemorySourceEvent::new(
            ProjectId::new("project.memory").expect("project"),
            MissionId::new("mission.source").expect("mission"),
            Digest::from_text("source-event-1"),
            revision,
            MemorySourceKind::Conversation,
            Digest::from_text("source-content"),
            true,
        )
        .expect("source")
    }

    fn draft() -> MemoryCandidateDraft {
        MemoryCandidateDraft::new(
            MemoryCandidateClass::Preference,
            MemoryPayload::public("prefers concise reports").expect("payload"),
            90,
            MemoryApplicability::Project,
        )
        .expect("draft")
    }

    #[test]
    fn propose_adopt_query_forget_and_reopen_are_reversible() {
        let mut candidate_service = service();
        let source_event = source(4);
        let candidate_draft = draft();
        let proposed = candidate_service
            .propose(&source_event, &candidate_draft)
            .expect("propose");
        assert_eq!(proposed.status(), MemoryCandidateStatus::Proposed);
        assert!(!format!("{proposed:?}").contains("prefers concise reports"));
        let adopted = candidate_service
            .adopt(proposed.candidate_id(), 4, MemoryConsent::Explicit)
            .expect("adopt");
        assert_eq!(adopted.candidate_id(), proposed.candidate_id());
        let (receipt, recalls) = candidate_service
            .query(
                ProjectId::new("project.memory").expect("project"),
                MissionId::new("mission.next").expect("mission"),
                1,
            )
            .expect("query")
            .recall()
            .expect("recall");
        assert_eq!(receipt.recalled_count(), 1);
        assert_eq!(recalls[0].payload().as_str(), "prefers concise reports");
        assert_eq!(recalls[0].source_revision(), 4);
        let events = candidate_service.events().to_vec();
        let reopened = MemoryCandidateService::from_events(
            scope("project.memory", "mission.source", 1),
            binding(
                &scope("project.memory", "mission.source", 1),
                PluginVersion::new(1, 0, 0),
            ),
            MemoryPolicy::explicit_only(1, Digest::from_text("memory-policy-v1")).expect("policy"),
            events,
        )
        .expect("reopen");
        assert_eq!(reopened.events().len(), 3);
        let mut reopened = reopened;
        reopened.forget(proposed.candidate_id()).expect("forget");
        assert!(matches!(
            reopened.adopt(proposed.candidate_id(), 4, MemoryConsent::Explicit),
            Err(MemoryRuntimeError::AlreadyAdopted | MemoryRuntimeError::LifecycleViolation)
        ));
        let (_, recalls) = reopened
            .query(
                ProjectId::new("project.memory").expect("project"),
                MissionId::new("mission.next").expect("mission"),
                1,
            )
            .expect("query")
            .recall()
            .expect("empty recall");
        assert!(recalls.is_empty());
    }

    #[test]
    fn scope_secret_stale_source_and_duplicate_adoption_fail_closed() {
        let mut candidate_service = service();
        let secret = MemoryCandidateDraft::new(
            MemoryCandidateClass::Fact,
            MemoryPayload::secret("private tool token").expect("secret payload"),
            100,
            MemoryApplicability::Project,
        )
        .expect("draft");
        let secret_source = source(1);
        assert!(matches!(
            candidate_service.propose(&secret_source, &secret),
            Err(MemoryRuntimeError::InvalidSource)
        ));
        assert_eq!(candidate_service.events().len(), 0);
        let source_event = source(2);
        let candidate_draft = draft();
        let candidate = candidate_service
            .propose(&source_event, &candidate_draft)
            .expect("propose");
        assert!(matches!(
            candidate_service.adopt(candidate.candidate_id(), 1, MemoryConsent::Explicit),
            Err(MemoryRuntimeError::SourceStale)
        ));
        candidate_service
            .refresh_source(source(3))
            .expect("refresh");
        assert!(matches!(
            candidate_service.adopt(candidate.candidate_id(), 2, MemoryConsent::Explicit),
            Err(MemoryRuntimeError::SourceStale)
        ));
        let mut other_service = service();
        assert!(matches!(
            other_service.query(
                ProjectId::new("project.other").expect("project"),
                MissionId::new("mission.other").expect("mission"),
                1,
            ),
            Err(MemoryRuntimeError::ScopeMismatch)
        ));
        let source_event = source(4);
        let candidate_draft = draft();
        let candidate = candidate_service
            .propose(&source_event, &candidate_draft)
            .expect("second propose");
        candidate_service
            .adopt(candidate.candidate_id(), 4, MemoryConsent::Explicit)
            .expect("adopt");
        assert!(matches!(
            candidate_service.adopt(candidate.candidate_id(), 4, MemoryConsent::Explicit),
            Err(MemoryRuntimeError::AlreadyAdopted)
        ));
    }

    #[test]
    fn revoke_unmount_crash_and_upgrade_leave_no_queryable_memory() {
        let mut service = service();
        let source_event = source(1);
        let candidate_draft = draft();
        let candidate = service
            .propose(&source_event, &candidate_draft)
            .expect("propose");
        service
            .adopt(candidate.candidate_id(), 1, MemoryConsent::Explicit)
            .expect("adopt");
        let events = service.events().to_vec();
        let mut revoked = MemoryCandidateService::from_events(
            scope("project.memory", "mission.source", 1),
            binding(
                &scope("project.memory", "mission.source", 1),
                PluginVersion::new(1, 0, 0),
            ),
            MemoryPolicy::explicit_only(1, Digest::from_text("memory-policy-v1")).expect("policy"),
            events,
        )
        .expect("reopen");
        revoked.revoke_plugin().expect("revoke");
        assert!(matches!(
            revoked.query(
                ProjectId::new("project.memory").expect("project"),
                MissionId::new("mission.next").expect("mission"),
                1,
            ),
            Err(MemoryRuntimeError::PluginRevoked)
        ));
        let upgraded_events = revoked.events().to_vec();
        assert!(matches!(
            MemoryCandidateService::from_events(
                scope("project.memory", "mission.source", 1),
                binding(
                    &scope("project.memory", "mission.source", 1),
                    PluginVersion::new(2, 0, 0),
                ),
                MemoryPolicy::explicit_only(1, Digest::from_text("memory-policy-v1"))
                    .expect("policy"),
                upgraded_events,
            ),
            Err(MemoryRuntimeError::PluginUpgradeRequiresMigration)
        ));

        let mut unmounted = MemoryCandidateService::new(
            scope("project.memory", "mission.source", 1),
            binding(
                &scope("project.memory", "mission.source", 1),
                PluginVersion::new(1, 0, 0),
            ),
            MemoryPolicy::explicit_only(1, Digest::from_text("memory-policy-v1")).expect("policy"),
        )
        .expect("unmounted service");
        let source_event = source(2);
        let candidate_draft = draft();
        unmounted
            .propose(&source_event, &candidate_draft)
            .expect("propose before unmount");
        unmounted.unmount_plugin().expect("unmount");
        assert!(matches!(
            unmounted.query(
                ProjectId::new("project.memory").expect("project"),
                MissionId::new("mission.next").expect("mission"),
                1,
            ),
            Err(MemoryRuntimeError::PluginInactive)
        ));
    }

    #[test]
    fn query_is_idempotent_and_recall_event_cannot_cross_project_or_generation() {
        let mut service = service();
        let source_event = source(7);
        let candidate_draft = draft();
        let candidate = service
            .propose(&source_event, &candidate_draft)
            .expect("propose");
        service
            .adopt(candidate.candidate_id(), 7, MemoryConsent::Explicit)
            .expect("adopt");
        let (first_receipt, first) = service
            .query(
                ProjectId::new("project.memory").expect("project"),
                MissionId::new("mission.other").expect("mission"),
                1,
            )
            .expect("query")
            .recall()
            .expect("first recall");
        assert_eq!(first_receipt.recalled_count(), 1);
        assert_eq!(first.len(), 1);
        let (second_receipt, second) = service
            .query(
                ProjectId::new("project.memory").expect("project"),
                MissionId::new("mission.other").expect("mission"),
                1,
            )
            .expect("query replay")
            .recall()
            .expect("second recall");
        assert_eq!(second_receipt.recalled_count(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(service.events().len(), 4);
        assert!(matches!(
            service.query(
                ProjectId::new("project.memory").expect("project"),
                MissionId::new("mission.other").expect("mission"),
                2,
            ),
            Err(MemoryRuntimeError::ScopeMismatch)
        ));
        assert!(matches!(
            service.query(
                ProjectId::new("project.other").expect("project"),
                MissionId::new("mission.other").expect("mission"),
                1,
            ),
            Err(MemoryRuntimeError::ScopeMismatch)
        ));
    }

    #[test]
    fn source_event_digest_and_payload_are_bound_before_adoption() {
        let mut service = service();
        let source_event = source(8);
        let candidate_draft = draft();
        let candidate = service
            .propose(&source_event, &candidate_draft)
            .expect("propose");
        let mut tampered = service.events().to_vec();
        tampered[0].source_content_digest = Digest::from_text("tampered-content");
        assert!(matches!(
            MemoryCandidateService::from_events(
                scope("project.memory", "mission.source", 1),
                binding(
                    &scope("project.memory", "mission.source", 1),
                    PluginVersion::new(1, 0, 0),
                ),
                MemoryPolicy::explicit_only(1, Digest::from_text("memory-policy-v1"))
                    .expect("policy"),
                tampered,
            ),
            Err(MemoryRuntimeError::InvalidHistory)
        ));
        assert!(matches!(
            service.adopt(candidate.candidate_id(), 9, MemoryConsent::Explicit),
            Err(MemoryRuntimeError::SourceStale)
        ));
    }
}
