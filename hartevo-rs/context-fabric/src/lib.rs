//! Deterministic Context assembly for Runtime projections.
//!
//! The assembler never treats a model window as authority. It validates the
//! current Checkpoint/Capsule closure, resolves only typed references, verifies
//! every content digest, records every omission, and emits a bounded transient
//! envelope. Only the content-free manifest is suitable for persistence.

mod model_tokenizer;
mod steering;

pub use model_tokenizer::{
    ConservativeByteBudgetTokenizer, PinnedModelTokenizer, PinnedTokenizerSpec,
};
pub use steering::{
    SteeringCancellationReason, SteeringCheckpoint, SteeringCompactionInput, SteeringConsumedInput,
    SteeringConsumer, SteeringDurableEvent, SteeringError, SteeringEventStatus, SteeringInput,
    SteeringJournal, SteeringLifecycle, SteeringMicroCompaction, SteeringPluginService,
    SteeringProvider, SteeringSafePoint, SteeringSubmitOutcome, SteeringTurnFence,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    ContextAssemblyId, ContextBranch, ContextCapsule, ContextCapsuleStatus, ContextDataClass,
    ContextFoundationSnapshot, ContextItemAvailability, ContextWorkingItemKind,
    ContinuationEntryKind, Mission, WorkerLease, validate_context_branch_lineage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ASSEMBLY_SCHEMA_VERSION: u32 = 2;
const TOKENIZER_PROFILE_SCHEMA_VERSION: u32 = 1;
const MAX_PROMPT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PROMPT_TOKENS: u64 = 4 * 1024 * 1024;
const MAX_OPTIONAL_FRAMES: u32 = 512;
const MAX_GAP_RECORDS: u32 = 1_024;
const CONTINUATION_DELIVERY_SCHEMA: &str = "hartevo.context-continuation-delivery/v1";
const CONTINUATION_DELIVERY_CONTRACT_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../contracts/context/continuation-delivery-v1.json"
));
const CONTINUATION_ENTRY_KINDS: [ContinuationEntryKind; 8] = [
    ContinuationEntryKind::Decision,
    ContinuationEntryKind::Blocker,
    ContinuationEntryKind::NextAction,
    ContinuationEntryKind::UserCorrection,
    ContinuationEntryKind::CheckpointTransition,
    ContinuationEntryKind::ApprovalPending,
    ContinuationEntryKind::EffectUncertain,
    ContinuationEntryKind::HumanHandoff,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ContinuationEntryLifetime {
    NonExpiring,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AbsentContinuationKindPolicy {
    NoSyntheticReference,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ContinuationDeliveryRequirement {
    RequiredWhenPresent,
    #[serde(other)]
    Unsupported,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum RequiredReferenceDisposition {
    BlockedMissingRequired,
    BlockedBudget,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenericRequiredReferenceDisposition {
    missing: RequiredReferenceDisposition,
    expired: RequiredReferenceDisposition,
    budget_overflow: RequiredReferenceDisposition,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ContinuationDeliveryPolicy {
    schema: String,
    continuation_entry_lifetime: ContinuationEntryLifetime,
    absent_kind_policy: AbsentContinuationKindPolicy,
    delivery_by_kind: BTreeMap<ContinuationEntryKind, ContinuationDeliveryRequirement>,
    generic_required_reference_disposition: GenericRequiredReferenceDisposition,
}

impl ContinuationDeliveryPolicy {
    fn load() -> Result<Self, ContextAssemblyError> {
        let policy: Self = serde_json::from_slice(CONTINUATION_DELIVERY_CONTRACT_BYTES)
            .map_err(|_| ContextAssemblyError::InvalidContinuationDeliveryPolicy)?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), ContextAssemblyError> {
        let expected_kinds = CONTINUATION_ENTRY_KINDS
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual_kinds = self
            .delivery_by_kind
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let disposition = &self.generic_required_reference_disposition;
        if self.schema != CONTINUATION_DELIVERY_SCHEMA
            || self.continuation_entry_lifetime != ContinuationEntryLifetime::NonExpiring
            || self.absent_kind_policy != AbsentContinuationKindPolicy::NoSyntheticReference
            || actual_kinds != expected_kinds
            || self.delivery_by_kind.values().any(|requirement| {
                *requirement != ContinuationDeliveryRequirement::RequiredWhenPresent
            })
            || disposition.missing != RequiredReferenceDisposition::BlockedMissingRequired
            || disposition.expired != RequiredReferenceDisposition::BlockedMissingRequired
            || disposition.budget_overflow != RequiredReferenceDisposition::BlockedBudget
        {
            return Err(ContextAssemblyError::InvalidContinuationDeliveryPolicy);
        }
        Ok(())
    }

    fn requirement_for(
        &self,
        kind: ContinuationEntryKind,
    ) -> Result<ContextFrameRequirement, ContextAssemblyError> {
        match self.delivery_by_kind.get(&kind) {
            Some(ContinuationDeliveryRequirement::RequiredWhenPresent) => {
                Ok(ContextFrameRequirement::Required)
            }
            Some(ContinuationDeliveryRequirement::Unsupported) | None => {
                Err(ContextAssemblyError::InvalidContinuationDeliveryPolicy)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextAssemblyPolicy {
    pub version: u32,
    pub max_prompt_tokens: u64,
    pub reserved_output_tokens: u64,
    pub max_prompt_bytes: u64,
    pub max_optional_frames: u32,
    pub max_gap_records: u32,
}

impl ContextAssemblyPolicy {
    pub fn validate(&self, capsule: &ContextCapsule) -> Result<(), ContextAssemblyError> {
        let total_tokens = self
            .max_prompt_tokens
            .checked_add(self.reserved_output_tokens)
            .ok_or(ContextAssemblyError::InvalidPolicy)?;
        if !self.has_valid_shape() || total_tokens > capsule.budget.token_limit {
            return Err(ContextAssemblyError::InvalidPolicy);
        }
        Ok(())
    }

    fn has_valid_shape(&self) -> bool {
        self.version > 0
            && self.max_prompt_tokens > 0
            && self.reserved_output_tokens > 0
            && self
                .max_prompt_tokens
                .checked_add(self.reserved_output_tokens)
                .is_some()
            && self.max_prompt_tokens <= MAX_PROMPT_TOKENS
            && self.max_prompt_bytes > 0
            && self.max_prompt_bytes <= MAX_PROMPT_BYTES
            && self.max_optional_frames <= MAX_OPTIONAL_FRAMES
            && self.max_gap_records > 0
            && self.max_gap_records <= MAX_GAP_RECORDS
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextFrameSource {
    TypedInvariant,
    CapsuleContract,
    TruthFact,
    Evidence,
    WorkProduct,
    CompactionSummary,
    Continuation,
    WorkingItem,
    FileSnapshot,
    QuerySnapshot,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextFrameRequirement {
    Required,
    Optional,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextGapReason {
    Missing,
    Expired,
    BudgetOmitted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextAssemblyStatus {
    Ready,
    BlockedMissingRequired,
    BlockedBudget,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextMaterialReference {
    pub source: ContextFrameSource,
    pub source_id: String,
    pub storage_ref: String,
    pub expected_digest: String,
    pub declared_max_bytes: Option<u64>,
    pub classification: ContextDataClass,
    pub requirement: ContextFrameRequirement,
    pub expired: bool,
}

impl fmt::Debug for ContextMaterialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextMaterialReference")
            .field("source", &self.source)
            .field("source_id_digest", &digest(self.source_id.as_bytes()))
            .field("storage_ref_digest", &digest(self.storage_ref.as_bytes()))
            .field("expected_digest", &self.expected_digest)
            .field("declared_max_bytes", &self.declared_max_bytes)
            .field("classification", &self.classification)
            .field("requirement", &self.requirement)
            .field("expired", &self.expired)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedContextMaterial {
    text: String,
}

impl ResolvedContextMaterial {
    pub fn text(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for ResolvedContextMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedContextMaterial")
            .field("byte_count", &self.text.len())
            .field("content_digest", &digest(self.text.as_bytes()))
            .finish()
    }
}

pub trait ContextMaterialResolver {
    fn resolve(
        &self,
        reference: &ContextMaterialReference,
    ) -> Result<Option<ResolvedContextMaterial>, ContextAssemblyError>;
}

pub trait ContextTokenizer {
    fn profile(&self) -> Result<ContextTokenizerProfile, ContextAssemblyError>;

    fn count_tokens(&self, text: &str) -> Result<u64, ContextAssemblyError>;
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextTokenizerProfile {
    pub schema_version: u32,
    pub provider: String,
    pub model: String,
    pub model_revision: String,
    pub artifact_digest: String,
    pub add_special_tokens: bool,
    pub request_overhead_tokens: u64,
    pub max_input_bytes: u64,
}

impl ContextTokenizerProfile {
    pub fn new(
        provider: impl Into<String>,
        model: impl Into<String>,
        model_revision: impl Into<String>,
        artifact_digest: impl Into<String>,
        add_special_tokens: bool,
        request_overhead_tokens: u64,
        max_input_bytes: u64,
    ) -> Result<Self, ContextAssemblyError> {
        let profile = Self {
            schema_version: TOKENIZER_PROFILE_SCHEMA_VERSION,
            provider: provider.into(),
            model: model.into(),
            model_revision: model_revision.into(),
            artifact_digest: artifact_digest.into(),
            add_special_tokens,
            request_overhead_tokens,
            max_input_bytes,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), ContextAssemblyError> {
        if self.schema_version != TOKENIZER_PROFILE_SCHEMA_VERSION
            || !is_bounded_tokenizer_identity(&self.provider)
            || !is_bounded_tokenizer_identity(&self.model)
            || !is_bounded_tokenizer_identity(&self.model_revision)
            || !is_lower_sha256(&self.artifact_digest)
            || self.request_overhead_tokens > 65_536
            || self.max_input_bytes == 0
            || self.max_input_bytes > MAX_PROMPT_BYTES
        {
            return Err(ContextAssemblyError::InvalidTokenizerProfile);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ContextAssemblyError> {
        self.validate()?;
        Ok(digest(&serde_json::to_vec(self)?))
    }
}

impl fmt::Debug for ContextTokenizerProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextTokenizerProfile")
            .field("schema_version", &self.schema_version)
            .field("provider_digest", &digest(self.provider.as_bytes()))
            .field("model_digest", &digest(self.model.as_bytes()))
            .field(
                "model_revision_digest",
                &digest(self.model_revision.as_bytes()),
            )
            .field("artifact_digest", &self.artifact_digest)
            .field("add_special_tokens", &self.add_special_tokens)
            .field("request_overhead_tokens", &self.request_overhead_tokens)
            .field("max_input_bytes", &self.max_input_bytes)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextFrameManifest {
    pub source: ContextFrameSource,
    pub source_id_digest: String,
    pub source_digest: String,
    pub content_digest: String,
    pub byte_count: u64,
    pub token_count: u64,
    pub classification: ContextDataClass,
    pub requirement: ContextFrameRequirement,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextGap {
    pub source: ContextFrameSource,
    pub source_id_digest: String,
    pub expected_digest: String,
    pub requirement: ContextFrameRequirement,
    pub reason: ContextGapReason,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextAssemblyManifest {
    pub schema_version: u32,
    pub id: ContextAssemblyId,
    pub tenant_id: hartevo_domain_kernel::TenantId,
    pub project_id: hartevo_domain_kernel::ProjectId,
    pub mission_id: hartevo_domain_kernel::MissionId,
    pub workspace_id: hartevo_domain_kernel::ContextWorkspaceId,
    pub capsule_id: hartevo_domain_kernel::ContextCapsuleId,
    pub capsule_revision: u64,
    pub branch_id: hartevo_domain_kernel::ContextBranchId,
    pub branch_revision: u64,
    pub worker_id: hartevo_domain_kernel::WorkerId,
    pub worker_generation: u64,
    pub worker_lease_id: hartevo_domain_kernel::WorkerLeaseId,
    pub worker_lease_revision: u64,
    pub foundation_sync_version: u64,
    pub checkpoint_id: hartevo_domain_kernel::ContextCheckpointId,
    pub checkpoint_digest: String,
    pub capsule_authority_digest: String,
    pub policy: ContextAssemblyPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer_profile: Option<ContextTokenizerProfile>,
    pub input_digest: String,
    pub frames: Vec<ContextFrameManifest>,
    pub gaps: Vec<ContextGap>,
    pub prompt_digest: Option<String>,
    pub prompt_byte_count: u64,
    pub prompt_token_count: u64,
    pub status: ContextAssemblyStatus,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
}

impl ContextAssemblyManifest {
    #[allow(
        clippy::too_many_lines,
        reason = "the content-free manifest validates one auditable tokenizer, authority, frame, gap, budget, and terminal-shape closure"
    )]
    pub fn validate(&self) -> Result<(), ContextAssemblyError> {
        let frame_keys = self
            .frames
            .iter()
            .map(|frame| (frame.source, frame.source_id_digest.as_str()))
            .collect::<BTreeSet<_>>();
        let gap_keys = self
            .gaps
            .iter()
            .map(|gap| (gap.source, gap.source_id_digest.as_str()))
            .collect::<BTreeSet<_>>();
        let has_required_frame = |source| {
            self.frames.iter().any(|frame| {
                frame.source == source && frame.requirement == ContextFrameRequirement::Required
            })
        };
        let prompt_shape_matches = match self.status {
            ContextAssemblyStatus::Ready => {
                self.prompt_digest
                    .as_ref()
                    .is_some_and(|value| is_sha256(value))
                    && self.prompt_byte_count > 0
                    && self.prompt_byte_count <= self.policy.max_prompt_bytes
                    && self
                        .tokenizer_profile
                        .as_ref()
                        .is_none_or(|profile| self.prompt_byte_count <= profile.max_input_bytes)
                    && self.prompt_token_count > 0
                    && self.prompt_token_count <= self.policy.max_prompt_tokens
                    && self
                        .gaps
                        .iter()
                        .all(|gap| gap.requirement == ContextFrameRequirement::Optional)
                    && has_required_frame(ContextFrameSource::CompactionSummary)
            }
            ContextAssemblyStatus::BlockedMissingRequired => {
                self.prompt_digest.is_none()
                    && self.prompt_byte_count == 0
                    && self.prompt_token_count == 0
                    && self.gaps.iter().any(|gap| {
                        gap.requirement == ContextFrameRequirement::Required
                            && matches!(
                                gap.reason,
                                ContextGapReason::Missing | ContextGapReason::Expired
                            )
                    })
            }
            ContextAssemblyStatus::BlockedBudget => {
                self.prompt_digest.is_none()
                    && self.prompt_byte_count == 0
                    && self.prompt_token_count == 0
                    && self.gaps.iter().any(|gap| {
                        gap.requirement == ContextFrameRequirement::Required
                            && gap.reason == ContextGapReason::BudgetOmitted
                    })
            }
        };
        let tokenizer_profile_matches = match (self.schema_version, self.tokenizer_profile.as_ref())
        {
            (1, None) => true,
            (ASSEMBLY_SCHEMA_VERSION, Some(profile)) => profile.validate().is_ok(),
            _ => false,
        };
        if !tokenizer_profile_matches
            || self.id.as_str().trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.workspace_id.as_str().trim().is_empty()
            || self.capsule_id.as_str().trim().is_empty()
            || self.branch_id.as_str().trim().is_empty()
            || self.worker_id.as_str().trim().is_empty()
            || self.worker_lease_id.as_str().trim().is_empty()
            || self.checkpoint_id.as_str().trim().is_empty()
            || self.capsule_revision == 0
            || self.branch_revision == 0
            || self.worker_generation == 0
            || self.worker_lease_revision == 0
            || self.foundation_sync_version == 0
            || !self.policy.has_valid_shape()
            || !is_sha256(&self.checkpoint_digest)
            || !is_sha256(&self.capsule_authority_digest)
            || !is_sha256(&self.input_digest)
            || self.frames.iter().any(|frame| {
                !is_sha256(&frame.source_id_digest)
                    || !is_sha256(&frame.source_digest)
                    || !is_sha256(&frame.content_digest)
                    || frame.byte_count == 0
                    || frame.token_count == 0
            })
            || self
                .gaps
                .iter()
                .any(|gap| !is_sha256(&gap.source_id_digest) || !is_sha256(&gap.expected_digest))
            || frame_keys.len() != self.frames.len()
            || gap_keys.len() != self.gaps.len()
            || !frame_keys.is_disjoint(&gap_keys)
            || !has_required_frame(ContextFrameSource::TypedInvariant)
            || !has_required_frame(ContextFrameSource::CapsuleContract)
            || self.gaps.len() > usize::try_from(self.policy.max_gap_records).unwrap_or(0)
            || self.revision != 1
            || !prompt_shape_matches
        {
            return Err(ContextAssemblyError::InvalidManifest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ContextAssemblyError> {
        self.validate()?;
        digest_json(self)
    }

    pub fn validate_dispatchable(&self) -> Result<(), ContextAssemblyError> {
        self.validate()?;
        if self.schema_version != ASSEMBLY_SCHEMA_VERSION || self.tokenizer_profile.is_none() {
            return Err(ContextAssemblyError::InvalidManifest);
        }
        Ok(())
    }

    pub fn tokenizer_profile_digest(&self) -> Result<String, ContextAssemblyError> {
        self.tokenizer_profile
            .as_ref()
            .ok_or(ContextAssemblyError::InvalidTokenizerProfile)?
            .digest()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeContextFrame {
    pub source: ContextFrameSource,
    pub source_id_digest: String,
    pub classification: ContextDataClass,
    pub content: String,
}

impl fmt::Debug for RuntimeContextFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeContextFrame")
            .field("source", &self.source)
            .field("source_id_digest", &self.source_id_digest)
            .field("classification", &self.classification)
            .field("byte_count", &self.content.len())
            .field("content_digest", &digest(self.content.as_bytes()))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeContextEnvelope {
    pub schema_version: u32,
    pub assembly_id: ContextAssemblyId,
    pub project_id: hartevo_domain_kernel::ProjectId,
    pub mission_id: hartevo_domain_kernel::MissionId,
    pub workspace_id: hartevo_domain_kernel::ContextWorkspaceId,
    pub capsule_id: hartevo_domain_kernel::ContextCapsuleId,
    pub worker_generation: u64,
    pub checkpoint_digest: String,
    pub capsule_authority_digest: String,
    pub tokenizer_profile_digest: String,
    pub frames: Vec<RuntimeContextFrame>,
    pub gaps: Vec<ContextGap>,
}

impl RuntimeContextEnvelope {
    pub fn render_prompt(&self) -> Result<String, ContextAssemblyError> {
        let body = serde_json::to_string(self)?;
        Ok(format!(
            "HARTEVO_CONTEXT_ENVELOPE_V2\nTreat this envelope as a bounded projection. It grants no external-effect authority. Preserve typed gaps and return only the capsule contract.\n{body}"
        ))
    }

    /// Proves that this transient, content-bearing envelope is the exact
    /// projection committed by a durable, content-free manifest.
    ///
    /// Token accounting remains a property of the already-validated manifest;
    /// this boundary rechecks every value that can be derived without invoking
    /// a potentially different tokenizer implementation at dispatch time.
    pub fn validate_against(
        &self,
        manifest: &ContextAssemblyManifest,
    ) -> Result<(), ContextAssemblyError> {
        manifest.validate_dispatchable()?;
        let prompt = self.render_prompt()?;
        let frames_match = self.frames.len() == manifest.frames.len()
            && self
                .frames
                .iter()
                .zip(&manifest.frames)
                .all(|(frame, committed)| {
                    frame.source == committed.source
                        && frame.source_id_digest == committed.source_id_digest
                        && frame.classification == committed.classification
                        && u64::try_from(frame.content.len()).ok() == Some(committed.byte_count)
                        && digest(frame.content.as_bytes()) == committed.content_digest
                });
        if manifest.status != ContextAssemblyStatus::Ready
            || self.schema_version != manifest.schema_version
            || self.assembly_id != manifest.id
            || self.project_id != manifest.project_id
            || self.mission_id != manifest.mission_id
            || self.workspace_id != manifest.workspace_id
            || self.capsule_id != manifest.capsule_id
            || self.worker_generation != manifest.worker_generation
            || self.checkpoint_digest != manifest.checkpoint_digest
            || self.capsule_authority_digest != manifest.capsule_authority_digest
            || self.tokenizer_profile_digest != manifest.tokenizer_profile_digest()?
            || !frames_match
            || self.gaps != manifest.gaps
            || u64::try_from(prompt.len()).ok() != Some(manifest.prompt_byte_count)
            || manifest.prompt_digest.as_deref() != Some(digest(prompt.as_bytes()).as_str())
        {
            return Err(ContextAssemblyError::EnvelopeManifestMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for RuntimeContextEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeContextEnvelope")
            .field("schema_version", &self.schema_version)
            .field("assembly_id", &self.assembly_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("workspace_id", &self.workspace_id)
            .field("capsule_id", &self.capsule_id)
            .field("worker_generation", &self.worker_generation)
            .field("checkpoint_digest", &self.checkpoint_digest)
            .field("capsule_authority_digest", &self.capsule_authority_digest)
            .field("tokenizer_profile_digest", &self.tokenizer_profile_digest)
            .field("frame_count", &self.frames.len())
            .field("gap_count", &self.gaps.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ContextAssemblyOutcome {
    pub manifest: ContextAssemblyManifest,
    pub envelope: Option<RuntimeContextEnvelope>,
}

impl fmt::Debug for ContextAssemblyOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextAssemblyOutcome")
            .field("manifest", &self.manifest)
            .field("has_envelope", &self.envelope.is_some())
            .finish()
    }
}

pub struct ContextAssemblyRequest<'a> {
    pub id: ContextAssemblyId,
    pub mission: &'a Mission,
    pub foundation: &'a ContextFoundationSnapshot,
    pub previous_compaction: Option<&'a hartevo_domain_kernel::ContextCompactionRecord>,
    pub previous_checkpoint: Option<&'a hartevo_domain_kernel::ContextCheckpoint>,
    pub branch_lineage: &'a [ContextBranch],
    pub worker_lease: &'a WorkerLease,
    pub capsule: &'a ContextCapsule,
    pub policy: ContextAssemblyPolicy,
    pub now: DateTime<Utc>,
}

impl fmt::Debug for ContextAssemblyRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContextAssemblyRequest")
            .field("id", &self.id)
            .field("mission_id", &self.mission.id)
            .field("workspace_id", &self.foundation.workspace.id)
            .field("capsule_id", &self.capsule.id)
            .field("worker_id", &self.capsule.worker_id)
            .field("policy", &self.policy)
            .field("now", &self.now)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct ContextAssembler;

impl ContextAssembler {
    #[allow(
        clippy::too_many_lines,
        reason = "one deterministic assembly boundary validates authority, resolves every reference, accounts every gap, and enforces the final serialized prompt budget"
    )]
    pub fn assemble(
        request: &ContextAssemblyRequest<'_>,
        resolver: &impl ContextMaterialResolver,
        tokenizer: &impl ContextTokenizer,
    ) -> Result<ContextAssemblyOutcome, ContextAssemblyError> {
        validate_scope(request)?;
        request.policy.validate(request.capsule)?;
        let tokenizer_profile = tokenizer.profile()?;
        tokenizer_profile.validate()?;

        let checkpoint_digest = request.foundation.checkpoint.digest()?;
        let mut selected = mandatory_inline_frames(request, tokenizer)?;
        let (required_references, optional_references) = material_references(request)?;
        let input_digest = assembly_input_digest(
            request,
            &checkpoint_digest,
            &selected,
            &required_references,
            &optional_references,
            &tokenizer_profile,
        )?;
        let mut gaps = Vec::new();
        for reference in &required_references {
            match resolve_frame(reference, resolver, tokenizer)? {
                Resolution::Frame(frame) => selected.push(frame),
                Resolution::Gap(gap) => push_gap(&mut gaps, gap, &request.policy)?,
            }
        }

        if gaps
            .iter()
            .any(|gap| gap.requirement == ContextFrameRequirement::Required)
        {
            return blocked_outcome(
                request,
                checkpoint_digest,
                input_digest,
                &selected,
                gaps,
                &tokenizer_profile,
                ContextAssemblyStatus::BlockedMissingRequired,
            );
        }

        if !fits_budget(
            request,
            &checkpoint_digest,
            &selected,
            &gaps,
            &tokenizer_profile,
            tokenizer,
        )? {
            let source = selected
                .last()
                .map_or(ContextFrameSource::TypedInvariant, |frame| {
                    frame.manifest.source
                });
            push_gap(
                &mut gaps,
                ContextGap {
                    source,
                    source_id_digest: digest(b"mandatory-context-budget"),
                    expected_digest: checkpoint_digest.clone(),
                    requirement: ContextFrameRequirement::Required,
                    reason: ContextGapReason::BudgetOmitted,
                },
                &request.policy,
            )?;
            return blocked_outcome(
                request,
                checkpoint_digest,
                input_digest,
                &selected,
                gaps,
                &tokenizer_profile,
                ContextAssemblyStatus::BlockedBudget,
            );
        }

        let mut optional_selected = 0_u32;
        for reference in &optional_references {
            match resolve_frame(reference, resolver, tokenizer)? {
                Resolution::Gap(gap) => push_gap(&mut gaps, gap, &request.policy)?,
                Resolution::Frame(frame) => {
                    if optional_selected >= request.policy.max_optional_frames {
                        push_gap(
                            &mut gaps,
                            gap_for(reference, ContextGapReason::BudgetOmitted),
                            &request.policy,
                        )?;
                        continue;
                    }
                    selected.push(frame);
                    if fits_budget(
                        request,
                        &checkpoint_digest,
                        &selected,
                        &gaps,
                        &tokenizer_profile,
                        tokenizer,
                    )? {
                        optional_selected = optional_selected
                            .checked_add(1)
                            .ok_or(ContextAssemblyError::BudgetOverflow)?;
                    } else {
                        selected.pop();
                        push_gap(
                            &mut gaps,
                            gap_for(reference, ContextGapReason::BudgetOmitted),
                            &request.policy,
                        )?;
                    }
                }
            }
        }

        let envelope = build_envelope(
            request,
            &checkpoint_digest,
            &selected,
            &gaps,
            &tokenizer_profile,
        )?;
        let prompt = envelope.render_prompt()?;
        let prompt_byte_count =
            u64::try_from(prompt.len()).map_err(|_| ContextAssemblyError::BudgetOverflow)?;
        let prompt_token_count = count_prompt_tokens(tokenizer, &tokenizer_profile, &prompt)?;
        if prompt_byte_count > request.policy.max_prompt_bytes
            || prompt_token_count > request.policy.max_prompt_tokens
        {
            push_gap(
                &mut gaps,
                ContextGap {
                    source: ContextFrameSource::TypedInvariant,
                    source_id_digest: digest(b"final-context-budget"),
                    expected_digest: checkpoint_digest.clone(),
                    requirement: ContextFrameRequirement::Required,
                    reason: ContextGapReason::BudgetOmitted,
                },
                &request.policy,
            )?;
            return blocked_outcome(
                request,
                checkpoint_digest,
                input_digest,
                &selected,
                gaps,
                &tokenizer_profile,
                ContextAssemblyStatus::BlockedBudget,
            );
        }
        let manifest = build_manifest(
            request,
            checkpoint_digest,
            input_digest,
            &selected,
            gaps,
            Some(digest(prompt.as_bytes())),
            prompt_byte_count,
            prompt_token_count,
            &tokenizer_profile,
            ContextAssemblyStatus::Ready,
        )?;
        Ok(ContextAssemblyOutcome {
            manifest,
            envelope: Some(envelope),
        })
    }
}

#[derive(Clone)]
struct SelectedFrame {
    manifest: ContextFrameManifest,
    frame: RuntimeContextFrame,
}

enum Resolution {
    Frame(SelectedFrame),
    Gap(ContextGap),
}

fn validate_scope(request: &ContextAssemblyRequest<'_>) -> Result<(), ContextAssemblyError> {
    let foundation = request.foundation;
    let mission = request.mission;
    if foundation.sync_version == 0
        || foundation.workspace.tenant_id != mission.tenant_id
        || foundation.workspace.project_id != mission.project_id
        || foundation.workspace.mission_id != mission.id
        || request.capsule.tenant_id != mission.tenant_id
        || request.capsule.project_id != mission.project_id
        || request.capsule.mission_id != mission.id
        || request.capsule.workspace_id != foundation.workspace.id
        || request.capsule.worker_generation != foundation.workspace.generation
        || request.capsule.status != ContextCapsuleStatus::Claimed
        || request.worker_lease.id != request.capsule.worker_lease_id
    {
        return Err(ContextAssemblyError::ScopeMismatch);
    }
    foundation.validate_for(
        mission,
        request.previous_compaction,
        request.previous_checkpoint,
        request.now,
    )?;
    foundation.workspace.validate_for(mission, request.now)?;
    foundation
        .working_set
        .validate_for(&foundation.workspace, request.now)?;
    foundation.continuation_ledger.validate_for(
        &foundation.workspace,
        Some(mission),
        request.now,
    )?;
    foundation
        .checkpoint
        .invariant
        .assert_exact(mission, &foundation.truth_facts, request.now)?;
    foundation
        .compaction
        .invariant
        .assert_exact(mission, &foundation.truth_facts, request.now)?;
    if foundation.checkpoint.invariant != foundation.compaction.invariant
        || foundation.checkpoint.invariant_digest != foundation.compaction.invariant_digest
        || foundation.checkpoint.working_set_id != foundation.working_set.id
        || foundation.checkpoint.working_set_revision != foundation.working_set.revision
        || foundation.checkpoint.working_set_digest != foundation.working_set.digest()?
        || foundation.checkpoint.continuation_ledger_id != foundation.continuation_ledger.id
        || foundation.checkpoint.continuation_ledger_revision
            != foundation.continuation_ledger.revision
        || foundation.checkpoint.continuation_ledger_digest
            != foundation.continuation_ledger.digest()?
        || foundation.checkpoint.compaction_record_id != foundation.compaction.id
        || foundation.checkpoint.compaction_ordinal != foundation.compaction.ordinal
        || foundation.checkpoint.compaction_digest != foundation.compaction.digest()?
        || foundation.checkpoint.generation != foundation.workspace.generation
        || foundation.checkpoint.mission_revision != mission.revision
    {
        return Err(ContextAssemblyError::StaleCheckpoint);
    }
    validate_context_branch_lineage(&foundation.workspace, request.branch_lineage, request.now)?;
    let branch = request
        .branch_lineage
        .last()
        .ok_or(ContextAssemblyError::ScopeMismatch)?;
    if branch.id != request.capsule.branch_id {
        return Err(ContextAssemblyError::ScopeMismatch);
    }
    request
        .worker_lease
        .validate_for(&foundation.workspace, branch, request.now)?;
    let granted_fact_keys = request
        .capsule
        .required_facts
        .iter()
        .map(|grant| (grant.fact_id.clone(), grant.version))
        .collect::<BTreeSet<_>>();
    let capsule_facts = foundation
        .truth_facts
        .iter()
        .filter(|fact| granted_fact_keys.contains(&(fact.id.clone(), fact.version)))
        .cloned()
        .collect::<Vec<_>>();
    request.capsule.validate_for(
        &foundation.workspace,
        branch,
        request.worker_lease,
        mission,
        &capsule_facts,
        request.now,
    )?;
    Ok(())
}

fn mandatory_inline_frames(
    request: &ContextAssemblyRequest<'_>,
    tokenizer: &impl ContextTokenizer,
) -> Result<Vec<SelectedFrame>, ContextAssemblyError> {
    let mut frames = vec![
        inline_frame(
            ContextFrameSource::TypedInvariant,
            request.foundation.checkpoint.id.as_str(),
            request.foundation.checkpoint.invariant_digest.clone(),
            ContextDataClass::Business,
            ContextFrameRequirement::Required,
            &request.foundation.checkpoint.invariant,
            tokenizer,
        )?,
        inline_frame(
            ContextFrameSource::CapsuleContract,
            request.capsule.id.as_str(),
            request.capsule.authority_digest.clone(),
            request.capsule.data_policy.maximum_class(),
            ContextFrameRequirement::Required,
            request.capsule,
            tokenizer,
        )?,
    ];

    for grant in &request.capsule.required_facts {
        let fact = request
            .foundation
            .truth_facts
            .iter()
            .find(|fact| fact.id == grant.fact_id && fact.version == grant.version)
            .ok_or(ContextAssemblyError::ScopeMismatch)?;
        frames.push(inline_frame(
            ContextFrameSource::TruthFact,
            fact.id.as_str(),
            fact.digest()?,
            grant.classification,
            ContextFrameRequirement::Required,
            fact,
            tokenizer,
        )?);
    }
    for evidence_id in &request.capsule.inputs.evidence_ids {
        let evidence = request
            .mission
            .evidence
            .iter()
            .find(|evidence| &evidence.id == evidence_id)
            .ok_or(ContextAssemblyError::ScopeMismatch)?;
        frames.push(inline_frame(
            ContextFrameSource::Evidence,
            evidence.id.as_str(),
            evidence.content_digest.clone(),
            ContextDataClass::Business,
            ContextFrameRequirement::Required,
            evidence,
            tokenizer,
        )?);
    }
    for work_product_id in &request.capsule.inputs.work_product_ids {
        let work_product = request
            .mission
            .work_products
            .iter()
            .find(|work_product| &work_product.id == work_product_id)
            .ok_or(ContextAssemblyError::ScopeMismatch)?;
        frames.push(inline_frame(
            ContextFrameSource::WorkProduct,
            work_product.id.as_str(),
            work_product.content_digest.clone(),
            ContextDataClass::Business,
            ContextFrameRequirement::Required,
            work_product,
            tokenizer,
        )?);
    }
    Ok(frames)
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered projection makes required-versus-optional reference policy auditable"
)]
fn material_references(
    request: &ContextAssemblyRequest<'_>,
) -> Result<(Vec<ContextMaterialReference>, Vec<ContextMaterialReference>), ContextAssemblyError> {
    let continuation_delivery = ContinuationDeliveryPolicy::load()?;
    let mut required = vec![ContextMaterialReference {
        source: ContextFrameSource::CompactionSummary,
        source_id: request.foundation.compaction.id.to_string(),
        storage_ref: request.foundation.compaction.summary_ref.clone(),
        expected_digest: request.foundation.compaction.summary_digest.clone(),
        declared_max_bytes: Some(request.foundation.compaction.summary_byte_len),
        classification: request.foundation.workspace.data_policy.maximum_class(),
        requirement: ContextFrameRequirement::Required,
        expired: false,
    }];
    let mut optional = Vec::new();

    for entry in &request.foundation.continuation_ledger.entries {
        let requirement = continuation_delivery.requirement_for(entry.kind)?;
        let reference = ContextMaterialReference {
            source: ContextFrameSource::Continuation,
            source_id: format!("{}:{}", entry.sequence, entry.subject_id),
            storage_ref: entry.payload_ref.clone(),
            expected_digest: entry.payload_digest.clone(),
            declared_max_bytes: None,
            classification: ContextDataClass::Business,
            requirement,
            expired: false,
        };
        if requirement == ContextFrameRequirement::Required {
            required.push(reference);
        } else {
            optional.push(reference);
        }
    }

    for item in request.foundation.working_set.items.values() {
        let requirement = if matches!(
            item.kind,
            ContextWorkingItemKind::TruthReference
                | ContextWorkingItemKind::EvidenceReference
                | ContextWorkingItemKind::WorkProductReference
                | ContextWorkingItemKind::EffectReference
        ) {
            ContextFrameRequirement::Required
        } else {
            ContextFrameRequirement::Optional
        };
        let reference = ContextMaterialReference {
            source: ContextFrameSource::WorkingItem,
            source_id: item.key.clone(),
            storage_ref: item.storage_ref.clone(),
            expected_digest: item.content_digest.clone(),
            declared_max_bytes: Some(item.byte_len),
            classification: item.classification,
            requirement,
            expired: item.availability_at(request.now) == ContextItemAvailability::Expired,
        };
        if requirement == ContextFrameRequirement::Required {
            required.push(reference);
        } else {
            optional.push(reference);
        }
    }
    for value in &request.capsule.inputs.file_snapshot_digests {
        required.push(ContextMaterialReference {
            source: ContextFrameSource::FileSnapshot,
            source_id: value.clone(),
            storage_ref: format!("cas://{value}"),
            expected_digest: value.clone(),
            declared_max_bytes: None,
            classification: request.capsule.data_policy.maximum_class(),
            requirement: ContextFrameRequirement::Required,
            expired: false,
        });
    }
    for value in &request.capsule.inputs.query_snapshot_digests {
        required.push(ContextMaterialReference {
            source: ContextFrameSource::QuerySnapshot,
            source_id: value.clone(),
            storage_ref: format!("cas://{value}"),
            expected_digest: value.clone(),
            declared_max_bytes: None,
            classification: request.capsule.data_policy.maximum_class(),
            requirement: ContextFrameRequirement::Required,
            expired: false,
        });
    }
    optional.sort_by(|left, right| {
        right
            .source
            .cmp(&left.source)
            .then_with(|| right.source_id.cmp(&left.source_id))
    });
    Ok((required, optional))
}

fn inline_frame(
    source: ContextFrameSource,
    source_id: &str,
    source_digest: String,
    classification: ContextDataClass,
    requirement: ContextFrameRequirement,
    value: &impl Serialize,
    tokenizer: &impl ContextTokenizer,
) -> Result<SelectedFrame, ContextAssemblyError> {
    let content = serde_json::to_string(value)?;
    selected_frame(
        source,
        source_id,
        source_digest,
        classification,
        requirement,
        content,
        tokenizer,
    )
}

fn selected_frame(
    source: ContextFrameSource,
    source_id: &str,
    source_digest: String,
    classification: ContextDataClass,
    requirement: ContextFrameRequirement,
    content: String,
    tokenizer: &impl ContextTokenizer,
) -> Result<SelectedFrame, ContextAssemblyError> {
    if !is_sha256(&source_digest) || content.is_empty() {
        return Err(ContextAssemblyError::InvalidMaterial);
    }
    let byte_count =
        u64::try_from(content.len()).map_err(|_| ContextAssemblyError::BudgetOverflow)?;
    let token_count = tokenizer.count_tokens(&content)?;
    if token_count == 0 {
        return Err(ContextAssemblyError::TokenizerFailure);
    }
    let source_id_digest = digest(source_id.as_bytes());
    let content_digest = digest(content.as_bytes());
    Ok(SelectedFrame {
        manifest: ContextFrameManifest {
            source,
            source_id_digest: source_id_digest.clone(),
            source_digest,
            content_digest,
            byte_count,
            token_count,
            classification,
            requirement,
        },
        frame: RuntimeContextFrame {
            source,
            source_id_digest,
            classification,
            content,
        },
    })
}

fn resolve_frame(
    reference: &ContextMaterialReference,
    resolver: &impl ContextMaterialResolver,
    tokenizer: &impl ContextTokenizer,
) -> Result<Resolution, ContextAssemblyError> {
    if reference.expired {
        return Ok(Resolution::Gap(gap_for(
            reference,
            ContextGapReason::Expired,
        )));
    }
    let Some(material) = resolver.resolve(reference)? else {
        return Ok(Resolution::Gap(gap_for(
            reference,
            ContextGapReason::Missing,
        )));
    };
    let actual_digest = digest(material.as_str().as_bytes());
    if actual_digest != reference.expected_digest {
        return Err(ContextAssemblyError::MaterialDigestMismatch {
            material_source: reference.source,
            expected_digest: reference.expected_digest.clone(),
            actual_digest,
        });
    }
    let byte_count =
        u64::try_from(material.as_str().len()).map_err(|_| ContextAssemblyError::BudgetOverflow)?;
    if reference
        .declared_max_bytes
        .is_some_and(|maximum| byte_count > maximum)
    {
        return Err(ContextAssemblyError::MaterialSizeMismatch {
            material_source: reference.source,
        });
    }
    Ok(Resolution::Frame(selected_frame(
        reference.source,
        &reference.source_id,
        reference.expected_digest.clone(),
        reference.classification,
        reference.requirement,
        material.as_str().to_owned(),
        tokenizer,
    )?))
}

fn gap_for(reference: &ContextMaterialReference, reason: ContextGapReason) -> ContextGap {
    ContextGap {
        source: reference.source,
        source_id_digest: digest(reference.source_id.as_bytes()),
        expected_digest: reference.expected_digest.clone(),
        requirement: reference.requirement,
        reason,
    }
}

fn push_gap(
    gaps: &mut Vec<ContextGap>,
    gap: ContextGap,
    policy: &ContextAssemblyPolicy,
) -> Result<(), ContextAssemblyError> {
    if gaps.len() >= usize::try_from(policy.max_gap_records).unwrap_or(0) {
        return Err(ContextAssemblyError::GapBudgetExceeded);
    }
    gaps.push(gap);
    Ok(())
}

fn count_prompt_tokens(
    tokenizer: &impl ContextTokenizer,
    frozen_profile: &ContextTokenizerProfile,
    prompt: &str,
) -> Result<u64, ContextAssemblyError> {
    if tokenizer.profile()? != *frozen_profile
        || u64::try_from(prompt.len()).map_err(|_| ContextAssemblyError::TokenizerFailure)?
            > frozen_profile.max_input_bytes
    {
        return Err(ContextAssemblyError::InvalidTokenizerProfile);
    }
    let content_tokens = tokenizer.count_tokens(prompt)?;
    let total = content_tokens
        .checked_add(frozen_profile.request_overhead_tokens)
        .ok_or(ContextAssemblyError::TokenizerFailure)?;
    if content_tokens == 0 || total == 0 {
        return Err(ContextAssemblyError::TokenizerFailure);
    }
    Ok(total)
}

fn fits_budget(
    request: &ContextAssemblyRequest<'_>,
    checkpoint_digest: &str,
    selected: &[SelectedFrame],
    gaps: &[ContextGap],
    tokenizer_profile: &ContextTokenizerProfile,
    tokenizer: &impl ContextTokenizer,
) -> Result<bool, ContextAssemblyError> {
    let envelope = build_envelope(
        request,
        checkpoint_digest,
        selected,
        gaps,
        tokenizer_profile,
    )?;
    let prompt = envelope.render_prompt()?;
    let byte_count =
        u64::try_from(prompt.len()).map_err(|_| ContextAssemblyError::BudgetOverflow)?;
    let token_count = count_prompt_tokens(tokenizer, tokenizer_profile, &prompt)?;
    Ok(byte_count <= request.policy.max_prompt_bytes
        && token_count <= request.policy.max_prompt_tokens)
}

fn build_envelope(
    request: &ContextAssemblyRequest<'_>,
    checkpoint_digest: &str,
    selected: &[SelectedFrame],
    gaps: &[ContextGap],
    tokenizer_profile: &ContextTokenizerProfile,
) -> Result<RuntimeContextEnvelope, ContextAssemblyError> {
    Ok(RuntimeContextEnvelope {
        schema_version: ASSEMBLY_SCHEMA_VERSION,
        assembly_id: request.id.clone(),
        project_id: request.mission.project_id.clone(),
        mission_id: request.mission.id.clone(),
        workspace_id: request.foundation.workspace.id.clone(),
        capsule_id: request.capsule.id.clone(),
        worker_generation: request.capsule.worker_generation,
        checkpoint_digest: checkpoint_digest.to_owned(),
        capsule_authority_digest: request.capsule.authority_digest.clone(),
        tokenizer_profile_digest: tokenizer_profile.digest()?,
        frames: selected.iter().map(|value| value.frame.clone()).collect(),
        gaps: gaps.to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
fn build_manifest(
    request: &ContextAssemblyRequest<'_>,
    checkpoint_digest: String,
    input_digest: String,
    selected: &[SelectedFrame],
    gaps: Vec<ContextGap>,
    prompt_digest: Option<String>,
    prompt_byte_count: u64,
    prompt_token_count: u64,
    tokenizer_profile: &ContextTokenizerProfile,
    status: ContextAssemblyStatus,
) -> Result<ContextAssemblyManifest, ContextAssemblyError> {
    let manifest = ContextAssemblyManifest {
        schema_version: ASSEMBLY_SCHEMA_VERSION,
        id: request.id.clone(),
        tenant_id: request.mission.tenant_id.clone(),
        project_id: request.mission.project_id.clone(),
        mission_id: request.mission.id.clone(),
        workspace_id: request.foundation.workspace.id.clone(),
        capsule_id: request.capsule.id.clone(),
        capsule_revision: request.capsule.revision,
        branch_id: request.capsule.branch_id.clone(),
        branch_revision: request
            .branch_lineage
            .last()
            .map_or(0, |branch| branch.revision),
        worker_id: request.capsule.worker_id.clone(),
        worker_generation: request.capsule.worker_generation,
        worker_lease_id: request.worker_lease.id.clone(),
        worker_lease_revision: request.worker_lease.revision,
        foundation_sync_version: request.foundation.sync_version,
        checkpoint_id: request.foundation.checkpoint.id.clone(),
        checkpoint_digest,
        capsule_authority_digest: request.capsule.authority_digest.clone(),
        policy: request.policy.clone(),
        tokenizer_profile: Some(tokenizer_profile.clone()),
        input_digest,
        frames: selected
            .iter()
            .map(|value| value.manifest.clone())
            .collect(),
        gaps,
        prompt_digest,
        prompt_byte_count,
        prompt_token_count,
        status,
        revision: 1,
        created_at: request.now,
    };
    manifest.validate()?;
    Ok(manifest)
}

fn blocked_outcome(
    request: &ContextAssemblyRequest<'_>,
    checkpoint_digest: String,
    input_digest: String,
    selected: &[SelectedFrame],
    gaps: Vec<ContextGap>,
    tokenizer_profile: &ContextTokenizerProfile,
    status: ContextAssemblyStatus,
) -> Result<ContextAssemblyOutcome, ContextAssemblyError> {
    let manifest = build_manifest(
        request,
        checkpoint_digest,
        input_digest,
        selected,
        gaps,
        None,
        0,
        0,
        tokenizer_profile,
        status,
    )?;
    Ok(ContextAssemblyOutcome {
        manifest,
        envelope: None,
    })
}

fn assembly_input_digest(
    request: &ContextAssemblyRequest<'_>,
    checkpoint_digest: &str,
    inline: &[SelectedFrame],
    required: &[ContextMaterialReference],
    optional: &[ContextMaterialReference],
    tokenizer_profile: &ContextTokenizerProfile,
) -> Result<String, ContextAssemblyError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DigestInput<'a> {
        checkpoint_digest: &'a str,
        capsule_authority_digest: &'a str,
        capsule_revision: u64,
        mission_revision: u64,
        worker_lease_digest: String,
        branch_lineage_digest: String,
        policy: &'a ContextAssemblyPolicy,
        tokenizer_profile: &'a ContextTokenizerProfile,
        inline: Vec<&'a ContextFrameManifest>,
        references: Vec<ReferenceDigest<'a>>,
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ReferenceDigest<'a> {
        source: ContextFrameSource,
        source_id_digest: String,
        storage_ref_digest: String,
        expected_digest: &'a str,
        declared_max_bytes: Option<u64>,
        classification: ContextDataClass,
        requirement: ContextFrameRequirement,
        expired: bool,
    }
    let inline = inline.iter().map(|frame| &frame.manifest).collect();
    let references = required
        .iter()
        .chain(optional)
        .map(|reference| ReferenceDigest {
            source: reference.source,
            source_id_digest: digest(reference.source_id.as_bytes()),
            storage_ref_digest: digest(reference.storage_ref.as_bytes()),
            expected_digest: reference.expected_digest.as_str(),
            declared_max_bytes: reference.declared_max_bytes,
            classification: reference.classification,
            requirement: reference.requirement,
            expired: reference.expired,
        })
        .collect();
    digest_json(&DigestInput {
        checkpoint_digest,
        capsule_authority_digest: &request.capsule.authority_digest,
        capsule_revision: request.capsule.revision,
        mission_revision: request.mission.revision,
        worker_lease_digest: digest_json(request.worker_lease)?,
        branch_lineage_digest: digest_json(&request.branch_lineage)?,
        policy: &request.policy,
        tokenizer_profile,
        inline,
        references,
    })
}

fn digest_json(value: &impl Serialize) -> Result<String, ContextAssemblyError> {
    Ok(digest(&serde_json::to_vec(value)?))
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_bounded_tokenizer_identity(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 256
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

#[derive(Debug, Error)]
pub enum ContextAssemblyError {
    #[error(transparent)]
    Context(#[from] hartevo_domain_kernel::ContextError),
    #[error(transparent)]
    Truth(#[from] hartevo_domain_kernel::TruthError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("context assembly policy is invalid or exceeds the worker token budget")]
    InvalidPolicy,
    #[error("embedded continuation delivery policy is invalid or incomplete")]
    InvalidContinuationDeliveryPolicy,
    #[error("context assembly scope, generation, branch, lease, or capsule is inconsistent")]
    ScopeMismatch,
    #[error("context checkpoint does not match the current working set, continuation, or mission")]
    StaleCheckpoint,
    #[error("context material is empty or has an invalid source digest")]
    InvalidMaterial,
    #[error("context material resolver failed without exposing source content")]
    ResolverFailure,
    #[error("context tokenizer failed or returned zero tokens")]
    TokenizerFailure,
    #[error("context tokenizer profile is invalid or does not match its pinned artifact")]
    InvalidTokenizerProfile,
    #[error(
        "context material digest mismatch for {material_source:?}: {expected_digest} != {actual_digest}"
    )]
    MaterialDigestMismatch {
        material_source: ContextFrameSource,
        expected_digest: String,
        actual_digest: String,
    },
    #[error("context material exceeds its declared byte bound for {material_source:?}")]
    MaterialSizeMismatch { material_source: ContextFrameSource },
    #[error("context prompt or accounting value overflowed its configured budget")]
    BudgetOverflow,
    #[error("context gap manifest exceeds its configured bound")]
    GapBudgetExceeded,
    #[error("context assembly manifest is malformed or falsely claims readiness")]
    InvalidManifest,
    #[error("runtime context envelope does not match its durable assembly manifest")]
    EnvelopeManifestMismatch,
}

/// The typed, content-free Mission Control records that make the Context
/// Fabric durable without introducing a second task-board authority.  Bodies
/// and credentials stay in the existing Project/Mission stores; this surface
/// binds only their stable digests, revisions, and ownership fences.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionControlGateStatus {
    Pending,
    Ready,
    Running,
    Blocked,
    WaitingHuman,
    Completed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionControlTodoStatus {
    Pending,
    Claimed,
    Completed,
    Blocked,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlObjective {
    pub objective_digest: String,
    pub contract_digest: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlGate {
    pub gate_id: String,
    pub status: MissionControlGateStatus,
    pub required_evidence_digest: Option<String>,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlTodo {
    pub todo_id: String,
    pub status: MissionControlTodoStatus,
    pub idempotency_digest: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlEvidence {
    pub evidence_digest: String,
    pub source_digest: String,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlQuota {
    pub token_limit: u64,
    pub token_spent: u64,
    pub cost_limit_minor: i64,
    pub cost_spent_minor: i64,
    pub deadline_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlClaim {
    pub owner_digest: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub lease_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlHandoff {
    pub from_owner_digest: String,
    pub to_owner_digest: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub reason_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlWriteback {
    pub idempotency_digest: String,
    pub payload_digest: String,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionControlSnapshot {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub objective: MissionControlObjective,
    pub gates: Vec<MissionControlGate>,
    pub todos: Vec<MissionControlTodo>,
    pub evidence: Vec<MissionControlEvidence>,
    pub quota: MissionControlQuota,
    pub claim: Option<MissionControlClaim>,
    pub handoff: Option<MissionControlHandoff>,
    pub worker_graph_digest: String,
    pub accepted_writebacks: Vec<MissionControlWriteback>,
    pub mission_revision: u64,
}

impl fmt::Debug for MissionControlSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionControlSnapshot")
            .field("tenant_digest", &digest(self.tenant_id.as_bytes()))
            .field("project_digest", &digest(self.project_id.as_bytes()))
            .field("mission_digest", &digest(self.mission_id.as_bytes()))
            .field("objective_digest", &self.objective.objective_digest)
            .field("gate_count", &self.gates.len())
            .field("todo_count", &self.todos.len())
            .field("evidence_count", &self.evidence.len())
            .field("quota", &(&self.quota.token_limit, &self.quota.token_spent))
            .field("has_claim", &self.claim.is_some())
            .field("has_handoff", &self.handoff.is_some())
            .field("worker_graph_digest", &self.worker_graph_digest)
            .field("accepted_writeback_count", &self.accepted_writebacks.len())
            .field("mission_revision", &self.mission_revision)
            .finish()
    }
}

impl MissionControlSnapshot {
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), MissionControlError> {
        if self.tenant_id.trim().is_empty()
            || self.project_id.trim().is_empty()
            || self.mission_id.trim().is_empty()
            || self.objective.revision == 0
            || !is_sha256(&self.objective.objective_digest)
            || !is_sha256(&self.objective.contract_digest)
            || self.mission_revision == 0
            || !is_sha256(&self.worker_graph_digest)
            || self.quota.token_spent > self.quota.token_limit
            || self.quota.cost_limit_minor < 0
            || self.quota.cost_spent_minor < 0
            || self.quota.cost_spent_minor > self.quota.cost_limit_minor
            || self.quota.deadline_at < now
        {
            return Err(MissionControlError::InvalidSnapshot);
        }
        let mut gate_ids = BTreeSet::new();
        for gate in &self.gates {
            if gate.gate_id.trim().is_empty()
                || !gate_ids.insert(gate.gate_id.as_str())
                || gate.revision == 0
                || gate
                    .required_evidence_digest
                    .as_deref()
                    .is_some_and(|value| !is_sha256(value))
            {
                return Err(MissionControlError::InvalidSnapshot);
            }
        }
        let mut todo_ids = BTreeSet::new();
        let mut writeback_ids = BTreeSet::new();
        for todo in &self.todos {
            if todo.todo_id.trim().is_empty()
                || !todo_ids.insert(todo.todo_id.as_str())
                || todo.revision == 0
                || !is_sha256(&todo.idempotency_digest)
            {
                return Err(MissionControlError::InvalidSnapshot);
            }
        }
        for evidence in &self.evidence {
            if !is_sha256(&evidence.evidence_digest)
                || !is_sha256(&evidence.source_digest)
                || evidence.revision == 0
            {
                return Err(MissionControlError::InvalidSnapshot);
            }
        }
        if let Some(claim) = &self.claim
            && (!is_sha256(&claim.owner_digest)
                || claim.generation == 0
                || claim.attachment_epoch == 0)
        {
            return Err(MissionControlError::InvalidClaim);
        }
        if let Some(handoff) = &self.handoff {
            if !is_sha256(&handoff.from_owner_digest)
                || !is_sha256(&handoff.to_owner_digest)
                || !is_sha256(&handoff.reason_digest)
                || handoff.generation == 0
                || handoff.attachment_epoch == 0
            {
                return Err(MissionControlError::InvalidHandoff);
            }
            if self.claim.as_ref().is_some_and(|claim| {
                claim.owner_digest != handoff.to_owner_digest
                    || claim.generation != handoff.generation
                    || claim.attachment_epoch != handoff.attachment_epoch
            }) {
                return Err(MissionControlError::InvalidHandoff);
            }
        }
        for writeback in &self.accepted_writebacks {
            if !is_sha256(&writeback.idempotency_digest)
                || !is_sha256(&writeback.payload_digest)
                || !writeback_ids.insert(writeback.idempotency_digest.as_str())
            {
                return Err(MissionControlError::InvalidWriteback);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, MissionControlError> {
        serde_json::to_vec(self)
            .map(|bytes| digest(&bytes))
            .map_err(|_| MissionControlError::InvalidSnapshot)
    }

    /// Claims the current generation.  A different owner cannot steal an
    /// active lease; reclamation must present a strictly newer generation.
    pub fn claim(
        &self,
        owner: &str,
        generation: u64,
        attachment_epoch: u64,
        lease_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(Self, MissionControlClaimDisposition), MissionControlError> {
        self.validate(now)?;
        if owner.trim().is_empty() || generation == 0 || attachment_epoch == 0 {
            return Err(MissionControlError::InvalidClaim);
        }
        let owner_digest = digest(owner.as_bytes());
        if lease_expires_at <= now {
            return Err(MissionControlError::InvalidClaim);
        }
        if let Some(current) = &self.claim {
            if current.lease_expires_at > now {
                if current.owner_digest == owner_digest
                    && current.generation == generation
                    && current.attachment_epoch == attachment_epoch
                {
                    return Ok((self.clone(), MissionControlClaimDisposition::Replay));
                }
                return Err(MissionControlError::ClaimLost);
            }
            if generation <= current.generation || attachment_epoch < current.attachment_epoch {
                return Err(MissionControlError::StaleGeneration);
            }
        }
        let mut next = self.clone();
        next.claim = Some(MissionControlClaim {
            owner_digest,
            generation,
            attachment_epoch,
            lease_expires_at,
        });
        next.handoff = None;
        next.validate(now)?;
        Ok((next, MissionControlClaimDisposition::Acquired))
    }

    pub fn handoff(
        &self,
        owner: &str,
        generation: u64,
        attachment_epoch: u64,
        next_owner: &str,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, MissionControlError> {
        self.validate(now)?;
        let claim = self.claim.as_ref().ok_or(MissionControlError::ClaimLost)?;
        if owner.trim().is_empty()
            || next_owner.trim().is_empty()
            || reason.trim().is_empty()
            || claim.owner_digest != digest(owner.as_bytes())
            || claim.generation != generation
            || claim.attachment_epoch != attachment_epoch
            || claim.lease_expires_at <= now
        {
            return Err(MissionControlError::ClaimLost);
        }
        let mut next = self.clone();
        let next_generation = generation
            .checked_add(1)
            .ok_or(MissionControlError::RevisionOverflow)?;
        let next_attachment_epoch = attachment_epoch
            .checked_add(1)
            .ok_or(MissionControlError::RevisionOverflow)?;
        next.handoff = Some(MissionControlHandoff {
            from_owner_digest: claim.owner_digest.clone(),
            to_owner_digest: digest(next_owner.as_bytes()),
            generation: next_generation,
            attachment_epoch: next_attachment_epoch,
            reason_digest: digest(reason.as_bytes()),
        });
        next.claim = Some(MissionControlClaim {
            owner_digest: digest(next_owner.as_bytes()),
            generation: next_generation,
            attachment_epoch: next_attachment_epoch,
            lease_expires_at: claim.lease_expires_at,
        });
        next.validate(now)?;
        Ok(next)
    }

    /// Commits one accepted writeback.  Replaying the same idempotency and
    /// payload is a no-op; reusing an idempotency key for different state is
    /// rejected before any caller can mutate Mission/Event/Outbox rows.
    pub fn accept_writeback(
        &self,
        owner: &str,
        generation: u64,
        attachment_epoch: u64,
        idempotency_key: &str,
        payload_digest: &str,
        now: DateTime<Utc>,
    ) -> Result<(Self, MissionControlWritebackDisposition), MissionControlError> {
        self.validate(now)?;
        let claim = self.claim.as_ref().ok_or(MissionControlError::ClaimLost)?;
        if claim.owner_digest != digest(owner.as_bytes())
            || claim.generation != generation
            || claim.attachment_epoch != attachment_epoch
            || claim.lease_expires_at <= now
            || idempotency_key.trim().is_empty()
            || !is_sha256(payload_digest)
        {
            return Err(MissionControlError::ClaimLost);
        }
        let idempotency_digest = digest(idempotency_key.as_bytes());
        if let Some(existing) = self
            .accepted_writebacks
            .iter()
            .find(|value| value.idempotency_digest == idempotency_digest)
        {
            if existing.payload_digest == payload_digest {
                return Ok((self.clone(), MissionControlWritebackDisposition::Replay));
            }
            return Err(MissionControlError::DuplicateWriteback);
        }
        let mut next = self.clone();
        next.accepted_writebacks.push(MissionControlWriteback {
            idempotency_digest,
            payload_digest: payload_digest.to_owned(),
        });
        next.validate(now)?;
        Ok((next, MissionControlWritebackDisposition::Accepted))
    }

    pub fn reserve_quota(
        &self,
        token_cost: u64,
        cost_minor: i64,
        now: DateTime<Utc>,
    ) -> Result<Self, MissionControlError> {
        self.validate(now)?;
        if token_cost == 0
            || cost_minor < 0
            || self.quota.token_spent.saturating_add(token_cost) > self.quota.token_limit
            || self.quota.cost_spent_minor.saturating_add(cost_minor) > self.quota.cost_limit_minor
        {
            return Err(MissionControlError::QuotaExceeded);
        }
        let mut next = self.clone();
        next.quota.token_spent += token_cost;
        next.quota.cost_spent_minor += cost_minor;
        next.validate(now)?;
        Ok(next)
    }

    /// Returns a bounded control decision without reserving anything.  The
    /// caller must perform an accepted `reserve_quota` write only for
    /// `Deliver`; asking, waiting, falling back, and stopping are read-only.
    pub fn decide_quota(
        &self,
        token_cost: u64,
        cost_minor: i64,
        human_decision_required: bool,
        safe_fallback_available: bool,
        now: DateTime<Utc>,
    ) -> Result<MissionControlQuotaDecision, MissionControlError> {
        self.validate(now)?;
        if token_cost == 0 || cost_minor < 0 {
            return Ok(MissionControlQuotaDecision::Stop);
        }
        if now >= self.quota.deadline_at {
            return Ok(MissionControlQuotaDecision::Stop);
        }
        let fits = self
            .quota
            .token_spent
            .checked_add(token_cost)
            .is_some_and(|spent| spent <= self.quota.token_limit)
            && self
                .quota
                .cost_spent_minor
                .checked_add(cost_minor)
                .is_some_and(|spent| spent <= self.quota.cost_limit_minor);
        if fits {
            Ok(MissionControlQuotaDecision::Deliver)
        } else if human_decision_required {
            Ok(MissionControlQuotaDecision::Ask)
        } else if safe_fallback_available {
            Ok(MissionControlQuotaDecision::SafeFallback)
        } else {
            Ok(MissionControlQuotaDecision::Wait)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionControlClaimDisposition {
    Acquired,
    Replay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionControlWritebackDisposition {
    Accepted,
    Replay,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionControlQuotaDecision {
    Deliver,
    Ask,
    Wait,
    SafeFallback,
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum MissionControlError {
    #[error("mission control snapshot is malformed or exceeds its declared authority")]
    InvalidSnapshot,
    #[error("mission control claim is missing, expired, or outside its generation fence")]
    ClaimLost,
    #[error("mission control generation or attachment epoch is stale")]
    StaleGeneration,
    #[error("mission control claim fields are invalid")]
    InvalidClaim,
    #[error("mission control handoff fields are invalid")]
    InvalidHandoff,
    #[error("mission control writeback fields are invalid")]
    InvalidWriteback,
    #[error("mission control idempotency key was reused with different state")]
    DuplicateWriteback,
    #[error("mission control quota would be exceeded")]
    QuotaExceeded,
    #[error("mission control revision overflowed")]
    RevisionOverflow,
}

/// The three user-visible recovery boundaries of a long-running Mission.
///
/// These are deliberately not Runtime states.  A Runtime generation may be
/// replaced while the Mission, its evidence, and its decision contract stay
/// the same.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionRestartPhase {
    BeforeFirstDelta,
    DuringStreaming,
    BeforeHumanDecision,
}

/// Content-free, exact identity/revision fence used when reopening a Mission.
/// All payloads are represented by digests; the snapshot is safe to carry in
/// an Event, Outbox, or diagnostic response.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionRestartSnapshot {
    pub tenant_id: hartevo_domain_kernel::TenantId,
    pub project_id: hartevo_domain_kernel::ProjectId,
    pub mission_id: hartevo_domain_kernel::MissionId,
    pub conversation_id: hartevo_domain_kernel::MissionConversationId,
    pub checkpoint_id: hartevo_domain_kernel::ContextCheckpointId,
    pub project_digest: String,
    pub mission_digest: String,
    pub contract_digest: String,
    pub conversation_digest: String,
    pub mission_control_digest: String,
    pub pack_digest: Option<String>,
    pub pack_revision: Option<u64>,
    pub mission_revision: u64,
    pub conversation_revision: u64,
    pub cursor_digest: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub idempotency_digest: String,
    pub event_log_digest: String,
    pub outbox_digest: String,
}

impl fmt::Debug for MissionRestartSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionRestartSnapshot")
            .field("tenant_digest", &digest(self.tenant_id.as_str().as_bytes()))
            .field(
                "project_digest",
                &digest(self.project_id.as_str().as_bytes()),
            )
            .field(
                "mission_digest",
                &digest(self.mission_id.as_str().as_bytes()),
            )
            .field(
                "conversation_digest",
                &digest(self.conversation_id.as_str().as_bytes()),
            )
            .field(
                "checkpoint_id_digest",
                &digest(self.checkpoint_id.as_str().as_bytes()),
            )
            .field("project_state_digest", &self.project_digest)
            .field("mission_state_digest", &self.mission_digest)
            .field("contract_digest", &self.contract_digest)
            .field("conversation_state_digest", &self.conversation_digest)
            .field("mission_control_digest", &self.mission_control_digest)
            .field("pack_digest", &self.pack_digest)
            .field("pack_revision", &self.pack_revision)
            .field("mission_revision", &self.mission_revision)
            .field("conversation_revision", &self.conversation_revision)
            .field("cursor_digest", &self.cursor_digest)
            .field("generation", &self.generation)
            .field("attachment_epoch", &self.attachment_epoch)
            .field("idempotency_digest", &self.idempotency_digest)
            .field("event_log_digest", &self.event_log_digest)
            .field("outbox_digest", &self.outbox_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionRestartSnapshotParts {
    pub tenant_id: hartevo_domain_kernel::TenantId,
    pub project_id: hartevo_domain_kernel::ProjectId,
    pub mission_id: hartevo_domain_kernel::MissionId,
    pub conversation_id: hartevo_domain_kernel::MissionConversationId,
    pub checkpoint_id: hartevo_domain_kernel::ContextCheckpointId,
    pub project_digest: String,
    pub mission_digest: String,
    pub contract_digest: String,
    pub conversation_digest: String,
    pub mission_control_digest: String,
    pub pack_digest: Option<String>,
    pub pack_revision: Option<u64>,
    pub mission_revision: u64,
    pub conversation_revision: u64,
    pub cursor_digest: String,
    pub generation: u64,
    pub attachment_epoch: u64,
    pub idempotency_digest: String,
    pub event_log_digest: String,
    pub outbox_digest: String,
}

impl MissionRestartSnapshot {
    pub fn from_parts(parts: MissionRestartSnapshotParts) -> Result<Self, MissionRestartError> {
        let value = Self {
            tenant_id: parts.tenant_id,
            project_id: parts.project_id,
            mission_id: parts.mission_id,
            conversation_id: parts.conversation_id,
            checkpoint_id: parts.checkpoint_id,
            project_digest: parts.project_digest,
            mission_digest: parts.mission_digest,
            contract_digest: parts.contract_digest,
            conversation_digest: parts.conversation_digest,
            mission_control_digest: parts.mission_control_digest,
            pack_digest: parts.pack_digest,
            pack_revision: parts.pack_revision,
            mission_revision: parts.mission_revision,
            conversation_revision: parts.conversation_revision,
            cursor_digest: parts.cursor_digest,
            generation: parts.generation,
            attachment_epoch: parts.attachment_epoch,
            idempotency_digest: parts.idempotency_digest,
            event_log_digest: parts.event_log_digest,
            outbox_digest: parts.outbox_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), MissionRestartError> {
        let valid_ids = !self.tenant_id.as_str().trim().is_empty()
            && !self.project_id.as_str().trim().is_empty()
            && !self.mission_id.as_str().trim().is_empty()
            && !self.conversation_id.as_str().trim().is_empty()
            && !self.checkpoint_id.as_str().trim().is_empty();
        let valid_digests = [
            self.project_digest.as_str(),
            self.mission_digest.as_str(),
            self.contract_digest.as_str(),
            self.conversation_digest.as_str(),
            self.mission_control_digest.as_str(),
            self.cursor_digest.as_str(),
            self.idempotency_digest.as_str(),
            self.event_log_digest.as_str(),
            self.outbox_digest.as_str(),
        ]
        .into_iter()
        .all(is_sha256);
        if !valid_ids
            || !valid_digests
            || self
                .pack_digest
                .as_deref()
                .is_some_and(|value| !is_sha256(value))
            || self.pack_digest.is_some() != self.pack_revision.is_some()
            || self.pack_revision.is_some_and(|value| value == 0)
            || self.mission_revision == 0
            || self.conversation_revision == 0
            || self.generation == 0
            || self.attachment_epoch == 0
        {
            return Err(MissionRestartError::InvalidSnapshot);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, MissionRestartError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(|bytes| digest(&bytes))
            .map_err(|_| MissionRestartError::InvalidSnapshot)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionRestartCheckpoint {
    pub schema_version: u32,
    pub phase: MissionRestartPhase,
    pub snapshot: MissionRestartSnapshot,
    pub checkpoint_digest: String,
}

impl MissionRestartCheckpoint {
    pub const SCHEMA_VERSION: u32 = 1;

    pub fn new(
        phase: MissionRestartPhase,
        snapshot: MissionRestartSnapshot,
    ) -> Result<Self, MissionRestartError> {
        snapshot.validate()?;
        if phase == MissionRestartPhase::BeforeHumanDecision && snapshot.pack_digest.is_none() {
            return Err(MissionRestartError::MissingAuthority);
        }
        let mut value = Self {
            schema_version: Self::SCHEMA_VERSION,
            phase,
            snapshot,
            checkpoint_digest: String::new(),
        };
        value.checkpoint_digest = value.calculate_digest()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), MissionRestartError> {
        if self.schema_version != Self::SCHEMA_VERSION
            || self.snapshot.validate().is_err()
            || (self.phase == MissionRestartPhase::BeforeHumanDecision
                && self.snapshot.pack_digest.is_none())
            || self.checkpoint_digest != self.calculate_digest()?
        {
            return Err(MissionRestartError::InvalidCheckpoint);
        }
        Ok(())
    }

    pub fn validate_reopen(
        &self,
        current: &MissionRestartCheckpoint,
    ) -> Result<MissionRestartDisposition, MissionRestartError> {
        self.validate()?;
        current.validate()?;
        if self.snapshot.tenant_id != current.snapshot.tenant_id
            || self.snapshot.project_id != current.snapshot.project_id
            || self.snapshot.mission_id != current.snapshot.mission_id
            || self.snapshot.conversation_id != current.snapshot.conversation_id
        {
            return Err(MissionRestartError::CrossProject);
        }
        if self.phase != current.phase || self.snapshot != current.snapshot {
            return Err(MissionRestartError::StaleSnapshot);
        }
        Ok(MissionRestartDisposition::ExactReplay)
    }

    fn calculate_digest(&self) -> Result<String, MissionRestartError> {
        let mut value = serde_json::to_value(&self.snapshot)
            .map_err(|_| MissionRestartError::InvalidCheckpoint)?;
        let object = value
            .as_object_mut()
            .ok_or(MissionRestartError::InvalidCheckpoint)?;
        object.insert("phase".into(), serde_json::json!(self.phase));
        object.insert(
            "schemaVersion".into(),
            serde_json::json!(self.schema_version),
        );
        object.insert(
            "checkpointDigest".into(),
            serde_json::Value::String(String::new()),
        );
        serde_json::to_vec(&value)
            .map(|bytes| digest(&bytes))
            .map_err(|_| MissionRestartError::InvalidCheckpoint)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionRestartDisposition {
    ExactReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum MissionRestartError {
    #[error("restart snapshot is malformed or incomplete")]
    InvalidSnapshot,
    #[error("restart checkpoint is malformed or its digest does not match")]
    InvalidCheckpoint,
    #[error("restart checkpoint lacks required durable authority")]
    MissingAuthority,
    #[error("restart checkpoint belongs to another project or mission")]
    CrossProject,
    #[error("restart checkpoint cursor, generation, epoch, or revision is stale")]
    StaleSnapshot,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{Duration, TimeZone};
    use hartevo_domain_kernel::{
        ApprovalPolicy, AutonomyLevel, Constraint, ContextBranchId, ContextBudget,
        ContextCapsuleId, ContextCheckpoint, ContextCheckpointId, ContextCompactionRecord,
        ContextCompactionRecordId, ContextContinuationLedgerId, ContextDataPolicy,
        ContextInputRefs, ContextMergePolicy, ContextReturnContract, ContextWorkingItem,
        ContextWorkingSet, ContextWorkingSetId, ContextWorkspace, ContextWorkspaceId, CurrencyCode,
        EffectClass, MissionContract, MissionId, Money, OperatingMode, ProjectId, Task, TaskId,
        TaskStatus, TenantId, WorkerId, WorkerLeaseId,
    };

    use super::*;

    const SUMMARY_TEXT: &str = "PRIVATE-SUMMARY::bounded decision context";
    const DECISION_TEXT: &str = "PRIVATE-DECISION::Germany evidence is incomplete";
    const REQUIRED_ITEM_TEXT: &str = "PRIVATE-EFFECT::approval remains pending";
    const NEXT_ACTION_TEXT: &str = "PRIVATE-NEXT-ACTION::collect counterevidence";
    const CHECKPOINT_TRANSITION_TEXT: &str =
        "PRIVATE-CHECKPOINT-TRANSITION::resume after checkpoint";
    const ASSEMBLY_AT_SECONDS: i64 = 10;

    #[derive(Clone, Copy)]
    struct FixtureContinuation {
        kind: ContinuationEntryKind,
        subject_id: &'static str,
        storage_ref: &'static str,
        text: &'static str,
    }

    const NEXT_ACTION_CONTINUATION: FixtureContinuation = FixtureContinuation {
        kind: ContinuationEntryKind::NextAction,
        subject_id: "next-action",
        storage_ref: "cas://next-action-context",
        text: NEXT_ACTION_TEXT,
    };
    const CHECKPOINT_TRANSITION_CONTINUATION: FixtureContinuation = FixtureContinuation {
        kind: ContinuationEntryKind::CheckpointTransition,
        subject_id: "checkpoint-transition",
        storage_ref: "cas://checkpoint-transition-context",
        text: CHECKPOINT_TRANSITION_TEXT,
    };

    fn at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn sha(value: &str) -> String {
        digest(value.as_bytes())
    }

    fn usize_as_u64(value: usize) -> u64 {
        u64::try_from(value).expect("test material fits u64")
    }

    #[derive(Clone)]
    struct MapResolver {
        materials: BTreeMap<String, String>,
    }

    impl ContextMaterialResolver for MapResolver {
        fn resolve(
            &self,
            reference: &ContextMaterialReference,
        ) -> Result<Option<ResolvedContextMaterial>, ContextAssemblyError> {
            Ok(self
                .materials
                .get(&reference.storage_ref)
                .cloned()
                .map(ResolvedContextMaterial::text))
        }
    }

    struct ByteTokenizer;

    impl ContextTokenizer for ByteTokenizer {
        fn profile(&self) -> Result<ContextTokenizerProfile, ContextAssemblyError> {
            ContextTokenizerProfile::new(
                "fixture-provider",
                "fixture-byte-model",
                "fixture-revision-v1",
                digest(b"fixture-byte-tokenizer"),
                false,
                0,
                MAX_PROMPT_BYTES,
            )
        }

        fn count_tokens(&self, text: &str) -> Result<u64, ContextAssemblyError> {
            u64::try_from(text.len()).map_err(|_| ContextAssemblyError::TokenizerFailure)
        }
    }

    struct OverheadByteTokenizer;

    impl ContextTokenizer for OverheadByteTokenizer {
        fn profile(&self) -> Result<ContextTokenizerProfile, ContextAssemblyError> {
            ContextTokenizerProfile::new(
                "fixture-provider",
                "fixture-byte-model",
                "fixture-revision-v1",
                digest(b"fixture-byte-tokenizer"),
                false,
                7,
                MAX_PROMPT_BYTES,
            )
        }

        fn count_tokens(&self, text: &str) -> Result<u64, ContextAssemblyError> {
            u64::try_from(text.len()).map_err(|_| ContextAssemblyError::TokenizerFailure)
        }
    }

    struct DriftingTokenizer {
        profile_calls: std::cell::Cell<u32>,
    }

    impl ContextTokenizer for DriftingTokenizer {
        fn profile(&self) -> Result<ContextTokenizerProfile, ContextAssemblyError> {
            let call = self.profile_calls.get();
            self.profile_calls.set(call + 1);
            ContextTokenizerProfile::new(
                "fixture-provider",
                if call == 0 {
                    "fixture-byte-model"
                } else {
                    "drifted-byte-model"
                },
                "fixture-revision-v1",
                digest(b"fixture-byte-tokenizer"),
                false,
                0,
                MAX_PROMPT_BYTES,
            )
        }

        fn count_tokens(&self, text: &str) -> Result<u64, ContextAssemblyError> {
            u64::try_from(text.len()).map_err(|_| ContextAssemblyError::TokenizerFailure)
        }
    }

    struct AssemblyFixture {
        mission: Mission,
        foundation: ContextFoundationSnapshot,
        branch_lineage: Vec<ContextBranch>,
        worker_lease: WorkerLease,
        capsule: ContextCapsule,
        resolver: MapResolver,
    }

    impl AssemblyFixture {
        fn request(&self, policy: ContextAssemblyPolicy) -> ContextAssemblyRequest<'_> {
            ContextAssemblyRequest {
                id: ContextAssemblyId::from("assembly-context-v1"),
                mission: &self.mission,
                foundation: &self.foundation,
                previous_compaction: None,
                previous_checkpoint: None,
                branch_lineage: &self.branch_lineage,
                worker_lease: &self.worker_lease,
                capsule: &self.capsule,
                policy,
                now: at() + Duration::seconds(ASSEMBLY_AT_SECONDS),
            }
        }
    }

    fn roomy_policy() -> ContextAssemblyPolicy {
        ContextAssemblyPolicy {
            version: 1,
            max_prompt_tokens: 100_000,
            reserved_output_tokens: 10_000,
            max_prompt_bytes: 1_000_000,
            max_optional_frames: 32,
            max_gap_records: 64,
        }
    }

    fn expiry(expired_at_assembly: bool) -> Option<DateTime<Utc>> {
        expired_at_assembly.then(|| at() + Duration::seconds(6))
    }

    fn fixture(required_expired: bool, optional_expired: bool) -> AssemblyFixture {
        fixture_with_continuation(required_expired, optional_expired, NEXT_ACTION_CONTINUATION)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the test fixture constructs one fully valid Mission-to-Checkpoint-to-Capsule authority closure"
    )]
    fn fixture_with_continuation(
        required_expired: bool,
        optional_expired: bool,
        fixture_continuation: FixtureContinuation,
    ) -> AssemblyFixture {
        let contract = MissionContract {
            version: 1,
            mode: OperatingMode::BuildOnce,
            parent_mission_id: None,
            goal: "Produce one bounded market decision".into(),
            non_goals: vec!["Never publish or spend".into()],
            market: "DE".into(),
            language: "de".into(),
            audience: "owner".into(),
            kpis: BTreeMap::new(),
            budget: Money::new(50_000, CurrencyCode::parse("EUR").expect("EUR")),
            timezone: "Europe/Berlin".into(),
            cadence: None,
            autonomy_by_capability: BTreeMap::from([(
                "market.analyze".into(),
                AutonomyLevel::ApprovalRequired,
            )]),
            consent_requirements: BTreeSet::new(),
            approval_policy: ApprovalPolicy {
                required_effect_classes: BTreeSet::from([EffectClass::ExternalWrite]),
                validity_seconds: 3_600,
                exact_scope_required: true,
            },
            stop_conditions: vec!["user_cancelled".into()],
            completion_conditions: vec!["typed_decision_returned".into()],
            valid_from: at(),
            valid_until: at() + Duration::days(1),
            constraints: vec![Constraint::Market { value: "DE".into() }],
            enabled_capabilities: BTreeSet::from(["market.analyze".into()]),
            forbidden_capabilities: BTreeSet::new(),
        };
        let mut mission = Mission::compile(
            TenantId::from("tenant-context-assembly"),
            MissionId::from("mission-context-assembly"),
            ProjectId::from("project-context-assembly"),
            "Context assembly",
            contract,
            at(),
        )
        .expect("mission");
        mission
            .start_research(
                [Task {
                    id: TaskId::from("task-context-assembly"),
                    title: "Analyze bounded evidence".into(),
                    status: TaskStatus::Ready,
                    capability: "market.analyze".into(),
                }],
                at(),
            )
            .expect("running mission");
        let workspace = ContextWorkspace::create(
            ContextWorkspaceId::from("workspace-context-assembly"),
            &mission,
            7,
            "context-policy/v1",
            mission.contract.enabled_capabilities.clone(),
            ContextBudget {
                token_limit: 250_000,
                cost_limit: mission.contract.budget.clone(),
                deadline_at: at() + Duration::hours(6),
                max_depth: 4,
                max_concurrency: 2,
            },
            ContextDataPolicy::BusinessOnly,
            at(),
        )
        .expect("workspace");
        let branch = ContextBranch::create(
            ContextBranchId::from("branch-context-assembly"),
            &workspace,
            None,
            "isolate one runtime turn",
            "1".repeat(64),
            ContextMergePolicy::TypedResultOnly,
            at(),
        )
        .expect("branch");
        let worker_lease = WorkerLease::issue(
            WorkerLeaseId::from("lease-context-assembly"),
            &workspace,
            &branch,
            WorkerId::from("worker-context-assembly"),
            workspace.generation,
            "2".repeat(64),
            Some("3".repeat(64)),
            at() + Duration::hours(4),
            at(),
        )
        .expect("worker lease");

        let optional_text = format!("PRIVATE-OPTIONAL::{}", "x".repeat(6_000));
        let mut working_set = ContextWorkingSet::create(
            ContextWorkingSetId::from("working-set-context-assembly"),
            &workspace,
            at(),
        )
        .expect("working set");
        working_set
            .replace_items(
                BTreeMap::from([
                    (
                        "pending-effect".into(),
                        ContextWorkingItem {
                            key: "pending-effect".into(),
                            kind: ContextWorkingItemKind::EffectReference,
                            storage_ref: "cas://pending-effect-context".into(),
                            content_digest: sha(REQUIRED_ITEM_TEXT),
                            byte_len: usize_as_u64(REQUIRED_ITEM_TEXT.len()),
                            classification: ContextDataClass::Business,
                            provenance_digest: "4".repeat(64),
                            expires_at: expiry(required_expired),
                            created_at: at(),
                        },
                    ),
                    (
                        "conversation-tail".into(),
                        ContextWorkingItem {
                            key: "conversation-tail".into(),
                            kind: ContextWorkingItemKind::ConversationTail,
                            storage_ref: "cas://conversation-tail-context".into(),
                            content_digest: sha(&optional_text),
                            byte_len: usize_as_u64(optional_text.len()),
                            classification: ContextDataClass::Business,
                            provenance_digest: "5".repeat(64),
                            expires_at: expiry(optional_expired),
                            created_at: at(),
                        },
                    ),
                ]),
                &workspace,
                at() + Duration::seconds(1),
            )
            .expect("working material");
        let mut continuation = hartevo_domain_kernel::ContinuationLedger::create(
            ContextContinuationLedgerId::from("continuation-context-assembly"),
            &workspace,
            at(),
        )
        .expect("continuation ledger");
        continuation
            .append(
                hartevo_domain_kernel::ContinuationEntryInput {
                    kind: ContinuationEntryKind::Decision,
                    subject_id: "market-decision".into(),
                    payload_ref: "cas://decision-context".into(),
                    payload_digest: sha(DECISION_TEXT),
                    evidence_ids: BTreeSet::new(),
                },
                &workspace,
                &mission,
                at() + Duration::seconds(1),
            )
            .expect("decision continuation");
        continuation
            .append(
                hartevo_domain_kernel::ContinuationEntryInput {
                    kind: fixture_continuation.kind,
                    subject_id: fixture_continuation.subject_id.into(),
                    payload_ref: fixture_continuation.storage_ref.into(),
                    payload_digest: sha(fixture_continuation.text),
                    evidence_ids: BTreeSet::new(),
                },
                &workspace,
                &mission,
                at() + Duration::seconds(2),
            )
            .expect("required continuation");
        let compaction = ContextCompactionRecord::create(
            ContextCompactionRecordId::from("compaction-context-assembly"),
            &workspace,
            &mission,
            &[],
            None,
            1,
            20,
            "6".repeat(64),
            20_000,
            15,
            "cas://summary-context".into(),
            sha(SUMMARY_TEXT),
            usize_as_u64(SUMMARY_TEXT.len()),
            usize_as_u64(SUMMARY_TEXT.len()),
            BTreeSet::new(),
            "7".repeat(64),
            "8".repeat(64),
            "9".repeat(64),
            at() + Duration::seconds(3),
        )
        .expect("compaction");
        let checkpoint = ContextCheckpoint::create(
            ContextCheckpointId::from("checkpoint-context-assembly"),
            &workspace,
            &mission,
            &[],
            &working_set,
            &continuation,
            &compaction,
            None,
            "a".repeat(64),
            "b".repeat(64),
            20,
            at() + Duration::seconds(4),
        )
        .expect("checkpoint");
        let foundation = ContextFoundationSnapshot {
            sync_version: 1,
            workspace: workspace.clone(),
            working_set,
            continuation_ledger: continuation,
            compaction,
            checkpoint,
            truth_facts: vec![],
        };
        let mut capsule = ContextCapsule::issue(
            ContextCapsuleId::from("capsule-context-assembly"),
            &workspace,
            &branch,
            &worker_lease,
            &mission,
            "Return only the typed decision contract",
            TaskId::from("task-context-assembly"),
            BTreeSet::new(),
            &[],
            BTreeSet::from(["market.analyze".into()]),
            ContextBudget {
                token_limit: 200_000,
                cost_limit: Money::new(10_000, CurrencyCode::parse("EUR").expect("EUR")),
                deadline_at: at() + Duration::hours(2),
                max_depth: 1,
                max_concurrency: 1,
            },
            ContextInputRefs::default(),
            ContextReturnContract {
                schema_id: "hartevo.context.typed-decision".into(),
                schema_version: 1,
                required_fields: BTreeSet::from(["decision".into(), "uncertainty".into()]),
                allowed_artifact_types: BTreeSet::new(),
                evidence_required: false,
                uncertainty_required: true,
                max_result_bytes: 64 * 1024,
            },
            at() + Duration::minutes(90),
            at() + Duration::seconds(4),
        )
        .expect("capsule");
        capsule
            .claim(workspace.generation, at() + Duration::seconds(5))
            .expect("capsule claim");
        let mut materials = BTreeMap::from([
            ("cas://summary-context".into(), SUMMARY_TEXT.into()),
            ("cas://decision-context".into(), DECISION_TEXT.into()),
            (
                "cas://pending-effect-context".into(),
                REQUIRED_ITEM_TEXT.into(),
            ),
            ("cas://conversation-tail-context".into(), optional_text),
        ]);
        materials.insert(
            fixture_continuation.storage_ref.into(),
            fixture_continuation.text.into(),
        );
        AssemblyFixture {
            mission,
            foundation,
            branch_lineage: vec![branch],
            worker_lease,
            capsule,
            resolver: MapResolver { materials },
        }
    }

    #[test]
    fn continuation_delivery_contract_is_total_required_when_present_and_non_synthesizing() {
        let policy = ContinuationDeliveryPolicy::load().expect("valid embedded delivery contract");
        assert_eq!(
            policy.continuation_entry_lifetime,
            ContinuationEntryLifetime::NonExpiring
        );
        assert_eq!(
            policy.absent_kind_policy,
            AbsentContinuationKindPolicy::NoSyntheticReference
        );
        assert_eq!(
            policy.delivery_by_kind.len(),
            CONTINUATION_ENTRY_KINDS.len()
        );
        for kind in CONTINUATION_ENTRY_KINDS {
            assert_eq!(
                policy.requirement_for(kind).expect("known kind"),
                ContextFrameRequirement::Required
            );
        }
        for kind in CONTINUATION_ENTRY_KINDS {
            let mut unsupported = ContinuationDeliveryPolicy::load().expect("valid policy");
            unsupported
                .delivery_by_kind
                .insert(kind, ContinuationDeliveryRequirement::Unsupported);
            assert!(matches!(
                unsupported.validate(),
                Err(ContextAssemblyError::InvalidContinuationDeliveryPolicy)
            ));
            assert!(matches!(
                unsupported.requirement_for(kind),
                Err(ContextAssemblyError::InvalidContinuationDeliveryPolicy)
            ));
        }

        let fixture = fixture(false, false);
        let request = fixture.request(roomy_policy());
        let (required, optional) = material_references(&request).expect("material projection");
        let required_continuations = required
            .iter()
            .filter(|reference| reference.source == ContextFrameSource::Continuation)
            .collect::<Vec<_>>();
        assert_eq!(
            required_continuations.len(),
            fixture.foundation.continuation_ledger.entries.len()
        );
        assert!(required_continuations.iter().all(|reference| {
            reference.requirement == ContextFrameRequirement::Required && !reference.expired
        }));
        assert!(
            optional
                .iter()
                .all(|reference| reference.source != ContextFrameSource::Continuation)
        );
    }

    #[test]
    fn deterministic_ready_projection_persists_only_content_free_evidence() {
        let fixture = fixture(false, false);
        let request = fixture.request(roomy_policy());
        let first = ContextAssembler::assemble(&request, &fixture.resolver, &ByteTokenizer)
            .expect("first assembly");
        let second = ContextAssembler::assemble(&request, &fixture.resolver, &ByteTokenizer)
            .expect("deterministic replay");
        assert_eq!(first, second);
        assert_eq!(first.manifest.status, ContextAssemblyStatus::Ready);
        let tokenizer_profile = first
            .manifest
            .tokenizer_profile
            .as_ref()
            .expect("tokenizer profile");
        assert_eq!(
            envelope_tokenizer_digest(first.envelope.as_ref().expect("envelope")),
            tokenizer_profile
                .digest()
                .expect("tokenizer profile digest")
        );
        assert!(first.manifest.prompt_token_count > 0);
        assert!(first.manifest.frames.iter().any(|frame| {
            frame.source == ContextFrameSource::TypedInvariant
                && frame.requirement == ContextFrameRequirement::Required
        }));
        assert!(first.manifest.frames.iter().any(|frame| {
            frame.source == ContextFrameSource::CompactionSummary
                && frame.requirement == ContextFrameRequirement::Required
        }));
        let envelope = first.envelope.as_ref().expect("ready envelope");
        envelope
            .validate_against(&first.manifest)
            .expect("exact transient projection");
        let prompt = envelope.render_prompt().expect("runtime prompt");
        assert!(prompt.contains(SUMMARY_TEXT));
        assert!(prompt.contains(REQUIRED_ITEM_TEXT));
        let manifest_json = serde_json::to_string(&first.manifest).expect("manifest");
        let debug = format!(
            "{first:?} {envelope:?} {:?}",
            fixture
                .resolver
                .resolve(&ContextMaterialReference {
                    source: ContextFrameSource::WorkingItem,
                    source_id: "secret-id".into(),
                    storage_ref: "cas://pending-effect-context".into(),
                    expected_digest: sha(REQUIRED_ITEM_TEXT),
                    declared_max_bytes: None,
                    classification: ContextDataClass::Business,
                    requirement: ContextFrameRequirement::Required,
                    expired: false,
                })
                .expect("resolver")
                .expect("material")
        );
        for secret in [
            SUMMARY_TEXT,
            DECISION_TEXT,
            REQUIRED_ITEM_TEXT,
            NEXT_ACTION_TEXT,
        ] {
            assert!(!manifest_json.contains(secret));
            assert!(!debug.contains(secret));
        }
        first.manifest.digest().expect("valid evidence digest");

        let mut forged_envelope = envelope.clone();
        forged_envelope.frames[0].content.push_str("::forged");
        assert!(matches!(
            forged_envelope.validate_against(&first.manifest),
            Err(ContextAssemblyError::EnvelopeManifestMismatch)
        ));
    }

    fn envelope_tokenizer_digest(envelope: &RuntimeContextEnvelope) -> String {
        envelope.tokenizer_profile_digest.clone()
    }

    #[test]
    fn tokenizer_request_overhead_is_applied_once_and_profile_drift_fails_closed() {
        let fixture = fixture(false, false);
        let request = fixture.request(roomy_policy());
        let outcome =
            ContextAssembler::assemble(&request, &fixture.resolver, &OverheadByteTokenizer)
                .expect("overhead assembly");
        let envelope = outcome.envelope.as_ref().expect("ready envelope");
        let prompt = envelope.render_prompt().expect("prompt");
        assert_eq!(
            outcome.manifest.prompt_token_count,
            u64::try_from(prompt.len()).expect("prompt length") + 7
        );
        assert!(
            outcome
                .manifest
                .frames
                .iter()
                .all(|frame| frame.token_count == frame.byte_count)
        );

        let drifting = DriftingTokenizer {
            profile_calls: std::cell::Cell::new(0),
        };
        assert!(matches!(
            ContextAssembler::assemble(&request, &fixture.resolver, &drifting),
            Err(ContextAssemblyError::InvalidTokenizerProfile)
        ));
    }

    #[test]
    fn legacy_unbound_manifest_is_auditable_but_never_dispatchable() {
        let fixture = fixture(false, false);
        let outcome = ContextAssembler::assemble(
            &fixture.request(roomy_policy()),
            &fixture.resolver,
            &ByteTokenizer,
        )
        .expect("current assembly");
        let mut legacy = outcome.manifest.clone();
        legacy.schema_version = 1;
        legacy.tokenizer_profile = None;
        legacy.validate().expect("legacy evidence remains readable");
        legacy.digest().expect("legacy evidence remains hashable");
        assert!(matches!(
            legacy.validate_dispatchable(),
            Err(ContextAssemblyError::InvalidManifest)
        ));
        assert!(matches!(
            outcome
                .envelope
                .expect("current envelope")
                .validate_against(&legacy),
            Err(ContextAssemblyError::InvalidManifest)
        ));
        assert!(
            !serde_json::to_string(&legacy)
                .expect("legacy JSON")
                .contains("tokenizerProfile")
        );
    }

    #[test]
    fn required_material_missing_or_tampered_never_reaches_runtime() {
        let fixture = fixture(false, false);
        let mut missing = fixture.resolver.clone();
        missing.materials.remove("cas://summary-context");
        let request = fixture.request(roomy_policy());
        let blocked = ContextAssembler::assemble(&request, &missing, &ByteTokenizer)
            .expect("missing material becomes an explicit block");
        assert_eq!(
            blocked.manifest.status,
            ContextAssemblyStatus::BlockedMissingRequired
        );
        assert!(blocked.envelope.is_none());
        assert!(blocked.manifest.gaps.iter().any(|gap| {
            gap.source == ContextFrameSource::CompactionSummary
                && gap.requirement == ContextFrameRequirement::Required
                && gap.reason == ContextGapReason::Missing
        }));

        let mut tampered = fixture.resolver.clone();
        tampered.materials.insert(
            "cas://summary-context".into(),
            "ATTACKER-CONTROLLED-SUMMARY".into(),
        );
        assert!(matches!(
            ContextAssembler::assemble(&request, &tampered, &ByteTokenizer),
            Err(ContextAssemblyError::MaterialDigestMismatch {
                material_source: ContextFrameSource::CompactionSummary,
                ..
            })
        ));
    }

    #[test]
    fn present_next_action_and_checkpoint_transition_missing_material_blocks() {
        for continuation in [NEXT_ACTION_CONTINUATION, CHECKPOINT_TRANSITION_CONTINUATION] {
            let fixture = fixture_with_continuation(false, false, continuation);
            let mut missing = fixture.resolver.clone();
            missing.materials.remove(continuation.storage_ref);
            let blocked = ContextAssembler::assemble(
                &fixture.request(roomy_policy()),
                &missing,
                &ByteTokenizer,
            )
            .expect("missing required continuation becomes an explicit block");
            assert_eq!(
                blocked.manifest.status,
                ContextAssemblyStatus::BlockedMissingRequired
            );
            assert!(blocked.envelope.is_none());
            assert!(blocked.manifest.gaps.iter().any(|gap| {
                gap.source == ContextFrameSource::Continuation
                    && gap.expected_digest == sha(continuation.text)
                    && gap.requirement == ContextFrameRequirement::Required
                    && gap.reason == ContextGapReason::Missing
            }));
            let manifest_json = serde_json::to_string(&blocked.manifest).expect("manifest");
            assert!(!manifest_json.contains(continuation.text));
            assert!(!format!("{blocked:?}").contains(continuation.text));
        }
    }

    #[test]
    fn expiry_distinguishes_required_block_from_optional_gap() {
        let generic_required_reference = ContextMaterialReference {
            source: ContextFrameSource::WorkingItem,
            source_id: "generic-expired-required".into(),
            storage_ref: "cas://generic-expired-required".into(),
            expected_digest: sha("generic expired material"),
            declared_max_bytes: None,
            classification: ContextDataClass::Business,
            requirement: ContextFrameRequirement::Required,
            expired: true,
        };
        let direct_resolution = resolve_frame(
            &generic_required_reference,
            &MapResolver {
                materials: BTreeMap::new(),
            },
            &ByteTokenizer,
        )
        .expect("generic expiry resolves without loading material");
        assert!(matches!(
            direct_resolution,
            Resolution::Gap(ContextGap {
                requirement: ContextFrameRequirement::Required,
                reason: ContextGapReason::Expired,
                ..
            })
        ));

        let required_expired = fixture(true, false);
        let blocked = ContextAssembler::assemble(
            &required_expired.request(roomy_policy()),
            &required_expired.resolver,
            &ByteTokenizer,
        )
        .expect("required expiry is represented");
        assert_eq!(
            blocked.manifest.status,
            ContextAssemblyStatus::BlockedMissingRequired
        );
        assert!(blocked.envelope.is_none());
        assert!(blocked.manifest.gaps.iter().any(|gap| {
            gap.requirement == ContextFrameRequirement::Required
                && gap.reason == ContextGapReason::Expired
        }));

        let optional_expired = fixture(false, true);
        let ready = ContextAssembler::assemble(
            &optional_expired.request(roomy_policy()),
            &optional_expired.resolver,
            &ByteTokenizer,
        )
        .expect("optional expiry remains explicit");
        assert_eq!(ready.manifest.status, ContextAssemblyStatus::Ready);
        assert!(ready.envelope.is_some());
        assert!(ready.manifest.gaps.iter().any(|gap| {
            gap.requirement == ContextFrameRequirement::Optional
                && gap.reason == ContextGapReason::Expired
        }));
    }

    #[test]
    fn optional_budget_omission_is_explicit_and_mandatory_overflow_blocks() {
        let fixture = fixture(false, false);
        let mut without_optional = fixture.resolver.clone();
        without_optional
            .materials
            .remove("cas://conversation-tail-context");
        let baseline = ContextAssembler::assemble(
            &fixture.request(roomy_policy()),
            &without_optional,
            &ByteTokenizer,
        )
        .expect("measure required projection");
        let mut bounded = roomy_policy();
        bounded.max_prompt_tokens = baseline
            .manifest
            .prompt_token_count
            .checked_add(128)
            .expect("bounded test budget");
        let omitted = ContextAssembler::assemble(
            &fixture.request(bounded),
            &fixture.resolver,
            &ByteTokenizer,
        )
        .expect("optional material may be omitted");
        assert_eq!(omitted.manifest.status, ContextAssemblyStatus::Ready);
        assert!(omitted.manifest.gaps.iter().any(|gap| {
            gap.requirement == ContextFrameRequirement::Optional
                && gap.reason == ContextGapReason::BudgetOmitted
        }));

        for continuation in [NEXT_ACTION_CONTINUATION, CHECKPOINT_TRANSITION_CONTINUATION] {
            let fixture = fixture_with_continuation(false, false, continuation);
            let mut impossible = roomy_policy();
            impossible.max_prompt_tokens = 10;
            impossible.max_prompt_bytes = 10;
            let blocked = ContextAssembler::assemble(
                &fixture.request(impossible),
                &fixture.resolver,
                &ByteTokenizer,
            )
            .expect("mandatory overflow is durable evidence, not a partial prompt");
            assert_eq!(
                blocked.manifest.status,
                ContextAssemblyStatus::BlockedBudget
            );
            assert!(blocked.envelope.is_none());
            assert!(blocked.manifest.frames.iter().any(|frame| {
                frame.source == ContextFrameSource::Continuation
                    && frame.requirement == ContextFrameRequirement::Required
                    && frame.content_digest == sha(continuation.text)
            }));
            assert!(blocked.manifest.gaps.iter().any(|gap| {
                gap.requirement == ContextFrameRequirement::Required
                    && gap.reason == ContextGapReason::BudgetOmitted
            }));
        }
    }

    #[test]
    fn stale_authority_and_false_manifest_status_are_rejected() {
        let fixture = fixture(false, false);
        let mut stale_foundation = fixture.foundation.clone();
        stale_foundation.checkpoint.working_set_revision += 1;
        let request = ContextAssemblyRequest {
            foundation: &stale_foundation,
            ..fixture.request(roomy_policy())
        };
        assert!(matches!(
            ContextAssembler::assemble(&request, &fixture.resolver, &ByteTokenizer),
            Err(ContextAssemblyError::Context(_) | ContextAssemblyError::StaleCheckpoint)
        ));

        let mut missing = fixture.resolver.clone();
        missing.materials.remove("cas://summary-context");
        let mut forged =
            ContextAssembler::assemble(&fixture.request(roomy_policy()), &missing, &ByteTokenizer)
                .expect("blocked evidence")
                .manifest;
        forged.status = ContextAssemblyStatus::Ready;
        forged.prompt_digest = Some("f".repeat(64));
        forged.prompt_byte_count = 1;
        forged.prompt_token_count = 1;
        assert!(matches!(
            forged.validate(),
            Err(ContextAssemblyError::InvalidManifest)
        ));

        let mut unclaimed = fixture.capsule.clone();
        unclaimed.status = ContextCapsuleStatus::Issued;
        let request = ContextAssemblyRequest {
            capsule: &unclaimed,
            ..fixture.request(roomy_policy())
        };
        assert!(matches!(
            ContextAssembler::assemble(&request, &fixture.resolver, &ByteTokenizer),
            Err(ContextAssemblyError::ScopeMismatch)
        ));
    }

    fn restart_snapshot(pack: bool) -> MissionRestartSnapshot {
        let digest = || "a".repeat(64);
        MissionRestartSnapshot::from_parts(MissionRestartSnapshotParts {
            tenant_id: TenantId::from("restart-tenant"),
            project_id: ProjectId::from("restart-project"),
            mission_id: MissionId::from("restart-mission"),
            conversation_id: hartevo_domain_kernel::MissionConversationId::from(
                "restart-conversation",
            ),
            checkpoint_id: ContextCheckpointId::from("restart-checkpoint"),
            project_digest: digest(),
            mission_digest: digest(),
            contract_digest: digest(),
            conversation_digest: digest(),
            mission_control_digest: digest(),
            pack_digest: pack.then(digest),
            pack_revision: pack.then_some(3),
            mission_revision: 4,
            conversation_revision: 5,
            cursor_digest: digest(),
            generation: 6,
            attachment_epoch: 7,
            idempotency_digest: digest(),
            event_log_digest: digest(),
            outbox_digest: digest(),
        })
        .expect("valid restart snapshot")
    }

    #[test]
    fn mission_restart_checkpoint_is_exact_and_fails_closed_on_scope_or_cursor_drift() {
        for phase in [
            MissionRestartPhase::BeforeFirstDelta,
            MissionRestartPhase::DuringStreaming,
            MissionRestartPhase::BeforeHumanDecision,
        ] {
            let snapshot = restart_snapshot(true);
            let checkpoint = MissionRestartCheckpoint::new(phase, snapshot.clone())
                .expect("phase has required durable fields");
            assert_eq!(
                checkpoint
                    .validate_reopen(&checkpoint)
                    .expect("exact reopen"),
                MissionRestartDisposition::ExactReplay
            );

            let mut stale_snapshot = snapshot.clone();
            stale_snapshot.cursor_digest = "b".repeat(64);
            let stale = MissionRestartCheckpoint::new(phase, stale_snapshot)
                .expect("stale snapshot remains well-formed");
            assert_eq!(
                checkpoint.validate_reopen(&stale),
                Err(MissionRestartError::StaleSnapshot)
            );

            let mutations: [fn(&mut MissionRestartSnapshot); 3] = [
                |snapshot: &mut MissionRestartSnapshot| snapshot.generation += 1,
                |snapshot: &mut MissionRestartSnapshot| snapshot.attachment_epoch += 1,
                |snapshot: &mut MissionRestartSnapshot| snapshot.mission_revision += 1,
            ];
            for mutate in mutations {
                let mut stale_snapshot = snapshot.clone();
                mutate(&mut stale_snapshot);
                let stale = MissionRestartCheckpoint::new(phase, stale_snapshot)
                    .expect("fenced snapshot remains well-formed");
                assert_eq!(
                    checkpoint.validate_reopen(&stale),
                    Err(MissionRestartError::StaleSnapshot)
                );
            }

            let mut cross_project = snapshot;
            cross_project.project_id = ProjectId::from("other-project");
            let cross_project = MissionRestartCheckpoint::new(phase, cross_project)
                .expect("cross-project snapshot remains well-formed");
            assert_eq!(
                checkpoint.validate_reopen(&cross_project),
                Err(MissionRestartError::CrossProject)
            );
        }
    }

    #[test]
    fn mission_restart_checkpoint_requires_pack_before_human_decision_and_redacts_ids() {
        assert_eq!(
            MissionRestartCheckpoint::new(
                MissionRestartPhase::BeforeHumanDecision,
                restart_snapshot(false),
            ),
            Err(MissionRestartError::MissingAuthority)
        );

        let snapshot = restart_snapshot(true);
        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("restart-project"));
        assert!(!debug.contains("restart-mission"));
        assert!(debug.contains("project_state_digest"));

        let mut invalid = snapshot;
        invalid.cursor_digest.clear();
        assert_eq!(
            invalid.validate(),
            Err(MissionRestartError::InvalidSnapshot)
        );
    }

    fn mission_control_snapshot(at: DateTime<Utc>) -> MissionControlSnapshot {
        let digest = || "a".repeat(64);
        MissionControlSnapshot {
            tenant_id: "restart-tenant".into(),
            project_id: "restart-project".into(),
            mission_id: "restart-mission".into(),
            objective: MissionControlObjective {
                objective_digest: digest(),
                contract_digest: digest(),
                revision: 1,
            },
            gates: vec![MissionControlGate {
                gate_id: "gate-one".into(),
                status: MissionControlGateStatus::Ready,
                required_evidence_digest: None,
                revision: 1,
            }],
            todos: vec![MissionControlTodo {
                todo_id: "todo-one".into(),
                status: MissionControlTodoStatus::Pending,
                idempotency_digest: digest(),
                revision: 1,
            }],
            evidence: vec![MissionControlEvidence {
                evidence_digest: digest(),
                source_digest: digest(),
                revision: 1,
            }],
            quota: MissionControlQuota {
                token_limit: 100,
                token_spent: 0,
                cost_limit_minor: 10_000,
                cost_spent_minor: 0,
                deadline_at: at + chrono::Duration::hours(1),
            },
            claim: None,
            handoff: None,
            worker_graph_digest: digest(),
            accepted_writebacks: Vec::new(),
            mission_revision: 1,
        }
    }

    #[test]
    fn mission_control_claim_handoff_quota_and_writeback_are_generation_fenced() {
        let at = Utc
            .with_ymd_and_hms(2026, 8, 13, 9, 0, 0)
            .single()
            .expect("valid time");
        let snapshot = mission_control_snapshot(at);
        snapshot.validate(at).expect("valid control snapshot");
        assert_eq!(
            snapshot
                .decide_quota(10, 100, false, false, at)
                .expect("deliver decision"),
            MissionControlQuotaDecision::Deliver
        );
        assert_eq!(
            snapshot
                .decide_quota(101, 100, true, false, at)
                .expect("ask decision"),
            MissionControlQuotaDecision::Ask
        );
        assert_eq!(
            snapshot
                .decide_quota(101, 100, false, false, at)
                .expect("wait decision"),
            MissionControlQuotaDecision::Wait
        );
        assert_eq!(
            snapshot
                .decide_quota(101, 100, false, true, at)
                .expect("fallback decision"),
            MissionControlQuotaDecision::SafeFallback
        );
        assert_eq!(
            snapshot
                .decide_quota(0, 0, false, false, at)
                .expect("stop decision"),
            MissionControlQuotaDecision::Stop
        );
        let (claimed, disposition) = snapshot
            .claim("worker-a", 1, 1, at + chrono::Duration::minutes(5), at)
            .expect("claim");
        assert_eq!(disposition, MissionControlClaimDisposition::Acquired);
        assert_eq!(
            claimed.claim("worker-b", 1, 1, at + chrono::Duration::minutes(5), at),
            Err(MissionControlError::ClaimLost)
        );
        let (_, replay) = claimed
            .claim("worker-a", 1, 1, at + chrono::Duration::minutes(5), at)
            .expect("same owner replay");
        assert_eq!(replay, MissionControlClaimDisposition::Replay);

        let payload = "b".repeat(64);
        let (written, writeback) = claimed
            .accept_writeback("worker-a", 1, 1, "request-1", &payload, at)
            .expect("accepted writeback");
        assert_eq!(writeback, MissionControlWritebackDisposition::Accepted);
        let (_, replay) = written
            .accept_writeback("worker-a", 1, 1, "request-1", &payload, at)
            .expect("idempotent writeback replay");
        assert_eq!(replay, MissionControlWritebackDisposition::Replay);
        assert_eq!(
            written.accept_writeback("worker-a", 1, 1, "request-1", &"c".repeat(64), at),
            Err(MissionControlError::DuplicateWriteback)
        );

        let handed = written
            .handoff("worker-a", 1, 1, "worker-b", "operator takeover", at)
            .expect("handoff");
        assert_eq!(
            handed.handoff.as_ref().expect("handoff record").generation,
            2
        );
        assert_eq!(
            handed.accept_writeback("worker-a", 1, 1, "request-2", &payload, at),
            Err(MissionControlError::ClaimLost)
        );
        let (handed_writeback, _) = handed
            .accept_writeback("worker-b", 2, 2, "request-2", &payload, at)
            .expect("new owner writeback");
        assert_eq!(
            handed_writeback.reserve_quota(101, 0, at),
            Err(MissionControlError::QuotaExceeded)
        );
        let spent = handed_writeback
            .reserve_quota(10, 100, at)
            .expect("quota reservation");
        assert_eq!(spent.quota.token_spent, 10);
    }

    #[test]
    fn mission_control_expired_claim_requires_new_generation_and_rejects_invalid_records() {
        let at = Utc
            .with_ymd_and_hms(2026, 8, 13, 9, 0, 0)
            .single()
            .expect("valid time");
        let snapshot = mission_control_snapshot(at);
        let (claimed, _) = snapshot
            .claim("worker-a", 3, 2, at + chrono::Duration::minutes(1), at)
            .expect("claim");
        assert_eq!(
            claimed.claim("worker-b", 3, 2, at + chrono::Duration::minutes(5), at),
            Err(MissionControlError::ClaimLost)
        );
        let (_, _) = claimed
            .claim(
                "worker-b",
                4,
                3,
                at + chrono::Duration::minutes(5),
                at + chrono::Duration::minutes(2),
            )
            .expect("new generation after expiry");

        let mut invalid = mission_control_snapshot(at);
        invalid.gates.push(invalid.gates[0].clone());
        assert_eq!(
            invalid.validate(at),
            Err(MissionControlError::InvalidSnapshot)
        );
    }
}
