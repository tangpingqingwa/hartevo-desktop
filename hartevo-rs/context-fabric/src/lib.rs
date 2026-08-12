//! Deterministic Context assembly for Runtime projections.
//!
//! The assembler never treats a model window as authority. It validates the
//! current Checkpoint/Capsule closure, resolves only typed references, verifies
//! every content digest, records every omission, and emits a bounded transient
//! envelope. Only the content-free manifest is suitable for persistence.

mod model_tokenizer;

pub use model_tokenizer::{
    ConservativeByteBudgetTokenizer, PinnedModelTokenizer, PinnedTokenizerSpec,
};

use std::collections::BTreeSet;
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
        let (required_references, optional_references) = material_references(request);
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
) -> (Vec<ContextMaterialReference>, Vec<ContextMaterialReference>) {
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
        let requirement = if matches!(
            entry.kind,
            ContinuationEntryKind::Decision
                | ContinuationEntryKind::Blocker
                | ContinuationEntryKind::UserCorrection
                | ContinuationEntryKind::ApprovalPending
                | ContinuationEntryKind::EffectUncertain
                | ContinuationEntryKind::HumanHandoff
        ) {
            ContextFrameRequirement::Required
        } else {
            ContextFrameRequirement::Optional
        };
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
    (required, optional)
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
    const ASSEMBLY_AT_SECONDS: i64 = 10;

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

    #[allow(
        clippy::too_many_lines,
        reason = "the test fixture constructs one fully valid Mission-to-Checkpoint-to-Capsule authority closure"
    )]
    fn fixture(required_expired: bool, optional_expired: bool) -> AssemblyFixture {
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
                    kind: ContinuationEntryKind::NextAction,
                    subject_id: "next-action".into(),
                    payload_ref: "cas://next-action-context".into(),
                    payload_digest: sha(NEXT_ACTION_TEXT),
                    evidence_ids: BTreeSet::new(),
                },
                &workspace,
                &mission,
                at() + Duration::seconds(2),
            )
            .expect("next-action continuation");
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
        let materials = BTreeMap::from([
            ("cas://summary-context".into(), SUMMARY_TEXT.into()),
            ("cas://decision-context".into(), DECISION_TEXT.into()),
            (
                "cas://pending-effect-context".into(),
                REQUIRED_ITEM_TEXT.into(),
            ),
            ("cas://next-action-context".into(), NEXT_ACTION_TEXT.into()),
            ("cas://conversation-tail-context".into(), optional_text),
        ]);
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
    fn expiry_distinguishes_required_block_from_optional_gap() {
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
        without_optional
            .materials
            .remove("cas://next-action-context");
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
        assert!(blocked.manifest.gaps.iter().any(|gap| {
            gap.requirement == ContextFrameRequirement::Required
                && gap.reason == ContextGapReason::BudgetOmitted
        }));
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
}
