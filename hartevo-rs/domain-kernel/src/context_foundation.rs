//! Typed, replayable context state layered over the authoritative Mission.
//!
//! Summaries and model-authored continuation notes are never authority. Every
//! compaction and resume checkpoint closes over a deterministic invariant block
//! rebuilt from the current Mission and Project Truth revisions.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    ContextCheckpointId, ContextCompactionRecordId, ContextContinuationLedgerId, ContextDataClass,
    ContextError, ContextWorkingSetId, ContextWorkspace, EffectId, EffectStatus, EvidenceId,
    EvidenceStatus, FactId, Mission, MissionId, MissionStage, ProjectId, TaskId, TaskStatus,
    TenantId, TruthFact, TruthStatus, WorkProductId, WorkProductStatus,
};

const MAX_WORKING_ITEMS: usize = 512;
const MAX_WORKING_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REFERENCE_BYTES: usize = 2_048;
const MAX_SUBJECT_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextWorkingItemKind {
    ConversationTail,
    ToolResult,
    TruthReference,
    EvidenceReference,
    WorkProductReference,
    EffectReference,
    ArtifactReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextItemAvailability {
    Available,
    Expired,
}

/// A bounded reference to encrypted CAS or an authoritative typed projection.
/// Content is deliberately absent so traces and outbox payloads cannot acquire
/// secrets, cookies, tokens, or direct PII through this type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextWorkingItem {
    pub key: String,
    pub kind: ContextWorkingItemKind,
    pub storage_ref: String,
    pub content_digest: String,
    pub byte_len: u64,
    pub classification: ContextDataClass,
    pub provenance_digest: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ContextWorkingItem {
    pub fn availability_at(&self, now: DateTime<Utc>) -> ContextItemAvailability {
        if self.expires_at.is_some_and(|expires_at| now >= expires_at) {
            ContextItemAvailability::Expired
        } else {
            ContextItemAvailability::Available
        }
    }

    fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.key.trim().is_empty()
            || self.key.len() > MAX_SUBJECT_BYTES
            || !is_safe_storage_ref(&self.storage_ref)
            || !is_sha256(&self.content_digest)
            || self.byte_len == 0
            || self.byte_len > MAX_WORKING_BYTES
            || self.classification > workspace.data_policy.maximum_class()
            || !is_sha256(&self.provenance_digest)
            || self.created_at < workspace.created_at
            || self.created_at > now
            || self
                .expires_at
                .is_some_and(|expires_at| expires_at <= self.created_at)
        {
            return Err(ContextError::InvalidWorkingItem);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextWorkingSet {
    pub id: ContextWorkingSetId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: crate::ContextWorkspaceId,
    pub generation: u64,
    pub items: BTreeMap<String, ContextWorkingItem>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ContextWorkingSet {
    pub fn create(
        id: ContextWorkingSetId,
        workspace: &ContextWorkspace,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let value = Self {
            id,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            workspace_id: workspace.id.clone(),
            generation: workspace.generation,
            items: BTreeMap::new(),
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        value.validate_for(workspace, now)?;
        Ok(value)
    }

    pub fn replace_items(
        &mut self,
        items: BTreeMap<String, ContextWorkingItem>,
        workspace: &ContextWorkspace,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if now < self.updated_at
            || items
                .values()
                .any(|item| item.availability_at(now) != ContextItemAvailability::Available)
        {
            return Err(ContextError::InvalidWorkingSet);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        let previous = self.clone();
        self.items = items;
        self.revision = next_revision;
        self.updated_at = now;
        if self.validate_for(workspace, now).is_err() || !self.follows(&previous)? {
            *self = previous;
            return Err(ContextError::InvalidWorkingSet);
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        let total_bytes = self.items.values().try_fold(0_u64, |total, item| {
            total
                .checked_add(item.byte_len)
                .ok_or(ContextError::InvalidWorkingSet)
        })?;
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.workspace_id != workspace.id
            || self.generation != workspace.generation
            || self.items.len() > MAX_WORKING_ITEMS
            || total_bytes > MAX_WORKING_BYTES
            || self.revision == 0
            || self.created_at < workspace.created_at
            || self.created_at > now
            || self.updated_at < self.created_at
            || self.updated_at > now
        {
            return Err(ContextError::InvalidWorkingSet);
        }
        for (key, item) in &self.items {
            if key != &item.key {
                return Err(ContextError::InvalidWorkingSet);
            }
            item.validate_for(workspace, now)?;
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, ContextError> {
        Ok(self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.workspace_id == previous.workspace_id
            && self.generation == previous.generation
            && self.created_at == previous.created_at
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.updated_at >= previous.updated_at)
    }

    pub fn digest(&self) -> Result<String, ContextError> {
        digest_json(self)
    }

    pub fn availability_at(&self, now: DateTime<Utc>) -> BTreeMap<String, ContextItemAvailability> {
        self.items
            .iter()
            .map(|(key, item)| (key.clone(), item.availability_at(now)))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationEntryKind {
    Decision,
    Blocker,
    NextAction,
    UserCorrection,
    CheckpointTransition,
    ApprovalPending,
    EffectUncertain,
    HumanHandoff,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationEntryInput {
    pub kind: ContinuationEntryKind,
    pub subject_id: String,
    pub payload_ref: String,
    pub payload_digest: String,
    pub evidence_ids: BTreeSet<EvidenceId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuationEntry {
    pub sequence: u64,
    pub mission_revision: u64,
    pub kind: ContinuationEntryKind,
    pub subject_id: String,
    pub payload_ref: String,
    pub payload_digest: String,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub recorded_at: DateTime<Utc>,
}

impl ContinuationEntry {
    fn validate_for(&self, mission: &Mission, now: DateTime<Utc>) -> Result<(), ContextError> {
        let known_evidence = mission
            .evidence
            .iter()
            .map(|value| &value.id)
            .collect::<BTreeSet<_>>();
        if self.sequence == 0
            || self.mission_revision == 0
            || self.mission_revision > mission.revision
            || self.subject_id.trim().is_empty()
            || self.subject_id.len() > MAX_SUBJECT_BYTES
            || !is_safe_storage_ref(&self.payload_ref)
            || !is_sha256(&self.payload_digest)
            || !self
                .evidence_ids
                .iter()
                .all(|evidence_id| known_evidence.contains(evidence_id))
            || self.recorded_at < mission.created_at
            || self.recorded_at > now
        {
            return Err(ContextError::InvalidContinuationEntry);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContinuationLedger {
    pub id: ContextContinuationLedgerId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: crate::ContextWorkspaceId,
    pub generation: u64,
    pub entries: Vec<ContinuationEntry>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ContinuationLedger {
    pub fn create(
        id: ContextContinuationLedgerId,
        workspace: &ContextWorkspace,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let value = Self {
            id,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            workspace_id: workspace.id.clone(),
            generation: workspace.generation,
            entries: Vec::new(),
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        value.validate_for(workspace, None, now)?;
        Ok(value)
    }

    pub fn append(
        &mut self,
        input: ContinuationEntryInput,
        workspace: &ContextWorkspace,
        mission: &Mission,
        now: DateTime<Utc>,
    ) -> Result<ContinuationEntry, ContextError> {
        if now < self.updated_at {
            return Err(ContextError::InvalidContinuationLedger);
        }
        let sequence = u64::try_from(self.entries.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(ContextError::RevisionOverflow)?;
        let entry = ContinuationEntry {
            sequence,
            mission_revision: mission.revision,
            kind: input.kind,
            subject_id: input.subject_id.trim().to_owned(),
            payload_ref: input.payload_ref,
            payload_digest: input.payload_digest,
            evidence_ids: input.evidence_ids,
            recorded_at: now,
        };
        entry.validate_for(mission, now)?;
        let previous = self.clone();
        self.entries.push(entry.clone());
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(ContextError::RevisionOverflow)?;
        self.updated_at = now;
        if self.validate_for(workspace, Some(mission), now).is_err() || !self.follows(&previous)? {
            *self = previous;
            return Err(ContextError::InvalidContinuationLedger);
        }
        Ok(entry)
    }

    pub fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        mission: Option<&Mission>,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.workspace_id != workspace.id
            || self.generation != workspace.generation
            || self.revision == 0
            || self.revision != u64::try_from(self.entries.len()).unwrap_or(u64::MAX) + 1
            || self.created_at < workspace.created_at
            || self.created_at > now
            || self.updated_at < self.created_at
            || self.updated_at > now
        {
            return Err(ContextError::InvalidContinuationLedger);
        }
        if let Some(mission) = mission {
            if mission.id != self.mission_id
                || mission.project_id != self.project_id
                || mission.tenant_id != self.tenant_id
            {
                return Err(ContextError::InvalidContinuationLedger);
            }
            let mut prior_mission_revision = 0;
            for (index, entry) in self.entries.iter().enumerate() {
                if entry.sequence != u64::try_from(index).unwrap_or(u64::MAX) + 1
                    || entry.mission_revision < prior_mission_revision
                {
                    return Err(ContextError::InvalidContinuationLedger);
                }
                entry.validate_for(mission, now)?;
                prior_mission_revision = entry.mission_revision;
            }
        } else if !self.entries.is_empty() {
            return Err(ContextError::InvalidContinuationLedger);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, ContextError> {
        Ok(self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.workspace_id == previous.workspace_id
            && self.generation == previous.generation
            && self.created_at == previous.created_at
            && previous.revision.checked_add(1) == Some(self.revision)
            && self.entries.len() == previous.entries.len() + 1
            && self.entries.starts_with(&previous.entries)
            && self.updated_at >= previous.updated_at)
    }

    pub fn digest(&self) -> Result<String, ContextError> {
        digest_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextTaskInvariant {
    pub id: TaskId,
    pub status: TaskStatus,
    pub capability: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextTruthInvariant {
    pub id: FactId,
    pub version: u64,
    pub status: TruthStatus,
    pub market: String,
    pub language: String,
    pub fact_digest: String,
    pub correction_chain_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextEvidenceInvariant {
    pub id: EvidenceId,
    pub status: EvidenceStatus,
    pub content_digest: String,
    pub source_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextWorkProductInvariant {
    pub id: WorkProductId,
    pub revision: u64,
    pub status: WorkProductStatus,
    pub content_digest: String,
    pub evidence_ids: BTreeSet<EvidenceId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextEffectInvariant {
    pub id: EffectId,
    pub status: EffectStatus,
    pub exact_scope_digest: String,
    pub approval_scope_digest: Option<String>,
    pub permission_digest: Option<String>,
    pub receipt_digest: Option<String>,
    pub verification_digest: Option<String>,
    pub provider_state_uncertain: bool,
}

/// Deterministic state that no compactor, model, provider, or runtime may omit
/// or rewrite. It contains digests and typed state, never content bodies.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextInvariantBlock {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub contract_version: u64,
    pub mission_stage: MissionStage,
    pub goal_digest: String,
    pub non_goals_digest: String,
    pub constraints_digest: String,
    pub stop_conditions_digest: String,
    pub completion_conditions_digest: String,
    pub authority_digest: String,
    pub mission_block_digest: Option<String>,
    pub tasks: Vec<ContextTaskInvariant>,
    pub truth_facts: Vec<ContextTruthInvariant>,
    pub evidence: Vec<ContextEvidenceInvariant>,
    pub work_products: Vec<ContextWorkProductInvariant>,
    pub effects: Vec<ContextEffectInvariant>,
    pub open_task_ids: BTreeSet<TaskId>,
    pub pending_effect_ids: BTreeSet<EffectId>,
    pub uncertain_effect_ids: BTreeSet<EffectId>,
    pub outcome_history_digest: String,
}

impl ContextInvariantBlock {
    #[allow(
        clippy::too_many_lines,
        reason = "one deterministic capture point must close over every Mission and Project Truth invariant"
    )]
    pub fn capture(
        mission: &Mission,
        truth_facts: &[TruthFact],
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let mut facts = truth_facts.to_vec();
        facts.sort_by(|left, right| left.id.cmp(&right.id));
        let mut seen_facts = BTreeSet::new();
        let mut truth_invariants = Vec::with_capacity(facts.len());
        for fact in &facts {
            fact.validate(now)
                .map_err(|_| ContextError::ContextInvariantMismatch)?;
            if fact.tenant_id != mission.tenant_id
                || fact.project_id != mission.project_id
                || !seen_facts.insert(fact.id.clone())
            {
                return Err(ContextError::ContextInvariantMismatch);
            }
            truth_invariants.push(ContextTruthInvariant {
                id: fact.id.clone(),
                version: fact.version,
                status: fact.status.clone(),
                market: fact.market.clone(),
                language: fact.language.clone(),
                fact_digest: fact
                    .digest()
                    .map_err(|_| ContextError::ContextInvariantMismatch)?,
                correction_chain_digest: fact
                    .revision_link
                    .as_ref()
                    .map(digest_json)
                    .transpose()?,
            });
        }

        let mut tasks = mission
            .tasks
            .iter()
            .map(|task| ContextTaskInvariant {
                id: task.id.clone(),
                status: task.status.clone(),
                capability: task.capability.clone(),
            })
            .collect::<Vec<_>>();
        tasks.sort_by(|left, right| left.id.cmp(&right.id));
        let open_task_ids = tasks
            .iter()
            .filter(|task| !matches!(task.status, TaskStatus::Completed | TaskStatus::Cancelled))
            .map(|task| task.id.clone())
            .collect();

        let mut evidence = mission
            .evidence
            .iter()
            .map(|value| {
                Ok(ContextEvidenceInvariant {
                    id: value.id.clone(),
                    status: value.status.clone(),
                    content_digest: value.content_digest.clone(),
                    source_digest: digest_json(&(
                        &value.source_uri,
                        value.observed_at,
                        value.confidence.to_bits(),
                    ))?,
                })
            })
            .collect::<Result<Vec<_>, ContextError>>()?;
        evidence.sort_by(|left, right| left.id.cmp(&right.id));

        let mut work_products = mission
            .work_products
            .iter()
            .map(|value| ContextWorkProductInvariant {
                id: value.id.clone(),
                revision: value.revision,
                status: value.status.clone(),
                content_digest: value.content_digest.clone(),
                evidence_ids: value.evidence_ids.clone(),
            })
            .collect::<Vec<_>>();
        work_products.sort_by(|left, right| left.id.cmp(&right.id));

        let mut effects = mission
            .effects
            .iter()
            .map(|value| {
                let provider_state_uncertain =
                    value.status == EffectStatus::VerificationRequired && value.receipt.is_none();
                Ok(ContextEffectInvariant {
                    id: value.id.clone(),
                    status: value.status.clone(),
                    exact_scope_digest: value.approval_digest(),
                    approval_scope_digest: value
                        .approval
                        .as_ref()
                        .map(|approval| approval.scope_digest.clone()),
                    permission_digest: value
                        .approval
                        .as_ref()
                        .map(|approval| approval.permission_digest.clone()),
                    receipt_digest: value.receipt.as_ref().map(digest_json).transpose()?,
                    verification_digest: value
                        .verification
                        .as_ref()
                        .map(digest_json)
                        .transpose()?,
                    provider_state_uncertain,
                })
            })
            .collect::<Result<Vec<_>, ContextError>>()?;
        effects.sort_by(|left, right| left.id.cmp(&right.id));
        let pending_effect_ids = effects
            .iter()
            .filter(|effect| {
                matches!(
                    effect.status,
                    EffectStatus::Proposed
                        | EffectStatus::Approved
                        | EffectStatus::Executing
                        | EffectStatus::ReceiptRecorded
                        | EffectStatus::VerificationRequired
                )
            })
            .map(|effect| effect.id.clone())
            .collect();
        let uncertain_effect_ids = effects
            .iter()
            .filter(|effect| effect.provider_state_uncertain)
            .map(|effect| effect.id.clone())
            .collect();

        Ok(Self {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            mission_revision: mission.revision,
            contract_version: mission.contract.version,
            mission_stage: mission.stage.clone(),
            goal_digest: digest_json(&mission.contract.goal)?,
            non_goals_digest: digest_json(&mission.contract.non_goals)?,
            constraints_digest: digest_json(&mission.contract.constraints)?,
            stop_conditions_digest: digest_json(&mission.contract.stop_conditions)?,
            completion_conditions_digest: digest_json(&mission.contract.completion_conditions)?,
            authority_digest: digest_json(&(
                &mission.contract.enabled_capabilities,
                &mission.contract.forbidden_capabilities,
                &mission.contract.autonomy_by_capability,
                &mission.contract.approval_policy,
                &mission.contract.budget,
                mission.contract.valid_until,
            ))?,
            mission_block_digest: mission.block.as_ref().map(digest_json).transpose()?,
            tasks,
            truth_facts: truth_invariants,
            evidence,
            work_products,
            effects,
            open_task_ids,
            pending_effect_ids,
            uncertain_effect_ids,
            outcome_history_digest: digest_json(&(&mission.outcome_history, &mission.outcome))?,
        })
    }

    pub fn assert_exact(
        &self,
        mission: &Mission,
        truth_facts: &[TruthFact],
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if *self != Self::capture(mission, truth_facts, now)? {
            return Err(ContextError::ContextInvariantMismatch);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ContextError> {
        digest_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextCompactionRecord {
    pub id: ContextCompactionRecordId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: crate::ContextWorkspaceId,
    pub generation: u64,
    pub ordinal: u64,
    pub source_first_sequence: u64,
    pub source_last_sequence: u64,
    pub source_trace_digest: String,
    pub source_token_count: u64,
    pub retained_tail_start: u64,
    pub summary_ref: String,
    pub summary_digest: String,
    pub summary_byte_len: u64,
    pub summary_token_count: u64,
    pub invariant: ContextInvariantBlock,
    pub invariant_digest: String,
    pub provenance_evidence_ids: BTreeSet<EvidenceId>,
    pub provenance_coverage_digest: String,
    pub model_digest: String,
    pub provider_route_digest: String,
    pub config_digest: String,
    pub created_at: DateTime<Utc>,
}

impl ContextCompactionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: ContextCompactionRecordId,
        workspace: &ContextWorkspace,
        mission: &Mission,
        truth_facts: &[TruthFact],
        previous: Option<&Self>,
        source_first_sequence: u64,
        source_last_sequence: u64,
        source_trace_digest: String,
        source_token_count: u64,
        retained_tail_start: u64,
        summary_ref: String,
        summary_digest: String,
        summary_byte_len: u64,
        summary_token_count: u64,
        provenance_evidence_ids: BTreeSet<EvidenceId>,
        model_digest: String,
        provider_route_digest: String,
        config_digest: String,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let ordinal = previous.map_or(1, |value| value.ordinal.saturating_add(1));
        let invariant = ContextInvariantBlock::capture(mission, truth_facts, now)?;
        let value = Self {
            id,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            workspace_id: workspace.id.clone(),
            generation: workspace.generation,
            ordinal,
            source_first_sequence,
            source_last_sequence,
            source_trace_digest,
            source_token_count,
            retained_tail_start,
            summary_ref,
            summary_digest,
            summary_byte_len,
            summary_token_count,
            invariant_digest: invariant.digest()?,
            invariant,
            provenance_coverage_digest: digest_json(&provenance_evidence_ids)?,
            provenance_evidence_ids,
            model_digest,
            provider_route_digest,
            config_digest,
            created_at: now,
        };
        value.validate_for(workspace, mission, truth_facts, previous, now)?;
        Ok(value)
    }

    pub fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        mission: &Mission,
        truth_facts: &[TruthFact],
        previous: Option<&Self>,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        let expected_ordinal = previous.map_or(1, |value| value.ordinal.saturating_add(1));
        let known_evidence = mission
            .evidence
            .iter()
            .map(|value| &value.id)
            .collect::<BTreeSet<_>>();
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.workspace_id != workspace.id
            || self.generation != workspace.generation
            || self.ordinal != expected_ordinal
            || self.source_first_sequence == 0
            || self.source_last_sequence < self.source_first_sequence
            || previous.is_some_and(|value| {
                value.workspace_id != self.workspace_id
                    || value.generation != self.generation
                    || value.source_last_sequence >= self.source_first_sequence
                    || value.created_at > self.created_at
            })
            || !is_sha256(&self.source_trace_digest)
            || self.source_token_count == 0
            || self.retained_tail_start < self.source_first_sequence
            || self.retained_tail_start > self.source_last_sequence.saturating_add(1)
            || !is_safe_storage_ref(&self.summary_ref)
            || !is_sha256(&self.summary_digest)
            || self.summary_byte_len == 0
            || self.summary_byte_len > MAX_WORKING_BYTES
            || self.summary_token_count == 0
            || self.summary_token_count >= self.source_token_count
            || self.invariant_digest != self.invariant.digest()?
            || !self
                .provenance_evidence_ids
                .iter()
                .all(|id| known_evidence.contains(id))
            || self.provenance_coverage_digest != digest_json(&self.provenance_evidence_ids)?
            || !is_sha256(&self.model_digest)
            || !is_sha256(&self.provider_route_digest)
            || !is_sha256(&self.config_digest)
            || self.created_at < workspace.created_at
            || self.created_at > now
        {
            return Err(ContextError::InvalidCompactionRecord);
        }
        self.invariant
            .assert_exact(mission, truth_facts, now)
            .map_err(|_| ContextError::InvalidCompactionRecord)
    }

    pub fn digest(&self) -> Result<String, ContextError> {
        digest_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextCheckpoint {
    pub id: ContextCheckpointId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: crate::ContextWorkspaceId,
    pub generation: u64,
    pub ordinal: u64,
    pub previous_checkpoint_id: Option<ContextCheckpointId>,
    pub mission_revision: u64,
    pub working_set_id: ContextWorkingSetId,
    pub working_set_revision: u64,
    pub working_set_digest: String,
    pub continuation_ledger_id: ContextContinuationLedgerId,
    pub continuation_ledger_revision: u64,
    pub continuation_ledger_digest: String,
    pub compaction_record_id: ContextCompactionRecordId,
    pub compaction_ordinal: u64,
    pub compaction_digest: String,
    pub invariant: ContextInvariantBlock,
    pub invariant_digest: String,
    pub worker_graph_digest: String,
    pub resume_cursor_digest: String,
    pub trace_tail_sequence: u64,
    pub created_at: DateTime<Utc>,
}

impl ContextCheckpoint {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        id: ContextCheckpointId,
        workspace: &ContextWorkspace,
        mission: &Mission,
        truth_facts: &[TruthFact],
        working_set: &ContextWorkingSet,
        continuation_ledger: &ContinuationLedger,
        compaction: &ContextCompactionRecord,
        previous: Option<&Self>,
        worker_graph_digest: String,
        resume_cursor_digest: String,
        trace_tail_sequence: u64,
        now: DateTime<Utc>,
    ) -> Result<Self, ContextError> {
        let ordinal = previous.map_or(1, |value| value.ordinal.saturating_add(1));
        let invariant = ContextInvariantBlock::capture(mission, truth_facts, now)?;
        let value = Self {
            id,
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            workspace_id: workspace.id.clone(),
            generation: workspace.generation,
            ordinal,
            previous_checkpoint_id: previous.map(|value| value.id.clone()),
            mission_revision: mission.revision,
            working_set_id: working_set.id.clone(),
            working_set_revision: working_set.revision,
            working_set_digest: working_set.digest()?,
            continuation_ledger_id: continuation_ledger.id.clone(),
            continuation_ledger_revision: continuation_ledger.revision,
            continuation_ledger_digest: continuation_ledger.digest()?,
            compaction_record_id: compaction.id.clone(),
            compaction_ordinal: compaction.ordinal,
            compaction_digest: compaction.digest()?,
            invariant_digest: invariant.digest()?,
            invariant,
            worker_graph_digest,
            resume_cursor_digest,
            trace_tail_sequence,
            created_at: now,
        };
        value.validate_for(
            workspace,
            mission,
            truth_facts,
            working_set,
            continuation_ledger,
            compaction,
            previous,
            now,
        )?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_for(
        &self,
        workspace: &ContextWorkspace,
        mission: &Mission,
        truth_facts: &[TruthFact],
        working_set: &ContextWorkingSet,
        continuation_ledger: &ContinuationLedger,
        compaction: &ContextCompactionRecord,
        previous: Option<&Self>,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        working_set.validate_for(workspace, now)?;
        continuation_ledger.validate_for(workspace, Some(mission), now)?;
        let expected_ordinal = previous.map_or(1, |value| value.ordinal.saturating_add(1));
        if self.id.as_str().trim().is_empty()
            || self.tenant_id != workspace.tenant_id
            || self.project_id != workspace.project_id
            || self.mission_id != workspace.mission_id
            || self.workspace_id != workspace.id
            || self.generation != workspace.generation
            || self.ordinal != expected_ordinal
            || self.previous_checkpoint_id != previous.map(|value| value.id.clone())
            || previous.is_some_and(|value| {
                value.workspace_id != self.workspace_id
                    || value.generation != self.generation
                    || value.created_at > self.created_at
            })
            || self.mission_revision != mission.revision
            || self.working_set_id != working_set.id
            || self.working_set_revision != working_set.revision
            || self.working_set_digest != working_set.digest()?
            || self.continuation_ledger_id != continuation_ledger.id
            || self.continuation_ledger_revision != continuation_ledger.revision
            || self.continuation_ledger_digest != continuation_ledger.digest()?
            || self.compaction_record_id != compaction.id
            || self.compaction_ordinal != compaction.ordinal
            || self.compaction_digest != compaction.digest()?
            || self.invariant != compaction.invariant
            || self.invariant_digest != self.invariant.digest()?
            || !is_sha256(&self.worker_graph_digest)
            || !is_sha256(&self.resume_cursor_digest)
            || self.trace_tail_sequence < compaction.retained_tail_start
            || self.created_at < compaction.created_at
            || self.created_at > now
        {
            return Err(ContextError::InvalidContextCheckpoint);
        }
        self.invariant
            .assert_exact(mission, truth_facts, now)
            .map_err(|_| ContextError::InvalidContextCheckpoint)
    }

    pub fn digest(&self) -> Result<String, ContextError> {
        digest_json(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextFoundationSnapshot {
    pub sync_version: u64,
    pub workspace: ContextWorkspace,
    pub working_set: ContextWorkingSet,
    pub continuation_ledger: ContinuationLedger,
    pub compaction: ContextCompactionRecord,
    pub checkpoint: ContextCheckpoint,
    pub truth_facts: Vec<TruthFact>,
}

impl ContextFoundationSnapshot {
    pub fn validate_for(
        &self,
        mission: &Mission,
        previous_compaction: Option<&ContextCompactionRecord>,
        previous_checkpoint: Option<&ContextCheckpoint>,
        now: DateTime<Utc>,
    ) -> Result<(), ContextError> {
        if self.sync_version == 0 {
            return Err(ContextError::InvalidContextCheckpoint);
        }
        self.workspace.validate_for(mission, now)?;
        self.compaction.validate_for(
            &self.workspace,
            mission,
            &self.truth_facts,
            previous_compaction,
            now,
        )?;
        self.checkpoint.validate_for(
            &self.workspace,
            mission,
            &self.truth_facts,
            &self.working_set,
            &self.continuation_ledger,
            &self.compaction,
            previous_checkpoint,
            now,
        )
    }
}

fn digest_json(value: &impl Serialize) -> Result<String, ContextError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ContextError::Serialization)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_safe_storage_ref(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_REFERENCE_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains("..")
        || value.contains(['\\', '?', '#', '@'])
    {
        return false;
    }
    let Some((scheme, target)) = value.split_once("://") else {
        return false;
    };
    matches!(
        scheme,
        "cas" | "artifact" | "truth" | "mission" | "trace" | "file-broker"
    ) && !target.is_empty()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::{Duration, TimeZone};

    use super::*;
    use crate::{
        ApprovalPolicy, AutonomyLevel, Constraint, CurrencyCode, EffectClass, MissionContract,
        Money, OperatingMode,
    };

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 12, 0, 0)
            .single()
            .expect("valid time")
    }

    fn mission() -> Mission {
        let contract = MissionContract {
            version: 1,
            mode: OperatingMode::BuildOnce,
            parent_mission_id: None,
            goal: "Make a bounded decision".into(),
            non_goals: vec!["Do not publish".into()],
            market: "DE".into(),
            language: "de".into(),
            audience: "owner".into(),
            kpis: BTreeMap::new(),
            budget: Money::new(10_000, CurrencyCode::parse("EUR").expect("EUR")),
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
            completion_conditions: vec!["decision_recorded".into()],
            valid_from: now(),
            valid_until: now() + Duration::days(1),
            constraints: vec![Constraint::Market { value: "DE".into() }],
            enabled_capabilities: BTreeSet::from(["market.analyze".into()]),
            forbidden_capabilities: BTreeSet::new(),
        };
        Mission::compile(
            TenantId::from("tenant-context-foundation"),
            MissionId::from("mission-context-foundation"),
            ProjectId::from("project-context-foundation"),
            "Context foundation",
            contract,
            now(),
        )
        .expect("mission")
    }

    fn workspace(mission: &Mission) -> ContextWorkspace {
        ContextWorkspace::create(
            crate::ContextWorkspaceId::from("workspace-foundation"),
            mission,
            1,
            "policy-v1",
            BTreeSet::from(["market.analyze".into()]),
            crate::ContextBudget {
                token_limit: 20_000,
                cost_limit: mission.contract.budget.clone(),
                deadline_at: now() + Duration::hours(12),
                max_depth: 4,
                max_concurrency: 2,
            },
            crate::ContextDataPolicy::BusinessOnly,
            now(),
        )
        .expect("workspace")
    }

    fn working_item(expires_at: Option<DateTime<Utc>>) -> ContextWorkingItem {
        ContextWorkingItem {
            key: "research-tail".into(),
            kind: ContextWorkingItemKind::ConversationTail,
            storage_ref: format!("cas://{}", "1".repeat(64)),
            content_digest: "2".repeat(64),
            byte_len: 512,
            classification: ContextDataClass::Business,
            provenance_digest: "3".repeat(64),
            expires_at,
            created_at: now(),
        }
    }

    #[test]
    fn working_set_expiry_is_explicit_and_never_silently_available() {
        let mission = mission();
        let workspace = workspace(&mission);
        let mut set =
            ContextWorkingSet::create(ContextWorkingSetId::from("working-set"), &workspace, now())
                .expect("set");
        set.replace_items(
            BTreeMap::from([(
                "research-tail".into(),
                working_item(Some(now() + Duration::minutes(5))),
            )]),
            &workspace,
            now() + Duration::seconds(1),
        )
        .expect("replace");
        assert_eq!(
            set.availability_at(now() + Duration::minutes(5))
                .get("research-tail"),
            Some(&ContextItemAvailability::Expired)
        );
        assert!(
            set.replace_items(
                BTreeMap::from([(
                    "research-tail".into(),
                    working_item(Some(now() + Duration::minutes(5))),
                )]),
                &workspace,
                now() + Duration::minutes(6),
            )
            .is_err()
        );
    }

    #[test]
    fn continuation_ledger_is_append_only_and_binds_mission_revision() {
        let mission = mission();
        let workspace = workspace(&mission);
        let mut ledger = ContinuationLedger::create(
            ContextContinuationLedgerId::from("continuation"),
            &workspace,
            now(),
        )
        .expect("ledger");
        ledger
            .append(
                ContinuationEntryInput {
                    kind: ContinuationEntryKind::NextAction,
                    subject_id: "mission-context-foundation".into(),
                    payload_ref: format!("cas://{}", "4".repeat(64)),
                    payload_digest: "5".repeat(64),
                    evidence_ids: BTreeSet::new(),
                },
                &workspace,
                &mission,
                now() + Duration::seconds(1),
            )
            .expect("append");
        let previous = ledger.clone();
        let mut rewritten = ledger.clone();
        rewritten.entries[0].payload_digest = "6".repeat(64);
        rewritten.revision += 1;
        rewritten.updated_at += Duration::seconds(1);
        assert!(!rewritten.follows(&previous).expect("comparison"));
    }

    #[test]
    fn compaction_and_checkpoint_reject_invariant_loss_or_stale_dependencies() {
        let mission = mission();
        let workspace = workspace(&mission);
        let working_set =
            ContextWorkingSet::create(ContextWorkingSetId::from("working-set"), &workspace, now())
                .expect("working set");
        let continuation = ContinuationLedger::create(
            ContextContinuationLedgerId::from("continuation"),
            &workspace,
            now(),
        )
        .expect("continuation");
        let compaction = ContextCompactionRecord::create(
            ContextCompactionRecordId::from("compaction-1"),
            &workspace,
            &mission,
            &[],
            None,
            1,
            100,
            "a".repeat(64),
            4_000,
            90,
            format!("cas://{}", "b".repeat(64)),
            "c".repeat(64),
            1_024,
            500,
            BTreeSet::new(),
            "d".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
            now() + Duration::seconds(1),
        )
        .expect("compaction");
        let checkpoint = ContextCheckpoint::create(
            ContextCheckpointId::from("checkpoint-1"),
            &workspace,
            &mission,
            &[],
            &working_set,
            &continuation,
            &compaction,
            None,
            "1".repeat(64),
            "2".repeat(64),
            100,
            now() + Duration::seconds(2),
        )
        .expect("checkpoint");

        let mut tampered = checkpoint.clone();
        tampered.invariant.stop_conditions_digest = "0".repeat(64);
        tampered.invariant_digest = tampered.invariant.digest().expect("digest");
        assert!(matches!(
            tampered.validate_for(
                &workspace,
                &mission,
                &[],
                &working_set,
                &continuation,
                &compaction,
                None,
                now() + Duration::seconds(2),
            ),
            Err(ContextError::InvalidContextCheckpoint)
        ));

        let mut stale_set = working_set.clone();
        stale_set.revision += 1;
        stale_set.updated_at += Duration::seconds(1);
        assert!(
            checkpoint
                .validate_for(
                    &workspace,
                    &mission,
                    &[],
                    &stale_set,
                    &continuation,
                    &compaction,
                    None,
                    now() + Duration::seconds(2),
                )
                .is_err()
        );
    }
}
