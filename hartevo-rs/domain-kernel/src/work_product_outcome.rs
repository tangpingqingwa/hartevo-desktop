use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    MissionId, ProjectId, TenantId, WorkProductId, WorkProductManifestError, WorkProductPreview,
};

pub const WORK_PRODUCT_HANDOFF_PREVIEW_MEDIA_TYPE: &str =
    "application/vnd.hartevo.work-product-handoff+json";
pub const WORK_PRODUCT_HANDOFF_TYPE: &str = "result_work_product";
pub const WORK_PRODUCT_HANDOFF_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultClassification {
    Candidate,
    Partial,
    ReadyForReview,
    Conflicted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultCounterevidence {
    pub evidence_ref: String,
    pub content_digest: String,
    pub observed_at: DateTime<Utc>,
}

impl ResultCounterevidence {
    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        if !valid_reference(&self.evidence_ref) || !is_sha256(&self.content_digest) {
            return Err(WorkProductOutcomeError::InvalidCounterevidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultPacket {
    pub packet_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub source_ref: String,
    pub runtime_ref: String,
    pub provider_ref: Option<String>,
    pub title: String,
    pub content: String,
    pub content_digest: String,
    pub classification: ResultClassification,
    pub counterevidence: Vec<ResultCounterevidence>,
    pub created_at: DateTime<Utc>,
    pub observed_at: DateTime<Utc>,
    pub packet_digest: String,
}

impl ResultPacket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        packet_id: impl Into<String>,
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
        source_ref: impl Into<String>,
        runtime_ref: impl Into<String>,
        provider_ref: Option<String>,
        title: impl Into<String>,
        content: impl Into<String>,
        classification: ResultClassification,
        counterevidence: Vec<ResultCounterevidence>,
        created_at: DateTime<Utc>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        let content = content.into();
        let mut packet = Self {
            packet_id: packet_id.into(),
            tenant_id,
            project_id,
            mission_id,
            mission_revision,
            source_ref: source_ref.into(),
            runtime_ref: runtime_ref.into(),
            provider_ref,
            title: title.into(),
            content_digest: sha256(content.as_bytes()),
            content,
            classification,
            counterevidence,
            created_at,
            observed_at,
            packet_digest: String::new(),
        };
        packet.packet_digest = packet.calculate_digest()?;
        packet.validate()?;
        Ok(packet)
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        if !valid_id(self.tenant_id.as_str())
            || !valid_id(self.project_id.as_str())
            || !valid_id(self.mission_id.as_str())
            || !valid_reference(&self.packet_id)
            || self.mission_revision == 0
            || !valid_reference(&self.source_ref)
            || !valid_reference(&self.runtime_ref)
            || self
                .provider_ref
                .as_deref()
                .is_some_and(|value| !valid_reference(value))
            || self.title.trim().is_empty()
            || self.content.trim().is_empty()
            || self.content_digest != sha256(self.content.as_bytes())
            || !is_sha256(&self.packet_digest)
            || self.counterevidence.len() > 32
            || self
                .counterevidence
                .iter()
                .any(|item| item.validate().is_err())
            || self.observed_at < self.created_at
            || self.packet_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidResultPacket);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.packet_digest.clear();
        digest_json(&material)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductRevision {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub revision: u64,
    pub mission_revision: u64,
    pub packet_id: String,
    pub packet_digest: String,
    pub title: String,
    pub content: String,
    pub packet_content_digest: String,
    pub work_product_content_digest: String,
    pub created_at: DateTime<Utc>,
    pub revision_digest: String,
}

impl WorkProductRevision {
    pub fn from_packet(
        packet: &ResultPacket,
        work_product_id: WorkProductId,
        revision: u64,
        created_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        packet.validate()?;
        let mut work_product_revision = Self {
            tenant_id: packet.tenant_id.clone(),
            project_id: packet.project_id.clone(),
            mission_id: packet.mission_id.clone(),
            work_product_id,
            revision,
            mission_revision: packet.mission_revision,
            packet_id: packet.packet_id.clone(),
            packet_digest: packet.packet_digest.clone(),
            title: packet.title.clone(),
            content: packet.content.clone(),
            packet_content_digest: packet.content_digest.clone(),
            work_product_content_digest: work_product_digest(&packet.title, &packet.content),
            created_at,
            revision_digest: String::new(),
        };
        work_product_revision.revision_digest = work_product_revision.calculate_digest()?;
        work_product_revision.validate()?;
        Ok(work_product_revision)
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        if !valid_id(self.tenant_id.as_str())
            || !valid_id(self.project_id.as_str())
            || !valid_id(self.mission_id.as_str())
            || !valid_id(self.work_product_id.as_str())
            || self.revision == 0
            || self.mission_revision == 0
            || !valid_reference(self.packet_id.as_str())
            || !is_sha256(&self.packet_digest)
            || self.title.trim().is_empty()
            || self.content.trim().is_empty()
            || self.packet_content_digest != sha256(self.content.as_bytes())
            || self.work_product_content_digest != work_product_digest(&self.title, &self.content)
            || !is_sha256(&self.revision_digest)
            || self.revision_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidWorkProductRevision);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.revision_digest.clear();
        digest_json(&material)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionDecisionKind {
    Adopt,
    Reject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdoptionDecision {
    pub decision_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub packet_digest: String,
    pub decision: AdoptionDecisionKind,
    pub rationale: String,
    pub decided_at: DateTime<Utc>,
    pub decision_digest: String,
}

impl AdoptionDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        decision_id: impl Into<String>,
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
        work_product_id: WorkProductId,
        work_product_revision: u64,
        packet_digest: impl Into<String>,
        decision: AdoptionDecisionKind,
        rationale: impl Into<String>,
        decided_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        let mut decision = Self {
            decision_id: decision_id.into(),
            tenant_id,
            project_id,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            packet_digest: packet_digest.into(),
            decision,
            rationale: rationale.into(),
            decided_at,
            decision_digest: String::new(),
        };
        decision.decision_digest = decision.calculate_digest()?;
        decision.validate()?;
        Ok(decision)
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        if !valid_id(self.tenant_id.as_str())
            || !valid_id(self.project_id.as_str())
            || !valid_id(self.mission_id.as_str())
            || !valid_id(self.work_product_id.as_str())
            || !valid_reference(&self.decision_id)
            || self.mission_revision == 0
            || self.work_product_revision == 0
            || !is_sha256(&self.packet_digest)
            || self.rationale.trim().is_empty()
            || !is_sha256(&self.decision_digest)
            || self.decision_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionDecision);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.decision_digest.clear();
        digest_json(&material)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeVerificationKind {
    IndependentProvider,
    Reconciliation,
}

impl OutcomeVerificationKind {
    pub const fn is_independent(&self) -> bool {
        matches!(self, Self::IndependentProvider | Self::Reconciliation)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeClassification {
    Positive,
    Negative,
    Neutral,
    Mixed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutcomeLink {
    pub link_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub packet_digest: String,
    pub verification_kind: OutcomeVerificationKind,
    pub provider_ref: String,
    pub external_ref: String,
    pub outcome_classification: OutcomeClassification,
    pub outcome_digest: String,
    pub verification_digest: String,
    pub verified_at: DateTime<Utc>,
    pub link_digest: String,
}

impl OutcomeLink {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        link_id: impl Into<String>,
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        mission_revision: u64,
        work_product_id: WorkProductId,
        work_product_revision: u64,
        packet_digest: impl Into<String>,
        verification_kind: OutcomeVerificationKind,
        provider_ref: impl Into<String>,
        external_ref: impl Into<String>,
        outcome_classification: OutcomeClassification,
        outcome_digest: impl Into<String>,
        verification_digest: impl Into<String>,
        verified_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        let mut link = Self {
            link_id: link_id.into(),
            tenant_id,
            project_id,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            packet_digest: packet_digest.into(),
            verification_kind,
            provider_ref: provider_ref.into(),
            external_ref: external_ref.into(),
            outcome_classification,
            outcome_digest: outcome_digest.into(),
            verification_digest: verification_digest.into(),
            verified_at,
            link_digest: String::new(),
        };
        link.link_digest = link.calculate_digest()?;
        link.validate()?;
        Ok(link)
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        if !valid_id(self.tenant_id.as_str())
            || !valid_id(self.project_id.as_str())
            || !valid_id(self.mission_id.as_str())
            || !valid_id(self.work_product_id.as_str())
            || !valid_reference(&self.link_id)
            || self.mission_revision == 0
            || self.work_product_revision == 0
            || !is_sha256(&self.packet_digest)
            || !self.verification_kind.is_independent()
            || !valid_reference(&self.provider_ref)
            || !valid_reference(&self.external_ref)
            || self.provider_ref.starts_with("runtime://")
            || self.external_ref.starts_with("runtime://")
            || !is_sha256(&self.outcome_digest)
            || !is_sha256(&self.verification_digest)
            || !is_sha256(&self.link_digest)
            || self.link_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidOutcomeLink);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.link_digest.clear();
        digest_json(&material)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductHandoffSnapshot {
    pub schema_version: u32,
    pub packet: ResultPacket,
    pub revisions: Vec<WorkProductRevision>,
    pub adoption_decisions: Vec<AdoptionDecision>,
    pub outcome_links: Vec<OutcomeLink>,
    pub current_revision: u64,
    pub snapshot_digest: String,
}

impl WorkProductHandoffSnapshot {
    pub fn new(
        packet: ResultPacket,
        revision: WorkProductRevision,
    ) -> Result<Self, WorkProductOutcomeError> {
        let mut snapshot = Self {
            schema_version: WORK_PRODUCT_HANDOFF_SCHEMA_VERSION,
            packet,
            revisions: vec![revision],
            adoption_decisions: Vec::new(),
            outcome_links: Vec::new(),
            current_revision: 1,
            snapshot_digest: String::new(),
        };
        snapshot.snapshot_digest = snapshot.calculate_digest()?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn append_revision(
        &mut self,
        revision: WorkProductRevision,
    ) -> Result<(), WorkProductOutcomeError> {
        self.validate()?;
        let expected_revision = self
            .current_revision
            .checked_add(1)
            .ok_or(WorkProductOutcomeError::InvalidWorkProductRevision)?;
        let first = self
            .revisions
            .first()
            .ok_or(WorkProductOutcomeError::InvalidHandoffSnapshot)?;
        if revision.revision != expected_revision
            || revision.tenant_id != self.packet.tenant_id
            || revision.project_id != self.packet.project_id
            || revision.mission_id != self.packet.mission_id
            || revision.work_product_id != first.work_product_id
            || self
                .revisions
                .iter()
                .any(|item| item.revision == revision.revision)
        {
            return Err(WorkProductOutcomeError::InvalidWorkProductRevision);
        }
        self.revisions.push(revision);
        self.current_revision = self
            .revisions
            .last()
            .map_or(self.current_revision, |item| item.revision);
        self.refresh_digest()
    }

    pub fn append_adoption_decision(
        &mut self,
        decision: AdoptionDecision,
    ) -> Result<(), WorkProductOutcomeError> {
        self.validate()?;
        if self.adoption_decisions.iter().any(|item| {
            item.decision_id == decision.decision_id
                || (item.work_product_revision == decision.work_product_revision
                    && item.packet_digest == decision.packet_digest)
        }) {
            return Err(WorkProductOutcomeError::AdoptionDecisionConflict);
        }
        let revision = self.revision(decision.work_product_revision)?;
        if revision.packet_digest != decision.packet_digest {
            return Err(WorkProductOutcomeError::LineageMismatch);
        }
        self.adoption_decisions.push(decision);
        self.refresh_digest()
    }

    pub fn append_outcome_link(
        &mut self,
        link: OutcomeLink,
    ) -> Result<(), WorkProductOutcomeError> {
        self.validate()?;
        if self
            .outcome_links
            .iter()
            .any(|item| item.link_id == link.link_id)
        {
            return Err(WorkProductOutcomeError::DuplicateOutcomeLink);
        }
        let revision = self.revision(link.work_product_revision)?;
        if revision.packet_digest != link.packet_digest
            || revision.mission_revision != link.mission_revision
            || !link.verification_kind.is_independent()
        {
            return Err(WorkProductOutcomeError::LineageMismatch);
        }
        if !self.has_adopted_revision(link.work_product_revision, &link.packet_digest) {
            return Err(WorkProductOutcomeError::OutcomeRequiresAdoption);
        }
        self.outcome_links.push(link);
        self.refresh_digest()
    }

    pub fn revision(&self, revision: u64) -> Result<&WorkProductRevision, WorkProductOutcomeError> {
        self.revisions
            .iter()
            .find(|item| item.revision == revision)
            .ok_or(WorkProductOutcomeError::UnknownWorkProductRevision)
    }

    pub fn has_adopted_revision(&self, revision: u64, packet_digest: &str) -> bool {
        self.adoption_decisions.iter().any(|decision| {
            decision.work_product_revision == revision
                && decision.packet_digest == packet_digest
                && decision.decision == AdoptionDecisionKind::Adopt
        })
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        if self.schema_version != WORK_PRODUCT_HANDOFF_SCHEMA_VERSION
            || self.revisions.is_empty()
            || self.current_revision == 0
            || !is_sha256(&self.snapshot_digest)
        {
            return Err(WorkProductOutcomeError::InvalidHandoffSnapshot);
        }
        self.packet.validate()?;
        let mut packet_ids = BTreeSet::new();
        for (index, revision) in self.revisions.iter().enumerate() {
            revision.validate()?;
            let expected_revision = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(WorkProductOutcomeError::InvalidHandoffSnapshot)?;
            if revision.revision != expected_revision
                || revision.tenant_id != self.packet.tenant_id
                || revision.project_id != self.packet.project_id
                || revision.mission_id != self.packet.mission_id
                || !packet_ids.insert(revision.packet_id.clone())
            {
                return Err(WorkProductOutcomeError::InvalidHandoffSnapshot);
            }
        }
        let first = self
            .revisions
            .first()
            .ok_or(WorkProductOutcomeError::InvalidHandoffSnapshot)?;
        if first.packet_id != self.packet.packet_id
            || first.packet_digest != self.packet.packet_digest
            || self
                .revisions
                .iter()
                .any(|revision| revision.work_product_id != first.work_product_id)
            || self.current_revision
                != u64::try_from(self.revisions.len())
                    .map_err(|_| WorkProductOutcomeError::InvalidHandoffSnapshot)?
        {
            return Err(WorkProductOutcomeError::InvalidHandoffSnapshot);
        }
        let mut decision_ids = BTreeSet::new();
        for decision in &self.adoption_decisions {
            decision.validate()?;
            if !decision_ids.insert(decision.decision_id.clone())
                || !same_scope(
                    &decision.tenant_id,
                    &decision.project_id,
                    &decision.mission_id,
                    &self.packet.tenant_id,
                    &self.packet.project_id,
                    &self.packet.mission_id,
                )
                || self.revision(decision.work_product_revision)?.packet_digest
                    != decision.packet_digest
            {
                return Err(WorkProductOutcomeError::InvalidHandoffSnapshot);
            }
        }
        let mut link_ids = BTreeSet::new();
        for link in &self.outcome_links {
            link.validate()?;
            if !link_ids.insert(link.link_id.clone())
                || !same_scope(
                    &link.tenant_id,
                    &link.project_id,
                    &link.mission_id,
                    &self.packet.tenant_id,
                    &self.packet.project_id,
                    &self.packet.mission_id,
                )
                || self.revision(link.work_product_revision)?.packet_digest != link.packet_digest
                || self.revision(link.work_product_revision)?.mission_revision
                    != link.mission_revision
                || !self.has_adopted_revision(link.work_product_revision, &link.packet_digest)
            {
                return Err(WorkProductOutcomeError::InvalidHandoffSnapshot);
            }
        }
        if self.snapshot_digest != self.calculate_digest()? {
            return Err(WorkProductOutcomeError::InvalidHandoffSnapshot);
        }
        Ok(())
    }

    pub fn to_preview(&self) -> Result<WorkProductPreview, WorkProductOutcomeError> {
        self.validate()?;
        let text = serde_json::to_string(self).map_err(WorkProductOutcomeError::Serialization)?;
        WorkProductPreview::new(WORK_PRODUCT_HANDOFF_PREVIEW_MEDIA_TYPE, text)
            .map_err(WorkProductOutcomeError::Manifest)
    }

    pub fn from_preview(preview: &WorkProductPreview) -> Result<Self, WorkProductOutcomeError> {
        preview
            .validate()
            .map_err(WorkProductOutcomeError::Manifest)?;
        if preview.media_type != WORK_PRODUCT_HANDOFF_PREVIEW_MEDIA_TYPE {
            return Err(WorkProductOutcomeError::UnsupportedPreview);
        }
        let snapshot: Self =
            serde_json::from_str(&preview.text).map_err(WorkProductOutcomeError::Serialization)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn refresh_digest(&mut self) -> Result<(), WorkProductOutcomeError> {
        self.snapshot_digest = self.calculate_digest()?;
        self.validate()
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.snapshot_digest.clear();
        digest_json(&material)
    }
}

pub const WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION: u32 = 1;
pub const WORK_PRODUCT_ADOPTION_PLUGIN_ID: &str = "hartevo.adoptable-result";
pub const WORK_PRODUCT_ADOPTION_PLUGIN_VERSION: u32 = 1;
pub const WORK_PRODUCT_ADOPTION_SUMMARY_MEDIA_TYPE: &str =
    "application/vnd.hartevo.work-product-adoption-summary+json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkProductAdoptionPluginCapability {
    AdoptVerifiedHandoff,
    ContextualSummary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductAdoptionPluginService {
    pub schema_version: u32,
    pub plugin_id: String,
    pub version: u32,
    pub provider_id: String,
    pub capabilities: BTreeSet<WorkProductAdoptionPluginCapability>,
    pub service_digest: String,
}

impl WorkProductAdoptionPluginService {
    pub fn new(provider_id: impl Into<String>) -> Result<Self, WorkProductOutcomeError> {
        let mut capabilities = BTreeSet::new();
        capabilities.insert(WorkProductAdoptionPluginCapability::AdoptVerifiedHandoff);
        capabilities.insert(WorkProductAdoptionPluginCapability::ContextualSummary);
        let mut service = Self {
            schema_version: WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION,
            plugin_id: WORK_PRODUCT_ADOPTION_PLUGIN_ID.into(),
            version: WORK_PRODUCT_ADOPTION_PLUGIN_VERSION,
            provider_id: provider_id.into(),
            capabilities,
            service_digest: String::new(),
        };
        service.service_digest = service.calculate_digest()?;
        service.validate()?;
        Ok(service)
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        let expected_capabilities = [
            WorkProductAdoptionPluginCapability::AdoptVerifiedHandoff,
            WorkProductAdoptionPluginCapability::ContextualSummary,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if self.schema_version != WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION
            || self.plugin_id != WORK_PRODUCT_ADOPTION_PLUGIN_ID
            || self.version != WORK_PRODUCT_ADOPTION_PLUGIN_VERSION
            || !valid_reference(&self.provider_id)
            || self.capabilities != expected_capabilities
            || !is_sha256(&self.service_digest)
            || self.service_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionPlugin);
        }
        Ok(())
    }

    pub fn supports(&self, capability: WorkProductAdoptionPluginCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn mount_request(
        &self,
        scope: WorkProductAdoptionScope,
        consumer_id: impl Into<String>,
        generation: u64,
        requested_at: DateTime<Utc>,
    ) -> Result<WorkProductAdoptionMountRequest, WorkProductOutcomeError> {
        self.validate()?;
        scope.validate()?;
        WorkProductAdoptionMountRequest::new(self, scope, consumer_id, generation, requested_at)
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.service_digest.clear();
        digest_json(&material)
    }
}

pub type AdoptableResultPluginService = WorkProductAdoptionPluginService;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductAdoptionScope {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub source_mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub packet_digest: String,
    pub result_classification: ResultClassification,
    pub outcome_link_id: String,
    pub outcome_link_digest: String,
    pub scope_digest: String,
}

impl WorkProductAdoptionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_handoff(
        snapshot: &WorkProductHandoffSnapshot,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        mission_id: &MissionId,
        mission_revision: u64,
        work_product_revision: u64,
    ) -> Result<Self, WorkProductOutcomeError> {
        snapshot.validate()?;
        let revision = snapshot.revision(work_product_revision)?;
        if mission_revision == 0
            || snapshot.packet.tenant_id != *tenant_id
            || snapshot.packet.project_id != *project_id
            || snapshot.packet.mission_id != *mission_id
            || revision.mission_revision > mission_revision
            || !snapshot.has_adopted_revision(work_product_revision, &revision.packet_digest)
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionScope);
        }
        let link = snapshot
            .outcome_links
            .iter()
            .find(|link| {
                link.work_product_revision == work_product_revision
                    && link.packet_digest == revision.packet_digest
                    && link.verification_kind.is_independent()
            })
            .ok_or(WorkProductOutcomeError::AdoptionUnavailable)?;
        link.validate()?;
        let mut scope = Self {
            tenant_id: tenant_id.clone(),
            project_id: project_id.clone(),
            mission_id: mission_id.clone(),
            mission_revision,
            source_mission_revision: revision.mission_revision,
            work_product_id: revision.work_product_id.clone(),
            work_product_revision,
            packet_digest: revision.packet_digest.clone(),
            result_classification: snapshot.packet.classification.clone(),
            outcome_link_id: link.link_id.clone(),
            outcome_link_digest: link.link_digest.clone(),
            scope_digest: String::new(),
        };
        scope.scope_digest = scope.calculate_digest()?;
        scope.validate()?;
        Ok(scope)
    }

    pub fn matches_verified_handoff(
        &self,
        snapshot: &WorkProductHandoffSnapshot,
    ) -> Result<(), WorkProductOutcomeError> {
        let expected = Self::from_verified_handoff(
            snapshot,
            &self.tenant_id,
            &self.project_id,
            &self.mission_id,
            self.mission_revision,
            self.work_product_revision,
        )?;
        if expected != *self {
            return Err(WorkProductOutcomeError::InvalidAdoptionScope);
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        if !valid_id(self.tenant_id.as_str())
            || !valid_id(self.project_id.as_str())
            || !valid_id(self.mission_id.as_str())
            || self.mission_revision == 0
            || self.source_mission_revision == 0
            || self.source_mission_revision > self.mission_revision
            || !valid_id(self.work_product_id.as_str())
            || self.work_product_revision == 0
            || !is_sha256(&self.packet_digest)
            || !valid_reference(&self.outcome_link_id)
            || !is_sha256(&self.outcome_link_digest)
            || !is_sha256(&self.scope_digest)
            || self.scope_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionScope);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.scope_digest.clear();
        digest_json(&material)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductAdoptionMountRequest {
    pub schema_version: u32,
    pub plugin_id: String,
    pub service_digest: String,
    pub scope: WorkProductAdoptionScope,
    pub consumer_id: String,
    pub generation: u64,
    pub requested_at: DateTime<Utc>,
    pub mount_digest: String,
}

impl WorkProductAdoptionMountRequest {
    fn new(
        service: &WorkProductAdoptionPluginService,
        scope: WorkProductAdoptionScope,
        consumer_id: impl Into<String>,
        generation: u64,
        requested_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        let mut mount = Self {
            schema_version: WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION,
            plugin_id: service.plugin_id.clone(),
            service_digest: service.service_digest.clone(),
            scope,
            consumer_id: consumer_id.into(),
            generation,
            requested_at,
            mount_digest: String::new(),
        };
        mount.mount_digest = mount.calculate_digest()?;
        mount.validate_for(service)?;
        Ok(mount)
    }

    pub fn validate_for(
        &self,
        service: &WorkProductAdoptionPluginService,
    ) -> Result<(), WorkProductOutcomeError> {
        service.validate()?;
        self.scope.validate()?;
        if self.schema_version != WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION
            || self.plugin_id != service.plugin_id
            || self.service_digest != service.service_digest
            || !valid_reference(&self.consumer_id)
            || self.generation == 0
            || !is_sha256(&self.mount_digest)
            || self.mount_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionMount);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.mount_digest.clear();
        digest_json(&material)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkProductAdoptionLifecycle {
    Mounted,
    Unmounted,
    Revoked,
    Crashed,
}

impl WorkProductAdoptionLifecycle {
    pub const fn can_adopt(self) -> bool {
        matches!(self, Self::Mounted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkProductAdoptionOperationKind {
    Mount,
    Unmount,
    Revoke,
    Crash,
    Adopt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductAdoptionConsumerBinding {
    pub consumer_id: String,
    pub mount_generation: u64,
    pub mount_digest: String,
    pub consumer_digest: String,
}

impl WorkProductAdoptionConsumerBinding {
    fn from_mount(
        mount: &WorkProductAdoptionMountRequest,
    ) -> Result<Self, WorkProductOutcomeError> {
        let mut binding = Self {
            consumer_id: mount.consumer_id.clone(),
            mount_generation: mount.generation,
            mount_digest: mount.mount_digest.clone(),
            consumer_digest: String::new(),
        };
        binding.consumer_digest = binding.calculate_digest()?;
        binding.validate_for(mount)?;
        Ok(binding)
    }

    fn validate_for(
        &self,
        mount: &WorkProductAdoptionMountRequest,
    ) -> Result<(), WorkProductOutcomeError> {
        if !valid_reference(&self.consumer_id)
            || self.mount_generation != mount.generation
            || self.mount_digest != mount.mount_digest
            || !is_sha256(&self.consumer_digest)
            || self.consumer_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionState);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.consumer_digest.clear();
        digest_json(&material)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContextualWorkProductOutcomeSummary {
    pub schema_version: u32,
    pub media_type: String,
    pub plugin_id: String,
    pub service_digest: String,
    pub scope_digest: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub source_mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub packet_digest: String,
    pub result_classification: ResultClassification,
    pub outcome_link_id: String,
    pub outcome_link_digest: String,
    pub lifecycle: WorkProductAdoptionLifecycle,
    pub mount_generation: u64,
    pub adoption_available: bool,
    pub summary_digest: String,
}

impl ContextualWorkProductOutcomeSummary {
    fn from_scope(
        service: &WorkProductAdoptionPluginService,
        scope: &WorkProductAdoptionScope,
        lifecycle: WorkProductAdoptionLifecycle,
        mount_generation: u64,
    ) -> Result<Self, WorkProductOutcomeError> {
        let mut summary = Self {
            schema_version: WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION,
            media_type: WORK_PRODUCT_ADOPTION_SUMMARY_MEDIA_TYPE.into(),
            plugin_id: service.plugin_id.clone(),
            service_digest: service.service_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            tenant_id: scope.tenant_id.clone(),
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
            mission_revision: scope.mission_revision,
            source_mission_revision: scope.source_mission_revision,
            work_product_id: scope.work_product_id.clone(),
            work_product_revision: scope.work_product_revision,
            packet_digest: scope.packet_digest.clone(),
            result_classification: scope.result_classification.clone(),
            outcome_link_id: scope.outcome_link_id.clone(),
            outcome_link_digest: scope.outcome_link_digest.clone(),
            lifecycle,
            mount_generation,
            adoption_available: lifecycle.can_adopt(),
            summary_digest: String::new(),
        };
        summary.summary_digest = summary.calculate_digest()?;
        summary.validate_for(service, scope)?;
        Ok(summary)
    }

    pub fn validate_for(
        &self,
        service: &WorkProductAdoptionPluginService,
        scope: &WorkProductAdoptionScope,
    ) -> Result<(), WorkProductOutcomeError> {
        service.validate()?;
        scope.validate()?;
        if self.schema_version != WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION
            || self.media_type != WORK_PRODUCT_ADOPTION_SUMMARY_MEDIA_TYPE
            || self.plugin_id != service.plugin_id
            || self.service_digest != service.service_digest
            || self.scope_digest != scope.scope_digest
            || self.tenant_id != scope.tenant_id
            || self.project_id != scope.project_id
            || self.mission_id != scope.mission_id
            || self.mission_revision != scope.mission_revision
            || self.source_mission_revision != scope.source_mission_revision
            || self.work_product_id != scope.work_product_id
            || self.work_product_revision != scope.work_product_revision
            || self.packet_digest != scope.packet_digest
            || self.result_classification != scope.result_classification
            || self.outcome_link_id != scope.outcome_link_id
            || self.outcome_link_digest != scope.outcome_link_digest
            || self.mount_generation == 0
            || self.adoption_available != self.lifecycle.can_adopt()
            || !is_sha256(&self.summary_digest)
            || self.summary_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionState);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.summary_digest.clear();
        digest_json(&material)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductAdoptionReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub plugin_id: String,
    pub service_digest: String,
    pub provider_id: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub source_mission_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub packet_digest: String,
    pub scope_digest: String,
    pub outcome_link_id: String,
    pub outcome_link_digest: String,
    pub consumer_id: String,
    pub mount_generation: u64,
    pub mount_digest: String,
    pub adopted_at: DateTime<Utc>,
    pub receipt_digest: String,
}

impl WorkProductAdoptionReceipt {
    fn new(
        service: &WorkProductAdoptionPluginService,
        mount: &WorkProductAdoptionMountRequest,
        consumer: &MissionWorkProductAdoptionConsumer,
        receipt_id: impl Into<String>,
        adopted_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        let scope = &mount.scope;
        let mut receipt = Self {
            schema_version: WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION,
            receipt_id: receipt_id.into(),
            plugin_id: service.plugin_id.clone(),
            service_digest: service.service_digest.clone(),
            provider_id: service.provider_id.clone(),
            tenant_id: scope.tenant_id.clone(),
            project_id: scope.project_id.clone(),
            mission_id: scope.mission_id.clone(),
            mission_revision: scope.mission_revision,
            source_mission_revision: scope.source_mission_revision,
            work_product_id: scope.work_product_id.clone(),
            work_product_revision: scope.work_product_revision,
            packet_digest: scope.packet_digest.clone(),
            scope_digest: scope.scope_digest.clone(),
            outcome_link_id: scope.outcome_link_id.clone(),
            outcome_link_digest: scope.outcome_link_digest.clone(),
            consumer_id: consumer.consumer_id.clone(),
            mount_generation: mount.generation,
            mount_digest: mount.mount_digest.clone(),
            adopted_at,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        receipt.validate_for(service, scope, mount, consumer)?;
        Ok(receipt)
    }

    pub fn validate_for(
        &self,
        service: &WorkProductAdoptionPluginService,
        scope: &WorkProductAdoptionScope,
        mount: &WorkProductAdoptionMountRequest,
        consumer: &MissionWorkProductAdoptionConsumer,
    ) -> Result<(), WorkProductOutcomeError> {
        service.validate()?;
        mount.validate_for(service)?;
        scope.validate()?;
        self.validate_scope_only(service, scope)?;
        if self.schema_version != WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION
            || !valid_reference(&self.receipt_id)
            || self.plugin_id != service.plugin_id
            || self.service_digest != service.service_digest
            || self.provider_id != service.provider_id
            || self.tenant_id != scope.tenant_id
            || self.project_id != scope.project_id
            || self.mission_id != scope.mission_id
            || self.mission_revision != scope.mission_revision
            || self.source_mission_revision != scope.source_mission_revision
            || self.work_product_id != scope.work_product_id
            || self.work_product_revision != scope.work_product_revision
            || self.packet_digest != scope.packet_digest
            || self.scope_digest != scope.scope_digest
            || self.outcome_link_id != scope.outcome_link_id
            || self.outcome_link_digest != scope.outcome_link_digest
            || self.consumer_id != consumer.consumer_id
            || self.consumer_id != mount.consumer_id
            || self.mount_generation != mount.generation
            || self.mount_digest != mount.mount_digest
            || self.adopted_at < mount.requested_at
            || !is_sha256(&self.receipt_digest)
            || self.receipt_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionReceipt);
        }
        Ok(())
    }

    fn validate_scope_only(
        &self,
        service: &WorkProductAdoptionPluginService,
        scope: &WorkProductAdoptionScope,
    ) -> Result<(), WorkProductOutcomeError> {
        service.validate()?;
        scope.validate()?;
        if self.schema_version != WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION
            || !valid_reference(&self.receipt_id)
            || self.plugin_id != service.plugin_id
            || self.service_digest != service.service_digest
            || self.provider_id != service.provider_id
            || self.tenant_id != scope.tenant_id
            || self.project_id != scope.project_id
            || self.mission_id != scope.mission_id
            || self.mission_revision != scope.mission_revision
            || self.source_mission_revision != scope.source_mission_revision
            || self.work_product_id != scope.work_product_id
            || self.work_product_revision != scope.work_product_revision
            || self.packet_digest != scope.packet_digest
            || self.scope_digest != scope.scope_digest
            || self.outcome_link_id != scope.outcome_link_id
            || self.outcome_link_digest != scope.outcome_link_digest
            || !valid_reference(&self.consumer_id)
            || self.mount_generation == 0
            || !is_sha256(&self.mount_digest)
            || !is_sha256(&self.receipt_digest)
            || self.receipt_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionReceipt);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.receipt_digest.clear();
        digest_json(&material)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductAdoptionOperationRecord {
    pub operation_id: String,
    pub operation_kind: WorkProductAdoptionOperationKind,
    pub operation_digest: String,
    pub service_digest: String,
    pub resulting_lifecycle: WorkProductAdoptionLifecycle,
    pub generation: u64,
    pub mount_digest: String,
    pub consumer_id: Option<String>,
    pub receipt_id: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

impl WorkProductAdoptionOperationRecord {
    fn new(
        command: &WorkProductAdoptionCommand,
        resulting_lifecycle: WorkProductAdoptionLifecycle,
        occurred_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        let record = Self {
            operation_id: command.operation_id().to_owned(),
            operation_kind: command.operation_kind(),
            operation_digest: command.operation_digest()?,
            service_digest: command.service_digest().to_owned(),
            resulting_lifecycle,
            generation: command.generation(),
            mount_digest: command.mount_digest().to_owned(),
            consumer_id: command.consumer_id().map(ToOwned::to_owned),
            receipt_id: command.receipt_id().map(ToOwned::to_owned),
            occurred_at,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        if !valid_reference(&self.operation_id)
            || !is_sha256(&self.operation_digest)
            || !is_sha256(&self.service_digest)
            || self.generation == 0
            || !is_sha256(&self.mount_digest)
            || self
                .consumer_id
                .as_deref()
                .is_some_and(|value| !valid_reference(value))
            || self
                .receipt_id
                .as_deref()
                .is_some_and(|value| !valid_reference(value))
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionState);
        }
        if self.operation_digest
            != adoption_operation_digest(
                self.operation_kind,
                &self.operation_id,
                &self.service_digest,
                &self.mount_digest,
                self.generation,
                self.consumer_id.as_deref(),
                self.receipt_id.as_deref(),
            )?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionState);
        }
        if (self.operation_kind == WorkProductAdoptionOperationKind::Mount
            && (self.resulting_lifecycle != WorkProductAdoptionLifecycle::Mounted
                || self.consumer_id.is_some()
                || self.receipt_id.is_some()))
            || (self.operation_kind == WorkProductAdoptionOperationKind::Adopt
                && (self.resulting_lifecycle != WorkProductAdoptionLifecycle::Mounted
                    || self.consumer_id.is_none()
                    || self.receipt_id.is_none()))
            || (matches!(
                self.operation_kind,
                WorkProductAdoptionOperationKind::Unmount
                    | WorkProductAdoptionOperationKind::Revoke
                    | WorkProductAdoptionOperationKind::Crash
            ) && (self.consumer_id.is_some() || self.receipt_id.is_some()))
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionState);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductAdoptionState {
    pub schema_version: u32,
    pub plugin_id: String,
    pub service: WorkProductAdoptionPluginService,
    pub scope: WorkProductAdoptionScope,
    pub lifecycle: WorkProductAdoptionLifecycle,
    pub generation: u64,
    pub mount: WorkProductAdoptionMountRequest,
    pub consumer: WorkProductAdoptionConsumerBinding,
    pub summary: ContextualWorkProductOutcomeSummary,
    pub receipts: Vec<WorkProductAdoptionReceipt>,
    pub operations: Vec<WorkProductAdoptionOperationRecord>,
    pub state_digest: String,
}

impl WorkProductAdoptionState {
    pub fn initial(
        service: WorkProductAdoptionPluginService,
        mount: WorkProductAdoptionMountRequest,
        occurred_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        mount.validate_for(&service)?;
        let consumer = WorkProductAdoptionConsumerBinding::from_mount(&mount)?;
        let summary = ContextualWorkProductOutcomeSummary::from_scope(
            &service,
            &mount.scope,
            WorkProductAdoptionLifecycle::Mounted,
            mount.generation,
        )?;
        let command = WorkProductAdoptionCommand::Mount {
            service: service.clone(),
            mount: Box::new(mount.clone()),
        };
        let operations = vec![WorkProductAdoptionOperationRecord::new(
            &command,
            WorkProductAdoptionLifecycle::Mounted,
            occurred_at,
        )?];
        let mut state = Self {
            schema_version: WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION,
            plugin_id: service.plugin_id.clone(),
            service,
            scope: mount.scope.clone(),
            lifecycle: WorkProductAdoptionLifecycle::Mounted,
            generation: mount.generation,
            mount,
            consumer,
            summary,
            receipts: Vec::new(),
            operations,
            state_digest: String::new(),
        };
        state.state_digest = state.calculate_digest()?;
        state.validate()?;
        Ok(state)
    }

    pub fn remount(
        &self,
        service: WorkProductAdoptionPluginService,
        mount: WorkProductAdoptionMountRequest,
        occurred_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        self.validate()?;
        if self.lifecycle == WorkProductAdoptionLifecycle::Revoked {
            return Err(WorkProductOutcomeError::AdoptionPluginRevoked);
        }
        if !matches!(
            self.lifecycle,
            WorkProductAdoptionLifecycle::Unmounted | WorkProductAdoptionLifecycle::Crashed
        ) || mount.generation <= self.generation
        {
            return Err(WorkProductOutcomeError::AdoptionLifecycleConflict);
        }
        if mount.scope != self.scope {
            return Err(WorkProductOutcomeError::InvalidAdoptionScope);
        }
        if service.service_digest != self.service.service_digest {
            return Err(WorkProductOutcomeError::InvalidAdoptionPlugin);
        }
        mount.validate_for(&service)?;
        let consumer = WorkProductAdoptionConsumerBinding::from_mount(&mount)?;
        let summary = ContextualWorkProductOutcomeSummary::from_scope(
            &service,
            &self.scope,
            WorkProductAdoptionLifecycle::Mounted,
            mount.generation,
        )?;
        let command = WorkProductAdoptionCommand::Mount {
            service: service.clone(),
            mount: Box::new(mount.clone()),
        };
        let mut state = Self {
            schema_version: WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION,
            plugin_id: service.plugin_id.clone(),
            service,
            scope: self.scope.clone(),
            lifecycle: WorkProductAdoptionLifecycle::Mounted,
            generation: mount.generation,
            mount,
            consumer,
            summary,
            receipts: self.receipts.clone(),
            operations: self.operations.clone(),
            state_digest: String::new(),
        };
        state
            .operations
            .push(WorkProductAdoptionOperationRecord::new(
                &command,
                WorkProductAdoptionLifecycle::Mounted,
                occurred_at,
            )?);
        state.state_digest = state.calculate_digest()?;
        state.validate()?;
        Ok(state)
    }

    pub fn transition(
        &self,
        lifecycle: WorkProductAdoptionLifecycle,
        command: &WorkProductAdoptionCommand,
        occurred_at: DateTime<Utc>,
    ) -> Result<Self, WorkProductOutcomeError> {
        self.validate()?;
        if !self.lifecycle.can_adopt()
            || !matches!(
                lifecycle,
                WorkProductAdoptionLifecycle::Unmounted
                    | WorkProductAdoptionLifecycle::Revoked
                    | WorkProductAdoptionLifecycle::Crashed
            )
            || command.operation_kind() == WorkProductAdoptionOperationKind::Mount
        {
            return Err(WorkProductOutcomeError::AdoptionLifecycleConflict);
        }
        self.validate_command_binding(command)?;
        let operation = WorkProductAdoptionOperationRecord::new(command, lifecycle, occurred_at)?;
        let summary = ContextualWorkProductOutcomeSummary::from_scope(
            &self.service,
            &self.scope,
            lifecycle,
            self.generation,
        )?;
        let mut state = self.clone();
        state.lifecycle = lifecycle;
        state.summary = summary;
        state.operations.push(operation);
        state.state_digest = state.calculate_digest()?;
        state.validate()?;
        Ok(state)
    }

    pub fn adopt(
        &self,
        command: &WorkProductAdoptionCommand,
        occurred_at: DateTime<Utc>,
    ) -> Result<(Self, WorkProductAdoptionReceipt), WorkProductOutcomeError> {
        self.validate()?;
        if !self.lifecycle.can_adopt()
            || command.operation_kind() != WorkProductAdoptionOperationKind::Adopt
        {
            return Err(WorkProductOutcomeError::AdoptionLifecycleConflict);
        }
        self.validate_command_binding(command)?;
        let consumer_id = command
            .consumer_id()
            .ok_or(WorkProductOutcomeError::AdoptionConsumerMismatch)?;
        if consumer_id != self.consumer.consumer_id {
            return Err(WorkProductOutcomeError::AdoptionConsumerMismatch);
        }
        let consumer =
            MissionWorkProductAdoptionConsumer::from_binding(&self.mount, &self.consumer)?;
        let receipt_id = command
            .receipt_id()
            .ok_or(WorkProductOutcomeError::InvalidAdoptionReceipt)?;
        if self
            .receipts
            .iter()
            .any(|receipt| receipt.receipt_id == receipt_id)
        {
            return Err(WorkProductOutcomeError::AdoptionReplayMismatch);
        }
        let receipt = WorkProductAdoptionReceipt::new(
            &self.service,
            &self.mount,
            &consumer,
            receipt_id,
            occurred_at,
        )?;
        let mut state = self.clone();
        state.receipts.push(receipt.clone());
        state
            .operations
            .push(WorkProductAdoptionOperationRecord::new(
                command,
                WorkProductAdoptionLifecycle::Mounted,
                occurred_at,
            )?);
        state.state_digest = state.calculate_digest()?;
        state.validate()?;
        Ok((state, receipt))
    }

    pub fn operation(&self, operation_id: &str) -> Option<&WorkProductAdoptionOperationRecord> {
        self.operations
            .iter()
            .find(|operation| operation.operation_id == operation_id)
    }

    pub fn receipt_for_operation(&self, operation_id: &str) -> Option<&WorkProductAdoptionReceipt> {
        self.operation(operation_id)
            .and_then(|operation| operation.receipt_id.as_ref())
            .and_then(|receipt_id| {
                self.receipts
                    .iter()
                    .find(|receipt| &receipt.receipt_id == receipt_id)
            })
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        self.service.validate()?;
        self.scope.validate()?;
        self.mount.validate_for(&self.service)?;
        self.consumer.validate_for(&self.mount)?;
        self.summary.validate_for(&self.service, &self.scope)?;
        if self.schema_version != WORK_PRODUCT_ADOPTION_PLUGIN_SCHEMA_VERSION
            || self.plugin_id != self.service.plugin_id
            || self.scope != self.mount.scope
            || self.generation != self.mount.generation
            || self.summary.lifecycle != self.lifecycle
            || self.summary.mount_generation != self.generation
            || self.lifecycle == WorkProductAdoptionLifecycle::Mounted
                && !self.summary.adoption_available
            || self.lifecycle != WorkProductAdoptionLifecycle::Mounted
                && self.summary.adoption_available
            || self.operations.is_empty()
            || self
                .operations
                .iter()
                .any(|operation| operation.validate().is_err())
            || self.validate_operation_history().is_err()
            || self
                .operations
                .windows(2)
                .any(|window| window[0].operation_id == window[1].operation_id)
            || self.receipts.iter().any(|receipt| {
                receipt
                    .validate_scope_only(&self.service, &self.scope)
                    .is_err()
            })
            || !is_sha256(&self.state_digest)
            || self.state_digest != self.calculate_digest()?
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionState);
        }
        let mut operation_ids = BTreeSet::new();
        if self
            .operations
            .iter()
            .any(|operation| !operation_ids.insert(operation.operation_id.clone()))
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionState);
        }
        Ok(())
    }

    fn validate_operation_history(&self) -> Result<(), WorkProductOutcomeError> {
        let mut lifecycle = None;
        let mut generation = 0;
        let mut mount_digest = None;
        for operation in &self.operations {
            if operation.service_digest != self.service.service_digest {
                return Err(WorkProductOutcomeError::InvalidAdoptionState);
            }
            match operation.operation_kind {
                WorkProductAdoptionOperationKind::Mount => {
                    if lifecycle.is_some_and(|value| {
                        !matches!(
                            value,
                            WorkProductAdoptionLifecycle::Unmounted
                                | WorkProductAdoptionLifecycle::Crashed
                        )
                    }) || lifecycle.is_some() && operation.generation <= generation
                    {
                        return Err(WorkProductOutcomeError::InvalidAdoptionState);
                    }
                }
                WorkProductAdoptionOperationKind::Adopt => {
                    if operation.resulting_lifecycle != WorkProductAdoptionLifecycle::Mounted
                        || lifecycle != Some(WorkProductAdoptionLifecycle::Mounted)
                        || operation.generation != generation
                        || mount_digest.as_deref() != Some(operation.mount_digest.as_str())
                    {
                        return Err(WorkProductOutcomeError::InvalidAdoptionState);
                    }
                    let receipt_id = operation
                        .receipt_id
                        .as_deref()
                        .ok_or(WorkProductOutcomeError::InvalidAdoptionState)?;
                    let receipt = self
                        .receipts
                        .iter()
                        .find(|receipt| receipt.receipt_id == receipt_id)
                        .ok_or(WorkProductOutcomeError::InvalidAdoptionState)?;
                    if receipt.mount_generation != operation.generation
                        || receipt.mount_digest != operation.mount_digest
                        || operation.consumer_id.as_deref() != Some(receipt.consumer_id.as_str())
                        || receipt.adopted_at < operation.occurred_at
                    {
                        return Err(WorkProductOutcomeError::InvalidAdoptionState);
                    }
                }
                WorkProductAdoptionOperationKind::Unmount
                | WorkProductAdoptionOperationKind::Revoke
                | WorkProductAdoptionOperationKind::Crash => {
                    let expected_lifecycle = match operation.operation_kind {
                        WorkProductAdoptionOperationKind::Unmount => {
                            WorkProductAdoptionLifecycle::Unmounted
                        }
                        WorkProductAdoptionOperationKind::Revoke => {
                            WorkProductAdoptionLifecycle::Revoked
                        }
                        WorkProductAdoptionOperationKind::Crash => {
                            WorkProductAdoptionLifecycle::Crashed
                        }
                        _ => unreachable!(),
                    };
                    if operation.resulting_lifecycle != expected_lifecycle
                        || lifecycle != Some(WorkProductAdoptionLifecycle::Mounted)
                        || operation.generation != generation
                        || mount_digest.as_deref() != Some(operation.mount_digest.as_str())
                    {
                        return Err(WorkProductOutcomeError::InvalidAdoptionState);
                    }
                }
            }
            lifecycle = Some(operation.resulting_lifecycle);
            generation = operation.generation;
            mount_digest = Some(operation.mount_digest.clone());
        }
        if lifecycle != Some(self.lifecycle)
            || generation != self.generation
            || mount_digest.as_deref() != Some(self.mount.mount_digest.as_str())
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionState);
        }
        for receipt in &self.receipts {
            if !self.operations.iter().any(|operation| {
                operation.operation_kind == WorkProductAdoptionOperationKind::Adopt
                    && operation.receipt_id.as_deref() == Some(receipt.receipt_id.as_str())
            }) {
                return Err(WorkProductOutcomeError::InvalidAdoptionState);
            }
        }
        Ok(())
    }

    fn validate_command_binding(
        &self,
        command: &WorkProductAdoptionCommand,
    ) -> Result<(), WorkProductOutcomeError> {
        if command.service_digest() != self.service.service_digest
            || command.mount_digest() != self.mount.mount_digest
            || command.generation() != self.generation
        {
            return Err(WorkProductOutcomeError::AdoptionMountMismatch);
        }
        command.validate()?;
        Ok(())
    }

    fn calculate_digest(&self) -> Result<String, WorkProductOutcomeError> {
        let mut material = self.clone();
        material.state_digest.clear();
        digest_json(&material)
    }
}

fn adoption_operation_digest(
    operation_kind: WorkProductAdoptionOperationKind,
    operation_id: &str,
    service_digest: &str,
    mount_digest: &str,
    generation: u64,
    consumer_id: Option<&str>,
    receipt_id: Option<&str>,
) -> Result<String, WorkProductOutcomeError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationMaterial<'a> {
        operation_kind: WorkProductAdoptionOperationKind,
        operation_id: &'a str,
        service_digest: &'a str,
        mount_digest: &'a str,
        generation: u64,
        consumer_id: Option<&'a str>,
        receipt_id: Option<&'a str>,
    }
    digest_json(&OperationMaterial {
        operation_kind,
        operation_id,
        service_digest,
        mount_digest,
        generation,
        consumer_id,
        receipt_id,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum WorkProductAdoptionCommand {
    Mount {
        service: WorkProductAdoptionPluginService,
        mount: Box<WorkProductAdoptionMountRequest>,
    },
    Unmount {
        operation_id: String,
        service_digest: String,
        mount_digest: String,
        generation: u64,
    },
    Revoke {
        operation_id: String,
        service_digest: String,
        mount_digest: String,
        generation: u64,
    },
    Crash {
        operation_id: String,
        service_digest: String,
        mount_digest: String,
        generation: u64,
    },
    Adopt {
        operation_id: String,
        service_digest: String,
        mount_digest: String,
        generation: u64,
        consumer_id: String,
        receipt_id: String,
    },
}

impl WorkProductAdoptionCommand {
    pub fn mount(
        service: WorkProductAdoptionPluginService,
        mount: WorkProductAdoptionMountRequest,
    ) -> Self {
        Self::Mount {
            service,
            mount: Box::new(mount),
        }
    }

    pub fn unmount(
        operation_id: impl Into<String>,
        service_digest: impl Into<String>,
        mount_digest: impl Into<String>,
        generation: u64,
    ) -> Self {
        Self::Unmount {
            operation_id: operation_id.into(),
            service_digest: service_digest.into(),
            mount_digest: mount_digest.into(),
            generation,
        }
    }

    pub fn revoke(
        operation_id: impl Into<String>,
        service_digest: impl Into<String>,
        mount_digest: impl Into<String>,
        generation: u64,
    ) -> Self {
        Self::Revoke {
            operation_id: operation_id.into(),
            service_digest: service_digest.into(),
            mount_digest: mount_digest.into(),
            generation,
        }
    }

    pub fn crash(
        operation_id: impl Into<String>,
        service_digest: impl Into<String>,
        mount_digest: impl Into<String>,
        generation: u64,
    ) -> Self {
        Self::Crash {
            operation_id: operation_id.into(),
            service_digest: service_digest.into(),
            mount_digest: mount_digest.into(),
            generation,
        }
    }

    pub fn adopt(
        operation_id: impl Into<String>,
        service_digest: impl Into<String>,
        mount_digest: impl Into<String>,
        generation: u64,
        consumer_id: impl Into<String>,
        receipt_id: impl Into<String>,
    ) -> Self {
        Self::Adopt {
            operation_id: operation_id.into(),
            service_digest: service_digest.into(),
            mount_digest: mount_digest.into(),
            generation,
            consumer_id: consumer_id.into(),
            receipt_id: receipt_id.into(),
        }
    }

    pub fn operation_id(&self) -> &str {
        match self {
            Self::Mount { mount, .. } => &mount.mount_digest,
            Self::Unmount { operation_id, .. }
            | Self::Revoke { operation_id, .. }
            | Self::Crash { operation_id, .. }
            | Self::Adopt { operation_id, .. } => operation_id,
        }
    }

    fn operation_kind(&self) -> WorkProductAdoptionOperationKind {
        match self {
            Self::Mount { .. } => WorkProductAdoptionOperationKind::Mount,
            Self::Unmount { .. } => WorkProductAdoptionOperationKind::Unmount,
            Self::Revoke { .. } => WorkProductAdoptionOperationKind::Revoke,
            Self::Crash { .. } => WorkProductAdoptionOperationKind::Crash,
            Self::Adopt { .. } => WorkProductAdoptionOperationKind::Adopt,
        }
    }

    fn service_digest(&self) -> &str {
        match self {
            Self::Mount { service, .. } => &service.service_digest,
            Self::Unmount { service_digest, .. }
            | Self::Revoke { service_digest, .. }
            | Self::Crash { service_digest, .. }
            | Self::Adopt { service_digest, .. } => service_digest,
        }
    }

    fn mount_digest(&self) -> &str {
        match self {
            Self::Mount { mount, .. } => &mount.mount_digest,
            Self::Unmount { mount_digest, .. }
            | Self::Revoke { mount_digest, .. }
            | Self::Crash { mount_digest, .. }
            | Self::Adopt { mount_digest, .. } => mount_digest,
        }
    }

    fn generation(&self) -> u64 {
        match self {
            Self::Mount { mount, .. } => mount.generation,
            Self::Unmount { generation, .. }
            | Self::Revoke { generation, .. }
            | Self::Crash { generation, .. }
            | Self::Adopt { generation, .. } => *generation,
        }
    }

    fn consumer_id(&self) -> Option<&str> {
        match self {
            Self::Adopt { consumer_id, .. } => Some(consumer_id),
            _ => None,
        }
    }

    fn receipt_id(&self) -> Option<&str> {
        match self {
            Self::Adopt { receipt_id, .. } => Some(receipt_id),
            _ => None,
        }
    }

    pub fn operation_digest(&self) -> Result<String, WorkProductOutcomeError> {
        adoption_operation_digest(
            self.operation_kind(),
            self.operation_id(),
            self.service_digest(),
            self.mount_digest(),
            self.generation(),
            self.consumer_id(),
            self.receipt_id(),
        )
    }

    pub fn validate(&self) -> Result<(), WorkProductOutcomeError> {
        if !valid_reference(self.operation_id())
            || !is_sha256(self.mount_digest())
            || self.generation() == 0
            || !is_sha256(self.service_digest())
            || self
                .consumer_id()
                .is_some_and(|value| !valid_reference(value))
            || self
                .receipt_id()
                .is_some_and(|value| !valid_reference(value))
        {
            return Err(WorkProductOutcomeError::InvalidAdoptionState);
        }
        if let Self::Mount { service, mount } = self {
            service.validate()?;
            mount.validate_for(service)?;
            if mount.mount_digest != self.mount_digest() {
                return Err(WorkProductOutcomeError::InvalidAdoptionMount);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct WorkProductAdoptionProvider {
    pub service: WorkProductAdoptionPluginService,
    pub mount: WorkProductAdoptionMountRequest,
    pub lifecycle: WorkProductAdoptionLifecycle,
}

impl WorkProductAdoptionProvider {
    pub fn mount(
        service: WorkProductAdoptionPluginService,
        mount: WorkProductAdoptionMountRequest,
    ) -> Result<Self, WorkProductOutcomeError> {
        mount.validate_for(&service)?;
        Ok(Self {
            service,
            mount,
            lifecycle: WorkProductAdoptionLifecycle::Mounted,
        })
    }

    pub fn adopt(
        &self,
        consumer: &MissionWorkProductAdoptionConsumer,
        receipt_id: impl Into<String>,
        adopted_at: DateTime<Utc>,
    ) -> Result<WorkProductAdoptionReceipt, WorkProductOutcomeError> {
        if !self.lifecycle.can_adopt() {
            return Err(WorkProductOutcomeError::AdoptionLifecycleConflict);
        }
        consumer.validate_for(&self.mount)?;
        WorkProductAdoptionReceipt::new(
            &self.service,
            &self.mount,
            consumer,
            receipt_id,
            adopted_at,
        )
    }

    pub fn transition(
        &self,
        lifecycle: WorkProductAdoptionLifecycle,
    ) -> Result<Self, WorkProductOutcomeError> {
        if !self.lifecycle.can_adopt() || lifecycle == WorkProductAdoptionLifecycle::Mounted {
            return Err(WorkProductOutcomeError::AdoptionLifecycleConflict);
        }
        Ok(Self {
            service: self.service.clone(),
            mount: self.mount.clone(),
            lifecycle,
        })
    }
}

pub type AdoptableResultPluginProvider = WorkProductAdoptionProvider;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionWorkProductAdoptionConsumer {
    pub consumer_id: String,
    pub mount_generation: u64,
    pub mount_digest: String,
    pub lifecycle: WorkProductAdoptionLifecycle,
}

impl MissionWorkProductAdoptionConsumer {
    pub fn new(
        consumer_id: impl Into<String>,
        mount: &WorkProductAdoptionMountRequest,
    ) -> Result<Self, WorkProductOutcomeError> {
        let consumer_id = consumer_id.into();
        if consumer_id != mount.consumer_id {
            return Err(WorkProductOutcomeError::AdoptionConsumerMismatch);
        }
        let consumer = Self {
            consumer_id,
            mount_generation: mount.generation,
            mount_digest: mount.mount_digest.clone(),
            lifecycle: WorkProductAdoptionLifecycle::Mounted,
        };
        consumer.validate_for(mount)?;
        Ok(consumer)
    }

    fn from_binding(
        mount: &WorkProductAdoptionMountRequest,
        binding: &WorkProductAdoptionConsumerBinding,
    ) -> Result<Self, WorkProductOutcomeError> {
        let consumer = Self {
            consumer_id: binding.consumer_id.clone(),
            mount_generation: binding.mount_generation,
            mount_digest: binding.mount_digest.clone(),
            lifecycle: WorkProductAdoptionLifecycle::Mounted,
        };
        consumer.validate_for(mount)?;
        Ok(consumer)
    }

    pub fn validate_for(
        &self,
        mount: &WorkProductAdoptionMountRequest,
    ) -> Result<(), WorkProductOutcomeError> {
        if !valid_reference(&self.consumer_id)
            || self.consumer_id != mount.consumer_id
            || self.mount_generation != mount.generation
            || self.mount_digest != mount.mount_digest
            || !self.lifecycle.can_adopt()
        {
            return Err(WorkProductOutcomeError::AdoptionConsumerMismatch);
        }
        Ok(())
    }

    pub fn adopt(
        &self,
        provider: &WorkProductAdoptionProvider,
        receipt_id: impl Into<String>,
        adopted_at: DateTime<Utc>,
    ) -> Result<WorkProductAdoptionReceipt, WorkProductOutcomeError> {
        if !self.lifecycle.can_adopt() {
            return Err(WorkProductOutcomeError::AdoptionLifecycleConflict);
        }
        provider.adopt(self, receipt_id, adopted_at)
    }

    pub fn transition(
        &self,
        lifecycle: WorkProductAdoptionLifecycle,
    ) -> Result<Self, WorkProductOutcomeError> {
        if !self.lifecycle.can_adopt() || lifecycle == WorkProductAdoptionLifecycle::Mounted {
            return Err(WorkProductOutcomeError::AdoptionLifecycleConflict);
        }
        Ok(Self {
            consumer_id: self.consumer_id.clone(),
            mount_generation: self.mount_generation,
            mount_digest: self.mount_digest.clone(),
            lifecycle,
        })
    }
}

pub type AdoptableResultMissionConsumer = MissionWorkProductAdoptionConsumer;

#[derive(Debug, Error)]
pub enum WorkProductOutcomeError {
    #[error("result packet scope, time, content digest, or packet digest is invalid")]
    InvalidResultPacket,
    #[error("result counterevidence reference or digest is invalid")]
    InvalidCounterevidence,
    #[error("work product revision lineage, content digest, or revision digest is invalid")]
    InvalidWorkProductRevision,
    #[error("adoption decision scope, lineage, or decision digest is invalid")]
    InvalidAdoptionDecision,
    #[error("verified outcome link is not independently verified or has invalid lineage")]
    InvalidOutcomeLink,
    #[error("work product handoff snapshot is invalid or tampered")]
    InvalidHandoffSnapshot,
    #[error("work product handoff preview media type is not supported")]
    UnsupportedPreview,
    #[error("work product handoff snapshot serialization failed: {0}")]
    Serialization(serde_json::Error),
    #[error(transparent)]
    Manifest(#[from] WorkProductManifestError),
    #[error("a work product revision already has an adoption decision")]
    AdoptionDecisionConflict,
    #[error("work product handoff contains duplicate outcome link")]
    DuplicateOutcomeLink,
    #[error("work product handoff lineage does not match the exact revision")]
    LineageMismatch,
    #[error("an outcome link requires an adopted work product revision")]
    OutcomeRequiresAdoption,
    #[error("the referenced work product revision does not exist")]
    UnknownWorkProductRevision,
    #[error("the adoptable-result plugin service is invalid")]
    InvalidAdoptionPlugin,
    #[error("the adoption scope is not an exact verified Work Product and Outcome handoff")]
    InvalidAdoptionScope,
    #[error("the adoption mount request is invalid")]
    InvalidAdoptionMount,
    #[error("the adoption receipt is invalid or not revision-bound")]
    InvalidAdoptionReceipt,
    #[error("the persisted adoption plugin state is invalid or tampered")]
    InvalidAdoptionState,
    #[error("the exact Work Product revision has no adopted independently verified Outcome")]
    AdoptionUnavailable,
    #[error("the adoption plugin lifecycle does not permit this operation")]
    AdoptionLifecycleConflict,
    #[error("the adoption operation replay does not match its original digest")]
    AdoptionReplayMismatch,
    #[error("the adoption consumer is not the exact mounted Mission consumer")]
    AdoptionConsumerMismatch,
    #[error("the adoption operation is bound to a stale or different mount")]
    AdoptionMountMismatch,
    #[error("the adoption plugin was revoked and cannot be remounted")]
    AdoptionPluginRevoked,
}

fn same_scope(
    tenant_id: &TenantId,
    project_id: &ProjectId,
    mission_id: &MissionId,
    expected_tenant_id: &TenantId,
    expected_project_id: &ProjectId,
    expected_mission_id: &MissionId,
) -> bool {
    tenant_id == expected_tenant_id
        && project_id == expected_project_id
        && mission_id == expected_mission_id
}

fn valid_reference(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn valid_id(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn work_product_digest(title: &str, content: &str) -> String {
    sha256(format!("{title}\n{content}").as_bytes())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, WorkProductOutcomeError> {
    let canonical = serde_json::to_vec(value).map_err(WorkProductOutcomeError::Serialization)?;
    Ok(sha256(&canonical))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 10, 0, 0)
            .single()
            .expect("valid time")
    }

    fn packet() -> ResultPacket {
        ResultPacket::new(
            "packet-1",
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            MissionId::from("mission-1"),
            4,
            "source://packet-1",
            "runtime://turn-1",
            Some("provider://model-1".into()),
            "Adoptable result",
            "A bounded result",
            ResultClassification::ReadyForReview,
            vec![],
            now(),
            now(),
        )
        .expect("packet")
    }

    #[test]
    fn snapshot_digest_rejects_preview_tamper() {
        let packet = packet();
        let revision = WorkProductRevision::from_packet(
            &packet,
            WorkProductId::from("work-product-1"),
            1,
            now(),
        )
        .expect("revision");
        let snapshot = WorkProductHandoffSnapshot::new(packet, revision).expect("snapshot");
        let mut preview = snapshot.to_preview().expect("preview");
        preview.text.push('x');
        assert!(matches!(
            WorkProductHandoffSnapshot::from_preview(&preview),
            Err(WorkProductOutcomeError::Manifest(
                WorkProductManifestError::InvalidPreview
            ))
        ));
    }

    #[test]
    fn outcome_link_rejects_runtime_completion_source() {
        let packet = packet();
        let error = OutcomeLink::new(
            "link-1",
            packet.tenant_id,
            packet.project_id,
            packet.mission_id,
            packet.mission_revision,
            WorkProductId::from("work-product-1"),
            1,
            packet.packet_digest,
            OutcomeVerificationKind::IndependentProvider,
            "runtime://completion",
            "provider-event://1",
            OutcomeClassification::Positive,
            "a".repeat(64),
            "b".repeat(64),
            now(),
        );
        assert!(matches!(
            error,
            Err(WorkProductOutcomeError::InvalidOutcomeLink)
        ));
    }

    #[test]
    fn snapshot_requires_unique_packet_lineage_and_exact_work_product_id() {
        let packet = packet();
        let first = WorkProductRevision::from_packet(
            &packet,
            WorkProductId::from("work-product-1"),
            1,
            now(),
        )
        .expect("first revision");
        let mut snapshot =
            WorkProductHandoffSnapshot::new(packet.clone(), first).expect("snapshot");
        let mut second_packet = packet;
        second_packet.packet_id = "packet-1".into();
        second_packet.packet_digest = second_packet.calculate_digest().expect("digest");
        let second = WorkProductRevision::from_packet(
            &second_packet,
            WorkProductId::from("other-work-product"),
            2,
            now(),
        )
        .expect("second revision");
        assert!(matches!(
            snapshot.append_revision(second),
            Err(WorkProductOutcomeError::InvalidWorkProductRevision)
        ));
    }

    fn verified_snapshot() -> WorkProductHandoffSnapshot {
        let packet = packet();
        let revision = WorkProductRevision::from_packet(
            &packet,
            WorkProductId::from("work-product-1"),
            1,
            now(),
        )
        .expect("revision");
        let mut snapshot =
            WorkProductHandoffSnapshot::new(packet.clone(), revision).expect("snapshot");
        snapshot
            .append_adoption_decision(
                AdoptionDecision::new(
                    "decision-1",
                    packet.tenant_id.clone(),
                    packet.project_id.clone(),
                    packet.mission_id.clone(),
                    packet.mission_revision,
                    WorkProductId::from("work-product-1"),
                    1,
                    packet.packet_digest.clone(),
                    AdoptionDecisionKind::Adopt,
                    "bounded adoption",
                    now(),
                )
                .expect("decision"),
            )
            .expect("adoption");
        snapshot
            .append_outcome_link(
                OutcomeLink::new(
                    "outcome-link-1",
                    packet.tenant_id,
                    packet.project_id,
                    packet.mission_id,
                    packet.mission_revision,
                    WorkProductId::from("work-product-1"),
                    1,
                    packet.packet_digest,
                    OutcomeVerificationKind::IndependentProvider,
                    "provider://independent-1",
                    "outcome://event-1",
                    OutcomeClassification::Positive,
                    "c".repeat(64),
                    "d".repeat(64),
                    now(),
                )
                .expect("outcome link"),
            )
            .expect("outcome");
        snapshot
    }

    #[test]
    fn adoption_provider_and_consumer_require_the_exact_mount_lifecycle() {
        let snapshot = verified_snapshot();
        let scope = WorkProductAdoptionScope::from_verified_handoff(
            &snapshot,
            &TenantId::from("tenant-1"),
            &ProjectId::from("project-1"),
            &MissionId::from("mission-1"),
            5,
            1,
        )
        .expect("scope");
        let service =
            WorkProductAdoptionPluginService::new("provider://adoption-1").expect("service");
        let mount = service
            .mount_request(scope, "mission-consumer-1", 1, now())
            .expect("mount");
        let provider =
            WorkProductAdoptionProvider::mount(service, mount.clone()).expect("provider");
        let consumer = MissionWorkProductAdoptionConsumer::new("mission-consumer-1", &mount)
            .expect("consumer");
        let receipt = consumer
            .adopt(&provider, "receipt-1", now())
            .expect("receipt");
        assert_eq!(receipt.work_product_revision, 1);

        let unmounted = provider
            .transition(WorkProductAdoptionLifecycle::Unmounted)
            .expect("unmount");
        assert!(matches!(
            consumer.adopt(&unmounted, "receipt-2", now()),
            Err(WorkProductOutcomeError::AdoptionLifecycleConflict)
        ));
        let stale_consumer = consumer
            .transition(WorkProductAdoptionLifecycle::Unmounted)
            .expect("consumer unmount");
        assert!(matches!(
            stale_consumer.adopt(&provider, "receipt-3", now()),
            Err(WorkProductOutcomeError::AdoptionLifecycleConflict)
        ));
    }

    #[test]
    fn adoption_scope_rejects_a_result_without_independent_outcome_verification() {
        let packet = packet();
        let revision = WorkProductRevision::from_packet(
            &packet,
            WorkProductId::from("work-product-1"),
            1,
            now(),
        )
        .expect("revision");
        let mut snapshot = WorkProductHandoffSnapshot::new(packet, revision).expect("snapshot");
        snapshot
            .append_adoption_decision(
                AdoptionDecision::new(
                    "decision-1",
                    TenantId::from("tenant-1"),
                    ProjectId::from("project-1"),
                    MissionId::from("mission-1"),
                    4,
                    WorkProductId::from("work-product-1"),
                    1,
                    snapshot.packet.packet_digest.clone(),
                    AdoptionDecisionKind::Adopt,
                    "adopt packet only",
                    now(),
                )
                .expect("decision"),
            )
            .expect("adoption");
        assert!(matches!(
            WorkProductAdoptionScope::from_verified_handoff(
                &snapshot,
                &TenantId::from("tenant-1"),
                &ProjectId::from("project-1"),
                &MissionId::from("mission-1"),
                5,
                1,
            ),
            Err(WorkProductOutcomeError::AdoptionUnavailable)
        ));
    }
}
