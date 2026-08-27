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
}
