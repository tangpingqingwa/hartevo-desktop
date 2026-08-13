use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    AdoptionDecision, Mission, MissionError, MissionId, MissionStage, OutcomeLink, ProjectId,
    ResultPacket, WORK_PRODUCT_HANDOFF_TYPE, WorkProduct, WorkProductHandoffSnapshot,
    WorkProductId, WorkProductManifest, WorkProductManifestError, WorkProductOutcomeError,
    WorkProductPreview, WorkProductRevision, WorkProductStatus,
};
use hartevo_storage::{PendingEvent, StorageError};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::ApplicationService;

const HANDOFF_EDITABLE_SCOPES: [&str; 3] = ["/title", "/content", "/adoption"];

#[derive(Clone, Debug)]
pub struct AcceptResultPacket {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub packet: ResultPacket,
    pub expected_mission_revision: u64,
}

#[derive(Clone, Debug)]
pub struct ReviseWorkProductResult {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub packet: ResultPacket,
    pub expected_mission_revision: u64,
    pub expected_manifest_version: u64,
}

#[derive(Clone, Debug)]
pub struct DecideWorkProductAdoption {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub decision: AdoptionDecision,
    pub expected_mission_revision: u64,
    pub expected_manifest_version: u64,
}

#[derive(Clone, Debug)]
pub struct LinkVerifiedOutcome {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub link: OutcomeLink,
    pub expected_mission_revision: u64,
    pub expected_manifest_version: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WorkProductOutcomeHandoff {
    pub mission: Mission,
    pub manifest: WorkProductManifest,
    pub work_product: WorkProduct,
    pub snapshot: WorkProductHandoffSnapshot,
    pub replayed: bool,
}

#[derive(Debug, Error)]
pub enum WorkProductOutcomeApplicationError {
    #[error(transparent)]
    Domain(#[from] WorkProductOutcomeError),
    #[error(transparent)]
    Mission(#[from] MissionError),
    #[error(transparent)]
    Manifest(#[from] WorkProductManifestError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("the requested Mission, Project, or Tenant scope does not match the result handoff")]
    ScopeMismatch,
    #[error("Mission revision changed: expected {expected}, actual {actual}")]
    MissionRevisionMismatch { expected: u64, actual: u64 },
    #[error("work product manifest version changed: expected {expected}, actual {actual}")]
    ManifestVersionMismatch { expected: u64, actual: u64 },
    #[error("result packet was observed at a stale Mission revision")]
    ResultPacketMissionRevisionMismatch { expected: u64, actual: u64 },
    #[error("result packet timestamp is later than the transaction timestamp")]
    ResultPacketTimeMismatch,
    #[error("a work product already exists for this handoff; use the revision command")]
    WorkProductAlreadyExists,
    #[error("the result packet id was reused with a different digest or lineage")]
    ReplayMismatch,
    #[error("the requested adoption decision targets a non-current revision")]
    AdoptionDecisionRevisionMismatch,
    #[error("a different adoption decision already exists for this work product revision")]
    AdoptionDecisionConflict,
    #[error("the Mission is not in a state that can accept a work product handoff")]
    MissionStageBlocked,
    #[error("Mission revision overflowed")]
    MissionRevisionOverflow,
    #[error("the current work product and typed handoff snapshot do not match")]
    HandoffTampered,
}

impl ApplicationService {
    #[allow(
        clippy::needless_pass_by_value,
        reason = "typed handoff commands are one-shot Application inputs"
    )]
    pub fn accept_result_packet(
        &mut self,
        command: AcceptResultPacket,
        now: DateTime<Utc>,
    ) -> Result<WorkProductOutcomeHandoff, WorkProductOutcomeApplicationError> {
        command.packet.validate()?;
        let mission = self
            .store
            .load_mission(&command.project_id, &command.mission_id)?;
        validate_packet_scope(
            &command.packet,
            &mission,
            &command.project_id,
            &command.mission_id,
            &command.work_product_id,
        )?;

        match self
            .store
            .load_work_product_manifest(&command.project_id, &command.work_product_id)
        {
            Ok(_) => {
                let state = self.load_work_product_outcome_state(
                    &command.project_id,
                    &command.mission_id,
                    &command.work_product_id,
                )?;
                if state.snapshot.packet.packet_id == command.packet.packet_id {
                    if state.snapshot.packet.packet_digest == command.packet.packet_digest {
                        return Ok(with_replay_flag(state, true));
                    }
                    return Err(WorkProductOutcomeApplicationError::ReplayMismatch);
                }
                return Err(WorkProductOutcomeApplicationError::WorkProductAlreadyExists);
            }
            Err(StorageError::ScopedRecordNotFound { .. }) => {}
            Err(error) => return Err(error.into()),
        }

        require_mission_revision(&mission, command.expected_mission_revision)?;
        require_packet_revision(&command.packet, mission.revision)?;
        require_packet_time(&command.packet, now)?;
        ensure_handoff_stage(&mission)?;

        let expected_mission_revision = mission.revision;
        let mut next_mission = mission;
        next_mission.record_work_product(
            WorkProduct::draft(
                command.work_product_id.clone(),
                command.packet.title.clone(),
                command.packet.content.clone(),
                BTreeSet::new(),
            ),
            now,
        )?;
        let work_product = current_work_product(&next_mission, &command.work_product_id)?;
        let revision = WorkProductRevision::from_packet(
            &command.packet,
            command.work_product_id.clone(),
            work_product.revision,
            now,
        )?;
        let snapshot = WorkProductHandoffSnapshot::new(command.packet.clone(), revision)?;
        let manifest = create_manifest(&next_mission, &work_product, snapshot.to_preview()?, now)?;

        self.store.create_work_product_outcome_atomic(
            &next_mission,
            expected_mission_revision,
            &manifest,
            &result_packet_events(&work_product, &command.packet, &manifest, now),
        )?;
        Ok(WorkProductOutcomeHandoff {
            mission: next_mission,
            manifest,
            work_product,
            snapshot,
            replayed: false,
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "typed handoff commands are one-shot Application inputs"
    )]
    pub fn revise_work_product_result(
        &mut self,
        command: ReviseWorkProductResult,
        now: DateTime<Utc>,
    ) -> Result<WorkProductOutcomeHandoff, WorkProductOutcomeApplicationError> {
        command.packet.validate()?;
        let state = self.load_work_product_outcome_state(
            &command.project_id,
            &command.mission_id,
            &command.work_product_id,
        )?;
        validate_packet_scope(
            &command.packet,
            &state.mission,
            &command.project_id,
            &command.mission_id,
            &command.work_product_id,
        )?;
        if let Some(existing) = state
            .snapshot
            .revisions
            .iter()
            .find(|revision| revision.packet_id == command.packet.packet_id)
        {
            if existing.packet_digest == command.packet.packet_digest {
                return Ok(with_replay_flag(state, true));
            }
            return Err(WorkProductOutcomeApplicationError::ReplayMismatch);
        }

        require_mission_revision(&state.mission, command.expected_mission_revision)?;
        require_manifest_version(&state.manifest, command.expected_manifest_version)?;
        require_packet_revision(&command.packet, state.mission.revision)?;
        require_packet_time(&command.packet, now)?;
        ensure_handoff_stage(&state.mission)?;

        let expected_mission_revision = state.mission.revision;
        let previous = state.work_product.clone();
        let revised = previous.revise_content(
            command.packet.title.clone(),
            command.packet.content.clone(),
            BTreeSet::new(),
        )?;
        let mut next_mission = state.mission;
        next_mission.revise_work_product(revised.clone(), now)?;
        let revision = WorkProductRevision::from_packet(
            &command.packet,
            command.work_product_id.clone(),
            revised.revision,
            now,
        )?;
        let mut snapshot = state.snapshot;
        snapshot.append_revision(revision)?;
        let manifest = state.manifest.revise(
            &revised,
            state.manifest.dependencies.clone(),
            state.manifest.file_digest.clone(),
            snapshot.to_preview()?,
            state.manifest.editable_scopes.clone(),
            now,
        )?;
        self.store.revise_work_product_outcome_atomic(
            &next_mission,
            expected_mission_revision,
            &manifest,
            command.expected_manifest_version,
            &[PendingEvent::new(
                "work_product.result_revision.created",
                json!({
                    "workProductId": revised.id,
                    "workProductRevision": revised.revision,
                    "packetId": command.packet.packet_id,
                    "packetDigest": command.packet.packet_digest,
                    "missionRevision": command.packet.mission_revision,
                    "manifestVersion": manifest.version,
                    "manifestDigest": manifest.manifest_digest,
                }),
                now,
            )],
        )?;
        Ok(WorkProductOutcomeHandoff {
            mission: next_mission,
            manifest,
            work_product: revised,
            snapshot,
            replayed: false,
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "typed handoff commands are one-shot Application inputs"
    )]
    pub fn decide_work_product_adoption(
        &mut self,
        command: DecideWorkProductAdoption,
        now: DateTime<Utc>,
    ) -> Result<WorkProductOutcomeHandoff, WorkProductOutcomeApplicationError> {
        command.decision.validate()?;
        let state = self.load_work_product_outcome_state(
            &command.project_id,
            &command.mission_id,
            &command.work_product_id,
        )?;
        validate_decision_scope(&command.decision, &state, &command.work_product_id)?;
        if let Some(existing) = state
            .snapshot
            .adoption_decisions
            .iter()
            .find(|decision| decision.decision_id == command.decision.decision_id)
        {
            if existing.decision_digest == command.decision.decision_digest {
                return Ok(with_replay_flag(state, true));
            }
            return Err(WorkProductOutcomeApplicationError::ReplayMismatch);
        }
        require_mission_revision(&state.mission, command.expected_mission_revision)?;
        require_manifest_version(&state.manifest, command.expected_manifest_version)?;
        if command.decision.mission_revision != state.mission.revision {
            return Err(
                WorkProductOutcomeApplicationError::ResultPacketMissionRevisionMismatch {
                    expected: state.mission.revision,
                    actual: command.decision.mission_revision,
                },
            );
        }
        require_transaction_time(command.decision.decided_at, now)?;
        if command.decision.work_product_revision != state.snapshot.current_revision {
            return Err(WorkProductOutcomeApplicationError::AdoptionDecisionRevisionMismatch);
        }
        if state.snapshot.adoption_decisions.iter().any(|decision| {
            decision.work_product_revision == command.decision.work_product_revision
        }) {
            return Err(WorkProductOutcomeApplicationError::AdoptionDecisionConflict);
        }
        ensure_handoff_stage(&state.mission)?;
        let expected_mission_revision = state.mission.revision;
        let mut snapshot = state.snapshot;
        snapshot.append_adoption_decision(command.decision.clone())?;
        let mut next_mission = state.mission;
        advance_mission_revision(&mut next_mission, now)?;
        let manifest = state.manifest.revise(
            &state.work_product,
            state.manifest.dependencies.clone(),
            state.manifest.file_digest.clone(),
            snapshot.to_preview()?,
            state.manifest.editable_scopes.clone(),
            now,
        )?;
        self.store.revise_work_product_outcome_atomic(
            &next_mission,
            expected_mission_revision,
            &manifest,
            command.expected_manifest_version,
            &[PendingEvent::new(
                "work_product.adoption.decided",
                json!({
                    "decisionId": command.decision.decision_id,
                    "decisionDigest": command.decision.decision_digest,
                    "decision": command.decision.decision,
                    "workProductId": command.work_product_id,
                    "workProductRevision": command.decision.work_product_revision,
                    "packetDigest": command.decision.packet_digest,
                    "missionRevision": command.decision.mission_revision,
                    "manifestVersion": manifest.version,
                    "manifestDigest": manifest.manifest_digest,
                }),
                now,
            )],
        )?;
        Ok(WorkProductOutcomeHandoff {
            mission: next_mission,
            manifest,
            work_product: state.work_product,
            snapshot,
            replayed: false,
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "typed handoff commands are one-shot Application inputs"
    )]
    pub fn link_verified_outcome(
        &mut self,
        command: LinkVerifiedOutcome,
        now: DateTime<Utc>,
    ) -> Result<WorkProductOutcomeHandoff, WorkProductOutcomeApplicationError> {
        command.link.validate()?;
        let state = self.load_work_product_outcome_state(
            &command.project_id,
            &command.mission_id,
            &command.work_product_id,
        )?;
        validate_link_scope(&command.link, &state, &command.work_product_id)?;
        if let Some(existing) = state
            .snapshot
            .outcome_links
            .iter()
            .find(|link| link.link_id == command.link.link_id)
        {
            if existing.link_digest == command.link.link_digest {
                return Ok(with_replay_flag(state, true));
            }
            return Err(WorkProductOutcomeApplicationError::ReplayMismatch);
        }
        require_mission_revision(&state.mission, command.expected_mission_revision)?;
        require_manifest_version(&state.manifest, command.expected_manifest_version)?;
        let linked_revision = state
            .snapshot
            .revision(command.link.work_product_revision)?;
        if command.link.mission_revision != linked_revision.mission_revision {
            return Err(
                WorkProductOutcomeApplicationError::ResultPacketMissionRevisionMismatch {
                    expected: linked_revision.mission_revision,
                    actual: command.link.mission_revision,
                },
            );
        }
        require_transaction_time(command.link.verified_at, now)?;
        ensure_handoff_stage(&state.mission)?;
        let expected_mission_revision = state.mission.revision;
        let mut snapshot = state.snapshot;
        snapshot.append_outcome_link(command.link.clone())?;
        let mut next_mission = state.mission;
        advance_mission_revision(&mut next_mission, now)?;
        let manifest = state.manifest.revise(
            &state.work_product,
            state.manifest.dependencies.clone(),
            state.manifest.file_digest.clone(),
            snapshot.to_preview()?,
            state.manifest.editable_scopes.clone(),
            now,
        )?;
        self.store.revise_work_product_outcome_atomic(
            &next_mission,
            expected_mission_revision,
            &manifest,
            command.expected_manifest_version,
            &[PendingEvent::new(
                "work_product.outcome_link.verified",
                json!({
                    "linkId": command.link.link_id,
                    "linkDigest": command.link.link_digest,
                    "verificationKind": command.link.verification_kind,
                    "providerRefDigest": digest_reference(command.link.provider_ref.as_bytes()),
                    "externalRefDigest": digest_reference(command.link.external_ref.as_bytes()),
                    "workProductId": command.work_product_id,
                    "workProductRevision": command.link.work_product_revision,
                    "packetDigest": command.link.packet_digest,
                    "missionRevision": command.link.mission_revision,
                    "verificationMissionRevision": expected_mission_revision,
                    "manifestVersion": manifest.version,
                    "manifestDigest": manifest.manifest_digest,
                }),
                now,
            )],
        )?;
        Ok(WorkProductOutcomeHandoff {
            mission: next_mission,
            manifest,
            work_product: state.work_product,
            snapshot,
            replayed: false,
        })
    }

    pub fn load_work_product_outcome_handoff(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        work_product_id: &WorkProductId,
    ) -> Result<WorkProductOutcomeHandoff, WorkProductOutcomeApplicationError> {
        self.load_work_product_outcome_state(project_id, mission_id, work_product_id)
    }

    fn load_work_product_outcome_state(
        &self,
        project_id: &ProjectId,
        mission_id: &MissionId,
        work_product_id: &WorkProductId,
    ) -> Result<WorkProductOutcomeHandoff, WorkProductOutcomeApplicationError> {
        let mission = self
            .store
            .load_work_product_outcome_mission(project_id, mission_id)?;
        let manifest = self
            .store
            .load_work_product_manifest(project_id, work_product_id)?;
        if manifest.project_id != *project_id
            || manifest.mission_id != *mission_id
            || manifest.work_product_id != *work_product_id
            || manifest.tenant_id != mission.tenant_id
            || mission.project_id != *project_id
            || mission.id != *mission_id
        {
            return Err(WorkProductOutcomeApplicationError::ScopeMismatch);
        }
        let work_product = current_work_product(&mission, work_product_id)?;
        let snapshot = self
            .store
            .load_work_product_outcome_snapshot(project_id, work_product_id)?;
        if snapshot.revisions.iter().any(|revision| {
            revision.tenant_id != mission.tenant_id
                || revision.project_id != mission.project_id
                || revision.mission_id != mission.id
                || revision.work_product_id != *work_product_id
        }) || snapshot.current_revision != work_product.revision
            || manifest.work_product_revision != work_product.revision
            || manifest.adoption_status != WorkProductStatus::ReadyForReview
        {
            return Err(WorkProductOutcomeApplicationError::HandoffTampered);
        }
        let current_revision = snapshot.revision(snapshot.current_revision)?;
        if current_revision.title != work_product.title
            || current_revision.content != work_product.body
            || current_revision.work_product_content_digest != work_product.content_digest
        {
            return Err(WorkProductOutcomeApplicationError::HandoffTampered);
        }
        Ok(WorkProductOutcomeHandoff {
            mission,
            manifest,
            work_product,
            snapshot,
            replayed: false,
        })
    }
}

fn validate_packet_scope(
    packet: &ResultPacket,
    mission: &Mission,
    project_id: &ProjectId,
    mission_id: &MissionId,
    work_product_id: &WorkProductId,
) -> Result<(), WorkProductOutcomeApplicationError> {
    if packet.tenant_id != mission.tenant_id
        || packet.project_id != *project_id
        || packet.mission_id != *mission_id
        || mission.project_id != *project_id
        || work_product_id.as_str().trim().is_empty()
    {
        return Err(WorkProductOutcomeApplicationError::ScopeMismatch);
    }
    Ok(())
}

fn validate_decision_scope(
    decision: &AdoptionDecision,
    state: &WorkProductOutcomeHandoff,
    work_product_id: &WorkProductId,
) -> Result<(), WorkProductOutcomeApplicationError> {
    if decision.tenant_id != state.mission.tenant_id
        || decision.project_id != state.mission.project_id
        || decision.mission_id != state.mission.id
        || decision.work_product_id != *work_product_id
    {
        return Err(WorkProductOutcomeApplicationError::ScopeMismatch);
    }
    let revision = state.snapshot.revision(decision.work_product_revision)?;
    if revision.packet_digest != decision.packet_digest {
        return Err(WorkProductOutcomeApplicationError::ReplayMismatch);
    }
    Ok(())
}

fn validate_link_scope(
    link: &OutcomeLink,
    state: &WorkProductOutcomeHandoff,
    work_product_id: &WorkProductId,
) -> Result<(), WorkProductOutcomeApplicationError> {
    if link.tenant_id != state.mission.tenant_id
        || link.project_id != state.mission.project_id
        || link.mission_id != state.mission.id
        || link.work_product_id != *work_product_id
    {
        return Err(WorkProductOutcomeApplicationError::ScopeMismatch);
    }
    Ok(())
}

fn require_mission_revision(
    mission: &Mission,
    expected: u64,
) -> Result<(), WorkProductOutcomeApplicationError> {
    if mission.revision != expected {
        return Err(
            WorkProductOutcomeApplicationError::MissionRevisionMismatch {
                expected,
                actual: mission.revision,
            },
        );
    }
    Ok(())
}

fn require_manifest_version(
    manifest: &WorkProductManifest,
    expected: u64,
) -> Result<(), WorkProductOutcomeApplicationError> {
    if manifest.version != expected {
        return Err(
            WorkProductOutcomeApplicationError::ManifestVersionMismatch {
                expected,
                actual: manifest.version,
            },
        );
    }
    Ok(())
}

fn require_packet_revision(
    packet: &ResultPacket,
    mission_revision: u64,
) -> Result<(), WorkProductOutcomeApplicationError> {
    if packet.mission_revision != mission_revision {
        return Err(
            WorkProductOutcomeApplicationError::ResultPacketMissionRevisionMismatch {
                expected: mission_revision,
                actual: packet.mission_revision,
            },
        );
    }
    Ok(())
}

fn require_packet_time(
    packet: &ResultPacket,
    now: DateTime<Utc>,
) -> Result<(), WorkProductOutcomeApplicationError> {
    if now < packet.created_at || now < packet.observed_at {
        return Err(WorkProductOutcomeApplicationError::ResultPacketTimeMismatch);
    }
    Ok(())
}

fn require_transaction_time(
    observed_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), WorkProductOutcomeApplicationError> {
    if now < observed_at {
        return Err(WorkProductOutcomeApplicationError::ResultPacketTimeMismatch);
    }
    Ok(())
}

fn ensure_handoff_stage(mission: &Mission) -> Result<(), WorkProductOutcomeApplicationError> {
    if matches!(
        mission.stage,
        MissionStage::Running
            | MissionStage::WaitingUser
            | MissionStage::WaitingApproval
            | MissionStage::Verifying
    ) {
        Ok(())
    } else {
        Err(WorkProductOutcomeApplicationError::MissionStageBlocked)
    }
}

fn advance_mission_revision(
    mission: &mut Mission,
    now: DateTime<Utc>,
) -> Result<(), WorkProductOutcomeApplicationError> {
    if now < mission.updated_at {
        return Err(WorkProductOutcomeApplicationError::ResultPacketTimeMismatch);
    }
    mission.revision = mission
        .revision
        .checked_add(1)
        .ok_or(WorkProductOutcomeApplicationError::MissionRevisionOverflow)?;
    mission.updated_at = now;
    Ok(())
}

fn current_work_product(
    mission: &Mission,
    work_product_id: &WorkProductId,
) -> Result<WorkProduct, WorkProductOutcomeApplicationError> {
    mission
        .work_products
        .iter()
        .find(|product| product.id == *work_product_id)
        .cloned()
        .ok_or_else(|| MissionError::UnknownWorkProduct(work_product_id.clone()).into())
}

fn create_manifest(
    mission: &Mission,
    work_product: &WorkProduct,
    preview: WorkProductPreview,
    now: DateTime<Utc>,
) -> Result<WorkProductManifest, WorkProductOutcomeApplicationError> {
    Ok(WorkProductManifest::create(
        mission.tenant_id.clone(),
        mission.project_id.clone(),
        mission.id.clone(),
        work_product,
        WORK_PRODUCT_HANDOFF_TYPE,
        hartevo_domain_kernel::WorkProductDependencies {
            fact_ids: BTreeSet::new(),
            evidence_ids: work_product.evidence_ids.clone(),
            task_ids: BTreeSet::new(),
        },
        None,
        preview,
        HANDOFF_EDITABLE_SCOPES
            .into_iter()
            .map(str::to_owned)
            .collect(),
        now,
    )?)
}

fn result_packet_events(
    work_product: &WorkProduct,
    packet: &ResultPacket,
    manifest: &WorkProductManifest,
    now: DateTime<Utc>,
) -> Vec<PendingEvent> {
    vec![
        PendingEvent::new(
            "work_product.result_packet.accepted",
            json!({
                "packetId": packet.packet_id,
                "packetDigest": packet.packet_digest,
                "contentDigest": packet.content_digest,
                "classification": packet.classification,
                "counterevidenceCount": packet.counterevidence.len(),
                "missionRevision": packet.mission_revision,
                "workProductId": work_product.id,
                "workProductRevision": work_product.revision,
                "manifestVersion": manifest.version,
                "manifestDigest": manifest.manifest_digest,
            }),
            now,
        ),
        PendingEvent::new(
            "work_product.result_revision.created",
            json!({
                "packetId": packet.packet_id,
                "packetDigest": packet.packet_digest,
                "workProductId": work_product.id,
                "workProductRevision": work_product.revision,
                "manifestVersion": manifest.version,
            }),
            now,
        ),
    ]
}

fn with_replay_flag(
    mut state: WorkProductOutcomeHandoff,
    replayed: bool,
) -> WorkProductOutcomeHandoff {
    state.replayed = replayed;
    state
}

fn digest_reference(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::{DateTime, TimeZone, Utc};
    use hartevo_domain_kernel::{
        AdoptionDecisionKind, OutcomeClassification, OutcomeVerificationKind, ProjectId,
        ResultClassification, ResultCounterevidence, StorageMode, TaskId, TenantId,
    };
    use hartevo_storage::{DatabaseKey, ProjectStore};
    use tempfile::tempdir;

    use super::*;
    use crate::{CreateProject, StartMission};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 13, 10, 0, 0)
            .single()
            .expect("valid test time")
    }

    fn seeded_service(store: ProjectStore, workspace_root: PathBuf) -> ApplicationService {
        let mut service = ApplicationService::new(store);
        let project_id = ProjectId::from("result-project");
        service
            .create_project(
                CreateProject {
                    tenant_id: TenantId::from("result-tenant"),
                    id: project_id.clone(),
                    name: "Result handoff project".into(),
                    description: "generic result handoff test".into(),
                    workspace_root,
                    storage_mode: StorageMode::LocalNew,
                },
                now(),
            )
            .expect("project");
        service
            .start_mission(
                StartMission {
                    id: MissionId::from("result-mission"),
                    research_task_id: TaskId::from("result-task"),
                    project_id,
                    title: Some("Adoptable user result".into()),
                    prompt: "Produce a reviewable result a user can adopt or revise".into(),
                },
                now() + chrono::Duration::seconds(1),
            )
            .expect("mission");
        service
    }

    fn packet_for(
        mission: &Mission,
        packet_id: &str,
        title: &str,
        content: &str,
        observed_at: DateTime<Utc>,
    ) -> ResultPacket {
        ResultPacket::new(
            packet_id,
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            mission.revision,
            format!("source://result/{packet_id}"),
            format!("runtime://result/{packet_id}"),
            Some(format!("provider://model/{packet_id}")),
            title,
            content,
            ResultClassification::ReadyForReview,
            vec![ResultCounterevidence {
                evidence_ref: format!("counterevidence://{packet_id}"),
                content_digest: "a".repeat(64),
                observed_at,
            }],
            observed_at,
            observed_at,
        )
        .expect("result packet")
    }

    fn adoption_for(
        mission: &Mission,
        product_id: &WorkProductId,
        packet: &ResultPacket,
        decision_id: &str,
        decision: AdoptionDecisionKind,
        decided_at: DateTime<Utc>,
    ) -> AdoptionDecision {
        AdoptionDecision::new(
            decision_id,
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            mission.revision,
            product_id.clone(),
            1,
            packet.packet_digest.clone(),
            decision,
            "User reviewed the exact result revision",
            decided_at,
        )
        .expect("adoption decision")
    }

    fn outcome_link_for(
        mission: &Mission,
        product_id: &WorkProductId,
        packet: &ResultPacket,
        link_id: &str,
        verified_at: DateTime<Utc>,
    ) -> OutcomeLink {
        OutcomeLink::new(
            link_id,
            mission.tenant_id.clone(),
            mission.project_id.clone(),
            mission.id.clone(),
            packet.mission_revision,
            product_id.clone(),
            1,
            packet.packet_digest.clone(),
            OutcomeVerificationKind::IndependentProvider,
            "provider://reconciliation/verified",
            "provider-event://result-1",
            OutcomeClassification::Positive,
            "b".repeat(64),
            "c".repeat(64),
            verified_at,
        )
        .expect("verified outcome link")
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn result_packet_adoption_revision_and_verified_outcome_are_restartable_and_replay_safe() {
        let workspace = tempdir().expect("workspace");
        let mut service = seeded_service(
            ProjectStore::in_memory().expect("store"),
            workspace.path().to_path_buf(),
        );
        let project_id = ProjectId::from("result-project");
        let mission_id = MissionId::from("result-mission");
        let work_product_id = WorkProductId::from("adoptable-result");
        let t1 = now() + chrono::Duration::seconds(2);
        let initial_mission = service
            .load_mission(&project_id, &mission_id)
            .expect("mission");
        let packet = packet_for(
            &initial_mission,
            "packet-1",
            "Reviewable result",
            "A concrete result the user can adopt",
            t1,
        );
        let accepted = service
            .accept_result_packet(
                AcceptResultPacket {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    packet: packet.clone(),
                    expected_mission_revision: initial_mission.revision,
                },
                t1,
            )
            .expect("accepted result");
        assert!(!accepted.replayed);
        assert_eq!(accepted.work_product.revision, 1);
        assert_eq!(accepted.snapshot.current_revision, 1);
        let event_count_after_accept = service
            .mission_events(&project_id, &mission_id)
            .expect("events")
            .len();
        let outbox_count_after_accept = service
            .store
            .outbox_sequences_for_mission(&project_id, &mission_id)
            .expect("outbox");
        assert_eq!(outbox_count_after_accept.len(), event_count_after_accept);

        let t2 = t1 + chrono::Duration::seconds(1);
        let adoption = adoption_for(
            &accepted.mission,
            &work_product_id,
            &packet,
            "decision-1",
            AdoptionDecisionKind::Adopt,
            t2,
        );
        let adopted = service
            .decide_work_product_adoption(
                DecideWorkProductAdoption {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    decision: adoption.clone(),
                    expected_mission_revision: accepted.mission.revision,
                    expected_manifest_version: accepted.manifest.version,
                },
                t2,
            )
            .expect("adopted result");
        assert_eq!(adopted.snapshot.adoption_decisions.len(), 1);
        assert_eq!(
            adopted.work_product.status,
            WorkProductStatus::ReadyForReview
        );

        let t3 = t2 + chrono::Duration::seconds(1);
        let revised_packet = packet_for(
            &adopted.mission,
            "packet-2",
            "Revised reviewable result",
            "A revised result with the user's requested change",
            t3,
        );
        let revised = service
            .revise_work_product_result(
                ReviseWorkProductResult {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    packet: revised_packet,
                    expected_mission_revision: adopted.mission.revision,
                    expected_manifest_version: adopted.manifest.version,
                },
                t3,
            )
            .expect("revised result");
        assert_eq!(revised.work_product.revision, 2);
        assert_eq!(revised.snapshot.current_revision, 2);

        let t4 = t3 + chrono::Duration::seconds(1);
        let link = outcome_link_for(
            &revised.mission,
            &work_product_id,
            &packet,
            "outcome-link-1",
            t4,
        );
        let linked = service
            .link_verified_outcome(
                LinkVerifiedOutcome {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    link: link.clone(),
                    expected_mission_revision: revised.mission.revision,
                    expected_manifest_version: revised.manifest.version,
                },
                t4,
            )
            .expect("independently verified outcome");
        assert_eq!(linked.snapshot.outcome_links.len(), 1);
        assert_eq!(linked.snapshot.outcome_links[0].work_product_revision, 1);
        assert_eq!(
            linked.snapshot.outcome_links[0].packet_digest,
            packet.packet_digest
        );

        let loaded = service
            .load_work_product_outcome_handoff(&project_id, &mission_id, &work_product_id)
            .expect("loaded handoff");
        assert_eq!(loaded.snapshot, linked.snapshot);
        assert_eq!(loaded.work_product, linked.work_product);

        let replayed_accept = service
            .accept_result_packet(
                AcceptResultPacket {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    packet: packet.clone(),
                    expected_mission_revision: initial_mission.revision,
                },
                t1,
            )
            .expect("replayed result");
        assert!(replayed_accept.replayed);
        let replayed_adoption = service
            .decide_work_product_adoption(
                DecideWorkProductAdoption {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    decision: adoption,
                    expected_mission_revision: accepted.mission.revision,
                    expected_manifest_version: accepted.manifest.version,
                },
                t2,
            )
            .expect("replayed adoption");
        assert!(replayed_adoption.replayed);
        let replayed_link = service
            .link_verified_outcome(
                LinkVerifiedOutcome {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    link,
                    expected_mission_revision: revised.mission.revision,
                    expected_manifest_version: revised.manifest.version + 1,
                },
                t4,
            )
            .expect("replayed link");
        assert!(replayed_link.replayed);
        assert_eq!(
            service
                .mission_events(&project_id, &mission_id)
                .expect("events after replay")
                .len(),
            event_count_after_accept + 3
        );
        assert_eq!(
            service
                .store
                .outbox_sequences_for_mission(&project_id, &mission_id)
                .expect("outbox after replay")
                .len(),
            outbox_count_after_accept.len() + 3
        );
        for event in service
            .mission_events(&project_id, &mission_id)
            .expect("final events")
        {
            let payload = event.payload.to_string();
            assert!(!payload.contains("A concrete result the user can adopt"));
            assert!(!payload.contains("A revised result with the user's requested change"));
        }
        for sequence in service
            .store
            .outbox_sequences_for_mission(&project_id, &mission_id)
            .expect("final outbox")
        {
            let payload = service
                .store
                .outbox_message(sequence)
                .expect("outbox message")
                .payload
                .to_string();
            assert!(!payload.contains("A concrete result the user can adopt"));
            assert!(!payload.contains("A revised result with the user's requested change"));
        }

        let workspace_restart = tempdir().expect("restart workspace");
        let database_path = workspace_restart.path().join("handoff.db");
        let mut persistent = seeded_service(
            ProjectStore::open(
                &database_path,
                &DatabaseKey::new([7; 32]).expect("database key"),
            )
            .expect("persistent store"),
            workspace_restart.path().to_path_buf(),
        );
        let persistent_mission = persistent
            .load_mission(&project_id, &mission_id)
            .expect("persistent mission");
        let persistent_packet = packet_for(
            &persistent_mission,
            "persistent-packet",
            "Persistent result",
            "The result survives an application restart",
            t1,
        );
        let persistent_accept = persistent
            .accept_result_packet(
                AcceptResultPacket {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: WorkProductId::from("persistent-result"),
                    packet: persistent_packet,
                    expected_mission_revision: persistent_mission.revision,
                },
                t1,
            )
            .expect("persistent accept");
        let persistent_event_count = persistent
            .mission_events(&project_id, &mission_id)
            .expect("persistent events")
            .len();
        drop(persistent);
        let restarted = ApplicationService::new(
            ProjectStore::open(
                &database_path,
                &DatabaseKey::new([7; 32]).expect("database key"),
            )
            .expect("reopened store"),
        );
        let restarted_state = restarted
            .load_work_product_outcome_handoff(
                &project_id,
                &mission_id,
                &persistent_accept.work_product.id,
            )
            .expect("restarted handoff");
        assert_eq!(restarted_state.snapshot, persistent_accept.snapshot);
        assert_eq!(
            restarted
                .mission_events(&project_id, &mission_id)
                .expect("restarted events")
                .len(),
            persistent_event_count
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the adversarial test keeps stale, scope, digest, and verification fences together"
    )]
    fn stale_cross_project_tampered_and_unverified_inputs_fail_closed_without_growth() {
        let workspace = tempdir().expect("workspace");
        let mut service = seeded_service(
            ProjectStore::in_memory().expect("store"),
            workspace.path().to_path_buf(),
        );
        let project_id = ProjectId::from("result-project");
        let mission_id = MissionId::from("result-mission");
        let work_product_id = WorkProductId::from("adversarial-result");
        let mission = service
            .load_mission(&project_id, &mission_id)
            .expect("mission");
        let observed_at = now() + chrono::Duration::seconds(2);
        let packet = packet_for(
            &mission,
            "adversarial-packet",
            "Result",
            "Safe content",
            observed_at,
        );
        let accepted = service
            .accept_result_packet(
                AcceptResultPacket {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    packet: packet.clone(),
                    expected_mission_revision: mission.revision,
                },
                observed_at,
            )
            .expect("accepted");
        let event_count = service
            .mission_events(&project_id, &mission_id)
            .expect("events")
            .len();

        let unadopted_link = outcome_link_for(
            &accepted.mission,
            &WorkProductId::from("adversarial-result"),
            &packet,
            "unadopted-link",
            observed_at,
        );
        let unadopted = service.link_verified_outcome(
            LinkVerifiedOutcome {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                work_product_id: WorkProductId::from("adversarial-result"),
                link: unadopted_link,
                expected_mission_revision: accepted.mission.revision,
                expected_manifest_version: accepted.manifest.version,
            },
            observed_at,
        );
        assert!(matches!(
            unadopted,
            Err(WorkProductOutcomeApplicationError::Domain(
                WorkProductOutcomeError::OutcomeRequiresAdoption
            ))
        ));
        assert_eq!(
            service
                .mission_events(&project_id, &mission_id)
                .expect("events after unadopted link")
                .len(),
            event_count
        );

        let stale_packet = packet_for(
            &accepted.mission,
            "stale-packet",
            "Stale",
            "Must not write",
            observed_at + chrono::Duration::seconds(1),
        );
        let stale = service.revise_work_product_result(
            ReviseWorkProductResult {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                work_product_id: work_product_id.clone(),
                packet: stale_packet,
                expected_mission_revision: mission.revision,
                expected_manifest_version: accepted.manifest.version,
            },
            observed_at + chrono::Duration::seconds(1),
        );
        assert!(matches!(
            stale,
            Err(WorkProductOutcomeApplicationError::MissionRevisionMismatch { .. })
        ));

        let cross_project_packet = ResultPacket::new(
            "cross-project-packet",
            mission.tenant_id.clone(),
            ProjectId::from("other-project"),
            mission.id.clone(),
            mission.revision,
            "source://cross-project",
            "runtime://cross-project",
            None,
            "Cross project",
            "Must not cross project boundary",
            ResultClassification::ReadyForReview,
            Vec::new(),
            observed_at + chrono::Duration::seconds(2),
            observed_at + chrono::Duration::seconds(2),
        )
        .expect("cross-project packet");
        let cross_project = service.accept_result_packet(
            AcceptResultPacket {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                work_product_id: WorkProductId::from("cross-project-result"),
                packet: cross_project_packet,
                expected_mission_revision: accepted.mission.revision,
            },
            observed_at + chrono::Duration::seconds(2),
        );
        assert!(matches!(
            cross_project,
            Err(WorkProductOutcomeApplicationError::ScopeMismatch)
        ));

        let mut tampered_packet = packet;
        tampered_packet.content.push_str(" tampered");
        let tampered = service.accept_result_packet(
            AcceptResultPacket {
                project_id: project_id.clone(),
                mission_id: mission_id.clone(),
                work_product_id,
                packet: tampered_packet,
                expected_mission_revision: mission.revision,
            },
            observed_at,
        );
        assert!(matches!(
            tampered,
            Err(WorkProductOutcomeApplicationError::Domain(
                WorkProductOutcomeError::InvalidResultPacket
            ))
        ));

        let mut link = outcome_link_for(
            &accepted.mission,
            &WorkProductId::from("adversarial-result"),
            &ResultPacket::new(
                "link-packet",
                accepted.mission.tenant_id.clone(),
                accepted.mission.project_id.clone(),
                accepted.mission.id.clone(),
                accepted.mission.revision,
                "source://link",
                "runtime://link",
                None,
                "Link",
                "Link content",
                ResultClassification::ReadyForReview,
                Vec::new(),
                observed_at,
                observed_at,
            )
            .expect("link packet"),
            "invalid-link",
            observed_at,
        );
        link.link_digest = "d".repeat(64);
        let invalid_link = service.link_verified_outcome(
            LinkVerifiedOutcome {
                project_id: ProjectId::from("result-project"),
                mission_id: MissionId::from("result-mission"),
                work_product_id: WorkProductId::from("adversarial-result"),
                link,
                expected_mission_revision: accepted.mission.revision,
                expected_manifest_version: accepted.manifest.version,
            },
            observed_at,
        );
        assert!(matches!(
            invalid_link,
            Err(WorkProductOutcomeApplicationError::Domain(
                WorkProductOutcomeError::InvalidOutcomeLink
            ))
        ));

        let mut unverified_json = serde_json::to_value(outcome_link_for(
            &accepted.mission,
            &WorkProductId::from("adversarial-result"),
            &packet_for(
                &accepted.mission,
                "typed-link-packet",
                "Typed link",
                "Typed link content",
                observed_at,
            ),
            "typed-link",
            observed_at,
        ))
        .expect("link json");
        unverified_json["verificationKind"] =
            serde_json::Value::String("runtime_completion".into());
        assert!(serde_json::from_value::<OutcomeLink>(unverified_json).is_err());

        assert_eq!(
            service
                .mission_events(&project_id, &mission_id)
                .expect("events")
                .len(),
            event_count
        );
        assert_eq!(
            service
                .store
                .outbox_sequences_for_mission(&project_id, &mission_id)
                .expect("outbox")
                .len(),
            event_count
        );
    }

    #[test]
    fn rejection_is_durable_and_revision_remains_available_without_evidence_mutation() {
        let workspace = tempdir().expect("workspace");
        let mut service = seeded_service(
            ProjectStore::in_memory().expect("store"),
            workspace.path().to_path_buf(),
        );
        let project_id = ProjectId::from("result-project");
        let mission_id = MissionId::from("result-mission");
        let work_product_id = WorkProductId::from("rejected-result");
        let initial = service
            .load_mission(&project_id, &mission_id)
            .expect("mission");
        let result_time = now() + chrono::Duration::seconds(2);
        let packet = packet_for(
            &initial,
            "reject-packet",
            "Result for review",
            "The user may reject this result",
            result_time,
        );
        let accepted = service
            .accept_result_packet(
                AcceptResultPacket {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    packet: packet.clone(),
                    expected_mission_revision: initial.revision,
                },
                result_time,
            )
            .expect("result");
        let source_evidence = accepted.mission.evidence.clone();
        let decision_time = result_time + chrono::Duration::seconds(1);
        let rejected = service
            .decide_work_product_adoption(
                DecideWorkProductAdoption {
                    project_id: project_id.clone(),
                    mission_id: mission_id.clone(),
                    work_product_id: work_product_id.clone(),
                    decision: adoption_for(
                        &accepted.mission,
                        &work_product_id,
                        &packet,
                        "reject-decision",
                        AdoptionDecisionKind::Reject,
                        decision_time,
                    ),
                    expected_mission_revision: accepted.mission.revision,
                    expected_manifest_version: accepted.manifest.version,
                },
                decision_time,
            )
            .expect("rejection");
        assert_eq!(
            rejected.snapshot.adoption_decisions[0].decision,
            AdoptionDecisionKind::Reject
        );
        assert_eq!(
            rejected.work_product.status,
            WorkProductStatus::ReadyForReview
        );
        assert_eq!(rejected.mission.evidence, source_evidence);

        let revised_time = decision_time + chrono::Duration::seconds(1);
        let revised_packet = packet_for(
            &rejected.mission,
            "reject-revision-packet",
            "Revised after rejection",
            "The user can revise a rejected result",
            revised_time,
        );
        let revised = service
            .revise_work_product_result(
                ReviseWorkProductResult {
                    project_id,
                    mission_id,
                    work_product_id,
                    packet: revised_packet,
                    expected_mission_revision: rejected.mission.revision,
                    expected_manifest_version: rejected.manifest.version,
                },
                revised_time,
            )
            .expect("revision after rejection");
        assert_eq!(revised.work_product.revision, 2);
        assert_eq!(revised.mission.evidence, source_evidence);
    }
}
