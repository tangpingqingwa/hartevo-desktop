use std::collections::BTreeSet;
use std::env;

use hartevo_application::{
    DesktopInventoryProjection, DesktopProjectProjection, MissionProjection,
    ProjectEncryptionReadiness, WorkProductProjection,
};
use hartevo_catalog::{EvidenceLevel, MissionEvidenceStatus};
use hartevo_domain_kernel::{
    MissionCheckpointCompletionPolicy, MissionCheckpointExecutor, MissionCheckpointStatus,
    MissionConversationId, MissionId, MissionStage, ProjectEncryptionMode, ProjectId, StorageMode,
    TenantId, WorkProductId, WorkProductStatus,
};
use hartevo_storage::RuntimeTurnStartupReconciliation;
use serde::Deserialize;

use crate::data_plane::{
    DesktopSnapshot, MissionContractEvidenceProjection, ProductEvidenceProjection,
    ProjectContextAccessProjection, ProjectContextAccessStatus,
};
use crate::{
    DesktopBackendState, DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection,
    DesktopUiModel, Surface,
};

const SCENARIO_ENV: &str = "HARTEVO_DESKTOP_UI_SCENARIO";
const SURFACE_ENV: &str = "HARTEVO_DESKTOP_UI_SURFACE";
const PROTOTYPE_SCENARIO_ID: &str = "prototype-baseline-v1";
const PROTOTYPE_SCENARIO: &str = include_str!("../fixtures/prototype-baseline.v1.json");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VisualFixtureDefinition {
    scenario_id: String,
    source: String,
    disclosure: String,
    project: VisualProject,
    missions: Vec<VisualMission>,
    catalog: Vec<(String, String, String)>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VisualProject {
    project_id: String,
    name: String,
    description: String,
    revision: u64,
    workspace_root_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VisualMission {
    mission_id: String,
    title: String,
    goal: String,
    manifest_id: String,
    stage: String,
    checkpoint_id: String,
    completed_checkpoints: usize,
    checkpoint_count: usize,
    cycle: u64,
    pending_approvals: usize,
    work_products: usize,
}

pub(super) fn load_from_environment() -> Option<DesktopUiModel> {
    let requested = env::var(SCENARIO_ENV).ok()?;
    if requested != PROTOTYPE_SCENARIO_ID {
        return None;
    }
    let definition: VisualFixtureDefinition = serde_json::from_str(PROTOTYPE_SCENARIO)
        .expect("checked-in prototype visual fixture must deserialize");
    assert_eq!(definition.scenario_id, requested);
    assert_eq!(definition.disclosure, "VISUAL_FIXTURE");

    let project_id = ProjectId::from(definition.project.project_id.as_str());
    let missions = definition
        .missions
        .into_iter()
        .map(|mission| mission_projection(&project_id, mission))
        .collect::<Vec<_>>();
    let selected_mission_id = selected_fixture_mission_id(&missions);
    let project = fixture_project_projection(project_id.clone(), definition.project, missions);
    let evidence = fixture_evidence_projection(
        &definition.scenario_id,
        &definition.source,
        definition.catalog,
    );
    let snapshot = fixture_snapshot(project_id.clone(), project, evidence);

    Some(DesktopUiModel {
        backend: DesktopBackendState::Ready(Box::new(snapshot)),
        selected_project_id: Some(project_id),
        selected_mission_id,
        notice: None,
    })
}

fn selected_fixture_mission_id(missions: &[MissionProjection]) -> Option<MissionId> {
    let selected_manifest_id = match initial_surface() {
        Some(Surface::ChannelOperations) => Some("VM-04"),
        Some(Surface::Relationships) => Some("VM-05"),
        Some(Surface::Outcomes) => Some("VM-01"),
        _ => None,
    };
    selected_manifest_id.and_then(|manifest_id| {
        missions
            .iter()
            .find(|mission| mission.manifest_id.as_deref() == Some(manifest_id))
            .map(|mission| mission.mission_id.clone())
    })
}

fn fixture_project_projection(
    project_id: ProjectId,
    source: VisualProject,
    missions: Vec<MissionProjection>,
) -> DesktopProjectProjection {
    DesktopProjectProjection {
        tenant_id: TenantId::from("visual-fixture-tenant"),
        project_id,
        name: source.name,
        description: source.description,
        storage_mode: StorageMode::LocalEncryptedSync,
        data_cell: None,
        revision: source.revision,
        workspace_root_count: source.workspace_root_count,
        encryption: ProjectEncryptionReadiness::Ready {
            mode: ProjectEncryptionMode::PersonalE2ee,
            active_key_version: 1,
            keyring_revision: 1,
        },
        missions,
    }
}

fn fixture_evidence_projection(
    scenario_id: &str,
    source: &str,
    catalog: Vec<(String, String, String)>,
) -> ProductEvidenceProjection {
    ProductEvidenceProjection {
        catalog_digest: format!("visual-fixture:{scenario_id}:{source}"),
        release_passed: false,
        missions: catalog
            .into_iter()
            .map(
                |(mission_id, title, mode)| MissionContractEvidenceProjection {
                    mission_id,
                    title,
                    modes: vec![mode],
                    default_cadence: "VISUAL_FIXTURE · not release evidence".into(),
                    evidence_level: EvidenceLevel::E1,
                    status: MissionEvidenceStatus::Partial,
                    failure_count: 0,
                },
            )
            .collect(),
    }
}

fn fixture_snapshot(
    project_id: ProjectId,
    project: DesktopProjectProjection,
    evidence: ProductEvidenceProjection,
) -> DesktopSnapshot {
    DesktopSnapshot {
        inventory: DesktopInventoryProjection {
            projects: vec![project],
        },
        context_access: vec![ProjectContextAccessProjection {
            project_id,
            status: ProjectContextAccessStatus::Ready {
                keyring_revision: 1,
                active_key_version: 1,
                readable_key_versions: vec![1],
            },
        }],
        runtime_reconciliation: RuntimeTurnStartupReconciliation {
            scanned_attempts: 0,
            failed_before_dispatch: 0,
            frozen_uncertain: 0,
            already_safe: 0,
            event_sequences: Vec::new(),
            outbox_sequences: Vec::new(),
        },
        runtime: DesktopRuntimeProjection {
            status: DesktopRuntimeAvailabilityStatus::NotConfigured,
            target: None,
            release: "VISUAL_FIXTURE".into(),
            program_sha256: None,
            provider: None,
            model: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        },
        runtime_activity: Vec::new(),
        product_evidence: evidence,
    }
}

pub(super) fn active_id() -> Option<String> {
    env::var(SCENARIO_ENV)
        .ok()
        .filter(|value| value == PROTOTYPE_SCENARIO_ID)
}

pub(super) fn initial_surface() -> Option<Surface> {
    active_id()?;
    Some(match env::var(SURFACE_ENV).ok().as_deref() {
        None | Some("orchestrator") => Surface::Orchestrator,
        Some("current") => Surface::Current,
        Some("missions") => Surface::Missions,
        Some("channels") => Surface::ChannelOperations,
        Some("relationships") => Surface::Relationships,
        Some("partners") => Surface::Partners,
        Some("connections") => Surface::Connections,
        Some("outcomes") => Surface::Outcomes,
        Some("capability-evidence") => Surface::CapabilityEvidence,
        Some("settings") => Surface::Settings,
        Some("state-coverage") => Surface::StateCoverage,
        Some(value) => panic!("unsupported visual fixture surface: {value}"),
    })
}

fn mission_projection(project_id: &ProjectId, source: VisualMission) -> MissionProjection {
    let mission_id = MissionId::from(source.mission_id.as_str());
    let stage = mission_stage(&source.stage);
    let work_products = (0..source.work_products)
        .map(|index| {
            let id = format!("{}-artifact-{}", source.mission_id, index + 1);
            WorkProductProjection {
            work_product_id: WorkProductId::from(id.as_str()),
            title: format!("{} · 视觉夹具产物 {}", source.title, index + 1),
            work_product_type: "visual_fixture".into(),
            manifest_version: 1,
            work_product_revision: 1,
            preview_media_type: "text/plain".into(),
            preview_text: "VISUAL_FIXTURE：仅用于原型视觉与交互回归，不是 Provider Receipt、Verification 或真实业务成果。".into(),
            preview_digest: format!("visual-fixture-preview-{}", index + 1),
            manifest_digest: format!("visual-fixture-manifest-{}", index + 1),
            adoption_status: WorkProductStatus::Draft,
            editable_scope_count: 1,
            evidence_count: 0,
        }
        })
        .collect::<Vec<_>>();
    MissionProjection {
        surface: "orchestrator".into(),
        project_id: project_id.clone(),
        mission_id: mission_id.clone(),
        title: source.title,
        goal: source.goal,
        manifest_id: Some(source.manifest_id),
        manifest_version: Some(1),
        catalog_digest: Some("visual-fixture-not-release-evidence".into()),
        current_checkpoint_id: Some(source.checkpoint_id),
        current_checkpoint_status: Some(checkpoint_status(&stage)),
        current_checkpoint_revision: Some(1),
        current_checkpoint_capability_id: Some("fixture.read_only_projection".into()),
        current_checkpoint_executor: Some(MissionCheckpointExecutor::Runtime),
        current_checkpoint_application_handler_status: None,
        current_checkpoint_application_handler_id: None,
        current_checkpoint_oracle_ids: BTreeSet::from(["work_product".into()]),
        current_checkpoint_completion_policy: Some(MissionCheckpointCompletionPolicy::WorkProduct),
        completed_checkpoint_count: source.completed_checkpoints,
        checkpoint_count: source.checkpoint_count,
        cycle: source.cycle,
        schedule: None,
        conversation_id: Some({
            let id = format!("conversation-{mission_id}");
            MissionConversationId::from(id.as_str())
        }),
        conversation_revision: Some(1),
        conversation_messages: Vec::new(),
        stage,
        revision: 1,
        evidence_count: 0,
        work_product_count: work_products.len(),
        work_products,
        pending_approval_count: source.pending_approvals,
        verified_effect_count: 0,
        outcome_summary: None,
    }
}

fn mission_stage(value: &str) -> MissionStage {
    match value {
        "running" => MissionStage::Running,
        "waiting_user" => MissionStage::WaitingUser,
        "waiting_approval" => MissionStage::WaitingApproval,
        "scheduled" => MissionStage::Scheduled,
        _ => panic!("unsupported visual fixture stage: {value}"),
    }
}

fn checkpoint_status(stage: &MissionStage) -> MissionCheckpointStatus {
    match stage {
        MissionStage::Running => MissionCheckpointStatus::Running,
        MissionStage::WaitingUser => MissionCheckpointStatus::WaitingUser,
        MissionStage::WaitingApproval => MissionCheckpointStatus::WaitingApproval,
        MissionStage::Scheduled => MissionCheckpointStatus::Ready,
        _ => MissionCheckpointStatus::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_fixture_is_explicit_and_never_claims_release_success() {
        let fixture: VisualFixtureDefinition =
            serde_json::from_str(PROTOTYPE_SCENARIO).expect("fixture");
        assert_eq!(fixture.scenario_id, PROTOTYPE_SCENARIO_ID);
        assert_eq!(fixture.disclosure, "VISUAL_FIXTURE");
        assert_eq!(fixture.catalog.len(), 12);
        assert_eq!(fixture.missions.len(), 7);
    }
}
