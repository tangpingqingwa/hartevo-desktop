use std::collections::BTreeSet;
use std::env;

use hartevo_application::{
    DesktopInventoryProjection, DesktopProjectProjection, MissionConversationMessageProjection,
    MissionProjection, ProjectEncryptionReadiness, WorkProductProjection,
};
use hartevo_catalog::{EvidenceLevel, MissionEvidenceStatus};
use hartevo_domain_kernel::{
    MissionCheckpointCompletionPolicy, MissionCheckpointExecutor, MissionCheckpointStatus,
    MissionConversationId, MissionConversationMessageId, MissionConversationMessageKind,
    MissionConversationRole, MissionId, MissionStage, ProjectEncryptionMode, ProjectId,
    RuntimeTurnStatus, StorageMode, TenantId, WorkProductId, WorkProductStatus,
};
use hartevo_storage::RuntimeTurnStartupReconciliation;
use serde::Deserialize;

use crate::data_plane::{
    DesktopRuntimeTextItemProjection, DesktopRuntimeTextStreamProjection, DesktopSnapshot,
    MissionContractEvidenceProjection, ProductEvidenceProjection, ProjectContextAccessProjection,
    ProjectContextAccessStatus,
};
use crate::{
    DesktopBackendState, DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection,
    DesktopUiModel, Surface, VisualRuntimeFixtureState,
};

const SCENARIO_ENV: &str = "HARTEVO_DESKTOP_UI_SCENARIO";
const SURFACE_ENV: &str = "HARTEVO_DESKTOP_UI_SURFACE";
const RUNTIME_STATE_ENV: &str = "HARTEVO_DESKTOP_UI_RUNTIME_STATE";
const PROTOTYPE_SCENARIO_ID: &str = "prototype-baseline-v1";
const PROTOTYPE_SCENARIO: &str = include_str!("../fixtures/prototype-baseline.v1.json");

impl VisualRuntimeFixtureState {
    const fn environment_value(self) -> &'static str {
        match self {
            Self::Awaiting => "awaiting",
            Self::FirstAppend => "first-append",
            Self::RunningCaughtUp => "running-caught-up",
            Self::TerminalBeforeAck => "terminal-before-ack",
            Self::FinalCaughtUp => "final-caught-up",
            Self::ErrorRetained => "error-retained",
            Self::OffscreenReselect => "offscreen-reselect",
        }
    }

    fn for_request(
        surface: Option<&str>,
        requested_state: Option<&str>,
    ) -> Result<Option<Self>, VisualRuntimeFixtureStateRequestError> {
        if surface != Some("mission-persisted-stream") {
            return if requested_state.is_some() {
                Err(VisualRuntimeFixtureStateRequestError::IncompatibleSurface)
            } else {
                Ok(None)
            };
        }
        let value = requested_state.unwrap_or("first-append");
        Self::ALL
            .into_iter()
            .find(|state| state.environment_value() == value)
            .map(Some)
            .ok_or(VisualRuntimeFixtureStateRequestError::UnsupportedState)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisualRuntimeFixtureStateRequestError {
    IncompatibleSurface,
    UnsupportedState,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct VisualRuntimeFailure {
    pub(super) code: &'static str,
    pub(super) message: &'static str,
}

#[derive(Clone)]
pub(super) struct VisualRuntimeFixture {
    pub(super) state: VisualRuntimeFixtureState,
    pub(super) scope: Option<(ProjectId, MissionId)>,
    pub(super) stream: Option<DesktopRuntimeTextStreamProjection>,
    pub(super) error: Option<VisualRuntimeFailure>,
}

#[derive(Clone, Copy)]
struct VisualRuntimeStreamSpec {
    turn_status: RuntimeTurnStatus,
    turn_revision: u64,
    delta_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VisualFixtureDefinition {
    scenario_id: String,
    source: String,
    disclosure: String,
    project: VisualProject,
    #[serde(default)]
    related_projects: Vec<VisualProject>,
    missions: Vec<VisualMission>,
    catalog: Vec<(String, String, String)>,
    presentation: VisualPresentation,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VisualProject {
    project_id: String,
    name: String,
    description: String,
    revision: u64,
    workspace_root_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
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

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualPresentation {
    pub(super) notifications: Vec<VisualNotification>,
    pub(super) conversation: VisualConversation,
    pub(super) approval: VisualApproval,
    pub(super) outcome: VisualOutcome,
    pub(super) workpad: VisualWorkpad,
    pub(super) pages: Vec<VisualPage>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualNotification {
    pub(super) mark: String,
    pub(super) title: String,
    pub(super) context: String,
    pub(super) time: String,
    pub(super) kind: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualConversation {
    pub(super) user_prompt: String,
    pub(super) assistant_intro: String,
    pub(super) goal: String,
    pub(super) automatic: String,
    pub(super) approval: String,
    pub(super) progress: Vec<VisualProgress>,
    pub(super) capability_summary: String,
    pub(super) connection_title: String,
    pub(super) connection_detail: String,
    pub(super) artifact_title: String,
    pub(super) artifact_meta: String,
    pub(super) decision: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualProgress {
    pub(super) title: String,
    pub(super) detail: String,
    pub(super) capability: String,
    pub(super) state: String,
    pub(super) time: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualApproval {
    pub(super) user_prompt: String,
    pub(super) assistant_intro: String,
    pub(super) effects: Vec<VisualRow>,
    pub(super) facts: Vec<VisualRow>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualOutcome {
    pub(super) intro: String,
    pub(super) metrics: Vec<VisualMetric>,
    pub(super) rows: Vec<VisualRow>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualWorkpad {
    pub(super) tabs: Vec<String>,
    pub(super) eyebrow: String,
    pub(super) title: String,
    pub(super) meta: String,
    pub(super) conclusion: String,
    pub(super) phases: Vec<String>,
    pub(super) candidates: Vec<VisualRow>,
    pub(super) sources: Vec<VisualRow>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualPage {
    pub(super) id: String,
    pub(super) stats: Vec<VisualMetric>,
    pub(super) tabs: Vec<VisualPageTab>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualMetric {
    pub(super) value: String,
    pub(super) label: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualPageTab {
    pub(super) id: String,
    pub(super) label: String,
    pub(super) kind: String,
    pub(super) headline: String,
    pub(super) subline: String,
    pub(super) columns: Vec<String>,
    pub(super) rows: Vec<VisualRow>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(super) struct VisualRow {
    pub(super) title: String,
    pub(super) detail: String,
    pub(super) meta: String,
    pub(super) state: String,
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
    let requested_surface = requested_surface_id();
    let conversation = definition.presentation.conversation.clone();
    let missions = definition
        .missions
        .into_iter()
        .map(|mission| {
            let mut projection = mission_projection(&project_id, mission);
            if requested_surface.as_deref() == Some("mission-persisted-stream")
                && projection.manifest_id.as_deref() == Some("VM-07")
            {
                projection.conversation_messages = vec![fixture_user_message(&conversation)];
            }
            projection
        })
        .collect::<Vec<_>>();
    let selected_mission_id = selected_fixture_mission_id(&missions);
    let project = fixture_project_projection(project_id.clone(), definition.project, missions);
    let mut projects = vec![project];
    projects.extend(definition.related_projects.into_iter().map(|related| {
        let related_id = ProjectId::from(related.project_id.as_str());
        fixture_project_projection(related_id, related, Vec::new())
    }));
    let evidence = fixture_evidence_projection(
        &definition.scenario_id,
        &definition.source,
        definition.catalog,
    );
    let snapshot = fixture_snapshot(project_id.clone(), projects, evidence);

    Some(DesktopUiModel {
        backend: DesktopBackendState::Ready(Box::new(snapshot)),
        selected_project_id: Some(project_id),
        selected_mission_id,
        notice: None,
    })
}

pub(super) fn presentation() -> Option<VisualPresentation> {
    active_id()?;
    let definition: VisualFixtureDefinition = serde_json::from_str(PROTOTYPE_SCENARIO)
        .expect("checked-in prototype visual fixture must deserialize");
    Some(definition.presentation)
}

pub(super) fn page(page_id: &str) -> Option<VisualPage> {
    presentation()?
        .pages
        .into_iter()
        .find(|page| page.id == page_id)
}

pub(super) fn runtime_fixture() -> Option<VisualRuntimeFixture> {
    active_id()?;
    let requested_surface = requested_surface_id();
    let requested_state = env::var(RUNTIME_STATE_ENV).ok();
    let state = VisualRuntimeFixtureState::for_request(
        requested_surface.as_deref(),
        requested_state.as_deref(),
    )
    .unwrap_or_else(|error| panic!("invalid visual Runtime state request: {error:?}"))?;
    Some(runtime_fixture_for_state(state))
}

pub(super) fn runtime_fixture_for_state(state: VisualRuntimeFixtureState) -> VisualRuntimeFixture {
    let definition: VisualFixtureDefinition = serde_json::from_str(PROTOTYPE_SCENARIO)
        .expect("checked-in prototype visual fixture must deserialize");
    let selected_mission = definition
        .missions
        .iter()
        .find(|mission| mission.manifest_id == "VM-07")
        .expect("fixture must include VM-07 selected Mission");
    let offscreen_mission = definition
        .missions
        .iter()
        .find(|mission| mission.manifest_id == "VM-03")
        .expect("fixture must include a distinct offscreen Mission");
    let project_id = ProjectId::from(definition.project.project_id.as_str());
    let selected_mission_id = MissionId::from(selected_mission.mission_id.as_str());
    let stream_mission_id = if state == VisualRuntimeFixtureState::OffscreenReselect {
        MissionId::from(offscreen_mission.mission_id.as_str())
    } else {
        selected_mission_id.clone()
    };
    let observed_at = "2026-08-12T10:21:00Z"
        .parse()
        .expect("fixed visual fixture timestamp");
    let text = definition
        .presentation
        .conversation
        .assistant_intro
        .as_str();
    let stream = runtime_stream_for_state(
        state,
        project_id.clone(),
        stream_mission_id,
        text,
        observed_at,
    );
    let scope = stream.as_ref().map_or_else(
        || Some((project_id, selected_mission_id)),
        |projection| Some((projection.project_id.clone(), projection.mission_id.clone())),
    );
    VisualRuntimeFixture {
        state,
        scope,
        stream,
        error: (state == VisualRuntimeFixtureState::ErrorRetained).then_some(
            VisualRuntimeFailure {
                code: "RUNTIME_EXECUTION_FAILED",
                message: "Runtime 返回失败终态；已持久正文仍可审阅，当前状态不构成 Mission 完成或 Provider 结果。",
            },
        ),
    }
}

fn runtime_stream_for_state(
    state: VisualRuntimeFixtureState,
    project_id: ProjectId,
    mission_id: MissionId,
    text: &str,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> Option<DesktopRuntimeTextStreamProjection> {
    let spec = match state {
        VisualRuntimeFixtureState::Awaiting => None,
        VisualRuntimeFixtureState::FirstAppend => Some(VisualRuntimeStreamSpec {
            turn_status: RuntimeTurnStatus::Running,
            turn_revision: 1,
            delta_count: 1,
        }),
        VisualRuntimeFixtureState::RunningCaughtUp => Some(VisualRuntimeStreamSpec {
            turn_status: RuntimeTurnStatus::Running,
            turn_revision: 4,
            delta_count: 12,
        }),
        VisualRuntimeFixtureState::TerminalBeforeAck | VisualRuntimeFixtureState::FinalCaughtUp => {
            Some(VisualRuntimeStreamSpec {
                turn_status: RuntimeTurnStatus::Completed,
                turn_revision: 5,
                delta_count: 13,
            })
        }
        VisualRuntimeFixtureState::ErrorRetained => Some(VisualRuntimeStreamSpec {
            turn_status: RuntimeTurnStatus::Failed,
            turn_revision: 5,
            delta_count: 12,
        }),
        VisualRuntimeFixtureState::OffscreenReselect => Some(VisualRuntimeStreamSpec {
            turn_status: RuntimeTurnStatus::Running,
            turn_revision: 4,
            delta_count: 7,
        }),
    };
    spec.map(|spec| {
        runtime_stream_projection(project_id, mission_id, state, spec, text, observed_at)
    })
}

fn runtime_stream_projection(
    project_id: ProjectId,
    mission_id: MissionId,
    state: VisualRuntimeFixtureState,
    spec: VisualRuntimeStreamSpec,
    text: &str,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> DesktopRuntimeTextStreamProjection {
    DesktopRuntimeTextStreamProjection {
        project_id,
        mission_id,
        worker_generation: 1,
        turn_revision: spec.turn_revision,
        turn_status: spec.turn_status,
        last_evidence_sequence: Some(
            u64::try_from(spec.delta_count).expect("visual delta count fits u64"),
        ),
        delta_count: spec.delta_count,
        items: vec![DesktopRuntimeTextItemProjection {
            item_id_digest: format!("visual-fixture-runtime-item-{}", state.environment_value()),
            cumulative_byte_count: text.len() as u64,
            text: text.to_owned(),
            delta_count: spec.delta_count,
            last_stream_sequence: u64::try_from(spec.delta_count)
                .expect("visual delta count fits u64"),
            observed_at,
        }],
        updated_at: observed_at,
    }
}

fn fixture_user_message(conversation: &VisualConversation) -> MissionConversationMessageProjection {
    MissionConversationMessageProjection {
        message_id: MissionConversationMessageId::from("visual-fixture-user-message"),
        sequence: 1,
        role: MissionConversationRole::User,
        kind: MissionConversationMessageKind::Goal,
        body: conversation.user_prompt.clone(),
        content_digest: "visual-fixture-user-message-digest".into(),
        mission_revision: 1,
        checkpoint_id: None,
        work_product_id: None,
        recorded_at: "2026-08-12T10:21:00Z"
            .parse()
            .expect("fixed visual fixture timestamp"),
    }
}

fn selected_fixture_mission_id(missions: &[MissionProjection]) -> Option<MissionId> {
    let requested_surface = requested_surface_id();
    let selected_manifest_id = match requested_surface.as_deref() {
        Some(
            "mission-conversation"
            | "mission-streaming"
            | "mission-persisted-stream"
            | "mission-workpad"
            | "mission-inspector",
        ) => Some("VM-07"),
        Some("mission-approval" | "mission-outcome") => Some("VM-03"),
        _ => match initial_surface() {
            Some(Surface::ChannelOperations) => Some("VM-04"),
            Some(Surface::Relationships) => Some("VM-05"),
            Some(Surface::Outcomes) => Some("VM-01"),
            _ => None,
        },
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
    projects: Vec<DesktopProjectProjection>,
    evidence: ProductEvidenceProjection,
) -> DesktopSnapshot {
    DesktopSnapshot {
        inventory: DesktopInventoryProjection { projects },
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

pub(super) fn active_surface_variant() -> Option<String> {
    active_id()?;
    requested_surface_id()
}

fn requested_surface_id() -> Option<String> {
    env::var(SURFACE_ENV).ok()
}

pub(super) fn initial_surface() -> Option<Surface> {
    active_id()?;
    Some(match env::var(SURFACE_ENV).ok().as_deref() {
        None
        | Some(
            "orchestrator"
            | "mission-conversation"
            | "mission-streaming"
            | "mission-persisted-stream"
            | "mission-workpad"
            | "mission-inspector"
            | "mission-approval"
            | "mission-outcome",
        ) => Surface::Orchestrator,
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
        browser_workspace: None,
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
        pending_effects: Vec::new(),
        verified_effect_count: 0,
        outcome_summary: None,
        vm11_outcome_review: None,
        creator_work: None,
        relationship_conversation: None,
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

    fn stream_matches_scope(fixture: &VisualRuntimeFixture) -> bool {
        match (&fixture.stream, &fixture.scope) {
            (Some(stream), Some((project_id, mission_id))) => {
                stream.project_id == *project_id && stream.mission_id == *mission_id
            }
            (None, Some(_)) => fixture.state == VisualRuntimeFixtureState::Awaiting,
            (Some(_) | None, None) => false,
        }
    }

    #[test]
    fn checked_in_fixture_is_explicit_and_never_claims_release_success() {
        let fixture: VisualFixtureDefinition =
            serde_json::from_str(PROTOTYPE_SCENARIO).expect("fixture");
        assert_eq!(fixture.scenario_id, PROTOTYPE_SCENARIO_ID);
        assert_eq!(fixture.disclosure, "VISUAL_FIXTURE");
        assert_eq!(fixture.catalog.len(), 12);
        assert_eq!(fixture.missions.len(), 7);
        assert_eq!(fixture.related_projects.len(), 3);
        assert_eq!(fixture.presentation.pages.len(), 5);
        assert_eq!(fixture.presentation.notifications.len(), 4);
        let creator_work = fixture
            .presentation
            .pages
            .iter()
            .find(|page| page.id == "partners")
            .and_then(|page| page.tabs.iter().find(|tab| tab.id == "work"))
            .expect("creator work lifecycle fixture");
        assert_eq!(creator_work.kind, "workflow");
        assert_eq!(creator_work.rows.len(), 6);
        assert!(creator_work.rows[0].detail.contains("Reward $300 USD"));
        assert!(creator_work.rows[3].title.contains("Deliverable Upload"));
        assert!(creator_work.rows[4].title.contains("Review / Revision"));
        assert!(creator_work.rows[5].title.contains("Payout Verification"));
        assert!(
            fixture
                .presentation
                .outcome
                .rows
                .iter()
                .all(|row| { !row.state.contains("verified") && !row.state.contains("已付款") })
        );
    }

    #[test]
    fn runtime_state_contract_is_exactly_seven_strict_variants() {
        assert_eq!(VisualRuntimeFixtureState::ALL.len(), 7);
        for state in VisualRuntimeFixtureState::ALL {
            assert_eq!(
                VisualRuntimeFixtureState::for_request(
                    Some("mission-persisted-stream"),
                    Some(state.environment_value()),
                ),
                Ok(Some(state))
            );
        }
        assert_eq!(
            VisualRuntimeFixtureState::for_request(Some("mission-persisted-stream"), None),
            Ok(Some(VisualRuntimeFixtureState::FirstAppend))
        );
        assert_eq!(
            VisualRuntimeFixtureState::for_request(
                Some("mission-persisted-stream"),
                Some("connected-provider-success"),
            ),
            Err(VisualRuntimeFixtureStateRequestError::UnsupportedState)
        );
        assert_eq!(
            VisualRuntimeFixtureState::for_request(Some("mission-conversation"), Some("awaiting")),
            Err(VisualRuntimeFixtureStateRequestError::IncompatibleSurface)
        );
        assert_eq!(
            VisualRuntimeFixtureState::for_request(Some("mission-conversation"), None),
            Ok(None)
        );
    }

    #[test]
    fn runtime_fixture_states_keep_transport_and_business_boundaries_distinct() {
        for state in VisualRuntimeFixtureState::ALL {
            let fixture = runtime_fixture_for_state(state);
            assert_eq!(fixture.state, state);
            assert!(stream_matches_scope(&fixture));
            assert_eq!(
                fixture.error.is_some(),
                state == VisualRuntimeFixtureState::ErrorRetained
            );
        }

        let awaiting = runtime_fixture_for_state(VisualRuntimeFixtureState::Awaiting);
        assert!(awaiting.state.waiting_for_turn());
        assert!(awaiting.state.runtime_busy());
        assert!(awaiting.state.stop_available());
        assert!(!awaiting.state.transport_caught_up());
        assert!(awaiting.stream.is_none());

        let first_append = runtime_fixture_for_state(VisualRuntimeFixtureState::FirstAppend);
        assert!(first_append.state.runtime_busy());
        assert!(!first_append.state.transport_caught_up());
        assert!(first_append.stream.as_ref().is_some_and(|stream| {
            stream.turn_status == RuntimeTurnStatus::Running && stream.delta_count == 1
        }));

        let running_caught_up =
            runtime_fixture_for_state(VisualRuntimeFixtureState::RunningCaughtUp);
        assert!(running_caught_up.state.runtime_busy());
        assert!(running_caught_up.state.transport_caught_up());
        assert!(running_caught_up.stream.as_ref().is_some_and(|stream| {
            stream.turn_status == RuntimeTurnStatus::Running && stream.delta_count == 12
        }));

        let terminal_before_ack =
            runtime_fixture_for_state(VisualRuntimeFixtureState::TerminalBeforeAck);
        assert!(terminal_before_ack.state.runtime_busy());
        assert!(!terminal_before_ack.state.stop_available());
        assert!(!terminal_before_ack.state.transport_caught_up());
        assert!(terminal_before_ack.stream.as_ref().is_some_and(|stream| {
            stream.turn_status == RuntimeTurnStatus::Completed && stream.delta_count == 13
        }));

        let final_caught_up = runtime_fixture_for_state(VisualRuntimeFixtureState::FinalCaughtUp);
        assert!(!final_caught_up.state.runtime_busy());
        assert!(final_caught_up.state.transport_caught_up());
        assert!(final_caught_up.stream.as_ref().is_some_and(|stream| {
            stream.turn_status == RuntimeTurnStatus::Completed && stream.delta_count == 13
        }));

        let error_retained = runtime_fixture_for_state(VisualRuntimeFixtureState::ErrorRetained);
        assert!(!error_retained.state.runtime_busy());
        assert!(error_retained.stream.as_ref().is_some_and(|stream| {
            stream.turn_status == RuntimeTurnStatus::Failed && stream.delta_count == 12
        }));
        assert!(error_retained.error.is_some_and(|failure| {
            failure.code == "RUNTIME_EXECUTION_FAILED"
                && !failure.message.contains("Receipt")
                && !failure.message.contains("Verification")
        }));
    }

    #[test]
    fn offscreen_reselect_keeps_stale_private_projection_scope_distinct() {
        let definition: VisualFixtureDefinition =
            serde_json::from_str(PROTOTYPE_SCENARIO).expect("fixture");
        let selected_mission_id = definition
            .missions
            .iter()
            .find(|mission| mission.manifest_id == "VM-07")
            .map(|mission| MissionId::from(mission.mission_id.as_str()))
            .expect("selected Mission");
        let fixture = runtime_fixture_for_state(VisualRuntimeFixtureState::OffscreenReselect);
        assert!(fixture.state.runtime_busy());
        assert!(fixture.state.transport_caught_up());
        assert!(!fixture.state.follow_latest());
        assert!(fixture.state.has_unseen());
        assert!(fixture.stream.as_ref().is_some_and(|stream| {
            stream.mission_id != selected_mission_id
                && fixture
                    .scope
                    .as_ref()
                    .is_some_and(|(_, mission_id)| mission_id == &stream.mission_id)
        }));
    }
}
