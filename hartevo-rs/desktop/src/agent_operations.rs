//! Read-only on-demand Mission plugin surface model for Desktop.
//!
//! OI-01, CAP-01, CTX-01 and BW-01 own the durable control-plane records that
//! will eventually fill these panels.  Until those APIs land, this module
//! projects only existing Application/Desktop facts and represents every
//! unavailable field as an honest typed state.  It has no persistence,
//! runtime loop, browser control, approval authority or Effect path.

use std::fmt;

use hartevo_application::{MissionProjection, MissionRuntimeProjection};
use hartevo_domain_kernel::{
    MissionConversationMessageKind, MissionConversationRole, MissionId, ProjectId,
    RuntimeRecoveryStatus, RuntimeTurnStatus, WorkProductStatus,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationsStatus {
    Ready,
    Active,
    Empty,
    WaitingUser,
    RecoveryRequired,
    Failed,
}

impl OperationsStatus {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Active => "RUNNING",
            Self::Empty => "EMPTY",
            Self::WaitingUser => "WAITING_USER",
            Self::RecoveryRequired => "RECOVERY_REQUIRED",
            Self::Failed => "FAILED",
        }
    }

    pub const fn tone(self) -> &'static str {
        match self {
            Self::Ready | Self::Active => "ready",
            Self::Empty => "empty",
            Self::WaitingUser => "attention",
            Self::RecoveryRequired | Self::Failed => "blocked",
        }
    }

    pub const fn is_actionable(self) -> bool {
        matches!(self, Self::Ready | Self::Active | Self::WaitingUser)
    }
}

/// Content-free optimistic-concurrency material held by the Desktop command
/// surface. It intentionally carries revisions only; Mission/Project IDs stay
/// in the selected read model and are never rendered as implementation IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationsRevisionFence {
    pub mission: u64,
    pub checkpoint: Option<u64>,
    pub conversation: Option<u64>,
}

impl OperationsRevisionFence {
    pub fn from_mission(mission: &MissionProjection) -> Self {
        Self {
            mission: mission.revision,
            checkpoint: mission.current_checkpoint_revision,
            conversation: mission.conversation_revision,
        }
    }

    pub fn matches_mission(self, mission: &MissionProjection) -> bool {
        self == Self::from_mission(mission)
    }

    pub fn label(self) -> String {
        format!(
            "Mission r{} · Checkpoint {} · Conversation {}",
            self.mission,
            self.checkpoint
                .map_or_else(|| "—".into(), |revision| format!("r{revision}")),
            self.conversation
                .map_or_else(|| "—".into(), |revision| format!("r{revision}")),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionSurfaceProjection {
    pub status: OperationsStatus,
    pub gate: String,
    pub transport: String,
    pub revision_fence: OperationsRevisionFence,
    pub stop_available: bool,
    pub stop_requested: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResultSurfaceProjection {
    pub title: String,
    pub kind: String,
    pub revision: String,
    pub lineage: String,
    pub preview: String,
    pub status: OperationsStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionPluginNodeKind {
    Invocation,
    Result,
}

impl MissionPluginNodeKind {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invocation => "TOOL_INVOCATION",
            Self::Result => "TOOL_RESULT",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Invocation => "Execution",
            Self::Result => "Result",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionPluginNodeStatus {
    Awaiting,
    Running,
    Completed,
    Failed,
    Uncertain,
}

impl MissionPluginNodeStatus {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Awaiting => "AWAITING",
            Self::Running => "RUNNING",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Uncertain => "UNCERTAIN",
        }
    }

    pub const fn tone(self) -> &'static str {
        match self {
            Self::Awaiting => "attention",
            Self::Running | Self::Completed => "ready",
            Self::Failed | Self::Uncertain => "blocked",
        }
    }
}

/// Content-free token for opening an inline plugin detail. It carries exact
/// scope and persisted revisions so a reselect cannot reveal the old Mission's
/// private Conversation body.
#[derive(Clone, Eq, PartialEq)]
pub struct MissionPluginNodeSelection {
    project_id: ProjectId,
    mission_id: MissionId,
    sequence: u64,
    revision_fence: OperationsRevisionFence,
}

impl fmt::Debug for MissionPluginNodeSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionPluginNodeSelection")
            .field("sequence", &self.sequence)
            .field("revision_fence", &self.revision_fence)
            .finish_non_exhaustive()
    }
}

impl MissionPluginNodeSelection {
    fn new(mission: &MissionProjection, sequence: u64) -> Self {
        Self {
            project_id: mission.project_id.clone(),
            mission_id: mission.mission_id.clone(),
            sequence,
            revision_fence: OperationsRevisionFence::from_mission(mission),
        }
    }

    pub fn matches_mission(&self, mission: &MissionProjection) -> bool {
        self.project_id == mission.project_id
            && self.mission_id == mission.mission_id
            && mission.conversation_messages.iter().any(|message| {
                message.sequence == self.sequence
                    && message.role == MissionConversationRole::Assistant
                    && message.kind == MissionConversationMessageKind::RuntimeDraft
            })
            && self.revision_fence.matches_mission(mission)
    }
}

/// A durable RuntimeDraft message mapped to an inline Conversation node. The
/// body stays owned by MissionProjection and is only passed to the renderer
/// when the user opens details; this projection never duplicates private text.
#[derive(Clone, Eq, PartialEq)]
pub struct MissionPluginConversationNode {
    pub sequence: u64,
    pub kind: MissionPluginNodeKind,
    pub status: MissionPluginNodeStatus,
    pub title: String,
    pub summary: String,
    pub selected_result: bool,
    pub detail_available: bool,
    pub selection: MissionPluginNodeSelection,
}

impl fmt::Debug for MissionPluginConversationNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionPluginConversationNode")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("selected_result", &self.selected_result)
            .field("detail_available", &self.detail_available)
            .finish_non_exhaustive()
    }
}

impl MissionPluginConversationNode {
    pub fn is_selected_by(&self, selection: Option<&MissionPluginNodeSelection>) -> bool {
        selection == Some(&self.selection)
    }

    pub fn detail_body<'a>(
        &self,
        mission: &'a MissionProjection,
        selection: Option<&MissionPluginNodeSelection>,
    ) -> Option<&'a str> {
        if !self.is_selected_by(selection) || !self.selection.matches_mission(mission) {
            return None;
        }
        mission
            .conversation_messages
            .iter()
            .find(|message| {
                message.sequence == self.sequence
                    && message.role == MissionConversationRole::Assistant
                    && message.kind == MissionConversationMessageKind::RuntimeDraft
            })
            .map(|message| message.body.as_str())
    }
}

impl fmt::Debug for ResultSurfaceProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResultSurfaceProjection")
            .field("kind", &self.kind)
            .field("revision", &self.revision)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// Crate-private plugin slots. Empty slots are omitted from the Mission shell;
/// they never render placeholder controls for capabilities whose owner is not
/// mounted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MissionPluginSurfaceRegistry {
    pub execution: Option<ExecutionSurfaceProjection>,
    pub result: Option<ResultSurfaceProjection>,
    pub conversation_nodes: Vec<MissionPluginConversationNode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeActivitySurface {
    Idle,
    Busy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeTurnSurface {
    Hidden,
    Awaiting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStreamSurface {
    Hidden,
    Visible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeErrorSurface {
    Hidden,
    Visible,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeTransportSurface {
    Live,
    CaughtUp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeStopSurface {
    Unavailable,
    Available,
    Requested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissionPluginSurfaceInput {
    pub activity: RuntimeActivitySurface,
    pub turn: RuntimeTurnSurface,
    pub stream: RuntimeStreamSurface,
    pub error: RuntimeErrorSurface,
    pub transport: RuntimeTransportSurface,
    pub stop: RuntimeStopSurface,
}

impl Default for MissionPluginSurfaceInput {
    fn default() -> Self {
        Self {
            activity: RuntimeActivitySurface::Idle,
            turn: RuntimeTurnSurface::Hidden,
            stream: RuntimeStreamSurface::Hidden,
            error: RuntimeErrorSurface::Hidden,
            transport: RuntimeTransportSurface::Live,
            stop: RuntimeStopSurface::Unavailable,
        }
    }
}

impl MissionPluginSurfaceRegistry {
    pub fn from_read_models(
        mission: Option<&MissionProjection>,
        runtime_activity: Option<&MissionRuntimeProjection>,
        input: MissionPluginSurfaceInput,
    ) -> Self {
        let Some(mission) = mission else {
            return Self::default();
        };

        let conversation_nodes = durable_conversation_nodes(mission, runtime_activity);

        let recovery_required = runtime_activity.is_some_and(|activity| {
            activity.requires_reconciliation
                || activity.recovery_status == Some(RuntimeRecoveryStatus::Failed)
                || activity.turn_status == Some(RuntimeTurnStatus::Uncertain)
        });
        let active_turn = runtime_activity
            .and_then(|activity| activity.turn_status)
            .is_some_and(RuntimeTurnStatus::is_active);
        let execution_mounted = matches!(input.activity, RuntimeActivitySurface::Busy)
            || matches!(input.turn, RuntimeTurnSurface::Awaiting)
            || matches!(input.stream, RuntimeStreamSurface::Visible)
            || matches!(input.error, RuntimeErrorSurface::Visible)
            || active_turn
            || recovery_required;
        let execution = execution_mounted.then(|| {
            let status = if recovery_required {
                OperationsStatus::RecoveryRequired
            } else if matches!(input.error, RuntimeErrorSurface::Visible) {
                OperationsStatus::Failed
            } else if matches!(input.turn, RuntimeTurnSurface::Awaiting) {
                OperationsStatus::WaitingUser
            } else if matches!(input.activity, RuntimeActivitySurface::Busy)
                || matches!(input.stream, RuntimeStreamSurface::Visible)
                || active_turn
            {
                OperationsStatus::Active
            } else {
                OperationsStatus::Ready
            };
            let gate = mission
                .current_checkpoint_id
                .as_deref()
                .map_or_else(|| "当前 Mission gate".into(), humanize_checkpoint);
            let transport = if matches!(input.transport, RuntimeTransportSurface::CaughtUp) {
                "Transport caught up · business state unchanged".into()
            } else if matches!(input.turn, RuntimeTurnSurface::Awaiting) {
                "Awaiting first durable turn".into()
            } else if matches!(input.stream, RuntimeStreamSurface::Visible) {
                "Streaming durable Runtime text".into()
            } else {
                "Runtime contribution mounted".into()
            };
            ExecutionSurfaceProjection {
                status,
                gate,
                transport,
                revision_fence: OperationsRevisionFence::from_mission(mission),
                stop_available: matches!(input.stop, RuntimeStopSurface::Available)
                    && !recovery_required,
                stop_requested: matches!(input.stop, RuntimeStopSurface::Requested),
            }
        });
        let result = mission
            .work_products
            .last()
            .map(|product| ResultSurfaceProjection {
                title: product.title.clone(),
                kind: humanize_checkpoint(product.work_product_type.as_str()),
                revision: format!(
                    "Manifest v{} · revision {}",
                    product.manifest_version, product.work_product_revision
                ),
                lineage: format!(
                    "{} evidence references · Mission-owned lineage",
                    product.evidence_count
                ),
                preview: product.preview_text.clone(),
                status: artifact_status(&product.adoption_status),
            });
        Self {
            execution,
            result,
            conversation_nodes,
        }
    }
}

fn durable_conversation_nodes(
    mission: &MissionProjection,
    runtime_activity: Option<&MissionRuntimeProjection>,
) -> Vec<MissionPluginConversationNode> {
    let last_work_product_id = mission
        .work_products
        .last()
        .map(|product| &product.work_product_id);
    let status = runtime_plugin_node_status(runtime_activity);
    mission
        .conversation_messages
        .iter()
        .filter(|message| {
            message.role == MissionConversationRole::Assistant
                && message.kind == MissionConversationMessageKind::RuntimeDraft
        })
        .map(|message| {
            let kind = if message.work_product_id.is_some() {
                MissionPluginNodeKind::Result
            } else {
                MissionPluginNodeKind::Invocation
            };
            let title = message.checkpoint_id.as_deref().map_or_else(
                || match kind {
                    MissionPluginNodeKind::Invocation => "Runtime execution".into(),
                    MissionPluginNodeKind::Result => "Selected result".into(),
                },
                humanize_checkpoint,
            );
            let selected_result = message
                .work_product_id
                .as_ref()
                .is_some_and(|work_product_id| Some(work_product_id) == last_work_product_id);
            MissionPluginConversationNode {
                sequence: message.sequence,
                kind,
                status,
                title,
                summary: if selected_result {
                    "Durable result is available in the selected Workpad surface.".into()
                } else {
                    "Durable Runtime invocation recorded in this Mission Conversation.".into()
                },
                selected_result,
                detail_available: !message.body.is_empty(),
                selection: MissionPluginNodeSelection::new(mission, message.sequence),
            }
        })
        .collect()
}

fn runtime_plugin_node_status(
    runtime_activity: Option<&MissionRuntimeProjection>,
) -> MissionPluginNodeStatus {
    match runtime_activity.and_then(|activity| activity.turn_status) {
        Some(
            RuntimeTurnStatus::Prepared
            | RuntimeTurnStatus::Dispatching
            | RuntimeTurnStatus::Running
            | RuntimeTurnStatus::ApprovalResponding
            | RuntimeTurnStatus::InterruptRequested,
        ) => MissionPluginNodeStatus::Running,
        Some(RuntimeTurnStatus::WaitingLocalApproval) => MissionPluginNodeStatus::Awaiting,
        None => MissionPluginNodeStatus::Completed,
        Some(RuntimeTurnStatus::Completed | RuntimeTurnStatus::Interrupted) => {
            MissionPluginNodeStatus::Completed
        }
        Some(RuntimeTurnStatus::Failed) => MissionPluginNodeStatus::Failed,
        Some(RuntimeTurnStatus::Uncertain) => MissionPluginNodeStatus::Uncertain,
    }
}

fn artifact_status(status: &WorkProductStatus) -> OperationsStatus {
    match status {
        WorkProductStatus::Draft | WorkProductStatus::ReadyForReview => OperationsStatus::Ready,
        WorkProductStatus::Accepted => OperationsStatus::Active,
        WorkProductStatus::Superseded => OperationsStatus::Empty,
    }
}

fn humanize_checkpoint(value: &str) -> String {
    let words = value
        .trim()
        .split('_')
        .filter(|word| !word.is_empty() && *word != "checkpoint")
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + chars.as_str()
            })
        })
        .collect::<Vec<_>>();
    if words.is_empty() {
        "Current gate".into()
    } else {
        words.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hartevo_application::{MissionConversationMessageProjection, WorkProductProjection};
    use hartevo_domain_kernel::{MissionConversationMessageId, MissionStage};

    fn running_input() -> MissionPluginSurfaceInput {
        MissionPluginSurfaceInput {
            activity: RuntimeActivitySurface::Busy,
            turn: RuntimeTurnSurface::Hidden,
            stream: RuntimeStreamSurface::Visible,
            error: RuntimeErrorSurface::Hidden,
            transport: RuntimeTransportSurface::Live,
            stop: RuntimeStopSurface::Available,
        }
    }

    #[test]
    fn revision_fence_changes_when_any_persisted_revision_changes() {
        let mut mission = mission_projection_for_test();
        let fence = OperationsRevisionFence::from_mission(&mission);
        assert!(fence.matches_mission(&mission));

        mission.revision = mission.revision.saturating_add(1);
        assert!(!fence.matches_mission(&mission));
        mission.revision = fence.mission;

        mission.current_checkpoint_revision =
            Some(fence.checkpoint.unwrap_or_default().saturating_add(1));
        assert!(!fence.matches_mission(&mission));
        mission.current_checkpoint_revision = fence.checkpoint;

        mission.conversation_revision =
            Some(fence.conversation.unwrap_or_default().saturating_add(1));
        assert!(!fence.matches_mission(&mission));
    }

    #[test]
    fn revision_fence_label_is_content_free() {
        let mission = mission_projection_for_test();
        let label = OperationsRevisionFence::from_mission(&mission).label();
        assert!(label.contains("Mission r"));
        assert!(label.contains("Checkpoint r"));
        assert!(label.contains("Conversation r"));
        assert!(!label.contains(mission.project_id.as_str()));
        assert!(!label.contains(mission.mission_id.as_str()));
        assert!(!label.contains(mission.goal.as_str()));
    }

    #[test]
    fn no_plugin_keeps_the_mission_shell_free_of_operations_dashboard() {
        let mission = mission_projection_for_test();
        let registry = MissionPluginSurfaceRegistry::from_read_models(
            Some(&mission),
            None,
            MissionPluginSurfaceInput::default(),
        );
        assert_eq!(registry, MissionPluginSurfaceRegistry::default());
    }

    #[test]
    fn execution_plugin_mounts_and_unmounts_without_retaining_authority() {
        let mission = mission_projection_for_test();
        let mounted =
            MissionPluginSurfaceRegistry::from_read_models(Some(&mission), None, running_input());
        assert!(mounted.execution.as_ref().is_some_and(|surface| {
            surface.stop_available && surface.revision_fence.matches_mission(&mission)
        }));

        let unmounted = MissionPluginSurfaceRegistry::from_read_models(
            Some(&mission),
            None,
            MissionPluginSurfaceInput::default(),
        );
        assert!(unmounted.execution.is_none());
        assert!(unmounted.result.is_none());
    }

    #[test]
    fn result_plugin_mounts_only_for_a_selected_work_product() {
        let mut mission = mission_projection_for_test();
        mission.work_products.push(work_product_for_test());
        let mounted = MissionPluginSurfaceRegistry::from_read_models(
            Some(&mission),
            None,
            MissionPluginSurfaceInput::default(),
        );
        assert!(mounted.execution.is_none());
        assert!(mounted.result.is_some());

        mission.work_products.clear();
        let unmounted = MissionPluginSurfaceRegistry::from_read_models(
            Some(&mission),
            None,
            MissionPluginSurfaceInput::default(),
        );
        assert!(unmounted.result.is_none());
    }

    #[test]
    fn durable_runtime_drafts_mount_inline_nodes_and_selected_result() {
        let mut mission = mission_projection_for_test();
        mission.conversation_messages = vec![
            runtime_message_for_test(1, None, "private invocation body"),
            runtime_message_for_test(2, Some("private-work-product"), "private result body"),
        ];
        mission.work_products.push(work_product_for_test());

        let registry = MissionPluginSurfaceRegistry::from_read_models(
            Some(&mission),
            None,
            MissionPluginSurfaceInput::default(),
        );

        assert_eq!(registry.conversation_nodes.len(), 2);
        assert_eq!(
            registry.conversation_nodes[0].kind,
            MissionPluginNodeKind::Invocation
        );
        assert_eq!(
            registry.conversation_nodes[1].kind,
            MissionPluginNodeKind::Result
        );
        assert!(!registry.conversation_nodes[0].selected_result);
        assert!(registry.conversation_nodes[1].selected_result);
        assert!(
            registry
                .conversation_nodes
                .iter()
                .all(|node| node.detail_available)
        );
    }

    #[test]
    fn inline_node_selection_is_revision_and_scope_fenced() {
        let mut mission = mission_projection_for_test();
        mission.conversation_messages.push(runtime_message_for_test(
            1,
            None,
            "private invocation body",
        ));
        let registry = MissionPluginSurfaceRegistry::from_read_models(
            Some(&mission),
            None,
            MissionPluginSurfaceInput::default(),
        );
        let selection = registry.conversation_nodes[0].selection.clone();
        assert!(selection.matches_mission(&mission));
        assert!(registry.conversation_nodes[0].is_selected_by(Some(&selection)));
        assert_eq!(
            registry.conversation_nodes[0].detail_body(&mission, Some(&selection)),
            Some("private invocation body")
        );

        mission.mission_id = "reselected-private-mission".into();
        assert!(!selection.matches_mission(&mission));
        assert!(!registry.conversation_nodes[0].is_selected_by(None));
        assert!(
            registry.conversation_nodes[0]
                .detail_body(&mission, Some(&selection))
                .is_none()
        );
        let debug = format!("{registry:?}");
        assert!(!debug.contains("private invocation body"));
        assert!(!debug.contains("private-project-id"));
        assert!(!debug.contains("private-mission-id"));
    }

    #[test]
    fn inline_nodes_unmount_when_durable_conversation_is_no_longer_selected() {
        let mut mission = mission_projection_for_test();
        mission.conversation_messages.push(runtime_message_for_test(
            1,
            None,
            "private invocation body",
        ));
        let mounted = MissionPluginSurfaceRegistry::from_read_models(
            Some(&mission),
            None,
            MissionPluginSurfaceInput::default(),
        );
        assert_eq!(mounted.conversation_nodes.len(), 1);

        mission.conversation_messages.clear();
        let unmounted = MissionPluginSurfaceRegistry::from_read_models(
            Some(&mission),
            None,
            MissionPluginSurfaceInput::default(),
        );
        assert!(unmounted.conversation_nodes.is_empty());
    }

    #[test]
    fn stale_execution_action_and_reselect_do_not_reuse_old_scope() {
        let mut first = mission_projection_for_test();
        let first_registry =
            MissionPluginSurfaceRegistry::from_read_models(Some(&first), None, running_input());
        let Some(first_fence) = first_registry
            .execution
            .map(|surface| surface.revision_fence)
        else {
            panic!("execution plugin should mount");
        };
        first.mission_id = "reselected-mission-id".into();
        first.revision = first.revision.saturating_add(1);
        assert!(!first_fence.matches_mission(&first));

        let second_registry = MissionPluginSurfaceRegistry::from_read_models(
            Some(&first),
            None,
            MissionPluginSurfaceInput::default(),
        );
        assert_eq!(second_registry, MissionPluginSurfaceRegistry::default());
        assert!(!format!("{second_registry:?}").contains("Private goal"));
    }

    #[test]
    fn plugin_registry_debug_is_content_free() {
        let mut mission = mission_projection_for_test();
        mission.work_products.push(work_product_for_test());
        let registry =
            MissionPluginSurfaceRegistry::from_read_models(Some(&mission), None, running_input());
        let debug = format!("{registry:?}");
        assert!(!debug.contains(mission.project_id.as_str()));
        assert!(!debug.contains(mission.mission_id.as_str()));
        assert!(!debug.contains(mission.goal.as_str()));
        assert!(!debug.contains("private-preview"));
    }

    fn mission_projection_for_test() -> MissionProjection {
        MissionProjection {
            surface: "test".into(),
            project_id: "private-project-id".into(),
            mission_id: "private-mission-id".into(),
            title: "Private title".into(),
            goal: "Private goal".into(),
            manifest_id: Some("VM-07".into()),
            manifest_version: Some(1),
            catalog_digest: Some("catalog-digest".into()),
            current_checkpoint_id: Some("evidence_plan".into()),
            current_checkpoint_status: Some(
                hartevo_domain_kernel::MissionCheckpointStatus::Running,
            ),
            current_checkpoint_revision: Some(5),
            current_checkpoint_capability_id: Some("market.evidence".into()),
            current_checkpoint_executor: Some(
                hartevo_domain_kernel::MissionCheckpointExecutor::Runtime,
            ),
            current_checkpoint_application_handler_status: None,
            current_checkpoint_application_handler_id: None,
            current_checkpoint_oracle_ids: std::collections::BTreeSet::default(),
            current_checkpoint_completion_policy: None,
            completed_checkpoint_count: 1,
            checkpoint_count: 8,
            cycle: 0,
            schedule: None,
            conversation_id: Some("private-conversation-id".into()),
            conversation_revision: Some(7),
            conversation_messages: Vec::new(),
            stage: MissionStage::Running,
            revision: 9,
            evidence_count: 2,
            work_product_count: 0,
            work_products: Vec::new(),
            pending_approval_count: 0,
            verified_effect_count: 0,
            outcome_summary: None,
            vm11_outcome_review: None,
        }
    }

    fn work_product_for_test() -> WorkProductProjection {
        WorkProductProjection {
            work_product_id: "private-work-product".into(),
            title: "Private result".into(),
            work_product_type: "market_evidence_pack".into(),
            manifest_version: 1,
            work_product_revision: 2,
            preview_media_type: "text/plain".into(),
            preview_text: "private-preview".into(),
            preview_digest: "preview-digest".into(),
            manifest_digest: "manifest-digest".into(),
            adoption_status: hartevo_domain_kernel::WorkProductStatus::ReadyForReview,
            editable_scope_count: 0,
            evidence_count: 1,
        }
    }

    fn runtime_message_for_test(
        sequence: u64,
        work_product_id: Option<&str>,
        body: &str,
    ) -> MissionConversationMessageProjection {
        MissionConversationMessageProjection {
            message_id: MissionConversationMessageId::from("private-message"),
            sequence,
            role: MissionConversationRole::Assistant,
            kind: MissionConversationMessageKind::RuntimeDraft,
            body: body.into(),
            content_digest: format!("private-digest-{sequence}"),
            mission_revision: 9,
            checkpoint_id: Some("evidence_plan".into()),
            work_product_id: work_product_id.map(Into::into),
            recorded_at: Utc::now(),
        }
    }
}
