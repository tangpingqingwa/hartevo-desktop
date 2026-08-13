//! Read-only on-demand Mission plugin surface model for Desktop.
//!
//! OI-01, CAP-01, CTX-01 and BW-01 own the durable control-plane records that
//! will eventually fill these panels.  Until those APIs land, this module
//! projects only existing Application/Desktop facts and represents every
//! unavailable field as an honest typed state.  It has no persistence,
//! runtime loop, browser control, approval authority or Effect path.

use std::fmt;

use hartevo_application::{MissionProjection, MissionRuntimeProjection};
use hartevo_domain_kernel::{RuntimeRecoveryStatus, RuntimeTurnStatus, WorkProductStatus};

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
    pub worker: String,
    pub recovery: String,
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
            let worker = runtime_activity
                .and_then(|activity| activity.turn_status)
                .map_or_else(|| "等待 Runtime worker claim".into(), turn_status_detail);
            let recovery = runtime_activity
                .and_then(|activity| activity.recovery_status)
                .map_or_else(|| "No recovery fence".into(), recovery_status_detail);
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
                worker,
                recovery,
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
        Self { execution, result }
    }
}

fn recovery_status_detail(status: RuntimeRecoveryStatus) -> String {
    match status {
        RuntimeRecoveryStatus::Prepared => "恢复记录已准备，尚未获得健康运行时。".into(),
        RuntimeRecoveryStatus::Spawned => "恢复进程已启动，等待健康检查。".into(),
        RuntimeRecoveryStatus::Healthy => "健康检查通过，仍需绑定同一 Mission turn。".into(),
        RuntimeRecoveryStatus::ThreadBound => {
            "Runtime thread 已绑定，等待 Desktop 读取终态。".into()
        }
        RuntimeRecoveryStatus::Attached => "恢复已附着到持久上下文。".into(),
        RuntimeRecoveryStatus::Failed => "恢复失败；uncertain 状态不会自动重放。".into(),
    }
}

fn turn_status_detail(status: RuntimeTurnStatus) -> String {
    match status {
        RuntimeTurnStatus::WaitingLocalApproval => {
            "这是本机 Runtime 请求，不等同于外部 Effect approval。".into()
        }
        RuntimeTurnStatus::Uncertain => "内容与执行状态保留；恢复前不允许自动重放。".into(),
        RuntimeTurnStatus::Completed => "本次 turn 已终态；不据此声明业务 Outcome。".into(),
        RuntimeTurnStatus::Failed => {
            "Runtime 失败保持 content-free；已收到的持久正文不会被覆盖。".into()
        }
        _ => "状态来自持久 Runtime ledger；页面不创建第二个 Agent loop。".into(),
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
    use hartevo_application::WorkProductProjection;
    use hartevo_domain_kernel::MissionStage;

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
}
