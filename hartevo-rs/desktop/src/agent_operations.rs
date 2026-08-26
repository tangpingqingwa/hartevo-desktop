//! Read-only Agent Operations Workbench model for Desktop.
//!
//! OI-01, CAP-01 and CTX-01 own remaining control-plane records that will
//! eventually fill these panels. Browser Continue reads the durable
//! Mission-bound workspace projection and stays empty until a user-held lease
//! exists. This module has no persistence, runtime loop, approval authority or
//! Effect path.

use hartevo_application::{
    BrowserWorkspaceProjection as DurableBrowserWorkspaceProjection, DesktopProjectProjection,
    MissionProjection, MissionRuntimeProjection, WorkProductProjection,
};
use hartevo_browser_adapter::BrowserControlState;
use hartevo_domain_kernel::{
    BrowserWorkspaceId, MissionStage, RuntimeProcessClaimStatus, RuntimeRecoveryStatus,
    RuntimeTurnStatus, WorkProductStatus,
};

use crate::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationsStatus {
    Ready,
    Active,
    Empty,
    WaitingUser,
    WaitingApproval,
    RecoveryRequired,
    BlockedEnv,
    NotImplemented,
    Failed,
}

impl OperationsStatus {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Active => "RUNNING",
            Self::Empty => "EMPTY",
            Self::WaitingUser => "WAITING_USER",
            Self::WaitingApproval => "WAITING_APPROVAL",
            Self::RecoveryRequired => "RECOVERY_REQUIRED",
            Self::BlockedEnv => "BLOCKED_ENV",
            Self::NotImplemented => "NOT_IMPLEMENTED",
            Self::Failed => "FAILED",
        }
    }

    pub const fn tone(self) -> &'static str {
        match self {
            Self::Ready | Self::Active => "ready",
            Self::Empty => "empty",
            Self::WaitingUser | Self::WaitingApproval => "attention",
            Self::RecoveryRequired | Self::BlockedEnv | Self::NotImplemented | Self::Failed => {
                "blocked"
            }
        }
    }

    pub const fn is_actionable(self) -> bool {
        matches!(self, Self::Ready | Self::Active | Self::WaitingUser)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionControlProjection {
    pub status: OperationsStatus,
    pub objective: String,
    pub current_gate: String,
    pub next_todos: Vec<String>,
    pub active_claims: Vec<ClaimProjection>,
    pub quota: QuotaProjection,
    pub evidence: EvidenceChangeProjection,
    pub stage: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimProjection {
    pub title: String,
    pub status: OperationsStatus,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotaProjection {
    pub status: OperationsStatus,
    pub used: String,
    pub limit: String,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceChangeProjection {
    pub evidence_count: usize,
    pub work_product_count: usize,
    pub verified_effect_count: usize,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfigurationProjection {
    pub status: OperationsStatus,
    pub provider: String,
    pub model: String,
    pub harness: String,
    pub reasoning_effort: String,
    pub service_tier: String,
    pub data_boundary: String,
    pub pinned_release: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerProjection {
    pub worker_type: String,
    pub task: String,
    pub lease: String,
    pub generation: String,
    pub progress: String,
    pub budget: String,
    pub handoff: String,
    pub recovery: String,
    pub status: OperationsStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactActionsProjection {
    pub diff: OperationsStatus,
    pub adopt: OperationsStatus,
    pub reject: OperationsStatus,
    pub rollback: OperationsStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactProjection {
    pub title: String,
    pub kind: String,
    pub revision: String,
    pub lineage: String,
    pub preview: String,
    pub evidence_count: usize,
    pub status: OperationsStatus,
    pub actions: ArtifactActionsProjection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalEffectProjection {
    pub external_approval_count: usize,
    pub verified_effect_count: usize,
    pub external_status: OperationsStatus,
    pub local_runtime_status: OperationsStatus,
    pub local_runtime_detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserWorkspaceProjection {
    pub status: OperationsStatus,
    pub identity: String,
    pub control_owner: String,
    pub next_action: String,
    pub workspace_id: Option<BrowserWorkspaceId>,
    pub revision: Option<u64>,
    pub lease_generation: Option<u64>,
    pub continue_status: OperationsStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryProjection {
    pub status: OperationsStatus,
    pub detail: String,
    pub next_action: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuickEntryProjection {
    pub status: OperationsStatus,
    pub hint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentOperationsWorkbenchProjection {
    pub project_name: String,
    pub mission: MissionControlProjection,
    pub runtime: RuntimeConfigurationProjection,
    pub workers: Vec<WorkerProjection>,
    pub artifacts: Vec<ArtifactProjection>,
    pub approvals: ApprovalEffectProjection,
    pub browser: BrowserWorkspaceProjection,
    pub recovery: RecoveryProjection,
    pub quick_entry: QuickEntryProjection,
}

impl AgentOperationsWorkbenchProjection {
    pub fn from_parts(
        project: Option<&DesktopProjectProjection>,
        mission: Option<&MissionProjection>,
        runtime_activity: Option<&MissionRuntimeProjection>,
        runtime: Option<&DesktopRuntimeProjection>,
    ) -> Self {
        let project_name =
            project.map_or_else(|| "未选择 Project".into(), |project| project.name.clone());
        let mission_control = mission_control_projection(mission, runtime_activity);
        let runtime_projection = runtime_projection(runtime);
        let workers = worker_projection(mission, runtime_activity);
        let artifacts = mission.map_or_else(Vec::new, |mission| {
            mission
                .work_products
                .iter()
                .map(artifact_projection)
                .collect()
        });
        let approvals = approval_projection(mission, runtime_activity);
        let browser = browser_projection(mission);
        let recovery = recovery_projection(runtime_activity);
        let quick_entry = QuickEntryProjection {
            status: if mission.is_some() {
                OperationsStatus::Ready
            } else {
                OperationsStatus::WaitingUser
            },
            hint: if mission.is_some() {
                "输入目标、纠正或停止条件；消息仍归属于当前 Mission。".into()
            } else {
                "先选择或创建一个持久 Mission，再进入 Quick Entry。".into()
            },
        };
        Self {
            project_name,
            mission: mission_control,
            runtime: runtime_projection,
            workers,
            artifacts,
            approvals,
            browser,
            recovery,
            quick_entry,
        }
    }
}

fn mission_control_projection(
    mission: Option<&MissionProjection>,
    runtime_activity: Option<&MissionRuntimeProjection>,
) -> MissionControlProjection {
    let Some(mission) = mission else {
        return MissionControlProjection {
            status: OperationsStatus::Empty,
            objective: "选择一个持久 Mission 以查看目标与下一道门".into(),
            current_gate: "尚未选择 Mission".into(),
            next_todos: vec!["从 Mission 列表选择一个真实目标".into()],
            active_claims: Vec::new(),
            quota: quota_not_available(),
            evidence: EvidenceChangeProjection {
                evidence_count: 0,
                work_product_count: 0,
                verified_effect_count: 0,
                detail: "选择 Mission 后读取持久证据变化".into(),
            },
            stage: "未选择".into(),
        };
    };
    let status = mission_status(mission);
    let current_gate = mission
        .current_checkpoint_id
        .as_deref()
        .map_or_else(|| "当前合同没有活动检查点".into(), humanize_checkpoint);
    let next_todos = next_todos_for(mission, status);
    let active_claims = claim_projection(runtime_activity);
    MissionControlProjection {
        status,
        objective: mission.goal.clone(),
        current_gate,
        next_todos,
        active_claims,
        quota: quota_not_available(),
        evidence: EvidenceChangeProjection {
            evidence_count: mission.evidence_count,
            work_product_count: mission.work_product_count,
            verified_effect_count: mission.verified_effect_count,
            detail: "计数来自当前 Mission projection；quota delta 等待 CTX-01/OI-01 read model。"
                .into(),
        },
        stage: mission_stage_label(&mission.stage),
    }
}

fn mission_status(mission: &MissionProjection) -> OperationsStatus {
    match mission.stage {
        MissionStage::Running | MissionStage::Verifying => OperationsStatus::Active,
        MissionStage::WaitingApproval => OperationsStatus::WaitingApproval,
        MissionStage::WaitingUser => OperationsStatus::WaitingUser,
        MissionStage::Blocked | MissionStage::Failed => OperationsStatus::BlockedEnv,
        MissionStage::Draft | MissionStage::Ready | MissionStage::Scheduled => {
            OperationsStatus::Ready
        }
        MissionStage::CycleReviewed | MissionStage::Completed | MissionStage::Cancelled => {
            OperationsStatus::Empty
        }
        MissionStage::Partial | MissionStage::ExpectedRefusal => OperationsStatus::Failed,
    }
}

fn next_todos_for(mission: &MissionProjection, status: OperationsStatus) -> Vec<String> {
    match status {
        OperationsStatus::WaitingApproval => vec!["审阅独立 Effect approval surface".into()],
        OperationsStatus::WaitingUser => vec!["输入下一步判断、纠正或停止条件".into()],
        OperationsStatus::RecoveryRequired => vec!["先完成精确 Runtime recovery".into()],
        OperationsStatus::BlockedEnv => vec!["查看阻塞原因并保持当前 Mission 不变".into()],
        OperationsStatus::Empty if mission.stage.is_terminal() => {
            vec!["复核持久证据与最终状态".into()]
        }
        OperationsStatus::Active => vec![
            "观察当前 gate 与 worker progress".into(),
            "必要时使用 Quick Entry steer 或 interrupt".into(),
        ],
        _ if mission.current_checkpoint_id.is_some() => {
            vec!["审阅当前 gate 的持久输入与下一转换".into()]
        }
        _ => vec!["确认 Mission objective 与运行边界".into()],
    }
}

fn claim_projection(runtime_activity: Option<&MissionRuntimeProjection>) -> Vec<ClaimProjection> {
    let Some(activity) = runtime_activity else {
        return Vec::new();
    };
    let mut claims = Vec::new();
    if let Some(status) = activity.process_claim_status {
        claims.push(ClaimProjection {
            title: "Runtime worker claim".into(),
            status: if status == RuntimeProcessClaimStatus::Blocked {
                OperationsStatus::BlockedEnv
            } else if status.is_terminal() {
                OperationsStatus::Empty
            } else {
                OperationsStatus::Active
            },
            detail: process_claim_detail(status),
        });
    }
    if let Some(status) = activity.recovery_status {
        claims.push(ClaimProjection {
            title: "Recovery claim".into(),
            status: if status == RuntimeRecoveryStatus::Failed {
                OperationsStatus::RecoveryRequired
            } else if status == RuntimeRecoveryStatus::Attached {
                OperationsStatus::Ready
            } else {
                OperationsStatus::Active
            },
            detail: recovery_status_detail(status),
        });
    }
    if let Some(status) = activity.turn_status {
        claims.push(ClaimProjection {
            title: "Current turn".into(),
            status: turn_operations_status(status),
            detail: turn_status_detail(status),
        });
    }
    claims
}

fn process_claim_detail(status: RuntimeProcessClaimStatus) -> String {
    match status {
        RuntimeProcessClaimStatus::Prepared => "Worker claim 已准备，尚未证明进程已启动。".into(),
        RuntimeProcessClaimStatus::Spawned => "本机进程 identity 已由持久 claim 管理。".into(),
        RuntimeProcessClaimStatus::Terminated => "进程已被精确终止；不会按 PID 猜测重放。".into(),
        RuntimeProcessClaimStatus::Exited => "进程已退出；等待同一 Mission 的恢复判断。".into(),
        RuntimeProcessClaimStatus::Blocked => {
            "进程清理或 identity 检查阻塞，保持 fail-closed。".into()
        }
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

fn turn_operations_status(status: RuntimeTurnStatus) -> OperationsStatus {
    match status {
        RuntimeTurnStatus::Prepared
        | RuntimeTurnStatus::Dispatching
        | RuntimeTurnStatus::Running
        | RuntimeTurnStatus::ApprovalResponding
        | RuntimeTurnStatus::InterruptRequested => OperationsStatus::Active,
        RuntimeTurnStatus::WaitingLocalApproval => OperationsStatus::WaitingApproval,
        RuntimeTurnStatus::Completed | RuntimeTurnStatus::Interrupted => OperationsStatus::Empty,
        RuntimeTurnStatus::Failed => OperationsStatus::Failed,
        RuntimeTurnStatus::Uncertain => OperationsStatus::RecoveryRequired,
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

fn runtime_projection(
    runtime: Option<&DesktopRuntimeProjection>,
) -> RuntimeConfigurationProjection {
    let Some(runtime) = runtime else {
        return RuntimeConfigurationProjection {
            status: OperationsStatus::BlockedEnv,
            provider: "未读取".into(),
            model: "未读取".into(),
            harness: "等待 OI-01".into(),
            reasoning_effort: "等待 OI-01".into(),
            service_tier: "等待 OI-01".into(),
            data_boundary: "Project-bound local Context".into(),
            pinned_release: "未读取".into(),
        };
    };
    let status = runtime_operations_status(runtime.status);
    RuntimeConfigurationProjection {
        status,
        provider: runtime.provider.clone().unwrap_or_else(|| "未配置".into()),
        model: runtime.model.clone().unwrap_or_else(|| "未配置".into()),
        harness: if status.is_actionable() {
            "Pinned OpenInterpreter App Server".into()
        } else {
            "等待 OI-01 harness identity".into()
        },
        reasoning_effort: "等待 OI-01 typed setting".into(),
        service_tier: "等待 OI-01 typed setting".into(),
        data_boundary: "Project-bound local Context".into(),
        pinned_release: runtime.release.clone(),
    }
}

fn runtime_operations_status(status: DesktopRuntimeAvailabilityStatus) -> OperationsStatus {
    match status {
        DesktopRuntimeAvailabilityStatus::ReadyDevelopment
        | DesktopRuntimeAvailabilityStatus::ReadyDistribution => OperationsStatus::Ready,
        DesktopRuntimeAvailabilityStatus::NotConfigured
        | DesktopRuntimeAvailabilityStatus::ConfigurationRequired => OperationsStatus::WaitingUser,
        DesktopRuntimeAvailabilityStatus::EvidenceMissing
        | DesktopRuntimeAvailabilityStatus::UnsupportedHost => OperationsStatus::NotImplemented,
        DesktopRuntimeAvailabilityStatus::BlockedEnvironment => OperationsStatus::BlockedEnv,
        DesktopRuntimeAvailabilityStatus::IntegrityError => OperationsStatus::Failed,
    }
}

fn worker_projection(
    mission: Option<&MissionProjection>,
    runtime_activity: Option<&MissionRuntimeProjection>,
) -> Vec<WorkerProjection> {
    let Some(mission) = mission else {
        return Vec::new();
    };
    let Some(activity) = runtime_activity else {
        return vec![WorkerProjection {
            worker_type: "Mission coordinator".into(),
            task: "No active worker claim".into(),
            lease: "No active lease".into(),
            generation: "Worker generation pending CTX-01".into(),
            progress: "等待持久 Runtime 状态".into(),
            budget: "Quota read model pending".into(),
            handoff: "User remains in control".into(),
            recovery: "No recovery record".into(),
            status: OperationsStatus::Empty,
        }];
    };
    let status = if activity.requires_reconciliation {
        OperationsStatus::RecoveryRequired
    } else if activity
        .turn_status
        .is_some_and(RuntimeTurnStatus::is_active)
    {
        OperationsStatus::Active
    } else {
        OperationsStatus::Empty
    };
    vec![WorkerProjection {
        worker_type: "Local Runtime worker".into(),
        task: mission
            .current_checkpoint_id
            .as_deref()
            .map_or_else(|| "Current Mission objective".into(), humanize_checkpoint),
        lease: activity
            .process_claim_status
            .map_or_else(|| "No active process claim".into(), process_claim_lease),
        generation: "Worker generation pending CTX-01 read model".into(),
        progress: activity
            .turn_status
            .map_or_else(|| "No active turn".into(), turn_status_detail),
        budget: "Quota read model pending CTX-01/OI-01".into(),
        handoff: if activity.requires_reconciliation {
            "Handoff held until exact recovery".into()
        } else {
            "User can steer or interrupt the current turn".into()
        },
        recovery: activity
            .recovery_status
            .map_or_else(|| "No recovery record".into(), recovery_status_detail),
        status,
    }]
}

fn process_claim_lease(status: RuntimeProcessClaimStatus) -> String {
    match status {
        RuntimeProcessClaimStatus::Prepared => "Lease prepared".into(),
        RuntimeProcessClaimStatus::Spawned => "Lease active".into(),
        RuntimeProcessClaimStatus::Terminated | RuntimeProcessClaimStatus::Exited => {
            "Lease closed".into()
        }
        RuntimeProcessClaimStatus::Blocked => "Lease blocked".into(),
    }
}

fn artifact_projection(product: &WorkProductProjection) -> ArtifactProjection {
    ArtifactProjection {
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
        evidence_count: product.evidence_count,
        status: artifact_status(&product.adoption_status),
        actions: ArtifactActionsProjection {
            diff: OperationsStatus::NotImplemented,
            adopt: OperationsStatus::NotImplemented,
            reject: OperationsStatus::NotImplemented,
            rollback: OperationsStatus::NotImplemented,
        },
    }
}

fn artifact_status(status: &WorkProductStatus) -> OperationsStatus {
    match status {
        WorkProductStatus::Draft | WorkProductStatus::ReadyForReview => OperationsStatus::Ready,
        WorkProductStatus::Accepted => OperationsStatus::Active,
        WorkProductStatus::Superseded => OperationsStatus::Empty,
    }
}

fn approval_projection(
    mission: Option<&MissionProjection>,
    runtime_activity: Option<&MissionRuntimeProjection>,
) -> ApprovalEffectProjection {
    let external_approval_count = mission.map_or(0, |mission| mission.pending_approval_count);
    let verified_effect_count = mission.map_or(0, |mission| mission.verified_effect_count);
    let local_runtime_status = match runtime_activity.and_then(|activity| activity.turn_status) {
        Some(RuntimeTurnStatus::WaitingLocalApproval | RuntimeTurnStatus::ApprovalResponding) => {
            OperationsStatus::WaitingApproval
        }
        Some(_) | None => OperationsStatus::Empty,
    };
    ApprovalEffectProjection {
        external_approval_count,
        verified_effect_count,
        external_status: if external_approval_count > 0 {
            OperationsStatus::WaitingApproval
        } else {
            OperationsStatus::Empty
        },
        local_runtime_status,
        local_runtime_detail: "Local Runtime approval is separate from external Effect approval."
            .into(),
    }
}

fn browser_projection(mission: Option<&MissionProjection>) -> BrowserWorkspaceProjection {
    let Some(mission) = mission else {
        return BrowserWorkspaceProjection {
            status: OperationsStatus::Empty,
            identity: "No Mission-bound Browser Workspace".into(),
            control_owner: "No owner".into(),
            next_action: "Select a Mission".into(),
            workspace_id: None,
            revision: None,
            lease_generation: None,
            continue_status: OperationsStatus::Empty,
        };
    };
    let Some(workspace) = mission.browser_workspace.as_ref() else {
        return BrowserWorkspaceProjection {
            status: OperationsStatus::Empty,
            identity: "No Mission-bound Browser Workspace".into(),
            control_owner: "No owner".into(),
            next_action: "Continue stays empty until a durable workspace exists".into(),
            workspace_id: None,
            revision: None,
            lease_generation: None,
            continue_status: OperationsStatus::Empty,
        };
    };
    match workspace.control_state {
        BrowserControlState::UserControlled => BrowserWorkspaceProjection {
            status: OperationsStatus::WaitingUser,
            identity: short_identity_digest(&workspace.identity_digest),
            control_owner: "User holds the current lease".into(),
            next_action: "Continue issues Application continue_browser_workspace".into(),
            workspace_id: Some(workspace.workspace_id.clone()),
            revision: Some(workspace.revision),
            lease_generation: Some(workspace.lease_generation),
            continue_status: OperationsStatus::Ready,
        },
        BrowserControlState::AgentControlled => browser_workspace_view(
            workspace,
            OperationsStatus::Active,
            "Agent holds the current lease",
            "Take over remains NOT_IMPLEMENTED; Continue stays disabled",
            OperationsStatus::NotImplemented,
        ),
        BrowserControlState::PausedAgent | BrowserControlState::PausedUser => {
            browser_workspace_view(
                workspace,
                OperationsStatus::WaitingUser,
                "Workspace is paused",
                "Pause/Resume remains NOT_IMPLEMENTED; Continue stays disabled",
                OperationsStatus::NotImplemented,
            )
        }
        BrowserControlState::Completed
        | BrowserControlState::KeptForUser
        | BrowserControlState::Closed => browser_workspace_view(
            workspace,
            OperationsStatus::Empty,
            "Workspace is terminal",
            "Continue does not reopen a closed workspace",
            OperationsStatus::Empty,
        ),
    }
}

fn browser_workspace_view(
    workspace: &DurableBrowserWorkspaceProjection,
    status: OperationsStatus,
    control_owner: &str,
    next_action: &str,
    continue_status: OperationsStatus,
) -> BrowserWorkspaceProjection {
    BrowserWorkspaceProjection {
        status,
        identity: short_identity_digest(&workspace.identity_digest),
        control_owner: control_owner.into(),
        next_action: next_action.into(),
        workspace_id: Some(workspace.workspace_id.clone()),
        revision: Some(workspace.revision),
        lease_generation: Some(workspace.lease_generation),
        continue_status,
    }
}

fn short_identity_digest(digest: &str) -> String {
    if digest.len() >= 12 {
        format!("identity {}", &digest[..12])
    } else {
        "Mission-bound identity".into()
    }
}

fn recovery_projection(runtime_activity: Option<&MissionRuntimeProjection>) -> RecoveryProjection {
    let Some(activity) = runtime_activity else {
        return RecoveryProjection {
            status: OperationsStatus::Empty,
            detail: "No active recovery record".into(),
            next_action: "No recovery action required".into(),
        };
    };
    if activity.requires_reconciliation
        || activity.recovery_status == Some(RuntimeRecoveryStatus::Failed)
        || activity.turn_status == Some(RuntimeTurnStatus::Uncertain)
    {
        return RecoveryProjection {
            status: OperationsStatus::RecoveryRequired,
            detail: "A persisted Runtime/worker state needs exact reconciliation before retry."
                .into(),
            next_action: "Open recovery review; do not replay uncertain work".into(),
        };
    }
    RecoveryProjection {
        status: OperationsStatus::Ready,
        detail: "No recovery fence is currently active.".into(),
        next_action: "Continue normal Mission review".into(),
    }
}

fn quota_not_available() -> QuotaProjection {
    QuotaProjection {
        status: OperationsStatus::NotImplemented,
        used: "—".into(),
        limit: "Not available".into(),
        detail: "Quota/claim accounting waits for the CTX-01 and OI-01 typed read models.".into(),
    }
}

fn mission_stage_label(stage: &MissionStage) -> String {
    match stage {
        MissionStage::Draft => "Draft",
        MissionStage::Ready => "Ready",
        MissionStage::Running => "Running",
        MissionStage::WaitingUser => "Waiting for user",
        MissionStage::WaitingApproval => "Waiting for approval",
        MissionStage::Blocked => "Blocked",
        MissionStage::Verifying => "Verifying",
        MissionStage::Scheduled => "Scheduled",
        MissionStage::CycleReviewed => "Cycle reviewed",
        MissionStage::Completed => "Completed",
        MissionStage::Partial => "Partial",
        MissionStage::ExpectedRefusal => "Expected refusal",
        MissionStage::Failed => "Failed",
        MissionStage::Cancelled => "Cancelled",
    }
    .into()
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

    #[test]
    fn runtime_config_maps_missing_control_plane_fields_honestly() {
        let runtime = DesktopRuntimeProjection {
            status: DesktopRuntimeAvailabilityStatus::ConfigurationRequired,
            target: Some("private-target-path".into()),
            release: "pinned-release".into(),
            program_sha256: Some("private-program-digest".into()),
            provider: None,
            model: None,
            distribution_signature_evidence: None,
            exact_tokenizer_evidence: false,
        };
        let projection = runtime_projection(Some(&runtime));
        assert_eq!(projection.status, OperationsStatus::WaitingUser);
        assert_eq!(projection.provider, "未配置");
        assert_eq!(projection.model, "未配置");
        assert_eq!(projection.reasoning_effort, "等待 OI-01 typed setting");
        assert!(!projection.harness.contains("private-target-path"));
        assert!(!projection.harness.contains("private-program-digest"));
    }

    #[test]
    fn checkpoint_ids_are_not_normal_product_language() {
        assert_eq!(
            humanize_checkpoint("go_no_go_need_more_evidence"),
            "Go No Go Need More Evidence"
        );
        assert_eq!(humanize_checkpoint("_"), "Current gate");
    }

    #[test]
    fn local_runtime_approval_is_separate_from_external_effect_approval() {
        let activity = MissionRuntimeProjection {
            project_id: "project".into(),
            mission_id: "mission".into(),
            process_claim_status: None,
            process_cleanup_attempt_count: 0,
            recovery_status: None,
            recovery_failure_count: 0,
            recovery_process_attempt: None,
            turn_status: Some(RuntimeTurnStatus::WaitingLocalApproval),
            turn_failure_count: 0,
            turn_evidence_count: 0,
            last_updated_at: None,
            requires_reconciliation: false,
        };
        let approval = approval_projection(None, Some(&activity));
        assert_eq!(approval.external_status, OperationsStatus::Empty);
        assert_eq!(
            approval.local_runtime_status,
            OperationsStatus::WaitingApproval
        );
        assert!(approval.local_runtime_detail.contains("separate"));
    }

    #[test]
    fn uncertain_runtime_requires_recovery_without_claiming_success() {
        let activity = MissionRuntimeProjection {
            project_id: "project".into(),
            mission_id: "mission".into(),
            process_claim_status: Some(RuntimeProcessClaimStatus::Blocked),
            process_cleanup_attempt_count: 1,
            recovery_status: Some(RuntimeRecoveryStatus::Failed),
            recovery_failure_count: 1,
            recovery_process_attempt: Some(1),
            turn_status: Some(RuntimeTurnStatus::Uncertain),
            turn_failure_count: 0,
            turn_evidence_count: 1,
            last_updated_at: None,
            requires_reconciliation: true,
        };
        let recovery = recovery_projection(Some(&activity));
        assert_eq!(recovery.status, OperationsStatus::RecoveryRequired);
        assert!(!recovery.detail.contains("success"));
        let workers = worker_projection(None, Some(&activity));
        assert!(workers.is_empty());
    }

    #[test]
    fn browser_continue_stays_empty_without_a_mission_bound_workspace() {
        let mission = MissionProjection {
            surface: "orchestrator".into(),
            project_id: "project".into(),
            mission_id: "mission".into(),
            title: "goal".into(),
            goal: "goal".into(),
            manifest_id: None,
            manifest_version: None,
            catalog_digest: None,
            current_checkpoint_id: None,
            current_checkpoint_status: None,
            current_checkpoint_revision: None,
            current_checkpoint_capability_id: None,
            current_checkpoint_executor: None,
            current_checkpoint_application_handler_status: None,
            current_checkpoint_application_handler_id: None,
            current_checkpoint_oracle_ids: std::collections::BTreeSet::default(),
            current_checkpoint_completion_policy: None,
            browser_workspace: None,
            completed_checkpoint_count: 0,
            checkpoint_count: 0,
            cycle: 1,
            schedule: None,
            conversation_id: None,
            conversation_revision: None,
            conversation_messages: Vec::new(),
            stage: MissionStage::Running,
            revision: 1,
            evidence_count: 0,
            work_product_count: 0,
            work_products: Vec::new(),
            pending_approval_count: 0,
            pending_effects: Vec::new(),
            verified_effect_count: 0,
            outcome_summary: None,
            vm11_outcome_review: None,
        };
        let empty = browser_projection(Some(&mission));
        assert_eq!(empty.status, OperationsStatus::Empty);
        assert_eq!(empty.continue_status, OperationsStatus::Empty);
        assert!(empty.workspace_id.is_none());

        let mut held = mission.clone();
        held.browser_workspace = Some(DurableBrowserWorkspaceProjection {
            workspace_id: BrowserWorkspaceId::from("workspace-held"),
            profile_id: "profile-held".into(),
            identity_digest: "a".repeat(64),
            control_state: BrowserControlState::UserControlled,
            revision: 2,
            lease_generation: 2,
        });
        let ready = browser_projection(Some(&held));
        assert_eq!(ready.continue_status, OperationsStatus::Ready);
        assert_eq!(ready.status, OperationsStatus::WaitingUser);

        held.browser_workspace
            .as_mut()
            .expect("workspace")
            .control_state = BrowserControlState::AgentControlled;
        let agent = browser_projection(Some(&held));
        assert_eq!(agent.continue_status, OperationsStatus::NotImplemented);
        assert!(
            agent
                .next_action
                .contains("Take over remains NOT_IMPLEMENTED")
        );
    }

    #[test]
    fn artifact_mutations_are_disabled_until_the_owner_api_exists() {
        let product = WorkProductProjection {
            work_product_id: "work-product".into(),
            title: "Typed output".into(),
            work_product_type: "research_packet".into(),
            manifest_version: 1,
            work_product_revision: 2,
            preview_media_type: "text/plain".into(),
            preview_text: "preview".into(),
            preview_digest: "preview-digest".into(),
            manifest_digest: "manifest-digest".into(),
            adoption_status: WorkProductStatus::Draft,
            editable_scope_count: 0,
            evidence_count: 1,
        };
        let artifact = artifact_projection(&product);
        assert_eq!(artifact.actions.adopt, OperationsStatus::NotImplemented);
        assert_eq!(artifact.actions.reject, OperationsStatus::NotImplemented);
        assert_eq!(artifact.actions.rollback, OperationsStatus::NotImplemented);
    }

    #[test]
    fn reduced_motion_and_quick_entry_contracts_are_not_authority() {
        assert!(OperationsStatus::Ready.is_actionable());
        assert!(!OperationsStatus::NotImplemented.is_actionable());
        assert_eq!(OperationsStatus::RecoveryRequired.tone(), "blocked");
        let quick = QuickEntryProjection {
            status: OperationsStatus::Ready,
            hint: "same Mission".into(),
        };
        assert!(quick.hint.contains("Mission"));
    }

    #[test]
    fn workbench_css_covers_focus_reduced_motion_and_zoom() {
        let css = include_str!("../assets/main.css");
        assert!(css.contains(".agent-operations-workbench"));
        assert!(css.contains("button:focus-visible"));
        assert!(css.contains("@media (prefers-reduced-motion: reduce)"));
        assert!(css.contains("@media (max-width: 720px), (max-height: 520px)"));
        assert!(css.contains("overflow-wrap: anywhere"));
    }
}
