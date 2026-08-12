use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use dioxus::prelude::*;
use dioxus_icons::lucide::{
    ArrowUp, Bell, Blocks, BotMessageSquare, BriefcaseBusiness, CalendarDays, ChartNoAxesCombined,
    Check, ChevronDown, ContactRound, Ellipsis, FileCheck, FileText, FolderKanban, Handshake,
    House, Inbox, LayoutDashboard, ListChecks, Mail, MessageSquareText, PanelRightOpen, Pin,
    PlugZap, Plus, RefreshCw, Search, Settings, ShieldCheck, Sparkles, Square, Target, UsersRound,
    WalletCards, Workflow, X,
};
use hartevo_application::{
    ApplicationCheckpointHandlerStatus, ApplicationError, DesktopProjectProjection,
    MissionProjection, MissionRuntimeProjection, ProjectEncryptionReadiness,
};
use hartevo_catalog::{EvidenceLevel, MissionEvidenceStatus};
use hartevo_domain_kernel::{
    CadenceTriggerKind, KpiContract, KpiDirection, MissionCheckpointCompletionPolicy,
    MissionCheckpointExecutor, MissionCheckpointStatus, MissionConversationMessageId,
    MissionConversationMessageKind, MissionConversationRole, MissionId, MissionScheduleStatus,
    MissionStage, Money, OperatingMode, OutcomeDecision, OutcomeReviewCaveat,
    OutcomeReviewDecisionGateStatus, OutcomeReviewGateStatus, ProjectEncryptionMode, ProjectId,
    RuntimeProcessClaimStatus, RuntimeRecoveryStatus, RuntimeTurnStatus, StorageMode,
    WorkProductId, WorkProductStatus,
};
use rust_decimal::Decimal;
use zeroize::Zeroizing;

pub mod data_plane;
mod runtime_plane;
mod runtime_subscription;
#[cfg(feature = "visual-fixtures")]
mod visual_fixture;

use data_plane::{
    DesktopCatalogMissionRequest, DesktopDataError, DesktopDataPlane,
    DesktopHumanCheckpointConfirmationRequest, DesktopLoadState, DesktopMissionContinuationRequest,
    DesktopRuntimeCancellation, DesktopRuntimeProgressEvent, DesktopRuntimeProgressPhase,
    DesktopRuntimeTextStreamProjection, DesktopSnapshot, DesktopVm11OutcomeDecisionRequest,
    ProductEvidenceProjection, ProjectContextAccessProjection, ProjectContextAccessStatus,
    RecoveryKitDraft,
};
pub use runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

static MAIN_CSS: Asset = asset!("/assets/main.css");
static PROTOTYPE_CSS: Asset = asset!("/assets/prototype.css");
#[allow(
    dead_code,
    reason = "bundled source asset is used by the visual fixture surface"
)]
static PROTOTYPE_TREND_SVG: Asset = asset!("/assets/prototype-demand-trend.svg");
static BRAND_MARK_DATA_URL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "data:image/png;base64,{}",
        BASE64_STANDARD.encode(include_bytes!("../../../prototype/hartevo-logo-mark.png"))
    )
});

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Surface {
    Orchestrator,
    Current,
    Missions,
    ChannelOperations,
    Relationships,
    Partners,
    Connections,
    Outcomes,
    CapabilityEvidence,
    Settings,
    StateCoverage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UiIconName {
    ArrowUp,
    Bell,
    Blocks,
    Bot,
    Briefcase,
    Calendar,
    Chart,
    Check,
    ChevronDown,
    Contact,
    Ellipsis,
    FileCheck,
    FileText,
    Folder,
    Handshake,
    Home,
    Inbox,
    Layout,
    List,
    Mail,
    Message,
    Panel,
    Pin,
    Plug,
    Plus,
    Refresh,
    Search,
    Settings,
    Shield,
    Sparkles,
    Square,
    Target,
    Users,
    Wallet,
    Workflow,
    X,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppShortcut {
    DismissOverlays,
    GlobalSearch,
    NewTask,
    ProjectDispatcher,
    Settings,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ActiveOverlay {
    #[default]
    None,
    GlobalSearch,
    Notifications,
    ProjectSwitcher,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SearchTarget {
    Project(ProjectId),
    Mission(ProjectId, MissionId),
}

impl ActiveOverlay {
    fn toggle(self, target: Self) -> Self {
        if self == target { Self::None } else { target }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UiStateContract {
    code: &'static str,
    title: &'static str,
    detail: &'static str,
    action: &'static str,
    tone: &'static str,
}

const UI_STATE_CONTRACTS: [UiStateContract; 10] = [
    UiStateContract {
        code: "LOADING",
        title: "正在读取本地投影",
        detail: "保留当前导航与操作上下文，不用空白页代替加载反馈。",
        action: "请稍候",
        tone: "neutral",
    },
    UiStateContract {
        code: "EMPTY",
        title: "还没有可显示的记录",
        detail: "解释缺少的是哪类持久数据，并提供不会扩大权限的下一步。",
        action: "返回总调度",
        tone: "neutral",
    },
    UiStateContract {
        code: "OFFLINE",
        title: "当前处于离线模式",
        detail: "本地读取和草稿继续可用；Provider 写入、回调与独立验证保持暂停。",
        action: "查看离线边界",
        tone: "warning",
    },
    UiStateContract {
        code: "ERROR",
        title: "读取失败，未改变业务状态",
        detail: "错误反馈不包含 Secret、Token、Cookie、PII 或本机敏感路径。",
        action: "安全重试",
        tone: "error",
    },
    UiStateContract {
        code: "BLOCKED",
        title: "能力或环境阻塞",
        detail: "显示精确阻塞原因与解除条件；不得把 Provider 200 OK 当作业务完成。",
        action: "查看解除条件",
        tone: "warning",
    },
    UiStateContract {
        code: "WAITING_USER",
        title: "等待你的判断",
        detail: "保留 Mission、Checkpoint、草稿与已采用纠正，不清空无关分支。",
        action: "继续审阅",
        tone: "warning",
    },
    UiStateContract {
        code: "WAITING_APPROVAL",
        title: "外部动作等待精确审批",
        detail: "对象、受众、素材、金额、时间或账号变化都会使旧批准失效。",
        action: "审阅完整 Digest",
        tone: "warning",
    },
    UiStateContract {
        code: "HANDOFF",
        title: "人工已接管",
        detail: "旧 Worker 与 Browser generation 被硬停止；只有人工显式结束才能恢复。",
        action: "保持人工控制",
        tone: "info",
    },
    UiStateContract {
        code: "SUCCESS",
        title: "独立验证已通过",
        detail: "仅当业务 Oracle 与持久 Verification 明确成功时显示；视觉 fixture 不构成该证据。",
        action: "查看 Verification",
        tone: "success",
    },
    UiStateContract {
        code: "RECOVERY",
        title: "正在恢复安全执行代次",
        detail: "先 reconcile 持久 attempt 与 provider receipt；uncertain 永不自动重放。",
        action: "查看恢复账本",
        tone: "info",
    },
];

const CREATOR_WORK_STAGES: [&str; 12] = [
    "Offer / Listing",
    "Invite / Apply",
    "Award",
    "Task Accepted",
    "Funding Ready",
    "In Progress",
    "Deliverable Uploaded",
    "User Review",
    "Revision Requested",
    "Accepted",
    "Rights Recorded",
    "Payout Verified",
];

#[component]
fn UiIcon(name: UiIconName, #[props(default = 16)] size: u32) -> Element {
    match name {
        UiIconName::ArrowUp => rsx! { ArrowUp { size } },
        UiIconName::Bell => rsx! { Bell { size } },
        UiIconName::Blocks => rsx! { Blocks { size } },
        UiIconName::Bot => rsx! { BotMessageSquare { size } },
        UiIconName::Briefcase => rsx! { BriefcaseBusiness { size } },
        UiIconName::Calendar => rsx! { CalendarDays { size } },
        UiIconName::Chart => rsx! { ChartNoAxesCombined { size } },
        UiIconName::Check => rsx! { Check { size } },
        UiIconName::ChevronDown => rsx! { ChevronDown { size } },
        UiIconName::Contact => rsx! { ContactRound { size } },
        UiIconName::Ellipsis => rsx! { Ellipsis { size } },
        UiIconName::FileCheck => rsx! { FileCheck { size } },
        UiIconName::FileText => rsx! { FileText { size } },
        UiIconName::Folder => rsx! { FolderKanban { size } },
        UiIconName::Handshake => rsx! { Handshake { size } },
        UiIconName::Home => rsx! { House { size } },
        UiIconName::Inbox => rsx! { Inbox { size } },
        UiIconName::Layout => rsx! { LayoutDashboard { size } },
        UiIconName::List => rsx! { ListChecks { size } },
        UiIconName::Mail => rsx! { Mail { size } },
        UiIconName::Message => rsx! { MessageSquareText { size } },
        UiIconName::Panel => rsx! { PanelRightOpen { size } },
        UiIconName::Pin => rsx! { Pin { size } },
        UiIconName::Plug => rsx! { PlugZap { size } },
        UiIconName::Plus => rsx! { Plus { size } },
        UiIconName::Refresh => rsx! { RefreshCw { size } },
        UiIconName::Search => rsx! { Search { size } },
        UiIconName::Settings => rsx! { Settings { size } },
        UiIconName::Shield => rsx! { ShieldCheck { size } },
        UiIconName::Sparkles => rsx! { Sparkles { size } },
        UiIconName::Square => rsx! { Square { size } },
        UiIconName::Target => rsx! { Target { size } },
        UiIconName::Users => rsx! { UsersRound { size } },
        UiIconName::Wallet => rsx! { WalletCards { size } },
        UiIconName::Workflow => rsx! { Workflow { size } },
        UiIconName::X => rsx! { X { size } },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UiFailure {
    code: String,
    message: String,
}

struct SensitiveRecoveryInput {
    value: Zeroizing<String>,
}

impl Default for SensitiveRecoveryInput {
    fn default() -> Self {
        Self {
            value: Zeroizing::new(String::new()),
        }
    }
}

impl SensitiveRecoveryInput {
    fn replace(&mut self, value: String) {
        self.value = Zeroizing::new(value);
    }

    fn expose_for_submission(&self) -> &str {
        self.value.as_str()
    }

    fn has_valid_shape(&self) -> bool {
        let value = self.value.trim();
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    fn clear(&mut self) {
        self.value = Zeroizing::new(String::new());
    }
}

impl std::fmt::Debug for SensitiveRecoveryInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveRecoveryInput([REDACTED])")
    }
}

impl UiFailure {
    fn from_error(error: &DesktopDataError) -> Self {
        match error {
            DesktopDataError::MissingDatabaseKey => Self {
                code: "BLOCKED_ENV".into(),
                message: "本地数据库仍在，但 OS Vault 中的密钥不存在。Hartevo 不会生成新密钥覆盖现有数据；请进入恢复或支持流程。".into(),
            },
            DesktopDataError::ProjectEncryptionNotReady(_) => Self {
                code: "NOT_IMPLEMENTED".into(),
                message: "该项目尚无可用且无需轮换的加密 Keyring。安全 Recovery Kit 导出流程完成前，不会从 Desktop 创建 Mission。".into(),
            },
            DesktopDataError::ProjectContextRecoveryRequired(_) => Self {
                code: "RECOVERY_REQUIRED".into(),
                message: "Keyring 存在，但本机设备没有可用的 exact wrapping key。恢复或设备附加完成前不会创建 Mission 或打开项目内容。".into(),
            },
            DesktopDataError::ProjectContextBlockedEnvironment(_) => Self {
                code: "BLOCKED_ENV".into(),
                message: "项目工作区当前无法安全打开；未读取 Context 内容，也未创建 Mission。".into(),
            },
            DesktopDataError::ProjectContextIntegrityError(_) => Self {
                code: "INTEGRITY_ERROR".into(),
                message: "项目 Keyring、SecretReference 或 encrypted Context 未通过完整性校验；Hartevo 已停止该项目执行。".into(),
            },
            DesktopDataError::EmptyMissionGoal | DesktopDataError::EmptyProjectName => Self {
                code: "WAITING_USER".into(),
                message: "项目名称与 Mission 目标不能为空。".into(),
            },
            DesktopDataError::InvalidCatalogMissionContract => Self {
                code: "WAITING_USER".into(),
                message: "请选择明确的 VM-00～VM-11 路由与允许的运行模式，并确认市场、语言、受众、时区、ISO 币种和非负 minor-unit 预算。未创建 Mission。".into(),
            },
            DesktopDataError::InvalidMissionContinuation => Self {
                code: "WAITING_USER".into(),
                message: "同一 Mission 的续写消息与稳定幂等键不能为空；未新增 Conversation 消息，也未运行 Runtime。".into(),
            },
            DesktopDataError::InvalidHumanCheckpointConfirmation => Self {
                code: "WAITING_USER".into(),
                message: "Human Checkpoint 确认必须绑定当前 Mission/Checkpoint revision、持久 Conversation、非空确认和稳定幂等键；未写入部分状态。".into(),
            },
            DesktopDataError::InvalidVm11OutcomeDecision => Self {
                code: "WAITING_USER".into(),
                message: "VM-11 决策必须选择一个当前可用的结构化动作，填写私密理由，并绑定冻结 Review 与当前 CAS revision；未写入部分状态。".into(),
            },
            DesktopDataError::InvalidRecoveryKey => Self {
                code: "WAITING_USER".into(),
                message: "Recovery Kit 必须是此前导出的 64 位十六进制密钥；Hartevo 不会代替用户保存或猜测恢复密钥。".into(),
            },
            DesktopDataError::ProjectNotFound(_)
            | DesktopDataError::ProjectEncryptionAlreadyProvisioned(_) => Self {
                code: "STALE_SELECTION".into(),
                message: "当前项目已变化，请刷新后重试。".into(),
            },
            DesktopDataError::ProjectRecoveryNotApplicable(_) => Self {
                code: "RECOVERY_UNAVAILABLE".into(),
                message: "该项目不是可由单一用户自持 Recovery Kit 恢复的个人 Keyring；Hartevo 未尝试修改任何设备 envelope。".into(),
            },
            DesktopDataError::DataDirectoryUnavailable
            | DesktopDataError::InvalidDataRoot(_)
            | DesktopDataError::Io(_)
            | DesktopDataError::SecretStore(_) => Self {
                code: "BLOCKED_ENV".into(),
                message: "本机数据目录或 OS Secret Store 当前不可用；未写入任何项目或外部系统。".into(),
            },
            DesktopDataError::Application(ApplicationError::RuntimeProcessCleanupBlocked {
                ..
            }) => Self {
                code: "BLOCKED_ENV".into(),
                message: "此前认领的本机 Runtime 进程无法被精确检查或终止。Hartevo 不会按 PID 猜测清理，也不会启动第二个 Runtime；请保留现场并进入支持恢复流程。".into(),
            },
            DesktopDataError::Application(
                ApplicationError::StructuredOutcomeDecisionRequired
                | ApplicationError::StructuredOutcomeDecisionCommandMismatch,
            ) => Self {
                code: "WAITING_USER".into(),
                message: "该 VM-11 Checkpoint 不接受自由文本冒充决策；请选择 Continue、Stop、Scale 或 Test，并填写理由。".into(),
            },
            DesktopDataError::Application(
                ApplicationError::StructuredOutcomeDecisionUnavailable
                | ApplicationError::StructuredOutcomeDecisionReviewMismatch
                | ApplicationError::StructuredOutcomeDecisionReplayMismatch,
            ) => Self {
                code: "STALE_DECISION".into(),
                message: "冻结 Outcome Review 或 Mission/Conversation revision 已变化；请刷新后重新审阅，旧决策未被写入或重放。".into(),
            },
            DesktopDataError::Storage(_)
            | DesktopDataError::Application(_)
            | DesktopDataError::Catalog(_) => Self {
                code: "INTEGRITY_ERROR".into(),
                message: "持久状态或机器合同未通过完整性校验；Hartevo 已停止继续执行。".into(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum DesktopBackendState {
    Uninitialized(ProductEvidenceProjection),
    Ready(Box<DesktopSnapshot>),
    Failed(UiFailure),
}

#[derive(Clone, Debug, PartialEq)]
struct DesktopUiModel {
    backend: DesktopBackendState,
    selected_project_id: Option<ProjectId>,
    selected_mission_id: Option<MissionId>,
    notice: Option<UiFailure>,
}

impl DesktopUiModel {
    fn load() -> Self {
        #[cfg(feature = "visual-fixtures")]
        if let Some(model) = visual_fixture::load_from_environment() {
            return model;
        }
        match DesktopDataPlane::discover().and_then(|plane| plane.load_os(Utc::now())) {
            Ok(DesktopLoadState::Uninitialized { product_evidence }) => Self {
                backend: DesktopBackendState::Uninitialized(product_evidence),
                selected_project_id: None,
                selected_mission_id: None,
                notice: None,
            },
            Ok(DesktopLoadState::Ready(snapshot)) => {
                let mut model = Self {
                    backend: DesktopBackendState::Ready(snapshot),
                    selected_project_id: None,
                    selected_mission_id: None,
                    notice: None,
                };
                model.restore_valid_selection(false);
                model
            }
            Err(error) => Self {
                backend: DesktopBackendState::Failed(UiFailure::from_error(&error)),
                selected_project_id: None,
                selected_mission_id: None,
                notice: None,
            },
        }
    }

    fn set_ready(&mut self, snapshot: DesktopSnapshot, select_latest_mission: bool) {
        self.backend = DesktopBackendState::Ready(Box::new(snapshot));
        self.notice = None;
        self.restore_valid_selection(select_latest_mission);
    }

    fn set_notice(&mut self, error: &DesktopDataError) {
        self.notice = Some(UiFailure::from_error(error));
    }

    fn restore_valid_selection(&mut self, select_latest_mission: bool) {
        let DesktopBackendState::Ready(snapshot) = &self.backend else {
            self.selected_project_id = None;
            self.selected_mission_id = None;
            return;
        };
        let selected_project = self
            .selected_project_id
            .as_ref()
            .and_then(|id| {
                snapshot
                    .inventory
                    .projects
                    .iter()
                    .find(|project| &project.project_id == id)
            })
            .or_else(|| snapshot.inventory.projects.first());
        self.selected_project_id = selected_project.map(|project| project.project_id.clone());
        let Some(project) = selected_project else {
            self.selected_mission_id = None;
            return;
        };
        let existing_is_valid = !select_latest_mission
            && self.selected_mission_id.as_ref().is_some_and(|id| {
                project
                    .missions
                    .iter()
                    .any(|mission| &mission.mission_id == id)
            });
        if !existing_is_valid {
            self.selected_mission_id = project
                .missions
                .last()
                .map(|mission| mission.mission_id.clone());
        }
    }

    fn select_project(&mut self, project_id: &ProjectId) {
        let DesktopBackendState::Ready(snapshot) = &self.backend else {
            return;
        };
        let Some(project) = snapshot
            .inventory
            .projects
            .iter()
            .find(|project| &project.project_id == project_id)
        else {
            return;
        };
        self.selected_project_id = Some(project.project_id.clone());
        self.selected_mission_id = project
            .missions
            .last()
            .map(|mission| mission.mission_id.clone());
        self.notice = None;
    }

    fn select_mission(&mut self, mission_id: MissionId) {
        if self.current_project().is_some_and(|project| {
            project
                .missions
                .iter()
                .any(|mission| mission.mission_id == mission_id)
        }) {
            self.selected_mission_id = Some(mission_id);
            self.notice = None;
        }
    }

    fn select_dispatcher(&mut self) {
        if self.current_project().is_some() {
            self.selected_mission_id = None;
            self.notice = None;
        }
    }

    fn current_project(&self) -> Option<&DesktopProjectProjection> {
        let DesktopBackendState::Ready(snapshot) = &self.backend else {
            return None;
        };
        let project_id = self.selected_project_id.as_ref()?;
        snapshot
            .inventory
            .projects
            .iter()
            .find(|project| &project.project_id == project_id)
    }

    fn current_mission(&self) -> Option<&MissionProjection> {
        let mission_id = self.selected_mission_id.as_ref()?;
        self.current_project()?
            .missions
            .iter()
            .find(|mission| &mission.mission_id == mission_id)
    }

    fn current_context_access(&self) -> Option<&ProjectContextAccessProjection> {
        let DesktopBackendState::Ready(snapshot) = &self.backend else {
            return None;
        };
        let project_id = self.selected_project_id.as_ref()?;
        snapshot.context_access_for(project_id)
    }

    fn current_runtime_activity(&self) -> Option<&MissionRuntimeProjection> {
        let DesktopBackendState::Ready(snapshot) = &self.backend else {
            return None;
        };
        let project_id = self.selected_project_id.as_ref()?;
        let mission_id = self.selected_mission_id.as_ref()?;
        snapshot.runtime_activity.iter().find(|activity| {
            &activity.project_id == project_id && &activity.mission_id == mission_id
        })
    }

    fn product_evidence(&self) -> Option<&ProductEvidenceProjection> {
        match &self.backend {
            DesktopBackendState::Uninitialized(evidence) => Some(evidence),
            DesktopBackendState::Ready(snapshot) => Some(&snapshot.product_evidence),
            DesktopBackendState::Failed(_) => None,
        }
    }

    fn can_start_mission(&self) -> bool {
        self.current_project().is_some_and(|project| {
            matches!(
                &project.encryption,
                ProjectEncryptionReadiness::Ready { .. }
            )
        }) && self.current_context_access().is_some_and(|access| {
            matches!(
                access.status,
                ProjectContextAccessStatus::Ready { .. }
                    | ProjectContextAccessStatus::Degraded { .. }
            )
        })
    }
}

#[component]
pub fn App() -> Element {
    let desktop_context = dioxus::desktop::use_window();
    let visual_zoom = active_visual_zoom();
    let visual_fixture_mode = active_visual_fixture_id().is_some();
    let initial_visual_runtime_text_stream = active_visual_runtime_text_stream();
    let visual_persisted_stream_fixture = initial_visual_runtime_text_stream.is_some();
    let visual_streaming_fixture = visual_fixture_mode
        && matches!(
            active_visual_surface_variant().as_deref(),
            Some("mission-streaming" | "mission-persisted-stream")
        );
    use_effect(move || desktop_context.set_zoom_level(visual_zoom));
    let mut surface = use_signal(initial_surface);
    let mut model = use_signal(DesktopUiModel::load);
    let mut draft = use_signal(String::new);
    let mut catalog_manifest_id = use_signal(String::new);
    let mut catalog_mode = use_signal(String::new);
    let mut catalog_market = use_signal(String::new);
    let mut catalog_language = use_signal(String::new);
    let mut catalog_audience = use_signal(String::new);
    let mut catalog_timezone = use_signal(String::new);
    let mut catalog_currency = use_signal(|| "USD".to_owned());
    let mut catalog_budget_minor = use_signal(|| "0".to_owned());
    let mut catalog_parent_mission_id = use_signal(String::new);
    let mut catalog_kpi_metric = use_signal(|| "lead_qualified_count".to_owned());
    let mut catalog_kpi_baseline = use_signal(|| "0".to_owned());
    let mut catalog_kpi_target = use_signal(|| "1".to_owned());
    let mut catalog_kpi_unit = use_signal(|| "count".to_owned());
    let mut catalog_kpi_direction = use_signal(|| "at_least".to_owned());
    let mut catalog_contract_expanded = use_signal(|| false);
    let mut mission_submitting = use_signal(move || visual_streaming_fixture);
    let mut runtime_retrying = use_signal(|| false);
    let mut runtime_cancellation =
        use_signal(move || visual_streaming_fixture.then(DesktopRuntimeCancellation::default));
    let mut runtime_stop_requested = use_signal(|| false);
    let mut runtime_progress = use_signal(move || {
        if visual_streaming_fixture {
            vec![
                DesktopRuntimeProgressEvent {
                    sequence: 1,
                    phase: DesktopRuntimeProgressPhase::Preparing,
                },
                DesktopRuntimeProgressEvent {
                    sequence: 2,
                    phase: DesktopRuntimeProgressPhase::Dispatched,
                },
                DesktopRuntimeProgressEvent {
                    sequence: 3,
                    phase: DesktopRuntimeProgressPhase::TurnStarted,
                },
                DesktopRuntimeProgressEvent {
                    sequence: 4,
                    phase: DesktopRuntimeProgressPhase::ItemStarted,
                },
            ]
        } else {
            Vec::new()
        }
    });
    let mut runtime_text_scope = use_signal(|| None::<(ProjectId, MissionId)>);
    let mut runtime_text_stream = use_signal(move || initial_visual_runtime_text_stream);
    let mut runtime_text_error = use_signal(|| None::<UiFailure>);
    let mut runtime_follow_latest = use_signal(|| true);
    let mut runtime_has_unseen = use_signal(|| false);
    let mut composer_expanded = use_signal(|| false);
    let mut composer_guidance_dismissed = use_signal(|| false);
    let mut human_work_product_selection = use_signal(BTreeSet::<WorkProductId>::new);
    let mut vm11_outcome_action = use_signal(|| None::<(MissionId, OutcomeDecision)>);
    let mut workpad_open = use_signal(initial_workpad_open);
    let mut global_search_query = use_signal(String::new);
    let mut active_overlay = use_signal(ActiveOverlay::default);
    let mut composer_tool_menu = use_signal(|| false);
    let mut runtime_profile_open = use_signal(|| false);
    let mut fixture_attachment_visible = use_signal(|| false);
    let mut mission_menu_id = use_signal(|| None::<MissionId>);
    let mut current_object_menu = use_signal(|| false);
    let mut current_object_pinned = use_signal(|| false);
    let mut surface_before_settings = use_signal(|| Surface::Orchestrator);
    use_effect(move || {
        if visual_fixture_mode {
            return;
        }
        let selected_scope = {
            let current = model.read();
            current
                .selected_project_id
                .clone()
                .zip(current.selected_mission_id.clone())
        };
        let scope_changed = runtime_text_scope.peek().as_ref() != selected_scope.as_ref();
        if scope_changed {
            runtime_text_scope.set(selected_scope.clone());
            runtime_text_stream.set(None);
            runtime_text_error.set(None);
            runtime_follow_latest.set(true);
            runtime_has_unseen.set(false);
        }
        let Some((project_id, mission_id)) = selected_scope else {
            return;
        };
        spawn(async move {
            let query_project_id = project_id.clone();
            let query_mission_id = mission_id.clone();
            let result = tokio::task::spawn_blocking(move || {
                DesktopDataPlane::discover().and_then(|plane| {
                    plane.runtime_text_stream_os(&query_project_id, &query_mission_id, Utc::now())
                })
            })
            .await;
            if !desktop_scope_is_selected(model, &project_id, &mission_id) {
                return;
            }
            match result {
                Ok(Ok(projection)) => {
                    runtime_text_error.set(None);
                    update_runtime_text_stream(
                        projection,
                        runtime_text_stream,
                        runtime_follow_latest,
                        runtime_has_unseen,
                    );
                }
                Ok(Err(error)) => {
                    runtime_text_stream.set(None);
                    runtime_text_error.set(Some(UiFailure::from_error(&error)));
                }
                Err(_) => {
                    runtime_text_stream.set(None);
                    runtime_text_error.set(Some(UiFailure {
                        code: "RUNTIME_STREAM_QUERY_FAILED".into(),
                        message: "持久 Runtime 正文查询异常结束；正文保持隐藏，Mission 与 Runtime ledger 未改变。".into(),
                    }));
                }
            }
        });
    });
    let view = model.read().clone();
    let current_surface = surface();
    let project = view.current_project().cloned();
    let mission = view.current_mission().cloned();
    let context_access = view.current_context_access().cloned();
    let runtime_activity = view.current_runtime_activity().cloned();
    let project_name = project
        .as_ref()
        .map_or_else(|| "未选择项目".to_owned(), |item| item.name.clone());
    let mission_title = mission
        .as_ref()
        .map_or_else(|| "项目总调度".to_owned(), |item| item.title.clone());
    let status = status_label(&view);
    let surface_heading = surface_heading(current_surface, &mission_title);
    let surface_context = surface_context_label(current_surface);
    let workpad_visible =
        workpad_open() && current_surface == Surface::Orchestrator && mission.is_some();
    let runtime_busy = mission_submitting() || runtime_retrying();
    let runtime_stop_available = runtime_cancellation.read().is_some();
    let project_can_start_mission = view.can_start_mission();
    let evidence = view.product_evidence().cloned();
    let project_storage_status = project
        .as_ref()
        .map_or("本地数据层未就绪", project_storage_label);
    let composer_target = if mission.is_some() {
        "当前 Mission 持久会话"
    } else {
        "项目总调度 · 新建 Catalog Mission"
    };
    let catalog_routes = evidence
        .as_ref()
        .map_or_else(Vec::new, |evidence| evidence.missions.clone());
    let catalog_routes_for_selection = catalog_routes.clone();
    let selected_manifest_id = catalog_manifest_id();
    let selected_catalog_route = catalog_routes
        .iter()
        .find(|route| route.mission_id == selected_manifest_id)
        .cloned();
    let allowed_modes = selected_catalog_route
        .as_ref()
        .map_or_else(Vec::new, |route| route.modes.clone());
    let selected_mode = catalog_mode();
    let selected_mode_is_allowed = allowed_modes.iter().any(|mode| mode == &selected_mode);
    let vm11_selected = selected_manifest_id == "VM-11";
    let current_catalog_digest = evidence
        .as_ref()
        .map(|evidence| evidence.catalog_digest.as_str());
    let parent_mission_candidates = project.as_ref().map_or_else(Vec::new, |project| {
        project
            .missions
            .iter()
            .filter(|mission| {
                mission
                    .manifest_id
                    .as_deref()
                    .is_some_and(|manifest_id| manifest_id != "VM-11")
                    && mission.catalog_digest.as_deref() == current_catalog_digest
            })
            .map(|mission| {
                (
                    mission.mission_id.clone(),
                    format!(
                        "{} · {}",
                        mission.manifest_id.as_deref().unwrap_or("UNKNOWN"),
                        mission.title
                    ),
                )
            })
            .collect::<Vec<_>>()
    });
    let parent_mission_id_value = catalog_parent_mission_id();
    let selected_parent_exists = parent_mission_candidates
        .iter()
        .any(|(mission_id, _)| mission_id.as_str() == parent_mission_id_value);
    let market_value = catalog_market();
    let language_value = catalog_language();
    let audience_value = catalog_audience();
    let timezone_value = catalog_timezone();
    let currency_value = catalog_currency();
    let budget_minor_value = catalog_budget_minor();
    let budget_minor = budget_minor_value
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|amount| *amount >= 0);
    let kpi_metric_value = catalog_kpi_metric();
    let kpi_baseline_value = catalog_kpi_baseline();
    let kpi_target_value = catalog_kpi_target();
    let kpi_unit_value = catalog_kpi_unit();
    let kpi_direction_value = catalog_kpi_direction();
    let catalog_kpis = catalog_kpi_contracts(
        &selected_manifest_id,
        &kpi_metric_value,
        &kpi_baseline_value,
        &kpi_target_value,
        &kpi_unit_value,
        &kpi_direction_value,
    );
    let mission_specific_contract_ready = if vm11_selected {
        selected_parent_exists
    } else {
        catalog_kpis.as_ref().is_some_and(|kpis| !kpis.is_empty())
    };
    let catalog_contract_ready = !selected_manifest_id.is_empty()
        && selected_mode_is_allowed
        && operating_mode_from_catalog_name(&selected_mode).is_some()
        && !draft.read().trim().is_empty()
        && mission_specific_contract_ready
        && (vm11_selected
            || (!market_value.trim().is_empty()
                && !language_value.trim().is_empty()
                && !audience_value.trim().is_empty()
                && !timezone_value.trim().is_empty()
                && valid_currency_shape(&currency_value)
                && budget_minor.is_some()));
    let can_edit_catalog = project_can_start_mission && mission.is_none() && !runtime_busy;
    let can_submit_catalog = can_edit_catalog && catalog_contract_ready;
    let human_route_active = mission.as_ref().is_some_and(|mission| {
        mission.current_checkpoint_executor == Some(MissionCheckpointExecutor::Human)
            && mission.current_checkpoint_completion_policy
                == Some(MissionCheckpointCompletionPolicy::HumanConfirmation)
            && mission.current_checkpoint_status == Some(MissionCheckpointStatus::Running)
            && mission.current_checkpoint_id.is_some()
            && mission.current_checkpoint_revision.is_some()
            && mission.conversation_revision.is_some()
    });
    let application_route_active = mission.as_ref().is_some_and(|mission| {
        mission.current_checkpoint_executor == Some(MissionCheckpointExecutor::Application)
            && mission.current_checkpoint_application_handler_status
                == Some(ApplicationCheckpointHandlerStatus::Implemented)
            && mission.current_checkpoint_completion_policy
                == Some(MissionCheckpointCompletionPolicy::DeterministicEvidence)
            && matches!(
                mission.current_checkpoint_status,
                Some(MissionCheckpointStatus::Running | MissionCheckpointStatus::Blocked)
            )
            && mission.current_checkpoint_id.is_some()
    });
    let application_route_not_implemented = mission.as_ref().is_some_and(|mission| {
        mission.current_checkpoint_executor == Some(MissionCheckpointExecutor::Application)
            && mission.current_checkpoint_application_handler_status
                == Some(ApplicationCheckpointHandlerStatus::NotImplemented)
    });
    let application_route_catalog_mismatch = mission.as_ref().is_some_and(|mission| {
        mission.current_checkpoint_executor == Some(MissionCheckpointExecutor::Application)
            && mission.current_checkpoint_application_handler_status
                == Some(ApplicationCheckpointHandlerStatus::CatalogRevisionMismatch)
    });
    let runtime_progress_events = runtime_progress.read().clone();
    let recent_runtime_progress = runtime_progress_events
        .iter()
        .rev()
        .take(4)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let active_operation_label = runtime_progress_events.last().map_or_else(
        || {
            if runtime_retrying() {
                "正在安全恢复本地 Runtime"
            } else if application_route_active {
                "正在运行确定性 Application Checkpoint"
            } else if human_route_active {
                "正在原子确认 Human Checkpoint"
            } else if mission.is_some() {
                "正在续写同一 Mission"
            } else {
                "正在固化 Operating Contract 与首个 Checkpoint"
            }
        },
        |event| desktop_runtime_progress_display_label(event.phase, visual_streaming_fixture),
    );
    let application_route_boundary_code = if application_route_catalog_mismatch {
        "BLOCKED_CATALOG_REVISION"
    } else {
        "NOT_IMPLEMENTED"
    };
    let application_route_boundary_detail = if application_route_catalog_mismatch {
        "该 Mission 绑定的 Catalog digest 与当前二进制不同；必须显式迁移或重建合同，不能把新 handler 权限静默授予旧 Mission。"
    } else {
        "当前路由没有进入本二进制的版本化 handler allow-list。"
    };
    let human_checkpoint_id_label = mission
        .as_ref()
        .and_then(|mission| mission.current_checkpoint_id.as_deref())
        .unwrap_or("UNKNOWN")
        .to_owned();
    let application_checkpoint_id_label = human_checkpoint_id_label.clone();
    let human_oracle_label = mission.as_ref().map_or_else(String::new, |mission| {
        mission
            .current_checkpoint_oracle_ids
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(" + ")
    });
    let human_requires_work_product = mission.as_ref().is_some_and(|mission| {
        mission
            .current_checkpoint_oracle_ids
            .contains("work_product")
    });
    let vm11_outcome_decision_active = human_route_active
        && mission.as_ref().is_some_and(|mission| {
            mission.manifest_id.as_deref() == Some("VM-11")
                && mission.current_checkpoint_id.as_deref() == Some("continue_stop_scale_test")
        });
    let vm11_outcome_review = mission
        .as_ref()
        .and_then(|mission| mission.vm11_outcome_review.clone());
    let selected_vm11_action =
        vm11_outcome_action
            .read()
            .as_ref()
            .and_then(|(selected_mission_id, action)| {
                mission
                    .as_ref()
                    .filter(|mission| mission.mission_id == *selected_mission_id)
                    .map(|_| action.clone())
            });
    let selected_vm11_action_available = selected_vm11_action.as_ref().is_some_and(|action| {
        vm11_outcome_review.as_ref().is_some_and(|projection| {
            projection.action_gates.iter().any(|gate| {
                gate.action == *action && gate.status == OutcomeReviewDecisionGateStatus::Available
            })
        })
    });
    let available_human_work_product_ids = mission.as_ref().map_or_else(BTreeSet::new, |mission| {
        mission
            .work_products
            .iter()
            .map(|product| product.work_product_id.clone())
            .collect()
    });
    let selected_human_work_product_ids = human_work_product_selection
        .read()
        .iter()
        .filter(|work_product_id| available_human_work_product_ids.contains(*work_product_id))
        .cloned()
        .collect::<BTreeSet<_>>();
    let can_edit_human_confirmation =
        project_can_start_mission && human_route_active && !runtime_busy;
    let can_submit_human_confirmation = can_edit_human_confirmation
        && !vm11_outcome_decision_active
        && !draft.read().trim().is_empty()
        && (!human_requires_work_product || !selected_human_work_product_ids.is_empty());
    let can_submit_vm11_outcome_decision = can_edit_human_confirmation
        && vm11_outcome_decision_active
        && selected_vm11_action_available
        && !draft.read().trim().is_empty();
    let can_execute_application_route =
        project_can_start_mission && application_route_active && !runtime_busy;
    let can_edit_continuation = project_can_start_mission
        && !human_route_active
        && mission.as_ref().is_some_and(|mission| {
            mission.conversation_revision.is_some()
                && matches!(
                    mission.stage,
                    MissionStage::Running
                        | MissionStage::Blocked
                        | MissionStage::WaitingUser
                        | MissionStage::WaitingApproval
                        | MissionStage::Scheduled
                        | MissionStage::CycleReviewed
                )
        })
        && !runtime_busy;
    let can_write_composer =
        can_edit_catalog || can_edit_continuation || can_edit_human_confirmation;
    let can_submit_continuation = can_edit_continuation && !draft.read().trim().is_empty();
    let runtime_projection = match &view.backend {
        DesktopBackendState::Ready(snapshot) => Some(snapshot.runtime.clone()),
        DesktopBackendState::Uninitialized(_) | DesktopBackendState::Failed(_) => None,
    };
    let runtime_chip = runtime_projection.as_ref().map_or_else(
        || "Runtime · 数据层未就绪".to_owned(),
        |runtime| format!("Runtime · {}", runtime_availability_label(runtime.status)),
    );
    let provider_chip = runtime_projection.as_ref().map_or_else(
        || "Provider · 未配置".to_owned(),
        |runtime| {
            let route = match (&runtime.provider, &runtime.model) {
                (Some(provider), Some(model)) => format!("{provider}/{model}"),
                _ => "未配置".to_owned(),
            };
            format!("Provider · {route} · 无业务 Receipt")
        },
    );
    let runtime_retry_needed = mission.as_ref().is_some_and(|mission| {
        mission_runtime_retry_needed(&mission.stage, runtime_activity.as_ref())
    });
    let runtime_environment_ready = runtime_projection.as_ref().is_some_and(|runtime| {
        matches!(
            runtime.status,
            DesktopRuntimeAvailabilityStatus::ReadyDevelopment
                | DesktopRuntimeAvailabilityStatus::ReadyDistribution
        )
    });
    let can_retry_runtime = runtime_retry_needed && runtime_environment_ready && !runtime_busy;
    let keyboard_has_project = project.is_some();
    let visual_fixture_id = active_visual_fixture_id();
    let visual_fixture_active = visual_fixture_id.is_some();
    let current_object_deep_link = mission.as_ref().map_or_else(
        || {
            project.as_ref().map_or_else(
                || "hartevo://dispatcher".to_owned(),
                |project| format!("hartevo://project/{}", project.project_id),
            )
        },
        |mission| format!("hartevo://mission/{}", mission.mission_id),
    );
    let notification_count = active_visual_notification_count();
    let visual_surface_variant = active_visual_surface_variant();
    let (composer_guidance_title, composer_guidance_action) =
        match visual_surface_variant.as_deref() {
            Some("mission-approval") => (
                "外部动作仍在等待确认；你也可以直接修改预算、渠道或停止条件",
                "修改计划",
            ),
            Some("mission-outcome") => (
                "结果区只是结构预览；你可以返回审批或写下下一步判断",
                "写下下一步",
            ),
            _ if mission.is_some() => (
                "继续说，随时调整当前 Mission 的范围、优先级或停止条件",
                "调整方向",
            ),
            _ => (
                "你可以随时创建、暂停或重排多个任务，不需要先选择功能模块",
                "描述任务",
            ),
        };
    let composer_guidance_visible = !composer_guidance_dismissed()
        && !composer_expanded()
        && !runtime_busy
        && visual_surface_variant.as_deref() != Some("mission-streaming");
    let running_missions = project.as_ref().map_or_else(Vec::new, |project| {
        project
            .missions
            .iter()
            .filter(|mission| {
                !matches!(
                    mission.stage,
                    MissionStage::Scheduled
                        | MissionStage::Completed
                        | MissionStage::Cancelled
                        | MissionStage::Failed
                )
            })
            .take(4)
            .cloned()
            .collect::<Vec<_>>()
    });
    let scheduled_missions = project.as_ref().map_or_else(Vec::new, |project| {
        project
            .missions
            .iter()
            .filter(|mission| mission.stage == MissionStage::Scheduled)
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
    });
    let waiting_count = project.as_ref().map_or(0, |project| {
        project
            .missions
            .iter()
            .filter(|mission| {
                matches!(
                    mission.stage,
                    MissionStage::WaitingUser | MissionStage::WaitingApproval
                )
            })
            .count()
    });
    let mission_count = project.as_ref().map_or(0, |project| project.missions.len());

    rsx! {
        document::Title { "Hartevo Desktop" }
        document::Stylesheet { href: MAIN_CSS }
        document::Stylesheet { href: PROTOTYPE_CSS }
        div {
            class: "desktop-shell",
            tabindex: "-1",
            onkeydown: move |event| {
                match app_shortcut(&event.key(), event.modifiers()) {
                    Some(AppShortcut::DismissOverlays) => {
                        let focus_target = if current_object_menu() {
                            Some("current-object-menu-trigger".to_owned())
                        } else if composer_tool_menu() {
                            Some("composer-tool-trigger".to_owned())
                        } else if runtime_profile_open() {
                            Some("runtime-profile-trigger".to_owned())
                        } else if let Some(mission_id) = mission_menu_id.read().clone() {
                            Some(format!("mission-menu-trigger-{}", mission_id.as_str()))
                        } else {
                            match active_overlay() {
                                ActiveOverlay::GlobalSearch => Some("global-search-trigger".to_owned()),
                                ActiveOverlay::Notifications => Some("notification-center-trigger".to_owned()),
                                ActiveOverlay::ProjectSwitcher => Some("project-switcher-trigger".to_owned()),
                                ActiveOverlay::None => None,
                            }
                        };
                        active_overlay.set(ActiveOverlay::None);
                        composer_tool_menu.set(false);
                        runtime_profile_open.set(false);
                        mission_menu_id.set(None);
                        current_object_menu.set(false);
                        composer_expanded.set(false);
                        let _ = dioxus::document::eval(
                            "document.getElementById('mission-composer-input')?.blur()",
                        );
                        if let Some(focus_target) = focus_target {
                            restore_ui_focus(&focus_target);
                        }
                        if current_surface == Surface::Settings {
                            surface.set(surface_before_settings());
                        }
                    }
                    Some(AppShortcut::GlobalSearch) => {
                        event.prevent_default();
                        active_overlay.set(ActiveOverlay::GlobalSearch);
                        restore_ui_focus("global-search-input");
                    }
                    Some(AppShortcut::NewTask) => {
                        event.prevent_default();
                        if keyboard_has_project {
                            model.write().select_dispatcher();
                            surface.set(Surface::Orchestrator);
                            catalog_contract_expanded.set(true);
                            composer_expanded.set(true);
                            let _ = dioxus::document::eval(
                                "requestAnimationFrame(() => document.getElementById('mission-composer-input')?.focus())",
                            );
                        }
                    }
                    Some(AppShortcut::ProjectDispatcher) => {
                        event.prevent_default();
                        if keyboard_has_project {
                            model.write().select_dispatcher();
                            active_overlay.set(ActiveOverlay::None);
                            surface.set(Surface::Orchestrator);
                            composer_expanded.set(true);
                            let _ = dioxus::document::eval(
                                "requestAnimationFrame(() => document.getElementById('mission-composer-input')?.focus())",
                            );
                        }
                    }
                    Some(AppShortcut::Settings) => {
                        event.prevent_default();
                        if current_surface != Surface::Settings {
                            surface_before_settings.set(current_surface);
                        }
                        surface.set(Surface::Settings);
                    }
                    None => {}
                }
            },
            header { class: "app-chrome",
                div { class: "brand-bar",
                    img { src: BRAND_MARK_DATA_URL.as_str(), alt: "Hartevo" }
                    strong { class: "brand-name", "Hartevo" }
                    div { class: "brand-global-actions",
                        button {
                            id: "global-search-trigger",
                            class: if active_overlay() == ActiveOverlay::GlobalSearch { "brand-action active" } else { "brand-action" },
                            aria_label: "搜索所有项目与任务",
                            title: "搜索所有项目与任务",
                            onclick: move |_| {
                                active_overlay.set(ActiveOverlay::GlobalSearch);
                                restore_ui_focus("global-search-input");
                            },
                            UiIcon { name: UiIconName::Search, size: 15 }
                        }
                        button {
                            id: "notification-center-trigger",
                            class: if active_overlay() == ActiveOverlay::Notifications { "brand-action active" } else { "brand-action" },
                            aria_label: "查看全部项目通知",
                            title: "全部项目通知",
                            aria_expanded: active_overlay() == ActiveOverlay::Notifications,
                            onclick: move |_| {
                                let next = active_overlay().toggle(ActiveOverlay::Notifications);
                                active_overlay.set(next);
                                if next == ActiveOverlay::Notifications {
                                    restore_ui_focus("notification-center-close");
                                }
                            },
                            UiIcon { name: UiIconName::Bell, size: 15 }
                            span {
                                class: if notification_count == 0 { "notification-badge quiet" } else { "notification-badge" },
                                "{notification_count}"
                            }
                        }
                    }
                }
                div { class: "mission-bar",
                    i { class: "mission-indicator" }
                    div { class: "mission-copy",
                        strong { "{surface_heading}" }
                        span { "{status}" }
                    }
                    div { class: "mission-actions",
                        button {
                            id: "current-object-pin-trigger",
                            class: if current_object_pinned() { "icon-button active" } else { "icon-button" },
                            disabled: !visual_fixture_active,
                            aria_label: if current_object_pinned() { "取消置顶当前对象" } else { "置顶当前对象" },
                            aria_pressed: current_object_pinned(),
                            title: if visual_fixture_active { "切换视觉夹具中的置顶表现" } else { "NOT_IMPLEMENTED · 等待 UI Preference Application Service" },
                            onclick: move |_| current_object_pinned.set(!current_object_pinned()),
                            UiIcon { name: UiIconName::Pin, size: 14 }
                        }
                        button {
                            id: "current-object-menu-trigger",
                            class: if current_object_menu() { "icon-button active" } else { "icon-button" },
                            aria_label: "当前对象操作",
                            aria_haspopup: "menu",
                            aria_expanded: current_object_menu(),
                            onclick: move |_| current_object_menu.set(!current_object_menu()),
                            UiIcon { name: UiIconName::Ellipsis, size: 15 }
                        }
                        if current_object_menu() {
                            button {
                                class: "current-object-menu-dismiss",
                                aria_label: "关闭当前对象操作",
                                onclick: move |_| {
                                    current_object_menu.set(false);
                                    restore_ui_focus("current-object-menu-trigger");
                                },
                            }
                            section {
                                class: "current-object-menu",
                                role: "menu",
                                aria_label: "当前对象操作",
                                onkeydown: move |event| {
                                    if event.key() == Key::Escape {
                                        event.stop_propagation();
                                        current_object_menu.set(false);
                                        restore_ui_focus("current-object-menu-trigger");
                                    }
                                },
                                button {
                                    id: "current-object-menu-first",
                                    autofocus: true,
                                    role: "menuitem",
                                    onclick: move |_| {
                                        model.set(DesktopUiModel::load());
                                        current_object_menu.set(false);
                                    },
                                    UiIcon { name: UiIconName::Refresh, size: 13 }
                                    "重新读取持久状态"
                                }
                                button {
                                    role: "menuitem",
                                    onclick: move |_| {
                                        let script = format!(
                                            "navigator.clipboard?.writeText({current_object_deep_link:?}).catch(() => undefined)"
                                        );
                                        let _ = dioxus::document::eval(&script);
                                        current_object_menu.set(false);
                                    },
                                    UiIcon { name: UiIconName::FileCheck, size: 13 }
                                    "复制 Deep Link"
                                }
                                button {
                                    role: "menuitem",
                                    disabled: true,
                                    title: "NOT_IMPLEMENTED · 等待 Mission metadata Application command",
                                    UiIcon { name: UiIconName::FileText, size: 13 }
                                    "编辑名称与说明"
                                }
                                button {
                                    class: "danger",
                                    role: "menuitem",
                                    disabled: true,
                                    title: "NOT_IMPLEMENTED · 等待可恢复归档命令",
                                    UiIcon { name: UiIconName::X, size: 13 }
                                    "归档当前对象"
                                }
                            }
                        }
                    }
                }
                div { class: "document-bar",
                    span { class: "surface-chrome",
                        UiIcon { name: UiIconName::Layout, size: 14 }
                        small { "{surface_context}" }
                        strong { "{surface_heading}" }
                    }
                    button {
                        class: if workpad_visible { "workpad-chrome-button active" } else { "workpad-chrome-button" },
                        aria_label: if workpad_visible { "收起任务工作台" } else { "打开任务工作台" },
                        aria_pressed: workpad_visible,
                        onclick: move |_| workpad_open.set(!workpad_open()),
                        UiIcon { name: UiIconName::Panel, size: 14 }
                        span { "任务工作台" }
                    }
                }
            }
            aside { class: "sidebar", aria_label: "项目与任务导航",
                div { class: "side-top",
                    button {
                        class: "new-task",
                        disabled: project.is_none(),
                        aria_label: "在当前项目描述新任务",
                        onclick: move |_| {
                            model.write().select_dispatcher();
                            surface.set(Surface::Orchestrator);
                            catalog_contract_expanded.set(true);
                        },
                        UiIcon { name: UiIconName::Plus, size: 15 }
                        span { "新任务" }
                        kbd { "⌘ N" }
                    }
                }
                nav { class: "primary-nav prototype-primary-nav", aria_label: "项目工作面",
                    div { class: "nav-label", "工作" }
                    NavButton { label: "总调度", meta: "运行中", icon: UiIconName::Sparkles, active: current_surface == Surface::Orchestrator && view.selected_mission_id.is_none(), onclick: move |_| { model.write().select_dispatcher(); surface.set(Surface::Orchestrator); } }
                    NavButton { label: "当前状态", meta: "Project", icon: UiIconName::Home, active: current_surface == Surface::Current, onclick: move |_| surface.set(Surface::Current) }
                    NavButton { label: "全部任务", meta: "{mission_count}", icon: UiIconName::List, active: current_surface == Surface::Missions, onclick: move |_| surface.set(Surface::Missions) }
                    NavButton { label: "待确认", meta: "{waiting_count}", icon: UiIconName::Shield, active: false, onclick: move |_| surface.set(Surface::Missions) }

                    if !running_missions.is_empty() {
                        div { class: "nav-label mission-group-label", span { "任务 · 进行中" } em { "{running_missions.len()}" } }
                        for item in running_missions.clone() {
                            {
                                let mission_id = item.mission_id.clone();
                                let selected = current_surface == Surface::Orchestrator
                                    && view.selected_mission_id.as_ref() == Some(&mission_id);
                                rsx! {
                                    MissionNavRow {
                                        mission: item,
                                        active: selected,
                                        menu_open: mission_menu_id.read().as_ref() == Some(&mission_id),
                                        onclick: move |_| {
                                            mission_menu_id.set(None);
                                            model.write().select_mission(mission_id.clone());
                                            surface.set(Surface::Orchestrator);
                                        },
                                        on_menu: move |target_id| {
                                            mission_menu_id.set(
                                                if mission_menu_id.read().as_ref() == Some(&target_id) {
                                                    None
                                                } else {
                                                    Some(target_id)
                                                },
                                            );
                                        },
                                    }
                                }
                            }
                        }
                    }

                    if !scheduled_missions.is_empty() {
                        div { class: "nav-label mission-group-label", span { "自动任务" } em { "持续运行" } }
                        for item in scheduled_missions.clone() {
                            {
                                let mission_id = item.mission_id.clone();
                                let selected = current_surface == Surface::Orchestrator
                                    && view.selected_mission_id.as_ref() == Some(&mission_id);
                                rsx! {
                                    MissionNavRow {
                                        mission: item,
                                        active: selected,
                                        menu_open: mission_menu_id.read().as_ref() == Some(&mission_id),
                                        onclick: move |_| {
                                            mission_menu_id.set(None);
                                            model.write().select_mission(mission_id.clone());
                                            surface.set(Surface::Orchestrator);
                                        },
                                        on_menu: move |target_id| {
                                            mission_menu_id.set(
                                                if mission_menu_id.read().as_ref() == Some(&target_id) {
                                                    None
                                                } else {
                                                    Some(target_id)
                                                },
                                            );
                                        },
                                    }
                                }
                            }
                        }
                    }

                    div { class: "nav-label", "成果与工作面" }
                    NavButton { label: "成果与循环", meta: "Outcome", icon: UiIconName::Chart, active: current_surface == Surface::Outcomes, onclick: move |_| surface.set(Surface::Outcomes) }
                    NavButton { label: "渠道运营", meta: "Channel", icon: UiIconName::Mail, active: current_surface == Surface::ChannelOperations, onclick: move |_| surface.set(Surface::ChannelOperations) }
                    NavButton { label: "关系与 CRM", meta: "CRM", icon: UiIconName::Contact, active: current_surface == Surface::Relationships, onclick: move |_| surface.set(Surface::Relationships) }
                    NavButton { label: "达人与联盟", meta: "Partner", icon: UiIconName::Handshake, active: current_surface == Surface::Partners, onclick: move |_| surface.set(Surface::Partners) }
                    NavButton { label: "连接中心", meta: "Probe", icon: UiIconName::Plug, active: current_surface == Surface::Connections, onclick: move |_| surface.set(Surface::Connections) }
                    NavButton { label: "能力与证据", meta: "E0–E5", icon: UiIconName::Blocks, active: current_surface == Surface::CapabilityEvidence, onclick: move |_| surface.set(Surface::CapabilityEvidence) }
                }

                footer { class: "workspace-switcher",
                    if active_overlay() == ActiveOverlay::ProjectSwitcher {
                        button {
                            class: "project-switcher-dismiss",
                            aria_label: "关闭宣发项目切换器",
                            onclick: move |_| {
                                active_overlay.set(ActiveOverlay::None);
                                restore_ui_focus("project-switcher-trigger");
                            },
                        }
                        section {
                            class: "project-switcher",
                            role: "dialog",
                            aria_modal: "true",
                            aria_label: "宣发项目切换器",
                            tabindex: "-1",
                            onkeydown: move |event| match event.key() {
                                Key::Escape => {
                                    event.stop_propagation();
                                    active_overlay.set(ActiveOverlay::None);
                                    restore_ui_focus("project-switcher-trigger");
                                }
                                Key::Tab => {
                                    event.prevent_default();
                                    cycle_dialog_focus(
                                        ".project-switcher",
                                        event.modifiers().contains(Modifiers::SHIFT),
                                    );
                                }
                                _ => {}
                            },
                            header { class: "project-switcher-head",
                                span { class: "user-avatar", "本" }
                                span { strong { "本机工作区" } small { "Local-first · 项目严格隔离" } }
                                button {
                                    id: "project-switcher-initial",
                                    autofocus: true,
                                    class: "icon-button",
                                    aria_label: "打开设置",
                                    onclick: move |_| {
                                        active_overlay.set(ActiveOverlay::None);
                                        surface_before_settings.set(current_surface);
                                        surface.set(Surface::Settings);
                                    },
                                    UiIcon { name: UiIconName::Settings, size: 14 }
                                }
                            }
                            div { class: "project-switcher-label", "宣发项目" span { "按持久 Inventory 排序" } }
                            div { class: "project-list", role: "list", aria_label: "选择宣发项目",
                                if let DesktopBackendState::Ready(snapshot) = &view.backend {
                                    for item in snapshot.inventory.projects.clone() {
                                        {
                                            let project_id = item.project_id.clone();
                                            let selected = view.selected_project_id.as_ref() == Some(&project_id);
                                            rsx! {
                                                button {
                                                    class: if selected { "project-option active" } else { "project-option" },
                                                    aria_current: selected,
                                                    onclick: move |_| {
                                                        model.write().select_project(&project_id);
                                                        active_overlay.set(ActiveOverlay::None);
                                                        surface.set(Surface::Current);
                                                    },
                                                    i { class: "project-mark", "{project_initials(&item.name)}" }
                                                    span { strong { "{item.name}" } small { "revision {item.revision} · {encryption_short_label(&item.encryption)}" } }
                                                    if selected { UiIcon { name: UiIconName::Check, size: 14 } }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    div { class: "project-switcher-empty", "当前没有可读取的项目 Inventory" }
                                }
                            }
                            div { class: "project-switcher-actions",
                                button {
                                    class: "project-switcher-action",
                                    onclick: move |_| {
                                        active_overlay.set(ActiveOverlay::None);
                                        surface.set(Surface::CapabilityEvidence);
                                    },
                                    UiIcon { name: UiIconName::Chart, size: 14 }
                                    "查看能力与证据"
                                }
                                button {
                                    class: "project-switcher-action",
                                    onclick: move |_| {
                                        active_overlay.set(ActiveOverlay::None);
                                        surface_before_settings.set(current_surface);
                                        surface.set(Surface::Settings);
                                    },
                                    UiIcon { name: UiIconName::Settings, size: 14 }
                                    "设置"
                                }
                            }
                        }
                    }
                    button {
                        id: "project-switcher-trigger",
                        class: "workspace-button",
                        aria_haspopup: "true",
                        aria_expanded: active_overlay() == ActiveOverlay::ProjectSwitcher,
                        onclick: move |_| {
                            let next = active_overlay().toggle(ActiveOverlay::ProjectSwitcher);
                            active_overlay.set(next);
                            if next == ActiveOverlay::ProjectSwitcher {
                                restore_ui_focus("project-switcher-initial");
                            }
                        },
                        img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                        span { strong { "{project_name}" } small { b { "{project_storage_status}" } } }
                        UiIcon { name: UiIconName::ChevronDown, size: 14 }
                    }
                    div { class: "local-path", "路径只用于本机数据层，不进入日志或 Release Evidence" }
                }
            }

            main { class: "workspace",
                header { class: "workspace-header",
                    div { class: "conversation-state", aria_live: "polite",
                        span { class: "status-dot live" }
                        strong { "{surface_context}" }
                    }
                    span { class: "conversation-hint",
                        if current_surface == Surface::Orchestrator { "可以随时改变方向；不会扩大 Capability" } else { "变化回写同一 Project / Mission Truth" }
                    }
                    if let Some(fixture_id) = &visual_fixture_id {
                        span { class: "visual-fixture-indicator", "VISUAL_FIXTURE · {fixture_id}" }
                    }
                    div { class: "header-actions",
                        button { class: if workpad_visible { "quiet-button active" } else { "quiet-button" },
                            onclick: move |_| workpad_open.set(!workpad_open()),
                            UiIcon { name: UiIconName::Panel, size: 14 }
                            "工作台"
                        }
                    }
                }

                div { class: if workpad_visible { "workspace-grid workpad-visible" } else { "workspace-grid" },
                    section { class: "main-surface",
                        if let Some(notice) = &view.notice {
                            IntegrityBanner { failure: notice.clone() }
                        }
                        if current_surface == Surface::Orchestrator {
                            OrchestratorSurface {
                                backend: view.backend.clone(),
                                project: project.clone(),
                                mission: mission.clone(),
                                runtime_activity: runtime_activity.clone(),
                                runtime_text_stream: runtime_text_stream.read().clone(),
                                runtime_text_error: runtime_text_error.read().clone(),
                                runtime_busy,
                                runtime_stream_is_fixture: visual_persisted_stream_fixture,
                                runtime_follow_latest: runtime_follow_latest(),
                                runtime_has_unseen: runtime_has_unseen(),
                                context_access: context_access.clone(),
                                on_initialize: move |_| {
                                    match DesktopDataPlane::discover().and_then(|plane| plane.initialize_os(Utc::now())) {
                                        Ok(snapshot) => model.write().set_ready(snapshot, false),
                                        Err(error) => model.write().set_notice(&error),
                                    }
                                },
                                on_ready: move |snapshot| model.write().set_ready(snapshot, true),
                                on_error: move |error| model.write().set_notice(&error),
                                on_select_mission: move |mission_id| model.write().select_mission(mission_id),
                                on_open_workpad: move |()| workpad_open.set(true),
                                on_runtime_scroll: move |near_bottom| {
                                    runtime_follow_latest.set(near_bottom);
                                    if near_bottom {
                                        runtime_has_unseen.set(false);
                                    }
                                },
                                on_follow_latest: move |()| {
                                    runtime_follow_latest.set(true);
                                    runtime_has_unseen.set(false);
                                    scroll_mission_thread_to_latest();
                                },
                            }
                        } else if current_surface == Surface::Current {
                            CurrentSurface { project: project.clone(), context_access: context_access.clone() }
                        } else if current_surface == Surface::Missions {
                            MissionsSurface { project: project.clone(), selected_mission_id: view.selected_mission_id.clone(), on_select: move |mission_id| {
                                model.write().select_mission(mission_id);
                                surface.set(Surface::Orchestrator);
                            } }
                        } else if current_surface == Surface::ChannelOperations {
                            ChannelSurface { project: project.clone(), mission: mission.clone() }
                        } else if current_surface == Surface::Relationships {
                            RelationshipsSurface { project: project.clone(), mission: mission.clone() }
                        } else if current_surface == Surface::Partners {
                            PartnersSurface { project: project.clone(), mission: mission.clone() }
                        } else if current_surface == Surface::Connections {
                            ConnectionsSurface { project: project.clone(), context_access: context_access.clone() }
                        } else if current_surface == Surface::Outcomes {
                            OutcomesSurface { project: project.clone(), mission: mission.clone() }
                        } else if current_surface == Surface::Settings {
                            SettingsSurface { runtime: runtime_projection.clone(), on_close: move |()| surface.set(surface_before_settings()) }
                        } else if current_surface == Surface::StateCoverage {
                            StateCoverageSurface {}
                        } else if let Some(product_evidence) = evidence.clone() {
                            CapabilityEvidenceSurface { evidence: product_evidence }
                        } else {
                            EmptyState { code: "INTEGRITY_ERROR", title: "机器合同不可用", detail: "Catalog 未通过加载与验证，能力声明已停止显示。" }
                        }

                        if current_surface == Surface::Orchestrator {
                            section {
                                class: if composer_expanded()
                                    || fixture_attachment_visible()
                                    || catalog_contract_expanded()
                                    || runtime_busy
                                    || human_route_active
                                    || application_route_active
                                    || application_route_not_implemented
                                    || application_route_catalog_mismatch
                                    || runtime_retry_needed
                                {
                                    if runtime_busy && fixture_attachment_visible() {
                                        "composer-zone is-expanded runtime-active has-attachments"
                                    } else if runtime_busy {
                                        "composer-zone is-expanded runtime-active"
                                    } else if fixture_attachment_visible() {
                                        "composer-zone is-expanded has-attachments"
                                    } else {
                                        "composer-zone is-expanded"
                                    }
                                } else {
                                    "composer-zone"
                                },
                                if composer_guidance_visible {
                                    section { class: "mission-intent-guidance", aria_live: "polite",
                                        i { img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" } }
                                        span {
                                            strong { "{composer_guidance_title}" }
                                            small { "{project_name} · ⌘K 随时聚焦同一 Mission" }
                                        }
                                        button {
                                            class: "mission-intent-guidance-action",
                                            onclick: move |_| {
                                                composer_expanded.set(true);
                                                let _ = dioxus::document::eval(
                                                    "requestAnimationFrame(() => document.getElementById('mission-composer-input')?.focus())",
                                                );
                                            },
                                            "{composer_guidance_action}"
                                        }
                                        button {
                                            class: "mission-intent-guidance-dismiss",
                                            aria_label: "暂时收起建议",
                                            title: "暂时收起建议",
                                            onclick: move |_| composer_guidance_dismissed.set(true),
                                            UiIcon { name: UiIconName::X, size: 13 }
                                        }
                                    }
                                }
                                div { class: "composer-context",
                                    span { "{project_name} · {composer_target}" }
                                    div { class: "composer-context-actions",
                                        span { class: "permission-pill",
                                            if mission.is_some() { "同一 Mission · Capability 不扩大" } else { "外部动作仍需精确审批" }
                                        }
                                        if mission.is_none() {
                                            button {
                                                id: "operating-contract-trigger",
                                                class: if catalog_contract_expanded() { "contract-toggle active" } else { "contract-toggle" },
                                                aria_expanded: catalog_contract_expanded(),
                                                aria_controls: "operating-contract-fields",
                                                onclick: move |_| catalog_contract_expanded.set(!catalog_contract_expanded()),
                                                span { "Operating Contract" }
                                                UiIcon { name: UiIconName::ChevronDown, size: 12 }
                                            }
                                        }
                                    }
                                }
                                if runtime_busy {
                                    div {
                                        class: if runtime_stop_requested() { "live-operation-strip stop-requested" } else { "live-operation-strip" },
                                        role: "status",
                                        aria_live: "polite",
                                        i { UiIcon { name: UiIconName::Refresh, size: 13 } }
                                        span {
                                            strong { "{active_operation_label}" }
                                            small {
                                                if visual_streaming_fixture && runtime_stop_requested() {
                                                    "VISUAL_FIXTURE · 已触发 Stop 控件状态；未发送真实 Interrupt，也没有 Provider Effect。"
                                                } else if visual_streaming_fixture {
                                                    "VISUAL_FIXTURE · 仅验证事件流、跟随状态与 Stop 交互；不构成 Runtime 或 Provider 执行证据。"
                                                } else if runtime_stop_requested() {
                                                    "停止请求已交给 exact Runtime attempt；等待 Interrupt receipt 或 UNCERTAIN reconciliation。"
                                                } else if runtime_stop_available {
                                                    "过程会持续写入持久 Runtime ledger；可以安全请求停止。"
                                                } else {
                                                    "此步骤由 Application 事务协调；不会用隐藏动画代替取消。"
                                                }
                                            }
                                        }
                                        if runtime_stop_available {
                                            em {
                                                if runtime_stop_requested() { "等待中断" } else { "可安全停止" }
                                            }
                                        } else {
                                            em { "事务提交中" }
                                        }
                                        if !recent_runtime_progress.is_empty() {
                                            div { class: "live-operation-events", aria_label: "Runtime 事件流",
                                                for event in recent_runtime_progress.clone() {
                                                    div { class: desktop_runtime_progress_class(event.phase),
                                                        i {}
                                                        span { "{desktop_runtime_progress_display_label(event.phase, visual_streaming_fixture)}" }
                                                        em { "#{event.sequence}" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if visual_fixture_id.is_some() && fixture_attachment_visible() {
                                    div { class: "prototype-composer-attachments", aria_label: "附件结构样例",
                                        article {
                                            img { src: PROTOTYPE_TREND_SVG, alt: "需求趋势工作产物结构样例" }
                                            span { strong { "需求趋势样例.svg" } small { "VISUAL_FIXTURE · 不会上传" } }
                                            button {
                                                aria_label: "移除附件结构样例",
                                                onclick: move |_| fixture_attachment_visible.set(false),
                                                UiIcon { name: UiIconName::X, size: 13 }
                                            }
                                        }
                                    }
                                }
                                if mission.is_none() && catalog_contract_expanded() {
                                    div { id: "operating-contract-fields", class: "catalog-contract-fields",
                                    label { class: "catalog-route-field",
                                        span { "Mission 路由" }
                                        select {
                                            value: "{selected_manifest_id}",
                                            disabled: !can_edit_catalog,
                                            aria_label: "选择 VM-00 到 VM-11 Mission 路由",
                                            onchange: move |event| {
                                                let manifest_id = event.value();
                                                let first_mode = catalog_routes_for_selection
                                                    .iter()
                                                    .find(|route| route.mission_id == manifest_id)
                                                    .and_then(|route| route.modes.first())
                                                    .cloned()
                                                    .unwrap_or_default();
                                                catalog_manifest_id.set(manifest_id);
                                                catalog_mode.set(first_mode);
                                                catalog_parent_mission_id.set(String::new());
                                            },
                                            option { value: "", "选择 VM-00～VM-11…" }
                                            for route in catalog_routes.clone() {
                                                option { value: "{route.mission_id}", "{route.mission_id} · {route.title}" }
                                            }
                                        }
                                    }
                                    if vm11_selected {
                                        label { class: "catalog-route-field",
                                            span { "父 Mission（经营维度与 KPI 后端继承）" }
                                            select {
                                                value: "{parent_mission_id_value}",
                                                disabled: !can_edit_catalog,
                                                aria_label: "选择 VM-11 要复算的父 Mission",
                                                onchange: move |event| catalog_parent_mission_id.set(event.value()),
                                                option { value: "", "选择同项目真实父 Mission…" }
                                                for (parent_mission_id, parent_label) in parent_mission_candidates.clone() {
                                                    option {
                                                        value: "{parent_mission_id.as_str()}",
                                                        "{parent_label}"
                                                    }
                                                }
                                            }
                                        }
                                        div { class: "catalog-route-note",
                                            span { "模式、市场、locale、受众、时区、预算与 KPI 均从所选父 Mission 当前合同重载；下方禁用值不会作为 VM-11 输入。" }
                                        }
                                    }
                                    label {
                                        span { "运行模式" }
                                        select {
                                            value: "{selected_mode}",
                                            disabled: !can_edit_catalog || allowed_modes.is_empty() || vm11_selected,
                                            aria_label: "选择 Manifest 允许的运行模式",
                                            onchange: move |event| catalog_mode.set(event.value()),
                                            if allowed_modes.is_empty() {
                                                option { value: "", "先选择 Mission" }
                                            }
                                            for mode in allowed_modes.clone() {
                                                option { value: "{mode}", "{operating_mode_label(&mode)}" }
                                            }
                                        }
                                    }
                                    label {
                                        span { "市场" }
                                        input {
                                            value: "{market_value}",
                                            disabled: !can_edit_catalog || vm11_selected,
                                            autocomplete: "off",
                                            placeholder: "US / DE / JP",
                                            aria_label: "Operating Contract 市场",
                                            oninput: move |event| catalog_market.set(event.value()),
                                        }
                                    }
                                    label {
                                        span { "语言 / locale" }
                                        input {
                                            value: "{language_value}",
                                            disabled: !can_edit_catalog || vm11_selected,
                                            autocomplete: "off",
                                            placeholder: "en-US / de-DE / ja-JP",
                                            aria_label: "Operating Contract 语言或 locale",
                                            oninput: move |event| catalog_language.set(event.value()),
                                        }
                                    }
                                    label {
                                        span { "受众" }
                                        input {
                                            value: "{audience_value}",
                                            disabled: !can_edit_catalog || vm11_selected,
                                            autocomplete: "off",
                                            placeholder: "buyer / owner / operator",
                                            aria_label: "Operating Contract 受众",
                                            oninput: move |event| catalog_audience.set(event.value()),
                                        }
                                    }
                                    label {
                                        span { "时区" }
                                        input {
                                            value: "{timezone_value}",
                                            disabled: !can_edit_catalog || vm11_selected,
                                            autocomplete: "off",
                                            placeholder: "Europe/Berlin",
                                            aria_label: "Operating Contract IANA 时区",
                                            oninput: move |event| catalog_timezone.set(event.value()),
                                        }
                                    }
                                    label {
                                        span { "币种" }
                                        input {
                                            value: "{currency_value}",
                                            disabled: !can_edit_catalog || vm11_selected,
                                            autocomplete: "off",
                                            maxlength: 3,
                                            placeholder: "USD",
                                            aria_label: "Operating Contract ISO 4217 币种",
                                            oninput: move |event| catalog_currency.set(event.value().to_ascii_uppercase()),
                                        }
                                    }
                                    label {
                                        span { "预算（minor units）" }
                                        input {
                                            value: "{budget_minor_value}",
                                            disabled: !can_edit_catalog || vm11_selected,
                                            inputmode: "numeric",
                                            autocomplete: "off",
                                            placeholder: "0",
                                            aria_label: "Operating Contract minor-unit 预算",
                                            oninput: move |event| catalog_budget_minor.set(event.value()),
                                        }
                                    }
                                    if !vm11_selected {
                                        label {
                                            span { "KPI metric ID" }
                                            input {
                                                value: "{kpi_metric_value}",
                                                disabled: !can_edit_catalog,
                                                autocomplete: "off",
                                                placeholder: "lead_qualified_count",
                                                aria_label: "Operating Contract KPI metric ID",
                                                oninput: move |event| catalog_kpi_metric.set(event.value()),
                                            }
                                        }
                                        label {
                                            span { "KPI baseline（可留空）" }
                                            input {
                                                value: "{kpi_baseline_value}",
                                                disabled: !can_edit_catalog,
                                                inputmode: "decimal",
                                                autocomplete: "off",
                                                placeholder: "0",
                                                aria_label: "Operating Contract KPI baseline",
                                                oninput: move |event| catalog_kpi_baseline.set(event.value()),
                                            }
                                        }
                                        label {
                                            span { "KPI target" }
                                            input {
                                                value: "{kpi_target_value}",
                                                disabled: !can_edit_catalog,
                                                inputmode: "decimal",
                                                autocomplete: "off",
                                                placeholder: "1",
                                                aria_label: "Operating Contract KPI target",
                                                oninput: move |event| catalog_kpi_target.set(event.value()),
                                            }
                                        }
                                        label {
                                            span { "KPI unit" }
                                            input {
                                                value: "{kpi_unit_value}",
                                                disabled: !can_edit_catalog,
                                                autocomplete: "off",
                                                placeholder: "count / minor_units:USD",
                                                aria_label: "Operating Contract KPI unit",
                                                oninput: move |event| catalog_kpi_unit.set(event.value()),
                                            }
                                        }
                                        label {
                                            span { "KPI 方向" }
                                            select {
                                                value: "{kpi_direction_value}",
                                                disabled: !can_edit_catalog,
                                                aria_label: "Operating Contract KPI direction",
                                                onchange: move |event| catalog_kpi_direction.set(event.value()),
                                                option { value: "at_least", "至少达到" }
                                                option { value: "at_most", "至多不超过" }
                                            }
                                        }
                                    }
                                    }
                                }
                                if let Some(route) = &selected_catalog_route {
                                    div { class: "catalog-route-note",
                                        span { "{route.mission_id} · {route.default_cadence}" }
                                        span { "当前 Release Evidence {mission_evidence_status_label(route.status)} / {evidence_level_label(route.evidence_level)}" }
                                    }
                                } else if mission.is_some() {
                                    div { class: "catalog-route-note",
                                        span { "Mission Conversation revision {mission.as_ref().and_then(|mission| mission.conversation_revision).unwrap_or_default()}" }
                                        span { "消息会写入同一 Mission Stream；不会另建 Mission，也不会修改 Operating Contract 权限。" }
                                    }
                                }
                                if application_route_not_implemented || application_route_catalog_mismatch {
                                    div { class: "catalog-route-note application-handler-boundary", role: "status",
                                        span { class: "honesty-badge", "{application_route_boundary_code}" }
                                        span {
                                            "Application Checkpoint {application_checkpoint_id_label}：{application_route_boundary_detail}"
                                        }
                                        span { "Mission 保持原 revision；不会运行模型、伪造 Oracle 证据或自动跳到下一 Checkpoint。" }
                                    }
                                }
                                if human_route_active {
                                    section { class: "human-checkpoint-confirmation", aria_label: "Human Checkpoint 精确确认",
                                        if vm11_outcome_decision_active {
                                            strong { "选择下一步：Continue / Stop / Scale / Test" }
                                            span {
                                                "Checkpoint {human_checkpoint_id_label} · Oracle {human_oracle_label}"
                                            }
                                            if let Some(projection) = &vm11_outcome_review {
                                                div { class: "outcome-review-gates",
                                                    span { "KPI · {outcome_review_gate_label(projection.review.kpi_status)}" }
                                                    span { "归因 · {outcome_review_gate_label(projection.review.attribution_status)}" }
                                                    span { "结算 · {outcome_review_gate_label(projection.review.settlement_status)}" }
                                                    span { "成本 · {outcome_review_gate_label(projection.review.cost_status)}" }
                                                    span { "预算 · {outcome_review_gate_label(projection.review.budget_status)}" }
                                                    span { "Scale evidence · {outcome_review_gate_label(projection.review.scale_evidence_status)}" }
                                                }
                                                div { class: "outcome-review-summary",
                                                    span { "KPI {projection.review.target_met_count} 达标 / {projection.review.target_gap_count} 未达标" }
                                                    span { "订单 {projection.review.order_count} · 已归因 {projection.review.attributed_order_count} · 未归因 {projection.review.unattributed_order_count}" }
                                                    span { "结算组 {projection.review.settlement_group_count} · 未结 {projection.review.outstanding_settlement_group_count}" }
                                                    span { "已验证 Effect {projection.review.verified_effect_count} · Pending {projection.review.pending_effect_count}" }
                                                    span { "预算 {money_label(&projection.review.budget)} · 剩余 {money_label(&projection.review.budget_remaining)} · 超支 {money_label(&projection.review.budget_overrun)}" }
                                                }
                                                if !projection.review.economics.is_empty() {
                                                    div { class: "outcome-review-economics",
                                                        for economics in projection.review.economics.values() {
                                                            span {
                                                                "{economics.currency}：净收入 {money_label(&economics.net_revenue)} · 已付佣金 {money_label(&economics.commission_paid)} · 待付 {money_label(&economics.commission_outstanding)} · 已验证支出 {money_label(&economics.verified_effect_outflow)}"
                                                            }
                                                        }
                                                    }
                                                }
                                                if !projection.review.caveats.is_empty() {
                                                    div { class: "outcome-review-caveats",
                                                        strong { "限制与不确定性" }
                                                        for caveat in projection.review.caveats.iter() {
                                                            span { "{outcome_review_caveat_label(*caveat)}" }
                                                        }
                                                    }
                                                }
                                                div { class: "outcome-review-actions", role: "group", aria_label: "选择 VM-11 Outcome 决策",
                                                    for gate in projection.action_gates.clone() {
                                                        {
                                                            let action = gate.action.clone();
                                                            let action_for_selection = action.clone();
                                                            let selected = selected_vm11_action.as_ref() == Some(&action);
                                                            let available = gate.status == OutcomeReviewDecisionGateStatus::Available;
                                                            let mission_id = mission.as_ref().map(|mission| mission.mission_id.clone());
                                                            rsx! {
                                                                button {
                                                                    class: if selected { "outcome-action selected" } else { "outcome-action" },
                                                                    disabled: !can_edit_human_confirmation || !available || mission_id.is_none(),
                                                                    aria_pressed: selected,
                                                                    aria_label: "选择 {outcome_decision_label(&action)}",
                                                                    onclick: move |_| {
                                                                        if let Some(mission_id) = mission_id.clone() {
                                                                            vm11_outcome_action.set(Some((mission_id, action_for_selection.clone())));
                                                                        }
                                                                    },
                                                                    strong { "{outcome_decision_label(&action)}" }
                                                                    small { "{outcome_decision_gate_label(gate.status)}" }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                small { "决策会绑定此冻结 Review 的 projection/completion digest、当前 Mission/Checkpoint/Conversation revision 与私密理由；修改任一输入都会拒绝旧提交。" }
                                            } else {
                                                div { class: "catalog-route-note application-handler-boundary", role: "status",
                                                    span { class: "honesty-badge", "BLOCKED_DATA" }
                                                    span { "outcome_review 已标记完成，但当前 SQLCipher 数据库没有可验证的冻结 Review。不会退化为自由文本确认。" }
                                                }
                                            }
                                        } else {
                                            strong { "需要你的精确确认" }
                                            span {
                                                "Checkpoint {human_checkpoint_id_label} · Oracle {human_oracle_label}"
                                            }
                                            if human_requires_work_product {
                                                if mission.as_ref().is_none_or(|mission| mission.work_products.is_empty()) {
                                                    em { "BLOCKED：此确认必须绑定真实 WorkProduct，但当前解锁投影中没有可审阅产物。不会空确认。" }
                                                } else if let Some(current_mission) = &mission {
                                                    div { class: "human-work-product-list",
                                                        for product in current_mission.work_products.clone() {
                                                            {
                                                                let work_product_id = product.work_product_id.clone();
                                                                let checked = selected_human_work_product_ids.contains(&work_product_id);
                                                                rsx! {
                                                                    label { class: "human-work-product-option",
                                                                        input {
                                                                            r#type: "checkbox",
                                                                            checked,
                                                                            disabled: !can_edit_human_confirmation,
                                                                            onchange: move |event| {
                                                                                let mut selected = human_work_product_selection.write();
                                                                                if event.checked() {
                                                                                    selected.insert(work_product_id.clone());
                                                                                } else {
                                                                                    selected.remove(&work_product_id);
                                                                                }
                                                                            },
                                                                        }
                                                                        span { strong { "{product.title}" } small { "{product.work_product_id} · revision {product.work_product_revision}" } }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            } else {
                                                small { "该 Checkpoint 不声明 WorkProduct Oracle；确认只绑定下面的用户陈述、Mission/Checkpoint revision 与 Catalog route digest。" }
                                            }
                                        }
                                    }
                                }
                                textarea {
                                    id: "mission-composer-input",
                                    value: "{draft}",
                                    disabled: !can_write_composer,
                                    aria_label: "Operating Contract 目标、约束与停止条件",
                                    placeholder: if mission.is_some() {
                                        if vm11_outcome_decision_active { "写下选择该动作的理由、风险与停止条件；正文只进入加密 Mission Conversation…" } else if human_route_active { "写下你对当前 Checkpoint 的明确确认；这段内容会私密写入 Mission Conversation…" } else if can_edit_continuation { "继续当前 Mission，或写明纠正与新约束…" } else { "当前 Mission 状态不接受续写，或它是 legacy bootstrap" }
                                    } else if project_can_start_mission {
                                        "写明目标、硬约束、非目标与停止条件…"
                                    } else {
                                        "项目加密与 Context 就绪后才能创建 Mission"
                                    },
                                    onfocus: move |_| composer_expanded.set(true),
                                    oninput: move |event| {
                                        draft.set(event.value());
                                        let _ = dioxus::document::eval(
                                            "const input = document.getElementById('mission-composer-input'); if (input) { input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 160)}px`; }",
                                        );
                                    },
                                    onkeydown: move |event| {
                                        if composer_should_submit(
                                            &event.key(),
                                            event.modifiers(),
                                            event.data.is_composing(),
                                        ) {
                                            event.prevent_default();
                                            let _ = dioxus::document::eval(
                                                "document.getElementById('mission-composer-send')?.click()",
                                            );
                                        }
                                    },
                                }
                                footer {
                                    div { class: "composer-tool-cluster",
                                        div { class: "composer-tool-anchor",
                                            button {
                                                id: "composer-tool-trigger",
                                                class: if composer_tool_menu() { "composer-icon-tool active" } else { "composer-icon-tool" },
                                                aria_label: "添加附件或上下文",
                                                aria_expanded: composer_tool_menu(),
                                                onclick: move |_| {
                                                    composer_expanded.set(true);
                                                    composer_tool_menu.set(!composer_tool_menu());
                                                    runtime_profile_open.set(false);
                                                },
                                                UiIcon { name: UiIconName::Plus, size: 16 }
                                            }
                                            if composer_tool_menu() {
                                                section { class: "composer-tool-menu", role: "menu", aria_label: "添加到 Mission",
                                                    header { strong { "添加到 Mission" } small { "不扩大 Capability" } }
                                                    button {
                                                        role: "menuitem",
                                                        disabled: visual_fixture_id.is_none(),
                                                        onclick: move |_| {
                                                            fixture_attachment_visible.set(true);
                                                            composer_expanded.set(true);
                                                            composer_tool_menu.set(false);
                                                        },
                                                        UiIcon { name: UiIconName::FileText, size: 14 }
                                                        span { strong { "工作产物结构样例" } small { "仅视觉 fixture；不读取本机文件" } }
                                                    }
                                                    button { role: "menuitem", disabled: true,
                                                        UiIcon { name: UiIconName::Folder, size: 14 }
                                                        span { strong { "选择本机文件" } small { "NOT_IMPLEMENTED · File Broker 未接线" } }
                                                    }
                                                    button { role: "menuitem", disabled: true,
                                                        UiIcon { name: UiIconName::Blocks, size: 14 }
                                                        span { strong { "引用 Project Truth" } small { "NOT_IMPLEMENTED · 等待 Truth Picker" } }
                                                    }
                                                }
                                            }
                                        }
                                        button {
                                            class: "composer-icon-tool",
                                            disabled: true,
                                            aria_label: "语音输入未实现",
                                            title: "BLOCKED_ENV · 麦克风与本地转写尚未接线",
                                            UiIcon { name: UiIconName::Bot, size: 15 }
                                        }
                                    }
                                    div { class: "runtime-pickers",
                                        div { class: "runtime-profile-anchor",
                                            button {
                                                id: "runtime-profile-trigger",
                                                class: "runtime-profile-toggle honesty-chip",
                                                aria_expanded: runtime_profile_open(),
                                                onclick: move |_| {
                                                    composer_expanded.set(true);
                                                    runtime_profile_open.set(!runtime_profile_open());
                                                    composer_tool_menu.set(false);
                                                },
                                                span { "{runtime_chip}" }
                                                UiIcon { name: UiIconName::ChevronDown, size: 11 }
                                            }
                                            if runtime_profile_open() {
                                                section { class: "runtime-profile-menu", role: "dialog", aria_label: "Runtime 与权限边界",
                                                    header { strong { "Runtime Profile" } small { "模型 × Mission 最小能力" } }
                                                    div { span { "执行环境" } b { "{runtime_chip}" } }
                                                    div { span { "Provider route" } b { "{provider_chip}" } }
                                                    div { span { "外部 Effect" } b { "必须独立审批" } }
                                                    footer { "切换模型不能扩大 Capability、Consent 或账号范围。" }
                                                }
                                            }
                                        }
                                        span { class: "honesty-chip", "{provider_chip}" }
                                        if runtime_projection.as_ref().is_some_and(|runtime| !runtime.exact_tokenizer_evidence) {
                                            span { class: "honesty-chip", "Tokenizer · DEV_FALLBACK" }
                                        }
                                    }
                                    div { class: "composer-actions",
                                        if application_route_active {
                                            button {
                                                class: "application-checkpoint-button",
                                                disabled: !can_execute_application_route,
                                                aria_label: "执行当前 Application Checkpoint 的确定性 Oracle handler",
                                                onclick: move |_| {
                                                    let selection = {
                                                        let model = model.read();
                                                        model.selected_project_id.clone().zip(
                                                            model.selected_mission_id.clone(),
                                                        )
                                                    };
                                                    let Some((project_id, mission_id)) = selection else { return; };
                                                    mission_submitting.set(true);
                                                    spawn(async move {
                                                        let result = tokio::task::spawn_blocking(move || {
                                                            DesktopDataPlane::discover().and_then(|plane| {
                                                                plane.execute_application_mission_checkpoint_os(
                                                                    &project_id,
                                                                    &mission_id,
                                                                    Utc::now(),
                                                                )
                                                            })
                                                        })
                                                        .await;
                                                        match result {
                                                            Ok(Ok(submission)) => {
                                                                model.write().set_ready(submission.snapshot, false);
                                                            }
                                                            Ok(Err(error)) => model.write().set_notice(&error),
                                                            Err(_) => {
                                                                model.write().notice = Some(UiFailure {
                                                                    code: "APPLICATION_CHECKPOINT_COORDINATOR_FAILED".into(),
                                                                    message: "Application Checkpoint 协调异常结束；Mission CAS 与来源 revision fence 不会留下半完成 Oracle 证据。".into(),
                                                                });
                                                            }
                                                        }
                                                        mission_submitting.set(false);
                                                    });
                                                },
                                                if mission_submitting() {
                                                    "正在核验来源并原子推进…"
                                                } else if mission.as_ref().is_some_and(|mission| {
                                                    mission.current_checkpoint_status
                                                        == Some(MissionCheckpointStatus::Blocked)
                                                }) {
                                                    "重新检查来源证据"
                                                } else {
                                                    "运行确定性 Checkpoint"
                                                }
                                            }
                                        }
                                        if runtime_retry_needed {
                                            button {
                                                class: "runtime-retry-button",
                                                disabled: !can_retry_runtime,
                                                aria_label: "安全重试当前 Mission 的本地 Runtime",
                                                onclick: move |_| {
                                                    let selection = {
                                                        let model = model.read();
                                                        model.selected_project_id.clone().zip(
                                                            model.selected_mission_id.clone(),
                                                        )
                                                    };
                                                    let Some((project_id, mission_id)) = selection else { return; };
                                                    let cancellation = DesktopRuntimeCancellation::default();
                                                    runtime_cancellation.set(Some(cancellation.clone()));
                                                    runtime_stop_requested.set(false);
                                                    runtime_progress.set(Vec::new());
                                                    runtime_retrying.set(true);
                                                    begin_runtime_progress_monitor(
                                                        cancellation.clone(),
                                                        runtime_progress,
                                                        mission_submitting,
                                                        runtime_retrying,
                                                    );
                                                    begin_runtime_text_stream_monitor(
                                                        model,
                                                        project_id.clone(),
                                                        mission_id.clone(),
                                                        runtime_text_stream,
                                                        runtime_text_error,
                                                        runtime_follow_latest,
                                                        runtime_has_unseen,
                                                        mission_submitting,
                                                        runtime_retrying,
                                                    );
                                                    spawn(async move {
                                                        let result = tokio::task::spawn_blocking(move || {
                                                            DesktopDataPlane::discover().and_then(|plane| {
                                                                plane.resume_mission_runtime_cancellable_os(
                                                                    &project_id,
                                                                    &mission_id,
                                                                    &cancellation,
                                                                    Utc::now(),
                                                                )
                                                            })
                                                        })
                                                        .await;
                                                        match result {
                                                            Ok(Ok(submission)) => {
                                                                model.write().set_ready(submission.snapshot, false);
                                                            }
                                                            Ok(Err(error)) => model.write().set_notice(&error),
                                                            Err(_) => {
                                                                model.write().notice = Some(UiFailure {
                                                                    code: "RUNTIME_RETRY_COORDINATOR_FAILED".into(),
                                                                    message: "本地 Runtime 恢复协调异常结束；持久 recovery/turn ledger 保留原状态，未自动重放外部动作，也未声明 Mission 完成。".into(),
                                                                });
                                                            }
                                                        }
                                                        runtime_cancellation.set(None);
                                                        runtime_stop_requested.set(false);
                                                        runtime_retrying.set(false);
                                                    });
                                                },
                                                if runtime_retrying() {
                                                    "正在安全恢复…"
                                                } else if !runtime_environment_ready {
                                                    "Runtime 环境未就绪"
                                                } else {
                                                    "重试本地 Runtime"
                                                }
                                            }
                                        }
                                        if !(runtime_busy && runtime_stop_available) {
                                        if mission.is_some() {
                                            if human_route_active {
                                                if vm11_outcome_decision_active {
                                                    button {
                                                        id: "mission-composer-send",
                                                        class: "send-button",
                                                        disabled: !can_submit_vm11_outcome_decision,
                                                        aria_label: "提交结构化 VM-11 Outcome 决策并原子进入下一路由",
                                                        onclick: move |_| {
                                                            let selection = {
                                                                let model = model.read();
                                                                model.selected_project_id.clone().zip(
                                                                    model.current_mission().and_then(|mission| {
                                                                        let review = mission.vm11_outcome_review.as_ref()?;
                                                                        let action = vm11_outcome_action
                                                                            .read()
                                                                            .as_ref()
                                                                            .filter(|(mission_id, _)| *mission_id == mission.mission_id)
                                                                            .map(|(_, action)| action.clone())?;
                                                                        Some((
                                                                            mission.mission_id.clone(),
                                                                            action,
                                                                            review.review_projection_digest.clone(),
                                                                            review.review_completion_digest.clone(),
                                                                            mission.revision,
                                                                            mission.current_checkpoint_revision?,
                                                                            mission.conversation_revision?,
                                                                        ))
                                                                    }),
                                                                )
                                                            };
                                                            let Some((project_id, (mission_id, action, expected_review_projection_digest, expected_review_completion_digest, expected_mission_revision, expected_checkpoint_revision, expected_conversation_revision))) = selection else {
                                                                model.write().notice = Some(UiFailure {
                                                                    code: "BLOCKED_DATA".into(),
                                                                    message: "冻结 Review、结构化动作或当前 CAS revision 不完整；未写入决策。".into(),
                                                                });
                                                                return;
                                                            };
                                                            let message_id = MissionConversationMessageId::new();
                                                            let request = DesktopVm11OutcomeDecisionRequest {
                                                                project_id,
                                                                mission_id,
                                                                action,
                                                                message_id: message_id.clone(),
                                                                rationale: draft(),
                                                                idempotency_key: format!("desktop-vm11-outcome-decision:{}", message_id.as_str()),
                                                                expected_review_projection_digest,
                                                                expected_review_completion_digest,
                                                                expected_mission_revision,
                                                                expected_checkpoint_revision,
                                                                expected_conversation_revision,
                                                            };
                                                            mission_submitting.set(true);
                                                            spawn(async move {
                                                                let result = tokio::task::spawn_blocking(move || {
                                                                    DesktopDataPlane::discover().and_then(|plane| {
                                                                        plane.decide_vm11_outcome_review_os(request, Utc::now())
                                                                    })
                                                                })
                                                                .await;
                                                                match result {
                                                                    Ok(Ok(snapshot)) => {
                                                                        model.write().set_ready(snapshot, false);
                                                                        draft.set(String::new());
                                                                        vm11_outcome_action.set(None);
                                                                    }
                                                                    Ok(Err(error)) => model.write().set_notice(&error),
                                                                    Err(_) => {
                                                                        model.write().notice = Some(UiFailure {
                                                                            code: "VM11_OUTCOME_DECISION_COORDINATOR_FAILED".into(),
                                                                            message: "结构化 Outcome 决策协调异常结束；Review 来源 fence、Mission/Conversation 双 CAS 与事务回滚仍然生效。".into(),
                                                                        });
                                                                    }
                                                                }
                                                                mission_submitting.set(false);
                                                            });
                                                        },
                                                        if mission_submitting() {
                                                            "正在绑定 Review 并原子交接…"
                                                        } else if selected_vm11_action.is_none() {
                                                            "先选择 Continue / Stop / Scale / Test"
                                                        } else if !selected_vm11_action_available {
                                                            "所选动作被冻结证据阻断"
                                                        } else {
                                                            "提交结构化决策"
                                                        }
                                                    }
                                                } else {
                                                    button {
                                                        id: "mission-composer-send",
                                                        class: "send-button",
                                                        disabled: !can_submit_human_confirmation,
                                                        aria_label: "确认当前 Human Checkpoint 并原子进入下一路由",
                                                        onclick: move |_| {
                                                            let selection = {
                                                                let model = model.read();
                                                                model.selected_project_id.clone().zip(
                                                                    model.current_mission().and_then(|mission| {
                                                                        Some((
                                                                            mission.mission_id.clone(),
                                                                            mission.current_checkpoint_id.clone()?,
                                                                            mission.revision,
                                                                            mission.current_checkpoint_revision?,
                                                                            mission.conversation_revision?,
                                                                        ))
                                                                    }),
                                                                )
                                                            };
                                                            let Some((project_id, (mission_id, checkpoint_id, expected_mission_revision, expected_checkpoint_revision, expected_conversation_revision))) = selection else {
                                                                model.write().notice = Some(UiFailure {
                                                                    code: "WAITING_USER".into(),
                                                                    message: "当前 Human Checkpoint revision 或持久 Conversation 不完整；未写入确认。".into(),
                                                                });
                                                                return;
                                                            };
                                                            let message_id = MissionConversationMessageId::new();
                                                            let request = DesktopHumanCheckpointConfirmationRequest {
                                                                project_id,
                                                                mission_id,
                                                                checkpoint_id,
                                                                message_id: message_id.clone(),
                                                                body: draft(),
                                                                idempotency_key: format!("desktop-human-confirmation:{}", message_id.as_str()),
                                                                work_product_ids: selected_human_work_product_ids.clone(),
                                                                expected_mission_revision,
                                                                expected_checkpoint_revision,
                                                                expected_conversation_revision,
                                                            };
                                                            mission_submitting.set(true);
                                                            spawn(async move {
                                                                let result = tokio::task::spawn_blocking(move || {
                                                                    DesktopDataPlane::discover().and_then(|plane| {
                                                                        plane.confirm_human_mission_checkpoint_os(request, Utc::now())
                                                                    })
                                                                })
                                                                .await;
                                                                match result {
                                                                    Ok(Ok(snapshot)) => {
                                                                        model.write().set_ready(snapshot, false);
                                                                        draft.set(String::new());
                                                                        human_work_product_selection.write().clear();
                                                                    }
                                                                    Ok(Err(error)) => model.write().set_notice(&error),
                                                                    Err(_) => {
                                                                        model.write().notice = Some(UiFailure {
                                                                            code: "HUMAN_CONFIRMATION_COORDINATOR_FAILED".into(),
                                                                            message: "Human Checkpoint 原子协调异常结束；Mission 与 Conversation 使用双 CAS，不会留下半完成确认。".into(),
                                                                        });
                                                                    }
                                                                }
                                                                mission_submitting.set(false);
                                                            });
                                                        },
                                                        if mission_submitting() {
                                                            "正在原子确认与交接…"
                                                        } else if human_requires_work_product && selected_human_work_product_ids.is_empty() {
                                                            "先选择真实 WorkProduct"
                                                        } else {
                                                            "确认当前 Checkpoint"
                                                        }
                                                    }
                                                }
                                            } else {
                                            button { class: "send-button", disabled: !can_submit_continuation,
                                                id: "mission-composer-send",
                                                aria_label: "续写当前持久 Mission Conversation",
                                                onclick: move |_| {
                                                    let selection = {
                                                        let model = model.read();
                                                        model.selected_project_id.clone().zip(
                                                            model.current_mission().and_then(|mission| {
                                                                mission.conversation_revision.map(|revision| {
                                                                    (mission.mission_id.clone(), revision)
                                                                })
                                                            }),
                                                        )
                                                    };
                                                    let Some((project_id, (mission_id, expected_revision))) = selection else {
                                                        model.write().notice = Some(UiFailure {
                                                            code: "NOT_IMPLEMENTED".into(),
                                                            message: "该 Mission 没有持久 Conversation；legacy bootstrap 不会伪装成可续写会话。".into(),
                                                        });
                                                        return;
                                                    };
                                                    let message_id = MissionConversationMessageId::new();
                                                    let request = DesktopMissionContinuationRequest {
                                                        project_id,
                                                        mission_id,
                                                        idempotency_key: format!("desktop-message:{}", message_id.as_str()),
                                                        message_id,
                                                        kind: MissionConversationMessageKind::Steering,
                                                        body: draft(),
                                                        expected_conversation_revision: expected_revision,
                                                    };
                                                    let cancellation = DesktopRuntimeCancellation::default();
                                                    runtime_cancellation.set(Some(cancellation.clone()));
                                                    runtime_stop_requested.set(false);
                                                    runtime_progress.set(Vec::new());
                                                    mission_submitting.set(true);
                                                    begin_runtime_progress_monitor(
                                                        cancellation.clone(),
                                                        runtime_progress,
                                                        mission_submitting,
                                                        runtime_retrying,
                                                    );
                                                    begin_runtime_text_stream_monitor(
                                                        model,
                                                        request.project_id.clone(),
                                                        request.mission_id.clone(),
                                                        runtime_text_stream,
                                                        runtime_text_error,
                                                        runtime_follow_latest,
                                                        runtime_has_unseen,
                                                        mission_submitting,
                                                        runtime_retrying,
                                                    );
                                                    spawn(async move {
                                                        let result = tokio::task::spawn_blocking(move || {
                                                            DesktopDataPlane::discover().and_then(|plane| {
                                                                plane.continue_mission_and_run_cancellable_os(
                                                                    request,
                                                                    &cancellation,
                                                                    Utc::now(),
                                                                )
                                                            })
                                                        })
                                                        .await;
                                                        match result {
                                                            Ok(Ok(submission)) => {
                                                                model.write().set_ready(submission.snapshot, false);
                                                                draft.set(String::new());
                                                            }
                                                            Ok(Err(error)) => model.write().set_notice(&error),
                                                            Err(_) => {
                                                                model.write().notice = Some(UiFailure {
                                                                    code: "RUNTIME_COORDINATOR_FAILED".into(),
                                                                    message: "续写协调任务异常结束；已持久化的 Conversation/Turn Ledger 会在重启后重读，不会另建 Mission 或自动重放外部动作。".into(),
                                                                });
                                                            }
                                                        }
                                                        runtime_cancellation.set(None);
                                                        runtime_stop_requested.set(false);
                                                        mission_submitting.set(false);
                                                    });
                                                },
                                                UiIcon { name: UiIconName::ArrowUp, size: 15 }
                                            }
                                            }
                                        } else {
                                            button { class: "send-button", disabled: !can_submit_catalog,
                                                id: "mission-composer-send",
                                                aria_label: "提交 Catalog-bound 持久 Mission",
                                                onclick: move |_| {
                                                    let project_id = model.read().selected_project_id.clone();
                                                    let manifest_id = catalog_manifest_id();
                                                    let mode = operating_mode_from_catalog_name(&catalog_mode());
                                                    let goal = draft();
                                                    let market = catalog_market();
                                                    let language = catalog_language();
                                                    let audience = catalog_audience();
                                                    let timezone = catalog_timezone();
                                                    let currency = catalog_currency();
                                                    let budget_minor = if manifest_id == "VM-11" {
                                                        Some(0)
                                                    } else {
                                                        catalog_budget_minor().trim().parse::<i64>().ok()
                                                    };
                                                    let parent_mission_id = catalog_parent_mission_id();
                                                    let parent_mission_id = (!parent_mission_id.trim().is_empty())
                                                        .then(|| MissionId::from(parent_mission_id.as_str()));
                                                    let kpis = catalog_kpi_contracts(
                                                        &manifest_id,
                                                        &catalog_kpi_metric(),
                                                        &catalog_kpi_baseline(),
                                                        &catalog_kpi_target(),
                                                        &catalog_kpi_unit(),
                                                        &catalog_kpi_direction(),
                                                    );
                                                    let (Some(project_id), Some(mode), Some(budget_minor), Some(kpis)) =
                                                        (project_id, mode, budget_minor, kpis)
                                                    else {
                                                        model.write().notice = Some(UiFailure {
                                                            code: "WAITING_USER".into(),
                                                            message: "Catalog Mission 合同尚不完整；未创建 Mission。".into(),
                                                        });
                                                        return;
                                                    };
                                                    let request = DesktopCatalogMissionRequest {
                                                        project_id,
                                                        manifest_id,
                                                        mode,
                                                        parent_mission_id,
                                                        title: None,
                                                        goal,
                                                        market,
                                                        language,
                                                        audience,
                                                        timezone,
                                                        kpis,
                                                        budget_minor,
                                                        currency,
                                                    };
                                                    let cancellation = DesktopRuntimeCancellation::default();
                                                    runtime_cancellation.set(Some(cancellation.clone()));
                                                    runtime_stop_requested.set(false);
                                                    runtime_progress.set(Vec::new());
                                                    mission_submitting.set(true);
                                                    begin_runtime_progress_monitor(
                                                        cancellation.clone(),
                                                        runtime_progress,
                                                        mission_submitting,
                                                        runtime_retrying,
                                                    );
                                                    spawn(async move {
                                                        let result = tokio::task::spawn_blocking(move || {
                                                            DesktopDataPlane::discover().and_then(|plane| {
                                                                plane.start_catalog_mission_and_run_cancellable_os(
                                                                    request,
                                                                    &cancellation,
                                                                    Utc::now(),
                                                                )
                                                            })
                                                        })
                                                        .await;
                                                        match result {
                                                            Ok(Ok(submission)) => {
                                                                model.write().set_ready(submission.snapshot, true);
                                                                draft.set(String::new());
                                                                catalog_manifest_id.set(String::new());
                                                                catalog_mode.set(String::new());
                                                                catalog_parent_mission_id.set(String::new());
                                                            }
                                                            Ok(Err(error)) => model.write().set_notice(&error),
                                                            Err(_) => {
                                                                model.write().notice = Some(UiFailure {
                                                                    code: "RUNTIME_COORDINATOR_FAILED".into(),
                                                                    message: "本地 Runtime 协调任务异常结束；重启读取时会由持久 Turn Ledger 进行 fencing，未声明 Mission 完成。".into(),
                                                                });
                                                            }
                                                        }
                                                        runtime_cancellation.set(None);
                                                        runtime_stop_requested.set(false);
                                                        mission_submitting.set(false);
                                                    });
                                                },
                                                if mission_submitting() {
                                                    "正在固化合同与首个 Checkpoint…"
                                                } else if !catalog_contract_ready {
                                                    "确认完整合同后创建"
                                                } else {
                                                    "创建 Catalog Mission"
                                                }
                                            }
                                        }
                                        }
                                        if runtime_busy && runtime_stop_available {
                                            button {
                                                id: "mission-composer-stop",
                                                class: "send-button stream-stop-button",
                                                disabled: runtime_stop_requested(),
                                                aria_label: if visual_streaming_fixture { "停止 Runtime 交互结构样例" } else if runtime_stop_requested() { "正在等待 Runtime 停止回执" } else { "停止当前 Runtime turn" },
                                                title: if visual_streaming_fixture { "VISUAL_FIXTURE · 仅切换 Stop 交互状态，不发送真实 interrupt" } else { "停止 exact Runtime attempt；保留已持久化的正文、事件与 Mission 边界" },
                                                onclick: move |_| {
                                                    request_desktop_runtime_stop(
                                                        runtime_cancellation.read().clone(),
                                                        runtime_stop_requested,
                                                        runtime_progress,
                                                        visual_streaming_fixture,
                                                    );
                                                },
                                                UiIcon { name: UiIconName::Square, size: 12 }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if workpad_visible {
                        button {
                            class: "workpad-compact-backdrop",
                            aria_label: "收起任务工作台",
                            onclick: move |_| workpad_open.set(false),
                        }
                        div {
                            id: "workpad-resize-handle",
                            class: "workpad-resize-handle",
                            role: "separator",
                            tabindex: "0",
                            aria_orientation: "vertical",
                            aria_valuemin: "440",
                            aria_valuemax: "650",
                            aria_valuenow: "500",
                            aria_valuetext: "500px Mission 会话宽度",
                            aria_label: "调整 Mission 会话与工作台宽度",
                            onpointerdown: move |event| {
                                begin_workpad_resize(event.data.client_coordinates().x);
                            },
                            onkeydown: move |event| match event.key() {
                                Key::ArrowLeft => {
                                    event.prevent_default();
                                    nudge_workpad_width(-24);
                                }
                                Key::ArrowRight => {
                                    event.prevent_default();
                                    nudge_workpad_width(24);
                                }
                                Key::Home => {
                                    event.prevent_default();
                                    set_workpad_width(440);
                                }
                                _ => {}
                            },
                            i {}
                        }
                        Workpad {
                            mission: mission.clone(),
                            context_access: context_access.clone(),
                            on_close: move |()| workpad_open.set(false),
                        }
                    }
                }
            }
            if active_overlay() == ActiveOverlay::GlobalSearch {
                GlobalSearchOverlay {
                    backend: view.backend.clone(),
                    query: global_search_query(),
                    on_query: move |value| global_search_query.set(value),
                    on_close: move |()| {
                        active_overlay.set(ActiveOverlay::None);
                        restore_ui_focus("global-search-trigger");
                    },
                    on_project: move |project_id| {
                        model.write().select_project(&project_id);
                        active_overlay.set(ActiveOverlay::None);
                        surface.set(Surface::Current);
                    },
                    on_mission: move |(project_id, mission_id)| {
                        model.write().select_project(&project_id);
                        model.write().select_mission(mission_id);
                        active_overlay.set(ActiveOverlay::None);
                        surface.set(Surface::Orchestrator);
                    },
                }
            }
            if active_overlay() == ActiveOverlay::Notifications {
                NotificationsPanel {
                    on_close: move |()| {
                        active_overlay.set(ActiveOverlay::None);
                        restore_ui_focus("notification-center-trigger");
                    },
                    on_settings: move |()| {
                        active_overlay.set(ActiveOverlay::None);
                        surface_before_settings.set(current_surface);
                        surface.set(Surface::Settings);
                    },
                }
            }
        }
    }
}

#[component]
fn NavButton(
    #[props(into)] label: String,
    #[props(into)] meta: String,
    icon: UiIconName,
    active: bool,
    onclick: EventHandler<MouseEvent>,
) -> Element {
    rsx! {
        button { class: if active { "nav-item active" } else { "nav-item" }, aria_current: active, onclick,
            span { class: "nav-icon", UiIcon { name: icon, size: 15 } }
            span { "{label}" }
            em { "{meta}" }
        }
    }
}

#[component]
fn MissionNavRow(
    mission: MissionProjection,
    active: bool,
    menu_open: bool,
    onclick: EventHandler<MouseEvent>,
    on_menu: EventHandler<MissionId>,
) -> Element {
    let dot = dispatcher_stage_dot(&mission.stage);
    let stage = mission_stage_label(&mission.stage);
    let cadence = if mission.stage == MissionStage::Scheduled {
        "持续运行".to_owned()
    } else if mission.current_checkpoint_id.is_some() {
        format!(
            "{}/{} 步 · {}",
            mission.completed_checkpoint_count, mission.checkpoint_count, stage
        )
    } else {
        stage.to_owned()
    };
    let trigger_mission_id = mission.mission_id.clone();
    let escape_mission_id = mission.mission_id.clone();
    let trigger_id = format!("mission-menu-trigger-{}", mission.mission_id.as_str());
    let escape_trigger_id = trigger_id.clone();
    let deep_link = format!("hartevo://mission/{}", mission.mission_id);
    rsx! {
        div {
            class: if active { "prototype-mission-nav-row active" } else { "prototype-mission-nav-row" },
            button {
                class: "prototype-mission-nav-main",
                aria_current: active,
                onclick,
                i { class: "{dot}" }
                span {
                    strong { "{mission.title}" }
                    small { "{cadence}" }
                }
                em { "{mission.revision}" }
            }
            button {
                id: "{trigger_id}",
                class: if menu_open { "prototype-mission-menu-trigger active" } else { "prototype-mission-menu-trigger" },
                aria_label: "{mission.title} 操作",
                aria_haspopup: "menu",
                aria_expanded: menu_open,
                onclick: move |event| {
                    event.stop_propagation();
                    on_menu.call(trigger_mission_id.clone());
                },
                UiIcon { name: UiIconName::Ellipsis, size: 14 }
            }
            if menu_open {
                section {
                    class: "prototype-mission-object-menu",
                    role: "menu",
                    aria_label: "{mission.title} 操作",
                    onkeydown: move |event| {
                        if event.key() == Key::Escape {
                            event.stop_propagation();
                            on_menu.call(escape_mission_id.clone());
                            restore_ui_focus(&escape_trigger_id);
                        }
                    },
                    button { autofocus: true, role: "menuitem", onclick, UiIcon { name: UiIconName::Message, size: 13 } "在会话中打开" }
                    button {
                        role: "menuitem",
                        onclick: move |_| {
                            let script = format!(
                                "navigator.clipboard?.writeText({deep_link:?}).catch(() => undefined)"
                            );
                            let _ = dioxus::document::eval(&script);
                        },
                        UiIcon { name: UiIconName::FileCheck, size: 13 }
                        "复制 Deep Link"
                    }
                    button { role: "menuitem", disabled: true, title: "NOT_IMPLEMENTED · 需要 Mission rename Application command", UiIcon { name: UiIconName::FileText, size: 13 } "重命名" }
                    button { class: "danger", role: "menuitem", disabled: true, title: "NOT_IMPLEMENTED · 需要可恢复归档命令", UiIcon { name: UiIconName::X, size: 13 } "归档任务" }
                }
            }
        }
    }
}

#[component]
fn GlobalSearchOverlay(
    backend: DesktopBackendState,
    query: String,
    on_query: EventHandler<String>,
    on_close: EventHandler<()>,
    on_project: EventHandler<ProjectId>,
    on_mission: EventHandler<(ProjectId, MissionId)>,
) -> Element {
    let mut selected_index = use_signal(|| 0_usize);
    let normalized = query.trim().to_lowercase();
    let mut project_results = Vec::new();
    let mut mission_results = Vec::new();
    if let DesktopBackendState::Ready(snapshot) = backend {
        for project in snapshot.inventory.projects {
            if normalized.is_empty() || project.name.to_lowercase().contains(&normalized) {
                project_results.push(project.clone());
            }
            for mission in project.missions {
                if normalized.is_empty()
                    || mission.title.to_lowercase().contains(&normalized)
                    || mission
                        .mission_id
                        .to_string()
                        .to_lowercase()
                        .contains(&normalized)
                {
                    mission_results.push((
                        project.project_id.clone(),
                        project.name.clone(),
                        mission,
                    ));
                }
            }
        }
    }
    let result_count = project_results.len() + mission_results.len();
    let mut targets = project_results
        .iter()
        .map(|project| SearchTarget::Project(project.project_id.clone()))
        .collect::<Vec<_>>();
    targets.extend(mission_results.iter().map(|(project_id, _, mission)| {
        SearchTarget::Mission(project_id.clone(), mission.mission_id.clone())
    }));
    let active_index = if result_count == 0 {
        0
    } else {
        selected_index().min(result_count.saturating_sub(1))
    };
    let active_target = targets.get(active_index).cloned();
    let project_result_count = project_results.len();
    rsx! {
        button { class: "overlay-backdrop search-backdrop", aria_label: "关闭全局搜索", onclick: move |_| on_close.call(()) }
        section {
            class: "global-search",
            role: "dialog",
            aria_modal: "true",
            aria_label: "搜索所有项目与任务",
            onkeydown: move |event| {
                match event.key() {
                    Key::Escape => on_close.call(()),
                    Key::ArrowDown if result_count > 0 => {
                        event.prevent_default();
                        selected_index.set((active_index + 1).min(result_count - 1));
                    }
                    Key::ArrowUp if result_count > 0 => {
                        event.prevent_default();
                        selected_index.set(active_index.saturating_sub(1));
                    }
                    Key::Enter => {
                        event.prevent_default();
                        match active_target.clone() {
                            Some(SearchTarget::Project(project_id)) => on_project.call(project_id),
                            Some(SearchTarget::Mission(project_id, mission_id)) => {
                                on_mission.call((project_id, mission_id));
                            }
                            None => {}
                        }
                    }
                    Key::Tab => {
                        event.prevent_default();
                        cycle_dialog_focus(
                            ".global-search",
                            event.modifiers().contains(Modifiers::SHIFT),
                        );
                    }
                    _ => {}
                }
            },
            header {
                UiIcon { name: UiIconName::Search, size: 18 }
                input {
                    id: "global-search-input",
                    autofocus: true,
                    value: "{query}",
                    aria_label: "搜索 Project 或 Mission",
                    placeholder: "搜索项目、Mission 与状态…",
                    oninput: move |event| {
                        selected_index.set(0);
                        on_query.call(event.value());
                    },
                }
                kbd { "Esc" }
            }
            div { class: "global-search-results",
                if result_count == 0 {
                    div { class: "search-empty", span { class: "honesty-badge", "EMPTY" } p { "当前持久 Inventory 中没有匹配结果。" } }
                } else {
                    if !project_results.is_empty() {
                        h2 { "项目" }
                        for (index, project) in project_results.into_iter().enumerate() {
                            {
                                let project_id = project.project_id.clone();
                                rsx! {
                                    button {
                                        class: if active_index == index { "search-result active" } else { "search-result" },
                                        onclick: move |_| on_project.call(project_id.clone()),
                                        i { class: "project-mark", "{project_initials(&project.name)}" }
                                        span { strong { "{project.name}" } small { "Project revision {project.revision} · {encryption_short_label(&project.encryption)}" } }
                                        em { "当前状态" }
                                    }
                                }
                            }
                        }
                    }
                    if !mission_results.is_empty() {
                        h2 { "Mission" }
                        for (index, (project_id, project_name, mission)) in mission_results.into_iter().enumerate() {
                            {
                                let mission_id = mission.mission_id.clone();
                                rsx! {
                                    button {
                                        class: if active_index == project_result_count + index { "search-result active" } else { "search-result" },
                                        onclick: move |_| on_mission.call((project_id.clone(), mission_id.clone())),
                                        i { class: "mission-result-mark", UiIcon { name: UiIconName::Target, size: 14 } }
                                        span { strong { "{mission.title}" } small { "{project_name} · {mission_stage_label(&mission.stage)} · revision {mission.revision}" } }
                                        em { "打开会话" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            footer { span { "↑ ↓ 选择" } span { "Enter 打开" } span { "结果来自持久 Application Projection" } }
        }
    }
}

#[component]
fn NotificationsPanel(on_close: EventHandler<()>, on_settings: EventHandler<()>) -> Element {
    #[cfg(feature = "visual-fixtures")]
    if let Some(presentation) = visual_fixture::presentation() {
        return rsx! {
            PrototypeNotificationsPanel {
                notifications: presentation.notifications,
                on_close,
                on_settings,
            }
        };
    }
    rsx! {
        button { class: "overlay-dismiss", aria_label: "关闭通知", onclick: move |_| on_close.call(()) }
        section {
            class: "notification-center",
            role: "dialog",
            aria_modal: "true",
            aria_label: "全部项目通知",
            tabindex: "-1",
            onkeydown: move |event| match event.key() {
                Key::Escape => on_close.call(()),
                Key::Tab => {
                    event.prevent_default();
                    cycle_dialog_focus(
                        ".notification-center",
                        event.modifiers().contains(Modifiers::SHIFT),
                    );
                }
                _ => {}
            },
            header { class: "notification-head",
                strong { "通知" }
                span { "所有宣发项目" }
                button { id: "notification-center-close", autofocus: true, aria_label: "关闭通知", onclick: move |_| on_close.call(()), UiIcon { name: UiIconName::X, size: 14 } }
            }
            nav { class: "notification-tabs", aria_label: "筛选通知",
                button { class: "active", "全部" }
                button { disabled: true, "需要你 0" }
                button { disabled: true, "运行动态" }
            }
            div { class: "notification-empty",
                UiIcon { name: UiIconName::Bell, size: 19 }
                strong { "暂无持久通知" }
                span { "Application 尚未提供跨项目 Notification Projection；这里不会复制原型中的演示提醒。" }
                em { "NOT_IMPLEMENTED" }
            }
            footer { class: "notification-footer",
                span { "通知按项目隔离，用户级聚合" }
                button { onclick: move |_| on_settings.call(()), "通知设置" }
            }
        }
    }
}

#[cfg(feature = "visual-fixtures")]
#[component]
fn PrototypeNotificationsPanel(
    notifications: Vec<visual_fixture::VisualNotification>,
    on_close: EventHandler<()>,
    on_settings: EventHandler<()>,
) -> Element {
    let mut active_tab = use_signal(|| "all".to_owned());
    let mut read_all = use_signal(|| false);
    let visible = notifications
        .iter()
        .filter(|notification| {
            active_tab() == "all"
                || (active_tab() == "attention" && notification.kind == "需要你")
                || (active_tab() == "activity" && notification.kind == "运行动态")
        })
        .cloned()
        .collect::<Vec<_>>();
    let attention_count = notifications
        .iter()
        .filter(|notification| notification.kind == "需要你")
        .count();
    rsx! {
        button { class: "overlay-dismiss", aria_label: "关闭通知", onclick: move |_| on_close.call(()) }
        section {
            class: "notification-center fixture-notifications",
            role: "dialog",
            aria_modal: "true",
            aria_label: "全部项目通知",
            tabindex: "-1",
            onkeydown: move |event| match event.key() {
                Key::Escape => on_close.call(()),
                Key::Tab => {
                    event.prevent_default();
                    cycle_dialog_focus(
                        ".notification-center.fixture-notifications",
                        event.modifiers().contains(Modifiers::SHIFT),
                    );
                }
                _ => {}
            },
            header { class: "notification-head",
                strong { "通知" }
                span { "所有宣发项目" }
                button { class: "notification-read-all", onclick: move |_| read_all.set(true), if read_all() { "已全部标记" } else { "全部已读" } }
                button { id: "notification-center-close", autofocus: true, aria_label: "关闭通知", onclick: move |_| on_close.call(()), UiIcon { name: UiIconName::X, size: 14 } }
            }
            div { class: "fixture-notification-disclosure", "VISUAL_FIXTURE · 结构样例，不是持久 Notification Projection" }
            nav { class: "notification-tabs", aria_label: "筛选通知",
                button { class: if active_tab() == "all" { "active" } else { "" }, onclick: move |_| active_tab.set("all".into()), "全部" }
                button { class: if active_tab() == "attention" { "active" } else { "" }, onclick: move |_| active_tab.set("attention".into()), "需要你 {attention_count}" }
                button { class: if active_tab() == "activity" { "active" } else { "" }, onclick: move |_| active_tab.set("activity".into()), "运行动态" }
            }
            div { class: "fixture-notification-list",
                for item in visible {
                    button { class: if read_all() { "fixture-notification-row read" } else { "fixture-notification-row" },
                        i { "{item.mark}" }
                        span { strong { "{item.title}" } small { "{item.context}" } time { "{item.time}" } }
                        em { "{item.kind}" }
                    }
                }
            }
            footer { class: "notification-footer",
                span { "通知按项目隔离，用户级聚合" }
                button { onclick: move |_| on_settings.call(()), "通知设置" }
            }
        }
    }
}

#[cfg(feature = "visual-fixtures")]
#[component]
fn PrototypeMissionJourney(
    mission: MissionProjection,
    conversation: visual_fixture::VisualConversation,
    approval: visual_fixture::VisualApproval,
    outcome: visual_fixture::VisualOutcome,
    on_open_workpad: EventHandler<()>,
) -> Element {
    let fixture_variant = active_visual_surface_variant();
    let frozen_stream_frame = fixture_variant.as_deref() == Some("mission-streaming");
    let initial_outcome = fixture_variant.as_deref() == Some("mission-outcome");
    let mut capability_open = use_signal(|| false);
    let mut preview_outcome = use_signal(move || initial_outcome);
    let mut progress_open = use_signal(|| false);
    let mut approval_facts_open = use_signal(|| false);
    let mut approval_edit_open = use_signal(|| false);
    let mut approval_deferred = use_signal(|| false);
    let mut approval_digest_revision = use_signal(|| 1_u32);
    let mut approval_budget = use_signal(|| "140000".to_owned());
    let mut stream_interrupted = use_signal(|| false);
    let intro_source = conversation.assistant_intro.clone();
    let intro_initial = if frozen_stream_frame {
        intro_source.chars().take(56).collect::<String>()
    } else {
        intro_source.clone()
    };
    let progress_total = conversation.progress.len();
    let mut streamed_intro = use_signal(move || intro_initial);
    let initial_progress = if frozen_stream_frame {
        progress_total.min(3)
    } else {
        progress_total
    };
    let mut visible_progress = use_signal(move || initial_progress);
    let mut stream_running = use_signal(move || frozen_stream_frame);
    let mut stream_generation = use_signal(|| 0_u64);
    let approval_view = mission.stage == MissionStage::WaitingApproval;

    if preview_outcome() {
        return rsx! {
            div { class: "surface-scroll prototype-thread",
                article { class: "assistant-turn prototype-turn fixture-outcome-turn",
                    header { class: "assistant-byline",
                        img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                        strong { "Hartevo" }
                        time { "结构预览" }
                    }
                    div { class: "fixture-disclosure-banner", role: "status",
                        strong { "VISUAL_FIXTURE · 未执行" }
                        span { "此状态只验证结果区交互与布局；没有 ProviderReceipt、Verification、OutcomeEvent 或支出。" }
                    }
                    div { class: "assistant-copy", p { "{outcome.intro}" } }
                    section { class: "fixture-outcome-metrics", aria_label: "结果结构样例",
                        for metric in outcome.metrics.clone() {
                            div { strong { "{metric.value}" } small { "{metric.label}" } }
                        }
                    }
                    div { class: "fixture-receipt-stack",
                        for row in outcome.rows.clone() {
                            div { class: "fixture-receipt-row",
                                i { UiIcon { name: UiIconName::Shield, size: 13 } }
                                span { strong { "{row.title}" } small { "{row.detail}" } }
                                em { "{row.meta}" }
                                b { class: "fixture-state neutral", "{row.state}" }
                            }
                        }
                    }
                    div { class: "prototype-next-loop",
                        span { strong { "下一步仍由用户决定" } small { "Continue / Stop / Scale / Test；不会因为预览结果而推进 Mission。" } }
                        button { onclick: move |_| preview_outcome.set(false), "返回审批结构" }
                    }
                }
            }
        };
    }

    if approval_view {
        return rsx! {
            div { class: "surface-scroll prototype-thread",
                div { class: "prototype-user-row",
                    div { class: "prototype-user-message", "{approval.user_prompt}" time { "10:26" } }
                }
                article { class: "assistant-turn prototype-turn",
                    header { class: "assistant-byline",
                        img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                        strong { "Hartevo" }
                        time { "10:28" }
                    }
                    div { class: "assistant-copy",
                        p { "{approval.assistant_intro}" }
                        p { "你可以直接修改预算、渠道、受众或时间；任何字段变化都会生成新的完整 digest。" }
                    }
                    if approval_deferred() {
                        div { class: "fixture-approval-notice", role: "status",
                            strong { "已保留在等待确认" }
                            span { "仅改变本页视觉夹具状态；未创建 ApprovalGrant，也未执行 Effect。" }
                        }
                    }
                    section { class: "prototype-approval-panel", aria_label: "精确审批结构样例",
                        header {
                            i { UiIcon { name: UiIconName::Shield, size: 14 } }
                            strong { "审阅 4 个外部动作结构" }
                            span { "Effect Broker · VISUAL_FIXTURE" }
                        }
                        div { class: "prototype-effect-list",
                            for (index, effect) in approval.effects.clone().into_iter().enumerate() {
                                div { class: "prototype-effect-row",
                                    i { "{index + 1}" }
                                    span { strong { "{effect.title}" } small { "{effect.detail}" } }
                                    b { "{effect.state}" }
                                }
                            }
                        }
                        if approval_edit_open() {
                            section { class: "fixture-approval-editor", aria_label: "修改审批结构样例",
                                header { strong { "修改会使旧 digest 失效" } span { "SAMPLE revision {approval_digest_revision}" } }
                                label { span { "预算（minor units）" } input {
                                    value: "{approval_budget}",
                                    inputmode: "numeric",
                                    aria_label: "视觉夹具预算 minor units",
                                    oninput: move |event| approval_budget.set(event.value()),
                                } }
                                label { span { "渠道" } select { aria_label: "视觉夹具渠道", option { "Meta Ads · US" } option { "TikTok Ads · US" } } }
                                footer {
                                    span { "VISUAL_FIXTURE · 不写入 Domain" }
                                    button {
                                        class: "surface-button primary",
                                        onclick: move |_| {
                                            approval_digest_revision.set(approval_digest_revision().saturating_add(1));
                                            approval_edit_open.set(false);
                                        },
                                        "生成新结构 digest"
                                    }
                                }
                            }
                        }
                        if approval_facts_open() {
                            div { class: "prototype-approval-facts",
                                for fact in approval.facts.clone() {
                                    div { span { "{fact.title}" } strong { "{fact.detail}" } small { "{fact.state}" } }
                                }
                            }
                        }
                        footer { class: "prototype-approval-actions",
                            button {
                                class: "surface-button primary",
                                onclick: move |_| preview_outcome.set(true),
                                "预览批准后结构"
                            }
                            button { class: "surface-button", onclick: move |_| approval_edit_open.set(!approval_edit_open()), "修改样例" }
                            button { class: "surface-button", onclick: move |_| approval_deferred.set(true), "稍后处理" }
                            button { class: "approval-digest-toggle", aria_expanded: approval_facts_open(), onclick: move |_| approval_facts_open.set(!approval_facts_open()), "完整 digest" }
                            span { "SAMPLE r{approval_digest_revision} · 不创建 ApprovalGrant / EffectIntent" }
                        }
                    }
                }
            }
        };
    }

    rsx! {
        div { class: "surface-scroll prototype-thread",
            div { class: "prototype-user-row",
                div { class: "prototype-user-message", "{conversation.user_prompt}" time { "10:21" } }
            }
                article { class: "assistant-turn prototype-turn",
                    header { class: "assistant-byline",
                        img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                        strong { "Hartevo" }
                        time { "10:21" }
                        button {
                            class: "fixture-stream-replay",
                            disabled: stream_running(),
                            aria_label: "重播视觉夹具的流式响应",
                            onclick: move |_| {
                                let next_generation = stream_generation().saturating_add(1);
                                stream_generation.set(next_generation);
                                streamed_intro.set(String::new());
                                visible_progress.set(0);
                                stream_running.set(true);
                                stream_interrupted.set(false);
                                let full_intro = intro_source.clone();
                                spawn(async move {
                                    let mut rendered = String::new();
                                    let characters = full_intro.chars().collect::<Vec<_>>();
                                    for chunk in characters.chunks(3) {
                                        if stream_generation() != next_generation {
                                            return;
                                        }
                                        rendered.extend(chunk.iter());
                                        streamed_intro.set(rendered.clone());
                                        let _ = dioxus::document::eval(
                                            "(() => { const thread = document.querySelector('.prototype-thread'); if (!thread) return; const nearBottom = thread.scrollHeight - thread.scrollTop - thread.clientHeight < 80; if (nearBottom) thread.scrollTo({top: thread.scrollHeight, behavior: 'smooth'}); })();",
                                        );
                                        tokio::time::sleep(std::time::Duration::from_millis(34)).await;
                                    }
                                    for count in 1..=progress_total {
                                        if stream_generation() != next_generation {
                                            return;
                                        }
                                        visible_progress.set(count);
                                        tokio::time::sleep(std::time::Duration::from_millis(260)).await;
                                    }
                                    stream_running.set(false);
                                    stream_interrupted.set(false);
                                });
                            },
                            UiIcon { name: UiIconName::Refresh, size: 12 }
                            if frozen_stream_frame { "流式取证帧" } else { "重播流式轨迹" }
                        }
                    }
                    div { class: "assistant-copy fixture-stream-copy", aria_live: "polite", aria_busy: stream_running(),
                        p {
                            "{streamed_intro}"
                            if stream_running() { i { class: "fixture-stream-caret", aria_hidden: "true" } }
                        }
                    }
                section { class: "prototype-mission-contract", aria_label: "系统理解的任务边界",
                    header {
                        UiIcon { name: UiIconName::FileText, size: 14 }
                        strong { "已编译为 Hartevo Mission" }
                        span { "你可以直接用自然语言修改" }
                    }
                    div { class: "prototype-contract-grid",
                        div { small { "目标" } strong { "{conversation.goal}" } }
                        div { small { "自动执行" } strong { "{conversation.automatic}" } }
                        div { small { "必须确认" } strong { "{conversation.approval}" } }
                    }
                }
                section { class: "mission-activity-stream", aria_label: "Mission 流式活动",
                    header {
                        strong { "运行轨迹" }
                        span { "事件来自冻结视觉夹具 · 不构成 Runtime/Provider 证据" }
                    }
                    for item in conversation.progress.clone().into_iter().take(visible_progress()) {
                        div { class: "mission-activity-row",
                            i { class: if item.state == "live" { "mission-activity-icon live" } else { "mission-activity-icon done" },
                                if item.state == "live" { span {} } else { UiIcon { name: UiIconName::Check, size: 10 } }
                            }
                            span { class: "mission-activity-copy",
                                strong { "{item.title}" }
                                small { "{item.detail}" }
                                em { "{item.capability}" }
                            }
                            time { "{item.time}" }
                        }
                    }
                    button {
                        class: "mission-activity-group-toggle",
                        aria_expanded: capability_open(),
                        onclick: move |_| capability_open.set(!capability_open()),
                        UiIcon { name: UiIconName::Workflow, size: 14 }
                        span { strong { "本次任务的能力与运行事件" } small { "{conversation.capability_summary}" } }
                        UiIcon { name: UiIconName::ChevronDown, size: 13 }
                    }
                    if capability_open() {
                        div { class: "mission-activity-details",
                            span { strong { "Skill" } small { "Opportunity Validation · Candidate" } }
                            span { strong { "Provider route" } small { "Simulator only · no live account" } }
                            span { strong { "Worker generation" } small { "Fixture g1 · no process started" } }
                            span { strong { "Effect boundary" } small { "0 intents · 0 receipts · 0 verifications" } }
                        }
                    }
                    if frozen_stream_frame || stream_running() || stream_interrupted() {
                        div { class: "compaction-event-row",
                            UiIcon { name: UiIconName::FileCheck, size: 14 }
                            span { strong { "上下文压缩记录结构" } small { "Truth correction、Pending Effect 与审批边界保持；fixture 未执行压缩。" } }
                            em { "CTX · SAMPLE" }
                        }
                    }
                }
                div { class: "prototype-connection-suggestion",
                    i { "+" }
                    span { strong { "{conversation.connection_title}" } small { "{conversation.connection_detail}" } }
                    button { "查看连接建议" }
                }
                button { class: "prototype-artifact-attachment", onclick: move |_| on_open_workpad.call(()),
                    i { UiIcon { name: UiIconName::FileText, size: 17 } }
                    span { strong { "{conversation.artifact_title}" } small { "{conversation.artifact_meta}" } }
                    em { "在工作台打开" }
                }
                section { class: "prototype-decision-summary",
                    h3 { "结论" }
                    p { "{conversation.decision}" }
                }
                button {
                    class: if progress_open() { "mission-progress-pill open" } else { "mission-progress-pill" },
                    aria_label: "打开 Checkpoint 进度",
                    aria_expanded: progress_open(),
                    onclick: move |_| progress_open.set(!progress_open()),
                    i { class: "live" }
                    strong { "第 {mission.completed_checkpoint_count + 1} / {mission.checkpoint_count} 步" }
                    span { "· revision {mission.revision} · 0 外部 Effect" }
                    UiIcon { name: UiIconName::ChevronDown, size: 12 }
                }
                if progress_open() {
                    section { class: "mission-progress-popover", aria_label: "Checkpoint 进度结构",
                        header { strong { "Mission Checkpoints" } span { "VISUAL_FIXTURE" } }
                        div { i { class: "done" } span { strong { "约束与证据计划" } small { "已冻结 · 无外部动作" } } em { "1" } }
                        div { i { class: "live" } span { strong { "采集与冲突核验" } small { "当前结构样例" } } em { "2" } }
                        div { i {} span { strong { "决策与反证" } small { "等待前序 Oracle" } } em { "3" } }
                        footer { "纠正只使依赖分支失效；不会清空无关 Work Product。" }
                    }
                }
                if stream_running() {
                    div { class: "fixture-stream-controls", role: "status",
                        button {
                            class: "fixture-follow-latest",
                            onclick: move |_| {
                                let _ = dioxus::document::eval(
                                    "document.querySelector('.prototype-thread')?.scrollTo({top: document.querySelector('.prototype-thread').scrollHeight, behavior: 'smooth'});",
                                );
                            },
                            "回到最新"
                        }
                        button {
                            class: "fixture-stop-stream",
                            onclick: move |_| {
                                stream_generation.set(stream_generation().saturating_add(1));
                                stream_running.set(false);
                                stream_interrupted.set(true);
                            },
                            span { aria_hidden: "true" }
                            "停止重播"
                        }
                    }
                } else if stream_interrupted() {
                    div { class: "fixture-stream-interrupted", role: "status",
                        span { aria_hidden: "true" }
                        strong { "已停止重播" }
                        small { "当前正文、活动与 Mission 边界保持；没有回滚或外部 Effect。" }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "visual-fixtures")]
fn fixture_state_tone(value: &str) -> &'static str {
    if value.contains("BLOCKED") || value.contains("重新授权") || value.contains("安全阻塞")
    {
        "error"
    } else if value.contains("等待") || value.contains("需") || value.contains("审批") {
        "warning"
    } else if value.contains("可研究") || value.contains("可选") || value.contains("采用") {
        "success"
    } else {
        "neutral"
    }
}

#[cfg(feature = "visual-fixtures")]
#[component]
fn PrototypeOperationsSurface(
    page: visual_fixture::VisualPage,
    #[props(into)] title: String,
    #[props(into)] description: String,
    #[props(into)] eyebrow: String,
) -> Element {
    let initial_tab = page
        .tabs
        .first()
        .map(|tab| tab.id.clone())
        .unwrap_or_default();
    let mut active_tab = use_signal(move || initial_tab);
    let mut selected_row = use_signal(|| None::<visual_fixture::VisualRow>);
    let mut strategy_open = use_signal(|| false);
    let mut split_index = use_signal(|| 0_usize);
    let mut connection_flow_open = use_signal(|| false);
    let mut connection_flow_step = use_signal(|| 1_u8);
    let is_connections = page.id == "connections";
    let selected = page
        .tabs
        .iter()
        .find(|tab| tab.id == active_tab())
        .cloned()
        .or_else(|| page.tabs.first().cloned());
    let Some(selected) = selected else {
        return rsx! { EmptyState { code: "EMPTY", title: "视觉夹具缺少页面状态", detail: "Fixture schema 未提供可渲染 tab。" } };
    };
    let column_count = selected.columns.len().max(1);
    let grid_style = format!("grid-template-columns: repeat({column_count}, minmax(0, 1fr));");
    let suggested_row = selected.rows.first().cloned();
    let split_row = selected.rows.get(split_index()).cloned();
    let split_title = split_row
        .as_ref()
        .map_or("Conversation sample", |row| row.title.as_str());
    let split_detail = split_row
        .as_ref()
        .map_or("No selected fixture conversation", |row| {
            row.detail.as_str()
        });

    rsx! {
        div { class: "surface-scroll business-surface prototype-operations-surface",
            div { class: "prototype-growth-topbar",
                strong { "北美增长项目" }
                nav { aria_label: "增长运营模块",
                    span { "连接" }
                    span { "渠道" }
                    span { "关系" }
                    span { "达人与联盟" }
                }
                em { i {} "共享总调度状态 · 视觉夹具" }
            }
            header { class: "surface-head prototype-surface-head",
                div { class: "surface-head-copy",
                    span { class: "surface-eyebrow", "{eyebrow}" }
                    h1 { "{title}" }
                    p { "{description}" }
                }
                div { class: "surface-head-actions",
                    button { class: "surface-button", onclick: move |_| strategy_open.set(true), "页面策略" }
                    button {
                        class: "surface-button primary",
                        onclick: move |_| {
                            if is_connections {
                                connection_flow_step.set(1);
                                connection_flow_open.set(true);
                            } else {
                                selected_row.set(suggested_row.clone());
                            }
                        },
                        if is_connections { "连接服务" } else { "建议下一步" }
                    }
                }
            }
            nav { class: "surface-tabs prototype-surface-tabs", aria_label: "{title} 视图",
                for tab in page.tabs.clone() {
                    {
                        let tab_id = tab.id.clone();
                        rsx! {
                            button {
                                class: if active_tab() == tab.id { "active" } else { "" },
                                onclick: move |_| active_tab.set(tab_id.clone()),
                                "{tab.label}"
                            }
                        }
                    }
                }
            }
            section { class: "prototype-readiness-strip",
                div { class: "prototype-readiness-intro",
                    span { class: "readiness-mark", UiIcon { name: UiIconName::Sparkles, size: 17 } }
                    span { strong { "结构样例，不构成业务状态" } small { "数据来自 prototype-baseline-v1；真实页面仍只读取 Application Projection。" } }
                }
                for metric in page.stats.clone() {
                    div { class: "readiness-stat", b { "{metric.value}" } small { "{metric.label}" } }
                }
            }
            section { class: "prototype-operation-section",
                header { h2 { "{selected.headline}" } p { "{selected.subline}" } span { "VISUAL_FIXTURE" } }
                if selected.kind == "ranked" {
                    div { class: "prototype-ranked-layout",
                        main { class: "prototype-ranked-list",
                            for (index, row) in selected.rows.clone().into_iter().enumerate() {
                                div { class: "prototype-ranked-row",
                                    i { "{index + 1}" }
                                    span { strong { "{row.title}" } small { "{row.detail}" } }
                                    em { "{row.meta}" }
                                    b { class: "fixture-state {fixture_state_tone(&row.state)}", "{row.state}" }
                                    button {
                                        aria_label: "打开 {row.title}",
                                        onclick: {
                                            let row = row.clone();
                                            move |_| selected_row.set(Some(row.clone()))
                                        },
                                        "打开"
                                    }
                                }
                            }
                        }
                        aside { class: "prototype-operation-aside",
                            UiIcon { name: UiIconName::Shield, size: 17 }
                            strong { "能力不会因页面样例自动启用" }
                            p { "连接、Consent、Contact Permission、审批、Receipt 与 Verification 仍由真实 Domain 状态决定。" }
                            button { onclick: move |_| strategy_open.set(true), "查看动作边界" }
                        }
                    }
                } else if selected.kind == "calendar" {
                    div { class: "prototype-calendar",
                        div { class: "prototype-calendar-head", style: "{grid_style}",
                            for column in selected.columns.clone() { strong { "{column}" } }
                        }
                        for row in selected.rows.clone() {
                            div { class: "prototype-calendar-row",
                                span { strong { "{row.title}" } small { "{row.detail}" } }
                                div { class: "prototype-calendar-lane", span { "{row.meta}" } }
                                b { class: "fixture-state {fixture_state_tone(&row.state)}", "{row.state}" }
                            }
                        }
                    }
                } else if selected.kind == "split" {
                    div { class: "prototype-split-view",
                        nav { aria_label: "会话样例",
                            for (index, row) in selected.rows.clone().into_iter().enumerate() {
                                button {
                                    class: if split_index() == index { "active" } else { "" },
                                    onclick: move |_| split_index.set(index),
                                    span { strong { "{row.title}" } small { "{row.detail}" } }
                                    em { "{row.meta}" }
                                    b { "{row.state}" }
                                }
                            }
                        }
                        article {
                            span { class: "surface-eyebrow", "HUMAN HANDOFF · SAMPLE" }
                            h3 { "{split_title}" }
                            p { "{split_detail}" }
                            div { class: "prototype-handoff-card",
                                UiIcon { name: UiIconName::Bot, size: 16 }
                                span { strong { "人工接管锁结构" } small { "旧 Worker generation 不得继续外发；fixture 没有发送消息。" } }
                                b { "HANDOFF" }
                            }
                            button {
                                class: "surface-button primary",
                                onclick: {
                                    let row = split_row.clone();
                                    move |_| selected_row.set(row.clone())
                                },
                                "查看回复草稿"
                            }
                        }
                    }
                } else if selected.kind == "kanban" {
                    div { class: "prototype-kanban",
                        for (index, column) in selected.columns.clone().into_iter().enumerate() {
                            div { class: "prototype-kanban-column",
                                header { strong { "{column}" } span { "1" } }
                                if let Some(row) = selected.rows.get(index) {
                                    button {
                                        class: "prototype-kanban-card",
                                        onclick: {
                                            let row = row.clone();
                                            move |_| selected_row.set(Some(row.clone()))
                                        },
                                        strong { "{row.title}" }
                                        p { "{row.detail}" }
                                        small { "{row.meta}" }
                                        b { class: "fixture-state {fixture_state_tone(&row.state)}", "{row.state}" }
                                    }
                                }
                            }
                        }
                    }
                } else if selected.kind == "workflow" {
                    div { class: "prototype-workflow-layout",
                        main { class: "prototype-workflow-list",
                            for (index, row) in selected.rows.clone().into_iter().enumerate() {
                                button {
                                    class: "prototype-workflow-row",
                                    onclick: {
                                        let row = row.clone();
                                        move |_| selected_row.set(Some(row.clone()))
                                    },
                                    i { "{index + 1}" }
                                    span { strong { "{row.title}" } small { "{row.detail}" } }
                                    em { "{row.meta}" }
                                    b { class: "fixture-state {fixture_state_tone(&row.state)}", "{row.state}" }
                                }
                            }
                        }
                        aside { class: "prototype-review-panel",
                            span { class: "surface-eyebrow", "DELIVERABLE REVIEW" }
                            h3 { "交付、Review、Rights 与付款分离" }
                            p { "真实 Deliverable digest、用户接受、权益记录和精确 Payout 审批必须齐全。Provider 接受不等于已付款。" }
                            div { strong { "$300.00 USD" } small { "Reward fixture · 0 payout effects" } }
                            button { class: "surface-button", onclick: move |_| strategy_open.set(true), "查看合同边界" }
                        }
                    }
                } else {
                    div { class: "prototype-data-table",
                        if !selected.columns.is_empty() {
                            div { class: "prototype-data-head", style: "{grid_style}",
                                for column in selected.columns.clone() { strong { "{column}" } }
                            }
                        }
                        for row in selected.rows.clone() {
                            div { class: "prototype-data-row",
                                span { strong { "{row.title}" } small { "{row.detail}" } }
                                em { "{row.meta}" }
                                b { class: "fixture-state {fixture_state_tone(&row.state)}", "{row.state}" }
                                button {
                                    onclick: {
                                        let row = row.clone();
                                        move |_| selected_row.set(Some(row.clone()))
                                    },
                                    "查看"
                                }
                            }
                        }
                    }
                }
            }
            if let Some(row) = selected_row() {
                button { class: "prototype-drawer-backdrop", aria_label: "关闭详情", onclick: move |_| selected_row.set(None) }
                aside {
                    class: "prototype-detail-drawer",
                    role: "dialog",
                    aria_modal: "true",
                    aria_label: "{row.title} 详情",
                    tabindex: "-1",
                    onkeydown: move |event| match event.key() {
                        Key::Escape => selected_row.set(None),
                        Key::Tab => {
                            event.prevent_default();
                            cycle_dialog_focus(
                                ".prototype-detail-drawer",
                                event.modifiers().contains(Modifiers::SHIFT),
                            );
                        }
                        _ => {}
                    },
                    header {
                        span { class: "surface-eyebrow", "{page.id.to_uppercase()} · VISUAL_FIXTURE" }
                        button { autofocus: true, aria_label: "关闭详情", onclick: move |_| selected_row.set(None), UiIcon { name: UiIconName::X, size: 15 } }
                    }
                    section {
                        h2 { "{row.title}" }
                        p { "{row.detail}" }
                        div { class: "prototype-detail-state",
                            span { "当前结构状态" }
                            b { class: "fixture-state {fixture_state_tone(&row.state)}", "{row.state}" }
                        }
                        dl {
                            div { dt { "范围" } dd { "{row.meta}" } }
                            div { dt { "外部动作" } dd { "0 EffectIntent" } }
                            div { dt { "业务证据" } dd { "0 Receipt · 0 Verification" } }
                            div { dt { "数据来源" } dd { "prototype-baseline-v1" } }
                        }
                        article { class: "prototype-detail-note",
                            UiIcon { name: UiIconName::Shield, size: 15 }
                            span { strong { "这是可操作结构，不是业务成功" } small { "真实按钮必须由 Application Service 提供精确命令；当前只允许关闭、切换与审阅结构。" } }
                        }
                    }
                    footer {
                        button { class: "surface-button", onclick: move |_| selected_row.set(None), "返回列表" }
                        button { class: "surface-button primary", disabled: true, "NOT_IMPLEMENTED" }
                    }
                }
            }
            if strategy_open() {
                button { class: "prototype-drawer-backdrop", aria_label: "关闭页面策略", onclick: move |_| strategy_open.set(false) }
                aside {
                    class: "prototype-detail-drawer strategy",
                    role: "dialog",
                    aria_modal: "true",
                    aria_label: "页面策略与动作边界",
                    tabindex: "-1",
                    onkeydown: move |event| match event.key() {
                        Key::Escape => strategy_open.set(false),
                        Key::Tab => {
                            event.prevent_default();
                            cycle_dialog_focus(
                                ".prototype-detail-drawer.strategy",
                                event.modifiers().contains(Modifiers::SHIFT),
                            );
                        }
                        _ => {}
                    },
                    header {
                        span { class: "surface-eyebrow", "PAGE POLICY · HONEST BOUNDARY" }
                        button { autofocus: true, aria_label: "关闭页面策略", onclick: move |_| strategy_open.set(false), UiIcon { name: UiIconName::X, size: 15 } }
                    }
                    section {
                        h2 { "{title}如何读取与改变状态" }
                        p { "页面、Tab、筛选和抽屉只是同一 Project / Mission Domain 的投影视图；它们不能自己生成成功状态。" }
                        ol { class: "prototype-policy-steps",
                            li { strong { "1 · Read" } span { "从 Application Projection 读取项目、账号与业务对象。" } }
                            li { strong { "2 · Prepare" } span { "草稿保持本地，变更先形成精确 diff 与 digest。" } }
                            li { strong { "3 · Approve" } span { "对象、受众、素材、金额、时间、账号任一变化都会使批准失效。" } }
                            li { strong { "4 · Verify" } span { "Provider 接受之后仍需独立 readback；uncertain 永不自动重放。" } }
                        }
                        div { class: "fixture-disclosure-banner",
                            strong { "VISUAL_FIXTURE" }
                            span { "当前页面没有 Connection、Consent、Receipt、Verification 或 E3 证据。" }
                        }
                    }
                    footer { button { class: "surface-button primary", onclick: move |_| strategy_open.set(false), "知道了" } }
                }
            }
            if connection_flow_open() {
                button { class: "prototype-modal-backdrop", aria_label: "关闭连接向导", onclick: move |_| connection_flow_open.set(false) }
                section {
                    class: "prototype-connection-modal",
                    role: "dialog",
                    aria_modal: "true",
                    aria_label: "连接服务流程结构",
                    tabindex: "-1",
                    onkeydown: move |event| match event.key() {
                        Key::Escape => connection_flow_open.set(false),
                        Key::Tab => {
                            event.prevent_default();
                            cycle_dialog_focus(
                                ".prototype-connection-modal",
                                event.modifiers().contains(Modifiers::SHIFT),
                            );
                        }
                        _ => {}
                    },
                    header {
                        span { strong { "连接服务" } small { "Step {connection_flow_step} of 4 · VISUAL_FIXTURE" } }
                        button { autofocus: true, aria_label: "关闭连接向导", onclick: move |_| connection_flow_open.set(false), UiIcon { name: UiIconName::X, size: 15 } }
                    }
                    div { class: "prototype-flow-progress",
                        for step in 1_u8..=4 {
                            i { class: if step <= connection_flow_step() { "active" } else { "" } }
                        }
                    }
                    main {
                        if connection_flow_step() == 1 {
                            span { class: "surface-eyebrow", "SELECT PROVIDER" }
                            h2 { "选择当前 Mission 真正需要的服务" }
                            p { "连接不会自动启用写入；每项 Capability 仍需独立 Policy 和审批。" }
                            div { class: "prototype-provider-grid",
                                button { class: "selected", UiIcon { name: UiIconName::Chart, size: 17 } strong { "Google Analytics" } small { "Read-only measurement" } }
                                button { UiIcon { name: UiIconName::Mail, size: 17 } strong { "Gmail" } small { "Read + send boundaries" } }
                                button { UiIcon { name: UiIconName::Contact, size: 17 } strong { "HubSpot" } small { "CRM identity" } }
                                button { UiIcon { name: UiIconName::Wallet, size: 17 } strong { "Stripe" } small { "Billing / settlement" } }
                            }
                        } else if connection_flow_step() == 2 {
                            span { class: "surface-eyebrow", "ACCOUNT & SCOPE" }
                            h2 { "确认账号身份与最小 Scope" }
                            p { "实际 OAuth 必须显示 Provider、账号和 scopes；当前环境没有打开授权页面。" }
                            div { class: "prototype-auth-scope",
                                strong { "analytics.readonly" }
                                small { "只读 Measurement；不允许管理账号或修改数据。" }
                                b { "BLOCKED_ENV" }
                            }
                        } else if connection_flow_step() == 3 {
                            span { class: "surface-eyebrow", "PROBE" }
                            h2 { "实时验证连接与目标账号" }
                            p { "只有实时 Probe 成功才能显示 Connected。fixture 不会生成绿色成功状态。" }
                            div { class: "prototype-probe-state", UiIcon { name: UiIconName::Shield, size: 18 } strong { "等待真实 OAuth 环境" } small { "No token · no account identity · no scopes" } b { "BLOCKED_ENV" } }
                        } else {
                            span { class: "surface-eyebrow", "MISSION BINDING" }
                            h2 { "绑定项目与允许的 Capability" }
                            p { "连接只绑定当前 Tenant / Project / Provider / Account；不会跨项目复用正文或凭据。" }
                            div { class: "fixture-disclosure-banner", strong { "未连接" } span { "向导结构已覆盖；真实回调、Probe、撤销和重授权仍为 BLOCKED_ENV。" } }
                        }
                    }
                    footer {
                        button { class: "surface-button", disabled: connection_flow_step() == 1, onclick: move |_| connection_flow_step.set(connection_flow_step().saturating_sub(1).max(1)), "上一步" }
                        span { "不会启动 OAuth 或写入 Secret Store" }
                        if connection_flow_step() < 4 {
                            button { class: "surface-button primary", onclick: move |_| connection_flow_step.set(connection_flow_step().saturating_add(1).min(4)), "下一步" }
                        } else {
                            button { class: "surface-button primary", onclick: move |_| connection_flow_open.set(false), "完成结构审阅" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn IntegrityBanner(failure: UiFailure) -> Element {
    rsx! {
        section { class: "integrity-banner", role: "alert",
            strong { "{failure.code}" }
            span { "{failure.message}" }
        }
    }
}

#[component]
fn EmptyState(code: &'static str, title: &'static str, detail: &'static str) -> Element {
    rsx! {
        section { class: "empty-state",
            span { class: "honesty-badge", "{code}" }
            h2 { "{title}" }
            p { "{detail}" }
        }
    }
}

#[component]
fn StateContractCard(
    code: &'static str,
    title: &'static str,
    detail: &'static str,
    action: &'static str,
    tone: &'static str,
) -> Element {
    rsx! {
        article {
            class: "state-contract-card {tone}",
            role: if tone == "error" { "alert" } else { "status" },
            aria_label: "{code}: {title}",
            header { span { class: "state-contract-dot" } strong { "{code}" } }
            h2 { "{title}" }
            p { "{detail}" }
            button { disabled: true, "{action}" }
        }
    }
}

#[component]
fn StateCoverageSurface() -> Element {
    rsx! {
        div { class: "surface-scroll business-surface state-coverage-surface",
            header { class: "surface-head",
                div { class: "surface-head-copy",
                    span { class: "surface-eyebrow", "UI STATE CONTRACT · VISUAL_FIXTURE" }
                    h1 { "产品状态覆盖" }
                    p { "状态只能来自 Application / Domain 投影；此页冻结视觉、语义与恢复动作，不提升任何业务证据等级。" }
                }
                span { class: "honesty-badge", "VISUAL_FIXTURE" }
            }
            section { class: "state-contract-grid", aria_label: "Hartevo UI 状态矩阵",
                for state in UI_STATE_CONTRACTS {
                    StateContractCard { code: state.code, title: state.title, detail: state.detail, action: state.action, tone: state.tone }
                }
            }
            section { class: "text-stress-contract", aria_label: "多语言与长文本覆盖",
                div { lang: "de", strong { "Deutsch · blockierter Zustand" } p { "Die Verbindung wurde widerrufen; externe Aktionen bleiben gesperrt, bis die Kontoberechtigung erneut geprüft wurde." } }
                div { lang: "ja", strong { "日本語 · 承認待ち" } p { "対象アカウント、金額、配信時刻を確認するまで、外部への書き込みは実行されません。" } }
                div { strong { "超长内容" } p { "北美与德国及日本多市场增长项目／产品目录／2026-Q3-运营证据／一个不会因为名称、路径或说明很长就遮挡审批与恢复操作的可换行测试。" } }
            }
        }
    }
}

#[component]
fn ProjectDispatcherSurface(
    project: DesktopProjectProjection,
    on_select_mission: EventHandler<MissionId>,
) -> Element {
    let running = project
        .missions
        .iter()
        .filter(|mission| mission.stage == MissionStage::Running)
        .count();
    let waiting = project
        .missions
        .iter()
        .filter(|mission| {
            matches!(
                mission.stage,
                MissionStage::WaitingUser | MissionStage::WaitingApproval
            )
        })
        .count();
    let scheduled = project
        .missions
        .iter()
        .filter(|mission| mission.stage == MissionStage::Scheduled)
        .count();
    let priority = project
        .missions
        .iter()
        .filter(|mission| mission.stage != MissionStage::Scheduled)
        .take(3)
        .cloned()
        .collect::<Vec<_>>();
    let waiting_missions = project
        .missions
        .iter()
        .filter(|mission| {
            matches!(
                mission.stage,
                MissionStage::WaitingUser | MissionStage::WaitingApproval
            )
        })
        .take(2)
        .cloned()
        .collect::<Vec<_>>();
    rsx! {
        article { class: "dispatcher-overview",
            header { class: "dispatcher-hero",
                img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                div {
                    h1 { "{project.name} · 总调度" }
                    p { "{project.description}" }
                }
                span { class: "projection-chip", "APPLICATION PROJECTION" }
            }
            section { class: "dispatcher-stats", aria_label: "项目任务摘要",
                div { strong { "{running}" } small { "进行中的任务" } }
                div { strong { "{waiting}" } small { "等待确认" } }
                div { strong { "{scheduled}" } small { "自动任务" } }
                div { strong { "{project.revision}" } small { "Project revision" } }
            }
            section { class: "dispatcher-priority",
                header { h2 { "现在优先处理" } span { "按状态与项目顺序投影" } }
                if priority.is_empty() {
                    div { class: "compact-empty", span { class: "honesty-badge", "EMPTY" } p { "当前没有非排期 Mission。" } }
                } else {
                    for mission in priority {
                        {
                            let mission_id = mission.mission_id.clone();
                            rsx! {
                                button { class: "dispatcher-mission-row", onclick: move |_| on_select_mission.call(mission_id.clone()),
                                    i { class: dispatcher_stage_dot(&mission.stage) }
                                    span { strong { "{mission.title}" } small { "{dispatcher_mission_detail(&mission)}" } }
                                    em { "{mission.completed_checkpoint_count}/{mission.checkpoint_count}" }
                                    b { "打开" }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "dispatcher-lower-grid",
                section { class: "dispatcher-waiting",
                    header { h2 { "等待你" } span { "只显示持久等待状态" } }
                    if waiting_missions.is_empty() {
                        div { class: "compact-empty", span { class: "honesty-badge", "EMPTY" } p { "没有等待用户或审批的 Mission。" } }
                    } else {
                        for mission in waiting_missions {
                            {
                                let mission_id = mission.mission_id.clone();
                                rsx! {
                                    button { class: "dispatcher-waiting-row", onclick: move |_| on_select_mission.call(mission_id.clone()),
                                        i { class: dispatcher_stage_dot(&mission.stage) }
                                        span { strong { "{mission.title}" } small { "{mission_stage_label(&mission.stage)}" } }
                                        em { "处理" }
                                    }
                                }
                            }
                        }
                    }
                }
                section { class: "dispatcher-update",
                    header {
                        img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                        span { strong { "Hartevo · 刚刚" } small { "调度更新" } }
                    }
                    p { "任务、工作面变化与审批会汇总到同一 Project/Mission Truth；这里不会从页面样例推导 Provider 成功。" }
                    ul {
                        li { "{running} 个 Mission 正在运行" }
                        li { "{waiting} 个 Mission 等待你的明确输入" }
                        li { "{scheduled} 个周期任务保持排期；Provider readback 未接入时不声称已执行" }
                    }
                }
            }
        }
    }
}

#[component]
fn OrchestratorSurface(
    backend: DesktopBackendState,
    project: Option<DesktopProjectProjection>,
    mission: Option<MissionProjection>,
    runtime_activity: Option<MissionRuntimeProjection>,
    runtime_text_stream: Option<DesktopRuntimeTextStreamProjection>,
    runtime_text_error: Option<UiFailure>,
    runtime_busy: bool,
    runtime_stream_is_fixture: bool,
    runtime_follow_latest: bool,
    runtime_has_unseen: bool,
    context_access: Option<ProjectContextAccessProjection>,
    on_initialize: EventHandler<MouseEvent>,
    on_ready: EventHandler<DesktopSnapshot>,
    on_error: EventHandler<DesktopDataError>,
    on_select_mission: EventHandler<MissionId>,
    on_open_workpad: EventHandler<()>,
    on_runtime_scroll: EventHandler<bool>,
    on_follow_latest: EventHandler<()>,
) -> Element {
    match backend {
        DesktopBackendState::Uninitialized(evidence) => rsx! {
            div { class: "surface-scroll",
                article { class: "assistant-turn onboarding-card",
                    span { class: "honesty-badge", "LOCAL-FIRST" }
                    h2 { "初始化本地加密数据层" }
                    p { "此动作只创建 SQLCipher 数据库与 OS Vault 密钥，不创建云项目、不连接 Provider，也不执行外部动作。首次启动不会暗中写入钥匙串。" }
                    div { class: "evidence-summary",
                        span { strong { "{evidence.missions.len()}" } small { "Mission 合同" } }
                        span { strong { "E1" } small { "当前证据" } }
                        span { strong { "false" } small { "Release passed" } }
                    }
                    button { class: "primary-button", onclick: move |event| on_initialize.call(event), "显式初始化" }
                }
            }
        },
        DesktopBackendState::Failed(failure) => rsx! {
            div { class: "surface-scroll",
                IntegrityBanner { failure }
                EmptyState { code: "FAIL_CLOSED", title: "Desktop 数据层已停止", detail: "修复本机环境或使用恢复流程后，再点击左上角重新读取。当前未执行任何 Provider 动作。" }
            }
        },
        DesktopBackendState::Ready(_) => {
            let Some(project) = project else {
                return rsx! {
                    div { class: "surface-scroll",
                        PersonalProjectOnboarding { on_ready, on_error }
                    }
                };
            };
            if project.encryption == ProjectEncryptionReadiness::NotProvisioned {
                let project_id = project.project_id.clone();
                return rsx! {
                    div { class: "surface-scroll",
                        article { class: "assistant-turn onboarding-card",
                            span { class: "honesty-badge", "RECOVERY_REQUIRED" }
                            h2 { "继续未完成的个人项目加密" }
                            p { "项目 {project.name} 已持久化，但 Keyring 尚未建立。请使用你此前离线保存的 Recovery Kit 完成本次配置；密钥只在本机内存中短暂使用，不会写入 SQLCipher、日志或 OS Vault。" }
                            RecoveryCompletionCard { project_id, on_ready, on_error }
                        }
                    }
                };
            }
            let context_is_open = context_access.as_ref().is_some_and(|access| {
                matches!(
                    access.status,
                    ProjectContextAccessStatus::Ready { .. }
                        | ProjectContextAccessStatus::Degraded { .. }
                )
            });
            if !context_is_open {
                let can_recover_device = matches!(
                    context_access.as_ref().map(|access| &access.status),
                    Some(ProjectContextAccessStatus::RecoveryRequired)
                ) && matches!(
                    &project.encryption,
                    ProjectEncryptionReadiness::Ready {
                        mode: ProjectEncryptionMode::PersonalE2ee,
                        ..
                    }
                );
                let project_id = project.project_id.clone();
                return rsx! {
                    div { class: "surface-scroll",
                        article { class: "assistant-turn onboarding-card",
                            span { class: "honesty-badge", "CONTEXT_LOCKED" }
                            h2 { "本机尚不能打开项目内容" }
                            p { "Project 与 Mission 元数据仍可从 SQLCipher 读取，但本机必须先用 exact Device envelope 打开 encrypted Context CAS，才允许创建新 Mission、运行 Agent 或展示工作产物。" }
                            ContextAccessCard { access: context_access }
                            if can_recover_device {
                                DeviceRecoveryCard { project_id, on_ready, on_error }
                            }
                        }
                    }
                };
            }
            let Some(mission) = mission else {
                return rsx! {
                    div { class: "surface-scroll",
                        ProjectDispatcherSurface { project, on_select_mission }
                    }
                };
            };
            #[cfg(feature = "visual-fixtures")]
            if let Some(presentation) = visual_fixture::presentation()
                && active_visual_surface_variant().as_deref() != Some("mission-persisted-stream")
            {
                return rsx! {
                    PrototypeMissionJourney {
                        mission,
                        conversation: presentation.conversation,
                        approval: presentation.approval,
                        outcome: presentation.outcome,
                        on_open_workpad,
                    }
                };
            }
            let route_label = mission.manifest_id.as_ref().map_or_else(
                || "LEGACY_BOOTSTRAP · 未绑定 Catalog".to_owned(),
                |manifest_id| {
                    format!(
                        "{manifest_id} v{} · {}",
                        mission.manifest_version.unwrap_or_default(),
                        mission
                            .catalog_digest
                            .as_deref()
                            .map_or("missing digest", short_digest)
                    )
                },
            );
            let checkpoint_label = mission.current_checkpoint_id.as_ref().map_or_else(
                || "NOT_IMPLEMENTED".to_owned(),
                |checkpoint_id| {
                    let execution_route = mission
                        .current_checkpoint_capability_id
                        .as_ref()
                        .zip(mission.current_checkpoint_executor)
                        .map_or_else(
                            || "ROUTE_UNBOUND".to_owned(),
                            |(capability, executor)| {
                                let application_status = match (
                                    executor,
                                    mission.current_checkpoint_application_handler_status,
                                    mission.current_checkpoint_application_handler_id.as_deref(),
                                ) {
                                    (
                                        MissionCheckpointExecutor::Application,
                                        Some(ApplicationCheckpointHandlerStatus::Implemented),
                                        Some(handler_id),
                                    ) => format!(" · handler {handler_id}"),
                                    (
                                        MissionCheckpointExecutor::Application,
                                        Some(ApplicationCheckpointHandlerStatus::NotImplemented),
                                        _,
                                    ) => " · NOT_IMPLEMENTED".to_owned(),
                                    (
                                        MissionCheckpointExecutor::Application,
                                        Some(
                                            ApplicationCheckpointHandlerStatus::CatalogRevisionMismatch,
                                        ),
                                        _,
                                    ) => " · BLOCKED_CATALOG_REVISION".to_owned(),
                                    _ => String::new(),
                                };
                                format!(
                                    "{capability} via {}{application_status}",
                                    mission_checkpoint_executor_label(executor)
                                )
                            },
                        );
                    format!(
                        "{checkpoint_id} · {} · {execution_route} · {}/{} completed",
                        mission
                            .current_checkpoint_status
                            .map_or("UNKNOWN", mission_checkpoint_status_label),
                        mission.completed_checkpoint_count,
                        mission.checkpoint_count
                    )
                },
            );
            let mission_evidence_label = if mission.manifest_id.is_some() {
                "E2 FOUNDATION · E3 NOT_IMPLEMENTED"
            } else {
                "LEGACY_BOOTSTRAP · 非 Catalog 完整性证据"
            };
            let replayed_message_sequence = runtime_text_stream.as_ref().and_then(|stream| {
                mission
                    .conversation_messages
                    .iter()
                    .rev()
                    .find(|message| {
                        runtime_stream_matches_message(
                            stream,
                            message.role,
                            message.kind,
                            &message.body,
                        )
                    })
                    .map(|message| message.sequence)
            });
            let render_stream_turn =
                runtime_text_stream.is_some() && replayed_message_sequence.is_none();
            rsx! {
                div {
                    id: "persisted-mission-thread",
                    class: "surface-scroll persisted-mission-thread",
                    aria_label: "持久 Mission Conversation",
                    onmounted: move |_| scroll_mission_thread_to_latest(),
                    onscroll: move |event| {
                        let remaining = f64::from(
                            event.data.scroll_height() - event.data.client_height(),
                        ) - event.data.scroll_top();
                        on_runtime_scroll.call(remaining <= 96.0);
                    },
                    PersistedConversationMessages {
                        mission: mission.clone(),
                        runtime_text_stream: runtime_text_stream.clone(),
                        replayed_message_sequence,
                    }
                    if render_stream_turn {
                        if let Some(stream) = runtime_text_stream.clone() {
                            PersistedRuntimeStreamTurn {
                                stream,
                                runtime_busy,
                                visual_fixture: runtime_stream_is_fixture,
                            }
                        }
                    }
                    if let Some(failure) = runtime_text_error {
                        div { class: "runtime-stream-error", role: "status",
                            UiIcon { name: UiIconName::Shield, size: 14 }
                            span {
                                strong { "{failure.code}" }
                                small { "{failure.message}" }
                            }
                        }
                    }
                    PersistedMissionProcessDensity {
                        mission: mission.clone(),
                        visual_fixture: runtime_stream_is_fixture,
                        on_open_workpad,
                    }
                    details { class: "persisted-state-details",
                        summary {
                            UiIcon { name: UiIconName::Workflow, size: 14 }
                            span {
                                strong { "任务边界与持久状态" }
                                small { "{mission_stage_label(&mission.stage)} · revision {mission.revision} · {mission.completed_checkpoint_count}/{mission.checkpoint_count} Checkpoints" }
                            }
                            em { "按需展开" }
                            UiIcon { name: UiIconName::ChevronDown, size: 12 }
                        }
                        article { class: "assistant-turn persisted-state-turn",
                            header { class: "assistant-byline",
                                img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                                strong { "Hartevo" }
                                time { "任务边界" }
                            }
                            p { class: "assistant-lead", "下面的合同与运行状态来自同一个 Project/Mission Domain；页面不会生成 Receipt、Verification 或完成状态。" }
                            section { class: "mission-contract",
                                header { strong { "Operating Contract" } span { "revision {mission.revision}" } }
                                div { class: "contract-grid",
                                    div { small { "目标" } strong { "{mission.goal}" } }
                                    div { small { "Domain stage" } strong { "{mission_stage_label(&mission.stage)}" } }
                                    div { small { "Catalog route" } strong { "{route_label}" } }
                                    div { small { "Current Checkpoint" } strong { "{checkpoint_label}" } }
                                    div { small { "产品证据" } strong { "{mission_evidence_label}" } }
                                }
                            }
                            MissionStateCard { mission, runtime_activity }
                            ContextAccessCard { access: context_access }
                        }
                    }
                    if !runtime_follow_latest {
                        button {
                            class: if runtime_has_unseen { "mission-follow-latest has-unseen" } else { "mission-follow-latest" },
                            aria_label: if runtime_has_unseen { "有新的 Runtime 正文，回到最新" } else { "回到 Mission Conversation 最新位置" },
                            onclick: move |_| on_follow_latest.call(()),
                            if runtime_has_unseen { span { "有新内容" } }
                            UiIcon { name: UiIconName::ArrowUp, size: 12 }
                            "回到最新"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn PersistedConversationMessages(
    mission: MissionProjection,
    runtime_text_stream: Option<DesktopRuntimeTextStreamProjection>,
    replayed_message_sequence: Option<u64>,
) -> Element {
    if mission.conversation_messages.is_empty() {
        return rsx! {
            article { class: "assistant-turn persisted-assistant-turn conversation-empty",
                header { class: "assistant-byline",
                    img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                    strong { "Hartevo" }
                    time { "Mission 已持久化" }
                }
                div { class: "assistant-copy",
                    p { "当前 Mission 还没有可展示的 Conversation 正文。你可以从下方输入目标或纠正；未开始的 Runtime 不会被绘制成答案。" }
                }
            }
        };
    }
    rsx! {
        for message in mission.conversation_messages.clone() {
            {
                let recorded_time = message.recorded_at.format("%H:%M").to_string();
                let replayed = replayed_message_sequence == Some(message.sequence);
                let message_key = message.message_id.to_string();
                if message.role == MissionConversationRole::User {
                    rsx! {
                        div { key: "{message_key}", class: "persisted-user-row",
                            article { class: "persisted-user-message",
                                for (index, paragraph) in runtime_stream_paragraphs(&message.body).into_iter().enumerate() {
                                    p { key: "{message_key}-p-{index}", "{paragraph}" }
                                }
                                footer {
                                    span { "{mission_conversation_role_label(message.role)} · {mission_conversation_kind_label(message.kind)}" }
                                    time { "{recorded_time}" }
                                }
                            }
                        }
                    }
                } else if message.role == MissionConversationRole::Assistant {
                    rsx! {
                        article { key: "{message_key}", class: "assistant-turn persisted-assistant-turn",
                            header { class: "assistant-byline",
                                img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                                strong { "Hartevo" }
                                time { "{recorded_time}" }
                            }
                            div { class: "assistant-copy persisted-assistant-copy",
                                for (index, paragraph) in runtime_stream_paragraphs(&message.body).into_iter().enumerate() {
                                    p { key: "{message_key}-p-{index}", "{paragraph}" }
                                }
                            }
                            if replayed {
                                if let Some(stream) = runtime_text_stream.as_ref() {
                                    footer { class: "runtime-stream-receipt",
                                        UiIcon { name: UiIconName::FileCheck, size: 12 }
                                        span { "从 SQLCipher 重放 {stream.delta_count} 个正文增量" }
                                        em { "cursor {stream.last_evidence_sequence.unwrap_or_default()}" }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    rsx! {
                        div { key: "{message_key}", class: "persisted-system-notice", role: "status",
                            UiIcon { name: UiIconName::Shield, size: 13 }
                            span {
                                strong { "系统边界 · {recorded_time}" }
                                small { "{message.body}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn PersistedRuntimeStreamTurn(
    stream: DesktopRuntimeTextStreamProjection,
    runtime_busy: bool,
    visual_fixture: bool,
) -> Element {
    let stream_active = stream.turn_status.is_active();
    let last_item_index = stream.items.len().saturating_sub(1);
    rsx! {
        article { class: if stream_active { "assistant-turn persisted-assistant-turn runtime-stream-turn is-streaming" } else { "assistant-turn persisted-assistant-turn runtime-stream-turn" },
            header { class: "assistant-byline",
                img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                strong { "Hartevo" }
                time {
                    if stream_active || runtime_busy { "正在响应" } else { "已从本机恢复" }
                }
            }
            div {
                class: "assistant-copy runtime-stream-copy",
                aria_live: "polite",
                aria_atomic: "false",
                aria_busy: stream_active || runtime_busy,
                if stream.items.is_empty() && (stream_active || runtime_busy) {
                    p { class: "runtime-stream-waiting",
                        "正在等待首个持久正文增量"
                        i { class: "runtime-stream-caret", aria_hidden: "true" }
                    }
                }
                for (item_index, item) in stream.items.clone().into_iter().enumerate() {
                    {
                        let item_key = item.item_id_digest.clone();
                        let paragraphs = runtime_stream_paragraphs(&item.text);
                        let last_paragraph_index = paragraphs.len().saturating_sub(1);
                        rsx! {
                            section { key: "{item_key}", class: "runtime-stream-item",
                                for (paragraph_index, paragraph) in paragraphs.into_iter().enumerate() {
                                    p { key: "{item_key}-p-{paragraph_index}",
                                        "{paragraph}"
                                        if stream_active && item_index == last_item_index && paragraph_index == last_paragraph_index {
                                            i { class: "runtime-stream-caret", aria_hidden: "true" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            footer { class: "runtime-stream-receipt",
                UiIcon { name: UiIconName::FileCheck, size: 12 }
                span {
                    if visual_fixture {
                        "VISUAL_FIXTURE · 模拟 {stream.delta_count} 个正文增量；未读取 SQLCipher"
                    } else if stream_active {
                        "已持久化 {stream.delta_count} 个正文增量"
                    } else {
                        "从 SQLCipher 重放 {stream.delta_count} 个正文增量"
                    }
                }
                em { "{runtime_turn_status_label(stream.turn_status)} · cursor {stream.last_evidence_sequence.unwrap_or_default()}" }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MissionNextBoundaryKind {
    ApplicationNotImplemented,
    CatalogRevisionMismatch,
    WaitingApproval,
    WaitingUser,
    Blocked,
    Verifying,
    Scheduled,
    CycleReviewed,
    Completed,
    Partial,
    ExpectedRefusal,
    Failed,
    Cancelled,
    Running,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MissionNextBoundaryCopy {
    code: &'static str,
    title: &'static str,
    detail: &'static str,
    tone: &'static str,
}

fn mission_next_boundary_kind(
    stage: &MissionStage,
    checkpoint_status: Option<MissionCheckpointStatus>,
    application_handler_status: Option<ApplicationCheckpointHandlerStatus>,
) -> MissionNextBoundaryKind {
    // MissionStage is the persisted aggregate authority. A pending Effect count is
    // deliberately absent from this input: another Effect cannot rewrite the
    // current Mission or Checkpoint boundary in the UI.
    match stage {
        MissionStage::WaitingApproval => return MissionNextBoundaryKind::WaitingApproval,
        MissionStage::WaitingUser => return MissionNextBoundaryKind::WaitingUser,
        MissionStage::Blocked => return MissionNextBoundaryKind::Blocked,
        MissionStage::Verifying => return MissionNextBoundaryKind::Verifying,
        MissionStage::Scheduled => return MissionNextBoundaryKind::Scheduled,
        MissionStage::CycleReviewed => return MissionNextBoundaryKind::CycleReviewed,
        MissionStage::Completed => return MissionNextBoundaryKind::Completed,
        MissionStage::Partial => return MissionNextBoundaryKind::Partial,
        MissionStage::ExpectedRefusal => return MissionNextBoundaryKind::ExpectedRefusal,
        MissionStage::Failed => return MissionNextBoundaryKind::Failed,
        MissionStage::Cancelled => return MissionNextBoundaryKind::Cancelled,
        MissionStage::Draft | MissionStage::Ready | MissionStage::Running => {}
    }
    match checkpoint_status {
        Some(MissionCheckpointStatus::WaitingApproval) => {
            return MissionNextBoundaryKind::WaitingApproval;
        }
        Some(MissionCheckpointStatus::WaitingUser) => {
            return MissionNextBoundaryKind::WaitingUser;
        }
        Some(MissionCheckpointStatus::Blocked) => return MissionNextBoundaryKind::Blocked,
        Some(MissionCheckpointStatus::Verifying) => return MissionNextBoundaryKind::Verifying,
        Some(
            MissionCheckpointStatus::Pending
            | MissionCheckpointStatus::Ready
            | MissionCheckpointStatus::Running
            | MissionCheckpointStatus::Completed
            | MissionCheckpointStatus::Skipped,
        )
        | None => {}
    }
    if application_handler_status
        == Some(ApplicationCheckpointHandlerStatus::CatalogRevisionMismatch)
    {
        return MissionNextBoundaryKind::CatalogRevisionMismatch;
    }
    if application_handler_status == Some(ApplicationCheckpointHandlerStatus::NotImplemented) {
        return MissionNextBoundaryKind::ApplicationNotImplemented;
    }
    if *stage == MissionStage::Running
        || checkpoint_status == Some(MissionCheckpointStatus::Running)
    {
        return MissionNextBoundaryKind::Running;
    }
    MissionNextBoundaryKind::Ready
}

const fn mission_next_boundary_copy(kind: MissionNextBoundaryKind) -> MissionNextBoundaryCopy {
    match kind {
        MissionNextBoundaryKind::ApplicationNotImplemented => MissionNextBoundaryCopy {
            code: "NOT_IMPLEMENTED",
            title: "当前 Application 路由尚未实现",
            detail: "Capability 与边界可见，但不会用 Runtime、页面按钮或模拟结果代替缺失 handler。",
            tone: "blocked",
        },
        MissionNextBoundaryKind::CatalogRevisionMismatch => MissionNextBoundaryCopy {
            code: "BLOCKED_CATALOG_REVISION",
            title: "当前 Mission 与 Catalog 版本不一致",
            detail: "必须显式迁移或重建合同；新二进制不会把能力静默授予旧 Mission。",
            tone: "blocked",
        },
        MissionNextBoundaryKind::WaitingApproval => MissionNextBoundaryCopy {
            code: "WAITING_APPROVAL",
            title: "等待精确审批",
            detail: "只有完整 Effect digest 的 ApprovalGrant 才能继续；页面不会替代审批或执行外部动作。",
            tone: "attention",
        },
        MissionNextBoundaryKind::WaitingUser => MissionNextBoundaryCopy {
            code: "WAITING_USER",
            title: "等待你的判断或纠正",
            detail: "可以在下方直接回复；纠正只使依赖分支失效，不会清空无关工作产物。",
            tone: "attention",
        },
        MissionNextBoundaryKind::Blocked => MissionNextBoundaryCopy {
            code: "BLOCKED",
            title: "当前 Checkpoint 已阻塞",
            detail: "阻塞状态来自 Mission Domain；恢复前不会跳过 Oracle、扩大能力或声明完成。",
            tone: "blocked",
        },
        MissionNextBoundaryKind::Verifying => MissionNextBoundaryCopy {
            code: "VERIFYING",
            title: "正在等待独立核验",
            detail: "Provider 接受不等于业务真实发生；只有持久 Verification 能推进当前 Mission。",
            tone: "active",
        },
        MissionNextBoundaryKind::Scheduled => MissionNextBoundaryCopy {
            code: "SCHEDULED",
            title: "等待 durable Scheduler 触发",
            detail: "页面不能绕过到期时间、事件条件或 lease worker 直接启动下一周期。",
            tone: "active",
        },
        MissionNextBoundaryKind::CycleReviewed => MissionNextBoundaryCopy {
            code: "CYCLE_REVIEWED",
            title: "当前周期已完成复盘",
            detail: "下一周期或新合同仍须由持久调度与用户决策推进；页面不会自动开始循环。",
            tone: "settled",
        },
        MissionNextBoundaryKind::Completed => MissionNextBoundaryCopy {
            code: "COMPLETED",
            title: "Mission 已进入合法完成终态",
            detail: "这是持久 Domain 状态；页面不会据此补造 Provider Receipt、Verification 或业务 Outcome。",
            tone: "settled",
        },
        MissionNextBoundaryKind::Partial => MissionNextBoundaryCopy {
            code: "PARTIAL",
            title: "Mission 仅部分完成",
            detail: "已完成部分与未满足条件必须分别保留；页面不会把 Partial 美化为完整交付。",
            tone: "attention",
        },
        MissionNextBoundaryKind::ExpectedRefusal => MissionNextBoundaryCopy {
            code: "EXPECTED_REFUSAL",
            title: "Mission 已按边界正确拒绝",
            detail: "该终态只证明拒绝符合合同与安全边界，不代表执行过外部 Effect。",
            tone: "settled",
        },
        MissionNextBoundaryKind::Failed => MissionNextBoundaryCopy {
            code: "FAILED",
            title: "Mission 已失败",
            detail: "失败原因与恢复策略须来自持久证据；页面不会自动重试或伪装成 Outcome Review。",
            tone: "blocked",
        },
        MissionNextBoundaryKind::Cancelled => MissionNextBoundaryCopy {
            code: "CANCELLED",
            title: "Mission 已取消",
            detail: "取消后的 Runtime、Browser 与外部 Effect 不得继续；恢复需要新的合法状态转换。",
            tone: "neutral",
        },
        MissionNextBoundaryKind::Running => MissionNextBoundaryCopy {
            code: "RUNNING",
            title: "继续当前 Checkpoint",
            detail: "执行权仍受当前 Capability、Executor、Oracle 与完成策略约束；Mission 不会由模型自完成。",
            tone: "active",
        },
        MissionNextBoundaryKind::Ready => MissionNextBoundaryCopy {
            code: "READY",
            title: "等待当前合同的下一次合法转换",
            detail: "页面只投影已持久状态；未派发的执行、产物与外部动作不会被提前绘制。",
            tone: "neutral",
        },
    }
}

fn mission_checkpoint_completion_policy_label(
    policy: MissionCheckpointCompletionPolicy,
) -> &'static str {
    match policy {
        MissionCheckpointCompletionPolicy::DeterministicEvidence => "DETERMINISTIC_EVIDENCE",
        MissionCheckpointCompletionPolicy::WorkProduct => "WORK_PRODUCT",
        MissionCheckpointCompletionPolicy::VerifiedEffect => "VERIFIED_EFFECT",
        MissionCheckpointCompletionPolicy::EffectReadbackV2 => "EFFECT_READBACK_V2",
        MissionCheckpointCompletionPolicy::HumanConfirmation => "HUMAN_CONFIRMATION",
    }
}

fn application_checkpoint_handler_status_label(
    status: ApplicationCheckpointHandlerStatus,
) -> &'static str {
    match status {
        ApplicationCheckpointHandlerStatus::Implemented => "IMPLEMENTED",
        ApplicationCheckpointHandlerStatus::NotImplemented => "NOT_IMPLEMENTED",
        ApplicationCheckpointHandlerStatus::CatalogRevisionMismatch => "BLOCKED_CATALOG_REVISION",
    }
}

fn mission_checkpoint_process_tone(status: Option<MissionCheckpointStatus>) -> &'static str {
    match status {
        Some(MissionCheckpointStatus::Completed | MissionCheckpointStatus::Skipped) => "done",
        Some(MissionCheckpointStatus::Running | MissionCheckpointStatus::Verifying) => "active",
        Some(MissionCheckpointStatus::WaitingUser | MissionCheckpointStatus::WaitingApproval) => {
            "attention"
        }
        Some(MissionCheckpointStatus::Blocked) => "blocked",
        Some(MissionCheckpointStatus::Pending | MissionCheckpointStatus::Ready) | None => "neutral",
    }
}

fn mission_undisclosed_checkpoint_count(
    checkpoint_count: usize,
    completed_checkpoint_count: usize,
    has_current_checkpoint: bool,
    current_checkpoint_status: Option<MissionCheckpointStatus>,
) -> usize {
    let completed_count = completed_checkpoint_count.min(checkpoint_count);
    // Application's completed_checkpoint_count contains only Completed. A known
    // Skipped (or otherwise non-completed) current checkpoint therefore still
    // occupies one disclosed slot and must not be counted again as undisclosed.
    let current_is_not_in_completed_count = has_current_checkpoint
        && current_checkpoint_status != Some(MissionCheckpointStatus::Completed);
    checkpoint_count
        .saturating_sub(completed_count + usize::from(current_is_not_in_completed_count))
}

#[component]
fn PersistedMissionProcessDensity(
    mission: MissionProjection,
    visual_fixture: bool,
    on_open_workpad: EventHandler<()>,
) -> Element {
    let completed_count = mission
        .completed_checkpoint_count
        .min(mission.checkpoint_count);
    let undisclosed_checkpoint_count = mission_undisclosed_checkpoint_count(
        mission.checkpoint_count,
        mission.completed_checkpoint_count,
        mission.current_checkpoint_id.is_some(),
        mission.current_checkpoint_status,
    );
    let checkpoint_id = mission
        .current_checkpoint_id
        .as_deref()
        .unwrap_or("NO_CURRENT_CHECKPOINT");
    let checkpoint_status = mission
        .current_checkpoint_status
        .map_or("UNKNOWN", mission_checkpoint_status_label);
    let capability_id = mission
        .current_checkpoint_capability_id
        .as_deref()
        .unwrap_or("ROUTE_UNBOUND");
    let executor = mission
        .current_checkpoint_executor
        .map_or("UNBOUND", mission_checkpoint_executor_label);
    let completion_policy = mission
        .current_checkpoint_completion_policy
        .map_or("UNBOUND", mission_checkpoint_completion_policy_label);
    let oracle_label = if mission.current_checkpoint_oracle_ids.is_empty() {
        "ORACLE_UNBOUND".to_owned()
    } else {
        mission
            .current_checkpoint_oracle_ids
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(" · ")
    };
    let handler_label = if mission.current_checkpoint_executor
        == Some(MissionCheckpointExecutor::Application)
    {
        match (
            mission.current_checkpoint_application_handler_status,
            mission.current_checkpoint_application_handler_id.as_deref(),
        ) {
            (Some(status), Some(handler_id)) => format!(
                "{} · {handler_id}",
                application_checkpoint_handler_status_label(status)
            ),
            (Some(status), None) => application_checkpoint_handler_status_label(status).to_owned(),
            (None, _) => "HANDLER_STATUS_UNBOUND".to_owned(),
        }
    } else {
        "不适用当前 Executor".to_owned()
    };
    let boundary_kind = mission_next_boundary_kind(
        &mission.stage,
        mission.current_checkpoint_status,
        if mission.current_checkpoint_executor == Some(MissionCheckpointExecutor::Application) {
            mission.current_checkpoint_application_handler_status
        } else {
            None
        },
    );
    let boundary = mission_next_boundary_copy(boundary_kind);
    let current_tone = mission_checkpoint_process_tone(mission.current_checkpoint_status);
    let current_checkpoint_revision = mission.current_checkpoint_revision.unwrap_or_default();
    let mission_route = mission.manifest_id.as_deref().unwrap_or("LEGACY_BOOTSTRAP");
    let product_count = mission.work_products.len();
    let capability_count = usize::from(mission.current_checkpoint_capability_id.is_some());
    let completed_row_tone = if completed_count > 0 {
        "done"
    } else {
        "neutral"
    };
    let completed_title = if completed_count > 0 {
        format!("已完成 {completed_count} 个 Checkpoint")
    } else {
        "尚无完成的 Checkpoint".to_owned()
    };
    let projection_origin = if visual_fixture {
        "VISUAL_FIXTURE · 未读取 SQLCipher"
    } else {
        "Project-local Application projection"
    };

    rsx! {
        section { class: "persisted-process-density", aria_label: "Mission 过程与工作产物",
            header { class: "persisted-process-head",
                span {
                    strong { "Mission 过程与工作产物" }
                    small { "{mission_route} · Mission revision {mission.revision} · {projection_origin}" }
                }
                em { "{completed_count}/{mission.checkpoint_count} Checkpoints" }
            }
            div { class: "persisted-work-progress", aria_label: "Checkpoint 过程",
                div { class: "persisted-process-row {completed_row_tone}",
                    i {
                        if completed_count > 0 {
                            UiIcon { name: UiIconName::Check, size: 10 }
                        } else {
                            UiIcon { name: UiIconName::List, size: 10 }
                        }
                    }
                    span {
                        strong { "{completed_title}" }
                        small { "来自持久 Mission aggregate；不等于整个 Mission 已完成。" }
                        em { "DOMAIN · revision {mission.revision}" }
                    }
                    time { "{completed_count}/{mission.checkpoint_count}" }
                }
                div {
                    class: "persisted-process-row current {current_tone}",
                    aria_current: if mission.current_checkpoint_id.is_some() { "step" } else { "false" },
                    i {
                        if current_tone == "done" {
                            UiIcon { name: UiIconName::Check, size: 10 }
                        } else if current_tone == "blocked" || current_tone == "attention" {
                            UiIcon { name: UiIconName::Shield, size: 10 }
                        } else {
                            span {}
                        }
                    }
                    span {
                        strong { "{checkpoint_id}" }
                        small { "{checkpoint_status} · {capability_id}" }
                        em { "{executor} · checkpoint revision {current_checkpoint_revision}" }
                    }
                    time { "当前" }
                }
                if undisclosed_checkpoint_count > 0 {
                    div { class: "persisted-process-row neutral",
                        i { UiIcon { name: UiIconName::List, size: 10 } }
                        span {
                            strong { "另有 {undisclosed_checkpoint_count} 个 Checkpoint 尚未展开" }
                            small { "当前 Projection 只公开数量；不会编造名称、顺序或执行记录。" }
                            em { "MISSION DAG · COUNT ONLY" }
                        }
                        time { "待后续" }
                    }
                }
            }
            details { class: "persisted-capability-stack",
                summary {
                    UiIcon { name: UiIconName::Blocks, size: 14 }
                    span {
                        strong { "当前能力与完成条件" }
                        small { "{capability_count} Capability · {mission.current_checkpoint_oracle_ids.len()} Oracle · {executor}" }
                    }
                    em { "{checkpoint_status}" }
                    UiIcon { name: UiIconName::ChevronDown, size: 12 }
                }
                div { class: "persisted-capability-grid",
                    span { strong { "Capability" } small { "{capability_id}" } }
                    span { strong { "Executor" } small { "{executor}" } }
                    span { strong { "Completion policy" } small { "{completion_policy}" } }
                    span { strong { "Business Oracle" } small { "{oracle_label}" } }
                    span { strong { "Application handler" } small { "{handler_label}" } }
                    span {
                        strong { "Effect evidence" }
                        small { "{mission.pending_approval_count} pending approval · {mission.verified_effect_count} verified effect" }
                    }
                }
            }
            if mission.work_products.is_empty() {
                div { class: "persisted-work-product-empty",
                    UiIcon { name: UiIconName::FileText, size: 14 }
                    span {
                        strong { "还没有持久 Work Product" }
                        small { "Projection count {mission.work_product_count}；页面不会补一份示例报告。" }
                    }
                    em { "EMPTY" }
                }
            } else {
                div { class: "persisted-artifact-list", aria_label: "持久工作产物 {product_count} 项",
                    for product in mission.work_products.clone() {
                        {
                            let product_id = product.work_product_id.to_string();
                            rsx! {
                                button {
                                    key: "{product_id}",
                                    class: "persisted-artifact-attachment",
                                    aria_label: "在任务工作台打开 {product.title}",
                                    onclick: move |_| on_open_workpad.call(()),
                                    i { UiIcon { name: UiIconName::FileText, size: 16 } }
                                    span {
                                        strong { "{product.title}" }
                                        small {
                                            "{product.work_product_type} · r{product.work_product_revision} · {product.evidence_count} evidence · {work_product_status_label(&product.adoption_status)}"
                                        }
                                    }
                                    em { "在工作台打开" }
                                }
                            }
                        }
                    }
                }
            }
            aside { class: "persisted-next-boundary {boundary.tone}", aria_label: "Mission 下一步边界",
                i { UiIcon { name: UiIconName::Shield, size: 14 } }
                span {
                    strong { "{boundary.title}" }
                    small { "{boundary.detail}" }
                }
                em { "{boundary.code}" }
            }
        }
    }
}

#[component]
fn PersonalProjectOnboarding(
    on_ready: EventHandler<DesktopSnapshot>,
    on_error: EventHandler<DesktopDataError>,
) -> Element {
    let mut project_name = use_signal(String::new);
    let mut initial_goal = use_signal(String::new);
    let mut recovery_kit = use_signal(|| None::<RecoveryKitDraft>);
    let mut recovery_saved = use_signal(|| false);
    let recovery_kit_view = recovery_kit.read();
    let kit_generated = recovery_kit_view.is_some();
    let can_create = kit_generated
        && recovery_saved()
        && !project_name.read().trim().is_empty()
        && !initial_goal.read().trim().is_empty();

    rsx! {
        article { class: "assistant-turn onboarding-card project-onboarding",
            span { class: "honesty-badge", "PERSONAL · LOCAL-FIRST" }
            h2 { "创建第一个个人项目" }
            p { "项目内容保存在本机 SQLCipher 与加密工作区中。Recovery Kit 由你离线保管；Hartevo 和 OS Vault 都不会保存它。项目、Keyring 与首个 Mission 只会在你确认保存后创建。" }
            div { class: "onboarding-form",
                label {
                    span { "项目名称" }
                    input {
                        value: "{project_name}",
                        autocomplete: "off",
                        placeholder: "例如：德国市场增长",
                        oninput: move |event| project_name.set(event.value()),
                    }
                }
                label {
                    span { "首个 Mission 目标" }
                    textarea {
                        value: "{initial_goal}",
                        placeholder: "写明目标、硬约束与停止条件；创建后只进入持久 Running 状态，不冒充已完成。",
                        oninput: move |event| initial_goal.set(event.value()),
                    }
                }
            }
            if !kit_generated {
                div { class: "recovery-boundary",
                    strong { "先生成一次性 Recovery Kit" }
                    small { "它不会被写入 Hartevo 数据库、日志、Release Evidence 或系统钥匙串。请准备离线保存。" }
                    button {
                        class: "primary-button",
                        onclick: move |_| match RecoveryKitDraft::generate() {
                            Ok(draft) => {
                                recovery_kit.set(Some(draft));
                                recovery_saved.set(false);
                            }
                            Err(error) => on_error.call(error),
                        },
                        "生成 Recovery Kit"
                    }
                }
            } else {
                div { class: "recovery-kit", role: "group", aria_label: "一次性 Recovery Kit" ,
                    header {
                        span {
                            strong { "只显示本次" }
                            small { "复制到离线密码库或打印保存；不要上传到云盘或聊天工具。" }
                        }
                        button {
                            class: "text-button",
                            onclick: move |_| {
                                recovery_kit.set(None);
                                recovery_saved.set(false);
                            },
                            "作废并重生成"
                        }
                    }
                    if let Some(kit) = recovery_kit_view.as_ref() {
                        code { class: "recovery-value", "{kit.expose_for_user_export()}" }
                    }
                    label { class: "recovery-confirmation",
                        input {
                            r#type: "checkbox",
                            checked: recovery_saved(),
                            onchange: move |event| recovery_saved.set(event.checked()),
                        }
                        span { "我已把完整 Recovery Kit 保存到安全的离线位置，并理解 Hartevo 无法替我找回它。" }
                    }
                    button {
                        class: "primary-button",
                        disabled: !can_create,
                        onclick: move |_| {
                            let result = {
                                let kit = recovery_kit.read();
                                let Some(kit) = kit.as_ref() else { return; };
                                DesktopDataPlane::discover().and_then(|plane| {
                                    plane.create_personal_project_os(
                                        project_name.read().as_str(),
                                        initial_goal.read().as_str(),
                                        kit.expose_for_user_export(),
                                        Utc::now(),
                                    )
                                })
                            };
                            match result {
                                Ok(snapshot) => {
                                    recovery_kit.set(None);
                                    recovery_saved.set(false);
                                    on_ready.call(snapshot);
                                }
                                Err(error) => on_error.call(error),
                            }
                        },
                        "已安全保存，创建加密项目"
                    }
                }
            }
            div { class: "boundary-note", "创建动作不会连接 Provider、上传项目正文或执行外部 Effect。首个 Mission 的 Runtime/Scheduler 尚未接线时会诚实显示 NOT_IMPLEMENTED。" }
        }
    }
}

#[component]
fn RecoveryCompletionCard(
    project_id: ProjectId,
    on_ready: EventHandler<DesktopSnapshot>,
    on_error: EventHandler<DesktopDataError>,
) -> Element {
    let mut recovery_input = use_signal(SensitiveRecoveryInput::default);
    let can_complete = recovery_input.read().has_valid_shape();
    rsx! {
        div { class: "recovery-boundary recovery-resume",
            label {
                span { "已保存的 64 位 Recovery Kit" }
                input {
                    r#type: "password",
                    value: "{recovery_input.read().expose_for_submission()}",
                    autocomplete: "off",
                    spellcheck: "false",
                    placeholder: "粘贴 Recovery Kit",
                    oninput: move |event| recovery_input.write().replace(event.value()),
                }
            }
            small { "输入只用于建立 Recovery envelope；提交成功后立即从组件状态清除。" }
            button {
                class: "primary-button",
                disabled: !can_complete,
                onclick: move |_| {
                    let result = {
                        let input = recovery_input.read();
                        DesktopDataPlane::discover().and_then(|plane| {
                            plane.complete_personal_encryption_os(
                                &project_id,
                                input.expose_for_submission(),
                                Utc::now(),
                            )
                        })
                    };
                    match result {
                        Ok(snapshot) => {
                            recovery_input.write().clear();
                            on_ready.call(snapshot);
                        }
                        Err(error) => on_error.call(error),
                    }
                },
                "完成个人项目加密"
            }
        }
    }
}

#[component]
fn DeviceRecoveryCard(
    project_id: ProjectId,
    on_ready: EventHandler<DesktopSnapshot>,
    on_error: EventHandler<DesktopDataError>,
) -> Element {
    let mut recovery_input = use_signal(SensitiveRecoveryInput::default);
    let can_recover = recovery_input.read().has_valid_shape();
    rsx! {
        div { class: "recovery-boundary recovery-resume",
            strong { "用用户自持 Recovery Kit 附加本机新 Device key" }
            label {
                span { "已保存的 64 位 Recovery Kit" }
                input {
                    r#type: "password",
                    value: "{recovery_input.read().expose_for_submission()}",
                    autocomplete: "off",
                    spellcheck: "false",
                    placeholder: "粘贴 Recovery Kit",
                    oninput: move |event| recovery_input.write().replace(event.value()),
                }
            }
            small { "Hartevo 会建立独立 successor Device envelope；不会覆盖缺失的旧 key，也不会把 Kit 写入 SQLCipher、OS Vault、日志或 Trace。只有 Context 重开成功后才恢复预览与 Mission 写入。" }
            button {
                class: "primary-button",
                disabled: !can_recover,
                onclick: move |_| {
                    let result = {
                        let input = recovery_input.read();
                        DesktopDataPlane::discover().and_then(|plane| {
                            plane.recover_personal_project_device_os(
                                &project_id,
                                input.expose_for_submission(),
                                Utc::now(),
                            )
                        })
                    };
                    match result {
                        Ok(snapshot) => {
                            recovery_input.write().clear();
                            on_ready.call(snapshot);
                        }
                        Err(error) => on_error.call(error),
                    }
                },
                "验证并恢复本机访问"
            }
        }
    }
}

#[component]
fn MissionStateCard(
    mission: MissionProjection,
    runtime_activity: Option<MissionRuntimeProjection>,
) -> Element {
    let outcome = mission
        .outcome_summary
        .as_deref()
        .unwrap_or("尚无 Outcome Review");
    let runtime_note = runtime_activity
        .as_ref()
        .map(|activity| runtime_activity_note(activity, mission.work_product_count));
    let recovery_label = runtime_activity
        .as_ref()
        .and_then(|activity| activity.recovery_status)
        .map_or("未启动", runtime_recovery_status_label);
    let process_claim_label = runtime_activity
        .as_ref()
        .and_then(|activity| activity.process_claim_status)
        .map_or("未认领", runtime_process_claim_status_label);
    let turn_label = runtime_activity
        .as_ref()
        .and_then(|activity| activity.turn_status)
        .map_or("未派发", runtime_turn_status_label);
    rsx! {
        section { class: "live-work",
            div { class: "live-row",
                span { class: "status-dot live" }
                span { strong { "{mission_stage_label(&mission.stage)}" } small { "Mission {mission.mission_id} · revision {mission.revision}" } }
                em { "DOMAIN" }
            }
            div { class: "evidence-summary",
                span { strong { "{mission.evidence_count}" } small { "Evidence" } }
                span { strong { "{mission.work_product_count}" } small { "Work Product" } }
                span { strong { "{mission.pending_approval_count}" } small { "Pending approval" } }
                span { strong { "{mission.verified_effect_count}" } small { "Verified Effect" } }
                span { strong { "{mission.cycle}" } small { "Mission cycle" } }
            }
            if let Some(schedule) = &mission.schedule {
                div { class: "evidence-summary runtime-summary", aria_label: "持久 Mission Scheduler 状态",
                    span { strong { "{mission_schedule_status_label(schedule.status)}" } small { "Schedule" } }
                    span { strong { "{cadence_trigger_label(schedule.trigger)}" } small { "Trigger" } }
                    span { strong { "{schedule.cycle}" } small { "Next cycle" } }
                    span { strong { if schedule.signal_received { "已收到" } else { "未收到" } } small { "Event signal" } }
                    span { strong { "{schedule.lease_generation}" } small { "Lease generation" } }
                    span { strong { "{schedule.failure_count}" } small { "Schedule failures" } }
                }
            }
            if let Some(activity) = &runtime_activity {
                RuntimeProjectionTimeline { activity: activity.clone() }
                div { class: "evidence-summary runtime-summary",
                    span { strong { "{process_claim_label}" } small { "OS process claim" } }
                    span { strong { "{recovery_label}" } small { "Runtime recovery" } }
                    span { strong { "{turn_label}" } small { "Runtime turn" } }
                    span { strong { "{activity.process_cleanup_attempt_count}" } small { "Process cleanup" } }
                    span { strong { "{activity.turn_evidence_count}" } small { "Turn evidence" } }
                    span { strong { "{activity.recovery_failure_count + activity.turn_failure_count}" } small { "Runtime failures" } }
                }
            }
            if mission.stage == MissionStage::Running && runtime_note.is_some() {
                div { class: "boundary-note", "{runtime_note.as_deref().unwrap_or_default()}" }
            } else if mission.stage == MissionStage::Running && mission.evidence_count == 0 {
                div { class: "boundary-note", "NOT_STARTED：Mission 已持久化，但尚无 Runtime Turn；没有研究结果、Provider Receipt 或业务完成声明。" }
            } else if mission.stage == MissionStage::WaitingApproval {
                div { class: "boundary-note", "审批数来自 Effect Ledger；Desktop 精确 digest 审批 UI 尚未接线，因此不会在此处制造批准。" }
            } else if mission.stage == MissionStage::Verifying {
                div { class: "boundary-note", "Domain 正处于 Verifying；只有持久 Verification 能推进，页面按钮不能直接完成 Mission。" }
            } else if mission.stage == MissionStage::Scheduled {
                if let Some(schedule) = &mission.schedule {
                    div { class: "boundary-note",
                        "SCHEDULED：cycle {schedule.cycle} · {cadence_trigger_label(schedule.trigger)} · {mission_schedule_status_label(schedule.status)}。"
                        if let Some(due_at) = schedule.due_at {
                            " 锚定时间 {due_at}."
                        }
                        if schedule.signal_received {
                            " 已持久接收首个合法事件；等待 lease worker 原子启动 Mission。"
                        } else {
                            " 未到期或尚未收到合法事件；页面不能绕过 Scheduler 直接启动。"
                        }
                    }
                } else {
                    div { class: "boundary-note", "INTEGRITY_ERROR：Mission 显示 Scheduled，但没有 durable Schedule；已禁止直接启动下一周期。" }
                }
            } else if mission.stage.is_terminal() || mission.stage == MissionStage::CycleReviewed {
                div { class: "boundary-note", "Outcome：{outcome}" }
            } else {
                div { class: "boundary-note", "当前状态仅由 Application projection 决定；未接入的下一步保持 NOT_IMPLEMENTED。" }
            }
        }
    }
}

#[component]
fn RuntimeProjectionTimeline(activity: MissionRuntimeProjection) -> Element {
    let process = activity
        .process_claim_status
        .map(runtime_process_claim_status_label);
    let recovery = activity.recovery_status.map(runtime_recovery_status_label);
    let turn = activity.turn_status.map(runtime_turn_status_label);
    let process_active = matches!(
        activity.process_claim_status,
        Some(RuntimeProcessClaimStatus::Prepared | RuntimeProcessClaimStatus::Spawned)
    );
    let recovery_active = matches!(
        activity.recovery_status,
        Some(
            RuntimeRecoveryStatus::Prepared
                | RuntimeRecoveryStatus::Spawned
                | RuntimeRecoveryStatus::ThreadBound
                | RuntimeRecoveryStatus::Attached
        )
    );
    let turn_active = activity
        .turn_status
        .is_some_and(RuntimeTurnStatus::is_active);
    rsx! {
        section {
            class: if activity.requires_reconciliation { "runtime-projection-timeline uncertain" } else { "runtime-projection-timeline" },
            aria_label: "持久 Runtime 活动",
            aria_live: "polite",
            header {
                span { strong { "Runtime 活动" } small { "来自持久 Application Projection" } }
                if activity.requires_reconciliation {
                    b { "UNCERTAIN · 禁止自动重放" }
                } else {
                    em { "{activity.turn_evidence_count} evidence" }
                }
            }
            div { class: "runtime-projection-events",
                if let Some(process) = process {
                    div { class: if process_active { "runtime-projection-event live" } else { "runtime-projection-event done" },
                        i { if process_active { span {} } else { UiIcon { name: UiIconName::Check, size: 10 } } }
                        span { strong { "OS process claim" } small { "{process} · 仅代表本机执行权，不是业务完成" } }
                    }
                }
                if let Some(recovery) = recovery {
                    div { class: if recovery_active { "runtime-projection-event live" } else { "runtime-projection-event done" },
                        i { if recovery_active { span {} } else { UiIcon { name: UiIconName::Check, size: 10 } } }
                        span { strong { "Runtime recovery" } small { "{recovery} · generation 与 thread binding 由账本 fencing" } }
                    }
                }
                if let Some(turn) = turn {
                    div { class: if turn_active { "runtime-projection-event live" } else if activity.requires_reconciliation { "runtime-projection-event uncertain" } else { "runtime-projection-event done" },
                        i {
                            if turn_active { span {} } else if activity.requires_reconciliation { "?" } else { UiIcon { name: UiIconName::Check, size: 10 } }
                        }
                        span { strong { "Runtime turn" } small { "{turn} · 模型终态不能直接完成 Mission" } }
                    }
                }
                div { class: "runtime-projection-event ledger",
                    i { UiIcon { name: UiIconName::FileCheck, size: 10 } }
                    span {
                        strong { "持久事件账本" }
                        small { "{activity.turn_evidence_count} turn evidence · {activity.process_cleanup_attempt_count} cleanup · {activity.recovery_failure_count + activity.turn_failure_count} failures" }
                    }
                }
            }
            details {
                summary { "查看安全边界" UiIcon { name: UiIconName::ChevronDown, size: 12 } }
                p { "当前列表只显示已经进入 SQLCipher/Application Projection 的状态；未持久化的 token、私有推理和正文不会作为遥测事件显示。停止/中断必须由精确 Runtime attempt 命令完成，页面不会只隐藏动画。" }
            }
        }
    }
}

#[component]
fn EncryptionReadinessCard(encryption: ProjectEncryptionReadiness) -> Element {
    let (code, title, detail) = match encryption {
        ProjectEncryptionReadiness::NotProvisioned => (
            "RECOVERY_REQUIRED",
            "项目加密尚未配置",
            "请使用此前离线保存的 Recovery Kit 完成配置；Desktop 不会静默生成替代 Keyring。",
        ),
        ProjectEncryptionReadiness::Ready {
            mode,
            active_key_version,
            keyring_revision,
        } => (
            "READY",
            encryption_mode_label(&mode),
            if active_key_version == keyring_revision {
                "Keyring 可用；可创建持久 Mission。"
            } else {
                "Keyring 可用；key version 与 revision 独立演进。"
            },
        ),
        ProjectEncryptionReadiness::RotationRequired { .. } => (
            "BLOCKED_ENV",
            "Keyring 必须轮换",
            "轮换完成前禁止创建新的 Desktop Mission 或 Runtime session。",
        ),
    };
    rsx! {
        section { class: "connection-readiness",
            span { class: "honesty-badge", "{code}" }
            span { strong { "{title}" } small { "{detail}" } }
        }
    }
}

#[component]
fn ContextAccessCard(access: Option<ProjectContextAccessProjection>) -> Element {
    let (code, title, detail) = match access.map(|projection| projection.status) {
        Some(ProjectContextAccessStatus::NotProvisioned) => (
            "RECOVERY_REQUIRED".to_owned(),
            "项目 Keyring 尚未配置".to_owned(),
            "使用个人项目 Recovery Kit 完成 Keyring 后才能打开 encrypted Context CAS。"
                .to_owned(),
        ),
        Some(ProjectContextAccessStatus::RotationRequired) => (
            "BLOCKED_ENV".to_owned(),
            "Keyring 必须轮换".to_owned(),
            "轮换完成前，本机不会解密项目内容或创建新的 Runtime 工作。".to_owned(),
        ),
        Some(ProjectContextAccessStatus::Ready {
            keyring_revision,
            active_key_version,
            readable_key_versions,
        }) => (
            "READY".to_owned(),
            "Encrypted Context 已由本机设备解锁".to_owned(),
            format!(
                "Keyring revision {keyring_revision} · active key v{active_key_version} · readable {readable_key_versions:?}"
            ),
        ),
        Some(ProjectContextAccessStatus::Degraded {
            keyring_revision,
            active_key_version,
            readable_key_versions,
            unavailable_historical_key_versions,
        }) => (
            "DEGRADED".to_owned(),
            "当前 Context 可用，部分历史版本不可读".to_owned(),
            format!(
                "Keyring revision {keyring_revision} · active v{active_key_version} · readable {readable_key_versions:?} · unavailable history {unavailable_historical_key_versions:?}"
            ),
        ),
        Some(ProjectContextAccessStatus::RecoveryRequired) => (
            "RECOVERY_REQUIRED".to_owned(),
            "本机设备没有可用的 Project key".to_owned(),
            "需要用用户自持 Recovery Kit 或已授权设备完成 Device Attachment；当前禁止新 Mission 与内容读取。".to_owned(),
        ),
        Some(ProjectContextAccessStatus::BlockedEnvironment) => (
            "BLOCKED_ENV".to_owned(),
            "项目工作区不可安全打开".to_owned(),
            "检查本机目录、权限与磁盘状态；Hartevo 未读取 Context 内容。".to_owned(),
        ),
        Some(ProjectContextAccessStatus::IntegrityError) | None => (
            "INTEGRITY_ERROR".to_owned(),
            "Context access projection 未通过完整性校验".to_owned(),
            "Keyring、SecretReference、设备 envelope 或 encrypted CAS 状态不一致；该项目执行已停止。".to_owned(),
        ),
    };
    rsx! {
        section { class: "connection-readiness context-access-card",
            span { class: "honesty-badge", "{code}" }
            span { strong { "{title}" } small { "{detail}" } }
        }
    }
}

#[component]
fn CurrentSurface(
    project: Option<DesktopProjectProjection>,
    context_access: Option<ProjectContextAccessProjection>,
) -> Element {
    let Some(project) = project else {
        return rsx! { EmptyState { code: "EMPTY", title: "没有当前项目", detail: "先从本机 Inventory 选择或安全创建项目；Current 不会显示跨项目样例数据。" } };
    };
    let mission_count = project.missions.len();
    let active_count = project
        .missions
        .iter()
        .filter(|mission| !mission.stage.is_terminal())
        .count();
    let work_product_count = project
        .missions
        .iter()
        .map(|mission| mission.work_product_count)
        .sum::<usize>();
    let attention_count = project
        .missions
        .iter()
        .map(|mission| mission.pending_approval_count)
        .sum::<usize>();
    rsx! {
        div { class: "surface-scroll business-surface current-surface",
            header { class: "surface-head",
                div { class: "surface-head-copy",
                    span { class: "surface-eyebrow", "CURRENT · PROJECT PROJECTION" }
                    h1 { "{project.name}" }
                    p { "{project.description}" }
                }
                div { class: "surface-head-actions",
                    span { class: "sync-chip", "Project revision {project.revision}" }
                }
            }
            section { class: "readiness-strip",
                div { class: "readiness-intro",
                    span { class: "readiness-mark", UiIcon { name: UiIconName::Folder, size: 18 } }
                    span { strong { "当前项目边界" } small { "所有数字来自同一 DesktopProjectProjection；Provider 状态未接入时保持未测量。" } }
                }
                div { class: "readiness-stat", b { "{mission_count}" } small { "持久 Mission" } }
                div { class: "readiness-stat", b { "{active_count}" } small { "非终态" } }
                div { class: "readiness-stat", b { "{attention_count}" } small { "待审批" } }
            }
            div { class: "current-grid",
                main {
                    section { class: "surface-section",
                        div { class: "surface-section-head", h2 { "这个项目正在做什么" } p { "Mission 不跨项目混用" } }
                        if project.missions.is_empty() {
                            div { class: "compact-empty", span { class: "honesty-badge", "EMPTY" } p { "尚无持久 Mission。" } }
                        } else {
                            div { class: "project-mission-list",
                                for mission in project.missions.clone() {
                                    article { class: "project-mission-row",
                                        i { class: if mission.stage.is_terminal() { "" } else { "live" } }
                                        span { strong { "{mission.title}" } small { "{mission_stage_label(&mission.stage)} · checkpoint {mission.completed_checkpoint_count}/{mission.checkpoint_count} · revision {mission.revision}" } }
                                        em { "{mission.work_product_count} 产物" }
                                    }
                                }
                            }
                        }
                    }
                    section { class: "surface-section",
                        div { class: "surface-section-head", h2 { "最近成果" } p { "Work Product manifest 投影" } }
                        div { class: "outcome-placeholder",
                            UiIcon { name: UiIconName::FileCheck, size: 18 }
                            span { strong { "{work_product_count} 个真实 Work Product" } small { "没有持久 manifest 时不会生成示例成果。" } }
                            em { if work_product_count == 0 { "EMPTY" } else { "DOMAIN" } }
                        }
                    }
                }
                aside {
                    section { class: "surface-section",
                        div { class: "surface-section-head", h2 { "项目边界" } p { "Project scoped" } }
                        div { class: "project-context-list",
                            div { class: "project-context-row", span { "存储模式" } strong { "{project_storage_label(&project)}" } }
                            div { class: "project-context-row", span { "Workspace roots" } strong { "{project.workspace_root_count}" } }
                            div { class: "project-context-row", span { "外部动作" } strong { "Effect Broker + 精确审批" } }
                            div { class: "project-context-row", span { "数据与记忆" } strong { "Tenant / Project 隔离" } }
                        }
                    }
                    ContextAccessCard { access: context_access }
                    section { class: "surface-section provider-honesty",
                        div { class: "surface-section-head", h2 { "连接与运行状态" } p { "未伪造 Probe" } }
                        div { class: "context-note",
                            header { UiIcon { name: UiIconName::Plug, size: 15 } strong { "Provider Projection 尚未接入" } }
                            p { "Current 不能从 Catalog 声明推导 Connected。实时 Probe 接线前，连接数量与健康度保持 Not Measured。" }
                            span { class: "honesty-badge", "NOT_IMPLEMENTED" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn MissionsSurface(
    project: Option<DesktopProjectProjection>,
    selected_mission_id: Option<MissionId>,
    on_select: EventHandler<MissionId>,
) -> Element {
    let Some(project) = project else {
        return rsx! { EmptyState { code: "EMPTY", title: "没有 Mission 项目范围", detail: "选择项目后，Missions 只显示该项目的持久 Application projection。" } };
    };
    rsx! {
        div { class: "surface-scroll business-surface missions-surface",
            header { class: "surface-head",
                div { class: "surface-head-copy",
                    span { class: "surface-eyebrow", "MISSIONS · APPLICATION PROJECTION" }
                    h1 { "全部任务" }
                    p { "一次选择会继续原来的 Mission Conversation，不创建第二套页面状态。" }
                }
                span { class: "sync-chip", "{project.name} · {project.missions.len()} Missions" }
            }
            nav { class: "surface-tabs", aria_label: "Mission 视图",
                button { class: "active", "全部" }
                button { disabled: true, "进行中" }
                button { disabled: true, "自动任务" }
                button { disabled: true, "历史" }
            }
            section { class: "surface-section mission-table-section",
                if project.missions.is_empty() {
                    div { class: "compact-empty", span { class: "honesty-badge", "EMPTY" } h2 { "尚无持久 Mission" } p { "返回总调度，选择 VM-00～VM-11 并完成 Operating Contract。" } }
                } else {
                    div { class: "mission-table", role: "list",
                        for mission in project.missions {
                            {
                                let mission_id = mission.mission_id.clone();
                                let selected = selected_mission_id.as_ref() == Some(&mission_id);
                                rsx! {
                                    button { class: if selected { "mission-table-row active" } else { "mission-table-row" }, onclick: move |_| on_select.call(mission_id.clone()),
                                        span { class: "mission-table-status", i { class: if mission.stage.is_terminal() { "" } else { "live" } } }
                                        span { class: "mission-table-copy", strong { "{mission.title}" } small { "{mission.goal}" } }
                                        span { strong { "{mission_stage_label(&mission.stage)}" } small { "状态" } }
                                        span { strong { "{mission.completed_checkpoint_count}/{mission.checkpoint_count}" } small { "Checkpoint" } }
                                        span { strong { "{mission.pending_approval_count}" } small { "待审批" } }
                                        span { class: "mission-table-action", "继续 →" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ChannelSurface(
    project: Option<DesktopProjectProjection>,
    mission: Option<MissionProjection>,
) -> Element {
    #[cfg(feature = "visual-fixtures")]
    if let Some(page) = visual_fixture::page("channels") {
        return rsx! {
            PrototypeOperationsSurface {
                page,
                title: "渠道运营",
                description: "根据受众、市场、内容能力与目标选择值得经营的渠道；每个平台保留独立素材、节奏、审批和结果。",
                eyebrow: "CHANNELS · GROWTH OPERATIONS",
            }
        };
    }
    let mut active_tab = use_signal(|| "plan");
    let Some(project) = project else {
        return rsx! { EmptyState { code: "NOT_IMPLEMENTED", title: "没有渠道上下文", detail: "先完成安全项目创建；渠道页不会使用 demo store。" } };
    };
    let Some(mission) = mission else {
        return rsx! { EmptyState { code: "EMPTY", title: "没有绑定 Mission", detail: "渠道工作面只投影已有 Mission，不创建独立业务状态。" } };
    };
    rsx! {
        div { class: "surface-scroll business-surface channels-surface",
            header { class: "surface-head",
                div { class: "surface-head-copy",
                    span { class: "surface-eyebrow", "CHANNELS · GROWTH OPERATIONS" }
                    h1 { "渠道运营" }
                    p { "根据受众、市场、内容能力与目标选择值得经营的渠道；每个平台有独立素材、节奏、审批与结果。" }
                }
                span { class: "sync-chip", "{project.name} · Mission revision {mission.revision}" }
            }
            nav { class: "surface-tabs", aria_label: "渠道运营视图",
                button { class: if active_tab() == "plan" { "active" } else { "" }, onclick: move |_| active_tab.set("plan"), "计划" }
                button { class: if active_tab() == "calendar" { "active" } else { "" }, onclick: move |_| active_tab.set("calendar"), "日历" }
                button { class: if active_tab() == "queue" { "active" } else { "" }, onclick: move |_| active_tab.set("queue"), "发布队列" }
                button { class: if active_tab() == "performance" { "active" } else { "" }, onclick: move |_| active_tab.set("performance"), "效果" }
            }
            section { class: "pipeline-strip channel-strip",
                div { class: "pipeline-stage", strong { "{mission.work_product_count}" } span { "真实工作产物" } }
                div { class: "pipeline-stage", strong { "{mission.pending_approval_count}" } span { "等待审批" } }
                div { class: "pipeline-stage", strong { "{mission.verified_effect_count}" } span { "已独立验证" } }
                div { class: "pipeline-stage", strong { "0" } span { "页面生成回执" } }
            }
            section { class: "surface-section channel-content",
                div { class: "surface-section-head",
                    h2 {
                        if active_tab() == "plan" { "渠道计划" }
                        else if active_tab() == "calendar" { "内容日历" }
                        else if active_tab() == "queue" { "发布队列" }
                        else { "互动、Referral 与 Outcome" }
                    }
                    p { "同一 Mission · 同一 Effect Ledger" }
                }
                if active_tab() == "plan" {
                    if mission.work_products.is_empty() {
                        div { class: "state-canvas compact", span { class: "honesty-badge", "EMPTY" } h3 { "尚无渠道 Work Product" } p { "页面不会从 Mission 标题生成演示计划；需要真实 WorkProductManifest。" } }
                    } else {
                        div { class: "channel-work-products",
                            for product in mission.work_products.clone() {
                                article { class: "channel-work-product",
                                    UiIcon { name: UiIconName::FileText, size: 16 }
                                    span { strong { "{product.title}" } small { "{product.work_product_type} · evidence {product.evidence_count}" } }
                                    em { "{work_product_status_label(&product.adoption_status)}" }
                                }
                            }
                        }
                    }
                } else if active_tab() == "calendar" {
                    div { class: "calendar-empty",
                        div { class: "calendar-title", UiIcon { name: UiIconName::Calendar, size: 15 } span { "本周" } }
                        div { class: "calendar-week",
                            for day in ["一", "二", "三", "四", "五", "六", "日"] { span { strong { "周{day}" } small { "—" } } }
                        }
                        div { class: "state-canvas compact", span { class: "honesty-badge", "EMPTY" } h3 { "没有持久排期" } p { "Schedule / timezone / payload digest 接线后才会显示日历项。" } }
                    }
                } else if active_tab() == "queue" {
                    if mission.pending_approval_count == 0 && mission.verified_effect_count == 0 {
                        div { class: "state-canvas compact", span { class: "honesty-badge", "EMPTY" } h3 { "没有持久 Effect" } p { "Provider 连接或页面草稿不会冒充发布队列。" } }
                    } else {
                        div { class: "policy-row", span { "等待审批" } strong { "{mission.pending_approval_count}" } em { "DOMAIN" } }
                        div { class: "policy-row", span { "已独立验证" } strong { "{mission.verified_effect_count}" } em { "DOMAIN" } }
                    }
                } else {
                    div { class: "state-canvas compact",
                        UiIcon { name: UiIconName::Chart, size: 22 }
                        span { class: "honesty-badge", "NOT_IMPLEMENTED" }
                        h3 { "尚无 Channel Outcome Projection" }
                        p { "发帖数不会冒充有效互动、Referral、Lead 或 Revenue；Outcome Event 与 Attribution 接线前保持未测量。" }
                    }
                }
            }
        }
    }
}

#[component]
fn RelationshipsSurface(
    project: Option<DesktopProjectProjection>,
    mission: Option<MissionProjection>,
) -> Element {
    #[cfg(feature = "visual-fixtures")]
    if let Some(page) = visual_fixture::page("relationships") {
        return rsx! {
            PrototypeOperationsSurface {
                page,
                title: "关系与 CRM",
                description: "联系人、公司、邮件、会话与机会共享同一条关系记录；公开发现不会自动获得触达许可。",
                eyebrow: "RELATIONSHIPS · CRM",
            }
        };
    }
    let mut active_tab = use_signal(|| "pipeline");
    let Some(project) = project else {
        return rsx! { EmptyState { code: "EMPTY", title: "没有关系项目范围", detail: "Identity、Consent、Conversation 和 Opportunity 必须绑定明确项目。" } };
    };
    let mission_label = mission
        .as_ref()
        .map_or("未选择 Mission", |mission| mission.title.as_str());
    rsx! {
        div { class: "surface-scroll business-surface relationships-surface",
            header { class: "surface-head",
                div { class: "surface-head-copy",
                    span { class: "surface-eyebrow", "RELATIONSHIPS · CRM" }
                    h1 { "关系与 CRM" }
                    p { "联系人、公司、邮件、会话与机会共享同一条关系记录；公开发现不会自动获得触达许可。" }
                }
                span { class: "honesty-badge", "NOT_IMPLEMENTED" }
            }
            nav { class: "surface-tabs", aria_label: "关系与 CRM 视图",
                button { class: if active_tab() == "pipeline" { "active" } else { "" }, onclick: move |_| active_tab.set("pipeline"), "Pipeline" }
                button { class: if active_tab() == "inbox" { "active" } else { "" }, onclick: move |_| active_tab.set("inbox"), "Inbox" }
                button { class: if active_tab() == "sequences" { "active" } else { "" }, onclick: move |_| active_tab.set("sequences"), "邮件序列" }
                button { class: if active_tab() == "contacts" { "active" } else { "" }, onclick: move |_| active_tab.set("contacts"), "联系人" }
            }
            section { class: "readiness-strip blocked",
                div { class: "readiness-intro",
                    span { class: "readiness-mark", UiIcon { name: if active_tab() == "inbox" { UiIconName::Inbox } else { UiIconName::Contact }, size: 18 } }
                    span { strong { "CRM / Inbox Projection 尚未接线" } small { "可以查看当前 Mission 边界；不能显示演示联系人、Consent、发送或回复。" } }
                }
                div { class: "readiness-stat", b { "0" } small { "可验证联系人" } }
                div { class: "readiness-stat", b { "0" } small { "可合法跟进" } }
                div { class: "readiness-stat", b { "0" } small { "开放机会" } }
            }
            div { class: "relationship-layout",
                section { class: "surface-section relationship-main",
                    div { class: "surface-section-head",
                        h2 {
                            if active_tab() == "pipeline" { "Pipeline" }
                            else if active_tab() == "inbox" { "Inbox 与人工接管" }
                            else if active_tab() == "sequences" { "Consent-safe 邮件序列" }
                            else { "Person / Company Identity" }
                        }
                        p { "{project.name} · {mission_label}" }
                    }
                    div { class: "state-canvas",
                        UiIcon {
                            name: if active_tab() == "pipeline" { UiIconName::Briefcase } else if active_tab() == "inbox" { UiIconName::Message } else if active_tab() == "sequences" { UiIconName::Mail } else { UiIconName::Contact },
                            size: 22,
                        }
                        span { class: "honesty-badge", "NOT_IMPLEMENTED" }
                        h3 { "等待 Application Projection" }
                        p { "该视图不会从页面维护第二套 CRM，也不会把公开邮箱、草稿或 Provider 200 OK 冒充 Consent、Conversation 或业务完成。" }
                    }
                }
                aside { class: "surface-section relationship-policy",
                    div { class: "surface-section-head", h2 { "关系安全边界" } p { "Contract" } }
                    div { class: "policy-check-list",
                        span { UiIcon { name: UiIconName::Shield, size: 14 } strong { "Identity 先解析再合并" } small { "Person / Company / Account 不跨租户猜测合并" } }
                        span { UiIcon { name: UiIconName::Check, size: 14 } strong { "Consent 按用途与市场" } small { "公开地址不等于可触达许可" } }
                        span { UiIcon { name: UiIconName::Bot, size: 14 } strong { "Human handoff 是 CAS 锁" } small { "人工接管后旧 Worker 禁止外发" } }
                    }
                }
            }
        }
    }
}

#[component]
fn PartnersSurface(
    project: Option<DesktopProjectProjection>,
    mission: Option<MissionProjection>,
) -> Element {
    #[cfg(feature = "visual-fixtures")]
    if let Some(page) = visual_fixture::page("partners") {
        return rsx! {
            PrototypeOperationsSurface {
                page,
                title: "达人与联盟",
                description: "从身份与许可开始，覆盖建联、雇佣、悬赏任务、真实交付、Review、权益接受与付款。",
                eyebrow: "PARTNERS · CREATOR WORK",
            }
        };
    }
    let mut active_tab = use_signal(|| "supply");
    let Some(project) = project else {
        return rsx! { EmptyState { code: "EMPTY", title: "没有 Partner 项目范围", detail: "Creator、Partner、任务、交付与付款必须绑定 Tenant/Project。" } };
    };
    let selected_mission = mission
        .as_ref()
        .map_or("未选择 Mission", |mission| mission.title.as_str());
    rsx! {
        div { class: "surface-scroll business-surface partners-surface",
            header { class: "surface-head",
                div { class: "surface-head-copy",
                    span { class: "surface-eyebrow", "PARTNERS · CREATOR WORK" }
                    h1 { "达人与联盟" }
                    p { "从身份与许可开始，覆盖建联、雇佣、悬赏任务、真实交付、Review、权益接受与付款。" }
                }
                span { class: "honesty-badge", "NOT_IMPLEMENTED" }
            }
            nav { class: "surface-tabs", aria_label: "达人与联盟视图",
                button { class: if active_tab() == "supply" { "active" } else { "" }, onclick: move |_| active_tab.set("supply"), "供给" }
                button { class: if active_tab() == "creators" { "active" } else { "" }, onclick: move |_| active_tab.set("creators"), "达人" }
                button { class: if active_tab() == "work" { "active" } else { "" }, onclick: move |_| active_tab.set("work"), "任务与交付" }
                button { class: if active_tab() == "programs" { "active" } else { "" }, onclick: move |_| active_tab.set("programs"), "项目" }
                button { class: if active_tab() == "economics" { "active" } else { "" }, onclick: move |_| active_tab.set("economics"), "结算" }
            }
            section { class: "readiness-strip blocked",
                div { class: "readiness-intro",
                    span { class: "readiness-mark", UiIcon { name: UiIconName::Handshake, size: 18 } }
                    span { strong { "Partner / Creator Projection 尚未接线" } small { "公开候选只允许研究；没有 Contact Permission 时不得自动触达。" } }
                }
                div { class: "readiness-stat", b { "0" } small { "已验证 Partner" } }
                div { class: "readiness-stat", b { "0" } small { "进行中任务" } }
                div { class: "readiness-stat", b { "0" } small { "待付款" } }
            }
            if active_tab() == "work" {
                section { class: "surface-section creator-work-contract",
                    div { class: "surface-section-head", h2 { "达人雇佣与悬赏交付合同" } p { "状态合同，不是业务完成证据" } }
                    div { class: "creator-work-flow", aria_label: "达人工作状态合同",
                        for (index, step) in CREATOR_WORK_STAGES.iter().enumerate() {
                            div { class: "creator-work-step",
                                i { "{index + 1}" }
                                span { strong { "{step}" } small { "CONTRACT · 尚无实例" } }
                            }
                        }
                    }
                    div { class: "creator-review-boundary",
                        UiIcon { name: UiIconName::FileCheck, size: 18 }
                        span { strong { "交付与付款必须分离" } small { "只有真实 Deliverable digest、用户 Review/Acceptance、权益记录和精确 Payout 审批齐全，才能进入付款验证。" } }
                        em { "NOT_IMPLEMENTED" }
                    }
                }
            } else {
                section { class: "surface-section",
                    div { class: "surface-section-head",
                        h2 {
                            if active_tab() == "supply" { "四类供给边界" }
                            else if active_tab() == "creators" { "Creator Identity 与建联许可" }
                            else if active_tab() == "programs" { "Program / Terms / Budget" }
                            else { "Commission / Refund / Payout" }
                        }
                        p { "{project.name} · {selected_mission}" }
                    }
                    div { class: "state-canvas",
                        UiIcon { name: if active_tab() == "economics" { UiIconName::Wallet } else { UiIconName::Users }, size: 22 }
                        span { class: "honesty-badge", "NOT_IMPLEMENTED" }
                        h3 { "等待持久 Partner Aggregate" }
                        p { "官方网络、Hartevo Opt-in、租户私域与公开候选必须明确区分；页面不会填充演示达人、订单、佣金或 Payout。" }
                    }
                }
            }
        }
    }
}

#[component]
fn OutcomesSurface(
    project: Option<DesktopProjectProjection>,
    mission: Option<MissionProjection>,
) -> Element {
    #[cfg(feature = "visual-fixtures")]
    if let Some(page) = visual_fixture::page("outcomes") {
        return rsx! {
            PrototypeOperationsSurface {
                page,
                title: "成果与下一循环",
                description: "原始事件、身份链、退款与归因不被页面覆盖；相关性不会被描述为因果。",
                eyebrow: "OUTCOMES · ATTRIBUTION",
            }
        };
    }
    let Some(project) = project else {
        return rsx! { EmptyState { code: "EMPTY", title: "没有 Outcome 项目范围", detail: "Outcome、Attribution、Refund 与 Payout 必须绑定明确项目。" } };
    };
    let selected = mission.as_ref();
    let work_products = selected.map_or(0, |mission| mission.work_product_count);
    let verified_effects = selected.map_or(0, |mission| mission.verified_effect_count);
    let evidence = selected.map_or(0, |mission| mission.evidence_count);
    rsx! {
        div { class: "surface-scroll business-surface outcomes-surface",
            header { class: "surface-head",
                div { class: "surface-head-copy",
                    span { class: "surface-eyebrow", "OUTCOMES · ATTRIBUTION" }
                    h1 { "成果与下一循环" }
                    p { "原始事件、身份链、退款与归因不被页面覆盖；相关性不会被描述为因果。" }
                }
                span { class: "sync-chip", "{project.name}" }
            }
            section { class: "pipeline-strip",
                div { class: "pipeline-stage", strong { "{evidence}" } span { "Evidence" } }
                div { class: "pipeline-stage", strong { "{work_products}" } span { "Work Products" } }
                div { class: "pipeline-stage", strong { "{verified_effects}" } span { "Verified Effects" } }
                div { class: "pipeline-stage", strong { "0" } span { "Revenue Events" } }
                div { class: "pipeline-stage", strong { "0" } span { "Refund Events" } }
                div { class: "pipeline-stage", strong { "—" } span { "Attribution" } }
            }
            div { class: "outcome-layout",
                section { class: "surface-section",
                    div { class: "surface-section-head", h2 { "Outcome Ledger" } p { "不可变、可复算" } }
                    if let Some(mission) = selected {
                        if let Some(summary) = &mission.outcome_summary {
                            div { class: "verified-outcome",
                                UiIcon { name: UiIconName::Check, size: 18 }
                                span { strong { "Domain Outcome Summary" } p { "{summary}" } }
                                em { "DOMAIN" }
                            }
                        } else {
                            div { class: "state-canvas compact", span { class: "honesty-badge", "EMPTY" } h3 { "尚无 Outcome Review" } p { "当前 Mission 没有持久 Outcome summary；不会从 Stage 或 Provider 响应推导 Revenue。" } }
                        }
                    } else {
                        div { class: "state-canvas compact", span { class: "honesty-badge", "WAITING_USER" } h3 { "选择一个 Mission" } p { "项目级汇总需要 Attribution Projection；当前先保持 Mission scoped。" } }
                    }
                }
                section { class: "surface-section",
                    div { class: "surface-section-head", h2 { "归因与下一决策" } p { "VM-11" } }
                    div { class: "policy-check-list",
                        span { UiIcon { name: UiIconName::Workflow, size: 14 } strong { "身份链优先" } small { "Verified link / coupon / provider identity chain" } }
                        span { UiIcon { name: UiIconName::Chart, size: 14 } strong { "保留 Unattributed" } small { "无法确定来源时不强行分配" } }
                        span { UiIcon { name: UiIconName::Wallet, size: 14 } strong { "退款为独立反向事件" } small { "原订单不会被覆盖" } }
                    }
                    span { class: "honesty-badge", "NOT_IMPLEMENTED" }
                }
            }
        }
    }
}

#[component]
fn SettingsSurface(
    runtime: Option<DesktopRuntimeProjection>,
    on_close: EventHandler<()>,
) -> Element {
    let mut active_panel = use_signal(|| "general");
    let mut settings_query = use_signal(String::new);
    let runtime_status = runtime.as_ref().map_or("数据层未就绪", |runtime| {
        runtime_availability_label(runtime.status)
    });
    let provider = runtime
        .as_ref()
        .and_then(|runtime| runtime.provider.as_deref())
        .unwrap_or("未配置");
    let model = runtime
        .as_ref()
        .and_then(|runtime| runtime.model.as_deref())
        .unwrap_or("未配置");
    rsx! {
        section { class: "settings-shell", aria_label: "Hartevo 设置",
            header { class: "settings-topbar",
                img { src: BRAND_MARK_DATA_URL.as_str(), alt: "" }
                strong { "Hartevo" }
                span { "设置" }
                button { class: "settings-close", onclick: move |_| on_close.call(()), "返回工作台" kbd { "Esc" } }
            }
            aside { class: "settings-sidebar",
                label { class: "settings-search", UiIcon { name: UiIconName::Search, size: 14 } input {
                    value: "{settings_query}",
                    placeholder: "搜索设置",
                    aria_label: "搜索设置分区",
                    oninput: move |event| settings_query.set(event.value()),
                } }
                nav { aria_label: "设置分区",
                    h2 { "应用" }
                    for (id, label) in [
                        ("general", "常规"), ("appearance", "外观与语言"), ("models", "模型与运行"),
                        ("storage", "数据与存储"), ("privacy", "隐私与权限"), ("notifications", "通知"),
                    ] {
                        if settings_query.read().trim().is_empty() || label.contains(settings_query.read().trim()) {
                            button { class: if active_panel() == id { "active" } else { "" }, onclick: move |_| active_panel.set(id), "{label}" }
                        }
                    }
                    h2 { "组织与系统" }
                    for (id, label) in [
                        ("connections", "连接与凭据"), ("account", "账户与团队"), ("usage", "用量与计费"),
                        ("shortcuts", "快捷键"),
                    ] {
                        if settings_query.read().trim().is_empty() || label.contains(settings_query.read().trim()) {
                            button { class: if active_panel() == id { "active" } else { "" }, onclick: move |_| active_panel.set(id), "{label}" }
                        }
                    }
                }
                div { class: "settings-version", "Hartevo Desktop" small { "UI baseline · prototype v12" } }
            }
            main { class: "settings-content",
                if active_panel() == "general" {
                    GeneralSettingsPanel {}
                } else if active_panel() == "appearance" {
                    SettingsPanel { title: "外观", detail: "视觉遵循冻结交互原型的 light-first 基线。",
                        SettingsRow { title: "主题", detail: "原型基线未定义暗色主题。", value: "浅色" }
                        SettingsRow { title: "字体", detail: "Geist → 系统 UI → 中日韩系统字体。", value: "System fallback" }
                        SettingsRow { title: "减少动态效果", detail: "跟随系统 prefers-reduced-motion。", value: "跟随系统" }
                    }
                } else if active_panel() == "models" {
                    SettingsPanel { title: "模型与 Runtime", detail: "模型选择不改变 Mission Capability、预算或审批边界。",
                        SettingsRow { title: "Runtime", detail: "来自 DesktopRuntimeProjection。", value: runtime_status }
                        SettingsRow { title: "Provider", detail: "没有配置时不显示可用。", value: provider }
                        SettingsRow { title: "Model", detail: "只展示真实配置。", value: model }
                    }
                } else if active_panel() == "shortcuts" {
                    SettingsPanel { title: "快捷键", detail: "核心路径支持键盘与明确焦点。",
                        SettingsRow { title: "新建任务", detail: "回到当前项目总调度。", value: "⌘ N" }
                        SettingsRow { title: "全局搜索", detail: "搜索持久 Project / Mission。", value: "⌘ P" }
                        SettingsRow { title: "回到总调度", detail: "不创建新 Conversation。", value: "⌘ K" }
                        SettingsRow { title: "打开设置", detail: "用户级设置。", value: "⌘ ," }
                    }
                } else {
                    SettingsPanel { title: settings_panel_label(active_panel()), detail: "该设置分区的 Application Service 尚未接线；视觉与键盘结构已按原型实现。",
                        SettingsRow { title: "能力状态", detail: "不会使用页面本地 store 伪造保存。", value: "NOT_IMPLEMENTED" }
                        SettingsRow { title: "数据边界", detail: "正文、Secret、Token、Cookie 与直接 PII 不进入遥测。", value: "POLICY" }
                    }
                }
            }
        }
    }
}

#[component]
fn GeneralSettingsPanel() -> Element {
    rsx! {
        section { class: "settings-panel",
            header { h1 { "常规" } p { "定义 Hartevo Desktop 启动、创建项目和自然语言调度的默认行为。尚未接入 Settings Application Service 的控件保持禁用。" } }
            section { class: "settings-section",
                h2 { "项目默认值" }
                div { class: "settings-group",
                    SettingsControlRow { title: "新项目默认存储方式", detail: "创建时仍会明确显示和确认，不会暗中上传。",
                        select { disabled: true, aria_label: "新项目默认存储方式",
                            option { selected: true, "本地文件夹（推荐）" }
                            option { "本地 + 加密同步" }
                            option { "云端工作区" }
                        }
                    }
                    SettingsControlRow { title: "默认本地项目位置", detail: "新建本地目录时使用；选择已有文件夹不会复制文件。",
                        div { class: "settings-path-control",
                            input { disabled: true, value: "未配置", aria_label: "默认本地项目位置" }
                            button { disabled: true, "浏览…" }
                        }
                    }
                    SettingsControlRow { title: "切换项目后", detail: "默认进入项目总调度，自动加载该项目的任务、事实和连接状态。",
                        select { disabled: true, aria_label: "切换项目后的默认页面",
                            option { selected: true, "进入总调度" }
                            option { "恢复上次工作面" }
                        }
                    }
                }
            }
            section { class: "settings-section",
                h2 { "应用行为" }
                div { class: "settings-group",
                    SettingsSwitchRow { title: "开机启动", detail: "只启动桌面壳；自动任务由各项目策略独立决定。", enabled: false }
                    SettingsSwitchRow { title: "建议下一步", detail: "根据当前 Mission、缺口和等待确认状态给出建议。", enabled: true }
                }
            }
            p { class: "settings-boundary", span { class: "honesty-badge", "NOT_IMPLEMENTED" } " 这些值尚未持久化；视觉与键盘结构不代表设置已生效。" }
        }
    }
}

#[component]
fn SettingsControlRow(
    #[props(into)] title: String,
    #[props(into)] detail: String,
    children: Element,
) -> Element {
    rsx! {
        div { class: "settings-control-row",
            span { strong { "{title}" } small { "{detail}" } }
            div { class: "settings-control", {children} }
        }
    }
}

#[component]
fn SettingsSwitchRow(
    #[props(into)] title: String,
    #[props(into)] detail: String,
    enabled: bool,
) -> Element {
    rsx! {
        div { class: "settings-control-row",
            span { strong { "{title}" } small { "{detail}" } }
            button {
                class: if enabled { "settings-switch on" } else { "settings-switch" },
                role: "switch",
                aria_checked: enabled,
                aria_label: "{title}",
                disabled: true,
                i {}
            }
        }
    }
}

#[component]
fn SettingsPanel(
    #[props(into)] title: String,
    #[props(into)] detail: String,
    children: Element,
) -> Element {
    rsx! {
        section { class: "settings-panel",
            header { h1 { "{title}" } p { "{detail}" } }
            section { class: "settings-section", h2 { "配置" } div { class: "settings-group", {children} } }
        }
    }
}

#[component]
fn SettingsRow(
    #[props(into)] title: String,
    #[props(into)] detail: String,
    #[props(into)] value: String,
) -> Element {
    rsx! {
        div { class: "settings-row",
            span { strong { "{title}" } small { "{detail}" } }
            span { class: "settings-value", "{value}" }
        }
    }
}

#[component]
fn ConnectionsSurface(
    project: Option<DesktopProjectProjection>,
    context_access: Option<ProjectContextAccessProjection>,
) -> Element {
    #[cfg(feature = "visual-fixtures")]
    if let Some(page) = visual_fixture::page("connections") {
        return rsx! {
            PrototypeOperationsSurface {
                page,
                title: "连接中心",
                description: "管理 Hartevo 为当前项目读取、发布、发送和同步所需的账号；连接不自动放宽权限。",
                eyebrow: "CONNECTIONS · CAPABILITY AVAILABILITY",
            }
        };
    }
    let mut active_tab = use_signal(|| "overview");
    let mut flow_open = use_signal(|| false);
    let mut flow_step = use_signal(|| 1_u8);
    let Some(project) = project else {
        return rsx! { EmptyState { code: "EMPTY", title: "没有项目连接范围", detail: "连接必须绑定 Tenant/Project/Account；未选择项目时不会展示假连接。" } };
    };
    let revision = project.revision;
    rsx! {
        div { class: "surface-scroll business-surface connections-surface",
            header { class: "surface-head",
                div { class: "surface-head-copy",
                    span { class: "surface-eyebrow", "CONNECTIONS · CAPABILITY AVAILABILITY" }
                    h1 { "连接中心" }
                    p { "连接只让 Capability 变得可用；外部写入仍需策略、精确审批、Receipt 与独立 Verification。" }
                }
                div { class: "surface-head-actions",
                    button { class: "surface-button", onclick: move |_| { flow_step.set(1); flow_open.set(true); }, UiIcon { name: UiIconName::Plus, size: 14 } "查看连接流程" }
                    span { class: "sync-chip", "Project revision {revision}" }
                }
            }
            nav { class: "surface-tabs", aria_label: "连接中心视图",
                button { class: if active_tab() == "overview" { "active" } else { "" }, onclick: move |_| active_tab.set("overview"), "概览" }
                button { class: if active_tab() == "all" { "active" } else { "" }, onclick: move |_| active_tab.set("all"), "全部连接" }
                button { class: if active_tab() == "policies" { "active" } else { "" }, onclick: move |_| active_tab.set("policies"), "动作策略" }
                button { class: if active_tab() == "activity" { "active" } else { "" }, onclick: move |_| active_tab.set("activity"), "活动" }
            }
            if active_tab() == "overview" {
                div { class: "connections-overview-grid",
                    main {
                        EncryptionReadinessCard { encryption: project.encryption.clone() }
                        ContextAccessCard { access: context_access }
                        section { class: "surface-section",
                            div { class: "surface-section-head", h2 { "Mission 需要的连接" } p { "Provider Probe" } }
                            div { class: "state-canvas compact",
                                UiIcon { name: UiIconName::Plug, size: 22 }
                                span { class: "honesty-badge", "NOT_IMPLEMENTED" }
                                h3 { "尚无 Connection Projection" }
                                p { "当前 Desktop 数据面没有读取 Provider 凭据，也没有把 Catalog 中的 Provider 目标声明为 Connected。" }
                            }
                        }
                    }
                    aside { class: "surface-section",
                        div { class: "surface-section-head", h2 { "连接原则" } p { "Zero-trust" } }
                        div { class: "policy-check-list",
                            span { UiIcon { name: UiIconName::Target, size: 14 } strong { "账号身份必须 Probe" } small { "错误账号或 Scope 撤销会立即阻塞" } }
                            span { UiIcon { name: UiIconName::Shield, size: 14 } strong { "连接不扩大权限" } small { "Capability 与 Effect Policy 独立判定" } }
                            span { UiIcon { name: UiIconName::Refresh, size: 14 } strong { "uncertain 不自动重放" } small { "先 reconcile，再显式决定" } }
                        }
                    }
                }
            } else if active_tab() == "all" {
                section { class: "surface-section",
                    div { class: "surface-section-head", h2 { "全部连接" } p { "Tenant / Project / Account scoped" } }
                    div { class: "connection-table-header", span { "服务与账号" } span { "用途" } span { "Scope" } span { "状态" } span { "最近验证" } }
                    div { class: "state-canvas compact", span { class: "honesty-badge", "EMPTY" } h3 { "没有可展示的真实 Connection" } p { "Provider Adapter 与 Secret Store 投影接线后才会出现行。" } }
                }
            } else if active_tab() == "policies" {
                section { class: "surface-section",
                    div { class: "surface-section-head", h2 { "项目动作策略" } p { "连接提供能力，Mission 决定能否执行" } }
                    div { class: "policy-matrix",
                        div { class: "policy-matrix-row head", span { "Capability" } span { "读取" } span { "草稿" } span { "外部写入" } span { "金额动作" } }
                        div { class: "policy-matrix-row", strong { "Channel" } span { "Policy checked" } span { "允许" } span { "精确审批" } span { "不适用" } }
                        div { class: "policy-matrix-row", strong { "Email / CRM" } span { "Consent required" } span { "允许" } span { "精确审批" } span { "不适用" } }
                        div { class: "policy-matrix-row", strong { "Partner / Creator" } span { "Permission required" } span { "允许" } span { "合同审批" } span { "Payout 审批" } }
                    }
                    p { class: "contract-disclaimer", "以上为 Operating Contract 的静态边界，不表示任何 Provider 已连接或 Effect 已获批准。" }
                }
            } else {
                section { class: "surface-section",
                    div { class: "surface-section-head", h2 { "连接活动" } p { "Audit projection" } }
                    div { class: "state-canvas compact", span { class: "honesty-badge", "EMPTY" } h3 { "暂无持久连接事件" } p { "不会复制原型中的 Twenty、X、WordPress 或 Chatwoot 演示活动。" } }
                }
            }

            if flow_open() {
                button { class: "overlay-backdrop", aria_label: "关闭连接流程", onclick: move |_| flow_open.set(false) }
                section { class: "connection-flow", role: "dialog", aria_modal: "true", aria_label: "连接服务流程",
                    header {
                        span { strong { "连接服务" } small { "FLOW CONTRACT · 不触发 OAuth" } }
                        button { aria_label: "关闭", onclick: move |_| flow_open.set(false), UiIcon { name: UiIconName::X, size: 15 } }
                    }
                    div { class: "flow-progress",
                        for step in 1_u8..=4 {
                            span { class: if step == flow_step() { "active" } else if step < flow_step() { "done" } else { "" }, i { "{step}" } small { if step == 1 { "用途" } else if step == 2 { "权限" } else if step == 3 { "账号" } else { "验证" } } }
                        }
                    }
                    div { class: "flow-body",
                        if flow_step() == 1 {
                            h2 { "为什么需要连接" }
                            p { "Hartevo 只会为当前 Mission 明确需要的 Capability 请求连接；当前没有选定 Provider，因此不会开始授权。" }
                            div { class: "context-note", header { UiIcon { name: UiIconName::Target, size: 14 } strong { "Project scoped" } } p { "{project.name} · Connection 必须绑定 tenant/project/provider/account。" } }
                        } else if flow_step() == 2 {
                            h2 { "审阅最小权限" }
                            p { "读取与写入 Scope 分开；连接成功不会自动批准发布、发送、邀请、合同或付款。" }
                            div { class: "permission-list",
                                span { UiIcon { name: UiIconName::Check, size: 14 } strong { "读取账号与健康状态" } em { "自动" } }
                                span { UiIcon { name: UiIconName::Check, size: 14 } strong { "读取当前项目需要的数据" } em { "Policy" } }
                                span { UiIcon { name: UiIconName::Shield, size: 14 } strong { "执行对外写入" } em { "需要审批" } }
                            }
                        } else if flow_step() == 3 {
                            h2 { "确认真实账号" }
                            p { "OAuth callback、state/nonce 和实时 Probe 尚未接入 Desktop；不能选择或声称账号已连接。" }
                            div { class: "state-canvas compact", span { class: "honesty-badge", "BLOCKED_ENV" } h3 { "Provider 授权环境未配置" } }
                        } else {
                            h2 { "独立验证" }
                            p { "只有实时 Probe 返回匹配的 tenant/project/provider/account 与最小 Scope，连接才能显示 Connected。" }
                            div { class: "state-canvas compact", span { class: "honesty-badge", "NOT_IMPLEMENTED" } h3 { "尚无 Probe Receipt" } }
                        }
                    }
                    footer {
                        button { class: "surface-button", disabled: flow_step() == 1, onclick: move |_| flow_step.set(flow_step().saturating_sub(1)), "上一步" }
                        span { "{flow_step()} / 4" }
                        if flow_step() < 4 {
                            button { class: "surface-button primary", onclick: move |_| flow_step.set(flow_step() + 1), "继续" }
                        } else {
                            button { class: "surface-button primary", onclick: move |_| flow_open.set(false), "关闭" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn CapabilityEvidenceSurface(evidence: ProductEvidenceProjection) -> Element {
    let digest = evidence.catalog_digest.clone();
    rsx! {
        div { class: "surface-scroll business-surface",
            header { class: "surface-title", div { small { "机器可读 Source of Truth" } h2 { "十二条 Mission 证据" } } span { class: "honesty-badge", "passed: {evidence.release_passed}" } }
            section { class: "surface-panel evidence-ledger",
                header { h3 { "Mission Catalog" } span { title: "{digest}", "digest {short_digest(&digest)}" } }
                for item in evidence.missions {
                    div { class: "evidence-ledger-row",
                        strong { "{item.mission_id}" }
                        span { "{item.title}" }
                        em { "{evidence_level_label(item.evidence_level)}" }
                        b { "{mission_evidence_status_label(item.status)}" }
                    }
                }
            }
            div { class: "boundary-note", "这些是合同基线，不是 E3/E4/E5 证明。V0/V1/V2 未执行、Provider Canary 与 12 租户长周期证据缺失时，Release passed 必须保持 false。" }
        }
    }
}

#[cfg(feature = "visual-fixtures")]
#[component]
fn PrototypeWorkpad(
    mission: MissionProjection,
    workpad: visual_fixture::VisualWorkpad,
    on_close: EventHandler<()>,
) -> Element {
    let initial_tab = if active_visual_surface_variant().as_deref() == Some("mission-inspector") {
        "运行检查器".to_owned()
    } else {
        workpad.tabs.first().cloned().unwrap_or_default()
    };
    let mut active_tab = use_signal(move || initial_tab);
    let mut expanded_candidate = use_signal(|| None::<usize>);
    let mut selected_source = use_signal(|| None::<visual_fixture::VisualRow>);
    let mut action_notice = use_signal(|| None::<String>);
    let inspector_active = active_tab() == "运行检查器";
    rsx! {
        aside { class: "workpad prototype-workpad", aria_label: "任务工作台",
            header { class: "prototype-workpad-header",
                nav { class: "prototype-workpad-tabs", aria_label: "工作产物标签",
                    for tab in workpad.tabs.clone() {
                        {
                            let tab_id = tab.clone();
                            rsx! {
                                button { class: if active_tab() == tab { "active" } else { "" }, onclick: move |_| active_tab.set(tab_id.clone()),
                                    UiIcon { name: UiIconName::FileText, size: 13 }
                                    span { "{tab}" }
                                }
                            }
                        }
                    }
                    button { class: if inspector_active { "active inspector" } else { "inspector" }, onclick: move |_| active_tab.set("运行检查器".into()),
                        UiIcon { name: UiIconName::Workflow, size: 13 }
                        span { "运行检查器" }
                    }
                }
                div { class: "prototype-workpad-actions",
                    button { aria_label: "评论", onclick: move |_| action_notice.set(Some("NOT_IMPLEMENTED · 评论服务尚未接线；未写入任何内容。".into())), UiIcon { name: UiIconName::Message, size: 14 } }
                    button { aria_label: "导出", onclick: move |_| action_notice.set(Some("NOT_IMPLEMENTED · 导出签名与敏感字段清洗尚未接线。".into())), UiIcon { name: UiIconName::FileCheck, size: 14 } }
                    button { aria_label: "收起工作台", onclick: move |_| on_close.call(()), UiIcon { name: UiIconName::Panel, size: 14 } }
                }
            }
            if let Some(notice) = action_notice() {
                div { class: "prototype-workpad-notice", role: "status",
                    span { "{notice}" }
                    button { aria_label: "关闭提示", onclick: move |_| action_notice.set(None), UiIcon { name: UiIconName::X, size: 12 } }
                }
            }
            if inspector_active {
                div { class: "prototype-inspector-body",
                    header {
                        span { class: "document-kicker", "MISSION INSPECTOR · VISUAL_FIXTURE" }
                        h2 { "运行环境与证据" }
                        p { "所有分区来自同一 Mission projection；fixture 不会创建 Worker、Browser、Effect 或 Provider 连接。" }
                    }
                    section { class: "inspector-summary-grid",
                        div { strong { "+{mission.completed_checkpoint_count}" } small { "Checkpoint transitions" } }
                        div { strong { "{mission.work_product_count}" } small { "Work Products" } }
                        div { strong { "0" } small { "External Effects" } }
                    }
                    details { open: true, class: "inspector-section",
                        summary { UiIcon { name: UiIconName::Workflow, size: 14 } strong { "Checkpoint 与工作树" } span { "{mission.completed_checkpoint_count}/{mission.checkpoint_count}" } }
                        div { class: "inspector-list",
                            span { i { class: "done" } strong { "scoped_collection" } small { "completed fixture transition" } }
                            span { i { class: "live" } strong { "evidence_plan" } small { "current structural sample" } }
                            span { i {} strong { "decision" } small { "pending" } }
                        }
                    }
                    details { open: true, class: "inspector-section",
                        summary { UiIcon { name: UiIconName::Bot, size: 14 } strong { "Worker 与后台运行" } span { "0 active" } }
                        div { class: "inspector-empty-row", "BLOCKED_ENV · 没有启动 Runtime 子进程或 Worker lease" }
                    }
                    details { class: "inspector-section",
                        summary { UiIcon { name: UiIconName::Layout, size: 14 } strong { "Browser Workspace" } span { "未创建" } }
                        div { class: "inspector-empty-row", "人工接管锁、Browser lease 与 stable locator 将在真实 projection 中显示。" }
                    }
                    details { open: true, class: "inspector-section",
                        summary { UiIcon { name: UiIconName::FileCheck, size: 14 } strong { "来源" } span { "3 fixture" } }
                        div { class: "inspector-source-list",
                            for source in workpad.sources.clone() {
                                button { UiIcon { name: UiIconName::FileText, size: 13 } span { strong { "{source.title}" } small { "{source.detail}" } } em { "{source.state}" } }
                            }
                        }
                    }
                }
            } else {
                div { class: "workpad-body prototype-document",
                    header { class: "prototype-document-title",
                        span { class: "document-kicker", "{workpad.eyebrow}" }
                        h2 { "{workpad.title}" }
                        p { "{workpad.meta}" }
                        div { class: "prototype-document-chips",
                            span { "revision {mission.revision}" }
                            span { "0 ProviderReceipt" }
                            span { "0 Verification" }
                        }
                    }
                    section { class: "prototype-loop-strip", aria_label: "增长循环",
                        for (index, phase) in workpad.phases.clone().into_iter().enumerate() {
                            span { i { "{index + 1}" } strong { "{phase}" } }
                        }
                    }
                    section { class: "prototype-doc-section executive",
                        header { h3 { "结论" } span { "结构样例" } }
                        p { "{workpad.conclusion}" }
                        div { class: "prototype-evidence-line",
                            span { i {} "需求趋势样例 +34%" }
                            span { i {} "讨论量样例 2.1×" }
                            span { i { class: "gold" } "竞争密度待验证" }
                        }
                    }
                    section { class: "prototype-doc-section",
                        header { h3 { "需求趋势" } span { "过去 12 个月 · 标准化结构" } }
                        div { class: "prototype-trend-layout",
                            div { class: "prototype-chart",
                                header { strong { "搜索与社交需求" } span { i { class: "gold" } "可调哑铃" } span { i { class: "green" } "折叠划船机" } }
                                img { src: PROTOTYPE_TREND_SVG, alt: "美国健身器材需求趋势视觉夹具" }
                            }
                            aside { span { i {} "验证窗口结构" } strong { "需求在样例中增长，真实结论仍需 Provider Evidence" } p { "先验证空间效率与快速换重两个购买理由，不在第一轮扩大主张。" } }
                        }
                    }
                    section { class: "prototype-doc-section",
                        header { h3 { "候选方向" } span { "综合需求、利润与风险" } }
                        div { class: "prototype-opportunity-list",
                            for (index, row) in workpad.candidates.clone().into_iter().enumerate() {
                                div {
                                    class: if expanded_candidate() == Some(index) { "prototype-opportunity-item open" } else { "prototype-opportunity-item" },
                                    button {
                                        class: "prototype-opportunity-row",
                                        aria_expanded: expanded_candidate() == Some(index),
                                        onclick: move |_| {
                                            expanded_candidate.set(
                                                if expanded_candidate() == Some(index) { None } else { Some(index) },
                                            );
                                        },
                                        i { "{index + 1}" }
                                        span { strong { "{row.title}" } small { "{row.detail}" } }
                                        em { strong { "{row.meta}" } small { "{row.state}" } }
                                        UiIcon { name: UiIconName::ChevronDown, size: 13 }
                                    }
                                    if expanded_candidate() == Some(index) {
                                        div { class: "prototype-opportunity-detail",
                                            span { strong { "验证假设" } small { "需求、利润、交付可行性与反证必须分别记录。" } }
                                            span { strong { "允许动作" } small { "只允许生成 Research/Decision Work Product；0 外部 Effect。" } }
                                            button { onclick: move |_| action_notice.set(Some("VISUAL_FIXTURE · 已定位到候选结构；没有改变 Project Truth。".into())), "在 Mission 中定位" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    section { class: "prototype-doc-section",
                        header { h3 { "来源与边界" } span { "provenance" } }
                        div { class: "prototype-source-list",
                            for source in workpad.sources.clone() {
                                button {
                                    onclick: {
                                        let source = source.clone();
                                        move |_| selected_source.set(Some(source.clone()))
                                    },
                                    UiIcon { name: UiIconName::FileText, size: 13 }
                                    span { strong { "{source.title}" } small { "{source.detail}" } }
                                    em { "{source.meta} · {source.state}" }
                                }
                            }
                        }
                        if let Some(source) = selected_source() {
                            div { class: "prototype-source-detail", role: "status",
                                span { strong { "{source.title}" } small { "{source.detail}" } }
                                b { "VISUAL_FIXTURE · {source.state}" }
                                button { aria_label: "关闭来源详情", onclick: move |_| selected_source.set(None), UiIcon { name: UiIconName::X, size: 12 } }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn Workpad(
    mission: Option<MissionProjection>,
    context_access: Option<ProjectContextAccessProjection>,
    on_close: EventHandler<()>,
) -> Element {
    #[cfg(feature = "visual-fixtures")]
    if let (Some(mission), Some(presentation)) = (mission.clone(), visual_fixture::presentation()) {
        return rsx! { PrototypeWorkpad { mission, workpad: presentation.workpad, on_close } };
    }
    let context_is_open = context_access.as_ref().is_some_and(|access| {
        matches!(
            access.status,
            ProjectContextAccessStatus::Ready { .. } | ProjectContextAccessStatus::Degraded { .. }
        )
    });
    rsx! {
        aside { class: "workpad", aria_label: "任务工作台",
            header {
                span { strong { "工作产物" } small { "Application projection" } }
                button { class: "icon-button", aria_label: "收起工作台", onclick: move |_| on_close.call(()), UiIcon { name: UiIconName::Panel, size: 14 } }
            }
            div { class: "workpad-body",
                if !context_is_open {
                    div { class: "document-kicker", "CONTEXT LOCKED" }
                    h2 { "工作产物不可读" }
                    p { class: "document-lead", "本机 Device envelope 未打开 encrypted Context；这里不会显示 Mission 正文、Preview 或假文档。" }
                } else if let Some(mission) = mission {
                    div { class: "document-kicker", "MISSION · REVISION {mission.revision}" }
                    h2 { "{mission.title}" }
                    if mission.work_product_count == 0 {
                        p { class: "document-lead", "EMPTY：当前 Mission 没有持久 WorkProductManifest。页面不会填充示例报告。" }
                    } else {
                        p { class: "document-lead", "以下 Preview 来自 SQLCipher 中通过 Application 完整校验的 WorkProductManifest；不是页面生成的示例内容。" }
                        for product in mission.work_products {
                            article { class: "work-product-preview",
                                header {
                                    span { class: "file-mark", "WP" }
                                    span {
                                        strong { "{product.title}" }
                                        small { "{product.work_product_type} · manifest v{product.manifest_version} · product r{product.work_product_revision}" }
                                    }
                                    em { "{work_product_status_label(&product.adoption_status)}" }
                                }
                                p { "{product.preview_text}" }
                                footer {
                                    span { "{product.preview_media_type}" }
                                    span { "evidence {product.evidence_count}" }
                                    span { "editable {product.editable_scope_count}" }
                                    code { title: "{product.manifest_digest}", "manifest {short_digest(&product.manifest_digest)}" }
                                }
                            }
                        }
                    }
                    div { class: "document-state", small { "Mission state" } strong { "{mission_stage_label(&mission.stage)}" } span { "revision {mission.revision}" } }
                } else {
                    div { class: "document-kicker", "NO ACTIVE MISSION" }
                    h2 { "没有工作产物" }
                    p { class: "document-lead", "选择真实 Mission 后，此处只显示其持久 WorkProduct；不会加载 demo 文档。" }
                }
            }
        }
    }
}

fn work_product_status_label(status: &WorkProductStatus) -> &'static str {
    match status {
        WorkProductStatus::Draft => "DRAFT",
        WorkProductStatus::ReadyForReview => "READY_FOR_REVIEW",
        WorkProductStatus::Accepted => "ACCEPTED",
        WorkProductStatus::Superseded => "SUPERSEDED",
    }
}

fn surface_heading(surface: Surface, mission_title: &str) -> String {
    match surface {
        Surface::Orchestrator => mission_title.to_owned(),
        Surface::Current => "当前状态".to_owned(),
        Surface::Missions => "全部任务".to_owned(),
        Surface::ChannelOperations => "渠道运营".to_owned(),
        Surface::Relationships => "关系与 CRM".to_owned(),
        Surface::Partners => "达人与联盟".to_owned(),
        Surface::Connections => "连接中心".to_owned(),
        Surface::Outcomes => "成果与循环".to_owned(),
        Surface::CapabilityEvidence => "能力与证据".to_owned(),
        Surface::Settings => "设置".to_owned(),
        Surface::StateCoverage => "产品状态覆盖".to_owned(),
    }
}

const fn surface_context_label(surface: Surface) -> &'static str {
    match surface {
        Surface::Orchestrator => "Mission Conversation",
        Surface::Current => "Project Current",
        Surface::Missions => "Mission Inventory",
        Surface::ChannelOperations => "Growth Operations",
        Surface::Relationships => "Relationships",
        Surface::Partners => "Partner Operations",
        Surface::Connections => "Capability Availability",
        Surface::Outcomes => "Outcome & Attribution",
        Surface::CapabilityEvidence => "Release Evidence",
        Surface::Settings => "User Preferences",
        Surface::StateCoverage => "UI State Contract",
    }
}

fn active_visual_fixture_id() -> Option<String> {
    #[cfg(feature = "visual-fixtures")]
    {
        visual_fixture::active_id()
    }
    #[cfg(not(feature = "visual-fixtures"))]
    {
        None
    }
}

fn active_visual_surface_variant() -> Option<String> {
    #[cfg(feature = "visual-fixtures")]
    {
        visual_fixture::active_surface_variant()
    }
    #[cfg(not(feature = "visual-fixtures"))]
    {
        None
    }
}

fn active_visual_runtime_text_stream() -> Option<DesktopRuntimeTextStreamProjection> {
    #[cfg(feature = "visual-fixtures")]
    {
        visual_fixture::runtime_text_stream()
    }
    #[cfg(not(feature = "visual-fixtures"))]
    {
        None
    }
}

fn initial_workpad_open() -> bool {
    #[cfg(feature = "visual-fixtures")]
    if active_visual_fixture_id().is_some() {
        return matches!(
            active_visual_surface_variant().as_deref(),
            Some("mission-workpad" | "mission-inspector")
        );
    }
    true
}

#[cfg(feature = "visual-fixtures")]
fn active_visual_notification_count() -> usize {
    visual_fixture::presentation().map_or(0, |presentation| presentation.notifications.len())
}

#[cfg(not(feature = "visual-fixtures"))]
const fn active_visual_notification_count() -> usize {
    0
}

fn active_visual_zoom() -> f64 {
    #[cfg(feature = "visual-fixtures")]
    {
        if std::env::var("HARTEVO_DESKTOP_UI_ZOOM").ok().as_deref() == Some("2") {
            return 2.0;
        }
    }
    1.0
}

fn begin_runtime_progress_monitor(
    control: DesktopRuntimeCancellation,
    mut progress: Signal<Vec<DesktopRuntimeProgressEvent>>,
    submitting: Signal<bool>,
    retrying: Signal<bool>,
) {
    spawn(async move {
        let mut cursor = 0_u64;
        loop {
            let events = control.progress_since(cursor);
            let terminal = events.iter().any(|event| event.phase.is_terminal());
            if let Some(last) = events.last() {
                cursor = last.sequence;
                let mut projection = progress.write();
                projection.extend(events);
                if projection.len() > 32 {
                    let overflow = projection.len() - 32;
                    projection.drain(0..overflow);
                }
            }
            if terminal || (!*submitting.read() && !*retrying.read()) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        }
    });
}

fn desktop_scope_is_selected(
    model: Signal<DesktopUiModel>,
    project_id: &ProjectId,
    mission_id: &MissionId,
) -> bool {
    let current = model.read();
    current.selected_project_id.as_ref() == Some(project_id)
        && current.selected_mission_id.as_ref() == Some(mission_id)
}

fn update_runtime_text_stream(
    projection: Option<DesktopRuntimeTextStreamProjection>,
    mut stream: Signal<Option<DesktopRuntimeTextStreamProjection>>,
    follow_latest: Signal<bool>,
    mut has_unseen: Signal<bool>,
) {
    if stream.peek().as_ref() == projection.as_ref() {
        return;
    }
    let previous_sequence = stream
        .peek()
        .as_ref()
        .and_then(|current| current.last_evidence_sequence);
    let next_sequence = projection
        .as_ref()
        .and_then(|current| current.last_evidence_sequence);
    let received_new_text = next_sequence
        .is_some_and(|sequence| previous_sequence.is_none_or(|previous| sequence > previous));
    stream.set(projection);
    if *follow_latest.peek() {
        scroll_mission_thread_to_latest();
    } else if received_new_text {
        has_unseen.set(true);
    }
}

fn scroll_mission_thread_to_latest() {
    let _ = dioxus::document::eval(
        "requestAnimationFrame(() => { const thread = document.getElementById('persisted-mission-thread'); if (!thread) return; const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches; thread.scrollTo({ top: thread.scrollHeight, behavior: reduced ? 'auto' : 'smooth' }); });",
    );
}

#[allow(clippy::too_many_arguments)]
fn begin_runtime_text_stream_monitor(
    model: Signal<DesktopUiModel>,
    project_id: ProjectId,
    mission_id: MissionId,
    mut stream: Signal<Option<DesktopRuntimeTextStreamProjection>>,
    mut stream_error: Signal<Option<UiFailure>>,
    follow_latest: Signal<bool>,
    has_unseen: Signal<bool>,
    submitting: Signal<bool>,
    retrying: Signal<bool>,
) {
    spawn(async move {
        loop {
            let query_project_id = project_id.clone();
            let query_mission_id = mission_id.clone();
            let result = tokio::task::spawn_blocking(move || {
                DesktopDataPlane::discover().and_then(|plane| {
                    plane.runtime_text_stream_os(&query_project_id, &query_mission_id, Utc::now())
                })
            })
            .await;
            if !desktop_scope_is_selected(model, &project_id, &mission_id) {
                break;
            }
            match result {
                Ok(Ok(projection)) => {
                    stream_error.set(None);
                    update_runtime_text_stream(projection, stream, follow_latest, has_unseen);
                }
                Ok(Err(error)) => {
                    stream.set(None);
                    stream_error.set(Some(UiFailure::from_error(&error)));
                    break;
                }
                Err(_) => {
                    stream.set(None);
                    stream_error.set(Some(UiFailure {
                        code: "RUNTIME_STREAM_QUERY_FAILED".into(),
                        message: "持久 Runtime 正文查询异常结束；正文保持隐藏，Mission 与 Runtime ledger 未改变。".into(),
                    }));
                    break;
                }
            }
            if !*submitting.read() && !*retrying.read() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });
}

fn runtime_stream_paragraphs(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    text.split("\n\n").collect()
}

fn runtime_stream_matches_message(
    stream: &DesktopRuntimeTextStreamProjection,
    role: MissionConversationRole,
    kind: MissionConversationMessageKind,
    body: &str,
) -> bool {
    stream.turn_status.is_terminal()
        && role == MissionConversationRole::Assistant
        && kind == MissionConversationMessageKind::RuntimeDraft
        && stream.items.len() == 1
        && stream.items[0].text == body
}

fn request_desktop_runtime_stop(
    control: Option<DesktopRuntimeCancellation>,
    mut stop_requested: Signal<bool>,
    mut progress: Signal<Vec<DesktopRuntimeProgressEvent>>,
    visual_streaming_fixture: bool,
) {
    let Some(control) = control else {
        return;
    };
    control.request();
    stop_requested.set(true);
    if visual_streaming_fixture {
        let mut projection = progress.write();
        if projection
            .iter()
            .any(|event| event.phase == DesktopRuntimeProgressPhase::StopRequested)
        {
            return;
        }
        let sequence = projection
            .last()
            .map_or(1, |event| event.sequence.saturating_add(1));
        projection.push(DesktopRuntimeProgressEvent {
            sequence,
            phase: DesktopRuntimeProgressPhase::StopRequested,
        });
    }
}

const fn desktop_runtime_progress_label(phase: DesktopRuntimeProgressPhase) -> &'static str {
    match phase {
        DesktopRuntimeProgressPhase::Preparing => "正在准备加密 Context 与 Runtime authority",
        DesktopRuntimeProgressPhase::Dispatched => "exact Runtime turn 已派发",
        DesktopRuntimeProgressPhase::TurnStarted => "Runtime 已确认开始",
        DesktopRuntimeProgressPhase::ItemStarted => "正在处理下一项 Runtime 工作",
        DesktopRuntimeProgressPhase::ItemCompleted => "Runtime 工作项已完成",
        DesktopRuntimeProgressPhase::LocalActionDeclined => "本地写入请求已按默认策略拒绝",
        DesktopRuntimeProgressPhase::StopRequested => "停止请求已交给协调器",
        DesktopRuntimeProgressPhase::InterruptSent => "fenced interrupt 已发送",
        DesktopRuntimeProgressPhase::Completed => "Runtime turn 已完成，正在采纳最终产物",
        DesktopRuntimeProgressPhase::Interrupted => "Runtime 已确认中断",
        DesktopRuntimeProgressPhase::Failed => "Runtime 已返回失败终态",
        DesktopRuntimeProgressPhase::Uncertain => "Runtime 结果不确定，等待 reconcile",
    }
}

const fn desktop_runtime_progress_display_label(
    phase: DesktopRuntimeProgressPhase,
    visual_streaming_fixture: bool,
) -> &'static str {
    if visual_streaming_fixture && matches!(phase, DesktopRuntimeProgressPhase::StopRequested) {
        "VISUAL_FIXTURE · Stop 控件状态已触发"
    } else {
        desktop_runtime_progress_label(phase)
    }
}

const fn desktop_runtime_progress_class(phase: DesktopRuntimeProgressPhase) -> &'static str {
    match phase {
        DesktopRuntimeProgressPhase::Completed | DesktopRuntimeProgressPhase::Interrupted => {
            "terminal"
        }
        DesktopRuntimeProgressPhase::Failed | DesktopRuntimeProgressPhase::Uncertain => "danger",
        DesktopRuntimeProgressPhase::StopRequested
        | DesktopRuntimeProgressPhase::InterruptSent
        | DesktopRuntimeProgressPhase::LocalActionDeclined => "attention",
        DesktopRuntimeProgressPhase::Preparing
        | DesktopRuntimeProgressPhase::Dispatched
        | DesktopRuntimeProgressPhase::TurnStarted
        | DesktopRuntimeProgressPhase::ItemStarted
        | DesktopRuntimeProgressPhase::ItemCompleted => "active",
    }
}

fn initial_surface() -> Surface {
    #[cfg(feature = "visual-fixtures")]
    if let Some(surface) = visual_fixture::initial_surface() {
        return surface;
    }
    Surface::Orchestrator
}

fn app_shortcut(key: &Key, modifiers: Modifiers) -> Option<AppShortcut> {
    if *key == Key::Escape {
        return Some(AppShortcut::DismissOverlays);
    }
    if !modifiers.intersects(Modifiers::META | Modifiers::CONTROL) {
        return None;
    }
    let Key::Character(character) = key else {
        return None;
    };
    if character.eq_ignore_ascii_case("p") {
        Some(AppShortcut::GlobalSearch)
    } else if character.eq_ignore_ascii_case("k") {
        Some(AppShortcut::ProjectDispatcher)
    } else if character.eq_ignore_ascii_case("n") {
        Some(AppShortcut::NewTask)
    } else if character == "," {
        Some(AppShortcut::Settings)
    } else {
        None
    }
}

fn composer_should_submit(key: &Key, modifiers: Modifiers, is_composing: bool) -> bool {
    *key == Key::Enter && !modifiers.contains(Modifiers::SHIFT) && !is_composing
}

fn cycle_dialog_focus(selector: &str, reverse: bool) {
    let direction = if reverse { "-1" } else { "1" };
    let script = format!(
        r#"
        (() => {{
          const root = document.querySelector({selector:?});
          if (!root) return;
          const nodes = [...root.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')];
          if (!nodes.length) return;
          const current = nodes.indexOf(document.activeElement);
          const next = current < 0
            ? ({direction} < 0 ? nodes.length - 1 : 0)
            : (current + {direction} + nodes.length) % nodes.length;
          nodes[next].focus();
        }})()
        "#
    );
    let _ = dioxus::document::eval(&script);
}

fn restore_ui_focus(element_id: &str) {
    let script =
        format!("requestAnimationFrame(() => document.getElementById({element_id:?})?.focus())");
    let _ = dioxus::document::eval(&script);
}

fn begin_workpad_resize(start_x: f64) {
    let script = format!(
        r"
        (() => {{
          const root = document.documentElement;
          const style = getComputedStyle(root);
          const startWidth = parseFloat(style.getPropertyValue('--chat-w')) || 500;
          const sideWidth = parseFloat(style.getPropertyValue('--side-w')) || 238;
          const maxWidth = Math.max(440, window.innerWidth - sideWidth - 360);
          const handle = document.getElementById('workpad-resize-handle');
          const updateWidth = (width) => {{
            const rounded = Math.round(width);
            root.style.setProperty('--chat-w', `${{rounded}}px`);
            handle?.setAttribute('aria-valuenow', String(rounded));
            handle?.setAttribute('aria-valuetext', `${{rounded}}px Mission 会话宽度`);
          }};
          document.body.classList.add('resizing-workpad');
          const move = (event) => {{
            const width = Math.max(440, Math.min(maxWidth, startWidth + event.clientX - {start_x}));
            updateWidth(width);
          }};
          const finish = () => {{
            document.body.classList.remove('resizing-workpad');
            window.removeEventListener('pointermove', move);
            window.removeEventListener('pointerup', finish);
            window.removeEventListener('pointercancel', finish);
          }};
          window.addEventListener('pointermove', move);
          window.addEventListener('pointerup', finish, {{ once: true }});
          window.addEventListener('pointercancel', finish, {{ once: true }});
        }})()
        "
    );
    let _ = dioxus::document::eval(&script);
}

fn nudge_workpad_width(delta: i32) {
    let script = format!(
        r"
        (() => {{
          const root = document.documentElement;
          const style = getComputedStyle(root);
          const current = parseFloat(style.getPropertyValue('--chat-w')) || 500;
          const sideWidth = parseFloat(style.getPropertyValue('--side-w')) || 238;
          const maxWidth = Math.max(440, window.innerWidth - sideWidth - 360);
          const width = Math.round(Math.max(440, Math.min(maxWidth, current + {delta})));
          root.style.setProperty('--chat-w', `${{width}}px`);
          const handle = document.getElementById('workpad-resize-handle');
          handle?.setAttribute('aria-valuenow', String(width));
          handle?.setAttribute('aria-valuetext', `${{width}}px Mission 会话宽度`);
        }})()
        "
    );
    let _ = dioxus::document::eval(&script);
}

fn set_workpad_width(width: i32) {
    let width = width.max(440);
    let script = format!(
        "document.documentElement.style.setProperty('--chat-w', '{width}px'); const handle = document.getElementById('workpad-resize-handle'); handle?.setAttribute('aria-valuenow', '{width}'); handle?.setAttribute('aria-valuetext', '{width}px Mission 会话宽度')"
    );
    let _ = dioxus::document::eval(&script);
}

fn dispatcher_stage_dot(stage: &MissionStage) -> &'static str {
    match stage {
        MissionStage::Running => "live",
        MissionStage::WaitingUser | MissionStage::WaitingApproval => "attention",
        MissionStage::Scheduled => "scheduled",
        _ if stage.is_terminal() => "terminal",
        _ => "",
    }
}

fn dispatcher_mission_detail(mission: &MissionProjection) -> String {
    let checkpoint = mission
        .current_checkpoint_id
        .as_deref()
        .unwrap_or("unbound");
    format!(
        "{} · {} · cycle {}",
        mission_stage_label(&mission.stage),
        checkpoint,
        mission.cycle
    )
}

fn project_initials(name: &str) -> String {
    let initials = name
        .split_whitespace()
        .filter_map(|word| word.chars().next())
        .take(3)
        .collect::<String>();
    if initials.chars().count() > 1 {
        return initials;
    }
    name.chars().take(2).collect()
}

fn settings_panel_label(panel: &str) -> &'static str {
    match panel {
        "storage" => "存储与同步",
        "privacy" => "隐私与数据",
        "notifications" => "通知",
        "connections" => "连接与凭据",
        "account" => "账户与团队",
        "usage" => "用量",
        _ => "设置",
    }
}

fn status_label(model: &DesktopUiModel) -> String {
    if let Some(notice) = &model.notice {
        return format!("{} · 已停止", notice.code);
    }
    if let Some(access) = model.current_context_access() {
        match &access.status {
            ProjectContextAccessStatus::NotProvisioned => return "等待项目加密配置".into(),
            ProjectContextAccessStatus::RotationRequired => return "等待 Keyring 轮换".into(),
            ProjectContextAccessStatus::RecoveryRequired => return "需要设备恢复".into(),
            ProjectContextAccessStatus::BlockedEnvironment => {
                return "BLOCKED_ENV · Context 已停止".into();
            }
            ProjectContextAccessStatus::IntegrityError => {
                return "INTEGRITY_ERROR · Context 已停止".into();
            }
            ProjectContextAccessStatus::Ready { .. }
            | ProjectContextAccessStatus::Degraded { .. } => {}
        }
    }
    if let Some(activity) = model.current_runtime_activity() {
        match activity.process_claim_status {
            Some(RuntimeProcessClaimStatus::Blocked) => {
                return "Runtime process BLOCKED · 禁止重复启动".into();
            }
            Some(
                status @ (RuntimeProcessClaimStatus::Prepared | RuntimeProcessClaimStatus::Spawned),
            ) => {
                return format!(
                    "Runtime process {} · 独占执行权",
                    runtime_process_claim_status_label(status)
                );
            }
            Some(RuntimeProcessClaimStatus::Terminated | RuntimeProcessClaimStatus::Exited)
            | None => {}
        }
        if activity.requires_reconciliation {
            return "Runtime UNCERTAIN · 禁止自动重放".into();
        }
        if let Some(status) = activity.turn_status {
            return format!(
                "Runtime {} · Mission 未自完成",
                runtime_turn_status_label(status)
            );
        }
        if activity.recovery_status == Some(RuntimeRecoveryStatus::Failed) {
            return "Runtime recovery FAILED · 等待安全重建".into();
        }
    }
    match &model.backend {
        DesktopBackendState::Uninitialized(_) => "等待显式本地初始化".into(),
        DesktopBackendState::Failed(failure) => format!("{} · 已停止", failure.code),
        DesktopBackendState::Ready(_) => model.current_mission().map_or_else(
            || {
                if model.current_project().is_some() {
                    "等待持久 Mission".into()
                } else {
                    "没有宣发项目".into()
                }
            },
            |mission| mission_stage_label(&mission.stage).into(),
        ),
    }
}

fn mission_stage_label(stage: &MissionStage) -> &'static str {
    match stage {
        MissionStage::Draft => "草稿",
        MissionStage::Ready => "已就绪",
        MissionStage::Running => "运行中",
        MissionStage::Blocked => "已阻塞",
        MissionStage::WaitingUser => "等待用户",
        MissionStage::WaitingApproval => "等待审批",
        MissionStage::Verifying => "核验中",
        MissionStage::CycleReviewed => "周期已复盘",
        MissionStage::Scheduled => "已排期",
        MissionStage::Completed => "已完成",
        MissionStage::Partial => "部分完成",
        MissionStage::ExpectedRefusal => "预期拒绝",
        MissionStage::Failed => "失败",
        MissionStage::Cancelled => "已取消",
    }
}

fn mission_schedule_status_label(status: MissionScheduleStatus) -> &'static str {
    match status {
        MissionScheduleStatus::Pending => "PENDING",
        MissionScheduleStatus::Leased => "LEASED",
        MissionScheduleStatus::Triggered => "TRIGGERED",
        MissionScheduleStatus::Cancelled => "CANCELLED",
        MissionScheduleStatus::Expired => "EXPIRED",
        MissionScheduleStatus::DeadLetter => "DEAD_LETTER",
    }
}

fn cadence_trigger_label(trigger: CadenceTriggerKind) -> &'static str {
    match trigger {
        CadenceTriggerKind::Interval => "INTERVAL",
        CadenceTriggerKind::EventDriven => "EVENT_DRIVEN",
        CadenceTriggerKind::IntervalOrEvent => "INTERVAL_OR_EVENT",
    }
}

fn operating_mode_from_catalog_name(value: &str) -> Option<OperatingMode> {
    match value {
        "build_once" => Some(OperatingMode::BuildOnce),
        "continuous_operator" => Some(OperatingMode::ContinuousOperator),
        "campaign" => Some(OperatingMode::Campaign),
        "continuous_relationship" => Some(OperatingMode::ContinuousRelationship),
        "one_off_decision" => Some(OperatingMode::OneOffDecision),
        _ => None,
    }
}

fn operating_mode_label(value: &str) -> &'static str {
    match value {
        "build_once" => "Build once",
        "continuous_operator" => "Continuous operator",
        "campaign" => "Campaign",
        "continuous_relationship" => "Continuous relationship",
        "one_off_decision" => "One-off decision",
        _ => "UNKNOWN MODE",
    }
}

fn valid_currency_shape(value: &str) -> bool {
    let value = value.trim();
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn catalog_kpi_contracts(
    manifest_id: &str,
    metric_id: &str,
    baseline: &str,
    target: &str,
    unit: &str,
    direction: &str,
) -> Option<BTreeMap<String, KpiContract>> {
    if manifest_id == "VM-11" {
        return Some(BTreeMap::new());
    }
    let metric_id = metric_id.trim();
    let unit = unit.trim();
    if metric_id.is_empty() || unit.is_empty() {
        return None;
    }
    let baseline = if baseline.trim().is_empty() {
        None
    } else {
        Some(baseline.trim().parse::<Decimal>().ok()?)
    };
    let target = target.trim().parse::<Decimal>().ok()?;
    let direction = match direction {
        "at_least" => KpiDirection::AtLeast,
        "at_most" => KpiDirection::AtMost,
        _ => return None,
    };
    Some(BTreeMap::from([(
        metric_id.into(),
        KpiContract {
            baseline,
            target,
            unit: unit.into(),
            direction,
        },
    )]))
}

fn mission_checkpoint_status_label(status: MissionCheckpointStatus) -> &'static str {
    match status {
        MissionCheckpointStatus::Pending => "PENDING",
        MissionCheckpointStatus::Ready => "READY",
        MissionCheckpointStatus::Running => "RUNNING",
        MissionCheckpointStatus::Blocked => "BLOCKED",
        MissionCheckpointStatus::WaitingUser => "WAITING_USER",
        MissionCheckpointStatus::WaitingApproval => "WAITING_APPROVAL",
        MissionCheckpointStatus::Verifying => "VERIFYING",
        MissionCheckpointStatus::Completed => "COMPLETED",
        MissionCheckpointStatus::Skipped => "SKIPPED",
    }
}

fn mission_checkpoint_executor_label(executor: MissionCheckpointExecutor) -> &'static str {
    match executor {
        MissionCheckpointExecutor::Application => "APPLICATION",
        MissionCheckpointExecutor::Runtime => "RUNTIME",
        MissionCheckpointExecutor::EffectBroker => "EFFECT_BROKER",
        MissionCheckpointExecutor::Human => "HUMAN",
    }
}

fn mission_conversation_role_label(role: MissionConversationRole) -> &'static str {
    match role {
        MissionConversationRole::User => "用户",
        MissionConversationRole::Assistant => "Hartevo",
        MissionConversationRole::System => "系统",
    }
}

fn mission_conversation_kind_label(kind: MissionConversationMessageKind) -> &'static str {
    match kind {
        MissionConversationMessageKind::Goal => "GOAL",
        MissionConversationMessageKind::Steering => "STEERING",
        MissionConversationMessageKind::Correction => "CORRECTION",
        MissionConversationMessageKind::Clarification => "CLARIFICATION",
        MissionConversationMessageKind::CheckpointConfirmation => "CHECKPOINT_CONFIRMATION",
        MissionConversationMessageKind::RuntimeDraft => "RUNTIME_DRAFT",
        MissionConversationMessageKind::SystemNotice => "SYSTEM_NOTICE",
    }
}

const fn outcome_review_gate_label(status: OutcomeReviewGateStatus) -> &'static str {
    match status {
        OutcomeReviewGateStatus::Satisfied => "SATISFIED",
        OutcomeReviewGateStatus::Blocked => "BLOCKED",
    }
}

const fn outcome_decision_label(action: &OutcomeDecision) -> &'static str {
    match action {
        OutcomeDecision::Continue => "Continue",
        OutcomeDecision::Stop => "Stop",
        OutcomeDecision::Scale => "Scale",
        OutcomeDecision::Test => "Test",
    }
}

const fn outcome_decision_gate_label(status: OutcomeReviewDecisionGateStatus) -> &'static str {
    match status {
        OutcomeReviewDecisionGateStatus::Available => "可选择",
        OutcomeReviewDecisionGateStatus::BlockedLoopPolicy => "当前合同禁止隐式循环",
        OutcomeReviewDecisionGateStatus::BlockedScaleEvidence => "Scale 证据不足",
    }
}

const fn outcome_review_caveat_label(caveat: OutcomeReviewCaveat) -> &'static str {
    match caveat {
        OutcomeReviewCaveat::KpiTargetGap => "存在 KPI 目标缺口",
        OutcomeReviewCaveat::UnattributedOrders => "存在未归因订单",
        OutcomeReviewCaveat::OutstandingSettlement => "存在未结算义务",
        OutcomeReviewCaveat::PendingEffect => "存在 Pending Effect",
        OutcomeReviewCaveat::UnresolvedEffectCost => "存在未解析 Effect 成本",
        OutcomeReviewCaveat::BudgetExceeded => "预算已超支",
        OutcomeReviewCaveat::CrossCurrencyCostWithoutFx => "跨币种成本缺少已验证 FX",
        OutcomeReviewCaveat::ImplicitLoopForbidden => "当前 Operating Contract 禁止隐式循环",
    }
}

fn money_label(money: &Money) -> String {
    format!("{} {} minor", money.amount_minor, money.currency)
}

fn runtime_availability_label(status: DesktopRuntimeAvailabilityStatus) -> &'static str {
    match status {
        DesktopRuntimeAvailabilityStatus::NotConfigured => "NOT_CONFIGURED",
        DesktopRuntimeAvailabilityStatus::ConfigurationRequired => "CONFIGURATION_REQUIRED",
        DesktopRuntimeAvailabilityStatus::EvidenceMissing => "EVIDENCE_MISSING",
        DesktopRuntimeAvailabilityStatus::ReadyDevelopment => "DEV_READY",
        DesktopRuntimeAvailabilityStatus::ReadyDistribution => "DISTRIBUTION_READY",
        DesktopRuntimeAvailabilityStatus::BlockedEnvironment => "BLOCKED_ENV",
        DesktopRuntimeAvailabilityStatus::IntegrityError => "INTEGRITY_ERROR",
        DesktopRuntimeAvailabilityStatus::UnsupportedHost => "UNSUPPORTED_HOST",
    }
}

fn runtime_recovery_status_label(status: RuntimeRecoveryStatus) -> &'static str {
    match status {
        RuntimeRecoveryStatus::Prepared => "PREPARED",
        RuntimeRecoveryStatus::Spawned => "SPAWNED",
        RuntimeRecoveryStatus::Healthy => "HEALTHY",
        RuntimeRecoveryStatus::ThreadBound => "THREAD_BOUND",
        RuntimeRecoveryStatus::Attached => "ATTACHED",
        RuntimeRecoveryStatus::Failed => "FAILED",
    }
}

fn runtime_process_claim_status_label(status: RuntimeProcessClaimStatus) -> &'static str {
    match status {
        RuntimeProcessClaimStatus::Prepared => "PREPARED",
        RuntimeProcessClaimStatus::Spawned => "SPAWNED",
        RuntimeProcessClaimStatus::Terminated => "TERMINATED",
        RuntimeProcessClaimStatus::Exited => "EXITED",
        RuntimeProcessClaimStatus::Blocked => "BLOCKED",
    }
}

fn runtime_turn_status_label(status: RuntimeTurnStatus) -> &'static str {
    match status {
        RuntimeTurnStatus::Prepared => "PREPARED",
        RuntimeTurnStatus::Dispatching => "DISPATCHING",
        RuntimeTurnStatus::Running => "RUNNING",
        RuntimeTurnStatus::WaitingLocalApproval => "LOCAL_APPROVAL_BLOCKED",
        RuntimeTurnStatus::ApprovalResponding => "LOCAL_APPROVAL_RESPONDING",
        RuntimeTurnStatus::InterruptRequested => "INTERRUPTING",
        RuntimeTurnStatus::Completed => "COMPLETED",
        RuntimeTurnStatus::Interrupted => "INTERRUPTED",
        RuntimeTurnStatus::Failed => "FAILED",
        RuntimeTurnStatus::Uncertain => "UNCERTAIN",
    }
}

fn runtime_activity_note(activity: &MissionRuntimeProjection, work_product_count: usize) -> String {
    match activity.process_claim_status {
        Some(RuntimeProcessClaimStatus::Blocked) => {
            return "PROCESS_CLEANUP_BLOCKED：无法安全确认或终止此前认领的 OS 进程；不会按 PID 猜测清理，也不会启动第二个 Runtime。".into();
        }
        Some(
            status @ (RuntimeProcessClaimStatus::Prepared | RuntimeProcessClaimStatus::Spawned),
        ) => {
            return format!(
                "PROCESS_{}：存在精确 Runtime 进程认领；终止或启动恢复 reconcile 前禁止重复启动，Mission 仍未完成。",
                runtime_process_claim_status_label(status)
            );
        }
        Some(RuntimeProcessClaimStatus::Terminated | RuntimeProcessClaimStatus::Exited) | None => {}
    }
    if activity.requires_reconciliation {
        return "UNCERTAIN：Runtime 请求是否产生结果尚不确定；禁止自动重放，必须先 reconcile。Mission 仍未完成。".into();
    }
    if activity.recovery_status == Some(RuntimeRecoveryStatus::Failed)
        && activity.turn_status.is_none()
    {
        return "RUNTIME_RECOVERY_FAILED：进程恢复尝试已耗尽；当前 Worker 不会伪装为已连接，需安全重建执行 generation。".into();
    }
    match activity.turn_status {
        Some(RuntimeTurnStatus::Completed) if work_product_count > 0 => {
            "DRAFT_READY：Runtime Turn 已完成并形成可审阅草稿；这不是 Provider Verification，也没有把 Mission 自动标为完成。".into()
        }
        Some(RuntimeTurnStatus::Completed) => {
            "COMPLETED_WITHOUT_ARTIFACT：Runtime Turn 已结束，但没有可采纳产物；Mission 保持 Running。".into()
        }
        Some(RuntimeTurnStatus::Interrupted) => {
            "INTERRUPTED：本地 Turn 已被中断；没有外部业务完成声明。".into()
        }
        Some(RuntimeTurnStatus::Failed) => {
            "FAILED：本地 Turn 已确定失败；没有生成虚假产物或外部 Effect 成功声明。".into()
        }
        Some(status) => format!(
            "Runtime Turn {}；本地写入请求默认拒绝，Mission 与业务终态仍由 Domain/Oracle 决定。",
            runtime_turn_status_label(status)
        ),
        None if activity.recovery_status.is_some() => {
            "Runtime recovery 已持久化，但 Turn 尚未派发；没有 Work Product 或完成声明。".into()
        }
        None => "NOT_STARTED：尚无 Runtime ledger；没有 Work Product 或完成声明。".into(),
    }
}

fn mission_runtime_retry_needed(
    mission_stage: &MissionStage,
    activity: Option<&MissionRuntimeProjection>,
) -> bool {
    if mission_stage != &MissionStage::Running {
        return false;
    }
    let Some(activity) = activity else {
        return false;
    };
    if activity.requires_reconciliation {
        return false;
    }
    match activity.turn_status {
        Some(status) if status.is_active() || status == RuntimeTurnStatus::Completed => false,
        Some(RuntimeTurnStatus::Failed | RuntimeTurnStatus::Interrupted) => true,
        Some(_) => false,
        None => matches!(
            activity.recovery_status,
            Some(RuntimeRecoveryStatus::Prepared | RuntimeRecoveryStatus::Failed)
        ),
    }
}

fn project_storage_label(project: &DesktopProjectProjection) -> &'static str {
    match project.storage_mode {
        StorageMode::LocalExisting => "本地现有目录",
        StorageMode::LocalNew => "本地新目录",
        StorageMode::LocalEncryptedSync => "本地 E2EE 同步",
        StorageMode::Cloud => "Cloud metadata",
    }
}

fn encryption_short_label(encryption: &ProjectEncryptionReadiness) -> &'static str {
    match encryption {
        ProjectEncryptionReadiness::NotProvisioned => "加密未配置",
        ProjectEncryptionReadiness::Ready { .. } => "Keyring 就绪",
        ProjectEncryptionReadiness::RotationRequired { .. } => "等待轮换",
    }
}

fn encryption_mode_label(mode: &ProjectEncryptionMode) -> &'static str {
    match mode {
        ProjectEncryptionMode::PersonalE2ee => "Personal E2EE Keyring 就绪",
        ProjectEncryptionMode::TeamEnvelope => "Team Envelope Keyring 就绪",
    }
}

const fn evidence_level_label(level: EvidenceLevel) -> &'static str {
    match level {
        EvidenceLevel::E0 => "E0",
        EvidenceLevel::E1 => "E1",
        EvidenceLevel::E2 => "E2",
        EvidenceLevel::E3 => "E3",
        EvidenceLevel::E4 => "E4",
        EvidenceLevel::E5 => "E5",
    }
}

const fn mission_evidence_status_label(status: MissionEvidenceStatus) -> &'static str {
    match status {
        MissionEvidenceStatus::NotImplemented => "NOT_IMPLEMENTED",
        MissionEvidenceStatus::BlockedEnv => "BLOCKED_ENV",
        MissionEvidenceStatus::Fail => "FAIL",
        MissionEvidenceStatus::Partial => "PARTIAL",
        MissionEvidenceStatus::ExpectedRefusal => "EXPECTED_REFUSAL",
        MissionEvidenceStatus::Pass => "PASS",
    }
}

fn short_digest(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_errors_never_render_sensitive_paths_or_low_level_database_details() {
        let failure = UiFailure::from_error(&DesktopDataError::InvalidDataRoot(
            "/Users/private/secret-project".into(),
        ));
        assert_eq!(failure.code, "BLOCKED_ENV");
        assert!(!failure.message.contains("/Users/private"));
        let missing = UiFailure::from_error(&DesktopDataError::MissingDatabaseKey);
        assert!(missing.message.contains("不会生成新密钥"));
        let blocked_process = UiFailure::from_error(&DesktopDataError::Application(
            ApplicationError::RuntimeProcessCleanupBlocked { claim_count: 1 },
        ));
        assert_eq!(blocked_process.code, "BLOCKED_ENV");
        assert!(blocked_process.message.contains("不会按 PID 猜测清理"));
        let invalid_confirmation =
            UiFailure::from_error(&DesktopDataError::InvalidHumanCheckpointConfirmation);
        assert_eq!(invalid_confirmation.code, "WAITING_USER");
        assert!(!invalid_confirmation.message.contains("SQL"));
        assert!(invalid_confirmation.message.contains("未写入部分状态"));
    }

    #[test]
    fn catalog_operating_mode_and_money_inputs_are_explicit_and_lossless() {
        assert_eq!(
            operating_mode_from_catalog_name("build_once"),
            Some(OperatingMode::BuildOnce)
        );
        assert_eq!(
            operating_mode_from_catalog_name("continuous_operator"),
            Some(OperatingMode::ContinuousOperator)
        );
        assert_eq!(
            operating_mode_from_catalog_name("campaign"),
            Some(OperatingMode::Campaign)
        );
        assert_eq!(
            operating_mode_from_catalog_name("continuous_relationship"),
            Some(OperatingMode::ContinuousRelationship)
        );
        assert_eq!(
            operating_mode_from_catalog_name("one_off_decision"),
            Some(OperatingMode::OneOffDecision)
        );
        assert_eq!(operating_mode_from_catalog_name(""), None);
        assert_eq!(operating_mode_from_catalog_name("build-once"), None);
        assert!(valid_currency_shape("EUR"));
        assert!(!valid_currency_shape("eur"));
        assert!(!valid_currency_shape("EU"));
        assert_eq!("9007199254740993".parse::<i64>(), Ok(9_007_199_254_740_993));
        let kpis = catalog_kpi_contracts(
            "VM-07",
            "lead_qualified_count",
            "0",
            "1",
            "count",
            "at_least",
        )
        .expect("explicit KPI contract");
        assert_eq!(
            kpis.get("lead_qualified_count"),
            Some(&KpiContract {
                baseline: Some(Decimal::ZERO),
                target: Decimal::ONE,
                unit: "count".into(),
                direction: KpiDirection::AtLeast,
            })
        );
        assert!(catalog_kpi_contracts("VM-07", "", "0", "1", "count", "at_least").is_none());
        assert!(
            catalog_kpi_contracts(
                "VM-07",
                "lead_qualified_count",
                "0",
                "not-a-decimal",
                "count",
                "at_least",
            )
            .is_none()
        );
        assert_eq!(
            catalog_kpi_contracts("VM-11", "", "", "", "", ""),
            Some(BTreeMap::new())
        );
    }

    #[test]
    fn prototype_keyboard_contract_maps_without_expanding_authority() {
        assert_eq!(
            app_shortcut(&Key::Character("p".into()), Modifiers::META),
            Some(AppShortcut::GlobalSearch)
        );
        assert_eq!(
            app_shortcut(&Key::Character("k".into()), Modifiers::META),
            Some(AppShortcut::ProjectDispatcher)
        );
        assert_eq!(
            app_shortcut(&Key::Character("N".into()), Modifiers::CONTROL),
            Some(AppShortcut::NewTask)
        );
        assert_eq!(
            app_shortcut(&Key::Character(",".into()), Modifiers::META),
            Some(AppShortcut::Settings)
        );
        assert_eq!(
            app_shortcut(&Key::Escape, Modifiers::empty()),
            Some(AppShortcut::DismissOverlays)
        );
        assert_eq!(
            app_shortcut(&Key::Character("k".into()), Modifiers::empty()),
            None
        );
        assert_eq!(
            ActiveOverlay::GlobalSearch.toggle(ActiveOverlay::Notifications),
            ActiveOverlay::Notifications
        );
        assert_eq!(
            ActiveOverlay::Notifications.toggle(ActiveOverlay::Notifications),
            ActiveOverlay::None
        );
        assert!(composer_should_submit(
            &Key::Enter,
            Modifiers::empty(),
            false
        ));
        assert!(!composer_should_submit(
            &Key::Enter,
            Modifiers::SHIFT,
            false
        ));
        assert!(!composer_should_submit(
            &Key::Enter,
            Modifiers::empty(),
            true
        ));
        assert!(!composer_should_submit(
            &Key::Character("a".into()),
            Modifiers::empty(),
            false
        ));
        assert_eq!(
            desktop_runtime_progress_display_label(
                DesktopRuntimeProgressPhase::StopRequested,
                true,
            ),
            "VISUAL_FIXTURE · Stop 控件状态已触发"
        );
        assert_eq!(
            desktop_runtime_progress_display_label(
                DesktopRuntimeProgressPhase::StopRequested,
                false,
            ),
            "停止请求已交给协调器"
        );
    }

    #[test]
    fn prototype_token_sheet_keeps_source_colors_breakpoints_and_accessibility() {
        let css = include_str!("../assets/prototype.css");
        for token in [
            "--ink: #202124",
            "--line: #e6e6e8",
            "--sidebar: #f6f6f7",
            "--gold: #c8932f",
            "--green: #237a50",
            "--red: #b5403a",
            "--side-w: 260px",
            "--chat-w: 550px",
        ] {
            assert!(css.contains(token), "missing prototype token {token}");
        }
        for contract in [
            "@media (max-width: 1390px)",
            "@media (max-width: 1120px)",
            "@media (max-width: 900px)",
            "@media (max-width: 680px)",
            "@media (prefers-reduced-motion: reduce)",
            ":focus-visible",
        ] {
            assert!(css.contains(contract), "missing UI contract {contract}");
        }
        assert!(!css.contains("linear-gradient"));
        assert!(!css.contains("radial-gradient"));
    }

    #[test]
    fn chat_first_interaction_contract_is_structural_and_truthful() {
        let source = include_str!("lib.rs");
        let css = include_str!("../assets/prototype.css");
        for contract in [
            "重播流式轨迹",
            "停止重播",
            "回到最新",
            "上下文压缩记录结构",
            "Mission Checkpoints",
            "Runtime Profile",
            "工作产物结构样例",
            "No token · no account identity · no scopes",
            "mission-composer-stop",
            "event.data.is_composing()",
            "continue_mission_and_run_cancellable_os",
        ] {
            assert!(
                source.contains(contract),
                "missing interaction contract {contract}"
            );
        }
        for selector in [
            ".fixture-stream-caret",
            ".mission-progress-popover",
            ".prototype-composer-attachments",
            ".composer-tool-menu",
            ".runtime-profile-menu",
            ".composer-zone:not(.is-expanded)",
            ".stream-stop-button",
            ".prototype-detail-drawer",
            ".prototype-connection-modal",
            ".search-result.active",
        ] {
            assert!(
                css.contains(selector),
                "missing interaction selector {selector}"
            );
        }
        assert!(css.contains(".prototype-thread .assistant-copy { font-size: 12.5px"));
        assert!(source.contains("0 EffectIntent"));
        assert!(source.contains("0 Receipt · 0 Verification"));
    }

    #[test]
    fn persisted_runtime_stream_contract_is_contextual_stable_and_accessible() {
        let source = include_str!("lib.rs");
        let css = include_str!("../assets/prototype.css");
        for contract in [
            "runtime_text_stream_os",
            "persisted-mission-thread",
            "aria_live: \"polite\"",
            "aria_atomic: \"false\"",
            "从 SQLCipher 重放",
            "begin_runtime_text_stream_monitor",
        ] {
            assert!(
                source.contains(contract),
                "missing persisted stream contract {contract}"
            );
        }
        for selector in [
            ".persisted-mission-thread",
            ".persisted-user-message",
            ".persisted-assistant-turn",
            ".runtime-stream-caret",
            ".runtime-stream-receipt",
            ".mission-follow-latest",
        ] {
            assert!(
                css.contains(selector),
                "missing persisted stream selector {selector}"
            );
        }
        assert!(css.contains("@media (prefers-reduced-motion: reduce)"));
    }

    #[test]
    fn persisted_mission_process_density_is_projection_bound_and_interactive() {
        let source = include_str!("lib.rs");
        let css = include_str!("../assets/prototype.css");
        for contract in [
            "PersistedMissionProcessDensity",
            "另有 {undisclosed_checkpoint_count} 个 Checkpoint 尚未展开",
            "当前 Projection 只公开数量；不会编造名称、顺序或执行记录。",
            "current_checkpoint_capability_id",
            "current_checkpoint_oracle_ids",
            "current_checkpoint_completion_policy",
            "current_checkpoint_application_handler_status",
            "在任务工作台打开 {product.title}",
            "work_product_status_label(&product.adoption_status)",
            "Mission 下一步边界",
        ] {
            assert!(
                source.contains(contract),
                "missing persisted process contract {contract}"
            );
        }
        for selector in [
            ".persisted-process-density",
            ".persisted-process-row",
            ".persisted-capability-stack",
            ".persisted-capability-grid",
            ".persisted-artifact-attachment",
            ".persisted-next-boundary",
        ] {
            assert!(
                css.contains(selector),
                "missing persisted process selector {selector}"
            );
        }
        assert!(css.contains("@media (max-width: 680px)"));
        assert!(css.contains(".persisted-process-row.active > i > span { animation: none"));
    }

    #[test]
    fn mission_process_counts_fail_closed() {
        assert_eq!(
            mission_undisclosed_checkpoint_count(
                9,
                3,
                true,
                Some(MissionCheckpointStatus::Running),
            ),
            5
        );
        assert_eq!(
            mission_undisclosed_checkpoint_count(
                9,
                3,
                true,
                Some(MissionCheckpointStatus::Completed),
            ),
            6
        );
        assert_eq!(
            mission_undisclosed_checkpoint_count(
                9,
                3,
                true,
                Some(MissionCheckpointStatus::Skipped),
            ),
            5
        );
        assert_eq!(mission_undisclosed_checkpoint_count(9, 3, false, None), 6);
        assert_eq!(mission_undisclosed_checkpoint_count(3, 9, false, None), 0);
    }

    #[test]
    fn mission_next_boundary_uses_persisted_authority() {
        assert_eq!(
            mission_next_boundary_kind(
                &MissionStage::Running,
                Some(MissionCheckpointStatus::Running),
                Some(ApplicationCheckpointHandlerStatus::CatalogRevisionMismatch),
            ),
            MissionNextBoundaryKind::CatalogRevisionMismatch
        );
        assert_eq!(
            mission_next_boundary_kind(
                &MissionStage::Running,
                Some(MissionCheckpointStatus::Running),
                Some(ApplicationCheckpointHandlerStatus::NotImplemented),
            ),
            MissionNextBoundaryKind::ApplicationNotImplemented
        );
        assert_eq!(
            mission_next_boundary_kind(
                &MissionStage::Running,
                Some(MissionCheckpointStatus::Running),
                Some(ApplicationCheckpointHandlerStatus::Implemented),
            ),
            MissionNextBoundaryKind::Running
        );

        // A pending Effect may belong to another Checkpoint. Its count stays
        // display-only and is intentionally outside the boundary helper's typed
        // inputs, so these contradictory observations cannot overwrite state.
        for (stage, checkpoint_status, pending_approval_count, expected) in [
            (
                MissionStage::Blocked,
                MissionCheckpointStatus::Blocked,
                2,
                MissionNextBoundaryKind::Blocked,
            ),
            (
                MissionStage::WaitingUser,
                MissionCheckpointStatus::WaitingUser,
                3,
                MissionNextBoundaryKind::WaitingUser,
            ),
        ] {
            assert!(pending_approval_count > 0);
            assert_eq!(
                mission_next_boundary_kind(
                    &stage,
                    Some(checkpoint_status),
                    Some(ApplicationCheckpointHandlerStatus::Implemented),
                ),
                expected
            );
        }
        assert_eq!(
            mission_next_boundary_kind(
                &MissionStage::Verifying,
                Some(MissionCheckpointStatus::Verifying),
                None,
            ),
            MissionNextBoundaryKind::Verifying
        );
        assert_eq!(
            mission_next_boundary_kind(
                &MissionStage::Completed,
                Some(MissionCheckpointStatus::Completed),
                None,
            ),
            MissionNextBoundaryKind::Completed
        );
        assert_eq!(
            mission_next_boundary_copy(MissionNextBoundaryKind::Completed).code,
            "COMPLETED"
        );
        assert_eq!(
            mission_next_boundary_copy(MissionNextBoundaryKind::Partial).code,
            "PARTIAL"
        );
        assert_eq!(
            mission_next_boundary_copy(MissionNextBoundaryKind::ExpectedRefusal).code,
            "EXPECTED_REFUSAL"
        );
        assert_eq!(
            mission_next_boundary_copy(MissionNextBoundaryKind::Failed).code,
            "FAILED"
        );
        assert_eq!(
            mission_next_boundary_copy(MissionNextBoundaryKind::Cancelled).code,
            "CANCELLED"
        );
        assert_eq!(
            mission_next_boundary_copy(MissionNextBoundaryKind::ApplicationNotImplemented).code,
            "NOT_IMPLEMENTED"
        );
        assert_eq!(
            mission_next_boundary_copy(MissionNextBoundaryKind::CatalogRevisionMismatch).code,
            "BLOCKED_CATALOG_REVISION"
        );
    }

    #[test]
    fn runtime_stream_paragraphs_are_append_stable_and_terminal_dedupe_is_exact() {
        assert_eq!(
            runtime_stream_paragraphs("第一段\n仍是第一段\n\n第二段"),
            vec!["第一段\n仍是第一段", "第二段"]
        );
        assert_eq!(
            runtime_stream_paragraphs("第一段\n仍是第一段\n\n第二段追加"),
            vec!["第一段\n仍是第一段", "第二段追加"]
        );
        assert!(runtime_stream_paragraphs("").is_empty());

        let now = Utc::now();
        let mut stream = DesktopRuntimeTextStreamProjection {
            project_id: ProjectId::from("project-stream-ui"),
            mission_id: MissionId::from("mission-stream-ui"),
            worker_generation: 3,
            turn_revision: 8,
            turn_status: RuntimeTurnStatus::Completed,
            last_evidence_sequence: Some(14),
            delta_count: 2,
            items: vec![data_plane::DesktopRuntimeTextItemProjection {
                item_id_digest: "item-digest".into(),
                text: "可恢复的真实正文".into(),
                delta_count: 2,
                last_stream_sequence: 2,
                cumulative_byte_count: 27,
                observed_at: now,
            }],
            updated_at: now,
        };
        assert!(runtime_stream_matches_message(
            &stream,
            MissionConversationRole::Assistant,
            MissionConversationMessageKind::RuntimeDraft,
            "可恢复的真实正文",
        ));
        assert!(!runtime_stream_matches_message(
            &stream,
            MissionConversationRole::Assistant,
            MissionConversationMessageKind::RuntimeDraft,
            "可恢复的真实正文。",
        ));
        stream.turn_status = RuntimeTurnStatus::Running;
        assert!(!runtime_stream_matches_message(
            &stream,
            MissionConversationRole::Assistant,
            MissionConversationMessageKind::RuntimeDraft,
            "可恢复的真实正文",
        ));
    }

    #[test]
    fn visual_state_contract_covers_every_required_honest_product_state() {
        assert_eq!(
            UI_STATE_CONTRACTS.map(|state| state.code),
            [
                "LOADING",
                "EMPTY",
                "OFFLINE",
                "ERROR",
                "BLOCKED",
                "WAITING_USER",
                "WAITING_APPROVAL",
                "HANDOFF",
                "SUCCESS",
                "RECOVERY",
            ]
        );
        assert!(
            UI_STATE_CONTRACTS
                .iter()
                .find(|state| state.code == "SUCCESS")
                .is_some_and(|state| state.detail.contains("Verification"))
        );
        assert!(
            UI_STATE_CONTRACTS
                .iter()
                .find(|state| state.code == "RECOVERY")
                .is_some_and(|state| state.detail.contains("uncertain"))
        );
    }

    #[test]
    fn creator_work_contract_keeps_delivery_review_rights_and_payment_in_order() {
        assert_eq!(CREATOR_WORK_STAGES.len(), 12);
        assert_eq!(CREATOR_WORK_STAGES[0], "Offer / Listing");
        assert_eq!(CREATOR_WORK_STAGES[6], "Deliverable Uploaded");
        assert_eq!(CREATOR_WORK_STAGES[7], "User Review");
        assert_eq!(CREATOR_WORK_STAGES[9], "Accepted");
        assert_eq!(CREATOR_WORK_STAGES[10], "Rights Recorded");
        assert_eq!(CREATOR_WORK_STAGES[11], "Payout Verified");
    }

    #[test]
    fn mission_stage_labels_preserve_non_success_terminal_states() {
        assert_eq!(
            mission_stage_label(&MissionStage::ExpectedRefusal),
            "预期拒绝"
        );
        assert_eq!(mission_stage_label(&MissionStage::Partial), "部分完成");
        assert_eq!(mission_stage_label(&MissionStage::Failed), "失败");
        assert_ne!(mission_stage_label(&MissionStage::Verifying), "已完成");
        assert_eq!(
            mission_checkpoint_executor_label(MissionCheckpointExecutor::EffectBroker),
            "EFFECT_BROKER"
        );
        assert_ne!(
            mission_checkpoint_executor_label(MissionCheckpointExecutor::Human),
            "RUNTIME"
        );
        assert_eq!(
            mission_conversation_kind_label(MissionConversationMessageKind::CheckpointConfirmation),
            "CHECKPOINT_CONFIRMATION"
        );
    }

    #[test]
    fn recovery_input_validates_shape_and_redacts_diagnostics() {
        let mut input = SensitiveRecoveryInput::default();
        input.replace("ab".repeat(32));
        assert!(input.has_valid_shape());
        assert_eq!(input.expose_for_submission().len(), 64);
        let diagnostics = format!("{input:?}");
        assert_eq!(diagnostics, "SensitiveRecoveryInput([REDACTED])");
        assert!(!diagnostics.contains("abababab"));
        input.clear();
        assert!(!input.has_valid_shape());
        assert!(input.expose_for_submission().is_empty());
    }

    #[test]
    fn runtime_labels_never_collapse_uncertain_or_failed_into_success() {
        assert_eq!(
            runtime_availability_label(DesktopRuntimeAvailabilityStatus::ReadyDevelopment),
            "DEV_READY"
        );
        assert_eq!(
            runtime_availability_label(DesktopRuntimeAvailabilityStatus::EvidenceMissing),
            "EVIDENCE_MISSING"
        );
        assert_eq!(
            runtime_turn_status_label(RuntimeTurnStatus::Uncertain),
            "UNCERTAIN"
        );
        assert_eq!(
            runtime_recovery_status_label(RuntimeRecoveryStatus::Failed),
            "FAILED"
        );
        assert_eq!(
            runtime_process_claim_status_label(RuntimeProcessClaimStatus::Blocked),
            "BLOCKED"
        );
        let uncertain = MissionRuntimeProjection {
            project_id: ProjectId::from("project-runtime-label"),
            mission_id: MissionId::from("mission-runtime-label"),
            process_claim_status: Some(RuntimeProcessClaimStatus::Terminated),
            process_cleanup_attempt_count: 1,
            recovery_status: Some(RuntimeRecoveryStatus::Attached),
            recovery_failure_count: 0,
            recovery_process_attempt: Some(1),
            turn_status: Some(RuntimeTurnStatus::Uncertain),
            turn_failure_count: 1,
            turn_evidence_count: 4,
            last_updated_at: Some(Utc::now()),
            requires_reconciliation: true,
        };
        let note = runtime_activity_note(&uncertain, 0);
        assert!(note.contains("UNCERTAIN"));
        assert!(note.contains("禁止自动重放"));
        assert!(!note.contains("DRAFT_READY"));

        let completed = MissionRuntimeProjection {
            turn_status: Some(RuntimeTurnStatus::Completed),
            requires_reconciliation: false,
            ..uncertain
        };
        let note = runtime_activity_note(&completed, 1);
        assert!(note.contains("DRAFT_READY"));
        assert!(note.contains("没有把 Mission 自动标为完成"));

        let blocked_process = MissionRuntimeProjection {
            process_claim_status: Some(RuntimeProcessClaimStatus::Blocked),
            process_cleanup_attempt_count: 2,
            turn_status: None,
            requires_reconciliation: true,
            ..completed
        };
        let note = runtime_activity_note(&blocked_process, 0);
        assert!(note.contains("PROCESS_CLEANUP_BLOCKED"));
        assert!(note.contains("不会按 PID 猜测清理"));
        assert!(!note.contains("DRAFT_READY"));
    }

    #[test]
    fn runtime_retry_control_only_opens_for_safe_running_mission_states() {
        let prepared = MissionRuntimeProjection {
            project_id: ProjectId::from("project-runtime-retry"),
            mission_id: MissionId::from("mission-runtime-retry"),
            process_claim_status: Some(RuntimeProcessClaimStatus::Terminated),
            process_cleanup_attempt_count: 1,
            recovery_status: Some(RuntimeRecoveryStatus::Prepared),
            recovery_failure_count: 1,
            recovery_process_attempt: Some(1),
            turn_status: None,
            turn_failure_count: 0,
            turn_evidence_count: 0,
            last_updated_at: Some(Utc::now()),
            requires_reconciliation: false,
        };
        assert!(mission_runtime_retry_needed(
            &MissionStage::Running,
            Some(&prepared)
        ));
        assert!(!mission_runtime_retry_needed(
            &MissionStage::Completed,
            Some(&prepared)
        ));

        let failed_turn = MissionRuntimeProjection {
            recovery_status: Some(RuntimeRecoveryStatus::Attached),
            turn_status: Some(RuntimeTurnStatus::Failed),
            ..prepared.clone()
        };
        assert!(mission_runtime_retry_needed(
            &MissionStage::Running,
            Some(&failed_turn)
        ));

        let uncertain = MissionRuntimeProjection {
            turn_status: Some(RuntimeTurnStatus::Uncertain),
            requires_reconciliation: true,
            ..failed_turn.clone()
        };
        assert!(!mission_runtime_retry_needed(
            &MissionStage::Running,
            Some(&uncertain)
        ));

        let completed = MissionRuntimeProjection {
            turn_status: Some(RuntimeTurnStatus::Completed),
            requires_reconciliation: false,
            ..failed_turn
        };
        assert!(!mission_runtime_retry_needed(
            &MissionStage::Running,
            Some(&completed)
        ));
    }
}
