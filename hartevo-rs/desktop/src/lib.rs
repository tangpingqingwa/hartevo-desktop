use std::collections::BTreeSet;
use std::sync::LazyLock;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use dioxus::prelude::*;
use dioxus_icons::lucide::{
    Bell, Blocks, BotMessageSquare, BriefcaseBusiness, CalendarDays, ChartNoAxesCombined, Check,
    ChevronDown, ContactRound, FileCheck, FileText, FolderKanban, Handshake, House, Inbox,
    LayoutDashboard, ListChecks, Mail, MessageSquareText, PanelRightOpen, PlugZap, Plus, RefreshCw,
    Search, Settings, ShieldCheck, Sparkles, Target, UsersRound, WalletCards, Workflow, X,
};
use hartevo_application::{
    ApplicationCheckpointHandlerStatus, ApplicationError, DesktopProjectProjection,
    MissionProjection, MissionRuntimeProjection, ProjectEncryptionReadiness,
};
use hartevo_catalog::{EvidenceLevel, MissionEvidenceStatus};
use hartevo_domain_kernel::{
    CadenceTriggerKind, MissionCheckpointCompletionPolicy, MissionCheckpointExecutor,
    MissionCheckpointStatus, MissionConversationMessageId, MissionConversationMessageKind,
    MissionConversationRole, MissionId, MissionScheduleStatus, MissionStage, OperatingMode,
    ProjectEncryptionMode, ProjectId, RuntimeProcessClaimStatus, RuntimeRecoveryStatus,
    RuntimeTurnStatus, StorageMode, WorkProductId, WorkProductStatus,
};
use zeroize::Zeroizing;

pub mod data_plane;
mod runtime_plane;
#[cfg(feature = "visual-fixtures")]
mod visual_fixture;

use data_plane::{
    DesktopCatalogMissionRequest, DesktopDataError, DesktopDataPlane,
    DesktopHumanCheckpointConfirmationRequest, DesktopLoadState, DesktopMissionContinuationRequest,
    DesktopSnapshot, ProductEvidenceProjection, ProjectContextAccessProjection,
    ProjectContextAccessStatus, RecoveryKitDraft,
};
pub use runtime_plane::{DesktopRuntimeAvailabilityStatus, DesktopRuntimeProjection};

static MAIN_CSS: Asset = asset!("/assets/main.css");
static PROTOTYPE_CSS: Asset = asset!("/assets/prototype.css");
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
    Bell,
    Blocks,
    Bot,
    Briefcase,
    Calendar,
    Chart,
    Check,
    ChevronDown,
    Contact,
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
    Plug,
    Plus,
    Refresh,
    Search,
    Settings,
    Shield,
    Sparkles,
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
        UiIconName::Bell => rsx! { Bell { size } },
        UiIconName::Blocks => rsx! { Blocks { size } },
        UiIconName::Bot => rsx! { BotMessageSquare { size } },
        UiIconName::Briefcase => rsx! { BriefcaseBusiness { size } },
        UiIconName::Calendar => rsx! { CalendarDays { size } },
        UiIconName::Chart => rsx! { ChartNoAxesCombined { size } },
        UiIconName::Check => rsx! { Check { size } },
        UiIconName::ChevronDown => rsx! { ChevronDown { size } },
        UiIconName::Contact => rsx! { ContactRound { size } },
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
        UiIconName::Plug => rsx! { PlugZap { size } },
        UiIconName::Plus => rsx! { Plus { size } },
        UiIconName::Refresh => rsx! { RefreshCw { size } },
        UiIconName::Search => rsx! { Search { size } },
        UiIconName::Settings => rsx! { Settings { size } },
        UiIconName::Shield => rsx! { ShieldCheck { size } },
        UiIconName::Sparkles => rsx! { Sparkles { size } },
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
    let mut catalog_contract_expanded = use_signal(|| false);
    let mut mission_submitting = use_signal(|| false);
    let mut runtime_retrying = use_signal(|| false);
    let mut human_work_product_selection = use_signal(BTreeSet::<WorkProductId>::new);
    let mut workpad_open = use_signal(|| true);
    let mut global_search_query = use_signal(String::new);
    let mut active_overlay = use_signal(ActiveOverlay::default);
    let mut surface_before_settings = use_signal(|| Surface::Orchestrator);
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
    let catalog_contract_ready = !selected_manifest_id.is_empty()
        && selected_mode_is_allowed
        && operating_mode_from_catalog_name(&selected_mode).is_some()
        && !draft.read().trim().is_empty()
        && !market_value.trim().is_empty()
        && !language_value.trim().is_empty()
        && !audience_value.trim().is_empty()
        && !timezone_value.trim().is_empty()
        && valid_currency_shape(&currency_value)
        && budget_minor.is_some();
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
        && !draft.read().trim().is_empty()
        && (!human_requires_work_product || !selected_human_work_product_ids.is_empty());
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
                        active_overlay.set(ActiveOverlay::None);
                        if current_surface == Surface::Settings {
                            surface.set(surface_before_settings());
                        }
                    }
                    Some(AppShortcut::GlobalSearch) => {
                        event.prevent_default();
                        active_overlay.set(ActiveOverlay::GlobalSearch);
                    }
                    Some(AppShortcut::NewTask) => {
                        event.prevent_default();
                        if keyboard_has_project {
                            model.write().select_dispatcher();
                            surface.set(Surface::Orchestrator);
                            catalog_contract_expanded.set(true);
                        }
                    }
                    Some(AppShortcut::ProjectDispatcher) => {
                        event.prevent_default();
                        if keyboard_has_project {
                            model.write().select_dispatcher();
                            active_overlay.set(ActiveOverlay::None);
                            surface.set(Surface::Orchestrator);
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
                            class: if active_overlay() == ActiveOverlay::GlobalSearch { "brand-action active" } else { "brand-action" },
                            aria_label: "搜索所有项目与任务",
                            title: "搜索所有项目与任务",
                            onclick: move |_| {
                                active_overlay.set(ActiveOverlay::GlobalSearch);
                            },
                            UiIcon { name: UiIconName::Search, size: 15 }
                        }
                        button {
                            class: if active_overlay() == ActiveOverlay::Notifications { "brand-action active" } else { "brand-action" },
                            aria_label: "查看全部项目通知",
                            title: "全部项目通知",
                            aria_expanded: active_overlay() == ActiveOverlay::Notifications,
                            onclick: move |_| {
                                active_overlay.set(active_overlay().toggle(ActiveOverlay::Notifications));
                            },
                            UiIcon { name: UiIconName::Bell, size: 15 }
                            span { class: "notification-badge quiet", "0" }
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
                            class: "icon-button",
                            aria_label: "重新读取持久状态",
                            title: "重新读取持久状态",
                            onclick: move |_| model.set(DesktopUiModel::load()),
                            UiIcon { name: UiIconName::Refresh, size: 14 }
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
                nav { class: "primary-nav", aria_label: "项目工作面",
                    div { class: "nav-label", "工作" }
                    NavButton { label: "当前状态", meta: "Project", icon: UiIconName::Home, active: current_surface == Surface::Current, onclick: move |_| surface.set(Surface::Current) }
                    NavButton { label: "总调度", meta: "同一会话", icon: UiIconName::Sparkles, active: current_surface == Surface::Orchestrator, onclick: move |_| surface.set(Surface::Orchestrator) }
                    NavButton { label: "全部任务", meta: "Mission", icon: UiIconName::List, active: current_surface == Surface::Missions, onclick: move |_| surface.set(Surface::Missions) }
                    NavButton { label: "成果与循环", meta: "Outcome", icon: UiIconName::Chart, active: current_surface == Surface::Outcomes, onclick: move |_| surface.set(Surface::Outcomes) }
                    div { class: "nav-label", "增长运营" }
                    NavButton { label: "渠道运营", meta: "Channel", icon: UiIconName::Mail, active: current_surface == Surface::ChannelOperations, onclick: move |_| surface.set(Surface::ChannelOperations) }
                    NavButton { label: "关系与 CRM", meta: "未接入", icon: UiIconName::Contact, active: current_surface == Surface::Relationships, onclick: move |_| surface.set(Surface::Relationships) }
                    NavButton { label: "达人与联盟", meta: "未接入", icon: UiIconName::Handshake, active: current_surface == Surface::Partners, onclick: move |_| surface.set(Surface::Partners) }
                    div { class: "nav-label", "系统与连接" }
                    NavButton { label: "连接中心", meta: "Probe", icon: UiIconName::Plug, active: current_surface == Surface::Connections, onclick: move |_| surface.set(Surface::Connections) }
                    NavButton { label: "能力与证据", meta: "E0–E5", icon: UiIconName::Blocks, active: current_surface == Surface::CapabilityEvidence, onclick: move |_| surface.set(Surface::CapabilityEvidence) }
                }

                if let DesktopBackendState::Ready(snapshot) = &view.backend {
                    section { class: "project-rail", aria_label: "宣发项目",
                        header { span { "宣发项目" } em { "{snapshot.inventory.projects.len()}" } }
                        for item in snapshot.inventory.projects.clone() {
                            {
                                let project_id = item.project_id.clone();
                                let selected = view.selected_project_id.as_ref() == Some(&project_id);
                                rsx! {
                                    button { class: if selected { "project-row active" } else { "project-row" },
                                        onclick: move |_| model.write().select_project(&project_id),
                                        span { class: "workspace-mark", "{item.name.chars().next().unwrap_or('项')}" }
                                        span { strong { "{item.name}" } small { "revision {item.revision} · {encryption_short_label(&item.encryption)}" } }
                                    }
                                }
                            }
                        }
                    }
                    section { class: "mission-rail", aria_label: "持久任务",
                        header { span { "持久 Mission" } em { "{project.as_ref().map_or(0, |item| item.missions.len())}" } }
                        if let Some(selected_project) = &project {
                            button {
                                class: if view.selected_mission_id.is_none() { "mission-row dispatcher active" } else { "mission-row dispatcher" },
                                onclick: move |_| model.write().select_dispatcher(),
                                span { class: "status-dot" }
                                span { strong { "项目总调度" } small { "显式选择 VM-00～VM-11" } }
                                em { "CATALOG" }
                            }
                            for item in selected_project.missions.clone() {
                                {
                                    let mission_id = item.mission_id.clone();
                                    let selected = view.selected_mission_id.as_ref() == Some(&mission_id);
                                    rsx! {
                                        button { class: if selected { "mission-row active" } else { "mission-row" },
                                            onclick: move |_| model.write().select_mission(mission_id.clone()),
                                            span { class: "status-dot live" }
                                            span { strong { "{item.title}" } small { "{mission_stage_label(&item.stage)}" } }
                                            em { "{item.revision}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                footer { class: "workspace-switcher",
                    if active_overlay() == ActiveOverlay::ProjectSwitcher {
                        section { class: "project-switcher", aria_label: "宣发项目切换器",
                            header { class: "project-switcher-head",
                                span { class: "user-avatar", "本" }
                                span { strong { "本机工作区" } small { "Local-first · 项目严格隔离" } }
                                button {
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
                        class: "workspace-button",
                        aria_haspopup: "true",
                        aria_expanded: active_overlay() == ActiveOverlay::ProjectSwitcher,
                        onclick: move |_| {
                            active_overlay.set(active_overlay().toggle(ActiveOverlay::ProjectSwitcher));
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
                            section { class: "composer-zone",
                                div { class: "composer-context",
                                    span { "{project_name} · {composer_target}" }
                                    div { class: "composer-context-actions",
                                        span { class: "permission-pill",
                                            if mission.is_some() { "同一 Mission · Capability 不扩大" } else { "外部动作仍需精确审批" }
                                        }
                                        if mission.is_none() {
                                            button {
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
                                            },
                                            option { value: "", "选择 VM-00～VM-11…" }
                                            for route in catalog_routes.clone() {
                                                option { value: "{route.mission_id}", "{route.mission_id} · {route.title}" }
                                            }
                                        }
                                    }
                                    label {
                                        span { "运行模式" }
                                        select {
                                            value: "{selected_mode}",
                                            disabled: !can_edit_catalog || allowed_modes.is_empty(),
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
                                            disabled: !can_edit_catalog,
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
                                            disabled: !can_edit_catalog,
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
                                            disabled: !can_edit_catalog,
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
                                            disabled: !can_edit_catalog,
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
                                            disabled: !can_edit_catalog,
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
                                            disabled: !can_edit_catalog,
                                            inputmode: "numeric",
                                            autocomplete: "off",
                                            placeholder: "0",
                                            aria_label: "Operating Contract minor-unit 预算",
                                            oninput: move |event| catalog_budget_minor.set(event.value()),
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
                                textarea {
                                    value: "{draft}",
                                    disabled: !can_write_composer,
                                    aria_label: "Operating Contract 目标、约束与停止条件",
                                    placeholder: if mission.is_some() {
                                        if human_route_active { "写下你对当前 Checkpoint 的明确确认；这段内容会私密写入 Mission Conversation…" } else if can_edit_continuation { "继续当前 Mission，或写明纠正与新约束…" } else { "当前 Mission 状态不接受续写，或它是 legacy bootstrap" }
                                    } else if project_can_start_mission {
                                        "写明目标、硬约束、非目标与停止条件…"
                                    } else {
                                        "项目加密与 Context 就绪后才能创建 Mission"
                                    },
                                    oninput: move |event| draft.set(event.value()),
                                }
                                footer {
                                    div { class: "runtime-pickers",
                                        span { class: "honesty-chip", "{runtime_chip}" }
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
                                                    runtime_retrying.set(true);
                                                    spawn(async move {
                                                        let result = tokio::task::spawn_blocking(move || {
                                                            DesktopDataPlane::discover().and_then(|plane| {
                                                                plane.resume_mission_runtime_os(
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
                                                                    code: "RUNTIME_RETRY_COORDINATOR_FAILED".into(),
                                                                    message: "本地 Runtime 恢复协调异常结束；持久 recovery/turn ledger 保留原状态，未自动重放外部动作，也未声明 Mission 完成。".into(),
                                                                });
                                                            }
                                                        }
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
                                        if mission.is_some() {
                                            if human_route_active {
                                                button {
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
                                            } else {
                                            button { class: "send-button", disabled: !can_submit_continuation,
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
                                                    mission_submitting.set(true);
                                                    spawn(async move {
                                                        let result = tokio::task::spawn_blocking(move || {
                                                            DesktopDataPlane::discover().and_then(|plane| {
                                                                plane.continue_mission_and_run_os(request, Utc::now())
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
                                                        mission_submitting.set(false);
                                                    });
                                                },
                                                if mission_submitting() { "正在续写同一 Mission…" } else { "继续当前 Mission" }
                                            }
                                            }
                                        } else {
                                            button { class: "send-button", disabled: !can_submit_catalog,
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
                                                    let budget_minor = catalog_budget_minor().trim().parse::<i64>().ok();
                                                    let (Some(project_id), Some(mode), Some(budget_minor)) =
                                                        (project_id, mode, budget_minor)
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
                                                        title: None,
                                                        goal,
                                                        market,
                                                        language,
                                                        audience,
                                                        timezone,
                                                        budget_minor,
                                                        currency,
                                                    };
                                                    mission_submitting.set(true);
                                                    spawn(async move {
                                                        let result = tokio::task::spawn_blocking(move || {
                                                            DesktopDataPlane::discover().and_then(|plane| {
                                                                plane.start_catalog_mission_and_run_os(request, Utc::now())
                                                            })
                                                        })
                                                        .await;
                                                        match result {
                                                            Ok(Ok(submission)) => {
                                                                model.write().set_ready(submission.snapshot, true);
                                                                draft.set(String::new());
                                                                catalog_manifest_id.set(String::new());
                                                                catalog_mode.set(String::new());
                                                            }
                                                            Ok(Err(error)) => model.write().set_notice(&error),
                                                            Err(_) => {
                                                                model.write().notice = Some(UiFailure {
                                                                    code: "RUNTIME_COORDINATOR_FAILED".into(),
                                                                    message: "本地 Runtime 协调任务异常结束；重启读取时会由持久 Turn Ledger 进行 fencing，未声明 Mission 完成。".into(),
                                                                });
                                                            }
                                                        }
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
                                }
                            }
                        }
                    }

                    if workpad_visible {
                        Workpad { mission: mission.clone(), context_access: context_access.clone() }
                    }
                }
            }
            if active_overlay() == ActiveOverlay::GlobalSearch {
                GlobalSearchOverlay {
                    backend: view.backend.clone(),
                    query: global_search_query(),
                    on_query: move |value| global_search_query.set(value),
                    on_close: move |()| active_overlay.set(ActiveOverlay::None),
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
                    on_close: move |()| active_overlay.set(ActiveOverlay::None),
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
    label: &'static str,
    meta: &'static str,
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
fn GlobalSearchOverlay(
    backend: DesktopBackendState,
    query: String,
    on_query: EventHandler<String>,
    on_close: EventHandler<()>,
    on_project: EventHandler<ProjectId>,
    on_mission: EventHandler<(ProjectId, MissionId)>,
) -> Element {
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
    rsx! {
        button { class: "overlay-backdrop search-backdrop", aria_label: "关闭全局搜索", onclick: move |_| on_close.call(()) }
        section {
            class: "global-search",
            role: "dialog",
            aria_modal: "true",
            aria_label: "搜索所有项目与任务",
            onkeydown: move |event| {
                if event.key() == Key::Escape {
                    on_close.call(());
                }
            },
            header {
                UiIcon { name: UiIconName::Search, size: 18 }
                input {
                    autofocus: true,
                    value: "{query}",
                    aria_label: "搜索 Project 或 Mission",
                    placeholder: "搜索项目、Mission 与状态…",
                    oninput: move |event| on_query.call(event.value()),
                }
                kbd { "Esc" }
            }
            div { class: "global-search-results",
                if result_count == 0 {
                    div { class: "search-empty", span { class: "honesty-badge", "EMPTY" } p { "当前持久 Inventory 中没有匹配结果。" } }
                } else {
                    if !project_results.is_empty() {
                        h2 { "项目" }
                        for project in project_results {
                            {
                                let project_id = project.project_id.clone();
                                rsx! {
                                    button { class: "search-result", onclick: move |_| on_project.call(project_id.clone()),
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
                        for (project_id, project_name, mission) in mission_results {
                            {
                                let mission_id = mission.mission_id.clone();
                                rsx! {
                                    button { class: "search-result", onclick: move |_| on_mission.call((project_id.clone(), mission_id.clone())),
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
    rsx! {
        button { class: "overlay-dismiss", aria_label: "关闭通知", onclick: move |_| on_close.call(()) }
        section { class: "notification-center", role: "dialog", aria_label: "全部项目通知",
            header { class: "notification-head",
                strong { "通知" }
                span { "所有宣发项目" }
                button { onclick: move |_| on_close.call(()), UiIcon { name: UiIconName::X, size: 14 } }
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
    context_access: Option<ProjectContextAccessProjection>,
    on_initialize: EventHandler<MouseEvent>,
    on_ready: EventHandler<DesktopSnapshot>,
    on_error: EventHandler<DesktopDataError>,
    on_select_mission: EventHandler<MissionId>,
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
            rsx! {
                div { class: "surface-scroll",
                    article { class: "assistant-turn",
                        header { class: "assistant-byline", span { class: "brand-mark small", "H" } strong { "Hartevo" } time { "持久状态" } }
                        p { class: "assistant-lead", "下面内容来自同一个 Project/Mission Domain；页面不会生成 Receipt、Verification 或完成状态。" }
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
    let mut conversation_tail = mission
        .conversation_messages
        .iter()
        .rev()
        .take(8)
        .cloned()
        .collect::<Vec<_>>();
    conversation_tail.reverse();
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
            if !conversation_tail.is_empty() {
                section { class: "mission-conversation", aria_label: "持久 Mission Conversation",
                    header {
                        strong { "Mission Conversation" }
                        span { "revision {mission.conversation_revision.unwrap_or_default()} · {mission.conversation_messages.len()} messages" }
                    }
                    for message in conversation_tail {
                        article { class: if message.role == MissionConversationRole::User { "conversation-message user" } else { "conversation-message assistant" },
                            div {
                                strong { "{mission_conversation_role_label(message.role)}" }
                                span { "#{message.sequence} · {mission_conversation_kind_label(message.kind)}" }
                            }
                            p { "{message.body}" }
                            code { title: "{message.content_digest}", "digest {short_digest(&message.content_digest)}" }
                        }
                    }
                }
            }
            if let Some(activity) = &runtime_activity {
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

#[component]
fn Workpad(
    mission: Option<MissionProjection>,
    context_access: Option<ProjectContextAccessProjection>,
) -> Element {
    let context_is_open = context_access.as_ref().is_some_and(|access| {
        matches!(
            access.status,
            ProjectContextAccessStatus::Ready { .. } | ProjectContextAccessStatus::Degraded { .. }
        )
    });
    rsx! {
        aside { class: "workpad", aria_label: "任务工作台",
            header { span { strong { "工作产物" } small { "Application projection" } } }
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

fn active_visual_zoom() -> f64 {
    #[cfg(feature = "visual-fixtures")]
    {
        if std::env::var("HARTEVO_DESKTOP_UI_ZOOM").ok().as_deref() == Some("2") {
            return 2.0;
        }
    }
    1.0
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
