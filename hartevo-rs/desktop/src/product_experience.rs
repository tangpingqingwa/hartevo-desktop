//! User-facing task summaries derived from durable state.

use dioxus::prelude::*;
use hartevo_application::{DesktopProjectProjection, MissionProjection, WorkProductProjection};
use hartevo_domain_kernel::{MissionStage, WorkProductStatus, media_generation::MediaKind};

use crate::media_workspace::MediaAssetPreview;
use crate::result_adoption_surface::{ResultSurfaceAction, selected_result_projection};
use crate::{UiIcon, UiIconName};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum TaskFilter {
    #[default]
    All,
    Active,
    Waiting,
    History,
}

pub(crate) type TaskScope = (
    hartevo_domain_kernel::ProjectId,
    hartevo_domain_kernel::MissionId,
);

pub(crate) fn scope_matches(mission: &MissionProjection, scope: Option<&TaskScope>) -> bool {
    scope.is_some_and(|(project, id)| project == &mission.project_id && id == &mission.mission_id)
}

pub(crate) fn legacy_media_entry_available(
    mission: Option<&MissionProjection>,
    executing: bool,
    recovering: bool,
) -> bool {
    !executing
        && !recovering
        && mission.is_some_and(|m| {
            m.stage == MissionStage::Running
                && m.manifest_id.is_none()
                && m.conversation_revision.is_none()
                && m.current_checkpoint_id.is_none()
                && m.pending_approval_count == 0
        })
}

impl TaskFilter {
    pub(crate) fn matches_with_attention(
        self,
        mission: &MissionProjection,
        attention: Option<&TaskScope>,
    ) -> bool {
        match self {
            Self::All => true,
            Self::Active => !mission.stage.is_terminal(),
            Self::Waiting => {
                scope_matches(mission, attention)
                    || mission.pending_approval_count > 0
                    || matches!(
                        mission.stage,
                        MissionStage::WaitingUser | MissionStage::WaitingApproval
                    )
                    || mission
                        .work_products
                        .iter()
                        .any(|p| p.adoption_status == WorkProductStatus::ReadyForReview)
            }
            Self::History => mission.stage.is_terminal(),
        }
    }
}

#[component]
pub(crate) fn TaskList(
    project: Option<DesktopProjectProjection>,
    selected_mission_id: Option<hartevo_domain_kernel::MissionId>,
    executing_mission_id: Option<hartevo_domain_kernel::MissionId>,
    live_attention: Option<TaskScope>,
    filter: TaskFilter,
    on_filter: EventHandler<TaskFilter>,
    on_select: EventHandler<hartevo_domain_kernel::MissionId>,
) -> Element {
    let mut query = use_signal(String::new);
    let Some(project) = project else {
        return rsx! {p {class:"task-empty","选择项目后查看任务。"}};
    };
    let search = query().trim().to_lowercase();
    let rows: Vec<_> = project
        .missions
        .iter()
        .filter(|m| filter.matches_with_attention(m, live_attention.as_ref()))
        .filter(|m| {
            search.is_empty()
                || format!("{} {}", m.title, m.goal)
                    .to_lowercase()
                    .contains(&search)
        })
        .cloned()
        .collect();
    rsx! {
        div {class:"surface-scroll business-surface missions-surface",
            header {class:"surface-head",
                div {class:"surface-head-copy",span {class:"surface-eyebrow","{project.name}"} h1 {"全部任务"} p {"查看进展、审阅成果，或继续之前的工作。"} }
                span {class:"sync-chip","{project.missions.len()} 个任务"}
            }
            div {class:"task-list-controls",
                nav {class:"surface-tabs",aria_label:"筛选任务",
                    for (value,label) in [(TaskFilter::All,"全部"),(TaskFilter::Active,"进行中"),(TaskFilter::Waiting,"待确认"),(TaskFilter::History,"已结束")] {
                        button {class:if filter == value {"active"} else {""},aria_pressed:filter == value,
                            onclick:move |_|on_filter.call(value),"{label}"}
                    }
                }
                input {class:"task-search",r#type:"search",aria_label:"搜索任务",placeholder:"搜索任务…",value:"{query}",oninput:move |e|query.set(e.value())}
            }
            if rows.is_empty() {
                p {class:"task-empty",role:"status",if !search.is_empty() {"没有找到匹配的任务。换个关键词试试。"} else if filter == TaskFilter::Waiting {"没有需要你确认的任务。"} else if filter == TaskFilter::History {"还没有已结束的任务。"} else {"这里还没有任务。点击「新任务」开始。"}}
            } else {
                div {class:"mission-table",role:"list",
                    for mission in rows {
                        {
                            let id = mission.mission_id.clone();
                            let selected = selected_mission_id.as_ref() == Some(&id);
                            let status = if scope_matches(&mission,live_attention.as_ref()) {"等待确认"} else {task_status(&mission,executing_mission_id.as_ref() == Some(&id))};
                            let result_count = mission.work_products.iter().filter(|p|p.adoption_status != WorkProductStatus::Superseded).count();
                            rsx! {
                                button {class:if selected {"mission-table-row active"} else {"mission-table-row"},onclick:move |_|on_select.call(id.clone()),
                                    span {class:"mission-table-copy",strong {"{mission.title}"} small {if mission.title != mission.goal {"{mission.goal}"} else {"打开查看进展和成果"}}}
                                    span {class:"task-state","{status}"}
                                    span {class:"task-result-count","{result_count} 份成果"}
                                    span {class:"mission-table-action","打开 →"}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn task_status(mission: &MissionProjection, executing: bool) -> &'static str {
    let result = if mission
        .work_products
        .iter()
        .any(|p| p.adoption_status == WorkProductStatus::ReadyForReview)
    {
        Some(&WorkProductStatus::ReadyForReview)
    } else if mission
        .work_products
        .iter()
        .any(|p| p.adoption_status == WorkProductStatus::Accepted)
    {
        Some(&WorkProductStatus::Accepted)
    } else {
        None
    };
    task_status_from_facts(
        &mission.stage,
        executing,
        mission.pending_approval_count > 0,
        result,
    )
}

fn task_status_from_facts(
    stage: &MissionStage,
    executing: bool,
    approval: bool,
    result: Option<&WorkProductStatus>,
) -> &'static str {
    match stage {
        MissionStage::Running if approval => "等待确认",
        MissionStage::Running if executing => "正在处理",
        MissionStage::Running if result == Some(&WorkProductStatus::ReadyForReview) => "待审阅",
        MissionStage::Running if result == Some(&WorkProductStatus::Accepted) => "成果已保存",
        MissionStage::Running => "待继续",
        _ => crate::mission_stage_label(stage),
    }
}

pub(crate) fn result_status(status: &WorkProductStatus) -> &'static str {
    match status {
        WorkProductStatus::Draft => "草稿",
        WorkProductStatus::ReadyForReview => "待审阅",
        WorkProductStatus::Accepted => "已采用",
        WorkProductStatus::Superseded => "历史版本",
    }
}

pub(crate) fn media_identity(product: &WorkProductProjection) -> Option<(String, MediaKind)> {
    let kind = match product.work_product_type.as_str() {
        "generated_image" => MediaKind::Image,
        "generated_video" => MediaKind::Video,
        _ => return None,
    };
    let value: serde_json::Value = serde_json::from_str(&product.preview_text).ok()?;
    let id = value.get("generationId")?.as_str()?.to_owned();
    (!id.is_empty()).then_some((id, kind))
}

#[component]
pub(crate) fn MissionOverview(
    project: DesktopProjectProjection,
    mission: MissionProjection,
    executing: bool,
    awaiting_confirmation: bool,
    model_ready: bool,
    on_open_workpad: EventHandler<()>,
    on_open_settings: EventHandler<()>,
    on_result_action: EventHandler<ResultSurfaceAction>,
) -> Element {
    let status = if awaiting_confirmation {
        "等待确认"
    } else {
        task_status(&mission, executing)
    };
    let products: Vec<_> = mission
        .work_products
        .iter()
        .filter(|p| p.adoption_status != WorkProductStatus::Superseded)
        .cloned()
        .collect();
    let count = products.len();
    let review_count = products
        .iter()
        .filter(|p| p.adoption_status == WorkProductStatus::ReadyForReview)
        .count();
    rsx! {
        section { class: "mission-overview", aria_label: "任务概览与成果",
            header { class: "mission-focus-heading",
                div {
                    span { class: "mission-focus-context", "{project.name}" }
                    h1 { "{mission.title}" }
                }
                span { class: if executing {"task-state is-active"} else {"task-state"}, role:"status", "{status}" }
            }
            if mission.goal != mission.title { p { class: "mission-focus-brief", "{mission.goal}" } }
            if !products.is_empty() {
                div { class:"mission-results-heading",
                    h2 { "任务成果" }
                    span { if review_count > 0 { "{count} 份成果 · {review_count} 份待审阅" } else { "{count} 份成果" } }
                    button {class:"task-text-action",onclick:move |_|on_open_workpad.call(()),"管理素材与版本" UiIcon {name:UiIconName::Panel,size:14} }
                }
                div {class:"mission-result-gallery",
                    for product in products {
                        if let Some(result) = selected_result_projection(&project,&mission,Some(&product.work_product_id)) {
                            {
                                let open = result.open_artifact_action();
                                let status = result_status(&product.adoption_status);
                                let identity = media_identity(&product);
                                rsx! {
                                    article {key:"result-{product.work_product_id}",class:"mission-result-card",
                                        div {class:"mission-result-preview",
                                            if let Some((id,kind)) = identity {
                                                MediaAssetPreview {key:"{id}",project_id:mission.project_id.clone(),mission_id:mission.mission_id.clone(),id,kind,
                                                    on_loaded:move |()|{},on_failed:move |()|{} }
                                            } else {
                                                div {class:"mission-result-excerpt",
                                                    UiIcon {name:UiIconName::FileText,size:20}
                                                    p { "{crate::draft_preview::excerpt(&product.preview_text)}" }
                                                }
                                            }
                                        }
                                        footer {
                                            div {strong { "{crate::draft_preview::product_title(&product)}" } span { "{status}" } }
                                            button {class:"task-secondary-action",onclick:move |_|on_result_action.call(open.clone()),"打开成果"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else if !executing && mission.conversation_messages.is_empty() {
                div {class:"mission-ready-note",
                    UiIcon {name:UiIconName::Message,size:19}
                    div {strong { "目标已保存" } p {if mission.conversation_revision.is_some() {"在下方补充受众、渠道或期望的交付内容，也可以打开工作台准备创意素材。"} else {"打开工作台，描述你需要的图片或视频，查看结果后采用或修改。"}} }
                    button {class:"task-secondary-action",onclick:move |_|on_open_workpad.call(()),"准备素材"}
                }
            }
            if !model_ready && !executing && mission.conversation_revision.is_some() {
                div {class:"mission-connection-note",role:"status",
                    UiIcon {name:UiIconName::Plug,size:15}
                    span {"对话模型尚未连接。已保存的成果仍可查看。"}
                    button {class:"task-text-action",onclick:move |_|on_open_settings.call(()),"设置模型"}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::task_status_from_facts;
    use hartevo_domain_kernel::{MissionStage, WorkProductStatus};

    #[test]
    fn accepted_artifacts_do_not_claim_active_work_or_business_completion() {
        assert_eq!(
            task_status_from_facts(
                &MissionStage::Running,
                false,
                false,
                Some(&WorkProductStatus::Accepted)
            ),
            "成果已保存"
        );
        assert_eq!(
            task_status_from_facts(&MissionStage::Running, false, false, None),
            "待继续"
        );
        assert_eq!(
            task_status_from_facts(
                &MissionStage::Running,
                true,
                false,
                Some(&WorkProductStatus::Accepted)
            ),
            "正在处理"
        );
    }

    #[test]
    fn task_filters_keep_durable_results_and_pending_decisions_in_the_right_views() {
        use super::TaskFilter;
        use hartevo_domain_kernel::WorkProductStatus;
        let (_, mut mission) =
            crate::result_adoption_surface::tests::project_and_mission(WorkProductStatus::Accepted);
        assert!(TaskFilter::All.matches_with_attention(&mission, None));
        assert!(TaskFilter::Active.matches_with_attention(&mission, None));
        assert!(!TaskFilter::Waiting.matches_with_attention(&mission, None));
        assert!(!TaskFilter::History.matches_with_attention(&mission, None));
        mission.work_products[0].adoption_status = WorkProductStatus::ReadyForReview;
        assert!(TaskFilter::Waiting.matches_with_attention(&mission, None));
        mission.work_products[0].adoption_status = WorkProductStatus::Accepted;
        mission.pending_approval_count = 1;
        assert!(TaskFilter::Waiting.matches_with_attention(&mission, None));
        mission.pending_approval_count = 0;
        mission.stage = MissionStage::WaitingUser;
        assert!(TaskFilter::Waiting.matches_with_attention(&mission, None));
        mission.stage = MissionStage::Failed;
        assert!(!TaskFilter::Active.matches_with_attention(&mission, None));
        assert!(TaskFilter::History.matches_with_attention(&mission, None));
    }

    #[test]
    fn live_approval_uses_the_command_scope_even_without_a_proposed_effect() {
        use super::{TaskFilter, scope_matches};
        let (_, mission) =
            crate::result_adoption_surface::tests::project_and_mission(WorkProductStatus::Accepted);
        let scope = (mission.project_id.clone(), mission.mission_id.clone());
        assert_eq!(mission.pending_approval_count, 0);
        assert!(TaskFilter::Waiting.matches_with_attention(&mission, Some(&scope)));
        let other = (
            mission.project_id.clone(),
            hartevo_domain_kernel::MissionId::from("other-task"),
        );
        assert!(!scope_matches(&mission, Some(&other)));
        assert!(!TaskFilter::Waiting.matches_with_attention(&mission, Some(&other)));
    }

    #[test]
    fn legacy_creative_entry_keeps_approval_checkpoint_and_recovery_actions_accessible() {
        use super::legacy_media_entry_available;
        let (_, mut mission) =
            crate::result_adoption_surface::tests::project_and_mission(WorkProductStatus::Accepted);
        mission.manifest_id = None;
        assert!(legacy_media_entry_available(Some(&mission), false, false));
        mission.stage = MissionStage::WaitingApproval;
        mission.pending_approval_count = 1;
        assert!(!legacy_media_entry_available(Some(&mission), false, false));
        mission.stage = MissionStage::Running;
        mission.pending_approval_count = 0;
        assert!(!legacy_media_entry_available(Some(&mission), false, true));
        assert!(!legacy_media_entry_available(Some(&mission), true, false));
        mission.current_checkpoint_id = Some("checkpoint".into());
        assert!(!legacy_media_entry_available(Some(&mission), false, false));
    }

    #[test]
    fn a_pending_decision_takes_priority_over_saved_artifacts() {
        assert_eq!(
            task_status_from_facts(
                &MissionStage::Running,
                false,
                true,
                Some(&WorkProductStatus::ReadyForReview)
            ),
            "等待确认"
        );
        assert_eq!(
            task_status_from_facts(
                &MissionStage::Running,
                false,
                false,
                Some(&WorkProductStatus::ReadyForReview)
            ),
            "待审阅"
        );
        assert_eq!(
            task_status_from_facts(
                &MissionStage::Blocked,
                false,
                false,
                Some(&WorkProductStatus::ReadyForReview)
            ),
            crate::mission_stage_label(&MissionStage::Blocked)
        );
    }
}
