//! Goal-first task entry. Suggestions are editable UI defaults, never authority.
use std::collections::BTreeMap;

use dioxus::prelude::*;
use hartevo_domain_kernel::{MissionId, ProjectId};
use rust_decimal::Decimal;

use crate::data_plane::{DesktopCatalogMissionRequest, MissionContractEvidenceProjection};
use crate::{
    UiIcon, UiIconName, catalog_kpi_contracts, operating_mode_from_catalog_name, restore_ui_focus,
};

type ComposerScope = (Option<ProjectId>, Option<MissionId>);

#[derive(Default)]
pub(crate) struct ComposerDrafts {
    // Slots never move, so an in-flight completion retains its original scope.
    entries: Vec<(ComposerScope, String)>,
}

impl ComposerDrafts {
    fn slot(&mut self, scope: ComposerScope) -> usize {
        if let Some(index) = self.entries.iter().position(|(key, _)| *key == scope) {
            return index;
        }
        self.entries.push((scope, String::new()));
        self.entries.len() - 1
    }

    fn clear_submission(&mut self, slot: usize, expected: &str) {
        if let Some((_, text)) = self.entries.get_mut(slot)
            && text == expected
        {
            text.clear();
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) struct DraftHandle {
    drafts: Signal<ComposerDrafts>,
    slot: usize,
}

impl DraftHandle {
    pub(crate) fn bind(mut drafts: Signal<ComposerDrafts>, scope: ComposerScope) -> Self {
        let existing = drafts
            .peek()
            .entries
            .iter()
            .position(|(key, _)| *key == scope);
        let slot = existing.unwrap_or_else(|| drafts.write().slot(scope));
        Self { drafts, slot }
    }

    pub(crate) fn get(&self) -> String {
        self.drafts.read().entries[self.slot].1.clone()
    }
    pub(crate) fn set(&mut self, value: String) {
        self.drafts.write().entries[self.slot].1 = value;
    }
    pub(crate) fn submission(&self) -> DraftSubmission {
        self.submission_for(self.get())
    }
    pub(crate) fn submission_for(&self, text: String) -> DraftSubmission {
        DraftSubmission {
            handle: *self,
            text,
        }
    }
}

impl std::fmt::Display for DraftHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.get())
    }
}

pub(crate) struct DraftSubmission {
    handle: DraftHandle,
    text: String,
}

impl DraftSubmission {
    pub(crate) fn clear(mut self) {
        self.handle
            .drafts
            .write()
            .clear_submission(self.handle.slot, &self.text);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TaskDraft {
    pub goal: String,
    route: String,
    mode: String,
    market: String,
    language: String,
    audience: String,
    timezone: String,
    currency: String,
    budget: String,
    metric: String,
    target: String,
    parent: String,
    reviewing: bool,
    show_errors: bool,
}

impl Default for TaskDraft {
    fn default() -> Self {
        Self {
            goal: String::new(),
            route: String::new(),
            mode: String::new(),
            market: String::new(),
            language: "zh-CN".into(),
            audience: String::new(),
            timezone: "UTC".into(),
            currency: "USD".into(),
            budget: "0".into(),
            metric: "work_product_count".into(),
            target: "1".into(),
            parent: String::new(),
            reviewing: false,
            show_errors: false,
        }
    }
}

pub(crate) type TaskDrafts = BTreeMap<ProjectId, TaskDraft>;

pub(crate) fn clear_created_draft(drafts: &mut TaskDrafts, project: &ProjectId, goal: &str) {
    if drafts
        .get(project)
        .is_some_and(|draft| draft.goal.trim() == goal.trim())
    {
        drafts.remove(project);
    }
}

pub(crate) fn route_label(id: &str) -> &str {
    match id {
        "VM-00" => "梳理项目与工作准备",
        "VM-01" => "搜索流量与内容优化",
        "VM-02" => "AI 搜索与品牌可见度",
        "VM-03" => "网站与着陆页建设",
        "VM-04" => "社媒内容与渠道运营",
        "VM-05" => "邮件与客户触达",
        "VM-06" => "达人合作与联盟营销",
        "VM-07" => "市场研究与机会判断",
        "VM-08" => "电商平台与商品运营",
        "VM-09" => "企业客户与销售线索",
        "VM-10" => "收件箱与客户回复",
        "VM-11" => "效果复盘与下一步",
        _ => id,
    }
}

fn mode_label(mode: &str) -> &str {
    match mode {
        "build_once" => "完成一次交付",
        "campaign" => "推进一轮活动",
        "continuous_operator" => "持续运营",
        "continuous_relationship" => "持续维护关系",
        "one_off_decision" => "完成一次研究与决策",
        _ => mode,
    }
}

fn metric_label(metric: &str) -> &str {
    match metric {
        "work_product_count" => "可审阅成果数",
        "lead_qualified_count" => "合格线索数",
        "conversion_count" => "转化数",
        _ => metric,
    }
}

fn suggested_route(goal: &str) -> Option<&'static str> {
    let text = goal.to_lowercase();
    // Ambiguous goals stay unselected. The user reviews the actual route before creation.
    let groups: &[(&str, &[&str])] = &[
        ("VM-01", &["seo", "搜索流量"]),
        ("VM-02", &["ai 搜索", "ai推荐", "ai 推荐", "品牌可见度"]),
        ("VM-03", &["着陆页", "落地页", "网站", "landing page"]),
        ("VM-04", &["社媒", "社交媒体", "social media"]),
        ("VM-05", &["邮件", "email"]),
        ("VM-06", &["达人", "联盟营销", "affiliate", "creator"]),
        (
            "VM-07",
            &["市场研究", "市场机会", "市场调研", "market research"],
        ),
        ("VM-08", &["商品运营", "电商平台", "listing"]),
        ("VM-09", &["企业客户", "销售线索", "b2b"]),
        ("VM-10", &["收件箱", "客户回复", "inbox"]),
    ];
    let mut matches = groups
        .iter()
        .filter(|(_, words)| words.iter().any(|word| text.contains(word)));
    let candidate = matches.next()?.0;
    matches.next().is_none().then_some(candidate)
}

fn budget_minor(amount: &str, currency: &str) -> Option<i64> {
    let digits = match currency {
        "USD" | "EUR" | "CNY" | "GBP" => 2,
        "JPY" => 0,
        _ => return None,
    };
    // Parse the entered digits before any decimal rounding can occur.
    let amount = amount.trim();
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    if (whole.is_empty() && fraction.is_empty())
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let fraction = fraction.trim_end_matches('0');
    if fraction.len() > digits as usize {
        return None;
    }
    let whole = if whole.is_empty() {
        0
    } else {
        whole.parse::<i64>().ok()?
    };
    let minor = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<i64>().ok()?
    };
    let fraction_digits = u32::try_from(fraction.len()).ok()?;
    whole
        .checked_mul(10_i64.pow(digits))?
        .checked_add(minor.checked_mul(10_i64.pow(digits - fraction_digits))?)
}

impl TaskDraft {
    fn edit_goal(&mut self, goal: String) {
        if self.goal != goal {
            self.goal = goal;
            self.route.clear();
            self.mode.clear();
            self.parent.clear();
            self.reviewing = false;
            self.show_errors = false;
        }
    }

    fn prepare(&mut self, routes: &[MissionContractEvidenceProjection]) {
        if self.route.is_empty()
            && let Some(route) = suggested_route(&self.goal)
                .and_then(|id| routes.iter().find(|route| route.mission_id == id))
        {
            self.route = route.mission_id.clone();
            self.mode = route.modes.first().cloned().unwrap_or_default();
        }
        self.reviewing = true;
        self.show_errors = false;
    }

    fn errors(
        &self,
        routes: &[MissionContractEvidenceProjection],
        parents: &[(MissionId, String)],
    ) -> Vec<(&'static str, &'static str)> {
        let mut errors = Vec::new();
        if self.goal.trim().is_empty() {
            errors.push(("mission-composer-input", "请先描述任务目标"));
        }
        let route = routes.iter().find(|route| route.mission_id == self.route);
        if route.is_none() {
            errors.push(("task-entry-route", "请选择要推进的任务方向"));
        }
        if !route.is_some_and(|route| route.modes.contains(&self.mode))
            || operating_mode_from_catalog_name(&self.mode).is_none()
        {
            errors.push(("task-entry-mode", "请选择任务的运行方式"));
        }
        if self.route == "VM-11" {
            if !parents.iter().any(|(id, _)| id.as_str() == self.parent) {
                errors.push(("task-entry-parent", "请选择本项目中要复盘的任务"));
            }
            return errors;
        }
        for (id, value, message) in [
            ("task-entry-market", self.market.as_str(), "请填写目标市场"),
            (
                "task-entry-audience",
                self.audience.as_str(),
                "请填写目标受众",
            ),
            (
                "task-entry-language",
                self.language.as_str(),
                "请选择内容语言",
            ),
            (
                "task-entry-timezone",
                self.timezone.as_str(),
                "请填写排期使用的时区",
            ),
        ] {
            if value.trim().is_empty() {
                errors.push((id, message));
            }
        }
        if budget_minor(&self.budget, &self.currency).is_none() {
            errors.push((
                "task-entry-budget",
                "请填写有效预算；日元使用整数，其他币种最多两位小数",
            ));
        }
        if Decimal::from_str_exact(self.target.trim())
            .ok()
            .is_none_or(|target| target <= Decimal::ZERO)
        {
            errors.push(("task-entry-target", "完成标准需大于 0"));
        }
        errors
    }

    fn request(
        &self,
        project_id: ProjectId,
        routes: &[MissionContractEvidenceProjection],
        parents: &[(MissionId, String)],
    ) -> Option<DesktopCatalogMissionRequest> {
        if !self.reviewing || !self.errors(routes, parents).is_empty() {
            return None;
        }
        Some(DesktopCatalogMissionRequest {
            project_id,
            manifest_id: self.route.clone(),
            mode: operating_mode_from_catalog_name(&self.mode)?,
            parent_mission_id: (self.route == "VM-11")
                .then(|| MissionId::from(self.parent.as_str())),
            title: None,
            goal: self.goal.trim().into(),
            market: self.market.trim().into(),
            language: self.language.clone(),
            audience: self.audience.trim().into(),
            timezone: self.timezone.trim().into(),
            currency: self.currency.clone(),
            budget_minor: if self.route == "VM-11" {
                0
            } else {
                budget_minor(&self.budget, &self.currency)?
            },
            kpis: catalog_kpi_contracts(
                &self.route,
                &self.metric,
                "",
                &self.target,
                "count",
                "at_least",
            )?,
        })
    }
}

#[component]
pub(crate) fn NewTaskEntry(
    project_id: ProjectId,
    project_name: String,
    routes: Vec<MissionContractEvidenceProjection>,
    parents: Vec<(MissionId, String)>,
    available: bool,
    model_ready: bool,
    model_label: String,
    submitting: bool,
    mut drafts: Signal<TaskDrafts>,
    mut expanded: Signal<bool>,
    on_create: EventHandler<DesktopCatalogMissionRequest>,
    on_open_settings: EventHandler<()>,
) -> Element {
    let storage_key = project_id.clone();
    let effect_key = project_id.clone();
    let mut form = use_signal(move || drafts.peek().get(&storage_key).cloned().unwrap_or_default());
    use_effect(move || {
        let current = form.read().clone();
        drafts.write().insert(effect_key.clone(), current);
    });
    if !available {
        // Keep the draft in memory, but remove all private fields from the DOM
        // as soon as project authorization is no longer available.
        return rsx! {
            section { class: "task-entry is-expanded", aria_label: "新任务暂不可用",
                div { class: "task-entry-review", role: "status",
                    strong { "解锁项目后继续" }
                    p { class: "task-entry-boundary", "草稿已保留在当前会话中，恢复项目访问后可继续编辑。" }
                }
            }
        };
    }
    let state = form.read().clone();
    let reviewing = state.reviewing;
    let errors = state.errors(&routes, &parents);
    let modes = routes
        .iter()
        .find(|route| route.mission_id == state.route)
        .map(|route| route.modes.clone())
        .unwrap_or_default();
    let route_choices = routes.clone();
    let action_routes = routes.clone();
    let action_parents = parents.clone();
    let has_errors = !errors.is_empty();
    let scope_locked = !available || submitting;
    let invalid = |id: &str| state.show_errors && errors.iter().any(|(field, _)| *field == id);
    let act = move |_| {
        if scope_locked {
            return;
        }
        if !form.peek().reviewing {
            if form.peek().goal.trim().is_empty() {
                restore_ui_focus("mission-composer-input");
                return;
            }
            form.write().prepare(&action_routes);
            expanded.set(true);
            restore_ui_focus("task-entry-route");
            return;
        }
        let issues = form.peek().errors(&action_routes, &action_parents);
        if let Some((field, _)) = issues.first() {
            form.write().show_errors = true;
            restore_ui_focus(field);
            return;
        }
        if !model_ready {
            on_open_settings.call(());
            return;
        }
        if let Some(request) =
            form.peek()
                .request(project_id.clone(), &action_routes, &action_parents)
        {
            on_create.call(request);
        }
    };
    rsx! {
        section {
            class: if reviewing { "task-entry is-reviewing" } else if expanded() { "task-entry is-expanded" } else { "task-entry" },
            aria_label: "描述并确认新任务",
            header { class: "task-entry-context",
                span { i {} "{project_name}" }
                small { if reviewing { "确认任务范围" } else { "新任务" } }
                if reviewing {
                    button { class: "task-text-action", onclick: move |_| { form.write().reviewing = false; restore_ui_focus("mission-composer-input"); }, "修改目标" }
                }
            }
            if reviewing {
                div { class: "task-entry-review",
                    p { class: "task-entry-goal", "{state.goal}" }
                    div { class: "task-entry-fields",
                        label { class: "task-entry-wide", r#for: "task-entry-route",
                            span { "任务方向" }
                            select { id: "task-entry-route", value: "{state.route}", disabled: scope_locked,
                                aria_invalid: invalid("task-entry-route"),
                                onmounted: move |_| restore_ui_focus("task-entry-route"),
                                onchange: move |event| {
                                    let id = event.value();
                                    let mode = route_choices.iter().find(|route| route.mission_id == id).and_then(|route| route.modes.first()).cloned().unwrap_or_default();
                                    let mut current = form.write(); current.route = id; current.mode = mode; current.parent.clear();
                                },
                                option { value: "", selected: state.route.is_empty(), "选择要推进的工作…" }
                                for route in routes { option { value: "{route.mission_id}", selected: state.route == route.mission_id, "{route_label(&route.mission_id)}" } }
                            }
                        }
                        if state.route == "VM-11" {
                            label { class: "task-entry-wide", r#for: "task-entry-parent", span { "要复盘的任务" }
                                select { id: "task-entry-parent", value: "{state.parent}", disabled: scope_locked,
                                    aria_invalid: invalid("task-entry-parent"), onchange: move |event| form.write().parent = event.value(),
                                    option { value: "", selected: state.parent.is_empty(), "选择当前项目中的任务…" }
                                    for (id, label) in parents { option { value: "{id}", selected: state.parent == id.as_str(), "{label}" } }
                                }
                                small { "沿用原任务的市场、预算与衡量标准。" }
                            }
                        } else {
                            label { r#for: "task-entry-market", span { "目标市场" }
                                input { id: "task-entry-market", value: "{state.market}", placeholder: "例如：美国、德国或日本", disabled: scope_locked, aria_invalid: invalid("task-entry-market"), oninput: move |event| form.write().market = event.value() }
                            }
                            label { r#for: "task-entry-language", span { "内容语言" }
                                select { id: "task-entry-language", value: "{state.language}", disabled: scope_locked, onchange: move |event| form.write().language = event.value(),
                                    for (id, label) in [("zh-CN", "简体中文"), ("en-US", "英语"), ("de-DE", "德语"), ("ja-JP", "日语"), ("fr-FR", "法语"), ("es-ES", "西班牙语")] {
                                        option { value: id, selected: state.language == id, "{label}" }
                                    }
                                }
                            }
                            label { class: "task-entry-wide", r#for: "task-entry-audience", span { "面向谁" }
                                input { id: "task-entry-audience", value: "{state.audience}", placeholder: "例如：喜欢户外活动的年轻消费者", disabled: scope_locked, aria_invalid: invalid("task-entry-audience"), oninput: move |event| form.write().audience = event.value() }
                            }
                        }
                    }
                    if state.route != "VM-11" { details { class: "task-entry-options",
                        summary { "运行方式、预算与完成标准" }
                        div { class: "task-entry-fields",
                            label { class: "task-entry-wide", r#for: "task-entry-mode", span { "运行方式" }
                                select { id: "task-entry-mode", value: "{state.mode}", disabled: scope_locked, onchange: move |event| form.write().mode = event.value(),
                                    if modes.is_empty() { option { value: "", "先选择任务方向" } }
                                    for mode in modes { option { value: "{mode}", selected: state.mode == mode, "{mode_label(&mode)}" } }
                                }
                            }
                            if state.route != "VM-11" {
                                label { r#for: "task-entry-currency", span { "预算币种" }
                                    select { id: "task-entry-currency", value: "{state.currency}", disabled: scope_locked, onchange: move |event| form.write().currency = event.value(),
                                        for (id, label) in [("USD", "美元 USD"), ("CNY", "人民币 CNY"), ("EUR", "欧元 EUR"), ("GBP", "英镑 GBP"), ("JPY", "日元 JPY")] {
                                            option { value: id, selected: state.currency == id, "{label}" }
                                        }
                                    }
                                }
                                label { r#for: "task-entry-budget", span { "预算上限（{state.currency}）" }
                                    input { id: "task-entry-budget", value: "{state.budget}", inputmode: "decimal", disabled: scope_locked, aria_invalid: invalid("task-entry-budget"), oninput: move |event| form.write().budget = event.value() }
                                }
                                label { r#for: "task-entry-metric", span { "衡量指标" }
                                    select { id: "task-entry-metric", value: "{state.metric}", disabled: scope_locked, onchange: move |event| form.write().metric = event.value(),
                                        for (id, label) in [("work_product_count", "可审阅成果数"), ("lead_qualified_count", "合格线索数"), ("conversion_count", "转化数")] {
                                            option { value: id, selected: state.metric == id, "{label}" }
                                        }
                                    }
                                }
                                label { r#for: "task-entry-target", span { "至少达到" }
                                    input { id: "task-entry-target", value: "{state.target}", inputmode: "decimal", disabled: scope_locked, aria_invalid: invalid("task-entry-target"), oninput: move |event| form.write().target = event.value() }
                                }
                                label { class: "task-entry-wide", r#for: "task-entry-timezone", span { "排期时区" }
                                    input { id: "task-entry-timezone", value: "{state.timezone}", placeholder: "例如：Asia/Shanghai", disabled: scope_locked, aria_invalid: invalid("task-entry-timezone"), oninput: move |event| form.write().timezone = event.value() }
                                }
                            }
                        }
                    } }
                    if state.route != "VM-11" {
                        p { class: "task-entry-summary", "{mode_label(&state.mode)} · {state.currency} {state.budget} 上限 · {metric_label(&state.metric)}至少 {state.target}" }
                    }
                    p { class: "task-entry-boundary", "发布、触达与其他外部操作会按任务权限单独确认。" }
                    if state.show_errors && has_errors {
                        div { class: "task-entry-errors", role: "alert",
                            for (_, message) in errors.clone() { p { "{message}" } }
                        }
                    }
                }
            } else {
                label { class: "task-entry-input-label", r#for: "mission-composer-input", "希望 Hartevo 帮你推进什么？" }
                textarea { id: "mission-composer-input", value: if available { state.goal.clone() } else { String::new() },
                    aria_label: "新任务目标", placeholder: "描述目标、受众和约束，其余可以逐步补充…", disabled: scope_locked,
                    onmounted: move |_| { if expanded() { restore_ui_focus("mission-composer-input"); } },
                    onfocus: move |_| expanded.set(true),
                    oninput: move |event| {
                        form.write().edit_goal(event.value());
                        let _ = document::eval("const input=document.getElementById('mission-composer-input');if(input){input.style.height='auto';input.style.height=`${Math.min(input.scrollHeight,160)}px`;}");
                    },
                    onkeydown: move |event| {
                        if crate::composer_should_submit(&event.key(),event.modifiers(),event.data.is_composing()) {
                            event.prevent_default(); let _ = document::eval("document.getElementById('mission-composer-send')?.click()");
                        }
                    },
                }
                if state.goal.is_empty() && available {
                    div { class: "task-entry-examples", aria_label: "任务示例",
                        for (label, goal) in [
                            ("研究市场机会", "研究新产品的市场机会，整理需求、竞争与建议。"),
                            ("准备社媒内容", "为新产品准备一周社媒内容，先给我草稿。"),
                            ("起草客户邮件", "为潜在客户起草介绍邮件，先审阅，不发送。"),
                        ] {
                            button { disabled: scope_locked, onclick: move |_| { form.write().edit_goal(goal.into()); expanded.set(true); restore_ui_focus("mission-composer-input"); }, "{label}" }
                        }
                    }
                }
            }
            footer {
                button { id: "runtime-profile-trigger", class: "task-entry-model", onclick: move |_| on_open_settings.call(()),
                    UiIcon { name: UiIconName::Sparkles, size: 14 }
                    span { if model_ready { "{model_label}" } else { "连接模型" } }
                    UiIcon { name: UiIconName::ChevronDown, size: 11 }
                }
                small { if !available { "解锁当前项目后即可创建任务" } else if reviewing && model_ready { "开始任务可能产生模型调用费用" } else if reviewing { "连接模型后回到这里继续" } else { "Enter 继续 · Shift Enter 换行" } }
                button { id: "mission-composer-send", class: "task-primary-action", disabled: scope_locked || state.goal.trim().is_empty(), onclick: act,
                    if submitting { "正在创建…" } else if !reviewing { "继续" } else if !model_ready && !has_errors { "设置模型并继续" } else { "确认并开始" }
                    if !submitting { UiIcon { name: UiIconName::ArrowUp, size: 14 } }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route() -> MissionContractEvidenceProjection {
        MissionContractEvidenceProjection {
            mission_id: "VM-04".into(),
            title: "Social Matrix Operator".into(),
            modes: vec!["campaign".into()],
            default_cadence: "weekly".into(),
            evidence_level: hartevo_catalog::EvidenceLevel::E0,
            status: hartevo_catalog::MissionEvidenceStatus::NotImplemented,
            failure_count: 0,
        }
    }

    #[test]
    fn task_creation_requires_review_current_catalog_and_complete_scope() {
        let mut form = TaskDraft {
            goal: "准备社媒内容".into(),
            market: "美国".into(),
            audience: "户外消费者".into(),
            budget: "12.34".into(),
            ..TaskDraft::default()
        };
        let project = ProjectId::from("project-a");
        let routes = [route()];
        assert!(form.request(project.clone(), &routes, &[]).is_none());
        form.prepare(&routes);
        let request = form.request(project.clone(), &routes, &[]).unwrap();
        assert_eq!(request.project_id, project);
        assert_eq!(request.budget_minor, 1234);
        assert_eq!(request.manifest_id, "VM-04");
        assert!(request.parent_mission_id.is_none());
        assert_eq!(request.kpis["work_product_count"].target, Decimal::ONE);
        assert!(form.request(ProjectId::from("p"), &[], &[]).is_none());
        form.mode = "continuous_operator".into();
        assert!(form.request(ProjectId::from("p"), &routes, &[]).is_none());
        form.mode = "campaign".into();
        form.audience.clear();
        assert!(form.request(ProjectId::from("p"), &routes, &[]).is_none());
    }

    #[test]
    fn editing_goal_invalidates_the_previous_suggestion_and_confirmation() {
        let mut form = TaskDraft {
            goal: "准备社媒内容".into(),
            ..TaskDraft::default()
        };
        form.prepare(&[route()]);
        assert_eq!(form.route, "VM-04");
        form.edit_goal("研究市场机会和邮件".into());
        assert!(!form.reviewing);
        assert!(form.route.is_empty());
        form.prepare(&[route()]);
        assert!(form.route.is_empty());
    }

    #[test]
    fn composer_drafts_keep_exact_scope_and_late_completions_preserve_edits() {
        let mut drafts = ComposerDrafts::default();
        let project = Some(ProjectId::from("p"));
        let a = drafts.slot((project.clone(), Some(MissionId::from("a"))));
        let b = drafts.slot((project.clone(), Some(MissionId::from("b"))));
        let other_project = drafts.slot((Some(ProjectId::from("q")), Some(MissionId::from("a"))));
        drafts.entries[a].1 = "submitted".into();
        drafts.entries[b].1 = "another task".into();
        drafts.entries[other_project].1 = "another project".into();
        assert_eq!(drafts.slot((project, Some(MissionId::from("a")))), a);
        drafts.entries[a].1 = "newer edit".into();
        drafts.clear_submission(a, "submitted");
        assert_eq!(drafts.entries[a].1, "newer edit");
        drafts.clear_submission(a, "newer edit");
        assert!(drafts.entries[a].1.is_empty());
        assert_eq!(drafts.entries[b].1, "another task");
        assert_eq!(drafts.entries[other_project].1, "another project");
    }

    #[test]
    fn task_suggestions_never_select_ambiguous_or_unrelated_routes() {
        assert_eq!(suggested_route("为新产品准备社媒内容"), Some("VM-04"));
        assert_eq!(suggested_route("市场研究和社媒内容"), None);
        assert_eq!(suggested_route("帮我做点事"), None);
        assert_eq!(suggested_route("批准付款"), None);
    }

    #[test]
    fn budget_conversion_is_exact_and_rejects_precision_loss_and_overflow() {
        assert_eq!(budget_minor("12.34", "USD"), Some(1234));
        assert_eq!(budget_minor("12.00", "JPY"), Some(12));
        assert_eq!(budget_minor("12.34", "JPY"), None);
        assert_eq!(budget_minor("1.001", "EUR"), None);
        assert_eq!(budget_minor("-1", "USD"), None);
        assert_eq!(budget_minor("92233720368547758.08", "USD"), None);
        assert_eq!(budget_minor("1", "UNKNOWN"), None);
        assert_eq!(
            budget_minor("0.000000000000000000000000000001", "USD"),
            None
        );
        assert_eq!(
            budget_minor("1.009999999999999999999999999999999", "USD"),
            None
        );
        assert_eq!(budget_minor("1e2", "USD"), None);
        assert_eq!(budget_minor("1_000", "USD"), None);
        assert_eq!(budget_minor("1.2.3", "USD"), None);
        assert_eq!(budget_minor(".50", "USD"), Some(50));
        assert_eq!(budget_minor("92233720368547758.07", "USD"), Some(i64::MAX));
    }

    #[test]
    fn locked_project_does_not_mount_private_confirmation_fields() {
        fn locked_entry() -> Element {
            let drafts = use_signal(|| {
                TaskDrafts::from([(
                    ProjectId::from("private-project"),
                    TaskDraft {
                        goal: "private-goal-secret".into(),
                        market: "private-market-secret".into(),
                        audience: "private-audience-secret".into(),
                        reviewing: true,
                        ..TaskDraft::default()
                    },
                )])
            });
            let expanded = use_signal(|| true);
            rsx! { NewTaskEntry {
                project_id: ProjectId::from("private-project"), project_name: "private-project-secret".to_owned(),
                routes: vec![route()], parents: vec![], available: false, model_ready: true,
                model_label: "model".to_owned(), submitting: false, drafts, expanded,
                on_create: |_| {}, on_open_settings: |()| {},
            } }
        }
        fn inspect_mounted(node: &VNode, dom: &VirtualDom, output: &mut String) {
            use dioxus::dioxus_core::DynamicNode;
            use std::fmt::Write as _;
            write!(output, "{:?} {:?}", node.template, node.dynamic_attrs).unwrap();
            for (index, child) in node.dynamic_nodes.iter().enumerate() {
                match child {
                    DynamicNode::Component(component) => {
                        if let Some(scope) = component.mounted_scope(index, node, dom) {
                            inspect_mounted(scope.root_node(), dom, output);
                        }
                    }
                    DynamicNode::Fragment(children) => {
                        for child in children {
                            inspect_mounted(child, dom, output);
                        }
                    }
                    DynamicNode::Text(text) => output.push_str(&text.value),
                    DynamicNode::Placeholder(_) => {}
                }
            }
        }
        let mut dom = VirtualDom::new(locked_entry);
        let mutations = dom.rebuild_to_vec();
        let mut rendered = format!("{mutations:?}");
        inspect_mounted(dom.base_scope().root_node(), &dom, &mut rendered);
        assert!(rendered.contains("解锁项目后继续"));
        for private in [
            "private-goal-secret",
            "private-market-secret",
            "private-audience-secret",
            "private-project-secret",
            "task-entry-route",
        ] {
            assert!(!rendered.contains(private), "locked DOM exposed {private}");
        }
    }

    #[test]
    fn a_late_creation_does_not_clear_another_project_or_newer_draft() {
        let a = ProjectId::from("a");
        let b = ProjectId::from("b");
        let mut drafts = TaskDrafts::from([
            (
                a.clone(),
                TaskDraft {
                    goal: "newer goal".into(),
                    ..TaskDraft::default()
                },
            ),
            (
                b.clone(),
                TaskDraft {
                    goal: "other project".into(),
                    ..TaskDraft::default()
                },
            ),
        ]);
        clear_created_draft(&mut drafts, &a, "old goal");
        assert_eq!(drafts.len(), 2);
        clear_created_draft(&mut drafts, &a, "newer goal");
        assert!(!drafts.contains_key(&a));
        assert_eq!(drafts[&b].goal, "other project");
    }
}
