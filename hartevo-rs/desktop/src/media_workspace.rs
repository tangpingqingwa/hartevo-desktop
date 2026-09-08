use crate::data_plane::media::{DesktopMediaConfiguration, DesktopMediaRequest};
use crate::data_plane::{
    DesktopDataError, DesktopDataPlane, DesktopLoadState, DesktopSnapshot,
    DesktopWorkProductAdoptionRequest,
};
use base64::Engine;
use dioxus::prelude::*;
use hartevo_application::MissionProjection;
use hartevo_domain_kernel::media_generation::{
    MediaGeneration, MediaGenerationState, MediaKind, MediaProvider,
};
use hartevo_domain_kernel::{MissionId, MissionStage, ProjectId, WorkProductStatus};

fn failure(error: DesktopDataError) -> String {
    match error {
        DesktopDataError::Media(code) => media_failure_message(&code).into(),
        DesktopDataError::WorkProductActionStale => "素材版本已变化，请刷新后查看当前版本。".into(),
        _ => "素材操作未完成，请确认项目仍已解锁后重试。".into(),
    }
}

fn media_failure_message(code: &str) -> &'static str {
    match code {
        "MEDIA_FORMAT_MISMATCH" => "返回素材的尺寸或时长不符合要求，已保留供检查。",
        "MEDIA_STALE_SOURCE" | "MEDIA_REQUEST_CONFLICT" => {
            "来源版本已改变，请查看当前素材后重新选择。"
        }
        "MEDIA_CONFIG_REQUIRED" | "MEDIA_CONFIG_INVALID" | "MEDIA_CREDENTIAL_MISSING" => {
            "生成模型尚未配置可用凭据。"
        }
        "MEDIA_CONNECTION_CHANGED" => "模型连接已变化，请恢复原连接后取回视频。",
        "MEDIA_TRANSPORT_UNCERTAIN" => "请求结果不明确，未重复发起生成。",
        "MEDIA_ASSET_ORIGIN_NOT_ALLOWED" => "模型返回的下载地址尚不受此连接支持。",
        "MEDIA_MISSION_NOT_RUNNING" => "当前任务已停止，请恢复任务后生成素材。",
        "MEDIA_CONTEXT_REVOKED" => "生成期间项目被锁定；返回素材已隔离保存，不能直接采用。",
        _ => "素材操作未完成；已记录的任务仍可查看。",
    }
}

fn state_label(state: MediaGenerationState) -> &'static str {
    match state {
        MediaGenerationState::Submitting => "请求已记录，结果尚不明确",
        MediaGenerationState::Submitted => "视频生成中，可继续取回原任务",
        MediaGenerationState::Ready => "待审阅",
        MediaGenerationState::Rejected => "未通过格式或版本检查",
        MediaGenerationState::Uncertain => "请求结果不明，未自动重发",
        MediaGenerationState::Failed => "生成失败",
    }
}

enum Action {
    Generate(DesktopMediaRequest),
    Poll(ProjectId, MissionId, String),
    Adopt(String, DesktopWorkProductAdoptionRequest),
}

fn execute(action: Action) -> Result<(Option<MediaGeneration>, DesktopSnapshot), String> {
    let plane = DesktopDataPlane::persistent().map_err(failure)?;
    let job = match action {
        Action::Generate(request) => Some(plane.media_generate_os(request).map_err(failure)?),
        Action::Poll(project, mission, id) => Some(
            plane
                .media_poll_os(&project, &mission, &id)
                .map_err(failure)?,
        ),
        Action::Adopt(id, request) => {
            return Ok((None, plane.media_adopt_os(&id, request).map_err(failure)?));
        }
    };
    match plane.load_os(chrono::Utc::now()).map_err(failure)? {
        DesktopLoadState::Ready(snapshot) => Ok((job, *snapshot)),
        DesktopLoadState::Uninitialized { .. } => Err("项目需要重新解锁。".into()),
    }
}

fn load_workspace(
    project: &ProjectId,
    mission: &MissionId,
    requested: Option<&hartevo_domain_kernel::WorkProductId>,
) -> Result<(Vec<MediaGeneration>, DesktopSnapshot), String> {
    let plane = DesktopDataPlane::persistent().map_err(failure)?;
    let DesktopLoadState::Ready(snapshot) = plane.load_os(chrono::Utc::now()).map_err(failure)?
    else {
        return Err("项目需要重新解锁。".into());
    };
    let mut jobs = plane.media_jobs_os(project, mission).map_err(failure)?;
    if let Some(product_id) = requested {
        let generation = snapshot
            .inventory
            .projects
            .iter()
            .find(|p| &p.project_id == project)
            .and_then(|p| p.missions.iter().find(|m| &m.mission_id == mission))
            .and_then(|m| {
                m.work_products
                    .iter()
                    .find(|p| &p.work_product_id == product_id)
            })
            .and_then(crate::product_experience::media_identity)
            .ok_or("所选素材已变化，请返回任务重新打开。")?;
        if !jobs.iter().any(|job| job.request.id == generation.0) {
            // The recent history is bounded to 50 rows. An explicit result must
            // still open its own generation, never a different recent result.
            jobs.push(
                plane
                    .media_job_os(project, mission, &generation.0)
                    .map_err(failure)?,
            );
        }
    }
    Ok((jobs, *snapshot))
}

fn export_bytes(
    url: &str,
    metadata: &hartevo_domain_kernel::media_generation::MediaAssetMetadata,
) -> Result<Vec<u8>, String> {
    let prefix = format!("data:{};base64,", metadata.media_type);
    let encoded = url
        .strip_prefix(&prefix)
        .ok_or("素材类型已变化，请重新打开。")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "素材暂时无法读取。")?;
    metadata
        .validate_bytes(&bytes)
        .map_err(|_| "素材校验失败，未导出文件。")?;
    Ok(bytes)
}

fn export_asset(
    job: MediaGeneration,
    selected: Signal<Option<String>>,
    mut notice: Signal<String>,
) {
    spawn(async move {
        let generation_id = job.request.id.clone();
        let Some(metadata) = job.asset else {
            return;
        };
        let extension = match metadata.media_type.as_str() {
            "image/jpeg" => "jpg",
            "image/png" => "png",
            "video/mp4" => "mp4",
            _ => return,
        };
        let filename = format!(
            "Hartevo-{}.{}",
            job.created_at.format("%Y%m%d-%H%M%S"),
            extension
        );
        let Some(destination) = rfd::AsyncFileDialog::new()
            .set_title("导出素材")
            .add_filter("创意素材", &[extension])
            .set_file_name(filename)
            .save_file()
            .await
        else {
            return;
        };
        let path = destination.path().to_owned();
        let result = tokio::task::spawn_blocking(move || {
            // Recheck the unlocked project and exact artifact after the save dialog.
            let url = DesktopDataPlane::persistent()
                .and_then(|plane| {
                    plane.media_preview_os(
                        &job.request.project_id,
                        &job.request.mission_id,
                        &job.request.id,
                    )
                })
                .map_err(failure)?;
            let bytes = export_bytes(&url, &metadata)?;
            std::fs::write(path, bytes)
                .map_err(|_| "无法保存到所选位置，请检查文件夹权限。".to_owned())
        })
        .await;
        if selected.peek().as_ref() == Some(&generation_id) {
            notice.set(match result {
                Ok(Ok(())) => "素材已导出。".into(),
                Ok(Err(error)) => error,
                Err(_) => "导出未完成，请重试。".into(),
            });
        }
    });
}

fn start_action(
    action: Action,
    mut busy: Signal<bool>,
    mut notice: Signal<String>,
    mut refresh: Signal<u64>,
    mut selected: Signal<Option<String>>,
    on_changed: EventHandler<DesktopSnapshot>,
) {
    if *busy.peek() {
        return;
    }
    busy.set(true);
    notice.set("正在处理素材…".into());
    spawn(async move {
        let mut action = action;
        let started = std::time::Instant::now();
        loop {
            let result = tokio::task::spawn_blocking(move || execute(action)).await;
            match result {
                Ok(Ok((job, snapshot))) => {
                    on_changed.call(snapshot);
                    refresh += 1;
                    if let Some(job) = job {
                        selected.set(Some(job.request.id.clone()));
                        notice.set(state_label(job.state).into());
                        if job.state == MediaGenerationState::Submitted
                            && started.elapsed().as_secs() < 180
                        {
                            action = Action::Poll(
                                job.request.project_id,
                                job.request.mission_id,
                                job.request.id,
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                            continue;
                        }
                    } else {
                        notice.set("已采用当前素材。".into());
                    }
                }
                Ok(Err(error)) => {
                    notice.set(error);
                    refresh += 1;
                }
                Err(_) => {
                    notice.set("素材协调任务中断，已保存的任务可在重开后查看。".into());
                    refresh += 1;
                }
            }
            break;
        }
        busy.set(false);
    });
}

fn current_product<'a>(
    mission: &'a MissionProjection,
    job: &MediaGeneration,
) -> Option<&'a hartevo_application::WorkProductProjection> {
    mission
        .work_products
        .iter()
        .find(|p| p.work_product_id == job.work_product_id)
        .filter(|p| {
            crate::product_experience::media_identity(p).is_some_and(|(id, _)| id == job.request.id)
        })
}

fn preferred_job<'a>(
    rows: &'a [MediaGeneration],
    mission: &MissionProjection,
    requested: Option<&hartevo_domain_kernel::WorkProductId>,
) -> Option<&'a MediaGeneration> {
    if let Some(id) = requested {
        return rows
            .iter()
            .find(|job| &job.work_product_id == id && current_product(mission, job).is_some());
    }
    rows.iter()
        .find(|job| {
            current_product(mission, job).is_some() && job.state == MediaGenerationState::Ready
        })
        .or_else(|| rows.first())
}

#[component]
pub(crate) fn MediaWorkspace(
    mission: MissionProjection,
    initial_work_product_id: Option<hartevo_domain_kernel::WorkProductId>,
    on_changed: EventHandler<DesktopSnapshot>,
) -> Element {
    let mut prompt = use_signal(String::new);
    let mut model_choice = use_signal(|| "grok-image".to_owned());
    let mut revises = use_signal(|| None::<String>);
    let selected = use_signal(|| None::<String>);
    let mut selected_writer = selected;
    let busy = use_signal(|| false);
    let mut notice = use_signal(String::new);
    let mut refresh = use_signal(|| 0u64);
    let mut viewed = use_signal(|| None::<String>);
    let mut show_generator = use_signal(|| false);
    let scope = use_hook(|| {
        (
            mission.project_id.clone(),
            mission.mission_id.clone(),
            initial_work_product_id.clone(),
        )
    });
    let jobs = use_resource(move || {
        let _ = refresh();
        let (project, mission, requested) = scope.clone();
        async move {
            tokio::task::spawn_blocking(move || {
                load_workspace(&project, &mission, requested.as_ref())
            })
            .await
            .unwrap_or_else(|_| Err("暂时无法读取素材任务。".into()))
        }
    });
    let rows = jobs
        .read_unchecked()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .map(|(rows, _)| rows.clone())
        .unwrap_or_default();
    let initial_selection = use_hook(|| (mission.clone(), initial_work_product_id));
    use_effect(move || {
        if let Some(Ok((rows, snapshot))) = jobs.read().as_ref() {
            if selected.peek().is_none() {
                let current = snapshot
                    .inventory
                    .projects
                    .iter()
                    .find(|p| p.project_id == initial_selection.0.project_id)
                    .and_then(|p| {
                        p.missions
                            .iter()
                            .find(|m| m.mission_id == initial_selection.0.mission_id)
                    });
                selected_writer.set(
                    current
                        .and_then(|m| preferred_job(rows, m, initial_selection.1.as_ref()))
                        .map(|job| job.request.id.clone()),
                );
                if rows.is_empty() {
                    show_generator.set(true);
                }
            }
            on_changed.call(snapshot.clone());
        }
    });
    let load_error = jobs
        .read_unchecked()
        .as_ref()
        .and_then(|r| r.as_ref().err())
        .cloned();
    let (kind, provider) = match model_choice().as_str() {
        "gpt-image" => (MediaKind::Image, MediaProvider::OpenAi),
        "grok-video" => (MediaKind::Video, MediaProvider::Grok),
        _ => (MediaKind::Image, MediaProvider::Grok),
    };
    let configured = DesktopMediaConfiguration::discover(kind, provider).is_ok();
    let can_generate = configured
        && mission.stage == MissionStage::Running
        && !busy()
        && prompt().len() <= 4096
        && !prompt().trim().is_empty();
    let generate_mission = mission.clone();
    let selected_job = rows
        .iter()
        .find(|j| selected().as_ref() == Some(&j.request.id))
        .cloned();
    let (current, history): (Vec<_>, Vec<_>) = rows.into_iter().partition(|job| {
        current_product(&mission, job).is_some()
            || matches!(
                job.state,
                MediaGenerationState::Submitted | MediaGenerationState::Submitting
            )
    });
    rsx! {
        section {class:"media-workspace",aria_label:"创意素材",
            div {class:"media-workspace-heading",
                h3 {"创意素材"}
                button {class:"task-text-action",disabled:busy(),onclick:move |_|{revises.set(None);prompt.set(String::new());show_generator.set(true);},"＋ 新建素材"}
            }
            if !current.is_empty() {
                nav {class:"media-current-choices",aria_label:"当前素材",
                    for job in current {
                        {
                            let id = job.request.id.clone();
                            let selected = selected().as_ref() == Some(&id);
                            let status = current_product(&mission,&job).map_or_else(||state_label(job.state), |p| crate::product_experience::result_status(&p.adoption_status));
                            let kind = if job.request.kind == MediaKind::Image {"图片"} else {"视频"};
                            rsx! {button {class:if selected {"active"} else {""},aria_pressed:selected,onclick:move |_|{
                                if selected_writer.peek().as_ref() != Some(&id) {viewed.set(None);notice.set(String::new());selected_writer.set(Some(id.clone()));}
                            },strong {"{kind}"} span {"{status}"}}}
                        }
                    }
                }
            }
            if let Some(job) = selected_job {
                {
                    let id = job.request.id.clone();
                    let product = current_product(&mission,&job);
                    let status = product.map_or_else(|| if job.state == MediaGenerationState::Ready {"历史版本"} else {state_label(job.state)}, |p| crate::product_experience::result_status(&p.adoption_status));
                    let adoption = product.filter(|p| p.adoption_status == WorkProductStatus::ReadyForReview && job.state == MediaGenerationState::Ready)
                        .map(|p| DesktopWorkProductAdoptionRequest {project_id:mission.project_id.clone(),mission_id:mission.mission_id.clone(),
                            work_product_id:p.work_product_id.clone(),expected_mission_revision:mission.revision,
                            expected_work_product_revision:p.work_product_revision,expected_manifest_version:p.manifest_version});
                    let adopt_enabled = adoption.is_some() && viewed().as_ref() == Some(&id) && !busy();
                    let can_revise = job.state == MediaGenerationState::Rejected || adoption.is_some();
                    let revise_id = id.clone();
                    let poll_id = id.clone();
                    let loaded_id = id.clone();
                    let failed_id = id.clone();
                    let prompt_copy = job.request.prompt.clone();
                    let export_job = job.clone();
                    let job_choice = match (job.request.kind,job.request.provider) {(MediaKind::Video,_)=>"grok-video",(_,MediaProvider::OpenAi)=>"gpt-image",_=>"grok-image"};
                    let scope = (mission.project_id.clone(),mission.mission_id.clone());
                    rsx! {
                        article {class:"media-selected-result",key:"selected-{id}",
                            div {class:"media-selected-meta",strong {"{status}"} span {{job.created_at.format("%m月%d日 %H:%M").to_string()}}}
                            if job.asset.is_some() {
                                MediaAssetPreview {key:"{id}",project_id:mission.project_id.clone(),mission_id:mission.mission_id.clone(),id:id.clone(),kind:job.request.kind,
                                    on_loaded:move |()|viewed.set(Some(loaded_id.clone())),
                                    on_failed:move |()|{if viewed.peek().as_ref() == Some(&failed_id) {viewed.set(None);}}}
                            }
                            if let Some(code) = &job.failure_code {p {class:"media-status error",role:"status","{media_failure_message(code)}"}}
                            div {class:"media-actions",
                                if job.asset.is_some() {
                                    button {class:"task-secondary-action",disabled:busy(),onclick:move |_|export_asset(export_job.clone(),selected,notice),"导出素材"}
                                }
                                if adoption.is_some() {
                                    button {class:"task-primary-action",disabled:!adopt_enabled,aria_label:"采用预览素材",onclick:move |_|{
                                        if let Some(request) = adoption.clone() {start_action(Action::Adopt(id.clone(),request),busy,notice,refresh,selected,on_changed);}
                                    },"采用此素材"}
                                }
                                if job.asset.is_some() || can_revise {
                                    button {class:"task-secondary-action",disabled:busy(),onclick:move |_|{
                                        prompt.set(prompt_copy.clone());revises.set(can_revise.then(||revise_id.clone()));model_choice.set(job_choice.into());show_generator.set(true);
                                    },if can_revise {"修改描述"} else {"再做一版"}}
                                }
                                if job.state == MediaGenerationState::Submitted {
                                    button {class:"task-primary-action",disabled:busy(),onclick:move |_|start_action(Action::Poll(scope.0.clone(),scope.1.clone(),poll_id.clone()),busy,notice,refresh,selected,on_changed),"取回视频"}
                                }
                            }
                            details {class:"media-result-details",summary {"画面要求与生成信息"} p {class:"media-prompt","{job.request.prompt}"} p {class:"media-status","{job.request.model}"}
                                if let Some(asset) = &job.asset {p {class:"media-status","{asset.width} × {asset.height}"}}
                            }
                        }
                    }
                }
            }
            if show_generator() {
                section {class:"media-create-form",aria_label:"生成新素材",
                    onmounted:move |_|{let _ = dioxus::document::eval("requestAnimationFrame(() => {const input = document.getElementById('media-generation-prompt'); input?.scrollIntoView({block:'nearest'}); input?.focus();})");},
                    h4 {if revises().is_some() {"调整素材"} else {"生成新素材"}}
                    label {r#for:"media-model-choice","图片或视频"}
                    select {id:"media-model-choice",value:"{model_choice}",disabled:busy(),onchange:move |e|{model_choice.set(e.value());revises.set(None);},
                        option {value:"grok-image","Grok · 图片 1024 × 1024"}
                        option {value:"gpt-image","GPT · 图片 1024 × 1024"}
                        option {value:"grok-video","Grok · 视频 3 秒 / 480p"}
                    }
                    label {r#for:"media-generation-prompt","描述画面与要求"}
                    textarea {id:"media-generation-prompt",value:"{prompt}",maxlength:4096,disabled:busy(),placeholder:"主体、场景、色调和构图，例如：绿色水瓶置于浅色石面，柔和自然光。",oninput:move |e|prompt.set(e.value())}
                    if !configured {p {class:"media-status error","此模型尚未连接，请先配置生成模型凭据。"}}
                    if prompt().len() > 4096 {p {class:"media-status error",role:"status","描述过长，请精简后再生成。"}}
                    p {class:"media-status","生成会调用所选模型并产生费用。已有成果会保留。"}
                    div {class:"media-actions",
                        button {class:"task-primary-action",disabled:!can_generate,aria_label:"生成任务素材",onclick:move |_|{
                            let request = DesktopMediaRequest {id:format!("creative-{}",chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()),
                                project_id:generate_mission.project_id.clone(),mission_id:generate_mission.mission_id.clone(),expected_mission_revision:generate_mission.revision,
                                prompt:prompt(),kind,provider,revises_job_id:revises()};
                            show_generator.set(false);start_action(Action::Generate(request),busy,notice,refresh,selected,on_changed);
                        },if busy() {"正在生成…"} else {"生成素材"}}
                        button {class:"task-secondary-action",disabled:busy(),onclick:move |_|{revises.set(None);show_generator.set(false);},"取消"}
                    }
                }
            }
            if !notice().is_empty() {p {class:"media-status",role:"status",aria_live:"polite","{notice}"}}
            if let Some(error) = load_error {p {class:"media-status error",role:"alert","{error}"}}
            if !history.is_empty() {
                details {class:"media-history",summary {"历史版本与未通过检查的素材（{history.len()}）"}
                    for job in history {
                        {
                            let id = job.request.id.clone();
                            let status = if job.state == MediaGenerationState::Ready {"历史版本"} else {state_label(job.state)};
                            rsx! {button {class:"media-history-row",onclick:move |_|{
                                if selected_writer.peek().as_ref() != Some(&id) {viewed.set(None);notice.set(String::new());selected_writer.set(Some(id.clone()));}
                            },strong {"{job.request.model}"} span {"{status}"} small {{job.created_at.format("%m-%d %H:%M").to_string()}}}}
                        }
                    }
                }
            }
            button {class:"task-text-action media-refresh",disabled:busy(),onclick:move |_|refresh+=1,"刷新素材"}
        }
    }
}

#[component]
pub(crate) fn MediaAssetPreview(
    project_id: ProjectId,
    mission_id: MissionId,
    id: String,
    kind: MediaKind,
    on_loaded: EventHandler<()>,
    on_failed: EventHandler<()>,
) -> Element {
    let resource = use_resource(move || {
        let (project, mission, id) = (project_id.clone(), mission_id.clone(), id.clone());
        async move {
            tokio::task::spawn_blocking(move || {
                DesktopDataPlane::persistent()
                    .and_then(|plane| plane.media_preview_os(&project, &mission, &id))
                    .map_err(failure)
            })
            .await
            .unwrap_or_else(|_| Err("素材暂时无法打开。".into()))
        }
    });
    let mut decode_failed = use_signal(|| false);
    match resource.read_unchecked().as_ref() {
        Some(Ok(url)) if !decode_failed() => rsx! {
            if kind == MediaKind::Image { img {class:"media-asset",src:"{url}",alt:"当前生成图片",onload:move |_|on_loaded.call(()),onerror:move |_|{decode_failed.set(true);on_failed.call(());}} }
            else { video {class:"media-asset",src:"{url}",controls:true,preload:"auto",aria_label:"当前生成视频",onloadeddata:move |_|on_loaded.call(()),onerror:move |_|{decode_failed.set(true);on_failed.call(());}} }
        },
        Some(Err(message)) => rsx! {p {class:"media-status error","{message}"}},
        _ if decode_failed() => rsx! {p {class:"media-status error","素材无法解码，不能采用。"}},
        _ => rsx! {p {class:"media-status","正在加载本地素材…"}},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hartevo_domain_kernel::media_generation::{MediaAssetMetadata, MediaGenerationRequest};
    use hartevo_domain_kernel::{TenantId, WorkProductId};
    use sha2::{Digest, Sha256};

    fn job(mission: &MissionProjection, id: &str, state: MediaGenerationState) -> MediaGeneration {
        let now = chrono::Utc::now();
        MediaGeneration {
            tenant_id: TenantId::from("media-selection-test"),
            request: MediaGenerationRequest {
                id: id.into(),
                project_id: mission.project_id.clone(),
                mission_id: mission.mission_id.clone(),
                expected_mission_revision: mission.revision,
                kind: MediaKind::Image,
                provider: MediaProvider::Grok,
                model: "test-image".into(),
                endpoint_digest: "a".repeat(64),
                prompt: "test creative".into(),
                revises_job_id: None,
            },
            revision: 1,
            state,
            provider_request_id: None,
            work_product_id: WorkProductId::from(id),
            source_work_product_revision: None,
            source_manifest_version: None,
            asset: None,
            failure_code: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn opening_an_exact_result_selects_its_current_generation_over_newer_failures() {
        let (_, mut mission) =
            crate::result_adoption_surface::tests::project_and_mission(WorkProductStatus::Accepted);
        mission.work_products[0].work_product_type = "generated_image".into();
        mission.work_products[0].preview_text = r#"{"generationId":"current-image"}"#.into();
        let product_id = mission.work_products[0].work_product_id.clone();
        let failed = job(&mission, "newer-failed", MediaGenerationState::Rejected);
        let mut current = job(&mission, "current-image", MediaGenerationState::Ready);
        current.work_product_id = product_id.clone();
        let mut old = job(&mission, "old-image", MediaGenerationState::Ready);
        old.work_product_id = product_id.clone();
        let rows = vec![failed, old, current];
        assert_eq!(
            preferred_job(&rows, &mission, None).unwrap().request.id,
            "current-image"
        );
        assert_eq!(
            preferred_job(&rows, &mission, Some(&product_id))
                .unwrap()
                .request
                .id,
            "current-image"
        );
        assert!(current_product(&mission, &rows[1]).is_none());
        assert!(preferred_job(&[], &mission, Some(&product_id)).is_none());
        assert!(preferred_job(&rows[..2], &mission, Some(&product_id)).is_none());
        assert!(preferred_job(&rows, &mission, Some(&WorkProductId::from("not-loaded"))).is_none());
    }

    #[test]
    fn export_requires_the_same_mime_bytes_and_digest_as_the_selected_asset() {
        let bytes = b"verified local asset";
        let metadata = MediaAssetMetadata {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            media_type: "image/png".into(),
            byte_length: bytes.len(),
            width: 1,
            height: 1,
            duration_millis: None,
        };
        let url = format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(bytes)
        );
        assert_eq!(export_bytes(&url, &metadata).unwrap(), bytes);
        assert!(export_bytes(&url.replace("image/png", "video/mp4"), &metadata).is_err());
        assert!(export_bytes("data:image/png;base64,Y2hhbmdlZA==", &metadata).is_err());
        assert!(export_bytes("https://example.invalid/asset.png", &metadata).is_err());
    }
}
