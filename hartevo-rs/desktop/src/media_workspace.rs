use crate::data_plane::media::{DesktopMediaConfiguration, DesktopMediaRequest};
use crate::data_plane::{
    DesktopDataError, DesktopDataPlane, DesktopLoadState, DesktopSnapshot,
    DesktopWorkProductAdoptionRequest,
};
use dioxus::prelude::*;
use hartevo_application::MissionProjection;
use hartevo_domain_kernel::media_generation::{
    MediaGeneration, MediaGenerationState, MediaKind, MediaProvider,
};
use hartevo_domain_kernel::{MissionId, MissionStage, ProjectId, WorkProductStatus};

const STYLE: &str = ".media-workspace{border-bottom:1px solid var(--line,#dce2dc);padding:0 0 20px;margin-bottom:24px}.media-workspace h3{margin:0 0 12px;font-size:16px}.media-workspace label{display:block;margin:12px 0 6px;font-size:12px}.media-workspace textarea,.media-workspace select{box-sizing:border-box;width:100%;border:1px solid #cbd3cc;border-radius:6px;background:#fafbf8;color:#213e32;padding:9px;font:inherit;font-size:13px}.media-workspace textarea{min-height:106px;resize:vertical}.media-workspace .media-actions{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}.media-status{font-size:12px;line-height:1.6;color:#53645a}.media-status.error{color:#a44329}.media-job{padding:12px 0;border-top:1px solid #dce2dc}.media-job button{margin:8px 8px 0 0}.media-job.selected{border-left:3px solid #315c45;padding-left:10px}.media-asset{width:100%;border-radius:6px;max-height:420px;object-fit:contain;background:#eef0eb}.media-generation-list{margin-top:16px}.media-prompt{white-space:pre-wrap;font-size:12px;line-height:1.5}.media-job small{display:block;font-size:11px;color:#627368;margin-top:5px}";

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
) -> Result<(Vec<MediaGeneration>, DesktopSnapshot), String> {
    let plane = DesktopDataPlane::persistent().map_err(failure)?;
    let DesktopLoadState::Ready(snapshot) = plane.load_os(chrono::Utc::now()).map_err(failure)?
    else {
        return Err("项目需要重新解锁。".into());
    };
    let jobs = plane.media_jobs_os(project, mission).map_err(failure)?;
    Ok((jobs, *snapshot))
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

#[component]
pub(crate) fn MediaWorkspace(
    mission: MissionProjection,
    on_changed: EventHandler<DesktopSnapshot>,
) -> Element {
    let mut prompt = use_signal(String::new);
    let mut model_choice = use_signal(|| "grok-image".to_owned());
    let mut revises = use_signal(|| None::<String>);
    let selected = use_signal(|| None::<String>);
    let mut selected_writer = selected;
    let busy = use_signal(|| false);
    let notice = use_signal(String::new);
    let mut refresh = use_signal(|| 0u64);
    let mut viewed = use_signal(|| None::<String>);
    let scope = use_hook(|| (mission.project_id.clone(), mission.mission_id.clone()));
    let jobs = use_resource(move || {
        let _ = refresh();
        let (project, mission) = scope.clone();
        async move {
            tokio::task::spawn_blocking(move || load_workspace(&project, &mission))
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
    use_effect(move || {
        if let Some(Ok((rows, snapshot))) = jobs.read().as_ref() {
            if selected.peek().is_none() {
                selected_writer.set(rows.first().map(|job| job.request.id.clone()));
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
        && !prompt().trim().is_empty();
    let generate_mission = mission.clone();
    rsx! {
        section { class: "media-workspace", aria_label: "Mission 创意素材",
            style { "{STYLE}" }
            h3 { "创意素材" }
            p { class: "media-status", "为当前任务生成图片或短视频，查看画面后采用。" }
            label { r#for: "media-model-choice", "生成模型" }
            select { id: "media-model-choice", value: "{model_choice}", disabled: busy(),
                onchange: move |e|{model_choice.set(e.value());revises.set(None);},
                option { value: "grok-image", "Grok · 图片 1024 × 1024" }
                option { value: "gpt-image", "GPT · 图片 1024 × 1024" }
                option { value: "grok-video", "Grok · 视频 3 秒 / 480p" }
            }
            label { r#for: "media-generation-prompt", "描述画面与要求" }
            textarea { id: "media-generation-prompt", value: "{prompt}", maxlength: 4096, disabled: busy(),
                placeholder: "例如：绿色水瓶置于浅色石面，柔和自然光，不出现文字或标志。",
                oninput: move |e|prompt.set(e.value()),
            }
            if revises().is_some() { p { class: "media-status", "正在调整所选素材的描述；本次将重新生成一个版本。" } }
            if !configured { p { class: "media-status", "此模型尚未配置凭据。" } }
            div { class: "media-actions",
                button { class: "quiet-button", disabled: !can_generate, aria_label: "生成任务素材",
                    onclick: move |_| {
                        let request = DesktopMediaRequest {id:format!("creative-{}",chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()),
                            project_id:generate_mission.project_id.clone(),mission_id:generate_mission.mission_id.clone(),
                            expected_mission_revision:generate_mission.revision,kind,provider,prompt:prompt(),revises_job_id:revises()};
                        revises.set(None);
                        start_action(Action::Generate(request),busy,notice,refresh,selected,on_changed);
                    },
                    if busy() { "生成中…" } else if revises().is_some() { "生成新版本" } else { "生成素材" }
                }
                if revises().is_some() { button {class:"quiet-button",disabled:busy(),onclick:move |_|revises.set(None),"取消修改"} }
                button {class:"quiet-button",disabled:busy(),onclick:move |_|refresh+=1,"刷新素材"}
            }
            if !notice().is_empty() { p {class:"media-status",role:"status", "{notice}"} }
            if let Some(error) = load_error { p {class:"media-status error",role:"alert","{error}"} }
            div {class:"media-generation-list",
                for job in rows {
                    {
                        let id = job.request.id.clone();
                        let generated_at = job.created_at.format("%m-%d %H:%M:%S").to_string();
                        let is_selected = selected().as_ref() == Some(&id);
                        let select_id = id.clone();
                        let revise_id = id.clone();
                        let poll_id = id.clone();
                        let prompt_copy = job.request.prompt.clone();
                        let job_choice = match (job.request.kind,job.request.provider) {
                            (MediaKind::Video,_)=>"grok-video",(_,MediaProvider::OpenAi)=>"gpt-image",_=>"grok-image"
                        };
                        let scope = (mission.project_id.clone(),mission.mission_id.clone());
                        let preview_scope = scope.clone();
                        let preview_id = id.clone();
                        let loaded_id = id.clone();
                        let failed_id = id.clone();
                        let current_product = mission.work_products.iter().find(|p|p.work_product_id == job.work_product_id)
                            .filter(|p|serde_json::from_str::<serde_json::Value>(&p.preview_text).ok()
                                .is_some_and(|preview|preview["generationId"].as_str() == Some(id.as_str())));
                        let status = if job.state == MediaGenerationState::Ready {
                            match current_product.map(|p|&p.adoption_status) { Some(WorkProductStatus::Accepted)=>"已采用",Some(_)=>"待审阅",None=>"历史版本" }
                        } else {state_label(job.state)};
                        let adoption = current_product
                            .filter(|p|p.adoption_status == WorkProductStatus::ReadyForReview && job.state == MediaGenerationState::Ready)
                            .map(|p|DesktopWorkProductAdoptionRequest {project_id:mission.project_id.clone(),mission_id:mission.mission_id.clone(),
                                work_product_id:p.work_product_id.clone(),expected_mission_revision:mission.revision,
                                expected_work_product_revision:p.work_product_revision,expected_manifest_version:p.manifest_version});
                        let adopt_enabled = adoption.is_some() && viewed().as_ref() == Some(&id) && !busy();
                        rsx! {
                            article {key:"{id}", class:if is_selected {"media-job selected"} else {"media-job"},
                                strong { "{job.request.model}" }
                                small { "{generated_at} · {status}" }
                                if let Some(asset) = &job.asset { small { "{asset.width} × {asset.height} · {asset.byte_length} bytes" } }
                                if let Some(code) = &job.failure_code { p {class:"media-status error", "{media_failure_message(code)}"} }
                                button {class:"quiet-button",aria_label:"查看生成素材",onclick:move |_|{
                                    if selected_writer.peek().as_ref() != Some(&select_id) {
                                        viewed.set(None);
                                        selected_writer.set(Some(select_id.clone()));
                                    }
                                },"查看"}
                                if job.state == MediaGenerationState::Rejected || adoption.is_some() {
                                    button {class:"quiet-button",disabled:busy(),onclick:move |_|{
                                        prompt.set(prompt_copy.clone());revises.set(Some(revise_id.clone()));model_choice.set(job_choice.into());
                                    },"修改描述"}
                                }
                                if job.state == MediaGenerationState::Submitted {
                                    button {class:"quiet-button",disabled:busy(),onclick:move |_|start_action(Action::Poll(scope.0.clone(),scope.1.clone(),poll_id.clone()),busy,notice,refresh,selected,on_changed),"继续取回视频"}
                                }
                                if is_selected {
                                    p {class:"media-prompt","{job.request.prompt}"}
                                    if job.asset.is_some() {
                                        MediaAssetPreview {key:"{preview_id}",project_id:preview_scope.0,mission_id:preview_scope.1,id:preview_id,kind:job.request.kind,
                                            on_loaded:move |()|viewed.set(Some(loaded_id.clone())),
                                            on_failed:move |()|{if viewed.peek().as_ref() == Some(&failed_id) {viewed.set(None);}}}
                                    }
                                    if job.state == MediaGenerationState::Ready {
                                        button {class:"quiet-button",disabled:!adopt_enabled,aria_label:"采用预览素材",onclick:move |_|{
                                            if let Some(request) = adoption.clone() {start_action(Action::Adopt(id.clone(),request),busy,notice,refresh,selected,on_changed);}
                                        },"采用此素材"}
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
fn MediaAssetPreview(
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
