//! A deterministic static preview compiler, not a model-supplied build-success claim.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hartevo_catalog::Catalog;
use hartevo_domain_kernel::{
    Mission, MissionCheckpointApplicationEvidence, MissionCheckpointCompletionPolicy,
    MissionCheckpointExecutor, MissionCheckpointOracleSource, MissionCheckpointRoute,
    MissionCheckpointStatus, Project, TaskStatus, WorkProduct, WorkProductDependencies,
    WorkProductId, WorkProductManifest, WorkProductPreview, WorkProductStatus,
};
use hartevo_storage::{ApplicationSourceKind, ApplicationSourceRevisionFence, ProjectStore};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::{
    ApplicationError, ExecuteApplicationMissionCheckpoint, canonical_sha256, is_sha256_text,
};

pub(super) const HANDLER_ID: &str = "vm03.static-site-quality/v1";
const TEMPLATE_ID: &str = "static-first-party/v1";
pub(super) const SPEC_OUTPUT_CONTRACT: &str = "For VM-03 site_spec_and_claims return a JSON WorkProduct with exactly schemaVersion=hartevo-site-spec/v1, projectRevision, domainName (the verified purchased domain), language (BCP47 ASCII tag), title and description copied verbatim from the supplied Project name and description, claimPolicy=project_metadata_verbatim/v1. This first static preview supports only adopted Project metadata, no invented claims, forms, scripts or external assets. The user must review and adopt this specification; missing source data must block.";
pub(super) const BUILD_OUTPUT_CONTRACT: &str = "For VM-03 sandbox_build return a JSON build-plan WorkProduct with exactly schemaVersion=hartevo-static-site-build-plan/v1, templateId=static-first-party/v1, siteSpecWorkProductId, siteSpecRevision and siteSpecDigest copied from the adopted site_spec_and_claims WorkProduct. This is a plan, not evidence of a successful build. The next Application quality_gate independently compiles a script-free single-page HTML preview from the adopted specification. Do not claim a shell build, deployment, form delivery or live verification.";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SiteSpec {
    schema_version: String,
    project_revision: u64,
    domain_name: String,
    language: String,
    title: String,
    description: String,
    claim_policy: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildPlan {
    schema_version: String,
    template_id: String,
    site_spec_work_product_id: WorkProductId,
    site_spec_revision: u64,
    site_spec_digest: String,
}

pub(super) struct PreparedSiteBuild {
    pub(super) manifest: WorkProductManifest,
    source_digest: String,
    project_revision: u64,
}

fn mismatch() -> ApplicationError {
    ApplicationError::Vm03SiteBuildMismatch
}

fn runtime_product<'a>(
    store: &ProjectStore,
    mission: &'a Mission,
    checkpoint_id: &str,
    now: DateTime<Utc>,
) -> Result<(&'a WorkProduct, WorkProductManifest, DateTime<Utc>), ApplicationError> {
    let checkpoint = mission
        .definition
        .as_ref()
        .ok_or_else(mismatch)?
        .checkpoints
        .iter()
        .find(|checkpoint| checkpoint.id == checkpoint_id)
        .ok_or_else(mismatch)?;
    let route = checkpoint.route.as_ref().ok_or_else(mismatch)?;
    let completion = checkpoint.completion.as_ref().ok_or_else(mismatch)?;
    if checkpoint.status != MissionCheckpointStatus::Completed
        || checkpoint.depends_on
            != BTreeSet::from([match checkpoint_id {
                "site_spec_and_claims" => "domain_purchase_approval".into(),
                "sandbox_build" => "site_spec_and_claims".into(),
                _ => return Err(mismatch()),
            }])
        || route.capability_id != "site.build"
        || route.executor != MissionCheckpointExecutor::Runtime
        || route.completion_policy != Some(MissionCheckpointCompletionPolicy::WorkProduct)
        || route.oracle_ids
            != BTreeSet::from([
                "decision".into(),
                "work_product".into(),
                "operating_state".into(),
            ])
        || completion.oracle_ids != route.oracle_ids
        || completion.work_product_ids.len() != 1
        || !completion.effect_ids.is_empty()
        || completion.application_evidence.is_some()
        || !is_sha256_text(&completion.evidence_digest)
        || completion.verified_at > now
    {
        return Err(mismatch());
    }
    let id = completion.work_product_ids.first().ok_or_else(mismatch)?;
    let product = mission
        .work_products
        .iter()
        .find(|product| &product.id == id)
        .ok_or_else(mismatch)?;
    let manifest = store.load_work_product_manifest(&mission.project_id, id)?;
    manifest.validate_against(product)?;
    if product.status != WorkProductStatus::Accepted
        || manifest.tenant_id != mission.tenant_id
        || manifest.project_id != mission.project_id
        || manifest.mission_id != mission.id
        || manifest.work_product_type != "runtime_draft"
        || manifest.adoption_status != WorkProductStatus::Accepted
        || manifest.updated_at != completion.verified_at
    {
        return Err(mismatch());
    }
    Ok((product, manifest, completion.verified_at))
}

pub(super) fn runtime_source(
    store: &ProjectStore,
    mission: &Mission,
    now: DateTime<Utc>,
) -> Result<Option<serde_json::Value>, ApplicationError> {
    let Some(definition) = mission.definition.as_ref() else {
        return Ok(None);
    };
    if definition.manifest_id != "VM-03" || definition.manifest_version != 3 {
        return Ok(None);
    }
    match definition
        .current_checkpoint()
        .map(|checkpoint| checkpoint.id.as_str())
    {
        Some("site_spec_and_claims") => {
            let project = store.load_project(&mission.project_id)?;
            if project.tenant_id != mission.tenant_id {
                return Err(mismatch());
            }
            Ok(Some(serde_json::json!({
                "artifactContract": SPEC_OUTPUT_CONTRACT,
                "project": {"revision": project.revision, "name": project.name, "description": project.description},
                "domainName": super::vm03_domain_purchase::purchased_domain_name(mission)?,
            })))
        }
        Some("sandbox_build") => {
            let (spec, _, _) = runtime_product(store, mission, "site_spec_and_claims", now)?;
            Ok(Some(serde_json::json!({
                "artifactContract": BUILD_OUTPUT_CONTRACT,
                "siteSpec": {"workProductId": spec.id, "revision": spec.revision, "digest": spec.content_digest},
            })))
        }
        _ => Ok(None),
    }
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn compile_preview(spec: &SiteSpec, project: &Project) -> Result<String, ApplicationError> {
    if spec.schema_version != "hartevo-site-spec/v1"
        || spec.claim_policy != "project_metadata_verbatim/v1"
        || spec.project_revision != project.revision
        || spec.title != project.name
        || spec.description != project.description
        || spec.title.trim().is_empty()
        || spec.title.len() > 256
        || spec.description.trim().is_empty()
        || spec.description.len() > 16_000
        || spec.language.len() < 2
        || spec.language.len() > 35
        || spec.language.starts_with('-')
        || spec.language.ends_with('-')
        || !spec
            .language
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || [&spec.title, &spec.description].into_iter().any(|text| {
            text.chars()
                .any(|character| character.is_control() && character != '\n' && character != '\t')
        })
    {
        return Err(mismatch());
    }
    // ponytail: one fixed static page, no arbitrary HTML/JS/framework execution.
    // Add a separately sandboxed compiler only when another template is needed.
    Ok(format!(
        r#"<!doctype html>
<html lang="{}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{}</title><style>body{{font:18px/1.6 system-ui;margin:0;background:#faf9f6;color:#18241f}}main{{max-width:52rem;margin:10vh auto;padding:2rem}}h1{{font-size:clamp(2rem,6vw,4rem);line-height:1.1}}p{{white-space:pre-wrap;overflow-wrap:anywhere}}footer{{font-size:.85rem;color:#4b6055}}</style>
</head><body><main><h1>{}</h1><p>{}</p><footer>{} · Preview only — no live form or deployment.</footer></main></body></html>"#,
        escape_html(&spec.language),
        escape_html(&spec.title),
        escape_html(&spec.title),
        escape_html(&spec.description),
        escape_html(&spec.domain_name)
    ))
}

pub(super) fn preview_projection(
    store: &ProjectStore,
    mission: &Mission,
    product: &WorkProduct,
    manifest: &WorkProductManifest,
) -> Result<Option<String>, ApplicationError> {
    if manifest.work_product_type != "site_preview_bundle"
        || !matches!(
            product.status,
            WorkProductStatus::ReadyForReview | WorkProductStatus::Accepted
        )
    {
        return Ok(None);
    }
    let Some(definition) = mission.definition.as_ref() else {
        return Ok(None);
    };
    let completion = definition
        .checkpoints
        .iter()
        .find(|checkpoint| {
            checkpoint.id == "quality_gate"
                && checkpoint.status == MissionCheckpointStatus::Completed
        })
        .and_then(|checkpoint| checkpoint.completion.as_ref());
    let Some(completion) = completion else {
        return Ok(None);
    };
    if definition.manifest_id != "VM-03"
        || definition.manifest_version != 3
        || completion.work_product_ids != BTreeSet::from([product.id.clone()])
        || !completion
            .application_evidence
            .as_ref()
            .is_some_and(|evidence| {
                evidence.handler_id == HANDLER_ID
                    && evidence.sources.iter().any(|source| {
                        source.source_kind == "site_quality_build"
                            && source.source_id == product.id.as_str()
                    })
            })
    {
        return Ok(None);
    }
    let (spec_product, _, _) = match runtime_product(
        store,
        mission,
        "site_spec_and_claims",
        completion.verified_at,
    ) {
        Ok(source) => source,
        Err(ApplicationError::Vm03SiteBuildMismatch) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Ok(spec) = serde_json::from_str::<SiteSpec>(&spec_product.body) else {
        return Ok(None);
    };
    let project = store.load_project(&mission.project_id)?;
    if project.tenant_id != mission.tenant_id
        || spec.domain_name != super::vm03_domain_purchase::purchased_domain_name(mission)?
    {
        return Ok(None);
    }
    // Recompile the fixed template; never pass arbitrary WorkProduct HTML to a WebView.
    let Ok(html) = compile_preview(&spec, &project) else {
        return Ok(None);
    };
    let Ok(bundle) = serde_json::from_str::<serde_json::Value>(&product.body) else {
        return Ok(None);
    };
    Ok(
        bundle_matches_preview(&bundle, product.id.as_str(), &spec.domain_name, &html)
            .then_some(html),
    )
}

fn bundle_matches_preview(
    bundle: &serde_json::Value,
    product_id: &str,
    domain: &str,
    html: &str,
) -> bool {
    let Some(source_digest) = bundle["sourceDigest"].as_str() else {
        return false;
    };
    bundle["schemaVersion"] == "hartevo-site-preview-bundle/v1"
        && bundle["templateId"] == TEMPLATE_ID
        && is_sha256_text(source_digest)
        && product_id == format!("vm03-static-preview:{source_digest}")
        && bundle["domainName"] == domain
        && bundle["files"]
            .as_array()
            .is_some_and(|files| files.len() == 1)
        && bundle["files"][0]["path"] == "index.html"
        && bundle["files"][0]["mediaType"] == "text/html"
        && bundle["files"][0]["content"] == html
        && bundle["files"][0]["sha256"] == format!("{:x}", Sha256::digest(html.as_bytes()))
        && bundle["quality"]["compiler"] == "rust_static_template"
        && bundle["quality"]["claims"] == "adopted_project_metadata_verbatim"
        && bundle["quality"]["scriptExecution"] == false
        && bundle["quality"]["formDeliveryVerified"] == false
        && bundle["quality"]["deployed"] == false
}

#[allow(
    clippy::too_many_lines,
    reason = "source validation and artifact preparation stay together before the single atomic commit"
)]
pub(super) fn prepare(
    store: &ProjectStore,
    mission: &mut Mission,
    now: DateTime<Utc>,
) -> Result<PreparedSiteBuild, ApplicationError> {
    let definition = mission.definition.as_ref().ok_or_else(mismatch)?;
    let checkpoint = definition.current_checkpoint().ok_or_else(mismatch)?;
    if definition.manifest_id != "VM-03"
        || definition.manifest_version != 3
        || definition.catalog_digest != Catalog::load()?.snapshot()?.digest
        || checkpoint.id != "quality_gate"
        || checkpoint.status != MissionCheckpointStatus::Running
        || checkpoint.depends_on != BTreeSet::from(["sandbox_build".into()])
        || mission.contract.validate(now).is_err()
    {
        return Err(mismatch());
    }
    let project = store.load_project(&mission.project_id)?;
    if project.tenant_id != mission.tenant_id || project.id != mission.project_id {
        return Err(mismatch());
    }
    let domain = super::vm03_domain_purchase::purchased_domain_name(mission)?;
    let (spec_product, spec_manifest, spec_at) =
        runtime_product(store, mission, "site_spec_and_claims", now)?;
    let (plan_product, plan_manifest, plan_at) =
        runtime_product(store, mission, "sandbox_build", now)?;
    let purchase_completion = definition
        .checkpoints
        .iter()
        .find(|checkpoint| checkpoint.id == "domain_purchase_approval")
        .and_then(|checkpoint| checkpoint.completion.as_ref())
        .ok_or_else(mismatch)?;
    if spec_product.id == plan_product.id
        || spec_at > plan_at
        || purchase_completion.verified_at > spec_at
    {
        return Err(mismatch());
    }
    let spec: SiteSpec = serde_json::from_str(&spec_product.body).map_err(|_| mismatch())?;
    let plan: BuildPlan = serde_json::from_str(&plan_product.body).map_err(|_| mismatch())?;
    if spec.domain_name != domain
        || plan.schema_version != "hartevo-static-site-build-plan/v1"
        || plan.template_id != TEMPLATE_ID
        || plan.site_spec_work_product_id != spec_product.id
        || plan.site_spec_revision != spec_product.revision
        || plan.site_spec_digest != spec_product.content_digest
    {
        return Err(mismatch());
    }
    let html = compile_preview(&spec, &project)?;
    let html_digest = format!("{:x}", Sha256::digest(html.as_bytes()));
    let source_digest = canonical_sha256(&serde_json::json!({
        "schemaVersion": "hartevo-static-site-build-source/v1",
        "missionId": mission.id, "projectId": project.id, "projectRevision": project.revision,
        "purchaseCompletion": purchase_completion,
        "specWorkProductId": spec_product.id, "specRevision": spec_product.revision,
        "specDigest": spec_product.content_digest, "specManifestDigest": spec_manifest.manifest_digest,
        "planWorkProductId": plan_product.id, "planRevision": plan_product.revision,
        "planDigest": plan_product.content_digest, "planManifestDigest": plan_manifest.manifest_digest,
        "templateId": TEMPLATE_ID, "htmlDigest": html_digest,
    }))?;
    let product_id = WorkProductId::from_stable(format!("vm03-static-preview:{source_digest}"));
    let body = serde_json::to_string(&serde_json::json!({
        "schemaVersion": "hartevo-site-preview-bundle/v1", "templateId": TEMPLATE_ID,
        "sourceDigest": source_digest, "domainName": domain,
        "files": [{"path": "index.html", "mediaType": "text/html", "content": html, "sha256": html_digest}],
        "quality": {"compiler": "rust_static_template", "claims": "adopted_project_metadata_verbatim",
            "scriptExecution": false, "formDeliveryVerified": false, "deployed": false},
    }))?;
    let task_ids = mission
        .tasks
        .iter()
        .filter(|task| task.status == TaskStatus::Running && task.capability == "site.build")
        .map(|task| task.id.clone())
        .collect::<BTreeSet<_>>();
    if task_ids.len() != 1 {
        return Err(mismatch());
    }
    mission.record_work_product(
        WorkProduct::draft(
            product_id.clone(),
            "VM-03 static site preview",
            body,
            BTreeSet::new(),
        ),
        now,
    )?;
    let product = mission
        .work_products
        .iter()
        .find(|product| product.id == product_id)
        .ok_or_else(mismatch)?;
    let manifest = WorkProductManifest::create(
        mission.tenant_id.clone(),
        mission.project_id.clone(),
        mission.id.clone(),
        product,
        "site_preview_bundle",
        WorkProductDependencies {
            task_ids,
            ..WorkProductDependencies::default()
        },
        None,
        WorkProductPreview::new(
            "text/plain",
            "Static HTML preview built from the adopted Project metadata. Review required; no scripts, live form, publication or deployment.",
        )?,
        BTreeSet::from(["/body".into()]),
        now,
    )?;
    Ok(PreparedSiteBuild {
        manifest,
        source_digest,
        project_revision: project.revision,
    })
}

pub(super) fn application_evidence(
    mission: &Mission,
    route: &MissionCheckpointRoute,
    command: &ExecuteApplicationMissionCheckpoint,
    prepared: &PreparedSiteBuild,
    now: DateTime<Utc>,
) -> Result<
    (
        MissionCheckpointApplicationEvidence,
        u64,
        Vec<ApplicationSourceRevisionFence>,
    ),
    ApplicationError,
> {
    let definition = mission.definition.as_ref().ok_or_else(mismatch)?;
    let checkpoint = definition.current_checkpoint().ok_or_else(mismatch)?;
    if checkpoint.id != "quality_gate"
        || checkpoint.status != MissionCheckpointStatus::Verifying
        || route.capability_id != "site.build"
        || route.executor != MissionCheckpointExecutor::Application
        || route.completion_policy != Some(MissionCheckpointCompletionPolicy::DeterministicEvidence)
        || route.oracle_ids
            != BTreeSet::from([
                "decision".into(),
                "work_product".into(),
                "operating_state".into(),
            ])
    {
        return Err(mismatch());
    }
    let evidence = MissionCheckpointApplicationEvidence {
        schema_version: MissionCheckpointApplicationEvidence::SCHEMA_VERSION,
        handler_id: HANDLER_ID.into(),
        tenant_id: mission.tenant_id.clone(),
        project_id: mission.project_id.clone(),
        mission_id: mission.id.clone(),
        manifest_id: definition.manifest_id.clone(),
        manifest_version: definition.manifest_version,
        catalog_digest: definition.catalog_digest.clone(),
        cycle: definition.cycle,
        checkpoint_id: checkpoint.id.clone(),
        dispatch_mission_revision: command.expected_mission_revision,
        dispatch_checkpoint_revision: command.expected_checkpoint_revision,
        verification_mission_revision: mission.revision,
        verification_checkpoint_revision: checkpoint.revision,
        capability_id: route.capability_id.clone(),
        executor: route.executor,
        completion_policy: MissionCheckpointCompletionPolicy::DeterministicEvidence,
        sources: BTreeSet::from([
            MissionCheckpointOracleSource {
                source_kind: "mission_checkpoint".into(),
                source_id: format!("{}:{}", mission.id, checkpoint.id),
                source_revision: command.expected_checkpoint_revision,
                projection_digest: canonical_sha256(&serde_json::json!({
                    "missionId": mission.id, "checkpointId": checkpoint.id,
                    "dispatchMissionRevision": command.expected_mission_revision,
                    "dispatchCheckpointRevision": command.expected_checkpoint_revision,
                    "verificationMissionRevision": mission.revision, "verificationCheckpointRevision": checkpoint.revision,
                    "catalogDigest": definition.catalog_digest,
                }))?,
                oracle_ids: BTreeSet::from(["operating_state".into()]),
            },
            MissionCheckpointOracleSource {
                source_kind: "site_quality_build".into(),
                source_id: prepared.manifest.work_product_id.to_string(),
                source_revision: prepared.manifest.version,
                projection_digest: canonical_sha256(&serde_json::json!({
                    "sourceDigest": prepared.source_digest, "manifestDigest": prepared.manifest.manifest_digest,
                    "projectRevision": prepared.project_revision, "compiler": TEMPLATE_ID,
                }))?,
                oracle_ids: BTreeSet::from(["decision".into(), "work_product".into()]),
            },
        ]),
        observed_at: now,
    };
    Ok((
        evidence,
        prepared.manifest.version,
        vec![
            ApplicationSourceRevisionFence::present(
                ApplicationSourceKind::Project,
                mission.project_id.to_string(),
                prepared.project_revision,
            ),
            ApplicationSourceRevisionFence::present(
                ApplicationSourceKind::Mission,
                mission.id.to_string(),
                command.expected_mission_revision,
            ),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hartevo_domain_kernel::{ProjectId, StorageMode, TenantId};

    #[test]
    fn static_compiler_escapes_adopted_text_and_rejects_invented_claims_or_executable_plans() {
        let project = Project::create_local(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            "Owner <brand>",
            "Text & <script>alert('x')</script>",
            std::path::PathBuf::from("/tmp/vm03-compiler"),
            StorageMode::LocalExisting,
        )
        .unwrap();
        let mut spec = SiteSpec {
            schema_version: "hartevo-site-spec/v1".into(),
            project_revision: project.revision,
            domain_name: "owner.example".into(),
            language: "en-US".into(),
            title: project.name.clone(),
            description: project.description.clone(),
            claim_policy: "project_metadata_verbatim/v1".into(),
        };
        let html = compile_preview(&spec, &project).unwrap();
        assert!(html.contains("Owner &lt;brand&gt;"));
        assert!(html.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("form-action 'none'"));
        let source_digest = "d".repeat(64);
        let product_id = format!("vm03-static-preview:{source_digest}");
        let mut bundle = serde_json::json!({
            "schemaVersion": "hartevo-site-preview-bundle/v1", "templateId": TEMPLATE_ID,
            "sourceDigest": source_digest, "domainName": spec.domain_name,
            "files": [{"path": "index.html", "mediaType": "text/html", "content": html,
                "sha256": format!("{:x}", Sha256::digest(html.as_bytes()))}],
            "quality": {"compiler": "rust_static_template", "claims": "adopted_project_metadata_verbatim",
                "scriptExecution": false, "formDeliveryVerified": false, "deployed": false},
        });
        assert!(bundle_matches_preview(
            &bundle,
            &product_id,
            &spec.domain_name,
            &html
        ));
        assert!(!bundle_matches_preview(
            &bundle,
            "another-product",
            &spec.domain_name,
            &html
        ));
        assert!(!bundle_matches_preview(
            &bundle,
            &product_id,
            "another.example",
            &html
        ));
        bundle["files"][0]["content"] = "<script>unsafe()</script>".into();
        bundle["files"][0]["sha256"] =
            format!("{:x}", Sha256::digest(b"<script>unsafe()</script>")).into();
        assert!(!bundle_matches_preview(
            &bundle,
            &product_id,
            &spec.domain_name,
            &html
        ));
        bundle["files"][0]["content"] = html.clone().into();
        bundle["files"][0]["sha256"] = format!("{:x}", Sha256::digest(html.as_bytes())).into();
        bundle["quality"]["deployed"] = true.into();
        assert!(!bundle_matches_preview(
            &bundle,
            &product_id,
            &spec.domain_name,
            &html
        ));
        spec.description.push_str(" invented claim");
        assert!(compile_preview(&spec, &project).is_err());
        spec.description = project.description.clone();
        spec.project_revision += 1;
        assert!(compile_preview(&spec, &project).is_err());
        spec.project_revision = project.revision;
        spec.language = "en\" onload=\"alert(1)".into();
        assert!(compile_preview(&spec, &project).is_err());
        assert!(serde_json::from_str::<BuildPlan>(r#"{"schemaVersion":"hartevo-static-site-build-plan/v1","templateId":"static-first-party/v1","siteSpecWorkProductId":"spec","siteSpecRevision":1,"siteSpecDigest":"digest","passed":true,"command":"publish"}"#).is_err());
    }
}
