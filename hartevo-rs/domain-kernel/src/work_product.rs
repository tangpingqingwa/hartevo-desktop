use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::mission::{WorkProduct, WorkProductStatus};
use crate::{EvidenceId, FactId, MissionId, ProjectId, TaskId, TenantId, WorkProductId};

const MAX_PREVIEW_BYTES: usize = 16 * 1024;
const MAX_EDITABLE_SCOPE_BYTES: usize = 256;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductDependencies {
    pub fact_ids: BTreeSet<FactId>,
    pub evidence_ids: BTreeSet<EvidenceId>,
    pub task_ids: BTreeSet<TaskId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductPreview {
    pub media_type: String,
    pub text: String,
    pub content_digest: String,
}

impl WorkProductPreview {
    pub fn new(
        media_type: impl Into<String>,
        text: impl Into<String>,
    ) -> Result<Self, WorkProductManifestError> {
        let preview = Self {
            media_type: media_type.into(),
            text: text.into(),
            content_digest: String::new(),
        };
        let content_digest = sha256(preview.text.as_bytes());
        let preview = Self {
            content_digest,
            ..preview
        };
        preview.validate()?;
        Ok(preview)
    }

    pub fn validate(&self) -> Result<(), WorkProductManifestError> {
        if self.media_type.trim().is_empty()
            || self.text.trim().is_empty()
            || self.text.len() > MAX_PREVIEW_BYTES
            || self.content_digest != sha256(self.text.as_bytes())
        {
            return Err(WorkProductManifestError::InvalidPreview);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductManifest {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_type: String,
    pub version: u64,
    pub work_product_revision: u64,
    pub dependencies: WorkProductDependencies,
    pub artifact_digest: String,
    pub file_digest: Option<String>,
    pub preview: WorkProductPreview,
    pub editable_scopes: BTreeSet<String>,
    pub adoption_status: WorkProductStatus,
    pub manifest_digest: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WorkProductManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product: &WorkProduct,
        work_product_type: impl Into<String>,
        dependencies: WorkProductDependencies,
        file_digest: Option<String>,
        preview: WorkProductPreview,
        editable_scopes: BTreeSet<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, WorkProductManifestError> {
        let mut manifest = Self {
            tenant_id,
            project_id,
            mission_id,
            work_product_id: work_product.id.clone(),
            work_product_type: work_product_type.into(),
            version: 1,
            work_product_revision: work_product.revision,
            dependencies,
            artifact_digest: work_product.content_digest.clone(),
            file_digest,
            preview,
            editable_scopes,
            adoption_status: work_product.status.clone(),
            manifest_digest: String::new(),
            created_at: now,
            updated_at: now,
        };
        manifest.manifest_digest = manifest.calculate_digest()?;
        manifest.validate_against(work_product)?;
        Ok(manifest)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn revise(
        &self,
        work_product: &WorkProduct,
        dependencies: WorkProductDependencies,
        file_digest: Option<String>,
        preview: WorkProductPreview,
        editable_scopes: BTreeSet<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, WorkProductManifestError> {
        if now < self.updated_at {
            return Err(WorkProductManifestError::InvalidTime);
        }
        let mut revised = Self {
            version: self
                .version
                .checked_add(1)
                .ok_or(WorkProductManifestError::RevisionOverflow)?,
            work_product_revision: work_product.revision,
            dependencies,
            artifact_digest: work_product.content_digest.clone(),
            file_digest,
            preview,
            editable_scopes,
            adoption_status: work_product.status.clone(),
            manifest_digest: String::new(),
            updated_at: now,
            ..self.clone()
        };
        revised.manifest_digest = revised.calculate_digest()?;
        revised.validate_against(work_product)?;
        if !revised.follows(self)? {
            return Err(WorkProductManifestError::InvalidRevisionChain);
        }
        Ok(revised)
    }

    pub fn validate(&self) -> Result<(), WorkProductManifestError> {
        self.preview.validate()?;
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.work_product_id.as_str().trim().is_empty()
            || !is_slug(&self.work_product_type)
            || self.version == 0
            || self.work_product_revision == 0
            || !is_sha256(&self.artifact_digest)
            || self
                .file_digest
                .as_deref()
                .is_some_and(|value| !is_sha256(value))
            || self.editable_scopes.is_empty()
            || self.editable_scopes.iter().any(|scope| !valid_scope(scope))
            || self.created_at > self.updated_at
            || self.manifest_digest != self.calculate_digest()?
            || !valid_ids(&self.dependencies.fact_ids)
            || !valid_ids(&self.dependencies.evidence_ids)
            || !valid_ids(&self.dependencies.task_ids)
        {
            return Err(WorkProductManifestError::InvalidManifest);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        work_product: &WorkProduct,
    ) -> Result<(), WorkProductManifestError> {
        self.validate()?;
        work_product
            .validate()
            .map_err(|_| WorkProductManifestError::WorkProductMismatch)?;
        if self.work_product_id != work_product.id
            || self.work_product_revision != work_product.revision
            || self.dependencies.evidence_ids != work_product.evidence_ids
            || self.artifact_digest != work_product.content_digest
            || self.adoption_status != work_product.status
        {
            return Err(WorkProductManifestError::WorkProductMismatch);
        }
        Ok(())
    }

    pub fn follows(&self, previous: &Self) -> Result<bool, WorkProductManifestError> {
        self.validate()?;
        previous.validate()?;
        Ok(self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.work_product_id == previous.work_product_id
            && self.work_product_type == previous.work_product_type
            && self.created_at == previous.created_at
            && previous.version.checked_add(1) == Some(self.version)
            && (self.work_product_revision == previous.work_product_revision
                || previous.work_product_revision.checked_add(1)
                    == Some(self.work_product_revision))
            && self.updated_at >= previous.updated_at)
    }

    fn calculate_digest(&self) -> Result<String, WorkProductManifestError> {
        let material = WorkProductManifestDigest {
            tenant_id: &self.tenant_id,
            project_id: &self.project_id,
            mission_id: &self.mission_id,
            work_product_id: &self.work_product_id,
            work_product_type: &self.work_product_type,
            version: self.version,
            work_product_revision: self.work_product_revision,
            dependencies: &self.dependencies,
            artifact_digest: &self.artifact_digest,
            file_digest: self.file_digest.as_deref(),
            preview: &self.preview,
            editable_scopes: &self.editable_scopes,
            adoption_status: &self.adoption_status,
            created_at: self.created_at,
            updated_at: self.updated_at,
        };
        let canonical =
            serde_json::to_vec(&material).map_err(|_| WorkProductManifestError::InvalidManifest)?;
        Ok(sha256(&canonical))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkProductManifestDigest<'a> {
    tenant_id: &'a TenantId,
    project_id: &'a ProjectId,
    mission_id: &'a MissionId,
    work_product_id: &'a WorkProductId,
    work_product_type: &'a str,
    version: u64,
    work_product_revision: u64,
    dependencies: &'a WorkProductDependencies,
    artifact_digest: &'a str,
    file_digest: Option<&'a str>,
    preview: &'a WorkProductPreview,
    editable_scopes: &'a BTreeSet<String>,
    adoption_status: &'a WorkProductStatus,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WorkProductManifestError {
    #[error("work product preview is empty, too large, or has the wrong digest")]
    InvalidPreview,
    #[error("work product manifest scope, dependency, digest, or version is invalid")]
    InvalidManifest,
    #[error("work product manifest does not bind the exact work product revision")]
    WorkProductMismatch,
    #[error("work product manifest revision does not follow the prior manifest")]
    InvalidRevisionChain,
    #[error("work product manifest time moved backwards")]
    InvalidTime,
    #[error("work product manifest revision overflow")]
    RevisionOverflow,
}

fn valid_ids<T>(ids: &BTreeSet<T>) -> bool
where
    T: AsRefId,
{
    ids.iter().all(|id| !id.id_text().trim().is_empty())
}

trait AsRefId {
    fn id_text(&self) -> &str;
}

macro_rules! impl_id_text {
    ($($id:ty),+ $(,)?) => {
        $(
            impl AsRefId for $id {
                fn id_text(&self) -> &str {
                    self.as_str()
                }
            }
        )+
    };
}

impl_id_text!(FactId, EvidenceId, TaskId);

fn valid_scope(scope: &str) -> bool {
    scope.starts_with('/')
        && scope.len() <= MAX_EDITABLE_SCOPE_BYTES
        && !scope.contains("..")
        && !scope.chars().any(char::is_control)
}

fn is_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 18, 0, 0)
            .single()
            .expect("valid time")
    }

    fn work_product() -> WorkProduct {
        let mut product = WorkProduct::draft(
            WorkProductId::from("work-product-1"),
            "Launch brief",
            "Evidence-backed launch brief",
            [EvidenceId::from("evidence-1")],
        );
        product.status = WorkProductStatus::ReadyForReview;
        product
    }

    fn manifest(product: &WorkProduct) -> WorkProductManifest {
        WorkProductManifest::create(
            TenantId::from("tenant-1"),
            ProjectId::from("project-1"),
            MissionId::from("mission-1"),
            product,
            "document.brief",
            WorkProductDependencies {
                fact_ids: BTreeSet::from([FactId::from("fact-1")]),
                evidence_ids: product.evidence_ids.clone(),
                task_ids: BTreeSet::from([TaskId::from("task-1")]),
            },
            None,
            WorkProductPreview::new("text/plain", "Launch brief preview").expect("preview"),
            BTreeSet::from(["/body".into()]),
            now(),
        )
        .expect("manifest")
    }

    #[test]
    fn manifest_binds_artifact_dependencies_preview_and_editable_scope() {
        let product = work_product();
        let manifest = manifest(&product);
        assert!(manifest.validate_against(&product).is_ok());

        let mut changed = product;
        changed.body.push_str(" changed");
        assert_eq!(
            manifest.validate_against(&changed),
            Err(WorkProductManifestError::WorkProductMismatch)
        );
    }

    #[test]
    fn manifest_revision_is_exact_and_cannot_change_immutable_scope() {
        let product = work_product();
        let first = manifest(&product);
        let second = first
            .revise(
                &product,
                first.dependencies.clone(),
                None,
                WorkProductPreview::new("text/plain", "Updated preview").expect("preview"),
                first.editable_scopes.clone(),
                now() + chrono::Duration::minutes(1),
            )
            .expect("revision");
        assert!(second.follows(&first).expect("valid manifests"));

        let mut wrong_project = second;
        wrong_project.project_id = ProjectId::from("project-2");
        wrong_project.manifest_digest = wrong_project.calculate_digest().expect("digest");
        assert!(!wrong_project.follows(&first).expect("valid manifests"));
    }
}
