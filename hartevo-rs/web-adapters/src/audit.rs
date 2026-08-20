use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{MissionId, ProjectId, TenantId, WorkProductId};
use serde::{Deserialize, Serialize};

use crate::{GithubPagesEnvironment, WebPublicationError, digest_bytes};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationOperation {
    Read,
    Proposal,
    Publish,
    Rollback,
    Reconcile,
}

/// Content-free durable evidence for every model-visible publication read,
/// proposal, mutation, or reconciliation. The event contains references and
/// digests, never site bytes or a resolved credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicationAuditEntry {
    pub schema_version: String,
    pub event_id: String,
    pub event_digest: String,
    pub operation: PublicationOperation,
    pub model_visible: bool,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub connection_id: String,
    pub account_id: String,
    pub registration_digest: String,
    pub registry_version: String,
    pub scope_digest: String,
    pub plugin_version: String,
    pub adapter_id: String,
    pub adapter_version: u32,
    pub environment: GithubPagesEnvironment,
    pub owner: String,
    pub repository: String,
    pub git_ref: String,
    pub pages_url: String,
    pub source_work_product_id: WorkProductId,
    pub source_work_product_revision: u64,
    pub source_work_product_digest: String,
    pub site_revision: u64,
    pub base_head_sha: String,
    pub base_tree_sha: String,
    pub observed_content_digest: String,
    pub observed_tree_digest: String,
    pub observed_file_count: u32,
    pub result_digest: String,
    pub diff_digest: Option<String>,
    pub effect_digest: Option<String>,
    pub observed_at: DateTime<Utc>,
}

impl PublicationAuditEntry {
    pub(crate) fn finalize(mut self) -> Result<Self, WebPublicationError> {
        self.event_digest.clear();
        let bytes = serde_json::to_vec(&self)?;
        self.event_digest = digest_bytes(&bytes);
        Ok(self)
    }

    pub(crate) fn verify_digest(&self) -> Result<bool, WebPublicationError> {
        let mut unsigned = self.clone();
        let expected = unsigned.event_digest.clone();
        unsigned.event_digest.clear();
        Ok(expected == digest_bytes(&serde_json::to_vec(&unsigned)?))
    }
}

pub trait PublicationDurableLog {
    fn append(&mut self, entry: PublicationAuditEntry) -> Result<(), WebPublicationError>;
}

#[derive(Debug)]
pub struct FilePublicationDurableLog {
    path: PathBuf,
}

impl FilePublicationDurableLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl PublicationDurableLog for FilePublicationDurableLog {
    fn append(&mut self, entry: PublicationAuditEntry) -> Result<(), WebPublicationError> {
        if !entry.verify_digest()? {
            return Err(WebPublicationError::Audit {
                detail: "publication audit event digest is invalid".to_owned(),
            });
        }
        let line = serde_json::to_vec(&entry)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| WebPublicationError::Audit {
                detail: error.to_string(),
            })?;
        file.write_all(&line)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_data())
            .map_err(|error| WebPublicationError::Audit {
                detail: error.to_string(),
            })
    }
}
