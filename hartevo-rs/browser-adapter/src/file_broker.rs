use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use hartevo_domain_kernel::{
    BrowserFileClaimId, BrowserFileGrantId, BrowserWorkspaceId, MissionId, Project, ProjectId,
    TenantId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempBuilder, TempDir};

use crate::workspace::{digest, digest_json, is_bounded_identifier, is_sha256};
use crate::{BrowserError, BrowserLeaseProof, BrowserWorkspace};

const FILE_GRANT_SCHEMA_VERSION: u32 = 1;
const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1_024 * 1_024;
const MAX_GRANT_LIFETIME: Duration = Duration::minutes(15);
const MAX_TEXT_BYTES: u64 = 16 * 1_024 * 1_024;
const FILE_TYPE_RULESET: &str = "hartevo-file-type/v1";
const DURABLE_BROKER_SCHEMA_VERSION: u32 = 1;
const DURABLE_SCOPE_MARKER: &str = "scope.digest";
const DURABLE_LOCK_FILE: &str = "broker.lock";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFileType {
    Pdf,
    Png,
    Jpeg,
    Gif,
    WebP,
    Mp4,
    Json,
    Utf8Text,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileScanDecision {
    Clean,
    Rejected,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileScanReport {
    pub scanner_id: String,
    pub scanner_version: String,
    pub decision: FileScanDecision,
    pub evidence_digest: String,
    pub scanned_at: DateTime<Utc>,
}

impl FileScanReport {
    fn validate(&self, expected_time: DateTime<Utc>) -> Result<(), BrowserError> {
        if !is_bounded_identifier(&self.scanner_id)
            || !is_bounded_identifier(&self.scanner_version)
            || !is_sha256(&self.evidence_digest)
            || self.scanned_at != expected_time
        {
            return Err(BrowserError::FileScanUnavailable);
        }
        Ok(())
    }
}

pub struct FileScanRequest<'a> {
    staged_path: &'a Path,
    pub content_digest: &'a str,
    pub byte_count: u64,
    pub detected_type: BrowserFileType,
    pub observed_at: DateTime<Utc>,
}

impl FileScanRequest<'_> {
    pub fn staged_path(&self) -> &Path {
        self.staged_path
    }
}

impl fmt::Debug for FileScanRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileScanRequest")
            .field(
                "staged_path_digest",
                &digest(self.staged_path.as_os_str().as_encoded_bytes()),
            )
            .field("content_digest", &self.content_digest)
            .field("byte_count", &self.byte_count)
            .field("detected_type", &self.detected_type)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

pub trait FileSafetyScanner {
    fn scan(&mut self, request: &FileScanRequest<'_>) -> Result<FileScanReport, BrowserError>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFileGrantState {
    Prepared,
    Leased,
    Consumed,
    Revoked,
    Expired,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserFileGrant {
    pub schema_version: u32,
    pub id: BrowserFileGrantId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub workspace_id: BrowserWorkspaceId,
    pub lease_id_digest: String,
    pub lease_generation: u64,
    pub source_path_digest: String,
    pub original_name_digest: String,
    pub content_digest: String,
    pub byte_count: u64,
    pub detected_type: BrowserFileType,
    pub type_ruleset_digest: String,
    pub scan_report: FileScanReport,
    pub authorization_evidence_digest: String,
    pub upload_payload_digest: String,
    pub state: BrowserFileGrantState,
    pub claim_id: Option<BrowserFileClaimId>,
    pub terminal_evidence_digest: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub revision: u64,
}

impl BrowserFileGrant {
    pub fn validate(&self) -> Result<(), BrowserError> {
        self.scan_report.validate(self.created_at)?;
        let expected_payload_digest = file_grant_payload_digest(self)?;
        let state_shape = match self.state {
            BrowserFileGrantState::Prepared => {
                self.claim_id.is_none() && self.terminal_evidence_digest.is_none()
            }
            BrowserFileGrantState::Leased => {
                self.claim_id.is_some() && self.terminal_evidence_digest.is_none()
            }
            BrowserFileGrantState::Consumed => {
                self.claim_id.is_some()
                    && self
                        .terminal_evidence_digest
                        .as_deref()
                        .is_some_and(is_sha256)
            }
            BrowserFileGrantState::Revoked | BrowserFileGrantState::Expired => self
                .terminal_evidence_digest
                .as_deref()
                .is_some_and(is_sha256),
        };
        if self.schema_version != FILE_GRANT_SCHEMA_VERSION
            || !is_bounded_identifier(self.id.as_str())
            || !is_bounded_identifier(self.tenant_id.as_str())
            || !is_bounded_identifier(self.project_id.as_str())
            || !is_bounded_identifier(self.mission_id.as_str())
            || !is_bounded_identifier(self.workspace_id.as_str())
            || !is_sha256(&self.lease_id_digest)
            || self.lease_generation == 0
            || !is_sha256(&self.source_path_digest)
            || !is_sha256(&self.original_name_digest)
            || !is_sha256(&self.content_digest)
            || self.byte_count == 0
            || self.type_ruleset_digest != digest(FILE_TYPE_RULESET.as_bytes())
            || self.scan_report.decision != FileScanDecision::Clean
            || !is_sha256(&self.authorization_evidence_digest)
            || self.upload_payload_digest != expected_payload_digest
            || self.expires_at <= self.created_at
            || self.expires_at - self.created_at > MAX_GRANT_LIFETIME
            || self.updated_at < self.created_at
            || self.revision == 0
            || !state_shape
        {
            return Err(BrowserError::InvalidFileGrant);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, BrowserError> {
        self.validate()?;
        digest_json(self)
    }

    pub fn is_valid_successor_of(&self, previous: &Self) -> Result<bool, BrowserError> {
        self.validate()?;
        previous.validate()?;
        let immutable = self.schema_version == previous.schema_version
            && self.id == previous.id
            && self.tenant_id == previous.tenant_id
            && self.project_id == previous.project_id
            && self.mission_id == previous.mission_id
            && self.workspace_id == previous.workspace_id
            && self.lease_id_digest == previous.lease_id_digest
            && self.lease_generation == previous.lease_generation
            && self.source_path_digest == previous.source_path_digest
            && self.original_name_digest == previous.original_name_digest
            && self.content_digest == previous.content_digest
            && self.byte_count == previous.byte_count
            && self.detected_type == previous.detected_type
            && self.type_ruleset_digest == previous.type_ruleset_digest
            && self.scan_report == previous.scan_report
            && self.authorization_evidence_digest == previous.authorization_evidence_digest
            && self.upload_payload_digest == previous.upload_payload_digest
            && self.expires_at == previous.expires_at
            && self.created_at == previous.created_at;
        let exact_revision = previous
            .revision
            .checked_add(1)
            .is_some_and(|revision| self.revision == revision)
            && self.updated_at >= previous.updated_at;
        let transition = match (previous.state, self.state) {
            (BrowserFileGrantState::Prepared, BrowserFileGrantState::Leased) => {
                previous.claim_id.is_none()
                    && self.claim_id.is_some()
                    && self.terminal_evidence_digest.is_none()
            }
            (BrowserFileGrantState::Leased, BrowserFileGrantState::Consumed) => {
                self.claim_id == previous.claim_id && self.terminal_evidence_digest.is_some()
            }
            (
                BrowserFileGrantState::Prepared | BrowserFileGrantState::Leased,
                BrowserFileGrantState::Expired | BrowserFileGrantState::Revoked,
            ) => self.claim_id == previous.claim_id && self.terminal_evidence_digest.is_some(),
            _ => false,
        };
        Ok(immutable && exact_revision && transition)
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            BrowserFileGrantState::Prepared | BrowserFileGrantState::Leased
        )
    }
}

impl fmt::Debug for BrowserFileGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserFileGrant")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("project_id", &self.project_id)
            .field("mission_id", &self.mission_id)
            .field("workspace_id", &self.workspace_id)
            .field("lease_id_digest", &self.lease_id_digest)
            .field("lease_generation", &self.lease_generation)
            .field("source_path_digest", &self.source_path_digest)
            .field("original_name_digest", &self.original_name_digest)
            .field("content_digest", &self.content_digest)
            .field("byte_count", &self.byte_count)
            .field("detected_type", &self.detected_type)
            .field("type_ruleset_digest", &self.type_ruleset_digest)
            .field("scan_report", &self.scan_report)
            .field(
                "authorization_evidence_digest",
                &self.authorization_evidence_digest,
            )
            .field("upload_payload_digest", &self.upload_payload_digest)
            .field("state", &self.state)
            .field("claim_id", &self.claim_id)
            .field("terminal_evidence_digest", &self.terminal_evidence_digest)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("revision", &self.revision)
            .finish()
    }
}

fn file_grant_payload_digest(grant: &BrowserFileGrant) -> Result<String, BrowserError> {
    digest_json(&serde_json::json!({
        "schemaVersion": grant.schema_version,
        "grantId": grant.id,
        "tenantId": grant.tenant_id,
        "projectId": grant.project_id,
        "missionId": grant.mission_id,
        "workspaceId": grant.workspace_id,
        "leaseIdDigest": grant.lease_id_digest,
        "leaseGeneration": grant.lease_generation,
        "sourcePathDigest": grant.source_path_digest,
        "originalNameDigest": grant.original_name_digest,
        "contentDigest": grant.content_digest,
        "byteCount": grant.byte_count,
        "detectedType": grant.detected_type,
        "typeRulesetDigest": grant.type_ruleset_digest,
        "scanReportDigest": digest_json(&grant.scan_report)?,
        "authorizationEvidenceDigest": grant.authorization_evidence_digest,
        "expiresAt": grant.expires_at,
    }))
}

pub struct FileUploadHandle {
    pub grant_id: BrowserFileGrantId,
    pub claim_id: BrowserFileClaimId,
    pub workspace_id: BrowserWorkspaceId,
    pub lease_generation: u64,
    pub content_digest: String,
    pub byte_count: u64,
    pub detected_type: BrowserFileType,
    staged_path: PathBuf,
}

impl FileUploadHandle {
    pub fn staged_path(&self) -> &Path {
        &self.staged_path
    }

    pub fn validate_for(
        &self,
        grant: &BrowserFileGrant,
        workspace: &BrowserWorkspace,
    ) -> Result<(), BrowserError> {
        grant.validate()?;
        if grant.state != BrowserFileGrantState::Leased
            || grant.claim_id.as_ref() != Some(&self.claim_id)
            || grant.id != self.grant_id
            || grant.workspace_id != self.workspace_id
            || grant.workspace_id != workspace.id
            || grant.tenant_id != workspace.tenant_id
            || grant.project_id != workspace.project_id
            || grant.mission_id != workspace.mission_id
            || grant.lease_id_digest != digest(workspace.lease_id.as_str().as_bytes())
            || grant.lease_generation != self.lease_generation
            || grant.lease_generation != workspace.lease_generation
            || grant.content_digest != self.content_digest
            || grant.byte_count != self.byte_count
            || grant.detected_type != self.detected_type
        {
            return Err(BrowserError::InvalidFileGrant);
        }
        verify_staged_file(&self.staged_path, &self.content_digest, self.byte_count)
    }
}

impl fmt::Debug for FileUploadHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileUploadHandle")
            .field("grant_id", &self.grant_id)
            .field("claim_id", &self.claim_id)
            .field("workspace_id", &self.workspace_id)
            .field("lease_generation", &self.lease_generation)
            .field("content_digest", &self.content_digest)
            .field("byte_count", &self.byte_count)
            .field("detected_type", &self.detected_type)
            .field(
                "staged_path_digest",
                &digest(self.staged_path.as_os_str().as_encoded_bytes()),
            )
            .finish()
    }
}

pub struct FileClaimPlan {
    previous: BrowserFileGrant,
    next: BrowserFileGrant,
    handle: FileUploadHandle,
}

impl FileClaimPlan {
    pub fn grant(&self) -> &BrowserFileGrant {
        &self.next
    }
}

impl fmt::Debug for FileClaimPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileClaimPlan")
            .field("grant_id", &self.next.id)
            .field("claim_id", &self.next.claim_id)
            .field("previous_revision", &self.previous.revision)
            .field("next_revision", &self.next.revision)
            .field("content_digest", &self.next.content_digest)
            .finish_non_exhaustive()
    }
}

pub struct FileTerminalPlan {
    previous: BrowserFileGrant,
    next: BrowserFileGrant,
    staged_path: Option<PathBuf>,
}

impl FileTerminalPlan {
    pub fn grant(&self) -> &BrowserFileGrant {
        &self.next
    }
}

impl fmt::Debug for FileTerminalPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileTerminalPlan")
            .field("grant_id", &self.next.id)
            .field("state", &self.next.state)
            .field("previous_revision", &self.previous.revision)
            .field("next_revision", &self.next.revision)
            .field(
                "staged_path_digest",
                &self
                    .staged_path
                    .as_ref()
                    .map(|path| digest(path.as_os_str().as_encoded_bytes())),
            )
            .finish_non_exhaustive()
    }
}

enum BrokerDirectory {
    Ephemeral(TempDir),
    Durable(DurableBrokerDirectory),
}

impl BrokerDirectory {
    fn path(&self) -> &Path {
        match self {
            Self::Ephemeral(directory) => directory.path(),
            Self::Durable(directory) => &directory.path,
        }
    }

    fn mode_name(&self) -> &'static str {
        match self {
            Self::Ephemeral(_) => "ephemeral",
            Self::Durable(_) => "durable",
        }
    }
}

struct DurableBrokerDirectory {
    path: PathBuf,
    _lock_file: File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileBrokerReconciliation {
    pub restored_active_grants: usize,
    pub restored_terminal_grants: usize,
    pub removed_orphan_files: usize,
    pub removed_terminal_files: usize,
    pub missing_or_changed_grants: Vec<BrowserFileGrantId>,
}

impl FileBrokerReconciliation {
    pub fn is_healthy(&self) -> bool {
        self.missing_or_changed_grants.is_empty()
    }
}

pub struct FileBroker {
    directory: BrokerDirectory,
    root_digest: String,
    max_file_bytes: u64,
    grants: BTreeMap<BrowserFileGrantId, BrowserFileGrant>,
    staged_paths: BTreeMap<BrowserFileGrantId, PathBuf>,
}

impl FileBroker {
    pub fn new(private_root: &Path) -> Result<Self, BrowserError> {
        Self::with_max_file_bytes(private_root, DEFAULT_MAX_FILE_BYTES)
    }

    pub fn with_max_file_bytes(
        private_root: &Path,
        max_file_bytes: u64,
    ) -> Result<Self, BrowserError> {
        if max_file_bytes == 0 || max_file_bytes > 2 * 1_024 * 1_024 * 1_024 {
            return Err(BrowserError::FileSizeRejected);
        }
        let metadata = fs::symlink_metadata(private_root)
            .map_err(|_| BrowserError::InvalidProfileDirectory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(BrowserError::InvalidProfileDirectory);
        }
        validate_private_directory(&metadata)?;
        let canonical_root = fs::canonicalize(private_root)?;
        let session_directory = TempBuilder::new()
            .prefix("file-broker-")
            .tempdir_in(&canonical_root)?;
        set_private_directory(session_directory.path())?;
        Ok(Self {
            directory: BrokerDirectory::Ephemeral(session_directory),
            root_digest: digest(canonical_root.as_os_str().as_encoded_bytes()),
            max_file_bytes,
            grants: BTreeMap::new(),
            staged_paths: BTreeMap::new(),
        })
    }

    pub fn open_durable(
        private_root: &Path,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        persisted_grants: impl IntoIterator<Item = BrowserFileGrant>,
    ) -> Result<(Self, FileBrokerReconciliation), BrowserError> {
        Self::open_durable_with_max_file_bytes(
            private_root,
            tenant_id,
            project_id,
            persisted_grants,
            DEFAULT_MAX_FILE_BYTES,
        )
    }

    pub fn open_durable_with_max_file_bytes(
        private_root: &Path,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        persisted_grants: impl IntoIterator<Item = BrowserFileGrant>,
        max_file_bytes: u64,
    ) -> Result<(Self, FileBrokerReconciliation), BrowserError> {
        if max_file_bytes == 0 || max_file_bytes > 2 * 1_024 * 1_024 * 1_024 {
            return Err(BrowserError::FileSizeRejected);
        }
        let root_metadata = fs::symlink_metadata(private_root)
            .map_err(|_| BrowserError::InvalidProfileDirectory)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(BrowserError::InvalidProfileDirectory);
        }
        validate_private_directory(&root_metadata)?;
        let canonical_root = fs::canonicalize(private_root)?;
        let scope_digest = durable_scope_digest(tenant_id, project_id)?;
        let directory_path = canonical_root.join(format!("project-{}", &scope_digest[..32]));
        prepare_durable_directory(&directory_path, &scope_digest)?;
        if fs::canonicalize(&directory_path)?
            .parent()
            .is_none_or(|parent| parent != canonical_root)
        {
            return Err(BrowserError::FileBrokerDirectoryTampered);
        }
        let lock_path = directory_path.join(DURABLE_LOCK_FILE);
        let lock_file = open_broker_lock(&lock_path)?;
        set_private_file(&lock_path)?;
        lock_file
            .try_lock()
            .map_err(|_| BrowserError::FileBrokerInUse)?;
        let mut broker = Self {
            directory: BrokerDirectory::Durable(DurableBrokerDirectory {
                path: directory_path,
                _lock_file: lock_file,
            }),
            root_digest: digest(canonical_root.as_os_str().as_encoded_bytes()),
            max_file_bytes,
            grants: BTreeMap::new(),
            staged_paths: BTreeMap::new(),
        };
        let reconciliation = broker.restore_durable_grants(
            tenant_id,
            project_id,
            persisted_grants.into_iter().collect(),
        )?;
        Ok((broker, reconciliation))
    }

    fn restore_durable_grants(
        &mut self,
        tenant_id: &TenantId,
        project_id: &ProjectId,
        persisted_grants: Vec<BrowserFileGrant>,
    ) -> Result<FileBrokerReconciliation, BrowserError> {
        let mut active_names = BTreeSet::new();
        let mut terminal_names = BTreeSet::new();
        let mut missing_or_changed_grants = Vec::new();
        let mut restored_terminal_grants = 0_usize;
        for grant in persisted_grants {
            grant.validate()?;
            if grant.tenant_id != *tenant_id
                || grant.project_id != *project_id
                || grant.byte_count > self.max_file_bytes
                || self.grants.contains_key(&grant.id)
            {
                return Err(BrowserError::InvalidFileGrant);
            }
            let name = staged_file_name(&grant.id, &grant.content_digest);
            if grant.is_active() {
                if terminal_names.contains(&name) || !active_names.insert(name.clone()) {
                    return Err(BrowserError::FileBrokerDirectoryTampered);
                }
                let path = self.directory.path().join(&name);
                match validate_restored_staged_file(&path, &grant.content_digest, grant.byte_count)
                {
                    Ok(()) => {
                        self.staged_paths.insert(grant.id.clone(), path);
                    }
                    Err(RestoredFileError::Missing) => {
                        active_names.remove(&name);
                        missing_or_changed_grants.push(grant.id.clone());
                    }
                    Err(RestoredFileError::Changed) => {
                        active_names.remove(&name);
                        fs::remove_file(&path)?;
                        missing_or_changed_grants.push(grant.id.clone());
                    }
                    Err(RestoredFileError::Tampered) => {
                        return Err(BrowserError::FileBrokerDirectoryTampered);
                    }
                    Err(RestoredFileError::Io(error)) => return Err(BrowserError::Io(error)),
                }
            } else {
                if active_names.contains(&name) || !terminal_names.insert(name) {
                    return Err(BrowserError::FileBrokerDirectoryTampered);
                }
                restored_terminal_grants = restored_terminal_grants
                    .checked_add(1)
                    .ok_or(BrowserError::CounterOverflow)?;
            }
            self.grants.insert(grant.id.clone(), grant);
        }

        let mut removed_orphan_files = 0_usize;
        let mut removed_terminal_files = 0_usize;
        for entry in fs::read_dir(self.directory.path())? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| BrowserError::FileBrokerDirectoryTampered)?;
            if name == DURABLE_SCOPE_MARKER || name == DURABLE_LOCK_FILE {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(BrowserError::FileBrokerDirectoryTampered);
            }
            if active_names.contains(&name) {
                continue;
            }
            if terminal_names.contains(&name) {
                fs::remove_file(entry.path())?;
                removed_terminal_files = removed_terminal_files
                    .checked_add(1)
                    .ok_or(BrowserError::CounterOverflow)?;
            } else if is_managed_pending_name(&name) || is_managed_blob_name(&name) {
                fs::remove_file(entry.path())?;
                removed_orphan_files = removed_orphan_files
                    .checked_add(1)
                    .ok_or(BrowserError::CounterOverflow)?;
            } else {
                return Err(BrowserError::FileBrokerDirectoryTampered);
            }
        }
        missing_or_changed_grants.sort();
        Ok(FileBrokerReconciliation {
            restored_active_grants: self.staged_paths.len(),
            restored_terminal_grants,
            removed_orphan_files,
            removed_terminal_files,
            missing_or_changed_grants,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_upload(
        &mut self,
        grant_id: BrowserFileGrantId,
        project: &Project,
        workspace: &BrowserWorkspace,
        proof: &BrowserLeaseProof,
        source_path: &Path,
        expected_type: BrowserFileType,
        authorization_evidence_digest: String,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
        scanner: &mut impl FileSafetyScanner,
    ) -> Result<BrowserFileGrant, BrowserError> {
        workspace.validate_agent_lease(proof, now)?;
        if project.tenant_id != workspace.tenant_id
            || project.id != workspace.project_id
            || self.grants.contains_key(&grant_id)
            || !is_bounded_identifier(grant_id.as_str())
            || !is_sha256(&authorization_evidence_digest)
            || expires_at <= now
            || expires_at - now > MAX_GRANT_LIFETIME
        {
            return Err(BrowserError::InvalidFileGrant);
        }
        let source = open_authorized_source(project, source_path, self.max_file_bytes)?;
        let pending_path = self.directory.path().join(format!(
            "pending-{}",
            &digest(grant_id.as_str().as_bytes())[..32]
        ));
        let staged = stage_source(source, &pending_path, self.max_file_bytes)?;
        let final_path = self
            .directory
            .path()
            .join(staged_file_name(&grant_id, &staged.content_digest));
        let (detected_type, scan_report) = finalize_staged_source(
            &pending_path,
            &final_path,
            &staged,
            expected_type,
            now,
            scanner,
        )?;

        let type_ruleset_digest = digest(FILE_TYPE_RULESET.as_bytes());
        let lease_id_digest = digest(workspace.lease_id.as_str().as_bytes());
        let mut grant = BrowserFileGrant {
            schema_version: FILE_GRANT_SCHEMA_VERSION,
            id: grant_id.clone(),
            tenant_id: workspace.tenant_id.clone(),
            project_id: workspace.project_id.clone(),
            mission_id: workspace.mission_id.clone(),
            workspace_id: workspace.id.clone(),
            lease_id_digest,
            lease_generation: workspace.lease_generation,
            source_path_digest: staged.source_path_digest,
            original_name_digest: staged.original_name_digest,
            content_digest: staged.content_digest,
            byte_count: staged.byte_count,
            detected_type,
            type_ruleset_digest,
            scan_report,
            authorization_evidence_digest,
            upload_payload_digest: digest(b"pending-file-grant-payload"),
            state: BrowserFileGrantState::Prepared,
            claim_id: None,
            terminal_evidence_digest: None,
            expires_at,
            created_at: now,
            updated_at: now,
            revision: 1,
        };
        grant.upload_payload_digest = file_grant_payload_digest(&grant)?;
        grant.validate()?;
        self.staged_paths.insert(grant_id.clone(), final_path);
        self.grants.insert(grant_id, grant.clone());
        Ok(grant)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn claim_upload(
        &mut self,
        grant_id: &BrowserFileGrantId,
        claim_id: BrowserFileClaimId,
        workspace: &BrowserWorkspace,
        proof: &BrowserLeaseProof,
        action_payload_digest: &str,
        expected_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<FileUploadHandle, BrowserError> {
        let plan = self.plan_claim_upload(
            grant_id,
            claim_id,
            workspace,
            proof,
            action_payload_digest,
            expected_revision,
            now,
        )?;
        self.commit_claim_upload(plan)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_claim_upload(
        &self,
        grant_id: &BrowserFileGrantId,
        claim_id: BrowserFileClaimId,
        workspace: &BrowserWorkspace,
        proof: &BrowserLeaseProof,
        action_payload_digest: &str,
        expected_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<FileClaimPlan, BrowserError> {
        workspace.validate_agent_lease(proof, now)?;
        let grant = self
            .grants
            .get(grant_id)
            .ok_or(BrowserError::InvalidFileGrant)?;
        grant.validate()?;
        if grant.revision != expected_revision
            || grant.state != BrowserFileGrantState::Prepared
            || !is_bounded_identifier(claim_id.as_str())
            || grant.tenant_id != workspace.tenant_id
            || grant.project_id != workspace.project_id
            || grant.mission_id != workspace.mission_id
            || grant.workspace_id != workspace.id
            || grant.lease_id_digest != digest(workspace.lease_id.as_str().as_bytes())
            || grant.lease_generation != workspace.lease_generation
            || action_payload_digest != grant.upload_payload_digest
        {
            return Err(BrowserError::InvalidFileGrant);
        }
        if now >= grant.expires_at {
            return Err(BrowserError::FileGrantExpired);
        }
        let path = self
            .staged_paths
            .get(grant_id)
            .ok_or(BrowserError::FileChanged)?;
        verify_staged_file(path, &grant.content_digest, grant.byte_count)?;
        let mut next = grant.clone();
        next.state = BrowserFileGrantState::Leased;
        next.claim_id = Some(claim_id.clone());
        next.updated_at = now;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        next.validate()?;
        let handle = FileUploadHandle {
            grant_id: next.id.clone(),
            claim_id,
            workspace_id: next.workspace_id.clone(),
            lease_generation: next.lease_generation,
            content_digest: next.content_digest.clone(),
            byte_count: next.byte_count,
            detected_type: next.detected_type,
            staged_path: path.clone(),
        };
        Ok(FileClaimPlan {
            previous: grant.clone(),
            next,
            handle,
        })
    }

    pub fn commit_claim_upload(
        &mut self,
        plan: FileClaimPlan,
    ) -> Result<FileUploadHandle, BrowserError> {
        let current = self
            .grants
            .get(&plan.next.id)
            .ok_or(BrowserError::InvalidFileGrant)?;
        let staged_path = self
            .staged_paths
            .get(&plan.next.id)
            .ok_or(BrowserError::FileChanged)?;
        if current != &plan.previous
            || staged_path != plan.handle.staged_path()
            || plan.next.state != BrowserFileGrantState::Leased
            || !plan.next.is_valid_successor_of(current)?
        {
            return Err(BrowserError::InvalidFileGrant);
        }
        verify_staged_file(staged_path, &plan.next.content_digest, plan.next.byte_count)?;
        self.grants.insert(plan.next.id.clone(), plan.next);
        Ok(plan.handle)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn complete_upload(
        &mut self,
        grant_id: &BrowserFileGrantId,
        claim_id: &BrowserFileClaimId,
        workspace: &BrowserWorkspace,
        proof: &BrowserLeaseProof,
        expected_revision: u64,
        completion_evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<BrowserFileGrant, BrowserError> {
        let plan = self.plan_complete_upload(
            grant_id,
            claim_id,
            workspace,
            proof,
            expected_revision,
            completion_evidence_digest,
            now,
        )?;
        self.commit_terminal_transition(plan)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_complete_upload(
        &self,
        grant_id: &BrowserFileGrantId,
        claim_id: &BrowserFileClaimId,
        workspace: &BrowserWorkspace,
        proof: &BrowserLeaseProof,
        expected_revision: u64,
        completion_evidence_digest: String,
        now: DateTime<Utc>,
    ) -> Result<FileTerminalPlan, BrowserError> {
        workspace.validate_agent_lease(proof, now)?;
        let grant = self
            .grants
            .get(grant_id)
            .ok_or(BrowserError::InvalidFileGrant)?;
        if grant.revision != expected_revision
            || grant.state != BrowserFileGrantState::Leased
            || grant.claim_id.as_ref() != Some(claim_id)
            || grant.workspace_id != workspace.id
            || grant.lease_generation != workspace.lease_generation
            || grant.lease_id_digest != digest(workspace.lease_id.as_str().as_bytes())
            || !is_sha256(&completion_evidence_digest)
        {
            return Err(BrowserError::InvalidFileGrant);
        }
        let path = self
            .staged_paths
            .get(grant_id)
            .cloned()
            .ok_or(BrowserError::FileChanged)?;
        verify_staged_file(&path, &grant.content_digest, grant.byte_count)?;
        let mut next = grant.clone();
        next.state = BrowserFileGrantState::Consumed;
        next.terminal_evidence_digest = Some(completion_evidence_digest);
        next.updated_at = now;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        next.validate()?;
        Ok(FileTerminalPlan {
            previous: grant.clone(),
            next,
            staged_path: Some(path),
        })
    }

    pub fn expire_grant(
        &mut self,
        grant_id: &BrowserFileGrantId,
        expected_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<BrowserFileGrant, BrowserError> {
        let plan = self.plan_expire_grant(grant_id, expected_revision, now)?;
        self.commit_terminal_transition(plan)
    }

    pub fn plan_expire_grant(
        &self,
        grant_id: &BrowserFileGrantId,
        expected_revision: u64,
        now: DateTime<Utc>,
    ) -> Result<FileTerminalPlan, BrowserError> {
        let grant = self
            .grants
            .get(grant_id)
            .ok_or(BrowserError::InvalidFileGrant)?;
        if grant.revision != expected_revision
            || !matches!(
                grant.state,
                BrowserFileGrantState::Prepared | BrowserFileGrantState::Leased
            )
            || now < grant.expires_at
        {
            return Err(BrowserError::FileGrantUnavailable);
        }
        let mut next = grant.clone();
        next.state = BrowserFileGrantState::Expired;
        next.terminal_evidence_digest = Some(digest_json(&serde_json::json!({
            "grantId": grant.id,
            "expiredAt": now,
            "priorRevision": grant.revision,
        }))?);
        next.updated_at = now;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(BrowserError::CounterOverflow)?;
        next.validate()?;
        Ok(FileTerminalPlan {
            previous: grant.clone(),
            next,
            staged_path: self.staged_paths.get(grant_id).cloned(),
        })
    }

    pub fn commit_terminal_transition(
        &mut self,
        plan: FileTerminalPlan,
    ) -> Result<BrowserFileGrant, BrowserError> {
        let current = self
            .grants
            .get(&plan.next.id)
            .ok_or(BrowserError::InvalidFileGrant)?;
        if current != &plan.previous
            || !matches!(
                plan.next.state,
                BrowserFileGrantState::Consumed
                    | BrowserFileGrantState::Revoked
                    | BrowserFileGrantState::Expired
            )
            || !plan.next.is_valid_successor_of(current)?
            || self.staged_paths.get(&plan.next.id) != plan.staged_path.as_ref()
        {
            return Err(BrowserError::InvalidFileGrant);
        }
        if plan.next.state == BrowserFileGrantState::Consumed {
            let path = plan.staged_path.as_ref().ok_or(BrowserError::FileChanged)?;
            verify_staged_file(path, &plan.next.content_digest, plan.next.byte_count)?;
        }
        if let Some(path) = &plan.staged_path {
            fs::remove_file(path)?;
        }
        self.staged_paths.remove(&plan.next.id);
        self.grants.insert(plan.next.id.clone(), plan.next.clone());
        Ok(plan.next)
    }

    pub fn discard_unpersisted_prepared_grant(
        &mut self,
        grant: &BrowserFileGrant,
    ) -> Result<(), BrowserError> {
        grant.validate()?;
        let current = self
            .grants
            .get(&grant.id)
            .ok_or(BrowserError::InvalidFileGrant)?;
        if current != grant || grant.revision != 1 || grant.state != BrowserFileGrantState::Prepared
        {
            return Err(BrowserError::InvalidFileGrant);
        }
        let path = self
            .staged_paths
            .get(&grant.id)
            .cloned()
            .ok_or(BrowserError::FileChanged)?;
        fs::remove_file(&path)?;
        self.staged_paths.remove(&grant.id);
        self.grants.remove(&grant.id);
        Ok(())
    }

    pub fn grant(&self, id: &BrowserFileGrantId) -> Option<&BrowserFileGrant> {
        self.grants.get(id)
    }
}

impl fmt::Debug for FileBroker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileBroker")
            .field("root_digest", &self.root_digest)
            .field(
                "directory_digest",
                &digest(self.directory.path().as_os_str().as_encoded_bytes()),
            )
            .field("mode", &self.directory.mode_name())
            .field("max_file_bytes", &self.max_file_bytes)
            .field("grant_count", &self.grants.len())
            .field("staged_file_count", &self.staged_paths.len())
            .finish()
    }
}

fn durable_scope_digest(
    tenant_id: &TenantId,
    project_id: &ProjectId,
) -> Result<String, BrowserError> {
    digest_json(&serde_json::json!({
        "schemaVersion": DURABLE_BROKER_SCHEMA_VERSION,
        "tenantId": tenant_id,
        "projectId": project_id,
    }))
}

fn prepare_durable_directory(path: &Path, scope_digest: &str) -> Result<(), BrowserError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(BrowserError::FileBrokerDirectoryTampered);
            }
            validate_private_directory(&metadata)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path)?;
            set_private_directory(path)?;
        }
        Err(error) => return Err(BrowserError::Io(error)),
    }
    let marker_path = path.join(DURABLE_SCOPE_MARKER);
    match fs::symlink_metadata(&marker_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 64 {
                return Err(BrowserError::FileBrokerDirectoryTampered);
            }
            let value = fs::read_to_string(&marker_path)?;
            if value != scope_digest {
                return Err(BrowserError::FileBrokerDirectoryTampered);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut marker = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker_path)?;
            set_private_file(&marker_path)?;
            marker.write_all(scope_digest.as_bytes())?;
            marker.flush()?;
            marker.sync_all()?;
            drop(marker);
            set_read_only_file(&marker_path)?;
        }
        Err(error) => return Err(BrowserError::Io(error)),
    }
    Ok(())
}

fn open_broker_lock(path: &Path) -> Result<File, BrowserError> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(BrowserError::FileBrokerDirectoryTampered);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(BrowserError::FileBrokerDirectoryTampered);
    }
    Ok(file)
}

fn staged_file_name(grant_id: &BrowserFileGrantId, content_digest: &str) -> String {
    format!(
        "blob-{}-{}",
        &content_digest[..32],
        &digest(grant_id.as_str().as_bytes())[..16]
    )
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_managed_pending_name(name: &str) -> bool {
    name.len() == 40 && name.starts_with("pending-") && is_lower_hex(&name[8..])
}

fn is_managed_blob_name(name: &str) -> bool {
    name.len() == 54
        && name.starts_with("blob-")
        && name.as_bytes().get(37) == Some(&b'-')
        && is_lower_hex(&name[5..37])
        && is_lower_hex(&name[38..])
}

enum RestoredFileError {
    Missing,
    Changed,
    Tampered,
    Io(std::io::Error),
}

fn validate_restored_staged_file(
    path: &Path,
    expected_digest: &str,
    expected_bytes: u64,
) -> Result<(), RestoredFileError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(RestoredFileError::Missing);
        }
        Err(error) => return Err(RestoredFileError::Io(error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RestoredFileError::Tampered);
    }
    match verify_staged_file(path, expected_digest, expected_bytes) {
        Ok(()) => Ok(()),
        Err(BrowserError::FileChanged) => Err(RestoredFileError::Changed),
        Err(BrowserError::Io(error)) => Err(RestoredFileError::Io(error)),
        Err(_) => Err(RestoredFileError::Tampered),
    }
}

struct AuthorizedSource {
    file: File,
    identity: SourceIdentity,
    source_path_digest: String,
    original_name_digest: String,
}

struct SourceIdentity {
    byte_count: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

struct StagedSource {
    source_path_digest: String,
    original_name_digest: String,
    content_digest: String,
    byte_count: u64,
}

fn open_authorized_source(
    project: &Project,
    source_path: &Path,
    maximum: u64,
) -> Result<AuthorizedSource, BrowserError> {
    if !source_path.is_absolute() {
        return Err(BrowserError::FileOutsideProject);
    }
    let mut authorized = false;
    for root in &project.workspace_roots {
        if validate_path_under_root(root, source_path).is_ok() {
            authorized = true;
            break;
        }
    }
    if !authorized {
        return Err(BrowserError::FileOutsideProject);
    }
    let metadata = fs::symlink_metadata(source_path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BrowserError::FileOutsideProject);
    }
    let identity = source_identity(&metadata)?;
    if identity.byte_count == 0 || identity.byte_count > maximum {
        return Err(BrowserError::FileSizeRejected);
    }
    let file = open_source_no_follow(source_path)?;
    let opened_identity = source_identity(&file.metadata()?)?;
    if !same_source_identity(&identity, &opened_identity) {
        return Err(BrowserError::FileChanged);
    }
    let canonical = fs::canonicalize(source_path)?;
    let original_name = source_path
        .file_name()
        .ok_or(BrowserError::FileOutsideProject)?;
    Ok(AuthorizedSource {
        file,
        identity,
        source_path_digest: digest(canonical.as_os_str().as_encoded_bytes()),
        original_name_digest: digest(original_name.as_encoded_bytes()),
    })
}

fn stage_source(
    mut source: AuthorizedSource,
    pending_path: &Path,
    maximum: u64,
) -> Result<StagedSource, BrowserError> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(pending_path)?;
    set_private_file(pending_path)?;
    let result = (|| {
        let mut hasher = Sha256::new();
        let mut byte_count = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
        loop {
            let read = source.file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            byte_count = byte_count
                .checked_add(u64::try_from(read).map_err(|_| BrowserError::CounterOverflow)?)
                .ok_or(BrowserError::CounterOverflow)?;
            if byte_count > maximum {
                return Err(BrowserError::FileSizeRejected);
            }
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        output.flush()?;
        output.sync_all()?;
        let final_identity = source_identity(&source.file.metadata()?)?;
        if byte_count != source.identity.byte_count
            || !same_source_identity(&source.identity, &final_identity)
        {
            return Err(BrowserError::FileChanged);
        }
        Ok(StagedSource {
            source_path_digest: source.source_path_digest,
            original_name_digest: source.original_name_digest,
            content_digest: hex::encode(hasher.finalize()),
            byte_count,
        })
    })();
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(pending_path);
    }
    result
}

fn finalize_staged_source(
    pending_path: &Path,
    final_path: &Path,
    staged: &StagedSource,
    expected_type: BrowserFileType,
    now: DateTime<Utc>,
    scanner: &mut impl FileSafetyScanner,
) -> Result<(BrowserFileType, FileScanReport), BrowserError> {
    let result = (|| {
        let detected_type = detect_file_type(pending_path, staged.byte_count)?;
        if detected_type != expected_type {
            return Err(BrowserError::FileTypeRejected);
        }
        fs::rename(pending_path, final_path)?;
        set_read_only_file(final_path)?;
        let scan_request = FileScanRequest {
            staged_path: final_path,
            content_digest: &staged.content_digest,
            byte_count: staged.byte_count,
            detected_type,
            observed_at: now,
        };
        let scan_report = scanner.scan(&scan_request)?;
        scan_report.validate(now)?;
        match scan_report.decision {
            FileScanDecision::Clean => {}
            FileScanDecision::Rejected => return Err(BrowserError::FileScanRejected),
            FileScanDecision::Unavailable => return Err(BrowserError::FileScanUnavailable),
        }
        verify_staged_file(final_path, &staged.content_digest, staged.byte_count)?;
        Ok((detected_type, scan_report))
    })();
    if result.is_err() {
        let _ = fs::remove_file(pending_path);
        let _ = fs::remove_file(final_path);
    }
    result
}

fn detect_file_type(path: &Path, byte_count: u64) -> Result<BrowserFileType, BrowserError> {
    let mut file = File::open(path)?;
    let mut prefix = [0_u8; 16];
    let read = file.read(&mut prefix)?;
    let prefix = &prefix[..read];
    if prefix.starts_with(b"%PDF-") {
        return Ok(BrowserFileType::Pdf);
    }
    if prefix.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Ok(BrowserFileType::Png);
    }
    if prefix.starts_with(b"\xff\xd8\xff") {
        return Ok(BrowserFileType::Jpeg);
    }
    if prefix.starts_with(b"GIF87a") || prefix.starts_with(b"GIF89a") {
        return Ok(BrowserFileType::Gif);
    }
    if prefix.len() >= 12 && &prefix[..4] == b"RIFF" && &prefix[8..12] == b"WEBP" {
        return Ok(BrowserFileType::WebP);
    }
    if prefix.len() >= 8 && &prefix[4..8] == b"ftyp" {
        return Ok(BrowserFileType::Mp4);
    }
    if byte_count > MAX_TEXT_BYTES {
        return Err(BrowserError::FileTypeRejected);
    }
    let bytes = fs::read(path)?;
    if bytes.contains(&0) {
        return Err(BrowserError::FileTypeRejected);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| BrowserError::FileTypeRejected)?;
    let trimmed = text.trim_start().to_ascii_lowercase();
    if trimmed.starts_with("<svg")
        || trimmed.starts_with("<!doctype html")
        || trimmed.starts_with("<html")
        || trimmed.starts_with("<script")
    {
        return Err(BrowserError::FileTypeRejected);
    }
    if serde_json::from_str::<Value>(text).is_ok() {
        Ok(BrowserFileType::Json)
    } else {
        Ok(BrowserFileType::Utf8Text)
    }
}

fn verify_staged_file(
    path: &Path,
    expected_digest: &str,
    expected_bytes: u64,
) -> Result<(), BrowserError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != expected_bytes
    {
        return Err(BrowserError::FileChanged);
    }
    let mut reader = BufReader::new(open_source_no_follow(path)?);
    let mut hasher = Sha256::new();
    let mut byte_count = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1_024].into_boxed_slice();
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        byte_count = byte_count
            .checked_add(u64::try_from(read).map_err(|_| BrowserError::CounterOverflow)?)
            .ok_or(BrowserError::CounterOverflow)?;
        hasher.update(&buffer[..read]);
    }
    if byte_count != expected_bytes || hex::encode(hasher.finalize()) != expected_digest {
        return Err(BrowserError::FileChanged);
    }
    Ok(())
}

fn validate_path_under_root(root: &Path, source: &Path) -> Result<(), BrowserError> {
    let root_metadata = fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(BrowserError::FileOutsideProject);
    }
    let relative = source
        .strip_prefix(root)
        .map_err(|_| BrowserError::FileOutsideProject)?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(BrowserError::FileOutsideProject);
        };
        cursor.push(component);
        let metadata = fs::symlink_metadata(&cursor)?;
        if metadata.file_type().is_symlink() {
            return Err(BrowserError::FileOutsideProject);
        }
    }
    let canonical_root = fs::canonicalize(root)?;
    let canonical_source = fs::canonicalize(source)?;
    if canonical_source == canonical_root || !canonical_source.starts_with(canonical_root) {
        return Err(BrowserError::FileOutsideProject);
    }
    Ok(())
}

fn source_identity(metadata: &fs::Metadata) -> Result<SourceIdentity, BrowserError> {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    Ok(SourceIdentity {
        byte_count: metadata.len(),
        modified: metadata.modified()?,
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    })
}

fn same_source_identity(left: &SourceIdentity, right: &SourceIdentity) -> bool {
    left.byte_count == right.byte_count && left.modified == right.modified && {
        #[cfg(unix)]
        {
            left.device == right.device && left.inode == right.inode
        }
        #[cfg(not(unix))]
        {
            true
        }
    }
}

#[cfg(unix)]
fn open_source_no_follow(path: &Path) -> Result<File, BrowserError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(BrowserError::Io)
}

#[cfg(not(unix))]
fn open_source_no_follow(path: &Path) -> Result<File, BrowserError> {
    File::open(path).map_err(BrowserError::Io)
}

#[cfg(unix)]
fn validate_private_directory(metadata: &fs::Metadata) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(BrowserError::InvalidProfileDirectory);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_directory(_metadata: &fs::Metadata) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<(), BrowserError> {
    Ok(())
}

#[cfg(unix)]
fn set_read_only_file(path: &Path) -> Result<(), BrowserError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_read_only_file(path: &Path) -> Result<(), BrowserError> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use chrono::TimeZone;
    use hartevo_domain_kernel::{
        AccountId, BrowserControlLeaseId, BrowserProfileId, BrowserTabId, Mission, MissionContract,
        ProjectId, StorageMode,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{BrowserIdentity, BrowserProfile};

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 11, 14, 0, 0)
            .single()
            .expect("time")
    }

    fn fixture(temp: &TempDir) -> (Project, BrowserWorkspace, PathBuf, FileBroker) {
        let project_root = temp.path().join("project");
        let broker_root = temp.path().join("broker");
        fs::create_dir(&project_root).expect("project root");
        fs::create_dir(&broker_root).expect("broker root");
        #[cfg(unix)]
        fs::set_permissions(&broker_root, fs::Permissions::from_mode(0o700))
            .expect("private broker root");
        let project = Project::create_local(
            TenantId::from("tenant-file-broker"),
            ProjectId::from("project-file-broker"),
            "File broker",
            "",
            &project_root,
            StorageMode::LocalExisting,
        )
        .expect("project");
        let mission = Mission::compile(
            project.tenant_id.clone(),
            MissionId::from("mission-file-broker"),
            project.id.clone(),
            "Upload deliverable",
            MissionContract::bootstrap(
                "Upload one reviewed deliverable",
                ["deliverable.upload".into()],
                now(),
            ),
            now(),
        )
        .expect("mission");
        let identity = BrowserIdentity::new(
            "hartevo-opt-in",
            AccountId::from("account-file-broker"),
            sha('1'),
            sha('2'),
            now(),
        )
        .expect("identity");
        let profile = BrowserProfile::create_managed(
            BrowserProfileId::from("profile-file-broker"),
            &project,
            "keyring://browser/file-broker",
            identity,
            now(),
        )
        .expect("profile");
        let workspace = BrowserWorkspace::create(
            BrowserWorkspaceId::from("workspace-file-broker"),
            &project,
            &mission,
            &profile,
            BrowserTabId::from("tab-file-broker"),
            BrowserControlLeaseId::from("lease-file-broker-1"),
            now() + Duration::hours(1),
            sha('3'),
            now(),
        )
        .expect("workspace");
        let broker = FileBroker::new(&broker_root).expect("broker");
        (project, workspace, project_root, broker)
    }

    struct CleanScanner;

    impl FileSafetyScanner for CleanScanner {
        fn scan(&mut self, request: &FileScanRequest<'_>) -> Result<FileScanReport, BrowserError> {
            Ok(FileScanReport {
                scanner_id: "fixture-scanner".into(),
                scanner_version: "v1".into(),
                decision: FileScanDecision::Clean,
                evidence_digest: digest_json(&serde_json::json!({
                    "contentDigest": request.content_digest,
                    "byteCount": request.byte_count,
                    "type": request.detected_type,
                }))?,
                scanned_at: request.observed_at,
            })
        }
    }

    #[test]
    fn exact_clean_file_grant_claim_and_completion_is_single_use_and_redacted() {
        let temp = TempDir::new().expect("temp dir");
        let (project, workspace, project_root, mut broker) = fixture(&temp);
        let source = project_root.join("deliverable.json");
        let private_content = br#"{"customer":"private@example.com","status":"ready"}"#;
        fs::write(&source, private_content).expect("source file");
        let proof = workspace.agent_lease_proof(now()).expect("proof");
        let grant_id = BrowserFileGrantId::from("grant-file-broker-1");
        let grant = broker
            .prepare_upload(
                grant_id.clone(),
                &project,
                &workspace,
                &proof,
                &source,
                BrowserFileType::Json,
                sha('4'),
                now() + Duration::minutes(10),
                now(),
                &mut CleanScanner,
            )
            .expect("prepare upload");
        assert_eq!(grant.state, BrowserFileGrantState::Prepared);
        let mut tampered = grant.clone();
        tampered.content_digest = sha('8');
        assert!(matches!(
            tampered.validate(),
            Err(BrowserError::InvalidFileGrant)
        ));
        let debug = format!("{grant:?} {broker:?}");
        assert!(!debug.contains("private@example.com"));
        assert!(!debug.contains(source.to_string_lossy().as_ref()));
        let claim_plan = broker
            .plan_claim_upload(
                &grant_id,
                BrowserFileClaimId::from("claim-file-broker-1"),
                &workspace,
                &proof,
                &grant.upload_payload_digest,
                grant.revision,
                now(),
            )
            .expect("plan claim upload");
        assert_eq!(
            broker
                .grant(&grant_id)
                .expect("grant before durable claim")
                .state,
            BrowserFileGrantState::Prepared
        );
        assert_eq!(claim_plan.grant().state, BrowserFileGrantState::Leased);
        let claim = broker
            .commit_claim_upload(claim_plan)
            .expect("commit claim after persistence boundary");
        claim
            .validate_for(broker.grant(&grant_id).expect("leased grant"), &workspace)
            .expect("exact leased handle");
        assert!(claim.staged_path().exists());
        assert!(!format!("{claim:?}").contains(claim.staged_path().to_string_lossy().as_ref()));
        assert!(matches!(
            broker.claim_upload(
                &grant_id,
                BrowserFileClaimId::from("claim-file-broker-2"),
                &workspace,
                &proof,
                &grant.upload_payload_digest,
                grant.revision,
                now(),
            ),
            Err(BrowserError::InvalidFileGrant)
        ));
        let terminal_plan = broker
            .plan_complete_upload(
                &grant_id,
                &claim.claim_id,
                &workspace,
                &proof,
                2,
                sha('5'),
                now(),
            )
            .expect("plan complete upload");
        assert_eq!(
            broker
                .grant(&grant_id)
                .expect("grant before durable terminal")
                .state,
            BrowserFileGrantState::Leased
        );
        assert!(claim.staged_path().exists());
        let completed = broker
            .commit_terminal_transition(terminal_plan)
            .expect("commit terminal after persistence boundary");
        assert_eq!(completed.state, BrowserFileGrantState::Consumed);
        assert!(!claim.staged_path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn source_symlink_escape_and_in_project_symlink_are_both_rejected() {
        let temp = TempDir::new().expect("temp dir");
        let (project, workspace, project_root, mut broker) = fixture(&temp);
        let outside = temp.path().join("outside.json");
        fs::write(&outside, b"{}").expect("outside file");
        let linked = project_root.join("linked.json");
        symlink(&outside, &linked).expect("symlink");
        let proof = workspace.agent_lease_proof(now()).expect("proof");
        let result = broker.prepare_upload(
            BrowserFileGrantId::from("grant-symlink"),
            &project,
            &workspace,
            &proof,
            &linked,
            BrowserFileType::Json,
            sha('4'),
            now() + Duration::minutes(10),
            now(),
            &mut CleanScanner,
        );
        assert!(matches!(result, Err(BrowserError::FileOutsideProject)));
        let result = broker.prepare_upload(
            BrowserFileGrantId::from("grant-outside"),
            &project,
            &workspace,
            &proof,
            &outside,
            BrowserFileType::Json,
            sha('4'),
            now() + Duration::minutes(10),
            now(),
            &mut CleanScanner,
        );
        assert!(matches!(result, Err(BrowserError::FileOutsideProject)));
    }

    struct MutatingScanner;

    impl FileSafetyScanner for MutatingScanner {
        fn scan(&mut self, request: &FileScanRequest<'_>) -> Result<FileScanReport, BrowserError> {
            #[cfg(unix)]
            fs::set_permissions(request.staged_path(), fs::Permissions::from_mode(0o600))?;
            fs::write(request.staged_path(), b"scanner-mutated-content")?;
            Ok(FileScanReport {
                scanner_id: "mutating-scanner".into(),
                scanner_version: "v1".into(),
                decision: FileScanDecision::Clean,
                evidence_digest: sha('9'),
                scanned_at: request.observed_at,
            })
        }
    }

    #[test]
    fn scanner_mutation_is_detected_after_a_claimed_clean_verdict() {
        let temp = TempDir::new().expect("temp dir");
        let (project, workspace, project_root, mut broker) = fixture(&temp);
        let source = project_root.join("deliverable.json");
        fs::write(&source, b"{}").expect("source file");
        let proof = workspace.agent_lease_proof(now()).expect("proof");
        let result = broker.prepare_upload(
            BrowserFileGrantId::from("grant-mutated"),
            &project,
            &workspace,
            &proof,
            &source,
            BrowserFileType::Json,
            sha('4'),
            now() + Duration::minutes(10),
            now(),
            &mut MutatingScanner,
        );
        assert!(matches!(result, Err(BrowserError::FileChanged)));
        assert!(broker.grants.is_empty());
    }

    #[test]
    fn wrong_type_active_content_and_oversize_are_rejected_before_a_grant() {
        let temp = TempDir::new().expect("temp dir");
        let (project, workspace, project_root, _) = fixture(&temp);
        let broker_root = temp.path().join("small-broker");
        fs::create_dir(&broker_root).expect("small broker root");
        #[cfg(unix)]
        fs::set_permissions(&broker_root, fs::Permissions::from_mode(0o700))
            .expect("private broker root");
        let proof = workspace.agent_lease_proof(now()).expect("proof");

        let source = project_root.join("wrong.txt");
        fs::write(&source, b"plain text").expect("source file");
        let mut broker = FileBroker::new(&broker_root).expect("broker");
        assert!(matches!(
            broker.prepare_upload(
                BrowserFileGrantId::from("grant-wrong-type"),
                &project,
                &workspace,
                &proof,
                &source,
                BrowserFileType::Json,
                sha('4'),
                now() + Duration::minutes(10),
                now(),
                &mut CleanScanner,
            ),
            Err(BrowserError::FileTypeRejected)
        ));

        let html = project_root.join("active.txt");
        fs::write(&html, b"<script>steal()</script>").expect("active file");
        assert!(matches!(
            broker.prepare_upload(
                BrowserFileGrantId::from("grant-active"),
                &project,
                &workspace,
                &proof,
                &html,
                BrowserFileType::Utf8Text,
                sha('4'),
                now() + Duration::minutes(10),
                now(),
                &mut CleanScanner,
            ),
            Err(BrowserError::FileTypeRejected)
        ));

        let large = project_root.join("large.txt");
        fs::write(&large, b"12345").expect("large file");
        let mut small_broker =
            FileBroker::with_max_file_bytes(&broker_root, 4).expect("small broker");
        assert!(matches!(
            small_broker.prepare_upload(
                BrowserFileGrantId::from("grant-large"),
                &project,
                &workspace,
                &proof,
                &large,
                BrowserFileType::Utf8Text,
                sha('4'),
                now() + Duration::minutes(10),
                now(),
                &mut CleanScanner,
            ),
            Err(BrowserError::FileSizeRejected)
        ));
    }

    #[test]
    fn takeover_or_expiry_invalidates_a_prepared_file_grant_without_rebinding() {
        let temp = TempDir::new().expect("temp dir");
        let (project, mut workspace, project_root, mut broker) = fixture(&temp);
        let source = project_root.join("deliverable.json");
        fs::write(&source, b"{}").expect("source file");
        let proof = workspace.agent_lease_proof(now()).expect("proof");
        let grant_id = BrowserFileGrantId::from("grant-takeover");
        let grant = broker
            .prepare_upload(
                grant_id.clone(),
                &project,
                &workspace,
                &proof,
                &source,
                BrowserFileType::Json,
                sha('4'),
                now() + Duration::minutes(10),
                now(),
                &mut CleanScanner,
            )
            .expect("grant");
        workspace
            .user_takeover(
                workspace.revision,
                workspace.lease_generation,
                BrowserControlLeaseId::from("lease-file-broker-2"),
                sha('5'),
                now(),
            )
            .expect("takeover");
        assert!(matches!(
            broker.claim_upload(
                &grant_id,
                BrowserFileClaimId::from("claim-after-takeover"),
                &workspace,
                &proof,
                &grant.upload_payload_digest,
                grant.revision,
                now(),
            ),
            Err(BrowserError::ControlLeaseLost)
        ));
        let expired = broker
            .expire_grant(&grant_id, grant.revision, grant.expires_at)
            .expect("expire grant");
        assert_eq!(expired.state, BrowserFileGrantState::Expired);
    }

    #[test]
    fn durable_broker_restores_exact_claim_and_cleans_terminal_crash_residue() {
        let temp = TempDir::new().expect("temp dir");
        let (project, workspace, project_root, ephemeral) = fixture(&temp);
        drop(ephemeral);
        let durable_root = temp.path().join("durable-broker");
        fs::create_dir(&durable_root).expect("durable broker root");
        #[cfg(unix)]
        fs::set_permissions(&durable_root, fs::Permissions::from_mode(0o700))
            .expect("private durable root");
        let (mut broker, initial) =
            FileBroker::open_durable(&durable_root, &project.tenant_id, &project.id, [])
                .expect("open durable broker");
        assert!(initial.is_healthy());
        let source = project_root.join("durable-deliverable.json");
        fs::write(&source, br#"{"durable":true}"#).expect("source file");
        let proof = workspace.agent_lease_proof(now()).expect("proof");
        let grant_id = BrowserFileGrantId::from("grant-durable-file-broker");
        let prepared = broker
            .prepare_upload(
                grant_id.clone(),
                &project,
                &workspace,
                &proof,
                &source,
                BrowserFileType::Json,
                sha('4'),
                now() + Duration::minutes(10),
                now(),
                &mut CleanScanner,
            )
            .expect("prepare durable grant");
        let handle = broker
            .claim_upload(
                &grant_id,
                BrowserFileClaimId::from("claim-durable-file-broker"),
                &workspace,
                &proof,
                &prepared.upload_payload_digest,
                prepared.revision,
                now() + Duration::seconds(1),
            )
            .expect("claim durable grant");
        let leased = broker.grant(&grant_id).expect("leased record").clone();
        assert!(leased.is_valid_successor_of(&prepared).expect("successor"));
        assert!(handle.staged_path().exists());
        assert!(matches!(
            FileBroker::open_durable(
                &durable_root,
                &project.tenant_id,
                &project.id,
                [leased.clone()]
            ),
            Err(BrowserError::FileBrokerInUse)
        ));
        drop(handle);
        drop(broker);

        let (restored, reconciliation) = FileBroker::open_durable(
            &durable_root,
            &project.tenant_id,
            &project.id,
            [leased.clone()],
        )
        .expect("restore durable claim");
        assert_eq!(reconciliation.restored_active_grants, 1);
        assert!(reconciliation.is_healthy());
        assert_eq!(restored.grant(&grant_id), Some(&leased));
        let staged_path = restored
            .staged_paths
            .get(&grant_id)
            .expect("restored staged path")
            .clone();
        drop(restored);

        let mut consumed_after_database_commit = leased.clone();
        consumed_after_database_commit.state = BrowserFileGrantState::Consumed;
        consumed_after_database_commit.terminal_evidence_digest = Some(sha('5'));
        consumed_after_database_commit.updated_at = now() + Duration::seconds(2);
        consumed_after_database_commit.revision = 3;
        consumed_after_database_commit
            .validate()
            .expect("valid terminal record");
        assert!(
            consumed_after_database_commit
                .is_valid_successor_of(&leased)
                .expect("terminal successor")
        );
        let (terminal, reconciliation) = FileBroker::open_durable(
            &durable_root,
            &project.tenant_id,
            &project.id,
            [consumed_after_database_commit.clone()],
        )
        .expect("reconcile terminal file after crash");
        assert_eq!(reconciliation.restored_terminal_grants, 1);
        assert_eq!(reconciliation.removed_terminal_files, 1);
        assert!(reconciliation.is_healthy());
        assert!(!staged_path.exists());
        assert_eq!(
            terminal.grant(&grant_id),
            Some(&consumed_after_database_commit)
        );
    }

    #[test]
    fn durable_broker_removes_known_orphans_but_fails_closed_on_unknown_entries() {
        let temp = TempDir::new().expect("temp dir");
        let (project, _, _, ephemeral) = fixture(&temp);
        drop(ephemeral);
        let durable_root = temp.path().join("durable-orphans");
        fs::create_dir(&durable_root).expect("durable root");
        #[cfg(unix)]
        fs::set_permissions(&durable_root, fs::Permissions::from_mode(0o700))
            .expect("private durable root");
        let (broker, _) =
            FileBroker::open_durable(&durable_root, &project.tenant_id, &project.id, [])
                .expect("open broker");
        let directory = broker.directory.path().to_path_buf();
        fs::write(
            directory.join(format!("pending-{}", "a".repeat(32))),
            b"partial",
        )
        .expect("pending orphan");
        fs::write(
            directory.join(format!("blob-{}-{}", "b".repeat(32), "c".repeat(16))),
            b"orphan",
        )
        .expect("blob orphan");
        drop(broker);
        let (broker, reconciliation) =
            FileBroker::open_durable(&durable_root, &project.tenant_id, &project.id, [])
                .expect("clean known orphans");
        assert_eq!(reconciliation.removed_orphan_files, 2);
        fs::write(directory.join("unexpected-private-file"), b"tamper").expect("unknown entry");
        drop(broker);
        assert!(matches!(
            FileBroker::open_durable(&durable_root, &project.tenant_id, &project.id, []),
            Err(BrowserError::FileBrokerDirectoryTampered)
        ));
    }
}
