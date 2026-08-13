use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    DeploymentId, DomainId, Mission, MissionId, ProjectId, PublicationActivityId, PublicationId,
    SiteId, TenantId, WorkProductId, WorkProductManifest, WorkProductManifestError,
    WorkProductPreview, WorkProductStatus,
};

pub const WEB_PUBLICATION_SCHEMA_VERSION: &str = "hartevo-web-publication/v1";
const DIGEST_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationEnvironment {
    Staging,
    Production,
}

impl PublicationEnvironment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteStatus {
    Draft,
    Active,
    Archived,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Site {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub id: SiteId,
    pub name: String,
    pub status: SiteStatus,
    pub latest_revision: u64,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Site {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        id: SiteId,
        name: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        let name = non_empty(name.into(), "site name")?;
        Ok(Self {
            tenant_id,
            project_id,
            id,
            name,
            status: SiteStatus::Draft,
            latest_revision: 0,
            revision: 1,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn record_revision(
        &self,
        revision: u64,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        let expected = self
            .latest_revision
            .checked_add(1)
            .ok_or(WebPublicationError::RevisionOverflow)?;
        if revision != expected {
            return Err(WebPublicationError::UnexpectedRevision {
                expected,
                actual: revision,
            });
        }
        Ok(Self {
            latest_revision: revision,
            revision: self
                .revision
                .checked_add(1)
                .ok_or(WebPublicationError::RevisionOverflow)?,
            updated_at: now,
            ..self.clone()
        })
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        non_empty(self.name.clone(), "site name")?;
        if self.revision == 0 {
            return Err(WebPublicationError::InvalidRevision);
        }
        if self.updated_at < self.created_at {
            return Err(WebPublicationError::InvalidTimestamp("site"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainStatus {
    Unconfigured,
    PendingVerification,
    Verified,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub site_id: SiteId,
    pub id: DomainId,
    pub hostname: String,
    pub status: DomainStatus,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Domain {
    pub fn new(
        tenant_id: TenantId,
        project_id: ProjectId,
        site_id: SiteId,
        id: DomainId,
        hostname: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        let hostname = hostname.into();
        let hostname = validate_hostname(&hostname)?;
        Ok(Self {
            tenant_id,
            project_id,
            site_id,
            id,
            hostname,
            status: DomainStatus::Unconfigured,
            revision: 1,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn mark_verified(&self, now: DateTime<Utc>) -> Result<Self, WebPublicationError> {
        Ok(Self {
            status: DomainStatus::Verified,
            revision: self
                .revision
                .checked_add(1)
                .ok_or(WebPublicationError::RevisionOverflow)?,
            updated_at: now,
            ..self.clone()
        })
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        validate_hostname(&self.hostname)?;
        if self.revision == 0 {
            return Err(WebPublicationError::InvalidRevision);
        }
        if self.updated_at < self.created_at {
            return Err(WebPublicationError::InvalidTimestamp("domain"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    PreviewReady,
    ApprovedForPublication,
    Published,
    Verified,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub site_id: SiteId,
    pub id: DeploymentId,
    pub source_revision: u64,
    pub environment: PublicationEnvironment,
    pub artifact_digest: String,
    pub preview_digest: String,
    pub status: DeploymentStatus,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Deployment {
    pub fn validate(&self) -> Result<(), WebPublicationError> {
        validate_digest(&self.artifact_digest, "deployment artifact digest")?;
        validate_digest(&self.preview_digest, "deployment preview digest")?;
        if self.source_revision == 0 || self.revision == 0 {
            return Err(WebPublicationError::InvalidRevision);
        }
        if self.updated_at < self.created_at {
            return Err(WebPublicationError::InvalidTimestamp("deployment"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteRevision {
    pub site_id: SiteId,
    pub revision: u64,
    pub artifact_digest: String,
    pub files: Vec<SiteFile>,
    pub created_at: DateTime<Utc>,
}

impl SiteRevision {
    pub fn new(
        site_id: SiteId,
        revision: u64,
        files: Vec<SiteFile>,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        let files = normalized_files(files)?;
        let artifact_digest = site_content_digest(&files);
        let record = Self {
            site_id,
            revision,
            artifact_digest,
            files,
            created_at: now,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        if self.revision == 0 {
            return Err(WebPublicationError::InvalidRevision);
        }
        let files = normalized_files(self.files.clone())?;
        if files != self.files {
            return Err(WebPublicationError::NonCanonicalFiles);
        }
        if site_content_digest(&self.files) != self.artifact_digest {
            return Err(WebPublicationError::DigestMismatch(
                "site revision artifact",
            ));
        }
        Ok(())
    }
}

/// The durable source binding consumed by the publication plugin. It is
/// deliberately constructed from the Mission aggregate and the exact
/// WorkProductManifest rather than from a page-local title or preview.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationWorkProductSelection {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub site_id: SiteId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
    pub work_product_type: String,
    pub work_product_status: WorkProductStatus,
    pub work_product_digest: String,
    pub manifest_digest: String,
    pub preview: WorkProductPreview,
    pub site_revision: SiteRevision,
}

impl PublicationWorkProductSelection {
    pub fn from_mission(
        mission: &Mission,
        site_id: &SiteId,
        work_product_id: &WorkProductId,
        manifest: &WorkProductManifest,
        site_revision: SiteRevision,
    ) -> Result<Self, WebPublicationError> {
        if mission.revision == 0
            || mission.tenant_id != manifest.tenant_id
            || mission.project_id != manifest.project_id
            || mission.id != manifest.mission_id
            || manifest.work_product_id != *work_product_id
        {
            return Err(WebPublicationError::WorkProductScopeMismatch);
        }
        let work_product = mission
            .work_products
            .iter()
            .find(|candidate| candidate.id == *work_product_id)
            .ok_or_else(|| WebPublicationError::WorkProductNotFound(work_product_id.clone()))?;
        manifest
            .validate_against(work_product)
            .map_err(|error| map_manifest_selection_error(&error))?;
        if !matches!(
            work_product.status,
            WorkProductStatus::ReadyForReview | WorkProductStatus::Accepted
        ) {
            return Err(WebPublicationError::WorkProductNotAdoptable(
                work_product.id.clone(),
            ));
        }
        if is_fixture_work_product_type(&manifest.work_product_type) {
            return Err(WebPublicationError::FixtureWorkProduct(
                manifest.work_product_type.clone(),
            ));
        }
        if manifest.file_digest.as_deref() != Some(site_revision.artifact_digest.as_str()) {
            return Err(WebPublicationError::SourceDigestMismatch);
        }
        let selection = Self {
            tenant_id: mission.tenant_id.clone(),
            project_id: mission.project_id.clone(),
            mission_id: mission.id.clone(),
            mission_revision: mission.revision,
            site_id: site_id.clone(),
            work_product_id: work_product.id.clone(),
            work_product_revision: work_product.revision,
            work_product_type: manifest.work_product_type.clone(),
            work_product_status: work_product.status.clone(),
            work_product_digest: work_product.content_digest.clone(),
            manifest_digest: manifest.manifest_digest.clone(),
            preview: manifest.preview.clone(),
            site_revision,
        };
        selection.validate()?;
        Ok(selection)
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        if self.mission_revision == 0
            || self.work_product_revision == 0
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.mission_id.as_str().trim().is_empty()
            || self.site_id.as_str().trim().is_empty()
            || self.work_product_id.as_str().trim().is_empty()
            || is_fixture_work_product_type(&self.work_product_type)
        {
            return Err(WebPublicationError::InvalidSourceBinding);
        }
        validate_digest(&self.work_product_digest, "work product digest")?;
        validate_digest(&self.manifest_digest, "work product manifest digest")?;
        self.preview
            .validate()
            .map_err(|_| WebPublicationError::InvalidSourceBinding)?;
        self.site_revision.validate()?;
        if self.site_revision.site_id != self.site_id
            || self.site_revision.revision == 0
            || !matches!(
                self.work_product_status,
                WorkProductStatus::ReadyForReview | WorkProductStatus::Accepted
            )
        {
            return Err(WebPublicationError::InvalidSourceBinding);
        }
        Ok(())
    }

    pub fn is_adoptable(&self) -> bool {
        self.work_product_status == WorkProductStatus::Accepted
    }
}

fn map_manifest_selection_error(error: &WorkProductManifestError) -> WebPublicationError {
    match error {
        WorkProductManifestError::WorkProductMismatch
        | WorkProductManifestError::InvalidRevisionChain => {
            WebPublicationError::WorkProductManifestMismatch
        }
        _ => WebPublicationError::InvalidSourceBinding,
    }
}

fn is_fixture_work_product_type(work_product_type: &str) -> bool {
    work_product_type
        .split(['_', '-', '.', ':'])
        .any(|part| part.eq_ignore_ascii_case("fixture"))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteFile {
    pub path: String,
    pub content: String,
    pub content_digest: String,
}

impl SiteFile {
    pub fn new(
        path: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<Self, WebPublicationError> {
        let path = validate_site_path(path.into())?;
        let content = content.into();
        let content_digest = sha256(content.as_bytes());
        Ok(Self {
            path,
            content,
            content_digest,
        })
    }

    fn validate(&self) -> Result<(), WebPublicationError> {
        validate_site_path(self.path.clone())?;
        if sha256(self.content.as_bytes()) != self.content_digest {
            return Err(WebPublicationError::DigestMismatch("site file content"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SitePreview {
    pub artifact_digest: String,
    pub preview_digest: String,
    pub preview_url: Option<String>,
    pub generated_at: DateTime<Utc>,
}

impl SitePreview {
    pub fn new(
        artifact_digest: impl Into<String>,
        preview_document: impl AsRef<str>,
        preview_url: Option<String>,
        generated_at: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        let artifact_digest = artifact_digest.into();
        validate_digest(&artifact_digest, "preview artifact digest")?;
        if let Some(url) = &preview_url {
            validate_https_url(url, "preview URL")?;
        }
        Ok(Self {
            artifact_digest,
            preview_digest: sha256(preview_document.as_ref().as_bytes()),
            preview_url,
            generated_at,
        })
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        validate_digest(&self.artifact_digest, "preview artifact digest")?;
        validate_digest(&self.preview_digest, "preview digest")?;
        if let Some(url) = &self.preview_url {
            validate_https_url(url, "preview URL")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalDiffEntryKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalDiffEntry {
    pub path: String,
    pub kind: CanonicalDiffEntryKind,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalSiteDiff {
    pub base_revision: u64,
    pub base_authority_digest: String,
    pub entries: Vec<CanonicalDiffEntry>,
    pub digest: String,
}

impl CanonicalSiteDiff {
    pub fn from_snapshots(
        base_revision: u64,
        base_authority_digest: impl Into<String>,
        base_files: &BTreeMap<String, String>,
        proposed_files: &[SiteFile],
    ) -> Result<Self, WebPublicationError> {
        if base_revision == 0 {
            return Err(WebPublicationError::InvalidRevision);
        }
        let base_authority_digest = base_authority_digest.into();
        validate_digest(&base_authority_digest, "base authority digest")?;
        let proposed_files = normalized_files(proposed_files.to_vec())?;
        let proposed = proposed_files
            .iter()
            .map(|file| (file.path.clone(), file))
            .collect::<BTreeMap<_, _>>();
        let paths = base_files
            .keys()
            .chain(proposed.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut entries = Vec::new();
        for path in paths {
            let before = base_files.get(&path).map(|value| sha256(value.as_bytes()));
            let after = proposed.get(&path).map(|file| file.content_digest.clone());
            if before == after {
                continue;
            }
            let kind = match (before.is_some(), after.is_some()) {
                (false, true) => CanonicalDiffEntryKind::Added,
                (true, false) => CanonicalDiffEntryKind::Deleted,
                (true, true) => CanonicalDiffEntryKind::Modified,
                (false, false) => continue,
            };
            entries.push(CanonicalDiffEntry {
                path,
                kind,
                before_digest: before,
                after_digest: after,
            });
        }
        let digest = canonical_diff_digest(base_revision, &base_authority_digest, &entries)?;
        Ok(Self {
            base_revision,
            base_authority_digest,
            entries,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        if self.base_revision == 0 {
            return Err(WebPublicationError::InvalidRevision);
        }
        validate_digest(&self.base_authority_digest, "base authority digest")?;
        let mut previous_path = None;
        for entry in &self.entries {
            validate_site_path(entry.path.clone())?;
            if let Some(previous_path) = &previous_path
                && previous_path >= &entry.path
            {
                return Err(WebPublicationError::NonCanonicalDiff);
            }
            previous_path = Some(entry.path.clone());
            if let Some(digest) = &entry.before_digest {
                validate_digest(digest, "diff before digest")?;
            }
            if let Some(digest) = &entry.after_digest {
                validate_digest(digest, "diff after digest")?;
            }
            match entry.kind {
                CanonicalDiffEntryKind::Added if entry.before_digest.is_some() => {
                    return Err(WebPublicationError::InvalidDiffEntry(entry.path.clone()));
                }
                CanonicalDiffEntryKind::Deleted if entry.after_digest.is_some() => {
                    return Err(WebPublicationError::InvalidDiffEntry(entry.path.clone()));
                }
                CanonicalDiffEntryKind::Modified
                    if entry.before_digest.is_none() || entry.after_digest.is_none() =>
                {
                    return Err(WebPublicationError::InvalidDiffEntry(entry.path.clone()));
                }
                _ => {}
            }
        }
        let expected = canonical_diff_digest(
            self.base_revision,
            &self.base_authority_digest,
            &self.entries,
        )?;
        if expected != self.digest {
            return Err(WebPublicationError::DigestMismatch("canonical diff"));
        }
        Ok(())
    }

    pub fn render(&self) -> String {
        let mut rendered = String::new();
        for entry in &self.entries {
            let marker = match entry.kind {
                CanonicalDiffEntryKind::Added => "+",
                CanonicalDiffEntryKind::Modified => "~",
                CanonicalDiffEntryKind::Deleted => "-",
            };
            let _ = writeln!(rendered, "{marker} {}", entry.path);
        }
        rendered
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationTarget {
    pub provider: String,
    pub account_id: String,
    pub resource_id: String,
    pub branch: String,
    pub url: String,
    pub environment: PublicationEnvironment,
    pub configuration_digest: String,
}

impl PublicationTarget {
    pub fn validate(&self) -> Result<(), WebPublicationError> {
        non_empty(self.provider.clone(), "publication provider")?;
        non_empty(self.account_id.clone(), "publication account")?;
        non_empty(self.resource_id.clone(), "publication resource")?;
        non_empty(self.branch.clone(), "publication branch")?;
        validate_https_url(&self.url, "publication URL")?;
        validate_digest(
            &self.configuration_digest,
            "publication configuration digest",
        )?;
        if self.branch.contains(char::is_whitespace) || self.branch.contains("..") {
            return Err(WebPublicationError::InvalidTarget("publication branch"));
        }
        Ok(())
    }

    pub fn authority_fence(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}",
            self.provider,
            self.account_id,
            self.resource_id,
            self.branch,
            self.url,
            self.environment.as_str(),
            self.configuration_digest
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationPublishRequest {
    pub site_id: SiteId,
    pub domain_id: DomainId,
    pub deployment_id: DeploymentId,
    pub environment: PublicationEnvironment,
    pub target: PublicationTarget,
    pub source_revision: u64,
    pub base_revision: u64,
    pub canonical_diff: CanonicalSiteDiff,
    pub files: Vec<SiteFile>,
    pub preview: SitePreview,
    pub content_digest: String,
    pub payload_digest: String,
    pub idempotency_key: String,
    pub proposed_at: DateTime<Utc>,
}

impl PublicationPublishRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        site_id: SiteId,
        domain_id: DomainId,
        deployment_id: DeploymentId,
        environment: PublicationEnvironment,
        target: PublicationTarget,
        source_revision: u64,
        base_revision: u64,
        base_authority_digest: impl Into<String>,
        base_files: &BTreeMap<String, String>,
        files: Vec<SiteFile>,
        preview: SitePreview,
        proposed_at: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        let files = normalized_files(files)?;
        let canonical_diff = CanonicalSiteDiff::from_snapshots(
            base_revision,
            base_authority_digest,
            base_files,
            &files,
        )?;
        let content_digest = site_content_digest(&files);
        let material = PublishRequestMaterial {
            site_id: &site_id,
            domain_id: &domain_id,
            deployment_id: &deployment_id,
            environment,
            target: &target,
            source_revision,
            base_revision,
            canonical_diff: &canonical_diff,
            files: &files,
            preview: &preview,
            content_digest: &content_digest,
        };
        let payload_digest = sha256(serde_json::to_vec(&material)?);
        let idempotency_key = sha256(format!("publication:v1:{payload_digest}").as_bytes());
        let request = Self {
            site_id,
            domain_id,
            deployment_id,
            environment,
            target,
            source_revision,
            base_revision,
            canonical_diff,
            files,
            preview,
            content_digest,
            payload_digest,
            idempotency_key,
            proposed_at,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        if self.source_revision == 0 || self.base_revision == 0 {
            return Err(WebPublicationError::InvalidRevision);
        }
        self.target.validate()?;
        if self.target.environment != self.environment {
            return Err(WebPublicationError::EnvironmentFence);
        }
        self.canonical_diff.validate()?;
        if self.canonical_diff.base_revision != self.base_revision {
            return Err(WebPublicationError::RevisionFence);
        }
        let files = normalized_files(self.files.clone())?;
        if files != self.files {
            return Err(WebPublicationError::NonCanonicalFiles);
        }
        self.preview.validate()?;
        validate_digest(&self.content_digest, "publication content digest")?;
        validate_digest(&self.payload_digest, "publication payload digest")?;
        validate_digest(&self.idempotency_key, "publication idempotency key")?;
        if site_content_digest(&self.files) != self.content_digest {
            return Err(WebPublicationError::DigestMismatch("publication content"));
        }
        let material = PublishRequestMaterial {
            site_id: &self.site_id,
            domain_id: &self.domain_id,
            deployment_id: &self.deployment_id,
            environment: self.environment,
            target: &self.target,
            source_revision: self.source_revision,
            base_revision: self.base_revision,
            canonical_diff: &self.canonical_diff,
            files: &self.files,
            preview: &self.preview,
            content_digest: &self.content_digest,
        };
        if sha256(serde_json::to_vec(&material)?) != self.payload_digest {
            return Err(WebPublicationError::DigestMismatch("publication payload"));
        }
        if sha256(format!("publication:v1:{}", self.payload_digest).as_bytes())
            != self.idempotency_key
        {
            return Err(WebPublicationError::DigestMismatch(
                "publication idempotency",
            ));
        }
        Ok(())
    }

    pub fn target_resource(&self, publication_id: &PublicationId) -> String {
        format!(
            "{}/site/{}/publication/{}/{}",
            self.target.resource_id,
            self.site_id,
            publication_id,
            self.environment.as_str()
        )
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishRequestMaterial<'a> {
    site_id: &'a SiteId,
    domain_id: &'a DomainId,
    deployment_id: &'a DeploymentId,
    environment: PublicationEnvironment,
    target: &'a PublicationTarget,
    source_revision: u64,
    base_revision: u64,
    canonical_diff: &'a CanonicalSiteDiff,
    files: &'a [SiteFile],
    preview: &'a SitePreview,
    content_digest: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    Draft,
    WaitingApproval,
    Approved,
    Publishing,
    ProviderAccepted,
    OnlineVerified,
    Failed,
    Uncertain,
    Reopened,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationProviderReceipt {
    pub provider: String,
    pub external_id: String,
    pub request_digest: String,
    pub response_digest: String,
    pub environment: PublicationEnvironment,
    pub resource_id: String,
    pub branch: String,
    pub url: String,
    pub accepted_at: DateTime<Utc>,
}

impl PublicationProviderReceipt {
    pub fn validate(&self) -> Result<(), WebPublicationError> {
        non_empty(self.provider.clone(), "receipt provider")?;
        non_empty(self.external_id.clone(), "receipt external id")?;
        validate_digest(&self.request_digest, "receipt request digest")?;
        validate_digest(&self.response_digest, "receipt response digest")?;
        non_empty(self.resource_id.clone(), "receipt resource")?;
        non_empty(self.branch.clone(), "receipt branch")?;
        validate_https_url(&self.url, "receipt URL")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationReadback {
    pub environment: PublicationEnvironment,
    pub url: String,
    pub http_status: u16,
    pub dns_resolved: bool,
    pub content_digest: String,
    pub publication_digest: String,
    pub evidence_digest: String,
    pub independent: bool,
    pub observed_at: DateTime<Utc>,
}

impl PublicationReadback {
    pub fn validate(&self) -> Result<(), WebPublicationError> {
        validate_https_url(&self.url, "readback URL")?;
        validate_digest(&self.content_digest, "readback content digest")?;
        validate_digest(&self.publication_digest, "readback publication digest")?;
        validate_digest(&self.evidence_digest, "readback evidence digest")?;
        if !self.independent {
            return Err(WebPublicationError::NotIndependent);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationActivityKind {
    Proposed,
    ApprovalRequested,
    Approved,
    Publishing,
    ProviderAccepted,
    OnlineVerified,
    Failed,
    Uncertain,
    Reopened,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationActivity {
    pub id: PublicationActivityId,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub publication_id: PublicationId,
    pub kind: PublicationActivityKind,
    pub status: PublicationStatus,
    pub digest: String,
    pub recorded_at: DateTime<Utc>,
}

impl PublicationActivity {
    pub fn validate(&self) -> Result<(), WebPublicationError> {
        validate_digest(&self.digest, "publication activity digest")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Publication {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub site_id: SiteId,
    pub domain_id: DomainId,
    pub deployment_id: DeploymentId,
    pub id: PublicationId,
    pub request: PublicationPublishRequest,
    pub status: PublicationStatus,
    pub approval_digest: Option<String>,
    pub provider_receipt: Option<PublicationProviderReceipt>,
    pub readback: Option<PublicationReadback>,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Publication {
    #[allow(clippy::too_many_arguments)]
    pub fn propose(
        tenant_id: TenantId,
        project_id: ProjectId,
        mission_id: MissionId,
        site_id: SiteId,
        domain_id: DomainId,
        deployment_id: DeploymentId,
        id: PublicationId,
        request: PublicationPublishRequest,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        request.validate()?;
        if request.site_id != site_id
            || request.domain_id != domain_id
            || request.deployment_id != deployment_id
        {
            return Err(WebPublicationError::ScopeMismatch);
        }
        let publication = Self {
            tenant_id,
            project_id,
            mission_id,
            site_id,
            domain_id,
            deployment_id,
            id,
            request,
            status: PublicationStatus::Draft,
            approval_digest: None,
            provider_receipt: None,
            readback: None,
            revision: 1,
            created_at: now,
            updated_at: now,
        };
        publication.validate()?;
        Ok(publication)
    }

    pub fn request_approval(&self, now: DateTime<Utc>) -> Result<Self, WebPublicationError> {
        if self.status != PublicationStatus::Draft {
            return Err(WebPublicationError::InvalidPublicationTransition {
                from: self.status,
                to: PublicationStatus::WaitingApproval,
            });
        }
        self.with_status(PublicationStatus::WaitingApproval, now)
    }

    pub fn bind_approval(
        &self,
        approval_digest: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        if self.status != PublicationStatus::WaitingApproval {
            return Err(WebPublicationError::InvalidPublicationTransition {
                from: self.status,
                to: PublicationStatus::Approved,
            });
        }
        let approval_digest = approval_digest.into();
        validate_digest(&approval_digest, "approval digest")?;
        let mut next = self.with_status_unvalidated(PublicationStatus::Approved, now)?;
        next.approval_digest = Some(approval_digest);
        next.validate()?;
        Ok(next)
    }

    pub fn start_publishing(&self, now: DateTime<Utc>) -> Result<Self, WebPublicationError> {
        if self.status != PublicationStatus::Approved || self.approval_digest.is_none() {
            return Err(WebPublicationError::ApprovalRequired);
        }
        self.with_status(PublicationStatus::Publishing, now)
    }

    pub fn mark_provider_accepted(
        &self,
        receipt: PublicationProviderReceipt,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        if self.status != PublicationStatus::Publishing {
            return Err(WebPublicationError::InvalidPublicationTransition {
                from: self.status,
                to: PublicationStatus::ProviderAccepted,
            });
        }
        receipt.validate()?;
        if receipt.provider != self.request.target.provider
            || receipt.environment != self.request.environment
            || receipt.resource_id != self.request.target.resource_id
            || receipt.branch != self.request.target.branch
            || receipt.url != self.request.target.url
            || self.approval_digest.as_deref() != Some(receipt.request_digest.as_str())
        {
            return Err(WebPublicationError::ReceiptFence);
        }
        let mut next = self.with_status_unvalidated(PublicationStatus::ProviderAccepted, now)?;
        next.provider_receipt = Some(receipt);
        next.validate()?;
        Ok(next)
    }

    pub fn mark_online_verified(
        &self,
        readback: PublicationReadback,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        if self.status != PublicationStatus::ProviderAccepted || self.provider_receipt.is_none() {
            return Err(WebPublicationError::ProviderReceiptRequired);
        }
        readback.validate()?;
        if readback.environment != self.request.environment
            || readback.url != self.request.target.url
            || readback.http_status != 200
            || !readback.dns_resolved
            || readback.content_digest != self.request.content_digest
            || readback.publication_digest != self.request.payload_digest
        {
            return Err(WebPublicationError::ReadbackFence);
        }
        let mut next = self.with_status_unvalidated(PublicationStatus::OnlineVerified, now)?;
        next.readback = Some(readback);
        next.validate()?;
        Ok(next)
    }

    pub fn mark_uncertain(&self, now: DateTime<Utc>) -> Result<Self, WebPublicationError> {
        if !matches!(
            self.status,
            PublicationStatus::Publishing | PublicationStatus::ProviderAccepted
        ) {
            return Err(WebPublicationError::InvalidPublicationTransition {
                from: self.status,
                to: PublicationStatus::Uncertain,
            });
        }
        self.with_status(PublicationStatus::Uncertain, now)
    }

    pub fn mark_failed(&self, now: DateTime<Utc>) -> Result<Self, WebPublicationError> {
        if matches!(
            self.status,
            PublicationStatus::OnlineVerified | PublicationStatus::Reopened
        ) {
            return Err(WebPublicationError::InvalidPublicationTransition {
                from: self.status,
                to: PublicationStatus::Failed,
            });
        }
        self.with_status(PublicationStatus::Failed, now)
    }

    pub fn reopen(&self, now: DateTime<Utc>) -> Result<Self, WebPublicationError> {
        if self.status != PublicationStatus::OnlineVerified {
            return Err(WebPublicationError::InvalidPublicationTransition {
                from: self.status,
                to: PublicationStatus::Reopened,
            });
        }
        self.with_status(PublicationStatus::Reopened, now)
    }

    pub fn target_resource(&self) -> String {
        self.request.target_resource(&self.id)
    }

    pub fn validate(&self) -> Result<(), WebPublicationError> {
        self.request.validate()?;
        if self.site_id != self.request.site_id
            || self.domain_id != self.request.domain_id
            || self.deployment_id != self.request.deployment_id
        {
            return Err(WebPublicationError::ScopeMismatch);
        }
        if self.revision == 0 || self.updated_at < self.created_at {
            return Err(WebPublicationError::InvalidRevision);
        }
        if let Some(digest) = &self.approval_digest {
            validate_digest(digest, "publication approval digest")?;
        }
        if let Some(receipt) = &self.provider_receipt {
            receipt.validate()?;
        }
        if let Some(readback) = &self.readback {
            readback.validate()?;
        }
        match self.status {
            PublicationStatus::Approved
            | PublicationStatus::Publishing
            | PublicationStatus::ProviderAccepted
            | PublicationStatus::OnlineVerified
                if self.approval_digest.is_none() =>
            {
                return Err(WebPublicationError::ApprovalRequired);
            }
            PublicationStatus::ProviderAccepted | PublicationStatus::OnlineVerified
                if self.provider_receipt.is_none() =>
            {
                return Err(WebPublicationError::ProviderReceiptRequired);
            }
            PublicationStatus::OnlineVerified if self.readback.is_none() => {
                return Err(WebPublicationError::ReadbackRequired);
            }
            _ => {}
        }
        Ok(())
    }

    fn with_status(
        &self,
        status: PublicationStatus,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        let next = Self {
            status,
            revision: self
                .revision
                .checked_add(1)
                .ok_or(WebPublicationError::RevisionOverflow)?,
            updated_at: now,
            ..self.clone()
        };
        next.validate()?;
        Ok(next)
    }

    fn with_status_unvalidated(
        &self,
        status: PublicationStatus,
        now: DateTime<Utc>,
    ) -> Result<Self, WebPublicationError> {
        Ok(Self {
            status,
            revision: self
                .revision
                .checked_add(1)
                .ok_or(WebPublicationError::RevisionOverflow)?,
            updated_at: now,
            ..self.clone()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebPublicationProjection {
    pub site: Site,
    pub domain: Domain,
    pub deployment: Deployment,
    pub publication: Publication,
    pub activity: Vec<PublicationActivity>,
}

impl WebPublicationProjection {
    pub fn validate(&self) -> Result<(), WebPublicationError> {
        self.site.validate()?;
        self.domain.validate()?;
        self.deployment.validate()?;
        self.publication.validate()?;
        if self.site.tenant_id != self.domain.tenant_id
            || self.site.tenant_id != self.deployment.tenant_id
            || self.site.tenant_id != self.publication.tenant_id
            || self.site.project_id != self.domain.project_id
            || self.site.project_id != self.deployment.project_id
            || self.site.project_id != self.publication.project_id
            || self.site.id != self.domain.site_id
            || self.site.id != self.deployment.site_id
            || self.site.id != self.publication.site_id
            || self.deployment.id != self.publication.deployment_id
            || self.domain.id != self.publication.domain_id
        {
            return Err(WebPublicationError::ScopeMismatch);
        }
        for activity in &self.activity {
            activity.validate()?;
            if activity.tenant_id != self.site.tenant_id
                || activity.project_id != self.site.project_id
                || activity.mission_id != self.publication.mission_id
                || activity.publication_id != self.publication.id
            {
                return Err(WebPublicationError::ScopeMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum WebPublicationError {
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("invalid {0}")]
    InvalidTarget(&'static str),
    #[error("invalid hostname")]
    InvalidHostname,
    #[error("invalid HTTPS URL for {0}")]
    InvalidHttpsUrl(&'static str),
    #[error("invalid SHA-256 digest for {0}")]
    InvalidDigest(&'static str),
    #[error("digest mismatch for {0}")]
    DigestMismatch(&'static str),
    #[error("invalid site path")]
    InvalidSitePath,
    #[error("invalid revision")]
    InvalidRevision,
    #[error("revision overflow")]
    RevisionOverflow,
    #[error("expected revision {expected}, got {actual}")]
    UnexpectedRevision { expected: u64, actual: u64 },
    #[error("publication scope mismatch")]
    ScopeMismatch,
    #[error("publication environment fence failed")]
    EnvironmentFence,
    #[error("publication revision fence failed")]
    RevisionFence,
    #[error("files are not in canonical order")]
    NonCanonicalFiles,
    #[error("diff is not canonical")]
    NonCanonicalDiff,
    #[error("invalid diff entry for {0}")]
    InvalidDiffEntry(String),
    #[error("invalid timestamp for {0}")]
    InvalidTimestamp(&'static str),
    #[error("invalid publication transition from {from:?} to {to:?}")]
    InvalidPublicationTransition {
        from: PublicationStatus,
        to: PublicationStatus,
    },
    #[error("the selected WorkProduct is outside the publication Mission scope")]
    WorkProductScopeMismatch,
    #[error("selected WorkProduct {0} was not found in the Mission")]
    WorkProductNotFound(WorkProductId),
    #[error("selected WorkProduct {0} is not adoptable")]
    WorkProductNotAdoptable(WorkProductId),
    #[error("WorkProduct type {0} is a fixture and cannot be published")]
    FixtureWorkProduct(String),
    #[error("selected WorkProduct manifest does not bind its exact revision")]
    WorkProductManifestMismatch,
    #[error("selected WorkProduct source digest does not match the site revision")]
    SourceDigestMismatch,
    #[error("selected WorkProduct source binding is invalid")]
    InvalidSourceBinding,
    #[error("approval is required")]
    ApprovalRequired,
    #[error("provider receipt is required")]
    ProviderReceiptRequired,
    #[error("provider receipt fence failed")]
    ReceiptFence,
    #[error("independent readback is required")]
    NotIndependent,
    #[error("readback fence failed")]
    ReadbackFence,
    #[error("readback is required")]
    ReadbackRequired,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

fn normalized_files(mut files: Vec<SiteFile>) -> Result<Vec<SiteFile>, WebPublicationError> {
    for file in &files {
        file.validate()?;
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    if files.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err(WebPublicationError::NonCanonicalFiles);
    }
    Ok(files)
}

fn site_content_digest(files: &[SiteFile]) -> String {
    let mut bytes = Vec::new();
    for file in files {
        bytes.extend_from_slice(file.path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(file.content.as_bytes());
        bytes.push(0);
    }
    sha256(bytes)
}

fn canonical_diff_digest(
    base_revision: u64,
    base_authority_digest: &str,
    entries: &[CanonicalDiffEntry],
) -> Result<String, WebPublicationError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Material<'a> {
        base_revision: u64,
        base_authority_digest: &'a str,
        entries: &'a [CanonicalDiffEntry],
    }
    Ok(sha256(serde_json::to_vec(&Material {
        base_revision,
        base_authority_digest,
        entries,
    })?))
}

fn validate_site_path(path: String) -> Result<String, WebPublicationError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains("//")
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path == ".git"
        || path.starts_with(".git/")
        || path.starts_with(".hartevo/")
        || path.chars().any(char::is_control)
    {
        return Err(WebPublicationError::InvalidSitePath);
    }
    Ok(path)
}

fn validate_hostname(hostname: &str) -> Result<String, WebPublicationError> {
    let normalized = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized.contains('/')
        || normalized.contains(':')
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        return Err(WebPublicationError::InvalidHostname);
    }
    Ok(normalized)
}

fn validate_https_url(url: &str, field: &'static str) -> Result<(), WebPublicationError> {
    if !url.starts_with("https://")
        || url.len() <= "https://".len()
        || url.chars().any(char::is_control)
        || url.contains(' ')
    {
        return Err(WebPublicationError::InvalidHttpsUrl(field));
    }
    Ok(())
}

fn non_empty(value: String, field: &'static str) -> Result<String, WebPublicationError> {
    if value.trim().is_empty() {
        return Err(WebPublicationError::EmptyField(field));
    }
    Ok(value)
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), WebPublicationError> {
    if value.len() != DIGEST_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WebPublicationError::InvalidDigest(field));
    }
    Ok(())
}

fn sha256(value: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(value.as_ref());
    digest
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: &str) -> String {
        sha256(value.as_bytes())
    }

    fn target(environment: PublicationEnvironment) -> PublicationTarget {
        PublicationTarget {
            provider: "github".into(),
            account_id: "acct-1".into(),
            resource_id: if environment == PublicationEnvironment::Staging {
                "owner/staging-site"
            } else {
                "owner/production-site"
            }
            .into(),
            branch: "pages".into(),
            url: if environment == PublicationEnvironment::Staging {
                "https://staging.example.com"
            } else {
                "https://example.com"
            }
            .into(),
            environment,
            configuration_digest: digest(environment.as_str()),
        }
    }

    #[test]
    fn canonical_diff_is_sorted_and_excludes_unchanged_files() {
        let base = BTreeMap::from([
            ("about.html".into(), "old".into()),
            ("index.html".into(), "same".into()),
        ]);
        let files = vec![
            SiteFile::new("index.html", "same").expect("file"),
            SiteFile::new("new.html", "new").expect("file"),
            SiteFile::new("about.html", "updated").expect("file"),
        ];
        let diff =
            CanonicalSiteDiff::from_snapshots(3, digest("head"), &base, &files).expect("diff");
        assert_eq!(diff.entries.len(), 2);
        assert_eq!(diff.entries[0].path, "about.html");
        assert_eq!(diff.entries[1].path, "new.html");
        assert_eq!(diff.entries[0].kind, CanonicalDiffEntryKind::Modified);
        assert_eq!(diff.entries[1].kind, CanonicalDiffEntryKind::Added);
        assert_eq!(diff.render(), "~ about.html\n+ new.html\n");
        diff.validate().expect("valid diff");
    }

    #[test]
    fn publication_requires_approval_receipt_and_independent_readback() {
        let files = vec![SiteFile::new("index.html", "hello").expect("file")];
        let preview = SitePreview::new(
            digest("artifact"),
            "preview",
            Some("https://preview.example.com".into()),
            Utc::now(),
        )
        .expect("preview");
        let request = PublicationPublishRequest::new(
            SiteId::from_stable("site-1"),
            DomainId::from_stable("domain-1"),
            DeploymentId::from_stable("deployment-1"),
            PublicationEnvironment::Production,
            target(PublicationEnvironment::Production),
            2,
            1,
            digest("head"),
            &BTreeMap::new(),
            files,
            preview,
            Utc::now(),
        )
        .expect("request");
        let now = Utc::now();
        let publication = Publication::propose(
            TenantId::from_stable("tenant-1"),
            ProjectId::from_stable("project-1"),
            MissionId::from_stable("mission-1"),
            request.site_id.clone(),
            request.domain_id.clone(),
            request.deployment_id.clone(),
            PublicationId::from_stable("publication-1"),
            request,
            now,
        )
        .expect("publication");
        let publication = publication.request_approval(now).expect("approval request");
        let approval = digest("approval");
        let publication = publication
            .bind_approval(approval.clone(), now)
            .expect("approved");
        let publication = publication.start_publishing(now).expect("publishing");
        let receipt = PublicationProviderReceipt {
            provider: "github".into(),
            external_id: "commit-1".into(),
            request_digest: approval,
            response_digest: digest("receipt"),
            environment: PublicationEnvironment::Production,
            resource_id: "owner/production-site".into(),
            branch: "pages".into(),
            url: "https://example.com".into(),
            accepted_at: now,
        };
        let publication = publication
            .mark_provider_accepted(receipt, now)
            .expect("receipt");
        let readback = PublicationReadback {
            environment: PublicationEnvironment::Production,
            url: "https://example.com".into(),
            http_status: 200,
            dns_resolved: true,
            content_digest: publication.request.content_digest.clone(),
            publication_digest: publication.request.payload_digest.clone(),
            evidence_digest: digest("readback"),
            independent: true,
            observed_at: now,
        };
        let publication = publication
            .mark_online_verified(readback, now)
            .expect("verified");
        assert_eq!(publication.status, PublicationStatus::OnlineVerified);
        assert_eq!(
            publication.reopen(now).expect("reopen").status,
            PublicationStatus::Reopened
        );
    }

    #[test]
    fn preview_digest_is_not_a_publication_digest() {
        let preview = SitePreview::new(digest("artifact"), "preview document", None, Utc::now())
            .expect("preview");
        assert_ne!(preview.preview_digest, preview.artifact_digest);
    }
}
