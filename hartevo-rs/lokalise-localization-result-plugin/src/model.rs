use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_TRANSLATIONS: usize = 256;
pub const MAX_TASKS: usize = 64;
pub const MAX_BUILDS: usize = 64;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGE_SIZE: usize = 100;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_REQUESTS_PER_MINUTE: u16 = 60;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("Lokalise typed value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{label} is empty, malformed, or too long")]
    InvalidIdentifier { label: &'static str },
    #[error("{label} revision must be non-zero")]
    InvalidRevision { label: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("Lokalise permission set is incomplete or contains an unsupported permission")]
    InvalidPermission,
    #[error("Lokalise scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("Lokalise cursor is empty, malformed, or too long")]
    InvalidCursor,
    #[error("Lokalise response is malformed or outside the Layer-1 bounds: {0}")]
    InvalidResponse(&'static str),
    #[error("Lokalise response contains duplicate items")]
    DuplicateItem,
    #[error("Lokalise rate-limit receipt is invalid")]
    InvalidRateLimit,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

fn validate_identifier(value: &str, label: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-$@+~".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier { label });
    }
    Ok(())
}

fn validate_revision(revision: u64, label: &'static str) -> Result<(), ModelError> {
    if revision == 0 {
        Err(ModelError::InvalidRevision { label })
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), ModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ModelError::InvalidDigest)
    }
}

macro_rules! identifier_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                canonical_digest(self)
            }
        }
    };
}

identifier_type!(TeamId, "team id");
identifier_type!(ProjectId, "project id");
identifier_type!(BranchName, "branch name");
identifier_type!(KeyId, "key id");
identifier_type!(FileId, "file id");
identifier_type!(LanguageId, "language id");
identifier_type!(LanguageIso, "language ISO");
identifier_type!(TranslationId, "translation id");
identifier_type!(TaskId, "task id");
identifier_type!(BuildId, "build id");
identifier_type!(MissionId, "mission id");
identifier_type!(WorkProductId, "work product id");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    id: ProjectId,
    revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    id: MissionId,
    revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.id.as_str()
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    revision: Revision,
}

impl ConsentScope {
    pub fn new(reference: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let reference = reference.into();
        validate_identifier(&reference, "consent reference")?;
        Ok(Self {
            consent_digest: sha256_digest(format!("lokalise-consent/v1|{reference}").as_bytes()),
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.consent_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.consent_digest)?;
        validate_revision(self.revision.get(), "consent")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LokalisePermission {
    ReadProjects,
    ReadLanguages,
    ReadFiles,
    ReadTranslations,
    ReadTasks,
    ReadBackgroundProcesses,
}

impl LokalisePermission {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReadProjects => "read_projects",
            Self::ReadLanguages => "read_languages",
            Self::ReadFiles => "read_files",
            Self::ReadTranslations => "read_translations",
            Self::ReadTasks => "read_tasks",
            Self::ReadBackgroundProcesses => "read_background_processes",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokalisePermissionSet {
    permissions: BTreeSet<LokalisePermission>,
    revision: Revision,
}

impl LokalisePermissionSet {
    pub fn read_only(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                LokalisePermission::ReadProjects,
                LokalisePermission::ReadLanguages,
                LokalisePermission::ReadFiles,
                LokalisePermission::ReadTranslations,
                LokalisePermission::ReadTasks,
                LokalisePermission::ReadBackgroundProcesses,
            ],
            revision,
        )
    }

    pub fn least_privilege(revision: u64) -> Result<Self, ModelError> {
        Self::read_only(revision)
    }

    pub fn new(
        permissions: impl IntoIterator<Item = LokalisePermission>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let set = Self {
            permissions: permissions.into_iter().collect(),
            revision: Revision::new(revision)?,
        };
        set.validate()?;
        Ok(set)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = [
            LokalisePermission::ReadProjects,
            LokalisePermission::ReadLanguages,
            LokalisePermission::ReadFiles,
            LokalisePermission::ReadTranslations,
            LokalisePermission::ReadTasks,
            LokalisePermission::ReadBackgroundProcesses,
        ];
        if self.permissions.len() != expected.len()
            || expected
                .iter()
                .any(|permission| !self.permissions.contains(permission))
        {
            return Err(ModelError::InvalidPermission);
        }
        validate_revision(self.revision.get(), "permission set")
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<LokalisePermission> {
        &self.permissions
    }

    #[must_use]
    pub fn has(&self, permission: LokalisePermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

/// Opaque handle for a host-owned keyring or OAuth credential. The handle and
/// credential material deliberately have no Serialize implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    opaque_id: String,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let opaque_id = opaque_id.into();
        validate_identifier(&opaque_id, "secret reference")?;
        Ok(Self {
            opaque_id,
            revision: Revision::new(revision)?,
            revoked: false,
        })
    }

    pub fn api_token(opaque_id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Self::new(opaque_id, revision)
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        sha256_digest(
            format!(
                "lokalise-secret-reference/v1|{}|{}",
                self.opaque_id,
                self.revision.get()
            )
            .as_bytes(),
        )
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("opaque_id", &"<redacted>")
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseLanguage {
    language_id: LanguageId,
    iso: LanguageIso,
    name_digest: Digest,
    revision: Revision,
}

impl LokaliseLanguage {
    pub fn new(
        language_id: impl Into<String>,
        iso: impl Into<String>,
        name: impl Into<String>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let name = name.into();
        validate_identifier(&name, "language name")?;
        Ok(Self {
            language_id: LanguageId::new(language_id)?,
            iso: LanguageIso::new(iso)?,
            name_digest: sha256_digest(format!("lokalise-language-name/v1|{name}").as_bytes()),
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn language_id(&self) -> &LanguageId {
        &self.language_id
    }

    #[must_use]
    pub fn iso(&self) -> &LanguageIso {
        &self.iso
    }

    #[must_use]
    pub fn name_digest(&self) -> &Digest {
        &self.name_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_digest(&self.name_digest)?;
        validate_revision(self.revision.get(), "language")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseLocalizationScopeSpec {
    pub team_id: TeamId,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub branch: BranchName,
    pub branch_revision: Revision,
    pub file_id: FileId,
    pub file_revision: Revision,
    pub language: LokaliseLanguage,
    pub permission: LokalisePermissionSet,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
}

impl LokaliseLocalizationScopeSpec {
    #[must_use]
    pub fn new(
        team_id: TeamId,
        project_id: ProjectId,
        project_revision: Revision,
        branch: BranchName,
        branch_revision: Revision,
        file_id: FileId,
        file_revision: Revision,
        language: LokaliseLanguage,
        permission: LokalisePermissionSet,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        consent: ConsentScope,
    ) -> Self {
        Self {
            team_id,
            project_id,
            project_revision,
            branch,
            branch_revision,
            file_id,
            file_revision,
            language,
            permission,
            project,
            mission,
            work_product,
            consent,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseLocalizationScope {
    team_id: TeamId,
    project_id: ProjectId,
    project_revision: Revision,
    branch: BranchName,
    branch_revision: Revision,
    file_id: FileId,
    file_revision: Revision,
    language: LokaliseLanguage,
    permission: LokalisePermissionSet,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    consent: ConsentScope,
    scope_digest: Digest,
    revision_digest: Digest,
    privacy_digest: Digest,
}

impl LokaliseLocalizationScope {
    pub fn new(spec: LokaliseLocalizationScopeSpec) -> Result<Self, ModelError> {
        validate_revision(spec.project_revision.get(), "project")?;
        validate_revision(spec.branch_revision.get(), "branch")?;
        validate_revision(spec.file_revision.get(), "file")?;
        spec.language.validate()?;
        spec.permission.validate()?;
        spec.consent.validate()?;
        let scope_digest = canonical_digest(&(
            &spec.team_id,
            &spec.project_id,
            spec.project_revision,
            &spec.branch,
            spec.branch_revision,
            &spec.file_id,
            spec.file_revision,
            &spec.language,
            &spec.permission,
            &spec.project,
            &spec.mission,
            &spec.work_product,
            &spec.consent,
        ));
        let revision_digest = canonical_digest(&(
            spec.project_revision,
            spec.branch_revision,
            spec.file_revision,
            spec.language.revision(),
            spec.permission.revision(),
            spec.project.revision(),
            spec.mission.revision(),
            spec.work_product.revision(),
            spec.consent.revision(),
        ));
        let privacy_digest = canonical_digest(&(
            "lokalise-privacy/v1",
            "source_text_dropped",
            "translated_text_dropped",
            "translator_identity_dropped",
            "comments_dropped",
            "screenshots_dropped",
            &spec.language.name_digest,
        ));
        Ok(Self {
            team_id: spec.team_id,
            project_id: spec.project_id,
            project_revision: spec.project_revision,
            branch: spec.branch,
            branch_revision: spec.branch_revision,
            file_id: spec.file_id,
            file_revision: spec.file_revision,
            language: spec.language,
            permission: spec.permission,
            project: spec.project,
            mission: spec.mission,
            work_product: spec.work_product,
            consent: spec.consent,
            scope_digest,
            revision_digest,
            privacy_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(LokaliseLocalizationScopeSpec {
            team_id: self.team_id.clone(),
            project_id: self.project_id.clone(),
            project_revision: self.project_revision,
            branch: self.branch.clone(),
            branch_revision: self.branch_revision,
            file_id: self.file_id.clone(),
            file_revision: self.file_revision,
            language: self.language.clone(),
            permission: self.permission.clone(),
            project: self.project.clone(),
            mission: self.mission.clone(),
            work_product: self.work_product.clone(),
            consent: self.consent.clone(),
        })
        .and_then(|rebuilt| {
            if rebuilt.scope_digest == self.scope_digest
                && rebuilt.revision_digest == self.revision_digest
                && rebuilt.privacy_digest == self.privacy_digest
            {
                Ok(())
            } else {
                Err(ModelError::InvalidScope("scope digest"))
            }
        })
    }

    #[must_use]
    pub fn team_id(&self) -> &TeamId {
        &self.team_id
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    #[must_use]
    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    #[must_use]
    pub fn branch(&self) -> &BranchName {
        &self.branch
    }

    #[must_use]
    pub const fn branch_revision(&self) -> Revision {
        self.branch_revision
    }

    #[must_use]
    pub fn file_id(&self) -> &FileId {
        &self.file_id
    }

    #[must_use]
    pub const fn file_revision(&self) -> Revision {
        self.file_revision
    }

    #[must_use]
    pub fn language(&self) -> &LokaliseLanguage {
        &self.language
    }

    #[must_use]
    pub fn permission(&self) -> &LokalisePermissionSet {
        &self.permission
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn revision_digest(&self) -> &Digest {
        &self.revision_digest
    }

    #[must_use]
    pub fn privacy_digest(&self) -> &Digest {
        &self.privacy_digest
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LokaliseReadOperation {
    ProjectMetadata,
    LanguageMetadata,
    FileMetadata,
    TranslationItems,
    TaskReviewStatus,
    ExportBuildMetadata,
}

impl LokaliseReadOperation {
    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::ProjectMetadata => "/api2/projects/{project_id}",
            Self::LanguageMetadata => "/api2/projects/{project_id}:{branch}/languages",
            Self::FileMetadata => "/api2/projects/{project_id}:{branch}/files",
            Self::TranslationItems => "/api2/projects/{project_id}:{branch}/translations",
            Self::TaskReviewStatus => "/api2/projects/{project_id}:{branch}/tasks",
            Self::ExportBuildMetadata => "/api2/projects/{project_id}/processes",
        }
    }

    #[must_use]
    pub const fn permission(self) -> LokalisePermission {
        match self {
            Self::ProjectMetadata => LokalisePermission::ReadProjects,
            Self::LanguageMetadata => LokalisePermission::ReadLanguages,
            Self::FileMetadata => LokalisePermission::ReadFiles,
            Self::TranslationItems => LokalisePermission::ReadTranslations,
            Self::TaskReviewStatus => LokalisePermission::ReadTasks,
            Self::ExportBuildMetadata => LokalisePermission::ReadBackgroundProcesses,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProjectMetadata => "project_metadata",
            Self::LanguageMetadata => "language_metadata",
            Self::FileMetadata => "file_metadata",
            Self::TranslationItems => "translation_items",
            Self::TaskReviewStatus => "task_review_status",
            Self::ExportBuildMetadata => "export_build_metadata",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LokaliseHttpMethod {
    Get,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LokaliseProjectPayload {
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub project_type: Option<String>,
}

impl LokaliseProjectPayload {
    #[must_use]
    pub fn new(
        project_id: impl Into<String>,
        team_id: impl Into<String>,
        branch: impl Into<String>,
        name: impl Into<String>,
        project_type: impl Into<String>,
    ) -> Self {
        Self {
            project_id: Some(project_id.into()),
            team_id: Some(team_id.into()),
            branch: Some(branch.into()),
            name: Some(name.into()),
            project_type: Some(project_type.into()),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LokaliseLanguagePayload {
    #[serde(default)]
    pub lang_id: Option<u64>,
    #[serde(default)]
    pub language_id: Option<u64>,
    #[serde(default)]
    pub lang_iso: Option<String>,
    #[serde(default)]
    pub language_iso: Option<String>,
    #[serde(default)]
    pub lang_name: Option<String>,
    #[serde(default)]
    pub language_name: Option<String>,
    #[serde(default)]
    pub is_rtl: Option<bool>,
}

impl LokaliseLanguagePayload {
    #[must_use]
    pub fn new(id: u64, iso: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            lang_id: Some(id),
            language_id: None,
            lang_iso: Some(iso.into()),
            language_iso: None,
            lang_name: Some(name.into()),
            language_name: None,
            is_rtl: None,
        }
    }

    fn resolved_id(&self) -> Option<u64> {
        self.lang_id.or(self.language_id)
    }

    fn resolved_iso(&self) -> Option<&str> {
        self.lang_iso.as_deref().or(self.language_iso.as_deref())
    }

    fn resolved_name(&self) -> Option<&str> {
        self.lang_name.as_deref().or(self.language_name.as_deref())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LokaliseFilePayload {
    pub file_id: u64,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub key_count: u64,
}

impl LokaliseFilePayload {
    #[must_use]
    pub fn new(file_id: u64, filename: impl Into<String>, key_count: u64) -> Self {
        Self {
            file_id,
            filename: filename.into(),
            key_count,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LokaliseTranslationPayload {
    pub translation_id: u64,
    pub key_id: u64,
    #[serde(default)]
    pub file_id: Option<u64>,
    #[serde(default)]
    pub language_id: Option<u64>,
    #[serde(default)]
    pub language_iso: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub translation: Option<String>,
    #[serde(default)]
    pub is_reviewed: bool,
    #[serde(default)]
    pub is_unverified: bool,
    #[serde(default)]
    pub is_untranslated: bool,
    #[serde(default)]
    pub qa_issues: Vec<String>,
    #[serde(default)]
    pub translator_id: Option<u64>,
    #[serde(default)]
    pub translator_email: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub screenshots: Vec<String>,
}

impl LokaliseTranslationPayload {
    #[must_use]
    pub fn new(
        translation_id: u64,
        key_id: u64,
        file_id: u64,
        language_id: u64,
        source: impl Into<String>,
        translation: Option<String>,
    ) -> Self {
        Self {
            translation_id,
            key_id,
            file_id: Some(file_id),
            language_id: Some(language_id),
            language_iso: None,
            source: Some(source.into()),
            translation,
            is_reviewed: false,
            is_unverified: false,
            is_untranslated: false,
            qa_issues: Vec::new(),
            translator_id: None,
            translator_email: None,
            comment: None,
            screenshots: Vec::new(),
        }
    }

    #[must_use]
    pub fn untranslated(
        translation_id: u64,
        key_id: u64,
        file_id: u64,
        language_id: u64,
        source: impl Into<String>,
    ) -> Self {
        Self {
            is_untranslated: true,
            ..Self::new(translation_id, key_id, file_id, language_id, source, None)
        }
    }

    #[must_use]
    pub fn translated(
        translation_id: u64,
        key_id: u64,
        file_id: u64,
        language_id: u64,
        source: impl Into<String>,
        translation: impl Into<String>,
    ) -> Self {
        Self::new(
            translation_id,
            key_id,
            file_id,
            language_id,
            source,
            Some(translation.into()),
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LokaliseTaskLanguagePayload {
    #[serde(default)]
    pub language_id: Option<u64>,
    #[serde(default)]
    pub language_iso: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub progress: Option<u8>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LokaliseTaskPayload {
    pub task_id: u64,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub progress: Option<u8>,
    #[serde(default)]
    pub keys_count: u64,
    #[serde(default)]
    pub words_count: u64,
    #[serde(default)]
    pub done_words_count: u64,
    #[serde(default)]
    pub task_type: Option<String>,
    #[serde(default)]
    pub languages: Vec<LokaliseTaskLanguagePayload>,
    #[serde(default)]
    pub created_by_email: Option<String>,
}

impl LokaliseTaskPayload {
    #[must_use]
    pub fn new(task_id: u64, status: impl Into<String>, progress: u8) -> Self {
        Self {
            task_id,
            status: status.into(),
            progress: Some(progress),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LokaliseProcessPayload {
    pub process_id: String,
    #[serde(default, rename = "type")]
    pub process_type: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub percentage: Option<u8>,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub version: Option<u64>,
}

impl LokaliseProcessPayload {
    #[must_use]
    pub fn new(
        process_id: impl Into<String>,
        status: impl Into<String>,
        percentage: u8,
        version: Option<u64>,
    ) -> Self {
        Self {
            process_id: process_id.into(),
            status: status.into(),
            percentage: Some(percentage),
            version,
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LokaliseLocalizationPayload {
    #[serde(default)]
    pub project: Option<LokaliseProjectPayload>,
    #[serde(default)]
    pub languages: Vec<LokaliseLanguagePayload>,
    #[serde(default)]
    pub files: Vec<LokaliseFilePayload>,
    #[serde(default)]
    pub translations: Vec<LokaliseTranslationPayload>,
    #[serde(default)]
    pub tasks: Vec<LokaliseTaskPayload>,
    #[serde(default)]
    pub processes: Vec<LokaliseProcessPayload>,
    #[serde(default)]
    pub partial: bool,
}

impl LokaliseLocalizationPayload {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_project(project: LokaliseProjectPayload) -> Self {
        Self {
            project: Some(project),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_languages(languages: Vec<LokaliseLanguagePayload>) -> Self {
        Self {
            languages,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_files(files: Vec<LokaliseFilePayload>) -> Self {
        Self {
            files,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_translations(translations: Vec<LokaliseTranslationPayload>) -> Self {
        Self {
            translations,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_tasks(tasks: Vec<LokaliseTaskPayload>) -> Self {
        Self {
            tasks,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_processes(processes: Vec<LokaliseProcessPayload>) -> Self {
        Self {
            processes,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn projection(&self, operation: LokaliseReadOperation) -> Self {
        let mut projection = Self {
            partial: self.partial,
            ..Self::default()
        };
        match operation {
            LokaliseReadOperation::ProjectMetadata => projection.project.clone_from(&self.project),
            LokaliseReadOperation::LanguageMetadata => {
                projection.languages.clone_from(&self.languages);
            }
            LokaliseReadOperation::FileMetadata => projection.files.clone_from(&self.files),
            LokaliseReadOperation::TranslationItems => {
                projection.translations.clone_from(&self.translations);
            }
            LokaliseReadOperation::TaskReviewStatus => projection.tasks.clone_from(&self.tasks),
            LokaliseReadOperation::ExportBuildMetadata => {
                projection.processes.clone_from(&self.processes);
            }
        }
        projection
    }

    pub fn normalize(
        &self,
        scope: &LokaliseLocalizationScope,
    ) -> Result<LokaliseLocalizationAggregate, ModelError> {
        if self.translations.len() > MAX_TRANSLATIONS {
            return Err(ModelError::InvalidResponse("translation item bound"));
        }
        if self.tasks.len() > MAX_TASKS {
            return Err(ModelError::InvalidResponse("task bound"));
        }
        if self.processes.len() > MAX_BUILDS {
            return Err(ModelError::InvalidResponse("build bound"));
        }
        let project = normalize_project(self.project.as_ref(), scope)?;
        let language = normalize_language(&self.languages, scope)?;
        let file = normalize_file(&self.files, scope)?;
        let mut translations = self
            .translations
            .iter()
            .map(|translation| normalize_translation(translation, scope))
            .collect::<Result<Vec<_>, _>>()?;
        translations.sort_by(|left, right| {
            left.language_id
                .cmp(&right.language_id)
                .then_with(|| left.key_id.cmp(&right.key_id))
                .then_with(|| left.translation_id.cmp(&right.translation_id))
        });
        if translations
            .windows(2)
            .any(|pair| pair[0].translation_id == pair[1].translation_id)
        {
            return Err(ModelError::DuplicateItem);
        }
        let mut tasks = self
            .tasks
            .iter()
            .filter_map(|task| normalize_task(task, scope))
            .collect::<Vec<_>>();
        tasks.sort_by(|left, right| left.task_id.cmp(&right.task_id));
        if tasks
            .windows(2)
            .any(|pair| pair[0].task_id == pair[1].task_id)
        {
            return Err(ModelError::DuplicateItem);
        }
        let mut builds = self
            .processes
            .iter()
            .map(normalize_build)
            .collect::<Result<Vec<_>, _>>()?;
        builds.sort_by(|left, right| left.build_id.cmp(&right.build_id));
        if builds
            .windows(2)
            .any(|pair| pair[0].build_id == pair[1].build_id)
        {
            return Err(ModelError::DuplicateItem);
        }
        let counts = LokaliseCounts::from_translations(&translations);
        let content_digest =
            canonical_digest(&(&project, &language, &file, &translations, &tasks, &counts));
        let build_digest = canonical_digest(&builds);
        Ok(LokaliseLocalizationAggregate {
            project,
            language,
            file,
            translations,
            tasks,
            builds,
            counts,
            content_digest,
            build_digest,
            partial: self.partial,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseProjectSummary {
    pub project_id: ProjectId,
    pub team_id: TeamId,
    pub branch_digest: Digest,
    pub name_digest: Option<Digest>,
    pub project_type: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseLanguageSummary {
    pub language_id: LanguageId,
    pub iso: LanguageIso,
    pub name_digest: Digest,
    pub is_rtl: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseFileSummary {
    pub file_id: FileId,
    pub filename_digest: Digest,
    pub key_count: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LokaliseTranslationState {
    Untranslated,
    Translated,
    Unverified,
    Reviewed,
    QaIssue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseTranslationSummary {
    pub translation_id: TranslationId,
    pub key_id: KeyId,
    pub file_id: FileId,
    pub language_id: LanguageId,
    pub language_iso: Option<LanguageIso>,
    pub state: LokaliseTranslationState,
    pub qa_issue_count: u16,
    pub content_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LokaliseTaskStatus {
    Created,
    Queued,
    InProgress,
    Completed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseTaskSummary {
    pub task_id: TaskId,
    pub status: LokaliseTaskStatus,
    pub progress: Option<u8>,
    pub language_ids: Vec<LanguageId>,
    pub keys_count: u64,
    pub words_count: u64,
    pub done_words_count: u64,
    pub task_type_digest: Option<Digest>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LokaliseBuildStatus {
    Building,
    Ready,
    Expired,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseBuildSummary {
    pub build_id: BuildId,
    pub status: LokaliseBuildStatus,
    pub progress: Option<u8>,
    pub version: Option<u64>,
    pub build_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseCounts {
    pub translation_count: usize,
    pub translated_count: usize,
    pub untranslated_count: usize,
    pub unverified_count: usize,
    pub reviewed_count: usize,
    pub qa_issue_count: usize,
}

impl LokaliseCounts {
    fn from_translations(translations: &[LokaliseTranslationSummary]) -> Self {
        Self {
            translation_count: translations.len(),
            translated_count: translations
                .iter()
                .filter(|item| {
                    matches!(
                        item.state,
                        LokaliseTranslationState::Translated
                            | LokaliseTranslationState::Unverified
                            | LokaliseTranslationState::Reviewed
                    )
                })
                .count(),
            untranslated_count: translations
                .iter()
                .filter(|item| item.state == LokaliseTranslationState::Untranslated)
                .count(),
            unverified_count: translations
                .iter()
                .filter(|item| item.state == LokaliseTranslationState::Unverified)
                .count(),
            reviewed_count: translations
                .iter()
                .filter(|item| item.state == LokaliseTranslationState::Reviewed)
                .count(),
            qa_issue_count: translations
                .iter()
                .map(|item| item.qa_issue_count as usize)
                .sum(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseLocalizationAggregate {
    pub project: LokaliseProjectSummary,
    pub language: LokaliseLanguageSummary,
    pub file: LokaliseFileSummary,
    pub translations: Vec<LokaliseTranslationSummary>,
    pub tasks: Vec<LokaliseTaskSummary>,
    pub builds: Vec<LokaliseBuildSummary>,
    pub counts: LokaliseCounts,
    pub content_digest: Digest,
    pub build_digest: Digest,
    pub partial: bool,
}

impl LokaliseLocalizationAggregate {
    #[must_use]
    pub fn state(&self) -> LokaliseEvidenceState {
        if self
            .builds
            .iter()
            .any(|build| build.status == LokaliseBuildStatus::Expired)
        {
            return LokaliseEvidenceState::Expired;
        }
        if self
            .builds
            .iter()
            .any(|build| build.status == LokaliseBuildStatus::Building)
        {
            return LokaliseEvidenceState::Building;
        }
        if self.partial {
            return LokaliseEvidenceState::Partial;
        }
        if self
            .builds
            .iter()
            .any(|build| build.status == LokaliseBuildStatus::Ready)
        {
            return LokaliseEvidenceState::Ready;
        }
        if self.counts.qa_issue_count > 0 {
            return LokaliseEvidenceState::QaIssue;
        }
        if self.counts.untranslated_count > 0 {
            return LokaliseEvidenceState::Untranslated;
        }
        if self.counts.unverified_count > 0 {
            return LokaliseEvidenceState::Unverified;
        }
        if self.counts.translation_count > 0
            && self.counts.reviewed_count == self.counts.translation_count
        {
            return LokaliseEvidenceState::Reviewed;
        }
        if self.counts.translated_count > 0 {
            LokaliseEvidenceState::Translated
        } else {
            LokaliseEvidenceState::Partial
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LokaliseEvidenceState {
    Untranslated,
    Translated,
    Unverified,
    Reviewed,
    QaIssue,
    Building,
    Ready,
    Expired,
    Partial,
    RateLimited,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LokaliseEvidenceClassification {
    Normalized,
    Untranslated,
    Translated,
    Unverified,
    Reviewed,
    QaIssue,
    Building,
    Ready,
    Expired,
    Partial,
    AccessLost,
    BlockedEnv,
    RateLimited,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseRateLimitReceipt {
    pub limit_per_minute: u16,
    pub remaining: Option<u16>,
    pub retry_after_seconds: Option<u32>,
    pub throttled: bool,
}

impl Default for LokaliseRateLimitReceipt {
    fn default() -> Self {
        Self {
            limit_per_minute: MAX_REQUESTS_PER_MINUTE,
            remaining: Some(MAX_REQUESTS_PER_MINUTE),
            retry_after_seconds: None,
            throttled: false,
        }
    }
}

impl LokaliseRateLimitReceipt {
    pub fn new(
        limit_per_minute: u16,
        remaining: Option<u16>,
        retry_after_seconds: Option<u32>,
        throttled: bool,
    ) -> Result<Self, ModelError> {
        let receipt = Self {
            limit_per_minute,
            remaining,
            retry_after_seconds,
            throttled,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.limit_per_minute == 0
            || self.limit_per_minute > MAX_REQUESTS_PER_MINUTE
            || self
                .remaining
                .is_some_and(|remaining| remaining > self.limit_per_minute)
            || self
                .retry_after_seconds
                .is_some_and(|retry| retry > MAX_RETRY_AFTER_SECONDS)
        {
            return Err(ModelError::InvalidRateLimit);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseReadReceipt {
    pub operation: LokaliseReadOperation,
    pub method: LokaliseHttpMethod,
    pub endpoint: String,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub status_code: Option<u16>,
    pub response_bytes: usize,
    pub rate_limit_digest: Digest,
    pub next_cursor_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseEvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub privacy_digest: Digest,
    pub registration_digest: Digest,
    pub team_digest: Digest,
    pub project_digest: Digest,
    pub branch_digest: Digest,
    pub file_digest: Digest,
    pub language_digest: Digest,
    pub content_digest: Digest,
    pub build_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseLocalizationResultEvidence {
    pub state: LokaliseEvidenceState,
    pub classification: LokaliseEvidenceClassification,
    pub scope: LokaliseLocalizationScope,
    pub aggregate: Option<LokaliseLocalizationAggregate>,
    pub read_receipts: Vec<LokaliseReadReceipt>,
    pub rate_limits: Vec<LokaliseRateLimitReceipt>,
    pub digests: LokaliseEvidenceDigests,
    pub provenance: TransportProvenance,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub evidence_digest: Digest,
}

impl LokaliseLocalizationResultEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.state,
            &self.classification,
            &self.scope,
            &self.aggregate,
            &self.read_receipts,
            &self.rate_limits,
            &self.digests,
            self.provenance,
            self.proposal_only,
            self.native,
            self.connected,
            self.first_party,
            self.adopts_outcome,
        ))
    }

    #[must_use]
    pub fn state(&self) -> LokaliseEvidenceState {
        self.state.clone()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LokaliseRecommendationDisposition {
    ReviewUntranslated,
    ReviewUnverified,
    ReviewQaIssues,
    ReviewTaskProgress,
    ReviewBuildReadiness,
    ReviewLocalizedArtifact,
    NoRecommendationPartial,
    NoRecommendationExpired,
    NoRecommendationAccessLost,
    NoRecommendationRateLimited,
    NoRecommendationProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseLocalizationResultRecommendation {
    pub disposition: LokaliseRecommendationDisposition,
    pub provider_reported_only: bool,
    pub non_mutating: bool,
    pub claims_translation_quality: bool,
    pub claims_publication: bool,
    pub claims_approval: bool,
    pub rationale_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseLocalizationResultProposal {
    pub scope: LokaliseLocalizationScope,
    pub evidence: LokaliseLocalizationResultEvidence,
    pub source_evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub adopts_outcome: bool,
    pub recommendation: LokaliseLocalizationResultRecommendation,
    pub proposal_digest: Digest,
}

impl LokaliseLocalizationResultProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&(
            &self.scope,
            &self.evidence,
            &self.source_evidence_digest,
            &self.registration_digest,
            &self.provider_digest,
            &self.contract_digest,
            &self.permission_digest,
            self.proposal_only,
            self.native,
            self.connected,
            self.first_party,
            self.adopts_outcome,
            &self.recommendation,
        ))
    }

    #[must_use]
    pub fn state(&self) -> LokaliseEvidenceState {
        self.evidence.state.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recorded: bool,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

pub type LokaliseObservationReceipt = ObservationReceipt;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseReadbackReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub status: String,
    pub independent_native_readback: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LokaliseRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub team_digest: Digest,
    pub project_digest: Digest,
    pub branch_digest: Digest,
    pub file_digest: Digest,
    pub language_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub privacy_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

impl LokaliseRegistration {
    #[must_use]
    pub fn bind(
        scope: &LokaliseLocalizationScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            plugin_version: crate::LOKALISE_LOCALIZATION_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::LOKALISE_LOCALIZATION_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_id: crate::LOKALISE_PROVIDER_ID.to_owned(),
            provider_digest,
            team_digest: scope.team_id().digest(),
            project_digest: scope.project_id().digest(),
            branch_digest: scope.branch().digest(),
            file_digest: scope.file_id().digest(),
            language_digest: scope.language().digest(),
            permission_digest: scope.permission().digest(),
            scope_digest: scope.scope_digest().clone(),
            revision_digest: scope.revision_digest().clone(),
            privacy_digest: scope.privacy_digest().clone(),
            secret_reference_digest: secret_reference.digest(),
            registration_revision: Revision::new(1).expect("registration revision"),
            registration_digest: String::new(),
            state: RegistrationState::Active,
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    fn compute_digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "schema": "lokalise-registration/v1",
            "pluginVersion": &self.plugin_version,
            "contractVersion": &self.contract_version,
            "contractDigest": &self.contract_digest,
            "providerId": &self.provider_id,
            "providerDigest": &self.provider_digest,
            "teamDigest": &self.team_digest,
            "projectDigest": &self.project_digest,
            "branchDigest": &self.branch_digest,
            "fileDigest": &self.file_digest,
            "languageDigest": &self.language_digest,
            "permissionDigest": &self.permission_digest,
            "scopeDigest": &self.scope_digest,
            "revisionDigest": &self.revision_digest,
            "privacyDigest": &self.privacy_digest,
            "secretReferenceDigest": &self.secret_reference_digest,
            "registrationRevision": self.registration_revision,
            "state": &self.state,
            "reversible": self.reversible,
            "revocable": self.revocable,
        }))
    }

    pub fn validate(
        &self,
        scope: &LokaliseLocalizationScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.state != RegistrationState::Active {
            return Err(ModelError::InvalidScope("registration revoked"));
        }
        if self.plugin_version != crate::LOKALISE_LOCALIZATION_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::LOKALISE_LOCALIZATION_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_id != crate::LOKALISE_PROVIDER_ID
            || &self.provider_digest != provider_digest
            || self.team_digest != scope.team_id().digest()
            || self.project_digest != scope.project_id().digest()
            || self.branch_digest != scope.branch().digest()
            || self.file_digest != scope.file_id().digest()
            || self.language_digest != scope.language().digest()
            || self.permission_digest != scope.permission().digest()
            || self.scope_digest != *scope.scope_digest()
            || self.revision_digest != *scope.revision_digest()
            || self.privacy_digest != *scope.privacy_digest()
            || self.secret_reference_digest != secret_reference.digest()
            || !self.reversible
            || !self.revocable
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ModelError> {
        if !self.revocable {
            return Err(ModelError::InvalidScope("registration is not revocable"));
        }
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            reversible: self.reversible,
            revocable: self.revocable,
            native: false,
            connected: false,
            first_party: false,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.reversible {
            return Err(ModelError::InvalidScope("registration is not reversible"));
        }
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        self.registration_revision = Revision::new(
            self.registration_revision
                .get()
                .checked_add(1)
                .ok_or(ModelError::RevisionOverflow)?,
        )?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

fn normalize_project(
    payload: Option<&LokaliseProjectPayload>,
    scope: &LokaliseLocalizationScope,
) -> Result<LokaliseProjectSummary, ModelError> {
    let Some(payload) = payload else {
        return Ok(LokaliseProjectSummary {
            project_id: scope.project_id().clone(),
            team_id: scope.team_id().clone(),
            branch_digest: scope.branch().digest(),
            name_digest: None,
            project_type: None,
        });
    };
    if let Some(project_id) = payload.project_id.as_deref()
        && project_id != scope.project_id().as_str()
    {
        return Err(ModelError::InvalidScope("project metadata"));
    }
    if let Some(team_id) = payload.team_id.as_deref()
        && team_id != scope.team_id().as_str()
    {
        return Err(ModelError::InvalidScope("team metadata"));
    }
    if let Some(branch) = payload.branch.as_deref()
        && branch != scope.branch().as_str()
    {
        return Err(ModelError::InvalidScope("branch metadata"));
    }
    Ok(LokaliseProjectSummary {
        project_id: scope.project_id().clone(),
        team_id: scope.team_id().clone(),
        branch_digest: scope.branch().digest(),
        name_digest: payload
            .name
            .as_deref()
            .map(|name| sha256_digest(format!("lokalise-project-name/v1|{name}").as_bytes())),
        project_type: payload.project_type.clone(),
    })
}

fn normalize_language(
    payloads: &[LokaliseLanguagePayload],
    scope: &LokaliseLocalizationScope,
) -> Result<LokaliseLanguageSummary, ModelError> {
    let matching = payloads.iter().find(|payload| {
        payload
            .resolved_id()
            .is_some_and(|id| id.to_string() == scope.language().language_id().as_str())
            || payload
                .resolved_iso()
                .is_some_and(|iso| iso == scope.language().iso().as_str())
    });
    if !payloads.is_empty() && matching.is_none() {
        return Err(ModelError::InvalidScope("language metadata"));
    }
    let Some(payload) = matching else {
        return Ok(LokaliseLanguageSummary {
            language_id: scope.language().language_id().clone(),
            iso: scope.language().iso().clone(),
            name_digest: scope.language().name_digest().clone(),
            is_rtl: None,
        });
    };
    let language_id = payload
        .resolved_id()
        .map(|id| LanguageId::new(id.to_string()))
        .transpose()?
        .unwrap_or_else(|| scope.language().language_id().clone());
    let iso = payload
        .resolved_iso()
        .map(LanguageIso::new)
        .transpose()?
        .unwrap_or_else(|| scope.language().iso().clone());
    let name_digest = payload.resolved_name().map_or_else(
        || scope.language().name_digest().clone(),
        |name| sha256_digest(format!("lokalise-language-name/v1|{name}").as_bytes()),
    );
    Ok(LokaliseLanguageSummary {
        language_id,
        iso,
        name_digest,
        is_rtl: payload.is_rtl,
    })
}

fn normalize_file(
    payloads: &[LokaliseFilePayload],
    scope: &LokaliseLocalizationScope,
) -> Result<LokaliseFileSummary, ModelError> {
    let matching = payloads
        .iter()
        .find(|payload| payload.file_id.to_string() == scope.file_id().as_str());
    if !payloads.is_empty() && matching.is_none() {
        return Err(ModelError::InvalidScope("file metadata"));
    }
    let Some(payload) = matching else {
        return Ok(LokaliseFileSummary {
            file_id: scope.file_id().clone(),
            filename_digest: sha256_digest(b"lokalise-filename-unavailable"),
            key_count: 0,
        });
    };
    Ok(LokaliseFileSummary {
        file_id: scope.file_id().clone(),
        filename_digest: sha256_digest(
            format!("lokalise-filename/v1|{}", payload.filename).as_bytes(),
        ),
        key_count: payload.key_count,
    })
}

fn normalize_translation(
    payload: &LokaliseTranslationPayload,
    scope: &LokaliseLocalizationScope,
) -> Result<LokaliseTranslationSummary, ModelError> {
    if payload.translation_id == 0 || payload.key_id == 0 {
        return Err(ModelError::InvalidResponse("translation identifier"));
    }
    let file_id = payload
        .file_id
        .ok_or(ModelError::InvalidScope("translation file missing"))?;
    if file_id.to_string() != scope.file_id().as_str() {
        return Err(ModelError::InvalidScope("translation file"));
    }
    if let Some(language_id) = payload.language_id
        && language_id.to_string() != scope.language().language_id().as_str()
    {
        return Err(ModelError::InvalidScope("translation language"));
    }
    let language_iso = payload
        .language_iso
        .as_deref()
        .map(LanguageIso::new)
        .transpose()?;
    if language_iso
        .as_ref()
        .is_some_and(|iso| iso != scope.language().iso())
    {
        return Err(ModelError::InvalidScope("translation language ISO"));
    }
    let state = if !payload.qa_issues.is_empty() {
        LokaliseTranslationState::QaIssue
    } else if payload.is_untranslated || payload.translation.as_deref().is_none_or(str::is_empty) {
        LokaliseTranslationState::Untranslated
    } else if payload.is_unverified {
        LokaliseTranslationState::Unverified
    } else if payload.is_reviewed {
        LokaliseTranslationState::Reviewed
    } else {
        LokaliseTranslationState::Translated
    };
    let content_digest = canonical_digest(&(
        "lokalise-translation-content/v1",
        payload.translation_id,
        payload.key_id,
        file_id,
        payload.language_id,
        &payload.source,
        &payload.translation,
    ));
    Ok(LokaliseTranslationSummary {
        translation_id: TranslationId::new(payload.translation_id.to_string())?,
        key_id: KeyId::new(payload.key_id.to_string())?,
        file_id: FileId::new(file_id.to_string())?,
        language_id: payload
            .language_id
            .map(|id| LanguageId::new(id.to_string()))
            .transpose()?
            .unwrap_or_else(|| scope.language().language_id().clone()),
        language_iso,
        state,
        qa_issue_count: u16::try_from(payload.qa_issues.len())
            .map_err(|_| ModelError::InvalidResponse("QA issue bound"))?,
        content_digest,
    })
}

fn normalize_task(
    payload: &LokaliseTaskPayload,
    scope: &LokaliseLocalizationScope,
) -> Option<LokaliseTaskSummary> {
    if payload.task_id == 0 {
        return None;
    }
    let language_ids = payload
        .languages
        .iter()
        .filter_map(|language| {
            let matches_id = language
                .language_id
                .is_some_and(|id| id.to_string() == scope.language().language_id().as_str());
            let matches_iso = language
                .language_iso
                .as_deref()
                .is_some_and(|iso| iso == scope.language().iso().as_str());
            if matches_id || matches_iso {
                language
                    .language_id
                    .and_then(|id| LanguageId::new(id.to_string()).ok())
                    .or_else(|| Some(scope.language().language_id().clone()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    if !payload.languages.is_empty() && language_ids.is_empty() {
        return None;
    }
    let status = match payload.status.to_ascii_lowercase().as_str() {
        "created" => LokaliseTaskStatus::Created,
        "queued" => LokaliseTaskStatus::Queued,
        "in_progress" | "in progress" => LokaliseTaskStatus::InProgress,
        "completed" | "complete" => LokaliseTaskStatus::Completed,
        _ => LokaliseTaskStatus::Unknown,
    };
    Some(LokaliseTaskSummary {
        task_id: TaskId::new(payload.task_id.to_string()).ok()?,
        status,
        progress: payload.progress,
        language_ids,
        keys_count: payload.keys_count,
        words_count: payload.words_count,
        done_words_count: payload.done_words_count,
        task_type_digest: payload
            .task_type
            .as_deref()
            .map(|value| sha256_digest(format!("lokalise-task-type/v1|{value}").as_bytes())),
    })
}

fn normalize_build(payload: &LokaliseProcessPayload) -> Result<LokaliseBuildSummary, ModelError> {
    let build_id = BuildId::new(&payload.process_id)?;
    let status = match payload.status.to_ascii_lowercase().as_str() {
        "queued" | "running" | "in_progress" | "building" => LokaliseBuildStatus::Building,
        "completed" | "complete" | "finished" | "ready" => LokaliseBuildStatus::Ready,
        "expired" | "deleted" => LokaliseBuildStatus::Expired,
        _ => LokaliseBuildStatus::ProviderUnknown,
    };
    Ok(LokaliseBuildSummary {
        build_id,
        status,
        progress: payload.percentage,
        version: payload.version,
        build_digest: canonical_digest(&(
            "lokalise-build/v1",
            &payload.process_id,
            &payload.process_type,
            &payload.status,
            payload.percentage,
            &payload.details,
            &payload.url,
            payload.version,
        )),
    })
}
