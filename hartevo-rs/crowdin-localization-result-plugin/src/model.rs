//! Typed, bounded, and redacted Crowdin localization-result models.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION, CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT,
    CROWDIN_LOCALIZATION_RESULT_SERVICE_ID, CROWDIN_PROVIDER_ID, CROWDIN_PROVIDER_REVISION,
    MAX_BACKOFF_MS, MAX_PAGES, MAX_RESPONSE_BYTES, MAX_RETRIES, MAX_WINDOW_SECONDS, PAGE_SIZE,
};

pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_LANGUAGE_LENGTH: usize = 64;
pub const MAX_CONSENT_SCOPE_LENGTH: usize = 128;
pub const MAX_COUNT: u64 = 100_000_000;
pub const MAX_RECEIPTS: usize = 8;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains whitespace")]
    Whitespace { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is outside its bound")]
    OutOfBounds { field: &'static str },
    #[error("{field} is inconsistent with its parent scope")]
    Inconsistent { field: &'static str },
}

pub(crate) fn validate_text(
    value: &str,
    field: &'static str,
    maximum: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > maximum {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::Whitespace { field });
    }
    Ok(())
}

pub(crate) fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_string {
    ($name:ident, $field:literal, $maximum:expr, $allow_internal_whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $maximum, $allow_internal_whitespace)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

macro_rules! positive_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub fn new(value: u64) -> Result<Self, ModelError> {
                validate_positive(value, $field)?;
                Ok(Self(value))
            }

            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_string!(
    OrganizationId,
    "Crowdin organization",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(LanguageCode, "target language", MAX_LANGUAGE_LENGTH, false);
bounded_string!(
    SourceBranchName,
    "source branch name",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(
    HartevoProjectId,
    "Hartevo Project id",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(MissionId, "Mission id", MAX_IDENTIFIER_LENGTH, false);
bounded_string!(
    WorkProductId,
    "Work Product id",
    MAX_IDENTIFIER_LENGTH,
    false
);
bounded_string!(
    ConsentScopeId,
    "consent scope",
    MAX_CONSENT_SCOPE_LENGTH,
    false
);

positive_id!(CrowdinProjectId, "Crowdin project id");
positive_id!(CrowdinBranchId, "Crowdin source branch id");
positive_id!(CrowdinFileId, "Crowdin source file id");
positive_id!(CrowdinBundleId, "Crowdin translation bundle id");

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidDigest {
                field: "SHA-256 digest",
            });
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    pub fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut material = Vec::new();
        material.extend_from_slice(domain.as_bytes());
        material.push(0);
        for field in fields {
            material.extend_from_slice(field.as_bytes());
            material.push(0);
        }
        Self::from_bytes(&material)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::InvalidText {
        field: "canonical digest input",
    })?;
    Ok(sha256_digest(&bytes))
}

/// Opaque host-owned credential metadata. The constructor hashes and drops
/// the supplied handle, so a Crowdin token can never enter a serialized model.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    reference_digest: Digest,
    credential_revision: u64,
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(
            &reference_id,
            "secret reference handle",
            MAX_IDENTIFIER_LENGTH,
            false,
        )?;
        validate_positive(credential_revision, "credential revision")?;
        Ok(Self {
            reference_digest: sha256_digest(reference_id.as_bytes()),
            credential_revision,
        })
    }

    pub fn crowdin(
        reference_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(reference_id, credential_revision)
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &"<opaque>")
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HartevoProjectBinding {
    pub id: HartevoProjectId,
    pub revision: u64,
}

impl HartevoProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "Hartevo Project revision")?;
        Ok(Self {
            id: HartevoProjectId::parse(id)?,
            revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: u64,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "Mission revision")?;
        Ok(Self {
            id: MissionId::parse(id)?,
            revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: u64,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "Work Product revision")?;
        Ok(Self {
            id: WorkProductId::parse(id)?,
            revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub id: ConsentScopeId,
    pub revision: u64,
    pub digest: Digest,
}

impl ConsentScope {
    pub fn new(id: impl Into<String>, revision: u64, digest: Digest) -> Result<Self, ModelError> {
        validate_positive(revision, "consent revision")?;
        Ok(Self {
            id: ConsentScopeId::parse(id)?,
            revision,
            digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBranchBinding {
    pub id: CrowdinBranchId,
    pub name: SourceBranchName,
    pub revision: u64,
}

impl SourceBranchBinding {
    pub fn new(id: u64, name: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "source branch revision")?;
        Ok(Self {
            id: CrowdinBranchId::new(id)?,
            name: SourceBranchName::parse(name)?,
            revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceFileBinding {
    pub id: CrowdinFileId,
    pub revision: u64,
    pub path_digest: Digest,
}

impl SourceFileBinding {
    pub fn new(id: u64, revision: u64, path_digest: Digest) -> Result<Self, ModelError> {
        validate_positive(revision, "source file revision")?;
        Ok(Self {
            id: CrowdinFileId::new(id)?,
            revision,
            path_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdinLocalizationScopeInput {
    pub organization: String,
    pub crowdin_project_id: u64,
    pub crowdin_project_revision: u64,
    pub source_branch_id: u64,
    pub source_branch_name: String,
    pub source_branch_revision: u64,
    pub source_file_id: u64,
    pub source_file_revision: u64,
    pub source_file_path_digest: Digest,
    pub target_language: String,
    pub hartevo_project_id: String,
    pub hartevo_project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub consent_scope: String,
    pub consent_revision: u64,
    pub consent_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdinLocalizationScope {
    pub organization: OrganizationId,
    pub crowdin_project: CrowdinProjectId,
    pub crowdin_project_revision: u64,
    pub source_branch: SourceBranchBinding,
    pub source_file: SourceFileBinding,
    pub target_language: LanguageCode,
    pub hartevo_project: HartevoProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub consent: ConsentScope,
}

impl CrowdinLocalizationScope {
    pub fn new(input: CrowdinLocalizationScopeInput) -> Result<Self, ModelError> {
        validate_positive(input.crowdin_project_revision, "Crowdin project revision")?;
        Ok(Self {
            organization: OrganizationId::parse(input.organization)?,
            crowdin_project: CrowdinProjectId::new(input.crowdin_project_id)?,
            crowdin_project_revision: input.crowdin_project_revision,
            source_branch: SourceBranchBinding::new(
                input.source_branch_id,
                input.source_branch_name,
                input.source_branch_revision,
            )?,
            source_file: SourceFileBinding::new(
                input.source_file_id,
                input.source_file_revision,
                input.source_file_path_digest,
            )?,
            target_language: LanguageCode::parse(input.target_language)?,
            hartevo_project: HartevoProjectBinding::new(
                input.hartevo_project_id,
                input.hartevo_project_revision,
            )?,
            mission: MissionBinding::new(input.mission_id, input.mission_revision)?,
            work_product: WorkProductBinding::new(
                input.work_product_id,
                input.work_product_revision,
            )?,
            consent: ConsentScope::new(
                input.consent_scope,
                input.consent_revision,
                input.consent_digest,
            )?,
        })
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("Crowdin localization scope serializes")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ObservationWindow {
    pub from_epoch_seconds: u64,
    pub until_epoch_seconds: u64,
}

impl ObservationWindow {
    pub fn new(from_epoch_seconds: u64, until_epoch_seconds: u64) -> Result<Self, ModelError> {
        if until_epoch_seconds <= from_epoch_seconds
            || until_epoch_seconds - from_epoch_seconds > MAX_WINDOW_SECONDS
        {
            return Err(ModelError::OutOfBounds {
                field: "observation window",
            });
        }
        Ok(Self {
            from_epoch_seconds,
            until_epoch_seconds,
        })
    }

    pub const fn duration_seconds(self) -> u64 {
        self.until_epoch_seconds - self.from_epoch_seconds
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadBounds {
    pub max_response_bytes: usize,
    pub max_pages: u16,
    pub page_size: u16,
    pub max_retries: u8,
    pub max_backoff_ms: u64,
}

impl ReadBounds {
    pub const fn layer1() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_pages: MAX_PAGES,
            page_size: PAGE_SIZE,
            max_retries: MAX_RETRIES,
            max_backoff_ms: MAX_BACKOFF_MS,
        }
    }

    pub fn validate(self) -> Result<(), ModelError> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_retries > MAX_RETRIES
            || self.max_backoff_ms > MAX_BACKOFF_MS
        {
            return Err(ModelError::OutOfBounds {
                field: "Crowdin read bounds",
            });
        }
        Ok(())
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self::layer1()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadCursor {
    pub page: u16,
    pub offset: u32,
    pub cursor_digest: Option<Digest>,
}

impl ReadCursor {
    pub fn first() -> Self {
        Self {
            page: 0,
            offset: 0,
            cursor_digest: None,
        }
    }

    pub fn validate(&self, bounds: ReadBounds) -> Result<(), ModelError> {
        bounds.validate()?;
        if self.page >= bounds.max_pages {
            return Err(ModelError::OutOfBounds { field: "read page" });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrowdinReadOperation {
    ProjectMetadata,
    LanguageCoverage,
    SourceFileMetadata,
    TranslationProgress,
    TranslationBuildStatus,
}

impl CrowdinReadOperation {
    pub const fn contract_name(self) -> &'static str {
        match self {
            Self::ProjectMetadata => "read_project_metadata",
            Self::LanguageCoverage => "read_language_coverage",
            Self::SourceFileMetadata => "read_source_file_metadata",
            Self::TranslationProgress => "read_translation_progress",
            Self::TranslationBuildStatus => "read_translation_build_status",
        }
    }
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalizationState {
    Source,
    Translated,
    NeedsReview,
    Approved,
    Building,
    Ready,
    Expired,
    Partial,
    RetentionGap,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    NotRequested,
    NeedsReview,
    Approved,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildState {
    Building,
    Ready,
    Expired,
    Partial,
    AccessLost,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionKind {
    String,
    File,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalizationRevision {
    pub kind: RevisionKind,
    pub revision: u64,
    pub content_digest: Digest,
}

impl LocalizationRevision {
    pub fn new(
        kind: RevisionKind,
        revision: u64,
        content_digest: Digest,
    ) -> Result<Self, ModelError> {
        validate_positive(revision, "localization revision")?;
        Ok(Self {
            kind,
            revision,
            content_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundedCounts {
    pub source_units: u64,
    pub translated_units: u64,
    pub needs_review_units: u64,
    pub approved_units: u64,
}

impl BoundedCounts {
    pub fn new(
        source_units: u64,
        translated_units: u64,
        needs_review_units: u64,
        approved_units: u64,
    ) -> Result<Self, ModelError> {
        if source_units > MAX_COUNT
            || translated_units > source_units
            || needs_review_units > translated_units
            || approved_units > translated_units
        {
            return Err(ModelError::OutOfBounds {
                field: "localization counts",
            });
        }
        Ok(Self {
            source_units,
            translated_units,
            needs_review_units,
            approved_units,
        })
    }

    pub const fn is_partial(self) -> bool {
        self.translated_units < self.source_units
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectMetadata {
    pub project_id: CrowdinProjectId,
    pub organization_digest: Digest,
    pub project_revision: u64,
    pub source_language: LanguageCode,
    pub target_languages: Vec<LanguageCode>,
    pub metadata_digest: Digest,
}

impl ProjectMetadata {
    pub fn new(
        project_id: CrowdinProjectId,
        organization: &OrganizationId,
        project_revision: u64,
        source_language: impl Into<String>,
        target_languages: Vec<LanguageCode>,
    ) -> Result<Self, ModelError> {
        validate_positive(project_revision, "Crowdin project revision")?;
        if target_languages.is_empty() {
            return Err(ModelError::Empty {
                field: "target languages",
            });
        }
        let source_language = LanguageCode::parse(source_language)?;
        let organization_digest = sha256_digest(organization.as_str().as_bytes());
        let metadata_digest = Digest::from_fields(
            "crowdin-project-metadata/v1",
            &[
                project_id.get().to_string(),
                organization_digest.as_str().to_owned(),
                project_revision.to_string(),
                source_language.as_str().to_owned(),
                target_languages
                    .iter()
                    .map(LanguageCode::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        Ok(Self {
            project_id,
            organization_digest,
            project_revision,
            source_language,
            target_languages,
            metadata_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LanguageCoverage {
    pub project_id: CrowdinProjectId,
    pub branch_id: CrowdinBranchId,
    pub language: LanguageCode,
    pub counts: BoundedCounts,
    pub state: LocalizationState,
    pub coverage_digest: Digest,
}

impl LanguageCoverage {
    pub fn new(
        project_id: CrowdinProjectId,
        branch_id: CrowdinBranchId,
        language: impl Into<String>,
        counts: BoundedCounts,
        state: LocalizationState,
    ) -> Result<Self, ModelError> {
        let language = LanguageCode::parse(language)?;
        let coverage_digest = Digest::from_fields(
            "crowdin-language-coverage/v1",
            &[
                project_id.get().to_string(),
                branch_id.get().to_string(),
                language.as_str().to_owned(),
                serde_json::to_string(&counts).map_err(|_| ModelError::InvalidText {
                    field: "coverage digest input",
                })?,
                serde_json::to_string(&state).map_err(|_| ModelError::InvalidText {
                    field: "coverage state digest input",
                })?,
            ],
        );
        Ok(Self {
            project_id,
            branch_id,
            language,
            counts,
            state,
            coverage_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceFileMetadata {
    pub project_id: CrowdinProjectId,
    pub branch_id: CrowdinBranchId,
    pub file_id: CrowdinFileId,
    pub file_revision: u64,
    pub path_digest: Digest,
    pub string_count: u64,
    pub source_revision: LocalizationRevision,
    pub metadata_digest: Digest,
}

impl SourceFileMetadata {
    pub fn new(
        project_id: CrowdinProjectId,
        branch_id: CrowdinBranchId,
        file_id: CrowdinFileId,
        file_revision: u64,
        path_digest: Digest,
        string_count: u64,
        source_revision: LocalizationRevision,
    ) -> Result<Self, ModelError> {
        validate_positive(file_revision, "source file revision")?;
        if string_count > MAX_COUNT {
            return Err(ModelError::OutOfBounds {
                field: "source file string count",
            });
        }
        if source_revision.kind != RevisionKind::File || source_revision.revision != file_revision {
            return Err(ModelError::Inconsistent {
                field: "source file revision",
            });
        }
        let metadata_digest = Digest::from_fields(
            "crowdin-source-file-metadata/v1",
            &[
                project_id.get().to_string(),
                branch_id.get().to_string(),
                file_id.get().to_string(),
                file_revision.to_string(),
                path_digest.as_str().to_owned(),
                string_count.to_string(),
                source_revision.content_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            project_id,
            branch_id,
            file_id,
            file_revision,
            path_digest,
            string_count,
            source_revision,
            metadata_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TranslationProgress {
    pub project_id: CrowdinProjectId,
    pub branch_id: CrowdinBranchId,
    pub file_id: CrowdinFileId,
    pub language: LanguageCode,
    pub source_revision: LocalizationRevision,
    pub translation_revision: Option<LocalizationRevision>,
    pub counts: BoundedCounts,
    pub approval: ApprovalState,
    pub state: LocalizationState,
    pub progress_digest: Digest,
}

impl TranslationProgress {
    pub fn new(
        project_id: CrowdinProjectId,
        branch_id: CrowdinBranchId,
        file_id: CrowdinFileId,
        language: impl Into<String>,
        source_revision: LocalizationRevision,
        translation_revision: Option<LocalizationRevision>,
        counts: BoundedCounts,
        approval: ApprovalState,
        state: LocalizationState,
    ) -> Result<Self, ModelError> {
        if let Some(revision) = &translation_revision
            && revision.kind != RevisionKind::String
        {
            return Err(ModelError::Inconsistent {
                field: "translation revision kind",
            });
        }
        let language = LanguageCode::parse(language)?;
        let progress_digest = Digest::from_fields(
            "crowdin-translation-progress/v1",
            &[
                project_id.get().to_string(),
                branch_id.get().to_string(),
                file_id.get().to_string(),
                language.as_str().to_owned(),
                source_revision.content_digest.as_str().to_owned(),
                translation_revision.as_ref().map_or_else(
                    || "none".to_owned(),
                    |value| value.content_digest.to_string(),
                ),
                serde_json::to_string(&counts).map_err(|_| ModelError::InvalidText {
                    field: "progress digest input",
                })?,
                serde_json::to_string(&approval).map_err(|_| ModelError::InvalidText {
                    field: "approval digest input",
                })?,
                serde_json::to_string(&state).map_err(|_| ModelError::InvalidText {
                    field: "progress state digest input",
                })?,
            ],
        );
        Ok(Self {
            project_id,
            branch_id,
            file_id,
            language,
            source_revision,
            translation_revision,
            counts,
            approval,
            state,
            progress_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TranslationBuildStatus {
    pub project_id: CrowdinProjectId,
    pub branch_id: CrowdinBranchId,
    pub file_id: CrowdinFileId,
    pub language: LanguageCode,
    pub bundle_id: CrowdinBundleId,
    pub source_revision_digest: Digest,
    pub state: BuildState,
    pub progress_percent: Option<u8>,
    pub build_digest: Digest,
}

impl TranslationBuildStatus {
    pub fn new(
        project_id: CrowdinProjectId,
        branch_id: CrowdinBranchId,
        file_id: CrowdinFileId,
        language: impl Into<String>,
        bundle_id: CrowdinBundleId,
        source_revision_digest: Digest,
        state: BuildState,
        progress_percent: Option<u8>,
        build_digest: Digest,
    ) -> Result<Self, ModelError> {
        if progress_percent.is_some_and(|progress| progress > 100) {
            return Err(ModelError::OutOfBounds {
                field: "translation build progress",
            });
        }
        Ok(Self {
            project_id,
            branch_id,
            file_id,
            language: LanguageCode::parse(language)?,
            bundle_id,
            source_revision_digest,
            state,
            progress_percent,
            build_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdinReadReceipt {
    pub operation: CrowdinReadOperation,
    pub request_digest: Digest,
    pub response_status: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provider_revision: String,
    pub retry_count: u8,
    pub raw_body_retained: bool,
    pub credential_material_retained: bool,
}

impl CrowdinReadReceipt {
    pub fn validate(&self, bounds: ReadBounds) -> Result<(), ModelError> {
        bounds.validate()?;
        if self.response_status != 200
            || self.response_bytes > bounds.max_response_bytes
            || self.retry_count > bounds.max_retries
            || self.raw_body_retained
            || self.credential_material_retained
        {
            return Err(ModelError::Inconsistent {
                field: "redacted Crowdin read receipt",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrowdinLocalizationResultProposal {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_revision: String,
    pub scope: CrowdinLocalizationScope,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub consent_digest: Digest,
    pub observation_window: ObservationWindow,
    pub bounds: ReadBounds,
    pub operations: Vec<CrowdinReadOperation>,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub publication_claim: bool,
    pub proposal_digest: Digest,
}

impl CrowdinLocalizationResultProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: CrowdinLocalizationScope,
        secret_reference: &SecretReference,
        observation_window: ObservationWindow,
        bounds: ReadBounds,
        contract_digest: Digest,
        provider_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        bounds.validate()?;
        let provider_revision = provider_revision.into();
        validate_text(
            &provider_revision,
            "Crowdin provider revision",
            MAX_IDENTIFIER_LENGTH,
            false,
        )?;
        let scope_digest = scope.digest();
        let consent_digest = scope.consent.digest.clone();
        let operations = vec![
            CrowdinReadOperation::ProjectMetadata,
            CrowdinReadOperation::LanguageCoverage,
            CrowdinReadOperation::SourceFileMetadata,
            CrowdinReadOperation::TranslationProgress,
            CrowdinReadOperation::TranslationBuildStatus,
        ];
        let mut proposal = Self {
            plugin_version: CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT.to_owned(),
            contract_version: CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest,
            service_id: CROWDIN_LOCALIZATION_RESULT_SERVICE_ID.to_owned(),
            provider_id: CROWDIN_PROVIDER_ID.to_owned(),
            provider_revision,
            scope,
            scope_digest,
            secret_reference_digest: secret_reference.reference_digest.clone(),
            consent_digest,
            observation_window,
            bounds,
            operations,
            read_only: true,
            native: false,
            connected: false,
            publication_claim: false,
            proposal_digest: sha256_digest(b"uninitialized-crowdin-proposal"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        Ok(proposal)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "crowdin-localization-result-proposal/v1",
            &[
                self.plugin_version.clone(),
                self.contract_version.clone(),
                self.contract_digest.to_string(),
                self.service_id.clone(),
                self.provider_id.clone(),
                self.provider_revision.clone(),
                self.scope_digest.to_string(),
                self.secret_reference_digest.to_string(),
                self.consent_digest.to_string(),
                self.observation_window.from_epoch_seconds.to_string(),
                self.observation_window.until_epoch_seconds.to_string(),
                serde_json::to_string(&self.bounds).expect("read bounds serialize"),
                serde_json::to_string(&self.operations).expect("operations serialize"),
                self.read_only.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.publication_claim.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.bounds.validate()?;
        if self.plugin_version != CROWDIN_LOCALIZATION_RESULT_PLUGIN_VERSION_TEXT
            || self.contract_version != CROWDIN_LOCALIZATION_RESULT_CONTRACT_VERSION
            || self.service_id != CROWDIN_LOCALIZATION_RESULT_SERVICE_ID
            || self.provider_id != CROWDIN_PROVIDER_ID
            || self.provider_revision != CROWDIN_PROVIDER_REVISION
            || self.scope_digest != self.scope.digest()
            || self.consent_digest != self.scope.consent.digest
            || self.operations.len() != 5
            || !self.read_only
            || self.native
            || self.connected
            || self.publication_claim
            || self.proposal_digest != self.compute_digest()
        {
            return Err(ModelError::Inconsistent {
                field: "Crowdin localization result proposal",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalizationObservation {
    pub proposal_digest: Digest,
    pub scope: CrowdinLocalizationScope,
    pub scope_digest: Digest,
    pub project_metadata: ProjectMetadata,
    pub language_coverage: LanguageCoverage,
    pub source_file: SourceFileMetadata,
    pub translation_progress: TranslationProgress,
    pub build_status: TranslationBuildStatus,
    pub states: Vec<LocalizationState>,
    pub approval: ApprovalState,
    pub receipts: Vec<CrowdinReadReceipt>,
    pub provenance: TransportProvenance,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub publication_claim: bool,
    pub response_digest: Digest,
    pub observation_digest: Digest,
}

impl LocalizationObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposal: &CrowdinLocalizationResultProposal,
        project_metadata: ProjectMetadata,
        language_coverage: LanguageCoverage,
        source_file: SourceFileMetadata,
        translation_progress: TranslationProgress,
        build_status: TranslationBuildStatus,
        receipts: Vec<CrowdinReadReceipt>,
        provenance: TransportProvenance,
    ) -> Result<Self, ModelError> {
        proposal.validate()?;
        if receipts.is_empty() || receipts.len() > MAX_RECEIPTS {
            return Err(ModelError::OutOfBounds {
                field: "Crowdin read receipts",
            });
        }
        for receipt in &receipts {
            receipt.validate(proposal.bounds)?;
        }
        let scope = proposal.scope.clone();
        validate_observation_scope(
            &scope,
            &project_metadata,
            &language_coverage,
            &source_file,
            &translation_progress,
            &build_status,
        )?;
        let states = derive_states(&translation_progress, &build_status);
        let response_digest = Digest::from_fields(
            "crowdin-localization-result-read/v1",
            &[
                project_metadata.metadata_digest.to_string(),
                language_coverage.coverage_digest.to_string(),
                source_file.metadata_digest.to_string(),
                translation_progress.progress_digest.to_string(),
                build_status.build_digest.to_string(),
                receipts
                    .iter()
                    .map(|receipt| receipt.response_digest.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        );
        let approval = translation_progress.approval;
        let mut observation = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            scope: scope.clone(),
            scope_digest: scope.digest(),
            project_metadata,
            language_coverage,
            source_file,
            translation_progress,
            build_status,
            states,
            approval,
            receipts,
            provenance,
            read_only: true,
            native: false,
            connected: false,
            publication_claim: false,
            response_digest,
            observation_digest: sha256_digest(b"uninitialized-crowdin-observation"),
        };
        observation.observation_digest = observation.compute_digest();
        Ok(observation)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "crowdin-localization-result-observation/v1",
            &[
                self.proposal_digest.to_string(),
                self.scope_digest.to_string(),
                self.response_digest.to_string(),
                serde_json::to_string(&self.states).expect("states serialize"),
                serde_json::to_string(&self.approval).expect("approval serialize"),
                serde_json::to_string(&self.provenance).expect("provenance serialize"),
                self.read_only.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.publication_claim.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.scope_digest != self.scope.digest()
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || !self.read_only
            || self.native
            || self.connected
            || self.publication_claim
            || self.states != derive_states(&self.translation_progress, &self.build_status)
            || self.observation_digest != self.compute_digest()
        {
            return Err(ModelError::Inconsistent {
                field: "Crowdin localization observation",
            });
        }
        validate_observation_scope(
            &self.scope,
            &self.project_metadata,
            &self.language_coverage,
            &self.source_file,
            &self.translation_progress,
            &self.build_status,
        )
    }

    pub fn primary_state(&self) -> LocalizationState {
        [
            LocalizationState::AccessLost,
            LocalizationState::RetentionGap,
            LocalizationState::ProviderUnknown,
            LocalizationState::Building,
            LocalizationState::Expired,
            LocalizationState::Partial,
            LocalizationState::Ready,
            LocalizationState::Approved,
            LocalizationState::NeedsReview,
            LocalizationState::Translated,
            LocalizationState::Source,
        ]
        .into_iter()
        .find(|state| self.states.contains(state))
        .unwrap_or(LocalizationState::ProviderUnknown)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalizationResultReceipt {
    pub proposal_digest: Digest,
    pub observation_digest: Digest,
    pub scope_digest: Digest,
    pub provider_revision: String,
    pub provenance: TransportProvenance,
    pub recorded_at_epoch_seconds: u64,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub durable: bool,
    pub publication_claim: bool,
    pub adoption_authority: bool,
    pub receipt_digest: Digest,
}

impl LocalizationResultReceipt {
    pub fn new(
        observation: &LocalizationObservation,
        provider_revision: impl Into<String>,
        recorded_at_epoch_seconds: u64,
    ) -> Result<Self, ModelError> {
        observation.validate()?;
        let mut receipt = Self {
            proposal_digest: observation.proposal_digest.clone(),
            observation_digest: observation.observation_digest.clone(),
            scope_digest: observation.scope_digest.clone(),
            provider_revision: provider_revision.into(),
            provenance: observation.provenance,
            recorded_at_epoch_seconds,
            read_only: true,
            native: false,
            connected: false,
            durable: false,
            publication_claim: false,
            adoption_authority: false,
            receipt_digest: sha256_digest(b"uninitialized-crowdin-receipt"),
        };
        receipt.receipt_digest = receipt.compute_digest();
        Ok(receipt)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "crowdin-localization-result-receipt/v1",
            &[
                self.proposal_digest.to_string(),
                self.observation_digest.to_string(),
                self.scope_digest.to_string(),
                self.provider_revision.clone(),
                self.provenance.as_str().to_owned(),
                self.recorded_at_epoch_seconds.to_string(),
                self.read_only.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.durable.to_string(),
                self.publication_claim.to_string(),
                self.adoption_authority.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.read_only
            || self.native
            || self.connected
            || self.durable
            || self.publication_claim
            || self.adoption_authority
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.receipt_digest != self.compute_digest()
        {
            return Err(ModelError::Inconsistent {
                field: "Crowdin localization result receipt",
            });
        }
        Ok(())
    }
}

fn validate_observation_scope(
    scope: &CrowdinLocalizationScope,
    project_metadata: &ProjectMetadata,
    language_coverage: &LanguageCoverage,
    source_file: &SourceFileMetadata,
    translation_progress: &TranslationProgress,
    build_status: &TranslationBuildStatus,
) -> Result<(), ModelError> {
    let project_id = scope.crowdin_project;
    let branch_id = scope.source_branch.id;
    let file_id = scope.source_file.id;
    let language = scope.target_language.as_str();
    if project_metadata.project_id != project_id
        || project_metadata.project_revision != scope.crowdin_project_revision
        || project_metadata.organization_digest
            != sha256_digest(scope.organization.as_str().as_bytes())
        || !project_metadata
            .target_languages
            .iter()
            .any(|candidate| candidate == &scope.target_language)
        || language_coverage.project_id != project_id
        || language_coverage.branch_id != branch_id
        || language_coverage.language.as_str() != language
        || source_file.project_id != project_id
        || source_file.branch_id != branch_id
        || source_file.file_id != file_id
        || source_file.file_revision != scope.source_file.revision
        || source_file.path_digest != scope.source_file.path_digest
        || translation_progress.project_id != project_id
        || translation_progress.branch_id != branch_id
        || translation_progress.file_id != file_id
        || translation_progress.language.as_str() != language
        || translation_progress.source_revision.content_digest
            != source_file.source_revision.content_digest
        || build_status.project_id != project_id
        || build_status.branch_id != branch_id
        || build_status.file_id != file_id
        || build_status.language.as_str() != language
        || build_status.source_revision_digest != source_file.source_revision.content_digest
    {
        return Err(ModelError::Inconsistent {
            field: "Crowdin observation scope fence",
        });
    }
    Ok(())
}

fn derive_states(
    progress: &TranslationProgress,
    build: &TranslationBuildStatus,
) -> Vec<LocalizationState> {
    let mut states = vec![LocalizationState::Source];
    if progress.counts.translated_units > 0 {
        states.push(LocalizationState::Translated);
        if progress.translation_revision.is_none() {
            states.push(LocalizationState::RetentionGap);
        }
    }
    if progress.approval == ApprovalState::NeedsReview || progress.counts.needs_review_units > 0 {
        states.push(LocalizationState::NeedsReview);
    }
    if progress.approval == ApprovalState::Approved || progress.counts.approved_units > 0 {
        states.push(LocalizationState::Approved);
    }
    if progress.approval == ApprovalState::Unknown {
        states.push(LocalizationState::ProviderUnknown);
    }
    if progress.counts.is_partial() {
        states.push(LocalizationState::Partial);
    }
    match progress.state {
        LocalizationState::RetentionGap => states.push(LocalizationState::RetentionGap),
        LocalizationState::AccessLost => states.push(LocalizationState::AccessLost),
        LocalizationState::ProviderUnknown => states.push(LocalizationState::ProviderUnknown),
        LocalizationState::Source
        | LocalizationState::Translated
        | LocalizationState::NeedsReview
        | LocalizationState::Approved
        | LocalizationState::Building
        | LocalizationState::Ready
        | LocalizationState::Expired
        | LocalizationState::Partial => {}
    }
    states.push(match build.state {
        BuildState::Building => LocalizationState::Building,
        BuildState::Ready => LocalizationState::Ready,
        BuildState::Expired => LocalizationState::Expired,
        BuildState::Partial => LocalizationState::Partial,
        BuildState::AccessLost => LocalizationState::AccessLost,
        BuildState::ProviderUnknown => LocalizationState::ProviderUnknown,
    });
    states.sort_by_key(|state| format!("{state:?}"));
    states.dedup();
    states
}
