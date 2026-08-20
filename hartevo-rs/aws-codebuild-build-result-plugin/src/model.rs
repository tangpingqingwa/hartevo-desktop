//! Typed, bounded, and redacted AWS CodeBuild projections.
//!
//! Provider payloads are normalized before they reach this module. The model
//! contains no commands, environment variables, secrets, logs, source bytes,
//! artifact bytes, raw request/response bodies, or native receipts.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AWS_CODEBUILD_IAM_PERMISSIONS, AWS_CODEBUILD_MAX_ARTIFACTS_PER_BUILD,
    AWS_CODEBUILD_MAX_BATCH_METADATA, AWS_CODEBUILD_MAX_BUILDS, AWS_CODEBUILD_MAX_PAGE_SIZE,
    AWS_CODEBUILD_MAX_PAGES, AWS_CODEBUILD_MAX_PROJECTS, AWS_CODEBUILD_PLUGIN_VERSION,
};

pub const MAX_IDENTIFIER_LENGTH: usize = crate::AWS_CODEBUILD_MAX_IDENTIFIER_LENGTH;
pub const MAX_PAGE_SIZE: u16 = AWS_CODEBUILD_MAX_PAGE_SIZE;
pub const MAX_PAGES: u16 = AWS_CODEBUILD_MAX_PAGES;
pub const MAX_BUILDS: usize = AWS_CODEBUILD_MAX_BUILDS;
pub const MAX_PROJECTS: usize = AWS_CODEBUILD_MAX_PROJECTS;
pub const MAX_ARTIFACTS_PER_BUILD: usize = AWS_CODEBUILD_MAX_ARTIFACTS_PER_BUILD;
pub const MAX_BATCH_METADATA: usize = AWS_CODEBUILD_MAX_BATCH_METADATA;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains unsupported whitespace")]
    InvalidWhitespace { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid bounded value")]
    InvalidValue { field: &'static str },
    #[error("{field} exceeds the configured bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} is not a valid CodeBuild status")]
    InvalidStatus { field: &'static str },
    #[error("{field} has invalid timestamp ordering")]
    InvalidTimestamp { field: &'static str },
    #[error("{field} is not monotonically ordered")]
    NonMonotonic { field: &'static str },
    #[error("the provider payload is malformed")]
    InvalidProviderPayload,
    #[error("the provider payload drifted from the requested scope")]
    ScopeDrift,
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidWhitespace { field });
    }
    Ok(())
}

macro_rules! bounded_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::new(value)
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
                Self::new(value)
            }
        }
    };
}

bounded_id!(AwsAccountId, "AWS account id");
bounded_id!(AwsRegion, "AWS region");
bounded_id!(AwsCodeBuildProjectName, "AWS CodeBuild project name");
bounded_id!(BuildId, "AWS CodeBuild build id");
bounded_id!(SourceRepository, "source repository");
bounded_id!(SourceCommit, "source commit");
bounded_id!(ArtifactId, "artifact id");
bounded_id!(ProjectId, "Hartevo project id");
bounded_id!(MissionId, "Mission id");
bounded_id!(WorkProductId, "Work Product id");

pub type AccountId = AwsAccountId;
pub type Region = AwsRegion;
pub type CodeBuildProjectName = AwsCodeBuildProjectName;
pub type ProjectName = AwsCodeBuildProjectName;
pub type CodeBuildBuildId = BuildId;
pub type SourceId = SourceRepository;
pub type CommitId = SourceCommit;
pub type ArtifactReference = ArtifactId;

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

    pub fn from_bytes(value: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(value)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields<T: AsRef<str>>(namespace: &str, fields: &[T]) -> Self {
        let mut canonical = format!("{namespace}\0");
        for field in fields {
            let value = field.as_ref();
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\0');
        }
        Self::from_text(canonical)
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

pub fn sha256_digest(value: &[u8]) -> Digest {
    Digest::from_bytes(value)
}

pub fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<Digest, ModelError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_digest(&bytes))
        .map_err(|_| ModelError::InvalidValue {
            field: "canonical digest input",
        })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::MustBePositive { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn seconds(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

/// Complete AWS and Mission/Project/Work Product CodeBuild fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsCodeBuildScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub project_name: AwsCodeBuildProjectName,
    pub build_id: BuildId,
    pub source_repository: Option<SourceRepository>,
    pub source_commit: Option<SourceCommit>,
    pub artifact_id: Option<ArtifactId>,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
}

impl AwsCodeBuildScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        project_name: AwsCodeBuildProjectName,
        build_id: BuildId,
        mission_id: MissionId,
        project_id: ProjectId,
        work_product_id: WorkProductId,
    ) -> Self {
        Self {
            account_id,
            region,
            project_name,
            build_id,
            source_repository: None,
            source_commit: None,
            artifact_id: None,
            mission_id,
            mission_revision: Revision(1),
            project_id,
            project_revision: Revision(1),
            work_product_id,
            work_product_revision: Revision(1),
            permission_digest: crate::permission_digest(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_fences(
        account_id: AwsAccountId,
        region: AwsRegion,
        project_name: AwsCodeBuildProjectName,
        build_id: BuildId,
        source_repository: Option<SourceRepository>,
        source_commit: Option<SourceCommit>,
        artifact_id: Option<ArtifactId>,
        mission_id: MissionId,
        mission_revision: Revision,
        project_id: ProjectId,
        project_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            account_id,
            region,
            project_name,
            build_id,
            source_repository,
            source_commit,
            artifact_id,
            mission_id,
            mission_revision,
            project_id,
            project_revision,
            work_product_id,
            work_product_revision,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[must_use]
    pub fn with_source_repository(mut self, value: SourceRepository) -> Self {
        self.source_repository = Some(value);
        self
    }

    #[must_use]
    pub fn with_source(self, value: SourceRepository) -> Self {
        self.with_source_repository(value)
    }

    #[must_use]
    pub fn with_source_commit(mut self, value: SourceCommit) -> Self {
        self.source_commit = Some(value);
        self
    }

    #[must_use]
    pub fn with_commit(self, value: SourceCommit) -> Self {
        self.with_source_commit(value)
    }

    #[must_use]
    pub fn with_artifact_id(mut self, value: ArtifactId) -> Self {
        self.artifact_id = Some(value);
        self
    }

    #[must_use]
    pub fn with_artifact(self, value: ArtifactId) -> Self {
        self.with_artifact_id(value)
    }

    #[must_use]
    pub fn with_revisions(
        mut self,
        mission_revision: Revision,
        project_revision: Revision,
        work_product_revision: Revision,
    ) -> Self {
        self.mission_revision = mission_revision;
        self.project_revision = project_revision;
        self.work_product_revision = work_product_revision;
        self
    }

    #[must_use]
    pub fn with_permission_digest(mut self, value: Digest) -> Self {
        self.permission_digest = value;
        self
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(self.account_id.as_str(), "AWS account id")?;
        validate_text(self.region.as_str(), "AWS region")?;
        validate_text(self.project_name.as_str(), "AWS CodeBuild project name")?;
        validate_text(self.build_id.as_str(), "AWS CodeBuild build id")?;
        if let Some(value) = &self.source_repository {
            validate_text(value.as_str(), "source repository")?;
        }
        if let Some(value) = &self.source_commit {
            validate_text(value.as_str(), "source commit")?;
        }
        if let Some(value) = &self.artifact_id {
            validate_text(value.as_str(), "artifact id")?;
        }
        validate_text(self.mission_id.as_str(), "Mission id")?;
        validate_text(self.project_id.as_str(), "Hartevo project id")?;
        validate_text(self.work_product_id.as_str(), "Work Product id")?;
        Revision::new(self.mission_revision.get())?;
        Revision::new(self.project_revision.get())?;
        Revision::new(self.work_product_revision.get())?;
        Digest::parse(self.permission_digest.as_str())?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("AwsCodeBuildScope is serializable")
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub fn project_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-project-fence/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                self.project_name.as_str().to_owned(),
                self.project_id.as_str().to_owned(),
                self.project_revision.get().to_string(),
            ],
        )
    }

    pub fn build_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-build-fence/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                self.project_name.as_str().to_owned(),
                self.build_id.as_str().to_owned(),
            ],
        )
    }

    pub fn source_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-source-fence/v1",
            &[
                self.source_repository
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.source_commit
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ],
        )
    }

    pub fn artifact_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-artifact-fence/v1",
            &[self
                .artifact_id
                .as_ref()
                .map_or_else(String::new, |value| value.as_str().to_owned())],
        )
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn project_name(&self) -> &AwsCodeBuildProjectName {
        &self.project_name
    }

    pub fn build(&self) -> &BuildId {
        &self.build_id
    }

    pub fn project(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn work_product(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
}

/// Host-owned credential identity. Raw credential material and the caller's
/// reference string are not retained, and this type intentionally does not
/// implement `Serialize` or `Deserialize`.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SigV4SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
}

impl SigV4SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &AwsCodeBuildScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(&reference_id, "SigV4 secret reference")?;
        Self::from_scope_digest(
            Digest::from_fields(
                "hartevo.sigv4-secret-reference-id/v1",
                &[reference_id, scope.digest().as_str().to_owned()],
            ),
            scope.digest(),
            credential_revision,
        )
    }

    pub fn from_scope_digest(
        reference_digest: Digest,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Digest::parse(reference_digest.as_str())?;
        Digest::parse(scope_digest.as_str())?;
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision: Revision::new(credential_revision)?,
        })
    }

    pub fn reference_digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn is_for_scope(&self, scope: &AwsCodeBuildScope) -> bool {
        self.scope_digest == scope.digest()
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SigV4SecretReference({})", self.reference_digest)
    }
}

pub type SecretReference = SigV4SecretReference;
pub type AwsSigV4SecretReference = SigV4SecretReference;
pub type AwsCodeBuildBuildResultScope = AwsCodeBuildScope;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodeBuildStatus {
    Failed,
    Fault,
    InProgress,
    Queued,
    Stopped,
    Succeeded,
    TimedOut,
    Unknown,
}

impl CodeBuildStatus {
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            Some("FAILED") => Self::Failed,
            Some("FAULT") => Self::Fault,
            Some("IN_PROGRESS") => Self::InProgress,
            Some("QUEUED") => Self::Queued,
            Some("STOPPED") => Self::Stopped,
            Some("SUCCEEDED") => Self::Succeeded,
            Some("TIMED_OUT") => Self::TimedOut,
            _ => Self::Unknown,
        }
    }

    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::Fault | Self::Stopped | Self::Succeeded | Self::TimedOut
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "FAILED",
            Self::Fault => "FAULT",
            Self::InProgress => "IN_PROGRESS",
            Self::Queued => "QUEUED",
            Self::Stopped => "STOPPED",
            Self::Succeeded => "SUCCEEDED",
            Self::TimedOut => "TIMED_OUT",
            Self::Unknown => "UNKNOWN",
        }
    }

    pub fn allows_transition_to(self, next: Self) -> bool {
        if self.is_unknown() || next.is_unknown() {
            return false;
        }
        if self.is_terminal() {
            return self == next;
        }
        true
    }
}

impl FromStr for CodeBuildStatus {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(Some(value)))
    }
}

pub type AwsCodeBuildStatus = CodeBuildStatus;
pub type AwsCodeBuildBuildStatus = CodeBuildStatus;
pub type BuildStatus = CodeBuildStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    S3,
    Container,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub kind: ArtifactKind,
    pub metadata_digest: Digest,
    pub content_digest: Option<Digest>,
    pub size_bytes: Option<u64>,
}

impl ArtifactMetadata {
    pub fn new(
        kind: ArtifactKind,
        provider_reference: impl AsRef<str>,
        content_digest: Option<Digest>,
        size_bytes: Option<u64>,
    ) -> Result<Self, ModelError> {
        validate_text(provider_reference.as_ref(), "artifact provider reference")?;
        let metadata_digest = Digest::from_fields(
            "hartevo.aws-codebuild-artifact-metadata/v1",
            &[
                format!("{kind:?}"),
                provider_reference.as_ref().to_owned(),
                content_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                size_bytes.map_or_else(String::new, |value| value.to_string()),
            ],
        );
        let artifact = Self {
            kind,
            metadata_digest,
            content_digest,
            size_bytes,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn from_metadata_digest(
        kind: ArtifactKind,
        metadata_digest: Digest,
        content_digest: Option<Digest>,
        size_bytes: Option<u64>,
    ) -> Result<Self, ModelError> {
        Digest::parse(metadata_digest.as_str())?;
        if let Some(value) = &content_digest {
            Digest::parse(value.as_str())?;
        }
        Ok(Self {
            kind,
            metadata_digest,
            content_digest,
            size_bytes,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Digest::parse(self.metadata_digest.as_str())?;
        if let Some(value) = &self.content_digest {
            Digest::parse(value.as_str())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildBatchMetadata {
    pub batch_id_digest: Digest,
    pub status: CodeBuildStatus,
    pub build_count: u16,
    pub metadata_digest: Digest,
}

impl BuildBatchMetadata {
    pub fn new(
        provider_batch_id: impl AsRef<str>,
        status: CodeBuildStatus,
        build_count: u16,
    ) -> Result<Self, ModelError> {
        validate_text(provider_batch_id.as_ref(), "CodeBuild batch id")?;
        if usize::from(build_count) > MAX_BATCH_METADATA {
            return Err(ModelError::BoundExceeded {
                field: "build batch metadata count",
            });
        }
        let batch_id_digest = Digest::from_fields(
            "hartevo.aws-codebuild-batch-id/v1",
            &[provider_batch_id.as_ref().to_owned()],
        );
        let metadata_digest = Digest::from_fields(
            "hartevo.aws-codebuild-batch-metadata/v1",
            &[
                batch_id_digest.as_str().to_owned(),
                status.as_str().to_owned(),
                build_count.to_string(),
            ],
        );
        Ok(Self {
            batch_id_digest,
            status,
            build_count,
            metadata_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Digest::parse(self.batch_id_digest.as_str())?;
        if usize::from(self.build_count) > MAX_BATCH_METADATA {
            return Err(ModelError::BoundExceeded {
                field: "build batch metadata count",
            });
        }
        let expected = Digest::from_fields(
            "hartevo.aws-codebuild-batch-metadata/v1",
            &[
                self.batch_id_digest.as_str().to_owned(),
                self.status.as_str().to_owned(),
                self.build_count.to_string(),
            ],
        );
        if self.metadata_digest != expected {
            return Err(ModelError::InvalidDigest {
                field: "build batch metadata",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildSummary {
    pub build_id: BuildId,
    pub project_name: AwsCodeBuildProjectName,
    pub source_repository: Option<SourceRepository>,
    pub source_commit: Option<SourceCommit>,
    pub artifact_id: Option<ArtifactId>,
    pub status: CodeBuildStatus,
    pub started_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
    pub duration_seconds: Option<u64>,
    pub artifact_metadata: Vec<ArtifactMetadata>,
    pub batch_metadata: Option<BuildBatchMetadata>,
    pub metadata_digest: Digest,
}

impl BuildSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        build_id: BuildId,
        project_name: AwsCodeBuildProjectName,
        source_repository: Option<SourceRepository>,
        source_commit: Option<SourceCommit>,
        artifact_id: Option<ArtifactId>,
        status: CodeBuildStatus,
        started_at: Option<Timestamp>,
        finished_at: Option<Timestamp>,
        artifact_metadata: Vec<ArtifactMetadata>,
        batch_metadata: Option<BuildBatchMetadata>,
    ) -> Result<Self, ModelError> {
        if artifact_metadata.len() > MAX_ARTIFACTS_PER_BUILD {
            return Err(ModelError::BoundExceeded {
                field: "artifacts per build",
            });
        }
        if let (Some(start), Some(finish)) = (started_at, finished_at)
            && finish.seconds() < start.seconds()
        {
            return Err(ModelError::InvalidTimestamp {
                field: "build finish before start",
            });
        }
        for artifact in &artifact_metadata {
            artifact.validate()?;
        }
        if let Some(value) = &batch_metadata {
            value.validate()?;
        }
        let metadata_digest = Digest::from_fields(
            "hartevo.aws-codebuild-build-metadata/v1",
            &[
                build_id.as_str().to_owned(),
                project_name.as_str().to_owned(),
                source_repository
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                source_commit
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                artifact_id
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                status.as_str().to_owned(),
                started_at.map_or_else(String::new, |value| value.seconds().to_string()),
                finished_at.map_or_else(String::new, |value| value.seconds().to_string()),
                artifact_metadata
                    .iter()
                    .map(|value| value.metadata_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                batch_metadata.as_ref().map_or_else(String::new, |value| {
                    value.metadata_digest.as_str().to_owned()
                }),
            ],
        );
        let build = Self {
            build_id,
            project_name,
            source_repository,
            source_commit,
            artifact_id,
            status,
            started_at,
            finished_at,
            duration_seconds: match (started_at, finished_at) {
                (Some(start), Some(finish)) => Some(finish.seconds() - start.seconds()),
                _ => None,
            },
            artifact_metadata,
            batch_metadata,
            metadata_digest,
        };
        build.validate()?;
        Ok(build)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(self.build_id.as_str(), "AWS CodeBuild build id")?;
        validate_text(self.project_name.as_str(), "AWS CodeBuild project name")?;
        if let Some(value) = &self.source_repository {
            validate_text(value.as_str(), "source repository")?;
        }
        if let Some(value) = &self.source_commit {
            validate_text(value.as_str(), "source commit")?;
        }
        if let Some(value) = &self.artifact_id {
            validate_text(value.as_str(), "artifact id")?;
        }
        if self.artifact_metadata.len() > MAX_ARTIFACTS_PER_BUILD {
            return Err(ModelError::BoundExceeded {
                field: "artifacts per build",
            });
        }
        if let (Some(start), Some(finish)) = (self.started_at, self.finished_at) {
            if finish.seconds() < start.seconds() {
                return Err(ModelError::InvalidTimestamp {
                    field: "build finish before start",
                });
            }
            if self.duration_seconds != Some(finish.seconds() - start.seconds()) {
                return Err(ModelError::InvalidTimestamp {
                    field: "build duration",
                });
            }
        }
        for artifact in &self.artifact_metadata {
            artifact.validate()?;
        }
        if let Some(value) = &self.batch_metadata {
            value.validate()?;
        }
        if self.metadata_digest != self.computed_metadata_digest() {
            return Err(ModelError::InvalidDigest {
                field: "build metadata",
            });
        }
        Ok(())
    }

    fn computed_metadata_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-build-metadata/v1",
            &[
                self.build_id.as_str().to_owned(),
                self.project_name.as_str().to_owned(),
                self.source_repository
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.source_commit
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.artifact_id
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.status.as_str().to_owned(),
                self.started_at
                    .map_or_else(String::new, |value| value.seconds().to_string()),
                self.finished_at
                    .map_or_else(String::new, |value| value.seconds().to_string()),
                self.artifact_metadata
                    .iter()
                    .map(|value| value.metadata_digest.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                self.batch_metadata
                    .as_ref()
                    .map_or_else(String::new, |value| {
                        value.metadata_digest.as_str().to_owned()
                    }),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCodeBuildScope) -> Result<(), ModelError> {
        self.validate()?;
        if self.build_id != scope.build_id || self.project_name != scope.project_name {
            return Err(ModelError::ScopeDrift);
        }
        if scope.source_repository.is_some() && self.source_repository != scope.source_repository {
            return Err(ModelError::ScopeDrift);
        }
        if scope.source_commit.is_some() && self.source_commit != scope.source_commit {
            return Err(ModelError::ScopeDrift);
        }
        if scope.artifact_id.is_some() && self.artifact_id != scope.artifact_id {
            return Err(ModelError::ScopeDrift);
        }
        Ok(())
    }

    pub fn artifact_metadata_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-artifacts/v1",
            &self
                .artifact_metadata
                .iter()
                .map(|value| value.metadata_digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectSummary {
    pub project_name: AwsCodeBuildProjectName,
    pub source_repository: Option<SourceRepository>,
    pub source_commit: Option<SourceCommit>,
    pub artifact_metadata_digest: Option<Digest>,
    pub batch_metadata_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

impl ProjectSummary {
    pub fn new(
        project_name: AwsCodeBuildProjectName,
        source_repository: Option<SourceRepository>,
        source_commit: Option<SourceCommit>,
        artifact_metadata_digest: Option<Digest>,
        batch_metadata_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if let Some(value) = &artifact_metadata_digest {
            Digest::parse(value.as_str())?;
        }
        if let Some(value) = &batch_metadata_digest {
            Digest::parse(value.as_str())?;
        }
        let metadata_digest = Digest::from_fields(
            "hartevo.aws-codebuild-project-metadata/v1",
            &[
                project_name.as_str().to_owned(),
                source_repository
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                source_commit
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                artifact_metadata_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                batch_metadata_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ],
        );
        let project = Self {
            project_name,
            source_repository,
            source_commit,
            artifact_metadata_digest,
            batch_metadata_digest,
            metadata_digest,
        };
        project.validate()?;
        Ok(project)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(self.project_name.as_str(), "AWS CodeBuild project name")?;
        if let Some(value) = &self.source_repository {
            validate_text(value.as_str(), "source repository")?;
        }
        if let Some(value) = &self.source_commit {
            validate_text(value.as_str(), "source commit")?;
        }
        if let Some(value) = &self.artifact_metadata_digest {
            Digest::parse(value.as_str())?;
        }
        if let Some(value) = &self.batch_metadata_digest {
            Digest::parse(value.as_str())?;
        }
        if self.metadata_digest != self.computed_metadata_digest() {
            return Err(ModelError::InvalidDigest {
                field: "project metadata",
            });
        }
        Ok(())
    }

    fn computed_metadata_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-codebuild-project-metadata/v1",
            &[
                self.project_name.as_str().to_owned(),
                self.source_repository
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.source_commit
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.artifact_metadata_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.batch_metadata_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_against(&self, scope: &AwsCodeBuildScope) -> Result<(), ModelError> {
        self.validate()?;
        if self.project_name != scope.project_name {
            return Err(ModelError::ScopeDrift);
        }
        if scope.source_repository.is_some() && self.source_repository != scope.source_repository {
            return Err(ModelError::ScopeDrift);
        }
        if scope.source_commit.is_some() && self.source_commit != scope.source_commit {
            return Err(ModelError::ScopeDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLost,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLossKind {
    BlockedEnv,
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    ProviderUnavailable,
    Timeout,
    MalformedResponse,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessLossEvidence {
    pub kind: AccessLossKind,
    pub provider_code: String,
    pub operation: String,
    pub page_number: u16,
    pub diagnostic_digest: Digest,
}

impl AccessLossEvidence {
    pub fn new(
        kind: AccessLossKind,
        provider_code: impl Into<String>,
        operation: impl Into<String>,
        page_number: u16,
    ) -> Result<Self, ModelError> {
        let provider_code = provider_code.into();
        let operation = operation.into();
        validate_text(&provider_code, "provider access-loss code")?;
        validate_text(&operation, "provider operation")?;
        Ok(Self {
            diagnostic_digest: Digest::from_fields(
                "hartevo.aws-codebuild-access-loss/v1",
                &[
                    provider_code.clone(),
                    operation.clone(),
                    page_number.to_string(),
                ],
            ),
            kind,
            provider_code,
            operation,
            page_number,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(&self.provider_code, "provider access-loss code")?;
        validate_text(&self.operation, "provider operation")?;
        Digest::parse(self.diagnostic_digest.as_str())?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageLimitReached,
    BuildLimitReached,
    UnknownStatus,
    MissingTargetBuild,
    MissingProject,
    ProviderMarkedPartial,
    OptionalBatchMetadataTruncated,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub raw_provider_payload: bool,
    pub raw_requests: bool,
    pub raw_responses: bool,
    pub raw_command_arguments: bool,
    pub raw_environment: bool,
    pub raw_secrets: bool,
    pub raw_logs: bool,
    pub raw_source_bytes: bool,
    pub raw_artifact_bytes: bool,
    pub durable_native_receipt: bool,
    pub independent_artifact_readback: bool,
    pub native: bool,
    pub connected: bool,
}

impl RedactionSummary {
    pub const fn layer1() -> Self {
        Self {
            raw_provider_payload: false,
            raw_requests: false,
            raw_responses: false,
            raw_command_arguments: false,
            raw_environment: false,
            raw_secrets: false,
            raw_logs: false,
            raw_source_bytes: false,
            raw_artifact_bytes: false,
            durable_native_receipt: false,
            independent_artifact_readback: false,
            native: false,
            connected: false,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.raw_provider_payload
            || self.raw_requests
            || self.raw_responses
            || self.raw_command_arguments
            || self.raw_environment
            || self.raw_secrets
            || self.raw_logs
            || self.raw_source_bytes
            || self.raw_artifact_bytes
            || self.durable_native_receipt
            || self.independent_artifact_readback
            || self.native
            || self.connected
        {
            return Err(ModelError::InvalidValue {
                field: "Layer-1 redaction or authority boundary",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub build_digest: Digest,
    pub source_digest: Digest,
    pub artifact_digest: Digest,
    pub evidence_schema_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn validate(&self) -> Result<(), ModelError> {
        for digest in [
            &self.version_digest,
            &self.contract_digest,
            &self.provider_digest,
            &self.api_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.project_digest,
            &self.build_digest,
            &self.source_digest,
            &self.artifact_digest,
            &self.evidence_schema_digest,
            &self.registration_digest,
            &self.evidence_digest,
        ] {
            Digest::parse(digest.as_str())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeBuildEvidencePage {
    pub operation: String,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub page_number: u16,
    pub page_token_digest: Option<Digest>,
}

impl CodeBuildEvidencePage {
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_text(&self.operation, "evidence operation")?;
        Digest::parse(self.request_digest.as_str())?;
        Digest::parse(self.response_digest.as_str())?;
        if let Some(value) = &self.page_token_digest {
            Digest::parse(value.as_str())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeBuildEvidence {
    pub provider_revision: String,
    pub digests: EvidenceDigests,
    pub request_digest: Digest,
    pub pages: Vec<CodeBuildEvidencePage>,
    pub builds: Vec<BuildSummary>,
    pub projects: Vec<ProjectSummary>,
    pub provenance: ProviderProvenance,
    pub status: EvidenceStatus,
    pub partial_reason: Option<PartialReason>,
    pub access_loss: Option<AccessLossEvidence>,
    pub redaction: RedactionSummary,
}

pub type AwsCodeBuildBuildResultEvidence = CodeBuildEvidence;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestInput<'a> {
    provider_revision: &'a str,
    version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    project_digest: &'a Digest,
    build_digest: &'a Digest,
    source_digest: &'a Digest,
    artifact_digest: &'a Digest,
    evidence_schema_digest: &'a Digest,
    registration_digest: &'a Digest,
    request_digest: &'a Digest,
    pages: &'a [CodeBuildEvidencePage],
    builds: &'a [BuildSummary],
    projects: &'a [ProjectSummary],
    provenance: ProviderProvenance,
    status: EvidenceStatus,
    partial_reason: Option<PartialReason>,
    access_loss: &'a Option<AccessLossEvidence>,
    redaction: &'a RedactionSummary,
}

impl CodeBuildEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsCodeBuildScope,
        provider_revision: impl Into<String>,
        provider_digest: Digest,
        registration_digest: Digest,
        request_digest: Digest,
        pages: Vec<CodeBuildEvidencePage>,
        builds: Vec<BuildSummary>,
        projects: Vec<ProjectSummary>,
        provenance: ProviderProvenance,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        access_loss: Option<AccessLossEvidence>,
    ) -> Result<Self, ModelError> {
        scope.validate()?;
        let provider_revision = provider_revision.into();
        validate_text(&provider_revision, "provider revision")?;
        if pages.is_empty() || pages.len() > usize::from(MAX_PAGES) + 2 {
            return Err(ModelError::BoundExceeded {
                field: "evidence pages",
            });
        }
        if builds.len() > MAX_BUILDS {
            return Err(ModelError::BoundExceeded {
                field: "evidence builds",
            });
        }
        if projects.len() > MAX_PROJECTS {
            return Err(ModelError::BoundExceeded {
                field: "evidence projects",
            });
        }
        for page in &pages {
            page.validate()?;
        }
        for build in &builds {
            build.validate()?;
        }
        for project in &projects {
            project.validate()?;
        }
        if let Some(loss) = &access_loss {
            loss.validate()?;
        }
        let redaction = RedactionSummary::layer1();
        redaction.validate()?;
        let mut evidence = Self {
            provider_revision,
            digests: EvidenceDigests {
                version_digest: crate::version_digest(),
                contract_digest: crate::contract_digest(),
                provider_digest,
                api_digest: crate::api_digest(),
                permission_digest: scope.permission_digest.clone(),
                scope_digest: scope.digest(),
                project_digest: scope.project_digest(),
                build_digest: scope.build_digest(),
                source_digest: scope.source_digest(),
                artifact_digest: scope.artifact_digest(),
                evidence_schema_digest: crate::evidence_schema_digest(),
                registration_digest,
                evidence_digest: Digest::from_text("pending-codebuild-evidence-digest"),
            },
            request_digest,
            pages,
            builds,
            projects,
            provenance,
            status,
            partial_reason,
            access_loss,
            redaction,
        };
        evidence.digests.evidence_digest = evidence.compute_digest()?;
        evidence.validate_for(scope)?;
        Ok(evidence)
    }

    fn digest_input(&self) -> EvidenceDigestInput<'_> {
        EvidenceDigestInput {
            provider_revision: &self.provider_revision,
            version_digest: &self.digests.version_digest,
            contract_digest: &self.digests.contract_digest,
            provider_digest: &self.digests.provider_digest,
            api_digest: &self.digests.api_digest,
            permission_digest: &self.digests.permission_digest,
            scope_digest: &self.digests.scope_digest,
            project_digest: &self.digests.project_digest,
            build_digest: &self.digests.build_digest,
            source_digest: &self.digests.source_digest,
            artifact_digest: &self.digests.artifact_digest,
            evidence_schema_digest: &self.digests.evidence_schema_digest,
            registration_digest: &self.digests.registration_digest,
            request_digest: &self.request_digest,
            pages: &self.pages,
            builds: &self.builds,
            projects: &self.projects,
            provenance: self.provenance,
            status: self.status,
            partial_reason: self.partial_reason,
            access_loss: &self.access_loss,
            redaction: &self.redaction,
        }
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&self.digest_input())
    }

    pub fn validate_for(&self, scope: &AwsCodeBuildScope) -> Result<(), ModelError> {
        scope.validate()?;
        self.validate_integrity()?;
        if self.digests.permission_digest != *scope.permission_digest()
            || self.digests.scope_digest != scope.digest()
            || self.digests.project_digest != scope.project_digest()
            || self.digests.build_digest != scope.build_digest()
            || self.digests.source_digest != scope.source_digest()
            || self.digests.artifact_digest != scope.artifact_digest()
        {
            return Err(ModelError::ScopeDrift);
        }
        Ok(())
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        validate_text(&self.provider_revision, "provider revision")?;
        self.digests.validate()?;
        Digest::parse(self.request_digest.as_str())?;
        if self.pages.is_empty() || self.pages.len() > usize::from(MAX_PAGES) + 2 {
            return Err(ModelError::BoundExceeded {
                field: "evidence pages",
            });
        }
        if self.builds.len() > MAX_BUILDS || self.projects.len() > MAX_PROJECTS {
            return Err(ModelError::BoundExceeded {
                field: "evidence result count",
            });
        }
        if self.digests.version_digest != crate::version_digest()
            || self.digests.contract_digest != crate::contract_digest()
            || self.digests.api_digest != crate::api_digest()
            || self.digests.evidence_schema_digest != crate::evidence_schema_digest()
        {
            return Err(ModelError::InvalidDigest {
                field: "version, contract, api, or evidence-schema digest",
            });
        }
        for page in &self.pages {
            page.validate()?;
        }
        for build in &self.builds {
            build.validate()?;
        }
        for project in &self.projects {
            project.validate()?;
        }
        if let Some(loss) = &self.access_loss {
            loss.validate()?;
        }
        self.redaction.validate()?;
        if self.status == EvidenceStatus::Complete
            && (self.partial_reason.is_some() || self.access_loss.is_some())
        {
            return Err(ModelError::InvalidValue {
                field: "complete evidence status",
            });
        }
        if self.status == EvidenceStatus::AccessLost && self.access_loss.is_none() {
            return Err(ModelError::InvalidValue {
                field: "access-lost evidence status",
            });
        }
        if self.digests.evidence_digest != self.compute_digest()? {
            return Err(ModelError::InvalidDigest {
                field: "evidence digest",
            });
        }
        Ok(())
    }

    pub fn digests(&self) -> &EvidenceDigests {
        &self.digests
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    pub fn is_complete(&self) -> bool {
        self.status == EvidenceStatus::Complete && self.access_loss.is_none()
    }

    pub fn is_native(&self) -> bool {
        false
    }

    pub fn is_connected(&self) -> bool {
        false
    }
}

pub fn permission_digest_from_names() -> Digest {
    Digest::from_fields(
        "hartevo.aws-codebuild-permissions/v1",
        &AWS_CODEBUILD_IAM_PERMISSIONS.map(str::to_owned),
    )
}

pub fn plugin_version_text() -> &'static str {
    AWS_CODEBUILD_PLUGIN_VERSION
}
