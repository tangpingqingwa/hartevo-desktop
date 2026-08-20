//! Typed, bounded Jenkins build-result models.
//!
//! The provider may inspect fixture JSON internally, but only the normalized
//! projections in this module cross the provider boundary.  No model retains
//! console text, raw artifacts, source, scripts, credentials, or a raw
//! response body.

use std::{collections::BTreeSet, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use url::Url;
use zeroize::Zeroize;

use crate::{
    JENKINS_BUILD_RESULT_CONTRACT_VERSION, JENKINS_BUILD_RESULT_PLUGIN_VERSION,
    JENKINS_BUILD_RESULT_SCHEMA_VERSION, JENKINS_PROVIDER_REVISION,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_FOLDER_DEPTH: usize = 16;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_OPERATIONS: usize = 8;
pub const MAX_JOBS: usize = 256;
pub const MAX_ARTIFACTS: usize = 128;
pub const MAX_REQUESTS_PER_MINUTE: u8 = 60;
pub const MAX_CURSOR_BYTES: usize = 256;
pub const MAX_CURSOR_PAGE: u16 = 16;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_TEST_COUNT: u32 = 1_000_000;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum JenkinsModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid commit identifier")]
    InvalidCommit { field: &'static str },
    #[error("the Jenkins controller origin is invalid")]
    InvalidController,
    #[error("the Jenkins scope is inconsistent")]
    ScopeMismatch,
    #[error("{field} exceeded its maximum bound of {maximum}")]
    BoundExceeded { field: &'static str, maximum: usize },
    #[error("serialization failed: {0}")]
    Serialization(String),
}

fn validate_text(
    value: &str,
    field: &'static str,
    allow_internal_whitespace: bool,
) -> Result<(), JenkinsModelError> {
    if value.is_empty() {
        return Err(JenkinsModelError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(JenkinsModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(JenkinsModelError::ControlCharacter { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(JenkinsModelError::Invalid { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), JenkinsModelError> {
    if value == 0 {
        Err(JenkinsModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $allow_internal_whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, JenkinsModelError> {
                let value = value.into();
                validate_text(&value, $field, $allow_internal_whitespace)?;
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
            type Err = JenkinsModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

/// Lowercase SHA-256 digest used for every cross-boundary fence.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    #[must_use]
    pub fn from_fields<I, S>(fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hasher = Sha256::new();
        for field in fields {
            let value = field.as_ref();
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
        Self(format!("{:x}", hasher.finalize()))
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, JenkinsModelError> {
        let value = value.into();
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
        {
            return Err(JenkinsModelError::InvalidDigest { field: "digest" });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn zero() -> Self {
        Self("0".repeat(64))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), JenkinsModelError> {
        Self::parse(self.0.clone()).map(|_| ())
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

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest::from_bytes(bytes)
}

pub fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<Digest, JenkinsModelError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| JenkinsModelError::Serialization(error.to_string()))?;
    Ok(sha256_digest(&bytes))
}

bounded_identifier!(ProjectId, "Project id", false);
bounded_identifier!(MissionId, "Mission id", false);
bounded_identifier!(WorkProductId, "Work Product id", false);
bounded_identifier!(JenkinsJobName, "Jenkins job name", true);
bounded_identifier!(JenkinsBranchName, "Jenkins branch name", true);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: u64,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, JenkinsModelError> {
        validate_positive(revision, "Project revision")?;
        Ok(Self {
            id: ProjectId::new(id)?,
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields([self.id.as_str(), &self.revision.to_string()])
    }

    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: u64,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, JenkinsModelError> {
        validate_positive(revision, "Mission revision")?;
        Ok(Self {
            id: MissionId::new(id)?,
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields([self.id.as_str(), &self.revision.to_string()])
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: u64,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, JenkinsModelError> {
        validate_positive(revision, "Work Product revision")?;
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields([self.id.as_str(), &self.revision.to_string()])
    }

    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JenkinsController {
    origin: String,
}

impl JenkinsController {
    pub fn new(value: impl Into<String>) -> Result<Self, JenkinsModelError> {
        let value = value.into();
        validate_text(&value, "controller URL", false)?;
        let parsed = Url::parse(&value).map_err(|_| JenkinsModelError::InvalidController)?;
        let allowed_scheme = parsed.scheme() == "https"
            || (parsed.scheme() == "http"
                && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1")));
        if !allowed_scheme
            || parsed.host_str().is_none()
            || (!parsed.path().is_empty() && parsed.path() != "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(JenkinsModelError::InvalidController);
        }
        Ok(Self {
            origin: value.trim_end_matches('/').to_owned(),
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.origin())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JenkinsFolderPath {
    segments: Vec<String>,
}

impl JenkinsFolderPath {
    pub fn new<I, S>(segments: I) -> Result<Self, JenkinsModelError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let segments = segments.into_iter().map(Into::into).collect::<Vec<_>>();
        if segments.len() > MAX_FOLDER_DEPTH {
            return Err(JenkinsModelError::BoundExceeded {
                field: "folder depth",
                maximum: MAX_FOLDER_DEPTH,
            });
        }
        for segment in &segments {
            validate_text(segment, "folder segment", true)?;
            if segment.contains('/') || segment.contains('\\') {
                return Err(JenkinsModelError::Invalid {
                    field: "folder segment",
                });
            }
        }
        Ok(Self { segments })
    }

    #[must_use]
    pub fn empty() -> Self {
        Self { segments: vec![] }
    }

    pub fn segments(&self) -> &[String] {
        &self.segments
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_fields(self.segments.iter().map(String::as_str))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct JenkinsBuildNumber(u64);

impl JenkinsBuildNumber {
    pub fn new(value: u64) -> Result<Self, JenkinsModelError> {
        validate_positive(value, "build number")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn new(value: impl Into<String>) -> Result<Self, JenkinsModelError> {
        let value = value.into().to_ascii_lowercase();
        if !(7..=64).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(JenkinsModelError::InvalidCommit {
                field: "commit SHA",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CommitSha").field(&self.0).finish()
    }
}

/// An opaque host-owned credential reference. The supplied handle is hashed
/// and zeroized immediately; this type intentionally has no `Serialize`
/// implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: u64,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiToken,
}

impl SecretKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiToken => "api_token",
        }
    }
}

impl SecretReference {
    pub fn new(opaque_handle: impl Into<String>, revision: u64) -> Result<Self, JenkinsModelError> {
        let mut handle = opaque_handle.into();
        if handle.is_empty()
            || handle.len() > MAX_IDENTIFIER_BYTES
            || handle.chars().any(char::is_control)
            || revision == 0
        {
            handle.zeroize();
            return Err(JenkinsModelError::Invalid {
                field: "opaque secret reference",
            });
        }
        let reference_digest = Digest::from_fields([
            "jenkins-opaque-secret-reference/v1",
            SecretKind::ApiToken.as_str(),
            handle.as_str(),
            &revision.to_string(),
        ]);
        handle.zeroize();
        Ok(Self {
            kind: SecretKind::ApiToken,
            reference_digest,
            scope_digest: Digest::zero(),
            revision,
            revoked: false,
        })
    }

    pub fn for_scope(
        opaque_handle: impl Into<String>,
        scope: &JenkinsBuildResultScope,
        revision: u64,
    ) -> Result<Self, JenkinsModelError> {
        let mut reference = Self::new(opaque_handle, revision)?;
        reference.scope_digest = scope.digest().clone();
        reference.reference_digest = Digest::from_fields([
            "jenkins-opaque-secret-reference/v1",
            reference.reference_digest.as_str(),
            reference.scope_digest.as_str(),
            &revision.to_string(),
        ]);
        Ok(reference)
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_opaque(&self) -> bool {
        true
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), JenkinsModelError> {
        if self.revoked {
            return Err(JenkinsModelError::Invalid {
                field: "secret reference state",
            });
        }
        self.revoked = true;
        Ok(())
    }

    pub(crate) fn validate_for_scope(
        &self,
        scope: &JenkinsBuildResultScope,
    ) -> Result<(), JenkinsModelError> {
        if self.revoked || self.revision == 0 || self.scope_digest != *scope.digest() {
            return Err(JenkinsModelError::ScopeMismatch);
        }
        self.reference_digest.validate()
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JenkinsBuildResultStatus {
    Queued,
    Running,
    Success,
    Unstable,
    Failure,
    Aborted,
    NotBuilt,
    Partial,
    Expired,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl JenkinsBuildResultStatus {
    pub const ALL: [Self; 13] = [
        Self::Queued,
        Self::Running,
        Self::Success,
        Self::Unstable,
        Self::Failure,
        Self::Aborted,
        Self::NotBuilt,
        Self::Partial,
        Self::Expired,
        Self::AccessLost,
        Self::ProviderUnknown,
        Self::Tampered,
        Self::Revoked,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Running => "RUNNING",
            Self::Success => "SUCCESS",
            Self::Unstable => "UNSTABLE",
            Self::Failure => "FAILURE",
            Self::Aborted => "ABORTED",
            Self::NotBuilt => "NOT_BUILT",
            Self::Partial => "PARTIAL",
            Self::Expired => "EXPIRED",
            Self::AccessLost => "ACCESS_LOST",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
            Self::Tampered => "TAMPERED",
            Self::Revoked => "REVOKED",
        }
    }

    #[must_use]
    pub fn from_wire(result: Option<&str>, building: bool, queued: bool) -> Self {
        if queued {
            return Self::Queued;
        }
        if building {
            return Self::Running;
        }
        match result.map(str::to_ascii_uppercase).as_deref() {
            Some("SUCCESS") => Self::Success,
            Some("UNSTABLE") => Self::Unstable,
            Some("FAILURE") => Self::Failure,
            Some("ABORTED") => Self::Aborted,
            Some("NOT_BUILT") => Self::NotBuilt,
            Some(_) | None => Self::ProviderUnknown,
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Success
                | Self::Unstable
                | Self::Failure
                | Self::Aborted
                | Self::NotBuilt
                | Self::Expired
                | Self::AccessLost
                | Self::ProviderUnknown
                | Self::Tampered
                | Self::Revoked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JenkinsPermission {
    ControllerRead,
    FolderRead,
    JobRead,
    BranchRead,
    BuildRead,
    CommitRead,
    TestSummaryRead,
    ArtifactMetadataRead,
}

impl JenkinsPermission {
    pub const ALL: [Self; 8] = [
        Self::ControllerRead,
        Self::FolderRead,
        Self::JobRead,
        Self::BranchRead,
        Self::BuildRead,
        Self::CommitRead,
        Self::TestSummaryRead,
        Self::ArtifactMetadataRead,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControllerRead => "jenkins.controller.read",
            Self::FolderRead => "jenkins.folder.read",
            Self::JobRead => "jenkins.job.read",
            Self::BranchRead => "jenkins.branch.read",
            Self::BuildRead => "jenkins.build.read",
            Self::CommitRead => "jenkins.commit.read",
            Self::TestSummaryRead => "jenkins.test-summary.read",
            Self::ArtifactMetadataRead => "jenkins.artifact-metadata.read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsPermissionSnapshot {
    pub revision: u64,
    pub permissions: BTreeSet<JenkinsPermission>,
    pub digest: Digest,
}

impl JenkinsPermissionSnapshot {
    pub fn for_layer_one(revision: u64) -> Result<Self, JenkinsModelError> {
        Self::new(revision, JenkinsPermission::ALL)
    }

    pub fn new<I>(revision: u64, permissions: I) -> Result<Self, JenkinsModelError>
    where
        I: IntoIterator<Item = JenkinsPermission>,
    {
        if revision == 0 {
            return Err(JenkinsModelError::MustBePositive {
                field: "permission revision",
            });
        }
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let digest = permission_snapshot_digest(revision, &permissions);
        let snapshot = Self {
            revision,
            permissions,
            digest,
        };
        snapshot.validate_exact()?;
        Ok(snapshot)
    }

    pub fn validate_exact(&self) -> Result<(), JenkinsModelError> {
        let expected = JenkinsPermission::ALL.into_iter().collect::<BTreeSet<_>>();
        if self.revision == 0
            || self.permissions != expected
            || self.digest != permission_snapshot_digest(self.revision, &self.permissions)
        {
            return Err(JenkinsModelError::Invalid {
                field: "permission snapshot",
            });
        }
        Ok(())
    }

    pub fn allows(&self, permission: JenkinsPermission) -> bool {
        self.permissions.contains(&permission)
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

fn permission_snapshot_digest(revision: u64, permissions: &BTreeSet<JenkinsPermission>) -> Digest {
    let mut fields = Vec::with_capacity(permissions.len() + 1);
    fields.push(revision.to_string());
    fields.extend(
        permissions
            .iter()
            .map(|permission| permission.as_str().to_owned()),
    );
    Digest::from_fields(fields)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

impl RegistrationState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

/// Cursor value whose provider token is never retained; only its scoped
/// digest and page number are serializable.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JenkinsCursor {
    cursor_digest: Digest,
    scope_digest: Digest,
    page_number: u16,
}

impl JenkinsCursor {
    pub fn new(
        opaque_cursor: impl Into<String>,
        scope: &JenkinsBuildResultScope,
        page_number: u16,
    ) -> Result<Self, JenkinsModelError> {
        let mut opaque_cursor = opaque_cursor.into();
        if opaque_cursor.is_empty()
            || opaque_cursor.len() > MAX_CURSOR_BYTES
            || opaque_cursor.chars().any(char::is_control)
            || !(1..=MAX_CURSOR_PAGE).contains(&page_number)
        {
            opaque_cursor.zeroize();
            return Err(JenkinsModelError::Invalid { field: "cursor" });
        }
        let cursor_digest = Digest::from_fields([
            "jenkins-opaque-cursor/v1",
            opaque_cursor.as_str(),
            scope.digest().as_str(),
            &page_number.to_string(),
        ]);
        opaque_cursor.zeroize();
        Ok(Self {
            cursor_digest,
            scope_digest: scope.digest().clone(),
            page_number,
        })
    }

    pub fn cursor_digest(&self) -> &Digest {
        &self.cursor_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub(crate) fn validate(
        &self,
        scope: &JenkinsBuildResultScope,
    ) -> Result<(), JenkinsModelError> {
        if self.scope_digest != *scope.digest()
            || !(1..=MAX_CURSOR_PAGE).contains(&self.page_number)
        {
            return Err(JenkinsModelError::ScopeMismatch);
        }
        self.cursor_digest.validate()
    }
}

impl fmt::Debug for JenkinsCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JenkinsCursor")
            .field("cursor_digest", &self.cursor_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

pub type OpaqueCursor = JenkinsCursor;
pub type Cursor = JenkinsCursor;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JenkinsBuildResultScopeInput {
    pub controller_url: String,
    pub folder_path: Vec<String>,
    pub job_name: String,
    pub build_number: u64,
    pub branch_name: Option<String>,
    pub commit_sha: Option<String>,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsBuildResultScope {
    controller: JenkinsController,
    folder_path: JenkinsFolderPath,
    job_name: JenkinsJobName,
    build_number: JenkinsBuildNumber,
    branch_name: Option<JenkinsBranchName>,
    commit_sha: Option<CommitSha>,
    project: ProjectBinding,
    mission: MissionBinding,
    work_product: WorkProductBinding,
    scope_digest: Digest,
}

impl JenkinsBuildResultScope {
    pub fn new(input: JenkinsBuildResultScopeInput) -> Result<Self, JenkinsModelError> {
        let controller = JenkinsController::new(input.controller_url)?;
        let folder_path = JenkinsFolderPath::new(input.folder_path)?;
        let job_name = JenkinsJobName::new(input.job_name)?;
        let build_number = JenkinsBuildNumber::new(input.build_number)?;
        let branch_name = input.branch_name.map(JenkinsBranchName::new).transpose()?;
        let commit_sha = input.commit_sha.map(CommitSha::new).transpose()?;
        let project = ProjectBinding::new(input.project_id, input.project_revision)?;
        let mission = MissionBinding::new(input.mission_id, input.mission_revision)?;
        let work_product =
            WorkProductBinding::new(input.work_product_id, input.work_product_revision)?;
        let mut scope = Self {
            controller,
            folder_path,
            job_name,
            build_number,
            branch_name,
            commit_sha,
            project,
            mission,
            work_product,
            scope_digest: Digest::zero(),
        };
        scope.scope_digest = scope.recompute_digest();
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn for_build(
        controller_url: impl Into<String>,
        folder_path: Vec<String>,
        job_name: impl Into<String>,
        build_number: u64,
        branch_name: Option<String>,
        commit_sha: Option<String>,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self, JenkinsModelError> {
        Self::new(JenkinsBuildResultScopeInput {
            controller_url: controller_url.into(),
            folder_path,
            job_name: job_name.into(),
            build_number,
            branch_name,
            commit_sha,
            project_id: project.id.as_str().to_owned(),
            project_revision: project.revision,
            mission_id: mission.id.as_str().to_owned(),
            mission_revision: mission.revision,
            work_product_id: work_product.id.as_str().to_owned(),
            work_product_revision: work_product.revision,
        })
    }

    fn recompute_digest(&self) -> Digest {
        Digest::from_fields([
            self.controller.origin(),
            self.folder_path.digest().as_str(),
            self.job_name.as_str(),
            &self.build_number.get().to_string(),
            self.branch_name
                .as_ref()
                .map_or("", JenkinsBranchName::as_str),
            self.commit_sha.as_ref().map_or("", CommitSha::as_str),
            self.project.digest().as_str(),
            self.mission.digest().as_str(),
            self.work_product.digest().as_str(),
            JENKINS_BUILD_RESULT_CONTRACT_VERSION,
        ])
    }

    pub fn validate(&self) -> Result<(), JenkinsModelError> {
        if self.scope_digest == self.recompute_digest() {
            Ok(())
        } else {
            Err(JenkinsModelError::ScopeMismatch)
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn controller(&self) -> &JenkinsController {
        &self.controller
    }

    pub fn folder_path(&self) -> &JenkinsFolderPath {
        &self.folder_path
    }

    pub fn job_name(&self) -> &JenkinsJobName {
        &self.job_name
    }

    pub const fn build_number(&self) -> JenkinsBuildNumber {
        self.build_number
    }

    pub fn branch_name(&self) -> Option<&JenkinsBranchName> {
        self.branch_name.as_ref()
    }

    pub fn commit_sha(&self) -> Option<&CommitSha> {
        self.commit_sha.as_ref()
    }

    pub fn project(&self) -> &ProjectBinding {
        &self.project
    }

    pub fn mission(&self) -> &MissionBinding {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductBinding {
        &self.work_product
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JenkinsReadOperation {
    ReadController,
    ReadFolder,
    ReadJob,
    ReadBranch,
    ReadBuild,
    ReadCommit,
    ReadTestSummary,
    ReadArtifactMetadata,
}

impl JenkinsReadOperation {
    pub const ALL: [Self; 8] = [
        Self::ReadController,
        Self::ReadFolder,
        Self::ReadJob,
        Self::ReadBuild,
        Self::ReadBranch,
        Self::ReadCommit,
        Self::ReadTestSummary,
        Self::ReadArtifactMetadata,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadController => "read_controller",
            Self::ReadFolder => "read_folder",
            Self::ReadJob => "read_job",
            Self::ReadBranch => "read_branch",
            Self::ReadBuild => "read_build",
            Self::ReadCommit => "read_commit",
            Self::ReadTestSummary => "read_test_summary",
            Self::ReadArtifactMetadata => "read_artifact_metadata",
        }
    }

    pub const fn permission(self) -> JenkinsPermission {
        match self {
            Self::ReadController => JenkinsPermission::ControllerRead,
            Self::ReadFolder => JenkinsPermission::FolderRead,
            Self::ReadJob => JenkinsPermission::JobRead,
            Self::ReadBranch => JenkinsPermission::BranchRead,
            Self::ReadBuild => JenkinsPermission::BuildRead,
            Self::ReadCommit => JenkinsPermission::CommitRead,
            Self::ReadTestSummary => JenkinsPermission::TestSummaryRead,
            Self::ReadArtifactMetadata => JenkinsPermission::ArtifactMetadataRead,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
pub enum JenkinsEndpoint {
    Controller,
    Folder,
    Job,
    Branch,
    Build,
    Commit,
    TestSummary,
    ArtifactMetadata,
}

impl JenkinsEndpoint {
    pub const fn operation(&self) -> JenkinsReadOperation {
        match self {
            Self::Controller => JenkinsReadOperation::ReadController,
            Self::Folder => JenkinsReadOperation::ReadFolder,
            Self::Job => JenkinsReadOperation::ReadJob,
            Self::Branch => JenkinsReadOperation::ReadBranch,
            Self::Build => JenkinsReadOperation::ReadBuild,
            Self::Commit => JenkinsReadOperation::ReadCommit,
            Self::TestSummary => JenkinsReadOperation::ReadTestSummary,
            Self::ArtifactMetadata => JenkinsReadOperation::ReadArtifactMetadata,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsControllerProjection {
    pub version_digest: Option<Digest>,
    pub job_count: u16,
    pub folder_count: u16,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsFolderProjection {
    pub folder_digest: Digest,
    pub job_count: u16,
    pub folder_count: u16,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsJobProjection {
    pub job_digest: Digest,
    pub branch_count: u16,
    pub latest_build_number: Option<JenkinsBuildNumber>,
    pub latest_build_status: Option<JenkinsBuildResultStatus>,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsBranchProjection {
    pub branch_digest: Digest,
    pub latest_build_number: Option<JenkinsBuildNumber>,
    pub latest_build_status: Option<JenkinsBuildResultStatus>,
    pub commit_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsBuildProjection {
    pub build_number: JenkinsBuildNumber,
    pub status: JenkinsBuildResultStatus,
    pub timestamp_millis: Option<i64>,
    pub duration_millis: Option<u64>,
    pub branch_digest: Option<Digest>,
    pub commit_digest: Option<Digest>,
    pub test_summary_digest: Option<Digest>,
    pub artifact_metadata_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsCommitProjection {
    pub commit_digest: Digest,
    pub commit_count: u16,
    pub metadata_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsTestSummary {
    pub passed: u32,
    pub failed: u32,
    pub skipped: u32,
    pub total: u32,
    pub summary_digest: Digest,
}

impl JenkinsTestSummary {
    pub fn new(passed: u32, failed: u32, skipped: u32) -> Result<Self, JenkinsModelError> {
        let total = passed
            .checked_add(failed)
            .and_then(|value| value.checked_add(skipped))
            .ok_or(JenkinsModelError::BoundExceeded {
                field: "test count",
                maximum: MAX_TEST_COUNT as usize,
            })?;
        if total > MAX_TEST_COUNT {
            return Err(JenkinsModelError::BoundExceeded {
                field: "test count",
                maximum: MAX_TEST_COUNT as usize,
            });
        }
        let summary_digest = Digest::from_fields([
            "jenkins-test-summary/v1",
            &passed.to_string(),
            &failed.to_string(),
            &skipped.to_string(),
            &total.to_string(),
        ]);
        Ok(Self {
            passed,
            failed,
            skipped,
            total,
            summary_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsArtifactMetadata {
    pub artifact_count: u16,
    pub total_bytes: u64,
    pub metadata_digest: Digest,
}

impl JenkinsArtifactMetadata {
    pub fn new(
        artifact_count: usize,
        total_bytes: u64,
        metadata_digest: Digest,
    ) -> Result<Self, JenkinsModelError> {
        if artifact_count > MAX_ARTIFACTS {
            return Err(JenkinsModelError::BoundExceeded {
                field: "artifact count",
                maximum: MAX_ARTIFACTS,
            });
        }
        Ok(Self {
            artifact_count: artifact_count as u16,
            total_bytes,
            metadata_digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsReadReceipt {
    pub operation: JenkinsReadOperation,
    pub method: String,
    pub path_digest: Digest,
    pub request_digest: Digest,
    pub response_status: u16,
    pub response_bytes: usize,
    pub response_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub provenance: TransportProvenance,
    pub cursor_digest: Option<Digest>,
    pub redacted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsReadFailure {
    pub operation: JenkinsReadOperation,
    pub code: JenkinsFailureCode,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JenkinsFailureCode {
    BlockedEnv,
    AccessLost,
    RateLimited,
    ProviderUnknown,
    ResponseTooLarge,
    MalformedResponse,
    RequestRejected,
    ResponseTampered,
    CursorMismatch,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsBuildResultEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub source_digest: Digest,
    pub evidence_digest: Digest,
    pub status: JenkinsBuildResultStatus,
    pub provenance: TransportProvenance,
    pub controller: Option<JenkinsControllerProjection>,
    pub folder: Option<JenkinsFolderProjection>,
    pub job: Option<JenkinsJobProjection>,
    pub branch: Option<JenkinsBranchProjection>,
    pub build: Option<JenkinsBuildProjection>,
    pub commit: Option<JenkinsCommitProjection>,
    pub test_summary: Option<JenkinsTestSummary>,
    pub artifact_metadata: Option<JenkinsArtifactMetadata>,
    pub receipts: Vec<JenkinsReadReceipt>,
    pub failures: Vec<JenkinsReadFailure>,
    pub cursor_digest: Option<Digest>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub external_writes: bool,
    pub raw_response_retained: bool,
    pub raw_console_logs_retained: bool,
    pub raw_artifacts_retained: bool,
    pub raw_source_retained: bool,
    pub raw_scripts_retained: bool,
}

impl JenkinsBuildResultEvidence {
    pub fn recompute_digest(&self) -> Result<Digest, JenkinsModelError> {
        let mut without_digest = self.clone();
        without_digest.evidence_digest = Digest::zero();
        digest_serializable(&without_digest)
    }

    pub fn validate_integrity(&self) -> Result<(), JenkinsModelError> {
        let expected_source_digest = Digest::from_fields(
            self.receipts
                .iter()
                .map(|receipt| receipt.response_digest.as_str().to_owned()),
        );
        if self.schema_version != JENKINS_BUILD_RESULT_SCHEMA_VERSION
            || self.contract_version != JENKINS_BUILD_RESULT_CONTRACT_VERSION
            || self.plugin_version != JENKINS_BUILD_RESULT_PLUGIN_VERSION
            || self.scope_digest.validate().is_err()
            || self.registration_digest.validate().is_err()
            || self.provider_digest.validate().is_err()
            || self.permission_digest.validate().is_err()
            || self.source_digest != expected_source_digest
            || self
                .cursor_digest
                .as_ref()
                .is_some_and(|digest| digest.validate().is_err())
            || self.evidence_digest != self.recompute_digest()?
            || !self.read_only
            || !self.proposal_only
            || self.native
            || self.connected
            || self.external_writes
            || self.raw_response_retained
            || self.raw_console_logs_retained
            || self.raw_artifacts_retained
            || self.raw_source_retained
            || self.raw_scripts_retained
            || self.receipts.iter().any(|receipt| {
                receipt.method != "GET"
                    || !receipt.redacted
                    || receipt.response_status != 200
                    || receipt.response_bytes > MAX_RESPONSE_BYTES
                    || receipt.path_digest.validate().is_err()
                    || receipt.request_digest.validate().is_err()
                    || receipt.response_digest.validate().is_err()
                    || receipt.provider_digest != self.provider_digest
                    || receipt.permission_digest != self.permission_digest
                    || receipt.provenance != self.provenance
                    || receipt.cursor_digest != self.cursor_digest
                    || receipt.provenance.is_native()
                    || receipt.provenance.is_connected()
            })
        {
            return Err(JenkinsModelError::Invalid {
                field: "evidence integrity",
            });
        }
        Ok(())
    }
}

pub type JenkinsEvidence = JenkinsBuildResultEvidence;
pub type JenkinsResultStatus = JenkinsBuildResultStatus;
pub type BuildResultStatus = JenkinsBuildResultStatus;

/// Fields used by registration are intentionally separate from the opaque
/// secret itself so registration serialization cannot accidentally serialize
/// credential material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JenkinsRegistrationSnapshot {
    pub state: RegistrationState,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub revision: u64,
    pub registration_digest: Digest,
}

impl JenkinsRegistrationSnapshot {
    pub fn recompute_digest(&self) -> Digest {
        Digest::from_fields([
            self.state.as_str(),
            self.version_digest.as_str(),
            self.contract_digest.as_str(),
            self.provider_digest.as_str(),
            self.permission_digest.as_str(),
            self.scope_digest.as_str(),
            self.evidence_digest.as_str(),
            self.secret_reference_digest.as_str(),
            &self.revision.to_string(),
        ])
    }
}

#[allow(dead_code)]
fn _compile_time_contract_pins() {
    let _ = JENKINS_BUILD_RESULT_PLUGIN_VERSION;
    let _ = JENKINS_PROVIDER_REVISION;
}

// Keep these imports and the helper aliases visible to downstream contract
// validators without making the opaque types serializable.
