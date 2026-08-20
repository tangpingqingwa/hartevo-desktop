use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_ARTIFACT_NAME_BYTES: usize = 256;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_OPAQUE_HEADER_BYTES: usize = 512;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: usize = 8;
pub const MAX_JOBS: usize = 256;
pub const MAX_ARTIFACTS: usize = 256;
pub const MAX_ARTIFACT_SIZE_BYTES: u64 = 1_073_741_824;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("GitHub Actions typed value serializes");
    sha256_digest(&bytes)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_revision(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::InvalidRevision { field })
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() || value.len() > max || value.trim() != value {
        return Err(ModelError::InvalidText { field });
    }
    if value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("{field} must be a bounded SHA-256 or Git object identifier")]
    InvalidCommit { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("GitHub repository owner must match the organization scope")]
    RepositoryOrganizationMismatch,
    #[error("GitHub Actions read permission is required")]
    MissingActionsReadPermission,
    #[error("GitHub Actions permission set contains a write permission")]
    WritePermission,
    #[error("opaque header or pagination token is invalid")]
    InvalidOpaqueValue,
    #[error("run attempt is invalid")]
    InvalidAttempt,
    #[error("artifact size exceeds the Layer-1 bound")]
    ArtifactTooLarge,
    #[error("artifact digest is missing or malformed")]
    InvalidArtifactDigest,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
}

macro_rules! positive_id {
    ($name:ident, $label:literal) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub fn new(value: u64) -> Result<Self, ModelError> {
                validate_revision(value, $label)?;
                Ok(Self(value))
            }

            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }
        }
    };
}

positive_id!(GithubAppInstallationId, "installation id");
positive_id!(GithubWorkflowId, "workflow id");
positive_id!(GithubWorkflowRunId, "workflow run id");
positive_id!(GithubJobId, "job id");

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubRunAttempt(u32);

impl GithubRunAttempt {
    pub fn new(value: u32) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidAttempt)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubOrganization(String);

impl GithubOrganization {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "organization")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubRepositoryName(String);

impl GithubRepositoryName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "repository")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubRepository {
    pub owner: GithubOrganization,
    pub name: GithubRepositoryName,
}

impl GithubRepository {
    pub fn new(owner: GithubOrganization, name: GithubRepositoryName) -> Result<Self, ModelError> {
        Ok(Self { owner, name })
    }

    pub fn from_full_name(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        let (owner, name) = value.split_once('/').ok_or(ModelError::InvalidIdentifier {
            field: "repository",
        })?;
        if name.contains('/') {
            return Err(ModelError::InvalidIdentifier {
                field: "repository",
            });
        }
        Self::new(
            GithubOrganization::new(owner)?,
            GithubRepositoryName::new(name)?,
        )
    }

    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner.as_str(), self.name.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubCommitSha(String);

impl GithubCommitSha {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if !(value.len() == 40 || value.len() == 64)
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ModelError::InvalidCommit {
                field: "commit SHA",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubTimestamp(String);

impl GithubTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "timestamp", MAX_TIMESTAMP_BYTES, false)?;
        if !value.contains('T') || !(value.ends_with('Z') || value.contains('+')) {
            return Err(ModelError::InvalidText { field: "timestamp" });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

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
#[serde(rename_all = "camelCase")]
pub struct ProjectBinding {
    pub id: String,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let id = id.into();
        validate_identifier(&id, "project id")?;
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionBinding {
    pub id: String,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let id = id.into();
        validate_identifier(&id, "mission id")?;
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkProductBinding {
    pub id: String,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let id = id.into();
        validate_identifier(&id, "work product id")?;
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubActionsPermission {
    ActionsRead,
    MetadataRead,
}

impl GithubActionsPermission {
    #[must_use]
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ActionsRead => "actions:read",
            Self::MetadataRead => "metadata:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsPermissions {
    pub permissions: BTreeSet<GithubActionsPermission>,
    pub revision: Revision,
    pub permission_digest: Digest,
}

impl GithubActionsPermissions {
    pub fn new(
        permissions: impl IntoIterator<Item = GithubActionsPermission>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&GithubActionsPermission::ActionsRead) {
            return Err(ModelError::MissingActionsReadPermission);
        }
        let revision = Revision::new(revision)?;
        let permission_digest = canonical_digest(
            &permissions
                .iter()
                .map(|permission| permission.api_name())
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            permissions,
            revision,
            permission_digest,
        })
    }

    pub fn read_only(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                GithubActionsPermission::ActionsRead,
                GithubActionsPermission::MetadataRead,
            ],
            revision,
        )
    }

    #[must_use]
    pub fn contains(&self, permission: GithubActionsPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.permission_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsScopeSpec {
    pub installation_id: GithubAppInstallationId,
    pub organization: GithubOrganization,
    pub repository: GithubRepository,
    pub workflow_id: GithubWorkflowId,
    pub run_id: GithubWorkflowRunId,
    pub job_id: GithubJobId,
    pub attempt: GithubRunAttempt,
    pub commit: GithubCommitSha,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permissions: GithubActionsPermissions,
}

impl GithubActionsScopeSpec {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: GithubAppInstallationId,
        organization: GithubOrganization,
        repository: GithubRepository,
        workflow_id: GithubWorkflowId,
        run_id: GithubWorkflowRunId,
        job_id: GithubJobId,
        attempt: GithubRunAttempt,
        commit: GithubCommitSha,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permissions: GithubActionsPermissions,
    ) -> Self {
        Self {
            installation_id,
            organization,
            repository,
            workflow_id,
            run_id,
            job_id,
            attempt,
            commit,
            project,
            mission,
            work_product,
            permissions,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.repository.owner != self.organization {
            return Err(ModelError::RepositoryOrganizationMismatch);
        }
        if !self
            .permissions
            .contains(GithubActionsPermission::ActionsRead)
        {
            return Err(ModelError::MissingActionsReadPermission);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubActionsScope {
    spec: GithubActionsScopeSpec,
    scope_digest: Digest,
    installation_digest: Digest,
    workflow_digest: Digest,
    run_digest: Digest,
    job_digest: Digest,
    attempt_digest: Digest,
    commit_digest: Digest,
}

impl GithubActionsScope {
    pub fn new(spec: GithubActionsScopeSpec) -> Result<Self, ModelError> {
        spec.validate()?;
        let installation_digest = canonical_digest(&spec.installation_id);
        let workflow_digest = canonical_digest(&spec.workflow_id);
        let run_digest = canonical_digest(&spec.run_id);
        let job_digest = canonical_digest(&spec.job_id);
        let attempt_digest = canonical_digest(&spec.attempt);
        let commit_digest = canonical_digest(&spec.commit);
        let scope_digest = canonical_digest(&spec);
        Ok(Self {
            spec,
            scope_digest,
            installation_digest,
            workflow_digest,
            run_digest,
            job_digest,
            attempt_digest,
            commit_digest,
        })
    }

    #[must_use]
    pub fn spec(&self) -> &GithubActionsScopeSpec {
        &self.spec
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn installation_digest(&self) -> &Digest {
        &self.installation_digest
    }

    #[must_use]
    pub fn workflow_digest(&self) -> &Digest {
        &self.workflow_digest
    }

    #[must_use]
    pub fn run_digest(&self) -> &Digest {
        &self.run_digest
    }

    #[must_use]
    pub fn job_digest(&self) -> &Digest {
        &self.job_digest
    }

    #[must_use]
    pub fn attempt_digest(&self) -> &Digest {
        &self.attempt_digest
    }

    #[must_use]
    pub fn commit_digest(&self) -> &Digest {
        &self.commit_digest
    }

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        self.spec.permissions.digest()
    }

    #[must_use]
    pub fn evidence_binding_digest(&self) -> Digest {
        canonical_digest(&(
            "github-actions-evidence-binding/v1",
            &self.scope_digest,
            self.permission_digest(),
            &self.run_digest,
            &self.job_digest,
            &self.attempt_digest,
            &self.commit_digest,
        ))
    }

    #[must_use]
    pub fn project(&self) -> &ProjectBinding {
        &self.spec.project
    }

    #[must_use]
    pub fn mission(&self) -> &MissionBinding {
        &self.spec.mission
    }

    #[must_use]
    pub fn work_product(&self) -> &WorkProductBinding {
        &self.spec.work_product
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.spec.validate()?;
        if !valid_digest(&self.scope_digest)
            || !valid_digest(self.permission_digest())
            || !valid_digest(&self.evidence_binding_digest())
        {
            return Err(ModelError::InvalidScope("scope digest"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubAuthKind {
    App,
    OAuth,
}

pub type GithubAppAuthKind = GithubAuthKind;

/// Opaque host-keyring reference. It intentionally does not implement
/// `Serialize`, `Deserialize`, or a formatter that exposes the reference id.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: GithubAuthKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
            revoked: self.revoked,
        }
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &GithubActionsScope,
        credential_revision: u64,
        auth_kind: GithubAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_identifier(&reference_id, "secret reference")?;
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest().clone();
        let reference_digest = canonical_digest(&(
            "github-actions-secret-reference/v1",
            &reference_id,
            &scope_digest,
            credential_revision,
            auth_kind,
        ));
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
        })
    }

    pub fn app(
        reference_id: impl Into<String>,
        scope: &GithubActionsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            scope,
            credential_revision,
            GithubAuthKind::App,
        )
    }

    pub fn oauth(
        reference_id: impl Into<String>,
        scope: &GithubActionsScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            reference_id,
            scope,
            credential_revision,
            GithubAuthKind::OAuth,
        )
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    #[must_use]
    pub const fn auth_kind(&self) -> GithubAuthKind {
        self.auth_kind
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
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

#[derive(Serialize)]
pub struct OpaqueEtag {
    #[serde(skip)]
    value: String,
    pub etag_digest: Digest,
}

impl OpaqueEtag {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_OPAQUE_HEADER_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidOpaqueValue);
        }
        let etag_digest = canonical_digest(&("github-actions-etag/v1", &value));
        Ok(Self { value, etag_digest })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.etag_digest
    }
}

impl Clone for OpaqueEtag {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            etag_digest: self.etag_digest.clone(),
        }
    }
}

impl PartialEq for OpaqueEtag {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for OpaqueEtag {}

impl fmt::Debug for OpaqueEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueEtag")
            .field("etag_digest", &self.etag_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Eq, PartialEq)]
pub struct OpaquePageToken {
    value: String,
    page_token_digest: Digest,
}

impl Clone for OpaquePageToken {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            page_token_digest: self.page_token_digest.clone(),
        }
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("page_token_digest", &self.page_token_digest)
            .finish_non_exhaustive()
    }
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_OPAQUE_HEADER_BYTES
            || value.chars().any(char::is_whitespace)
        {
            return Err(ModelError::InvalidOpaqueValue);
        }
        let page_token_digest = canonical_digest(&("github-actions-page-token/v1", &value));
        Ok(Self {
            value,
            page_token_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.page_token_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubWorkflowRunStatus {
    Requested,
    Queued,
    Pending,
    Waiting,
    InProgress,
    Completed,
    Unknown,
}

impl GithubWorkflowRunStatus {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "requested" => Self::Requested,
            "queued" => Self::Queued,
            "pending" => Self::Pending,
            "waiting" => Self::Waiting,
            "in_progress" => Self::InProgress,
            "completed" => Self::Completed,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubJobStatus {
    Queued,
    InProgress,
    Completed,
    Waiting,
    Unknown,
}

impl GithubJobStatus {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "queued" => Self::Queued,
            "in_progress" => Self::InProgress,
            "completed" => Self::Completed,
            "waiting" => Self::Waiting,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubActionsConclusion {
    Success,
    Failure,
    Neutral,
    Cancelled,
    Skipped,
    TimedOut,
    ActionRequired,
    Stale,
    StartupFailure,
    Ineligible,
    Unknown,
}

impl GithubActionsConclusion {
    pub(crate) fn parse(value: Option<&str>) -> Option<Self> {
        Some(match value? {
            "success" => Self::Success,
            "failure" => Self::Failure,
            "neutral" => Self::Neutral,
            "cancelled" => Self::Cancelled,
            "skipped" => Self::Skipped,
            "timed_out" => Self::TimedOut,
            "action_required" => Self::ActionRequired,
            "stale" => Self::Stale,
            "startup_failure" => Self::StartupFailure,
            "ineligible" => Self::Ineligible,
            _ => Self::Unknown,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubWorkflowRunMetadata {
    pub id: GithubWorkflowRunId,
    pub workflow_id: GithubWorkflowId,
    pub attempt: GithubRunAttempt,
    pub status: GithubWorkflowRunStatus,
    pub conclusion: Option<GithubActionsConclusion>,
    pub commit: GithubCommitSha,
    pub created_at: GithubTimestamp,
    pub updated_at: GithubTimestamp,
    pub run_started_at: Option<GithubTimestamp>,
    pub metadata_digest: Digest,
}

impl GithubWorkflowRunMetadata {
    pub(crate) fn with_digest(mut self) -> Self {
        self.metadata_digest = String::new();
        self.metadata_digest = canonical_digest(&self);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubJobMetadata {
    pub id: GithubJobId,
    pub name: String,
    pub status: GithubJobStatus,
    pub conclusion: Option<GithubActionsConclusion>,
    pub started_at: Option<GithubTimestamp>,
    pub completed_at: Option<GithubTimestamp>,
    pub metadata_digest: Digest,
}

impl GithubJobMetadata {
    pub(crate) fn with_digest(mut self) -> Self {
        self.metadata_digest = String::new();
        self.metadata_digest = canonical_digest(&self);
        self
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubArtifactMetadata {
    pub id: u64,
    pub name: String,
    pub size_bytes: u64,
    pub digest: Digest,
    pub expired: bool,
    pub expires_at: Option<GithubTimestamp>,
    pub metadata_digest: Digest,
}

impl GithubArtifactMetadata {
    pub(crate) fn with_digest(mut self) -> Self {
        self.metadata_digest = String::new();
        self.metadata_digest = canonical_digest(&self);
        self
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Layer1Authority {
    pub native: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
    pub green_ci_authority: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubActionsRegistration {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub installation_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub workflow_digest: Digest,
    pub run_digest: Digest,
    pub job_digest: Digest,
    pub attempt_digest: Digest,
    pub commit_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub reversible: bool,
    pub revocable: bool,
    pub native: bool,
    pub connected: bool,
}

impl GithubActionsRegistration {
    #[must_use]
    pub fn bind(
        scope: &GithubActionsScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
        provider_version: impl Into<String>,
    ) -> Self {
        let provider_version = provider_version.into();
        let mut registration = Self {
            plugin_version: crate::GITHUB_ACTIONS_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: crate::GITHUB_ACTIONS_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            service_id: crate::GITHUB_ACTIONS_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::GITHUB_ACTIONS_PROVIDER_ID.to_owned(),
            provider_version: provider_version.clone(),
            api_revision: crate::GITHUB_ACTIONS_API_REVISION.to_owned(),
            api_digest: canonical_digest(&crate::GITHUB_ACTIONS_API_REVISION),
            provider_digest,
            installation_digest: scope.installation_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest().clone(),
            workflow_digest: scope.workflow_digest().clone(),
            run_digest: scope.run_digest().clone(),
            job_digest: scope.job_digest().clone(),
            attempt_digest: scope.attempt_digest().clone(),
            commit_digest: scope.commit_digest().clone(),
            evidence_digest: scope.evidence_binding_digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
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
        let mut value = self.clone();
        value.registration_digest.clear();
        canonical_digest(&value)
    }

    pub fn validate(
        &self,
        scope: &GithubActionsScope,
        secret_reference: &SecretReference,
        provider_digest: &Digest,
        provider_version: &str,
    ) -> Result<(), ModelError> {
        scope.validate()?;
        if self.state != RegistrationState::Active
            || self.plugin_version != crate::GITHUB_ACTIONS_RESULT_PLUGIN_VERSION
            || self.contract_version != crate::GITHUB_ACTIONS_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.service_id != crate::GITHUB_ACTIONS_RESULT_SERVICE_ID
            || self.provider_id != crate::GITHUB_ACTIONS_PROVIDER_ID
            || self.provider_version != provider_version
            || self.api_revision != crate::GITHUB_ACTIONS_API_REVISION
            || self.api_digest != canonical_digest(&crate::GITHUB_ACTIONS_API_REVISION)
            || &self.provider_digest != provider_digest
            || self.installation_digest != *scope.installation_digest()
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != *scope.digest()
            || self.workflow_digest != *scope.workflow_digest()
            || self.run_digest != *scope.run_digest()
            || self.job_digest != *scope.job_digest()
            || self.attempt_digest != *scope.attempt_digest()
            || self.commit_digest != *scope.commit_digest()
            || self.evidence_digest != scope.evidence_binding_digest()
            || self.secret_reference_digest != *secret_reference.reference_digest()
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

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }
}

pub type InstallationId = GithubAppInstallationId;
pub type Organization = GithubOrganization;
pub type RepositoryName = GithubRepositoryName;
pub type WorkflowId = GithubWorkflowId;
pub type WorkflowRunId = GithubWorkflowRunId;
pub type JobId = GithubJobId;
pub type Attempt = GithubRunAttempt;
pub type CommitSha = GithubCommitSha;
