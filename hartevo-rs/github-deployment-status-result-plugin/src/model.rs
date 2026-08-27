use std::{collections::BTreeSet, fmt};

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_REF_BYTES: usize = 256;
pub const MAX_ENVIRONMENT_BYTES: usize = 128;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_URL_BYTES: usize = 2_048;
pub const MAX_OPAQUE_HEADER_BYTES: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_PAGES: usize = 8;
pub const MAX_STATUSES: usize = 256;
pub const MAX_HISTORY_DAYS: i64 = 90;
pub const HISTORY_SECONDS: i64 = MAX_HISTORY_DAYS * 24 * 60 * 60;

pub type Digest = String;

#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> Digest {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn canonical_digest<T: Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed Layer-1 value serializes");
    sha256_digest(&bytes)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty, malformed, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is empty, malformed, or too long")]
    InvalidText { field: &'static str },
    #[error("{field} revision must be non-zero")]
    InvalidRevision { field: &'static str },
    #[error("digest is not a lowercase SHA-256 digest")]
    InvalidDigest,
    #[error("timestamp is not bounded RFC-3339 text")]
    InvalidTimestamp,
    #[error("deployment-status state is not allowlisted")]
    InvalidStatusState,
    #[error("GitHub deployment-status permissions are incomplete")]
    InvalidPermissions,
    #[error("scope is invalid: {0}")]
    InvalidScope(&'static str),
    #[error("URL metadata is invalid")]
    InvalidUrl,
    #[error("opaque metadata is invalid")]
    InvalidOpaqueValue,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
    #[error("registration revision overflowed")]
    RevisionOverflow,
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str, max_bytes: usize) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

fn validate_revision(value: u64, field: &'static str) -> Result<Revision, ModelError> {
    if value == 0 {
        Err(ModelError::InvalidRevision { field })
    } else {
        Ok(Revision(value))
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

fn next_revision(revision: Revision) -> Result<Revision, ModelError> {
    revision
        .0
        .checked_add(1)
        .map(Revision)
        .ok_or(ModelError::RevisionOverflow)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_revision(value, "revision")
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubAppInstallationId(u64);

impl GithubAppInstallationId {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidIdentifier {
                field: "installation id",
            })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn value(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubRepositoryName(String);

impl GithubRepositoryName {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_identifier(&value, "repository name")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubRepository {
    pub owner: GithubOrganization,
    pub name: GithubRepositoryName,
}

impl GithubRepository {
    pub fn new(owner: GithubOrganization, name: GithubRepositoryName) -> Result<Self, ModelError> {
        Ok(Self { owner, name })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubDeploymentId(u64);

impl GithubDeploymentId {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidIdentifier {
                field: "deployment id",
            })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn value(&self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubRef(String);

impl GithubRef {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "ref", MAX_REF_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub type GithubRefName = GithubRef;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubCommitSha(String);

impl GithubCommitSha {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if !(value.len() == 40 || value.len() == 64)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ModelError::InvalidText {
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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubEnvironment(String);

impl GithubEnvironment {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "environment", MAX_ENVIRONMENT_BYTES)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct GithubTimestamp(String);

impl GithubTimestamp {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "timestamp", MAX_TIMESTAMP_BYTES)?;
        DateTime::parse_from_rfc3339(&value).map_err(|_| ModelError::InvalidTimestamp)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn epoch_seconds(&self) -> i64 {
        DateTime::parse_from_rfc3339(&self.0)
            .expect("GithubTimestamp validates RFC-3339 at construction")
            .timestamp()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubDeploymentStatusState {
    Queued,
    Pending,
    InProgress,
    Success,
    Failure,
    Error,
    Inactive,
}

pub type GithubDeploymentState = GithubDeploymentStatusState;

impl GithubDeploymentStatusState {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Error => "error",
            Self::Inactive => "inactive",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubAuthKind {
    App,
    OAuth,
}

pub type GithubAppAuthKind = GithubAuthKind;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubDeploymentStatusPermission {
    DeploymentsRead,
    MetadataRead,
}

impl GithubDeploymentStatusPermission {
    #[must_use]
    pub const fn api_name(&self) -> &'static str {
        match self {
            Self::DeploymentsRead => "deployments:read",
            Self::MetadataRead => "metadata:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusPermissions {
    pub permissions: BTreeSet<GithubDeploymentStatusPermission>,
    pub revision: Revision,
    pub permission_digest: Digest,
}

impl GithubDeploymentStatusPermissions {
    pub fn new(
        permissions: impl IntoIterator<Item = GithubDeploymentStatusPermission>,
        revision: u64,
    ) -> Result<Self, ModelError> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if !permissions.contains(&GithubDeploymentStatusPermission::DeploymentsRead)
            || !permissions.contains(&GithubDeploymentStatusPermission::MetadataRead)
        {
            return Err(ModelError::InvalidPermissions);
        }
        let revision = Revision::new(revision)?;
        let permission_names = permissions
            .iter()
            .map(GithubDeploymentStatusPermission::api_name)
            .collect::<Vec<_>>();
        let permission_digest = canonical_digest(&(
            "github-deployment-status-permissions/v1",
            &permission_names,
            revision,
        ));
        Ok(Self {
            permissions,
            revision,
            permission_digest,
        })
    }

    pub fn read_only(revision: u64) -> Result<Self, ModelError> {
        Self::new(
            [
                GithubDeploymentStatusPermission::DeploymentsRead,
                GithubDeploymentStatusPermission::MetadataRead,
            ],
            revision,
        )
    }

    #[must_use]
    pub fn contains(&self, permission: GithubDeploymentStatusPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.permission_digest
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusScopeSpec {
    pub installation_id: GithubAppInstallationId,
    pub organization: GithubOrganization,
    pub repository: GithubRepository,
    pub deployment_id: GithubDeploymentId,
    pub ref_name: GithubRef,
    pub commit: GithubCommitSha,
    pub environment: GithubEnvironment,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permissions: GithubDeploymentStatusPermissions,
}

impl GithubDeploymentStatusScopeSpec {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        installation_id: GithubAppInstallationId,
        organization: GithubOrganization,
        repository: GithubRepository,
        deployment_id: GithubDeploymentId,
        ref_name: GithubRef,
        commit: GithubCommitSha,
        environment: GithubEnvironment,
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permissions: GithubDeploymentStatusPermissions,
    ) -> Self {
        Self {
            installation_id,
            organization,
            repository,
            deployment_id,
            ref_name,
            commit,
            environment,
            project,
            mission,
            work_product,
            permissions,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.repository.owner != self.organization {
            return Err(ModelError::InvalidScope("repository owner"));
        }
        if !self
            .permissions
            .contains(GithubDeploymentStatusPermission::DeploymentsRead)
            || !self
                .permissions
                .contains(GithubDeploymentStatusPermission::MetadataRead)
        {
            return Err(ModelError::InvalidPermissions);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GithubDeploymentStatusScope {
    spec: GithubDeploymentStatusScopeSpec,
    scope_digest: Digest,
    installation_digest: Digest,
    repository_digest: Digest,
    deployment_digest: Digest,
    ref_digest: Digest,
    commit_digest: Digest,
    environment_digest: Digest,
}

impl GithubDeploymentStatusScope {
    pub fn new(spec: GithubDeploymentStatusScopeSpec) -> Result<Self, ModelError> {
        spec.validate()?;
        let installation_digest = canonical_digest(&spec.installation_id);
        let repository_digest = canonical_digest(&spec.repository);
        let deployment_digest = canonical_digest(&spec.deployment_id);
        let ref_digest = canonical_digest(&spec.ref_name);
        let commit_digest = canonical_digest(&spec.commit);
        let environment_digest = canonical_digest(&spec.environment);
        let scope_digest = canonical_digest(&(
            "github-deployment-status-scope/v1",
            &spec,
            &installation_digest,
            &repository_digest,
            &deployment_digest,
            &ref_digest,
            &commit_digest,
            &environment_digest,
        ));
        Ok(Self {
            spec,
            scope_digest,
            installation_digest,
            repository_digest,
            deployment_digest,
            ref_digest,
            commit_digest,
            environment_digest,
        })
    }

    #[must_use]
    pub fn spec(&self) -> &GithubDeploymentStatusScopeSpec {
        &self.spec
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn installation_id(&self) -> &GithubAppInstallationId {
        &self.spec.installation_id
    }

    #[must_use]
    pub fn organization(&self) -> &GithubOrganization {
        &self.spec.organization
    }

    #[must_use]
    pub fn repository(&self) -> &GithubRepository {
        &self.spec.repository
    }

    #[must_use]
    pub fn deployment_id(&self) -> &GithubDeploymentId {
        &self.spec.deployment_id
    }

    #[must_use]
    pub fn ref_name(&self) -> &GithubRef {
        &self.spec.ref_name
    }

    #[must_use]
    pub fn git_ref(&self) -> &GithubRef {
        self.ref_name()
    }

    #[must_use]
    pub fn commit(&self) -> &GithubCommitSha {
        &self.spec.commit
    }

    #[must_use]
    pub fn environment(&self) -> &GithubEnvironment {
        &self.spec.environment
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

    #[must_use]
    pub fn permission_digest(&self) -> &Digest {
        self.spec.permissions.digest()
    }

    #[must_use]
    pub fn installation_digest(&self) -> &Digest {
        &self.installation_digest
    }

    #[must_use]
    pub fn repository_digest(&self) -> &Digest {
        &self.repository_digest
    }

    #[must_use]
    pub fn deployment_digest(&self) -> &Digest {
        &self.deployment_digest
    }

    #[must_use]
    pub fn ref_digest(&self) -> &Digest {
        &self.ref_digest
    }

    #[must_use]
    pub fn commit_digest(&self) -> &Digest {
        &self.commit_digest
    }

    #[must_use]
    pub fn environment_digest(&self) -> &Digest {
        &self.environment_digest
    }

    #[must_use]
    pub fn evidence_binding_digest(&self) -> Digest {
        canonical_digest(&(
            "github-deployment-status-evidence-binding/v1",
            self.digest(),
            self.deployment_digest(),
            self.ref_digest(),
            self.commit_digest(),
            self.environment_digest(),
            self.permission_digest(),
            &self.spec.project,
            &self.spec.mission,
            &self.spec.work_product,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.spec.validate()?;
        for digest in [
            &self.scope_digest,
            &self.installation_digest,
            &self.repository_digest,
            &self.deployment_digest,
            &self.ref_digest,
            &self.commit_digest,
            &self.environment_digest,
            self.permission_digest(),
        ] {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

/// Opaque host-keyring or OAuth reference. The raw reference id is never
/// serialized, formatted, placed in a request, or retained after hashing.
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
        scope: &GithubDeploymentStatusScope,
        credential_revision: u64,
        auth_kind: GithubAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_identifier(&reference_id, "secret reference")?;
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest().clone();
        let reference_digest = canonical_digest(&(
            "github-deployment-status-secret-reference/v1",
            &reference_id,
            &scope_digest,
            credential_revision,
            &auth_kind,
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
        scope: &GithubDeploymentStatusScope,
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
        scope: &GithubDeploymentStatusScope,
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

#[derive(Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
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
        let etag_digest = canonical_digest(&("github-deployment-status-etag/v1", &value));
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

impl fmt::Debug for OpaqueEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueEtag")
            .field("etag_digest", &self.etag_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaquePageToken {
    #[serde(skip)]
    value: String,
    pub page_token_digest: Digest,
    #[serde(skip)]
    scope_digest: Option<Digest>,
    #[serde(skip)]
    request_digest: Option<Digest>,
}

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        Self::with_binding(value, None, None)
    }

    pub fn for_request(
        value: impl Into<String>,
        scope_digest: &str,
        request_digest: &str,
    ) -> Result<Self, ModelError> {
        validate_digest(scope_digest)?;
        validate_digest(request_digest)?;
        Self::with_binding(
            value,
            Some(scope_digest.to_owned()),
            Some(request_digest.to_owned()),
        )
    }

    fn with_binding(
        value: impl Into<String>,
        scope_digest: Option<Digest>,
        request_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_OPAQUE_HEADER_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ModelError::InvalidOpaqueValue);
        }
        let page_token_digest = canonical_digest(&(
            "github-deployment-status-page-token/v1",
            &value,
            &scope_digest,
            &request_digest,
        ));
        Ok(Self {
            value,
            page_token_digest,
            scope_digest,
            request_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.page_token_digest
    }

    pub(crate) fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
    }

    pub(crate) fn request_digest(&self) -> Option<&Digest> {
        self.request_digest.as_ref()
    }
}

impl Clone for OpaquePageToken {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            page_token_digest: self.page_token_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            request_digest: self.request_digest.clone(),
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

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubUrlDigests {
    pub deployment_url_digest: Option<Digest>,
    pub statuses_url_digest: Option<Digest>,
    pub target_url_digest: Option<Digest>,
    pub environment_url_digest: Option<Digest>,
    pub log_url_digest: Option<Digest>,
}

impl GithubUrlDigests {
    pub fn validate(&self) -> Result<(), ModelError> {
        for digest in [
            &self.deployment_url_digest,
            &self.statuses_url_digest,
            &self.target_url_digest,
            &self.environment_url_digest,
            &self.log_url_digest,
        ]
        .into_iter()
        .flatten()
        {
            validate_digest(digest)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentMetadata {
    pub id: GithubDeploymentId,
    pub ref_name: GithubRef,
    pub commit: GithubCommitSha,
    pub environment: GithubEnvironment,
    pub created_at: GithubTimestamp,
    pub updated_at: GithubTimestamp,
    pub url_digests: GithubUrlDigests,
    pub deployment_digest: Digest,
}

impl GithubDeploymentMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: GithubDeploymentId,
        ref_name: GithubRef,
        commit: GithubCommitSha,
        environment: GithubEnvironment,
        created_at: GithubTimestamp,
        updated_at: GithubTimestamp,
        url_digests: GithubUrlDigests,
    ) -> Result<Self, ModelError> {
        if updated_at.epoch_seconds() < created_at.epoch_seconds() {
            return Err(ModelError::InvalidScope("deployment timestamp order"));
        }
        url_digests.validate()?;
        let deployment_digest = canonical_digest(&(
            "github-deployment-metadata/v1",
            &id,
            &ref_name,
            &commit,
            &environment,
            &created_at,
            &updated_at,
            &url_digests,
        ));
        Ok(Self {
            id,
            ref_name,
            commit,
            environment,
            created_at,
            updated_at,
            url_digests,
            deployment_digest,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = canonical_digest(&(
            "github-deployment-metadata/v1",
            &self.id,
            &self.ref_name,
            &self.commit,
            &self.environment,
            &self.created_at,
            &self.updated_at,
            &self.url_digests,
        ));
        if expected != self.deployment_digest {
            return Err(ModelError::InvalidDigest);
        }
        self.url_digests.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusMetadata {
    pub id: u64,
    pub deployment_id: GithubDeploymentId,
    pub environment: GithubEnvironment,
    pub state: GithubDeploymentStatusState,
    pub created_at: GithubTimestamp,
    pub updated_at: GithubTimestamp,
    pub url_digests: GithubUrlDigests,
    pub status_digest: Digest,
}

impl GithubDeploymentStatusMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        deployment_id: GithubDeploymentId,
        environment: GithubEnvironment,
        state: GithubDeploymentStatusState,
        created_at: GithubTimestamp,
        updated_at: GithubTimestamp,
        url_digests: GithubUrlDigests,
    ) -> Result<Self, ModelError> {
        if id == 0 {
            return Err(ModelError::InvalidIdentifier {
                field: "deployment status id",
            });
        }
        if updated_at.epoch_seconds() < created_at.epoch_seconds() {
            return Err(ModelError::InvalidScope("status timestamp order"));
        }
        url_digests.validate()?;
        let status_digest = canonical_digest(&(
            "github-deployment-status-metadata/v1",
            id,
            &deployment_id,
            &environment,
            &state,
            &created_at,
            &updated_at,
            &url_digests,
        ));
        Ok(Self {
            id,
            deployment_id,
            environment,
            state,
            created_at,
            updated_at,
            url_digests,
            status_digest,
        })
    }

    pub fn validate_integrity(&self) -> Result<(), ModelError> {
        let expected = canonical_digest(&(
            "github-deployment-status-metadata/v1",
            self.id,
            &self.deployment_id,
            &self.environment,
            &self.state,
            &self.created_at,
            &self.updated_at,
            &self.url_digests,
        ));
        if expected != self.status_digest {
            return Err(ModelError::InvalidDigest);
        }
        self.url_digests.validate()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Layer1Authority {
    pub read_only: bool,
    pub proposal_only: bool,
    pub native: bool,
    pub connected: bool,
    pub durable_receipt: bool,
    pub kernel_authority: bool,
    pub truth_authority: bool,
    pub outcome_authority: bool,
    pub external_writes: bool,
}

impl Default for Layer1Authority {
    fn default() -> Self {
        Self {
            read_only: true,
            proposal_only: true,
            ..Self::default_fields()
        }
    }
}

impl Layer1Authority {
    const fn default_fields() -> Self {
        Self {
            read_only: false,
            proposal_only: false,
            native: false,
            connected: false,
            durable_receipt: false,
            kernel_authority: false,
            truth_authority: false,
            outcome_authority: false,
            external_writes: false,
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
    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRevocationReceipt {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GithubDeploymentStatusRegistration {
    pub schema_version: String,
    pub plugin_version: String,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl GithubDeploymentStatusRegistration {
    pub fn bind(
        scope: &GithubDeploymentStatusScope,
        secret_reference: &SecretReference,
        provider_digest: Digest,
    ) -> Self {
        let mut registration = Self {
            schema_version: crate::GITHUB_DEPLOYMENT_STATUS_RESULT_SCHEMA_VERSION.to_owned(),
            plugin_version: crate::GITHUB_DEPLOYMENT_STATUS_RESULT_PLUGIN_VERSION.to_owned(),
            version_digest: crate::version_digest(),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.digest().clone(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_revision: Revision(1),
            state: RegistrationState::Active,
            registration_digest: String::new(),
        };
        registration.registration_digest = registration.compute_digest();
        registration
    }

    pub fn validate(
        &self,
        scope: &GithubDeploymentStatusScope,
        secret_reference: &SecretReference,
        provider_digest: &str,
    ) -> Result<(), ModelError> {
        if self.schema_version != crate::GITHUB_DEPLOYMENT_STATUS_RESULT_SCHEMA_VERSION
            || self.plugin_version != crate::GITHUB_DEPLOYMENT_STATUS_RESULT_PLUGIN_VERSION
            || self.version_digest != crate::version_digest()
            || self.contract_digest != crate::contract_digest()
            || self.provider_digest != provider_digest
            || self.permission_digest != *scope.permission_digest()
            || self.scope_digest != *scope.digest()
            || self.secret_reference_digest != *secret_reference.reference_digest()
            || self.registration_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidScope("registration digest"));
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt, ModelError> {
        if self.state == RegistrationState::Revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        let previous_registration_digest = self.registration_digest.clone();
        self.registration_revision = next_revision(self.registration_revision)?;
        self.state = RegistrationState::Revoked;
        self.registration_digest = self.compute_digest();
        Ok(RegistrationRevocationReceipt {
            previous_registration_digest,
            registration_digest: self.registration_digest.clone(),
            registration_revision: self.registration_revision,
            state: self.state,
            reversible: true,
            revocable: true,
        })
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        self.registration_revision = next_revision(self.registration_revision)?;
        self.state = RegistrationState::Active;
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        let mut value = self.clone();
        value.registration_digest.clear();
        canonical_digest(&value)
    }
}

pub(crate) fn validate_url(value: &str) -> Result<(), ModelError> {
    if value.is_empty()
        || value.len() > MAX_URL_BYTES
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        Err(ModelError::InvalidUrl)
    } else {
        Ok(())
    }
}

pub(crate) fn digest_url(value: &str) -> Result<Digest, ModelError> {
    validate_url(value)?;
    Ok(sha256_digest(value.as_bytes()))
}
