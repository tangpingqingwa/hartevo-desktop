use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    GCP_CLOUD_DEPLOY_API_VERSION, GCP_CLOUD_DEPLOY_PROVIDER_ID,
    GCP_CLOUD_DEPLOY_PROVIDER_VERSION_TEXT, MAX_JOB_RUNS_PER_PAGE, MAX_PAGE_SIZE,
    MAX_ROLLOUTS_PER_PAGE,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("timestamp must be non-negative")]
    InvalidTimestamp,
    #[error("API version is not supported")]
    InvalidApiVersion,
    #[error("permission scope is not the least-privilege read-only set")]
    InvalidPermissionScope,
    #[error("consent scope must be read-only and effect-free")]
    InvalidConsentScope,
    #[error("scope is invalid")]
    InvalidScope,
    #[error("secret reference is invalid")]
    InvalidSecretReference,
    #[error("page exceeds the bounded page size")]
    PageTooLarge,
    #[error("page cursor is bound to another scope or operation")]
    CursorMismatch,
    #[error("job-run observations are not strictly ordered")]
    InvalidJobRunOrdering,
    #[error("snapshot identity is invalid")]
    InvalidSnapshot,
    #[error("phase transition is not monotonic")]
    InvalidPhaseTransition,
    #[error("digest does not match immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration or secret is already revoked")]
    AlreadyRevoked,
    #[error("value exceeds a contract bound")]
    BoundExceeded,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_fields(domain: &str, fields: &[String]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for field in fields {
            append_field(&mut bytes, field);
        }
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

fn append_field(bytes: &mut Vec<u8>, field: &str) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

macro_rules! string_identifier {
    ($name:ident) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if valid_identifier(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
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
    };
}

string_identifier!(ProjectId);
string_identifier!(LocationId);
string_identifier!(PipelineId);
string_identifier!(ReleaseId);
string_identifier!(RolloutId);
string_identifier!(TargetId);
string_identifier!(JobRunId);
string_identifier!(CommitId);
string_identifier!(MissionId);
string_identifier!(WorkProductId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn new(seconds: i64) -> Result<Self, ModelError> {
        if seconds < 0 {
            Err(ModelError::InvalidTimestamp)
        } else {
            Ok(Self(seconds))
        }
    }

    pub const fn seconds(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpCloudDeployApiVersion {
    V1,
}

impl GcpCloudDeployApiVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V1 => GCP_CLOUD_DEPLOY_API_VERSION,
        }
    }

    pub fn digest(self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpCloudDeployPermission {
    ReleasesGet,
    ReleasesList,
    RolloutsGet,
    RolloutsList,
    JobRunsGet,
    JobRunsList,
    TargetsGet,
}

impl GcpCloudDeployPermission {
    pub const fn api_name(self) -> &'static str {
        match self {
            Self::ReleasesGet => "clouddeploy.releases.get",
            Self::ReleasesList => "clouddeploy.releases.list",
            Self::RolloutsGet => "clouddeploy.rollouts.get",
            Self::RolloutsList => "clouddeploy.rollouts.list",
            Self::JobRunsGet => "clouddeploy.jobRuns.get",
            Self::JobRunsList => "clouddeploy.jobRuns.list",
            Self::TargetsGet => "clouddeploy.targets.get",
        }
    }

    pub const fn all() -> [Self; 7] {
        [
            Self::ReleasesGet,
            Self::ReleasesList,
            Self::RolloutsGet,
            Self::RolloutsList,
            Self::JobRunsGet,
            Self::JobRunsList,
            Self::TargetsGet,
        ]
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PermissionScope(Vec<GcpCloudDeployPermission>);

impl PermissionScope {
    pub fn least_privilege() -> Self {
        Self(GcpCloudDeployPermission::all().into_iter().collect())
    }

    pub fn new<I>(permissions: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = GcpCloudDeployPermission>,
    {
        let permissions = permissions.into_iter().collect::<Vec<_>>();
        let result = Self(permissions);
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let actual = self.0.iter().copied().collect::<BTreeSet<_>>();
        let expected = GcpCloudDeployPermission::all()
            .into_iter()
            .collect::<BTreeSet<_>>();
        if self.0.len() != actual.len() || actual != expected {
            Err(ModelError::InvalidPermissionScope)
        } else {
            Ok(())
        }
    }

    pub fn contains(&self, permission: GcpCloudDeployPermission) -> bool {
        self.0.contains(&permission)
    }

    pub fn as_slice(&self) -> &[GcpCloudDeployPermission] {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-permissions/v1",
            &self
                .0
                .iter()
                .map(|permission| permission.api_name().to_owned())
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentPurpose {
    ReadDeploymentEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    consent_digest: Digest,
    purpose: ConsentPurpose,
    revision: Revision,
    read_only: bool,
    effects_allowed: bool,
}

impl ConsentScope {
    pub fn read_only(reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        if reference.as_ref().is_empty() {
            return Err(ModelError::InvalidConsentScope);
        }
        let consent = Self {
            consent_digest: Digest::from_text(reference.as_ref()),
            purpose: ConsentPurpose::ReadDeploymentEvidence,
            revision: Revision::new(revision)?,
            read_only: true,
            effects_allowed: false,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.purpose != ConsentPurpose::ReadDeploymentEvidence
            || !self.read_only
            || self.effects_allowed
            || Digest::parse(self.consent_digest.as_str().to_owned()).is_err()
        {
            Err(ModelError::InvalidConsentScope)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-consent/v1",
            &[
                self.consent_digest.as_str().to_owned(),
                format!("{:?}", self.purpose),
                self.revision.get().to_string(),
                self.read_only.to_string(),
                self.effects_allowed.to_string(),
            ],
        )
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    ServiceAccount,
}

impl SecretKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::ServiceAccount => "service_account",
        }
    }
}

/// Opaque host-keychain reference. It deliberately has no serde implementation
/// and retains only binding digests; neither a token nor a service-account key
/// can enter this crate's value graph.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl SecretReference {
    pub fn oauth(
        reference_id: impl AsRef<str>,
        scope: &GcpCloudDeployScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(SecretKind::OAuth, reference_id, scope, credential_revision)
    }

    pub fn service_account(
        reference_id: impl AsRef<str>,
        scope: &GcpCloudDeployScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            SecretKind::ServiceAccount,
            reference_id,
            scope,
            credential_revision,
        )
    }

    pub fn new(
        kind: SecretKind,
        reference_id: impl AsRef<str>,
        scope: &GcpCloudDeployScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        if !valid_identifier(reference_id.as_ref()) {
            return Err(ModelError::InvalidSecretReference);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.digest();
        let reference_digest = Digest::from_fields(
            "gcp-cloud-deploy-secret-reference/v1",
            &[
                reference_id.as_ref().to_owned(),
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                kind.as_str().to_owned(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind,
            revoked: false,
        })
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

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
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
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
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fixture => "fixture",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    id: MissionId,
    revision: Revision,
}

impl MissionScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-mission-scope/v1",
            &[self.id.as_str().to_owned(), self.revision.get().to_string()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectScope {
    id: ProjectId,
    revision: Revision,
}

impl ProjectScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: ProjectId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-project-scope/v1",
            &[self.id.as_str().to_owned(), self.revision.get().to_string()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductScope {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductScope {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-work-product-scope/v1",
            &[self.id.as_str().to_owned(), self.revision.get().to_string()],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseIdentity {
    project_id: ProjectId,
    location: LocationId,
    pipeline_id: PipelineId,
    release_id: ReleaseId,
}

impl ReleaseIdentity {
    pub fn new(
        project_id: impl Into<String>,
        location: impl Into<String>,
        pipeline_id: impl Into<String>,
        release_id: impl Into<String>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            project_id: ProjectId::new(project_id)?,
            location: LocationId::new(location)?,
            pipeline_id: PipelineId::new(pipeline_id)?,
            release_id: ReleaseId::new(release_id)?,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn location(&self) -> &LocationId {
        &self.location
    }

    pub fn pipeline_id(&self) -> &PipelineId {
        &self.pipeline_id
    }

    pub fn release_id(&self) -> &ReleaseId {
        &self.release_id
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-release/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.location.as_str().to_owned(),
                self.pipeline_id.as_str().to_owned(),
                self.release_id.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloutIdentity {
    release: ReleaseIdentity,
    rollout_id: RolloutId,
}

impl RolloutIdentity {
    pub fn new(
        release: ReleaseIdentity,
        rollout_id: impl Into<String>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            release,
            rollout_id: RolloutId::new(rollout_id)?,
        })
    }

    pub fn release(&self) -> &ReleaseIdentity {
        &self.release
    }

    pub fn rollout_id(&self) -> &RolloutId {
        &self.rollout_id
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-rollout/v1",
            &[
                self.release.digest().as_str().to_owned(),
                self.rollout_id.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobRunIdentity {
    rollout: RolloutIdentity,
    job_run_id: JobRunId,
}

impl JobRunIdentity {
    pub fn new(
        rollout: RolloutIdentity,
        job_run_id: impl Into<String>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            rollout,
            job_run_id: JobRunId::new(job_run_id)?,
        })
    }

    pub fn rollout(&self) -> &RolloutIdentity {
        &self.rollout
    }

    pub fn job_run_id(&self) -> &JobRunId {
        &self.job_run_id
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-job-run/v1",
            &[
                self.rollout.digest().as_str().to_owned(),
                self.job_run_id.as_str().to_owned(),
            ],
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GcpCloudDeployScope {
    project_id: ProjectId,
    location: LocationId,
    pipeline_id: PipelineId,
    release_id: ReleaseId,
    target_id: TargetId,
    commit_id: CommitId,
    mission: MissionScope,
    project: ProjectScope,
    work_product: WorkProductScope,
    permissions: PermissionScope,
    consent: ConsentScope,
}

impl GcpCloudDeployScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        location: impl Into<String>,
        pipeline_id: impl Into<String>,
        release_id: impl Into<String>,
        target_id: impl Into<String>,
        commit_id: impl Into<String>,
        mission: MissionScope,
        project: ProjectScope,
        work_product: WorkProductScope,
        permissions: PermissionScope,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            project_id: ProjectId::new(project_id)?,
            location: LocationId::new(location)?,
            pipeline_id: PipelineId::new(pipeline_id)?,
            release_id: ReleaseId::new(release_id)?,
            target_id: TargetId::new(target_id)?,
            commit_id: CommitId::new(commit_id)?,
            mission,
            project,
            work_product,
            permissions,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.permissions.validate()?;
        self.consent.validate()?;
        if self.project.id().as_str().is_empty()
            || self.mission.id().as_str().is_empty()
            || self.work_product.id().as_str().is_empty()
        {
            Err(ModelError::InvalidScope)
        } else {
            Ok(())
        }
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn location(&self) -> &LocationId {
        &self.location
    }

    pub fn pipeline_id(&self) -> &PipelineId {
        &self.pipeline_id
    }

    pub fn release_id(&self) -> &ReleaseId {
        &self.release_id
    }

    pub fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    pub fn commit_id(&self) -> &CommitId {
        &self.commit_id
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    pub fn permissions(&self) -> &PermissionScope {
        &self.permissions
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    ///
    /// # Panics
    ///
    /// This cannot panic for a scope produced by [`Self::new`], because all
    /// identifiers are validated before the scope is returned.
    pub fn release_identity(&self) -> ReleaseIdentity {
        ReleaseIdentity::new(
            self.project_id.as_str(),
            self.location.as_str(),
            self.pipeline_id.as_str(),
            self.release_id.as_str(),
        )
        .expect("validated release identity")
    }

    pub fn release_digest(&self) -> Digest {
        self.release_identity().digest()
    }

    pub fn target_digest(&self) -> Digest {
        self.target_id.digest()
    }

    pub fn commit_digest(&self) -> Digest {
        self.commit_id.digest()
    }

    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }

    pub fn project_scope_digest(&self) -> Digest {
        self.project.digest()
    }

    pub fn work_product_digest(&self) -> Digest {
        self.work_product.digest()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-scope/v1",
            &[
                self.project_id.as_str().to_owned(),
                self.location.as_str().to_owned(),
                self.pipeline_id.as_str().to_owned(),
                self.release_id.as_str().to_owned(),
                self.target_id.as_str().to_owned(),
                self.commit_id.as_str().to_owned(),
                self.mission.digest().as_str().to_owned(),
                self.project.digest().as_str().to_owned(),
                self.work_product.digest().as_str().to_owned(),
                self.permissions.digest().as_str().to_owned(),
                self.consent.digest().as_str().to_owned(),
            ],
        )
    }
}

impl fmt::Debug for GcpCloudDeployScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpCloudDeployScope")
            .field("project_id", &self.project_id)
            .field("location", &self.location)
            .field("pipeline_id", &self.pipeline_id)
            .field("release_id", &self.release_id)
            .field("target_id", &self.target_id)
            .field("commit_id", &self.commit_id)
            .field("mission", &self.mission)
            .field("project", &self.project)
            .field("work_product", &self.work_product)
            .field("permission_digest", &self.permissions.digest())
            .field("consent_digest", &self.consent.digest())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudDeployPhase {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}

impl CloudDeployPhase {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Unknown => true,
            Self::Pending => matches!(next, Self::Pending | Self::InProgress | Self::Unknown),
            Self::InProgress => matches!(
                next,
                Self::InProgress | Self::Succeeded | Self::Failed | Self::Cancelled | Self::Unknown
            ),
            Self::Succeeded => matches!(next, Self::Succeeded | Self::Unknown),
            Self::Failed => matches!(next, Self::Failed | Self::Unknown),
            Self::Cancelled => matches!(next, Self::Cancelled | Self::Unknown),
        }
    }
}

pub type ReleasePhase = CloudDeployPhase;
pub type RolloutPhase = CloudDeployPhase;
pub type JobRunPhase = CloudDeployPhase;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudDeployStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Unknown,
}

impl CloudDeployStatus {
    pub const fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Unknown => true,
            Self::Pending => matches!(next, Self::Pending | Self::Running | Self::Unknown),
            Self::Running => matches!(
                next,
                Self::Running | Self::Succeeded | Self::Failed | Self::Cancelled | Self::Unknown
            ),
            Self::Succeeded => matches!(next, Self::Succeeded | Self::Unknown),
            Self::Failed => matches!(next, Self::Failed | Self::Unknown),
            Self::Cancelled => matches!(next, Self::Cancelled | Self::Unknown),
        }
    }
}

pub type ReleaseStatus = CloudDeployStatus;
pub type RolloutStatus = CloudDeployStatus;
pub type JobRunStatus = CloudDeployStatus;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProjection {
    Complete,
    Partial,
    Unknown,
    AccessLost,
    RateLimited,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Server,
    Timeout,
    Transport,
    Malformed,
    CursorMismatch,
    ScopeMismatch,
    StaleCommit,
    StaleTarget,
    SecretRevoked,
    BlockedEnv,
    PhaseRegression,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListOperation {
    Releases,
    Rollouts,
    JobRuns,
}

/// A cursor is intentionally not serde-enabled and does not expose a provider
/// page token. Its only usable operation is to return to the same bound scope.
#[derive(Clone, Eq, PartialEq)]
pub struct PageCursor {
    binding_digest: Digest,
    operation: ListOperation,
    position: usize,
    opaque_digest: Digest,
}

impl PageCursor {
    pub fn from_scope(
        scope: &GcpCloudDeployScope,
        operation: ListOperation,
        position: usize,
    ) -> Result<Self, ModelError> {
        Self::from_binding(&scope.digest(), operation, position)
    }

    pub(crate) fn from_binding(
        binding_digest: &Digest,
        operation: ListOperation,
        position: usize,
    ) -> Result<Self, ModelError> {
        if position == 0 || position > MAX_PAGE_SIZE {
            return Err(ModelError::BoundExceeded);
        }
        let opaque_digest = Digest::from_fields(
            "gcp-cloud-deploy-opaque-cursor/v1",
            &[
                binding_digest.as_str().to_owned(),
                format!("{operation:?}"),
                position.to_string(),
            ],
        );
        Ok(Self {
            binding_digest: binding_digest.clone(),
            operation,
            position,
            opaque_digest,
        })
    }

    pub fn operation(&self) -> ListOperation {
        self.operation
    }

    pub const fn position(&self) -> usize {
        self.position
    }

    pub fn opaque_digest(&self) -> &Digest {
        &self.opaque_digest
    }

    pub fn matches(&self, scope: &GcpCloudDeployScope, operation: ListOperation) -> bool {
        self.binding_digest == scope.digest() && self.operation == operation
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("operation", &self.operation)
            .field("position", &self.position)
            .field("opaque_digest", &self.opaque_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReleaseSnapshot {
    identity: ReleaseIdentity,
    target_id: TargetId,
    commit_id: CommitId,
    phase: ReleasePhase,
    status: ReleaseStatus,
    revision: Revision,
    observed_at: Timestamp,
    payload_digest: Digest,
    log_digest: Option<Digest>,
    artifact_digest: Option<Digest>,
    snapshot_digest: Digest,
}

impl ReleaseSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: ReleaseIdentity,
        target_id: TargetId,
        commit_id: CommitId,
        phase: ReleasePhase,
        status: ReleaseStatus,
        revision: Revision,
        observed_at: Timestamp,
        payload_digest: Digest,
        log_digest: Option<Digest>,
        artifact_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        let mut snapshot = Self {
            identity,
            target_id,
            commit_id,
            phase,
            status,
            revision,
            observed_at,
            payload_digest,
            log_digest,
            artifact_digest,
            snapshot_digest: Digest::from_text("pending"),
        };
        snapshot.snapshot_digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    pub fn recorded(
        scope: &GcpCloudDeployScope,
        phase: ReleasePhase,
        status: ReleaseStatus,
        observed_at: Timestamp,
        payload_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new(
            scope.release_identity(),
            scope.target_id.clone(),
            scope.commit_id.clone(),
            phase,
            status,
            Revision::new(1)?,
            observed_at,
            payload_digest,
            None,
            None,
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-release-snapshot/v1",
            &[
                self.identity.digest().as_str().to_owned(),
                self.target_id.digest().as_str().to_owned(),
                self.commit_id.digest().as_str().to_owned(),
                format!("{:?}", self.phase),
                format!("{:?}", self.status),
                self.revision.get().to_string(),
                self.observed_at.seconds().to_string(),
                self.payload_digest.as_str().to_owned(),
                self.log_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                self.artifact_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.snapshot_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn identity(&self) -> &ReleaseIdentity {
        &self.identity
    }

    pub fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    pub fn commit_id(&self) -> &CommitId {
        &self.commit_id
    }

    pub fn phase(&self) -> ReleasePhase {
        self.phase
    }

    pub fn status(&self) -> ReleaseStatus {
        self.status
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    pub fn payload_digest(&self) -> &Digest {
        &self.payload_digest
    }

    pub fn log_digest(&self) -> Option<&Digest> {
        self.log_digest.as_ref()
    }

    pub fn artifact_digest(&self) -> Option<&Digest> {
        self.artifact_digest.as_ref()
    }

    pub fn snapshot_digest(&self) -> &Digest {
        &self.snapshot_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolloutSnapshot {
    identity: RolloutIdentity,
    target_id: TargetId,
    commit_id: CommitId,
    phase: RolloutPhase,
    status: RolloutStatus,
    revision: Revision,
    observed_at: Timestamp,
    payload_digest: Digest,
    log_digest: Option<Digest>,
    artifact_digest: Option<Digest>,
    snapshot_digest: Digest,
}

impl RolloutSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: RolloutIdentity,
        target_id: TargetId,
        commit_id: CommitId,
        phase: RolloutPhase,
        status: RolloutStatus,
        revision: Revision,
        observed_at: Timestamp,
        payload_digest: Digest,
        log_digest: Option<Digest>,
        artifact_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        let mut snapshot = Self {
            identity,
            target_id,
            commit_id,
            phase,
            status,
            revision,
            observed_at,
            payload_digest,
            log_digest,
            artifact_digest,
            snapshot_digest: Digest::from_text("pending"),
        };
        snapshot.snapshot_digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    pub fn recorded(
        scope: &GcpCloudDeployScope,
        rollout_id: impl Into<String>,
        phase: RolloutPhase,
        status: RolloutStatus,
        observed_at: Timestamp,
        payload_digest: Digest,
    ) -> Result<Self, ModelError> {
        Self::new(
            RolloutIdentity::new(scope.release_identity(), rollout_id)?,
            scope.target_id.clone(),
            scope.commit_id.clone(),
            phase,
            status,
            Revision::new(1)?,
            observed_at,
            payload_digest,
            None,
            None,
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-rollout-snapshot/v1",
            &[
                self.identity.digest().as_str().to_owned(),
                self.target_id.digest().as_str().to_owned(),
                self.commit_id.digest().as_str().to_owned(),
                format!("{:?}", self.phase),
                format!("{:?}", self.status),
                self.revision.get().to_string(),
                self.observed_at.seconds().to_string(),
                self.payload_digest.as_str().to_owned(),
                self.log_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                self.artifact_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.snapshot_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn identity(&self) -> &RolloutIdentity {
        &self.identity
    }

    pub fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    pub fn commit_id(&self) -> &CommitId {
        &self.commit_id
    }

    pub fn phase(&self) -> RolloutPhase {
        self.phase
    }

    pub fn status(&self) -> RolloutStatus {
        self.status
    }

    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    pub fn log_digest(&self) -> Option<&Digest> {
        self.log_digest.as_ref()
    }

    pub fn artifact_digest(&self) -> Option<&Digest> {
        self.artifact_digest.as_ref()
    }

    pub fn snapshot_digest(&self) -> &Digest {
        &self.snapshot_digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobRunSnapshot {
    identity: JobRunIdentity,
    target_id: TargetId,
    commit_id: CommitId,
    sequence: u32,
    phase: JobRunPhase,
    status: JobRunStatus,
    revision: Revision,
    observed_at: Timestamp,
    payload_digest: Digest,
    log_digest: Option<Digest>,
    artifact_digest: Option<Digest>,
    snapshot_digest: Digest,
}

impl JobRunSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: JobRunIdentity,
        target_id: TargetId,
        commit_id: CommitId,
        sequence: u32,
        phase: JobRunPhase,
        status: JobRunStatus,
        revision: Revision,
        observed_at: Timestamp,
        payload_digest: Digest,
        log_digest: Option<Digest>,
        artifact_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if sequence == 0 {
            return Err(ModelError::InvalidJobRunOrdering);
        }
        let mut snapshot = Self {
            identity,
            target_id,
            commit_id,
            sequence,
            phase,
            status,
            revision,
            observed_at,
            payload_digest,
            log_digest,
            artifact_digest,
            snapshot_digest: Digest::from_text("pending"),
        };
        snapshot.snapshot_digest = snapshot.compute_digest();
        Ok(snapshot)
    }

    pub fn recorded(
        scope: &GcpCloudDeployScope,
        rollout_id: impl Into<String>,
        job_run_id: impl Into<String>,
        sequence: u32,
        phase: JobRunPhase,
        status: JobRunStatus,
        observed_at: Timestamp,
        payload_digest: Digest,
    ) -> Result<Self, ModelError> {
        let rollout = RolloutIdentity::new(scope.release_identity(), rollout_id)?;
        Self::new(
            JobRunIdentity::new(rollout, job_run_id)?,
            scope.target_id.clone(),
            scope.commit_id.clone(),
            sequence,
            phase,
            status,
            Revision::new(1)?,
            observed_at,
            payload_digest,
            None,
            None,
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-cloud-deploy-job-run-snapshot/v1",
            &[
                self.identity.digest().as_str().to_owned(),
                self.target_id.digest().as_str().to_owned(),
                self.commit_id.digest().as_str().to_owned(),
                self.sequence.to_string(),
                format!("{:?}", self.phase),
                format!("{:?}", self.status),
                self.revision.get().to_string(),
                self.observed_at.seconds().to_string(),
                self.payload_digest.as_str().to_owned(),
                self.log_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                self.artifact_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.snapshot_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn identity(&self) -> &JobRunIdentity {
        &self.identity
    }

    pub fn target_id(&self) -> &TargetId {
        &self.target_id
    }

    pub fn commit_id(&self) -> &CommitId {
        &self.commit_id
    }

    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    pub fn phase(&self) -> JobRunPhase {
        self.phase
    }

    pub fn status(&self) -> JobRunStatus {
        self.status
    }

    pub const fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    pub fn log_digest(&self) -> Option<&Digest> {
        self.log_digest.as_ref()
    }

    pub fn artifact_digest(&self) -> Option<&Digest> {
        self.artifact_digest.as_ref()
    }

    pub fn snapshot_digest(&self) -> &Digest {
        &self.snapshot_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasePage {
    items: Vec<ReleaseSnapshot>,
    next_cursor: Option<PageCursor>,
}

impl ReleasePage {
    pub fn new(
        items: Vec<ReleaseSnapshot>,
        next_cursor: Option<PageCursor>,
    ) -> Result<Self, ModelError> {
        if items.len() > MAX_PAGE_SIZE {
            return Err(ModelError::PageTooLarge);
        }
        let mut seen = BTreeSet::new();
        if items
            .iter()
            .any(|item| !seen.insert(item.identity().release_id().clone()))
        {
            return Err(ModelError::InvalidSnapshot);
        }
        Ok(Self { items, next_cursor })
    }

    pub fn items(&self) -> &[ReleaseSnapshot] {
        &self.items
    }

    pub fn next_cursor(&self) -> Option<&PageCursor> {
        self.next_cursor.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolloutPage {
    items: Vec<RolloutSnapshot>,
    next_cursor: Option<PageCursor>,
}

impl RolloutPage {
    pub fn new(
        items: Vec<RolloutSnapshot>,
        next_cursor: Option<PageCursor>,
    ) -> Result<Self, ModelError> {
        if items.len() > MAX_ROLLOUTS_PER_PAGE {
            return Err(ModelError::PageTooLarge);
        }
        let mut seen = BTreeSet::new();
        if items
            .iter()
            .any(|item| !seen.insert(item.identity().rollout_id().clone()))
        {
            return Err(ModelError::InvalidSnapshot);
        }
        Ok(Self { items, next_cursor })
    }

    pub fn items(&self) -> &[RolloutSnapshot] {
        &self.items
    }

    pub fn next_cursor(&self) -> Option<&PageCursor> {
        self.next_cursor.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobRunPage {
    items: Vec<JobRunSnapshot>,
    next_cursor: Option<PageCursor>,
}

impl JobRunPage {
    pub fn new(
        items: Vec<JobRunSnapshot>,
        next_cursor: Option<PageCursor>,
    ) -> Result<Self, ModelError> {
        if items.len() > MAX_JOB_RUNS_PER_PAGE {
            return Err(ModelError::PageTooLarge);
        }
        validate_job_run_order(&items)?;
        Ok(Self { items, next_cursor })
    }

    pub fn items(&self) -> &[JobRunSnapshot] {
        &self.items
    }

    pub fn next_cursor(&self) -> Option<&PageCursor> {
        self.next_cursor.as_ref()
    }
}

pub(crate) fn validate_job_run_order(items: &[JobRunSnapshot]) -> Result<(), ModelError> {
    let mut seen = BTreeSet::new();
    let mut previous_sequence = 0;
    let mut previous_observed_at = None;
    for item in items {
        if !seen.insert(item.identity().job_run_id().clone())
            || item.sequence() <= previous_sequence
            || previous_observed_at.is_some_and(|previous| item.observed_at() < previous)
        {
            return Err(ModelError::InvalidJobRunOrdering);
        }
        previous_sequence = item.sequence();
        previous_observed_at = Some(item.observed_at());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderErrorSummary {
    pub kind: ProviderErrorKind,
    pub status: Option<u16>,
    pub detail_digest: Digest,
}

impl ProviderErrorSummary {
    pub(crate) fn new(kind: ProviderErrorKind, status: Option<u16>, detail_digest: Digest) -> Self {
        Self {
            kind,
            status,
            detail_digest,
        }
    }
}

pub(crate) fn registration_digest(
    service_digest: &Digest,
    version_digest: &Digest,
    api_digest: &Digest,
    contract_digest: &Digest,
    provider_digest: &Digest,
    permission_digest: &Digest,
    scope_digest: &Digest,
    release_digest: &Digest,
) -> Digest {
    Digest::from_fields(
        "gcp-cloud-deploy-registration/v1",
        &[
            service_digest.as_str().to_owned(),
            version_digest.as_str().to_owned(),
            api_digest.as_str().to_owned(),
            contract_digest.as_str().to_owned(),
            GCP_CLOUD_DEPLOY_PROVIDER_ID.to_owned(),
            GCP_CLOUD_DEPLOY_PROVIDER_VERSION_TEXT.to_owned(),
            provider_digest.as_str().to_owned(),
            permission_digest.as_str().to_owned(),
            scope_digest.as_str().to_owned(),
            release_digest.as_str().to_owned(),
        ],
    )
}
