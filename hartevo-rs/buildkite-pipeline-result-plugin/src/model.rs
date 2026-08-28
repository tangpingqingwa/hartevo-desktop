//! Exact Buildkite identity, Mission scope, and bounded non-native projections.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    BuildkitePipelineResultError, MAX_ANNOTATIONS, MAX_ARTIFACTS, MAX_ATTEMPTS, MAX_BUILDS,
    MAX_IDENTIFIER_BYTES, MAX_JOBS, MAX_METADATA_BYTES, MAX_RESPONSE_BYTES, MAX_RETRY_NUMBER,
    Result, digest_serialized, sha256_hex, validate_digest, validate_identifier, validate_text,
};

/// A SHA-256 digest used for identity, request, tamper, and redaction binding.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_digest(&value, "digest")?;
        Ok(Self(value))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self(sha256_hex(value.as_ref()))
    }

    pub fn from_serialized<T: Serialize>(value: &T) -> Self {
        Self(digest_serialized(value))
    }

    pub fn from_parts(label: &str, values: &[(&str, String)]) -> Self {
        let mut canonical = String::with_capacity(64 + values.len() * 24);
        canonical.push_str(label);
        for (name, value) in values {
            canonical.push('|');
            canonical.push_str(name);
            canonical.push(':');
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
        }
        Self::from_text(canonical)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        validate_digest(&self.0, "digest")
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

macro_rules! define_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<()> {
                validate_identifier(&self.0, $field)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

define_identifier!(MissionId, "missionId");
define_identifier!(ProjectId, "projectId");
define_identifier!(WorkProductId, "workProductId");
define_identifier!(RegistrationId, "registrationId");
define_identifier!(OrganizationSlug, "organizationSlug");
define_identifier!(PipelineSlug, "pipelineSlug");
define_identifier!(BuildId, "buildId");
define_identifier!(JobId, "jobId");
define_identifier!(AttemptId, "attemptId");
define_identifier!(ArtifactId, "artifactId");
define_identifier!(AnnotationId, "annotationId");

pub type OrganizationId = OrganizationSlug;
pub type PipelineId = PipelineSlug;

/// A Buildkite commit SHA, retained as an identifier and never as a patch or
/// source checkout.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !(40..=64).contains(&value.len())
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(BuildkitePipelineResultError::InvalidIdentifier { field: "commitSha" });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Display for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Semantic version bound into a registration, independent of the crate
/// packaging version.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    pub fn parse(value: &str) -> Result<Self> {
        let mut parts = value.split('.');
        let parsed = [parts.next(), parts.next(), parts.next()];
        if parts.next().is_some() || parsed.iter().any(Option::is_none) {
            return Err(BuildkitePipelineResultError::InvalidIdentifier {
                field: "pluginVersion",
            });
        }
        let mut numbers = [0_u16; 3];
        for (index, part) in parsed.into_iter().enumerate() {
            numbers[index] = part
                .expect("checked version part")
                .parse::<u16>()
                .map_err(|_| BuildkitePipelineResultError::InvalidIdentifier {
                    field: "pluginVersion",
                })?;
        }
        Ok(Self {
            major: numbers[0],
            minor: numbers[1],
            patch: numbers[2],
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// The only credential kinds accepted at Layer 1.  Credential bytes are not
/// accepted by any public API.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiToken,
    Oidc,
}

/// An opaque host-owned API-token or OIDC handle.  Only its digest, kind,
/// revision, and local revocation bit are observable.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    revision: u64,
    revoked: bool,
}

impl SecretReference {
    pub fn api_token(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::ApiToken, opaque_id, revision)
    }

    pub fn oidc(opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(SecretKind::Oidc, opaque_id, revision)
    }

    pub fn new(kind: SecretKind, opaque_id: impl Into<String>, revision: u64) -> Result<Self> {
        let opaque_id = opaque_id.into();
        validate_text(&opaque_id, "secretReference", MAX_IDENTIFIER_BYTES, true)?;
        if revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidSecretReference);
        }
        Ok(Self {
            kind,
            reference_digest: Digest::from_parts(
                "buildkite-opaque-secret-reference/v1",
                &[
                    ("kind", format!("{kind:?}")),
                    ("opaque_id", opaque_id),
                    ("revision", revision.to_string()),
                ],
            ),
            revision,
            revoked: false,
        })
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    pub fn validate(&self) -> Result<()> {
        self.reference_digest.validate()?;
        if self.revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidSecretReference);
        }
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

fn normalize_https_origin(value: &str) -> Result<String> {
    let candidate = value.strip_suffix('/').unwrap_or(value);
    let remainder = candidate
        .strip_prefix("https://")
        .ok_or(BuildkitePipelineResultError::InvalidHost)?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.contains('@')
        || remainder.contains(':')
        || remainder.chars().any(char::is_whitespace)
    {
        return Err(BuildkitePipelineResultError::InvalidHost);
    }
    let host = remainder.to_ascii_lowercase();
    if host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(BuildkitePipelineResultError::InvalidHost);
    }
    Ok(format!("https://{host}"))
}

/// The exact HTTPS origin bound to the registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostIdentity {
    pub https_origin: String,
    pub revision: u64,
}

impl HostIdentity {
    pub fn new(https_origin: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        Ok(Self {
            https_origin: normalize_https_origin(&https_origin.into())?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if Self::new(self.https_origin.clone(), self.revision)? == *self {
            Ok(())
        } else {
            Err(BuildkitePipelineResultError::InvalidHost)
        }
    }

    pub fn host(&self) -> &str {
        &self.https_origin
    }
}

macro_rules! define_revisioned_identity {
    ($name:ident, $id:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $name {
            pub id: $id,
            pub revision: u64,
        }

        impl $name {
            pub fn new(id: impl Into<String>, revision: u64) -> Result<Self> {
                if revision == 0 {
                    return Err(BuildkitePipelineResultError::InvalidScope);
                }
                Ok(Self {
                    id: $id::new(id)?,
                    revision,
                })
            }

            pub fn validate(&self) -> Result<()> {
                self.id.validate()?;
                if self.revision == 0 {
                    return Err(BuildkitePipelineResultError::InvalidScope);
                }
                Ok(())
            }

            pub fn id(&self) -> &str {
                self.id.as_str()
            }
        }
    };
}

define_revisioned_identity!(OrganizationIdentity, OrganizationSlug, "organization");
define_revisioned_identity!(PipelineIdentity, PipelineSlug, "pipeline");
define_revisioned_identity!(BuildIdentityBase, BuildId, "build");
define_revisioned_identity!(JobIdentity, JobId, "job");
define_revisioned_identity!(ArtifactIdentity, ArtifactId, "artifact");
define_revisioned_identity!(AnnotationIdentity, AnnotationId, "annotation");

/// Buildkite exposes both a stable build id and a monotonic build number.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildIdentity {
    pub id: BuildId,
    pub number: u64,
    pub revision: u64,
}

impl BuildIdentity {
    pub fn new(id: impl Into<String>, number: u64, revision: u64) -> Result<Self> {
        if number == 0 || revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        Ok(Self {
            id: BuildId::new(id)?,
            number,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.number == 0 || self.revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// Compatibility aliases make the build-number binding explicit to callers
/// that prefer the longer name.
pub type BuildIdentityWithNumber = BuildIdentity;
pub type BuildIdentityExact = BuildIdentity;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptIdentity {
    pub id: AttemptId,
    pub number: u32,
    pub revision: u64,
}

impl AttemptIdentity {
    pub fn new(id: impl Into<String>, number: u32, revision: u64) -> Result<Self> {
        if number == 0 || number > MAX_RETRY_NUMBER || revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        Ok(Self {
            id: AttemptId::new(id)?,
            number,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.id.validate()?;
        if self.number == 0 || self.number > MAX_RETRY_NUMBER || self.revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn id_str(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitIdentity {
    pub sha: CommitSha,
    pub revision: u64,
}

impl CommitIdentity {
    pub fn new(sha: impl Into<String>, revision: u64) -> Result<Self> {
        if revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        Ok(Self {
            sha: CommitSha::new(sha)?,
            revision,
        })
    }

    pub fn validate(&self) -> Result<()> {
        self.sha.validate()?;
        if self.revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        self.sha.as_str()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub project_id: ProjectId,
    pub project_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
}

impl MissionScope {
    pub fn new(
        mission_id: impl Into<String>,
        mission_revision: u64,
        project_id: impl Into<String>,
        project_revision: u64,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
    ) -> Result<Self> {
        if mission_revision == 0 || project_revision == 0 || work_product_revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        let scope = Self {
            mission_id: MissionId::new(mission_id)?,
            mission_revision,
            project_id: ProjectId::new(project_id)?,
            project_revision,
            work_product_id: WorkProductId::new(work_product_id)?,
            work_product_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.mission_id.validate()?;
        self.project_id.validate()?;
        self.work_product_id.validate()?;
        if self.mission_revision == 0
            || self.project_revision == 0
            || self.work_product_revision == 0
        {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }
}

/// Complete provider and Mission fence.  Artifact and annotation selectors
/// are bound even when a read returns a bounded collection of metadata.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildkiteScope {
    pub host: HostIdentity,
    pub organization: OrganizationIdentity,
    pub pipeline: PipelineIdentity,
    pub build: BuildIdentity,
    pub job: JobIdentity,
    pub attempt: AttemptIdentity,
    pub commit: CommitIdentity,
    pub artifact: ArtifactIdentity,
    pub annotation: AnnotationIdentity,
    pub mission: MissionScope,
}

impl BuildkiteScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: HostIdentity,
        organization: OrganizationIdentity,
        pipeline: PipelineIdentity,
        build: BuildIdentity,
        job: JobIdentity,
        attempt: AttemptIdentity,
        commit: CommitIdentity,
        artifact: ArtifactIdentity,
        annotation: AnnotationIdentity,
        mission: MissionScope,
    ) -> Result<Self> {
        let scope = Self {
            host,
            organization,
            pipeline,
            build,
            job,
            attempt,
            commit,
            artifact,
            annotation,
            mission,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_ids(
        host: impl Into<String>,
        host_revision: u64,
        organization: impl Into<String>,
        organization_revision: u64,
        pipeline: impl Into<String>,
        pipeline_revision: u64,
        build_id: impl Into<String>,
        build_number: u64,
        build_revision: u64,
        job_id: impl Into<String>,
        job_revision: u64,
        attempt_id: impl Into<String>,
        attempt_number: u32,
        attempt_revision: u64,
        commit_sha: impl Into<String>,
        commit_revision: u64,
        artifact_id: impl Into<String>,
        artifact_revision: u64,
        annotation_id: impl Into<String>,
        annotation_revision: u64,
        mission_id: impl Into<String>,
        mission_revision: u64,
        project_id: impl Into<String>,
        project_revision: u64,
        work_product_id: impl Into<String>,
        work_product_revision: u64,
    ) -> Result<Self> {
        Self::new(
            HostIdentity::new(host, host_revision)?,
            OrganizationIdentity::new(organization, organization_revision)?,
            PipelineIdentity::new(pipeline, pipeline_revision)?,
            BuildIdentity::new(build_id, build_number, build_revision)?,
            JobIdentity::new(job_id, job_revision)?,
            AttemptIdentity::new(attempt_id, attempt_number, attempt_revision)?,
            CommitIdentity::new(commit_sha, commit_revision)?,
            ArtifactIdentity::new(artifact_id, artifact_revision)?,
            AnnotationIdentity::new(annotation_id, annotation_revision)?,
            MissionScope::new(
                mission_id,
                mission_revision,
                project_id,
                project_revision,
                work_product_id,
                work_product_revision,
            )?,
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.host.validate()?;
        self.organization.validate()?;
        self.pipeline.validate()?;
        self.build.validate()?;
        self.job.validate()?;
        self.attempt.validate()?;
        self.commit.validate()?;
        self.artifact.validate()?;
        self.annotation.validate()?;
        self.mission.validate()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serialized(self)
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub fn host(&self) -> &HostIdentity {
        &self.host
    }

    pub fn organization(&self) -> &OrganizationIdentity {
        &self.organization
    }

    pub fn pipeline(&self) -> &PipelineIdentity {
        &self.pipeline
    }

    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }

    pub fn job(&self) -> &JobIdentity {
        &self.job
    }

    pub fn attempt(&self) -> &AttemptIdentity {
        &self.attempt
    }

    pub fn commit(&self) -> &CommitIdentity {
        &self.commit
    }

    pub fn artifact(&self) -> &ArtifactIdentity {
        &self.artifact
    }

    pub fn annotation(&self) -> &AnnotationIdentity {
        &self.annotation
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }
}

impl fmt::Debug for BuildkiteScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuildkiteScope")
            .field("scope_digest", &self.digest())
            .field("host", &self.host)
            .field("organization", &self.organization)
            .field("pipeline", &self.pipeline)
            .field("build", &self.build)
            .field("job", &self.job)
            .field("attempt", &self.attempt)
            .field("commit", &self.commit)
            .field("artifact", &self.artifact)
            .field("annotation", &self.annotation)
            .field("mission", &self.mission)
            .finish()
    }
}

/// Closed read-only permission set.  The exact set prevents write authority
/// from being smuggled into a Layer-1 registration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionSnapshot {
    permissions: BTreeSet<String>,
    revision: u64,
    digest: Digest,
}

impl PermissionSnapshot {
    pub fn read_only(revision: u64) -> Result<Self> {
        Self::new(
            Self::expected_permissions().into_iter().map(str::to_owned),
            revision,
        )
    }

    pub fn new(permissions: impl IntoIterator<Item = String>, revision: u64) -> Result<Self> {
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        let expected = Self::expected_permissions()
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if revision == 0
            || permissions != expected
            || permissions.iter().any(|permission| {
                permission.is_empty()
                    || permission.len() > 128
                    || permission.chars().any(char::is_control)
            })
        {
            return Err(BuildkitePipelineResultError::InvalidPermissionSnapshot);
        }
        let digest = Digest::from_parts(
            "buildkite-permission-snapshot/v1",
            &[
                (
                    "permissions",
                    permissions.iter().cloned().collect::<Vec<_>>().join(","),
                ),
                ("revision", revision.to_string()),
            ],
        );
        Ok(Self {
            permissions,
            revision,
            digest,
        })
    }

    fn expected_permissions() -> [&'static str; 10] {
        [
            "host.read",
            "organization.read",
            "pipeline.read",
            "build.read",
            "job.read",
            "attempt.read",
            "commit.read",
            "artifact.read",
            "annotation.read",
            "mission.scope",
        ]
    }

    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.permissions
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.permissions.iter().cloned(), self.revision)?;
        if expected.digest == self.digest {
            Ok(())
        } else {
            Err(BuildkitePipelineResultError::InvalidPermissionSnapshot)
        }
    }
}

/// Every Layer-1 transport is explicitly non-native and non-connected.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn claims_connected(self) -> bool {
        false
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Fake => "fake",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildState {
    Scheduled,
    Running,
    Passed,
    Failed,
    Canceled,
    Blocked,
    Unknown,
}

impl BuildState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Passed | Self::Failed | Self::Canceled | Self::Blocked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Waiting,
    Running,
    Passed,
    Failed,
    Canceled,
    Skipped,
    Blocked,
    Unknown,
}

impl JobState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Passed | Self::Failed | Self::Canceled | Self::Skipped | Self::Blocked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryState {
    NotRetried,
    Scheduled,
    Running,
    Passed,
    Failed,
    Canceled,
    Unknown,
}

impl RetryState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::NotRetried | Self::Passed | Self::Failed | Self::Canceled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionCompleteness {
    Complete,
    Partial,
    Truncated,
    Unavailable,
}

/// Explicit evidence that provider payloads and sensitive content were
/// dropped before a typed projection was returned.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RedactionEvidence {
    pub raw_provider_payload_retained: bool,
    pub raw_logs_retained: bool,
    pub raw_artifact_content_retained: bool,
    pub raw_annotation_body_retained: bool,
    pub secret_material_retained: bool,
    pub redacted_fields: BTreeSet<String>,
    pub redaction_digest: Digest,
}

impl RedactionEvidence {
    pub fn standard() -> Self {
        let redacted_fields = [
            "providerPayload",
            "logs",
            "artifactContent",
            "annotationBody",
            "secretMaterial",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        Self::from_fields(redacted_fields)
    }

    pub fn from_fields(redacted_fields: BTreeSet<String>) -> Self {
        let mut evidence = Self {
            raw_provider_payload_retained: false,
            raw_logs_retained: false,
            raw_artifact_content_retained: false,
            raw_annotation_body_retained: false,
            secret_material_retained: false,
            redacted_fields,
            redaction_digest: Digest::from_text("unsealed-buildkite-redaction"),
        };
        evidence.redaction_digest = evidence.calculate_digest();
        evidence
    }

    pub fn validate(&self) -> Result<()> {
        if self.raw_provider_payload_retained
            || self.raw_logs_retained
            || self.raw_artifact_content_retained
            || self.raw_annotation_body_retained
            || self.secret_material_retained
            || self.redacted_fields.is_empty()
            || self.redaction_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::RedactionViolation);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-redaction-evidence/v1",
            &[
                (
                    "fields",
                    self.redacted_fields
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("provider", self.raw_provider_payload_retained.to_string()),
                ("logs", self.raw_logs_retained.to_string()),
                ("artifact", self.raw_artifact_content_retained.to_string()),
                ("annotation", self.raw_annotation_body_retained.to_string()),
                ("secret", self.secret_material_retained.to_string()),
            ],
        )
    }

    pub fn digest(&self) -> &Digest {
        &self.redaction_digest
    }
}

/// Retry identity is kept separately from state so a retried job cannot be
/// mistaken for the original attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryIdentity {
    pub job_id: JobId,
    pub attempt_id: AttemptId,
    pub attempt_number: u32,
    pub state: RetryState,
    pub revision: u64,
    pub identity_digest: Digest,
}

impl RetryIdentity {
    pub fn new(
        job_id: impl Into<String>,
        attempt_id: impl Into<String>,
        attempt_number: u32,
        state: RetryState,
        revision: u64,
    ) -> Result<Self> {
        if attempt_number == 0 || attempt_number > MAX_RETRY_NUMBER || revision == 0 {
            return Err(BuildkitePipelineResultError::InvalidScope);
        }
        let mut identity = Self {
            job_id: JobId::new(job_id)?,
            attempt_id: AttemptId::new(attempt_id)?,
            attempt_number,
            state,
            revision,
            identity_digest: Digest::from_text("unsealed-buildkite-retry"),
        };
        identity.identity_digest = identity.calculate_digest();
        Ok(identity)
    }

    pub fn for_scope(scope: &BuildkiteScope, state: RetryState) -> Self {
        Self::new(
            scope.job.id.as_str().to_owned(),
            scope.attempt.id.as_str().to_owned(),
            scope.attempt.number,
            state,
            scope.attempt.revision,
        )
        .expect("validated scope produces retry identity")
    }

    pub fn validate(&self) -> Result<()> {
        self.job_id.validate()?;
        self.attempt_id.validate()?;
        if self.attempt_number == 0
            || self.attempt_number > MAX_RETRY_NUMBER
            || self.revision == 0
            || self.identity_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-retry-identity/v1",
            &[
                ("job", self.job_id.as_str().to_owned()),
                ("attempt", self.attempt_id.as_str().to_owned()),
                ("number", self.attempt_number.to_string()),
                ("state", format!("{:?}", self.state)),
                ("revision", self.revision.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildRecord {
    pub host: HostIdentity,
    pub organization: OrganizationIdentity,
    pub pipeline: PipelineIdentity,
    pub build: BuildIdentityWithNumber,
    pub commit: CommitIdentity,
    pub state: BuildState,
    pub retry_identity: RetryIdentity,
    pub observed_at_epoch_seconds: u64,
    pub response_bytes: u64,
    pub record_digest: Digest,
}

impl BuildRecord {
    pub fn for_scope(scope: &BuildkiteScope, state: BuildState, observed_at: u64) -> Self {
        Self::from_values(scope, state, RetryState::NotRetried, observed_at, 512)
    }

    pub fn from_values(
        scope: &BuildkiteScope,
        state: BuildState,
        retry_state: RetryState,
        observed_at: u64,
        response_bytes: u64,
    ) -> Self {
        let mut record = Self {
            host: scope.host.clone(),
            organization: scope.organization.clone(),
            pipeline: scope.pipeline.clone(),
            build: scope.build.clone(),
            commit: scope.commit.clone(),
            state,
            retry_identity: RetryIdentity::for_scope(scope, retry_state),
            observed_at_epoch_seconds: observed_at,
            response_bytes,
            record_digest: Digest::from_text("unsealed-buildkite-build-record"),
        };
        record.record_digest = record.calculate_digest();
        record
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.host.validate()?;
        self.organization.validate()?;
        self.pipeline.validate()?;
        self.build.validate()?;
        self.commit.validate()?;
        self.retry_identity.validate()?;
        if self.observed_at_epoch_seconds == 0
            || self.response_bytes > MAX_RESPONSE_BYTES as u64
            || self.record_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn matches_scope(&self, scope: &BuildkiteScope) -> bool {
        self.host == scope.host
            && self.organization == scope.organization
            && self.pipeline == scope.pipeline
            && self.build == scope.build
            && self.commit == scope.commit
            && self.retry_identity.job_id == scope.job.id
            && self.retry_identity.attempt_id == scope.attempt.id
            && self.retry_identity.attempt_number == scope.attempt.number
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-build-record/v1",
            &[
                ("host", serde_json::to_string(&self.host).expect("identity")),
                (
                    "organization",
                    serde_json::to_string(&self.organization).expect("identity"),
                ),
                (
                    "pipeline",
                    serde_json::to_string(&self.pipeline).expect("identity"),
                ),
                (
                    "build",
                    serde_json::to_string(&self.build).expect("identity"),
                ),
                (
                    "commit",
                    serde_json::to_string(&self.commit).expect("identity"),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "retry",
                    serde_json::to_string(&self.retry_identity).expect("retry identity"),
                ),
                ("observed", self.observed_at_epoch_seconds.to_string()),
                ("bytes", self.response_bytes.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobRecord {
    pub host: HostIdentity,
    pub organization: OrganizationIdentity,
    pub pipeline: PipelineIdentity,
    pub build: BuildIdentityWithNumber,
    pub job: JobIdentity,
    pub attempt: AttemptIdentity,
    pub commit: CommitIdentity,
    pub state: JobState,
    pub retry_identity: RetryIdentity,
    pub annotation_count: usize,
    pub artifact_count: usize,
    pub observed_at_epoch_seconds: u64,
    pub response_bytes: u64,
    pub redaction: RedactionEvidence,
    pub record_digest: Digest,
}

impl JobRecord {
    pub fn for_scope(scope: &BuildkiteScope, state: JobState, observed_at: u64) -> Self {
        Self::from_values(scope, state, RetryState::NotRetried, 1, 1, observed_at, 512)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        scope: &BuildkiteScope,
        state: JobState,
        retry_state: RetryState,
        annotation_count: usize,
        artifact_count: usize,
        observed_at: u64,
        response_bytes: u64,
    ) -> Self {
        let mut record = Self {
            host: scope.host.clone(),
            organization: scope.organization.clone(),
            pipeline: scope.pipeline.clone(),
            build: scope.build.clone(),
            job: scope.job.clone(),
            attempt: scope.attempt.clone(),
            commit: scope.commit.clone(),
            state,
            retry_identity: RetryIdentity::for_scope(scope, retry_state),
            annotation_count,
            artifact_count,
            observed_at_epoch_seconds: observed_at,
            response_bytes,
            redaction: RedactionEvidence::standard(),
            record_digest: Digest::from_text("unsealed-buildkite-job-record"),
        };
        record.record_digest = record.calculate_digest();
        record
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.host.validate()?;
        self.organization.validate()?;
        self.pipeline.validate()?;
        self.build.validate()?;
        self.job.validate()?;
        self.attempt.validate()?;
        self.commit.validate()?;
        self.retry_identity.validate()?;
        self.redaction.validate()?;
        if self.annotation_count > MAX_ANNOTATIONS
            || self.artifact_count > MAX_ARTIFACTS
            || self.observed_at_epoch_seconds == 0
            || self.response_bytes > MAX_RESPONSE_BYTES as u64
            || self.record_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn matches_scope(&self, scope: &BuildkiteScope) -> bool {
        self.host == scope.host
            && self.organization == scope.organization
            && self.pipeline == scope.pipeline
            && self.build == scope.build
            && self.job == scope.job
            && self.attempt == scope.attempt
            && self.commit == scope.commit
            && self.retry_identity.job_id == scope.job.id
            && self.retry_identity.attempt_id == scope.attempt.id
            && self.retry_identity.attempt_number == scope.attempt.number
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-job-record/v1",
            &[
                ("host", serde_json::to_string(&self.host).expect("identity")),
                (
                    "organization",
                    serde_json::to_string(&self.organization).expect("identity"),
                ),
                (
                    "pipeline",
                    serde_json::to_string(&self.pipeline).expect("identity"),
                ),
                (
                    "build",
                    serde_json::to_string(&self.build).expect("identity"),
                ),
                ("job", serde_json::to_string(&self.job).expect("identity")),
                (
                    "attempt",
                    serde_json::to_string(&self.attempt).expect("identity"),
                ),
                (
                    "commit",
                    serde_json::to_string(&self.commit).expect("identity"),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "retry",
                    serde_json::to_string(&self.retry_identity).expect("retry identity"),
                ),
                ("annotations", self.annotation_count.to_string()),
                ("artifacts", self.artifact_count.to_string()),
                ("observed", self.observed_at_epoch_seconds.to_string()),
                ("bytes", self.response_bytes.to_string()),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationStyle {
    Info,
    Success,
    Warning,
    Error,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnotationMetadata {
    pub host: HostIdentity,
    pub organization: OrganizationIdentity,
    pub pipeline: PipelineIdentity,
    pub build: BuildIdentityWithNumber,
    pub job: JobIdentity,
    pub attempt: AttemptIdentity,
    pub commit: CommitIdentity,
    pub annotation: AnnotationIdentity,
    pub context: String,
    pub style: AnnotationStyle,
    pub body_digest: Digest,
    pub body_bytes: u64,
    pub redaction: RedactionEvidence,
    pub observed_at_epoch_seconds: u64,
    pub response_bytes: u64,
    pub annotation_digest: Digest,
}

impl AnnotationMetadata {
    pub fn for_scope(scope: &BuildkiteScope, observed_at: u64) -> Self {
        Self::from_values(
            scope,
            "default",
            AnnotationStyle::Info,
            Digest::from_text("redacted-buildkite-annotation-body"),
            0,
            observed_at,
            512,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        scope: &BuildkiteScope,
        context: impl Into<String>,
        style: AnnotationStyle,
        body_digest: Digest,
        body_bytes: u64,
        observed_at: u64,
        response_bytes: u64,
    ) -> Self {
        let mut metadata = Self {
            host: scope.host.clone(),
            organization: scope.organization.clone(),
            pipeline: scope.pipeline.clone(),
            build: scope.build.clone(),
            job: scope.job.clone(),
            attempt: scope.attempt.clone(),
            commit: scope.commit.clone(),
            annotation: scope.annotation.clone(),
            context: context.into(),
            style,
            body_digest,
            body_bytes,
            redaction: RedactionEvidence::standard(),
            observed_at_epoch_seconds: observed_at,
            response_bytes,
            annotation_digest: Digest::from_text("unsealed-buildkite-annotation"),
        };
        metadata.annotation_digest = metadata.calculate_digest();
        metadata
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.host.validate()?;
        self.organization.validate()?;
        self.pipeline.validate()?;
        self.build.validate()?;
        self.job.validate()?;
        self.attempt.validate()?;
        self.commit.validate()?;
        self.annotation.validate()?;
        validate_text(&self.context, "annotationContext", 256, false)?;
        self.body_digest.validate()?;
        self.redaction.validate()?;
        if self.body_bytes > MAX_METADATA_BYTES
            || self.observed_at_epoch_seconds == 0
            || self.response_bytes > MAX_RESPONSE_BYTES as u64
            || self.annotation_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn matches_scope(&self, scope: &BuildkiteScope) -> bool {
        self.host == scope.host
            && self.organization == scope.organization
            && self.pipeline == scope.pipeline
            && self.build == scope.build
            && self.job == scope.job
            && self.attempt == scope.attempt
            && self.commit == scope.commit
            && self.annotation == scope.annotation
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-annotation-metadata/v1",
            &[
                ("host", serde_json::to_string(&self.host).expect("identity")),
                (
                    "organization",
                    serde_json::to_string(&self.organization).expect("identity"),
                ),
                (
                    "pipeline",
                    serde_json::to_string(&self.pipeline).expect("identity"),
                ),
                (
                    "build",
                    serde_json::to_string(&self.build).expect("identity"),
                ),
                ("job", serde_json::to_string(&self.job).expect("identity")),
                (
                    "attempt",
                    serde_json::to_string(&self.attempt).expect("identity"),
                ),
                (
                    "commit",
                    serde_json::to_string(&self.commit).expect("identity"),
                ),
                (
                    "annotation",
                    serde_json::to_string(&self.annotation).expect("identity"),
                ),
                ("context", self.context.clone()),
                ("style", format!("{:?}", self.style)),
                ("body", self.body_digest.as_str().to_owned()),
                ("body_bytes", self.body_bytes.to_string()),
                ("observed", self.observed_at_epoch_seconds.to_string()),
                ("bytes", self.response_bytes.to_string()),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub host: HostIdentity,
    pub organization: OrganizationIdentity,
    pub pipeline: PipelineIdentity,
    pub build: BuildIdentityWithNumber,
    pub job: JobIdentity,
    pub attempt: AttemptIdentity,
    pub commit: CommitIdentity,
    pub artifact: ArtifactIdentity,
    pub filename: String,
    pub mime_type: Option<String>,
    pub size_bytes: u64,
    pub content_digest: Option<Digest>,
    pub download_url_digest: Option<Digest>,
    pub redaction: RedactionEvidence,
    pub observed_at_epoch_seconds: u64,
    pub response_bytes: u64,
    pub artifact_digest: Digest,
}

impl ArtifactMetadata {
    pub fn for_scope(scope: &BuildkiteScope, observed_at: u64) -> Self {
        Self::from_values(
            scope,
            "artifact.metadata",
            Some("application/octet-stream"),
            0,
            None,
            None,
            observed_at,
            512,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_values(
        scope: &BuildkiteScope,
        filename: impl Into<String>,
        mime_type: Option<impl Into<String>>,
        size_bytes: u64,
        content_digest: Option<Digest>,
        download_url_digest: Option<Digest>,
        observed_at: u64,
        response_bytes: u64,
    ) -> Self {
        let mut metadata = Self {
            host: scope.host.clone(),
            organization: scope.organization.clone(),
            pipeline: scope.pipeline.clone(),
            build: scope.build.clone(),
            job: scope.job.clone(),
            attempt: scope.attempt.clone(),
            commit: scope.commit.clone(),
            artifact: scope.artifact.clone(),
            filename: filename.into(),
            mime_type: mime_type.map(Into::into),
            size_bytes,
            content_digest,
            download_url_digest,
            redaction: RedactionEvidence::standard(),
            observed_at_epoch_seconds: observed_at,
            response_bytes,
            artifact_digest: Digest::from_text("unsealed-buildkite-artifact"),
        };
        metadata.artifact_digest = metadata.calculate_digest();
        metadata
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.host.validate()?;
        self.organization.validate()?;
        self.pipeline.validate()?;
        self.build.validate()?;
        self.job.validate()?;
        self.attempt.validate()?;
        self.commit.validate()?;
        self.artifact.validate()?;
        validate_text(&self.filename, "artifactFilename", 512, true)?;
        if let Some(mime_type) = &self.mime_type {
            validate_text(mime_type, "artifactMimeType", 256, false)?;
        }
        if let Some(digest) = &self.content_digest {
            digest.validate()?;
        }
        if let Some(digest) = &self.download_url_digest {
            digest.validate()?;
        }
        self.redaction.validate()?;
        if self.size_bytes > (1_u64 << 40)
            || self.observed_at_epoch_seconds == 0
            || self.response_bytes > MAX_RESPONSE_BYTES as u64
            || self.artifact_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn matches_scope(&self, scope: &BuildkiteScope) -> bool {
        self.host == scope.host
            && self.organization == scope.organization
            && self.pipeline == scope.pipeline
            && self.build == scope.build
            && self.job == scope.job
            && self.attempt == scope.attempt
            && self.commit == scope.commit
            && self.artifact == scope.artifact
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-artifact-metadata/v1",
            &[
                ("host", serde_json::to_string(&self.host).expect("identity")),
                (
                    "organization",
                    serde_json::to_string(&self.organization).expect("identity"),
                ),
                (
                    "pipeline",
                    serde_json::to_string(&self.pipeline).expect("identity"),
                ),
                (
                    "build",
                    serde_json::to_string(&self.build).expect("identity"),
                ),
                ("job", serde_json::to_string(&self.job).expect("identity")),
                (
                    "attempt",
                    serde_json::to_string(&self.attempt).expect("identity"),
                ),
                (
                    "commit",
                    serde_json::to_string(&self.commit).expect("identity"),
                ),
                (
                    "artifact",
                    serde_json::to_string(&self.artifact).expect("identity"),
                ),
                ("filename", self.filename.clone()),
                ("mime", self.mime_type.clone().unwrap_or_default()),
                ("size", self.size_bytes.to_string()),
                (
                    "content",
                    self.content_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "url",
                    self.download_url_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                ("observed", self.observed_at_epoch_seconds.to_string()),
                ("bytes", self.response_bytes.to_string()),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

fn validate_projection_limits(
    count: usize,
    maximum: usize,
    pages_read: usize,
    response_bytes: u64,
) -> Result<()> {
    if count == 0 || count > maximum || pages_read == 0 || pages_read > crate::MAX_PAGES {
        return Err(BuildkitePipelineResultError::PaginationLimit);
    }
    if response_bytes > MAX_RESPONSE_BYTES as u64 {
        return Err(BuildkitePipelineResultError::ResponseTooLarge);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildsProjection {
    pub scope_digest: Digest,
    pub builds: Vec<BuildRecord>,
    pub pages_read: usize,
    pub response_bytes: u64,
    pub completeness: ProjectionCompleteness,
    pub response_truncated: bool,
    pub provenance: TransportProvenance,
    pub retry_evidence: Vec<RetryIdentity>,
    pub redaction: RedactionEvidence,
    pub projection_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl BuildsProjection {
    pub fn new(
        scope: &BuildkiteScope,
        builds: Vec<BuildRecord>,
        pages_read: usize,
        response_bytes: u64,
        completeness: ProjectionCompleteness,
        response_truncated: bool,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_projection_limits(builds.len(), MAX_BUILDS, pages_read, response_bytes)?;
        for build in &builds {
            build.validate_integrity()?;
            if !build.matches_scope(scope) {
                return Err(BuildkitePipelineResultError::OutOfScope);
            }
        }
        let retry_evidence = builds
            .iter()
            .map(|build| build.retry_identity.clone())
            .collect();
        let mut projection = Self {
            scope_digest: scope.digest(),
            builds,
            pages_read,
            response_bytes,
            completeness,
            response_truncated,
            provenance,
            retry_evidence,
            redaction: RedactionEvidence::standard(),
            projection_digest: Digest::from_text("unsealed-buildkite-builds-projection"),
            connected: false,
            native: false,
        };
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn for_scope(scope: &BuildkiteScope, provenance: TransportProvenance) -> Self {
        Self::new(
            scope,
            vec![BuildRecord::for_scope(
                scope,
                BuildState::Passed,
                1_744_550_400,
            )],
            1,
            512,
            ProjectionCompleteness::Complete,
            false,
            provenance,
        )
        .expect("scope fixture is bounded")
    }

    pub fn validate_integrity(&self) -> Result<()> {
        validate_projection_limits(
            self.builds.len(),
            MAX_BUILDS,
            self.pages_read,
            self.response_bytes,
        )?;
        if self.scope_digest.validate().is_err()
            || self.connected
            || self.native
            || self.redaction.validate().is_err()
            || self.projection_digest != self.calculate_digest()
            || self.retry_evidence
                != self
                    .builds
                    .iter()
                    .map(|b| b.retry_identity.clone())
                    .collect::<Vec<_>>()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        for build in &self.builds {
            build.validate_integrity()?;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.completeness == ProjectionCompleteness::Complete && !self.response_truncated
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-builds-projection/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "builds",
                    self.builds
                        .iter()
                        .map(|entry| entry.record_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("pages", self.pages_read.to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("completeness", format!("{:?}", self.completeness)),
                ("truncated", self.response_truncated.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobsProjection {
    pub scope_digest: Digest,
    pub jobs: Vec<JobRecord>,
    pub pages_read: usize,
    pub response_bytes: u64,
    pub completeness: ProjectionCompleteness,
    pub response_truncated: bool,
    pub provenance: TransportProvenance,
    pub retry_evidence: Vec<RetryIdentity>,
    pub redaction: RedactionEvidence,
    pub projection_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl JobsProjection {
    pub fn new(
        scope: &BuildkiteScope,
        jobs: Vec<JobRecord>,
        pages_read: usize,
        response_bytes: u64,
        completeness: ProjectionCompleteness,
        response_truncated: bool,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_projection_limits(jobs.len(), MAX_JOBS, pages_read, response_bytes)?;
        for job in &jobs {
            job.validate_integrity()?;
            if !job.matches_scope(scope) {
                return Err(BuildkitePipelineResultError::OutOfScope);
            }
        }
        let retry_evidence = jobs.iter().map(|job| job.retry_identity.clone()).collect();
        let mut projection = Self {
            scope_digest: scope.digest(),
            jobs,
            pages_read,
            response_bytes,
            completeness,
            response_truncated,
            provenance,
            retry_evidence,
            redaction: RedactionEvidence::standard(),
            projection_digest: Digest::from_text("unsealed-buildkite-jobs-projection"),
            connected: false,
            native: false,
        };
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn for_scope(scope: &BuildkiteScope, provenance: TransportProvenance) -> Self {
        Self::new(
            scope,
            vec![JobRecord::for_scope(scope, JobState::Passed, 1_744_550_400)],
            1,
            512,
            ProjectionCompleteness::Complete,
            false,
            provenance,
        )
        .expect("scope fixture is bounded")
    }

    pub fn validate_integrity(&self) -> Result<()> {
        validate_projection_limits(
            self.jobs.len(),
            MAX_JOBS,
            self.pages_read,
            self.response_bytes,
        )?;
        if self.scope_digest.validate().is_err()
            || self.connected
            || self.native
            || self.redaction.validate().is_err()
            || self.projection_digest != self.calculate_digest()
            || self.retry_evidence
                != self
                    .jobs
                    .iter()
                    .map(|j| j.retry_identity.clone())
                    .collect::<Vec<_>>()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        for job in &self.jobs {
            job.validate_integrity()?;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.completeness == ProjectionCompleteness::Complete && !self.response_truncated
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-jobs-projection/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "jobs",
                    self.jobs
                        .iter()
                        .map(|entry| entry.record_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("pages", self.pages_read.to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("completeness", format!("{:?}", self.completeness)),
                ("truncated", self.response_truncated.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnnotationsProjection {
    pub scope_digest: Digest,
    pub annotations: Vec<AnnotationMetadata>,
    pub pages_read: usize,
    pub response_bytes: u64,
    pub completeness: ProjectionCompleteness,
    pub response_truncated: bool,
    pub provenance: TransportProvenance,
    pub redaction: RedactionEvidence,
    pub projection_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl AnnotationsProjection {
    pub fn new(
        scope: &BuildkiteScope,
        annotations: Vec<AnnotationMetadata>,
        pages_read: usize,
        response_bytes: u64,
        completeness: ProjectionCompleteness,
        response_truncated: bool,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_projection_limits(
            annotations.len(),
            MAX_ANNOTATIONS,
            pages_read,
            response_bytes,
        )?;
        for annotation in &annotations {
            annotation.validate_integrity()?;
            if !annotation.matches_scope(scope) {
                return Err(BuildkitePipelineResultError::OutOfScope);
            }
        }
        let mut projection = Self {
            scope_digest: scope.digest(),
            annotations,
            pages_read,
            response_bytes,
            completeness,
            response_truncated,
            provenance,
            redaction: RedactionEvidence::standard(),
            projection_digest: Digest::from_text("unsealed-buildkite-annotations-projection"),
            connected: false,
            native: false,
        };
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn for_scope(scope: &BuildkiteScope, provenance: TransportProvenance) -> Self {
        Self::new(
            scope,
            vec![AnnotationMetadata::for_scope(scope, 1_744_550_400)],
            1,
            512,
            ProjectionCompleteness::Complete,
            false,
            provenance,
        )
        .expect("scope fixture is bounded")
    }

    pub fn validate_integrity(&self) -> Result<()> {
        validate_projection_limits(
            self.annotations.len(),
            MAX_ANNOTATIONS,
            self.pages_read,
            self.response_bytes,
        )?;
        if self.scope_digest.validate().is_err()
            || self.connected
            || self.native
            || self.redaction.validate().is_err()
            || self.projection_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        for annotation in &self.annotations {
            annotation.validate_integrity()?;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.completeness == ProjectionCompleteness::Complete && !self.response_truncated
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-annotations-projection/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "annotations",
                    self.annotations
                        .iter()
                        .map(|entry| entry.annotation_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("pages", self.pages_read.to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("completeness", format!("{:?}", self.completeness)),
                ("truncated", self.response_truncated.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactMetadataProjection {
    pub scope_digest: Digest,
    pub artifacts: Vec<ArtifactMetadata>,
    pub pages_read: usize,
    pub response_bytes: u64,
    pub completeness: ProjectionCompleteness,
    pub response_truncated: bool,
    pub provenance: TransportProvenance,
    pub redaction: RedactionEvidence,
    pub projection_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl ArtifactMetadataProjection {
    pub fn new(
        scope: &BuildkiteScope,
        artifacts: Vec<ArtifactMetadata>,
        pages_read: usize,
        response_bytes: u64,
        completeness: ProjectionCompleteness,
        response_truncated: bool,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_projection_limits(artifacts.len(), MAX_ARTIFACTS, pages_read, response_bytes)?;
        for artifact in &artifacts {
            artifact.validate_integrity()?;
            if !artifact.matches_scope(scope) {
                return Err(BuildkitePipelineResultError::OutOfScope);
            }
        }
        let mut projection = Self {
            scope_digest: scope.digest(),
            artifacts,
            pages_read,
            response_bytes,
            completeness,
            response_truncated,
            provenance,
            redaction: RedactionEvidence::standard(),
            projection_digest: Digest::from_text("unsealed-buildkite-artifacts-projection"),
            connected: false,
            native: false,
        };
        projection.projection_digest = projection.calculate_digest();
        Ok(projection)
    }

    pub fn for_scope(scope: &BuildkiteScope, provenance: TransportProvenance) -> Self {
        Self::new(
            scope,
            vec![ArtifactMetadata::for_scope(scope, 1_744_550_400)],
            1,
            512,
            ProjectionCompleteness::Complete,
            false,
            provenance,
        )
        .expect("scope fixture is bounded")
    }

    pub fn validate_integrity(&self) -> Result<()> {
        validate_projection_limits(
            self.artifacts.len(),
            MAX_ARTIFACTS,
            self.pages_read,
            self.response_bytes,
        )?;
        if self.scope_digest.validate().is_err()
            || self.connected
            || self.native
            || self.redaction.validate().is_err()
            || self.projection_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        for artifact in &self.artifacts {
            artifact.validate_integrity()?;
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.completeness == ProjectionCompleteness::Complete && !self.response_truncated
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-artifacts-projection/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "artifacts",
                    self.artifacts
                        .iter()
                        .map(|entry| entry.artifact_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("pages", self.pages_read.to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("completeness", format!("{:?}", self.completeness)),
                ("truncated", self.response_truncated.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

pub type BuildkiteBuildsProjection = BuildsProjection;
pub type BuildkiteJobsProjection = JobsProjection;
pub type BuildkiteAnnotationsProjection = AnnotationsProjection;
pub type BuildkiteArtifactMetadataProjection = ArtifactMetadataProjection;

/// Combined typed evidence consumed by the Mission seam.  It is always below
/// kernel authority and never asserts Connected/native status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct BuildkitePipelineResultEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub builds: BuildsProjection,
    pub jobs: JobsProjection,
    pub annotations: AnnotationsProjection,
    pub artifacts: ArtifactMetadataProjection,
    pub retry_evidence: Vec<RetryIdentity>,
    pub redaction: RedactionEvidence,
    pub provenance: TransportProvenance,
    pub response_truncated: bool,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl BuildkitePipelineResultEvidence {
    pub fn new(
        scope: &BuildkiteScope,
        builds: BuildsProjection,
        jobs: JobsProjection,
        annotations: AnnotationsProjection,
        artifacts: ArtifactMetadataProjection,
    ) -> Result<Self> {
        builds.validate_integrity()?;
        jobs.validate_integrity()?;
        annotations.validate_integrity()?;
        artifacts.validate_integrity()?;
        let scope_digest = scope.digest();
        if builds.scope_digest != scope_digest
            || jobs.scope_digest != scope_digest
            || annotations.scope_digest != scope_digest
            || artifacts.scope_digest != scope_digest
            || builds.provenance != jobs.provenance
            || builds.provenance != annotations.provenance
            || builds.provenance != artifacts.provenance
        {
            return Err(BuildkitePipelineResultError::ScopeMismatch);
        }
        let retry_evidence = builds
            .retry_evidence
            .iter()
            .chain(jobs.retry_evidence.iter())
            .cloned()
            .collect::<Vec<_>>();
        if retry_evidence.len() > MAX_ATTEMPTS {
            return Err(BuildkitePipelineResultError::PaginationLimit);
        }
        let response_truncated = !builds.is_complete()
            || !jobs.is_complete()
            || !annotations.is_complete()
            || !artifacts.is_complete();
        let provenance = builds.provenance;
        let mut evidence = Self {
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(crate::CONTRACT_DIGEST)?,
            scope_digest,
            builds,
            jobs,
            annotations,
            artifacts,
            retry_evidence,
            redaction: RedactionEvidence::standard(),
            provenance,
            response_truncated,
            evidence_digest: Digest::from_text("unsealed-buildkite-evidence"),
            connected: false,
            native: false,
        };
        evidence.evidence_digest = evidence.calculate_digest();
        Ok(evidence)
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.contract_version != crate::CONTRACT_VERSION
            || self.contract_digest.as_str() != crate::contract_digest()
            || self.scope_digest.validate().is_err()
            || self.connected
            || self.native
            || self.redaction.validate().is_err()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        self.builds.validate_integrity()?;
        self.jobs.validate_integrity()?;
        self.annotations.validate_integrity()?;
        self.artifacts.validate_integrity()?;
        if self.provenance != self.builds.provenance
            || self.provenance != self.jobs.provenance
            || self.provenance != self.annotations.provenance
            || self.provenance != self.artifacts.provenance
        {
            return Err(BuildkitePipelineResultError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        !self.response_truncated
            && self.builds.is_complete()
            && self.jobs.is_complete()
            && self.annotations.is_complete()
            && self.artifacts.is_complete()
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn computed_digest(&self) -> Digest {
        self.calculate_digest()
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "buildkite-pipeline-result-evidence/v1",
            &[
                ("contract", self.contract_version.clone()),
                ("contract_digest", self.contract_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("builds", self.builds.projection_digest.as_str().to_owned()),
                ("jobs", self.jobs.projection_digest.as_str().to_owned()),
                (
                    "annotations",
                    self.annotations.projection_digest.as_str().to_owned(),
                ),
                (
                    "artifacts",
                    self.artifacts.projection_digest.as_str().to_owned(),
                ),
                (
                    "retry",
                    self.retry_evidence
                        .iter()
                        .map(|retry| retry.identity_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "redaction",
                    self.redaction.redaction_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("truncated", self.response_truncated.to_string()),
            ],
        )
    }
}
