//! Typed W&B evaluation-result contract models.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{canonical_digest, sha256_digest};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_METRIC_NAME_BYTES: usize = 128;
pub const MAX_REVISION_BYTES: usize = 128;
pub const MAX_PAGE_SIZE: u16 = 25;
pub const MAX_PAGES: u16 = 1;
pub const MAX_HISTORY_SAMPLES: usize = 512;
pub const MAX_SUMMARY_METRICS: usize = 32;
pub const MAX_ARTIFACTS: usize = 32;
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
pub const MAX_AGE_MS: u64 = 86_400_000;

/// Typed errors for the W&B Layer-1 boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WandbEvaluationError {
    #[error("{field} is empty, invalid, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("the W&B API host must be a valid HTTPS origin")]
    InvalidHost,
    #[error("{field} is not a valid bounded revision")]
    InvalidRevision { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("the exact W&B evaluation scope is invalid")]
    InvalidScope,
    #[error("the W&B permission snapshot is invalid or over-privileged")]
    InvalidPermissionSnapshot,
    #[error("the registered operation requires permission {permission}")]
    MissingPermission { permission: &'static str },
    #[error(
        "a version, contract, provider, API, permission, revision, metric, and scope registration is required"
    )]
    RegistrationRequired,
    #[error("the W&B registration has been revoked")]
    RegistrationRevoked,
    #[error("the W&B registration digest is invalid or tampered")]
    RegistrationTampered,
    #[error("the contract version or digest drifted")]
    ContractDrift,
    #[error("the provider manifest is missing or drifted")]
    ProviderManifestDrift,
    #[error("the W&B Public API version or digest drifted")]
    ApiDrift,
    #[error("the provider is not bound to the requested exact scope")]
    ScopeMismatch,
    #[error("the W&B entity does not match the exact scope")]
    EntityMismatch,
    #[error("the W&B project or project revision drifted")]
    ProjectRevisionDrift,
    #[error("the W&B run does not match the exact scope")]
    RunMismatch,
    #[error("the W&B run revision drifted")]
    RunRevisionDrift,
    #[error("the returned metric is not in the allowlist")]
    MetricMismatch,
    #[error("the metric revision or metric digest drifted")]
    MetricRevisionDrift,
    #[error("the config or config revision drifted")]
    ConfigRevisionDrift,
    #[error("the artifact is outside the exact allowlist")]
    ArtifactMismatch,
    #[error("the artifact revision or artifact digest drifted")]
    ArtifactRevisionDrift,
    #[error("the commit or commit revision drifted")]
    CommitRevisionDrift,
    #[error("the Mission is outside the exact scope")]
    MissionMismatch,
    #[error("the Hartevo Project is outside the exact scope")]
    ProjectBindingMismatch,
    #[error("the Work Product is outside the exact scope")]
    WorkProductMismatch,
    #[error("the permission revision or digest drifted")]
    PermissionDrift,
    #[error("the aggregate revision digest drifted")]
    RevisionDrift,
    #[error("the evaluation read request is invalid")]
    InvalidRequest,
    #[error("the requested page size must be between 1 and {maximum}")]
    InvalidPageSize { maximum: u16 },
    #[error("the requested history sample limit must be between 1 and {maximum}")]
    InvalidHistoryLimit { maximum: usize },
    #[error("the requested response byte cap must be between 1 and {maximum}")]
    InvalidByteLimit { maximum: usize },
    #[error("the bounded {field} list exceeded {maximum} items")]
    BoundExceeded { field: &'static str, maximum: usize },
    #[error("the evaluation pagination cursor is invalid for this scope")]
    CursorMismatch,
    #[error("the evaluation pagination cursor repeated")]
    CursorLoop,
    #[error("the evaluation page sequence is invalid")]
    PaginationMismatch,
    #[error("the provider response was stale and cannot claim current evidence")]
    StaleResult,
    #[error("the provider response is invalid or exceeds the bounded contract")]
    InvalidResponse,
    #[error("the provider response fingerprint failed its tamper check")]
    ResponseTampered,
    #[error("the proposal fingerprint failed its tamper check")]
    ProposalTampered,
    #[error("the evidence is not redacted or contains forbidden raw content")]
    RedactionViolation,
    #[error("fixture, recording, loopback, or BLOCKED_ENV evidence cannot be native or connected")]
    NativeClassificationMismatch,
    #[error("the requested operation is outside the Layer-1 read-only authority")]
    MutationForbidden,
    #[error("a provider error occurred: {0}")]
    Provider(WandbProviderError),
}

/// Provider failures never contain response bodies, API tokens, or raw
/// provider error text.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WandbProviderError {
    #[error("BLOCKED_ENV: native W&B API-token resolution or HTTPS transport is unavailable")]
    BlockedEnv,
    #[error("W&B returned HTTP 401")]
    Unauthorized401,
    #[error("W&B returned HTTP 403")]
    Forbidden403,
    #[error("W&B returned HTTP 404")]
    NotFound404,
    #[error("W&B returned HTTP 409 ({reason:?})")]
    Conflict409 { reason: ConflictReason },
    #[error("W&B returned HTTP 429")]
    RateLimited429 { retry_after_seconds: Option<u64> },
    #[error("W&B request timed out")]
    Timeout,
    #[error("W&B returned HTTP {status}")]
    Server5xx { status: u16 },
    #[error("W&B access was lost")]
    AccessLoss,
    #[error("the W&B registration has been revoked")]
    RegistrationRevoked,
    #[error("W&B scope did not match the registered exact scope")]
    ScopeMismatch,
    #[error("W&B permission revision drifted")]
    PermissionDrift,
    #[error("W&B API revision drifted")]
    ApiDrift,
    #[error("W&B metric revision drifted")]
    MetricRevisionDrift,
    #[error("W&B config revision drifted")]
    ConfigRevisionDrift,
    #[error("W&B artifact revision drifted")]
    ArtifactRevisionDrift,
    #[error("W&B commit revision drifted")]
    CommitRevisionDrift,
    #[error("W&B response was stale")]
    StaleResult,
    #[error("W&B response fingerprint was tampered")]
    ResponseTampered,
    #[error("W&B response was invalid or exceeded a bound")]
    InvalidResponse,
    #[error("W&B pagination cursor repeated")]
    CursorLoop,
    #[error("mutation operation is outside the Layer-1 provider authority")]
    MutationForbidden,
    #[error("credential resolution failed: {0}")]
    Credential(#[from] CredentialResolutionError),
}

impl WandbProviderError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized401 => Some(401),
            Self::Forbidden403 => Some(403),
            Self::NotFound404 => Some(404),
            Self::Conflict409 { .. } => Some(409),
            Self::RateLimited429 { .. } => Some(429),
            Self::Server5xx { status } => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLoss
            | Self::RegistrationRevoked
            | Self::ScopeMismatch
            | Self::PermissionDrift
            | Self::ApiDrift
            | Self::MetricRevisionDrift
            | Self::ConfigRevisionDrift
            | Self::ArtifactRevisionDrift
            | Self::CommitRevisionDrift
            | Self::StaleResult
            | Self::ResponseTampered
            | Self::InvalidResponse
            | Self::CursorLoop
            | Self::MutationForbidden
            | Self::Credential(_) => None,
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized401 | Self::Forbidden403 | Self::NotFound404 | Self::AccessLoss
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictReason {
    ScopeDrift,
    ApiDrift,
    PermissionDrift,
    RevisionDrift,
    MetricDrift,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CredentialResolutionError {
    #[error("BLOCKED_ENV: native secret resolution is unavailable")]
    BlockedEnv,
    #[error("the opaque API-token reference is invalid")]
    InvalidReference,
}

/// Lower-case SHA-256 content/fence digest.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_hex(bytes: impl AsRef<[u8]>) -> Self {
        Self(crate::hex_encode(bytes))
    }

    #[must_use]
    pub fn from_text(value: &str) -> Self {
        sha256_digest(value.as_bytes())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_sha256(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    pub fn validate(&self, field: &'static str) -> Result<(), WandbEvaluationError> {
        if !self.is_sha256() {
            return Err(WandbEvaluationError::InvalidDigest { field });
        }
        Ok(())
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

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

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

    pub fn parse(value: &str) -> Result<Self, WandbEvaluationError> {
        let parts = value.split('.').collect::<Vec<_>>();
        let [major, minor, patch] = parts.as_slice() else {
            return Err(WandbEvaluationError::InvalidRevision {
                field: "plugin_version",
            });
        };
        Ok(Self {
            major: major
                .parse()
                .map_err(|_| WandbEvaluationError::InvalidRevision {
                    field: "plugin_version",
                })?,
            minor: minor
                .parse()
                .map_err(|_| WandbEvaluationError::InvalidRevision {
                    field: "plugin_version",
                })?,
            patch: patch
                .parse()
                .map_err(|_| WandbEvaluationError::InvalidRevision {
                    field: "plugin_version",
                })?,
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretKind {
    ApiToken,
}

/// Opaque Layer-2 API-token binding.
///
/// This type intentionally does not implement `Serialize` or `Deserialize`.
/// The constructor hashes the supplied host handle and drops it immediately;
/// neither the handle nor token material is retained or exposed by `Debug`.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

impl SecretReference {
    pub fn api_token(
        opaque_handle: impl AsRef<str>,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, WandbEvaluationError> {
        let opaque_handle = opaque_handle.as_ref();
        if opaque_handle.trim().is_empty()
            || opaque_handle.len() > MAX_IDENTIFIER_BYTES
            || opaque_handle.chars().any(char::is_control)
        {
            return Err(WandbEvaluationError::InvalidIdentifier {
                field: "opaque_api_token_reference",
            });
        }
        scope_digest.validate("secret_scope_digest")?;
        revision.validate("secret_reference_revision")?;
        Ok(Self {
            kind: SecretKind::ApiToken,
            reference_digest: Digest::from_text(&format!(
                "hartevo:wandb:api-token-reference:v1:{opaque_handle}:{revision}"
            )),
            scope_digest,
            revision,
        })
    }

    pub fn new(
        opaque_handle: impl AsRef<str>,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, WandbEvaluationError> {
        Self::api_token(opaque_handle, scope_digest, revision)
    }

    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
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
    pub fn revision(&self) -> &Revision {
        &self.revision
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.reference_digest.validate("secret_reference_digest")?;
        self.scope_digest.validate("secret_scope_digest")?;
        self.revision.validate("secret_reference_revision")
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $maximum:expr) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, WandbEvaluationError> {
                let value = value.into();
                validate_identifier(&value, $field, $maximum)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), WandbEvaluationError> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_identifier!(EntityId, "entity", MAX_IDENTIFIER_BYTES);
bounded_identifier!(WandbProjectId, "wandb_project", MAX_IDENTIFIER_BYTES);
bounded_identifier!(RunId, "run", MAX_IDENTIFIER_BYTES);
bounded_identifier!(MetricName, "metric_name", MAX_METRIC_NAME_BYTES);
bounded_identifier!(ArtifactId, "artifact", MAX_IDENTIFIER_BYTES);
bounded_identifier!(CommitId, "commit", MAX_IDENTIFIER_BYTES);
bounded_identifier!(MissionId, "mission", MAX_IDENTIFIER_BYTES);
bounded_identifier!(ProjectId, "hartevo_project", MAX_IDENTIFIER_BYTES);
bounded_identifier!(WorkProductId, "work_product", MAX_IDENTIFIER_BYTES);

/// Compatibility aliases that keep the provider terms explicit at call sites.
pub type WandbEntityId = EntityId;
pub type WandbRunId = RunId;

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(String);

impl Revision {
    pub fn new(value: impl Into<String>) -> Result<Self, WandbEvaluationError> {
        let value = value.into();
        validate_revision(&value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self(String::from("v1"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self, field: &'static str) -> Result<(), WandbEvaluationError> {
        validate_revision(&self.0, field)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct WandbHost(String);

impl WandbHost {
    pub fn new(value: impl Into<String>) -> Result<Self, WandbEvaluationError> {
        let value = value.into();
        validate_host(&value)?;
        Ok(Self(value.trim_end_matches('/').to_ascii_lowercase()))
    }

    #[must_use]
    pub fn api() -> Self {
        Self(String::from("https://api.wandb.ai"))
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self::api()
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WandbHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbProjectScope {
    pub id: WandbProjectId,
    pub revision: Revision,
    pub digest: Digest,
}

impl WandbProjectScope {
    pub fn new(id: WandbProjectId, revision: Revision) -> Result<Self, WandbEvaluationError> {
        id.validate()?;
        revision.validate("wandb_project_revision")?;
        let mut scope = Self {
            id,
            revision,
            digest: Digest::from_text("uninitialized-wandb-project"),
        };
        scope.digest = canonical_digest(&ProjectIdentity {
            id: scope.id.clone(),
            revision: scope.revision.clone(),
        });
        Ok(scope)
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self::new(
            WandbProjectId::new("project-fixture").expect("fixture project"),
            Revision::fixture(),
        )
        .expect("fixture project scope")
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.id.validate()?;
        self.revision.validate("wandb_project_revision")?;
        self.digest.validate("wandb_project_digest")?;
        if self.digest
            != canonical_digest(&ProjectIdentity {
                id: self.id.clone(),
                revision: self.revision.clone(),
            })
        {
            return Err(WandbEvaluationError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbRunScope {
    pub id: RunId,
    pub revision: Revision,
    pub digest: Digest,
}

impl WandbRunScope {
    pub fn new(id: RunId, revision: Revision) -> Result<Self, WandbEvaluationError> {
        id.validate()?;
        revision.validate("run_revision")?;
        let mut run = Self {
            id,
            revision,
            digest: Digest::from_text("uninitialized-wandb-run"),
        };
        run.digest = canonical_digest(&RunIdentity {
            id: run.id.clone(),
            revision: run.revision.clone(),
        });
        Ok(run)
    }

    pub fn fixture(mission: &MissionId) -> Result<Self, WandbEvaluationError> {
        Self::new(
            RunId::new(format!("run-{}", mission.as_str()))?,
            Revision::fixture(),
        )
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.id.validate()?;
        self.revision.validate("run_revision")?;
        self.digest.validate("run_digest")?;
        if self.digest
            != canonical_digest(&RunIdentity {
                id: self.id.clone(),
                revision: self.revision.clone(),
            })
        {
            return Err(WandbEvaluationError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetricBinding {
    pub name: MetricName,
    pub revision: Revision,
    pub digest: Digest,
}

impl MetricBinding {
    pub fn new(name: MetricName, revision: Revision) -> Result<Self, WandbEvaluationError> {
        name.validate()?;
        revision.validate("metric_revision")?;
        let mut metric = Self {
            name,
            revision,
            digest: Digest::from_text("uninitialized-metric"),
        };
        metric.digest = canonical_digest(&MetricIdentity {
            name: metric.name.clone(),
            revision: metric.revision.clone(),
        });
        Ok(metric)
    }

    pub fn fixture(name: impl Into<String>) -> Result<Self, WandbEvaluationError> {
        Self::new(MetricName::new(name)?, Revision::fixture())
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.name.validate()?;
        self.revision.validate("metric_revision")?;
        self.digest.validate("metric_digest")?;
        if self.digest
            != canonical_digest(&MetricIdentity {
                name: self.name.clone(),
                revision: self.revision.clone(),
            })
        {
            return Err(WandbEvaluationError::MetricRevisionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigBinding {
    pub digest: Digest,
    pub revision: Revision,
}

impl ConfigBinding {
    pub fn new(digest: Digest, revision: Revision) -> Result<Self, WandbEvaluationError> {
        digest.validate("config_digest")?;
        revision.validate("config_revision")?;
        Ok(Self { digest, revision })
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self::new(Digest::from_text("fixture-config"), Revision::fixture()).expect("fixture config")
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.digest.validate("config_digest")?;
        self.revision.validate("config_revision")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactBinding {
    pub id: ArtifactId,
    pub revision: Revision,
    pub digest: Digest,
}

impl ArtifactBinding {
    pub fn new(
        id: ArtifactId,
        revision: Revision,
        digest: Digest,
    ) -> Result<Self, WandbEvaluationError> {
        id.validate()?;
        revision.validate("artifact_revision")?;
        digest.validate("artifact_digest")?;
        Ok(Self {
            id,
            revision,
            digest,
        })
    }

    pub fn fixture(id: impl Into<String>) -> Result<Self, WandbEvaluationError> {
        Self::new(
            ArtifactId::new(id)?,
            Revision::fixture(),
            Digest::from_text("fixture-artifact"),
        )
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.id.validate()?;
        self.revision.validate("artifact_revision")?;
        self.digest.validate("artifact_digest")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitBinding {
    pub id: CommitId,
    pub revision: Revision,
    pub digest: Digest,
}

impl CommitBinding {
    pub fn new(id: CommitId, revision: Revision) -> Result<Self, WandbEvaluationError> {
        id.validate()?;
        revision.validate("commit_revision")?;
        let digest = Digest::from_text(&format!("{}@{}", id.as_str(), revision.as_str()));
        Ok(Self {
            id,
            revision,
            digest,
        })
    }

    pub fn fixture() -> Result<Self, WandbEvaluationError> {
        Self::new(
            CommitId::new("0123456789abcdef0123456789abcdef01234567")?,
            Revision::fixture(),
        )
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.id.validate()?;
        self.revision.validate("commit_revision")?;
        self.digest.validate("commit_digest")?;
        if self.digest
            != Digest::from_text(&format!("{}@{}", self.id.as_str(), self.revision.as_str()))
        {
            return Err(WandbEvaluationError::CommitRevisionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionScope {
    pub id: MissionId,
    pub revision: Revision,
    pub digest: Digest,
}

impl MissionScope {
    pub fn new(id: MissionId, revision: Revision) -> Result<Self, WandbEvaluationError> {
        id.validate()?;
        revision.validate("mission_revision")?;
        let digest = canonical_digest(&MissionIdentity {
            id: id.clone(),
            revision: revision.clone(),
        });
        Ok(Self {
            id,
            revision,
            digest,
        })
    }

    pub fn fixture(id: impl Into<String>) -> Result<Self, WandbEvaluationError> {
        Self::new(MissionId::new(id)?, Revision::fixture())
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.id.validate()?;
        self.revision.validate("mission_revision")?;
        self.digest.validate("mission_digest")?;
        if self.digest
            != canonical_digest(&MissionIdentity {
                id: self.id.clone(),
                revision: self.revision.clone(),
            })
        {
            return Err(WandbEvaluationError::MissionMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectScope {
    pub id: ProjectId,
    pub revision: Revision,
    pub digest: Digest,
}

impl ProjectScope {
    pub fn new(id: ProjectId, revision: Revision) -> Result<Self, WandbEvaluationError> {
        id.validate()?;
        revision.validate("hartevo_project_revision")?;
        let digest = canonical_digest(&HartevoProjectIdentity {
            id: id.clone(),
            revision: revision.clone(),
        });
        Ok(Self {
            id,
            revision,
            digest,
        })
    }

    pub fn fixture() -> Result<Self, WandbEvaluationError> {
        Self::new(ProjectId::new("project-fixture")?, Revision::fixture())
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.id.validate()?;
        self.revision.validate("hartevo_project_revision")?;
        self.digest.validate("hartevo_project_digest")?;
        if self.digest
            != canonical_digest(&HartevoProjectIdentity {
                id: self.id.clone(),
                revision: self.revision.clone(),
            })
        {
            return Err(WandbEvaluationError::ProjectBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkProductScope {
    pub id: WorkProductId,
    pub revision: Revision,
    pub digest: Digest,
}

impl WorkProductScope {
    pub fn new(id: WorkProductId, revision: Revision) -> Result<Self, WandbEvaluationError> {
        id.validate()?;
        revision.validate("work_product_revision")?;
        let digest = canonical_digest(&WorkProductIdentity {
            id: id.clone(),
            revision: revision.clone(),
        });
        Ok(Self {
            id,
            revision,
            digest,
        })
    }

    pub fn fixture() -> Result<Self, WandbEvaluationError> {
        Self::new(
            WorkProductId::new("work-product-fixture")?,
            Revision::fixture(),
        )
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.id.validate()?;
        self.revision.validate("work_product_revision")?;
        self.digest.validate("work_product_digest")?;
        if self.digest
            != canonical_digest(&WorkProductIdentity {
                id: self.id.clone(),
                revision: self.revision.clone(),
            })
        {
            return Err(WandbEvaluationError::WorkProductMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WandbPermission {
    ReadRun,
    ReadSummaryMetrics,
    ReadHistorySamples,
    ReadArtifactMetadata,
}

impl WandbPermission {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReadRun => "read_run",
            Self::ReadSummaryMetrics => "read_summary_metrics",
            Self::ReadHistorySamples => "read_history_samples",
            Self::ReadArtifactMetadata => "read_artifact_metadata",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbPermissionSnapshot {
    pub revision: Revision,
    pub permissions: BTreeSet<WandbPermission>,
    pub digest: Digest,
}

impl WandbPermissionSnapshot {
    pub fn new(
        revision: Revision,
        permissions: impl IntoIterator<Item = WandbPermission>,
    ) -> Result<Self, WandbEvaluationError> {
        revision.validate("permission_revision")?;
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if permissions.is_empty()
            || permissions.iter().any(|permission| {
                !matches!(
                    permission,
                    WandbPermission::ReadRun
                        | WandbPermission::ReadSummaryMetrics
                        | WandbPermission::ReadHistorySamples
                        | WandbPermission::ReadArtifactMetadata
                )
            })
        {
            return Err(WandbEvaluationError::InvalidPermissionSnapshot);
        }
        let digest = canonical_digest(&PermissionIdentity {
            revision: revision.clone(),
            permissions: permissions.clone(),
        });
        Ok(Self {
            revision,
            permissions,
            digest,
        })
    }

    pub fn read_only(revision: Revision) -> Result<Self, WandbEvaluationError> {
        Self::new(
            revision,
            [
                WandbPermission::ReadRun,
                WandbPermission::ReadSummaryMetrics,
                WandbPermission::ReadHistorySamples,
                WandbPermission::ReadArtifactMetadata,
            ],
        )
    }

    #[must_use]
    pub fn allows(&self, permission: WandbPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        true
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.revision.validate("permission_revision")?;
        self.digest.validate("permission_digest")?;
        if self.permissions.is_empty()
            || self.digest
                != canonical_digest(&PermissionIdentity {
                    revision: self.revision.clone(),
                    permissions: self.permissions.clone(),
                })
        {
            return Err(WandbEvaluationError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PermissionIdentity {
    revision: Revision,
    permissions: BTreeSet<WandbPermission>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbEvaluationScope {
    pub host: WandbHost,
    pub entity: EntityId,
    pub project: WandbProjectScope,
    pub run: WandbRunScope,
    pub metric_allowlist: Vec<MetricBinding>,
    pub metric_digest: Digest,
    pub config: ConfigBinding,
    pub artifact_allowlist: Vec<ArtifactBinding>,
    pub artifact_digest: Digest,
    pub commit: CommitBinding,
    pub mission: MissionScope,
    pub hartevo_project: ProjectScope,
    pub work_product: WorkProductScope,
    pub permission_revision: Revision,
    pub provider_revision: Revision,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub scope_digest: Digest,
}

impl WandbEvaluationScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: WandbHost,
        entity: EntityId,
        project: WandbProjectScope,
        run: WandbRunScope,
        metric_allowlist: Vec<MetricBinding>,
        config: ConfigBinding,
        artifact_allowlist: Vec<ArtifactBinding>,
        commit: CommitBinding,
        mission: MissionScope,
        hartevo_project: ProjectScope,
        work_product: WorkProductScope,
        permission_revision: Revision,
        provider_revision: Revision,
    ) -> Result<Self, WandbEvaluationError> {
        let api_digest = api_digest_for_host(&host);
        let permission = WandbPermissionSnapshot::read_only(permission_revision.clone())?;
        let metric_digest = calculate_metric_digest(&metric_allowlist)?;
        let artifact_digest = calculate_artifact_digest(&artifact_allowlist)?;
        let revision_digest = calculate_revision_digest(
            &project,
            &run,
            &metric_allowlist,
            &config,
            &artifact_allowlist,
            &commit,
            &mission,
            &hartevo_project,
            &work_product,
            &permission_revision,
            &provider_revision,
        )?;
        let mut scope = Self {
            host,
            entity,
            project,
            run,
            metric_allowlist,
            metric_digest,
            config,
            artifact_allowlist,
            artifact_digest,
            commit,
            mission,
            hartevo_project,
            work_product,
            permission_revision,
            provider_revision,
            api_digest,
            permission_digest: permission.digest,
            revision_digest,
            scope_digest: Digest::from_text("uninitialized-wandb-scope"),
        };
        scope.scope_digest = scope.calculated_digest();
        scope.validate()?;
        Ok(scope)
    }

    /// Construct the complete exact fixture scope used by local evidence.
    pub fn fixture(mission: impl Into<String>) -> Result<Self, WandbEvaluationError> {
        let mission = MissionScope::fixture(mission)?;
        let project = WandbProjectScope::fixture();
        let run = WandbRunScope::fixture(&mission.id)?;
        Self::new(
            WandbHost::fixture(),
            EntityId::new("entity-fixture")?,
            project,
            run,
            vec![
                MetricBinding::fixture("accuracy")?,
                MetricBinding::fixture("loss")?,
            ],
            ConfigBinding::fixture(),
            vec![ArtifactBinding::fixture("model:v1")?],
            CommitBinding::fixture()?,
            mission,
            ProjectScope::fixture()?,
            WorkProductScope::fixture()?,
            Revision::fixture(),
            Revision::fixture(),
        )
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn metric(&self) -> &MetricBinding {
        &self.metric_allowlist[0]
    }

    #[must_use]
    pub fn metrics(&self) -> &[MetricBinding] {
        &self.metric_allowlist
    }

    #[must_use]
    pub fn artifacts(&self) -> &[ArtifactBinding] {
        &self.artifact_allowlist
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        validate_host(self.host.as_str())?;
        self.entity.validate()?;
        self.project.validate()?;
        self.run.validate()?;
        if self.metric_allowlist.is_empty() {
            return Err(WandbEvaluationError::InvalidScope);
        }
        validate_bounded_list(
            &self.metric_allowlist,
            MAX_SUMMARY_METRICS,
            "metric_allowlist",
        )?;
        let mut metric_names = BTreeSet::new();
        for metric in &self.metric_allowlist {
            metric.validate()?;
            if !metric_names.insert(metric.name.clone()) {
                return Err(WandbEvaluationError::InvalidScope);
            }
        }
        if self.metric_digest != calculate_metric_digest(&self.metric_allowlist)? {
            return Err(WandbEvaluationError::MetricRevisionDrift);
        }
        self.config.validate()?;
        if self.artifact_allowlist.is_empty() {
            return Err(WandbEvaluationError::InvalidScope);
        }
        validate_bounded_list(
            &self.artifact_allowlist,
            MAX_ARTIFACTS,
            "artifact_allowlist",
        )?;
        let mut artifact_ids = BTreeSet::new();
        for artifact in &self.artifact_allowlist {
            artifact.validate()?;
            if !artifact_ids.insert(artifact.id.clone()) {
                return Err(WandbEvaluationError::InvalidScope);
            }
        }
        if self.artifact_digest != calculate_artifact_digest(&self.artifact_allowlist)? {
            return Err(WandbEvaluationError::ArtifactRevisionDrift);
        }
        self.commit.validate()?;
        self.mission.validate()?;
        self.hartevo_project.validate()?;
        self.work_product.validate()?;
        self.permission_revision.validate("permission_revision")?;
        self.provider_revision.validate("provider_revision")?;
        self.api_digest.validate("api_digest")?;
        self.permission_digest.validate("permission_digest")?;
        self.revision_digest.validate("revision_digest")?;
        self.scope_digest.validate("scope_digest")?;
        if self.api_digest != api_digest_for_host(&self.host)
            || self.permission_digest
                != WandbPermissionSnapshot::read_only(self.permission_revision.clone())?.digest
            || self.revision_digest != self.calculated_revision_digest()?
            || self.scope_digest != self.calculated_digest()
        {
            return Err(WandbEvaluationError::InvalidScope);
        }
        Ok(())
    }

    pub fn with_metric_allowlist(
        mut self,
        metric_allowlist: Vec<MetricBinding>,
    ) -> Result<Self, WandbEvaluationError> {
        self.metric_allowlist = metric_allowlist;
        self.metric_digest = calculate_metric_digest(&self.metric_allowlist)?;
        self.revision_digest = self.calculated_revision_digest()?;
        self.scope_digest = self.calculated_digest();
        self.validate()?;
        Ok(self)
    }

    fn calculated_revision_digest(&self) -> Result<Digest, WandbEvaluationError> {
        calculate_revision_digest(
            &self.project,
            &self.run,
            &self.metric_allowlist,
            &self.config,
            &self.artifact_allowlist,
            &self.commit,
            &self.mission,
            &self.hartevo_project,
            &self.work_product,
            &self.permission_revision,
            &self.provider_revision,
        )
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&ScopeIdentity {
            host: self.host.clone(),
            entity: self.entity.clone(),
            project: self.project.clone(),
            run: self.run.clone(),
            metric_allowlist: self.metric_allowlist.clone(),
            metric_digest: self.metric_digest.clone(),
            config: self.config.clone(),
            artifact_allowlist: self.artifact_allowlist.clone(),
            artifact_digest: self.artifact_digest.clone(),
            commit: self.commit.clone(),
            mission: self.mission.clone(),
            hartevo_project: self.hartevo_project.clone(),
            work_product: self.work_product.clone(),
            permission_revision: self.permission_revision.clone(),
            provider_revision: self.provider_revision.clone(),
            api_digest: self.api_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            revision_digest: self.revision_digest.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ScopeIdentity {
    host: WandbHost,
    entity: EntityId,
    project: WandbProjectScope,
    run: WandbRunScope,
    metric_allowlist: Vec<MetricBinding>,
    metric_digest: Digest,
    config: ConfigBinding,
    artifact_allowlist: Vec<ArtifactBinding>,
    artifact_digest: Digest,
    commit: CommitBinding,
    mission: MissionScope,
    hartevo_project: ProjectScope,
    work_product: WorkProductScope,
    permission_revision: Revision,
    provider_revision: Revision,
    api_digest: Digest,
    permission_digest: Digest,
    revision_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProjectIdentity {
    id: WandbProjectId,
    revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RunIdentity {
    id: RunId,
    revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct MetricIdentity {
    name: MetricName,
    revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct MissionIdentity {
    id: MissionId,
    revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct WorkProductIdentity {
    id: WorkProductId,
    revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct HartevoProjectIdentity {
    id: ProjectId,
    revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RevisionIdentity {
    project_revision: Revision,
    run_revision: Revision,
    metric_revisions: Vec<Revision>,
    config_revision: Revision,
    artifact_revisions: Vec<Revision>,
    commit_revision: Revision,
    mission_revision: Revision,
    hartevo_project_revision: Revision,
    work_product_revision: Revision,
    permission_revision: Revision,
    provider_revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ArtifactListIdentity {
    artifacts: Vec<ArtifactBinding>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct MetricListIdentity {
    metrics: Vec<MetricBinding>,
}

fn calculate_metric_digest(metrics: &[MetricBinding]) -> Result<Digest, WandbEvaluationError> {
    validate_bounded_list(metrics, MAX_SUMMARY_METRICS, "metric_allowlist")?;
    Ok(canonical_digest(&MetricListIdentity {
        metrics: metrics.to_vec(),
    }))
}

fn calculate_artifact_digest(
    artifacts: &[ArtifactBinding],
) -> Result<Digest, WandbEvaluationError> {
    validate_bounded_list(artifacts, MAX_ARTIFACTS, "artifact_allowlist")?;
    Ok(canonical_digest(&ArtifactListIdentity {
        artifacts: artifacts.to_vec(),
    }))
}

fn calculate_revision_digest(
    project: &WandbProjectScope,
    run: &WandbRunScope,
    metrics: &[MetricBinding],
    config: &ConfigBinding,
    artifacts: &[ArtifactBinding],
    commit: &CommitBinding,
    mission: &MissionScope,
    hartevo_project: &ProjectScope,
    work_product: &WorkProductScope,
    permission_revision: &Revision,
    provider_revision: &Revision,
) -> Result<Digest, WandbEvaluationError> {
    validate_bounded_list(metrics, MAX_SUMMARY_METRICS, "metric_allowlist")?;
    validate_bounded_list(artifacts, MAX_ARTIFACTS, "artifact_allowlist")?;
    Ok(canonical_digest(&RevisionIdentity {
        project_revision: project.revision.clone(),
        run_revision: run.revision.clone(),
        metric_revisions: metrics
            .iter()
            .map(|metric| metric.revision.clone())
            .collect(),
        config_revision: config.revision.clone(),
        artifact_revisions: artifacts
            .iter()
            .map(|artifact| artifact.revision.clone())
            .collect(),
        commit_revision: commit.revision.clone(),
        mission_revision: mission.revision.clone(),
        hartevo_project_revision: hartevo_project.revision.clone(),
        work_product_revision: work_product.revision.clone(),
        permission_revision: permission_revision.clone(),
        provider_revision: provider_revision.clone(),
    }))
}

fn api_digest_for_host(host: &WandbHost) -> Digest {
    Digest::from_text(&format!(
        "{}|{}|GET /api/v1/runs/{{entity}}/{{project}}/{{run}}|summary_metrics|sampled_history|run_state|artifact_metadata",
        crate::WANDB_EVALUATION_RESULT_API_VERSION,
        host.as_str()
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbPluginRegistration {
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub revision_digest: Digest,
    pub metric_digest: Digest,
    pub active: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub registration_digest: Digest,
}

impl WandbPluginRegistration {
    pub fn new(
        scope: &WandbEvaluationScope,
        permission: &WandbPermissionSnapshot,
        provider_digest: Digest,
        api_digest: Digest,
    ) -> Result<Self, WandbEvaluationError> {
        scope.validate()?;
        permission.validate()?;
        provider_digest.validate("provider_digest")?;
        api_digest.validate("api_digest")?;
        if permission.revision != scope.permission_revision
            || permission.digest != scope.permission_digest
            || api_digest != scope.api_digest
        {
            return Err(WandbEvaluationError::PermissionDrift);
        }
        let mut registration = Self {
            plugin_version: PluginVersion::V1,
            contract_version: String::from(crate::WANDB_EVALUATION_RESULT_CONTRACT_VERSION),
            contract_digest: Digest::from_text(
                crate::WANDB_EVALUATION_RESULT_CONTRACT_DIGEST_INPUT,
            ),
            provider_id: String::from(crate::WANDB_EVALUATION_RESULT_PROVIDER_ID),
            provider_digest,
            api_digest,
            permission_digest: permission.digest.clone(),
            scope_digest: scope.digest().clone(),
            revision_digest: scope.revision_digest.clone(),
            metric_digest: scope.metric_digest.clone(),
            active: true,
            reversible: true,
            revocable: true,
            registration_digest: Digest::from_text("uninitialized-wandb-registration"),
        };
        registration.registration_digest = registration.calculated_digest();
        registration.validate(scope, permission)?;
        Ok(registration)
    }

    pub fn fixture(scope: &WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        let permission = WandbPermissionSnapshot::read_only(scope.permission_revision.clone())?;
        Self::new(
            scope,
            &permission,
            Digest::from_text("fixture-wandb-provider"),
            scope.api_digest.clone(),
        )
    }

    pub fn validate(
        &self,
        scope: &WandbEvaluationScope,
        permission: &WandbPermissionSnapshot,
    ) -> Result<(), WandbEvaluationError> {
        scope.validate()?;
        permission.validate()?;
        if self.plugin_version != PluginVersion::V1
            || self.contract_version != crate::WANDB_EVALUATION_RESULT_CONTRACT_VERSION
            || self.contract_digest
                != Digest::from_text(crate::WANDB_EVALUATION_RESULT_CONTRACT_DIGEST_INPUT)
            || self.provider_id != crate::WANDB_EVALUATION_RESULT_PROVIDER_ID
        {
            return Err(WandbEvaluationError::ContractDrift);
        }
        for (field, digest) in [
            ("provider_digest", &self.provider_digest),
            ("api_digest", &self.api_digest),
            ("permission_digest", &self.permission_digest),
            ("scope_digest", &self.scope_digest),
            ("revision_digest", &self.revision_digest),
            ("metric_digest", &self.metric_digest),
        ] {
            digest.validate(field)?;
        }
        if self.api_digest != scope.api_digest
            || self.permission_digest != permission.digest
            || self.scope_digest != *scope.digest()
            || self.revision_digest != scope.revision_digest
            || self.metric_digest != scope.metric_digest
            || permission.revision != scope.permission_revision
        {
            return Err(WandbEvaluationError::RegistrationTampered);
        }
        if !self.reversible || !self.revocable {
            return Err(WandbEvaluationError::RegistrationRequired);
        }
        if self.registration_digest != self.calculated_digest() {
            return Err(WandbEvaluationError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn ensure_active(
        &self,
        scope: &WandbEvaluationScope,
        permission: &WandbPermissionSnapshot,
    ) -> Result<(), WandbEvaluationError> {
        self.validate(scope, permission)?;
        if self.active {
            Ok(())
        } else {
            Err(WandbEvaluationError::RegistrationRevoked)
        }
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revoke(
        &mut self,
        reason: impl AsRef<str>,
        scope: &WandbEvaluationScope,
        permission: &WandbPermissionSnapshot,
    ) -> Result<RegistrationRevocation, WandbEvaluationError> {
        self.ensure_active(scope, permission)?;
        let reason = reason.as_ref();
        if reason.trim().is_empty() {
            return Err(WandbEvaluationError::InvalidIdentifier {
                field: "revocation_reason",
            });
        }
        let previous_digest = self.registration_digest.clone();
        self.active = false;
        self.registration_digest = self.calculated_digest();
        Ok(RegistrationRevocation {
            previous_registration_digest: previous_digest,
            registration_digest: self.registration_digest.clone(),
            reason_digest: Digest::from_text(reason),
            reversible: self.reversible,
        })
    }

    pub fn restore(
        &mut self,
        scope: &WandbEvaluationScope,
        permission: &WandbPermissionSnapshot,
    ) -> Result<(), WandbEvaluationError> {
        self.validate(scope, permission)?;
        self.active = true;
        self.registration_digest = self.calculated_digest();
        self.validate(scope, permission)
    }

    pub fn reissue(
        &self,
        scope: &WandbEvaluationScope,
        permission: &WandbPermissionSnapshot,
    ) -> Result<Self, WandbEvaluationError> {
        Self::new(
            scope,
            permission,
            self.provider_digest.clone(),
            self.api_digest.clone(),
        )
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&RegistrationIdentity {
            plugin_version: self.plugin_version,
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_id: self.provider_id.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision_digest: self.revision_digest.clone(),
            metric_digest: self.metric_digest.clone(),
            active: self.active,
            reversible: self.reversible,
            revocable: self.revocable,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RegistrationIdentity {
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    scope_digest: Digest,
    revision_digest: Digest,
    metric_digest: Digest,
    active: bool,
    reversible: bool,
    revocable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub previous_registration_digest: Digest,
    pub registration_digest: Digest,
    pub reason_digest: Digest,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbEvaluationPolicy {
    pub max_page_size: u16,
    pub max_pages: u16,
    pub max_history_samples: usize,
    pub max_summary_metrics: usize,
    pub max_artifacts: usize,
    pub max_response_bytes: usize,
    pub max_age_ms: u64,
}

impl WandbEvaluationPolicy {
    pub fn new(
        max_page_size: u16,
        max_pages: u16,
        max_history_samples: usize,
        max_summary_metrics: usize,
        max_artifacts: usize,
        max_response_bytes: usize,
        max_age_ms: u64,
    ) -> Result<Self, WandbEvaluationError> {
        if max_page_size == 0
            || max_page_size > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
        {
            return Err(WandbEvaluationError::InvalidRequest);
        }
        if max_history_samples == 0
            || max_history_samples > MAX_HISTORY_SAMPLES
            || max_summary_metrics == 0
            || max_summary_metrics > MAX_SUMMARY_METRICS
            || max_artifacts == 0
            || max_artifacts > MAX_ARTIFACTS
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(WandbEvaluationError::InvalidRequest);
        }
        Ok(Self {
            max_page_size,
            max_pages,
            max_history_samples,
            max_summary_metrics,
            max_artifacts,
            max_response_bytes,
            max_age_ms,
        })
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self {
            max_page_size: MAX_PAGE_SIZE,
            max_pages: MAX_PAGES,
            max_history_samples: 64,
            max_summary_metrics: MAX_SUMMARY_METRICS,
            max_artifacts: MAX_ARTIFACTS,
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_age_ms: MAX_AGE_MS,
        }
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        Self::new(
            self.max_page_size,
            self.max_pages,
            self.max_history_samples,
            self.max_summary_metrics,
            self.max_artifacts,
            self.max_response_bytes,
            self.max_age_ms,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbEvaluationReadRequest {
    pub scope: WandbEvaluationScope,
    pub page_size: u16,
    pub history_limit: usize,
    pub max_response_bytes: usize,
    pub cursor: Option<WandbEvaluationCursor>,
    pub as_of_ms: u64,
}

impl WandbEvaluationReadRequest {
    pub fn new(
        scope: WandbEvaluationScope,
        page_size: u16,
        history_limit: usize,
        max_response_bytes: usize,
        as_of_ms: u64,
    ) -> Result<Self, WandbEvaluationError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(WandbEvaluationError::InvalidPageSize {
                maximum: MAX_PAGE_SIZE,
            });
        }
        if history_limit == 0 || history_limit > MAX_HISTORY_SAMPLES {
            return Err(WandbEvaluationError::InvalidHistoryLimit {
                maximum: MAX_HISTORY_SAMPLES,
            });
        }
        if max_response_bytes == 0 || max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(WandbEvaluationError::InvalidByteLimit {
                maximum: MAX_RESPONSE_BYTES,
            });
        }
        scope.validate()?;
        Ok(Self {
            scope,
            page_size,
            history_limit,
            max_response_bytes,
            cursor: None,
            as_of_ms,
        })
    }

    pub fn fixture(scope: WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        Self::new(scope, MAX_PAGE_SIZE, 64, MAX_RESPONSE_BYTES, 10_000)
    }

    pub fn next_page(&self, cursor: WandbEvaluationCursor) -> Result<Self, WandbEvaluationError> {
        cursor.validate()?;
        if cursor.scope_digest != *self.scope.digest() {
            return Err(WandbEvaluationError::CursorMismatch);
        }
        Ok(Self {
            scope: self.scope.clone(),
            page_size: self.page_size,
            history_limit: self.history_limit,
            max_response_bytes: self.max_response_bytes,
            cursor: Some(cursor),
            as_of_ms: self.as_of_ms,
        })
    }

    pub fn validate(&self, policy: &WandbEvaluationPolicy) -> Result<(), WandbEvaluationError> {
        policy.validate()?;
        self.scope.validate()?;
        if self.page_size == 0 || self.page_size > policy.max_page_size {
            return Err(WandbEvaluationError::InvalidPageSize {
                maximum: policy.max_page_size,
            });
        }
        if self.history_limit == 0 || self.history_limit > policy.max_history_samples {
            return Err(WandbEvaluationError::InvalidHistoryLimit {
                maximum: policy.max_history_samples,
            });
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > policy.max_response_bytes {
            return Err(WandbEvaluationError::InvalidByteLimit {
                maximum: policy.max_response_bytes,
            });
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
            if cursor.scope_digest != *self.scope.digest() {
                return Err(WandbEvaluationError::CursorMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbEvaluationCursor {
    pub page: u16,
    pub scope_digest: Digest,
    pub prior_response_digest: Digest,
    pub cursor_digest: Digest,
}

impl WandbEvaluationCursor {
    pub fn new(
        page: u16,
        scope_digest: Digest,
        prior_response_digest: Digest,
    ) -> Result<Self, WandbEvaluationError> {
        if page == 0 || page > MAX_PAGES {
            return Err(WandbEvaluationError::PaginationMismatch);
        }
        scope_digest.validate("cursor_scope_digest")?;
        prior_response_digest.validate("prior_response_digest")?;
        let cursor_digest = canonical_digest(&CursorIdentity {
            page,
            scope_digest: scope_digest.clone(),
            prior_response_digest: prior_response_digest.clone(),
        });
        Ok(Self {
            page,
            scope_digest,
            prior_response_digest,
            cursor_digest,
        })
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        if self.page == 0 || self.page > MAX_PAGES {
            return Err(WandbEvaluationError::PaginationMismatch);
        }
        self.scope_digest.validate("cursor_scope_digest")?;
        self.prior_response_digest
            .validate("prior_response_digest")?;
        self.cursor_digest.validate("cursor_digest")?;
        if self.cursor_digest
            != canonical_digest(&CursorIdentity {
                page: self.page,
                scope_digest: self.scope_digest.clone(),
                prior_response_digest: self.prior_response_digest.clone(),
            })
        {
            return Err(WandbEvaluationError::CursorMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CursorIdentity {
    page: u16,
    scope_digest: Digest,
    prior_response_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Running,
    Finished,
    Crashed,
    Failed,
    Killed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Present,
    Empty,
    Partial,
    Stale,
    AccessLoss,
    ProviderUnknown,
}

impl EvidenceStatus {
    #[must_use]
    pub const fn is_current_evidence(self) -> bool {
        matches!(self, Self::Present | Self::Empty)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunTimestamps {
    pub created_at_ms: u64,
    pub started_at_ms: Option<u64>,
    pub finished_at_ms: Option<u64>,
    pub updated_at_ms: u64,
}

impl RunTimestamps {
    pub fn new(
        created_at_ms: u64,
        started_at_ms: Option<u64>,
        finished_at_ms: Option<u64>,
        updated_at_ms: u64,
    ) -> Result<Self, WandbEvaluationError> {
        if let Some(started) = started_at_ms
            && (started < created_at_ms || started > updated_at_ms)
        {
            return Err(WandbEvaluationError::InvalidResponse);
        }
        if let Some(finished) = finished_at_ms
            && (finished < started_at_ms.unwrap_or(created_at_ms) || finished > updated_at_ms)
        {
            return Err(WandbEvaluationError::InvalidResponse);
        }
        if updated_at_ms < created_at_ms {
            return Err(WandbEvaluationError::InvalidResponse);
        }
        Ok(Self {
            created_at_ms,
            started_at_ms,
            finished_at_ms,
            updated_at_ms,
        })
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self::new(1_000, Some(1_010), Some(1_250), 1_250).expect("fixture timestamps")
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        Self::new(
            self.created_at_ms,
            self.started_at_ms,
            self.finished_at_ms,
            self.updated_at_ms,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SummaryMetric {
    pub name: MetricName,
    pub value: f64,
    pub digest: Digest,
}

impl SummaryMetric {
    pub fn new(name: MetricName, value: f64) -> Result<Self, WandbEvaluationError> {
        if !value.is_finite() {
            return Err(WandbEvaluationError::InvalidResponse);
        }
        name.validate()?;
        let digest = canonical_digest(&SummaryMetricIdentity {
            name: name.clone(),
            value_bits: value.to_bits(),
        });
        Ok(Self {
            name,
            value,
            digest,
        })
    }

    pub fn fixture(name: &MetricName, value: f64) -> Result<Self, WandbEvaluationError> {
        Self::new(name.clone(), value)
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.name.validate()?;
        if !self.value.is_finite() {
            return Err(WandbEvaluationError::InvalidResponse);
        }
        self.digest.validate("summary_metric_digest")?;
        if self.digest
            != canonical_digest(&SummaryMetricIdentity {
                name: self.name.clone(),
                value_bits: self.value.to_bits(),
            })
        {
            return Err(WandbEvaluationError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct HistorySample {
    pub name: MetricName,
    pub step: u64,
    pub timestamp_ms: Option<u64>,
    pub value: f64,
    pub sampled: bool,
    pub digest: Digest,
}

impl HistorySample {
    pub fn new(
        name: MetricName,
        step: u64,
        timestamp_ms: Option<u64>,
        value: f64,
    ) -> Result<Self, WandbEvaluationError> {
        if !value.is_finite() {
            return Err(WandbEvaluationError::InvalidResponse);
        }
        name.validate()?;
        let digest = canonical_digest(&HistorySampleIdentity {
            name: name.clone(),
            step,
            timestamp_ms,
            value_bits: value.to_bits(),
        });
        Ok(Self {
            name,
            step,
            timestamp_ms,
            value,
            sampled: true,
            digest,
        })
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.name.validate()?;
        if !self.sampled || !self.value.is_finite() {
            return Err(WandbEvaluationError::RedactionViolation);
        }
        self.digest.validate("history_sample_digest")?;
        if self.digest
            != canonical_digest(&HistorySampleIdentity {
                name: self.name.clone(),
                step: self.step,
                timestamp_ms: self.timestamp_ms,
                value_bits: self.value.to_bits(),
            })
        {
            return Err(WandbEvaluationError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactMetadata {
    pub id: ArtifactId,
    pub artifact_type_digest: Digest,
    pub revision: Revision,
    pub digest: Digest,
    pub size_bytes: u64,
    pub created_at_ms: u64,
    pub metadata_only: bool,
}

impl ArtifactMetadata {
    pub fn new(
        id: ArtifactId,
        artifact_type: impl AsRef<str>,
        revision: Revision,
        digest: Digest,
        size_bytes: u64,
        created_at_ms: u64,
    ) -> Result<Self, WandbEvaluationError> {
        id.validate()?;
        revision.validate("artifact_revision")?;
        digest.validate("artifact_digest")?;
        let artifact_type = artifact_type.as_ref();
        if artifact_type.trim().is_empty() || artifact_type.len() > MAX_IDENTIFIER_BYTES {
            return Err(WandbEvaluationError::InvalidIdentifier {
                field: "artifact_type",
            });
        }
        Ok(Self {
            id,
            artifact_type_digest: Digest::from_text(artifact_type),
            revision,
            digest,
            size_bytes,
            created_at_ms,
            metadata_only: true,
        })
    }

    pub fn fixture(binding: &ArtifactBinding) -> Result<Self, WandbEvaluationError> {
        Self::new(
            binding.id.clone(),
            "model",
            binding.revision.clone(),
            binding.digest.clone(),
            4_096,
            1_240,
        )
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.id.validate()?;
        self.artifact_type_digest.validate("artifact_type_digest")?;
        self.revision.validate("artifact_revision")?;
        self.digest.validate("artifact_digest")?;
        if !self.metadata_only {
            return Err(WandbEvaluationError::RedactionViolation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WandbRunResult {
    pub entity: EntityId,
    pub project: WandbProjectScope,
    pub run: WandbRunScope,
    pub state: RunState,
    pub timestamps: RunTimestamps,
    pub summary_metrics: Vec<SummaryMetric>,
    pub sampled_history: Vec<HistorySample>,
    pub config: ConfigBinding,
    pub artifacts: Vec<ArtifactMetadata>,
    pub commit: CommitBinding,
    pub response_bytes: usize,
    pub redacted: bool,
    pub result_digest: Digest,
}

impl WandbRunResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entity: EntityId,
        project: WandbProjectScope,
        run: WandbRunScope,
        state: RunState,
        timestamps: RunTimestamps,
        summary_metrics: Vec<SummaryMetric>,
        sampled_history: Vec<HistorySample>,
        config: ConfigBinding,
        artifacts: Vec<ArtifactMetadata>,
        commit: CommitBinding,
        response_bytes: usize,
    ) -> Result<Self, WandbEvaluationError> {
        let mut result = Self {
            entity,
            project,
            run,
            state,
            timestamps,
            summary_metrics,
            sampled_history,
            config,
            artifacts,
            commit,
            response_bytes,
            redacted: true,
            result_digest: Digest::from_text("uninitialized-wandb-run-result"),
        };
        result.result_digest = result.calculated_digest();
        result.validate()?;
        Ok(result)
    }

    #[allow(clippy::cast_precision_loss)]
    pub fn fixture(scope: &WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        let summary_metrics = scope
            .metric_allowlist
            .iter()
            .enumerate()
            .map(|(index, metric)| SummaryMetric::fixture(&metric.name, 0.9 - index as f64 * 0.1))
            .collect::<Result<Vec<_>, _>>()?;
        let sampled_history = scope
            .metric_allowlist
            .iter()
            .enumerate()
            .map(|(index, metric)| {
                HistorySample::new(
                    metric.name.clone(),
                    index as u64,
                    Some(1_100 + index as u64),
                    0.8,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let artifacts = scope
            .artifact_allowlist
            .iter()
            .map(ArtifactMetadata::fixture)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(
            scope.entity.clone(),
            scope.project.clone(),
            scope.run.clone(),
            RunState::Finished,
            RunTimestamps::fixture(),
            summary_metrics,
            sampled_history,
            scope.config.clone(),
            artifacts,
            scope.commit.clone(),
            8_192,
        )
    }

    pub fn validate(&self) -> Result<(), WandbEvaluationError> {
        self.entity.validate()?;
        self.project.validate()?;
        self.run.validate()?;
        self.timestamps.validate()?;
        validate_bounded_list(
            &self.summary_metrics,
            MAX_SUMMARY_METRICS,
            "summary_metrics",
        )?;
        let mut summary_names = BTreeSet::new();
        for metric in &self.summary_metrics {
            metric.validate()?;
            if !summary_names.insert(metric.name.clone()) {
                return Err(WandbEvaluationError::InvalidResponse);
            }
        }
        validate_bounded_list(
            &self.sampled_history,
            MAX_HISTORY_SAMPLES,
            "sampled_history",
        )?;
        let mut previous_step = None;
        for sample in &self.sampled_history {
            sample.validate()?;
            if let Some(previous) = previous_step
                && sample.step < previous
            {
                return Err(WandbEvaluationError::InvalidResponse);
            }
            previous_step = Some(sample.step);
        }
        self.config.validate()?;
        validate_bounded_list(&self.artifacts, MAX_ARTIFACTS, "artifact_metadata")?;
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        self.commit.validate()?;
        if self.response_bytes == 0 || self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(WandbEvaluationError::BoundExceeded {
                field: "response_bytes",
                maximum: MAX_RESPONSE_BYTES,
            });
        }
        if !self.redacted {
            return Err(WandbEvaluationError::RedactionViolation);
        }
        self.result_digest.validate("run_result_digest")?;
        if self.result_digest != self.calculated_digest() {
            return Err(WandbEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&RunResultIdentity {
            entity: self.entity.clone(),
            project: self.project.clone(),
            run: self.run.clone(),
            state: self.state,
            timestamps: self.timestamps.clone(),
            summary_metrics: self.summary_metrics.clone(),
            sampled_history: self.sampled_history.clone(),
            config: self.config.clone(),
            artifacts: self.artifacts.clone(),
            commit: self.commit.clone(),
            response_bytes: self.response_bytes,
            redacted: self.redacted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct SummaryMetricIdentity {
    name: MetricName,
    value_bits: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct HistorySampleIdentity {
    name: MetricName,
    step: u64,
    timestamp_ms: Option<u64>,
    value_bits: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct RunResultIdentity {
    entity: EntityId,
    project: WandbProjectScope,
    run: WandbRunScope,
    state: RunState,
    timestamps: RunTimestamps,
    summary_metrics: Vec<SummaryMetric>,
    sampled_history: Vec<HistorySample>,
    config: ConfigBinding,
    artifacts: Vec<ArtifactMetadata>,
    commit: CommitBinding,
    response_bytes: usize,
    redacted: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WandbEvaluationPage {
    pub scope_digest: Digest,
    pub entity: EntityId,
    pub project: WandbProjectScope,
    pub run: WandbRunResult,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub metric_digest: Digest,
    pub config_digest: Digest,
    pub artifact_digest: Digest,
    pub commit_digest: Digest,
    pub revision_digest: Digest,
    pub page: u16,
    pub observed_at_ms: u64,
    pub status: EvidenceStatus,
    pub partial: bool,
    pub response_bytes: usize,
    pub next_cursor: Option<WandbEvaluationCursor>,
    pub response_digest: Digest,
}

impl WandbEvaluationPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &WandbEvaluationScope,
        run: WandbRunResult,
        page: u16,
        observed_at_ms: u64,
        status: EvidenceStatus,
        partial: bool,
        response_bytes: usize,
        next_cursor: Option<WandbEvaluationCursor>,
    ) -> Result<Self, WandbEvaluationError> {
        scope.validate()?;
        run.validate()?;
        if page == 0 || page > MAX_PAGES {
            return Err(WandbEvaluationError::PaginationMismatch);
        }
        if response_bytes == 0 || response_bytes > MAX_RESPONSE_BYTES {
            return Err(WandbEvaluationError::BoundExceeded {
                field: "response_bytes",
                maximum: MAX_RESPONSE_BYTES,
            });
        }
        if let Some(cursor) = &next_cursor {
            cursor.validate()?;
        }
        let mut result = Self {
            scope_digest: scope.digest().clone(),
            entity: scope.entity.clone(),
            project: scope.project.clone(),
            run,
            api_digest: scope.api_digest.clone(),
            permission_digest: scope.permission_digest.clone(),
            metric_digest: scope.metric_digest.clone(),
            config_digest: scope.config.digest.clone(),
            artifact_digest: scope.artifact_digest.clone(),
            commit_digest: scope.commit.digest.clone(),
            revision_digest: scope.revision_digest.clone(),
            page,
            observed_at_ms,
            status,
            partial,
            response_bytes,
            next_cursor,
            response_digest: Digest::from_text("uninitialized-wandb-response"),
        };
        result.response_digest = result.calculated_digest();
        result.validate(&WandbEvaluationPolicy::fixture())?;
        Ok(result)
    }

    pub fn fixture(scope: &WandbEvaluationScope) -> Result<Self, WandbEvaluationError> {
        Self::new(
            scope,
            WandbRunResult::fixture(scope)?,
            1,
            10_000,
            EvidenceStatus::Present,
            false,
            8_192,
            None,
        )
    }

    pub fn validate(&self, policy: &WandbEvaluationPolicy) -> Result<(), WandbEvaluationError> {
        policy.validate()?;
        self.scope_digest.validate("scope_digest")?;
        self.entity.validate()?;
        self.project.validate()?;
        self.run.validate()?;
        self.api_digest.validate("api_digest")?;
        self.permission_digest.validate("permission_digest")?;
        self.metric_digest.validate("metric_digest")?;
        self.config_digest.validate("config_digest")?;
        self.artifact_digest.validate("artifact_digest")?;
        self.commit_digest.validate("commit_digest")?;
        self.revision_digest.validate("revision_digest")?;
        if self.page == 0 || self.page > policy.max_pages {
            return Err(WandbEvaluationError::PaginationMismatch);
        }
        if self.run.response_bytes > policy.max_response_bytes
            || self.response_bytes > policy.max_response_bytes
            || self.run.response_bytes != self.response_bytes
        {
            return Err(WandbEvaluationError::BoundExceeded {
                field: "response_bytes",
                maximum: policy.max_response_bytes,
            });
        }
        if self.run.sampled_history.len() > policy.max_history_samples {
            return Err(WandbEvaluationError::BoundExceeded {
                field: "sampled_history",
                maximum: policy.max_history_samples,
            });
        }
        if self.run.summary_metrics.len() > policy.max_summary_metrics {
            return Err(WandbEvaluationError::BoundExceeded {
                field: "summary_metrics",
                maximum: policy.max_summary_metrics,
            });
        }
        if self.run.artifacts.len() > policy.max_artifacts {
            return Err(WandbEvaluationError::BoundExceeded {
                field: "artifact_metadata",
                maximum: policy.max_artifacts,
            });
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate()?;
            if cursor.page <= self.page {
                return Err(WandbEvaluationError::PaginationMismatch);
            }
        }
        if self.response_digest != self.calculated_digest() {
            return Err(WandbEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&PageIdentity {
            scope_digest: self.scope_digest.clone(),
            entity: self.entity.clone(),
            project: self.project.clone(),
            run: self.run.clone(),
            api_digest: self.api_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            metric_digest: self.metric_digest.clone(),
            config_digest: self.config_digest.clone(),
            artifact_digest: self.artifact_digest.clone(),
            commit_digest: self.commit_digest.clone(),
            revision_digest: self.revision_digest.clone(),
            page: self.page,
            observed_at_ms: self.observed_at_ms,
            status: self.status,
            partial: self.partial,
            response_bytes: self.response_bytes,
            next_cursor: self.next_cursor.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct PageIdentity {
    scope_digest: Digest,
    entity: EntityId,
    project: WandbProjectScope,
    run: WandbRunResult,
    api_digest: Digest,
    permission_digest: Digest,
    metric_digest: Digest,
    config_digest: Digest,
    artifact_digest: Digest,
    commit_digest: Digest,
    revision_digest: Digest,
    page: u16,
    observed_at_ms: u64,
    status: EvidenceStatus,
    partial: bool,
    response_bytes: usize,
    next_cursor: Option<WandbEvaluationCursor>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl EvidenceSource {
    #[must_use]
    pub const fn native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeStatus {
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderState {
    Ready,
    BlockedEnv,
    AccessLost,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WandbEvaluationEvidence {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub metric_digest: Digest,
    pub page_count: u16,
    pub status: EvidenceStatus,
    pub partial: bool,
    pub source: EvidenceSource,
    pub run: WandbRunResult,
    pub response_digests: Vec<Digest>,
    pub redacted: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted: bool,
    pub durable_native_receipt: bool,
    pub external_write_performed: bool,
    pub evidence_digest: Digest,
}

impl WandbEvaluationEvidence {
    pub fn from_page(
        page: &WandbEvaluationPage,
        registration: &WandbPluginRegistration,
        provider_digest: Digest,
        source: EvidenceSource,
    ) -> Result<Self, WandbEvaluationError> {
        page.validate(&WandbEvaluationPolicy::fixture())?;
        provider_digest.validate("provider_digest")?;
        let mut evidence = Self {
            scope_digest: page.scope_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            provider_digest,
            api_digest: page.api_digest.clone(),
            permission_digest: page.permission_digest.clone(),
            revision_digest: page.revision_digest.clone(),
            metric_digest: page.metric_digest.clone(),
            page_count: 1,
            status: page.status,
            partial: page.partial,
            source,
            run: page.run.clone(),
            response_digests: vec![page.response_digest.clone()],
            redacted: true,
            connected: false,
            native: false,
            adopted: false,
            durable_native_receipt: false,
            external_write_performed: false,
            evidence_digest: Digest::from_text("uninitialized-wandb-evidence"),
        };
        evidence.evidence_digest = evidence.calculated_digest();
        evidence.validate(registration)?;
        Ok(evidence)
    }

    pub fn validate(
        &self,
        registration: &WandbPluginRegistration,
    ) -> Result<(), WandbEvaluationError> {
        self.scope_digest.validate("scope_digest")?;
        self.registration_digest.validate("registration_digest")?;
        self.provider_digest.validate("provider_digest")?;
        self.api_digest.validate("api_digest")?;
        self.permission_digest.validate("permission_digest")?;
        self.revision_digest.validate("revision_digest")?;
        self.metric_digest.validate("metric_digest")?;
        if self.page_count == 0
            || self.page_count > MAX_PAGES
            || self.response_digests.len() != self.page_count as usize
        {
            return Err(WandbEvaluationError::PaginationMismatch);
        }
        for digest in &self.response_digests {
            digest.validate("response_digest")?;
        }
        self.run.validate()?;
        if !self.redacted
            || self.connected
            || self.native
            || self.adopted
            || self.durable_native_receipt
            || self.external_write_performed
            || !registration.active
            || self.registration_digest != registration.registration_digest
            || self.scope_digest != registration.scope_digest
            || self.api_digest != registration.api_digest
            || self.permission_digest != registration.permission_digest
            || self.revision_digest != registration.revision_digest
            || self.metric_digest != registration.metric_digest
        {
            if !registration.active {
                return Err(WandbEvaluationError::RegistrationRevoked);
            }
            return Err(WandbEvaluationError::NativeClassificationMismatch);
        }
        if self.evidence_digest != self.calculated_digest() {
            return Err(WandbEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_redacted(&self) -> bool {
        self.redacted
    }

    #[must_use]
    pub fn can_claim_current(&self) -> bool {
        self.status.is_current_evidence() && !self.partial && !self.connected && !self.native
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&EvidenceIdentity {
            scope_digest: self.scope_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            revision_digest: self.revision_digest.clone(),
            metric_digest: self.metric_digest.clone(),
            page_count: self.page_count,
            status: self.status,
            partial: self.partial,
            source: self.source,
            run: self.run.clone(),
            response_digests: self.response_digests.clone(),
            redacted: self.redacted,
            connected: self.connected,
            native: self.native,
            adopted: self.adopted,
            durable_native_receipt: self.durable_native_receipt,
            external_write_performed: self.external_write_performed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct EvidenceIdentity {
    scope_digest: Digest,
    registration_digest: Digest,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    revision_digest: Digest,
    metric_digest: Digest,
    page_count: u16,
    status: EvidenceStatus,
    partial: bool,
    source: EvidenceSource,
    run: WandbRunResult,
    response_digests: Vec<Digest>,
    redacted: bool,
    connected: bool,
    native: bool,
    adopted: bool,
    durable_native_receipt: bool,
    external_write_performed: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct WandbEvaluationResultProposal {
    pub scope: WandbEvaluationScope,
    pub evidence: WandbEvaluationEvidence,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub metric_digest: Digest,
    pub external_write: bool,
    pub connected: bool,
    pub native: bool,
    pub adopted: bool,
    pub proposal_digest: Digest,
}

impl WandbEvaluationResultProposal {
    pub fn new(
        scope: WandbEvaluationScope,
        evidence: WandbEvaluationEvidence,
        registration: &WandbPluginRegistration,
    ) -> Result<Self, WandbEvaluationError> {
        let mut proposal = Self {
            provider_digest: evidence.provider_digest.clone(),
            api_digest: evidence.api_digest.clone(),
            permission_digest: evidence.permission_digest.clone(),
            revision_digest: evidence.revision_digest.clone(),
            metric_digest: evidence.metric_digest.clone(),
            registration_digest: registration.registration_digest.clone(),
            scope,
            evidence,
            external_write: false,
            connected: false,
            native: false,
            adopted: false,
            proposal_digest: Digest::from_text("uninitialized-wandb-proposal"),
        };
        proposal.proposal_digest = proposal.calculated_digest();
        proposal.validate(registration)?;
        Ok(proposal)
    }

    pub fn validate(
        &self,
        registration: &WandbPluginRegistration,
    ) -> Result<(), WandbEvaluationError> {
        self.scope.validate()?;
        self.evidence.validate(registration)?;
        self.registration_digest.validate("registration_digest")?;
        for (field, digest) in [
            ("provider_digest", &self.provider_digest),
            ("api_digest", &self.api_digest),
            ("permission_digest", &self.permission_digest),
            ("revision_digest", &self.revision_digest),
            ("metric_digest", &self.metric_digest),
        ] {
            digest.validate(field)?;
        }
        if self.registration_digest != registration.registration_digest
            || self.scope.digest() != &registration.scope_digest
            || self.provider_digest != registration.provider_digest
            || self.api_digest != registration.api_digest
            || self.permission_digest != registration.permission_digest
            || self.revision_digest != registration.revision_digest
            || self.metric_digest != registration.metric_digest
            || self.external_write
            || self.connected
            || self.native
            || self.adopted
        {
            return Err(WandbEvaluationError::ProposalTampered);
        }
        self.proposal_digest.validate("proposal_digest")?;
        if self.proposal_digest != self.calculated_digest() {
            return Err(WandbEvaluationError::ProposalTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&ProposalIdentity {
            scope: self.scope.clone(),
            evidence_digest: self.evidence.evidence_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            revision_digest: self.revision_digest.clone(),
            metric_digest: self.metric_digest.clone(),
            external_write: self.external_write,
            connected: self.connected,
            native: self.native,
            adopted: self.adopted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct ProposalIdentity {
    scope: WandbEvaluationScope,
    evidence_digest: Digest,
    registration_digest: Digest,
    provider_digest: Digest,
    api_digest: Digest,
    permission_digest: Digest,
    revision_digest: Digest,
    metric_digest: Digest,
    external_write: bool,
    connected: bool,
    native: bool,
    adopted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WandbEvaluationReceiptCandidate {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
    pub external_write_performed: bool,
}

impl WandbEvaluationReceiptCandidate {
    pub fn from_proposal(
        proposal: &WandbEvaluationResultProposal,
        registration: &WandbPluginRegistration,
    ) -> Result<Self, WandbEvaluationError> {
        proposal.validate(registration)?;
        Ok(Self {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            scope_digest: proposal.scope.digest().clone(),
            registration_digest: registration.registration_digest.clone(),
            durable: false,
            native: false,
            connected: false,
            external_write_performed: false,
        })
    }
}

fn validate_identifier(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), WandbEvaluationError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
    {
        return Err(WandbEvaluationError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_revision(value: &str, field: &'static str) -> Result<(), WandbEvaluationError> {
    if value.is_empty()
        || value.len() > MAX_REVISION_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/+-".contains(&byte))
    {
        return Err(WandbEvaluationError::InvalidRevision { field });
    }
    Ok(())
}

fn validate_host(value: &str) -> Result<(), WandbEvaluationError> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or(WandbEvaluationError::InvalidHost)?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.contains(':')
        || remainder.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(WandbEvaluationError::InvalidHost);
    }
    let host = remainder.to_ascii_lowercase();
    if !host.contains('.')
        || host.starts_with('.')
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
        return Err(WandbEvaluationError::InvalidHost);
    }
    Ok(())
}

fn validate_bounded_list<T>(
    values: &[T],
    maximum: usize,
    field: &'static str,
) -> Result<(), WandbEvaluationError> {
    if values.len() > maximum {
        return Err(WandbEvaluationError::BoundExceeded { field, maximum });
    }
    Ok(())
}
