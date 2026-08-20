//! Layer 1 Vercel delivery capability.
//!
//! This crate is deliberately self-contained because the protected Desktop
//! workspace cannot be widened by a root-layer plugin. It exposes three typed
//! seams: DeploymentService, VercelDeploymentProvider, and
//! MissionSelectedResultConsumer. The provider has only authenticated read
//! operations; there is no deployment-creation method in this crate.

#![deny(unsafe_code)]

mod provider;
mod service;
mod transport;

pub use provider::{
    BlockedEnvCredentialResolver, DeploymentEventApi, DeploymentEventProjection,
    DeploymentEventsProjection, DeploymentListApi, DeploymentListProjection,
    DeploymentPaginationApi, DeploymentProjection, DeploymentSourceProjection,
    EnvironmentVercelCredentialResolver, ProjectApi, TeamApi, VercelApiTransport,
    VercelCredentialResolver, VercelDeploymentApi, VercelDeploymentProvider,
    VercelDeploymentSourceApi, VercelProviderError, VercelProviderState,
};
pub use service::{
    ConsumerError, DeploymentService, DeploymentServiceDefinition, MissionSelectedResultConsumer,
    SelectedPreviewResult, SelectedResultStatus, ServiceOperation,
};
pub use transport::{
    RetryPolicy, UreqVercelHttpTransport, VercelHttpTransportConfigurationError,
    VercelTransportError,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-vercel-delivery-plugin-contract/v1";
pub const CONTRACT_VERSION: &str = "vercel-delivery-layer1/v1";
pub const PLUGIN_ID: &str = "hartevo.vercel-delivery";
pub const PLUGIN_VERSION: &str = "vercel-delivery/v1";
pub const SERVICE_ID: &str = "DeploymentService";
pub const PROVIDER_ID: &str = "vercel";
pub const PROVIDER_ID_ADAPTER: &str = "deployment.vercel";
pub const PROVIDER_ADAPTER_VERSION: u32 = 1;
pub const CONSUMER_ID: &str = "MissionSelectedResultConsumer";
pub const API_BASE_URL: &str = "https://api.vercel.com";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/vercel-delivery/deployment.v1.json");
pub const VERCEL_TOKEN_ENVIRONMENT_VARIABLE: &str = "HARTEVO_VERCEL_TOKEN";

const SHA256_HEX_LENGTH: usize = 64;

/// Provider evidence provenance. Only ProductionProvider may be reported as
/// native or Connected; controlled transports and fixtures remain useful for
/// tests without becoming false production claims.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    ProductionProvider,
    ControlledProvider,
    Fixture,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        matches!(self, Self::ProductionProvider)
    }
}

/// The only external target environment authorized by Layer 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentEnvironment {
    Preview,
    Production,
    Development,
    Unknown,
}

impl DeploymentEnvironment {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Production => "production",
            Self::Development => "development",
            Self::Unknown => "unknown",
        }
    }

    pub(crate) fn from_api(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_lowercase).as_deref() {
            Some("preview") => Self::Preview,
            Some("production") => Self::Production,
            Some("development" | "developmental") => Self::Development,
            _ => Self::Unknown,
        }
    }
}

/// The normalized deployment lifecycle state projected by the provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentState {
    Queued,
    Building,
    Ready,
    Error,
    Cancelled,
    Unknown,
}

impl DeploymentState {
    pub(crate) fn from_api(value: Option<&str>) -> Self {
        match value.map(str::to_ascii_uppercase).as_deref() {
            Some("QUEUED" | "INITIALIZING" | "ANALYZING" | "CREATING") => Self::Queued,
            Some("BUILDING" | "PROVISIONING") => Self::Building,
            Some("READY") => Self::Ready,
            Some("ERROR" | "LOAD_ERROR") => Self::Error,
            Some("CANCELED" | "CANCELLED") => Self::Cancelled,
            _ => Self::Unknown,
        }
    }
}

/// A Hartevo Project/Mission binding. It contains identifiers only and is
/// safe to include in a proposal or read projection.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
}

impl MissionScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
    ) -> Result<Self, VercelDeliveryError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            mission_id: mission_id.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn digest(&self) -> String {
        digest_parts([
            self.tenant_id.as_str(),
            self.project_id.as_str(),
            self.mission_id.as_str(),
        ])
    }

    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        validate_identifier(&self.tenant_id, "tenant_id")?;
        validate_identifier(&self.project_id, "project_id")?;
        validate_identifier(&self.mission_id, "mission_id")
    }
}

/// The exact Vercel team/project target. Layer 1 registrations are Preview
/// scoped so a proposal cannot silently become a Production operation.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VercelTarget {
    pub team_id: String,
    pub project_id: String,
    pub environment: DeploymentEnvironment,
}

impl VercelTarget {
    pub fn preview(
        team_id: impl Into<String>,
        project_id: impl Into<String>,
    ) -> Result<Self, VercelDeliveryError> {
        Self::new(team_id, project_id, DeploymentEnvironment::Preview)
    }

    pub fn new(
        team_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: DeploymentEnvironment,
    ) -> Result<Self, VercelDeliveryError> {
        let target = Self {
            team_id: team_id.into(),
            project_id: project_id.into(),
            environment,
        };
        target.validate()?;
        Ok(target)
    }

    pub fn digest(&self) -> String {
        digest_parts([
            self.team_id.as_str(),
            self.project_id.as_str(),
            self.environment.as_str(),
        ])
    }

    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        validate_identifier(&self.team_id, "team_id")?;
        validate_identifier(&self.project_id, "vercel project_id")?;
        if self.environment != DeploymentEnvironment::Preview {
            return Err(VercelDeliveryError::UnsupportedTargetEnvironment {
                environment: self.environment.as_str().to_owned(),
            });
        }
        Ok(())
    }
}

/// Opaque credential identity. The token bytes are deliberately absent from
/// this type and can only be resolved for the duration of one provider call.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VercelSecretReference {
    pub reference_id: String,
    pub scope_digest: String,
    pub credential_revision: u64,
}

impl VercelSecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope_digest: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, VercelDeliveryError> {
        let reference = Self {
            reference_id: reference_id.into(),
            scope_digest: scope_digest.into(),
            credential_revision,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn for_target(
        reference_id: impl Into<String>,
        scope: &MissionScope,
        target: &VercelTarget,
        credential_revision: u64,
    ) -> Result<Self, VercelDeliveryError> {
        Self::new(
            reference_id,
            registration_scope_digest(scope, target),
            credential_revision,
        )
    }

    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        if !self.reference_id.starts_with("secret-ref-") {
            return Err(VercelDeliveryError::InvalidInput {
                field: "secret reference_id".to_owned(),
                detail: "must start with secret-ref-".to_owned(),
            });
        }
        validate_identifier(&self.reference_id, "secret reference_id")?;
        validate_digest(&self.scope_digest, "secret scope_digest")?;
        if self.credential_revision == 0 {
            return Err(VercelDeliveryError::InvalidInput {
                field: "credential_revision".to_owned(),
                detail: "must be positive".to_owned(),
            });
        }
        Ok(())
    }
}

/// Version-, digest-, and scope-bound registration state. Revocation is
/// monotonic and makes subsequent provider operations fail closed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VercelPluginRegistration {
    pub scope: MissionScope,
    pub target: VercelTarget,
    pub secret_reference: VercelSecretReference,
    pub plugin_version: String,
    pub registration_digest: String,
    pub revoked_at_ms: Option<u64>,
}

impl VercelPluginRegistration {
    pub fn new(
        scope: MissionScope,
        target: VercelTarget,
        secret_reference: VercelSecretReference,
        plugin_version: impl Into<String>,
    ) -> Result<Self, VercelDeliveryError> {
        let registration = Self {
            scope,
            target,
            secret_reference,
            plugin_version: plugin_version.into(),
            registration_digest: String::new(),
            revoked_at_ms: None,
        };
        let registration = Self {
            registration_digest: registration.compute_digest(),
            ..registration
        };
        registration.validate()?;
        Ok(registration)
    }

    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        self.scope.validate()?;
        self.target.validate()?;
        self.secret_reference.validate()?;
        validate_identifier(&self.plugin_version, "plugin_version")?;
        if self.plugin_version != PLUGIN_VERSION {
            return Err(VercelDeliveryError::InvalidInput {
                field: "plugin_version".to_owned(),
                detail: "does not match the registered Layer 1 plugin version".to_owned(),
            });
        }
        if self.secret_reference.scope_digest
            != registration_scope_digest(&self.scope, &self.target)
        {
            return Err(VercelDeliveryError::ScopeMismatch {
                detail: "secret reference is not bound to the Mission and Vercel target".to_owned(),
            });
        }
        if self.registration_digest != self.compute_digest() {
            return Err(VercelDeliveryError::DigestMismatch {
                field: "registration_digest".to_owned(),
            });
        }
        Ok(())
    }

    pub fn revoke(&mut self, revoked_at_ms: u64) -> Result<(), VercelDeliveryError> {
        if revoked_at_ms == 0 {
            return Err(VercelDeliveryError::InvalidInput {
                field: "revoked_at_ms".to_owned(),
                detail: "must be positive".to_owned(),
            });
        }
        if let Some(existing) = self.revoked_at_ms {
            if existing != revoked_at_ms {
                return Err(VercelDeliveryError::AlreadyRevoked);
            }
            return Ok(());
        }
        self.revoked_at_ms = Some(revoked_at_ms);
        self.registration_digest = self.compute_digest();
        Ok(())
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked_at_ms.is_some()
    }

    pub(crate) fn compute_digest(&self) -> String {
        let credential_revision = self.secret_reference.credential_revision.to_string();
        let revoked_at = self
            .revoked_at_ms
            .map_or_else(String::new, |value| value.to_string());
        digest_parts([
            PLUGIN_ID,
            self.plugin_version.as_str(),
            self.scope.digest().as_str(),
            self.target.digest().as_str(),
            self.secret_reference.reference_id.as_str(),
            self.secret_reference.scope_digest.as_str(),
            credential_revision.as_str(),
            revoked_at.as_str(),
        ])
    }
}

/// Source identity that must be preserved by a Preview proposal.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceCommit {
    pub repository: String,
    pub reference: String,
    pub sha: String,
}

impl SourceCommit {
    pub fn new(
        repository: impl Into<String>,
        reference: impl Into<String>,
        sha: impl Into<String>,
    ) -> Result<Self, VercelDeliveryError> {
        let commit = Self {
            repository: repository.into(),
            reference: reference.into(),
            sha: sha.into(),
        };
        commit.validate()?;
        Ok(commit)
    }

    pub fn digest(&self) -> String {
        digest_parts([
            self.repository.as_str(),
            self.reference.as_str(),
            self.sha.as_str(),
        ])
    }

    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        validate_identifier(&self.repository, "source repository")?;
        validate_identifier(&self.reference, "source reference")?;
        if !is_git_sha(&self.sha) {
            return Err(VercelDeliveryError::InvalidInput {
                field: "source commit sha".to_owned(),
                detail: "must be a lowercase 40 or 64 character hexadecimal commit id".to_owned(),
            });
        }
        Ok(())
    }
}

/// One source file's immutable digest. Layer 1 records the manifest; it does
/// not upload these files or create a deployment.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactFile {
    pub path: String,
    pub digest: String,
    pub size_bytes: u64,
}

impl ArtifactFile {
    pub fn new(
        path: impl Into<String>,
        digest: impl Into<String>,
        size_bytes: u64,
    ) -> Result<Self, VercelDeliveryError> {
        let file = Self {
            path: path.into(),
            digest: digest.into(),
            size_bytes,
        };
        file.validate()?;
        Ok(file)
    }

    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        validate_artifact_path(&self.path)?;
        validate_digest(&self.digest, "artifact file digest")
    }
}

/// Canonical artifact manifest used to bind a proposal to exact file digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactManifest {
    pub files: Vec<ArtifactFile>,
    pub artifact_digest: String,
}

impl ArtifactManifest {
    pub fn new(files: impl IntoIterator<Item = ArtifactFile>) -> Result<Self, VercelDeliveryError> {
        let files = canonical_files(files.into_iter().collect())?;
        let manifest = Self {
            artifact_digest: artifact_digest(&files),
            files,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        let files = canonical_files(self.files.clone())?;
        if files != self.files {
            return Err(VercelDeliveryError::NonCanonicalArtifact);
        }
        if artifact_digest(&self.files) != self.artifact_digest {
            return Err(VercelDeliveryError::DigestMismatch {
                field: "artifact_digest".to_owned(),
            });
        }
        validate_digest(&self.artifact_digest, "artifact_digest")
    }

    pub fn digest(&self) -> &str {
        &self.artifact_digest
    }
}

/// Input for a canonical, prepare-only Preview deployment proposal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreviewDeploymentProposalInput {
    pub scope: MissionScope,
    pub source_commit: SourceCommit,
    pub artifact: ArtifactManifest,
    pub requested_at_ms: u64,
}

impl PreviewDeploymentProposalInput {
    pub fn new(
        scope: MissionScope,
        source_commit: SourceCommit,
        artifact: ArtifactManifest,
        requested_at_ms: u64,
    ) -> Result<Self, VercelDeliveryError> {
        let input = Self {
            scope,
            source_commit,
            artifact,
            requested_at_ms,
        };
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        self.scope.validate()?;
        self.source_commit.validate()?;
        self.artifact.validate()?;
        if self.requested_at_ms == 0 {
            return Err(VercelDeliveryError::InvalidInput {
                field: "requested_at_ms".to_owned(),
                detail: "must be positive".to_owned(),
            });
        }
        Ok(())
    }
}

/// Authenticated, exact team/project target projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetProjection {
    pub team_id: String,
    pub team_slug: String,
    pub team_name: String,
    pub project_id: String,
    pub project_name: String,
    pub account_id: Option<String>,
    pub framework: Option<String>,
    pub environment: DeploymentEnvironment,
    pub scope_digest: String,
    pub provenance: ProviderProvenance,
    pub native: bool,
}

impl TargetProjection {
    pub(crate) fn digest(&self) -> String {
        digest_parts([
            self.team_id.as_str(),
            self.team_slug.as_str(),
            self.team_name.as_str(),
            self.project_id.as_str(),
            self.project_name.as_str(),
            self.account_id.as_deref().unwrap_or_default(),
            self.framework.as_deref().unwrap_or_default(),
            self.environment.as_str(),
            self.scope_digest.as_str(),
            if self.native { "native" } else { "controlled" },
        ])
    }
}

/// Canonical read/proposal record. external_effect_created is structurally
/// fixed to false by construction and rechecked by validate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreviewDeploymentProposal {
    pub proposal_id: String,
    pub proposal_digest: String,
    pub scope: MissionScope,
    pub target: VercelTarget,
    pub target_projection: TargetProjection,
    pub source_commit: SourceCommit,
    pub artifact_digest: String,
    pub file_digests: Vec<ArtifactFile>,
    pub plugin_id: String,
    pub plugin_version: String,
    pub service_id: String,
    pub registration_digest: String,
    pub operation: String,
    pub requested_at_ms: u64,
    pub non_mutating: bool,
    pub external_effect_created: bool,
}

impl PreviewDeploymentProposal {
    pub fn validate(&self) -> Result<(), VercelDeliveryError> {
        self.scope.validate()?;
        self.target.validate()?;
        if self.target_projection.environment != DeploymentEnvironment::Preview
            || self.target.environment != DeploymentEnvironment::Preview
        {
            return Err(VercelDeliveryError::UnsupportedTargetEnvironment {
                environment: self.target.environment.as_str().to_owned(),
            });
        }
        if self.target_projection.team_id != self.target.team_id
            || self.target_projection.project_id != self.target.project_id
        {
            return Err(VercelDeliveryError::ScopeMismatch {
                detail: "target projection differs from proposal target".to_owned(),
            });
        }
        if self.target_projection.scope_digest
            != registration_scope_digest(&self.scope, &self.target)
        {
            return Err(VercelDeliveryError::ScopeMismatch {
                detail: "target projection is not bound to the proposal Mission and Vercel target"
                    .to_owned(),
            });
        }
        if self.target_projection.native != self.target_projection.provenance.is_native() {
            return Err(VercelDeliveryError::ScopeMismatch {
                detail: "native flag does not match provider provenance".to_owned(),
            });
        }
        self.source_commit.validate()?;
        let artifact = ArtifactManifest {
            files: self.file_digests.clone(),
            artifact_digest: self.artifact_digest.clone(),
        };
        artifact.validate()?;
        if self.plugin_id != PLUGIN_ID || self.service_id != SERVICE_ID {
            return Err(VercelDeliveryError::InvalidInput {
                field: "proposal identity".to_owned(),
                detail: "plugin and service identifiers do not match Layer 1".to_owned(),
            });
        }
        validate_identifier(&self.plugin_version, "plugin_version")?;
        validate_digest(&self.registration_digest, "registration_digest")?;
        if self.operation != "preview_proposal"
            || !self.non_mutating
            || self.external_effect_created
            || self.requested_at_ms == 0
        {
            return Err(VercelDeliveryError::MutationForbidden);
        }
        validate_digest(&self.proposal_digest, "proposal_digest")?;
        if self.proposal_digest != self.compute_digest() {
            return Err(VercelDeliveryError::DigestMismatch {
                field: "proposal_digest".to_owned(),
            });
        }
        if self.proposal_id != format!("preview-proposal-{}", &self.proposal_digest[..24]) {
            return Err(VercelDeliveryError::DigestMismatch {
                field: "proposal_id".to_owned(),
            });
        }
        Ok(())
    }

    pub(crate) fn compute_digest(&self) -> String {
        let files_digest = artifact_digest(&self.file_digests);
        digest_parts([
            self.scope.digest().as_str(),
            self.target.digest().as_str(),
            self.target_projection.digest().as_str(),
            self.source_commit.digest().as_str(),
            self.artifact_digest.as_str(),
            files_digest.as_str(),
            self.plugin_id.as_str(),
            self.plugin_version.as_str(),
            self.service_id.as_str(),
            self.registration_digest.as_str(),
            self.operation.as_str(),
            self.requested_at_ms.to_string().as_str(),
        ])
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum VercelDeliveryError {
    #[error("BLOCKED_ENV: Vercel credential is unavailable")]
    BlockedEnv,
    #[error("provider is disconnected")]
    Disconnected,
    #[error("provider registration is revoked")]
    Revoked,
    #[error("invalid {field}: {detail}")]
    InvalidInput { field: String, detail: String },
    #[error("scope mismatch: {detail}")]
    ScopeMismatch { detail: String },
    #[error("digest mismatch for {field}")]
    DigestMismatch { field: String },
    #[error("artifact files are not in canonical order")]
    NonCanonicalArtifact,
    #[error("unsupported target environment: {environment}")]
    UnsupportedTargetEnvironment { environment: String },
    #[error("provider request was rejected: {detail}")]
    ProviderRejected { detail: String },
    #[error("provider response was uncertain: {detail}")]
    ProviderUncertain { detail: String },
    #[error("provider response could not be decoded: {detail}")]
    Decode { detail: String },
    #[error("provider transport failed: {detail}")]
    Transport { detail: String },
    #[error("provider is rate limited")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("provider retry budget exhausted: {detail}")]
    RetryExhausted { detail: String },
    #[error("provider registration is already revoked")]
    AlreadyRevoked,
    #[error("Layer 1 cannot create or execute a deployment")]
    MutationForbidden,
    #[error("selected result is not adoptable: {detail}")]
    NotAdoptable { detail: String },
}

pub(crate) fn registration_scope_digest(scope: &MissionScope, target: &VercelTarget) -> String {
    digest_parts([
        PROVIDER_ID,
        scope.digest().as_str(),
        target.team_id.as_str(),
        target.project_id.as_str(),
        target.environment.as_str(),
    ])
}

pub(crate) fn artifact_digest(files: &[ArtifactFile]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"hartevo-vercel-artifact/v1\0");
    for file in files {
        update_length_prefixed(&mut hasher, file.path.as_bytes());
        update_length_prefixed(&mut hasher, file.digest.as_bytes());
        update_length_prefixed(&mut hasher, file.size_bytes.to_string().as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub(crate) fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"hartevo-vercel-delivery/v1\0");
    for part in parts {
        update_length_prefixed(&mut hasher, part.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

fn update_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(bytes.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(bytes);
    hasher.update(b"|");
}

pub(crate) fn canonical_files(
    mut files: Vec<ArtifactFile>,
) -> Result<Vec<ArtifactFile>, VercelDeliveryError> {
    for file in &files {
        file.validate()?;
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    if files.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err(VercelDeliveryError::InvalidInput {
            field: "artifact files".to_owned(),
            detail: "paths must be unique".to_owned(),
        });
    }
    Ok(files)
}

pub(crate) fn validate_identifier(value: &str, field: &str) -> Result<(), VercelDeliveryError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(VercelDeliveryError::InvalidInput {
            field: field.to_owned(),
            detail: "must be non-empty and contain no control characters".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &str, field: &str) -> Result<(), VercelDeliveryError> {
    if value.len() == SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(VercelDeliveryError::InvalidInput {
            field: field.to_owned(),
            detail: "must be a lowercase SHA-256 digest".to_owned(),
        })
    }
}

fn is_git_sha(value: &str) -> bool {
    (value.len() == 40 || value.len() == SHA256_HEX_LENGTH)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_artifact_path(path: &str) -> Result<(), VercelDeliveryError> {
    if path.trim().is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || path.chars().any(char::is_control)
    {
        return Err(VercelDeliveryError::InvalidInput {
            field: "artifact path".to_owned(),
            detail: "must be a normalized relative path".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn scope() -> MissionScope {
        MissionScope::new("tenant-1", "project-1", "mission-1").expect("scope")
    }

    fn target() -> VercelTarget {
        VercelTarget::preview("team_1", "prj_1").expect("target")
    }

    #[test]
    fn artifact_manifest_is_sorted_and_bound_to_file_digests() {
        let files = [
            ArtifactFile::new("z.txt", DIGEST_B, 2).expect("z"),
            ArtifactFile::new("a.txt", DIGEST_A, 1).expect("a"),
        ];
        let manifest = ArtifactManifest::new(files).expect("manifest");
        assert_eq!(manifest.files[0].path, "a.txt");
        assert_eq!(manifest.files[1].path, "z.txt");
        assert!(manifest.validate().is_ok());
        let mut tampered = manifest.clone();
        tampered.files[0].digest = DIGEST_B.to_owned();
        assert!(matches!(
            tampered.validate(),
            Err(VercelDeliveryError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn registration_digest_changes_on_revocation_and_scope_is_exact() {
        let scope = scope();
        let target = target();
        let secret =
            VercelSecretReference::for_target("secret-ref-1", &scope, &target, 1).expect("secret");
        let mut registration =
            VercelPluginRegistration::new(scope.clone(), target.clone(), secret, PLUGIN_VERSION)
                .expect("registration");
        let before = registration.registration_digest.clone();
        registration.revoke(1).expect("revoke");
        assert_ne!(before, registration.registration_digest);
        assert!(registration.validate().is_ok());
        let wrong_secret = VercelSecretReference::new("secret-ref-2", scope.digest(), 1)
            .expect("secret reference");
        assert!(matches!(
            VercelPluginRegistration::new(scope, target, wrong_secret, PLUGIN_VERSION),
            Err(VercelDeliveryError::ScopeMismatch { .. })
        ));
    }

    #[test]
    fn source_commit_requires_a_full_git_sha() {
        assert!(SourceCommit::new("org/site", "main", COMMIT).is_ok());
        assert!(SourceCommit::new("org/site", "main", "short").is_err());
    }

    #[test]
    fn contract_declares_read_only_preview_layer() {
        let contract: serde_json::Value =
            serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(contract["layer"], 1);
        assert_eq!(
            contract["provider"]["deploymentCreation"],
            "forbidden_in_layer_1"
        );
        assert_eq!(contract["target"]["environment"], "preview");
        assert_eq!(contract["nativeBoundary"]["loopbackIsNative"], false);
    }
}
