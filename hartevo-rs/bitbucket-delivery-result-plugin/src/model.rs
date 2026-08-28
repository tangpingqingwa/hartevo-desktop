//! Bounded, normalized Bitbucket delivery-result models.
//!
//! The model deliberately stops at metadata and digests.  It contains no
//! source, diff, comment, artifact bytes, access token, or pagination token.

use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION, BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION,
    BITBUCKET_PROVIDER_REVISION, MAX_DEPLOYMENTS, MAX_IDENTIFIER_BYTES, MAX_PAGES,
    MAX_RESPONSE_BYTES, MAX_RETRY_AFTER_SECONDS, MAX_STATUS_RECORDS, PAGE_SIZE,
};

pub const MAX_TITLE_BYTES: usize = 4_096;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains whitespace or a control character")]
    InvalidText { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is invalid")]
    Invalid { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid commit hash")]
    InvalidCommitHash { field: &'static str },
    #[error("{field} is not a valid timestamp")]
    InvalidTimestamp { field: &'static str },
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidText { field });
    }
    Ok(())
}

fn validate_positive(value: u64, field: &'static str) -> Result<(), ModelError> {
    if value == 0 {
        Err(ModelError::MustBePositive { field })
    } else {
        Ok(())
    }
}

macro_rules! bounded_string {
    ($name:ident, $field:literal, $allow_internal_whitespace:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(
                    &value,
                    $field,
                    MAX_IDENTIFIER_BYTES,
                    $allow_internal_whitespace,
                )?;
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

bounded_string!(WorkspaceId, "workspace", false);
bounded_string!(RepositorySlug, "repository slug", false);
bounded_string!(RepositoryUuid, "repository UUID", false);
bounded_string!(PipelineUuid, "pipeline UUID", false);
bounded_string!(DeploymentUuid, "deployment UUID", false);
bounded_string!(ProjectId, "Project id", false);
bounded_string!(MissionId, "Mission id", false);
bounded_string!(WorkProductId, "Work Product id", false);
bounded_string!(ProviderRevision, "provider revision", false);

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(String);

impl Revision {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(
            &value,
            "provider object revision",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Revision")
            .field(&sha256_digest(self.0.as_bytes()))
            .finish()
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommitHash(String);

impl CommitHash {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if !(7..=128).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ModelError::InvalidCommitHash {
                field: "commit hash",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }
}

impl fmt::Debug for CommitHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CommitHash")
            .field(&sha256_digest(self.0.as_bytes()))
            .finish()
    }
}

impl fmt::Display for CommitHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for CommitHash {
    type Err = ModelError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    #[serde(rename = "oauth")]
    OAuth,
    #[serde(rename = "api_token")]
    ApiToken,
}

impl fmt::Debug for SecretReferenceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OAuth => "OAuth",
            Self::ApiToken => "ApiToken",
        })
    }
}

/// Host-owned credential metadata.  This type intentionally has no serde
/// implementation: a SecretReference is an opaque handle, never credential
/// material and never a serialized plugin payload.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_id: String,
    credential_revision: u64,
}

impl SecretReference {
    pub fn oauth(
        reference_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            SecretReferenceKind::OAuth,
            reference_id,
            credential_revision,
        )
    }

    pub fn api_token(
        reference_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            SecretReferenceKind::ApiToken,
            reference_id,
            credential_revision,
        )
    }

    pub fn new(
        kind: SecretReferenceKind,
        reference_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(
            &reference_id,
            "SecretReference id",
            MAX_IDENTIFIER_BYTES,
            false,
        )?;
        validate_positive(credential_revision, "credential revision")?;
        Ok(Self {
            kind,
            reference_id,
            credential_revision,
        })
    }

    pub const fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    /// Only a digest of the host handle is allowed across the evidence seam.
    pub fn digest(&self) -> Digest {
        digest_serializable(&(
            self.kind,
            sha256_digest(self.reference_id.as_bytes()),
            self.credential_revision,
        ))
        .expect("SecretReference digest input serializes")
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_id", &"<opaque>")
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

/// Short-lived host-resolved credential.  It is intentionally not
/// serializable and its `Debug` output never contains the token value.
pub struct BitbucketAccessToken {
    value: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl BitbucketAccessToken {
    pub fn new(
        value: impl Into<String>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "access token", MAX_IDENTIFIER_BYTES, false)?;
        if expires_at <= issued_at {
            return Err(ModelError::InvalidTimestamp {
                field: "access token expiry",
            });
        }
        Ok(Self {
            value,
            issued_at,
            expires_at,
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.value
    }

    pub fn issued_at(&self) -> DateTime<Utc> {
        self.issued_at
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn validate_at(&self, at: DateTime<Utc>) -> Result<(), ModelError> {
        if at < self.issued_at || at >= self.expires_at {
            return Err(ModelError::InvalidTimestamp {
                field: "access token validity",
            });
        }
        Ok(())
    }
}

impl fmt::Debug for BitbucketAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitbucketAccessToken")
            .field("value", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Drop for BitbucketAccessToken {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: u64,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "Project revision")?;
        Ok(Self {
            id: ProjectId::parse(id)?,
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
pub struct BitbucketDeliveryScopeInput {
    pub workspace: String,
    pub repository: String,
    pub repository_uuid: Option<String>,
    pub pull_request_id: u64,
    pub commit: String,
    pub build_number: u64,
    pub pipeline_uuid: String,
    pub deployment_uuid: Option<String>,
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitbucketDeliveryScope {
    pub workspace: WorkspaceId,
    pub repository: RepositorySlug,
    pub repository_uuid: Option<RepositoryUuid>,
    pub pull_request_id: PullRequestId,
    pub commit: CommitHash,
    pub build_number: BuildNumber,
    pub pipeline_uuid: PipelineUuid,
    pub deployment_uuid: Option<DeploymentUuid>,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
}

impl BitbucketDeliveryScope {
    pub fn new(input: BitbucketDeliveryScopeInput) -> Result<Self, ModelError> {
        Ok(Self {
            workspace: WorkspaceId::parse(input.workspace)?,
            repository: RepositorySlug::parse(input.repository)?,
            repository_uuid: input
                .repository_uuid
                .map(RepositoryUuid::parse)
                .transpose()?,
            pull_request_id: PullRequestId::new(input.pull_request_id)?,
            commit: CommitHash::new(input.commit)?,
            build_number: BuildNumber::new(input.build_number)?,
            pipeline_uuid: PipelineUuid::parse(input.pipeline_uuid)?,
            deployment_uuid: input
                .deployment_uuid
                .map(DeploymentUuid::parse)
                .transpose()?,
            project: ProjectBinding::new(input.project_id, input.project_revision)?,
            mission: MissionBinding::new(input.mission_id, input.mission_revision)?,
            work_product: WorkProductBinding::new(
                input.work_product_id,
                input.work_product_revision,
            )?,
        })
    }

    pub fn workspace(&self) -> &str {
        self.workspace.as_str()
    }

    pub fn repository(&self) -> &str {
        self.repository.as_str()
    }

    pub fn repository_uuid(&self) -> Option<&str> {
        self.repository_uuid.as_ref().map(RepositoryUuid::as_str)
    }

    pub const fn pull_request_id(&self) -> PullRequestId {
        self.pull_request_id
    }

    pub fn commit(&self) -> &CommitHash {
        &self.commit
    }

    pub const fn build_number(&self) -> BuildNumber {
        self.build_number
    }

    pub fn pipeline_uuid(&self) -> &str {
        self.pipeline_uuid.as_str()
    }

    pub fn deployment_uuid(&self) -> Option<&str> {
        self.deployment_uuid.as_ref().map(DeploymentUuid::as_str)
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

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("Bitbucket scope serializes")
    }
}

pub type BitbucketScope = BitbucketDeliveryScope;
pub type BitbucketScopeInput = BitbucketDeliveryScopeInput;
pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PullRequestId(u64);

impl PullRequestId {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "pull request id")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BuildNumber(u64);

impl BuildNumber {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "build number")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitbucketReadRequest {
    pub expected_repository_revision: Option<Revision>,
    pub expected_pull_request_revision: Option<Revision>,
    pub expected_pipeline_revision: Option<Revision>,
    pub expected_deployment_revision: Option<Revision>,
    pub expected_commit: Option<CommitHash>,
    pub page_size: u16,
    pub max_pages: u16,
    pub request_nonce: Option<String>,
}

impl BitbucketReadRequest {
    pub fn new() -> Self {
        Self {
            expected_repository_revision: None,
            expected_pull_request_revision: None,
            expected_pipeline_revision: None,
            expected_deployment_revision: None,
            expected_commit: None,
            page_size: PAGE_SIZE,
            max_pages: MAX_PAGES,
            request_nonce: None,
        }
    }

    pub fn with_expected_repository_revision(
        mut self,
        revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        self.expected_repository_revision = Some(Revision::new(revision)?);
        Ok(self)
    }

    pub fn with_expected_pull_request_revision(
        mut self,
        revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        self.expected_pull_request_revision = Some(Revision::new(revision)?);
        Ok(self)
    }

    pub fn with_expected_pipeline_revision(
        mut self,
        revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        self.expected_pipeline_revision = Some(Revision::new(revision)?);
        Ok(self)
    }

    pub fn with_expected_deployment_revision(
        mut self,
        revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        self.expected_deployment_revision = Some(Revision::new(revision)?);
        Ok(self)
    }

    pub fn with_expected_commit(mut self, commit: impl Into<String>) -> Result<Self, ModelError> {
        self.expected_commit = Some(CommitHash::new(commit)?);
        Ok(self)
    }

    pub fn with_page_bounds(mut self, page_size: u16, max_pages: u16) -> Result<Self, ModelError> {
        if page_size == 0 || page_size > PAGE_SIZE || max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::Invalid {
                field: "Bitbucket pagination bounds",
            });
        }
        self.page_size = page_size;
        self.max_pages = max_pages;
        Ok(self)
    }

    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Result<Self, ModelError> {
        let nonce = nonce.into();
        validate_text(&nonce, "request nonce", MAX_IDENTIFIER_BYTES, false)?;
        self.request_nonce = Some(nonce);
        Ok(self)
    }

    pub fn idempotency_key(&self, scope: &BitbucketDeliveryScope) -> Digest {
        digest_serializable(&(
            scope.digest(),
            &self.expected_repository_revision,
            &self.expected_pull_request_revision,
            &self.expected_pipeline_revision,
            &self.expected_deployment_revision,
            &self.expected_commit,
            self.page_size,
            self.max_pages,
            &self.request_nonce,
        ))
        .expect("Bitbucket request serializes")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.page_size == 0
            || self.page_size > PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
        {
            return Err(ModelError::Invalid {
                field: "Bitbucket pagination bounds",
            });
        }
        if let Some(nonce) = &self.request_nonce {
            validate_text(nonce, "request nonce", MAX_IDENTIFIER_BYTES, false)?;
        }
        Ok(())
    }
}

impl Default for BitbucketReadRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// A Bitbucket `page` cursor is retained only inside a transport.  Public
/// request/receipt/evidence structures expose its digest, never the token.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct OpaquePageToken(String);

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "Bitbucket page token", MAX_IDENTIFIER_BYTES, false)?;
        Ok(Self(value))
    }

    pub fn digest(&self) -> Digest {
        sha256_digest(self.0.as_bytes())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaquePageToken")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryPayload {
    pub uuid: String,
    pub workspace: String,
    pub slug: String,
    pub name: Option<String>,
    pub is_private: bool,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullRequestPayload {
    pub id: u64,
    pub repository_uuid: String,
    pub state: String,
    pub title: Option<String>,
    pub source_commit: String,
    pub destination_commit: String,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitStatusPayload {
    pub key: String,
    pub name: Option<String>,
    pub state: String,
    pub revision: String,
    pub target_url_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PipelinePayload {
    pub uuid: String,
    pub build_number: u64,
    pub state: String,
    pub result: Option<String>,
    pub commit: String,
    pub target_ref: Option<String>,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentPayload {
    pub uuid: String,
    pub pipeline_uuid: String,
    pub commit: String,
    pub state: String,
    pub environment: Option<String>,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum BitbucketResponseBody {
    Repository(RepositoryPayload),
    PullRequest(PullRequestPayload),
    CommitStatuses(Vec<CommitStatusPayload>),
    Pipeline(PipelinePayload),
    Deployment(DeploymentPayload),
    Empty,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Fake,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryResultState {
    Open,
    Merged,
    Declined,
    Failed,
    Partial,
    Denied,
    #[serde(rename = "rate_limit")]
    RateLimited,
    ProviderUnknown,
    #[serde(rename = "tamper")]
    Tampered,
}

impl DeliveryResultState {
    #[allow(non_upper_case_globals)]
    pub const RateLimit: Self = Self::RateLimited;

    #[allow(non_upper_case_globals)]
    pub const Tamper: Self = Self::Tampered;
}

pub type BitbucketDeliveryResultState = DeliveryResultState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    CommitStatusReadDenied,
    PipelineReadDenied,
    DeploymentReadDenied,
    DeploymentNotFound,
    PaginationBoundExceeded,
    AccessLost,
    ProviderRevisionDrift,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitbucketResponseReceipt {
    pub request_digest: Digest,
    pub path_and_query: String,
    pub api_revision: String,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub page_token_digest: Option<Digest>,
    pub retry_after_seconds: Option<u32>,
    pub raw_provider_payload_retained: bool,
    pub raw_credential_material_retained: bool,
    pub raw_pagination_token_retained: bool,
    pub observed_at: DateTime<Utc>,
}

impl BitbucketResponseReceipt {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.path_and_query.len() > MAX_IDENTIFIER_BYTES * 16
            || self.path_and_query.chars().any(char::is_control)
            || self.raw_provider_payload_retained
            || self.raw_credential_material_retained
            || self.raw_pagination_token_retained
            || self.response_size > MAX_RESPONSE_BYTES
            || self
                .retry_after_seconds
                .is_some_and(|value| value == 0 || value > MAX_RETRY_AFTER_SECONDS)
        {
            return Err(ModelError::Invalid {
                field: "redacted Bitbucket response receipt",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryProjection {
    pub uuid: RepositoryUuid,
    pub workspace: WorkspaceId,
    pub slug: RepositorySlug,
    pub name: Option<String>,
    pub is_private: bool,
    pub revision: Revision,
}

impl RepositoryProjection {
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("repository projection serializes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullRequestProjection {
    pub id: PullRequestId,
    pub repository_uuid: RepositoryUuid,
    pub state: String,
    pub title: Option<String>,
    pub source_commit: CommitHash,
    pub destination_commit: CommitHash,
    pub revision: Revision,
}

impl PullRequestProjection {
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("pull request projection serializes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitStatusProjection {
    pub key: String,
    pub name: Option<String>,
    pub state: String,
    pub revision: Revision,
    pub target_url_digest: Option<Digest>,
}

impl CommitStatusProjection {
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("commit status projection serializes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PipelineProjection {
    pub uuid: PipelineUuid,
    pub build_number: BuildNumber,
    pub state: String,
    pub result: Option<String>,
    pub commit: CommitHash,
    pub target_ref: Option<String>,
    pub revision: Revision,
}

impl PipelineProjection {
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("pipeline projection serializes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentProjection {
    pub uuid: DeploymentUuid,
    pub pipeline_uuid: PipelineUuid,
    pub commit: CommitHash,
    pub state: String,
    pub environment: Option<String>,
    pub revision: Revision,
}

impl DeploymentProjection {
    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("deployment projection serializes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BitbucketDeliveryEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub idempotency_key: Digest,
    pub provenance: TransportProvenance,
    pub state: DeliveryResultState,
    pub repository: Option<RepositoryProjection>,
    pub pull_request: Option<PullRequestProjection>,
    pub commit_statuses: Vec<CommitStatusProjection>,
    pub pipeline: Option<PipelineProjection>,
    pub deployment: Option<DeploymentProjection>,
    pub partial_reasons: Vec<PartialReason>,
    pub page_count: u16,
    pub receipts: Vec<BitbucketResponseReceipt>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_write_performed: bool,
    pub generic_ci_authority: bool,
    pub raw_diff_retained: bool,
    pub raw_comments_retained: bool,
    pub raw_artifact_bytes_retained: bool,
    pub evidence_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BitbucketHttpMethod {
    Get,
}

impl BitbucketDeliveryEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.contract_version != BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || self.provider_revision.as_str() != BITBUCKET_PROVIDER_REVISION
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || !self.read_only
            || self.connected
            || self.native
            || self.first_party
            || self.external_write_performed
            || self.generic_ci_authority
            || self.raw_diff_retained
            || self.raw_comments_retained
            || self.raw_artifact_bytes_retained
            || self.page_count == 0
            || self.page_count > MAX_PAGES
            || self.commit_statuses.len() > MAX_STATUS_RECORDS
            || self.receipts.len() > 1 + 1 + usize::from(MAX_PAGES) + 1 + MAX_DEPLOYMENTS
            || self
                .receipts
                .iter()
                .any(|receipt| receipt.validate().is_err())
            || compute_evidence_digest(self)? != self.evidence_digest
        {
            return Err(ModelError::Invalid {
                field: "Bitbucket delivery evidence",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        self.evidence_digest.clone()
    }
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest(format!("{:x}", Sha256::digest(bytes)))
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(sha256_digest(&bytes))
}

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

pub fn compute_evidence_digest(evidence: &BitbucketDeliveryEvidence) -> Result<Digest, ModelError> {
    let receipts = evidence
        .receipts
        .iter()
        .map(|receipt| ReceiptDigestMaterial {
            request_digest: &receipt.request_digest,
            path_and_query: &receipt.path_and_query,
            api_revision: &receipt.api_revision,
            response_status: receipt.response_status,
            response_size: receipt.response_size,
            response_digest: &receipt.response_digest,
            provider_revision: &receipt.provider_revision,
            page_token_digest: &receipt.page_token_digest,
            retry_after_seconds: &receipt.retry_after_seconds,
            raw_provider_payload_retained: receipt.raw_provider_payload_retained,
            raw_credential_material_retained: receipt.raw_credential_material_retained,
            raw_pagination_token_retained: receipt.raw_pagination_token_retained,
        })
        .collect::<Vec<_>>();
    digest_serializable(&EvidenceDigestMaterial {
        contract_version: &evidence.contract_version,
        contract_digest: &evidence.contract_digest,
        scope_digest: &evidence.scope_digest,
        registration_digest: &evidence.registration_digest,
        provider_revision: &evidence.provider_revision,
        idempotency_key: &evidence.idempotency_key,
        provenance: evidence.provenance,
        state: &evidence.state,
        repository: &evidence.repository,
        pull_request: &evidence.pull_request,
        commit_statuses: &evidence.commit_statuses,
        pipeline: &evidence.pipeline,
        deployment: &evidence.deployment,
        partial_reasons: &evidence.partial_reasons,
        page_count: evidence.page_count,
        receipts,
        read_only: evidence.read_only,
        connected: evidence.connected,
        native: evidence.native,
        first_party: evidence.first_party,
        external_write_performed: evidence.external_write_performed,
        generic_ci_authority: evidence.generic_ci_authority,
        raw_diff_retained: evidence.raw_diff_retained,
        raw_comments_retained: evidence.raw_comments_retained,
        raw_artifact_bytes_retained: evidence.raw_artifact_bytes_retained,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptDigestMaterial<'a> {
    request_digest: &'a Digest,
    path_and_query: &'a str,
    api_revision: &'a str,
    response_status: u16,
    response_size: usize,
    response_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    page_token_digest: &'a Option<Digest>,
    retry_after_seconds: &'a Option<u32>,
    raw_provider_payload_retained: bool,
    raw_credential_material_retained: bool,
    raw_pagination_token_retained: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceDigestMaterial<'a> {
    contract_version: &'a str,
    contract_digest: &'a Digest,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_revision: &'a ProviderRevision,
    idempotency_key: &'a Digest,
    provenance: TransportProvenance,
    state: &'a DeliveryResultState,
    repository: &'a Option<RepositoryProjection>,
    pull_request: &'a Option<PullRequestProjection>,
    commit_statuses: &'a Vec<CommitStatusProjection>,
    pipeline: &'a Option<PipelineProjection>,
    deployment: &'a Option<DeploymentProjection>,
    partial_reasons: &'a Vec<PartialReason>,
    page_count: u16,
    receipts: Vec<ReceiptDigestMaterial<'a>>,
    read_only: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    external_write_performed: bool,
    generic_ci_authority: bool,
    raw_diff_retained: bool,
    raw_comments_retained: bool,
    raw_artifact_bytes_retained: bool,
}

pub fn validate_plugin_metadata(
    plugin_version: &str,
    contract_version: &str,
) -> Result<(), ModelError> {
    if plugin_version != BITBUCKET_DELIVERY_RESULT_PLUGIN_VERSION
        || contract_version != BITBUCKET_DELIVERY_RESULT_CONTRACT_VERSION
    {
        return Err(ModelError::Invalid {
            field: "Bitbucket plugin metadata",
        });
    }
    Ok(())
}

// These aliases preserve the natural names used by a delivery-result caller
// while retaining the provider-specific types above.
pub type Repository = RepositoryProjection;
pub type PullRequest = PullRequestProjection;
pub type Commit = CommitHash;
pub type Build = BuildNumber;
pub type CommitStatus = CommitStatusProjection;
pub type Pipeline = PipelineProjection;
pub type Deployment = DeploymentProjection;
