//! Bounded, provider-specific Azure DevOps Work projections.
//!
//! The types in this module deliberately contain only normalized evidence.
//! They do not retain Azure DevOps JSON, build logs, artifact bytes, download
//! URLs, access tokens, or any other provider payload that would become a
//! second storage/effect authority.

use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use url::Url;

use crate::{
    AZURE_DEVOPS_API_VERSION, AZURE_DEVOPS_WORK_CONTRACT_VERSION,
    AZURE_DEVOPS_WORK_PLUGIN_VERSION_TEXT,
};

pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_TITLE_LENGTH: usize = 4_096;
pub const MAX_STATUS_LENGTH: usize = 128;
pub const MAX_RELATIONS: usize = 128;
pub const MAX_BUILDS: usize = 8;
pub const MAX_TIMELINE_RECORDS: usize = 512;
pub const MAX_ARTIFACTS: usize = 128;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character")]
    ControlCharacter { field: &'static str },
    #[error("{field} is not a valid bounded value")]
    Invalid { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a commit SHA")]
    InvalidCommitSha { field: &'static str },
    #[error("Azure DevOps API version must be {expected}")]
    InvalidApiVersion { expected: &'static str },
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
        return Err(ModelError::ControlCharacter { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid { field });
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
                    MAX_IDENTIFIER_LENGTH,
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

bounded_string!(OrganizationName, "Azure DevOps organization", false);
bounded_string!(ProjectName, "Azure DevOps project", true);
bounded_string!(RepositoryId, "Azure Repos repository id", false);
bounded_string!(MissionId, "Mission id", false);
bounded_string!(HartevoProjectId, "Hartevo project id", false);
bounded_string!(WorkProductId, "Work Product id", false);
bounded_string!(ProviderRevision, "provider revision", false);

#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct WorkItemId(u64);

impl WorkItemId {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "work item id")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for WorkItemId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Display for WorkItemId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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

impl fmt::Debug for PullRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Display for PullRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BuildId(u64);

impl BuildId {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        validate_positive(value, "build id")?;
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for BuildId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Display for BuildId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::InvalidCommitSha {
                field: "commit SHA",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CommitSha").field(&self.0).finish()
    }
}

impl fmt::Display for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
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

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    Digest(format!("{:x}", Sha256::digest(bytes)))
}

pub fn digest_serializable<T: Serialize>(value: &T) -> Result<Digest, ModelError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ModelError::Invalid {
        field: "canonical digest input",
    })?;
    Ok(sha256_digest(&bytes))
}

/// Microsoft Entra authentication mode metadata.  It is an opaque reference
/// only; no token, client secret, refresh token, or certificate is permitted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntraAuthMode {
    Delegated,
    ServicePrincipal,
    ManagedIdentity,
}

/// A reference to host-owned Microsoft Entra credentials.
///
/// The reference is safe to serialize as metadata, but its `Debug` output
/// intentionally redacts all identifying values.  Resolving it is a host
/// concern represented by `EntraCredentialResolver` in the provider module.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntraSecretReference {
    mode: EntraAuthMode,
    reference_id: String,
    tenant_id: String,
    client_id: Option<String>,
    credential_revision: u64,
}

impl EntraSecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::service_principal(reference_id, tenant_id, client_id, credential_revision)
    }

    pub fn delegated(
        reference_id: impl Into<String>,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::build(
            EntraAuthMode::Delegated,
            reference_id.into(),
            tenant_id.into(),
            Some(client_id.into()),
            credential_revision,
        )
    }

    pub fn service_principal(
        reference_id: impl Into<String>,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::build(
            EntraAuthMode::ServicePrincipal,
            reference_id.into(),
            tenant_id.into(),
            Some(client_id.into()),
            credential_revision,
        )
    }

    pub fn managed_identity(
        reference_id: impl Into<String>,
        tenant_id: impl Into<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::build(
            EntraAuthMode::ManagedIdentity,
            reference_id.into(),
            tenant_id.into(),
            None,
            credential_revision,
        )
    }

    fn build(
        mode: EntraAuthMode,
        reference_id: String,
        tenant_id: String,
        client_id: Option<String>,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        validate_text(
            &reference_id,
            "Entra secret reference id",
            MAX_IDENTIFIER_LENGTH,
            false,
        )?;
        validate_text(&tenant_id, "Entra tenant id", MAX_IDENTIFIER_LENGTH, false)?;
        if let Some(client_id) = &client_id {
            validate_text(client_id, "Entra client id", MAX_IDENTIFIER_LENGTH, false)?;
        }
        if credential_revision == 0 {
            return Err(ModelError::MustBePositive {
                field: "credential revision",
            });
        }
        if mode == EntraAuthMode::ManagedIdentity && client_id.is_some() {
            return Err(ModelError::Invalid {
                field: "managed identity client id",
            });
        }
        if mode != EntraAuthMode::ManagedIdentity && client_id.is_none() {
            return Err(ModelError::Invalid {
                field: "Entra client id",
            });
        }
        Ok(Self {
            mode,
            reference_id,
            tenant_id,
            client_id,
            credential_revision,
        })
    }

    pub const fn mode(&self) -> EntraAuthMode {
        self.mode
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }
}

impl fmt::Debug for EntraSecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EntraSecretReference")
            .field("mode", &self.mode)
            .field("reference_id", &"<opaque>")
            .field("tenant_id", &"<opaque>")
            .field("client_id", &self.client_id.as_ref().map(|_| "<opaque>"))
            .field("credential_revision", &self.credential_revision)
            .finish()
    }
}

/// Compatibility spelling used by connector boundaries.  It remains an
/// Entra-only reference and cannot be used to carry credential material.
pub type SecretReference = EntraSecretReference;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDevOpsScopeInput {
    pub organization: String,
    pub project: String,
    pub repository_id: String,
    pub work_item_id: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub hartevo_project_id: String,
    pub project_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDevOpsScope {
    organization: OrganizationName,
    project: ProjectName,
    repository_id: RepositoryId,
    work_item_id: WorkItemId,
    mission_id: MissionId,
    mission_revision: u64,
    hartevo_project_id: HartevoProjectId,
    project_revision: u64,
    work_product_id: WorkProductId,
    work_product_revision: u64,
}

impl AzureDevOpsScope {
    pub fn new(input: AzureDevOpsScopeInput) -> Result<Self, ModelError> {
        if input.mission_revision == 0 {
            return Err(ModelError::MustBePositive {
                field: "mission revision",
            });
        }
        if input.project_revision == 0 {
            return Err(ModelError::MustBePositive {
                field: "project revision",
            });
        }
        if input.work_product_revision == 0 {
            return Err(ModelError::MustBePositive {
                field: "work product revision",
            });
        }
        Ok(Self {
            organization: OrganizationName::parse(input.organization)?,
            project: ProjectName::parse(input.project)?,
            repository_id: RepositoryId::parse(input.repository_id)?,
            work_item_id: WorkItemId::new(input.work_item_id)?,
            mission_id: MissionId::parse(input.mission_id)?,
            mission_revision: input.mission_revision,
            hartevo_project_id: HartevoProjectId::parse(input.hartevo_project_id)?,
            project_revision: input.project_revision,
            work_product_id: WorkProductId::parse(input.work_product_id)?,
            work_product_revision: input.work_product_revision,
        })
    }

    pub fn organization(&self) -> &str {
        self.organization.as_str()
    }

    pub fn project(&self) -> &str {
        self.project.as_str()
    }

    pub fn repository_id(&self) -> &str {
        self.repository_id.as_str()
    }

    pub const fn work_item_id(&self) -> WorkItemId {
        self.work_item_id
    }

    pub fn mission_id(&self) -> &str {
        self.mission_id.as_str()
    }

    pub const fn mission_revision(&self) -> u64 {
        self.mission_revision
    }

    pub fn hartevo_project_id(&self) -> &str {
        self.hartevo_project_id.as_str()
    }

    pub const fn project_revision(&self) -> u64 {
        self.project_revision
    }

    pub fn work_product_id(&self) -> &str {
        self.work_product_id.as_str()
    }

    pub const fn work_product_revision(&self) -> u64 {
        self.work_product_revision
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("Azure DevOps scope serializes")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDevOpsReadRequest {
    pub expected_work_item_rev: Option<u64>,
    pub expected_pull_request_id: Option<PullRequestId>,
}

impl AzureDevOpsReadRequest {
    pub fn new() -> Self {
        Self {
            expected_work_item_rev: None,
            expected_pull_request_id: None,
        }
    }

    pub fn with_expected_work_item_rev(mut self, revision: u64) -> Result<Self, ModelError> {
        validate_positive(revision, "expected work item revision")?;
        self.expected_work_item_rev = Some(revision);
        Ok(self)
    }

    pub fn with_expected_pull_request_id(mut self, id: u64) -> Result<Self, ModelError> {
        self.expected_pull_request_id = Some(PullRequestId::new(id)?);
        Ok(self)
    }
}

impl Default for AzureDevOpsReadRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureReposPullRequestLink {
    pub project: Option<String>,
    pub repository_id: RepositoryId,
    pub pull_request_id: PullRequestId,
}

impl AzureReposPullRequestLink {
    pub fn new(
        project: Option<impl Into<String>>,
        repository_id: impl Into<String>,
        pull_request_id: u64,
    ) -> Result<Self, ModelError> {
        let project = project
            .map(Into::into)
            .map(ProjectName::parse)
            .transpose()?;
        Ok(Self {
            project: project.map(|value| value.to_string()),
            repository_id: RepositoryId::parse(repository_id)?,
            pull_request_id: PullRequestId::new(pull_request_id)?,
        })
    }

    /// Parses the two Azure DevOps relation forms used for work-item links:
    /// an Azure Repos URL and a `vstfs:///Git/PullRequestId/...` artifact link.
    pub fn parse_relation_url(value: &str) -> Result<Self, ModelError> {
        validate_text(value, "work item relation URL", 2_048, false)?;
        let decoded = percent_decode(value);
        let lower = decoded.to_ascii_lowercase();
        if let Some(marker) = lower.find("pullrequestid/") {
            let tail = &decoded[marker + "pullrequestid/".len()..];
            let pieces = tail
                .split(['/', '\\'])
                .filter(|piece| !piece.is_empty())
                .collect::<Vec<_>>();
            if pieces.len() >= 2 {
                let pull_request_id = pieces
                    .last()
                    .and_then(|piece| piece.parse::<u64>().ok())
                    .ok_or(ModelError::Invalid {
                        field: "pull request relation id",
                    })?;
                let repository_id = pieces[pieces.len() - 2].to_owned();
                return Self::new(None::<String>, repository_id, pull_request_id);
            }
        }
        let url = Url::parse(value).map_err(|_| ModelError::Invalid {
            field: "work item relation URL",
        })?;
        let segments = url
            .path_segments()
            .ok_or(ModelError::Invalid {
                field: "work item relation URL",
            })?
            .collect::<Vec<_>>();
        let marker = segments.iter().position(|segment| {
            segment.eq_ignore_ascii_case("pullrequests")
                || segment.eq_ignore_ascii_case("pullrequest")
        });
        let Some(marker) = marker else {
            return Err(ModelError::Invalid {
                field: "pull request relation URL",
            });
        };
        let repository_index = segments
            .iter()
            .position(|segment| segment.eq_ignore_ascii_case("repositories"))
            .and_then(|index| segments.get(index + 1))
            .ok_or(ModelError::Invalid {
                field: "pull request repository relation",
            })?;
        let pull_request_id = segments
            .get(marker + 1)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(ModelError::Invalid {
                field: "pull request relation id",
            })?;
        Self::new(
            None::<String>,
            (*repository_index).to_owned(),
            pull_request_id,
        )
    }
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                output.push(u8::try_from(high * 16 + low).expect("percent byte fits in u8"));
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkItemRelationPayload {
    pub relation_type: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkItemPayload {
    pub id: u64,
    pub rev: u64,
    pub title: Option<String>,
    pub state: Option<String>,
    pub work_item_type: Option<String>,
    pub relations: Vec<WorkItemRelationPayload>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullRequestPayload {
    pub pull_request_id: u64,
    pub repository_id: String,
    pub status: String,
    pub title: Option<String>,
    pub source_ref_name: String,
    pub target_ref_name: String,
    pub source_commit: Option<String>,
    pub target_commit: Option<String>,
    pub last_merge_source_commit: Option<String>,
    pub last_merge_target_commit: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildPayload {
    pub id: u64,
    pub build_number: Option<String>,
    pub status: Option<String>,
    pub result: Option<String>,
    pub source_version: String,
    pub source_branch: String,
    pub repository_id: Option<String>,
    pub queue_time: Option<DateTime<Utc>>,
    pub start_time: Option<DateTime<Utc>>,
    pub finish_time: Option<DateTime<Utc>>,
    pub definition_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelineRecordPayload {
    pub id: String,
    pub record_type: Option<String>,
    pub name: Option<String>,
    pub state: Option<String>,
    pub result: Option<String>,
    pub order: Option<i64>,
    pub start_time: Option<DateTime<Utc>>,
    pub finish_time: Option<DateTime<Utc>>,
    pub error_count: Option<u32>,
    pub warning_count: Option<u32>,
    pub log_reference_present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactPayload {
    pub id: String,
    pub name: String,
    pub artifact_type: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum AzureDevOpsResponseBody {
    WorkItem(WorkItemPayload),
    PullRequest(PullRequestPayload),
    Builds(Vec<BuildPayload>),
    Timeline(Vec<TimelineRecordPayload>),
    Artifacts(Vec<ArtifactPayload>),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    BlockedEnv,
    ProductionRead,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AzureDevOpsResponseReceipt {
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub endpoint: String,
    pub api_version: String,
    pub status: u16,
    pub response_size: usize,
    pub provider_revision: ProviderRevision,
    pub etag: Option<String>,
    pub continuation_token_present: bool,
    pub raw_payload_retained: bool,
    pub raw_logs_retained: bool,
    pub raw_artifacts_retained: bool,
    pub credential_material_retained: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkItemProjection {
    pub id: WorkItemId,
    pub rev: u64,
    pub title: Option<String>,
    pub state: Option<String>,
    pub work_item_type: Option<String>,
    pub pull_request_links: Vec<AzureReposPullRequestLink>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PullRequestProjection {
    pub id: PullRequestId,
    pub repository_id: RepositoryId,
    pub status: String,
    pub title: Option<String>,
    pub source_ref_name: String,
    pub target_ref_name: String,
    pub source_commit: Option<CommitSha>,
    pub target_commit: Option<CommitSha>,
    pub last_merge_source_commit: Option<CommitSha>,
    pub last_merge_target_commit: Option<CommitSha>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildProjection {
    pub id: BuildId,
    pub build_number: Option<String>,
    pub status: Option<String>,
    pub result: Option<String>,
    pub source_version: CommitSha,
    pub source_branch: String,
    pub repository_id: Option<RepositoryId>,
    pub queue_time: Option<DateTime<Utc>>,
    pub start_time: Option<DateTime<Utc>>,
    pub finish_time: Option<DateTime<Utc>>,
    pub definition_name: Option<String>,
    pub work_item_rev: u64,
    pub pull_request_id: PullRequestId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TimelineRecordProjection {
    pub id: String,
    pub record_type: Option<String>,
    pub name: Option<String>,
    pub state: Option<String>,
    pub result: Option<String>,
    pub order: Option<i64>,
    pub start_time: Option<DateTime<Utc>>,
    pub finish_time: Option<DateTime<Utc>>,
    pub error_count: Option<u32>,
    pub warning_count: Option<u32>,
    pub log_reference_present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactProjection {
    pub id: String,
    pub name: String,
    pub artifact_type: Option<String>,
    pub build_id: BuildId,
    pub work_item_rev: u64,
    pub pull_request_id: PullRequestId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuildEvidence {
    pub build: BuildProjection,
    pub timeline: Vec<TimelineRecordProjection>,
    pub artifacts: Vec<ArtifactProjection>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDevOpsWorkEvidence {
    pub contract_version: String,
    pub contract_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_revision: ProviderRevision,
    pub provenance: TransportProvenance,
    pub native_evidence: bool,
    pub external_write_performed: bool,
    pub outcome_authority: bool,
    pub work_item: WorkItemProjection,
    pub pull_request: PullRequestProjection,
    pub builds: Vec<BuildEvidence>,
    pub receipts: Vec<AzureDevOpsResponseReceipt>,
    pub evidence_digest: Digest,
}

impl AzureDevOpsWorkEvidence {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.contract_version != AZURE_DEVOPS_WORK_CONTRACT_VERSION
            || self.provider_revision.as_str().is_empty()
            || self.native_evidence
            || self.external_write_performed
            || self.outcome_authority
            || self.receipts.is_empty()
            || self.builds.is_empty()
        {
            return Err(ModelError::Invalid {
                field: "Azure DevOps Work evidence authority",
            });
        }
        if self.work_item.rev == 0
            || self.pull_request.id.get() == 0
            || self.builds.len() > MAX_BUILDS
        {
            return Err(ModelError::Invalid {
                field: "Azure DevOps Work evidence bounds",
            });
        }
        if self.receipts.iter().any(|receipt| {
            receipt.api_version != AZURE_DEVOPS_API_VERSION
                || receipt.raw_payload_retained
                || receipt.raw_logs_retained
                || receipt.raw_artifacts_retained
                || receipt.credential_material_retained
        }) {
            return Err(ModelError::Invalid {
                field: "Azure DevOps response receipt",
            });
        }
        if self
            .builds
            .iter()
            .flat_map(|evidence| evidence.timeline.iter())
            .any(|record| record.log_reference_present)
        {
            return Err(ModelError::Invalid {
                field: "raw timeline log reference",
            });
        }
        if compute_evidence_digest(self)? != self.evidence_digest {
            return Err(ModelError::Invalid {
                field: "Azure DevOps evidence digest",
            });
        }
        Ok(())
    }
}

pub fn compute_evidence_digest(evidence: &AzureDevOpsWorkEvidence) -> Result<Digest, ModelError> {
    let mut canonical = serde_json::to_value(evidence).map_err(|_| ModelError::Invalid {
        field: "Azure DevOps evidence digest input",
    })?;
    let object = canonical.as_object_mut().ok_or(ModelError::Invalid {
        field: "Azure DevOps evidence digest input",
    })?;
    object.remove("evidenceDigest");
    digest_serializable(&canonical)
}

pub fn validate_api_version(value: &str) -> Result<(), ModelError> {
    if value == AZURE_DEVOPS_API_VERSION {
        Ok(())
    } else {
        Err(ModelError::InvalidApiVersion {
            expected: AZURE_DEVOPS_API_VERSION,
        })
    }
}

pub fn validate_plugin_metadata(
    plugin_version: &str,
    contract_version: &str,
) -> Result<(), ModelError> {
    if plugin_version != AZURE_DEVOPS_WORK_PLUGIN_VERSION_TEXT {
        return Err(ModelError::Invalid {
            field: "plugin version",
        });
    }
    if contract_version != AZURE_DEVOPS_WORK_CONTRACT_VERSION {
        return Err(ModelError::Invalid {
            field: "contract version",
        });
    }
    Ok(())
}
