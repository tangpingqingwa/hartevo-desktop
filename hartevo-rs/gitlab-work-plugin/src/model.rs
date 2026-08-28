//! Stable, provider-specific GitLab work types.
//!
//! The model intentionally stops below Hartevo's Effect, Receipt, Verification
//! and Outcome authority.  It contains no credential material, no provider
//! payloads and no mutation operations.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use url::{Host, Url};

pub const PROVIDER_ID: &str = "gitlab.work";
pub const SERVICE_ID: &str = "gitlab.work";
pub const CONTRACT_VERSION: &str = "gitlab-work/v1";
pub const SERVICE_VERSION: &str = "1.0.0";
pub const EVIDENCE_LEVEL: &str = "E1";
pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_TITLE_LENGTH: usize = 4_096;
pub const MAX_STATUS_LENGTH: usize = 64;
pub const MAX_APPROVERS: usize = 64;
pub const MAX_JOBS: usize = 256;
pub const MAX_REPLAY_ENTRIES: usize = 1_024;
pub const MAX_WEBHOOK_BODY_BYTES: usize = 1_048_576;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is invalid: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{field} exceeds its maximum length")]
    TooLong { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
}

fn validate_bounded(value: &str, field: &'static str, max: usize) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > max {
        return Err(ModelError::TooLong { field });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::Invalid {
            field,
            reason: "whitespace is not allowed",
        });
    }
    Ok(())
}

macro_rules! bounded_string {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_bounded(&value, $field, MAX_IDENTIFIER_LENGTH)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
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

macro_rules! positive_id {
    ($name:ident, $field:literal) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            pub fn new(value: u64) -> Result<Self, ModelError> {
                if value == 0 {
                    return Err(ModelError::MustBePositive { field: $field });
                }
                Ok(Self(value))
            }

            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

bounded_string!(MissionId, "mission id");
bounded_string!(HartevoProjectId, "Hartevo project id");
bounded_string!(WorkProductId, "work product id");
bounded_string!(ProviderUserId, "provider user id");
bounded_string!(RefName, "ref name");
bounded_string!(ProviderRevision, "provider revision");

positive_id!(GitLabProjectId, "GitLab project id");
positive_id!(IssueIid, "Issue IID");
positive_id!(MergeRequestIid, "Merge Request IID");
positive_id!(GlobalGitLabId, "GitLab global id");
positive_id!(PipelineId, "pipeline id");
positive_id!(JobId, "job id");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct NamespacePath(String);

impl NamespacePath {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_bounded(&value, "namespace path", MAX_IDENTIFIER_LENGTH)?;
        if value.starts_with('/')
            || value.ends_with('/')
            || value.split('/').any(|segment| {
                segment.is_empty()
                    || !segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
        {
            return Err(ModelError::Invalid {
                field: "namespace path",
                reason: "must be slash-separated GitLab path segments",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NamespacePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CommitSha(String);

impl CommitSha {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::Invalid {
                field: "commit SHA",
                reason: "must be exactly 40 hexadecimal characters",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CommitSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into().to_ascii_lowercase();
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ModelError::Invalid {
                field: "SHA-256 digest",
                reason: "must be exactly 64 hexadecimal characters",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

pub fn sha256_digest(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    Digest(value)
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitLabHost {
    GitLabCom,
    SelfManaged { origin: String },
}

impl GitLabHost {
    pub fn parse(value: &str) -> Result<Self, ModelError> {
        let url = Url::parse(value).map_err(|_| ModelError::Invalid {
            field: "GitLab host",
            reason: "must be a valid HTTPS origin",
        })?;
        let origin = normalized_origin(&url)?;
        if url.path() != "" && url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(ModelError::Invalid {
                field: "GitLab host",
                reason: "must not contain a path, query or fragment",
            });
        }
        if origin == "https://gitlab.com" {
            Ok(Self::GitLabCom)
        } else {
            Ok(Self::SelfManaged { origin })
        }
    }

    pub fn gitlab_com() -> Self {
        Self::GitLabCom
    }

    pub fn self_managed(value: &str) -> Result<Self, ModelError> {
        match Self::parse(value)? {
            Self::GitLabCom => Err(ModelError::Invalid {
                field: "self-managed GitLab host",
                reason: "GitLab.com must use the GitLab.com registration",
            }),
            Self::SelfManaged { origin } => Ok(Self::SelfManaged { origin }),
        }
    }

    pub fn origin(&self) -> &str {
        match self {
            Self::GitLabCom => "https://gitlab.com",
            Self::SelfManaged { origin } => origin,
        }
    }

    pub fn matches_url(&self, value: &str) -> Result<bool, ModelError> {
        let url = Url::parse(value).map_err(|_| ModelError::Invalid {
            field: "provider URL",
            reason: "must be a valid HTTPS URL",
        })?;
        Ok(normalized_origin(&url)? == self.origin())
    }
}

fn normalized_origin(url: &Url) -> Result<String, ModelError> {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return Err(ModelError::Invalid {
            field: "GitLab host",
            reason: "only HTTPS without userinfo is allowed",
        });
    }
    let host = url.host().ok_or(ModelError::Invalid {
        field: "GitLab host",
        reason: "host is required",
    })?;
    let host_text = match host {
        Host::Domain(value) => value.to_ascii_lowercase(),
        Host::Ipv4(value) => value.to_string(),
        Host::Ipv6(value) => format!("[{value}]"),
    };
    let port = url.port().filter(|port| *port != 443);
    Ok(match port {
        Some(port) => format!("https://{host_text}:{port}"),
        None => format!("https://{host_text}"),
    })
}

pub(crate) fn url_origin(value: &str) -> Result<String, ModelError> {
    let url = Url::parse(value).map_err(|_| ModelError::Invalid {
        field: "provider URL",
        reason: "must be a valid HTTPS URL",
    })?;
    normalized_origin(&url)
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    OAuth,
    Pat,
}

/// A reference into a credential boundary.  It deliberately cannot contain a
/// token, and its `Debug` implementation never prints even the opaque handle.
#[derive(Clone, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretReference {
    kind: SecretKind,
    reference_id: String,
}

impl SecretReference {
    pub fn oauth(reference_id: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(SecretKind::OAuth, reference_id)
    }

    pub fn pat(reference_id: impl Into<String>) -> Result<Self, ModelError> {
        Self::new(SecretKind::Pat, reference_id)
    }

    fn new(kind: SecretKind, reference_id: impl Into<String>) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_bounded(&reference_id, "secret reference id", MAX_IDENTIFIER_LENGTH)?;
        Ok(Self { kind, reference_id })
    }

    pub const fn kind(&self) -> &SecretKind {
        &self.kind
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_id", &"<opaque>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScope {
    pub mission_id: MissionId,
    pub mission_revision: u64,
    pub project_id: HartevoProjectId,
    pub project_revision: u64,
    pub work_product_id: WorkProductId,
    pub work_product_revision: u64,
}

impl MissionScope {
    pub fn new(
        mission_id: MissionId,
        mission_revision: u64,
        project_id: HartevoProjectId,
        project_revision: u64,
        work_product_id: WorkProductId,
        work_product_revision: u64,
    ) -> Result<Self, ModelError> {
        if mission_revision == 0 {
            return Err(ModelError::MustBePositive {
                field: "mission revision",
            });
        }
        if project_revision == 0 {
            return Err(ModelError::MustBePositive {
                field: "project revision",
            });
        }
        if work_product_revision == 0 {
            return Err(ModelError::MustBePositive {
                field: "work product revision",
            });
        }
        Ok(Self {
            mission_id,
            mission_revision,
            project_id,
            project_revision,
            work_product_id,
            work_product_revision,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitLabScopeSpec {
    pub host: GitLabHost,
    pub namespace: NamespacePath,
    pub project_id: GitLabProjectId,
    pub issue_iid: Option<IssueIid>,
    pub merge_request_iid: Option<MergeRequestIid>,
    pub source_ref: Option<RefName>,
    pub target_ref: Option<RefName>,
    pub source_sha: Option<CommitSha>,
    pub target_sha: Option<CommitSha>,
    pub head_sha: Option<CommitSha>,
    pub pipeline_id: Option<PipelineId>,
    pub job_ids: Vec<JobId>,
    pub mission: MissionScope,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitLabScope {
    pub host: GitLabHost,
    pub namespace: NamespacePath,
    pub project_id: GitLabProjectId,
    pub issue_iid: Option<IssueIid>,
    pub merge_request_iid: Option<MergeRequestIid>,
    pub source_ref: Option<RefName>,
    pub target_ref: Option<RefName>,
    pub source_sha: Option<CommitSha>,
    pub target_sha: Option<CommitSha>,
    pub head_sha: Option<CommitSha>,
    pub pipeline_id: Option<PipelineId>,
    pub job_ids: Vec<JobId>,
    pub mission: MissionScope,
}

impl GitLabScope {
    pub fn new(spec: GitLabScopeSpec) -> Result<Self, ModelError> {
        if spec.issue_iid.is_none()
            && spec.merge_request_iid.is_none()
            && spec.pipeline_id.is_none()
        {
            return Err(ModelError::Invalid {
                field: "GitLab scope",
                reason: "at least one Issue IID, Merge Request IID or pipeline id is required",
            });
        }
        if spec.merge_request_iid.is_some()
            && (spec.source_ref.is_none()
                || spec.target_ref.is_none()
                || spec.source_sha.is_none()
                || spec.target_sha.is_none()
                || spec.head_sha.is_none())
        {
            return Err(ModelError::Invalid {
                field: "Merge Request scope",
                reason: "source/target refs and all three SHAs are required",
            });
        }
        if spec.pipeline_id.is_some() && spec.head_sha.is_none() {
            return Err(ModelError::Invalid {
                field: "pipeline scope",
                reason: "head SHA is required",
            });
        }
        if spec.job_ids.len() > MAX_JOBS {
            return Err(ModelError::TooLong { field: "job ids" });
        }
        let mut job_ids = spec.job_ids;
        job_ids.sort_unstable();
        if job_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ModelError::Invalid {
                field: "job ids",
                reason: "duplicate job ids are not allowed",
            });
        }
        Ok(Self {
            host: spec.host,
            namespace: spec.namespace,
            project_id: spec.project_id,
            issue_iid: spec.issue_iid,
            merge_request_iid: spec.merge_request_iid,
            source_ref: spec.source_ref,
            target_ref: spec.target_ref,
            source_sha: spec.source_sha,
            target_sha: spec.target_sha,
            head_sha: spec.head_sha,
            pipeline_id: spec.pipeline_id,
            job_ids,
            mission: spec.mission,
        })
    }

    pub fn fence(&self) -> Digest {
        digest_serializable(self)
    }

    pub fn sha_fence(&self) -> ShaFence {
        ShaFence {
            source_sha: self.source_sha.clone(),
            target_sha: self.target_sha.clone(),
            head_sha: self.head_sha.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ShaFence {
    pub source_sha: Option<CommitSha>,
    pub target_sha: Option<CommitSha>,
    pub head_sha: Option<CommitSha>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    DescribeCapabilities,
    ProbeRegistration,
    ReadIssueGraph,
    ReadMergeRequest,
    ReadPipelineResult,
    CompileIssueProposal,
    CompileMergeRequestProposal,
    VerifyWebhookEnvelope,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationRequest {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub host: GitLabHost,
    pub scope: GitLabScope,
    pub provider_revision: ProviderRevision,
    pub secret_reference: SecretReference,
    pub capabilities: BTreeSet<Capability>,
}

impl RegistrationRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin_version: impl Into<String>,
        contract_version: impl Into<String>,
        contract_digest: Digest,
        provider_id: impl Into<String>,
        host: GitLabHost,
        scope: GitLabScope,
        provider_revision: ProviderRevision,
        secret_reference: SecretReference,
        capabilities: BTreeSet<Capability>,
    ) -> Result<Self, ModelError> {
        let plugin_version = plugin_version.into();
        let contract_version = contract_version.into();
        let provider_id = provider_id.into();
        validate_bounded(&plugin_version, "plugin version", MAX_IDENTIFIER_LENGTH)?;
        validate_bounded(&contract_version, "contract version", MAX_IDENTIFIER_LENGTH)?;
        validate_bounded(&provider_id, "provider id", MAX_IDENTIFIER_LENGTH)?;
        if host != scope.host {
            return Err(ModelError::Invalid {
                field: "registration host",
                reason: "must exactly match the scope host",
            });
        }
        if capabilities.is_empty() {
            return Err(ModelError::Invalid {
                field: "registration capabilities",
                reason: "at least one capability is required",
            });
        }
        Ok(Self {
            plugin_version,
            contract_version,
            contract_digest,
            provider_id,
            host,
            scope,
            provider_revision,
            secret_reference,
            capabilities,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationBinding {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub host: GitLabHost,
    pub scope: GitLabScope,
    pub provider_revision: ProviderRevision,
    pub secret_reference: SecretReference,
    pub capabilities: BTreeSet<Capability>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    binding: RegistrationBinding,
    state: RegistrationState,
    generation: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationChangeReceipt {
    pub previous_state: RegistrationState,
    pub current_state: RegistrationState,
    pub generation: u64,
    pub registration_fence: Digest,
    pub reversible: bool,
}

impl Registration {
    pub(crate) fn from_request(request: RegistrationRequest) -> Self {
        Self {
            binding: RegistrationBinding {
                plugin_version: request.plugin_version,
                contract_version: request.contract_version,
                contract_digest: request.contract_digest,
                provider_id: request.provider_id,
                host: request.host,
                scope: request.scope,
                provider_revision: request.provider_revision,
                secret_reference: request.secret_reference,
                capabilities: request.capabilities,
            },
            state: RegistrationState::Active,
            generation: 1,
        }
    }

    pub fn binding(&self) -> &RegistrationBinding {
        &self.binding
    }

    pub const fn state(&self) -> RegistrationState {
        self.state
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn registration_fence(&self) -> Digest {
        digest_serializable(&(&self.binding, self.generation, self.state))
    }

    pub fn revoke(&mut self) -> Result<RegistrationChangeReceipt, ModelError> {
        if !self.is_active() {
            return Err(ModelError::Invalid {
                field: "registration state",
                reason: "registration is already revoked",
            });
        }
        let previous_state = self.state;
        self.state = RegistrationState::Revoked;
        self.generation = self.generation.saturating_add(1);
        Ok(self.change_receipt(previous_state))
    }

    pub fn reinstate(&mut self) -> Result<RegistrationChangeReceipt, ModelError> {
        if self.is_active() {
            return Err(ModelError::Invalid {
                field: "registration state",
                reason: "registration is already active",
            });
        }
        let previous_state = self.state;
        self.state = RegistrationState::Active;
        self.generation = self.generation.saturating_add(1);
        Ok(self.change_receipt(previous_state))
    }

    fn change_receipt(&self, previous_state: RegistrationState) -> RegistrationChangeReceipt {
        RegistrationChangeReceipt {
            previous_state,
            current_state: self.state,
            generation: self.generation,
            registration_fence: self.registration_fence(),
            reversible: true,
        }
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

    pub const fn is_first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityDescription {
    pub capability: Capability,
    pub read_only: bool,
    pub provider_provenance: ProviderProvenance,
    pub native_evidence: bool,
    pub mutates_provider: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GitLabWorkService {
    pub service_id: String,
    pub provider_id: String,
    pub contract_version: String,
    pub service_version: String,
    pub evidence_level: String,
    pub provider_provenance: ProviderProvenance,
    pub read_only: bool,
    pub connected: bool,
    pub native_evidence: bool,
    pub first_party_evidence: bool,
}

impl GitLabWorkService {
    pub fn new(provider_provenance: ProviderProvenance) -> Self {
        Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            service_version: SERVICE_VERSION.to_owned(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            provider_provenance,
            read_only: true,
            connected: false,
            native_evidence: false,
            first_party_evidence: false,
        }
    }

    pub fn describe_capabilities(&self) -> Vec<CapabilityDescription> {
        [
            Capability::DescribeCapabilities,
            Capability::ProbeRegistration,
            Capability::ReadIssueGraph,
            Capability::ReadMergeRequest,
            Capability::ReadPipelineResult,
            Capability::CompileIssueProposal,
            Capability::CompileMergeRequestProposal,
            Capability::VerifyWebhookEnvelope,
        ]
        .into_iter()
        .map(|capability| CapabilityDescription {
            capability,
            read_only: true,
            provider_provenance: self.provider_provenance,
            native_evidence: false,
            mutates_provider: false,
        })
        .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderFence {
    pub provider_id: String,
    pub service_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub registration_fence: Digest,
    pub host: GitLabHost,
    pub scope_fence: Digest,
    pub provider_revision: ProviderRevision,
    pub provenance: ProviderProvenance,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueState {
    Opened,
    Closed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueProjection {
    pub scope: GitLabScope,
    pub scope_fence: Digest,
    pub registration_fence: Digest,
    pub provider_revision: ProviderRevision,
    pub provenance: ProviderProvenance,
    pub project_id: GitLabProjectId,
    pub iid: IssueIid,
    pub global_id: GlobalGitLabId,
    pub title: String,
    pub state: IssueState,
    pub updated_at: Option<String>,
    pub web_url: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeRequestState {
    Opened,
    Closed,
    Merged,
    Locked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStatus {
    CanBeMerged,
    CannotBeMerged,
    Checking,
    Unknown,
}

impl MergeStatus {
    pub const fn eligible(self) -> Option<bool> {
        match self {
            Self::CanBeMerged => Some(true),
            Self::CannotBeMerged => Some(false),
            Self::Checking | Self::Unknown => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Approved,
    NeedsApproval,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalEntry {
    pub user_id: ProviderUserId,
    pub approved_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalProjection {
    pub scope: GitLabScope,
    pub scope_fence: Digest,
    pub registration_fence: Digest,
    pub provider_revision: ProviderRevision,
    pub provenance: ProviderProvenance,
    pub project_id: GitLabProjectId,
    pub merge_request_iid: MergeRequestIid,
    pub state: ApprovalState,
    pub required: u32,
    pub approvals_left: u32,
    pub approvers: Vec<ApprovalEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MergeRequestProjection {
    pub scope: GitLabScope,
    pub scope_fence: Digest,
    pub registration_fence: Digest,
    pub provider_revision: ProviderRevision,
    pub provenance: ProviderProvenance,
    pub project_id: GitLabProjectId,
    pub iid: MergeRequestIid,
    pub global_id: GlobalGitLabId,
    pub title: String,
    pub state: MergeRequestState,
    pub draft: bool,
    pub source_ref: RefName,
    pub target_ref: RefName,
    pub source_sha: CommitSha,
    pub target_sha: CommitSha,
    pub head_sha: CommitSha,
    pub merge_status: MergeStatus,
    pub merge_status_detail: String,
    pub updated_at: Option<String>,
    pub web_url: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStatus {
    Created,
    Pending,
    Running,
    Success,
    Failed,
    Canceled,
    Skipped,
    Manual,
    Scheduled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Created,
    Pending,
    Running,
    Success,
    Failed,
    Canceled,
    Skipped,
    Manual,
    WaitingForResource,
    Preparing,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobProjection {
    pub id: JobId,
    pub name: String,
    pub stage: String,
    pub status: JobStatus,
    pub sha: Option<CommitSha>,
    pub provider_revision: ProviderRevision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PipelineProjection {
    pub scope: GitLabScope,
    pub scope_fence: Digest,
    pub registration_fence: Digest,
    pub provider_revision: ProviderRevision,
    pub provenance: ProviderProvenance,
    pub project_id: GitLabProjectId,
    pub pipeline_id: PipelineId,
    pub sha: CommitSha,
    pub ref_name: RefName,
    pub status: PipelineStatus,
    pub jobs: Vec<JobProjection>,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRequestReceipt {
    pub operation: String,
    pub request_fingerprint: Digest,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub page: u16,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub final_origin: String,
    pub rate_limit: RateLimitObservation,
    pub raw_payload_retained: bool,
    pub credential_material_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitObservation {
    pub remaining: Option<u64>,
    pub reset_at: Option<u64>,
    pub retry_after_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProposal {
    pub kind: WorkProposalKind,
    pub scope: GitLabScope,
    pub mission_scope: MissionScope,
    pub provider_fence: ProviderFence,
    pub sha_fence: ShaFence,
    pub subject: WorkProposalSubject,
    pub non_mutating: bool,
    pub creates_effect: bool,
    pub adopts_work_product: bool,
    pub native_evidence: bool,
    pub proposal_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkProposalKind {
    IssueObservation,
    MergeRequestObservation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum WorkProposalSubject {
    Issue(Box<IssueProjection>),
    MergeRequest {
        merge_request: Box<MergeRequestProjection>,
        approval: Box<ApprovalProjection>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PipelineResultProposal {
    pub scope: GitLabScope,
    pub mission_scope: MissionScope,
    pub provider_fence: ProviderFence,
    pub sha_fence: ShaFence,
    pub pipeline: PipelineProjection,
    pub non_mutating: bool,
    pub creates_effect: bool,
    pub adopts_work_product: bool,
    pub native_evidence: bool,
    pub proposal_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookEnvelope {
    pub host: GitLabHost,
    pub project_id: GitLabProjectId,
    pub delivery_id: String,
    pub event_name: String,
    pub timestamp: i64,
    pub payload_digest: Digest,
    pub payload_size: usize,
    pub signature_digest: Digest,
}

impl WebhookEnvelope {
    pub fn new(
        host: GitLabHost,
        project_id: GitLabProjectId,
        delivery_id: impl Into<String>,
        event_name: impl Into<String>,
        timestamp: i64,
        body: &[u8],
        signature: &str,
    ) -> Result<Self, ModelError> {
        if body.len() > MAX_WEBHOOK_BODY_BYTES {
            return Err(ModelError::TooLong {
                field: "webhook body",
            });
        }
        let delivery_id = delivery_id.into();
        let event_name = event_name.into();
        validate_bounded(&delivery_id, "webhook delivery id", MAX_IDENTIFIER_LENGTH)?;
        if event_name.is_empty()
            || event_name.len() > MAX_STATUS_LENGTH
            || event_name.chars().any(char::is_control)
        {
            return Err(ModelError::Invalid {
                field: "webhook event name",
                reason: "must be bounded and contain no control characters",
            });
        }
        validate_bounded(signature, "webhook signature", 512)?;
        if timestamp <= 0 {
            return Err(ModelError::Invalid {
                field: "webhook timestamp",
                reason: "must be a positive Unix timestamp",
            });
        }
        Ok(Self {
            host,
            project_id,
            delivery_id,
            event_name,
            timestamp,
            payload_digest: sha256_digest(body),
            payload_size: body.len(),
            signature_digest: sha256_digest(signature.as_bytes()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookVerificationReceipt {
    pub delivery_id: String,
    pub project_id: GitLabProjectId,
    pub origin: String,
    pub payload_digest: Digest,
    pub signature_digest: Digest,
    pub timestamp: i64,
    pub verified: bool,
    pub accepted_as_truth: bool,
    pub requires_readback: bool,
    pub provider_provenance: ProviderProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UntrustedWebhookSignal {
    pub event_name: String,
    pub delivery_id: String,
    pub scope_fence: Digest,
    pub provider_revision: ProviderRevision,
    pub receipt: WebhookVerificationReceipt,
    pub change_signal_only: bool,
    pub accepted_as_truth: bool,
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    match serde_json::to_vec(value) {
        Ok(bytes) => sha256_digest(&bytes),
        Err(_) => sha256_digest(b"serialization-error"),
    }
}
