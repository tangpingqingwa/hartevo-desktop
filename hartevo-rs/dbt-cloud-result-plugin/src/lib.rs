#![forbid(unsafe_code)]
#![doc = "Standalone Layer-1 dbt Cloud transformation-result plugin."]
//!
//! This crate is deliberately a read/proposal/recording boundary. It does
//! not trigger, cancel, retry, or mutate a dbt Cloud job; it does not resolve
//! credentials; and it does not adopt a Hartevo kernel Outcome. The public
//! types are the service definition, provider seam, bounded evidence model,
//! registration lifecycle, and Mission-scoped proposal consumer.
//!
//! Every response is bounded and typed. Raw logs, artifact bodies, bearer
//! tokens, and generic SQL/data-truth authority have no representation here.
//! Fixture, fake, recording, loopback, and BLOCKED_ENV transports are always
//! projected as disconnected, non-native Layer-1 evidence.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.dbt-cloud-result/v1";
pub const SERVICE_ID: &str = "transformation.dbt-cloud.result.read";
pub const PROVIDER_ID: &str = "dbt-cloud";
pub const SERVICE_VERSION: Version = Version::new(0, 1, 0);
pub const DBT_CLOUD_API_V2: &str = "v2";
pub const DBT_CLOUD_API_V3: &str = "v3";
pub const DEFAULT_API_HOST: &str = "cloud.getdbt.com";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SELECTOR_BYTES: usize = 512;
pub const MAX_SELECTOR_COUNT: usize = 256;
pub const MAX_ARTIFACT_COUNT: usize = 64;
pub const MAX_ARTIFACT_NAME_BYTES: usize = 256;
pub const MAX_STEP_COUNT: usize = 128;
pub const MAX_STEP_ID_BYTES: usize = 128;
pub const MAX_EVIDENCE_ITEMS: usize = 4_096;
pub const MAX_PAGE_COUNT: usize = 32;
pub const MAX_PAGE_ITEMS: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ARTIFACT_METADATA_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    major: u16,
    minor: u16,
    patch: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("contract values must serialize");
        Self::from_bytes(&bytes)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64 && self.0.bytes().all(|byte| byte.is_ascii_hexdigit())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DbtCloudApiVersion {
    V2,
    V3,
}

impl DbtCloudApiVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2 => DBT_CLOUD_API_V2,
            Self::V3 => DBT_CLOUD_API_V3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepositoryIdentity {
    pub provider: String,
    pub owner: String,
    pub name: String,
    pub url: String,
}

impl RepositoryIdentity {
    pub fn new(
        provider: impl Into<String>,
        owner: impl Into<String>,
        name: impl Into<String>,
        url: impl Into<String>,
    ) -> Result<Self, DbtCloudError> {
        let identity = Self {
            provider: provider.into(),
            owner: owner.into(),
            name: name.into(),
            url: url.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), DbtCloudError> {
        validate_identifier("repository provider", &self.provider)?;
        validate_identifier("repository owner", &self.owner)?;
        validate_identifier("repository name", &self.name)?;
        validate_bounded_text("repository URL", &self.url, MAX_IDENTIFIER_BYTES)?;
        if !(self.url.starts_with("https://") || self.url.starts_with("ssh://")) {
            return Err(DbtCloudError::InvalidInput("repository URL"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionScopeBinding {
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub policy_digest: Digest,
    pub consent_digest: Digest,
}

impl MissionScopeBinding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        project_revision: u64,
        mission_revision: u64,
        work_product_revision: u64,
        policy_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, DbtCloudError> {
        let binding = Self {
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            work_product_id: work_product_id.into(),
            project_revision,
            mission_revision,
            work_product_revision,
            policy_digest,
            consent_digest,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<(), DbtCloudError> {
        validate_identifier("Hartevo Project", &self.project_id)?;
        validate_identifier("Hartevo Mission", &self.mission_id)?;
        validate_identifier("Hartevo Work Product", &self.work_product_id)?;
        if self.project_revision == 0
            || self.mission_revision == 0
            || self.work_product_revision == 0
        {
            return Err(DbtCloudError::InvalidInput("scope revision"));
        }
        if !self.policy_digest.is_valid() || !self.consent_digest.is_valid() {
            return Err(DbtCloudError::InvalidDigest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DbtCloudPermission {
    JobRead,
    RunRead,
    RunResultsRead,
    ArtifactMetadataRead,
}

impl DbtCloudPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JobRead => "job:read",
            Self::RunRead => "run:read",
            Self::RunResultsRead => "run-results:read",
            Self::ArtifactMetadataRead => "artifact-metadata:read",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbtCloudScope {
    pub api_version: DbtCloudApiVersion,
    pub api_host: String,
    pub account_id: String,
    pub dbt_project_id: String,
    pub environment_id: String,
    pub job_id: String,
    pub repository: RepositoryIdentity,
    pub commit_sha: String,
    pub model_selectors: Vec<String>,
    pub test_selectors: Vec<String>,
    pub artifact_allowlist: Vec<String>,
    pub mission: MissionScopeBinding,
    pub permissions: BTreeSet<DbtCloudPermission>,
}

impl DbtCloudScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        api_version: DbtCloudApiVersion,
        api_host: impl Into<String>,
        account_id: impl Into<String>,
        dbt_project_id: impl Into<String>,
        environment_id: impl Into<String>,
        job_id: impl Into<String>,
        repository: RepositoryIdentity,
        commit_sha: impl Into<String>,
        model_selectors: impl IntoIterator<Item = String>,
        test_selectors: impl IntoIterator<Item = String>,
        artifact_allowlist: impl IntoIterator<Item = String>,
        mission: MissionScopeBinding,
        permissions: impl IntoIterator<Item = DbtCloudPermission>,
    ) -> Result<Self, DbtCloudError> {
        let scope = Self {
            api_version,
            api_host: api_host.into(),
            account_id: account_id.into(),
            dbt_project_id: dbt_project_id.into(),
            environment_id: environment_id.into(),
            job_id: job_id.into(),
            repository,
            commit_sha: commit_sha.into(),
            model_selectors: canonical_strings(model_selectors, MAX_SELECTOR_COUNT)?,
            test_selectors: canonical_strings(test_selectors, MAX_SELECTOR_COUNT)?,
            artifact_allowlist: canonical_strings(artifact_allowlist, MAX_ARTIFACT_COUNT)?,
            mission,
            permissions: permissions.into_iter().collect(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), DbtCloudError> {
        validate_bounded_text("API host", &self.api_host, MAX_IDENTIFIER_BYTES)?;
        if self.api_host.contains('/') || self.api_host.contains('@') {
            return Err(DbtCloudError::InvalidInput("API host"));
        }
        validate_identifier("dbt account", &self.account_id)?;
        validate_identifier("dbt project", &self.dbt_project_id)?;
        validate_identifier("dbt environment", &self.environment_id)?;
        validate_identifier("dbt job", &self.job_id)?;
        self.repository.validate()?;
        validate_commit_sha(&self.commit_sha)?;
        validate_selector_list(&self.model_selectors, MAX_SELECTOR_COUNT)?;
        validate_selector_list(&self.test_selectors, MAX_SELECTOR_COUNT)?;
        if self.model_selectors.is_empty() {
            return Err(DbtCloudError::InvalidInput("model selectors"));
        }
        validate_artifact_list(&self.artifact_allowlist)?;
        self.mission.validate()?;
        if !self.permissions.contains(&DbtCloudPermission::JobRead)
            || !self.permissions.contains(&DbtCloudPermission::RunRead)
            || !self
                .permissions
                .contains(&DbtCloudPermission::RunResultsRead)
        {
            return Err(DbtCloudError::PermissionDrift);
        }
        if !self.artifact_allowlist.is_empty()
            && !self
                .permissions
                .contains(&DbtCloudPermission::ArtifactMetadataRead)
        {
            return Err(DbtCloudError::PermissionDrift);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn account_digest(&self) -> Digest {
        Digest::from_text(&self.account_id)
    }

    pub fn project_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.dbt_project_id,
            &self.environment_id,
            self.mission.project_revision,
        ))
    }

    pub fn environment_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.dbt_project_id,
            &self.environment_id,
            self.mission.mission_revision,
        ))
    }

    pub fn job_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.account_id,
            &self.dbt_project_id,
            &self.environment_id,
            &self.job_id,
        ))
    }

    pub fn repository_digest(&self) -> Digest {
        self.repository.digest()
    }

    pub fn commit_digest(&self) -> Digest {
        Digest::from_text(&self.commit_sha)
    }

    pub fn model_selector_digest(&self) -> Digest {
        Digest::from_serializable(&self.model_selectors)
    }

    pub fn test_selector_digest(&self) -> Digest {
        Digest::from_serializable(&self.test_selectors)
    }

    pub fn selector_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.model_selector_digest(),
            self.test_selector_digest(),
            &self.artifact_allowlist,
        ))
    }

    pub fn permission_digest(&self) -> Digest {
        let permissions: Vec<&str> = self
            .permissions
            .iter()
            .map(|permission| permission.as_str())
            .collect();
        Digest::from_serializable(&permissions)
    }
}

/// The reference names a keyring entry; it never contains or serializes a
/// dbt token. Its debug representation contains only digests and a revision.
pub struct SecretReference {
    reference_id: String,
    scope_digest: Digest,
    credential_revision: u64,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_id: self.reference_id.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_id == other.reference_id
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest())
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &DbtCloudScope,
        credential_revision: u64,
    ) -> Result<Self, DbtCloudError> {
        scope.validate()?;
        let reference = Self {
            reference_id: reference_id.into(),
            scope_digest: scope.scope_digest(),
            credential_revision,
            revoked: false,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.reference_id,
            &self.scope_digest,
            self.credential_revision,
        ))
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> u64 {
        self.credential_revision
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    fn validate(&self) -> Result<(), DbtCloudError> {
        if !self.reference_id.starts_with("secret-ref-") {
            return Err(DbtCloudError::InvalidSecretReference);
        }
        validate_identifier("secret reference", &self.reference_id)?;
        if self.credential_revision == 0 || !self.scope_digest.is_valid() {
            return Err(DbtCloudError::InvalidSecretReference);
        }
        Ok(())
    }

    fn is_bound_to(&self, scope: &DbtCloudScope) -> bool {
        !self.revoked && self.scope_digest == scope.scope_digest()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Unmounted,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbtCloudRegistration {
    pub schema_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub plugin_version: Version,
    pub api_version: DbtCloudApiVersion,
    pub status: RegistrationStatus,
    pub version_digest: Digest,
    pub account_digest: Digest,
    pub project_digest: Digest,
    pub environment_digest: Digest,
    pub job_digest: Digest,
    pub repository_digest: Digest,
    pub commit_digest: Digest,
    pub selector_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub credential_digest: Digest,
    pub registration_digest: Digest,
}

#[derive(Serialize)]
struct RegistrationDigestInput<'a> {
    schema_version: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    plugin_version: Version,
    api_version: DbtCloudApiVersion,
    version_digest: &'a Digest,
    account_digest: &'a Digest,
    project_digest: &'a Digest,
    environment_digest: &'a Digest,
    job_digest: &'a Digest,
    repository_digest: &'a Digest,
    commit_digest: &'a Digest,
    selector_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    credential_digest: &'a Digest,
}

impl DbtCloudRegistration {
    pub fn new(
        scope: &DbtCloudScope,
        secret_reference: &SecretReference,
    ) -> Result<Self, DbtCloudError> {
        scope.validate()?;
        if !secret_reference.is_bound_to(scope) {
            return Err(DbtCloudError::SecretScopeMismatch);
        }
        let version_digest = Digest::from_serializable(&(
            CONTRACT_SCHEMA,
            SERVICE_ID,
            PROVIDER_ID,
            SERVICE_VERSION,
            scope.api_version,
        ));
        let mut registration = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            service_id: SERVICE_ID.into(),
            provider_id: PROVIDER_ID.into(),
            plugin_version: SERVICE_VERSION,
            api_version: scope.api_version,
            status: RegistrationStatus::Active,
            version_digest,
            account_digest: scope.account_digest(),
            project_digest: scope.project_digest(),
            environment_digest: scope.environment_digest(),
            job_digest: scope.job_digest(),
            repository_digest: scope.repository_digest(),
            commit_digest: scope.commit_digest(),
            selector_digest: scope.selector_digest(),
            permission_digest: scope.permission_digest(),
            scope_digest: scope.scope_digest(),
            credential_digest: secret_reference.reference_digest(),
            registration_digest: Digest::from_text("uncomputed"),
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&RegistrationDigestInput {
            schema_version: &self.schema_version,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            plugin_version: self.plugin_version,
            api_version: self.api_version,
            version_digest: &self.version_digest,
            account_digest: &self.account_digest,
            project_digest: &self.project_digest,
            environment_digest: &self.environment_digest,
            job_digest: &self.job_digest,
            repository_digest: &self.repository_digest,
            commit_digest: &self.commit_digest,
            selector_digest: &self.selector_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            credential_digest: &self.credential_digest,
        })
    }

    pub fn validate_binding(
        &self,
        scope: &DbtCloudScope,
        secret_reference: &SecretReference,
    ) -> Result<(), DbtCloudError> {
        if self.compute_digest() != self.registration_digest {
            return Err(DbtCloudError::RegistrationTampered);
        }
        let expected = Self::new(scope, secret_reference)?;
        if self.scope_digest != expected.scope_digest
            || self.account_digest != expected.account_digest
            || self.project_digest != expected.project_digest
            || self.environment_digest != expected.environment_digest
            || self.job_digest != expected.job_digest
            || self.repository_digest != expected.repository_digest
            || self.commit_digest != expected.commit_digest
            || self.selector_digest != expected.selector_digest
            || self.permission_digest != expected.permission_digest
            || self.version_digest != expected.version_digest
            || self.credential_digest != expected.credential_digest
        {
            return Err(DbtCloudError::RegistrationBindingDrift);
        }
        Ok(())
    }

    pub fn unmount(&mut self) -> Result<(), DbtCloudError> {
        match self.status {
            RegistrationStatus::Active => {
                self.status = RegistrationStatus::Unmounted;
                Ok(())
            }
            RegistrationStatus::Unmounted => Ok(()),
            RegistrationStatus::Revoked => Err(DbtCloudError::RegistrationRevoked),
        }
    }

    pub fn remount(
        &mut self,
        scope: &DbtCloudScope,
        secret_reference: &SecretReference,
    ) -> Result<(), DbtCloudError> {
        if self.status == RegistrationStatus::Revoked {
            return Err(DbtCloudError::RegistrationRevoked);
        }
        self.validate_binding(scope, secret_reference)?;
        self.status = RegistrationStatus::Active;
        Ok(())
    }

    pub fn revoke(&mut self, secret_reference: &mut SecretReference) -> RevocationReceipt {
        self.status = RegistrationStatus::Revoked;
        secret_reference.revoke();
        RevocationReceipt {
            schema_version: CONTRACT_SCHEMA.into(),
            registration_digest: self.registration_digest.clone(),
            status: self.status,
            credential_digest: self.credential_digest.clone(),
        }
    }

    pub fn is_active(&self) -> bool {
        self.status == RegistrationStatus::Active
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub schema_version: String,
    pub registration_digest: Digest,
    pub status: RegistrationStatus,
    pub credential_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DbtCloudOperation {
    DescribeJob,
    ReadRunEvidence,
    ReadRunResults,
    CompileTransformationProposal,
    RecordRunReceipt,
    VerifyDataProductResult,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbtCloudServiceDefinition {
    pub schema_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub service_version: Version,
    pub layer: u8,
    pub operations: Vec<DbtCloudOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub forbidden_effects: Vec<String>,
}

impl DbtCloudServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.into(),
            service_id: SERVICE_ID.into(),
            provider_id: PROVIDER_ID.into(),
            service_version: SERVICE_VERSION,
            layer: 1,
            operations: vec![
                DbtCloudOperation::DescribeJob,
                DbtCloudOperation::ReadRunEvidence,
                DbtCloudOperation::ReadRunResults,
                DbtCloudOperation::CompileTransformationProposal,
                DbtCloudOperation::RecordRunReceipt,
                DbtCloudOperation::VerifyDataProductResult,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            forbidden_effects: vec![
                "trigger_live_job".into(),
                "cancel_live_job".into(),
                "retry_live_job".into(),
                "mutate_credentials".into(),
                "retain_raw_logs".into(),
                "retain_unbounded_artifact_bodies".into(),
                "adopt_kernel_outcome".into(),
                "generic_scheduler".into(),
                "sql_authority".into(),
                "data_truth_authority".into(),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Queued,
    Running,
    Success,
    Error,
    Cancelled,
    Partial,
    Expired,
    AccessLoss,
    ProviderUnknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceNodeKind {
    Model,
    Test,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceNodeStatus {
    Pass,
    Fail,
    Error,
    Skipped,
    Warn,
    NoResult,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobConfiguration {
    pub account_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub job_id: String,
    pub repository: RepositoryIdentity,
    pub branch: Option<String>,
    pub commit_sha: Option<String>,
    pub model_selector_digest: Digest,
    pub test_selector_digest: Digest,
    pub selector_digest: Digest,
    pub configured_step_ids: Vec<String>,
}

impl JobConfiguration {
    pub fn for_scope(scope: &DbtCloudScope) -> Self {
        Self {
            account_id: scope.account_id.clone(),
            project_id: scope.dbt_project_id.clone(),
            environment_id: scope.environment_id.clone(),
            job_id: scope.job_id.clone(),
            repository: scope.repository.clone(),
            branch: Some("main".into()),
            commit_sha: Some(scope.commit_sha.clone()),
            model_selector_digest: scope.model_selector_digest(),
            test_selector_digest: scope.test_selector_digest(),
            selector_digest: scope.selector_digest(),
            configured_step_ids: vec!["run".into(), "test".into()],
        }
    }

    fn validate(&self) -> Result<(), DbtCloudError> {
        validate_identifier("job account", &self.account_id)?;
        validate_identifier("job project", &self.project_id)?;
        validate_identifier("job environment", &self.environment_id)?;
        validate_identifier("job id", &self.job_id)?;
        self.repository.validate()?;
        if let Some(commit_sha) = &self.commit_sha {
            validate_commit_sha(commit_sha)?;
        }
        if self.branch.as_ref().is_some_and(|branch| {
            validate_bounded_text("job branch", branch, MAX_IDENTIFIER_BYTES).is_err()
        }) {
            return Err(DbtCloudError::InvalidInput("job branch"));
        }
        validate_step_ids(&self.configured_step_ids)?;
        if !self.model_selector_digest.is_valid()
            || !self.test_selector_digest.is_valid()
            || !self.selector_digest.is_valid()
        {
            return Err(DbtCloudError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunSnapshot {
    pub account_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub job_id: String,
    pub run_id: String,
    pub status: RunStatus,
    pub repository: RepositoryIdentity,
    pub commit_sha: String,
    pub selector_digest: Digest,
    pub step_ids: Vec<String>,
    pub invocation_id_digest: Option<Digest>,
    pub started_at_epoch_seconds: Option<u64>,
    pub finished_at_epoch_seconds: Option<u64>,
    pub expires_at_epoch_seconds: Option<u64>,
}

impl RunSnapshot {
    pub fn for_scope(
        scope: &DbtCloudScope,
        run_id: impl Into<String>,
        status: RunStatus,
        started_at_epoch_seconds: Option<u64>,
        finished_at_epoch_seconds: Option<u64>,
        expires_at_epoch_seconds: Option<u64>,
    ) -> Result<Self, DbtCloudError> {
        let snapshot = Self {
            account_id: scope.account_id.clone(),
            project_id: scope.dbt_project_id.clone(),
            environment_id: scope.environment_id.clone(),
            job_id: scope.job_id.clone(),
            run_id: run_id.into(),
            status,
            repository: scope.repository.clone(),
            commit_sha: scope.commit_sha.clone(),
            selector_digest: scope.selector_digest(),
            step_ids: vec!["run".into(), "test".into()],
            invocation_id_digest: Some(Digest::from_text("fixture-invocation")),
            started_at_epoch_seconds,
            finished_at_epoch_seconds,
            expires_at_epoch_seconds,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), DbtCloudError> {
        validate_identifier("run account", &self.account_id)?;
        validate_identifier("run project", &self.project_id)?;
        validate_identifier("run environment", &self.environment_id)?;
        validate_identifier("run job", &self.job_id)?;
        validate_identifier("run id", &self.run_id)?;
        self.repository.validate()?;
        validate_commit_sha(&self.commit_sha)?;
        if !self.selector_digest.is_valid() {
            return Err(DbtCloudError::InvalidDigest);
        }
        validate_step_ids(&self.step_ids)?;
        if self
            .finished_at_epoch_seconds
            .zip(self.started_at_epoch_seconds)
            .is_some_and(|(finished, started)| finished < started)
        {
            return Err(DbtCloudError::InvalidInput("run time ordering"));
        }
        if self
            .expires_at_epoch_seconds
            .zip(self.started_at_epoch_seconds)
            .is_some_and(|(expires, started)| expires <= started)
        {
            return Err(DbtCloudError::InvalidInput("run expiry"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelTestEvidence {
    pub unique_id: String,
    pub name: String,
    pub kind: EvidenceNodeKind,
    pub status: EvidenceNodeStatus,
    pub selector_digest: Digest,
    pub execution_time_millis: Option<u64>,
    pub failure_message_digest: Option<Digest>,
    pub step_id: Option<String>,
}

impl ModelTestEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        unique_id: impl Into<String>,
        name: impl Into<String>,
        kind: EvidenceNodeKind,
        status: EvidenceNodeStatus,
        selector_digest: Digest,
        execution_time_millis: Option<u64>,
        failure_message_digest: Option<Digest>,
        step_id: Option<String>,
    ) -> Result<Self, DbtCloudError> {
        let evidence = Self {
            unique_id: unique_id.into(),
            name: name.into(),
            kind,
            status,
            selector_digest,
            execution_time_millis,
            failure_message_digest,
            step_id,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<(), DbtCloudError> {
        validate_identifier("evidence unique id", &self.unique_id)?;
        validate_bounded_text("evidence name", &self.name, MAX_IDENTIFIER_BYTES)?;
        if !self.selector_digest.is_valid() {
            return Err(DbtCloudError::InvalidDigest);
        }
        if self
            .execution_time_millis
            .is_some_and(|time| time > 86_400_000)
        {
            return Err(DbtCloudError::InvalidInput("execution time"));
        }
        if self.step_id.as_ref().is_some_and(|step| {
            validate_bounded_text("evidence step", step, MAX_STEP_ID_BYTES).is_err()
        }) {
            return Err(DbtCloudError::InvalidInput("evidence step"));
        }
        if self
            .failure_message_digest
            .as_ref()
            .is_some_and(|digest| !digest.is_valid())
        {
            return Err(DbtCloudError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub sha256: Digest,
    pub content_type: String,
    pub generated_at_epoch_seconds: Option<u64>,
    pub expires_at_epoch_seconds: Option<u64>,
}

impl ArtifactMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        path: impl Into<String>,
        size_bytes: u64,
        sha256: Digest,
        content_type: impl Into<String>,
        generated_at_epoch_seconds: Option<u64>,
        expires_at_epoch_seconds: Option<u64>,
    ) -> Result<Self, DbtCloudError> {
        let metadata = Self {
            name: name.into(),
            path: path.into(),
            size_bytes,
            sha256,
            content_type: content_type.into(),
            generated_at_epoch_seconds,
            expires_at_epoch_seconds,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    fn validate(&self) -> Result<(), DbtCloudError> {
        validate_bounded_text("artifact name", &self.name, MAX_ARTIFACT_NAME_BYTES)?;
        validate_bounded_text("artifact path", &self.path, MAX_ARTIFACT_METADATA_BYTES)?;
        validate_bounded_text("artifact content type", &self.content_type, 128)?;
        if !self.sha256.is_valid() {
            return Err(DbtCloudError::InvalidDigest);
        }
        if self.size_bytes > MAX_ARTIFACT_METADATA_BYTES as u64 * 1024 {
            return Err(DbtCloudError::UnboundedArtifact);
        }
        if self
            .expires_at_epoch_seconds
            .zip(self.generated_at_epoch_seconds)
            .is_some_and(|(expires, generated)| expires <= generated)
        {
            return Err(DbtCloudError::InvalidInput("artifact expiry"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbtCloudPayload<T> {
    pub payload: T,
    pub response_digest: Digest,
    pub content_length_bytes: usize,
    pub truncated: bool,
}

impl<T: Serialize> DbtCloudPayload<T> {
    pub fn new(payload: T) -> Self {
        let content_length_bytes = serde_json::to_vec(&payload)
            .expect("typed dbt payload must serialize")
            .len();
        let response_digest = Digest::from_serializable(&payload);
        Self {
            payload,
            response_digest,
            content_length_bytes,
            truncated: false,
        }
    }

    #[must_use]
    pub fn with_transport_metadata(
        mut self,
        content_length_bytes: usize,
        truncated: bool,
        response_digest: Digest,
    ) -> Self {
        self.content_length_bytes = content_length_bytes;
        self.truncated = truncated;
        self.response_digest = response_digest;
        self
    }

    fn verify(&self, max_response_bytes: usize) -> Result<(), DbtCloudError> {
        if self.truncated {
            return Err(DbtCloudError::PayloadTruncated);
        }
        if self.content_length_bytes > max_response_bytes {
            return Err(DbtCloudError::ResponseTooLarge);
        }
        if self.response_digest != Digest::from_serializable(&self.payload) {
            return Err(DbtCloudError::PayloadTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbtCloudPage<T> {
    pub page_index: usize,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub items: Vec<T>,
    pub response_digest: Digest,
    pub content_length_bytes: usize,
    pub truncated: bool,
}

#[derive(Serialize)]
struct PageDigestInput<'a, T> {
    page_index: usize,
    cursor: &'a Option<String>,
    next_cursor: &'a Option<String>,
    items: &'a [T],
    content_length_bytes: usize,
    truncated: bool,
}

impl<T: Serialize> DbtCloudPage<T> {
    pub fn new(
        page_index: usize,
        cursor: Option<String>,
        next_cursor: Option<String>,
        items: Vec<T>,
    ) -> Self {
        let content_length_bytes = serde_json::to_vec(&items)
            .expect("typed dbt page must serialize")
            .len();
        let mut page = Self {
            page_index,
            cursor,
            next_cursor,
            items,
            response_digest: Digest::from_text("uncomputed"),
            content_length_bytes,
            truncated: false,
        };
        page.response_digest = page.compute_digest();
        page
    }

    #[must_use]
    pub fn with_transport_metadata(
        mut self,
        content_length_bytes: usize,
        truncated: bool,
        response_digest: Digest,
    ) -> Self {
        self.content_length_bytes = content_length_bytes;
        self.truncated = truncated;
        self.response_digest = response_digest;
        self
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&PageDigestInput {
            page_index: self.page_index,
            cursor: &self.cursor,
            next_cursor: &self.next_cursor,
            items: &self.items,
            content_length_bytes: self.content_length_bytes,
            truncated: self.truncated,
        })
    }

    fn verify(
        &self,
        expected_page: usize,
        expected_cursor: Option<&String>,
        limits: &ReadLimits,
    ) -> Result<(), DbtCloudError> {
        if self.truncated {
            return Err(DbtCloudError::PayloadTruncated);
        }
        if self.content_length_bytes > limits.max_response_bytes {
            return Err(DbtCloudError::ResponseTooLarge);
        }
        if self.items.len() > limits.max_page_items {
            return Err(DbtCloudError::PageTooLarge);
        }
        if self.page_index != expected_page || self.cursor.as_ref() != expected_cursor {
            return Err(DbtCloudError::PaginationDrift);
        }
        if self.next_cursor.as_ref().is_some_and(String::is_empty) {
            return Err(DbtCloudError::PaginationDrift);
        }
        if self.response_digest != self.compute_digest() {
            return Err(DbtCloudError::PayloadTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ReadLimits {
    pub max_response_bytes: usize,
    pub max_page_items: usize,
    pub max_pages: usize,
    pub max_total_items: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_page_items: MAX_PAGE_ITEMS,
            max_pages: MAX_PAGE_COUNT,
            max_total_items: MAX_EVIDENCE_ITEMS,
        }
    }
}

impl ReadLimits {
    fn validate(self) -> Result<Self, DbtCloudError> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_page_items == 0
            || self.max_page_items > MAX_PAGE_ITEMS
            || self.max_pages == 0
            || self.max_pages > MAX_PAGE_COUNT
            || self.max_total_items == 0
            || self.max_total_items > MAX_EVIDENCE_ITEMS
        {
            return Err(DbtCloudError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbtCloudReadRequest {
    pub operation: DbtCloudOperation,
    pub api_version: DbtCloudApiVersion,
    pub api_host: String,
    pub account_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub job_id: String,
    pub repository_digest: Digest,
    pub commit_digest: Digest,
    pub scope_digest: Digest,
    pub run_id: Option<String>,
    pub cursor: Option<String>,
}

impl DbtCloudReadRequest {
    fn for_scope(
        scope: &DbtCloudScope,
        operation: DbtCloudOperation,
        run_id: Option<String>,
        cursor: Option<String>,
    ) -> Self {
        Self {
            operation,
            api_version: scope.api_version,
            api_host: scope.api_host.clone(),
            account_id: scope.account_id.clone(),
            project_id: scope.dbt_project_id.clone(),
            environment_id: scope.environment_id.clone(),
            job_id: scope.job_id.clone(),
            repository_digest: scope.repository_digest(),
            commit_digest: scope.commit_digest(),
            scope_digest: scope.scope_digest(),
            run_id,
            cursor,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DbtCloudRequestAudit {
    pub operation: DbtCloudOperation,
    pub scope_digest: Digest,
    pub run_id: Option<String>,
    pub cursor: Option<String>,
    pub secret_reference_digest: Digest,
    pub connected: bool,
    pub native: bool,
}

impl DbtCloudRequestAudit {
    fn from_request(request: &DbtCloudReadRequest, secret: &SecretReference) -> Self {
        Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            run_id: request.run_id.clone(),
            cursor: request.cursor.clone(),
            secret_reference_digest: secret.reference_digest(),
            connected: false,
            native: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DbtCloudTransportError {
    #[error("dbt Cloud returned HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("dbt Cloud read timed out")]
    Timeout,
    #[error("dbt Cloud environment is blocked")]
    BlockedEnv,
    #[error("dbt Cloud recording has no response for the requested operation")]
    RecordingExhausted,
    #[error("dbt Cloud recording response has the wrong operation type")]
    UnexpectedResponse,
}

pub trait DbtCloudTransport {
    fn kind(&self) -> TransportKind;

    fn describe_job(
        &mut self,
        request: &DbtCloudReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DbtCloudPayload<JobConfiguration>, DbtCloudTransportError>;

    fn read_run_status(
        &mut self,
        request: &DbtCloudReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DbtCloudPayload<RunSnapshot>, DbtCloudTransportError>;

    fn read_run_results(
        &mut self,
        request: &DbtCloudReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DbtCloudPage<ModelTestEvidence>, DbtCloudTransportError>;

    fn read_artifact_metadata(
        &mut self,
        request: &DbtCloudReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DbtCloudPage<ArtifactMetadata>, DbtCloudTransportError>;
}

#[derive(Clone, Debug)]
enum RecordedResponse {
    Job(Result<DbtCloudPayload<JobConfiguration>, DbtCloudTransportError>),
    Run(Result<DbtCloudPayload<RunSnapshot>, DbtCloudTransportError>),
    Results(Result<DbtCloudPage<ModelTestEvidence>, DbtCloudTransportError>),
    Artifacts(Result<DbtCloudPage<ArtifactMetadata>, DbtCloudTransportError>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordedResponseKind {
    Job,
    Run,
    Results,
    Artifacts,
}

impl RecordedResponse {
    fn kind(&self) -> RecordedResponseKind {
        match self {
            Self::Job(_) => RecordedResponseKind::Job,
            Self::Run(_) => RecordedResponseKind::Run,
            Self::Results(_) => RecordedResponseKind::Results,
            Self::Artifacts(_) => RecordedResponseKind::Artifacts,
        }
    }
}

/// Deterministic fixture/fake/recording/loopback transport. It records only
/// typed request audits and returns bounded typed payloads.
#[derive(Clone, Debug)]
pub struct RecordingDbtCloudTransport {
    kind: TransportKind,
    responses: VecDeque<RecordedResponse>,
    requests: Vec<DbtCloudRequestAudit>,
    forced_error: Option<DbtCloudTransportError>,
}

impl RecordingDbtCloudTransport {
    pub fn new(kind: TransportKind) -> Result<Self, DbtCloudError> {
        if kind == TransportKind::BlockedEnv {
            return Ok(Self::blocked_env());
        }
        Ok(Self {
            kind,
            responses: VecDeque::new(),
            requests: Vec::new(),
            forced_error: None,
        })
    }

    pub fn fixture() -> Self {
        Self::new(TransportKind::Fixture).expect("fixture kind is valid")
    }

    pub fn fake() -> Self {
        Self::new(TransportKind::Fake).expect("fake kind is valid")
    }

    pub fn loopback() -> Self {
        Self::new(TransportKind::Loopback).expect("loopback kind is valid")
    }

    pub fn blocked_env() -> Self {
        Self {
            kind: TransportKind::BlockedEnv,
            responses: VecDeque::new(),
            requests: Vec::new(),
            forced_error: Some(DbtCloudTransportError::BlockedEnv),
        }
    }

    pub fn fail_with(&mut self, error: DbtCloudTransportError) {
        self.forced_error = Some(error);
    }

    pub fn push_job_response(
        &mut self,
        response: Result<DbtCloudPayload<JobConfiguration>, DbtCloudTransportError>,
    ) {
        self.responses.push_back(RecordedResponse::Job(response));
    }

    pub fn push_run_response(
        &mut self,
        response: Result<DbtCloudPayload<RunSnapshot>, DbtCloudTransportError>,
    ) {
        self.responses.push_back(RecordedResponse::Run(response));
    }

    pub fn push_results_response(
        &mut self,
        response: Result<DbtCloudPage<ModelTestEvidence>, DbtCloudTransportError>,
    ) {
        self.responses
            .push_back(RecordedResponse::Results(response));
    }

    pub fn push_artifacts_response(
        &mut self,
        response: Result<DbtCloudPage<ArtifactMetadata>, DbtCloudTransportError>,
    ) {
        self.responses
            .push_back(RecordedResponse::Artifacts(response));
    }

    pub fn requests(&self) -> &[DbtCloudRequestAudit] {
        &self.requests
    }

    fn take(
        &mut self,
        expected: RecordedResponseKind,
        request: &DbtCloudReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<RecordedResponse, DbtCloudTransportError> {
        self.requests.push(DbtCloudRequestAudit::from_request(
            request,
            secret_reference,
        ));
        if let Some(error) = &self.forced_error {
            return Err(*error);
        }
        let response = self
            .responses
            .pop_front()
            .ok_or(DbtCloudTransportError::RecordingExhausted)?;
        if response.kind() == expected {
            Ok(response)
        } else {
            Err(DbtCloudTransportError::UnexpectedResponse)
        }
    }
}

impl DbtCloudTransport for RecordingDbtCloudTransport {
    fn kind(&self) -> TransportKind {
        self.kind
    }

    fn describe_job(
        &mut self,
        request: &DbtCloudReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DbtCloudPayload<JobConfiguration>, DbtCloudTransportError> {
        match self.take(RecordedResponseKind::Job, request, secret_reference)? {
            RecordedResponse::Job(response) => response,
            _ => Err(DbtCloudTransportError::UnexpectedResponse),
        }
    }

    fn read_run_status(
        &mut self,
        request: &DbtCloudReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DbtCloudPayload<RunSnapshot>, DbtCloudTransportError> {
        match self.take(RecordedResponseKind::Run, request, secret_reference)? {
            RecordedResponse::Run(response) => response,
            _ => Err(DbtCloudTransportError::UnexpectedResponse),
        }
    }

    fn read_run_results(
        &mut self,
        request: &DbtCloudReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DbtCloudPage<ModelTestEvidence>, DbtCloudTransportError> {
        match self.take(RecordedResponseKind::Results, request, secret_reference)? {
            RecordedResponse::Results(response) => response,
            _ => Err(DbtCloudTransportError::UnexpectedResponse),
        }
    }

    fn read_artifact_metadata(
        &mut self,
        request: &DbtCloudReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DbtCloudPage<ArtifactMetadata>, DbtCloudTransportError> {
        match self.take(RecordedResponseKind::Artifacts, request, secret_reference)? {
            RecordedResponse::Artifacts(response) => response,
            _ => Err(DbtCloudTransportError::UnexpectedResponse),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PagedEvidence<T> {
    pub items: Vec<T>,
    pub pages_read: usize,
    pub total_items: usize,
}

#[derive(Clone, Debug)]
pub struct DbtCloudProvider<T> {
    transport: T,
    limits: ReadLimits,
}

impl<T: DbtCloudTransport> DbtCloudProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            limits: ReadLimits::default(),
        }
    }

    pub fn with_limits(transport: T, limits: ReadLimits) -> Result<Self, DbtCloudError> {
        Ok(Self {
            transport,
            limits: limits.validate()?,
        })
    }

    pub fn transport_kind(&self) -> TransportKind {
        self.transport.kind()
    }

    pub fn limits(&self) -> ReadLimits {
        self.limits
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_job(
        &mut self,
        scope: &DbtCloudScope,
        secret_reference: &SecretReference,
    ) -> Result<JobConfiguration, DbtCloudError> {
        Self::validate_secret(scope, secret_reference)?;
        let request =
            DbtCloudReadRequest::for_scope(scope, DbtCloudOperation::DescribeJob, None, None);
        let response = self
            .transport
            .describe_job(&request, secret_reference)
            .map_err(DbtCloudError::from_transport)?;
        response.verify(self.limits.max_response_bytes)?;
        response.payload.validate()?;
        Ok(response.payload)
    }

    pub fn read_run_status(
        &mut self,
        scope: &DbtCloudScope,
        run_id: &str,
        secret_reference: &SecretReference,
    ) -> Result<RunSnapshot, DbtCloudError> {
        Self::validate_secret(scope, secret_reference)?;
        validate_identifier("run id", run_id)?;
        let request = DbtCloudReadRequest::for_scope(
            scope,
            DbtCloudOperation::ReadRunEvidence,
            Some(run_id.into()),
            None,
        );
        let response = self
            .transport
            .read_run_status(&request, secret_reference)
            .map_err(DbtCloudError::from_transport)?;
        response.verify(self.limits.max_response_bytes)?;
        response.payload.validate()?;
        Ok(response.payload)
    }

    pub fn read_run_results(
        &mut self,
        scope: &DbtCloudScope,
        run_id: &str,
        secret_reference: &SecretReference,
    ) -> Result<PagedEvidence<ModelTestEvidence>, DbtCloudError> {
        Self::validate_secret(scope, secret_reference)?;
        self.read_pages(
            scope,
            run_id,
            DbtCloudOperation::ReadRunResults,
            secret_reference,
            DbtCloudTransport::read_run_results,
            |page: &DbtCloudPage<ModelTestEvidence>| {
                for item in &page.items {
                    item.validate()?;
                }
                Ok(())
            },
        )
    }

    pub fn read_artifact_metadata(
        &mut self,
        scope: &DbtCloudScope,
        run_id: &str,
        secret_reference: &SecretReference,
    ) -> Result<PagedEvidence<ArtifactMetadata>, DbtCloudError> {
        Self::validate_secret(scope, secret_reference)?;
        self.read_pages(
            scope,
            run_id,
            DbtCloudOperation::ReadRunEvidence,
            secret_reference,
            DbtCloudTransport::read_artifact_metadata,
            |page: &DbtCloudPage<ArtifactMetadata>| {
                for item in &page.items {
                    item.validate()?;
                    if !scope.artifact_allowlist.contains(&item.name) {
                        return Err(DbtCloudError::ArtifactNotAllowlisted);
                    }
                }
                Ok(())
            },
        )
    }

    fn read_pages<U, F, FFetch>(
        &mut self,
        scope: &DbtCloudScope,
        run_id: &str,
        operation: DbtCloudOperation,
        secret_reference: &SecretReference,
        mut fetch: FFetch,
        mut validate_item: F,
    ) -> Result<PagedEvidence<U>, DbtCloudError>
    where
        U: Clone + Serialize,
        FFetch: FnMut(
            &mut T,
            &DbtCloudReadRequest,
            &SecretReference,
        ) -> Result<DbtCloudPage<U>, DbtCloudTransportError>,
        F: FnMut(&DbtCloudPage<U>) -> Result<(), DbtCloudError>,
    {
        validate_identifier("run id", run_id)?;
        let mut page_index = 0;
        let mut cursor: Option<String> = None;
        let mut seen_cursors = BTreeSet::new();
        let mut items = Vec::new();
        loop {
            if page_index >= self.limits.max_pages {
                return Err(DbtCloudError::PaginationLimit);
            }
            if !seen_cursors.insert(cursor.clone()) {
                return Err(DbtCloudError::PaginationRepeatedCursor);
            }
            let request = DbtCloudReadRequest::for_scope(
                scope,
                operation,
                Some(run_id.into()),
                cursor.clone(),
            );
            let response = fetch(&mut self.transport, &request, secret_reference)
                .map_err(DbtCloudError::from_transport)?;
            response.verify(page_index, cursor.as_ref(), &self.limits)?;
            validate_item(&response)?;
            if items.len().saturating_add(response.items.len()) > self.limits.max_total_items {
                return Err(DbtCloudError::EvidenceTooLarge);
            }
            items.extend(response.items.iter().cloned());
            let next_cursor = response.next_cursor.clone();
            page_index += 1;
            match next_cursor {
                Some(next) => {
                    if seen_cursors.contains(&Some(next.clone())) {
                        return Err(DbtCloudError::PaginationRepeatedCursor);
                    }
                    cursor = Some(next);
                }
                None => {
                    return Ok(PagedEvidence {
                        total_items: items.len(),
                        items,
                        pages_read: page_index,
                    });
                }
            }
        }
    }

    fn validate_secret(
        scope: &DbtCloudScope,
        secret_reference: &SecretReference,
    ) -> Result<(), DbtCloudError> {
        if !secret_reference.is_bound_to(scope) {
            return if secret_reference.is_revoked() {
                Err(DbtCloudError::SecretRevoked)
            } else {
                Err(DbtCloudError::SecretScopeMismatch)
            };
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestSummary {
    pub model_count: usize,
    pub test_count: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub error_count: usize,
    pub skipped_count: usize,
    pub warn_count: usize,
    pub unknown_count: usize,
    pub summary_digest: Digest,
}

impl TestSummary {
    fn from_items(items: &[ModelTestEvidence]) -> Self {
        let mut summary = Self {
            model_count: 0,
            test_count: 0,
            pass_count: 0,
            fail_count: 0,
            error_count: 0,
            skipped_count: 0,
            warn_count: 0,
            unknown_count: 0,
            summary_digest: Digest::from_text("uncomputed"),
        };
        for item in items {
            match item.kind {
                EvidenceNodeKind::Model => summary.model_count += 1,
                EvidenceNodeKind::Test => summary.test_count += 1,
            }
            match item.status {
                EvidenceNodeStatus::Pass => summary.pass_count += 1,
                EvidenceNodeStatus::Fail => summary.fail_count += 1,
                EvidenceNodeStatus::Error => summary.error_count += 1,
                EvidenceNodeStatus::Skipped => summary.skipped_count += 1,
                EvidenceNodeStatus::Warn => summary.warn_count += 1,
                EvidenceNodeStatus::NoResult | EvidenceNodeStatus::Unknown => {
                    summary.unknown_count += 1;
                }
            }
        }
        summary.summary_digest = Digest::from_serializable(&(
            summary.model_count,
            summary.test_count,
            summary.pass_count,
            summary.fail_count,
            summary.error_count,
            summary.skipped_count,
            summary.warn_count,
            summary.unknown_count,
        ));
        summary
    }

    fn has_incomplete_tests(&self) -> bool {
        self.fail_count > 0
            || self.error_count > 0
            || self.skipped_count > 0
            || self.unknown_count > 0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceOrigin {
    Fixture,
    Recording,
    Fake,
    Loopback,
    BlockedEnv,
}

impl From<TransportKind> for EvidenceOrigin {
    fn from(kind: TransportKind) -> Self {
        match kind {
            TransportKind::Fixture => Self::Fixture,
            TransportKind::Recording => Self::Recording,
            TransportKind::Fake => Self::Fake,
            TransportKind::Loopback => Self::Loopback,
            TransportKind::BlockedEnv => Self::BlockedEnv,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub origin: EvidenceOrigin,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
}

impl EvidenceProvenance {
    fn layer1(kind: TransportKind) -> Self {
        Self {
            origin: kind.into(),
            recording_only: true,
            connected: false,
            native: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunEvidence {
    pub schema_version: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub run: RunSnapshot,
    pub status: RunStatus,
    pub model_test_evidence: Vec<ModelTestEvidence>,
    pub test_summary: TestSummary,
    pub artifact_metadata: Vec<ArtifactMetadata>,
    pub results_pages_read: usize,
    pub artifact_pages_read: usize,
    pub observed_at_epoch_seconds: u64,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct RunEvidenceDigestInput<'a> {
    schema_version: &'a str,
    registration_digest: &'a Digest,
    scope_digest: &'a Digest,
    run: &'a RunSnapshot,
    status: RunStatus,
    model_test_evidence: &'a [ModelTestEvidence],
    test_summary: &'a TestSummary,
    artifact_metadata: &'a [ArtifactMetadata],
    results_pages_read: usize,
    artifact_pages_read: usize,
    observed_at_epoch_seconds: u64,
    provenance: &'a EvidenceProvenance,
}

impl RunEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &DbtCloudRegistration,
        scope: &DbtCloudScope,
        run: RunSnapshot,
        model_test_evidence: Vec<ModelTestEvidence>,
        artifact_metadata: Vec<ArtifactMetadata>,
        results_pages_read: usize,
        artifact_pages_read: usize,
        observed_at_epoch_seconds: u64,
        transport_kind: TransportKind,
    ) -> Result<Self, DbtCloudError> {
        if model_test_evidence.len() > MAX_EVIDENCE_ITEMS {
            return Err(DbtCloudError::EvidenceTooLarge);
        }
        if artifact_metadata.len() > MAX_ARTIFACT_COUNT {
            return Err(DbtCloudError::EvidenceTooLarge);
        }
        let test_summary = TestSummary::from_items(&model_test_evidence);
        let mut status = run.status;
        if run
            .expires_at_epoch_seconds
            .is_some_and(|expires| expires <= observed_at_epoch_seconds)
            || artifact_metadata.iter().any(|artifact| {
                artifact
                    .expires_at_epoch_seconds
                    .is_some_and(|expires| expires <= observed_at_epoch_seconds)
            })
        {
            status = RunStatus::Expired;
        } else if status == RunStatus::Success && test_summary.has_incomplete_tests() {
            status = RunStatus::Partial;
        }
        let provenance = EvidenceProvenance::layer1(transport_kind);
        let mut evidence = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: scope.scope_digest(),
            run,
            status,
            model_test_evidence,
            test_summary,
            artifact_metadata,
            results_pages_read,
            artifact_pages_read,
            observed_at_epoch_seconds,
            provenance,
            evidence_digest: Digest::from_text("uncomputed"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        Ok(evidence)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&RunEvidenceDigestInput {
            schema_version: &self.schema_version,
            registration_digest: &self.registration_digest,
            scope_digest: &self.scope_digest,
            run: &self.run,
            status: self.status,
            model_test_evidence: &self.model_test_evidence,
            test_summary: &self.test_summary,
            artifact_metadata: &self.artifact_metadata,
            results_pages_read: self.results_pages_read,
            artifact_pages_read: self.artifact_pages_read,
            observed_at_epoch_seconds: self.observed_at_epoch_seconds,
            provenance: &self.provenance,
        })
    }

    pub fn validate(
        &self,
        scope: &DbtCloudScope,
        registration: &DbtCloudRegistration,
    ) -> Result<(), DbtCloudError> {
        self.run.validate()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != registration.registration_digest
            || self.evidence_digest != self.compute_digest()
            || !self.provenance.recording_only
            || self.provenance.connected
            || self.provenance.native
        {
            return Err(DbtCloudError::EvidenceTampered);
        }
        if self.model_test_evidence.len() > MAX_EVIDENCE_ITEMS
            || self.artifact_metadata.len() > MAX_ARTIFACT_COUNT
        {
            return Err(DbtCloudError::EvidenceTooLarge);
        }
        if self.test_summary != TestSummary::from_items(&self.model_test_evidence) {
            return Err(DbtCloudError::EvidenceTampered);
        }
        for item in &self.model_test_evidence {
            item.validate()?;
            if item.selector_digest != scope.selector_digest() {
                return Err(DbtCloudError::SelectionDrift);
            }
        }
        for artifact in &self.artifact_metadata {
            artifact.validate()?;
            if !scope.artifact_allowlist.contains(&artifact.name) {
                return Err(DbtCloudError::ArtifactNotAllowlisted);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionDisposition {
    Layer2Required,
    BlockedByProjection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransformationResultProposal {
    pub schema_version: String,
    pub service_id: String,
    pub registration_digest: Digest,
    pub scope: DbtCloudScope,
    pub run_id: String,
    pub status: RunStatus,
    pub evidence_digest: Digest,
    pub test_summary: TestSummary,
    pub model_test_evidence: Vec<ModelTestEvidence>,
    pub artifact_metadata: Vec<ArtifactMetadata>,
    pub provenance: EvidenceProvenance,
    pub connected: bool,
    pub native: bool,
    pub adoption: AdoptionDisposition,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
struct ProposalDigestInput<'a> {
    schema_version: &'a str,
    service_id: &'a str,
    registration_digest: &'a Digest,
    scope: &'a DbtCloudScope,
    run_id: &'a str,
    status: RunStatus,
    evidence_digest: &'a Digest,
    test_summary: &'a TestSummary,
    model_test_evidence: &'a [ModelTestEvidence],
    artifact_metadata: &'a [ArtifactMetadata],
    provenance: &'a EvidenceProvenance,
    connected: bool,
    native: bool,
    adoption: AdoptionDisposition,
}

impl TransformationResultProposal {
    fn from_evidence(
        evidence: &RunEvidence,
        scope: &DbtCloudScope,
        registration: &DbtCloudRegistration,
    ) -> Self {
        let adoption = if evidence.status == RunStatus::Success {
            AdoptionDisposition::Layer2Required
        } else {
            AdoptionDisposition::BlockedByProjection
        };
        let mut proposal = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            service_id: SERVICE_ID.into(),
            registration_digest: registration.registration_digest.clone(),
            scope: scope.clone(),
            run_id: evidence.run.run_id.clone(),
            status: evidence.status,
            evidence_digest: evidence.evidence_digest.clone(),
            test_summary: evidence.test_summary.clone(),
            model_test_evidence: evidence.model_test_evidence.clone(),
            artifact_metadata: evidence.artifact_metadata.clone(),
            provenance: evidence.provenance.clone(),
            connected: false,
            native: false,
            adoption,
            proposal_digest: Digest::from_text("uncomputed"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&ProposalDigestInput {
            schema_version: &self.schema_version,
            service_id: &self.service_id,
            registration_digest: &self.registration_digest,
            scope: &self.scope,
            run_id: &self.run_id,
            status: self.status,
            evidence_digest: &self.evidence_digest,
            test_summary: &self.test_summary,
            model_test_evidence: &self.model_test_evidence,
            artifact_metadata: &self.artifact_metadata,
            provenance: &self.provenance,
            connected: self.connected,
            native: self.native,
            adoption: self.adoption,
        })
    }

    pub fn validate(&self) -> Result<(), DbtCloudError> {
        self.scope.validate()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.service_id != SERVICE_ID
            || self.proposal_digest != self.compute_digest()
            || self.connected
            || self.native
            || !self.provenance.recording_only
            || self.provenance.connected
            || self.provenance.native
        {
            return Err(DbtCloudError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordingDisposition {
    Fresh,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunRecording {
    pub schema_version: String,
    pub recording_id: Digest,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub run_id: String,
    pub evidence_digest: Digest,
    pub disposition: RecordingDisposition,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
}

impl RunRecording {
    fn new(evidence: &RunEvidence, registration: &DbtCloudRegistration) -> Self {
        let recording_id = Digest::from_serializable(&(
            &registration.registration_digest,
            &evidence.scope_digest,
            &evidence.run.run_id,
            &evidence.evidence_digest,
        ));
        Self {
            schema_version: CONTRACT_SCHEMA.into(),
            recording_id,
            registration_digest: registration.registration_digest.clone(),
            scope_digest: evidence.scope_digest.clone(),
            run_id: evidence.run.run_id.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            disposition: RecordingDisposition::Fresh,
            durable: false,
            connected: false,
            native: false,
        }
    }

    fn replayed(mut self) -> Self {
        self.disposition = RecordingDisposition::Replay;
        self
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConsumptionDisposition {
    Fresh,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionDbtResult {
    pub scope_digest: Digest,
    pub mission_id: String,
    pub work_product_id: String,
    pub run_id: String,
    pub proposal_digest: Digest,
    pub disposition: MissionConsumptionDisposition,
    pub adopted: bool,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug)]
pub struct MissionDbtResultConsumer {
    binding: MissionScopeBinding,
    scope_digest: Digest,
    consumed: BTreeMap<String, Digest>,
    active: bool,
}

impl MissionDbtResultConsumer {
    pub fn new(scope: &DbtCloudScope) -> Result<Self, DbtCloudError> {
        scope.validate()?;
        Ok(Self {
            binding: scope.mission.clone(),
            scope_digest: scope.scope_digest(),
            consumed: BTreeMap::new(),
            active: true,
        })
    }

    pub fn binding(&self) -> &MissionScopeBinding {
        &self.binding
    }

    pub fn unmount(&mut self) {
        self.active = false;
    }

    pub fn remount(&mut self) {
        self.active = true;
    }

    pub fn revoke(&mut self) {
        self.active = false;
    }

    pub fn consume(
        &mut self,
        proposal: &TransformationResultProposal,
    ) -> Result<MissionDbtResult, DbtCloudError> {
        if !self.active {
            return Err(DbtCloudError::ConsumerInactive);
        }
        proposal.validate()?;
        if proposal.scope.scope_digest() != self.scope_digest
            || proposal.scope.mission != self.binding
        {
            return Err(DbtCloudError::MissionScopeMismatch);
        }
        let disposition = match self.consumed.get(&proposal.run_id) {
            None => {
                self.consumed
                    .insert(proposal.run_id.clone(), proposal.proposal_digest.clone());
                MissionConsumptionDisposition::Fresh
            }
            Some(existing) if existing == &proposal.proposal_digest => {
                MissionConsumptionDisposition::Replay
            }
            Some(_) => return Err(DbtCloudError::DuplicateRun),
        };
        Ok(MissionDbtResult {
            scope_digest: self.scope_digest.clone(),
            mission_id: self.binding.mission_id.clone(),
            work_product_id: self.binding.work_product_id.clone(),
            run_id: proposal.run_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            disposition,
            adopted: false,
            connected: false,
            native: false,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationProjection {
    pub schema_version: String,
    pub run_id: String,
    pub status: RunStatus,
    pub evidence_digest: Digest,
    pub bounded_evidence_verified: bool,
    pub adoption: AdoptionDisposition,
    pub connected: bool,
    pub native: bool,
}

#[derive(Clone, Debug)]
pub struct DbtCloudResultService<T> {
    provider: DbtCloudProvider<T>,
    scope: DbtCloudScope,
    secret_reference: SecretReference,
    registration: DbtCloudRegistration,
    recordings: BTreeMap<String, Digest>,
}

impl<T: DbtCloudTransport> DbtCloudResultService<T> {
    pub fn new(
        provider: DbtCloudProvider<T>,
        scope: DbtCloudScope,
        secret_reference: SecretReference,
    ) -> Result<Self, DbtCloudError> {
        scope.validate()?;
        let registration = DbtCloudRegistration::new(&scope, &secret_reference)?;
        Ok(Self {
            provider,
            scope,
            secret_reference,
            registration,
            recordings: BTreeMap::new(),
        })
    }

    pub fn definition() -> DbtCloudServiceDefinition {
        DbtCloudServiceDefinition::layer1()
    }

    pub fn scope(&self) -> &DbtCloudScope {
        &self.scope
    }

    pub fn registration(&self) -> &DbtCloudRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &DbtCloudProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut DbtCloudProvider<T> {
        &mut self.provider
    }

    pub fn describe_job(&mut self) -> Result<JobConfiguration, DbtCloudError> {
        self.ensure_active()?;
        let job = self
            .provider
            .describe_job(&self.scope, &self.secret_reference)?;
        self.validate_job_binding(&job)?;
        Ok(job)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn read_run_evidence(
        &mut self,
        request: RunReadRequest,
    ) -> Result<RunEvidence, DbtCloudError> {
        self.ensure_active()?;
        request.validate()?;
        if request.job_id != self.scope.job_id {
            return Err(DbtCloudError::JobMismatch);
        }
        let run =
            self.provider
                .read_run_status(&self.scope, &request.run_id, &self.secret_reference)?;
        self.validate_run_binding(&run, &request)?;
        let (results, artifacts) = if matches!(
            run.status,
            RunStatus::Expired | RunStatus::AccessLoss | RunStatus::ProviderUnknown
        ) {
            (
                PagedEvidence {
                    items: Vec::new(),
                    pages_read: 0,
                    total_items: 0,
                },
                PagedEvidence {
                    items: Vec::new(),
                    pages_read: 0,
                    total_items: 0,
                },
            )
        } else {
            let results = self.provider.read_run_results(
                &self.scope,
                &request.run_id,
                &self.secret_reference,
            )?;
            let artifacts = self.provider.read_artifact_metadata(
                &self.scope,
                &request.run_id,
                &self.secret_reference,
            )?;
            (results, artifacts)
        };
        RunEvidence::new(
            &self.registration,
            &self.scope,
            run,
            results.items,
            artifacts.items,
            results.pages_read,
            artifacts.pages_read,
            request.observed_at_epoch_seconds,
            self.provider.transport_kind(),
        )
    }

    pub fn compile_transformation_proposal(
        &self,
        evidence: &RunEvidence,
    ) -> Result<TransformationResultProposal, DbtCloudError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        Ok(TransformationResultProposal::from_evidence(
            evidence,
            &self.scope,
            &self.registration,
        ))
    }

    pub fn record_run_receipt(
        &mut self,
        evidence: &RunEvidence,
    ) -> Result<RunRecording, DbtCloudError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        let run_id = evidence.run.run_id.clone();
        if let Some(existing) = self.recordings.get(&run_id) {
            if existing != &evidence.evidence_digest {
                return Err(DbtCloudError::DuplicateRun);
            }
            return Ok(RunRecording::new(evidence, &self.registration).replayed());
        }
        self.recordings
            .insert(run_id, evidence.evidence_digest.clone());
        Ok(RunRecording::new(evidence, &self.registration))
    }

    pub fn verify_data_product_result(
        &self,
        evidence: &RunEvidence,
    ) -> Result<VerificationProjection, DbtCloudError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        Ok(VerificationProjection {
            schema_version: CONTRACT_SCHEMA.into(),
            run_id: evidence.run.run_id.clone(),
            status: evidence.status,
            evidence_digest: evidence.evidence_digest.clone(),
            bounded_evidence_verified: evidence.status == RunStatus::Success,
            adoption: if evidence.status == RunStatus::Success {
                AdoptionDisposition::Layer2Required
            } else {
                AdoptionDisposition::BlockedByProjection
            },
            connected: false,
            native: false,
        })
    }

    pub fn projection_for_error(&self, error: &DbtCloudError) -> RunStatus {
        error.projection()
    }

    pub fn unmount(&mut self) -> Result<(), DbtCloudError> {
        self.registration.unmount()
    }

    pub fn remount(&mut self) -> Result<(), DbtCloudError> {
        self.registration
            .remount(&self.scope, &self.secret_reference)
    }

    pub fn revoke(&mut self) -> RevocationReceipt {
        self.registration.revoke(&mut self.secret_reference)
    }

    fn ensure_active(&self) -> Result<(), DbtCloudError> {
        if self.secret_reference.is_revoked()
            || self.registration.status == RegistrationStatus::Revoked
        {
            return Err(DbtCloudError::RegistrationRevoked);
        }
        if !self.registration.is_active() {
            return Err(DbtCloudError::RegistrationInactive);
        }
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)
    }

    fn validate_evidence(&self, evidence: &RunEvidence) -> Result<(), DbtCloudError> {
        self.ensure_active()?;
        evidence.validate(&self.scope, &self.registration)?;
        self.validate_run_binding(
            &evidence.run,
            &RunReadRequest {
                job_id: self.scope.job_id.clone(),
                run_id: evidence.run.run_id.clone(),
                observed_at_epoch_seconds: evidence.observed_at_epoch_seconds,
            },
        )?;
        Ok(())
    }

    fn validate_job_binding(&self, job: &JobConfiguration) -> Result<(), DbtCloudError> {
        if job.account_id != self.scope.account_id
            || job.project_id != self.scope.dbt_project_id
            || job.environment_id != self.scope.environment_id
            || job.job_id != self.scope.job_id
        {
            return Err(DbtCloudError::JobMismatch);
        }
        if job.repository != self.scope.repository {
            return Err(DbtCloudError::RepositoryMismatch);
        }
        if job.commit_sha.as_deref() != Some(self.scope.commit_sha.as_str()) {
            return Err(DbtCloudError::CommitMismatch);
        }
        if job.model_selector_digest != self.scope.model_selector_digest()
            || job.test_selector_digest != self.scope.test_selector_digest()
            || job.selector_digest != self.scope.selector_digest()
        {
            return Err(DbtCloudError::SelectionDrift);
        }
        Ok(())
    }

    fn validate_run_binding(
        &self,
        run: &RunSnapshot,
        request: &RunReadRequest,
    ) -> Result<(), DbtCloudError> {
        if run.run_id != request.run_id {
            return Err(DbtCloudError::RunMismatch);
        }
        if run.account_id != self.scope.account_id
            || run.project_id != self.scope.dbt_project_id
            || run.environment_id != self.scope.environment_id
            || run.job_id != self.scope.job_id
        {
            return Err(DbtCloudError::JobMismatch);
        }
        if run.repository != self.scope.repository {
            return Err(DbtCloudError::RepositoryMismatch);
        }
        if run.commit_sha != self.scope.commit_sha {
            return Err(DbtCloudError::CommitMismatch);
        }
        if run.selector_digest != self.scope.selector_digest() {
            return Err(DbtCloudError::SelectionDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunReadRequest {
    pub job_id: String,
    pub run_id: String,
    pub observed_at_epoch_seconds: u64,
}

impl RunReadRequest {
    pub fn new(
        job_id: impl Into<String>,
        run_id: impl Into<String>,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self, DbtCloudError> {
        let request = Self {
            job_id: job_id.into(),
            run_id: run_id.into(),
            observed_at_epoch_seconds,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), DbtCloudError> {
        validate_identifier("request job", &self.job_id)?;
        validate_identifier("request run", &self.run_id)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DbtCloudError {
    #[error("invalid Layer-1 dbt Cloud input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid SecretReference")]
    InvalidSecretReference,
    #[error("SecretReference is revoked")]
    SecretRevoked,
    #[error("SecretReference is bound to a different exact scope")]
    SecretScopeMismatch,
    #[error("registration binding drifted")]
    RegistrationBindingDrift,
    #[error("registration digest was tampered")]
    RegistrationTampered,
    #[error("registration is inactive")]
    RegistrationInactive,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("permission digest or read-only permission set drifted")]
    PermissionDrift,
    #[error("job identity does not match exact account/project/environment/job scope")]
    JobMismatch,
    #[error("run identity does not match the requested run")]
    RunMismatch,
    #[error("repository identity does not match the exact binding")]
    RepositoryMismatch,
    #[error("commit binding does not match the exact scope")]
    CommitMismatch,
    #[error("model/test selector digest drifted")]
    SelectionDrift,
    #[error("Mission/Project/Work Product scope does not match")]
    MissionScopeMismatch,
    #[error("duplicate run has a different evidence digest")]
    DuplicateRun,
    #[error("Mission consumer is inactive")]
    ConsumerInactive,
    #[error("payload was truncated")]
    PayloadTruncated,
    #[error("payload exceeded the bounded response limit")]
    ResponseTooLarge,
    #[error("payload response digest did not verify")]
    PayloadTampered,
    #[error("evidence digest or provenance was tampered")]
    EvidenceTampered,
    #[error("proposal digest or provenance was tampered")]
    ProposalTampered,
    #[error("artifact is not in the exact allowlist")]
    ArtifactNotAllowlisted,
    #[error("artifact metadata refers to an unbounded artifact")]
    UnboundedArtifact,
    #[error("bounded page item limit exceeded")]
    PageTooLarge,
    #[error("bounded evidence item limit exceeded")]
    EvidenceTooLarge,
    #[error("pagination cursor repeated")]
    PaginationRepeatedCursor,
    #[error("pagination response drifted from the requested page")]
    PaginationDrift,
    #[error("pagination page limit exceeded")]
    PaginationLimit,
    #[error("configured read limits are invalid")]
    InvalidLimits,
    #[error("dbt Cloud returned HTTP {status}, projected as {projection:?}")]
    HttpStatus { status: u16, projection: RunStatus },
    #[error("dbt Cloud read timed out")]
    Timeout,
    #[error("dbt Cloud environment is blocked")]
    BlockedEnv,
    #[error("dbt Cloud provider returned an unknown or unusable result")]
    ProviderUnknown,
}

impl DbtCloudError {
    fn from_transport(error: DbtCloudTransportError) -> Self {
        match error {
            DbtCloudTransportError::HttpStatus { status, .. } => Self::HttpStatus {
                status,
                projection: projection_for_http_status(status),
            },
            DbtCloudTransportError::Timeout => Self::Timeout,
            DbtCloudTransportError::BlockedEnv => Self::BlockedEnv,
            DbtCloudTransportError::RecordingExhausted
            | DbtCloudTransportError::UnexpectedResponse => Self::ProviderUnknown,
        }
    }

    pub const fn projection(&self) -> RunStatus {
        match self {
            Self::HttpStatus { projection, .. } => *projection,
            Self::Timeout
            | Self::ProviderUnknown
            | Self::BlockedEnv
            | Self::PayloadTruncated
            | Self::ResponseTooLarge
            | Self::PayloadTampered
            | Self::EvidenceTampered
            | Self::ProposalTampered
            | Self::PaginationRepeatedCursor
            | Self::PaginationDrift
            | Self::PaginationLimit
            | Self::PageTooLarge
            | Self::EvidenceTooLarge
            | Self::JobMismatch
            | Self::RunMismatch
            | Self::RepositoryMismatch
            | Self::CommitMismatch
            | Self::SelectionDrift
            | Self::MissionScopeMismatch
            | Self::DuplicateRun
            | Self::ConsumerInactive
            | Self::RegistrationBindingDrift
            | Self::RegistrationTampered
            | Self::RegistrationInactive
            | Self::PermissionDrift
            | Self::InvalidInput(_)
            | Self::InvalidDigest
            | Self::InvalidSecretReference
            | Self::InvalidLimits => RunStatus::ProviderUnknown,
            Self::SecretRevoked | Self::SecretScopeMismatch | Self::RegistrationRevoked => {
                RunStatus::AccessLoss
            }
            Self::ArtifactNotAllowlisted | Self::UnboundedArtifact => RunStatus::Partial,
        }
    }

    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }
}

fn projection_for_http_status(status: u16) -> RunStatus {
    match status {
        401 | 403 => RunStatus::AccessLoss,
        404 => RunStatus::Expired,
        _ => RunStatus::ProviderUnknown,
    }
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), DbtCloudError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(DbtCloudError::InvalidInput(field));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), DbtCloudError> {
    validate_bounded_text(field, value, MAX_IDENTIFIER_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(&byte))
    {
        return Err(DbtCloudError::InvalidInput(field));
    }
    Ok(())
}

fn validate_commit_sha(value: &str) -> Result<(), DbtCloudError> {
    if !(value.len() == 40 || value.len() == 64)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DbtCloudError::InvalidInput("commit SHA"));
    }
    Ok(())
}

fn canonical_strings(
    values: impl IntoIterator<Item = String>,
    max_count: usize,
) -> Result<Vec<String>, DbtCloudError> {
    let mut set = BTreeSet::new();
    for value in values {
        validate_bounded_text("bounded selector", &value, MAX_SELECTOR_BYTES)?;
        set.insert(value);
        if set.len() > max_count {
            return Err(DbtCloudError::EvidenceTooLarge);
        }
    }
    Ok(set.into_iter().collect())
}

fn validate_selector_list(values: &[String], max_count: usize) -> Result<(), DbtCloudError> {
    if values.len() > max_count {
        return Err(DbtCloudError::EvidenceTooLarge);
    }
    for value in values {
        validate_bounded_text("selector", value, MAX_SELECTOR_BYTES)?;
    }
    Ok(())
}

fn validate_artifact_list(values: &[String]) -> Result<(), DbtCloudError> {
    if values.len() > MAX_ARTIFACT_COUNT {
        return Err(DbtCloudError::EvidenceTooLarge);
    }
    for value in values {
        validate_bounded_text("artifact allowlist", value, MAX_ARTIFACT_NAME_BYTES)?;
    }
    Ok(())
}

fn validate_step_ids(values: &[String]) -> Result<(), DbtCloudError> {
    if values.len() > MAX_STEP_COUNT {
        return Err(DbtCloudError::EvidenceTooLarge);
    }
    for value in values {
        validate_identifier("step id", value)?;
        if value.len() > MAX_STEP_ID_BYTES {
            return Err(DbtCloudError::InvalidInput("step id"));
        }
    }
    Ok(())
}
