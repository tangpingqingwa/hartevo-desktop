#![forbid(unsafe_code)]
#![doc = "Standalone Layer-1 Airflow DAG-run result plugin."]
//!
//! This crate is a bounded read/proposal boundary for Airflow. It binds one
//! exact host, tenant, DAG, run, task, logical date, code revision, and
//! Hartevo Mission scope. It has no native HTTP client, credential resolver,
//! scheduler authority, mutation API, raw log/XCom representation, durable
//! provider receipt, or Work Product adoption authority.
//!
//! Recording, fixture, fake, loopback, and BLOCKED_ENV transports are typed
//! evidence sources. They never claim connected, native, or first-party
//! evidence.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.airflow-dag-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AIRFLOW-01-L1/v1";
pub const PLUGIN_ID: &str = "airflow.dag-result";
pub const SERVICE_ID: &str = "AirflowDagResultService";
pub const PROVIDER_ID: &str = "AirflowProvider";
pub const CONSUMER_ID: &str = "MissionAirflowRunConsumer";
pub const AIRFLOW_API_REVISION: &str = "stable-rest-api-v1";
pub const AIRFLOW_API_BASE_PATH: &str = "/api/v1";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/airflow-dag-result/service.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TIMESTAMP_BYTES: usize = 64;
pub const MAX_PAGE_ITEMS: usize = 256;
pub const MAX_PAGES: usize = 32;
pub const MAX_TASK_INSTANCES: usize = 4_096;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_STATE_FILTERS: usize = 8;

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

pub const PLUGIN_VERSION: Version = Version::new(1, 0, 0);

/// Lowercase SHA-256 over canonical typed values. Raw provider payloads never
/// enter this type.
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

    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded contract values serialize");
        Self::from_bytes(&bytes)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        self.0.len() == 64
            && self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowHostIdentity {
    pub origin: String,
    pub host_id: String,
    pub api_revision: String,
    pub revision: u64,
}

impl AirflowHostIdentity {
    pub fn new(
        origin: impl Into<String>,
        host_id: impl Into<String>,
        api_revision: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        let identity = Self {
            origin: origin.into(),
            host_id: host_id.into(),
            api_revision: api_revision.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<()> {
        validate_origin(&self.origin)?;
        validate_identifier("host id", &self.host_id)?;
        validate_identifier("API revision", &self.api_revision)?;
        if self.api_revision != AIRFLOW_API_REVISION {
            return Err(AirflowError::ApiRevisionMismatch);
        }
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

macro_rules! define_revisioned_identity {
    ($type_name:ident, $field:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $type_name {
            pub $field: String,
            pub revision: u64,
        }

        impl $type_name {
            pub fn new(value: impl Into<String>, revision: u64) -> Result<Self> {
                let identity = Self {
                    $field: value.into(),
                    revision,
                };
                identity.validate()?;
                Ok(identity)
            }

            fn validate(&self) -> Result<()> {
                validate_identifier($label, &self.$field)?;
                validate_revision(self.revision)
            }

            pub fn digest(&self) -> Digest {
                Digest::from_serializable(self)
            }
        }
    };
}

define_revisioned_identity!(AirflowTenantIdentity, tenant_id, "tenant id");
define_revisioned_identity!(AirflowDagIdentity, dag_id, "DAG id");
define_revisioned_identity!(AirflowRunIdentity, run_id, "DAG run id");
define_revisioned_identity!(AirflowTaskIdentity, task_id, "task id");

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowLogicalDate {
    pub value: String,
    pub revision: u64,
}

impl AirflowLogicalDate {
    pub fn new(value: impl Into<String>, revision: u64) -> Result<Self> {
        let logical_date = Self {
            value: value.into(),
            revision,
        };
        logical_date.validate()?;
        Ok(logical_date)
    }

    fn validate(&self) -> Result<()> {
        validate_timestamp(&self.value)?;
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirflowCommitOrReleaseKind {
    Commit,
    Release,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowCommitOrRelease {
    pub kind: AirflowCommitOrReleaseKind,
    pub value: String,
    pub revision: u64,
}

impl AirflowCommitOrRelease {
    pub fn new(
        kind: AirflowCommitOrReleaseKind,
        value: impl Into<String>,
        revision: u64,
    ) -> Result<Self> {
        let reference = Self {
            kind,
            value: value.into(),
            revision,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn commit(value: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(AirflowCommitOrReleaseKind::Commit, value, revision)
    }

    pub fn release(value: impl Into<String>, revision: u64) -> Result<Self> {
        Self::new(AirflowCommitOrReleaseKind::Release, value, revision)
    }

    fn validate(&self) -> Result<()> {
        match self.kind {
            AirflowCommitOrReleaseKind::Commit => {
                if !matches!(self.value.len(), 40 | 64)
                    || !self.value.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(AirflowError::InvalidInput("commit SHA"));
                }
            }
            AirflowCommitOrReleaseKind::Release => {
                validate_identifier("release", &self.value)?;
            }
        }
        validate_revision(self.revision)
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
    ) -> Result<Self> {
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

    fn validate(&self) -> Result<()> {
        validate_identifier("Project", &self.project_id)?;
        validate_identifier("Mission", &self.mission_id)?;
        validate_identifier("Work Product", &self.work_product_id)?;
        validate_revision(self.project_revision)?;
        validate_revision(self.mission_revision)?;
        validate_revision(self.work_product_revision)?;
        if !self.policy_digest.is_valid() || !self.consent_digest.is_valid() {
            return Err(AirflowError::InvalidDigest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AirflowPermission {
    HostRead,
    TenantRead,
    DagRead,
    DagRunRead,
    TaskInstanceRead,
    LogicalDateRead,
    CommitRead,
    MissionScope,
}

impl AirflowPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostRead => "host:read",
            Self::TenantRead => "tenant:read",
            Self::DagRead => "dag:read",
            Self::DagRunRead => "dag-run:read",
            Self::TaskInstanceRead => "task-instance:read",
            Self::LogicalDateRead => "logical-date:read",
            Self::CommitRead => "commit:read",
            Self::MissionScope => "mission:scope",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowScope {
    pub host: AirflowHostIdentity,
    pub tenant: AirflowTenantIdentity,
    pub dag: AirflowDagIdentity,
    pub run: AirflowRunIdentity,
    pub task: AirflowTaskIdentity,
    pub logical_date: AirflowLogicalDate,
    pub commit_or_release: AirflowCommitOrRelease,
    pub mission: MissionScopeBinding,
    pub permissions: BTreeSet<AirflowPermission>,
}

impl AirflowScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: AirflowHostIdentity,
        tenant: AirflowTenantIdentity,
        dag: AirflowDagIdentity,
        run: AirflowRunIdentity,
        task: AirflowTaskIdentity,
        logical_date: AirflowLogicalDate,
        commit_or_release: AirflowCommitOrRelease,
        mission: MissionScopeBinding,
        permissions: impl IntoIterator<Item = AirflowPermission>,
    ) -> Result<Self> {
        let scope = Self {
            host,
            tenant,
            dag,
            run,
            task,
            logical_date,
            commit_or_release,
            mission,
            permissions: permissions.into_iter().collect(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        self.host.validate()?;
        self.tenant.validate()?;
        self.dag.validate()?;
        self.run.validate()?;
        self.task.validate()?;
        self.logical_date.validate()?;
        self.commit_or_release.validate()?;
        self.mission.validate()?;
        let required = [
            AirflowPermission::HostRead,
            AirflowPermission::TenantRead,
            AirflowPermission::DagRead,
            AirflowPermission::DagRunRead,
            AirflowPermission::TaskInstanceRead,
            AirflowPermission::LogicalDateRead,
            AirflowPermission::CommitRead,
            AirflowPermission::MissionScope,
        ];
        if required
            .iter()
            .any(|permission| !self.permissions.contains(permission))
        {
            return Err(AirflowError::PermissionDrift);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn host_digest(&self) -> Digest {
        self.host.digest()
    }

    pub fn tenant_digest(&self) -> Digest {
        self.tenant.digest()
    }

    pub fn dag_digest(&self) -> Digest {
        self.dag.digest()
    }

    pub fn run_digest(&self) -> Digest {
        self.run.digest()
    }

    pub fn task_digest(&self) -> Digest {
        self.task.digest()
    }

    pub fn logical_date_digest(&self) -> Digest {
        self.logical_date.digest()
    }

    pub fn commit_or_release_digest(&self) -> Digest {
        self.commit_or_release.digest()
    }

    pub fn mission_digest(&self) -> Digest {
        self.mission.digest()
    }

    pub fn permission_digest(&self) -> Digest {
        let permissions: Vec<&str> = self
            .permissions
            .iter()
            .map(|permission| permission.as_str())
            .collect();
        Digest::from_serializable(&permissions)
    }

    pub fn revision_digest(&self) -> Digest {
        Digest::from_serializable(&(
            self.host.revision,
            self.tenant.revision,
            self.dag.revision,
            self.run.revision,
            self.task.revision,
            self.logical_date.revision,
            self.commit_or_release.revision,
            self.mission.project_revision,
            self.mission.mission_revision,
            self.mission.work_product_revision,
        ))
    }

    pub fn api_digest(&self) -> Digest {
        Digest::from_text(self.host.api_revision.as_bytes())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirflowState {
    Queued,
    Running,
    Success,
    Failed,
    UpstreamFailed,
    Skipped,
    Deferred,
}

impl AirflowState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Success | Self::Failed | Self::UpstreamFailed | Self::Skipped
        )
    }

    pub const fn projection(self) -> AirflowRunProjection {
        match self {
            Self::Queued => AirflowRunProjection::Queued,
            Self::Running => AirflowRunProjection::Running,
            Self::Success => AirflowRunProjection::Success,
            Self::Failed => AirflowRunProjection::Failed,
            Self::UpstreamFailed => AirflowRunProjection::UpstreamFailed,
            Self::Skipped => AirflowRunProjection::Skipped,
            Self::Deferred => AirflowRunProjection::Deferred,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirflowRunProjection {
    Queued,
    Running,
    Success,
    Failed,
    UpstreamFailed,
    Skipped,
    Deferred,
    Partial,
    Stale,
    AccessLoss,
    ProviderUnknown,
}

impl AirflowRunProjection {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Success
                | Self::Failed
                | Self::UpstreamFailed
                | Self::Skipped
                | Self::Stale
                | Self::AccessLoss
                | Self::ProviderUnknown
        )
    }

    pub const fn is_access_loss(self) -> bool {
        matches!(self, Self::AccessLoss)
    }

    pub const fn can_follow(self, next: Self) -> bool {
        if self as u8 == next as u8 {
            return true;
        }
        match self {
            Self::Queued => matches!(
                next,
                Self::Running
                    | Self::Success
                    | Self::Failed
                    | Self::UpstreamFailed
                    | Self::Skipped
                    | Self::Deferred
                    | Self::Partial
                    | Self::Stale
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Running | Self::Deferred | Self::Partial => matches!(
                next,
                Self::Running
                    | Self::Success
                    | Self::Failed
                    | Self::UpstreamFailed
                    | Self::Skipped
                    | Self::Deferred
                    | Self::Partial
                    | Self::Stale
                    | Self::AccessLoss
                    | Self::ProviderUnknown
            ),
            Self::Success
            | Self::Failed
            | Self::UpstreamFailed
            | Self::Skipped
            | Self::Stale
            | Self::AccessLoss
            | Self::ProviderUnknown => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Bearer,
    Oidc,
}

/// Opaque reference to a credential held outside this crate. It deliberately
/// has no `Serialize` or `Deserialize` implementation and never stores token
/// bytes.
pub struct SecretReference {
    reference_id: String,
    kind: SecretKind,
    scope_digest: Digest,
    credential_revision: u64,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_id: self.reference_id.clone(),
            kind: self.kind,
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            revoked: self.revoked,
        }
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_id == other.reference_id
            && self.kind == other.kind
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
            .field("kind", &self.kind)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        kind: SecretKind,
        scope: &AirflowScope,
        credential_revision: u64,
    ) -> Result<Self> {
        scope.validate()?;
        let reference = Self {
            reference_id: reference_id.into(),
            kind,
            scope_digest: scope.scope_digest(),
            credential_revision,
            revoked: false,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn bearer(
        reference_id: impl Into<String>,
        scope: &AirflowScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(reference_id, SecretKind::Bearer, scope, credential_revision)
    }

    pub fn oidc(
        reference_id: impl Into<String>,
        scope: &AirflowScope,
        credential_revision: u64,
    ) -> Result<Self> {
        Self::new(reference_id, SecretKind::Oidc, scope, credential_revision)
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.reference_id,
            self.kind,
            &self.scope_digest,
            self.credential_revision,
        ))
    }

    pub const fn kind(&self) -> SecretKind {
        self.kind
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

    pub fn is_bound_to(&self, scope: &AirflowScope) -> bool {
        !self.revoked && self.scope_digest == scope.scope_digest()
    }

    fn validate(&self) -> Result<()> {
        if !self.reference_id.starts_with("secret-ref-")
            || self.reference_id.len() > MAX_IDENTIFIER_BYTES
        {
            return Err(AirflowError::InvalidSecretReference);
        }
        validate_identifier("SecretReference", &self.reference_id)?;
        if self.credential_revision == 0 || !self.scope_digest.is_valid() {
            return Err(AirflowError::InvalidSecretReference);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Unmounted,
    Revoked,
    Reversed,
}

impl RegistrationStatus {
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub plugin_version: Version,
    pub status: RegistrationStatus,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub host_digest: Digest,
    pub tenant_digest: Digest,
    pub dag_digest: Digest,
    pub run_digest: Digest,
    pub task_digest: Digest,
    pub logical_date_digest: Digest,
    pub commit_or_release_digest: Digest,
    pub mission_digest: Digest,
    pub permission_digest: Digest,
    pub revision_digest: Digest,
    pub scope_digest: Digest,
    pub credential_digest: Digest,
    pub registration_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

#[derive(Serialize)]
struct RegistrationDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    service_id: &'a str,
    provider_id: &'a str,
    plugin_version: Version,
    version_digest: &'a Digest,
    contract_digest: &'a Digest,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    host_digest: &'a Digest,
    tenant_digest: &'a Digest,
    dag_digest: &'a Digest,
    run_digest: &'a Digest,
    task_digest: &'a Digest,
    logical_date_digest: &'a Digest,
    commit_or_release_digest: &'a Digest,
    mission_digest: &'a Digest,
    permission_digest: &'a Digest,
    revision_digest: &'a Digest,
    scope_digest: &'a Digest,
    credential_digest: &'a Digest,
    reversible: bool,
    revocable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationTransitionEvidence {
    pub registration_digest: Digest,
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub reason_digest: Digest,
    pub transition_digest: Digest,
    pub reversible: bool,
    pub revocable: bool,
}

impl RegistrationTransitionEvidence {
    fn new(
        registration_digest: &Digest,
        from: RegistrationStatus,
        to: RegistrationStatus,
        reason: &str,
    ) -> Self {
        let reason_digest = Digest::from_text(reason);
        let transition_digest =
            Digest::from_serializable(&(registration_digest, from, to, &reason_digest));
        Self {
            registration_digest: registration_digest.clone(),
            from,
            to,
            reason_digest,
            transition_digest,
            reversible: true,
            revocable: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.registration_digest.is_valid()
            || !self.reason_digest.is_valid()
            || self.transition_digest
                != Digest::from_serializable(&(
                    &self.registration_digest,
                    self.from,
                    self.to,
                    &self.reason_digest,
                ))
            || !self.reversible
            || !self.revocable
        {
            return Err(AirflowError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationReceipt {
    pub registration_digest: Digest,
    pub status: RegistrationStatus,
    pub transition: RegistrationTransitionEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationReceipt {
    pub registration_digest: Digest,
    pub secret_reference_digest: Digest,
    pub transition: RegistrationTransitionEvidence,
}

impl AirflowRegistration {
    pub fn new(scope: &AirflowScope, secret_reference: &SecretReference) -> Result<Self> {
        scope.validate()?;
        if !secret_reference.is_bound_to(scope) {
            return if secret_reference.is_revoked() {
                Err(AirflowError::SecretRevoked)
            } else {
                Err(AirflowError::SecretScopeMismatch)
            };
        }
        let version_digest = Digest::from_serializable(&(
            CONTRACT_SCHEMA,
            CONTRACT_VERSION,
            PLUGIN_ID,
            PLUGIN_VERSION,
        ));
        let mut registration = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            service_id: SERVICE_ID.into(),
            provider_id: PROVIDER_ID.into(),
            plugin_version: PLUGIN_VERSION,
            status: RegistrationStatus::Active,
            version_digest,
            contract_digest: contract_digest(),
            provider_digest: Digest::from_text(PROVIDER_ID),
            api_digest: scope.api_digest(),
            host_digest: scope.host_digest(),
            tenant_digest: scope.tenant_digest(),
            dag_digest: scope.dag_digest(),
            run_digest: scope.run_digest(),
            task_digest: scope.task_digest(),
            logical_date_digest: scope.logical_date_digest(),
            commit_or_release_digest: scope.commit_or_release_digest(),
            mission_digest: scope.mission_digest(),
            permission_digest: scope.permission_digest(),
            revision_digest: scope.revision_digest(),
            scope_digest: scope.scope_digest(),
            credential_digest: secret_reference.reference_digest(),
            registration_digest: Digest::from_text("uncomputed"),
            reversible: true,
            revocable: true,
        };
        registration.registration_digest = registration.compute_digest();
        Ok(registration)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&RegistrationDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            service_id: &self.service_id,
            provider_id: &self.provider_id,
            plugin_version: self.plugin_version,
            version_digest: &self.version_digest,
            contract_digest: &self.contract_digest,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            host_digest: &self.host_digest,
            tenant_digest: &self.tenant_digest,
            dag_digest: &self.dag_digest,
            run_digest: &self.run_digest,
            task_digest: &self.task_digest,
            logical_date_digest: &self.logical_date_digest,
            commit_or_release_digest: &self.commit_or_release_digest,
            mission_digest: &self.mission_digest,
            permission_digest: &self.permission_digest,
            revision_digest: &self.revision_digest,
            scope_digest: &self.scope_digest,
            credential_digest: &self.credential_digest,
            reversible: self.reversible,
            revocable: self.revocable,
        })
    }

    pub fn validate_binding(
        &self,
        scope: &AirflowScope,
        secret_reference: &SecretReference,
    ) -> Result<()> {
        if self.compute_digest() != self.registration_digest {
            return Err(AirflowError::RegistrationTampered);
        }
        let expected = Self::new(scope, secret_reference)?;
        if self.schema_version != expected.schema_version
            || self.contract_version != expected.contract_version
            || self.service_id != expected.service_id
            || self.provider_id != expected.provider_id
            || self.plugin_version != expected.plugin_version
            || self.version_digest != expected.version_digest
            || self.contract_digest != expected.contract_digest
            || self.provider_digest != expected.provider_digest
            || self.api_digest != expected.api_digest
            || self.host_digest != expected.host_digest
            || self.tenant_digest != expected.tenant_digest
            || self.dag_digest != expected.dag_digest
            || self.run_digest != expected.run_digest
            || self.task_digest != expected.task_digest
            || self.logical_date_digest != expected.logical_date_digest
            || self.commit_or_release_digest != expected.commit_or_release_digest
            || self.mission_digest != expected.mission_digest
            || self.permission_digest != expected.permission_digest
            || self.revision_digest != expected.revision_digest
            || self.scope_digest != expected.scope_digest
            || self.credential_digest != expected.credential_digest
            || !self.reversible
            || !self.revocable
        {
            return Err(AirflowError::RegistrationBindingDrift);
        }
        Ok(())
    }

    pub fn registration_id(&self) -> &Digest {
        &self.registration_digest
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub const fn is_active(&self) -> bool {
        self.status.is_active()
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Active {
            return Err(AirflowError::RegistrationInactive);
        }
        let from = self.status;
        self.status = RegistrationStatus::Unmounted;
        Ok(RegistrationTransitionEvidence::new(
            &self.registration_digest,
            from,
            self.status,
            "unmount",
        ))
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Unmounted {
            return Err(AirflowError::RegistrationInactive);
        }
        let from = self.status;
        self.status = RegistrationStatus::Active;
        Ok(RegistrationTransitionEvidence::new(
            &self.registration_digest,
            from,
            self.status,
            "remount",
        ))
    }

    pub fn revoke(&mut self, secret_reference: &mut SecretReference) -> Result<RevocationReceipt> {
        if self.status == RegistrationStatus::Reversed {
            return Err(AirflowError::RegistrationInactive);
        }
        let from = self.status;
        self.status = RegistrationStatus::Revoked;
        secret_reference.revoke();
        let transition = RegistrationTransitionEvidence::new(
            &self.registration_digest,
            from,
            self.status,
            "revoke",
        );
        Ok(RevocationReceipt {
            registration_digest: self.registration_digest.clone(),
            secret_reference_digest: secret_reference.reference_digest(),
            transition,
        })
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if self.status != RegistrationStatus::Revoked {
            return Err(AirflowError::RegistrationInactive);
        }
        let from = self.status;
        self.status = RegistrationStatus::Reversed;
        Ok(RegistrationTransitionEvidence::new(
            &self.registration_digest,
            from,
            self.status,
            "reverse",
        ))
    }
}

#[derive(Clone, Debug, Default)]
pub struct AirflowRegistrationRegistry {
    registrations: BTreeMap<String, AirflowRegistration>,
}

impl AirflowRegistrationRegistry {
    pub fn register(&mut self, registration: AirflowRegistration) -> Result<RegistrationReceipt> {
        if registration.compute_digest() != registration.registration_digest
            || !registration.reversible
            || !registration.revocable
        {
            return Err(AirflowError::RegistrationTampered);
        }
        if self
            .registrations
            .contains_key(registration.registration_id().as_str())
        {
            return Err(AirflowError::DuplicateEvidence);
        }
        let transition = RegistrationTransitionEvidence::new(
            registration.registration_id(),
            RegistrationStatus::Unmounted,
            registration.status,
            "register",
        );
        let key = registration.registration_id().as_str().to_owned();
        let status = registration.status;
        self.registrations.insert(key, registration);
        Ok(RegistrationReceipt {
            registration_digest: transition.registration_digest.clone(),
            status,
            transition,
        })
    }

    pub fn get(&self, registration_digest: &Digest) -> Option<&AirflowRegistration> {
        self.registrations.get(registration_digest.as_str())
    }

    pub fn get_mut(&mut self, registration_digest: &Digest) -> Option<&mut AirflowRegistration> {
        self.registrations.get_mut(registration_digest.as_str())
    }

    pub fn revoke(
        &mut self,
        registration_digest: &Digest,
        secret_reference: &mut SecretReference,
    ) -> Result<RevocationReceipt> {
        self.get_mut(registration_digest)
            .ok_or(AirflowError::RegistrationBindingDrift)?
            .revoke(secret_reference)
    }

    pub fn restore(
        &mut self,
        registration_digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence> {
        self.get_mut(registration_digest)
            .ok_or(AirflowError::RegistrationBindingDrift)?
            .remount()
    }

    pub fn reverse(
        &mut self,
        registration_digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence> {
        self.get_mut(registration_digest)
            .ok_or(AirflowError::RegistrationBindingDrift)?
            .reverse()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AirflowError {
    #[error("invalid Layer-1 Airflow input: {0}")]
    InvalidInput(&'static str),
    #[error("invalid digest")]
    InvalidDigest,
    #[error("invalid opaque SecretReference")]
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
    #[error("permission digest or required read-only permission drifted")]
    PermissionDrift,
    #[error("Airflow API revision does not match the stable REST contract")]
    ApiRevisionMismatch,
    #[error("Airflow host identity does not match the exact scope")]
    HostMismatch,
    #[error("Airflow tenant identity does not match the exact scope")]
    TenantMismatch,
    #[error("Airflow DAG identity does not match the exact scope")]
    DagMismatch,
    #[error("Airflow DAG run identity does not match the exact scope")]
    RunMismatch,
    #[error("Airflow task identity does not match the exact scope")]
    TaskMismatch,
    #[error("Airflow logical date does not match the exact scope")]
    LogicalDateMismatch,
    #[error("Airflow commit-or-release reference does not match the exact scope")]
    CommitOrReleaseMismatch,
    #[error("Mission/Project/Work Product scope does not match")]
    MissionScopeMismatch,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("revision fence is stale")]
    StaleRevision,
    #[error("run state transition is invalid")]
    InvalidStateTransition,
    #[error("payload was truncated")]
    PayloadTruncated,
    #[error("payload was marked partial")]
    PartialResponse,
    #[error("payload exceeded the bounded response limit")]
    ResponseTooLarge,
    #[error("payload response digest did not verify")]
    PayloadTampered,
    #[error("evidence, page, or provenance digest was tampered")]
    EvidenceTampered,
    #[error("proposal digest or provenance was tampered")]
    ProposalTampered,
    #[error("redaction boundary was violated")]
    RedactionViolation,
    #[error("bounded page item limit exceeded")]
    PageTooLarge,
    #[error("bounded evidence item limit exceeded")]
    EvidenceTooLarge,
    #[error("pagination cursor or page limit exceeded")]
    PaginationLimit,
    #[error("pagination response drifted from the requested page")]
    PaginationDrift,
    #[error("pagination cursor repeated")]
    PaginationRepeated,
    #[error("duplicate evidence fingerprint")]
    DuplicateEvidence,
    #[error("consumer is inactive")]
    ConsumerInactive,
    #[error("date filter is outside the exact logical-date scope")]
    DateFilterOutOfScope,
    #[error("HTTP {status} projected as {projection:?}")]
    HttpStatus {
        status: u16,
        projection: AirflowRunProjection,
    },
    #[error("Airflow read timed out")]
    Timeout,
    #[error("Airflow environment is blocked")]
    BlockedEnv,
    #[error("Airflow provider returned an unknown or unusable result")]
    ProviderUnknown,
    #[error("recording has no response for the requested typed operation")]
    RecordingExhausted,
    #[error("recording response has the wrong typed operation")]
    UnexpectedResponse,
    #[error("only GET reads are allowed in Layer 1")]
    ReadMethodForbidden,
}

impl AirflowError {
    fn from_transport(error: &AirflowTransportError) -> Self {
        match error {
            AirflowTransportError::HttpStatus { status, .. } => Self::HttpStatus {
                status: *status,
                projection: projection_for_http_status(*status),
            },
            AirflowTransportError::Timeout => Self::Timeout,
            AirflowTransportError::BlockedEnv => Self::BlockedEnv,
            AirflowTransportError::MalformedResponse => Self::PartialResponse,
            AirflowTransportError::ResponseTooLarge => Self::ResponseTooLarge,
            AirflowTransportError::RecordingExhausted => Self::RecordingExhausted,
            AirflowTransportError::UnexpectedOperation => Self::UnexpectedResponse,
        }
    }

    pub const fn projection(&self) -> AirflowRunProjection {
        match self {
            Self::HttpStatus { projection, .. } => *projection,
            Self::SecretRevoked
            | Self::SecretScopeMismatch
            | Self::RegistrationRevoked
            | Self::RegistrationInactive => AirflowRunProjection::AccessLoss,
            Self::StaleMissionRevision | Self::StaleRevision => AirflowRunProjection::Stale,
            _ => AirflowRunProjection::ProviderUnknown,
        }
    }

    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }
}

fn projection_for_http_status(status: u16) -> AirflowRunProjection {
    match status {
        401 | 403 => AirflowRunProjection::AccessLoss,
        404 | 409 => AirflowRunProjection::Stale,
        _ => AirflowRunProjection::ProviderUnknown,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowHostDescription {
    pub host: AirflowHostIdentity,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub read_only: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl AirflowHostDescription {
    fn for_scope(scope: &AirflowScope) -> Self {
        Self {
            host: scope.host.clone(),
            api_digest: scope.api_digest(),
            scope_digest: scope.scope_digest(),
            read_only: true,
            native_connected: false,
            first_party: false,
        }
    }

    pub fn validate(&self, scope: &AirflowScope) -> Result<()> {
        self.host.validate()?;
        if self.host != scope.host
            || self.api_digest != scope.api_digest()
            || self.scope_digest != scope.scope_digest()
            || !self.read_only
            || self.native_connected
            || self.first_party
        {
            return Err(AirflowError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowTenantDescription {
    pub tenant: AirflowTenantIdentity,
    pub scope_digest: Digest,
    pub read_only: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl AirflowTenantDescription {
    fn for_scope(scope: &AirflowScope) -> Self {
        Self {
            tenant: scope.tenant.clone(),
            scope_digest: scope.scope_digest(),
            read_only: true,
            native_connected: false,
            first_party: false,
        }
    }

    pub fn validate(&self, scope: &AirflowScope) -> Result<()> {
        self.tenant.validate()?;
        if self.tenant != scope.tenant
            || self.scope_digest != scope.scope_digest()
            || !self.read_only
            || self.native_connected
            || self.first_party
        {
            return Err(AirflowError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowDagDescription {
    pub dag: AirflowDagIdentity,
    pub scope_digest: Digest,
    pub stable_rest_read: bool,
    pub native_connected: bool,
    pub first_party: bool,
}

impl AirflowDagDescription {
    fn for_scope(scope: &AirflowScope) -> Self {
        Self {
            dag: scope.dag.clone(),
            scope_digest: scope.scope_digest(),
            stable_rest_read: true,
            native_connected: false,
            first_party: false,
        }
    }

    pub fn validate(&self, scope: &AirflowScope) -> Result<()> {
        self.dag.validate()?;
        if self.dag != scope.dag
            || self.scope_digest != scope.scope_digest()
            || !self.stable_rest_read
            || self.native_connected
            || self.first_party
        {
            return Err(AirflowError::EvidenceTampered);
        }
        Ok(())
    }
}

/// Allowlisted fields from the stable Airflow DAG-run resource. Configuration,
/// variables, connections, logs, and XCom are intentionally not represented.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowDagRunRecord {
    pub dag: AirflowDagIdentity,
    pub run: AirflowRunIdentity,
    pub logical_date: AirflowLogicalDate,
    pub state: AirflowState,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub run_type: Option<String>,
    pub data_interval_start: Option<String>,
    pub data_interval_end: Option<String>,
}

impl AirflowDagRunRecord {
    pub fn new(
        dag: AirflowDagIdentity,
        run: AirflowRunIdentity,
        logical_date: AirflowLogicalDate,
        state: AirflowState,
    ) -> Result<Self> {
        let record = Self {
            dag,
            run,
            logical_date,
            state,
            start_date: None,
            end_date: None,
            run_type: None,
            data_interval_start: None,
            data_interval_end: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn with_dates(
        mut self,
        start_date: Option<String>,
        end_date: Option<String>,
        data_interval_start: Option<String>,
        data_interval_end: Option<String>,
    ) -> Result<Self> {
        self.start_date = start_date;
        self.end_date = end_date;
        self.data_interval_start = data_interval_start;
        self.data_interval_end = data_interval_end;
        self.validate()?;
        Ok(self)
    }

    pub fn with_run_type(mut self, run_type: impl Into<String>) -> Result<Self> {
        self.run_type = Some(run_type.into());
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.dag.validate()?;
        self.run.validate()?;
        self.logical_date.validate()?;
        for timestamp in [
            self.start_date.as_deref(),
            self.end_date.as_deref(),
            self.data_interval_start.as_deref(),
            self.data_interval_end.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_timestamp(timestamp)?;
        }
        if let Some(run_type) = &self.run_type {
            validate_identifier("run type", run_type)?;
        }
        Ok(())
    }

    pub fn validate_for_scope(&self, scope: &AirflowScope) -> Result<()> {
        self.validate()?;
        if self.dag != scope.dag {
            return Err(AirflowError::DagMismatch);
        }
        if self.run != scope.run {
            return Err(AirflowError::RunMismatch);
        }
        if self.logical_date != scope.logical_date {
            return Err(AirflowError::LogicalDateMismatch);
        }
        Ok(())
    }

    pub fn metadata_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// Allowlisted fields from a stable Airflow task-instance resource. Hostname,
/// executor config, rendered fields, logs, and XCom are not accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowTaskInstanceRecord {
    pub dag: AirflowDagIdentity,
    pub run: AirflowRunIdentity,
    pub task: AirflowTaskIdentity,
    pub logical_date: AirflowLogicalDate,
    pub state: AirflowState,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub duration_seconds: Option<u64>,
    pub try_number: u32,
    pub map_index: i32,
    pub operator: Option<String>,
}

impl AirflowTaskInstanceRecord {
    pub fn new(
        dag: AirflowDagIdentity,
        run: AirflowRunIdentity,
        task: AirflowTaskIdentity,
        logical_date: AirflowLogicalDate,
        state: AirflowState,
    ) -> Result<Self> {
        let record = Self {
            dag,
            run,
            task,
            logical_date,
            state,
            start_date: None,
            end_date: None,
            duration_seconds: None,
            try_number: 0,
            map_index: -1,
            operator: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn with_execution_metadata(
        mut self,
        start_date: Option<String>,
        end_date: Option<String>,
        duration_seconds: Option<u64>,
        try_number: u32,
        map_index: i32,
        operator: Option<String>,
    ) -> Result<Self> {
        self.start_date = start_date;
        self.end_date = end_date;
        self.duration_seconds = duration_seconds;
        self.try_number = try_number;
        self.map_index = map_index;
        self.operator = operator;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        self.dag.validate()?;
        self.run.validate()?;
        self.task.validate()?;
        self.logical_date.validate()?;
        if self.map_index < -1 || self.try_number > 1_000_000 {
            return Err(AirflowError::InvalidInput("task execution metadata"));
        }
        for timestamp in [self.start_date.as_deref(), self.end_date.as_deref()]
            .into_iter()
            .flatten()
        {
            validate_timestamp(timestamp)?;
        }
        if let Some(operator) = &self.operator {
            validate_identifier("operator", operator)?;
        }
        Ok(())
    }

    pub fn validate_for_scope(&self, scope: &AirflowScope) -> Result<()> {
        self.validate()?;
        if self.dag != scope.dag {
            return Err(AirflowError::DagMismatch);
        }
        if self.run != scope.run {
            return Err(AirflowError::RunMismatch);
        }
        if self.task != scope.task {
            return Err(AirflowError::TaskMismatch);
        }
        if self.logical_date != scope.logical_date {
            return Err(AirflowError::LogicalDateMismatch);
        }
        Ok(())
    }

    pub fn metadata_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn materialization_metadata(&self) -> AirflowMaterializationMetadata {
        AirflowMaterializationMetadata {
            task: self.task.clone(),
            logical_date: self.logical_date.clone(),
            map_index: self.map_index,
            state: self.state,
            operator: self.operator.clone(),
            metadata_digest: self.metadata_digest(),
        }
    }
}

/// Digest-only materialization metadata. It is derived from allowlisted task
/// fields and is not an XCom value, log body, or provider receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowMaterializationMetadata {
    pub task: AirflowTaskIdentity,
    pub logical_date: AirflowLogicalDate,
    pub map_index: i32,
    pub state: AirflowState,
    pub operator: Option<String>,
    pub metadata_digest: Digest,
}

impl AirflowMaterializationMetadata {
    pub fn validate(&self) -> Result<()> {
        self.task.validate()?;
        self.logical_date.validate()?;
        if self.map_index < -1 || !self.metadata_digest.is_valid() {
            return Err(AirflowError::EvidenceTampered);
        }
        if let Some(operator) = &self.operator {
            validate_identifier("operator", operator)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowPage<T> {
    pub items: Vec<T>,
    pub total_entries: usize,
    pub offset: usize,
    pub limit: usize,
    pub partial: bool,
}

impl<T> AirflowPage<T> {
    pub fn new(
        items: Vec<T>,
        total_entries: usize,
        offset: usize,
        limit: usize,
        partial: bool,
    ) -> Self {
        Self {
            items,
            total_entries,
            offset,
            limit,
            partial,
        }
    }

    pub fn page_digest(&self) -> Digest
    where
        T: Serialize,
    {
        Digest::from_serializable(self)
    }
}

pub type AirflowTaskInstancePage = AirflowPage<AirflowTaskInstanceRecord>;
pub type AirflowTaskPage = AirflowTaskInstancePage;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirflowOperation {
    GetDagRun,
    ListTaskInstances,
    GetTaskInstance,
}

impl AirflowOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetDagRun => "get_dag_run",
            Self::ListTaskInstances => "list_task_instances",
            Self::GetTaskInstance => "get_task_instance",
        }
    }

    pub const fn method(self) -> &'static str {
        "GET"
    }

    pub fn endpoint_path(self, scope: &AirflowScope) -> String {
        match self {
            Self::GetDagRun => format!(
                "{AIRFLOW_API_BASE_PATH}/dags/{}/dagRuns/{}",
                scope.dag.dag_id, scope.run.run_id
            ),
            Self::ListTaskInstances => format!(
                "{AIRFLOW_API_BASE_PATH}/dags/{}/dagRuns/{}/taskInstances",
                scope.dag.dag_id, scope.run.run_id
            ),
            Self::GetTaskInstance => format!(
                "{AIRFLOW_API_BASE_PATH}/dags/{}/dagRuns/{}/taskInstances/{}",
                scope.dag.dag_id, scope.run.run_id, scope.task.task_id
            ),
        }
    }
}

pub fn dag_run_endpoint_path(scope: &AirflowScope) -> String {
    AirflowOperation::GetDagRun.endpoint_path(scope)
}

pub fn task_instances_endpoint_path(scope: &AirflowScope) -> String {
    AirflowOperation::ListTaskInstances.endpoint_path(scope)
}

pub fn task_instance_endpoint_path(scope: &AirflowScope) -> String {
    AirflowOperation::GetTaskInstance.endpoint_path(scope)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowReadRequest {
    pub operation: AirflowOperation,
    pub offset: usize,
    pub limit: usize,
    pub logical_date_gte: Option<String>,
    pub logical_date_lte: Option<String>,
    pub states: BTreeSet<AirflowState>,
}

impl AirflowReadRequest {
    pub fn new(
        operation: AirflowOperation,
        offset: usize,
        limit: usize,
        date_from: Option<String>,
        date_to: Option<String>,
        states: impl IntoIterator<Item = AirflowState>,
    ) -> Result<Self> {
        let request = Self {
            operation,
            offset,
            limit,
            logical_date_gte: date_from,
            logical_date_lte: date_to,
            states: states.into_iter().collect(),
        };
        request.validate(&ReadLimits::default())?;
        Ok(request)
    }

    pub fn for_dag_run() -> Self {
        Self {
            operation: AirflowOperation::GetDagRun,
            offset: 0,
            limit: 1,
            logical_date_gte: None,
            logical_date_lte: None,
            states: BTreeSet::new(),
        }
    }

    pub fn for_task_instances(offset: usize, limit: usize) -> Result<Self> {
        Self::new(
            AirflowOperation::ListTaskInstances,
            offset,
            limit,
            None,
            None,
            [],
        )
    }

    pub fn for_task_instance() -> Self {
        Self {
            operation: AirflowOperation::GetTaskInstance,
            offset: 0,
            limit: 1,
            logical_date_gte: None,
            logical_date_lte: None,
            states: BTreeSet::new(),
        }
    }

    pub fn with_date_bounds(
        mut self,
        date_from: Option<String>,
        date_to: Option<String>,
    ) -> Result<Self> {
        self.logical_date_gte = date_from;
        self.logical_date_lte = date_to;
        self.validate(&ReadLimits::default())?;
        Ok(self)
    }

    pub fn with_states(mut self, states: impl IntoIterator<Item = AirflowState>) -> Result<Self> {
        self.states = states.into_iter().collect();
        self.validate(&ReadLimits::default())?;
        Ok(self)
    }

    pub fn validate(&self, limits: &ReadLimits) -> Result<()> {
        if self.limit == 0 || self.limit > limits.max_page_items || self.offset > MAX_TASK_INSTANCES
        {
            return Err(AirflowError::PaginationLimit);
        }
        if matches!(
            self.operation,
            AirflowOperation::GetDagRun | AirflowOperation::GetTaskInstance
        ) && (self.offset != 0 || self.limit != 1)
        {
            return Err(AirflowError::InvalidInput(
                "exact Airflow GET request bounds",
            ));
        }
        if self.states.len() > MAX_STATE_FILTERS {
            return Err(AirflowError::InvalidInput("state filter bounds"));
        }
        if let Some(value) = &self.logical_date_gte {
            validate_timestamp(value)?;
        }
        if let Some(value) = &self.logical_date_lte {
            validate_timestamp(value)?;
        }
        if let (Some(lower), Some(upper)) = (&self.logical_date_gte, &self.logical_date_lte)
            && lower > upper
        {
            return Err(AirflowError::InvalidInput("logical-date bounds"));
        }
        Ok(())
    }

    pub fn validate_for_scope(&self, scope: &AirflowScope, limits: &ReadLimits) -> Result<()> {
        self.validate(limits)?;
        let logical_date = &scope.logical_date.value;
        if self
            .logical_date_gte
            .as_ref()
            .is_some_and(|lower| logical_date < lower)
            || self
                .logical_date_lte
                .as_ref()
                .is_some_and(|upper| logical_date > upper)
        {
            return Err(AirflowError::DateFilterOutOfScope);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionEvidence {
    pub redacted_fields: BTreeSet<String>,
    pub raw_payload_retained: bool,
    pub raw_headers_retained: bool,
    pub digest: Digest,
}

impl RedactionEvidence {
    pub fn standard() -> Self {
        Self::new([
            "authorization",
            "cookie",
            "conf",
            "variables",
            "connections",
            "logs",
            "xcom",
            "executor_config",
            "rendered_fields",
            "raw_response",
        ])
    }

    pub fn new<I, S>(fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut evidence = Self {
            redacted_fields: fields.into_iter().map(Into::into).collect(),
            raw_payload_retained: false,
            raw_headers_retained: false,
            digest: Digest::from_text("uncomputed"),
        };
        evidence.digest = evidence.compute_digest();
        evidence
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.redacted_fields,
            self.raw_payload_retained,
            self.raw_headers_retained,
        ))
    }

    pub fn validate(&self) -> Result<()> {
        if self.raw_payload_retained
            || self.raw_headers_retained
            || self.digest != self.compute_digest()
            || !self.redacted_fields.contains("authorization")
            || !self.redacted_fields.contains("logs")
            || !self.redacted_fields.contains("xcom")
        {
            return Err(AirflowError::RedactionViolation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowRequestAudit {
    pub method: String,
    pub path: String,
    pub operation: AirflowOperation,
    pub offset: usize,
    pub limit: usize,
    pub logical_date_gte: Option<String>,
    pub logical_date_lte: Option<String>,
    pub states: BTreeSet<AirflowState>,
    pub request_digest: Digest,
}

impl AirflowRequestAudit {
    pub fn for_scope(scope: &AirflowScope, request: &AirflowReadRequest) -> Self {
        let mut audit = Self {
            method: request.operation.method().into(),
            path: request.operation.endpoint_path(scope),
            operation: request.operation,
            offset: request.offset,
            limit: request.limit,
            logical_date_gte: request.logical_date_gte.clone(),
            logical_date_lte: request.logical_date_lte.clone(),
            states: request.states.clone(),
            request_digest: Digest::from_text("uncomputed"),
        };
        audit.request_digest = Digest::from_serializable(&(
            &audit.method,
            &audit.path,
            audit.operation,
            audit.offset,
            audit.limit,
            &audit.logical_date_gte,
            &audit.logical_date_lte,
            &audit.states,
        ));
        audit
    }

    pub fn validate(&self, scope: &AirflowScope, request: &AirflowReadRequest) -> Result<()> {
        let expected = Self::for_scope(scope, request);
        if self != &expected || self.method != "GET" {
            return Err(AirflowError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Fake,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub transport: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl EvidenceProvenance {
    fn from_transport(transport: TransportProvenance) -> Self {
        Self {
            transport,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    pub fn is_native(&self) -> bool {
        self.native
    }

    pub fn is_first_party(&self) -> bool {
        self.first_party
    }

    pub fn validate(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.transport.connected()
            || self.transport.native()
            || self.transport.first_party()
        {
            return Err(AirflowError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReadLimits {
    pub max_response_bytes: usize,
    pub max_page_items: usize,
    pub max_pages: usize,
    pub max_task_instances: usize,
    pub max_metadata_bytes: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_page_items: MAX_PAGE_ITEMS,
            max_pages: MAX_PAGES,
            max_task_instances: MAX_TASK_INSTANCES,
            max_metadata_bytes: MAX_METADATA_BYTES,
        }
    }
}

impl ReadLimits {
    pub fn validate(self) -> Result<Self> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_page_items == 0
            || self.max_page_items > MAX_PAGE_ITEMS
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_task_instances == 0
            || self.max_task_instances > MAX_TASK_INSTANCES
            || self.max_metadata_bytes == 0
            || self.max_metadata_bytes > MAX_METADATA_BYTES
        {
            return Err(AirflowError::InvalidInput("read limits"));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowPayload<T> {
    pub operation: AirflowOperation,
    pub offset: usize,
    pub limit: usize,
    pub response_bytes: usize,
    pub partial: bool,
    pub redaction: RedactionEvidence,
    pub response_digest: Digest,
    pub value: T,
}

#[derive(Serialize)]
struct PayloadDigestInput<'a, T: Serialize + ?Sized> {
    operation: AirflowOperation,
    offset: usize,
    limit: usize,
    response_bytes: usize,
    partial: bool,
    redaction: &'a RedactionEvidence,
    value: &'a T,
}

impl<T: Serialize> AirflowPayload<T> {
    pub fn new(
        operation: AirflowOperation,
        offset: usize,
        limit: usize,
        response_bytes: usize,
        partial: bool,
        redaction: RedactionEvidence,
        value: T,
    ) -> Self {
        let mut payload = Self {
            operation,
            offset,
            limit,
            response_bytes,
            partial,
            redaction,
            response_digest: Digest::from_text("uncomputed"),
            value,
        };
        payload.response_digest = payload.compute_digest();
        payload
    }

    pub fn recording(operation: AirflowOperation, offset: usize, limit: usize, value: T) -> Self {
        let response_bytes =
            serde_json::to_vec(&value).map_or(MAX_RESPONSE_BYTES + 1, |bytes| bytes.len());
        Self::new(
            operation,
            offset,
            limit,
            response_bytes,
            false,
            RedactionEvidence::standard(),
            value,
        )
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&PayloadDigestInput {
            operation: self.operation,
            offset: self.offset,
            limit: self.limit,
            response_bytes: self.response_bytes,
            partial: self.partial,
            redaction: &self.redaction,
            value: &self.value,
        })
    }

    pub fn verify(&self, request: &AirflowReadRequest, limits: &ReadLimits) -> Result<()> {
        request.validate(limits)?;
        self.redaction.validate()?;
        if self.operation != request.operation
            || self.offset != request.offset
            || self.limit != request.limit
        {
            return Err(AirflowError::PaginationDrift);
        }
        if self.response_bytes > limits.max_response_bytes {
            return Err(AirflowError::ResponseTooLarge);
        }
        if serde_json::to_vec(&self.value)
            .map_err(|_| AirflowError::PayloadTampered)?
            .len()
            > self.response_bytes
        {
            return Err(AirflowError::PayloadTampered);
        }
        if self.response_digest != self.compute_digest() {
            return Err(AirflowError::PayloadTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AirflowTransportError {
    #[error("Airflow returned HTTP {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("Airflow read timed out")]
    Timeout,
    #[error("Airflow environment is blocked")]
    BlockedEnv,
    #[error("Airflow response was malformed or incomplete")]
    MalformedResponse,
    #[error("Airflow response exceeded the bounded response limit")]
    ResponseTooLarge,
    #[error("recording has no response for the requested operation")]
    RecordingExhausted,
    #[error("recording operation did not match the request")]
    UnexpectedOperation,
}

pub trait AirflowTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_dag_run(
        &mut self,
        request: &AirflowReadRequest,
    ) -> std::result::Result<AirflowPayload<AirflowDagRunRecord>, AirflowTransportError>;

    fn list_task_instances(
        &mut self,
        request: &AirflowReadRequest,
    ) -> std::result::Result<AirflowPayload<AirflowTaskInstancePage>, AirflowTransportError>;

    fn get_task_instance(
        &mut self,
        request: &AirflowReadRequest,
    ) -> std::result::Result<AirflowPayload<AirflowTaskInstanceRecord>, AirflowTransportError>;
}

/// Deterministic transport used by recording, fixture, fake, and loopback
/// evidence. It stores typed allowlisted values only; it has no response
/// bytes, headers, credential material, or mutable Airflow operation.
#[derive(Clone, Debug)]
pub struct RecordingAirflowTransport {
    provenance: TransportProvenance,
    dag_runs:
        VecDeque<std::result::Result<AirflowPayload<AirflowDagRunRecord>, AirflowTransportError>>,
    task_pages: VecDeque<
        std::result::Result<AirflowPayload<AirflowTaskInstancePage>, AirflowTransportError>,
    >,
    task_instances: VecDeque<
        std::result::Result<AirflowPayload<AirflowTaskInstanceRecord>, AirflowTransportError>,
    >,
}

impl RecordingAirflowTransport {
    pub fn new(
        provenance: TransportProvenance,
        dag_run: AirflowDagRunRecord,
        task_pages: impl IntoIterator<Item = AirflowTaskInstancePage>,
    ) -> Self {
        let task_pages: Vec<AirflowTaskInstancePage> = task_pages.into_iter().collect();
        let task_instances = task_pages
            .iter()
            .flat_map(|page| page.items.iter().cloned())
            .map(|record| {
                Ok(AirflowPayload::recording(
                    AirflowOperation::GetTaskInstance,
                    0,
                    1,
                    record,
                ))
            })
            .collect();
        Self {
            provenance,
            dag_runs: VecDeque::from([Ok(AirflowPayload::recording(
                AirflowOperation::GetDagRun,
                0,
                1,
                dag_run,
            ))]),
            task_pages: task_pages
                .into_iter()
                .enumerate()
                .map(|(index, page)| {
                    Ok(AirflowPayload::recording(
                        AirflowOperation::ListTaskInstances,
                        page.offset.max(index.saturating_mul(page.limit.max(1))),
                        page.limit.max(1),
                        page,
                    ))
                })
                .collect(),
            task_instances,
        }
    }

    pub fn recording(dag_run: AirflowDagRunRecord, page: AirflowTaskInstancePage) -> Self {
        Self::new(TransportProvenance::Recording, dag_run, [page])
    }

    pub fn recording_with_pages(
        dag_run: AirflowDagRunRecord,
        pages: impl IntoIterator<Item = AirflowTaskInstancePage>,
    ) -> Self {
        Self::new(TransportProvenance::Recording, dag_run, pages)
    }

    pub fn fixture(dag_run: AirflowDagRunRecord, page: AirflowTaskInstancePage) -> Self {
        Self::new(TransportProvenance::Fixture, dag_run, [page])
    }

    pub fn fake(dag_run: AirflowDagRunRecord, page: AirflowTaskInstancePage) -> Self {
        Self::new(TransportProvenance::Fake, dag_run, [page])
    }

    pub fn loopback(dag_run: AirflowDagRunRecord, page: AirflowTaskInstancePage) -> Self {
        Self::new(TransportProvenance::Loopback, dag_run, [page])
    }

    pub fn blocked_env() -> BlockedEnvAirflowTransport {
        BlockedEnvAirflowTransport
    }

    pub fn with_http_error(provenance: TransportProvenance, status: u16) -> Self {
        Self {
            provenance,
            dag_runs: VecDeque::from([Err(AirflowTransportError::HttpStatus {
                status,
                retry_after_seconds: None,
            })]),
            task_pages: VecDeque::new(),
            task_instances: VecDeque::new(),
        }
    }

    pub fn with_transport_error(
        provenance: TransportProvenance,
        error: AirflowTransportError,
    ) -> Self {
        Self {
            provenance,
            dag_runs: VecDeque::from([Err(error)]),
            task_pages: VecDeque::new(),
            task_instances: VecDeque::new(),
        }
    }

    pub fn push_dag_run(
        &mut self,
        payload: std::result::Result<AirflowPayload<AirflowDagRunRecord>, AirflowTransportError>,
    ) {
        self.dag_runs.push_back(payload);
    }

    pub fn push_task_page(
        &mut self,
        payload: std::result::Result<
            AirflowPayload<AirflowTaskInstancePage>,
            AirflowTransportError,
        >,
    ) {
        self.task_pages.push_back(payload);
    }

    pub fn push_task_instance(
        &mut self,
        payload: std::result::Result<
            AirflowPayload<AirflowTaskInstanceRecord>,
            AirflowTransportError,
        >,
    ) {
        self.task_instances.push_back(payload);
    }
}

impl AirflowTransport for RecordingAirflowTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn get_dag_run(
        &mut self,
        request: &AirflowReadRequest,
    ) -> std::result::Result<AirflowPayload<AirflowDagRunRecord>, AirflowTransportError> {
        if request.operation != AirflowOperation::GetDagRun {
            return Err(AirflowTransportError::UnexpectedOperation);
        }
        self.dag_runs
            .pop_front()
            .unwrap_or(Err(AirflowTransportError::RecordingExhausted))
    }

    fn list_task_instances(
        &mut self,
        request: &AirflowReadRequest,
    ) -> std::result::Result<AirflowPayload<AirflowTaskInstancePage>, AirflowTransportError> {
        if request.operation != AirflowOperation::ListTaskInstances {
            return Err(AirflowTransportError::UnexpectedOperation);
        }
        self.task_pages
            .pop_front()
            .unwrap_or(Err(AirflowTransportError::RecordingExhausted))
    }

    fn get_task_instance(
        &mut self,
        request: &AirflowReadRequest,
    ) -> std::result::Result<AirflowPayload<AirflowTaskInstanceRecord>, AirflowTransportError> {
        if request.operation != AirflowOperation::GetTaskInstance {
            return Err(AirflowTransportError::UnexpectedOperation);
        }
        self.task_instances
            .pop_front()
            .unwrap_or(Err(AirflowTransportError::RecordingExhausted))
    }
}

pub type AirflowFakeTransport = RecordingAirflowTransport;
pub type AirflowFixtureTransport = RecordingAirflowTransport;
pub type AirflowLoopbackTransport = RecordingAirflowTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvAirflowTransport;

impl AirflowTransport for BlockedEnvAirflowTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_dag_run(
        &mut self,
        _request: &AirflowReadRequest,
    ) -> std::result::Result<AirflowPayload<AirflowDagRunRecord>, AirflowTransportError> {
        Err(AirflowTransportError::BlockedEnv)
    }

    fn list_task_instances(
        &mut self,
        _request: &AirflowReadRequest,
    ) -> std::result::Result<AirflowPayload<AirflowTaskInstancePage>, AirflowTransportError> {
        Err(AirflowTransportError::BlockedEnv)
    }

    fn get_task_instance(
        &mut self,
        _request: &AirflowReadRequest,
    ) -> std::result::Result<AirflowPayload<AirflowTaskInstanceRecord>, AirflowTransportError> {
        Err(AirflowTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowRunEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope: AirflowScope,
    pub registration_digest: Digest,
    pub request: AirflowReadRequest,
    pub dag_run: AirflowDagRunRecord,
    pub task_instances: Vec<AirflowTaskInstanceRecord>,
    pub materializations: Vec<AirflowMaterializationMetadata>,
    pub page_digests: Vec<Digest>,
    pub materialization_digest: Digest,
    pub pages_read: usize,
    pub total_task_instances: usize,
    pub complete: bool,
    pub projection: AirflowRunProjection,
    pub request_audit: AirflowRequestAudit,
    pub redaction: RedactionEvidence,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowFailureEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub projection: AirflowRunProjection,
    pub http_status: Option<u16>,
    pub error_digest: Digest,
    pub redaction: RedactionEvidence,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct FailureEvidenceDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    projection: AirflowRunProjection,
    http_status: Option<u16>,
    error_digest: &'a Digest,
    redaction: &'a RedactionEvidence,
    provenance: &'a EvidenceProvenance,
}

impl AirflowFailureEvidence {
    fn from_error(
        scope: &AirflowScope,
        registration: &AirflowRegistration,
        error: &AirflowError,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope_digest: scope.scope_digest(),
            registration_digest: registration.registration_digest.clone(),
            projection: error.projection(),
            http_status: error.status(),
            error_digest: Digest::from_text(error.to_string()),
            redaction: RedactionEvidence::standard(),
            provenance: EvidenceProvenance::from_transport(provenance),
            evidence_digest: Digest::from_text("uncomputed"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&FailureEvidenceDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            projection: self.projection,
            http_status: self.http_status,
            error_digest: &self.error_digest,
            redaction: &self.redaction,
            provenance: &self.provenance,
        })
    }

    pub fn validate(&self, scope: &AirflowScope, registration: &AirflowRegistration) -> Result<()> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != registration.registration_digest
            || !self.error_digest.is_valid()
            || !self.evidence_digest.is_valid()
            || self.projection == AirflowRunProjection::Success
            || self.redaction.validate().is_err()
            || self.provenance.validate().is_err()
            || self.evidence_digest != self.compute_digest()
        {
            return Err(AirflowError::EvidenceTampered);
        }
        Ok(())
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AirflowReadOutcome {
    Evidence(AirflowRunEvidence),
    Failure(AirflowFailureEvidence),
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope: &'a AirflowScope,
    registration_digest: &'a Digest,
    request: &'a AirflowReadRequest,
    dag_run: &'a AirflowDagRunRecord,
    task_instances: &'a [AirflowTaskInstanceRecord],
    materializations: &'a [AirflowMaterializationMetadata],
    page_digests: &'a [Digest],
    materialization_digest: &'a Digest,
    pages_read: usize,
    total_task_instances: usize,
    complete: bool,
    projection: AirflowRunProjection,
    request_audit: &'a AirflowRequestAudit,
    redaction: &'a RedactionEvidence,
    provenance: &'a EvidenceProvenance,
}

impl AirflowRunEvidence {
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        scope: &AirflowScope,
        registration: &AirflowRegistration,
        request: AirflowReadRequest,
        dag_run: AirflowDagRunRecord,
        task_instances: Vec<AirflowTaskInstanceRecord>,
        page_digests: Vec<Digest>,
        pages_read: usize,
        total_task_instances: usize,
        complete: bool,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        dag_run.validate_for_scope(scope)?;
        let materializations: Vec<AirflowMaterializationMetadata> = task_instances
            .iter()
            .map(AirflowTaskInstanceRecord::materialization_metadata)
            .collect();
        let materialization_digest = Digest::from_serializable(&materializations);
        let request_audit = AirflowRequestAudit::for_scope(scope, &request);
        let redaction = RedactionEvidence::standard();
        let provenance = EvidenceProvenance::from_transport(provenance);
        let projection = derive_projection(dag_run.state, &task_instances, complete);
        let mut evidence = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope: scope.clone(),
            registration_digest: registration.registration_digest.clone(),
            request,
            dag_run,
            task_instances,
            materializations,
            page_digests,
            materialization_digest,
            pages_read,
            total_task_instances,
            complete,
            projection,
            request_audit,
            redaction,
            provenance,
            evidence_digest: Digest::from_text("uncomputed"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence.validate(scope, registration, &ReadLimits::default())?;
        Ok(evidence)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&EvidenceDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            scope: &self.scope,
            registration_digest: &self.registration_digest,
            request: &self.request,
            dag_run: &self.dag_run,
            task_instances: &self.task_instances,
            materializations: &self.materializations,
            page_digests: &self.page_digests,
            materialization_digest: &self.materialization_digest,
            pages_read: self.pages_read,
            total_task_instances: self.total_task_instances,
            complete: self.complete,
            projection: self.projection,
            request_audit: &self.request_audit,
            redaction: &self.redaction,
            provenance: &self.provenance,
        })
    }

    pub fn validate(
        &self,
        scope: &AirflowScope,
        registration: &AirflowRegistration,
        limits: &ReadLimits,
    ) -> Result<()> {
        scope.validate()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope != *scope
            || self.registration_digest != registration.registration_digest
        {
            return Err(AirflowError::MissionScopeMismatch);
        }
        self.request.validate_for_scope(scope, limits)?;
        self.request_audit.validate(scope, &self.request)?;
        self.dag_run.validate_for_scope(scope)?;
        if self.pages_read == 0
            || self.pages_read > limits.max_pages
            || self.page_digests.len() != self.pages_read
            || self.total_task_instances > limits.max_task_instances
            || self.task_instances.len() > limits.max_task_instances
            || self.task_instances.len() != self.total_task_instances
        {
            return Err(AirflowError::EvidenceTooLarge);
        }
        for digest in &self.page_digests {
            if !digest.is_valid() {
                return Err(AirflowError::EvidenceTampered);
            }
        }
        for task in &self.task_instances {
            task.validate_for_scope(scope)?;
        }
        if self.materializations.len() != self.task_instances.len() {
            return Err(AirflowError::EvidenceTampered);
        }
        for (task, materialization) in self.task_instances.iter().zip(&self.materializations) {
            materialization.validate()?;
            if materialization != &task.materialization_metadata() {
                return Err(AirflowError::EvidenceTampered);
            }
        }
        if serde_json::to_vec(&self.materializations)
            .map_err(|_| AirflowError::EvidenceTampered)?
            .len()
            > limits.max_metadata_bytes
        {
            return Err(AirflowError::EvidenceTooLarge);
        }
        if self.materialization_digest != Digest::from_serializable(&self.materializations) {
            return Err(AirflowError::EvidenceTampered);
        }
        if !self.complete && self.projection != AirflowRunProjection::Partial {
            return Err(AirflowError::EvidenceTampered);
        }
        if self.complete && self.projection == AirflowRunProjection::Partial {
            return Err(AirflowError::EvidenceTampered);
        }
        if self.projection
            != derive_projection(self.dag_run.state, &self.task_instances, self.complete)
        {
            return Err(AirflowError::EvidenceTampered);
        }
        self.redaction.validate()?;
        self.provenance.validate()?;
        if self.evidence_digest != self.compute_digest() {
            return Err(AirflowError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn is_review_only(&self) -> bool {
        true
    }
}

fn derive_projection(
    dag_run_state: AirflowState,
    task_instances: &[AirflowTaskInstanceRecord],
    complete: bool,
) -> AirflowRunProjection {
    if !complete || task_instances.is_empty() {
        return AirflowRunProjection::Partial;
    }
    if task_instances
        .iter()
        .any(|task| task.state == AirflowState::Failed)
    {
        return AirflowRunProjection::Failed;
    }
    if task_instances
        .iter()
        .any(|task| task.state == AirflowState::UpstreamFailed)
    {
        return AirflowRunProjection::UpstreamFailed;
    }
    if task_instances
        .iter()
        .any(|task| task.state == AirflowState::Deferred)
    {
        return AirflowRunProjection::Deferred;
    }
    if task_instances
        .iter()
        .any(|task| task.state == AirflowState::Running)
    {
        return AirflowRunProjection::Running;
    }
    if task_instances
        .iter()
        .any(|task| task.state == AirflowState::Queued)
    {
        return AirflowRunProjection::Queued;
    }
    if task_instances
        .iter()
        .all(|task| task.state == AirflowState::Skipped)
    {
        return AirflowRunProjection::Skipped;
    }
    match dag_run_state {
        AirflowState::Queued => AirflowRunProjection::Queued,
        AirflowState::Running => AirflowRunProjection::Running,
        AirflowState::Success => AirflowRunProjection::Success,
        AirflowState::Failed => AirflowRunProjection::Failed,
        AirflowState::UpstreamFailed => AirflowRunProjection::UpstreamFailed,
        AirflowState::Skipped => AirflowRunProjection::Skipped,
        AirflowState::Deferred => AirflowRunProjection::Deferred,
    }
}

#[derive(Clone, Debug)]
pub struct AirflowProvider<T> {
    scope: AirflowScope,
    secret_reference: SecretReference,
    registration: AirflowRegistration,
    transport: T,
    limits: ReadLimits,
}

impl<T: AirflowTransport> AirflowProvider<T> {
    pub fn new(
        scope: AirflowScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self> {
        let registration = AirflowRegistration::new(&scope, &secret_reference)?;
        Self::with_registration(scope, registration, secret_reference, transport)
    }

    pub fn with_registration(
        scope: AirflowScope,
        registration: AirflowRegistration,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self> {
        registration.validate_binding(&scope, &secret_reference)?;
        Ok(Self {
            scope,
            secret_reference,
            registration,
            transport,
            limits: ReadLimits::default(),
        })
    }

    pub fn with_limits(mut self, limits: ReadLimits) -> Result<Self> {
        self.limits = limits.validate()?;
        Ok(self)
    }

    pub fn scope(&self) -> &AirflowScope {
        &self.scope
    }

    pub fn registration(&self) -> &AirflowRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AirflowRegistration {
        &mut self.registration
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
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

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn connected(&self) -> bool {
        self.provenance().connected()
    }

    pub fn native(&self) -> bool {
        self.provenance().native()
    }

    pub fn first_party(&self) -> bool {
        self.provenance().first_party()
    }

    pub fn describe_host(&self) -> Result<AirflowHostDescription> {
        self.ensure_active()?;
        Ok(AirflowHostDescription::for_scope(&self.scope))
    }

    pub fn describe_tenant(&self) -> Result<AirflowTenantDescription> {
        self.ensure_active()?;
        Ok(AirflowTenantDescription::for_scope(&self.scope))
    }

    pub fn describe_dag(&self) -> Result<AirflowDagDescription> {
        self.ensure_active()?;
        Ok(AirflowDagDescription::for_scope(&self.scope))
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.unmount()
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.remount()
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt> {
        self.registration.revoke(&mut self.secret_reference)
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn read_dag_run(
        &mut self,
        request: &AirflowReadRequest,
    ) -> Result<AirflowPayload<AirflowDagRunRecord>> {
        self.ensure_active()?;
        if request.operation != AirflowOperation::GetDagRun {
            return Err(AirflowError::UnexpectedResponse);
        }
        request.validate_for_scope(&self.scope, &self.limits)?;
        let payload = self
            .transport
            .get_dag_run(request)
            .map_err(|error| AirflowError::from_transport(&error))?;
        payload.verify(request, &self.limits)?;
        payload.value.validate_for_scope(&self.scope)?;
        Ok(payload)
    }

    pub fn read_task_instances(
        &mut self,
        request: &AirflowReadRequest,
    ) -> Result<AirflowPayload<AirflowTaskInstancePage>> {
        self.ensure_active()?;
        if request.operation != AirflowOperation::ListTaskInstances {
            return Err(AirflowError::UnexpectedResponse);
        }
        request.validate_for_scope(&self.scope, &self.limits)?;
        let payload = self
            .transport
            .list_task_instances(request)
            .map_err(|error| AirflowError::from_transport(&error))?;
        payload.verify(request, &self.limits)?;
        validate_task_page(&payload.value, request, &self.limits)?;
        Ok(payload)
    }

    pub fn read_task_instance(
        &mut self,
        request: &AirflowReadRequest,
    ) -> Result<AirflowPayload<AirflowTaskInstanceRecord>> {
        self.ensure_active()?;
        if request.operation != AirflowOperation::GetTaskInstance {
            return Err(AirflowError::UnexpectedResponse);
        }
        request.validate_for_scope(&self.scope, &self.limits)?;
        let payload = self
            .transport
            .get_task_instance(request)
            .map_err(|error| AirflowError::from_transport(&error))?;
        payload.verify(request, &self.limits)?;
        payload.value.validate_for_scope(&self.scope)?;
        Ok(payload)
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_evidence(&mut self, request: AirflowReadRequest) -> Result<AirflowRunEvidence> {
        self.ensure_active()?;
        request.validate_for_scope(&self.scope, &self.limits)?;

        let dag_request = AirflowReadRequest {
            operation: AirflowOperation::GetDagRun,
            offset: 0,
            limit: 1,
            logical_date_gte: request.logical_date_gte.clone(),
            logical_date_lte: request.logical_date_lte.clone(),
            states: request.states.clone(),
        };
        let dag_run = self.read_dag_run(&dag_request)?.value;
        let mut page_digests = Vec::new();
        let mut task_instances = Vec::new();
        let mut pages_read = 0;
        let complete = match request.operation {
            AirflowOperation::GetTaskInstance => {
                let payload = self.read_task_instance(&request)?;
                page_digests.push(payload.response_digest);
                pages_read = 1;
                task_instances.push(payload.value);
                !payload.partial
            }
            AirflowOperation::ListTaskInstances => {
                let mut current_offset = request.offset;
                let mut last_key: Option<(String, i32)> = None;
                let mut seen_target = BTreeSet::new();
                loop {
                    if pages_read >= self.limits.max_pages {
                        return Err(AirflowError::PaginationLimit);
                    }
                    let page_request = AirflowReadRequest {
                        operation: AirflowOperation::ListTaskInstances,
                        offset: current_offset,
                        limit: request.limit,
                        logical_date_gte: request.logical_date_gte.clone(),
                        logical_date_lte: request.logical_date_lte.clone(),
                        states: request.states.clone(),
                    };
                    let payload = self.read_task_instances(&page_request)?;
                    let page = payload.value;
                    pages_read += 1;
                    page_digests.push(payload.response_digest);
                    let item_count = page.items.len();
                    let page_limit = page.limit;
                    let page_total_entries = page.total_entries;
                    let page_partial = page.partial;
                    for task in page.items {
                        validate_task_for_run_scope(&task, &self.scope)?;
                        if !request.states.is_empty() && !request.states.contains(&task.state) {
                            return Err(AirflowError::PaginationDrift);
                        }
                        let key = (task.task.task_id.clone(), task.map_index);
                        if let Some(previous) = &last_key
                            && key < *previous
                        {
                            return Err(AirflowError::PaginationDrift);
                        }
                        last_key = Some(key);
                        if task.task == self.scope.task {
                            let fingerprint = task.metadata_digest();
                            if !seen_target.insert(fingerprint) {
                                return Err(AirflowError::DuplicateEvidence);
                            }
                            task_instances.push(task);
                        }
                    }
                    if page_partial {
                        break false;
                    }
                    let next_offset = current_offset
                        .checked_add(item_count)
                        .ok_or(AirflowError::PaginationLimit)?;
                    if next_offset >= page_total_entries {
                        break !task_instances.is_empty();
                    }
                    if item_count == 0 || next_offset <= current_offset {
                        return Err(AirflowError::PaginationDrift);
                    }
                    if item_count < page_limit {
                        return Err(AirflowError::PaginationDrift);
                    }
                    current_offset = next_offset;
                }
            }
            AirflowOperation::GetDagRun => {
                return Err(AirflowError::InvalidInput(
                    "evidence requires task-instance read",
                ));
            }
        };
        if task_instances.len() > self.limits.max_task_instances {
            return Err(AirflowError::EvidenceTooLarge);
        }
        let total_task_instances = task_instances.len();
        AirflowRunEvidence::from_parts(
            &self.scope,
            &self.registration,
            request,
            dag_run,
            task_instances,
            page_digests,
            pages_read,
            total_task_instances,
            complete,
            self.provenance(),
        )
    }

    pub fn read_evidence_projected(&mut self, request: AirflowReadRequest) -> AirflowReadOutcome {
        match self.read_evidence(request) {
            Ok(evidence) => AirflowReadOutcome::Evidence(evidence),
            Err(error) => AirflowReadOutcome::Failure(AirflowFailureEvidence::from_error(
                &self.scope,
                &self.registration,
                &error,
                self.provenance(),
            )),
        }
    }

    fn ensure_active(&self) -> Result<()> {
        self.scope.validate()?;
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)?;
        match self.registration.status {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Unmounted => Err(AirflowError::RegistrationInactive),
            RegistrationStatus::Revoked | RegistrationStatus::Reversed => {
                Err(AirflowError::RegistrationRevoked)
            }
        }
    }
}

fn validate_task_page(
    page: &AirflowTaskInstancePage,
    request: &AirflowReadRequest,
    limits: &ReadLimits,
) -> Result<()> {
    if page.items.len() > limits.max_page_items
        || page.items.len() > page.limit
        || page.total_entries > limits.max_task_instances
        || page.offset != request.offset
        || page.limit != request.limit
        || (page.total_entries > 0 && page.offset >= page.total_entries)
    {
        return Err(AirflowError::PageTooLarge);
    }
    Ok(())
}

fn validate_task_for_run_scope(
    task: &AirflowTaskInstanceRecord,
    scope: &AirflowScope,
) -> Result<()> {
    task.validate()?;
    if task.dag != scope.dag {
        return Err(AirflowError::DagMismatch);
    }
    if task.run != scope.run {
        return Err(AirflowError::RunMismatch);
    }
    if task.logical_date != scope.logical_date {
        return Err(AirflowError::LogicalDateMismatch);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AirflowAdoptionDisposition {
    Layer2Required,
    BlockedByProjection,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowRunResultProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub run_id: String,
    pub mission: MissionScopeBinding,
    pub evidence_digest: Digest,
    pub materialization_digest: Digest,
    pub projection: AirflowRunProjection,
    pub disposition: AirflowAdoptionDisposition,
    pub kernel_authority: bool,
    pub provider_receipt: bool,
    pub work_product_adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ProposalDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope_digest: &'a Digest,
    registration_digest: &'a Digest,
    run_id: &'a str,
    mission: &'a MissionScopeBinding,
    evidence_digest: &'a Digest,
    materialization_digest: &'a Digest,
    projection: AirflowRunProjection,
    disposition: AirflowAdoptionDisposition,
    kernel_authority: bool,
    provider_receipt: bool,
    work_product_adopted: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AirflowRunResultProposal {
    fn from_evidence(evidence: &AirflowRunEvidence) -> Self {
        let disposition = if matches!(
            evidence.projection,
            AirflowRunProjection::Success
                | AirflowRunProjection::Failed
                | AirflowRunProjection::UpstreamFailed
                | AirflowRunProjection::Skipped
        ) && evidence.complete
        {
            AirflowAdoptionDisposition::Layer2Required
        } else {
            AirflowAdoptionDisposition::BlockedByProjection
        };
        let mut proposal = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope_digest: evidence.scope.scope_digest(),
            registration_digest: evidence.registration_digest.clone(),
            run_id: evidence.scope.run.run_id.clone(),
            mission: evidence.scope.mission.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            materialization_digest: evidence.materialization_digest.clone(),
            projection: evidence.projection,
            disposition,
            kernel_authority: false,
            provider_receipt: false,
            work_product_adopted: false,
            connected: false,
            native: false,
            first_party: false,
            proposal_digest: Digest::from_text("uncomputed"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&ProposalDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            scope_digest: &self.scope_digest,
            registration_digest: &self.registration_digest,
            run_id: &self.run_id,
            mission: &self.mission,
            evidence_digest: &self.evidence_digest,
            materialization_digest: &self.materialization_digest,
            projection: self.projection,
            disposition: self.disposition,
            kernel_authority: self.kernel_authority,
            provider_receipt: self.provider_receipt,
            work_product_adopted: self.work_product_adopted,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }

    pub fn validate_integrity(
        &self,
        scope: &AirflowScope,
        registration: &AirflowRegistration,
    ) -> Result<()> {
        self.validate_for_scope(scope, &registration.registration_digest)
    }

    pub fn validate_for_scope(
        &self,
        scope: &AirflowScope,
        registration_digest: &Digest,
    ) -> Result<()> {
        scope.validate()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest()
            || self.registration_digest != *registration_digest
            || self.run_id != scope.run.run_id
            || self.mission != scope.mission
            || !self.evidence_digest.is_valid()
            || !self.materialization_digest.is_valid()
            || self.kernel_authority
            || self.provider_receipt
            || self.work_product_adopted
            || self.connected
            || self.native
            || self.first_party
            || self.proposal_digest != self.compute_digest()
        {
            return Err(AirflowError::ProposalTampered);
        }
        Ok(())
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

pub type Result<T> = std::result::Result<T, AirflowError>;
pub const SCHEMA_VERSION: &str = CONTRACT_SCHEMA;
pub const PROVIDER_VERSION: Version = PLUGIN_VERSION;

pub const NATIVE_GAP: &str = "BLOCKED_ENV: native bearer/OIDC resolution, live bounded HTTPS GET reads, durable provider receipts, independent read-back, and verified Work Product adoption remain Layer 2 gaps";

/// Compile-time authority marker used by audits and adversarial tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn external_writes() -> bool {
        false
    }

    pub const fn trigger_dag() -> bool {
        false
    }

    pub const fn clear_task_instance() -> bool {
        false
    }

    pub const fn retry_task_instance() -> bool {
        false
    }

    pub const fn read_variables() -> bool {
        false
    }

    pub const fn read_connections() -> bool {
        false
    }

    pub const fn raw_logs() -> bool {
        false
    }

    pub const fn raw_xcom() -> bool {
        false
    }

    pub const fn scheduler_authority() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn provider_receipt() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }

    pub const fn native_connected() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

fn validate_revision(revision: u64) -> Result<()> {
    if revision == 0 {
        Err(AirflowError::InvalidInput("revision"))
    } else {
        Ok(())
    }
}

fn validate_origin(origin: &str) -> Result<()> {
    if origin.len() > MAX_IDENTIFIER_BYTES
        || !(origin.starts_with("https://") || origin.starts_with("http://"))
        || origin
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || origin.ends_with('/')
    {
        return Err(AirflowError::InvalidInput("host origin"));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'?' | b':' | b'#'))
    {
        return Err(AirflowError::InvalidInput(field));
    }
    Ok(())
}

fn validate_timestamp(value: &str) -> Result<()> {
    if value.len() > MAX_TIMESTAMP_BYTES || value.len() < 20 {
        return Err(AirflowError::InvalidInput("timestamp"));
    }
    let bytes = value.as_bytes();
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|(index, expected)| bytes.get(*index) != Some(expected))
        || (0..4).any(|index| !bytes[index].is_ascii_digit())
        || (5..7).any(|index| !bytes[index].is_ascii_digit())
        || (8..10).any(|index| !bytes[index].is_ascii_digit())
        || (11..13).any(|index| !bytes[index].is_ascii_digit())
        || (14..16).any(|index| !bytes[index].is_ascii_digit())
        || (17..19).any(|index| !bytes[index].is_ascii_digit())
    {
        return Err(AirflowError::InvalidInput("timestamp"));
    }
    let suffix = &value[19..];
    if !(suffix == "Z"
        || (suffix.len() >= 6
            && matches!(suffix.as_bytes().first(), Some(b'+' | b'-'))
            && suffix.as_bytes().get(3) == Some(&b':')
            && suffix[1..3].bytes().all(|byte| byte.is_ascii_digit())
            && suffix[4..6].bytes().all(|byte| byte.is_ascii_digit())))
    {
        return Err(AirflowError::InvalidInput("timestamp timezone"));
    }
    Ok(())
}

pub type AirflowRunProposal = AirflowRunResultProposal;

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowVerificationProjection {
    pub schema_version: String,
    pub run_id: String,
    pub projection: AirflowRunProjection,
    pub evidence_digest: Digest,
    pub materialization_digest: Digest,
    pub registration_digest: Digest,
    pub bounded_evidence_verified: bool,
    pub adoption: AirflowAdoptionDisposition,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AirflowVerificationProjection {
    fn from_evidence(evidence: &AirflowRunEvidence) -> Self {
        let bounded_evidence_verified = evidence.complete
            && matches!(
                evidence.projection,
                AirflowRunProjection::Success
                    | AirflowRunProjection::Failed
                    | AirflowRunProjection::UpstreamFailed
                    | AirflowRunProjection::Skipped
            );
        Self {
            schema_version: CONTRACT_SCHEMA.into(),
            run_id: evidence.scope.run.run_id.clone(),
            projection: evidence.projection,
            evidence_digest: evidence.evidence_digest.clone(),
            materialization_digest: evidence.materialization_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            bounded_evidence_verified,
            adoption: if bounded_evidence_verified {
                AirflowAdoptionDisposition::Layer2Required
            } else {
                AirflowAdoptionDisposition::BlockedByProjection
            },
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub const fn verified(&self) -> bool {
        self.bounded_evidence_verified
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AirflowServiceDefinition {
    pub schema_version: &'static str,
    pub contract_version: &'static str,
    pub service_id: &'static str,
    pub provider_id: &'static str,
    pub consumer_id: &'static str,
    pub layer: u8,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub operations: Vec<AirflowOperation>,
    pub forbidden_effects: Vec<&'static str>,
    pub allowed_provenance: Vec<TransportProvenance>,
}

impl AirflowServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA,
            contract_version: CONTRACT_VERSION,
            service_id: SERVICE_ID,
            provider_id: PROVIDER_ID,
            consumer_id: CONSUMER_ID,
            layer: 1,
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            operations: vec![
                AirflowOperation::GetDagRun,
                AirflowOperation::ListTaskInstances,
                AirflowOperation::GetTaskInstance,
            ],
            forbidden_effects: vec![
                "trigger_dag",
                "clear_task_instance",
                "retry_task_instance",
                "read_variables",
                "read_connections",
                "read_raw_logs",
                "read_xcom",
                "control_scheduler",
                "control_ui",
                "resolve_native_secret",
                "retain_raw_payload",
                "retain_unbounded_tasks",
                "adopt_kernel_truth",
                "adopt_work_product",
            ],
            allowed_provenance: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fixture,
                TransportProvenance::Fake,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.layer != 1
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(AirflowError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AirflowDagResultService<T> {
    provider: AirflowProvider<T>,
    recordings: BTreeMap<String, Digest>,
    observed_status: BTreeMap<String, AirflowRunProjection>,
}

impl<T: AirflowTransport> AirflowDagResultService<T> {
    pub fn new(provider: AirflowProvider<T>) -> Result<Self> {
        provider.scope.validate()?;
        Ok(Self {
            provider,
            recordings: BTreeMap::new(),
            observed_status: BTreeMap::new(),
        })
    }

    pub fn from_transport(
        scope: AirflowScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self> {
        Self::new(AirflowProvider::new(scope, secret_reference, transport)?)
    }

    pub fn definition() -> AirflowServiceDefinition {
        AirflowServiceDefinition::layer1()
    }

    pub fn scope(&self) -> &AirflowScope {
        self.provider.scope()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.provider.secret_reference()
    }

    pub fn registration(&self) -> &AirflowRegistration {
        self.provider.registration()
    }

    pub fn provider(&self) -> &AirflowProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AirflowProvider<T> {
        &mut self.provider
    }

    pub fn describe_host(&self) -> Result<AirflowHostDescription> {
        self.provider.describe_host()
    }

    pub fn describe_tenant(&self) -> Result<AirflowTenantDescription> {
        self.provider.describe_tenant()
    }

    pub fn describe_dag(&self) -> Result<AirflowDagDescription> {
        self.provider.describe_dag()
    }

    pub fn read_run_evidence(&mut self, request: AirflowReadRequest) -> Result<AirflowRunEvidence> {
        self.read_evidence(request)
    }

    pub fn read_evidence(&mut self, request: AirflowReadRequest) -> Result<AirflowRunEvidence> {
        let evidence = self.provider.read_evidence(request)?;
        let run_id = evidence.scope.run.run_id.clone();
        if let Some(previous) = self.observed_status.get(&run_id)
            && !previous.can_follow(evidence.projection)
        {
            return Err(AirflowError::InvalidStateTransition);
        }
        self.observed_status.insert(run_id, evidence.projection);
        Ok(evidence)
    }

    pub fn read_evidence_projected(&mut self, request: AirflowReadRequest) -> AirflowReadOutcome {
        self.provider.read_evidence_projected(request)
    }

    /// Record only an in-memory evidence fingerprint. This is not a durable
    /// provider receipt and carries no provider payload.
    pub fn record_run_evidence(
        &mut self,
        evidence: &AirflowRunEvidence,
    ) -> Result<AirflowEvidenceRecording> {
        self.validate_evidence(evidence)?;
        let run_id = evidence.scope.run.run_id.clone();
        if let Some(existing) = self.recordings.get(&run_id) {
            if existing != &evidence.evidence_digest {
                return Err(AirflowError::DuplicateEvidence);
            }
            return Ok(AirflowEvidenceRecording {
                run_id,
                evidence_digest: evidence.evidence_digest.clone(),
                replayed: true,
            });
        }
        self.recordings
            .insert(run_id.clone(), evidence.evidence_digest.clone());
        Ok(AirflowEvidenceRecording {
            run_id,
            evidence_digest: evidence.evidence_digest.clone(),
            replayed: false,
        })
    }

    pub fn compile_run_result_proposal(
        &self,
        evidence: &AirflowRunEvidence,
    ) -> Result<AirflowRunResultProposal> {
        self.validate_evidence(evidence)?;
        Ok(AirflowRunResultProposal::from_evidence(evidence))
    }

    pub fn compile_run_proposal(
        &self,
        evidence: &AirflowRunEvidence,
    ) -> Result<AirflowRunResultProposal> {
        self.compile_run_result_proposal(evidence)
    }

    pub fn verify_run_evidence(
        &self,
        evidence: &AirflowRunEvidence,
    ) -> Result<AirflowVerificationProjection> {
        self.validate_evidence(evidence)?;
        Ok(AirflowVerificationProjection::from_evidence(evidence))
    }

    pub fn verify_run_result(
        &self,
        evidence: &AirflowRunEvidence,
    ) -> Result<AirflowVerificationProjection> {
        self.verify_run_evidence(evidence)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AirflowRunResultProposal,
        evidence: &AirflowRunEvidence,
    ) -> Result<AirflowVerificationProjection> {
        self.validate_evidence(evidence)?;
        proposal.validate_integrity(self.scope(), self.registration())?;
        if proposal.evidence_digest != evidence.evidence_digest
            || proposal.materialization_digest != evidence.materialization_digest
        {
            return Err(AirflowError::ProposalTampered);
        }
        Ok(AirflowVerificationProjection::from_evidence(evidence))
    }

    pub fn projection_for_error(&self, error: &AirflowError) -> AirflowRunProjection {
        error.projection()
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.provider.unmount()
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.provider.remount()
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt> {
        self.provider.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.provider.reverse()
    }

    fn validate_evidence(&self, evidence: &AirflowRunEvidence) -> Result<()> {
        self.provider
            .registration
            .validate_binding(&self.provider.scope, &self.provider.secret_reference)?;
        if !self.provider.registration.is_active() {
            return Err(AirflowError::RegistrationInactive);
        }
        evidence.validate(
            &self.provider.scope,
            &self.provider.registration,
            &self.provider.limits,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AirflowEvidenceRecording {
    pub run_id: String,
    pub evidence_digest: Digest,
    pub replayed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionConsumptionDisposition {
    Fresh,
    Replay,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAirflowRun {
    pub schema_version: String,
    pub scope_digest: Digest,
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub dag_id: String,
    pub run_id: String,
    pub task_id: String,
    pub logical_date: String,
    pub projection: AirflowRunProjection,
    pub proposal_digest: Digest,
    pub disposition: MissionConsumptionDisposition,
    pub adopted: bool,
    pub kernel_authority: bool,
    pub work_product_adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub struct MissionAirflowRunConsumer {
    binding: MissionScopeBinding,
    scope_digest: Digest,
    registration_digest: Digest,
    dag_id: String,
    run_id: String,
    task_id: String,
    logical_date: String,
    consumed: BTreeMap<String, Digest>,
    active: bool,
}

impl fmt::Debug for MissionAirflowRunConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAirflowRunConsumer")
            .field("scope_digest", &self.scope_digest)
            .field("registration_digest", &self.registration_digest)
            .field("binding", &self.binding)
            .field("consumed_count", &self.consumed.len())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl MissionAirflowRunConsumer {
    pub fn new(scope: &AirflowScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            binding: scope.mission.clone(),
            scope_digest: scope.scope_digest(),
            registration_digest: Digest::from_text("unbound-registration"),
            dag_id: scope.dag.dag_id.clone(),
            run_id: scope.run.run_id.clone(),
            task_id: scope.task.task_id.clone(),
            logical_date: scope.logical_date.value.clone(),
            consumed: BTreeMap::new(),
            active: true,
        })
    }

    pub fn from_registration(
        registration: &AirflowRegistration,
        scope: &AirflowScope,
    ) -> Result<Self> {
        scope.validate()?;
        if registration.compute_digest() != registration.registration_digest
            || registration.scope_digest != scope.scope_digest()
            || !registration.reversible
            || !registration.revocable
        {
            return Err(AirflowError::RegistrationTampered);
        }
        if !registration.is_active() {
            return if matches!(
                registration.status,
                RegistrationStatus::Revoked | RegistrationStatus::Reversed
            ) {
                Err(AirflowError::RegistrationRevoked)
            } else {
                Err(AirflowError::RegistrationInactive)
            };
        }
        let mut consumer = Self::new(scope)?;
        consumer.registration_digest = registration.registration_digest.clone();
        Ok(consumer)
    }

    pub fn binding(&self) -> &MissionScopeBinding {
        &self.binding
    }

    pub const fn is_active(&self) -> bool {
        self.active
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

    pub fn consume(&mut self, proposal: &AirflowRunResultProposal) -> Result<MissionAirflowRun> {
        if !self.active {
            return Err(AirflowError::ConsumerInactive);
        }
        let expected_registration = if self.registration_digest.is_valid() {
            &self.registration_digest
        } else {
            &proposal.registration_digest
        };
        proposal.validate_for_scope_view(
            &AirflowScopeForConsumer {
                scope_digest: self.scope_digest.clone(),
                mission: self.binding.clone(),
                run_id: &self.run_id,
            },
            expected_registration,
        )?;
        if !self.registration_digest.is_valid() {
            self.registration_digest = proposal.registration_digest.clone();
        }
        self.consume_validated(proposal)
    }

    pub fn consume_result(
        &mut self,
        proposal: &AirflowRunResultProposal,
    ) -> Result<MissionAirflowRun> {
        self.consume(proposal)
    }

    pub fn consume_at_revision(
        &mut self,
        proposal: &AirflowRunResultProposal,
        current_binding: &MissionScopeBinding,
    ) -> Result<MissionAirflowRun> {
        if current_binding.project_id != self.binding.project_id
            || current_binding.mission_id != self.binding.mission_id
            || current_binding.work_product_id != self.binding.work_product_id
        {
            return Err(AirflowError::MissionScopeMismatch);
        }
        if current_binding != &self.binding {
            return Err(AirflowError::StaleMissionRevision);
        }
        self.consume(proposal)
    }

    fn consume_validated(
        &mut self,
        proposal: &AirflowRunResultProposal,
    ) -> Result<MissionAirflowRun> {
        let disposition = match self.consumed.get(&proposal.run_id) {
            None => {
                self.consumed
                    .insert(proposal.run_id.clone(), proposal.proposal_digest.clone());
                MissionConsumptionDisposition::Fresh
            }
            Some(existing) if existing == &proposal.proposal_digest => {
                MissionConsumptionDisposition::Replay
            }
            Some(_) => return Err(AirflowError::DuplicateEvidence),
        };
        Ok(MissionAirflowRun {
            schema_version: CONTRACT_SCHEMA.into(),
            scope_digest: self.scope_digest.clone(),
            project_id: self.binding.project_id.clone(),
            mission_id: self.binding.mission_id.clone(),
            work_product_id: self.binding.work_product_id.clone(),
            project_revision: self.binding.project_revision,
            mission_revision: self.binding.mission_revision,
            work_product_revision: self.binding.work_product_revision,
            dag_id: self.dag_id.clone(),
            run_id: proposal.run_id.clone(),
            task_id: self.task_id.clone(),
            logical_date: self.logical_date.clone(),
            projection: proposal.projection,
            proposal_digest: proposal.proposal_digest.clone(),
            disposition,
            adopted: false,
            kernel_authority: false,
            work_product_adopted: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }
}

/// Internal scope view used to validate a proposal without giving the Mission
/// consumer any way to reconstruct or mutate provider scope authority.
struct AirflowScopeForConsumer<'a> {
    scope_digest: Digest,
    mission: MissionScopeBinding,
    run_id: &'a str,
}

impl AirflowScopeForConsumer<'_> {
    fn validate(&self) -> Result<()> {
        if !self.scope_digest.is_valid() {
            return Err(AirflowError::MissionScopeMismatch);
        }
        Ok(())
    }
}

impl AirflowRunResultProposal {
    fn validate_for_scope_view(
        &self,
        scope: &AirflowScopeForConsumer<'_>,
        registration_digest: &Digest,
    ) -> Result<()> {
        scope.validate()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope_digest != scope.scope_digest
            || self.registration_digest != *registration_digest
            || self.run_id != scope.run_id
            || self.mission != scope.mission
            || !self.evidence_digest.is_valid()
            || !self.materialization_digest.is_valid()
            || self.kernel_authority
            || self.provider_receipt
            || self.work_product_adopted
            || self.connected
            || self.native
            || self.first_party
            || self.proposal_digest != self.compute_digest()
        {
            return Err(AirflowError::ProposalTampered);
        }
        Ok(())
    }
}
