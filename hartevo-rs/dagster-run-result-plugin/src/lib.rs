#![forbid(unsafe_code)]
#![doc = "Standalone Layer-1 Dagster run-result plugin."]
//!
//! This crate is a deliberately bounded read/proposal/recording boundary. It
//! binds one Dagster deployment, repository, code location, job, run,
//! partition, asset, commit, and exact Hartevo Mission scope. It has no
//! native HTTP client, credential resolver, scheduler, worker kernel, asset
//! mutation, raw-log representation, or Outcome adoption authority.
//!
//! Recording, fake, loopback, and BLOCKED_ENV transports are deterministic
//! evidence sources. They never claim Connected, native, or first-party
//! evidence.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
};

use serde::{Deserialize, Serialize, ser::SerializeStruct};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.dagster-run-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-DAGSTER-01-L1/v1";
pub const PLUGIN_ID: &str = "dagster.run-result";
pub const PLUGIN_VERSION: Version = Version::new(1, 0, 0);
pub const SERVICE_ID: &str = "DagsterRunResultService";
pub const PROVIDER_ID: &str = "DagsterProvider";
pub const CONSUMER_ID: &str = "MissionDagsterRunConsumer";
pub const DAGSTER_GRAPHQL_ENDPOINT_PATH: &str = "/graphql";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/dagster-run-result/service.v1.json");

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_ASSET_PATH_SEGMENTS: usize = 64;
pub const MAX_ASSET_PATH_SEGMENT_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 512;
pub const MAX_PAGE_ITEMS: usize = 256;
pub const MAX_PAGES: usize = 32;
pub const MAX_EVENTS: usize = 4_096;
pub const MAX_STEP_SUMMARIES: usize = 256;
pub const MAX_MATERIALIZATIONS: usize = 512;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_EVENT_ID_BYTES: usize = 256;
pub const MAX_QUERY_VARIABLE_BYTES: usize = 4 * 1024;

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

/// A lowercase SHA-256 digest. Raw provider payloads are never represented by
/// this type; only bounded typed values are digested.
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
pub struct DagsterDeploymentIdentity {
    pub origin: String,
    pub deployment_id: String,
    pub revision: u64,
}

impl DagsterDeploymentIdentity {
    pub fn new(
        origin: impl Into<String>,
        deployment_id: impl Into<String>,
        revision: u64,
    ) -> Result<Self, DagsterError> {
        let identity = Self {
            origin: origin.into(),
            deployment_id: deployment_id.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), DagsterError> {
        validate_origin(&self.origin)?;
        validate_identifier("deployment id", &self.deployment_id)?;
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

macro_rules! define_revisioned_name {
    ($type_name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        pub struct $type_name {
            pub name: String,
            pub revision: u64,
        }

        impl $type_name {
            pub fn new(name: impl Into<String>, revision: u64) -> Result<Self, DagsterError> {
                let identity = Self {
                    name: name.into(),
                    revision,
                };
                identity.validate()?;
                Ok(identity)
            }

            fn validate(&self) -> Result<(), DagsterError> {
                validate_identifier($label, &self.name)?;
                validate_revision(self.revision)
            }

            pub fn digest(&self) -> Digest {
                Digest::from_serializable(self)
            }
        }
    };
}

define_revisioned_name!(DagsterRepositoryIdentity, "repository name");
define_revisioned_name!(DagsterCodeLocationIdentity, "code location name");
define_revisioned_name!(DagsterJobIdentity, "job name");

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterRunIdentity {
    pub run_id: String,
    pub revision: u64,
}

impl DagsterRunIdentity {
    pub fn new(run_id: impl Into<String>, revision: u64) -> Result<Self, DagsterError> {
        let identity = Self {
            run_id: run_id.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), DagsterError> {
        validate_identifier("run id", &self.run_id)?;
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterPartitionIdentity {
    pub key: String,
    pub revision: u64,
}

impl DagsterPartitionIdentity {
    pub fn new(key: impl Into<String>, revision: u64) -> Result<Self, DagsterError> {
        let identity = Self {
            key: key.into(),
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), DagsterError> {
        validate_identifier("partition key", &self.key)?;
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterAssetIdentity {
    pub path: Vec<String>,
    pub revision: u64,
}

impl DagsterAssetIdentity {
    pub fn new(
        path: impl IntoIterator<Item = String>,
        revision: u64,
    ) -> Result<Self, DagsterError> {
        let identity = Self {
            path: canonical_asset_path(path)?,
            revision,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), DagsterError> {
        if self.path.is_empty() || self.path.len() > MAX_ASSET_PATH_SEGMENTS {
            return Err(DagsterError::InvalidInput("asset path"));
        }
        for segment in &self.path {
            validate_bounded_text("asset path segment", segment, MAX_ASSET_PATH_SEGMENT_BYTES)?;
        }
        validate_revision(self.revision)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterCommitReference {
    pub sha: String,
    pub revision: u64,
}

impl DagsterCommitReference {
    pub fn new(sha: impl Into<String>, revision: u64) -> Result<Self, DagsterError> {
        let reference = Self {
            sha: sha.into(),
            revision,
        };
        reference.validate()?;
        Ok(reference)
    }

    fn validate(&self) -> Result<(), DagsterError> {
        validate_commit_sha(&self.sha)?;
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
    ) -> Result<Self, DagsterError> {
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

    fn validate(&self) -> Result<(), DagsterError> {
        validate_identifier("Project", &self.project_id)?;
        validate_identifier("Mission", &self.mission_id)?;
        validate_identifier("Work Product", &self.work_product_id)?;
        validate_revision(self.project_revision)?;
        validate_revision(self.mission_revision)?;
        validate_revision(self.work_product_revision)?;
        if !self.policy_digest.is_valid() || !self.consent_digest.is_valid() {
            return Err(DagsterError::InvalidDigest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DagsterPermission {
    DeploymentRead,
    RepositoryRead,
    CodeLocationRead,
    JobRead,
    RunRead,
    EventRead,
    AssetRead,
    PartitionRead,
    CommitRead,
    MissionScope,
}

impl DagsterPermission {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentRead => "deployment:read",
            Self::RepositoryRead => "repository:read",
            Self::CodeLocationRead => "code-location:read",
            Self::JobRead => "job:read",
            Self::RunRead => "run:read",
            Self::EventRead => "event:read",
            Self::AssetRead => "asset:read",
            Self::PartitionRead => "partition:read",
            Self::CommitRead => "commit:read",
            Self::MissionScope => "mission:scope",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterScope {
    pub deployment: DagsterDeploymentIdentity,
    pub repository: DagsterRepositoryIdentity,
    pub code_location: DagsterCodeLocationIdentity,
    pub job: DagsterJobIdentity,
    pub run: DagsterRunIdentity,
    pub partition: Option<DagsterPartitionIdentity>,
    pub asset: DagsterAssetIdentity,
    pub commit: DagsterCommitReference,
    pub mission: MissionScopeBinding,
    pub permissions: BTreeSet<DagsterPermission>,
}

impl DagsterScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deployment: DagsterDeploymentIdentity,
        repository: DagsterRepositoryIdentity,
        code_location: DagsterCodeLocationIdentity,
        job: DagsterJobIdentity,
        run: DagsterRunIdentity,
        partition: Option<DagsterPartitionIdentity>,
        asset: DagsterAssetIdentity,
        commit: DagsterCommitReference,
        mission: MissionScopeBinding,
        permissions: impl IntoIterator<Item = DagsterPermission>,
    ) -> Result<Self, DagsterError> {
        let scope = Self {
            deployment,
            repository,
            code_location,
            job,
            run,
            partition,
            asset,
            commit,
            mission,
            permissions: permissions.into_iter().collect(),
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<(), DagsterError> {
        self.deployment.validate()?;
        self.repository.validate()?;
        self.code_location.validate()?;
        self.job.validate()?;
        self.run.validate()?;
        if let Some(partition) = &self.partition {
            partition.validate()?;
        }
        self.asset.validate()?;
        self.commit.validate()?;
        self.mission.validate()?;
        let required = [
            DagsterPermission::DeploymentRead,
            DagsterPermission::RepositoryRead,
            DagsterPermission::CodeLocationRead,
            DagsterPermission::JobRead,
            DagsterPermission::RunRead,
            DagsterPermission::EventRead,
            DagsterPermission::AssetRead,
            DagsterPermission::CommitRead,
            DagsterPermission::MissionScope,
        ];
        if required
            .iter()
            .any(|permission| !self.permissions.contains(permission))
        {
            return Err(DagsterError::PermissionDrift);
        }
        if self.partition.is_some() && !self.permissions.contains(&DagsterPermission::PartitionRead)
        {
            return Err(DagsterError::PermissionDrift);
        }
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn deployment_digest(&self) -> Digest {
        self.deployment.digest()
    }

    pub fn repository_digest(&self) -> Digest {
        self.repository.digest()
    }

    pub fn code_location_digest(&self) -> Digest {
        self.code_location.digest()
    }

    pub fn job_digest(&self) -> Digest {
        self.job.digest()
    }

    pub fn run_digest(&self) -> Digest {
        self.run.digest()
    }

    pub fn partition_digest(&self) -> Option<Digest> {
        self.partition
            .as_ref()
            .map(DagsterPartitionIdentity::digest)
    }

    pub fn asset_digest(&self) -> Digest {
        self.asset.digest()
    }

    pub fn commit_digest(&self) -> Digest {
        self.commit.digest()
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DagsterRunStatus {
    Queued,
    NotStarted,
    Started,
    Success,
    Failure,
    Canceled,
    Timeout,
    Invalid,
    ProviderUnknown,
    AccessLoss,
}

impl DagsterRunStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Success
                | Self::Failure
                | Self::Canceled
                | Self::Timeout
                | Self::Invalid
                | Self::ProviderUnknown
                | Self::AccessLoss
        )
    }

    pub fn can_follow(self, next: Self) -> bool {
        if self as u8 == next as u8 {
            return true;
        }
        match self {
            Self::Queued => next != Self::AccessLoss,
            Self::NotStarted => matches!(
                next,
                Self::Queued
                    | Self::Started
                    | Self::Success
                    | Self::Failure
                    | Self::Canceled
                    | Self::Timeout
                    | Self::Invalid
                    | Self::ProviderUnknown
            ),
            Self::Started => matches!(
                next,
                Self::Success
                    | Self::Failure
                    | Self::Canceled
                    | Self::Timeout
                    | Self::Invalid
                    | Self::ProviderUnknown
            ),
            Self::Success
            | Self::Failure
            | Self::Canceled
            | Self::Timeout
            | Self::Invalid
            | Self::ProviderUnknown
            | Self::AccessLoss => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DagsterEventKind {
    RunQueued,
    RunStarted,
    RunSuccess,
    RunFailure,
    RunCanceled,
    RunTimeout,
    Step,
    AssetMaterialization,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DagsterEventStatus {
    Queued,
    Started,
    Success,
    Failure,
    Canceled,
    Skipped,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DagsterError {
    #[error("invalid Layer-1 Dagster input: {0}")]
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
    #[error("deployment identity does not match the exact scope")]
    DeploymentMismatch,
    #[error("repository identity does not match the exact scope")]
    RepositoryMismatch,
    #[error("code-location identity does not match the exact scope")]
    CodeLocationMismatch,
    #[error("job identity does not match the exact scope")]
    JobMismatch,
    #[error("run identity does not match the exact requested run")]
    RunMismatch,
    #[error("partition identity does not match the exact scope")]
    PartitionMismatch,
    #[error("asset identity does not match the exact scope")]
    AssetMismatch,
    #[error("repository commit does not match the exact scope")]
    CommitMismatch,
    #[error("Mission/Project/Work Product scope does not match")]
    MissionScopeMismatch,
    #[error("Mission revision is stale")]
    StaleMissionRevision,
    #[error("run state transition is invalid")]
    InvalidStateTransition,
    #[error("event is outside the exact run, asset, or partition scope")]
    EventOutOfScope,
    #[error("materialization has no verified data-version digest")]
    MissingDataVersionDigest,
    #[error("duplicate event identity was observed")]
    DuplicateEvent,
    #[error("duplicate run has a different evidence digest")]
    DuplicateRun,
    #[error("Mission consumer is inactive")]
    ConsumerInactive,
    #[error("payload was truncated")]
    PayloadTruncated,
    #[error("payload was marked partial")]
    PartialResponse,
    #[error("payload exceeded the bounded response limit")]
    ResponseTooLarge,
    #[error("payload response digest did not verify")]
    PayloadTampered,
    #[error("evidence digest, page digest, or provenance was tampered")]
    EvidenceTampered,
    #[error("proposal digest or provenance was tampered")]
    ProposalTampered,
    #[error("redaction boundary was violated")]
    RedactionViolation,
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
    #[error("Dagster returned HTTP {status}, projected as {projection:?}")]
    HttpStatus {
        status: u16,
        projection: DagsterRunStatus,
    },
    #[error("Dagster read timed out")]
    Timeout,
    #[error("Dagster environment is blocked")]
    BlockedEnv,
    #[error("Dagster provider returned an unknown or unusable result")]
    ProviderUnknown,
    #[error("recording has no response for the requested typed operation")]
    RecordingExhausted,
    #[error("recording response has the wrong typed operation")]
    UnexpectedResponse,
}

impl DagsterError {
    fn from_transport(error: DagsterTransportError) -> Self {
        match error {
            DagsterTransportError::HttpStatus {
                status,
                retry_after_seconds: _,
            } => Self::HttpStatus {
                status,
                projection: projection_for_http_status(status),
            },
            DagsterTransportError::Timeout => Self::Timeout,
            DagsterTransportError::BlockedEnv => Self::BlockedEnv,
            DagsterTransportError::RecordingExhausted => Self::RecordingExhausted,
            DagsterTransportError::UnexpectedResponse => Self::UnexpectedResponse,
            DagsterTransportError::MalformedResponse => Self::PartialResponse,
        }
    }

    pub const fn projection(&self) -> DagsterRunStatus {
        match self {
            Self::HttpStatus { projection, .. } => *projection,
            Self::SecretRevoked | Self::SecretScopeMismatch | Self::RegistrationRevoked => {
                DagsterRunStatus::AccessLoss
            }
            Self::Timeout => DagsterRunStatus::Timeout,
            Self::InvalidInput(_)
            | Self::InvalidDigest
            | Self::InvalidSecretReference
            | Self::RegistrationBindingDrift
            | Self::RegistrationTampered
            | Self::RegistrationInactive
            | Self::PermissionDrift
            | Self::DeploymentMismatch
            | Self::RepositoryMismatch
            | Self::CodeLocationMismatch
            | Self::JobMismatch
            | Self::RunMismatch
            | Self::PartitionMismatch
            | Self::AssetMismatch
            | Self::CommitMismatch
            | Self::MissionScopeMismatch
            | Self::StaleMissionRevision
            | Self::InvalidStateTransition
            | Self::EventOutOfScope
            | Self::MissingDataVersionDigest
            | Self::DuplicateEvent
            | Self::DuplicateRun
            | Self::ConsumerInactive
            | Self::PayloadTruncated
            | Self::PartialResponse
            | Self::ResponseTooLarge
            | Self::PayloadTampered
            | Self::EvidenceTampered
            | Self::ProposalTampered
            | Self::RedactionViolation
            | Self::PageTooLarge
            | Self::EvidenceTooLarge
            | Self::PaginationRepeatedCursor
            | Self::PaginationDrift
            | Self::PaginationLimit
            | Self::InvalidLimits => DagsterRunStatus::Invalid,
            Self::BlockedEnv
            | Self::ProviderUnknown
            | Self::RecordingExhausted
            | Self::UnexpectedResponse => DagsterRunStatus::ProviderUnknown,
        }
    }

    pub const fn status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus { status, .. } => Some(*status),
            _ => None,
        }
    }
}

fn projection_for_http_status(status: u16) -> DagsterRunStatus {
    match status {
        401 | 403 => DagsterRunStatus::AccessLoss,
        404 => DagsterRunStatus::Invalid,
        _ => DagsterRunStatus::ProviderUnknown,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    DeploymentToken,
    ApiSecret,
}

/// Opaque reference to a credential held outside this crate. The reference
/// identifier is deliberately excluded from serialization and Debug output.
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

impl Serialize for SecretReference {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("SecretReference", 5)?;
        state.serialize_field("referenceDigest", &self.reference_digest())?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.serialize_field("revoked", &self.revoked)?;
        state.end()
    }
}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        kind: SecretKind,
        scope: &DagsterScope,
        credential_revision: u64,
    ) -> Result<Self, DagsterError> {
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

    pub fn deployment_token(
        reference_id: impl Into<String>,
        scope: &DagsterScope,
        credential_revision: u64,
    ) -> Result<Self, DagsterError> {
        Self::new(
            reference_id,
            SecretKind::DeploymentToken,
            scope,
            credential_revision,
        )
    }

    pub fn api_secret(
        reference_id: impl Into<String>,
        scope: &DagsterScope,
        credential_revision: u64,
    ) -> Result<Self, DagsterError> {
        Self::new(
            reference_id,
            SecretKind::ApiSecret,
            scope,
            credential_revision,
        )
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.reference_id,
            self.kind,
            &self.scope_digest,
            self.credential_revision,
        ))
    }

    pub fn kind(&self) -> SecretKind {
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

    pub fn is_bound_to(&self, scope: &DagsterScope) -> bool {
        !self.revoked && self.scope_digest == scope.scope_digest()
    }

    fn validate(&self) -> Result<(), DagsterError> {
        if !self.reference_id.starts_with("secret-ref-") {
            return Err(DagsterError::InvalidSecretReference);
        }
        validate_identifier("SecretReference", &self.reference_id)?;
        if self.credential_revision == 0 || !self.scope_digest.is_valid() {
            return Err(DagsterError::InvalidSecretReference);
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
pub struct DagsterRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub plugin_version: Version,
    pub status: RegistrationStatus,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub deployment_digest: Digest,
    pub repository_digest: Digest,
    pub code_location_digest: Digest,
    pub job_digest: Digest,
    pub run_digest: Digest,
    pub partition_digest: Option<Digest>,
    pub asset_digest: Digest,
    pub commit_digest: Digest,
    pub mission_digest: Digest,
    pub permission_digest: Digest,
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
    deployment_digest: &'a Digest,
    repository_digest: &'a Digest,
    code_location_digest: &'a Digest,
    job_digest: &'a Digest,
    run_digest: &'a Digest,
    partition_digest: &'a Option<Digest>,
    asset_digest: &'a Digest,
    commit_digest: &'a Digest,
    mission_digest: &'a Digest,
    permission_digest: &'a Digest,
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

    pub fn validate(&self) -> Result<(), DagsterError> {
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
            return Err(DagsterError::EvidenceTampered);
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

impl DagsterRegistration {
    pub fn new(
        scope: &DagsterScope,
        secret_reference: &SecretReference,
    ) -> Result<Self, DagsterError> {
        scope.validate()?;
        if !secret_reference.is_bound_to(scope) {
            return if secret_reference.is_revoked() {
                Err(DagsterError::SecretRevoked)
            } else {
                Err(DagsterError::SecretScopeMismatch)
            };
        }
        let version_digest = Digest::from_serializable(&(
            CONTRACT_SCHEMA,
            CONTRACT_VERSION,
            PLUGIN_ID,
            PLUGIN_VERSION,
        ));
        let contract_digest = contract_digest();
        let provider_digest = Digest::from_text(PROVIDER_ID);
        let mut registration = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            service_id: SERVICE_ID.into(),
            provider_id: PROVIDER_ID.into(),
            plugin_version: PLUGIN_VERSION,
            status: RegistrationStatus::Active,
            version_digest,
            contract_digest,
            provider_digest,
            deployment_digest: scope.deployment_digest(),
            repository_digest: scope.repository_digest(),
            code_location_digest: scope.code_location_digest(),
            job_digest: scope.job_digest(),
            run_digest: scope.run_digest(),
            partition_digest: scope.partition_digest(),
            asset_digest: scope.asset_digest(),
            commit_digest: scope.commit_digest(),
            mission_digest: scope.mission_digest(),
            permission_digest: scope.permission_digest(),
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
            deployment_digest: &self.deployment_digest,
            repository_digest: &self.repository_digest,
            code_location_digest: &self.code_location_digest,
            job_digest: &self.job_digest,
            run_digest: &self.run_digest,
            partition_digest: &self.partition_digest,
            asset_digest: &self.asset_digest,
            commit_digest: &self.commit_digest,
            mission_digest: &self.mission_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            credential_digest: &self.credential_digest,
            reversible: self.reversible,
            revocable: self.revocable,
        })
    }

    pub fn validate_binding(
        &self,
        scope: &DagsterScope,
        secret_reference: &SecretReference,
    ) -> Result<(), DagsterError> {
        if self.compute_digest() != self.registration_digest {
            return Err(DagsterError::RegistrationTampered);
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
            || self.deployment_digest != expected.deployment_digest
            || self.repository_digest != expected.repository_digest
            || self.code_location_digest != expected.code_location_digest
            || self.job_digest != expected.job_digest
            || self.run_digest != expected.run_digest
            || self.partition_digest != expected.partition_digest
            || self.asset_digest != expected.asset_digest
            || self.commit_digest != expected.commit_digest
            || self.mission_digest != expected.mission_digest
            || self.permission_digest != expected.permission_digest
            || self.scope_digest != expected.scope_digest
            || self.credential_digest != expected.credential_digest
            || !self.reversible
            || !self.revocable
            || self.reversible != expected.reversible
            || self.revocable != expected.revocable
        {
            return Err(DagsterError::RegistrationBindingDrift);
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

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence, DagsterError> {
        if self.status != RegistrationStatus::Active {
            return Err(DagsterError::RegistrationInactive);
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

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence, DagsterError> {
        if self.status != RegistrationStatus::Unmounted {
            return Err(DagsterError::RegistrationInactive);
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

    pub fn revoke(
        &mut self,
        secret_reference: &mut SecretReference,
    ) -> Result<RevocationReceipt, DagsterError> {
        if self.status == RegistrationStatus::Reversed {
            return Err(DagsterError::RegistrationInactive);
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

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence, DagsterError> {
        if self.status != RegistrationStatus::Revoked {
            return Err(DagsterError::RegistrationInactive);
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
pub struct DagsterRegistrationRegistry {
    registrations: BTreeMap<String, DagsterRegistration>,
}

impl DagsterRegistrationRegistry {
    pub fn register(
        &mut self,
        registration: DagsterRegistration,
    ) -> Result<RegistrationReceipt, DagsterError> {
        if registration.compute_digest() != registration.registration_digest
            || !registration.reversible
            || !registration.revocable
        {
            return Err(DagsterError::RegistrationTampered);
        }
        if self
            .registrations
            .contains_key(registration.registration_id().as_str())
        {
            return Err(DagsterError::DuplicateRun);
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

    pub fn get(&self, registration_digest: &Digest) -> Option<&DagsterRegistration> {
        self.registrations.get(registration_digest.as_str())
    }

    pub fn get_mut(&mut self, registration_digest: &Digest) -> Option<&mut DagsterRegistration> {
        self.registrations.get_mut(registration_digest.as_str())
    }

    pub fn revoke(
        &mut self,
        registration_digest: &Digest,
        secret_reference: &mut SecretReference,
    ) -> Result<RevocationReceipt, DagsterError> {
        self.get_mut(registration_digest)
            .ok_or(DagsterError::RegistrationBindingDrift)?
            .revoke(secret_reference)
    }

    pub fn restore(
        &mut self,
        registration_digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence, DagsterError> {
        self.get_mut(registration_digest)
            .ok_or(DagsterError::RegistrationBindingDrift)?
            .remount()
    }

    pub fn reverse(
        &mut self,
        registration_digest: &Digest,
    ) -> Result<RegistrationTransitionEvidence, DagsterError> {
        self.get_mut(registration_digest)
            .ok_or(DagsterError::RegistrationBindingDrift)?
            .reverse()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterDeploymentDescription {
    pub deployment: DagsterDeploymentIdentity,
    pub graphql_api_revision: String,
    pub repository_count: usize,
    pub code_location_count: usize,
    pub scope_digest: Digest,
}

impl DagsterDeploymentDescription {
    pub fn for_scope(scope: &DagsterScope) -> Self {
        Self {
            deployment: scope.deployment.clone(),
            graphql_api_revision: "dagster-graphql-read-v1".into(),
            repository_count: 1,
            code_location_count: 1,
            scope_digest: scope.scope_digest(),
        }
    }

    fn validate(&self) -> Result<(), DagsterError> {
        self.deployment.validate()?;
        validate_identifier("GraphQL API revision", &self.graphql_api_revision)?;
        if self.repository_count > MAX_PAGE_ITEMS || self.code_location_count > MAX_PAGE_ITEMS {
            return Err(DagsterError::EvidenceTooLarge);
        }
        if !self.scope_digest.is_valid() {
            return Err(DagsterError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterRepositoryDescription {
    pub deployment: DagsterDeploymentIdentity,
    pub repository: DagsterRepositoryIdentity,
    pub code_location: DagsterCodeLocationIdentity,
    pub commit: DagsterCommitReference,
    pub job_names: Vec<String>,
    pub asset_count: usize,
    pub scope_digest: Digest,
}

impl DagsterRepositoryDescription {
    pub fn for_scope(scope: &DagsterScope) -> Self {
        Self {
            deployment: scope.deployment.clone(),
            repository: scope.repository.clone(),
            code_location: scope.code_location.clone(),
            commit: scope.commit.clone(),
            job_names: vec![scope.job.name.clone()],
            asset_count: 1,
            scope_digest: scope.scope_digest(),
        }
    }

    fn validate(&self) -> Result<(), DagsterError> {
        self.deployment.validate()?;
        self.repository.validate()?;
        self.code_location.validate()?;
        self.commit.validate()?;
        if self.job_names.len() > MAX_PAGE_ITEMS || self.asset_count > MAX_MATERIALIZATIONS {
            return Err(DagsterError::EvidenceTooLarge);
        }
        for name in &self.job_names {
            validate_identifier("repository job name", name)?;
        }
        if !self.scope_digest.is_valid() {
            return Err(DagsterError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterCodeLocationDescription {
    pub deployment: DagsterDeploymentIdentity,
    pub repository: DagsterRepositoryIdentity,
    pub code_location: DagsterCodeLocationIdentity,
    pub load_status: String,
    pub definition_digest: Digest,
    pub scope_digest: Digest,
}

impl DagsterCodeLocationDescription {
    pub fn for_scope(scope: &DagsterScope) -> Self {
        Self {
            deployment: scope.deployment.clone(),
            repository: scope.repository.clone(),
            code_location: scope.code_location.clone(),
            load_status: "loaded".into(),
            definition_digest: Digest::from_serializable(&(
                &scope.repository,
                &scope.code_location,
                &scope.job,
                &scope.asset,
            )),
            scope_digest: scope.scope_digest(),
        }
    }

    fn validate(&self) -> Result<(), DagsterError> {
        self.deployment.validate()?;
        self.repository.validate()?;
        self.code_location.validate()?;
        validate_identifier("code location load status", &self.load_status)?;
        if !self.definition_digest.is_valid() || !self.scope_digest.is_valid() {
            return Err(DagsterError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterJobDescription {
    pub deployment: DagsterDeploymentIdentity,
    pub repository: DagsterRepositoryIdentity,
    pub code_location: DagsterCodeLocationIdentity,
    pub job: DagsterJobIdentity,
    pub commit: DagsterCommitReference,
    pub asset_keys: Vec<DagsterAssetIdentity>,
    pub partition_definition_digest: Option<Digest>,
    pub definition_digest: Digest,
    pub scope_digest: Digest,
}

impl DagsterJobDescription {
    pub fn for_scope(scope: &DagsterScope) -> Self {
        Self {
            deployment: scope.deployment.clone(),
            repository: scope.repository.clone(),
            code_location: scope.code_location.clone(),
            job: scope.job.clone(),
            commit: scope.commit.clone(),
            asset_keys: vec![scope.asset.clone()],
            partition_definition_digest: scope
                .partition
                .as_ref()
                .map(DagsterPartitionIdentity::digest),
            definition_digest: Digest::from_serializable(&(
                &scope.job,
                &scope.asset,
                &scope.partition,
                &scope.commit,
            )),
            scope_digest: scope.scope_digest(),
        }
    }

    fn validate(&self) -> Result<(), DagsterError> {
        self.deployment.validate()?;
        self.repository.validate()?;
        self.code_location.validate()?;
        self.job.validate()?;
        self.commit.validate()?;
        if self.asset_keys.len() > MAX_MATERIALIZATIONS {
            return Err(DagsterError::EvidenceTooLarge);
        }
        for asset in &self.asset_keys {
            asset.validate()?;
        }
        if self
            .partition_definition_digest
            .as_ref()
            .is_some_and(|digest| !digest.is_valid())
            || !self.definition_digest.is_valid()
            || !self.scope_digest.is_valid()
        {
            return Err(DagsterError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterAssetDescription {
    pub deployment: DagsterDeploymentIdentity,
    pub repository: DagsterRepositoryIdentity,
    pub code_location: DagsterCodeLocationIdentity,
    pub job: DagsterJobIdentity,
    pub asset: DagsterAssetIdentity,
    pub partition_definition_digest: Option<Digest>,
    pub latest_data_version_digest: Option<Digest>,
    pub scope_digest: Digest,
}

impl DagsterAssetDescription {
    pub fn for_scope(scope: &DagsterScope) -> Self {
        Self {
            deployment: scope.deployment.clone(),
            repository: scope.repository.clone(),
            code_location: scope.code_location.clone(),
            job: scope.job.clone(),
            asset: scope.asset.clone(),
            partition_definition_digest: scope
                .partition
                .as_ref()
                .map(DagsterPartitionIdentity::digest),
            latest_data_version_digest: None,
            scope_digest: scope.scope_digest(),
        }
    }

    fn validate(&self) -> Result<(), DagsterError> {
        self.deployment.validate()?;
        self.repository.validate()?;
        self.code_location.validate()?;
        self.job.validate()?;
        self.asset.validate()?;
        if self
            .partition_definition_digest
            .as_ref()
            .is_some_and(|digest| !digest.is_valid())
            || self
                .latest_data_version_digest
                .as_ref()
                .is_some_and(|digest| !digest.is_valid())
            || !self.scope_digest.is_valid()
        {
            return Err(DagsterError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterRunSnapshot {
    pub deployment: DagsterDeploymentIdentity,
    pub repository: DagsterRepositoryIdentity,
    pub code_location: DagsterCodeLocationIdentity,
    pub job: DagsterJobIdentity,
    pub run: DagsterRunIdentity,
    pub partition: Option<DagsterPartitionIdentity>,
    pub asset: DagsterAssetIdentity,
    pub commit: DagsterCommitReference,
    pub status: DagsterRunStatus,
    pub created_at_epoch_seconds: Option<u64>,
    pub started_at_epoch_seconds: Option<u64>,
    pub finished_at_epoch_seconds: Option<u64>,
    pub run_metadata_digest: Digest,
    pub state_revision: u64,
    pub snapshot_digest: Digest,
}

#[derive(Serialize)]
struct RunSnapshotDigestInput<'a> {
    deployment: &'a DagsterDeploymentIdentity,
    repository: &'a DagsterRepositoryIdentity,
    code_location: &'a DagsterCodeLocationIdentity,
    job: &'a DagsterJobIdentity,
    run: &'a DagsterRunIdentity,
    partition: &'a Option<DagsterPartitionIdentity>,
    asset: &'a DagsterAssetIdentity,
    commit: &'a DagsterCommitReference,
    status: DagsterRunStatus,
    created_at_epoch_seconds: Option<u64>,
    started_at_epoch_seconds: Option<u64>,
    finished_at_epoch_seconds: Option<u64>,
    run_metadata_digest: &'a Digest,
    state_revision: u64,
}

impl DagsterRunSnapshot {
    pub fn for_scope(scope: &DagsterScope, status: DagsterRunStatus) -> Self {
        let mut snapshot = Self {
            deployment: scope.deployment.clone(),
            repository: scope.repository.clone(),
            code_location: scope.code_location.clone(),
            job: scope.job.clone(),
            run: scope.run.clone(),
            partition: scope.partition.clone(),
            asset: scope.asset.clone(),
            commit: scope.commit.clone(),
            status,
            created_at_epoch_seconds: Some(100),
            started_at_epoch_seconds: Some(110),
            finished_at_epoch_seconds: status.is_terminal().then_some(200),
            run_metadata_digest: Digest::from_text("dagster-run-metadata"),
            state_revision: 1,
            snapshot_digest: Digest::from_text("uncomputed"),
        };
        snapshot.snapshot_digest = snapshot.compute_digest();
        snapshot
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&RunSnapshotDigestInput {
            deployment: &self.deployment,
            repository: &self.repository,
            code_location: &self.code_location,
            job: &self.job,
            run: &self.run,
            partition: &self.partition,
            asset: &self.asset,
            commit: &self.commit,
            status: self.status,
            created_at_epoch_seconds: self.created_at_epoch_seconds,
            started_at_epoch_seconds: self.started_at_epoch_seconds,
            finished_at_epoch_seconds: self.finished_at_epoch_seconds,
            run_metadata_digest: &self.run_metadata_digest,
            state_revision: self.state_revision,
        })
    }

    pub fn reseal(&mut self) {
        self.snapshot_digest = self.compute_digest();
    }

    pub fn validate(&self) -> Result<(), DagsterError> {
        self.deployment.validate()?;
        self.repository.validate()?;
        self.code_location.validate()?;
        self.job.validate()?;
        self.run.validate()?;
        if let Some(partition) = &self.partition {
            partition.validate()?;
        }
        self.asset.validate()?;
        self.commit.validate()?;
        if self
            .created_at_epoch_seconds
            .zip(self.started_at_epoch_seconds)
            .is_some_and(|(created, started)| started < created)
            || self
                .started_at_epoch_seconds
                .zip(self.finished_at_epoch_seconds)
                .is_some_and(|(started, finished)| finished < started)
        {
            return Err(DagsterError::InvalidInput("run time ordering"));
        }
        if !self.run_metadata_digest.is_valid()
            || self.state_revision == 0
            || self.snapshot_digest != self.compute_digest()
        {
            return Err(DagsterError::PayloadTampered);
        }
        Ok(())
    }

    pub fn validate_transition(&self, next: &Self) -> Result<(), DagsterError> {
        self.validate()?;
        next.validate()?;
        if self.run != next.run
            || self.deployment != next.deployment
            || self.repository != next.repository
            || self.code_location != next.code_location
            || self.job != next.job
            || self.partition != next.partition
            || self.asset != next.asset
            || self.commit != next.commit
            || next.state_revision < self.state_revision
            || !self.status.can_follow(next.status)
        {
            return Err(DagsterError::InvalidStateTransition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterRunReadRequest {
    pub run_id: String,
    pub observed_at_epoch_seconds: u64,
}

impl DagsterRunReadRequest {
    pub fn new(
        run_id: impl Into<String>,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self, DagsterError> {
        let request = Self {
            run_id: run_id.into(),
            observed_at_epoch_seconds,
        };
        validate_identifier("requested run id", &request.run_id)?;
        Ok(request)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterStepSummary {
    pub step_key: String,
    pub status: DagsterEventStatus,
    pub duration_millis: Option<u64>,
    pub metadata_digest: Digest,
}

impl DagsterStepSummary {
    pub fn new(
        step_key: impl Into<String>,
        status: DagsterEventStatus,
        duration_millis: Option<u64>,
        metadata_digest: Digest,
    ) -> Result<Self, DagsterError> {
        let summary = Self {
            step_key: step_key.into(),
            status,
            duration_millis,
            metadata_digest,
        };
        summary.validate()?;
        Ok(summary)
    }

    fn validate(&self) -> Result<(), DagsterError> {
        validate_identifier("step key", &self.step_key)?;
        if self
            .duration_millis
            .is_some_and(|duration| duration > 86_400_000)
        {
            return Err(DagsterError::InvalidInput("step duration"));
        }
        if !self.metadata_digest.is_valid() {
            return Err(DagsterError::InvalidDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterAssetMaterialization {
    pub asset: DagsterAssetIdentity,
    pub partition: Option<DagsterPartitionIdentity>,
    pub step_key: String,
    pub metadata_digest: Digest,
    pub data_version_digest: Option<Digest>,
    pub observed_at_epoch_seconds: u64,
}

impl DagsterAssetMaterialization {
    pub fn new(
        asset: DagsterAssetIdentity,
        partition: Option<DagsterPartitionIdentity>,
        step_key: impl Into<String>,
        metadata_digest: Digest,
        data_version_digest: Option<Digest>,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self, DagsterError> {
        let materialization = Self {
            asset,
            partition,
            step_key: step_key.into(),
            metadata_digest,
            data_version_digest,
            observed_at_epoch_seconds,
        };
        materialization.validate()?;
        Ok(materialization)
    }

    pub fn for_scope(
        scope: &DagsterScope,
        step_key: impl Into<String>,
        data_version_digest: Digest,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self, DagsterError> {
        Self::new(
            scope.asset.clone(),
            scope.partition.clone(),
            step_key,
            Digest::from_text("dagster-materialization-metadata"),
            Some(data_version_digest),
            observed_at_epoch_seconds,
        )
    }

    fn validate(&self) -> Result<(), DagsterError> {
        self.asset.validate()?;
        if let Some(partition) = &self.partition {
            partition.validate()?;
        }
        validate_identifier("materialization step key", &self.step_key)?;
        if !self.metadata_digest.is_valid() {
            return Err(DagsterError::InvalidDigest);
        }
        if self
            .data_version_digest
            .as_ref()
            .is_some_and(|digest| !digest.is_valid())
        {
            return Err(DagsterError::InvalidDigest);
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterEventSummary {
    pub event_id: String,
    pub kind: DagsterEventKind,
    pub status: DagsterEventStatus,
    pub step_key: Option<String>,
    pub duration_millis: Option<u64>,
    pub metadata_digest: Digest,
    pub materialization: Option<DagsterAssetMaterialization>,
    pub observed_at_epoch_seconds: u64,
}

impl DagsterEventSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: impl Into<String>,
        kind: DagsterEventKind,
        status: DagsterEventStatus,
        step_key: Option<String>,
        duration_millis: Option<u64>,
        metadata_digest: Digest,
        materialization: Option<DagsterAssetMaterialization>,
        observed_at_epoch_seconds: u64,
    ) -> Result<Self, DagsterError> {
        let event = Self {
            event_id: event_id.into(),
            kind,
            status,
            step_key,
            duration_millis,
            metadata_digest,
            materialization,
            observed_at_epoch_seconds,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn step(
        event_id: impl Into<String>,
        status: DagsterEventStatus,
        step_key: impl Into<String>,
        duration_millis: Option<u64>,
    ) -> Result<Self, DagsterError> {
        Self::new(
            event_id,
            DagsterEventKind::Step,
            status,
            Some(step_key.into()),
            duration_millis,
            Digest::from_text("dagster-step-metadata"),
            None,
            0,
        )
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn materialization(
        event_id: impl Into<String>,
        materialization: DagsterAssetMaterialization,
    ) -> Result<Self, DagsterError> {
        Self::new(
            event_id,
            DagsterEventKind::AssetMaterialization,
            DagsterEventStatus::Success,
            Some(materialization.step_key.clone()),
            None,
            materialization.metadata_digest.clone(),
            Some(materialization.clone()),
            materialization.observed_at_epoch_seconds,
        )
    }

    fn validate(&self) -> Result<(), DagsterError> {
        validate_bounded_text("event id", &self.event_id, MAX_EVENT_ID_BYTES)?;
        if self
            .step_key
            .as_ref()
            .is_some_and(|step| validate_identifier("event step key", step).is_err())
        {
            return Err(DagsterError::InvalidInput("event step key"));
        }
        if self
            .duration_millis
            .is_some_and(|duration| duration > 86_400_000)
        {
            return Err(DagsterError::InvalidInput("event duration"));
        }
        if !self.metadata_digest.is_valid() {
            return Err(DagsterError::InvalidDigest);
        }
        if self.kind == DagsterEventKind::AssetMaterialization && self.materialization.is_none() {
            return Err(DagsterError::PartialResponse);
        }
        if self.kind != DagsterEventKind::AssetMaterialization && self.materialization.is_some() {
            return Err(DagsterError::InvalidInput("event materialization kind"));
        }
        if let Some(materialization) = &self.materialization {
            materialization.validate()?;
        }
        Ok(())
    }

    fn validate_for_scope(&self, scope: &DagsterScope) -> Result<(), DagsterError> {
        self.validate()?;
        if let Some(materialization) = &self.materialization {
            if materialization.asset != scope.asset || materialization.partition != scope.partition
            {
                return Err(DagsterError::EventOutOfScope);
            }
            if materialization.data_version_digest.is_none() {
                return Err(DagsterError::MissingDataVersionDigest);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Recording,
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionEvidence {
    pub raw_logs_retained: bool,
    pub raw_config_retained: bool,
    pub raw_secret_retained: bool,
    pub redacted_field_count: usize,
}

impl RedactionEvidence {
    fn validate(&self) -> Result<(), DagsterError> {
        if self.raw_logs_retained || self.raw_config_retained || self.raw_secret_retained {
            return Err(DagsterError::RedactionViolation);
        }
        if self.redacted_field_count > MAX_EVENTS {
            return Err(DagsterError::EvidenceTooLarge);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterPayload<T> {
    pub payload: T,
    pub response_digest: Digest,
    pub content_length_bytes: usize,
    pub truncated: bool,
    pub partial: bool,
    pub redaction: RedactionEvidence,
}

#[derive(Serialize)]
struct PayloadDigestInput<'a, T> {
    payload: &'a T,
    content_length_bytes: usize,
    truncated: bool,
    partial: bool,
    redaction: &'a RedactionEvidence,
}

impl<T: Serialize> DagsterPayload<T> {
    pub fn new(payload: T) -> Self {
        let content_length_bytes = serde_json::to_vec(&payload)
            .expect("typed Dagster payload must serialize")
            .len();
        let redaction = RedactionEvidence::default();
        let mut result = Self {
            payload,
            response_digest: Digest::from_text("uncomputed"),
            content_length_bytes,
            truncated: false,
            partial: false,
            redaction,
        };
        result.response_digest = result.compute_digest();
        result
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

    #[must_use]
    pub fn with_event_metadata(mut self, partial: bool, redaction: RedactionEvidence) -> Self {
        self.partial = partial;
        self.redaction = redaction;
        self.response_digest = self.compute_digest();
        self
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&PayloadDigestInput {
            payload: &self.payload,
            content_length_bytes: self.content_length_bytes,
            truncated: self.truncated,
            partial: self.partial,
            redaction: &self.redaction,
        })
    }

    fn verify(&self) -> Result<(), DagsterError> {
        if self.truncated {
            return Err(DagsterError::PayloadTruncated);
        }
        if self.partial {
            return Err(DagsterError::PartialResponse);
        }
        if self.content_length_bytes > MAX_RESPONSE_BYTES {
            return Err(DagsterError::ResponseTooLarge);
        }
        self.redaction.validate()?;
        if self.response_digest != self.compute_digest() {
            return Err(DagsterError::PayloadTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterPage<T> {
    pub operation: DagsterOperation,
    pub page_index: usize,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub items: Vec<T>,
    pub response_digest: Digest,
    pub content_length_bytes: usize,
    pub truncated: bool,
    pub partial: bool,
    pub redaction: RedactionEvidence,
}

#[derive(Serialize)]
struct PageDigestInput<'a, T> {
    operation: DagsterOperation,
    page_index: usize,
    cursor: &'a Option<String>,
    next_cursor: &'a Option<String>,
    items: &'a [T],
    content_length_bytes: usize,
    truncated: bool,
    partial: bool,
    redaction: &'a RedactionEvidence,
}

impl<T: Serialize> DagsterPage<T> {
    pub fn new(
        operation: DagsterOperation,
        page_index: usize,
        cursor: Option<String>,
        next_cursor: Option<String>,
        items: Vec<T>,
    ) -> Self {
        let content_length_bytes = serde_json::to_vec(&items)
            .expect("typed Dagster page must serialize")
            .len();
        let mut page = Self {
            operation,
            page_index,
            cursor,
            next_cursor,
            items,
            response_digest: Digest::from_text("uncomputed"),
            content_length_bytes,
            truncated: false,
            partial: false,
            redaction: RedactionEvidence::default(),
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

    #[must_use]
    pub fn with_event_metadata(mut self, partial: bool, redaction: RedactionEvidence) -> Self {
        self.partial = partial;
        self.redaction = redaction;
        self.response_digest = self.compute_digest();
        self
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&PageDigestInput {
            operation: self.operation,
            page_index: self.page_index,
            cursor: &self.cursor,
            next_cursor: &self.next_cursor,
            items: &self.items,
            content_length_bytes: self.content_length_bytes,
            truncated: self.truncated,
            partial: self.partial,
            redaction: &self.redaction,
        })
    }

    fn verify(
        &self,
        expected_operation: DagsterOperation,
        expected_page: usize,
        expected_cursor: Option<&String>,
        limits: &ReadLimits,
    ) -> Result<(), DagsterError> {
        if self.operation != expected_operation
            || self.page_index != expected_page
            || self.cursor.as_ref() != expected_cursor
        {
            return Err(DagsterError::PaginationDrift);
        }
        if self.next_cursor.as_ref().is_some_and(String::is_empty)
            || self
                .next_cursor
                .as_ref()
                .is_some_and(|cursor| cursor.len() > MAX_CURSOR_BYTES)
        {
            return Err(DagsterError::PaginationDrift);
        }
        if self.items.len() > limits.max_page_items {
            return Err(DagsterError::PageTooLarge);
        }
        if self.truncated {
            return Err(DagsterError::PayloadTruncated);
        }
        if self.partial {
            return Err(DagsterError::PartialResponse);
        }
        if self.content_length_bytes > limits.max_response_bytes {
            return Err(DagsterError::ResponseTooLarge);
        }
        self.redaction.validate()?;
        if self.response_digest != self.compute_digest() {
            return Err(DagsterError::PayloadTampered);
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
    pub max_events: usize,
    pub max_step_summaries: usize,
    pub max_materializations: usize,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_response_bytes: MAX_RESPONSE_BYTES,
            max_page_items: MAX_PAGE_ITEMS,
            max_pages: MAX_PAGES,
            max_events: MAX_EVENTS,
            max_step_summaries: MAX_STEP_SUMMARIES,
            max_materializations: MAX_MATERIALIZATIONS,
        }
    }
}

impl ReadLimits {
    fn validate(self) -> Result<Self, DagsterError> {
        if self.max_response_bytes == 0
            || self.max_response_bytes > MAX_RESPONSE_BYTES
            || self.max_page_items == 0
            || self.max_page_items > MAX_PAGE_ITEMS
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.max_events == 0
            || self.max_events > MAX_EVENTS
            || self.max_step_summaries == 0
            || self.max_step_summaries > MAX_STEP_SUMMARIES
            || self.max_materializations == 0
            || self.max_materializations > MAX_MATERIALIZATIONS
        {
            return Err(DagsterError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DagsterOperation {
    DescribeDeployment,
    DescribeRepository,
    DescribeCodeLocation,
    DescribeJob,
    DescribeAsset,
    ReadRun,
    ReadEvents,
}

impl DagsterOperation {
    pub const fn is_read_only(self) -> bool {
        true
    }

    pub const fn graphql_document(self) -> &'static str {
        match self {
            Self::DescribeDeployment => {
                "query DagsterDeploymentRead { repositoriesOrError { __typename } }"
            }
            Self::DescribeRepository => {
                "query DagsterRepositoryRead($repositoryLocationName: String!, $repositoryName: String!) { repositoryOrError(repositorySelector: { repositoryLocationName: $repositoryLocationName, repositoryName: $repositoryName }) { __typename } }"
            }
            Self::DescribeCodeLocation => {
                "query DagsterCodeLocationRead($repositoryLocationName: String!) { repositoriesOrError { __typename } }"
            }
            Self::DescribeJob => {
                "query DagsterJobRead($repositoryLocationName: String!, $repositoryName: String!) { repositoryOrError(repositorySelector: { repositoryLocationName: $repositoryLocationName, repositoryName: $repositoryName }) { __typename } }"
            }
            Self::DescribeAsset => {
                "query DagsterAssetRead($assetKey: AssetKeyInput!) { assetOrError(assetKey: $assetKey) { __typename } }"
            }
            Self::ReadRun => {
                "query DagsterRunRead($runId: ID!) { runOrError(runId: $runId) { __typename } }"
            }
            Self::ReadEvents => {
                "query DagsterEventRead($runId: ID!, $cursor: String, $limit: Int) { logsForRun(runId: $runId, cursor: $cursor, limit: $limit) { __typename } }"
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterReadRequest {
    pub operation: DagsterOperation,
    pub deployment_digest: Digest,
    pub repository_digest: Digest,
    pub code_location_digest: Digest,
    pub job_digest: Digest,
    pub run_digest: Digest,
    pub partition_digest: Option<Digest>,
    pub asset_digest: Digest,
    pub commit_digest: Digest,
    pub scope_digest: Digest,
    pub run_id: Option<String>,
    pub cursor: Option<String>,
    pub page_size: usize,
    pub query_digest: Digest,
    pub variables_digest: Digest,
}

impl DagsterReadRequest {
    fn for_scope(
        scope: &DagsterScope,
        operation: DagsterOperation,
        run_id: Option<String>,
        cursor: Option<String>,
        page_size: usize,
    ) -> Self {
        let variables_digest = Digest::from_serializable(&(
            scope.deployment_digest(),
            scope.repository_digest(),
            scope.code_location_digest(),
            scope.job_digest(),
            scope.run_digest(),
            scope.partition_digest(),
            scope.asset_digest(),
            scope.commit_digest(),
            run_id.as_deref(),
            cursor.as_deref(),
            page_size,
        ));
        Self {
            operation,
            deployment_digest: scope.deployment_digest(),
            repository_digest: scope.repository_digest(),
            code_location_digest: scope.code_location_digest(),
            job_digest: scope.job_digest(),
            run_digest: scope.run_digest(),
            partition_digest: scope.partition_digest(),
            asset_digest: scope.asset_digest(),
            commit_digest: scope.commit_digest(),
            scope_digest: scope.scope_digest(),
            run_id,
            cursor,
            page_size,
            query_digest: Digest::from_text(operation.graphql_document()),
            variables_digest,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterRequestAudit {
    pub operation: DagsterOperation,
    pub scope_digest: Digest,
    pub run_id: Option<String>,
    pub cursor: Option<String>,
    pub page_size: usize,
    pub query_digest: Digest,
    pub variables_digest: Digest,
    pub secret_reference_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl DagsterRequestAudit {
    fn from_request(request: &DagsterReadRequest, secret: &SecretReference) -> Self {
        Self {
            operation: request.operation,
            scope_digest: request.scope_digest.clone(),
            run_id: request.run_id.clone(),
            cursor: request.cursor.clone(),
            page_size: request.page_size,
            query_digest: request.query_digest.clone(),
            variables_digest: request.variables_digest.clone(),
            secret_reference_digest: secret.reference_digest(),
            connected: false,
            native: false,
            first_party: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum DagsterTransportError {
    #[error("Dagster returned HTTP status {status}")]
    HttpStatus {
        status: u16,
        retry_after_seconds: Option<u64>,
    },
    #[error("Dagster read timed out")]
    Timeout,
    #[error("Dagster environment is blocked")]
    BlockedEnv,
    #[error("recording has no response")]
    RecordingExhausted,
    #[error("recording response has the wrong operation type")]
    UnexpectedResponse,
    #[error("Dagster GraphQL response was malformed or partial")]
    MalformedResponse,
}

pub trait DagsterTransport {
    fn provenance(&self) -> TransportProvenance;

    fn describe_deployment(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterDeploymentDescription>, DagsterTransportError>;

    fn describe_repository(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterRepositoryDescription>, DagsterTransportError>;

    fn describe_code_location(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterCodeLocationDescription>, DagsterTransportError>;

    fn describe_job(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterJobDescription>, DagsterTransportError>;

    fn describe_asset(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterAssetDescription>, DagsterTransportError>;

    fn read_run(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterRunSnapshot>, DagsterTransportError>;

    fn read_events(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPage<DagsterEventSummary>, DagsterTransportError>;
}

#[derive(Clone, Debug)]
enum RecordedResponse {
    Deployment(Result<DagsterPayload<DagsterDeploymentDescription>, DagsterTransportError>),
    Repository(Result<DagsterPayload<DagsterRepositoryDescription>, DagsterTransportError>),
    CodeLocation(Result<DagsterPayload<DagsterCodeLocationDescription>, DagsterTransportError>),
    Job(Result<DagsterPayload<DagsterJobDescription>, DagsterTransportError>),
    Asset(Result<DagsterPayload<DagsterAssetDescription>, DagsterTransportError>),
    Run(Result<DagsterPayload<DagsterRunSnapshot>, DagsterTransportError>),
    Events(Result<DagsterPage<DagsterEventSummary>, DagsterTransportError>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordedResponseKind {
    Deployment,
    Repository,
    CodeLocation,
    Job,
    Asset,
    Run,
    Events,
}

impl RecordedResponse {
    const fn kind(&self) -> RecordedResponseKind {
        match self {
            Self::Deployment(_) => RecordedResponseKind::Deployment,
            Self::Repository(_) => RecordedResponseKind::Repository,
            Self::CodeLocation(_) => RecordedResponseKind::CodeLocation,
            Self::Job(_) => RecordedResponseKind::Job,
            Self::Asset(_) => RecordedResponseKind::Asset,
            Self::Run(_) => RecordedResponseKind::Run,
            Self::Events(_) => RecordedResponseKind::Events,
        }
    }
}

/// Deterministic local transport. It records only typed request audits and
/// returns bounded typed responses; it never opens a network connection.
#[derive(Clone, Debug)]
pub struct RecordingDagsterTransport {
    provenance: TransportProvenance,
    responses: VecDeque<RecordedResponse>,
    requests: Vec<DagsterRequestAudit>,
    forced_error: Option<DagsterTransportError>,
}

impl RecordingDagsterTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            responses: VecDeque::new(),
            requests: Vec::new(),
            forced_error: (provenance == TransportProvenance::BlockedEnv)
                .then_some(DagsterTransportError::BlockedEnv),
        }
    }

    pub fn recording() -> Self {
        Self::new(TransportProvenance::Recording)
    }

    pub fn fixture() -> Self {
        Self::recording()
    }

    pub fn fake() -> Self {
        Self::new(TransportProvenance::Fake)
    }

    pub fn loopback() -> Self {
        Self::new(TransportProvenance::Loopback)
    }

    pub fn blocked_env() -> Self {
        Self::new(TransportProvenance::BlockedEnv)
    }

    pub fn fail_with(&mut self, error: DagsterTransportError) {
        self.forced_error = Some(error);
    }

    pub fn push_deployment_response(
        &mut self,
        response: Result<DagsterPayload<DagsterDeploymentDescription>, DagsterTransportError>,
    ) {
        self.responses
            .push_back(RecordedResponse::Deployment(response));
    }

    pub fn push_repository_response(
        &mut self,
        response: Result<DagsterPayload<DagsterRepositoryDescription>, DagsterTransportError>,
    ) {
        self.responses
            .push_back(RecordedResponse::Repository(response));
    }

    pub fn push_code_location_response(
        &mut self,
        response: Result<DagsterPayload<DagsterCodeLocationDescription>, DagsterTransportError>,
    ) {
        self.responses
            .push_back(RecordedResponse::CodeLocation(response));
    }

    pub fn push_job_response(
        &mut self,
        response: Result<DagsterPayload<DagsterJobDescription>, DagsterTransportError>,
    ) {
        self.responses.push_back(RecordedResponse::Job(response));
    }

    pub fn push_asset_response(
        &mut self,
        response: Result<DagsterPayload<DagsterAssetDescription>, DagsterTransportError>,
    ) {
        self.responses.push_back(RecordedResponse::Asset(response));
    }

    pub fn push_run_response(
        &mut self,
        response: Result<DagsterPayload<DagsterRunSnapshot>, DagsterTransportError>,
    ) {
        self.responses.push_back(RecordedResponse::Run(response));
    }

    pub fn push_events_response(
        &mut self,
        response: Result<DagsterPage<DagsterEventSummary>, DagsterTransportError>,
    ) {
        self.responses.push_back(RecordedResponse::Events(response));
    }

    pub fn requests(&self) -> &[DagsterRequestAudit] {
        &self.requests
    }

    fn take(
        &mut self,
        expected: RecordedResponseKind,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<RecordedResponse, DagsterTransportError> {
        self.requests
            .push(DagsterRequestAudit::from_request(request, secret_reference));
        if let Some(error) = self.forced_error {
            return Err(error);
        }
        let response = self
            .responses
            .pop_front()
            .ok_or(DagsterTransportError::RecordingExhausted)?;
        if response.kind() != expected {
            return Err(DagsterTransportError::UnexpectedResponse);
        }
        Ok(response)
    }
}

impl DagsterTransport for RecordingDagsterTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn describe_deployment(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterDeploymentDescription>, DagsterTransportError> {
        match self.take(RecordedResponseKind::Deployment, request, secret_reference)? {
            RecordedResponse::Deployment(response) => response,
            _ => Err(DagsterTransportError::UnexpectedResponse),
        }
    }

    fn describe_repository(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterRepositoryDescription>, DagsterTransportError> {
        match self.take(RecordedResponseKind::Repository, request, secret_reference)? {
            RecordedResponse::Repository(response) => response,
            _ => Err(DagsterTransportError::UnexpectedResponse),
        }
    }

    fn describe_code_location(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterCodeLocationDescription>, DagsterTransportError> {
        match self.take(
            RecordedResponseKind::CodeLocation,
            request,
            secret_reference,
        )? {
            RecordedResponse::CodeLocation(response) => response,
            _ => Err(DagsterTransportError::UnexpectedResponse),
        }
    }

    fn describe_job(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterJobDescription>, DagsterTransportError> {
        match self.take(RecordedResponseKind::Job, request, secret_reference)? {
            RecordedResponse::Job(response) => response,
            _ => Err(DagsterTransportError::UnexpectedResponse),
        }
    }

    fn describe_asset(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterAssetDescription>, DagsterTransportError> {
        match self.take(RecordedResponseKind::Asset, request, secret_reference)? {
            RecordedResponse::Asset(response) => response,
            _ => Err(DagsterTransportError::UnexpectedResponse),
        }
    }

    fn read_run(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterRunSnapshot>, DagsterTransportError> {
        match self.take(RecordedResponseKind::Run, request, secret_reference)? {
            RecordedResponse::Run(response) => response,
            _ => Err(DagsterTransportError::UnexpectedResponse),
        }
    }

    fn read_events(
        &mut self,
        request: &DagsterReadRequest,
        secret_reference: &SecretReference,
    ) -> Result<DagsterPage<DagsterEventSummary>, DagsterTransportError> {
        match self.take(RecordedResponseKind::Events, request, secret_reference)? {
            RecordedResponse::Events(response) => response,
            _ => Err(DagsterTransportError::UnexpectedResponse),
        }
    }
}

pub type DagsterFakeTransport = RecordingDagsterTransport;
pub type DagsterLoopbackTransport = RecordingDagsterTransport;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl DagsterTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_deployment(
        &mut self,
        _request: &DagsterReadRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterDeploymentDescription>, DagsterTransportError> {
        Err(DagsterTransportError::BlockedEnv)
    }

    fn describe_repository(
        &mut self,
        _request: &DagsterReadRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterRepositoryDescription>, DagsterTransportError> {
        Err(DagsterTransportError::BlockedEnv)
    }

    fn describe_code_location(
        &mut self,
        _request: &DagsterReadRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterCodeLocationDescription>, DagsterTransportError> {
        Err(DagsterTransportError::BlockedEnv)
    }

    fn describe_job(
        &mut self,
        _request: &DagsterReadRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterJobDescription>, DagsterTransportError> {
        Err(DagsterTransportError::BlockedEnv)
    }

    fn describe_asset(
        &mut self,
        _request: &DagsterReadRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterAssetDescription>, DagsterTransportError> {
        Err(DagsterTransportError::BlockedEnv)
    }

    fn read_run(
        &mut self,
        _request: &DagsterReadRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DagsterPayload<DagsterRunSnapshot>, DagsterTransportError> {
        Err(DagsterTransportError::BlockedEnv)
    }

    fn read_events(
        &mut self,
        _request: &DagsterReadRequest,
        _secret_reference: &SecretReference,
    ) -> Result<DagsterPage<DagsterEventSummary>, DagsterTransportError> {
        Err(DagsterTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug)]
pub struct PagedDagsterEvents {
    pub items: Vec<DagsterEventSummary>,
    pub pages_read: usize,
    pub total_items: usize,
    pub page_digests: Vec<Digest>,
}

#[derive(Clone, Debug)]
pub struct DagsterProvider<T> {
    transport: T,
    limits: ReadLimits,
}

impl<T: DagsterTransport> DagsterProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            limits: ReadLimits::default(),
        }
    }

    pub fn with_limits(transport: T, limits: ReadLimits) -> Result<Self, DagsterError> {
        Ok(Self {
            transport,
            limits: limits.validate()?,
        })
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

    pub fn limits(&self) -> ReadLimits {
        self.limits
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_deployment(
        &mut self,
        scope: &DagsterScope,
        secret_reference: &SecretReference,
    ) -> Result<DagsterDeploymentDescription, DagsterError> {
        Self::ensure_scope_secret(scope, secret_reference)?;
        let request = DagsterReadRequest::for_scope(
            scope,
            DagsterOperation::DescribeDeployment,
            None,
            None,
            self.limits.max_page_items,
        );
        let payload = self
            .transport
            .describe_deployment(&request, secret_reference)
            .map_err(DagsterError::from_transport)?;
        payload.verify()?;
        let description = payload.payload;
        description.validate()?;
        if description.scope_digest != scope.scope_digest() {
            return Err(DagsterError::DeploymentMismatch);
        }
        Ok(description)
    }

    pub fn describe_repository(
        &mut self,
        scope: &DagsterScope,
        secret_reference: &SecretReference,
    ) -> Result<DagsterRepositoryDescription, DagsterError> {
        Self::ensure_scope_secret(scope, secret_reference)?;
        let request = DagsterReadRequest::for_scope(
            scope,
            DagsterOperation::DescribeRepository,
            None,
            None,
            self.limits.max_page_items,
        );
        let payload = self
            .transport
            .describe_repository(&request, secret_reference)
            .map_err(DagsterError::from_transport)?;
        payload.verify()?;
        let description = payload.payload;
        description.validate()?;
        if description.scope_digest != scope.scope_digest() {
            return Err(DagsterError::RepositoryMismatch);
        }
        Ok(description)
    }

    pub fn describe_code_location(
        &mut self,
        scope: &DagsterScope,
        secret_reference: &SecretReference,
    ) -> Result<DagsterCodeLocationDescription, DagsterError> {
        Self::ensure_scope_secret(scope, secret_reference)?;
        let request = DagsterReadRequest::for_scope(
            scope,
            DagsterOperation::DescribeCodeLocation,
            None,
            None,
            self.limits.max_page_items,
        );
        let payload = self
            .transport
            .describe_code_location(&request, secret_reference)
            .map_err(DagsterError::from_transport)?;
        payload.verify()?;
        let description = payload.payload;
        description.validate()?;
        if description.scope_digest != scope.scope_digest() {
            return Err(DagsterError::CodeLocationMismatch);
        }
        Ok(description)
    }

    pub fn describe_job(
        &mut self,
        scope: &DagsterScope,
        secret_reference: &SecretReference,
    ) -> Result<DagsterJobDescription, DagsterError> {
        Self::ensure_scope_secret(scope, secret_reference)?;
        let request = DagsterReadRequest::for_scope(
            scope,
            DagsterOperation::DescribeJob,
            None,
            None,
            self.limits.max_page_items,
        );
        let payload = self
            .transport
            .describe_job(&request, secret_reference)
            .map_err(DagsterError::from_transport)?;
        payload.verify()?;
        let description = payload.payload;
        description.validate()?;
        if description.scope_digest != scope.scope_digest() {
            return Err(DagsterError::JobMismatch);
        }
        Ok(description)
    }

    pub fn describe_asset(
        &mut self,
        scope: &DagsterScope,
        secret_reference: &SecretReference,
    ) -> Result<DagsterAssetDescription, DagsterError> {
        Self::ensure_scope_secret(scope, secret_reference)?;
        let request = DagsterReadRequest::for_scope(
            scope,
            DagsterOperation::DescribeAsset,
            None,
            None,
            self.limits.max_page_items,
        );
        let payload = self
            .transport
            .describe_asset(&request, secret_reference)
            .map_err(DagsterError::from_transport)?;
        payload.verify()?;
        let description = payload.payload;
        description.validate()?;
        if description.scope_digest != scope.scope_digest() {
            return Err(DagsterError::AssetMismatch);
        }
        Ok(description)
    }

    pub fn read_run_snapshot(
        &mut self,
        scope: &DagsterScope,
        run_id: &str,
        secret_reference: &SecretReference,
    ) -> Result<DagsterRunSnapshot, DagsterError> {
        Self::ensure_scope_secret(scope, secret_reference)?;
        validate_identifier("requested run id", run_id)?;
        if run_id != scope.run.run_id {
            return Err(DagsterError::RunMismatch);
        }
        let request = DagsterReadRequest::for_scope(
            scope,
            DagsterOperation::ReadRun,
            Some(run_id.to_owned()),
            None,
            self.limits.max_page_items,
        );
        let payload = self
            .transport
            .read_run(&request, secret_reference)
            .map_err(DagsterError::from_transport)?;
        payload.verify()?;
        let snapshot = payload.payload;
        snapshot.validate()?;
        Self::validate_snapshot_scope(scope, &snapshot).map(|()| snapshot)
    }

    pub fn read_event_pages(
        &mut self,
        scope: &DagsterScope,
        run_id: &str,
        secret_reference: &SecretReference,
    ) -> Result<PagedDagsterEvents, DagsterError> {
        Self::ensure_scope_secret(scope, secret_reference)?;
        validate_identifier("requested run id", run_id)?;
        if run_id != scope.run.run_id {
            return Err(DagsterError::RunMismatch);
        }
        let mut cursor = None;
        let mut seen_cursors = BTreeSet::new();
        let mut seen_events = BTreeSet::new();
        let mut items = Vec::new();
        let mut page_digests = Vec::new();
        let mut page_index = 0;

        loop {
            if page_index >= self.limits.max_pages {
                return Err(DagsterError::PaginationLimit);
            }
            let request = DagsterReadRequest::for_scope(
                scope,
                DagsterOperation::ReadEvents,
                Some(run_id.to_owned()),
                cursor.clone(),
                self.limits.max_page_items,
            );
            let page = self
                .transport
                .read_events(&request, secret_reference)
                .map_err(DagsterError::from_transport)?;
            page.verify(
                DagsterOperation::ReadEvents,
                page_index,
                cursor.as_ref(),
                &self.limits,
            )?;
            for event in &page.items {
                event.validate_for_scope(scope)?;
                if !seen_events.insert(event.event_id.clone()) {
                    return Err(DagsterError::DuplicateEvent);
                }
            }
            if items.len() + page.items.len() > self.limits.max_events {
                return Err(DagsterError::EvidenceTooLarge);
            }
            page_digests.push(page.response_digest.clone());
            items.extend(page.items);
            match page.next_cursor {
                None => break,
                Some(next_cursor) => {
                    if !seen_cursors.insert(next_cursor.clone()) {
                        return Err(DagsterError::PaginationRepeatedCursor);
                    }
                    cursor = Some(next_cursor);
                    page_index += 1;
                }
            }
        }

        Ok(PagedDagsterEvents {
            total_items: items.len(),
            pages_read: page_digests.len(),
            items,
            page_digests,
        })
    }

    fn ensure_scope_secret(
        scope: &DagsterScope,
        secret_reference: &SecretReference,
    ) -> Result<(), DagsterError> {
        scope.validate()?;
        if secret_reference.is_revoked() {
            return Err(DagsterError::SecretRevoked);
        }
        if !secret_reference.is_bound_to(scope) {
            return Err(DagsterError::SecretScopeMismatch);
        }
        Ok(())
    }

    fn validate_snapshot_scope(
        scope: &DagsterScope,
        snapshot: &DagsterRunSnapshot,
    ) -> Result<(), DagsterError> {
        if snapshot.run.run_id != scope.run.run_id {
            return Err(DagsterError::RunMismatch);
        }
        if snapshot.deployment != scope.deployment {
            return Err(DagsterError::DeploymentMismatch);
        }
        if snapshot.repository != scope.repository {
            return Err(DagsterError::RepositoryMismatch);
        }
        if snapshot.code_location != scope.code_location {
            return Err(DagsterError::CodeLocationMismatch);
        }
        if snapshot.job != scope.job {
            return Err(DagsterError::JobMismatch);
        }
        if snapshot.partition != scope.partition {
            return Err(DagsterError::PartitionMismatch);
        }
        if snapshot.asset != scope.asset {
            return Err(DagsterError::AssetMismatch);
        }
        if snapshot.commit != scope.commit {
            return Err(DagsterError::CommitMismatch);
        }
        Ok(())
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

    fn validate(&self) -> Result<(), DagsterError> {
        if self.connected
            || self.native
            || self.first_party
            || self.transport.connected()
            || self.transport.native()
            || self.transport.first_party()
        {
            return Err(DagsterError::EvidenceTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterRunEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub scope: DagsterScope,
    pub registration_digest: Digest,
    pub run: DagsterRunSnapshot,
    pub status: DagsterRunStatus,
    pub steps: Vec<DagsterStepSummary>,
    pub materializations: Vec<DagsterAssetMaterialization>,
    pub event_page_digests: Vec<Digest>,
    pub event_digest: Digest,
    pub materialization_digest: Digest,
    pub data_version_digests: Vec<Digest>,
    pub pages_read: usize,
    pub total_events: usize,
    pub complete: bool,
    pub materialization_verified: bool,
    pub observed_at_epoch_seconds: u64,
    pub provenance: EvidenceProvenance,
    pub evidence_digest: Digest,
}

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope: &'a DagsterScope,
    registration_digest: &'a Digest,
    run: &'a DagsterRunSnapshot,
    status: DagsterRunStatus,
    steps: &'a [DagsterStepSummary],
    materializations: &'a [DagsterAssetMaterialization],
    event_page_digests: &'a [Digest],
    event_digest: &'a Digest,
    materialization_digest: &'a Digest,
    data_version_digests: &'a [Digest],
    pages_read: usize,
    total_events: usize,
    complete: bool,
    materialization_verified: bool,
    observed_at_epoch_seconds: u64,
    provenance: &'a EvidenceProvenance,
}

impl DagsterRunEvidence {
    fn from_paged(
        scope: &DagsterScope,
        registration: &DagsterRegistration,
        run: DagsterRunSnapshot,
        events: PagedDagsterEvents,
        observed_at_epoch_seconds: u64,
        provenance: TransportProvenance,
    ) -> Result<Self, DagsterError> {
        run.validate()?;
        let mut steps = BTreeMap::new();
        let mut materializations = Vec::new();
        for event in &events.items {
            event.validate_for_scope(scope)?;
            if let Some(step_key) = &event.step_key {
                let summary = DagsterStepSummary::new(
                    step_key.clone(),
                    event.status,
                    event.duration_millis,
                    event.metadata_digest.clone(),
                )?;
                steps.insert(step_key.clone(), summary);
            }
            if let Some(materialization) = &event.materialization {
                if materialization.data_version_digest.is_none() {
                    return Err(DagsterError::MissingDataVersionDigest);
                }
                materializations.push(materialization.clone());
            }
        }
        if steps.len() > MAX_STEP_SUMMARIES || materializations.len() > MAX_MATERIALIZATIONS {
            return Err(DagsterError::EvidenceTooLarge);
        }
        let steps: Vec<DagsterStepSummary> = steps.into_values().collect();
        let data_version_digests: Vec<Digest> = materializations
            .iter()
            .filter_map(|materialization| materialization.data_version_digest.clone())
            .collect();
        let materialization_verified =
            !materializations.is_empty() && data_version_digests.len() == materializations.len();
        let event_digest = Digest::from_serializable(&events.items);
        let materialization_digest = Digest::from_serializable(&materializations);
        let provenance = EvidenceProvenance::from_transport(provenance);
        let mut evidence = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope: scope.clone(),
            registration_digest: registration.registration_digest.clone(),
            status: run.status,
            run,
            steps,
            materializations,
            event_page_digests: events.page_digests,
            event_digest,
            materialization_digest,
            data_version_digests,
            pages_read: events.pages_read,
            total_events: events.total_items,
            complete: true,
            materialization_verified,
            observed_at_epoch_seconds,
            provenance,
            evidence_digest: Digest::from_text("uncomputed"),
        };
        evidence.evidence_digest = evidence.compute_digest();
        evidence.validate(scope, registration)?;
        Ok(evidence)
    }

    pub fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&EvidenceDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            scope: &self.scope,
            registration_digest: &self.registration_digest,
            run: &self.run,
            status: self.status,
            steps: &self.steps,
            materializations: &self.materializations,
            event_page_digests: &self.event_page_digests,
            event_digest: &self.event_digest,
            materialization_digest: &self.materialization_digest,
            data_version_digests: &self.data_version_digests,
            pages_read: self.pages_read,
            total_events: self.total_events,
            complete: self.complete,
            materialization_verified: self.materialization_verified,
            observed_at_epoch_seconds: self.observed_at_epoch_seconds,
            provenance: &self.provenance,
        })
    }

    pub fn validate(
        &self,
        scope: &DagsterScope,
        registration: &DagsterRegistration,
    ) -> Result<(), DagsterError> {
        scope.validate()?;
        if self.schema_version != CONTRACT_SCHEMA || self.contract_version != CONTRACT_VERSION {
            return Err(DagsterError::EvidenceTampered);
        }
        if self.scope != *scope || self.registration_digest != registration.registration_digest {
            return Err(DagsterError::MissionScopeMismatch);
        }
        self.run.validate()?;
        if self.status != self.run.status {
            return Err(DagsterError::EvidenceTampered);
        }
        if self.run.deployment != scope.deployment
            || self.run.repository != scope.repository
            || self.run.code_location != scope.code_location
            || self.run.job != scope.job
            || self.run.run != scope.run
            || self.run.partition != scope.partition
            || self.run.asset != scope.asset
            || self.run.commit != scope.commit
        {
            return Err(DagsterError::EvidenceTampered);
        }
        if self.steps.len() > MAX_STEP_SUMMARIES
            || self.materializations.len() > MAX_MATERIALIZATIONS
            || self.event_page_digests.len() > MAX_PAGES
            || self.total_events > MAX_EVENTS
            || self.pages_read > MAX_PAGES
            || self.total_events < self.materializations.len()
        {
            return Err(DagsterError::EvidenceTooLarge);
        }
        for step in &self.steps {
            step.validate()?;
        }
        for materialization in &self.materializations {
            materialization.validate()?;
            if materialization.asset != scope.asset
                || materialization.partition != scope.partition
                || materialization.data_version_digest.is_none()
            {
                return Err(DagsterError::EventOutOfScope);
            }
        }
        if self
            .event_page_digests
            .iter()
            .any(|digest| !digest.is_valid())
            || !self.event_digest.is_valid()
            || !self.materialization_digest.is_valid()
            || self
                .data_version_digests
                .iter()
                .any(|digest| !digest.is_valid())
            || self.data_version_digests.len() != self.materializations.len()
            || self.materialization_verified
                != (!self.materializations.is_empty()
                    && self.data_version_digests.len() == self.materializations.len())
            || !self.complete
        {
            return Err(DagsterError::EvidenceTampered);
        }
        self.provenance.validate()?;
        if self.evidence_digest != self.compute_digest() {
            return Err(DagsterError::EvidenceTampered);
        }
        Ok(())
    }
}

pub type RunEvidence = DagsterRunEvidence;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionDisposition {
    Layer2Required,
    BlockedByProjection,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterRunResultProposal {
    pub schema_version: String,
    pub contract_version: String,
    pub scope: DagsterScope,
    pub mission: MissionScopeBinding,
    pub registration_digest: Digest,
    pub run_id: String,
    pub status: DagsterRunStatus,
    pub evidence_digest: Digest,
    pub event_digest: Digest,
    pub materialization_digest: Digest,
    pub data_version_digests: Vec<Digest>,
    pub adoption: AdoptionDisposition,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub proposal_digest: Digest,
}

#[derive(Serialize)]
struct ProposalDigestInput<'a> {
    schema_version: &'a str,
    contract_version: &'a str,
    scope: &'a DagsterScope,
    mission: &'a MissionScopeBinding,
    registration_digest: &'a Digest,
    run_id: &'a str,
    status: DagsterRunStatus,
    evidence_digest: &'a Digest,
    event_digest: &'a Digest,
    materialization_digest: &'a Digest,
    data_version_digests: &'a [Digest],
    adoption: AdoptionDisposition,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl DagsterRunResultProposal {
    fn from_evidence(evidence: &DagsterRunEvidence, scope: &DagsterScope) -> Self {
        let adoption = if evidence.status == DagsterRunStatus::Success
            && evidence.complete
            && evidence.materialization_verified
        {
            AdoptionDisposition::Layer2Required
        } else {
            AdoptionDisposition::BlockedByProjection
        };
        let mut proposal = Self {
            schema_version: CONTRACT_SCHEMA.into(),
            contract_version: CONTRACT_VERSION.into(),
            scope: scope.clone(),
            mission: scope.mission.clone(),
            registration_digest: evidence.registration_digest.clone(),
            run_id: evidence.run.run.run_id.clone(),
            status: evidence.status,
            evidence_digest: evidence.evidence_digest.clone(),
            event_digest: evidence.event_digest.clone(),
            materialization_digest: evidence.materialization_digest.clone(),
            data_version_digests: evidence.data_version_digests.clone(),
            adoption,
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
            scope: &self.scope,
            mission: &self.mission,
            registration_digest: &self.registration_digest,
            run_id: &self.run_id,
            status: self.status,
            evidence_digest: &self.evidence_digest,
            event_digest: &self.event_digest,
            materialization_digest: &self.materialization_digest,
            data_version_digests: &self.data_version_digests,
            adoption: self.adoption,
            connected: self.connected,
            native: self.native,
            first_party: self.first_party,
        })
    }

    pub fn validate(
        &self,
        scope: &DagsterScope,
        registration: &DagsterRegistration,
    ) -> Result<(), DagsterError> {
        if self.schema_version != CONTRACT_SCHEMA || self.contract_version != CONTRACT_VERSION {
            return Err(DagsterError::ProposalTampered);
        }
        if self.scope != *scope
            || self.mission != scope.mission
            || self.registration_digest != registration.registration_digest
            || self.run_id != scope.run.run_id
            || self.connected
            || self.native
            || self.first_party
            || !self.evidence_digest.is_valid()
            || !self.event_digest.is_valid()
            || !self.materialization_digest.is_valid()
            || self
                .data_version_digests
                .iter()
                .any(|digest| !digest.is_valid())
            || self.proposal_digest != self.compute_digest()
        {
            return Err(DagsterError::ProposalTampered);
        }
        Ok(())
    }
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DagsterRunRecording {
    pub schema_version: String,
    pub registration_digest: Digest,
    pub run_id: String,
    pub evidence_digest: Digest,
    pub receipt_digest: Digest,
    pub replayed: bool,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
}

impl DagsterRunRecording {
    fn new(evidence: &DagsterRunEvidence, registration: &DagsterRegistration) -> Self {
        let receipt_digest = Digest::from_serializable(&(
            CONTRACT_SCHEMA,
            &registration.registration_digest,
            &evidence.run.run.run_id,
            &evidence.evidence_digest,
        ));
        Self {
            schema_version: CONTRACT_SCHEMA.into(),
            registration_digest: registration.registration_digest.clone(),
            run_id: evidence.run.run.run_id.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest,
            replayed: false,
            durable: false,
            connected: false,
            native: false,
        }
    }

    fn replayed(mut self) -> Self {
        self.replayed = true;
        self
    }

    pub fn validate(
        &self,
        evidence: &DagsterRunEvidence,
        registration: &DagsterRegistration,
    ) -> Result<(), DagsterError> {
        evidence.validate(&evidence.scope, registration)?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.registration_digest != registration.registration_digest
            || self.run_id != evidence.run.run.run_id
            || self.evidence_digest != evidence.evidence_digest
            || self.receipt_digest
                != Digest::from_serializable(&(
                    CONTRACT_SCHEMA,
                    &registration.registration_digest,
                    &evidence.run.run.run_id,
                    &evidence.evidence_digest,
                ))
            || self.durable
            || self.connected
            || self.native
        {
            return Err(DagsterError::EvidenceTampered);
        }
        Ok(())
    }
}

pub type RunRecording = DagsterRunRecording;

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationProjection {
    pub schema_version: String,
    pub run_id: String,
    pub status: DagsterRunStatus,
    pub evidence_digest: Digest,
    pub event_digest: Digest,
    pub materialization_digest: Digest,
    pub registration_digest: Digest,
    pub bounded_evidence_verified: bool,
    pub adoption: AdoptionDisposition,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DagsterServiceDefinition {
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
    pub operations: Vec<DagsterOperation>,
    pub forbidden_effects: Vec<&'static str>,
    pub allowed_provenance: Vec<TransportProvenance>,
}

impl DagsterServiceDefinition {
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
                DagsterOperation::DescribeDeployment,
                DagsterOperation::DescribeRepository,
                DagsterOperation::DescribeCodeLocation,
                DagsterOperation::DescribeJob,
                DagsterOperation::DescribeAsset,
                DagsterOperation::ReadRun,
                DagsterOperation::ReadEvents,
            ],
            forbidden_effects: vec![
                "launch_run",
                "reexecute_run",
                "terminate_run",
                "mutate_asset",
                "select_arbitrary_operation",
                "control_schedule",
                "control_sensor",
                "resolve_native_secret",
                "retain_raw_config",
                "retain_raw_logs",
                "retain_unbounded_events",
                "adopt_kernel_outcome",
            ],
            allowed_provenance: vec![
                TransportProvenance::Recording,
                TransportProvenance::Fake,
                TransportProvenance::Loopback,
                TransportProvenance::BlockedEnv,
            ],
        }
    }
}

#[derive(Clone, Debug)]
pub struct DagsterRunResultService<T> {
    provider: DagsterProvider<T>,
    scope: DagsterScope,
    secret_reference: SecretReference,
    registration: DagsterRegistration,
    recordings: BTreeMap<String, Digest>,
    observed_status: BTreeMap<String, DagsterRunStatus>,
}

impl<T: DagsterTransport> DagsterRunResultService<T> {
    pub fn new(
        provider: DagsterProvider<T>,
        scope: DagsterScope,
        secret_reference: SecretReference,
    ) -> Result<Self, DagsterError> {
        scope.validate()?;
        let registration = DagsterRegistration::new(&scope, &secret_reference)?;
        Ok(Self {
            provider,
            scope,
            secret_reference,
            registration,
            recordings: BTreeMap::new(),
            observed_status: BTreeMap::new(),
        })
    }

    pub fn from_transport(
        scope: DagsterScope,
        secret_reference: SecretReference,
        transport: T,
    ) -> Result<Self, DagsterError> {
        Self::new(DagsterProvider::new(transport), scope, secret_reference)
    }

    pub fn definition() -> DagsterServiceDefinition {
        DagsterServiceDefinition::layer1()
    }

    pub fn scope(&self) -> &DagsterScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn registration(&self) -> &DagsterRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &DagsterProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut DagsterProvider<T> {
        &mut self.provider
    }

    pub fn describe_deployment(&mut self) -> Result<DagsterDeploymentDescription, DagsterError> {
        self.ensure_active()?;
        self.provider
            .describe_deployment(&self.scope, &self.secret_reference)
    }

    pub fn describe_repository(&mut self) -> Result<DagsterRepositoryDescription, DagsterError> {
        self.ensure_active()?;
        self.provider
            .describe_repository(&self.scope, &self.secret_reference)
    }

    pub fn describe_code_location(
        &mut self,
    ) -> Result<DagsterCodeLocationDescription, DagsterError> {
        self.ensure_active()?;
        self.provider
            .describe_code_location(&self.scope, &self.secret_reference)
    }

    pub fn describe_job(&mut self) -> Result<DagsterJobDescription, DagsterError> {
        self.ensure_active()?;
        self.provider
            .describe_job(&self.scope, &self.secret_reference)
    }

    pub fn describe_asset(&mut self) -> Result<DagsterAssetDescription, DagsterError> {
        self.ensure_active()?;
        self.provider
            .describe_asset(&self.scope, &self.secret_reference)
    }

    pub fn read_run_evidence(
        &mut self,
        request: DagsterRunReadRequest,
    ) -> Result<DagsterRunEvidence, DagsterError> {
        self.ensure_active()?;
        validate_identifier("requested run id", &request.run_id)?;
        if request.run_id != self.scope.run.run_id {
            return Err(DagsterError::RunMismatch);
        }
        let run = self.provider.read_run_snapshot(
            &self.scope,
            &request.run_id,
            &self.secret_reference,
        )?;
        self.validate_run_binding(&run)?;
        if let Some(previous_status) = self.observed_status.get(&request.run_id)
            && !previous_status.can_follow(run.status)
        {
            return Err(DagsterError::InvalidStateTransition);
        }
        let events =
            self.provider
                .read_event_pages(&self.scope, &request.run_id, &self.secret_reference)?;
        let evidence = DagsterRunEvidence::from_paged(
            &self.scope,
            &self.registration,
            run.clone(),
            events,
            request.observed_at_epoch_seconds,
            self.provider.provenance(),
        )?;
        self.observed_status.insert(request.run_id, run.status);
        Ok(evidence)
    }

    pub fn compile_run_result_proposal(
        &self,
        evidence: &DagsterRunEvidence,
    ) -> Result<DagsterRunResultProposal, DagsterError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        Ok(DagsterRunResultProposal::from_evidence(
            evidence,
            &self.scope,
        ))
    }

    pub fn compile_run_proposal(
        &self,
        evidence: &DagsterRunEvidence,
    ) -> Result<DagsterRunResultProposal, DagsterError> {
        self.compile_run_result_proposal(evidence)
    }

    pub fn record_run_receipt(
        &mut self,
        evidence: &DagsterRunEvidence,
    ) -> Result<DagsterRunRecording, DagsterError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        let run_id = evidence.run.run.run_id.clone();
        if let Some(existing) = self.recordings.get(&run_id) {
            if existing != &evidence.evidence_digest {
                return Err(DagsterError::DuplicateRun);
            }
            return Ok(DagsterRunRecording::new(evidence, &self.registration).replayed());
        }
        self.recordings
            .insert(run_id, evidence.evidence_digest.clone());
        Ok(DagsterRunRecording::new(evidence, &self.registration))
    }

    pub fn verify_run_evidence(
        &self,
        evidence: &DagsterRunEvidence,
    ) -> Result<VerificationProjection, DagsterError> {
        self.ensure_active()?;
        self.validate_evidence(evidence)?;
        let bounded_evidence_verified = evidence.status == DagsterRunStatus::Success
            && evidence.complete
            && evidence.materialization_verified;
        Ok(VerificationProjection {
            schema_version: CONTRACT_SCHEMA.into(),
            run_id: evidence.run.run.run_id.clone(),
            status: evidence.status,
            evidence_digest: evidence.evidence_digest.clone(),
            event_digest: evidence.event_digest.clone(),
            materialization_digest: evidence.materialization_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            bounded_evidence_verified,
            adoption: if bounded_evidence_verified {
                AdoptionDisposition::Layer2Required
            } else {
                AdoptionDisposition::BlockedByProjection
            },
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn verify_run_result(
        &self,
        evidence: &DagsterRunEvidence,
    ) -> Result<VerificationProjection, DagsterError> {
        self.verify_run_evidence(evidence)
    }

    pub fn projection_for_error(&self, error: &DagsterError) -> DagsterRunStatus {
        error.projection()
    }

    pub fn unmount(&mut self) -> Result<RegistrationTransitionEvidence, DagsterError> {
        self.registration.unmount()
    }

    pub fn remount(&mut self) -> Result<RegistrationTransitionEvidence, DagsterError> {
        if self.secret_reference.is_revoked() {
            return Err(DagsterError::SecretRevoked);
        }
        self.registration.remount()
    }

    pub fn revoke(&mut self) -> Result<RevocationReceipt, DagsterError> {
        self.registration.revoke(&mut self.secret_reference)
    }

    fn ensure_active(&self) -> Result<(), DagsterError> {
        if self.secret_reference.is_revoked() {
            return Err(DagsterError::SecretRevoked);
        }
        if !self.registration.is_active() {
            return if self.registration.status == RegistrationStatus::Revoked
                || self.registration.status == RegistrationStatus::Reversed
            {
                Err(DagsterError::RegistrationRevoked)
            } else {
                Err(DagsterError::RegistrationInactive)
            };
        }
        self.registration
            .validate_binding(&self.scope, &self.secret_reference)
    }

    fn validate_run_binding(&self, run: &DagsterRunSnapshot) -> Result<(), DagsterError> {
        if run.run != self.scope.run {
            return Err(DagsterError::RunMismatch);
        }
        if run.deployment != self.scope.deployment {
            return Err(DagsterError::DeploymentMismatch);
        }
        if run.repository != self.scope.repository {
            return Err(DagsterError::RepositoryMismatch);
        }
        if run.code_location != self.scope.code_location {
            return Err(DagsterError::CodeLocationMismatch);
        }
        if run.job != self.scope.job {
            return Err(DagsterError::JobMismatch);
        }
        if run.partition != self.scope.partition {
            return Err(DagsterError::PartitionMismatch);
        }
        if run.asset != self.scope.asset {
            return Err(DagsterError::AssetMismatch);
        }
        if run.commit != self.scope.commit {
            return Err(DagsterError::CommitMismatch);
        }
        Ok(())
    }

    fn validate_evidence(&self, evidence: &DagsterRunEvidence) -> Result<(), DagsterError> {
        self.ensure_active()?;
        evidence.validate(&self.scope, &self.registration)
    }
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
pub struct MissionDagsterRun {
    pub schema_version: String,
    pub scope_digest: Digest,
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub project_revision: u64,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub run_id: String,
    pub proposal_digest: Digest,
    pub disposition: MissionConsumptionDisposition,
    pub adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

pub struct MissionDagsterRunConsumer {
    binding: MissionScopeBinding,
    scope_digest: Digest,
    consumed: BTreeMap<String, Digest>,
    active: bool,
}

impl fmt::Debug for MissionDagsterRunConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionDagsterRunConsumer")
            .field("scope_digest", &self.scope_digest)
            .field("binding", &self.binding)
            .field("consumed_count", &self.consumed.len())
            .field("active", &self.active)
            .finish()
    }
}

impl MissionDagsterRunConsumer {
    pub fn new(scope: &DagsterScope) -> Result<Self, DagsterError> {
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
        proposal: &DagsterRunResultProposal,
    ) -> Result<MissionDagsterRun, DagsterError> {
        if !self.active {
            return Err(DagsterError::ConsumerInactive);
        }
        proposal.validate_integrity()?;
        if proposal.scope.scope_digest() != self.scope_digest {
            if proposal.mission.project_id == self.binding.project_id
                && proposal.mission.mission_id == self.binding.mission_id
                && proposal.mission.work_product_id == self.binding.work_product_id
            {
                return Err(DagsterError::StaleMissionRevision);
            }
            return Err(DagsterError::MissionScopeMismatch);
        }
        if proposal.mission != self.binding {
            if proposal.mission.project_id == self.binding.project_id
                && proposal.mission.mission_id == self.binding.mission_id
                && proposal.mission.work_product_id == self.binding.work_product_id
            {
                return Err(DagsterError::StaleMissionRevision);
            }
            return Err(DagsterError::MissionScopeMismatch);
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
            Some(_) => return Err(DagsterError::DuplicateRun),
        };
        Ok(MissionDagsterRun {
            schema_version: CONTRACT_SCHEMA.into(),
            scope_digest: self.scope_digest.clone(),
            project_id: self.binding.project_id.clone(),
            mission_id: self.binding.mission_id.clone(),
            work_product_id: self.binding.work_product_id.clone(),
            project_revision: self.binding.project_revision,
            mission_revision: self.binding.mission_revision,
            work_product_revision: self.binding.work_product_revision,
            run_id: proposal.run_id.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            disposition,
            adopted: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }
}

impl DagsterRunResultProposal {
    fn validate_integrity(&self) -> Result<(), DagsterError> {
        self.scope.validate()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.scope.mission != self.mission
            || self.run_id != self.scope.run.run_id
            || self.connected
            || self.native
            || self.first_party
            || !self.evidence_digest.is_valid()
            || !self.event_digest.is_valid()
            || !self.materialization_digest.is_valid()
            || self
                .data_version_digests
                .iter()
                .any(|digest| !digest.is_valid())
            || self.proposal_digest != self.compute_digest()
        {
            return Err(DagsterError::ProposalTampered);
        }
        Ok(())
    }
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

fn validate_revision(revision: u64) -> Result<(), DagsterError> {
    if revision == 0 {
        Err(DagsterError::InvalidInput("revision"))
    } else {
        Ok(())
    }
}

fn validate_origin(origin: &str) -> Result<(), DagsterError> {
    validate_bounded_text("deployment origin", origin, MAX_IDENTIFIER_BYTES)?;
    if !(origin.starts_with("https://")
        || origin.starts_with("http://localhost")
        || origin.starts_with("http://127.0.0.1"))
    {
        return Err(DagsterError::InvalidInput("deployment origin"));
    }
    Ok(())
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), DagsterError> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(DagsterError::InvalidInput(field));
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), DagsterError> {
    validate_bounded_text(field, value, MAX_IDENTIFIER_BYTES)?;
    if value.chars().any(char::is_whitespace) {
        return Err(DagsterError::InvalidInput(field));
    }
    Ok(())
}

fn validate_commit_sha(value: &str) -> Result<(), DagsterError> {
    if !(value.len() == 40 || value.len() == 64)
        || !value.bytes().all(|byte| {
            byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) || (b'A'..=b'F').contains(&byte)
        })
    {
        return Err(DagsterError::InvalidInput("commit SHA"));
    }
    Ok(())
}

fn canonical_asset_path(
    values: impl IntoIterator<Item = String>,
) -> Result<Vec<String>, DagsterError> {
    let values: Vec<String> = values.into_iter().collect();
    if values.is_empty() || values.len() > MAX_ASSET_PATH_SEGMENTS {
        return Err(DagsterError::InvalidInput("asset path"));
    }
    for value in &values {
        validate_bounded_text("asset path segment", value, MAX_ASSET_PATH_SEGMENT_BYTES)?;
        if value.contains('/') {
            return Err(DagsterError::InvalidInput("asset path segment"));
        }
    }
    Ok(values)
}
