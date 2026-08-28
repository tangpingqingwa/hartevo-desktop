use std::{
    collections::BTreeSet,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    MLFLOW_EVALUATION_RESULT_CONSUMER_ID, MLFLOW_EVALUATION_RESULT_CONTRACT_VERSION,
    MLFLOW_EVALUATION_RESULT_SCHEMA_VERSION, MLFLOW_EVALUATION_RESULT_SERVICE_ID,
};

pub(crate) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(crate) const MAX_KEY_BYTES: usize = 128;
pub(crate) const MAX_PAGE_TOKEN_BYTES: usize = 4 * 1024;
pub(crate) const MAX_FILTER_BYTES: usize = 4 * 1024;
pub(crate) const MAX_EXPERIMENTS: u32 = 1_000;
pub(crate) const MAX_RUNS: u32 = 50_000;
pub(crate) const MAX_METRICS: u32 = 1_024;
pub(crate) const MAX_METRIC_HISTORY: u32 = 10_000;
pub(crate) const MAX_PAGES: u8 = 32;
pub(crate) const MAX_PAGE_SIZE: u32 = 1_000;
pub(crate) const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_SCOPE_ALLOWLIST_ENTRIES: usize = 4_096;
pub(crate) const MAX_EXPERIMENT_TAGS_PER_RECORD: usize = 32;
pub(crate) const MAX_RUN_METRICS_PER_RECORD: usize = 256;
pub(crate) const MAX_RUN_PARAMS_PER_RECORD: usize = 128;
pub(crate) const MAX_RUN_TAGS_PER_RECORD: usize = 128;
pub(crate) const MAX_RUN_DATASETS_PER_RECORD: usize = 64;
pub(crate) const MAX_PROVIDER_ERRORS: usize = 64;
pub(crate) const MAX_RETRIES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("key is empty, malformed, or too long")]
    InvalidKey,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("dataset digest is empty, malformed, or too long")]
    InvalidDatasetDigest,
    #[error("scope is empty or contains an invalid allowlist")]
    InvalidScope,
    #[error("bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("page token is empty, contains whitespace, or is too large")]
    InvalidPageToken,
    #[error("record is malformed or exceeds its safety bound")]
    InvalidRecord,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration or secret reference is already revoked")]
    AlreadyRevoked,
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(|error| serde::de::Error::custom(error.to_string()))
    }
}

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

fn valid_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KEY_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b' ' | b'$')
        })
}

fn valid_dataset_digest(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

macro_rules! string_identifier {
    ($name:ident, $validator:ident, $error:expr) => {
        #[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(|error| serde::de::Error::custom(error.to_string()))
            }
        }

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if $validator(&value) {
                    Ok(Self(value))
                } else {
                    Err($error)
                }
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
    };
}

string_identifier!(
    ExperimentId,
    valid_identifier,
    ModelError::InvalidIdentifier
);
string_identifier!(RunId, valid_identifier, ModelError::InvalidIdentifier);
string_identifier!(MissionId, valid_identifier, ModelError::InvalidIdentifier);
string_identifier!(ProjectId, valid_identifier, ModelError::InvalidIdentifier);
string_identifier!(
    WorkProductId,
    valid_identifier,
    ModelError::InvalidIdentifier
);
string_identifier!(ServiceId, valid_identifier, ModelError::InvalidIdentifier);
string_identifier!(ProviderId, valid_identifier, ModelError::InvalidIdentifier);
string_identifier!(ConsumerId, valid_identifier, ModelError::InvalidIdentifier);
string_identifier!(MetricKey, valid_key, ModelError::InvalidKey);
string_identifier!(ParamKey, valid_key, ModelError::InvalidKey);
string_identifier!(TagKey, valid_key, ModelError::InvalidKey);

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DatasetDigest(String);

impl<'de> Deserialize<'de> for DatasetDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|error| serde::de::Error::custom(error.to_string()))
    }
}

impl DatasetDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_dataset_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDatasetDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DatasetDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("DatasetDigest")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl<'de> Deserialize<'de> for Revision {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(|error| serde::de::Error::custom(error.to_string()))
    }
}

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlflowAuthKind {
    ApiToken,
    OAuth,
    ServicePrincipal,
}

/// A live, monotonic revocation fence shared by all in-process snapshots.
///
/// This is deliberately an in-memory fence. It detects revocation across
/// cloned service/consumer handles in one process; it is not durable storage
/// and therefore cannot claim restart-safe revocation.
#[derive(Clone)]
pub struct LiveRevocationFence {
    generation: Arc<AtomicU64>,
}

impl fmt::Debug for LiveRevocationFence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveRevocationFence")
            .field("generation", &self.generation())
            .field("durable", &false)
            .finish()
    }
}

impl PartialEq for LiveRevocationFence {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.generation, &other.generation)
    }
}

impl Eq for LiveRevocationFence {}

impl LiveRevocationFence {
    pub(crate) fn new() -> Self {
        Self {
            generation: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn is_active(&self) -> bool {
        self.generation() % 2 == 1
    }

    pub const fn durable() -> bool {
        false
    }

    pub fn revoke(&self) -> Result<(), ModelError> {
        let mut current = self.generation();
        loop {
            if current.is_multiple_of(2) {
                return Err(ModelError::AlreadyRevoked);
            }
            let next = current.checked_add(1).ok_or(ModelError::AlreadyRevoked)?;
            match self.generation.compare_exchange(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }
}

/// An opaque reference into host-managed secret storage.
///
/// The reference identifier is hashed at construction and is never retained,
/// serialized, or printed. Layer 1 can bind a proposal to the reference
/// without receiving a credential or claiming native authentication.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    auth_kind: MlflowAuthKind,
    revoked: bool,
    revocation_fence: LiveRevocationFence,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            auth_kind: self.auth_kind,
            revoked: self.revoked,
            revocation_fence: self.revocation_fence.clone(),
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
            .field("auth_kind", &self.auth_kind)
            .field("revoked", &self.revoked)
            .field("revocation_fence", &self.revocation_fence)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.auth_kind == other.auth_kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &MlflowScope,
        credential_revision: u64,
        auth_kind: MlflowAuthKind,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "mlflow-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                format!("{auth_kind:?}"),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            auth_kind,
            revoked: false,
            revocation_fence: LiveRevocationFence::new(),
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

    pub const fn auth_kind(&self) -> MlflowAuthKind {
        self.auth_kind
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked || !self.revocation_fence.is_active()
    }

    pub fn revocation_fence(&self) -> LiveRevocationFence {
        self.revocation_fence.clone()
    }

    pub fn revocation_generation(&self) -> u64 {
        self.revocation_fence.generation()
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revocation_fence.revoke()?;
            self.revoked = true;
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialOrd, Ord, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRevisions {
    pub experiment: Revision,
    pub run: Revision,
    pub dataset: Revision,
    pub mission: Revision,
    pub project: Revision,
    pub work_product: Revision,
}

impl ScopeRevisions {
    pub const fn new(
        experiment: Revision,
        run: Revision,
        dataset: Revision,
        mission: Revision,
        project: Revision,
        work_product: Revision,
    ) -> Self {
        Self {
            experiment,
            run,
            dataset,
            mission,
            project,
            work_product,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlflowScope {
    tracking_server_digest: Digest,
    allowlisted_experiments: BTreeSet<ExperimentId>,
    allowlisted_runs: BTreeSet<RunId>,
    allowlisted_metrics: BTreeSet<MetricKey>,
    allowlisted_params: BTreeSet<ParamKey>,
    allowlisted_tags: BTreeSet<TagKey>,
    allowlisted_dataset_digests: BTreeSet<DatasetDigest>,
    mission_id: MissionId,
    project_id: ProjectId,
    work_product_id: WorkProductId,
    revisions: ScopeRevisions,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl MlflowScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tracking_server_digest: Digest,
        allowlisted_experiments: impl IntoIterator<Item = ExperimentId>,
        allowlisted_runs: impl IntoIterator<Item = RunId>,
        allowlisted_metrics: impl IntoIterator<Item = MetricKey>,
        allowlisted_params: impl IntoIterator<Item = ParamKey>,
        allowlisted_tags: impl IntoIterator<Item = TagKey>,
        allowlisted_dataset_digests: impl IntoIterator<Item = DatasetDigest>,
        mission_id: MissionId,
        project_id: ProjectId,
        work_product_id: WorkProductId,
        revisions: ScopeRevisions,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let allowlisted_experiments = allowlisted_experiments.into_iter().collect::<BTreeSet<_>>();
        if allowlisted_experiments.is_empty() {
            return Err(ModelError::InvalidScope);
        }
        let allowlisted_runs = allowlisted_runs.into_iter().collect::<BTreeSet<_>>();
        let allowlisted_metrics = allowlisted_metrics.into_iter().collect::<BTreeSet<_>>();
        let allowlisted_params = allowlisted_params.into_iter().collect::<BTreeSet<_>>();
        let allowlisted_tags = allowlisted_tags.into_iter().collect::<BTreeSet<_>>();
        let allowlisted_dataset_digests = allowlisted_dataset_digests
            .into_iter()
            .collect::<BTreeSet<_>>();
        if allowlisted_experiments.len() > MAX_EXPERIMENTS as usize
            || allowlisted_runs.len() > MAX_RUNS as usize
            || allowlisted_metrics.len() > MAX_SCOPE_ALLOWLIST_ENTRIES
            || allowlisted_params.len() > MAX_SCOPE_ALLOWLIST_ENTRIES
            || allowlisted_tags.len() > MAX_SCOPE_ALLOWLIST_ENTRIES
            || allowlisted_dataset_digests.len() > MAX_SCOPE_ALLOWLIST_ENTRIES
        {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "mlflow-scope/v1",
            &[
                tracking_server_digest.as_str().to_owned(),
                join_set(&allowlisted_experiments, ExperimentId::as_str),
                join_set(&allowlisted_runs, RunId::as_str),
                join_set(&allowlisted_metrics, MetricKey::as_str),
                join_set(&allowlisted_params, ParamKey::as_str),
                join_set(&allowlisted_tags, TagKey::as_str),
                join_set(&allowlisted_dataset_digests, DatasetDigest::as_str),
                mission_id.as_str().to_owned(),
                project_id.as_str().to_owned(),
                work_product_id.as_str().to_owned(),
                revisions.experiment.get().to_string(),
                revisions.run.get().to_string(),
                revisions.dataset.get().to_string(),
                revisions.mission.get().to_string(),
                revisions.project.get().to_string(),
                revisions.work_product.get().to_string(),
                permission_digest.as_str().to_owned(),
                consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            tracking_server_digest,
            allowlisted_experiments,
            allowlisted_runs,
            allowlisted_metrics,
            allowlisted_params,
            allowlisted_tags,
            allowlisted_dataset_digests,
            mission_id,
            project_id,
            work_product_id,
            revisions,
            permission_digest,
            consent_digest,
            scope_digest,
        })
    }

    pub fn tracking_server_digest(&self) -> &Digest {
        &self.tracking_server_digest
    }

    pub fn allowlisted_experiments(&self) -> &BTreeSet<ExperimentId> {
        &self.allowlisted_experiments
    }

    pub fn allowlisted_runs(&self) -> &BTreeSet<RunId> {
        &self.allowlisted_runs
    }

    pub fn allowlisted_metrics(&self) -> &BTreeSet<MetricKey> {
        &self.allowlisted_metrics
    }

    pub fn allowlisted_params(&self) -> &BTreeSet<ParamKey> {
        &self.allowlisted_params
    }

    pub fn allowlisted_tags(&self) -> &BTreeSet<TagKey> {
        &self.allowlisted_tags
    }

    pub fn allowlisted_dataset_digests(&self) -> &BTreeSet<DatasetDigest> {
        &self.allowlisted_dataset_digests
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn revisions(&self) -> ScopeRevisions {
        self.revisions
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn scope_digest(&self) -> Digest {
        self.scope_digest.clone()
    }

    pub(crate) fn allows_experiment(&self, id: &ExperimentId) -> bool {
        self.allowlisted_experiments.contains(id)
    }

    pub(crate) fn allows_run(&self, id: &RunId) -> bool {
        self.allowlisted_runs.is_empty() || self.allowlisted_runs.contains(id)
    }

    pub(crate) fn allows_metric(&self, key: &MetricKey) -> bool {
        self.allowlisted_metrics.contains(key)
    }

    pub(crate) fn allows_param(&self, key: &ParamKey) -> bool {
        self.allowlisted_params.contains(key)
    }

    pub(crate) fn allows_tag(&self, key: &TagKey) -> bool {
        self.allowlisted_tags.contains(key)
    }

    pub(crate) fn allows_dataset_digest(&self, digest: &DatasetDigest) -> bool {
        self.allowlisted_dataset_digests.contains(digest)
    }
}

fn join_set<T>(set: &BTreeSet<T>, render: impl Fn(&T) -> &str) -> String {
    set.iter().map(render).collect::<Vec<_>>().join(",")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionFence {
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub revisions: ScopeRevisions,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MlflowOperation {
    SearchExperiments,
    GetExperiment,
    SearchRuns,
    GetRun,
    GetMetricHistory,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExperimentLifecycle {
    Active,
    Deleted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Finished,
    Failed,
    Killed,
    Unknown,
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    BadRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    RateLimited,
    ServerFailure,
    Timeout,
    Tampered,
    PaginationLoop,
    BlockedEnv,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSeverity {
    Warning,
    Final,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderErrorEvidence {
    pub kind: ProviderErrorKind,
    pub severity: ErrorSeverity,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub attempt: u8,
    pub blocked_env: bool,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub(crate) fn new(
        kind: ProviderErrorKind,
        severity: ErrorSeverity,
        status_code: Option<u16>,
        retryable: bool,
        attempt: u8,
        blocked_env: bool,
        diagnostic_digest: &Digest,
    ) -> Self {
        let error_digest = Digest::from_fields(
            "mlflow-provider-error/v1",
            &[
                format!("{kind:?}"),
                format!("{severity:?}"),
                status_code.map_or_else(|| "none".to_owned(), |code| code.to_string()),
                retryable.to_string(),
                attempt.to_string(),
                blocked_env.to_string(),
                diagnostic_digest.as_str().to_owned(),
            ],
        );
        Self {
            kind,
            severity,
            status_code,
            retryable,
            attempt,
            blocked_env,
            error_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryEvidence {
    pub operation: MlflowOperation,
    pub attempt: u8,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageLimit,
    ExperimentLimit,
    RunLimit,
    MetricLimit,
    MetricHistoryLimit,
    ResponseBytesLimit,
    PaginationLoop,
    MissingPage,
    ProviderError,
    StaleAfterProgress,
    AccessLossAfterProgress,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Complete,
    Stale,
    Partial(PartialReason),
    AccessLoss,
    ProviderUnknown,
    FinalError,
}

impl ResultStatus {
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::Complete)
    }

    pub const fn is_partial(self) -> bool {
        matches!(self, Self::Partial(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MlflowAuthority;

impl MlflowAuthority {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn truth(self) -> bool {
        false
    }

    pub const fn adopted(self) -> bool {
        false
    }

    pub const fn kernel(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedactedAttribute {
    pub key: String,
    pub value_digest: Digest,
}

impl RedactedAttribute {
    pub fn from_public_value(
        key: impl Into<String>,
        value: impl AsRef<[u8]>,
    ) -> Result<Self, ModelError> {
        let key = key.into();
        if !valid_key(&key) {
            return Err(ModelError::InvalidKey);
        }
        Ok(Self {
            key,
            value_digest: Digest::from_text(value),
        })
    }

    pub fn from_digest(key: impl Into<String>, value_digest: Digest) -> Result<Self, ModelError> {
        let key = key.into();
        if !valid_key(&key) {
            return Err(ModelError::InvalidKey);
        }
        Ok(Self { key, value_digest })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if valid_key(&self.key) && is_digest(self.value_digest.as_str()) {
            Ok(())
        } else {
            Err(ModelError::InvalidRecord)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DatasetReference {
    pub name_digest: Digest,
    pub digest: DatasetDigest,
    pub context_digest: Option<Digest>,
    pub reference_digest: Digest,
}

impl DatasetReference {
    pub fn new(
        name: impl AsRef<[u8]>,
        digest: DatasetDigest,
        context: Option<impl AsRef<[u8]>>,
    ) -> Self {
        let name_digest = Digest::from_text(name);
        let context_digest = context.map(Digest::from_text);
        let reference_digest = Digest::from_fields(
            "mlflow-dataset-reference/v1",
            &[
                name_digest.as_str().to_owned(),
                digest.as_str().to_owned(),
                context_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            ],
        );
        Self {
            name_digest,
            digest,
            context_digest,
            reference_digest,
        }
    }

    pub fn from_digests(
        name_digest: Digest,
        digest: DatasetDigest,
        context_digest: Option<Digest>,
    ) -> Self {
        let reference_digest = Digest::from_fields(
            "mlflow-dataset-reference/v1",
            &[
                name_digest.as_str().to_owned(),
                digest.as_str().to_owned(),
                context_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            ],
        );
        Self {
            name_digest,
            digest,
            context_digest,
            reference_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::from_digests(
            self.name_digest.clone(),
            self.digest.clone(),
            self.context_digest.clone(),
        )
        .reference_digest;
        if expected == self.reference_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MetricValue {
    pub key: MetricKey,
    pub value: f64,
    pub timestamp_ms: u64,
    pub step: i64,
    pub dataset_digest: Option<DatasetDigest>,
    pub metric_digest: Digest,
}

impl MetricValue {
    pub fn new(
        key: MetricKey,
        value: f64,
        timestamp_ms: u64,
        step: i64,
        dataset_digest: Option<DatasetDigest>,
    ) -> Result<Self, ModelError> {
        if !value.is_finite() {
            return Err(ModelError::InvalidRecord);
        }
        let metric_digest =
            Self::compute_digest(&key, value, timestamp_ms, step, dataset_digest.as_ref());
        Ok(Self {
            key,
            value,
            timestamp_ms,
            step,
            dataset_digest,
            metric_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if !self.value.is_finite()
            || Self::compute_digest(
                &self.key,
                self.value,
                self.timestamp_ms,
                self.step,
                self.dataset_digest.as_ref(),
            ) != self.metric_digest
        {
            Err(ModelError::DigestMismatch)
        } else {
            Ok(())
        }
    }

    fn compute_digest(
        key: &MetricKey,
        value: f64,
        timestamp_ms: u64,
        step: i64,
        dataset_digest: Option<&DatasetDigest>,
    ) -> Digest {
        Digest::from_fields(
            "mlflow-metric/v1",
            &[
                key.as_str().to_owned(),
                value.to_bits().to_string(),
                timestamp_ms.to_string(),
                step.to_string(),
                dataset_digest
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MetricHistoryPoint {
    pub metric: MetricValue,
    pub point_digest: Digest,
}

impl MetricHistoryPoint {
    pub fn new(metric: MetricValue) -> Self {
        let point_digest = Digest::from_fields(
            "mlflow-metric-history-point/v1",
            &[metric.metric_digest.as_str().to_owned()],
        );
        Self {
            metric,
            point_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.metric.validate_digest()?;
        let expected = Digest::from_fields(
            "mlflow-metric-history-point/v1",
            &[self.metric.metric_digest.as_str().to_owned()],
        );
        if expected == self.point_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExperimentRecord {
    pub experiment_id: ExperimentId,
    pub name_digest: Digest,
    pub lifecycle: ExperimentLifecycle,
    pub revision: Revision,
    pub redacted_tags: Vec<RedactedAttribute>,
    pub record_digest: Digest,
}

impl ExperimentRecord {
    pub fn new(
        experiment_id: ExperimentId,
        name: impl AsRef<[u8]>,
        lifecycle: ExperimentLifecycle,
        revision: Revision,
        redacted_tags: Vec<RedactedAttribute>,
    ) -> Self {
        let name_digest = Digest::from_text(name);
        let record_digest = Self::compute_digest(
            &experiment_id,
            &name_digest,
            lifecycle,
            revision,
            &redacted_tags,
        );
        Self {
            experiment_id,
            name_digest,
            lifecycle,
            revision,
            redacted_tags,
            record_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        for tag in &self.redacted_tags {
            tag.validate()?;
        }
        if Self::compute_digest(
            &self.experiment_id,
            &self.name_digest,
            self.lifecycle,
            self.revision,
            &self.redacted_tags,
        ) == self.record_digest
        {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(
        experiment_id: &ExperimentId,
        name_digest: &Digest,
        lifecycle: ExperimentLifecycle,
        revision: Revision,
        redacted_tags: &[RedactedAttribute],
    ) -> Digest {
        let mut fields = vec![
            experiment_id.as_str().to_owned(),
            name_digest.as_str().to_owned(),
            format!("{lifecycle:?}"),
            revision.get().to_string(),
        ];
        fields.extend(
            redacted_tags
                .iter()
                .flat_map(|tag| [tag.key.clone(), tag.value_digest.as_str().to_owned()]),
        );
        Digest::from_fields("mlflow-experiment-record/v1", &fields)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RunRecord {
    pub run_id: RunId,
    pub experiment_id: ExperimentId,
    pub status: RunStatus,
    pub start_time_ms: Option<u64>,
    pub end_time_ms: Option<u64>,
    pub run_name_digest: Option<Digest>,
    pub user_id_digest: Option<Digest>,
    pub metrics: Vec<MetricValue>,
    pub redacted_params: Vec<RedactedAttribute>,
    pub redacted_tags: Vec<RedactedAttribute>,
    pub datasets: Vec<DatasetReference>,
    pub revision: Revision,
    pub record_digest: Digest,
}

impl RunRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: RunId,
        experiment_id: ExperimentId,
        status: RunStatus,
        start_time_ms: Option<u64>,
        end_time_ms: Option<u64>,
        run_name: Option<impl AsRef<[u8]>>,
        user_id: Option<impl AsRef<[u8]>>,
        metrics: Vec<MetricValue>,
        redacted_params: Vec<RedactedAttribute>,
        redacted_tags: Vec<RedactedAttribute>,
        datasets: Vec<DatasetReference>,
        revision: Revision,
    ) -> Self {
        let run_name_digest = run_name.map(Digest::from_text);
        let user_id_digest = user_id.map(Digest::from_text);
        let record_digest = Self::compute_digest(
            &run_id,
            &experiment_id,
            status,
            start_time_ms,
            end_time_ms,
            run_name_digest.as_ref(),
            user_id_digest.as_ref(),
            &metrics,
            &redacted_params,
            &redacted_tags,
            &datasets,
            revision,
        );
        Self {
            run_id,
            experiment_id,
            status,
            start_time_ms,
            end_time_ms,
            run_name_digest,
            user_id_digest,
            metrics,
            redacted_params,
            redacted_tags,
            datasets,
            revision,
            record_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        for attribute in self.redacted_params.iter().chain(self.redacted_tags.iter()) {
            attribute.validate()?;
        }
        if self
            .metrics
            .iter()
            .any(|metric| metric.validate_digest().is_err())
            || self
                .datasets
                .iter()
                .any(|dataset| dataset.validate_digest().is_err())
        {
            return Err(ModelError::DigestMismatch);
        }
        let expected = Self::compute_digest(
            &self.run_id,
            &self.experiment_id,
            self.status,
            self.start_time_ms,
            self.end_time_ms,
            self.run_name_digest.as_ref(),
            self.user_id_digest.as_ref(),
            &self.metrics,
            &self.redacted_params,
            &self.redacted_tags,
            &self.datasets,
            self.revision,
        );
        if expected == self.record_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_digest(
        run_id: &RunId,
        experiment_id: &ExperimentId,
        status: RunStatus,
        start_time_ms: Option<u64>,
        end_time_ms: Option<u64>,
        run_name_digest: Option<&Digest>,
        user_id_digest: Option<&Digest>,
        metrics: &[MetricValue],
        redacted_params: &[RedactedAttribute],
        redacted_tags: &[RedactedAttribute],
        datasets: &[DatasetReference],
        revision: Revision,
    ) -> Digest {
        let mut fields = vec![
            run_id.as_str().to_owned(),
            experiment_id.as_str().to_owned(),
            format!("{status:?}"),
            start_time_ms.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            end_time_ms.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            run_name_digest.map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            user_id_digest.map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            revision.get().to_string(),
        ];
        fields.extend(
            metrics
                .iter()
                .map(|metric| metric.metric_digest.as_str().to_owned()),
        );
        fields.extend(
            redacted_params
                .iter()
                .flat_map(|param| [param.key.clone(), param.value_digest.as_str().to_owned()]),
        );
        fields.extend(
            redacted_tags
                .iter()
                .flat_map(|tag| [tag.key.clone(), tag.value_digest.as_str().to_owned()]),
        );
        fields.extend(
            datasets
                .iter()
                .map(|dataset| dataset.reference_digest.as_str().to_owned()),
        );
        Digest::from_fields("mlflow-run-record/v1", &fields)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ResultBounds {
    max_experiments: u32,
    max_runs: u32,
    max_metric_history: u32,
    max_pages: u8,
    page_size: u32,
    max_response_bytes: u64,
}

impl ResultBounds {
    pub fn new(
        max_experiments: u32,
        max_runs: u32,
        max_metric_history: u32,
        max_pages: u8,
        page_size: u32,
        max_response_bytes: u64,
    ) -> Result<Self, ModelError> {
        if max_experiments == 0
            || max_experiments > MAX_EXPERIMENTS
            || max_runs == 0
            || max_runs > MAX_RUNS
            || max_metric_history == 0
            || max_metric_history > MAX_METRIC_HISTORY
            || max_pages == 0
            || max_pages > MAX_PAGES
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            max_experiments,
            max_runs,
            max_metric_history,
            max_pages,
            page_size,
            max_response_bytes,
        })
    }

    pub const fn max_experiments(self) -> u32 {
        self.max_experiments
    }

    pub const fn max_runs(self) -> u32 {
        self.max_runs
    }

    pub const fn max_metric_history(self) -> u32 {
        self.max_metric_history
    }

    pub const fn max_pages(self) -> u8 {
        self.max_pages
    }

    pub const fn page_size(self) -> u32 {
        self.page_size
    }

    pub const fn max_response_bytes(self) -> u64 {
        self.max_response_bytes
    }
}

impl Default for ResultBounds {
    fn default() -> Self {
        Self::new(100, 1_000, 1_000, 8, 100, 1_024 * 1_024).expect("default bounds are valid")
    }
}

/// A provider page token is deliberately not serializable or printable.
/// Evidence can carry only its digest, which prevents cursor leakage.
pub struct OpaquePageToken(String);

impl OpaquePageToken {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_PAGE_TOKEN_BYTES
            || value.chars().any(char::is_whitespace)
        {
            Err(ModelError::InvalidPageToken)
        } else {
            Ok(Self(value))
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(&self.0)
    }
}

impl Clone for OpaquePageToken {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("digest", &self.digest())
            .finish()
    }
}

impl PartialEq for OpaquePageToken {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for OpaquePageToken {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceDigests {
    pub scope_digest: Digest,
    pub version_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub query_digest: Digest,
    pub config_digest: Digest,
    pub experiment_set_digest: Digest,
    pub run_set_digest: Digest,
    pub metric_history_digest: Digest,
    pub dataset_set_digest: Digest,
    pub result_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MlflowRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: ConsumerId,
    pub provider_version: String,
    pub scope_digest: Digest,
    pub capability_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
    #[serde(skip)]
    revocation_fence: LiveRevocationFence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub revocation_digest: Digest,
}

impl MlflowRegistration {
    pub fn new(
        scope_digest: Digest,
        provider_id: ProviderId,
        provider_version: impl Into<String>,
        capability_digest: Digest,
    ) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty()
            || provider_version.len() > MAX_IDENTIFIER_BYTES
            || provider_version.chars().any(char::is_control)
            || provider_version.chars().any(char::is_whitespace)
            || !is_digest(scope_digest.as_str())
        {
            return Err(ModelError::InvalidRegistration);
        }
        let service_id = ServiceId::new(MLFLOW_EVALUATION_RESULT_SERVICE_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let consumer_id = ConsumerId::new(MLFLOW_EVALUATION_RESULT_CONSUMER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let revision = Revision::new(1)?;
        let registration_digest = Self::compute_digest(
            &scope_digest,
            &provider_id,
            &provider_version,
            &capability_digest,
            revision,
        );
        Ok(Self {
            schema_version: MLFLOW_EVALUATION_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: MLFLOW_EVALUATION_RESULT_CONTRACT_VERSION.to_owned(),
            service_id,
            provider_id,
            consumer_id,
            provider_version,
            scope_digest,
            capability_digest,
            registration_digest,
            revision,
            state: RegistrationState::Active,
            revocation_fence: LiveRevocationFence::new(),
        })
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        if self.state == RegistrationState::Active && self.revocation_fence.is_active() {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocation, ModelError> {
        self.ensure_active()?;
        self.revocation_fence.revoke()?;
        self.state = RegistrationState::Revoked;
        let revocation_digest = Digest::from_fields(
            "mlflow-registration-revocation/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.revision.get().to_string(),
            ],
        );
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            revocation_digest,
        })
    }

    pub fn revocation_fence(&self) -> LiveRevocationFence {
        self.revocation_fence.clone()
    }

    pub fn revocation_generation(&self) -> u64 {
        self.revocation_fence.generation()
    }

    fn compute_digest(
        scope_digest: &Digest,
        provider_id: &ProviderId,
        provider_version: &str,
        capability_digest: &Digest,
        revision: Revision,
    ) -> Digest {
        Digest::from_fields(
            "mlflow-registration/v1",
            &[
                MLFLOW_EVALUATION_RESULT_SCHEMA_VERSION.to_owned(),
                MLFLOW_EVALUATION_RESULT_CONTRACT_VERSION.to_owned(),
                MLFLOW_EVALUATION_RESULT_SERVICE_ID.to_owned(),
                provider_id.as_str().to_owned(),
                MLFLOW_EVALUATION_RESULT_CONSUMER_ID.to_owned(),
                provider_version.to_owned(),
                scope_digest.as_str().to_owned(),
                capability_digest.as_str().to_owned(),
                revision.get().to_string(),
            ],
        )
    }
}
